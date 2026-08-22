//! Commit 35: the durable pending-**upload** context.
//!
//! The download side lost its JSON sidecar in commit 34; this is the same
//! move for uploads. What used to be `pending-uploads.json` — a whole-file
//! JSON read-modify-write performed from a background upload thread — is
//! now rows in [`TransferStore`]:
//!
//! - **The multipart handle** (`object_key` + `upload_id`) is the primary
//!   key, because that pair is exactly what an abort or a completion has to
//!   address. One real remote multipart upload, one row.
//! - **The parts** are durable rows too, written as S3 acknowledges them.
//!   The old sidecar recorded only that an upload existed, so a process
//!   that died mid-upload could abort the orphan but never resume or even
//!   describe it.
//! - **The entry revision** the upload was started for is a column, so a
//!   recovered record can be told apart from a newer attempt on the same
//!   library entry instead of being applied blind.
//! - **The desired state** (`running` / `aborting`) is the durable half of
//!   the in-memory `UploadOperation` token. Startup no longer reads a file,
//!   rebuilds a `Vec`, and writes it back: it runs one transaction that
//!   flips every surviving record to `aborting` and hands them out
//!   ([`TransferStore::claim_orphan_uploads`]).
//!
//! No credential material has a column here — see the migration's own
//! "No secrets in this table" note and
//! `tests/transfer_store_uploads.rs::the_upload_schema_has_no_credential_columns`.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::error::PersistenceError;
use super::legacy_import::{self, LegacyPendingUploadStore};
use super::schema::JobStateTag;
use super::transfer_store::{
    read_job, CompleteJobOutcome, MigrationMarker, OperationKind, RetryJobError, RetryJobOutcome,
    StoredJob, TerminalOutcome, TransferStore,
};
use crate::domain::{DeviceId, JobIdentity, SessionId};
use crate::transfer::{JobAggregate, JobCommand, TransferJobState};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------

/// What the owner of an upload wants to happen to it.
///
/// Deliberately only two values. "Finished" is not one of them: a finished
/// multipart upload has no row at all (see
/// [`TransferStore::finish_upload`]), so "there is a row" and "the object
/// store still holds parts nobody has accounted for" can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UploadDesiredState {
    /// A live task owns this upload and is expected to complete it.
    Running,
    /// Nobody owns it any more; the next process that can reach the object
    /// store must abort it.
    Aborting,
}

/// URL addressing style used to sign requests for a multipart upload.
///
/// This is persisted with each multipart handle because the endpoint's
/// addressing convention is part of the request identity. A later restart
/// must not reinterpret an old row using whatever style happens to be
/// configured today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UploadUrlStyle {
    /// `https://bucket.endpoint/object` addressing.
    VirtualHost,
    /// `https://endpoint/bucket/object` addressing.
    Path,
    /// The row predates persisted URL styles, so recovery must use the
    /// current configured style. This is only valid for rows upgraded by the
    /// v18 migration; all newly-created rows carry `VirtualHost` or `Path`.
    LegacyConfigured,
}

impl UploadUrlStyle {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::VirtualHost => "virtual_host",
            Self::Path => "path",
            Self::LegacyConfigured => "legacy_configured",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "virtual_host" => Some(Self::VirtualHost),
            "path" => Some(Self::Path),
            "legacy_configured" => Some(Self::LegacyConfigured),
            _ => None,
        }
    }
}

impl UploadDesiredState {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            UploadDesiredState::Running => "running",
            UploadDesiredState::Aborting => "aborting",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        Some(match value {
            "running" => UploadDesiredState::Running,
            "aborting" => UploadDesiredState::Aborting,
            _ => return None,
        })
    }
}

/// The coordinates of one real remote multipart upload, plus the local
/// context needed to converge the library entry it belongs to.
///
/// This is the value a caller *supplies*; [`StoredUpload`] is what comes
/// back out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUpload {
    /// The in-memory `Transfer::key` this upload belongs to.
    pub transfer_key: String,
    /// `LibraryEntry::key()` ("{device_id}|{session_id}").
    pub entry_key: String,
    /// The publication revision the upload was started for.
    pub revision: String,
    pub object_key: String,
    pub upload_id: String,
    pub endpoint: String,
    pub bucket: String,
    /// The endpoint URL style used for this multipart upload.
    pub url_style: UploadUrlStyle,
}

/// Immutable input identity for one durable upload job. The entry and
/// publication revision form the natural key; `input_digest` is the sealed
/// bundle/material digest used to distinguish an idempotent replay from a
/// conflicting request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadJobSpec {
    pub entry_key: String,
    pub revision: String,
    pub input_digest: String,
    /// Normalized destination object-key prefix. `None` means the row
    /// predates the v19 namespace proof and cannot authorize an exact
    /// full-key check.
    pub object_prefix: Option<String>,
}

/// Immutable UI metadata captured when an upload job is created. Progress is
/// deliberately excluded: it is updated only from acknowledged data parts
/// in the same transaction as their evidence rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadActivitySeed {
    pub label: String,
    pub target_label: String,
    /// Zero means the source did not provide a trusted total.
    pub total_bytes: u64,
}

impl UploadActivitySeed {
    #[must_use]
    pub fn fallback(spec: &UploadJobSpec) -> Self {
        Self {
            label: spec.entry_key.clone(),
            target_label: String::new(),
            total_bytes: 0,
        }
    }
}

/// Joined durable upload activity projection. The job/spec remain available
/// so callers never have to recover identity from a UI-only transfer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUploadActivity {
    pub job: StoredJob,
    pub spec: UploadJobSpec,
    pub label: String,
    pub target_label: String,
    pub total_bytes: u64,
    pub confirmed_bytes: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Which kind of object a verified upload receipt describes.
///
/// The role is part of the durable receipt identity. It is supplied by the
/// upload plan rather than inferred from an object-key suffix, because a
/// publication object can be renamed without changing what was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UploadReceiptRole {
    Data,
    Evidence,
}

impl UploadReceiptRole {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Evidence => "evidence",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "data" => Some(Self::Data),
            "evidence" => Some(Self::Evidence),
            _ => None,
        }
    }
}

/// How the verified object bytes were proven to match the source digest.
///
/// This mirrors the object-store port's proof vocabulary but remains a
/// persistence-owned type so the SQLite schema does not depend on a concrete
/// adapter. The value is immutable evidence, not a hint for a future retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UploadReceiptDigestProof {
    ServerChecksum,
    StreamedReadback,
}

impl UploadReceiptDigestProof {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::ServerChecksum => "server_checksum",
            Self::StreamedReadback => "streamed_readback",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "server_checksum" => Some(Self::ServerChecksum),
            "streamed_readback" => Some(Self::StreamedReadback),
            _ => None,
        }
    }
}

/// One verified object to stage for an upload job.
///
/// The caller must supply the object role explicitly. `entry_key` and
/// `revision` are intentionally absent here: the staging API reads those
/// immutable values from the upload job spec and rejects a caller-provided
/// context that does not match it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadReceiptSeed {
    pub object_key: String,
    pub role: UploadReceiptRole,
    pub etag: String,
    pub version_id: Option<String>,
    pub size_bytes: u64,
    pub source_sha256: String,
    pub digest_proof: UploadReceiptDigestProof,
}

impl UploadReceiptSeed {
    #[must_use]
    pub fn new(
        object_key: impl Into<String>,
        role: UploadReceiptRole,
        etag: impl Into<String>,
        version_id: Option<String>,
        size_bytes: u64,
        source_sha256: impl Into<String>,
        digest_proof: UploadReceiptDigestProof,
    ) -> Self {
        Self {
            object_key: object_key.into(),
            role,
            etag: etag.into(),
            version_id,
            size_bytes,
            source_sha256: source_sha256.into(),
            digest_proof,
        }
    }
}

/// Durable, immutable upload receipt joined with its job-owned version
/// context. Receipt rows survive multipart retirement and job dismissal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUploadReceipt {
    pub job_id: String,
    pub entry_key: String,
    pub revision: String,
    pub object_key: String,
    pub role: UploadReceiptRole,
    pub etag: String,
    pub version_id: Option<String>,
    pub size_bytes: u64,
    pub source_sha256: String,
    pub digest_proof: UploadReceiptDigestProof,
    pub staged_at: String,
}

/// Compatibility spelling for callers that prefer the object-store name.
pub type VerifiedUploadReceipt = StoredUploadReceipt;
/// Compatibility spelling for callers that use "object role" terminology.
pub type UploadObjectRole = UploadReceiptRole;
/// Compatibility spelling for callers that use "proof" terminology.
pub type ReceiptDigestProof = UploadReceiptDigestProof;

impl UploadJobSpec {
    pub fn new(
        entry_key: impl Into<String>,
        revision: impl Into<String>,
        input_digest: impl Into<String>,
    ) -> Result<Self, UploadStoreError> {
        let spec = UploadJobSpec {
            entry_key: entry_key.into(),
            revision: revision.into(),
            input_digest: input_digest.into(),
            object_prefix: None,
        };
        validate_upload_job_spec(&spec).map_err(UploadStoreError::Invalid)?;
        Ok(spec)
    }

    /// Creates a spec for a newly-started upload with a proven destination
    /// namespace. The prefix is normalized exactly once before persistence.
    pub fn new_with_prefix(
        entry_key: impl Into<String>,
        revision: impl Into<String>,
        input_digest: impl Into<String>,
        object_prefix: impl Into<String>,
    ) -> Result<Self, UploadStoreError> {
        let object_prefix = normalize_object_prefix(&object_prefix.into());
        let spec = UploadJobSpec {
            entry_key: entry_key.into(),
            revision: revision.into(),
            input_digest: input_digest.into(),
            object_prefix: Some(object_prefix),
        };
        validate_upload_job_spec(&spec).map_err(UploadStoreError::Invalid)?;
        Ok(spec)
    }

    #[must_use]
    pub fn natural_key(&self) -> String {
        length_prefixed_key([self.entry_key.as_str(), self.revision.as_str()])
    }

    #[must_use]
    pub fn immutable_input(&self) -> &str {
        &self.input_digest
    }
}

/// Explicit spelling for app composition code.
pub type UploadJobRequest = UploadJobSpec;
pub type NewUploadJob = UploadJobSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadJobCreateOutcome {
    Created(Box<StoredJob>),
    Existing(Box<StoredJob>),
}

/// Test-only crash points for the job/spec/activity transaction.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadJobCreateAbort {
    AfterJob,
    AfterSpec,
    AfterActivity,
}

impl UploadJobCreateOutcome {
    #[must_use]
    pub fn job(&self) -> &StoredJob {
        match self {
            UploadJobCreateOutcome::Created(job) | UploadJobCreateOutcome::Existing(job) => job,
        }
    }

    #[must_use]
    pub fn was_created(&self) -> bool {
        matches!(self, UploadJobCreateOutcome::Created(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadJobConflict {
    pub entry_key: String,
    pub existing_job_id: String,
    pub existing_revision: String,
    pub requested_revision: String,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UploadJobCreateError {
    #[error("upload job input is invalid: {0}")]
    Invalid(String),

    #[error("upload job conflict: {0:?}")]
    Conflict(Box<UploadJobConflict>),

    #[error("job id {job_id:?} is already taken")]
    JobIdCollision { job_id: String },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for UploadJobCreateError {
    fn from(error: rusqlite::Error) -> Self {
        UploadJobCreateError::Persistence(error.into())
    }
}

/// Errors returned while creating an explicit successful-upload repeat.
///
/// A repeat is intentionally separate from [`RetryJobError`]: retries are
/// restricted to failed retryable parents, while an explicit repeat is
/// allowed from a dismissed successful parent and may use a changed input
/// digest (for example, a different destination profile).
#[derive(Debug, thiserror::Error)]
pub enum RepeatUploadJobError {
    #[error("upload job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {job_id:?} is a {operation_kind:?} job, not an upload job")]
    WrongOperationKind {
        job_id: String,
        operation_kind: OperationKind,
    },

    #[error("upload job {job_id:?} is not a successful terminal job (state {state})")]
    NotSuccessful { job_id: String, state: String },

    #[error("upload job {job_id:?} has an unacknowledged terminal outcome")]
    UnacknowledgedParent { job_id: String },

    #[error(
        "repeat spec for upload job {job_id:?} does not match its immutable entry/revision \
         (expected {expected_entry_key:?}@{expected_revision:?}, requested \
         {requested_entry_key:?}@{requested_revision:?})"
    )]
    SpecMismatch {
        job_id: String,
        expected_entry_key: String,
        expected_revision: String,
        requested_entry_key: String,
        requested_revision: String,
    },

    #[error("repeat upload input is invalid: {0}")]
    Invalid(String),

    #[error(
        "upload job {job_id:?} has the same immutable input; matching terminal failures must use retry policy"
    )]
    UnchangedInput { job_id: String },

    #[error("repeat child job id {job_id:?} is already taken")]
    JobIdCollision { job_id: String },

    #[error("repeat child job {job_id:?} conflicts with the requested immutable input: {detail}")]
    ChildConflict { job_id: String, detail: String },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for RepeatUploadJobError {
    fn from(error: rusqlite::Error) -> Self {
        RepeatUploadJobError::Persistence(error.into())
    }
}

/// Errors returned by upload job lifecycle operations. `Stale` is distinct
/// from `AlreadyTerminal`: the former means the caller lost an expected
/// version race, while the latter means a terminal winner is already
/// durable and must never be overwritten.
#[derive(Debug, thiserror::Error)]
pub enum UploadJobError {
    #[error("upload job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {job_id:?} is a {operation_kind:?} job, not an upload job")]
    WrongOperationKind {
        job_id: String,
        operation_kind: OperationKind,
    },

    #[error("upload job {job_id:?} expected version {expected}, actual {actual}")]
    Stale {
        job_id: String,
        expected: u64,
        actual: u64,
    },

    #[error("upload job {job_id:?} is already terminal as {existing}")]
    AlreadyTerminal {
        job_id: String,
        existing: TerminalOutcome,
    },

    #[error("upload job {job_id:?} cannot apply requested lifecycle command: {detail}")]
    IllegalTransition { job_id: String, detail: String },

    #[error("multipart upload {object_key} / {upload_id} belongs to a different job")]
    JobMismatch {
        object_key: String,
        upload_id: String,
    },

    #[error(transparent)]
    Part(#[from] UploadStoreError),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for UploadJobError {
    fn from(error: rusqlite::Error) -> Self {
        UploadJobError::Persistence(error.into())
    }
}

/// One acknowledged part of a multipart upload. `etag` and `size_bytes`
/// are evidence S3 produced, never a local guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPartRecord {
    pub part_number: u32,
    pub etag: String,
    pub size_bytes: u64,
}

/// A `transfer_uploads` row plus its ordered parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUpload {
    pub upload: NewUpload,
    /// `Some` for uploads created by a durable upload job; `None` is kept for
    /// legacy sidecar rows imported before jobs existed.
    pub job_id: Option<String>,
    pub desired_state: UploadDesiredState,
    /// Parts in ascending part-number order.
    pub parts: Vec<UploadPartRecord>,
    pub created_at: String,
    pub updated_at: String,
}

impl StoredUpload {
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.upload.object_key
    }

    #[must_use]
    pub fn upload_id(&self) -> &str {
        &self.upload.upload_id
    }

    /// Bytes S3 has acknowledged for this upload so far.
    #[must_use]
    pub fn confirmed_bytes(&self) -> u64 {
        self.parts.iter().map(|part| part.size_bytes).sum()
    }
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum UploadStoreError {
    /// The same multipart handle is already recorded for a *different*
    /// logical upload. Never merged: two library entries sharing one remote
    /// upload id would make an abort tear down someone else's work.
    #[error(
        "multipart upload {object_key} / {upload_id} is already recorded for a different upload \
         ({detail})"
    )]
    Conflict {
        object_key: String,
        upload_id: String,
        detail: String,
    },

    /// No row for this multipart handle. Recording a part for an upload the
    /// store has never seen is a bug, not something to paper over by
    /// inventing the parent row.
    #[error("no pending upload recorded for {object_key} / {upload_id}")]
    UnknownUpload {
        object_key: String,
        upload_id: String,
    },

    /// A part number already carries different evidence. Part evidence is
    /// write-once: rewriting it would silently change what
    /// `CompleteMultipartUpload` replays.
    #[error(
        "part {part_number} of {object_key} / {upload_id} is already recorded as \
         (etag {existing_etag}, {existing_size} bytes); refusing to overwrite it with \
         (etag {requested_etag}, {requested_size} bytes)"
    )]
    PartConflict {
        object_key: String,
        upload_id: String,
        part_number: u32,
        existing_etag: String,
        existing_size: u64,
        requested_etag: String,
        requested_size: u64,
    },

    /// The supplied record is not addressable at all (empty key/id/bucket).
    #[error("pending upload is unusable: {0}")]
    Invalid(String),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for UploadStoreError {
    fn from(error: rusqlite::Error) -> Self {
        UploadStoreError::Persistence(error.into())
    }
}

/// Errors returned while staging immutable verified-object evidence.
#[derive(Debug, thiserror::Error)]
pub enum UploadReceiptError {
    #[error("upload job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {job_id:?} is a {operation_kind:?} job, not an upload job")]
    WrongOperationKind {
        job_id: String,
        operation_kind: OperationKind,
    },

    #[error(
        "receipt context for upload job {job_id:?} does not match its immutable spec \
         (expected entry {expected_entry_key:?}, revision {expected_revision:?}; \
          requested entry {requested_entry_key:?}, revision {requested_revision:?})"
    )]
    JobContextMismatch {
        job_id: String,
        expected_entry_key: String,
        expected_revision: String,
        requested_entry_key: String,
        requested_revision: String,
    },

    #[error("verified upload receipt is invalid: {0}")]
    Invalid(String),

    #[error(
        "verified upload receipt {job_id:?} / {object_key:?} conflicts with durable evidence: {detail}"
    )]
    Conflict {
        job_id: String,
        object_key: String,
        detail: String,
    },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for UploadReceiptError {
    fn from(error: rusqlite::Error) -> Self {
        UploadReceiptError::Persistence(error.into())
    }
}

// ---------------------------------------------------------------------
// Legacy import
// ---------------------------------------------------------------------

/// Marker written by [`TransferStore::import_legacy_pending_uploads`].
pub const LEGACY_PENDING_UPLOAD_MARKER: &str = "legacy_pending_uploads_v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyUploadImportReport {
    /// `(object_key, upload_id)` pairs newly recorded by this import.
    pub imported: Vec<(String, String)>,
    /// Handles that were already recorded, so nothing was written for them.
    pub skipped_existing: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyUploadImportOutcome {
    /// No sidecar file exists — nothing to do, and no marker is written.
    NoLegacyStore,
    /// A previous run already imported this file. Nothing was read.
    AlreadyImported(MigrationMarker),
    Imported(LegacyUploadImportReport),
}

#[derive(Debug, thiserror::Error)]
pub enum LegacyUploadImportError {
    #[error("failed to read legacy pending-upload store at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The sidecar's bytes are unusable. `object_key` names the specific
    /// record that failed when the failure is per-record. **The file is
    /// never modified by the importer**, so the original data survives a
    /// retry after the cause is fixed — and an empty in-memory state is
    /// never silently substituted for it.
    #[error("legacy pending-upload store at {path} is unusable{}: {detail}",
        .object_key.as_ref().map(|k| format!(" (object {k})")).unwrap_or_default())]
    Corrupt {
        path: PathBuf,
        object_key: Option<String>,
        detail: String,
    },

    #[error(transparent)]
    Upload(#[from] UploadStoreError),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

// ---------------------------------------------------------------------
// TransferStore: upload context
// ---------------------------------------------------------------------

impl TransferStore {
    /// Tables the upload context owns, for schema-review tests.
    #[doc(hidden)]
    pub fn upload_tables() -> &'static [&'static str] {
        &[
            "transfer_upload_job_specs",
            "transfer_upload_activity",
            "transfer_upload_receipts",
            "transfer_uploads",
            "transfer_upload_parts",
        ]
    }

    fn require_upload_job(&self, job_id: &str) -> Result<StoredJob, UploadJobError> {
        let job = self
            .get_job(job_id)?
            .ok_or_else(|| UploadJobError::UnknownJob(job_id.to_string()))?;
        ensure_upload_kind(&job)?;
        Ok(job)
    }

    /// Creates the durable tagged upload job and its immutable natural-key
    /// input in one transaction. Replaying the same entry/revision/input is
    /// an `Existing` hit. A changed input on that natural key, or a different
    /// revision while another attempt for the entry is still live, is an
    /// explicit `Conflict`.
    pub fn create_upload_job(
        &mut self,
        job_id: &str,
        spec: &UploadJobSpec,
        now: &str,
    ) -> Result<UploadJobCreateOutcome, UploadJobCreateError> {
        let activity = UploadActivitySeed::fallback(spec);
        self.create_upload_job_with_activity(job_id, spec, &activity, now)
    }

    /// Creates the durable job, immutable input and upload activity seed in
    /// one transaction. The seed is immutable; confirmed bytes are updated
    /// only after acknowledged data parts.
    pub fn create_upload_job_with_activity(
        &mut self,
        job_id: &str,
        spec: &UploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
    ) -> Result<UploadJobCreateOutcome, UploadJobCreateError> {
        self.create_upload_job_with_activity_inner(job_id, spec, activity, now, None)
    }

    /// Test-only crash injection for the atomic job/spec/activity create.
    #[doc(hidden)]
    pub fn create_upload_job_with_activity_aborting_after(
        &mut self,
        job_id: &str,
        spec: &UploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
        abort: UploadJobCreateAbort,
    ) -> Result<UploadJobCreateOutcome, UploadJobCreateError> {
        self.create_upload_job_with_activity_inner(job_id, spec, activity, now, Some(abort))
    }

    fn create_upload_job_with_activity_inner(
        &mut self,
        job_id: &str,
        spec: &UploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
        abort: Option<UploadJobCreateAbort>,
    ) -> Result<UploadJobCreateOutcome, UploadJobCreateError> {
        validate_upload_job_spec(spec).map_err(UploadJobCreateError::Invalid)?;
        if job_id.trim().is_empty() {
            return Err(UploadJobCreateError::Invalid("job_id is empty".to_string()));
        }
        validate_upload_activity_seed(activity).map_err(UploadJobCreateError::Invalid)?;

        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let existing_same: Option<(String, String)> = tx
            .query_row(
                "SELECT job_id, input_digest FROM transfer_upload_job_specs \
                 WHERE subject_kind = 'library_publication' \
                   AND entry_key = ?1 AND revision = ?2",
                rusqlite::params![spec.entry_key, spec.revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_id, existing_digest)) = existing_same {
            let existing = read_job(&tx, "job_id", &existing_id)?.ok_or_else(|| {
                PersistenceError::corrupt(
                    "transfer_upload_job_specs",
                    format!("upload spec points at missing job {existing_id}"),
                )
            })?;
            if existing.operation_kind != OperationKind::Upload {
                return Err(UploadJobCreateError::Conflict(Box::new(
                    UploadJobConflict {
                        entry_key: spec.entry_key.clone(),
                        existing_job_id: existing_id,
                        existing_revision: spec.revision.clone(),
                        requested_revision: spec.revision.clone(),
                        detail: "natural key is occupied by a non-upload job".to_string(),
                    },
                )));
            }
            if existing_digest == spec.input_digest {
                tx.commit().map_err(PersistenceError::from)?;
                return Ok(UploadJobCreateOutcome::Existing(Box::new(existing)));
            }
            return Err(UploadJobCreateError::Conflict(Box::new(
                UploadJobConflict {
                    entry_key: spec.entry_key.clone(),
                    existing_job_id: existing_id,
                    existing_revision: spec.revision.clone(),
                    requested_revision: spec.revision.clone(),
                    detail: format!(
                        "immutable input differs (stored {existing_digest:?}, requested {:?})",
                        spec.input_digest
                    ),
                },
            )));
        }

        // A live job for the same library entry owns the write target. A
        // newer revision may proceed once the old attempt is terminal; while
        // it is live, report the revision conflict before touching rows.
        let live: Option<(String, String, String)> = tx
            .query_row(
                "SELECT s.job_id, s.revision, s.input_digest \
                 FROM transfer_upload_job_specs s \
                 JOIN transfer_jobs j ON j.job_id = s.job_id \
                 WHERE s.subject_kind = 'library_publication' \
                   AND s.entry_key = ?1 \
                   AND j.state NOT IN ('succeeded', 'failed', 'cancelled') \
                 ORDER BY j.created_at DESC, j.job_id DESC LIMIT 1",
                [spec.entry_key.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((existing_id, existing_revision, _)) = live {
            return Err(UploadJobCreateError::Conflict(Box::new(
                UploadJobConflict {
                    entry_key: spec.entry_key.clone(),
                    existing_job_id: existing_id,
                    existing_revision,
                    requested_revision: spec.revision.clone(),
                    detail: "another upload revision for this entry is still active".to_string(),
                },
            )));
        }

        if let Some(existing) = read_job(&tx, "job_id", job_id)? {
            return Err(UploadJobCreateError::JobIdCollision {
                job_id: existing.job_id,
            });
        }
        let identity = upload_job_identity(&spec.entry_key, &spec.revision)
            .map_err(UploadJobCreateError::Invalid)?;
        let request_digest = upload_input_digest(&spec.input_digest);
        tx.execute(
            "INSERT INTO transfer_jobs (
                 job_id, operation_kind, natural_key, device_id, session_id, revision,
                 request_digest, state, state_version, desired_run_state, created_at, updated_at
             ) VALUES (?1, 'upload', ?2, ?3, ?4, ?5, ?6, 'queued', 1, 'run', ?7, ?7)",
            rusqlite::params![
                job_id,
                format!("upload:{}", spec.natural_key()),
                identity.device_id().as_str(),
                identity.session_id().as_str(),
                identity.revision(),
                request_digest,
                now,
            ],
        )?;
        abort_upload_job_create_if(abort, UploadJobCreateAbort::AfterJob)?;
        tx.execute(
            "INSERT INTO transfer_upload_job_specs \
                 (job_id, entry_key, revision, input_digest, object_prefix) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                job_id,
                spec.entry_key,
                spec.revision,
                spec.input_digest,
                spec.object_prefix,
            ],
        )?;
        abort_upload_job_create_if(abort, UploadJobCreateAbort::AfterSpec)?;
        tx.execute(
            "INSERT INTO transfer_upload_activity (
                 job_id, label, target_label, total_bytes, confirmed_bytes, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            rusqlite::params![
                job_id,
                activity.label,
                activity.target_label,
                checked_i64_upload(activity.total_bytes, "total_bytes")?,
                now,
            ],
        )?;
        abort_upload_job_create_if(abort, UploadJobCreateAbort::AfterActivity)?;
        let job = read_job(&tx, "job_id", job_id)?.ok_or_else(|| PersistenceError::NotFound {
            detail: format!("upload job {job_id} vanished immediately after insert"),
        })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(UploadJobCreateOutcome::Created(Box::new(job)))
    }

    /// Reads the immutable upload input associated with a job.
    pub fn upload_job_spec(&self, job_id: &str) -> Result<Option<UploadJobSpec>, PersistenceError> {
        self.conn
            .query_row(
                "SELECT entry_key, revision, input_digest, object_prefix \
                 FROM transfer_upload_job_specs \
                 WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok(UploadJobSpec {
                        entry_key: row.get(0)?,
                        revision: row.get(1)?,
                        input_digest: row.get(2)?,
                        object_prefix: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Reads one joined upload activity projection, including dismissed and
    /// successful jobs for audit/retry callers.
    pub fn upload_activity(
        &self,
        job_id: &str,
    ) -> Result<Option<StoredUploadActivity>, PersistenceError> {
        let Some(job) = self.get_job(job_id)? else {
            return Ok(None);
        };
        if job.operation_kind != OperationKind::Upload {
            return Ok(None);
        }
        let spec = self.upload_job_spec(job_id)?.ok_or_else(|| {
            PersistenceError::corrupt(
                "transfer_upload_job_specs",
                format!("upload job {job_id} has no immutable activity spec"),
            )
        })?;
        let row: Option<(String, String, i64, i64, String, String)> = self
            .conn
            .query_row(
                "SELECT label, target_label, total_bytes, confirmed_bytes, created_at, updated_at \
                 FROM transfer_upload_activity WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((label, target_label, total_bytes, confirmed_bytes, created_at, updated_at)) = row
        else {
            return Err(PersistenceError::corrupt(
                "transfer_upload_activity",
                format!("upload job {job_id} has no activity row"),
            ));
        };
        let total_bytes = u64::try_from(total_bytes).map_err(|_| {
            PersistenceError::corrupt(
                "transfer_upload_activity",
                format!("upload job {job_id} has negative total_bytes {total_bytes}"),
            )
        })?;
        let confirmed_bytes = u64::try_from(confirmed_bytes).map_err(|_| {
            PersistenceError::corrupt(
                "transfer_upload_activity",
                format!("upload job {job_id} has negative confirmed_bytes {confirmed_bytes}"),
            )
        })?;
        if total_bytes != 0 && confirmed_bytes > total_bytes {
            return Err(PersistenceError::corrupt(
                "transfer_upload_activity",
                format!(
                    "upload job {job_id} confirmed {confirmed_bytes} exceeds total {total_bytes}"
                ),
            ));
        }
        Ok(Some(StoredUploadActivity {
            job,
            spec,
            label,
            target_label,
            total_bytes,
            confirmed_bytes,
            created_at,
            updated_at,
        }))
    }

    /// Lists the visible upload activity lane. Successful jobs retain their
    /// durable activity for audit but follow the existing tray contract and
    /// disappear after completion; explicit dismissals are filtered by the
    /// general job tombstone.
    pub fn list_upload_activities(&self) -> Result<Vec<StoredUploadActivity>, PersistenceError> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id FROM transfer_jobs \
             WHERE operation_kind = 'upload' AND dismissed_at IS NULL \
               AND (state <> 'succeeded' OR NOT EXISTS (\
                   SELECT 1 FROM transfer_completion_outbox o \
                   WHERE o.job_id = transfer_jobs.job_id \
                     AND o.acknowledged_at IS NOT NULL\
               )) \
             ORDER BY created_at DESC, job_id DESC",
        )?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|job_id| {
                self.upload_activity(&job_id)?.ok_or_else(|| {
                    PersistenceError::corrupt(
                        "transfer_upload_activity",
                        format!("visible upload job {job_id} disappeared while listing"),
                    )
                })
            })
            .collect()
    }

    /// Stages a complete batch of verified object receipts for one upload
    /// attempt. The caller supplies the expected entry/revision context as an
    /// explicit fence; this method checks it against the immutable upload job
    /// spec before opening the write transaction.
    ///
    /// Every receipt in the batch is written atomically. Replaying an
    /// identical row is a no-op and returns the same durable projection. A
    /// changed proof, role, size or object-store version for an existing key
    /// is a conflict, and the whole batch is rolled back. Receipt rows are
    /// never deleted by multipart cleanup or dismissal.
    pub fn stage_upload_receipts(
        &mut self,
        job_id: &str,
        entry_key: &str,
        revision: &str,
        receipts: &[UploadReceiptSeed],
        staged_at: &str,
    ) -> Result<Vec<StoredUploadReceipt>, UploadReceiptError> {
        if job_id.trim().is_empty() {
            return Err(UploadReceiptError::Invalid("job_id is empty".to_string()));
        }
        if entry_key.trim().is_empty() {
            return Err(UploadReceiptError::Invalid(
                "entry_key is empty".to_string(),
            ));
        }
        if revision.trim().is_empty() {
            return Err(UploadReceiptError::Invalid("revision is empty".to_string()));
        }
        if staged_at.trim().is_empty() {
            return Err(UploadReceiptError::Invalid(
                "staged_at is empty".to_string(),
            ));
        }

        // Validate all values before starting the transaction. This also
        // rejects duplicate object keys in one batch rather than letting the
        // order of INSERTs decide which role wins.
        let mut normalized = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            let mut normalized_receipt = receipt.clone();
            validate_upload_receipt_seed(&mut normalized_receipt)
                .map_err(UploadReceiptError::Invalid)?;
            if normalized
                .iter()
                .any(|seen: &UploadReceiptSeed| seen.object_key == normalized_receipt.object_key)
            {
                return Err(UploadReceiptError::Invalid(format!(
                    "object key {:?} appears more than once in one receipt batch",
                    normalized_receipt.object_key
                )));
            }
            normalized.push(normalized_receipt);
        }

        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let job = read_job(&tx, "job_id", job_id)?
            .ok_or_else(|| UploadReceiptError::UnknownJob(job_id.to_string()))?;
        if job.operation_kind != OperationKind::Upload {
            return Err(UploadReceiptError::WrongOperationKind {
                job_id: job_id.to_string(),
                operation_kind: job.operation_kind,
            });
        }
        let expected_context: Option<(String, String)> = tx
            .query_row(
                "SELECT entry_key, revision FROM transfer_upload_job_specs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((expected_entry_key, expected_revision)) = expected_context else {
            return Err(UploadReceiptError::Persistence(PersistenceError::corrupt(
                "transfer_upload_job_specs",
                format!("upload job {job_id} has no immutable receipt context"),
            )));
        };
        if expected_entry_key != entry_key || expected_revision != revision {
            return Err(UploadReceiptError::JobContextMismatch {
                job_id: job_id.to_string(),
                expected_entry_key,
                expected_revision,
                requested_entry_key: entry_key.to_string(),
                requested_revision: revision.to_string(),
            });
        }

        for receipt in &normalized {
            let existing: Option<StoredUploadReceipt> = tx
                .query_row(
                    "SELECT job_id, entry_key, revision, object_key, object_role, etag, \
                            version_id, size_bytes, source_sha256, digest_proof, staged_at \
                     FROM transfer_upload_receipts \
                     WHERE job_id = ?1 AND object_key = ?2",
                    rusqlite::params![job_id, receipt.object_key],
                    read_upload_receipt_row,
                )
                .optional()?;
            if let Some(existing) = existing {
                if !upload_receipt_matches_seed(&existing, entry_key, revision, receipt) {
                    return Err(UploadReceiptError::Conflict {
                        job_id: job_id.to_string(),
                        object_key: receipt.object_key.clone(),
                        detail: describe_upload_receipt_conflict(
                            &existing, entry_key, revision, receipt,
                        ),
                    });
                }
                continue;
            }

            tx.execute(
                "INSERT INTO transfer_upload_receipts (\
                     job_id, entry_key, revision, object_key, object_role, etag, version_id,\
                     size_bytes, source_sha256, digest_proof, staged_at\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    job_id,
                    entry_key,
                    revision,
                    receipt.object_key,
                    receipt.role.as_db_str(),
                    receipt.etag,
                    receipt.version_id,
                    checked_i64_upload(receipt.size_bytes, "receipt size_bytes")?,
                    receipt.source_sha256,
                    receipt.digest_proof.as_db_str(),
                    staged_at,
                ],
            )?;
        }

        let staged = read_upload_receipt_rows(&tx, job_id, None)?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(staged)
    }

    /// Stages receipts while deriving the entry/revision fence from the
    /// immutable upload job spec. This is the preferred form for callers that
    /// already trust the durable job id and do not need to repeat its context.
    pub fn stage_upload_receipts_for_job(
        &mut self,
        job_id: &str,
        receipts: &[UploadReceiptSeed],
        staged_at: &str,
    ) -> Result<Vec<StoredUploadReceipt>, UploadReceiptError> {
        let Some(job) = self.get_job(job_id)? else {
            return Err(UploadReceiptError::UnknownJob(job_id.to_string()));
        };
        if job.operation_kind != OperationKind::Upload {
            return Err(UploadReceiptError::WrongOperationKind {
                job_id: job_id.to_string(),
                operation_kind: job.operation_kind,
            });
        }
        let spec = self.upload_job_spec(job_id)?.ok_or_else(|| {
            UploadReceiptError::Persistence(PersistenceError::corrupt(
                "transfer_upload_job_specs",
                format!("upload job {job_id} has no immutable receipt context"),
            ))
        })?;
        self.stage_upload_receipts(job_id, &spec.entry_key, &spec.revision, receipts, staged_at)
    }

    /// Reads every immutable verified receipt for an upload job in
    /// deterministic object-key order. Multipart rows may already have been
    /// retired; receipt rows remain available for completion projection and
    /// audit. An unknown job simply has no receipts.
    pub fn list_upload_receipts(
        &self,
        job_id: &str,
    ) -> Result<Vec<StoredUploadReceipt>, UploadReceiptError> {
        read_upload_receipt_rows(&self.conn, job_id, None)
    }

    /// Alias for callers that use the shorter retrieval spelling.
    pub fn upload_receipts(
        &self,
        job_id: &str,
    ) -> Result<Vec<StoredUploadReceipt>, UploadReceiptError> {
        self.list_upload_receipts(job_id)
    }

    /// Reads one receipt by object key, preserving the distinction between a
    /// missing object and a corrupt durable row.
    pub fn upload_receipt(
        &self,
        job_id: &str,
        object_key: &str,
    ) -> Result<Option<StoredUploadReceipt>, UploadReceiptError> {
        let mut rows = read_upload_receipt_rows(&self.conn, job_id, Some(object_key))?;
        Ok(rows.pop())
    }

    /// Compatibility alias for the explicit verified-object wording.
    pub fn list_verified_upload_receipts(
        &self,
        job_id: &str,
    ) -> Result<Vec<StoredUploadReceipt>, UploadReceiptError> {
        self.list_upload_receipts(job_id)
    }

    /// Starts an upload through the shared `JobAggregate` graph and a
    /// single expected-version CAS. A queued upload enters `preparing`;
    /// callers can then drive the worker reports independently.
    pub fn start_upload_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        now: &str,
    ) -> Result<u64, UploadJobError> {
        let job = self.require_upload_job(job_id)?;
        check_expected_version(&job, expected_version)?;
        let current = persisted_state(&job)?;
        let decision = JobAggregate::new(current)
            .with_version(expected_version)
            .decide(JobCommand::Transition(TransferJobState::Preparing));
        if decision.outcome.is_rejected() {
            return Err(UploadJobError::IllegalTransition {
                job_id: job_id.to_string(),
                detail: format!("cannot start from {}", job.state.as_db_str()),
            });
        }
        self.transition_job(job_id, expected_version, JobStateTag::Preparing, None, now)
            .map_err(map_upload_persistence_error)
    }

    /// Completes an upload with the terminal outbox CAS. The first writer
    /// whose expected version still matches wins; a late writer receives
    /// `Stale` or `AlreadyTerminal` and cannot overwrite the evidence.
    pub fn complete_upload_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        outcome: &TerminalOutcome,
        now: &str,
    ) -> Result<CompleteJobOutcome, UploadJobError> {
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let job = read_job(&tx, "job_id", job_id)?
            .ok_or_else(|| UploadJobError::UnknownJob(job_id.to_string()))?;
        ensure_upload_kind(&job)?;
        if job.state.is_terminal() {
            let existing = terminal_outcome(&job)?;
            return Err(UploadJobError::AlreadyTerminal {
                job_id: job_id.to_string(),
                existing,
            });
        }
        if job.state_version != expected_version {
            return Err(UploadJobError::Stale {
                job_id: job_id.to_string(),
                expected: expected_version,
                actual: job.state_version,
            });
        }
        let next_version = expected_version.checked_add(1).ok_or_else(|| {
            UploadJobError::Persistence(PersistenceError::Conflict {
                detail: format!("upload job {job_id} state version exhausted"),
            })
        })?;
        let (error_code, error_retryable) = match outcome {
            TerminalOutcome::Failed { code, retryable } => {
                (Some(code.as_str()), Some(i64::from(*retryable)))
            }
            _ => (None, None),
        };
        let changed = tx.execute(
            "UPDATE transfer_jobs SET state = ?2, state_version = ?3, error_code = ?4, \
             error_retryable = ?5, updated_at = ?6 \
             WHERE job_id = ?1 AND operation_kind = 'upload' AND state_version = ?7 \
               AND state NOT IN ('succeeded', 'failed', 'cancelled')",
            rusqlite::params![
                job_id,
                outcome.as_db_str(),
                i64::try_from(next_version).map_err(|_| UploadJobError::Persistence(
                    PersistenceError::Conflict {
                        detail: "state version exceeds SQLite range".into()
                    }
                ))?,
                error_code,
                error_retryable,
                now,
                i64::try_from(expected_version).map_err(|_| UploadJobError::Persistence(
                    PersistenceError::Conflict {
                        detail: "expected version exceeds SQLite range".into()
                    }
                ))?,
            ],
        )?;
        if changed == 0 {
            return Err(UploadJobError::Stale {
                job_id: job_id.to_string(),
                expected: expected_version,
                actual: read_job(&tx, "job_id", job_id)?
                    .map(|j| j.state_version)
                    .unwrap_or(expected_version),
            });
        }
        // Keep the durable activity projection and terminal outbox in the
        // same transaction. We intentionally do not fabricate a final byte
        // count here: only acknowledged data-part writes may advance it.
        let activity_changed = tx.execute(
            "UPDATE transfer_upload_activity SET updated_at = ?2 WHERE job_id = ?1",
            rusqlite::params![job_id, now],
        )?;
        if activity_changed == 0 {
            return Err(UploadJobError::Persistence(PersistenceError::corrupt(
                "transfer_upload_activity",
                format!("upload job {job_id} has no activity row"),
            )));
        }
        let record = insert_upload_outbox_row(&tx, job_id, outcome, next_version, now)?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(CompleteJobOutcome::Recorded(Box::new(record)))
    }

    /// Alias used by callers that call the terminal operation "finish".
    pub fn finish_upload_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        outcome: &TerminalOutcome,
        now: &str,
    ) -> Result<CompleteJobOutcome, UploadJobError> {
        self.complete_upload_job(job_id, expected_version, outcome, now)
    }

    /// Cancel is a terminal command for upload jobs. It uses the same
    /// terminal CAS/outbox path as finish, so cancel-first and finish-first
    /// races have one durable winner.
    pub fn cancel_upload_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        now: &str,
    ) -> Result<CompleteJobOutcome, UploadJobError> {
        self.complete_upload_job(job_id, expected_version, &TerminalOutcome::Cancelled, now)
    }

    /// Retry an upload through the existing durable parent/child lineage.
    /// The failed parent remains terminal and its multipart evidence is not
    /// deleted; only the child receives a fresh job id and immutable spec.
    pub fn retry_upload_job(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        now: &str,
    ) -> Result<RetryJobOutcome, RetryJobError> {
        self.spawn_upload_retry_job(parent_job_id, child_job_id, now)
    }

    /// Creates a fresh child for an explicit successful-upload repeat.
    ///
    /// The successful parent remains immutable history. The child gets its
    /// own natural key, immutable input/spec, zeroed activity and lineage
    /// row. Receipt evidence is deliberately not copied: it belongs to the
    /// completed parent attempt and can only be staged again by the child
    /// after its own objects have been verified.
    ///
    /// A write transaction is started with an immediate SQLite lock before
    /// checking for an active child. That makes two concurrent repeat calls
    /// serialize around the active-child fence, so the loser returns the
    /// child the winner already created rather than leaving an unowned
    /// queued/preparing sibling.
    pub fn repeat_upload_job(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        spec: &UploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
    ) -> Result<RetryJobOutcome, RepeatUploadJobError> {
        self.repeat_upload_job_inner(parent_job_id, child_job_id, spec, activity, now, false)
    }

    /// Creates a fresh child for an explicit library action whose terminal
    /// parent used a changed destination/input. Failed and cancelled parents
    /// are accepted only when the requested immutable input differs from the
    /// parent; matching terminal failures must continue through retry policy.
    /// Successful parents retain the ordinary repeat semantics and may repeat
    /// with either the same or a changed destination.
    pub fn supersede_upload_job(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        spec: &UploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
    ) -> Result<RetryJobOutcome, RepeatUploadJobError> {
        self.repeat_upload_job_inner(parent_job_id, child_job_id, spec, activity, now, true)
    }

    fn repeat_upload_job_inner(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        spec: &UploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
        allow_terminal_supersede: bool,
    ) -> Result<RetryJobOutcome, RepeatUploadJobError> {
        validate_upload_job_spec(spec).map_err(RepeatUploadJobError::Invalid)?;
        if child_job_id.trim().is_empty() {
            return Err(RepeatUploadJobError::Invalid(
                "child_job_id is empty".to_string(),
            ));
        }
        validate_upload_activity_seed(activity).map_err(RepeatUploadJobError::Invalid)?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(PersistenceError::from)?;
        let parent = read_job(&tx, "job_id", parent_job_id)?
            .ok_or_else(|| RepeatUploadJobError::UnknownJob(parent_job_id.to_string()))?;
        if parent.operation_kind != OperationKind::Upload {
            return Err(RepeatUploadJobError::WrongOperationKind {
                job_id: parent_job_id.to_string(),
                operation_kind: parent.operation_kind,
            });
        }
        let terminal_supersede = allow_terminal_supersede
            && matches!(parent.state, JobStateTag::Failed | JobStateTag::Cancelled);
        if parent.state != JobStateTag::Succeeded && !terminal_supersede {
            return Err(RepeatUploadJobError::NotSuccessful {
                job_id: parent_job_id.to_string(),
                state: parent.state.as_db_str().to_string(),
            });
        }

        // A terminal state without an acknowledged completion is not a
        // repeatable user-visible success. Treat a missing outbox row as the
        // same durable invariant violation as an unacknowledged row.
        let acknowledged_at: Option<Option<String>> = tx
            .query_row(
                "SELECT acknowledged_at FROM transfer_completion_outbox WHERE job_id = ?1",
                [parent_job_id],
                |row| row.get(0),
            )
            .optional()?;
        if !matches!(acknowledged_at, Some(Some(_))) {
            return Err(RepeatUploadJobError::UnacknowledgedParent {
                job_id: parent_job_id.to_string(),
            });
        }

        let (parent_entry_key, parent_revision, parent_input_digest): (String, String, String) = tx
            .query_row(
                "SELECT entry_key, revision, input_digest \
                 FROM transfer_upload_job_specs \
                 WHERE job_id = ?1",
                [parent_job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| {
                RepeatUploadJobError::Persistence(PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_upload_job_specs"),
                    detail: format!(
                        "successful upload repeat parent {parent_job_id} has no immutable spec: \
                         {error}"
                    ),
                })
            })?;
        if terminal_supersede
            && parent_input_digest == spec.input_digest
            && parent.dismissed_at.is_none()
        {
            return Err(RepeatUploadJobError::UnchangedInput {
                job_id: parent_job_id.to_string(),
            });
        }
        if parent_entry_key != spec.entry_key || parent_revision != spec.revision {
            return Err(RepeatUploadJobError::SpecMismatch {
                job_id: parent_job_id.to_string(),
                expected_entry_key: parent_entry_key,
                expected_revision: parent_revision,
                requested_entry_key: spec.entry_key.clone(),
                requested_revision: spec.revision.clone(),
            });
        }
        // Replaying a caller-supplied child id is idempotent only when that
        // id is already linked to this parent. A globally reused id is a
        // collision, even if its current row is terminal.
        if let Some(existing) = read_job(&tx, "job_id", child_job_id)? {
            let linked_parent: Option<String> = tx
                .query_row(
                    "SELECT parent_job_id FROM transfer_job_lineage WHERE child_job_id = ?1",
                    [child_job_id],
                    |row| row.get(0),
                )
                .optional()?;
            if linked_parent.as_deref() == Some(parent_job_id) {
                if !repeat_child_matches(&tx, child_job_id, spec, activity)? {
                    return Err(RepeatUploadJobError::ChildConflict {
                        job_id: child_job_id.to_string(),
                        detail: "replayed child id has different spec or activity metadata"
                            .to_string(),
                    });
                }
                return Ok(RetryJobOutcome::Existing(Box::new(existing)));
            }
            return Err(RepeatUploadJobError::JobIdCollision {
                job_id: child_job_id.to_string(),
            });
        }

        // One live child per successful parent is the duplicate-click and
        // restart fence. Once that child is terminal, a later explicit
        // repeat may create another attempt with the next lineage number.
        let active_child_id: Option<String> = tx
            .query_row(
                "SELECT l.child_job_id FROM transfer_job_lineage l \
                 JOIN transfer_jobs j ON j.job_id = l.child_job_id \
                 WHERE l.parent_job_id = ?1 \
                   AND j.operation_kind = 'upload' \
                   AND j.state NOT IN ('succeeded', 'failed', 'cancelled') \
                 ORDER BY l.attempt DESC LIMIT 1",
                [parent_job_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(active_child_id) = active_child_id {
            let existing = read_job(&tx, "job_id", &active_child_id)?.ok_or_else(|| {
                RepeatUploadJobError::Persistence(PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_job_lineage"),
                    detail: format!(
                        "repeat parent {parent_job_id} points at missing active child \
                         {active_child_id}"
                    ),
                })
            })?;
            if !repeat_child_matches(&tx, &active_child_id, spec, activity)? {
                return Err(RepeatUploadJobError::ChildConflict {
                    job_id: active_child_id,
                    detail: "an active repeat already owns a different spec or activity metadata"
                        .to_string(),
                });
            }
            return Ok(RetryJobOutcome::Existing(Box::new(existing)));
        }

        let previous_attempt: i64 = tx.query_row(
            "SELECT COALESCE(MAX(attempt), 0) FROM transfer_job_lineage WHERE parent_job_id = ?1",
            [parent_job_id],
            |row| row.get(0),
        )?;
        let previous_attempt = u64::try_from(previous_attempt).map_err(|_| {
            RepeatUploadJobError::Persistence(PersistenceError::Corrupt {
                path: PathBuf::from("transfer_job_lineage"),
                detail: format!(
                    "repeat parent {parent_job_id} has a negative lineage attempt \
                     {previous_attempt}"
                ),
            })
        })?;
        let attempt = previous_attempt.checked_add(1).ok_or_else(|| {
            RepeatUploadJobError::Persistence(PersistenceError::Conflict {
                detail: format!("repeat attempt for {parent_job_id} exhausted SQLite range"),
            })
        })?;
        let attempt = i64::try_from(attempt).map_err(|_| {
            RepeatUploadJobError::Persistence(PersistenceError::Conflict {
                detail: format!("repeat attempt for {parent_job_id} exceeds SQLite range"),
            })
        })?;

        let request_digest = upload_input_digest(&spec.input_digest);
        let natural_key = format!(
            "upload:{}#repeat:{}",
            parent.identity.natural_key(),
            child_job_id
        );
        tx.execute(
            "INSERT INTO transfer_jobs (
                 job_id, operation_kind, natural_key, device_id, session_id, revision,
                 request_digest, state, state_version, desired_run_state, created_at, updated_at
             ) VALUES (?1, 'upload', ?2, ?3, ?4, ?5, ?6, 'queued', 1, 'run', ?7, ?7)",
            rusqlite::params![
                child_job_id,
                natural_key,
                parent.identity.device_id().as_str(),
                parent.identity.session_id().as_str(),
                parent.identity.revision(),
                request_digest,
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_upload_job_specs \
                 (job_id, entry_key, revision, input_digest, object_prefix) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                child_job_id,
                spec.entry_key,
                spec.revision,
                spec.input_digest,
                spec.object_prefix,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_upload_activity (
                 job_id, label, target_label, total_bytes, confirmed_bytes, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            rusqlite::params![
                child_job_id,
                activity.label,
                activity.target_label,
                checked_i64_upload(activity.total_bytes, "total_bytes")?,
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_job_lineage (child_job_id, parent_job_id, attempt, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![child_job_id, parent_job_id, attempt, now],
        )?;
        let child = read_job(&tx, "job_id", child_job_id)?.ok_or_else(|| {
            RepeatUploadJobError::Persistence(PersistenceError::NotFound {
                detail: format!("repeat child {child_job_id} vanished after insert"),
            })
        })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(RetryJobOutcome::Created(Box::new(child)))
    }

    /// Records a multipart upload that now really exists remotely, with
    /// `desired_state = running`.
    ///
    /// Called **before the first part is sent**, which is the whole point:
    /// from the moment this commits, a crash leaves a durable record this
    /// or a later process can abort, instead of billable parts nobody knows
    /// about.
    ///
    /// The remote multipart-create response and this SQLite insert are two
    /// different resource managers and cannot be one atomic transaction. A
    /// crash after the provider returns `upload_id` but before this method
    /// commits can leave an untracked remote handle. Callers must use the
    /// strongest available saga: persist immediately, retry idempotently, and
    /// run provider-side orphan listing/retention cleanup when the object
    /// store exposes it. The durable row is the guarantee only after this
    /// method returns `Ok`; it must not be described as covering that
    /// response-ID window.
    ///
    /// Idempotent for a byte-identical record (a retried write after a
    /// partial failure is safe); a *different* record on the same multipart
    /// handle is [`UploadStoreError::Conflict`], never a silent overwrite.
    pub fn begin_upload(
        &mut self,
        upload: &NewUpload,
        now: &str,
    ) -> Result<StoredUpload, UploadStoreError> {
        validate_new_upload(upload)?;
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;

        if let Some(existing) = read_upload(&tx, &upload.object_key, &upload.upload_id)? {
            if existing.upload != *upload {
                return Err(UploadStoreError::Conflict {
                    object_key: upload.object_key.clone(),
                    upload_id: upload.upload_id.clone(),
                    detail: describe_upload_mismatch(&existing.upload, upload),
                });
            }
            return Ok(existing);
        }

        tx.execute(
            "INSERT INTO transfer_uploads (
                 object_key, upload_id, transfer_key, entry_key, revision, endpoint, bucket,
                 url_style, desired_state, created_at, updated_at, job_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'running', ?9, ?9, NULL)",
            rusqlite::params![
                upload.object_key,
                upload.upload_id,
                upload.transfer_key,
                upload.entry_key,
                upload.revision,
                upload.endpoint,
                upload.bucket,
                upload.url_style.as_db_str(),
                now,
            ],
        )?;
        let stored = read_upload(&tx, &upload.object_key, &upload.upload_id)?.ok_or_else(|| {
            UploadStoreError::Persistence(PersistenceError::NotFound {
                detail: format!(
                    "pending upload {} / {} vanished immediately after insert",
                    upload.object_key, upload.upload_id
                ),
            })
        })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(stored)
    }

    /// Records a multipart handle for a specific upload job. The job kind
    /// and expected version are checked in the same transaction as the row
    /// insert, so a terminal or stale caller cannot leave a late orphan
    /// attached to a completed job.
    pub fn begin_upload_for_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        upload: &NewUpload,
        now: &str,
    ) -> Result<StoredUpload, UploadJobError> {
        validate_new_upload(upload)?;
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let job = read_job(&tx, "job_id", job_id)?
            .ok_or_else(|| UploadJobError::UnknownJob(job_id.to_string()))?;
        ensure_upload_kind(&job)?;
        check_expected_version(&job, expected_version)?;
        if job.state.is_terminal() {
            return Err(UploadJobError::AlreadyTerminal {
                job_id: job_id.to_string(),
                existing: terminal_outcome(&job)?,
            });
        }
        if let Some(existing) = read_upload(&tx, &upload.object_key, &upload.upload_id)? {
            if existing.upload != *upload || existing.job_id.as_deref() != Some(job_id) {
                return Err(UploadJobError::JobMismatch {
                    object_key: upload.object_key.clone(),
                    upload_id: upload.upload_id.clone(),
                });
            }
            tx.commit().map_err(PersistenceError::from)?;
            return Ok(existing);
        }
        tx.execute(
            "INSERT INTO transfer_uploads (
                 object_key, upload_id, transfer_key, entry_key, revision, endpoint, bucket,
                 url_style, desired_state, created_at, updated_at, job_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'running', ?9, ?9, ?10)",
            rusqlite::params![
                upload.object_key,
                upload.upload_id,
                upload.transfer_key,
                upload.entry_key,
                upload.revision,
                upload.endpoint,
                upload.bucket,
                upload.url_style.as_db_str(),
                now,
                job_id,
            ],
        )?;
        let stored = read_upload(&tx, &upload.object_key, &upload.upload_id)?.ok_or_else(|| {
            UploadJobError::Persistence(PersistenceError::NotFound {
                detail: format!(
                    "pending upload {} / {} vanished after insert",
                    upload.object_key, upload.upload_id
                ),
            })
        })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(stored)
    }

    /// Records one part S3 has acknowledged.
    ///
    /// Write-once: replaying the identical part is a no-op (so a crash
    /// between the PUT and this write converges), but a different
    /// etag/size for the same part number is
    /// [`UploadStoreError::PartConflict`].
    pub fn record_upload_part(
        &mut self,
        object_key: &str,
        upload_id: &str,
        part: &UploadPartRecord,
        now: &str,
    ) -> Result<(), UploadStoreError> {
        if part.part_number == 0 {
            return Err(UploadStoreError::Invalid(
                "part numbers start at 1".to_string(),
            ));
        }
        if part.etag.trim().is_empty() {
            return Err(UploadStoreError::Invalid(format!(
                "part {} has no etag",
                part.part_number
            )));
        }
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        if read_upload_row(&tx, object_key, upload_id)?.is_none() {
            return Err(UploadStoreError::UnknownUpload {
                object_key: object_key.to_string(),
                upload_id: upload_id.to_string(),
            });
        }

        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT etag, size_bytes FROM transfer_upload_parts \
                 WHERE object_key = ?1 AND upload_id = ?2 AND part_number = ?3",
                rusqlite::params![object_key, upload_id, i64::from(part.part_number)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((etag, size)) = existing {
            let size = u64::try_from(size).map_err(|_| {
                UploadStoreError::Persistence(PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_upload_parts"),
                    detail: format!(
                        "part {} of {object_key} / {upload_id} has negative size {size}",
                        part.part_number
                    ),
                })
            })?;
            if etag == part.etag && size == part.size_bytes {
                return Ok(());
            }
            return Err(UploadStoreError::PartConflict {
                object_key: object_key.to_string(),
                upload_id: upload_id.to_string(),
                part_number: part.part_number,
                existing_etag: etag,
                existing_size: size,
                requested_etag: part.etag.clone(),
                requested_size: part.size_bytes,
            });
        }

        let size_bytes = i64::try_from(part.size_bytes).map_err(|_| {
            UploadStoreError::Invalid(format!(
                "part {} size {} exceeds SQLite INTEGER range",
                part.part_number, part.size_bytes
            ))
        })?;
        tx.execute(
            "INSERT INTO transfer_upload_parts (
                 object_key, upload_id, part_number, etag, size_bytes, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                object_key,
                upload_id,
                i64::from(part.part_number),
                part.etag,
                size_bytes,
                now,
            ],
        )?;
        tx.execute(
            "UPDATE transfer_uploads SET updated_at = ?3 WHERE object_key = ?1 AND upload_id = ?2",
            rusqlite::params![object_key, upload_id, now],
        )?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(())
    }

    /// Job-aware part evidence write. Unlike the legacy handle-only method,
    /// this rejects a terminal job or stale expected version before writing.
    pub fn record_upload_part_for_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        object_key: &str,
        upload_id: &str,
        part: &UploadPartRecord,
        now: &str,
    ) -> Result<(), UploadJobError> {
        self.record_upload_part_for_job_with_progress(
            job_id,
            expected_version,
            object_key,
            upload_id,
            part,
            None,
            now,
        )
    }

    /// Job-aware part write with an optional data-file progress contribution.
    /// `Some(bytes)` is reserved for acknowledged data-file parts; evidence
    /// and manifest parts pass `None`. Part insertion and aggregate progress
    /// update commit together, and an identical duplicate is a no-op.
    #[allow(clippy::too_many_arguments)]
    pub fn record_upload_part_for_job_with_progress(
        &mut self,
        job_id: &str,
        expected_version: u64,
        object_key: &str,
        upload_id: &str,
        part: &UploadPartRecord,
        progress_bytes: Option<u64>,
        now: &str,
    ) -> Result<(), UploadJobError> {
        validate_part(part).map_err(UploadJobError::Part)?;
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let job = read_job(&tx, "job_id", job_id)?
            .ok_or_else(|| UploadJobError::UnknownJob(job_id.to_string()))?;
        ensure_upload_kind(&job)?;
        check_expected_version(&job, expected_version)?;
        if job.state.is_terminal() {
            return Err(UploadJobError::AlreadyTerminal {
                job_id: job_id.to_string(),
                existing: terminal_outcome(&job)?,
            });
        }
        let stored_job: Option<String> = tx
            .query_row(
                "SELECT job_id FROM transfer_uploads WHERE object_key = ?1 AND upload_id = ?2",
                rusqlite::params![object_key, upload_id],
                |row| row.get(0),
            )
            .optional()?;
        if stored_job.as_deref() != Some(job_id) {
            return Err(UploadJobError::JobMismatch {
                object_key: object_key.to_string(),
                upload_id: upload_id.to_string(),
            });
        }
        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT etag, size_bytes FROM transfer_upload_parts \
                 WHERE object_key = ?1 AND upload_id = ?2 AND part_number = ?3",
                rusqlite::params![object_key, upload_id, i64::from(part.part_number)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((etag, size)) = existing {
            let size = u64::try_from(size).map_err(|_| {
                UploadJobError::Persistence(PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_upload_parts"),
                    detail: format!("negative part size {size}"),
                })
            })?;
            if etag == part.etag && size == part.size_bytes {
                tx.commit().map_err(PersistenceError::from)?;
                return Ok(());
            }
            return Err(UploadJobError::Part(UploadStoreError::PartConflict {
                object_key: object_key.to_string(),
                upload_id: upload_id.to_string(),
                part_number: part.part_number,
                existing_etag: etag,
                existing_size: size,
                requested_etag: part.etag.clone(),
                requested_size: part.size_bytes,
            }));
        }
        tx.execute(
            "INSERT INTO transfer_upload_parts (
                 object_key, upload_id, part_number, etag, size_bytes, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                object_key,
                upload_id,
                i64::from(part.part_number),
                part.etag,
                i64::try_from(part.size_bytes).map_err(|_| UploadJobError::Part(
                    UploadStoreError::Invalid("part size exceeds SQLite range".to_string())
                ))?,
                now,
            ],
        )?;
        tx.execute(
            "UPDATE transfer_uploads SET updated_at = ?3 WHERE object_key = ?1 AND upload_id = ?2",
            rusqlite::params![object_key, upload_id, now],
        )?;
        if let Some(progress_bytes) = progress_bytes {
            let (total_bytes, confirmed_bytes): (i64, i64) = tx.query_row(
                "SELECT total_bytes, confirmed_bytes FROM transfer_upload_activity WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(|error| UploadJobError::Persistence(PersistenceError::corrupt(
                "transfer_upload_activity",
                format!("upload job {job_id} has no readable activity row: {error}"),
            )))?;
            let total_bytes = u64::try_from(total_bytes).map_err(|_| {
                UploadJobError::Persistence(PersistenceError::corrupt(
                    "transfer_upload_activity",
                    format!("upload job {job_id} has negative total_bytes {total_bytes}"),
                ))
            })?;
            let confirmed_bytes = u64::try_from(confirmed_bytes).map_err(|_| {
                UploadJobError::Persistence(PersistenceError::corrupt(
                    "transfer_upload_activity",
                    format!("upload job {job_id} has negative confirmed_bytes {confirmed_bytes}"),
                ))
            })?;
            let next = confirmed_bytes.checked_add(progress_bytes).ok_or_else(|| {
                UploadJobError::Persistence(PersistenceError::Conflict {
                    detail: format!("upload job {job_id} confirmed progress overflow"),
                })
            })?;
            if total_bytes != 0 && next > total_bytes {
                return Err(UploadJobError::Persistence(PersistenceError::Conflict {
                    detail: format!(
                        "upload job {job_id} progress {next} exceeds total {total_bytes}"
                    ),
                }));
            }
            tx.execute(
                "UPDATE transfer_upload_activity SET confirmed_bytes = ?2, updated_at = ?3 \
                 WHERE job_id = ?1",
                rusqlite::params![job_id, checked_i64_upload(next, "confirmed_bytes")?, now,],
            )?;
        }
        tx.commit().map_err(PersistenceError::from)?;
        Ok(())
    }

    /// Changes what should happen to an upload. `false` means there is no
    /// such record (already finished, or never started).
    pub fn set_upload_desired_state(
        &mut self,
        object_key: &str,
        upload_id: &str,
        desired: UploadDesiredState,
        now: &str,
    ) -> Result<bool, PersistenceError> {
        let changed = self.conn.execute(
            "UPDATE transfer_uploads SET desired_state = ?3, updated_at = ?4 \
             WHERE object_key = ?1 AND upload_id = ?2",
            rusqlite::params![object_key, upload_id, desired.as_db_str(), now],
        )?;
        Ok(changed > 0)
    }

    /// Retires an upload that has been completed or aborted **for real**,
    /// dropping its parts with it in one transaction.
    ///
    /// The row's absence is the only "this upload is accounted for" signal,
    /// so this must be called after the remote side is actually gone — not
    /// before.
    pub fn finish_upload(
        &mut self,
        object_key: &str,
        upload_id: &str,
    ) -> Result<bool, PersistenceError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM transfer_upload_parts WHERE object_key = ?1 AND upload_id = ?2",
            rusqlite::params![object_key, upload_id],
        )?;
        let removed = tx.execute(
            "DELETE FROM transfer_uploads WHERE object_key = ?1 AND upload_id = ?2",
            rusqlite::params![object_key, upload_id],
        )?;
        tx.commit()?;
        Ok(removed > 0)
    }

    pub fn pending_upload(
        &self,
        object_key: &str,
        upload_id: &str,
    ) -> Result<Option<StoredUpload>, UploadStoreError> {
        read_upload(&self.conn, object_key, upload_id)
    }

    /// Every recorded multipart upload, oldest first.
    pub fn list_pending_uploads(&self) -> Result<Vec<StoredUpload>, UploadStoreError> {
        read_uploads(&self.conn, None)
    }

    /// **Startup recovery.** Flips every surviving record to `aborting` and
    /// returns them, in one transaction.
    ///
    /// A record that is still here when a process starts was created by a
    /// process that is gone, so nothing will ever complete it. Doing the
    /// claim and the read as one statement pair under one transaction is
    /// what replaced the old read-file / rebuild-`Vec` / rewrite-file dance:
    /// there is no window in which the records exist in memory but not on
    /// disk, and a crash mid-claim simply re-claims the same rows next time.
    pub fn claim_orphan_uploads(
        &mut self,
        now: &str,
    ) -> Result<Vec<StoredUpload>, UploadStoreError> {
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        tx.execute(
            "UPDATE transfer_uploads SET desired_state = 'aborting', updated_at = ?1 \
             WHERE desired_state <> 'aborting'",
            [now],
        )?;
        let claimed = read_uploads(&tx, None)?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(claimed)
    }

    // -----------------------------------------------------------------
    // Legacy sidecar importer
    // -----------------------------------------------------------------

    /// Imports the legacy `pending-uploads.json` sidecar into this store.
    ///
    /// Same contract as the download importer: **one transaction** for
    /// every record plus the migration marker, **the file is never written
    /// to**, and a corrupt input names the specific record that failed
    /// rather than degrading to an empty state.
    ///
    /// Imported records land as `aborting` with an empty `revision`: the
    /// sidecar had no column for the revision, and by definition every
    /// record in it was written by a process that is no longer running, so
    /// the only correct intent for it is "tear this down".
    pub fn import_legacy_pending_uploads(
        &mut self,
        path: &Path,
        now: &str,
    ) -> Result<LegacyUploadImportOutcome, LegacyUploadImportError> {
        if let Some(marker) = self.migration_marker(LEGACY_PENDING_UPLOAD_MARKER)? {
            return Ok(LegacyUploadImportOutcome::AlreadyImported(marker));
        }

        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LegacyUploadImportOutcome::NoLegacyStore)
            }
            Err(source) => {
                return Err(LegacyUploadImportError::Read {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };

        let store: LegacyPendingUploadStore =
            serde_json::from_slice(&raw).map_err(|error| LegacyUploadImportError::Corrupt {
                path: path.to_path_buf(),
                object_key: None,
                detail: format!("not a valid pending-upload store: {error}"),
            })?;
        legacy_import::check_upload_store_version(&store).map_err(|detail| {
            LegacyUploadImportError::Corrupt {
                path: path.to_path_buf(),
                object_key: None,
                detail,
            }
        })?;

        // Convert (and therefore validate) every record before opening the
        // transaction: a bad record must not even begin a write.
        let mut converted: Vec<NewUpload> = Vec::with_capacity(store.uploads.len());
        for record in &store.uploads {
            let upload = legacy_import::to_new_upload(record).map_err(|detail| {
                LegacyUploadImportError::Corrupt {
                    path: path.to_path_buf(),
                    object_key: Some(record.object_key.trim().to_string()),
                    detail,
                }
            })?;
            if converted.iter().any(|seen| {
                seen.object_key == upload.object_key && seen.upload_id == upload.upload_id
            }) {
                return Err(LegacyUploadImportError::Corrupt {
                    path: path.to_path_buf(),
                    object_key: Some(upload.object_key.clone()),
                    detail: "the store lists this multipart upload more than once".to_string(),
                });
            }
            converted.push(upload);
        }

        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let mut report = LegacyUploadImportReport {
            imported: Vec::new(),
            skipped_existing: Vec::new(),
        };
        for upload in &converted {
            let handle = (upload.object_key.clone(), upload.upload_id.clone());
            if read_upload_row(&tx, &upload.object_key, &upload.upload_id)?.is_some() {
                report.skipped_existing.push(handle);
                continue;
            }
            tx.execute(
                "INSERT INTO transfer_uploads (
                     object_key, upload_id, transfer_key, entry_key, revision, endpoint, bucket,
                     url_style, desired_state, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'aborting', ?9, ?9)",
                rusqlite::params![
                    upload.object_key,
                    upload.upload_id,
                    upload.transfer_key,
                    upload.entry_key,
                    upload.revision,
                    upload.endpoint,
                    upload.bucket,
                    upload.url_style.as_db_str(),
                    now,
                ],
            )
            .map_err(PersistenceError::from)?;
            report.imported.push(handle);
        }

        tx.execute(
            "INSERT INTO transfer_migration_markers (marker, applied_at, detail) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                LEGACY_PENDING_UPLOAD_MARKER,
                now,
                format!(
                    "imported {} multipart upload(s) ({} already present) from {}",
                    report.imported.len(),
                    report.skipped_existing.len(),
                    path.display()
                )
            ],
        )
        .map_err(PersistenceError::from)?;
        tx.commit().map_err(PersistenceError::from)?;

        Ok(LegacyUploadImportOutcome::Imported(report))
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn validate_upload_receipt_seed(receipt: &mut UploadReceiptSeed) -> Result<(), String> {
    if receipt.object_key.trim().is_empty() {
        return Err("object_key is empty".to_string());
    }
    if receipt.etag.trim().is_empty() {
        return Err(format!(
            "receipt for {} has an empty etag",
            receipt.object_key
        ));
    }
    if receipt
        .version_id
        .as_deref()
        .is_some_and(|version| version.trim().is_empty())
    {
        return Err(format!(
            "receipt for {} has an empty version_id",
            receipt.object_key
        ));
    }
    receipt.source_sha256 = normalize_upload_sha256(&receipt.source_sha256)?;
    Ok(())
}

fn normalize_upload_sha256(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "source_sha256 must be exactly 64 hexadecimal characters, got {value:?}"
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn upload_receipt_matches_seed(
    existing: &StoredUploadReceipt,
    entry_key: &str,
    revision: &str,
    requested: &UploadReceiptSeed,
) -> bool {
    existing.entry_key == entry_key
        && existing.revision == revision
        && existing.object_key == requested.object_key
        && existing.role == requested.role
        && existing.etag == requested.etag
        && existing.version_id == requested.version_id
        && existing.size_bytes == requested.size_bytes
        && existing.source_sha256 == requested.source_sha256
        && existing.digest_proof == requested.digest_proof
}

fn describe_upload_receipt_conflict(
    existing: &StoredUploadReceipt,
    entry_key: &str,
    revision: &str,
    requested: &UploadReceiptSeed,
) -> String {
    let fields = [
        ("entry_key", existing.entry_key.as_str(), entry_key),
        ("revision", existing.revision.as_str(), revision),
        (
            "role",
            existing.role.as_db_str(),
            requested.role.as_db_str(),
        ),
        ("etag", existing.etag.as_str(), requested.etag.as_str()),
        (
            "version_id",
            existing.version_id.as_deref().unwrap_or("<none>"),
            requested.version_id.as_deref().unwrap_or("<none>"),
        ),
        (
            "source_sha256",
            existing.source_sha256.as_str(),
            requested.source_sha256.as_str(),
        ),
        (
            "digest_proof",
            existing.digest_proof.as_db_str(),
            requested.digest_proof.as_db_str(),
        ),
    ];
    for (name, stored, wanted) in fields {
        if stored != wanted {
            return format!("{name} differs (stored {stored:?}, requested {wanted:?})");
        }
    }
    if existing.size_bytes != requested.size_bytes {
        return format!(
            "size_bytes differs (stored {}, requested {})",
            existing.size_bytes, requested.size_bytes
        );
    }
    "the records differ".to_string()
}

fn read_upload_receipt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredUploadReceipt> {
    let role_raw: String = row.get(4)?;
    let role = UploadReceiptRole::from_db_str(&role_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            format!("unrecognized upload receipt role {role_raw:?}").into(),
        )
    })?;
    let proof_raw: String = row.get(9)?;
    let digest_proof = UploadReceiptDigestProof::from_db_str(&proof_raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            format!("unrecognized upload receipt digest proof {proof_raw:?}").into(),
        )
    })?;
    let size_bytes: i64 = row.get(7)?;
    let size_bytes = u64::try_from(size_bytes).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Integer,
            format!("negative upload receipt size_bytes {size_bytes}").into(),
        )
    })?;
    let source_sha256_raw: String = row.get(8)?;
    let source_sha256 = normalize_upload_sha256(&source_sha256_raw).map_err(|detail| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, detail.into())
    })?;
    let version_id: Option<String> = row.get(6)?;
    if version_id
        .as_deref()
        .is_some_and(|version| version.trim().is_empty())
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            "empty upload receipt version_id".into(),
        ));
    }
    Ok(StoredUploadReceipt {
        job_id: row.get(0)?,
        entry_key: row.get(1)?,
        revision: row.get(2)?,
        object_key: row.get(3)?,
        role,
        etag: row.get(5)?,
        version_id,
        size_bytes,
        source_sha256,
        digest_proof,
        staged_at: row.get(10)?,
    })
}

fn read_upload_receipt_rows(
    conn: &Connection,
    job_id: &str,
    object_key: Option<&str>,
) -> Result<Vec<StoredUploadReceipt>, UploadReceiptError> {
    let mut out = Vec::new();
    if let Some(object_key) = object_key {
        let mut stmt = conn.prepare(
            "SELECT job_id, entry_key, revision, object_key, object_role, etag, version_id, \
                    size_bytes, source_sha256, digest_proof, staged_at \
             FROM transfer_upload_receipts \
             WHERE job_id = ?1 AND object_key = ?2 ORDER BY object_key",
        )?;
        out.extend(
            stmt.query_map(
                rusqlite::params![job_id, object_key],
                read_upload_receipt_row,
            )?
            .collect::<Result<Vec<_>, _>>()?,
        );
    } else {
        let mut stmt = conn.prepare(
            "SELECT job_id, entry_key, revision, object_key, object_role, etag, version_id, \
                    size_bytes, source_sha256, digest_proof, staged_at \
             FROM transfer_upload_receipts \
             WHERE job_id = ?1 ORDER BY object_key",
        )?;
        out.extend(
            stmt.query_map([job_id], read_upload_receipt_row)?
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    Ok(out)
}

fn validate_new_upload(upload: &NewUpload) -> Result<(), UploadStoreError> {
    for (label, value) in [
        ("object key", upload.object_key.as_str()),
        ("upload id", upload.upload_id.as_str()),
        ("transfer key", upload.transfer_key.as_str()),
        ("entry key", upload.entry_key.as_str()),
        ("revision", upload.revision.as_str()),
        ("endpoint", upload.endpoint.as_str()),
        ("bucket", upload.bucket.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(UploadStoreError::Invalid(format!("{label} is empty")));
        }
    }
    Ok(())
}

fn validate_upload_job_spec(spec: &UploadJobSpec) -> Result<(), String> {
    for (label, value) in [
        ("entry_key", spec.entry_key.as_str()),
        ("revision", spec.revision.as_str()),
        ("input_digest", spec.input_digest.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{label} is empty"));
        }
    }
    if let Some(prefix) = &spec.object_prefix {
        if normalize_object_prefix(prefix) != *prefix {
            return Err("object_prefix must be a normalized path".to_string());
        }
    }
    Ok(())
}

fn normalize_object_prefix(prefix: &str) -> String {
    prefix.trim().trim_matches('/').to_string()
}

fn validate_upload_activity_seed(seed: &UploadActivitySeed) -> Result<(), String> {
    if seed.label.trim().is_empty() {
        return Err("upload activity label is empty".to_string());
    }
    Ok(())
}

fn repeat_child_matches(
    tx: &rusqlite::Transaction<'_>,
    child_job_id: &str,
    spec: &UploadJobSpec,
    activity: &UploadActivitySeed,
) -> Result<bool, RepeatUploadJobError> {
    let (entry_key, revision, input_digest, object_prefix): (
        String,
        String,
        String,
        Option<String>,
    ) = tx
        .query_row(
            "SELECT entry_key, revision, input_digest, object_prefix \
             FROM transfer_upload_job_specs \
             WHERE job_id = ?1",
            [child_job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| {
            RepeatUploadJobError::Persistence(PersistenceError::Corrupt {
                path: PathBuf::from("transfer_upload_job_specs"),
                detail: format!("repeat child {child_job_id} has no immutable spec: {error}"),
            })
        })?;
    let (label, target_label, total_bytes): (String, String, i64) = tx
        .query_row(
            "SELECT label, target_label, total_bytes FROM transfer_upload_activity \
             WHERE job_id = ?1",
            [child_job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| {
            RepeatUploadJobError::Persistence(PersistenceError::Corrupt {
                path: PathBuf::from("transfer_upload_activity"),
                detail: format!("repeat child {child_job_id} has no activity row: {error}"),
            })
        })?;
    let total_bytes = u64::try_from(total_bytes).map_err(|_| {
        RepeatUploadJobError::Persistence(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_upload_activity"),
            detail: format!("repeat child {child_job_id} has negative total_bytes {total_bytes}"),
        })
    })?;
    Ok(entry_key == spec.entry_key
        && revision == spec.revision
        && input_digest == spec.input_digest
        && object_prefix == spec.object_prefix
        && label == activity.label
        && target_label == activity.target_label
        && total_bytes == activity.total_bytes)
}

fn checked_i64_upload(value: u64, field: &str) -> Result<i64, PersistenceError> {
    i64::try_from(value).map_err(|_| PersistenceError::Conflict {
        detail: format!("{field} value {value} exceeds SQLite INTEGER range"),
    })
}

fn abort_upload_job_create_if(
    abort: Option<UploadJobCreateAbort>,
    stage: UploadJobCreateAbort,
) -> Result<(), UploadJobCreateError> {
    if abort == Some(stage) {
        return Err(UploadJobCreateError::Persistence(
            PersistenceError::Conflict {
                detail: format!("simulated upload job create crash at {stage:?}"),
            },
        ));
    }
    Ok(())
}

fn length_prefixed_key<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut key = String::new();
    for part in parts {
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(part);
    }
    key
}

pub(super) fn upload_job_identity(entry_key: &str, revision: &str) -> Result<JobIdentity, String> {
    JobIdentity::new(
        DeviceId("__upload__".to_string()),
        SessionId(entry_key.to_string()),
        revision.to_string(),
    )
    .map_err(|error| error.to_string())
}

pub(super) fn upload_input_digest(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let bytes = hasher.finalize();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_part(part: &UploadPartRecord) -> Result<(), UploadStoreError> {
    if part.part_number == 0 {
        return Err(UploadStoreError::Invalid(
            "part numbers start at 1".to_string(),
        ));
    }
    if part.etag.trim().is_empty() {
        return Err(UploadStoreError::Invalid(format!(
            "part {} has no etag",
            part.part_number
        )));
    }
    Ok(())
}

fn ensure_upload_kind(job: &StoredJob) -> Result<(), UploadJobError> {
    if job.operation_kind != OperationKind::Upload {
        return Err(UploadJobError::WrongOperationKind {
            job_id: job.job_id.clone(),
            operation_kind: job.operation_kind,
        });
    }
    Ok(())
}

fn check_expected_version(job: &StoredJob, expected: u64) -> Result<(), UploadJobError> {
    if job.state_version != expected {
        return Err(UploadJobError::Stale {
            job_id: job.job_id.clone(),
            expected,
            actual: job.state_version,
        });
    }
    Ok(())
}

fn persisted_state(job: &StoredJob) -> Result<TransferJobState, UploadJobError> {
    Ok(match job.state {
        JobStateTag::Queued => TransferJobState::Queued,
        JobStateTag::WaitingForDevice => TransferJobState::WaitingForDevice,
        JobStateTag::WaitingForPairing => TransferJobState::WaitingForPairing,
        JobStateTag::PausedCaptureActive => TransferJobState::PausedCaptureActive,
        JobStateTag::Preparing => TransferJobState::Preparing,
        JobStateTag::Transferring => TransferJobState::Transferring,
        JobStateTag::Verifying => TransferJobState::Verifying,
        JobStateTag::Committing => TransferJobState::Committing,
        JobStateTag::RetryWait => TransferJobState::RetryWait,
        JobStateTag::Cancelling => TransferJobState::Cancelling,
        JobStateTag::Succeeded => TransferJobState::Succeeded,
        JobStateTag::Cancelled => TransferJobState::Cancelled,
        JobStateTag::Failed => {
            let (code, retryable) = job.error.clone().ok_or_else(|| {
                UploadJobError::Persistence(PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_jobs"),
                    detail: format!("failed upload job {} has no error", job.job_id),
                })
            })?;
            TransferJobState::Failed {
                code: crate::transfer::FailureCode::Other(code),
                retryable,
            }
        }
    })
}

fn terminal_outcome(job: &StoredJob) -> Result<TerminalOutcome, UploadJobError> {
    match (job.state, job.error.clone()) {
        (JobStateTag::Succeeded, _) => Ok(TerminalOutcome::Succeeded),
        (JobStateTag::Cancelled, _) => Ok(TerminalOutcome::Cancelled),
        (JobStateTag::Failed, Some((code, retryable))) => {
            Ok(TerminalOutcome::Failed { code, retryable })
        }
        _ => Err(UploadJobError::Persistence(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_jobs"),
            detail: format!("upload job {} has no usable terminal outcome", job.job_id),
        })),
    }
}

fn map_upload_persistence_error(error: PersistenceError) -> UploadJobError {
    UploadJobError::Persistence(error)
}

fn insert_upload_outbox_row(
    tx: &rusqlite::Transaction<'_>,
    job_id: &str,
    outcome: &TerminalOutcome,
    state_version: u64,
    now: &str,
) -> Result<super::transfer_store::CompletionRecord, UploadJobError> {
    let (error_code, error_retryable) = match outcome {
        TerminalOutcome::Failed { code, retryable } => {
            (Some(code.as_str()), Some(i64::from(*retryable)))
        }
        _ => (None, None),
    };
    tx.execute(
        "INSERT INTO transfer_completion_outbox (
             job_id, operation_kind, outcome, error_code, error_retryable, state_version, recorded_at
         ) VALUES (?1, 'upload', ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            job_id,
            outcome.as_db_str(),
            error_code,
            error_retryable,
            i64::try_from(state_version).map_err(|_| UploadJobError::Persistence(
                PersistenceError::Conflict { detail: "state version exceeds SQLite range".into() }
            ))?,
            now,
        ],
    )?;
    let sequence: i64 = tx.query_row(
        "SELECT sequence FROM transfer_completion_outbox WHERE job_id = ?1",
        [job_id],
        |row| row.get(0),
    )?;
    let sequence = u64::try_from(sequence).map_err(|_| {
        UploadJobError::Persistence(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_completion_outbox"),
            detail: format!("completion sequence {sequence} is negative"),
        })
    })?;
    Ok(super::transfer_store::CompletionRecord {
        sequence,
        job_id: job_id.to_string(),
        operation_kind: OperationKind::Upload,
        outcome: outcome.clone(),
        state_version,
        recorded_at: now.to_string(),
        acknowledged_at: None,
    })
}

fn describe_upload_mismatch(existing: &NewUpload, requested: &NewUpload) -> String {
    for (label, stored, wanted) in [
        (
            "transfer key",
            existing.transfer_key.as_str(),
            requested.transfer_key.as_str(),
        ),
        (
            "entry key",
            existing.entry_key.as_str(),
            requested.entry_key.as_str(),
        ),
        (
            "revision",
            existing.revision.as_str(),
            requested.revision.as_str(),
        ),
        (
            "endpoint",
            existing.endpoint.as_str(),
            requested.endpoint.as_str(),
        ),
        (
            "bucket",
            existing.bucket.as_str(),
            requested.bucket.as_str(),
        ),
    ] {
        if stored != wanted {
            return format!("{label} differs (stored {stored:?}, requested {wanted:?})");
        }
    }
    if existing.url_style != requested.url_style {
        return format!(
            "url style differs (stored {:?}, requested {:?})",
            existing.url_style, requested.url_style
        );
    }
    "the records differ".to_string()
}

const UPLOAD_COLUMNS: &str = "object_key, upload_id, transfer_key, entry_key, revision, endpoint, \
                              bucket, url_style, desired_state, created_at, updated_at, job_id";

fn read_upload_row(
    conn: &Connection,
    object_key: &str,
    upload_id: &str,
) -> Result<Option<()>, UploadStoreError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM transfer_uploads WHERE object_key = ?1 AND upload_id = ?2",
            rusqlite::params![object_key, upload_id],
            |_| Ok(()),
        )
        .optional()?)
}

fn read_upload(
    conn: &Connection,
    object_key: &str,
    upload_id: &str,
) -> Result<Option<StoredUpload>, UploadStoreError> {
    let mut found = read_uploads(conn, Some((object_key, upload_id)))?;
    Ok(if found.is_empty() {
        None
    } else {
        Some(found.remove(0))
    })
}

fn read_uploads(
    conn: &Connection,
    handle: Option<(&str, &str)>,
) -> Result<Vec<StoredUpload>, UploadStoreError> {
    let filter = if handle.is_some() {
        "WHERE object_key = ?1 AND upload_id = ?2 "
    } else {
        ""
    };
    let sql =
        format!("SELECT {UPLOAD_COLUMNS} FROM transfer_uploads {filter}ORDER BY created_at, rowid");
    let mut stmt = conn.prepare(&sql)?;
    let mapper = |row: &rusqlite::Row<'_>| {
        let url_style: String = row.get(7)?;
        let desired: String = row.get(8)?;
        Ok((
            NewUpload {
                object_key: row.get(0)?,
                upload_id: row.get(1)?,
                transfer_key: row.get(2)?,
                entry_key: row.get(3)?,
                revision: row.get(4)?,
                endpoint: row.get(5)?,
                bucket: row.get(6)?,
                url_style: UploadUrlStyle::from_db_str(&url_style).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        format!("unknown multipart URL style {url_style:?}").into(),
                    )
                })?,
            },
            desired,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, Option<String>>(11)?,
        ))
    };
    let rows = match handle {
        Some((object_key, upload_id)) => stmt
            .query_map(rusqlite::params![object_key, upload_id], mapper)?
            .collect::<Result<Vec<_>, _>>()?,
        None => stmt.query_map([], mapper)?.collect::<Result<Vec<_>, _>>()?,
    };

    let mut out = Vec::with_capacity(rows.len());
    for (upload, desired, created_at, updated_at, job_id) in rows {
        // An unrecognized desired state is a corrupt store, not a reason to
        // quietly drop a real remote upload from the list: dropping it would
        // leave orphan parts nobody ever aborts.
        let desired_state =
            UploadDesiredState::from_db_str(&desired).ok_or_else(|| PersistenceError::Corrupt {
                path: PathBuf::from("transfer_uploads"),
                detail: format!(
                    "multipart upload {} / {} has unrecognized desired state {desired:?}",
                    upload.object_key, upload.upload_id
                ),
            })?;
        let parts = read_parts(conn, &upload.object_key, &upload.upload_id)?;
        out.push(StoredUpload {
            upload,
            job_id,
            desired_state,
            parts,
            created_at,
            updated_at,
        });
    }
    Ok(out)
}

fn read_parts(
    conn: &Connection,
    object_key: &str,
    upload_id: &str,
) -> Result<Vec<UploadPartRecord>, PersistenceError> {
    let mut stmt = conn.prepare(
        "SELECT part_number, etag, size_bytes FROM transfer_upload_parts \
         WHERE object_key = ?1 AND upload_id = ?2 ORDER BY part_number",
    )?;
    let parts = stmt
        .query_map(rusqlite::params![object_key, upload_id], |row| {
            let part_number: i64 = row.get(0)?;
            let part_number = u32::try_from(part_number).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Integer,
                    format!("part number {part_number} is outside u32 range").into(),
                )
            })?;
            if part_number == 0 {
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Integer,
                    "part number must be positive".into(),
                ));
            }
            let size_bytes: i64 = row.get(2)?;
            let size_bytes = u64::try_from(size_bytes).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    format!("negative size_bytes {size_bytes}").into(),
                )
            })?;
            Ok(UploadPartRecord {
                part_number,
                etag: row.get(1)?,
                size_bytes,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parts)
}
