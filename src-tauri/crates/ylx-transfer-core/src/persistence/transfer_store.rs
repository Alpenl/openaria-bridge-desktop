//! `TransferStore` — the durable authority for transfer jobs (issue #1
//! Phase 2, commits 22–26).
//!
//! This is the store the plan's decision document names as *the* source of
//! truth for job spec, ordered file plan, per-file ledger and state/version.
//! The migration list still carries the retired `jobs`/`checkpoints` DDL so
//! existing files can be opened, but all runtime reads and writes go through
//! the `transfer_*` tables owned here.
//!
//! What this module owns:
//!
//! - **One transaction per job creation** ([`TransferStore::create_job`]).
//!   Job identity, the complete spec, the ordered files and the initial
//!   ledger are one atomic unit — a failure at any point leaves no row at
//!   all, which the `create_job_aborting_after` crash-point tests exercise
//!   directly rather than by inspection.
//! - **Request-digest verification** on an idempotent hit. Same natural key
//!   with different content is an explicit
//!   [`CreateJobError::RequestDigestMismatch`], never a silent reuse of a
//!   different file plan.
//! - **Recovery enumeration from SQLite** ([`TransferStore::
//!   list_recoverable_jobs`]) — a missing or unreadable spec becomes an
//!   observable [`RecoverableJob::Blocked`], never a silently shorter list.
//! - **The one-shot legacy importer** ([`TransferStore::
//!   import_legacy_pending_downloads`]), which reads the pending-download
//!   JSON sidecar, imports every record in one transaction, and writes a
//!   migration marker in that same transaction.
//! - **The durable completion outbox** ([`TransferStore::complete_job`],
//!   commit 29). The terminal state transition and the outcome the rest of
//!   the app has to learn about are one transaction; success, failure and
//!   cancellation all stay re-observable through
//!   [`TransferStore::pending_completions`] until
//!   [`TransferStore::acknowledge_completion`] stamps them.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::domain::{
    DeviceId, FileId, JobFileSpec, JobIdentity, JobSpec, PublicationMaterial, RequestDigest,
    SessionId,
};
use crate::transfer::DesiredRunState;

use super::error::PersistenceError;
use super::legacy_import::{self, LegacyPendingDownloadStore};
use super::schema::{self, FileLedgerStatus, JobStateTag, CURRENT_JOB_SPEC_VERSION};

/// The durable lane a job belongs to. This tag is part of the persistence
/// contract: upload jobs may share the transfer database, but they must
/// never be handed to the download dispatcher or download recovery code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationKind {
    Download,
    Upload,
}

impl OperationKind {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            OperationKind::Download => "download",
            OperationKind::Upload => "upload",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "download" => Some(OperationKind::Download),
            "upload" => Some(OperationKind::Upload),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_upload(self) -> bool {
        matches!(self, OperationKind::Upload)
    }
}

/// Compatibility spelling for callers that prefer the more explicit name.
pub type JobOperationKind = OperationKind;

// ---------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------

/// A `transfer_jobs` row: identity, digest and durable state/version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredJob {
    pub job_id: String,
    pub operation_kind: OperationKind,
    pub identity: JobIdentity,
    pub request_digest: RequestDigest,
    pub state: JobStateTag,
    /// Monotonic version for the expected-version CAS a later commit adds.
    /// Always 1 for a freshly created job.
    pub state_version: u64,
    /// User intent that must survive a restart independently of the tagged
    /// execution state. This used to live in the coordinator sidecar.
    pub desired_run_state: DesiredRunState,
    /// `Some((code, retryable))` iff `state == JobStateTag::Failed`.
    pub error: Option<(String, bool)>,
    pub created_at: String,
    pub updated_at: String,
    /// Durable UI visibility tombstone. A dismissed job remains in the
    /// store for audit, retry lineage and completion evidence.
    pub dismissed_at: Option<String>,
}

/// Durable parent/child retry relationship. The failed parent remains a
/// terminal job row; a retry is a separate queued child row carrying the
/// same immutable spec and file evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryLineageRecord {
    pub parent_job_id: String,
    pub child_job_id: String,
    pub attempt: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryJobOutcome {
    Created(Box<StoredJob>),
    Existing(Box<StoredJob>),
}

impl RetryJobOutcome {
    #[must_use]
    pub fn job(&self) -> &StoredJob {
        match self {
            RetryJobOutcome::Created(job) | RetryJobOutcome::Existing(job) => job,
        }
    }

    #[must_use]
    pub fn was_created(&self) -> bool {
        matches!(self, RetryJobOutcome::Created(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RetryJobError {
    #[error("job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {job_id:?} is not a retryable failed job")]
    NotRetryable { job_id: String },

    #[error("job {job_id:?} has been dismissed")]
    DismissedParent { job_id: String },

    #[error("job {job_id:?} has an unacknowledged terminal outcome")]
    UnacknowledgedParent { job_id: String },

    #[error(
        "upload job {parent_job_id:?} already has a successful retry descendant {child_job_id:?}"
    )]
    SuccessfulDescendant {
        parent_job_id: String,
        child_job_id: String,
    },

    #[error("retry job id {job_id:?} is already taken")]
    JobIdCollision { job_id: String },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetrySpawnPolicy {
    StandardDownload,
    FreshDownload,
    DismissedDownloadEnqueue,
    Upload,
}

/// Errors returned when a terminal job is dismissed from user-facing
/// projections. Dismissal is deliberately a tombstone rather than a delete:
/// retry lineage and completion evidence must remain durable.
#[derive(Debug, thiserror::Error)]
pub enum DismissJobError {
    #[error("job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {job_id:?} is not terminal (state {state})")]
    NotTerminal { job_id: String, state: String },

    #[error("job {job_id:?} has an unacknowledged terminal outcome")]
    Unacknowledged { job_id: String },

    #[error("upload job {job_id:?} still has pending multipart uploads")]
    PendingMultipart { job_id: String },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for DismissJobError {
    fn from(error: rusqlite::Error) -> Self {
        DismissJobError::Persistence(error.into())
    }
}

impl From<rusqlite::Error> for RetryJobError {
    fn from(error: rusqlite::Error) -> Self {
        RetryJobError::Persistence(error.into())
    }
}

/// One `transfer_file_ledger` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLedgerEntry {
    pub file_id: FileId,
    pub status: FileLedgerStatus,
    pub bytes_confirmed: u64,
    /// The digest actually recomputed from local bytes. Present iff
    /// `status == FileLedgerStatus::Verified`.
    pub verified_sha256: Option<String>,
    pub updated_at: String,
}

/// A completed one-shot data migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationMarker {
    pub marker: String,
    pub applied_at: String,
    pub detail: String,
}

// ---------------------------------------------------------------------
// create_job outcomes / errors
// ---------------------------------------------------------------------

/// What [`TransferStore::create_job`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateJobOutcome {
    /// A brand-new job (identity + spec + files + ledger) was committed.
    Created(Box<StoredJob>),
    /// The same logical transfer, with a byte-identical request digest,
    /// already existed. The caller must use the returned job.
    Existing(Box<StoredJob>),
}

impl CreateJobOutcome {
    #[must_use]
    pub fn job(&self) -> &StoredJob {
        match self {
            CreateJobOutcome::Created(job) | CreateJobOutcome::Existing(job) => job,
        }
    }

    #[must_use]
    pub fn was_created(&self) -> bool {
        matches!(self, CreateJobOutcome::Created(_))
    }
}

/// Commit 24: an existing job shares the natural key but *not* the request
/// content. Carries both digests and a human-readable diagnostic naming
/// the first field that differs, so an operator does not have to diff two
/// opaque hashes by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRequestConflict {
    pub job_id: String,
    pub identity: JobIdentity,
    pub existing_digest: RequestDigest,
    pub requested_digest: RequestDigest,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateJobError {
    /// Same `(device, session, revision)`, different content. Never
    /// downgraded to [`CreateJobOutcome::Existing`]: handing back a job
    /// that transfers a different file plan than the caller asked for is
    /// exactly the silent-reuse bug this check exists to prevent.
    #[error(
        "job {} already exists for {} with request digest {} but the new request digests to {}: {}",
        .0.job_id, .0.identity, .0.existing_digest, .0.requested_digest, .0.detail
    )]
    RequestDigestMismatch(Box<JobRequestConflict>),

    /// The requested `job_id` is already taken by a *different* logical
    /// transfer.
    #[error("job id {job_id:?} is already taken by a different logical transfer ({existing})")]
    JobIdCollision { job_id: String, existing: String },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for CreateJobError {
    fn from(error: rusqlite::Error) -> Self {
        CreateJobError::Persistence(error.into())
    }
}

/// Test-only crash points inside [`TransferStore::create_job`]'s single
/// transaction, used to prove that a failure at any stage leaves no
/// partial row behind.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateJobAbort {
    AfterJobRow,
    AfterSpecRow,
    AfterFiles,
    AfterLedger,
}

// ---------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------

/// Why a durable job cannot be handed to recovery as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryBlockedReason {
    /// No `transfer_job_specs` row for a job that has a `transfer_jobs` row.
    MissingSpec,
    /// The spec row exists but no ordered files (or no requested files).
    MissingFiles,
    /// `spec_version` is one this build does not understand.
    UnknownSpecVersion,
    /// The stored rows exist but no longer form a valid
    /// [`crate::domain::JobSpec`] (bad hash, empty identity, requested file
    /// missing from the inventory, …).
    CorruptSpec,
    /// The spec reassembles, but its digest no longer matches the digest
    /// recorded when the job was created — someone edited rows underneath
    /// the store.
    DigestMismatch,
    /// The `state` column holds a value this build does not know.
    UnknownState,
}

/// An observable "this job exists but recovery cannot run it" record.
/// Recovery must surface these; dropping them would turn a corrupt store
/// into a silently empty one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBlocked {
    pub job_id: String,
    /// Best-effort identity. `None` when even the identity columns are
    /// unusable.
    pub identity: Option<JobIdentity>,
    pub reason: RecoveryBlockedReason,
    pub detail: String,
}

/// A job plus everything recovery needs to resume it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverableJobDetail {
    pub job: StoredJob,
    pub spec: JobSpec,
    /// Ledger rows in request order.
    pub ledger: Vec<FileLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverableJob {
    Ready(Box<RecoverableJobDetail>),
    Blocked(Box<RecoveryBlocked>),
}

impl RecoverableJob {
    #[must_use]
    pub fn job_id(&self) -> &str {
        match self {
            RecoverableJob::Ready(detail) => &detail.job.job_id,
            RecoverableJob::Blocked(blocked) => &blocked.job_id,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JobSpecLoadError {
    #[error("job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {}'s durable spec is unusable ({:?}): {}", .0.job_id, .0.reason, .0.detail)]
    Blocked(Box<RecoveryBlocked>),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

// ---------------------------------------------------------------------
// Legacy import
// ---------------------------------------------------------------------

/// Marker written by [`TransferStore::import_legacy_pending_downloads`].
pub const LEGACY_PENDING_DOWNLOAD_MARKER: &str = "legacy_pending_downloads_v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyImportReport {
    /// Job ids newly created by this import, in file order.
    pub imported: Vec<String>,
    /// Job ids whose logical transfer already existed (identical request
    /// digest), so nothing was created for them.
    pub skipped_existing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyImportOutcome {
    /// No sidecar file exists — nothing to do, and no marker is written
    /// (so a sidecar appearing later still gets imported).
    NoLegacyStore,
    /// The marker was already present: a previous run imported this file.
    /// Nothing was read or written.
    AlreadyImported(MigrationMarker),
    /// The import ran and committed.
    Imported(LegacyImportReport),
}

#[derive(Debug, thiserror::Error)]
pub enum LegacyImportError {
    /// The sidecar could not be read.
    #[error("failed to read legacy pending-download store at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The sidecar's bytes are unusable. `job_id` names the specific record
    /// that failed when the failure is per-record; it is `None` only when
    /// the file as a whole failed to parse. **The file itself is never
    /// modified by the importer**, so the original data survives for a
    /// retry after the cause is fixed.
    #[error("legacy pending-download store at {path} is unusable{}: {detail}",
        .job_id.as_ref().map(|id| format!(" (job {id})")).unwrap_or_default())]
    Corrupt {
        path: PathBuf,
        job_id: Option<String>,
        detail: String,
    },

    /// A record's natural key already exists in the store with different
    /// content. Reported rather than merged, for the same reason
    /// [`CreateJobError::RequestDigestMismatch`] exists.
    #[error("legacy record for job {} conflicts with an existing durable job: {}", .0.job_id, .0.detail)]
    Conflict(Box<JobRequestConflict>),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

// ---------------------------------------------------------------------
// Commit 29: terminal outcomes and the durable completion outbox
// ---------------------------------------------------------------------

/// How a job ended. The payload is part of the tag (rather than three
/// loose columns a caller has to re-assemble) so "failed without a code"
/// is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalOutcome {
    Succeeded,
    Failed { code: String, retryable: bool },
    Cancelled,
}

impl TerminalOutcome {
    #[must_use]
    pub fn state_tag(&self) -> JobStateTag {
        match self {
            TerminalOutcome::Succeeded => JobStateTag::Succeeded,
            TerminalOutcome::Failed { .. } => JobStateTag::Failed,
            TerminalOutcome::Cancelled => JobStateTag::Cancelled,
        }
    }

    #[must_use]
    pub fn as_db_str(&self) -> &'static str {
        self.state_tag().as_db_str()
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, TerminalOutcome::Succeeded)
    }

    fn error_columns(&self) -> (Option<&str>, Option<i64>) {
        match self {
            TerminalOutcome::Failed { code, retryable } => {
                (Some(code.as_str()), Some(i64::from(*retryable)))
            }
            _ => (None, None),
        }
    }

    fn from_columns(
        outcome: &str,
        code: Option<String>,
        retryable: Option<i64>,
    ) -> Result<Self, String> {
        Ok(match outcome {
            "succeeded" => TerminalOutcome::Succeeded,
            "cancelled" => TerminalOutcome::Cancelled,
            "failed" => TerminalOutcome::Failed {
                code: code.ok_or_else(|| "a failed outcome has no error code".to_string())?,
                retryable: retryable
                    .ok_or_else(|| "a failed outcome has no retryable flag".to_string())?
                    != 0,
            },
            other => return Err(format!("unrecognized terminal outcome {other:?}")),
        })
    }
}

impl std::fmt::Display for TerminalOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TerminalOutcome::Succeeded => f.write_str("succeeded"),
            TerminalOutcome::Cancelled => f.write_str("cancelled"),
            TerminalOutcome::Failed { code, retryable } => {
                write!(f, "failed({code}, retryable={retryable})")
            }
        }
    }
}

/// One `transfer_completion_outbox` row: a terminal outcome that is
/// re-observable until it is explicitly acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionRecord {
    /// Monotonic delivery order.
    pub sequence: u64,
    pub job_id: String,
    /// The lane that produced this evidence. Upload completions are
    /// projected by the upload owner and are not download requests.
    pub operation_kind: OperationKind,
    pub outcome: TerminalOutcome,
    /// The `transfer_jobs.state_version` produced by the very transition
    /// this row was written with. A consumer that records it can tell a
    /// re-delivery of the same fact from a genuinely new one.
    pub state_version: u64,
    pub recorded_at: String,
    /// `None` while the outcome still has to be delivered.
    pub acknowledged_at: Option<String>,
}

impl CompletionRecord {
    #[must_use]
    pub fn is_acknowledged(&self) -> bool {
        self.acknowledged_at.is_some()
    }
}

/// Whether a job's terminal outcome still needs to be projected by the
/// completion consumer. `Missing` is intentionally distinct from `Pending`:
/// a succeeded job without an outbox row is inconsistent durable state, while
/// a pending row is a normal, replayable delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompletionDeliveryState {
    Missing,
    Pending,
    Acknowledged,
}

/// One download job in the session-status snapshot used by list views.
///
/// Keeping the job and its completion delivery state in the same row lets a
/// caller build all visible session states from one SQLite statement instead
/// of repeatedly loading the full job and completion tables for every
/// session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadSessionJobState {
    pub job: StoredJob,
    pub completion: CompletionDeliveryState,
}

/// What [`TransferStore::complete_job`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteJobOutcome {
    /// The job transitioned to its terminal state and the outbox row was
    /// written — in one transaction.
    Recorded(Box<CompletionRecord>),
    /// This exact terminal outcome was already durable. Nothing was
    /// written; the existing (possibly still unacknowledged) row is
    /// returned, which is what makes replaying a terminal transition after
    /// a crash safe.
    AlreadyRecorded(Box<CompletionRecord>),
}

impl CompleteJobOutcome {
    #[must_use]
    pub fn record(&self) -> &CompletionRecord {
        match self {
            CompleteJobOutcome::Recorded(record) | CompleteJobOutcome::AlreadyRecorded(record) => {
                record
            }
        }
    }

    #[must_use]
    pub fn was_recorded(&self) -> bool {
        matches!(self, CompleteJobOutcome::Recorded(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompleteJobError {
    #[error("job {0:?} does not exist")]
    UnknownJob(String),

    /// The job already ended *differently*. Never downgraded to an
    /// idempotent hit: a cancellation overwriting a committed success (or
    /// the reverse) is precisely the terminal-outcome race this table
    /// exists to make impossible.
    #[error("job {job_id} already ended as {existing}; refusing to overwrite it with {requested}")]
    AlreadyTerminal {
        job_id: String,
        existing: TerminalOutcome,
        requested: TerminalOutcome,
    },

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for CompleteJobError {
    fn from(error: rusqlite::Error) -> Self {
        CompleteJobError::Persistence(error.into())
    }
}

/// Test-only crash point inside [`TransferStore::complete_job`]'s single
/// transaction. `AfterStateUpdate` is the interesting one: it is exactly
/// the "the job finished but nobody recorded it" window commit 29 closes.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteJobAbort {
    AfterStateUpdate,
    AfterOutboxRow,
}

/// What [`TransferStore::acknowledge_completion`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    /// This call stamped the row; it will never be delivered again.
    Acknowledged(Box<CompletionRecord>),
    /// A previous call already stamped it. A duplicate ack is a no-op, not
    /// an error — the consumer may legitimately re-run after a crash that
    /// happened between the ack commit and its own bookkeeping.
    AlreadyAcknowledged(Box<CompletionRecord>),
    /// No outbox row for this job (never completed, or the job was
    /// deleted).
    Unknown,
}

// ---------------------------------------------------------------------
// TransferStore
// ---------------------------------------------------------------------

#[derive(Debug)]
pub struct TransferStore {
    /// `pub(super)` so [`super::upload_store`] can add commit 35's upload
    /// context as an `impl TransferStore` block of its own instead of
    /// growing this module by another table's worth of SQL.
    pub(super) conn: Connection,
    path: PathBuf,
}

const DOWNLOAD_SESSION_JOB_STATES_SQL: &str = "WITH requested_devices(device_id) AS ( \
         SELECT value FROM json_each(?1) \
     ), requested_sessions(session_id) AS ( \
         SELECT value FROM json_each(?2) \
     ) \
     SELECT j.job_id, j.operation_kind, j.device_id, j.session_id, j.revision, \
            j.request_digest, j.state, j.state_version, j.desired_run_state, \
            j.error_code, j.error_retryable, j.created_at, j.updated_at, j.dismissed_at, \
            c.job_id, c.operation_kind, c.acknowledged_at \
     FROM requested_devices AS d \
     CROSS JOIN requested_sessions AS s \
     CROSS JOIN transfer_jobs AS j INDEXED BY transfer_jobs_download_device_session_idx \
     LEFT JOIN transfer_completion_outbox AS c ON c.job_id = j.job_id \
     WHERE j.device_id = d.device_id \
       AND j.session_id = s.session_id \
       AND j.operation_kind = 'download' \
     ORDER BY j.device_id, j.session_id, j.created_at, j.job_id";

impl TransferStore {
    /// Opens (creating if needed) the transfer store at `path`.
    ///
    /// Parent directories are created first, then `PRAGMA integrity_check`
    /// runs before any pragma or DDL touches the file; WAL/FULL/
    /// foreign-keys are enabled before the shared migration list runs.
    ///
    /// A file recorded at a schema version above this build's
    /// [`schema::latest_version`] is **not opened**: it returns
    /// [`PersistenceError::UnsupportedSchemaVersion`] with both versions in
    /// the diagnostic.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistenceError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| PersistenceError::io(parent, e))?;
        }

        let conn = Connection::open(&path)?;
        let mut store = TransferStore { conn, path };
        store.check_integrity()?;

        store.conn.pragma_update(None, "journal_mode", "WAL")?;
        store.conn.pragma_update(None, "synchronous", "FULL")?;
        store.conn.pragma_update(None, "foreign_keys", "ON")?;

        let path = store.path.clone();
        schema::run_migrations(&mut store.conn, &path)?;
        Ok(store)
    }

    fn check_integrity(&self) -> Result<(), PersistenceError> {
        let result: Result<String, rusqlite::Error> =
            self.conn
                .query_row("PRAGMA integrity_check", [], |row| row.get(0));
        match result {
            Ok(message) if message == "ok" => Ok(()),
            Ok(message) => Err(PersistenceError::corrupt(&self.path, message)),
            Err(error) => Err(PersistenceError::corrupt(&self.path, error.to_string())),
        }
    }

    /// The file's `schema_migrations` high-water mark.
    pub fn schema_version(&self) -> Result<u32, PersistenceError> {
        schema::read_schema_version(&self.conn)
    }

    /// Tables this store owns, for schema-review tests.
    #[doc(hidden)]
    pub fn transfer_tables() -> &'static [&'static str] {
        &[
            "transfer_jobs",
            "transfer_job_specs",
            "transfer_job_files",
            "transfer_file_ledger",
            "transfer_migration_markers",
            "transfer_completion_outbox",
            "transfer_uploads",
            "transfer_upload_parts",
            "transfer_upload_job_specs",
            "transfer_upload_activity",
            "transfer_upload_receipts",
            "transfer_job_lineage",
        ]
    }

    #[doc(hidden)]
    pub fn table_columns(&self, table: &str) -> Result<Vec<String>, PersistenceError> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(columns)
    }

    /// Escape hatch for tests that need to corrupt rows underneath the
    /// store the way a bad actor or a botched manual edit would.
    #[doc(hidden)]
    pub fn raw_execute(&self, sql: &str) -> Result<usize, PersistenceError> {
        Ok(self.conn.execute(sql, [])?)
    }

    /// Atomically applies one non-terminal state transition only when the
    /// caller still owns the expected state version. The aggregate owns the
    /// legal transition graph; this method owns the durable CAS boundary.
    /// Terminal outcomes must use [`Self::complete_job`] so the completion
    /// outbox and state row remain one transaction.
    pub fn transition_job(
        &mut self,
        job_id: &str,
        expected_version: u64,
        to: JobStateTag,
        error: Option<(&str, bool)>,
        now: &str,
    ) -> Result<u64, PersistenceError> {
        if to.is_terminal() {
            return Err(PersistenceError::Conflict {
                detail: format!("terminal state {} must use complete_job", to.as_db_str()),
            });
        }
        if (to == JobStateTag::Failed) != error.is_some() {
            return Err(PersistenceError::Conflict {
                detail: "error must be Some(..) iff transitioning to Failed".into(),
            });
        }
        let next_version =
            expected_version
                .checked_add(1)
                .ok_or_else(|| PersistenceError::Conflict {
                    detail: format!("job {job_id} state version exhausted u64 range"),
                })?;
        let (error_code, error_retryable) = match error {
            Some((code, retryable)) => (Some(code), Some(i64::from(retryable))),
            None => (None, None),
        };
        let changed = self.conn.execute(
            "UPDATE transfer_jobs SET state = ?2, state_version = ?3, error_code = ?4, \
             error_retryable = ?5, updated_at = ?6 \
             WHERE job_id = ?1 AND state_version = ?7 AND state NOT IN \
             ('succeeded', 'failed', 'cancelled')",
            rusqlite::params![
                job_id,
                to.as_db_str(),
                checked_i64(next_version, "state_version")?,
                error_code,
                error_retryable,
                now,
                checked_i64(expected_version, "expected_version")?,
            ],
        )?;
        if changed == 0 {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "stale or terminal transfer job {job_id}: expected state version {expected_version}"
                ),
            });
        }
        Ok(next_version)
    }

    /// Persists the user's run intent independently of the tagged execution
    /// state. The optional expected version closes a stale-command race when
    /// callers have a snapshot; the row's state version itself is not bumped
    /// because this is intent, not an execution transition.
    pub fn set_desired_run_state(
        &mut self,
        job_id: &str,
        desired: DesiredRunState,
        now: &str,
        expected_version: Option<u64>,
    ) -> Result<(), PersistenceError> {
        let desired = desired_run_state_db(desired);
        let mut sql = String::from(
            "UPDATE transfer_jobs SET desired_run_state = ?2, updated_at = ?3 WHERE job_id = ?1",
        );
        if expected_version.is_some() {
            sql.push_str(" AND state_version = ?4");
        }
        let changed = match expected_version {
            Some(version) => self.conn.execute(
                &sql,
                rusqlite::params![
                    job_id,
                    desired,
                    now,
                    checked_i64(version, "expected_version")?,
                ],
            )?,
            None => self
                .conn
                .execute(&sql, rusqlite::params![job_id, desired, now])?,
        };
        if changed == 0 {
            return Err(PersistenceError::Conflict {
                detail: format!("job {job_id} not found or state version is stale"),
            });
        }
        Ok(())
    }

    /// Advances one requested file's durable evidence ledger. Evidence is
    /// monotonic: bytes never move backwards, a verified row never downgrades
    /// and a verified digest is write-once. The expected size is read from
    /// the signed file plan, never trusted from the caller.
    pub fn update_file_ledger(
        &mut self,
        job_id: &str,
        file_id: &FileId,
        status: FileLedgerStatus,
        bytes_confirmed: u64,
        verified_sha256: Option<&str>,
        now: &str,
    ) -> Result<(), PersistenceError> {
        let expected_size: i64 = self
            .conn
            .query_row(
                "SELECT size_bytes FROM transfer_job_files WHERE job_id = ?1 AND file_id = ?2",
                rusqlite::params![job_id, file_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => PersistenceError::NotFound {
                    detail: format!("file {} is not part of job {job_id}", file_id.as_str()),
                },
                other => other.into(),
            })?;
        let expected_size =
            u64::try_from(expected_size).map_err(|_| PersistenceError::Corrupt {
                path: PathBuf::from("transfer_job_files"),
                detail: format!(
                    "file {} has negative expected size {expected_size}",
                    file_id.as_str()
                ),
            })?;
        if bytes_confirmed > expected_size {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "file {} checkpoint {bytes_confirmed} exceeds expected size {expected_size}",
                    file_id.as_str()
                ),
            });
        }
        let digest = match status {
            FileLedgerStatus::Verified => {
                let digest = verified_sha256.ok_or_else(|| PersistenceError::Conflict {
                    detail: "a verified file must carry its actual SHA-256".to_string(),
                })?;
                RequestDigest::from_hex(digest).map_err(|error| PersistenceError::Conflict {
                    detail: format!("verified file digest is invalid: {error}"),
                })?;
                Some(digest.to_string())
            }
            _ if verified_sha256.is_some() => {
                return Err(PersistenceError::Conflict {
                    detail: "only a verified file may carry verified_sha256".to_string(),
                })
            }
            _ => None,
        };
        let tx = self.conn.transaction()?;
        let existing: Option<(String, i64, Option<String>)> = tx
            .query_row(
                "SELECT status, bytes_confirmed, verified_sha256 FROM transfer_file_ledger \
                 WHERE job_id = ?1 AND file_id = ?2",
                rusqlite::params![job_id, file_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((stored_status, stored_bytes, stored_digest)) = existing {
            let stored_status = FileLedgerStatus::from_db_str(&stored_status).ok_or_else(|| {
                PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_file_ledger"),
                    detail: format!("unknown ledger status {stored_status:?}"),
                }
            })?;
            let stored_bytes =
                u64::try_from(stored_bytes).map_err(|_| PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_file_ledger"),
                    detail: format!("negative checkpoint {stored_bytes}"),
                })?;
            if stored_status == FileLedgerStatus::Verified
                && (status != FileLedgerStatus::Verified
                    || stored_digest.as_deref() != digest.as_deref())
            {
                return Err(PersistenceError::Conflict {
                    detail: format!(
                        "verified ledger row for {} cannot be downgraded",
                        file_id.as_str()
                    ),
                });
            }
            if bytes_confirmed < stored_bytes {
                return Err(PersistenceError::Conflict {
                    detail: format!(
                        "file {} checkpoint moves backwards from {stored_bytes} to {bytes_confirmed}",
                        file_id.as_str()
                    ),
                });
            }
            if stored_status == FileLedgerStatus::Verified
                && stored_digest.as_deref() == digest.as_deref()
                && bytes_confirmed == stored_bytes
            {
                return Ok(());
            }
        }
        tx.execute(
            "UPDATE transfer_file_ledger SET status = ?3, bytes_confirmed = ?4, \
             verified_sha256 = ?5, updated_at = ?6 WHERE job_id = ?1 AND file_id = ?2",
            rusqlite::params![
                job_id,
                file_id.as_str(),
                status.as_db_str(),
                checked_i64(bytes_confirmed, "bytes_confirmed")?,
                digest,
                now,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Commit 23/24: transactional create_job
    // -----------------------------------------------------------------

    /// Creates one job — identity, complete spec, ordered files and the
    /// initial per-file ledger — in a **single transaction**.
    ///
    /// - Fresh natural key → [`CreateJobOutcome::Created`].
    /// - Natural key already present **and** the request digests match →
    ///   [`CreateJobOutcome::Existing`], no writes.
    /// - Natural key already present with a *different* digest →
    ///   [`CreateJobError::RequestDigestMismatch`] (commit 24).
    /// - `job_id` taken by a different natural key →
    ///   [`CreateJobError::JobIdCollision`].
    ///
    /// Any failure — including a crash simulated at one of the
    /// [`CreateJobAbort`] points — rolls the whole transaction back, so the
    /// store never holds a job row without its spec, files and ledger.
    pub fn create_job(
        &mut self,
        job_id: &str,
        spec: &JobSpec,
        now: &str,
    ) -> Result<CreateJobOutcome, CreateJobError> {
        self.create_job_inner(job_id, spec, now, None)
    }

    #[doc(hidden)]
    pub fn create_job_aborting_after(
        &mut self,
        job_id: &str,
        spec: &JobSpec,
        now: &str,
        abort: CreateJobAbort,
    ) -> Result<CreateJobOutcome, CreateJobError> {
        self.create_job_inner(job_id, spec, now, Some(abort))
    }

    fn create_job_inner(
        &mut self,
        job_id: &str,
        spec: &JobSpec,
        now: &str,
        abort: Option<CreateJobAbort>,
    ) -> Result<CreateJobOutcome, CreateJobError> {
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let outcome = insert_job_tx(&tx, job_id, spec, now, abort)?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(outcome)
    }

    // -----------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------

    pub fn get_job(&self, job_id: &str) -> Result<Option<StoredJob>, PersistenceError> {
        read_job(&self.conn, "job_id", job_id)
    }

    pub fn find_job_by_identity(
        &self,
        identity: &JobIdentity,
    ) -> Result<Option<StoredJob>, PersistenceError> {
        read_latest_job_by_identity(&self.conn, identity)
    }

    /// Every job row, in creation order — terminal ones included.
    ///
    /// [`TransferStore::list_recoverable_jobs`] deliberately stops at
    /// non-terminal jobs; this is for the callers that also need the
    /// finished-but-not-yet-dismissed ones (a failed download the user can
    /// still see and retry).
    pub fn list_jobs(&self) -> Result<Vec<StoredJob>, PersistenceError> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id, operation_kind, device_id, session_id, revision, request_digest, state, state_version, \
                    desired_run_state, error_code, error_retryable, created_at, updated_at, dismissed_at \
             FROM transfer_jobs ORDER BY created_at, job_id",
        )?;
        let rows = stmt
            .query_map([], |row| Ok(read_job_row(row)))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|row| {
                row.map_err(|detail| PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_jobs"),
                    detail,
                })
            })
            .collect()
    }

    /// User-facing job projection: all lanes, including terminal outcomes,
    /// except jobs that have a durable dismissal tombstone. Audit callers
    /// should use [`Self::list_jobs`] instead.
    pub fn list_visible_jobs(&self) -> Result<Vec<StoredJob>, PersistenceError> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id, operation_kind, device_id, session_id, revision, request_digest, state, state_version, \
                    desired_run_state, error_code, error_retryable, created_at, updated_at, dismissed_at \
             FROM transfer_jobs WHERE dismissed_at IS NULL ORDER BY created_at, job_id",
        )?;
        let rows = stmt
            .query_map([], |row| Ok(read_job_row(row)))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|row| {
                row.map_err(|detail| PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_jobs"),
                    detail,
                })
            })
            .collect()
    }

    /// Download jobs for the requested device/session sets and their
    /// completion delivery state in one durable snapshot.
    ///
    /// Both input sets are de-duplicated before being serialized as JSON. The
    /// query therefore always binds exactly two values regardless of page
    /// size, avoiding SQLite's positional-parameter limit while still letting
    /// the partial `(device_id, session_id, created_at, job_id)` index drive
    /// each requested pair. Upload jobs are excluded at the SQL boundary.
    pub fn list_download_session_job_states_for_sessions(
        &self,
        device_ids: &[String],
        session_ids: &[String],
    ) -> Result<Vec<DownloadSessionJobState>, PersistenceError> {
        let device_ids = device_ids.iter().collect::<std::collections::BTreeSet<_>>();
        let session_ids = session_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let device_ids_json = serde_json::to_string(&device_ids)?;
        let session_ids_json = serde_json::to_string(&session_ids)?;
        let mut stmt = self.conn.prepare(DOWNLOAD_SESSION_JOB_STATES_SQL)?;
        let rows = stmt
            .query_map(
                rusqlite::params![device_ids_json, session_ids_json],
                |row| Ok(read_download_session_job_state_row(row)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|row| {
                row.map_err(|detail| PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_jobs/transfer_completion_outbox"),
                    detail,
                })
            })
            .collect()
    }

    pub fn count_jobs(&self) -> Result<u64, PersistenceError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM transfer_jobs", [], |row| row.get(0))?;
        u64::try_from(count).map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: format!("job count {count} is negative"),
        })
    }

    /// Reassembles the durable spec through [`JobSpec::new`], i.e. through
    /// exactly the same validation an in-memory spec goes through. Rows
    /// that no longer form a valid spec surface as
    /// [`JobSpecLoadError::Blocked`] instead of a half-trusted value.
    pub fn job_spec(&self, job_id: &str) -> Result<JobSpec, JobSpecLoadError> {
        let job = self
            .get_job(job_id)?
            .ok_or_else(|| JobSpecLoadError::UnknownJob(job_id.to_string()))?;
        match load_spec(&self.conn, &job)? {
            Ok(spec) => Ok(spec),
            Err(blocked) => Err(JobSpecLoadError::Blocked(Box::new(blocked))),
        }
    }

    /// Ledger rows for `job_id`, in request order (unrequested inventory
    /// files have no ledger row).
    pub fn file_ledger(&self, job_id: &str) -> Result<Vec<FileLedgerEntry>, PersistenceError> {
        read_ledger(&self.conn, job_id)
    }

    // -----------------------------------------------------------------
    // Commit 25: recovery enumeration
    // -----------------------------------------------------------------

    /// Every non-terminal durable job, in creation order.
    ///
    /// Recovery reads *this*, not a JSON sidecar. A job whose spec is
    /// missing, unreadable or inconsistent is returned as
    /// [`RecoverableJob::Blocked`] carrying the reason — it is never
    /// dropped, because a corrupt store that enumerates as empty looks
    /// exactly like a store with no work left.
    pub fn list_recoverable_jobs(&self) -> Result<Vec<RecoverableJob>, PersistenceError> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id, operation_kind, device_id, session_id, revision, request_digest, state, state_version, \
                    desired_run_state, error_code, error_retryable, created_at, updated_at, dismissed_at \
             FROM transfer_jobs \
             WHERE operation_kind = 'download' \
               AND state NOT IN ('succeeded', 'failed', 'cancelled') \
             ORDER BY created_at, job_id",
        )?;
        // `read_job_row` is fallible for *domain* reasons (unknown state,
        // empty identity columns). Those must become `Blocked`, not a query
        // error, so the row mapper yields `(job_id, Result<StoredJob, _>)`
        // and keeps the raw job id available either way.
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    read_job_row(row).map_err(|_| rusqlite::Error::InvalidQuery),
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut out = Vec::with_capacity(rows.len());
        for (job_id, parsed) in rows {
            let job = match parsed {
                Ok(job) => job,
                Err(_) => {
                    out.push(RecoverableJob::Blocked(Box::new(blocked_row(
                        &self.conn, &job_id,
                    )?)));
                    continue;
                }
            };
            match load_spec(&self.conn, &job)? {
                Ok(spec) => {
                    let ledger = read_ledger(&self.conn, &job.job_id)?;
                    out.push(RecoverableJob::Ready(Box::new(RecoverableJobDetail {
                        job,
                        spec,
                        ledger,
                    })));
                }
                Err(blocked) => out.push(RecoverableJob::Blocked(Box::new(blocked))),
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Commit 26: legacy sidecar importer
    // -----------------------------------------------------------------

    pub fn migration_marker(
        &self,
        marker: &str,
    ) -> Result<Option<MigrationMarker>, PersistenceError> {
        Ok(self
            .conn
            .query_row(
                "SELECT marker, applied_at, detail FROM transfer_migration_markers WHERE marker = ?1",
                [marker],
                |row| {
                    Ok(MigrationMarker {
                        marker: row.get(0)?,
                        applied_at: row.get(1)?,
                        detail: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Imports the legacy pending-download JSON sidecar into this store.
    ///
    /// Contract:
    ///
    /// - **One transaction.** Every record plus the migration marker commit
    ///   together, so a failure imports nothing.
    /// - **The sidecar file is never written to.** A corrupt input is
    ///   reported with the specific job id that failed
    ///   ([`LegacyImportError::Corrupt`]) and the original bytes are left
    ///   exactly as they were, so the operator can fix and retry.
    /// - **Idempotent.** A second run short-circuits on the marker; even
    ///   without the marker, records whose natural key already exists are
    ///   reported as `skipped_existing` rather than duplicated.
    pub fn import_legacy_pending_downloads(
        &mut self,
        path: &Path,
        now: &str,
    ) -> Result<LegacyImportOutcome, LegacyImportError> {
        if let Some(marker) = self.migration_marker(LEGACY_PENDING_DOWNLOAD_MARKER)? {
            return Ok(LegacyImportOutcome::AlreadyImported(marker));
        }

        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LegacyImportOutcome::NoLegacyStore)
            }
            Err(source) => {
                return Err(LegacyImportError::Read {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };

        let store: LegacyPendingDownloadStore =
            serde_json::from_slice(&raw).map_err(|error| LegacyImportError::Corrupt {
                path: path.to_path_buf(),
                job_id: None,
                detail: format!("not a valid pending-download store: {error}"),
            })?;
        legacy_import::check_store_version(&store).map_err(|detail| {
            LegacyImportError::Corrupt {
                path: path.to_path_buf(),
                job_id: None,
                detail,
            }
        })?;

        // Convert every record *before* opening the transaction: a
        // conversion failure must not even begin a write.
        let mut converted = Vec::with_capacity(store.downloads.len());
        let mut seen: Vec<String> = Vec::with_capacity(store.downloads.len());
        for record in &store.downloads {
            let job_id = record.job_id.trim().to_string();
            if job_id.is_empty() {
                return Err(LegacyImportError::Corrupt {
                    path: path.to_path_buf(),
                    job_id: None,
                    detail: "a record has an empty job id".to_string(),
                });
            }
            if seen.contains(&job_id) {
                return Err(LegacyImportError::Corrupt {
                    path: path.to_path_buf(),
                    job_id: Some(job_id.clone()),
                    detail: "the store lists this job id more than once".to_string(),
                });
            }
            seen.push(job_id.clone());

            let spec = legacy_import::to_job_spec(record).map_err(|detail| {
                LegacyImportError::Corrupt {
                    path: path.to_path_buf(),
                    job_id: Some(job_id.clone()),
                    detail,
                }
            })?;
            converted.push((job_id, spec));
        }

        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let mut report = LegacyImportReport {
            imported: Vec::new(),
            skipped_existing: Vec::new(),
        };
        for (job_id, spec) in &converted {
            match insert_job_tx(&tx, job_id, spec, now, None) {
                Ok(CreateJobOutcome::Created(_)) => report.imported.push(job_id.clone()),
                Ok(CreateJobOutcome::Existing(_)) => report.skipped_existing.push(job_id.clone()),
                Err(CreateJobError::RequestDigestMismatch(conflict)) => {
                    return Err(LegacyImportError::Conflict(conflict))
                }
                Err(CreateJobError::JobIdCollision { job_id, existing }) => {
                    return Err(LegacyImportError::Corrupt {
                        path: path.to_path_buf(),
                        job_id: Some(job_id.clone()),
                        detail: format!(
                            "job id is already taken by a different logical transfer ({existing})"
                        ),
                    })
                }
                Err(CreateJobError::Persistence(error)) => return Err(error.into()),
            }
        }

        tx.execute(
            "INSERT INTO transfer_migration_markers (marker, applied_at, detail) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                LEGACY_PENDING_DOWNLOAD_MARKER,
                now,
                format!(
                    "imported {} job(s) ({} already present) from {}",
                    report.imported.len(),
                    report.skipped_existing.len(),
                    path.display()
                )
            ],
        )
        .map_err(PersistenceError::from)?;
        tx.commit().map_err(PersistenceError::from)?;

        Ok(LegacyImportOutcome::Imported(report))
    }

    // -----------------------------------------------------------------
    // Commit 29: durable terminal outcomes
    // -----------------------------------------------------------------

    /// Commits a job's **terminal transition and its outcome in the same
    /// transaction**.
    ///
    /// `transfer_jobs.state`/`state_version`/error columns and the
    /// `transfer_completion_outbox` row are one atomic unit, which is the
    /// whole point: a crash between "the job finished" and "the app
    /// learned about it" leaves the outcome sitting unacknowledged in the
    /// outbox, ready to be delivered again on the next start, instead of
    /// leaving a job durably `succeeded` that nothing will ever act on.
    ///
    /// Success, failure and cancellation are all recorded the same way —
    /// a cancelled or failed job the user is still looking at is exactly
    /// as much a result to deliver as a successful one.
    ///
    /// Idempotent: replaying the same terminal outcome returns
    /// [`CompleteJobOutcome::AlreadyRecorded`] and writes nothing.
    /// Replaying a *different* one is
    /// [`CompleteJobError::AlreadyTerminal`].
    ///
    /// This deliberately does not consult
    /// [`super::schema::is_valid_transition`]: the legal-transition graph
    /// belongs to `JobAggregate` (commit 37), and the store's job is to
    /// make the write atomic, not to own a second state machine.
    pub fn complete_job(
        &mut self,
        job_id: &str,
        outcome: &TerminalOutcome,
        now: &str,
    ) -> Result<CompleteJobOutcome, CompleteJobError> {
        self.complete_job_inner(job_id, outcome, now, None)
    }

    #[doc(hidden)]
    pub fn complete_job_aborting_after(
        &mut self,
        job_id: &str,
        outcome: &TerminalOutcome,
        now: &str,
        abort: CompleteJobAbort,
    ) -> Result<CompleteJobOutcome, CompleteJobError> {
        self.complete_job_inner(job_id, outcome, now, Some(abort))
    }

    fn complete_job_inner(
        &mut self,
        job_id: &str,
        outcome: &TerminalOutcome,
        now: &str,
        abort: Option<CompleteJobAbort>,
    ) -> Result<CompleteJobOutcome, CompleteJobError> {
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;

        let Some(job) = read_job(&tx, "job_id", job_id)? else {
            return Err(CompleteJobError::UnknownJob(job_id.to_string()));
        };

        if let Some(existing) = read_completion(&tx, job_id)? {
            if &existing.outcome == outcome {
                return Ok(CompleteJobOutcome::AlreadyRecorded(Box::new(existing)));
            }
            return Err(CompleteJobError::AlreadyTerminal {
                job_id: job_id.to_string(),
                existing: existing.outcome,
                requested: outcome.clone(),
            });
        }
        // A terminal job with no outbox row can only come from rows edited
        // underneath the store; treat it as the same conflict rather than
        // silently appending a second ending.
        if job.state.is_terminal() {
            let existing = match (job.state, job.error.clone()) {
                (JobStateTag::Succeeded, _) => TerminalOutcome::Succeeded,
                (JobStateTag::Cancelled, _) => TerminalOutcome::Cancelled,
                (JobStateTag::Failed, Some((code, retryable))) => {
                    TerminalOutcome::Failed { code, retryable }
                }
                (state, _) => {
                    return Err(CompleteJobError::Persistence(PersistenceError::Corrupt {
                        path: self.path.clone(),
                        detail: format!(
                            "job {job_id} is in terminal state {} without usable error columns",
                            state.as_db_str()
                        ),
                    }))
                }
            };
            if &existing == outcome {
                // Same ending, missing row: re-record it so the outcome is
                // observable again rather than lost forever.
                let record = insert_outbox_row(&tx, job_id, outcome, job.state_version, now)?;
                tx.commit().map_err(PersistenceError::from)?;
                return Ok(CompleteJobOutcome::Recorded(Box::new(record)));
            }
            return Err(CompleteJobError::AlreadyTerminal {
                job_id: job_id.to_string(),
                existing,
                requested: outcome.clone(),
            });
        }

        let next_version = job.state_version.checked_add(1).ok_or_else(|| {
            CompleteJobError::Persistence(PersistenceError::Conflict {
                detail: format!("job {job_id} state version exhausted u64 range"),
            })
        })?;
        let (error_code, error_retryable) = outcome.error_columns();
        tx.execute(
            "UPDATE transfer_jobs \
             SET state = ?2, state_version = ?3, error_code = ?4, error_retryable = ?5, \
                 updated_at = ?6 \
             WHERE job_id = ?1",
            rusqlite::params![
                job_id,
                outcome.as_db_str(),
                checked_i64(next_version, "state_version")?,
                error_code,
                error_retryable,
                now,
            ],
        )?;
        abort_completion_if(abort, CompleteJobAbort::AfterStateUpdate)?;

        let record = insert_outbox_row(&tx, job_id, outcome, next_version, now)?;
        abort_completion_if(abort, CompleteJobAbort::AfterOutboxRow)?;

        tx.commit().map_err(PersistenceError::from)?;
        Ok(CompleteJobOutcome::Recorded(Box::new(record)))
    }

    /// Every outcome that has not been acknowledged yet, oldest first.
    ///
    /// This is the queue a consumer drains. It reads only committed rows,
    /// so a job whose terminal transition never committed is simply not
    /// here — there is no window where the state says "done" and the
    /// outbox disagrees.
    pub fn pending_completions(&self) -> Result<Vec<CompletionRecord>, PersistenceError> {
        read_completions(&self.conn, true)
    }

    /// Every outbox row, acknowledged or not, oldest first.
    pub fn all_completions(&self) -> Result<Vec<CompletionRecord>, PersistenceError> {
        read_completions(&self.conn, false)
    }

    pub fn completion(&self, job_id: &str) -> Result<Option<CompletionRecord>, PersistenceError> {
        read_completion(&self.conn, job_id)
    }

    /// Marks one outcome delivered. Only a consumer that has *durably*
    /// applied the outcome may call this — everything before the ack is
    /// re-runnable, and everything after is gone.
    pub fn acknowledge_completion(
        &mut self,
        job_id: &str,
        now: &str,
    ) -> Result<AckOutcome, PersistenceError> {
        let tx = self.conn.transaction()?;
        let Some(existing) = read_completion(&tx, job_id)? else {
            return Ok(AckOutcome::Unknown);
        };
        if existing.is_acknowledged() {
            return Ok(AckOutcome::AlreadyAcknowledged(Box::new(existing)));
        }
        tx.execute(
            "UPDATE transfer_completion_outbox SET acknowledged_at = ?2 WHERE job_id = ?1",
            rusqlite::params![job_id, now],
        )?;
        let acknowledged =
            read_completion(&tx, job_id)?.ok_or_else(|| PersistenceError::NotFound {
                detail: format!("completion for job {job_id} vanished during acknowledgement"),
            })?;
        tx.commit()?;
        Ok(AckOutcome::Acknowledged(Box::new(acknowledged)))
    }

    /// Returns the most recent retry child for a parent, if one exists.
    /// This is the restart-safe replacement for the coordinator's in-memory
    /// `parent -> child` map.
    pub fn latest_retry_child(
        &self,
        parent_job_id: &str,
    ) -> Result<Option<StoredJob>, PersistenceError> {
        let child_id: Option<String> = self
            .conn
            .query_row(
                "SELECT child_job_id FROM transfer_job_lineage \
                 WHERE parent_job_id = ?1 ORDER BY attempt DESC LIMIT 1",
                [parent_job_id],
                |row| row.get(0),
            )
            .optional()?;
        child_id
            .map(|id| self.get_job(&id))
            .transpose()
            .map(|job| job.flatten())
    }

    /// Creates a new retry child and records its parent relationship in the
    /// same transaction as the copied spec/files/ledger. A replay for the
    /// same parent while its latest child is still non-terminal returns that
    /// child, so a crash or a double-click cannot create sibling workers.
    pub fn spawn_retry_job(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        now: &str,
    ) -> Result<RetryJobOutcome, RetryJobError> {
        self.spawn_retry_job_inner(
            parent_job_id,
            child_job_id,
            now,
            RetrySpawnPolicy::StandardDownload,
            || Ok(()),
        )
    }

    /// Creates a download retry whose durable file evidence starts from
    /// scratch. This is reserved for an interrupted attempt that policy says
    /// must not resume (startup interruption or device/network loss). Its old
    /// staging bytes are discarded only when no active download owns the same
    /// publication identity, so copying a `partial` or `verified` ledger into
    /// the new attempt can never claim evidence that no longer exists.
    pub(crate) fn spawn_fresh_download_retry_job<F>(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        now: &str,
        discard_staging: F,
    ) -> Result<RetryJobOutcome, RetryJobError>
    where
        F: FnOnce() -> Result<(), PersistenceError>,
    {
        self.spawn_retry_job_inner(
            parent_job_id,
            child_job_id,
            now,
            RetrySpawnPolicy::FreshDownload,
            discard_staging,
        )
    }

    /// Enqueue-only repeat for an acknowledged, dismissed failed download.
    /// Unlike tray retry, this deliberately accepts the tombstoned parent so
    /// a user can start the same signed session again without erasing audit
    /// history. It still uses the fresh-ledger/staging guard and refuses a
    /// non-dismissed parent, so callers cannot use it to bypass ordinary retry
    /// policy.
    pub(crate) fn spawn_fresh_download_enqueue_repeat<F>(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        now: &str,
        discard_staging: F,
    ) -> Result<RetryJobOutcome, RetryJobError>
    where
        F: FnOnce() -> Result<(), PersistenceError>,
    {
        self.spawn_retry_job_inner(
            parent_job_id,
            child_job_id,
            now,
            RetrySpawnPolicy::DismissedDownloadEnqueue,
            discard_staging,
        )
    }

    /// Upload-specific retry entry point. A cancelled upload is a valid fresh
    /// attempt once its terminal completion has been acknowledged; downloads
    /// intentionally retain the stricter failed-and-retryable rule exposed by
    /// [`Self::spawn_retry_job`].
    pub(crate) fn spawn_upload_retry_job(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        now: &str,
    ) -> Result<RetryJobOutcome, RetryJobError> {
        self.spawn_retry_job_inner(
            parent_job_id,
            child_job_id,
            now,
            RetrySpawnPolicy::Upload,
            || Ok(()),
        )
    }

    fn spawn_retry_job_inner<F>(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        now: &str,
        policy: RetrySpawnPolicy,
        discard_staging: F,
    ) -> Result<RetryJobOutcome, RetryJobError>
    where
        F: FnOnce() -> Result<(), PersistenceError>,
    {
        // Fresh download retry owns both the durable active-attempt decision
        // and destructive staging cleanup. IMMEDIATE prevents another store
        // connection from creating or advancing a same-revision attempt in
        // the gap between the query and cleanup.
        let fresh_download_ledger = matches!(
            policy,
            RetrySpawnPolicy::FreshDownload | RetrySpawnPolicy::DismissedDownloadEnqueue
        );
        let behavior = if fresh_download_ledger {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        };
        let tx = self
            .conn
            .transaction_with_behavior(behavior)
            .map_err(PersistenceError::from)?;
        let parent = read_job(&tx, "job_id", parent_job_id)?
            .ok_or_else(|| RetryJobError::UnknownJob(parent_job_id.to_string()))?;
        if policy == RetrySpawnPolicy::DismissedDownloadEnqueue
            && (parent.operation_kind != OperationKind::Download || parent.dismissed_at.is_none())
        {
            return Err(RetryJobError::NotRetryable {
                job_id: parent_job_id.to_string(),
            });
        }
        if parent.dismissed_at.is_some() && policy != RetrySpawnPolicy::DismissedDownloadEnqueue {
            return Err(RetryJobError::DismissedParent {
                job_id: parent_job_id.to_string(),
            });
        }
        let retryable_failed = matches!(parent.state, JobStateTag::Failed)
            && parent
                .error
                .as_ref()
                .is_some_and(|(_, retryable)| *retryable);
        let acknowledged_cancelled_upload = policy == RetrySpawnPolicy::Upload
            && parent.operation_kind == OperationKind::Upload
            && parent.state == JobStateTag::Cancelled;
        if !retryable_failed && !acknowledged_cancelled_upload {
            return Err(RetryJobError::NotRetryable {
                job_id: parent_job_id.to_string(),
            });
        }
        let Some(completion) = read_completion(&tx, parent_job_id)? else {
            return Err(RetryJobError::UnacknowledgedParent {
                job_id: parent_job_id.to_string(),
            });
        };
        if !completion.is_acknowledged() {
            return Err(RetryJobError::UnacknowledgedParent {
                job_id: parent_job_id.to_string(),
            });
        }

        if parent.operation_kind == OperationKind::Upload {
            let successful_child: Option<String> = tx
                .query_row(
                    "SELECT l.child_job_id FROM transfer_job_lineage l \
                     JOIN transfer_jobs j ON j.job_id = l.child_job_id \
                     WHERE l.parent_job_id = ?1 AND j.state = 'succeeded' \
                     ORDER BY l.attempt DESC LIMIT 1",
                    [parent_job_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(child_job_id) = successful_child {
                return Err(RetryJobError::SuccessfulDescendant {
                    parent_job_id: parent_job_id.to_string(),
                    child_job_id,
                });
            }
        }

        if let Some(existing) = read_job(&tx, "job_id", child_job_id)? {
            let linked: Option<String> = tx
                .query_row(
                    "SELECT parent_job_id FROM transfer_job_lineage WHERE child_job_id = ?1",
                    [child_job_id],
                    |row| row.get(0),
                )
                .optional()?;
            if linked.as_deref() == Some(parent_job_id) {
                return Ok(RetryJobOutcome::Existing(Box::new(existing)));
            }
            return Err(RetryJobError::JobIdCollision {
                job_id: child_job_id.to_string(),
            });
        }

        let previous_child: Option<(String, i64)> = tx
            .query_row(
                "SELECT l.child_job_id, l.attempt FROM transfer_job_lineage l \
                 JOIN transfer_jobs j ON j.job_id = l.child_job_id \
                 WHERE l.parent_job_id = ?1 ORDER BY l.attempt DESC LIMIT 1",
                [parent_job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if policy != RetrySpawnPolicy::DismissedDownloadEnqueue {
            if let Some((existing_id, _)) = previous_child.as_ref() {
                if let Some(existing) = read_job(&tx, "job_id", existing_id)? {
                    if !existing.state.is_terminal() {
                        return Ok(RetryJobOutcome::Existing(Box::new(existing)));
                    }
                }
            }
        }

        if fresh_download_ledger && parent.operation_kind == OperationKind::Download {
            let active_job_id: Option<String> = tx
                .query_row(
                    "SELECT job_id FROM transfer_jobs \
                     WHERE operation_kind = 'download' \
                       AND device_id = ?1 AND session_id = ?2 AND revision = ?3 \
                       AND state NOT IN ('succeeded', 'failed', 'cancelled') \
                     ORDER BY created_at DESC, job_id DESC LIMIT 1",
                    rusqlite::params![
                        parent.identity.device_id().as_str(),
                        parent.identity.session_id().as_str(),
                        parent.identity.revision(),
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(active_job_id) = active_job_id {
                let active = read_job(&tx, "job_id", &active_job_id)?.ok_or_else(|| {
                    RetryJobError::Persistence(PersistenceError::NotFound {
                        detail: format!(
                            "active same-revision retry {active_job_id} vanished during selection"
                        ),
                    })
                })?;
                return Ok(RetryJobOutcome::Existing(Box::new(active)));
            }
        }

        // An enqueue replay of a dismissed root is permanently idempotent
        // once it has produced a direct child, even after that child becomes
        // terminal. The active identity guard above must run first, however:
        // an explicit retry descendant owns the shared staging and is the
        // current attempt the stale root enqueue must resolve to.
        if policy == RetrySpawnPolicy::DismissedDownloadEnqueue {
            if let Some((existing_id, _)) = previous_child.as_ref() {
                if let Some(existing) = read_job(&tx, "job_id", existing_id)? {
                    return Ok(RetryJobOutcome::Existing(Box::new(existing)));
                }
            }
        }

        let attempt = match previous_child {
            Some((_, attempt)) => attempt.checked_add(1).ok_or_else(|| {
                RetryJobError::Persistence(PersistenceError::Conflict {
                    detail: format!("retry attempt for {parent_job_id} exhausted SQLite range"),
                })
            })?,
            None => 1,
        };

        if parent.operation_kind == OperationKind::Upload {
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
                    [parent_job_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(|error| {
                    RetryJobError::Persistence(PersistenceError::Corrupt {
                        path: PathBuf::from("transfer_upload_job_specs"),
                        detail: format!(
                            "upload retry parent {parent_job_id} has no immutable spec: {error}"
                        ),
                    })
                })?;
            let natural_key = format!(
                "upload:{}#retry:{child_job_id}",
                length_prefixed_key_for_retry(&entry_key, &revision)
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
                    parent.request_digest.to_hex(),
                    now,
                ],
            )?;
            tx.execute(
                "INSERT INTO transfer_upload_job_specs \
                     (job_id, entry_key, revision, input_digest, object_prefix) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    child_job_id,
                    entry_key,
                    revision,
                    input_digest,
                    object_prefix,
                ],
            )?;
            let (label, target_label, total_bytes): (String, String, i64) = tx
                .query_row(
                    "SELECT label, target_label, total_bytes FROM transfer_upload_activity \
                     WHERE job_id = ?1",
                    [parent_job_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| {
                    RetryJobError::Persistence(PersistenceError::Corrupt {
                        path: PathBuf::from("transfer_upload_activity"),
                        detail: format!(
                            "upload retry parent {parent_job_id} has no activity row: {error}"
                        ),
                    })
                })?;
            tx.execute(
                "INSERT INTO transfer_upload_activity (
                     job_id, label, target_label, total_bytes, confirmed_bytes, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
                rusqlite::params![child_job_id, label, target_label, total_bytes, now],
            )?;
            tx.execute(
                "INSERT INTO transfer_job_lineage (child_job_id, parent_job_id, attempt, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![child_job_id, parent_job_id, attempt, now],
            )?;
            let child = read_job(&tx, "job_id", child_job_id)?.ok_or_else(|| {
                RetryJobError::Persistence(PersistenceError::NotFound {
                    detail: format!("upload retry child {child_job_id} vanished after insert"),
                })
            })?;
            tx.commit().map_err(PersistenceError::from)?;
            return Ok(RetryJobOutcome::Created(Box::new(child)));
        }
        if fresh_download_ledger {
            discard_staging()?;
        }
        let natural_key = format!("{}#retry:{child_job_id}", parent.identity.natural_key());
        tx.execute(
            "INSERT INTO transfer_jobs (
             job_id, operation_kind, natural_key, device_id, session_id, revision, request_digest,
             state, state_version, desired_run_state, created_at, updated_at
         ) VALUES (?1, 'download', ?2, ?3, ?4, ?5, ?6, 'queued', 1, 'run', ?7, ?7)",
            rusqlite::params![
                child_job_id,
                natural_key,
                parent.identity.device_id().as_str(),
                parent.identity.session_id().as_str(),
                parent.identity.revision(),
                parent.request_digest.to_hex(),
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_job_specs (
                 job_id, spec_version, full_session, date_label, publication_revision,
                 publication_payload, publication_signature, publication_public_key
             ) SELECT ?2, spec_version, full_session, date_label, publication_revision,
                 publication_payload, publication_signature, publication_public_key
             FROM transfer_job_specs WHERE job_id = ?1",
            rusqlite::params![parent_job_id, child_job_id],
        )?;
        tx.execute(
            "INSERT INTO transfer_job_files (
                 job_id, inventory_index, request_index, file_id, display_path, size_bytes, sha256
             ) SELECT ?2, inventory_index, request_index, file_id, display_path, size_bytes, sha256
             FROM transfer_job_files WHERE job_id = ?1",
            rusqlite::params![parent_job_id, child_job_id],
        )?;
        if fresh_download_ledger {
            tx.execute(
                "INSERT INTO transfer_file_ledger (
                     job_id, file_id, status, bytes_confirmed, verified_sha256, updated_at
                 ) SELECT ?2, file_id, 'missing', 0, NULL, ?3
                 FROM transfer_file_ledger WHERE job_id = ?1",
                rusqlite::params![parent_job_id, child_job_id, now],
            )?;
        } else {
            tx.execute(
                "INSERT INTO transfer_file_ledger (
                     job_id, file_id, status, bytes_confirmed, verified_sha256, updated_at
                 ) SELECT ?2, file_id, status, bytes_confirmed, verified_sha256, ?3
                 FROM transfer_file_ledger WHERE job_id = ?1",
                rusqlite::params![parent_job_id, child_job_id, now],
            )?;
        }
        tx.execute(
            "INSERT INTO transfer_job_lineage (child_job_id, parent_job_id, attempt, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![child_job_id, parent_job_id, attempt, now],
        )?;
        let child = read_job(&tx, "job_id", child_job_id)?.ok_or_else(|| {
            RetryJobError::Persistence(PersistenceError::NotFound {
                detail: format!("retry child {child_job_id} vanished before commit"),
            })
        })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(RetryJobOutcome::Created(Box::new(child)))
    }

    /// Reads the durable retry relationship for one child.
    pub fn retry_parent(
        &self,
        child_job_id: &str,
    ) -> Result<Option<RetryLineageRecord>, PersistenceError> {
        let row = self
            .conn
            .query_row(
                "SELECT parent_job_id, child_job_id, attempt, created_at \
                 FROM transfer_job_lineage WHERE child_job_id = ?1",
                [child_job_id],
                |row| {
                    let attempt: i64 = row.get(2)?;
                    Ok((row.get(0)?, row.get(1)?, attempt, row.get(3)?))
                },
            )
            .optional()?;
        row.map(|(parent_job_id, child_job_id, attempt, created_at)| {
            Ok(RetryLineageRecord {
                parent_job_id,
                child_job_id,
                attempt: u64::try_from(attempt).map_err(|_| PersistenceError::Corrupt {
                    path: PathBuf::from("transfer_job_lineage"),
                    detail: format!("negative retry attempt {attempt}"),
                })?,
                created_at,
            })
        })
        .transpose()
    }

    // -----------------------------------------------------------------
    // Commit 34: durable-context lifecycle the app needs in place of the
    // pending-download JSON
    // -----------------------------------------------------------------

    /// Tombstones a terminal job after its completion outcome has been
    /// acknowledged. Upload jobs are also required to have no pending
    /// multipart handles: otherwise hiding the activity would hide remote
    /// work that still needs an abort/finish decision.
    ///
    /// This operation never deletes the job or any dependent evidence. It is
    /// idempotent for an already-dismissed row and returns `false` in that
    /// case.
    pub fn dismiss_job(&mut self, job_id: &str, now: &str) -> Result<bool, DismissJobError> {
        let tx = self.conn.transaction().map_err(PersistenceError::from)?;
        let job = read_job(&tx, "job_id", job_id)?
            .ok_or_else(|| DismissJobError::UnknownJob(job_id.to_string()))?;
        if job.dismissed_at.is_some() {
            tx.commit().map_err(PersistenceError::from)?;
            return Ok(false);
        }
        if !job.state.is_terminal() {
            return Err(DismissJobError::NotTerminal {
                job_id: job_id.to_string(),
                state: job.state.as_db_str().to_string(),
            });
        }
        let completion =
            read_completion(&tx, job_id)?.ok_or_else(|| DismissJobError::Unacknowledged {
                job_id: job_id.to_string(),
            })?;
        if !completion.is_acknowledged() {
            return Err(DismissJobError::Unacknowledged {
                job_id: job_id.to_string(),
            });
        }
        if job.operation_kind == OperationKind::Upload {
            let upload_entry_key: Option<String> = tx
                .query_row(
                    "SELECT entry_key FROM transfer_upload_job_specs WHERE job_id = ?1",
                    [job_id],
                    |row| row.get(0),
                )
                .optional()?;
            let pending: i64 = tx.query_row(
                "SELECT COUNT(*) FROM transfer_uploads
                 WHERE job_id = ?1
                    OR (job_id IS NULL AND
                        (transfer_key = ?1 OR
                         (length(?2) > 0 AND entry_key = ?2)))",
                rusqlite::params![job_id, upload_entry_key],
                |row| row.get(0),
            )?;
            if pending != 0 {
                return Err(DismissJobError::PendingMultipart {
                    job_id: job_id.to_string(),
                });
            }
        }
        let changed = tx.execute(
            "UPDATE transfer_jobs SET dismissed_at = ?2, updated_at = ?2 \
             WHERE job_id = ?1 AND dismissed_at IS NULL",
            rusqlite::params![job_id, now],
        )?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(changed > 0)
    }

    /// Removes a job and everything hanging off it (spec, files, ledger,
    /// outbox row) in one transaction.
    ///
    /// Refuses while the job still has an **unacknowledged** outcome:
    /// deleting then would throw away a result the app has not learned
    /// about yet, which is the exact loss the outbox exists to prevent.
    pub fn delete_job(&mut self, job_id: &str) -> Result<bool, PersistenceError> {
        let tx = self.conn.transaction()?;
        if let Some(completion) = read_completion(&tx, job_id)? {
            if !completion.is_acknowledged() {
                return Err(PersistenceError::Conflict {
                    detail: format!(
                        "job {job_id} has an unacknowledged {} outcome; acknowledge it before \
                         deleting the job",
                        completion.outcome
                    ),
                });
            }
        }
        let removed = tx.execute("DELETE FROM transfer_jobs WHERE job_id = ?1", [job_id])?;
        tx.commit()?;
        Ok(removed > 0)
    }

    /// Moves an existing durable job (spec, files, ledger) onto a new job
    /// id and returns it to `queued`, in one transaction.
    ///
    /// This is what a retry needs: the coordinator's retry contract is "a
    /// new job id, never a resurrected row", but the *spec* is the same
    /// logical transfer and its natural key is unique, so it has to move
    /// rather than be re-created alongside itself. Doing it in one
    /// transaction is what keeps a crash mid-retry from leaving a live job
    /// with no durable spec.
    ///
    /// The superseded outcome is dropped with the old id, so it is
    /// required to have been acknowledged first — same rule as
    /// [`TransferStore::delete_job`].
    pub fn retarget_job(
        &mut self,
        old_job_id: &str,
        new_job_id: &str,
        now: &str,
    ) -> Result<StoredJob, PersistenceError> {
        let tx = self.conn.transaction()?;
        // Parent-key updates would trip the child foreign keys mid-statement;
        // deferring them to commit time is what lets one transaction move a
        // whole job without ever leaving a dangling child row visible.
        tx.pragma_update(None, "defer_foreign_keys", true)?;

        if read_job(&tx, "job_id", old_job_id)?.is_none() {
            return Err(PersistenceError::NotFound {
                detail: format!("job {old_job_id} does not exist"),
            });
        }
        if read_job(&tx, "job_id", new_job_id)?.is_some() {
            return Err(PersistenceError::Conflict {
                detail: format!("job id {new_job_id:?} is already taken"),
            });
        }
        if let Some(completion) = read_completion(&tx, old_job_id)? {
            if !completion.is_acknowledged() {
                return Err(PersistenceError::Conflict {
                    detail: format!(
                        "job {old_job_id} has an unacknowledged {} outcome; acknowledge it before \
                         retrying",
                        completion.outcome
                    ),
                });
            }
            tx.execute(
                "DELETE FROM transfer_completion_outbox WHERE job_id = ?1",
                [old_job_id],
            )?;
        }

        tx.execute(
            "UPDATE transfer_jobs \
             SET job_id = ?2, state = 'queued', state_version = state_version + 1, \
                 error_code = NULL, error_retryable = NULL, dismissed_at = NULL, updated_at = ?3 \
             WHERE job_id = ?1",
            rusqlite::params![old_job_id, new_job_id, now],
        )?;
        for table in [
            "transfer_job_specs",
            "transfer_job_files",
            "transfer_file_ledger",
        ] {
            tx.execute(
                &format!("UPDATE {table} SET job_id = ?2 WHERE job_id = ?1"),
                rusqlite::params![old_job_id, new_job_id],
            )?;
        }

        let moved =
            read_job(&tx, "job_id", new_job_id)?.ok_or_else(|| PersistenceError::NotFound {
                detail: format!("job {old_job_id} vanished while being retargeted to {new_job_id}"),
            })?;
        tx.commit()?;
        Ok(moved)
    }
}

// ---------------------------------------------------------------------
// Transaction-scoped helpers
// ---------------------------------------------------------------------

fn checked_i64(value: u64, field: &str) -> Result<i64, PersistenceError> {
    i64::try_from(value).map_err(|_| PersistenceError::Conflict {
        detail: format!("{field} value {value} exceeds SQLite INTEGER range"),
    })
}

fn desired_run_state_db(value: DesiredRunState) -> &'static str {
    match value {
        DesiredRunState::Run => "run",
        DesiredRunState::Paused => "paused",
    }
}

fn desired_run_state_from_db(value: &str) -> Option<DesiredRunState> {
    match value {
        "run" => Some(DesiredRunState::Run),
        "paused" => Some(DesiredRunState::Paused),
        _ => None,
    }
}

fn length_prefixed_key_for_retry(entry_key: &str, revision: &str) -> String {
    let mut key = String::new();
    for part in [entry_key, revision] {
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(part);
    }
    key
}

/// The whole of commit 23's write path, factored out of
/// [`TransferStore::create_job`] so the legacy importer can run many of
/// them inside *one* transaction.
fn insert_job_tx(
    tx: &Transaction<'_>,
    job_id: &str,
    spec: &JobSpec,
    now: &str,
    abort: Option<CreateJobAbort>,
) -> Result<CreateJobOutcome, CreateJobError> {
    let identity = spec.identity();
    let natural_key = identity.natural_key();
    let requested_digest = spec.request_digest();

    // Commit 24: an existing natural key only counts as an idempotent hit
    // when the request content matches too.
    if let Some(existing) = read_latest_job_by_identity(tx, identity)? {
        if existing.request_digest == requested_digest {
            return Ok(CreateJobOutcome::Existing(Box::new(existing)));
        }
        let detail = describe_digest_mismatch(tx, &existing, spec)?;
        return Err(CreateJobError::RequestDigestMismatch(Box::new(
            JobRequestConflict {
                job_id: existing.job_id,
                identity: existing.identity,
                existing_digest: existing.request_digest,
                requested_digest,
                detail,
            },
        )));
    }
    if let Some(existing) = read_job(tx, "job_id", job_id)? {
        return Err(CreateJobError::JobIdCollision {
            job_id: job_id.to_string(),
            existing: existing.identity.to_string(),
        });
    }

    tx.execute(
        "INSERT INTO transfer_jobs (
             job_id, operation_kind, natural_key, device_id, session_id, revision, request_digest,
             state, state_version, desired_run_state, created_at, updated_at
         ) VALUES (?1, 'download', ?2, ?3, ?4, ?5, ?6, 'queued', 1, 'run', ?7, ?7)",
        rusqlite::params![
            job_id,
            natural_key,
            identity.device_id().as_str(),
            identity.session_id().as_str(),
            identity.revision(),
            requested_digest.to_hex(),
            now,
        ],
    )?;
    abort_if(abort, CreateJobAbort::AfterJobRow)?;

    let publication = spec.publication();
    tx.execute(
        "INSERT INTO transfer_job_specs (
             job_id, spec_version, full_session, date_label, publication_revision,
             publication_payload, publication_signature, publication_public_key
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            job_id,
            CURRENT_JOB_SPEC_VERSION,
            i64::from(spec.full_session()),
            spec.date_label(),
            publication.revision(),
            publication.payload(),
            publication.signature(),
            publication.public_key(),
        ],
    )?;
    abort_if(abort, CreateJobAbort::AfterSpecRow)?;

    for (inventory_index, file) in spec.session_files().iter().enumerate() {
        let request_index = spec
            .request_position(file.file_id())
            .map(|index| checked_i64(index as u64, "request_index"))
            .transpose()
            .map_err(CreateJobError::Persistence)?;
        tx.execute(
            "INSERT INTO transfer_job_files (
                 job_id, inventory_index, request_index, file_id, display_path, size_bytes, sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                job_id,
                checked_i64(inventory_index as u64, "inventory_index")?,
                request_index,
                file.file_id().as_str(),
                file.display_path(),
                checked_i64(file.size_bytes(), "size_bytes")?,
                file.sha256(),
            ],
        )?;
    }
    abort_if(abort, CreateJobAbort::AfterFiles)?;

    for file in spec.requested_files() {
        tx.execute(
            "INSERT INTO transfer_file_ledger (job_id, file_id, status, bytes_confirmed, updated_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            rusqlite::params![
                job_id,
                file.file_id().as_str(),
                FileLedgerStatus::Missing.as_db_str(),
                now,
            ],
        )?;
    }
    abort_if(abort, CreateJobAbort::AfterLedger)?;

    let job = read_job(tx, "job_id", job_id)?.ok_or_else(|| {
        CreateJobError::Persistence(PersistenceError::NotFound {
            detail: format!("job {job_id} vanished immediately after insert"),
        })
    })?;
    Ok(CreateJobOutcome::Created(Box::new(job)))
}

fn insert_outbox_row(
    tx: &Transaction<'_>,
    job_id: &str,
    outcome: &TerminalOutcome,
    state_version: u64,
    now: &str,
) -> Result<CompletionRecord, CompleteJobError> {
    let (error_code, error_retryable) = outcome.error_columns();
    let operation_kind: String = tx.query_row(
        "SELECT operation_kind FROM transfer_jobs WHERE job_id = ?1",
        [job_id],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO transfer_completion_outbox (
             job_id, operation_kind, outcome, error_code, error_retryable,
             state_version, recorded_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            job_id,
            operation_kind,
            outcome.as_db_str(),
            error_code,
            error_retryable,
            checked_i64(state_version, "state_version")?,
            now,
        ],
    )?;
    read_completion(tx, job_id)?.ok_or_else(|| {
        CompleteJobError::Persistence(PersistenceError::NotFound {
            detail: format!("outbox row for job {job_id} vanished immediately after insert"),
        })
    })
}

fn abort_completion_if(
    abort: Option<CompleteJobAbort>,
    stage: CompleteJobAbort,
) -> Result<(), CompleteJobError> {
    if abort == Some(stage) {
        return Err(CompleteJobError::Persistence(PersistenceError::Conflict {
            detail: format!("simulated crash at {stage:?}"),
        }));
    }
    Ok(())
}

const COMPLETION_COLUMNS: &str = "sequence, job_id, operation_kind, outcome, error_code, \
                                  error_retryable, state_version, recorded_at, \
                                  acknowledged_at";

fn read_completion(
    conn: &Connection,
    job_id: &str,
) -> Result<Option<CompletionRecord>, PersistenceError> {
    let row: Option<Result<CompletionRecord, String>> = conn
        .query_row(
            &format!(
                "SELECT {COMPLETION_COLUMNS} FROM transfer_completion_outbox WHERE job_id = ?1"
            ),
            [job_id],
            |row| Ok(read_completion_row(row)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some(Ok(record)) => Ok(Some(record)),
        Some(Err(detail)) => Err(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_completion_outbox"),
            detail,
        }),
    }
}

fn read_completions(
    conn: &Connection,
    unacknowledged_only: bool,
) -> Result<Vec<CompletionRecord>, PersistenceError> {
    let filter = if unacknowledged_only {
        "WHERE acknowledged_at IS NULL "
    } else {
        ""
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT {COMPLETION_COLUMNS} FROM transfer_completion_outbox {filter}ORDER BY sequence"
    ))?;
    let rows = stmt
        .query_map([], |row| Ok(read_completion_row(row)))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            row.map_err(|detail| PersistenceError::Corrupt {
                path: PathBuf::from("transfer_completion_outbox"),
                detail,
            })
        })
        .collect()
}

fn read_completion_row(row: &rusqlite::Row<'_>) -> Result<CompletionRecord, String> {
    let get = |index: usize| -> Result<String, String> {
        row.get::<_, String>(index)
            .map_err(|e| format!("column {index}: {e}"))
    };
    let sequence: i64 = row.get(0).map_err(|e| format!("sequence: {e}"))?;
    let job_id = get(1)?;
    let operation_kind_str = get(2)?;
    let outcome = get(3)?;
    let error_code: Option<String> = row.get(4).map_err(|e| format!("error_code: {e}"))?;
    let error_retryable: Option<i64> = row.get(5).map_err(|e| format!("error_retryable: {e}"))?;
    let state_version: i64 = row.get(6).map_err(|e| format!("state_version: {e}"))?;
    let sequence = u64::try_from(sequence)
        .map_err(|_| format!("job {job_id}: sequence {sequence} is negative"))?;
    let operation_kind = OperationKind::from_db_str(&operation_kind_str).ok_or_else(|| {
        format!("job {job_id}: unrecognized operation_kind {operation_kind_str:?}")
    })?;
    let state_version = u64::try_from(state_version)
        .map_err(|_| format!("job {job_id}: state_version {state_version} is negative"))?;
    let outcome_job_id = job_id.clone();
    Ok(CompletionRecord {
        sequence,
        job_id,
        operation_kind,
        outcome: TerminalOutcome::from_columns(&outcome, error_code, error_retryable)
            .map_err(|detail| format!("job {outcome_job_id}: {detail}"))?,
        state_version,
        recorded_at: get(7)?,
        acknowledged_at: row.get(8).map_err(|e| format!("acknowledged_at: {e}"))?,
    })
}

fn abort_if(abort: Option<CreateJobAbort>, stage: CreateJobAbort) -> Result<(), CreateJobError> {
    if abort == Some(stage) {
        return Err(CreateJobError::Persistence(PersistenceError::Conflict {
            detail: format!("simulated crash at {stage:?}"),
        }));
    }
    Ok(())
}

/// Names the first field that differs between the stored job and the
/// incoming spec, so the conflict is actionable without diffing hashes.
fn describe_digest_mismatch(
    conn: &Connection,
    existing: &StoredJob,
    spec: &JobSpec,
) -> Result<String, PersistenceError> {
    let stored = match load_spec(conn, existing)? {
        Ok(stored) => stored,
        Err(blocked) => {
            return Ok(format!(
                "the stored spec is itself unusable ({:?}: {})",
                blocked.reason, blocked.detail
            ))
        }
    };

    if stored.publication() != spec.publication() {
        return Ok("the signed publication material differs".to_string());
    }
    if stored.full_session() != spec.full_session() {
        return Ok(format!(
            "full_session differs (stored {}, requested {})",
            stored.full_session(),
            spec.full_session()
        ));
    }
    if stored.session_files().len() != spec.session_files().len() {
        return Ok(format!(
            "the signed inventory differs in length (stored {}, requested {})",
            stored.session_files().len(),
            spec.session_files().len()
        ));
    }
    for (stored_file, new_file) in stored.session_files().iter().zip(spec.session_files()) {
        if stored_file != new_file {
            return Ok(format!(
                "inventory entry {:?} differs (stored size {} sha {}, requested size {} sha {})",
                stored_file.file_id().as_str(),
                stored_file.size_bytes(),
                stored_file.sha256(),
                new_file.size_bytes(),
                new_file.sha256(),
            ));
        }
    }
    let stored_plan: Vec<&str> = stored
        .requested_files()
        .map(|f| f.file_id().as_str())
        .collect();
    let new_plan: Vec<&str> = spec
        .requested_files()
        .map(|f| f.file_id().as_str())
        .collect();
    if stored_plan != new_plan {
        return Ok(format!(
            "the requested file plan differs (stored {stored_plan:?}, requested {new_plan:?})"
        ));
    }
    Ok("the request digests differ".to_string())
}

pub(super) fn read_job(
    conn: &Connection,
    column: &str,
    value: &str,
) -> Result<Option<StoredJob>, PersistenceError> {
    let sql = format!(
        "SELECT job_id, operation_kind, device_id, session_id, revision, request_digest, state, state_version, \
                desired_run_state, error_code, error_retryable, created_at, updated_at, dismissed_at \
         FROM transfer_jobs WHERE {column} = ?1"
    );
    let row: Option<Result<StoredJob, String>> = conn
        .query_row(&sql, [value], |row| Ok(read_job_row(row)))
        .optional()?;
    match row {
        None => Ok(None),
        Some(Ok(job)) => Ok(Some(job)),
        Some(Err(detail)) => Err(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_jobs"),
            detail,
        }),
    }
}

fn read_latest_job_by_identity(
    conn: &Connection,
    identity: &JobIdentity,
) -> Result<Option<StoredJob>, PersistenceError> {
    let row: Option<Result<StoredJob, String>> = conn
        .query_row(
            "SELECT job_id, operation_kind, device_id, session_id, revision, request_digest, state, state_version, \
                    desired_run_state, error_code, error_retryable, created_at, updated_at, dismissed_at \
             FROM transfer_jobs WHERE device_id = ?1 AND session_id = ?2 AND revision = ?3 \
             ORDER BY created_at DESC, job_id DESC LIMIT 1",
            rusqlite::params![
                identity.device_id().as_str(),
                identity.session_id().as_str(),
                identity.revision(),
            ],
            |row| Ok(read_job_row(row)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some(Ok(job)) => Ok(Some(job)),
        Some(Err(detail)) => Err(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_jobs"),
            detail,
        }),
    }
}

fn read_job_row(row: &rusqlite::Row<'_>) -> Result<StoredJob, String> {
    let get = |index: usize| -> Result<String, String> {
        row.get::<_, String>(index)
            .map_err(|e| format!("column {index}: {e}"))
    };
    let job_id = get(0)?;
    let operation_kind_str = get(1)?;
    let operation_kind = OperationKind::from_db_str(&operation_kind_str).ok_or_else(|| {
        format!("job {job_id} has unrecognized operation_kind {operation_kind_str:?}")
    })?;
    let identity = JobIdentity::new(DeviceId(get(2)?), SessionId(get(3)?), get(4)?)
        .map_err(|e| format!("job {job_id} has an unusable identity: {e}"))?;
    let request_digest = RequestDigest::from_hex(&get(5)?)
        .map_err(|e| format!("job {job_id} has an unusable request digest: {e}"))?;
    let state_str = get(6)?;
    let state = JobStateTag::from_db_str(&state_str)
        .ok_or_else(|| format!("job {job_id} has unrecognized state {state_str:?}"))?;
    let state_version: i64 = row.get(7).map_err(|e| format!("state_version: {e}"))?;
    let state_version = u64::try_from(state_version)
        .map_err(|_| format!("job {job_id} has negative state_version {state_version}"))?;
    let desired_run_state: String = row.get(8).map_err(|e| format!("desired_run_state: {e}"))?;
    let desired_run_state = desired_run_state_from_db(&desired_run_state).ok_or_else(|| {
        format!("job {job_id} has unrecognized desired_run_state {desired_run_state:?}")
    })?;
    let error_code: Option<String> = row.get(9).map_err(|e| format!("error_code: {e}"))?;
    let error_retryable: Option<i64> = row.get(10).map_err(|e| format!("error_retryable: {e}"))?;
    let error = match (error_code, error_retryable) {
        (Some(code), Some(retryable)) => Some((code, retryable != 0)),
        _ => None,
    };
    Ok(StoredJob {
        job_id,
        operation_kind,
        identity,
        request_digest,
        state,
        state_version,
        desired_run_state,
        error,
        created_at: get(11)?,
        updated_at: get(12)?,
        dismissed_at: row.get(13).map_err(|e| format!("dismissed_at: {e}"))?,
    })
}

fn read_download_session_job_state_row(
    row: &rusqlite::Row<'_>,
) -> Result<DownloadSessionJobState, String> {
    let job = read_job_row(row)?;
    let completion_job_id: Option<String> = row
        .get(14)
        .map_err(|error| format!("job {} completion job_id: {error}", job.job_id))?;
    let completion_operation_kind: Option<String> = row
        .get(15)
        .map_err(|error| format!("job {} completion operation_kind: {error}", job.job_id))?;
    let acknowledged_at: Option<String> = row
        .get(16)
        .map_err(|error| format!("job {} completion acknowledged_at: {error}", job.job_id))?;

    let completion = match completion_job_id {
        None => {
            if completion_operation_kind.is_some() || acknowledged_at.is_some() {
                return Err(format!(
                    "job {} has partial completion columns without an outbox identity",
                    job.job_id
                ));
            }
            CompletionDeliveryState::Missing
        }
        Some(completion_job_id) => {
            if completion_job_id != job.job_id {
                return Err(format!(
                    "job {} joined completion for {completion_job_id}",
                    job.job_id
                ));
            }
            let operation_kind = completion_operation_kind
                .ok_or_else(|| format!("job {} completion has no operation_kind", job.job_id))?;
            if OperationKind::from_db_str(&operation_kind) != Some(OperationKind::Download) {
                return Err(format!(
                    "download job {} has completion operation_kind {operation_kind:?}",
                    job.job_id
                ));
            }
            if acknowledged_at.is_some() {
                CompletionDeliveryState::Acknowledged
            } else {
                CompletionDeliveryState::Pending
            }
        }
    };

    Ok(DownloadSessionJobState { job, completion })
}

/// Builds the `Blocked` record for a `transfer_jobs` row whose own columns
/// could not be parsed.
fn blocked_row(conn: &Connection, job_id: &str) -> Result<RecoveryBlocked, PersistenceError> {
    let state: Option<String> = conn
        .query_row(
            "SELECT state FROM transfer_jobs WHERE job_id = ?1",
            [job_id],
            |row| row.get(0),
        )
        .optional()?;
    let reason = match state.as_deref() {
        Some(state) if JobStateTag::from_db_str(state).is_none() => {
            RecoveryBlockedReason::UnknownState
        }
        _ => RecoveryBlockedReason::CorruptSpec,
    };
    Ok(RecoveryBlocked {
        job_id: job_id.to_string(),
        identity: None,
        reason,
        detail: format!(
            "the transfer_jobs row for {job_id} could not be read (state {:?})",
            state.unwrap_or_else(|| "<missing>".into())
        ),
    })
}

/// Reassembles a durable spec, or explains why it cannot be.
///
/// The `Ok(Err(..))` shape is deliberate: an unreadable spec is a
/// *domain* outcome recovery must report, not an I/O failure. Only real
/// storage errors take the outer `Err`.
#[allow(clippy::type_complexity)]
fn load_spec(
    conn: &Connection,
    job: &StoredJob,
) -> Result<Result<JobSpec, RecoveryBlocked>, PersistenceError> {
    let blocked = |reason: RecoveryBlockedReason, detail: String| RecoveryBlocked {
        job_id: job.job_id.clone(),
        identity: Some(job.identity.clone()),
        reason,
        detail,
    };

    let spec_row: Option<(i64, i64, String, String, Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT spec_version, full_session, date_label, publication_revision, \
                    publication_payload, publication_signature, publication_public_key \
             FROM transfer_job_specs WHERE job_id = ?1",
            [&job.job_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;

    let Some((spec_version, full_session, date_label, pub_revision, payload, signature, key)) =
        spec_row
    else {
        return Ok(Err(blocked(
            RecoveryBlockedReason::MissingSpec,
            format!("no transfer_job_specs row for job {}", job.job_id),
        )));
    };

    if spec_version != i64::from(CURRENT_JOB_SPEC_VERSION) {
        return Ok(Err(blocked(
            RecoveryBlockedReason::UnknownSpecVersion,
            format!(
                "spec_version {spec_version} is not understood by this build (expected \
                 {CURRENT_JOB_SPEC_VERSION})"
            ),
        )));
    }
    let full_session = match full_session {
        0 => false,
        1 => true,
        other => {
            return Ok(Err(blocked(
                RecoveryBlockedReason::CorruptSpec,
                format!("full_session value {other} is outside the SQL boolean range"),
            )))
        }
    };

    let mut stmt = conn.prepare(
        "SELECT file_id, display_path, size_bytes, sha256, request_index \
         FROM transfer_job_files WHERE job_id = ?1 ORDER BY inventory_index",
    )?;
    let rows = stmt
        .query_map([&job.job_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if rows.is_empty() {
        return Ok(Err(blocked(
            RecoveryBlockedReason::MissingFiles,
            format!("job {} has a spec row but no file rows", job.job_id),
        )));
    }

    let mut session_files = Vec::with_capacity(rows.len());
    let mut requested: Vec<(i64, FileId)> = Vec::new();
    for (file_id, display_path, size_bytes, sha256, request_index) in rows {
        let size_bytes = match u64::try_from(size_bytes) {
            Ok(size_bytes) => size_bytes,
            Err(_) => {
                return Ok(Err(blocked(
                    RecoveryBlockedReason::CorruptSpec,
                    format!("file row {file_id:?} has negative size {size_bytes}"),
                )))
            }
        };
        let file = match JobFileSpec::new(FileId(file_id.clone()), display_path, size_bytes, sha256)
        {
            Ok(file) => file,
            Err(error) => {
                return Ok(Err(blocked(
                    RecoveryBlockedReason::CorruptSpec,
                    format!("file row {file_id:?} is unusable: {error}"),
                )))
            }
        };
        if let Some(index) = request_index {
            if index < 0 {
                return Ok(Err(blocked(
                    RecoveryBlockedReason::CorruptSpec,
                    format!("file row {file_id:?} has negative request index {index}"),
                )));
            }
            requested.push((index, FileId(file_id)));
        }
        session_files.push(file);
    }

    if requested.is_empty() {
        return Ok(Err(blocked(
            RecoveryBlockedReason::MissingFiles,
            format!("job {} has no requested files", job.job_id),
        )));
    }
    requested.sort_by_key(|(index, _)| *index);
    let requested_ids: Vec<FileId> = requested.into_iter().map(|(_, id)| id).collect();

    let publication = match PublicationMaterial::new(pub_revision, payload, signature, key) {
        Ok(publication) => publication,
        Err(error) => {
            return Ok(Err(blocked(
                RecoveryBlockedReason::CorruptSpec,
                format!("publication material is unusable: {error}"),
            )))
        }
    };

    let spec = match JobSpec::new(
        job.identity.clone(),
        publication,
        session_files,
        &requested_ids,
        full_session,
        date_label,
    ) {
        Ok(spec) => spec,
        Err(error) => {
            return Ok(Err(blocked(
                RecoveryBlockedReason::CorruptSpec,
                format!("the stored rows no longer form a valid spec: {error}"),
            )))
        }
    };

    if spec.request_digest() != job.request_digest {
        return Ok(Err(blocked(
            RecoveryBlockedReason::DigestMismatch,
            format!(
                "the reassembled spec digests to {} but the job row records {}",
                spec.request_digest(),
                job.request_digest
            ),
        )));
    }

    Ok(Ok(spec))
}

fn read_ledger(conn: &Connection, job_id: &str) -> Result<Vec<FileLedgerEntry>, PersistenceError> {
    let mut stmt = conn.prepare(
        "SELECT l.file_id, l.status, l.bytes_confirmed, l.verified_sha256, l.updated_at \
         FROM transfer_file_ledger l \
         JOIN transfer_job_files f ON f.job_id = l.job_id AND f.file_id = l.file_id \
         WHERE l.job_id = ?1 ORDER BY f.request_index",
    )?;
    let rows = stmt
        .query_map([job_id], |row| {
            let status: String = row.get(1)?;
            let bytes_confirmed: i64 = row.get(2)?;
            let bytes_confirmed = u64::try_from(bytes_confirmed).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    format!("negative bytes_confirmed {bytes_confirmed}").into(),
                )
            })?;
            Ok(FileLedgerEntry {
                file_id: FileId(row.get(0)?),
                status: FileLedgerStatus::from_db_str(&status).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        format!("unknown ledger status {status:?}").into(),
                    )
                })?,
                bytes_confirmed,
                verified_sha256: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::ffi::{c_char, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{TransferStore, DOWNLOAD_SESSION_JOB_STATES_SQL};

    unsafe extern "C" fn count_statement(context: *mut c_void, _sql: *const c_char) {
        // SQLite invokes the callback synchronously while `context` is alive.
        let counter = unsafe { &*context.cast::<AtomicUsize>() };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn download_session_job_snapshot_executes_one_statement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open");
        store
            .raw_execute(
                "INSERT INTO transfer_jobs (
                    job_id, natural_key, device_id, session_id, revision,
                    request_digest, state, created_at, updated_at
                 ) VALUES
                    ('job-a', 'natural-a', 'pi-a', 'session-a', 'rev-a',
                     '0000000000000000000000000000000000000000000000000000000000000000',
                     'queued', 't0', 't0'),
                    ('job-b', 'natural-b', 'pi-a', 'session-b', 'rev-b',
                     '1111111111111111111111111111111111111111111111111111111111111111',
                     'queued', 't0', 't0'),
                    ('job-c', 'natural-c', 'pi-a', 'session-c', 'rev-c',
                     '2222222222222222222222222222222222222222222222222222222222222222',
                     'queued', 't0', 't0')",
            )
            .expect("seed jobs");
        let statement_count = AtomicUsize::new(0);

        unsafe {
            rusqlite::ffi::sqlite3_trace(
                store.conn.handle(),
                Some(count_statement),
                (&statement_count as *const AtomicUsize).cast_mut().cast(),
            );
        }
        let result = store.list_download_session_job_states_for_sessions(
            &["pi-a".to_string()],
            &["session-a".to_string(), "session-b".to_string()],
        );
        unsafe {
            rusqlite::ffi::sqlite3_trace(store.conn.handle(), None, ptr::null_mut());
        }

        assert_eq!(result.expect("snapshot").len(), 2);
        assert_eq!(statement_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn download_session_job_snapshot_uses_the_partial_lookup_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open");
        let explain = format!("EXPLAIN QUERY PLAN {DOWNLOAD_SESSION_JOB_STATES_SQL}");
        let mut statement = store.conn.prepare(&explain).expect("prepare explain");
        let details = statement
            .query_map(
                rusqlite::params![r#"["pi-a"]"#, r#"["session-a"]"#],
                |row| row.get::<_, String>(3),
            )
            .expect("explain query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect query plan");

        assert!(
            details.iter().any(|detail| {
                detail.contains("transfer_jobs_download_device_session_idx")
                    && detail.contains("device_id=?")
                    && detail.contains("session_id=?")
            }),
            "scoped lookup did not search the partial index: {details:?}"
        );
    }
}
