use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ingest::MediaGeneration;
use crate::ingest::{ImportSnapshot, ImportSpec, MediaLocator};
use crate::media_pipeline::{PipelineActionRequired, SessionPipeline};
use crate::normalization::{DerivationSnapshot, DerivationSpec};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMediaGeneration {
    pub generation: MediaGeneration,
    pub is_present: bool,
    pub first_observed_at: String,
    pub last_observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportLocatorSnapshot {
    pub locator: MediaLocator,
    pub version: u64,
    pub installed_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredImportJob {
    pub spec: ImportSpec,
    pub snapshot: ImportSnapshot,
    pub locator: ImportLocatorSnapshot,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportLocatorUpdate<'a> {
    pub expected_version: u64,
    pub locator: &'a MediaLocator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompareAndSwapOutcome<T> {
    Applied(T),
    AlreadyApplied(T),
}

impl<T> CompareAndSwapOutcome<T> {
    #[must_use]
    pub fn value(&self) -> &T {
        match self {
            Self::Applied(value) | Self::AlreadyApplied(value) => value,
        }
    }

    #[must_use]
    pub fn was_applied(&self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CreateImportJobError {
    #[error(transparent)]
    Conflict(#[from] CreateJobConflict),
    #[error(transparent)]
    Store(#[from] super::error::MediaStoreError),
}

impl From<rusqlite::Error> for CreateImportJobError {
    fn from(error: rusqlite::Error) -> Self {
        super::error::MediaStoreError::from(error).into()
    }
}

impl From<serde_json::Error> for CreateImportJobError {
    fn from(error: serde_json::Error) -> Self {
        super::error::MediaStoreError::from(error).into()
    }
}

/// Extra immutable projection keys required when a `LocalVerified` import
/// snapshot is committed. The typed `LocalSourceReceipt` itself comes from
/// the snapshot; these values bind it to the long-lived library fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportCommitProjection<'a> {
    pub receipt_id: &'a str,
    pub source_identity: &'a str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompleteImportOutcome {
    pub job: StoredImportJob,
    pub completion: CompleteOutcome<ImportSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDerivationJob {
    pub spec: DerivationSpec,
    pub snapshot: DerivationSnapshot,
    pub natural_key: String,
    pub request_digest: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateDerivationJobError {
    #[error(transparent)]
    Conflict(#[from] CreateJobConflict),
    #[error(transparent)]
    Store(#[from] super::error::MediaStoreError),
}

impl From<rusqlite::Error> for CreateDerivationJobError {
    fn from(error: rusqlite::Error) -> Self {
        super::error::MediaStoreError::from(error).into()
    }
}

impl From<serde_json::Error> for CreateDerivationJobError {
    fn from(error: serde_json::Error) -> Self {
        super::error::MediaStoreError::from(error).into()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompleteDerivationOutcome {
    pub job: StoredDerivationJob,
    pub completion: CompleteOutcome<DerivationSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryRevisionKind {
    Source,
    Derived,
}

impl LibraryRevisionKind {
    pub(crate) fn as_db_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Derived => "derived",
        }
    }

    pub(crate) fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "source" => Some(Self::Source),
            "derived" => Some(Self::Derived),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryLeaseMode {
    Shared,
    Exclusive,
}

impl LibraryLeaseMode {
    pub(crate) fn as_db_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Exclusive => "exclusive",
        }
    }

    pub(crate) fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "shared" => Some(Self::Shared),
            "exclusive" => Some(Self::Exclusive),
            _ => None,
        }
    }
}

/// Durable ownership of a sealed source or derived revision.
///
/// `fencing_token` is monotonic per revision. A filesystem mutation must
/// verify it immediately before publish/delete so an expired owner cannot
/// commit after a newer owner acquired the revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryRevisionLease {
    pub lease_id: String,
    pub revision_kind: LibraryRevisionKind,
    pub revision_id: String,
    pub owner_id: String,
    pub mode: LibraryLeaseMode,
    pub fencing_token: u64,
    pub acquired_at: String,
    pub updated_at: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireLibraryLease<'a> {
    pub lease_id: &'a str,
    pub revision_kind: LibraryRevisionKind,
    pub revision_id: &'a str,
    pub owner_id: &'a str,
    pub mode: LibraryLeaseMode,
    pub now: &'a str,
    pub now_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireLeaseOutcome {
    Acquired(LibraryRevisionLease),
    Existing(LibraryRevisionLease),
    Conflict(Vec<LibraryRevisionLease>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseLeaseOutcome {
    Released,
    AlreadyReleased,
    OwnershipLost,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceReceipt {
    pub source_revision: String,
    pub source_identity: String,
    pub sealed_inventory_digest: String,
    pub provenance: Value,
    pub local_path: String,
    pub commit_receipt: Value,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivedReceipt {
    pub derivation_job_id: String,
    pub derived_revision: String,
    pub source_revision: String,
    pub source_manifest_digest: String,
    pub profile_revision: String,
    pub local_path: String,
    pub commit_receipt: Value,
    pub committed_at: String,
}

/// Long-lived duplicate-import fence. This survives retirement of the
/// corresponding import job and is checked by source identity + revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LibraryImportReceipt {
    pub receipt_id: String,
    pub import_job_id: String,
    pub source_revision: String,
    pub source_identity: String,
    pub sealed_inventory_digest: String,
    pub provenance: Value,
    pub local_path: String,
    pub commit_receipt: Value,
    pub committed_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReceiptWriteOutcome<T> {
    Recorded(T),
    Existing(T),
}

impl<T> ReceiptWriteOutcome<T> {
    #[must_use]
    pub fn receipt(&self) -> &T {
        match self {
            Self::Recorded(receipt) | Self::Existing(receipt) => receipt,
        }
    }

    #[must_use]
    pub fn was_recorded(&self) -> bool {
        matches!(self, Self::Recorded(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Import,
    Derivation,
    Upload,
}

impl PipelineStage {
    pub(crate) fn as_db_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Derivation => "derivation",
            Self::Upload => "upload",
        }
    }

    pub(crate) fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "import" => Some(Self::Import),
            "derivation" => Some(Self::Derivation),
            "upload" => Some(Self::Upload),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineDependency {
    pub stage: PipelineStage,
    pub job_id: String,
    pub required_milestone: String,
    pub detail: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineSnapshot {
    pub pipeline_id: String,
    pub source_key: String,
    pub pipeline: SessionPipeline,
    pub action_required: Option<PipelineActionRequired>,
    pub pipeline_version: u64,
    pub dependencies: Vec<PipelineDependency>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionedCollection<T> {
    pub revision: u64,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreatePipelineOutcome {
    Created(PipelineSnapshot),
    Existing(PipelineSnapshot),
}

/// Result of admitting one import and its owning session-pipeline intent in a
/// single SQLite transaction. The booleans distinguish idempotent recovery
/// from newly inserted resources without weakening either aggregate's typed
/// snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateImportPipelineOutcome {
    pub import: StoredImportJob,
    pub pipeline: PipelineSnapshot,
    pub import_created: bool,
    pub pipeline_created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcknowledgeOutcome<T> {
    Acknowledged(T),
    AlreadyAcknowledged(T),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionEnvelope<T> {
    pub sequence: u64,
    pub job_id: String,
    pub outcome: T,
    pub state_version: u64,
    pub recorded_at: String,
    pub acknowledged_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompleteOutcome<T> {
    Recorded(CompletionEnvelope<T>),
    AlreadyRecorded(CompletionEnvelope<T>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateJobOutcome<T> {
    Created(T),
    Existing(T),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreateJobConflict {
    #[error(
        "natural key {natural_key:?} already belongs to job {existing_job_id:?} with digest {existing_digest}; requested digest is {requested_digest}"
    )]
    RequestDigestMismatch {
        natural_key: String,
        existing_job_id: String,
        existing_digest: String,
        requested_digest: String,
    },
    #[error("job id {job_id:?} is already used by natural key {existing_natural_key:?}")]
    JobIdCollision {
        job_id: String,
        existing_natural_key: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryBlockedReason {
    MissingSpec,
    MissingFiles,
    MissingLocator,
    UnknownSpecVersion,
    CorruptSpec,
    DigestMismatch,
    UnknownState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBlocked {
    pub job_id: String,
    pub reason: RecoveryBlockedReason,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Recoverable<T> {
    Ready(T),
    Blocked(RecoveryBlocked),
}

impl<T> Recoverable<T> {
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
}
