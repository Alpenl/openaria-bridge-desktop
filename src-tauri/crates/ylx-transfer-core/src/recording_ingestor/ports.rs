//! Narrow integration ports used by the recording-ingest effect executor.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::ingest::{
    ArtifactSource, CandidateId, ImportJobId, ImportPolicy, ImportSnapshot, ImportSpec,
    LocalSourceReceipt, MediaGenerationId, MediaLocator, ScanCandidate, ScanRequest, ScanSnapshot,
    SourceRecording,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct IngestPortError {
    code: &'static str,
    message: String,
}

impl IngestPortError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let message = message.into();
        let message = message
            .chars()
            .filter(|character| !character.is_control())
            .take(1_024)
            .collect();
        Self { code, message }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredImport {
    pub spec: ImportSpec,
    pub snapshot: ImportSnapshot,
    pub locator: MediaLocator,
    pub locator_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateStoredImportOutcome {
    Created(StoredImport),
    Existing(StoredImport),
    Conflict {
        existing_job_id: ImportJobId,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareAndSwapOutcome {
    Applied(ImportSnapshot),
    Conflict(ImportSnapshot),
    Missing,
}

/// Durable import authority. `create_import` must insert immutable spec,
/// ordered files, initial snapshot/checkpoints and initial locator in one
/// transaction before returning `Created`.
///
/// The production `MediaStore` adapter maps these calls to
/// `create_import_job`, `import_job`, `compare_and_swap_import_snapshot`,
/// `complete_import_job`, and `import_projection`. Its CAS must pass the
/// snapshot's `active_locator` as `ImportLocatorUpdate` in the same SQLite
/// transaction; a separate locator write would permit a stale reader to win.
pub trait ImportRepository: Send + Sync {
    fn create_import(
        &self,
        spec: &ImportSpec,
        initial_snapshot: &ImportSnapshot,
    ) -> Result<CreateStoredImportOutcome, IngestPortError>;

    fn load_import(&self, job_id: &ImportJobId) -> Result<Option<StoredImport>, IngestPortError>;

    fn list_import_snapshots(&self) -> Result<Vec<ImportSnapshot>, IngestPortError>;

    /// Expected-version CAS of state, desired state and every file
    /// checkpoint. A terminal failure/cancellation outbox, when required by
    /// the repository contract, is written by this same transaction.
    fn compare_and_swap(
        &self,
        job_id: &ImportJobId,
        expected_version: u64,
        next: &ImportSnapshot,
    ) -> Result<CompareAndSwapOutcome, IngestPortError>;

    /// Atomic database half of local publication: write the `local_verified`
    /// snapshot, source/import receipts and completion outbox together.
    fn commit_local_verified(
        &self,
        job_id: &ImportJobId,
        expected_version: u64,
        next: &ImportSnapshot,
        receipt: &LocalSourceReceipt,
    ) -> Result<CompareAndSwapOutcome, IngestPortError>;
}

/// Scanner/admission boundary. The concrete constrained scanner retains the
/// untrusted candidate details; only `admit` may return the field-private
/// `SourceRecording` accepted by an import spec.
pub trait CandidateCatalog: Send + Sync {
    fn scan(&self, request: ScanRequest) -> Result<ScanSnapshot, IngestPortError>;

    fn candidate(
        &self,
        candidate_id: &CandidateId,
    ) -> Result<Option<ScanCandidate>, IngestPortError>;

    fn admit(
        &self,
        candidate_id: &CandidateId,
        policy: &ImportPolicy,
    ) -> Result<SourceRecording, IngestPortError>;
}

pub struct ResolvedArtifactSource {
    pub source: Arc<dyn ArtifactSource>,
    pub observed_generation: Option<MediaGenerationId>,
}

impl fmt::Debug for ResolvedArtifactSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedArtifactSource")
            .field("observed_generation", &self.observed_generation)
            .finish_non_exhaustive()
    }
}

/// Resolves a durable locator to a read-only source. The returned object's
/// lifetime owns any platform watcher/root handle needed for opens; dropping
/// it must release those resources.
pub trait ArtifactSourceResolver: Send + Sync {
    fn resolve(&self, locator: &MediaLocator) -> Result<ResolvedArtifactSource, IngestPortError>;
}

pub trait LocalSpace: Send + Sync {
    fn available_bytes(&self, library_root: &Path) -> Result<u64, IngestPortError>;
}

/// The scheduler may use a blocking pool, Tokio task, or a deterministic
/// test queue. Duplicate enqueue is legal; job CAS and writer gates make it
/// harmless.
pub trait ImportScheduler: Send + Sync {
    fn enqueue(&self, job_id: &ImportJobId) -> Result<(), IngestPortError>;

    fn enqueue_retry(&self, job_id: &ImportJobId) -> Result<(), IngestPortError>;
}

pub trait IngestClock: Send + Sync {
    fn now_rfc3339(&self) -> String;
}

/// Exclusive durable lease held across seal and directory publication. The
/// adapter should back this with `MediaStore`'s `LibraryRevisionLease` and
/// verify its fencing token immediately before rename. Acquire with
/// `LibraryRevisionKind::Source` and release in the guard's `Drop`; expiry or
/// ownership loss must make `assert_current` fail closed.
pub trait SourcePublishLease: Send {
    fn assert_current(&mut self) -> Result<(), IngestPortError>;
}

pub trait SourcePublishLeases: Send + Sync {
    fn acquire_exclusive(
        &self,
        source_revision: &str,
        owner_job_id: &ImportJobId,
    ) -> Result<Box<dyn SourcePublishLease>, IngestPortError>;
}

pub trait ImportNotificationSink: Send + Sync {
    fn local_verified(
        &self,
        job_id: &ImportJobId,
        receipt: &LocalSourceReceipt,
    ) -> Result<(), IngestPortError>;
}
