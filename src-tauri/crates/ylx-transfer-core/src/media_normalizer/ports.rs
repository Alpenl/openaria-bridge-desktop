//! Narrow integration ports for the media-normalization effect executor.

use crate::normalization::{
    DerivationJobId, DerivationSnapshot, DerivationSpec, DerivedCompletion, DerivedManifest,
    EncodeSegmentPairRequest, EncodedSegmentPair, MediaOperationControl, MediaProcessOutcome,
    ProfileRevision, QualityEvidence, SourceContentRevision,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct MediaNormalizerPortError {
    code: &'static str,
    message: String,
}

impl MediaNormalizerPortError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let message = message
            .into()
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
pub struct StoredDerivation {
    pub snapshot: DerivationSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateDerivationOutcome {
    Created(StoredDerivation),
    Existing(StoredDerivation),
    Conflict {
        existing_job_id: DerivationJobId,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSwapOutcome {
    Applied(StoredDerivation),
    AlreadyApplied(StoredDerivation),
    Stale(StoredDerivation),
    Missing,
}

/// Filesystem and manifest evidence written atomically with the terminal
/// snapshot and completion outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedCommitEvidence {
    pub manifest_sha256: String,
    pub output_inventory_sha256: String,
    pub local_relative_path: String,
    pub local_commit_receipt: String,
}

/// Durable derivation authority. Implementations are expected to map this
/// directly onto `media_store`'s derivation job, pair ledger, receipt and
/// outbox transactions.
pub trait DerivationRepository: Send + Sync {
    fn create_derivation(
        &self,
        spec: &DerivationSpec,
        initial: &DerivationSnapshot,
        now: &str,
    ) -> Result<CreateDerivationOutcome, MediaNormalizerPortError>;

    fn load_derivation(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<Option<StoredDerivation>, MediaNormalizerPortError>;

    fn list_derivations(&self) -> Result<Vec<StoredDerivation>, MediaNormalizerPortError>;

    /// Expected-version CAS of one aggregate effect. When `next` adds a pair
    /// checkpoint, its left/right hashes and checkpoint JSON must be written
    /// in the same transaction as the job snapshot.
    fn compare_and_swap(
        &self,
        job_id: &DerivationJobId,
        expected_version: u64,
        next: &DerivationSnapshot,
        now: &str,
    ) -> Result<SnapshotSwapOutcome, MediaNormalizerPortError>;

    /// Atomic database half of final publication: terminal snapshot,
    /// `DerivedCompletion`, immutable derived receipt and completion outbox.
    // All evidence stays explicit because this is the repository's atomic commit boundary.
    #[allow(clippy::too_many_arguments)]
    fn commit_derived_verified(
        &self,
        job_id: &DerivationJobId,
        expected_version: u64,
        next: &DerivationSnapshot,
        completion: &DerivedCompletion,
        manifest: &DerivedManifest,
        evidence: &DerivedCommitEvidence,
        now: &str,
    ) -> Result<SnapshotSwapOutcome, MediaNormalizerPortError>;

    /// Retirement is legal only after the repository's completion outbox has
    /// been acknowledged. Immutable derived receipts remain after retirement.
    fn retire_derivation(&self, job_id: &DerivationJobId) -> Result<(), MediaNormalizerPortError>;
}

/// A shared lease on the immutable source tree. Production implementations
/// should auto-renew while held and validate the durable fencing token in
/// `assert_current`; dropping it releases the lease.
pub trait SourceReadLease: Send {
    fn assert_current(&mut self) -> Result<(), MediaNormalizerPortError>;
}

pub trait SourceReadLeases: Send + Sync {
    fn acquire_shared(
        &self,
        source_revision: &SourceContentRevision,
        owner_job_id: &DerivationJobId,
    ) -> Result<Box<dyn SourceReadLease>, MediaNormalizerPortError>;
}

/// Per-eye VMAF/SSIM/domain evidence. Quality measurement is a real process
/// seam because it needs source-aware filters and may itself spawn FFmpeg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairQualityEvidence {
    left: QualityEvidence,
    right: QualityEvidence,
}

impl PairQualityEvidence {
    pub fn new(
        left: QualityEvidence,
        right: QualityEvidence,
    ) -> Result<Self, MediaNormalizerPortError> {
        if left.eye() != crate::normalization::Eye::Left
            || right.eye() != crate::normalization::Eye::Right
        {
            return Err(MediaNormalizerPortError::new(
                "quality_eye_mismatch",
                "quality analyzer must return one left and one right eye",
            ));
        }
        Ok(Self { left, right })
    }

    #[must_use]
    pub fn left(&self) -> &QualityEvidence {
        &self.left
    }

    #[must_use]
    pub fn right(&self) -> &QualityEvidence {
        &self.right
    }
}

pub trait SegmentQualityAnalyzer: Send + Sync {
    fn analyze_segment_pair(
        &self,
        request: &EncodeSegmentPairRequest,
        encoded: &EncodedSegmentPair,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<PairQualityEvidence>;
}

pub trait MediaNormalizerScheduler: Send + Sync {
    fn enqueue(&self, job_id: &DerivationJobId) -> Result<(), MediaNormalizerPortError>;
}

pub trait MediaNormalizerClock: Send + Sync {
    fn now_rfc3339(&self) -> String;
}

/// Best-effort wakeup only. Durable consumers replay the repository outbox,
/// so a notification failure never rolls back committed media or state.
pub trait CompletionNotificationSink: Send + Sync {
    fn derived_verified(
        &self,
        job_id: &DerivationJobId,
        completion: &DerivedCompletion,
    ) -> Result<(), MediaNormalizerPortError>;
}

#[allow(dead_code)]
fn _identity_contract<'source, 'profile>(
    source: &'source SourceContentRevision,
    profile: &'profile ProfileRevision,
) -> (&'source str, &'profile str) {
    (source.as_str(), profile.as_str())
}
