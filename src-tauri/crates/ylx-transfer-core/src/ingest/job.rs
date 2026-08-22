//! Durable import-job aggregate and deterministic command reducer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::identity::{
    CandidateRevision, ImportJobId, InventoryDigest, MediaGenerationId, SourceArtifactId,
    SourceContentRevision, SourceRevisionClaim,
};
use super::path::SafeRelativePath;
use super::source::{
    InventoryHashesVerdict, LocalSourceReceipt, MediaLocator, SourceArtifactClaim,
    SourceArtifactRole, SourceModelError, SourceProvenance, SourceRecording,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsignedImportPolicy {
    Reject,
    RequireAdmissionReceipt,
    AllowExplicitSelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportPolicy {
    unsigned: UnsignedImportPolicy,
    local_space_budget_bytes: u64,
    safety_margin_bytes: u64,
}

impl ImportPolicy {
    #[must_use]
    pub fn new(
        unsigned: UnsignedImportPolicy,
        local_space_budget_bytes: u64,
        safety_margin_bytes: u64,
    ) -> Self {
        Self {
            unsigned,
            local_space_budget_bytes,
            safety_margin_bytes,
        }
    }

    #[must_use]
    pub fn unsigned(&self) -> UnsignedImportPolicy {
        self.unsigned
    }

    #[must_use]
    pub fn local_space_budget_bytes(&self) -> u64 {
        self.local_space_budget_bytes
    }

    #[must_use]
    pub fn safety_margin_bytes(&self) -> u64 {
        self.safety_margin_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "identity", rename_all = "snake_case")]
pub enum ImportNaturalKey {
    DeviceSigned {
        producer_key_fingerprint: String,
        session_id: String,
        revision: SourceContentRevision,
    },
    UnsignedContent(SourceContentRevision),
    Provisional(CandidateRevision),
}

impl ImportNaturalKey {
    /// Return the content-revision component of this key.
    ///
    /// This accessor is retained for callers that need the revision fence
    /// itself. It is deliberately not suitable as a durable natural-key
    /// column for signed publications because two producers may publish the
    /// same revision string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::DeviceSigned { revision, .. } | Self::UnsignedContent(revision) => {
                revision.as_str()
            }
            Self::Provisional(revision) => revision.as_str(),
        }
    }

    /// Return a collision-free, durable encoding of the complete natural key.
    ///
    /// Components are length-prefixed rather than separator-joined. This
    /// keeps producer/session values opaque while preventing delimiter
    /// ambiguity in SQL uniqueness and idempotency keys.
    #[must_use]
    pub fn canonical_key(&self) -> String {
        let mut key = String::from("import:");
        match self {
            Self::DeviceSigned {
                producer_key_fingerprint,
                session_id,
                revision,
            } => {
                key.push_str("device_signed:");
                append_key_component(&mut key, producer_key_fingerprint);
                append_key_component(&mut key, session_id);
                append_key_component(&mut key, revision.as_str());
            }
            Self::UnsignedContent(revision) => {
                key.push_str("unsigned_content:");
                append_key_component(&mut key, revision.as_str());
            }
            Self::Provisional(revision) => {
                key.push_str("provisional:");
                append_key_component(&mut key, revision.as_str());
            }
        }
        key
    }
}

fn append_key_component(key: &mut String, component: &str) {
    use std::fmt::Write as _;

    // `str::len` is byte length, matching the opaque identity limits and
    // making the encoding unambiguous for UTF-8 values.
    write!(key, "{}:{}", component.len(), component).expect("writing to String cannot fail");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFileSpec {
    file_id: SourceArtifactId,
    relative_path: SafeRelativePath,
    role: SourceArtifactRole,
    expected_size: u64,
    expected_source_sha256: Option<String>,
}

impl From<&SourceArtifactClaim> for ImportFileSpec {
    fn from(claim: &SourceArtifactClaim) -> Self {
        Self {
            file_id: claim.id().clone(),
            relative_path: claim.relative_path().clone(),
            role: claim.role(),
            expected_size: claim.size_bytes(),
            expected_source_sha256: claim.source_sha256().map(ToOwned::to_owned),
        }
    }
}

impl ImportFileSpec {
    #[must_use]
    pub fn file_id(&self) -> &SourceArtifactId {
        &self.file_id
    }

    #[must_use]
    pub fn relative_path(&self) -> &SafeRelativePath {
        &self.relative_path
    }

    #[must_use]
    pub fn role(&self) -> SourceArtifactRole {
        self.role
    }

    #[must_use]
    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    #[must_use]
    pub fn expected_source_sha256(&self) -> Option<&str> {
        self.expected_source_sha256.as_deref()
    }
}

/// Immutable request. File order is the detector/manifest order and therefore
/// also the copy/checkpoint order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSpec {
    job_id: ImportJobId,
    natural_key: ImportNaturalKey,
    request_digest: String,
    source: SourceRecording,
    locator: MediaLocator,
    files: Vec<ImportFileSpec>,
    total_bytes: u64,
    policy: ImportPolicy,
}

impl ImportSpec {
    pub fn new(
        job_id: ImportJobId,
        source: SourceRecording,
        policy: ImportPolicy,
    ) -> Result<Self, ImportSpecError> {
        enforce_unsigned_policy(&source, &policy)?;
        let files: Vec<ImportFileSpec> = source.inventory().iter().map(Into::into).collect();
        if files.is_empty() {
            return Err(ImportSpecError::EmptyInventory);
        }
        let total_bytes = files.iter().try_fold(0u64, |total, file| {
            total
                .checked_add(file.expected_size)
                .ok_or(ImportSpecError::TotalBytesOverflow)
        })?;
        let required = total_bytes
            .checked_add(policy.safety_margin_bytes)
            .ok_or(ImportSpecError::TotalBytesOverflow)?;
        if policy.local_space_budget_bytes < required {
            return Err(ImportSpecError::InsufficientLocalSpace {
                required,
                available: policy.local_space_budget_bytes,
            });
        }
        let natural_key = match (source.provenance(), source.revision_claim()) {
            (SourceProvenance::DeviceSigned(signed), SourceRevisionClaim::Published(revision)) => {
                ImportNaturalKey::DeviceSigned {
                    producer_key_fingerprint: signed.publication_key_fingerprint().to_string(),
                    session_id: source.session_id().to_string(),
                    revision: revision.clone(),
                }
            }
            (
                SourceProvenance::LocallyValidatedUnsigned(_),
                SourceRevisionClaim::Published(revision),
            ) => ImportNaturalKey::UnsignedContent(revision.clone()),
            (
                SourceProvenance::LocallyValidatedUnsigned(_),
                SourceRevisionClaim::Provisional(revision),
            ) => ImportNaturalKey::Provisional(revision.clone()),
            _ => return Err(ImportSpecError::ProvenanceRevisionMismatch),
        };
        let locator = source.locator().clone();
        // The locator is an acquisition detail, not request identity. A
        // signed session may move between a mounted card and a LAN source;
        // both must resolve to the same durable job. Candidate id, media
        // generation, trust receipts and local-space admission budgets are
        // likewise observation metadata. Keep immutable transfer evidence
        // (natural key, schema/media plan and ordered file claims) in the
        // request digest so a changed file plan still produces a conflict on
        // the same natural key.
        let request_payload = serde_json::to_vec(&(
            &natural_key,
            source.schema(),
            source.media_plan(),
            &files,
            total_bytes,
        ))
        .map_err(|error| ImportSpecError::Serialization(error.to_string()))?;
        let request_digest = format!("sha256:{:x}", Sha256::digest(request_payload));
        Ok(Self {
            job_id,
            natural_key,
            request_digest,
            source,
            locator,
            files,
            total_bytes,
            policy,
        })
    }

    #[must_use]
    pub fn job_id(&self) -> &ImportJobId {
        &self.job_id
    }

    #[must_use]
    pub fn natural_key(&self) -> &ImportNaturalKey {
        &self.natural_key
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub fn source(&self) -> &SourceRecording {
        &self.source
    }

    #[must_use]
    pub fn locator(&self) -> &MediaLocator {
        &self.locator
    }

    #[must_use]
    pub fn files(&self) -> &[ImportFileSpec] {
        &self.files
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn policy(&self) -> &ImportPolicy {
        &self.policy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportDesiredState {
    Running,
    Paused,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportResumePoint {
    Preflight,
    Copy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ImportJobState {
    Queued,
    WaitingForMedia { resume_from: ImportResumePoint },
    Preflighting,
    Copying,
    Verifying,
    Committing,
    LocalVerified,
    Pausing { resume_from: ImportResumePoint },
    Paused { resume_from: ImportResumePoint },
    Cancelling,
    Cancelled,
    RetryWait { resume_from: ImportResumePoint },
    Failed,
}

impl ImportJobState {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::LocalVerified | Self::Cancelled | Self::Failed)
    }

    #[must_use]
    pub fn needs_media(&self) -> bool {
        matches!(
            self,
            Self::WaitingForMedia { .. } | Self::Preflighting | Self::Copying
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFileCheckpoint {
    file_id: SourceArtifactId,
    durable_offset: u64,
    expected_size: u64,
    source_sha256: Option<String>,
    target_sha256: Option<String>,
    verified: bool,
}

impl ImportFileCheckpoint {
    fn from_spec(spec: &ImportFileSpec) -> Self {
        Self {
            file_id: spec.file_id.clone(),
            durable_offset: 0,
            expected_size: spec.expected_size,
            source_sha256: None,
            target_sha256: None,
            verified: false,
        }
    }

    #[must_use]
    pub fn file_id(&self) -> &SourceArtifactId {
        &self.file_id
    }

    #[must_use]
    pub fn durable_offset(&self) -> u64 {
        self.durable_offset
    }

    #[must_use]
    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    #[must_use]
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }

    #[must_use]
    pub fn target_sha256(&self) -> Option<&str> {
        self.target_sha256.as_deref()
    }

    #[must_use]
    pub fn verified(&self) -> bool {
        self.verified
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFailureCode {
    SourceUnavailable,
    MediaChanged,
    UnsafePath,
    PermissionDenied,
    InsufficientLocalSpace,
    IntegrityMismatch,
    SourceRevisionMismatch,
    CommitFailed,
    ResourceStuck,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFailure {
    code: ImportFailureCode,
    message: String,
    retryable: bool,
}

impl ImportFailure {
    pub fn new(
        code: ImportFailureCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<Self, ImportJobError> {
        let message = message.into();
        if message.is_empty() || message.len() > 1_024 || message.chars().any(char::is_control) {
            return Err(ImportJobError::InvalidFailureMessage);
        }
        Ok(Self {
            code,
            message,
            retryable,
        })
    }

    #[must_use]
    pub fn code(&self) -> ImportFailureCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn retryable(&self) -> bool {
        self.retryable
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSnapshot {
    job_id: ImportJobId,
    request_digest: String,
    natural_key: ImportNaturalKey,
    state: ImportJobState,
    desired_state: ImportDesiredState,
    version: u64,
    attempt: u32,
    checkpoints: Vec<ImportFileCheckpoint>,
    active_locator: Option<MediaLocator>,
    verified_source: Option<SourceRecording>,
    local_receipt: Option<LocalSourceReceipt>,
    failure: Option<ImportFailure>,
}

impl ImportSnapshot {
    #[must_use]
    pub fn job_id(&self) -> &ImportJobId {
        &self.job_id
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub fn natural_key(&self) -> &ImportNaturalKey {
        &self.natural_key
    }

    #[must_use]
    pub fn state(&self) -> &ImportJobState {
        &self.state
    }

    #[must_use]
    pub fn desired_state(&self) -> ImportDesiredState {
        self.desired_state
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    #[must_use]
    pub fn checkpoints(&self) -> &[ImportFileCheckpoint] {
        &self.checkpoints
    }

    #[must_use]
    pub fn active_media_generation(&self) -> Option<&MediaGenerationId> {
        self.active_locator
            .as_ref()
            .and_then(MediaLocator::media_generation_id)
    }

    #[must_use]
    pub fn active_locator(&self) -> Option<&MediaLocator> {
        self.active_locator.as_ref()
    }

    #[must_use]
    pub fn verified_source(&self) -> Option<&SourceRecording> {
        self.verified_source.as_ref()
    }

    #[must_use]
    pub fn content_revision(&self) -> Option<&SourceContentRevision> {
        self.verified_source
            .as_ref()
            .and_then(SourceRecording::content_revision)
    }

    #[must_use]
    pub fn local_receipt(&self) -> Option<&LocalSourceReceipt> {
        self.local_receipt.as_ref()
    }

    #[must_use]
    pub fn failure(&self) -> Option<&ImportFailure> {
        self.failure.as_ref()
    }

    #[must_use]
    pub fn durable_bytes(&self) -> u64 {
        self.checkpoints.iter().fold(0u64, |total, checkpoint| {
            total.saturating_add(checkpoint.durable_offset.min(checkpoint.expected_size))
        })
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportCommand {
    Start,
    ResetProgressForSource {
        revision_claim: SourceRevisionClaim,
    },
    SourceAvailable {
        locator: MediaLocator,
        revision_claim: SourceRevisionClaim,
    },
    SourceUnavailable,
    PreflightPassed,
    CopyCheckpoint {
        file_id: SourceArtifactId,
        durable_offset: u64,
    },
    CopyFinished,
    FileVerified {
        file_id: SourceArtifactId,
        source_sha256: String,
        target_sha256: String,
    },
    VerificationPassed {
        inventory_digest: InventoryDigest,
    },
    CommitSucceeded {
        receipt: LocalSourceReceipt,
    },
    RetryableFailure {
        failure: ImportFailure,
    },
    PermanentFailure {
        failure: ImportFailure,
    },
    RequestPause,
    PauseCompleted,
    Resume,
    RequestCancel,
    CancellationCompleted,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportControlCommand {
    Pause,
    Resume,
    Cancel,
    Retry,
}

impl From<ImportControlCommand> for ImportCommand {
    fn from(command: ImportControlCommand) -> Self {
        match command {
            ImportControlCommand::Pause => Self::RequestPause,
            ImportControlCommand::Resume => Self::Resume,
            ImportControlCommand::Cancel => Self::RequestCancel,
            ImportControlCommand::Retry => Self::Retry,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Effects deliberately carry the complete immutable source into the commit boundary.
#[allow(clippy::large_enum_variant)]
pub enum ImportEffect {
    PersistSnapshot,
    Schedule,
    StartPreflight {
        locator: MediaLocator,
    },
    StartCopy {
        locator: MediaLocator,
        resume_offsets: Vec<(SourceArtifactId, u64)>,
    },
    StartVerification,
    StartCommit {
        source: SourceRecording,
    },
    CancelIo,
    ScheduleRetry,
    PublishLocalVerified {
        receipt: LocalSourceReceipt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportRejectReason {
    Terminal,
    IllegalInState,
    StaleOrRegressedCheckpoint,
    UnknownFile,
    CopyIncomplete,
    InvalidDigest,
    IntegrityMismatch,
    ReceiptMismatch,
    FailureRetryabilityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportCommandOutcome {
    Applied,
    NoChange,
    Rejected(ImportRejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDecision {
    outcome: ImportCommandOutcome,
    effects: Vec<ImportEffect>,
    snapshot: ImportSnapshot,
}

impl ImportDecision {
    #[must_use]
    pub fn outcome(&self) -> &ImportCommandOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn effects(&self) -> &[ImportEffect] {
        &self.effects
    }

    #[must_use]
    pub fn snapshot(&self) -> &ImportSnapshot {
        &self.snapshot
    }
}

#[derive(Debug, Clone)]
pub struct ImportJob {
    spec: ImportSpec,
    snapshot: ImportSnapshot,
}

impl ImportJob {
    #[must_use]
    pub fn new(spec: ImportSpec) -> Self {
        let checkpoints = spec
            .files
            .iter()
            .map(ImportFileCheckpoint::from_spec)
            .collect();
        let snapshot = ImportSnapshot {
            job_id: spec.job_id.clone(),
            request_digest: spec.request_digest.clone(),
            natural_key: spec.natural_key.clone(),
            state: ImportJobState::Queued,
            desired_state: ImportDesiredState::Running,
            version: 0,
            attempt: 0,
            checkpoints,
            active_locator: Some(spec.locator.clone()),
            verified_source: None,
            local_receipt: None,
            failure: None,
        };
        Self { spec, snapshot }
    }

    pub fn from_snapshot(
        spec: ImportSpec,
        snapshot: ImportSnapshot,
    ) -> Result<Self, ImportJobError> {
        if snapshot.job_id != spec.job_id
            || snapshot.request_digest != spec.request_digest
            || snapshot.natural_key != spec.natural_key
            || snapshot.checkpoints.len() != spec.files.len()
            || snapshot
                .checkpoints
                .iter()
                .zip(&spec.files)
                .any(|(checkpoint, file)| {
                    checkpoint.file_id != file.file_id
                        || checkpoint.expected_size != file.expected_size
                        || checkpoint.durable_offset > checkpoint.expected_size
                })
        {
            return Err(ImportJobError::SnapshotDoesNotMatchSpec);
        }
        Ok(Self { spec, snapshot })
    }

    #[must_use]
    pub fn spec(&self) -> &ImportSpec {
        &self.spec
    }

    #[must_use]
    pub fn snapshot(&self) -> &ImportSnapshot {
        &self.snapshot
    }

    /// Apply one command as a deterministic reducer step. Rejected commands
    /// never change version or state; every accepted mutation emits
    /// `PersistSnapshot` before any externally visible effect.
    pub fn decide(&mut self, command: ImportCommand) -> ImportDecision {
        let mut next = self.snapshot.clone();
        let result = reduce(&self.spec, &mut next, command);
        match result {
            Ok(mut effects) => {
                if next == self.snapshot {
                    return ImportDecision {
                        outcome: ImportCommandOutcome::NoChange,
                        effects: Vec::new(),
                        snapshot: self.snapshot.clone(),
                    };
                }
                next.version = next.version.saturating_add(1);
                effects.insert(0, ImportEffect::PersistSnapshot);
                self.snapshot = next.clone();
                ImportDecision {
                    outcome: ImportCommandOutcome::Applied,
                    effects,
                    snapshot: next,
                }
            }
            Err(reason) => ImportDecision {
                outcome: ImportCommandOutcome::Rejected(reason),
                effects: Vec::new(),
                snapshot: self.snapshot.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportStartOutcome {
    Created {
        job_id: ImportJobId,
    },
    Existing {
        job_id: ImportJobId,
    },
    Conflict {
        existing_job_id: ImportJobId,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportSpecError {
    #[error("source inventory must not be empty")]
    EmptyInventory,
    #[error("source inventory total size overflowed u64")]
    TotalBytesOverflow,
    #[error("local space is insufficient: need {required} bytes, have {available}")]
    InsufficientLocalSpace { required: u64, available: u64 },
    #[error("unsigned source is forbidden by import policy")]
    UnsignedRejected,
    #[error("unsigned source requires an explicit admission receipt")]
    UnsignedReceiptRequired,
    #[error("source provenance does not match its revision claim")]
    ProvenanceRevisionMismatch,
    #[error("cannot serialize import request: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportJobError {
    #[error("persisted import snapshot does not match its immutable spec")]
    SnapshotDoesNotMatchSpec,
    #[error("failure message is empty, too long, or contains control characters")]
    InvalidFailureMessage,
    #[error(transparent)]
    Source(#[from] SourceModelError),
}

fn reduce(
    spec: &ImportSpec,
    snapshot: &mut ImportSnapshot,
    command: ImportCommand,
) -> Result<Vec<ImportEffect>, ImportRejectReason> {
    if snapshot.state.is_terminal()
        && !matches!(
            &command,
            ImportCommand::Retry if matches!(&snapshot.state, ImportJobState::Failed)
        )
    {
        return Err(ImportRejectReason::Terminal);
    }

    match command {
        ImportCommand::Start if matches!(&snapshot.state, ImportJobState::Queued) => {
            snapshot.state = ImportJobState::Preflighting;
            let locator = snapshot
                .active_locator
                .clone()
                .unwrap_or_else(|| spec.locator.clone());
            snapshot.active_locator = Some(locator.clone());
            Ok(vec![ImportEffect::StartPreflight { locator }])
        }
        ImportCommand::ResetProgressForSource { revision_claim }
            if matches!(&snapshot.state, ImportJobState::WaitingForMedia { .. }) =>
        {
            if &revision_claim != spec.source.revision_claim() {
                return Err(ImportRejectReason::IntegrityMismatch);
            }
            for checkpoint in &mut snapshot.checkpoints {
                checkpoint.durable_offset = 0;
                checkpoint.source_sha256 = None;
                checkpoint.target_sha256 = None;
                checkpoint.verified = false;
            }
            snapshot.active_locator = None;
            snapshot.verified_source = None;
            snapshot.local_receipt = None;
            snapshot.failure = None;
            snapshot.state = ImportJobState::WaitingForMedia {
                resume_from: ImportResumePoint::Preflight,
            };
            Ok(Vec::new())
        }
        ImportCommand::SourceAvailable {
            locator,
            revision_claim,
        } if matches!(&snapshot.state, ImportJobState::WaitingForMedia { .. }) => {
            if &revision_claim != spec.source.revision_claim() {
                return Err(ImportRejectReason::IntegrityMismatch);
            }
            let resume_from = match &snapshot.state {
                ImportJobState::WaitingForMedia { resume_from } => *resume_from,
                _ => unreachable!(),
            };
            snapshot.active_locator = Some(locator.clone());
            snapshot.state = match resume_from {
                ImportResumePoint::Preflight => ImportJobState::Preflighting,
                ImportResumePoint::Copy => ImportJobState::Copying,
            };
            Ok(match resume_from {
                ImportResumePoint::Preflight => vec![ImportEffect::StartPreflight { locator }],
                ImportResumePoint::Copy => vec![ImportEffect::StartCopy {
                    locator,
                    resume_offsets: resume_offsets(snapshot),
                }],
            })
        }
        ImportCommand::SourceUnavailable
            if matches!(
                &snapshot.state,
                ImportJobState::Preflighting | ImportJobState::Copying
            ) =>
        {
            let resume_from = resume_point(&snapshot.state);
            snapshot.active_locator = None;
            snapshot.state = ImportJobState::WaitingForMedia { resume_from };
            Ok(vec![ImportEffect::CancelIo])
        }
        ImportCommand::PreflightPassed
            if matches!(&snapshot.state, ImportJobState::Preflighting) =>
        {
            let locator = snapshot
                .active_locator
                .clone()
                .ok_or(ImportRejectReason::IllegalInState)?;
            snapshot.state = ImportJobState::Copying;
            Ok(vec![ImportEffect::StartCopy {
                locator,
                resume_offsets: resume_offsets(snapshot),
            }])
        }
        ImportCommand::CopyCheckpoint {
            file_id,
            durable_offset,
        } if matches!(&snapshot.state, ImportJobState::Copying) => {
            let checkpoint = snapshot
                .checkpoints
                .iter_mut()
                .find(|checkpoint| checkpoint.file_id == file_id)
                .ok_or(ImportRejectReason::UnknownFile)?;
            if durable_offset < checkpoint.durable_offset
                || durable_offset > checkpoint.expected_size
            {
                return Err(ImportRejectReason::StaleOrRegressedCheckpoint);
            }
            checkpoint.durable_offset = durable_offset;
            Ok(Vec::new())
        }
        ImportCommand::CopyFinished if matches!(&snapshot.state, ImportJobState::Copying) => {
            if snapshot
                .checkpoints
                .iter()
                .any(|checkpoint| checkpoint.durable_offset != checkpoint.expected_size)
            {
                return Err(ImportRejectReason::CopyIncomplete);
            }
            snapshot.state = ImportJobState::Verifying;
            Ok(vec![ImportEffect::StartVerification])
        }
        ImportCommand::FileVerified {
            file_id,
            source_sha256,
            target_sha256,
        } if matches!(&snapshot.state, ImportJobState::Verifying) => {
            if !is_sha256_hex(&source_sha256) || !is_sha256_hex(&target_sha256) {
                return Err(ImportRejectReason::InvalidDigest);
            }
            if source_sha256 != target_sha256 {
                return Err(ImportRejectReason::IntegrityMismatch);
            }
            let (file, checkpoint) = spec
                .files
                .iter()
                .zip(snapshot.checkpoints.iter_mut())
                .find(|(file, _)| file.file_id == file_id)
                .ok_or(ImportRejectReason::UnknownFile)?;
            if file
                .expected_source_sha256
                .as_ref()
                .is_some_and(|expected| expected != &source_sha256)
            {
                return Err(ImportRejectReason::IntegrityMismatch);
            }
            if checkpoint.durable_offset != checkpoint.expected_size {
                return Err(ImportRejectReason::CopyIncomplete);
            }
            checkpoint.source_sha256 = Some(source_sha256);
            checkpoint.target_sha256 = Some(target_sha256);
            checkpoint.verified = true;
            Ok(Vec::new())
        }
        ImportCommand::VerificationPassed { inventory_digest }
            if matches!(&snapshot.state, ImportJobState::Verifying) =>
        {
            if snapshot
                .checkpoints
                .iter()
                .any(|checkpoint| !checkpoint.verified)
            {
                return Err(ImportRejectReason::CopyIncomplete);
            }
            let verified_source = spec
                .source
                .clone()
                .with_verified_inventory(inventory_digest);
            snapshot.verified_source = Some(verified_source.clone());
            snapshot.state = ImportJobState::Committing;
            Ok(vec![ImportEffect::StartCommit {
                source: verified_source,
            }])
        }
        ImportCommand::CommitSucceeded { receipt }
            if matches!(&snapshot.state, ImportJobState::Committing) =>
        {
            let Some(source) = snapshot.verified_source.as_ref() else {
                return Err(ImportRejectReason::ReceiptMismatch);
            };
            let Some(content_revision) = source.content_revision() else {
                return Err(ImportRejectReason::ReceiptMismatch);
            };
            let InventoryHashesVerdict::Valid { digest } =
                source.trust_verdicts().inventory_hashes()
            else {
                return Err(ImportRejectReason::ReceiptMismatch);
            };
            if receipt.content_revision() != content_revision
                || receipt.inventory_digest() != digest
                || receipt.provenance() != source.provenance()
            {
                return Err(ImportRejectReason::ReceiptMismatch);
            }
            snapshot.local_receipt = Some(receipt.clone());
            snapshot.state = ImportJobState::LocalVerified;
            snapshot.failure = None;
            Ok(vec![ImportEffect::PublishLocalVerified { receipt }])
        }
        ImportCommand::RetryableFailure { failure } if !snapshot.state.is_terminal() => {
            if !failure.retryable {
                return Err(ImportRejectReason::FailureRetryabilityMismatch);
            }
            let resume_from = resume_point(&snapshot.state);
            snapshot.failure = Some(failure);
            snapshot.attempt = snapshot.attempt.saturating_add(1);
            snapshot.state = ImportJobState::RetryWait { resume_from };
            Ok(vec![ImportEffect::CancelIo, ImportEffect::ScheduleRetry])
        }
        ImportCommand::PermanentFailure { failure } if !snapshot.state.is_terminal() => {
            if failure.retryable {
                return Err(ImportRejectReason::FailureRetryabilityMismatch);
            }
            snapshot.failure = Some(failure);
            snapshot.state = ImportJobState::Failed;
            Ok(vec![ImportEffect::CancelIo])
        }
        ImportCommand::RequestPause if !snapshot.state.is_terminal() => {
            let resume_from = resume_point(&snapshot.state);
            snapshot.desired_state = ImportDesiredState::Paused;
            snapshot.state = ImportJobState::Pausing { resume_from };
            Ok(vec![ImportEffect::CancelIo])
        }
        ImportCommand::PauseCompleted
            if matches!(&snapshot.state, ImportJobState::Pausing { .. }) =>
        {
            let resume_from = match &snapshot.state {
                ImportJobState::Pausing { resume_from } => *resume_from,
                _ => unreachable!(),
            };
            snapshot.state = ImportJobState::Paused { resume_from };
            Ok(Vec::new())
        }
        ImportCommand::Resume if matches!(&snapshot.state, ImportJobState::Paused { .. }) => {
            snapshot.desired_state = ImportDesiredState::Running;
            snapshot.state = ImportJobState::Queued;
            Ok(vec![ImportEffect::Schedule])
        }
        ImportCommand::RequestCancel if !snapshot.state.is_terminal() => {
            snapshot.desired_state = ImportDesiredState::Cancelled;
            snapshot.state = ImportJobState::Cancelling;
            Ok(vec![ImportEffect::CancelIo])
        }
        ImportCommand::CancellationCompleted
            if matches!(&snapshot.state, ImportJobState::Cancelling) =>
        {
            snapshot.state = ImportJobState::Cancelled;
            Ok(Vec::new())
        }
        ImportCommand::Retry
            if matches!(
                &snapshot.state,
                ImportJobState::RetryWait { .. } | ImportJobState::Failed
            ) && snapshot
                .failure
                .as_ref()
                .is_some_and(ImportFailure::retryable) =>
        {
            snapshot.desired_state = ImportDesiredState::Running;
            snapshot.failure = None;
            snapshot.state = ImportJobState::Queued;
            Ok(vec![ImportEffect::Schedule])
        }
        _ => Err(ImportRejectReason::IllegalInState),
    }
}

fn enforce_unsigned_policy(
    source: &SourceRecording,
    policy: &ImportPolicy,
) -> Result<(), ImportSpecError> {
    let SourceProvenance::LocallyValidatedUnsigned(unsigned) = source.provenance() else {
        return Ok(());
    };
    match policy.unsigned {
        UnsignedImportPolicy::Reject => Err(ImportSpecError::UnsignedRejected),
        UnsignedImportPolicy::RequireAdmissionReceipt
            if unsigned.user_admission_receipt().is_none() =>
        {
            Err(ImportSpecError::UnsignedReceiptRequired)
        }
        UnsignedImportPolicy::RequireAdmissionReceipt
        | UnsignedImportPolicy::AllowExplicitSelection => Ok(()),
    }
}

fn resume_offsets(snapshot: &ImportSnapshot) -> Vec<(SourceArtifactId, u64)> {
    snapshot
        .checkpoints
        .iter()
        .filter(|checkpoint| !checkpoint.verified)
        .map(|checkpoint| (checkpoint.file_id.clone(), checkpoint.durable_offset))
        .collect()
}

fn resume_point(state: &ImportJobState) -> ImportResumePoint {
    match state {
        ImportJobState::Copying
        | ImportJobState::Verifying
        | ImportJobState::Committing
        | ImportJobState::Pausing {
            resume_from: ImportResumePoint::Copy,
        }
        | ImportJobState::Paused {
            resume_from: ImportResumePoint::Copy,
        }
        | ImportJobState::RetryWait {
            resume_from: ImportResumePoint::Copy,
        } => ImportResumePoint::Copy,
        _ => ImportResumePoint::Preflight,
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
