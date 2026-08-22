use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ingest::{LocalSourceReceipt, SourceContentRevision};

use super::identity::{DerivationJobId, ProfileRevision, SourceManifestDigest};
use super::manifest::{DerivedCompletion, DerivedSubject, SegmentPairCheckpoint};
use super::plan::{MediaPlan, NormalizationInput, ProbeReport};
use super::ports::ProcessStopReason;
use super::profile::{EncoderBuild, NormalizationProfile, ProfileError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationSpec {
    job_id: DerivationJobId,
    subject: DerivedSubject,
    local_source: LocalSourceReceipt,
    source_manifest_digest: SourceManifestDigest,
    profile: NormalizationProfile,
    encoder_build: EncoderBuild,
    input: NormalizationInput,
    created_at: String,
}

impl DerivationSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: DerivationJobId,
        subject: DerivedSubject,
        local_source: LocalSourceReceipt,
        source_manifest_digest: SourceManifestDigest,
        profile: NormalizationProfile,
        encoder_build: EncoderBuild,
        input: NormalizationInput,
        created_at: impl Into<String>,
    ) -> Result<Self, DerivationSpecError> {
        let created_at = created_at.into();
        let spec = Self {
            job_id,
            subject,
            local_source,
            source_manifest_digest,
            profile,
            encoder_build,
            input,
            created_at,
        };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), DerivationSpecError> {
        if self.created_at.is_empty()
            || self.created_at.len() > 128
            || self.created_at.chars().any(char::is_control)
        {
            return Err(DerivationSpecError::InvalidCreatedAt);
        }
        self.profile
            .require_compatible_encoder(&self.encoder_build)?;
        if !self
            .profile
            .quality_variant()
            .accepts_source_codec(self.input.source_codec())
        {
            return Err(DerivationSpecError::InputProfileMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn job_id(&self) -> &DerivationJobId {
        &self.job_id
    }

    #[must_use]
    pub fn subject(&self) -> &DerivedSubject {
        &self.subject
    }

    #[must_use]
    pub fn local_source(&self) -> &LocalSourceReceipt {
        &self.local_source
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        self.local_source.content_revision()
    }

    #[must_use]
    pub fn source_manifest_digest(&self) -> &SourceManifestDigest {
        &self.source_manifest_digest
    }

    #[must_use]
    pub fn profile(&self) -> &NormalizationProfile {
        &self.profile
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        self.profile.profile_revision()
    }

    #[must_use]
    pub fn encoder_build(&self) -> &EncoderBuild {
        &self.encoder_build
    }

    #[must_use]
    pub fn input(&self) -> &NormalizationInput {
        &self.input
    }

    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DerivationSpecError {
    #[error("derivation created_at must be bounded, non-empty, and contain no control characters")]
    InvalidCreatedAt,
    #[error("normalization profile quality variant does not admit this input codec")]
    InputProfileMismatch,
    #[error("durable derivation snapshot is internally inconsistent: {0}")]
    InvalidSnapshot(String),
    #[error(transparent)]
    Profile(#[from] ProfileError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DerivationStartOutcome {
    Created { job_id: DerivationJobId },
    Existing { job_id: DerivationJobId },
    Conflict { existing_job_id: DerivationJobId },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaNormalizerError {
    #[error("derivation job {0} was not found")]
    NotFound(DerivationJobId),
    #[error("derivation job changed concurrently; expected version {expected}, found {actual}")]
    Stale { expected: u64, actual: u64 },
    #[error("derivation command was rejected: {0:?}")]
    Rejected(DerivationRejectReason),
    #[error("media normalizer is shutting down")]
    ShuttingDown,
    #[error("media normalizer resource did not stop: {0}")]
    ResourceStuck(String),
    #[error("durable media repository failure: {0}")]
    Repository(String),
    #[error("media worker failure: {0}")]
    Worker(String),
}

/// Application-facing deep interface. Implementations serialize commands per
/// job, persist the aggregate effects, and own worker/process orchestration.
pub trait MediaNormalizer: Send + Sync {
    fn start(&self, spec: DerivationSpec) -> Result<DerivationStartOutcome, MediaNormalizerError>;

    fn command(
        &self,
        job_id: &DerivationJobId,
        command: DerivationCommand,
    ) -> Result<DerivationSnapshot, MediaNormalizerError>;

    fn snapshot(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<Option<DerivationSnapshot>, MediaNormalizerError>;

    fn snapshots(&self) -> Result<Vec<DerivationSnapshot>, MediaNormalizerError>;

    fn recover(&self) -> Result<Vec<DerivationSnapshot>, MediaNormalizerError>;

    fn shutdown(&self) -> Result<(), MediaNormalizerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationFailureCode {
    SourceUnavailable,
    ProbeFailed,
    PlanRejected,
    EncoderFailed,
    ValidationFailed,
    ProfileUnapproved,
    IntegrityMismatch,
    Disk,
    DeadlineExceeded,
    ResourceStuck,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DerivationJobState {
    Queued,
    WaitingForSource,
    Probing,
    Planning,
    Encoding,
    Validating,
    Committing,
    RetryWait,
    Cancelling,
    DerivedVerified,
    Failed {
        code: DerivationFailureCode,
        retryable: bool,
    },
    Cancelled,
}

impl DerivationJobState {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::DerivedVerified | Self::Failed { .. } | Self::Cancelled
        )
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Probing | Self::Planning | Self::Encoding | Self::Validating | Self::Committing
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationDesiredState {
    Run,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationWorkerReport {
    ProbeCompleted(ProbeReport),
    PlanCompleted(MediaPlan),
    PairStarted {
        segment_index: u32,
    },
    PairCheckpointed(SegmentPairCheckpoint),
    ValidationCompleted,
    CommitCompleted(DerivedCompletion),
    ProcessStopped(ProcessStopReason),
    StageFailed {
        code: DerivationFailureCode,
        retryable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Worker reports own stage evidence so state transitions remain self-contained.
#[allow(clippy::large_enum_variant)]
pub enum DerivationCommand {
    SourceAvailable,
    SourceUnavailable,
    Pause,
    Resume,
    Cancel,
    FinalizeCancel,
    Retry,
    Dismiss,
    Worker(DerivationWorkerReport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationEffect {
    CommitState {
        expected_version: u64,
        to: DerivationJobState,
    },
    SetDesiredState {
        expected_version: u64,
        to: DerivationDesiredState,
    },
    PersistProbe {
        expected_version: u64,
        report: ProbeReport,
        to: DerivationJobState,
    },
    PersistPlan {
        expected_version: u64,
        plan: MediaPlan,
        to: DerivationJobState,
    },
    SetCurrentPair {
        expected_version: u64,
        segment_index: u32,
    },
    CommitPairCheckpoint {
        expected_version: u64,
        checkpoint: SegmentPairCheckpoint,
        to: DerivationJobState,
    },
    PublishCompletion {
        expected_version: u64,
        completion: DerivedCompletion,
        to: DerivationJobState,
    },
    RequestProcessStop(ProcessStopReason),
    AwaitProcessReap,
    DiscardCurrentPartialPair {
        segment_index: u32,
    },
    Dispatch,
    RemoveJob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationRejectReason {
    AlreadyTerminal,
    NotTerminal,
    NotRetryable,
    WrongState {
        expected: DerivationJobState,
        actual: DerivationJobState,
    },
    UnexpectedSegment {
        segment_index: u32,
    },
    EvidenceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationOutcome {
    Accepted,
    NoOp,
    Rejected(DerivationRejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationDecision {
    outcome: DerivationOutcome,
    effects: Vec<DerivationEffect>,
}

impl DerivationDecision {
    fn accepted(effects: Vec<DerivationEffect>) -> Self {
        Self {
            outcome: DerivationOutcome::Accepted,
            effects,
        }
    }

    fn no_op() -> Self {
        Self {
            outcome: DerivationOutcome::NoOp,
            effects: Vec::new(),
        }
    }

    fn rejected(reason: DerivationRejectReason) -> Self {
        Self {
            outcome: DerivationOutcome::Rejected(reason),
            effects: Vec::new(),
        }
    }

    #[must_use]
    pub fn outcome(&self) -> &DerivationOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn effects(&self) -> &[DerivationEffect] {
        &self.effects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationSnapshot {
    spec: DerivationSpec,
    state: DerivationJobState,
    desired_state: DerivationDesiredState,
    version: u64,
    probe_report: Option<ProbeReport>,
    media_plan: Option<MediaPlan>,
    checkpoints: Vec<SegmentPairCheckpoint>,
    current_pair: Option<u32>,
    completion: Option<DerivedCompletion>,
}

impl DerivationSnapshot {
    #[must_use]
    pub fn spec(&self) -> &DerivationSpec {
        &self.spec
    }

    #[must_use]
    pub fn state(&self) -> &DerivationJobState {
        &self.state
    }

    #[must_use]
    pub fn desired_state(&self) -> DerivationDesiredState {
        self.desired_state
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn probe_report(&self) -> Option<&ProbeReport> {
        self.probe_report.as_ref()
    }

    #[must_use]
    pub fn media_plan(&self) -> Option<&MediaPlan> {
        self.media_plan.as_ref()
    }

    #[must_use]
    pub fn checkpoints(&self) -> &[SegmentPairCheckpoint] {
        &self.checkpoints
    }

    #[must_use]
    pub fn current_pair(&self) -> Option<u32> {
        self.current_pair
    }

    #[must_use]
    pub fn completion(&self) -> Option<&DerivedCompletion> {
        self.completion.as_ref()
    }
}

/// Pure durable derivation aggregate. Effects are interpreted by one
/// serialized job owner; the aggregate opens no files, database, or process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationJob {
    spec: DerivationSpec,
    state: DerivationJobState,
    desired_state: DerivationDesiredState,
    version: u64,
    probe_report: Option<ProbeReport>,
    media_plan: Option<MediaPlan>,
    checkpoints: BTreeMap<u32, SegmentPairCheckpoint>,
    current_pair: Option<u32>,
    completion: Option<DerivedCompletion>,
}

impl DerivationJob {
    pub fn new(spec: DerivationSpec) -> Result<Self, DerivationSpecError> {
        spec.validate()?;
        Ok(Self {
            spec,
            state: DerivationJobState::Queued,
            desired_state: DerivationDesiredState::Run,
            version: 1,
            probe_report: None,
            media_plan: None,
            checkpoints: BTreeMap::new(),
            current_pair: None,
            completion: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        spec: DerivationSpec,
        state: DerivationJobState,
        desired_state: DerivationDesiredState,
        version: u64,
        probe_report: Option<ProbeReport>,
        media_plan: Option<MediaPlan>,
        checkpoints: Vec<SegmentPairCheckpoint>,
        current_pair: Option<u32>,
        completion: Option<DerivedCompletion>,
    ) -> Result<Self, DerivationSpecError> {
        spec.validate()?;
        if version == 0 {
            return Err(DerivationSpecError::InvalidSnapshot(
                "version must be positive".to_string(),
            ));
        }
        let mut checkpoint_map = BTreeMap::new();
        for checkpoint in checkpoints {
            if checkpoint.profile_revision() != spec.profile_revision()
                || checkpoint.encoder_build_fingerprint()
                    != spec.encoder_build().build_fingerprint()
                || checkpoint_map
                    .insert(checkpoint.segment_index(), checkpoint)
                    .is_some()
            {
                return Err(DerivationSpecError::InvalidSnapshot(
                    "checkpoint identity mismatch or duplicate".to_string(),
                ));
            }
        }
        if checkpoint_map
            .keys()
            .enumerate()
            .any(|(expected, actual)| usize::try_from(*actual).ok() != Some(expected))
        {
            return Err(DerivationSpecError::InvalidSnapshot(
                "checkpoints must be contiguous from segment zero".to_string(),
            ));
        }
        if !checkpoint_map.is_empty() && media_plan.is_none() {
            return Err(DerivationSpecError::InvalidSnapshot(
                "checkpoint ledger requires a media plan".to_string(),
            ));
        }
        if let Some(plan) = &media_plan {
            if plan.source_kind() != spec.input().kind()
                || plan.profile_revision() != spec.profile_revision()
                || checkpoint_map
                    .keys()
                    .any(|index| plan.segment_pair(*index).is_none())
            {
                return Err(DerivationSpecError::InvalidSnapshot(
                    "media plan differs from the durable spec".to_string(),
                ));
            }
        }
        if current_pair.is_some_and(|index| checkpoint_map.contains_key(&index)) {
            return Err(DerivationSpecError::InvalidSnapshot(
                "current partial pair is already checkpointed".to_string(),
            ));
        }
        if state == DerivationJobState::DerivedVerified {
            let Some(completion) = &completion else {
                return Err(DerivationSpecError::InvalidSnapshot(
                    "derived_verified requires completion evidence".to_string(),
                ));
            };
            if completion.source_content_revision() != spec.source_revision()
                || completion.profile_revision() != spec.profile_revision()
            {
                return Err(DerivationSpecError::InvalidSnapshot(
                    "completion identity differs from the durable spec".to_string(),
                ));
            }
        } else if completion.is_some() {
            return Err(DerivationSpecError::InvalidSnapshot(
                "completion evidence exists before derived_verified".to_string(),
            ));
        }
        Ok(Self {
            spec,
            state,
            desired_state,
            version,
            probe_report,
            media_plan,
            checkpoints: checkpoint_map,
            current_pair,
            completion,
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> DerivationSnapshot {
        DerivationSnapshot {
            spec: self.spec.clone(),
            state: self.state.clone(),
            desired_state: self.desired_state,
            version: self.version,
            probe_report: self.probe_report.clone(),
            media_plan: self.media_plan.clone(),
            checkpoints: self.checkpoints.values().cloned().collect(),
            current_pair: self.current_pair,
            completion: self.completion.clone(),
        }
    }

    /// Apply one durable aggregate effect after its side effect has committed.
    ///
    /// The executor must not reimplement this reducer: keeping the transition
    /// here makes replay and live execution share the same version fence and
    /// identity checks. Effects that only request process/worker activity are
    /// intentionally rejected because they do not mutate the durable
    /// snapshot.
    pub fn apply_committed_effect(
        &mut self,
        effect: &DerivationEffect,
    ) -> Result<DerivationSnapshot, DerivationSpecError> {
        let expected_version = match effect {
            DerivationEffect::CommitState {
                expected_version, ..
            }
            | DerivationEffect::SetDesiredState {
                expected_version, ..
            }
            | DerivationEffect::PersistProbe {
                expected_version, ..
            }
            | DerivationEffect::PersistPlan {
                expected_version, ..
            }
            | DerivationEffect::SetCurrentPair {
                expected_version, ..
            }
            | DerivationEffect::CommitPairCheckpoint {
                expected_version, ..
            }
            | DerivationEffect::PublishCompletion {
                expected_version, ..
            } => *expected_version,
            DerivationEffect::RequestProcessStop(_)
            | DerivationEffect::AwaitProcessReap
            | DerivationEffect::DiscardCurrentPartialPair { .. }
            | DerivationEffect::Dispatch
            | DerivationEffect::RemoveJob => {
                return Err(DerivationSpecError::InvalidSnapshot(
                    "effect does not mutate the durable derivation snapshot".to_string(),
                ));
            }
        };
        if expected_version != self.version {
            return Err(DerivationSpecError::InvalidSnapshot(format!(
                "effect expected version {expected_version}, current version {}",
                self.version
            )));
        }

        match effect {
            DerivationEffect::CommitState { to, .. } => {
                self.state = to.clone();
            }
            DerivationEffect::SetDesiredState { to, .. } => {
                self.desired_state = *to;
            }
            DerivationEffect::PersistProbe { report, to, .. } => {
                self.probe_report = Some(report.clone());
                self.state = to.clone();
            }
            DerivationEffect::PersistPlan { plan, to, .. } => {
                if plan.source_kind() != self.spec.input().kind()
                    || plan.profile_revision() != self.spec.profile_revision()
                {
                    return Err(DerivationSpecError::InvalidSnapshot(
                        "persisted plan differs from the durable derivation spec".to_string(),
                    ));
                }
                self.media_plan = Some(plan.clone());
                self.state = to.clone();
            }
            DerivationEffect::SetCurrentPair { segment_index, .. } => {
                if self.checkpoints.contains_key(segment_index) || self.current_pair.is_some() {
                    return Err(DerivationSpecError::InvalidSnapshot(
                        "current pair is already set or checkpointed".to_string(),
                    ));
                }
                let expected_segment = u32::try_from(self.checkpoints.len()).map_err(|_| {
                    DerivationSpecError::InvalidSnapshot(
                        "checkpoint count exceeds segment index range".to_string(),
                    )
                })?;
                if *segment_index != expected_segment
                    || self
                        .media_plan
                        .as_ref()
                        .and_then(|plan| plan.segment_pair(*segment_index))
                        .is_none()
                {
                    return Err(DerivationSpecError::InvalidSnapshot(
                        "current pair is not the next pair in the media plan".to_string(),
                    ));
                }
                self.current_pair = Some(*segment_index);
            }
            DerivationEffect::CommitPairCheckpoint { checkpoint, to, .. } => {
                let segment_index = checkpoint.segment_index();
                if self.current_pair != Some(segment_index)
                    || self.checkpoints.contains_key(&segment_index)
                    || usize::try_from(segment_index).ok() != Some(self.checkpoints.len())
                    || checkpoint.profile_revision() != self.spec.profile_revision()
                    || checkpoint.encoder_build_fingerprint()
                        != self.spec.encoder_build().build_fingerprint()
                {
                    return Err(DerivationSpecError::InvalidSnapshot(
                        "pair checkpoint does not match the next durable pair".to_string(),
                    ));
                }
                self.checkpoints.insert(segment_index, checkpoint.clone());
                self.current_pair = None;
                self.state = to.clone();
            }
            DerivationEffect::PublishCompletion { completion, to, .. } => {
                if completion.source_content_revision() != self.spec.source_revision()
                    || completion.profile_revision() != self.spec.profile_revision()
                {
                    return Err(DerivationSpecError::InvalidSnapshot(
                        "completion evidence differs from the durable derivation spec".to_string(),
                    ));
                }
                self.completion = Some(completion.clone());
                self.state = to.clone();
            }
            DerivationEffect::RequestProcessStop(_)
            | DerivationEffect::AwaitProcessReap
            | DerivationEffect::DiscardCurrentPartialPair { .. }
            | DerivationEffect::Dispatch
            | DerivationEffect::RemoveJob => unreachable!("non-persistent effects returned above"),
        }

        self.version = self.version.checked_add(1).ok_or_else(|| {
            DerivationSpecError::InvalidSnapshot("derivation version overflow".to_string())
        })?;
        Ok(self.snapshot())
    }

    #[must_use]
    pub fn decide(&self, command: DerivationCommand) -> DerivationDecision {
        match command {
            DerivationCommand::SourceAvailable => self.source_available(),
            DerivationCommand::SourceUnavailable => self.source_unavailable(),
            DerivationCommand::Pause => self.pause(),
            DerivationCommand::Resume => self.resume(),
            DerivationCommand::Cancel => self.cancel(),
            DerivationCommand::FinalizeCancel => self.finalize_cancel(),
            DerivationCommand::Retry => self.retry(),
            DerivationCommand::Dismiss => self.dismiss(),
            DerivationCommand::Worker(report) => self.worker(report),
        }
    }

    fn source_available(&self) -> DerivationDecision {
        if self.state.is_terminal() || self.state == DerivationJobState::Cancelling {
            return DerivationDecision::no_op();
        }
        if self.desired_state == DerivationDesiredState::Paused {
            return DerivationDecision::no_op();
        }
        if matches!(
            self.state,
            DerivationJobState::Queued
                | DerivationJobState::WaitingForSource
                | DerivationJobState::RetryWait
        ) {
            DerivationDecision::accepted(vec![
                self.commit(DerivationJobState::Probing),
                DerivationEffect::Dispatch,
            ])
        } else {
            DerivationDecision::no_op()
        }
    }

    fn source_unavailable(&self) -> DerivationDecision {
        if self.state.is_terminal() || self.state == DerivationJobState::Cancelling {
            return DerivationDecision::no_op();
        }
        if self.state.is_active() {
            return DerivationDecision::accepted(vec![
                DerivationEffect::RequestProcessStop(ProcessStopReason::SourceUnavailable),
                DerivationEffect::AwaitProcessReap,
            ]);
        }
        if self.state == DerivationJobState::WaitingForSource {
            DerivationDecision::no_op()
        } else {
            DerivationDecision::accepted(vec![self.commit(DerivationJobState::WaitingForSource)])
        }
    }

    fn pause(&self) -> DerivationDecision {
        if self.state.is_terminal() {
            return DerivationDecision::rejected(DerivationRejectReason::AlreadyTerminal);
        }
        if self.desired_state == DerivationDesiredState::Paused {
            return DerivationDecision::no_op();
        }
        let mut effects = vec![DerivationEffect::SetDesiredState {
            expected_version: self.version,
            to: DerivationDesiredState::Paused,
        }];
        if self.state.is_active() {
            effects.push(DerivationEffect::RequestProcessStop(
                ProcessStopReason::Pause,
            ));
            effects.push(DerivationEffect::AwaitProcessReap);
        }
        DerivationDecision::accepted(effects)
    }

    fn resume(&self) -> DerivationDecision {
        if self.state.is_terminal() {
            return DerivationDecision::rejected(DerivationRejectReason::AlreadyTerminal);
        }
        if self.desired_state == DerivationDesiredState::Run {
            return DerivationDecision::no_op();
        }
        DerivationDecision::accepted(vec![
            DerivationEffect::SetDesiredState {
                expected_version: self.version,
                to: DerivationDesiredState::Run,
            },
            DerivationEffect::Dispatch,
        ])
    }

    fn cancel(&self) -> DerivationDecision {
        if self.state.is_terminal() {
            return DerivationDecision::rejected(DerivationRejectReason::AlreadyTerminal);
        }
        if self.state == DerivationJobState::Cancelling {
            return DerivationDecision::no_op();
        }
        let mut effects = vec![self.commit(DerivationJobState::Cancelling)];
        if self.state.is_active() {
            effects.push(DerivationEffect::RequestProcessStop(
                ProcessStopReason::Cancel,
            ));
            effects.push(DerivationEffect::AwaitProcessReap);
        } else {
            if let Some(segment_index) = self.current_pair {
                effects.push(DerivationEffect::DiscardCurrentPartialPair { segment_index });
            }
            effects.push(DerivationEffect::CommitState {
                expected_version: self.version + 1,
                to: DerivationJobState::Cancelled,
            });
        }
        DerivationDecision::accepted(effects)
    }

    fn finalize_cancel(&self) -> DerivationDecision {
        if self.state != DerivationJobState::Cancelling {
            return DerivationDecision::rejected(DerivationRejectReason::WrongState {
                expected: DerivationJobState::Cancelling,
                actual: self.state.clone(),
            });
        }
        let mut effects = Vec::new();
        if let Some(segment_index) = self.current_pair {
            effects.push(DerivationEffect::DiscardCurrentPartialPair { segment_index });
        }
        effects.push(self.commit(DerivationJobState::Cancelled));
        DerivationDecision::accepted(effects)
    }

    fn retry(&self) -> DerivationDecision {
        match &self.state {
            DerivationJobState::Failed {
                retryable: true, ..
            } => DerivationDecision::accepted(vec![
                self.commit(DerivationJobState::Queued),
                DerivationEffect::Dispatch,
            ]),
            DerivationJobState::Failed {
                retryable: false, ..
            } => DerivationDecision::rejected(DerivationRejectReason::NotRetryable),
            _ => DerivationDecision::rejected(DerivationRejectReason::WrongState {
                expected: DerivationJobState::Failed {
                    code: DerivationFailureCode::Internal,
                    retryable: true,
                },
                actual: self.state.clone(),
            }),
        }
    }

    fn dismiss(&self) -> DerivationDecision {
        if self.state.is_terminal() {
            DerivationDecision::accepted(vec![DerivationEffect::RemoveJob])
        } else {
            DerivationDecision::rejected(DerivationRejectReason::NotTerminal)
        }
    }

    fn worker(&self, report: DerivationWorkerReport) -> DerivationDecision {
        match report {
            DerivationWorkerReport::ProbeCompleted(report) => {
                if self.state != DerivationJobState::Probing {
                    return self.wrong_state(DerivationJobState::Probing);
                }
                DerivationDecision::accepted(vec![
                    DerivationEffect::PersistProbe {
                        expected_version: self.version,
                        report,
                        to: DerivationJobState::Planning,
                    },
                    DerivationEffect::Dispatch,
                ])
            }
            DerivationWorkerReport::PlanCompleted(plan) => {
                if self.state != DerivationJobState::Planning {
                    return self.wrong_state(DerivationJobState::Planning);
                }
                if plan.source_kind() != self.spec.input().kind()
                    || plan.profile_revision() != self.spec.profile_revision()
                {
                    return DerivationDecision::rejected(DerivationRejectReason::EvidenceMismatch);
                }
                DerivationDecision::accepted(vec![
                    DerivationEffect::PersistPlan {
                        expected_version: self.version,
                        plan,
                        to: DerivationJobState::Encoding,
                    },
                    DerivationEffect::Dispatch,
                ])
            }
            DerivationWorkerReport::PairStarted { segment_index } => {
                if self.state != DerivationJobState::Encoding {
                    return self.wrong_state(DerivationJobState::Encoding);
                }
                let expected = u32::try_from(self.checkpoints.len()).unwrap_or(u32::MAX);
                if segment_index != expected
                    || self
                        .media_plan
                        .as_ref()
                        .and_then(|plan| plan.segment_pair(segment_index))
                        .is_none()
                {
                    return DerivationDecision::rejected(
                        DerivationRejectReason::UnexpectedSegment { segment_index },
                    );
                }
                DerivationDecision::accepted(vec![DerivationEffect::SetCurrentPair {
                    expected_version: self.version,
                    segment_index,
                }])
            }
            DerivationWorkerReport::PairCheckpointed(checkpoint) => {
                if self.state != DerivationJobState::Encoding {
                    return self.wrong_state(DerivationJobState::Encoding);
                }
                let segment_index = checkpoint.segment_index();
                if self.current_pair != Some(segment_index)
                    || usize::try_from(segment_index).ok() != Some(self.checkpoints.len())
                    || checkpoint.profile_revision() != self.spec.profile_revision()
                    || checkpoint.encoder_build_fingerprint()
                        != self.spec.encoder_build().build_fingerprint()
                {
                    return DerivationDecision::rejected(
                        DerivationRejectReason::UnexpectedSegment { segment_index },
                    );
                }
                let pair_count = self
                    .media_plan
                    .as_ref()
                    .map(|plan| plan.segment_pairs().len())
                    .unwrap_or(0);
                let to = if self.checkpoints.len() + 1 == pair_count {
                    DerivationJobState::Validating
                } else {
                    DerivationJobState::Encoding
                };
                DerivationDecision::accepted(vec![
                    DerivationEffect::CommitPairCheckpoint {
                        expected_version: self.version,
                        checkpoint,
                        to,
                    },
                    DerivationEffect::Dispatch,
                ])
            }
            DerivationWorkerReport::ValidationCompleted => {
                if self.state != DerivationJobState::Validating {
                    return self.wrong_state(DerivationJobState::Validating);
                }
                let pair_count = self
                    .media_plan
                    .as_ref()
                    .map(|plan| plan.segment_pairs().len())
                    .unwrap_or(0);
                if pair_count == 0 || pair_count != self.checkpoints.len() {
                    return DerivationDecision::rejected(DerivationRejectReason::EvidenceMismatch);
                }
                DerivationDecision::accepted(vec![
                    self.commit(DerivationJobState::Committing),
                    DerivationEffect::Dispatch,
                ])
            }
            DerivationWorkerReport::CommitCompleted(completion) => {
                if self.state != DerivationJobState::Committing {
                    return self.wrong_state(DerivationJobState::Committing);
                }
                if completion.source_content_revision() != self.spec.source_revision()
                    || completion.profile_revision() != self.spec.profile_revision()
                {
                    return DerivationDecision::rejected(DerivationRejectReason::EvidenceMismatch);
                }
                DerivationDecision::accepted(vec![DerivationEffect::PublishCompletion {
                    expected_version: self.version,
                    completion,
                    to: DerivationJobState::DerivedVerified,
                }])
            }
            DerivationWorkerReport::ProcessStopped(reason) => self.process_stopped(reason),
            DerivationWorkerReport::StageFailed { code, retryable } => {
                self.stage_failed(code, retryable)
            }
        }
    }

    fn process_stopped(&self, reason: ProcessStopReason) -> DerivationDecision {
        if self.state == DerivationJobState::Cancelling && reason == ProcessStopReason::Cancel {
            return self.finalize_cancel();
        }
        let target = match reason {
            ProcessStopReason::Pause if self.desired_state == DerivationDesiredState::Paused => {
                DerivationJobState::RetryWait
            }
            ProcessStopReason::SourceUnavailable => DerivationJobState::WaitingForSource,
            ProcessStopReason::Shutdown => DerivationJobState::RetryWait,
            _ => return DerivationDecision::rejected(DerivationRejectReason::EvidenceMismatch),
        };
        let mut effects = Vec::new();
        if let Some(segment_index) = self.current_pair {
            effects.push(DerivationEffect::DiscardCurrentPartialPair { segment_index });
        }
        effects.push(self.commit(target));
        DerivationDecision::accepted(effects)
    }

    fn stage_failed(&self, code: DerivationFailureCode, retryable: bool) -> DerivationDecision {
        if self.state.is_terminal() {
            return DerivationDecision::rejected(DerivationRejectReason::AlreadyTerminal);
        }
        let mut effects = Vec::new();
        if let Some(segment_index) = self.current_pair {
            effects.push(DerivationEffect::DiscardCurrentPartialPair { segment_index });
        }
        effects.push(self.commit(DerivationJobState::Failed { code, retryable }));
        DerivationDecision::accepted(effects)
    }

    fn wrong_state(&self, expected: DerivationJobState) -> DerivationDecision {
        DerivationDecision::rejected(DerivationRejectReason::WrongState {
            expected,
            actual: self.state.clone(),
        })
    }

    fn commit(&self, to: DerivationJobState) -> DerivationEffect {
        DerivationEffect::CommitState {
            expected_version: self.version,
            to,
        }
    }
}
