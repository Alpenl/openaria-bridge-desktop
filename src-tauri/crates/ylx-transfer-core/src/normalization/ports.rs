use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ingest::{LocalSourceReceipt, SourceContentRevision};

use super::plan::{MediaPlanError, NormalizationInput, ProbeReport, SegmentPairPlan};
use super::profile::{EncoderBuild, NormalizationProfile, ProfileError};
use super::validation::{QualityEvidence, SegmentValidationReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStopReason {
    Pause,
    Cancel,
    Shutdown,
    SourceUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessDeadline {
    timeout_ms: u64,
    terminate_grace_ms: u64,
    kill_grace_ms: u64,
}

impl ProcessDeadline {
    pub fn new(
        timeout_ms: u64,
        terminate_grace_ms: u64,
        kill_grace_ms: u64,
    ) -> Result<Self, MediaRequestError> {
        if timeout_ms == 0 || terminate_grace_ms == 0 || kill_grace_ms == 0 {
            return Err(MediaRequestError::InvalidDeadline);
        }
        Ok(Self {
            timeout_ms,
            terminate_grace_ms,
            kill_grace_ms,
        })
    }

    #[must_use]
    pub fn timeout_ms(self) -> u64 {
        self.timeout_ms
    }

    #[must_use]
    pub fn terminate_grace_ms(self) -> u64 {
        self.terminate_grace_ms
    }

    #[must_use]
    pub fn kill_grace_ms(self) -> u64 {
        self.kill_grace_ms
    }
}

/// Cancellation/deadline view polled by a process-owning adapter. A stop
/// request is only a request; the adapter must terminate, kill if needed,
/// wait, and return a process disposition accounting for the child.
pub trait MediaOperationControl: Send + Sync {
    fn stop_requested(&self) -> Option<ProcessStopReason>;
    fn deadline(&self) -> ProcessDeadline;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReapReceipt {
    process_id: u32,
    exit_code: Option<i32>,
    terminate_requested: bool,
    kill_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessReapReport {
    receipts: Vec<ReapReceipt>,
}

impl ProcessReapReport {
    pub fn new(receipts: Vec<ReapReceipt>) -> Result<Self, MediaRequestError> {
        if receipts.is_empty() {
            Err(MediaRequestError::EmptyReapReport)
        } else {
            Ok(Self { receipts })
        }
    }

    #[must_use]
    pub fn one(receipt: ReapReceipt) -> Self {
        Self {
            receipts: vec![receipt],
        }
    }

    #[must_use]
    pub fn receipts(&self) -> &[ReapReceipt] {
        &self.receipts
    }
}

impl ReapReceipt {
    #[must_use]
    pub fn new(
        process_id: u32,
        exit_code: Option<i32>,
        terminate_requested: bool,
        kill_requested: bool,
    ) -> Self {
        Self {
            process_id,
            exit_code,
            terminate_requested,
            kill_requested,
        }
    }

    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    #[must_use]
    pub fn terminate_requested(&self) -> bool {
        self.terminate_requested
    }

    #[must_use]
    pub fn kill_requested(&self) -> bool {
        self.kill_requested
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcessDisposition {
    NotSpawned,
    Reaped {
        report: ProcessReapReport,
    },
    ResourceStuck {
        process_id: u32,
        terminate_requested: bool,
        kill_requested: bool,
    },
}

impl ProcessDisposition {
    #[must_use]
    pub fn reaped(report: ProcessReapReport) -> Self {
        Self::Reaped { report }
    }

    #[must_use]
    pub fn is_accounted_for(&self) -> bool {
        !matches!(self, Self::ResourceStuck { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaProcessFailureCode {
    ExecutableUnavailable,
    SpawnRejected,
    ProbeRejected,
    EncodeRejected,
    ValidationRejected,
    DeadlineExceeded,
    Io,
    InvalidOutput,
    ResourceStuck,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaProcessFailure {
    code: MediaProcessFailureCode,
    retryable: bool,
    sanitized_detail: String,
}

impl MediaProcessFailure {
    #[must_use]
    pub fn new(code: MediaProcessFailureCode, retryable: bool, detail: impl AsRef<str>) -> Self {
        Self {
            code,
            retryable,
            sanitized_detail: sanitize_process_detail(detail.as_ref()),
        }
    }

    #[must_use]
    pub fn resource_stuck(process_id: u32) -> Self {
        Self::new(
            MediaProcessFailureCode::ResourceStuck,
            false,
            format!("media process {process_id} did not exit after terminate and kill deadlines"),
        )
    }

    #[must_use]
    pub fn code(&self) -> MediaProcessFailureCode {
        self.code
    }

    #[must_use]
    pub fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub fn sanitized_detail(&self) -> &str {
        &self.sanitized_detail
    }
}

/// Every return path accounts for the child process. `Stopped` structurally
/// requires a reap receipt; a child that survives kill is a typed failure,
/// never a successful pause/cancel acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaProcessOutcome<T> {
    Completed {
        value: T,
        reap: ProcessReapReport,
    },
    Stopped {
        reason: ProcessStopReason,
        reap: ProcessReapReport,
    },
    Failed {
        failure: MediaProcessFailure,
        disposition: ProcessDisposition,
    },
}

impl<T> MediaProcessOutcome<T> {
    #[must_use]
    pub fn completed(value: T, reap: ProcessReapReport) -> Self {
        Self::Completed { value, reap }
    }

    #[must_use]
    pub fn stopped(reason: ProcessStopReason, reap: ProcessReapReport) -> Self {
        Self::Stopped { reason, reap }
    }

    #[must_use]
    pub fn failed(failure: MediaProcessFailure, disposition: ProcessDisposition) -> Self {
        Self::Failed {
            failure,
            disposition,
        }
    }

    #[must_use]
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> MediaProcessOutcome<U> {
        match self {
            Self::Completed { value, reap } => MediaProcessOutcome::Completed {
                value: map(value),
                reap,
            },
            Self::Stopped { reason, reap } => MediaProcessOutcome::Stopped { reason, reap },
            Self::Failed {
                failure,
                disposition,
            } => MediaProcessOutcome::Failed {
                failure,
                disposition,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    local_source: LocalSourceReceipt,
    input: NormalizationInput,
}

impl ProbeRequest {
    #[must_use]
    pub fn new(local_source: LocalSourceReceipt, input: NormalizationInput) -> Self {
        Self {
            local_source,
            input,
        }
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
    pub fn input(&self) -> &NormalizationInput {
        &self.input
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderStatistics {
    encoded_frame_count: u64,
    output_duration_ticks: u64,
    elapsed_ms: u64,
    encoding_fps_milli: u64,
    peak_memory_bytes: Option<u64>,
}

impl EncoderStatistics {
    pub fn new(
        encoded_frame_count: u64,
        output_duration_ticks: u64,
        elapsed_ms: u64,
        encoding_fps_milli: u64,
        peak_memory_bytes: Option<u64>,
    ) -> Result<Self, MediaRequestError> {
        if encoded_frame_count == 0 || output_duration_ticks == 0 || elapsed_ms == 0 {
            return Err(MediaRequestError::InvalidEncoderStatistics);
        }
        Ok(Self {
            encoded_frame_count,
            output_duration_ticks,
            elapsed_ms,
            encoding_fps_milli,
            peak_memory_bytes,
        })
    }

    #[must_use]
    pub fn encoded_frame_count(&self) -> u64 {
        self.encoded_frame_count
    }

    #[must_use]
    pub fn output_duration_ticks(&self) -> u64 {
        self.output_duration_ticks
    }

    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncodeSegmentPairRequest {
    local_source: LocalSourceReceipt,
    input: NormalizationInput,
    pair_plan: SegmentPairPlan,
    profile: NormalizationProfile,
    encoder_build: EncoderBuild,
    left_partial_path: PathBuf,
    right_partial_path: PathBuf,
}

impl EncodeSegmentPairRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn from_media_plan(
        local_source: LocalSourceReceipt,
        input: NormalizationInput,
        media_plan: &super::MediaPlan,
        segment_index: u32,
        profile: NormalizationProfile,
        encoder_build: EncoderBuild,
        left_partial_path: PathBuf,
        right_partial_path: PathBuf,
    ) -> Result<Self, MediaRequestError> {
        if input.kind() != media_plan.source_kind()
            || media_plan.profile_revision() != profile.profile_revision()
        {
            return Err(MediaRequestError::InputPlanMismatch);
        }
        let pair_plan = media_plan
            .segment_pair(segment_index)
            .cloned()
            .ok_or(MediaRequestError::UnknownSegment(segment_index))?;
        profile.require_compatible_encoder(&encoder_build)?;
        validate_partial_pair(&left_partial_path, &right_partial_path)?;
        Ok(Self {
            local_source,
            input,
            pair_plan,
            profile,
            encoder_build,
            left_partial_path,
            right_partial_path,
        })
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
    pub fn input(&self) -> &NormalizationInput {
        &self.input
    }

    #[must_use]
    pub fn pair_plan(&self) -> &SegmentPairPlan {
        &self.pair_plan
    }

    #[must_use]
    pub fn profile(&self) -> &NormalizationProfile {
        &self.profile
    }

    #[must_use]
    pub fn encoder_build(&self) -> &EncoderBuild {
        &self.encoder_build
    }

    #[must_use]
    pub fn left_partial_path(&self) -> &Path {
        &self.left_partial_path
    }

    #[must_use]
    pub fn right_partial_path(&self) -> &Path {
        &self.right_partial_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedSegmentPair {
    segment_index: u32,
    left_partial_path: PathBuf,
    right_partial_path: PathBuf,
    statistics: EncoderStatistics,
}

impl EncodedSegmentPair {
    pub fn from_request(
        request: &EncodeSegmentPairRequest,
        statistics: EncoderStatistics,
    ) -> Result<Self, MediaRequestError> {
        if statistics.encoded_frame_count() != request.pair_plan().frame_count() {
            return Err(MediaRequestError::EncoderFrameCountMismatch {
                expected: request.pair_plan().frame_count(),
                actual: statistics.encoded_frame_count(),
            });
        }
        Ok(Self {
            segment_index: request.pair_plan().segment_index(),
            left_partial_path: request.left_partial_path.clone(),
            right_partial_path: request.right_partial_path.clone(),
            statistics,
        })
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn left_partial_path(&self) -> &Path {
        &self.left_partial_path
    }

    #[must_use]
    pub fn right_partial_path(&self) -> &Path {
        &self.right_partial_path
    }

    #[must_use]
    pub fn statistics(&self) -> &EncoderStatistics {
        &self.statistics
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SegmentValidationRequest {
    local_source: LocalSourceReceipt,
    input: NormalizationInput,
    pair_plan: SegmentPairPlan,
    profile: NormalizationProfile,
    encoder_build: EncoderBuild,
    encoded: EncodedSegmentPair,
    left_quality: QualityEvidence,
    right_quality: QualityEvidence,
}

impl SegmentValidationRequest {
    pub fn new(
        encode_request: &EncodeSegmentPairRequest,
        encoded: EncodedSegmentPair,
        left_quality: QualityEvidence,
        right_quality: QualityEvidence,
    ) -> Result<Self, MediaRequestError> {
        if encoded.segment_index() != encode_request.pair_plan().segment_index()
            || encoded.left_partial_path() != encode_request.left_partial_path()
            || encoded.right_partial_path() != encode_request.right_partial_path()
        {
            return Err(MediaRequestError::EncodedPairMismatch);
        }
        if left_quality.eye() != super::Eye::Left || right_quality.eye() != super::Eye::Right {
            return Err(MediaRequestError::QualityEyeMismatch);
        }
        Ok(Self {
            local_source: encode_request.local_source.clone(),
            input: encode_request.input.clone(),
            pair_plan: encode_request.pair_plan.clone(),
            profile: encode_request.profile.clone(),
            encoder_build: encode_request.encoder_build.clone(),
            encoded,
            left_quality,
            right_quality,
        })
    }

    #[must_use]
    pub fn local_source(&self) -> &LocalSourceReceipt {
        &self.local_source
    }

    #[must_use]
    pub fn input(&self) -> &NormalizationInput {
        &self.input
    }

    #[must_use]
    pub fn pair_plan(&self) -> &SegmentPairPlan {
        &self.pair_plan
    }

    #[must_use]
    pub fn profile(&self) -> &NormalizationProfile {
        &self.profile
    }

    #[must_use]
    pub fn encoder_build(&self) -> &EncoderBuild {
        &self.encoder_build
    }

    #[must_use]
    pub fn encoded(&self) -> &EncodedSegmentPair {
        &self.encoded
    }

    #[must_use]
    pub fn left_quality(&self) -> &QualityEvidence {
        &self.left_quality
    }

    #[must_use]
    pub fn right_quality(&self) -> &QualityEvidence {
        &self.right_quality
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaRequestError {
    #[error("media process deadline and reap grace periods must be non-zero")]
    InvalidDeadline,
    #[error("a completed or stopped media operation must account for at least one reaped process")]
    EmptyReapReport,
    #[error("encoder statistics must contain non-zero frame count, duration, and elapsed time")]
    InvalidEncoderStatistics,
    #[error("normalization input, plan, and profile do not describe the same derivation")]
    InputPlanMismatch,
    #[error("segment {0} is not part of the media plan")]
    UnknownSegment(u32),
    #[error(
        "left/right partial outputs must be distinct .partial.mp4 files in one pair directory"
    )]
    InvalidPartialPair,
    #[error("encoder reported {actual} frames, expected {expected}")]
    EncoderFrameCountMismatch { expected: u64, actual: u64 },
    #[error("encoded pair does not match its encode request")]
    EncodedPairMismatch,
    #[error("quality evidence must contain one left and one right eye")]
    QualityEyeMismatch,
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(transparent)]
    Plan(#[from] MediaPlanError),
}

/// Production FFmpeg/ffprobe and deterministic fakes both implement these
/// two ports. Command lines, JSON, handles, and process trees remain adapter
/// details and never cross into the aggregate.
pub trait MediaProbe: Send + Sync {
    fn probe(
        &self,
        request: &ProbeRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<ProbeReport>;

    fn validate_segment_pair(
        &self,
        request: &SegmentValidationRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<SegmentValidationReport>;
}

pub trait MediaEncoder: Send + Sync {
    fn encoder_build(&self) -> EncoderBuild;

    fn encode_segment_pair(
        &self,
        request: &EncodeSegmentPairRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<EncodedSegmentPair>;
}

fn validate_partial_pair(left: &Path, right: &Path) -> Result<(), MediaRequestError> {
    let valid_suffix = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".partial.mp4"))
    };
    if left == right
        || left.parent() != right.parent()
        || !valid_suffix(left)
        || !valid_suffix(right)
    {
        Err(MediaRequestError::InvalidPartialPair)
    } else {
        Ok(())
    }
}

fn sanitize_process_detail(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                '\u{fffd}'
            } else {
                character
            }
        })
        .take(1_024)
        .collect()
}
