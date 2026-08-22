use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ingest::SourceArtifactId;

use super::identity::{ContentSha256, ProfileRevision, SourceManifestDigest};
use super::profile::{
    ContainerFormat, NormalizationProfile, PixelFormat, ProfileError, VideoCodec,
};
use super::rational::{Rational, RationalError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMediaKind {
    RawCaptureV2,
    LegacyMjpegSessionV5,
    ApplianceSpoolV6,
    CompleteUnpublishedV6,
    PairedH264PublicationV1,
    UnsignedPairedH264PublicationV1,
    UnsignedMjpegPublicationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Eye {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dimensions {
    width: u32,
    height: u32,
}

impl Dimensions {
    pub fn new(width: u32, height: u32) -> Result<Self, MediaPlanError> {
        if width == 0 || height == 0 {
            return Err(MediaPlanError::InvalidGeometry { width, height });
        }
        Ok(Self { width, height })
    }

    #[must_use]
    pub fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(self) -> u32 {
        self.height
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

impl Rect {
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Result<Self, MediaPlanError> {
        let _ = Dimensions::new(width, height)?;
        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }

    #[must_use]
    pub fn x(self) -> u32 {
        self.x
    }

    #[must_use]
    pub fn y(self) -> u32 {
        self.y
    }

    #[must_use]
    pub fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(self) -> u32 {
        self.height
    }
}

/// A local, already-imported source artifact. The manifest-relative path is
/// carried for evidence; the adapter receives the separately resolved local
/// path and must never join the relative path itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSourceArtifact {
    id: SourceArtifactId,
    local_path: PathBuf,
    manifest_relative_path: String,
    expected_size_bytes: u64,
    expected_sha256: ContentSha256,
}

impl ResolvedSourceArtifact {
    pub fn new(
        id: SourceArtifactId,
        local_path: PathBuf,
        manifest_relative_path: impl Into<String>,
        expected_size_bytes: u64,
        expected_sha256: ContentSha256,
    ) -> Result<Self, MediaPlanError> {
        let manifest_relative_path = manifest_relative_path.into();
        validate_relative_path(&manifest_relative_path)?;
        if local_path.as_os_str().is_empty() {
            return Err(MediaPlanError::InvalidLocalPath);
        }
        if expected_size_bytes == 0 {
            return Err(MediaPlanError::EmptySourceArtifact(id));
        }
        Ok(Self {
            id,
            local_path,
            manifest_relative_path,
            expected_size_bytes,
            expected_sha256,
        })
    }

    #[must_use]
    pub fn id(&self) -> &SourceArtifactId {
        &self.id
    }

    #[must_use]
    pub fn local_path(&self) -> &Path {
        &self.local_path
    }

    #[must_use]
    pub fn manifest_relative_path(&self) -> &str {
        &self.manifest_relative_path
    }

    #[must_use]
    pub fn expected_size_bytes(&self) -> u64 {
        self.expected_size_bytes
    }

    #[must_use]
    pub fn expected_sha256(&self) -> &ContentSha256 {
        &self.expected_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSegment {
    segment_index: u32,
    artifact: ResolvedSourceArtifact,
}

impl SourceSegment {
    #[must_use]
    pub fn new(segment_index: u32, artifact: ResolvedSourceArtifact) -> Self {
        Self {
            segment_index,
            artifact,
        }
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn artifact(&self) -> &ResolvedSourceArtifact {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedSourceSegment {
    segment_index: u32,
    left: ResolvedSourceArtifact,
    right: ResolvedSourceArtifact,
}

impl PairedSourceSegment {
    pub fn new(
        segment_index: u32,
        left: ResolvedSourceArtifact,
        right: ResolvedSourceArtifact,
    ) -> Result<Self, MediaPlanError> {
        if left.id() == right.id() {
            return Err(MediaPlanError::DuplicateArtifact(left.id().clone()));
        }
        Ok(Self {
            segment_index,
            left,
            right,
        })
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn left(&self) -> &ResolvedSourceArtifact {
        &self.left
    }

    #[must_use]
    pub fn right(&self) -> &ResolvedSourceArtifact {
        &self.right
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawFrameEvidence {
    declared_frame_count: u64,
    declared_source_fps: Rational,
    jpeg_boundaries_verified: bool,
    sequence_gap_count: u64,
    timestamp_error_count: u64,
}

impl RawFrameEvidence {
    pub fn new(
        declared_frame_count: u64,
        declared_source_fps: Rational,
        jpeg_boundaries_verified: bool,
        sequence_gap_count: u64,
        timestamp_error_count: u64,
    ) -> Result<Self, MediaPlanError> {
        if declared_frame_count == 0
            || !jpeg_boundaries_verified
            || sequence_gap_count != 0
            || timestamp_error_count != 0
        {
            return Err(MediaPlanError::InvalidRawFrameEvidence);
        }
        Ok(Self {
            declared_frame_count,
            declared_source_fps,
            jpeg_boundaries_verified,
            sequence_gap_count,
            timestamp_error_count,
        })
    }

    #[must_use]
    pub fn declared_frame_count(&self) -> u64 {
        self.declared_frame_count
    }

    #[must_use]
    pub fn declared_source_fps(&self) -> Rational {
        self.declared_source_fps
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTimingEvidence {
    frames_jsonl_digest: ContentSha256,
    declared_total_frames: u64,
    declared_source_fps: Rational,
    segment_pts_reset: bool,
}

impl LegacyTimingEvidence {
    pub fn new(
        frames_jsonl_digest: ContentSha256,
        declared_total_frames: u64,
        declared_source_fps: Rational,
        segment_pts_reset: bool,
    ) -> Result<Self, MediaPlanError> {
        if declared_total_frames == 0 || !segment_pts_reset {
            return Err(MediaPlanError::InvalidLegacyTimingEvidence);
        }
        Ok(Self {
            frames_jsonl_digest,
            declared_total_frames,
            declared_source_fps,
            segment_pts_reset,
        })
    }

    #[must_use]
    pub fn declared_total_frames(&self) -> u64 {
        self.declared_total_frames
    }

    #[must_use]
    pub fn declared_source_fps(&self) -> Rational {
        self.declared_source_fps
    }
}

/// The source shapes admitted by the V1 normalizer. Constructors and
/// the planner both validate ordering because persisted input is untrusted
/// again after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizationInput {
    RawCaptureV2 {
        stereo: ResolvedSourceArtifact,
        frame_evidence: RawFrameEvidence,
    },
    LegacyMjpegSessionV5 {
        segments: Vec<SourceSegment>,
        timing_evidence: LegacyTimingEvidence,
    },
    ApplianceSpoolV6 {
        segments: Vec<SourceSegment>,
        capture_commit_digest: SourceManifestDigest,
    },
    CompleteUnpublishedV6 {
        segments: Vec<PairedSourceSegment>,
        source_manifest_digest: SourceManifestDigest,
    },
    PairedH264PublicationV1 {
        segments: Vec<PairedSourceSegment>,
        publication_manifest_digest: SourceManifestDigest,
    },
    UnsignedPairedH264PublicationV1 {
        segments: Vec<PairedSourceSegment>,
        publication_manifest_digest: SourceManifestDigest,
    },
    UnsignedMjpegPublicationV1 {
        segments: Vec<SourceSegment>,
        publication_manifest_digest: SourceManifestDigest,
    },
}

impl NormalizationInput {
    pub fn raw_capture_v2(
        stereo: ResolvedSourceArtifact,
        frame_evidence: RawFrameEvidence,
    ) -> Self {
        Self::RawCaptureV2 {
            stereo,
            frame_evidence,
        }
    }

    pub fn legacy_mjpeg_session_v5(
        segments: Vec<SourceSegment>,
        timing_evidence: LegacyTimingEvidence,
    ) -> Result<Self, MediaPlanError> {
        validate_segment_sequence(&segments)?;
        Ok(Self::LegacyMjpegSessionV5 {
            segments,
            timing_evidence,
        })
    }

    pub fn appliance_spool_v6(
        segments: Vec<SourceSegment>,
        capture_commit_digest: SourceManifestDigest,
    ) -> Result<Self, MediaPlanError> {
        validate_segment_sequence(&segments)?;
        Ok(Self::ApplianceSpoolV6 {
            segments,
            capture_commit_digest,
        })
    }

    pub fn complete_unpublished_v6(
        segments: Vec<PairedSourceSegment>,
        source_manifest_digest: SourceManifestDigest,
    ) -> Result<Self, MediaPlanError> {
        validate_paired_segment_sequence(&segments)?;
        Ok(Self::CompleteUnpublishedV6 {
            segments,
            source_manifest_digest,
        })
    }

    pub fn paired_h264_publication_v1(
        segments: Vec<PairedSourceSegment>,
        publication_manifest_digest: SourceManifestDigest,
    ) -> Result<Self, MediaPlanError> {
        validate_paired_segment_sequence(&segments)?;
        Ok(Self::PairedH264PublicationV1 {
            segments,
            publication_manifest_digest,
        })
    }

    pub fn unsigned_paired_h264_publication_v1(
        segments: Vec<PairedSourceSegment>,
        publication_manifest_digest: SourceManifestDigest,
    ) -> Result<Self, MediaPlanError> {
        validate_paired_segment_sequence(&segments)?;
        Ok(Self::UnsignedPairedH264PublicationV1 {
            segments,
            publication_manifest_digest,
        })
    }

    pub fn unsigned_mjpeg_publication_v1(
        segments: Vec<SourceSegment>,
        publication_manifest_digest: SourceManifestDigest,
    ) -> Result<Self, MediaPlanError> {
        validate_segment_sequence(&segments)?;
        Ok(Self::UnsignedMjpegPublicationV1 {
            segments,
            publication_manifest_digest,
        })
    }

    #[must_use]
    pub fn kind(&self) -> SourceMediaKind {
        match self {
            Self::RawCaptureV2 { .. } => SourceMediaKind::RawCaptureV2,
            Self::LegacyMjpegSessionV5 { .. } => SourceMediaKind::LegacyMjpegSessionV5,
            Self::ApplianceSpoolV6 { .. } => SourceMediaKind::ApplianceSpoolV6,
            Self::CompleteUnpublishedV6 { .. } => SourceMediaKind::CompleteUnpublishedV6,
            Self::PairedH264PublicationV1 { .. } => SourceMediaKind::PairedH264PublicationV1,
            Self::UnsignedPairedH264PublicationV1 { .. } => {
                SourceMediaKind::UnsignedPairedH264PublicationV1
            }
            Self::UnsignedMjpegPublicationV1 { .. } => SourceMediaKind::UnsignedMjpegPublicationV1,
        }
    }

    #[must_use]
    pub fn source_codec(&self) -> VideoCodec {
        match self {
            Self::RawCaptureV2 { .. }
            | Self::LegacyMjpegSessionV5 { .. }
            | Self::ApplianceSpoolV6 { .. }
            | Self::UnsignedMjpegPublicationV1 { .. } => VideoCodec::Mjpeg,
            Self::CompleteUnpublishedV6 { .. }
            | Self::PairedH264PublicationV1 { .. }
            | Self::UnsignedPairedH264PublicationV1 { .. } => VideoCodec::H264,
        }
    }

    #[must_use]
    pub fn artifacts(&self) -> Vec<&ResolvedSourceArtifact> {
        match self {
            Self::RawCaptureV2 { stereo, .. } => vec![stereo],
            Self::LegacyMjpegSessionV5 { segments, .. }
            | Self::ApplianceSpoolV6 { segments, .. }
            | Self::UnsignedMjpegPublicationV1 { segments, .. } => {
                segments.iter().map(SourceSegment::artifact).collect()
            }
            Self::CompleteUnpublishedV6 { segments, .. }
            | Self::PairedH264PublicationV1 { segments, .. }
            | Self::UnsignedPairedH264PublicationV1 { segments, .. } => segments
                .iter()
                .flat_map(|segment| [segment.left(), segment.right()])
                .collect(),
        }
    }
}

/// Sanitized ffprobe result for exactly one expected source artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbedArtifact {
    artifact_id: SourceArtifactId,
    codec: VideoCodec,
    codec_profile: Option<String>,
    container: ContainerFormat,
    sample_entry: Option<String>,
    pixel_format: PixelFormat,
    dimensions: Dimensions,
    frame_rate: Rational,
    time_base: Rational,
    first_pts: i64,
    frame_count: u64,
    duration_ticks: u64,
    video_track_count: u8,
    audio_track_count: u8,
    keyframe_frames: Vec<u64>,
}

impl ProbedArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_id: SourceArtifactId,
        codec: VideoCodec,
        codec_profile: Option<String>,
        container: ContainerFormat,
        sample_entry: Option<String>,
        pixel_format: PixelFormat,
        dimensions: Dimensions,
        frame_rate: Rational,
        time_base: Rational,
        first_pts: i64,
        frame_count: u64,
        duration_ticks: u64,
        video_track_count: u8,
        audio_track_count: u8,
        keyframe_frames: Vec<u64>,
    ) -> Result<Self, MediaPlanError> {
        if frame_count == 0 || duration_ticks == 0 {
            return Err(MediaPlanError::EmptyProbe(artifact_id));
        }
        if keyframe_frames.iter().any(|frame| *frame >= frame_count)
            || keyframe_frames
                .windows(2)
                .any(|window| window[0] >= window[1])
        {
            return Err(MediaPlanError::InvalidKeyframeInventory(artifact_id));
        }
        Ok(Self {
            artifact_id,
            codec,
            codec_profile,
            container,
            sample_entry,
            pixel_format,
            dimensions,
            frame_rate,
            time_base,
            first_pts,
            frame_count,
            duration_ticks,
            video_track_count,
            audio_track_count,
            keyframe_frames,
        })
    }

    #[must_use]
    pub fn artifact_id(&self) -> &SourceArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    #[must_use]
    pub fn codec_profile(&self) -> Option<&str> {
        self.codec_profile.as_deref()
    }

    #[must_use]
    pub fn container(&self) -> ContainerFormat {
        self.container
    }

    #[must_use]
    pub fn sample_entry(&self) -> Option<&str> {
        self.sample_entry.as_deref()
    }

    #[must_use]
    pub fn pixel_format(&self) -> PixelFormat {
        self.pixel_format
    }

    #[must_use]
    pub fn dimensions(&self) -> Dimensions {
        self.dimensions
    }

    #[must_use]
    pub fn frame_rate(&self) -> Rational {
        self.frame_rate
    }

    #[must_use]
    pub fn time_base(&self) -> Rational {
        self.time_base
    }

    #[must_use]
    pub fn first_pts(&self) -> i64 {
        self.first_pts
    }

    #[must_use]
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    #[must_use]
    pub fn duration_ticks(&self) -> u64 {
        self.duration_ticks
    }

    #[must_use]
    pub fn video_track_count(&self) -> u8 {
        self.video_track_count
    }

    #[must_use]
    pub fn audio_track_count(&self) -> u8 {
        self.audio_track_count
    }

    #[must_use]
    pub fn keyframe_frames(&self) -> &[u64] {
        &self.keyframe_frames
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    artifacts: Vec<ProbedArtifact>,
}

impl ProbeReport {
    pub fn new(artifacts: Vec<ProbedArtifact>) -> Result<Self, MediaPlanError> {
        let mut ids = BTreeSet::new();
        for artifact in &artifacts {
            if !ids.insert(artifact.artifact_id().clone()) {
                return Err(MediaPlanError::DuplicateProbe(
                    artifact.artifact_id().clone(),
                ));
            }
        }
        Ok(Self { artifacts })
    }

    #[must_use]
    pub fn artifacts(&self) -> &[ProbedArtifact] {
        &self.artifacts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingBasis {
    RawFrameIndex,
    LegacyV5ResetPtsAccumulated,
    CaptureCommitSegmentOrder,
    CompleteUnpublishedPairOrder,
    SignedPublicationPairOrder,
    UnsignedPublicationPairOrder,
    UnsignedPublicationSideBySideOrder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameSlice {
    artifact_id: SourceArtifactId,
    first_frame_in_artifact: u64,
    frame_count: u64,
    source_pts_first: i64,
    source_time_base: Rational,
    session_first_frame: u64,
}

impl FrameSlice {
    #[must_use]
    pub fn artifact_id(&self) -> &SourceArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub fn first_frame_in_artifact(&self) -> u64 {
        self.first_frame_in_artifact
    }

    #[must_use]
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    #[must_use]
    pub fn source_pts_first(&self) -> i64 {
        self.source_pts_first
    }

    #[must_use]
    pub fn source_time_base(&self) -> Rational {
        self.source_time_base
    }

    #[must_use]
    pub fn session_first_frame(&self) -> u64 {
        self.session_first_frame
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EyeInputPlan {
    eye: Eye,
    slices: Vec<FrameSlice>,
    crop: Option<Rect>,
}

impl EyeInputPlan {
    #[must_use]
    pub fn eye(&self) -> Eye {
        self.eye
    }

    #[must_use]
    pub fn slices(&self) -> &[FrameSlice] {
        &self.slices
    }

    #[must_use]
    pub fn crop(&self) -> Option<Rect> {
        self.crop
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentPairPlan {
    segment_index: u32,
    first_frame: u64,
    frame_count: u64,
    start_ticks: u64,
    duration_ticks: u64,
    source_fps: Rational,
    eye_dimensions: Dimensions,
    left: EyeInputPlan,
    right: EyeInputPlan,
    left_output_relative_path: String,
    right_output_relative_path: String,
}

impl SegmentPairPlan {
    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn first_frame(&self) -> u64 {
        self.first_frame
    }

    #[must_use]
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    #[must_use]
    pub fn start_ticks(&self) -> u64 {
        self.start_ticks
    }

    #[must_use]
    pub fn duration_ticks(&self) -> u64 {
        self.duration_ticks
    }

    #[must_use]
    pub fn source_fps(&self) -> Rational {
        self.source_fps
    }

    #[must_use]
    pub fn eye_dimensions(&self) -> Dimensions {
        self.eye_dimensions
    }

    #[must_use]
    pub fn left(&self) -> &EyeInputPlan {
        &self.left
    }

    #[must_use]
    pub fn right(&self) -> &EyeInputPlan {
        &self.right
    }

    #[must_use]
    pub fn output_relative_path(&self, eye: Eye) -> &str {
        match eye {
            Eye::Left => &self.left_output_relative_path,
            Eye::Right => &self.right_output_relative_path,
        }
    }
}

/// A field-private plan that can only be produced after source/probe
/// reconciliation. Adapter code may inspect it but cannot splice in an
/// unprobed artifact or alter the left/right timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlan {
    source_kind: SourceMediaKind,
    profile_revision: ProfileRevision,
    source_fps: Rational,
    eye_dimensions: Dimensions,
    time_base: Rational,
    timing_basis: TimingBasis,
    total_frames: u64,
    segment_pairs: Vec<SegmentPairPlan>,
}

impl MediaPlan {
    #[must_use]
    pub fn source_kind(&self) -> SourceMediaKind {
        self.source_kind
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }

    #[must_use]
    pub fn source_fps(&self) -> Rational {
        self.source_fps
    }

    #[must_use]
    pub fn eye_dimensions(&self) -> Dimensions {
        self.eye_dimensions
    }

    #[must_use]
    pub fn time_base(&self) -> Rational {
        self.time_base
    }

    #[must_use]
    pub fn timing_basis(&self) -> TimingBasis {
        self.timing_basis
    }

    #[must_use]
    pub fn total_frames(&self) -> u64 {
        self.total_frames
    }

    #[must_use]
    pub fn segment_pairs(&self) -> &[SegmentPairPlan] {
        &self.segment_pairs
    }

    #[must_use]
    pub fn segment_pair(&self, index: u32) -> Option<&SegmentPairPlan> {
        self.segment_pairs
            .get(usize::try_from(index).ok()?)
            .filter(|pair| pair.segment_index() == index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaPlanError {
    #[error("media dimensions must be non-zero, got {width}x{height}")]
    InvalidGeometry { width: u32, height: u32 },
    #[error("side-by-side width must be even, got {0}")]
    OddStereoWidth(u32),
    #[error("resolved local source path is empty")]
    InvalidLocalPath,
    #[error("manifest-relative source path is unsafe: {0:?}")]
    UnsafeRelativePath(String),
    #[error("source artifact {0} is empty")]
    EmptySourceArtifact(SourceArtifactId),
    #[error("source artifact {0} occurs more than once")]
    DuplicateArtifact(SourceArtifactId),
    #[error("probe for source artifact {0} occurs more than once")]
    DuplicateProbe(SourceArtifactId),
    #[error("probe result for source artifact {0} is missing")]
    MissingProbe(SourceArtifactId),
    #[error("probe returned an unexpected source artifact {0}")]
    UnexpectedProbe(SourceArtifactId),
    #[error("probe result for source artifact {0} has no frames or duration")]
    EmptyProbe(SourceArtifactId),
    #[error("probe result for source artifact {0} has an invalid keyframe inventory")]
    InvalidKeyframeInventory(SourceArtifactId),
    #[error("source segment sequence must be non-empty and contiguous from index zero")]
    InvalidSegmentSequence,
    #[error("raw frame evidence is incomplete, discontinuous, or reports capture errors")]
    InvalidRawFrameEvidence,
    #[error("legacy v5 timing evidence must be complete and explicitly confirm reset PTS")]
    InvalidLegacyTimingEvidence,
    #[error("profile variant {variant:?} does not admit source codec {codec:?}")]
    ProfileSourceMismatch {
        variant: super::QualityVariant,
        codec: VideoCodec,
    },
    #[error("artifact {artifact} has codec {actual:?}, expected {expected:?}")]
    CodecMismatch {
        artifact: SourceArtifactId,
        expected: VideoCodec,
        actual: VideoCodec,
    },
    #[error("artifact {artifact} must contain exactly one video track and no audio track")]
    TrackLayoutMismatch { artifact: SourceArtifactId },
    #[error("artifact {artifact} frame rate differs from the session frame rate")]
    FrameRateMismatch { artifact: SourceArtifactId },
    #[error("paired source segment {segment_index} has mismatched eyes: {reason}")]
    PairedEyeMismatch { segment_index: u32, reason: String },
    #[error("declared frame evidence says {declared}, probe says {probed}")]
    FrameEvidenceMismatch { declared: u64, probed: u64 },
    #[error("legacy v5 segment {artifact} did not reset its PTS to zero")]
    LegacyPtsNotReset { artifact: SourceArtifactId },
    #[error("media plan arithmetic overflow")]
    ArithmeticOverflow,
    #[error(transparent)]
    Rational(#[from] RationalError),
    #[error(transparent)]
    Profile(#[from] ProfileError),
}

pub struct MediaPlanner;

impl MediaPlanner {
    pub fn plan(
        input: &NormalizationInput,
        probe_report: &ProbeReport,
        profile: &NormalizationProfile,
    ) -> Result<MediaPlan, MediaPlanError> {
        if !profile
            .quality_variant()
            .accepts_source_codec(input.source_codec())
        {
            return Err(MediaPlanError::ProfileSourceMismatch {
                variant: profile.quality_variant(),
                codec: input.source_codec(),
            });
        }

        validate_input_sequences(input)?;
        let probes = reconcile_probes(input, probe_report)?;
        validate_common_probe_contract(input, &probes)?;

        let first = probes
            .values()
            .next()
            .ok_or(MediaPlanError::InvalidSegmentSequence)?;
        let source_fps = first.frame_rate();
        let (runs, eye_dimensions, timing_basis, declared_total_frames) =
            build_runs(input, &probes, source_fps)?;
        let probed_total_frames = runs.iter().try_fold(0_u64, |total, run| {
            total
                .checked_add(run.frame_count)
                .ok_or(MediaPlanError::ArithmeticOverflow)
        })?;
        if let Some(declared) = declared_total_frames {
            if declared != probed_total_frames {
                return Err(MediaPlanError::FrameEvidenceMismatch {
                    declared,
                    probed: probed_total_frames,
                });
            }
        }

        let segment_frame_limit = profile.segment_frames(source_fps)?;
        let segment_pairs = partition_runs(
            &runs,
            input.kind(),
            eye_dimensions,
            source_fps,
            profile.time_base(),
            segment_frame_limit,
        )?;

        Ok(MediaPlan {
            source_kind: input.kind(),
            profile_revision: profile.profile_revision().clone(),
            source_fps,
            eye_dimensions,
            time_base: profile.time_base(),
            timing_basis,
            total_frames: probed_total_frames,
            segment_pairs,
        })
    }
}

#[derive(Debug, Clone)]
struct PairedRun<'a> {
    left: &'a ProbedArtifact,
    right: &'a ProbedArtifact,
    frame_count: u64,
}

fn reconcile_probes<'a>(
    input: &NormalizationInput,
    report: &'a ProbeReport,
) -> Result<BTreeMap<SourceArtifactId, &'a ProbedArtifact>, MediaPlanError> {
    let expected = input
        .artifacts()
        .into_iter()
        .map(|artifact| artifact.id().clone())
        .collect::<BTreeSet<_>>();
    if expected.len() != input.artifacts().len() {
        let mut seen = BTreeSet::new();
        let duplicate = input
            .artifacts()
            .into_iter()
            .map(|artifact| artifact.id().clone())
            .find(|id| !seen.insert(id.clone()))
            .expect("set length proved a duplicate");
        return Err(MediaPlanError::DuplicateArtifact(duplicate));
    }
    let actual = report
        .artifacts()
        .iter()
        .map(|artifact| (artifact.artifact_id().clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    if let Some(missing) = expected.iter().find(|id| !actual.contains_key(*id)) {
        return Err(MediaPlanError::MissingProbe(missing.clone()));
    }
    if let Some(unexpected) = actual.keys().find(|id| !expected.contains(*id)) {
        return Err(MediaPlanError::UnexpectedProbe(unexpected.clone()));
    }
    Ok(actual)
}

fn validate_common_probe_contract(
    input: &NormalizationInput,
    probes: &BTreeMap<SourceArtifactId, &ProbedArtifact>,
) -> Result<(), MediaPlanError> {
    let expected_codec = input.source_codec();
    let mut source_fps = None;
    for probe in probes.values() {
        if probe.codec() != expected_codec {
            return Err(MediaPlanError::CodecMismatch {
                artifact: probe.artifact_id().clone(),
                expected: expected_codec,
                actual: probe.codec(),
            });
        }
        if probe.video_track_count() != 1 || probe.audio_track_count() != 0 {
            return Err(MediaPlanError::TrackLayoutMismatch {
                artifact: probe.artifact_id().clone(),
            });
        }
        if source_fps.is_some_and(|fps| fps != probe.frame_rate()) {
            return Err(MediaPlanError::FrameRateMismatch {
                artifact: probe.artifact_id().clone(),
            });
        }
        source_fps = Some(probe.frame_rate());
    }
    Ok(())
}

fn build_runs<'a>(
    input: &NormalizationInput,
    probes: &BTreeMap<SourceArtifactId, &'a ProbedArtifact>,
    source_fps: Rational,
) -> Result<(Vec<PairedRun<'a>>, Dimensions, TimingBasis, Option<u64>), MediaPlanError> {
    match input {
        NormalizationInput::RawCaptureV2 {
            stereo,
            frame_evidence,
        } => {
            if frame_evidence.declared_source_fps() != source_fps {
                return Err(MediaPlanError::FrameRateMismatch {
                    artifact: stereo.id().clone(),
                });
            }
            let probe = probes[stereo.id()];
            let eye_dimensions = side_by_side_eye_dimensions(probe.dimensions())?;
            Ok((
                vec![PairedRun {
                    left: probe,
                    right: probe,
                    frame_count: probe.frame_count(),
                }],
                eye_dimensions,
                TimingBasis::RawFrameIndex,
                Some(frame_evidence.declared_frame_count()),
            ))
        }
        NormalizationInput::LegacyMjpegSessionV5 {
            segments,
            timing_evidence,
        } => {
            if timing_evidence.declared_source_fps() != source_fps {
                return Err(MediaPlanError::FrameRateMismatch {
                    artifact: segments[0].artifact().id().clone(),
                });
            }
            let mut runs = Vec::with_capacity(segments.len());
            let mut eye_dimensions = None;
            for segment in segments {
                let probe = probes[segment.artifact().id()];
                if probe.first_pts() != 0 {
                    return Err(MediaPlanError::LegacyPtsNotReset {
                        artifact: probe.artifact_id().clone(),
                    });
                }
                let dimensions = side_by_side_eye_dimensions(probe.dimensions())?;
                ensure_eye_dimensions(&mut eye_dimensions, dimensions, segment.segment_index())?;
                runs.push(PairedRun {
                    left: probe,
                    right: probe,
                    frame_count: probe.frame_count(),
                });
            }
            Ok((
                runs,
                eye_dimensions.expect("non-empty sequence was checked"),
                TimingBasis::LegacyV5ResetPtsAccumulated,
                Some(timing_evidence.declared_total_frames()),
            ))
        }
        NormalizationInput::ApplianceSpoolV6 { segments, .. } => {
            let (runs, dimensions) = side_by_side_runs(segments, probes)?;
            Ok((
                runs,
                dimensions,
                TimingBasis::CaptureCommitSegmentOrder,
                None,
            ))
        }
        NormalizationInput::UnsignedMjpegPublicationV1 { segments, .. } => {
            let (runs, dimensions) = side_by_side_runs(segments, probes)?;
            Ok((
                runs,
                dimensions,
                TimingBasis::UnsignedPublicationSideBySideOrder,
                None,
            ))
        }
        NormalizationInput::CompleteUnpublishedV6 { segments, .. } => {
            paired_eye_runs(segments, probes, TimingBasis::CompleteUnpublishedPairOrder)
        }
        NormalizationInput::PairedH264PublicationV1 { segments, .. } => {
            paired_eye_runs(segments, probes, TimingBasis::SignedPublicationPairOrder)
        }
        NormalizationInput::UnsignedPairedH264PublicationV1 { segments, .. } => {
            paired_eye_runs(segments, probes, TimingBasis::UnsignedPublicationPairOrder)
        }
    }
}

fn paired_eye_runs<'a>(
    segments: &[PairedSourceSegment],
    probes: &BTreeMap<SourceArtifactId, &'a ProbedArtifact>,
    timing_basis: TimingBasis,
) -> Result<(Vec<PairedRun<'a>>, Dimensions, TimingBasis, Option<u64>), MediaPlanError> {
    let mut runs = Vec::with_capacity(segments.len());
    let mut dimensions = None;
    for segment in segments {
        let left = probes[segment.left().id()];
        let right = probes[segment.right().id()];
        if left.dimensions() != right.dimensions()
            || left.frame_rate() != right.frame_rate()
            || left.frame_count() != right.frame_count()
        {
            return Err(MediaPlanError::PairedEyeMismatch {
                segment_index: segment.segment_index(),
                reason: "dimensions, frame rate, and frame count must match".to_string(),
            });
        }
        ensure_eye_dimensions(&mut dimensions, left.dimensions(), segment.segment_index())?;
        runs.push(PairedRun {
            left,
            right,
            frame_count: left.frame_count(),
        });
    }
    Ok((
        runs,
        dimensions.expect("non-empty sequence was checked"),
        timing_basis,
        None,
    ))
}

fn side_by_side_runs<'a>(
    segments: &[SourceSegment],
    probes: &BTreeMap<SourceArtifactId, &'a ProbedArtifact>,
) -> Result<(Vec<PairedRun<'a>>, Dimensions), MediaPlanError> {
    let mut runs = Vec::with_capacity(segments.len());
    let mut dimensions = None;
    for segment in segments {
        let probe = probes[segment.artifact().id()];
        let eye_dimensions = side_by_side_eye_dimensions(probe.dimensions())?;
        ensure_eye_dimensions(&mut dimensions, eye_dimensions, segment.segment_index())?;
        runs.push(PairedRun {
            left: probe,
            right: probe,
            frame_count: probe.frame_count(),
        });
    }
    Ok((runs, dimensions.expect("non-empty sequence was checked")))
}

fn ensure_eye_dimensions(
    expected: &mut Option<Dimensions>,
    actual: Dimensions,
    segment_index: u32,
) -> Result<(), MediaPlanError> {
    if expected.is_some_and(|dimensions| dimensions != actual) {
        return Err(MediaPlanError::PairedEyeMismatch {
            segment_index,
            reason: "eye dimensions change between segments".to_string(),
        });
    }
    *expected = Some(actual);
    Ok(())
}

fn side_by_side_eye_dimensions(source: Dimensions) -> Result<Dimensions, MediaPlanError> {
    if !source.width().is_multiple_of(2) {
        return Err(MediaPlanError::OddStereoWidth(source.width()));
    }
    Dimensions::new(source.width() / 2, source.height())
}

fn partition_runs(
    runs: &[PairedRun<'_>],
    source_kind: SourceMediaKind,
    eye_dimensions: Dimensions,
    source_fps: Rational,
    time_base: Rational,
    segment_frame_limit: u64,
) -> Result<Vec<SegmentPairPlan>, MediaPlanError> {
    if segment_frame_limit == 0 {
        return Err(MediaPlanError::ArithmeticOverflow);
    }
    let crop_left = Rect::new(0, 0, eye_dimensions.width(), eye_dimensions.height())?;
    let crop_right = Rect::new(
        eye_dimensions.width(),
        0,
        eye_dimensions.width(),
        eye_dimensions.height(),
    )?;
    let side_by_side = matches!(
        source_kind,
        SourceMediaKind::RawCaptureV2
            | SourceMediaKind::LegacyMjpegSessionV5
            | SourceMediaKind::ApplianceSpoolV6
            | SourceMediaKind::UnsignedMjpegPublicationV1
    );
    let total_frames = runs.iter().try_fold(0_u64, |total, run| {
        total
            .checked_add(run.frame_count)
            .ok_or(MediaPlanError::ArithmeticOverflow)
    })?;
    let mut pairs = Vec::new();
    let mut session_cursor = 0_u64;
    let mut run_index = 0_usize;
    let mut frame_in_run = 0_u64;

    while session_cursor < total_frames {
        let pair_frame_count = segment_frame_limit.min(total_frames - session_cursor);
        let pair_end = session_cursor
            .checked_add(pair_frame_count)
            .ok_or(MediaPlanError::ArithmeticOverflow)?;
        let mut left_slices = Vec::new();
        let mut right_slices = Vec::new();
        let mut slice_session_cursor = session_cursor;

        while slice_session_cursor < pair_end {
            let run = runs
                .get(run_index)
                .ok_or(MediaPlanError::ArithmeticOverflow)?;
            let available = run.frame_count - frame_in_run;
            let take = available.min(pair_end - slice_session_cursor);
            left_slices.push(make_slice(
                run.left,
                frame_in_run,
                take,
                slice_session_cursor,
                source_fps,
            )?);
            right_slices.push(make_slice(
                run.right,
                frame_in_run,
                take,
                slice_session_cursor,
                source_fps,
            )?);
            frame_in_run += take;
            slice_session_cursor += take;
            if frame_in_run == run.frame_count {
                run_index += 1;
                frame_in_run = 0;
            }
        }

        let segment_index =
            u32::try_from(pairs.len()).map_err(|_| MediaPlanError::ArithmeticOverflow)?;
        pairs.push(SegmentPairPlan {
            segment_index,
            first_frame: session_cursor,
            frame_count: pair_frame_count,
            start_ticks: source_fps.ticks_for_frames(session_cursor, time_base)?,
            duration_ticks: source_fps.ticks_for_frames(pair_frame_count, time_base)?,
            source_fps,
            eye_dimensions,
            left: EyeInputPlan {
                eye: Eye::Left,
                slices: left_slices,
                crop: side_by_side.then_some(crop_left),
            },
            right: EyeInputPlan {
                eye: Eye::Right,
                slices: right_slices,
                crop: side_by_side.then_some(crop_right),
            },
            left_output_relative_path: format!("video/pairs/{segment_index:05}/left.mp4"),
            right_output_relative_path: format!("video/pairs/{segment_index:05}/right.mp4"),
        });
        session_cursor = pair_end;
    }
    Ok(pairs)
}

fn make_slice(
    probe: &ProbedArtifact,
    first_frame_in_artifact: u64,
    frame_count: u64,
    session_first_frame: u64,
    source_fps: Rational,
) -> Result<FrameSlice, MediaPlanError> {
    let pts_offset = source_fps.ticks_for_frames(first_frame_in_artifact, probe.time_base())?;
    let pts_offset = i64::try_from(pts_offset).map_err(|_| MediaPlanError::ArithmeticOverflow)?;
    let source_pts_first = probe
        .first_pts()
        .checked_add(pts_offset)
        .ok_or(MediaPlanError::ArithmeticOverflow)?;
    Ok(FrameSlice {
        artifact_id: probe.artifact_id().clone(),
        first_frame_in_artifact,
        frame_count,
        source_pts_first,
        source_time_base: probe.time_base(),
        session_first_frame,
    })
}

fn validate_input_sequences(input: &NormalizationInput) -> Result<(), MediaPlanError> {
    match input {
        NormalizationInput::RawCaptureV2 { frame_evidence, .. } => {
            if frame_evidence.declared_frame_count == 0
                || !frame_evidence.jpeg_boundaries_verified
                || frame_evidence.sequence_gap_count != 0
                || frame_evidence.timestamp_error_count != 0
            {
                return Err(MediaPlanError::InvalidRawFrameEvidence);
            }
        }
        NormalizationInput::LegacyMjpegSessionV5 {
            segments,
            timing_evidence,
        } => {
            validate_segment_sequence(segments)?;
            if timing_evidence.declared_total_frames == 0 || !timing_evidence.segment_pts_reset {
                return Err(MediaPlanError::InvalidLegacyTimingEvidence);
            }
        }
        NormalizationInput::ApplianceSpoolV6 { segments, .. } => {
            validate_segment_sequence(segments)?;
        }
        NormalizationInput::UnsignedMjpegPublicationV1 { segments, .. } => {
            validate_segment_sequence(segments)?;
        }
        NormalizationInput::CompleteUnpublishedV6 { segments, .. }
        | NormalizationInput::PairedH264PublicationV1 { segments, .. }
        | NormalizationInput::UnsignedPairedH264PublicationV1 { segments, .. } => {
            validate_paired_segment_sequence(segments)?;
        }
    }
    Ok(())
}

fn validate_segment_sequence(segments: &[SourceSegment]) -> Result<(), MediaPlanError> {
    if segments.is_empty()
        || segments
            .iter()
            .enumerate()
            .any(|(index, segment)| usize::try_from(segment.segment_index()).ok() != Some(index))
    {
        return Err(MediaPlanError::InvalidSegmentSequence);
    }
    Ok(())
}

fn validate_paired_segment_sequence(
    segments: &[PairedSourceSegment],
) -> Result<(), MediaPlanError> {
    if segments.is_empty()
        || segments
            .iter()
            .enumerate()
            .any(|(index, segment)| usize::try_from(segment.segment_index()).ok() != Some(index))
    {
        return Err(MediaPlanError::InvalidSegmentSequence);
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), MediaPlanError> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains('\0')
        || Path::new(value).is_absolute()
        || Path::new(value).components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component.as_os_str().to_string_lossy().starts_with('.')
        })
    {
        Err(MediaPlanError::UnsafeRelativePath(value.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> ContentSha256 {
        ContentSha256::parse("a".repeat(64)).expect("digest")
    }

    fn artifact(id: &str) -> ResolvedSourceArtifact {
        ResolvedSourceArtifact::new(
            SourceArtifactId::parse(id).expect("id"),
            PathBuf::from(format!("/library/{id}.mp4")),
            format!("video/{id}.mp4"),
            1,
            digest(),
        )
        .expect("artifact")
    }

    fn probe(id: &str, frames: u64, first_pts: i64) -> ProbedArtifact {
        ProbedArtifact::new(
            SourceArtifactId::parse(id).expect("id"),
            VideoCodec::Mjpeg,
            None,
            ContainerFormat::FragmentedMp4,
            None,
            PixelFormat::Yuv422p,
            Dimensions::new(3840, 1080).expect("dimensions"),
            Rational::new(30, 1).expect("fps"),
            Rational::new(1, 90_000).expect("time base"),
            first_pts,
            frames,
            frames * 3_000,
            1,
            0,
            vec![0],
        )
        .expect("probe")
    }

    #[test]
    fn legacy_v5_reset_pts_are_accumulated_into_one_session_timeline() {
        let segments = vec![
            SourceSegment::new(0, artifact("segment-0")),
            SourceSegment::new(1, artifact("segment-1")),
        ];
        let input = NormalizationInput::legacy_mjpeg_session_v5(
            segments,
            LegacyTimingEvidence::new(digest(), 1_200, Rational::new(30, 1).expect("fps"), true)
                .expect("evidence"),
        )
        .expect("input");
        let probes = ProbeReport::new(vec![probe("segment-0", 600, 0), probe("segment-1", 600, 0)])
            .expect("probes");
        let profile = NormalizationProfile::candidate_mjpeg_x265_slow_v1().expect("profile");
        let plan = MediaPlanner::plan(&input, &probes, &profile).expect("plan");

        assert_eq!(
            plan.timing_basis(),
            TimingBasis::LegacyV5ResetPtsAccumulated
        );
        assert_eq!(plan.segment_pairs().len(), 2);
        assert_eq!(plan.segment_pairs()[0].frame_count(), 900);
        assert_eq!(plan.segment_pairs()[1].first_frame(), 900);
        assert_eq!(plan.segment_pairs()[1].start_ticks(), 2_700_000);
        assert_eq!(plan.segment_pairs()[1].frame_count(), 300);
    }

    #[test]
    fn unknown_probe_artifacts_fail_closed() {
        let input = NormalizationInput::raw_capture_v2(
            artifact("raw"),
            RawFrameEvidence::new(30, Rational::new(30, 1).expect("fps"), true, 0, 0)
                .expect("evidence"),
        );
        let probes = ProbeReport::new(vec![probe("other", 30, 0)]).expect("probes");
        let profile = NormalizationProfile::candidate_mjpeg_x265_slow_v1().expect("profile");
        assert!(matches!(
            MediaPlanner::plan(&input, &probes, &profile),
            Err(MediaPlanError::MissingProbe(_))
        ));
    }
}
