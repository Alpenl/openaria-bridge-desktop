use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::identity::{ContentSha256, ProfileRevision};
use super::plan::{Dimensions, Eye, SegmentPairPlan};
use super::profile::{
    ContainerFormat, HevcProfile, NormalizationProfile, PixelFormat, SampleEntry, VideoCodec,
};
use super::rational::Rational;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationIssueCode {
    WrongEye,
    WrongProfileRevision,
    WrongOutputPath,
    EmptyOutput,
    CodecMismatch,
    CodecProfileMismatch,
    ContainerMismatch,
    SampleEntryMismatch,
    PixelFormatMismatch,
    GeometryMismatch,
    FrameRateMismatch,
    TimeBaseMismatch,
    FrameCountMismatch,
    DurationMismatch,
    ExtraTrack,
    FirstFrameNotDecodable,
    OpenGop,
    GopTooLong,
    SceneCutKeyframe,
    FullDecodeFailed,
    DecodeFrameCountMismatch,
    StereoFrameCountMismatch,
    StereoDurationMismatch,
    StereoKeyframeMismatch,
    VmafMeanBelowThreshold,
    VmafFrameP01BelowThreshold,
    SsimMeanBelowThreshold,
    StereoDomainMetricFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    code: ValidationIssueCode,
    eye: Option<Eye>,
    detail: String,
}

impl ValidationIssue {
    fn new(code: ValidationIssueCode, eye: Option<Eye>, detail: impl Into<String>) -> Self {
        let detail = sanitize_detail(&detail.into());
        Self { code, eye, detail }
    }

    #[must_use]
    pub fn code(&self) -> ValidationIssueCode {
        self.code
    }

    #[must_use]
    pub fn eye(&self) -> Option<Eye> {
        self.eye
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputMediaEvidence {
    eye: Eye,
    partial_path: PathBuf,
    manifest_relative_path: String,
    profile_revision: ProfileRevision,
    size_bytes: u64,
    sha256: ContentSha256,
    codec: VideoCodec,
    codec_profile: HevcProfile,
    container: ContainerFormat,
    sample_entry: SampleEntry,
    pixel_format: PixelFormat,
    dimensions: Dimensions,
    frame_rate: Rational,
    time_base: Rational,
    frame_count: u64,
    duration_ticks: u64,
    video_track_count: u8,
    audio_track_count: u8,
    first_frame_decodable: bool,
    closed_gop: bool,
    scene_cut_keyframes_detected: bool,
    keyframe_frames: Vec<u64>,
    fully_decoded: bool,
    decoded_frame_count: u64,
}

impl OutputMediaEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        eye: Eye,
        partial_path: PathBuf,
        manifest_relative_path: impl Into<String>,
        profile_revision: ProfileRevision,
        size_bytes: u64,
        sha256: ContentSha256,
        codec: VideoCodec,
        codec_profile: HevcProfile,
        container: ContainerFormat,
        sample_entry: SampleEntry,
        pixel_format: PixelFormat,
        dimensions: Dimensions,
        frame_rate: Rational,
        time_base: Rational,
        frame_count: u64,
        duration_ticks: u64,
        video_track_count: u8,
        audio_track_count: u8,
        first_frame_decodable: bool,
        closed_gop: bool,
        scene_cut_keyframes_detected: bool,
        keyframe_frames: Vec<u64>,
        fully_decoded: bool,
        decoded_frame_count: u64,
    ) -> Result<Self, ValidationError> {
        let manifest_relative_path = manifest_relative_path.into();
        validate_relative_path(&manifest_relative_path)?;
        if partial_path.as_os_str().is_empty() {
            return Err(ValidationError::InvalidPartialPath);
        }
        if keyframe_frames
            .windows(2)
            .any(|window| window[0] >= window[1])
        {
            return Err(ValidationError::InvalidKeyframeInventory);
        }
        Ok(Self {
            eye,
            partial_path,
            manifest_relative_path,
            profile_revision,
            size_bytes,
            sha256,
            codec,
            codec_profile,
            container,
            sample_entry,
            pixel_format,
            dimensions,
            frame_rate,
            time_base,
            frame_count,
            duration_ticks,
            video_track_count,
            audio_track_count,
            first_frame_decodable,
            closed_gop,
            scene_cut_keyframes_detected,
            keyframe_frames,
            fully_decoded,
            decoded_frame_count,
        })
    }

    #[must_use]
    pub fn eye(&self) -> Eye {
        self.eye
    }

    #[must_use]
    pub fn partial_path(&self) -> &Path {
        &self.partial_path
    }

    #[must_use]
    pub fn manifest_relative_path(&self) -> &str {
        &self.manifest_relative_path
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &ContentSha256 {
        &self.sha256
    }

    #[must_use]
    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    #[must_use]
    pub fn codec_profile(&self) -> HevcProfile {
        self.codec_profile
    }

    #[must_use]
    pub fn container(&self) -> ContainerFormat {
        self.container
    }

    #[must_use]
    pub fn sample_entry(&self) -> SampleEntry {
        self.sample_entry
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
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    #[must_use]
    pub fn duration_ticks(&self) -> u64 {
        self.duration_ticks
    }

    #[must_use]
    pub fn keyframe_frames(&self) -> &[u64] {
        &self.keyframe_frames
    }

    #[must_use]
    pub fn fully_decoded(&self) -> bool {
        self.fully_decoded
    }

    #[must_use]
    pub fn decoded_frame_count(&self) -> u64 {
        self.decoded_frame_count
    }
}

/// Fixed-point quality metrics. Scores use thousandths for VMAF and
/// millionths for SSIM so canonical manifests never depend on float JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityEvidence {
    eye: Eye,
    vmaf_neg_model: String,
    vmaf_mean_milli: u32,
    vmaf_frame_p01_milli: u32,
    ssim_mean_millionths: u32,
    stereo_domain_metrics_passed: bool,
    report_digest: ContentSha256,
}

impl QualityEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        eye: Eye,
        vmaf_neg_model: impl Into<String>,
        vmaf_mean_milli: u32,
        vmaf_frame_p01_milli: u32,
        ssim_mean_millionths: u32,
        stereo_domain_metrics_passed: bool,
        report_digest: ContentSha256,
    ) -> Result<Self, ValidationError> {
        let vmaf_neg_model = vmaf_neg_model.into();
        if vmaf_neg_model.is_empty()
            || vmaf_neg_model.len() > 256
            || vmaf_neg_model.chars().any(char::is_control)
            || vmaf_mean_milli > 100_000
            || vmaf_frame_p01_milli > 100_000
            || ssim_mean_millionths > 1_000_000
        {
            return Err(ValidationError::InvalidQualityEvidence);
        }
        Ok(Self {
            eye,
            vmaf_neg_model,
            vmaf_mean_milli,
            vmaf_frame_p01_milli,
            ssim_mean_millionths,
            stereo_domain_metrics_passed,
            report_digest,
        })
    }

    #[must_use]
    pub fn eye(&self) -> Eye {
        self.eye
    }

    #[must_use]
    pub fn vmaf_neg_model(&self) -> &str {
        &self.vmaf_neg_model
    }

    #[must_use]
    pub fn vmaf_mean_milli(&self) -> u32 {
        self.vmaf_mean_milli
    }

    #[must_use]
    pub fn vmaf_frame_p01_milli(&self) -> u32 {
        self.vmaf_frame_p01_milli
    }

    #[must_use]
    pub fn ssim_mean_millionths(&self) -> u32 {
        self.ssim_mean_millionths
    }

    #[must_use]
    pub fn stereo_domain_metrics_passed(&self) -> bool {
        self.stereo_domain_metrics_passed
    }

    #[must_use]
    pub fn report_digest(&self) -> &ContentSha256 {
        &self.report_digest
    }
}

macro_rules! verdict {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name {
            passed: bool,
            issues: Vec<ValidationIssue>,
        }

        impl $name {
            fn from_issues(issues: Vec<ValidationIssue>) -> Self {
                Self {
                    passed: issues.is_empty(),
                    issues,
                }
            }

            #[must_use]
            pub fn passed(&self) -> bool {
                self.passed
            }

            #[must_use]
            pub fn issues(&self) -> &[ValidationIssue] {
                &self.issues
            }
        }
    };
}

verdict!(StructuralVerdict);
verdict!(FullDecodeVerdict);
verdict!(StereoSyncVerdict);
verdict!(QualityVerdict);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("partial output path must not be empty")]
    InvalidPartialPath,
    #[error("manifest-relative output path is unsafe: {0:?}")]
    UnsafeRelativePath(String),
    #[error("keyframe inventory must be strictly increasing")]
    InvalidKeyframeInventory,
    #[error("validation evidence must contain exactly one left and one right eye")]
    InvalidEyePair,
    #[error("quality evidence contains an invalid model name or metric value")]
    InvalidQualityEvidence,
    #[error("segment validation failed and cannot become a reusable checkpoint")]
    VerdictFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentValidationReport {
    segment_index: u32,
    left: OutputMediaEvidence,
    right: OutputMediaEvidence,
    left_quality: QualityEvidence,
    right_quality: QualityEvidence,
    structural: StructuralVerdict,
    full_decode: FullDecodeVerdict,
    sync: StereoSyncVerdict,
    quality: QualityVerdict,
}

impl SegmentValidationReport {
    pub fn evaluate(
        plan: &SegmentPairPlan,
        profile: &NormalizationProfile,
        left: OutputMediaEvidence,
        right: OutputMediaEvidence,
        left_quality: QualityEvidence,
        right_quality: QualityEvidence,
    ) -> Result<Self, ValidationError> {
        if left.eye() != Eye::Left
            || right.eye() != Eye::Right
            || left_quality.eye() != Eye::Left
            || right_quality.eye() != Eye::Right
        {
            return Err(ValidationError::InvalidEyePair);
        }

        let mut structural_issues = Vec::new();
        validate_output_structure(plan, profile, &left, Eye::Left, &mut structural_issues);
        validate_output_structure(plan, profile, &right, Eye::Right, &mut structural_issues);

        let mut decode_issues = Vec::new();
        validate_full_decode(plan, &left, &mut decode_issues);
        validate_full_decode(plan, &right, &mut decode_issues);

        let mut sync_issues = Vec::new();
        if left.frame_count != right.frame_count {
            sync_issues.push(ValidationIssue::new(
                ValidationIssueCode::StereoFrameCountMismatch,
                None,
                "left and right frame counts differ",
            ));
        }
        let frame_ticks = profile
            .time_base()
            .denominator()
            .checked_div(plan.frame_count().min(u64::from(u32::MAX)) as u32)
            .unwrap_or(0);
        let duration_delta = left.duration_ticks.abs_diff(right.duration_ticks);
        let one_frame_ticks = plan
            .duration_ticks()
            .checked_div(plan.frame_count())
            .unwrap_or(u64::from(frame_ticks));
        if duration_delta > one_frame_ticks {
            sync_issues.push(ValidationIssue::new(
                ValidationIssueCode::StereoDurationMismatch,
                None,
                format!("left/right duration delta is {duration_delta} ticks"),
            ));
        }
        if left.keyframe_frames != right.keyframe_frames {
            sync_issues.push(ValidationIssue::new(
                ValidationIssueCode::StereoKeyframeMismatch,
                None,
                "left and right keyframe positions differ",
            ));
        }

        let mut quality_issues = Vec::new();
        validate_quality(profile, &left_quality, &mut quality_issues);
        validate_quality(profile, &right_quality, &mut quality_issues);

        Ok(Self {
            segment_index: plan.segment_index(),
            left,
            right,
            left_quality,
            right_quality,
            structural: StructuralVerdict::from_issues(structural_issues),
            full_decode: FullDecodeVerdict::from_issues(decode_issues),
            sync: StereoSyncVerdict::from_issues(sync_issues),
            quality: QualityVerdict::from_issues(quality_issues),
        })
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn left(&self) -> &OutputMediaEvidence {
        &self.left
    }

    #[must_use]
    pub fn right(&self) -> &OutputMediaEvidence {
        &self.right
    }

    #[must_use]
    pub fn left_quality(&self) -> &QualityEvidence {
        &self.left_quality
    }

    #[must_use]
    pub fn right_quality(&self) -> &QualityEvidence {
        &self.right_quality
    }

    #[must_use]
    pub fn structural(&self) -> &StructuralVerdict {
        &self.structural
    }

    #[must_use]
    pub fn full_decode(&self) -> &FullDecodeVerdict {
        &self.full_decode
    }

    #[must_use]
    pub fn sync(&self) -> &StereoSyncVerdict {
        &self.sync
    }

    #[must_use]
    pub fn quality(&self) -> &QualityVerdict {
        &self.quality
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.structural.passed()
            && self.full_decode.passed()
            && self.sync.passed()
            && self.quality.passed()
    }
}

/// Proof that both eyes of one pair passed every gate. There is no
/// constructor accepting individual eyes, so a half-pair cannot become a
/// durable checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedSegmentPair {
    report: SegmentValidationReport,
}

impl ValidatedSegmentPair {
    pub fn try_from_report(report: SegmentValidationReport) -> Result<Self, ValidationError> {
        if report.passed() {
            Ok(Self { report })
        } else {
            Err(ValidationError::VerdictFailed)
        }
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.report.segment_index()
    }

    #[must_use]
    pub fn report(&self) -> &SegmentValidationReport {
        &self.report
    }

    #[must_use]
    pub fn into_report(self) -> SegmentValidationReport {
        self.report
    }
}

fn validate_output_structure(
    plan: &SegmentPairPlan,
    profile: &NormalizationProfile,
    output: &OutputMediaEvidence,
    eye: Eye,
    issues: &mut Vec<ValidationIssue>,
) {
    let mut check = |condition: bool, code: ValidationIssueCode, detail: &'static str| {
        if !condition {
            issues.push(ValidationIssue::new(code, Some(eye), detail));
        }
    };
    check(
        output.eye == eye,
        ValidationIssueCode::WrongEye,
        "wrong eye role",
    );
    check(
        output.profile_revision == *profile.profile_revision(),
        ValidationIssueCode::WrongProfileRevision,
        "output profile revision differs from the plan",
    );
    check(
        output.manifest_relative_path == plan.output_relative_path(eye),
        ValidationIssueCode::WrongOutputPath,
        "output relative path differs from the paired plan",
    );
    check(
        output.size_bytes > 0,
        ValidationIssueCode::EmptyOutput,
        "output is empty",
    );
    check(
        output.codec == profile.codec(),
        ValidationIssueCode::CodecMismatch,
        "output codec differs from profile",
    );
    check(
        output.codec_profile == profile.codec_profile(),
        ValidationIssueCode::CodecProfileMismatch,
        "output codec profile differs from profile",
    );
    check(
        output.container == profile.container(),
        ValidationIssueCode::ContainerMismatch,
        "output container differs from profile",
    );
    check(
        output.sample_entry == profile.sample_entry(),
        ValidationIssueCode::SampleEntryMismatch,
        "output sample entry is not hvc1",
    );
    check(
        output.pixel_format == profile.pixel_format(),
        ValidationIssueCode::PixelFormatMismatch,
        "output pixel format differs from profile",
    );
    check(
        output.dimensions == plan.eye_dimensions(),
        ValidationIssueCode::GeometryMismatch,
        "output dimensions differ from the eye plan",
    );
    check(
        output.frame_count == plan.frame_count(),
        ValidationIssueCode::FrameCountMismatch,
        "output frame count differs from source plan",
    );
    check(
        output.duration_ticks.abs_diff(plan.duration_ticks())
            <= plan
                .duration_ticks()
                .checked_div(plan.frame_count())
                .unwrap_or(0)
                .saturating_add(900),
        ValidationIssueCode::DurationMismatch,
        "output duration differs by more than one frame plus 10ms",
    );
    check(
        output.video_track_count == 1 && output.audio_track_count == 0,
        ValidationIssueCode::ExtraTrack,
        "output must contain one video track and no audio",
    );
    check(
        output.first_frame_decodable,
        ValidationIssueCode::FirstFrameNotDecodable,
        "first frame is not independently decodable",
    );
    check(
        output.closed_gop,
        ValidationIssueCode::OpenGop,
        "output contains an open GOP",
    );
    check(
        !output.scene_cut_keyframes_detected,
        ValidationIssueCode::SceneCutKeyframe,
        "scene-cut introduced an unplanned keyframe",
    );
    let gop_limit = profile.gop_frames(output.frame_rate).unwrap_or(0);
    let gaps_ok = output.keyframe_frames.first() == Some(&0)
        && output
            .keyframe_frames
            .windows(2)
            .all(|window| window[1] - window[0] == gop_limit)
        && output
            .keyframe_frames
            .last()
            .is_some_and(|last| output.frame_count.saturating_sub(*last) <= gop_limit);
    check(
        gaps_ok,
        ValidationIssueCode::GopTooLong,
        "keyframe inventory violates the fixed GOP",
    );
    check(
        output.frame_rate == plan.source_fps(),
        ValidationIssueCode::FrameRateMismatch,
        "output frame rate is invalid",
    );
    check(
        output.time_base == profile.time_base(),
        ValidationIssueCode::TimeBaseMismatch,
        "output time base is not 1/90000",
    );
}

fn validate_full_decode(
    plan: &SegmentPairPlan,
    output: &OutputMediaEvidence,
    issues: &mut Vec<ValidationIssue>,
) {
    if !output.fully_decoded {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::FullDecodeFailed,
            Some(output.eye),
            "full decode under fail-on-error mode did not complete",
        ));
    }
    if output.decoded_frame_count != plan.frame_count() {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::DecodeFrameCountMismatch,
            Some(output.eye),
            "decoded frame count differs from the source plan",
        ));
    }
}

fn validate_quality(
    profile: &NormalizationProfile,
    quality: &QualityEvidence,
    issues: &mut Vec<ValidationIssue>,
) {
    let thresholds = profile.quality_thresholds();
    if quality.vmaf_neg_model != thresholds.vmaf_neg_model() {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::VmafMeanBelowThreshold,
            Some(quality.eye),
            "VMAF NEG model version differs from the exact profile",
        ));
    }
    if quality.vmaf_mean_milli < thresholds.vmaf_mean_milli_min() {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::VmafMeanBelowThreshold,
            Some(quality.eye),
            "VMAF mean is below the profile threshold",
        ));
    }
    if quality.vmaf_frame_p01_milli < thresholds.vmaf_frame_p01_milli_min() {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::VmafFrameP01BelowThreshold,
            Some(quality.eye),
            "VMAF frame 1st percentile is below the profile threshold",
        ));
    }
    if quality.ssim_mean_millionths < thresholds.ssim_mean_millionths_min() {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::SsimMeanBelowThreshold,
            Some(quality.eye),
            "SSIM mean is below the profile threshold",
        ));
    }
    if thresholds.stereo_domain_metrics_required() && !quality.stereo_domain_metrics_passed {
        issues.push(ValidationIssue::new(
            ValidationIssueCode::StereoDomainMetricFailed,
            Some(quality.eye),
            "stereo/CV domain metrics did not pass",
        ));
    }
}

fn validate_relative_path(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains('\0')
        || Path::new(value).is_absolute()
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(ValidationError::UnsafeRelativePath(value.to_string()))
    } else {
        Ok(())
    }
}

fn sanitize_detail(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(1_024)
        .collect()
}
