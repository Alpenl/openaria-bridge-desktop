use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::identity::{canonical_json, EncoderBuildFingerprint, IdentityError, ProfileRevision};
use super::rational::{Rational, RationalError};
use super::SourceManifestDigest;

pub const PROFILE_SCHEMA_VERSION: u32 = 1;
pub const HEVC_PROFILE_FAMILY_V1: &str = "hevc-main-cfr-sourcefps-gop2s-x265-slow-v1";
pub const X265_SOFTWARE_COMPATIBILITY_V1: &str = "x265-software-hevc-main-8bit-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    Mjpeg,
    H264,
    Hevc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HevcProfile {
    Main,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PixelFormat {
    Yuv420p,
    Yuv422p,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFormat {
    MjpegElementary,
    Mp4,
    FragmentedMp4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleEntry {
    Hvc1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityVariant {
    MjpegCrf20,
    H264Crf18,
    H264Crf16Retry,
}

impl QualityVariant {
    #[must_use]
    pub fn crf(self) -> u8 {
        match self {
            Self::MjpegCrf20 => 20,
            Self::H264Crf18 => 18,
            Self::H264Crf16Retry => 16,
        }
    }

    #[must_use]
    pub fn generation(self) -> TranscodeGeneration {
        match self {
            Self::MjpegCrf20 => TranscodeGeneration::FirstGeneration,
            Self::H264Crf18 => TranscodeGeneration::SecondGeneration,
            Self::H264Crf16Retry => TranscodeGeneration::SecondGenerationRetry,
        }
    }

    #[must_use]
    pub fn accepts_source_codec(self, codec: VideoCodec) -> bool {
        match self {
            Self::MjpegCrf20 => codec == VideoCodec::Mjpeg,
            Self::H264Crf18 | Self::H264Crf16Retry => codec == VideoCodec::H264,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscodeGeneration {
    FirstGeneration,
    SecondGeneration,
    SecondGenerationRetry,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EncoderCompatibilityClass(String);

impl EncoderCompatibilityClass {
    #[must_use]
    pub fn x265_software_v1() -> Self {
        Self(X265_SOFTWARE_COMPATIBILITY_V1.to_string())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ProfileError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(value))
        } else {
            Err(ProfileError::InvalidField {
                field: "encoder_compatibility_class",
                reason: "expected 1-128 lowercase ASCII letters, digits, or hyphens".to_string(),
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The exact encoder binary/build selected for one derivation attempt.
///
/// Compatibility decides whether the build may implement a profile. The
/// fingerprint still enters the derived manifest, so compatible builds may
/// produce different (honestly identified) derived revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderBuild {
    implementation: String,
    version: String,
    build_fingerprint: EncoderBuildFingerprint,
    compatibility_class: EncoderCompatibilityClass,
    build_parameters: BTreeMap<String, String>,
}

impl EncoderBuild {
    pub fn new(
        implementation: impl Into<String>,
        version: impl Into<String>,
        build_fingerprint: EncoderBuildFingerprint,
        compatibility_class: EncoderCompatibilityClass,
        build_parameters: BTreeMap<String, String>,
    ) -> Result<Self, ProfileError> {
        let implementation = implementation.into();
        let version = version.into();
        validate_bounded_text("encoder_implementation", &implementation, 128)?;
        validate_bounded_text("encoder_version", &version, 256)?;
        if build_parameters.len() > 64
            || build_parameters.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 128
                    || value.is_empty()
                    || value.len() > 512
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
        {
            return Err(ProfileError::InvalidField {
                field: "encoder_build_parameters",
                reason: "at most 64 bounded, non-control key/value pairs are allowed".to_string(),
            });
        }
        Ok(Self {
            implementation,
            version,
            build_fingerprint,
            compatibility_class,
            build_parameters,
        })
    }

    #[must_use]
    pub fn implementation(&self) -> &str {
        &self.implementation
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn build_fingerprint(&self) -> &EncoderBuildFingerprint {
        &self.build_fingerprint
    }

    #[must_use]
    pub fn compatibility_class(&self) -> &EncoderCompatibilityClass {
        &self.compatibility_class
    }

    #[must_use]
    pub fn build_parameters(&self) -> &BTreeMap<String, String> {
        &self.build_parameters
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityThresholds {
    vmaf_neg_model: String,
    vmaf_mean_milli_min: u32,
    vmaf_frame_p01_milli_min: u32,
    ssim_mean_millionths_min: u32,
    h264_corpus_size_ratio_basis_points_max: Option<u16>,
    stereo_domain_metrics_required: bool,
}

impl QualityThresholds {
    #[must_use]
    pub fn proposed_v1(variant: QualityVariant) -> Self {
        Self {
            vmaf_neg_model: "vmaf_v0.6.1neg".to_string(),
            vmaf_mean_milli_min: 95_000,
            vmaf_frame_p01_milli_min: 90_000,
            ssim_mean_millionths_min: 990_000,
            h264_corpus_size_ratio_basis_points_max: match variant {
                QualityVariant::MjpegCrf20 => None,
                QualityVariant::H264Crf18 | QualityVariant::H264Crf16Retry => Some(6_500),
            },
            stereo_domain_metrics_required: true,
        }
    }

    #[must_use]
    pub fn vmaf_neg_model(&self) -> &str {
        &self.vmaf_neg_model
    }

    #[must_use]
    pub fn vmaf_mean_milli_min(&self) -> u32 {
        self.vmaf_mean_milli_min
    }

    #[must_use]
    pub fn vmaf_frame_p01_milli_min(&self) -> u32 {
        self.vmaf_frame_p01_milli_min
    }

    #[must_use]
    pub fn ssim_mean_millionths_min(&self) -> u32 {
        self.ssim_mean_millionths_min
    }

    #[must_use]
    pub fn h264_corpus_size_ratio_basis_points_max(&self) -> Option<u16> {
        self.h264_corpus_size_ratio_basis_points_max
    }

    #[must_use]
    pub fn stereo_domain_metrics_required(&self) -> bool {
        self.stereo_domain_metrics_required
    }
}

/// Review receipts required to turn an exact candidate profile into an
/// approved production profile. Digests bind external benchmark/legal
/// reports; booleans or UI flags are intentionally insufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileApprovalEvidence {
    profile_revision: ProfileRevision,
    quality_corpus_report: SourceManifestDigest,
    throughput_resource_report: SourceManifestDigest,
    stereo_cv_report: SourceManifestDigest,
    encoder_distribution_legal_review: SourceManifestDigest,
    playback_compatibility_report: SourceManifestDigest,
    approved_at: String,
}

impl ProfileApprovalEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_revision: ProfileRevision,
        quality_corpus_report: SourceManifestDigest,
        throughput_resource_report: SourceManifestDigest,
        stereo_cv_report: SourceManifestDigest,
        encoder_distribution_legal_review: SourceManifestDigest,
        playback_compatibility_report: SourceManifestDigest,
        approved_at: impl Into<String>,
    ) -> Result<Self, ProfileError> {
        let approved_at = approved_at.into();
        validate_bounded_text("profile_approved_at", &approved_at, 128)?;
        Ok(Self {
            profile_revision,
            quality_corpus_report,
            throughput_resource_report,
            stereo_cv_report,
            encoder_distribution_legal_review,
            playback_compatibility_report,
            approved_at,
        })
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProfileReleaseStatus {
    CandidateUnapproved,
    Approved { evidence: ProfileApprovalEvidence },
}

impl ProfileReleaseStatus {
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("profile remains a candidate and is not approved for derived commit or upload")]
    CandidateUnapproved,
    #[error("approval evidence targets {evidence}, but this profile is {profile}")]
    ApprovalRevisionMismatch {
        profile: ProfileRevision,
        evidence: ProfileRevision,
    },
    #[error("encoder compatibility class {actual:?} cannot implement required class {required:?}")]
    IncompatibleEncoder { required: String, actual: String },
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Rational(#[from] RationalError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProfileRevisionMaterial {
    schema_version: u32,
    family_id: String,
    quality_variant: QualityVariant,
    transcode_generation: TranscodeGeneration,
    codec: VideoCodec,
    codec_profile: HevcProfile,
    pixel_format: PixelFormat,
    container: ContainerFormat,
    sample_entry: SampleEntry,
    preset: String,
    crf: u8,
    time_base: Rational,
    gop_seconds: u32,
    segment_seconds: u32,
    closed_gop: bool,
    scene_cut_keyframes: bool,
    preserve_source_fps: bool,
    preserve_eye_dimensions: bool,
    audio_tracks: u8,
    encoder_compatibility_class: EncoderCompatibilityClass,
    quality_thresholds: QualityThresholds,
}

/// An exact, immutable normalization profile plus a separate release gate.
/// Approval is intentionally excluded from the revision hash: approving a
/// byte-identical candidate does not silently rename its encoding contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationProfile {
    revision_material: ProfileRevisionMaterial,
    profile_revision: ProfileRevision,
    release_status: ProfileReleaseStatus,
}

impl NormalizationProfile {
    pub fn candidate_mjpeg_x265_slow_v1() -> Result<Self, ProfileError> {
        Self::candidate(QualityVariant::MjpegCrf20)
    }

    pub fn candidate_h264_x265_slow_v1() -> Result<Self, ProfileError> {
        Self::candidate(QualityVariant::H264Crf18)
    }

    pub fn candidate_h264_crf16_retry_x265_slow_v1() -> Result<Self, ProfileError> {
        Self::candidate(QualityVariant::H264Crf16Retry)
    }

    pub fn candidate(quality_variant: QualityVariant) -> Result<Self, ProfileError> {
        let revision_material = ProfileRevisionMaterial {
            schema_version: PROFILE_SCHEMA_VERSION,
            family_id: HEVC_PROFILE_FAMILY_V1.to_string(),
            quality_variant,
            transcode_generation: quality_variant.generation(),
            codec: VideoCodec::Hevc,
            codec_profile: HevcProfile::Main,
            pixel_format: PixelFormat::Yuv420p,
            container: ContainerFormat::Mp4,
            sample_entry: SampleEntry::Hvc1,
            preset: "slow".to_string(),
            crf: quality_variant.crf(),
            time_base: Rational::new(1, 90_000)?,
            gop_seconds: 2,
            segment_seconds: 30,
            closed_gop: true,
            scene_cut_keyframes: false,
            preserve_source_fps: true,
            preserve_eye_dimensions: true,
            audio_tracks: 0,
            encoder_compatibility_class: EncoderCompatibilityClass::x265_software_v1(),
            quality_thresholds: QualityThresholds::proposed_v1(quality_variant),
        };
        let profile_revision =
            ProfileRevision::from_canonical_bytes(&canonical_json(&revision_material)?);
        Ok(Self {
            revision_material,
            profile_revision,
            release_status: ProfileReleaseStatus::CandidateUnapproved,
        })
    }

    pub fn approve(mut self, evidence: ProfileApprovalEvidence) -> Result<Self, ProfileError> {
        if evidence.profile_revision() != &self.profile_revision {
            return Err(ProfileError::ApprovalRevisionMismatch {
                profile: self.profile_revision.clone(),
                evidence: evidence.profile_revision().clone(),
            });
        }
        self.release_status = ProfileReleaseStatus::Approved { evidence };
        Ok(self)
    }

    pub fn require_approved(&self) -> Result<(), ProfileError> {
        if self.release_status.is_approved() {
            Ok(())
        } else {
            Err(ProfileError::CandidateUnapproved)
        }
    }

    pub fn require_compatible_encoder(&self, build: &EncoderBuild) -> Result<(), ProfileError> {
        if build.compatibility_class() == self.encoder_compatibility_class() {
            Ok(())
        } else {
            Err(ProfileError::IncompatibleEncoder {
                required: self.encoder_compatibility_class().as_str().to_string(),
                actual: build.compatibility_class().as_str().to_string(),
            })
        }
    }

    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.revision_material.schema_version
    }

    #[must_use]
    pub fn family_id(&self) -> &str {
        &self.revision_material.family_id
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }

    #[must_use]
    pub fn release_status(&self) -> &ProfileReleaseStatus {
        &self.release_status
    }

    #[must_use]
    pub fn quality_variant(&self) -> QualityVariant {
        self.revision_material.quality_variant
    }

    #[must_use]
    pub fn transcode_generation(&self) -> TranscodeGeneration {
        self.revision_material.transcode_generation
    }

    #[must_use]
    pub fn codec(&self) -> VideoCodec {
        self.revision_material.codec
    }

    #[must_use]
    pub fn codec_profile(&self) -> HevcProfile {
        self.revision_material.codec_profile
    }

    #[must_use]
    pub fn pixel_format(&self) -> PixelFormat {
        self.revision_material.pixel_format
    }

    #[must_use]
    pub fn container(&self) -> ContainerFormat {
        self.revision_material.container
    }

    #[must_use]
    pub fn sample_entry(&self) -> SampleEntry {
        self.revision_material.sample_entry
    }

    #[must_use]
    pub fn preset(&self) -> &str {
        &self.revision_material.preset
    }

    #[must_use]
    pub fn crf(&self) -> u8 {
        self.revision_material.crf
    }

    #[must_use]
    pub fn time_base(&self) -> Rational {
        self.revision_material.time_base
    }

    #[must_use]
    pub fn gop_seconds(&self) -> u32 {
        self.revision_material.gop_seconds
    }

    #[must_use]
    pub fn segment_seconds(&self) -> u32 {
        self.revision_material.segment_seconds
    }

    #[must_use]
    pub fn closed_gop(&self) -> bool {
        self.revision_material.closed_gop
    }

    #[must_use]
    pub fn scene_cut_keyframes(&self) -> bool {
        self.revision_material.scene_cut_keyframes
    }

    #[must_use]
    pub fn encoder_compatibility_class(&self) -> &EncoderCompatibilityClass {
        &self.revision_material.encoder_compatibility_class
    }

    #[must_use]
    pub fn quality_thresholds(&self) -> &QualityThresholds {
        &self.revision_material.quality_thresholds
    }

    pub fn gop_frames(&self, source_fps: Rational) -> Result<u64, ProfileError> {
        Ok(source_fps.frames_in_whole_seconds(self.gop_seconds())?)
    }

    pub fn segment_frames(&self, source_fps: Rational) -> Result<u64, ProfileError> {
        Ok(source_fps.frames_in_whole_seconds(self.segment_seconds())?)
    }
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProfileError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(ProfileError::InvalidField {
            field,
            reason: format!("expected 1-{maximum} non-control characters"),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_variants_have_distinct_exact_revisions_and_are_not_publishable() {
        let mjpeg = NormalizationProfile::candidate_mjpeg_x265_slow_v1().expect("profile");
        let h264 = NormalizationProfile::candidate_h264_x265_slow_v1().expect("profile");
        let retry =
            NormalizationProfile::candidate_h264_crf16_retry_x265_slow_v1().expect("profile");
        assert_ne!(mjpeg.profile_revision(), h264.profile_revision());
        assert_ne!(h264.profile_revision(), retry.profile_revision());
        assert_eq!(mjpeg.crf(), 20);
        assert_eq!(h264.crf(), 18);
        assert_eq!(retry.crf(), 16);
        assert_eq!(
            mjpeg.require_approved(),
            Err(ProfileError::CandidateUnapproved)
        );
    }

    #[test]
    fn encoder_build_must_match_the_exact_compatibility_class() {
        let profile = NormalizationProfile::candidate_mjpeg_x265_slow_v1().expect("profile");
        let build = EncoderBuild::new(
            "hardware-hevc",
            "1",
            EncoderBuildFingerprint::parse(format!("sha256:{}", "a".repeat(64)))
                .expect("fingerprint"),
            EncoderCompatibilityClass::parse("nvenc-hevc-v1").expect("class"),
            BTreeMap::new(),
        )
        .expect("build");
        assert!(matches!(
            profile.require_compatible_encoder(&build),
            Err(ProfileError::IncompatibleEncoder { .. })
        ));
    }
}
