//! Schema-driven recording detectors used by [`super::scan::ConstrainedScanner`].

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use crate::publication::{canonicalize_rp_manifest, parse_strict_json};
use chrono::{DateTime, FixedOffset};
use jsonschema::Draft;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::identity::{
    AcquisitionSourceId, CandidateId, CandidateRevision, MediaGeneration, SourceArtifactId,
    SourceContentRevision, SourceRevisionClaim,
};
use super::path::{
    open_regular_file_beneath, validate_relative_path, PathSafetyError, SafeRelativePath,
};
use super::scan::{ScanDiagnostic, ScanDiagnosticCode, ScanLimits};
use super::source::{
    CandidateReadiness, FrameRate, MediaLocator, ScanCandidate, SignedPublicationMaterial,
    SourceArtifactClaim, SourceArtifactRole, SourceKind, SourceMediaPlan, SourceSchema,
    SourceTrustVerdicts, SourceVideoCodec, StereoLayout, ValidationCheck, ValidationReport,
};

pub struct SignedPublicationV1Detector;
pub struct DeviceSessionV1Detector;
pub struct RawCaptureV2Detector;
pub struct LegacyMjpegSessionV5Detector;
pub struct ApplianceSpoolV6Detector;

const DEVICE_SESSION_V1_SCHEMA_JSON: &str = include_str!(
    "../../../../../fixtures/device-session-v1/central/schemas/ylx-device-session-v1.schema.json"
);
const DEVICE_SESSION_V2_SCHEMA_JSON: &str = include_str!(
    "../../../../../fixtures/device-session-v1/central/schemas/ylx-device-session-v2.schema.json"
);
const AUDIO_DURATION_EPSILON_SECONDS: f64 = 1e-9;
const MAX_WAV_HEADER_BYTES: u64 = 65_536;
const MAX_AUDIO_BYTE_COUNT: u64 = i64::MAX as u64;

pub(crate) struct DetectionContext<'a> {
    pub(crate) candidate_root: &'a Path,
    pub(crate) candidate_relative_path: Option<SafeRelativePath>,
    pub(crate) source_id: &'a AcquisitionSourceId,
    pub(crate) media_generation: Option<&'a MediaGeneration>,
    pub(crate) source_kind: SourceKind,
    pub(crate) limits: &'a ScanLimits,
}

pub(crate) enum DetectionResult {
    Candidate(Box<ScanCandidate>),
    Rejected {
        readiness: CandidateReadiness,
        diagnostics: Vec<ScanDiagnostic>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceSessionVersion {
    V1,
    V2,
}

impl DeviceSessionVersion {
    fn discriminator(self) -> &'static str {
        match self {
            Self::V1 => "ylx.device-session.v1",
            Self::V2 => "ylx.device-session.v2",
        }
    }

    fn source_schema(self) -> SourceSchema {
        match self {
            Self::V1 => SourceSchema::DeviceSessionV1,
            Self::V2 => SourceSchema::DeviceSessionV2,
        }
    }

    fn schema_report_label(self) -> &'static str {
        match self {
            Self::V1 => "device_session_v1",
            Self::V2 => "device_session_v2",
        }
    }

    fn expected_imu_frame(self) -> &'static str {
        match self {
            Self::V1 => "opencv_optical",
            Self::V2 => "raw_device_axes",
        }
    }
}

pub(crate) fn detect_candidate(context: &DetectionContext<'_>) -> DetectionResult {
    match marker_exists(context, "manifest.json") {
        Ok(true) => return DeviceSessionV1Detector::detect(context),
        Ok(false) => {}
        Err(result) => return result,
    }

    match marker_exists(context, "publication_manifest.json") {
        Ok(true) => return SignedPublicationV1Detector::detect(context),
        Ok(false) => {}
        Err(result) => return result,
    }

    match marker_exists(context, "session.json") {
        Ok(true) => {
            let bytes = match read_manifest(context, "session.json") {
                Ok(bytes) => bytes,
                Err(result) => return result,
            };
            let value: Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        format!("session.json is not valid JSON: {error}"),
                    )
                }
            };
            let Some(version) = value.get("schema_version").and_then(Value::as_u64) else {
                return rejected(
                    CandidateReadiness::UnsupportedSchema,
                    ScanDiagnosticCode::UnknownSchema,
                    "session.json has no recognized numeric schema_version",
                );
            };
            return match version {
                1..=4 => rejected(
                    CandidateReadiness::UnsupportedSchema,
                    ScanDiagnosticCode::UnsupportedLegacySchema,
                    format!("legacy appliance schema v{version} is unsupported; v1-v4 are never guessed as v5"),
                ),
                5 => LegacyMjpegSessionV5Detector::detect_with_manifest(context, bytes, value),
                6 => ApplianceSpoolV6Detector::detect_with_manifest(context, bytes, value),
                other => rejected(
                    CandidateReadiness::UnsupportedSchema,
                    ScanDiagnosticCode::UnknownSchema,
                    format!("unknown appliance schema major {other}; refusing to guess"),
                ),
            };
        }
        Ok(false) => {}
        Err(result) => return result,
    }

    match marker_exists(context, "capture.json") {
        Ok(true) => RawCaptureV2Detector::detect(context),
        Ok(false) => rejected(
            CandidateReadiness::UnsupportedSchema,
            ScanDiagnosticCode::NoRecognizedMarker,
            "directory has none of publication_manifest.json, session.json, or capture.json",
        ),
        Err(result) => result,
    }
}

impl DeviceSessionV1Detector {
    fn detect(context: &DetectionContext<'_>) -> DetectionResult {
        let payload = match read_manifest(context, "manifest.json") {
            Ok(payload) => payload,
            Err(result) => return result,
        };
        let strict_value = match parse_strict_json(&payload) {
            Ok(value) => value,
            Err(error) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    error.to_string(),
                )
            }
        };
        let version = match string_at(&strict_value, &["/schema"]) {
            Some("ylx.device-session.v1") => DeviceSessionVersion::V1,
            Some("ylx.device-session.v2") => DeviceSessionVersion::V2,
            Some(other) => {
                return rejected(
                    CandidateReadiness::UnsupportedSchema,
                    ScanDiagnosticCode::UnknownSchema,
                    format!("unknown device session schema {other:?}; refusing to guess"),
                )
            }
            None => {
                return rejected(
                    CandidateReadiness::UnsupportedSchema,
                    ScanDiagnosticCode::UnknownSchema,
                    "manifest.json has no recognized device session schema discriminator",
                )
            }
        };

        let manifest: DeviceSessionManifest = match serde_json::from_value(strict_value.clone()) {
            Ok(manifest) => manifest,
            Err(error) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    format!("device session manifest shape is invalid: {error}"),
                )
            }
        };
        if let Err(result) = validate_device_session_header(&manifest, version) {
            return result;
        }
        let video = match parse_device_session_video(&manifest.video) {
            Ok(video) => video,
            Err(message) => return model_rejected(message),
        };

        let manifest_sha256 = sha256_hex(&payload);
        let manifest_path = SafeRelativePath::parse("manifest.json").expect("fixed path");
        let manifest_claim = match SourceArtifactClaim::new(
            SourceArtifactId::parse("device-session-manifest").expect("fixed artifact id"),
            manifest_path,
            SourceArtifactRole::SessionManifest,
            payload.len() as u64,
            Some(manifest_sha256.clone()),
            Some("application/json".to_string()),
        ) {
            Ok(claim) => claim,
            Err(error) => return model_rejected(error.to_string()),
        };

        let mut inventory = vec![manifest_claim];
        let mut seen_artifact_ids = HashSet::new();
        let mut seen_artifact_paths = HashSet::new();
        let mut frame_span = 0u64;
        let mut split_frame_span = None;
        let (layout, codec, width, height, segment_count) = match video {
            DeviceVideoShape::SplitEyes(video) => {
                if video.segments.is_empty()
                    || video.segments.len() > context.limits.maximum_files_per_candidate()
                {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::FileCountLimitExceeded,
                        "device session split-eyes segment count is empty or over limit",
                    );
                }
                let mut previous_frame_end: Option<u64> = None;
                let mut previous_time_end: Option<f64> = None;
                let mut split_frame_start: Option<u64> = None;
                let mut split_frame_end: Option<u64> = None;
                for (position, segment) in video.segments.iter().enumerate() {
                    if segment.index != position as u64
                        || segment.end_frame <= segment.start_frame
                        || segment.end_time_seconds <= segment.start_time_seconds
                    {
                        return rejected(
                            CandidateReadiness::Corrupt,
                            ScanDiagnosticCode::InvalidManifest,
                            "device session segment indices, frame ranges, and time ranges must be ordered",
                        );
                    }
                    if previous_frame_end.is_some_and(|end| segment.start_frame != end) {
                        return rejected(
                            CandidateReadiness::Corrupt,
                            ScanDiagnosticCode::InvalidManifest,
                            "device session segment frame intervals must be contiguous",
                        );
                    }
                    if previous_time_end
                        .is_some_and(|end| (segment.start_time_seconds - end).abs() > 1e-9)
                    {
                        return rejected(
                            CandidateReadiness::Corrupt,
                            ScanDiagnosticCode::InvalidManifest,
                            "device session segment time intervals must be contiguous",
                        );
                    }
                    if split_frame_start.is_none() {
                        split_frame_start = Some(segment.start_frame);
                    }
                    split_frame_end = Some(segment.end_frame);
                    previous_frame_end = Some(segment.end_frame);
                    previous_time_end = Some(segment.end_time_seconds);
                    frame_span =
                        match frame_span.checked_add(segment.end_frame - segment.start_frame) {
                            Some(total) => total,
                            None => {
                                return model_rejected(
                                    "device session frame span overflowed".to_string(),
                                )
                            }
                        };
                    let left = match validate_device_session_artifact(
                        context,
                        &segment.artifacts.left,
                        "video.left",
                        "video/mp4",
                        SourceArtifactRole::VideoLeft,
                        &mut seen_artifact_ids,
                        &mut seen_artifact_paths,
                    ) {
                        Ok(claim) => claim,
                        Err(result) => return result,
                    };
                    inventory.push(left);
                    let right = match validate_device_session_artifact(
                        context,
                        &segment.artifacts.right,
                        "video.right",
                        "video/mp4",
                        SourceArtifactRole::VideoRight,
                        &mut seen_artifact_ids,
                        &mut seen_artifact_paths,
                    ) {
                        Ok(claim) => claim,
                        Err(result) => return result,
                    };
                    inventory.push(right);
                }
                split_frame_span = split_frame_start.zip(split_frame_end);
                (
                    StereoLayout::SeparateEyes,
                    SourceVideoCodec::H264,
                    Some(manifest.camera.eye_width),
                    Some(manifest.camera.height),
                    video.segments.len() as u32,
                )
            }
            DeviceVideoShape::RawSideBySide(video) => {
                let stereo = match validate_device_session_artifact(
                    context,
                    &video.artifact,
                    "video.raw-side-by-side",
                    "video/x-motion-jpeg",
                    SourceArtifactRole::VideoStereo,
                    &mut seen_artifact_ids,
                    &mut seen_artifact_paths,
                ) {
                    Ok(claim) => claim,
                    Err(result) => return result,
                };
                inventory.push(stereo);
                frame_span = match manifest
                    .frames
                    .count
                    .checked_add(manifest.integrity.dropped_frames)
                {
                    Some(total) => total,
                    None => {
                        return model_rejected(
                            "device session raw frame span overflowed".to_string(),
                        )
                    }
                };
                (
                    StereoLayout::LeftRightSideBySide,
                    SourceVideoCodec::Mjpeg,
                    Some(manifest.camera.width),
                    Some(manifest.camera.height),
                    1,
                )
            }
        };

        let imu = match validate_device_session_artifact(
            context,
            &manifest.imu.artifact,
            "imu.samples",
            "application/x-ndjson",
            SourceArtifactRole::Imu,
            &mut seen_artifact_ids,
            &mut seen_artifact_paths,
        ) {
            Ok(claim) => claim,
            Err(result) => return result,
        };
        inventory.push(imu);
        let frames = match validate_device_session_artifact(
            context,
            &manifest.frames.artifact,
            "frames.index",
            "application/x-ndjson",
            SourceArtifactRole::FrameIndex,
            &mut seen_artifact_ids,
            &mut seen_artifact_paths,
        ) {
            Ok(claim) => claim,
            Err(result) => return result,
        };
        inventory.push(frames);
        if let Err(result) = append_device_session_audio_inventory(
            context,
            version,
            &manifest,
            &mut inventory,
            &mut seen_artifact_ids,
            &mut seen_artifact_paths,
        ) {
            return result;
        }
        for log in &manifest.logs {
            let log_claim = match validate_device_session_log_artifact(
                context,
                log,
                &mut seen_artifact_ids,
                &mut seen_artifact_paths,
            ) {
                Ok(claim) => claim,
                Err(result) => return result,
            };
            inventory.push(log_claim);
        }
        if let Err(result) = validate_device_session_schema(&strict_value, version) {
            return result;
        }
        if let Err(result) =
            validate_device_session_cross_fields(&manifest, frame_span, split_frame_span)
        {
            return result;
        }
        if let Err(result) = enforce_inventory_limits(context, &inventory) {
            return result;
        }

        let media_plan = match SourceMediaPlan::new(
            layout,
            codec,
            frame_rate_from_number(manifest.camera.effective_fps),
            width,
            height,
            segment_count,
            false,
        ) {
            Ok(plan) => plan.with_raw_frame_count(manifest.frames.count),
            Err(error) => return model_rejected(error.to_string()),
        };
        let revision = CandidateRevision::from_digest(Sha256::digest(&payload).into());

        make_candidate(
            context,
            version.source_schema(),
            manifest.session_id,
            SourceRevisionClaim::Provisional(revision),
            inventory,
            media_plan,
            SourceTrustVerdicts::pending_unsigned(),
            CandidateReadiness::PendingArtifactValidation,
            device_session_report(version, &manifest_sha256),
            None,
            &payload,
            context.source_kind,
        )
    }
}

impl SignedPublicationV1Detector {
    fn detect(context: &DetectionContext<'_>) -> DetectionResult {
        let payload = match read_manifest(context, "publication_manifest.json") {
            Ok(payload) => payload,
            Err(result) => return result,
        };
        let strict_value = match parse_strict_json(&payload) {
            Ok(value) => value,
            Err(error) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    error.to_string(),
                )
            }
        };
        let payload_text = match String::from_utf8(payload.clone()) {
            Ok(text) => text,
            Err(_) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    "publication manifest is not UTF-8",
                )
            }
        };
        let manifest: SignedManifest = match serde_json::from_value(strict_value.clone()) {
            Ok(manifest) => manifest,
            Err(error) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    format!("publication manifest shape is invalid: {error}"),
                )
            }
        };
        if manifest.schema_version != 1 {
            return rejected(
                CandidateReadiness::UnsupportedSchema,
                ScanDiagnosticCode::UnknownSchema,
                format!(
                    "unknown signed publication schema major {}; refusing to guess",
                    manifest.schema_version
                ),
            );
        }
        // Conductor v1 carries its signature inline. Presence of the inline
        // envelope means this is a signed-profile candidate even before the
        // PC can resolve its external device registry; it must never fall
        // through to unsigned admission due to a malformed envelope.
        let inline = manifest.publication_signature.as_ref();
        let canonical_payload_text = if let Some(inline) = inline {
            if inline.algorithm != "ed25519"
                || inline.key_version == 0
                || !is_fingerprint(&inline.public_key_fingerprint)
                || !is_lower_hex_exact(&inline.signature, 128)
            {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    "publication inline signature envelope is malformed or unsupported",
                );
            }
            let bytes = match canonicalize_rp_manifest(&strict_value) {
                Ok(value) => value,
                Err(error) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        error.to_string(),
                    )
                }
            };
            match String::from_utf8(bytes) {
                Ok(value) => Some(value),
                Err(_) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        "publication canonical payload is not UTF-8",
                    )
                }
            }
        } else {
            None
        };
        if !manifest.integrity_ok
            || !manifest.duration_seconds.is_finite()
            || manifest.duration_seconds < 0.0
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "publication does not declare a finite, integrity-valid recording",
            );
        }
        let content_revision = match SourceContentRevision::parse(&manifest.revision) {
            Ok(revision) => revision,
            Err(error) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    error.to_string(),
                )
            }
        };
        if manifest.files.is_empty()
            || manifest.files.len() > context.limits.maximum_files_per_candidate()
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::FileCountLimitExceeded,
                "signed inventory is empty or exceeds the configured file-count limit",
            );
        }

        let mut inventory = Vec::with_capacity(manifest.files.len());
        let mut envelope_files = Vec::with_capacity(manifest.files.len());
        let mut total = 0u64;
        let mut left_count = 0u32;
        let mut right_count = 0u32;
        let mut stereo_count = 0u32;
        for file in &manifest.files {
            let path = match checked_relative_path(context, &file.display_path) {
                Ok(path) => path,
                Err(result) => return result,
            };
            let file_id = match SourceArtifactId::parse(&file.id) {
                Ok(id) => id,
                Err(error) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        error.to_string(),
                    )
                }
            };
            if !is_sha256_hex(&file.sha256) {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    format!("artifact {:?} has an invalid SHA-256 claim", file.id),
                );
            }
            let actual_size = match inspect_regular_file(context, &path) {
                Ok(size) => size,
                Err(result) => return result,
            };
            if actual_size != file.size_bytes {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::SizeMismatch,
                    format!(
                        "artifact {:?} is {actual_size} bytes, manifest claims {}",
                        file.display_path, file.size_bytes
                    ),
                );
            }
            total = match total.checked_add(file.size_bytes) {
                Some(total) if total <= context.limits.maximum_declared_bytes_per_candidate() => {
                    total
                }
                _ => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::DeclaredBytesLimitExceeded,
                        "signed inventory exceeds the configured byte limit",
                    )
                }
            };
            let role = map_signed_role(&file.role);
            match role {
                SourceArtifactRole::VideoLeft => left_count = left_count.saturating_add(1),
                SourceArtifactRole::VideoRight => right_count = right_count.saturating_add(1),
                SourceArtifactRole::VideoStereo => stereo_count = stereo_count.saturating_add(1),
                _ => {}
            }
            let claim = match SourceArtifactClaim::new(
                file_id,
                path,
                role,
                file.size_bytes,
                Some(file.sha256.clone()),
                Some(file.media_type.clone()),
            ) {
                Ok(claim) => claim,
                Err(error) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        error.to_string(),
                    )
                }
            };
            inventory.push(claim);
            envelope_files.push((
                file.id.clone(),
                file.display_path.clone(),
                file.role.clone(),
                file.size_bytes,
                file.sha256.clone(),
                file.media_type.clone(),
            ));
        }
        if total != manifest.total_bytes {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                format!(
                    "inventory totals {total} bytes but manifest declares {}",
                    manifest.total_bytes
                ),
            );
        }
        let (layout, segment_count) = if left_count > 0 && left_count == right_count {
            (StereoLayout::SeparateEyes, left_count)
        } else if stereo_count > 0 {
            (StereoLayout::LeftRightSideBySide, stereo_count)
        } else {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "signed publication has no complete stereo video inventory",
            );
        };

        // The removable-media contract permits either an RP inline envelope
        // or an exact detached signature/public-key pair. Mixing the two
        // profiles is ambiguous, while a half-present detached pair must
        // never silently downgrade to unsigned admission.
        let has_signature = match marker_exists(context, "publication_manifest.sig") {
            Ok(present) => present,
            Err(result) => return result,
        };
        let has_public_key = match marker_exists(context, "publication_public_key.hex") {
            Ok(present) => present,
            Err(result) => return result,
        };
        if inline.is_some() && (has_signature || has_public_key) {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "an inline publication must not be combined with detached signature sidecars",
            );
        }
        if inline.is_none() && !has_signature && !has_public_key {
            return unsigned_publication_candidate(
                context,
                &manifest,
                payload,
                inventory,
                layout,
                segment_count,
            );
        }
        if inline.is_none() && has_signature != has_public_key {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "a detached signed publication must present both its signature and public key",
            );
        }

        let (presented_key_fingerprint, signed_material) = if let Some(inline) = inline {
            let fingerprint = inline.public_key_fingerprint.clone();
            let material = SignedPublicationMaterial::inline(
                manifest.session_id.clone(),
                manifest.revision.clone(),
                manifest.captured_at.clone(),
                manifest.published_at.clone(),
                manifest.duration_seconds,
                manifest.total_bytes,
                manifest.video_bytes,
                envelope_files,
                canonical_payload_text.expect("inline manifests always canonicalize"),
                inline.signature.clone(),
                fingerprint.clone(),
                inline.key_version,
            );
            (fingerprint, material)
        } else {
            let signature = match read_small_text(context, "publication_manifest.sig", 512) {
                Ok(value) if is_lower_hex_exact(&value, 128) => value,
                Ok(_) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        "detached Ed25519 signature must be 128 lowercase hex characters",
                    )
                }
                Err(result) => return result,
            };
            let public_key = match read_small_text(context, "publication_public_key.hex", 256) {
                Ok(value) if is_lower_hex_exact(&value, 64) => value,
                Ok(_) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidManifest,
                        "presented Ed25519 public key must be 64 lowercase hex characters",
                    )
                }
                Err(result) => return result,
            };
            let key_bytes = decode_lower_hex(&public_key).expect("validated lowercase hex");
            let fingerprint = format!("sha256:{:x}", Sha256::digest(&key_bytes));
            let material = SignedPublicationMaterial::new(
                manifest.session_id.clone(),
                manifest.revision.clone(),
                manifest.captured_at.clone(),
                manifest.published_at.clone(),
                manifest.duration_seconds,
                manifest.total_bytes,
                manifest.video_bytes,
                envelope_files,
                payload_text,
                signature,
                public_key,
                fingerprint.clone(),
            );
            (fingerprint, material)
        };
        let media_plan = match SourceMediaPlan::new(
            layout,
            SourceVideoCodec::H264,
            None,
            None,
            None,
            segment_count,
            false,
        ) {
            Ok(plan) => plan,
            Err(error) => return model_rejected(error.to_string()),
        };
        let report = accepted_report("signed_publication_v1");
        make_candidate(
            context,
            SourceSchema::SignedPublicationV1,
            manifest.session_id,
            SourceRevisionClaim::Published(content_revision),
            inventory,
            media_plan,
            SourceTrustVerdicts::pending_signed(presented_key_fingerprint),
            CandidateReadiness::WaitingForPairingKey,
            report,
            Some(signed_material),
            &payload,
            context.source_kind,
        )
    }
}

/// Admit a publication whose manifest is intact but unsigned.
///
/// The caller has already validated the manifest shape and checked every
/// declared artifact's path, size, and digest format against the card, so what
/// is left is the media geometry. The signed path can assume its own encoded
/// output; an unsigned publication cannot, because the recorder publishes both
/// separate-eye H.264 output and passed-through side-by-side MJPEG under the
/// same manifest schema. Geometry therefore comes from `session.json`, and an
/// unreadable or unrecognized codec is refused rather than guessed: claiming
/// the wrong codec here would mis-drive normalization later.
fn unsigned_publication_candidate(
    context: &DetectionContext<'_>,
    manifest: &SignedManifest,
    payload: Vec<u8>,
    inventory: Vec<SourceArtifactClaim>,
    layout: StereoLayout,
    segment_count: u32,
) -> DetectionResult {
    let session_bytes = match read_manifest(context, "session.json") {
        Ok(bytes) => bytes,
        Err(result) => return result,
    };
    let session: Value = match serde_json::from_slice(&session_bytes) {
        Ok(value) => value,
        Err(error) => return model_rejected(format!("session.json is invalid: {error}")),
    };

    let codec = match string_at(&session, &["/camera/video_codec", "/video_codec"]) {
        Some("mjpeg") => SourceVideoCodec::Mjpeg,
        Some("h264") => SourceVideoCodec::H264,
        other => {
            return rejected(
                CandidateReadiness::UnsupportedSchema,
                ScanDiagnosticCode::UnknownSchema,
                format!("unsigned publication declares unsupported video codec {other:?}"),
            )
        }
    };
    let frame_rate = number_at(
        &session,
        &["/camera/fps", "/camera/output_fps", "/video_fps"],
    )
    .and_then(frame_rate_from_number);
    // Separate-eye output is per eye, so the combined source width on the
    // camera block would overstate each track by a factor of two.
    let (width, height) = match layout {
        StereoLayout::SeparateEyes => (
            u32_at(
                &session,
                &["/camera/left_size/0", "/camera/eye_width", "/camera/width"],
            ),
            u32_at(&session, &["/camera/left_size/1", "/camera/height"]),
        ),
        StereoLayout::LeftRightSideBySide => (
            u32_at(&session, &["/camera/width"]),
            u32_at(&session, &["/camera/height"]),
        ),
    };

    let media_plan = match SourceMediaPlan::new(
        layout,
        codec,
        frame_rate,
        width,
        height,
        segment_count,
        false,
    ) {
        Ok(plan) => plan,
        Err(error) => return model_rejected(error.to_string()),
    };

    make_candidate(
        context,
        SourceSchema::UnsignedPublicationV1,
        manifest.session_id.clone(),
        // The manifest states a content revision and every artifact behind it
        // has been checked, but nothing attests who wrote it, so the claim
        // stays provisional rather than published.
        SourceRevisionClaim::Provisional(provisional_revision(&payload, &inventory)),
        inventory,
        media_plan,
        SourceTrustVerdicts::pending_unsigned(),
        CandidateReadiness::ReadyUnsignedRequiresPolicy,
        accepted_report("unsigned_publication_v1"),
        None,
        &payload,
        context.source_kind,
    )
}

impl RawCaptureV2Detector {
    fn detect(context: &DetectionContext<'_>) -> DetectionResult {
        let bytes = match read_manifest(context, "capture.json") {
            Ok(bytes) => bytes,
            Err(result) => return result,
        };
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(error) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidManifest,
                    format!("capture.json is not valid JSON: {error}"),
                )
            }
        };
        let schema = string_at(&value, &["/schema", "/schema_id", "/schema_version"]);
        if schema != Some("ylx.stereo_imu.raw.v2") {
            return rejected(
                CandidateReadiness::UnsupportedSchema,
                ScanDiagnosticCode::UnknownSchema,
                format!("unknown raw capture schema {:?}; refusing to guess", schema),
            );
        }
        let state = string_at(&value, &["/state", "/result/state"]);
        if state != Some("complete") {
            return rejected(
                CandidateReadiness::RecordingOrEncodingIncomplete,
                ScanDiagnosticCode::IncompleteRecording,
                format!("raw capture state is {:?}, not complete", state),
            );
        }
        let encoding = string_at(&value, &["/video/encoding", "/video/codec"]);
        let transport = string_at(&value, &["/video/transport"]);
        let persistent = bool_at(&value, &["/video/persistent"]);
        if encoding != Some("mjpeg")
            || transport != Some("file")
            || persistent != Some(true)
            || string_at(&value, &["/video/layout"]) != Some("left_right_side_by_side")
            || bool_at(&value, &["/result/native_capture_ok"]) != Some(true)
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "raw v2 must declare persistent MJPEG file transport",
            );
        }
        if any_nonzero_u64(
            &value,
            &[
                "/result/sequence_gaps",
                "/capture/sequence_gaps",
                "/sequence_gaps",
                "/result/timestamp_errors",
                "/result/imu_timestamp_errors",
                "/imu/timestamp_errors",
            ],
        ) {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidFrameIndex,
                "raw capture reports sequence gaps or timestamp errors",
            );
        }

        let video_path_text = string_at(&value, &["/files/video", "/video/path", "/video/file"])
            .unwrap_or("stereo.mjpeg");
        let frames_path_text = string_at(
            &value,
            &["/files/frames", "/files/frame_index", "/frames/path"],
        )
        .unwrap_or("frames.jsonl");
        let imu_path_text = string_at(&value, &["/files/imu", "/imu/path"]).unwrap_or("imu.jsonl");
        let video_path = match checked_relative_path(context, video_path_text) {
            Ok(path) => path,
            Err(result) => return result,
        };
        let frames_path = match checked_relative_path(context, frames_path_text) {
            Ok(path) => path,
            Err(result) => return result,
        };
        let imu_path = match checked_relative_path(context, imu_path_text) {
            Ok(path) => path,
            Err(result) => return result,
        };
        let video_size = match inspect_regular_file(context, &video_path) {
            Ok(0) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::SizeMismatch,
                    "stereo MJPEG source is empty",
                )
            }
            Ok(size) => size,
            Err(result) => return result,
        };
        if first_u64(&value, &["/video/size_bytes"]).is_some_and(|claimed| claimed != video_size) {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::SizeMismatch,
                "stereo MJPEG size differs from capture.json",
            );
        }
        let frame_bytes = match read_bounded_relative(
            context,
            &frames_path,
            context.limits.maximum_auxiliary_index_bytes(),
            ScanDiagnosticCode::AuxiliaryIndexTooLarge,
        ) {
            Ok(bytes) => bytes,
            Err(result) => return result,
        };
        let frame_records = match validate_frame_index(
            &frame_bytes,
            Some(video_size),
            context.limits.maximum_index_records(),
        ) {
            Ok(records) => records,
            Err(message) => {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::InvalidFrameIndex,
                    message,
                )
            }
        };
        if any_u64_not_equal(
            &value,
            &["/video/frame_count", "/result/frame_count"],
            frame_records as u64,
        ) {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "frame index count differs from capture.json",
            );
        }
        let imu_bytes = match read_bounded_relative(
            context,
            &imu_path,
            context.limits.maximum_auxiliary_index_bytes(),
            ScanDiagnosticCode::AuxiliaryIndexTooLarge,
        ) {
            Ok(bytes) => bytes,
            Err(result) => return result,
        };
        let imu_records =
            match validate_imu_index(&imu_bytes, context.limits.maximum_index_records()) {
                Ok(records) => records,
                Err(message) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidFrameIndex,
                        message,
                    )
                }
            };
        if first_u64(&value, &["/result/imu_sample_count"])
            .is_some_and(|claimed| claimed != imu_records as u64)
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "IMU sample count differs from capture.json",
            );
        }
        let imu_size = imu_bytes.len() as u64;
        let capture_path = SafeRelativePath::parse("capture.json").expect("fixed path");
        let mut inventory = Vec::new();
        for (id, path, role, size, media_type) in [
            (
                "capture-manifest",
                capture_path,
                SourceArtifactRole::CaptureManifest,
                bytes.len() as u64,
                "application/json",
            ),
            (
                "stereo-video",
                video_path,
                SourceArtifactRole::VideoStereo,
                video_size,
                "video/x-motion-jpeg",
            ),
            (
                "frame-index",
                frames_path,
                SourceArtifactRole::FrameIndex,
                frame_bytes.len() as u64,
                "application/x-ndjson",
            ),
            (
                "imu",
                imu_path,
                SourceArtifactRole::Imu,
                imu_size,
                "application/x-ndjson",
            ),
        ] {
            let claim = match SourceArtifactClaim::new(
                SourceArtifactId::parse(id).expect("fixed artifact id"),
                path,
                role,
                size,
                None,
                Some(media_type.to_string()),
            ) {
                Ok(claim) => claim,
                Err(error) => return model_rejected(error.to_string()),
            };
            inventory.push(claim);
        }
        if let Err(result) = enforce_inventory_limits(context, &inventory) {
            return result;
        }
        let frame_rate = number_at(
            &value,
            &["/video/output_fps", "/video/fps", "/video/source_fps"],
        )
        .and_then(frame_rate_from_number);
        let width = u32_at(&value, &["/video/width", "/camera/width"]);
        let height = u32_at(&value, &["/video/height", "/camera/height"]);
        let media_plan = match SourceMediaPlan::new(
            StereoLayout::LeftRightSideBySide,
            SourceVideoCodec::Mjpeg,
            frame_rate,
            width,
            height,
            1,
            false,
        ) {
            Ok(plan) => plan.with_raw_frame_count(frame_records as u64),
            Err(error) => return model_rejected(error.to_string()),
        };
        let session_id = string_at(&value, &["/session_id", "/capture_id"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("raw-{}", short_digest(&bytes)));
        let candidate_revision = provisional_revision(&bytes, &inventory);
        make_candidate(
            context,
            SourceSchema::RawCaptureV2,
            session_id,
            SourceRevisionClaim::Provisional(candidate_revision),
            inventory,
            media_plan,
            SourceTrustVerdicts::pending_unsigned(),
            CandidateReadiness::ReadyUnsignedRequiresPolicy,
            accepted_report("raw_capture_v2"),
            None,
            &bytes,
            context.source_kind,
        )
    }
}

impl LegacyMjpegSessionV5Detector {
    fn detect_with_manifest(
        context: &DetectionContext<'_>,
        bytes: Vec<u8>,
        value: Value,
    ) -> DetectionResult {
        if string_at(&value, &["/state"]) != Some("complete") {
            return rejected(
                CandidateReadiness::RecordingOrEncodingIncomplete,
                ScanDiagnosticCode::IncompleteRecording,
                "legacy v5 session is not complete",
            );
        }
        if bool_at(&value, &["/native_capture_ok"]) != Some(true)
            || bool_at(&value, &["/mux_ok"]) != Some(true)
        {
            return rejected(
                CandidateReadiness::RecordingOrEncodingIncomplete,
                ScanDiagnosticCode::IncompleteRecording,
                "legacy v5 native capture or mux result is incomplete",
            );
        }
        if string_at(&value, &["/camera/layout"]) != Some("left_right_side_by_side")
            || string_at(&value, &["/video_codec", "/video/codec"]) != Some("mjpeg")
            || string_at(&value, &["/video_encoder", "/video/encoder"]) != Some("copy")
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "legacy v5 must declare side-by-side MJPEG stream-copy geometry",
            );
        }
        let Some(segments) = value.get("video_segments").and_then(Value::as_array) else {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "legacy v5 has no video_segments array",
            );
        };
        if segments.is_empty() || segments.len() > context.limits.maximum_files_per_candidate() {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::FileCountLimitExceeded,
                "legacy v5 segment count is empty or over limit",
            );
        }
        let mut inventory = Vec::new();
        let mut seen_paths = HashSet::new();
        let mut declared_frame_count = 0u64;
        for (position, segment) in segments.iter().enumerate() {
            let path_text = segment
                .as_str()
                .or_else(|| segment.get("path").and_then(Value::as_str));
            let Some(path_text) = path_text else {
                return model_rejected("legacy v5 segment has no path".to_string());
            };
            let index = segment
                .get("index")
                .and_then(Value::as_u64)
                .unwrap_or(position as u64);
            if index != position as u64 || !seen_paths.insert(path_text.to_string()) {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::ConflictingEvidence,
                    "legacy v5 segment indices or paths are duplicated/non-contiguous",
                );
            }
            let path = match checked_relative_path(context, path_text) {
                Ok(path) => path,
                Err(result) => return result,
            };
            let size = match inspect_regular_file(context, &path) {
                Ok(0) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::SizeMismatch,
                        format!("legacy segment {path_text:?} is empty"),
                    )
                }
                Ok(size) => size,
                Err(result) => return result,
            };
            if segment
                .get("size_bytes")
                .and_then(Value::as_u64)
                .is_some_and(|claimed| claimed != size)
            {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::SizeMismatch,
                    format!("legacy segment {path_text:?} size differs from session.json"),
                );
            }
            let Some(frame_count) = segment.get("frame_count").and_then(Value::as_u64) else {
                return model_rejected(format!("legacy segment {path_text:?} has no frame_count"));
            };
            declared_frame_count = match declared_frame_count.checked_add(frame_count) {
                Some(total) => total,
                None => return model_rejected("legacy frame count overflowed".to_string()),
            };
            let claim = match SourceArtifactClaim::new(
                generated_artifact_id("legacy-video", position),
                path,
                SourceArtifactRole::VideoStereo,
                size,
                None,
                Some("video/mp4".to_string()),
            ) {
                Ok(claim) => claim,
                Err(error) => return model_rejected(error.to_string()),
            };
            inventory.push(claim);
        }
        if let Err(result) = append_required_metadata(
            context,
            &mut inventory,
            &[
                (
                    "legacy-session",
                    "session.json",
                    SourceArtifactRole::SessionManifest,
                ),
                (
                    "legacy-frames",
                    "raw/frames.jsonl",
                    SourceArtifactRole::FrameIndex,
                ),
            ],
        ) {
            return result;
        }
        if let Err(result) = append_optional_metadata(
            context,
            &mut inventory,
            "legacy-imu",
            "raw/imu.jsonl",
            SourceArtifactRole::Imu,
        ) {
            return result;
        }
        if let Err(result) = enforce_inventory_limits(context, &inventory) {
            return result;
        }
        let frames = match read_bounded_path(
            context,
            "raw/frames.jsonl",
            context.limits.maximum_auxiliary_index_bytes(),
            ScanDiagnosticCode::AuxiliaryIndexTooLarge,
        ) {
            Ok(frames) => frames,
            Err(result) => return result,
        };
        let frame_records =
            match validate_frame_index(&frames, None, context.limits.maximum_index_records()) {
                Ok(records) => records,
                Err(message) => {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::InvalidFrameIndex,
                        message,
                    )
                }
            };
        if declared_frame_count != frame_records as u64 {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "legacy segment frame total differs from raw/frames.jsonl",
            );
        }
        let width = u32_at(&value, &["/camera/width", "/camera/frame_width"]);
        let height = u32_at(&value, &["/camera/height", "/camera/frame_height"]);
        let frame_rate =
            number_at(&value, &["/camera/fps", "/video_fps"]).and_then(frame_rate_from_number);
        let media_plan = match SourceMediaPlan::new(
            StereoLayout::LeftRightSideBySide,
            SourceVideoCodec::Mjpeg,
            frame_rate,
            width,
            height,
            segments.len() as u32,
            true,
        ) {
            Ok(plan) => plan.with_legacy_total_frames(declared_frame_count),
            Err(error) => return model_rejected(error.to_string()),
        };
        let session_id = string_at(&value, &["/session_id"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("legacy-v5-{}", short_digest(&bytes)));
        let revision = provisional_revision(&bytes, &inventory);
        make_candidate(
            context,
            SourceSchema::LegacyMjpegSessionV5,
            session_id,
            SourceRevisionClaim::Provisional(revision),
            inventory,
            media_plan,
            SourceTrustVerdicts::pending_unsigned(),
            CandidateReadiness::ReadyUnsignedRequiresPolicy,
            accepted_report("legacy_mjpeg_session_v5"),
            None,
            &bytes,
            SourceKind::LegacyRemovableMedia,
        )
    }
}

impl ApplianceSpoolV6Detector {
    fn detect_with_manifest(
        context: &DetectionContext<'_>,
        session_bytes: Vec<u8>,
        session: Value,
    ) -> DetectionResult {
        for marker in ["capture.commit.json", "encoding.json"] {
            match marker_exists(context, marker) {
                Ok(true) => {}
                Ok(false) => {
                    return rejected(
                        CandidateReadiness::RecordingOrEncodingIncomplete,
                        ScanDiagnosticCode::IncompleteRecording,
                        format!("appliance v6 has not durably published {marker}"),
                    )
                }
                Err(result) => return result,
            }
        }
        let commit_bytes = match read_manifest(context, "capture.commit.json") {
            Ok(bytes) => bytes,
            Err(result) => return result,
        };
        let encoding_bytes = match read_manifest(context, "encoding.json") {
            Ok(bytes) => bytes,
            Err(result) => return result,
        };
        let commit: Value = match serde_json::from_slice(&commit_bytes) {
            Ok(value) => value,
            Err(error) => {
                return model_rejected(format!("capture.commit.json is invalid: {error}"))
            }
        };
        let encoding: Value = match serde_json::from_slice(&encoding_bytes) {
            Ok(value) => value,
            Err(error) => return model_rejected(format!("encoding.json is invalid: {error}")),
        };
        if string_at(&commit, &["/state"]) != Some("committed")
            || bool_at(&commit, &["/native_capture_ok"]) != Some(true)
            || bool_at(&commit, &["/mux_ok"]) != Some(true)
        {
            return rejected(
                CandidateReadiness::RecordingOrEncodingIncomplete,
                ScanDiagnosticCode::IncompleteRecording,
                "appliance v6 has not crossed its durable capture commit boundary",
            );
        }

        let Some(session_identity) = string_at(&session, &["/session_id"]) else {
            return model_rejected("appliance v6 session has no session_id".to_string());
        };
        if string_at(&commit, &["/session_id"]) != Some(session_identity)
            || string_at(&encoding, &["/session_id"]) != Some(session_identity)
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "session, capture commit, and encoding state bind different session ids",
            );
        }

        let session_state = string_at(&session, &["/state"]);
        let encoding_state = string_at(&encoding, &["/state"]);
        if session_state == Some("complete") && encoding_state == Some("complete") {
            return detect_complete_unpublished_v6(
                context,
                session_bytes,
                session,
                commit_bytes,
                encoding_bytes,
                encoding,
            );
        }
        if matches!(session_state, Some("active" | "recording")) {
            return rejected(
                CandidateReadiness::RecordingOrEncodingIncomplete,
                ScanDiagnosticCode::IncompleteRecording,
                "appliance v6 capture is still active",
            );
        }
        if encoding_state != Some("encoding") {
            return rejected(
                CandidateReadiness::RecordingOrEncodingIncomplete,
                ScanDiagnosticCode::IncompleteRecording,
                format!(
                    "appliance encoding state is {:?}, not an admissible committed spool",
                    encoding_state
                ),
            );
        }
        if string_at(&session, &["/camera/layout"]) != Some("left_right_side_by_side")
            || string_at(&session, &["/source_codec"]) != Some("mjpeg")
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "appliance spool must declare side-by-side MJPEG source geometry",
            );
        }

        let segments_csv = match read_bounded_path(
            context,
            "spool/segments.csv",
            context.limits.maximum_manifest_bytes(),
            ScanDiagnosticCode::ManifestTooLarge,
        ) {
            Ok(bytes) => bytes,
            Err(result) => return result,
        };
        let csv_segments = match parse_segments_csv(&segments_csv) {
            Ok(segments) if !segments.is_empty() => segments,
            Ok(_) => return model_rejected("spool/segments.csv is empty".to_string()),
            Err(message) => return model_rejected(message),
        };
        let commit_segments = commit
            .get("source_segments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if commit_segments.len() != csv_segments.len() {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "capture commit source inventory and segments.csv have different segment counts",
            );
        }
        let committed_count = first_u64(&commit, &["/source_segment_count"]);
        if committed_count.is_some_and(|count| count != csv_segments.len() as u64) {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "capture commit and spool index have different segment counts",
            );
        }
        let mut inventory = Vec::new();
        for (position, csv) in csv_segments.iter().enumerate() {
            if csv.index != position as u64 {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::ConflictingEvidence,
                    "spool segment indices must be unique and contiguous from zero",
                );
            }
            if !csv.closed {
                return rejected(
                    CandidateReadiness::RecordingOrEncodingIncomplete,
                    ScanDiagnosticCode::IncompleteRecording,
                    "every committed spool segment must be closed",
                );
            }
            if let Some(committed) = commit_segments.get(position) {
                if committed.get("closed").and_then(Value::as_bool) != Some(true)
                    || committed
                        .get("index")
                        .and_then(Value::as_u64)
                        .unwrap_or(position as u64)
                        != csv.index
                    || committed.get("path").and_then(Value::as_str) != Some(csv.path.as_str())
                    || committed.get("size_bytes").and_then(Value::as_u64) != Some(csv.size_bytes)
                    || committed.get("sha256").and_then(Value::as_str) != Some(csv.sha256.as_str())
                {
                    return rejected(
                        CandidateReadiness::Corrupt,
                        ScanDiagnosticCode::ConflictingEvidence,
                        "capture commit source segment disagrees with the durable spool index",
                    );
                }
            }
            let path = match checked_relative_path(context, &csv.path) {
                Ok(path) => path,
                Err(result) => return result,
            };
            let size = match inspect_regular_file(context, &path) {
                Ok(0) => return model_rejected(format!("spool segment {:?} is empty", csv.path)),
                Ok(size) => size,
                Err(result) => return result,
            };
            if size != csv.size_bytes {
                return rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::SizeMismatch,
                    format!(
                        "spool segment {:?} size differs from its durable claim",
                        csv.path
                    ),
                );
            }
            let claim = match SourceArtifactClaim::new(
                generated_artifact_id("spool-video", position),
                path,
                SourceArtifactRole::VideoStereo,
                size,
                Some(csv.sha256.clone()),
                Some("video/mp4".to_string()),
            ) {
                Ok(claim) => claim,
                Err(error) => return model_rejected(error.to_string()),
            };
            inventory.push(claim);
        }
        if let Err(result) = append_required_metadata(
            context,
            &mut inventory,
            &[
                (
                    "spool-session",
                    "session.json",
                    SourceArtifactRole::SessionManifest,
                ),
                (
                    "spool-commit",
                    "capture.commit.json",
                    SourceArtifactRole::CaptureCommit,
                ),
                (
                    "spool-encoding",
                    "encoding.json",
                    SourceArtifactRole::EncodingState,
                ),
                (
                    "spool-index",
                    "spool/segments.csv",
                    SourceArtifactRole::SpoolIndex,
                ),
            ],
        ) {
            return result;
        }
        if let Err(result) = append_optional_metadata(
            context,
            &mut inventory,
            "spool-frames",
            "raw/frames.jsonl",
            SourceArtifactRole::FrameIndex,
        ) {
            return result;
        }
        if let Err(result) = append_optional_metadata(
            context,
            &mut inventory,
            "spool-imu",
            "raw/imu.jsonl",
            SourceArtifactRole::Imu,
        ) {
            return result;
        }
        if let Err(result) = enforce_inventory_limits(context, &inventory) {
            return result;
        }
        let width = u32_at(&session, &["/camera/width", "/camera/frame_width"]);
        let height = u32_at(&session, &["/camera/height", "/camera/frame_height"]);
        let frame_rate = number_at(
            &session,
            &["/camera/output_fps", "/camera/fps", "/video_fps"],
        )
        .and_then(frame_rate_from_number);
        let media_plan = match SourceMediaPlan::new(
            StereoLayout::LeftRightSideBySide,
            SourceVideoCodec::Mjpeg,
            frame_rate,
            width,
            height,
            csv_segments.len() as u32,
            false,
        ) {
            Ok(plan) => plan,
            Err(error) => return model_rejected(error.to_string()),
        };
        let session_id = string_at(&session, &["/session_id"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("spool-v6-{}", short_digest(&session_bytes)));
        let mut revision_material = session_bytes.clone();
        revision_material.extend_from_slice(&commit_bytes);
        revision_material.extend_from_slice(&encoding_bytes);
        revision_material.extend_from_slice(&segments_csv);
        let revision = provisional_revision(&revision_material, &inventory);
        make_candidate(
            context,
            SourceSchema::ApplianceSpoolV6,
            session_id,
            SourceRevisionClaim::Provisional(revision),
            inventory,
            media_plan,
            SourceTrustVerdicts::pending_unsigned(),
            CandidateReadiness::ReadyUnsignedRequiresPolicy,
            accepted_report("appliance_spool_v6"),
            None,
            &revision_material,
            context.source_kind,
        )
    }
}

fn detect_complete_unpublished_v6(
    context: &DetectionContext<'_>,
    session_bytes: Vec<u8>,
    session: Value,
    commit_bytes: Vec<u8>,
    encoding_bytes: Vec<u8>,
    encoding: Value,
) -> DetectionResult {
    if bool_at(&session, &["/integrity_ok"]) != Some(true)
        || bool_at(&encoding, &["/integrity_ok"]) != Some(true)
    {
        return rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "complete unpublished v6 session is not integrity-valid",
        );
    }
    if string_at(&session, &["/camera/layout"]) != Some("left_right_separate")
        || string_at(&session, &["/video_codec"]) != Some("h264")
    {
        return rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "complete unpublished v6 must declare separate-eye H.264 output",
        );
    }
    let Some(outputs) = encoding.get("outputs").and_then(Value::as_array) else {
        return model_rejected("complete encoding has no outputs array".to_string());
    };
    let mut inventory = Vec::new();
    let mut left = HashSet::new();
    let mut right = HashSet::new();
    for output in outputs {
        let Some(path_text) = output.get("path").and_then(Value::as_str) else {
            return model_rejected("encoded output has no path".to_string());
        };
        let Some(role_text) = output.get("role").and_then(Value::as_str) else {
            return model_rejected("encoded output has no role".to_string());
        };
        let index = output.get("index").and_then(Value::as_u64).unwrap_or(0);
        let role = match role_text {
            "video_left" => {
                if !left.insert(index) {
                    return model_rejected("duplicate left output index".to_string());
                }
                SourceArtifactRole::VideoLeft
            }
            "video_right" => {
                if !right.insert(index) {
                    return model_rejected("duplicate right output index".to_string());
                }
                SourceArtifactRole::VideoRight
            }
            _ => return model_rejected(format!("unknown encoded output role {role_text:?}")),
        };
        if output.get("full_decode_ok").and_then(Value::as_bool) == Some(false) {
            return model_rejected(format!("encoded output {path_text:?} failed full decode"));
        }
        let path = match checked_relative_path(context, path_text) {
            Ok(path) => path,
            Err(result) => return result,
        };
        let actual_size = match inspect_regular_file(context, &path) {
            Ok(size) => size,
            Err(result) => return result,
        };
        if output
            .get("size_bytes")
            .and_then(Value::as_u64)
            .is_some_and(|claimed| claimed != actual_size)
        {
            return rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::SizeMismatch,
                format!("encoded output {path_text:?} size differs from encoding.json"),
            );
        }
        let digest = output
            .get("sha256")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let Some(digest) = digest.filter(|digest| is_sha256_hex(digest)) else {
            return model_rejected(format!("encoded output {path_text:?} has no valid SHA-256"));
        };
        let claim = match SourceArtifactClaim::new(
            generated_artifact_id(role_text, index as usize),
            path,
            role,
            actual_size,
            Some(digest),
            Some("video/mp4".to_string()),
        ) {
            Ok(claim) => claim,
            Err(error) => return model_rejected(error.to_string()),
        };
        inventory.push(claim);
    }
    if left.is_empty() || left != right {
        return model_rejected("complete v6 output is missing an aligned eye segment".to_string());
    }
    if !(0..left.len() as u64).all(|index| left.contains(&index)) {
        return model_rejected("complete v6 eye segment indices are not contiguous".to_string());
    }
    if let Err(result) = append_required_metadata(
        context,
        &mut inventory,
        &[
            (
                "v6-session",
                "session.json",
                SourceArtifactRole::SessionManifest,
            ),
            (
                "v6-commit",
                "capture.commit.json",
                SourceArtifactRole::CaptureCommit,
            ),
            (
                "v6-encoding",
                "encoding.json",
                SourceArtifactRole::EncodingState,
            ),
        ],
    ) {
        return result;
    }
    if let Err(result) = append_optional_metadata(
        context,
        &mut inventory,
        "v6-imu",
        "raw/imu.jsonl",
        SourceArtifactRole::Imu,
    ) {
        return result;
    }
    if let Err(result) = enforce_inventory_limits(context, &inventory) {
        return result;
    }
    let frame_rate =
        number_at(&session, &["/camera/fps", "/video_fps"]).and_then(frame_rate_from_number);
    let width = u32_at(&session, &["/camera/eye_width", "/camera/width"]);
    let height = u32_at(&session, &["/camera/height"]);
    let media_plan = match SourceMediaPlan::new(
        StereoLayout::SeparateEyes,
        SourceVideoCodec::H264,
        frame_rate,
        width,
        height,
        left.len() as u32,
        false,
    ) {
        Ok(plan) => plan,
        Err(error) => return model_rejected(error.to_string()),
    };
    let session_id = string_at(&session, &["/session_id"])
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("unpublished-v6-{}", short_digest(&session_bytes)));
    let mut material = session_bytes;
    material.extend_from_slice(&commit_bytes);
    material.extend_from_slice(&encoding_bytes);
    let revision = provisional_revision(&material, &inventory);
    make_candidate(
        context,
        SourceSchema::CompleteUnpublishedV6,
        session_id,
        SourceRevisionClaim::Provisional(revision),
        inventory,
        media_plan,
        SourceTrustVerdicts::pending_unsigned(),
        CandidateReadiness::ReadyUnsignedRequiresPolicy,
        accepted_report("complete_unpublished_v6"),
        None,
        &material,
        context.source_kind,
    )
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionManifest {
    schema: String,
    manifest_id: String,
    sealed: bool,
    sealed_at: String,
    session_id: String,
    volume_id: String,
    capture_mode: String,
    display_name: String,
    device: DeviceSessionDevice,
    time: DeviceSessionTime,
    take: DeviceSessionTake,
    camera: DeviceSessionCamera,
    video: Value,
    imu: DeviceSessionImu,
    frames: DeviceSessionFrames,
    #[serde(default)]
    audio: Option<DeviceSessionAudio>,
    logs: Vec<DeviceArtifact>,
    integrity: DeviceSessionIntegrity,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionDevice {
    device_id: String,
    device_label: String,
    hardware_fingerprint: String,
    platform: String,
    software_version: String,
    commit: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionTime {
    started_at: String,
    ended_at: String,
    timezone: String,
    duration_seconds: f64,
    duration_clock: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionTake {
    take_id: String,
    sequence: u64,
    continuation_of: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionCamera {
    width: u32,
    height: u32,
    eye_width: u32,
    sensor_fps: f64,
    frame_decimation: u32,
    nominal_fps: Option<f64>,
    effective_fps: f64,
    coordinate_frame: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionImu {
    artifact: DeviceArtifact,
    sample_count: u64,
    units: String,
    coordinate_frame: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionFrames {
    artifact: DeviceArtifact,
    count: u64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionIntegrity {
    verified_at: String,
    dropped_frames: u64,
    drop_events: Vec<DeviceDropEvent>,
    quality_policy: Option<DeviceQualityPolicy>,
    media_write_throughput_bytes_per_second: Option<u64>,
    fatal_errors: Vec<Value>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceQualityPolicy {
    policy_id: String,
    max_contiguous_dropped_frames: u64,
    max_total_dropped_frames: u64,
    max_drop_fraction: f64,
    window_seconds: f64,
    max_dropped_frames_per_window: u64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceDropEvent {
    start_frame: u64,
    end_frame: u64,
    at_time_seconds: f64,
    reason: String,
    dropped: u64,
}

#[allow(dead_code)]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceArtifact {
    artifact_id: String,
    role: String,
    path: String,
    media_type: String,
    bytes: u64,
    sha256: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum DeviceSessionAudio {
    Recorded(DeviceSessionRecordedAudio),
    NotRecorded(DeviceSessionNotRecordedAudio),
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionRecordedAudio {
    requested_mode: String,
    resolved_mode: String,
    codec: String,
    container: String,
    sample_format: String,
    sample_rate: u64,
    channels: u64,
    sample_count: u64,
    sync: DeviceSessionAudioSync,
    segments: Vec<DeviceSessionAudioSegment>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionNotRecordedAudio {
    requested_mode: String,
    resolved_mode: String,
    reason: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionAudioSync {
    time_base: String,
    start_time_seconds: f64,
    end_time_seconds: f64,
    video_time_reference: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionAudioSegment {
    index: u64,
    start_sample: u64,
    end_sample: u64,
    start_time_seconds: f64,
    end_time_seconds: f64,
    pcm_payload_bytes: u64,
    wav_header_bytes: u64,
    artifact: DeviceArtifact,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SplitEyesVideo {
    layout: String,
    codec: String,
    container: String,
    segments: Vec<DeviceStereoSegment>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSideBySideVideo {
    layout: String,
    codec: String,
    continuous: bool,
    artifact: DeviceArtifact,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStereoSegment {
    index: u64,
    start_frame: u64,
    end_frame: u64,
    start_time_seconds: f64,
    end_time_seconds: f64,
    artifacts: DeviceStereoArtifacts,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStereoArtifacts {
    left: DeviceArtifact,
    right: DeviceArtifact,
}

enum DeviceVideoShape {
    SplitEyes(SplitEyesVideo),
    RawSideBySide(RawSideBySideVideo),
}

fn parse_device_session_video(value: &Value) -> Result<DeviceVideoShape, String> {
    match string_at(value, &["/layout"]) {
        Some("split-eyes") => {
            let video: SplitEyesVideo = serde_json::from_value(value.clone())
                .map_err(|error| format!("split-eyes video shape is invalid: {error}"))?;
            if video.codec != "h264" || video.container != "mp4" {
                return Err("split-eyes video must declare h264/mp4".to_string());
            }
            Ok(DeviceVideoShape::SplitEyes(video))
        }
        Some("raw-side-by-side") => {
            let video: RawSideBySideVideo = serde_json::from_value(value.clone())
                .map_err(|error| format!("raw-side-by-side video shape is invalid: {error}"))?;
            if video.codec != "mjpeg" || !video.continuous {
                return Err("raw-side-by-side video must declare continuous mjpeg".to_string());
            }
            Ok(DeviceVideoShape::RawSideBySide(video))
        }
        other => Err(format!(
            "unknown device session video layout {other:?}; refusing to guess"
        )),
    }
}

fn device_session_validator(version: DeviceSessionVersion) -> &'static jsonschema::Validator {
    match version {
        DeviceSessionVersion::V1 => device_session_v1_validator(),
        DeviceSessionVersion::V2 => device_session_v2_validator(),
    }
}

fn device_session_v1_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value =
            serde_json::from_str(DEVICE_SESSION_V1_SCHEMA_JSON).expect("vendored schema is JSON");
        jsonschema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .build(&schema)
            .expect("vendored Device Session v1 schema compiles")
    })
}

fn device_session_v2_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value =
            serde_json::from_str(DEVICE_SESSION_V2_SCHEMA_JSON).expect("vendored schema is JSON");
        jsonschema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .build(&schema)
            .expect("vendored Device Session v2 schema compiles")
    })
}

fn validate_device_session_schema(
    value: &Value,
    version: DeviceSessionVersion,
) -> Result<(), DetectionResult> {
    let validator = device_session_validator(version);
    let mut errors = validator.iter_errors(value).peekable();
    if errors.peek().is_none() {
        return Ok(());
    }
    let mut details = errors
        .take(8)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if details.len() == 8 {
        details.push("additional schema errors omitted".to_string());
    }
    Err(rejected(
        CandidateReadiness::Corrupt,
        ScanDiagnosticCode::InvalidManifest,
        format!(
            "{} manifest does not satisfy vendored central Draft2020-12 schema: {}",
            version.discriminator(),
            details.join("; ")
        ),
    ))
}

fn validate_device_session_header(
    manifest: &DeviceSessionManifest,
    version: DeviceSessionVersion,
) -> Result<(), DetectionResult> {
    if manifest.schema != version.discriminator() || !manifest.sealed {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            format!("device session must be sealed {}", version.discriminator()),
        ));
    }
    match (version, manifest.audio.as_ref()) {
        (DeviceSessionVersion::V1, None) | (DeviceSessionVersion::V2, Some(_)) => {}
        (DeviceSessionVersion::V1, Some(_)) => {
            return Err(model_rejected(
                "Device Session v1 must not carry v2 audio fields".to_string(),
            ))
        }
        (DeviceSessionVersion::V2, None) => {
            return Err(model_rejected(
                "Device Session v2 must carry explicit audio state".to_string(),
            ))
        }
    }
    for (field, value, version) in [
        ("manifest_id", manifest.manifest_id.as_str(), '7'),
        ("session_id", manifest.session_id.as_str(), '7'),
        ("volume_id", manifest.volume_id.as_str(), '4'),
        ("device_id", manifest.device.device_id.as_str(), '4'),
        ("take_id", manifest.take.take_id.as_str(), '7'),
    ] {
        if !is_uuid_version(value, version) {
            return Err(model_rejected(format!(
                "{field} has invalid UUIDv{version} shape"
            )));
        }
    }
    if !matches!(manifest.capture_mode.as_str(), "production" | "calibration") {
        return Err(model_rejected(
            "device session capture_mode is unsupported".to_string(),
        ));
    }
    if manifest.display_name.is_empty() || manifest.display_name.len() > 160 {
        return Err(model_rejected(
            "device session display_name is outside its length bounds".to_string(),
        ));
    }
    if !is_device_label(&manifest.device.device_label)
        || !is_fingerprint(&manifest.device.hardware_fingerprint)
        || manifest.device.platform.is_empty()
        || manifest.device.platform.len() > 128
        || manifest.device.software_version.is_empty()
        || manifest.device.software_version.len() > 64
        || !is_hex_between(&manifest.device.commit, 40, 64)
    {
        return Err(model_rejected(
            "device session device identity shape is invalid".to_string(),
        ));
    }
    for (field, timestamp) in [
        ("sealed_at", manifest.sealed_at.as_str()),
        ("started_at", manifest.time.started_at.as_str()),
        ("ended_at", manifest.time.ended_at.as_str()),
        ("verified_at", manifest.integrity.verified_at.as_str()),
    ] {
        if !is_rfc3339_like(timestamp) {
            return Err(model_rejected(format!("{field} is not a date-time string")));
        }
    }
    if !is_timezone_like(&manifest.time.timezone)
        || !manifest.time.duration_seconds.is_finite()
        || manifest.time.duration_seconds < 0.0
        || manifest
            .time
            .duration_clock
            .as_deref()
            .is_some_and(|clock| clock != "host_monotonic")
    {
        return Err(model_rejected(
            "device session time block violates v1 bounds".to_string(),
        ));
    }
    match (
        manifest.take.sequence,
        manifest.take.continuation_of.as_deref(),
    ) {
        (1, None) => {}
        (2.., Some(previous)) if is_uuid_version(previous, '7') => {}
        _ => {
            return Err(model_rejected(
                "device session take continuation does not match its sequence".to_string(),
            ))
        }
    }
    if manifest.camera.width == 0
        || manifest.camera.height == 0
        || manifest.camera.eye_width == 0
        || manifest.camera.sensor_fps <= 0.0
        || !manifest.camera.sensor_fps.is_finite()
        || manifest.camera.frame_decimation == 0
        || manifest.camera.effective_fps < 0.0
        || !manifest.camera.effective_fps.is_finite()
        || manifest.camera.coordinate_frame != "opencv_optical"
        || manifest
            .camera
            .nominal_fps
            .is_some_and(|fps| !fps.is_finite() || fps <= 0.0)
    {
        return Err(model_rejected(
            "device session camera block violates v1 bounds".to_string(),
        ));
    }
    if manifest.imu.units != "raw_int16"
        || manifest.imu.coordinate_frame != version.expected_imu_frame()
    {
        return Err(model_rejected(format!(
            "{} IMU block must be raw_int16/{}",
            version.discriminator(),
            version.expected_imu_frame()
        )));
    }
    Ok(())
}

fn validate_device_session_cross_fields(
    manifest: &DeviceSessionManifest,
    frame_span: u64,
    split_frame_span: Option<(u64, u64)>,
) -> Result<(), DetectionResult> {
    if !manifest.integrity.fatal_errors.is_empty() {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "sealed device session must not contain fatal errors",
        ));
    }
    if manifest.camera.width != manifest.camera.eye_width.saturating_mul(2) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "device session camera.width must equal two eye widths",
        ));
    }
    let nominal_fps = manifest.camera.sensor_fps / f64::from(manifest.camera.frame_decimation);
    let has_nominal_fps = manifest.camera.nominal_fps.is_some();
    let has_quality_policy = manifest.integrity.quality_policy.is_some();
    if has_nominal_fps != has_quality_policy {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "device session nominal_fps and quality_policy must appear together",
        ));
    }
    let measured_semantics = has_nominal_fps && has_quality_policy;
    if measured_semantics {
        let declared_nominal = manifest
            .camera
            .nominal_fps
            .expect("checked measured semantics");
        if (declared_nominal - nominal_fps).abs() > 1e-9 {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "device session nominal_fps must equal sensor_fps/frame_decimation",
            ));
        }
    } else if (manifest.camera.effective_fps - nominal_fps).abs() > 1e-9 {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "device session legacy effective_fps must equal sensor_fps/frame_decimation",
        ));
    }
    let mut dropped = 0u64;
    let mut previous_end = None;
    for event in &manifest.integrity.drop_events {
        if event.reason != "write_backpressure"
            || event.end_frame <= event.start_frame
            || event.dropped != event.end_frame - event.start_frame
            || !event.at_time_seconds.is_finite()
            || event.at_time_seconds < 0.0
            || previous_end.is_some_and(|end| event.start_frame <= end)
        {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::InvalidManifest,
                "device session drop events are malformed, adjacent, or unordered",
            ));
        }
        dropped = match dropped.checked_add(event.dropped) {
            Some(total) => total,
            None => {
                return Err(model_rejected(
                    "device session dropped frame count overflowed".to_string(),
                ))
            }
        };
        previous_end = Some(event.end_frame);
    }
    if dropped != manifest.integrity.dropped_frames {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "device session drop events do not match dropped_frames",
        ));
    }
    if let Some((split_start, split_end)) = split_frame_span {
        for event in &manifest.integrity.drop_events {
            if event.start_frame < split_start || event.end_frame > split_end {
                return Err(rejected(
                    CandidateReadiness::Corrupt,
                    ScanDiagnosticCode::ConflictingEvidence,
                    "device session drop event lies outside the segment sequence span",
                ));
            }
        }
        let Some(expected_count) = split_end
            .checked_sub(split_start)
            .and_then(|span| span.checked_sub(manifest.integrity.dropped_frames))
        else {
            return Err(model_rejected(
                "device session dropped frame count exceeds frame span".to_string(),
            ));
        };
        if manifest.frames.count != expected_count {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "device session frames.count and dropped_frames do not match the video frame span",
            ));
        }
    } else if manifest
        .frames
        .count
        .checked_add(manifest.integrity.dropped_frames)
        != Some(frame_span)
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "device session frames.count and dropped_frames do not match the raw video frame span",
        ));
    }
    let started_at = parse_device_session_datetime("started_at", &manifest.time.started_at)?;
    let ended_at = parse_device_session_datetime("ended_at", &manifest.time.ended_at)?;
    let verified_at =
        parse_device_session_datetime("verified_at", &manifest.integrity.verified_at)?;
    let sealed_at = parse_device_session_datetime("sealed_at", &manifest.sealed_at)?;
    if !(started_at <= ended_at && ended_at <= verified_at && verified_at <= sealed_at) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "device session timestamp order must include ended_at <= verified_at <= sealed_at",
        ));
    }
    if manifest.time.duration_clock.is_none() {
        let actual_duration = ended_at
            .signed_duration_since(started_at)
            .num_milliseconds() as f64
            / 1000.0;
        if (manifest.time.duration_seconds - actual_duration).abs() > 0.001 {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "device session duration_seconds does not match timestamps",
            ));
        }
    }
    if measured_semantics {
        let expected = if manifest.time.duration_seconds == 0.0 {
            0.0
        } else {
            manifest.frames.count as f64 / manifest.time.duration_seconds
        };
        if (manifest.camera.effective_fps - expected).abs() > 1e-9 {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "device session effective_fps must equal frames.count/duration_seconds",
            ));
        }
        if manifest.integrity.dropped_frames != 0 {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::ConflictingEvidence,
                "device session rdk-x5-lossless-v1 forbids dropped frames",
            ));
        }
    }
    if let Some(policy) = &manifest.integrity.quality_policy {
        if policy.policy_id != "rdk-x5-lossless-v1"
            || policy.max_contiguous_dropped_frames != 0
            || policy.max_total_dropped_frames != 0
            || policy.max_drop_fraction != 0.0
            || policy.window_seconds <= 0.0
            || !policy.window_seconds.is_finite()
            || policy.max_dropped_frames_per_window != 0
        {
            return Err(model_rejected(
                "device session quality policy violates rdk-x5-lossless-v1".to_string(),
            ));
        }
    }
    Ok(())
}

fn parse_device_session_datetime(
    field: &'static str,
    value: &str,
) -> Result<DateTime<FixedOffset>, DetectionResult> {
    DateTime::parse_from_rfc3339(value).map_err(|error| {
        rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            format!("device session {field} is not an RFC3339 date-time: {error}"),
        )
    })
}

fn append_device_session_audio_inventory(
    context: &DetectionContext<'_>,
    version: DeviceSessionVersion,
    manifest: &DeviceSessionManifest,
    inventory: &mut Vec<SourceArtifactClaim>,
    seen_artifact_ids: &mut HashSet<String>,
    seen_artifact_paths: &mut HashSet<String>,
) -> Result<(), DetectionResult> {
    match version {
        DeviceSessionVersion::V1 => Ok(()),
        DeviceSessionVersion::V2 => {
            let Some(audio) = manifest.audio.as_ref() else {
                return Err(model_rejected(
                    "Device Session v2 must carry explicit audio state".to_string(),
                ));
            };
            match audio {
                DeviceSessionAudio::NotRecorded(audio) => validate_not_recorded_audio(audio),
                DeviceSessionAudio::Recorded(audio) => validate_recorded_audio(
                    context,
                    manifest,
                    audio,
                    inventory,
                    seen_artifact_ids,
                    seen_artifact_paths,
                ),
            }
        }
    }
}

fn validate_not_recorded_audio(
    audio: &DeviceSessionNotRecordedAudio,
) -> Result<(), DetectionResult> {
    if !matches!(audio.requested_mode.as_str(), "device_default" | "disabled")
        || audio.resolved_mode != "disabled"
        || !matches!(
            audio.reason.as_str(),
            "user_disabled" | "device_default_disabled"
        )
    {
        return Err(model_rejected(
            "Device Session v2 not_recorded audio state violates central contract".to_string(),
        ));
    }
    Ok(())
}

fn validate_recorded_audio(
    context: &DetectionContext<'_>,
    manifest: &DeviceSessionManifest,
    audio: &DeviceSessionRecordedAudio,
    inventory: &mut Vec<SourceArtifactClaim>,
    seen_artifact_ids: &mut HashSet<String>,
    seen_artifact_paths: &mut HashSet<String>,
) -> Result<(), DetectionResult> {
    if !matches!(audio.requested_mode.as_str(), "device_default" | "enabled")
        || audio.resolved_mode != "enabled"
        || audio.codec != "pcm_s16le"
        || audio.container != "wav"
        || audio.sample_format != "S16_LE"
        || audio.sample_rate < 8_000
        || audio.sample_rate > 384_000
        || audio.channels == 0
        || audio.channels > 8
        || audio.sample_count == 0
        || audio.segments.is_empty()
        || audio.sync.time_base != "host_monotonic"
        || audio.sync.video_time_reference != "session_time_seconds"
        || !audio.sync.start_time_seconds.is_finite()
        || !audio.sync.end_time_seconds.is_finite()
        || audio.sync.start_time_seconds < 0.0
        || audio.sync.end_time_seconds <= audio.sync.start_time_seconds
    {
        return Err(model_rejected(
            "Device Session v2 recorded audio state violates central contract".to_string(),
        ));
    }

    let bytes_per_pcm_frame = audio.channels.checked_mul(2).ok_or_else(|| {
        model_rejected("Device Session v2 audio channel byte count overflowed".to_string())
    })?;
    let duration_tolerance = (1.0 / audio.sample_rate as f64) + AUDIO_DURATION_EPSILON_SECONDS;
    let mut previous_sample_end = None;
    let mut previous_time_end = None;
    let mut sample_total = 0u64;

    for (expected_index, segment) in audio.segments.iter().enumerate() {
        validate_audio_segment_domain(
            audio,
            segment,
            expected_index as u64,
            bytes_per_pcm_frame,
            duration_tolerance,
            &mut previous_sample_end,
            &mut previous_time_end,
            &mut sample_total,
        )?;
        let claim = validate_device_session_artifact(
            context,
            &segment.artifact,
            "audio.wav",
            "audio/wav",
            SourceArtifactRole::Audio,
            seen_artifact_ids,
            seen_artifact_paths,
        )?;
        validate_audio_file_if_present(
            context,
            &claim,
            segment,
            audio.sample_rate,
            audio.channels,
        )?;
        inventory.push(claim);
    }

    if audio
        .segments
        .first()
        .is_some_and(|segment| segment.start_sample != 0)
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio sample domain must start at zero",
        ));
    }
    if sample_total != audio.sample_count {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio.sample_count does not equal segment sample sum",
        ));
    }
    let first = audio.segments.first().expect("non-empty audio segments");
    let last = audio.segments.last().expect("non-empty audio segments");
    if (audio.sync.start_time_seconds - first.start_time_seconds).abs() > 1e-9
        || (audio.sync.end_time_seconds - last.end_time_seconds).abs() > 1e-9
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio sync interval must equal segment coverage",
        ));
    }
    let sync_duration = audio.sync.end_time_seconds - audio.sync.start_time_seconds;
    let expected_sync_duration = audio.sample_count as f64 / audio.sample_rate as f64;
    if (sync_duration - expected_sync_duration).abs() > duration_tolerance {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio sync duration must match sample_count and sample_rate",
        ));
    }
    if !(0.0 <= audio.sync.start_time_seconds
        && audio.sync.start_time_seconds < audio.sync.end_time_seconds
        && audio.sync.end_time_seconds <= manifest.time.duration_seconds)
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio sync interval must be inside session duration",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_audio_segment_domain(
    audio: &DeviceSessionRecordedAudio,
    segment: &DeviceSessionAudioSegment,
    expected_index: u64,
    bytes_per_pcm_frame: u64,
    duration_tolerance: f64,
    previous_sample_end: &mut Option<u64>,
    previous_time_end: &mut Option<f64>,
    sample_total: &mut u64,
) -> Result<(), DetectionResult> {
    if segment.index != expected_index
        || segment.end_sample <= segment.start_sample
        || segment.end_time_seconds <= segment.start_time_seconds
        || !segment.start_time_seconds.is_finite()
        || !segment.end_time_seconds.is_finite()
        || segment.start_time_seconds < 0.0
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "Device Session v2 audio segment indices, sample ranges, and time ranges must be ordered",
        ));
    }
    if previous_sample_end.is_some_and(|end| segment.start_sample != end) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "Device Session v2 audio segment sample intervals must be contiguous",
        ));
    }
    if previous_time_end.is_some_and(|end| (segment.start_time_seconds - end).abs() > 1e-9) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "Device Session v2 audio segment time intervals must be contiguous",
        ));
    }

    let segment_frames = segment.end_sample - segment.start_sample;
    let segment_duration = segment.end_time_seconds - segment.start_time_seconds;
    let expected_duration = segment_frames as f64 / audio.sample_rate as f64;
    if (segment_duration - expected_duration).abs() > duration_tolerance {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio segment duration must match sample frame domain and sample_rate",
        ));
    }
    let expected_payload_bytes =
        segment_frames
            .checked_mul(bytes_per_pcm_frame)
            .ok_or_else(|| {
                model_rejected(
                    "Device Session v2 audio pcm payload byte count overflowed".to_string(),
                )
            })?;
    if expected_payload_bytes > MAX_AUDIO_BYTE_COUNT
        || segment.pcm_payload_bytes != expected_payload_bytes
        || segment.wav_header_bytes < 44
        || segment.wav_header_bytes > MAX_WAV_HEADER_BYTES
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio payload/header byte domain is inconsistent",
        ));
    }
    let expected_file_bytes = segment
        .pcm_payload_bytes
        .checked_add(segment.wav_header_bytes)
        .ok_or_else(|| {
            model_rejected("Device Session v2 audio file byte count overflowed".to_string())
        })?;
    if expected_file_bytes > MAX_AUDIO_BYTE_COUNT || segment.artifact.bytes != expected_file_bytes {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 audio artifact bytes must equal pcm_payload_bytes + wav_header_bytes",
        ));
    }

    *sample_total = sample_total.checked_add(segment_frames).ok_or_else(|| {
        model_rejected("Device Session v2 audio sample count overflowed".to_string())
    })?;
    *previous_sample_end = Some(segment.end_sample);
    *previous_time_end = Some(segment.end_time_seconds);
    Ok(())
}

fn validate_audio_file_if_present(
    context: &DetectionContext<'_>,
    claim: &SourceArtifactClaim,
    segment: &DeviceSessionAudioSegment,
    sample_rate: u64,
    channels: u64,
) -> Result<(), DetectionResult> {
    let mut opened = match open_regular_file_beneath(context.candidate_root, claim.relative_path())
    {
        Ok(opened) => opened,
        Err(PathSafetyError::Inspection {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => return Ok(()),
        Err(error) => return Err(path_resolution_rejected(claim.relative_path(), error)),
    };
    if opened.len() != segment.artifact.bytes {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 mounted audio file size differs from manifest bytes",
        ));
    }

    let mut total = 0u64;
    let mut hasher = Sha256::new();
    let mut header = Vec::new();
    let header_limit = usize::try_from(segment.wav_header_bytes).unwrap_or(usize::MAX);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = opened.file_mut().read(&mut buffer).map_err(|error| {
            rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::Io,
                format!(
                    "Device Session v2 mounted audio file {:?} cannot be read: {error}",
                    claim.relative_path().as_str()
                ),
            )
        })?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            model_rejected("Device Session v2 mounted audio byte count overflowed".to_string())
        })?;
        hasher.update(&buffer[..read]);
        if header.len() < header_limit {
            let needed = header_limit - header.len();
            header.extend_from_slice(&buffer[..read.min(needed)]);
        }
    }
    opened
        .recheck()
        .map_err(|error| path_resolution_rejected(claim.relative_path(), error))?;
    if total != segment.artifact.bytes {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 mounted audio file length changed while reading",
        ));
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != segment.artifact.sha256 {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            "Device Session v2 mounted audio file sha256 differs from manifest",
        ));
    }
    validate_wav_header(
        &header,
        segment.wav_header_bytes,
        segment.pcm_payload_bytes,
        segment.artifact.bytes,
        sample_rate,
        channels,
    )
}

fn validate_wav_header(
    header: &[u8],
    declared_header_bytes: u64,
    declared_payload_bytes: u64,
    declared_file_bytes: u64,
    sample_rate: u64,
    channels: u64,
) -> Result<(), DetectionResult> {
    if !(44..=MAX_WAV_HEADER_BYTES).contains(&declared_header_bytes)
        || header.len() < declared_header_bytes as usize
        || declared_file_bytes != declared_header_bytes + declared_payload_bytes
        || header.get(0..4) != Some(b"RIFF")
        || header.get(8..12) != Some(b"WAVE")
    {
        return Err(invalid_wav_audio());
    }
    let riff_size = u64::from(read_u32_le(header, 4).ok_or_else(invalid_wav_audio)?);
    if riff_size.checked_add(8) != Some(declared_file_bytes) {
        return Err(invalid_wav_audio());
    }

    let mut cursor = 12usize;
    let mut saw_fmt = false;
    let mut saw_data = false;
    while cursor.checked_add(8).is_some_and(|end| end <= header.len()) {
        let chunk_id = &header[cursor..cursor + 4];
        let chunk_size = read_u32_le(header, cursor + 4).ok_or_else(invalid_wav_audio)? as usize;
        let data_start = cursor + 8;
        let data_end = data_start
            .checked_add(chunk_size)
            .ok_or_else(invalid_wav_audio)?;
        if data_end > header.len() && chunk_id != b"data" {
            return Err(invalid_wav_audio());
        }
        if chunk_id == b"fmt " {
            if chunk_size < 16 || data_end > header.len() {
                return Err(invalid_wav_audio());
            }
            let audio_format = read_u16_le(header, data_start).ok_or_else(invalid_wav_audio)?;
            let wav_channels =
                u64::from(read_u16_le(header, data_start + 2).ok_or_else(invalid_wav_audio)?);
            let wav_sample_rate =
                u64::from(read_u32_le(header, data_start + 4).ok_or_else(invalid_wav_audio)?);
            let wav_byte_rate =
                u64::from(read_u32_le(header, data_start + 8).ok_or_else(invalid_wav_audio)?);
            let wav_block_align =
                u64::from(read_u16_le(header, data_start + 12).ok_or_else(invalid_wav_audio)?);
            let bits_per_sample =
                read_u16_le(header, data_start + 14).ok_or_else(invalid_wav_audio)?;
            let expected_block_align = channels.checked_mul(2).ok_or_else(|| {
                model_rejected("Device Session v2 WAV block align overflowed".to_string())
            })?;
            let expected_byte_rate =
                sample_rate
                    .checked_mul(expected_block_align)
                    .ok_or_else(|| {
                        model_rejected("Device Session v2 WAV byte rate overflowed".to_string())
                    })?;
            if audio_format != 1
                || wav_channels != channels
                || wav_sample_rate != sample_rate
                || wav_byte_rate != expected_byte_rate
                || wav_block_align != expected_block_align
                || bits_per_sample != 16
            {
                return Err(invalid_wav_audio());
            }
            saw_fmt = true;
        } else if chunk_id == b"data" {
            if data_start as u64 != declared_header_bytes
                || chunk_size as u64 != declared_payload_bytes
            {
                return Err(invalid_wav_audio());
            }
            saw_data = true;
            break;
        }
        let padded_end = data_end
            .checked_add(chunk_size % 2)
            .ok_or_else(invalid_wav_audio)?;
        cursor = padded_end;
    }

    if saw_fmt && saw_data {
        Ok(())
    } else {
        Err(invalid_wav_audio())
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn invalid_wav_audio() -> DetectionResult {
    rejected(
        CandidateReadiness::Corrupt,
        ScanDiagnosticCode::ConflictingEvidence,
        "Device Session v2 mounted audio file must be RIFF/WAVE PCM S16_LE matching declared header, payload, sample rate, channels, bytes, and sha256",
    )
}

fn validate_device_session_artifact(
    context: &DetectionContext<'_>,
    artifact: &DeviceArtifact,
    expected_role: &str,
    expected_media_type: &str,
    mapped_role: SourceArtifactRole,
    seen_artifact_ids: &mut HashSet<String>,
    seen_artifact_paths: &mut HashSet<String>,
) -> Result<SourceArtifactClaim, DetectionResult> {
    if artifact.role != expected_role || artifact.media_type != expected_media_type {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            format!(
                "device session artifact {:?} must be {expected_role}/{expected_media_type}",
                artifact.path
            ),
        ));
    }
    validate_device_artifact_common(
        context,
        artifact,
        mapped_role,
        seen_artifact_ids,
        seen_artifact_paths,
    )
}

fn validate_device_session_log_artifact(
    context: &DetectionContext<'_>,
    artifact: &DeviceArtifact,
    seen_artifact_ids: &mut HashSet<String>,
    seen_artifact_paths: &mut HashSet<String>,
) -> Result<SourceArtifactClaim, DetectionResult> {
    if !is_log_role(&artifact.role) || !is_media_type(&artifact.media_type) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "device session log artifact role or media type is invalid",
        ));
    }
    validate_device_artifact_common(
        context,
        artifact,
        SourceArtifactRole::Metadata,
        seen_artifact_ids,
        seen_artifact_paths,
    )
}

fn validate_device_artifact_common(
    context: &DetectionContext<'_>,
    artifact: &DeviceArtifact,
    mapped_role: SourceArtifactRole,
    seen_artifact_ids: &mut HashSet<String>,
    seen_artifact_paths: &mut HashSet<String>,
) -> Result<SourceArtifactClaim, DetectionResult> {
    if !is_sha256_hex(&artifact.artifact_id)
        || !is_sha256_hex(&artifact.sha256)
        || artifact.artifact_id != artifact.sha256
    {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            "device session artifact_id must equal sha256",
        ));
    }
    if !seen_artifact_ids.insert(artifact.artifact_id.clone()) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            format!(
                "device session duplicate artifact id {:?}",
                artifact.artifact_id
            ),
        ));
    }
    let path = checked_device_artifact_path(context, &artifact.path)?;
    if !seen_artifact_paths.insert(path.as_str().to_string()) {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::ConflictingEvidence,
            format!("device session duplicate artifact path {:?}", artifact.path),
        ));
    }
    SourceArtifactClaim::new(
        SourceArtifactId::parse(&artifact.artifact_id)
            .map_err(|error| model_rejected(error.to_string()))?,
        path,
        mapped_role,
        artifact.bytes,
        Some(artifact.sha256.clone()),
        Some(artifact.media_type.clone()),
    )
    .map_err(|error| model_rejected(error.to_string()))
}

fn checked_device_artifact_path(
    context: &DetectionContext<'_>,
    path: &str,
) -> Result<SafeRelativePath, DetectionResult> {
    let relative = checked_relative_path(context, path)?;
    if path == "manifest.json"
        || path == "recording.json"
        || relative.components().any(is_tmp_component)
    {
        return Err(rejected(
            CandidateReadiness::UnsafePath,
            ScanDiagnosticCode::UnsafeRelativePath,
            format!("device session artifact path {path:?} is reserved by the seal protocol"),
        ));
    }
    Ok(relative)
}

fn device_session_report(version: DeviceSessionVersion, manifest_sha256: &str) -> ValidationReport {
    let imu_detail = match version {
        DeviceSessionVersion::V1 => {
            "legacy raw_int16 opencv_optical IMU is physical-unverified source metadata, not calibrated SI"
        }
        DeviceSessionVersion::V2 => {
            "raw_int16 raw_device_axes IMU is preserved as source metadata, not calibrated SI"
        }
    };
    ValidationReport::new(vec![
        ValidationCheck::new("schema_recognized", true, version.schema_report_label())
            .expect("static validation check is valid"),
        ValidationCheck::new(
            "exact_manifest_identity",
            true,
            format!("manifest.json exact bytes sha256:{manifest_sha256}"),
        )
        .expect("static validation check is valid"),
        ValidationCheck::new(
            "content_hash_pending",
            true,
            "declared artifact sizes and SHA-256 claims are deferred to explicit import/admission",
        )
        .expect("static validation check is valid"),
        ValidationCheck::new("raw_imu_source_only", true, imu_detail)
            .expect("static validation check is valid"),
    ])
    .expect("static validation report is non-empty")
}

#[derive(Deserialize)]
struct SignedManifest {
    schema_version: u64,
    session_id: String,
    revision: String,
    captured_at: String,
    published_at: String,
    duration_seconds: f64,
    total_bytes: u64,
    video_bytes: u64,
    integrity_ok: bool,
    files: Vec<SignedFile>,
    publication_signature: Option<InlinePublicationSignature>,
}

#[derive(Deserialize)]
struct InlinePublicationSignature {
    algorithm: String,
    key_version: u64,
    public_key_fingerprint: String,
    signature: String,
}

#[derive(Deserialize)]
struct SignedFile {
    id: String,
    display_path: String,
    role: String,
    size_bytes: u64,
    sha256: String,
    media_type: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_uuid_version(value: &str, version: char) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    for index in [8, 13, 18, 23] {
        if bytes[index] != b'-' {
            return false;
        }
    }
    value.chars().enumerate().all(|(index, character)| {
        matches!(index, 8 | 13 | 18 | 23)
            || character.is_ascii_digit()
            || ('a'..='f').contains(&character)
    }) && value.as_bytes()[14] == version as u8
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

fn is_device_label(value: &str) -> bool {
    value.strip_prefix("YLX-").is_some_and(|suffix| {
        suffix.len() == 8
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    })
}

fn is_hex_between(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_rfc3339_like(value: &str) -> bool {
    let Some((date, time_with_offset)) = value.split_once('T') else {
        return false;
    };
    if !is_rfc3339_date(date) {
        return false;
    }
    let (time, offset) = if let Some(time) = time_with_offset.strip_suffix('Z') {
        (time, None)
    } else if let Some(index) = time_with_offset
        .as_bytes()
        .iter()
        .enumerate()
        .skip(8)
        .find_map(|(index, byte)| matches!(byte, b'+' | b'-').then_some(index))
    {
        (&time_with_offset[..index], Some(&time_with_offset[index..]))
    } else {
        return false;
    };
    is_rfc3339_time(time) && offset.is_none_or(is_rfc3339_offset)
}

fn is_rfc3339_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !digits(&value[0..4])
        || !digits(&value[5..7])
        || !digits(&value[8..10])
    {
        return false;
    }
    let year = value[0..4].parse::<u32>().expect("digits only");
    let month = value[5..7].parse::<u32>().expect("digits only");
    let day = value[8..10].parse::<u32>().expect("digits only");
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn is_rfc3339_time(value: &str) -> bool {
    if value.len() < 8
        || value.as_bytes()[2] != b':'
        || value.as_bytes()[5] != b':'
        || !digits(&value[0..2])
        || !digits(&value[3..5])
        || !digits(&value[6..8])
    {
        return false;
    }
    let hour = value[0..2].parse::<u32>().expect("digits only");
    let minute = value[3..5].parse::<u32>().expect("digits only");
    let second = value[6..8].parse::<u32>().expect("digits only");
    if hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    match value.as_bytes().get(8) {
        None => true,
        Some(b'.') => value.len() > 9 && digits(&value[9..]),
        Some(_) => false,
    }
}

fn is_rfc3339_offset(value: &str) -> bool {
    if value.len() != 6
        || !matches!(value.as_bytes()[0], b'+' | b'-')
        || value.as_bytes()[3] != b':'
        || !digits(&value[1..3])
        || !digits(&value[4..6])
    {
        return false;
    }
    let hour = value[1..3].parse::<u32>().expect("digits only");
    let minute = value[4..6].parse::<u32>().expect("digits only");
    hour <= 23 && minute <= 59
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn digits(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_timezone_like(value: &str) -> bool {
    let mut segments = value.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    !first.is_empty()
        && first
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && segments.next().is_some_and(is_timezone_suffix_segment)
        && segments.all(is_timezone_suffix_segment)
}

fn is_timezone_suffix_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'.' | b'-'))
}

fn is_log_role(value: &str) -> bool {
    if value.len() > 96 {
        return false;
    };
    let Some(mut suffix) = value.strip_prefix("log") else {
        return false;
    };
    let mut groups = 0usize;
    while !suffix.is_empty() {
        let Some(separator) = suffix.as_bytes().first() else {
            return false;
        };
        if !matches!(separator, b'.' | b'_' | b'-') {
            return false;
        }
        suffix = &suffix[1..];
        let len = suffix
            .bytes()
            .take_while(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            .count();
        if len == 0 {
            return false;
        }
        suffix = &suffix[len..];
        groups += 1;
    }
    groups > 0
}

fn is_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.is_empty()
        && kind.bytes().all(is_media_type_byte)
        && subtype.bytes().all(is_media_type_byte)
}

fn is_media_type_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
        )
}

fn is_tmp_component(component: &str) -> bool {
    component.find(".tmp").is_some_and(|index| {
        let rest = &component[index + 4..];
        rest.is_empty()
            || rest
                .as_bytes()
                .first()
                .is_some_and(|byte| matches!(byte, b'.' | b'_' | b'-'))
    })
}

fn is_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_lower_hex_exact(hex, 64))
}

struct CsvSegment {
    index: u64,
    path: String,
    closed: bool,
    size_bytes: u64,
    sha256: String,
}

fn parse_segments_csv(bytes: &[u8]) -> Result<Vec<CsvSegment>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "segments.csv is not UTF-8".to_string())?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| "segments.csv has no header".to_string())?;
    let columns: Vec<&str> = header.split(',').map(str::trim).collect();
    let index_column = columns
        .iter()
        .position(|column| matches!(*column, "index" | "segment_index"))
        .ok_or_else(|| "segments.csv has no index column".to_string())?;
    let path_column = columns
        .iter()
        .position(|column| matches!(*column, "path" | "source_path" | "file"))
        .ok_or_else(|| "segments.csv has no path column".to_string())?;
    let closed_column = columns
        .iter()
        .position(|column| matches!(*column, "closed" | "complete"))
        .ok_or_else(|| "segments.csv has no closed column".to_string())?;
    let size_column = columns
        .iter()
        .position(|column| *column == "size_bytes")
        .ok_or_else(|| "segments.csv has no size_bytes column".to_string())?;
    let sha256_column = columns
        .iter()
        .position(|column| *column == "sha256")
        .ok_or_else(|| "segments.csv has no sha256 column".to_string())?;
    let required_columns = index_column
        .max(path_column)
        .max(closed_column)
        .max(size_column)
        .max(sha256_column)
        + 1;
    let mut segments = Vec::new();
    for line in lines {
        if line.contains('"') {
            return Err("quoted segments.csv fields are unsupported and fail closed".to_string());
        }
        let values: Vec<&str> = line.split(',').map(str::trim).collect();
        if values.len() < required_columns {
            return Err("segments.csv row has too few columns".to_string());
        }
        let index = values[index_column]
            .parse::<u64>()
            .map_err(|_| "segments.csv index is not an integer".to_string())?;
        let path = values[path_column].to_string();
        let closed = match values[closed_column] {
            "1" | "true" | "complete" | "closed" => true,
            "0" | "false" | "open" | "partial" => false,
            _ => return Err("segments.csv closed value is invalid".to_string()),
        };
        let size_bytes = values[size_column]
            .parse::<u64>()
            .map_err(|_| "segments.csv size_bytes is not an integer".to_string())?;
        let sha256 = values[sha256_column].to_string();
        if !is_sha256_hex(&sha256) {
            return Err("segments.csv sha256 is invalid".to_string());
        }
        segments.push(CsvSegment {
            index,
            path,
            closed,
            size_bytes,
            sha256,
        });
    }
    Ok(segments)
}

#[allow(clippy::too_many_arguments)]
fn make_candidate(
    context: &DetectionContext<'_>,
    schema: SourceSchema,
    session_id: String,
    revision_claim: SourceRevisionClaim,
    inventory: Vec<SourceArtifactClaim>,
    media_plan: SourceMediaPlan,
    trust_verdicts: SourceTrustVerdicts,
    readiness: CandidateReadiness,
    report: ValidationReport,
    signed_publication: Option<SignedPublicationMaterial>,
    marker_material: &[u8],
    source_kind: SourceKind,
) -> DetectionResult {
    let candidate_id = candidate_id(context, marker_material);
    let locator = MediaLocator::new(
        context.source_id.clone(),
        context.media_generation.cloned(),
        context.candidate_relative_path.clone(),
    );
    match ScanCandidate::new(
        candidate_id,
        revision_claim,
        source_kind,
        schema,
        session_id,
        locator,
        inventory,
        media_plan,
        trust_verdicts,
        readiness,
        report,
        signed_publication,
    ) {
        Ok(candidate) => DetectionResult::Candidate(Box::new(candidate)),
        Err(error) => model_rejected(error.to_string()),
    }
}

fn candidate_id(context: &DetectionContext<'_>, marker_material: &[u8]) -> CandidateId {
    let mut hasher = Sha256::new();
    hasher.update(context.source_id.as_str().as_bytes());
    if let Some(generation) = context.media_generation {
        hasher.update(generation.id().as_str().as_bytes());
    }
    if let Some(relative) = &context.candidate_relative_path {
        hasher.update(relative.as_str().as_bytes());
    }
    hasher.update(Sha256::digest(marker_material));
    CandidateId::from_digest(hasher.finalize().into())
}

fn provisional_revision(
    marker_material: &[u8],
    inventory: &[SourceArtifactClaim],
) -> CandidateRevision {
    let mut hasher = Sha256::new();
    hasher.update(Sha256::digest(marker_material));
    for artifact in inventory {
        hasher.update(artifact.id().as_str().as_bytes());
        hasher.update([0]);
        hasher.update(artifact.relative_path().as_str().as_bytes());
        hasher.update([0]);
        hasher.update(artifact.size_bytes().to_be_bytes());
        if let Some(digest) = artifact.source_sha256() {
            hasher.update(digest.as_bytes());
        }
    }
    CandidateRevision::from_digest(hasher.finalize().into())
}

fn marker_exists(context: &DetectionContext<'_>, marker: &str) -> Result<bool, DetectionResult> {
    let relative = SafeRelativePath::parse(marker).expect("fixed marker path is safe");
    match open_regular_file_beneath(context.candidate_root, &relative) {
        Ok(_) => Ok(true),
        Err(PathSafetyError::Inspection {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => Ok(false),
        Err(error) => Err(path_resolution_rejected(&relative, error)),
    }
}

fn read_manifest(context: &DetectionContext<'_>, path: &str) -> Result<Vec<u8>, DetectionResult> {
    read_bounded_path(
        context,
        path,
        context.limits.maximum_manifest_bytes(),
        ScanDiagnosticCode::ManifestTooLarge,
    )
}

fn read_small_text(
    context: &DetectionContext<'_>,
    path: &str,
    maximum: u64,
) -> Result<String, DetectionResult> {
    let bytes = read_bounded_path(context, path, maximum, ScanDiagnosticCode::ManifestTooLarge)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::InvalidManifest,
            format!("{path} is not UTF-8"),
        )
    })?;
    Ok(text.trim().to_string())
}

fn read_bounded_path(
    context: &DetectionContext<'_>,
    path: &str,
    maximum: u64,
    limit_code: ScanDiagnosticCode,
) -> Result<Vec<u8>, DetectionResult> {
    let relative = checked_relative_path(context, path)?;
    read_bounded_relative(context, &relative, maximum, limit_code)
}

fn read_bounded_relative(
    context: &DetectionContext<'_>,
    relative: &SafeRelativePath,
    maximum: u64,
    limit_code: ScanDiagnosticCode,
) -> Result<Vec<u8>, DetectionResult> {
    let mut opened = open_regular_file_beneath(context.candidate_root, relative)
        .map_err(|error| path_resolution_rejected(relative, error))?;
    if opened.len() > maximum {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            limit_code,
            format!(
                "source file {:?} exceeds its {maximum}-byte read limit",
                relative.as_str()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len().min(maximum) as usize);
    opened
        .file_mut()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::Io,
                format!(
                    "source file {:?} cannot be read: {error}",
                    relative.as_str()
                ),
            )
        })?;
    opened
        .recheck()
        .map_err(|error| path_resolution_rejected(relative, error))?;
    if bytes.len() as u64 > maximum {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            limit_code,
            format!(
                "source file {:?} grew beyond its read limit",
                relative.as_str()
            ),
        ));
    }
    Ok(bytes)
}

fn checked_relative_path(
    context: &DetectionContext<'_>,
    path: &str,
) -> Result<SafeRelativePath, DetectionResult> {
    validate_relative_path(
        path,
        context.limits.maximum_path_components(),
        context.limits.maximum_path_bytes(),
    )
    .map_err(|error| {
        rejected(
            CandidateReadiness::UnsafePath,
            ScanDiagnosticCode::UnsafeRelativePath,
            format!("source path {path:?} is unsafe: {error}"),
        )
    })?;
    SafeRelativePath::parse(path).map_err(|error| {
        rejected(
            CandidateReadiness::UnsafePath,
            ScanDiagnosticCode::UnsafeRelativePath,
            format!("source path {path:?} is unsafe: {error}"),
        )
    })
}

fn inspect_regular_file(
    context: &DetectionContext<'_>,
    relative: &SafeRelativePath,
) -> Result<u64, DetectionResult> {
    open_regular_file_beneath(context.candidate_root, relative)
        .map(|opened| opened.len())
        .map_err(|error| path_resolution_rejected(relative, error))
}

fn path_resolution_rejected(
    relative: &SafeRelativePath,
    error: PathSafetyError,
) -> DetectionResult {
    if matches!(
        error,
        PathSafetyError::Inspection {
            kind: std::io::ErrorKind::NotFound,
            ..
        }
    ) {
        rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::MissingRequiredFile,
            format!(
                "required source path {:?} is missing: {error}",
                relative.as_str()
            ),
        )
    } else {
        rejected(
            CandidateReadiness::UnsafePath,
            ScanDiagnosticCode::NonRegularFile,
            format!("source path {:?} is unsafe: {error}", relative.as_str()),
        )
    }
}

fn append_required_metadata(
    context: &DetectionContext<'_>,
    inventory: &mut Vec<SourceArtifactClaim>,
    files: &[(&str, &str, SourceArtifactRole)],
) -> Result<(), DetectionResult> {
    for (id, path_text, role) in files {
        let path = checked_relative_path(context, path_text)?;
        let size = inspect_regular_file(context, &path)?;
        let claim = SourceArtifactClaim::new(
            SourceArtifactId::parse(*id).expect("fixed metadata id"),
            path,
            *role,
            size,
            None,
            Some(
                if path_text.ends_with(".csv") {
                    "text/csv"
                } else if path_text.ends_with(".jsonl") {
                    "application/x-ndjson"
                } else {
                    "application/json"
                }
                .to_string(),
            ),
        )
        .map_err(|error| model_rejected(error.to_string()))?;
        inventory.push(claim);
    }
    Ok(())
}

fn append_optional_metadata(
    context: &DetectionContext<'_>,
    inventory: &mut Vec<SourceArtifactClaim>,
    id: &str,
    path_text: &str,
    role: SourceArtifactRole,
) -> Result<(), DetectionResult> {
    let path = checked_relative_path(context, path_text)?;
    let size = match inspect_regular_file(context, &path) {
        Ok(size) => size,
        Err(DetectionResult::Rejected { diagnostics, .. })
            if diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == ScanDiagnosticCode::MissingRequiredFile) =>
        {
            return Ok(())
        }
        Err(result) => return Err(result),
    };
    let claim = SourceArtifactClaim::new(
        SourceArtifactId::parse(id).expect("fixed optional metadata id"),
        path,
        role,
        size,
        None,
        Some("application/x-ndjson".to_string()),
    )
    .map_err(|error| model_rejected(error.to_string()))?;
    inventory.push(claim);
    Ok(())
}

fn enforce_inventory_limits(
    context: &DetectionContext<'_>,
    inventory: &[SourceArtifactClaim],
) -> Result<(), DetectionResult> {
    if inventory.len() > context.limits.maximum_files_per_candidate() {
        return Err(rejected(
            CandidateReadiness::Corrupt,
            ScanDiagnosticCode::FileCountLimitExceeded,
            "candidate inventory exceeds configured file-count limit",
        ));
    }
    let mut total = 0u64;
    for artifact in inventory {
        total = total.checked_add(artifact.size_bytes()).ok_or_else(|| {
            rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::DeclaredBytesLimitExceeded,
                "candidate inventory byte total overflowed",
            )
        })?;
        if total > context.limits.maximum_declared_bytes_per_candidate() {
            return Err(rejected(
                CandidateReadiness::Corrupt,
                ScanDiagnosticCode::DeclaredBytesLimitExceeded,
                "candidate inventory exceeds configured byte limit",
            ));
        }
    }
    Ok(())
}

fn validate_frame_index(
    bytes: &[u8],
    video_size: Option<u64>,
    maximum_records: usize,
) -> Result<usize, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "frame index is not UTF-8".to_string())?;
    let mut records = 0usize;
    let mut previous_index = None;
    let mut previous_sequence = None;
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records = records.saturating_add(1);
        if records > maximum_records {
            return Err("frame index exceeds configured record limit".to_string());
        }
        let value: Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "frame index line {} is invalid JSON: {error}",
                line_index + 1
            )
        })?;
        if let Some(index) = first_u64(&value, &["/frame_index", "/output_frame_index", "/index"]) {
            if previous_index.is_some_and(|previous| index != previous + 1) {
                return Err(format!("frame index has a gap at line {}", line_index + 1));
            }
            previous_index = Some(index);
        }
        if let Some(sequence) = first_u64(
            &value,
            &["/capture_sequence", "/sequence", "/sequence_number"],
        ) {
            if previous_sequence.is_some_and(|previous| sequence != previous + 1) {
                return Err(format!(
                    "capture sequence has a gap at line {}",
                    line_index + 1
                ));
            }
            previous_sequence = Some(sequence);
        }
        if let Some(video_size) = video_size {
            let offset = first_u64(&value, &["/jpeg_offset", "/offset", "/jpeg/offset"]);
            let length = first_u64(&value, &["/jpeg_length", "/length", "/jpeg/length"]);
            if let (Some(offset), Some(length)) = (offset, length) {
                if length == 0
                    || offset
                        .checked_add(length)
                        .is_none_or(|end| end > video_size)
                {
                    return Err(format!(
                        "JPEG byte range is invalid at line {}",
                        line_index + 1
                    ));
                }
            }
        }
    }
    if records == 0 {
        return Err("frame index contains no records".to_string());
    }
    Ok(records)
}

fn validate_imu_index(bytes: &[u8], maximum_records: usize) -> Result<usize, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "IMU index is not UTF-8".to_string())?;
    let mut records = 0usize;
    let mut previous_index = None;
    let mut previous_timestamp = None;
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records = records.saturating_add(1);
        if records > maximum_records {
            return Err("IMU index exceeds configured record limit".to_string());
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("IMU line {} is invalid JSON: {error}", line_index + 1))?;
        if let Some(index) = first_u64(&value, &["/sample_index", "/index"]) {
            if previous_index.is_some_and(|previous| index != previous + 1) {
                return Err(format!(
                    "IMU sample index has a gap at line {}",
                    line_index + 1
                ));
            }
            previous_index = Some(index);
        }
        let timestamp = first_u64(
            &value,
            &["/timestamp_ns", "/monotonic_timestamp_ns", "/time_ns"],
        )
        .ok_or_else(|| format!("IMU line {} has no timestamp", line_index + 1))?;
        if previous_timestamp.is_some_and(|previous| timestamp <= previous) {
            return Err(format!(
                "IMU timestamp is not monotonic at line {}",
                line_index + 1
            ));
        }
        previous_timestamp = Some(timestamp);
    }
    if records == 0 {
        return Err("IMU index contains no records".to_string());
    }
    Ok(records)
}

fn accepted_report(code: &str) -> ValidationReport {
    ValidationReport::new(vec![
        ValidationCheck::new("schema_recognized", true, code)
            .expect("static validation check is valid"),
        ValidationCheck::new(
            "bounded_inventory",
            true,
            "all declared paths are safe regular files within configured limits",
        )
        .expect("static validation check is valid"),
        ValidationCheck::new(
            "content_hash_pending",
            true,
            "full source and PC-staging hashes are deferred to ImportJob verification",
        )
        .expect("static validation check is valid"),
    ])
    .expect("static validation report is non-empty")
}

fn rejected(
    readiness: CandidateReadiness,
    code: ScanDiagnosticCode,
    message: impl Into<String>,
) -> DetectionResult {
    DetectionResult::Rejected {
        readiness,
        diagnostics: vec![ScanDiagnostic::error(code, message)],
    }
}

fn model_rejected(message: String) -> DetectionResult {
    rejected(
        CandidateReadiness::Corrupt,
        ScanDiagnosticCode::InvalidManifest,
        message,
    )
}

fn map_signed_role(role: &str) -> SourceArtifactRole {
    match role {
        "video_left" => SourceArtifactRole::VideoLeft,
        "video_right" => SourceArtifactRole::VideoRight,
        "video_mono" | "video_stereo" => SourceArtifactRole::VideoStereo,
        "imu" => SourceArtifactRole::Imu,
        _ => SourceArtifactRole::Metadata,
    }
}

fn generated_artifact_id(prefix: &str, index: usize) -> SourceArtifactId {
    SourceArtifactId::parse(format!("{prefix}-{index:05}"))
        .expect("fixed prefix and integer form a safe artifact id")
}

fn string_at<'a>(value: &'a Value, pointers: &[&str]) -> Option<&'a str> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
}

fn bool_at(value: &Value, pointers: &[&str]) -> Option<bool> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_bool))
}

fn first_u64(value: &Value, pointers: &[&str]) -> Option<u64> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_u64))
}

fn any_nonzero_u64(value: &Value, pointers: &[&str]) -> bool {
    pointers.iter().any(|pointer| {
        value
            .pointer(pointer)
            .and_then(Value::as_u64)
            .is_some_and(|number| number > 0)
    })
}

fn any_u64_not_equal(value: &Value, pointers: &[&str], expected: u64) -> bool {
    pointers.iter().any(|pointer| {
        value
            .pointer(pointer)
            .and_then(Value::as_u64)
            .is_some_and(|number| number != expected)
    })
}

fn number_at(value: &Value, pointers: &[&str]) -> Option<f64> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_f64))
}

fn u32_at(value: &Value, pointers: &[&str]) -> Option<u32> {
    first_u64(value, pointers).and_then(|number| u32::try_from(number).ok())
}

fn frame_rate_from_number(number: f64) -> Option<FrameRate> {
    if !number.is_finite() || number <= 0.0 || number > 1_000.0 {
        return None;
    }
    let scaled = (number * 1_000.0).round();
    if scaled <= 0.0 || scaled > u32::MAX as f64 {
        return None;
    }
    FrameRate::new(scaled as u32, 1_000).ok()
}

fn is_sha256_hex(value: &str) -> bool {
    is_lower_hex_exact(value, 64)
}

fn is_lower_hex_exact(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn short_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_string()
}
