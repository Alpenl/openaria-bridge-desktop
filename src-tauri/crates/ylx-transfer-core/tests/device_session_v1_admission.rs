use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use ylx_transfer_core::ingest::{
    AcquisitionSourceId, CandidateId, CandidateReadiness, CandidateRevision, ConstrainedScanner,
    FrameRate, ScanItemOutcome, ScanLimits, ScanRequest, SourceArtifactRole, SourceKind,
    SourceRevisionClaim, SourceSchema, SourceVideoCodec, StereoLayout,
};

const SESSION_ID: &str = "01989f6a-2c00-7a1b-8c2d-3e4f50617283";
const SOURCE_ID: &str = "device-session-v1-test-source";
const CENTRAL_SCHEMA_SHA256: &str =
    "9292820ba81b518c17fd580de49bfd1c92a3519242abf4eb29bbe05f96a02b9c";
const CENTRAL_V2_SCHEMA_SHA256: &str =
    "8dc6096981f3fc50f9b4418000431955e0ba9424c7c0257cd2e129251a6a715b";
const CENTRAL_FIXTURE_SNAPSHOT: &str = "1f026c9d0273186acc35f465014aa25029bd6863";
const CONTRACT_IDENTITY: &str =
    include_str!("../../../../fixtures/device-session-v1/contract-identity.json");
const VENDORED_CONTRACT_ROOT: &str = "../../../fixtures/device-session-v1/central";

const CENTRAL_VALID_DEVICE_SESSION_FIXTURES: &[&str] = &[
    "fixtures/valid/ylx-device-session-v1.json",
    "fixtures/valid/ylx-device-session-v1.continuation.json",
    "fixtures/valid/ylx-device-session-v1.multi-segment.json",
    "fixtures/valid/ylx-device-session-v1.raw-side-by-side.json",
    "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    "fixtures/valid/ylx-device-session-v2.audio-recorded-multi-segment.json",
    "fixtures/valid/ylx-device-session-v2.audio-not-recorded.json",
];

const CENTRAL_INVALID_DEVICE_SESSION_V1_LOCAL_FIXTURES: &[(&str, CandidateReadiness)] = &[
    (
        "fixtures/invalid/ylx-device-session-v1.unsealed.json",
        CandidateReadiness::Corrupt,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.sealed-before-verification.json",
        CandidateReadiness::Corrupt,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.adjacent-drop-events.json",
        CandidateReadiness::Corrupt,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.frame-count-mismatch.json",
        CandidateReadiness::Corrupt,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.effective-fps-mismatch.json",
        CandidateReadiness::Corrupt,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.role-media-type-mismatch.json",
        CandidateReadiness::Corrupt,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.unsafe-path-segments.json",
        CandidateReadiness::UnsafePath,
    ),
    (
        "fixtures/invalid/ylx-device-session-v1.duplicate-artifact-path.json",
        CandidateReadiness::Corrupt,
    ),
];

const CENTRAL_INVALID_DEVICE_SESSION_CLOSED_CORPUS_FIXTURE: &str =
    "fixtures/invalid/ylx-device-session-v1.successor-without-predecessor.json";

const CENTRAL_INVALID_DEVICE_SESSION_V2_FIXTURES: &[&str] = &[
    "fixtures/invalid/ylx-device-session-v2.missing-audio.json",
    "fixtures/invalid/ylx-device-session-v2.raw-imu-opencv-frame.json",
    "fixtures/invalid/ylx-device-session-v2.audio-recorded-missing-artifact.json",
    "fixtures/invalid/ylx-device-session-v2.audio-not-recorded-extra-artifact.json",
    "fixtures/invalid/ylx-device-session-v2.audio-segment-gap.json",
    "fixtures/invalid/ylx-device-session-v2.audio-sample-rate-time-mismatch.json",
    "fixtures/invalid/ylx-device-session-v2.audio-segment-sample-time-mismatch.json",
    "fixtures/invalid/ylx-device-session-v2.audio-sample-count-mismatch.json",
    "fixtures/invalid/ylx-device-session-v2.audio-channel-payload-mismatch.json",
    "fixtures/invalid/ylx-device-session-v2.audio-file-bytes-mismatch.json",
    "fixtures/invalid/ylx-device-session-v2.audio-zero-recorded-domain.json",
    "fixtures/invalid/ylx-device-session-v2.audio-header-file-inconsistency.json",
    "fixtures/invalid/ylx-device-session-v2.audio-sync-out-of-bounds.json",
    "fixtures/invalid/ylx-device-session-v2.duplicate-audio-path.json",
];

#[derive(Clone)]
struct ArtifactInput {
    path: &'static str,
    role: &'static str,
    media_type: &'static str,
    bytes: &'static [u8],
}

#[derive(Clone, Copy)]
enum VideoFixture {
    SplitEyes,
    RawSideBySide,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_artifact(root: &Path, input: &ArtifactInput) -> Value {
    let path = root.join(input.path);
    fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact directory");
    fs::write(&path, input.bytes).expect("write artifact");
    let digest = sha256_hex(input.bytes);
    json!({
        "artifact_id": digest,
        "role": input.role,
        "path": input.path,
        "media_type": input.media_type,
        "bytes": input.bytes.len() as u64,
        "sha256": digest,
    })
}

fn manifest_only_artifact(
    digest_prefix: char,
    path: &'static str,
    role: &'static str,
    media_type: &'static str,
    bytes: u64,
) -> Value {
    let digest = digest_prefix.to_string().repeat(64);
    json!({
        "artifact_id": digest,
        "role": role,
        "path": path,
        "media_type": media_type,
        "bytes": bytes,
        "sha256": digest,
    })
}

fn write_manifest(root: &Path, video: VideoFixture, pretty: bool) -> Vec<u8> {
    let imu = write_artifact(
        root,
        &ArtifactInput {
            path: "imu/imu.jsonl",
            role: "imu.samples",
            media_type: "application/x-ndjson",
            bytes: b"{\"sample_index\":0,\"timestamp_ns\":100}\n",
        },
    );
    let frames = write_artifact(
        root,
        &ArtifactInput {
            path: "imu/frames.jsonl",
            role: "frames.index",
            media_type: "application/x-ndjson",
            bytes: b"{\"index\":0}\n{\"index\":1}\n",
        },
    );
    let (video_value, frame_count, effective_fps) = match video {
        VideoFixture::SplitEyes => {
            let left = write_artifact(
                root,
                &ArtifactInput {
                    path: "video/left_00000.mp4",
                    role: "video.left",
                    media_type: "video/mp4",
                    bytes: b"left eye bytes\n",
                },
            );
            let right = write_artifact(
                root,
                &ArtifactInput {
                    path: "video/right_00000.mp4",
                    role: "video.right",
                    media_type: "video/mp4",
                    bytes: b"right eye bytes\n",
                },
            );
            (
                json!({
                    "layout": "split-eyes",
                    "codec": "h264",
                    "container": "mp4",
                    "segments": [{
                        "index": 0,
                        "start_frame": 0,
                        "end_frame": 2,
                        "start_time_seconds": 0,
                        "end_time_seconds": 1,
                        "artifacts": {
                            "left": left,
                            "right": right,
                        }
                    }]
                }),
                2_u64,
                2.0_f64,
            )
        }
        VideoFixture::RawSideBySide => {
            let stereo = write_artifact(
                root,
                &ArtifactInput {
                    path: "video/stereo.mjpeg",
                    role: "video.raw-side-by-side",
                    media_type: "video/x-motion-jpeg",
                    bytes: b"raw side by side mjpeg bytes\n",
                },
            );
            (
                json!({
                    "layout": "raw-side-by-side",
                    "codec": "mjpeg",
                    "continuous": true,
                    "artifact": stereo,
                }),
                2_u64,
                2.0_f64,
            )
        }
    };
    let manifest = json!({
        "schema": "ylx.device-session.v1",
        "manifest_id": "01989f6a-2c01-7b2c-9d3e-4f5061728394",
        "sealed": true,
        "sealed_at": "2026-08-08T10:24:33+08:00",
        "session_id": SESSION_ID,
        "volume_id": "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "capture_mode": "production",
        "display_name": "2026-08-08_10-24-00_YLX-30D5872D",
        "device": {
            "device_id": "550e8400-e29b-41d4-a716-446655440000",
            "device_label": "YLX-30D5872D",
            "hardware_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "platform": "rdk-x5",
            "software_version": "0.10.0-dev.1",
            "commit": "2db57ae68e04197397b8ac84f4d71548aa2fcb36"
        },
        "time": {
            "started_at": "2026-08-08T10:24:00+08:00",
            "ended_at": "2026-08-08T10:24:01+08:00",
            "timezone": "Asia/Shanghai",
            "duration_seconds": 1,
            "duration_clock": "host_monotonic"
        },
        "take": {
            "take_id": "01989f69-f000-7c3d-ae4f-5061728394a5",
            "sequence": 1,
            "continuation_of": null
        },
        "camera": {
            "width": 3840,
            "height": 1080,
            "eye_width": 1920,
            "sensor_fps": 60,
            "frame_decimation": 30,
            "nominal_fps": 2,
            "effective_fps": effective_fps,
            "coordinate_frame": "opencv_optical"
        },
        "video": video_value,
        "imu": {
            "artifact": imu,
            "sample_count": 1,
            "units": "raw_int16",
            "coordinate_frame": "opencv_optical"
        },
        "frames": {
            "artifact": frames,
            "count": frame_count
        },
        "logs": [],
        "integrity": {
            "verified_at": "2026-08-08T10:24:32.800+08:00",
            "dropped_frames": 0,
            "drop_events": [],
            "quality_policy": {
                "policy_id": "rdk-x5-lossless-v1",
                "max_contiguous_dropped_frames": 0,
                "max_total_dropped_frames": 0,
                "max_drop_fraction": 0,
                "window_seconds": 1,
                "max_dropped_frames_per_window": 0
            },
            "fatal_errors": []
        }
    });
    let bytes = if pretty {
        serde_json::to_vec_pretty(&manifest).expect("pretty manifest")
    } else {
        serde_json::to_vec(&manifest).expect("compact manifest")
    };
    fs::write(root.join("manifest.json"), &bytes).expect("write manifest");
    bytes
}

fn write_manifest_value(root: &Path, manifest: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(manifest).expect("manifest json");
    fs::write(root.join("manifest.json"), &bytes).expect("write manifest");
    bytes
}

fn write_central_manifest(root: &Path, fixture: &str) -> Value {
    let manifest_bytes = fs::read(vendored_contract_path(fixture)).expect("central fixture");
    fs::write(root.join("manifest.json"), &manifest_bytes).expect("write manifest only");
    serde_json::from_slice(&manifest_bytes).expect("central manifest json")
}

fn wav_pcm_s16le(sample_rate: u32, channels: u16, sample_count: u32, fill: u8) -> Vec<u8> {
    let block_align = channels.checked_mul(2).expect("block align");
    let payload_bytes = sample_count
        .checked_mul(u32::from(block_align))
        .expect("payload bytes");
    let chunk_size = 36_u32.checked_add(payload_bytes).expect("riff chunk size");
    let byte_rate = sample_rate
        .checked_mul(u32::from(block_align))
        .expect("byte rate");
    let mut bytes = Vec::with_capacity(44 + payload_bytes as usize);
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&chunk_size.to_le_bytes());
    bytes.extend_from_slice(b"WAVE");
    bytes.extend_from_slice(b"fmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&channels.to_le_bytes());
    bytes.extend_from_slice(&sample_rate.to_le_bytes());
    bytes.extend_from_slice(&byte_rate.to_le_bytes());
    bytes.extend_from_slice(&block_align.to_le_bytes());
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&payload_bytes.to_le_bytes());
    bytes.resize(44 + payload_bytes as usize, fill);
    bytes
}

fn install_single_segment_audio(
    root: &Path,
    manifest: &mut Value,
    sample_rate: u32,
    channels: u16,
    sample_count: u32,
) -> Vec<u8> {
    let wav = wav_pcm_s16le(sample_rate, channels, sample_count, 0);
    install_audio_bytes(root, manifest, wav, 44, sample_rate, channels, sample_count)
}

fn install_audio_bytes(
    root: &Path,
    manifest: &mut Value,
    wav: Vec<u8>,
    wav_header_bytes: u64,
    sample_rate: u32,
    channels: u16,
    sample_count: u32,
) -> Vec<u8> {
    let path = "audio/audio.wav";
    let audio_path = root.join(path);
    fs::create_dir_all(audio_path.parent().expect("audio parent")).expect("audio dir");
    fs::write(&audio_path, &wav).expect("write wav");
    let digest = sha256_hex(&wav);
    let payload_bytes = u64::from(sample_count) * u64::from(channels) * 2;
    manifest["audio"] = json!({
        "state": "recorded",
        "requested_mode": "enabled",
        "resolved_mode": "enabled",
        "codec": "pcm_s16le",
        "container": "wav",
        "sample_format": "S16_LE",
        "sample_rate": sample_rate,
        "channels": channels,
        "sample_count": sample_count,
        "sync": {
            "time_base": "host_monotonic",
            "start_time_seconds": 0,
            "end_time_seconds": f64::from(sample_count) / f64::from(sample_rate),
            "video_time_reference": "session_time_seconds"
        },
        "segments": [{
            "index": 0,
            "start_sample": 0,
            "end_sample": sample_count,
            "start_time_seconds": 0,
            "end_time_seconds": f64::from(sample_count) / f64::from(sample_rate),
            "pcm_payload_bytes": payload_bytes,
            "wav_header_bytes": wav_header_bytes,
            "artifact": {
                "artifact_id": digest,
                "role": "audio.wav",
                "path": path,
                "media_type": "audio/wav",
                "bytes": wav.len() as u64,
                "sha256": digest
            }
        }]
    });
    write_manifest_value(root, manifest)
}

fn detect(root: &Path) -> ScanItemOutcome {
    detect_with_kind(root, SourceKind::RemovableMedia)
}

fn detect_with_kind(root: &Path, source_kind: SourceKind) -> ScanItemOutcome {
    let source_id = AcquisitionSourceId::parse(SOURCE_ID).expect("source id");
    let request =
        ScanRequest::selected_directory(root, source_id, source_kind, None).expect("scan request");

    ConstrainedScanner::new(ScanLimits::default())
        .scan(&request)
        .items()
        .first()
        .expect("the selected directory is always inspected")
        .outcome()
        .clone()
}

fn candidate_id_for_manifest_bytes(bytes: &[u8]) -> CandidateId {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_ID.as_bytes());
    hasher.update(Sha256::digest(bytes));
    CandidateId::from_digest(hasher.finalize().into())
}

fn revision_for_manifest_bytes(bytes: &[u8]) -> SourceRevisionClaim {
    SourceRevisionClaim::Provisional(CandidateRevision::from_digest(Sha256::digest(bytes).into()))
}

fn vendored_contract_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(VENDORED_CONTRACT_ROOT)
        .join(relative)
}

fn vendored_path_for_source_contract_path(source_path: &str) -> PathBuf {
    let relative = source_path
        .strip_prefix("contracts/")
        .unwrap_or_else(|| panic!("source contract path {source_path:?} must be under contracts/"));
    vendored_contract_path(relative)
}

fn sha256_file_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    sha256_hex(&bytes)
}

fn collect_regular_files(root: &Path, directory: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        let metadata = entry
            .metadata()
            .unwrap_or_else(|error| panic!("metadata {}: {error}", path.display()));
        if metadata.is_dir() {
            collect_regular_files(root, &path, files);
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("descendant path")
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(relative);
        } else {
            panic!(
                "unexpected non-regular vendored contract entry {}",
                path.display()
            );
        }
    }
}

fn mutate_manifest(root: &Path, mut mutate: impl FnMut(&mut Value)) {
    let path = root.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&path).expect("read manifest")).expect("parse manifest");
    mutate(&mut manifest);
    fs::write(
        &path,
        serde_json::to_vec(&manifest).expect("mutated manifest"),
    )
    .expect("write mutated manifest");
}

fn expect_rejected(root: &Path, expected_readiness: CandidateReadiness) {
    let ScanItemOutcome::Rejected { readiness, .. } = detect(root) else {
        panic!("manifest must be rejected");
    };
    assert_eq!(readiness, expected_readiness);
}

#[test]
fn pins_the_central_device_session_v1_contract_identity() {
    let identity: Value = serde_json::from_str(CONTRACT_IDENTITY).expect("contract identity json");
    assert_eq!(
        identity["source_snapshot"].as_str(),
        Some(CENTRAL_FIXTURE_SNAPSHOT)
    );
    assert_eq!(
        identity["local_authority"].as_str(),
        Some("per_file_sha256")
    );
    assert_eq!(identity["contract_file_count"].as_u64(), Some(32));
    let schemas = identity["schemas"].as_array().expect("schemas array");
    assert!(schemas.iter().any(|schema| {
        schema["discriminator"].as_str() == Some("ylx.device-session.v1")
            && schema["sha256"].as_str() == Some(CENTRAL_SCHEMA_SHA256)
    }));
    assert!(schemas.iter().any(|schema| {
        schema["discriminator"].as_str() == Some("ylx.device-session.v2")
            && schema["sha256"].as_str() == Some(CENTRAL_V2_SCHEMA_SHA256)
    }));
    assert_eq!(
        identity["runtime_gate"]["reference_files"].as_str(),
        Some(
            "Reference-only conformance material; no script from the snapshot is executed at runtime."
        )
    );
}

#[test]
fn vendored_contract_tree_is_reference_only_and_hash_checked() {
    let identity: Value = serde_json::from_str(CONTRACT_IDENTITY).expect("contract identity json");
    let central_root = vendored_contract_path("");
    let mut expected_files = BTreeSet::new();

    let mut identity_contract_files = BTreeSet::new();
    for file in identity["contract_files"]
        .as_array()
        .expect("contract files array")
    {
        let source_path = file["path"].as_str().expect("contract file path");
        let expected_hash = file["sha256"].as_str().expect("contract file sha");
        assert_eq!(
            sha256_file_hex(&vendored_path_for_source_contract_path(source_path)),
            expected_hash,
            "{source_path}"
        );
        let relative = source_path
            .strip_prefix("contracts/")
            .expect("source contract path")
            .to_string();
        expected_files.insert(relative.clone());
        identity_contract_files.insert(relative);
    }
    assert_eq!(
        identity_contract_files.len() as u64,
        identity["contract_file_count"]
            .as_u64()
            .expect("contract file count")
    );

    for schema in identity["schemas"].as_array().expect("schemas array") {
        let source_path = schema["path"].as_str().expect("schema path");
        let expected_hash = schema["sha256"].as_str().expect("schema sha");
        assert_eq!(
            sha256_file_hex(&vendored_path_for_source_contract_path(source_path)),
            expected_hash,
            "{source_path}"
        );
        expected_files.insert(
            source_path
                .strip_prefix("contracts/")
                .expect("source contract path")
                .to_string(),
        );
    }

    let mut identity_valid = BTreeSet::new();
    for fixture in identity["valid_fixtures"]
        .as_array()
        .expect("valid fixtures array")
    {
        let source_path = fixture["path"].as_str().expect("fixture path");
        let expected_hash = fixture["sha256"].as_str().expect("fixture sha");
        assert_eq!(
            sha256_file_hex(&vendored_path_for_source_contract_path(source_path)),
            expected_hash,
            "{source_path}"
        );
        let relative = source_path
            .strip_prefix("contracts/")
            .expect("source contract path")
            .to_string();
        expected_files.insert(relative.clone());
        identity_valid.insert(relative);
    }

    let mut identity_invalid = BTreeSet::new();
    for fixture in identity["invalid_fixtures"]
        .as_array()
        .expect("invalid fixtures array")
    {
        let source_path = fixture["path"].as_str().expect("fixture path");
        let expected_hash = fixture["sha256"].as_str().expect("fixture sha");
        assert_eq!(
            sha256_file_hex(&vendored_path_for_source_contract_path(source_path)),
            expected_hash,
            "{source_path}"
        );
        let relative = source_path
            .strip_prefix("contracts/")
            .expect("source contract path")
            .to_string();
        expected_files.insert(relative.clone());
        identity_invalid.insert(relative);
    }

    let expected_valid = CENTRAL_VALID_DEVICE_SESSION_FIXTURES
        .iter()
        .map(|path| (*path).to_string())
        .collect::<BTreeSet<_>>();
    let mut expected_invalid = CENTRAL_INVALID_DEVICE_SESSION_V1_LOCAL_FIXTURES
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect::<BTreeSet<_>>();
    expected_invalid.insert(CENTRAL_INVALID_DEVICE_SESSION_CLOSED_CORPUS_FIXTURE.to_string());
    expected_invalid.extend(
        CENTRAL_INVALID_DEVICE_SESSION_V2_FIXTURES
            .iter()
            .map(|path| (*path).to_string()),
    );

    assert_eq!(identity_valid, expected_valid);
    assert_eq!(identity_invalid, expected_invalid);

    let mut actual_files = BTreeSet::new();
    collect_regular_files(&central_root, &central_root, &mut actual_files);
    assert_eq!(actual_files, expected_files);
}

#[test]
fn split_eye_device_session_v1_is_admitted_with_exact_manifest_bytes_identity() {
    let directory = tempfile::tempdir().expect("tempdir");
    let manifest_bytes = write_manifest(directory.path(), VideoFixture::SplitEyes, true);

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("valid device session v1 must be admitted");
    };

    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV1);
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::PendingArtifactValidation
    );
    assert_eq!(candidate.session_id(), SESSION_ID);
    assert_eq!(
        candidate.id(),
        &candidate_id_for_manifest_bytes(&manifest_bytes)
    );
    assert_eq!(
        candidate.revision_claim(),
        &revision_for_manifest_bytes(&manifest_bytes)
    );

    let plan = candidate.media_plan();
    assert_eq!(plan.codec(), SourceVideoCodec::H264);
    assert_eq!(plan.layout(), StereoLayout::SeparateEyes);
    assert_eq!(plan.frame_dimensions(), Some((1920, 1080)));
    assert_eq!(plan.frame_rate(), Some(FrameRate::new(2000, 1000).unwrap()));
    assert_eq!(plan.segment_count(), 1);
    assert_eq!(plan.raw_frame_count(), Some(2));

    let roles = candidate
        .inventory()
        .iter()
        .map(|claim| claim.role())
        .collect::<Vec<_>>();
    assert!(roles.contains(&SourceArtifactRole::VideoLeft));
    assert!(roles.contains(&SourceArtifactRole::VideoRight));
    assert!(roles.contains(&SourceArtifactRole::Imu));
    assert!(roles.contains(&SourceArtifactRole::FrameIndex));
    assert!(roles.contains(&SourceArtifactRole::SessionManifest));
}

#[test]
fn central_valid_device_session_corpus_scans_as_pending_without_artifact_files() {
    for fixture in CENTRAL_VALID_DEVICE_SESSION_FIXTURES {
        let directory = tempfile::tempdir().expect("tempdir");
        let manifest_bytes = fs::read(vendored_contract_path(fixture)).expect("central fixture");
        fs::write(directory.path().join("manifest.json"), &manifest_bytes)
            .expect("write manifest only");

        let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
            panic!("{fixture} should scan as a pending Device Session candidate");
        };

        let expected_schema = if fixture.contains("device-session-v2") {
            SourceSchema::DeviceSessionV2
        } else {
            SourceSchema::DeviceSessionV1
        };
        assert_eq!(candidate.schema(), expected_schema, "{fixture}");
        assert_eq!(
            candidate.readiness(),
            CandidateReadiness::PendingArtifactValidation,
            "{fixture}"
        );
        assert_eq!(
            candidate.revision_claim(),
            &revision_for_manifest_bytes(&manifest_bytes),
            "{fixture}"
        );
        assert!(
            candidate
                .inventory()
                .iter()
                .all(|claim| claim.source_sha256().is_some()),
            "{fixture}"
        );
    }
}

#[test]
fn central_invalid_device_session_local_corpus_fails_closed() {
    for (fixture, expected_readiness) in CENTRAL_INVALID_DEVICE_SESSION_V1_LOCAL_FIXTURES {
        let directory = tempfile::tempdir().expect("tempdir");
        let manifest_bytes = fs::read(vendored_contract_path(fixture)).expect("central fixture");
        fs::write(directory.path().join("manifest.json"), &manifest_bytes)
            .expect("write manifest only");

        let ScanItemOutcome::Rejected { readiness, .. } = detect(directory.path()) else {
            panic!("{fixture} should be rejected by the Device Session transfer gate");
        };
        assert_eq!(readiness, *expected_readiness, "{fixture}");
    }
}

#[test]
fn central_invalid_device_session_v2_corpus_fails_closed() {
    for fixture in CENTRAL_INVALID_DEVICE_SESSION_V2_FIXTURES {
        let directory = tempfile::tempdir().expect("tempdir");
        let manifest_bytes = fs::read(vendored_contract_path(fixture)).expect("central fixture");
        fs::write(directory.path().join("manifest.json"), &manifest_bytes)
            .expect("write manifest only");

        let ScanItemOutcome::Rejected { readiness, .. } = detect(directory.path()) else {
            panic!("{fixture} should be rejected by the Device Session transfer gate");
        };
        assert_eq!(readiness, CandidateReadiness::Corrupt, "{fixture}");
    }
}

#[test]
fn central_closed_corpus_successor_fixture_is_not_promoted_to_ready() {
    let directory = tempfile::tempdir().expect("tempdir");
    let manifest_bytes = fs::read(vendored_contract_path(
        CENTRAL_INVALID_DEVICE_SESSION_CLOSED_CORPUS_FIXTURE,
    ))
    .expect("central fixture");
    fs::write(directory.path().join("manifest.json"), &manifest_bytes).expect("write manifest");

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("a single successor manifest is a partial-view candidate, not a Ready recording");
    };
    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV1);
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::PendingArtifactValidation
    );
}

#[test]
fn raw_side_by_side_device_session_v1_is_admitted_without_calibration_claims() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_manifest(directory.path(), VideoFixture::RawSideBySide, false);

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("valid raw-side-by-side device session v1 must be admitted");
    };

    let plan = candidate.media_plan();
    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV1);
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::PendingArtifactValidation
    );
    assert_eq!(plan.codec(), SourceVideoCodec::Mjpeg);
    assert_eq!(plan.layout(), StereoLayout::LeftRightSideBySide);
    assert_eq!(plan.frame_dimensions(), Some((3840, 1080)));
    assert_eq!(plan.raw_frame_count(), Some(2));
}

#[test]
fn recorded_device_session_v2_is_admitted_with_raw_imu_and_audio_inventory() {
    let directory = tempfile::tempdir().expect("tempdir");
    let manifest_bytes = fs::read(vendored_contract_path(
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    ))
    .expect("central v2 fixture");
    fs::write(directory.path().join("manifest.json"), &manifest_bytes).expect("write manifest");

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("valid recorded Device Session v2 must be admitted");
    };

    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV2);
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::PendingArtifactValidation
    );
    assert_eq!(
        candidate.revision_claim(),
        &revision_for_manifest_bytes(&manifest_bytes)
    );
    let roles = candidate
        .inventory()
        .iter()
        .map(|claim| claim.role())
        .collect::<Vec<_>>();
    assert!(roles.contains(&SourceArtifactRole::Audio));
    assert!(roles.contains(&SourceArtifactRole::Imu));
    assert!(roles.contains(&SourceArtifactRole::FrameIndex));
    assert!(roles.contains(&SourceArtifactRole::SessionManifest));
}

#[test]
fn not_recorded_device_session_v2_carries_no_audio_artifact() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(
        directory.path().join("manifest.json"),
        fs::read(vendored_contract_path(
            "fixtures/valid/ylx-device-session-v2.audio-not-recorded.json",
        ))
        .expect("central v2 fixture"),
    )
    .expect("write manifest");

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("valid not_recorded Device Session v2 must be admitted");
    };

    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV2);
    assert!(candidate
        .inventory()
        .iter()
        .all(|claim| claim.role() != SourceArtifactRole::Audio));
}

#[test]
fn semantic_equivalent_manifest_uses_exact_bytes_not_reserialized_identity() {
    let pretty = tempfile::tempdir().expect("pretty tempdir");
    let compact = tempfile::tempdir().expect("compact tempdir");
    let pretty_bytes = write_manifest(pretty.path(), VideoFixture::SplitEyes, true);
    let compact_bytes = write_manifest(compact.path(), VideoFixture::SplitEyes, false);
    assert_ne!(pretty_bytes, compact_bytes);

    let ScanItemOutcome::Candidate {
        candidate: pretty_candidate,
    } = detect(pretty.path())
    else {
        panic!("pretty manifest must be admitted");
    };
    let ScanItemOutcome::Candidate {
        candidate: compact_candidate,
    } = detect(compact.path())
    else {
        panic!("compact manifest must be admitted");
    };

    assert_eq!(
        pretty_candidate.id(),
        &candidate_id_for_manifest_bytes(&pretty_bytes)
    );
    assert_eq!(
        compact_candidate.id(),
        &candidate_id_for_manifest_bytes(&compact_bytes)
    );
    assert_ne!(pretty_candidate.id(), compact_candidate.id());
    assert_ne!(
        pretty_candidate.revision_claim(),
        compact_candidate.revision_claim()
    );
}

#[test]
fn reordered_device_session_v2_uses_exact_raw_manifest_bytes_for_identity() {
    let first = tempfile::tempdir().expect("first tempdir");
    let second = tempfile::tempdir().expect("second tempdir");
    let manifest = write_central_manifest(
        first.path(),
        "fixtures/valid/ylx-device-session-v2.audio-not-recorded.json",
    );
    let first_bytes = fs::read(first.path().join("manifest.json")).expect("first manifest");
    let compact_bytes = write_manifest_value(second.path(), &manifest);
    assert_ne!(first_bytes, compact_bytes);

    let ScanItemOutcome::Candidate {
        candidate: first_candidate,
    } = detect(first.path())
    else {
        panic!("first v2 manifest must be admitted");
    };
    let ScanItemOutcome::Candidate {
        candidate: compact_candidate,
    } = detect(second.path())
    else {
        panic!("compact v2 manifest must be admitted");
    };

    assert_eq!(
        first_candidate.id(),
        &candidate_id_for_manifest_bytes(&first_bytes)
    );
    assert_eq!(
        compact_candidate.id(),
        &candidate_id_for_manifest_bytes(&compact_bytes)
    );
    assert_ne!(first_candidate.id(), compact_candidate.id());
}

#[test]
fn lan_and_removable_media_device_session_v2_share_manifest_identity() {
    let directory = tempfile::tempdir().expect("tempdir");
    let manifest_bytes = fs::read(vendored_contract_path(
        "fixtures/valid/ylx-device-session-v2.audio-not-recorded.json",
    ))
    .expect("central v2 fixture");
    fs::write(directory.path().join("manifest.json"), &manifest_bytes).expect("write manifest");

    let ScanItemOutcome::Candidate {
        candidate: media_candidate,
    } = detect_with_kind(directory.path(), SourceKind::RemovableMedia)
    else {
        panic!("removable-media v2 manifest must be admitted");
    };
    let ScanItemOutcome::Candidate {
        candidate: lan_candidate,
    } = detect_with_kind(directory.path(), SourceKind::Lan)
    else {
        panic!("LAN v2 manifest must be admitted");
    };

    assert_eq!(media_candidate.id(), lan_candidate.id());
    assert_eq!(
        media_candidate.revision_claim(),
        lan_candidate.revision_claim()
    );
    assert_eq!(
        media_candidate.revision_claim(),
        &revision_for_manifest_bytes(&manifest_bytes)
    );
}

#[test]
fn mounted_device_session_v2_audio_wav_must_match_header_bytes_and_hash() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    let manifest_bytes =
        install_single_segment_audio(directory.path(), &mut manifest, 48_000, 2, 1_440_000);

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("v2 with a matching 30s 48 kHz stereo WAV must be admitted");
    };
    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV2);
    assert_eq!(
        candidate.revision_claim(),
        &revision_for_manifest_bytes(&manifest_bytes)
    );
}

#[test]
fn mounted_device_session_v2_audio_accepts_8k_mono_byte_domain() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    install_single_segment_audio(directory.path(), &mut manifest, 8_000, 1, 8_000);

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("v2 with a matching 1s 8 kHz mono WAV must be admitted");
    };
    assert_eq!(candidate.schema(), SourceSchema::DeviceSessionV2);
    let audio = candidate
        .inventory()
        .iter()
        .find(|claim| claim.role() == SourceArtifactRole::Audio)
        .expect("audio claim");
    assert_eq!(audio.size_bytes(), 16_044);
}

#[test]
fn mounted_device_session_v2_audio_rejects_29s_sync_for_1440000_samples() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    install_single_segment_audio(directory.path(), &mut manifest, 48_000, 2, 1_440_000);
    mutate_manifest(directory.path(), |manifest| {
        manifest["audio"]["sync"]["end_time_seconds"] = json!(29);
        manifest["audio"]["segments"][0]["end_time_seconds"] = json!(29);
    });

    expect_rejected(directory.path(), CandidateReadiness::Corrupt);
}

#[test]
fn mounted_device_session_v2_audio_rejects_non_wav_even_when_hash_matches() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    let mut bytes = wav_pcm_s16le(8_000, 1, 8_000, 0);
    bytes[0..4].copy_from_slice(b"NOPE");
    install_audio_bytes(directory.path(), &mut manifest, bytes, 44, 8_000, 1, 8_000);

    expect_rejected(directory.path(), CandidateReadiness::Corrupt);
}

#[test]
fn mounted_device_session_v2_audio_rejects_declared_file_bytes_mismatch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    install_single_segment_audio(directory.path(), &mut manifest, 8_000, 2, 8_000);
    mutate_manifest(directory.path(), |manifest| {
        manifest["audio"]["segments"][0]["artifact"]["bytes"] = json!(32_045);
    });

    expect_rejected(directory.path(), CandidateReadiness::Corrupt);
}

#[test]
fn mounted_device_session_v2_audio_rejects_declared_hash_mismatch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    install_single_segment_audio(directory.path(), &mut manifest, 8_000, 2, 8_000);
    mutate_manifest(directory.path(), |manifest| {
        let wrong = "f".repeat(64);
        manifest["audio"]["segments"][0]["artifact"]["artifact_id"] = json!(wrong.clone());
        manifest["audio"]["segments"][0]["artifact"]["sha256"] = json!(wrong);
    });

    expect_rejected(directory.path(), CandidateReadiness::Corrupt);
}

#[test]
fn mounted_device_session_v2_audio_rejects_wav_header_domain_mismatch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut manifest = write_central_manifest(
        directory.path(),
        "fixtures/valid/ylx-device-session-v2.audio-recorded.json",
    );
    let mut bytes = wav_pcm_s16le(8_000, 1, 8_000, 0);
    bytes.extend_from_slice(&[0; 24]);
    install_audio_bytes(directory.path(), &mut manifest, bytes, 68, 8_000, 1, 8_000);

    expect_rejected(directory.path(), CandidateReadiness::Corrupt);
}

#[test]
fn unknown_root_manifest_schema_fails_closed_even_when_legacy_marker_exists() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_manifest(directory.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(directory.path(), |manifest| {
        manifest["schema"] = json!("ylx.device-session.v3");
    });
    fs::write(
        directory.path().join("capture.json"),
        br#"{"schema":"ylx.stereo_imu.raw.v2"}"#,
    )
    .expect("legacy marker");

    expect_rejected(directory.path(), CandidateReadiness::UnsupportedSchema);
}

#[test]
fn legacy_capture_marker_still_dispatches_without_root_manifest() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(directory.path().join("raw")).expect("raw dir");
    fs::write(directory.path().join("stereo.mjpeg"), b"jpeg bytes").expect("video");
    fs::write(
        directory.path().join("frames.jsonl"),
        b"{\"index\":0,\"offset\":0,\"length\":4}\n",
    )
    .expect("frames");
    fs::write(
        directory.path().join("imu.jsonl"),
        b"{\"index\":0,\"timestamp_ns\":100}\n",
    )
    .expect("imu");
    fs::write(
        directory.path().join("capture.json"),
        serde_json::to_vec(&json!({
            "schema": "ylx.stereo_imu.raw.v2",
            "state": "complete",
            "video": {
                "encoding": "mjpeg",
                "transport": "file",
                "persistent": true,
                "layout": "left_right_side_by_side",
                "path": "stereo.mjpeg",
                "size_bytes": 10,
                "frame_count": 1
            },
            "files": {
                "frames": "frames.jsonl",
                "imu": "imu.jsonl"
            },
            "result": {
                "native_capture_ok": true,
                "sequence_gaps": 0,
                "timestamp_errors": 0,
                "imu_sample_count": 1
            }
        }))
        .expect("capture manifest"),
    )
    .expect("capture.json");

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("legacy raw capture marker must still dispatch");
    };
    assert_eq!(candidate.schema(), SourceSchema::RawCaptureV2);
}

#[test]
fn path_traversal_and_reserved_control_paths_fail_closed() {
    let traversal = tempfile::tempdir().expect("traversal tempdir");
    write_manifest(traversal.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(traversal.path(), |manifest| {
        manifest["video"]["segments"][0]["artifacts"]["left"]["path"] = json!("../left.mp4");
    });
    expect_rejected(traversal.path(), CandidateReadiness::UnsafePath);

    let reserved = tempfile::tempdir().expect("reserved tempdir");
    write_manifest(reserved.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(reserved.path(), |manifest| {
        manifest["video"]["segments"][0]["artifacts"]["left"]["path"] = json!("manifest.json");
    });
    expect_rejected(reserved.path(), CandidateReadiness::UnsafePath);
}

#[test]
fn duplicate_artifact_path_or_id_fails_closed() {
    let duplicate_path = tempfile::tempdir().expect("duplicate path tempdir");
    write_manifest(duplicate_path.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(duplicate_path.path(), |manifest| {
        let left = manifest["video"]["segments"][0]["artifacts"]["left"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["path"] = left["path"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["bytes"] = left["bytes"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["sha256"] = left["sha256"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["artifact_id"] =
            left["artifact_id"].clone();
    });
    expect_rejected(duplicate_path.path(), CandidateReadiness::Corrupt);

    let duplicate_id = tempfile::tempdir().expect("duplicate id tempdir");
    write_manifest(duplicate_id.path(), VideoFixture::SplitEyes, false);
    let left_bytes = fs::read(duplicate_id.path().join("video/left_00000.mp4")).expect("left");
    fs::write(
        duplicate_id.path().join("video/right_00000.mp4"),
        left_bytes,
    )
    .expect("rewrite right");
    mutate_manifest(duplicate_id.path(), |manifest| {
        let left = manifest["video"]["segments"][0]["artifacts"]["left"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["sha256"] = left["sha256"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["artifact_id"] =
            left["artifact_id"].clone();
        manifest["video"]["segments"][0]["artifacts"]["right"]["bytes"] = left["bytes"].clone();
    });
    expect_rejected(duplicate_id.path(), CandidateReadiness::Corrupt);
}

#[test]
fn role_media_mismatches_fail_closed_before_import() {
    let role_media = tempfile::tempdir().expect("role tempdir");
    write_manifest(role_media.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(role_media.path(), |manifest| {
        manifest["video"]["segments"][0]["artifacts"]["left"]["media_type"] =
            json!("application/json");
    });
    expect_rejected(role_media.path(), CandidateReadiness::Corrupt);
}

#[test]
fn size_and_hash_mismatches_are_deferred_to_import_validation() {
    let size_mismatch = tempfile::tempdir().expect("size tempdir");
    write_manifest(size_mismatch.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(size_mismatch.path(), |manifest| {
        manifest["video"]["segments"][0]["artifacts"]["left"]["bytes"] = json!(999);
    });
    let ScanItemOutcome::Candidate { candidate } = detect(size_mismatch.path()) else {
        panic!("size mismatch should reach explicit import validation");
    };
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::PendingArtifactValidation
    );

    let hash_mismatch = tempfile::tempdir().expect("hash tempdir");
    write_manifest(hash_mismatch.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(hash_mismatch.path(), |manifest| {
        let digest = "f".repeat(64);
        manifest["video"]["segments"][0]["artifacts"]["left"]["artifact_id"] =
            json!(digest.clone());
        manifest["video"]["segments"][0]["artifacts"]["left"]["sha256"] = json!(digest);
    });
    let ScanItemOutcome::Candidate { candidate } = detect(hash_mismatch.path()) else {
        panic!("hash mismatch should reach explicit import validation");
    };
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::PendingArtifactValidation
    );
}

#[test]
fn central_schema_string_patterns_fail_closed() {
    let timezone = tempfile::tempdir().expect("timezone tempdir");
    write_manifest(timezone.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(timezone.path(), |manifest| {
        manifest["time"]["timezone"] = json!("Asia//Shanghai");
    });
    expect_rejected(timezone.path(), CandidateReadiness::Corrupt);

    let timestamp = tempfile::tempdir().expect("timestamp tempdir");
    write_manifest(timestamp.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(timestamp.path(), |manifest| {
        manifest["sealed_at"] = json!("2026-08-08 10:24:33+08:00");
    });
    expect_rejected(timestamp.path(), CandidateReadiness::Corrupt);

    let log_role = tempfile::tempdir().expect("log role tempdir");
    write_manifest(log_role.path(), VideoFixture::SplitEyes, false);
    let log_artifact = write_artifact(
        log_role.path(),
        &ArtifactInput {
            path: "logs/transform.log",
            role: "log.",
            media_type: "text/plain",
            bytes: b"transform log\n",
        },
    );
    mutate_manifest(log_role.path(), |manifest| {
        manifest["logs"] = json!([log_artifact]);
    });
    expect_rejected(log_role.path(), CandidateReadiness::Corrupt);
}

#[test]
fn central_cross_field_invariants_fail_closed() {
    let missing_nominal = tempfile::tempdir().expect("missing nominal tempdir");
    write_manifest(missing_nominal.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(missing_nominal.path(), |manifest| {
        manifest["camera"]
            .as_object_mut()
            .expect("camera object")
            .remove("nominal_fps");
    });
    expect_rejected(missing_nominal.path(), CandidateReadiness::Corrupt);

    let missing_quality = tempfile::tempdir().expect("missing quality tempdir");
    write_manifest(missing_quality.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(missing_quality.path(), |manifest| {
        manifest["integrity"]
            .as_object_mut()
            .expect("integrity object")
            .remove("quality_policy");
    });
    expect_rejected(missing_quality.path(), CandidateReadiness::Corrupt);

    let camera_width = tempfile::tempdir().expect("camera width tempdir");
    write_manifest(camera_width.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(camera_width.path(), |manifest| {
        manifest["camera"]["width"] = json!(3841);
    });
    expect_rejected(camera_width.path(), CandidateReadiness::Corrupt);

    let timestamp_order = tempfile::tempdir().expect("timestamp order tempdir");
    write_manifest(timestamp_order.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(timestamp_order.path(), |manifest| {
        manifest["sealed_at"] = json!("2026-08-08T10:24:31+08:00");
    });
    expect_rejected(timestamp_order.path(), CandidateReadiness::Corrupt);

    let duration_clock = tempfile::tempdir().expect("duration clock tempdir");
    write_manifest(duration_clock.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(duration_clock.path(), |manifest| {
        manifest["time"]
            .as_object_mut()
            .expect("time object")
            .remove("duration_clock");
        manifest["time"]["duration_seconds"] = json!(2);
    });
    expect_rejected(duration_clock.path(), CandidateReadiness::Corrupt);

    let frame_gap = tempfile::tempdir().expect("frame gap tempdir");
    write_manifest(frame_gap.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(frame_gap.path(), |manifest| {
        let mut second = manifest["video"]["segments"][0].clone();
        second["index"] = json!(1);
        second["start_frame"] = json!(3);
        second["end_frame"] = json!(4);
        second["start_time_seconds"] = json!(1);
        second["end_time_seconds"] = json!(2);
        second["artifacts"]["left"] =
            manifest_only_artifact('6', "video/left_00001.mp4", "video.left", "video/mp4", 1);
        second["artifacts"]["right"] =
            manifest_only_artifact('7', "video/right_00001.mp4", "video.right", "video/mp4", 1);
        manifest["video"]["segments"]
            .as_array_mut()
            .expect("segments array")
            .push(second);
    });
    expect_rejected(frame_gap.path(), CandidateReadiness::Corrupt);

    let time_gap = tempfile::tempdir().expect("time gap tempdir");
    write_manifest(time_gap.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(time_gap.path(), |manifest| {
        let mut second = manifest["video"]["segments"][0].clone();
        second["index"] = json!(1);
        second["start_frame"] = json!(2);
        second["end_frame"] = json!(4);
        second["start_time_seconds"] = json!(1.5);
        second["end_time_seconds"] = json!(2);
        second["artifacts"]["left"] =
            manifest_only_artifact('8', "video/left_00001.mp4", "video.left", "video/mp4", 1);
        second["artifacts"]["right"] =
            manifest_only_artifact('9', "video/right_00001.mp4", "video.right", "video/mp4", 1);
        manifest["frames"]["count"] = json!(4);
        manifest["camera"]["effective_fps"] = json!(4);
        manifest["video"]["segments"]
            .as_array_mut()
            .expect("segments array")
            .push(second);
    });
    expect_rejected(time_gap.path(), CandidateReadiness::Corrupt);

    let drop_sum = tempfile::tempdir().expect("drop sum tempdir");
    write_manifest(drop_sum.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(drop_sum.path(), |manifest| {
        manifest["integrity"]["dropped_frames"] = json!(1);
        manifest["integrity"]["drop_events"] = json!([]);
    });
    expect_rejected(drop_sum.path(), CandidateReadiness::Corrupt);

    let drop_domain = tempfile::tempdir().expect("drop domain tempdir");
    write_manifest(drop_domain.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(drop_domain.path(), |manifest| {
        manifest["video"]["segments"][0]["end_frame"] = json!(3);
        manifest["frames"]["count"] = json!(2);
        manifest["integrity"]["dropped_frames"] = json!(1);
        manifest["integrity"]["drop_events"] = json!([
            {
                "start_frame": 3,
                "end_frame": 4,
                "at_time_seconds": 1,
                "reason": "write_backpressure",
                "dropped": 1
            }
        ]);
    });
    expect_rejected(drop_domain.path(), CandidateReadiness::Corrupt);

    let measured_fps = tempfile::tempdir().expect("measured fps tempdir");
    write_manifest(measured_fps.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(measured_fps.path(), |manifest| {
        manifest["camera"]["effective_fps"] = json!(1);
    });
    expect_rejected(measured_fps.path(), CandidateReadiness::Corrupt);

    let legacy_fps = tempfile::tempdir().expect("legacy fps tempdir");
    write_manifest(legacy_fps.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(legacy_fps.path(), |manifest| {
        manifest["camera"]
            .as_object_mut()
            .expect("camera object")
            .remove("nominal_fps");
        manifest["integrity"]
            .as_object_mut()
            .expect("integrity object")
            .remove("quality_policy");
        manifest["camera"]["effective_fps"] = json!(1);
    });
    expect_rejected(legacy_fps.path(), CandidateReadiness::Corrupt);

    let lossless_drop = tempfile::tempdir().expect("lossless drop tempdir");
    write_manifest(lossless_drop.path(), VideoFixture::SplitEyes, false);
    mutate_manifest(lossless_drop.path(), |manifest| {
        manifest["video"]["segments"][0]["end_frame"] = json!(3);
        manifest["frames"]["count"] = json!(2);
        manifest["integrity"]["dropped_frames"] = json!(1);
        manifest["integrity"]["drop_events"] = json!([
            {
                "start_frame": 2,
                "end_frame": 3,
                "at_time_seconds": 1,
                "reason": "write_backpressure",
                "dropped": 1
            }
        ]);
    });
    expect_rejected(lossless_drop.path(), CandidateReadiness::Corrupt);
}

#[cfg(unix)]
#[test]
fn manifest_symlink_and_hardlink_fail_closed_before_parsing() {
    use std::os::unix::fs::symlink;

    let symlink_case = tempfile::tempdir().expect("symlink tempdir");
    let target = symlink_case.path().join("target.json");
    fs::write(
        &target,
        br#"{"schema":"ylx.device-session.v1","sealed":true}"#,
    )
    .expect("target manifest");
    symlink(&target, symlink_case.path().join("manifest.json")).expect("manifest symlink");
    expect_rejected(symlink_case.path(), CandidateReadiness::UnsafePath);

    let hardlink_case = tempfile::tempdir().expect("hardlink tempdir");
    write_manifest(hardlink_case.path(), VideoFixture::SplitEyes, false);
    fs::hard_link(
        hardlink_case.path().join("manifest.json"),
        hardlink_case.path().join("manifest.link"),
    )
    .expect("manifest hardlink");
    expect_rejected(hardlink_case.path(), CandidateReadiness::UnsafePath);
}
