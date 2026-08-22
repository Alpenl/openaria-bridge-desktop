//! A publication manifest with no detached signature beside it is an unsigned
//! source, not a broken signed one.
//!
//! The recorder publishes a complete, self-describing inventory but does not
//! always leave the detached Ed25519 artifacts next to it. Every integrity
//! claim in such a manifest is still checkable, so the recording is admissible
//! under the unsigned import policy while its origin stays unproven.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use ylx_transfer_core::ingest::{
    AcquisitionSourceId, CandidateReadiness, ConstrainedScanner, InventoryDigest, MediaGeneration,
    ScanItemOutcome, ScanLimits, ScanRequest, SourceKind, SourceSchema, SourceVideoCodec,
    StereoLayout,
};

const SESSION_ID: &str = "20260803T060347_023247_0000-28f96b7c5a19";

struct Artifact {
    path: &'static str,
    role: &'static str,
    media_type: &'static str,
    bytes: &'static [u8],
}

/// Write a publication whose manifest describes exactly what is on disk.
///
/// `video` chooses between the two shapes the recorder actually produces:
/// passed-through side-by-side MJPEG, and separate-eye H.264 output.
fn write_publication(root: &Path, codec: &str, video: &[Artifact]) {
    fs::create_dir_all(root.join("spool")).expect("spool directory");
    fs::create_dir_all(root.join("video")).expect("video directory");

    let session = serde_json::json!({
        "schema_version": 7,
        "state": "complete",
        "camera": {
            "width": 3840,
            "height": 1080,
            "fps": 30,
            "layout": "left_right_side_by_side",
            "left_size": [1920, 1080],
            "source_video_codec": "mjpeg",
            "video_codec": codec,
        },
    });
    let session_bytes = serde_json::to_vec_pretty(&session).expect("session json");
    fs::write(root.join("session.json"), &session_bytes).expect("write session");

    let mut files = Vec::new();
    let mut total = 0u64;
    let mut video_bytes = 0u64;
    let push = |path: &str, role: &str, media_type: &str, bytes: &[u8]| {
        let entry = serde_json::json!({
            "id": format!("f-{}", &format!("{:x}", Sha256::digest(path.as_bytes()))[..32]),
            "display_path": path,
            "role": role,
            "size_bytes": bytes.len() as u64,
            "sha256": format!("{:x}", Sha256::digest(bytes)),
            "media_type": media_type,
        });
        (entry, bytes.len() as u64)
    };

    for artifact in video {
        fs::write(root.join(artifact.path), artifact.bytes).expect("write artifact");
        let (entry, size) = push(
            artifact.path,
            artifact.role,
            artifact.media_type,
            artifact.bytes,
        );
        files.push(entry);
        total += size;
        video_bytes += size;
    }
    let (entry, size) = push(
        "session.json",
        "metadata",
        "application/json",
        &session_bytes,
    );
    files.push(entry);
    total += size;

    let manifest = serde_json::json!({
        "schema_version": 1,
        "session_id": SESSION_ID,
        "revision": format!("sha256:{:x}", Sha256::digest(b"revision-material")),
        "captured_at": "2026-08-03T06:05:11.130061+00:00",
        "published_at": "2026-08-03T06:06:25.822799Z",
        "duration_seconds": 68.8,
        "total_bytes": total,
        "video_bytes": video_bytes,
        "integrity_ok": true,
        "files": files,
    });
    fs::write(
        root.join("publication_manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");
}

fn stereo_mjpeg() -> Vec<Artifact> {
    vec![
        Artifact {
            path: "spool/source_00000.mp4",
            role: "video_stereo",
            media_type: "video/mp4",
            bytes: b"stereo-segment-zero",
        },
        Artifact {
            path: "spool/source_00001.mp4",
            role: "video_stereo",
            media_type: "video/mp4",
            bytes: b"stereo-segment-one",
        },
    ]
}

fn separate_eyes_h264() -> Vec<Artifact> {
    vec![
        Artifact {
            path: "video/left_00000.mp4",
            role: "video_left",
            media_type: "video/mp4",
            bytes: b"left-eye-zero",
        },
        Artifact {
            path: "video/right_00000.mp4",
            role: "video_right",
            media_type: "video/mp4",
            bytes: b"right-eye-zero",
        },
    ]
}

fn detect(root: &Path) -> ScanItemOutcome {
    let source_id = AcquisitionSourceId::parse("test-directory").expect("source id");
    let request = ScanRequest::selected_directory(
        root,
        source_id.clone(),
        SourceKind::RemovableMedia,
        Some(
            MediaGeneration::new(
                source_id,
                "test-platform-volume",
                InventoryDigest::from_material(b"test-root-marker"),
                1,
            )
            .expect("media generation"),
        ),
    )
    .expect("scan request");

    ConstrainedScanner::new(ScanLimits::default())
        .scan(&request)
        .items()
        .first()
        .expect("the selected directory is always inspected")
        .outcome()
        .clone()
}

#[test]
fn a_publication_without_a_detached_signature_is_admissible_as_unsigned() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "mjpeg", &stereo_mjpeg());

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("an intact unsigned publication must be admitted");
    };

    assert_eq!(candidate.schema(), SourceSchema::UnsignedPublicationV1);
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::ReadyUnsignedRequiresPolicy,
        "admission is the unsigned policy's decision, never automatic"
    );
    assert_eq!(candidate.session_id(), SESSION_ID);
    assert!(
        candidate.signed_publication().is_none(),
        "an unsigned candidate must not carry signed publication material"
    );
    // Passed-through stereo keeps the full side-by-side frame.
    let plan = candidate.media_plan();
    assert_eq!(plan.codec(), SourceVideoCodec::Mjpeg);
    assert_eq!(plan.layout(), StereoLayout::LeftRightSideBySide);
    assert_eq!(plan.frame_dimensions(), Some((3840, 1080)));
    assert_eq!(plan.segment_count(), 2);
}

#[test]
fn separate_eye_output_is_measured_per_eye_not_per_source_frame() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "h264", &separate_eyes_h264());

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("an intact unsigned publication must be admitted");
    };

    // The camera block reports the 3840-wide combined source, but each encoded
    // eye is half that. Reporting the source width here would overstate every
    // separate-eye track by a factor of two.
    let plan = candidate.media_plan();
    assert_eq!(plan.codec(), SourceVideoCodec::H264);
    assert_eq!(plan.layout(), StereoLayout::SeparateEyes);
    assert_eq!(plan.frame_dimensions(), Some((1920, 1080)));
    assert_eq!(plan.segment_count(), 1);
}

#[test]
fn a_half_present_signature_pair_is_refused_rather_than_downgraded() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "mjpeg", &stereo_mjpeg());
    // A publication that meant to be signed and did not arrive intact must not
    // quietly become an unsigned one.
    fs::write(
        directory.path().join("publication_manifest.sig"),
        "a".repeat(128),
    )
    .expect("write signature");

    let ScanItemOutcome::Rejected { readiness, .. } = detect(directory.path()) else {
        panic!("a half-present signature pair must be rejected");
    };
    assert_eq!(readiness, CandidateReadiness::Corrupt);
}

#[test]
fn a_complete_detached_pair_stays_signed_until_external_trust_admission() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "h264", &separate_eyes_h264());
    let public_key = "01".repeat(32);
    fs::write(
        directory.path().join("publication_manifest.sig"),
        "ab".repeat(64),
    )
    .expect("write signature");
    fs::write(
        directory.path().join("publication_public_key.hex"),
        &public_key,
    )
    .expect("write public key");

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("a structurally complete detached pair must remain a signed candidate");
    };
    assert_eq!(candidate.schema(), SourceSchema::SignedPublicationV1);
    assert_eq!(
        candidate.readiness(),
        CandidateReadiness::WaitingForPairingKey
    );
    let material = candidate
        .signed_publication()
        .expect("signed candidate material");
    assert_eq!(material.inline_key_version(), None);
    let key_bytes = (0..32).map(|_| 1_u8).collect::<Vec<_>>();
    assert_eq!(
        material.presented_key_fingerprint(),
        format!("sha256:{:x}", Sha256::digest(key_bytes))
    );
}

#[test]
fn an_inline_envelope_stays_signed_without_detached_sidecars() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "h264", &separate_eyes_h264());
    let manifest_path = directory.path().join("publication_manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["publication_signature"] = serde_json::json!({
        "algorithm": "ed25519",
        "key_version": 7,
        "public_key_fingerprint": format!("sha256:{}", "2".repeat(64)),
        "signature": "cd".repeat(64),
    });
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write inline manifest");

    let ScanItemOutcome::Candidate { candidate } = detect(directory.path()) else {
        panic!("a structurally complete inline envelope must remain a signed candidate");
    };
    assert_eq!(candidate.schema(), SourceSchema::SignedPublicationV1);
    let material = candidate
        .signed_publication()
        .expect("signed candidate material");
    assert_eq!(material.inline_key_version(), Some(7));
}

#[test]
fn inline_and_detached_profiles_cannot_be_mixed() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "h264", &separate_eyes_h264());
    let manifest_path = directory.path().join("publication_manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["publication_signature"] = serde_json::json!({
        "algorithm": "ed25519",
        "key_version": 7,
        "public_key_fingerprint": format!("sha256:{}", "2".repeat(64)),
        "signature": "cd".repeat(64),
    });
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write inline manifest");
    fs::write(
        directory.path().join("publication_manifest.sig"),
        "ab".repeat(64),
    )
    .expect("write detached signature");
    fs::write(
        directory.path().join("publication_public_key.hex"),
        "01".repeat(32),
    )
    .expect("write detached key");

    let ScanItemOutcome::Rejected { readiness, .. } = detect(directory.path()) else {
        panic!("mixed inline and detached profiles must fail closed");
    };
    assert_eq!(readiness, CandidateReadiness::Corrupt);
}

#[test]
fn an_unrecognized_codec_is_refused_rather_than_guessed() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_publication(directory.path(), "av1", &stereo_mjpeg());

    let ScanItemOutcome::Rejected { readiness, .. } = detect(directory.path()) else {
        panic!("an unknown codec must be rejected");
    };
    assert_eq!(readiness, CandidateReadiness::UnsupportedSchema);
}
