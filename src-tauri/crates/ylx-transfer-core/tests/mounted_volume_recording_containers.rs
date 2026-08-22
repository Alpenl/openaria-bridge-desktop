//! A mounted-volume scan must reach the recordings an Ubuntu Core capture
//! device writes.
//!
//! There the mounted volume root is the `ubuntu-data` partition root, not the
//! capture snap's directory, so the recordings sit several components below the
//! mount point instead of directly under it. The scan stays non-recursive, so
//! this only works if that layout is named in the fixed container list.

use std::fs;

use ylx_transfer_core::ingest::{
    AcquisitionSourceId, ConstrainedScanner, InventoryDigest, MediaGeneration, ScanLimits,
    ScanRequest, MOUNTED_VOLUME_RECORDING_CONTAINERS,
};

const SESSION_NAME: &str = "20260803T060347.023247+0000";

fn scan_containers(root: &std::path::Path) -> Vec<String> {
    let source_id = AcquisitionSourceId::parse("test-volume").expect("source id");
    let generation = MediaGeneration::new(
        source_id.clone(),
        "test-platform-volume",
        InventoryDigest::from_material(b"test-root-marker"),
        1,
    )
    .expect("media generation");
    let request = ScanRequest::mounted_volume(root, source_id, generation).expect("scan request");

    ConstrainedScanner::new(ScanLimits::default())
        .scan(&request)
        .items()
        .iter()
        .filter_map(|item| item.candidate_relative_path())
        .map(|relative| relative.as_str().to_string())
        .collect()
}

#[test]
fn scan_reaches_recordings_under_the_ubuntu_core_snap_tree() {
    let volume = tempfile::tempdir().expect("tempdir");
    let container = volume
        .path()
        .join("system-data/var/snap/ylx-capture/common/recordings");
    fs::create_dir_all(container.join(SESSION_NAME)).expect("session directory");

    // The session is deliberately empty of manifests: reaching it at all is
    // what this asserts. Whether it is then admissible is the detector's
    // business, and asserting that here would only restate the detector's own
    // tests while making this one brittle.
    let reached = scan_containers(volume.path());

    assert_eq!(
        reached,
        vec![format!(
            "system-data/var/snap/ylx-capture/common/recordings/{SESSION_NAME}"
        )],
        "the Ubuntu Core recording container must be probed on a mounted volume"
    );
}

#[test]
fn scan_still_reaches_recordings_at_the_volume_root() {
    let volume = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(volume.path().join("recordings").join(SESSION_NAME))
        .expect("session directory");

    let reached = scan_containers(volume.path());

    assert_eq!(reached, vec![format!("recordings/{SESSION_NAME}")]);
}

#[test]
fn scan_does_not_walk_a_card_looking_for_recordings() {
    let volume = tempfile::tempdir().expect("tempdir");
    // A recordings directory one component off the known layout stays
    // invisible: the container list is exhaustive, never a starting point for
    // a search.
    fs::create_dir_all(
        volume
            .path()
            .join("system-data/var/snap/some-other-snap/common/recordings")
            .join(SESSION_NAME),
    )
    .expect("session directory");

    assert!(scan_containers(volume.path()).is_empty());
}

#[test]
fn every_fixed_container_is_a_safe_relative_path() {
    for container in MOUNTED_VOLUME_RECORDING_CONTAINERS {
        assert!(
            ylx_transfer_core::ingest::SafeRelativePath::parse(container.to_owned()).is_ok(),
            "fixed container {container:?} must be a safe relative path"
        );
    }
}
