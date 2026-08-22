use super::*;
use crate::normalization::DerivationJobId;

#[test]
fn staging_uses_revision_safe_hidden_job_directories() {
    let root = tempfile::tempdir().expect("temporary library root");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::parse("derivation-fixture:one").expect("opaque job id");
    staging.prepare_job(&job).expect("prepare staging");
    let workspace = staging.prepare_pair(&job, 0).expect("prepare pair");
    assert!(workspace
        .pair_root()
        .to_string_lossy()
        .contains(".00000.work"));
    assert!(workspace
        .left_partial()
        .file_name()
        .is_some_and(|name| name == "left.partial.mp4"));
}

#[test]
fn pair_workspace_keeps_left_and_right_under_one_directory() {
    let root = tempfile::tempdir().expect("temporary library root");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    let workspace = staging.prepare_pair(&job, 7).expect("prepare pair");
    assert_eq!(
        workspace.left_partial().parent(),
        workspace.right_partial().parent()
    );
}

#[cfg(unix)]
#[test]
fn staging_refuses_a_symlinked_parent_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary library root");
    let outside = tempfile::tempdir().expect("outside directory");
    let sentinel = outside.path().join("must-not-be-removed");
    std::fs::write(&sentinel, b"outside").expect("sentinel");
    symlink(outside.path(), root.path().join(".ylx-derived-staging")).expect("symlink");

    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    assert!(staging.prepare_pair(&job, 0).is_err());
    assert_eq!(
        std::fs::read(&sentinel).expect("sentinel remains"),
        b"outside"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn prepared_workspace_stays_below_its_open_parent_after_parent_swap() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("library root");
    let outside = tempfile::tempdir().expect("outside directory");
    let sentinel = outside.path().join("sentinel");
    std::fs::write(&sentinel, b"outside").expect("sentinel");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    let workspace = staging.prepare_pair(&job, 3).expect("workspace");
    let original = root.path().join(".ylx-derived-staging-original");
    std::fs::rename(root.path().join(".ylx-derived-staging"), &original).expect("move parent");
    symlink(outside.path(), root.path().join(".ylx-derived-staging")).expect("replace parent");

    std::fs::write(workspace.left_partial(), b"anchored").expect("anchored write");
    assert_eq!(std::fs::read(&sentinel).expect("sentinel"), b"outside");
    assert!(original
        .join(job.as_str())
        .join("video/pairs/.00003.work/left.partial.mp4")
        .exists());
}

#[cfg(unix)]
#[test]
fn publish_rejects_a_replaced_work_directory_entry() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().expect("library root");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    let workspace = staging.prepare_pair(&job, 4).expect("workspace");
    std::fs::write(workspace.left_partial(), b"left").expect("left");
    std::fs::write(workspace.right_partial(), b"right").expect("right");
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let work = root
        .path()
        .join(".ylx-derived-staging")
        .join(job.as_str())
        .join("video/pairs/.00004.work");
    let moved = work.with_extension("moved");
    std::fs::rename(&work, &moved).expect("replace work entry");
    std::fs::create_dir(&work).expect("impostor work entry");
    assert!(staging
        .publish_validated_pair(&job, 4, &digest(b"left"), &digest(b"right"))
        .is_err());
    assert!(!root
        .path()
        .join(".ylx-derived-staging")
        .join(job.as_str())
        .join("video/pairs/00004")
        .exists());
}

#[cfg(unix)]
#[test]
fn publish_rejects_partial_replaced_after_initial_hash() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().expect("library root");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    let workspace = staging.prepare_pair(&job, 5).expect("workspace");
    std::fs::write(workspace.left_partial(), b"left").expect("left");
    std::fs::write(workspace.right_partial(), b"right").expect("right");
    let replacement = workspace.right_partial().to_path_buf();
    super::staging::set_after_pair_hash_hook(move || {
        std::fs::remove_file(&replacement).expect("remove hashed partial");
        std::fs::write(&replacement, b"unverified").expect("replace partial");
    });
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    assert!(staging
        .publish_validated_pair(&job, 5, &digest(b"left"), &digest(b"right"))
        .is_err());
    assert!(!root
        .path()
        .join(".ylx-derived-staging")
        .join(job.as_str())
        .join("video/pairs/00005")
        .exists());
}

#[cfg(unix)]
#[test]
fn recovery_reopens_the_renamed_work_directory() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().expect("library root");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    let workspace = staging.prepare_pair(&job, 6).expect("workspace");
    std::fs::write(workspace.left_partial(), b"left").expect("left");
    std::fs::write(workspace.right_partial(), b"right").expect("right");
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    staging
        .publish_validated_pair(&job, 6, &digest(b"left"), &digest(b"right"))
        .expect("publish");
    let recovered = staging
        .recover_uncheckpointed_pair(&job, 6)
        .expect("recover")
        .expect("work");
    assert_eq!(
        std::fs::read(recovered.left_partial()).expect("left partial"),
        b"left"
    );
    assert_eq!(
        std::fs::read(recovered.right_partial()).expect("right partial"),
        b"right"
    );
}

#[cfg(unix)]
#[test]
fn publish_cleans_an_impostor_swapped_after_work_precheck() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().expect("library root");
    let staging = DerivedStaging::new(root.path());
    let job = DerivationJobId::new();
    let workspace = staging.prepare_pair(&job, 7).expect("workspace");
    std::fs::write(workspace.left_partial(), b"left").expect("left");
    std::fs::write(workspace.right_partial(), b"right").expect("right");
    let pairs = root
        .path()
        .join(".ylx-derived-staging")
        .join(job.as_str())
        .join("video/pairs");
    let work = pairs.join(".00007.work");
    let hook_pairs = pairs.clone();
    super::staging::set_after_work_precheck_hook(move || {
        std::fs::rename(&work, hook_pairs.join("detached-work")).expect("swap original work");
        std::fs::create_dir(&work).expect("impostor work");
    });
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    assert!(staging
        .publish_validated_pair(&job, 7, &digest(b"left"), &digest(b"right"))
        .is_err());
    assert!(!pairs.join("00007").exists());
}
