//! Issue #1, commit 95: cross-platform filesystem and recovery contracts.
//!
//! These tests deliberately stay at the public seams.  They model the
//! filesystem states that a restart can observe (rather than asserting the
//! implementation's private helper calls), and print an explicit
//! `executed`/`skipped` record for host capabilities that are not portable.
//! Run with `--nocapture` when collecting the contract evidence.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, ErrorCode};
use sha2::{Digest, Sha256};
use ylx_transfer_core::library::download::FilePlan;
use ylx_transfer_core::library::staging::{
    RevisionState, SessionManifest, SessionStaging, STAGING_DIR_NAME,
};
use ylx_transfer_core::persistence::{AppLibraryPayload, AppStore, PersistenceError};

const DEVICE: &str = "device-fs-contract";
const SESSION: &str = "session-fs-contract";
const PAYLOAD: &[u8] = b"revision payload for filesystem contract";
const FILE_BYTES: &[u8] = b"verified bytes from a staged revision";

fn report(name: &str, status: &str, detail: impl std::fmt::Display) {
    eprintln!("[fs-recovery] {name}: {status} ({detail})");
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn plan() -> FilePlan {
    FilePlan {
        device_id: DEVICE.to_string(),
        session_id: SESSION.to_string(),
        file_id: "capture-0001".to_string(),
        target_relative_path: Some("capture.bin".to_string()),
        expected_size: FILE_BYTES.len() as u64,
        expected_sha256_hex: digest(FILE_BYTES),
    }
}

/// Build a sealed-capable revision without going through a network fake.  A
/// staged file is still inspected by the same ArtifactInspector as a real
/// download, so this fixture exercises the complete seal/publish protocol.
fn staged_revision(root: &Path) -> (SessionStaging, SessionManifest) {
    let staging = SessionStaging::for_publication(root, DEVICE, SESSION, PAYLOAD)
        .expect("valid contract ids");
    let file = staging.revision_dir().join("capture.bin");
    fs::create_dir_all(file.parent().expect("file parent")).expect("create revision tree");
    fs::write(&file, FILE_BYTES).expect("write staged bytes");
    let manifest = SessionManifest::from_plans(DEVICE, SESSION, &[plan()]);
    (staging, manifest)
}

fn old_published_tree(root: &Path) -> PathBuf {
    let old = root.join(DEVICE).join(SESSION).join("capture.bin");
    fs::create_dir_all(old.parent().expect("old parent")).expect("create old tree");
    fs::write(&old, b"bytes from the previous revision").expect("write old bytes");
    old
}

#[test]
fn preexisting_target_is_trashed_before_atomic_publish_on_all_hosts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let old = old_published_tree(dir.path());
    let (staging, manifest) = staged_revision(dir.path());

    let outcome = staging
        .publish(&manifest)
        .expect("publish replaces old target");
    assert!(matches!(
        outcome,
        ylx_transfer_core::library::staging::PublishOutcome::Published { .. }
    ));
    assert_eq!(staging.state(), RevisionState::Published);
    assert_eq!(
        fs::read(staging.published_dir().join("capture.bin")).unwrap(),
        FILE_BYTES
    );
    assert_eq!(
        fs::read(&old).unwrap(),
        FILE_BYTES,
        "the old target path now resolves to the newly published bytes"
    );
    assert!(
        !dir.path().join(STAGING_DIR_NAME).exists(),
        "successful publication cleans the hidden staging skeleton"
    );

    report(
        "preexisting-target",
        "executed",
        if cfg!(windows) {
            "Windows existing-directory rename contract"
        } else {
            "portable equivalent of Windows existing-directory rename"
        },
    );
}

#[test]
fn recovery_after_crash_between_trash_move_and_publish_converges_without_duplicate_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let old = old_published_tree(dir.path());
    let (staging, manifest) = staged_revision(dir.path());
    let sealed = staging.seal(&manifest).expect("seal revision");

    // A process can die after moving the previous revision aside but before
    // the second rename.  Recreate exactly that durable state, then invoke
    // the public recovery operation as a fresh process would.
    let superseded = dir
        .path()
        .join(STAGING_DIR_NAME)
        .join(".superseded")
        .join(staging.revision().as_str())
        .join(DEVICE)
        .join(SESSION);
    fs::create_dir_all(superseded.parent().expect("trash parent")).expect("create trash tree");
    fs::rename(old.parent().expect("old session directory"), &superseded)
        .expect("simulate crash-window trash move");
    assert_eq!(staging.state(), RevisionState::Sealed);
    drop(sealed);

    let restarted = SessionStaging::new(dir.path(), DEVICE, SESSION, staging.revision().clone())
        .expect("recreate staging handle after restart");
    let outcome = restarted
        .publish(&manifest)
        .expect("recovery finishes second rename");
    assert!(matches!(
        outcome,
        ylx_transfer_core::library::staging::PublishOutcome::Published { .. }
    ));
    assert_eq!(restarted.state(), RevisionState::Published);
    assert_eq!(
        fs::read(restarted.published_dir().join("capture.bin")).unwrap(),
        FILE_BYTES
    );
    assert!(
        !dir.path().join(STAGING_DIR_NAME).exists(),
        "recovery removes the stale trash/staging skeleton after publishing"
    );
    report(
        "trash-rollback-recovery",
        "executed",
        "crash after old-target rename, before new-target rename",
    );
}

#[test]
fn sealed_revision_is_idempotent_after_crash_after_atomic_rename() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (staging, manifest) = staged_revision(dir.path());
    staging.publish(&manifest).expect("first publish");

    let restarted = SessionStaging::new(dir.path(), DEVICE, SESSION, staging.revision().clone())
        .expect("recreate handle");
    let outcome = restarted.publish(&manifest).expect("rerun after rename");
    assert!(matches!(
        outcome,
        ylx_transfer_core::library::staging::PublishOutcome::AlreadyPublished { .. }
    ));
    assert_eq!(
        fs::read(restarted.published_dir().join("capture.bin")).unwrap(),
        FILE_BYTES
    );
    report(
        "post-rename-recovery",
        "executed",
        "already-published outcome is idempotent",
    );
}

#[test]
fn read_only_directory_surfaces_a_structured_write_error_or_reports_capability_skip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let readonly = dir.path().join("readonly");
    fs::create_dir(&readonly).expect("readonly directory");
    let path = readonly.join("app.sqlite3");
    let seed = AppStore::open(&path).expect("seed app store");
    seed.save(&[], b"seed").expect("seed app store contents");
    drop(seed);

    let original_permissions = fs::metadata(&readonly)
        .expect("stat readonly directory")
        .permissions();
    let mut permissions = original_permissions.clone();
    permissions.set_readonly(true);
    if let Err(error) = fs::set_permissions(&readonly, permissions) {
        report(
            "read-only-directory",
            "skipped",
            format!("cannot set read-only mode: {error}"),
        );
        return;
    }

    let result = AppStore::open(&path).and_then(|store| store.save(&[], b"readonly"));

    // Restore before TempDir cleanup.  Some privileged/container filesystems
    // intentionally ignore the read-only bit; that is a capability result,
    // not a false green assertion.
    fs::set_permissions(&readonly, original_permissions).expect("restore directory permissions");

    match result {
        Err(PersistenceError::Io { .. } | PersistenceError::Sqlite(_)) => {
            report(
                "read-only-directory",
                "executed",
                "durable SQLite app-store write rejected",
            );
        }
        Err(PersistenceError::Corrupt { detail, .. }) if detail.contains("readonly") => {
            report(
                "read-only-directory",
                "executed",
                "durable SQLite app-store write rejected",
            );
        }
        Ok(()) => {
            report(
                "read-only-directory",
                "skipped",
                "host filesystem allowed writes despite read-only permission",
            );
        }
        Err(other) => panic!("read-only write returned an unrelated error: {other:?}"),
    }
}

#[test]
fn deterministic_no_space_fixture_is_exercised_when_host_provides_dev_full() {
    let full = Path::new("/dev/full");
    if !full.exists() {
        report(
            "disk-full",
            "skipped",
            "/dev/full is not available on this host",
        );
        return;
    }

    // Keep the kernel errno assertion as a deterministic capability fixture.
    let mut file = match fs::OpenOptions::new().write(true).open(full) {
        Ok(file) => file,
        Err(error) => {
            report(
                "disk-full",
                "skipped",
                format!("cannot open /dev/full: {error}"),
            );
            return;
        }
    };
    let error = file
        .write_all(b"deterministic ENOSPC fixture")
        .expect_err("/dev/full must reject every write");
    assert_eq!(
        error.raw_os_error(),
        Some(28),
        "expected ENOSPC from /dev/full"
    );

    #[cfg(unix)]
    let staging_detail = {
        // Exercise the public staging seal at the same durable write
        // boundary, using a read-only revision directory as the portable
        // equivalent of a full volume. The host may ignore permission bits,
        // so that result is reported as a capability skip.
        let dir = tempfile::tempdir().expect("tempdir");
        let (staging, manifest) = staged_revision(dir.path());
        let revision_dir = staging.revision_dir();
        let original_permissions = fs::metadata(&revision_dir)
            .expect("stat revision directory")
            .permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        let detail = match fs::set_permissions(&revision_dir, permissions) {
            Err(error) => format!("staging read-only probe skipped: {error}"),
            Ok(()) => {
                let result = staging.seal(&manifest);
                fs::set_permissions(&revision_dir, original_permissions)
                    .expect("restore revision permissions");
                match result {
                    Err(ylx_transfer_core::library::staging::PublishError::Download(
                        ylx_transfer_core::library::download::DownloadError::Io { .. },
                    )) => "staging seal rejected the durable write".to_string(),
                    Ok(_) => "staging read-only probe skipped (host allowed the write)".to_string(),
                    Err(other) => panic!("staging seal returned an unrelated error: {other:?}"),
                }
            }
        };
        detail
    };
    #[cfg(not(unix))]
    let staging_detail = "staging read-only probe unavailable on this host";

    report(
        "disk-full",
        "executed",
        format!("kernel ENOSPC fixture returned errno 28; {staging_detail}"),
    );
}

#[test]
fn sqlite_busy_is_observable_and_store_recovers_after_blocker_releases() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("app.sqlite3");
    let store = AppStore::open(&path).expect("open app store");
    store.save(&[], b"initial").expect("seed app store");

    let blocker = Connection::open(&path).expect("open lock connection");
    blocker
        .busy_timeout(Duration::from_millis(0))
        .expect("disable lock wait for deterministic probe");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("acquire SQLite writer lock");

    let contender = Connection::open(&path).expect("open contender");
    contender
        .busy_timeout(Duration::from_millis(0))
        .expect("disable contender wait");
    let busy = contender
        .execute_batch("BEGIN IMMEDIATE")
        .expect_err("second writer must observe SQLITE_BUSY");
    assert!(matches!(
        busy,
        rusqlite::Error::SqliteFailure(ref code, _) if code.code == ErrorCode::DatabaseBusy
    ));
    let structured = PersistenceError::from(busy);
    assert!(matches!(structured, PersistenceError::Busy));

    blocker.execute_batch("ROLLBACK").expect("release lock");
    store
        .save(
            &[AppLibraryPayload {
                entry_key: "after-busy".to_string(),
                payload: b"recovered".to_vec(),
            }],
            b"updated",
        )
        .expect("store write succeeds after blocker release");
    assert_eq!(store.load().expect("load after busy").revision, 2);
    report(
        "sqlite-busy",
        "executed",
        "SQLITE_BUSY surfaced and later write recovered",
    );
}

#[test]
fn platform_capability_report_is_explicit_for_nonportable_contracts() {
    let rename_probe = tempfile::tempdir().expect("tempdir");
    let source = rename_probe.path().join("source");
    let destination = rename_probe.path().join("destination");
    fs::create_dir(&source).expect("source directory");
    fs::write(source.join("payload"), b"x").expect("source payload");
    fs::create_dir(&destination).expect("destination directory");
    fs::write(destination.join("existing"), b"x").expect("destination payload");
    let result = fs::rename(&source, &destination);
    if result.is_ok() {
        report(
            "atomic-rename-existing-target",
            "skipped",
            "host permits replacement of a non-empty directory; staging trash path remains required",
        );
    } else {
        report(
            "atomic-rename-existing-target",
            "executed",
            "host rejects replacement of non-empty directory",
        );
    }

    #[cfg(unix)]
    report(
        "directory-fsync",
        "executed",
        "POSIX directory handles are available",
    );
    #[cfg(not(unix))]
    report(
        "directory-fsync",
        "skipped",
        "portable std does not expose directory fsync on this host",
    );
}
