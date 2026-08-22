//! Commit 26: the one-shot importer for the legacy pending-download JSON
//! sidecar.
//!
//! The JSON built here is byte-shaped exactly like the file
//! `src-tauri/src/composition.rs`'s `persist_pending_downloads` writes:
//! `{"version": 2, "downloads": [{"jobId": ..., <flattened
//! PendingDownloadInfo camelCase fields>}]}`.
//!
//! Three properties are pinned down: one transaction plus a migration
//! marker, corrupt input leaves the original file untouched and names the
//! failing job, and a second run creates no duplicates.

#[path = "transfer_store_support/legacy.rs"]
mod transfer_store_support;

use std::path::Path;

use serde_json::{json, Value};
use ylx_transfer_core::persistence::{
    LegacyImportError, LegacyImportOutcome, TransferStore, LEGACY_PENDING_DOWNLOAD_MARKER,
};

use transfer_store_support::sha;

fn open(dir: &Path) -> TransferStore {
    TransferStore::open(dir.join("transfer.sqlite3")).expect("open transfer store")
}

fn legacy_file(id: &str, bytes: u64, seed: u8) -> Value {
    json!({
        "fileId": id,
        "displayPath": format!("video/{id}.mp4"),
        "bytes": bytes,
        "sha256": sha(seed),
    })
}

fn legacy_publication(revision: &str) -> Value {
    json!({
        "revision": revision,
        "payload": vec![1u8, 2, 3, 4],
        "signature": vec![7u8; 64],
        "publicKey": vec![9u8; 32],
    })
}

fn legacy_record(job_id: &str, device: &str, session: &str, revision: &str) -> Value {
    json!({
        "jobId": job_id,
        "deviceId": device,
        "sessionId": session,
        "dateLabel": "2026-08-01T04:00:00Z",
        "files": [legacy_file("f-0001", 1024, 0xaa), legacy_file("f-0002", 64, 0xbb)],
        "sessionFiles": [legacy_file("f-0001", 1024, 0xaa), legacy_file("f-0002", 64, 0xbb)],
        "publication": legacy_publication(revision),
        "fullSession": true,
    })
}

fn write_store(path: &Path, downloads: Vec<Value>) {
    write_raw(path, &json!({ "version": 2, "downloads": downloads }));
}

fn write_raw(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).expect("serialize")).expect("write");
}

fn imported(outcome: LegacyImportOutcome) -> ylx_transfer_core::persistence::LegacyImportReport {
    match outcome {
        LegacyImportOutcome::Imported(report) => report,
        other => panic!("expected Imported, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[test]
fn importing_creates_durable_jobs_and_writes_a_migration_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    write_store(
        &sidecar,
        vec![
            legacy_record("job-a", "pi-01", "session-x", "rev-1"),
            legacy_record("job-b", "pi-02", "session-y", "rev-2"),
        ],
    );
    let mut store = open(dir.path());

    let report = imported(
        store
            .import_legacy_pending_downloads(&sidecar, "t0")
            .expect("import"),
    );
    assert_eq!(report.imported, ["job-a", "job-b"]);
    assert!(report.skipped_existing.is_empty());

    assert_eq!(store.count_jobs().expect("count"), 2);
    let spec = store.job_spec("job-a").expect("spec");
    assert_eq!(spec.identity().device_id().as_str(), "pi-01");
    assert_eq!(spec.identity().session_id().as_str(), "session-x");
    assert_eq!(spec.identity().revision(), "rev-1");
    assert!(spec.full_session());
    assert_eq!(spec.date_label(), "2026-08-01T04:00:00Z");
    assert_eq!(spec.session_files().len(), 2);
    assert_eq!(spec.requested_files().count(), 2);
    assert_eq!(store.file_ledger("job-a").expect("ledger").len(), 2);

    let marker = store
        .migration_marker(LEGACY_PENDING_DOWNLOAD_MARKER)
        .expect("read marker")
        .expect("marker written");
    assert_eq!(marker.applied_at, "t0");
    assert!(marker.detail.contains("2 job"), "detail: {}", marker.detail);

    // Imported jobs are immediately recoverable from the database.
    assert_eq!(store.list_recoverable_jobs().expect("list").len(), 2);
}

#[test]
fn a_single_file_legacy_job_imports_as_a_partial_plan_over_the_full_inventory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    let mut record = legacy_record("job-a", "pi-01", "session-x", "rev-1");
    record["files"] = json!([legacy_file("f-0002", 64, 0xbb)]);
    record["fullSession"] = json!(false);
    write_store(&sidecar, vec![record]);

    let mut store = open(dir.path());
    imported(
        store
            .import_legacy_pending_downloads(&sidecar, "t0")
            .expect("import"),
    );

    let spec = store.job_spec("job-a").expect("spec");
    assert!(!spec.full_session());
    assert_eq!(spec.session_files().len(), 2, "the inventory is preserved");
    let plan: Vec<&str> = spec
        .requested_files()
        .map(|f| f.file_id().as_str())
        .collect();
    assert_eq!(plan, ["f-0002"]);
    // Only the requested file gets a ledger row.
    assert_eq!(store.file_ledger("job-a").expect("ledger").len(), 1);
}

#[test]
fn a_missing_sidecar_is_not_an_error_and_writes_no_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    let outcome = store
        .import_legacy_pending_downloads(&dir.path().join("absent.json"), "t0")
        .expect("a missing sidecar is normal");
    assert_eq!(outcome, LegacyImportOutcome::NoLegacyStore);
    assert!(store
        .migration_marker(LEGACY_PENDING_DOWNLOAD_MARKER)
        .expect("read")
        .is_none());
}

// ---------------------------------------------------------------------
// Idempotence
// ---------------------------------------------------------------------

#[test]
fn running_the_import_twice_creates_no_duplicates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    write_store(
        &sidecar,
        vec![legacy_record("job-a", "pi-01", "s", "rev-1")],
    );
    let mut store = open(dir.path());

    imported(
        store
            .import_legacy_pending_downloads(&sidecar, "t0")
            .expect("first import"),
    );
    let second = store
        .import_legacy_pending_downloads(&sidecar, "t1")
        .expect("second import");

    match second {
        LegacyImportOutcome::AlreadyImported(marker) => {
            assert_eq!(marker.marker, LEGACY_PENDING_DOWNLOAD_MARKER);
            assert_eq!(marker.applied_at, "t0", "the marker is not rewritten");
        }
        other => panic!("expected AlreadyImported, got {other:?}"),
    }
    assert_eq!(store.count_jobs().expect("count"), 1);
}

#[test]
fn a_record_whose_logical_transfer_already_exists_is_skipped_not_duplicated() {
    // Same file, but the marker is absent (e.g. the process died after the
    // enqueue path had already created the job durably). Natural-key
    // dedupe, not the marker, is what prevents the duplicate.
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    write_store(
        &sidecar,
        vec![
            legacy_record("job-a", "pi-01", "session-x", "rev-1"),
            legacy_record("job-b", "pi-02", "session-y", "rev-2"),
        ],
    );
    let mut store = open(dir.path());
    // Pre-create job-a through the normal path with identical content.
    let spec = store_spec_from_sidecar(&sidecar, "job-a");
    store.create_job("job-a", &spec, "t0").expect("pre-create");

    let report = imported(
        store
            .import_legacy_pending_downloads(&sidecar, "t1")
            .expect("import"),
    );
    assert_eq!(report.imported, ["job-b"]);
    assert_eq!(report.skipped_existing, ["job-a"]);
    assert_eq!(store.count_jobs().expect("count"), 2);
}

/// Round-trips one sidecar record through the importer into a temporary
/// store, so a test can obtain the exact `JobSpec` the importer would
/// build without duplicating the conversion rules here.
fn store_spec_from_sidecar(sidecar: &Path, job_id: &str) -> ylx_transfer_core::domain::JobSpec {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut scratch = open(dir.path());
    scratch
        .import_legacy_pending_downloads(sidecar, "t0")
        .expect("import into scratch store");
    scratch.job_spec(job_id).expect("spec")
}

// ---------------------------------------------------------------------
// Corrupt input
// ---------------------------------------------------------------------

fn assert_nothing_imported(store: &TransferStore, sidecar: &Path, original: &[u8]) {
    assert_eq!(
        store.count_jobs().expect("count"),
        0,
        "a failed import must import nothing"
    );
    assert!(
        store
            .migration_marker(LEGACY_PENDING_DOWNLOAD_MARKER)
            .expect("read")
            .is_none(),
        "a failed import must not claim to have run"
    );
    assert_eq!(
        std::fs::read(sidecar).expect("read sidecar"),
        original,
        "the original sidecar file must be left untouched"
    );
}

#[test]
fn a_corrupt_record_names_the_failing_job_and_leaves_the_file_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    let mut bad = legacy_record("job-b", "pi-02", "session-y", "rev-2");
    bad["sessionFiles"][0]["sha256"] = json!("not-a-sha256");
    bad["files"][0]["sha256"] = json!("not-a-sha256");
    write_store(
        &sidecar,
        vec![legacy_record("job-a", "pi-01", "session-x", "rev-1"), bad],
    );
    let original = std::fs::read(&sidecar).expect("read");
    let mut store = open(dir.path());

    let error = store
        .import_legacy_pending_downloads(&sidecar, "t0")
        .expect_err("a corrupt record must fail the import");
    match error {
        LegacyImportError::Corrupt { job_id, detail, .. } => {
            assert_eq!(job_id.as_deref(), Some("job-b"));
            assert!(detail.contains("f-0001"), "detail: {detail}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
    // Note job-a is valid and comes first — it must still not be imported,
    // because the whole import is one transaction.
    assert_nothing_imported(&store, &sidecar, &original);
}

#[test]
fn unparseable_json_is_reported_without_a_job_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    std::fs::write(&sidecar, b"{ this is not json").expect("write");
    let original = std::fs::read(&sidecar).expect("read");
    let mut store = open(dir.path());

    match store
        .import_legacy_pending_downloads(&sidecar, "t0")
        .expect_err("garbage must not import")
    {
        LegacyImportError::Corrupt { job_id, .. } => assert_eq!(job_id, None),
        other => panic!("expected Corrupt, got {other:?}"),
    }
    assert_nothing_imported(&store, &sidecar, &original);
}

#[test]
fn an_unsupported_store_version_is_rejected_rather_than_guessed_at() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    write_raw(
        &sidecar,
        &json!({
            "version": 99,
            "downloads": [legacy_record("job-a", "pi-01", "s", "rev-1")],
        }),
    );
    let original = std::fs::read(&sidecar).expect("read");
    let mut store = open(dir.path());

    match store
        .import_legacy_pending_downloads(&sidecar, "t0")
        .expect_err("an unknown version must not import")
    {
        LegacyImportError::Corrupt { job_id, detail, .. } => {
            assert_eq!(job_id, None);
            assert!(detail.contains("99"), "detail: {detail}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
    assert_nothing_imported(&store, &sidecar, &original);
}

#[test]
fn a_duplicated_job_id_inside_the_file_names_the_offending_job() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    write_store(
        &sidecar,
        vec![
            legacy_record("job-a", "pi-01", "session-x", "rev-1"),
            legacy_record("job-a", "pi-02", "session-y", "rev-2"),
        ],
    );
    let original = std::fs::read(&sidecar).expect("read");
    let mut store = open(dir.path());

    match store
        .import_legacy_pending_downloads(&sidecar, "t0")
        .expect_err("duplicate job ids must not import")
    {
        LegacyImportError::Corrupt { job_id, .. } => assert_eq!(job_id.as_deref(), Some("job-a")),
        other => panic!("expected Corrupt, got {other:?}"),
    }
    assert_nothing_imported(&store, &sidecar, &original);
}

#[test]
fn a_plan_entry_that_disagrees_with_the_signed_inventory_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    let mut record = legacy_record("job-a", "pi-01", "session-x", "rev-1");
    // The legacy format kept two independent lists; a divergent copy must
    // not be able to redefine what a signed file contains.
    record["files"][0]["bytes"] = json!(999_999);
    write_store(&sidecar, vec![record]);
    let original = std::fs::read(&sidecar).expect("read");
    let mut store = open(dir.path());

    match store
        .import_legacy_pending_downloads(&sidecar, "t0")
        .expect_err("a divergent plan entry must not import")
    {
        LegacyImportError::Corrupt { job_id, detail, .. } => {
            assert_eq!(job_id.as_deref(), Some("job-a"));
            assert!(detail.contains("disagrees"), "detail: {detail}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
    assert_nothing_imported(&store, &sidecar, &original);
}

#[test]
fn an_incomplete_publication_envelope_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    let mut record = legacy_record("job-a", "pi-01", "session-x", "rev-1");
    record["publication"]["signature"] = json!(vec![7u8; 10]);
    write_store(&sidecar, vec![record]);
    let original = std::fs::read(&sidecar).expect("read");
    let mut store = open(dir.path());

    match store
        .import_legacy_pending_downloads(&sidecar, "t0")
        .expect_err("a truncated signature must not import")
    {
        LegacyImportError::Corrupt { job_id, detail, .. } => {
            assert_eq!(job_id.as_deref(), Some("job-a"));
            assert!(detail.contains("signature"), "detail: {detail}");
        }
        other => panic!("expected Corrupt, got {other:?}"),
    }
    assert_nothing_imported(&store, &sidecar, &original);
}

#[test]
fn a_legacy_record_conflicting_with_an_existing_durable_job_is_reported_not_merged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("pending-downloads.json");
    write_store(
        &sidecar,
        vec![legacy_record("job-a", "pi-01", "session-x", "rev-1")],
    );
    let mut store = open(dir.path());
    // Same natural key, different content.
    let existing = transfer_store_support::full_session_spec(
        "pi-01",
        "session-x",
        "rev-1",
        &[("f-0001", 1024, 0x11)],
    );
    store
        .create_job("job-z", &existing, "t0")
        .expect("pre-create");

    match store
        .import_legacy_pending_downloads(&sidecar, "t1")
        .expect_err("a conflicting record must be reported")
    {
        LegacyImportError::Conflict(conflict) => {
            assert_eq!(conflict.job_id, "job-z");
            assert_ne!(conflict.existing_digest, conflict.requested_digest);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert_eq!(store.count_jobs().expect("count"), 1);
    assert!(store
        .migration_marker(LEGACY_PENDING_DOWNLOAD_MARKER)
        .expect("read")
        .is_none());
}
