//! Commits 23 and 24: transactional `create_job`, and request-digest
//! verification of an `Existing` job.
//!
//! Commit 23's property: one transaction writes the job identity, the
//! complete spec, the ordered files and the initial ledger, and a failure
//! anywhere leaves no partial row. That is tested by actually aborting the
//! transaction at each stage (`create_job_aborting_after`) and then
//! counting rows in every table, not by reading the code.
//!
//! Commit 24's property is "same natural key + different content is an
//! explicit conflict". Tested for a changed digest, a changed size, a
//! changed plan, a changed publication and a changed full-session flag.

mod transfer_store_support;

use rusqlite::Connection;
use transfer_store_support::{full_session_spec, sample_spec, spec_with};
use ylx_transfer_core::domain::FileId;
use ylx_transfer_core::persistence::transfer_store::CreateJobAbort;
use ylx_transfer_core::persistence::{
    CreateJobError, CreateJobOutcome, FileLedgerStatus, JobStateTag, TransferStore,
};

fn open(dir: &std::path::Path) -> TransferStore {
    TransferStore::open(dir.join("transfer.sqlite3")).expect("open transfer store")
}

fn row_count(path: &std::path::Path, table: &str) -> i64 {
    let conn = Connection::open(path).expect("raw open");
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("count rows")
}

// ---------------------------------------------------------------------
// Commit 23: the happy path writes everything
// ---------------------------------------------------------------------

#[test]
fn creating_a_job_writes_identity_spec_ordered_files_and_the_initial_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = TransferStore::open(&path).expect("open");
    let spec = sample_spec();

    let outcome = store.create_job("job-a", &spec, "t0").expect("create");
    assert!(outcome.was_created());

    let job = outcome.job();
    assert_eq!(job.job_id, "job-a");
    assert_eq!(job.identity, *spec.identity());
    assert_eq!(job.request_digest, spec.request_digest());
    assert_eq!(job.state, JobStateTag::Queued);
    assert_eq!(job.state_version, 1);
    assert_eq!(job.error, None);
    assert_eq!(job.created_at, "t0");

    assert_eq!(row_count(&path, "transfer_jobs"), 1);
    assert_eq!(row_count(&path, "transfer_job_specs"), 1);
    assert_eq!(row_count(&path, "transfer_job_files"), 2);
    assert_eq!(row_count(&path, "transfer_file_ledger"), 2);

    // The spec reads back through the same validating constructor.
    let stored = store.job_spec("job-a").expect("spec round-trips");
    assert_eq!(stored, spec);

    // The ledger starts as "we have nothing", in request order.
    let ledger = store.file_ledger("job-a").expect("ledger");
    let ids: Vec<&str> = ledger.iter().map(|e| e.file_id.as_str()).collect();
    assert_eq!(ids, ["f-0001", "f-0002"]);
    for entry in &ledger {
        assert_eq!(entry.status, FileLedgerStatus::Missing);
        assert_eq!(entry.bytes_confirmed, 0);
        assert_eq!(entry.verified_sha256, None);
        assert_eq!(entry.updated_at, "t0");
    }
}

#[test]
fn the_ordered_file_plan_survives_a_round_trip_including_unrequested_inventory_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    // Request the second file first, and leave the third out of the plan
    // entirely: inventory order, request order and membership are three
    // separate facts and all three must come back.
    let spec = spec_with(
        "pi-01",
        "session-x",
        "rev-1",
        &[("f-1", 10, 1), ("f-2", 20, 2), ("f-3", 30, 3)],
        &[FileId("f-2".into()), FileId("f-1".into())],
        false,
    );
    store.create_job("job-a", &spec, "t0").expect("create");

    let stored = store.job_spec("job-a").expect("spec");
    let inventory: Vec<&str> = stored
        .session_files()
        .iter()
        .map(|f| f.file_id().as_str())
        .collect();
    assert_eq!(inventory, ["f-1", "f-2", "f-3"]);
    let plan: Vec<&str> = stored
        .requested_files()
        .map(|f| f.file_id().as_str())
        .collect();
    assert_eq!(plan, ["f-2", "f-1"]);
    assert_eq!(stored.request_digest(), spec.request_digest());

    // Only requested files get a ledger row.
    let ledger = store.file_ledger("job-a").expect("ledger");
    let ledger_ids: Vec<&str> = ledger.iter().map(|e| e.file_id.as_str()).collect();
    assert_eq!(ledger_ids, ["f-2", "f-1"]);
}

#[test]
fn jobs_can_be_looked_up_by_id_and_by_natural_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    let spec = sample_spec();
    store.create_job("job-a", &spec, "t0").expect("create");

    assert_eq!(
        store.get_job("job-a").expect("get").unwrap().job_id,
        "job-a"
    );
    assert!(store.get_job("job-missing").expect("get").is_none());
    assert_eq!(
        store
            .find_job_by_identity(spec.identity())
            .expect("find")
            .unwrap()
            .job_id,
        "job-a"
    );

    let other = full_session_spec("pi-02", "session-y", "rev-9", &[("f-1", 1, 1)]);
    assert!(store
        .find_job_by_identity(other.identity())
        .expect("find")
        .is_none());
}

// ---------------------------------------------------------------------
// Commit 23: idempotence
// ---------------------------------------------------------------------

#[test]
fn re_creating_the_same_request_returns_existing_without_writing_anything() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = TransferStore::open(&path).expect("open");
    let spec = sample_spec();
    store.create_job("job-a", &spec, "t0").expect("create");

    // A different job id for the same logical transfer must resolve to the
    // committed job, not create a second one.
    let outcome = store
        .create_job("job-b", &spec, "t1")
        .expect("an identical request is idempotent");
    match outcome {
        CreateJobOutcome::Existing(job) => {
            assert_eq!(job.job_id, "job-a");
            assert_eq!(job.created_at, "t0");
        }
        other => panic!("expected Existing(job-a), got {other:?}"),
    }
    assert_eq!(store.count_jobs().expect("count"), 1);
    assert_eq!(row_count(&path, "transfer_job_files"), 2);
    assert_eq!(row_count(&path, "transfer_file_ledger"), 2);
    assert!(store.get_job("job-b").expect("get").is_none());
}

#[test]
fn a_job_id_taken_by_a_different_logical_transfer_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");

    let other = full_session_spec("pi-02", "session-y", "rev-2", &[("f-9", 5, 9)]);
    let error = store
        .create_job("job-a", &other, "t1")
        .expect_err("a job id collision must never alias another transfer");
    match error {
        CreateJobError::JobIdCollision { job_id, existing } => {
            assert_eq!(job_id, "job-a");
            assert!(
                existing.contains("pi-01"),
                "diagnostic names the squatter: {existing}"
            );
        }
        other => panic!("expected JobIdCollision, got {other:?}"),
    }
    assert_eq!(store.count_jobs().expect("count"), 1);
}

// ---------------------------------------------------------------------
// Commit 23: no partial rows on failure
// ---------------------------------------------------------------------

#[test]
fn a_crash_at_any_stage_of_create_job_leaves_no_partial_row() {
    for abort in [
        CreateJobAbort::AfterJobRow,
        CreateJobAbort::AfterSpecRow,
        CreateJobAbort::AfterFiles,
        CreateJobAbort::AfterLedger,
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("transfer.sqlite3");
        let mut store = TransferStore::open(&path).expect("open");

        store
            .create_job_aborting_after("job-a", &sample_spec(), "t0", abort)
            .expect_err("the simulated crash must surface as an error");

        for table in TransferStore::transfer_tables() {
            assert_eq!(
                row_count(&path, table),
                0,
                "aborting at {abort:?} left rows in {table}"
            );
        }
        assert!(store.get_job("job-a").expect("get").is_none());

        // And the store is still usable: the retry succeeds cleanly.
        let outcome = store
            .create_job("job-a", &sample_spec(), "t1")
            .expect("retry after a rolled-back attempt");
        assert!(outcome.was_created());
        assert_eq!(row_count(&path, "transfer_file_ledger"), 2);
    }
}

#[test]
fn a_rolled_back_creation_is_invisible_after_reopening_the_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    {
        let mut store = TransferStore::open(&path).expect("open");
        store
            .create_job_aborting_after("job-a", &sample_spec(), "t0", CreateJobAbort::AfterFiles)
            .expect_err("simulated crash");
    }
    let store = TransferStore::open(&path).expect("reopen");
    assert_eq!(store.count_jobs().expect("count"), 0);
    assert!(store.list_recoverable_jobs().expect("list").is_empty());
}

// ---------------------------------------------------------------------
// Commit 24: request-digest verification
// ---------------------------------------------------------------------

fn expect_conflict(error: CreateJobError) -> ylx_transfer_core::persistence::JobRequestConflict {
    match error {
        CreateJobError::RequestDigestMismatch(conflict) => *conflict,
        other => panic!("expected RequestDigestMismatch, got {other:?}"),
    }
}

#[test]
fn the_same_natural_key_with_different_file_content_is_an_explicit_conflict() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    let original = full_session_spec("pi-01", "session-x", "rev-1", &[("f-1", 100, 0xaa)]);
    store.create_job("job-a", &original, "t0").expect("create");

    // Same (device, session, revision) — but a different expected digest
    // for the file. Reusing the stored plan here would silently transfer
    // different bytes than the caller asked for.
    let tampered = full_session_spec("pi-01", "session-x", "rev-1", &[("f-1", 100, 0xcc)]);
    let conflict = expect_conflict(
        store
            .create_job("job-b", &tampered, "t1")
            .expect_err("differing content must not reuse the stored plan"),
    );

    assert_eq!(conflict.job_id, "job-a");
    assert_eq!(conflict.identity, *original.identity());
    assert_eq!(conflict.existing_digest, original.request_digest());
    assert_eq!(conflict.requested_digest, tampered.request_digest());
    assert_ne!(conflict.existing_digest, conflict.requested_digest);
    assert!(
        conflict.detail.contains("f-1"),
        "the diagnostic must name the differing file: {}",
        conflict.detail
    );

    // Nothing changed.
    assert_eq!(store.count_jobs().expect("count"), 1);
    assert_eq!(store.job_spec("job-a").expect("spec"), original);
}

#[test]
fn every_kind_of_content_difference_conflicts_rather_than_silently_reusing_the_plan() {
    let base = full_session_spec(
        "pi-01",
        "session-x",
        "rev-1",
        &[("f-1", 100, 0xaa), ("f-2", 200, 0xbb)],
    );

    let variants: Vec<(&str, ylx_transfer_core::domain::JobSpec, &str)> = vec![
        (
            "different expected size",
            full_session_spec(
                "pi-01",
                "session-x",
                "rev-1",
                &[("f-1", 999, 0xaa), ("f-2", 200, 0xbb)],
            ),
            "f-1",
        ),
        (
            "different inventory length",
            full_session_spec("pi-01", "session-x", "rev-1", &[("f-1", 100, 0xaa)]),
            "length",
        ),
        (
            "different requested plan",
            spec_with(
                "pi-01",
                "session-x",
                "rev-1",
                &[("f-1", 100, 0xaa), ("f-2", 200, 0xbb)],
                &[FileId("f-1".into())],
                false,
            ),
            "full_session",
        ),
    ];

    for (label, variant, expected_fragment) in variants {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = open(dir.path());
        store.create_job("job-a", &base, "t0").expect("create");

        let conflict = expect_conflict(store.create_job("job-b", &variant, "t1").expect_err(label));
        assert_eq!(conflict.job_id, "job-a", "{label}");
        assert!(
            conflict.detail.contains(expected_fragment),
            "{label}: diagnostic {:?} should mention {expected_fragment:?}",
            conflict.detail
        );
        assert_eq!(store.count_jobs().expect("count"), 1, "{label}");
    }
}

#[test]
fn a_different_publication_for_the_same_revision_conflicts() {
    use ylx_transfer_core::domain::{JobSpec, PublicationMaterial};

    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    let base = full_session_spec("pi-01", "session-x", "rev-1", &[("f-1", 100, 0xaa)]);
    store.create_job("job-a", &base, "t0").expect("create");

    let forged = JobSpec::new(
        base.identity().clone(),
        PublicationMaterial::new("rev-1", vec![9, 9, 9], vec![1u8; 64], vec![2u8; 32])
            .expect("valid material"),
        base.session_files().to_vec(),
        &[FileId("f-1".into())],
        true,
        "2026-08-01",
    )
    .expect("valid spec");

    let conflict = expect_conflict(
        store
            .create_job("job-b", &forged, "t1")
            .expect_err("a different signed envelope is a different request"),
    );
    assert!(
        conflict.detail.contains("publication"),
        "diagnostic: {}",
        conflict.detail
    );
}

#[test]
fn a_cosmetic_label_difference_is_not_a_conflict() {
    use ylx_transfer_core::domain::JobSpec;

    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    let base = full_session_spec("pi-01", "session-x", "rev-1", &[("f-1", 100, 0xaa)]);
    store.create_job("job-a", &base, "t0").expect("create");

    let relabelled = JobSpec::new(
        base.identity().clone(),
        base.publication().clone(),
        base.session_files().to_vec(),
        &[FileId("f-1".into())],
        true,
        "a different display label",
    )
    .expect("valid spec");

    let outcome = store
        .create_job("job-b", &relabelled, "t1")
        .expect("a display-only difference is the same request");
    assert!(!outcome.was_created());
    assert_eq!(outcome.job().job_id, "job-a");
}
