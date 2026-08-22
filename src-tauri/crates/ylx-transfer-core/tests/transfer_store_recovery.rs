//! Commit 25: recovery enumerates jobs from SQLite, and a missing or
//! corrupt spec is an *observable* `RecoveryBlocked`, never a silently
//! shorter list.
//!
//! Every corruption below is applied to the real database underneath the
//! store (raw `UPDATE`/`DELETE`), which is what a botched manual edit, a
//! partially restored backup or a future bug would actually leave behind.

mod transfer_store_support;

use transfer_store_support::{full_session_spec, sample_spec};
use ylx_transfer_core::persistence::{
    FileLedgerStatus, JobSpecLoadError, RecoverableJob, RecoveryBlockedReason, TransferStore,
};
use ylx_transfer_core::transfer::DesiredRunState;

fn open(dir: &std::path::Path) -> TransferStore {
    TransferStore::open(dir.join("transfer.sqlite3")).expect("open transfer store")
}

fn ready(job: &RecoverableJob) -> &ylx_transfer_core::persistence::RecoverableJobDetail {
    match job {
        RecoverableJob::Ready(detail) => detail,
        RecoverableJob::Blocked(blocked) => panic!("expected Ready, got blocked {blocked:?}"),
    }
}

fn blocked(job: &RecoverableJob) -> &ylx_transfer_core::persistence::RecoveryBlocked {
    match job {
        RecoverableJob::Blocked(blocked) => blocked,
        RecoverableJob::Ready(detail) => panic!("expected Blocked, got ready {:?}", detail.job),
    }
}

// ---------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------

#[test]
fn recovery_lists_durable_jobs_with_their_spec_and_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    let spec = sample_spec();
    store.create_job("job-a", &spec, "t0").expect("create");

    let jobs = store.list_recoverable_jobs().expect("list");
    assert_eq!(jobs.len(), 1);
    let detail = ready(&jobs[0]);
    assert_eq!(detail.job.job_id, "job-a");
    assert_eq!(detail.spec, spec);
    assert_eq!(detail.ledger.len(), 2);
    assert_eq!(detail.ledger[0].status, FileLedgerStatus::Missing);
}

#[test]
fn recovery_survives_a_restart_because_it_reads_the_database_not_a_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let spec = sample_spec();
    {
        let mut store = TransferStore::open(&path).expect("open");
        store.create_job("job-a", &spec, "t0").expect("create");
    }
    // A brand-new process, no in-memory state, no JSON file anywhere.
    let store = TransferStore::open(&path).expect("reopen");
    let jobs = store.list_recoverable_jobs().expect("list");
    assert_eq!(jobs.len(), 1);
    assert_eq!(ready(&jobs[0]).spec, spec);
}

#[test]
fn desired_run_state_and_file_ledger_survive_a_restart_with_monotonic_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let spec = sample_spec();
    let file = spec.requested_files().next().expect("requested file");
    let file_id = file.file_id().clone();
    let expected_size = file.size_bytes();
    let expected_sha256 = file.sha256().to_string();

    {
        let mut store = TransferStore::open(&path).expect("open");
        store.create_job("job-a", &spec, "t0").expect("create");
        store
            .set_desired_run_state("job-a", DesiredRunState::Paused, "t1", Some(1))
            .expect("persist paused intent");
        store
            .update_file_ledger(
                "job-a",
                &file_id,
                FileLedgerStatus::Partial,
                128,
                None,
                "t2",
            )
            .expect("checkpoint partial evidence");
    }

    let mut store = TransferStore::open(&path).expect("reopen");
    let row = store.get_job("job-a").expect("read").expect("job");
    assert_eq!(row.desired_run_state, DesiredRunState::Paused);
    assert_eq!(
        row.state_version, 1,
        "intent does not fake an execution commit"
    );
    let partial = store.file_ledger("job-a").expect("ledger");
    assert_eq!(partial[0].status, FileLedgerStatus::Partial);
    assert_eq!(partial[0].bytes_confirmed, 128);

    let backwards = store
        .update_file_ledger("job-a", &file_id, FileLedgerStatus::Partial, 64, None, "t3")
        .expect_err("checkpoint evidence cannot move backwards");
    assert!(matches!(
        backwards,
        ylx_transfer_core::persistence::PersistenceError::Conflict { .. }
    ));

    store
        .update_file_ledger(
            "job-a",
            &file_id,
            FileLedgerStatus::Verified,
            expected_size,
            Some(&expected_sha256),
            "t4",
        )
        .expect("record verified evidence");
    drop(store);

    let store = TransferStore::open(&path).expect("reopen after verify");
    let verified = store.file_ledger("job-a").expect("verified ledger");
    assert_eq!(verified[0].status, FileLedgerStatus::Verified);
    assert_eq!(verified[0].bytes_confirmed, expected_size);
    assert_eq!(
        verified[0].verified_sha256.as_deref(),
        Some(expected_sha256.as_str())
    );
}

#[test]
fn terminal_jobs_are_not_offered_for_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .create_job(
            "job-b",
            &full_session_spec("pi-02", "session-y", "rev-2", &[("f-9", 5, 9)]),
            "t1",
        )
        .expect("create");

    store
        .raw_execute("UPDATE transfer_jobs SET state = 'succeeded' WHERE job_id = 'job-a'")
        .expect("mark terminal");

    let jobs = store.list_recoverable_jobs().expect("list");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].job_id(), "job-b");
}

#[test]
fn recovery_returns_jobs_in_creation_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    for (index, job_id) in ["job-c", "job-a", "job-b"].iter().enumerate() {
        let spec = full_session_spec(
            "pi-01",
            &format!("session-{index}"),
            "rev-1",
            &[("f-1", 10, 1)],
        );
        store
            .create_job(job_id, &spec, &format!("t{index}"))
            .expect("create");
    }
    let jobs = store.list_recoverable_jobs().expect("list");
    let ids: Vec<&str> = jobs.iter().map(RecoverableJob::job_id).collect();
    assert_eq!(ids, ["job-c", "job-a", "job-b"]);
}

// ---------------------------------------------------------------------
// RecoveryBlocked
// ---------------------------------------------------------------------

#[test]
fn a_missing_spec_row_becomes_an_observable_blocked_job_not_an_empty_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .raw_execute("DELETE FROM transfer_job_specs WHERE job_id = 'job-a'")
        .expect("drop the spec row");

    let jobs = store.list_recoverable_jobs().expect("list");
    assert_eq!(jobs.len(), 1, "the job must still be reported");
    let blocked = blocked(&jobs[0]);
    assert_eq!(blocked.job_id, "job-a");
    assert_eq!(blocked.reason, RecoveryBlockedReason::MissingSpec);
    assert!(blocked.identity.is_some(), "identity is still readable");
    assert!(
        blocked.detail.contains("job-a"),
        "detail: {}",
        blocked.detail
    );
}

#[test]
fn missing_file_rows_become_blocked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .raw_execute("DELETE FROM transfer_job_files WHERE job_id = 'job-a'")
        .expect("drop file rows");

    let jobs = store.list_recoverable_jobs().expect("list");
    assert_eq!(
        blocked(&jobs[0]).reason,
        RecoveryBlockedReason::MissingFiles
    );
}

#[test]
fn a_spec_that_no_longer_validates_becomes_blocked_with_the_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    // 64 characters, so the column CHECK still passes -- but not hex, so
    // the domain constructor rejects it.
    store
        .raw_execute(&format!(
            "UPDATE transfer_job_files SET sha256 = '{}' WHERE file_id = 'f-0001'",
            "z".repeat(64)
        ))
        .expect("corrupt a digest");

    let jobs = store.list_recoverable_jobs().expect("list");
    let blocked = blocked(&jobs[0]);
    assert_eq!(blocked.reason, RecoveryBlockedReason::CorruptSpec);
    assert!(
        blocked.detail.contains("f-0001"),
        "the reason must name the file: {}",
        blocked.detail
    );
}

#[test]
fn rows_edited_underneath_the_store_are_caught_by_the_recorded_request_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    // A *valid* but different digest: the spec still reassembles, so only
    // the recorded request digest can catch this.
    store
        .raw_execute(&format!(
            "UPDATE transfer_job_files SET sha256 = '{}' WHERE file_id = 'f-0001'",
            "ab".repeat(32)
        ))
        .expect("swap a digest");

    let jobs = store.list_recoverable_jobs().expect("list");
    let blocked = blocked(&jobs[0]);
    assert_eq!(blocked.reason, RecoveryBlockedReason::DigestMismatch);
}

#[test]
fn an_unknown_spec_version_blocks_recovery_instead_of_being_guessed_at() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .raw_execute("UPDATE transfer_job_specs SET spec_version = 99 WHERE job_id = 'job-a'")
        .expect("bump spec version");

    let jobs = store.list_recoverable_jobs().expect("list");
    let blocked = blocked(&jobs[0]);
    assert_eq!(blocked.reason, RecoveryBlockedReason::UnknownSpecVersion);
    assert!(blocked.detail.contains("99"), "detail: {}", blocked.detail);
}

#[test]
fn one_blocked_job_does_not_hide_the_healthy_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .create_job(
            "job-b",
            &full_session_spec("pi-02", "session-y", "rev-2", &[("f-9", 5, 9)]),
            "t1",
        )
        .expect("create");
    store
        .raw_execute("DELETE FROM transfer_job_specs WHERE job_id = 'job-a'")
        .expect("corrupt job-a");

    let jobs = store.list_recoverable_jobs().expect("list");
    assert_eq!(jobs.len(), 2);
    assert_eq!(blocked(&jobs[0]).job_id, "job-a");
    assert_eq!(ready(&jobs[1]).job.job_id, "job-b");
}

#[test]
fn loading_a_single_spec_reports_the_same_blocked_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(dir.path());
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .raw_execute("DELETE FROM transfer_job_specs WHERE job_id = 'job-a'")
        .expect("drop spec");

    match store.job_spec("job-a").expect_err("must not return a spec") {
        JobSpecLoadError::Blocked(blocked) => {
            assert_eq!(blocked.reason, RecoveryBlockedReason::MissingSpec)
        }
        other => panic!("expected Blocked, got {other:?}"),
    }

    match store.job_spec("nope").expect_err("unknown job") {
        JobSpecLoadError::UnknownJob(id) => assert_eq!(id, "nope"),
        other => panic!("expected UnknownJob, got {other:?}"),
    }
}

#[test]
fn an_empty_store_enumerates_as_empty_only_when_it_really_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());
    assert!(store.list_recoverable_jobs().expect("list").is_empty());
    assert_eq!(store.count_jobs().expect("count"), 0);
}
