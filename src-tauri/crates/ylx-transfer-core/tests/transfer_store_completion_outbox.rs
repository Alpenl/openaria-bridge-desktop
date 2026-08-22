//! Commit 29: terminal outcomes go to a durable outbox.
//!
//! The property under test is that the terminal state transition and the
//! outcome the rest of the app has to learn about are **one transaction**,
//! and that success, failure *and* cancellation stay re-observable until
//! they are explicitly acknowledged. Both are tested against a real
//! SQLite file, by aborting inside the transaction and by dropping and
//! reopening the store (a process restart, as far as the file is
//! concerned) rather than by reading the implementation.

mod transfer_store_support;

use rusqlite::Connection;
use transfer_store_support::{full_session_spec, sample_spec};
use ylx_transfer_core::persistence::transfer_store::{
    CompleteJobAbort, RetryJobError, RetryJobOutcome,
};
use ylx_transfer_core::persistence::{
    AckOutcome, CompleteJobError, JobStateTag, PersistenceError, TerminalOutcome, TransferStore,
};

fn open(path: &std::path::Path) -> TransferStore {
    TransferStore::open(path).expect("open transfer store")
}

fn row_count(path: &std::path::Path, table: &str) -> i64 {
    let conn = Connection::open(path).expect("raw open");
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("count rows")
}

fn failed() -> TerminalOutcome {
    TerminalOutcome::Failed {
        code: "remote_unavailable".to_string(),
        retryable: true,
    }
}

// ---------------------------------------------------------------------
// One transaction
// ---------------------------------------------------------------------

#[test]
fn the_terminal_transition_and_its_outcome_commit_together() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let spec = sample_spec();
    store.create_job("job-a", &spec, "t0").expect("create");

    let outcome = store
        .complete_job("job-a", &TerminalOutcome::Succeeded, "t1")
        .expect("complete");
    assert!(outcome.was_recorded());

    let record = outcome.record();
    assert_eq!(record.job_id, "job-a");
    assert_eq!(record.outcome, TerminalOutcome::Succeeded);
    assert_eq!(record.recorded_at, "t1");
    assert!(!record.is_acknowledged());

    let job = store.get_job("job-a").expect("read").expect("job exists");
    assert_eq!(job.state, JobStateTag::Succeeded);
    assert_eq!(
        job.state_version, 2,
        "the terminal transition bumps version"
    );
    assert_eq!(
        record.state_version, job.state_version,
        "the outbox row is pinned to the transition that produced it"
    );
}

#[test]
fn a_crash_between_the_transition_and_the_outbox_row_commits_neither() {
    for abort in [
        CompleteJobAbort::AfterStateUpdate,
        CompleteJobAbort::AfterOutboxRow,
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("transfer.sqlite3");
        let mut store = open(&path);
        store
            .create_job("job-a", &sample_spec(), "t0")
            .expect("create");

        let error = store
            .complete_job_aborting_after("job-a", &TerminalOutcome::Succeeded, "t1", abort)
            .expect_err("the simulated crash must abort the transaction");
        assert!(
            matches!(error, CompleteJobError::Persistence(_)),
            "unexpected error at {abort:?}: {error}"
        );

        // Restart: nothing of the aborted transaction survived.
        drop(store);
        let store = open(&path);
        let job = store.get_job("job-a").expect("read").expect("job exists");
        assert_eq!(
            job.state,
            JobStateTag::Queued,
            "the job must not be terminal after {abort:?}"
        );
        assert_eq!(job.state_version, 1);
        assert_eq!(row_count(&path, "transfer_completion_outbox"), 0);
        assert!(store.pending_completions().expect("pending").is_empty());
    }
}

// ---------------------------------------------------------------------
// Re-observable until acknowledged
// ---------------------------------------------------------------------

#[test]
fn success_failure_and_cancellation_all_survive_a_restart_until_acknowledged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);

    let cases = [
        ("job-ok", "s-ok", TerminalOutcome::Succeeded),
        ("job-bad", "s-bad", failed()),
        ("job-gone", "s-gone", TerminalOutcome::Cancelled),
    ];
    for (job_id, session, outcome) in &cases {
        let spec = full_session_spec("pi-01", session, "rev-1", &[("f-0001", 10, 0x11)]);
        store.create_job(job_id, &spec, "t0").expect("create");
        store.complete_job(job_id, outcome, "t1").expect("complete");
    }

    // A crash right after the terminal transitions: the app never learned
    // about any of them.
    drop(store);
    let store = open(&path);

    let pending = store.pending_completions().expect("pending");
    assert_eq!(
        pending
            .iter()
            .map(|r| r.job_id.as_str())
            .collect::<Vec<_>>(),
        vec!["job-ok", "job-bad", "job-gone"],
        "every terminal outcome is still deliverable, in order"
    );
    for (record, (_, _, expected)) in pending.iter().zip(&cases) {
        assert_eq!(&record.outcome, expected);
        assert!(!record.is_acknowledged());
    }
    assert!(
        pending[0].sequence < pending[1].sequence && pending[1].sequence < pending[2].sequence,
        "delivery order is monotonic"
    );
}

#[test]
fn a_failed_outcome_keeps_its_code_and_retryable_flag_across_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .complete_job("job-a", &failed(), "t1")
        .expect("complete");
    drop(store);

    let store = open(&path);
    let record = store
        .completion("job-a")
        .expect("read")
        .expect("outbox row exists");
    assert_eq!(record.outcome, failed());
    let job = store.get_job("job-a").expect("read").expect("job");
    assert_eq!(job.state, JobStateTag::Failed);
    assert_eq!(
        job.error,
        Some(("remote_unavailable".to_string(), true)),
        "the job row and the outbox row agree about why it failed"
    );
}

#[test]
fn acknowledging_retires_an_outcome_and_is_itself_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .complete_job("job-a", &TerminalOutcome::Succeeded, "t1")
        .expect("complete");

    match store.acknowledge_completion("job-a", "t2").expect("ack") {
        AckOutcome::Acknowledged(record) => {
            assert_eq!(record.acknowledged_at.as_deref(), Some("t2"))
        }
        other => panic!("expected Acknowledged, got {other:?}"),
    }
    assert!(store.pending_completions().expect("pending").is_empty());

    // A consumer that crashed *after* the ack committed re-acks on restart.
    drop(store);
    let mut store = open(&path);
    assert!(
        store.pending_completions().expect("pending").is_empty(),
        "an acknowledged outcome is never delivered again"
    );
    match store.acknowledge_completion("job-a", "t3").expect("re-ack") {
        AckOutcome::AlreadyAcknowledged(record) => {
            assert_eq!(record.acknowledged_at.as_deref(), Some("t2"));
        }
        other => panic!("expected AlreadyAcknowledged, got {other:?}"),
    }
    assert_eq!(
        store.all_completions().expect("all").len(),
        1,
        "the row is kept as evidence, not deleted"
    );
}

#[test]
fn acknowledging_an_unknown_job_is_reported_not_invented() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    assert_eq!(
        store.acknowledge_completion("nope", "t1").expect("ack"),
        AckOutcome::Unknown
    );
}

// ---------------------------------------------------------------------
// Replaying a terminal transition
// ---------------------------------------------------------------------

#[test]
fn recording_the_same_terminal_outcome_twice_writes_one_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");

    let first = store
        .complete_job("job-a", &TerminalOutcome::Succeeded, "t1")
        .expect("complete");
    let second = store
        .complete_job("job-a", &TerminalOutcome::Succeeded, "t2")
        .expect("re-complete");
    assert!(first.was_recorded());
    assert!(!second.was_recorded(), "the replay must be a no-op");
    assert_eq!(first.record(), second.record());
    assert_eq!(row_count(&path, "transfer_completion_outbox"), 1);
    assert_eq!(
        store
            .get_job("job-a")
            .expect("read")
            .expect("job")
            .state_version,
        2,
        "a replay does not bump the version again"
    );
}

#[test]
fn a_second_different_ending_is_refused_rather_than_overwriting_the_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .complete_job("job-a", &TerminalOutcome::Succeeded, "t1")
        .expect("complete");

    let error = store
        .complete_job("job-a", &TerminalOutcome::Cancelled, "t2")
        .expect_err("a cancellation must not overwrite a committed success");
    match error {
        CompleteJobError::AlreadyTerminal {
            job_id,
            existing,
            requested,
        } => {
            assert_eq!(job_id, "job-a");
            assert_eq!(existing, TerminalOutcome::Succeeded);
            assert_eq!(requested, TerminalOutcome::Cancelled);
        }
        other => panic!("expected AlreadyTerminal, got {other}"),
    }
}

#[test]
fn completing_a_job_that_does_not_exist_is_an_explicit_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    match store.complete_job("ghost", &TerminalOutcome::Succeeded, "t1") {
        Err(CompleteJobError::UnknownJob(job_id)) => assert_eq!(job_id, "ghost"),
        other => panic!("expected UnknownJob, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Lifecycle: an outcome may not be discarded before it is delivered
// ---------------------------------------------------------------------

#[test]
fn a_job_with_an_undelivered_outcome_cannot_be_deleted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_job("job-a", &sample_spec(), "t0")
        .expect("create");
    store
        .complete_job("job-a", &failed(), "t1")
        .expect("complete");

    let error = store
        .delete_job("job-a")
        .expect_err("deleting would lose the undelivered failure");
    assert!(
        matches!(error, PersistenceError::Conflict { .. }),
        "unexpected error: {error}"
    );
    assert_eq!(row_count(&path, "transfer_jobs"), 1);

    store.acknowledge_completion("job-a", "t2").expect("ack");
    assert!(store.delete_job("job-a").expect("delete"));
    for table in TransferStore::transfer_tables() {
        if *table == "transfer_migration_markers" {
            continue;
        }
        assert_eq!(row_count(&path, table), 0, "{table} must be empty");
    }
}

#[test]
fn a_download_dismissal_is_a_tombstone_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_job("download-dismiss", &sample_spec(), "t0")
        .unwrap();
    store
        .complete_job("download-dismiss", &failed(), "t1")
        .unwrap();
    assert!(matches!(
        store.dismiss_job("download-dismiss", "t2"),
        Err(ylx_transfer_core::persistence::DismissJobError::Unacknowledged { .. })
    ));
    store
        .acknowledge_completion("download-dismiss", "t3")
        .unwrap();
    assert!(store.dismiss_job("download-dismiss", "t4").unwrap());
    assert!(store.list_visible_jobs().unwrap().is_empty());
    drop(store);

    let reopened = open(&path);
    let job = reopened.get_job("download-dismiss").unwrap().unwrap();
    assert_eq!(job.dismissed_at.as_deref(), Some("t4"));
    assert_eq!(job.state, JobStateTag::Failed);
    assert!(reopened.completion("download-dismiss").unwrap().is_some());
    assert!(reopened.list_visible_jobs().unwrap().is_empty());
}

#[test]
fn retargeting_moves_the_whole_durable_job_onto_the_retrys_new_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let spec = sample_spec();
    store.create_job("job-old", &spec, "t0").expect("create");
    store
        .complete_job("job-old", &failed(), "t1")
        .expect("complete");

    let refused = store
        .retarget_job("job-old", "job-new", "t2")
        .expect_err("an undelivered failure must not be dropped by a retry");
    assert!(
        matches!(refused, PersistenceError::Conflict { .. }),
        "unexpected error: {refused}"
    );

    store.acknowledge_completion("job-old", "t2").expect("ack");
    let moved = store
        .retarget_job("job-old", "job-new", "t3")
        .expect("retarget");
    assert_eq!(moved.job_id, "job-new");
    assert_eq!(moved.state, JobStateTag::Queued);
    assert_eq!(moved.error, None);
    assert!(moved.state_version > 1);

    drop(store);
    let store = open(&path);
    assert!(store.get_job("job-old").expect("read").is_none());
    assert_eq!(
        store.job_spec("job-new").expect("spec").request_digest(),
        spec.request_digest(),
        "the retried job keeps the identical durable spec"
    );
    assert_eq!(store.file_ledger("job-new").expect("ledger").len(), 2);
    assert_eq!(row_count(&path, "transfer_completion_outbox"), 0);
    assert_eq!(
        store.list_recoverable_jobs().expect("recoverable").len(),
        1,
        "the retried job is recoverable again"
    );
}

#[test]
fn retry_lineage_keeps_the_failed_parent_and_deduplicates_live_children() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let spec = sample_spec();

    store
        .create_job("parent", &spec, "t0")
        .expect("create parent");
    store
        .complete_job("parent", &failed(), "t1")
        .expect("record retryable failure");
    store
        .acknowledge_completion("parent", "t2")
        .expect("acknowledge parent outcome");

    let created = store
        .spawn_retry_job("parent", "child-1", "t3")
        .expect("spawn first retry");
    let child = match created {
        RetryJobOutcome::Created(child) => child,
        RetryJobOutcome::Existing(_) => panic!("first retry must create a child"),
    };
    assert_eq!(child.job_id, "child-1");
    assert_eq!(child.state, JobStateTag::Queued);
    assert_eq!(child.state_version, 1);
    assert_eq!(store.job_spec("child-1").expect("child spec"), spec);
    let child_ledger = store.file_ledger("child-1").expect("child ledger");
    let parent_ledger = store.file_ledger("parent").expect("parent ledger");
    assert_eq!(child_ledger.len(), parent_ledger.len());
    for (child_entry, parent_entry) in child_ledger.iter().zip(parent_ledger.iter()) {
        assert_eq!(child_entry.file_id, parent_entry.file_id);
        assert_eq!(child_entry.status, parent_entry.status);
        assert_eq!(child_entry.bytes_confirmed, parent_entry.bytes_confirmed);
        assert_eq!(child_entry.verified_sha256, parent_entry.verified_sha256);
    }
    assert_eq!(
        store
            .retry_parent("child-1")
            .expect("lineage")
            .expect("lineage row")
            .attempt,
        1
    );
    assert_eq!(
        store
            .latest_retry_child("parent")
            .expect("latest child")
            .expect("child exists")
            .job_id,
        "child-1"
    );

    // A replay with a fresh proposed id cannot create a sibling while the
    // first child is still live. The durable child is the idempotent result.
    let replay = store
        .spawn_retry_job("parent", "child-replay", "t4")
        .expect("duplicate retry");
    assert!(matches!(
        replay,
        RetryJobOutcome::Existing(child) if child.job_id == "child-1"
    ));

    // Once that child has its own acknowledged terminal outcome, a later
    // attempt gets a new child and a monotonic lineage attempt number. The
    // parent remains the original failed, auditable terminal row throughout.
    store
        .complete_job("child-1", &failed(), "t5")
        .expect("complete child");
    store
        .acknowledge_completion("child-1", "t6")
        .expect("acknowledge child");
    let second = store
        .spawn_retry_job("parent", "child-2", "t7")
        .expect("spawn second retry");
    assert!(matches!(
        second,
        RetryJobOutcome::Created(child) if child.job_id == "child-2"
    ));
    assert_eq!(
        store
            .retry_parent("child-2")
            .expect("second lineage")
            .expect("second lineage row")
            .attempt,
        2
    );
    let parent = store
        .get_job("parent")
        .expect("parent read")
        .expect("parent");
    assert_eq!(parent.state, JobStateTag::Failed);
    assert_eq!(parent.error, Some(("remote_unavailable".to_string(), true)));
    assert!(store
        .completion("parent")
        .expect("parent outcome")
        .unwrap()
        .is_acknowledged());

    let unknown = store
        .spawn_retry_job("missing", "child-3", "t8")
        .expect_err("unknown parent");
    assert!(matches!(unknown, RetryJobError::UnknownJob(job) if job == "missing"));
}
