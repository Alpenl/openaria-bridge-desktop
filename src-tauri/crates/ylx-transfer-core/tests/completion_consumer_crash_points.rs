//! Commit 30: the idempotent completion consumer, proved by restarting at
//! every crash point of the outbox protocol.
//!
//! The four points, in the order they happen:
//!
//! 1. after the terminal transition (the outcome is durable, nothing has
//!    consumed it);
//! 2. after the library commit (applied, not emitted, not acknowledged);
//! 3. after the event emit (applied and emitted, not acknowledged);
//! 4. after the acknowledgement (fully delivered).
//!
//! At 1–3 the next start must re-deliver and converge on exactly one
//! library entry; at 4 it must deliver nothing. "Restart" here means
//! dropping the `TransferStore` and reopening the same file, while the
//! projection — standing in for the app library, which lives in a
//! different database — survives, which is precisely the split that makes
//! a single transaction impossible and the outbox necessary.

mod transfer_store_support;

use std::collections::HashMap;

use transfer_store_support::{full_session_spec, sample_spec};
use ylx_transfer_core::persistence::completion_consumer::{
    drain_completions, drain_completions_aborting_after, Completion, CompletionProjection,
    DrainAbort, ProjectionOutcome,
};
use ylx_transfer_core::persistence::{TerminalOutcome, TransferStore};

// ---------------------------------------------------------------------
// A stand-in for the app library
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct LibraryRow {
    key: String,
    outcome: String,
    files: usize,
}

/// Deliberately **appends** on every unrecognised delivery: the only thing
/// stopping a duplicate row is the consumer re-delivering a completion the
/// projection has already recorded, and the projection recognising it. If
/// the protocol acknowledged too early (or too late without a guard), these
/// tests would show a second row rather than pass by luck.
#[derive(Default)]
struct FakeLibrary {
    rows: Vec<LibraryRow>,
    applied: HashMap<String, u64>,
    emitted: Vec<String>,
    apply_error: Option<String>,
    emit_error: Option<String>,
    defer_reason: Option<String>,
}

impl FakeLibrary {
    fn rows_for(&self, key: &str) -> Vec<&LibraryRow> {
        self.rows.iter().filter(|row| row.key == key).collect()
    }
}

impl CompletionProjection for FakeLibrary {
    type Error = String;

    fn apply(&mut self, completion: Completion<'_>) -> Result<ProjectionOutcome, Self::Error> {
        if let Some(error) = &self.apply_error {
            return Err(error.clone());
        }
        if let Some(reason) = &self.defer_reason {
            return Ok(ProjectionOutcome::Deferred(reason.clone()));
        }
        if self.applied.get(completion.job_id()) == Some(&completion.record.state_version) {
            return Ok(ProjectionOutcome::AlreadyApplied);
        }
        let identity = completion.spec.identity();
        self.rows.push(LibraryRow {
            key: format!(
                "{}|{}",
                identity.device_id().as_str(),
                identity.session_id().as_str()
            ),
            outcome: completion.record.outcome.to_string(),
            files: completion.spec.requested_files().count(),
        });
        self.applied.insert(
            completion.job_id().to_string(),
            completion.record.state_version,
        );
        Ok(ProjectionOutcome::Applied)
    }

    fn emit(
        &mut self,
        completion: Completion<'_>,
        _outcome: &ProjectionOutcome,
    ) -> Result<(), Self::Error> {
        if let Some(error) = &self.emit_error {
            return Err(error.clone());
        }
        self.emitted.push(format!(
            "{}:{}",
            completion.job_id(),
            completion.record.outcome
        ));
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl Fixture {
    /// A store holding one completed job, i.e. crash point 1: the terminal
    /// transition committed and nothing has consumed it yet.
    fn completed(outcome: &TerminalOutcome) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("transfer.sqlite3");
        let mut store = TransferStore::open(&path).expect("open");
        store
            .create_job("job-a", &sample_spec(), "t0")
            .expect("create");
        store
            .complete_job("job-a", outcome, "t1")
            .expect("complete");
        Fixture { _dir: dir, path }
    }

    /// Reopening the same file is this suite's "process restart".
    fn restart(&self) -> TransferStore {
        TransferStore::open(&self.path).expect("reopen")
    }
}

// ---------------------------------------------------------------------
// Crash point 1: after the terminal transition
// ---------------------------------------------------------------------

#[test]
fn a_crash_after_the_transition_still_delivers_the_outcome_on_the_next_start() {
    for outcome in [
        TerminalOutcome::Succeeded,
        TerminalOutcome::Failed {
            code: "disk_full".to_string(),
            retryable: false,
        },
        TerminalOutcome::Cancelled,
    ] {
        let fixture = Fixture::completed(&outcome);
        let mut store = fixture.restart();
        let mut library = FakeLibrary::default();

        let report = drain_completions(&mut store, &mut library, "t2").expect("drain");
        assert_eq!(report.acknowledged, vec!["job-a".to_string()]);
        assert!(report.already_applied.is_empty());
        assert_eq!(library.rows_for("pi-01|session-x").len(), 1);
        assert_eq!(library.rows[0].outcome, outcome.to_string());
        assert_eq!(
            library.rows[0].files, 2,
            "the durable spec supplied the context"
        );
        assert_eq!(library.emitted.len(), 1);
        assert!(store.pending_completions().expect("pending").is_empty());
    }
}

// ---------------------------------------------------------------------
// Crash point 2: after the library commit, before the emit and the ack
// ---------------------------------------------------------------------

#[test]
fn a_crash_after_the_library_commit_redelivers_without_duplicating() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut library = FakeLibrary::default();

    {
        let mut store = fixture.restart();
        drain_completions_aborting_after(&mut store, &mut library, "t2", DrainAbort::AfterApply)
            .expect("first drain");
    }
    assert_eq!(library.rows.len(), 1, "the library commit happened");
    assert!(library.emitted.is_empty(), "the emit did not");

    let mut store = fixture.restart();
    assert_eq!(
        store.pending_completions().expect("pending").len(),
        1,
        "an unacknowledged outcome is still deliverable"
    );

    let report = drain_completions(&mut store, &mut library, "t3").expect("second drain");
    assert_eq!(report.acknowledged, vec!["job-a".to_string()]);
    assert_eq!(
        report.already_applied,
        vec!["job-a".to_string()],
        "the re-delivery is recognised, not re-applied"
    );
    assert_eq!(library.rows.len(), 1, "no duplicate library entry");
    assert_eq!(library.emitted.len(), 1);
    assert!(store.pending_completions().expect("pending").is_empty());
}

// ---------------------------------------------------------------------
// Crash point 3: after the emit, before the ack
// ---------------------------------------------------------------------

#[test]
fn a_crash_after_the_emit_redelivers_and_converges_on_one_entry() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut library = FakeLibrary::default();

    {
        let mut store = fixture.restart();
        drain_completions_aborting_after(&mut store, &mut library, "t2", DrainAbort::AfterEmit)
            .expect("first drain");
    }
    assert_eq!(library.rows.len(), 1);
    assert_eq!(library.emitted.len(), 1);

    let mut store = fixture.restart();
    let report = drain_completions(&mut store, &mut library, "t3").expect("second drain");
    assert_eq!(report.acknowledged, vec!["job-a".to_string()]);
    assert_eq!(report.already_applied, vec!["job-a".to_string()]);
    assert_eq!(
        library.rows.len(),
        1,
        "delivery is at-least-once, the library is not"
    );
    assert_eq!(
        library.emitted.len(),
        2,
        "the event is re-emitted; that is the cost of never losing one"
    );
    assert!(store.pending_completions().expect("pending").is_empty());
}

// ---------------------------------------------------------------------
// Crash point 4: after the acknowledgement
// ---------------------------------------------------------------------

#[test]
fn a_crash_after_the_ack_delivers_nothing_more() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut library = FakeLibrary::default();
    {
        let mut store = fixture.restart();
        drain_completions(&mut store, &mut library, "t2").expect("first drain");
    }

    let mut store = fixture.restart();
    let report = drain_completions(&mut store, &mut library, "t3").expect("second drain");
    assert!(report.is_empty(), "nothing left to deliver: {report:?}");
    assert_eq!(library.rows.len(), 1);
    assert_eq!(library.emitted.len(), 1);
}

// ---------------------------------------------------------------------
// A consumer that cannot apply must not acknowledge
// ---------------------------------------------------------------------

#[test]
fn an_apply_failure_leaves_the_outcome_observable_until_it_succeeds() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut library = FakeLibrary {
        apply_error: Some("library database is locked".to_string()),
        ..FakeLibrary::default()
    };

    let mut store = fixture.restart();
    let report = drain_completions(&mut store, &mut library, "t2").expect("drain");
    assert_eq!(report.acknowledged, Vec::<String>::new());
    assert_eq!(report.deferred.len(), 1);
    assert_eq!(report.deferred[0].0, "job-a");
    assert!(library.rows.is_empty());
    assert_eq!(store.pending_completions().expect("pending").len(), 1);

    library.apply_error = None;
    let report = drain_completions(&mut store, &mut library, "t3").expect("drain again");
    assert_eq!(report.acknowledged, vec!["job-a".to_string()]);
    assert_eq!(library.rows.len(), 1);
}

#[test]
fn an_emit_failure_leaves_the_outcome_observable_and_does_not_re_apply() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut library = FakeLibrary {
        emit_error: Some("event bus is down".to_string()),
        ..FakeLibrary::default()
    };

    let mut store = fixture.restart();
    let report = drain_completions(&mut store, &mut library, "t2").expect("drain");
    assert!(report.acknowledged.is_empty());
    assert_eq!(report.deferred.len(), 1);
    assert_eq!(library.rows.len(), 1, "the library commit already happened");

    library.emit_error = None;
    let report = drain_completions(&mut store, &mut library, "t3").expect("drain again");
    assert_eq!(report.acknowledged, vec!["job-a".to_string()]);
    assert_eq!(report.already_applied, vec!["job-a".to_string()]);
    assert_eq!(library.rows.len(), 1, "still exactly one entry");
    assert_eq!(library.emitted.len(), 1);
}

#[test]
fn a_projection_that_defers_keeps_the_outcome_queued() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut library = FakeLibrary {
        defer_reason: Some("the downloaded file is not on disk yet".to_string()),
        ..FakeLibrary::default()
    };

    let mut store = fixture.restart();
    let report = drain_completions(&mut store, &mut library, "t2").expect("drain");
    assert_eq!(
        report.deferred,
        vec![(
            "job-a".to_string(),
            "the downloaded file is not on disk yet".to_string()
        )]
    );
    assert_eq!(store.pending_completions().expect("pending").len(), 1);
}

// ---------------------------------------------------------------------
// Ordering, multiple jobs, and unusable specs
// ---------------------------------------------------------------------

#[test]
fn several_outcomes_are_delivered_in_recorded_order_and_acked_individually() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let mut store = TransferStore::open(&path).expect("open");
    for (job_id, session) in [("job-1", "s-1"), ("job-2", "s-2"), ("job-3", "s-3")] {
        let spec = full_session_spec("pi-01", session, "rev-1", &[("f-0001", 8, 0x22)]);
        store.create_job(job_id, &spec, "t0").expect("create");
        store
            .complete_job(job_id, &TerminalOutcome::Succeeded, "t1")
            .expect("complete");
    }

    let mut library = FakeLibrary::default();
    let report = drain_completions(&mut store, &mut library, "t2").expect("drain");
    assert_eq!(report.acknowledged, vec!["job-1", "job-2", "job-3"]);
    assert_eq!(
        library
            .rows
            .iter()
            .map(|row| row.key.as_str())
            .collect::<Vec<_>>(),
        vec!["pi-01|s-1", "pi-01|s-2", "pi-01|s-3"]
    );
    assert!(store.pending_completions().expect("pending").is_empty());
}

#[test]
fn a_completion_whose_spec_is_unusable_is_reported_and_never_acknowledged() {
    let fixture = Fixture::completed(&TerminalOutcome::Succeeded);
    let mut store = fixture.restart();
    store
        .raw_execute("DELETE FROM transfer_job_specs WHERE job_id = 'job-a'")
        .expect("corrupt the spec the way a bad manual edit would");

    let mut library = FakeLibrary::default();
    let report = drain_completions(&mut store, &mut library, "t2").expect("drain");
    assert!(report.acknowledged.is_empty());
    assert_eq!(report.blocked.len(), 1);
    assert_eq!(report.blocked[0].job_id, "job-a");
    assert!(library.rows.is_empty());
    assert_eq!(
        store.pending_completions().expect("pending").len(),
        1,
        "an unreadable spec is a bug to fix, not a result to drop"
    );
}
