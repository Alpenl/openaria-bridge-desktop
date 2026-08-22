//! Commit 30: the idempotent consumer that drains the completion outbox.
//!
//! The handoff this module implements is deliberately *not* a transaction.
//! The durable transfer state lives in [`TransferStore`]'s SQLite file and
//! the user-facing library lives somewhere else entirely (today: the app
//! store, whose shape this crate does not own), so there is no single
//! commit that can cover both. What replaces it is the classic outbox
//! protocol, in a fixed order:
//!
//! 1. **Terminal transition + outcome** commit together (commit 29).
//! 2. **Apply** the outcome to the library and commit *that*.
//! 3. **Emit** the observable event.
//! 4. **Acknowledge** the outbox row.
//!
//! Every step before the ack is re-runnable, so a crash at any of the four
//! points converges on the next start: the outcome is still unacknowledged,
//! so it is delivered again. That makes delivery *at least once*, which is
//! only safe because step 2 is required to be idempotent — a
//! [`CompletionProjection`] that has already applied a completion must say
//! so ([`ProjectionOutcome::AlreadyApplied`]) rather than append a second
//! library entry. The `state_version` on every [`CompletionRecord`] is
//! what lets a projection recognise a re-delivery of the same fact.
//!
//! A projection that *cannot* apply right now (an I/O error, a file that
//! is not on disk yet) returns [`ProjectionOutcome::Deferred`] or an
//! error, and the row is left unacknowledged — visibly stuck rather than
//! silently dropped.

use super::error::PersistenceError;
use super::transfer_store::{
    AckOutcome, CompletionRecord, RecoveryBlocked, StoredJob, TransferStore,
};
use crate::domain::JobSpec;

/// One completion, with everything the projection needs to act on it: the
/// outbox row (the *outcome*) plus the durable spec (the *context*). This
/// pair is what replaces the pending-download JSON sidecar — commit 34.
#[derive(Debug, Clone, Copy)]
pub struct Completion<'a> {
    pub record: &'a CompletionRecord,
    pub job: &'a StoredJob,
    pub spec: &'a JobSpec,
}

impl Completion<'_> {
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.record.job_id
    }
}

/// What a projection did with one completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionOutcome {
    /// The library now durably reflects this outcome. Acknowledge it.
    Applied,
    /// The library *already* reflected this outcome (a re-delivery after a
    /// crash between the library commit and the ack). Acknowledge it —
    /// this is the case that must never produce a duplicate entry.
    AlreadyApplied,
    /// Not applicable right now; leave the outcome re-observable. The
    /// string is a diagnostic, not a control signal.
    Deferred(String),
}

/// The seam between the durable transfer store and whatever owns the
/// user-facing library.
pub trait CompletionProjection {
    type Error: std::fmt::Display;

    /// Durably apply one terminal outcome. **Must be idempotent**: it is
    /// called again for the same completion whenever a crash lands between
    /// the library commit and the acknowledgement.
    fn apply(&mut self, completion: Completion<'_>) -> Result<ProjectionOutcome, Self::Error>;

    /// Publish the outcome to observers, after `apply` committed and
    /// before the ack. Also at-least-once; an emit failure defers the
    /// acknowledgement so the whole delivery is retried.
    fn emit(
        &mut self,
        completion: Completion<'_>,
        outcome: &ProjectionOutcome,
    ) -> Result<(), Self::Error> {
        let _ = (completion, outcome);
        Ok(())
    }
}

/// What one [`drain_completions`] pass did. Every completion lands in
/// exactly one bucket, so "nothing happened" and "everything is stuck" are
/// distinguishable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainReport {
    /// Job ids applied and acknowledged by this pass.
    pub acknowledged: Vec<String>,
    /// Job ids that were re-delivered and recognised as already applied,
    /// then acknowledged. A subset of `acknowledged` in effect, listed
    /// separately so a test (and an operator) can see convergence happen.
    pub already_applied: Vec<String>,
    /// `(job_id, reason)` for outcomes deliberately left unacknowledged.
    pub deferred: Vec<(String, String)>,
    /// Completions whose durable spec is unusable. Reported, never
    /// acknowledged — an unreadable spec is a bug to fix, not a result to
    /// throw away.
    pub blocked: Vec<RecoveryBlocked>,
}

impl DrainReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.acknowledged.is_empty() && self.deferred.is_empty() && self.blocked.is_empty()
    }
}

/// Test-only crash points, one per step of the protocol above.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainAbort {
    /// Stop right after the library commit — before the emit and the ack.
    AfterApply,
    /// Stop right after the emit — before the ack.
    AfterEmit,
}

/// Drains every unacknowledged completion, oldest first.
pub fn drain_completions<P: CompletionProjection>(
    store: &mut TransferStore,
    projection: &mut P,
    now: &str,
) -> Result<DrainReport, PersistenceError> {
    drain_inner(store, projection, now, None)
}

#[doc(hidden)]
pub fn drain_completions_aborting_after<P: CompletionProjection>(
    store: &mut TransferStore,
    projection: &mut P,
    now: &str,
    abort: DrainAbort,
) -> Result<DrainReport, PersistenceError> {
    drain_inner(store, projection, now, Some(abort))
}

fn drain_inner<P: CompletionProjection>(
    store: &mut TransferStore,
    projection: &mut P,
    now: &str,
    abort: Option<DrainAbort>,
) -> Result<DrainReport, PersistenceError> {
    let mut report = DrainReport::default();
    for record in store.pending_completions()? {
        let Some(job) = store.get_job(&record.job_id)? else {
            // The FK is ON DELETE CASCADE, so this cannot happen through
            // the store's own API; treat it as blocked rather than
            // pretending the outcome was delivered.
            report.blocked.push(RecoveryBlocked {
                job_id: record.job_id.clone(),
                identity: None,
                reason: super::transfer_store::RecoveryBlockedReason::MissingSpec,
                detail: format!(
                    "completion {} has no transfer_jobs row",
                    record.job_id.clone()
                ),
            });
            continue;
        };
        let spec = match store.job_spec(&record.job_id) {
            Ok(spec) => spec,
            Err(super::transfer_store::JobSpecLoadError::Blocked(blocked)) => {
                report.blocked.push(*blocked);
                continue;
            }
            Err(super::transfer_store::JobSpecLoadError::UnknownJob(job_id)) => {
                report.blocked.push(RecoveryBlocked {
                    job_id,
                    identity: Some(job.identity.clone()),
                    reason: super::transfer_store::RecoveryBlockedReason::MissingSpec,
                    detail: "the job disappeared between reading the outbox and its spec"
                        .to_string(),
                });
                continue;
            }
            Err(super::transfer_store::JobSpecLoadError::Persistence(error)) => return Err(error),
        };

        let completion = Completion {
            record: &record,
            job: &job,
            spec: &spec,
        };

        // Step 2: apply to the library.
        let outcome = match projection.apply(completion) {
            Ok(outcome) => outcome,
            Err(error) => {
                report
                    .deferred
                    .push((record.job_id.clone(), error.to_string()));
                continue;
            }
        };
        if let ProjectionOutcome::Deferred(reason) = &outcome {
            report
                .deferred
                .push((record.job_id.clone(), reason.clone()));
            continue;
        }
        if outcome == ProjectionOutcome::AlreadyApplied {
            report.already_applied.push(record.job_id.clone());
        }
        if abort == Some(DrainAbort::AfterApply) {
            return Ok(report);
        }

        // Step 3: emit.
        if let Err(error) = projection.emit(completion, &outcome) {
            report
                .deferred
                .push((record.job_id.clone(), error.to_string()));
            continue;
        }
        if abort == Some(DrainAbort::AfterEmit) {
            return Ok(report);
        }

        // Step 4: acknowledge — and only now.
        match store.acknowledge_completion(&record.job_id, now)? {
            AckOutcome::Acknowledged(_) | AckOutcome::AlreadyAcknowledged(_) => {
                report.acknowledged.push(record.job_id.clone());
            }
            AckOutcome::Unknown => report.deferred.push((
                record.job_id.clone(),
                "the outbox row disappeared before it could be acknowledged".to_string(),
            )),
        }
    }
    Ok(report)
}
