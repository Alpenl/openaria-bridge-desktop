//! Issue #1 phase 3, commits 37–40: the **one** domain state model, the
//! pure `JobAggregate` reducer, expected-version CAS, and the atomic
//! [`JobSnapshot`].
//!
//! # Commit 37 — one state model, one transition graph
//!
//! [`TransferJobState`] (in `transfer::mod`) is the vertex set;
//! [`is_legal_transition`] in this module is the **edge set**, and it is
//! the only definition of "which transitions are legal" this codebase
//! reasons about. `persistence` is allowed to encode a *state tag* and a
//! *version* for a row — nothing more. `persistence::schema::
//! is_valid_transition` still exists (that module is owned elsewhere and
//! is scheduled for deletion by its owner), so this module pins it down
//! with an exhaustive 13x13 equivalence test: if the persistence copy ever
//! disagrees with this graph by a single edge, that test fails. There is
//! therefore no second, independently-evolvable state graph.
//!
//! # Commit 38 — the reducer is pure
//!
//! [`JobAggregate::decide`] takes the current state (plus version and
//! desired run state) and one [`JobCommand`], and returns a [`Decision`]:
//! an outcome plus an ordered list of [`Effect`]s for someone else to
//! perform. It opens no database, makes no network call, spawns no thread
//! and reads no clock — which is what makes the exhaustive state x command
//! table below possible at all.
//!
//! # Commit 39 — expected-version CAS
//!
//! Every durable transition the reducer proposes is an
//! [`Effect::Commit`] carrying the exact `expected_version` it was decided
//! against. A performer that finds a different version must report a stale
//! result (see `CoordinatorError::Stale`) instead of overwriting the state
//! another command already committed. A chain of commits inside one
//! decision (`cancelling` then `cancelled`) carries strictly increasing
//! expected versions, so replaying half a chain cannot silently succeed.
//!
//! # Commit 40 — one snapshot, one version
//!
//! [`JobSnapshot`] carries identity, state, desired run state, progress
//! and error together with the `version` they were all read at, so callers
//! stop stitching a job's view together from several reads that can
//! disagree.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::device::{CaptureActivityState, ConnectionState};
use crate::domain::{DeviceId, SessionId};

use super::commit::DownloadCommitOutcome;
use super::progress::JobProgress;
use super::queue::InterruptReason;
use super::{FailureCode, JobId, TransferJobState};

// =====================================================================
// Commit 37: the single transition graph
// =====================================================================

/// Every legal `from -> to` edge of the transfer job state machine. This
/// is the single definition; see the module doc comment.
///
/// Terminal states (`succeeded`/`failed`/`cancelled`) have no outgoing
/// edge at all — a retry is a *new* job, never a resurrection of this one.
#[must_use]
pub fn is_legal_transition(from: &TransferJobState, to: &TransferJobState) -> bool {
    use TransferJobState as S;
    if from.is_terminal() {
        return false;
    }
    matches!(
        (from, to),
        (S::Queued, S::WaitingForDevice)
            | (S::Queued, S::WaitingForPairing)
            | (S::Queued, S::Preparing)
            | (S::Queued, S::Cancelling)
            | (S::WaitingForDevice, S::Queued)
            | (S::WaitingForDevice, S::Preparing)
            | (S::WaitingForDevice, S::PausedCaptureActive)
            | (S::WaitingForDevice, S::Cancelling)
            | (S::WaitingForPairing, S::Queued)
            | (S::WaitingForPairing, S::Preparing)
            | (S::WaitingForPairing, S::Cancelling)
            | (S::PausedCaptureActive, S::Queued)
            | (S::PausedCaptureActive, S::Preparing)
            | (S::PausedCaptureActive, S::Cancelling)
            | (S::Preparing, S::Transferring)
            | (S::Preparing, S::WaitingForDevice)
            | (S::Preparing, S::Failed { .. })
            | (S::Preparing, S::Cancelling)
            | (S::Transferring, S::Verifying)
            | (S::Transferring, S::RetryWait)
            | (S::Transferring, S::PausedCaptureActive)
            | (S::Transferring, S::Failed { .. })
            | (S::Transferring, S::Cancelling)
            | (S::Verifying, S::Committing)
            | (S::Verifying, S::RetryWait)
            | (S::Verifying, S::Failed { .. })
            | (S::Verifying, S::Cancelling)
            | (S::Committing, S::Succeeded)
            | (S::Committing, S::RetryWait)
            | (S::Committing, S::Failed { .. })
            | (S::Committing, S::Cancelling)
            | (S::RetryWait, S::Queued)
            | (S::RetryWait, S::Preparing)
            | (S::RetryWait, S::Cancelling)
            | (S::RetryWait, S::Failed { .. })
            | (S::Cancelling, S::Cancelled)
            | (S::Cancelling, S::Failed { .. })
    )
}

/// One representative value per [`TransferJobState`] variant, in plan 5.4
/// order. Exists so tests can enumerate the whole state space rather than
/// hand-listing it per test (and so adding a variant makes the exhaustive
/// tables fail loudly).
#[must_use]
pub fn all_states() -> Vec<TransferJobState> {
    vec![
        TransferJobState::Queued,
        TransferJobState::WaitingForDevice,
        TransferJobState::WaitingForPairing,
        TransferJobState::PausedCaptureActive,
        TransferJobState::Preparing,
        TransferJobState::Transferring,
        TransferJobState::Verifying,
        TransferJobState::Committing,
        TransferJobState::RetryWait,
        TransferJobState::Cancelling,
        TransferJobState::Succeeded,
        TransferJobState::Failed {
            code: FailureCode::Network,
            retryable: true,
        },
        TransferJobState::Cancelled,
    ]
}

/// The stable snake_case name of a state, payload ignored. Used by the
/// table-driven tests (and by anything that wants to name a state without
/// caring about `Failed`'s payload).
#[must_use]
pub fn state_name(state: &TransferJobState) -> &'static str {
    match state {
        TransferJobState::Queued => "queued",
        TransferJobState::WaitingForDevice => "waiting_for_device",
        TransferJobState::WaitingForPairing => "waiting_for_pairing",
        TransferJobState::PausedCaptureActive => "paused_capture_active",
        TransferJobState::Preparing => "preparing",
        TransferJobState::Transferring => "transferring",
        TransferJobState::Verifying => "verifying",
        TransferJobState::Committing => "committing",
        TransferJobState::RetryWait => "retry_wait",
        TransferJobState::Cancelling => "cancelling",
        TransferJobState::Succeeded => "succeeded",
        TransferJobState::Failed { .. } => "failed",
        TransferJobState::Cancelled => "cancelled",
    }
}

/// Is there a legal route from `from` to `to` using at most one
/// intermediate hop through `queued`?
///
/// The graph is deliberately sparse: `paused_capture_active` has no direct
/// edge to `waiting_for_device`, for example. Rather than teaching every
/// caller which pairs need a detour (or, worse, letting them propose an
/// illegal edge and swallow the rejection — what the pre-migration worker
/// did), the reducer asks for a *target* and this function answers with
/// the exact chain of durable commits that reaches it, or `None` when the
/// graph has no route at all and the job must stay where it is.
#[must_use]
fn route(from: &TransferJobState, to: &TransferJobState) -> Option<Vec<TransferJobState>> {
    if from == to {
        return Some(Vec::new());
    }
    if is_legal_transition(from, to) {
        return Some(vec![to.clone()]);
    }
    if is_legal_transition(from, &TransferJobState::Queued)
        && is_legal_transition(&TransferJobState::Queued, to)
    {
        return Some(vec![TransferJobState::Queued, to.clone()]);
    }
    None
}

// =====================================================================
// Commit 46: readiness is one versioned device snapshot
// =====================================================================

/// What one device's state means for a job that wants to use it. Derived
/// from a [`DeviceSnapshot`] — never from two separate reads that can
/// disagree with each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceReadiness {
    Ready,
    WaitDevice,
    WaitPairing,
    CapturePaused,
}

/// Connection state and capture activity read **together**, stamped with
/// the observation `version` they were read at.
///
/// The version is a monotonically increasing observation counter (minted
/// by whoever performs the read — see `coordinator::Inner::observe_device`),
/// not the connection epoch: a device going offline lowers its epoch to
/// nothing, and a snapshot that looked stale for that reason would be
/// dropped exactly when it matters most. A job records the version of the
/// last snapshot it acted on, so an observation that raced past a newer one
/// can no longer re-park a job the newer one already released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub version: u64,
    pub connection: ConnectionState,
    pub capture: CaptureActivityState,
}

impl DeviceSnapshot {
    #[must_use]
    pub fn new(version: u64, connection: ConnectionState, capture: CaptureActivityState) -> Self {
        DeviceSnapshot {
            version,
            connection,
            capture,
        }
    }

    /// The single definition of "is this device usable right now".
    #[must_use]
    pub fn readiness(&self) -> DeviceReadiness {
        match self.connection {
            ConnectionState::Connected { .. } => match self.capture {
                CaptureActivityState::Recording
                | CaptureActivityState::Starting
                | CaptureActivityState::Stopping => DeviceReadiness::CapturePaused,
                CaptureActivityState::Idle
                | CaptureActivityState::Error
                | CaptureActivityState::Unknown => DeviceReadiness::Ready,
            },
            ConnectionState::Pairing { .. } => DeviceReadiness::WaitPairing,
            ConnectionState::Disconnected | ConnectionState::Expired { .. } => {
                DeviceReadiness::WaitDevice
            }
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.readiness() == DeviceReadiness::Ready
    }
}

// =====================================================================
// Commit 42: what a worker reports, so the reducer picks the state
// =====================================================================

/// What a worker *observed*, never what it decided. Before commit 42 the
/// worker chose the next `TransferJobState` itself and asked the
/// coordinator to commit it; now it reports the stage it finished (or the
/// way it was interrupted) and [`JobAggregate::decide`] picks the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerReport {
    /// Publication preflight passed; the job may start moving bytes.
    Prepared,
    PreparationFailed {
        code: FailureCode,
        retryable: bool,
    },
    /// Every file downloaded and verified.
    TransferComplete,
    TransferFailed {
        code: FailureCode,
        retryable: bool,
    },
    /// The worker boundary caught a panic while owning this job. The
    /// reducer turns the machinery fault into a non-retryable terminal
    /// failure so a panic can never strand a durable non-terminal row.
    WorkerPanicked {
        detail: String,
    },
    /// An in-flight transfer unwound at a chunk boundary.
    Interrupted(InterruptReason),
    /// Verification finished.
    Verified,
    /// The atomic session commit finished.
    CommitComplete(DownloadCommitOutcome),
    CommitFailed {
        code: FailureCode,
        retryable: bool,
    },
}

impl WorkerReport {
    /// The stage the worker must have been in for this report to apply.
    #[must_use]
    fn expected_state(&self) -> Option<TransferJobState> {
        match self {
            WorkerReport::Prepared | WorkerReport::PreparationFailed { .. } => {
                Some(TransferJobState::Preparing)
            }
            WorkerReport::TransferComplete
            | WorkerReport::TransferFailed { .. }
            | WorkerReport::Interrupted(_) => Some(TransferJobState::Transferring),
            WorkerReport::WorkerPanicked { .. } => None,
            WorkerReport::Verified => Some(TransferJobState::Verifying),
            WorkerReport::CommitComplete(_) | WorkerReport::CommitFailed { .. } => {
                Some(TransferJobState::Committing)
            }
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            WorkerReport::Prepared => "prepared",
            WorkerReport::PreparationFailed { .. } => "preparation_failed",
            WorkerReport::TransferComplete => "transfer_complete",
            WorkerReport::TransferFailed { .. } => "transfer_failed",
            WorkerReport::WorkerPanicked { .. } => "worker_panicked",
            WorkerReport::Interrupted(_) => "interrupted",
            WorkerReport::Verified => "verified",
            WorkerReport::CommitComplete(_) => "commit_complete",
            WorkerReport::CommitFailed { .. } => "commit_failed",
        }
    }
}

// =====================================================================
// Commit 38: commands, effects, decisions
// =====================================================================

/// What the *user* wants the job to be doing, independent of where its
/// state machine currently is. `paused` is a user intent, not a state:
/// plan 5.4's tagged enum has no "paused by user" variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredRunState {
    Run,
    Paused,
}

/// Everything that can drive one job. Worker results, dispatcher ticks
/// and user commands all become one of these and enter through the single
/// per-job serialized entry point (commit 41).
#[derive(Debug, Clone, PartialEq)]
pub enum JobCommand {
    /// A worker/dispatcher-observed move of the state machine — the
    /// worker reports *what it observed*, the reducer decides whether the
    /// move is legal.
    Transition(TransferJobState),
    /// User pause. Sets the desired run state, does not (and cannot)
    /// invent a "paused" state.
    Pause,
    /// User resume.
    Resume,
    /// User cancel: request the interrupt and durably enter `cancelling`.
    Cancel,
    /// Drive a job that is already cancelling (or that was cancelled while
    /// parked) all the way to `cancelled`. Idempotent by construction.
    FinalizeCancel,
    /// Retry a failed job — which per the state graph means enqueuing a
    /// *new* job, never re-animating this row.
    Retry,
    /// Forget a terminal job.
    Dismiss,
    /// Commit 46: one versioned reading of the job's device. The reducer —
    /// not the worker, not the dispatcher — decides which parked state (if
    /// any) that reading implies, and whether an *active* transfer has to
    /// be interrupted because the device went away underneath it.
    DeviceObserved(DeviceSnapshot),
    /// Commit 42: a worker reporting the stage it just finished.
    Worker(WorkerReport),
}

impl JobCommand {
    /// Stable name, for table-driven tests and diagnostics.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            JobCommand::Transition(_) => "transition",
            JobCommand::Pause => "pause",
            JobCommand::Resume => "resume",
            JobCommand::Cancel => "cancel",
            JobCommand::FinalizeCancel => "finalize_cancel",
            JobCommand::Retry => "retry",
            JobCommand::Dismiss => "dismiss",
            JobCommand::DeviceObserved(_) => "device_observed",
            JobCommand::Worker(_) => "worker",
        }
    }
}

/// Something the reducer decided must happen. The reducer never performs
/// any of these itself — that is the whole point of commit 38.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Durably commit `to`, but only if the job is still at
    /// `expected_version` (commit 39). The performer must bump the version
    /// on success and report a stale result otherwise.
    Commit {
        expected_version: u64,
        to: TransferJobState,
    },
    /// Publish the user's run intent.
    SetDesiredRunState(DesiredRunState),
    /// Ask any in-flight worker to unwind at its next chunk boundary.
    RequestInterrupt(InterruptReason),
    /// Clear a previously-requested interrupt.
    ClearInterrupt,
    /// Block until no worker owns this job any more. Splits an effect list
    /// into a before-phase and an after-phase for the performer: the
    /// per-job critical section is released across this effect, otherwise
    /// the worker being waited for could never make progress.
    AwaitWorkerRelease,
    /// Nudge the scheduler to look at this job again.
    Dispatch,
    /// Remember that this job has now acted on device observation
    /// `version`, so a later, older observation is ignored instead of
    /// re-parking a job a newer reading already released (commit 46).
    RecordDeviceVersion(u64),
    /// Enqueue a fresh job cloned from this one (retry lineage). Performed
    /// by the caller, because it creates a *different* job.
    SpawnRetryJob,
    /// Drop this job from memory and from its durable records. Performed
    /// by the caller, for the same reason.
    RemoveJob,
}

/// Why a command was refused. A refused command yields **no** effects.
#[derive(Debug, Clone, PartialEq)]
pub enum RejectReason {
    AlreadyTerminal,
    NotTerminal,
    NotFailed,
    IllegalTransition {
        from: TransferJobState,
        to: TransferJobState,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandOutcome {
    /// The command applies and produced effects.
    Accepted,
    /// The command is legal but there is nothing to do (already there).
    NoOp,
    /// The command does not apply in this state.
    Rejected(RejectReason),
}

impl CommandOutcome {
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, CommandOutcome::Rejected(_))
    }
}

/// The reducer's return value: one outcome plus an ordered effect list.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub outcome: CommandOutcome,
    pub effects: Vec<Effect>,
}

impl Decision {
    fn accepted(effects: Vec<Effect>) -> Self {
        Decision {
            outcome: CommandOutcome::Accepted,
            effects,
        }
    }

    fn no_op() -> Self {
        Decision {
            outcome: CommandOutcome::NoOp,
            effects: Vec::new(),
        }
    }

    fn rejected(reason: RejectReason) -> Self {
        Decision {
            outcome: CommandOutcome::Rejected(reason),
            effects: Vec::new(),
        }
    }

    /// The last state this decision would leave the job in, if every
    /// [`Effect::Commit`] it proposes is performed.
    #[must_use]
    pub fn final_state(&self, current: &TransferJobState) -> TransferJobState {
        self.effects
            .iter()
            .rev()
            .find_map(|e| match e {
                Effect::Commit { to, .. } => Some(to.clone()),
                _ => None,
            })
            .unwrap_or_else(|| current.clone())
    }
}

/// The pure per-job reducer. Holds exactly the facts a decision needs:
/// where the job is, which version that reading came from, and what the
/// user wants it to be doing.
#[derive(Debug, Clone, PartialEq)]
pub struct JobAggregate {
    pub state: TransferJobState,
    pub version: u64,
    pub desired_run_state: DesiredRunState,
    /// The `version` of the newest [`DeviceSnapshot`] this job has already
    /// acted on (commit 46). Zero means "never observed a device".
    pub observed_device_version: u64,
}

impl JobAggregate {
    #[must_use]
    pub fn new(state: TransferJobState) -> Self {
        JobAggregate {
            state,
            version: 1,
            desired_run_state: DesiredRunState::Run,
            observed_device_version: 0,
        }
    }

    #[must_use]
    pub fn with_version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }

    #[must_use]
    pub fn with_desired_run_state(mut self, desired: DesiredRunState) -> Self {
        self.desired_run_state = desired;
        self
    }

    #[must_use]
    pub fn with_observed_device_version(mut self, version: u64) -> Self {
        self.observed_device_version = version;
        self
    }

    /// The whole reducer. Pure: no I/O, no clock, no threads, no locks.
    #[must_use]
    pub fn decide(&self, command: JobCommand) -> Decision {
        match command {
            JobCommand::Transition(to) => self.decide_transition(to),
            JobCommand::Pause => self.decide_pause(),
            JobCommand::Resume => self.decide_resume(),
            JobCommand::Cancel => self.decide_cancel(),
            JobCommand::FinalizeCancel => self.decide_finalize_cancel(),
            JobCommand::Retry => self.decide_retry(),
            JobCommand::Dismiss => self.decide_dismiss(),
            JobCommand::DeviceObserved(snapshot) => self.decide_device_observed(&snapshot),
            JobCommand::Worker(report) => self.decide_worker(&report),
        }
    }

    fn commit(&self, to: TransferJobState) -> Effect {
        Effect::Commit {
            expected_version: self.version,
            to,
        }
    }

    /// The chain of [`Effect::Commit`]s that moves this job to `to`, with
    /// strictly increasing expected versions. Empty when it is already
    /// there; `None` when the graph offers no route at all.
    fn commits_towards(&self, to: &TransferJobState) -> Option<Vec<Effect>> {
        let hops = route(&self.state, to)?;
        Some(
            hops.into_iter()
                .enumerate()
                .map(|(i, hop)| Effect::Commit {
                    expected_version: self.version + i as u64,
                    to: hop,
                })
                .collect(),
        )
    }

    // -----------------------------------------------------------------
    // Commit 46: every parked-state transition, in one exhaustive place
    // -----------------------------------------------------------------

    fn decide_device_observed(&self, snapshot: &DeviceSnapshot) -> Decision {
        use DeviceReadiness as R;
        use TransferJobState as S;

        if snapshot.version < self.observed_device_version {
            // A stale reading raced past a newer one. Ignoring it is the
            // whole reason the snapshot is versioned.
            return Decision::no_op();
        }
        if self.state.is_terminal() || self.state == S::Cancelling {
            return Decision::no_op();
        }
        if self.desired_run_state == DesiredRunState::Paused {
            // A user pause outranks any device reading: a paused job does
            // not get re-parked, re-prepared or interrupted by the device
            // coming and going.
            return Decision::no_op();
        }

        let record = Effect::RecordDeviceVersion(snapshot.version);
        let parked = matches!(
            self.state,
            S::Queued | S::WaitingForDevice | S::WaitingForPairing | S::PausedCaptureActive
        ) || self.state == S::RetryWait;

        // Exhaustive over (state class) x (readiness).
        let target = match (parked, &self.state, snapshot.readiness()) {
            (true, _, R::Ready) => Some(S::Preparing),
            (true, _, R::WaitDevice) => Some(S::WaitingForDevice),
            (true, _, R::WaitPairing) => Some(S::WaitingForPairing),
            (true, _, R::CapturePaused) => Some(S::PausedCaptureActive),
            (false, S::Preparing, R::Ready) => None,
            (false, S::Preparing, _) => Some(S::WaitingForDevice),
            (false, S::Transferring, R::Ready) => None,
            (false, S::Transferring, R::CapturePaused) => {
                // An *active* transfer reacts too: interrupt now, and let
                // the worker's own report pick the resting state once the
                // in-flight read has unwound.
                return Decision::accepted(vec![
                    record,
                    Effect::RequestInterrupt(InterruptReason::CapturePause),
                ]);
            }
            (false, S::Transferring, R::WaitDevice | R::WaitPairing) => {
                return Decision::accepted(vec![
                    record,
                    Effect::RequestInterrupt(InterruptReason::DeviceLost),
                ]);
            }
            // `verifying`/`committing` no longer touch the device, and the
            // remaining states were handled above.
            (false, _, _) => None,
        };

        let commits = target
            .as_ref()
            .and_then(|target| self.commits_towards(target))
            .unwrap_or_default();
        if commits.is_empty() {
            // Nothing to do — but the observation is still the newest one
            // this job has seen, so it must not be forgotten.
            if snapshot.version > self.observed_device_version {
                return Decision::accepted(vec![record]);
            }
            return Decision::no_op();
        }
        let mut effects = vec![record];
        effects.extend(commits);
        Decision::accepted(effects)
    }

    // -----------------------------------------------------------------
    // Commit 42: worker-reported stages
    // -----------------------------------------------------------------

    fn decide_worker(&self, report: &WorkerReport) -> Decision {
        if self.state.is_terminal() {
            return Decision::rejected(RejectReason::AlreadyTerminal);
        }
        if let WorkerReport::WorkerPanicked { detail } = report {
            return self.decide_worker_panic(detail);
        }
        if let WorkerReport::Interrupted(reason) = report {
            return self.decide_interrupted(*reason);
        }
        if self.state == TransferJobState::Cancelling {
            // A cancel landed while this stage was running. The cancel
            // wins; the worker's next loop iteration finalizes it.
            return Decision::no_op();
        }
        let Some(expected) = report.expected_state() else {
            return Decision::no_op();
        };
        if self.state != expected {
            return Decision::rejected(RejectReason::IllegalTransition {
                from: self.state.clone(),
                to: expected,
            });
        }
        let to = match report {
            WorkerReport::Prepared => TransferJobState::Transferring,
            WorkerReport::TransferComplete => TransferJobState::Verifying,
            WorkerReport::Verified => TransferJobState::Committing,
            WorkerReport::CommitComplete(_) => TransferJobState::Succeeded,
            WorkerReport::PreparationFailed { code, retryable }
            | WorkerReport::TransferFailed { code, retryable }
            | WorkerReport::CommitFailed { code, retryable } => TransferJobState::Failed {
                code: code.clone(),
                retryable: *retryable,
            },
            WorkerReport::WorkerPanicked { .. } => unreachable!("handled above"),
            WorkerReport::Interrupted(_) => unreachable!("handled above"),
        };
        Decision::accepted(vec![Effect::Commit {
            expected_version: self.version,
            to,
        }])
    }

    /// Convert a caught worker panic into a terminal failed row through the
    /// same versioned reducer effects as every other worker result. Parked
    /// states have no direct `-> failed` edge, so they first pass through
    /// `cancelling`; both commits are emitted in one serialized decision and
    /// no worker remains that could otherwise finalize the intermediate row.
    fn decide_worker_panic(&self, detail: &str) -> Decision {
        let failed = TransferJobState::Failed {
            code: FailureCode::Other(detail.to_string()),
            retryable: false,
        };
        if let Some(commits) = self.commits_towards(&failed) {
            if !commits.is_empty() {
                return Decision::accepted(commits);
            }
        }
        if is_legal_transition(&self.state, &TransferJobState::Cancelling)
            && is_legal_transition(&TransferJobState::Cancelling, &failed)
        {
            return Decision::accepted(vec![
                self.commit(TransferJobState::Cancelling),
                Effect::Commit {
                    expected_version: self.version + 1,
                    to: failed,
                },
            ]);
        }
        // Every non-terminal state should be covered by the graph above. If
        // a future state forgets to add a panic path, surface the refusal as
        // a fault instead of claiming a successful convergence.
        Decision::rejected(RejectReason::IllegalTransition {
            from: self.state.clone(),
            to: failed,
        })
    }

    fn decide_interrupted(&self, reason: InterruptReason) -> Decision {
        // An interruption is a worker report, not a general-purpose state
        // transition. Only an in-flight transfer (or the cancelling state
        // reached by the cancel command) may produce one; accepting a late
        // report from a parked/queued job would let an ABA worker finalize
        // somebody else's cancel (commit 44).
        if self.state == TransferJobState::Cancelling && reason != InterruptReason::Cancel {
            // A cancellation already owns the terminal decision. Late
            // pause/device/shutdown reports are harmless acknowledgements,
            // not errors that should overwrite the cancel outcome.
            return Decision::no_op();
        }
        let valid_state = match reason {
            InterruptReason::Cancel => matches!(
                self.state,
                TransferJobState::Transferring
                    | TransferJobState::Committing
                    | TransferJobState::Cancelling
            ),
            InterruptReason::Shutdown
            | InterruptReason::UserPause
            | InterruptReason::CapturePause
            | InterruptReason::DeviceLost => self.state == TransferJobState::Transferring,
        };
        if !valid_state {
            return Decision::rejected(RejectReason::IllegalTransition {
                from: self.state.clone(),
                to: self.state.clone(),
            });
        }
        match reason {
            // Only the job owner finalizes a cancel (commit 44) — and the
            // owner is exactly whoever is reporting this.
            InterruptReason::Cancel => self.decide_finalize_cancel(),
            // A shutdown leaves the state alone: startup reconciliation
            // owns failing an interrupted `transferring` row on the next
            // production startup without scheduling it.
            InterruptReason::Shutdown => Decision::no_op(),
            InterruptReason::DeviceLost => Decision::accepted(vec![
                Effect::ClearInterrupt,
                self.commit(TransferJobState::Failed {
                    code: FailureCode::Network,
                    retryable: true,
                }),
            ]),
            InterruptReason::UserPause | InterruptReason::CapturePause => {
                let target = match reason {
                    InterruptReason::CapturePause => TransferJobState::PausedCaptureActive,
                    // `retry_wait` is reserved for a user-paused attempt that
                    // may be resumed explicitly in this process. A device or
                    // network interruption is terminal instead.
                    _ => TransferJobState::RetryWait,
                };
                let Some(commits) = self.commits_towards(&target) else {
                    return Decision::no_op();
                };
                if commits.is_empty() {
                    return Decision::no_op();
                }
                let mut effects = vec![Effect::ClearInterrupt];
                effects.extend(commits);
                Decision::accepted(effects)
            }
        }
    }

    fn decide_transition(&self, to: TransferJobState) -> Decision {
        if self.state == to {
            return Decision::no_op();
        }
        if self.state.is_terminal() {
            return Decision::rejected(RejectReason::AlreadyTerminal);
        }
        if !is_legal_transition(&self.state, &to) {
            return Decision::rejected(RejectReason::IllegalTransition {
                from: self.state.clone(),
                to,
            });
        }
        Decision::accepted(vec![self.commit(to)])
    }

    fn decide_pause(&self) -> Decision {
        if self.state.is_terminal() {
            return Decision::rejected(RejectReason::AlreadyTerminal);
        }
        // No durable transition: plan 5.4 has no "paused by user" state,
        // so pausing is expressed purely as desired run state plus an
        // interrupt that unwinds any in-flight read.
        Decision::accepted(vec![
            Effect::SetDesiredRunState(DesiredRunState::Paused),
            Effect::RequestInterrupt(InterruptReason::UserPause),
            Effect::AwaitWorkerRelease,
            Effect::ClearInterrupt,
        ])
    }

    fn decide_resume(&self) -> Decision {
        if self.state.is_terminal() {
            // Commit 43: an explicit refusal, not a silent no-op. Now that
            // the desired run state is durable, "resume" on a finished job
            // would otherwise durably publish an intent nothing can ever
            // satisfy, and report success for it.
            return Decision::rejected(RejectReason::AlreadyTerminal);
        }
        if self.state == TransferJobState::Cancelling {
            // Resuming out of a cancel would race the cancel's own
            // finalization; the cancel wins.
            return Decision::rejected(RejectReason::IllegalTransition {
                from: TransferJobState::Cancelling,
                to: TransferJobState::Queued,
            });
        }
        let mut effects = vec![Effect::SetDesiredRunState(DesiredRunState::Run)];
        if self.state == TransferJobState::RetryWait {
            // `retry_wait` is this graph's "not running right now, eligible
            // to resume" resting state (see `coordinator.rs`).
            effects.push(self.commit(TransferJobState::Queued));
        }
        effects.push(Effect::Dispatch);
        Decision::accepted(effects)
    }

    fn decide_cancel(&self) -> Decision {
        if self.state.is_terminal() {
            return Decision::rejected(RejectReason::AlreadyTerminal);
        }
        if self.state == TransferJobState::Cancelling {
            // Already cancelling: re-assert the interrupt and wait, but do
            // not attempt a second `cancelling -> cancelling` transition.
            // This is the exact race the old two-step read-then-transition
            // cancel lost.
            return Decision::accepted(vec![
                Effect::RequestInterrupt(InterruptReason::Cancel),
                Effect::Dispatch,
                Effect::AwaitWorkerRelease,
            ]);
        }
        if !is_legal_transition(&self.state, &TransferJobState::Cancelling) {
            return Decision::rejected(RejectReason::IllegalTransition {
                from: self.state.clone(),
                to: TransferJobState::Cancelling,
            });
        }
        Decision::accepted(vec![
            Effect::RequestInterrupt(InterruptReason::Cancel),
            self.commit(TransferJobState::Cancelling),
            Effect::Dispatch,
            Effect::AwaitWorkerRelease,
        ])
    }

    fn decide_finalize_cancel(&self) -> Decision {
        if self.state == TransferJobState::Cancelled {
            return Decision::no_op();
        }
        if self.state.is_terminal() {
            return Decision::rejected(RejectReason::AlreadyTerminal);
        }
        if self.state == TransferJobState::Cancelling {
            return Decision::accepted(vec![
                self.commit(TransferJobState::Cancelled),
                Effect::ClearInterrupt,
            ]);
        }
        if !is_legal_transition(&self.state, &TransferJobState::Cancelling) {
            return Decision::rejected(RejectReason::IllegalTransition {
                from: self.state.clone(),
                to: TransferJobState::Cancelling,
            });
        }
        // Reaching `cancelled` always goes through `cancelling` first, so
        // this is a two-commit chain — with strictly increasing expected
        // versions, so a stale performer cannot apply only the tail.
        Decision::accepted(vec![
            self.commit(TransferJobState::Cancelling),
            Effect::Commit {
                expected_version: self.version + 1,
                to: TransferJobState::Cancelled,
            },
            Effect::ClearInterrupt,
        ])
    }

    fn decide_retry(&self) -> Decision {
        if !matches!(self.state, TransferJobState::Failed { .. }) {
            return Decision::rejected(RejectReason::NotFailed);
        }
        Decision::accepted(vec![Effect::SpawnRetryJob])
    }

    fn decide_dismiss(&self) -> Decision {
        if !self.state.is_terminal() {
            return Decision::rejected(RejectReason::NotTerminal);
        }
        Decision::accepted(vec![Effect::AwaitWorkerRelease, Effect::RemoveJob])
    }
}

// =====================================================================
// Commit 40: one atomic snapshot per version
// =====================================================================

/// A job's failure, split out of [`TransferJobState::Failed`] so a
/// snapshot's `error` field is readable without matching on the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFailure {
    pub code: FailureCode,
    pub retryable: bool,
}

/// Everything a caller needs to know about one job, all read at one
/// `version` under one critical section — identity, state, desired run
/// state, progress and error can never disagree with each other.
#[derive(Debug, Clone, PartialEq)]
pub struct JobSnapshot {
    pub job_id: JobId,
    /// Monotonically increasing per job; bumped by every committed
    /// durable transition. Pass it back to a `*_if_unchanged` command to
    /// get a stale result instead of clobbering a newer state.
    pub version: u64,
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub state: TransferJobState,
    pub desired_run_state: DesiredRunState,
    pub progress: JobProgress,
    pub error: Option<JobFailure>,
    /// True while a worker owns this job right now.
    pub active: bool,
}

impl JobSnapshot {
    /// The error carried by a `failed` state, if any — derived, never
    /// stored twice.
    #[must_use]
    pub fn failure_of(state: &TransferJobState) -> Option<JobFailure> {
        match state {
            TransferJobState::Failed { code, retryable } => Some(JobFailure {
                code: code.clone(),
                retryable: *retryable,
            }),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

// =====================================================================
// Target leases: at most one writer per target
// =====================================================================

/// What a job writes to: one (device, session) directory in the library.
/// Two jobs with different idempotency keys can still name the same
/// target, so the target — not the job id — is what has to be exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetKey {
    pub device_id: DeviceId,
    pub session_id: SessionId,
}

impl TargetKey {
    #[must_use]
    pub fn new(device_id: &DeviceId, session_id: &SessionId) -> Self {
        TargetKey {
            device_id: device_id.clone(),
            session_id: session_id.clone(),
        }
    }
}

/// A registry of "who is currently allowed to write to this target".
/// Acquisition is all-or-nothing and the lease is released by RAII, so a
/// worker that panics or returns early cannot strand it.
#[derive(Debug, Default)]
pub struct TargetLeases {
    held: Mutex<HashMap<TargetKey, JobId>>,
}

impl TargetLeases {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the lease for `target` on behalf of `job_id`, or `None` if
    /// another job holds it. Re-acquiring a lease this same job already
    /// holds also returns `None` — a job never needs two.
    pub fn try_acquire(&self, target: TargetKey, job_id: &JobId) -> Option<TargetLease<'_>> {
        let mut held = self.held.lock().unwrap();
        if held.contains_key(&target) {
            return None;
        }
        held.insert(target.clone(), job_id.clone());
        Some(TargetLease {
            leases: self,
            target: Some(target),
        })
    }

    /// Which job currently holds `target`, if any.
    #[must_use]
    pub fn holder(&self, target: &TargetKey) -> Option<JobId> {
        self.held.lock().unwrap().get(target).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.held.lock().unwrap().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn release(&self, target: &TargetKey) {
        self.held.lock().unwrap().remove(target);
    }
}

/// RAII proof that its holder is the only writer for one target.
#[derive(Debug)]
pub struct TargetLease<'a> {
    leases: &'a TargetLeases,
    target: Option<TargetKey>,
}

impl TargetLease<'_> {
    #[must_use]
    pub fn target(&self) -> &TargetKey {
        self.target.as_ref().expect("lease still held")
    }
}

impl Drop for TargetLease<'_> {
    fn drop(&mut self) {
        if let Some(target) = self.target.take() {
            self.leases.release(&target);
        }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{is_valid_transition, JobStateTag};

    fn tag_of(state: &TransferJobState) -> JobStateTag {
        JobStateTag::from_db_str(state_name(state)).expect("every domain state has a tag")
    }

    // -----------------------------------------------------------------
    // Commit 37: exactly one state graph
    // -----------------------------------------------------------------

    #[test]
    fn persistence_encodes_the_same_graph_edge_for_edge_no_second_state_model() {
        // The exhaustive 13x13 table. `persistence` may encode a tag and a
        // version; it may not disagree about a single edge. If this fails,
        // two state models have started to drift and one of them is wrong.
        let mut mismatches = Vec::new();
        for from in all_states() {
            for to in all_states() {
                let domain = is_legal_transition(&from, &to);
                let persisted = is_valid_transition(tag_of(&from), tag_of(&to));
                if domain != persisted {
                    mismatches.push(format!(
                        "{} -> {}: domain={domain} persistence={persisted}",
                        state_name(&from),
                        state_name(&to)
                    ));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "persistence defines a second state graph: {mismatches:?}"
        );
    }

    #[test]
    fn the_transition_table_is_exhaustive_over_every_state_pair() {
        // Every one of the 169 ordered pairs is classified, and the set of
        // legal ones is exactly this list — a new edge cannot be added
        // anywhere without updating this table.
        let legal: Vec<String> = all_states()
            .iter()
            .flat_map(|from| {
                all_states()
                    .into_iter()
                    .filter(move |to| is_legal_transition(from, to))
                    .map(move |to| format!("{}->{}", state_name(from), state_name(&to)))
            })
            .collect();
        let expected = vec![
            "queued->waiting_for_device",
            "queued->waiting_for_pairing",
            "queued->preparing",
            "queued->cancelling",
            "waiting_for_device->queued",
            "waiting_for_device->paused_capture_active",
            "waiting_for_device->preparing",
            "waiting_for_device->cancelling",
            "waiting_for_pairing->queued",
            "waiting_for_pairing->preparing",
            "waiting_for_pairing->cancelling",
            "paused_capture_active->queued",
            "paused_capture_active->preparing",
            "paused_capture_active->cancelling",
            "preparing->waiting_for_device",
            "preparing->transferring",
            "preparing->cancelling",
            "preparing->failed",
            "transferring->paused_capture_active",
            "transferring->verifying",
            "transferring->retry_wait",
            "transferring->cancelling",
            "transferring->failed",
            "verifying->committing",
            "verifying->retry_wait",
            "verifying->cancelling",
            "verifying->failed",
            "committing->retry_wait",
            "committing->succeeded",
            "committing->cancelling",
            "committing->failed",
            "retry_wait->queued",
            "retry_wait->preparing",
            "retry_wait->cancelling",
            "retry_wait->failed",
            "cancelling->cancelled",
            "cancelling->failed",
        ];

        let mut legal_sorted = legal;
        legal_sorted.sort();
        let mut expected_sorted: Vec<String> = expected
            .into_iter()
            .map(std::string::ToString::to_string)
            .collect();
        expected_sorted.sort();
        assert_eq!(legal_sorted, expected_sorted);
        assert_eq!(expected_sorted.len(), 37);
    }

    #[test]
    fn no_terminal_state_has_an_outgoing_edge() {
        for from in all_states()
            .into_iter()
            .filter(TransferJobState::is_terminal)
        {
            for to in all_states() {
                assert!(
                    !is_legal_transition(&from, &to),
                    "{} must never leave a terminal state (to {})",
                    state_name(&from),
                    state_name(&to)
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Commit 38: exhaustive state x command table
    // -----------------------------------------------------------------

    fn commands() -> Vec<JobCommand> {
        vec![
            JobCommand::Transition(TransferJobState::Preparing),
            JobCommand::Pause,
            JobCommand::Resume,
            JobCommand::Cancel,
            JobCommand::FinalizeCancel,
            JobCommand::Retry,
            JobCommand::Dismiss,
        ]
    }

    fn outcome_name(outcome: &CommandOutcome) -> &'static str {
        match outcome {
            CommandOutcome::Accepted => "accepted",
            CommandOutcome::NoOp => "no_op",
            CommandOutcome::Rejected(RejectReason::AlreadyTerminal) => "rejected:already_terminal",
            CommandOutcome::Rejected(RejectReason::NotTerminal) => "rejected:not_terminal",
            CommandOutcome::Rejected(RejectReason::NotFailed) => "rejected:not_failed",
            CommandOutcome::Rejected(RejectReason::IllegalTransition { .. }) => "rejected:illegal",
        }
    }

    #[test]
    fn every_state_times_every_command_has_a_pinned_outcome() {
        let mut rows = Vec::new();
        for state in all_states() {
            for command in commands() {
                let aggregate = JobAggregate::new(state.clone());
                let decision = aggregate.decide(command.clone());
                rows.push(format!(
                    "{}+{} => {} -> {}",
                    state_name(&state),
                    command.name(),
                    outcome_name(&decision.outcome),
                    state_name(&decision.final_state(&state))
                ));
            }
        }

        let expected = vec![
            // queued
            "queued+transition => accepted -> preparing",
            "queued+pause => accepted -> queued",
            "queued+resume => accepted -> queued",
            "queued+cancel => accepted -> cancelling",
            "queued+finalize_cancel => accepted -> cancelled",
            "queued+retry => rejected:not_failed -> queued",
            "queued+dismiss => rejected:not_terminal -> queued",
            // waiting_for_device
            "waiting_for_device+transition => accepted -> preparing",
            "waiting_for_device+pause => accepted -> waiting_for_device",
            "waiting_for_device+resume => accepted -> waiting_for_device",
            "waiting_for_device+cancel => accepted -> cancelling",
            "waiting_for_device+finalize_cancel => accepted -> cancelled",
            "waiting_for_device+retry => rejected:not_failed -> waiting_for_device",
            "waiting_for_device+dismiss => rejected:not_terminal -> waiting_for_device",
            // waiting_for_pairing
            "waiting_for_pairing+transition => accepted -> preparing",
            "waiting_for_pairing+pause => accepted -> waiting_for_pairing",
            "waiting_for_pairing+resume => accepted -> waiting_for_pairing",
            "waiting_for_pairing+cancel => accepted -> cancelling",
            "waiting_for_pairing+finalize_cancel => accepted -> cancelled",
            "waiting_for_pairing+retry => rejected:not_failed -> waiting_for_pairing",
            "waiting_for_pairing+dismiss => rejected:not_terminal -> waiting_for_pairing",
            // paused_capture_active
            "paused_capture_active+transition => accepted -> preparing",
            "paused_capture_active+pause => accepted -> paused_capture_active",
            "paused_capture_active+resume => accepted -> paused_capture_active",
            "paused_capture_active+cancel => accepted -> cancelling",
            "paused_capture_active+finalize_cancel => accepted -> cancelled",
            "paused_capture_active+retry => rejected:not_failed -> paused_capture_active",
            "paused_capture_active+dismiss => rejected:not_terminal -> paused_capture_active",
            // preparing
            "preparing+transition => no_op -> preparing",
            "preparing+pause => accepted -> preparing",
            "preparing+resume => accepted -> preparing",
            "preparing+cancel => accepted -> cancelling",
            "preparing+finalize_cancel => accepted -> cancelled",
            "preparing+retry => rejected:not_failed -> preparing",
            "preparing+dismiss => rejected:not_terminal -> preparing",
            // transferring
            "transferring+transition => rejected:illegal -> transferring",
            "transferring+pause => accepted -> transferring",
            "transferring+resume => accepted -> transferring",
            "transferring+cancel => accepted -> cancelling",
            "transferring+finalize_cancel => accepted -> cancelled",
            "transferring+retry => rejected:not_failed -> transferring",
            "transferring+dismiss => rejected:not_terminal -> transferring",
            // verifying
            "verifying+transition => rejected:illegal -> verifying",
            "verifying+pause => accepted -> verifying",
            "verifying+resume => accepted -> verifying",
            "verifying+cancel => accepted -> cancelling",
            "verifying+finalize_cancel => accepted -> cancelled",
            "verifying+retry => rejected:not_failed -> verifying",
            "verifying+dismiss => rejected:not_terminal -> verifying",
            // committing remains cancellable until the committer claims its
            // atomic canonical publication point.
            "committing+transition => rejected:illegal -> committing",
            "committing+pause => accepted -> committing",
            "committing+resume => accepted -> committing",
            "committing+cancel => accepted -> cancelling",
            "committing+finalize_cancel => accepted -> cancelled",
            "committing+retry => rejected:not_failed -> committing",
            "committing+dismiss => rejected:not_terminal -> committing",
            // retry_wait
            "retry_wait+transition => accepted -> preparing",
            "retry_wait+pause => accepted -> retry_wait",
            "retry_wait+resume => accepted -> queued",
            "retry_wait+cancel => accepted -> cancelling",
            "retry_wait+finalize_cancel => accepted -> cancelled",
            "retry_wait+retry => rejected:not_failed -> retry_wait",
            "retry_wait+dismiss => rejected:not_terminal -> retry_wait",
            // cancelling
            "cancelling+transition => rejected:illegal -> cancelling",
            "cancelling+pause => accepted -> cancelling",
            "cancelling+resume => rejected:illegal -> cancelling",
            "cancelling+cancel => accepted -> cancelling",
            "cancelling+finalize_cancel => accepted -> cancelled",
            "cancelling+retry => rejected:not_failed -> cancelling",
            "cancelling+dismiss => rejected:not_terminal -> cancelling",
            // succeeded
            "succeeded+transition => rejected:already_terminal -> succeeded",
            "succeeded+pause => rejected:already_terminal -> succeeded",
            "succeeded+resume => rejected:already_terminal -> succeeded",
            "succeeded+cancel => rejected:already_terminal -> succeeded",
            "succeeded+finalize_cancel => rejected:already_terminal -> succeeded",
            "succeeded+retry => rejected:not_failed -> succeeded",
            "succeeded+dismiss => accepted -> succeeded",
            // failed
            "failed+transition => rejected:already_terminal -> failed",
            "failed+pause => rejected:already_terminal -> failed",
            "failed+resume => rejected:already_terminal -> failed",
            "failed+cancel => rejected:already_terminal -> failed",
            "failed+finalize_cancel => rejected:already_terminal -> failed",
            "failed+retry => accepted -> failed",
            "failed+dismiss => accepted -> failed",
            // cancelled
            "cancelled+transition => rejected:already_terminal -> cancelled",
            "cancelled+pause => rejected:already_terminal -> cancelled",
            "cancelled+resume => rejected:already_terminal -> cancelled",
            "cancelled+cancel => rejected:already_terminal -> cancelled",
            "cancelled+finalize_cancel => no_op -> cancelled",
            "cancelled+retry => rejected:not_failed -> cancelled",
            "cancelled+dismiss => accepted -> cancelled",
        ];
        assert_eq!(rows, expected);
    }

    // -----------------------------------------------------------------
    // Property-style invariants
    // -----------------------------------------------------------------

    #[test]
    fn a_terminal_state_is_never_left_by_any_command() {
        for state in all_states()
            .into_iter()
            .filter(TransferJobState::is_terminal)
        {
            for command in commands() {
                let decision = JobAggregate::new(state.clone()).decide(command.clone());
                assert!(
                    !decision
                        .effects
                        .iter()
                        .any(|e| matches!(e, Effect::Commit { .. })),
                    "{} + {} proposed a durable transition out of a terminal state",
                    state_name(&state),
                    command.name()
                );
                assert_eq!(decision.final_state(&state), state);
            }
        }
    }

    #[test]
    fn an_illegal_command_produces_no_effects_at_all() {
        for state in all_states() {
            for command in commands() {
                let decision = JobAggregate::new(state.clone()).decide(command.clone());
                if decision.outcome.is_rejected() {
                    assert!(
                        decision.effects.is_empty(),
                        "{} + {} was rejected but still asked for {:?}",
                        state_name(&state),
                        command.name(),
                        decision.effects
                    );
                }
            }
        }
    }

    #[test]
    fn expected_versions_within_one_decision_increase_monotonically_from_the_current_version() {
        for version in [1_u64, 7, 4_000_000_000] {
            for state in all_states() {
                for command in commands() {
                    let decision = JobAggregate::new(state.clone())
                        .with_version(version)
                        .decide(command.clone());
                    let mut next = version;
                    for effect in &decision.effects {
                        if let Effect::Commit {
                            expected_version, ..
                        } = effect
                        {
                            assert_eq!(
                                *expected_version,
                                next,
                                "{} + {} proposed a commit at version {expected_version}, expected {next}",
                                state_name(&state),
                                command.name()
                            );
                            next += 1;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_no_op_command_produces_no_effects() {
        for state in all_states() {
            for command in commands() {
                let decision = JobAggregate::new(state.clone()).decide(command.clone());
                if decision.outcome == CommandOutcome::NoOp {
                    assert!(decision.effects.is_empty());
                }
            }
        }
    }

    #[test]
    fn transitioning_to_the_state_a_job_is_already_in_is_a_no_op_not_a_second_commit() {
        // The exact shape of the cancel race: two commands both observe
        // "not cancelling yet" and both try to transition.
        for state in all_states() {
            let decision =
                JobAggregate::new(state.clone()).decide(JobCommand::Transition(state.clone()));
            assert_eq!(decision.outcome, CommandOutcome::NoOp, "{state:?}");
            assert!(decision.effects.is_empty());
        }
    }

    #[test]
    fn finalize_cancel_from_cancelling_commits_exactly_one_transition() {
        let decision =
            JobAggregate::new(TransferJobState::Cancelling).decide(JobCommand::FinalizeCancel);
        let commits: Vec<_> = decision
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::Commit { .. }))
            .collect();
        assert_eq!(commits.len(), 1);
        assert_eq!(
            commits[0],
            &Effect::Commit {
                expected_version: 1,
                to: TransferJobState::Cancelled,
            }
        );
    }

    #[test]
    fn pause_waits_for_the_worker_before_clearing_its_own_interrupt() {
        let decision = JobAggregate::new(TransferJobState::Transferring).decide(JobCommand::Pause);
        assert_eq!(
            decision.effects,
            vec![
                Effect::SetDesiredRunState(DesiredRunState::Paused),
                Effect::RequestInterrupt(InterruptReason::UserPause),
                Effect::AwaitWorkerRelease,
                Effect::ClearInterrupt,
            ]
        );
    }

    // -----------------------------------------------------------------
    // Commit 46: the exhaustive parked-state table
    // -----------------------------------------------------------------

    fn snapshot(version: u64, readiness: DeviceReadiness) -> DeviceSnapshot {
        let (connection, capture) = match readiness {
            DeviceReadiness::Ready => (
                ConnectionState::Connected {
                    connection_id: "c".to_string(),
                    epoch: 1,
                },
                CaptureActivityState::Idle,
            ),
            DeviceReadiness::CapturePaused => (
                ConnectionState::Connected {
                    connection_id: "c".to_string(),
                    epoch: 1,
                },
                CaptureActivityState::Recording,
            ),
            DeviceReadiness::WaitDevice => {
                (ConnectionState::Disconnected, CaptureActivityState::Unknown)
            }
            DeviceReadiness::WaitPairing => (
                ConnectionState::Pairing {
                    attempt_id: "a".to_string(),
                    phase: crate::device::PairingPhase::Pending,
                },
                CaptureActivityState::Unknown,
            ),
        };
        DeviceSnapshot::new(version, connection, capture)
    }

    fn readinesses() -> Vec<(&'static str, DeviceReadiness)> {
        vec![
            ("ready", DeviceReadiness::Ready),
            ("wait_device", DeviceReadiness::WaitDevice),
            ("wait_pairing", DeviceReadiness::WaitPairing),
            ("capture", DeviceReadiness::CapturePaused),
        ]
    }

    #[test]
    fn every_state_times_every_device_reading_has_a_pinned_parked_transition() {
        let mut rows = Vec::new();
        for state in all_states() {
            for (name, readiness) in readinesses() {
                let decision = JobAggregate::new(state.clone())
                    .decide(JobCommand::DeviceObserved(snapshot(1, readiness)));
                rows.push(format!(
                    "{}+{name} => {} -> {}",
                    state_name(&state),
                    outcome_name(&decision.outcome),
                    state_name(&decision.final_state(&state))
                ));
            }
        }

        let expected = vec![
            "queued+ready => accepted -> preparing",
            "queued+wait_device => accepted -> waiting_for_device",
            "queued+wait_pairing => accepted -> waiting_for_pairing",
            // No `queued -> paused_capture_active` edge exists; the job
            // simply stays queued and is not offered to a worker.
            "queued+capture => accepted -> queued",
            "waiting_for_device+ready => accepted -> preparing",
            "waiting_for_device+wait_device => accepted -> waiting_for_device",
            // Routed through `queued`, because no direct edge exists.
            "waiting_for_device+wait_pairing => accepted -> waiting_for_pairing",
            "waiting_for_device+capture => accepted -> paused_capture_active",
            "waiting_for_pairing+ready => accepted -> preparing",
            "waiting_for_pairing+wait_device => accepted -> waiting_for_device",
            "waiting_for_pairing+wait_pairing => accepted -> waiting_for_pairing",
            "waiting_for_pairing+capture => accepted -> waiting_for_pairing",
            "paused_capture_active+ready => accepted -> preparing",
            "paused_capture_active+wait_device => accepted -> waiting_for_device",
            "paused_capture_active+wait_pairing => accepted -> waiting_for_pairing",
            "paused_capture_active+capture => accepted -> paused_capture_active",
            "preparing+ready => accepted -> preparing",
            "preparing+wait_device => accepted -> waiting_for_device",
            "preparing+wait_pairing => accepted -> waiting_for_device",
            "preparing+capture => accepted -> waiting_for_device",
            // An active transfer is interrupted, never transitioned from
            // under the worker: the worker's own report lands the state.
            "transferring+ready => accepted -> transferring",
            "transferring+wait_device => accepted -> transferring",
            "transferring+wait_pairing => accepted -> transferring",
            "transferring+capture => accepted -> transferring",
            "verifying+ready => accepted -> verifying",
            "verifying+wait_device => accepted -> verifying",
            "verifying+wait_pairing => accepted -> verifying",
            "verifying+capture => accepted -> verifying",
            "committing+ready => accepted -> committing",
            "committing+wait_device => accepted -> committing",
            "committing+wait_pairing => accepted -> committing",
            "committing+capture => accepted -> committing",
            "retry_wait+ready => accepted -> preparing",
            "retry_wait+wait_device => accepted -> waiting_for_device",
            "retry_wait+wait_pairing => accepted -> waiting_for_pairing",
            "retry_wait+capture => accepted -> retry_wait",
            // A cancelling or finished job ignores its device entirely.
            "cancelling+ready => no_op -> cancelling",
            "cancelling+wait_device => no_op -> cancelling",
            "cancelling+wait_pairing => no_op -> cancelling",
            "cancelling+capture => no_op -> cancelling",
            "succeeded+ready => no_op -> succeeded",
            "succeeded+wait_device => no_op -> succeeded",
            "succeeded+wait_pairing => no_op -> succeeded",
            "succeeded+capture => no_op -> succeeded",
            "failed+ready => no_op -> failed",
            "failed+wait_device => no_op -> failed",
            "failed+wait_pairing => no_op -> failed",
            "failed+capture => no_op -> failed",
            "cancelled+ready => no_op -> cancelled",
            "cancelled+wait_device => no_op -> cancelled",
            "cancelled+wait_pairing => no_op -> cancelled",
            "cancelled+capture => no_op -> cancelled",
        ];
        assert_eq!(rows, expected);
    }

    #[test]
    fn a_paused_job_ignores_every_device_reading() {
        for (name, readiness) in readinesses() {
            let decision = JobAggregate::new(TransferJobState::WaitingForDevice)
                .with_desired_run_state(DesiredRunState::Paused)
                .decide(JobCommand::DeviceObserved(snapshot(9, readiness)));
            assert_eq!(decision.outcome, CommandOutcome::NoOp, "{name}");
            assert!(decision.effects.is_empty(), "{name}");
        }
    }

    #[test]
    fn a_device_reading_older_than_the_one_already_applied_is_ignored() {
        let aggregate =
            JobAggregate::new(TransferJobState::WaitingForDevice).with_observed_device_version(7);

        let stale = aggregate.decide(JobCommand::DeviceObserved(snapshot(
            6,
            DeviceReadiness::Ready,
        )));
        assert_eq!(stale.outcome, CommandOutcome::NoOp);
        assert!(stale.effects.is_empty());

        let fresh = aggregate.decide(JobCommand::DeviceObserved(snapshot(
            7,
            DeviceReadiness::Ready,
        )));
        assert_eq!(fresh.outcome, CommandOutcome::Accepted);
        assert_eq!(fresh.effects[0], Effect::RecordDeviceVersion(7));
        assert_eq!(
            fresh.final_state(&TransferJobState::WaitingForDevice),
            TransferJobState::Preparing
        );
    }

    #[test]
    fn an_active_transfer_reacts_to_its_device_dropping_offline() {
        for (readiness, reason) in [
            (DeviceReadiness::WaitDevice, InterruptReason::DeviceLost),
            (DeviceReadiness::WaitPairing, InterruptReason::DeviceLost),
            (
                DeviceReadiness::CapturePaused,
                InterruptReason::CapturePause,
            ),
        ] {
            let decision = JobAggregate::new(TransferJobState::Transferring)
                .decide(JobCommand::DeviceObserved(snapshot(3, readiness)));
            assert_eq!(
                decision.effects,
                vec![
                    Effect::RecordDeviceVersion(3),
                    Effect::RequestInterrupt(reason)
                ],
                "{readiness:?}"
            );
        }
    }

    #[test]
    fn device_loss_interruption_fails_the_attempt_instead_of_parking_for_auto_resume() {
        let decision = JobAggregate::new(TransferJobState::Transferring).decide(
            JobCommand::Worker(WorkerReport::Interrupted(InterruptReason::DeviceLost)),
        );

        assert_eq!(decision.outcome, CommandOutcome::Accepted);
        assert_eq!(
            decision.effects,
            vec![
                Effect::ClearInterrupt,
                Effect::Commit {
                    expected_version: 1,
                    to: TransferJobState::Failed {
                        code: FailureCode::Network,
                        retryable: true,
                    },
                },
            ]
        );
    }

    // -----------------------------------------------------------------
    // Commit 42: worker-reported stages
    // -----------------------------------------------------------------

    fn reports() -> Vec<WorkerReport> {
        vec![
            WorkerReport::Prepared,
            WorkerReport::PreparationFailed {
                code: FailureCode::Network,
                retryable: true,
            },
            WorkerReport::TransferComplete,
            WorkerReport::TransferFailed {
                code: FailureCode::HashMismatch,
                retryable: true,
            },
            WorkerReport::WorkerPanicked {
                detail: "worker exploded".to_string(),
            },
            WorkerReport::Interrupted(InterruptReason::UserPause),
            WorkerReport::Interrupted(InterruptReason::CapturePause),
            WorkerReport::Interrupted(InterruptReason::DeviceLost),
            WorkerReport::Interrupted(InterruptReason::Cancel),
            WorkerReport::Interrupted(InterruptReason::Shutdown),
            WorkerReport::Verified,
            WorkerReport::CommitComplete(DownloadCommitOutcome::clean()),
            WorkerReport::CommitFailed {
                code: FailureCode::DiskFull,
                retryable: false,
            },
        ]
    }

    #[test]
    fn the_worker_reports_a_stage_and_the_reducer_picks_the_state() {
        let cases = [
            (
                TransferJobState::Preparing,
                WorkerReport::Prepared,
                TransferJobState::Transferring,
            ),
            (
                TransferJobState::Transferring,
                WorkerReport::TransferComplete,
                TransferJobState::Verifying,
            ),
            (
                TransferJobState::Verifying,
                WorkerReport::Verified,
                TransferJobState::Committing,
            ),
            (
                TransferJobState::Committing,
                WorkerReport::CommitComplete(DownloadCommitOutcome::clean()),
                TransferJobState::Succeeded,
            ),
            (
                TransferJobState::Transferring,
                WorkerReport::Interrupted(InterruptReason::UserPause),
                TransferJobState::RetryWait,
            ),
            (
                TransferJobState::Transferring,
                WorkerReport::Interrupted(InterruptReason::CapturePause),
                TransferJobState::PausedCaptureActive,
            ),
            (
                TransferJobState::Transferring,
                WorkerReport::Interrupted(InterruptReason::DeviceLost),
                TransferJobState::Failed {
                    code: FailureCode::Network,
                    retryable: true,
                },
            ),
            (
                TransferJobState::Transferring,
                WorkerReport::Interrupted(InterruptReason::Cancel),
                TransferJobState::Cancelled,
            ),
        ];
        for (state, report, expected) in cases {
            let decision =
                JobAggregate::new(state.clone()).decide(JobCommand::Worker(report.clone()));
            assert_eq!(
                decision.outcome,
                CommandOutcome::Accepted,
                "{state:?} {report:?}"
            );
            assert_eq!(
                decision.final_state(&state),
                expected,
                "{} + {}",
                state_name(&state),
                report.name()
            );
        }
    }

    #[test]
    fn a_caught_worker_panic_converges_every_non_terminal_state_to_failed() {
        for state in all_states()
            .into_iter()
            .filter(|state| !state.is_terminal())
        {
            let decision = JobAggregate::new(state.clone()).decide(JobCommand::Worker(
                WorkerReport::WorkerPanicked {
                    detail: "panic in test worker".to_string(),
                },
            ));
            assert_eq!(decision.outcome, CommandOutcome::Accepted, "{state:?}");
            assert!(matches!(
                decision.final_state(&state),
                TransferJobState::Failed {
                    code: FailureCode::Other(_),
                    retryable: false,
                }
            ));

            let mut current = state;
            let mut expected_version = 1;
            for effect in decision.effects {
                let Effect::Commit {
                    expected_version: actual_version,
                    to,
                    ..
                } = effect
                else {
                    continue;
                };
                assert_eq!(actual_version, expected_version);
                assert!(is_legal_transition(&current, &to));
                current = to;
                expected_version += 1;
            }
            assert!(current.is_terminal());
        }
    }

    #[test]
    fn a_report_from_the_wrong_stage_never_commits_anything() {
        for state in all_states() {
            for report in reports() {
                let decision =
                    JobAggregate::new(state.clone()).decide(JobCommand::Worker(report.clone()));
                let matches_stage = report.expected_state().as_ref() == Some(&state);
                let cancel_owner_report =
                    matches!(report, WorkerReport::Interrupted(InterruptReason::Cancel))
                        && matches!(
                            &state,
                            TransferJobState::Transferring
                                | TransferJobState::Committing
                                | TransferJobState::Cancelling
                        );
                let panic_report = matches!(report, WorkerReport::WorkerPanicked { .. });
                if !matches_stage
                    && !cancel_owner_report
                    && !panic_report
                    && !decision.effects.is_empty()
                {
                    panic!(
                        "{} + {} proposed {:?} from the wrong stage",
                        state_name(&state),
                        report.name(),
                        decision.effects
                    );
                }
            }
        }
    }

    #[test]
    fn a_cancel_that_landed_first_makes_every_worker_report_a_no_op() {
        for report in reports() {
            let decision = JobAggregate::new(TransferJobState::Cancelling)
                .decide(JobCommand::Worker(report.clone()));
            match report {
                // The one exception: the interrupted worker *is* the owner
                // that finalizes the cancel (commit 44).
                WorkerReport::Interrupted(InterruptReason::Cancel) => {
                    assert_eq!(
                        decision.final_state(&TransferJobState::Cancelling),
                        TransferJobState::Cancelled
                    );
                }
                WorkerReport::WorkerPanicked { .. } => {
                    assert!(matches!(
                        decision.final_state(&TransferJobState::Cancelling),
                        TransferJobState::Failed {
                            code: FailureCode::Other(_),
                            retryable: false,
                        }
                    ));
                }
                _ => assert_eq!(decision.outcome, CommandOutcome::NoOp, "{}", report.name()),
            }
        }
    }

    #[test]
    fn a_shutdown_interrupt_leaves_the_state_for_startup_reconciliation() {
        let decision = JobAggregate::new(TransferJobState::Transferring).decide(
            JobCommand::Worker(WorkerReport::Interrupted(InterruptReason::Shutdown)),
        );
        assert_eq!(decision.outcome, CommandOutcome::NoOp);
        assert!(decision.effects.is_empty());
    }

    // -----------------------------------------------------------------
    // The invariant that has to hold for *every* command, old and new
    // -----------------------------------------------------------------

    fn extended_commands() -> Vec<JobCommand> {
        let mut all = commands();
        all.extend(
            readinesses()
                .into_iter()
                .map(|(_, r)| JobCommand::DeviceObserved(snapshot(5, r))),
        );
        all.extend(reports().into_iter().map(JobCommand::Worker));
        all
    }

    #[test]
    fn every_commit_chain_any_command_proposes_walks_only_legal_edges() {
        for state in all_states() {
            for command in extended_commands() {
                let decision = JobAggregate::new(state.clone())
                    .with_version(3)
                    .decide(command.clone());
                let mut current = state.clone();
                let mut expected_version = 3;
                for effect in &decision.effects {
                    let Effect::Commit {
                        expected_version: v,
                        to,
                        ..
                    } = effect
                    else {
                        continue;
                    };
                    assert_eq!(
                        *v,
                        expected_version,
                        "{} + {}",
                        state_name(&state),
                        command.name()
                    );
                    assert!(
                        is_legal_transition(&current, to),
                        "{} + {} proposed the illegal edge {} -> {}",
                        state_name(&state),
                        command.name(),
                        state_name(&current),
                        state_name(to)
                    );
                    current = to.clone();
                    expected_version += 1;
                }
                match &decision.outcome {
                    CommandOutcome::Accepted => assert!(!decision.effects.is_empty()),
                    CommandOutcome::NoOp | CommandOutcome::Rejected(_) => {
                        assert!(decision.effects.is_empty());
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Target leases
    // -----------------------------------------------------------------

    fn target(session: &str) -> TargetKey {
        TargetKey {
            device_id: DeviceId("dev-1".to_string()),
            session_id: SessionId(session.to_string()),
        }
    }

    #[test]
    fn one_target_has_at_most_one_lease() {
        let leases = TargetLeases::new();
        let first = JobId("job-a".to_string());
        let second = JobId("job-b".to_string());

        let held = leases
            .try_acquire(target("s1"), &first)
            .expect("first writer takes the target");
        assert_eq!(leases.holder(&target("s1")), Some(first.clone()));
        assert!(
            leases.try_acquire(target("s1"), &second).is_none(),
            "a second writer must not get the same target"
        );
        // A different target is unaffected.
        let other = leases
            .try_acquire(target("s2"), &second)
            .expect("a different target is independent");

        drop(held);
        assert_eq!(leases.holder(&target("s1")), None);
        let taken_over = leases
            .try_acquire(target("s1"), &second)
            .expect("released targets can be re-leased");
        assert_eq!(leases.holder(&target("s1")), Some(second));
        drop(taken_over);
        drop(other);
        assert!(leases.is_empty());
    }
}
