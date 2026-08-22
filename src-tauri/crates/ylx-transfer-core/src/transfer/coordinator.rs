//! PC-05: `TransferCoordinator` — the durable, bounded-concurrency job
//! scheduler that ties PC-00 (tagged job state), the journal spike
//! (durable transitions/reconcile), the download spike
//! (`DownloadSource`/`download_file`/`commit_session`), and PC-02
//! (`DeviceActor`'s connection/capture-activity state) together into one
//! working scheduler. See plan section 16 "PC-05 Durable
//! TransferCoordinator".
//!
//! # Collaborator seams (why no direct `DeviceActor`/`PiHttpClient` type
//! appears anywhere in this file)
//!
//! `ylx-transfer-core` has zero dependency on any network crate (see the
//! crate root doc comment); `ylx-transfer-adapters` (which owns
//! `PiHttpClient`) depends on `ylx-transfer-core`, never the reverse. A
//! `TransferCoordinator::enqueue`/worker that called `PiHttpClient`
//! directly, or held a `device::DeviceActor` and reached into its private
//! session token, would either reverse that dependency edge (impossible —
//! Cargo has no cycles) or force this crate to start depending on
//! `reqwest`/`tauri`, which the crate root doc comment says this crate
//! must never do. So, like the authenticated split device capabilities for
//! PC-02, this coordinator is generic over two small trait seams it
//! defines itself:
//!
//! - [`DeviceStatusPort`] — "what is this device's `ConnectionState`/
//!   `CaptureActivityState` right now" — the read-only subset of
//!   `DeviceActor` the coordinator needs for offline/pairing-wait and
//!   capture-priority pause. A real composition root (PC-08) implements
//!   this over a `DeviceFleet`; tests here inject a fake.
//! - [`DownloadSourceFactory`] — "give me a `library::download::
//!   DownloadSource` for this (device, session, file)". A real
//!   composition root implements this with
//!   `ylx_transfer_adapters::pi_download_source::PiDownloadSource`
//!   (wrapping `PiHttpClient::get_file`/`head_file`, built new in this
//!   task per the task card — see that module's doc comment); tests here
//!   inject a fake that never touches the network.
//!
//! This is a deliberate, documented deviation from the task card's literal
//! phrasing ("`PiDownloadSource` adapter... in `queue.rs` or its own small
//! file" under `ylx-transfer-core`): the adapter that actually names
//! `PiHttpClient` had to live in `ylx-transfer-adapters` instead, for the
//! crate-boundary reason above — see the final task report for the full
//! rationale. Everything *generic* the task asked for (the coordinator,
//! the worker pool, the pause/cancel/retry state machine, the interrupt-
//! aware/checkpoint-throttling `DownloadSource` decorator) lives here as
//! asked, in `ylx-transfer-core`.
//!
//! # Concurrency model (kept deliberately simple — no new async runtime)
//!
//! - A fixed pool of `num_workers` OS threads (`std::thread`) share one
//!   `std::sync::mpsc::Receiver<JobId>` (wrapped in a `Mutex` — `Receiver`
//!   is not `Clone`/`Sync`, this is the standard multi-consumer pattern
//!   for it). `enqueue`/`cancel`/`resume`/the dispatcher push `JobId`s
//!   onto the matching `Sender`.
//! - A job never *occupies* a worker thread while it is not actively
//!   doing work: if a job is not ready (device offline/pairing, capture
//!   active), the worker transitions it to the matching waiting state and
//!   immediately returns the thread to the pool — this is what keeps one
//!   device's outage from starving another device's jobs (see
//!   `two_devices_are_independent` in the tests below), without needing
//!   per-device worker affinity.
//! - A lightweight dispatcher thread wakes every `dispatch_interval` and
//!   re-pushes every non-terminal, currently-inactive job back onto the
//!   work channel, so a job parked in `waiting_for_device`/
//!   `paused_capture_active`/etc. eventually gets re-evaluated once
//!   conditions change, without the coordinator needing an explicit
//!   "device reconnected" event bus.
//! - [`JobControl::active`] (an `AtomicBool` per job) is the "a worker
//!   currently owns this job" flag `cancel()` polls on: it blocks the
//!   calling thread until the flag flips back to `false`, which by
//!   construction only happens *after* the in-flight `download_file` call
//!   (if any) has returned and therefore already closed its `.part` file
//!   handle (see `queue.rs`'s module doc comment) — so `cancel()` never
//!   observes `cancelled` with a dangling handle still open.
//!
//! # State-machine simplifications (documented, not hidden)
//!
//! Plan 5.4's tagged `TransferJobState` (verbatim in `transfer::mod`) has
//! **no** dedicated "paused by user" variant — only `paused_capture_active`
//! for the automatic capture-priority case. The user's intent therefore
//! lives in `TransferStore::desired_run_state`, mirrored in `ManagedJob` only
//! after the durable write succeeds. No worker-control flag is allowed to
//! shadow that intent. A job actively `transferring` is paused via the
//! *valid* `(Transferring, RetryWait)` edge — `retry_wait` is reused as the
//! generic "not running right now, eligible to resume" resting state.
//! `resume()` clears the durable intent and, for a job resting in
//! `retry_wait`, transitions it back to `queued` (a valid edge) so the normal
//! readiness-check path picks it up again.

use std::collections::HashMap;
use std::panic;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::device::{CaptureActivityState, ConnectionState};
use crate::domain::{DeviceId, FileId, PublicationScope, SessionId};
use crate::library::download::{
    commit_staged_session, DownloadError, DownloadSource, FilePlan, PublicationMaterial,
    PublicationVerifier, VerifiedFile, VerifyError,
};
use crate::library::staging::{published_revision, RevisionState, SessionManifest, SessionStaging};
use crate::persistence::transfer_store::RetryJobError;
use crate::persistence::{
    CompleteJobError, CreateJobError, JobStateTag, PersistenceError, TerminalOutcome, TransferStore,
};

use super::aggregate::{
    CommandOutcome, DesiredRunState, DeviceReadiness, DeviceSnapshot, Effect, JobAggregate,
    JobCommand, JobSnapshot, RejectReason, TargetKey, TargetLeases, WorkerReport,
};
use super::fault::{classify_download_failure, CoordinatorFault, FailureClass, FaultKind};
use super::progress::{disk_baseline, JobProgress, JobProgressTracker};
use super::queue::{
    is_interrupt_error, now_string, request_from_spec, state_to_tag, tag_to_state, InterruptReason,
    JobControl, ManagedJob, TrackingSource, TransferRequest,
};
use super::scheduler::{ScheduleOutcome, WorkQueue};
use super::{FailureCode, JobId, TransferJobState};

/// How long a command that must wait for a worker to release a job waits
/// before giving up. Generous relative to a chunk-boundary interrupt
/// check, small enough that a wedged worker surfaces as a timeout rather
/// than a hang.
const WORKER_RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

// =====================================================================
// Collaborator seams
// =====================================================================

/// Read-only view of one device's connection/capture-activity state, as
/// far as `TransferCoordinator` needs it. See module doc comment for why
/// this exists instead of a direct `device::DeviceActor` dependency.
pub trait DeviceStatusPort: Send + Sync {
    fn connection_state(&self, device_id: &DeviceId) -> ConnectionState;
    fn capture_activity(&self, device_id: &DeviceId) -> CaptureActivityState;

    /// One coherent observation seam for commit 46. Existing adapters that
    /// only expose the two legacy accessors get a compatibility default;
    /// production `DeviceFleet` implementations override this to read a
    /// single versioned snapshot under their actor boundary.
    fn device_snapshot(&self, device_id: &DeviceId) -> DeviceSnapshot {
        DeviceSnapshot::new(
            0,
            self.connection_state(device_id),
            self.capture_activity(device_id),
        )
    }
}

/// Builds a [`DownloadSource`] for one (device, session, file). See module
/// doc comment for why this indirection exists instead of the coordinator
/// naming `PiDownloadSource`/`PiHttpClient` directly.
pub trait DownloadSourceFactory: Send + Sync {
    fn make_source(
        &self,
        device_id: &DeviceId,
        session_id: &SessionId,
        file_id: &FileId,
    ) -> Result<Box<dyn DownloadSource>, DownloadError>;
}

// =====================================================================
// Config / errors
// =====================================================================

#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    pub num_workers: usize,
    pub dispatch_interval: Duration,
    /// See `queue::TrackingSource::checkpoint_threshold_bytes`.
    pub checkpoint_threshold_bytes: u64,
    pub library_root: PathBuf,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        CoordinatorConfig {
            num_workers: 3,
            dispatch_interval: Duration::from_millis(50),
            checkpoint_threshold_bytes: 256 * 1024,
            library_root: PathBuf::from("."),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("persistence error: {0}")]
    Persistence(#[from] PersistenceError),
    #[error("job {0} not found")]
    NotFound(String),
    #[error("job {0} is already in a terminal state")]
    AlreadyTerminal(String),
    #[error("job {0} is not in a terminal state")]
    NotTerminal(String),
    #[error("job {0} cannot be retried (not in a failed state)")]
    NotFailed(String),
    #[error("timed out waiting for job {0} to settle")]
    Timeout(String),
    /// Commit 39: an expected-version CAS lost. The caller decided against
    /// `expected`, but another command had already committed `actual` —
    /// nothing was overwritten, and this is an explicit result rather than
    /// a silent last-writer-wins.
    #[error("job {job_id} moved on: expected version {expected}, found {actual}")]
    Stale {
        job_id: String,
        expected: u64,
        actual: u64,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("publication verification error: {0}")]
    Verification(#[from] VerifyError),
    #[error("transfer coordinator is shutting down")]
    ShuttingDown,
}

// =====================================================================
// TransferCoordinator
// =====================================================================

/// Shared coordinator state. `pub(super)` (not fully private) so
/// `recovery.rs` — a sibling module under `transfer`, not a descendant of
/// this one — can implement `Inner::recover_on_startup` and
/// `TransferCoordinator::recover_on_startup` there, per the task's file
/// split (`coordinator.rs` / `queue.rs` / `recovery.rs`), without a pile
/// of single-field getter methods.
/// Commit 41: the per-job serialized runtime entry point.
///
/// Every command — worker result, dispatcher tick, pause, resume, cancel,
/// retry, dismiss — decides and commits inside `serial`, so a durable
/// commit and the matching in-memory publication can never interleave with
/// another command's. This is what killed the `cancelling -> cancelling`
/// race: `Inner::cancel` and the worker used to each read the state, both
/// see "not cancelling yet", and both transition.
///
/// `version` is the job's monotonically increasing state version (commit
/// 39/40). It is an atomic so a snapshot holder can compare against it
/// without taking the lock, but it is only ever *written* while `serial`
/// is held.
pub(super) struct JobCell {
    serial: Mutex<()>,
    version: AtomicU64,
    observed_device_version: AtomicU64,
}

impl JobCell {
    fn new() -> Self {
        JobCell {
            serial: Mutex::new(()),
            version: AtomicU64::new(1),
            observed_device_version: AtomicU64::new(0),
        }
    }
}

/// A stop token shared by the dispatcher and worker queue. `Condvar` makes
/// shutdown wake a dispatcher immediately even when its configured interval
/// is very long; workers are woken by `WorkQueue::stop`.
struct StopSignal {
    stopped: AtomicBool,
    gate: Mutex<()>,
    changed: Condvar,
}

impl StopSignal {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            gate: Mutex::new(()),
            changed: Condvar::new(),
        }
    }

    fn stop(&self) {
        // Hold the same gate used by `wait` while publishing the stop
        // predicate. This closes the check-then-sleep window where a
        // notification could otherwise be delivered before the waiter
        // enters `wait_timeout`, leaving shutdown delayed until the full
        // dispatch interval expires.
        let _gate = self.gate.lock().unwrap();
        self.stopped.store(true, Ordering::SeqCst);
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        if self.stopped.load(Ordering::SeqCst) {
            return true;
        }
        let guard = self.gate.lock().unwrap();
        if self.stopped.load(Ordering::SeqCst) {
            return true;
        }
        let _ = self
            .changed
            .wait_timeout_while(guard, timeout, |_| !self.stopped.load(Ordering::SeqCst))
            .unwrap();
        self.stopped.load(Ordering::SeqCst)
    }
}

pub(super) struct Inner {
    /// The sole durable authority for job identity, spec, state, desired
    /// intent, file ledger and retry lineage.
    pub(super) transfer_store: Arc<Mutex<TransferStore>>,
    pub(super) jobs: Mutex<HashMap<JobId, ManagedJob>>,
    pub(super) controls: Mutex<HashMap<JobId, Arc<JobControl>>>,
    /// One serialized owner per job — see [`JobCell`].
    pub(super) cells: Mutex<HashMap<JobId, Arc<JobCell>>>,
    /// At most one writer per (device, session) target directory.
    pub(super) target_leases: TargetLeases,
    /// Bounded, de-duplicating ready-set notifications (commit 47).
    pub(super) work_queue: Arc<WorkQueue>,
    /// Observable machinery failures (commit 48/49/50).
    pub(super) faults: Mutex<Vec<CoordinatorFault>>,
    /// Byte-level progress per job — a channel of its own, deliberately
    /// not folded into `ManagedJob::state` (see `transfer::progress`).
    /// Entries outlive the job's terminal transition so a finished or
    /// cancelled job's progress stays readable.
    pub(super) progress: Mutex<HashMap<JobId, Arc<JobProgressTracker>>>,
    device_status: Arc<dyn DeviceStatusPort>,
    source_factory: Arc<dyn DownloadSourceFactory>,
    verifier: Arc<dyn PublicationVerifier>,
    library_root: Mutex<PathBuf>,
    checkpoint_threshold_bytes: u64,
    shutdown: AtomicBool,
    stop_signal: Arc<StopSignal>,
    observation_version: AtomicU64,
}

/// The durable job scheduler. See module doc comment for the full design.
pub struct TransferCoordinator {
    pub(super) inner: Arc<Inner>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    dispatcher: Mutex<Option<JoinHandle<()>>>,
}

/// Result of an explicit coordinator shutdown. A timeout is a diagnostic
/// outcome, not a silent detach: callers can surface the number of worker
/// threads that did not observe the stop boundary before the deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    pub completed: bool,
    pub workers_remaining: usize,
    pub dispatcher_remaining: bool,
    pub faults: Vec<CoordinatorFault>,
}

impl TransferCoordinator {
    fn build(
        transfer_store: Arc<Mutex<TransferStore>>,
        device_status: Arc<dyn DeviceStatusPort>,
        source_factory: Arc<dyn DownloadSourceFactory>,
        verifier: Arc<dyn PublicationVerifier>,
        config: CoordinatorConfig,
    ) -> Self {
        let work_queue = Arc::new(WorkQueue::new(config.num_workers.max(1) * 2));
        let stop_signal = Arc::new(StopSignal::new());
        let inner = Arc::new(Inner {
            transfer_store,
            jobs: Mutex::new(HashMap::new()),
            controls: Mutex::new(HashMap::new()),
            cells: Mutex::new(HashMap::new()),
            target_leases: TargetLeases::new(),
            work_queue: work_queue.clone(),
            faults: Mutex::new(Vec::new()),
            progress: Mutex::new(HashMap::new()),
            device_status,
            source_factory,
            verifier,
            library_root: Mutex::new(config.library_root.clone()),
            checkpoint_threshold_bytes: config.checkpoint_threshold_bytes,
            shutdown: AtomicBool::new(false),
            stop_signal: stop_signal.clone(),
            observation_version: AtomicU64::new(0),
        });

        let mut workers = Vec::new();
        for _ in 0..config.num_workers.max(1) {
            let inner_c = inner.clone();
            workers.push(thread::spawn(move || worker_loop(inner_c)));
        }

        let dispatcher = {
            let inner_c = inner.clone();
            let interval = config.dispatch_interval;
            thread::spawn(move || {
                while !inner_c.stop_signal.wait(interval) {
                    if inner_c.shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| inner_c.tick()));
                    if let Err(payload) = result {
                        let detail = payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| {
                                "dispatcher collaborator panicked with a non-string payload"
                                    .to_string()
                            });
                        inner_c.record_fault(CoordinatorFault::new(
                            None,
                            FaultKind::WorkerPanic,
                            FailureClass::Remote,
                            detail,
                        ));
                        break;
                    }
                }
            })
        };

        TransferCoordinator {
            inner,
            workers: Mutex::new(workers),
            dispatcher: Mutex::new(Some(dispatcher)),
        }
    }

    /// Production constructor. The transfer store is shared with the
    /// composition root; no legacy journal or sidecar path is accepted.
    #[cfg(not(test))]
    pub fn new(
        transfer_store: Arc<Mutex<TransferStore>>,
        device_status: Arc<dyn DeviceStatusPort>,
        source_factory: Arc<dyn DownloadSourceFactory>,
        verifier: Arc<dyn PublicationVerifier>,
        config: CoordinatorConfig,
    ) -> Self {
        Self::build(
            transfer_store,
            device_status,
            source_factory,
            verifier,
            config,
        )
    }

    /// Durable enqueue. `TransferStore::create_job` returns the existing
    /// job for an identical natural identity and rejects a mismatched
    /// request digest rather than silently reusing a different file plan.
    pub fn enqueue(&self, request: TransferRequest) -> Result<JobId, CoordinatorError> {
        let spec = request.to_job_spec(true, "").map_err(|error| {
            CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!("cannot build durable transfer spec: {error}"),
            })
        })?;
        self.inner.enqueue(request, spec)
    }

    /// Production enqueue entry point when composition has the signed
    /// publication's real date/full-session context. The durable spec is
    /// committed before any runtime worker state is installed.
    pub fn enqueue_with_spec(
        &self,
        request: TransferRequest,
        spec: crate::domain::JobSpec,
    ) -> Result<JobId, CoordinatorError> {
        validate_request_against_spec(&request, &spec)?;
        self.inner.enqueue(request, spec)
    }

    /// Stop dispatch, wake blocked workers and wait up to `deadline` for all
    /// owned threads to finish. Effects are expected to check the stop token
    /// at claim and source boundaries; an uncooperative source is reported
    /// as a timeout and its join handle is detached rather than blocking the
    /// caller indefinitely.
    pub fn shutdown(&self, deadline: Duration) -> ShutdownReport {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.stop_signal.stop();
        for control in self.inner.controls.lock().unwrap().values() {
            if control.active.load(Ordering::SeqCst) {
                control.request_interrupt(InterruptReason::Shutdown);
            }
        }
        self.inner.work_queue.stop();

        let end = Instant::now() + deadline;
        let mut dispatcher_remaining = false;
        if let Some(handle) = self.dispatcher.lock().unwrap().take() {
            while !handle.is_finished() && Instant::now() < end {
                thread::yield_now();
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                dispatcher_remaining = true;
                drop(handle);
                self.inner.record_fault(CoordinatorFault::new(
                    None,
                    FaultKind::Shutdown,
                    FailureClass::LocalIo,
                    "dispatcher did not stop before deadline",
                ));
            }
        }

        let mut remaining = 0;
        let mut workers = self.workers.lock().unwrap();
        let mut pending = Vec::new();
        for handle in workers.drain(..) {
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                pending.push(handle);
            }
        }
        for handle in pending {
            if Instant::now() < end {
                while !handle.is_finished() && Instant::now() < end {
                    thread::yield_now();
                }
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                remaining += 1;
                drop(handle);
            }
        }
        drop(workers);
        let faults = self.faults();
        ShutdownReport {
            completed: remaining == 0 && !dispatcher_remaining,
            workers_remaining: remaining,
            dispatcher_remaining,
            faults,
        }
    }

    #[must_use]
    pub fn job_state(&self, job_id: &JobId) -> Option<TransferJobState> {
        self.inner
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .map(|j| j.state.clone())
    }

    /// Byte-level progress for one job, or `None` if this coordinator has
    /// never known that job id. Independent of [`Self::job_state`] — see
    /// `transfer::progress` for the accounting rules (monotonic, resume-
    /// aware, `transferred == total` once a job succeeds). Progress
    /// survives `pause`/`resume`/`cancel` and stays readable after a job
    /// reaches a terminal state.
    #[must_use]
    pub fn job_progress(&self, job_id: &JobId) -> Option<JobProgress> {
        self.inner
            .progress
            .lock()
            .unwrap()
            .get(job_id)
            .map(|t| t.snapshot())
    }

    #[must_use]
    pub fn job_ids(&self) -> Vec<JobId> {
        self.inner.jobs.lock().unwrap().keys().cloned().collect()
    }

    /// Commit 40: one job's identity, state, desired run state, progress
    /// and error, all read at one `version` inside that job's serialized
    /// critical section. Callers should use this instead of stitching a view
    /// together from several independently-timed reads.
    #[must_use]
    pub fn job_snapshot(&self, job_id: &JobId) -> Option<JobSnapshot> {
        self.inner.snapshot(job_id)
    }

    /// Every known job's [`JobSnapshot`]. Each entry is internally atomic;
    /// see [`Self::job_snapshot`].
    #[must_use]
    pub fn list_snapshots(&self) -> Vec<JobSnapshot> {
        self.inner.list_snapshots()
    }

    /// Snapshot all machinery faults since construction. Faults are never
    /// silently discarded; reading does not clear them.
    #[must_use]
    pub fn faults(&self) -> Vec<CoordinatorFault> {
        self.inner.faults()
    }

    /// Commit 41: the single serialized command entry point. `pause`,
    /// `resume`, `cancel`, `retry` and `dismiss` are thin wrappers over
    /// this; a caller that already has a [`JobCommand`] can send it
    /// directly.
    pub fn command(
        &self,
        job_id: &JobId,
        command: JobCommand,
    ) -> Result<CommandOutcome, CoordinatorError> {
        self.inner.apply(job_id, command)
    }

    /// Commit 39: [`Self::command`] with an expected-version CAS. If the
    /// job has moved past `expected_version` since the snapshot the caller
    /// decided from, this returns [`CoordinatorError::Stale`] and changes
    /// nothing — it never overwrites a state another command committed.
    pub fn command_if_unchanged(
        &self,
        job_id: &JobId,
        expected_version: u64,
        command: JobCommand,
    ) -> Result<CommandOutcome, CoordinatorError> {
        self.inner
            .apply_checked(job_id, command, Some(expected_version))
    }

    #[must_use]
    pub fn library_root(&self) -> PathBuf {
        self.inner.library_root()
    }

    #[must_use]
    pub fn has_non_terminal_jobs(&self) -> bool {
        self.inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .any(|job| !job.state.is_terminal())
    }

    pub fn set_library_root_if_idle(&self, library_root: PathBuf) -> Result<(), String> {
        if self.has_non_terminal_jobs() {
            return Err("仍有下载任务未结束，无法切换本机保存位置".to_string());
        }
        *self.inner.library_root.lock().unwrap() = library_root;
        Ok(())
    }

    /// Force one dispatcher pass synchronously (also happens automatically
    /// every `dispatch_interval` via the background thread) — mainly
    /// useful for deterministic tests.
    pub fn tick(&self) {
        self.inner.tick();
    }

    /// Pause a job. See module doc comment "State-machine simplifications"
    /// for exactly which DB transition (if any) this performs.
    pub fn pause(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.inner.pause(job_id)
    }

    /// Resume a previously-paused job.
    pub fn resume(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.inner.resume(job_id)
    }

    /// Cancel a job. Blocks the calling thread until any in-flight
    /// worker/file handle for this job has actually closed and the job
    /// has reached `cancelled` — see module doc comment.
    pub fn cancel(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.inner.cancel(job_id)
    }

    /// Re-enqueue a **terminal `failed`** job as a brand-new job (fresh
    /// `idempotency_key`). `TransferStore` keeps the failed parent terminal
    /// and records the retry as a separate durable child row.
    pub fn retry(&self, job_id: &JobId) -> Result<JobId, CoordinatorError> {
        self.inner.retry(job_id)
    }

    /// Permanently removes a terminal job from the live queue and its
    /// durable recovery records. Active jobs must be cancelled first.
    pub fn dismiss(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.inner.dismiss(job_id)
    }

    /// Checks whether a terminal download can be dismissed without changing
    /// either the runtime or durable state.  The application layer uses this
    /// before writing its durable visibility tombstone so a failed tombstone
    /// attempt cannot strand a job that has already been removed from the
    /// coordinator.
    pub fn validate_dismissal(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.inner.validate_dismissal(job_id)
    }

    /// Removes a dismissed job from the coordinator's in-memory views only.
    ///
    /// Unlike [`Self::dismiss`], this deliberately does not call
    /// `TransferStore::delete_job`: the application persistence boundary owns
    /// the durable `dismissed_at` tombstone and must retain the job, spec,
    /// completion outbox, and retry lineage for audit/replay.  The operation
    /// is idempotent for a runtime that has already forgotten the row, which
    /// lets a caller retry cleanup after a crash between the tombstone and
    /// this in-memory projection.
    pub fn dismiss_runtime(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.inner.dismiss_runtime(job_id)
    }

    // `recover_on_startup` is implemented in `recovery.rs`, per the task's
    // file split — see that module for `impl TransferCoordinator`.
}

impl Drop for TransferCoordinator {
    fn drop(&mut self) {
        let _ = self.shutdown(Duration::from_secs(1));
    }
}

// =====================================================================
// Worker thread
// =====================================================================

fn worker_loop(inner: Arc<Inner>) {
    loop {
        let Some(job_id) = inner.work_queue.claim(Duration::from_millis(100)) else {
            if inner.shutdown.load(Ordering::SeqCst) || inner.work_queue.is_stopped() {
                return;
            }
            continue;
        };

        let control = { inner.controls.lock().unwrap().get(&job_id).cloned() };
        let Some(control) = control else { continue };
        let Some(lease) = control.try_claim() else {
            // Another worker already owns this job (duplicate dispatch —
            // harmless, and collapsed by the ready set in normal operation).
            continue;
        };

        if inner.shutdown.load(Ordering::SeqCst) {
            control.request_interrupt(InterruptReason::Shutdown);
            drop(lease);
            return;
        }

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            inner.process_job(&job_id, lease.control());
        }));
        if let Err(payload) = result {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "worker panicked with a non-string payload".to_string());
            inner.record_fault(CoordinatorFault::new(
                Some(job_id.clone()),
                FaultKind::WorkerPanic,
                FailureClass::LocalIo,
                detail.clone(),
            ));
            if let Err(error) =
                inner.worker_report(&job_id, WorkerReport::WorkerPanicked { detail })
            {
                inner.record_fault(CoordinatorFault::new(
                    Some(job_id.clone()),
                    FaultKind::Transition,
                    FailureClass::LocalIo,
                    format!("worker panic failed to converge job: {error}"),
                ));
            }
            control.clear_interrupt();
        }
        // `lease` is deliberately dropped after panic handling. Its RAII
        // destructor releases `active` on every return path.
        drop(lease);
    }
}

// =====================================================================
// Readiness
// =====================================================================

#[derive(Debug)]
enum Readiness {
    Ready,
    WaitDevice,
    WaitPairing,
    CapturePaused,
}

enum TransferOutcome {
    AllDone(Vec<VerifiedFile>),
    NotReady,
    CapturePaused,
    UserPaused,
    Cancelled,
    Shutdown,
    Failed(FailureCode, bool),
}

impl Inner {
    pub(super) fn record_fault(&self, fault: CoordinatorFault) {
        self.faults.lock().unwrap().push(fault);
    }

    fn faults(&self) -> Vec<CoordinatorFault> {
        self.faults.lock().unwrap().clone()
    }

    fn library_root(&self) -> PathBuf {
        self.library_root.lock().unwrap().clone()
    }

    fn device_snapshot(&self, device_id: &DeviceId) -> DeviceSnapshot {
        let version = self.observation_version.fetch_add(1, Ordering::SeqCst) + 1;
        let mut snapshot = self.device_status.device_snapshot(device_id);
        // The adapter owns the coherent pair; the coordinator owns the
        // monotonic observation sequence used for stale-result fencing.
        snapshot.version = version;
        snapshot
    }

    fn readiness_from_snapshot(snapshot: &DeviceSnapshot) -> Readiness {
        match snapshot.readiness() {
            DeviceReadiness::Ready => Readiness::Ready,
            DeviceReadiness::WaitDevice => Readiness::WaitDevice,
            DeviceReadiness::WaitPairing => Readiness::WaitPairing,
            DeviceReadiness::CapturePaused => Readiness::CapturePaused,
        }
    }

    fn readiness(&self, device_id: &DeviceId) -> Readiness {
        Self::readiness_from_snapshot(&self.device_snapshot(device_id))
    }

    /// Apply one versioned readiness observation through the aggregate. The
    /// returned readiness is only a local hint for choosing an effect; the
    /// durable parked/interrupt decision belongs to the reducer.
    fn observe_device(
        &self,
        job_id: &JobId,
        device_id: &DeviceId,
    ) -> Result<Readiness, CoordinatorError> {
        let snapshot = self.device_snapshot(device_id);
        let readiness = Self::readiness_from_snapshot(&snapshot);
        self.apply(job_id, JobCommand::DeviceObserved(snapshot))?;
        Ok(readiness)
    }

    // -------------------------------------------------------------
    // enqueue
    // -------------------------------------------------------------

    /// Mint a fresh, random, opaque job id.
    ///
    /// This used to be a process-local `AtomicU64` counter formatted as
    /// `job-{seq:016x}`, which is unsound for an id that outlives the
    /// process: the counter restarts at 0 on every launch, so the first
    /// job enqueued after a restart re-proposes `job-0000000000000000` —
    /// an id the *previous* run already committed to the SQLite journal.
    /// The insert then failed on the `jobs` primary key and (before
    /// `try_insert_job` existed) was mistaken for an idempotency hit. A
    /// UUID v4 is 122 random bits, so a collision across restarts is not
    /// something a user will ever observe. `uuid` is already a dependency
    /// of the root Tauri app; see `Cargo.toml` for why only the `v4`
    /// feature is enabled here.
    fn next_job_id(&self) -> JobId {
        JobId(format!("job-{}", uuid::Uuid::new_v4()))
    }

    fn enqueue(
        &self,
        request: TransferRequest,
        spec: crate::domain::JobSpec,
    ) -> Result<JobId, CoordinatorError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(CoordinatorError::ShuttingDown);
        }

        self.verify_request_publication(&request)?;

        let now = now_string();
        let job_id = self.next_job_id();
        let outcome = self
            .transfer_store
            .lock()
            .unwrap()
            .create_job(job_id.as_str(), &spec, &now)
            .map_err(|error| match error {
                CreateJobError::RequestDigestMismatch(conflict) => {
                    CoordinatorError::Persistence(PersistenceError::Conflict {
                        detail: format!("{conflict:?}"),
                    })
                }
                CreateJobError::JobIdCollision { job_id, existing } => {
                    CoordinatorError::Persistence(PersistenceError::Conflict {
                        detail: format!("job id {job_id} collides with {existing}"),
                    })
                }
                CreateJobError::Persistence(error) => CoordinatorError::Persistence(error),
            })?;

        let stored = outcome.job().clone();
        if matches!(outcome, crate::persistence::CreateJobOutcome::Existing(_)) {
            if self
                .jobs
                .lock()
                .unwrap()
                .contains_key(&JobId(stored.job_id.clone()))
            {
                return Ok(JobId(stored.job_id));
            }
            if !stored.state.is_terminal() || stored.state == JobStateTag::Failed {
                let request = request_from_spec(&spec);
                self.rehydrate(
                    JobId(stored.job_id.clone()),
                    request,
                    tag_to_state(stored.state, stored.error),
                    spec.publication_scope(),
                    stored.desired_run_state,
                    stored.state_version,
                );
            }
            return Ok(JobId(stored.job_id));
        }

        let job_id = JobId(stored.job_id);
        self.install_progress(&job_id, &request);
        let managed = ManagedJob {
            job_id: job_id.clone(),
            request,
            state: TransferJobState::Queued,
            publication_scope: spec.publication_scope(),
            desired_run_state: DesiredRunState::Run,
            verified_files: Vec::new(),
        };
        self.jobs.lock().unwrap().insert(job_id.clone(), managed);
        self.controls
            .lock()
            .unwrap()
            .insert(job_id.clone(), Arc::new(JobControl::default()));
        self.cells
            .lock()
            .unwrap()
            .insert(job_id.clone(), Arc::new(JobCell::new()));
        self.schedule(&job_id);
        Ok(job_id)
    }

    /// Offer one job to the bounded ready set and make refusal observable.
    fn schedule(&self, job_id: &JobId) -> ScheduleOutcome {
        let outcome = self.work_queue.schedule(job_id);
        match outcome {
            ScheduleOutcome::Scheduled | ScheduleOutcome::AlreadyScheduled => {}
            ScheduleOutcome::Full => self.record_fault(CoordinatorFault::new(
                Some(job_id.clone()),
                FaultKind::Send,
                FailureClass::LocalIo,
                format!(
                    "ready queue is full (capacity {})",
                    self.work_queue.capacity()
                ),
            )),
            ScheduleOutcome::Stopped => self.record_fault(CoordinatorFault::new(
                Some(job_id.clone()),
                FaultKind::Send,
                FailureClass::Cancelled,
                "ready queue is stopped",
            )),
        }
        outcome
    }

    // -------------------------------------------------------------
    // tick / dispatch
    // -------------------------------------------------------------

    /// Reconcile one versioned device observation per non-terminal job and
    /// offer only jobs in the ready set to workers. Active transfers still
    /// receive observations so the reducer can request an interrupt when a
    /// device disappears mid-file.
    fn tick(&self) {
        let ids: Vec<JobId> = self.jobs.lock().unwrap().keys().cloned().collect();
        for job_id in ids {
            let (state, device_id, desired_run_state) = {
                let jobs = self.jobs.lock().unwrap();
                let Some(job) = jobs.get(&job_id) else {
                    continue;
                };
                (
                    job.state.clone(),
                    job.request.device_id.clone(),
                    job.desired_run_state,
                )
            };
            if state.is_terminal() {
                continue;
            }
            let target = {
                let jobs = self.jobs.lock().unwrap();
                let Some(job) = jobs.get(&job_id) else {
                    continue;
                };
                TargetKey::new(&job.request.device_id, &job.request.session_id)
            };
            if let Some(holder) = self.target_leases.holder(&target) {
                if holder != job_id {
                    // Do not even park/prepare a job whose target is held by
                    // another writer. Its queued state is the honest
                    // acknowledgement that no worker effect has started.
                    continue;
                }
            }
            let control = self.controls.lock().unwrap().get(&job_id).cloned();
            let Some(control) = control else { continue };

            // A queued notification is already an in-flight readiness
            // probe. Let its worker own the snapshot->reducer linearization
            // instead of racing it from the periodic dispatcher (which can
            // otherwise publish a second device observation before the first
            // commit has updated the in-memory row).
            if state == TransferJobState::Queued
                && (self.work_queue.is_scheduled(&job_id) || control.active.load(Ordering::SeqCst))
            {
                continue;
            }

            if control.active.load(Ordering::SeqCst) {
                if let Err(error) = self.observe_device(&job_id, &device_id) {
                    self.record_fault(CoordinatorFault::new(
                        Some(job_id.clone()),
                        FaultKind::Transition,
                        FailureClass::LocalIo,
                        error.to_string(),
                    ));
                }
                continue;
            }
            if desired_run_state == DesiredRunState::Paused {
                continue;
            }

            let readiness = if matches!(
                &state,
                TransferJobState::Queued
                    | TransferJobState::RetryWait
                    | TransferJobState::WaitingForDevice
                    | TransferJobState::WaitingForPairing
                    | TransferJobState::PausedCaptureActive
            ) {
                match self.observe_device(&job_id, &device_id) {
                    Ok(readiness) => readiness,
                    Err(error) => {
                        self.record_fault(CoordinatorFault::new(
                            Some(job_id.clone()),
                            FaultKind::Transition,
                            FailureClass::LocalIo,
                            error.to_string(),
                        ));
                        continue;
                    }
                }
            } else {
                Readiness::Ready
            };

            if matches!(readiness, Readiness::Ready)
                || matches!(
                    &state,
                    TransferJobState::Preparing
                        | TransferJobState::Verifying
                        | TransferJobState::Committing
                        | TransferJobState::Cancelling
                )
            {
                self.schedule(&job_id);
            }
        }
    }

    /// Worker effects enter the same reducer boundary as user commands. A
    /// stale/wrong-stage report is a machinery fault and is recorded rather
    /// than silently dropping the worker's result (commit 42/48).
    fn worker_report(
        &self,
        job_id: &JobId,
        report: WorkerReport,
    ) -> Result<CommandOutcome, CoordinatorError> {
        let result = self.apply(job_id, JobCommand::Worker(report));
        if let Err(error) = &result {
            self.record_fault(CoordinatorFault::new(
                Some(job_id.clone()),
                FaultKind::Transition,
                FailureClass::LocalIo,
                error.to_string(),
            ));
        }
        result
    }

    // -------------------------------------------------------------
    // Commit 41: the per-job serialized runtime entry point
    // -------------------------------------------------------------

    fn cell(&self, job_id: &JobId) -> Result<Arc<JobCell>, CoordinatorError> {
        self.cells
            .lock()
            .unwrap()
            .get(job_id)
            .cloned()
            .ok_or_else(|| CoordinatorError::NotFound(job_id.to_string()))
    }

    fn control(&self, job_id: &JobId) -> Result<Arc<JobControl>, CoordinatorError> {
        self.controls
            .lock()
            .unwrap()
            .get(job_id)
            .cloned()
            .ok_or_else(|| CoordinatorError::NotFound(job_id.to_string()))
    }

    pub(super) fn apply(
        &self,
        job_id: &JobId,
        command: JobCommand,
    ) -> Result<CommandOutcome, CoordinatorError> {
        self.apply_checked(job_id, command, None)
    }

    /// Decide one command against this job's current state and perform the
    /// resulting effects, all inside this job's critical section.
    ///
    /// The one place the section is released is across
    /// [`Effect::AwaitWorkerRelease`] — a command that waits for a worker
    /// to let go must not be holding the lock that worker needs to let go
    /// *through*. Everything after the await re-enters the section, so a
    /// two-phase command (pause, cancel) is still serialized against every
    /// other command at each phase.
    pub(super) fn apply_checked(
        &self,
        job_id: &JobId,
        command: JobCommand,
        expected_version: Option<u64>,
    ) -> Result<CommandOutcome, CoordinatorError> {
        let cell = self.cell(job_id)?;
        let control = self.control(job_id)?;

        let mut guard = Some(cell.serial.lock().unwrap());
        let aggregate = self.load_aggregate(job_id, &cell)?;
        if let Some(expected) = expected_version {
            if expected != aggregate.version {
                return Err(CoordinatorError::Stale {
                    job_id: job_id.to_string(),
                    expected,
                    actual: aggregate.version,
                });
            }
        }

        let decision = aggregate.decide(command);
        if let CommandOutcome::Rejected(reason) = &decision.outcome {
            return Err(reject_error(job_id, reason));
        }

        let mut effects = decision.effects.into_iter();
        let mut awaited = false;
        for effect in effects.by_ref() {
            if matches!(effect, Effect::AwaitWorkerRelease) {
                awaited = true;
                break;
            }
            self.perform(job_id, &cell, &control, effect)?;
        }
        let rest: Vec<Effect> = effects.collect();

        if awaited {
            drop(guard.take());
            if !wait_for_inactive(&control, WORKER_RELEASE_TIMEOUT) {
                return Err(CoordinatorError::Timeout(job_id.to_string()));
            }
            if !rest.is_empty() {
                guard = Some(cell.serial.lock().unwrap());
                for effect in rest {
                    self.perform(job_id, &cell, &control, effect)?;
                }
            }
        }
        drop(guard);
        Ok(decision.outcome)
    }

    /// Read the three facts the pure reducer needs. Callers must already
    /// hold `cell.serial`.
    fn load_aggregate(
        &self,
        job_id: &JobId,
        cell: &JobCell,
    ) -> Result<JobAggregate, CoordinatorError> {
        let (state, desired) = self
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .map(|j| (j.state.clone(), j.desired_run_state))
            .ok_or_else(|| CoordinatorError::NotFound(job_id.to_string()))?;
        Ok(JobAggregate::new(state)
            .with_version(cell.version.load(Ordering::SeqCst))
            .with_observed_device_version(cell.observed_device_version.load(Ordering::SeqCst))
            .with_desired_run_state(desired))
    }

    /// Perform one reducer-decided effect. Callers must already hold
    /// `cell.serial` (except across an await phase — see
    /// [`Self::apply_checked`]).
    fn perform(
        &self,
        job_id: &JobId,
        cell: &JobCell,
        control: &Arc<JobControl>,
        effect: Effect,
    ) -> Result<(), CoordinatorError> {
        match effect {
            Effect::Commit {
                expected_version,
                to,
            } => {
                let actual = cell.version.load(Ordering::SeqCst);
                if actual != expected_version {
                    return Err(CoordinatorError::Stale {
                        job_id: job_id.to_string(),
                        expected: expected_version,
                        actual,
                    });
                }
                if let Err(error) = self.commit_transition(job_id, expected_version, &to) {
                    self.record_fault(CoordinatorFault::new(
                        Some(job_id.clone()),
                        FaultKind::Transition,
                        FailureClass::LocalIo,
                        error.to_string(),
                    ));
                    return Err(error);
                }
                cell.version.store(expected_version + 1, Ordering::SeqCst);
            }
            Effect::SetDesiredRunState(desired) => {
                let version = cell.version.load(Ordering::SeqCst);
                if let Err(error) = self.transfer_store.lock().unwrap().set_desired_run_state(
                    job_id.as_str(),
                    desired,
                    &now_string(),
                    Some(version),
                ) {
                    self.record_fault(CoordinatorFault::new(
                        Some(job_id.clone()),
                        FaultKind::DesiredRunState,
                        FailureClass::LocalIo,
                        error.to_string(),
                    ));
                    return Err(CoordinatorError::Persistence(error));
                }
                // Publish the in-memory aggregate only after the durable
                // intent write succeeds. A failed CAS/write must leave both
                // authorities unchanged.
                if let Some(job) = self.jobs.lock().unwrap().get_mut(job_id) {
                    job.desired_run_state = desired;
                }
            }
            Effect::RequestInterrupt(reason) => control.request_interrupt(reason),
            Effect::ClearInterrupt => control.clear_interrupt(),
            Effect::Dispatch => {
                self.schedule(job_id);
            }
            Effect::RecordDeviceVersion(version) => {
                let mut current = cell.observed_device_version.load(Ordering::SeqCst);
                while version > current {
                    match cell.observed_device_version.compare_exchange(
                        current,
                        version,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(next) => current = next,
                    }
                }
            }
            // Handled by `apply_checked`'s phase split.
            Effect::AwaitWorkerRelease => {}
            // Performed by the command method that asked for them: they
            // create or destroy a *different* durable job, which is not a
            // state transition of this one.
            Effect::SpawnRetryJob | Effect::RemoveJob => {}
        }
        Ok(())
    }

    /// The durable write plus its in-memory publication — one indivisible
    /// step inside the per-job critical section, so no reader can ever see
    /// the two disagree.
    fn commit_transition(
        &self,
        job_id: &JobId,
        expected_version: u64,
        to: &TransferJobState,
    ) -> Result<(), CoordinatorError> {
        let (tag, error) = state_to_tag(to);
        let now = now_string();
        let mut transfer_store = self.transfer_store.lock().unwrap();
        if to.is_terminal() {
            // Terminal outcomes carry a durable completion-outbox record, so
            // they must use the store's atomic completion path. Keep the
            // coordinator's per-job version check in front of that write so
            // a stale worker cannot publish a second terminal outcome.
            let current = transfer_store
                .get_job(job_id.as_str())?
                .ok_or_else(|| CoordinatorError::NotFound(job_id.to_string()))?;
            if current.state_version != expected_version {
                return Err(CoordinatorError::Stale {
                    job_id: job_id.to_string(),
                    expected: expected_version,
                    actual: current.state_version,
                });
            }
            let outcome = match tag {
                JobStateTag::Succeeded => TerminalOutcome::Succeeded,
                JobStateTag::Cancelled => TerminalOutcome::Cancelled,
                JobStateTag::Failed => {
                    let (code, retryable) = error.expect("failed state carries error columns");
                    TerminalOutcome::Failed { code, retryable }
                }
                _ => unreachable!("terminal state tag expected, got {tag:?}"),
            };
            transfer_store
                .complete_job(job_id.as_str(), &outcome, &now)
                .map_err(map_complete_job_error)?;
        } else {
            transfer_store.transition_job(
                job_id.as_str(),
                expected_version,
                tag,
                error.as_ref().map(|(c, r)| (c.as_str(), *r)),
                &now,
            )?;
        }
        if let Some(job) = self.jobs.lock().unwrap().get_mut(job_id) {
            job.state = to.clone();
        }
        Ok(())
    }

    // -------------------------------------------------------------
    // Commit 40: atomic snapshots
    // -------------------------------------------------------------

    fn snapshot(&self, job_id: &JobId) -> Option<JobSnapshot> {
        let cell = self.cells.lock().unwrap().get(job_id).cloned()?;
        let _guard = cell.serial.lock().unwrap();
        let (state, desired_run_state, device_id, session_id) = {
            let jobs = self.jobs.lock().unwrap();
            let job = jobs.get(job_id)?;
            (
                job.state.clone(),
                job.desired_run_state,
                job.request.device_id.clone(),
                job.request.session_id.clone(),
            )
        };
        let control = self.controls.lock().unwrap().get(job_id).cloned();
        let active = control
            .as_ref()
            .map(|control| control.active.load(Ordering::SeqCst))
            .unwrap_or(false);
        let progress = self
            .progress
            .lock()
            .unwrap()
            .get(job_id)
            .map(|t| t.snapshot())
            .unwrap_or_default();
        Some(JobSnapshot {
            job_id: job_id.clone(),
            version: cell.version.load(Ordering::SeqCst),
            device_id,
            session_id,
            error: JobSnapshot::failure_of(&state),
            state,
            desired_run_state,
            progress,
            active,
        })
    }

    fn list_snapshots(&self) -> Vec<JobSnapshot> {
        let ids: Vec<JobId> = self.jobs.lock().unwrap().keys().cloned().collect();
        ids.iter().filter_map(|id| self.snapshot(id)).collect()
    }

    // -------------------------------------------------------------
    // progress
    // -------------------------------------------------------------

    /// Create (or replace) this job's progress tracker, seeded from
    /// whatever is already on disk for its files. Called from `enqueue`
    /// (normally a no-op baseline of zeros) and from `rehydrate` — where
    /// it is what stops a crash-recovered job's progress bar from
    /// restarting at zero. See `transfer::progress::disk_baseline` for the
    /// evidence rules and why they are trustworthy.
    fn install_progress(&self, job_id: &JobId, request: &TransferRequest) {
        let total_bytes = request.files.iter().map(|f| f.expected_size).sum();
        let files_total = request.files.len() as u32;
        let library_root = self.library_root();
        // New jobs count durable evidence from their revision-scoped hidden
        // root. A visible baseline is retained only for an explicitly
        // legacy tree with no revision marker; it must never make a prior
        // published revision look complete for a different publication.
        let baseline_root = SessionStaging::for_publication(
            &library_root,
            request.device_id.as_str(),
            request.session_id.as_str(),
            &request.manifest_bytes,
        )
        .ok()
        .map(|staging| match staging.state() {
            RevisionState::Staged | RevisionState::Sealed => staging.file_root(),
            RevisionState::Published | RevisionState::SelectedPublished => library_root.clone(),
            RevisionState::Absent => {
                if published_revision(
                    &library_root,
                    request.device_id.as_str(),
                    request.session_id.as_str(),
                )
                .is_none()
                {
                    library_root.clone()
                } else {
                    staging.file_root()
                }
            }
        })
        .unwrap_or_else(|| library_root.clone());
        let baseline = disk_baseline(
            &baseline_root,
            request.device_id.as_str(),
            request.session_id.as_str(),
            request.files.iter().map(|f| {
                (
                    f.file_id.as_str(),
                    f.target_relative_path.as_deref(),
                    f.expected_size,
                )
            }),
        );
        self.progress.lock().unwrap().insert(
            job_id.clone(),
            Arc::new(JobProgressTracker::with_baseline(
                total_bytes,
                files_total,
                baseline,
            )),
        );
    }

    fn progress_tracker(&self, job_id: &JobId) -> Option<Arc<JobProgressTracker>> {
        self.progress.lock().unwrap().get(job_id).cloned()
    }

    fn set_verified_files(&self, job_id: &JobId, files: Vec<VerifiedFile>) {
        if let Some(job) = self.jobs.lock().unwrap().get_mut(job_id) {
            job.verified_files = files;
        }
    }

    // -------------------------------------------------------------
    // process_job: the per-job state-machine loop a worker runs while it
    // owns the job (`control.active == true`).
    // -------------------------------------------------------------

    fn process_job(&self, job_id: &JobId, control: &Arc<JobControl>) {
        // At most one writer per target directory (commit 41's runtime
        // half of "one target, one lease"): two jobs may legitimately name
        // the same (device, session) — different idempotency keys, a retry
        // lineage — and they must not both write into it. The lease is
        // RAII, so an early return or a panic below releases it; a job
        // that cannot get it simply stays parked until the next dispatch.
        let target = {
            let jobs = self.jobs.lock().unwrap();
            let Some(job) = jobs.get(job_id) else { return };
            TargetKey::new(&job.request.device_id, &job.request.session_id)
        };
        let Some(lease) = self.target_leases.try_acquire(target, job_id) else {
            return;
        };

        loop {
            // Keep the RAII guard live for the entire worker loop. Merely
            // binding a Drop value as `_lease` permits the compiler to end
            // its lifetime before the first state transition, which would
            // let a second job acquire the same target while this worker is
            // still downloading.
            let _ = lease.target();
            let (state, device_id, desired_run_state) = {
                let jobs = self.jobs.lock().unwrap();
                let Some(job) = jobs.get(job_id) else { return };
                (
                    job.state.clone(),
                    job.request.device_id.clone(),
                    job.desired_run_state,
                )
            };

            match state {
                TransferJobState::Queued | TransferJobState::RetryWait => {
                    if desired_run_state == DesiredRunState::Paused {
                        return;
                    }
                    let readiness = match self.observe_device(job_id, &device_id) {
                        Ok(readiness) => readiness,
                        Err(error) => {
                            self.record_fault(CoordinatorFault::new(
                                Some(job_id.clone()),
                                FaultKind::Transition,
                                FailureClass::LocalIo,
                                error.to_string(),
                            ));
                            return;
                        }
                    };
                    match readiness {
                        Readiness::Ready => {
                            // `DeviceObserved` already committed preparing
                            // through the aggregate.
                            continue;
                        }
                        Readiness::WaitDevice => {
                            // Give the newly parked job one follow-up
                            // acknowledgement. The ready-set remains
                            // bounded and does not re-offer it on every
                            // dispatcher tick, but this preserves a useful
                            // happens-after observation for callers.
                            self.schedule(job_id);
                            return;
                        }
                        Readiness::WaitPairing => {
                            self.schedule(job_id);
                            return;
                        }
                        Readiness::CapturePaused => {
                            return;
                        }
                    }
                }
                TransferJobState::WaitingForDevice
                | TransferJobState::WaitingForPairing
                | TransferJobState::PausedCaptureActive => {
                    if desired_run_state == DesiredRunState::Paused {
                        return;
                    }
                    match self.observe_device(job_id, &device_id) {
                        Ok(Readiness::Ready) => {
                            continue;
                        }
                        Ok(_) => return, // still not ready; stay parked
                        Err(error) => {
                            self.record_fault(CoordinatorFault::new(
                                Some(job_id.clone()),
                                FaultKind::Transition,
                                FailureClass::LocalIo,
                                error.to_string(),
                            ));
                            return;
                        }
                    }
                }
                TransferJobState::Preparing => {
                    let verification = {
                        let jobs = self.jobs.lock().unwrap();
                        let job = jobs.get(job_id).expect("job present while preparing");
                        self.verify_request_publication(&job.request)
                    };
                    if let Err(error) = verification {
                        let _ = self.worker_report(
                            job_id,
                            WorkerReport::PreparationFailed {
                                code: FailureCode::Other(error.to_string()),
                                retryable: false,
                            },
                        );
                        return;
                    }
                    if self.worker_report(job_id, WorkerReport::Prepared).is_err() {
                        return;
                    }
                    continue;
                }
                TransferJobState::Transferring => {
                    let transfer_outcome = self.run_transfer(job_id, control);
                    if let Some(detail) = control.take_checkpoint_fault() {
                        self.record_fault(CoordinatorFault::new(
                            Some(job_id.clone()),
                            FaultKind::Checkpoint,
                            FailureClass::LocalIo,
                            detail,
                        ));
                    }
                    match transfer_outcome {
                        TransferOutcome::AllDone(files) => {
                            self.set_verified_files(job_id, files);
                            if self
                                .worker_report(job_id, WorkerReport::TransferComplete)
                                .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                        TransferOutcome::CapturePaused => {
                            // Clear the interrupt *before* parking — it has
                            // already done its job (unwinding `download_file`
                            // and, per that function's own guarantee, closing
                            // its `.part` file handle before returning). If
                            // left set, the next pickup of this job (once
                            // capture activity returns to idle) would
                            // immediately re-interrupt itself and never make
                            // progress.
                            control.clear_interrupt();
                            let _ = self.worker_report(
                                job_id,
                                WorkerReport::Interrupted(InterruptReason::CapturePause),
                            );
                            return;
                        }
                        TransferOutcome::UserPaused => {
                            control.clear_interrupt();
                            let _ = self.worker_report(
                                job_id,
                                WorkerReport::Interrupted(InterruptReason::UserPause),
                            );
                            return;
                        }
                        TransferOutcome::NotReady => {
                            control.clear_interrupt();
                            let reason = match self.readiness(&device_id) {
                                Readiness::WaitPairing | Readiness::WaitDevice => {
                                    InterruptReason::DeviceLost
                                }
                                Readiness::CapturePaused => InterruptReason::CapturePause,
                                Readiness::Ready => InterruptReason::DeviceLost,
                            };
                            let _ = self.worker_report(job_id, WorkerReport::Interrupted(reason));
                            return;
                        }
                        TransferOutcome::Cancelled => {
                            control.clear_interrupt();
                            let _ = self.worker_report(
                                job_id,
                                WorkerReport::Interrupted(InterruptReason::Cancel),
                            );
                            return;
                        }
                        TransferOutcome::Shutdown => {
                            control.clear_interrupt();
                            let _ = self.worker_report(
                                job_id,
                                WorkerReport::Interrupted(InterruptReason::Shutdown),
                            );
                            return;
                        }
                        TransferOutcome::Failed(code, retryable) => {
                            let _ = self.worker_report(
                                job_id,
                                WorkerReport::TransferFailed { code, retryable },
                            );
                            return;
                        }
                    }
                }
                TransferJobState::Verifying => {
                    if self.worker_report(job_id, WorkerReport::Verified).is_err() {
                        return;
                    }
                    continue;
                }
                TransferJobState::Committing => {
                    let commit_result = {
                        let jobs = self.jobs.lock().unwrap();
                        let job = jobs.get(job_id).expect("job present while committing");
                        self.do_commit(job)
                    };
                    match commit_result {
                        Ok(()) => {
                            let _ = self.worker_report(job_id, WorkerReport::CommitComplete);
                        }
                        Err((code, retryable)) => {
                            let _ = self.worker_report(
                                job_id,
                                WorkerReport::CommitFailed { code, retryable },
                            );
                        }
                    }
                    return;
                }
                TransferJobState::Cancelling => {
                    control.clear_interrupt();
                    let _ = self
                        .worker_report(job_id, WorkerReport::Interrupted(InterruptReason::Cancel));
                    return;
                }
                TransferJobState::Succeeded
                | TransferJobState::Failed { .. }
                | TransferJobState::Cancelled => {
                    return;
                }
            }
        }
    }

    fn run_transfer(&self, job_id: &JobId, control: &Arc<JobControl>) -> TransferOutcome {
        let (device_id, session_id, files, manifest_bytes) = {
            let jobs = self.jobs.lock().unwrap();
            let job = jobs.get(job_id).expect("job present while transferring");
            (
                job.request.device_id.clone(),
                job.request.session_id.clone(),
                job.request.files.clone(),
                job.request.manifest_bytes.clone(),
            )
        };

        let library_root = self.library_root();
        // Derive the revision-scoped hidden root before opening a source or
        // asking it for network bytes. Every `.part`, journal, and verified
        // file for this job therefore lands under the same-filesystem
        // staging tree; the visible session remains untouched until the
        // committing state performs one atomic publication rename.
        let staging = match SessionStaging::for_publication(
            &library_root,
            device_id.as_str(),
            session_id.as_str(),
            &manifest_bytes,
        ) {
            Ok(staging) => staging,
            Err(error) => {
                let error = DownloadError::from(error);
                self.record_fault(CoordinatorFault::new(
                    Some(job_id.clone()),
                    FaultKind::Transition,
                    classify_download_failure(&error),
                    error.to_string(),
                ));
                let (code, retryable) = classify_download_error(&error);
                return TransferOutcome::Failed(code, retryable);
            }
        };
        if let Err(error) = staging.prepare() {
            self.record_fault(CoordinatorFault::new(
                Some(job_id.clone()),
                FaultKind::Transition,
                classify_download_failure(&error),
                error.to_string(),
            ));
            let (code, retryable) = classify_download_error(&error);
            return TransferOutcome::Failed(code, retryable);
        }
        let progress = self.progress_tracker(job_id);
        let mut verified = Vec::new();
        for file in &files {
            if let Some(outcome) = self.pre_file_interrupt_check(job_id, control, &device_id) {
                return outcome;
            }

            let source =
                match self
                    .source_factory
                    .make_source(&device_id, &session_id, &file.file_id)
                {
                    Ok(s) => s,
                    Err(error) => {
                        self.record_fault(CoordinatorFault::new(
                            Some(job_id.clone()),
                            FaultKind::Transition,
                            FailureClass::Remote,
                            error.to_string(),
                        ));
                        return TransferOutcome::Failed(FailureCode::Network, true);
                    }
                };
            let tracking = TrackingSource {
                inner: source,
                control: control.clone(),
                transfer_store: self.transfer_store.clone(),
                job_id: job_id.as_str().to_string(),
                file_id: file.file_id.as_str().to_string(),
                expected_size: file.expected_size,
                expected_sha256_hex: file.expected_sha256_hex.clone(),
                checkpoint_threshold_bytes: self.checkpoint_threshold_bytes,
                progress: progress.clone(),
            };
            let plan = FilePlan {
                device_id: device_id.as_str().to_string(),
                session_id: session_id.as_str().to_string(),
                file_id: file.file_id.as_str().to_string(),
                target_relative_path: file.target_relative_path.clone(),
                expected_size: file.expected_size,
                expected_sha256_hex: file.expected_sha256_hex.clone(),
            };

            match staging.download_into(&tracking, &plan) {
                Ok(vf) => {
                    // `download_into` returning `Ok` is the only proof this
                    // crate accepts that a file is really done: size and
                    // SHA-256 both verified, then atomically renamed into
                    // the hidden revision directory (never the visible
                    // session path).
                    if let Some(progress) = progress.as_ref() {
                        progress.file_completed(file.expected_size);
                    }
                    verified.push(vf);
                }
                Err(e) => {
                    if is_interrupt_error(&e) {
                        return self.interrupt_outcome(control);
                    }
                    self.record_fault(CoordinatorFault::new(
                        Some(job_id.clone()),
                        FaultKind::Transition,
                        classify_download_failure(&e),
                        e.to_string(),
                    ));
                    let (code, retryable) = classify_download_error(&e);
                    return TransferOutcome::Failed(code, retryable);
                }
            }
        }
        TransferOutcome::AllDone(verified)
    }

    fn pre_file_interrupt_check(
        &self,
        job_id: &JobId,
        control: &Arc<JobControl>,
        device_id: &DeviceId,
    ) -> Option<TransferOutcome> {
        if control.interrupt_flag.load(Ordering::SeqCst) {
            return Some(self.interrupt_outcome(control));
        }
        let desired_run_state = self
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .map(|job| job.desired_run_state);
        if desired_run_state == Some(DesiredRunState::Paused) {
            return Some(TransferOutcome::UserPaused);
        }
        match self.readiness(device_id) {
            Readiness::Ready => None,
            Readiness::CapturePaused => Some(TransferOutcome::CapturePaused),
            Readiness::WaitDevice | Readiness::WaitPairing => Some(TransferOutcome::NotReady),
        }
    }

    fn interrupt_outcome(&self, control: &Arc<JobControl>) -> TransferOutcome {
        match control.current_interrupt_reason() {
            Some(InterruptReason::Cancel) => TransferOutcome::Cancelled,
            Some(InterruptReason::CapturePause) => TransferOutcome::CapturePaused,
            Some(InterruptReason::UserPause) => TransferOutcome::UserPaused,
            Some(InterruptReason::DeviceLost) => TransferOutcome::NotReady,
            Some(InterruptReason::Shutdown) => TransferOutcome::Shutdown,
            None => TransferOutcome::Cancelled,
        }
    }

    fn do_commit(&self, job: &ManagedJob) -> Result<(), (FailureCode, bool)> {
        let library_root = self.library_root();
        let staging = match SessionStaging::for_publication(
            &library_root,
            job.request.device_id.as_str(),
            job.request.session_id.as_str(),
            &job.request.manifest_bytes,
        ) {
            Ok(staging) => staging,
            Err(error) => {
                let error = DownloadError::from(error);
                return Err(classify_download_error(&error));
            }
        };
        let plans: Vec<FilePlan> = job
            .request
            .files
            .iter()
            .map(|file| FilePlan {
                device_id: job.request.device_id.as_str().to_string(),
                session_id: job.request.session_id.as_str().to_string(),
                file_id: file.file_id.as_str().to_string(),
                target_relative_path: file.target_relative_path.clone(),
                expected_size: file.expected_size,
                expected_sha256_hex: file.expected_sha256_hex.clone(),
            })
            .collect();
        let manifest = SessionManifest::from_plans(
            job.request.device_id.as_str(),
            job.request.session_id.as_str(),
            &plans,
        );
        match commit_staged_session(
            &staging,
            job.request.device_id.as_str().to_string(),
            job.request.session_id.as_str().to_string(),
            job.verified_files.clone(),
            &manifest,
            PublicationMaterial {
                payload: &job.request.manifest_bytes,
                signature: &job.request.signature,
                public_key: &job.request.publication_public_key,
            },
            self.verifier.as_ref(),
            job.publication_scope,
        ) {
            Ok(_entry) => Ok(()),
            Err(DownloadError::Verification(VerifyError::Rejected(msg))) => Err((
                FailureCode::Other(format!("publication verification failed: {msg}")),
                false,
            )),
            Err(e) => Err(classify_download_error(&e)),
        }
    }

    fn verify_request_publication(&self, request: &TransferRequest) -> Result<(), VerifyError> {
        self.verifier.verify(
            &request.manifest_bytes,
            &request.signature,
            &request.publication_public_key,
        )
    }

    // -------------------------------------------------------------
    // pause / resume / cancel / retry
    // -------------------------------------------------------------

    fn pause(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.apply(job_id, JobCommand::Pause).map(|_| ())
    }

    fn resume(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        self.apply(job_id, JobCommand::Resume).map(|_| ())
    }

    /// Cancel in two serialized phases: enter `cancelling` (and interrupt
    /// any in-flight read), then — once no worker owns the job any more —
    /// finalize to `cancelled`. Both phases go through the same per-job
    /// entry point as the worker's own transitions, so whichever of the
    /// two gets there first wins and the other observes a no-op instead of
    /// attempting a duplicate transition.
    fn cancel(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        match self.apply(job_id, JobCommand::Cancel) {
            Ok(_) => {}
            Err(CoordinatorError::AlreadyTerminal(_))
                if self
                    .jobs
                    .lock()
                    .unwrap()
                    .get(job_id)
                    .map(|job| job.state == TransferJobState::Cancelled)
                    .unwrap_or(false) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        }
        match self.apply(job_id, JobCommand::FinalizeCancel) {
            Ok(_) => Ok(()),
            Err(CoordinatorError::AlreadyTerminal(_))
                if self
                    .jobs
                    .lock()
                    .unwrap()
                    .get(job_id)
                    .map(|job| job.state == TransferJobState::Cancelled)
                    .unwrap_or(false) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn retry(&self, job_id: &JobId) -> Result<JobId, CoordinatorError> {
        let request = self
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .map(|job| job.request.clone());
        // The reducer owns "may this job be retried at all" (only a failed
        // job may); performing `Effect::SpawnRetryJob` is this method's
        // job, because it creates a different job.
        self.apply(job_id, JobCommand::Retry)?;
        let child_id = self.next_job_id();
        let outcome = self
            .transfer_store
            .lock()
            .unwrap()
            .spawn_retry_job(job_id.as_str(), child_id.as_str(), &now_string())
            .map_err(retry_error)?;
        let child = JobId(outcome.job().job_id.clone());
        if !self.jobs.lock().unwrap().contains_key(&child) {
            let spec = self
                .transfer_store
                .lock()
                .unwrap()
                .job_spec(child.as_str())
                .map_err(|error| {
                    CoordinatorError::Persistence(PersistenceError::Conflict {
                        detail: format!("retry child has no usable durable spec: {error}"),
                    })
                })?;
            let request = request.unwrap_or_else(|| request_from_spec(&spec));
            self.rehydrate(
                child.clone(),
                request,
                tag_to_state(outcome.job().state, outcome.job().error.clone()),
                spec.publication_scope(),
                outcome.job().desired_run_state,
                outcome.job().state_version,
            );
        }
        Ok(child)
    }

    fn dismiss(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        if !self.jobs.lock().unwrap().contains_key(job_id) {
            return Err(CoordinatorError::NotFound(job_id.to_string()));
        }
        // Rejects a non-terminal job and waits for any worker to let go —
        // both are reducer-decided effects (`Effect::AwaitWorkerRelease`,
        // `Effect::RemoveJob`); the durable removal below performs the
        // latter.
        self.apply(job_id, JobCommand::Dismiss)?;

        self.transfer_store
            .lock()
            .unwrap()
            .delete_job(job_id.as_str())?;

        self.jobs.lock().unwrap().remove(job_id);
        self.controls.lock().unwrap().remove(job_id);
        self.cells.lock().unwrap().remove(job_id);
        self.progress.lock().unwrap().remove(job_id);
        Ok(())
    }

    fn validate_dismissal(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        let state = self
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .map(|job| job.state.clone())
            .ok_or_else(|| CoordinatorError::NotFound(job_id.to_string()))?;
        if !state.is_terminal() {
            return Err(CoordinatorError::NotTerminal(job_id.to_string()));
        }

        // A visibility tombstone is only legal once the terminal outbox fact
        // is acknowledged.  Otherwise a user action could hide an outcome
        // that the application has not projected yet.
        let completion = self
            .transfer_store
            .lock()
            .unwrap()
            .completion(job_id.as_str())?;
        match completion {
            Some(record) if record.is_acknowledged() => Ok(()),
            Some(_) => Err(CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!("job {job_id} has an unacknowledged terminal outcome"),
            })),
            None => Err(CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!("job {job_id} has no terminal completion outcome"),
            })),
        }
    }

    fn dismiss_runtime(&self, job_id: &JobId) -> Result<(), CoordinatorError> {
        // Re-check immediately before mutating the runtime.  This protects a
        // caller that validated, wrote the tombstone, and then raced another
        // runtime command in between those two boundaries.
        self.validate_dismissal(job_id)?;

        // `Dismiss` only awaits a worker release and emits RemoveJob; it does
        // not itself mutate the durable store.  We intentionally perform the
        // map cleanup below instead of calling `dismiss`, whose final step is
        // the physical durable delete that this API exists to avoid.
        self.apply(job_id, JobCommand::Dismiss)?;

        self.jobs.lock().unwrap().remove(job_id);
        self.controls.lock().unwrap().remove(job_id);
        self.cells.lock().unwrap().remove(job_id);
        self.progress.lock().unwrap().remove(job_id);
        Ok(())
    }

    // -------------------------------------------------------------
    // recovery (see recovery.rs for `TransferCoordinator::recover_on_startup`,
    // which calls this)
    // -------------------------------------------------------------

    pub(super) fn rehydrate(
        &self,
        job_id: JobId,
        request: TransferRequest,
        state: TransferJobState,
        publication_scope: PublicationScope,
        desired: DesiredRunState,
        version: u64,
    ) {
        let should_dispatch = !state.is_terminal();
        self.install_progress(&job_id, &request);
        let managed = ManagedJob {
            job_id: job_id.clone(),
            request,
            state,
            publication_scope,
            desired_run_state: desired,
            verified_files: Vec::new(),
        };
        self.jobs.lock().unwrap().insert(job_id.clone(), managed);
        self.controls
            .lock()
            .unwrap()
            .entry(job_id.clone())
            .or_insert_with(|| Arc::new(JobControl::default()));
        self.cells
            .lock()
            .unwrap()
            .entry(job_id.clone())
            .or_insert_with(|| {
                let cell = Arc::new(JobCell::new());
                cell.version.store(version, Ordering::SeqCst);
                cell
            });
        if should_dispatch && desired == DesiredRunState::Run {
            self.schedule(&job_id);
        }
    }
}

/// Poll `control.active` until it is `false` (a worker has fully released
/// the job) or `timeout` elapses. Returns `true` iff it settled.
fn wait_for_inactive(control: &JobControl, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        if !control.active.load(Ordering::SeqCst) {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Map a reducer refusal onto this module's public error type. An illegal
/// transition keeps the shape callers already handle (the same
/// `Conflict`-flavoured persistence error the durable store used to raise
/// when it re-checked the edge), so refusing *before* touching the
/// database is invisible to callers except in being faster and race-free.
fn reject_error(job_id: &JobId, reason: &RejectReason) -> CoordinatorError {
    match reason {
        RejectReason::AlreadyTerminal => CoordinatorError::AlreadyTerminal(job_id.to_string()),
        RejectReason::NotTerminal => CoordinatorError::NotTerminal(job_id.to_string()),
        RejectReason::NotFailed => CoordinatorError::NotFailed(job_id.to_string()),
        RejectReason::IllegalTransition { from, to } => {
            CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!(
                    "illegal job state transition for {job_id}: {} -> {}",
                    super::aggregate::state_name(from),
                    super::aggregate::state_name(to)
                ),
            })
        }
    }
}

fn retry_error(error: RetryJobError) -> CoordinatorError {
    match error {
        RetryJobError::UnknownJob(job_id) => CoordinatorError::NotFound(job_id),
        RetryJobError::NotRetryable { job_id } => CoordinatorError::NotFailed(job_id),
        RetryJobError::UnacknowledgedParent { job_id } => {
            CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!("retry parent {job_id} has an unacknowledged terminal outcome"),
            })
        }
        RetryJobError::DismissedParent { job_id } => {
            CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!("retry parent {job_id} has been dismissed"),
            })
        }
        RetryJobError::SuccessfulDescendant {
            parent_job_id,
            child_job_id,
        } => CoordinatorError::Persistence(PersistenceError::Conflict {
            detail: format!(
                "upload retry parent {parent_job_id} already has successful child {child_job_id}"
            ),
        }),
        RetryJobError::JobIdCollision { job_id } => {
            CoordinatorError::Persistence(PersistenceError::Conflict {
                detail: format!("retry child id {job_id} is already taken"),
            })
        }
        RetryJobError::Persistence(error) => CoordinatorError::Persistence(error),
    }
}

fn map_complete_job_error(error: CompleteJobError) -> CoordinatorError {
    match error {
        CompleteJobError::Persistence(error) => CoordinatorError::Persistence(error),
        other => CoordinatorError::Persistence(PersistenceError::Conflict {
            detail: other.to_string(),
        }),
    }
}

/// Verify that an execution request is exactly the requested-file projection
/// of the durable spec supplied by composition. The durable spec remains the
/// authority for [`PublicationScope`], including `SelectedFiles`; this check
/// merely prevents a caller from pairing that scope with another session,
/// publication envelope, or file order.
fn validate_request_against_spec(
    request: &TransferRequest,
    spec: &crate::domain::JobSpec,
) -> Result<(), CoordinatorError> {
    let identity = spec.identity();
    if identity.device_id() != &request.device_id
        || identity.session_id() != &request.session_id
        || identity.revision() != request.revision
    {
        return Err(CoordinatorError::Persistence(PersistenceError::Conflict {
            detail: "transfer request identity does not match durable job spec".to_string(),
        }));
    }
    let publication = spec.publication();
    if publication.payload() != request.manifest_bytes.as_slice()
        || publication.signature() != request.signature.as_slice()
        || publication.public_key() != request.publication_public_key.as_slice()
    {
        return Err(CoordinatorError::Persistence(PersistenceError::Conflict {
            detail: "transfer request publication material does not match durable job spec"
                .to_string(),
        }));
    }

    let requested: Vec<_> = spec.requested_files().collect();
    if requested.len() != request.files.len()
        || requested
            .iter()
            .zip(&request.files)
            .any(|(expected, actual)| {
                expected.file_id() != &actual.file_id
                    || expected.display_path()
                        != actual
                            .target_relative_path
                            .as_deref()
                            .unwrap_or_else(|| actual.file_id.as_str())
                    || expected.size_bytes() != actual.expected_size
                    || expected.sha256() != actual.expected_sha256_hex
            })
    {
        return Err(CoordinatorError::Persistence(PersistenceError::Conflict {
            detail: format!(
                "transfer request files do not match durable {} publication scope",
                if spec.publication_scope().is_full_session() {
                    "full-session"
                } else {
                    "selected-files"
                }
            ),
        }));
    }
    Ok(())
}

fn classify_download_error(e: &DownloadError) -> (FailureCode, bool) {
    match e {
        DownloadError::HashMismatch { .. } | DownloadError::SizeMismatch { .. } => {
            (FailureCode::HashMismatch, true)
        }
        DownloadError::SourceIo(_) | DownloadError::Source(_) => (FailureCode::Network, true),
        DownloadError::Io { source, .. } => {
            if source.raw_os_error() == Some(28) {
                // ENOSPC
                (FailureCode::DiskFull, false)
            } else {
                (FailureCode::Network, true)
            }
        }
        DownloadError::RangeNotSatisfiable
        | DownloadError::RangeMismatch { .. }
        | DownloadError::MalformedContentRange(_)
        | DownloadError::UnexpectedStatus(_)
        | DownloadError::UnexpectedExtraBytes
        | DownloadError::ShortBody { .. }
        | DownloadError::TooManyRestarts => (FailureCode::Network, true),
        DownloadError::PathSafety(_)
        | DownloadError::InvalidPlan(_)
        | DownloadError::Checkpoint(_)
        | DownloadError::Serialization(_) => (FailureCode::Other(e.to_string()), false),
        DownloadError::Verification(_) => (FailureCode::Other(e.to_string()), false),
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{self, Read};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex as StdMutex;

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use crate::library::download::{
        AlwaysFailVerifierStub, AlwaysPassVerifierStub, RequestedRange, SourceResponse,
    };
    use crate::library::staging::{REVISION_MARKER_NAME, SELECTED_MARKER_NAME};
    use crate::persistence::JobStateTag;
    use crate::testing::{Deferred, RecordingSink, Rendezvous, DEFAULT_TEST_TIMEOUT};
    use crate::transfer::queue::JobFile;

    // -----------------------------------------------------------------
    // Test fakes
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_stop_serializes_with_waiters_and_cannot_lose_the_wakeup() {
        let signal = Arc::new(StopSignal::new());
        let gate = signal.gate.lock().unwrap();
        let waiting_started = Arc::new(AtomicBool::new(false));
        let waiting = {
            let signal = signal.clone();
            let waiting_started = waiting_started.clone();
            std::thread::spawn(move || {
                waiting_started.store(true, AtomicOrdering::SeqCst);
                signal.wait(Duration::from_secs(3600))
            })
        };
        while !waiting_started.load(AtomicOrdering::SeqCst) {
            std::thread::yield_now();
        }

        // The waiter has passed its fast-path check and is blocked on the
        // gate. A correct stop must publish the predicate under that same
        // gate, so this stopper cannot complete until the waiter is allowed
        // to enter (or release) its condvar wait.
        let started = Arc::new(AtomicBool::new(false));
        let stopper = {
            let signal = signal.clone();
            let started = started.clone();
            std::thread::spawn(move || {
                started.store(true, AtomicOrdering::SeqCst);
                signal.stop();
            })
        };
        while !started.load(AtomicOrdering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::yield_now();
        assert!(!stopper.is_finished(), "stop bypassed the waiter gate");
        drop(gate);

        stopper.join().expect("stopper thread");
        assert!(waiting.join().expect("waiter thread"));
    }

    #[test]
    fn shutdown_wait_ignores_notifications_until_the_stop_predicate_changes() {
        let signal = Arc::new(StopSignal::new());
        let waiting_started = Arc::new(AtomicBool::new(false));
        let waiting = {
            let signal = signal.clone();
            let waiting_started = waiting_started.clone();
            std::thread::spawn(move || {
                waiting_started.store(true, AtomicOrdering::SeqCst);
                signal.wait(Duration::from_secs(30))
            })
        };
        while !waiting_started.load(AtomicOrdering::SeqCst) {
            std::thread::yield_now();
        }

        for _ in 0..10_000 {
            signal.changed.notify_all();
            if waiting.is_finished() {
                break;
            }
            std::thread::yield_now();
        }
        if !waiting.is_finished() {
            signal.stop();
        }

        assert!(
            waiting.join().expect("waiter thread"),
            "a notification without the stop predicate ended the wait"
        );
    }

    #[derive(Default)]
    struct FakeDeviceStatus {
        states: StdMutex<HashMap<String, (ConnectionState, CaptureActivityState)>>,
    }

    impl FakeDeviceStatus {
        fn new() -> Self {
            Self::default()
        }

        fn set(&self, device_id: &DeviceId, conn: ConnectionState, capture: CaptureActivityState) {
            self.states
                .lock()
                .unwrap()
                .insert(device_id.as_str().to_string(), (conn, capture));
        }
    }

    impl DeviceStatusPort for FakeDeviceStatus {
        fn connection_state(&self, device_id: &DeviceId) -> ConnectionState {
            self.states
                .lock()
                .unwrap()
                .get(device_id.as_str())
                .map(|(c, _)| c.clone())
                .unwrap_or(ConnectionState::Connected {
                    connection_id: "conn".to_string(),
                    epoch: 1,
                })
        }

        fn capture_activity(&self, device_id: &DeviceId) -> CaptureActivityState {
            self.states
                .lock()
                .unwrap()
                .get(device_id.as_str())
                .map(|(_, a)| *a)
                .unwrap_or(CaptureActivityState::Idle)
        }
    }

    fn connected_device(device_id: &DeviceId, status: &FakeDeviceStatus) {
        status.set(
            device_id,
            ConnectionState::Connected {
                connection_id: "conn".to_string(),
                epoch: 1,
            },
            CaptureActivityState::Idle,
        );
    }

    /// A `DownloadSource` whose body reads out `chunk_size` bytes at a
    /// time, sleeping `delay` before each read — gives a test's main
    /// thread a real wall-clock window to observe an in-progress transfer
    /// (and call `pause`/`cancel`, or flip a fake device's capture
    /// activity) before the whole file finishes. `opened`/`closed` let a
    /// test prove no file handle is left dangling: `opened` increments
    /// once per `fetch_range` call, `closed` once per body `Drop`.
    struct SlowSource {
        data: Vec<u8>,
        chunk_size: usize,
        delay: std::time::Duration,
        opened: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }

    impl DownloadSource for SlowSource {
        fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            let start = request.start as usize;
            let chunk = self.data[start..].to_vec();
            Ok(SourceResponse {
                status: 200,
                etag: Some("etag-1".to_string()),
                content_range: None,
                content_length: Some(chunk.len() as u64),
                body: Box::new(SlowBody {
                    data: chunk,
                    pos: 0,
                    chunk_size: self.chunk_size.max(1),
                    delay: self.delay,
                    closed: self.closed.clone(),
                }),
            })
        }
    }

    struct SlowBody {
        data: Vec<u8>,
        pos: usize,
        chunk_size: usize,
        delay: std::time::Duration,
        closed: Arc<AtomicUsize>,
    }

    impl Read for SlowBody {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            let n = (self.data.len() - self.pos)
                .min(buf.len())
                .min(self.chunk_size);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl Drop for SlowBody {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TestFactory {
        data: Vec<u8>,
        chunk_size: usize,
        delay: std::time::Duration,
        opened: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }

    impl DownloadSourceFactory for TestFactory {
        fn make_source(
            &self,
            _device_id: &DeviceId,
            _session_id: &SessionId,
            _file_id: &FileId,
        ) -> Result<Box<dyn DownloadSource>, DownloadError> {
            Ok(Box::new(SlowSource {
                data: self.data.clone(),
                chunk_size: self.chunk_size,
                delay: self.delay,
                opened: self.opened.clone(),
                closed: self.closed.clone(),
            }))
        }
    }

    struct PanickingFactory {
        calls: Arc<AtomicUsize>,
    }

    impl DownloadSourceFactory for PanickingFactory {
        fn make_source(
            &self,
            _device_id: &DeviceId,
            _session_id: &SessionId,
            _file_id: &FileId,
        ) -> Result<Box<dyn DownloadSource>, DownloadError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("test source factory panic");
        }
    }

    /// Like [`TestFactory`] but serves a different body per `file_id`, so
    /// a multi-file job's per-file byte accounting can be asserted.
    struct MultiFileFactory {
        files: HashMap<String, Vec<u8>>,
        opened: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }

    impl DownloadSourceFactory for MultiFileFactory {
        fn make_source(
            &self,
            _device_id: &DeviceId,
            _session_id: &SessionId,
            file_id: &FileId,
        ) -> Result<Box<dyn DownloadSource>, DownloadError> {
            let data = self
                .files
                .get(file_id.as_str())
                .cloned()
                .unwrap_or_default();
            Ok(Box::new(SlowSource {
                chunk_size: data.len().max(1),
                data,
                delay: Duration::from_millis(0),
                opened: self.opened.clone(),
                closed: self.closed.clone(),
            }))
        }
    }

    /// Lets a coordinator test stop exactly between per-file verification and
    /// the single session publish rename. Enqueue and `Preparing` each verify
    /// once; the third call is the commit-time authenticity check.
    struct CommitGateVerifier {
        calls: AtomicUsize,
        entered_commit: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    impl PublicationVerifier for CommitGateVerifier {
        fn verify(
            &self,
            _manifest_bytes: &[u8],
            _signature: &[u8],
            _public_key: &[u8],
        ) -> Result<(), VerifyError> {
            if self.calls.fetch_add(1, AtomicOrdering::SeqCst) >= 2 {
                self.entered_commit.store(true, AtomicOrdering::SeqCst);
                while !self.release.load(AtomicOrdering::SeqCst) {
                    thread::yield_now();
                }
            }
            Ok(())
        }
    }

    fn instant_factory(data: Vec<u8>) -> Arc<TestFactory> {
        Arc::new(TestFactory {
            chunk_size: data.len().max(1),
            data,
            delay: Duration::from_millis(0),
            opened: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    fn open_transfer_store(path: &Path) -> Arc<Mutex<TransferStore>> {
        Arc::new(Mutex::new(
            TransferStore::open(path).expect("open transfer store"),
        ))
    }

    fn coordinator_with_store(
        transfer_store: Arc<Mutex<TransferStore>>,
        device_status: Arc<dyn DeviceStatusPort>,
        source_factory: Arc<dyn DownloadSourceFactory>,
        verifier: Arc<dyn PublicationVerifier>,
        config: CoordinatorConfig,
    ) -> TransferCoordinator {
        TransferCoordinator::build(
            transfer_store,
            device_status,
            source_factory,
            verifier,
            config,
        )
    }

    fn test_config(dir: &Path) -> CoordinatorConfig {
        CoordinatorConfig {
            num_workers: 2,
            dispatch_interval: Duration::from_millis(10),
            checkpoint_threshold_bytes: 16,
            library_root: dir.join("library"),
        }
    }

    fn one_file_request(
        device_id: &DeviceId,
        session_id: &str,
        key: &str,
        data: &[u8],
    ) -> TransferRequest {
        TransferRequest {
            device_id: device_id.clone(),
            session_id: SessionId(session_id.to_string()),
            revision: "rev-1".to_string(),
            idempotency_key: key.to_string(),
            files: vec![JobFile {
                file_id: FileId("f1".to_string()),
                target_relative_path: None,
                expected_size: data.len() as u64,
                expected_sha256_hex: sha256_hex(data),
            }],
            // The coordinator now persists a complete JobSpec before it
            // installs runtime state. These deterministic bytes satisfy the
            // spec's structural publication contract; test verifiers decide
            // whether the material is trusted.
            manifest_bytes: vec![0x01],
            signature: vec![0x02; 64],
            publication_public_key: vec![0x03; 32],
        }
    }

    #[test]
    fn idle_coordinator_can_switch_library_root() {
        let dir = tempdir().unwrap();
        let status = Arc::new(FakeDeviceStatus::new());
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(b"unused".to_vec()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let next_root = dir.path().join("next-library");

        coordinator
            .set_library_root_if_idle(next_root.clone())
            .expect("idle coordinator can switch roots");

        assert_eq!(coordinator.library_root(), next_root);
    }

    #[test]
    fn coordinator_rejects_library_root_switch_with_non_terminal_jobs() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(b"download body".to_vec()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let original_root = coordinator.library_root();
        let job_id = coordinator
            .enqueue(one_file_request(
                &device_id,
                "sess-1",
                "root-switch-blocked",
                b"download body",
            ))
            .expect("enqueue job");
        assert!(wait_until(Duration::from_secs(1), || coordinator
            .job_state(&job_id)
            .is_some()));

        let error = coordinator
            .set_library_root_if_idle(dir.path().join("next-library"))
            .expect_err("non-terminal jobs block root switching");

        assert!(error.contains("下载任务未结束"));
        assert_eq!(coordinator.library_root(), original_root);
    }

    fn wait_until<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
        let start = std::time::Instant::now();
        loop {
            if cond() {
                return true;
            }
            if start.elapsed() >= timeout {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    // -----------------------------------------------------------------
    // Happy path: exactly one terminal state (Succeeded)
    // -----------------------------------------------------------------

    #[test]
    fn job_completes_to_succeeded_exactly_once_and_closes_every_opened_source() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = b"hello world, this is some test file content".to_vec();
        let opened = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let factory = Arc::new(TestFactory {
            data: data.clone(),
            chunk_size: data.len(),
            delay: Duration::from_millis(0),
            opened: opened.clone(),
            closed: closed.clone(),
        });

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = one_file_request(&device_id, "sess-1", "job-succeed", &data);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "expected Succeeded, got {:?}",
            coordinator.job_state(&job_id)
        );
        assert_eq!(opened.load(Ordering::SeqCst), closed.load(Ordering::SeqCst));
        assert!(opened.load(Ordering::SeqCst) >= 1);
    }

    // -----------------------------------------------------------------
    // Failure mid-transfer surfaces Failed{code,retryable}, not silently
    // -----------------------------------------------------------------

    #[test]
    fn hash_mismatch_mid_transfer_surfaces_failed_with_code_and_retryable_not_silent() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = b"this file's real bytes".to_vec();
        let factory = instant_factory(data.clone());

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let mut request = one_file_request(&device_id, "sess-1", "job-fail", &data);
        // Corrupt the expected hash so `download_file` reports a hash
        // mismatch mid-transfer (after the body is fully read).
        request.files[0].expected_sha256_hex = "0".repeat(64);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Failed { .. })
            )
        });
        assert!(
            ok,
            "expected Failed, got {:?}",
            coordinator.job_state(&job_id)
        );
        match coordinator.job_state(&job_id) {
            Some(TransferJobState::Failed { code, retryable }) => {
                assert_eq!(code, FailureCode::HashMismatch);
                assert!(retryable);
            }
            other => panic!("expected Failed{{HashMismatch,true}}, got {other:?}"),
        }
        assert!(matches!(
            coordinator.resume(&job_id),
            Err(CoordinatorError::AlreadyTerminal(_))
        ));
        assert_eq!(
            coordinator
                .job_snapshot(&job_id)
                .expect("terminal snapshot")
                .desired_run_state,
            DesiredRunState::Run,
            "a late resume must not publish a durable intent for a terminal job"
        );
    }

    #[test]
    fn retry_child_keeps_parent_context_and_succeeds_after_restart() {
        let dir = tempdir().unwrap();
        let transfer_path = dir.path().join("transfer.sqlite3");
        let device_id = DeviceId("dev-retry-child".to_string());
        let data = b"durable retry child bytes".to_vec();
        let request = one_file_request(&device_id, "sess-retry-child", "retry-parent", &data);
        let parent_id = JobId("retry-parent".to_string());

        // Seed a terminal retryable parent exactly as a previous process
        // would have left it: immutable spec/ledger plus an acknowledged
        // completion outbox row.
        let parent_spec = request.to_job_spec(true, "").expect("build durable spec");
        let parent_ledger = {
            let mut store = TransferStore::open(&transfer_path).expect("open transfer store");
            store
                .create_job(parent_id.as_str(), &parent_spec, "t0")
                .expect("create parent");
            store
                .complete_job(
                    parent_id.as_str(),
                    &TerminalOutcome::Failed {
                        code: "network".to_string(),
                        retryable: true,
                    },
                    "t1",
                )
                .expect("complete retryable parent");
            store
                .acknowledge_completion(parent_id.as_str(), "t2")
                .expect("acknowledge parent");
            store
                .file_ledger(parent_id.as_str())
                .expect("parent ledger")
        };

        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let first = coordinator_with_store(
            open_transfer_store(&transfer_path),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        assert_eq!(
            first.enqueue(request.clone()).expect("rehydrate parent"),
            parent_id
        );
        first
            .recover_on_startup()
            .expect("recover retryable parent before retrying");
        // Stop the first process before asking it to retry. The child is
        // still durably created and queued, but cannot run until the fresh
        // coordinator below recovers it.
        first.shutdown(Duration::from_secs(1));
        let child_id = first.retry(&parent_id).expect("create retry child");
        assert_ne!(child_id, parent_id);

        {
            let store = first.inner.transfer_store.lock().unwrap();
            let parent = store
                .get_job(parent_id.as_str())
                .expect("read parent")
                .expect("parent remains durable");
            let child = store
                .get_job(child_id.as_str())
                .expect("read child")
                .expect("child is durable");
            assert_eq!(parent.state, JobStateTag::Failed);
            assert_eq!(child.state, JobStateTag::Queued);
            assert_eq!(
                store.job_spec(child_id.as_str()).unwrap(),
                parent_spec.clone()
            );
            let child_ledger = store.file_ledger(child_id.as_str()).expect("child ledger");
            assert_eq!(child_ledger.len(), parent_ledger.len());
            for (child_file, parent_file) in child_ledger.iter().zip(&parent_ledger) {
                assert_eq!(child_file.file_id, parent_file.file_id);
                assert_eq!(child_file.status, parent_file.status);
                assert_eq!(child_file.bytes_confirmed, parent_file.bytes_confirmed);
                assert_eq!(child_file.verified_sha256, parent_file.verified_sha256);
            }
            assert_eq!(
                store
                    .retry_parent(child_id.as_str())
                    .expect("read retry lineage")
                    .expect("child lineage")
                    .parent_job_id,
                parent_id.as_str()
            );
            assert_eq!(store.count_jobs().unwrap(), 2);
        }
        drop(first);

        // A fresh coordinator sees only SQLite, rehydrates the queued child,
        // and can complete it without any process-local retry map.
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let second = coordinator_with_store(
            open_transfer_store(&transfer_path),
            status,
            instant_factory(data),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let recovered = second
            .recover_on_startup()
            .expect("recover retry child after restart");
        assert_eq!(recovered, vec![child_id.clone()]);
        assert!(wait_until(Duration::from_secs(5), || matches!(
            second.job_state(&child_id),
            Some(TransferJobState::Succeeded)
        )));
    }

    #[test]
    fn worker_panic_records_fault_releases_lease_and_converges_to_failed() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-panic".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let calls = Arc::new(AtomicUsize::new(0));
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            Arc::new(PanickingFactory {
                calls: calls.clone(),
            }),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let job_id = coordinator
            .enqueue(one_file_request(
                &device_id,
                "sess-panic",
                "panic-key",
                b"panic body",
            ))
            .expect("enqueue");

        assert!(wait_until(Duration::from_secs(5), || matches!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Failed {
                code: FailureCode::Other(_),
                retryable: false,
            })
        )));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let faults = coordinator.faults();
        assert!(faults.iter().any(|fault| {
            fault.job_id.as_ref() == Some(&job_id)
                && fault.kind == FaultKind::WorkerPanic
                && fault.detail.contains("test source factory panic")
        }));
        let terminal_version = coordinator
            .job_snapshot(&job_id)
            .expect("terminal snapshot")
            .version;
        assert!(matches!(
            coordinator.command_if_unchanged(
                &job_id,
                terminal_version,
                JobCommand::Worker(WorkerReport::WorkerPanicked {
                    detail: "late panic".to_string(),
                })
            ),
            Err(CoordinatorError::AlreadyTerminal(_))
        ));
        let control = coordinator
            .inner
            .controls
            .lock()
            .unwrap()
            .get(&job_id)
            .cloned()
            .expect("control remains observable for terminal job");
        assert!(!control.active.load(Ordering::SeqCst));
        let stored = coordinator
            .inner
            .transfer_store
            .lock()
            .unwrap()
            .get_job(job_id.as_str())
            .expect("read durable state")
            .expect("durable row");
        assert_eq!(stored.state, JobStateTag::Failed);
    }

    #[test]
    fn shutdown_deadline_reports_uncooperative_worker_without_hanging() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-shutdown".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let gate = Deferred::new();
        let opened: RecordingSink<()> = RecordingSink::new();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            Arc::new(GatedFactory {
                data: b"blocked".to_vec(),
                gate: gate.clone(),
                opened: opened.clone(),
            }),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        coordinator
            .enqueue(one_file_request(
                &device_id,
                "sess-shutdown",
                "shutdown-key",
                b"blocked",
            ))
            .expect("enqueue");
        assert!(opened.wait_for(1, DEFAULT_TEST_TIMEOUT));

        let start = Instant::now();
        let report = coordinator.shutdown(Duration::from_millis(20));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(
            !report.completed,
            "an uncooperative worker must be reported at the deadline: {report:?}"
        );
        assert_eq!(report.workers_remaining, 1);
        assert!(!report.dispatcher_remaining);

        // Release the gated body so the detached worker can finish cleanly;
        // the explicit shutdown above already drained owned handles.
        gate.release(());
    }

    #[test]
    fn dismissing_a_failed_job_removes_the_durable_transfer_row_and_progress() {
        let dir = tempdir().unwrap();
        let transfer_path = dir.path().join("transfer.sqlite3");
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"bytes with a deliberately wrong expected hash".to_vec();
        let transfer_store = open_transfer_store(&transfer_path);
        let coordinator = coordinator_with_store(
            transfer_store.clone(),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let mut request = one_file_request(&device_id, "sess-1", "dismiss-key", &data);
        request.files[0].expected_sha256_hex = "0".repeat(64);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        assert!(wait_until(Duration::from_secs(5), || matches!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Failed { .. })
        )));

        transfer_store
            .lock()
            .unwrap()
            .acknowledge_completion(job_id.as_str(), "t-ack")
            .expect("acknowledge failed outcome before dismissal");

        coordinator
            .dismiss(&job_id)
            .expect("a terminal failed job can be dismissed");

        assert_eq!(coordinator.job_state(&job_id), None);
        assert_eq!(coordinator.job_progress(&job_id), None);
        assert!(!coordinator.job_ids().contains(&job_id));

        drop(coordinator);
        let reopened = TransferStore::open(&transfer_path).expect("reopen transfer store");
        assert!(reopened.get_job(job_id.as_str()).unwrap().is_none());
        assert!(reopened.completion(job_id.as_str()).unwrap().is_none());
    }

    #[test]
    fn runtime_dismissal_keeps_acknowledged_durable_history_for_tombstone_projection() {
        let dir = tempdir().unwrap();
        let transfer_path = dir.path().join("transfer.sqlite3");
        let device_id = DeviceId("dev-runtime-dismiss".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"runtime dismissal bytes".to_vec();
        let transfer_store = open_transfer_store(&transfer_path);
        let coordinator = coordinator_with_store(
            transfer_store.clone(),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let mut request = one_file_request(
            &device_id,
            "sess-runtime-dismiss",
            "runtime-dismiss-key",
            &data,
        );
        request.files[0].expected_sha256_hex = "0".repeat(64);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        assert!(wait_until(Duration::from_secs(5), || matches!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Failed { .. })
        )));
        transfer_store
            .lock()
            .unwrap()
            .acknowledge_completion(job_id.as_str(), "t-runtime-ack")
            .expect("acknowledge failed outcome");

        coordinator
            .validate_dismissal(&job_id)
            .expect("terminal acknowledged job validates");
        transfer_store
            .lock()
            .unwrap()
            .dismiss_job(job_id.as_str(), "t-runtime-dismiss")
            .expect("durable tombstone");
        coordinator
            .dismiss_runtime(&job_id)
            .expect("runtime-only cleanup");
        assert_eq!(coordinator.job_state(&job_id), None);
        assert_eq!(coordinator.job_progress(&job_id), None);

        let reopened = TransferStore::open(&transfer_path).expect("reopen transfer store");
        let stored = reopened
            .get_job(job_id.as_str())
            .expect("read tombstoned row")
            .expect("tombstone retains job history");
        assert_eq!(stored.dismissed_at.as_deref(), Some("t-runtime-dismiss"));
        assert!(reopened.completion(job_id.as_str()).unwrap().is_some());
        assert!(reopened.job_spec(job_id.as_str()).is_ok());
    }

    #[test]
    fn dismiss_rejects_a_non_terminal_job_without_removing_it() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-offline".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        status.set(
            &device_id,
            ConnectionState::Disconnected,
            CaptureActivityState::Idle,
        );
        let data = b"must remain queued".to_vec();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let job_id = coordinator
            .enqueue(one_file_request(
                &device_id,
                "sess-queued",
                "queued-key",
                &data,
            ))
            .expect("enqueue");

        let error = coordinator
            .dismiss(&job_id)
            .expect_err("an active job must be cancelled before dismissal");

        assert!(matches!(error, CoordinatorError::NotTerminal(_)));
        assert!(coordinator.job_state(&job_id).is_some());
        assert!(coordinator.job_ids().contains(&job_id));
    }

    // -----------------------------------------------------------------
    // Cancel mid-transfer waits for the handle to close before Cancelled
    // -----------------------------------------------------------------

    #[test]
    fn cancel_mid_transfer_waits_for_source_to_close_before_marking_cancelled() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = vec![7u8; 400];
        let opened = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let factory = Arc::new(TestFactory {
            data: data.clone(),
            chunk_size: 8,
            delay: Duration::from_millis(15),
            opened: opened.clone(),
            closed: closed.clone(),
        });

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = one_file_request(&device_id, "sess-1", "job-cancel", &data);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        let started = wait_until(Duration::from_secs(2), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Transferring)
            ) && opened.load(Ordering::SeqCst) >= 1
        });
        assert!(
            started,
            "expected job to reach Transferring with a source opened"
        );
        // Let a couple of chunks actually get read before cancelling.
        thread::sleep(Duration::from_millis(40));

        coordinator.cancel(&job_id).expect("cancel");

        assert_eq!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Cancelled)
        );
        assert_eq!(
            opened.load(Ordering::SeqCst),
            closed.load(Ordering::SeqCst),
            "every opened source body must have been closed by the time cancel() returns"
        );
        assert!(opened.load(Ordering::SeqCst) >= 1);
    }

    // -----------------------------------------------------------------
    // Capture-active pause: stream closes before the state transition is
    // observable, and the job resumes once activity returns to idle.
    // -----------------------------------------------------------------

    #[test]
    fn capture_active_pause_closes_stream_before_transitioning_then_resumes() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = vec![9u8; 400];
        let opened = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let factory = Arc::new(TestFactory {
            data: data.clone(),
            chunk_size: 8,
            delay: Duration::from_millis(15),
            opened: opened.clone(),
            closed: closed.clone(),
        });

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status.clone(),
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = one_file_request(&device_id, "sess-1", "job-capture-pause", &data);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        let started = wait_until(Duration::from_secs(2), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Transferring)
            ) && opened.load(Ordering::SeqCst) >= 1
        });
        assert!(
            started,
            "expected job to reach Transferring with a source opened"
        );
        thread::sleep(Duration::from_millis(40));

        // Capture starts recording on this device mid-transfer.
        status.set(
            &device_id,
            ConnectionState::Connected {
                connection_id: "conn".into(),
                epoch: 1,
            },
            CaptureActivityState::Recording,
        );

        let paused = wait_until(Duration::from_secs(2), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::PausedCaptureActive)
            )
        });
        assert!(
            paused,
            "expected PausedCaptureActive, got {:?}",
            coordinator.job_state(&job_id)
        );
        // By construction (`download_file` always drops its `.part`
        // handle before returning, on every path — see `library::
        // download`'s own doc comment — and `process_job` only calls
        // `transition()` to `paused_capture_active` after `run_transfer`
        // returns), observing the state transition here proves the
        // stream already closed.
        assert_eq!(
            opened.load(Ordering::SeqCst),
            closed.load(Ordering::SeqCst),
            "the interrupted source's body must already be closed by the time paused_capture_active is observable"
        );
        let opened_before_resume = opened.load(Ordering::SeqCst);
        assert!(opened_before_resume >= 1);

        // Capture goes back to idle -- the job must resume on its own
        // (the background dispatcher re-checks readiness periodically).
        connected_device(&device_id, &status);

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "expected job to resume and reach Succeeded, got {:?}",
            coordinator.job_state(&job_id)
        );
        assert_eq!(opened.load(Ordering::SeqCst), closed.load(Ordering::SeqCst));
    }

    #[test]
    fn coordinator_keeps_every_file_invisible_until_commit_publishes_the_session() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"staged-only-until-commit".to_vec();
        let entered_commit = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let verifier = Arc::new(CommitGateVerifier {
            calls: AtomicUsize::new(0),
            entered_commit: entered_commit.clone(),
            release: release.clone(),
        });
        let config = test_config(dir.path());
        let library_root = config.library_root.clone();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(data.clone()),
            verifier,
            config,
        );
        let job_id = coordinator
            .enqueue(one_file_request(
                &device_id,
                "sess-1",
                "staged-visibility",
                &data,
            ))
            .expect("enqueue job");

        assert!(wait_until(Duration::from_secs(3), || {
            entered_commit.load(AtomicOrdering::SeqCst)
        }));
        let visible_session = library_root.join("dev-1").join("sess-1");
        assert!(
            !visible_session.exists(),
            "visible session must not exist while commit authenticity is gated"
        );
        let staging = SessionStaging::for_publication(&library_root, "dev-1", "sess-1", &[0x01])
            .expect("test publication staging");
        assert!(
            staging.revision_dir().join("f1").exists(),
            "verified file must be present in hidden staging before publish"
        );

        release.store(true, AtomicOrdering::SeqCst);
        assert!(wait_until(Duration::from_secs(3), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        }));
        assert!(visible_session.join("f1").is_file());
        assert!(visible_session.join(".ylx-revision").is_file());
        assert!(!staging.staging_root().exists());
    }

    // -----------------------------------------------------------------
    // Two devices are fair/independent: one offline does not block the
    // other's jobs.
    // -----------------------------------------------------------------

    #[test]
    fn two_devices_are_independent_offline_device_does_not_block_the_other() {
        let dir = tempdir().unwrap();
        let offline = DeviceId("dev-offline".to_string());
        let online = DeviceId("dev-online".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        status.set(
            &offline,
            ConnectionState::Disconnected,
            CaptureActivityState::Unknown,
        );
        connected_device(&online, &status);

        let data = b"small file content".to_vec();
        let factory = instant_factory(data.clone());

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let offline_req = one_file_request(&offline, "sess-a", "job-offline", &data);
        let online_req = one_file_request(&online, "sess-b", "job-online", &data);
        let offline_id = coordinator.enqueue(offline_req).expect("enqueue offline");
        let online_id = coordinator.enqueue(online_req).expect("enqueue online");

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&online_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "online device's job should succeed even though the other device is offline, got {:?}",
            coordinator.job_state(&online_id)
        );
        assert_eq!(
            coordinator.job_state(&offline_id),
            Some(TransferJobState::WaitingForDevice)
        );
    }

    #[test]
    fn selected_spec_commits_requested_file_without_replacing_session_siblings() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"selected file body".to_vec();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = one_file_request(&device_id, "sess-selected", "selected-key", &data);
        let spec = request
            .to_job_spec(false, "2026-08-01")
            .expect("selected durable spec");
        let session_dir = coordinator
            .library_root()
            .join(device_id.as_str())
            .join("sess-selected");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("sibling-before-job"), b"keep this sibling").unwrap();

        let job_id = coordinator
            .enqueue_with_spec(request, spec)
            .expect("selected enqueue");
        assert!(wait_until(Duration::from_secs(5), || matches!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Succeeded)
        )));

        assert_eq!(
            fs::read(session_dir.join("sibling-before-job")).unwrap(),
            b"keep this sibling"
        );
        assert_eq!(fs::read(session_dir.join("f1")).unwrap(), data);
        assert!(session_dir.join(SELECTED_MARKER_NAME).is_file());
        assert!(
            !session_dir.join(REVISION_MARKER_NAME).exists(),
            "selected publication must not claim a whole session"
        );
    }

    // -----------------------------------------------------------------
    // Duplicate enqueue with the same idempotency key
    // -----------------------------------------------------------------

    #[test]
    fn duplicate_enqueue_with_same_idempotency_key_returns_the_existing_job_id() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = b"dedup me".to_vec();
        let factory = instant_factory(data.clone());

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request_a = one_file_request(&device_id, "sess-1", "shared-key", &data);
        let request_b = one_file_request(&device_id, "sess-1", "shared-key", &data);

        let id_a = coordinator.enqueue(request_a).expect("first enqueue");
        let id_b = coordinator
            .enqueue(request_b)
            .expect("second (duplicate) enqueue");

        assert_eq!(id_a, id_b);
        assert_eq!(coordinator.job_ids().len(), 1);
    }

    #[test]
    fn enqueue_with_spec_rejects_a_request_projection_mismatch_before_persisting() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"durable projection".to_vec();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let request = one_file_request(&device_id, "sess-1", "spec-mismatch", &data);
        let spec = request
            .to_job_spec(false, "2026-08-01")
            .expect("selected durable spec");

        let mut bad_files = request.clone();
        bad_files.files[0].expected_size += 1;
        assert!(matches!(
            coordinator.enqueue_with_spec(bad_files, spec.clone()),
            Err(CoordinatorError::Persistence(
                PersistenceError::Conflict { .. }
            ))
        ));
        assert!(coordinator.job_ids().is_empty());

        let mut bad_publication = request;
        bad_publication.manifest_bytes = vec![9];
        assert!(matches!(
            coordinator.enqueue_with_spec(bad_publication, spec),
            Err(CoordinatorError::Persistence(
                PersistenceError::Conflict { .. }
            ))
        ));
        assert!(coordinator.job_ids().is_empty());
    }

    #[test]
    fn enqueue_rejects_invalid_publication_before_persisting_or_opening_a_source() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let data = b"must never be downloaded".to_vec();
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let factory = instant_factory(data.clone());
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory.clone(),
            Arc::new(AlwaysFailVerifierStub("invalid publication".to_string())),
            test_config(dir.path()),
        );

        let error = coordinator
            .enqueue(one_file_request(
                &device_id,
                "sess-untrusted",
                "job-untrusted",
                &data,
            ))
            .expect_err("an unauthenticated request must be rejected synchronously");

        assert!(matches!(error, CoordinatorError::Verification(_)));
        assert!(coordinator.job_ids().is_empty());
        assert_eq!(factory.opened.load(Ordering::SeqCst), 0);
    }

    // -----------------------------------------------------------------
    // Restart: a fresh TransferCoordinator + recover_on_startup() against
    // the same TransferStore resumes a job that was `transferring`.
    // -----------------------------------------------------------------

    #[test]
    fn restart_resumes_a_job_that_was_transferring_when_interrupted() {
        let dir = tempdir().unwrap();
        let transfer_path = dir.path().join("transfer.sqlite3");

        let device_id = DeviceId("dev-1".to_string());
        let data = b"restart test file content bytes".to_vec();
        let request = one_file_request(&device_id, "sess-1", "job-restart", &data);
        let job_id = JobId("job-restart".to_string());

        // Simulate a previous process that durably enqueued this job and
        // got partway into `transferring` before dying — never reaching a
        // terminal state or `retry_wait`.
        {
            let mut store = TransferStore::open(&transfer_path).expect("open transfer store");
            let spec = request.to_job_spec(true, "").expect("build durable spec");
            store
                .create_job(job_id.as_str(), &spec, "t0")
                .expect("create durable job");
            store
                .transition_job(job_id.as_str(), 1, JobStateTag::Preparing, None, "t1")
                .expect("-> preparing");
            store
                .transition_job(job_id.as_str(), 2, JobStateTag::Transferring, None, "t2")
                .expect("-> transferring");
            assert_eq!(store.job_spec(job_id.as_str()).expect("spec"), spec);
            assert_eq!(store.file_ledger(job_id.as_str()).expect("ledger").len(), 1);
            // Dropping the store models the previous process exiting after
            // its durable state/spec/ledger commit.
        }

        // Restart: a fresh coordinator against the same durable files.
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let factory = instant_factory(data.clone());
        let coordinator = coordinator_with_store(
            open_transfer_store(&transfer_path),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let rehydrated = coordinator
            .recover_on_startup()
            .expect("recover_on_startup");
        assert_eq!(rehydrated, vec![job_id.clone()]);
        assert_eq!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Transferring)
        );

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "expected the resumed job to reach Succeeded, got {:?}",
            coordinator.job_state(&job_id)
        );
    }

    // -----------------------------------------------------------------
    // TransferJobState<->JobStateTag bridging sanity check at the
    // coordinator level (the exhaustive round-trip lives in queue.rs;
    // this proves the coordinator actually persists through it).
    // -----------------------------------------------------------------

    #[test]
    fn every_transition_the_happy_path_makes_is_durably_persisted() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"durability check".to_vec();
        let factory = instant_factory(data.clone());

        let transfer_path = dir.path().join("transfer.sqlite3");
        let coordinator = coordinator_with_store(
            open_transfer_store(&transfer_path),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let request = one_file_request(&device_id, "sess-1", "job-durable", &data);
        let job_id = coordinator.enqueue(request).expect("enqueue");
        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(ok);

        // Read the transfer authority back directly (bypassing the
        // coordinator's in-memory cache) to prove both the terminal row and
        // its completion outcome are durable.
        let readback = TransferStore::open(&transfer_path).expect("reopen transfer store");
        let record = readback
            .get_job(job_id.as_str())
            .unwrap()
            .expect("row exists");
        assert_eq!(record.state, JobStateTag::Succeeded);
        assert!(record.error.is_none());
        assert!(matches!(
            readback
                .completion(job_id.as_str())
                .unwrap()
                .map(|row| row.outcome),
            Some(TerminalOutcome::Succeeded)
        ));
    }

    // -----------------------------------------------------------------
    // Byte-level progress (`job_progress`) — see `transfer::progress`
    // -----------------------------------------------------------------

    fn multi_file_request(
        device_id: &DeviceId,
        session_id: &str,
        key: &str,
        files: &[(&str, Vec<u8>)],
    ) -> TransferRequest {
        TransferRequest {
            device_id: device_id.clone(),
            session_id: SessionId(session_id.to_string()),
            revision: "rev-1".to_string(),
            idempotency_key: key.to_string(),
            files: files
                .iter()
                .map(|(id, data)| JobFile {
                    file_id: FileId((*id).to_string()),
                    target_relative_path: None,
                    expected_size: data.len() as u64,
                    expected_sha256_hex: sha256_hex(data),
                })
                .collect(),
            manifest_bytes: vec![0x01],
            signature: vec![0x02; 64],
            publication_public_key: vec![0x03; 32],
        }
    }

    #[test]
    fn job_progress_is_none_for_an_unknown_job() {
        let dir = tempdir().unwrap();
        let status = Arc::new(FakeDeviceStatus::new());
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(b"unused".to_vec()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        assert_eq!(coordinator.job_progress(&JobId("no-such-job".into())), None);
    }

    #[test]
    fn multi_file_job_accumulates_bytes_across_files_and_ends_at_exactly_total() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let files = vec![
            ("f1", vec![1u8; 100]),
            ("f2", vec![2u8; 250]),
            ("f3", vec![3u8; 40]),
        ];
        let factory = Arc::new(MultiFileFactory {
            files: files
                .iter()
                .map(|(id, data)| ((*id).to_string(), data.clone()))
                .collect(),
            opened: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicUsize::new(0)),
        });

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = multi_file_request(&device_id, "sess-1", "job-progress-multi", &files);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        // Totals are known the moment the job is enqueued, before any
        // byte moves.
        let at_enqueue = coordinator.job_progress(&job_id).expect("progress exists");
        assert_eq!(at_enqueue.total_bytes, 390);
        assert_eq!(at_enqueue.files_total, 3);

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "expected Succeeded, got {:?}",
            coordinator.job_state(&job_id)
        );

        assert_eq!(
            coordinator.job_progress(&job_id),
            Some(JobProgress {
                total_bytes: 390,
                transferred_bytes: 390,
                files_total: 3,
                files_done: 3,
            })
        );
    }

    #[test]
    fn a_resumable_partial_on_disk_is_counted_at_enqueue_instead_of_starting_from_zero() {
        use crate::library::download::{journal_path, part_path, DownloadJournal};

        let dir = tempdir().unwrap();
        let config = test_config(dir.path());
        let library_root = config.library_root.clone();
        let device_id = DeviceId("dev-1".to_string());

        // Device is offline, so the job parks in `waiting_for_device` and
        // nothing downloads — progress can only come from the disk scan.
        let status = Arc::new(FakeDeviceStatus::new());
        status.set(
            &device_id,
            ConnectionState::Disconnected,
            CaptureActivityState::Unknown,
        );

        let f1 = vec![1u8; 100];
        let f2 = vec![2u8; 200];
        let files = vec![("f1", f1.clone()), ("f2", f2.clone())];

        // f1: already fully committed by a previous run.
        let session_dir = library_root.join("dev-1").join("sess-1");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("f1"), &f1).unwrap();
        // f2: 150 bytes written, but only 128 durably checkpointed —
        // `download_file` will resume from 128, so that (not 150) is the
        // honest baseline.
        let f2_target = session_dir.join("f2");
        std::fs::write(part_path(&f2_target), &f2[..150]).unwrap();
        DownloadJournal::write(
            &journal_path(&f2_target),
            &DownloadJournal {
                confirmed_offset: 128,
                expected_size: 200,
                expected_sha256_hex: sha256_hex(&f2),
                etag: None,
            },
        )
        .unwrap();

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            Arc::new(MultiFileFactory {
                files: files
                    .iter()
                    .map(|(id, data)| ((*id).to_string(), data.clone()))
                    .collect(),
                opened: Arc::new(AtomicUsize::new(0)),
                closed: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(AlwaysPassVerifierStub),
            config,
        );

        let request = multi_file_request(&device_id, "sess-1", "job-progress-resume", &files);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        assert_eq!(
            coordinator.job_progress(&job_id),
            Some(JobProgress {
                total_bytes: 300,
                transferred_bytes: 228, // 100 committed + 128 confirmed
                files_total: 2,
                files_done: 1,
            }),
            "a recovered/partial job must not restart its byte count at zero"
        );
    }

    #[test]
    fn progress_never_regresses_across_pause_resume_and_ends_complete() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = vec![7u8; 400];
        let factory = Arc::new(TestFactory {
            data: data.clone(),
            chunk_size: 8,
            delay: Duration::from_millis(10),
            opened: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicUsize::new(0)),
        });

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = one_file_request(&device_id, "sess-1", "job-progress-pause", &data);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        let started = wait_until(Duration::from_secs(3), || {
            coordinator
                .job_progress(&job_id)
                .is_some_and(|p| p.transferred_bytes > 0)
        });
        assert!(started, "expected some bytes to be reported in flight");

        let before_pause = coordinator.job_progress(&job_id).unwrap();
        coordinator.pause(&job_id).expect("pause");
        let after_pause = coordinator.job_progress(&job_id).unwrap();
        assert!(
            after_pause.transferred_bytes >= before_pause.transferred_bytes,
            "pause must not clear progress: {before_pause:?} -> {after_pause:?}"
        );
        assert!(after_pause.transferred_bytes > 0);
        assert_eq!(after_pause.total_bytes, 400);

        // The interrupted attempt never checkpointed its sidecar journal,
        // so `download_file` will restart this file from byte 0 on resume
        // — the reported value must plateau, never drop back down.
        coordinator.resume(&job_id).expect("resume");
        let highest = AtomicU64::new(after_pause.transferred_bytes);
        let done = wait_until(Duration::from_secs(10), || {
            let p = coordinator.job_progress(&job_id).unwrap();
            let seen = highest.fetch_max(p.transferred_bytes, Ordering::SeqCst);
            assert!(
                p.transferred_bytes >= seen,
                "progress went backwards after resume: {seen} -> {}",
                p.transferred_bytes
            );
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(done, "expected the resumed job to finish");

        assert_eq!(
            coordinator.job_progress(&job_id),
            Some(JobProgress {
                total_bytes: 400,
                transferred_bytes: 400,
                files_total: 1,
                files_done: 1,
            })
        );
    }

    #[test]
    fn a_cancelled_job_keeps_its_progress_readable_and_unzeroed() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = vec![5u8; 400];
        let factory = Arc::new(TestFactory {
            data: data.clone(),
            chunk_size: 8,
            delay: Duration::from_millis(10),
            opened: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicUsize::new(0)),
        });

        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            factory,
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        let request = one_file_request(&device_id, "sess-1", "job-progress-cancel", &data);
        let job_id = coordinator.enqueue(request).expect("enqueue");

        let started = wait_until(Duration::from_secs(3), || {
            coordinator
                .job_progress(&job_id)
                .is_some_and(|p| p.transferred_bytes > 0)
        });
        assert!(started, "expected some bytes to be reported in flight");
        let before_cancel = coordinator.job_progress(&job_id).unwrap();

        coordinator.cancel(&job_id).expect("cancel");
        assert_eq!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Cancelled)
        );

        let after_cancel = coordinator.job_progress(&job_id).expect("still readable");
        assert!(after_cancel.transferred_bytes >= before_cancel.transferred_bytes);
        assert!(after_cancel.transferred_bytes < after_cancel.total_bytes);
        assert_eq!(after_cancel.files_done, 0);
    }

    #[test]
    fn a_recovered_job_reports_its_totals_and_finishes_at_exactly_total() {
        let dir = tempdir().unwrap();
        let transfer_path = dir.path().join("transfer.sqlite3");
        let device_id = DeviceId("dev-1".to_string());
        let data = b"recovered job progress bytes".to_vec();
        let request = one_file_request(&device_id, "sess-1", "job-recover-progress", &data);
        let job_id = JobId("job-recover-progress".to_string());

        {
            let mut store = TransferStore::open(&transfer_path).expect("open transfer store");
            let spec = request.to_job_spec(true, "").expect("build durable spec");
            store
                .create_job(job_id.as_str(), &spec, "t0")
                .expect("create durable job");
            store
                .transition_job(job_id.as_str(), 1, JobStateTag::Preparing, None, "t1")
                .expect("-> preparing");
            store
                .transition_job(job_id.as_str(), 2, JobStateTag::Transferring, None, "t2")
                .expect("-> transferring");
            assert_eq!(store.file_ledger(job_id.as_str()).expect("ledger").len(), 1);
        }

        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let coordinator = coordinator_with_store(
            open_transfer_store(&transfer_path),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        assert_eq!(coordinator.job_progress(&job_id), None);
        coordinator
            .recover_on_startup()
            .expect("recover_on_startup");

        let recovered = coordinator
            .job_progress(&job_id)
            .expect("progress after recovery");
        assert_eq!(recovered.total_bytes, data.len() as u64);
        assert_eq!(recovered.files_total, 1);

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(ok, "expected the resumed job to reach Succeeded");
        assert_eq!(
            coordinator.job_progress(&job_id),
            Some(JobProgress {
                total_bytes: data.len() as u64,
                transferred_bytes: data.len() as u64,
                files_total: 1,
                files_done: 1,
            })
        );
    }

    // -----------------------------------------------------------------
    // Commits 39–41: one serialized owner per job, expected-version CAS,
    // atomic snapshots, one lease per target.
    // -----------------------------------------------------------------

    /// A source whose body blocks on a [`Deferred`] before it yields its
    /// first byte, so a test can hold a worker *inside* `download_file`
    /// with no sleeping and release it on demand.
    struct GatedFactory {
        data: Vec<u8>,
        gate: Deferred<()>,
        opened: RecordingSink<()>,
    }

    impl DownloadSourceFactory for GatedFactory {
        fn make_source(
            &self,
            _device_id: &DeviceId,
            _session_id: &SessionId,
            _file_id: &FileId,
        ) -> Result<Box<dyn DownloadSource>, DownloadError> {
            Ok(Box::new(GatedSource {
                data: self.data.clone(),
                gate: self.gate.clone(),
                opened: self.opened.clone(),
            }))
        }
    }

    struct GatedSource {
        data: Vec<u8>,
        gate: Deferred<()>,
        opened: RecordingSink<()>,
    }

    impl DownloadSource for GatedSource {
        fn fetch_range(&self, _request: RequestedRange) -> Result<SourceResponse, DownloadError> {
            Ok(SourceResponse {
                status: 200,
                etag: None,
                content_range: None,
                content_length: Some(self.data.len() as u64),
                body: Box::new(GatedBody {
                    data: self.data.clone(),
                    pos: 0,
                    gate: self.gate.clone(),
                    opened: self.opened.clone(),
                }),
            })
        }
    }

    struct GatedBody {
        data: Vec<u8>,
        pos: usize,
        gate: Deferred<()>,
        opened: RecordingSink<()>,
    }

    impl Read for GatedBody {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos == 0 {
                self.opened.emit(());
                self.gate.get_timeout(DEFAULT_TEST_TIMEOUT);
            }
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    /// Enqueue a job for a device that is reported offline, and wait until
    /// it has parked in `waiting_for_device`; then pause it, so nothing
    /// but the test itself can move it any more.
    fn parked_job(
        coordinator: &TransferCoordinator,
        device_id: &DeviceId,
        session: &str,
        key: &str,
        data: &[u8],
    ) -> JobId {
        let job_id = coordinator
            .enqueue(one_file_request(device_id, session, key, data))
            .expect("enqueue");
        assert!(wait_until(DEFAULT_TEST_TIMEOUT, || matches!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::WaitingForDevice)
        )));
        coordinator.pause(&job_id).expect("pause the parked job");
        job_id
    }

    #[test]
    fn paused_desired_run_state_survives_coordinator_restart_without_dispatch() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-restart-pause".to_string());
        let transfer_path = dir.path().join("transfer.sqlite3");

        let first = offline_coordinator(dir.path(), &device_id);
        let job_id = parked_job(
            &first,
            &device_id,
            "sess-restart-pause",
            "restart-pause-key",
            b"parked",
        );
        let paused = first.job_snapshot(&job_id).expect("paused snapshot");
        assert_eq!(paused.desired_run_state, DesiredRunState::Paused);
        assert_eq!(paused.state, TransferJobState::WaitingForDevice);
        first.shutdown(Duration::from_secs(1));
        drop(first);

        let second = offline_coordinator(dir.path(), &device_id);
        let recovered = second.recover_on_startup().expect("recover paused job");
        assert_eq!(recovered, vec![job_id.clone()]);
        let recovered_snapshot = second.job_snapshot(&job_id).expect("recovered snapshot");
        assert_eq!(
            recovered_snapshot.desired_run_state,
            DesiredRunState::Paused
        );
        assert_eq!(recovered_snapshot.state, TransferJobState::WaitingForDevice);
        thread::sleep(Duration::from_millis(30));
        assert_eq!(
            second.job_state(&job_id),
            Some(TransferJobState::WaitingForDevice),
            "a paused recovery must not dispatch while the device is offline"
        );

        second.resume(&job_id).expect("resume recovered job");
        assert_eq!(
            second
                .job_snapshot(&job_id)
                .expect("resumed snapshot")
                .desired_run_state,
            DesiredRunState::Run
        );
        second.shutdown(Duration::from_secs(1));
        let store = TransferStore::open(&transfer_path).expect("reopen store");
        assert_eq!(
            store
                .get_job(job_id.as_str())
                .expect("read row")
                .expect("row")
                .desired_run_state,
            DesiredRunState::Run
        );
    }

    fn offline_coordinator(dir: &Path, device_id: &DeviceId) -> TransferCoordinator {
        let status = Arc::new(FakeDeviceStatus::new());
        status.set(
            device_id,
            ConnectionState::Disconnected,
            CaptureActivityState::Idle,
        );
        coordinator_with_store(
            open_transfer_store(&dir.join("transfer.sqlite3")),
            status,
            instant_factory(b"parked".to_vec()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir),
        )
    }

    #[test]
    fn a_stale_expected_version_is_refused_instead_of_overwriting_a_committed_state() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let coordinator = offline_coordinator(dir.path(), &device_id);
        let job_id = parked_job(&coordinator, &device_id, "sess-cas", "cas-key", b"parked");

        let before = coordinator.job_snapshot(&job_id).expect("snapshot");
        assert_eq!(before.state, TransferJobState::WaitingForDevice);

        // Another command commits a transition against the same job.
        coordinator
            .command(&job_id, JobCommand::Transition(TransferJobState::Queued))
            .expect("a legal transition is accepted");
        let after = coordinator.job_snapshot(&job_id).expect("snapshot");
        assert_eq!(after.version, before.version + 1);
        assert_eq!(after.state, TransferJobState::Queued);

        // A writer still holding the *old* snapshot must be told it is
        // stale, not silently overwrite what the other command committed.
        let error = coordinator
            .command_if_unchanged(&job_id, before.version, JobCommand::Cancel)
            .expect_err("a stale writer must not win");
        match error {
            CoordinatorError::Stale {
                expected, actual, ..
            } => {
                assert_eq!(expected, before.version);
                assert_eq!(actual, after.version);
            }
            other => panic!("expected a stale result, got {other:?}"),
        }
        assert_eq!(
            coordinator
                .job_snapshot(&job_id)
                .map(|s| (s.state, s.version)),
            Some((TransferJobState::Queued, after.version)),
            "a refused CAS must leave the job exactly as it was"
        );

        // Re-deciding against the current version succeeds.
        coordinator
            .command_if_unchanged(&job_id, after.version, JobCommand::Cancel)
            .expect("a fresh expected version is accepted");
        // The command durably enters `cancelling` before returning, but its
        // dispatch can race the worker's cancellation acknowledgement. By
        // the time the snapshot is read the owner may therefore already
        // have completed the legal `cancelling -> cancelled` follow-up.
        let settled = coordinator.job_snapshot(&job_id).expect("snapshot");
        assert!(matches!(
            settled.state,
            TransferJobState::Cancelling | TransferJobState::Cancelled
        ));
        assert!(settled.version > after.version);
    }

    #[test]
    fn a_snapshot_reports_identity_state_desired_run_state_and_progress_at_one_version() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let coordinator = offline_coordinator(dir.path(), &device_id);
        let job_id = parked_job(&coordinator, &device_id, "sess-snap", "snap-key", b"parked");

        let snapshot = coordinator.job_snapshot(&job_id).expect("snapshot");
        assert_eq!(snapshot.job_id, job_id);
        assert_eq!(snapshot.device_id, device_id);
        assert_eq!(snapshot.session_id, SessionId("sess-snap".to_string()));
        assert_eq!(snapshot.state, TransferJobState::WaitingForDevice);
        // `pause` is a desired run state, never a state — the one place a
        // caller can see both facts together is this snapshot.
        assert_eq!(snapshot.desired_run_state, DesiredRunState::Paused);
        assert_eq!(snapshot.progress.total_bytes, 6);
        assert_eq!(snapshot.progress.files_total, 1);
        assert_eq!(snapshot.error, None);
        assert!(!snapshot.is_terminal());

        assert_eq!(coordinator.list_snapshots(), vec![snapshot.clone()]);
        assert_eq!(coordinator.job_snapshot(&JobId("nope".to_string())), None);

        coordinator.resume(&job_id).expect("resume");
        let resumed = coordinator.job_snapshot(&job_id).expect("snapshot");
        assert_eq!(resumed.desired_run_state, DesiredRunState::Run);
        assert!(resumed.version >= snapshot.version);
    }

    #[test]
    fn a_jobs_version_only_ever_increases_across_its_whole_lifetime() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);
        let data = b"versions must be monotonic".to_vec();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            instant_factory(data.clone()),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let job_id = coordinator
            .enqueue(one_file_request(&device_id, "sess-1", "version-key", &data))
            .expect("enqueue");

        let highest = AtomicU64::new(0);
        let done = wait_until(Duration::from_secs(5), || {
            if let Some(snapshot) = coordinator.job_snapshot(&job_id) {
                let seen = highest.fetch_max(snapshot.version, Ordering::SeqCst);
                assert!(
                    snapshot.version >= seen,
                    "version went backwards: {seen} -> {}",
                    snapshot.version
                );
                // Progress and state come from the same reading, so a
                // succeeded job can never be observed with partial bytes.
                if snapshot.state == TransferJobState::Succeeded {
                    assert_eq!(
                        snapshot.progress.transferred_bytes,
                        snapshot.progress.total_bytes
                    );
                    assert_eq!(snapshot.progress.files_done, snapshot.progress.files_total);
                    return true;
                }
            }
            false
        });
        assert!(done, "expected the job to succeed");
        assert!(
            highest.load(Ordering::SeqCst) >= 5,
            "queued->preparing->transferring->verifying->committing->succeeded is five commits"
        );
    }

    #[test]
    fn two_threads_cancelling_the_same_job_never_attempt_a_duplicate_transition() {
        // The production race this batch exists to kill: `cancel` and the
        // worker both used to read "state != cancelling" and both
        // transition, which the journal rejected with
        // `cancelling -> cancelling`. Two *callers* racing each other is
        // the same shape and needs no worker timing at all.
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = vec![7u8; 256];
        let gate = Deferred::new();
        let opened: RecordingSink<()> = RecordingSink::new();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            Arc::new(GatedFactory {
                data: data.clone(),
                gate: gate.clone(),
                opened: opened.clone(),
            }),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );
        let job_id = coordinator
            .enqueue(one_file_request(&device_id, "sess-1", "race-key", &data))
            .expect("enqueue");
        assert!(
            opened.wait_for(1, DEFAULT_TEST_TIMEOUT),
            "the worker never reached the download"
        );

        let start = Rendezvous::new(2);
        let errors: Vec<Option<String>> = thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let start = start.clone();
                    let coordinator = &coordinator;
                    let job_id = job_id.clone();
                    let gate = gate.clone();
                    scope.spawn(move || {
                        start.wait();
                        // Let the in-flight read finish unwinding: both
                        // threads are inside `cancel` before any of them
                        // can observe the worker letting go.
                        gate.release(());
                        coordinator.cancel(&job_id).err().map(|e| e.to_string())
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert_eq!(
            coordinator.job_state(&job_id),
            Some(TransferJobState::Cancelled)
        );
        for error in errors.iter().flatten() {
            assert!(
                !error.contains("cancelling -> cancelling"),
                "two commands both transitioned the same job: {error}"
            );
            assert!(
                error.contains("terminal"),
                "the losing cancel may only lose by finding the job already terminal: {error}"
            );
        }
    }

    #[test]
    fn one_target_has_at_most_one_lease_even_with_two_jobs_for_the_same_session() {
        let dir = tempdir().unwrap();
        let device_id = DeviceId("dev-1".to_string());
        let status = Arc::new(FakeDeviceStatus::new());
        connected_device(&device_id, &status);

        let data = vec![4u8; 64];
        let gate = Deferred::new();
        let opened: RecordingSink<()> = RecordingSink::new();
        let coordinator = coordinator_with_store(
            open_transfer_store(&dir.path().join("transfer.sqlite3")),
            status,
            Arc::new(GatedFactory {
                data: data.clone(),
                gate: gate.clone(),
                opened: opened.clone(),
            }),
            Arc::new(AlwaysPassVerifierStub),
            test_config(dir.path()),
        );

        // Two different jobs (different idempotency keys) naming the same
        // (device, session) target directory.
        let first = coordinator
            .enqueue(one_file_request(&device_id, "sess-shared", "key-a", &data))
            .expect("enqueue a");
        let second = coordinator
            .enqueue({
                let mut request = one_file_request(&device_id, "sess-shared", "key-b", &data);
                // Identity deduplication is durable on
                // (device, session, revision), so use a distinct revision
                // to model two logical jobs writing the same target.
                request.revision = "rev-2".to_string();
                request
            })
            .expect("enqueue b");
        assert!(
            opened.wait_for(1, DEFAULT_TEST_TIMEOUT),
            "no worker ever started a transfer"
        );

        let target = TargetKey {
            device_id: device_id.clone(),
            session_id: SessionId("sess-shared".to_string()),
        };
        let holder = coordinator
            .inner
            .target_leases
            .holder(&target)
            .expect("one writer holds the target");
        assert_eq!(coordinator.inner.target_leases.len(), 1);

        let blocked = if holder == first {
            second.clone()
        } else {
            first.clone()
        };
        // Nudge the dispatcher: the blocked job is repeatedly offered to
        // the worker pool and must keep bouncing off the lease instead of
        // opening a second writer on the same target.
        coordinator.tick();
        coordinator.tick();
        assert!(
            !opened.wait_for(2, Duration::from_millis(300)),
            "a second writer opened a source for a target that is already leased"
        );
        assert_eq!(
            coordinator.job_state(&blocked),
            Some(TransferJobState::Queued),
            "the job without the lease must not have started"
        );

        // A leaseless job is still fully controllable.
        coordinator
            .cancel(&blocked)
            .expect("cancel the blocked job");
        assert_eq!(
            coordinator.job_state(&blocked),
            Some(TransferJobState::Cancelled)
        );

        gate.release(());
        assert!(
            wait_until(Duration::from_secs(5), || matches!(
                coordinator.job_state(&holder),
                Some(TransferJobState::Succeeded)
            )),
            "the lease holder should finish once unblocked, got {:?}",
            coordinator.job_state(&holder)
        );
        assert!(
            coordinator.inner.target_leases.is_empty(),
            "a finished job must release its target"
        );
    }
}
