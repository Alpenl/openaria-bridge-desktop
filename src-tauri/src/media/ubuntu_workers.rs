//! Background worker lanes for the Ubuntu media pipeline.
//!
//! Commands persist intent and put a job id on a bounded wake queue; they do
//! not copy files, run FFmpeg, or talk to an object store. That separation is
//! the whole point: a multi-gigabyte session copy must not hold a Tauri command
//! open, and a lost wake-up must not lose work.
//!
//! The queue is therefore only a wake-up hint. SQLite is the recovery
//! authority: every durable job is enqueued again at startup, and a worker
//! always reloads the latest snapshot rather than trusting whatever was true
//! when the id was queued. Dropping a queue entry costs a delay, never a job.
//!
//! Shutdown is cooperative and joined. `stop` refuses new work, wakes every
//! worker, and waits for each thread; a lane that does not return inside its
//! deadline is reported as `resource_stuck` with its handle retained, so a
//! second `stop` can keep waiting instead of detaching and lying about success.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::json;

use super::ports::{MediaErrorCode, MediaPortError};

/// Maximum job ids one lane may hold. The bound exists so a runaway producer
/// cannot grow memory without limit; overflow is safe because the durable rows
/// are still discoverable by recovery.
pub const DEFAULT_QUEUE_CAPACITY: usize = 4_096;

/// How long `stop` waits for one lane's thread before reporting it stuck.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(30);

const STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Why an enqueue did not add work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// The id was added and a worker was woken.
    Queued,
    /// The id was already pending. A second copy would only cause a redundant
    /// snapshot reload.
    AlreadyPending,
    /// The queue is full. The durable row remains; recovery or a later command
    /// will schedule it.
    Full,
    /// The lane is shutting down and will not accept new work.
    Stopped,
}

#[derive(Default)]
struct QueueState {
    pending: VecDeque<String>,
    /// Membership index for the queue, so dedup does not become a linear scan.
    queued: HashSet<String>,
    stopped: bool,
}

/// Bounded, de-duplicating wake queue for one worker lane.
#[derive(Default)]
pub struct MediaWakeQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
    capacity: usize,
}

impl std::fmt::Debug for MediaWakeQueue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MediaWakeQueue")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl MediaWakeQueue {
    #[must_use]
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
            capacity: capacity.max(1),
        })
    }

    pub fn enqueue(&self, job_id: &str) -> EnqueueOutcome {
        let mut state = lock(&self.state);
        if state.stopped {
            return EnqueueOutcome::Stopped;
        }
        if state.queued.contains(job_id) {
            return EnqueueOutcome::AlreadyPending;
        }
        if state.pending.len() >= self.capacity {
            return EnqueueOutcome::Full;
        }
        state.queued.insert(job_id.to_string());
        state.pending.push_back(job_id.to_string());
        drop(state);
        self.ready.notify_one();
        EnqueueOutcome::Queued
    }

    /// Block until a job id is available or the lane is stopped.
    fn next(&self) -> Option<String> {
        let mut state = lock(&self.state);
        loop {
            if let Some(job_id) = state.pending.pop_front() {
                state.queued.remove(&job_id);
                return Some(job_id);
            }
            if state.stopped {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Remove one specific pending id, reporting whether it was there.
    ///
    /// A worker uses this to absorb a re-schedule the executor issued for the
    /// job it is already running, instead of letting the lane wake itself a
    /// second time for work it has just done.
    pub fn take(&self, job_id: &str) -> bool {
        let mut state = lock(&self.state);
        if !state.queued.remove(job_id) {
            return false;
        }
        state.pending.retain(|pending| pending != job_id);
        true
    }

    /// Refuse new work and wake every waiter. Already-queued ids are dropped:
    /// they are still durable rows and will be re-enqueued by recovery.
    pub fn stop(&self) {
        let mut state = lock(&self.state);
        state.stopped = true;
        state.pending.clear();
        state.queued.clear();
        drop(state);
        self.ready.notify_all();
    }

    #[must_use]
    #[cfg(test)]
    pub fn depth(&self) -> usize {
        lock(&self.state).pending.len()
    }
}

/// One named worker lane: a queue plus the single thread that drains it.
///
/// Concurrency is deliberately one thread per lane in this version. TF-card
/// random reads, libx265, and a single multipart upload are each the bottleneck
/// in their own lane, so parallelism here would contend rather than help.
/// Raising it is a benchmark decision, not a default.
pub struct WorkerLane {
    name: &'static str,
    queue: Arc<MediaWakeQueue>,
    handle: Mutex<Option<JoinHandle<()>>>,
    running: Arc<AtomicBool>,
    start_gate: Arc<(Mutex<bool>, Condvar)>,
}

impl std::fmt::Debug for WorkerLane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerLane")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl WorkerLane {
    /// Spawn the lane. `run` is invoked once per dequeued job id and must not
    /// panic on ordinary failure: a worker error is a durable job state, and
    /// the lane keeps serving other jobs.
    #[cfg(test)]
    pub fn spawn<F>(name: &'static str, capacity: usize, run: F) -> Arc<Self>
    where
        F: Fn(&str) + Send + 'static,
    {
        Self::spawn_over(name, MediaWakeQueue::new(capacity), run)
    }

    /// Spawn an inert lane over a new queue. The lane remains joinable but
    /// cannot consume queued work until `start` releases it.
    pub fn spawn_inactive<F>(name: &'static str, capacity: usize, run: F) -> Arc<Self>
    where
        F: Fn(&str) + Send + 'static,
    {
        Self::spawn_over_inactive(name, MediaWakeQueue::new(capacity), run)
    }

    /// Spawn the lane over a queue somebody else already owns.
    ///
    /// This is the normal production shape: the scheduler handed to the core
    /// executor and the worker thread must be the *same* queue, otherwise a
    /// `enqueue` from a command would never wake the thread.
    #[cfg(test)]
    pub fn spawn_over<F>(name: &'static str, queue: Arc<MediaWakeQueue>, run: F) -> Arc<Self>
    where
        F: Fn(&str) + Send + 'static,
    {
        Self::spawn_over_with_start(name, queue, run, true)
    }

    /// Spawn an inert lane. The thread exists so shutdown remains joinable,
    /// but it cannot dequeue durable work until WorkerLane::start is called
    /// after application recovery has completed.
    pub fn spawn_over_inactive<F>(
        name: &'static str,
        queue: Arc<MediaWakeQueue>,
        run: F,
    ) -> Arc<Self>
    where
        F: Fn(&str) + Send + 'static,
    {
        Self::spawn_over_with_start(name, queue, run, false)
    }

    fn spawn_over_with_start<F>(
        name: &'static str,
        queue: Arc<MediaWakeQueue>,
        run: F,
        start_immediately: bool,
    ) -> Arc<Self>
    where
        F: Fn(&str) + Send + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let thread_queue = Arc::clone(&queue);
        let thread_running = Arc::clone(&running);
        let start_gate = Arc::new((Mutex::new(start_immediately), Condvar::new()));
        let thread_start_gate = Arc::clone(&start_gate);
        let handle = thread::Builder::new()
            .name(format!("ylx-media-{name}"))
            .spawn(move || {
                let (started, wake) = &*thread_start_gate;
                let mut started = lock(started);
                while !*started && thread_running.load(Ordering::Acquire) {
                    started = wake
                        .wait(started)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                if !*started || !thread_running.load(Ordering::Acquire) {
                    return;
                }
                drop(started);
                while let Some(job_id) = thread_queue.next() {
                    if !thread_running.load(Ordering::Acquire) {
                        break;
                    }
                    run(&job_id);
                }
            })
            .ok();
        Arc::new(Self {
            name,
            queue,
            handle: Mutex::new(handle),
            running,
            start_gate,
        })
    }

    /// Release an inactive lane after durable recovery and managed-state
    /// registration have completed. Repeated calls are harmless.
    pub fn start(&self) {
        let (started, wake) = &*self.start_gate;
        let mut started = lock(started);
        if !*started {
            *started = true;
            wake.notify_one();
        }
    }

    pub fn enqueue(&self, job_id: &str) -> EnqueueOutcome {
        self.queue.enqueue(job_id)
    }

    /// Ask the lane to stop and join its thread.
    ///
    /// Retryable by construction: if the deadline elapses, the join handle is
    /// kept so a later `stop` can wait again. A detached thread reported as
    /// stopped would be a lie about released resources.
    pub fn stop(&self, timeout: Duration) -> Result<(), MediaPortError> {
        self.running.store(false, Ordering::Release);
        self.start();
        self.queue.stop();

        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut handle = lock(&self.handle);
                let Some(current) = handle.as_ref() else {
                    return Ok(());
                };
                if current.is_finished() {
                    if let Some(current) = handle.take() {
                        // The thread has already exited, so this join returns
                        // immediately and cannot block the shutdown sequence.
                        let _ = current.join();
                    }
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(MediaPortError::new(
                    MediaErrorCode::ResourceStuck,
                    format!(
                        "the {} media worker did not stop within {} seconds",
                        self.name,
                        timeout.as_secs()
                    ),
                )
                .with_retryable(true)
                .with_detail("lane", json!(self.name))
                .with_detail("capability", json!("media_worker_shutdown")));
            }
            // Re-notify: a worker that was mid-job when `stop` was first
            // called must still find the queue closed when it comes back.
            self.queue.stop();
            thread::sleep(STOP_POLL_INTERVAL);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn the_same_job_is_not_queued_twice() {
        let queue = MediaWakeQueue::new(8);
        assert_eq!(queue.enqueue("job-1"), EnqueueOutcome::Queued);
        assert_eq!(queue.enqueue("job-1"), EnqueueOutcome::AlreadyPending);
        assert_eq!(queue.depth(), 1);
    }

    #[test]
    fn a_full_queue_reports_overflow_rather_than_growing() {
        let queue = MediaWakeQueue::new(1);
        assert_eq!(queue.enqueue("job-1"), EnqueueOutcome::Queued);
        assert_eq!(queue.enqueue("job-2"), EnqueueOutcome::Full);
    }

    #[test]
    fn a_stopped_queue_refuses_new_work() {
        let queue = MediaWakeQueue::new(8);
        queue.stop();
        assert_eq!(queue.enqueue("job-1"), EnqueueOutcome::Stopped);
    }

    #[test]
    fn a_lane_runs_queued_work_and_joins_on_stop() {
        let (sender, receiver) = mpsc::channel();
        let lane = WorkerLane::spawn("test", 8, move |job_id| {
            let _ = sender.send(job_id.to_string());
        });
        assert_eq!(lane.enqueue("job-1"), EnqueueOutcome::Queued);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("worker ran"),
            "job-1"
        );
        lane.stop(Duration::from_secs(5)).expect("lane stops");
        // Stop is idempotent, so a second shutdown pass is safe.
        lane.stop(Duration::from_secs(5))
            .expect("stop is retryable");
    }

    #[test]
    fn an_inactive_lane_waits_until_start_before_running_queued_work() {
        let (sender, receiver) = mpsc::channel();
        let lane = WorkerLane::spawn_inactive("inactive-test", 8, move |job_id| {
            let _ = sender.send(job_id.to_string());
        });

        assert_eq!(lane.enqueue("job-before-start"), EnqueueOutcome::Queued);
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());

        lane.start();
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("worker ran after start"),
            "job-before-start"
        );
        lane.stop(Duration::from_secs(5)).expect("lane stops");
    }
}
