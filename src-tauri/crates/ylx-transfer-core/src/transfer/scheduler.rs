//! Issue #1 commit 47: the ready set and the bounded worker queue.
//!
//! # What was wrong with an unbounded `mpsc::Sender<JobId>`
//!
//! The dispatcher used to re-`send` **every** non-terminal, inactive job on
//! every tick. A job whose device was offline could therefore be queued
//! hundreds of times per second: the channel was unbounded, so nothing ever
//! pushed back, and each of those duplicates cost a worker a full pickup
//! (claim the job, read the state, query the device, park it again) during
//! which a job that had just become ready waited behind it. Two failure
//! modes from the same root: unbounded backlog growth, and starvation of
//! the jobs that actually could run.
//!
//! [`WorkQueue`] fixes both structurally rather than by tuning:
//!
//! - **At most one scheduled notification per job.** [`WorkQueue::schedule`]
//!   is idempotent while a job is still waiting to be claimed — a second
//!   `schedule` for a job already in the queue reports
//!   [`ScheduleOutcome::AlreadyScheduled`] and adds nothing. The queue can
//!   therefore never hold more entries than there are distinct jobs.
//! - **Bounded.** Beyond `capacity` a `schedule` is *refused*
//!   ([`ScheduleOutcome::Full`]) and counted, instead of growing without
//!   limit. A refusal is safe by construction: the dispatcher re-offers
//!   ready jobs on its next pass, so a refused notification costs latency,
//!   never correctness.
//! - **FIFO.** A job that keeps bouncing off a not-ready device goes to the
//!   *back* of the queue each time, so it cannot starve a job that became
//!   ready after it.
//! - **Wakeable.** [`WorkQueue::stop`] wakes every blocked claimer at once,
//!   which is what makes commit 50's `shutdown(deadline)` prompt rather
//!   than "up to one poll interval".
//!
//! The complementary half of commit 47 lives in the dispatcher (see
//! `coordinator::Inner::tick`): it only schedules jobs whose device
//! actually is ready — the *ready set* — so a parked job is not offered to
//! a worker at all until the condition that parked it has changed.

use std::collections::{HashSet, VecDeque};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::JobId;

/// What [`WorkQueue::schedule`] did with a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleOutcome {
    /// The job was added; exactly one worker will claim it.
    Scheduled,
    /// The job was already waiting to be claimed — deliberately *not* a
    /// second notification.
    AlreadyScheduled,
    /// The queue is at capacity. The job was not added; the caller (the
    /// dispatcher) will offer it again later.
    Full,
    /// The queue is shutting down and accepts nothing more.
    Stopped,
}

impl ScheduleOutcome {
    #[must_use]
    pub fn is_scheduled(self) -> bool {
        self == ScheduleOutcome::Scheduled
    }
}

#[derive(Default)]
struct QueueState {
    order: VecDeque<JobId>,
    scheduled: HashSet<JobId>,
    stopped: bool,
    overflows: u64,
    duplicates: u64,
    delivered: u64,
}

/// A bounded, de-duplicating, FIFO, wakeable job queue. See module doc.
pub struct WorkQueue {
    capacity: usize,
    state: Mutex<QueueState>,
    ready: Condvar,
}

/// Domain-facing name used by the phase-3 design. The implementation is
/// intentionally the small queue above: the coordinator owns command
/// acknowledgements and worker effects, while this type owns only ready-set
/// membership, bounded capacity and wake-up semantics.
pub type TransferScheduler = WorkQueue;

impl WorkQueue {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        WorkQueue {
            capacity: capacity.max(1),
            state: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Offer `job_id` to the worker pool. See [`ScheduleOutcome`].
    pub fn schedule(&self, job_id: &JobId) -> ScheduleOutcome {
        let mut state = self.state.lock().unwrap();
        if state.stopped {
            return ScheduleOutcome::Stopped;
        }
        if state.scheduled.contains(job_id) {
            state.duplicates += 1;
            return ScheduleOutcome::AlreadyScheduled;
        }
        if state.order.len() >= self.capacity {
            state.overflows += 1;
            return ScheduleOutcome::Full;
        }
        state.scheduled.insert(job_id.clone());
        state.order.push_back(job_id.clone());
        drop(state);
        self.ready.notify_one();
        ScheduleOutcome::Scheduled
    }

    /// Take the oldest waiting job, blocking up to `timeout`. `None` means
    /// the timeout elapsed or the queue was stopped — a worker treats the
    /// latter as "return from the worker loop".
    pub fn claim(&self, timeout: Duration) -> Option<JobId> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        loop {
            if state.stopped {
                return None;
            }
            if let Some(job_id) = state.order.pop_front() {
                state.scheduled.remove(&job_id);
                state.delivered += 1;
                return Some(job_id);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self
                .ready
                .wait_timeout(state, remaining)
                .expect("work queue mutex poisoned");
            state = next;
        }
    }

    /// Stop accepting work and wake every blocked claimer.
    pub fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.stopped = true;
        state.order.clear();
        state.scheduled.clear();
        drop(state);
        self.ready.notify_all();
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.state.lock().unwrap().stopped
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().unwrap().order.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn is_scheduled(&self, job_id: &JobId) -> bool {
        self.state.lock().unwrap().scheduled.contains(job_id)
    }

    /// How many notifications were refused because the queue was full.
    #[must_use]
    pub fn overflows(&self) -> u64 {
        self.state.lock().unwrap().overflows
    }

    /// How many notifications were collapsed into one because the job was
    /// already waiting.
    #[must_use]
    pub fn duplicates(&self) -> u64 {
        self.state.lock().unwrap().duplicates
    }

    /// How many jobs have been handed to a worker.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.state.lock().unwrap().delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{RecordingSink, DEFAULT_TEST_TIMEOUT};
    use std::sync::Arc;
    use std::thread;

    fn job(name: &str) -> JobId {
        JobId(name.to_string())
    }

    #[test]
    fn a_job_scheduled_twice_is_only_delivered_once() {
        let queue = WorkQueue::new(8);
        assert_eq!(queue.schedule(&job("a")), ScheduleOutcome::Scheduled);
        for _ in 0..100 {
            assert_eq!(queue.schedule(&job("a")), ScheduleOutcome::AlreadyScheduled);
        }
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.duplicates(), 100);

        assert_eq!(queue.claim(DEFAULT_TEST_TIMEOUT), Some(job("a")));
        assert!(queue.is_empty());
        assert_eq!(queue.claim(Duration::from_millis(10)), None);
        assert_eq!(queue.delivered(), 1);

        // Once claimed, the job can be scheduled again — the guarantee is
        // "at most one *pending* notification", not "at most one ever".
        assert_eq!(queue.schedule(&job("a")), ScheduleOutcome::Scheduled);
    }

    #[test]
    fn the_queue_is_bounded_and_refuses_instead_of_growing() {
        let queue = WorkQueue::new(2);
        assert_eq!(queue.schedule(&job("a")), ScheduleOutcome::Scheduled);
        assert_eq!(queue.schedule(&job("b")), ScheduleOutcome::Scheduled);
        assert_eq!(queue.schedule(&job("c")), ScheduleOutcome::Full);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.overflows(), 1);
    }

    #[test]
    fn a_job_that_keeps_bouncing_cannot_starve_a_job_that_became_ready_later() {
        let queue = WorkQueue::new(8);
        queue.schedule(&job("bouncy"));
        queue.schedule(&job("late"));

        // The bouncy job is claimed, finds nothing to do, and re-schedules
        // itself. FIFO puts it behind `late`, which therefore runs next.
        assert_eq!(queue.claim(DEFAULT_TEST_TIMEOUT), Some(job("bouncy")));
        queue.schedule(&job("bouncy"));
        assert_eq!(queue.claim(DEFAULT_TEST_TIMEOUT), Some(job("late")));
        assert_eq!(queue.claim(DEFAULT_TEST_TIMEOUT), Some(job("bouncy")));
    }

    #[test]
    fn stop_wakes_every_blocked_claimer_without_waiting_for_a_timeout() {
        let queue = Arc::new(WorkQueue::new(4));
        let woken: RecordingSink<()> = RecordingSink::new();
        let parked: RecordingSink<()> = RecordingSink::new();

        let workers: Vec<_> = (0..3)
            .map(|_| {
                let queue = queue.clone();
                let woken = woken.clone();
                let parked = parked.clone();
                thread::spawn(move || {
                    parked.emit(());
                    // A timeout far beyond any test's patience: only `stop`
                    // can return this promptly.
                    let claimed = queue.claim(Duration::from_secs(3600));
                    woken.emit(());
                    claimed
                })
            })
            .collect();

        assert!(parked.wait_for(3, DEFAULT_TEST_TIMEOUT));
        queue.stop();
        assert!(woken.wait_for(3, DEFAULT_TEST_TIMEOUT));
        for worker in workers {
            assert_eq!(worker.join().expect("worker thread"), None);
        }
        assert!(queue.is_stopped());
        assert_eq!(queue.schedule(&job("a")), ScheduleOutcome::Stopped);
    }

    #[test]
    fn a_blocked_claimer_wakes_as_soon_as_work_arrives() {
        let queue = Arc::new(WorkQueue::new(4));
        let parked: RecordingSink<()> = RecordingSink::new();
        let claimed: RecordingSink<JobId> = RecordingSink::new();

        let worker = {
            let queue = queue.clone();
            let parked = parked.clone();
            let claimed = claimed.clone();
            thread::spawn(move || {
                parked.emit(());
                if let Some(id) = queue.claim(Duration::from_secs(3600)) {
                    claimed.emit(id);
                }
            })
        };

        assert!(parked.wait_for(1, DEFAULT_TEST_TIMEOUT));
        queue.schedule(&job("work"));
        assert!(claimed.wait_for(1, DEFAULT_TEST_TIMEOUT));
        worker.join().expect("worker thread");
        assert_eq!(claimed.events(), vec![job("work")]);
    }
}
