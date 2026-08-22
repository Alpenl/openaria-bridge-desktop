use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::normalization::{
    DerivationJobId, MediaOperationControl, ProcessDeadline, ProcessStopReason,
};

#[derive(Debug, Default)]
struct OperationState {
    active: bool,
    epoch: u64,
}

#[derive(Debug)]
pub(crate) struct JobProcessControl {
    stop: AtomicU8,
    deadline: ProcessDeadline,
    state: Mutex<OperationState>,
    idle: Condvar,
}

impl JobProcessControl {
    pub(crate) fn new(deadline: ProcessDeadline) -> Self {
        Self {
            stop: AtomicU8::new(0),
            deadline,
            state: Mutex::new(OperationState::default()),
            idle: Condvar::new(),
        }
    }

    /// Called while the per-job command mutex is held. That ordering closes
    /// the gap where a pause could observe no active operation immediately
    /// before a worker spawns a child.
    pub(crate) fn begin(self: &Arc<Self>) -> ActiveOperation {
        let mut state = lock(&self.state);
        debug_assert!(!state.active, "one job may own only one process stage");
        state.active = true;
        state.epoch = state.epoch.saturating_add(1);
        ActiveOperation {
            control: Arc::clone(self),
            finished: false,
        }
    }

    pub(crate) fn request_stop(&self, reason: ProcessStopReason) {
        self.stop.store(encode_reason(reason), Ordering::Release);
    }

    pub(crate) fn clear_stop(&self) {
        self.stop.store(0, Ordering::Release);
    }

    pub(crate) fn is_active(&self) -> bool {
        lock(&self.state).active
    }

    pub(crate) fn wait_until_idle_until(&self, deadline: Instant) -> bool {
        let mut state = lock(&self.state);
        while state.active {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, timeout) = self
                .idle
                .wait_timeout_while(state, deadline.saturating_duration_since(now), |state| {
                    state.active
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() && state.active {
                return false;
            }
        }
        true
    }

    pub(crate) fn stop_wait_timeout(&self) -> Duration {
        const MAX_STOP_WAIT: Duration = Duration::from_secs(30);
        let grace_ms = self
            .deadline
            .terminate_grace_ms()
            .saturating_add(self.deadline.kill_grace_ms())
            .saturating_add(1_000);
        Duration::from_millis(grace_ms).min(MAX_STOP_WAIT)
    }

    fn finish(&self) {
        let mut state = lock(&self.state);
        state.active = false;
        self.idle.notify_all();
    }
}

impl MediaOperationControl for JobProcessControl {
    fn stop_requested(&self) -> Option<ProcessStopReason> {
        decode_reason(self.stop.load(Ordering::Acquire))
    }

    fn deadline(&self) -> ProcessDeadline {
        self.deadline
    }
}

pub(crate) struct ActiveOperation {
    control: Arc<JobProcessControl>,
    finished: bool,
}

impl ActiveOperation {
    /// Keep the operation active until the reaped outcome has also been
    /// reduced and persisted. Commands waiting for pause/cancel therefore
    /// never acknowledge a merely exited child with stale durable state.
    pub(crate) fn finish(mut self) {
        self.control.finish();
        self.finished = true;
    }
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        if !self.finished {
            self.control.finish();
        }
    }
}

#[derive(Debug)]
pub(crate) struct JobRuntime {
    command: Mutex<()>,
    worker: Mutex<()>,
    pub(crate) process: Arc<JobProcessControl>,
}

impl JobRuntime {
    fn new(deadline: ProcessDeadline) -> Self {
        Self {
            command: Mutex::new(()),
            worker: Mutex::new(()),
            process: Arc::new(JobProcessControl::new(deadline)),
        }
    }

    pub(crate) fn command(&self) -> MutexGuard<'_, ()> {
        lock(&self.command)
    }

    pub(crate) fn worker(&self) -> MutexGuard<'_, ()> {
        lock(&self.worker)
    }
}

#[derive(Debug)]
pub(crate) struct JobRuntimeRegistry {
    deadline: ProcessDeadline,
    jobs: Mutex<HashMap<DerivationJobId, Arc<JobRuntime>>>,
}

impl JobRuntimeRegistry {
    pub(crate) fn new(deadline: ProcessDeadline) -> Self {
        Self {
            deadline,
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn runtime_for(&self, job_id: &DerivationJobId) -> Arc<JobRuntime> {
        let mut jobs = lock(&self.jobs);
        Arc::clone(
            jobs.entry(job_id.clone())
                .or_insert_with(|| Arc::new(JobRuntime::new(self.deadline))),
        )
    }

    pub(crate) fn all(&self) -> Vec<Arc<JobRuntime>> {
        lock(&self.jobs).values().cloned().collect()
    }

    pub(crate) fn remove(&self, job_id: &DerivationJobId) {
        lock(&self.jobs).remove(job_id);
    }
}

fn encode_reason(reason: ProcessStopReason) -> u8 {
    match reason {
        ProcessStopReason::Pause => 1,
        ProcessStopReason::Cancel => 2,
        ProcessStopReason::Shutdown => 3,
        ProcessStopReason::SourceUnavailable => 4,
    }
}

fn decode_reason(value: u8) -> Option<ProcessStopReason> {
    match value {
        1 => Some(ProcessStopReason::Pause),
        2 => Some(ProcessStopReason::Cancel),
        3 => Some(ProcessStopReason::Shutdown),
        4 => Some(ProcessStopReason::SourceUnavailable),
        _ => None,
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_wait_times_out_and_can_be_retried_after_the_operation_finishes() {
        let deadline = ProcessDeadline::new(1_000, 10, 10).expect("deadline");
        let control = Arc::new(JobProcessControl::new(deadline));
        let operation = control.begin();

        assert!(!control.wait_until_idle_until(Instant::now() + Duration::from_millis(5)));
        drop(operation);
        assert!(control.wait_until_idle_until(Instant::now() + Duration::from_millis(5)));
    }
}
