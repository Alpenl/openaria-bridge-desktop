//! Crash recovery for [`TransferCoordinator`].
//!
//! The coordinator deliberately has no request or desired-state sidecar.
//! `TransferStore::list_recoverable_jobs` enumerates the complete durable
//! spec, state/version, desired run intent and file ledger in one authority;
//! malformed rows are returned as observable `Blocked` diagnostics instead
//! of silently shortening the recovery list.

use super::coordinator::{CoordinatorError, Inner, TransferCoordinator};
use super::queue::{request_from_spec, tag_to_state};
use super::JobId;
use crate::persistence::RecoverableJob;

impl TransferCoordinator {
    /// Rehydrates every non-terminal job and every retryable failed job from
    /// the durable transfer store. A recoverable job is installed before it
    /// is scheduled; a blocked row is surfaced as a coordinator fault and is
    /// never silently discarded.
    pub fn recover_on_startup(&self) -> Result<Vec<JobId>, CoordinatorError> {
        self.inner.recover_on_startup()
    }
}

impl Inner {
    pub(super) fn recover_on_startup(&self) -> Result<Vec<JobId>, CoordinatorError> {
        let recoverable = self
            .transfer_store
            .lock()
            .unwrap()
            .list_recoverable_jobs()?;
        let mut rehydrated = Vec::new();
        for job in recoverable {
            match job {
                RecoverableJob::Ready(detail) => {
                    let job_id = JobId(detail.job.job_id.clone());
                    let request = request_from_spec(&detail.spec);
                    let state = tag_to_state(detail.job.state, detail.job.error.clone());
                    self.rehydrate(
                        job_id.clone(),
                        request,
                        state,
                        detail.spec.publication_scope(),
                        detail.job.desired_run_state,
                        detail.job.state_version,
                    );
                    rehydrated.push(job_id);
                }
                RecoverableJob::Blocked(blocked) => {
                    self.record_fault(super::fault::CoordinatorFault::new(
                        Some(JobId(blocked.job_id.clone())),
                        super::fault::FaultKind::Transition,
                        super::fault::FailureClass::LocalIo,
                        format!(
                            "durable transfer job is blocked ({:?}): {}",
                            blocked.reason, blocked.detail
                        ),
                    ));
                }
            }
        }
        Ok(rehydrated)
    }
}
