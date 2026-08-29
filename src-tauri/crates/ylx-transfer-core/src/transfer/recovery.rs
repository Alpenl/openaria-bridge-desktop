//! Startup handling for durable [`TransferCoordinator`] jobs.
//!
//! The production desktop does not resume work left by a previous process.
//! [`TransferCoordinator::fail_interrupted_jobs_on_startup`] closes those
//! rows as explicit failures and installs only their terminal projections,
//! which makes manual retry possible without scheduling network work during
//! startup. The older [`TransferCoordinator::recover_on_startup`] entry point
//! remains for compatibility-only callers and tests; it is not a production
//! startup policy.

use super::coordinator::{map_complete_job_error, CoordinatorError, Inner, TransferCoordinator};
use super::fault::{CoordinatorFault, FailureClass, FaultKind};
use super::queue::now_string;
use super::JobId;
use crate::library::staging::SessionStaging;
use crate::persistence::{PersistenceError, RecoverableJob, TerminalOutcome};

/// Stable `FailureCode::Other` payload for a download left non-terminal by a
/// previous process. The text is user-visible in the transfer tray and makes
/// the absence of automatic interruption recovery explicit.
pub const INTERRUPTED_DOWNLOAD_FAILURE_CODE: &str =
    "other:下载在应用退出时中断，未自动恢复，请手动重试";

impl TransferCoordinator {
    /// Production startup policy: durably fail each download left
    /// non-terminal by the previous process, then install only usable
    /// terminal projections. Its revision-scoped staging bytes are discarded,
    /// so a later explicit retry is a new byte-zero attempt rather than
    /// interrupted-operation recovery. No row is scheduled and no download
    /// source is opened. Calling this after the current coordinator has
    /// accepted work is rejected so normal in-process pause/resume/retry cannot
    /// be swept up as an alleged previous-process interruption.
    pub fn fail_interrupted_jobs_on_startup(&self) -> Result<Vec<JobId>, CoordinatorError> {
        self.inner.fail_interrupted_jobs_on_startup()
    }

    /// Compatibility-only interrupted-operation recovery. Production
    /// applications must use [`Self::fail_interrupted_jobs_on_startup`].
    pub fn recover_on_startup(&self) -> Result<Vec<JobId>, CoordinatorError> {
        self.inner.recover_on_startup()
    }
}

impl Inner {
    pub(super) fn fail_interrupted_jobs_on_startup(&self) -> Result<Vec<JobId>, CoordinatorError> {
        if !self.jobs.lock().unwrap().is_empty() {
            return Err(CoordinatorError::Persistence(
                crate::persistence::PersistenceError::Conflict {
                    detail: "startup interruption settlement requires an empty runtime coordinator"
                        .to_string(),
                },
            ));
        }

        let recoverable = self
            .transfer_store
            .lock()
            .unwrap()
            .list_recoverable_jobs()?;
        let outcome = TerminalOutcome::Failed {
            code: INTERRUPTED_DOWNLOAD_FAILURE_CODE.to_string(),
            retryable: true,
        };
        let mut settled = Vec::with_capacity(recoverable.len());

        for job in recoverable {
            match job {
                RecoverableJob::Ready(detail) => {
                    let job_id = JobId(detail.job.job_id.clone());
                    let identity = detail.spec.identity();
                    let staging = SessionStaging::for_publication(
                        self.library_root(),
                        identity.device_id().as_str(),
                        identity.session_id().as_str(),
                        detail.spec.publication().payload(),
                    )
                    .map_err(|error| {
                        CoordinatorError::Persistence(PersistenceError::Conflict {
                            detail: format!(
                                "cannot derive interrupted staging for {job_id}: {error}"
                            ),
                        })
                    })?;
                    staging.discard().map_err(|error| {
                        CoordinatorError::Persistence(PersistenceError::Conflict {
                            detail: format!(
                                "cannot discard interrupted staging for {job_id}: {error}"
                            ),
                        })
                    })?;
                    self.transfer_store
                        .lock()
                        .unwrap()
                        .complete_job(job_id.as_str(), &outcome, &now_string())
                        .map_err(map_complete_job_error)?;
                    self.install_runtime_if_current(&job_id, true)?;
                    settled.push(job_id);
                }
                RecoverableJob::Blocked(blocked) => {
                    let job_id = JobId(blocked.job_id.clone());
                    self.transfer_store
                        .lock()
                        .unwrap()
                        .complete_job(job_id.as_str(), &outcome, &now_string())
                        .map_err(map_complete_job_error)?;
                    self.record_fault(CoordinatorFault::new(
                        Some(job_id.clone()),
                        FaultKind::Transition,
                        FailureClass::LocalIo,
                        format!(
                            "interrupted durable transfer was failed but its runtime projection is blocked ({:?}): {}",
                            blocked.reason, blocked.detail
                        ),
                    ));
                    settled.push(job_id);
                }
            }
        }
        Ok(settled)
    }

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
                    if self.install_runtime_if_current(&job_id, true)? {
                        rehydrated.push(job_id);
                    }
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
