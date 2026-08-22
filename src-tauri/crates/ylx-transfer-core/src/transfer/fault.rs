//! Issue #1 commit 48: `CoordinatorFault` and typed failure classes.
//!
//! # What was being swallowed
//!
//! The coordinator's worker path was full of `let _ = self.transition(...)`
//! and `let _ = self.work_tx.send(...)`: a durable transition that lost a
//! CAS, a scheduling notification that went nowhere, a checkpoint write
//! that failed, a collaborator that panicked — all of them returned a
//! `Result` that was dropped on the floor. The symptom a user saw was a job
//! that simply stopped moving, with nothing anywhere saying why.
//!
//! A fault is *not* the same thing as a job failure. `TransferJobState::
//! Failed { code, retryable }` is part of the job's own lifecycle and is
//! shown to the user; a [`CoordinatorFault`] is a defect in the machinery
//! that drives jobs. Recording one never changes a job's state — it makes
//! the swallowed failure observable ([`super::coordinator::
//! TransferCoordinator::faults`]) so it can be asserted on in a test and
//! surfaced to an operator.
//!
//! # Why the class is separate from `FailureCode`
//!
//! [`FailureClass`] answers "who has to do something about this", which is
//! the question a retry policy and an operator both actually ask:
//!
//! - [`FailureClass::LocalIo`] — this machine's disk/filesystem.
//! - [`FailureClass::Remote`] — the Pi, the network, the object store.
//! - [`FailureClass::Integrity`] — bytes that arrived but are not the bytes
//!   that were promised (hash/size mismatch, a rejected signature). Never
//!   silently retried forever, and never confused with a network blip.
//! - [`FailureClass::Configuration`] — a request that can never succeed as
//!   written (unsafe path, invalid plan). Retrying is pointless.
//! - [`FailureClass::Cancelled`] — deliberate, not a failure at all; kept
//!   as its own class precisely so it stops being counted as one.

use crate::library::download::DownloadError;

use super::JobId;

/// Which piece of machinery failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// A durable state transition was refused or lost its CAS.
    Transition,
    /// A scheduling notification could not be delivered.
    Send,
    /// A durable progress checkpoint could not be written.
    Checkpoint,
    /// A worker thread panicked while it owned a job.
    WorkerPanic,
    /// The durable desired-run-state record could not be written.
    DesiredRunState,
    /// Shutdown could not complete within its deadline.
    Shutdown,
}

impl FaultKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FaultKind::Transition => "transition",
            FaultKind::Send => "send",
            FaultKind::Checkpoint => "checkpoint",
            FaultKind::WorkerPanic => "worker_panic",
            FaultKind::DesiredRunState => "desired_run_state",
            FaultKind::Shutdown => "shutdown",
        }
    }
}

/// Who has to do something about a failure. See module doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    LocalIo,
    Remote,
    Integrity,
    Configuration,
    Cancelled,
}

impl FailureClass {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FailureClass::LocalIo => "local_io",
            FailureClass::Remote => "remote",
            FailureClass::Integrity => "integrity",
            FailureClass::Configuration => "configuration",
            FailureClass::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub fn from_download_error(error: &DownloadError) -> Self {
        classify_download_failure(error)
    }
}

/// One recorded defect in the coordinator's machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorFault {
    /// The job being driven when this happened, if any.
    pub job_id: Option<JobId>,
    pub kind: FaultKind,
    pub class: FailureClass,
    pub detail: String,
}

impl CoordinatorFault {
    #[must_use]
    pub fn new(
        job_id: Option<JobId>,
        kind: FaultKind,
        class: FailureClass,
        detail: impl Into<String>,
    ) -> Self {
        CoordinatorFault {
            job_id,
            kind,
            class,
            detail: detail.into(),
        }
    }
}

/// The single classification of a download failure. Deliberately separate
/// from `coordinator::classify_download_error`, which answers the *job
/// lifecycle* question ("which `FailureCode`, and may it be retried"): this
/// one answers the operational question, and the two must be able to
/// disagree (a hash mismatch is retryable *and* an integrity fault).
#[must_use]
pub fn classify_download_failure(error: &DownloadError) -> FailureClass {
    match error {
        DownloadError::HashMismatch { .. }
        | DownloadError::SizeMismatch { .. }
        | DownloadError::UnexpectedExtraBytes
        | DownloadError::ShortBody { .. }
        | DownloadError::RangeMismatch { .. }
        | DownloadError::Verification(_) => FailureClass::Integrity,
        DownloadError::SourceIo(_)
        | DownloadError::Source(_)
        | DownloadError::RangeNotSatisfiable
        | DownloadError::MalformedContentRange(_)
        | DownloadError::UnexpectedStatus(_)
        | DownloadError::TooManyRestarts => FailureClass::Remote,
        DownloadError::Io { .. } | DownloadError::Checkpoint(_) => FailureClass::LocalIo,
        DownloadError::PathSafety(_)
        | DownloadError::InvalidPlan(_)
        | DownloadError::Serialization(_) => FailureClass::Configuration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_failures_are_never_classified_as_a_network_blip() {
        assert_eq!(
            classify_download_failure(&DownloadError::HashMismatch {
                expected: "a".repeat(64),
                actual: "b".repeat(64),
            }),
            FailureClass::Integrity
        );
        assert_eq!(
            classify_download_failure(&DownloadError::Source("connection reset".to_string())),
            FailureClass::Remote
        );
        assert_eq!(
            classify_download_failure(&DownloadError::InvalidPlan("no files".to_string())),
            FailureClass::Configuration
        );
        assert_eq!(
            classify_download_failure(&DownloadError::Io {
                path: std::path::PathBuf::from("/tmp/x"),
                source: std::io::Error::other("disk"),
            }),
            FailureClass::LocalIo
        );
    }

    #[test]
    fn every_fault_kind_and_class_has_a_stable_name() {
        let kinds = [
            FaultKind::Transition,
            FaultKind::Send,
            FaultKind::Checkpoint,
            FaultKind::WorkerPanic,
            FaultKind::DesiredRunState,
            FaultKind::Shutdown,
        ];
        let names: Vec<&str> = kinds.iter().map(|k| k.name()).collect();
        assert_eq!(
            names,
            vec![
                "transition",
                "send",
                "checkpoint",
                "worker_panic",
                "desired_run_state",
                "shutdown"
            ]
        );
        let classes = [
            FailureClass::LocalIo,
            FailureClass::Remote,
            FailureClass::Integrity,
            FailureClass::Configuration,
            FailureClass::Cancelled,
        ];
        let names: Vec<&str> = classes.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            vec![
                "local_io",
                "remote",
                "integrity",
                "configuration",
                "cancelled"
            ]
        );
    }
}
