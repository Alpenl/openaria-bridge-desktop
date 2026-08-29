//! Download commit boundary.
//!
//! Network transfer and byte verification finish before this port is called,
//! but a download is not successful until its commit implementation has
//! published the complete local representation.  The default implementation
//! preserves the core crate's historical raw-session publication.  Desktop
//! production injects a deeper implementation that derives and validates the
//! canonical media bundle before making it visible.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::domain::PublicationScope;
use crate::library::download::{
    commit_staged_session, DownloadError, FilePlan, PublicationMaterial, PublicationVerifier,
    VerifiedFile, VerifyError,
};
use crate::library::staging::{SessionManifest, SessionStaging};

use super::coordinator::classify_download_error;
use super::queue::TransferRequest;
use super::{FailureCode, JobId};

/// Immutable, fully verified input supplied to the final download commit.
#[derive(Debug, Clone)]
pub struct DownloadCommitRequest {
    pub job_id: JobId,
    pub request: TransferRequest,
    pub publication_scope: PublicationScope,
    pub verified_files: Vec<VerifiedFile>,
    pub library_root: PathBuf,
}

/// A commit failure maps directly onto the coordinator's durable terminal
/// failure.  `retryable` belongs to the occurrence, not to the error class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadCommitFailure {
    pub code: FailureCode,
    pub retryable: bool,
}

/// Successful result of the final download commit boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DownloadCommitOutcome;

/// Result of racing a user cancellation against the canonical publication
/// commit point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadCommitCancelOutcome {
    Requested,
    AlreadyRequested,
    Irreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadCommitControlState {
    Cancellable,
    CancelRequested,
    Irreversible,
}

/// One job's cancellation/publication gate.
///
/// Preparation and media export remain cancellable. The final canonical
/// publication must call [`Self::begin_irreversible`] immediately before its
/// first visible rename. `request_cancel` and `begin_irreversible` serialize
/// on the same mutex, so exactly one side wins: either cancellation prevents
/// publication, or publication owns the terminal outcome and cancellation is
/// rejected as too late.
#[derive(Debug)]
pub struct DownloadCommitControl {
    state: Mutex<DownloadCommitControlState>,
}

impl Default for DownloadCommitControl {
    fn default() -> Self {
        Self {
            state: Mutex::new(DownloadCommitControlState::Cancellable),
        }
    }
}

impl DownloadCommitControl {
    #[must_use]
    pub fn request_cancel(&self) -> DownloadCommitCancelOutcome {
        let mut state = self.state.lock().unwrap();
        match *state {
            DownloadCommitControlState::Cancellable => {
                *state = DownloadCommitControlState::CancelRequested;
                DownloadCommitCancelOutcome::Requested
            }
            DownloadCommitControlState::CancelRequested => {
                DownloadCommitCancelOutcome::AlreadyRequested
            }
            DownloadCommitControlState::Irreversible => DownloadCommitCancelOutcome::Irreversible,
        }
    }

    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        *self.state.lock().unwrap() == DownloadCommitControlState::CancelRequested
    }

    /// Claims the irreversible publication point, or fails if cancellation
    /// already won the race.
    pub fn begin_irreversible(&self) -> Result<(), DownloadCommitFailure> {
        let mut state = self.state.lock().unwrap();
        match *state {
            DownloadCommitControlState::Cancellable => {
                *state = DownloadCommitControlState::Irreversible;
                Ok(())
            }
            DownloadCommitControlState::CancelRequested => Err(DownloadCommitFailure::cancelled()),
            DownloadCommitControlState::Irreversible => Ok(()),
        }
    }
}

impl DownloadCommitOutcome {
    #[must_use]
    pub const fn clean() -> Self {
        Self
    }
}

impl DownloadCommitFailure {
    #[must_use]
    pub fn new(code: FailureCode, retryable: bool) -> Self {
        Self { code, retryable }
    }

    #[must_use]
    pub fn retryable(detail: impl Into<String>) -> Self {
        Self::new(FailureCode::Other(detail.into()), true)
    }

    #[must_use]
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self::new(FailureCode::Other(detail.into()), false)
    }

    #[must_use]
    pub fn cancelled() -> Self {
        Self::permanent("download commit cancelled before canonical publication")
    }
}

/// Finalizes a verified download.  Returning `Ok` is the only event that can
/// move the owning transfer job from `committing` to `succeeded`.
pub trait DownloadCommitPort: Send + Sync {
    fn commit(
        &self,
        request: &DownloadCommitRequest,
    ) -> Result<DownloadCommitOutcome, DownloadCommitFailure>;

    /// Cancellable production entry point. Implementations with expensive
    /// preparation override this and defer `begin_irreversible` until the
    /// exact canonical publication boundary. Compatibility implementations
    /// treat their existing atomic commit as irreversible from entry.
    fn commit_cancellable(
        &self,
        request: &DownloadCommitRequest,
        control: &DownloadCommitControl,
    ) -> Result<DownloadCommitOutcome, DownloadCommitFailure> {
        control.begin_irreversible()?;
        self.commit(request)
    }
}

/// Compatibility committer used by `TransferCoordinator::new`.  Applications
/// that require a derived canonical representation inject their own port via
/// `TransferCoordinator::new_with_commit_port`.
pub struct RawSessionCommitter {
    verifier: Arc<dyn PublicationVerifier>,
}

impl RawSessionCommitter {
    #[must_use]
    pub fn new(verifier: Arc<dyn PublicationVerifier>) -> Self {
        Self { verifier }
    }
}

impl DownloadCommitPort for RawSessionCommitter {
    fn commit(
        &self,
        input: &DownloadCommitRequest,
    ) -> Result<DownloadCommitOutcome, DownloadCommitFailure> {
        let request = &input.request;
        let staging = SessionStaging::for_publication(
            &input.library_root,
            request.device_id.as_str(),
            request.session_id.as_str(),
            &request.manifest_bytes,
        )
        .map_err(DownloadError::from)
        .map_err(map_download_error)?;
        let plans: Vec<FilePlan> = request
            .files
            .iter()
            .map(|file| FilePlan {
                device_id: request.device_id.as_str().to_string(),
                session_id: request.session_id.as_str().to_string(),
                file_id: file.file_id.as_str().to_string(),
                target_relative_path: file.target_relative_path.clone(),
                expected_size: file.expected_size,
                expected_sha256_hex: file.expected_sha256_hex.clone(),
            })
            .collect();
        let manifest = SessionManifest::from_plans(
            request.device_id.as_str(),
            request.session_id.as_str(),
            &plans,
        );

        commit_staged_session(
            &staging,
            request.device_id.as_str().to_string(),
            request.session_id.as_str().to_string(),
            input.verified_files.clone(),
            &manifest,
            PublicationMaterial {
                payload: &request.manifest_bytes,
                signature: &request.signature,
                public_key: &request.publication_public_key,
            },
            self.verifier.as_ref(),
            input.publication_scope,
        )
        .map(|_| DownloadCommitOutcome::clean())
        .map_err(map_download_error)
    }
}

fn map_download_error(error: DownloadError) -> DownloadCommitFailure {
    if let DownloadError::Verification(VerifyError::Rejected(message)) = &error {
        return DownloadCommitFailure::permanent(format!(
            "publication verification failed: {message}"
        ));
    }
    let (code, retryable) = classify_download_error(&error);
    DownloadCommitFailure::new(code, retryable)
}
