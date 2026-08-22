//! PC-05: job-queue plumbing for [`super::coordinator::TransferCoordinator`].
//!
//! This module owns three things:
//!
//! 1. [`ManagedJob`]/[`TransferRequest`]/[`JobFile`] — the richer
//!    in-memory job shape `transfer::mod`'s doc comment says PC-05 would
//!    build on top of the minimal [`super::TransferJob`] (device_id/
//!    session_id/state only). `ManagedJob` wraps a `TransferRequest`
//!    (the durable input) plus the live `TransferJobState` and, once
//!    downloaded, the [`VerifiedFile`]s a commit needs.
//! 2. [`state_to_tag`]/[`tag_to_state`] — the `TransferJobState` (domain,
//!    what the coordinator reasons about, `Failed{code,retryable}` as one
//!    payload-carrying variant) <-> `persistence::JobStateTag` (DB row
//!    shape, a bare tag plus separate `error_code`/`error_retryable`
//!    columns) conversion the task card asks for. `FailureCode` itself
//!    has no natural DB column, so [`failure_code_to_db`]/
//!    [`failure_code_from_db`] give it a small stable string encoding
//!    (`"network"`, `"disk_full"`, ..., `"other:<message>"`).
//! 3. [`TrackingSource`] — a [`DownloadSource`] decorator (wraps another
//!    `DownloadSource`, never modifies `library::download`'s own code)
//!    that does two things on every byte read from a file's response
//!    body: (a) checks a shared interrupt flag and bails with a
//!    recognizable marker error if set — this is how capture-priority
//!    pause and cancel actually stop an in-flight `download_file` call
//!    *and* guarantee its `.part` file handle is closed before the
//!    coordinator observes the interruption (`download_file`'s own
//!    `write_response_body` always drops its `File` on any return path,
//!    Ok or Err, before returning — see that function's doc comment); (b)
//!    throttles durable `TransferStore` file-ledger writes to at
//!    most once per [`TrackingSource`]'s configured byte threshold,
//!    rather than on every ~64KB chunk `download_file` reads internally
//!    (task item 4 — "don't fsync every 150ms").

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::domain::{
    DeviceId, FileId, JobFileSpec, JobIdentity, JobSpec, JobSpecError, PublicationMaterial,
    PublicationScope, SessionId,
};
use crate::library::download::{DownloadError, DownloadSource, RequestedRange, SourceResponse};
use crate::persistence::transfer_store::TransferStore;
use crate::persistence::{FileLedgerStatus, JobStateTag};

use super::progress::JobProgressTracker;
use super::{DesiredRunState, FailureCode, JobId, TransferJobState};

// =====================================================================
// Job shapes
// =====================================================================

/// One file this job must download, identified by its opaque API ID plus
/// the size/hash and human-readable relative path supplied by the verified
/// signed publication payload. Mirrors `library::download::FilePlan`
/// field-for-field, kept
/// as a separate type here (rather than reusing `FilePlan` directly)
/// because `TransferRequest`/`ManagedJob` are also used in serializable test
/// fixtures and `FilePlan` is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobFile {
    pub file_id: FileId,
    /// Pi publication `display_path`, relative to the session directory.
    /// `None` is only the backwards-compatible representation of jobs
    /// persisted before this field existed; those jobs safely fall back to
    /// the opaque `file_id` as their local filename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_relative_path: Option<String>,
    pub expected_size: u64,
    /// Lowercase hex-encoded SHA-256, exactly 64 characters.
    pub expected_sha256_hex: String,
}

/// What a caller hands `TransferCoordinator::enqueue`: everything needed
/// to durably identify and eventually drive one logical transfer.
/// Publication material is verified before the coordinator persists this
/// request, rechecked before a recovered job opens a download source, and
/// checked again at atomic session commit.
/// `idempotency_key` is retained as a request-level label; durable natural
/// identity and request-digest conflict handling are owned by
/// `TransferStore::create_job`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferRequest {
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub revision: String,
    pub idempotency_key: String,
    pub files: Vec<JobFile>,
    /// Exact canonical publication payload bytes and detached Ed25519
    /// signature supplied by the authenticated Pi session-detail response.
    /// Production verifiers reject missing or malformed material.
    #[serde(default)]
    pub manifest_bytes: Vec<u8>,
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Raw 32-byte Ed25519 publication public key. `serde(default)` keeps
    /// old request fixtures readable; the production verifier rejects
    /// missing or malformed material instead of trusting it.
    #[serde(default)]
    pub publication_public_key: Vec<u8>,
}

impl TransferRequest {
    /// Builds the complete immutable spec that must exist before a runtime
    /// job is installed. Composition can pass the real display label and
    /// full-session flag; the compatibility enqueue path supplies defaults.
    pub fn to_job_spec(
        &self,
        full_session: bool,
        date_label: impl Into<String>,
    ) -> Result<JobSpec, JobSpecError> {
        let identity = JobIdentity::new(
            self.device_id.clone(),
            self.session_id.clone(),
            self.revision.clone(),
        )?;
        let publication = PublicationMaterial::new(
            self.revision.clone(),
            self.manifest_bytes.clone(),
            self.signature.clone(),
            self.publication_public_key.clone(),
        )?;
        let session_files = self
            .files
            .iter()
            .map(|file| {
                JobFileSpec::new(
                    file.file_id.clone(),
                    file.target_relative_path
                        .clone()
                        .unwrap_or_else(|| file.file_id.as_str().to_string()),
                    file.expected_size,
                    file.expected_sha256_hex.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let requested = self
            .files
            .iter()
            .map(|file| file.file_id.clone())
            .collect::<Vec<_>>();
        JobSpec::new(
            identity,
            publication,
            session_files,
            &requested,
            full_session,
            date_label,
        )
    }
}

/// Rehydrates the execution shape from the durable spec without consulting
/// a request sidecar. The job id itself is supplied by the caller when it
/// needs a retry-specific idempotency label; the stable natural identity is
/// sufficient for coordinator-internal recovery.
pub fn request_from_spec(spec: &JobSpec) -> TransferRequest {
    TransferRequest {
        device_id: spec.identity().device_id().clone(),
        session_id: spec.identity().session_id().clone(),
        revision: spec.identity().revision().to_string(),
        idempotency_key: spec.identity().natural_key(),
        files: spec
            .requested_files()
            .map(|file| JobFile {
                file_id: file.file_id().clone(),
                target_relative_path: Some(file.display_path().to_string()),
                expected_size: file.size_bytes(),
                expected_sha256_hex: file.sha256().to_string(),
            })
            .collect(),
        manifest_bytes: spec.publication().payload().to_vec(),
        signature: spec.publication().signature().to_vec(),
        publication_public_key: spec.publication().public_key().to_vec(),
    }
}

/// The richer, PC-05-owned in-memory job record `transfer::mod`'s doc
/// comment on [`super::TransferJob`] says a later task would build here.
/// Kept separate from `super::TransferJob` itself (rather than replacing
/// it) per that struct's own doc comment; `ManagedJob` is additive.
#[derive(Debug, Clone)]
pub struct ManagedJob {
    pub job_id: JobId,
    pub request: TransferRequest,
    pub state: TransferJobState,
    /// The publication unit is derived from the durable `JobSpec` and kept
    /// beside the runtime request because `TransferRequest` intentionally
    /// contains only the selected network files. Recovery must never infer a
    /// full-session publication from that shortened list.
    pub publication_scope: PublicationScope,
    /// Durable user intent, published only after `TransferStore` accepts
    /// the corresponding `SetDesiredRunState` effect. Keeping it beside the
    /// execution state makes the in-memory aggregate match the durable row;
    /// it is deliberately not a worker control flag.
    pub desired_run_state: DesiredRunState,
    /// Filled in once `run_transfer` finishes every file successfully;
    /// consumed by the `committing` phase's `commit_session` call.
    pub verified_files: Vec<crate::library::download::VerifiedFile>,
}

// =====================================================================
// TransferJobState <-> JobStateTag (+ error columns) conversion
// =====================================================================

/// Domain `TransferJobState` -> the `(JobStateTag, Option<(error_code,
/// retryable)>)` shape `TransferStore::transition_job` accepts. Only
/// `Failed` ever produces `Some(..)` for the error half — matches
/// `transition_job`'s own enforced invariant ("error must be Some(..)
/// iff transitioning to Failed").
#[must_use]
pub fn state_to_tag(state: &TransferJobState) -> (JobStateTag, Option<(String, bool)>) {
    match state {
        TransferJobState::Queued => (JobStateTag::Queued, None),
        TransferJobState::WaitingForDevice => (JobStateTag::WaitingForDevice, None),
        TransferJobState::WaitingForPairing => (JobStateTag::WaitingForPairing, None),
        TransferJobState::PausedCaptureActive => (JobStateTag::PausedCaptureActive, None),
        TransferJobState::Preparing => (JobStateTag::Preparing, None),
        TransferJobState::Transferring => (JobStateTag::Transferring, None),
        TransferJobState::Verifying => (JobStateTag::Verifying, None),
        TransferJobState::Committing => (JobStateTag::Committing, None),
        TransferJobState::RetryWait => (JobStateTag::RetryWait, None),
        TransferJobState::Cancelling => (JobStateTag::Cancelling, None),
        TransferJobState::Succeeded => (JobStateTag::Succeeded, None),
        TransferJobState::Failed { code, retryable } => (
            JobStateTag::Failed,
            Some((failure_code_to_db(code), *retryable)),
        ),
        TransferJobState::Cancelled => (JobStateTag::Cancelled, None),
    }
}

/// The inverse of [`state_to_tag`]: a DB row's `(JobStateTag,
/// Option<(error_code, retryable)>)` -> domain `TransferJobState`.
/// Panics if `tag == Failed` but `error` is `None` (or vice versa) —
/// `TransferStore`'s own `CHECK` constraints and `transition_job` already
/// make that combination unreachable for any row this crate wrote, so a
/// panic here means a real data-integrity bug worth surfacing loudly
/// rather than silently downgrading to some other state.
#[must_use]
pub fn tag_to_state(tag: JobStateTag, error: Option<(String, bool)>) -> TransferJobState {
    match tag {
        JobStateTag::Queued => TransferJobState::Queued,
        JobStateTag::WaitingForDevice => TransferJobState::WaitingForDevice,
        JobStateTag::WaitingForPairing => TransferJobState::WaitingForPairing,
        JobStateTag::PausedCaptureActive => TransferJobState::PausedCaptureActive,
        JobStateTag::Preparing => TransferJobState::Preparing,
        JobStateTag::Transferring => TransferJobState::Transferring,
        JobStateTag::Verifying => TransferJobState::Verifying,
        JobStateTag::Committing => TransferJobState::Committing,
        JobStateTag::RetryWait => TransferJobState::RetryWait,
        JobStateTag::Cancelling => TransferJobState::Cancelling,
        JobStateTag::Succeeded => TransferJobState::Succeeded,
        JobStateTag::Failed => {
            let (code_str, retryable) =
                error.expect("JobStateTag::Failed row must carry (error_code, error_retryable)");
            TransferJobState::Failed {
                code: failure_code_from_db(&code_str),
                retryable,
            }
        }
        JobStateTag::Cancelled => TransferJobState::Cancelled,
    }
}

fn failure_code_to_db(code: &FailureCode) -> String {
    match code {
        FailureCode::Network => "network".to_string(),
        FailureCode::DiskFull => "disk_full".to_string(),
        FailureCode::HashMismatch => "hash_mismatch".to_string(),
        FailureCode::ObjectStoreRejected => "object_store_rejected".to_string(),
        FailureCode::DeviceHeartbeatFailed => "device_heartbeat_failed".to_string(),
        FailureCode::Other(msg) => format!("other:{msg}"),
    }
}

fn failure_code_from_db(s: &str) -> FailureCode {
    match s {
        "network" => FailureCode::Network,
        "disk_full" => FailureCode::DiskFull,
        "hash_mismatch" => FailureCode::HashMismatch,
        "object_store_rejected" => FailureCode::ObjectStoreRejected,
        "device_heartbeat_failed" => FailureCode::DeviceHeartbeatFailed,
        other => FailureCode::Other(other.strip_prefix("other:").unwrap_or(other).to_string()),
    }
}

// =====================================================================
// Interrupt / checkpoint-throttling DownloadSource decorator
// =====================================================================

/// Why an in-flight transfer was interrupted — read back by the
/// coordinator after `download_file` returns the marker error, to decide
/// which state the job actually lands in (`paused_capture_active` /
/// `retry_wait` for a user pause / `cancelled`, never `failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptReason {
    CapturePause,
    UserPause,
    Cancel,
    /// Commit 46: the device this job is reading from stopped being usable
    /// (disconnected, expired, or back in pairing) *while* the transfer was
    /// in flight. Before this existed an active transfer only noticed at
    /// the next file boundary, if at all.
    DeviceLost,
    /// Commit 50: the coordinator is shutting down. Unlike every other
    /// reason this one deliberately commits no transition — startup
    /// reconciliation owns what an interrupted `transferring` row becomes.
    Shutdown,
}

/// Per-job control block shared between `TransferCoordinator`'s public
/// API (`pause`/`resume`/`cancel`) and whichever worker thread currently
/// owns the job. `active` is the mutual-exclusion flag ("a worker is
/// currently inside `process_job` for this job right now") that `cancel`
/// polls on to know the in-flight file handle has actually closed before
/// declaring the job `cancelled` — see `coordinator.rs`'s doc comment.
#[derive(Debug, Default)]
pub struct JobControl {
    pub active: AtomicBool,
    pub interrupt_flag: AtomicBool,
    pub interrupt_reason: Mutex<Option<InterruptReason>>,
    checkpoint_fault: Mutex<Option<String>>,
}

impl JobControl {
    /// Commit 49: take ownership of this job, or `None` if another worker
    /// already has it. The returned guard clears `active` when it drops —
    /// including while a panic unwinds, which is what stops a panicking
    /// worker from stranding a job as permanently "active" (and every
    /// `cancel`/`pause` waiting on it from timing out forever).
    pub fn try_claim(self: &Arc<Self>) -> Option<ActiveLease> {
        self.active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| ActiveLease {
                control: self.clone(),
            })
    }

    pub fn request_interrupt(&self, reason: InterruptReason) {
        *self.interrupt_reason.lock().unwrap() = Some(reason);
        self.interrupt_flag.store(true, Ordering::SeqCst);
    }

    pub fn clear_interrupt(&self) {
        self.interrupt_flag.store(false, Ordering::SeqCst);
        *self.interrupt_reason.lock().unwrap() = None;
    }

    pub fn current_interrupt_reason(&self) -> Option<InterruptReason> {
        *self.interrupt_reason.lock().unwrap()
    }

    /// Record a checkpoint failure without making the download path panic.
    /// The coordinator consumes this after the worker effect returns and
    /// turns it into a typed `CoordinatorFault` (commit 48).
    pub(crate) fn record_checkpoint_fault(&self, detail: impl Into<String>) {
        let mut fault = self.checkpoint_fault.lock().unwrap();
        if fault.is_none() {
            *fault = Some(detail.into());
        }
    }

    pub(crate) fn take_checkpoint_fault(&self) -> Option<String> {
        self.checkpoint_fault.lock().unwrap().take()
    }
}

/// RAII proof that its holder is the worker currently driving one job.
/// See [`JobControl::try_claim`].
#[derive(Debug)]
pub struct ActiveLease {
    control: Arc<JobControl>,
}

impl ActiveLease {
    #[must_use]
    pub fn control(&self) -> &Arc<JobControl> {
        &self.control
    }
}

impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.control.active.store(false, Ordering::SeqCst);
    }
}

/// Substring [`TrackingSource`]/[`TrackingBody`] embed in the
/// `DownloadError` they synthesize on interruption, so
/// [`is_interrupt_error`] can recognize "we did this on purpose" without
/// `library::download` needing any awareness that PC-05 exists.
pub const INTERRUPT_MARKER: &str = "__ylx_pc05_interrupt__";

#[must_use]
pub fn is_interrupt_error(err: &DownloadError) -> bool {
    match err {
        DownloadError::SourceIo(s) | DownloadError::Source(s) => s.contains(INTERRUPT_MARKER),
        _ => false,
    }
}

/// A [`DownloadSource`] decorator: wraps another `DownloadSource` (a real
/// `PiDownloadSource` in production, or a test fake) and adds interrupt-
/// checking plus throttled `TransferStore` file-ledger persistence on every
/// byte read from a response body. See module doc comment for the full
/// rationale.
pub struct TrackingSource {
    pub inner: Box<dyn DownloadSource>,
    pub control: Arc<JobControl>,
    pub transfer_store: Arc<Mutex<TransferStore>>,
    pub job_id: String,
    pub file_id: String,
    pub expected_size: u64,
    pub expected_sha256_hex: String,
    /// Checkpoint at most once per this many new bytes read for a single
    /// file (task item 4's "every fixed byte chunk" option).
    pub checkpoint_threshold_bytes: u64,
    /// Byte-level progress for the *job* this file belongs to, if the
    /// caller wants one (`TransferCoordinator` always does; a bare
    /// `TrackingSource` in a test need not). `Option` so this decorator
    /// stays usable without a coordinator.
    pub progress: Option<Arc<JobProgressTracker>>,
}

impl DownloadSource for TrackingSource {
    fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
        if self.control.interrupt_flag.load(Ordering::SeqCst) {
            return Err(DownloadError::Source(INTERRUPT_MARKER.to_string()));
        }
        let start = request.start;
        let resp = self.inner.fetch_range(request)?;
        // Where this response's bytes actually land in the file, per
        // `library::download`'s own interpretation of the status code: a
        // `206` continues at the requested offset, while a `200` means
        // "restart at byte 0, never append" no matter what was requested
        // (see `interpret_range_response` / `RangeOutcome::FullFromZero`).
        // Any other status carries no body worth counting.
        let effective_start = match resp.status {
            200 => Some(0),
            206 => Some(start),
            _ => None,
        };
        if let (Some(progress), Some(offset)) = (self.progress.as_ref(), effective_start) {
            progress.set_current_file_offset(offset);
        }
        let body = TrackingBody {
            inner: resp.body,
            control: self.control.clone(),
            transfer_store: self.transfer_store.clone(),
            job_id: self.job_id.clone(),
            file_id: self.file_id.clone(),
            offset: effective_start.unwrap_or(start),
            bytes_since_checkpoint: 0,
            threshold: self.checkpoint_threshold_bytes.max(1),
            progress: self.progress.clone(),
        };
        Ok(SourceResponse {
            body: Box::new(body),
            ..resp
        })
    }
}

struct TrackingBody {
    inner: Box<dyn Read + Send>,
    control: Arc<JobControl>,
    transfer_store: Arc<Mutex<TransferStore>>,
    job_id: String,
    file_id: String,
    offset: u64,
    bytes_since_checkpoint: u64,
    threshold: u64,
    progress: Option<Arc<JobProgressTracker>>,
}

impl Read for TrackingBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.control.interrupt_flag.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, INTERRUPT_MARKER));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.offset += n as u64;
            self.bytes_since_checkpoint += n as u64;
            // Unthrottled (a relaxed atomic store, no I/O) — unlike the
            // durable checkpoint below, which stays throttled.
            if let Some(progress) = self.progress.as_ref() {
                progress.set_current_file_offset(self.offset);
            }
            if self.bytes_since_checkpoint >= self.threshold {
                self.bytes_since_checkpoint = 0;
                // A checkpoint failure does not corrupt bytes already on
                // disk, so the worker may finish the file, but it must not
                // disappear. The coordinator records it as a typed fault
                // after this body is dropped (commit 48).
                match self.transfer_store.lock() {
                    Ok(mut store) => {
                        if let Err(error) = store.update_file_ledger(
                            &self.job_id,
                            &FileId(self.file_id.clone()),
                            FileLedgerStatus::Partial,
                            self.offset,
                            None,
                            &now_string(),
                        ) {
                            self.control.record_checkpoint_fault(error.to_string());
                        }
                    }
                    Err(_) => self
                        .control
                        .record_checkpoint_fault("checkpoint transfer store mutex poisoned"),
                }
            }
        }
        Ok(n)
    }
}

/// A monotonically-increasing-enough timestamp for the transfer store's
/// plain-`TEXT` columns. Nanoseconds-since-epoch, not RFC 3339 — this crate
/// has no date/time dependency and the persistence layer stores and returns
/// the value without parsing it.
pub(crate) fn now_string() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:09}", dur.as_secs(), dur.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_to_tag_and_back_round_trips_every_variant() {
        let values = vec![
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
            TransferJobState::Cancelled,
            TransferJobState::Failed {
                code: FailureCode::Network,
                retryable: true,
            },
            TransferJobState::Failed {
                code: FailureCode::DiskFull,
                retryable: false,
            },
            TransferJobState::Failed {
                code: FailureCode::HashMismatch,
                retryable: true,
            },
            TransferJobState::Failed {
                code: FailureCode::ObjectStoreRejected,
                retryable: false,
            },
            TransferJobState::Failed {
                code: FailureCode::DeviceHeartbeatFailed,
                retryable: true,
            },
            TransferJobState::Failed {
                code: FailureCode::Other("weird pi firmware quirk".to_string()),
                retryable: false,
            },
        ];
        for value in values {
            let (tag, error) = state_to_tag(&value);
            let back = tag_to_state(tag, error);
            assert_eq!(back, value, "round trip failed for {value:?}");
        }
    }

    #[test]
    fn request_from_selected_spec_preserves_scope_independently_of_file_count() {
        let request = TransferRequest {
            device_id: crate::domain::DeviceId("dev-1".to_string()),
            session_id: crate::domain::SessionId("sess-1".to_string()),
            revision: "rev-1".to_string(),
            idempotency_key: "selected-job".to_string(),
            files: vec![JobFile {
                file_id: crate::domain::FileId("f1".to_string()),
                target_relative_path: None,
                expected_size: 3,
                expected_sha256_hex: "a".repeat(64),
            }],
            manifest_bytes: vec![1],
            signature: vec![2; 64],
            publication_public_key: vec![3; 32],
        };
        let spec = request
            .to_job_spec(false, "2026-08-01")
            .expect("selected spec");
        assert_eq!(spec.publication_scope(), PublicationScope::SelectedFiles);
        let restored = request_from_spec(&spec);
        assert_eq!(restored.files.len(), 1);
        assert_eq!(restored.files[0].file_id.as_str(), "f1");
        assert_eq!(
            restored.files[0].target_relative_path.as_deref(),
            Some("f1")
        );
    }

    #[test]
    fn only_failed_tag_carries_error_columns() {
        let (tag, error) = state_to_tag(&TransferJobState::Queued);
        assert_eq!(tag, JobStateTag::Queued);
        assert!(error.is_none());

        let (tag, error) = state_to_tag(&TransferJobState::Failed {
            code: FailureCode::Network,
            retryable: true,
        });
        assert_eq!(tag, JobStateTag::Failed);
        assert_eq!(error, Some(("network".to_string(), true)));
    }

    #[test]
    fn is_interrupt_error_recognizes_the_marker_and_nothing_else() {
        let interrupted = DownloadError::Source(INTERRUPT_MARKER.to_string());
        assert!(is_interrupt_error(&interrupted));

        let real_source_error = DownloadError::Source("connection reset".to_string());
        assert!(!is_interrupt_error(&real_source_error));

        let hash_mismatch = DownloadError::HashMismatch {
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        };
        assert!(!is_interrupt_error(&hash_mismatch));
    }

    // -----------------------------------------------------------------
    // TrackingSource is itself a DownloadSource, and in production it is
    // the one the engine actually talks to (it wraps `PiDownloadSource`).
    // A decorator that dropped or rewrote a 412/416 would defeat the
    // adapter's fidelity just as thoroughly, so it runs the same shared
    // contract suite (issue #1, commit 10).
    // -----------------------------------------------------------------

    mod contract {
        use super::*;
        use crate::library::download::SourceResponse;
        use crate::library::download_contract::{
            assert_download_source_contract, contract_total, ContractCase,
            DownloadSourceContractHarness, CONTRACT_BODY, CONTRACT_ETAG, CONTRACT_RESUME_START,
        };

        /// The smallest possible `DownloadSource`: answers one scripted
        /// response, so the only thing under test is the decorator.
        struct ScriptedSource(Mutex<Option<SourceResponse>>);

        impl DownloadSource for ScriptedSource {
            fn fetch_range(
                &self,
                _request: RequestedRange,
            ) -> Result<SourceResponse, DownloadError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .take()
                    .expect("scripted source called twice"))
            }
        }

        struct TrackingSourceContractHarness {
            _dir: tempfile::TempDir,
            transfer_store: Arc<Mutex<TransferStore>>,
        }

        impl TrackingSourceContractHarness {
            fn new() -> Self {
                let dir = tempfile::tempdir().expect("tempdir");
                let transfer_store = TransferStore::open(dir.path().join("jobs.sqlite3"))
                    .expect("open transfer store");
                TrackingSourceContractHarness {
                    _dir: dir,
                    transfer_store: Arc::new(Mutex::new(transfer_store)),
                }
            }
        }

        impl DownloadSourceContractHarness for TrackingSourceContractHarness {
            fn name(&self) -> &str {
                "transfer::queue::TrackingSource"
            }

            fn source_for(&self, case: ContractCase) -> Box<dyn DownloadSource> {
                let total = contract_total();
                let inner = match case {
                    ContractCase::FullFromZero => SourceResponse {
                        status: 200,
                        etag: Some(CONTRACT_ETAG.to_string()),
                        content_range: None,
                        content_length: Some(total),
                        body: Box::new(io::Cursor::new(CONTRACT_BODY.to_vec())),
                    },
                    ContractCase::PartialFromOffset => SourceResponse {
                        status: 206,
                        etag: Some(CONTRACT_ETAG.to_string()),
                        content_range: Some(format!(
                            "bytes {}-{}/{}",
                            CONTRACT_RESUME_START,
                            total - 1,
                            total
                        )),
                        content_length: Some(total - CONTRACT_RESUME_START),
                        body: Box::new(io::Cursor::new(
                            CONTRACT_BODY[CONTRACT_RESUME_START as usize..].to_vec(),
                        )),
                    },
                    ContractCase::PreconditionFailed => SourceResponse {
                        status: 412,
                        etag: None,
                        content_range: None,
                        content_length: None,
                        body: Box::new(io::empty()),
                    },
                    ContractCase::RangeNotSatisfiable => SourceResponse {
                        status: 416,
                        etag: None,
                        content_range: Some(format!("bytes */{total}")),
                        content_length: None,
                        body: Box::new(io::empty()),
                    },
                };

                Box::new(TrackingSource {
                    inner: Box::new(ScriptedSource(Mutex::new(Some(inner)))),
                    control: Arc::new(JobControl::default()),
                    transfer_store: self.transfer_store.clone(),
                    job_id: "job-contract".to_string(),
                    file_id: "file-contract".to_string(),
                    expected_size: total,
                    expected_sha256_hex: "0".repeat(64),
                    checkpoint_threshold_bytes: 8,
                    progress: None,
                })
            }
        }

        #[test]
        fn tracking_source_decorator_satisfies_the_download_source_contract() {
            assert_download_source_contract(&TrackingSourceContractHarness::new());
        }
    }
}
