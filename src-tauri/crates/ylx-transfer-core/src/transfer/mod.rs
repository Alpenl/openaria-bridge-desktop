//! PC-00 transfer job state — plan section 5.4's single tagged job enum.
//!
//! Plan 5.4 (translated): "任务使用单一 tagged enum" ("a job uses a single
//! tagged enum"):
//!
//! ```text
//! queued
//! waiting_for_device
//! waiting_for_pairing
//! paused_capture_active
//! preparing
//! transferring
//! verifying
//! committing
//! retry_wait
//! cancelling
//! succeeded
//! failed(code, retryable)
//! cancelled
//! ```
//!
//! [`TransferJobState`] is that enum, verbatim: every variant here is a
//! plain unit variant except [`TransferJobState::Failed`], which alone
//! carries a payload — matching the plan text's own asymmetry (only
//! `failed(code, retryable)` has parentheses). Plan 5.4 also warns:
//! "网络失败、磁盘满、hash mismatch、对象存储拒绝和设备心跳失败是不同
//! error scope，不能统一改成 DeviceState::Error" ("network failure, disk
//! full, hash mismatch, object-store rejection, and device heartbeat
//! failure are different error scopes — they must not be collapsed into a
//! single `DeviceState::Error`"). This crate honors that split
//! structurally: [`TransferJobState::Failed`]'s `code` is a job-scoped
//! error classification (see [`FailureCode`]), completely separate from
//! [`crate::device::CaptureActivityState::Error`], which is the Pi's own
//! capture-activity domain and carries no code at all — the two error
//! notions are different enums in different modules on purpose.
//!
//! This is the real replacement for the W0-06 `TransferJobStub`
//! placeholder that used to live here.

use serde::{Deserialize, Serialize};

use crate::domain::{DeviceId, SessionId};

/// A job-scoped failure classification for [`TransferJobState::Failed`].
/// Deliberately its own enum, not a bare `String` — plan 5.4 explicitly
/// calls out that these are distinct error scopes that must not collapse
/// into one generic "error" bucket, and `retryable` (carried alongside
/// this on [`TransferJobState::Failed`], not baked into the code itself)
/// varies per *occurrence*, not per code, in general — e.g. a network
/// failure is usually retryable, but not always, so it stays a sibling
/// field rather than a fixed property of the code.
///
/// This is intentionally a small first-cut set covering the failure
/// classes plan 5.4 names explicitly, plus `Other` as an escape hatch for
/// anything a later task's real coordinator/adapter surfaces that doesn't
/// fit yet — kept open rather than guessed at exhaustively here, since
/// PC-03/PC-05 own the adapters that will actually produce these.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Network,
    DiskFull,
    HashMismatch,
    ObjectStoreRejected,
    DeviceHeartbeatFailed,
    Other(String),
}

/// The single tagged transfer-job state enum from plan section 5.4,
/// verbatim. Only [`TransferJobState::Failed`] carries a payload
/// (`code`/`retryable`); every other variant is a plain unit variant —
/// this makes "which fields exist" structurally obvious per state rather
/// than a struct with a pile of `Option` fields that could be
/// inconsistently populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransferJobState {
    Queued,
    WaitingForDevice,
    WaitingForPairing,
    PausedCaptureActive,
    Preparing,
    Transferring,
    Verifying,
    Committing,
    RetryWait,
    Cancelling,
    Succeeded,
    Failed { code: FailureCode, retryable: bool },
    Cancelled,
}

impl TransferJobState {
    /// True for states a real coordinator (PC-05) would never transition
    /// out of in place — a retry starts a fresh job rather than reviving
    /// this one. Mirrors `persistence::schema::JobStateTag::is_terminal`'s
    /// documented first-draft policy (see that module's doc comment); kept
    /// here too because this is the domain-level type PC-02/03/05 will
    /// actually hold in memory, not just the DB row shape.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransferJobState::Succeeded
                | TransferJobState::Failed { .. }
                | TransferJobState::Cancelled
        )
    }
}

/// A minimal identifying record for one transfer job: which device and
/// session it moves, plus its current tagged state. PC-01 (durable
/// journal) and PC-05 (coordinator) own the richer persisted/in-memory
/// shapes around this — this struct only fixes the "one job identifies a
/// (device, session) pair and carries one `TransferJobState`" invariant at
/// the domain layer, so those later tasks build on the same core shape
/// rather than each re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferJob {
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub state: TransferJobState,
}

/// PC-05 addition (additive, does not touch anything above): an opaque
/// coordinator-assigned job identifier, the same newtype-over-`String`
/// shape as [`DeviceId`]/[`SessionId`]/`FileId` (see `crate::domain`).
/// This is the primary key `TransferCoordinator` hands back from
/// `enqueue()` and expects on `pause`/`resume`/`retry`/`cancel` — distinct
/// from the durable transfer row's plain `String` job id (persistence
/// deliberately does not depend on `crate::domain`) only in that this wraps
/// the same value at the domain layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JobId(pub String);

impl JobId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Issue #1 commits 37–40: the single transition graph
/// ([`aggregate::is_legal_transition`]) over the [`TransferJobState`] enum
/// above, the pure [`aggregate::JobAggregate`] reducer, expected-version
/// CAS ([`aggregate::Effect::Commit`]) and the atomic
/// [`aggregate::JobSnapshot`]. `coordinator` performs what this module
/// decides; this module performs nothing itself.
pub mod aggregate;
/// PC-05: the durable `TransferCoordinator` (bounded-concurrency worker
/// pool, capture-priority pause, offline/pairing wait, crash recovery) —
/// see that module's doc comment for the full design. Owns/extends this
/// module additively; nothing above this point was restructured for it.
pub mod coordinator;
/// Typed coordinator faults and failure classification (issue #1 commit 48).
pub mod fault;
/// Byte-level job progress ([`JobProgress`]) — a read-only channel next to
/// [`TransferJobState`], deliberately *not* folded into that frozen tagged
/// enum. See the module doc comment for what `transferred_bytes` counts,
/// where a resume baseline comes from, and why it is monotonic.
pub mod progress;
/// PC-05: job-queue plumbing shared by `coordinator` and `recovery` —
/// `ManagedJob`/`TransferRequest`/`JobFile`, the
/// `TransferJobState`<->`persistence::JobStateTag` conversion, and the
/// interrupt-aware/checkpoint-throttling `DownloadSource` wrapper used to
/// implement capture-priority pause and cancel-waits-for-handle-close.
pub mod queue;
/// PC-05: `TransferCoordinator::recover_on_startup()` — enumerates complete
/// durable specs and file ledgers from `TransferStore`, then rehydrates
/// in-memory `ManagedJob`s and schedules the recoverable entries.
pub mod recovery;
/// Bounded ready-set queue used by the coordinator (issue #1 commit 47).
pub mod scheduler;

pub use aggregate::{
    is_legal_transition, CommandOutcome, Decision, DesiredRunState, DeviceReadiness,
    DeviceSnapshot, Effect, JobAggregate, JobCommand, JobFailure, JobSnapshot, RejectReason,
    TargetKey, TargetLease, TargetLeases, WorkerReport,
};
pub use fault::{classify_download_failure, CoordinatorFault, FailureClass, FaultKind};
pub use progress::{DiskBaseline, JobProgress, JobProgressTracker};

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Exact variant-list check (plan 5.4's literal enumeration)
    // -----------------------------------------------------------------

    #[test]
    fn transfer_job_state_has_exactly_the_plan_5_4_variants_in_order() {
        // Exhaustive match: adding/removing/renaming a variant upstream
        // fails to compile this test, not just an assertion at runtime.
        fn wire_tag(s: &TransferJobState) -> &'static str {
            match s {
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

        let plan_order = [
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
        ];
        let expected_tags = [
            "queued",
            "waiting_for_device",
            "waiting_for_pairing",
            "paused_capture_active",
            "preparing",
            "transferring",
            "verifying",
            "committing",
            "retry_wait",
            "cancelling",
            "succeeded",
            "failed",
            "cancelled",
        ];
        let actual_tags: Vec<&str> = plan_order.iter().map(wire_tag).collect();
        assert_eq!(actual_tags, expected_tags);
    }

    #[test]
    fn only_failed_carries_a_payload() {
        // Structural proof, not just an assertion: every other variant is
        // constructible with no arguments at all.
        let _: TransferJobState = TransferJobState::Queued;
        let _: TransferJobState = TransferJobState::WaitingForDevice;
        let _: TransferJobState = TransferJobState::WaitingForPairing;
        let _: TransferJobState = TransferJobState::PausedCaptureActive;
        let _: TransferJobState = TransferJobState::Preparing;
        let _: TransferJobState = TransferJobState::Transferring;
        let _: TransferJobState = TransferJobState::Verifying;
        let _: TransferJobState = TransferJobState::Committing;
        let _: TransferJobState = TransferJobState::RetryWait;
        let _: TransferJobState = TransferJobState::Cancelling;
        let _: TransferJobState = TransferJobState::Succeeded;
        let _: TransferJobState = TransferJobState::Cancelled;
        // Failed alone requires both fields — this is the "unrepresentable
        // to omit `retryable` on a failure" half of the plan 5.4 shape.
        let failed = TransferJobState::Failed {
            code: FailureCode::HashMismatch,
            retryable: false,
        };
        assert!(matches!(failed, TransferJobState::Failed { .. }));
    }

    #[test]
    fn terminal_states_match_succeeded_failed_cancelled_only() {
        assert!(!TransferJobState::Queued.is_terminal());
        assert!(!TransferJobState::Transferring.is_terminal());
        assert!(TransferJobState::Succeeded.is_terminal());
        assert!(TransferJobState::Cancelled.is_terminal());
        assert!(TransferJobState::Failed {
            code: FailureCode::Network,
            retryable: true,
        }
        .is_terminal());
    }

    // -----------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------

    #[test]
    fn every_variant_json_round_trips() {
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
            TransferJobState::Failed {
                code: FailureCode::ObjectStoreRejected,
                retryable: false,
            },
            TransferJobState::Cancelled,
        ];
        for value in values {
            let json = serde_json::to_string(&value).expect("serializes");
            let back: TransferJobState = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(back, value);
        }
    }

    #[test]
    fn failed_serializes_with_code_and_retryable_fields() {
        let value = TransferJobState::Failed {
            code: FailureCode::DiskFull,
            retryable: false,
        };
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["state"], "failed");
        assert_eq!(json["code"], "disk_full");
        assert_eq!(json["retryable"], false);
    }

    #[test]
    fn failure_code_other_carries_a_free_form_reason() {
        let value = FailureCode::Other("weird pi firmware quirk".to_string());
        let json = serde_json::to_string(&value).unwrap();
        let back: FailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn transfer_job_struct_round_trips() {
        let job = TransferJob {
            device_id: DeviceId("dev-1".to_string()),
            session_id: SessionId("sess-1".to_string()),
            state: TransferJobState::Transferring,
        };
        let json = serde_json::to_string(&job).unwrap();
        let back: TransferJob = serde_json::from_str(&json).unwrap();
        assert_eq!(back, job);
    }
}
