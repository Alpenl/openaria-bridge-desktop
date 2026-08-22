//! PC-00 device state — plan section 5.4's three *orthogonal* device state
//! domains, as real Rust enums.
//!
//! Plan section 5.4 (translated): "设备的三个状态域必须正交" ("a device's
//! three state domains must be orthogonal") — discovery, connection, and
//! capture activity are independent axes, not one combined state machine.
//! [`Device`] combines all three (plus identity) into one struct, but each
//! axis's enum can only ever hold values for its own domain: it is a
//! *compile* error, not a runtime validation failure, to try to construct
//! e.g. a "connected" state carrying a pairing `attempt_id` — see the
//! `tests` module for that property demonstrated directly.
//!
//! This is the real replacement for the W0-06 `DeviceStub` placeholder
//! that used to live here; [`crate::transfer::TransferJobState`] is the
//! sibling per-job enum PC-02/PC-05 build actor/coordinator logic on top
//! of.

use serde::{Deserialize, Serialize};

use crate::domain::DeviceId;

/// PC-02's per-device actor (connection lifecycle owner) and its split
/// capability ports. Lives in its own submodule since it is substantially
/// larger than the plain state types above; re-exported from here so callers
/// do not need to know the file split.
pub mod actor;
/// Commits 57/58/59: [`fleet::DeviceFleet`] — per-device handles, so the
/// registry lock only ever covers a map lookup/insert and per-device
/// network I/O runs with no lock held at all. This is the only device
/// registry there is; the older `DeviceActorRegistry`, which handed out
/// `&mut DeviceActor` borrows and so forced every caller to hold one
/// process-wide lock across its network calls, is gone.
pub mod fleet;
/// Canonical full-fingerprint identity, its purpose-specific projections,
/// and compatibility resolution for legacy short aliases.
pub mod identity;
pub use fleet::{
    ActorGuard, DeleteApplyOutcome, DeviceFleet, DeviceHandle, DeviceSnapshot, EpochTicket,
    FleetHeartbeatReport, HeartbeatTicket, PairingTicket, RefreshApplyOutcome,
    SessionDetailOutcome,
};
pub use identity::{
    DeviceFingerprint, DeviceFingerprintParseError, DeviceIdentity, DeviceIdentityResolutionError,
    DeviceIdentityResolver, StoredDeviceIdentity,
};

pub use actor::{
    AuthenticatedCatalogPort, AuthenticatedDevicePort, AuthenticatedPiSession,
    AuthenticatedPiSessionError, ByteRangeRequest, DeleteSessionReceiptView, DeviceActor,
    DeviceInfoView, DownloadTransportPort, FileDownloadView, FileHeadView, FileStreamView,
    HeartbeatApplyOutcome, HeartbeatOutcomeView, PairingAttemptInfo, PairingCreatedView,
    PairingPort, PairingStatusView, PiClientError, PiClientErrorKind, PollPairingOutcome,
    SessionCatalogPort, SessionDetailView, SessionFileEntryView, SessionSummaryView,
    SessionsPageView,
};

/// Whether a device is currently visible on the network, per plan 5.4:
/// `online | stale | offline`. This is purely a discovery-layer signal
/// (mDNS/manual probe freshness) — it says nothing about whether PC has an
/// authenticated session with the device; that is [`ConnectionState`]'s
/// job, and the two are tracked independently (a device can be `Online`
/// but `Disconnected`, or briefly `Stale` while still `Connected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryState {
    Online,
    Stale,
    Offline,
}

/// The phase of one pairing attempt, matching
/// `pairing-request.schema.json`'s `phase` enum exactly:
/// `pending | allowed | rejected | expired | cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingPhase {
    Pending,
    Allowed,
    Rejected,
    Expired,
    Cancelled,
}

/// PC's authentication/session relationship with one device, per plan 5.4:
/// `disconnected | pairing(attempt_id, phase) | connected(connection_id,
/// epoch) | expired(reason)`.
///
/// Each variant only carries the fields meaningful to that state — e.g.
/// only [`ConnectionState::Pairing`] has an `attempt_id`/`phase`, only
/// [`ConnectionState::Connected`] has a `connection_id`/`epoch`. This is
/// what "illegal states unrepresentable" means concretely here: there is
/// no single struct with a bunch of `Option<...>` fields where a caller
/// could accidentally set `attempt_id` on an otherwise-`Connected` value —
/// the type simply has no such field in that variant, and the language
/// rejects the attempt to construct it at compile time (see
/// `tests::connected_variant_has_no_pairing_fields_available` for the
/// executable form of this claim, using variants/fields that *do* compile
/// as the contrast case).
///
/// `epoch` exists specifically so PC-02's actor can discard stale
/// callbacks/responses from an old connection generation (plan section
/// 16 PC-02 deliverable: "connection epoch, re-auth").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Pairing {
        attempt_id: String,
        phase: PairingPhase,
    },
    Connected {
        connection_id: String,
        epoch: u64,
    },
    Expired {
        reason: String,
    },
}

/// Read-only mirror of the Conductor capture-activity domain:
/// `idle | starting | recording | stopping | error | unknown`. Exact value
/// set and wire spelling match the authenticated `GET /api/v1/device`
/// response. This is deliberately a coarser, desktop-side view of the same
/// domain: the desktop observes capture activity but does not mutate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureActivityState {
    Idle,
    Starting,
    Recording,
    Stopping,
    Error,
    Unknown,
}

/// One known device: stable identity plus its three orthogonal state
/// axes. `tls_fingerprint` is the Pi's own TLS identity pin (distinct from
/// [`DeviceId`], which is PC's own opaque handle for "this paired
/// device") — kept here rather than folded into [`ConnectionState`]
/// because identity/pinning outlives any single connection or pairing
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device_id: DeviceId,
    pub name: String,
    pub tls_fingerprint: String,
    pub discovery: DiscoveryState,
    pub connection: ConnectionState,
    pub capture_activity: CaptureActivityState,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Exact variant-list checks (plan 5.4's literal enumerations)
    // -----------------------------------------------------------------

    #[test]
    fn discovery_state_has_exactly_the_plan_5_4_variants() {
        // Exhaustive match: if a variant is added/removed upstream this
        // fails to compile, not just fails an assertion.
        fn all(s: DiscoveryState) -> &'static str {
            match s {
                DiscoveryState::Online => "online",
                DiscoveryState::Stale => "stale",
                DiscoveryState::Offline => "offline",
            }
        }
        assert_eq!(all(DiscoveryState::Online), "online");
        assert_eq!(all(DiscoveryState::Stale), "stale");
        assert_eq!(all(DiscoveryState::Offline), "offline");
    }

    #[test]
    fn capture_activity_state_has_exactly_the_plan_5_4_variants() {
        fn all(s: CaptureActivityState) -> &'static str {
            match s {
                CaptureActivityState::Idle => "idle",
                CaptureActivityState::Starting => "starting",
                CaptureActivityState::Recording => "recording",
                CaptureActivityState::Stopping => "stopping",
                CaptureActivityState::Error => "error",
                CaptureActivityState::Unknown => "unknown",
            }
        }
        assert_eq!(all(CaptureActivityState::Idle), "idle");
        assert_eq!(all(CaptureActivityState::Unknown), "unknown");
    }

    #[test]
    fn connection_state_has_exactly_the_plan_5_4_variant_shapes() {
        // Exhaustive match over constructed values proves both the variant
        // set AND each variant's field shape compile as plan 5.4 specifies.
        let values = [
            ConnectionState::Disconnected,
            ConnectionState::Pairing {
                attempt_id: "attempt-1".to_string(),
                phase: PairingPhase::Pending,
            },
            ConnectionState::Connected {
                connection_id: "conn-1".to_string(),
                epoch: 0,
            },
            ConnectionState::Expired {
                reason: "token expired".to_string(),
            },
        ];
        for v in values {
            match v {
                ConnectionState::Disconnected => {}
                ConnectionState::Pairing { attempt_id, phase } => {
                    assert_eq!(attempt_id, "attempt-1");
                    assert_eq!(phase, PairingPhase::Pending);
                }
                ConnectionState::Connected {
                    connection_id,
                    epoch,
                } => {
                    assert_eq!(connection_id, "conn-1");
                    assert_eq!(epoch, 0);
                }
                ConnectionState::Expired { reason } => assert_eq!(reason, "token expired"),
            }
        }
    }

    // -----------------------------------------------------------------
    // Illegal-state-unrepresentable: structural, not runtime, proof
    // -----------------------------------------------------------------

    /// This is the executable half of the "cannot construct a connected
    /// state with a pairing attempt_id" claim from the module doc comment.
    /// It cannot literally attempt the illegal construction (that would be
    /// a compile error, which can't be expressed as a passing `#[test]`),
    /// so instead it demonstrates the contrapositive: every field that
    /// *is* legal to construct for `Connected` is exactly
    /// `{connection_id, epoch}` — nothing else compiles in that position.
    /// A maintainer can confirm the negative claim by uncommenting the
    /// block below, which fails with "struct variant `Connected` has no
    /// field named `attempt_id`":
    ///
    /// ```compile_fail
    /// use ylx_transfer_core::device::ConnectionState;
    /// let _illegal = ConnectionState::Connected {
    ///     connection_id: "c".to_string(),
    ///     epoch: 0,
    ///     attempt_id: "should not compile".to_string(),
    /// };
    /// ```
    #[test]
    fn connected_variant_has_no_pairing_fields_available() {
        let connected = ConnectionState::Connected {
            connection_id: "conn-1".to_string(),
            epoch: 5,
        };
        let ConnectionState::Connected {
            connection_id,
            epoch,
        } = connected
        else {
            panic!("expected Connected");
        };
        assert_eq!(connection_id, "conn-1");
        assert_eq!(epoch, 5);
    }

    // -----------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------

    #[test]
    fn connection_state_json_round_trips_for_every_variant() {
        let values = vec![
            ConnectionState::Disconnected,
            ConnectionState::Pairing {
                attempt_id: "attempt-1".to_string(),
                phase: PairingPhase::Allowed,
            },
            ConnectionState::Connected {
                connection_id: "conn-1".to_string(),
                epoch: 7,
            },
            ConnectionState::Expired {
                reason: "heartbeat 401".to_string(),
            },
        ];
        for value in values {
            let json = serde_json::to_string(&value).expect("serializes");
            let back: ConnectionState = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(back, value);
        }
    }

    #[test]
    fn connection_state_pairing_serializes_with_tagged_shape() {
        let value = ConnectionState::Pairing {
            attempt_id: "a-1".to_string(),
            phase: PairingPhase::Pending,
        };
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["state"], "pairing");
        assert_eq!(json["attempt_id"], "a-1");
        assert_eq!(json["phase"], "pending");
    }

    #[test]
    fn device_struct_json_round_trips() {
        let device = Device {
            device_id: DeviceId("dev-1".to_string()),
            name: "Pi in the lab".to_string(),
            tls_fingerprint: "sha256:deadbeef".to_string(),
            discovery: DiscoveryState::Online,
            connection: ConnectionState::Connected {
                connection_id: "conn-1".to_string(),
                epoch: 1,
            },
            capture_activity: CaptureActivityState::Recording,
        };
        let json = serde_json::to_string(&device).expect("serializes");
        let back: Device = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, device);
    }
}
