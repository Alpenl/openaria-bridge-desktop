//! `DeviceFleet` — per-device actor handles, so the registry lock stops
//! being a global serialization point for every device (issue #1, commits
//! 57 and 58).
//!
//! # The problem this replaces
//!
//! The `DeviceActorRegistry` this replaced (deleted in commit 59) handed
//! out `&mut DeviceActor` borrows, which means a caller could only reach a
//! device's actor *while holding the registry itself*. In practice that
//! registry lived behind one process-wide `Mutex`, so the borrow forced every
//! caller to serialize on a single lock — and, worse, network I/O issued
//! through that borrow (`actor.heartbeat_with(client)`,
//! `actor.refresh_capture_activity_with(client)`) runs *inside* the critical
//! section. One slow or unreachable Pi therefore stalls every other
//! device's heartbeat, pairing, catalog listing, delete, disconnect and
//! transfer-readiness check — the exact opposite of plan section 16's
//! "一台设备故障不阻塞其他设备 actor".
//!
//! # The shape here
//!
//! A [`DeviceFleet`] owns `Mutex<HashMap<DeviceFingerprint, DeviceHandle>>`,
//! and that lock is held for exactly one thing: **look up or insert a
//! handle**. Every unit of per-device work then happens behind that
//! device's own [`DeviceHandle`], which is an `Arc` with its own lock and
//! no path back to the map. Two consequences fall out structurally rather
//! than by convention:
//!
//! - A handle cannot hold the registry lock, because it does not have one
//!   to hold.
//! - Per-device network I/O ([`DeviceHandle::heartbeat_with`],
//!   [`DeviceHandle::poll_pairing_with`], [`DeviceHandle::refresh_capture_activity_with`],
//!   [`DeviceHandle::delete_session_with`]) is written as *copy inputs under the
//!   handle lock → drop the lock → do the I/O → re-acquire and apply*, so
//!   even that per-device lock is not held across a network call.
//!
//! # Identity is the full fingerprint
//!
//! The map key is [`DeviceFingerprint`], the device's **whole** TLS
//! fingerprint. The short `YLX-XXXXXXXX` form the UI shows is a
//! *projection* ([`DeviceFingerprint::short_display_id`]) available on any
//! snapshot for display DTOs — never the identity. Truncating to eight hex
//! characters leaves ~2^32 possibilities, so two genuinely different
//! devices can share a short id; keying the map on it would silently merge
//! them into one actor, one session and one bearer token. See
//! `two_devices_with_colliding_short_ids_stay_distinct`.
//!
//! # Fencing (commit 58)
//!
//! Doing the I/O outside every lock means a reply can arrive after the
//! world moved on: the device may have been disconnected and re-paired, or
//! a newer heartbeat may already have been issued. Every off-lock operation
//! therefore takes a fencing token *before* the call
//! ([`HeartbeatTicket`], [`EpochTicket`]) and is only applied if that token
//! is still current when the reply comes back:
//!
//! - epoch — the connection generation the request was issued under
//!   (already enforced by [`DeviceActor::apply_heartbeat_result`]);
//! - attempt — a per-handle monotonic counter, so that even *within* one
//!   epoch a reply belonging to a superseded heartbeat attempt is dropped
//!   rather than applied.
//!
//! Pairing is fenced by `attempt_id` instead of by epoch (a pairing device
//! is not connected yet, so there is no epoch), which
//! [`DeviceActor::apply_pairing_status`] already implements.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::device::actor::{
    AuthenticatedCatalogPort, AuthenticatedDevicePort, AuthenticatedPiSession,
    DeleteSessionReceiptView, DeviceActor, DeviceInfoView, GatewayVerificationView,
    HeartbeatApplyOutcome, HeartbeatOutcomeView, PairingPort, PiClientError, PiClientErrorKind,
    PollPairingOutcome, SessionCatalogPort, SessionDetailView, SessionsPageView,
};
use crate::device::{ConnectionState, Device, DeviceFingerprint, DiscoveryState};

/// Everything a display DTO needs about one device, read in one short
/// handle-lock acquisition: the full identity, its short label, and a
/// snapshot of the device's three state axes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub fingerprint: DeviceFingerprint,
    /// `fingerprint.short_display_id()`, materialized for convenience.
    pub short_id: String,
    pub device: Device,
}

/// The capability negotiation that belongs to one currently connected
/// epoch. Reading both values under the actor's single lock prevents a
/// reconnect from pairing an old capability snapshot with a new epoch.
#[derive(Debug, Clone)]
pub struct NegotiatedDeviceSnapshot {
    pub epoch: u64,
    pub info: DeviceInfoView,
}

// =====================================================================
// Fencing tokens
// =====================================================================

/// Fencing token for one in-flight heartbeat: the connection epoch it was
/// issued under plus this handle's heartbeat attempt number. A reply is
/// applied only while *both* are still current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatTicket {
    epoch: u64,
    attempt: u64,
}

impl HeartbeatTicket {
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
}

/// Fencing token for an in-flight authenticated request whose result must
/// not be applied across a reconnect (delete receipts, `GET /device`
/// refreshes). Epoch-only: two concurrent deletes of *different* sessions
/// in the same epoch are both legitimate, so there is no attempt counter to
/// supersede.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTicket {
    epoch: u64,
}

impl EpochTicket {
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Fencing token for an in-flight pairing-request creation. A late create
/// response is ignored when a newer pairing was started or the device was
/// disconnected while the request was in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingTicket {
    generation: u64,
}

impl PairingTicket {
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// What applying an off-lock `GET /device` refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshApplyOutcome {
    /// Not connected when the request was about to be issued.
    NotConnected,
    /// The connection epoch moved while the request was in flight; the
    /// reply belongs to a superseded connection and was discarded.
    Stale,
    Refreshed,
    Failed(PiClientError),
}

/// What applying an off-lock `GET /sessions/{id}` reply did.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionDetailOutcome {
    NotConnected,
    /// The connection epoch moved while the request was in flight; the
    /// detail was read under a session that no longer exists.
    Stale,
    /// Boxed to keep this enum small: a `SessionDetailView` carries a
    /// whole file inventory plus the signed publication payload, and every
    /// caller matches on the outcome before it ever touches the detail.
    Fetched(Box<SessionDetailView>),
    Failed(PiClientError),
}

/// What applying an off-lock `DELETE /sessions/{id}` receipt did.
#[derive(Debug, Clone, PartialEq)]
pub enum DeleteApplyOutcome {
    NotConnected,
    /// The connection epoch moved while the delete was in flight; the
    /// receipt belongs to a superseded connection and was discarded.
    Stale,
    Deleted(DeleteSessionReceiptView),
    Failed(PiClientError),
}

// =====================================================================
// DeviceHandle
// =====================================================================

struct HandleInner {
    fingerprint: DeviceFingerprint,
    actor: Mutex<DeviceActor>,
    /// Monotonic counter of heartbeats *issued* through this handle. A
    /// reply whose ticket no longer matches this value was superseded.
    heartbeat_attempts: AtomicU64,
    pairing_attempts: AtomicU64,
}

/// A cheap, cloneable handle to exactly one device's actor.
///
/// Cloning shares the same underlying actor (that is the point: mDNS and
/// manual-address discovery both resolve to one handle). Holding a handle
/// never holds the fleet's registry lock, so any amount of slow work behind
/// one handle leaves every other device — and the fleet map itself —
/// completely free.
#[derive(Clone)]
pub struct DeviceHandle {
    inner: Arc<HandleInner>,
}

impl fmt::Debug for DeviceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceHandle")
            .field("fingerprint", &self.inner.fingerprint)
            .finish_non_exhaustive()
    }
}

/// A locked borrow of one device's actor. Deliberately a distinct type
/// (rather than handing out `&mut DeviceActor` from a registry borrow) so
/// the scope in which the per-device lock is held is visible at the call
/// site — and so it can never be held across the network calls the
/// `DeviceHandle` methods perform.
pub struct ActorGuard<'a> {
    guard: MutexGuard<'a, DeviceActor>,
}

impl std::ops::Deref for ActorGuard<'_> {
    type Target = DeviceActor;

    fn deref(&self) -> &DeviceActor {
        &self.guard
    }
}

impl std::ops::DerefMut for ActorGuard<'_> {
    fn deref_mut(&mut self) -> &mut DeviceActor {
        &mut self.guard
    }
}

impl DeviceHandle {
    fn new(fingerprint: DeviceFingerprint, device: Device) -> Self {
        DeviceHandle {
            inner: Arc::new(HandleInner {
                fingerprint,
                actor: Mutex::new(DeviceActor::new(device)),
                heartbeat_attempts: AtomicU64::new(0),
                pairing_attempts: AtomicU64::new(0),
            }),
        }
    }

    #[must_use]
    pub fn fingerprint(&self) -> &DeviceFingerprint {
        &self.inner.fingerprint
    }

    /// Display-only short label (see [`DeviceFingerprint::short_display_id`]).
    #[must_use]
    pub fn short_display_id(&self) -> String {
        self.inner.fingerprint.short_display_id()
    }

    /// Locks *this device's* actor (never the fleet). Prefer the operation
    /// methods below for anything that talks to the network — they exist
    /// precisely so no caller has to decide whether it is safe to do I/O
    /// while holding this guard (it is not).
    pub fn actor(&self) -> ActorGuard<'_> {
        ActorGuard {
            guard: self
                .inner
                .actor
                .lock()
                .expect("device actor mutex poisoned"),
        }
    }

    /// One short lock acquisition, everything a display DTO needs.
    #[must_use]
    pub fn snapshot(&self) -> DeviceSnapshot {
        let device = self.actor().device().clone();
        DeviceSnapshot {
            fingerprint: self.inner.fingerprint.clone(),
            short_id: self.inner.fingerprint.short_display_id(),
            device,
        }
    }

    /// Updates one device's discovery axis under its per-device lock. The
    /// boolean lets composition avoid redundant UI emissions.
    pub fn set_discovery_state(&self, state: DiscoveryState) -> bool {
        self.actor().set_discovery_state(state)
    }

    #[must_use]
    pub fn connection_state(&self) -> ConnectionState {
        self.actor().connection_state().clone()
    }

    /// Returns the last authenticated device/capability snapshot without
    /// issuing network I/O. The snapshot is cleared whenever the connection
    /// is cleared or a new pairing attempt supersedes it.
    #[must_use]
    pub fn negotiated_device_info(&self) -> Option<DeviceInfoView> {
        self.actor().negotiated_device_info().cloned()
    }

    /// Returns negotiation evidence only when it belongs to the currently
    /// connected epoch. Pairing, disconnect, expiry, and reconnect clear the
    /// actor's cached negotiation before this method can expose it again.
    #[must_use]
    pub fn negotiated_device_snapshot(&self) -> Option<NegotiatedDeviceSnapshot> {
        let actor = self.actor();
        Some(NegotiatedDeviceSnapshot {
            epoch: actor.current_epoch()?,
            info: actor.negotiated_device_info()?.clone(),
        })
    }

    #[must_use]
    pub fn current_epoch(&self) -> Option<u64> {
        self.actor().current_epoch()
    }

    // -----------------------------------------------------------------
    // Heartbeat (commit 58: network I/O with no lock held)
    // -----------------------------------------------------------------

    /// Reserves a heartbeat attempt, superseding any attempt still in
    /// flight. `None` if the device is not currently connected.
    ///
    /// Exposed so a caller that owns its own I/O scheduling can do the
    /// request itself and hand the reply back to [`Self::apply_heartbeat`]
    /// later — and so the fencing rule is testable without real
    /// concurrency.
    pub fn issue_heartbeat_ticket(&self) -> Option<HeartbeatTicket> {
        let session = self.checkout_authenticated_session()?;
        let attempt = self.inner.heartbeat_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        Some(HeartbeatTicket {
            epoch: session.epoch(),
            attempt,
        })
    }

    /// Applies a heartbeat reply issued under `ticket`. Discarded as
    /// [`HeartbeatApplyOutcome::Stale`] if a newer attempt has since been
    /// issued, or if the connection epoch has moved.
    pub fn apply_heartbeat(
        &self,
        ticket: HeartbeatTicket,
        result: Result<HeartbeatOutcomeView, PiClientError>,
    ) -> HeartbeatApplyOutcome {
        let mut actor = self.actor();
        if self.inner.heartbeat_attempts.load(Ordering::SeqCst) != ticket.attempt {
            return HeartbeatApplyOutcome::Stale;
        }
        actor.apply_heartbeat_result(ticket.epoch, result)
    }

    /// Full heartbeat cycle. The authenticated session crosses the adapter
    /// boundary with its TLS/publication identity and epoch binding. The
    /// network call happens with no fleet or handle lock held, and the reply
    /// is fenced on the way back in.
    pub fn heartbeat_with(&self, client: &dyn AuthenticatedDevicePort) -> HeartbeatApplyOutcome {
        let Some(session) = self.checkout_authenticated_session() else {
            return HeartbeatApplyOutcome::NotConnected;
        };
        let attempt = self.inner.heartbeat_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        let ticket = HeartbeatTicket {
            epoch: session.epoch(),
            attempt,
        };
        let result = client.heartbeat(&session);
        self.apply_heartbeat(ticket, result)
    }

    // -----------------------------------------------------------------
    // Capture-activity refresh
    // -----------------------------------------------------------------

    /// `GET /device` through the authenticated-device capability, issued
    /// off-lock and applied under epoch fencing.
    pub fn refresh_capture_activity_with(
        &self,
        client: &dyn AuthenticatedDevicePort,
    ) -> RefreshApplyOutcome {
        let Some(session) = self.checkout_authenticated_session() else {
            return RefreshApplyOutcome::NotConnected;
        };
        let ticket = EpochTicket {
            epoch: session.epoch(),
        };
        let result = client.get_device(&session);
        self.apply_device_info(ticket, result)
    }

    /// Fetches descriptor/capability negotiation for one newly connected
    /// epoch, with the network call outside the actor lock and the result
    /// applied only while that epoch remains current.
    pub fn negotiate_device_with(
        &self,
        client: &dyn AuthenticatedDevicePort,
    ) -> RefreshApplyOutcome {
        let Some(session) = self.checkout_authenticated_session() else {
            return RefreshApplyOutcome::NotConnected;
        };
        self.negotiate_device_for_session(client, session)
    }

    /// Negotiates only if the authenticated session still belongs to the
    /// connection epoch that produced the setup task. This pre-I/O fence is
    /// paired with [`Self::apply_device_info`]'s post-I/O fence: an old
    /// pairing task can therefore neither send a descriptor request through
    /// a newer token nor install its late reply into that newer connection.
    pub fn negotiate_device_with_for_epoch(
        &self,
        client: &dyn AuthenticatedDevicePort,
        expected_epoch: u64,
    ) -> RefreshApplyOutcome {
        let Some(session) = self.checkout_authenticated_session() else {
            return RefreshApplyOutcome::NotConnected;
        };
        if session.epoch() != expected_epoch {
            return RefreshApplyOutcome::Stale;
        }
        self.negotiate_device_for_session(client, session)
    }

    fn negotiate_device_for_session(
        &self,
        client: &dyn AuthenticatedDevicePort,
        session: AuthenticatedPiSession,
    ) -> RefreshApplyOutcome {
        let ticket = EpochTicket {
            epoch: session.epoch(),
        };
        let result = client.negotiate_device(&session);
        self.apply_device_info(ticket, result)
    }

    /// Reads one authenticated session-catalog page with no actor lock held.
    /// The page is accepted only if the connection epoch is unchanged when
    /// the request returns; a disconnect/reconnect therefore cannot let a
    /// response from the old authenticated session enter a new catalog read.
    pub fn list_sessions_with(
        &self,
        client: &dyn SessionCatalogPort,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError> {
        let Some(session) = self.checkout_authenticated_session() else {
            return Err(PiClientError {
                kind: PiClientErrorKind::Other,
                message: "list_sessions called without an authenticated session".to_string(),
            });
        };
        let epoch = session.epoch();
        let result = client.list_sessions(&session, cursor, limit);
        if self.current_epoch() != Some(epoch) {
            return Err(PiClientError {
                kind: PiClientErrorKind::Other,
                message: "authenticated session epoch changed during catalog request".to_string(),
            });
        }
        result
    }

    /// Applies a (possibly late) `GET /device` reply issued under `ticket`.
    pub fn apply_device_info(
        &self,
        ticket: EpochTicket,
        result: Result<DeviceInfoView, PiClientError>,
    ) -> RefreshApplyOutcome {
        let mut actor = self.actor();
        if actor.current_epoch() != Some(ticket.epoch) {
            return RefreshApplyOutcome::Stale;
        }
        match result {
            Ok(info) => match actor.apply_device_info(info) {
                Ok(()) => RefreshApplyOutcome::Refreshed,
                Err(e) => RefreshApplyOutcome::Failed(e),
            },
            Err(e) => RefreshApplyOutcome::Failed(e),
        }
    }

    // -----------------------------------------------------------------
    // Session detail
    // -----------------------------------------------------------------

    /// `GET /sessions/{id}` with the request issued outside every lock and
    /// the reply fenced on the connection epoch.
    ///
    /// The publication identity the detail is verified against is resolved
    /// exactly like [`DeviceActor::get_session_with`] resolves it — the
    /// SAS-confirmed value, else the one cached from an authenticated `GET
    /// /device`, else a fresh `GET /device` — except that each of those
    /// network calls also happens off-lock, and the freshly observed
    /// identity is applied under the same epoch fence before anything is
    /// verified against it.
    /// A legacy session with
    /// no SAS publication identity first obtains and binds `/device` through
    /// the authenticated-device capability, then performs the catalog read
    /// with the newly-bound session.
    pub fn get_session_with(
        &self,
        client: &dyn AuthenticatedCatalogPort,
        session_id: &str,
    ) -> SessionDetailOutcome {
        let Some(ticket) = self.issue_epoch_ticket() else {
            return SessionDetailOutcome::NotConnected;
        };
        let mut session = match self.checkout_authenticated_session() {
            Some(session) => session,
            None => return SessionDetailOutcome::NotConnected,
        };
        if session.publication_key_fingerprint().is_none() {
            let info = match client.get_device(&session) {
                Ok(info) => info,
                Err(error) => return SessionDetailOutcome::Failed(error),
            };
            match self.apply_device_info(ticket, Ok(info)) {
                RefreshApplyOutcome::Refreshed => {}
                RefreshApplyOutcome::Stale => return SessionDetailOutcome::Stale,
                RefreshApplyOutcome::NotConnected => return SessionDetailOutcome::NotConnected,
                RefreshApplyOutcome::Failed(error) => return SessionDetailOutcome::Failed(error),
            }
            session = match self.checkout_authenticated_session() {
                Some(session) => session,
                None => return SessionDetailOutcome::NotConnected,
            };
        }
        if self.current_epoch() != Some(ticket.epoch()) {
            return SessionDetailOutcome::Stale;
        }
        match client.get_session(&session, session_id) {
            Ok(detail) => {
                if self.current_epoch() == Some(ticket.epoch()) {
                    SessionDetailOutcome::Fetched(Box::new(detail))
                } else {
                    SessionDetailOutcome::Stale
                }
            }
            Err(error) => SessionDetailOutcome::Failed(error),
        }
    }

    /// v4 counterpart to [`Self::get_session_with`]: detail bytes are
    /// accepted only when they still match the selected usable gateway
    /// verification. Network I/O remains outside the actor lock and the
    /// response is fenced on the same connection epoch.
    pub fn get_verified_session_with(
        &self,
        client: &dyn AuthenticatedCatalogPort,
        session_id: &str,
        verification: &GatewayVerificationView,
    ) -> SessionDetailOutcome {
        let Some(ticket) = self.issue_epoch_ticket() else {
            return SessionDetailOutcome::NotConnected;
        };
        let mut session = match self.checkout_authenticated_session() {
            Some(session) => session,
            None => return SessionDetailOutcome::NotConnected,
        };
        if session.publication_key_fingerprint().is_none() {
            let info = match client.get_device(&session) {
                Ok(info) => info,
                Err(error) => return SessionDetailOutcome::Failed(error),
            };
            match self.apply_device_info(ticket, Ok(info)) {
                RefreshApplyOutcome::Refreshed => {}
                RefreshApplyOutcome::Stale => return SessionDetailOutcome::Stale,
                RefreshApplyOutcome::NotConnected => return SessionDetailOutcome::NotConnected,
                RefreshApplyOutcome::Failed(error) => return SessionDetailOutcome::Failed(error),
            }
            session = match self.checkout_authenticated_session() {
                Some(session) => session,
                None => return SessionDetailOutcome::NotConnected,
            };
        }
        if self.current_epoch() != Some(ticket.epoch()) {
            return SessionDetailOutcome::Stale;
        }
        match client.get_verified_session(&session, session_id, verification) {
            Ok(detail) => {
                if self.current_epoch() == Some(ticket.epoch()) {
                    SessionDetailOutcome::Fetched(Box::new(detail))
                } else {
                    SessionDetailOutcome::Stale
                }
            }
            Err(error) => SessionDetailOutcome::Failed(error),
        }
    }

    // -----------------------------------------------------------------
    // Disconnect
    // -----------------------------------------------------------------

    /// Ends this device's session. The local transition to `Disconnected`
    /// happens under the handle lock; the best-effort `revoke` at the
    /// device runs with no lock held, so an unreachable Pi delays nothing
    /// but this call.
    ///
    /// Needs no fencing: the transition is unconditional and already
    /// applied before the request is issued, so a late or failed revoke has
    /// nothing left to invalidate.
    /// Local state is cleared before the off-lock revoke, so a slow or
    /// failed network call cannot keep the fleet actor connected.
    pub fn disconnect_with(
        &self,
        client: &dyn AuthenticatedDevicePort,
    ) -> Result<(), PiClientError> {
        self.inner.pairing_attempts.fetch_add(1, Ordering::SeqCst);
        let session = self.checkout_authenticated_session();
        self.actor().clear_connection_state();
        match session {
            Some(session) => client.revoke_session(&session),
            None => Ok(()),
        }
    }

    /// Clears the local session without issuing a network revoke. This is
    /// used only when no transport is available; production callers should
    /// prefer [`Self::disconnect_with`] so the Pi also receives the revoke.
    pub fn disconnect_local(&self) {
        self.inner.pairing_attempts.fetch_add(1, Ordering::SeqCst);
        self.actor().clear_connection_state();
    }

    /// Clears only the connection generation whose setup failed. A late
    /// negotiation result from an older epoch therefore cannot disconnect a
    /// newer session.
    pub fn disconnect_local_if_epoch(&self, expected_epoch: u64) -> bool {
        let mut actor = self.actor();
        if actor.current_epoch() != Some(expected_epoch) {
            return false;
        }
        self.inner.pairing_attempts.fetch_add(1, Ordering::SeqCst);
        actor.clear_connection_state();
        true
    }

    // -----------------------------------------------------------------
    // Pairing
    // -----------------------------------------------------------------

    /// Starts a pairing request with the network call outside this
    /// device's actor lock. The returned SAS/attempt view is installed only
    /// after the adapter call succeeds; a transport error leaves the
    /// previous actor state untouched.
    pub fn start_pairing_with(
        &self,
        client: &dyn PairingPort,
        client_name: &str,
        client_nonce: &str,
    ) -> Result<crate::device::actor::PairingAttemptInfo, PiClientError> {
        let ticket = self.issue_pairing_ticket();
        let created = client.create_pairing_request(client_name, client_nonce)?;
        if self.inner.pairing_attempts.load(Ordering::SeqCst) != ticket.generation {
            return Err(PiClientError {
                kind: PiClientErrorKind::Other,
                message: "pairing response belongs to a superseded attempt".to_string(),
            });
        }
        Ok(self.actor().apply_pairing_created(created))
    }

    /// Installs an already-fetched pairing response after the caller has
    /// checked its [`PairingTicket`] generation. The poll secret is consumed
    /// inside the actor and is never returned from this API.
    pub fn apply_pairing_created(
        &self,
        created: crate::device::actor::PairingCreatedView,
    ) -> crate::device::actor::PairingAttemptInfo {
        self.actor().apply_pairing_created(created)
    }

    /// Reserve a pairing-create generation for callers that issue the
    /// network request themselves. Applying a response with an older ticket
    /// must be rejected by the caller before installing its poll secret.
    pub fn issue_pairing_ticket(&self) -> PairingTicket {
        let generation = self.inner.pairing_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        PairingTicket { generation }
    }

    /// Check whether a pairing-create response still belongs to the latest
    /// generation. This does not mutate actor state or expose the poll
    /// secret, so it is safe to call before `apply_pairing_created`.
    #[must_use]
    pub fn pairing_ticket_is_current(&self, ticket: PairingTicket) -> bool {
        self.inner.pairing_attempts.load(Ordering::SeqCst) == ticket.generation
    }

    /// Polls the in-flight pairing attempt with the `GET
    /// /pairing-requests/{id}` call made **outside** the handle lock. The
    /// reply is fenced on `attempt_id` by
    /// [`DeviceActor::apply_pairing_status`], so a late poll belonging to a
    /// superseded attempt is discarded.
    /// Polls through the pairing-only capability without holding the actor
    /// lock across network I/O.
    pub fn poll_pairing_with(&self, client: &dyn PairingPort) -> PollPairingOutcome {
        let Some((attempt_id, poll_secret)) = self.actor().checkout_pairing_poll() else {
            return PollPairingOutcome::NotPairing;
        };
        let result = client.get_pairing_status(&attempt_id, &poll_secret);
        self.actor().apply_pairing_status(&attempt_id, result)
    }

    // -----------------------------------------------------------------
    // Delete
    // -----------------------------------------------------------------

    /// Reserves an epoch fencing token for an authenticated request whose
    /// result must not survive a reconnect.
    pub fn issue_epoch_ticket(&self) -> Option<EpochTicket> {
        self.checkout_authenticated_session()
            .map(|session| EpochTicket {
                epoch: session.epoch(),
            })
    }

    /// Applies a (possibly late) delete receipt issued under `ticket`.
    pub fn apply_delete_receipt(
        &self,
        ticket: EpochTicket,
        result: Result<DeleteSessionReceiptView, PiClientError>,
    ) -> DeleteApplyOutcome {
        let actor = self.actor();
        if actor.current_epoch() != Some(ticket.epoch) {
            return DeleteApplyOutcome::Stale;
        }
        match result {
            Ok(receipt) => DeleteApplyOutcome::Deleted(receipt),
            Err(e) => DeleteApplyOutcome::Failed(e),
        }
    }

    /// `DELETE /sessions/{id}` through the catalog capability, with the
    /// request issued outside every lock and its receipt epoch-fenced.
    pub fn delete_session_with(
        &self,
        client: &dyn SessionCatalogPort,
        session_id: &str,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> DeleteApplyOutcome {
        let Some(session) = self.checkout_authenticated_session() else {
            return DeleteApplyOutcome::NotConnected;
        };
        let ticket = EpochTicket {
            epoch: session.epoch(),
        };
        let result =
            client.delete_session(&session, session_id, if_match_revision, idempotency_key);
        self.apply_delete_receipt(ticket, result)
    }

    fn checkout_authenticated_session(&self) -> Option<AuthenticatedPiSession> {
        self.actor().authenticated_session().cloned()
    }
}

// =====================================================================
// DeviceFleet
// =====================================================================

/// One [`DeviceHandle`] per device, keyed by full [`DeviceFingerprint`].
///
/// The internal lock guards *only* the map. Every method here either
/// returns handles (lock released before the caller does anything with
/// them) or runs a caller-supplied operation across handles with the lock
/// already dropped — see [`Self::for_each_device`].
pub struct DeviceFleet {
    devices: Mutex<HashMap<DeviceFingerprint, DeviceHandle>>,
}

impl fmt::Debug for DeviceFleet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceFleet")
            .field("len", &self.len())
            .finish()
    }
}

impl Default for DeviceFleet {
    fn default() -> Self {
        Self::new()
    }
}

/// One device's result from a fleet-wide heartbeat sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetHeartbeatReport {
    pub fingerprint: DeviceFingerprint,
    pub outcome: HeartbeatApplyOutcome,
}

impl DeviceFleet {
    #[must_use]
    pub fn new() -> Self {
        DeviceFleet {
            devices: Mutex::new(HashMap::new()),
        }
    }

    fn map(&self) -> MutexGuard<'_, HashMap<DeviceFingerprint, DeviceHandle>> {
        self.devices.lock().expect("device fleet mutex poisoned")
    }

    /// Looks up — or, on first sight, inserts — this device's handle. The
    /// fleet lock is held for the lookup/insert and nothing else;
    /// `make_device` is only called when the fingerprint is new.
    pub fn get_or_create(
        &self,
        fingerprint: impl Into<DeviceFingerprint>,
        make_device: impl FnOnce() -> Device,
    ) -> DeviceHandle {
        let fingerprint = fingerprint.into();
        self.map()
            .entry(fingerprint.clone())
            .or_insert_with(|| DeviceHandle::new(fingerprint, make_device()))
            .clone()
    }

    /// The handle for an already-registered device. `None` for an unknown
    /// fingerprint — an RPC-supplied id can never manufacture a device.
    pub fn handle(&self, fingerprint: impl Into<DeviceFingerprint>) -> Option<DeviceHandle> {
        self.map().get(&fingerprint.into()).cloned()
    }

    /// A snapshot of every handle. The fleet lock is released before this
    /// returns, so the caller can take as long as it likes over the result.
    #[must_use]
    pub fn handles(&self) -> Vec<DeviceHandle> {
        self.map().values().cloned().collect()
    }

    /// Display DTOs for every known device, sorted by identity so the order
    /// is stable across calls.
    #[must_use]
    pub fn snapshots(&self) -> Vec<DeviceSnapshot> {
        let mut out: Vec<DeviceSnapshot> =
            self.handles().iter().map(DeviceHandle::snapshot).collect();
        out.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        out
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map().is_empty()
    }

    /// Runs `op` once per device with **no fleet lock held**, at most
    /// `max_concurrency` devices at a time, and collects whatever each
    /// returns.
    ///
    /// This is the primitive commit 58 needs: the map is snapshotted (one
    /// short lock acquisition), the lock is dropped, and only then does any
    /// I/O start. A device whose `op` blocks forever therefore blocks
    /// nothing except its own worker slot — every other device's work, and
    /// every unrelated fleet lookup/insert, proceeds.
    ///
    /// `op` returning `None` means "nothing to report for this device"
    /// (e.g. no network client configured).
    pub fn for_each_device<T, F>(
        &self,
        max_concurrency: usize,
        op: F,
    ) -> Vec<(DeviceFingerprint, T)>
    where
        F: Fn(&DeviceHandle) -> Option<T> + Sync,
        T: Send,
    {
        let handles = self.handles();
        if handles.is_empty() {
            return Vec::new();
        }
        let workers = max_concurrency.clamp(1, handles.len());
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<(DeviceFingerprint, T)>> = Mutex::new(Vec::new());

        std::thread::scope(|scope| {
            for _ in 0..workers {
                let next = &next;
                let results = &results;
                let handles = &handles;
                let op = &op;
                scope.spawn(move || loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(handle) = handles.get(index) else {
                        break;
                    };
                    if let Some(value) = op(handle) {
                        results
                            .lock()
                            .expect("fleet result mutex poisoned")
                            .push((handle.fingerprint().clone(), value));
                    }
                });
            }
        });

        let mut out = results.into_inner().expect("fleet result mutex poisoned");
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Heartbeats every device that has a client, with the network calls
    /// running outside every lock and bounded by `max_concurrency`.
    /// Devices for which `client_for` yields `None`, and devices that are
    /// not connected, are simply absent from the report.
    #[cfg(test)]
    pub fn heartbeat_all<F>(
        &self,
        max_concurrency: usize,
        client_for: F,
    ) -> Vec<FleetHeartbeatReport>
    where
        F: Fn(&DeviceFingerprint) -> Option<Arc<dyn AuthenticatedDevicePort>> + Sync,
    {
        self.for_each_device(max_concurrency, |handle| {
            let client = client_for(handle.fingerprint())?;
            match handle.heartbeat_with(client.as_ref()) {
                HeartbeatApplyOutcome::NotConnected => None,
                outcome => Some(outcome),
            }
        })
        .into_iter()
        .map(|(fingerprint, outcome)| FleetHeartbeatReport {
            fingerprint,
            outcome,
        })
        .collect()
    }
}

/// Convenience for callers that only have a [`PiClientErrorKind`] to report.
#[must_use]
pub fn client_error(kind: PiClientErrorKind, message: impl Into<String>) -> PiClientError {
    PiClientError {
        kind,
        message: message.into(),
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;
    use crate::device::actor::{
        FileDownloadView, FileHeadView, PairingCreatedView, PairingStatusView, SessionDetailView,
        SessionsPageView,
    };
    use crate::device::{CaptureActivityState, DiscoveryState, PairingPhase};
    use crate::domain::DeviceId;
    use crate::testing::{Deferred, RecordingSink, DEFAULT_TEST_TIMEOUT};

    fn device_for(fingerprint: &str) -> Device {
        let identity = DeviceFingerprint::new(fingerprint);
        Device {
            device_id: DeviceId(identity.short_display_id()),
            name: "Test Pi".to_string(),
            tls_fingerprint: fingerprint.to_string(),
            discovery: DiscoveryState::Online,
            connection: ConnectionState::Disconnected,
            capture_activity: CaptureActivityState::Unknown,
        }
    }

    fn heartbeat_ok() -> HeartbeatOutcomeView {
        HeartbeatOutcomeView {
            idle_timeout_ms: 15_000,
            absolute_expires_at: "2026-08-01T05:00:00Z".to_string(),
            capture_activity: Some(CaptureActivityState::Recording),
        }
    }

    /// A fake capability adapter that can drive a device to `Connected`,
    /// block inside authenticated calls until a [`Deferred`] is released,
    /// and record every call it saw.
    struct FakeClient {
        name: &'static str,
        attempt_id: String,
        gate: Option<Deferred<()>>,
        sink: RecordingSink<String>,
        pairing_status: Mutex<VecDeque<Result<PairingStatusView, PiClientError>>>,
        delete_result: Mutex<VecDeque<Result<DeleteSessionReceiptView, PiClientError>>>,
        device_info: Mutex<VecDeque<Result<DeviceInfoView, PiClientError>>>,
        heartbeat_failure: Mutex<Option<PiClientError>>,
    }

    impl FakeClient {
        fn new(name: &'static str, attempt_id: &str, sink: RecordingSink<String>) -> Self {
            FakeClient {
                name,
                attempt_id: attempt_id.to_string(),
                gate: None,
                sink,
                pairing_status: Mutex::new(VecDeque::new()),
                delete_result: Mutex::new(VecDeque::new()),
                device_info: Mutex::new(VecDeque::new()),
                heartbeat_failure: Mutex::new(None),
            }
        }

        fn gated(mut self, gate: Deferred<()>) -> Self {
            self.gate = Some(gate);
            self
        }

        /// Blocks inside the "network call" until the test releases the
        /// gate — a Pi that accepted the connection and went quiet.
        fn block(&self) {
            if let Some(gate) = &self.gate {
                gate.get();
            }
        }

        fn session_detail(session_id: &str) -> SessionDetailView {
            SessionDetailView {
                session_id: session_id.to_string(),
                revision: "rev-1".to_string(),
                captured_at: "2026-08-01T04:00:00Z".to_string(),
                published_at: "2026-08-01T04:30:00Z".to_string(),
                duration_seconds: 1.0,
                total_bytes: 0,
                video_bytes: 0,
                file_count: 0,
                files: Vec::new(),
                publication_payload: Vec::new(),
                publication_signature: Vec::new(),
                publication_public_key: Vec::new(),
                publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
                gateway_verification: None,
                publication_origin: crate::device::PublicationEnvelopeOriginView::DeviceSigned,
            }
        }
    }

    impl PairingPort for FakeClient {
        fn create_pairing_request(
            &self,
            _client_name: &str,
            _client_nonce: &str,
        ) -> Result<PairingCreatedView, PiClientError> {
            Ok(PairingCreatedView {
                attempt_id: self.attempt_id.clone(),
                phase: PairingPhase::Pending,
                poll_secret: format!("poll-secret-{}", self.name),
                sas: "123456".to_string(),
                expires_at: "2026-08-01T05:00:00Z".to_string(),
                sas_publication_key_fingerprint: None,
            })
        }

        fn get_pairing_status(
            &self,
            attempt_id: &str,
            _poll_secret: &str,
        ) -> Result<PairingStatusView, PiClientError> {
            self.sink.emit(format!("{}:poll-pairing", self.name));
            self.block();
            self.sink.emit(format!("{}:poll-pairing-done", self.name));
            if let Some(queued) = self.pairing_status.lock().unwrap().pop_front() {
                return queued;
            }
            Ok(PairingStatusView {
                attempt_id: attempt_id.to_string(),
                phase: PairingPhase::Allowed,
                connection_token: Some(format!("token-{}", self.name)),
                sas: "123456".to_string(),
                expires_at: "2026-08-01T05:00:00Z".to_string(),
                sas_publication_key_fingerprint: None,
            })
        }
    }

    impl AuthenticatedDevicePort for FakeClient {
        fn heartbeat(
            &self,
            _session: &AuthenticatedPiSession,
        ) -> Result<HeartbeatOutcomeView, PiClientError> {
            self.sink.emit(format!("{}:heartbeat-enter", self.name));
            self.block();
            self.sink.emit(format!("{}:heartbeat-done", self.name));
            match self.heartbeat_failure.lock().unwrap().take() {
                Some(error) => Err(error),
                None => Ok(heartbeat_ok()),
            }
        }

        fn revoke_session(&self, _session: &AuthenticatedPiSession) -> Result<(), PiClientError> {
            Ok(())
        }

        fn get_device(
            &self,
            _session: &AuthenticatedPiSession,
        ) -> Result<DeviceInfoView, PiClientError> {
            self.sink.emit(format!("{}:get-device", self.name));
            self.block();
            self.sink.emit(format!("{}:get-device-done", self.name));
            self.device_info
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Ok(DeviceInfoView {
                        capture_activity: CaptureActivityState::Recording,
                        media_admission: "allowed".to_string(),
                        publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
                        profile: crate::device::DeviceApiProfileView::LegacyPinnedHttpsV1,
                        capabilities: crate::device::DeviceCapabilitiesView::default(),
                        capture_status: None,
                        publication_origin:
                            crate::device::PublicationEnvelopeOriginView::DeviceSigned,
                    })
                })
        }
    }

    impl SessionCatalogPort for FakeClient {
        fn list_sessions(
            &self,
            _session: &AuthenticatedPiSession,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> Result<SessionsPageView, PiClientError> {
            unimplemented!("not exercised by fleet tests")
        }

        fn get_session(
            &self,
            _session: &AuthenticatedPiSession,
            session_id: &str,
        ) -> Result<SessionDetailView, PiClientError> {
            self.sink.emit(format!("{}:get-session", self.name));
            self.block();
            self.sink.emit(format!("{}:get-session-done", self.name));
            Ok(FakeClient::session_detail(session_id))
        }

        fn delete_session(
            &self,
            _session: &AuthenticatedPiSession,
            _session_id: &str,
            _if_match_revision: &str,
            _idempotency_key: &str,
        ) -> Result<DeleteSessionReceiptView, PiClientError> {
            self.sink.emit(format!("{}:delete-session", self.name));
            self.block();
            self.sink.emit(format!("{}:delete-session-done", self.name));
            self.delete_result
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a delete_session response")
        }
    }

    impl crate::device::actor::DownloadTransportPort for FakeClient {
        fn get_file(
            &self,
            _session: &AuthenticatedPiSession,
            _session_id: &str,
            _file_id: &str,
            _if_match: Option<&str>,
            _range: Option<crate::device::actor::ByteRangeRequest>,
        ) -> Result<FileDownloadView, PiClientError> {
            unimplemented!("not exercised by fleet tests")
        }

        fn head_file(
            &self,
            _session: &AuthenticatedPiSession,
            _session_id: &str,
            _file_id: &str,
            _if_match: Option<&str>,
        ) -> Result<FileHeadView, PiClientError> {
            unimplemented!("not exercised by fleet tests")
        }
    }

    /// Drives `handle` from `Disconnected` to `Connected` using `client`.
    fn connect(handle: &DeviceHandle, client: &FakeClient) {
        handle
            .actor()
            .start_pairing_with(client, "pc-test", "nonce")
            .expect("start_pairing_with succeeds");
        assert!(matches!(
            handle.poll_pairing_with(client),
            PollPairingOutcome::Connected { .. }
        ));
    }

    // -----------------------------------------------------------------
    // Commit 57 — identity is the full fingerprint
    // -----------------------------------------------------------------

    /// Two *different* devices whose first eight fingerprint hex characters
    /// happen to match share one short display id. Keying the fleet on that
    /// short id would silently fuse them into a single actor (one session,
    /// one bearer token, one connection state) — a real cross-device
    /// credential leak. Keyed on the full fingerprint they stay distinct.
    #[test]
    fn two_devices_with_colliding_short_ids_stay_distinct() {
        let fp_a = format!("sha256:abcdef01{}", "1".repeat(56));
        let fp_b = format!("sha256:abcdef01{}", "2".repeat(56));
        assert_eq!(
            DeviceFingerprint::new(&fp_a).short_display_id(),
            DeviceFingerprint::new(&fp_b).short_display_id(),
            "precondition: the truncated ids really do collide"
        );

        let fleet = DeviceFleet::new();
        let a = fleet.get_or_create(fp_a.as_str(), || device_for(&fp_a));
        let b = fleet.get_or_create(fp_b.as_str(), || device_for(&fp_b));

        assert_eq!(fleet.len(), 2, "one entry per real device, not per label");
        assert_ne!(a.fingerprint(), b.fingerprint());

        // State moves independently: connecting A leaves B untouched.
        let sink: RecordingSink<String> = RecordingSink::new();
        let client_a = FakeClient::new("a", "attempt-a", sink.clone());
        connect(&a, &client_a);
        assert!(matches!(
            a.connection_state(),
            ConnectionState::Connected { .. }
        ));
        assert_eq!(b.connection_state(), ConnectionState::Disconnected);

        // Lookups round-trip on the full fingerprint, in either spelling…
        assert_eq!(
            fleet
                .handle(fp_a.to_uppercase().as_str())
                .expect("case-insensitive lookup")
                .fingerprint(),
            a.fingerprint()
        );
        assert_eq!(
            fleet
                .handle(DeviceFingerprint::new(&fp_b).as_str())
                .expect("prefix-less lookup")
                .fingerprint(),
            b.fingerprint()
        );
        // …and the short id is a view, never a fingerprint the fleet accepts.
        assert!(DeviceFingerprint::parse("YLX-ABCDEF01").is_err());
        assert_eq!(a.short_display_id(), "YLX-ABCDEF01");
    }

    #[test]
    fn get_or_create_returns_the_same_handle_for_both_discovery_paths() {
        let fingerprint = format!("sha256:{}", "c".repeat(64));
        let fleet = DeviceFleet::new();
        let via_mdns = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        let via_manual = fleet.get_or_create(fingerprint.to_uppercase().as_str(), || {
            panic!("second sighting must not construct a second device")
        });

        assert_eq!(fleet.len(), 1);
        // Both handles are views of one actor: pairing through one is
        // visible through the other, so only one pairing flow can exist.
        connect(
            &via_mdns,
            &FakeClient::new("a", "attempt-1", RecordingSink::new()),
        );
        assert!(matches!(
            via_manual.connection_state(),
            ConnectionState::Connected { .. }
        ));
    }

    #[test]
    fn discovery_state_updates_only_the_discovery_axis_and_reports_changes() {
        let fingerprint = format!("sha256:{}", "d".repeat(64));
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));

        assert!(handle.set_discovery_state(DiscoveryState::Offline));
        assert!(!handle.set_discovery_state(DiscoveryState::Offline));
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.device.discovery, DiscoveryState::Offline);
        assert_eq!(snapshot.device.connection, ConnectionState::Disconnected);
        assert_eq!(
            snapshot.device.capture_activity,
            CaptureActivityState::Unknown
        );

        assert!(handle.set_discovery_state(DiscoveryState::Online));
        assert_eq!(handle.snapshot().device.discovery, DiscoveryState::Online);
    }

    // -----------------------------------------------------------------
    // Commit 58 — one blocked device does not stall the fleet
    // -----------------------------------------------------------------

    /// The regression this whole change exists for. Device A's heartbeat
    /// blocks inside the network call until the test releases it; device
    /// B's heartbeat must still run and complete meanwhile, and the fleet's
    /// own registry must stay usable.
    ///
    /// Fails on the old shape (one process-wide `Arc<Mutex<registry>>` +
    /// `actor.heartbeat_with(client)` issued while holding that lock, one device
    /// after another): B's `heartbeat-done` never arrives until A is
    /// released, so `wait_for` returns false.
    #[test]
    fn a_blocked_device_heartbeat_does_not_stall_another_device() {
        let fp_a = format!("sha256:{}", "a".repeat(64));
        let fp_b = format!("sha256:{}", "b".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let gate: Deferred<()> = Deferred::new();

        let client_a: Arc<dyn AuthenticatedDevicePort> =
            Arc::new(FakeClient::new("a", "attempt-a", sink.clone()).gated(gate.clone()));
        let client_b: Arc<dyn AuthenticatedDevicePort> =
            Arc::new(FakeClient::new("b", "attempt-b", sink.clone()));

        let fleet = Arc::new(DeviceFleet::new());
        let handle_a = fleet.get_or_create(fp_a.as_str(), || device_for(&fp_a));
        let handle_b = fleet.get_or_create(fp_b.as_str(), || device_for(&fp_b));
        connect(
            &handle_a,
            &FakeClient::new("a", "attempt-a", RecordingSink::new()),
        );
        connect(
            &handle_b,
            &FakeClient::new("b", "attempt-b", RecordingSink::new()),
        );
        sink.take();

        let key_a = DeviceFingerprint::new(&fp_a);
        let sweeper = {
            let fleet = fleet.clone();
            std::thread::spawn(move || {
                fleet.heartbeat_all(4, |fingerprint| {
                    if *fingerprint == key_a {
                        Some(client_a.clone())
                    } else {
                        Some(client_b.clone())
                    }
                })
            })
        };

        // A is stuck in the network call. B must nevertheless finish.
        assert!(
            sink.wait_for(3, DEFAULT_TEST_TIMEOUT),
            "device B's heartbeat must complete while device A is blocked; saw {:?}",
            sink.events()
        );
        let seen = sink.events();
        assert!(
            seen.contains(&"b:heartbeat-done".to_string()),
            "expected B to have completed, saw {seen:?}"
        );
        assert!(
            !seen.contains(&"a:heartbeat-done".to_string()),
            "device A is supposed to still be blocked, saw {seen:?}"
        );

        // …and the fleet's own registry lock is free the whole time.
        let fp_c = format!("sha256:{}", "d".repeat(64));
        assert!(fleet.handle(fp_b.as_str()).is_some());
        fleet.get_or_create(fp_c.as_str(), || device_for(&fp_c));
        assert_eq!(fleet.len(), 3);

        gate.release(());
        let reports = sweeper.join().expect("heartbeat sweep thread");
        assert_eq!(reports.len(), 2);
        for report in reports {
            assert_eq!(report.outcome, HeartbeatApplyOutcome::Renewed);
        }
    }

    #[test]
    fn heartbeat_sweep_runs_at_most_four_devices_concurrently() {
        let sink: RecordingSink<String> = RecordingSink::new();
        let gate: Deferred<()> = Deferred::new();
        let fleet = Arc::new(DeviceFleet::new());
        let mut clients: HashMap<DeviceFingerprint, Arc<dyn AuthenticatedDevicePort>> =
            HashMap::new();

        for (name, byte) in [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")] {
            let fingerprint = format!("sha256:{}", byte.repeat(64));
            let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
            connect(
                &handle,
                &FakeClient::new(name, "connect", RecordingSink::new()),
            );
            clients.insert(
                DeviceFingerprint::new(&fingerprint),
                Arc::new(FakeClient::new(name, "poll", sink.clone()).gated(gate.clone())),
            );
        }

        let sweeper = {
            let fleet = fleet.clone();
            std::thread::spawn(move || {
                fleet.heartbeat_all(4, |fingerprint| clients.get(fingerprint).cloned())
            })
        };

        assert!(
            sink.wait_for(4, DEFAULT_TEST_TIMEOUT),
            "four worker slots must enter their network calls"
        );
        let blocked = sink.events();
        assert_eq!(blocked.len(), 4, "a fifth request must wait for a slot");
        assert!(blocked
            .iter()
            .all(|event| event.ends_with(":heartbeat-enter")));

        assert!(gate.release(()));
        let reports = sweeper.join().expect("heartbeat sweep thread");
        assert_eq!(reports.len(), 5);
        let completed = sink.events();
        assert_eq!(
            completed
                .iter()
                .filter(|event| event.ends_with(":heartbeat-enter"))
                .count(),
            5
        );
        assert_eq!(
            completed
                .iter()
                .filter(|event| event.ends_with(":heartbeat-done"))
                .count(),
            5
        );
    }

    /// The same regression for the paths a *user* is waiting on rather
    /// than a background timer: while device A sits inside an unanswered
    /// `GET /sessions/{id}`, device B must still be able to finish a
    /// pairing poll, a catalog/detail read and a delete — and the fleet
    /// itself must still register new devices.
    ///
    /// Fails on the old shape: every one of those paths reached its actor
    /// through `registry.lock().unwrap()` and then did its network call
    /// while holding that one mutex, so B's first line here would block
    /// until A's request came back.
    #[test]
    fn a_blocked_device_does_not_stall_another_devices_pairing_catalog_or_delete() {
        let fp_a = format!("sha256:{}", "a".repeat(64));
        let fp_b = format!("sha256:{}", "b".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let gate: Deferred<()> = Deferred::new();

        let fleet = Arc::new(DeviceFleet::new());
        let handle_a = fleet.get_or_create(fp_a.as_str(), || device_for(&fp_a));
        let handle_b = fleet.get_or_create(fp_b.as_str(), || device_for(&fp_b));
        connect(
            &handle_a,
            &FakeClient::new("a", "attempt-a", RecordingSink::new()),
        );
        connect(
            &handle_b,
            &FakeClient::new("b", "attempt-b", RecordingSink::new()),
        );

        // Device A goes into an authenticated read and never comes back.
        let client_a = FakeClient::new("a", "attempt-a", sink.clone()).gated(gate.clone());
        let stuck = {
            let handle_a = handle_a.clone();
            std::thread::spawn(move || handle_a.get_session_with(&client_a, "sess-a"))
        };
        assert!(
            sink.wait_for(1, DEFAULT_TEST_TIMEOUT),
            "device A must actually be inside its network call"
        );

        // Device B's user-facing paths, every one of which the old shape
        // serialized behind A: catalog/detail …
        let client_b = FakeClient::new("b", "attempt-b", sink.clone());
        assert!(matches!(
            handle_b.get_session_with(&client_b, "sess-b"),
            SessionDetailOutcome::Fetched(detail) if detail.session_id == "sess-b"
        ));

        // … delete …
        let receipt = DeleteSessionReceiptView {
            session_id: "sess-b".to_string(),
            revision: "rev-1".to_string(),
            deleted_at: "2026-08-01T05:00:00Z".to_string(),
        };
        client_b
            .delete_result
            .lock()
            .unwrap()
            .push_back(Ok(receipt.clone()));
        assert_eq!(
            handle_b.delete_session_with(&client_b, "sess-b", "rev-1", "idem-b"),
            DeleteApplyOutcome::Deleted(receipt)
        );

        // … disconnect, and a fresh pairing flow afterwards.
        handle_b.disconnect_with(&client_b).expect("revoke");
        assert_eq!(handle_b.connection_state(), ConnectionState::Disconnected);
        let repair = FakeClient::new("b", "attempt-b2", sink.clone());
        handle_b
            .actor()
            .start_pairing_with(&repair, "pc-test", "nonce-b2")
            .expect("pairing starts while A is stuck");
        assert!(matches!(
            handle_b.poll_pairing_with(&repair),
            PollPairingOutcome::Connected { .. }
        ));

        // … and the fleet's own map never stopped accepting devices.
        let fp_c = format!("sha256:{}", "c".repeat(64));
        fleet.get_or_create(fp_c.as_str(), || device_for(&fp_c));
        assert_eq!(fleet.len(), 3);

        let seen = sink.events();
        assert!(
            !seen.contains(&"a:get-session-done".to_string())
                && !seen.contains(&"a:get-device-done".to_string()),
            "device A was supposed to still be blocked, saw {seen:?}"
        );

        gate.release(());
        assert!(matches!(
            stuck.join().expect("A's thread"),
            SessionDetailOutcome::Fetched(_)
        ));
    }

    /// A session detail read under a connection the user has since ended
    /// describes a session state this process can no longer act on — it
    /// must not be handed back as if it were current.
    #[test]
    fn a_late_session_detail_reply_from_a_superseded_epoch_is_discarded() {
        let fingerprint = format!("sha256:{}", "3".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let gate: Deferred<()> = Deferred::new();
        let fleet = Arc::new(DeviceFleet::new());
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));

        let client = FakeClient::new("a", "attempt-1", sink.clone());
        connect(&handle, &client);
        // A cached publication identity, so the read is a single blocked
        // `GET /sessions/{id}` with nothing else in front of it.
        assert_eq!(
            handle.refresh_capture_activity_with(&client),
            RefreshApplyOutcome::Refreshed
        );

        sink.take();

        let blocked = FakeClient::new("a", "attempt-1", sink.clone()).gated(gate.clone());
        let reader = {
            let handle = handle.clone();
            std::thread::spawn(move || handle.get_session_with(&blocked, "sess-1"))
        };
        assert!(
            sink.wait_for(1, DEFAULT_TEST_TIMEOUT),
            "the read must be in flight before the world moves on; saw {:?}",
            sink.events()
        );

        // The user disconnects and re-pairs while that read is outstanding.
        handle.actor().disconnect_with(&client).expect("disconnect");
        let client2 = FakeClient::new("a", "attempt-2", sink.clone());
        connect(&handle, &client2);
        assert_eq!(handle.current_epoch(), Some(2));

        gate.release(());
        assert_eq!(
            reader.join().expect("reader thread"),
            SessionDetailOutcome::Stale,
            "a detail read under the ended session must not be reported as current"
        );
    }

    #[test]
    fn heartbeat_all_skips_devices_without_a_client_or_connection() {
        let fp_a = format!("sha256:{}", "a".repeat(64));
        let fp_b = format!("sha256:{}", "b".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let fleet = DeviceFleet::new();
        let handle_a = fleet.get_or_create(fp_a.as_str(), || device_for(&fp_a));
        // `b` is registered but never connected.
        fleet.get_or_create(fp_b.as_str(), || device_for(&fp_b));
        connect(&handle_a, &FakeClient::new("a", "attempt-a", sink.clone()));

        let key_a = DeviceFingerprint::new(&fp_a);
        let client: Arc<dyn AuthenticatedDevicePort> =
            Arc::new(FakeClient::new("a", "attempt-a", sink.clone()));
        let reports = fleet.heartbeat_all(1, |fingerprint| {
            (*fingerprint == key_a).then(|| client.clone())
        });
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].fingerprint, key_a);
        assert_eq!(reports[0].outcome, HeartbeatApplyOutcome::Renewed);
    }

    // -----------------------------------------------------------------
    // Commit 58 — fencing
    // -----------------------------------------------------------------

    /// A heartbeat reply that comes back *after* the device was
    /// disconnected and re-paired belongs to a dead connection generation:
    /// applying it would resurrect a session the user already ended.
    #[test]
    fn a_late_heartbeat_reply_from_a_superseded_epoch_is_discarded() {
        let fingerprint = format!("sha256:{}", "e".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let client = FakeClient::new("a", "attempt-1", sink.clone());
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        connect(&handle, &client);
        assert_eq!(handle.current_epoch(), Some(1));

        // Request issued at epoch 1 …
        let ticket = handle
            .issue_heartbeat_ticket()
            .expect("connected, so a ticket is available");
        assert_eq!(ticket.epoch(), 1);

        // … the world moves on: disconnect + re-pair to epoch 2.
        handle.actor().disconnect_with(&client).expect("disconnect");
        let client2 = FakeClient::new("a", "attempt-2", sink.clone());
        connect(&handle, &client2);
        assert_eq!(handle.current_epoch(), Some(2));

        // … and only now does the epoch-1 reply arrive. Even a successful
        // Lab-v4 poll must not project its capture state into epoch 2.
        assert_eq!(
            handle.apply_heartbeat(ticket, Ok(heartbeat_ok())),
            HeartbeatApplyOutcome::Stale
        );
        assert!(
            matches!(
                handle.connection_state(),
                ConnectionState::Connected { epoch: 2, .. }
            ),
            "the live epoch-2 session must survive the stale 401, got {:?}",
            handle.connection_state()
        );
        assert_eq!(
            handle.snapshot().device.capture_activity,
            CaptureActivityState::Unknown,
            "stale epoch-1 capture evidence must not enter epoch 2"
        );
    }

    /// Same epoch, but a newer heartbeat attempt was issued while the first
    /// was still in flight: the first is superseded and its reply dropped.
    #[test]
    fn a_late_heartbeat_reply_from_a_superseded_attempt_is_discarded() {
        let fingerprint = format!("sha256:{}", "f".repeat(64));
        let client = FakeClient::new("a", "attempt-1", RecordingSink::new());
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        connect(&handle, &client);

        let first = handle.issue_heartbeat_ticket().expect("first attempt");
        let second = handle.issue_heartbeat_ticket().expect("second attempt");
        assert_eq!(first.epoch(), second.epoch());
        assert!(second.attempt() > first.attempt());

        assert_eq!(
            handle.apply_heartbeat(first, Ok(heartbeat_ok())),
            HeartbeatApplyOutcome::Stale
        );
        assert!(matches!(
            handle.connection_state(),
            ConnectionState::Connected { .. }
        ));
        assert_eq!(
            handle.snapshot().device.capture_activity,
            CaptureActivityState::Unknown,
            "superseded same-epoch capture evidence must be discarded"
        );

        // The current attempt still applies normally.
        assert_eq!(
            handle.apply_heartbeat(second, Ok(heartbeat_ok())),
            HeartbeatApplyOutcome::Renewed
        );
        assert_eq!(
            handle.snapshot().device.capture_activity,
            CaptureActivityState::Recording
        );
    }

    /// A pairing poll answered after the user restarted pairing must not
    /// connect the device on the strength of the *old* attempt.
    #[test]
    fn a_late_pairing_reply_from_a_superseded_attempt_is_discarded() {
        let fingerprint = format!("sha256:{}", "9".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let client1 = FakeClient::new("a", "attempt-1", sink.clone());
        let client2 = FakeClient::new("a", "attempt-2", sink.clone());
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));

        handle
            .actor()
            .start_pairing_with(&client1, "pc-test", "nonce-1")
            .expect("first attempt starts");
        // The user restarts pairing before the first poll comes back.
        handle
            .actor()
            .start_pairing_with(&client2, "pc-test", "nonce-2")
            .expect("second attempt starts");

        let late = Ok(PairingStatusView {
            attempt_id: "attempt-1".to_string(),
            phase: PairingPhase::Allowed,
            connection_token: Some("token-from-the-abandoned-attempt".to_string()),
            sas: "123456".to_string(),
            expires_at: "2026-08-01T05:00:00Z".to_string(),
            sas_publication_key_fingerprint: None,
        });
        assert_eq!(
            handle.actor().apply_pairing_status("attempt-1", late),
            PollPairingOutcome::Stale
        );
        assert_eq!(
            handle.connection_state(),
            ConnectionState::Pairing {
                attempt_id: "attempt-2".to_string(),
                phase: PairingPhase::Pending,
            },
            "the abandoned attempt must not connect the device"
        );

        // The live attempt still resolves.
        assert!(matches!(
            handle.poll_pairing_with(&client2),
            PollPairingOutcome::Connected { .. }
        ));
    }

    /// A delete receipt that lands after a reconnect describes a session
    /// state observed under a connection that no longer exists.
    #[test]
    fn a_late_delete_receipt_from_a_superseded_epoch_is_discarded() {
        let fingerprint = format!("sha256:{}", "7".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let client = FakeClient::new("a", "attempt-1", sink.clone());
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        connect(&handle, &client);

        let ticket = handle.issue_epoch_ticket().expect("connected");
        assert_eq!(ticket.epoch(), 1);

        handle.actor().disconnect_with(&client).expect("disconnect");
        let client2 = FakeClient::new("a", "attempt-2", sink.clone());
        connect(&handle, &client2);

        let receipt = DeleteSessionReceiptView {
            session_id: "sess-1".to_string(),
            revision: "rev-1".to_string(),
            deleted_at: "2026-08-01T05:00:00Z".to_string(),
        };
        assert_eq!(
            handle.apply_delete_receipt(ticket, Ok(receipt.clone())),
            DeleteApplyOutcome::Stale
        );

        // A delete issued under the *current* epoch applies.
        let fresh = handle.issue_epoch_ticket().expect("still connected");
        assert_eq!(
            handle.apply_delete_receipt(fresh, Ok(receipt.clone())),
            DeleteApplyOutcome::Deleted(receipt)
        );
    }

    /// The whole `delete_session` round trip runs off-lock and is fenced.
    #[test]
    fn delete_session_runs_off_lock_and_reports_the_receipt() {
        let fingerprint = format!("sha256:{}", "8".repeat(64));
        let client = FakeClient::new("a", "attempt-1", RecordingSink::new());
        let receipt = DeleteSessionReceiptView {
            session_id: "sess-1".to_string(),
            revision: "rev-1".to_string(),
            deleted_at: "2026-08-01T05:00:00Z".to_string(),
        };
        client
            .delete_result
            .lock()
            .unwrap()
            .push_back(Ok(receipt.clone()));

        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        assert_eq!(
            handle.delete_session_with(&client, "sess-1", "rev-1", "idem-1"),
            DeleteApplyOutcome::NotConnected
        );
        connect(&handle, &client);
        assert_eq!(
            handle.delete_session_with(&client, "sess-1", "rev-1", "idem-1"),
            DeleteApplyOutcome::Deleted(receipt)
        );
    }

    /// A `GET /device` reply is likewise fenced on the epoch it was issued
    /// under.
    #[test]
    fn a_late_connection_negotiation_cannot_enter_or_disconnect_a_new_epoch() {
        let fingerprint = format!("sha256:{}", "6".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let gate: Deferred<()> = Deferred::new();
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        let first = FakeClient::new("a", "attempt-1", sink.clone()).gated(gate.clone());
        connect(
            &handle,
            &FakeClient::new("a", "attempt-1", RecordingSink::new()),
        );

        let negotiating = {
            let handle = handle.clone();
            std::thread::spawn(move || handle.negotiate_device_with_for_epoch(&first, 1))
        };
        assert!(
            sink.wait_for(1, DEFAULT_TEST_TIMEOUT),
            "descriptor request must be in flight"
        );

        assert!(handle.disconnect_local_if_epoch(1));
        let second = FakeClient::new("a", "attempt-2", RecordingSink::new());
        connect(&handle, &second);
        assert_eq!(handle.current_epoch(), Some(2));
        assert!(!handle.disconnect_local_if_epoch(1));
        let stale_sink = RecordingSink::new();
        let stale = FakeClient::new("stale", "attempt-1", stale_sink.clone());
        assert_eq!(
            handle.negotiate_device_with_for_epoch(&stale, 1),
            RefreshApplyOutcome::Stale
        );
        assert!(
            stale_sink.is_empty(),
            "an old connection setup must not issue descriptor I/O through the new epoch"
        );

        assert!(gate.release(()));
        assert_eq!(
            negotiating.join().expect("negotiation thread"),
            RefreshApplyOutcome::Stale
        );
        assert_eq!(handle.current_epoch(), Some(2));
        assert!(handle.negotiated_device_snapshot().is_none());
    }

    /// A `GET /device` reply is likewise fenced on the epoch it was issued
    /// under.
    #[test]
    fn a_late_device_info_reply_from_a_superseded_epoch_is_discarded() {
        let fingerprint = format!("sha256:{}", "6".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let client = FakeClient::new("a", "attempt-1", sink.clone());
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        connect(&handle, &client);
        assert!(
            handle.negotiated_device_snapshot().is_none(),
            "a connected epoch has no negotiation until GET /device succeeds"
        );

        let ticket = handle.issue_epoch_ticket().expect("connected");
        handle.actor().disconnect_with(&client).expect("disconnect");
        let client2 = FakeClient::new("a", "attempt-2", sink.clone());
        connect(&handle, &client2);
        assert!(
            handle.negotiated_device_snapshot().is_none(),
            "reconnect must not expose the prior epoch's negotiation"
        );

        let info = DeviceInfoView {
            capture_activity: CaptureActivityState::Recording,
            media_admission: "allowed".to_string(),
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            profile: crate::device::DeviceApiProfileView::LegacyPinnedHttpsV1,
            capabilities: crate::device::DeviceCapabilitiesView::default(),
            capture_status: None,
            publication_origin: crate::device::PublicationEnvelopeOriginView::DeviceSigned,
        };
        assert_eq!(
            handle.apply_device_info(ticket, Ok(info)),
            RefreshApplyOutcome::Stale
        );
        assert_eq!(
            handle.snapshot().device.capture_activity,
            CaptureActivityState::Unknown
        );

        assert_eq!(
            handle.refresh_capture_activity_with(&client2),
            RefreshApplyOutcome::Refreshed
        );
        assert_eq!(
            handle.snapshot().device.capture_activity,
            CaptureActivityState::Recording
        );
        let negotiated = handle
            .negotiated_device_snapshot()
            .expect("current refresh installs current negotiation");
        assert_eq!(negotiated.epoch, 2);
        assert_eq!(
            negotiated.info.capture_activity,
            CaptureActivityState::Recording
        );
    }

    // -----------------------------------------------------------------
    // for_each_device
    // -----------------------------------------------------------------

    #[test]
    fn for_each_device_visits_every_device_exactly_once_within_the_concurrency_bound() {
        let fleet = DeviceFleet::new();
        for byte in ["1", "2", "3", "4", "5"] {
            let fingerprint = format!("sha256:{}", byte.repeat(64));
            fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        }

        let live = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let visited = fleet.for_each_device(2, |handle| {
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::yield_now();
            live.fetch_sub(1, Ordering::SeqCst);
            Some(handle.short_display_id())
        });

        assert_eq!(visited.len(), 5);
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "concurrency bound must be respected, peaked at {}",
            peak.load(Ordering::SeqCst)
        );
        let mut ids: Vec<_> = visited.iter().map(|(_, id)| id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 5, "each device visited exactly once");
    }

    #[test]
    fn for_each_device_on_an_empty_fleet_does_nothing() {
        let fleet = DeviceFleet::new();
        let visited = fleet.for_each_device(4, |_| Some(()));
        assert!(visited.is_empty());
        assert!(fleet.is_empty());
    }

    #[test]
    fn snapshots_are_sorted_by_full_identity_and_carry_the_short_label() {
        let fleet = DeviceFleet::new();
        let fp_b = format!("sha256:{}", "b".repeat(64));
        let fp_a = format!("sha256:{}", "a".repeat(64));
        fleet.get_or_create(fp_b.as_str(), || device_for(&fp_b));
        fleet.get_or_create(fp_a.as_str(), || device_for(&fp_a));

        let snapshots = fleet.snapshots();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].fingerprint, DeviceFingerprint::new(&fp_a));
        assert_eq!(snapshots[0].short_id, "YLX-AAAAAAAA");
        assert_eq!(snapshots[0].device.tls_fingerprint, fp_a);
        assert!(snapshots[0].fingerprint < snapshots[1].fingerprint);
    }

    #[test]
    fn a_deferred_release_is_not_needed_for_a_healthy_sweep() {
        // Sanity guard for the blocking test above: with no gate at all the
        // sweep completes without any test-side release.
        let fingerprint = format!("sha256:{}", "5".repeat(64));
        let sink: RecordingSink<String> = RecordingSink::new();
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || device_for(&fingerprint));
        let client: Arc<dyn AuthenticatedDevicePort> =
            Arc::new(FakeClient::new("a", "attempt-1", sink.clone()));
        connect(&handle, &FakeClient::new("a", "attempt-1", sink.clone()));

        let reports = fleet.heartbeat_all(4, |_| Some(client.clone()));
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].outcome, HeartbeatApplyOutcome::Renewed);
        assert!(sink.wait_for(1, Duration::from_millis(1)));
    }
}
