//! PC-02 per-device actor: owns one [`Device`]'s full connection lifecycle
//! (pairing, heartbeat, disconnect, capture-activity refresh),
//! independent of every other device's actor -- plan section 16 "PC-02
//! Per-device actor 与 connection lifecycle" ("一台设备故障不阻塞其他设备
//! actor", "a fault on one device must never block another device's
//! actor").
//!
//! # Why capability ports instead of depending on adapters directly
//!
//! This crate (`ylx-transfer-core`) has zero dependency on `tauri`,
//! `reqwest`, or any network crate (see the crate root doc comment) --
//! `ylx-transfer-adapters` depends on `ylx-transfer-core`, never the
//! reverse. The small capability traits below are therefore the seams: the
//! actor depends only on the operation it is performing, and the adapters
//! crate implements those traits for its real HTTP client. This module never
//! references `PiHttpClient` or `PiHttpError` by name; tests inject focused
//! fake capability implementations instead of a real network client.
//!
//! # Connection epoch
//!
//! [`ConnectionState::Connected`] carries an `epoch` (see
//! `crate::device` module docs). Every successful pairing-to-connected
//! transition here allocates a fresh epoch (a simple monotonically
//! increasing counter -- the Pi wire protocol has no epoch concept of its
//! own to reuse). [`DeviceActor::apply_heartbeat_result`] is the
//! staleness guard: it takes the epoch the caller observed when it
//! *issued* the heartbeat request, and refuses to mutate state if the
//! actor has since moved to a different epoch (e.g. disconnected and
//! reconnected while that request was in flight) -- exactly the "old
//! epoch callback ignored" property plan section 16 requires.
//! [`DeviceActor::apply_pairing_status`] applies the analogous guard for
//! pairing polls, keyed by `attempt_id` instead (a device is not
//! connected yet, so there is no epoch to key on): a poll response for an
//! `attempt_id` that no longer matches the actor's current pairing
//! attempt is stale and ignored, so an old (superseded) pairing attempt
//! resolving late can never corrupt a newer attempt's state.
//!
//! # Token secrecy
//!
//! The Pi's one-shot `connection_token` (bearer credential for
//! authenticated calls) is moved directly into [`AuthenticatedPiSession`].
//! That session uses [`Secret`]'s redacted `Debug` implementation and travels
//! through authenticated capability ports together with its TLS pin,
//! publication identity, and connection epoch. The actor never stores or
//! returns a second raw-token representation.

use std::fmt;
use std::io::{Cursor, Read};

use crate::device::{CaptureActivityState, ConnectionState, Device, DiscoveryState, PairingPhase};
use crate::secret::Secret;

/// Coarse classification of a Pi capability call failure -- just
/// enough for this actor's state-transition logic to branch on (only a 401
/// proves the bearer token is no longer valid), not a full mirror of the Pi
/// wire error registry (that's
/// `ylx_transfer_adapters::pi_http::PiApiErrorCode`'s job, one layer
/// down, on the other side of this port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiClientErrorKind {
    /// The Pi rejected the credential (401) -- session token invalid,
    /// revoked, or never valid.
    Unauthorized,
    /// The call did not complete in time.
    Timeout,
    /// An opaque session-list cursor was bound to an older complete catalog.
    /// The current device revision is retained so application callers can
    /// discard the old chain and restart from the first page.
    CatalogChanged { catalog_revision: String },
    /// Any other failure (network, decode, wire-protocol error, ...).
    Other,
}

/// Everything a Pi capability call can fail with, as far as
/// [`DeviceActor`] needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiClientError {
    pub kind: PiClientErrorKind,
    pub message: String,
}

impl fmt::Display for PiClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pi client error ({:?}): {}", self.kind, self.message)
    }
}

impl std::error::Error for PiClientError {}

/// Result of `POST /pairing-requests`, trimmed to what the actor needs.
///
/// `sas_publication_key_fingerprint` is the publication-key identity the
/// user's short-authentication-string confirmation actually covers (one of
/// ADR-SEC-002's seven transcript fields, independently validated by the
/// adapter before the SAS is derived and shown). It is carried here so the
/// actor can bind that confirmed identity to the resulting authenticated
/// session -- see [`DeviceActor::sas_publication_key_fingerprint`].
#[derive(Debug, Clone)]
pub struct PairingCreatedView {
    pub attempt_id: String,
    pub phase: PairingPhase,
    pub poll_secret: String,
    pub sas: String,
    pub expires_at: String,
    pub sas_publication_key_fingerprint: Option<String>,
}

/// Result of `GET /pairing-requests/{id}`, trimmed to what the actor
/// needs. `connection_token` is one-shot (only present the first time the
/// attempt is observed as `allowed`) -- mirrored here exactly as PC-03's
/// `PairingStatus` documents it.
#[derive(Debug, Clone)]
pub struct PairingStatusView {
    pub attempt_id: String,
    pub phase: PairingPhase,
    pub connection_token: Option<String>,
    pub sas: String,
    pub expires_at: String,
    /// Publication-key identity covered by this attempt's SAS transcript,
    /// mirrored from the poll response (see
    /// [`PairingCreatedView::sas_publication_key_fingerprint`]).
    pub sas_publication_key_fingerprint: Option<String>,
}

/// Result of one periodic liveness poll, trimmed to what the actor needs.
/// Legacy heartbeat responses carry no capture evidence; Device API v4 uses
/// its authoritative capture-status snapshot as both liveness and activity
/// evidence so one fenced response updates both axes.
#[derive(Debug, Clone)]
pub struct HeartbeatOutcomeView {
    pub idle_timeout_ms: u64,
    pub absolute_expires_at: String,
    pub capture_activity: Option<CaptureActivityState>,
}

/// Result of `GET /device`, trimmed to what the actor needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceApiProfileView {
    #[default]
    LegacyPinnedHttpsV1,
    LabHttpV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapabilitySourceView {
    DeviceDescriptor,
    ProfileContract,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NegotiatedCapabilityView {
    pub supported: bool,
    pub source: CapabilitySourceView,
}

/// Explicit command/query capabilities negotiated for the authenticated
/// device. Callers must gate operations on these facts rather than infer
/// support from a profile name or from whether a session has files.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceCapabilitiesView {
    pub capture: NegotiatedCapabilityView,
    pub preview: NegotiatedCapabilityView,
    pub range_download: NegotiatedCapabilityView,
    pub network_mutation: NegotiatedCapabilityView,
    pub calibration_capture: NegotiatedCapabilityView,
    pub session_list: NegotiatedCapabilityView,
    pub session_detail: NegotiatedCapabilityView,
    pub artifact_download: NegotiatedCapabilityView,
    pub capture_status: NegotiatedCapabilityView,
    pub session_deletion: NegotiatedCapabilityView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureDeviceStateView {
    Idle,
    Recording,
    Finalizing,
    Encoding,
    Verifying,
    Blocked,
    Unknown(String),
}

/// Authoritative Device API v4 capture status. In particular,
/// `active_recording` comes from `/capture/status`, never from preview or
/// live-IMU availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatusView {
    pub authority_epoch: String,
    pub source_revision: u64,
    pub device_state: CaptureDeviceStateView,
    pub active_recording: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PublicationEnvelopeOriginView {
    #[default]
    DeviceSigned,
    ClientDerivedLabCompatibility,
}

#[derive(Debug, Clone)]
pub struct DeviceInfoView {
    pub capture_activity: CaptureActivityState,
    pub media_admission: String,
    /// Authenticated `GET /device` identity of the Pi's current
    /// publication-signing key (`sha256:<64 lowercase hex>`).
    pub publication_key_fingerprint: String,
    pub profile: DeviceApiProfileView,
    pub capabilities: DeviceCapabilitiesView,
    pub capture_status: Option<CaptureStatusView>,
    pub publication_origin: PublicationEnvelopeOriginView,
}

/// One completed recording session's summary, mirroring
/// `PiHttpClient::list_sessions`'s real wire response (`SessionSummary`,
/// via `GET /sessions`) -- **not** the full `PublicationManifest`. The
/// list endpoint deliberately never includes a per-file inventory (only
/// aggregate `total_bytes`/`video_bytes`/`file_count` -- see
/// `pi_http.rs`'s `SessionSummary` doc comment, itself citing the Pi-side
/// `http_handlers.py`'s `_summary_to_wire`), so this view has no `files`
/// field. `GET /sessions/{id}` (singular) is different: it returns the
/// richer [`SessionDetailView`] below, which *does* carry a real `files`
/// list -- see that type's doc comment. See
/// [`DeviceActor::download_file_with`]/[`DeviceActor::head_file_with`] for what is
/// possible once a `FileId` is already known (from `SessionDetailView` or
/// any other source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayVerificationVerdictView {
    Usable,
    Unusable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayVerificationDiagnosticView {
    LegacyMessage(String),
    Structured { code: String, summary: String },
}

/// Exact gateway verification facts returned by Device API v4. This view
/// preserves the device verdict and validator identity; callers may derive
/// availability, but must not invent additional wire verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayVerificationView {
    pub actor: String,
    pub validator_name: String,
    pub validator_version: String,
    pub validator_build_sha256: String,
    pub manifest_sha256: String,
    /// Whether the adapter accepted `manifest_sha256` as exactly 64
    /// lowercase hexadecimal characters. The raw safe value remains visible
    /// for diagnostics even when this is false.
    pub manifest_digest_valid: bool,
    pub verified_at: String,
    pub verdict: GatewayVerificationVerdictView,
    pub diagnostics: Vec<GatewayVerificationDiagnosticView>,
}

impl GatewayVerificationView {
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.verdict == GatewayVerificationVerdictView::Usable
    }

    #[must_use]
    pub fn revision(&self) -> String {
        if self.manifest_digest_valid {
            format!("sha256:{}", self.manifest_sha256)
        } else {
            String::new()
        }
    }

    #[must_use]
    pub fn is_detail_eligible(&self) -> bool {
        self.is_usable() && self.manifest_digest_valid
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionSummaryView {
    pub session_id: String,
    pub revision: String,
    pub captured_at: String,
    pub published_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    pub file_count: u64,
    /// `None` means missing or stale, never an implicit usable verdict.
    pub gateway_verification: Option<GatewayVerificationView>,
}

/// One entry in [`SessionDetailView::files`], mirroring the Conductor wire
/// shape for each element of `GET /sessions/{id}`'s `files[]` array exactly.
/// `id` is the opaque `FileId` string that round-trips against
/// `GET /sessions/{id}/files/{file_id}` (see [`DeviceActor::download_file_with`]/
/// [`DeviceActor::head_file_with`]) -- never derive a download path from
/// `display_path` instead, only from `id`. All six fields are always
/// present on the wire (never optional/null): a session only becomes
/// visible via this endpoint at all once every file's `sha256`/
/// `media_type` has been fully computed and validated on the Pi side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFileEntryView {
    pub id: String,
    pub display_path: String,
    pub role: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub media_type: String,
}

/// Result of `GET /sessions/{id}` (singular) -- a strict superset of
/// [`SessionSummaryView`]'s aggregate fields plus the real per-file
/// inventory (`files`). Kept as its own type rather than adding `files`
/// directly onto `SessionSummaryView`, because `GET /sessions` (list)
/// genuinely never includes `files[]` on the wire (see
/// `http_handlers.py`'s `_summary_to_wire`, deliberately distinct from
/// `_detail_to_wire`) -- `SessionSummaryView` would otherwise carry a
/// field that's always populated for one call and always empty for
/// another, with no way to tell the difference from the type alone. This
/// is what closes the gap `PC-08b`'s [`SessionSummaryView`] doc comment
/// used to describe as blocked: a real caller can now build a real
/// `TransferRequest`/`JobFile` list straight from `files` -- see
/// `composition::download_session` in the `ylx-transfer` (Tauri) crate.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionDetailView {
    pub session_id: String,
    pub revision: String,
    pub captured_at: String,
    pub published_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    pub file_count: u64,
    pub files: Vec<SessionFileEntryView>,
    /// Exact canonical UTF-8 JSON bytes covered by the detached signature.
    pub publication_payload: Vec<u8>,
    /// Raw 64-byte Ed25519 signature decoded from the wire hex.
    pub publication_signature: Vec<u8>,
    /// Raw 32-byte Ed25519 public key decoded from the wire hex.
    pub publication_public_key: Vec<u8>,
    /// Envelope fingerprint, already compared with the authenticated
    /// `/device` identity by the production session-catalog adapter.
    pub publication_key_fingerprint: String,
    pub gateway_verification: Option<GatewayVerificationView>,
    pub publication_origin: PublicationEnvelopeOriginView,
}

/// Result of `GET /sessions` (paginated via `cursor`/`limit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatalogRevisionAuthorityView {
    #[default]
    LegacyDevice,
    DeviceStable,
    LocalFirstPageCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginationUnavailableReasonView {
    FirmwareUpgradeRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionDiscoveryDiagnosticCodeView {
    ManifestUnreadable,
    UnsupportedSchema,
    ManifestInvalid,
    ManifestNotSealed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDiscoveryDiagnosticView {
    pub quarantine_id: String,
    pub code: SessionDiscoveryDiagnosticCodeView,
    pub observed_at: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionsPageView {
    pub catalog_revision: Option<String>,
    pub sessions: Vec<SessionSummaryView>,
    pub next_cursor: Option<String>,
    pub catalog_authority: CatalogRevisionAuthorityView,
    pub pagination_supported: bool,
    pub pagination_unavailable_reason: Option<PaginationUnavailableReasonView>,
    pub diagnostics: Vec<SessionDiscoveryDiagnosticView>,
}

/// Result of `DELETE /sessions/{id}`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeleteSessionReceiptView {
    pub session_id: String,
    pub revision: String,
    pub deleted_at: String,
}

/// A single-range byte-range request, mirroring
/// `ylx_transfer_adapters::pi_http::RangeRequest`'s exact wire shape --
/// duplicated here rather than depended-on, since this crate has zero
/// dependency on `ylx-transfer-adapters` (see module doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRangeRequest {
    From { start: u64 },
    Bounded { start: u64, end: u64 },
    Suffix { length: u64 },
}

/// Result of `GET /sessions/{id}/files/{file_id}`, trimmed to what the
/// actor needs. `content_range` is `Some((start, end, total_size))` iff a
/// `Range` was honored (`status == 206`).
#[derive(Debug, Clone)]
pub struct FileDownloadView {
    pub status: u16,
    pub etag: String,
    pub media_type: String,
    pub content_length: u64,
    pub content_range: Option<(u64, u64, u64)>,
    pub body: Vec<u8>,
}

/// Streaming counterpart to [`FileDownloadView`]. Production downloads use
/// this shape so a multi-gigabyte file is copied by the coordinator in
/// bounded chunks instead of being materialized in the actor boundary.
pub struct FileStreamView {
    pub status: u16,
    pub etag: String,
    pub media_type: String,
    pub content_length: u64,
    pub content_range: Option<(u64, u64, u64)>,
    pub body: Box<dyn Read + Send>,
}

/// Result of `HEAD /sessions/{id}/files/{file_id}` -- headers only, never
/// ranged.
#[derive(Debug, Clone)]
pub struct FileHeadView {
    pub etag: String,
    pub media_type: String,
    pub content_length: u64,
}

/// The pairing-only capability needed to establish a session.
pub trait PairingPort: Send + Sync {
    fn create_pairing_request(
        &self,
        client_name: &str,
        client_nonce: &str,
    ) -> Result<PairingCreatedView, PiClientError>;

    fn get_pairing_status(
        &self,
        attempt_id: &str,
        poll_secret: &str,
    ) -> Result<PairingStatusView, PiClientError>;
}

/// The authenticated device capability: liveness, revocation, and the
/// independently-authenticated device identity endpoint. Methods receive
/// an [`AuthenticatedPiSession`] rather than a bare token, so callers
/// cannot accidentally use a token with the wrong TLS/publication binding.
pub trait AuthenticatedDevicePort: Send + Sync {
    fn heartbeat(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<HeartbeatOutcomeView, PiClientError>;

    fn revoke_session(&self, session: &AuthenticatedPiSession) -> Result<(), PiClientError>;

    fn get_device(&self, session: &AuthenticatedPiSession)
        -> Result<DeviceInfoView, PiClientError>;

    /// Negotiates descriptor/capability facts for a newly connected epoch.
    /// Legacy transports use their ordinary authenticated device read. A
    /// transport with an independently polled activity endpoint may override
    /// this so connection setup does not duplicate that periodic request.
    fn negotiate_device(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<DeviceInfoView, PiClientError> {
        self.get_device(session)
    }
}

/// The authenticated session-catalog capability. Publication identity is
/// supplied by the session itself; there is no caller-controlled expected
/// fingerprint argument on this port.
pub trait SessionCatalogPort: Send + Sync {
    fn list_sessions(
        &self,
        session: &AuthenticatedPiSession,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError>;

    fn get_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
    ) -> Result<SessionDetailView, PiClientError>;

    /// Fetches detail while binding the exact response bytes to a current,
    /// known-usable gateway verification selected from the session list.
    /// Implementations that cannot provide that binding fail closed.
    fn get_verified_session(
        &self,
        _session: &AuthenticatedPiSession,
        _session_id: &str,
        _verification: &GatewayVerificationView,
    ) -> Result<SessionDetailView, PiClientError> {
        Err(PiClientError {
            kind: PiClientErrorKind::Other,
            message: "verified session detail is not supported by this catalog port".to_string(),
        })
    }

    fn delete_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> Result<DeleteSessionReceiptView, PiClientError>;
}

/// Convenience object-safe composition for workflows that need both the
/// authenticated `/device` identity refresh and session-catalog reads (for
/// example a legacy session whose first GET /device binds its publication
/// key). Individual callers can still depend on either smaller trait.
pub trait AuthenticatedCatalogPort: AuthenticatedDevicePort + SessionCatalogPort {}

impl<T: AuthenticatedDevicePort + SessionCatalogPort + ?Sized> AuthenticatedCatalogPort for T {}

/// The file-download capability. It is intentionally separate from the
/// session catalog so a resumable transfer fake only implements the two
/// transport calls it needs.
pub trait DownloadTransportPort: Send + Sync {
    fn get_file(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileDownloadView, PiClientError>;

    fn head_file(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
    ) -> Result<FileHeadView, PiClientError>;

    /// Streaming file transport used by production transfer jobs. The
    /// default implementation preserves source compatibility for small test
    /// fakes by wrapping the bounded `get_file` body in an in-memory reader.
    fn get_file_stream(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileStreamView, PiClientError> {
        let view = self.get_file(session, session_id, file_id, if_match, range)?;
        Ok(FileStreamView {
            status: view.status,
            etag: view.etag,
            media_type: view.media_type,
            content_length: view.content_length,
            content_range: view.content_range,
            body: Box::new(Cursor::new(view.body)),
        })
    }
}

// =====================================================================
// AuthenticatedPiSession (commit 56)
// =====================================================================

/// A single authenticated Pi session, with all identity facts that must
/// travel together after pairing.
///
/// The bearer token is held in [`Secret`], the TLS pin is retained so a
/// caller cannot accidentally use a session with another endpoint, and the
/// SAS-confirmed publication identity is immutable once present. The
/// connection epoch fences replies from an older authenticated session.
/// There is no public accessor returning the token; capability ports above
/// borrow it only for the duration of one adapter call.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedPiSession {
    token: Secret,
    tls_pin: String,
    publication_key_fingerprint: Option<String>,
    epoch: u64,
}

impl fmt::Debug for AuthenticatedPiSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedPiSession")
            .field("token", &self.token)
            .field("tls_pin", &self.tls_pin)
            .field(
                "publication_key_fingerprint",
                &self.publication_key_fingerprint,
            )
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// Construction/binding failures for [`AuthenticatedPiSession`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatedPiSessionError {
    #[error("authenticated Pi session token must not be empty")]
    EmptyToken,
    #[error("authenticated Pi session TLS pin must not be empty")]
    EmptyTlsPin,
    #[error("authenticated Pi session publication key fingerprint is invalid: {0}")]
    InvalidPublicationKey(String),
    #[error("authenticated Pi session epoch must be greater than zero")]
    InvalidEpoch,
    #[error(
        "device publication key identity changed since the SAS-confirmed pairing; re-pair to confirm the new key"
    )]
    PublicationKeyChanged,
    #[error("authenticated Pi session has no SAS-confirmed publication key")]
    MissingPublicationKey,
}

impl From<AuthenticatedPiSessionError> for PiClientError {
    fn from(error: AuthenticatedPiSessionError) -> Self {
        PiClientError {
            kind: PiClientErrorKind::Other,
            message: error.to_string(),
        }
    }
}

impl AuthenticatedPiSession {
    /// Create a session after an allowed pairing response. A legacy
    /// transcript-less pairing may pass `None` and bind its identity on the
    /// first authenticated `GET /device`; modern SAS-confirmed pairings
    /// should always pass `Some(fingerprint)`.
    pub fn new(
        token: impl Into<Secret>,
        tls_pin: impl Into<String>,
        publication_key_fingerprint: Option<String>,
        epoch: u64,
    ) -> Result<Self, AuthenticatedPiSessionError> {
        let token = token.into();
        if token.is_empty() {
            return Err(AuthenticatedPiSessionError::EmptyToken);
        }
        let tls_pin = tls_pin.into();
        if tls_pin.trim().is_empty() {
            return Err(AuthenticatedPiSessionError::EmptyTlsPin);
        }
        if epoch == 0 {
            return Err(AuthenticatedPiSessionError::InvalidEpoch);
        }
        if let Some(fingerprint) = &publication_key_fingerprint {
            validate_publication_key_fingerprint(fingerprint)?;
        }
        Ok(Self {
            token,
            tls_pin,
            publication_key_fingerprint,
            epoch,
        })
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Explicit spelling for call sites that model the value as a session
    /// epoch rather than a generic counter.
    #[must_use]
    pub fn session_epoch(&self) -> u64 {
        self.epoch
    }

    /// The endpoint's TLS pin. It is an identity value, not a credential.
    #[must_use]
    pub fn tls_pin(&self) -> &str {
        &self.tls_pin
    }

    /// Alias matching the device DTO vocabulary.
    #[must_use]
    pub fn tls_fingerprint(&self) -> &str {
        self.tls_pin()
    }

    /// The SAS-confirmed publication key identity, if this was a legacy
    /// transcript-less pairing that has not yet completed its first device
    /// identity read.
    #[must_use]
    pub fn publication_key_fingerprint(&self) -> Option<&str> {
        self.publication_key_fingerprint.as_deref()
    }

    /// Alias making the SAS provenance explicit at call sites.
    #[must_use]
    pub fn sas_publication_key_fingerprint(&self) -> Option<&str> {
        self.publication_key_fingerprint()
    }

    /// Verify an authenticated `/device` identity against this session's
    /// immutable SAS binding. A missing legacy binding accepts the first
    /// valid identity; callers can then install the returned bound session
    /// with [`Self::bind_publication_key`].
    pub fn ensure_publication_key(
        &self,
        observed: &str,
    ) -> Result<(), AuthenticatedPiSessionError> {
        validate_publication_key_fingerprint(observed)?;
        if let Some(expected) = &self.publication_key_fingerprint {
            if expected != observed {
                return Err(AuthenticatedPiSessionError::PublicationKeyChanged);
            }
        }
        Ok(())
    }

    /// Return a new session with the first authenticated publication key
    /// bound. Once a key is present, this method only accepts the same key;
    /// key rotation requires a new SAS pairing and therefore a new epoch.
    pub fn bind_publication_key(
        &self,
        observed: impl Into<String>,
    ) -> Result<Self, AuthenticatedPiSessionError> {
        let observed = observed.into();
        self.ensure_publication_key(&observed)?;
        let mut bound = self.clone();
        bound.publication_key_fingerprint = Some(observed);
        Ok(bound)
    }

    /// Runs one trusted adapter operation with a borrowed bearer token. The
    /// token is never returned, cloned, or stored by this API; this narrow
    /// callback is the adapter boundary needed for streaming responses that
    /// cannot be represented by the owned-body compatibility DTO.
    pub fn with_authenticated_token<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        operation(self.token.expose_secret())
    }
}

fn validate_publication_key_fingerprint(value: &str) -> Result<(), AuthenticatedPiSessionError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(AuthenticatedPiSessionError::InvalidPublicationKey(
            "expected sha256:<64 lowercase hex>".to_string(),
        ));
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AuthenticatedPiSessionError::InvalidPublicationKey(
            "expected sha256:<64 lowercase hex>".to_string(),
        ));
    }
    Ok(())
}

// =====================================================================
// Outcome types
// =====================================================================

/// What a successful [`DeviceActor::start_pairing_with`] call hands back to
/// the caller (e.g. to show the SAS to the user for out-of-band
/// confirmation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAttemptInfo {
    pub attempt_id: String,
    pub sas: String,
    pub expires_at: String,
}

/// What applying a pairing-status response did to the actor's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollPairingOutcome {
    /// The actor was not in `Pairing` state; nothing to poll.
    NotPairing,
    /// The response was for an `attempt_id` that no longer matches the
    /// actor's current pairing attempt (a superseded/late response) --
    /// ignored, current state untouched.
    Stale,
    /// Still `pending`; state unchanged (still `Pairing`).
    StillPending,
    /// Transitioned to `Connected` at this fresh epoch.
    Connected { epoch: u64 },
    /// The Pi operator rejected (or the attempt was cancelled); actor is
    /// now `Disconnected`.
    Rejected,
    /// The pairing attempt itself expired before being resolved; actor is
    /// now `Expired`.
    Expired,
    /// The pairing capability call failed (network/decode/etc); state
    /// left unchanged so the caller can retry the poll.
    Error(PiClientErrorKind),
}

/// What applying a heartbeat response did to the actor's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatApplyOutcome {
    /// The actor was not `Connected`; nothing to renew.
    NotConnected,
    /// The response was for an epoch the actor has since moved past
    /// (reconnected/disconnected while the request was in flight) --
    /// ignored, current state untouched.
    Stale,
    /// Session renewed; still `Connected` at the same epoch.
    Renewed,
    /// The Pi explicitly rejected the token with 401; actor is now `Expired`
    /// and its token cleared.
    Expired,
    /// Any other call failure; state left unchanged so the caller can
    /// retry.
    Error(PiClientErrorKind),
}

// =====================================================================
// DeviceActor
// =====================================================================

/// Owns one device's live connection state. A bug, hang, or error talking
/// to one device's actor has no way to reach another `DeviceActor`
/// instance -- there is no shared mutable state between them (see the
/// `two_devices_are_independent` test).
#[derive(Debug)]
pub struct DeviceActor {
    device: Device,
    poll_secret: Option<String>,
    /// The complete authenticated-session identity and sole owner of the
    /// bearer credential after pairing succeeds.
    authenticated_session: Option<AuthenticatedPiSession>,
    next_epoch: u64,
    media_admission: Option<String>,
    publication_key_fingerprint: Option<String>,
    negotiated_device_info: Option<DeviceInfoView>,
    /// Publication-key identity offered by the *in-flight* pairing attempt's
    /// SAS transcript. Promoted to `sas_publication_key_fingerprint` only
    /// once that attempt is actually allowed (i.e. the user confirmed the
    /// SAS on the Pi), and dropped otherwise.
    pending_sas_publication_key_fingerprint: Option<String>,
    /// The publication-key identity the user's SAS confirmation covered for
    /// the *current* session -- the trust anchor every later authenticated
    /// request is bound to.
    sas_publication_key_fingerprint: Option<String>,
}

impl DeviceActor {
    pub fn new(device: Device) -> Self {
        Self {
            device,
            poll_secret: None,
            authenticated_session: None,
            next_epoch: 0,
            media_admission: None,
            publication_key_fingerprint: None,
            negotiated_device_info: None,
            pending_sas_publication_key_fingerprint: None,
            sas_publication_key_fingerprint: None,
        }
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Updates only the network-discovery axis. Connection/session and
    /// capture state deliberately remain owned by their independent actor
    /// transitions.
    pub fn set_discovery_state(&mut self, state: DiscoveryState) -> bool {
        if self.device.discovery == state {
            return false;
        }
        self.device.discovery = state;
        true
    }

    pub fn connection_state(&self) -> &ConnectionState {
        &self.device.connection
    }

    pub fn tls_fingerprint(&self) -> &str {
        &self.device.tls_fingerprint
    }

    /// The current connected epoch, if any (`None` unless
    /// `connection_state()` is `Connected`).
    pub fn current_epoch(&self) -> Option<u64> {
        match &self.device.connection {
            ConnectionState::Connected { epoch, .. } => Some(*epoch),
            _ => None,
        }
    }

    pub fn media_admission(&self) -> Option<&str> {
        self.media_admission.as_deref()
    }

    /// The last authenticated `/device` result applied to this connection.
    /// This is a read-only snapshot: consumers can project negotiated
    /// capabilities without issuing another device-wide request.
    #[must_use]
    pub fn negotiated_device_info(&self) -> Option<&DeviceInfoView> {
        self.negotiated_device_info.as_ref()
    }

    /// The signing-key identity most recently obtained from authenticated
    /// `GET /device` for the current connection.
    pub fn publication_key_fingerprint(&self) -> Option<&str> {
        self.publication_key_fingerprint.as_deref()
    }

    /// The publication-key identity the user's SAS confirmation actually
    /// covered when this session was established (`None` until a pairing
    /// attempt carrying a validated transcript has been allowed).
    ///
    /// This is the session's trust anchor: every later authenticated request
    /// is bound to it, and a device that starts presenting a *different*
    /// publication key mid-session fails closed rather than being trusted
    /// (see [`Self::refresh_capture_activity_with`]/[`Self::get_session_with`]).
    /// Legitimate key rotation is still possible -- it just requires a fresh
    /// SAS confirmation, i.e. re-pairing, which replaces this value.
    pub fn sas_publication_key_fingerprint(&self) -> Option<&str> {
        self.authenticated_session
            .as_ref()
            .and_then(AuthenticatedPiSession::publication_key_fingerprint)
            .or(self.sas_publication_key_fingerprint.as_deref())
    }

    /// The authenticated session bound to the current connection. The
    /// returned reference exposes identity metadata and epoch but never a
    /// bearer token (its only token access is internal to capability ports).
    #[must_use]
    pub fn authenticated_session(&self) -> Option<&AuthenticatedPiSession> {
        self.authenticated_session.as_ref()
    }

    /// The publication identity a `GET /sessions/{id}` must be verified
    /// against, if one is already known: the SAS-confirmed value first (the
    /// only one the device cannot change unilaterally), then whatever the
    /// last authenticated `GET /device` cached. `None` means the caller has
    /// to obtain one before it can verify anything — see
    /// [`Self::get_session_with`] and
    /// [`crate::device::fleet::DeviceHandle::get_session_with`], which is the
    /// off-lock form of exactly that decision.
    pub fn expected_publication_key_fingerprint(&self) -> Option<&str> {
        self.authenticated_session
            .as_ref()
            .and_then(AuthenticatedPiSession::publication_key_fingerprint)
            .or(self.sas_publication_key_fingerprint.as_deref())
            .or(self.publication_key_fingerprint.as_deref())
    }

    /// Fails closed when `observed` is not the identity the user confirmed
    /// out of band. No SAS-confirmed identity (legacy/transcript-less
    /// pairing) means there is nothing to contradict, so the check passes.
    fn ensure_sas_confirmed_publication_key(&self, observed: &str) -> Result<(), PiClientError> {
        if let Some(session) = &self.authenticated_session {
            return session
                .ensure_publication_key(observed)
                .map_err(PiClientError::from);
        }
        match &self.sas_publication_key_fingerprint {
            Some(confirmed) if confirmed != observed => Err(PiClientError {
                kind: PiClientErrorKind::Other,
                message: format!(
                    "device publication key identity changed since the SAS-confirmed pairing \
                     (confirmed {confirmed}, device now presents {observed}); re-pair to \
                     confirm the new key"
                ),
            }),
            _ => Ok(()),
        }
    }

    /// Applies a successful pairing-request response after the network call
    /// has completed. This is `pub(crate)` because it carries the poll
    /// secret; [`DeviceHandle`](super::fleet::DeviceHandle) uses it to keep
    /// pairing I/O outside its actor lock.
    pub(crate) fn apply_pairing_created(
        &mut self,
        created: PairingCreatedView,
    ) -> PairingAttemptInfo {
        self.poll_secret = Some(created.poll_secret.clone());
        self.authenticated_session = None;
        self.publication_key_fingerprint = None;
        self.negotiated_device_info = None;
        // A new SAS confirmation is about to replace whatever identity the
        // previous one anchored -- until it is actually confirmed, this
        // device has no confirmed publication key at all.
        self.sas_publication_key_fingerprint = None;
        self.pending_sas_publication_key_fingerprint =
            created.sas_publication_key_fingerprint.clone();
        self.device.connection = ConnectionState::Pairing {
            attempt_id: created.attempt_id.clone(),
            phase: created.phase,
        };
        PairingAttemptInfo {
            attempt_id: created.attempt_id,
            sas: created.sas,
            expires_at: created.expires_at,
        }
    }

    /// Starts a new pairing attempt through the pairing-only capability,
    /// transitioning to `Pairing{attempt_id, phase}`. `client_nonce` is
    /// caller-supplied so the same call is reproducible in tests.
    pub fn start_pairing_with(
        &mut self,
        client: &dyn PairingPort,
        client_name: &str,
        client_nonce: &str,
    ) -> Result<PairingAttemptInfo, PiClientError> {
        let created = client.create_pairing_request(client_name, client_nonce)?;
        Ok(self.apply_pairing_created(created))
    }

    /// Polls the current pairing attempt through the pairing-only capability
    /// and applies the result. `DeviceHandle::poll_pairing_with` is the
    /// lock-free-during-I/O form for shared actors.
    pub fn poll_pairing_with(&mut self, client: &dyn PairingPort) -> PollPairingOutcome {
        let Some((attempt_id, poll_secret)) = self.checkout_pairing_poll() else {
            return PollPairingOutcome::NotPairing;
        };
        let result = client.get_pairing_status(&attempt_id, &poll_secret);
        self.apply_pairing_status(&attempt_id, result)
    }

    /// The `(attempt_id, poll_secret)` pair one pairing poll needs, or
    /// `None` when this actor is not currently `Pairing`.
    ///
    /// `pub(crate)` on purpose: `poll_secret` is a credential (it authorizes
    /// reading the attempt's one-shot `connection_token`), so like the
    /// bearer token it must not become part of this crate's public surface.
    /// `fleet.rs` uses it to issue the poll with no lock held and hand the
    /// reply back to [`Self::apply_pairing_status`].
    pub(crate) fn checkout_pairing_poll(&self) -> Option<(String, String)> {
        match (&self.device.connection, &self.poll_secret) {
            (ConnectionState::Pairing { attempt_id, .. }, Some(secret)) => {
                Some((attempt_id.clone(), secret.clone()))
            }
            _ => None,
        }
    }

    /// Applies a (possibly late/stale) pairing-status response for
    /// `response_attempt_id`. Exposed separately from [`Self::poll_pairing_with`]
    /// so tests -- and, later, an async caller holding a response that
    /// arrived after further actor state changes -- can exercise the
    /// staleness guard directly without needing real concurrency.
    pub fn apply_pairing_status(
        &mut self,
        response_attempt_id: &str,
        result: Result<PairingStatusView, PiClientError>,
    ) -> PollPairingOutcome {
        match &self.device.connection {
            ConnectionState::Pairing { attempt_id, .. } if attempt_id == response_attempt_id => {}
            _ => return PollPairingOutcome::Stale,
        }

        match result {
            Ok(status) => match status.phase {
                PairingPhase::Pending => {
                    self.device.connection = ConnectionState::Pairing {
                        attempt_id: response_attempt_id.to_string(),
                        phase: PairingPhase::Pending,
                    };
                    PollPairingOutcome::StillPending
                }
                PairingPhase::Allowed => {
                    let Some(token) = status.connection_token else {
                        // Malformed: `allowed` but no token delivered. Do
                        // not get stuck `Pairing` forever -- fail safe to
                        // `Disconnected` so the caller can retry pairing
                        // from scratch.
                        self.poll_secret = None;
                        self.pending_sas_publication_key_fingerprint = None;
                        self.device.connection = ConnectionState::Disconnected;
                        return PollPairingOutcome::Error(PiClientErrorKind::Other);
                    };
                    // The identity the SAS covered must not have moved
                    // between attempt creation and resolution.
                    let created_identity = self.pending_sas_publication_key_fingerprint.take();
                    let confirmed_identity = match (
                        created_identity,
                        status.sas_publication_key_fingerprint.clone(),
                    ) {
                        (Some(created), Some(polled)) if created != polled => {
                            self.poll_secret = None;
                            self.negotiated_device_info = None;
                            self.device.connection = ConnectionState::Disconnected;
                            return PollPairingOutcome::Error(PiClientErrorKind::Other);
                        }
                        (created, polled) => polled.or(created),
                    };
                    self.next_epoch += 1;
                    let epoch = self.next_epoch;
                    let session = match AuthenticatedPiSession::new(
                        token,
                        self.device.tls_fingerprint.clone(),
                        confirmed_identity.clone(),
                        epoch,
                    ) {
                        Ok(session) => session,
                        Err(_error) => {
                            self.poll_secret = None;
                            self.authenticated_session = None;
                            self.negotiated_device_info = None;
                            self.sas_publication_key_fingerprint = None;
                            self.device.connection = ConnectionState::Disconnected;
                            return PollPairingOutcome::Error(PiClientErrorKind::Other);
                        }
                    };
                    self.authenticated_session = Some(session);
                    self.publication_key_fingerprint = None;
                    self.sas_publication_key_fingerprint = confirmed_identity;
                    self.poll_secret = None;
                    self.device.connection = ConnectionState::Connected {
                        connection_id: response_attempt_id.to_string(),
                        epoch,
                    };
                    PollPairingOutcome::Connected { epoch }
                }
                PairingPhase::Rejected | PairingPhase::Cancelled => {
                    self.poll_secret = None;
                    self.authenticated_session = None;
                    self.publication_key_fingerprint = None;
                    self.negotiated_device_info = None;
                    self.pending_sas_publication_key_fingerprint = None;
                    self.sas_publication_key_fingerprint = None;
                    self.device.connection = ConnectionState::Disconnected;
                    PollPairingOutcome::Rejected
                }
                PairingPhase::Expired => {
                    self.poll_secret = None;
                    self.authenticated_session = None;
                    self.publication_key_fingerprint = None;
                    self.negotiated_device_info = None;
                    self.pending_sas_publication_key_fingerprint = None;
                    self.sas_publication_key_fingerprint = None;
                    self.device.connection = ConnectionState::Expired {
                        reason: "pairing attempt expired".to_string(),
                    };
                    PollPairingOutcome::Expired
                }
            },
            Err(e) => PollPairingOutcome::Error(e.kind),
        }
    }

    /// Sends a heartbeat through the authenticated-device capability. A
    /// complete session is required, so a bearer token cannot be detached
    /// from its identity or epoch binding.
    pub fn heartbeat_with(
        &mut self,
        client: &dyn AuthenticatedDevicePort,
    ) -> HeartbeatApplyOutcome {
        let Some(session) = self.authenticated_session.as_ref() else {
            return HeartbeatApplyOutcome::NotConnected;
        };
        let epoch = session.epoch();
        let result = client.heartbeat(session);
        self.apply_heartbeat_result(epoch, result)
    }

    /// Applies a (possibly late/stale) heartbeat response that was issued
    /// while the actor was at `request_epoch`. If the actor has since
    /// moved to a different epoch (reconnected, or disconnected), the
    /// response is stale and ignored -- see module doc comment.
    pub fn apply_heartbeat_result(
        &mut self,
        request_epoch: u64,
        result: Result<HeartbeatOutcomeView, PiClientError>,
    ) -> HeartbeatApplyOutcome {
        match &self.device.connection {
            ConnectionState::Connected { epoch, .. } if *epoch == request_epoch => {}
            _ => return HeartbeatApplyOutcome::Stale,
        }

        match result {
            Ok(outcome) => {
                if let Some(capture_activity) = outcome.capture_activity {
                    self.device.capture_activity = capture_activity;
                }
                HeartbeatApplyOutcome::Renewed
            }
            Err(e) if e.kind == PiClientErrorKind::Unauthorized => {
                self.authenticated_session = None;
                self.publication_key_fingerprint = None;
                self.negotiated_device_info = None;
                self.sas_publication_key_fingerprint = None;
                self.device.connection = ConnectionState::Expired {
                    reason: format!("heartbeat failed: {}", e.message),
                };
                HeartbeatApplyOutcome::Expired
            }
            Err(e) => HeartbeatApplyOutcome::Error(e.kind),
        }
    }

    /// Clears the local session and best-effort revokes it through the
    /// authenticated-device capability. Local state is cleared before I/O so
    /// a failed revoke cannot leave the actor looking connected.
    pub fn disconnect_with(
        &mut self,
        client: &dyn AuthenticatedDevicePort,
    ) -> Result<(), PiClientError> {
        let session = self.authenticated_session.clone();
        self.clear_connection_state();
        match session {
            Some(session) => client.revoke_session(&session),
            None => Ok(()),
        }
    }

    /// Clears all connection credentials and visible session identity while
    /// retaining no bearer value for production callers.
    pub(crate) fn clear_connection_state(&mut self) {
        self.authenticated_session = None;
        self.poll_secret = None;
        self.publication_key_fingerprint = None;
        self.negotiated_device_info = None;
        self.pending_sas_publication_key_fingerprint = None;
        self.sas_publication_key_fingerprint = None;
        self.device.connection = ConnectionState::Disconnected;
    }

    /// Refreshes capture activity through the authenticated-device capability. The
    /// authenticated adapter validates the `/device` publication identity
    /// against the immutable session before this actor caches the result.
    pub fn refresh_capture_activity_with(
        &mut self,
        client: &dyn AuthenticatedDevicePort,
    ) -> Result<(), PiClientError> {
        let Some(session) = self.authenticated_session.as_ref() else {
            return Err(PiClientError {
                kind: PiClientErrorKind::Other,
                message: "refresh_capture_activity called without an authenticated session"
                    .to_string(),
            });
        };
        let info = client.get_device(session)?;
        self.apply_device_info(info)
    }

    /// Applies an already-fetched `GET /device` response. Split out of
    /// [`Self::refresh_capture_activity_with`] so a caller can issue the request
    /// with no lock held and apply the reply afterwards under whatever
    /// fencing it needs -- see
    /// [`crate::device::fleet::DeviceHandle::refresh_capture_activity_with`].
    ///
    /// Fails closed: a device that starts presenting a publication key the
    /// user never confirmed out of band is not this session's device as far
    /// as publication trust goes. Nothing is cached from such a response.
    pub fn apply_device_info(&mut self, info: DeviceInfoView) -> Result<(), PiClientError> {
        self.ensure_sas_confirmed_publication_key(&info.publication_key_fingerprint)?;
        if let Some(session) = self.authenticated_session.as_ref() {
            let bound = session
                .bind_publication_key(info.publication_key_fingerprint.clone())
                .map_err(PiClientError::from)?;
            self.authenticated_session = Some(bound);
        }
        self.device.capture_activity = info.capture_activity;
        self.media_admission = Some(info.media_admission.clone());
        self.publication_key_fingerprint = Some(info.publication_key_fingerprint.clone());
        self.negotiated_device_info = Some(info);
        Ok(())
    }

    /// Lists this device's completed recording sessions through the catalog
    /// capability. Requires an authenticated session.
    pub fn list_sessions_with(
        &self,
        client: &dyn SessionCatalogPort,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError> {
        let session = self
            .authenticated_session
            .as_ref()
            .ok_or_else(|| PiClientError {
                kind: PiClientErrorKind::Other,
                message: "list_sessions called without an authenticated session".to_string(),
            })?;
        client.list_sessions(session, cursor, limit)
    }

    /// Fetches one session's detail through the catalog capability. The publication key
    /// is obtained from the session object, so the catalog port cannot be
    /// tricked into verifying a detail against an arbitrary caller value.
    pub fn get_session_with(
        &self,
        client: &dyn SessionCatalogPort,
        session_id: &str,
    ) -> Result<SessionDetailView, PiClientError> {
        let session = self
            .authenticated_session
            .as_ref()
            .ok_or_else(|| PiClientError {
                kind: PiClientErrorKind::Other,
                message: "get_session called without an authenticated session".to_string(),
            })?;
        client.get_session(session, session_id)
    }

    /// Fetches v4 detail bound to the usable gateway verification selected
    /// from the current list generation.
    pub fn get_verified_session_with(
        &self,
        client: &dyn SessionCatalogPort,
        session_id: &str,
        verification: &GatewayVerificationView,
    ) -> Result<SessionDetailView, PiClientError> {
        let session = self
            .authenticated_session
            .as_ref()
            .ok_or_else(|| PiClientError {
                kind: PiClientErrorKind::Other,
                message: "get_verified_session called without an authenticated session".to_string(),
            })?;
        client.get_verified_session(session, session_id, verification)
    }

    /// Deletes one session through the catalog capability, forwarding the
    /// required revision and idempotency key unchanged.
    pub fn delete_session_with(
        &self,
        client: &dyn SessionCatalogPort,
        session_id: &str,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> Result<DeleteSessionReceiptView, PiClientError> {
        let session = self
            .authenticated_session
            .as_ref()
            .ok_or_else(|| PiClientError {
                kind: PiClientErrorKind::Other,
                message: "delete_session called without an authenticated session".to_string(),
            })?;
        client.delete_session(session, session_id, if_match_revision, idempotency_key)
    }

    /// Downloads a possibly-ranged slice through the authenticated download
    /// capability. Production coordinator jobs use its streaming method.
    pub fn download_file_with(
        &self,
        client: &dyn DownloadTransportPort,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileDownloadView, PiClientError> {
        let session = self
            .authenticated_session
            .as_ref()
            .ok_or_else(|| PiClientError {
                kind: PiClientErrorKind::Other,
                message: "download_file called without an authenticated session".to_string(),
            })?;
        client.get_file(session, session_id, file_id, if_match, range)
    }

    /// `HEAD`s one file through the authenticated download capability.
    pub fn head_file_with(
        &self,
        client: &dyn DownloadTransportPort,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
    ) -> Result<FileHeadView, PiClientError> {
        let session = self
            .authenticated_session
            .as_ref()
            .ok_or_else(|| PiClientError {
                kind: PiClientErrorKind::Other,
                message: "head_file called without an authenticated session".to_string(),
            })?;
        client.head_file(session, session_id, file_id, if_match)
    }
}

// The manual-address / mDNS dedup registry that used to live here
// (`DeviceActorRegistry`, a `HashMap<String, DeviceActor>` handing out
// `&mut DeviceActor` borrows) is gone as of commit 59. Every borrow it
// handed out forced the caller to hold the one process-wide registry mutex
// for the whole operation — including the network calls issued through it
// — so one unreachable device stalled every other device. Its replacement
// is [`crate::device::fleet::DeviceFleet`], which keys the same dedup on
// the full [`crate::device::DeviceFingerprint`] and whose lock only
// ever covers a map lookup/insert.

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::device::DiscoveryState;
    use crate::domain::DeviceId;

    fn test_device(fingerprint: &str) -> Device {
        Device {
            device_id: DeviceId(format!("dev-{fingerprint}")),
            name: "Test Pi".to_string(),
            tls_fingerprint: fingerprint.to_string(),
            discovery: DiscoveryState::Online,
            connection: ConnectionState::Disconnected,
            capture_activity: CaptureActivityState::Unknown,
        }
    }

    fn unauthorized(message: &str) -> PiClientError {
        PiClientError {
            kind: PiClientErrorKind::Unauthorized,
            message: message.to_string(),
        }
    }

    fn other_error(message: &str) -> PiClientError {
        PiClientError {
            kind: PiClientErrorKind::Other,
            message: message.to_string(),
        }
    }

    fn timeout_error(message: &str) -> PiClientError {
        PiClientError {
            kind: PiClientErrorKind::Timeout,
            message: message.to_string(),
        }
    }

    /// A scriptable fake implementing each split capability directly. Each
    /// call pops the next queued response, keeping tests explicit about the
    /// exact capabilities and number of calls they exercise.
    #[derive(Default)]
    struct FakeClient {
        pairing_created: Mutex<VecDeque<Result<PairingCreatedView, PiClientError>>>,
        pairing_status: Mutex<VecDeque<Result<PairingStatusView, PiClientError>>>,
        heartbeat: Mutex<VecDeque<Result<HeartbeatOutcomeView, PiClientError>>>,
        revoke: Mutex<VecDeque<Result<(), PiClientError>>>,
        device_info: Mutex<VecDeque<Result<DeviceInfoView, PiClientError>>>,
        list_sessions: Mutex<VecDeque<Result<SessionsPageView, PiClientError>>>,
        get_session: Mutex<VecDeque<Result<SessionDetailView, PiClientError>>>,
        get_session_expected_fingerprints: Mutex<Vec<String>>,
        delete_session: Mutex<VecDeque<Result<DeleteSessionReceiptView, PiClientError>>>,
        get_file: Mutex<VecDeque<Result<FileDownloadView, PiClientError>>>,
        head_file: Mutex<VecDeque<Result<FileHeadView, PiClientError>>>,
        create_calls: Mutex<u32>,
        list_sessions_calls: Mutex<u32>,
    }

    impl FakeClient {
        fn new() -> Self {
            Self::default()
        }

        fn push_pairing_created(&self, result: Result<PairingCreatedView, PiClientError>) {
            self.pairing_created.lock().unwrap().push_back(result);
        }

        fn push_pairing_status(&self, result: Result<PairingStatusView, PiClientError>) {
            self.pairing_status.lock().unwrap().push_back(result);
        }

        fn push_heartbeat(&self, result: Result<HeartbeatOutcomeView, PiClientError>) {
            self.heartbeat.lock().unwrap().push_back(result);
        }

        fn push_revoke(&self, result: Result<(), PiClientError>) {
            self.revoke.lock().unwrap().push_back(result);
        }

        fn push_list_sessions(&self, result: Result<SessionsPageView, PiClientError>) {
            self.list_sessions.lock().unwrap().push_back(result);
        }

        fn push_get_session(&self, result: Result<SessionDetailView, PiClientError>) {
            self.get_session.lock().unwrap().push_back(result);
        }

        fn push_delete_session(&self, result: Result<DeleteSessionReceiptView, PiClientError>) {
            self.delete_session.lock().unwrap().push_back(result);
        }

        fn push_get_file(&self, result: Result<FileDownloadView, PiClientError>) {
            self.get_file.lock().unwrap().push_back(result);
        }
    }

    impl PairingPort for FakeClient {
        fn create_pairing_request(
            &self,
            _client_name: &str,
            _client_nonce: &str,
        ) -> Result<PairingCreatedView, PiClientError> {
            *self.create_calls.lock().unwrap() += 1;
            self.pairing_created
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a create_pairing_request response")
        }

        fn get_pairing_status(
            &self,
            _attempt_id: &str,
            _poll_secret: &str,
        ) -> Result<PairingStatusView, PiClientError> {
            self.pairing_status
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a get_pairing_status response")
        }
    }

    impl AuthenticatedDevicePort for FakeClient {
        fn heartbeat(
            &self,
            _session: &AuthenticatedPiSession,
        ) -> Result<HeartbeatOutcomeView, PiClientError> {
            self.heartbeat
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a heartbeat response")
        }

        fn revoke_session(&self, _session: &AuthenticatedPiSession) -> Result<(), PiClientError> {
            self.revoke
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a revoke_session response")
        }

        fn get_device(
            &self,
            _session: &AuthenticatedPiSession,
        ) -> Result<DeviceInfoView, PiClientError> {
            self.device_info
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a get_device response")
        }
    }

    impl SessionCatalogPort for FakeClient {
        fn list_sessions(
            &self,
            _session: &AuthenticatedPiSession,
            _cursor: Option<&str>,
            _limit: Option<u32>,
        ) -> Result<SessionsPageView, PiClientError> {
            *self.list_sessions_calls.lock().unwrap() += 1;
            self.list_sessions
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a list_sessions response")
        }

        fn get_session(
            &self,
            session: &AuthenticatedPiSession,
            _session_id: &str,
        ) -> Result<SessionDetailView, PiClientError> {
            if let Some(fingerprint) = session.publication_key_fingerprint() {
                self.get_session_expected_fingerprints
                    .lock()
                    .unwrap()
                    .push(fingerprint.to_string());
            }
            self.get_session
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a get_session response")
        }

        fn delete_session(
            &self,
            _session: &AuthenticatedPiSession,
            _session_id: &str,
            _if_match_revision: &str,
            _idempotency_key: &str,
        ) -> Result<DeleteSessionReceiptView, PiClientError> {
            self.delete_session
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a delete_session response")
        }
    }

    impl DownloadTransportPort for FakeClient {
        fn get_file(
            &self,
            _session: &AuthenticatedPiSession,
            _session_id: &str,
            _file_id: &str,
            _if_match: Option<&str>,
            _range: Option<ByteRangeRequest>,
        ) -> Result<FileDownloadView, PiClientError> {
            self.get_file
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a get_file response")
        }

        fn head_file(
            &self,
            _session: &AuthenticatedPiSession,
            _session_id: &str,
            _file_id: &str,
            _if_match: Option<&str>,
        ) -> Result<FileHeadView, PiClientError> {
            self.head_file
                .lock()
                .unwrap()
                .pop_front()
                .expect("test forgot to queue a head_file response")
        }
    }

    fn install_connected_session(
        actor: &mut DeviceActor,
        token: &str,
        connection_id: &str,
        epoch: u64,
        publication_key_fingerprint: Option<String>,
    ) {
        actor.next_epoch = epoch;
        actor.authenticated_session = Some(
            AuthenticatedPiSession::new(
                token,
                actor.device.tls_fingerprint.clone(),
                publication_key_fingerprint.clone(),
                epoch,
            )
            .expect("test session identity is valid"),
        );
        actor.publication_key_fingerprint = publication_key_fingerprint;
        actor.device.connection = ConnectionState::Connected {
            connection_id: connection_id.to_string(),
            epoch,
        };
    }

    // -----------------------------------------------------------------
    // Full pairing lifecycle: pending -> allowed -> connected
    // -----------------------------------------------------------------

    #[test]
    fn full_pairing_lifecycle_pending_then_allowed_connects() {
        let client = FakeClient::new();
        client.push_pairing_created(Ok(PairingCreatedView {
            attempt_id: "attempt-1".to_string(),
            phase: PairingPhase::Pending,
            poll_secret: "poll-secret-1".to_string(),
            sas: "123456".to_string(),
            expires_at: "2026-08-01T05:00:00Z".to_string(),
            sas_publication_key_fingerprint: None,
        }));
        client.push_pairing_status(Ok(PairingStatusView {
            attempt_id: "attempt-1".to_string(),
            phase: PairingPhase::Pending,
            connection_token: None,
            sas: "123456".to_string(),
            expires_at: "2026-08-01T05:00:00Z".to_string(),
            sas_publication_key_fingerprint: None,
        }));
        client.push_pairing_status(Ok(PairingStatusView {
            attempt_id: "attempt-1".to_string(),
            phase: PairingPhase::Allowed,
            connection_token: Some("secret-connection-token".to_string()),
            sas: "123456".to_string(),
            expires_at: "2026-08-01T05:00:00Z".to_string(),
            sas_publication_key_fingerprint: None,
        }));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        assert_eq!(actor.connection_state(), &ConnectionState::Disconnected);

        let info = actor
            .start_pairing_with(&client, "pc-test", "nonce-1")
            .expect("start_pairing succeeds");
        assert_eq!(info.attempt_id, "attempt-1");
        assert_eq!(
            actor.connection_state(),
            &ConnectionState::Pairing {
                attempt_id: "attempt-1".to_string(),
                phase: PairingPhase::Pending,
            }
        );

        let outcome = actor.poll_pairing_with(&client);
        assert_eq!(outcome, PollPairingOutcome::StillPending);
        assert!(matches!(
            actor.connection_state(),
            ConnectionState::Pairing { .. }
        ));

        let outcome = actor.poll_pairing_with(&client);
        assert_eq!(outcome, PollPairingOutcome::Connected { epoch: 1 });
        assert_eq!(
            actor.connection_state(),
            &ConnectionState::Connected {
                connection_id: "attempt-1".to_string(),
                epoch: 1,
            }
        );
        assert_eq!(actor.current_epoch(), Some(1));

        // Token must never surface in a Debug dump of the actor.
        let debug_repr = format!("{actor:?}");
        assert!(!debug_repr.contains("secret-connection-token"));
        assert!(debug_repr.contains("redacted"));
    }

    // -----------------------------------------------------------------
    // SAS-confirmed publication key identity is bound to the session
    // -----------------------------------------------------------------

    fn sas_pairing_created(attempt: &str, fingerprint: &str) -> PairingCreatedView {
        PairingCreatedView {
            attempt_id: attempt.to_string(),
            phase: PairingPhase::Pending,
            poll_secret: "poll-secret".to_string(),
            sas: "123456".to_string(),
            expires_at: "2026-08-01T05:00:00Z".to_string(),
            sas_publication_key_fingerprint: Some(fingerprint.to_string()),
        }
    }

    fn sas_pairing_allowed(attempt: &str, fingerprint: &str) -> PairingStatusView {
        PairingStatusView {
            attempt_id: attempt.to_string(),
            phase: PairingPhase::Allowed,
            connection_token: Some(format!("token-for-{attempt}")),
            sas: "123456".to_string(),
            expires_at: "2026-08-01T05:00:00Z".to_string(),
            sas_publication_key_fingerprint: Some(fingerprint.to_string()),
        }
    }

    fn device_info(fingerprint: &str) -> DeviceInfoView {
        DeviceInfoView {
            capture_activity: CaptureActivityState::Recording,
            media_admission: "allowed".to_string(),
            publication_key_fingerprint: fingerprint.to_string(),
            profile: DeviceApiProfileView::LegacyPinnedHttpsV1,
            capabilities: DeviceCapabilitiesView::default(),
            capture_status: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        }
    }

    /// Same key after pairing: the identity the user confirmed is recorded
    /// and is what later authenticated requests are verified against --
    /// without any extra `GET /device` round trip.
    #[test]
    fn sas_confirmed_publication_key_identity_is_bound_to_the_session() {
        let confirmed = format!("sha256:{}", "a".repeat(64));
        let client = FakeClient::new();
        client.push_pairing_created(Ok(sas_pairing_created("attempt-1", &confirmed)));
        client.push_pairing_status(Ok(sas_pairing_allowed("attempt-1", &confirmed)));
        client
            .device_info
            .lock()
            .unwrap()
            .push_back(Ok(device_info(&confirmed)));
        client.push_get_session(Err(other_error("detail sentinel")));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        actor
            .start_pairing_with(&client, "pc-test", "nonce-1")
            .expect("start_pairing succeeds");
        assert_eq!(actor.sas_publication_key_fingerprint(), None);
        assert_eq!(
            actor.poll_pairing_with(&client),
            PollPairingOutcome::Connected { epoch: 1 }
        );

        assert_eq!(
            actor.sas_publication_key_fingerprint(),
            Some(confirmed.as_str())
        );
        actor
            .refresh_capture_activity_with(&client)
            .expect("the unchanged, SAS-confirmed key is accepted");
        let _ = actor.get_session_with(&client, "sess-1");
        assert_eq!(
            *client.get_session_expected_fingerprints.lock().unwrap(),
            vec![confirmed]
        );
    }

    /// Changed key without a fresh SAS confirmation: hard failure. The
    /// device presenting a different publication key cannot make later
    /// publications verify against it, and nothing from that response is
    /// cached.
    #[test]
    fn publication_key_change_without_re_pairing_fails_closed() {
        let confirmed = format!("sha256:{}", "a".repeat(64));
        let rotated = format!("sha256:{}", "b".repeat(64));
        let client = FakeClient::new();
        client.push_pairing_created(Ok(sas_pairing_created("attempt-1", &confirmed)));
        client.push_pairing_status(Ok(sas_pairing_allowed("attempt-1", &confirmed)));
        client
            .device_info
            .lock()
            .unwrap()
            .push_back(Ok(device_info(&rotated)));
        client.push_get_session(Err(other_error("detail sentinel")));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        actor
            .start_pairing_with(&client, "pc-test", "nonce-1")
            .expect("start_pairing succeeds");
        assert_eq!(
            actor.poll_pairing_with(&client),
            PollPairingOutcome::Connected { epoch: 1 }
        );

        let error = actor
            .refresh_capture_activity_with(&client)
            .expect_err("a rotated publication key must fail closed");
        assert!(
            error.message.contains("changed since the SAS-confirmed"),
            "{}",
            error.message
        );
        assert_eq!(actor.publication_key_fingerprint(), None);
        assert_eq!(
            actor.device().capture_activity,
            CaptureActivityState::Unknown
        );

        // The authenticated detail path still binds to the confirmed
        // identity, so a publication signed by the rotated key can never
        // verify.
        let _ = actor.get_session_with(&client, "sess-1");
        assert_eq!(
            *client.get_session_expected_fingerprints.lock().unwrap(),
            vec![confirmed]
        );
    }

    /// Re-pairing (a fresh SAS confirmation) is the supported way to accept
    /// a rotated key.
    #[test]
    fn re_pairing_replaces_the_sas_confirmed_publication_key_identity() {
        let confirmed = format!("sha256:{}", "a".repeat(64));
        let rotated = format!("sha256:{}", "b".repeat(64));
        let client = FakeClient::new();
        client.push_pairing_created(Ok(sas_pairing_created("attempt-1", &confirmed)));
        client.push_pairing_status(Ok(sas_pairing_allowed("attempt-1", &confirmed)));
        client.push_pairing_created(Ok(sas_pairing_created("attempt-2", &rotated)));
        client.push_pairing_status(Ok(sas_pairing_allowed("attempt-2", &rotated)));
        client
            .device_info
            .lock()
            .unwrap()
            .push_back(Ok(device_info(&rotated)));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        actor
            .start_pairing_with(&client, "pc-test", "nonce-1")
            .unwrap();
        assert_eq!(
            actor.poll_pairing_with(&client),
            PollPairingOutcome::Connected { epoch: 1 }
        );
        actor
            .start_pairing_with(&client, "pc-test", "nonce-2")
            .unwrap();
        assert_eq!(actor.sas_publication_key_fingerprint(), None);
        assert_eq!(
            actor.poll_pairing_with(&client),
            PollPairingOutcome::Connected { epoch: 2 }
        );

        assert_eq!(
            actor.sas_publication_key_fingerprint(),
            Some(rotated.as_str())
        );
        actor
            .refresh_capture_activity_with(&client)
            .expect("the freshly confirmed key is accepted");
        assert_eq!(actor.publication_key_fingerprint(), Some(rotated.as_str()));
    }

    /// The transcript identity must not move between attempt creation and
    /// resolution: an `allowed` poll advertising a different publication key
    /// than the SAS the user was shown never becomes a session.
    #[test]
    fn pairing_whose_transcript_identity_moved_mid_attempt_never_connects() {
        let shown = format!("sha256:{}", "a".repeat(64));
        let swapped = format!("sha256:{}", "b".repeat(64));
        let client = FakeClient::new();
        client.push_pairing_created(Ok(sas_pairing_created("attempt-1", &shown)));
        client.push_pairing_status(Ok(sas_pairing_allowed("attempt-1", &swapped)));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        actor
            .start_pairing_with(&client, "pc-test", "nonce-1")
            .unwrap();

        assert_eq!(
            actor.poll_pairing_with(&client),
            PollPairingOutcome::Error(PiClientErrorKind::Other)
        );
        assert_eq!(actor.connection_state(), &ConnectionState::Disconnected);
        assert_eq!(actor.sas_publication_key_fingerprint(), None);
        assert!(actor.authenticated_session.is_none());
    }

    #[test]
    fn disconnect_clears_the_sas_confirmed_publication_key_identity() {
        let confirmed = format!("sha256:{}", "a".repeat(64));
        let client = FakeClient::new();
        client.push_pairing_created(Ok(sas_pairing_created("attempt-1", &confirmed)));
        client.push_pairing_status(Ok(sas_pairing_allowed("attempt-1", &confirmed)));
        client.push_revoke(Ok(()));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        actor
            .start_pairing_with(&client, "pc-test", "nonce-1")
            .unwrap();
        actor.poll_pairing_with(&client);
        actor.disconnect_with(&client).expect("disconnect succeeds");

        assert_eq!(actor.sas_publication_key_fingerprint(), None);
    }

    // -----------------------------------------------------------------
    // Stale pairing response (superseded attempt_id) ignored
    // -----------------------------------------------------------------

    #[test]
    fn stale_pairing_response_for_superseded_attempt_is_ignored() {
        let client = FakeClient::new();
        let mut actor = DeviceActor::new(test_device("fp-1"));
        actor.device.connection = ConnectionState::Pairing {
            attempt_id: "attempt-new".to_string(),
            phase: PairingPhase::Pending,
        };

        // A response for the OLD attempt_id arrives late.
        let outcome = actor.apply_pairing_status(
            "attempt-old",
            Ok(PairingStatusView {
                attempt_id: "attempt-old".to_string(),
                phase: PairingPhase::Allowed,
                connection_token: Some("should-never-be-applied".to_string()),
                sas: "000000".to_string(),
                expires_at: "2026-08-01T05:00:00Z".to_string(),
                sas_publication_key_fingerprint: None,
            }),
        );

        assert_eq!(outcome, PollPairingOutcome::Stale);
        assert_eq!(
            actor.connection_state(),
            &ConnectionState::Pairing {
                attempt_id: "attempt-new".to_string(),
                phase: PairingPhase::Pending,
            }
        );
        let _ = client; // unused in this test besides constructing FakeClient::new()
    }

    // -----------------------------------------------------------------
    // Late/stale heartbeat response tagged with an old epoch is ignored
    // -----------------------------------------------------------------

    #[test]
    fn late_heartbeat_response_with_old_epoch_does_not_corrupt_current_connection() {
        let mut actor = DeviceActor::new(test_device("fp-1"));
        install_connected_session(&mut actor, "current-token", "conn-current", 5, None);

        // A heartbeat response tagged with an OLD epoch (e.g. requested
        // before a reconnect bumped the epoch to 5) arrives late. Even
        // though it reports a 401 (which would normally expire the
        // session), it must be ignored because it no longer matches the
        // current epoch.
        let outcome = actor.apply_heartbeat_result(3, Err(unauthorized("late 401")));

        assert_eq!(outcome, HeartbeatApplyOutcome::Stale);
        assert_eq!(
            actor.connection_state(),
            &ConnectionState::Connected {
                connection_id: "conn-current".to_string(),
                epoch: 5,
            }
        );
    }

    // -----------------------------------------------------------------
    // Heartbeat 401 -> Expired
    // -----------------------------------------------------------------

    #[test]
    fn heartbeat_401_transitions_to_expired() {
        let client = FakeClient::new();
        client.push_heartbeat(Err(unauthorized("token no longer valid")));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        install_connected_session(
            &mut actor,
            "token-abc",
            "conn-1",
            1,
            Some(format!("sha256:{}", "a".repeat(64))),
        );

        let outcome = actor.heartbeat_with(&client);
        assert_eq!(outcome, HeartbeatApplyOutcome::Expired);
        match actor.connection_state() {
            ConnectionState::Expired { reason } => {
                assert!(reason.contains("heartbeat failed"));
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        assert!(actor.authenticated_session.is_none());
        assert!(actor.publication_key_fingerprint().is_none());
    }

    #[test]
    fn heartbeat_timeout_keeps_token_for_next_retry() {
        let client = FakeClient::new();
        client.push_heartbeat(Err(timeout_error("temporary network timeout")));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        install_connected_session(&mut actor, "token-abc", "conn-1", 1, None);

        let outcome = actor.heartbeat_with(&client);

        assert_eq!(
            outcome,
            HeartbeatApplyOutcome::Error(PiClientErrorKind::Timeout)
        );
        assert_eq!(actor.current_epoch(), Some(1));
        assert!(actor.authenticated_session.is_some());
        assert_eq!(
            actor.device().capture_activity,
            CaptureActivityState::Unknown,
            "a timeout carries no new capture evidence"
        );
    }

    #[test]
    fn heartbeat_success_renews_and_keeps_same_epoch() {
        let client = FakeClient::new();
        client.push_heartbeat(Ok(HeartbeatOutcomeView {
            idle_timeout_ms: 30_000,
            absolute_expires_at: "2026-08-01T06:00:00Z".to_string(),
            capture_activity: Some(CaptureActivityState::Recording),
        }));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        install_connected_session(
            &mut actor,
            "token-abc",
            "conn-1",
            1,
            Some(format!("sha256:{}", "a".repeat(64))),
        );

        let outcome = actor.heartbeat_with(&client);
        assert_eq!(outcome, HeartbeatApplyOutcome::Renewed);
        assert_eq!(actor.current_epoch(), Some(1));
        assert_eq!(
            actor.device().capture_activity,
            CaptureActivityState::Recording
        );
        assert_eq!(
            actor.publication_key_fingerprint(),
            Some(format!("sha256:{}", "a".repeat(64)).as_str())
        );
    }

    // -----------------------------------------------------------------
    // Two devices' actors are fully independent
    // -----------------------------------------------------------------

    #[test]
    fn two_devices_actors_are_fully_independent() {
        let broken_client = FakeClient::new();
        broken_client.push_heartbeat(Err(other_error("device offline / broken")));
        broken_client.push_heartbeat(Err(other_error("still broken")));

        let healthy_client = FakeClient::new();
        healthy_client.push_heartbeat(Ok(HeartbeatOutcomeView {
            idle_timeout_ms: 30_000,
            absolute_expires_at: "2026-08-01T06:00:00Z".to_string(),
            capture_activity: None,
        }));

        let mut broken_actor = DeviceActor::new(test_device("fp-broken"));
        install_connected_session(&mut broken_actor, "token-broken", "conn-broken", 1, None);

        let mut healthy_actor = DeviceActor::new(test_device("fp-healthy"));
        install_connected_session(&mut healthy_actor, "token-healthy", "conn-healthy", 1, None);

        // Hammer the broken device's actor with failures.
        let outcome1 = broken_actor.heartbeat_with(&broken_client);
        let outcome2 = broken_actor.heartbeat_with(&broken_client);
        assert_eq!(
            outcome1,
            HeartbeatApplyOutcome::Error(PiClientErrorKind::Other)
        );
        assert_eq!(
            outcome2,
            HeartbeatApplyOutcome::Error(PiClientErrorKind::Other)
        );
        // Errors that are not Unauthorized/Timeout leave state untouched,
        // still Connected -- confirms the broken actor's own state
        // survives repeated failure too, but the real point of this test
        // is the *other* actor below.
        assert!(matches!(
            broken_actor.connection_state(),
            ConnectionState::Connected { .. }
        ));

        // The healthy device's actor is completely untouched by any of
        // the above -- separate struct, separate fake client, no shared
        // state.
        let healthy_outcome = healthy_actor.heartbeat_with(&healthy_client);
        assert_eq!(healthy_outcome, HeartbeatApplyOutcome::Renewed);
        assert_eq!(
            healthy_actor.connection_state(),
            &ConnectionState::Connected {
                connection_id: "conn-healthy".to_string(),
                epoch: 1,
            }
        );
    }

    // -----------------------------------------------------------------
    // disconnect()
    // -----------------------------------------------------------------

    #[test]
    fn disconnect_revokes_session_and_transitions_to_disconnected() {
        let client = FakeClient::new();
        client.push_revoke(Ok(()));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        install_connected_session(
            &mut actor,
            "token-abc",
            "conn-1",
            1,
            Some(format!("sha256:{}", "a".repeat(64))),
        );

        let result = actor.disconnect_with(&client);
        assert!(result.is_ok());
        assert_eq!(actor.connection_state(), &ConnectionState::Disconnected);
        assert!(actor.authenticated_session.is_none());
        assert!(actor.publication_key_fingerprint().is_none());
    }

    // The manual-address / mDNS same-fingerprint dedup tests that used to
    // live here moved to `fleet.rs` along with the registry itself:
    // `get_or_create_returns_the_same_handle_for_both_discovery_paths` and
    // `two_devices_with_colliding_short_ids_stay_distinct`.

    // -----------------------------------------------------------------
    // refresh_capture_activity()
    // -----------------------------------------------------------------

    #[test]
    fn refresh_capture_activity_updates_view_when_connected() {
        let client = FakeClient::new();
        let capabilities = DeviceCapabilitiesView {
            artifact_download: NegotiatedCapabilityView {
                supported: true,
                source: CapabilitySourceView::ProfileContract,
            },
            ..DeviceCapabilitiesView::default()
        };
        client
            .device_info
            .lock()
            .unwrap()
            .push_back(Ok(DeviceInfoView {
                capture_activity: CaptureActivityState::Recording,
                media_admission: "allowed".to_string(),
                publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
                profile: DeviceApiProfileView::LegacyPinnedHttpsV1,
                capabilities,
                capture_status: None,
                publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
            }));

        let mut actor = DeviceActor::new(test_device("fp-1"));
        install_connected_session(&mut actor, "token-abc", "conn-1", 1, None);

        actor
            .refresh_capture_activity_with(&client)
            .expect("refresh succeeds while connected");
        assert_eq!(
            actor.device().capture_activity,
            CaptureActivityState::Recording
        );
        assert_eq!(actor.media_admission(), Some("allowed"));
        assert_eq!(
            actor.publication_key_fingerprint(),
            Some(format!("sha256:{}", "a".repeat(64)).as_str())
        );
        assert_eq!(
            actor
                .negotiated_device_info()
                .expect("authenticated snapshot is cached")
                .capabilities
                .artifact_download,
            NegotiatedCapabilityView {
                supported: true,
                source: CapabilitySourceView::ProfileContract,
            }
        );
    }

    #[test]
    fn refresh_capture_activity_errors_when_not_connected() {
        let client = FakeClient::new();
        let mut actor = DeviceActor::new(test_device("fp-1"));
        let result = actor.refresh_capture_activity_with(&client);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // PC-08b: split catalog and download capabilities
    // -----------------------------------------------------------------

    fn connected_actor(fingerprint: &str, token: &str) -> DeviceActor {
        let mut actor = DeviceActor::new(test_device(fingerprint));
        install_connected_session(
            &mut actor,
            token,
            "conn-1",
            1,
            Some(format!("sha256:{}", "a".repeat(64))),
        );
        actor
    }

    #[test]
    fn list_sessions_uses_the_held_token_and_returns_the_page() {
        let client = FakeClient::new();
        client.push_list_sessions(Ok(SessionsPageView {
            catalog_revision: Some("rev-1".to_string()),
            sessions: vec![SessionSummaryView {
                session_id: "sess-1".to_string(),
                revision: "rev-a".to_string(),
                captured_at: "2026-08-01T00:00:00Z".to_string(),
                published_at: "2026-08-01T00:01:00Z".to_string(),
                duration_seconds: 12.5,
                total_bytes: 1000,
                video_bytes: 900,
                file_count: 2,
                gateway_verification: None,
            }],
            next_cursor: None,
            catalog_authority: CatalogRevisionAuthorityView::LegacyDevice,
            pagination_supported: true,
            pagination_unavailable_reason: None,
            diagnostics: Vec::new(),
        }));

        let actor = connected_actor("fp-1", "secret-token");
        let page = actor
            .list_sessions_with(&client, None, None)
            .expect("list_sessions succeeds");
        assert_eq!(page.sessions.len(), 1);
        assert_eq!(page.sessions[0].session_id, "sess-1");
        assert_eq!(*client.list_sessions_calls.lock().unwrap(), 1);
    }

    #[test]
    fn list_sessions_errors_when_not_connected_and_never_calls_the_client() {
        let client = FakeClient::new();
        let actor = DeviceActor::new(test_device("fp-1"));
        let result = actor.list_sessions_with(&client, None, None);
        assert!(result.is_err());
        assert_eq!(*client.list_sessions_calls.lock().unwrap(), 0);
    }

    #[test]
    fn get_session_uses_identity_bound_by_authenticated_device_capability() {
        let client = FakeClient::new();
        let expected_fingerprint = format!("sha256:{}", "b".repeat(64));
        client
            .device_info
            .lock()
            .unwrap()
            .push_back(Ok(DeviceInfoView {
                capture_activity: CaptureActivityState::Idle,
                media_admission: "open".to_string(),
                publication_key_fingerprint: expected_fingerprint.clone(),
                profile: DeviceApiProfileView::LegacyPinnedHttpsV1,
                capabilities: DeviceCapabilitiesView::default(),
                capture_status: None,
                publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
            }));
        client.push_get_session(Err(other_error("detail sentinel")));
        let mut actor = connected_actor("fp-1", "secret-token");
        actor.publication_key_fingerprint = None;
        actor.authenticated_session = Some(
            AuthenticatedPiSession::new("secret-token", "fp-1", None, 1)
                .expect("unbound test session is valid"),
        );
        actor
            .refresh_capture_activity_with(&client)
            .expect("device identity binds the session");

        let error = actor
            .get_session_with(&client, "sess-1")
            .expect_err("fake detail response remains observable");

        assert_eq!(error.message, "detail sentinel");
        assert_eq!(
            *client.get_session_expected_fingerprints.lock().unwrap(),
            vec![expected_fingerprint]
        );
    }

    #[test]
    fn get_session_uses_the_held_token() {
        let client = FakeClient::new();
        client.push_get_session(Ok(SessionDetailView {
            session_id: "sess-1".to_string(),
            revision: "rev-a".to_string(),
            captured_at: "2026-08-01T00:00:00Z".to_string(),
            published_at: "2026-08-01T00:01:00Z".to_string(),
            duration_seconds: 12.5,
            total_bytes: 1000,
            video_bytes: 900,
            file_count: 2,
            files: Vec::new(),
            publication_payload: Vec::new(),
            publication_signature: Vec::new(),
            publication_public_key: Vec::new(),
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        }));
        let actor = connected_actor("fp-1", "secret-token");
        let summary = actor
            .get_session_with(&client, "sess-1")
            .expect("get_session succeeds");
        assert_eq!(summary.session_id, "sess-1");
    }

    /// PC-03b: `GET /sessions/{id}`'s real per-file inventory (`files[]`,
    /// closing the gap `PC-08b`'s `SessionSummaryView` doc comment used to
    /// describe as blocked) round-trips through `DeviceActor::get_session_with`
    /// unchanged, all the way down to each file's opaque `id`.
    #[test]
    fn get_session_carries_the_real_per_file_inventory_through() {
        let client = FakeClient::new();
        client.push_get_session(Ok(SessionDetailView {
            session_id: "sess-1".to_string(),
            revision: "rev-a".to_string(),
            captured_at: "2026-08-01T00:00:00Z".to_string(),
            published_at: "2026-08-01T00:01:00Z".to_string(),
            duration_seconds: 12.5,
            total_bytes: 1000,
            video_bytes: 900,
            file_count: 3,
            files: vec![
                SessionFileEntryView {
                    id: "f-0001".to_string(),
                    display_path: "video/left_00000.mp4".to_string(),
                    role: "video_left".to_string(),
                    size_bytes: 483920112,
                    sha256: "b".repeat(64),
                    media_type: "video/mp4".to_string(),
                },
                SessionFileEntryView {
                    id: "f-0002".to_string(),
                    display_path: "video/right_00000.mp4".to_string(),
                    role: "video_right".to_string(),
                    size_bytes: 483920000,
                    sha256: "c".repeat(64),
                    media_type: "video/mp4".to_string(),
                },
                SessionFileEntryView {
                    id: "f-0003".to_string(),
                    display_path: "imu/imu_00000.csv".to_string(),
                    role: "imu".to_string(),
                    size_bytes: 12345,
                    sha256: "d".repeat(64),
                    media_type: "text/csv".to_string(),
                },
            ],
            publication_payload: Vec::new(),
            publication_signature: Vec::new(),
            publication_public_key: Vec::new(),
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        }));
        let actor = connected_actor("fp-1", "secret-token");
        let detail = actor
            .get_session_with(&client, "sess-1")
            .expect("get_session succeeds");
        assert_eq!(detail.files.len(), 3);
        assert_eq!(detail.file_count, 3);
        assert_eq!(detail.files[0].id, "f-0001");
        assert_eq!(detail.files[0].display_path, "video/left_00000.mp4");
        assert_eq!(detail.files[0].role, "video_left");
        assert_eq!(detail.files[0].size_bytes, 483920112);
        assert_eq!(detail.files[0].sha256, "b".repeat(64));
        assert_eq!(detail.files[0].media_type, "video/mp4");
        assert_eq!(detail.files[2].role, "imu");
    }

    #[test]
    fn delete_session_uses_the_held_token() {
        let client = FakeClient::new();
        client.push_delete_session(Ok(DeleteSessionReceiptView {
            session_id: "sess-1".to_string(),
            revision: "rev-a".to_string(),
            deleted_at: "2026-08-01T00:02:00Z".to_string(),
        }));
        let actor = connected_actor("fp-1", "secret-token");
        let receipt = actor
            .delete_session_with(&client, "sess-1", "rev-a", "idem-1")
            .expect("delete_session succeeds");
        assert_eq!(receipt.session_id, "sess-1");
    }

    #[test]
    fn download_file_uses_the_held_token_and_never_returns_it() {
        let client = FakeClient::new();
        client.push_get_file(Ok(FileDownloadView {
            status: 200,
            etag: "etag-1".to_string(),
            media_type: "video/mp4".to_string(),
            content_length: 3,
            content_range: None,
            body: vec![1, 2, 3],
        }));
        let actor = connected_actor("fp-1", "very-secret-token");
        let file = actor
            .download_file_with(&client, "sess-1", "file-1", None, None)
            .expect("download_file succeeds");
        assert_eq!(file.body, vec![1, 2, 3]);

        // Nothing about the returned view -- or a Debug dump of the actor
        // -- ever contains the raw token.
        let debug_repr = format!("{actor:?}");
        assert!(!debug_repr.contains("very-secret-token"));
    }

    #[test]
    fn download_file_errors_when_not_connected() {
        let client = FakeClient::new();
        let actor = DeviceActor::new(test_device("fp-1"));
        let result = actor.download_file_with(&client, "sess-1", "file-1", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn authenticated_session_binds_identity_epoch_and_redacts_token() {
        let fingerprint = format!("sha256:{}", "a".repeat(64));
        let session = AuthenticatedPiSession::new(
            "connection-token-secret",
            "tls-pin-test",
            Some(fingerprint.clone()),
            7,
        )
        .expect("valid session");
        assert_eq!(session.epoch(), 7);
        assert_eq!(session.tls_pin(), "tls-pin-test");
        assert_eq!(
            session.publication_key_fingerprint(),
            Some(fingerprint.as_str())
        );
        assert!(session.ensure_publication_key(&fingerprint).is_ok());
        assert!(matches!(
            session.ensure_publication_key(&format!("sha256:{}", "b".repeat(64))),
            Err(AuthenticatedPiSessionError::PublicationKeyChanged)
        ));
        let debug = format!("{session:?}");
        assert!(!debug.contains("connection-token-secret"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn authenticated_session_rejects_empty_token_and_invalid_key() {
        assert!(matches!(
            AuthenticatedPiSession::new("", "tls", None, 1),
            Err(AuthenticatedPiSessionError::EmptyToken)
        ));
        assert!(matches!(
            AuthenticatedPiSession::new("token", "tls", Some("sha256:not-hex".to_string()), 1),
            Err(AuthenticatedPiSessionError::InvalidPublicationKey(_))
        ));
        assert!(matches!(
            AuthenticatedPiSession::new("token", "tls", None, 0),
            Err(AuthenticatedPiSessionError::InvalidEpoch)
        ));
    }
}
