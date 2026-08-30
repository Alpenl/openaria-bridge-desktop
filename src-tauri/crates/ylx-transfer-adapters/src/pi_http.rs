//! Client for the Conductor Device Session API.
//!
//! Current RDK X5 lab/internal devices speak HTTP `/api/v4` on port 8080:
//! `GET /device`, `GET /sessions`, `GET /sessions/{id}`, and artifact
//! `GET`/`HEAD` routes. The retained legacy profile speaks pinned HTTPS
//! `/api/v1`. Adapter and contract tests cover both profiles' parsing, error
//! mapping, identity pin handling, and cross-language request/response
//! boundary.
//!
//! # TLS: fingerprint pinning, not full CA validation (deliberate, v1 scope)
//!
//! Each device uses a self-signed TLS certificate. There is no CA to
//! chain-validate against by design: the trust anchor is
//! meant to be the human-verified SAS (Short Authentication String) at
//! pairing time, not a certificate authority. This client's [`PiTlsPin`]
//! therefore pins the exact SHA-256 hash of the certificate's DER-encoded
//! SubjectPublicKeyInfo (SPKI) -- the *same* value and the *same hash
//! input* `tls_identity.compute_fingerprint` computes on the Pi side (only
//! the SPKI substructure is hashed, never the whole certificate DER, so the
//! fingerprint survives a cert reissue that keeps the same key). A caller
//! obtains this fingerprint out of band (the pairing/SAS flow -- not
//! implemented by this task, PC-02/PC-07's job -- or a value passed in
//! directly, e.g. hard-coded for a dev/test daemon).
//!
//! Concretely: `PinnedFingerprintVerifier` implements
//! `rustls::client::danger::ServerCertVerifier` and accepts a server
//! certificate *iff* its SPKI's SHA-256 matches the configured pin --
//! skipping both hostname/SAN checks and CA chain-of-trust validation
//! entirely (there is no CA to validate against). It still cryptographically
//! verifies the TLS handshake signature (`verify_tls12_signature`/
//! `verify_tls13_signature`, delegated to `rustls::crypto`'s own WebPKI
//! signature-verification routines) -- this is *not* the same as
//! `disable_verification(true)`, which would accept **any** certificate
//! with **no** cryptographic check at all. `ureq`'s own `TlsConfig` only
//! exposes `disable_verification`/a fixed root-cert list, neither of which
//! expresses "pin by fingerprint, skip hostname" -- so this module plugs a
//! bespoke `Connector`/rustls `ClientConfig` directly into `ureq` via
//! `Agent::with_parts` (a documented, if "not yet semver-stable",
//! `ureq::unversioned` extension point) rather than working around that gap
//! with a weaker setting. The direct `rustls`/`rustls-webpki` dependencies
//! provide this verifier surface.
//!
//! Because hostname/SAN checks are skipped, this client dials the Pi
//! directly by IP:port (exactly like the real Python E2E test's
//! `http.client.HTTPSConnection("127.0.0.1", port, ...)` does) -- no
//! DNS/mDNS-name-to-TLS-SNI trick is needed or attempted.
//!
//! # No auto-follow redirects
//!
//! The Pi server never sends a redirect in v1, but this client does not
//! silently follow one if it ever did: the underlying `ureq` agent is
//! configured with `max_redirects(0)`, so any 3xx response is returned to
//! the caller as an ordinary (non-2xx) status, mapped the same way any
//! other unexpected status is (see [`PiHttpError::UnexpectedStatus`]).
//!
//! # Error mapping
//!
//! Every non-2xx response is expected to be `application/problem+json`.
//! [`PiApiErrorCode`] mirrors the frozen wire `code` registry and callers MUST
//! branch on it, never on `detail` (a free-form human string) -- matching
//! the schema's own documented contract. A response that claims a non-2xx
//! status but does not actually parse as a problem+json body (e.g. a
//! misbehaving/incompatible server, or the deliberately-untouched
//! redirect-not-followed case above) becomes
//! [`PiHttpError::UnexpectedStatus`] rather than panicking or silently
//! discarding the body.
//!
//! This module deliberately does not reuse `ylx_transfer_core::transfer::
//! FailureCode` for wire errors: that enum is PC-00's *job-scoped* failure
//! classification (network/disk-full/hash-mismatch/object-store-rejected/
//! device-heartbeat-failed -- a coordinator-level concept), not a mirror of
//! the Pi's wire error registry (invalid_request/session_in_use/
//! revision_mismatch/etc, an HTTP-protocol-scoped concept) -- collapsing
//! the two would lose exactly the distinction PC-00's own module doc
//! comment on `TransferJobState::Failed` warns against. It *does* reuse
//! [`ylx_transfer_core::domain::{SessionId, FileId}`] (path parameters) and
//! [`ylx_transfer_core::device::{CaptureActivityState, PairingPhase}`]
//! (wire enums that already match verbatim) wherever the wire shape and the
//! core domain type genuinely coincide.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ureq::http::{self, HeaderMap, Method};
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, TcpConnector,
    Transport, TransportAdapter,
};
use ureq::Agent;
use zeroize::Zeroizing;

use ylx_transfer_core::device::{CaptureActivityState, PairingPhase};
use ylx_transfer_core::domain::{FileId, SessionId};
use ylx_transfer_core::secret::Secret;

use crate::discovery_mdns::url_host_literal;

const SUPPORTED_PROTOCOL_MAJOR: u32 = 1;
pub const DEVICE_API_V4_SUPPORTED_MAJOR: u32 = 4;
pub const DEVICE_API_V4_CONTRACT_SHA256: &str =
    "b6f3c677c038e55c03581c587973811b0aa2dc91cfb8b602a95128fbac225827";
pub const DEVICE_API_V4_CONTRACT_BYTES: u64 = 124_739;
pub const DEVICE_API_V4_INFO_VERSION: &str = "4.0.0";
pub const DEVICE_API_V4_BASE_PATH: &str = "/api/v4";
const DEVICE_API_V4_DESCRIPTOR_SCHEMA: &str = "ylx.device.v4";
const DEVICE_API_V4_DESCRIPTOR_VERSION: &str = "4.0";
const DEVICE_API_V4_SESSION_CATALOG_TIMEOUT: Duration = Duration::from_secs(30);
const LAB_V4_LOCAL_PAIRING_EXPIRY: &str = "2099-01-01T00:00:00Z";
const LAB_V4_PUBLICATION_KEY_SEED: [u8; 32] = [
    0x74, 0x93, 0x4f, 0x27, 0x6d, 0x8b, 0x1c, 0x55, 0xa0, 0xf2, 0x42, 0x38, 0x91, 0x63, 0xd4, 0x2a,
    0x5f, 0x13, 0x8c, 0xe1, 0x97, 0x20, 0xab, 0x4d, 0x69, 0xbe, 0x03, 0x81, 0xca, 0x7d, 0x5e, 0x11,
];

// =====================================================================
// Secret-carrying arguments
// =====================================================================

/// Anything this client will accept as secret material for a request —
/// the pairing `poll_secret` or the bearer connection token.
///
/// Every credential-taking method takes `&(impl SecretRef + ?Sized)`
/// rather than a bare `&str`, so a caller that already holds a
/// [`Secret`] can hand it over **without** calling `expose_secret` at the
/// call site: the single unavoidable exposure happens inside this module,
/// immediately before the value is written into a header or a query
/// string. `&str`/`&String` remain accepted so pre-existing call sites
/// (and tests using literals) are unaffected.
pub(crate) trait SecretRef {
    /// Borrow the raw text. Implementations must not copy or retain it.
    fn expose(&self) -> &str;
}

impl SecretRef for str {
    fn expose(&self) -> &str {
        self
    }
}

impl SecretRef for String {
    fn expose(&self) -> &str {
        self.as_str()
    }
}

impl SecretRef for Secret {
    fn expose(&self) -> &str {
        self.expose_secret()
    }
}

impl<T: SecretRef + ?Sized> SecretRef for &T {
    fn expose(&self) -> &str {
        (**self).expose()
    }
}

// =====================================================================
// Remote-text sanitization
// =====================================================================

/// Maximum number of **bytes of remote-controlled text** this client will
/// ever retain in an error value (and therefore in a log line): 1 KiB.
///
/// A `problem+json` `detail`, an unparsable error body, an `ETag`, a
/// `Content-Range` — all of these are chosen by the device on the other
/// end of the connection, which is only ever authenticated by a TLS pin
/// the user may have accepted from a hostile device. Nothing
/// remote-controlled reaches an error string without passing through
/// [`sanitize_remote_text`] first.
pub const MAX_REMOTE_TEXT_BYTES: usize = 1024;

/// Appended by [`sanitize_remote_text`] when it dropped input.
pub const REMOTE_TEXT_TRUNCATION_MARKER: &str = "...[truncated]";

/// Bound and de-fang a remote-controlled byte string before it is stored
/// in a [`PiHttpError`], surfaced to the UI, or written to a log.
///
/// Two independent hostile inputs are neutralized:
///
/// 1. **Size.** Only the first [`MAX_REMOTE_TEXT_BYTES`] bytes are kept;
///    anything beyond is dropped and [`REMOTE_TEXT_TRUNCATION_MARKER`] is
///    appended, so a device answering an error with a multi-megabyte body
///    cannot flood the log or the error path. (The read itself is
///    separately capped at the adapter's private error-body limit.)
/// 2. **Content.** Every control character (which includes `ESC`, so ANSI
///    /terminal escape sequences cannot be injected into a terminal that
///    tails the log), every C1 code, and every Unicode bidi-override /
///    invisible-formatting code point is replaced with U+FFFD. Line
///    breaks are control characters too and are replaced as well, so a
///    hostile body cannot forge additional log lines.
///
/// Invalid UTF-8 (including a sequence split by the byte cap) degrades to
/// U+FFFD via lossy decoding rather than erroring — an unreadable error
/// body is still worth reporting.
pub fn sanitize_remote_text(raw: &[u8]) -> String {
    let kept = raw.len().min(MAX_REMOTE_TEXT_BYTES);
    let mut out = String::with_capacity(kept);
    for ch in String::from_utf8_lossy(&raw[..kept]).chars() {
        // `char::is_control` covers C0 (0x00-0x1F, incl. ESC/CR/LF/TAB)
        // and DEL/C1 (0x7F-0x9F). The explicit ranges below are the
        // non-control code points that still steer a terminal or a text
        // renderer: bidi embedding/override, isolates, and ZWJ/ZWNJ/BOM.
        let dangerous = ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}');
        out.push(if dangerous { '\u{fffd}' } else { ch });
    }
    if raw.len() > kept {
        out.push_str(REMOTE_TEXT_TRUNCATION_MARKER);
    }
    out
}

/// [`sanitize_remote_text`] for text that already decoded as a `str`
/// (a parsed `problem+json` field, a header value).
fn sanitize_remote_str(raw: &str) -> String {
    sanitize_remote_text(raw.as_bytes())
}

// =====================================================================
// Configuration
// =====================================================================

/// The Pi daemon's TLS identity pin: the `sha256:<64 lowercase hex>` (or
/// bare 64-hex-char) SHA-256 of its certificate's DER-encoded
/// SubjectPublicKeyInfo, exactly as `tls_identity.compute_fingerprint`
/// computes it on the Pi side. See the module doc comment's TLS section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiTlsPin(pub String);

/// Everything needed to construct a [`PiHttpClient`]. `host`/`port` are
/// dialed directly (no DNS/SNI hostname matching -- see module docs);
/// `host` is typically an IP address obtained from mDNS discovery
/// ([`crate::discovery_mdns`]) or a manually-entered address, never
/// trusted on its own (ADR-DISC-001) -- only `tls_pin` establishes trust.
#[derive(Debug, Clone)]
pub struct PiHttpClientConfig {
    pub host: String,
    pub port: u16,
    pub tls_pin: PiTlsPin,
    /// Total timeout for bounded control calls; connect/header and blocked
    /// read/write timeout for file streams. It is never a cumulative
    /// whole-file transfer deadline.
    pub request_timeout: Duration,
}

/// Which device HTTP contract this concrete client is speaking.
///
/// `V1PinnedHttps` is the historical production contract: pinned HTTPS,
/// `/api/v1`, bearer session tokens, SAS pairing, and detached Ed25519
/// publication envelopes from the device. `V4LabHttp` is the current
/// RDK-X5/internal-lab contract: plain HTTP on the trusted internal network,
/// `/api/v4`, no bearer requirement for the listed lab operations, and
/// immutable artifact descriptors from the Device Session v2 manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiApiMode {
    V1PinnedHttps,
    V4LabHttp,
}

/// Stable transport/profile identity negotiated by this concrete client.
/// This is deliberately separate from capabilities: callers gate commands on
/// [`DeviceCapabilities`], while the profile explains where those capability
/// facts came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceApiProfile {
    #[default]
    LegacyPinnedHttpsV1,
    LabHttpV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapabilitySource {
    DeviceDescriptor,
    ProfileContract,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NegotiatedCapability {
    pub supported: bool,
    pub source: CapabilitySource,
}

impl NegotiatedCapability {
    fn declared(supported: bool) -> Self {
        Self {
            supported,
            source: CapabilitySource::DeviceDescriptor,
        }
    }

    fn profile(supported: bool) -> Self {
        Self {
            supported,
            source: CapabilitySource::ProfileContract,
        }
    }
}

/// Command/query capabilities after combining explicit `/device`
/// declarations with the closed route set of the negotiated profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceCapabilities {
    pub capture: NegotiatedCapability,
    pub preview: NegotiatedCapability,
    pub range_download: NegotiatedCapability,
    pub network_mutation: NegotiatedCapability,
    pub calibration_capture: NegotiatedCapability,
    pub session_list: NegotiatedCapability,
    pub session_detail: NegotiatedCapability,
    pub artifact_download: NegotiatedCapability,
    pub capture_status: NegotiatedCapability,
    pub session_deletion: NegotiatedCapability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V4CaptureDeviceState {
    Idle,
    Recording,
    Finalizing,
    Encoding,
    Verifying,
    Blocked,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatusInfo {
    pub authority_epoch: String,
    pub source_revision: u64,
    pub device_state: V4CaptureDeviceState,
    pub active_recording: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PublicationEnvelopeOrigin {
    #[default]
    DeviceSigned,
    ClientDerivedLabCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabV4DeviceProbe {
    pub device_id: String,
    pub device_label: String,
    pub synthetic_identity_pin: PiTlsPin,
}

// =====================================================================
// Errors
// =====================================================================

/// Stable, wire-level error codes from `problem+json`'s `code` field.
/// The exact string set matches the Conductor v1 contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PiApiErrorCode {
    InvalidRequest,
    InvalidSession,
    Unauthorized,
    PairingQueueFull,
    RateLimited,
    CaptureBusy,
    SessionInUse,
    RevisionMismatch,
    RangeNotSatisfiable,
    StorageUnavailable,
    ServerOverloaded,
    InternalError,
    /// Any `code` value this client does not (yet) know about. Per the
    /// problem schema's own documented contract ("new codes may be added
    /// in a minor revision and unrecognized codes MUST be treated by
    /// clients as a generic structured failure, never ignored") -- this is
    /// that fail-safe bucket, not a parse failure.
    Unknown(String),
}

impl PiApiErrorCode {
    fn from_wire(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "invalid_session" => Self::InvalidSession,
            "unauthorized" => Self::Unauthorized,
            "pairing_queue_full" => Self::PairingQueueFull,
            "rate_limited" => Self::RateLimited,
            "capture_busy" => Self::CaptureBusy,
            "session_in_use" => Self::SessionInUse,
            "revision_mismatch" => Self::RevisionMismatch,
            "range_not_satisfiable" => Self::RangeNotSatisfiable,
            "storage_unavailable" => Self::StorageUnavailable,
            "server_overloaded" => Self::ServerOverloaded,
            "internal_error" => Self::InternalError,
            // An unrecognized `code` is remote-controlled text that ends
            // up in `Debug`-formatted error output, so it is bounded and
            // de-fanged like every other remote string.
            other => Self::Unknown(sanitize_remote_str(other)),
        }
    }
}

/// A structured `problem+json` error response, fully parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: PiApiErrorCode,
    pub status: u16,
    pub request_id: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub detail: String,
}

/// Every way a [`PiHttpClient`] call can fail.
#[derive(Debug)]
pub enum PiHttpError {
    /// A well-formed `problem+json` error response (the expected shape for
    /// any non-2xx response from a compliant Pi daemon).
    Api(ApiError),
    /// Device API v4 rejected an opaque session cursor because its complete
    /// catalog snapshot changed. The replacement revision is parsed only from
    /// the closed `ylx.api-error.v2` CatalogChangedError shape.
    CatalogChanged {
        status: u16,
        request_id: String,
        catalog_revision: String,
        detail: String,
    },
    /// A non-2xx (or otherwise unexpected-for-this-call) status whose body
    /// did **not** parse as `problem+json` -- includes the "redirect not
    /// followed" case (module docs) and any response from a
    /// misbehaving/incompatible server. Never silently discarded.
    UnexpectedStatus { status: u16, body: String },
    /// `412 Precondition Failed` on a file `GET` or `HEAD`: the object no
    /// longer matches the `If-Match` validator the caller supplied, so the
    /// remote object changed since that checkpoint was recorded.
    ///
    /// This is a *transport outcome the download state machine acts on*
    /// (discard the local partial, restart from byte 0), not a generic
    /// failure — hence its own variant instead of being folded into
    /// [`PiHttpError::Api`]/[`PiHttpError::UnexpectedStatus`], where the
    /// status could only be recovered by string-matching.
    PreconditionFailed {
        etag: Option<String>,
        detail: String,
    },
    /// `416 Range Not Satisfiable` on a ranged file `GET`. Carries the raw
    /// `Content-Range: bytes */{total}` header verbatim when the server
    /// sent one, because the caller needs the real object size to decide
    /// whether its local partial is already complete. Same rationale as
    /// [`PiHttpError::PreconditionFailed`] for having its own variant.
    RangeNotSatisfiable {
        content_range: Option<String>,
        etag: Option<String>,
        detail: String,
    },
    /// A v4 operation that may expose artifact bytes was attempted without a
    /// current, known-usable gateway verdict from the session list.
    SessionVerificationRequired {
        session_id: String,
        reason: String,
        diagnostics: Vec<V4GatewayDiagnostic>,
    },
    /// The exact manifest bytes no longer match the usable list revision the
    /// caller selected. This is ordinary freshness failure: refetch the list;
    /// never combine fields from the two revisions.
    SessionRevisionMismatch {
        session_id: String,
        expected_revision: String,
        observed_revision: String,
    },
    /// A 2xx response whose JSON body did not match the expected shape.
    Decode(String),
    /// A response header was missing/malformed in a way that made the
    /// response impossible to interpret safely (e.g. an unparsable
    /// `Content-Range` on a `206` -- see the internal range-request handling.
    InvalidResponse(String),
    /// A caller-supplied argument was rejected before any request was
    /// sent (e.g. a malformed TLS pin, or a session/file id containing a
    /// path separator -- ADR-PATH-001 discipline applied at the wire-id
    /// boundary too, not just the filesystem boundary).
    InvalidArgument(String),
    /// The TLS handshake or transport-level connection failed (includes
    /// the fingerprint-pin mismatch produced by
    /// `PinnedFingerprintVerifier`).
    Tls(String),
    /// Any other network/IO failure reaching the daemon at all.
    Network(String),
}

impl fmt::Display for PiHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(e) => write!(
                f,
                "pi api error: {:?} (status {}, request_id={}, retryable={}): {}",
                e.code, e.status, e.request_id, e.retryable, e.detail
            ),
            Self::CatalogChanged {
                status,
                request_id,
                catalog_revision,
                detail,
            } => write!(
                f,
                "pi catalog changed (status {status}, request_id={request_id}, catalog_revision={catalog_revision}): {detail}"
            ),
            Self::UnexpectedStatus { status, body } => {
                write!(f, "unexpected pi http status {status}: {body}")
            }
            Self::PreconditionFailed { etag, detail } => write!(
                f,
                "pi returned 412 precondition failed (etag={etag:?}): {detail}"
            ),
            Self::RangeNotSatisfiable {
                content_range,
                detail,
                ..
            } => write!(
                f,
                "pi returned 416 range not satisfiable (content-range={content_range:?}): {detail}"
            ),
            Self::SessionVerificationRequired {
                session_id,
                reason,
                diagnostics,
            } => write!(
                f,
                "Device API v4 session {session_id} is not verified usable ({reason}; diagnostics={diagnostics:?})"
            ),
            Self::SessionRevisionMismatch {
                session_id,
                expected_revision,
                observed_revision,
            } => write!(
                f,
                "Device API v4 session {session_id} revision changed (expected {expected_revision}, observed {observed_revision})"
            ),
            Self::Decode(msg) => write!(f, "failed to decode pi response body: {msg}"),
            Self::InvalidResponse(msg) => write!(f, "invalid pi response: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::Tls(msg) => write!(f, "pi tls error: {msg}"),
            Self::Network(msg) => write!(f, "pi network error: {msg}"),
        }
    }
}

impl std::error::Error for PiHttpError {}

// =====================================================================
// Wire DTOs
// =====================================================================

/// Raw wire shape of the v1 `application/problem+json` response.
#[derive(Debug, Deserialize)]
struct ProblemDetails {
    // Parsed to keep the wire contract strict, but deliberately not exposed
    // in `ApiError`: this client currently supports the schema's v1 shape.
    // The leading underscore documents that the version is intentionally
    // ignored while `serde(rename)` preserves the exact wire key.
    #[serde(rename = "error_schema_version")]
    _error_schema_version: u32,
    code: String,
    status: u16,
    request_id: String,
    retryable: bool,
    retry_after_ms: Option<u64>,
    detail: String,
}

/// Closed Device API v4 error envelope. `details` is an extension bag for
/// ordinary errors, but `catalog_changed` is decoded again into its dedicated
/// closed shape below before it can become a typed control-flow outcome.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2ErrorEnvelope {
    schema: String,
    error: V2ErrorBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2ErrorBody {
    code: String,
    message: String,
    request_id: String,
    retryable: bool,
    #[serde(default)]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogChangedDetails {
    catalog_revision: String,
}

impl From<ProblemDetails> for ApiError {
    fn from(p: ProblemDetails) -> Self {
        // `request_id`/`detail` are free-form strings chosen by the
        // remote device and are routinely logged and shown to the user;
        // bound and sanitize both (see `sanitize_remote_text`).
        ApiError {
            code: PiApiErrorCode::from_wire(&p.code),
            status: p.status,
            request_id: sanitize_remote_str(&p.request_id),
            retryable: p.retryable,
            retry_after_ms: p.retry_after_ms,
            detail: sanitize_remote_str(&p.detail),
        }
    }
}

/// `POST /api/v1/pairing-requests` (202) response.
///
/// `poll_secret` is secret material. It stays a `String` here because
/// this is the raw wire DTO and the field is copied straight into
/// `ylx_transfer_core::device::PairingCreatedView` (whose shape this
/// commit does not own); [`Self::poll_secret`] hands it back as a
/// zeroize-on-drop [`Secret`] for callers that can take one, and the
/// hand-written [`fmt::Debug`] impl below guarantees the value never
/// reaches a log line either way.
#[derive(Clone, Deserialize)]
pub(crate) struct PairingCreated {
    pub attempt_id: String,
    pub phase: PairingPhase,
    pub poll_secret_configured: bool,
    pub poll_secret: String,
    pub expires_at: String,
    pub sas: String,
    #[serde(default)]
    pub sas_transcript: Option<SasTranscript>,
}

impl PairingCreated {
    /// The poll secret, wrapped so it zeroizes on drop and redacts when
    /// formatted. Prefer this over reading the raw field.
    pub fn poll_secret(&self) -> Secret {
        Secret::new(self.poll_secret.as_str())
    }
}

/// Hand-written (never derived) so `{:?}` on this DTO -- or on anything
/// that contains it -- cannot print the pairing poll secret.
impl fmt::Debug for PairingCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCreated")
            .field("attempt_id", &self.attempt_id)
            .field("phase", &self.phase)
            .field("poll_secret_configured", &self.poll_secret_configured)
            .field("poll_secret", &self.poll_secret())
            .field("expires_at", &self.expires_at)
            .field("sas", &self.sas)
            .field("sas_transcript", &self.sas_transcript)
            .finish()
    }
}

/// `GET /api/v1/pairing-requests/{id}` (200) response. `connection_token`
/// is one-shot: the Pi never redelivers it on a later poll (ADR-SEC-003).
/// The `connection_token` is the long-lived bearer credential for every
/// authenticated call; same wire-DTO rationale as [`PairingCreated`] for
/// why the field stays a `String`, same two mitigations
/// (crate-private visibility and the redacted [`fmt::Debug`]).
#[derive(Clone, Deserialize)]
pub(crate) struct PairingStatus {
    pub attempt_id: String,
    pub phase: PairingPhase,
    pub poll_secret_configured: bool,
    pub expires_at: String,
    pub sas: String,
    pub(crate) connection_token: Option<String>,
    #[serde(default)]
    pub sas_transcript: Option<SasTranscript>,
}

/// Hand-written (never derived) so `{:?}` on this DTO -- or on anything
/// that contains it -- cannot print the connection token.
impl fmt::Debug for PairingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let connection_token = self.connection_token.as_deref().map(Secret::new);
        f.debug_struct("PairingStatus")
            .field("attempt_id", &self.attempt_id)
            .field("phase", &self.phase)
            .field("poll_secret_configured", &self.poll_secret_configured)
            .field("expires_at", &self.expires_at)
            .field("sas", &self.sas)
            .field("connection_token", &connection_token)
            .field("sas_transcript", &self.sas_transcript)
            .finish()
    }
}

/// ADR-SEC-002's fixed seven-field SAS transcript. The server sends these
/// public fields, but the client independently validates their bindings and
/// derives the displayed SAS; the server-provided `sas` is never trusted as
/// an authority on its own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct SasTranscript {
    pub tls_cert_fingerprint: String,
    pub publication_key_fingerprint: String,
    pub client_nonce: String,
    pub pi_nonce: String,
    pub device_name: String,
    pub protocol_version: String,
    pub request_digest: String,
}

/// `POST /api/v1/session/heartbeat` (200) response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HeartbeatOutcome {
    // The session facade currently consumes only timeout/expiry. Keep the
    // required wire field so decoding remains strict, but make its
    // intentionally unexported-to-callers status explicit.
    #[serde(rename = "daemon_instance_id")]
    pub _daemon_instance_id: String,
    pub idle_timeout_ms: u64,
    pub absolute_expires_at: String,
    /// Device API v4 derives liveness and capture activity from the same
    /// `/capture/status` snapshot. Legacy wire responses never contain it.
    #[serde(skip, default)]
    pub capture_activity: Option<CaptureActivityState>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StorageInfo {
    #[serde(rename = "free_bytes")]
    pub _free_bytes: u64,
    #[serde(rename = "total_bytes")]
    pub _total_bytes: u64,
}

/// `GET /api/v1/device` (200) response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DeviceInfo {
    pub protocol_major: u32,
    #[serde(rename = "protocol_minor")]
    pub _protocol_minor: u32,
    #[serde(rename = "capabilities")]
    pub _capabilities: Vec<String>,
    #[serde(rename = "storage")]
    pub _storage: StorageInfo,
    pub capture_activity: CaptureActivityState,
    pub media_admission: String,
    pub publication_key_fingerprint: String,
    #[serde(skip, default)]
    pub profile: DeviceApiProfile,
    #[serde(skip, default)]
    pub capabilities: DeviceCapabilities,
    #[serde(skip, default)]
    pub capture_status: Option<CaptureStatusInfo>,
    #[serde(skip, default)]
    pub publication_origin: PublicationEnvelopeOrigin,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DeviceIdentity {
    device_id: String,
    device_label: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DeviceDescriptor {
    schema: String,
    device: V4DeviceIdentity,
    hardware_fingerprint: String,
    api_version: String,
    build: V4DeviceBuild,
    security_profile: String,
    capabilities: V4DeviceCapabilities,
    storage: V4DeviceStorage,
    runtime: V4DeviceRuntime,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DeviceBuild {
    package_version: String,
    commit: String,
    build_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DeviceCapabilities {
    capture: bool,
    preview: bool,
    range_download: bool,
    network_mutation: bool,
    session_list: bool,
    session_detail: bool,
    artifact_download: bool,
    capture_status: bool,
    session_deletion: bool,
    calibration_capture: V4CalibrationCaptureCapability,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4CalibrationCaptureCapability {
    supported: bool,
    enabled: bool,
    disabled_reason: Option<String>,
    required_video_layout: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DeviceStorage {
    volume_id: String,
    total_bytes: u64,
    available_bytes: u64,
    writable: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4DeviceRuntime {
    observed_at: String,
    connection_method: String,
    temperature_celsius: f64,
    network: serde_json::Value,
    live_imu: serde_json::Value,
    camera: serde_json::Value,
    camera_focus: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct V4CaptureStatusWire {
    schema: String,
    authority_epoch: String,
    source_revision: u64,
    snapshot: V4CaptureSnapshotWire,
}

#[derive(Debug, Clone, Deserialize)]
struct V4CaptureSnapshotWire {
    schema: String,
    device_state: String,
    active_recording: serde_json::Value,
}

/// One entry in `GET /api/v1/sessions`'s `sessions[]` -- the *summary*
/// shape the Pi handler actually returns (session_id/revision/captured_at/
/// published_at/duration_seconds/total_bytes/video_bytes/file_count), not
/// the full `PublicationManifest` (publication_signature etc) -- verified
/// against `http_handlers.py`'s `_summary_to_wire`. This shape is also
/// used as the base for `GET /sessions/{id}` (singular)'s response, but
/// that endpoint additionally includes a real `files[]` array (see
/// [`SessionDetail`], `http_handlers.py`'s `_detail_to_wire`) -- this
/// `SessionSummary` type itself is only ever deserialized for the *list*
/// endpoint's entries, which never carry `files[]`. The singular detail
/// endpoint additionally returns the exact canonical publication payload
/// plus detached signature/public key material; see [`SessionDetail`].
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SessionSummary {
    pub session_id: SessionId,
    pub revision: String,
    pub captured_at: String,
    pub published_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    pub file_count: u64,
    #[serde(skip, default)]
    pub gateway_verification: Option<V4GatewayVerification>,
}

/// `GET /api/v1/sessions` (200) response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SessionsPage {
    pub catalog_revision: Option<String>,
    pub sessions: Vec<SessionSummary>,
    pub next_cursor: Option<String>,
    #[serde(skip, default)]
    pub diagnostics: Vec<V4SessionDiscoveryDiagnostic>,
    #[serde(skip, default)]
    pub catalog_authority: CatalogRevisionAuthority,
    #[serde(skip, default)]
    pub pagination_supported: bool,
    #[serde(skip, default)]
    pub pagination_unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatalogRevisionAuthority {
    #[default]
    LegacyDevice,
    DeviceStable,
    LocalFirstPageCompatibility,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4GatewayVerificationWire {
    actor: String,
    validator: V4GatewayValidatorWire,
    #[serde(default)]
    manifest_sha256: Option<String>,
    verified_at: String,
    verdict: String,
    diagnostics: Vec<V4GatewayDiagnosticWire>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum V4GatewayDiagnosticWire {
    LegacyMessage(String),
    Structured(V4GatewayDiagnosticV3Wire),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4GatewayDiagnosticV3Wire {
    code: String,
    summary: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4GatewayValidatorWire {
    name: String,
    version: String,
    build_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V4VerificationVerdict {
    Usable,
    Unusable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4GatewayVerification {
    pub actor: String,
    pub validator_name: String,
    pub validator_version: String,
    pub validator_build_sha256: String,
    pub manifest_sha256: String,
    pub manifest_digest_valid: bool,
    pub verified_at: String,
    pub verdict: V4VerificationVerdict,
    pub diagnostics: Vec<V4GatewayDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum V4GatewayDiagnostic {
    LegacyMessage(String),
    Structured { code: String, summary: String },
}

impl V4GatewayVerification {
    pub fn revision(&self) -> String {
        if self.manifest_digest_valid {
            format!("sha256:{}", self.manifest_sha256)
        } else {
            String::new()
        }
    }

    pub fn is_usable(&self) -> bool {
        self.verdict == V4VerificationVerdict::Usable
    }

    pub fn is_detail_eligible(&self) -> bool {
        self.is_usable() && self.manifest_digest_valid
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4SessionSummary {
    pub session_id: String,
    producer_outcome: String,
    take_id: String,
    take_sequence: u64,
    continuation_of: Option<String>,
    display_name: String,
    device: V4DeviceIdentity,
    pub started_at: String,
    pub ended_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub verification: Option<V4GatewayVerificationWire>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V4SessionListContract {
    V2,
    V3,
}

#[derive(Debug, Clone)]
struct V4SessionList {
    contract: V4SessionListContract,
    catalog_revision: Option<String>,
    items: Vec<V4SessionSummary>,
    diagnostics: Vec<V4SessionDiscoveryDiagnosticWire>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V4SessionListDiscriminator {
    schema: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4SessionListV2Wire {
    #[serde(rename = "schema")]
    _schema: String,
    items: Vec<V4SessionSummary>,
    diagnostics: Vec<V4SessionDiscoveryDiagnosticWire>,
    next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4SessionListV3Wire {
    #[serde(rename = "schema")]
    _schema: String,
    #[serde(default)]
    catalog_revision: Option<String>,
    items: Vec<V4SessionSummary>,
    diagnostics: Vec<V4SessionDiscoveryDiagnosticWire>,
    next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct V4SessionDiscoveryDiagnosticWire {
    quarantine_id: String,
    code: String,
    observed_at: String,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V4SessionDiagnosticCode {
    ManifestUnreadable,
    UnsupportedSchema,
    ManifestInvalid,
    ManifestNotSealed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4SessionDiscoveryDiagnostic {
    pub quarantine_id: String,
    pub code: V4SessionDiagnosticCode,
    pub observed_at: String,
    pub message: String,
}

/// One entry in `GET /api/v1/sessions/{id}`'s `files[]` array -- present
/// only in the *detail* response (`GET /sessions/{id}`, singular), never in
/// `GET /sessions`'s list items (see [`SessionSummary`]'s doc comment).
/// Mirrors the Conductor detail response exactly:
/// `id`/`display_path`/`role`/`size_bytes`/
/// `sha256`/`media_type`, snake_case, all six fields always present
/// (never optional/null on this endpoint -- a session only becomes
/// visible here once every file's `sha256`/`media_type` is fully computed
/// and validated on the Pi side).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SessionFileEntry {
    pub id: String,
    pub display_path: String,
    pub role: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub media_type: String,
}

/// `GET /api/v1/sessions/{id}` (200) response -- `SessionSummary`'s
/// aggregate fields plus the real per-file inventory (`files`) and the
/// immutable signed-publication envelope, closing
/// the gap `SessionSummary`'s doc comment describes: the singular
/// `GET /sessions/{id}` endpoint (`_detail_to_wire` on the Pi side) is
/// genuinely richer than the plural `GET /sessions` list endpoint
/// (`_summary_to_wire`), which never includes `files[]` at all. This is a
/// raw transport DTO, not a trusted inventory: production callers must use
/// the session-catalog capability mapping, which verifies the signature and binds the
/// envelope to authenticated `GET /device` before returning file IDs.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SessionDetail {
    pub session_id: SessionId,
    pub revision: String,
    pub captured_at: String,
    pub published_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    pub file_count: u64,
    pub files: Vec<SessionFileEntry>,
    pub publication_payload: String,
    pub publication_signature: String,
    pub publication_public_key: String,
    pub publication_key_fingerprint: String,
    #[serde(skip, default)]
    pub gateway_verification: Option<V4GatewayVerification>,
    #[serde(skip, default)]
    pub publication_origin: PublicationEnvelopeOrigin,
}

/// `DELETE /api/v1/sessions/{id}` (202) response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DeleteSessionReceipt {
    pub session_id: String,
    pub revision: String,
    pub deleted_at: String,
}

/// A resolved `Content-Range: bytes {start}-{end}/{total_size}` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total_size: u64,
}

/// `GET /api/v1/sessions/{id}/files/{file_id}` response (200 or 206).
///
/// This compatibility shape owns a bounded in-memory body. Production
/// downloads must use [`FileStreamResponse`] via
/// [`PiHttpClient::get_file_stream`], which never materializes the whole
/// file in RAM.
#[derive(Debug, Clone)]
pub(crate) struct FileGetResponse {
    /// 200 (no `Range` header was sent) or 206 (a `Range` was honored).
    pub status: u16,
    pub etag: String,
    pub media_type: String,
    pub content_length: u64,
    /// `Some` iff `status == 206`.
    pub content_range: Option<ContentRange>,
    pub body: Vec<u8>,
}

/// Streaming `GET /api/v1/sessions/{id}/files/{file_id}` response.
///
/// The body owns the underlying `ureq` response and is both `'static` and
/// `Send`, so the transfer coordinator may move it to its worker thread and
/// copy bytes incrementally. Dropping the reader before EOF closes or
/// discards the response according to `ureq`'s transport rules; it never
/// causes the remaining file to be buffered by this adapter.
pub(crate) struct FileStreamResponse {
    /// 200 (no `Range` header was sent) or 206 (a `Range` was honored).
    pub status: u16,
    pub etag: String,
    pub media_type: String,
    pub content_length: u64,
    /// `Some` iff `status == 206`.
    pub content_range: Option<ContentRange>,
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for FileStreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileStreamResponse")
            .field("status", &self.status)
            .field("etag", &self.etag)
            .field("media_type", &self.media_type)
            .field("content_length", &self.content_length)
            .field("content_range", &self.content_range)
            .field("body", &"<stream>")
            .finish()
    }
}

/// `HEAD /api/v1/sessions/{id}/files/{file_id}` response. The Pi handler
/// never honors `Range` on `HEAD` (it always resolves the full-file range
/// internally -- see `http_handlers.py::_get_session_file`'s
/// `is_head -> byte_range = None` branch), so this is always a `200`
/// shape, never `206`.
#[derive(Debug, Clone)]
pub(crate) struct FileHeadResponse {
    pub etag: String,
    pub media_type: String,
    pub content_length: u64,
}

/// A single-range `Range:` request, mirroring the exact wire syntax
/// `range_response.py::parse_range_header` accepts on the Pi side:
/// `bytes=<start>-`, `bytes=<start>-<end>` (inclusive), or
/// `bytes=-<suffix_length>`. Multi-range requests are not representable
/// here on purpose -- the Pi only ever accepts a single range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RangeRequest {
    From { start: u64 },
    Bounded { start: u64, end: u64 },
    Suffix { length: u64 },
}

impl RangeRequest {
    fn header_value(self) -> String {
        match self {
            RangeRequest::From { start } => format!("bytes={start}-"),
            RangeRequest::Bounded { start, end } => format!("bytes={start}-{end}"),
            RangeRequest::Suffix { length } => format!("bytes=-{length}"),
        }
    }
}

// =====================================================================
// TLS: fingerprint-pinned rustls ClientConfig + a bespoke ureq Connector
// =====================================================================

fn parse_tls_pin(pin: &PiTlsPin) -> Result<[u8; 32], PiHttpError> {
    let hex_str = pin.0.strip_prefix("sha256:").unwrap_or(&pin.0);
    if hex_str.len() != 64 {
        return Err(PiHttpError::InvalidArgument(format!(
            "tls pin must be 64 hex characters (optionally prefixed \"sha256:\"), got {} characters",
            hex_str.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte_out) in out.iter_mut().enumerate() {
        let byte_str = hex_str.get(i * 2..i * 2 + 2).ok_or_else(|| {
            PiHttpError::InvalidArgument(format!("tls pin is not valid hex: {:?}", pin.0))
        })?;
        *byte_out = u8::from_str_radix(byte_str, 16).map_err(|_| {
            PiHttpError::InvalidArgument(format!("tls pin is not valid hex: {:?}", pin.0))
        })?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn spki_fingerprint_from_der(end_entity: &CertificateDer<'_>) -> Result<PiTlsPin, String> {
    let parsed = webpki::EndEntityCert::try_from(end_entity)
        .map_err(|e| format!("cannot parse server certificate: {e:?}"))?;
    let spki = parsed.subject_public_key_info();
    let hash = Sha256::digest(spki.as_ref());
    Ok(PiTlsPin(format!("sha256:{}", hex_encode(&hash))))
}

const SAS_PROTOCOL_DOMAIN: &[u8] = b"YLX-TRANSFER-PAIRING-SAS-V1";

fn append_length_prefixed(out: &mut Vec<u8>, value: &[u8]) -> Result<(), PiHttpError> {
    let length = u32::try_from(value.len()).map_err(|_| {
        PiHttpError::InvalidResponse("pairing SAS transcript field is too large".to_string())
    })?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Independently derives ADR-SEC-002's six-digit SAS from the canonical,
/// length-prefixed transcript. Kept public so cross-language fixtures can
/// exercise the exact production implementation.
pub(crate) fn derive_pairing_sas(transcript: &SasTranscript) -> Result<String, PiHttpError> {
    let fields = [
        transcript.tls_cert_fingerprint.as_str(),
        transcript.publication_key_fingerprint.as_str(),
        transcript.client_nonce.as_str(),
        transcript.pi_nonce.as_str(),
        transcript.device_name.as_str(),
        transcript.protocol_version.as_str(),
        transcript.request_digest.as_str(),
    ];
    if fields.iter().any(|field| field.is_empty()) {
        return Err(PiHttpError::InvalidResponse(
            "pairing SAS transcript contains an empty field".to_string(),
        ));
    }
    let mut canonical = Vec::new();
    append_length_prefixed(&mut canonical, SAS_PROTOCOL_DOMAIN)?;
    for field in fields {
        append_length_prefixed(&mut canonical, field.as_bytes())?;
    }
    let digest = Sha256::digest(&canonical);
    let truncated = u32::from_be_bytes(digest[..4].try_into().expect("SHA-256 has four bytes"));
    Ok(format!("{:06}", truncated % 1_000_000))
}

/// Computes a [`PiTlsPin`] from a PEM-encoded X.509 certificate -- e.g.
/// one read directly off a Pi daemon's state directory
/// (`<state_dir>/tls_cert.pem`, `tls_identity.py`'s `CERT_FILENAME`) in a
/// test/dev setting, or obtained via any other out-of-band channel a real
/// pairing/SAS flow might use in production. Parses exactly one
/// `-----BEGIN CERTIFICATE-----` block; any other PEM blocks in the input
/// (e.g. a private key in the same file) are ignored. Hashes the same
/// SPKI substructure `tls_identity.compute_fingerprint` hashes on the Pi
/// side (see module doc comment's TLS section), so the result is byte-for-
/// byte the same fingerprint string the Pi daemon computes for itself.
pub fn tls_pin_from_pem_certificate(pem: &str) -> Result<PiTlsPin, PiHttpError> {
    let der = pem_certificate_to_der(pem)?;
    let cert_der = CertificateDer::from(der);
    spki_fingerprint_from_der(&cert_der).map_err(PiHttpError::InvalidArgument)
}

fn pem_certificate_to_der(pem: &str) -> Result<Vec<u8>, PiHttpError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN).ok_or_else(|| {
        PiHttpError::InvalidArgument("no BEGIN CERTIFICATE block found in PEM input".to_string())
    })?;
    let after_begin = start + BEGIN.len();
    let end_offset = pem[after_begin..].find(END).ok_or_else(|| {
        PiHttpError::InvalidArgument("no END CERTIFICATE block found in PEM input".to_string())
    })?;
    let b64: String = pem[after_begin..after_begin + end_offset]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| {
            PiHttpError::InvalidArgument(format!("invalid base64 in PEM certificate: {e}"))
        })
}

/// See the module doc comment's TLS section for the full rationale. Pins
/// the server certificate's SPKI SHA-256; still cryptographically verifies
/// the handshake signature; deliberately skips hostname/SAN and
/// chain-of-trust validation (there is no CA in this model).
struct PinnedFingerprintVerifier {
    expected_spki_sha256: [u8; 32],
    supported_algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedFingerprintVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedFingerprintVerifier")
            .field(
                "expected_spki_sha256",
                &hex_encode(&self.expected_spki_sha256),
            )
            .finish()
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual_pin = spki_fingerprint_from_der(end_entity)
            .map_err(|e| rustls::Error::General(format!("pi_http: {e}")))?;
        let actual = parse_tls_pin(&actual_pin)
            .map_err(|e| rustls::Error::General(format!("pi_http: {e}")))?;
        if actual == self.expected_spki_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "pi_http: server certificate fingerprint mismatch (pinned sha256:{}, presented sha256:{})",
                hex_encode(&self.expected_spki_sha256),
                hex_encode(&actual),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// First-contact verifier used only by [`probe_tls_identity`]. It records
/// the certificate presented by the endpoint and permits this one TLS
/// handshake; no HTTP request or credential crosses the connection. Trust
/// is established later when this observed fingerprint is bound into the
/// independently-derived, human-compared SAS.
struct RecordingFingerprintVerifier {
    observed: Arc<Mutex<Option<PiTlsPin>>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for RecordingFingerprintVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingFingerprintVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RecordingFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = spki_fingerprint_from_der(end_entity)
            .map_err(|e| rustls::Error::General(format!("pi_http bootstrap: {e}")))?;
        let mut observed = self.observed.lock().map_err(|_| {
            rustls::Error::General("pi_http bootstrap identity lock poisoned".into())
        })?;
        *observed = Some(pin);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Performs a TLS-1.3-only handshake to an unauthenticated discovery
/// candidate and returns the SPKI fingerprint actually observed on that
/// connection. This is evidence for the subsequent SAS transcript, not a
/// first-use trust decision.
pub fn probe_tls_identity(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<PiTlsPin, PiHttpError> {
    let mut addresses = (host, port).to_socket_addrs().map_err(|e| {
        PiHttpError::Network(format!("cannot resolve candidate {host}:{port}: {e}"))
    })?;
    let address = addresses.next().ok_or_else(|| {
        PiHttpError::Network(format!("candidate {host}:{port} resolved to no addresses"))
    })?;
    let mut socket = TcpStream::connect_timeout(&address, timeout)
        .map_err(|e| PiHttpError::Network(format!("cannot connect to candidate {address}: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|_| socket.set_write_timeout(Some(timeout)))
        .map_err(|e| PiHttpError::Network(format!("cannot set TLS probe timeout: {e}")))?;

    let observed = Arc::new(Mutex::new(None));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(RecordingFingerprintVerifier {
        observed: observed.clone(),
        supported_algs: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| PiHttpError::Tls(format!("TLS 1.3 unavailable: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let server_name: ServerName<'static> = ServerName::try_from(host)
        .map_err(|e| {
            PiHttpError::InvalidArgument(format!("invalid TLS candidate name {host:?}: {e}"))
        })?
        .to_owned();
    let mut connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| PiHttpError::Tls(format!("cannot initialize TLS probe: {e}")))?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|e| PiHttpError::Tls(format!("candidate TLS handshake failed: {e}")))?;
    }
    let observed_pin = observed
        .lock()
        .map_err(|_| PiHttpError::Tls("TLS probe identity lock poisoned".to_string()))?
        .clone()
        .ok_or_else(|| {
            PiHttpError::Tls("TLS probe completed without a server certificate".to_string())
        })?;
    Ok(observed_pin)
}

/// A `ureq` `Connector` that wraps an already-connected transport (a TCP
/// socket, via the standard `TcpConnector` earlier in the chain) in TLS
/// using our own fingerprint-pinned `rustls::ClientConfig`, rather than
/// `ureq`'s built-in `RustlsConnector` (whose `TlsConfig` has no hook for a
/// custom certificate verifier -- see module docs). Deliberately mirrors
/// the shape of `ureq`'s own internal `RustlsConnector`/`RustlsTransport`
/// (same crate, same rustls version already in this workspace's dependency
/// tree via `ureq`'s own `rustls` feature) -- this is not a fork of ureq,
/// just the smallest amount of new glue needed to plug in one different
/// `ServerCertVerifier`.
struct PinnedTlsConnector {
    client_config: Arc<ClientConfig>,
}

impl PinnedTlsConnector {
    fn new(expected_spki_sha256: [u8; 32]) -> Result<Self, PiHttpError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedFingerprintVerifier {
            expected_spki_sha256,
            supported_algs: provider.signature_verification_algorithms,
        });
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| PiHttpError::Tls(format!("unsupported TLS protocol versions: {e}")))?;
        let config = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(Self {
            client_config: Arc::new(config),
        })
    }
}

impl fmt::Debug for PinnedTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedTlsConnector").finish_non_exhaustive()
    }
}

impl<In: Transport> Connector<In> for PinnedTlsConnector {
    type Out = Either<In, PinnedTlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            panic!("PinnedTlsConnector requires a chained transport (e.g. TcpConnector)");
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }

        let host = details
            .uri
            .authority()
            .ok_or_else(|| {
                ureq::Error::Io(std::io::Error::other(
                    "pi_http: request URI has no authority/host",
                ))
            })?
            .host();
        let name: ServerName<'static> = ServerName::try_from(host)
            .map_err(|e| {
                ureq::Error::Io(std::io::Error::other(format!(
                    "pi_http: invalid TLS server name {host:?}: {e}"
                )))
            })?
            .to_owned();

        let conn = ClientConnection::new(self.client_config.clone(), name)?;
        let stream = StreamOwned {
            conn,
            sock: TransportAdapter::new(transport.boxed()),
        };
        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        Ok(Some(Either::B(PinnedTlsTransport { buffers, stream })))
    }
}

struct PinnedTlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl fmt::Debug for PinnedTlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedTlsTransport").finish_non_exhaustive()
    }
}

impl Transport for PinnedTlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

// =====================================================================
// The client
// =====================================================================

const MAX_BUFFERED_RESPONSE_BODY_BYTES: u64 = 10 * 1024 * 1024;

/// Device Session manifests are the only buffered v4 payload that can
/// authorize later artifact requests. Their wire framing is therefore part
/// of the integrity boundary: exactly one decimal `Content-Length`, no more
/// than this limit, and exactly that many response-body bytes.
const MAX_V4_MANIFEST_BODY_BYTES: u64 = MAX_BUFFERED_RESPONSE_BODY_BYTES;

/// Maximum number of bytes read from a **non-2xx** response body.
///
/// A success body is a real payload whose size the protocol dictates, so
/// it keeps the 10 MiB budget above. An error body only ever exists to be
/// parsed as a small `problem+json` document or quoted into a message, so
/// a hostile device gains nothing by making it large — reading is simply
/// stopped at 64 KiB and the excess is discarded (no error is raised;
/// truncating is strictly better than losing the status code). The text
/// that survives into the error value is bounded far more tightly again
/// by [`MAX_REMOTE_TEXT_BYTES`].
const MAX_ERROR_RESPONSE_BODY_BYTES: u64 = 64 * 1024;

struct RawResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct RawStreamResponse {
    status: u16,
    headers: HeaderMap,
    body: Box<dyn Read + Send>,
}

impl RawStreamResponse {
    fn into_bounded(self) -> Result<RawResponse, PiHttpError> {
        // Error responses get the tight cap and are silently truncated;
        // success responses keep the large payload budget and still fail
        // loudly if they blow past it.
        let body = if (200..300).contains(&self.status) {
            read_bounded_response_body(self.body)?
        } else {
            read_truncated_error_body(self.body)?
        };
        Ok(RawResponse {
            status: self.status,
            headers: self.headers,
            body,
        })
    }

    fn into_v4_manifest(self) -> Result<RawResponse, PiHttpError> {
        if self.status != 200 {
            return self.into_bounded();
        }
        let declared = exactly_one_header_str(&self.headers, "content-length")?
            .and_then(parse_ascii_u64)
            .ok_or_else(|| {
                PiHttpError::InvalidResponse(
                    "Device API v4 manifest response requires exactly one unsigned-decimal Content-Length"
                        .to_string(),
                )
            })?;
        if declared > MAX_V4_MANIFEST_BODY_BYTES {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device API v4 manifest Content-Length {declared} exceeds the {MAX_V4_MANIFEST_BODY_BYTES} byte limit"
            )));
        }
        let capacity = usize::try_from(declared).map_err(|_| {
            PiHttpError::InvalidResponse(
                "Device API v4 manifest Content-Length does not fit this platform".to_string(),
            )
        })?;
        let mut body = Vec::with_capacity(capacity);
        self.body
            .take(declared + 1)
            .read_to_end(&mut body)
            .map_err(|error| {
                PiHttpError::Network(format!(
                    "failed reading Device API v4 manifest response body: {error}"
                ))
            })?;
        if body.len() != capacity {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device API v4 manifest body length {} does not match Content-Length {declared}",
                body.len()
            )));
        }
        Ok(RawResponse {
            status: self.status,
            headers: self.headers,
            body,
        })
    }
}

/// Read at most [`MAX_ERROR_RESPONSE_BODY_BYTES`] of a non-2xx body,
/// discarding anything beyond without failing the call.
fn read_truncated_error_body(reader: impl Read) -> Result<Vec<u8>, PiHttpError> {
    let mut body = Vec::new();
    reader
        .take(MAX_ERROR_RESPONSE_BODY_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| PiHttpError::Network(format!("failed reading error response body: {e}")))?;
    Ok(body)
}

fn read_bounded_response_body(reader: impl Read) -> Result<Vec<u8>, PiHttpError> {
    let mut body = Vec::new();
    reader
        .take(MAX_BUFFERED_RESPONSE_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| PiHttpError::Network(format!("failed reading response body: {e}")))?;
    if body.len() as u64 > MAX_BUFFERED_RESPONSE_BODY_BYTES {
        return Err(PiHttpError::InvalidResponse(format!(
            "buffered response body exceeds the {} byte limit",
            MAX_BUFFERED_RESPONSE_BODY_BYTES
        )));
    }
    Ok(body)
}

/// Real HTTPS client for one Pi transfer-daemon. See module docs for the
/// TLS trust model and error-mapping contract.
pub struct PiHttpClient {
    control_agent: Agent,
    session_catalog_agent: Agent,
    stream_agent: Agent,
    base_url: String,
    tls_pin: Option<PiTlsPin>,
    api_mode: PiApiMode,
    pairing_transcripts: Mutex<HashMap<String, SasTranscript>>,
}

/// Validates a wire path segment (session id / file id) is exactly the
/// `^[A-Za-z0-9_-]+$` shape the schemas require, before it is ever
/// concatenated into a URL path -- refusing e.g. an embedded `/` or `..`
/// rather than silently building a request against a different path than
/// the caller intended. Mirrors the discipline
/// `ylx_transfer_core::domain::FileId`'s doc comment describes for the
/// filesystem side (ADR-PATH-001) at the URL-path boundary instead.
fn validate_path_segment(kind: &str, value: &str) -> Result<(), PiHttpError> {
    let valid = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(PiHttpError::InvalidArgument(format!(
            "{kind} {value:?} is not a valid wire id (expected ^[A-Za-z0-9_-]+$)"
        )))
    }
}

/// Render a manifest revision as the strong HTTP entity-tag required by
/// DELETE's `If-Match`. Callers own revision identity, while this adapter
/// owns wire syntax; preserving an already-quoted value keeps retries and
/// compatibility callers idempotent without producing doubled quotes.
fn strong_revision_etag(revision: &str) -> String {
    if revision.len() >= 2 && revision.starts_with('"') && revision.ends_with('"') {
        revision.to_string()
    } else {
        format!("\"{revision}\"")
    }
}

pub fn lab_v4_device_identity_pin(device_id: &str) -> PiTlsPin {
    let material = format!("openaria-bridge-desktop:ylx-device-api-v4-lab-device\0{device_id}");
    PiTlsPin(format!("sha256:{:x}", Sha256::digest(material.as_bytes())))
}

fn lab_v4_publication_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&LAB_V4_PUBLICATION_KEY_SEED)
        .expect("static lab v4 compatibility publication key seed is valid")
}

fn lab_v4_publication_public_key() -> Vec<u8> {
    lab_v4_publication_key_pair().public_key().as_ref().to_vec()
}

fn lab_v4_publication_key_fingerprint() -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(lab_v4_publication_public_key())
    )
}

fn lab_v4_sign_publication(payload: &[u8]) -> Vec<u8> {
    lab_v4_publication_key_pair()
        .sign(payload)
        .as_ref()
        .to_vec()
}

impl PiHttpClient {
    pub fn new(config: PiHttpClientConfig) -> Result<Self, PiHttpError> {
        let pin_bytes = parse_tls_pin(&config.tls_pin)?;
        let control_connector =
            ().chain(TcpConnector::default())
                .chain(PinnedTlsConnector::new(pin_bytes)?);
        let session_catalog_connector =
            ().chain(TcpConnector::default())
                .chain(PinnedTlsConnector::new(pin_bytes)?);
        let stream_connector =
            ().chain(TcpConnector::default())
                .chain(PinnedTlsConnector::new(pin_bytes)?);
        let control_config = Agent::config_builder()
            .timeout_global(Some(config.request_timeout))
            // Branch on status ourselves (mirrors object_store_s3.rs's
            // same choice) so a 4xx/5xx problem+json body is still
            // available to parse, and so no-2xx never becomes a bare
            // ureq::Error that swallows the response body.
            .http_status_as_error(false)
            // Never silently follow a redirect -- see module docs.
            .max_redirects(0)
            .build();
        let stream_config = Agent::config_builder()
            // A data-plane response may legitimately take hours. Bound every
            // setup phase and each blocking body read, but do not impose one
            // cumulative deadline on the complete video body.
            .timeout_resolve(Some(config.request_timeout))
            .timeout_connect(Some(config.request_timeout))
            // In ureq 3.3, RecvResponse checks SendRequest as its
            // predecessor, so this also bounds time-to-response-headers.
            // Do not configure timeout_recv_response here: RecvBody keeps
            // checking that predecessor deadline and would turn it into a
            // cumulative whole-video timeout despite the public API docs.
            .timeout_send_request(Some(config.request_timeout))
            .timeout_send_body(Some(config.request_timeout))
            .timeout_recv_body(Some(config.request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let session_catalog_config = Agent::config_builder()
            .timeout_global(Some(std::cmp::max(
                config.request_timeout,
                DEVICE_API_V4_SESSION_CATALOG_TIMEOUT,
            )))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let control_agent = Agent::with_parts(
            control_config,
            control_connector,
            DefaultResolver::default(),
        );
        let session_catalog_agent = Agent::with_parts(
            session_catalog_config,
            session_catalog_connector,
            DefaultResolver::default(),
        );
        let stream_agent =
            Agent::with_parts(stream_config, stream_connector, DefaultResolver::default());
        // `config.host` is a bare address literal (typically straight out
        // of mDNS). An IPv6 literal must be bracketed and its zone id
        // percent-encoded before it can go into a URL authority, or the
        // result (`https://fe80::1%eth0:9443/...`) is not a parseable URL
        // at all -- every request would fail with a confusing build
        // error. Reuse `discovery_mdns::url_host_literal`, which is the
        // one implementation of that rule in this crate (commit 60).
        let host_literal = url_host_literal(&config.host).map_err(|_| {
            PiHttpError::InvalidArgument(format!(
                "host {:?} is not a usable IPv4/IPv6 address literal",
                config.host
            ))
        })?;
        let base_url = format!("https://{}:{}/api/v1", host_literal, config.port);
        Ok(Self {
            control_agent,
            session_catalog_agent,
            stream_agent,
            base_url,
            tls_pin: Some(PiTlsPin(format!("sha256:{}", hex_encode(&pin_bytes)))),
            api_mode: PiApiMode::V1PinnedHttps,
            pairing_transcripts: Mutex::new(HashMap::new()),
        })
    }

    pub fn new_lab_v4_http(
        host: String,
        port: u16,
        synthetic_identity_pin: PiTlsPin,
        request_timeout: Duration,
    ) -> Result<Self, PiHttpError> {
        let pin_bytes = parse_tls_pin(&synthetic_identity_pin)?;
        let control_connector =
            ().chain(TcpConnector::default())
                .chain(PinnedTlsConnector::new([0u8; 32])?);
        let session_catalog_connector =
            ().chain(TcpConnector::default())
                .chain(PinnedTlsConnector::new([0u8; 32])?);
        let stream_connector =
            ().chain(TcpConnector::default())
                .chain(PinnedTlsConnector::new([0u8; 32])?);
        let control_config = Agent::config_builder()
            .timeout_global(Some(request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let stream_config = Agent::config_builder()
            .timeout_resolve(Some(request_timeout))
            .timeout_connect(Some(request_timeout))
            .timeout_send_request(Some(request_timeout))
            .timeout_send_body(Some(request_timeout))
            .timeout_recv_body(Some(request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let session_catalog_config = Agent::config_builder()
            .timeout_global(Some(std::cmp::max(
                request_timeout,
                DEVICE_API_V4_SESSION_CATALOG_TIMEOUT,
            )))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let control_agent = Agent::with_parts(
            control_config,
            control_connector,
            DefaultResolver::default(),
        );
        let session_catalog_agent = Agent::with_parts(
            session_catalog_config,
            session_catalog_connector,
            DefaultResolver::default(),
        );
        let stream_agent =
            Agent::with_parts(stream_config, stream_connector, DefaultResolver::default());
        let host_literal = url_host_literal(&host).map_err(|_| {
            PiHttpError::InvalidArgument(format!(
                "host {:?} is not a usable IPv4/IPv6 address literal",
                host
            ))
        })?;
        let base_url = format!(
            "http://{}:{}{}",
            host_literal, port, DEVICE_API_V4_BASE_PATH
        );
        Ok(Self {
            control_agent,
            session_catalog_agent,
            stream_agent,
            base_url,
            tls_pin: Some(PiTlsPin(format!("sha256:{}", hex_encode(&pin_bytes)))),
            api_mode: PiApiMode::V4LabHttp,
            pairing_transcripts: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn is_lab_v4_http(&self) -> bool {
        self.api_mode == PiApiMode::V4LabHttp
    }

    /// Check that an authenticated core session is bound to this transport's
    /// TLS identity.  The comparison is made on the parsed 32-byte pin so a
    /// bare hex pin and its `sha256:` spelling cannot accidentally create two
    /// identities.  `new_insecure_for_test` has no configured pin and is
    /// accepted only by test builds; production clients always have one.
    pub(crate) fn accepts_session_tls_pin(&self, session_pin: &str) -> bool {
        let Some(configured) = &self.tls_pin else {
            return cfg!(test);
        };
        let Ok(expected) = parse_tls_pin(configured) else {
            return false;
        };
        let Ok(observed) = parse_tls_pin(&PiTlsPin(session_pin.to_string())) else {
            return false;
        };
        expected == observed
    }

    #[cfg(test)]
    /// `pub(crate)` (not private) so `pi_client_port.rs`'s own tests --
    /// which live in a sibling module of this crate, not a submodule of
    /// this one -- can reuse the exact same "real loopback HTTP server,
    /// no TLS" test-client construction this module's own tests already
    /// use, rather than duplicating a second way to build a `PiHttpClient`
    /// against a fake server.
    pub(crate) fn new_insecure_for_test(base_url: String, request_timeout: Duration) -> Self {
        // Test-only constructor used by this module's unit tests against a
        // plain-`http://` `tiny_http` fake server (see module tests): no
        // `https://` scheme means `PinnedTlsConnector::connect` never
        // engages (its `!details.needs_tls()` early-return), so the TLS
        // pin never has to be real here. This keeps the request/response
        // mapping tests independent of standing up real TLS, matching the
        // loopback-server test pattern used by `object_store_s3.rs`.
        let control_connector = ()
            .chain(TcpConnector::default())
            .chain(PinnedTlsConnector::new([0u8; 32]).expect("dummy pin parses"));
        let session_catalog_connector = ()
            .chain(TcpConnector::default())
            .chain(PinnedTlsConnector::new([0u8; 32]).expect("dummy pin parses"));
        let stream_connector = ()
            .chain(TcpConnector::default())
            .chain(PinnedTlsConnector::new([0u8; 32]).expect("dummy pin parses"));
        let control_config = Agent::config_builder()
            .timeout_global(Some(request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let stream_config = Agent::config_builder()
            .timeout_resolve(Some(request_timeout))
            .timeout_connect(Some(request_timeout))
            .timeout_send_request(Some(request_timeout))
            .timeout_send_body(Some(request_timeout))
            .timeout_recv_body(Some(request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let session_catalog_config = Agent::config_builder()
            .timeout_global(Some(std::cmp::max(
                request_timeout,
                DEVICE_API_V4_SESSION_CATALOG_TIMEOUT,
            )))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let control_agent = Agent::with_parts(
            control_config,
            control_connector,
            DefaultResolver::default(),
        );
        let session_catalog_agent = Agent::with_parts(
            session_catalog_config,
            session_catalog_connector,
            DefaultResolver::default(),
        );
        let stream_agent =
            Agent::with_parts(stream_config, stream_connector, DefaultResolver::default());
        Self {
            control_agent,
            session_catalog_agent,
            stream_agent,
            base_url,
            tls_pin: None,
            api_mode: PiApiMode::V1PinnedHttps,
            pairing_transcripts: Mutex::new(HashMap::new()),
        }
    }

    fn validate_pairing_transcript(
        &self,
        attempt_id: &str,
        client_nonce: &str,
        sas: &str,
        transcript: Option<&SasTranscript>,
    ) -> Result<SasTranscript, PiHttpError> {
        // Plain HTTP exists only in cfg(test) loopback mapping tests. Every
        // production client has a TLS pin and therefore requires the full
        // transcript rather than accepting a legacy server-provided SAS.
        let Some(observed_pin) = &self.tls_pin else {
            return transcript.cloned().ok_or_else(|| {
                PiHttpError::InvalidResponse("test response has no SAS transcript".to_string())
            });
        };
        let transcript = transcript.ok_or_else(|| {
            PiHttpError::InvalidResponse("pairing response omitted sas_transcript".to_string())
        })?;
        if transcript.client_nonce != client_nonce {
            return Err(PiHttpError::InvalidResponse(
                "pairing transcript client_nonce does not match this request".to_string(),
            ));
        }
        let observed = parse_tls_pin(observed_pin)?;
        let claimed =
            parse_tls_pin(&PiTlsPin(transcript.tls_cert_fingerprint.clone())).map_err(|_| {
                PiHttpError::InvalidResponse(
                    "pairing transcript contains an invalid TLS fingerprint".to_string(),
                )
            })?;
        if claimed != observed {
            return Err(PiHttpError::InvalidResponse(
                "pairing transcript TLS fingerprint differs from the certificate observed by this client"
                    .to_string(),
            ));
        }
        parse_tls_pin(&PiTlsPin(transcript.publication_key_fingerprint.clone())).map_err(|_| {
            PiHttpError::InvalidResponse(
                "pairing transcript contains an invalid publication-key fingerprint".to_string(),
            )
        })?;
        let expected_request_digest = hex_encode(&Sha256::digest(attempt_id.as_bytes()));
        if transcript.request_digest != expected_request_digest {
            return Err(PiHttpError::InvalidResponse(
                "pairing transcript request_digest does not bind this attempt".to_string(),
            ));
        }
        if sas.len() != 6 || !sas.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PiHttpError::InvalidResponse(
                "pairing response SAS must contain exactly six ASCII digits".to_string(),
            ));
        }
        let independently_derived = derive_pairing_sas(transcript)?;
        if sas != independently_derived {
            return Err(PiHttpError::InvalidResponse(
                "pairing response SAS does not match the independently-derived transcript"
                    .to_string(),
            ));
        }
        Ok(transcript.clone())
    }

    fn execute(
        &self,
        agent: &Agent,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<http::Response<ureq::Body>, PiHttpError> {
        // The query string can carry the pairing `poll_secret`, so the
        // assembled URL is secret-bearing and is scrubbed when this call
        // returns rather than being left in a freed heap buffer. (The
        // per-part intermediates below are scrubbed for the same reason.)
        let mut url = Zeroizing::new(format!("{}{}", self.base_url, path));
        if !query.is_empty() {
            url.push('?');
            let parts: Vec<Zeroizing<String>> = query
                .iter()
                .map(|(k, v)| {
                    let encoded_v: Zeroizing<String> = Zeroizing::new(
                        url::form_urlencoded::byte_serialize(v.as_bytes()).collect(),
                    );
                    Zeroizing::new(format!("{k}={}", encoded_v.as_str()))
                })
                .collect();
            for (index, part) in parts.iter().enumerate() {
                if index > 0 {
                    url.push('&');
                }
                url.push_str(part);
            }
        }

        let mut builder = http::Request::builder().method(method).uri(url.as_str());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(body.unwrap_or_default()).map_err(|e| {
            PiHttpError::InvalidArgument(format!("failed to build HTTP request: {e}"))
        })?;

        agent.run(request).map_err(|e| match e {
            ureq::Error::Tls(msg) => PiHttpError::Tls(msg.to_string()),
            other => PiHttpError::Network(other.to_string()),
        })
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<RawResponse, PiHttpError> {
        let response = self.execute(&self.control_agent, method, path, query, headers, body)?;
        let (parts, body) = response.into_parts();
        RawStreamResponse {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: Box::new(body.into_reader()),
        }
        .into_bounded()
    }

    fn send_session_catalog(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<RawResponse, PiHttpError> {
        let response = self.execute(&self.session_catalog_agent, method, path, query, &[], None)?;
        let (parts, body) = response.into_parts();
        RawStreamResponse {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: Box::new(body.into_reader()),
        }
        .into_bounded()
    }

    fn send_stream(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<RawStreamResponse, PiHttpError> {
        let response = self.execute(&self.stream_agent, method, path, query, headers, body)?;
        let (parts, body) = response.into_parts();
        Ok(RawStreamResponse {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: Box::new(body.into_reader()),
        })
    }

    fn send_v4_manifest(&self, path: &str) -> Result<RawResponse, PiHttpError> {
        self.send_stream(
            Method::GET,
            path,
            &[],
            &[("Accept-Encoding", "identity")],
            None,
        )?
        .into_v4_manifest()
    }

    fn map_v2_error(status: u16, body: &[u8]) -> Option<PiHttpError> {
        let envelope = serde_json::from_slice::<V2ErrorEnvelope>(body).ok()?;
        if envelope.schema != "ylx.api-error.v2" {
            return None;
        }
        let V2ErrorBody {
            code,
            message,
            request_id,
            retryable,
            details,
        } = envelope.error;
        if !valid_v2_error_code(&code)
            || message.is_empty()
            || message.chars().count() > 1024
            || !valid_uuid(&request_id)
            || details.as_ref().is_some_and(|value| !value.is_object())
        {
            return None;
        }

        if code == "catalog_changed" {
            if status != 409 || !retryable {
                return None;
            }
            let details = serde_json::from_value::<CatalogChangedDetails>(details?).ok()?;
            let digest = details.catalog_revision.strip_prefix("sha256:")?;
            let digest = normalize_bare_sha256(digest, "catalog_changed catalog_revision").ok()?;
            return Some(PiHttpError::CatalogChanged {
                status,
                request_id: sanitize_remote_str(&request_id),
                catalog_revision: format!("sha256:{digest}"),
                detail: sanitize_remote_str(&message),
            });
        }

        Some(PiHttpError::Api(ApiError {
            code: PiApiErrorCode::from_wire(&code),
            status,
            request_id: sanitize_remote_str(&request_id),
            retryable,
            retry_after_ms: None,
            detail: sanitize_remote_str(&message),
        }))
    }

    fn map_error(resp: RawResponse) -> PiHttpError {
        if let Some(error) = Self::map_v2_error(resp.status, &resp.body) {
            return error;
        }
        match serde_json::from_slice::<ProblemDetails>(&resp.body) {
            Ok(problem) => PiHttpError::Api(problem.into()),
            // Not problem+json: the body is arbitrary remote-controlled
            // bytes, so it is bounded and de-fanged before it is stored.
            Err(_) => PiHttpError::UnexpectedStatus {
                status: resp.status,
                body: sanitize_remote_text(&resp.body),
            },
        }
    }

    fn map_precondition_failed(resp: RawResponse) -> Result<PiHttpError, PiHttpError> {
        debug_assert_eq!(resp.status, 412);
        let etag = exactly_one_header_str(&resp.headers, "etag")?.map(sanitize_remote_str);
        let detail = match serde_json::from_slice::<ProblemDetails>(&resp.body) {
            Ok(problem) => {
                let api: ApiError = problem.into();
                api.detail
            }
            Err(_) => sanitize_remote_text(&resp.body),
        };
        Ok(PiHttpError::PreconditionFailed { etag, detail })
    }

    fn json_response<T: DeserializeOwned>(
        resp: RawResponse,
        expected: u16,
    ) -> Result<T, PiHttpError> {
        if resp.status != expected {
            return Err(Self::map_error(resp));
        }
        serde_json::from_slice(&resp.body).map_err(|e| PiHttpError::Decode(e.to_string()))
    }

    fn empty_response(resp: RawResponse, expected: u16) -> Result<(), PiHttpError> {
        if resp.status == expected {
            Ok(())
        } else {
            Err(Self::map_error(resp))
        }
    }

    /// Build the `Authorization` header value.
    ///
    /// The result is a [`Zeroizing<String>`] rather than a plain `String`:
    /// it is a verbatim copy of the connection token and would otherwise
    /// be left in a freed heap buffer after every single request.
    fn bearer(token: &(impl SecretRef + ?Sized)) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", token.expose()))
    }

    fn v4_device_descriptor(&self) -> Result<V4DeviceDescriptor, PiHttpError> {
        let resp = self.send(Method::GET, "/device", &[], &[], None)?;
        let descriptor: V4DeviceDescriptor = Self::json_response(resp, 200)?;
        validate_v4_device_descriptor(&descriptor)?;
        Ok(descriptor)
    }

    fn lab_v4_pairing_created(&self, client_nonce: &str) -> Result<PairingCreated, PiHttpError> {
        let attempt_hash = Sha256::digest(client_nonce.as_bytes());
        let attempt_id = format!("lab-v4-{}", &hex_encode(&attempt_hash)[..24]);
        let Some(tls_pin) = &self.tls_pin else {
            return Err(PiHttpError::InvalidArgument(
                "lab v4 client has no synthetic identity pin".to_string(),
            ));
        };
        let request_digest = hex_encode(&Sha256::digest(attempt_id.as_bytes()));
        Ok(PairingCreated {
            attempt_id,
            phase: PairingPhase::Pending,
            poll_secret_configured: false,
            poll_secret: "lab-v4-local".to_string(),
            expires_at: LAB_V4_LOCAL_PAIRING_EXPIRY.to_string(),
            sas: "000000".to_string(),
            sas_transcript: Some(SasTranscript {
                tls_cert_fingerprint: tls_pin.0.clone(),
                publication_key_fingerprint: lab_v4_publication_key_fingerprint(),
                client_nonce: client_nonce.to_string(),
                pi_nonce: "lab-v4-local".to_string(),
                device_name: "ylx-device-api-v4-lab".to_string(),
                protocol_version: "4.0-lab-http".to_string(),
                request_digest,
            }),
        })
    }

    fn lab_v4_pairing_status(&self, attempt_id: &str) -> Result<PairingStatus, PiHttpError> {
        validate_path_segment("attempt_id", attempt_id)?;
        let Some(tls_pin) = &self.tls_pin else {
            return Err(PiHttpError::InvalidArgument(
                "lab v4 client has no synthetic identity pin".to_string(),
            ));
        };
        let request_digest = hex_encode(&Sha256::digest(attempt_id.as_bytes()));
        Ok(PairingStatus {
            attempt_id: attempt_id.to_string(),
            phase: PairingPhase::Allowed,
            poll_secret_configured: false,
            expires_at: LAB_V4_LOCAL_PAIRING_EXPIRY.to_string(),
            sas: "000000".to_string(),
            connection_token: Some(format!("lab-v4-{attempt_id}")),
            sas_transcript: Some(SasTranscript {
                tls_cert_fingerprint: tls_pin.0.clone(),
                publication_key_fingerprint: lab_v4_publication_key_fingerprint(),
                client_nonce: "lab-v4-local".to_string(),
                pi_nonce: "lab-v4-local".to_string(),
                device_name: "ylx-device-api-v4-lab".to_string(),
                protocol_version: "4.0-lab-http".to_string(),
                request_digest,
            }),
        })
    }

    fn v4_capture_status(&self) -> Result<CaptureStatusInfo, PiHttpError> {
        let resp = self.send(Method::GET, "/capture/status", &[], &[], None)?;
        let wire: V4CaptureStatusWire = Self::json_response(resp, 200)?;
        if wire.schema != "ylx.capture-status.v4"
            || wire.snapshot.schema != "ylx.capture-snapshot-event.v4"
        {
            return Err(PiHttpError::InvalidResponse(format!(
                "unsupported Device API v4 capture status schema: {}/{}",
                wire.schema, wire.snapshot.schema
            )));
        }
        if wire.authority_epoch.trim().is_empty() {
            return Err(PiHttpError::InvalidResponse(
                "Device API v4 capture status omitted authority_epoch".to_string(),
            ));
        }
        let active_recording = !wire.snapshot.active_recording.is_null();
        if active_recording && !wire.snapshot.active_recording.is_object() {
            return Err(PiHttpError::InvalidResponse(
                "Device API v4 active_recording must be an object or null".to_string(),
            ));
        }
        let device_state = match wire.snapshot.device_state.as_str() {
            "idle" => V4CaptureDeviceState::Idle,
            "recording" => V4CaptureDeviceState::Recording,
            "finalizing" => V4CaptureDeviceState::Finalizing,
            "encoding" => V4CaptureDeviceState::Encoding,
            "verifying" => V4CaptureDeviceState::Verifying,
            "blocked" => V4CaptureDeviceState::Blocked,
            other => V4CaptureDeviceState::Unknown(sanitize_remote_str(other)),
        };
        let state_requires_active = matches!(
            device_state,
            V4CaptureDeviceState::Recording
                | V4CaptureDeviceState::Finalizing
                | V4CaptureDeviceState::Encoding
                | V4CaptureDeviceState::Verifying
        );
        let state_requires_inactive = matches!(
            device_state,
            V4CaptureDeviceState::Idle | V4CaptureDeviceState::Blocked
        );
        if (state_requires_active && !active_recording)
            || (state_requires_inactive && active_recording)
        {
            return Err(PiHttpError::InvalidResponse(
                "Device API v4 capture status device_state disagrees with active_recording"
                    .to_string(),
            ));
        }
        Ok(CaptureStatusInfo {
            authority_epoch: wire.authority_epoch,
            source_revision: wire.source_revision,
            device_state,
            active_recording,
        })
    }

    fn capture_activity_from_v4_status(status: &CaptureStatusInfo) -> CaptureActivityState {
        match status.device_state {
            V4CaptureDeviceState::Idle => CaptureActivityState::Idle,
            V4CaptureDeviceState::Recording => CaptureActivityState::Recording,
            V4CaptureDeviceState::Finalizing
            | V4CaptureDeviceState::Encoding
            | V4CaptureDeviceState::Verifying => CaptureActivityState::Stopping,
            V4CaptureDeviceState::Blocked => CaptureActivityState::Error,
            V4CaptureDeviceState::Unknown(_) => CaptureActivityState::Unknown,
        }
    }

    fn device_info_from_v4_descriptor(
        descriptor: V4DeviceDescriptor,
        capture_status: Option<CaptureStatusInfo>,
    ) -> DeviceInfo {
        let capture_activity = capture_status
            .as_ref()
            .map(Self::capture_activity_from_v4_status)
            .unwrap_or(CaptureActivityState::Unknown);
        let capabilities = Self::v4_capabilities(&descriptor);
        DeviceInfo {
            protocol_major: SUPPORTED_PROTOCOL_MAJOR,
            _protocol_minor: 0,
            _capabilities: capabilities
                .range_download
                .supported
                .then(|| "range_download".to_string())
                .into_iter()
                .collect(),
            _storage: StorageInfo {
                _free_bytes: descriptor.storage.available_bytes,
                _total_bytes: descriptor.storage.total_bytes,
            },
            capture_activity,
            media_admission: "lab_v4".to_string(),
            publication_key_fingerprint: lab_v4_publication_key_fingerprint(),
            profile: DeviceApiProfile::LabHttpV4,
            capabilities,
            capture_status,
            publication_origin: PublicationEnvelopeOrigin::ClientDerivedLabCompatibility,
        }
    }

    fn v4_capabilities(descriptor: &V4DeviceDescriptor) -> DeviceCapabilities {
        let declared = &descriptor.capabilities;
        DeviceCapabilities {
            capture: NegotiatedCapability::declared(declared.capture),
            preview: NegotiatedCapability::declared(declared.preview),
            range_download: NegotiatedCapability::declared(declared.range_download),
            network_mutation: NegotiatedCapability::declared(declared.network_mutation),
            calibration_capture: NegotiatedCapability::declared(
                declared.calibration_capture.supported,
            ),
            session_list: NegotiatedCapability::profile(true),
            session_detail: NegotiatedCapability::profile(true),
            artifact_download: NegotiatedCapability::declared(declared.artifact_download),
            capture_status: NegotiatedCapability::profile(true),
            session_deletion: NegotiatedCapability::profile(false),
        }
    }

    fn legacy_v1_capabilities(declared: &[String]) -> DeviceCapabilities {
        let has = |underscore: &str, hyphen: &str| {
            declared
                .iter()
                .any(|value| value == underscore || value == hyphen)
        };
        DeviceCapabilities {
            capture: NegotiatedCapability::declared(has("capture", "capture")),
            preview: NegotiatedCapability::declared(has("preview", "preview")),
            range_download: NegotiatedCapability::declared(has("range_download", "range-download")),
            network_mutation: NegotiatedCapability::declared(has(
                "network_mutation",
                "network-mutation",
            )),
            calibration_capture: NegotiatedCapability::declared(has(
                "calibration_capture",
                "calibration-capture",
            )),
            session_list: NegotiatedCapability::profile(true),
            session_detail: NegotiatedCapability::profile(true),
            artifact_download: NegotiatedCapability::profile(true),
            capture_status: NegotiatedCapability::profile(false),
            session_deletion: NegotiatedCapability::profile(true),
        }
    }

    fn decode_v4_session_list(body: &[u8]) -> Result<V4SessionList, PiHttpError> {
        let discriminator: V4SessionListDiscriminator =
            serde_json::from_slice(body).map_err(|error| PiHttpError::Decode(error.to_string()))?;
        match discriminator.schema.as_str() {
            "ylx.session-list.v2" => {
                let page: V4SessionListV2Wire = serde_json::from_slice(body)
                    .map_err(|error| PiHttpError::Decode(error.to_string()))?;
                Ok(V4SessionList {
                    contract: V4SessionListContract::V2,
                    catalog_revision: None,
                    items: page.items,
                    diagnostics: page.diagnostics,
                    next_cursor: page.next_cursor,
                })
            }
            "ylx.session-list.v3" => {
                let page: V4SessionListV3Wire = serde_json::from_slice(body)
                    .map_err(|error| PiHttpError::Decode(error.to_string()))?;
                Ok(V4SessionList {
                    contract: V4SessionListContract::V3,
                    catalog_revision: page.catalog_revision,
                    items: page.items,
                    diagnostics: page.diagnostics,
                    next_cursor: page.next_cursor,
                })
            }
            other => Err(PiHttpError::InvalidResponse(format!(
                "unsupported Device API v4 session list schema {}",
                sanitize_remote_str(other)
            ))),
        }
    }

    fn v4_list_sessions(
        &self,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPage, PiHttpError> {
        if let Some(cursor) = cursor {
            validate_v4_session_cursor(cursor, "request cursor")?;
        }
        let requested_limit = limit.unwrap_or(50).min(200);
        if requested_limit == 0 {
            return Err(PiHttpError::InvalidArgument(
                "Device API v4 session list limit must be positive".to_string(),
            ));
        }
        let limit_str;
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor", c));
        }
        if limit.is_some() {
            limit_str = requested_limit.to_string();
            query.push(("limit", &limit_str));
        }
        let resp = self.send_session_catalog(Method::GET, "/sessions", &query)?;
        if resp.status != 200 {
            return Err(Self::map_error(resp));
        }
        let page = Self::decode_v4_session_list(&resp.body)?;
        let entry_count = page
            .items
            .len()
            .checked_add(page.diagnostics.len())
            .ok_or_else(|| {
                PiHttpError::InvalidResponse(
                    "Device API v4 session page entry count overflowed".to_string(),
                )
            })?;
        if entry_count > requested_limit as usize {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device API v4 session page has {entry_count} items plus diagnostics, exceeding request limit {requested_limit}"
            )));
        }
        if let Some(next_cursor) = page.next_cursor.as_deref() {
            validate_v4_session_cursor(next_cursor, "next_cursor")?;
        }
        let (catalog_revision, catalog_authority, pagination_supported, pagination_reason) =
            match page.contract {
                V4SessionListContract::V3 => {
                    let declared = page.catalog_revision.as_deref().ok_or_else(|| {
                        PiHttpError::InvalidResponse(
                            "Device API v4 session-list.v3 omitted catalog_revision".to_string(),
                        )
                    })?;
                    let catalog_digest = declared
                        .strip_prefix("sha256:")
                        .ok_or_else(|| {
                            PiHttpError::InvalidResponse(
                                "Device API v4 catalog_revision must use sha256:<digest>"
                                    .to_string(),
                            )
                        })
                        .and_then(|value| normalize_bare_sha256(value, "catalog_revision"))?;
                    (
                        Some(format!("sha256:{catalog_digest}")),
                        CatalogRevisionAuthority::DeviceStable,
                        true,
                        None,
                    )
                }
                V4SessionListContract::V2 => {
                    if cursor.is_some() {
                        return Err(PiHttpError::InvalidResponse(
                            "Device API v4 session-list.v2 supports first-page compatibility only; firmware upgrade required for pagination"
                                .to_string(),
                        ));
                    }
                    (
                        None,
                        CatalogRevisionAuthority::LocalFirstPageCompatibility,
                        false,
                        Some("firmware_upgrade_required".to_string()),
                    )
                }
            };

        let mut seen_sessions = std::collections::HashSet::with_capacity(page.items.len());
        for item in &page.items {
            validate_v4_session_summary(item)?;
            if !seen_sessions.insert(item.session_id.clone()) {
                return Err(PiHttpError::InvalidResponse(format!(
                    "Device API v4 session list repeats session_id {}",
                    item.session_id
                )));
            }
        }
        for pair in page.items.windows(2) {
            let newer_timestamp = pair[0].started_at.parse::<jiff::Timestamp>().map_err(|_| {
                PiHttpError::InvalidResponse(
                    "Device API v4 session list started_at is not a valid RFC 3339 timestamp"
                        .to_string(),
                )
            })?;
            let older_timestamp = pair[1].started_at.parse::<jiff::Timestamp>().map_err(|_| {
                PiHttpError::InvalidResponse(
                    "Device API v4 session list started_at is not a valid RFC 3339 timestamp"
                        .to_string(),
                )
            })?;
            let strictly_newer = newer_timestamp > older_timestamp
                || (newer_timestamp == older_timestamp && pair[0].session_id > pair[1].session_id);
            if !strictly_newer {
                return Err(PiHttpError::InvalidResponse(
                    "Device API v4 session items are not ordered newest-first by started_at and session_id"
                        .to_string(),
                ));
            }
        }

        let mut seen_diagnostics = std::collections::HashSet::with_capacity(page.diagnostics.len());
        let mut diagnostics = Vec::with_capacity(page.diagnostics.len());
        for diagnostic in page.diagnostics {
            if !seen_diagnostics.insert(diagnostic.quarantine_id.clone()) {
                return Err(PiHttpError::InvalidResponse(format!(
                    "Device API v4 session diagnostics repeat quarantine_id {}",
                    diagnostic.quarantine_id
                )));
            }
            diagnostics.push(validate_v4_session_diagnostic(diagnostic)?);
        }

        let mut sessions = Vec::with_capacity(page.items.len());
        for item in page.items {
            let gateway_verification = item
                .verification
                .map(|verification| validate_v4_gateway_verification(verification, page.contract))
                .transpose()?;
            let revision = gateway_verification
                .as_ref()
                .map(V4GatewayVerification::revision)
                .unwrap_or_default();
            sessions.push(SessionSummary {
                session_id: SessionId(item.session_id),
                revision,
                captured_at: item.started_at,
                published_at: item.ended_at,
                duration_seconds: item.duration_seconds,
                total_bytes: item.total_bytes,
                video_bytes: item.total_bytes,
                file_count: 0,
                gateway_verification,
            });
        }
        Ok(SessionsPage {
            catalog_revision,
            sessions,
            next_cursor: pagination_supported.then_some(page.next_cursor).flatten(),
            diagnostics,
            catalog_authority,
            pagination_supported,
            pagination_unavailable_reason: pagination_reason,
        })
    }

    fn v4_get_session(
        &self,
        session_id: &SessionId,
        expected_verification: Option<&V4GatewayVerification>,
    ) -> Result<SessionDetail, PiHttpError> {
        validate_path_segment("session_id", session_id.as_str())?;
        let path = format!("/sessions/{}", session_id.as_str());
        let resp = self.send_v4_manifest(&path)?;
        if resp.status != 200 {
            return Err(Self::map_error(resp));
        }
        let manifest_sha256 =
            manifest_sha256_from_headers_or_body(&resp.headers, &resp.body)?.to_string();
        if let Some(expected) = expected_verification {
            if !constant_time_sha256_text_eq(&expected.manifest_sha256, &manifest_sha256) {
                return Err(PiHttpError::SessionRevisionMismatch {
                    session_id: session_id.as_str().to_string(),
                    expected_revision: expected.revision(),
                    observed_revision: format!("sha256:{manifest_sha256}"),
                });
            }
        }
        let source_manifest_json = std::str::from_utf8(&resp.body)
            .map_err(|error| PiHttpError::Decode(format!("manifest is not UTF-8: {error}")))?
            .to_string();
        let manifest: serde_json::Value = serde_json::from_str(&source_manifest_json)
            .map_err(|e| PiHttpError::Decode(e.to_string()))?;
        v4_manifest_to_session_detail(
            session_id.as_str(),
            &manifest_sha256,
            source_manifest_json,
            manifest,
            expected_verification.cloned(),
        )
    }

    // -- pairing -----------------------------------------------------

    /// `POST /api/v1/pairing-requests` (unauthenticated). Returns `202`
    /// with a `poll_secret` the caller must present on every subsequent
    /// poll/cancel of this attempt.
    pub(crate) fn create_pairing_request(
        &self,
        client_name: &str,
        client_nonce: &str,
    ) -> Result<PairingCreated, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = client_name;
            return self.lab_v4_pairing_created(client_nonce);
        }
        let body = serde_json::to_vec(&PairingRequestBody {
            client_name,
            client_nonce,
        })
        .map_err(|e| PiHttpError::InvalidArgument(e.to_string()))?;
        let resp = self.send(
            Method::POST,
            "/pairing-requests",
            &[],
            &[("Content-Type", "application/json")],
            Some(body),
        )?;
        let created: PairingCreated = Self::json_response(resp, 202)?;
        if self.tls_pin.is_some() {
            let transcript = self.validate_pairing_transcript(
                &created.attempt_id,
                client_nonce,
                &created.sas,
                created.sas_transcript.as_ref(),
            )?;
            self.pairing_transcripts
                .lock()
                .map_err(|_| PiHttpError::Network("pairing transcript lock poisoned".to_string()))?
                .insert(created.attempt_id.clone(), transcript);
        }
        Ok(created)
    }

    /// `GET /api/v1/pairing-requests/{id}?poll_secret=...` (unauthenticated
    /// but requires the `poll_secret` from [`Self::create_pairing_request`]).
    pub(crate) fn get_pairing_status(
        &self,
        attempt_id: &str,
        poll_secret: &(impl SecretRef + ?Sized),
    ) -> Result<PairingStatus, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = poll_secret;
            return self.lab_v4_pairing_status(attempt_id);
        }
        validate_path_segment("attempt_id", attempt_id)?;
        let path = format!("/pairing-requests/{attempt_id}");
        let resp = self.send(
            Method::GET,
            &path,
            &[("poll_secret", poll_secret.expose())],
            &[],
            None,
        )?;
        let status: PairingStatus = Self::json_response(resp, 200)?;
        if self.tls_pin.is_some() {
            let expected = self
                .pairing_transcripts
                .lock()
                .map_err(|_| PiHttpError::Network("pairing transcript lock poisoned".to_string()))?
                .get(attempt_id)
                .cloned()
                .ok_or_else(|| {
                    PiHttpError::InvalidResponse(
                        "pairing status has no matching locally-created attempt transcript"
                            .to_string(),
                    )
                })?;
            let actual = self.validate_pairing_transcript(
                attempt_id,
                &expected.client_nonce,
                &status.sas,
                status.sas_transcript.as_ref(),
            )?;
            if actual != expected {
                return Err(PiHttpError::InvalidResponse(
                    "pairing status transcript changed after attempt creation".to_string(),
                ));
            }
        }
        Ok(status)
    }

    /// `DELETE /api/v1/pairing-requests/{id}?poll_secret=...`.
    pub(crate) fn cancel_pairing_request(
        &self,
        attempt_id: &str,
        poll_secret: &(impl SecretRef + ?Sized),
    ) -> Result<(), PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = (attempt_id, poll_secret.expose());
            return Ok(());
        }
        validate_path_segment("attempt_id", attempt_id)?;
        let path = format!("/pairing-requests/{attempt_id}");
        let resp = self.send(
            Method::DELETE,
            &path,
            &[("poll_secret", poll_secret.expose())],
            &[],
            None,
        )?;
        Self::empty_response(resp, 204)
    }

    // -- authenticated session/device -----------------------------------

    /// `POST /api/v1/session/heartbeat`.
    pub(crate) fn heartbeat(
        &self,
        token: &(impl SecretRef + ?Sized),
    ) -> Result<HeartbeatOutcome, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = token.expose();
            let capture_status = self.v4_capture_status()?;
            return Ok(HeartbeatOutcome {
                _daemon_instance_id: "lab-v4-http".to_string(),
                idle_timeout_ms: 60_000,
                absolute_expires_at: LAB_V4_LOCAL_PAIRING_EXPIRY.to_string(),
                capture_activity: Some(Self::capture_activity_from_v4_status(&capture_status)),
            });
        }
        let auth = Self::bearer(token);
        let resp = self.send(
            Method::POST,
            "/session/heartbeat",
            &[],
            &[("Authorization", &auth)],
            None,
        )?;
        Self::json_response(resp, 200)
    }

    /// `DELETE /api/v1/session` -- revokes the connection token itself.
    pub(crate) fn revoke_session(
        &self,
        token: &(impl SecretRef + ?Sized),
    ) -> Result<(), PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = token.expose();
            return Ok(());
        }
        let auth = Self::bearer(token);
        let resp = self.send(
            Method::DELETE,
            "/session",
            &[],
            &[("Authorization", &auth)],
            None,
        )?;
        Self::empty_response(resp, 204)
    }

    /// `GET /api/v1/device`.
    pub(crate) fn get_device(
        &self,
        token: &(impl SecretRef + ?Sized),
    ) -> Result<DeviceInfo, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = token.expose();
            let descriptor = self.v4_device_descriptor()?;
            let capture_status = self.v4_capture_status()?;
            return Ok(Self::device_info_from_v4_descriptor(
                descriptor,
                Some(capture_status),
            ));
        }
        let auth = Self::bearer(token);
        let resp = self.send(
            Method::GET,
            "/device",
            &[],
            &[("Authorization", &auth)],
            None,
        )?;
        let mut device: DeviceInfo = Self::json_response(resp, 200)?;
        if device.protocol_major != SUPPORTED_PROTOCOL_MAJOR {
            return Err(PiHttpError::InvalidResponse(format!(
                "unsupported Pi protocol major {}; expected {SUPPORTED_PROTOCOL_MAJOR}",
                device.protocol_major
            )));
        }
        device.profile = DeviceApiProfile::LegacyPinnedHttpsV1;
        device.capabilities = Self::legacy_v1_capabilities(&device._capabilities);
        device.capture_status = None;
        device.publication_origin = PublicationEnvelopeOrigin::DeviceSigned;
        Ok(device)
    }

    /// Negotiates the descriptor facts for a newly connected epoch. Device
    /// API v4 capture activity is deliberately excluded because the next
    /// periodic tick obtains it from its single authoritative status request.
    pub(crate) fn negotiate_device(
        &self,
        token: &(impl SecretRef + ?Sized),
    ) -> Result<DeviceInfo, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = token.expose();
            return self
                .v4_device_descriptor()
                .map(|descriptor| Self::device_info_from_v4_descriptor(descriptor, None));
        }
        self.get_device(token)
    }

    // -- sessions ---------------------------------------------------------

    /// `GET /api/v1/sessions` (paginated via `cursor`/`limit`).
    pub(crate) fn list_sessions(
        &self,
        token: &(impl SecretRef + ?Sized),
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPage, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = token.expose();
            return self.v4_list_sessions(cursor, limit);
        }
        let auth = Self::bearer(token);
        let limit_str;
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor", c));
        }
        if let Some(l) = limit {
            limit_str = l.to_string();
            query.push(("limit", &limit_str));
        }
        let resp = self.send(
            Method::GET,
            "/sessions",
            &query,
            &[("Authorization", &auth)],
            None,
        )?;
        let mut page: SessionsPage = Self::json_response(resp, 200)?;
        if page.catalog_revision.as_deref().is_none_or(str::is_empty) {
            return Err(PiHttpError::InvalidResponse(
                "legacy session list omitted a non-empty catalog_revision".to_string(),
            ));
        }
        page.catalog_authority = CatalogRevisionAuthority::LegacyDevice;
        page.pagination_supported = true;
        page.pagination_unavailable_reason = None;
        Ok(page)
    }

    /// `GET /api/v1/sessions/{id}` -- the raw detail shape, including the
    /// real per-file inventory and detached publication envelope (see
    /// [`SessionDetail`]'s doc comment). This transport method only parses;
    /// production code must consume it through `SessionCatalogPort` for identity
    /// binding and signature/schema/inventory validation.
    pub(crate) fn get_session(
        &self,
        token: &(impl SecretRef + ?Sized),
        session_id: &SessionId,
    ) -> Result<SessionDetail, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = token.expose();
            return self.v4_get_session(session_id, None);
        }
        validate_path_segment("session_id", session_id.as_str())?;
        let auth = Self::bearer(token);
        let path = format!("/sessions/{}", session_id.as_str());
        let resp = self.send(Method::GET, &path, &[], &[("Authorization", &auth)], None)?;
        Self::json_response(resp, 200)
    }

    /// Read a v4 manifest for a download/export path, bound to the exact
    /// current usable verification returned by the list endpoint. `None`, an
    /// unusable verdict all fail before any manifest request is sent.
    pub(crate) fn get_v4_verified_session(
        &self,
        token: &(impl SecretRef + ?Sized),
        session_id: &SessionId,
        verification: Option<&V4GatewayVerification>,
    ) -> Result<SessionDetail, PiHttpError> {
        if !self.is_lab_v4_http() {
            let _ = token.expose();
            return Err(PiHttpError::InvalidArgument(
                "v4 gateway verification was supplied to a non-v4 device profile".to_string(),
            ));
        }
        validate_path_segment("session_id", session_id.as_str())?;
        let verification =
            verification.ok_or_else(|| PiHttpError::SessionVerificationRequired {
                session_id: session_id.as_str().to_string(),
                reason: "missing_or_stale".to_string(),
                diagnostics: Vec::new(),
            })?;
        if !verification.manifest_digest_valid
            || normalize_bare_sha256(
                &verification.manifest_sha256,
                "verification manifest_sha256",
            )
            .is_err()
        {
            return Err(PiHttpError::SessionVerificationRequired {
                session_id: session_id.as_str().to_string(),
                reason: "invalid_manifest_digest".to_string(),
                diagnostics: verification.diagnostics.clone(),
            });
        }
        let rejection_reason = match &verification.verdict {
            V4VerificationVerdict::Usable => None,
            V4VerificationVerdict::Unusable => Some("unusable".to_string()),
        };
        if let Some(reason) = rejection_reason {
            return Err(PiHttpError::SessionVerificationRequired {
                session_id: session_id.as_str().to_string(),
                reason,
                diagnostics: verification.diagnostics.clone(),
            });
        }
        let _ = token.expose();
        self.v4_get_session(session_id, Some(verification))
    }

    /// `DELETE /api/v1/sessions/{id}`. `if_match_revision` and
    /// `idempotency_key` are both required by the Pi handler (a missing
    /// `If-Match`/`Idempotency-Key` header is a `400 invalid_request`, not
    /// silently defaulted) -- see `http_handlers.py::_delete_session`.
    pub(crate) fn delete_session(
        &self,
        token: &(impl SecretRef + ?Sized),
        session_id: &SessionId,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> Result<DeleteSessionReceipt, PiHttpError> {
        if self.is_lab_v4_http() {
            let _ = (
                token.expose(),
                session_id,
                if_match_revision,
                idempotency_key,
            );
            return Err(PiHttpError::InvalidArgument(
                "Device API v4 lab profile does not expose session deletion".to_string(),
            ));
        }
        validate_path_segment("session_id", session_id.as_str())?;
        let auth = Self::bearer(token);
        let if_match_etag = strong_revision_etag(if_match_revision);
        let path = format!("/sessions/{}", session_id.as_str());
        let resp = self.send(
            Method::DELETE,
            &path,
            &[],
            &[
                ("Authorization", &auth),
                ("If-Match", &if_match_etag),
                ("Idempotency-Key", idempotency_key),
            ],
            None,
        )?;
        Self::json_response(resp, 202)
    }

    // -- files --------------------------------------------------------

    /// Compatibility helper for callers whose port still requires owned
    /// bytes. The body is capped at 10 MiB and larger responses fail
    /// explicitly. Production transfer jobs use [`Self::get_file_stream`]
    /// instead.
    pub(crate) fn get_file(
        &self,
        token: &(impl SecretRef + ?Sized),
        session_id: &SessionId,
        file_id: &FileId,
        if_match: Option<&str>,
        range: Option<RangeRequest>,
    ) -> Result<FileGetResponse, PiHttpError> {
        let resp = self.get_file_stream(token, session_id, file_id, if_match, range)?;
        let FileStreamResponse {
            status,
            etag,
            media_type,
            content_length,
            content_range,
            body,
        } = resp;
        Ok(FileGetResponse {
            status,
            etag,
            media_type,
            content_length,
            content_range,
            body: read_bounded_response_body(body)?,
        })
    }

    /// `GET /api/v1/sessions/{id}/files/{file_id}`, optionally ranged,
    /// returning the real response body as an owned incremental reader.
    /// Successful file bytes are never copied into an intermediate `Vec`.
    pub(crate) fn get_file_stream(
        &self,
        token: &(impl SecretRef + ?Sized),
        session_id: &SessionId,
        file_id: &FileId,
        if_match: Option<&str>,
        range: Option<RangeRequest>,
    ) -> Result<FileStreamResponse, PiHttpError> {
        validate_path_segment("session_id", session_id.as_str())?;
        validate_path_segment("file_id", file_id.as_str())?;
        if self.is_lab_v4_http() {
            let _ = token.expose();
            return self.get_v4_artifact_stream(session_id, file_id, if_match, range);
        }
        let auth = Self::bearer(token);
        let path = format!(
            "/sessions/{}/files/{}",
            session_id.as_str(),
            file_id.as_str()
        );

        let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
        if let Some(m) = if_match {
            headers.push(("If-Match", m));
        }
        let range_header;
        if let Some(r) = range {
            range_header = r.header_value();
            headers.push(("Range", &range_header));
        }

        let resp = self.send_stream(Method::GET, &path, &[], &headers, None)?;
        if resp.status != 200 && resp.status != 206 {
            return Err(Self::map_file_status_error(resp)?);
        }
        Self::parse_file_stream(resp)
    }

    fn get_v4_artifact_stream(
        &self,
        session_id: &SessionId,
        file_id: &FileId,
        if_range: Option<&str>,
        range: Option<RangeRequest>,
    ) -> Result<FileStreamResponse, PiHttpError> {
        let path = format!(
            "/sessions/{}/artifacts/{}",
            session_id.as_str(),
            file_id.as_str()
        );
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(m) = if_range {
            headers.push(("If-Range", m));
        }
        let range_header;
        if let Some(r) = range {
            range_header = r.header_value();
            headers.push(("Range", &range_header));
        }

        let resp = self.send_stream(Method::GET, &path, &[], &headers, None)?;
        if resp.status != 200 && resp.status != 206 {
            return Err(Self::map_file_status_error(resp)?);
        }
        Self::parse_file_stream(resp)
    }

    fn head_v4_artifact(
        &self,
        session_id: &SessionId,
        file_id: &FileId,
        if_range: Option<&str>,
    ) -> Result<FileHeadResponse, PiHttpError> {
        let path = format!(
            "/sessions/{}/artifacts/{}",
            session_id.as_str(),
            file_id.as_str()
        );
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(m) = if_range {
            headers.push(("If-Range", m));
        }
        let resp = self.send(Method::HEAD, &path, &[], &headers, None)?;
        if resp.status != 200 {
            return Err(Self::map_error(resp));
        }
        let etag = exactly_one_header_str(&resp.headers, "etag")?
            .ok_or_else(|| {
                PiHttpError::InvalidResponse("response missing ETag header".to_string())
            })?
            .to_string();
        let media_type = header_str(&resp.headers, "content-type")
            .unwrap_or("")
            .to_string();
        let content_length: u64 = exactly_one_header_str(&resp.headers, "content-length")?
            .and_then(parse_ascii_u64)
            .ok_or_else(|| {
                PiHttpError::InvalidResponse(
                    "response missing/invalid Content-Length header".to_string(),
                )
            })?;
        Ok(FileHeadResponse {
            etag,
            media_type,
            content_length,
        })
    }

    /// Map a non-2xx ranged-file response, preserving `412`/`416` as their
    /// own [`PiHttpError`] variants instead of collapsing them into a
    /// `problem+json`/stringly error. `library::download`'s resume state
    /// machine has a dedicated branch for each of those two statuses; a
    /// caller that cannot tell them apart from "some 4xx" can never reach
    /// those branches. Anything else still goes through the ordinary
    /// [`PiHttpClient::map_error`] mapping.
    ///
    /// The `Result` wrapper only carries a body-read failure (the response
    /// body must be drained to build the error's detail); the `Ok` value is
    /// always itself an error.
    fn map_file_status_error(resp: RawStreamResponse) -> Result<PiHttpError, PiHttpError> {
        let status = resp.status;
        if status != 412 && status != 416 {
            return Ok(Self::map_error(resp.into_bounded()?));
        }
        // Header values are remote-controlled too and land verbatim in a
        // `{:?}`-formatted error; sanitize them alongside the body.
        let bounded = resp.into_bounded()?;
        if status == 412 {
            return Self::map_precondition_failed(bounded);
        }
        let etag = exactly_one_header_str(&bounded.headers, "etag")?.map(sanitize_remote_str);
        let content_range =
            exactly_one_header_str(&bounded.headers, "content-range")?.map(sanitize_remote_str);
        // A compliant Pi answers with problem+json; anything else is still
        // reported verbatim rather than discarded.
        let detail = match serde_json::from_slice::<ProblemDetails>(&bounded.body) {
            Ok(problem) => {
                let api: ApiError = problem.into();
                api.detail
            }
            Err(_) => sanitize_remote_text(&bounded.body),
        };
        Ok(PiHttpError::RangeNotSatisfiable {
            content_range,
            etag,
            detail,
        })
    }

    fn parse_file_stream(resp: RawStreamResponse) -> Result<FileStreamResponse, PiHttpError> {
        let etag = exactly_one_header_str(&resp.headers, "etag")?
            .ok_or_else(|| {
                PiHttpError::InvalidResponse("response missing ETag header".to_string())
            })?
            .to_string();
        let media_type = header_str(&resp.headers, "content-type")
            .unwrap_or("")
            .to_string();
        let raw_content_length = exactly_one_header_str(&resp.headers, "content-length")?;
        let content_length: u64 =
            raw_content_length
                .and_then(parse_ascii_u64)
                .ok_or_else(|| {
                    // The rejected header value is remote-controlled; bound
                    // and de-fang it before it becomes an error string.
                    let shown = raw_content_length.map(sanitize_remote_str);
                    PiHttpError::InvalidResponse(format!(
                        "response missing/invalid Content-Length header: {shown:?}"
                    ))
                })?;

        let content_range = if resp.status == 206 {
            let raw = exactly_one_header_str(&resp.headers, "content-range")?.ok_or_else(|| {
                PiHttpError::InvalidResponse(
                    "206 response missing Content-Range header".to_string(),
                )
            })?;
            Some(parse_content_range(raw)?)
        } else {
            None
        };

        Ok(FileStreamResponse {
            status: resp.status,
            etag,
            media_type,
            content_length,
            content_range,
            body: resp.body,
        })
    }

    /// `HEAD /api/v1/sessions/{id}/files/{file_id}` -- headers only, never
    /// ranged (see [`FileHeadResponse`] docs).
    pub(crate) fn head_file(
        &self,
        token: &(impl SecretRef + ?Sized),
        session_id: &SessionId,
        file_id: &FileId,
        if_match: Option<&str>,
    ) -> Result<FileHeadResponse, PiHttpError> {
        validate_path_segment("session_id", session_id.as_str())?;
        validate_path_segment("file_id", file_id.as_str())?;
        if self.is_lab_v4_http() {
            let _ = token.expose();
            return self.head_v4_artifact(session_id, file_id, if_match);
        }
        let auth = Self::bearer(token);
        let path = format!(
            "/sessions/{}/files/{}",
            session_id.as_str(),
            file_id.as_str()
        );
        let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
        if let Some(m) = if_match {
            headers.push(("If-Match", m));
        }
        let resp = self.send(Method::HEAD, &path, &[], &headers, None)?;
        if resp.status != 200 {
            if resp.status == 412 {
                return Err(Self::map_precondition_failed(resp)?);
            }
            return Err(Self::map_error(resp));
        }
        let etag = exactly_one_header_str(&resp.headers, "etag")?
            .ok_or_else(|| {
                PiHttpError::InvalidResponse("response missing ETag header".to_string())
            })?
            .to_string();
        let media_type = header_str(&resp.headers, "content-type")
            .unwrap_or("")
            .to_string();
        let content_length: u64 = exactly_one_header_str(&resp.headers, "content-length")?
            .and_then(parse_ascii_u64)
            .ok_or_else(|| {
                PiHttpError::InvalidResponse(
                    "response missing/invalid Content-Length header".to_string(),
                )
            })?;
        Ok(FileHeadResponse {
            etag,
            media_type,
            content_length,
        })
    }
}

pub fn probe_lab_v4_device(
    host: &str,
    port: u16,
    request_timeout: Duration,
) -> Result<LabV4DeviceProbe, PiHttpError> {
    let client = PiHttpClient::new_lab_v4_http(
        host.to_string(),
        port,
        PiTlsPin(format!("sha256:{}", "0".repeat(64))),
        request_timeout,
    )?;
    let descriptor = client.v4_device_descriptor()?;
    let synthetic_identity_pin = lab_v4_device_identity_pin(&descriptor.device.device_id);
    Ok(LabV4DeviceProbe {
        device_id: descriptor.device.device_id,
        device_label: descriptor.device.device_label,
        synthetic_identity_pin,
    })
}

#[derive(Serialize)]
struct PairingRequestBody<'a> {
    client_name: &'a str,
    client_nonce: &'a str,
}

fn validate_v4_device_descriptor(descriptor: &V4DeviceDescriptor) -> Result<(), PiHttpError> {
    if descriptor.schema != DEVICE_API_V4_DESCRIPTOR_SCHEMA
        || descriptor.api_version != DEVICE_API_V4_DESCRIPTOR_VERSION
    {
        return Err(PiHttpError::InvalidResponse(format!(
            "unsupported Device API descriptor schema/version: {}/{}",
            sanitize_remote_str(&descriptor.schema),
            sanitize_remote_str(&descriptor.api_version)
        )));
    }
    validate_v4_device_identity("descriptor device", &descriptor.device)?;
    descriptor
        .hardware_fingerprint
        .strip_prefix("sha256:")
        .ok_or_else(|| {
            PiHttpError::InvalidResponse(
                "Device API v4 hardware_fingerprint must use sha256:<digest>".to_string(),
            )
        })
        .and_then(|digest| normalize_bare_sha256(digest, "hardware_fingerprint"))?;
    validate_bounded_remote_field(
        "descriptor build package_version",
        &descriptor.build.package_version,
        64,
    )?;
    if !(40..=64).contains(&descriptor.build.commit.len())
        || !descriptor
            .build
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 descriptor build commit is not 40-64 lowercase hex characters"
                .to_string(),
        ));
    }
    validate_bounded_remote_field("descriptor build build_id", &descriptor.build.build_id, 128)?;
    if descriptor.security_profile != "lab" {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 lab HTTP adapter rejects security profile {}",
            sanitize_remote_str(&descriptor.security_profile)
        )));
    }

    let capabilities = &descriptor.capabilities;
    if !capabilities.range_download
        || !capabilities.session_list
        || !capabilities.session_detail
        || !capabilities.artifact_download
        || !capabilities.capture_status
        || capabilities.session_deletion
    {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 descriptor contradicts required session transfer capabilities"
                .to_string(),
        ));
    }
    validate_v4_calibration_capability(&capabilities.calibration_capture)?;

    validate_uuid_v4(
        "descriptor storage volume_id",
        &descriptor.storage.volume_id,
    )?;
    if descriptor.storage.available_bytes > descriptor.storage.total_bytes {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 descriptor available storage exceeds total storage".to_string(),
        ));
    }
    let _ = descriptor.storage.writable;

    validate_rfc3339_timestamp(
        "descriptor runtime observed_at",
        &descriptor.runtime.observed_at,
    )?;
    if !matches!(
        descriptor.runtime.connection_method.as_str(),
        "wifi_ap" | "wifi_client" | "ethernet_direct" | "ethernet_lan" | "offline"
    ) {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 descriptor has unknown connection_method {}",
            sanitize_remote_str(&descriptor.runtime.connection_method)
        )));
    }
    if !descriptor.runtime.temperature_celsius.is_finite()
        || !(-40.0..=125.0).contains(&descriptor.runtime.temperature_celsius)
    {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 descriptor temperature_celsius is outside -40..125".to_string(),
        ));
    }
    if !descriptor.runtime.network.is_object() || !descriptor.runtime.camera.is_object() {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 descriptor runtime network/camera must be objects".to_string(),
        ));
    }
    for (label, value) in [
        ("live_imu", &descriptor.runtime.live_imu),
        ("camera_focus", &descriptor.runtime.camera_focus),
    ] {
        if !value.is_null() && !value.is_object() {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device API v4 descriptor runtime {label} must be an object or null"
            )));
        }
    }
    Ok(())
}

fn validate_v4_calibration_capability(
    capability: &V4CalibrationCaptureCapability,
) -> Result<(), PiHttpError> {
    if capability.required_video_layout != "split-eyes" {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 calibration capture requires split-eyes layout".to_string(),
        ));
    }
    if capability.enabled {
        if !capability.supported || capability.disabled_reason.is_some() {
            return Err(PiHttpError::InvalidResponse(
                "Device API v4 enabled calibration capture has inconsistent support/reason"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    let reason = capability.disabled_reason.as_deref().ok_or_else(|| {
        PiHttpError::InvalidResponse(
            "Device API v4 disabled calibration capture omitted disabled_reason".to_string(),
        )
    })?;
    if !matches!(
        reason,
        "capture_source_unsupported"
            | "storage_unavailable"
            | "hardware_unavailable"
            | "maintenance_or_capture_busy"
    ) {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 calibration capture has unknown disabled_reason {}",
            sanitize_remote_str(reason)
        )));
    }
    Ok(())
}

fn validate_v4_device_identity(
    label: &str,
    identity: &V4DeviceIdentity,
) -> Result<(), PiHttpError> {
    validate_uuid_v4(&format!("{label} device_id"), &identity.device_id)?;
    let label_bytes = identity.device_label.as_bytes();
    if label_bytes.len() != 12
        || !identity.device_label.starts_with("YLX-")
        || !label_bytes[4..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} device_label does not match YLX-XXXXXXXX"
        )));
    }
    Ok(())
}

fn validate_v4_session_summary(summary: &V4SessionSummary) -> Result<(), PiHttpError> {
    validate_uuid_v7("session list session_id", &summary.session_id)?;
    if summary.producer_outcome != "sealed" {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 session list contains a non-sealed producer outcome".to_string(),
        ));
    }
    validate_uuid_v7("session list take_id", &summary.take_id)?;
    if summary.take_sequence == 0 {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 session list take_sequence must be positive".to_string(),
        ));
    }
    if let Some(continuation_of) = summary.continuation_of.as_deref() {
        validate_uuid_v7("session list continuation_of", continuation_of)?;
    }
    validate_bounded_remote_field("session list display_name", &summary.display_name, 160)?;
    validate_v4_device_identity("session list historical device", &summary.device)?;
    validate_rfc3339_timestamp("session list started_at", &summary.started_at)?;
    validate_rfc3339_timestamp("session list ended_at", &summary.ended_at)?;
    if !summary.duration_seconds.is_finite() || summary.duration_seconds < 0.0 {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 session list duration_seconds must be finite and non-negative"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_v4_gateway_verification(
    wire: V4GatewayVerificationWire,
    contract: V4SessionListContract,
) -> Result<V4GatewayVerification, PiHttpError> {
    if wire.actor != "gateway" {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 verification actor is not gateway".to_string(),
        ));
    }
    validate_bounded_remote_field("verification validator name", &wire.validator.name, 128)?;
    validate_bounded_remote_field(
        "verification validator version",
        &wire.validator.version,
        64,
    )?;
    let validator_build_sha256 = normalize_bare_sha256(
        &wire.validator.build_sha256,
        "verification validator build_sha256",
    )?;
    let raw_manifest_sha256 = wire.manifest_sha256.unwrap_or_default();
    let normalized_manifest_sha256 =
        normalize_bare_sha256(&raw_manifest_sha256, "verification manifest_sha256").ok();
    let manifest_digest_valid = normalized_manifest_sha256.is_some();
    let manifest_sha256 = normalized_manifest_sha256.unwrap_or_else(|| {
        sanitize_remote_str(&raw_manifest_sha256)
            .chars()
            .take(128)
            .collect()
    });
    validate_rfc3339_timestamp("verification verified_at", &wire.verified_at)?;

    let diagnostics = wire
        .diagnostics
        .into_iter()
        .map(|diagnostic| match (contract, diagnostic) {
            (V4SessionListContract::V2, V4GatewayDiagnosticWire::LegacyMessage(message)) => {
                validate_bounded_remote_field("verification diagnostic", &message, 512)?;
                Ok(V4GatewayDiagnostic::LegacyMessage(sanitize_remote_str(
                    &message,
                )))
            }
            (V4SessionListContract::V3, V4GatewayDiagnosticWire::Structured(diagnostic)) => {
                validate_bounded_remote_field(
                    "verification diagnostic code",
                    &diagnostic.code,
                    128,
                )?;
                if !matches!(
                    diagnostic.code.as_str(),
                    "artifact_digest_mismatch"
                        | "artifact_invalid"
                        | "manifest_invalid"
                        | "verification_failed"
                ) {
                    return Err(PiHttpError::InvalidResponse(format!(
                        "Device API v4 verification has unknown diagnostic code {}",
                        sanitize_remote_str(&diagnostic.code)
                    )));
                }
                validate_bounded_remote_field(
                    "verification diagnostic summary",
                    &diagnostic.summary,
                    512,
                )?;
                Ok(V4GatewayDiagnostic::Structured {
                    code: diagnostic.code,
                    summary: sanitize_remote_str(&diagnostic.summary),
                })
            }
            (V4SessionListContract::V2, V4GatewayDiagnosticWire::Structured(_)) => {
                Err(PiHttpError::InvalidResponse(
                    "Device API v4 session-list.v2 verification diagnostics must be strings"
                        .to_string(),
                ))
            }
            (V4SessionListContract::V3, V4GatewayDiagnosticWire::LegacyMessage(_)) => {
                Err(PiHttpError::InvalidResponse(
                    "Device API v4 session-list.v3 verification diagnostics must be closed objects"
                        .to_string(),
                ))
            }
        })
        .collect::<Result<Vec<_>, PiHttpError>>()?;
    let verdict = match wire.verdict.as_str() {
        "usable" => V4VerificationVerdict::Usable,
        "unusable" => {
            if diagnostics.is_empty() {
                return Err(PiHttpError::InvalidResponse(
                    "Device API v4 unusable verification omitted diagnostics".to_string(),
                ));
            }
            V4VerificationVerdict::Unusable
        }
        other => {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device API v4 verification has unknown verdict {}",
                sanitize_remote_str(other)
            )))
        }
    };
    Ok(V4GatewayVerification {
        actor: wire.actor,
        validator_name: sanitize_remote_str(&wire.validator.name),
        validator_version: sanitize_remote_str(&wire.validator.version),
        validator_build_sha256,
        manifest_sha256,
        manifest_digest_valid,
        verified_at: sanitize_remote_str(&wire.verified_at),
        verdict,
        diagnostics,
    })
}

fn validate_v4_session_diagnostic(
    wire: V4SessionDiscoveryDiagnosticWire,
) -> Result<V4SessionDiscoveryDiagnostic, PiHttpError> {
    validate_uuid_v4("session diagnostic quarantine_id", &wire.quarantine_id)?;
    validate_rfc3339_timestamp("session diagnostic observed_at", &wire.observed_at)?;
    validate_bounded_remote_field("session diagnostic message", &wire.message, 512)?;
    let code = match wire.code.as_str() {
        "manifest_unreadable" => V4SessionDiagnosticCode::ManifestUnreadable,
        "unsupported_schema" => V4SessionDiagnosticCode::UnsupportedSchema,
        "manifest_invalid" => V4SessionDiagnosticCode::ManifestInvalid,
        "manifest_not_sealed" => V4SessionDiagnosticCode::ManifestNotSealed,
        other => {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device API v4 session list has unknown quarantine diagnostic code {}",
                sanitize_remote_str(other)
            )))
        }
    };
    Ok(V4SessionDiscoveryDiagnostic {
        quarantine_id: sanitize_remote_str(&wire.quarantine_id),
        code,
        observed_at: sanitize_remote_str(&wire.observed_at),
        message: sanitize_remote_str(&wire.message),
    })
}

fn validate_bounded_remote_field(
    label: &str,
    value: &str,
    max_chars: usize,
) -> Result<(), PiHttpError> {
    if value.trim().is_empty() || value.chars().count() > max_chars {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} is empty or exceeds {max_chars} characters"
        )));
    }
    Ok(())
}

fn validate_v4_session_cursor(cursor: &str, label: &str) -> Result<(), PiHttpError> {
    const MAX_CURSOR_BYTES: usize = 4096;
    if cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} is empty or exceeds {MAX_CURSOR_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn valid_v2_error_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            return true;
        }
        matches!(byte, b'.' | b'_' | b'-')
            && index + 1 < bytes.len()
            && (bytes[index + 1].is_ascii_lowercase() || bytes[index + 1].is_ascii_digit())
    })
}

fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f' | b'A'..=b'F')
        })
}

fn validate_uuid_v4(label: &str, value: &str) -> Result<(), PiHttpError> {
    let bytes = value.as_bytes();
    let canonical_shape = bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        });
    if !canonical_shape {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} is not a canonical lowercase UUIDv4"
        )));
    }
    Ok(())
}

fn validate_uuid_v7(label: &str, value: &str) -> Result<(), PiHttpError> {
    let bytes = value.as_bytes();
    let canonical_shape = bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        });
    if !canonical_shape {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} is not a canonical lowercase UUIDv7"
        )));
    }
    Ok(())
}

fn validate_rfc3339_timestamp(label: &str, value: &str) -> Result<(), PiHttpError> {
    validate_bounded_remote_field(label, value, 128)?;
    let bytes = value.as_bytes();
    let zone_start = if bytes.last() == Some(&b'Z') {
        bytes.len().checked_sub(1)
    } else if bytes.len() >= 6
        && matches!(bytes[bytes.len() - 6], b'+' | b'-')
        && bytes[bytes.len() - 3] == b':'
    {
        Some(bytes.len() - 6)
    } else {
        None
    };
    let fixed_shape = bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && zone_start.is_some_and(|start| {
            start == 19
                || (start > 20
                    && bytes[19] == b'.'
                    && bytes[20..start].iter().all(u8::is_ascii_digit))
        });
    if !fixed_shape {
        return Err(PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} is not a valid RFC 3339 timestamp"
        )));
    }
    value.parse::<jiff::Timestamp>().map_err(|_| {
        PiHttpError::InvalidResponse(format!(
            "Device API v4 {label} is not a valid RFC 3339 timestamp"
        ))
    })?;
    Ok(())
}

fn manifest_sha256_from_headers_or_body(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, PiHttpError> {
    let declared = exactly_one_header_str(headers, "ylx-manifest-sha256")?
        .ok_or_else(|| {
            PiHttpError::InvalidResponse(
                "Device API v4 manifest response omitted YLX-Manifest-SHA256".to_string(),
            )
        })
        .and_then(|value| normalize_bare_sha256(value, "YLX-Manifest-SHA256"))?;
    let etag = exactly_one_header_str(headers, "etag")?.ok_or_else(|| {
        PiHttpError::InvalidResponse(
            "Device API v4 manifest response omitted the required ETag".to_string(),
        )
    })?;
    let etag_digest = etag
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            PiHttpError::InvalidResponse(
                "Device API v4 manifest ETag is not a strong quoted SHA-256 digest".to_string(),
            )
        })
        .and_then(|value| normalize_bare_sha256(value, "ETag"))?;
    if !constant_time_sha256_text_eq(&declared, &etag_digest) {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 manifest digest header and ETag disagree".to_string(),
        ));
    }

    let actual = format!("{:x}", Sha256::digest(body));
    if !constant_time_sha256_text_eq(&declared, &actual) {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 declared manifest digest does not match exact response body".to_string(),
        ));
    }
    Ok(actual)
}

/// Compare two already-normalized 64-byte lowercase SHA-256 texts without
/// data-dependent early exit. Length is public wire-shape information and is
/// checked first; all digest bytes are always visited for valid inputs.
fn constant_time_sha256_text_eq(left: &str, right: &str) -> bool {
    if left.len() != 64 || right.len() != 64 {
        return false;
    }
    let difference = left
        .bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        });
    difference == 0
}

fn normalize_bare_sha256(value: &str, label: &str) -> Result<String, PiHttpError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_string())
    } else {
        Err(PiHttpError::InvalidResponse(format!(
            "{label} is not a lowercase SHA-256 digest"
        )))
    }
}

#[derive(Debug, Clone)]
struct V4ArtifactDescriptor {
    artifact_id: String,
    role: String,
    path: String,
    media_type: String,
    bytes: u64,
    sha256: String,
}

fn v4_manifest_to_session_detail(
    requested_session_id: &str,
    manifest_sha256: &str,
    source_manifest_json: String,
    manifest: serde_json::Value,
    gateway_verification: Option<V4GatewayVerification>,
) -> Result<SessionDetail, PiHttpError> {
    let schema = required_string(&manifest, "/schema")?;
    if schema != "ylx.device-session.v2" && schema != "ylx.device-session.v1" {
        return Err(PiHttpError::InvalidResponse(format!(
            "unsupported Device Session schema {schema}"
        )));
    }
    let session_id = required_string(&manifest, "/session_id")?;
    if session_id != requested_session_id {
        return Err(PiHttpError::InvalidResponse(
            "Device API v4 session detail does not match requested session_id".to_string(),
        ));
    }
    let captured_at = required_string(&manifest, "/time/started_at")?;
    let published_at = optional_string(&manifest, "/sealed_at")
        .unwrap_or(required_string(&manifest, "/time/ended_at")?);
    let duration_seconds = required_f64(&manifest, "/time/duration_seconds")?;
    let mut artifacts = Vec::new();
    collect_v4_artifact_descriptors(&manifest, &mut artifacts)?;
    artifacts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });
    reject_duplicate_v4_artifacts(&artifacts)?;

    let total_bytes = artifacts
        .iter()
        .try_fold(0_u64, |total, artifact| total.checked_add(artifact.bytes))
        .ok_or_else(|| {
            PiHttpError::InvalidResponse("Device Session artifact sizes overflow".to_string())
        })?;
    let video_bytes = artifacts
        .iter()
        .filter(|artifact| artifact.role.starts_with("video."))
        .try_fold(0_u64, |total, artifact| total.checked_add(artifact.bytes))
        .ok_or_else(|| {
            PiHttpError::InvalidResponse("Device Session video artifact sizes overflow".to_string())
        })?;
    let revision = format!("sha256:{manifest_sha256}");
    let files = artifacts
        .into_iter()
        .map(|artifact| SessionFileEntry {
            id: artifact.artifact_id,
            display_path: artifact.path,
            role: artifact.role,
            size_bytes: artifact.bytes,
            sha256: artifact.sha256,
            media_type: artifact.media_type,
        })
        .collect::<Vec<_>>();
    let publication_payload = lab_v4_compat_publication_payload(
        &session_id,
        &revision,
        &captured_at,
        &published_at,
        duration_seconds,
        total_bytes,
        video_bytes,
        manifest_sha256,
        &schema,
        &files,
        gateway_verification.as_ref(),
        &source_manifest_json,
    )?;
    let publication_signature = lab_v4_sign_publication(&publication_payload);
    let publication_public_key = lab_v4_publication_public_key();
    Ok(SessionDetail {
        session_id: SessionId(session_id),
        revision,
        captured_at,
        published_at,
        duration_seconds,
        total_bytes,
        video_bytes,
        file_count: files.len() as u64,
        files,
        publication_payload: String::from_utf8(publication_payload).expect("JSON is UTF-8"),
        publication_signature: hex_encode(&publication_signature),
        publication_public_key: hex_encode(&publication_public_key),
        publication_key_fingerprint: lab_v4_publication_key_fingerprint(),
        gateway_verification,
        publication_origin: PublicationEnvelopeOrigin::ClientDerivedLabCompatibility,
    })
}

#[allow(clippy::too_many_arguments)]
fn lab_v4_compat_publication_payload(
    session_id: &str,
    revision: &str,
    captured_at: &str,
    published_at: &str,
    duration_seconds: f64,
    total_bytes: u64,
    video_bytes: u64,
    source_manifest_sha256: &str,
    source_schema: &str,
    files: &[SessionFileEntry],
    gateway_verification: Option<&V4GatewayVerification>,
    source_manifest_json: &str,
) -> Result<Vec<u8>, PiHttpError> {
    let files = files
        .iter()
        .map(|file| {
            serde_json::json!({
                "id": file.id,
                "display_path": file.display_path,
                "role": file.role,
                "size_bytes": file.size_bytes,
                "sha256": file.sha256,
                "media_type": file.media_type,
            })
        })
        .collect::<Vec<_>>();
    let integrity_ok = gateway_verification.is_some_and(V4GatewayVerification::is_detail_eligible);
    let gateway_verification = gateway_verification.map(|verification| {
        let verdict = match &verification.verdict {
            V4VerificationVerdict::Usable => "usable",
            V4VerificationVerdict::Unusable => "unusable",
        };
        serde_json::json!({
            "actor": verification.actor,
            "validator": {
                "name": verification.validator_name,
                "version": verification.validator_version,
                "build_sha256": verification.validator_build_sha256,
            },
            "manifest_sha256": verification.manifest_sha256,
            "manifest_digest_valid": verification.manifest_digest_valid,
            "verified_at": verification.verified_at,
            "verdict": verdict,
            "diagnostics": verification.diagnostics,
        })
    });
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "source_schema": source_schema,
        "source_manifest_sha256": source_manifest_sha256,
        "source_manifest_json": source_manifest_json,
        "source_profile": "ylx-device-api-v4-lab-http",
        "receipt_origin": "client-derived-lab-compatibility",
        "device_authenticity": "not_asserted",
        "gateway_verification": gateway_verification,
        "session_id": session_id,
        "revision": revision,
        "captured_at": captured_at,
        "published_at": published_at,
        "duration_seconds": duration_seconds,
        "total_bytes": total_bytes,
        "video_bytes": video_bytes,
        "integrity_ok": integrity_ok,
        "files": files,
    }))
    .map_err(|error| PiHttpError::InvalidResponse(format!("serialize lab v4 publication: {error}")))
}

fn collect_v4_artifact_descriptors(
    value: &serde_json::Value,
    out: &mut Vec<V4ArtifactDescriptor>,
) -> Result<(), PiHttpError> {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(artifact) = v4_artifact_descriptor_from_object(object)? {
                out.push(artifact);
                return Ok(());
            }
            for child in object.values() {
                collect_v4_artifact_descriptors(child, out)?;
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_v4_artifact_descriptors(child, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn v4_artifact_descriptor_from_object(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<V4ArtifactDescriptor>, PiHttpError> {
    let has_descriptor_keys = [
        "artifact_id",
        "role",
        "path",
        "media_type",
        "bytes",
        "sha256",
    ]
    .iter()
    .all(|key| object.contains_key(*key));
    if !has_descriptor_keys {
        return Ok(None);
    }
    let artifact_id = object_string(object, "artifact_id")?;
    let role = object_string(object, "role")?;
    let path = object_string(object, "path")?;
    let media_type = object_string(object, "media_type")?;
    let bytes = object_u64(object, "bytes")?;
    let sha256 = object_string(object, "sha256")?.to_ascii_lowercase();
    if artifact_id.is_empty()
        || role.is_empty()
        || path.is_empty()
        || media_type.is_empty()
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PiHttpError::InvalidResponse(
            "Device Session artifact descriptor is malformed".to_string(),
        ));
    }
    Ok(Some(V4ArtifactDescriptor {
        artifact_id,
        role,
        path,
        media_type,
        bytes,
        sha256,
    }))
}

fn reject_duplicate_v4_artifacts(artifacts: &[V4ArtifactDescriptor]) -> Result<(), PiHttpError> {
    let mut ids = std::collections::HashSet::with_capacity(artifacts.len());
    let mut paths = std::collections::HashSet::with_capacity(artifacts.len());
    for artifact in artifacts {
        if !ids.insert(artifact.artifact_id.as_str()) {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device Session contains duplicate artifact_id {}",
                artifact.artifact_id
            )));
        }
        if !paths.insert(artifact.path.as_str()) {
            return Err(PiHttpError::InvalidResponse(format!(
                "Device Session contains duplicate artifact path {}",
                artifact.path
            )));
        }
    }
    Ok(())
}

fn required_string(value: &serde_json::Value, pointer: &str) -> Result<String, PiHttpError> {
    optional_string(value, pointer).ok_or_else(|| {
        PiHttpError::InvalidResponse(format!("Device Session manifest missing string {pointer}"))
    })
}

fn optional_string(value: &serde_json::Value, pointer: &str) -> Option<String> {
    value.pointer(pointer)?.as_str().map(ToString::to_string)
}

fn required_f64(value: &serde_json::Value, pointer: &str) -> Result<f64, PiHttpError> {
    let number = value.pointer(pointer).and_then(serde_json::Value::as_f64);
    match number {
        Some(number) if number.is_finite() && number >= 0.0 => Ok(number),
        _ => Err(PiHttpError::InvalidResponse(format!(
            "Device Session manifest missing non-negative number {pointer}"
        ))),
    }
}

fn object_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, PiHttpError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            PiHttpError::InvalidResponse(format!(
                "Device Session artifact descriptor missing string {key}"
            ))
        })
}

fn object_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, PiHttpError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            PiHttpError::InvalidResponse(format!(
                "Device Session artifact descriptor missing integer {key}"
            ))
        })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn exactly_one_header_str<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, PiHttpError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(PiHttpError::InvalidResponse(format!(
            "response contains duplicate {name} headers"
        )));
    }
    value.to_str().map(Some).map_err(|_| {
        PiHttpError::InvalidResponse(format!("response contains a non-text {name} header"))
    })
}

fn parse_ascii_u64(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Parses `Content-Range: bytes {start}-{end}/{total_size}`, rejecting
/// anything else (including the `bytes */total` "unsatisfiable" form,
/// which the Pi never sends on a `206` -- it maps `range_not_satisfiable`
/// to a `416 problem+json` instead, per `range_response.py`'s own module
/// docs) as [`PiHttpError::InvalidResponse`] rather than silently
/// accepting a malformed value.
fn parse_content_range(value: &str) -> Result<ContentRange, PiHttpError> {
    let malformed =
        || PiHttpError::InvalidResponse(format!("malformed Content-Range header: {value:?}"));
    let rest = value.strip_prefix("bytes ").ok_or_else(malformed)?;
    let (range_part, total_part) = rest.split_once('/').ok_or_else(malformed)?;
    let (start_str, end_str) = range_part.split_once('-').ok_or_else(malformed)?;
    let start = parse_ascii_u64(start_str).ok_or_else(malformed)?;
    let end = parse_ascii_u64(end_str).ok_or_else(malformed)?;
    let total_size = parse_ascii_u64(total_part).ok_or_else(malformed)?;
    if start > end || end >= total_size {
        return Err(malformed());
    }
    Ok(ContentRange {
        start,
        end,
        total_size,
    })
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    //! Unit tests against a real `tiny_http` fake server on loopback,
    //! reusing the exact pattern `object_store_s3.rs`'s tests established:
    //! a real socket, real HTTP/1.1 wire bytes, a scripted
    //! response per request. Deliberately plain `http://`, not `https://`
    //! -- `PinnedTlsConnector` no-ops for a non-TLS scheme (see
    //! `new_insecure_for_test`'s doc comment), so these tests exercise this
    //! module's request-building/response-parsing/error-mapping logic
    //! without needing a real TLS handshake. The **real** TLS-pinning path
    //! (and a real cross-language server) is proven by
    //! `tests/pi_http_integration.rs` instead.

    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    use tiny_http::{Header, Response as TinyResponse, Server, StatusCode};

    use super::*;

    #[test]
    fn critical_response_headers_require_exactly_one_value() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::ETAG,
            http::HeaderValue::from_static("\"revision-a\""),
        );
        headers.append(
            http::header::ETAG,
            http::HeaderValue::from_static("\"revision-b\""),
        );

        assert!(matches!(
            exactly_one_header_str(&headers, "etag"),
            Err(PiHttpError::InvalidResponse(_))
        ));
    }

    #[test]
    fn wire_decimal_and_content_range_parsing_are_strict() {
        assert_eq!(parse_ascii_u64("0"), Some(0));
        assert_eq!(parse_ascii_u64("0007"), Some(7));
        assert_eq!(parse_ascii_u64("+7"), None);
        assert_eq!(parse_ascii_u64(" 7"), None);
        assert!(parse_content_range("bytes 0-0/1").is_ok());
        assert!(parse_content_range("bytes +0-0/1").is_err());
        assert!(parse_content_range("bytes 0-1/1").is_err());
    }

    #[test]
    fn pairing_sas_matches_the_frozen_cross_language_vector() {
        let transcript = SasTranscript {
            tls_cert_fingerprint: format!("sha256:{}", "1".repeat(64)),
            publication_key_fingerprint: format!("sha256:{}", "2".repeat(64)),
            client_nonce: "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1".to_string(),
            pi_nonce: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string(),
            device_name: "pi-lab-01".to_string(),
            protocol_version: "1.0".to_string(),
            request_digest: format!("sha256:{}", "3".repeat(64)),
        };
        assert_eq!(derive_pairing_sas(&transcript).unwrap(), "617768");
    }

    struct CapturedRequest {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    type ScriptedResponse = (u16, Vec<(&'static str, String)>, Vec<u8>);

    fn spawn_fake_server(
        scripted_responses: Vec<ScriptedResponse>,
    ) -> (
        String,
        mpsc::Receiver<CapturedRequest>,
        std::thread::JoinHandle<()>,
    ) {
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let addr = server.server_addr();
        let port = addr.to_ip().expect("loopback server has an IP addr").port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");

        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            for (status, headers, body) in scripted_responses {
                let mut request = match server.recv_timeout(Duration::from_secs(5)) {
                    Ok(Some(r)) => r,
                    _ => break,
                };
                let mut captured_body = Vec::new();
                request
                    .as_reader()
                    .read_to_end(&mut captured_body)
                    .expect("read request body");
                let captured = CapturedRequest {
                    method: request.method().as_str().to_string(),
                    url: request.url().to_string(),
                    headers: request
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.as_str().as_str().to_string(),
                                h.value.as_str().to_string(),
                            )
                        })
                        .collect(),
                    body: captured_body,
                };
                let _ = tx.send(captured);

                let mut response = TinyResponse::from_data(body)
                    .with_status_code(StatusCode(status))
                    // Real file responses carry Content-Length regardless
                    // of media size. tiny_http otherwise switches to
                    // chunked encoding above 32 KiB and removes that header.
                    .with_chunked_threshold(usize::MAX);
                for (name, value) in headers {
                    if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                        response.add_header(header);
                    }
                }
                let _ = request.respond(response);
            }
        });

        (base_url, rx, handle)
    }

    fn spawn_delayed_fake_server(
        delay: Duration,
        response_body: Vec<u8>,
    ) -> (
        String,
        mpsc::Receiver<CapturedRequest>,
        std::thread::JoinHandle<()>,
    ) {
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let addr = server.server_addr();
        let port = addr.to_ip().expect("loopback server has an IP addr").port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut request = server
                .recv_timeout(Duration::from_secs(5))
                .expect("receive delayed request")
                .expect("delayed request");
            let mut captured_body = Vec::new();
            request
                .as_reader()
                .read_to_end(&mut captured_body)
                .expect("read delayed request body");
            let _ = tx.send(CapturedRequest {
                method: request.method().as_str().to_string(),
                url: request.url().to_string(),
                headers: request
                    .headers()
                    .iter()
                    .map(|header| {
                        (
                            header.field.as_str().as_str().to_string(),
                            header.value.as_str().to_string(),
                        )
                    })
                    .collect(),
                body: captured_body,
            });
            std::thread::sleep(delay);
            let response = TinyResponse::from_data(response_body)
                .with_status_code(StatusCode(200))
                .with_chunked_threshold(usize::MAX);
            let _ = request.respond(response);
        });
        (base_url, rx, handle)
    }

    fn test_client(base_url: String) -> PiHttpClient {
        PiHttpClient::new_insecure_for_test(base_url, Duration::from_secs(5))
    }

    fn loopback_port_from_base_url(base_url: &str) -> u16 {
        base_url
            .strip_prefix("http://127.0.0.1:")
            .and_then(|rest| rest.strip_suffix("/api/v1"))
            .expect("test fake server base URL shape")
            .parse()
            .expect("test fake server port")
    }

    fn lab_v4_device_json() -> Vec<u8> {
        serde_json::json!({
            "schema": "ylx.device.v4",
            "device": {
                "device_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_label": "YLX-30D5872D"
            },
            "hardware_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "api_version": "4.0",
            "build": {
                "package_version": "0.10.0-dev.2",
                "commit": "2db57ae68e04197397b8ac84f4d71548aa2fcb36",
                "build_id": "build-20260821.1"
            },
            "security_profile": "lab",
            "capabilities": {
                "capture": true,
                "preview": true,
                "range_download": true,
                "network_mutation": true,
                "session_list": true,
                "session_detail": true,
                "artifact_download": true,
                "capture_status": true,
                "session_deletion": false,
                "calibration_capture": {
                    "supported": true,
                    "enabled": false,
                    "disabled_reason": "hardware_unavailable",
                    "required_video_layout": "split-eyes"
                }
            },
            "storage": {
                "volume_id": "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
                "total_bytes": 128000000000_u64,
                "available_bytes": 96000000000_u64,
                "writable": true
            },
            "runtime": {
                "observed_at": "2026-08-21T10:24:15+08:00",
                "connection_method": "ethernet_lan",
                "temperature_celsius": 53.5,
                "network": {
                    "ap": {
                        "state": "active",
                        "interface": "wlan0",
                        "addresses": ["10.42.0.1/24"],
                        "peer_or_ssid": "YLX-30D5872D"
                    },
                    "wifi_client": {
                        "state": "disconnected",
                        "interface": "wlan1",
                        "addresses": [],
                        "peer_or_ssid": null
                    },
                    "wired": {
                        "state": "connected",
                        "interface": "eth0",
                        "addresses": ["192.0.2.24/24"],
                        "peer_or_ssid": null
                    },
                    "default_route": "wired"
                },
                "live_imu": null,
                "camera": {
                    "schema": "ylx.camera-connection.v1",
                    "state": "disconnected"
                },
                "camera_focus": null
            }
        })
        .to_string()
        .into_bytes()
    }

    fn lab_v4_capture_status_json(
        device_state: &str,
        active_recording: serde_json::Value,
    ) -> Vec<u8> {
        serde_json::json!({
            "schema": "ylx.capture-status.v4",
            "authority_epoch": "4fa85f64-5717-4562-b3fc-2c963f66afa6",
            "source_revision": 7,
            "snapshot": {
                "schema": "ylx.capture-snapshot-event.v4",
                "device_state": device_state,
                "active_recording": active_recording,
                "retained_unsuccessful": null,
                "runtime": {
                    "observed_at": "2026-08-21T10:24:15+08:00",
                    "connection_method": "ethernet_lan",
                    "temperature_celsius": 53.5,
                    "network": {},
                    "live_imu": null,
                    "camera": {
                        "schema": "ylx.camera-connection.v1",
                        "state": "connected"
                    },
                    "camera_focus": null
                }
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn lab_v4_http_client_reads_device_descriptor_without_tls_or_bearer() {
        let (base_url, rx, handle) = spawn_fake_server(vec![
            (200, vec![], lab_v4_device_json()),
            (
                200,
                vec![],
                lab_v4_capture_status_json("idle", serde_json::Value::Null),
            ),
        ]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let device = client.get_device("lab-token-is-local").expect("v4 device");

        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "/api/v4/device");
        assert!(
            request
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")),
            "lab v4 device descriptor must not use the old bearer-only path"
        );
        assert_eq!(device.capture_activity, CaptureActivityState::Idle);
        assert_eq!(device.media_admission, "lab_v4");
        assert_eq!(
            device.publication_key_fingerprint,
            lab_v4_publication_key_fingerprint()
        );
        let status_request = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("status request");
        assert_eq!(status_request.method, "GET");
        assert_eq!(status_request.url, "/api/v4/capture/status");
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_catalog_has_a_cold_start_timeout_budget() {
        let page = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "e".repeat(64)),
            "items": [],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_delayed_fake_server(Duration::from_millis(150), page);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_millis(50),
        )
        .expect("lab v4 client");

        let result = client.list_sessions("lab-token-is-local", None, Some(50));

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("session catalog request")
                .url,
            "/api/v4/sessions?limit=50"
        );
        assert!(
            result.is_ok(),
            "cold session catalog should outlive control timeout: {result:?}"
        );
        handle.join().expect("fake server exits");
    }

    #[test]
    #[ignore = "requires a live Lab Device API v4 device; set YLX_LIVE_PI_HOST and run manually"]
    fn live_lab_v4_manual_probe_and_session_catalog_succeed() {
        let host = std::env::var("YLX_LIVE_PI_HOST").expect("YLX_LIVE_PI_HOST is required");
        let port = std::env::var("YLX_LIVE_PI_PORT")
            .ok()
            .map(|value| {
                value
                    .parse::<u16>()
                    .expect("YLX_LIVE_PI_PORT must be a port")
            })
            .unwrap_or(8080);
        let probe = probe_lab_v4_device(&host, port, Duration::from_secs(6))
            .expect("live Lab v4 descriptor probe");
        let client = PiHttpClient::new_lab_v4_http(
            host,
            port,
            probe.synthetic_identity_pin,
            Duration::from_secs(6),
        )
        .expect("live Lab v4 client");

        let descriptor = client
            .negotiate_device("lab-token-is-local")
            .expect("live Lab v4 negotiation");
        let sessions = client
            .list_sessions("lab-token-is-local", None, Some(50))
            .expect("live Lab v4 session catalog");

        assert_eq!(descriptor.profile, DeviceApiProfile::LabHttpV4);
        assert!(descriptor.capabilities.network_mutation.supported);
        assert!(!probe.device_id.is_empty());
        assert_eq!(
            sessions.catalog_authority,
            CatalogRevisionAuthority::DeviceStable
        );
    }

    #[test]
    fn lab_v4_connection_negotiation_is_one_descriptor_only_request() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], lab_v4_device_json())]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let device = client
            .negotiate_device("lab-token-is-local")
            .expect("descriptor negotiation");

        assert_eq!(device.profile, DeviceApiProfile::LabHttpV4);
        assert_eq!(device.capture_activity, CaptureActivityState::Unknown);
        assert!(device.capture_status.is_none());
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("descriptor request")
                .url,
            "/api/v4/device"
        );
        assert!(rx.try_recv().is_err(), "negotiation must not poll status");
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_device_uses_authoritative_capture_status_and_explicit_profile_capabilities() {
        let active_recording = serde_json::json!({
            "generation_id": "550e8400-e29b-41d4-a716-446655440001",
            "recording_state": {
                "state": "recording",
                "session_id": "01989f6c-2c00-7a1b-8c2d-3e4f50617283"
            }
        });
        let (base_url, rx, handle) = spawn_fake_server(vec![
            (200, vec![], lab_v4_device_json()),
            (
                200,
                vec![],
                lab_v4_capture_status_json("recording", active_recording),
            ),
        ]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let device = client.get_device("lab-token-is-local").expect("v4 device");

        assert_eq!(device.capture_activity, CaptureActivityState::Recording);
        assert_eq!(device.profile, DeviceApiProfile::LabHttpV4);
        assert!(device.capabilities.session_list.supported);
        assert!(device.capabilities.session_detail.supported);
        assert!(device.capabilities.artifact_download.supported);
        assert!(device.capabilities.capture_status.supported);
        assert!(!device.capabilities.session_deletion.supported);
        assert_eq!(
            device.capabilities.session_deletion.source,
            CapabilitySource::ProfileContract
        );
        let status = device.capture_status.expect("authoritative v4 status");
        assert_eq!(status.source_revision, 7);
        assert_eq!(status.device_state, V4CaptureDeviceState::Recording);
        assert!(status.active_recording);

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("device request")
                .url,
            "/api/v4/device"
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("capture status request")
                .url,
            "/api/v4/capture/status"
        );
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_heartbeat_is_one_capture_status_request_with_activity_evidence() {
        let active_recording = serde_json::json!({
            "generation_id": "550e8400-e29b-41d4-a716-446655440001",
            "recording_state": {
                "state": "recording",
                "session_id": "01989f6c-2c00-7a1b-8c2d-3e4f50617283"
            }
        });
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![],
            lab_v4_capture_status_json("recording", active_recording),
        )]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let heartbeat = client
            .heartbeat("lab-token-is-local")
            .expect("capture status is the Lab v4 heartbeat");

        assert_eq!(
            heartbeat.capture_activity,
            Some(CaptureActivityState::Recording)
        );
        let request = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("periodic poll request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "/api/v4/capture/status");
        assert!(rx.try_recv().is_err(), "one tick must issue one request");
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_device_rejects_a_missing_explicit_session_capability() {
        let mut descriptor: serde_json::Value =
            serde_json::from_slice(&lab_v4_device_json()).expect("device fixture JSON");
        descriptor["capabilities"]
            .as_object_mut()
            .expect("capabilities object")
            .remove("session_list");
        let (base_url, _rx, handle) = spawn_fake_server(vec![(
            200,
            vec![],
            serde_json::to_vec(&descriptor).expect("descriptor bytes"),
        )]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let error = client
            .get_device("lab-token-is-local")
            .expect_err("missing capability must fail closed before capture status");
        assert!(
            matches!(error, PiHttpError::Decode(ref detail) if detail.contains("session_list")),
            "unexpected error: {error}"
        );
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_pairing_is_local_and_does_not_need_the_old_pairing_endpoint() {
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            9,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_millis(10),
        )
        .expect("lab v4 client");

        let created = client
            .create_pairing_request("YLX Transfer PC", "nonce-local-only")
            .expect("local lab pairing create");
        let status = client
            .get_pairing_status(&created.attempt_id, &created.poll_secret)
            .expect("local lab pairing status");

        assert_eq!(created.phase, PairingPhase::Pending);
        assert_eq!(status.phase, PairingPhase::Allowed);
        assert!(status
            .connection_token
            .as_deref()
            .is_some_and(|token| token.starts_with("lab-v4-")));
        assert_eq!(
            status
                .sas_transcript
                .as_ref()
                .expect("lab status transcript")
                .publication_key_fingerprint,
            lab_v4_publication_key_fingerprint()
        );
    }

    fn lab_v4_verification_json(
        manifest_sha256: &str,
        verdict: &str,
        diagnostics: Vec<(&str, &str)>,
    ) -> serde_json::Value {
        let diagnostics = diagnostics
            .into_iter()
            .map(|(code, summary)| serde_json::json!({ "code": code, "summary": summary }))
            .collect::<Vec<_>>();
        serde_json::json!({
            "actor": "gateway",
            "validator": {
                "name": "rp-ylx-device-session-v1",
                "version": "1",
                "build_sha256": "f".repeat(64)
            },
            "manifest_sha256": manifest_sha256,
            "verified_at": "2026-08-08T10:31:32.800+08:00",
            "verdict": verdict,
            "diagnostics": diagnostics
        })
    }

    fn parsed_lab_v4_verification(
        manifest_sha256: &str,
        verdict: &str,
        diagnostics: Vec<(&str, &str)>,
    ) -> V4GatewayVerification {
        let wire = serde_json::from_value(lab_v4_verification_json(
            manifest_sha256,
            verdict,
            diagnostics,
        ))
        .expect("verification fixture matches wire DTO");
        validate_v4_gateway_verification(wire, V4SessionListContract::V3)
            .expect("verification fixture is valid")
    }

    fn lab_v4_session_summary_json(
        session_id: &str,
        verification: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "session_id": session_id,
            "producer_outcome": "sealed",
            "take_id": "01989f6c-f000-7c3d-ae4f-5061728394a5",
            "take_sequence": 1,
            "continuation_of": null,
            "display_name": format!("session-{session_id}"),
            "device": {
                "device_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_label": "YLX-30D5872D"
            },
            "started_at": "2026-08-08T10:31:00+08:00",
            "ended_at": "2026-08-08T10:31:30+08:00",
            "duration_seconds": 30,
            "total_bytes": 255,
            "verification": verification
        })
    }

    #[test]
    fn lab_v4_session_list_preserves_verdicts_and_quarantine_diagnostics() {
        let usable_digest = "a".repeat(64);
        let unusable_digest = "b".repeat(64);
        let mut missing_digest_verification =
            lab_v4_verification_json(&"c".repeat(64), "usable", vec![]);
        missing_digest_verification
            .as_object_mut()
            .expect("verification fixture is an object")
            .remove("manifest_sha256");
        let mut page = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "e".repeat(64)),
            "items": [
                lab_v4_session_summary_json(
                    "01989f6c-2c00-7a1b-8c2d-3e4f50617281",
                    lab_v4_verification_json(&usable_digest, "usable", vec![]),
                ),
                lab_v4_session_summary_json(
                    "01989f6c-2c00-7a1b-8c2d-3e4f50617282",
                    lab_v4_verification_json(
                        &unusable_digest,
                        "unusable",
                        vec![("artifact_digest_mismatch", "artifact digest mismatch")],
                    ),
                ),
                lab_v4_session_summary_json(
                    "01989f6c-2c00-7a1b-8c2d-3e4f50617284",
                    serde_json::Value::Null,
                ),
                lab_v4_session_summary_json(
                    "01989f6c-2c00-7a1b-8c2d-3e4f50617285",
                    lab_v4_verification_json("not-a-sha256", "usable", vec![]),
                ),
                lab_v4_session_summary_json(
                    "01989f6c-2c00-7a1b-8c2d-3e4f50617286",
                    missing_digest_verification,
                )
            ],
            "diagnostics": [{
                "quarantine_id": "550e8400-e29b-41d4-a716-446655440002",
                "code": "manifest_invalid",
                "observed_at": "2026-08-08T10:31:32.800+08:00",
                "message": "manifest does not satisfy the closed schema"
            }],
            "next_cursor": null
        });
        for (index, item) in page["items"]
            .as_array_mut()
            .expect("session list items")
            .iter_mut()
            .enumerate()
        {
            item["started_at"] =
                serde_json::json!(format!("2026-08-08T10:31:{:02}+08:00", 5 - index));
        }
        let page = page.to_string().into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], page)]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client
            .list_sessions("lab-token-is-local", None, Some(50))
            .expect("v4 session page");

        assert_eq!(result.sessions.len(), 5);
        assert_eq!(
            result.catalog_revision.as_deref(),
            Some(format!("sha256:{}", "e".repeat(64)).as_str())
        );
        assert_eq!(
            result.sessions[0]
                .gateway_verification
                .as_ref()
                .expect("usable verification")
                .verdict,
            V4VerificationVerdict::Usable
        );
        assert_eq!(
            result.sessions[1]
                .gateway_verification
                .as_ref()
                .expect("unusable verification")
                .diagnostics,
            vec![V4GatewayDiagnostic::Structured {
                code: "artifact_digest_mismatch".to_string(),
                summary: "artifact digest mismatch".to_string(),
            }]
        );
        assert!(result.sessions[2].gateway_verification.is_none());
        assert!(result.sessions[2].revision.is_empty());
        assert_eq!(
            result.sessions[3]
                .gateway_verification
                .as_ref()
                .expect("invalid digest verification remains visible")
                .manifest_sha256,
            "not-a-sha256"
        );
        assert!(
            !result.sessions[3]
                .gateway_verification
                .as_ref()
                .expect("invalid digest verification remains visible")
                .manifest_digest_valid
        );
        assert!(result.sessions[3].revision.is_empty());
        assert!(
            !result.sessions[4]
                .gateway_verification
                .as_ref()
                .expect("missing digest verification remains visible")
                .manifest_digest_valid
        );
        assert!(result.sessions[4].revision.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(
            result.diagnostics[0].code,
            V4SessionDiagnosticCode::ManifestInvalid
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("list request")
                .url,
            "/api/v4/sessions?limit=50"
        );
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_rejects_unknown_verification_verdict() {
        let page = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "e".repeat(64)),
            "items": [lab_v4_session_summary_json(
                "01989f6c-2c00-7a1b-8c2d-3e4f50617283",
                lab_v4_verification_json(
                    &"c".repeat(64),
                    "future-verdict",
                    vec![("verification_failed", "new gateway state")],
                ),
            )],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], page)]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client.list_sessions("lab-token-is-local", None, Some(50));

        let _ = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert!(matches!(
            result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("unknown verdict future-verdict")
        ));
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_rejects_unknown_verification_diagnostic_code() {
        let wire = serde_json::from_value(lab_v4_verification_json(
            &"c".repeat(64),
            "unusable",
            vec![("future_diagnostic", "new gateway diagnostic")],
        ))
        .expect("fixture decodes to the transport DTO");

        let result = validate_v4_gateway_verification(wire, V4SessionListContract::V3);

        assert!(matches!(
            result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("unknown diagnostic code future_diagnostic")
        ));
    }

    #[test]
    fn lab_v4_session_list_rejects_unknown_or_malformed_quarantine_diagnostics() {
        let unknown = validate_v4_session_diagnostic(V4SessionDiscoveryDiagnosticWire {
            quarantine_id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
            code: "future_quarantine_reason".to_string(),
            observed_at: "2026-08-08T10:31:32.800+08:00".to_string(),
            message: "future reason".to_string(),
        });
        let wrong_uuid_version = validate_v4_session_diagnostic(V4SessionDiscoveryDiagnosticWire {
            quarantine_id: "550e8400-e29b-71d4-a716-446655440002".to_string(),
            code: "manifest_invalid".to_string(),
            observed_at: "2026-08-08T10:31:32.800+08:00".to_string(),
            message: "invalid manifest".to_string(),
        });
        let malformed_time = validate_v4_session_diagnostic(V4SessionDiscoveryDiagnosticWire {
            quarantine_id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
            code: "manifest_invalid".to_string(),
            observed_at: "yesterday".to_string(),
            message: "invalid manifest".to_string(),
        });

        assert!(matches!(
            unknown,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("unknown quarantine diagnostic code")
        ));
        assert!(matches!(
            wrong_uuid_version,
            Err(PiHttpError::InvalidResponse(message)) if message.contains("UUIDv4")
        ));
        assert!(matches!(
            malformed_time,
            Err(PiHttpError::InvalidResponse(message)) if message.contains("RFC 3339")
        ));
    }

    #[test]
    fn lab_v4_catalog_changed_v2_error_is_not_downgraded_to_unexpected_status() {
        let catalog_revision = format!("sha256:{}", "d".repeat(64));
        let body = serde_json::json!({
            "schema": "ylx.api-error.v2",
            "error": {
                "code": "catalog_changed",
                "message": "The cursor belongs to an older catalog revision.",
                "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "retryable": true,
                "details": {
                    "catalog_revision": catalog_revision,
                },
            },
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            409,
            vec![("Content-Type", "application/problem+json".to_string())],
            body,
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let error = client
            .list_sessions("lab-token-is-local", Some("opaque-cursor"), Some(50))
            .expect_err("a stale cursor must return a typed catalog-changed error");

        match error {
            PiHttpError::CatalogChanged {
                status,
                request_id,
                catalog_revision: observed_revision,
                detail,
            } => {
                assert_eq!(status, 409);
                assert_eq!(request_id, "f47ac10b-58cc-4372-a567-0e02b2c3d479");
                assert_eq!(observed_revision, catalog_revision);
                assert_eq!(detail, "The cursor belongs to an older catalog revision.");
            }
            other => panic!(
                "a compliant ylx.api-error.v2 catalog_changed envelope was not typed: {other:?}"
            ),
        }
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("catalog request")
                .url,
            "/api/v4/sessions?cursor=opaque-cursor&limit=50"
        );
        handle.join().expect("fake server exits");
    }

    #[test]
    fn catalog_changed_v2_error_fails_closed_on_schema_or_revision_drift() {
        let valid = serde_json::json!({
            "schema": "ylx.api-error.v2",
            "error": {
                "code": "catalog_changed",
                "message": "The cursor belongs to an older catalog revision.",
                "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "retryable": true,
                "details": {
                    "catalog_revision": format!("sha256:{}", "d".repeat(64)),
                },
            },
        });
        let mut wrong_schema = valid.clone();
        wrong_schema["schema"] = serde_json::json!("ylx.api-error.v1");
        let mut unknown_outer = valid.clone();
        unknown_outer["debug"] = serde_json::json!(true);
        let mut unknown_error_field = valid.clone();
        unknown_error_field["error"]["debug_trace"] =
            serde_json::json!("must not cross the boundary");
        let mut missing_details = valid.clone();
        missing_details["error"]
            .as_object_mut()
            .expect("error object")
            .remove("details");
        let mut unknown_detail = valid.clone();
        unknown_detail["error"]["details"]["next_cursor"] = serde_json::json!("untrusted");
        let mut empty_revision = valid.clone();
        empty_revision["error"]["details"]["catalog_revision"] = serde_json::json!("");
        let mut bare_revision = valid.clone();
        bare_revision["error"]["details"]["catalog_revision"] = serde_json::json!("d".repeat(64));
        let mut uppercase_revision = valid.clone();
        uppercase_revision["error"]["details"]["catalog_revision"] =
            serde_json::json!(format!("sha256:{}", "D".repeat(64)));
        let mut not_retryable = valid.clone();
        not_retryable["error"]["retryable"] = serde_json::json!(false);

        for (label, body) in [
            ("wrong schema", wrong_schema),
            ("unknown outer field", unknown_outer),
            ("unknown error field", unknown_error_field),
            ("missing details", missing_details),
            ("unknown detail", unknown_detail),
            ("empty revision", empty_revision),
            ("bare revision", bare_revision),
            ("uppercase revision", uppercase_revision),
            ("retryable false", not_retryable),
        ] {
            let error = PiHttpClient::map_error(RawResponse {
                status: 409,
                headers: HeaderMap::new(),
                body: body.to_string().into_bytes(),
            });
            assert!(
                matches!(error, PiHttpError::UnexpectedStatus { status: 409, .. }),
                "{label} must fail closed, got {error:?}"
            );
        }

        let wrong_status = PiHttpClient::map_error(RawResponse {
            status: 500,
            headers: HeaderMap::new(),
            body: valid.to_string().into_bytes(),
        });
        assert!(matches!(
            wrong_status,
            PiHttpError::UnexpectedStatus { status: 500, .. }
        ));

        let mut wrong_code = valid;
        wrong_code["error"]["code"] = serde_json::json!("catalog.changed");
        let wrong_code = PiHttpClient::map_error(RawResponse {
            status: 409,
            headers: HeaderMap::new(),
            body: wrong_code.to_string().into_bytes(),
        });
        assert!(
            matches!(wrong_code, PiHttpError::Api(_)),
            "a different valid v2 code must stay a generic API error: {wrong_code:?}"
        );
    }

    #[test]
    fn lab_v4_session_list_returns_one_stable_catalog_revision_across_pages() {
        let catalog_revision = format!("sha256:{}", "e".repeat(64));
        let first_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617281";
        let second_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617280";
        let first = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": catalog_revision,
            "items": [lab_v4_session_summary_json(
                first_id,
                lab_v4_verification_json(&"a".repeat(64), "usable", vec![]),
            )],
            "diagnostics": [],
            "next_cursor": first_id
        })
        .to_string()
        .into_bytes();
        let second = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": catalog_revision,
            "items": [lab_v4_session_summary_json(
                second_id,
                lab_v4_verification_json(&"b".repeat(64), "usable", vec![]),
            )],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) =
            spawn_fake_server(vec![(200, vec![], first), (200, vec![], second)]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let first_page = client
            .list_sessions("lab-token-is-local", None, Some(1))
            .expect("first page");
        let second_page = client
            .list_sessions(
                "lab-token-is-local",
                first_page.next_cursor.as_deref(),
                Some(1),
            )
            .expect("second page");

        assert_eq!(
            first_page.catalog_revision.as_deref(),
            Some(catalog_revision.as_str())
        );
        assert_eq!(
            second_page.catalog_revision.as_deref(),
            Some(catalog_revision.as_str())
        );
        assert_eq!(first_page.sessions[0].session_id.as_str(), first_id);
        assert_eq!(second_page.sessions[0].session_id.as_str(), second_id);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("first request")
                .url,
            "/api/v4/sessions?limit=1"
        );
        assert!(rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second request")
            .url
            .contains(&format!("cursor={first_id}")));
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_rejects_missing_or_malformed_catalog_revision() {
        let missing = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "items": [],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let malformed = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": "page-local-revision",
            "items": [],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) =
            spawn_fake_server(vec![(200, vec![], missing), (200, vec![], malformed)]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let missing_result = client.list_sessions("lab-token-is-local", None, Some(50));
        let malformed_result = client.list_sessions("lab-token-is-local", None, Some(50));

        assert!(matches!(
            missing_result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("omitted catalog_revision")
        ));
        assert!(matches!(
            malformed_result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("catalog_revision must use sha256")
        ));
        assert_eq!(rx.iter().count(), 2);
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_v2_is_safe_first_page_only_compatibility() {
        let first_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617281";
        let page = serde_json::json!({
            "schema": "ylx.session-list.v2",
            "items": [lab_v4_session_summary_json(
                first_id,
                lab_v4_verification_json(&"a".repeat(64), "usable", vec![]),
            )],
            "diagnostics": [],
            "next_cursor": "device-offered-second-page"
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], page)]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client
            .list_sessions("lab-token-is-local", None, Some(50))
            .expect("v2 first page remains readable");

        assert_eq!(result.sessions[0].session_id.as_str(), first_id);
        assert_eq!(result.catalog_revision, None);
        assert_eq!(
            result.catalog_authority,
            CatalogRevisionAuthority::LocalFirstPageCompatibility
        );
        assert!(!result.pagination_supported);
        assert!(result.next_cursor.is_none());
        assert!(result.pagination_unavailable_reason.is_some());
        let _ = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_v2_preserves_unusable_string_diagnostics() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617281";
        let mut verification = lab_v4_verification_json(&"a".repeat(64), "unusable", Vec::new());
        verification["diagnostics"] = serde_json::json!(["artifact digest mismatch"]);
        let page = serde_json::json!({
            "schema": "ylx.session-list.v2",
            "items": [lab_v4_session_summary_json(session_id, verification)],
            "diagnostics": [],
            "next_cursor": "v2-cursor-must-not-be-exposed"
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], page)]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client
            .list_sessions("lab-token-is-local", None, Some(50))
            .expect("a frozen v2 unusable verification must remain readable");

        let verification = result.sessions[0]
            .gateway_verification
            .as_ref()
            .expect("v2 verification remains visible");
        assert_eq!(verification.verdict, V4VerificationVerdict::Unusable);
        assert_eq!(
            verification.diagnostics,
            vec![V4GatewayDiagnostic::LegacyMessage(
                "artifact digest mismatch".to_string()
            )]
        );
        assert_eq!(result.catalog_revision, None);
        assert!(!result.pagination_supported);
        assert!(result.next_cursor.is_none());
        let _ = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_rejects_diagnostics_from_the_other_schema_generation() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617281";
        let v2_with_v3_diagnostic = serde_json::json!({
            "schema": "ylx.session-list.v2",
            "items": [lab_v4_session_summary_json(
                session_id,
                lab_v4_verification_json(
                    &"a".repeat(64),
                    "unusable",
                    vec![("artifact_invalid", "not a v2 diagnostic")],
                ),
            )],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let mut v3_verification = lab_v4_verification_json(&"b".repeat(64), "unusable", Vec::new());
        v3_verification["diagnostics"] = serde_json::json!(["not a v3 diagnostic"]);
        let v3_with_v2_diagnostic = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "e".repeat(64)),
            "items": [lab_v4_session_summary_json(session_id, v3_verification)],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![
            (200, vec![], v2_with_v3_diagnostic),
            (200, vec![], v3_with_v2_diagnostic),
        ]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let wrong_v2 = client.list_sessions("lab-token-is-local", None, Some(50));
        let wrong_v3 = client.list_sessions("lab-token-is-local", None, Some(50));

        assert!(matches!(wrong_v2, Err(PiHttpError::InvalidResponse(_))));
        assert!(matches!(wrong_v3, Err(PiHttpError::InvalidResponse(_))));
        assert_eq!(rx.iter().count(), 2);
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_enforces_limit_order_and_diagnostic_identity() {
        let lower_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617281";
        let higher_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617282";
        let diagnostic = serde_json::json!({
            "quarantine_id": "550e8400-e29b-41d4-a716-446655440002",
            "code": "manifest_invalid",
            "observed_at": "2026-08-08T10:31:32.800+08:00",
            "message": "manifest does not satisfy the closed schema"
        });
        let over_limit = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "a".repeat(64)),
            "items": [lab_v4_session_summary_json(
                higher_id,
                lab_v4_verification_json(&"a".repeat(64), "usable", vec![]),
            )],
            "diagnostics": [diagnostic.clone()],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let unordered = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "b".repeat(64)),
            "items": [
                lab_v4_session_summary_json(
                    lower_id,
                    lab_v4_verification_json(&"b".repeat(64), "usable", vec![]),
                ),
                lab_v4_session_summary_json(
                    higher_id,
                    lab_v4_verification_json(&"c".repeat(64), "usable", vec![]),
                ),
            ],
            "diagnostics": [],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let duplicate_diagnostic = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "c".repeat(64)),
            "items": [],
            "diagnostics": [diagnostic.clone(), diagnostic],
            "next_cursor": null
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![
            (200, vec![], over_limit),
            (200, vec![], unordered),
            (200, vec![], duplicate_diagnostic),
        ]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let over_limit_result = client.list_sessions("lab-token-is-local", None, Some(1));
        let unordered_result = client.list_sessions("lab-token-is-local", None, Some(50));
        let duplicate_result = client.list_sessions("lab-token-is-local", None, Some(50));

        assert!(matches!(
            over_limit_result,
            Err(PiHttpError::InvalidResponse(message)) if message.contains("request limit")
        ));
        assert!(matches!(
            unordered_result,
            Err(PiHttpError::InvalidResponse(message)) if message.contains("newest-first")
        ));
        assert!(matches!(
            duplicate_result,
            Err(PiHttpError::InvalidResponse(message)) if message.contains("quarantine_id")
        ));
        assert_eq!(rx.iter().count(), 3);
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_list_rejects_unbounded_cursors_at_the_wire_boundary() {
        let page = serde_json::json!({
            "schema": "ylx.session-list.v3",
            "catalog_revision": format!("sha256:{}", "e".repeat(64)),
            "items": [],
            "diagnostics": [],
            "next_cursor": "y".repeat(4097)
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], page)]);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            loopback_port_from_base_url(&base_url),
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let oversized_request =
            client.list_sessions("lab-token-is-local", Some(&"x".repeat(4097)), Some(50));
        let oversized_response = client.list_sessions("lab-token-is-local", None, Some(50));

        assert!(matches!(
            oversized_request,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("request cursor") && message.contains("4096")
        ));
        assert!(matches!(
            oversized_response,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("next_cursor") && message.contains("4096")
        ));
        let _ = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        handle.join().expect("fake server exits");
    }

    fn lab_v4_session_manifest_json(session_id: &str) -> Vec<u8> {
        serde_json::json!({
            "schema": "ylx.device-session.v2",
            "manifest_id": "01989f6c-2c01-7b2c-9d3e-4f5061728394",
            "sealed": true,
            "sealed_at": "2026-08-08T10:31:33+08:00",
            "session_id": session_id,
            "volume_id": "6ba7b812-9dad-41d1-80b4-00c04fd430c8",
            "capture_mode": "production",
            "display_name": "2026-08-08_10-31-00_YLX-30D5872D",
            "device": {
                "device_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_label": "YLX-30D5872D",
                "hardware_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "platform": "rdk-x5",
                "software_version": "0.11.0-dev.1",
                "commit": "b7d044d4bbc5ef0e335d2789c54f7d837d1a3e01"
            },
            "time": {
                "started_at": "2026-08-08T10:31:00+08:00",
                "ended_at": "2026-08-08T10:31:30+08:00",
                "timezone": "Asia/Shanghai",
                "duration_seconds": 30
            },
            "take": {
                "take_id": "01989f6c-f000-7c3d-ae4f-5061728394a5",
                "sequence": 1,
                "continuation_of": null
            },
            "video": {
                "layout": "split-eyes",
                "codec": "h264",
                "container": "mp4",
                "segments": [{
                    "index": 0,
                    "start_frame": 0,
                    "end_frame": 900,
                    "start_time_seconds": 0,
                    "end_time_seconds": 30,
                    "artifacts": {
                        "left": {
                            "artifact_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "role": "video.left",
                            "path": "video/left_00000.mp4",
                            "media_type": "video/mp4",
                            "bytes": 100,
                            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        "right": {
                            "artifact_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "role": "video.right",
                            "path": "video/right_00000.mp4",
                            "media_type": "video/mp4",
                            "bytes": 120,
                            "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        }
                    }
                }]
            },
            "imu": {
                "artifact": {
                    "artifact_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "role": "imu.samples",
                    "path": "imu/imu.jsonl",
                    "media_type": "application/x-ndjson",
                    "bytes": 20,
                    "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                },
                "sample_count": 10,
                "units": "raw_int16",
                "coordinate_frame": "raw_device_axes"
            },
            "frames": {
                "artifact": {
                    "artifact_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "role": "frames.index",
                    "path": "imu/frames.jsonl",
                    "media_type": "application/x-ndjson",
                    "bytes": 10,
                    "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                },
                "count": 900
            },
            "audio": {
                "state": "not_recorded",
                "requested_mode": "disabled",
                "resolved_mode": "disabled",
                "reason": "user_disabled"
            },
            "logs": [{
                "artifact_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "role": "log.capture",
                "path": "logs/capture.log",
                "media_type": "text/plain",
                "bytes": 5,
                "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            }],
            "integrity": {
                "verified_at": "2026-08-08T10:31:32.800+08:00",
                "dropped_frames": 0,
                "drop_events": [],
                "fatal_errors": []
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn lab_v4_session_detail_maps_manifest_artifacts_to_existing_session_shape() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let mut manifest = lab_v4_session_manifest_json(session_id);
        manifest.extend_from_slice(b"\n ");
        let exact_manifest = manifest.clone();
        let manifest_sha256 = format!("{:x}", Sha256::digest(&manifest));
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![
                ("YLX-Manifest-SHA256", manifest_sha256.clone()),
                ("ETag", format!("\"{manifest_sha256}\"")),
            ],
            manifest,
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");
        let verification = parsed_lab_v4_verification(&manifest_sha256, "usable", vec![]);

        let detail = client
            .get_v4_verified_session(
                "lab-token-is-local",
                &SessionId(session_id.to_string()),
                Some(&verification),
            )
            .expect("v4 session detail");

        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, format!("/api/v4/sessions/{session_id}"));
        assert!(request
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")));
        assert_eq!(detail.revision, format!("sha256:{manifest_sha256}"));
        assert_eq!(detail.file_count, 5);
        assert_eq!(detail.total_bytes, 255);
        assert_eq!(detail.video_bytes, 220);
        assert!(detail.files.iter().any(|file| file.id
            == "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            && file.display_path == "imu/imu.jsonl"));
        let publication: serde_json::Value =
            serde_json::from_str(&detail.publication_payload).expect("compat publication JSON");
        assert_eq!(publication["source_schema"], "ylx.device-session.v2");
        assert_eq!(publication["source_profile"], "ylx-device-api-v4-lab-http");
        assert_eq!(
            publication["source_manifest_json"]
                .as_str()
                .expect("exact manifest JSON")
                .as_bytes(),
            exact_manifest
        );
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(
                    publication["source_manifest_json"]
                        .as_str()
                        .expect("exact manifest JSON")
                        .as_bytes()
                )
            ),
            manifest_sha256
        );
        assert_eq!(
            publication["receipt_origin"],
            "client-derived-lab-compatibility"
        );
        assert_eq!(publication["device_authenticity"], "not_asserted");
        assert_eq!(publication["integrity_ok"], true);
        assert_eq!(
            detail.publication_origin,
            PublicationEnvelopeOrigin::ClientDerivedLabCompatibility
        );
        assert_eq!(
            detail
                .gateway_verification
                .as_ref()
                .expect("detail retains list verification")
                .manifest_sha256,
            manifest_sha256
        );
        assert_eq!(detail.publication_signature.len(), 128);
        assert_eq!(detail.publication_public_key.len(), 64);
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_detail_rejects_declared_manifest_digest_that_does_not_match_body() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let manifest = lab_v4_session_manifest_json(session_id);
        let wrong_digest = "0".repeat(64);
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![
                ("YLX-Manifest-SHA256", wrong_digest.clone()),
                ("ETag", format!("\"{wrong_digest}\"")),
            ],
            manifest,
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client.get_session("lab-token-is-local", &SessionId(session_id.to_string()));

        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert_eq!(request.url, format!("/api/v4/sessions/{session_id}"));
        assert!(matches!(
            result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("does not match exact response body")
        ));
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_verified_session_rejects_missing_unusable_or_invalid_digest_before_network() {
        let session_id = SessionId("01989f6c-2c00-7a1b-8c2d-3e4f50617283".to_string());
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            9,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_millis(50),
        )
        .expect("lab v4 client");
        let unusable = parsed_lab_v4_verification(
            &"a".repeat(64),
            "unusable",
            vec![("artifact_digest_mismatch", "artifact digest mismatch")],
        );
        let invalid_digest = parsed_lab_v4_verification("not-a-sha256", "usable", Vec::new());

        let missing = client.get_v4_verified_session("lab-token-is-local", &session_id, None);
        let rejected_unusable =
            client.get_v4_verified_session("lab-token-is-local", &session_id, Some(&unusable));
        let rejected_invalid_digest = client.get_v4_verified_session(
            "lab-token-is-local",
            &session_id,
            Some(&invalid_digest),
        );

        assert!(matches!(
            missing,
            Err(PiHttpError::SessionVerificationRequired { reason, .. })
                if reason == "missing_or_stale"
        ));
        assert!(matches!(
            rejected_unusable,
            Err(PiHttpError::SessionVerificationRequired {
                reason,
                diagnostics,
                ..
            }) if reason == "unusable" && diagnostics == vec![V4GatewayDiagnostic::Structured {
                code: "artifact_digest_mismatch".to_string(),
                summary: "artifact digest mismatch".to_string(),
            }]
        ));
        assert!(matches!(
            rejected_invalid_digest,
            Err(PiHttpError::SessionVerificationRequired { reason, .. })
                if reason == "invalid_manifest_digest"
        ));
    }

    #[test]
    fn lab_v4_verified_session_rejects_revision_drift_between_list_and_detail() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let manifest = lab_v4_session_manifest_json(session_id);
        let observed_digest = format!("{:x}", Sha256::digest(&manifest));
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![
                ("YLX-Manifest-SHA256", observed_digest.clone()),
                ("ETag", format!("\"{observed_digest}\"")),
            ],
            manifest,
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");
        let expected = parsed_lab_v4_verification(&"f".repeat(64), "usable", vec![]);

        let result = client.get_v4_verified_session(
            "lab-token-is-local",
            &SessionId(session_id.to_string()),
            Some(&expected),
        );

        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert_eq!(request.url, format!("/api/v4/sessions/{session_id}"));
        assert!(matches!(
            result,
            Err(PiHttpError::SessionRevisionMismatch {
                expected_revision,
                observed_revision,
                ..
            }) if expected_revision == format!("sha256:{}", "f".repeat(64))
                && observed_revision == format!("sha256:{observed_digest}")
        ));
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_detail_requires_both_manifest_digest_headers() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let manifest = lab_v4_session_manifest_json(session_id);
        let digest = format!("{:x}", Sha256::digest(&manifest));
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![("ETag", format!("\"{digest}\""))],
            manifest,
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client.get_session("lab-token-is-local", &SessionId(session_id.to_string()));

        let _ = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert!(matches!(
            result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("omitted YLX-Manifest-SHA256")
        ));
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_session_detail_rejects_disagreeing_digest_headers() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let manifest = lab_v4_session_manifest_json(session_id);
        let digest = format!("{:x}", Sha256::digest(&manifest));
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![
                ("YLX-Manifest-SHA256", digest),
                ("ETag", format!("\"{}\"", "f".repeat(64))),
            ],
            manifest,
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let result = client.get_session("lab-token-is-local", &SessionId(session_id.to_string()));

        let _ = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert!(matches!(
            result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("digest header and ETag disagree")
        ));
        handle.join().expect("fake server exits");
    }

    #[test]
    fn lab_v4_manifest_content_length_corpus_fails_closed_before_artifact_requests() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let body = lab_v4_session_manifest_json(session_id);
        let digest = format!("{:x}", Sha256::digest(&body));
        let common =
            format!("YLX-Manifest-SHA256: {digest}\r\nETag: \"{digest}\"\r\nConnection: close\r\n");
        let cases = [
            (
                "missing",
                format!("HTTP/1.1 200 OK\r\n{common}\r\n"),
                body.clone(),
            ),
            (
                "duplicate",
                format!(
                    "HTTP/1.1 200 OK\r\n{common}Content-Length: {}\r\nContent-Length: {}\r\n\r\n",
                    body.len(),
                    body.len()
                ),
                body.clone(),
            ),
            (
                "conflicting",
                format!(
                    "HTTP/1.1 200 OK\r\n{common}Content-Length: {}\r\nContent-Length: {}\r\n\r\n",
                    body.len(),
                    body.len() + 1
                ),
                body.clone(),
            ),
            (
                "non_decimal",
                format!("HTTP/1.1 200 OK\r\n{common}Content-Length: +7\r\n\r\n"),
                body.clone(),
            ),
            (
                "over_limit",
                format!(
                    "HTTP/1.1 200 OK\r\n{common}Content-Length: {}\r\n\r\n",
                    MAX_V4_MANIFEST_BODY_BYTES + 1
                ),
                Vec::new(),
            ),
            (
                "short_body",
                format!(
                    "HTTP/1.1 200 OK\r\n{common}Content-Length: {}\r\n\r\n",
                    body.len() + 1
                ),
                body.clone(),
            ),
        ];

        for (label, headers, response_body) in cases {
            let mut response = headers.into_bytes();
            response.extend_from_slice(&response_body);
            let (port, requests, server) = spawn_raw_response_server(response);
            let client = PiHttpClient::new_lab_v4_http(
                "127.0.0.1".to_string(),
                port,
                lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
                Duration::from_secs(5),
            )
            .expect("lab v4 client");

            let result =
                client.get_session("lab-token-is-local", &SessionId(session_id.to_string()));

            assert!(result.is_err(), "{label} Content-Length must fail closed");
            let request = requests
                .recv_timeout(Duration::from_secs(2))
                .expect("manifest request captured");
            let request_text = String::from_utf8_lossy(&request);
            assert!(request_text.contains(&format!("/api/v4/sessions/{session_id}")));
            server.join().expect("raw server exits");
            let artifact_requests = request_text.matches("/artifacts/").count()
                + requests
                    .try_iter()
                    .map(|request| {
                        String::from_utf8_lossy(&request)
                            .matches("/artifacts/")
                            .count()
                    })
                    .sum::<usize>();
            assert_eq!(
                artifact_requests, 0,
                "{label} framing must be rejected before any artifact request"
            );
        }
    }

    #[test]
    fn v4_manifest_reader_rejects_more_body_bytes_than_declared() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("2"),
        );
        let response = RawStreamResponse {
            status: 200,
            headers,
            body: Box::new(std::io::Cursor::new(b"abc".to_vec())),
        };

        assert!(matches!(
            response.into_v4_manifest(),
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("body length 3")
        ));
    }

    #[test]
    fn lab_v4_artifact_stream_uses_artifacts_route_range_and_if_range() {
        let session_id = SessionId("01989f6c-2c00-7a1b-8c2d-3e4f50617283".to_string());
        let artifact_id =
            FileId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            206,
            vec![
                (
                    "ETag",
                    "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
                        .to_string(),
                ),
                ("Content-Type", "video/mp4".to_string()),
                ("Content-Length", "3".to_string()),
                ("Content-Range", "bytes 5-7/10".to_string()),
            ],
            b"abc".to_vec(),
        )]);
        let port = loopback_port_from_base_url(&base_url);
        let client = PiHttpClient::new_lab_v4_http(
            "127.0.0.1".to_string(),
            port,
            lab_v4_device_identity_pin("550e8400-e29b-41d4-a716-446655440000"),
            Duration::from_secs(5),
        )
        .expect("lab v4 client");

        let response = client
            .get_file_stream(
                "lab-token-is-local",
                &session_id,
                &artifact_id,
                Some("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""),
                Some(RangeRequest::From { start: 5 }),
            )
            .expect("artifact stream");

        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert_eq!(
            request.url,
            format!(
                "/api/v4/sessions/{}/artifacts/{}",
                session_id.as_str(),
                artifact_id.as_str()
            )
        );
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("range") && value == "bytes=5-"));
        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("if-range")
                && value == "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
        }));
        assert!(request
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")));
        assert_eq!(response.status, 206);
        assert_eq!(response.content_length, 3);
        assert_eq!(
            response
                .content_range
                .map(|range| (range.start, range.end, range.total_size)),
            Some((5, 7, 10))
        );
        handle.join().expect("fake server exits");
    }

    fn spawn_slow_file_server(chunk_gap: Duration) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind slow loopback server");
        let port = listener.local_addr().expect("read loopback address").port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");
        let handle = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let (mut stream, _) = listener.accept().expect("accept slow file request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set request read timeout");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).expect("read request headers");
                if count == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..count]);
            }

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nETag: \"etag-slow\"\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\nConnection: close\r\n\r\na",
                )
                .expect("write response headers and first byte");
            stream.flush().expect("flush first body byte");
            std::thread::sleep(chunk_gap);
            if stream.write_all(b"b").is_err() {
                return;
            }
            let _ = stream.flush();
            std::thread::sleep(chunk_gap);
            let _ = stream.write_all(b"c");
            let _ = stream.flush();
        });
        (base_url, handle)
    }

    fn spawn_raw_response_server(
        response: Vec<u8>,
    ) -> (u16, mpsc::Receiver<Vec<u8>>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind raw loopback server");
        let port = listener.local_addr().expect("read loopback address").port();
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let (mut stream, _) = listener.accept().expect("accept raw HTTP request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set raw request timeout");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).expect("read raw request headers");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            tx.send(request).expect("record raw HTTP request");
            stream
                .write_all(&response)
                .expect("write raw HTTP response");
            stream.flush().expect("flush raw HTTP response");
            drop(stream);

            // Keep observing briefly after the manifest response. A future
            // regression that starts an artifact request before accepting
            // the manifest must be visible to the corpus test rather than
            // merely failing against a listener that disappeared early.
            listener
                .set_nonblocking(true)
                .expect("make raw listener nonblocking");
            let deadline = std::time::Instant::now() + Duration::from_millis(100);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut extra, _)) => {
                        let mut request = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            match extra.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(count) => request.extend_from_slice(&chunk[..count]),
                            }
                        }
                        tx.send(request).expect("record unexpected extra request");
                        let _ = extra.write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (port, rx, handle)
    }

    fn problem_json(code: &str, status: u16, retryable: bool) -> Vec<u8> {
        serde_json::json!({
            "error_schema_version": 1,
            "code": code,
            "status": status,
            "request_id": "req-test-1",
            "retryable": retryable,
            "detail": format!("test detail for {code}"),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn create_pairing_request_parses_202_and_sends_json_body() {
        let created_json = serde_json::json!({
            "attempt_id": "attempt-0001",
            "phase": "pending",
            "poll_secret_configured": true,
            "poll_secret": "secret-xyz",
            "expires_at": "2026-08-01T04:01:00Z",
            "sas": "617768",
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(202, vec![], created_json)]);
        let client = test_client(base_url);

        let result = client.create_pairing_request("pc-test", "nonce-1");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let created = result.expect("create_pairing_request succeeds");
        assert_eq!(created.attempt_id, "attempt-0001");
        assert_eq!(created.phase, PairingPhase::Pending);
        assert_eq!(created.poll_secret, "secret-xyz");

        assert_eq!(captured.method, "POST");
        assert!(
            captured.url.ends_with("/pairing-requests"),
            "url was {}",
            captured.url
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&captured.body).expect("request body is JSON");
        assert_eq!(body_json["client_name"], "pc-test");
        assert_eq!(body_json["client_nonce"], "nonce-1");
    }

    #[test]
    fn get_pairing_status_sends_poll_secret_as_query_param() {
        let status_json = serde_json::json!({
            "attempt_id": "attempt-0001",
            "phase": "allowed",
            "poll_secret_configured": true,
            "expires_at": "2026-08-01T04:01:00Z",
            "sas": "617768",
            "connection_token": "opaque-token",
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], status_json)]);
        let client = test_client(base_url);

        let result = client.get_pairing_status("attempt-0001", "secret-xyz");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let status = result.expect("get_pairing_status succeeds");
        assert_eq!(status.phase, PairingPhase::Allowed);
        assert_eq!(status.connection_token.as_deref(), Some("opaque-token"));
        assert_eq!(captured.method, "GET");
        assert!(
            captured.url.contains("poll_secret=secret-xyz"),
            "url was {}",
            captured.url
        );
    }

    #[test]
    fn heartbeat_sends_bearer_authorization_header() {
        let heartbeat_json = serde_json::json!({
            "daemon_instance_id": "daemon-1",
            "idle_timeout_ms": 30000,
            "absolute_expires_at": "2026-08-01T05:00:00Z",
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], heartbeat_json)]);
        let client = test_client(base_url);

        let result = client.heartbeat("token-abc");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let outcome = result.expect("heartbeat succeeds");
        assert_eq!(outcome._daemon_instance_id, "daemon-1");
        assert_eq!(outcome.capture_activity, None);
        assert_eq!(captured.method, "POST");
        let auth = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"));
        assert_eq!(auth.map(|(_, v)| v.as_str()), Some("Bearer token-abc"));
    }

    #[test]
    fn unauthenticated_401_maps_to_structured_api_error_not_panic() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            401,
            vec![],
            problem_json("unauthorized", 401, false),
        )]);
        let client = test_client(base_url);

        let result = client.get_device("bad-token");

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(PiHttpError::Api(ApiError {
                code: PiApiErrorCode::Unauthorized,
                status: 401,
                retryable: false,
                ..
            })) => {}
            other => panic!("expected structured Unauthorized ApiError, got {other:?}"),
        }
    }

    #[test]
    fn invalid_session_404_maps_to_structured_api_error() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            404,
            vec![],
            problem_json("invalid_session", 404, false),
        )]);
        let client = test_client(base_url);

        let result = client.get_session("token", &SessionId("missing-sess".to_string()));

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(PiHttpError::Api(ApiError {
                code: PiApiErrorCode::InvalidSession,
                ..
            })) => {}
            other => panic!("expected InvalidSession ApiError, got {other:?}"),
        }
    }

    #[test]
    fn session_in_use_409_maps_correctly() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            409,
            vec![],
            problem_json("session_in_use", 409, true),
        )]);
        let client = test_client(base_url);

        let result =
            client.delete_session("token", &SessionId("sess-1".to_string()), "rev-1", "idem-1");

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(PiHttpError::Api(ApiError {
                code: PiApiErrorCode::SessionInUse,
                retryable: true,
                ..
            })) => {}
            other => panic!("expected SessionInUse ApiError, got {other:?}"),
        }
    }

    #[test]
    fn revision_mismatch_412_maps_correctly() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            412,
            vec![],
            problem_json("revision_mismatch", 412, false),
        )]);
        let client = test_client(base_url);

        let result = client.delete_session(
            "token",
            &SessionId("sess-1".to_string()),
            "stale-rev",
            "idem-1",
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        assert!(matches!(
            result,
            Err(PiHttpError::Api(ApiError {
                code: PiApiErrorCode::RevisionMismatch,
                ..
            }))
        ));
        let if_match = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("If-Match"));
        assert_eq!(if_match.map(|(_, v)| v.as_str()), Some("\"stale-rev\""));
    }

    #[test]
    fn strong_revision_etag_does_not_double_quote_an_existing_validator() {
        assert_eq!(strong_revision_etag("sha256:abc"), "\"sha256:abc\"");
        assert_eq!(strong_revision_etag("\"sha256:abc\""), "\"sha256:abc\"");
    }

    #[test]
    fn capture_busy_503_maps_correctly_with_retry_after() {
        let mut body =
            serde_json::from_slice::<serde_json::Value>(&problem_json("capture_busy", 503, true))
                .unwrap();
        body["retry_after_ms"] = serde_json::json!(2500);
        let (base_url, rx, handle) =
            spawn_fake_server(vec![(503, vec![], body.to_string().into_bytes())]);
        let client = test_client(base_url);

        let result = client.get_device("token");

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(PiHttpError::Api(ApiError {
                code: PiApiErrorCode::CaptureBusy,
                retry_after_ms: Some(2500),
                ..
            })) => {}
            other => panic!("expected CaptureBusy with retry_after_ms, got {other:?}"),
        }
    }

    #[test]
    fn get_file_200_full_body_no_range_requested() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![
                ("ETag", "\"etag-1\"".to_string()),
                ("Content-Type", "video/mp4".to_string()),
                ("Content-Length", "5".to_string()),
            ],
            b"hello".to_vec(),
        )]);
        let client = test_client(base_url);

        let result = client.get_file(
            "token",
            &SessionId("sess-1".to_string()),
            &FileId("f-1".to_string()),
            None,
            None,
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let file = result.expect("get_file succeeds");
        assert_eq!(file.status, 200);
        assert_eq!(file.etag, "\"etag-1\"");
        assert_eq!(file.media_type, "video/mp4");
        assert_eq!(file.body, b"hello");
        assert!(file.content_range.is_none());
        let range_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Range"));
        assert!(
            range_header.is_none(),
            "no Range header should be sent when none was requested"
        );
    }

    #[test]
    fn get_file_206_partial_body_sends_correct_range_header_and_parses_content_range() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            206,
            vec![
                ("ETag", "\"etag-1\"".to_string()),
                ("Content-Type", "video/mp4".to_string()),
                ("Content-Length", "3".to_string()),
                ("Content-Range", "bytes 2-4/10".to_string()),
            ],
            b"llo".to_vec(),
        )]);
        let client = test_client(base_url);

        let result = client.get_file(
            "token",
            &SessionId("sess-1".to_string()),
            &FileId("f-1".to_string()),
            None,
            Some(RangeRequest::Bounded { start: 2, end: 4 }),
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let file = result.expect("ranged get_file succeeds");
        assert_eq!(file.status, 206);
        assert_eq!(file.body, b"llo");
        assert_eq!(
            file.content_range,
            Some(ContentRange {
                start: 2,
                end: 4,
                total_size: 10
            })
        );
        let range_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Range"))
            .expect("Range header was sent");
        assert_eq!(range_header.1, "bytes=2-4");
    }

    #[test]
    fn get_file_stream_moves_to_worker_and_reads_large_body_incrementally() {
        let body_len = MAX_BUFFERED_RESPONSE_BODY_BYTES as usize + 65_537;
        let response_body = vec![0xa5; body_len];
        let (base_url, rx, server_handle) = spawn_fake_server(vec![(
            206,
            vec![
                ("ETag", "\"etag-large\"".to_string()),
                ("Content-Type", "application/octet-stream".to_string()),
                ("Content-Length", body_len.to_string()),
                (
                    "Content-Range",
                    format!("bytes 7-{}/{}", body_len + 6, body_len + 7),
                ),
            ],
            response_body,
        )]);
        let client = test_client(base_url);

        let response = client
            .get_file_stream(
                "token",
                &SessionId("sess-1".to_string()),
                &FileId("f-large".to_string()),
                Some("\"etag-large\""),
                Some(RangeRequest::From { start: 7 }),
            )
            .expect("large file response returns before buffering the body");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        assert_eq!(response.status, 206);
        assert_eq!(response.content_length, body_len as u64);
        assert_eq!(
            response.content_range,
            Some(ContentRange {
                start: 7,
                end: body_len as u64 + 6,
                total_size: body_len as u64 + 7,
            })
        );
        assert_eq!(
            captured
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("Range"))
                .map(|(_, value)| value.as_str()),
            Some("bytes=7-")
        );
        assert_eq!(
            captured
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("If-Match"))
                .map(|(_, value)| value.as_str()),
            Some("\"etag-large\"")
        );

        // Moving the complete response into this thread is a compile-time
        // proof that its owned socket reader is Send. A deliberately small
        // caller buffer proves the API supports incremental consumption of
        // a body larger than the bounded JSON/problem-response limit.
        let reader_handle = std::thread::spawn(move || {
            let mut reader = response.body;
            let mut buffer = [0_u8; 8 * 1024];
            let mut bytes_read = 0_usize;
            let mut read_calls = 0_usize;
            loop {
                let count = reader.read(&mut buffer).expect("stream read succeeds");
                if count == 0 {
                    break;
                }
                assert!(buffer[..count].iter().all(|byte| *byte == 0xa5));
                bytes_read += count;
                read_calls += 1;
            }
            (bytes_read, read_calls)
        });

        let (bytes_read, read_calls) = reader_handle.join().expect("reader worker exits cleanly");
        server_handle.join().expect("server thread exits cleanly");
        assert_eq!(bytes_read, body_len);
        assert!(
            read_calls > 1,
            "large response must require multiple caller reads"
        );
    }

    #[test]
    fn file_stream_timeout_is_idle_not_total_transfer_duration() {
        use std::io::Read as _;

        let idle_timeout = Duration::from_secs(1);
        let chunk_gap = Duration::from_millis(600);
        assert!(chunk_gap < idle_timeout);

        let (base_url, server) = spawn_slow_file_server(chunk_gap);
        let client = PiHttpClient::new_insecure_for_test(base_url, idle_timeout);
        let mut response = client
            .get_file_stream(
                "token",
                &SessionId("sess-1".to_string()),
                &FileId("f-slow".to_string()),
                None,
                None,
            )
            .expect("response headers arrive within the request budget");

        let mut body = Vec::new();
        let started_at = std::time::Instant::now();
        let read_result = response.body.read_to_end(&mut body);
        let elapsed = started_at.elapsed();
        server.join().expect("slow file server exits cleanly");

        read_result.expect("regular chunk progress must keep the stream alive");
        assert!(
            elapsed > idle_timeout,
            "test transfer must exceed the configured idle timeout to prove it is not cumulative"
        );
        assert_eq!(body, b"abc");
    }

    #[test]
    fn get_file_malformed_content_range_on_206_is_rejected_not_silently_accepted() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            206,
            vec![
                ("ETag", "\"etag-1\"".to_string()),
                ("Content-Type", "video/mp4".to_string()),
                ("Content-Length", "3".to_string()),
                ("Content-Range", "not-a-valid-content-range".to_string()),
            ],
            b"llo".to_vec(),
        )]);
        let client = test_client(base_url);

        let result = client.get_file(
            "token",
            &SessionId("sess-1".to_string()),
            &FileId("f-1".to_string()),
            None,
            Some(RangeRequest::Bounded { start: 2, end: 4 }),
        );

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        assert!(
            matches!(result, Err(PiHttpError::InvalidResponse(_))),
            "expected InvalidResponse, got {result:?}"
        );
    }

    #[test]
    fn range_not_satisfiable_416_maps_correctly() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            416,
            vec![],
            problem_json("range_not_satisfiable", 416, false),
        )]);
        let client = test_client(base_url);

        let result = client.get_file(
            "token",
            &SessionId("sess-1".to_string()),
            &FileId("f-1".to_string()),
            None,
            Some(RangeRequest::From { start: 999_999 }),
        );

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        // Issue #1 commit 10: a `416` used to be folded into the generic
        // `PiHttpError::Api` bucket, which forced every caller to
        // re-discover the status by matching on a `problem+json` code
        // (or, in `pi_download_source`'s case, on a formatted string).
        // It now keeps its own variant, with the problem+json detail
        // preserved rather than discarded.
        match result {
            Err(PiHttpError::RangeNotSatisfiable { detail, .. }) => assert!(
                detail.contains("range_not_satisfiable"),
                "problem+json detail must survive, got {detail:?}"
            ),
            other => panic!("416 must keep its own variant, got {other:?}"),
        }
    }

    #[test]
    fn head_file_sends_no_range_header_even_when_caller_never_asked_for_one() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            200,
            vec![
                ("ETag", "\"etag-1\"".to_string()),
                ("Content-Type", "video/mp4".to_string()),
                ("Content-Length", "12345".to_string()),
            ],
            Vec::new(),
        )]);
        let client = test_client(base_url);

        let result = client.head_file(
            "token",
            &SessionId("sess-1".to_string()),
            &FileId("f-1".to_string()),
            None,
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let head = result.expect("head_file succeeds");
        assert_eq!(head.content_length, 12345);
        assert_eq!(captured.method, "HEAD");
    }

    #[test]
    fn head_file_412_preserves_the_current_etag() {
        let (base_url, _rx, handle) = spawn_fake_server(vec![(
            412,
            vec![
                ("Content-Type", "application/problem+json".to_string()),
                ("ETag", "\"etag-new\"".to_string()),
            ],
            Vec::new(),
        )]);
        let client = test_client(base_url);

        let err = client
            .head_file(
                "token",
                &SessionId("sess-1".to_string()),
                &FileId("f-1".to_string()),
                Some("\"etag-old\""),
            )
            .expect_err("stale HEAD validator must fail");
        handle.join().expect("server thread exits cleanly");

        match err {
            PiHttpError::PreconditionFailed { etag, .. } => {
                assert_eq!(etag.as_deref(), Some("\"etag-new\""));
            }
            other => panic!("HEAD 412 must preserve the current ETag, got {other:?}"),
        }
    }

    #[test]
    fn no_redirect_is_followed_302_surfaces_as_unexpected_status() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(
            302,
            vec![("Location", "http://127.0.0.1:1/somewhere-else".to_string())],
            Vec::new(),
        )]);
        let client = test_client(base_url);

        let result = client.get_device("token");

        let captured_count = rx.iter().count(); // exactly one request should have been made -- no follow-up to Location
        handle.join().expect("server thread exits cleanly");

        assert_eq!(
            captured_count, 1,
            "client must not have followed the redirect"
        );
        match result {
            Err(PiHttpError::UnexpectedStatus { status: 302, .. }) => {}
            other => panic!("expected UnexpectedStatus{{302}}, got {other:?}"),
        }
    }

    #[test]
    fn device_rejects_an_incompatible_protocol_major() {
        let body = serde_json::json!({
            "capabilities": ["range-download"],
            "capture_activity": "idle",
            "media_admission": "open",
            "publication_key_fingerprint": format!("sha256:{}", "a".repeat(64)),
            "protocol_major": 2,
            "protocol_minor": 0,
            "storage": {
                "free_bytes": 1,
                "total_bytes": 2
            }
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], body)]);
        let client = test_client(base_url);

        let result = client.get_device("token");

        let _ = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");
        assert!(matches!(
            result,
            Err(PiHttpError::InvalidResponse(message))
                if message.contains("unsupported Pi protocol major 2")
        ));
    }

    #[test]
    fn revoke_session_treats_204_as_success() {
        let (base_url, rx, handle) = spawn_fake_server(vec![(204, vec![], Vec::new())]);
        let client = test_client(base_url);

        let result = client.revoke_session("token");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        assert!(result.is_ok());
        assert_eq!(captured.method, "DELETE");
    }

    #[test]
    fn list_sessions_encodes_cursor_and_limit_query_params() {
        let page_json = serde_json::json!({
            "catalog_revision": "cat-rev-1",
            "sessions": [],
            "next_cursor": null,
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], page_json)]);
        let client = test_client(base_url);

        let result = client.list_sessions("token", Some("cursor value/x"), Some(50));

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let page = result.expect("list_sessions succeeds");
        assert_eq!(page.catalog_revision.as_deref(), Some("cat-rev-1"));
        assert!(
            captured.url.contains("limit=50"),
            "url was {}",
            captured.url
        );
        assert!(
            captured.url.contains("cursor=cursor"),
            "url was {}",
            captured.url
        );
    }

    #[test]
    fn legacy_session_list_rejects_missing_or_empty_catalog_revision() {
        let missing = serde_json::json!({
            "sessions": [],
            "next_cursor": null,
        })
        .to_string()
        .into_bytes();
        let empty = serde_json::json!({
            "catalog_revision": "",
            "sessions": [],
            "next_cursor": null,
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) =
            spawn_fake_server(vec![(200, vec![], missing), (200, vec![], empty)]);
        let client = test_client(base_url);

        let missing_result = client.list_sessions("token", None, Some(50));
        let empty_result = client.list_sessions("token", None, Some(50));

        let captured_count = rx.iter().count();
        handle.join().expect("server thread exits cleanly");
        assert_eq!(captured_count, 2);
        for result in [missing_result, empty_result] {
            assert!(matches!(
                result,
                Err(PiHttpError::InvalidResponse(message))
                    if message.contains("non-empty catalog_revision")
            ));
        }
    }

    /// Transport-layer coverage for the complete `GET /sessions/{id}` DTO,
    /// including the required publication envelope and `files[]` inventory.
    /// Each file has the six frozen fields
    /// `id/display_path/role/size_bytes/sha256/media_type`. The cryptographic content is deliberately a
    /// placeholder here because this method only parses transport JSON;
    /// `pi_client_port` tests exercise real signatures and fail-closed
    /// identity/schema/inventory validation.
    #[test]
    fn get_session_parses_the_real_per_file_inventory() {
        let session_json = serde_json::json!({
            "session_id": "sess-1",
            "revision": format!("sha256:{}", "a".repeat(64)),
            "captured_at": "2026-08-01T00:00:00Z",
            "published_at": "2026-08-01T00:01:00Z",
            "duration_seconds": 12.5,
            "total_bytes": 967852457,
            "video_bytes": 967840112,
            "file_count": 3,
            "publication_payload": "{}",
            "publication_signature": "00".repeat(64),
            "publication_public_key": "11".repeat(32),
            "publication_key_fingerprint": format!("sha256:{}", "2".repeat(64)),
            "files": [
                {
                    "id": "f-0001",
                    "display_path": "video/left_00000.mp4",
                    "role": "video_left",
                    "size_bytes": 483920112,
                    "sha256": "b".repeat(64),
                    "media_type": "video/mp4",
                },
                {
                    "id": "f-0002",
                    "display_path": "video/right_00000.mp4",
                    "role": "video_right",
                    "size_bytes": 483920000,
                    "sha256": "c".repeat(64),
                    "media_type": "video/mp4",
                },
                {
                    "id": "f-0003",
                    "display_path": "imu/imu_00000.csv",
                    "role": "imu",
                    "size_bytes": 12345,
                    "sha256": "d".repeat(64),
                    "media_type": "text/csv",
                },
            ],
        })
        .to_string()
        .into_bytes();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], session_json)]);
        let client = test_client(base_url);

        let result = client.get_session("token", &SessionId("sess-1".to_string()));

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let detail = result.expect("get_session succeeds");
        assert_eq!(captured.method, "GET");
        assert_eq!(detail.session_id.as_str(), "sess-1");
        assert_eq!(detail.revision, format!("sha256:{}", "a".repeat(64)));
        assert_eq!(detail.file_count, 3);
        assert_eq!(detail.files.len(), 3);
        assert_eq!(detail.files[0].id, "f-0001");
        assert_eq!(detail.files[0].display_path, "video/left_00000.mp4");
        assert_eq!(detail.files[0].role, "video_left");
        assert_eq!(detail.files[0].size_bytes, 483920112);
        assert_eq!(detail.files[0].sha256, "b".repeat(64));
        assert_eq!(detail.files[0].media_type, "video/mp4");
        assert_eq!(detail.files[2].role, "imu");
        assert_eq!(detail.files[2].media_type, "text/csv");
    }

    #[test]
    fn invalid_path_segment_is_rejected_before_any_request_is_sent() {
        let client = test_client("http://127.0.0.1:1/api/v1".to_string());
        let result = client.get_session("token", &SessionId("../etc/passwd".to_string()));
        assert!(matches!(result, Err(PiHttpError::InvalidArgument(_))));
    }

    #[test]
    fn parse_tls_pin_accepts_both_prefixed_and_bare_hex() {
        let hex64 = "a".repeat(64);
        let bare = PiTlsPin(hex64.clone());
        let prefixed = PiTlsPin(format!("sha256:{hex64}"));
        assert_eq!(parse_tls_pin(&bare).unwrap(), [0xaa; 32]);
        assert_eq!(parse_tls_pin(&prefixed).unwrap(), [0xaa; 32]);
    }

    #[test]
    fn parse_tls_pin_rejects_wrong_length() {
        let result = parse_tls_pin(&PiTlsPin("deadbeef".to_string()));
        assert!(matches!(result, Err(PiHttpError::InvalidArgument(_))));
    }

    #[test]
    fn get_file_stream_412_is_reported_as_a_precondition_failure_not_a_generic_api_error() {
        let (base_url, _rx, handle) = spawn_fake_server(vec![(
            412,
            vec![
                ("Content-Type", "application/problem+json".to_string()),
                ("ETag", "\"etag-new\"".to_string()),
            ],
            problem_json("precondition_failed", 412, false),
        )]);
        let client = test_client(base_url);

        let err = client
            .get_file_stream(
                "token",
                &SessionId("sess-1".to_string()),
                &FileId("f-1".to_string()),
                Some("\"etag-old\""),
                Some(RangeRequest::From { start: 64 }),
            )
            .expect_err("412 is not a success");
        handle.join().expect("server thread exits cleanly");

        match err {
            PiHttpError::PreconditionFailed { etag, detail } => {
                assert_eq!(etag.as_deref(), Some("\"etag-new\""));
                assert!(
                    detail.contains("precondition_failed"),
                    "problem+json detail must be preserved, got {detail:?}"
                );
            }
            other => panic!(
                "412 must keep its own variant so the download engine can act on it, got {other:?}"
            ),
        }
    }

    #[test]
    fn get_file_stream_416_keeps_its_content_range_total() {
        let (base_url, _rx, handle) = spawn_fake_server(vec![(
            416,
            vec![
                ("Content-Type", "application/problem+json".to_string()),
                ("Content-Range", "bytes */4096".to_string()),
            ],
            problem_json("range_not_satisfiable", 416, false),
        )]);
        let client = test_client(base_url);

        let err = client
            .get_file_stream(
                "token",
                &SessionId("sess-1".to_string()),
                &FileId("f-1".to_string()),
                None,
                Some(RangeRequest::From { start: 4096 }),
            )
            .expect_err("416 is not a success");
        handle.join().expect("server thread exits cleanly");

        match err {
            PiHttpError::RangeNotSatisfiable { content_range, .. } => {
                assert_eq!(
                    content_range.as_deref(),
                    Some("bytes */4096"),
                    "the unsatisfiable total is what tells a resuming caller whether \
                     its local partial is already the whole object"
                );
            }
            other => panic!("416 must keep its own variant, got {other:?}"),
        }
    }

    #[test]
    fn other_non_2xx_file_statuses_still_map_to_the_generic_problem_json_error() {
        let (base_url, _rx, handle) = spawn_fake_server(vec![(
            404,
            vec![("Content-Type", "application/problem+json".to_string())],
            problem_json("not_found", 404, false),
        )]);
        let client = test_client(base_url);

        let err = client
            .get_file_stream(
                "token",
                &SessionId("sess-1".to_string()),
                &FileId("f-missing".to_string()),
                None,
                Some(RangeRequest::From { start: 0 }),
            )
            .expect_err("404 is not a success");
        handle.join().expect("server thread exits cleanly");

        match err {
            PiHttpError::Api(api) => assert_eq!(api.status, 404),
            other => panic!("unrelated statuses must keep the existing mapping, got {other:?}"),
        }
    }

    // =================================================================
    // Commit 51: redacted/zeroizing secrets, bounded+sanitized remote text
    // =================================================================

    const DUMMY_PIN: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn config_for_host(host: &str) -> PiHttpClientConfig {
        PiHttpClientConfig {
            host: host.to_string(),
            port: 9443,
            tls_pin: PiTlsPin(DUMMY_PIN.to_string()),
            request_timeout: Duration::from_secs(5),
        }
    }

    /// IPv6 follow-up to commit 60. `format!("https://{host}:{port}")` on
    /// an IPv6 literal produces `https://2001:db8::42:9443/...`, which is
    /// not a parseable URL at all -- every request against an IPv6 device
    /// would fail. The literal must be bracketed.
    #[test]
    fn base_url_brackets_an_ipv6_host_literal() {
        let client = PiHttpClient::new(config_for_host("2001:db8::42")).expect("client builds");
        assert_eq!(client.base_url, "https://[2001:db8::42]:9443/api/v1");
    }

    #[test]
    fn base_url_percent_encodes_an_ipv6_zone_id() {
        let client = PiHttpClient::new(config_for_host("fe80::1%eth0")).expect("client builds");
        assert_eq!(client.base_url, "https://[fe80::1%25eth0]:9443/api/v1");
    }

    #[test]
    fn base_url_passes_an_ipv4_host_through_unchanged() {
        let client = PiHttpClient::new(config_for_host("192.168.1.42")).expect("client builds");
        assert_eq!(client.base_url, "https://192.168.1.42:9443/api/v1");
    }

    #[test]
    fn a_non_address_host_is_rejected_instead_of_building_a_broken_url() {
        let result = PiHttpClient::new(config_for_host("[2001:db8::42]"));
        let Err(err) = result else {
            panic!("an already-bracketed literal is not a bare address literal");
        };
        assert!(
            matches!(err, PiHttpError::InvalidArgument(_)),
            "got {err:?}"
        );
    }

    // ---- remote text: bounded ---------------------------------------

    #[test]
    fn sanitize_remote_text_truncates_at_the_documented_cap() {
        let oversized = vec![b'A'; MAX_REMOTE_TEXT_BYTES * 64];
        let sanitized = sanitize_remote_text(&oversized);

        assert_eq!(
            sanitized,
            format!(
                "{}{}",
                "A".repeat(MAX_REMOTE_TEXT_BYTES),
                REMOTE_TEXT_TRUNCATION_MARKER
            )
        );
        // Exactly at the cap, nothing is dropped and no marker appears.
        let exact = vec![b'A'; MAX_REMOTE_TEXT_BYTES];
        assert_eq!(
            sanitize_remote_text(&exact),
            "A".repeat(MAX_REMOTE_TEXT_BYTES)
        );
        assert!(!sanitize_remote_text(&exact).contains(REMOTE_TEXT_TRUNCATION_MARKER));
    }

    /// End-to-end: a hostile device answering with a multi-megabyte
    /// non-problem+json error body must not put megabytes into the error
    /// value (or the log line it becomes).
    #[test]
    fn an_oversized_error_body_is_truncated_before_it_reaches_the_error() {
        let body = vec![b'Z'; 3 * 1024 * 1024];
        let (base_url, rx, handle) = spawn_fake_server(vec![(500, vec![], body)]);
        let client = test_client(base_url);

        let err = client
            .heartbeat("token-abc")
            .expect_err("a 500 with a junk body is an error");
        let _ = rx.recv_timeout(Duration::from_secs(5));
        let _ = handle.join();

        match err {
            PiHttpError::UnexpectedStatus { status, body } => {
                assert_eq!(status, 500);
                assert_eq!(
                    body.len(),
                    MAX_REMOTE_TEXT_BYTES + REMOTE_TEXT_TRUNCATION_MARKER.len()
                );
                assert!(body.ends_with(REMOTE_TEXT_TRUNCATION_MARKER));
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    /// The `problem+json` `detail` field is remote-controlled too, and it
    /// is the string that actually reaches the user and the log.
    #[test]
    fn an_oversized_problem_json_detail_is_truncated() {
        let detail = "d".repeat(MAX_REMOTE_TEXT_BYTES * 4);
        let body = serde_json::to_vec(&serde_json::json!({
            "error_schema_version": 1,
            "code": "internal_error",
            "status": 500,
            "request_id": "req-1",
            "retryable": false,
            "detail": detail,
        }))
        .unwrap();
        let (base_url, rx, handle) = spawn_fake_server(vec![(500, vec![], body)]);
        let client = test_client(base_url);

        let err = client.heartbeat("token-abc").expect_err("500 is an error");
        let _ = rx.recv_timeout(Duration::from_secs(5));
        let _ = handle.join();

        match err {
            PiHttpError::Api(api) => {
                assert_eq!(
                    api.detail.len(),
                    MAX_REMOTE_TEXT_BYTES + REMOTE_TEXT_TRUNCATION_MARKER.len()
                );
                assert!(api.detail.ends_with(REMOTE_TEXT_TRUNCATION_MARKER));
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    // ---- remote text: sanitized -------------------------------------

    #[test]
    fn sanitize_remote_text_strips_control_and_terminal_escaping_characters() {
        // A real ANSI sequence that would clear the screen and repaint a
        // fake "OK" line in any terminal tailing the log, plus a CRLF pair
        // that would forge an extra log line, plus a NUL and a bidi
        // override that flips displayed text order.
        let hostile = b"\x1b[2J\x1b[1;31mFAKE\r\nlog line\x00\xe2\x80\xaespoofed";
        let sanitized = sanitize_remote_text(hostile);

        assert!(!sanitized.contains('\x1b'), "ESC survived: {sanitized:?}");
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\0'));
        assert!(!sanitized.contains('\u{202e}'));
        assert!(!sanitized.chars().any(char::is_control));
        // Printable content is preserved so the message is still useful.
        assert!(sanitized.contains("FAKE"));
        assert!(sanitized.contains("log line"));
        assert!(sanitized.contains("spoofed"));
    }

    #[test]
    fn sanitize_remote_text_replaces_invalid_utf8_instead_of_failing() {
        assert_eq!(sanitize_remote_text(b"ok\xff\xfe!"), "ok\u{fffd}\u{fffd}!");
    }

    /// The whole point of sanitizing: what a hostile device sends must not
    /// be able to steer a terminal that reads the resulting error.
    #[test]
    fn a_control_character_error_body_is_sanitized_before_it_reaches_the_error() {
        let (base_url, rx, handle) =
            spawn_fake_server(vec![(503, vec![], b"\x1b]0;pwned\x07oops".to_vec())]);
        let client = test_client(base_url);

        let err = client.heartbeat("token-abc").expect_err("503 is an error");
        let _ = rx.recv_timeout(Duration::from_secs(5));
        let _ = handle.join();

        match err {
            PiHttpError::UnexpectedStatus { ref body, .. } => {
                assert!(!body.chars().any(char::is_control), "leaked: {body:?}");
                assert!(body.contains("oops"));
                // Display-formatting the whole error is also safe.
                assert!(!format!("{err}").chars().any(char::is_control));
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    // ---- secrets never reach a formatted string ----------------------

    #[test]
    fn debug_formatting_a_pairing_response_never_reveals_the_poll_secret() {
        let created: PairingCreated = serde_json::from_value(serde_json::json!({
            "attempt_id": "attempt-0001",
            "phase": "pending",
            "poll_secret_configured": true,
            "poll_secret": "poll-secret-plaintext",
            "expires_at": "2026-01-01T00:00:00Z",
            "sas": "123456",
        }))
        .expect("fixture parses");

        let rendered = format!("{created:?}");
        assert!(!rendered.contains("poll-secret-plaintext"), "{rendered}");
        assert!(rendered.contains(ylx_transfer_core::secret::REDACTED));
        // Non-secret fields still render, so the Debug output stays useful.
        assert!(rendered.contains("attempt-0001"));
        // ... and the accessor hands back a redacting, zeroizing wrapper.
        assert_eq!(
            created.poll_secret().expose_secret(),
            "poll-secret-plaintext"
        );
        assert_eq!(
            format!("{:?}", created.poll_secret()),
            ylx_transfer_core::secret::REDACTED
        );
    }

    #[test]
    fn debug_formatting_a_pairing_status_redacts_the_credential() {
        let status: PairingStatus = serde_json::from_value(serde_json::json!({
            "attempt_id": "attempt-0001",
            "phase": "allowed",
            "poll_secret_configured": true,
            "expires_at": "2026-01-01T00:00:00Z",
            "sas": "123456",
            "connection_token": "connection-token-plaintext",
        }))
        .expect("fixture parses");

        let rendered = format!("{status:?}");
        assert!(
            !rendered.contains("connection-token-plaintext"),
            "{rendered}"
        );
        assert!(rendered.contains(ylx_transfer_core::secret::REDACTED));
        assert!(status.connection_token.is_some());
    }

    /// A caller holding a `Secret` can drive the client without ever
    /// writing `expose_secret` at the call site, and the resulting request
    /// is byte-identical to the `&str` form.
    #[test]
    fn a_secret_can_be_passed_straight_through_as_the_bearer_token() {
        let heartbeat_json = serde_json::to_vec(&serde_json::json!({
            "daemon_instance_id": "daemon-1",
            "idle_timeout_ms": 30000,
            "absolute_expires_at": "2026-08-01T05:00:00Z",
        }))
        .unwrap();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], heartbeat_json)]);
        let client = test_client(base_url);

        let token = ylx_transfer_core::secret::Secret::new("token-abc");
        let result = client.heartbeat(&token);

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");
        assert!(result.is_ok(), "{result:?}");
        let auth = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"));
        assert_eq!(auth.map(|(_, v)| v.as_str()), Some("Bearer token-abc"));
    }

    #[test]
    fn a_secret_can_be_passed_straight_through_as_the_poll_secret() {
        let status_json = serde_json::to_vec(&serde_json::json!({
            "attempt_id": "attempt-0001",
            "phase": "pending",
            "poll_secret_configured": true,
            "expires_at": "2026-01-01T00:00:00Z",
            "sas": "123456",
            "connection_token": null,
            "sas_transcript": null,
        }))
        .unwrap();
        let (base_url, rx, handle) = spawn_fake_server(vec![(200, vec![], status_json)]);
        let client = test_client(base_url);

        let poll_secret = ylx_transfer_core::secret::Secret::new("secret-xyz");
        let result = client.get_pairing_status("attempt-0001", &poll_secret);

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");
        assert!(result.is_ok(), "{result:?}");
        assert!(
            captured.url.contains("poll_secret=secret-xyz"),
            "unexpected url: {}",
            captured.url
        );
    }
}
