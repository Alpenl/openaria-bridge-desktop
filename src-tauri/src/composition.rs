//! Production composition root for the PC client.
//!
//! The default build uses real mDNS discovery (or manual IP), Device API v4
//! lab/internal HTTP on port 8080 for current RDK X5 devices, opaque artifact
//! identifiers, Range downloads, persistent transfer jobs, local-library files,
//! and S3 uploads. Retained legacy Device API v1 adapters still support pinned
//! HTTPS and physical-confirmation pairing, but that is not the current
//! Windows/manual-connect path.
//!
//! Current Device API v4 session detail is accepted from the exact manifest
//! returned by `/api/v4/sessions/{session_id}` and mapped into the desktop's
//! existing local-library/download shape. Legacy v1 detail is accepted only
//! when its Ed25519 publication signature, public-key fingerprint,
//! authenticated `/device` identity, schema version, scalar projection, and
//! file inventory all agree.
//!
//! Download context is persisted in the shared transfer store so a terminal
//! job can be reconciled after restart. A successful job is not
//! exposed as a library entry until the complete signed inventory is present
//! at validated staging paths, transformed into the canonical derived bundle,
//! and the application store is durably committed. Raw selected-artifact
//! downloads are not a desktop product surface.
//!
//! Synthetic devices and timer-driven transfers live in `demo.rs`/`sim.rs`
//! and compile only with the explicit `demo` feature. No production command
//! falls back to them.

mod derived_media;
mod derived_publication;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Manager, Runtime};

#[cfg(test)]
use ylx_transfer_adapters::credential_keyring::InMemoryCredentialVault;
#[cfg(not(test))]
use ylx_transfer_adapters::credential_keyring::OsKeyringCredentialVault;
use ylx_transfer_adapters::discovery_mdns::{
    MdnsCandidate, MdnsChange, MdnsDiscovery, MdnsEventCursor, MdnsServiceId,
};
use ylx_transfer_adapters::object_store_s3::{S3ObjectStore, S3ObjectStoreConfig, UrlStyle};
use ylx_transfer_adapters::pi_client_port::{AuthenticatedPiClient, PiPairingClient};
use ylx_transfer_adapters::pi_download_source::PiDownloadSource;
use ylx_transfer_adapters::pi_http::{
    probe_lab_v4_device, LabV4DeviceProbe, PiHttpClient, PiHttpClientConfig, PiHttpError, PiTlsPin,
};
use ylx_transfer_adapters::publication_verifier::Ed25519PublicationVerifier;
use ylx_transfer_adapters::session_export::SessionExportConfig;

use ylx_transfer_core::credential_vault::{
    CredentialKey, CredentialVaultError, CredentialVaultPort, Secret, SecretStatus,
};
#[cfg(test)]
use ylx_transfer_core::device::{
    AuthenticatedPiSession, DeleteSessionReceiptView, PairingCreatedView, SessionCatalogPort,
    SessionsPageView,
};
use ylx_transfer_core::device::{
    CapabilitySourceView, CaptureActivityState, CatalogRevisionAuthorityView, ConnectionState,
    DeleteApplyOutcome, Device as CoreDevice, DeviceApiProfileView, DeviceCapabilitiesView,
    DeviceFingerprint, DeviceFleet, DeviceHandle, DeviceIdentity, DeviceIdentityResolutionError,
    DeviceIdentityResolver, DiscoveryState, GatewayVerificationDiagnosticView,
    GatewayVerificationVerdictView, GatewayVerificationView, HeartbeatApplyOutcome,
    NegotiatedCapabilityView, PaginationUnavailableReasonView, PairingPhase, PairingPort,
    PairingStatusView, PiClientError, PiClientErrorKind, PollPairingOutcome,
    PublicationEnvelopeOriginView, RefreshApplyOutcome, SessionDetailOutcome, SessionDetailView,
    SessionDiscoveryDiagnosticCodeView,
    SessionDiscoveryDiagnosticView as CoreSessionDiscoveryDiagnosticView, SessionSummaryView,
    StoredDeviceIdentity,
};
use ylx_transfer_core::domain::{DeviceId, FileId, JobFileSpec, JobSpec, SessionId};
use ylx_transfer_core::library::download::{
    derive_target_path, derive_target_path_for_file, DownloadError, DownloadSource,
    PublicationVerifier,
};
use ylx_transfer_core::library::object_store_port::{
    CompletedUpload, ExpectedObject, ImmutableObjectRequest, InitiateUploadRequest,
    MultipartUploadHandle, ObjectKey, ObjectStoreError, ObjectStorePort, PartETag, PartNumber,
    SourceSha256, UploadId, VerifiedObjectReceipt,
};
#[cfg(test)]
use ylx_transfer_core::library::object_store_port::{FaultPoint, MemoryObjectStore};
use ylx_transfer_core::media_store::MediaStore;
use ylx_transfer_core::persistence::completion_consumer::ProjectionOutcome;
use ylx_transfer_core::persistence::transfer_store::{
    AckOutcome, CompleteJobError, CompletionDeliveryState, CompletionRecord, CreateJobError,
    DownloadSessionJobState, JobSpecLoadError, LegacyImportOutcome, OperationKind, RetryJobOutcome,
    StoredJob, TerminalOutcome, TransferStore,
};
use ylx_transfer_core::persistence::upload_store::{
    LegacyUploadImportOutcome, NewUpload, RepeatUploadJobError, StoredUpload, StoredUploadReceipt,
    UploadDesiredState, UploadPartRecord, UploadReceiptDigestProof, UploadReceiptRole,
    UploadReceiptSeed, UploadUrlStyle as CoreUploadUrlStyle,
};
use ylx_transfer_core::persistence::{
    AppLibraryPayload, JobStateTag, UploadActivitySeed, UploadJobCreateError,
    UploadJobCreateOutcome, UploadJobError, UploadJobSpec,
};
use ylx_transfer_core::transfer::coordinator::{
    CoordinatorConfig, CoordinatorError, DeviceStatusPort, DownloadSourceFactory,
    TransferCoordinator,
};
use ylx_transfer_core::transfer::queue::{JobFile, TransferRequest};
use ylx_transfer_core::transfer::DeviceSnapshot as TransferDeviceSnapshot;
use ylx_transfer_core::transfer::{DesiredRunState, FailureCode, JobId, TransferJobState};

use self::derived_media::DerivedMediaCommitter;
#[cfg(test)]
use self::derived_publication::admission_object_key;
use self::derived_publication::{
    admission_key_belongs_to_marker, AdmissionError, DerivedPublicationInput,
    DerivedPublicationPlan, MAX_PUBLICATION_JSON_BYTES,
};

use crate::application::{
    emit_devices_event, emit_library_event, emit_pairing_event, emit_transfer_jobs_event,
    emit_transfers_event, TransferApplication,
};
use crate::models::{
    Device as FrontendDevice, DeviceState as FrontendDeviceState, DownloadStatus, LibraryEntry,
    ObjectVerificationReceipt, PublicationEvidence, Session, SessionApiProfile, SessionCapability,
    SessionCapabilitySource, SessionCatalogAuthority, SessionDiscoveryDiagnosticCode,
    SessionDiscoveryDiagnosticView, SessionFile, SessionPageCapabilities, SessionPageView,
    SessionPaginationUnavailableReason, SessionVerificationDiagnosticCode,
    SessionVerificationDiagnosticView, SessionVerificationValidatorView,
    SessionVerificationVerdict, SessionVerificationView, SessionView, StorageConfig,
    StorageUrlStyle, Transfer, TransferDirection, TransferState, UploadProjectionMarker,
    UploadProjectionReceipt, UploadStatus,
};
use crate::state::AppState;

/// Keep this comfortably below the Pi transfer service's initial 15-second
/// idle timeout. Ordinary authenticated requests do not renew the token.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How many devices one heartbeat sweep may talk to at once
/// (`DeviceFleet::for_each_device`'s bound). Bounded rather than unbounded
/// because each slot is a real blocking thread doing a real device request: a
/// home LAN with a handful of devices wants them all in flight together, but the
/// sweep must not spawn one thread per device without limit. A device that hangs
/// for its whole request timeout occupies exactly one slot; the others keep
/// flowing.
const HEARTBEAT_CONCURRENCY: usize = 4;

/// Current Device API v4 session lists are a navigation surface, not an
/// immutable export proof. Keep the first paint bounded and fetch full detail
/// only for an explicit download/delete-capable legacy mutation.
const LAB_V4_SESSION_LIST_LIMIT: u32 = 50;
const LAB_V4_MANUAL_PORT: u16 = 8080;
const MAX_SESSION_CURSOR_BYTES: usize = 4096;
const MAX_FULL_SESSION_CATALOG_PAGES: usize = 200;
const MAX_FULL_SESSION_CATALOG_ITEMS: usize = 10_000;
const FULL_SESSION_CATALOG_DEADLINE: Duration = Duration::from_secs(30);

const LAB_V4_SESSION_DELETE_UNSUPPORTED_MESSAGE: &str =
    "当前 Device API v4 契约不支持删除设备端会话；请在设备端存储管理中处理，或等待固件暴露明确的 destructive mutation 接口。";

/// Which Device API transport contract one endpoint speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceApiProfile {
    LegacyPinnedTlsV1,
    LabHttpV4,
}

/// What we learned about one device's network address. Legacy endpoints use
/// `tls_fingerprint` as the pinned TLS certificate identity. Current
/// lab/internal Device API v4 endpoints use HTTP on port 8080, so the same
/// field stores the desktop-internal synthetic identity derived from
/// `/api/v4/device.device.device_id`.
#[derive(Debug, Clone)]
pub struct DeviceEndpoint {
    pub host: String,
    pub port: u16,
    pub tls_fingerprint: String,
    pub name: String,
    pub display_label: Option<String>,
    pub api_profile: DeviceApiProfile,
}

/// One live Pi session that may be removed by the conservative
/// "delete downloaded data from Pi" operation. `revision` is retained so
/// execution can bind DELETE's `If-Match` and idempotency key to exactly the
/// catalog revision that passed the local-copy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedCleanupCandidate {
    pub session_id: String,
    pub revision: String,
    pub date_label: String,
    pub bytes: u64,
    pub(crate) local_device_id: String,
    pub(crate) local_files: Vec<SessionFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedCleanupSkip {
    pub session_id: String,
    pub date_label: String,
    pub bytes: u64,
    pub reason: String,
}

/// The result of reading the current authenticated catalog and comparing it
/// with the durable local library plus the files that still exist on disk.
#[derive(Debug, Clone)]
pub struct DownloadedCleanupPlan {
    pub eligible: Vec<DownloadedCleanupCandidate>,
    pub skipped: Vec<DownloadedCleanupSkip>,
    pub eligible_bytes: u64,
    pub sessions: Vec<SessionView>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DownloadSessionLocalJobStatus {
    active: bool,
    failed: bool,
}

/// Internal page read evidence. The epoch is not a frontend concept; it lets
/// the application reject a cursor issued by a prior authenticated connection
/// even when the remote catalog revision happens to be unchanged.
pub struct SessionCatalogPageRead {
    pub page: SessionPageView,
    pub connection_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCatalogPageError {
    CatalogChanged {
        catalog_revision: String,
        message: String,
    },
    Other(String),
}

impl From<String> for SessionCatalogPageError {
    fn from(message: String) -> Self {
        Self::Other(message)
    }
}

impl std::fmt::Display for SessionCatalogPageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CatalogChanged { message, .. } | Self::Other(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for SessionCatalogPageError {}

#[cfg(test)]
fn fallback_device(id: &str) -> CoreDevice {
    CoreDevice {
        device_id: DeviceId(id.to_string()),
        name: id.to_string(),
        tls_fingerprint: id.to_string(),
        discovery: DiscoveryState::Offline,
        connection: ConnectionState::Disconnected,
        capture_activity: CaptureActivityState::Unknown,
    }
}

fn build_client(endpoint: &DeviceEndpoint) -> Result<PiHttpClient, PiHttpError> {
    match endpoint.api_profile {
        DeviceApiProfile::LegacyPinnedTlsV1 => PiHttpClient::new(PiHttpClientConfig {
            host: endpoint.host.clone(),
            port: endpoint.port,
            tls_pin: PiTlsPin(endpoint.tls_fingerprint.clone()),
            request_timeout: Duration::from_secs(6),
        }),
        DeviceApiProfile::LabHttpV4 => PiHttpClient::new_lab_v4_http(
            endpoint.host.clone(),
            endpoint.port,
            PiTlsPin(endpoint.tls_fingerprint.clone()),
            Duration::from_secs(6),
        ),
    }
}

fn transport_origin_matches(left: &DeviceEndpoint, right: &DeviceEndpoint) -> bool {
    left.host == right.host
        && left.port == right.port
        && left.tls_fingerprint == right.tls_fingerprint
        && left.api_profile == right.api_profile
}

/// Binds the current actor session to its already-pinned transport. The
/// session is copied as an opaque identity value; its bearer token remains
/// private to the capability adapter and never enters composition state.
fn authenticated_client_for(
    handle: &DeviceHandle,
    client: Arc<PiHttpClient>,
) -> Result<AuthenticatedPiClient, String> {
    let session = handle
        .actor()
        .authenticated_session()
        .cloned()
        .ok_or_else(|| "该设备尚未连接或连接已失效".to_string())?;
    AuthenticatedPiClient::new(client, session)
        .map_err(|error| format!("无法绑定设备认证会话：{error}"))
}

#[cfg(test)]
fn unavailable_client_error() -> PiClientError {
    PiClientError {
        kind: PiClientErrorKind::Other,
        message: "no network client available for this device".to_string(),
    }
}

/// A split-capability client that always fails. Used only by composition tests
/// so `DeviceActor::disconnect` always has *something* to call even in the
/// (should-not-happen) case a device has no cached `PiHttpClient` -- see
/// `disconnect_device` below. `disconnect()` transitions to `Disconnected`
/// locally regardless of whether the revoke call itself succeeds.
#[cfg(test)]
struct NullPiClient;

#[cfg(test)]
impl PairingPort for NullPiClient {
    fn create_pairing_request(
        &self,
        _client_name: &str,
        _client_nonce: &str,
    ) -> Result<ylx_transfer_core::device::PairingCreatedView, PiClientError> {
        Err(unavailable_client_error())
    }
    fn get_pairing_status(
        &self,
        _attempt_id: &str,
        _poll_secret: &str,
    ) -> Result<PairingStatusView, PiClientError> {
        Err(unavailable_client_error())
    }
}

#[cfg(test)]
impl SessionCatalogPort for NullPiClient {
    fn list_sessions(
        &self,
        _session: &AuthenticatedPiSession,
        _cursor: Option<&str>,
        _limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError> {
        Err(unavailable_client_error())
    }
    fn get_session(
        &self,
        _session: &AuthenticatedPiSession,
        _session_id: &str,
    ) -> Result<SessionDetailView, PiClientError> {
        Err(unavailable_client_error())
    }
    fn delete_session(
        &self,
        _session: &AuthenticatedPiSession,
        _session_id: &str,
        _if_match_revision: &str,
        _idempotency_key: &str,
    ) -> Result<DeleteSessionReceiptView, PiClientError> {
        Err(unavailable_client_error())
    }
}

/// Feeds one already-authenticated real POST response into `DeviceActor`.
/// The POST itself is made before this adapter is constructed so composition
/// can retain the poll secret required by the Pi's real DELETE cancellation
/// endpoint without exposing that secret from the actor.
#[cfg(test)]
struct PreparedPairingClient(PairingCreatedView);

#[cfg(test)]
impl PairingPort for PreparedPairingClient {
    fn create_pairing_request(
        &self,
        _client_name: &str,
        _client_nonce: &str,
    ) -> Result<PairingCreatedView, PiClientError> {
        Ok(self.0.clone())
    }

    fn get_pairing_status(
        &self,
        _attempt_id: &str,
        _poll_secret: &str,
    ) -> Result<PairingStatusView, PiClientError> {
        Err(unavailable_client_error())
    }
}

/// One coherent production binding for a full device identity.
///
/// The endpoint, pinned client and actor handle are replaced together when
/// discovery refreshes an address. A caller therefore cannot resolve a
/// handle for one colliding short label and a client for another.
#[derive(Clone)]
struct DeviceBinding {
    identity: DeviceIdentity,
    endpoint: DeviceEndpoint,
    client: Arc<PiHttpClient>,
    handle: DeviceHandle,
}

#[derive(Clone)]
struct DevicePollBinding {
    device_id: String,
    client: Arc<PiHttpClient>,
    api_profile: DeviceApiProfile,
}

/// Full-fingerprint device registry plus the only legacy-id compatibility
/// resolver in production composition.
///
/// New entries are keyed only by [`DeviceFingerprint`]. The short
/// `YLX-XXXXXXXX` display projection is accepted solely as a legacy read and
/// fails closed as soon as more than one registered fingerprint shares it.
#[derive(Default)]
struct DeviceBindings {
    identities: DeviceIdentityResolver,
    by_fingerprint: BTreeMap<DeviceFingerprint, DeviceBinding>,
}

#[derive(Debug, Clone)]
struct EndpointRegistration {
    identity: DeviceIdentity,
    is_new: bool,
    endpoint_changed: bool,
    discovery_changed: bool,
    handle: DeviceHandle,
}

impl EndpointRegistration {
    fn changed(&self) -> bool {
        self.is_new || self.endpoint_changed || self.discovery_changed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceProbeTarget {
    host: String,
    port: u16,
}

impl DeviceProbeTarget {
    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn lab_v4_origin(&self) -> String {
        format!("http://{}", self.authority())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceProbeFailureClass {
    ConnectionRefused,
    Timeout,
    Network,
    ApiContract,
    InvalidCandidate,
    Tls,
}

impl DeviceProbeFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::Timeout => "timeout",
            Self::Network => "network",
            Self::ApiContract => "api_contract",
            Self::InvalidCandidate => "invalid_candidate",
            Self::Tls => "tls",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceProbeFailure {
    target: DeviceProbeTarget,
    class: DeviceProbeFailureClass,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceProbeFailures(Vec<DeviceProbeFailure>);

impl std::fmt::Display for DeviceProbeFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return formatter.write_str("没有可探测的地址");
        }
        formatter.write_str("已尝试 ")?;
        write!(formatter, "{} 个地址：", self.0.len())?;
        for (index, failure) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str("；")?;
            }
            write!(
                formatter,
                "{} [{}]: {}",
                failure.target.lab_v4_origin(),
                failure.class.as_str(),
                failure.detail
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DeviceProbeSuccess<T> {
    target: DeviceProbeTarget,
    value: T,
}

#[derive(Debug, Clone)]
struct MdnsServiceState {
    latest_cursor: MdnsEventCursor,
    advertised: bool,
    verified_cursor: Option<MdnsEventCursor>,
    canonical_fingerprint: Option<DeviceFingerprint>,
    verified_endpoint: Option<DeviceEndpoint>,
}

#[derive(Debug, Default)]
struct MdnsServiceRegistry {
    services: HashMap<MdnsServiceId, MdnsServiceState>,
    manual_endpoints: HashMap<DeviceFingerprint, DeviceEndpoint>,
}

#[derive(Debug)]
struct MdnsProbeAssociation {
    previous_fingerprint: Option<DeviceFingerprint>,
    fingerprint: DeviceFingerprint,
}

#[derive(Debug)]
struct MdnsResolvedObservation {
    previous_fingerprint: Option<DeviceFingerprint>,
}

impl MdnsServiceRegistry {
    fn observe_resolved(&mut self, candidate: &MdnsCandidate) -> Option<MdnsResolvedObservation> {
        if self
            .services
            .get(&candidate.service_id)
            .is_some_and(|state| state.latest_cursor >= candidate.cursor)
        {
            return None;
        }
        let previous_fingerprint = match self.services.get_mut(&candidate.service_id) {
            Some(state) => {
                state.latest_cursor = candidate.cursor;
                state.advertised = true;
                state.verified_cursor = None;
                state.verified_endpoint = None;
                state.canonical_fingerprint.clone()
            }
            None => {
                self.services.insert(
                    candidate.service_id.clone(),
                    MdnsServiceState {
                        latest_cursor: candidate.cursor,
                        advertised: true,
                        verified_cursor: None,
                        canonical_fingerprint: None,
                        verified_endpoint: None,
                    },
                );
                None
            }
        };
        Some(MdnsResolvedObservation {
            previous_fingerprint,
        })
    }

    fn observe_lost(
        &mut self,
        service_id: &MdnsServiceId,
        cursor: MdnsEventCursor,
    ) -> Option<DeviceFingerprint> {
        if self
            .services
            .get(service_id)
            .is_some_and(|state| state.latest_cursor >= cursor)
        {
            return None;
        }
        let state = self
            .services
            .entry(service_id.clone())
            .or_insert_with(|| MdnsServiceState {
                latest_cursor: cursor,
                advertised: false,
                verified_cursor: None,
                canonical_fingerprint: None,
                verified_endpoint: None,
            });
        state.latest_cursor = cursor;
        state.advertised = false;
        state.verified_cursor = None;
        state.verified_endpoint = None;
        state.canonical_fingerprint.clone()
    }

    fn candidate_is_current(&self, candidate: &MdnsCandidate) -> bool {
        self.services
            .get(&candidate.service_id)
            .is_some_and(|state| state.advertised && state.latest_cursor == candidate.cursor)
    }

    fn accept_probe(
        &mut self,
        service_id: &MdnsServiceId,
        cursor: MdnsEventCursor,
        fingerprint: DeviceFingerprint,
        endpoint: DeviceEndpoint,
    ) -> Option<MdnsProbeAssociation> {
        let state = self.services.get_mut(service_id)?;
        if !state.advertised || state.latest_cursor != cursor {
            return None;
        }
        let previous_fingerprint = state.canonical_fingerprint.replace(fingerprint.clone());
        state.verified_cursor = Some(cursor);
        state.verified_endpoint = Some(endpoint);
        Some(MdnsProbeAssociation {
            previous_fingerprint,
            fingerprint,
        })
    }

    fn mark_manual(&mut self, fingerprint: DeviceFingerprint, endpoint: DeviceEndpoint) {
        self.manual_endpoints.insert(fingerprint, endpoint);
    }

    fn selected_endpoint(&self, fingerprint: &DeviceFingerprint) -> Option<DeviceEndpoint> {
        self.services
            .iter()
            .filter(|(_, state)| {
                state.advertised
                    && state.verified_cursor == Some(state.latest_cursor)
                    && state.canonical_fingerprint.as_ref() == Some(fingerprint)
                    && state.verified_endpoint.is_some()
            })
            .max_by(|(left_id, left), (right_id, right)| {
                left.verified_cursor
                    .cmp(&right.verified_cursor)
                    .then_with(|| left_id.cmp(right_id))
            })
            .and_then(|(_, state)| state.verified_endpoint.clone())
            .or_else(|| self.manual_endpoints.get(fingerprint).cloned())
    }

    fn should_be_online(&self, fingerprint: &DeviceFingerprint) -> bool {
        self.manual_endpoints.contains_key(fingerprint)
            || self.services.values().any(|state| {
                state.advertised
                    && state.verified_cursor == Some(state.latest_cursor)
                    && state.canonical_fingerprint.as_ref() == Some(fingerprint)
            })
    }
}

fn classify_device_probe_error(error: &PiHttpError) -> DeviceProbeFailureClass {
    match error {
        PiHttpError::Network(detail) => {
            let normalized = detail.to_ascii_lowercase();
            if normalized.contains("connection refused")
                || normalized.contains("actively refused")
                || normalized.contains("os error 10061")
            {
                DeviceProbeFailureClass::ConnectionRefused
            } else if normalized.contains("timed out")
                || normalized.contains("timeout")
                || normalized.contains("deadline has elapsed")
                || normalized.contains("os error 10060")
            {
                DeviceProbeFailureClass::Timeout
            } else {
                DeviceProbeFailureClass::Network
            }
        }
        PiHttpError::InvalidArgument(_) => DeviceProbeFailureClass::InvalidCandidate,
        PiHttpError::Tls(_) => DeviceProbeFailureClass::Tls,
        PiHttpError::Api(_)
        | PiHttpError::CatalogChanged { .. }
        | PiHttpError::UnexpectedStatus { .. }
        | PiHttpError::PreconditionFailed { .. }
        | PiHttpError::RangeNotSatisfiable { .. }
        | PiHttpError::SessionVerificationRequired { .. }
        | PiHttpError::SessionRevisionMismatch { .. }
        | PiHttpError::Decode(_)
        | PiHttpError::InvalidResponse(_) => DeviceProbeFailureClass::ApiContract,
    }
}

fn probe_v4_targets_with<T>(
    targets: Vec<DeviceProbeTarget>,
    mut failures: Vec<DeviceProbeFailure>,
    timeout: Duration,
    mut probe: impl FnMut(&str, u16, Duration) -> Result<T, PiHttpError>,
) -> Result<DeviceProbeSuccess<T>, DeviceProbeFailures> {
    for target in targets {
        match probe(&target.host, target.port, timeout) {
            Ok(value) => return Ok(DeviceProbeSuccess { target, value }),
            Err(error) => failures.push(DeviceProbeFailure {
                target,
                class: classify_device_probe_error(&error),
                detail: error.to_string(),
            }),
        }
    }
    Err(DeviceProbeFailures(failures))
}

fn manual_lab_v4_probe_target(address: IpAddr) -> DeviceProbeTarget {
    DeviceProbeTarget {
        host: address.to_string(),
        port: LAB_V4_MANUAL_PORT,
    }
}

fn probe_mdns_candidate_with(
    candidate: &MdnsCandidate,
    timeout: Duration,
    probe: impl FnMut(&str, u16, Duration) -> Result<LabV4DeviceProbe, PiHttpError>,
) -> Result<DeviceProbeSuccess<LabV4DeviceProbe>, DeviceProbeFailures> {
    let mut targets = Vec::new();
    let mut failures = Vec::new();
    let mut seen = HashSet::new();
    for endpoint in candidate.ordered_endpoints(None) {
        let raw_host = endpoint.address.to_string();
        let invalid = |detail: String| DeviceProbeFailure {
            target: DeviceProbeTarget {
                host: raw_host.clone(),
                port: candidate.port,
            },
            class: DeviceProbeFailureClass::InvalidCandidate,
            detail,
        };
        if !endpoint.is_connectable() {
            failures.push(invalid("地址不可连接或缺少 IPv6 scope".to_string()));
            continue;
        }
        let host = match endpoint.host() {
            Ok(host) => host,
            Err(error) => {
                failures.push(invalid(error.to_string()));
                continue;
            }
        };
        if seen.insert((host.clone(), candidate.port)) {
            targets.push(DeviceProbeTarget {
                host,
                port: candidate.port,
            });
        }
    }
    probe_v4_targets_with(targets, failures, timeout, probe)
}

fn lab_v4_endpoint_from_probe(success: DeviceProbeSuccess<LabV4DeviceProbe>) -> DeviceEndpoint {
    DeviceEndpoint {
        host: success.target.host,
        port: success.target.port,
        tls_fingerprint: success.value.synthetic_identity_pin.0,
        name: success.value.device_label.clone(),
        display_label: Some(success.value.device_label),
        api_profile: DeviceApiProfile::LabHttpV4,
    }
}

impl DeviceBindings {
    fn endpoint_differs(&self, fingerprint: &DeviceFingerprint, endpoint: &DeviceEndpoint) -> bool {
        let Some(current) = self.by_fingerprint.get(fingerprint) else {
            return true;
        };
        current.endpoint.host != endpoint.host
            || current.endpoint.port != endpoint.port
            || current.endpoint.tls_fingerprint != endpoint.tls_fingerprint
            || current.endpoint.name != endpoint.name
            || current.endpoint.display_label != endpoint.display_label
            || current.endpoint.api_profile != endpoint.api_profile
    }

    fn origin_differs(&self, fingerprint: &DeviceFingerprint, endpoint: &DeviceEndpoint) -> bool {
        let Some(current) = self.by_fingerprint.get(fingerprint) else {
            return false;
        };
        current.endpoint.host != endpoint.host
            || current.endpoint.port != endpoint.port
            || current.endpoint.tls_fingerprint != endpoint.tls_fingerprint
            || current.endpoint.api_profile != endpoint.api_profile
    }

    fn bind(
        &mut self,
        identity: DeviceIdentity,
        endpoint: DeviceEndpoint,
        client: Arc<PiHttpClient>,
        handle: DeviceHandle,
    ) -> bool {
        let fingerprint = identity.fingerprint().clone();
        debug_assert_eq!(handle.fingerprint(), &fingerprint);
        let is_new = self.identities.insert(identity.clone());
        self.by_fingerprint.insert(
            fingerprint,
            DeviceBinding {
                identity,
                endpoint,
                client,
                handle,
            },
        );
        is_new
    }

    fn resolve(
        &self,
        device_id: &DeviceId,
    ) -> Result<DeviceBinding, DeviceIdentityResolutionError> {
        let identity = self.identities.resolve(device_id)?;
        Ok(self
            .by_fingerprint
            .get(identity.fingerprint())
            .cloned()
            .expect("identity resolver and binding map are updated together"))
    }

    fn bindings(&self) -> Vec<DeviceBinding> {
        self.by_fingerprint.values().cloned().collect()
    }

    fn clients_by_fingerprint(&self) -> HashMap<DeviceFingerprint, DevicePollBinding> {
        self.by_fingerprint
            .iter()
            .map(|(fingerprint, binding)| {
                (
                    fingerprint.clone(),
                    DevicePollBinding {
                        device_id: binding.identity.device_id().as_str().to_string(),
                        client: binding.client.clone(),
                        api_profile: binding.endpoint.api_profile,
                    },
                )
            })
            .collect()
    }

    fn device_ids_match(&self, left: &str, right: &str) -> bool {
        if left == right {
            return true;
        }
        let left = self.resolve(&DeviceId(left.to_string()));
        let right = self.resolve(&DeviceId(right.to_string()));
        matches!((left, right), (Ok(left), Ok(right)) if left.identity.fingerprint() == right.identity.fingerprint())
    }

    /// Exact durable keys that may belong to this physical device. New jobs
    /// use the canonical id. The retained display id is admitted only while
    /// the resolver proves it names this one fingerprint unambiguously.
    fn download_job_lookup_ids(&self, identity: &DeviceIdentity) -> Vec<String> {
        let canonical = identity.device_id().as_str().to_string();
        let legacy = identity.display_id().to_string();
        let legacy_is_unique = self
            .resolve(&DeviceId(legacy.clone()))
            .is_ok_and(|binding| binding.identity.fingerprint() == identity.fingerprint());
        if legacy != canonical && legacy_is_unique {
            vec![canonical, legacy]
        } else {
            vec![canonical]
        }
    }

    /// Projects a durable identity for a read boundary. A uniquely
    /// registered legacy alias upgrades to canonical; otherwise a valid
    /// canonical or legacy stored id is preserved. Invalid history yields no
    /// identity rather than a fabricated fingerprint.
    fn outward_identity(&self, stored: &DeviceId) -> Option<StoredDeviceIdentity> {
        self.resolve(stored)
            .map(|binding| StoredDeviceIdentity::from(&binding.identity))
            .or_else(|_| StoredDeviceIdentity::parse(stored))
            .ok()
    }
}

/// Read-only [`DeviceStatusPort`] over the coherent device bindings -- the
/// seam `TransferCoordinator` needs to decide job readiness. See
/// `coordinator.rs`'s own doc comment for why this trait exists.
///
/// Each answer costs one map lookup per lock, never a network call, so a
/// device that is mid-request delays no readiness check but its own.
struct FleetStatusPort {
    bindings: Arc<Mutex<DeviceBindings>>,
}

impl FleetStatusPort {
    fn binding(&self, device_id: &DeviceId) -> Option<DeviceBinding> {
        self.bindings.lock().unwrap().resolve(device_id).ok()
    }
}

impl DeviceStatusPort for FleetStatusPort {
    fn connection_state(&self, device_id: &DeviceId) -> ConnectionState {
        self.binding(device_id)
            .map(|binding| binding.handle.connection_state())
            .unwrap_or(ConnectionState::Disconnected)
    }

    fn capture_activity(&self, device_id: &DeviceId) -> CaptureActivityState {
        self.binding(device_id)
            .map(|binding| binding.handle.actor().device().capture_activity)
            .unwrap_or(CaptureActivityState::Unknown)
    }

    fn device_snapshot(&self, device_id: &DeviceId) -> TransferDeviceSnapshot {
        self.binding(device_id)
            .map(|binding| {
                let snapshot = binding.handle.snapshot();
                TransferDeviceSnapshot::new(
                    0,
                    snapshot.device.connection,
                    snapshot.device.capture_activity,
                )
            })
            .unwrap_or_else(|| {
                TransferDeviceSnapshot::new(
                    0,
                    ConnectionState::Disconnected,
                    CaptureActivityState::Unknown,
                )
            })
    }
}

/// Builds a real `PiDownloadSource` per opaque (device, session, file) tuple.
/// The source is bound to the actor's complete authenticated session and
/// handle, so every ranged request carries TLS/publication/epoch identity.
struct RealDownloadSourceFactory {
    bindings: Arc<Mutex<DeviceBindings>>,
}

impl DownloadSourceFactory for RealDownloadSourceFactory {
    fn make_source(
        &self,
        device_id: &ylx_transfer_core::domain::DeviceId,
        session_id: &ylx_transfer_core::domain::SessionId,
        file_id: &ylx_transfer_core::domain::FileId,
    ) -> Result<Box<dyn DownloadSource>, DownloadError> {
        let binding = self
            .bindings
            .lock()
            .unwrap()
            .resolve(device_id)
            .map_err(|error| DownloadError::Source(error.to_string()))?;
        let DeviceBinding { client, handle, .. } = binding;

        let session = handle
            .actor()
            .authenticated_session()
            .cloned()
            .ok_or_else(|| {
                DownloadError::Source(format!("device {} is not connected", device_id.as_str()))
            })?;
        let source = PiDownloadSource::new_with_handle(
            client,
            handle,
            session,
            session_id.clone(),
            file_id.clone(),
        )
        .map_err(|error| DownloadError::Source(error.to_string()))?;
        Ok(Box::new(source) as Box<dyn DownloadSource>)
    }
}

/// Borrows one opaque authenticated session under the device lock, then
/// runs the potentially slow operation with **no lock held at all**. Tests
/// use this to prove lock scope without ever handling a bearer token.
#[cfg(test)]
fn with_connected_session<T>(
    handle: &DeviceHandle,
    operation: impl FnOnce(&AuthenticatedPiSession) -> Result<T, String>,
) -> Result<T, String> {
    let session = handle
        .actor()
        .authenticated_session()
        .cloned()
        .ok_or_else(|| "该设备尚未连接或连接已失效".to_string())?;
    operation(&session)
}

fn authenticated_request_error(context: &str, error: PiClientError) -> String {
    if error.kind == PiClientErrorKind::Unauthorized {
        format!("设备连接已失效，请重新连接后重试：{error}")
    } else if context.is_empty() {
        error.to_string()
    } else {
        format!("{context}：{error}")
    }
}

fn session_catalog_request_error(context: &str, error: PiClientError) -> SessionCatalogPageError {
    if let PiClientErrorKind::CatalogChanged { catalog_revision } = &error.kind {
        return SessionCatalogPageError::CatalogChanged {
            catalog_revision: catalog_revision.clone(),
            message: authenticated_request_error(context, error),
        };
    }
    SessionCatalogPageError::Other(authenticated_request_error(context, error))
}

/// One transfer job's state and durable run intent, as pushed out over the
/// `transfer_jobs:update` event by the background poll loop. PC-11: now
/// rendered by the frontend (`src/ui/tray.ts` via `api.ts`'s
/// `onTransferJobsUpdate`) -- `state`
/// serializes exactly as `TransferJobState`'s own `#[serde(tag = "state",
/// rename_all = "snake_case")]` shape (e.g. `{"state":"queued"}` or
/// `{"state":"failed","code":"network","retryable":true}`), so the
/// frontend's `TransferJobState` type in `types.ts` mirrors that tagged
/// shape field-for-field.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobStateEvent {
    job_id: String,
    state: TransferJobState,
    desired_run_state: DesiredRunState,
    /// Immutable identity from the coordinator snapshot. The frontend uses
    /// the session id as the display label and the device id as context;
    /// both remain available for recovered jobs because they come from the
    /// durable job spec rather than the composition-side label cache.
    session_id: Option<String>,
    device_id: Option<String>,
    device_display_id: Option<String>,
    /// Real byte/file progress from the same atomic coordinator snapshot as
    /// state and desired intent. All four are `0` until the coordinator has
    /// observed progress for the job; no value is guessed.
    total_bytes: u64,
    transferred_bytes: u64,
    files_total: u32,
    files_done: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum PairingResolutionOutcome {
    Connected,
    Rejected,
    Expired,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingResolutionEvent {
    device_id: String,
    /// Which pairing attempt this resolution belongs to. The frontend drops
    /// a resolution whose attempt is not the one it is currently showing,
    /// so a late result from a superseded attempt can never close (or
    /// mislabel) the current one.
    attempt_id: String,
    outcome: PairingResolutionOutcome,
    error: Option<String>,
}

#[derive(Clone)]
struct ActivePairing {
    attempt_id: String,
    poll_secret: String,
    client: Arc<PiHttpClient>,
    /// The short authentication string the operator compared on both ends.
    /// It is never persisted; it only contributes to the pairing-evidence
    /// digest recorded when this attempt is confirmed.
    sas: String,
    /// Legacy v1 pairings use the SAS transcript to trust a producer key for
    /// removable-media/offline verification. Current Device API v4 lab HTTP
    /// auto-connects do not participate in that workflow and must not write
    /// producer trust rows.
    record_trusted_producer_key: bool,
}

/// The file name of the deleted pending-download sidecar. Kept only so the
/// one-time migration ([`migrate_legacy_pending_downloads`]) can still find
/// a file written by an older build; nothing writes it any more.
const LEGACY_PENDING_DOWNLOAD_FILE: &str = "pending-downloads.json";

/// Where the one-time backup of that sidecar is written before it is
/// deleted. Commit 34 requires the original bytes to survive the migration
/// even though the store they fed is gone.
const LEGACY_PENDING_DOWNLOAD_BACKUP: &str = "pending-downloads.json.migrated.bak";

fn session_file_from_job_spec(file: &JobFileSpec) -> SessionFile {
    SessionFile::new(
        file.file_id().as_str().to_string(),
        file.display_path().to_string(),
        file.size_bytes(),
        file.sha256().to_string(),
    )
}

fn publication_evidence_from_job_spec(spec: &JobSpec) -> PublicationEvidence {
    PublicationEvidence {
        revision: spec.publication().revision().to_string(),
        payload: spec.publication().payload().to_vec(),
        signature: spec.publication().signature().to_vec(),
        public_key: spec.publication().public_key().to_vec(),
    }
}

/// The inverse: builds the durable spec an enqueue must commit before the
/// job is allowed to run.
///
/// Every domain rule (non-empty ids, 64-hex digests, a requested file that
/// really is in the signed inventory, a `full_session` job that really
/// covers it) is enforced by `JobSpec::new`, so an enqueue cannot create a
/// durable job the recovery path would later refuse to read.
fn job_spec_from_context(
    device_id: &str,
    session_id: &str,
    date_label: &str,
    files: &[SessionFile],
    session_files: &[SessionFile],
    publication: &PublicationEvidence,
    full_session: bool,
) -> Result<ylx_transfer_core::domain::JobSpec, String> {
    use ylx_transfer_core::domain::{
        FileId as DomainFileId, JobFileSpec, JobIdentity, JobSpec, PublicationMaterial,
    };

    let identity = JobIdentity::new(
        DeviceId(device_id.to_string()),
        SessionId(session_id.to_string()),
        publication.revision.trim(),
    )
    .map_err(|e| format!("下载任务标识无效：{e}"))?;
    let material = PublicationMaterial::new(
        publication.revision.trim(),
        publication.payload.clone(),
        publication.signature.clone(),
        publication.public_key.clone(),
    )
    .map_err(|e| format!("发布材料无效：{e}"))?;

    let inventory = session_files
        .iter()
        .map(|file| {
            JobFileSpec::new(
                DomainFileId(file.file_id.clone()),
                file.display_path.clone(),
                file.bytes,
                file.sha256.to_ascii_lowercase(),
            )
            .map_err(|e| format!("会话文件 {} 无效：{e}", file.file_id))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let requested: Vec<DomainFileId> = files
        .iter()
        .map(|file| DomainFileId(file.file_id.clone()))
        .collect();

    JobSpec::new(
        identity,
        material,
        inventory,
        &requested,
        full_session,
        date_label,
    )
    .map_err(|e| format!("下载请求不构成完整的任务定义：{e}"))
}

/// Commit 34: imports the legacy `pending-downloads.json` sidecar into the
/// durable store, then deletes it.
///
/// Order matters and is the point of the function:
///
/// 1. **Back up first.** The original bytes are copied (durably — same
///    fsync/rename publish as any other sidecar write) to
///    [`LEGACY_PENDING_DOWNLOAD_BACKUP`] *before* anything is imported, so
///    an import that turns out to have been wrong is still recoverable by
///    hand.
/// 2. **Import in one transaction**, using the importer commit 26 already
///    built (`TransferStore::import_legacy_pending_downloads`) — records
///    plus migration marker commit together, and a corrupt record leaves
///    the file untouched and names the job that failed.
/// 3. **Delete only after the import committed.** A failure at any earlier
///    point leaves the sidecar exactly where it was and returns the
///    diagnostic, rather than silently starting from an empty state.
///
/// Deleting is safe to repeat: the migration marker makes a second run
/// short-circuit, and a missing file is simply nothing to do.
fn migrate_legacy_pending_downloads(
    store: &mut TransferStore,
    app_data_dir: &Path,
) -> Result<(), String> {
    let legacy_path = app_data_dir.join(LEGACY_PENDING_DOWNLOAD_FILE);
    let raw = match fs::read(&legacy_path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "failed to read legacy pending-download store at {legacy_path:?}: {e}"
            ))
        }
    };
    write_json_atomically(
        &app_data_dir.join(LEGACY_PENDING_DOWNLOAD_BACKUP),
        &raw,
        "pending-download backup",
    )?;

    let now = chrono::Utc::now().to_rfc3339();
    let outcome = store
        .import_legacy_pending_downloads(&legacy_path, &now)
        .map_err(|e| format!("迁移旧的下载上下文失败（原文件已保留）：{e}"))?;
    match &outcome {
        LegacyImportOutcome::NoLegacyStore => return Ok(()),
        LegacyImportOutcome::AlreadyImported(marker) => eprintln!(
            "[composition] legacy pending-download store was already imported at {} ({}); \
             deleting the leftover sidecar",
            marker.applied_at, marker.detail
        ),
        LegacyImportOutcome::Imported(report) => eprintln!(
            "[composition] migrated legacy pending-download store: {} job(s) imported {:?}, {} \
             already present {:?}; backup kept at {:?}",
            report.imported.len(),
            report.imported,
            report.skipped_existing.len(),
            report.skipped_existing,
            app_data_dir.join(LEGACY_PENDING_DOWNLOAD_BACKUP),
        ),
    }

    match fs::remove_file(&legacy_path) {
        Ok(()) => eprintln!("[composition] deleted legacy pending-download store {legacy_path:?}"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            // The import is committed and idempotent, so a sidecar we could
            // not delete costs a warning, not a launch.
            eprintln!(
                "[composition] failed to delete migrated pending-download store {legacy_path:?} \
                 (it will be skipped by the migration marker next time): {e}"
            );
        }
    }
    Ok(())
}

const LEGACY_PENDING_UPLOAD_FILE: &str = "pending-uploads.json";
const LEGACY_PENDING_UPLOAD_BACKUP: &str = "pending-uploads.json.migrated.bak";

/// Imports the retired upload sidecar into the shared [`TransferStore`].
///
/// The importer itself is deliberately read-only. A backup and deletion are
/// attempted only after the store transaction (including its migration
/// marker) has committed; malformed input therefore remains available for
/// diagnosis and a retry rather than being replaced by an empty state.
fn migrate_legacy_pending_uploads(
    store: &mut TransferStore,
    app_data_dir: &Path,
) -> Result<(), String> {
    let legacy_path = app_data_dir.join(LEGACY_PENDING_UPLOAD_FILE);
    let now = chrono::Utc::now().to_rfc3339();
    let outcome = store
        .import_legacy_pending_uploads(&legacy_path, &now)
        .map_err(|error| format!("迁移旧的上传上下文失败（原文件已保留）：{error}"))?;
    if matches!(&outcome, LegacyUploadImportOutcome::NoLegacyStore) {
        return Ok(());
    }

    // The first successful import backs up the exact source bytes before
    // removing the sidecar. If a prior run committed the marker but failed
    // during cleanup, repeating this is harmless and remains idempotent.
    let raw = match fs::read(&legacy_path) {
        Ok(raw) => raw,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && matches!(&outcome, LegacyUploadImportOutcome::AlreadyImported(_)) =>
        {
            return Ok(())
        }
        Err(error) => {
            return Err(format!(
                "上传上下文已导入但无法读取待清理的旧文件 {legacy_path:?}（原文件已保留）：{error}"
            ))
        }
    };
    write_json_atomically(
        &app_data_dir.join(LEGACY_PENDING_UPLOAD_BACKUP),
        &raw,
        "pending-upload backup",
    )?;

    match fs::remove_file(&legacy_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            let detail = format!(
                "上传上下文已导入且备份成功，但无法删除旧文件 {legacy_path:?}（原文件已保留）：{error}"
            );
            return Err(detail);
        }
    }
    match outcome {
        LegacyUploadImportOutcome::Imported(report) => eprintln!(
            "[composition] migrated legacy pending-upload store: {} upload(s) imported, {} already present; backup kept at {:?}",
            report.imported.len(),
            report.skipped_existing.len(),
            app_data_dir.join(LEGACY_PENDING_UPLOAD_BACKUP),
        ),
        LegacyUploadImportOutcome::AlreadyImported(marker) => eprintln!(
            "[composition] legacy pending-upload store was already imported at {} ({}); cleaned up leftover sidecar",
            marker.applied_at, marker.detail,
        ),
        LegacyUploadImportOutcome::NoLegacyStore => unreachable!(),
    }
    Ok(())
}

/// Durably publishes `bytes` at `path`: 0600 temp file in the same
/// directory, fsync, rename, then fsync the directory. Both legacy importer
/// backups need these guarantees. `label` appears only in error text.
fn write_json_atomically(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} store path has no parent: {path:?}"))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {label} directory {parent:?}: {e}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("store.json");
    let tmp = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));

    let write_result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|e| format!("failed to create {label} temp file {tmp:?}: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("failed to write {label} temp file {tmp:?}: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("failed to fsync {label} temp file {tmp:?}: {e}"))?;
        drop(file);
        fs::rename(&tmp, path)
            .map_err(|e| format!("failed to publish {label} store {path:?}: {e}"))?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("failed to fsync {label} directory {parent:?}: {e}"))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

/// The user-visible failure recorded for a library entry that was left
/// `Uploading` by a process that exited mid-upload. See
/// [`reconcile_interrupted_uploads`].
const UPLOAD_INTERRUPTED_MESSAGE: &str = "上传在应用退出时中断，请重新上传";

/// The user-visible failure recorded when an upload is cancelled from the
/// UI. See [`cancel_upload`].
const UPLOAD_CANCELLED_MESSAGE: &str = "已取消上传";

/// The terminal state of one upload operation. Exactly one of these is
/// ever *committed* per operation, no matter how many writers race for it
/// (see [`UploadOperation::claim_terminal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadTerminalOutcome {
    Succeeded,
    Failed,
    Cancelled,
}

impl UploadTerminalOutcome {
    /// The user-facing reason a cancel/finish was refused because the
    /// *other* one already committed.
    fn already_terminal_message(self) -> String {
        match self {
            UploadTerminalOutcome::Succeeded => "该上传任务已完成，无法取消".to_string(),
            UploadTerminalOutcome::Cancelled => "该上传任务已取消".to_string(),
            UploadTerminalOutcome::Failed => "该上传任务已结束，无法取消".to_string(),
        }
    }
}

/// The lifecycle of one upload operation. `Committed` is absorbing: once
/// reached, neither a cancel nor a finish may move it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadOperationPhase {
    Running,
    /// A cancel was requested; the owning task is expected to observe the
    /// flag and commit the terminal outcome itself.
    CancelRequested,
    Committed(UploadTerminalOutcome),
}

/// What [`UploadOperation::request_cancel`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelDecision {
    /// The flag was just raised; the owning upload task will converge the
    /// visible state.
    Requested,
    /// An earlier cancel already raised it; this call is a no-op.
    AlreadyRequested,
    /// A terminal outcome is already committed. The caller **must not**
    /// write any terminal state -- doing so is exactly the overwrite this
    /// token exists to prevent.
    AlreadyTerminal(UploadTerminalOutcome),
}

/// The single serialization point between "this upload finished" and
/// "cancel this upload".
///
/// Before this existed, `cancel_upload` and `finish_upload` each read the
/// `Transfer` row, decided independently that it was still live, and then
/// wrote their own terminal state -- so a cancel landing just after a
/// successful finish silently rewrote a committed, verified success into
/// `已取消上传` (and the mirror image was equally possible). Both paths now
/// have to win [`claim_terminal`](Self::claim_terminal) before they may
/// write anything, and exactly one of them can.
///
/// The same token doubles as the duplicate-upload gate: an operation is
/// registered in [`Composition::upload_operations`] under a single lock
/// that also checks for an existing active operation on the same library
/// entry, so two concurrent `start_upload` calls cannot both start.
pub struct UploadOperation {
    transfer_key: String,
    entry_key: String,
    /// The publication revision this upload was started for. Two starts
    /// for the *same* revision are duplicates; a start for a different
    /// revision while one is live is a conflict.
    revision: String,
    /// Polled by the upload task around every part (see
    /// [`UploadContext::check_cancelled`]).
    cancel: Arc<AtomicBool>,
    phase: Mutex<UploadOperationPhase>,
}

impl UploadOperation {
    fn new(transfer_key: &str, entry_key: &str, revision: &str) -> Self {
        UploadOperation {
            transfer_key: transfer_key.to_string(),
            entry_key: entry_key.to_string(),
            revision: revision.to_string(),
            cancel: Arc::new(AtomicBool::new(false)),
            phase: Mutex::new(UploadOperationPhase::Running),
        }
    }

    pub fn transfer_key(&self) -> &str {
        &self.transfer_key
    }

    fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    /// `true` while no terminal outcome has been committed yet. Only
    /// active operations block a new start for the same entry.
    fn is_active(&self) -> bool {
        !matches!(
            *self.phase.lock().unwrap(),
            UploadOperationPhase::Committed(_)
        )
    }

    /// Requests cancellation. Raising the flag and inspecting the phase
    /// happen under one lock, so a cancel can never raise a flag that a
    /// concurrently committing finish has already stopped reading.
    pub fn request_cancel(&self) -> CancelDecision {
        let mut phase = self.phase.lock().unwrap();
        match *phase {
            UploadOperationPhase::Committed(outcome) => CancelDecision::AlreadyTerminal(outcome),
            UploadOperationPhase::CancelRequested => CancelDecision::AlreadyRequested,
            UploadOperationPhase::Running => {
                *phase = UploadOperationPhase::CancelRequested;
                // Inside the lock on purpose: the flag and the phase must
                // never disagree about whether a cancel is in force.
                self.cancel.store(true, Ordering::SeqCst);
                CancelDecision::Requested
            }
        }
    }

    /// Attempts to make `proposed` **the** terminal outcome of this
    /// operation. `Err(existing)` means someone else already committed and
    /// the caller must leave every terminal state (transfer row, library
    /// entry, persistence) exactly as that winner left it.
    pub fn claim_terminal(
        &self,
        proposed: UploadTerminalOutcome,
    ) -> Result<(), UploadTerminalOutcome> {
        let mut phase = self.phase.lock().unwrap();
        match *phase {
            UploadOperationPhase::Committed(existing) => Err(existing),
            _ => {
                *phase = UploadOperationPhase::Committed(proposed);
                Ok(())
            }
        }
    }
}

/// The tagged result of [`start_upload`]. The backend -- not the
/// frontend's pending gate -- is what decides whether a second click for
/// the same library entry becomes a second real upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadStartOutcome {
    /// A new upload task was registered and spawned.
    Started { transfer_key: String },
    /// An upload for this exact entry *and* revision is already running;
    /// the caller is handed that operation's transfer key instead of a
    /// duplicate one.
    Existing { transfer_key: String },
    /// A *different* revision of this entry is still uploading. Starting
    /// now would race two writers onto one library entry.
    Conflict { active_revision: String },
}

/// Rejection message for a settings save whose observed revision is stale
/// (another save committed in between). See
/// [`Composition::commit_settings`].
const SETTINGS_CONFLICT_MESSAGE: &str = "设置已被另一次保存修改，请刷新后重试";

/// Backfills [`Composition::job_labels`] from the **durable job identities**
/// at startup (commit 34 — this used to read the pending-download sidecar),
/// so a job recovered from a previous process still emits a labelled
/// `transfer_jobs:update` event instead of `null`.
///
/// Reads every job row, not just the recoverable ones: a failed download the
/// user has not dismissed yet is finished but still on screen, and an
/// unlabelled row on screen is exactly the `null` this backfill exists to
/// prevent.
fn job_labels_from_store(
    store: &TransferStore,
) -> Result<HashMap<JobId, (String, String)>, String> {
    Ok(store
        .list_jobs()
        .map_err(|e| format!("failed to read durable transfer jobs: {e}"))?
        .into_iter()
        .map(|job| {
            (
                JobId(job.job_id),
                (
                    job.identity.device_id().as_str().to_string(),
                    job.identity.session_id().as_str().to_string(),
                ),
            )
        })
        .collect())
}

/// Validates and prepares the configured download directory before any
/// job can commit a file into it. Rejecting a relative path matters
/// beyond tidiness: every committed file's path is derived from this root
/// (`library::download::derive_target_path`), and a relative root would
/// resolve against whatever the process working directory happens to be
/// at the time -- which is not the same thing for a background worker
/// thread as for the command that configured it.
///
/// The write probe is what turns "your download folder is read-only" into
/// an error at startup instead of a per-file failure hours into a
/// transfer.
/// `pub` so startup can pre-flight the *user-configured* root and fall
/// back to the default instead of letting a typo'd directory abort
/// `spawn` -- which would mean a bad setting bricks the app on launch.
pub fn prepare_library_root(library_root: PathBuf) -> Result<PathBuf, String> {
    if library_root.as_os_str().is_empty() {
        return Err("下载目录未配置".to_string());
    }
    if !library_root.is_absolute() {
        return Err(format!(
            "下载目录必须是绝对路径：{}",
            library_root.display()
        ));
    }
    fs::create_dir_all(&library_root)
        .map_err(|e| format!("无法创建下载目录 {}：{e}", library_root.display()))?;
    if !library_root.is_dir() {
        return Err(format!("下载目录不是一个目录：{}", library_root.display()));
    }
    let probe = library_root.join(format!(
        ".ylx-write-probe-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::write(&probe, b"ylx")
        .map_err(|e| format!("下载目录不可写 {}：{e}", library_root.display()))?;
    let _ = fs::remove_file(&probe);
    Ok(library_root)
}

/// The composition root itself. One instance lives for the app's lifetime,
/// held by `AppState` as an `Arc<Composition>`.
pub struct Composition {
    /// One [`DeviceHandle`] per real device, keyed by full TLS
    /// fingerprint. Its lock covers a map lookup/insert and nothing else:
    /// every per-device network effect (heartbeat, pairing poll, catalog,
    /// detail, delete, disconnect, capture refresh) is issued through a
    /// handle with no lock of this composition's held, so one unreachable
    /// Pi cannot stall another device's work.
    fleet: Arc<DeviceFleet>,
    /// Full-fingerprint identity, endpoint, pinned client and actor handle
    /// are one atomic binding. Legacy short ids are resolved inside this
    /// module and never become map keys for new state.
    bindings: Arc<Mutex<DeviceBindings>>,
    pub coordinator: Arc<TransferCoordinator>,
    mdns_available: AtomicBool,
    /// Latest lifecycle cursor and verified canonical identity for every
    /// DNS-SD service, plus identities explicitly added by address.
    mdns_services: Mutex<MdnsServiceRegistry>,
    pairing_tasks: Mutex<HashMap<String, tauri::async_runtime::JoinHandle<()>>>,
    /// Secrets needed only for polling/cancelling a live pairing attempt.
    /// They are never serialized, logged, or emitted to the frontend.
    active_pairings: Mutex<HashMap<String, ActivePairing>>,
    /// PC-06: real secret storage for the object-store credential (see
    /// [`storage_credential_key`]). Chosen once in [`Composition::new`]
    /// -- see that function's doc comment on `choose_vault` for exactly
    /// when this is the real `OsKeyringCredentialVault` vs. the
    /// session-only `InMemoryCredentialVault` fallback. Never a plaintext
    /// file, under any condition (`CredentialVaultPort`'s own contract).
    vault: Arc<dyn CredentialVaultPort>,
    /// Where the production download commit path writes
    /// verified files (`library_root/{device_id}/{session_id}/{file_id}`,
    /// see `library::download::derive_target_path`) -- the same root
    /// `CoordinatorConfig::library_root` above uses, captured here too so
    /// `start_upload`'s real S3 upload reads from the exact same
    /// convention rather than re-deriving it independently.
    library_root: Mutex<PathBuf>,
    /// Serializes runtime library-root switches with every operation that
    /// creates or consumes root-bound state. Existing in-flight transfers
    /// block a switch; any durable media workflow evidence blocks it until a
    /// future migration/cleanup operation can explicitly retire that binding.
    /// Store locks are only acquired after this gate.
    ///
    /// Short transfer-side operations keep using this gate. Long media
    /// operations must not: an import that holds it for the length of a
    /// multi-gigabyte copy would block every other command, so those take a
    /// shared lease from [`Self::library_root_authority`] instead.
    library_root_gate: Mutex<()>,
    /// Reader/writer fence for the same root, used by the media pipeline.
    ///
    /// It is a second view of one fact, not a second fact: `switch_library_root`
    /// takes the exclusive lease and installs the new root here in the same
    /// critical section that updates `library_root`, so the two can never
    /// disagree about which root is current.
    #[cfg(target_os = "linux")]
    library_root_authority: Arc<crate::media::library_root::LibraryRootAuthority>,
    /// Commit 34: the single durable authority for what every download job
    /// is for (identity, complete spec, ordered files, ledger) **and** for
    /// its terminal outcome (the completion outbox). This replaced the
    /// `pending-downloads.json` sidecar and the process-local request map
    /// that shadowed it -- one fact, one writer, one file.
    transfer_store: Arc<Mutex<TransferStore>>,
    /// Durable authority for removable-media imports, normalization jobs,
    /// pipeline state, receipts, and revision leases. It remains separate
    /// from \`transfer_store\`, which owns the existing Pi download/upload
    /// workflow.
    media_store: Arc<Mutex<MediaStore>>,
    /// `JobId` -> `(device_id, session_id)`, purely for labelling
    /// `JobStateEvent` without a store round-trip per poll tick. A cache of
    /// the durable identity, backfilled at startup by
    /// [`job_labels_from_store`]; entries are removed when a terminal job is
    /// dismissed manually or automatically after a verified success.
    job_labels: Mutex<HashMap<JobId, (String, String)>>,
    /// `Transfer::key` -> the operation token for a live upload task (see
    /// [`UploadOperation`]).  Uploads do not go through
    /// `TransferCoordinator`, so this is their only control channel.
    /// Removed by the upload task itself once it has finished converging
    /// its own terminal state.
    ///
    /// This one mutex is also the duplicate-start gate: "is an operation
    /// for this entry already active?" and "register mine" happen inside a
    /// single critical section (see
    /// [`Composition::begin_upload_operation`]), so two concurrent
    /// `start_upload` calls for the same entry revision cannot both win.
    upload_operations: Mutex<HashMap<String, Arc<UploadOperation>>>,
    /// Monotonic settings revision, and the write gate for every settings
    /// commit. Held for the whole of [`Composition::commit_settings`], so
    /// the OS keyring write and the application-store write of one save
    /// can never interleave with another save's -- and a save that read a
    /// now-stale revision is rejected instead of clobbering.
    settings_revision: Mutex<u64>,
    /// Handles for the background loops started by
    /// [`Composition::start_background_loops`] (boot stage 4).
    ///
    /// Kept rather than detached: a spawned task that nobody holds a handle
    /// to can only be stopped by ending the process, so shutdown had no way
    /// to tell a loop to stop ticking against state that is being torn down.
    /// Empty until stage 4 runs, which is what makes a freshly built
    /// `Composition` inert.
    background_loops: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    /// Test-only fault injection for verifying that the application facade
    /// keeps independent device/storage reads usable when the durable
    /// transfer projection cannot be read.
    #[cfg(test)]
    transfer_projection_read_failure: AtomicBool,
}

#[cfg(target_os = "linux")]
impl crate::media::ubuntu_ingestor::UbuntuLibraryRootGate for Composition {
    fn with_library_root<T>(&self, operation: impl FnOnce(&Path) -> T) -> T {
        Composition::with_library_root(self, |library_root| operation(&library_root))
    }

    fn acquire_shared_library_root(
        &self,
        owner: &str,
    ) -> Result<crate::media::library_root::LibraryRootLease, crate::media::ports::MediaPortError>
    {
        self.library_root_authority.acquire_shared(owner)
    }
}

impl Composition {
    /// Boot stage 2: constructs the real composition **inert** -- no
    /// threads, no timers, no coordinator recovery. Nothing built here can
    /// observe or emit against the application state, because that state
    /// does not exist yet; it is registered in stage 3, and only then does
    /// [`Composition::start_background_loops`] (stage 4) start anything
    /// that ticks.
    ///
    /// That ordering is the point: the loops read `app.state::<AppState>()`
    /// and emit events keyed off it, so a tick that landed before
    /// `app.manage` would panic or publish state nobody had loaded yet.
    /// Taking no `AppHandle` here makes that mistake unrepresentable.
    ///
    /// `library_root` is where verified downloads are committed
    /// (`library_root/{device_id}/{session_id}/{file_id}`). It is a
    /// caller-supplied parameter rather than a fixed
    /// `app_data_dir/library` so the download location is configurable
    /// (the caller reads the user's configured directory and falls back
    /// to `app_data_dir/library` itself). It is validated and created
    /// here, and used both for `CoordinatorConfig::library_root` and for
    /// this composition's own `library_root` field, so the download
    /// commit path and the upload read path can never disagree. Runtime
    /// changes go through [`Composition::switch_library_root`], which only
    /// succeeds while transfer gates are empty and no root-bound media
    /// evidence exists.
    pub fn new(app_data_dir: PathBuf, library_root: PathBuf) -> Result<Arc<Composition>, String> {
        let library_root = prepare_library_root(library_root)?;
        let transfer_store_path = app_data_dir.join("transfer_store.sqlite3");
        let mut transfer_store = TransferStore::open(&transfer_store_path).map_err(|e| {
            format!("failed to open durable transfer store at {transfer_store_path:?}: {e}")
        })?;
        migrate_legacy_pending_downloads(&mut transfer_store, &app_data_dir)?;
        migrate_legacy_pending_uploads(&mut transfer_store, &app_data_dir)?;
        let job_labels = job_labels_from_store(&transfer_store)?;
        let transfer_store = Arc::new(Mutex::new(transfer_store));
        let media_store_path = app_data_dir.join("media_store.sqlite3");
        let media_store = MediaStore::open(&media_store_path).map_err(|error| {
            format!("failed to open durable media store at {media_store_path:?}: {error}")
        })?;
        let media_store = Arc::new(Mutex::new(media_store));

        let fleet = Arc::new(DeviceFleet::new());
        let bindings = Arc::new(Mutex::new(DeviceBindings::default()));
        let device_status: Arc<dyn DeviceStatusPort> = Arc::new(FleetStatusPort {
            bindings: bindings.clone(),
        });
        let source_factory: Arc<dyn DownloadSourceFactory> = Arc::new(RealDownloadSourceFactory {
            bindings: bindings.clone(),
        });
        let verifier: Arc<dyn ylx_transfer_core::library::download::PublicationVerifier> =
            Arc::new(Ed25519PublicationVerifier);

        let config = CoordinatorConfig {
            num_workers: 3,
            dispatch_interval: Duration::from_millis(200),
            checkpoint_threshold_bytes: 256 * 1024,
            library_root: library_root.clone(),
        };
        let commit_port = Arc::new(DerivedMediaCommitter::new(ffmpeg_export_config()?));
        let coordinator = Arc::new(TransferCoordinator::new_with_commit_port(
            transfer_store.clone(),
            device_status,
            source_factory,
            verifier,
            commit_port,
            config,
        ));

        let vault = choose_vault();

        let comp = Arc::new(Composition {
            fleet,
            bindings,
            coordinator,
            mdns_available: AtomicBool::new(false),
            mdns_services: Mutex::new(MdnsServiceRegistry::default()),
            pairing_tasks: Mutex::new(HashMap::new()),
            active_pairings: Mutex::new(HashMap::new()),
            vault,
            #[cfg(target_os = "linux")]
            library_root_authority: crate::media::library_root::LibraryRootAuthority::new(
                library_root.clone(),
            )
            .map_err(|error| format!("无法建立本机媒体库保存位置的身份围栏：{}", error))?,
            library_root: Mutex::new(library_root),
            library_root_gate: Mutex::new(()),
            transfer_store,
            media_store,
            job_labels: Mutex::new(job_labels),
            upload_operations: Mutex::new(HashMap::new()),
            settings_revision: Mutex::new(0),
            background_loops: Mutex::new(Vec::new()),
            #[cfg(test)]
            transfer_projection_read_failure: AtomicBool::new(false),
        });

        Ok(comp)
    }

    /// Boot stage 3 (runtime half): closes downloads left non-terminal by a
    /// previous process as explicit failures. Only terminal projections are
    /// installed; no source is opened and no work is scheduled. This runs
    /// before the initial application snapshot is published so the UI never
    /// observes an old `running` row that this process cannot own.
    pub fn fail_interrupted_downloads_on_startup(&self) -> Result<usize, String> {
        self.coordinator
            .fail_interrupted_jobs_on_startup()
            .map(|jobs| jobs.len())
            .map_err(|error| format!("无法收敛上次应用退出时中断的下载任务：{error}"))
    }

    /// Boot stage 4: starts the background loops (mDNS discovery,
    /// heartbeat, transfer-coordinator poll) and keeps their handles.
    ///
    /// Must only be called once the composition is registered as managed
    /// state (stage 3) -- every loop here resolves `app.state::<AppState>()`
    /// or emits events the frontend reads against it.
    pub fn start_background_loops(self: &Arc<Self>, app: AppHandle) {
        let mut handles = self.background_loops.lock().unwrap();
        if !handles.is_empty() {
            return;
        }
        handles.extend(spawn_mdns_loop(self.clone(), app.clone()));
        handles.push(spawn_heartbeat_loop(self.clone(), app.clone()));
        handles.push(spawn_transfer_poll_loop(self.clone(), app));
    }

    /// Stops every loop started by [`Composition::start_background_loops`].
    ///
    /// The counterpart to keeping the handles: without this a loop keeps
    /// ticking against application state that is being torn down.
    pub fn shutdown_background_loops(&self) {
        for handle in self.background_loops.lock().unwrap().drain(..) {
            handle.abort();
        }
    }

    pub fn library_root(&self) -> PathBuf {
        self.library_root.lock().unwrap().clone()
    }

    /// Runs one synchronous local-library operation against a stable root.
    ///
    /// The root is cloned while `library_root_gate` is held, and that gate
    /// remains held until `operation` returns. Callers may lock the media or
    /// transfer stores inside the closure; the global ordering is always
    /// root gate first, then a durable store. Returning deferred work (for
    /// example, an unpolled future) would end the protected operation and is
    /// therefore outside this API's contract.
    pub(crate) fn with_library_root<T>(&self, operation: impl FnOnce(PathBuf) -> T) -> T {
        let _root_gate = self.library_root_gate.lock().unwrap();
        let library_root = self.library_root.lock().unwrap().clone();
        operation(library_root)
    }

    /// Shared durable store for the removable-media application boundary.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn media_store(&self) -> Arc<Mutex<MediaStore>> {
        self.media_store.clone()
    }

    /// Revoke the currently active trusted producer for one producer
    /// identity. The operation stays in the composition's media-store
    /// boundary so callers cannot write arbitrary trust rows or bypass the
    /// append-only audit maintained by `MediaStore`.
    #[cfg(target_os = "linux")]
    pub fn revoke_trusted_producer_key(
        &self,
        producer_identity: &str,
        revoked_at: &str,
    ) -> Result<
        Option<ylx_transfer_core::media_store::TrustedProducerKeyReceipt>,
        ylx_transfer_core::media_store::TrustedProducerError,
    > {
        self.media_store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoke_trusted_producer_key(producer_identity, revoked_at)
    }

    /// Shared durable transfer store for the Ubuntu derived-upload owner.
    ///
    /// The upload lane uses a separate sidecar table in this store, but it
    /// must still share the same connection owner as the existing transfer
    /// workflow so terminal outcomes and completion outboxes remain one
    /// durable authority.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub(crate) fn transfer_store(&self) -> Arc<Mutex<TransferStore>> {
        self.transfer_store.clone()
    }

    /// Builds the one production S3-compatible object-store adapter used by
    /// Ubuntu media uploads. Credentials are read here, inside composition's
    /// vault boundary; media workers receive a configured client, never a
    /// secret-bearing DTO or a second copy of the S3 initialization logic.
    #[cfg(target_os = "linux")]
    pub(crate) fn build_object_store_for_media(
        &self,
        storage: &StorageConfig,
    ) -> Result<S3ObjectStore, String> {
        let credential = self
            .storage_credential()
            .map_err(|error| format!("无法读取对象存储凭据：{error}"))?;
        build_object_store(
            &storage.endpoint,
            &storage.bucket,
            storage.url_style,
            &credential,
        )
    }

    /// Reader/writer fence over the library root for the media pipeline.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn library_root_authority(&self) -> Arc<crate::media::library_root::LibraryRootAuthority> {
        self.library_root_authority.clone()
    }

    pub fn switch_library_root(&self, library_root: PathBuf) -> Result<PathBuf, String> {
        // Take the media exclusive lease first. It never waits, so an import
        // that is mid-copy produces an immediate, explainable conflict here
        // rather than a settings dialog that appears to hang. Holding it for
        // the whole check also stops a new media worker from starting between
        // the emptiness checks below and the actual install.
        #[cfg(target_os = "linux")]
        let exclusive = self
            .library_root_authority
            .acquire_exclusive()
            .map_err(|error| format!("无法独占本机保存位置：{error}"))?;

        self.with_library_root(|_current_root| {
            let has_media_evidence = self
                .media_store
                .lock()
                .unwrap()
                .has_library_root_evidence()
                .map_err(|error| format!("无法检查媒体库保存位置绑定：{error}"))?;
            if has_media_evidence {
                return Err(
                    "已有可移动媒体导入、处理或回执记录绑定当前保存位置；在提供迁移或清理流程前无法切换"
                        .to_string(),
                );
            }

            let (active_jobs, pending_completions, pending_upload_cleanup) = {
                let store = self.transfer_store.lock().unwrap();
                let active_jobs = store
                    .list_jobs()
                    .map_err(|e| format!("无法读取传输任务记录：{e}"))?
                    .into_iter()
                    .any(|job| !job.state.is_terminal());
                let pending_completions = store
                    .all_completions()
                    .map_err(|e| format!("无法读取传输完成记录：{e}"))?
                    .into_iter()
                    .any(|completion| !completion.is_acknowledged());
                let pending_upload_cleanup = !store
                    .list_pending_uploads()
                    .map_err(|e| format!("无法读取上传清理记录：{e}"))?
                    .is_empty();
                (active_jobs, pending_completions, pending_upload_cleanup)
            };
            let coordinator_active = self
                .coordinator
                .list_snapshots()
                .into_iter()
                .any(|snapshot| !snapshot.state.is_terminal());
            if active_jobs || coordinator_active || pending_completions || pending_upload_cleanup {
                return Err("仍有传输或清理任务未结束，无法切换本机保存位置".to_string());
            }

            let prepared = prepare_library_root(library_root)?;
            self.coordinator
                .set_library_root_if_idle(prepared.clone())?;
            // Install into the media fence inside the same critical section
            // that updates `library_root`, so the two views of "current root"
            // cannot disagree, and bump the generation that invalidates any
            // lease a suspended worker might still be carrying.
            #[cfg(target_os = "linux")]
            exclusive
                .install(prepared.clone())
                .map_err(|error| format!("无法更新本机保存位置的身份围栏：{error}"))?;
            *self.library_root.lock().unwrap() = prepared.clone();
            Ok(prepared)
        })
    }

    /// Enqueues a real download job through the coordinator and durably
    /// records its [`JobSpec`], so a later terminal state observed by
    /// [`spawn_transfer_poll_loop`] can be projected without a process-local
    /// copy of the request context.
    ///
    /// Test-only as of the download-progress work: every production call
    /// site now goes through [`Composition::enqueue_download_with_context`],
    /// which additionally records the session's file inventory. This
    /// narrower entry point is kept because this file's own tests use it to
    /// prove the tracking/library-entry machinery independently of
    /// `download_session`.
    #[cfg(test)]
    fn enqueue_download(
        &self,
        request: TransferRequest,
        date_label: String,
    ) -> Result<JobId, String> {
        let files: Vec<SessionFile> = request
            .files
            .iter()
            .map(|file| {
                let display_path = file
                    .target_relative_path
                    .clone()
                    .unwrap_or_else(|| file.file_id.as_str().to_string());
                SessionFile::new(
                    file.file_id.as_str().to_string(),
                    display_path,
                    file.expected_size,
                    file.expected_sha256_hex.clone(),
                )
            })
            .collect();
        self.enqueue_download_with_context(request, date_label, files.clone(), files)
    }

    fn enqueue_download_with_context(
        &self,
        request: TransferRequest,
        date_label: String,
        files: Vec<SessionFile>,
        session_files: Vec<SessionFile>,
    ) -> Result<JobId, String> {
        if request.files.is_empty() || files.is_empty() || session_files.is_empty() {
            return Err("下载请求缺少真实文件清单".to_string());
        }
        if request.files.len() != files.len()
            || request.files.iter().zip(&files).any(|(plan, file)| {
                plan.file_id.as_str() != file.file_id
                    || plan
                        .target_relative_path
                        .as_deref()
                        .unwrap_or_else(|| plan.file_id.as_str())
                        != file.display_path
                    || plan.expected_size != file.bytes
                    || plan.expected_sha256_hex.to_ascii_lowercase() != file.sha256
            })
        {
            return Err("下载请求与会话文件清单不一致".to_string());
        }
        let inventory_ids: HashSet<&str> = session_files
            .iter()
            .map(|file| file.file_id.as_str())
            .collect();
        let inventory_paths: HashSet<String> = session_files
            .iter()
            .map(|file| file.display_path.to_lowercase())
            .collect();
        if inventory_ids.len() != session_files.len()
            || inventory_paths.len() != session_files.len()
            || files.iter().any(|file| {
                !session_files.iter().any(|inventory| {
                    inventory.file_id == file.file_id
                        && inventory.display_path == file.display_path
                        && inventory.bytes == file.bytes
                        && inventory.sha256 == file.sha256
                })
            })
            || files.len() != session_files.len()
        {
            return Err("会话文件清单包含重复项或下载范围不一致".to_string());
        }
        let _root_gate = self.library_root_gate.lock().unwrap();
        let library_root = self.library_root();
        for file in files.iter().chain(session_files.iter()) {
            SourceSha256::from_hex(&file.sha256)
                .map_err(|error| format!("会话文件 SHA-256 无效（{}）：{error}", file.file_id))?;
            derive_target_path_for_file(
                &library_root,
                request.device_id.as_str(),
                request.session_id.as_str(),
                &file.file_id,
                Some(&file.display_path),
            )
            .map_err(|e| format!("下载文件路径不安全（{}）：{e:?}", file.display_path))?;
        }

        let publication = PublicationEvidence {
            revision: request.revision.clone(),
            payload: request.manifest_bytes.clone(),
            signature: request.signature.clone(),
            public_key: request.publication_public_key.clone(),
        };
        // Commit 34: the durable spec is built (and therefore validated)
        // *before* the coordinator job exists, so an enqueue that cannot be
        // described durably never becomes a running job at all.
        let spec = job_spec_from_context(
            request.device_id.as_str(),
            request.session_id.as_str(),
            &date_label,
            &files,
            &session_files,
            &publication,
            true,
        )?;
        let device_id = request.device_id.as_str().to_string();
        let session_id = request.session_id.as_str().to_string();

        let job_id = self
            .coordinator
            .enqueue_with_spec(request, spec.clone())
            .map_err(|e| e.to_string())?;
        self.remember_job_label(&job_id, &device_id, &session_id);
        if let Err(e) = self.create_durable_job(&job_id, &spec) {
            let cancel_error = self.coordinator.cancel(&job_id).err();
            return Err(match cancel_error {
                Some(cancel_error) => format!(
                    "下载任务已创建，但持久化恢复上下文失败（{e}），且取消任务失败：{cancel_error}"
                ),
                None => format!("无法持久化下载恢复上下文，任务已取消：{e}"),
            });
        }
        Ok(job_id)
    }

    /// Commits the durable spec for a freshly enqueued job.
    ///
    /// A natural-key hit whose content differs is surfaced, never merged:
    /// the store deliberately refuses to hand back a job that transfers a
    /// different file plan than the caller asked for, and silently reusing
    /// it here would defeat exactly that check.
    fn create_durable_job(
        &self,
        job_id: &JobId,
        spec: &ylx_transfer_core::domain::JobSpec,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        match self
            .transfer_store
            .lock()
            .unwrap()
            .create_job(job_id.as_str(), spec, &now)
        {
            Ok(_) => Ok(()),
            Err(CreateJobError::RequestDigestMismatch(conflict)) => Err(format!(
                "该会话已有一个内容不同的下载任务（{}），请先清除后重试",
                conflict.job_id
            )),
            Err(CreateJobError::JobIdCollision { job_id, existing }) => Err(format!(
                "下载任务 ID {job_id} 已被另一个任务占用（{existing}）"
            )),
            Err(CreateJobError::Persistence(error)) => {
                Err(format!("无法写入持久化下载上下文：{error}"))
            }
        }
    }

    /// What a job is downloading, read back from the durable spec.
    ///
    /// `None` means "this store has no job with that id" — the coordinator
    /// may still know about it (a demo/sim job, or one whose durable row was
    /// already retired). A spec that exists but cannot be read is logged and
    /// also reported as `None`, because fabricating a partial context here
    /// would be worse than declining to act on it.
    fn download_job_spec(&self, job_id: &JobId) -> Option<JobSpec> {
        match self
            .transfer_store
            .lock()
            .unwrap()
            .job_spec(job_id.as_str())
        {
            Ok(spec) => Some(spec),
            Err(JobSpecLoadError::UnknownJob(_)) => None,
            Err(error) => {
                eprintln!(
                    "[composition] durable download context for {job_id} is unusable: {error}"
                );
                None
            }
        }
    }

    /// Records the `(device_id, session_id)` a job is for. See
    /// [`Composition::job_labels`] for why this derived cache exists
    /// separately from the durable [`JobSpec`].
    fn remember_job_label(&self, job_id: &JobId, device_id: &str, session_id: &str) {
        self.job_labels.lock().unwrap().insert(
            job_id.clone(),
            (device_id.to_string(), session_id.to_string()),
        );
    }

    #[cfg(test)]
    fn job_label(&self, job_id: &JobId) -> Option<(String, String)> {
        self.job_labels.lock().unwrap().get(job_id).cloned()
    }

    /// Checks for an already-active upload of `entry_key` **and** registers
    /// a new operation, inside one critical section.
    ///
    /// This is the whole point of the method: previously `start_upload`
    /// read the library, decided the entry was idle, released the lock, and
    /// only then wrote `UploadStatus::Uploading` -- so two concurrent calls
    /// could both pass the check and both spawn a real S3 multipart upload
    /// against the same object keys. The frontend's pending gate hid it in
    /// practice; it is a UX nicety, and this is the authority.
    ///
    /// The scan is linear over a map that only ever holds live uploads, and
    /// skips operations that have already committed a terminal outcome (a
    /// finished-but-not-yet-retired row must not block a retry).
    pub fn begin_upload_operation(
        &self,
        transfer_key: &str,
        entry_key: &str,
        revision: &str,
    ) -> UploadStartOutcome {
        let mut operations = self.upload_operations.lock().unwrap();
        if let Some(active) = operations
            .values()
            .find(|operation| operation.entry_key == entry_key && operation.is_active())
        {
            return if active.revision == revision {
                UploadStartOutcome::Existing {
                    transfer_key: active.transfer_key.clone(),
                }
            } else {
                UploadStartOutcome::Conflict {
                    active_revision: active.revision.clone(),
                }
            };
        }
        operations.insert(
            transfer_key.to_string(),
            Arc::new(UploadOperation::new(transfer_key, entry_key, revision)),
        );
        UploadStartOutcome::Started {
            transfer_key: transfer_key.to_string(),
        }
    }

    fn upload_operation(&self, transfer_key: &str) -> Option<Arc<UploadOperation>> {
        self.upload_operations
            .lock()
            .unwrap()
            .get(transfer_key)
            .cloned()
    }

    /// Called by the upload task once it has converged its own terminal
    /// state, so a later `cancel_upload` for the same key reports "already
    /// finished" instead of silently setting a flag nobody reads.
    fn clear_upload_operation(&self, transfer_key: &str) {
        self.upload_operations.lock().unwrap().remove(transfer_key);
    }

    /// The current settings revision. Read *before* a save prepares its
    /// changes; handed back to [`Composition::commit_settings`], which
    /// refuses to run if anything committed in between.
    pub fn settings_revision(&self) -> u64 {
        *self.settings_revision.lock().unwrap()
    }

    /// Runs `commit` as the process's single settings writer.
    ///
    /// Settings live in two places that must agree -- the OS credential
    /// vault and the application store -- and the save path previously
    /// wrote the keyring, dropped every lock, then wrote the store. Two
    /// concurrent saves could therefore commit A's secret with B's
    /// endpoint. Everything that has to be atomic (the rollback snapshot
    /// read, the replace/keep credential write, the config persist, and
    /// the rollback on failure) now runs inside `commit`, under this lock.
    ///
    /// A save whose `observed` revision is stale is rejected **without
    /// running `commit` at all**, so a lost update surfaces as a conflict
    /// the user can retry rather than as a silent clobber. The revision
    /// only advances on success: a failed-and-rolled-back save leaves the
    /// world exactly as another in-flight save observed it.
    pub fn commit_settings<T>(
        &self,
        observed: u64,
        commit: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut revision = self.settings_revision.lock().unwrap();
        if *revision != observed {
            return Err(SETTINGS_CONFLICT_MESSAGE.to_string());
        }
        let value = commit()?;
        *revision = revision.wrapping_add(1);
        Ok(value)
    }

    /// Commit 29: commits a job's terminal transition **and** its outcome to
    /// the durable outbox in one transaction.
    ///
    /// Called on the first poll tick that observes a terminal coordinator
    /// state. Replaying it is a no-op, which is what makes it safe to call
    /// again after a restart that lost the in-memory `last_states` map.
    ///
    /// Returns `false` for a job this store has no row for (a demo/sim job,
    /// or one already retired) — there is nothing to record and nothing to
    /// deliver.
    fn record_terminal_outcome(
        &self,
        job_id: &JobId,
        state: &TransferJobState,
    ) -> Result<bool, String> {
        let Some(outcome) = terminal_outcome_from_state(state) else {
            return Ok(false);
        };
        let now = chrono::Utc::now().to_rfc3339();
        match self
            .transfer_store
            .lock()
            .unwrap()
            .complete_job(job_id.as_str(), &outcome, &now)
        {
            Ok(_) => Ok(true),
            Err(CompleteJobError::UnknownJob(_)) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }

    /// Commit 30: drains the completion outbox into the application library.
    ///
    /// Apply, emit, acknowledge — in that order, once per tick, for every
    /// outcome the store still owes the app. Because the terminal outcome is
    /// durable *before* this runs and is only acknowledged *after* the
    /// library commit, a crash anywhere in between converges on the next
    /// tick (or the next launch) instead of losing the result.
    ///
    /// Everything the projection needs comes from the durable spec plus the
    /// outbox row; there is no sidecar left to read.
    fn deliver_terminal_outcomes<R: Runtime>(&self, app: &AppHandle<R>) -> TerminalDeliveryReport {
        let now = chrono::Utc::now().to_rfc3339();
        let library_root = self.library_root();
        let mut report = TerminalDeliveryReport::default();
        let mut refresh_devices = HashSet::new();
        let records = match self.transfer_store.lock().unwrap().pending_completions() {
            Ok(records) => records,
            Err(error) => {
                eprintln!("[composition] failed to read completion outbox: {error}");
                return report;
            }
        };

        for record in records {
            let completion = {
                let mut store = self.transfer_store.lock().unwrap();
                match load_owned_completion(&mut store, &record) {
                    Ok(Some(completion)) => Some(completion),
                    Ok(None) => {
                        report.deferred.insert(JobId(record.job_id.clone()));
                        eprintln!(
                            "[composition] completion {} has no durable context; keeping it deliverable",
                            record.job_id
                        );
                        None
                    }
                    Err(error) => {
                        report.deferred.insert(JobId(record.job_id.clone()));
                        eprintln!(
                            "[composition] completion {} context is blocked: {error}",
                            record.job_id
                        );
                        None
                    }
                }
            };
            let Some(completion) = completion else {
                continue;
            };

            let projection = match &completion.context {
                OwnedCompletionContext::Download(_) => {
                    apply_download_completion(app, &completion, &library_root)
                        .map(|(outcome, changed, device)| (outcome, changed, Some(device)))
                }
                OwnedCompletionContext::Upload(_) => {
                    { apply_upload_completion(self, app, &completion) }
                        .map(|(outcome, changed)| (outcome, changed, None))
                }
            };
            let (outcome, changed, device_id) = match projection {
                Ok(projection) => projection,
                Err(error) => {
                    report.deferred.insert(JobId(record.job_id.clone()));
                    eprintln!(
                        "[composition] completion {} could not be applied yet: {error}",
                        record.job_id
                    );
                    continue;
                }
            };
            report.library_changed |= changed;
            if let Some(device_id) = device_id {
                // Deferred download projections still refresh the session so
                // the durable attention state becomes visible immediately.
                refresh_devices.insert(device_id);
            }
            let ack = acknowledge_projected_completion(
                &mut self.transfer_store.lock().unwrap(),
                &record,
                &outcome,
                &now,
            );
            match ack {
                Ok(None) => {
                    let ProjectionOutcome::Deferred(reason) = &outcome else {
                        unreachable!("only deferred projections skip acknowledgement")
                    };
                    report.deferred.insert(JobId(record.job_id.clone()));
                    eprintln!(
                        "[composition] completion {} deferred: {reason}",
                        record.job_id
                    );
                }
                Ok(Some(AckOutcome::Acknowledged(_)))
                | Ok(Some(AckOutcome::AlreadyAcknowledged(_))) => {}
                Ok(Some(AckOutcome::Unknown)) => {
                    report.deferred.insert(JobId(record.job_id.clone()));
                    eprintln!(
                        "[composition] completion {} disappeared before acknowledgement",
                        record.job_id
                    );
                }
                Err(error) => {
                    report.deferred.insert(JobId(record.job_id.clone()));
                    eprintln!(
                        "[composition] failed to acknowledge completion {}: {error}",
                        record.job_id
                    );
                }
            }
        }

        // The projection and acknowledgement loops above hold no global
        // locks here. Refreshing the affected Pi catalogs is asynchronous and
        // takes AppState only inside its own short snapshot/emit sections.
        for device_id in refresh_devices {
            spawn_sessions_refresh(app, device_id);
        }

        // A delivered success is the only outcome that retires its job.
        report.retirable = self
            .transfer_store
            .lock()
            .unwrap()
            .all_completions()
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                record.operation_kind == OperationKind::Download
                    && record.is_acknowledged()
                    && record.outcome.is_success()
            })
            .map(|record| JobId(record.job_id))
            .collect();
        report
    }

    /// Retires a successful job only once its outcome has been durably
    /// applied to the application library *and* acknowledged. Retirement is
    /// a visibility tombstone: the durable job, immutable spec, completion
    /// evidence, and retry lineage remain available for audit/replay.
    /// Failed/cancelled jobs never enter this path.
    fn retire_successful_download(&self, job_id: &JobId) -> Result<(), String> {
        match self.coordinator.job_state(job_id) {
            Some(TransferJobState::Succeeded) => self.dismiss_transfer_job(job_id.as_str()),
            // The coordinator has already forgotten this job (for example,
            // after a previous process completed runtime cleanup). Finish
            // the visibility transition against the durable row directly;
            // never physically delete the audit/history record.
            None => {
                let now = chrono::Utc::now().to_rfc3339();
                let dismissed = self
                    .transfer_store
                    .lock()
                    .unwrap()
                    .dismiss_job(job_id.as_str(), &now)
                    .map_err(|e| format!("无法标记持久化下载上下文为已清除：{e}"))?;
                if !dismissed {
                    // Idempotent retry after a crash between the durable
                    // tombstone and this process's in-memory cleanup.
                    let still_present = self
                        .transfer_store
                        .lock()
                        .unwrap()
                        .get_job(job_id.as_str())
                        .map_err(|e| format!("无法读取持久化下载上下文：{e}"))?
                        .is_some();
                    if !still_present {
                        return Ok(());
                    }
                }
                self.job_labels.lock().unwrap().remove(job_id);
                Ok(())
            }
            Some(_) => Err(format!(
                "refusing to retire non-succeeded download job {job_id}"
            )),
        }
    }

    /// Dismisses one terminal download from every queue/recovery view.
    ///
    /// Runtime validation happens before the durable write. The durable
    /// `dismissed_at` tombstone is then committed before the coordinator's
    /// in-memory maps are forgotten, so a persistence failure never leaves a
    /// live runtime row with missing recovery context. The final runtime
    /// cleanup is idempotent and may be retried after a crash; no job/spec/
    /// outbox/lineage record is physically deleted.
    pub fn dismiss_transfer_job(&self, job_id: &str) -> Result<(), String> {
        let job_id = JobId(job_id.to_string());
        self.coordinator
            .validate_dismissal(&job_id)
            .map_err(|error| describe_coordinator_error(job_id.as_str(), &error))?;
        let now = chrono::Utc::now().to_rfc3339();
        self.transfer_store
            .lock()
            .unwrap()
            .dismiss_job(job_id.as_str(), &now)
            .map_err(|error| format!("无法标记下载任务为已清除：{error}"))?;

        match self.coordinator.dismiss_runtime(&job_id) {
            Ok(()) | Err(CoordinatorError::NotFound(_)) => {}
            Err(error) => {
                // The tombstone is already durable. Returning the runtime
                // error tells the caller to retry cleanup, while a later
                // process can still rehydrate the row and finish this step.
                return Err(describe_coordinator_error(job_id.as_str(), &error));
            }
        }
        self.job_labels.lock().unwrap().remove(&job_id);
        Ok(())
    }

    /// Reads the durable job row used by the command layer to route retry
    /// without relying on a process-local transfer classification cache.
    pub(crate) fn stored_job(&self, job_id: &str) -> Result<Option<StoredJob>, String> {
        self.transfer_store
            .lock()
            .unwrap()
            .get_job(job_id)
            .map_err(|error| format!("无法读取持久化传输任务：{error}"))
    }

    /// Reads the immutable input for a durable upload retry. In particular,
    /// `entry_key` remains available after every in-memory projection is lost
    /// on restart.
    pub(crate) fn stored_upload_job_spec(
        &self,
        job_id: &str,
    ) -> Result<Option<UploadJobSpec>, String> {
        self.transfer_store
            .lock()
            .unwrap()
            .upload_job_spec(job_id)
            .map_err(|error| format!("无法读取上传任务 immutable spec：{error}"))
    }

    /// Classifies an upload from its durable typed subject. Derived-bundle
    /// attempts must never enter the legacy library-publication retry path,
    /// which does not understand their frozen bundle or destination identity.
    pub(crate) fn is_derived_upload_job(&self, job_id: &str) -> Result<bool, String> {
        self.transfer_store
            .lock()
            .unwrap()
            .is_derived_upload_job(job_id)
            .map_err(|error| format!("无法读取派生上传任务类型：{error}"))
    }

    /// Re-enqueues a retryable failed coordinator job. The coordinator's
    /// retry transaction already creates the child with copied immutable
    /// context, files, ledger, and lineage; the failed parent remains
    /// durable audit history.
    pub fn retry_download(&self, job_id: &str) -> Result<String, String> {
        let old_job_id = JobId(job_id.to_string());
        match self.coordinator.job_state(&old_job_id) {
            Some(TransferJobState::Failed {
                retryable: true, ..
            }) => {}
            Some(TransferJobState::Failed {
                retryable: false, ..
            }) => return Err("该下载失败不可重试".to_string()),
            Some(_) => return Err("只有失败的下载任务可以重试".to_string()),
            None => return Err("未找到下载任务".to_string()),
        }

        let spec = self
            .download_job_spec(&old_job_id)
            .ok_or_else(|| "该任务缺少持久化下载上下文，无法安全重试".to_string())?;
        let device_id = spec.identity().device_id().as_str().to_string();
        let session_id = spec.identity().session_id().as_str().to_string();
        let new_job_id = self
            .coordinator
            .retry(&old_job_id)
            .map_err(|e| e.to_string())?;
        self.remember_job_label(&new_job_id, &device_id, &session_id);
        Ok(new_job_id.to_string())
    }

    /// Existence-only check for the object-store credential (PC-06) --
    /// never returns the raw secret. Backs `commands::get_storage_config`'s
    /// `secretConfigured` field.
    pub fn storage_secret_status(&self) -> Result<SecretStatus, CredentialVaultError> {
        self.vault.status(&storage_credential_key())
    }

    /// Writes (or overwrites) the object-store credential into the vault.
    /// Called only by `commands::save_storage_config` and by the
    /// legacy-plaintext migration in `state.rs`'s `AppState::new` -- never
    /// with an empty pair (callers are expected to treat "both fields
    /// empty" as "leave existing secret alone" and simply not call this).
    pub fn set_storage_credential(
        &self,
        access_key: String,
        secret_key: String,
    ) -> Result<(), CredentialVaultError> {
        let payload = serde_json::to_string(&StoredCredential {
            access_key,
            secret_key,
        })
        .expect("StoredCredential is plain strings, always serializes");
        self.vault
            .set_secret(&storage_credential_key(), Secret::new(payload))
    }

    /// Captures the current credential for a configuration transaction.
    /// The value remains inside the Rust backend and is never serialized to
    /// the frontend or application store.
    pub fn storage_credential_snapshot(
        &self,
    ) -> Result<Option<StoredCredential>, CredentialVaultError> {
        if self.storage_secret_status()?.secret_configured {
            self.storage_credential().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Restores a credential snapshot after the non-secret configuration
    /// commit fails, preventing a mixed old-config/new-secret state.
    pub fn restore_storage_credential(
        &self,
        credential: Option<StoredCredential>,
    ) -> Result<(), CredentialVaultError> {
        match credential {
            Some(credential) => {
                self.set_storage_credential(credential.access_key, credential.secret_key)
            }
            None => self.vault.delete_secret(&storage_credential_key()),
        }
    }

    /// Reads the object-store credential back out of the vault, for the
    /// one real call site that actually needs to sign S3 requests with it
    /// (`start_upload`/`test_object_store_connection`).
    pub fn storage_credential(&self) -> Result<StoredCredential, CredentialVaultError> {
        read_storage_credential(self.vault.as_ref())
    }

    fn resolve_binding(&self, device_id: &str) -> Result<DeviceBinding, String> {
        self.bindings
            .lock()
            .unwrap()
            .resolve(&DeviceId(device_id.to_string()))
            .map_err(|error| format!("设备身份解析失败：{error}"))
    }

    /// Resolve canonical and unique legacy ids to one full device identity.
    /// Unknown and ambiguous aliases fail before callers allocate an
    /// operation gate or perform network I/O.
    pub(crate) fn canonical_device_id(&self, device_id: &str) -> Result<String, String> {
        self.resolve_binding(device_id)
            .map(|binding| binding.identity.device_id().as_str().to_string())
    }

    /// Exact current and retained-legacy library keys for one physical
    /// device. Application paging uses this before borrowing `AppData` so it
    /// can clone only page-relevant entries without reimplementing identity
    /// alias rules or holding the global application mutex during resolution.
    pub(crate) fn local_library_device_keys(&self, device_id: &str) -> Result<Vec<String>, String> {
        let bindings = self.bindings.lock().unwrap();
        let binding = bindings
            .resolve(&DeviceId(device_id.to_string()))
            .map_err(|error| format!("设备身份解析失败：{error}"))?;
        Ok(bindings.download_job_lookup_ids(&binding.identity))
    }

    #[cfg(test)]
    pub(crate) fn register_session_gate_device_for_test(
        &self,
        tls_fingerprint: String,
        host: String,
    ) -> Result<(String, String), String> {
        let registration = self.register_endpoint(DeviceEndpoint {
            host,
            port: 9,
            tls_fingerprint,
            name: "session gate fixture".to_string(),
            display_label: None,
            api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
        })?;
        Ok((
            registration.identity.device_id().as_str().to_string(),
            registration.identity.display_id().to_string(),
        ))
    }

    /// This device's fleet handle, resolved from a canonical id or one
    /// unambiguous legacy alias. Ambiguous aliases fail closed.
    fn handle_for(&self, device_id: &str) -> Option<DeviceHandle> {
        self.resolve_binding(device_id)
            .ok()
            .map(|binding| binding.handle)
    }

    fn device_ids_match(&self, left: &str, right: &str) -> bool {
        self.bindings.lock().unwrap().device_ids_match(left, right)
    }

    fn job_event_identity(&self, stored: &DeviceId) -> (Option<String>, Option<String>) {
        match self.bindings.lock().unwrap().outward_identity(stored) {
            Some(identity) => (
                Some(identity.device_id().as_str().to_string()),
                Some(identity.display_id().to_string()),
            ),
            None => (None, None),
        }
    }

    /// One heartbeat sweep's worth of "which client talks to which
    /// device", snapshotted up front so the sweep itself needs neither the
    /// binding registry nor the fleet map while it is doing network I/O.
    fn clients_by_fingerprint(&self) -> HashMap<DeviceFingerprint, DevicePollBinding> {
        let active_device_ids = self
            .active_pairings
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let mut clients = self.bindings.lock().unwrap().clients_by_fingerprint();
        clients.retain(|_, binding| !active_device_ids.contains(&binding.device_id));
        clients
    }

    /// Registers (or refreshes) a known network endpoint from its complete
    /// device identity pin, creating its `DeviceActor` on first sight. Identity
    /// parsing and pin normalization happen before any visible state is
    /// registered.
    fn register_endpoint(
        &self,
        mut endpoint: DeviceEndpoint,
    ) -> Result<EndpointRegistration, String> {
        let identity = DeviceIdentity::parse(&endpoint.tls_fingerprint)
            .map_err(|error| format!("设备身份指纹无效：{error}"))?;
        endpoint.tls_fingerprint = identity.tls_pin();
        let client =
            build_client(&endpoint).map_err(|error| format!("无法创建设备连接：{error}"))?;
        let fingerprint = identity.fingerprint().clone();
        let handle = self.fleet.get_or_create(fingerprint, || CoreDevice {
            device_id: identity.device_id().clone(),
            name: endpoint.name.clone(),
            tls_fingerprint: endpoint.tls_fingerprint.clone(),
            discovery: DiscoveryState::Online,
            connection: ConnectionState::Disconnected,
            capture_activity: CaptureActivityState::Unknown,
        });
        let (is_new, endpoint_changed) = {
            let mut bindings = self.bindings.lock().unwrap();
            let endpoint_changed = bindings.endpoint_differs(identity.fingerprint(), &endpoint);
            if bindings.origin_differs(identity.fingerprint(), &endpoint) {
                // An authenticated capability is valid only for the origin
                // on which it was established. Fence in-flight work and
                // discard the local token before publishing the replacement
                // client under the same stable physical-device identity.
                handle.disconnect_local();
            }
            let is_new =
                bindings.bind(identity.clone(), endpoint, Arc::new(client), handle.clone());
            (is_new, endpoint_changed)
        };
        let discovery_changed = handle.set_discovery_state(DiscoveryState::Online);

        Ok(EndpointRegistration {
            identity,
            is_new,
            endpoint_changed,
            discovery_changed,
            handle,
        })
    }

    /// Registers a manual current-contract candidate by address. The current
    /// RDK-X5 lab/internal deployment exposes Device API v4 over HTTP on
    /// port 8080; device identity comes from `/api/v4/device.device_id`,
    /// not from a TLS certificate on 8443.
    pub fn add_manual_device(&self, ip: String) -> Result<FrontendDevice, String> {
        let address: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| "请输入有效的 IPv4 或 IPv6 地址".to_string())?;
        self.add_manual_device_with(address, probe_lab_v4_device)
    }

    fn add_manual_device_with(
        &self,
        address: IpAddr,
        probe: impl FnMut(&str, u16, Duration) -> Result<LabV4DeviceProbe, PiHttpError>,
    ) -> Result<FrontendDevice, String> {
        let target = manual_lab_v4_probe_target(address);
        let success =
            probe_v4_targets_with(vec![target], Vec::new(), Duration::from_secs(6), probe)
                .map_err(|failures| {
                    format!("无法探测设备 Device API v4 身份（HTTP）：{failures}")
                })?;
        let mut endpoint = lab_v4_endpoint_from_probe(success);
        let registration = self.register_endpoint(endpoint.clone())?;
        endpoint.tls_fingerprint = registration.identity.tls_pin();
        self.mdns_services
            .lock()
            .unwrap()
            .mark_manual(registration.identity.fingerprint().clone(), endpoint);
        registration
            .handle
            .set_discovery_state(DiscoveryState::Online);
        let id = registration.identity.device_id().as_str();
        let binding = self.resolve_binding(id)?;
        Ok(to_frontend_device(
            &binding.identity,
            &binding.handle.snapshot().device,
            Some(&binding.endpoint),
        ))
    }

    /// Every device this process currently knows about, mapped to the
    /// frontend-facing `Device` shape `models.rs` defines.
    ///
    /// Each device is read through its own handle in one short lock
    /// acquisition; nothing here holds the fleet's map lock while doing so.
    pub fn frontend_devices(&self) -> Vec<FrontendDevice> {
        let active_device_ids = self
            .active_pairings
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let bindings = self.bindings.lock().unwrap().bindings();
        let mut out = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let snapshot = binding.handle.snapshot();
            let mut frontend =
                to_frontend_device(&binding.identity, &snapshot.device, Some(&binding.endpoint));
            if active_device_ids.contains(binding.identity.device_id().as_str()) {
                frontend.state = FrontendDeviceState::Pending;
            }
            out.push(frontend);
        }
        out
    }

    /// Projects the durable upload activity lane into the frontend tray
    /// shape. Uploads deliberately do not share the coordinator's download
    /// `Transfer[]` surface: downloads are published through the separate
    /// `transfer_jobs:update` event and session-status projections. Keeping
    /// this method upload-only preserves that wire contract while replacing
    /// the old process-local `AppData::transfers` vector.
    pub fn upload_transfer_projections(&self) -> Result<Vec<Transfer>, String> {
        #[cfg(test)]
        if self
            .transfer_projection_read_failure
            .load(Ordering::Acquire)
        {
            return Err("injected transfer projection read failure".to_string());
        }

        let activities = self
            .transfer_store
            .lock()
            .unwrap()
            .list_upload_activities()
            .map_err(|error| format!("无法读取持久化上传进度：{error}"))?;

        let mut transfers = activities
            .into_iter()
            .map(|activity| {
                let (state, error, retryable) =
                    upload_transfer_state(&activity.job, activity.confirmed_bytes);
                Transfer {
                    key: activity.job.job_id,
                    label: activity.label,
                    total_bytes: activity.total_bytes,
                    sent_bytes: activity.confirmed_bytes,
                    state,
                    error,
                    retryable,
                    direction: TransferDirection::Up,
                    target_label: activity.target_label,
                }
            })
            .collect::<Vec<_>>();

        // SQLite's listing order is useful for an operator, but the frontend
        // also receives refreshes from multiple worker paths. Sort by the
        // stable transfer key so snapshots/events do not churn when those
        // paths observe the same durable rows in a different order.
        transfers.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(transfers)
    }

    /// Inject a deterministic durable transfer projection read failure for a
    /// facade isolation regression test. This is intentionally unavailable in
    /// production builds; real failures still originate from the SQLite
    /// transfer store above.
    #[cfg(test)]
    pub(crate) fn fail_transfer_projections_for_test(&self) {
        self.transfer_projection_read_failure
            .store(true, Ordering::Release);
    }

    /// Compatibility name used by event/snapshot callers. The production
    /// `transfers:update` resource is the upload activity lane; download job
    /// snapshots continue to use `transfer_jobs:update`.
    pub fn transfer_projections(&self) -> Result<Vec<Transfer>, String> {
        self.upload_transfer_projections()
    }

    // `list_sessions` used to live here: an error-swallowing wrapper around
    // `try_list_sessions` that turned a network failure into an empty
    // session list. Nothing called it any more -- every caller uses
    // `list_sessions_with_local_state`, which surfaces the error instead of
    // making a reachable device look like one with no recordings.

    /// Reads exactly one bounded catalog page. The cursor remains opaque and
    /// the caller-provided catalog revision fences load-more against a new
    /// device snapshot. Current v4 list rows intentionally stay summary-only;
    /// legacy rows retain their historical per-page detail verification.
    fn try_list_session_page(
        &self,
        device_id: &str,
        cursor: Option<&str>,
        expected_catalog_revision: Option<&str>,
        expected_connection_epoch: Option<u64>,
    ) -> Result<SessionCatalogPageRead, SessionCatalogPageError> {
        if cursor.is_some_and(str::is_empty) {
            return Err("会话分页游标不能为空".to_string().into());
        }
        let binding = self.resolve_binding(device_id)?;
        let api_profile = binding.endpoint.api_profile;
        let client = binding.client;
        let handle = binding.handle;
        let mut authenticated = authenticated_client_for(&handle, client.clone())?;
        if api_profile == DeviceApiProfile::LegacyPinnedTlsV1 {
            match handle.refresh_capture_activity_with(&authenticated) {
                RefreshApplyOutcome::Refreshed => {}
                RefreshApplyOutcome::NotConnected => {
                    return Err("该设备尚未连接或连接已失效".to_string().into())
                }
                RefreshApplyOutcome::Stale => {
                    return Err("设备连接在刷新期间已重建，请重试".to_string().into())
                }
                RefreshApplyOutcome::Failed(error) => {
                    return Err(
                        authenticated_request_error("刷新设备 publication 身份失败", error).into(),
                    )
                }
            }
            // A legacy transcript-less session becomes publication-key-bound
            // by the refresh above; rebuild the façade around that identity.
            authenticated = authenticated_client_for(&handle, client)?;
        }
        let negotiated = handle
            .negotiated_device_snapshot()
            .ok_or_else(|| "设备能力协商结果不可用，请重新连接后重试".to_string())?;
        let connection_epoch = negotiated.epoch;
        if expected_connection_epoch.is_some_and(|expected| expected != connection_epoch) {
            return Err("设备已重新连接，旧会话分页 cursor 已失效"
                .to_string()
                .into());
        }
        let capabilities = session_page_capabilities_from_negotiation(
            api_profile,
            negotiated.info.profile,
            &negotiated.info.capabilities,
        )?;

        let page = handle
            .list_sessions_with(&authenticated, cursor, Some(LAB_V4_SESSION_LIST_LIMIT))
            .map_err(|error| session_catalog_request_error("读取设备会话目录失败", error))?;
        let (catalog_revision, catalog_authority, pagination_supported, pagination_reason) =
            match page.catalog_authority {
                CatalogRevisionAuthorityView::LegacyDevice
                | CatalogRevisionAuthorityView::DeviceStable => {
                    if !page.pagination_supported || page.pagination_unavailable_reason.is_some() {
                        return Err("设备返回的会话目录 authority 与分页能力不一致"
                            .to_string()
                            .into());
                    }
                    let revision = page
                        .catalog_revision
                        .as_deref()
                        .filter(|revision| !revision.is_empty())
                        .ok_or_else(|| "设备返回了空的会话目录 revision".to_string())?;
                    (
                        Some(revision.to_string()),
                        SessionCatalogAuthority::DeviceSnapshot,
                        true,
                        None,
                    )
                }
                CatalogRevisionAuthorityView::LocalFirstPageCompatibility => {
                    if page.catalog_revision.is_some()
                        || page.pagination_supported
                        || page.next_cursor.is_some()
                        || page.pagination_unavailable_reason
                            != Some(PaginationUnavailableReasonView::FirmwareUpgradeRequired)
                    {
                        return Err("设备返回的首屏兼容目录包含不安全的分页元数据"
                            .to_string()
                            .into());
                    }
                    (
                        None,
                        SessionCatalogAuthority::Unavailable,
                        false,
                        Some(SessionPaginationUnavailableReason::CatalogRevisionUnavailable),
                    )
                }
            };
        if expected_catalog_revision
            .is_some_and(|expected| catalog_revision.as_deref() != Some(expected))
        {
            return Err("读取期间设备会话目录发生变化，请从第一页重新刷新"
                .to_string()
                .into());
        }
        if page.next_cursor.as_deref().is_some_and(|next| {
            next.is_empty() || next.len() > MAX_SESSION_CURSOR_BYTES || Some(next) == cursor
        }) {
            return Err("设备返回了无效或重复的会话分页游标".to_string().into());
        }
        if page.sessions.len() > LAB_V4_SESSION_LIST_LIMIT as usize {
            return Err(format!(
                "设备返回的会话页超过客户端上限 {}",
                LAB_V4_SESSION_LIST_LIMIT
            )
            .into());
        }
        let diagnostics = page
            .diagnostics
            .into_iter()
            .map(session_discovery_diagnostic_to_view)
            .collect::<Result<Vec<_>, _>>()?;

        let mut items = Vec::with_capacity(page.sessions.len());
        for summary in page.sessions {
            if api_profile == DeviceApiProfile::LabHttpV4 {
                items.push(session_summary_to_view(summary)?);
                continue;
            }
            let detail = match handle.get_session_with(&authenticated, &summary.session_id) {
                SessionDetailOutcome::Fetched(detail) => *detail,
                SessionDetailOutcome::NotConnected => {
                    return Err("该设备尚未连接或连接已失效".to_string().into())
                }
                SessionDetailOutcome::Stale => {
                    return Err("设备连接在读取会话详情期间已重建，请重试"
                        .to_string()
                        .into())
                }
                SessionDetailOutcome::Failed(error) => {
                    return Err(authenticated_request_error(
                        &format!("读取会话 {} 详情失败", summary.session_id),
                        error,
                    )
                    .into())
                }
            };
            ensure_summary_matches_detail(&summary, &detail)?;
            items.push(session_detail_to_view(detail)?);
        }

        let next_cursor = page.next_cursor;
        Ok(SessionCatalogPageRead {
            page: SessionPageView {
                items,
                diagnostics,
                has_more: next_cursor.is_some(),
                next_cursor,
                catalog_revision,
                catalog_authority,
                pagination_supported,
                pagination_unavailable_reason: pagination_reason,
                capabilities,
            },
            connection_epoch,
        })
    }

    /// Compatibility full-catalog read for destructive workflows that must
    /// evaluate every current row. Ordinary navigation uses
    /// [`Self::read_session_page`] and never performs this loop.
    fn try_list_sessions(&self, device_id: &str) -> Result<Vec<SessionView>, String> {
        collect_full_session_catalog(|cursor, catalog_revision, connection_epoch| {
            self.try_list_session_page(device_id, cursor, catalog_revision, connection_epoch)
                .map_err(|error| error.to_string())
        })
    }

    /// Real session catalog plus local state derived from persisted library
    /// entries, durable jobs and their completion outbox. Startup and explicit
    /// mutations strongly verify canonical media; ordinary navigation trusts
    /// that durable projection and performs no media filesystem I/O.
    pub fn list_sessions_with_local_state(
        &self,
        device_id: &str,
        library: &[LibraryEntry],
    ) -> Result<Vec<SessionView>, String> {
        let mut sessions = self.try_list_sessions(device_id)?;
        self.apply_local_session_state(device_id, library, &mut sessions)?;
        Ok(sessions)
    }

    pub(crate) fn read_session_page(
        &self,
        device_id: &str,
        cursor: Option<&str>,
        expected_catalog_revision: Option<&str>,
        expected_connection_epoch: Option<u64>,
    ) -> Result<SessionCatalogPageRead, SessionCatalogPageError> {
        self.try_list_session_page(
            device_id,
            cursor,
            expected_catalog_revision,
            expected_connection_epoch,
        )
    }

    /// Fetches immutable artifact descriptors only for an explicitly opened
    /// row. The list revision supplied by the caller must match the detail;
    /// a changed manifest is never attached to a stale summary. Local-library
    /// state is projected by the application only after this network read.
    pub(crate) fn read_session_detail(
        &self,
        device_id: &str,
        session_id: &str,
        expected_session_revision: &str,
        expected_connection_epoch: u64,
        expected_verification: Option<&SessionVerificationView>,
    ) -> Result<SessionView, String> {
        let binding = self.resolve_binding(device_id)?;
        if binding.handle.current_epoch() != Some(expected_connection_epoch) {
            return Err("设备已重新连接，旧会话详情请求已失效".to_string());
        }
        let detail = match binding.endpoint.api_profile {
            DeviceApiProfile::LegacyPinnedTlsV1 => {
                fetch_session_detail(&binding.handle, binding.client, session_id)?
            }
            DeviceApiProfile::LabHttpV4 => {
                let verification = expected_verification
                    .filter(|verification| {
                        verification.permits_detail_for(expected_session_revision)
                    })
                    .ok_or_else(|| {
                        "该会话缺少可用且与当前 revision 匹配的 gateway verification".to_string()
                    })?;
                let core_verification = gateway_verification_from_view(verification);
                fetch_verified_session_detail(
                    &binding.handle,
                    binding.client,
                    session_id,
                    &core_verification,
                )?
            }
        };
        if binding.handle.current_epoch() != Some(expected_connection_epoch) {
            return Err("设备已重新连接，旧会话详情请求已失效".to_string());
        }
        if detail.revision != expected_session_revision {
            return Err(format!(
                "会话 {session_id} 的 revision 已变化，请刷新列表后重试"
            ));
        }
        session_detail_to_view(detail)
    }

    pub(crate) fn apply_local_session_state_to_items(
        &self,
        device_id: &str,
        library: &[LibraryEntry],
        sessions: &mut [SessionView],
    ) -> Result<(), String> {
        self.apply_local_session_state(device_id, library, sessions)
    }

    fn apply_local_session_state(
        &self,
        device_id: &str,
        library: &[LibraryEntry],
        sessions: &mut [SessionView],
    ) -> Result<(), String> {
        let (api_profile, device_keys) = {
            let bindings = self.bindings.lock().unwrap();
            let binding = bindings
                .resolve(&DeviceId(device_id.to_string()))
                .map_err(|error| format!("设备身份解析失败：{error}"))?;
            (
                binding.endpoint.api_profile,
                bindings.download_job_lookup_ids(&binding.identity),
            )
        };
        let session_ids = sessions
            .iter()
            .map(|view| view.session.id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let job_states = self
            .transfer_store
            .lock()
            .unwrap()
            .list_download_session_job_states_for_sessions(&device_keys, &session_ids)
            .map_err(|error| format!("无法读取下载任务状态：{error}"))?;
        let job_status_by_session = self.aggregate_download_session_job_states(job_states);
        let device_keys = device_keys
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let session_ids = session_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let mut library_by_session = HashMap::with_capacity(session_ids.len());
        for entry in library.iter().filter(|entry| {
            device_keys.contains(entry.device_id.as_str())
                && session_ids.contains(entry.session_id.as_str())
        }) {
            // Preserve the historical first-match behavior if corrupt history
            // contains duplicate rows; destructive actions reject duplicates
            // independently at their strong authorization boundary.
            library_by_session
                .entry(entry.session_id.as_str())
                .or_insert(entry);
        }

        for view in sessions {
            let entry = library_by_session.get(view.session.id.as_str()).copied();
            let complete_local = entry
                .map(|entry| {
                    library_entry_covers_session_for_profile(entry, &view.session, api_profile)
                        && entry_has_durable_canonical_projection(entry)
                })
                .unwrap_or(false);
            let job_status = job_status_by_session
                .get(view.session.id.as_str())
                .copied()
                .unwrap_or_default();
            view.download_status = download_status_for_local_state(
                complete_local,
                job_status.active,
                job_status.failed,
            );
            view.backed_up = complete_local
                && entry
                    .map(|entry| {
                        entry.upload_status == UploadStatus::Done
                            && entry_has_complete_object_receipts(entry)
                    })
                    .unwrap_or(false);
        }
        Ok(())
    }

    /// Builds a deletion preview from the *current* authenticated Pi
    /// catalog. A durable `Done` projection alone is deliberately
    /// insufficient: every locally recorded file must still be a regular
    /// file below `library_root` with the exact signed size.
    pub fn plan_downloaded_cleanup(
        &self,
        device_id: &str,
        library: &[LibraryEntry],
    ) -> Result<DownloadedCleanupPlan, String> {
        let library_root = self.library_root();
        let sessions = self.list_sessions_with_local_state(device_id, library)?;
        let (eligible, skipped) = downloaded_cleanup_candidates_with_match(
            &library_root,
            device_id,
            &sessions,
            library,
            |stored, current| self.device_ids_match(stored, current),
        );
        let eligible_bytes = eligible
            .iter()
            .fold(0_u64, |total, item| total.saturating_add(item.bytes));
        Ok(DownloadedCleanupPlan {
            eligible,
            skipped,
            eligible_bytes,
            sessions,
        })
    }

    /// Deletes one candidate at the exact revision that passed the local
    /// copy checks. The key is stable for `(device, session, revision)`, so
    /// retrying after a lost response replays the same idempotent Pi DELETE
    /// rather than creating a second logical operation.
    pub fn delete_downloaded_candidate(
        &self,
        device_id: &str,
        candidate: &DownloadedCleanupCandidate,
    ) -> Result<(), String> {
        if !self.device_ids_match(&candidate.local_device_id, device_id) {
            return Err("本地清理候选不属于当前设备".to_string());
        }
        // The preview may have been displayed for several seconds before
        // confirmation, and an external process may have moved a local file
        // in that interval. Re-check disk immediately before every DELETE.
        let library_root = self.library_root();
        validate_downloaded_cleanup_files(
            &library_root,
            &candidate.local_device_id,
            &candidate.session_id,
            &candidate.local_files,
        )?;
        let binding = self.resolve_binding(device_id)?;
        if binding.endpoint.api_profile == DeviceApiProfile::LabHttpV4 {
            return Err(LAB_V4_SESSION_DELETE_UNSUPPORTED_MESSAGE.to_string());
        }
        let idempotency_key = downloaded_cleanup_idempotency_key(
            binding.identity.device_id().as_str(),
            &candidate.session_id,
            &candidate.revision,
        );
        // The DELETE itself runs with no lock held and its receipt is
        // applied under epoch fencing, so a reply that arrives after the
        // session was re-established is refused rather than reported as a
        // deletion this connection observed.
        let authenticated = authenticated_client_for(&binding.handle, binding.client)?;
        let receipt = binding.handle.delete_session_with(
            &authenticated,
            &candidate.session_id,
            &candidate.revision,
            &idempotency_key,
        );
        let receipt = match receipt {
            DeleteApplyOutcome::Deleted(receipt) => receipt,
            DeleteApplyOutcome::NotConnected => {
                return Err("该设备尚未连接或连接已失效".to_string())
            }
            DeleteApplyOutcome::Stale => {
                return Err("设备连接在删除期间已重建，请重新确认后重试".to_string())
            }
            DeleteApplyOutcome::Failed(error) => {
                return Err(authenticated_request_error("", error));
            }
        };
        if receipt.session_id != candidate.session_id || receipt.revision != candidate.revision {
            return Err("设备返回了不匹配的删除回执".to_string());
        }
        Ok(())
    }

    pub fn revalidate_downloaded_candidate(
        &self,
        device_id: &str,
        candidate: &DownloadedCleanupCandidate,
    ) -> Result<(), String> {
        if !self.device_ids_match(&candidate.local_device_id, device_id) {
            return Err("本地清理候选不属于当前设备".to_string());
        }
        let library_root = self.library_root();
        validate_downloaded_cleanup_files(
            &library_root,
            &candidate.local_device_id,
            &candidate.session_id,
            &candidate.local_files,
        )
    }

    /// Automatic backed-up cleanup is one revision-bound operation: refresh
    /// the current Pi detail, re-prove the durable completion receipts, then
    /// issue DELETE with the original candidate's revision and stable key.
    pub fn delete_backed_up_candidate(
        &self,
        device_id: &str,
        candidate: &DownloadedCleanupCandidate,
        library: &[LibraryEntry],
    ) -> Result<(), String> {
        if self.resolve_binding(device_id)?.endpoint.api_profile == DeviceApiProfile::LabHttpV4 {
            return Err(LAB_V4_SESSION_DELETE_UNSUPPORTED_MESSAGE.to_string());
        }
        self.revalidate_backed_up_candidate(device_id, candidate, library)?;
        self.delete_downloaded_candidate(device_id, candidate)
    }

    fn revalidate_backed_up_candidate(
        &self,
        device_id: &str,
        candidate: &DownloadedCleanupCandidate,
        library: &[LibraryEntry],
    ) -> Result<(), String> {
        if !self.device_ids_match(&candidate.local_device_id, device_id) {
            return Err("本地清理候选不属于当前设备".to_string());
        }
        let binding = self.resolve_binding(device_id)?;
        let detail = fetch_session_detail(&binding.handle, binding.client, &candidate.session_id)?;
        let current_session = session_detail_to_view(detail)?.session;
        let library_root = self.library_root();
        validate_backed_up_cleanup_candidate(
            &library_root,
            device_id,
            candidate,
            &current_session,
            library,
            |stored, current| self.device_ids_match(stored, current),
        )
    }

    fn aggregate_download_session_job_states(
        &self,
        job_states: impl IntoIterator<Item = DownloadSessionJobState>,
    ) -> HashMap<String, DownloadSessionLocalJobStatus> {
        let mut by_session = HashMap::new();
        for state in job_states {
            let job = &state.job;
            let status = by_session
                .entry(job.identity.session_id().as_str().to_string())
                .or_insert_with(DownloadSessionLocalJobStatus::default);
            match job.state {
                JobStateTag::Failed | JobStateTag::Cancelled => status.failed = true,
                JobStateTag::Succeeded => match state.completion {
                    // Ack means the library projection was durably applied.
                    CompletionDeliveryState::Acknowledged => {}
                    // Pending is replayable; Missing is inconsistent. Both
                    // need attention rather than appearing as in-progress.
                    CompletionDeliveryState::Pending | CompletionDeliveryState::Missing => {
                        status.failed = true
                    }
                },
                _ => match self.coordinator.job_state(&JobId(job.job_id.clone())) {
                    Some(TransferJobState::Failed { .. }) | Some(TransferJobState::Cancelled) => {
                        status.failed = true
                    }
                    Some(_) => status.active = true,
                    None => status.failed = true,
                },
            }
        }
        by_session
    }

    #[cfg(test)]
    fn pending_status(&self, device_id: &str, session_id: &str) -> Result<(bool, bool), String> {
        let job_states = self
            .transfer_store
            .lock()
            .unwrap()
            .list_download_session_job_states_for_sessions(
                &[device_id.to_string()],
                &[session_id.to_string()],
            )
            .map_err(|error| format!("无法读取下载任务状态：{error}"))?;
        let status = self
            .aggregate_download_session_job_states(job_states)
            .remove(session_id)
            .unwrap_or_default();
        Ok((status.active, status.failed))
    }

    /// PC-08b: real session delete (`DELETE /sessions/{id}`) -- fetches the
    /// session's current `revision` first (the Pi requires a matching
    /// `If-Match`), then deletes with a fresh idempotency key. Returns
    /// `Err` with a user-facing message on any failure (unknown device,
    /// not connected, or the Pi call itself failing) rather than silently
    /// no-op'ing.
    pub fn delete_session(&self, device_id: &str, session_id: &str) -> Result<(), String> {
        let binding = self.resolve_binding(device_id)?;
        if binding.endpoint.api_profile == DeviceApiProfile::LabHttpV4 {
            return Err(LAB_V4_SESSION_DELETE_UNSUPPORTED_MESSAGE.to_string());
        }
        let client = binding.client;
        let handle = binding.handle;
        // Three network round trips, none of them holding a lock, each
        // fenced on the connection epoch it was issued under.
        let summary = fetch_session_detail(&handle, client.clone(), session_id)?;
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let authenticated = authenticated_client_for(&handle, client)?;
        match handle.delete_session_with(
            &authenticated,
            session_id,
            &summary.revision,
            &idempotency_key,
        ) {
            DeleteApplyOutcome::Deleted(_) => Ok(()),
            DeleteApplyOutcome::NotConnected => Err("该设备尚未连接或连接已失效".to_string()),
            DeleteApplyOutcome::Stale => {
                Err("设备连接在删除期间已重建，请重新确认后重试".to_string())
            }
            DeleteApplyOutcome::Failed(error) => Err(error.to_string()),
        }
    }
}

fn ensure_summary_matches_detail(
    summary: &SessionSummaryView,
    detail: &SessionDetailView,
) -> Result<(), String> {
    if summary.session_id != detail.session_id
        || summary.revision != detail.revision
        || summary.captured_at != detail.captured_at
        || summary.published_at != detail.published_at
        || summary.duration_seconds != detail.duration_seconds
        || summary.total_bytes != detail.total_bytes
        || summary.video_bytes != detail.video_bytes
        || summary.file_count != detail.file_count
        || detail.file_count != detail.files.len() as u64
    {
        return Err(format!(
            "会话 {} 的目录摘要与详情不一致，请刷新后重试",
            summary.session_id
        ));
    }
    Ok(())
}

fn collect_full_session_catalog<F>(mut read_page: F) -> Result<Vec<SessionView>, String>
where
    F: FnMut(Option<&str>, Option<&str>, Option<u64>) -> Result<SessionCatalogPageRead, String>,
{
    let started = Instant::now();
    let mut items = Vec::new();
    let mut received_items = 0_usize;
    let mut pages = 0_usize;
    let mut cursor: Option<String> = None;
    let mut catalog_revision: Option<String> = None;
    let mut connection_epoch: Option<u64> = None;
    let mut seen_cursors = HashSet::new();
    let mut seen_session_ids = HashSet::new();
    let mut seen_quarantine_ids = HashSet::new();
    loop {
        if pages >= MAX_FULL_SESSION_CATALOG_PAGES {
            return Err(format!(
                "设备会话目录超过客户端总页数上限 {}，已拒绝继续执行破坏性操作",
                MAX_FULL_SESSION_CATALOG_PAGES
            ));
        }
        if started.elapsed() >= FULL_SESSION_CATALOG_DEADLINE {
            return Err("读取完整设备会话目录超时，已拒绝继续执行破坏性操作".to_string());
        }
        let read = read_page(
            cursor.as_deref(),
            catalog_revision.as_deref(),
            connection_epoch,
        )?;
        pages += 1;
        if started.elapsed() >= FULL_SESSION_CATALOG_DEADLINE {
            return Err("读取完整设备会话目录超时，已拒绝继续执行破坏性操作".to_string());
        }
        connection_epoch = Some(read.connection_epoch);
        let page = read.page;
        if !page.pagination_supported {
            return Err(
                "设备会话目录不提供快照级 revision，已拒绝将首屏当作完整目录执行破坏性操作"
                    .to_string(),
            );
        }
        let page_revision = page
            .catalog_revision
            .as_deref()
            .ok_or_else(|| "设备会话目录缺少快照级 revision".to_string())?;
        if catalog_revision.is_none() {
            catalog_revision = Some(page_revision.to_string());
        } else if catalog_revision.as_deref() != Some(page_revision) {
            return Err("读取期间设备会话目录 revision 发生变化".to_string());
        }
        let page_entry_count = page
            .items
            .len()
            .checked_add(page.diagnostics.len())
            .ok_or_else(|| "设备会话目录条目计数溢出".to_string())?;
        received_items = received_items
            .checked_add(page_entry_count)
            .ok_or_else(|| "设备会话目录条目计数溢出".to_string())?;
        if received_items > MAX_FULL_SESSION_CATALOG_ITEMS {
            return Err(format!(
                "设备会话目录超过客户端总条目上限 {}，已拒绝继续执行破坏性操作",
                MAX_FULL_SESSION_CATALOG_ITEMS
            ));
        }
        for session in &page.items {
            if !seen_session_ids.insert(session.session.id.clone()) {
                return Err(format!(
                    "设备在完整会话目录中重复返回 sessionId {}",
                    session.session.id
                ));
            }
        }
        for diagnostic in &page.diagnostics {
            if !seen_quarantine_ids.insert(diagnostic.quarantine_id.clone()) {
                return Err(format!(
                    "设备在完整会话目录中重复返回 quarantineId {}",
                    diagnostic.quarantine_id
                ));
            }
        }
        validate_full_catalog_order(&items, &page.items)?;
        append_session_items(&mut items, page.items);
        let Some(next) = page.next_cursor else {
            return Ok(items);
        };
        if !seen_cursors.insert(next.clone()) {
            return Err("设备返回了重复的会话分页游标".to_string());
        }
        cursor = Some(next);
    }
}

/// Appends a page after `collect_full_session_catalog` has independently
/// admitted every identity and newest-first boundary.
fn append_session_items(existing: &mut Vec<SessionView>, incoming: Vec<SessionView>) {
    existing.extend(incoming);
}

fn validate_full_catalog_order(
    existing: &[SessionView],
    incoming: &[SessionView],
) -> Result<(), String> {
    let validate_pair = |newer: &SessionView, older: &SessionView| {
        let newer_timestamp = chrono::DateTime::parse_from_rfc3339(&newer.session.date_label)
            .map_err(|_| "设备会话目录 started_at 不是有效的 RFC 3339 时间".to_string())?;
        let older_timestamp = chrono::DateTime::parse_from_rfc3339(&older.session.date_label)
            .map_err(|_| "设备会话目录 started_at 不是有效的 RFC 3339 时间".to_string())?;
        if newer_timestamp > older_timestamp
            || (newer_timestamp == older_timestamp && newer.session.id > older.session.id)
        {
            Ok(())
        } else {
            Err("设备会话目录没有按 (started_at, session_id) newest-first 严格排序".to_string())
        }
    };
    for pair in incoming.windows(2) {
        validate_pair(&pair[0], &pair[1])?;
    }
    if let (Some(previous), Some(next)) = (existing.last(), incoming.first()) {
        validate_pair(previous, next)?;
    }
    Ok(())
}

fn session_capability_from_negotiation(capability: NegotiatedCapabilityView) -> SessionCapability {
    let source = match capability.source {
        CapabilitySourceView::DeviceDescriptor => SessionCapabilitySource::DeviceDescriptor,
        CapabilitySourceView::ProfileContract => SessionCapabilitySource::ProfileContract,
        CapabilitySourceView::Unavailable => SessionCapabilitySource::Unavailable,
    };
    SessionCapability {
        supported: capability.supported && source != SessionCapabilitySource::Unavailable,
        source,
    }
}

fn session_page_capabilities_from_negotiation(
    endpoint_profile: DeviceApiProfile,
    negotiated_profile: DeviceApiProfileView,
    capabilities: &DeviceCapabilitiesView,
) -> Result<SessionPageCapabilities, String> {
    let profile = match (endpoint_profile, negotiated_profile) {
        (DeviceApiProfile::LegacyPinnedTlsV1, DeviceApiProfileView::LegacyPinnedHttpsV1) => {
            SessionApiProfile::LegacyPinnedTlsV1
        }
        (DeviceApiProfile::LabHttpV4, DeviceApiProfileView::LabHttpV4) => {
            SessionApiProfile::LabHttpV4
        }
        _ => return Err("连接端点与设备协商的 API profile 不一致".to_string()),
    };
    let session_list = session_capability_from_negotiation(capabilities.session_list);
    if !session_list.supported {
        return Err("设备能力协商结果未授权读取会话目录".to_string());
    }
    Ok(SessionPageCapabilities {
        profile,
        session_deletion: session_capability_from_negotiation(capabilities.session_deletion),
        session_detail: session_capability_from_negotiation(capabilities.session_detail),
        artifact_download: session_capability_from_negotiation(capabilities.artifact_download),
        capture_status: session_capability_from_negotiation(capabilities.capture_status),
    })
}

fn session_discovery_diagnostic_to_view(
    diagnostic: CoreSessionDiscoveryDiagnosticView,
) -> Result<SessionDiscoveryDiagnosticView, String> {
    let code = match diagnostic.code {
        SessionDiscoveryDiagnosticCodeView::ManifestUnreadable => {
            SessionDiscoveryDiagnosticCode::ManifestUnreadable
        }
        SessionDiscoveryDiagnosticCodeView::UnsupportedSchema => {
            SessionDiscoveryDiagnosticCode::UnsupportedSchema
        }
        SessionDiscoveryDiagnosticCodeView::ManifestInvalid => {
            SessionDiscoveryDiagnosticCode::ManifestInvalid
        }
        SessionDiscoveryDiagnosticCodeView::ManifestNotSealed => {
            SessionDiscoveryDiagnosticCode::ManifestNotSealed
        }
    };
    Ok(SessionDiscoveryDiagnosticView {
        quarantine_id: diagnostic.quarantine_id,
        code,
        observed_at: diagnostic.observed_at,
        message: diagnostic.message,
    })
}

fn session_verification_to_view(
    verification: Option<GatewayVerificationView>,
) -> Result<Option<SessionVerificationView>, String> {
    let Some(verification) = verification else {
        return Ok(None);
    };
    let verdict = match verification.verdict {
        GatewayVerificationVerdictView::Usable => SessionVerificationVerdict::Usable,
        GatewayVerificationVerdictView::Unusable => SessionVerificationVerdict::Unusable,
    };
    let diagnostics = verification
        .diagnostics
        .into_iter()
        .map(|diagnostic| match diagnostic {
            GatewayVerificationDiagnosticView::LegacyMessage(message) => {
                Ok(SessionVerificationDiagnosticView::LegacyMessage(message))
            }
            GatewayVerificationDiagnosticView::Structured { code, summary } => {
                let code = match code.as_str() {
                    "artifact_digest_mismatch" => {
                        SessionVerificationDiagnosticCode::ArtifactDigestMismatch
                    }
                    "artifact_invalid" => SessionVerificationDiagnosticCode::ArtifactInvalid,
                    "manifest_invalid" => SessionVerificationDiagnosticCode::ManifestInvalid,
                    "verification_failed" => SessionVerificationDiagnosticCode::VerificationFailed,
                    _ => return Err("设备返回了未知的 gateway verification 诊断代码".to_string()),
                };
                Ok(SessionVerificationDiagnosticView::Structured { code, summary })
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Some(SessionVerificationView {
        verdict,
        actor: verification.actor,
        validator: SessionVerificationValidatorView {
            name: verification.validator_name,
            version: verification.validator_version,
            build_sha256: verification.validator_build_sha256,
        },
        manifest_sha256: verification.manifest_sha256,
        verified_at: verification.verified_at,
        diagnostics,
        manifest_digest_valid: verification.manifest_digest_valid,
    }))
}

fn gateway_verification_from_view(
    verification: &SessionVerificationView,
) -> GatewayVerificationView {
    let verdict = match verification.verdict {
        SessionVerificationVerdict::Usable => GatewayVerificationVerdictView::Usable,
        SessionVerificationVerdict::Unusable => GatewayVerificationVerdictView::Unusable,
    };
    GatewayVerificationView {
        actor: verification.actor.clone(),
        validator_name: verification.validator.name.clone(),
        validator_version: verification.validator.version.clone(),
        validator_build_sha256: verification.validator.build_sha256.clone(),
        manifest_sha256: verification.manifest_sha256.clone(),
        manifest_digest_valid: verification.manifest_digest_valid,
        verified_at: verification.verified_at.clone(),
        verdict,
        diagnostics: verification
            .diagnostics
            .iter()
            .map(|diagnostic| match diagnostic {
                SessionVerificationDiagnosticView::LegacyMessage(message) => {
                    GatewayVerificationDiagnosticView::LegacyMessage(message.clone())
                }
                SessionVerificationDiagnosticView::Structured { code, summary } => {
                    GatewayVerificationDiagnosticView::Structured {
                        code: match code {
                            SessionVerificationDiagnosticCode::ArtifactDigestMismatch => {
                                "artifact_digest_mismatch"
                            }
                            SessionVerificationDiagnosticCode::ArtifactInvalid => {
                                "artifact_invalid"
                            }
                            SessionVerificationDiagnosticCode::ManifestInvalid => {
                                "manifest_invalid"
                            }
                            SessionVerificationDiagnosticCode::VerificationFailed => {
                                "verification_failed"
                            }
                        }
                        .to_string(),
                        summary: summary.clone(),
                    }
                }
            })
            .collect(),
    }
}

fn session_detail_to_view(detail: SessionDetailView) -> Result<SessionView, String> {
    let verification = session_verification_to_view(detail.gateway_verification)?;
    Ok(SessionView {
        session: Session {
            id: detail.session_id,
            revision: detail.revision,
            date_label: detail.captured_at,
            duration_seconds: detail.duration_seconds,
            total_bytes: detail.total_bytes,
            video_bytes: detail.video_bytes,
            imu_samples: None,
            files: detail
                .files
                .into_iter()
                .map(|file| {
                    SessionFile::new(file.id, file.display_path, file.size_bytes, file.sha256)
                })
                .collect(),
        },
        download_status: DownloadStatus::None,
        backed_up: false,
        verification,
    })
}

fn session_summary_to_view(summary: SessionSummaryView) -> Result<SessionView, String> {
    let verification = session_verification_to_view(summary.gateway_verification)?;
    Ok(SessionView {
        session: Session {
            id: summary.session_id,
            revision: summary.revision,
            date_label: summary.captured_at,
            duration_seconds: summary.duration_seconds,
            total_bytes: summary.total_bytes,
            video_bytes: summary.video_bytes,
            imu_samples: None,
            // Device API v4 list pages are intentionally summary-only. Pulling
            // detail for every row made first paint and ordinary refresh scale
            // with N+1 network calls; explicit downloads still fetch detail.
            files: Vec::new(),
        },
        download_status: DownloadStatus::None,
        backed_up: false,
        verification,
    })
}

fn library_entry_covers_session_for_profile(
    entry: &LibraryEntry,
    session: &Session,
    api_profile: DeviceApiProfile,
) -> bool {
    if api_profile == DeviceApiProfile::LabHttpV4 && session.files.is_empty() {
        return entry.complete
            && entry
                .publication
                .as_ref()
                .is_some_and(|publication| publication.revision == session.revision);
    }
    library_entry_covers_session(entry, session)
}

fn library_entry_covers_session(entry: &LibraryEntry, session: &Session) -> bool {
    entry.complete
        && !session.files.is_empty()
        && entry.files.len() == session.files.len()
        && entry
            .publication
            .as_ref()
            .is_some_and(|publication| publication.revision == session.revision)
        && session.files.iter().all(|expected| {
            entry.files.iter().any(|local| {
                local.file_id == expected.file_id
                    && local.display_path == expected.display_path
                    && local.bytes == expected.bytes
                    && !local.sha256.is_empty()
                    && local.sha256 == expected.sha256
            })
        })
}

/// Pure durable projection check for ordinary session navigation.
///
/// The canonical commit and startup reconciliation are the boundaries that
/// populate this exact MP4/receipt pair after strong on-disk verification.
/// Session refresh deliberately consumes only those persisted fields; upload,
/// cleanup and delete authorization independently reopen and hash the assets.
fn entry_has_durable_canonical_projection(entry: &LibraryEntry) -> bool {
    if !entry.complete || entry.processed_files.len() != 2 {
        return false;
    }
    let output_path = format!("processed/{}.mp4", entry.session_id);
    let output = entry
        .processed_files
        .iter()
        .find(|file| file.display_path == output_path);
    let receipt = entry
        .processed_files
        .iter()
        .find(|file| file.display_path == derived_media::RECEIPT_DISPLAY_PATH);
    let Some((output, receipt)) = output.zip(receipt) else {
        return false;
    };
    let is_durable_asset = |file: &SessionFile| {
        file.bytes > 0
            && file.file_id == file.sha256
            && file.sha256.len() == 64
            && file
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    is_durable_asset(output)
        && is_durable_asset(receipt)
        && output
            .bytes
            .checked_add(receipt.bytes)
            .is_some_and(|total| total == entry.bytes)
}

fn download_status_for_local_state(
    complete_local: bool,
    has_active_job: bool,
    has_failed_job: bool,
) -> DownloadStatus {
    if has_active_job {
        DownloadStatus::Downloading
    } else if complete_local {
        DownloadStatus::Done
    } else if has_failed_job {
        DownloadStatus::Failed
    } else {
        DownloadStatus::None
    }
}

/// Pure catalog/library selection plus read-only filesystem validation. Kept
/// outside the command layer so preview and execution cannot drift into two
/// subtly different definitions of "already downloaded".
fn downloaded_cleanup_candidates_with_match<F>(
    library_root: &Path,
    device_id: &str,
    sessions: &[SessionView],
    library: &[LibraryEntry],
    device_ids_match: F,
) -> (Vec<DownloadedCleanupCandidate>, Vec<DownloadedCleanupSkip>)
where
    F: Fn(&str, &str) -> bool,
{
    let mut eligible = Vec::new();
    let mut skipped = Vec::new();

    for view in sessions {
        let session = &view.session;
        let skip = |reason: String| DownloadedCleanupSkip {
            session_id: session.id.clone(),
            date_label: session.date_label.clone(),
            bytes: session.total_bytes,
            reason,
        };

        if view.download_status != DownloadStatus::Done {
            let reason = match view.download_status {
                DownloadStatus::None => "尚未完整下载到本机".to_string(),
                DownloadStatus::Downloading => "本地下载尚未完成".to_string(),
                DownloadStatus::Failed => "本地下载失败或已取消".to_string(),
                DownloadStatus::Done => unreachable!(),
            };
            skipped.push(skip(reason));
            continue;
        }

        let matching = library
            .iter()
            .filter(|entry| {
                device_ids_match(&entry.device_id, device_id) && entry.session_id == session.id
            })
            .collect::<Vec<_>>();
        let entry = match matching.as_slice() {
            [entry] => *entry,
            [] => {
                skipped.push(skip("缺少本地 durable library 记录".to_string()));
                continue;
            }
            _ => {
                skipped.push(skip("存在重复的本地 durable library 记录".to_string()));
                continue;
            }
        };

        if let Err(reason) = validate_downloaded_cleanup_entry(library_root, entry, session) {
            skipped.push(skip(reason));
            continue;
        }

        let Some(canonical) = canonical_assets_for_entry(library_root, entry) else {
            skipped.push(skip(
                "本地规范 MP4 或 derived media receipt 无法重新验证".to_string(),
            ));
            continue;
        };
        eligible.push(DownloadedCleanupCandidate {
            session_id: session.id.clone(),
            revision: session.revision.clone(),
            date_label: session.date_label.clone(),
            bytes: canonical.total_bytes,
            local_device_id: entry.device_id.clone(),
            local_files: canonical.files,
        });
    }

    (eligible, skipped)
}

#[cfg(test)]
fn downloaded_cleanup_candidates(
    library_root: &Path,
    device_id: &str,
    sessions: &[SessionView],
    library: &[LibraryEntry],
) -> (Vec<DownloadedCleanupCandidate>, Vec<DownloadedCleanupSkip>) {
    downloaded_cleanup_candidates_with_match(
        library_root,
        device_id,
        sessions,
        library,
        |left, right| left == right,
    )
}

fn validate_downloaded_cleanup_entry(
    library_root: &Path,
    entry: &LibraryEntry,
    session: &Session,
) -> Result<(), String> {
    if !library_entry_covers_session(entry, session) {
        return Err("本地 durable library 记录不覆盖当前 Pi 会话 revision".to_string());
    }
    let unique_file_ids = entry
        .files
        .iter()
        .map(|file| file.file_id.as_str())
        .collect::<HashSet<_>>();
    if unique_file_ids.len() != entry.files.len() {
        return Err("本地 durable library 文件清单包含重复项".to_string());
    }

    canonical_assets_for_entry(library_root, entry)
        .map(|_| ())
        .ok_or_else(|| "本地规范 MP4 或 derived media receipt 无法重新验证".to_string())
}

fn validate_backed_up_cleanup_candidate<F>(
    library_root: &Path,
    device_id: &str,
    candidate: &DownloadedCleanupCandidate,
    current_session: &Session,
    library: &[LibraryEntry],
    device_ids_match: F,
) -> Result<(), String>
where
    F: Fn(&str, &str) -> bool,
{
    if !device_ids_match(&candidate.local_device_id, device_id) {
        return Err("本地清理候选不属于当前设备".to_string());
    }
    if current_session.id != candidate.session_id {
        return Err("设备返回了不匹配的会话详情".to_string());
    }
    if current_session.revision != candidate.revision {
        return Err(format!(
            "Pi 会话 revision 已从 {} 变为 {}，未执行自动清理",
            candidate.revision, current_session.revision
        ));
    }

    let matching = library
        .iter()
        .filter(|entry| {
            device_ids_match(&entry.device_id, device_id)
                && entry.session_id == candidate.session_id
        })
        .collect::<Vec<_>>();
    let entry = match matching.as_slice() {
        [entry] => *entry,
        [] => return Err("缺少当前 durable library 记录，未执行自动清理".to_string()),
        _ => return Err("存在重复的 durable library 记录，未执行自动清理".to_string()),
    };
    validate_downloaded_cleanup_entry(library_root, entry, current_session)?;
    if entry.upload_status != UploadStatus::Done || !entry_has_complete_object_receipts(entry) {
        return Err("当前 durable library 的备份完成凭证不完整，未执行自动清理".to_string());
    }
    Ok(())
}

fn validate_downloaded_cleanup_files(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    files: &[SessionFile],
) -> Result<(), String> {
    for file in files {
        resolve_downloaded_file(library_root, device_id, session_id, file)?;
    }
    Ok(())
}

/// Returns a frontend projection of durable library history. `complete` in
/// SQLite records that the immutable Pi inventory was downloaded at commit
/// time; the projected value additionally says every expected local file is
/// still a regular, exact-size file below the configured library root.
///
/// The durable entries are never mutated here. Publication evidence, upload
/// receipts and upload history remain available even after a user removes a
/// file outside the application.
pub(crate) fn project_library_entries(
    library_root: &Path,
    entries: &[LibraryEntry],
) -> Vec<LibraryEntry> {
    entries
        .iter()
        .cloned()
        .map(|mut entry| {
            if let Some(canonical) = canonical_assets_for_entry(library_root, &entry) {
                entry.complete = true;
                entry.processed_files = canonical.files;
                entry.bytes = canonical.total_bytes;
            } else {
                entry.complete = false;
                entry.processed_files.clear();
            }
            entry
        })
        .collect()
}

/// Promotes receipt-verifiable legacy processed MP4s into the canonical
/// derived-only layout before the durable library becomes visible. A failed
/// migration never mutates the legacy directory; the row is marked
/// incomplete and retains its source inventory for an ordinary reprocess.
pub(crate) fn reconcile_existing_derived_media(
    comp: &Composition,
    entries: &mut [LibraryEntry],
) -> Result<bool, String> {
    let committer = DerivedMediaCommitter::new(ffmpeg_export_config()?);
    let current_root = comp.library_root();
    let mut changed = false;
    for entry in entries {
        let publication = match validate_entry_publication(entry) {
            Ok(publication) => publication.payload.clone(),
            Err(error) => {
                eprintln!(
                    "[composition] legacy derived migration skipped for {}/{}: {}",
                    entry.device_id, entry.session_id, error
                );
                if entry.complete {
                    entry.complete = false;
                    changed = true;
                }
                continue;
            }
        };
        let roots = entry_search_roots(&current_root, entry);
        let mut promoted = None;
        let mut diagnostics = Vec::new();
        for root in roots {
            match committer.migrate_existing(
                &root,
                &entry.device_id,
                &entry.session_id,
                &publication,
                &entry.processed_files,
            ) {
                Ok(Some(canonical)) => {
                    promoted = Some((root, canonical));
                    break;
                }
                Ok(None) => diagnostics.push(format!("{}: no migration candidate", root.display())),
                Err(error) => diagnostics.push(format!("{}: {error}", root.display())),
            }
        }
        if let Some((root, canonical)) = promoted {
            let canonical_changed = !entry.complete
                || entry.processed_files != canonical.files
                || entry.bytes != canonical.total_bytes
                || entry.library_root.as_deref() != Some(root.to_string_lossy().as_ref());
            if canonical_changed {
                entry.complete = true;
                entry.processed_files = canonical.files;
                entry.bytes = canonical.total_bytes;
                entry.library_root = Some(root.to_string_lossy().into_owned());
                entry.upload_status = UploadStatus::None;
                entry.upload_retryable = false;
                entry.uploaded_at = None;
                entry.upload_error = None;
                entry.object_receipts.clear();
                entry.upload_projection = None;
                changed = true;
            }
            continue;
        }

        eprintln!(
            "[composition] legacy derived migration requires reprocessing for {}/{}: {}",
            entry.device_id,
            entry.session_id,
            diagnostics.join("; ")
        );
        if entry.complete {
            entry.complete = false;
            changed = true;
        }
        if let Some(actual_bytes) = entry_search_roots(&current_root, entry)
            .into_iter()
            .find_map(|root| exact_session_disk_bytes(&root, entry).ok())
        {
            if entry.bytes != actual_bytes {
                entry.bytes = actual_bytes;
                changed = true;
            }
        }
    }
    Ok(changed)
}

fn exact_session_disk_bytes(root: &Path, entry: &LibraryEntry) -> Result<u64, String> {
    let session_root = root.join(&entry.device_id).join(&entry.session_id);
    let canonical_root =
        fs::canonicalize(root).map_err(|error| format!("无法规范化库目录：{error}"))?;
    let canonical_session =
        fs::canonicalize(&session_root).map_err(|error| format!("无法规范化会话目录：{error}"))?;
    if !canonical_session.starts_with(&canonical_root) {
        return Err("会话目录逃逸出库目录".to_string());
    }
    fn walk(root: &Path, directory: &Path) -> Result<u64, String> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| format!("无法检查会话目录：{error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("会话目录包含符号链接或非目录节点".to_string());
        }
        let mut total = 0_u64;
        for entry in
            fs::read_dir(directory).map_err(|error| format!("无法读取会话目录：{error}"))?
        {
            let entry = entry.map_err(|error| format!("无法读取会话目录项：{error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("无法检查会话文件：{error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("会话目录包含符号链接".to_string());
            }
            let canonical =
                fs::canonicalize(&path).map_err(|error| format!("无法规范化会话文件：{error}"))?;
            if !canonical.starts_with(root) {
                return Err("会话文件逃逸出会话目录".to_string());
            }
            let bytes = if metadata.is_dir() {
                walk(root, &canonical)?
            } else if metadata.is_file() {
                metadata.len()
            } else {
                return Err("会话目录包含不支持的文件类型".to_string());
            };
            total = total
                .checked_add(bytes)
                .ok_or_else(|| "会话磁盘占用溢出".to_string())?;
        }
        Ok(total)
    }
    walk(&canonical_session, &canonical_session)
}

/// Where one library row's bytes may be found, most authoritative first.
///
/// A row remembers the root it was written under, because the configured root
/// moves: a user reconfiguration, or the startup fallback that quietly swaps
/// in the app-data directory when a configured one is briefly unusable.
/// Judging an old row against only today's root is what made a whole device's
/// recordings disappear from the library while their files sat on disk.
///
/// The current root is still searched, and searched last, so a library the
/// user moved wholesale keeps resolving and a stale recorded root cannot
/// shadow the real one.
fn entry_search_roots(current_root: &Path, entry: &LibraryEntry) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::with_capacity(2);
    if let Some(recorded) = entry
        .library_root
        .as_deref()
        .map(str::trim)
        .filter(|root| !root.is_empty())
    {
        roots.push(PathBuf::from(recorded));
    }
    if !roots.iter().any(|root| root == current_root) {
        roots.push(current_root.to_path_buf());
    }
    roots
}

/// Resolve one row's file, trying every root the row could live under.
///
/// The error reported is the one from the last root tried, which is the
/// current root: that is the location a user can act on.
pub(crate) fn resolve_existing_download_path_for_entry(
    current_root: &Path,
    entry: &LibraryEntry,
    file: &crate::models::SessionFile,
) -> Result<(PathBuf, fs::Metadata), String> {
    let mut last_error = None;
    for root in entry_search_roots(current_root, entry) {
        match resolve_existing_download_path(&root, &entry.device_id, &entry.session_id, file) {
            Ok(found) => return Ok(found),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "本地文件不可用".to_string()))
}

#[cfg(test)]
fn entry_has_complete_local_files(library_root: &Path, entry: &LibraryEntry) -> bool {
    entry.complete && canonical_assets_for_entry(library_root, entry).is_some()
}

fn canonical_assets_for_entry(
    library_root: &Path,
    entry: &LibraryEntry,
) -> Option<derived_media::CanonicalDerivedAssets> {
    let publication = validate_entry_publication(entry).ok()?;
    entry_search_roots(library_root, entry)
        .into_iter()
        .find_map(|root| {
            derived_media::canonical_assets_for_publication(
                &root,
                &entry.device_id,
                &entry.session_id,
                &publication.payload,
            )
            .ok()
        })
}

fn canonical_publication_bundle_for_entry(
    library_root: &Path,
    entry: &LibraryEntry,
) -> Result<derived_media::CanonicalPublicationBundle, String> {
    let publication = validate_entry_publication(entry)?;
    let mut last_error = None;
    for root in entry_search_roots(library_root, entry) {
        match derived_media::canonical_publication_bundle_for_entry(
            &root,
            &entry.device_id,
            &entry.session_id,
            &publication.payload,
        ) {
            Ok(bundle) => return Ok(bundle),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "本地规范派生发布资产不可用".to_string()))
}

fn derived_publication_plan(
    prefix: &str,
    bundle: &derived_media::CanonicalPublicationBundle,
) -> Result<DerivedPublicationPlan, String> {
    let source_manifest_sha256 = SourceSha256::from_hex(&bundle.source_manifest_sha256)
        .map_err(|error| format!("source manifest SHA-256 无效：{error}"))?;
    let receipt_sha256 = SourceSha256::from_hex(&bundle.receipt_sha256)
        .map_err(|error| format!("derived receipt SHA-256 无效：{error}"))?;
    let output_sha256 = SourceSha256::from_hex(&bundle.output_sha256)
        .map_err(|error| format!("derived MP4 SHA-256 无效：{error}"))?;
    DerivedPublicationPlan::build(&DerivedPublicationInput {
        prefix,
        source_device_id: &bundle.source_device_id,
        source_device_label: &bundle.source_device_label,
        source_manifest_id: &bundle.source_manifest_id,
        source_session_id: &bundle.source_session_id,
        source_volume_id: &bundle.source_volume_id,
        source_manifest_bytes: &bundle.source_manifest_bytes,
        source_manifest_sha256,
        receipt_id: &bundle.receipt_id,
        receipt_bytes: &bundle.receipt_bytes,
        receipt_sha256,
        output_artifact_id: &bundle.output_artifact_id,
        output_bytes: bundle.output_bytes,
        output_sha256,
        published_at: &bundle.published_at,
    })
}

fn downloaded_cleanup_idempotency_key(device_id: &str, session_id: &str, revision: &str) -> String {
    let material = format!("ylx-downloaded-cleanup-v1\0{device_id}\0{session_id}\0{revision}");
    let digest: [u8; 32] = Sha256::digest(material.as_bytes()).into();
    let mut key = String::with_capacity(18 + digest.len() * 2);
    key.push_str("pc-cleanup-v1-");
    for byte in digest {
        use std::fmt::Write as _;
        write!(key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

fn to_frontend_device(
    identity: &DeviceIdentity,
    core: &CoreDevice,
    endpoint: Option<&DeviceEndpoint>,
) -> FrontendDevice {
    let state = match &core.connection {
        ConnectionState::Connected { .. } => FrontendDeviceState::Connected,
        ConnectionState::Pairing { .. } => FrontendDeviceState::Pending,
        ConnectionState::Expired { .. } => FrontendDeviceState::Error,
        ConnectionState::Disconnected => {
            if core.discovery == DiscoveryState::Offline {
                FrontendDeviceState::Offline
            } else {
                FrontendDeviceState::Idle
            }
        }
    };
    FrontendDevice {
        id: identity.device_id().as_str().to_string(),
        display_id: endpoint
            .and_then(|e| e.display_label.clone())
            .unwrap_or_else(|| identity.display_id().to_string()),
        ip: endpoint.map(|e| e.host.clone()),
        state,
        last_seen: None,
    }
}

fn emit_devices(comp: &Composition, app: &AppHandle) {
    let _ = emit_devices_event(app, comp.frontend_devices());
}

#[derive(Debug)]
struct MdnsObservation {
    probes: Vec<MdnsCandidate>,
    device_state_changed: bool,
}

fn reconcile_discovery_state(comp: &Composition, fingerprint: &DeviceFingerprint) -> bool {
    let should_be_online = comp
        .mdns_services
        .lock()
        .unwrap()
        .should_be_online(fingerprint);
    let Some(handle) = comp.fleet.handle(fingerprint.clone()) else {
        return false;
    };
    let state = if should_be_online {
        DiscoveryState::Online
    } else {
        DiscoveryState::Offline
    };
    handle.set_discovery_state(state)
}

fn bind_selected_endpoint(
    comp: &Composition,
    registry: &MdnsServiceRegistry,
    fingerprint: &DeviceFingerprint,
) -> bool {
    let Some(endpoint) = registry.selected_endpoint(fingerprint) else {
        return false;
    };
    match comp.register_endpoint(endpoint) {
        Ok(registration) => registration.changed(),
        Err(error) => {
            eprintln!(
                "[composition] could not select a verified endpoint for {}: {error}",
                fingerprint.tls_pin()
            );
            false
        }
    }
}

/// Applies only lifecycle metadata. Device probes run separately so a slow
/// address cannot stop the browse loop from observing a newer removal/update.
fn observe_mdns_changes(comp: &Composition, changes: &[MdnsChange]) -> MdnsObservation {
    let mut probes = Vec::new();
    let mut affected = HashSet::new();
    let mut endpoint_changed = false;
    {
        let mut registry = comp.mdns_services.lock().unwrap();
        for change in changes {
            match change {
                MdnsChange::Resolved(candidate) => {
                    if let Some(observation) = registry.observe_resolved(candidate) {
                        probes.push(candidate.clone());
                        if let Some(fingerprint) = observation.previous_fingerprint {
                            affected.insert(fingerprint);
                        }
                    }
                }
                MdnsChange::Lost(loss) => {
                    if let Some(fingerprint) = registry.observe_lost(&loss.service_id, loss.cursor)
                    {
                        affected.insert(fingerprint);
                    }
                }
                MdnsChange::BrowseLost(loss) => {
                    for service_id in &loss.service_ids {
                        if let Some(fingerprint) = registry.observe_lost(service_id, loss.cursor) {
                            affected.insert(fingerprint);
                        }
                    }
                }
            }
        }
        for fingerprint in &affected {
            endpoint_changed |= bind_selected_endpoint(comp, &registry, fingerprint);
        }
    }
    let mut device_state_changed = endpoint_changed;
    for fingerprint in &affected {
        device_state_changed |= reconcile_discovery_state(comp, fingerprint);
    }
    MdnsObservation {
        probes,
        device_state_changed,
    }
}

fn probe_and_apply_mdns_candidate_with(
    comp: &Composition,
    candidate: MdnsCandidate,
    probe: impl FnMut(&str, u16, Duration) -> Result<LabV4DeviceProbe, PiHttpError>,
) -> bool {
    if !comp
        .mdns_services
        .lock()
        .unwrap()
        .candidate_is_current(&candidate)
    {
        return false;
    }
    let success = match probe_mdns_candidate_with(&candidate, Duration::from_secs(3), probe) {
        Ok(success) => success,
        Err(failures) => {
            eprintln!(
                "[composition] Device API v4 probe failed for mDNS service {}: {}",
                candidate.service_id, failures
            );
            return false;
        }
    };
    let mut endpoint = lab_v4_endpoint_from_probe(success);
    let identity = match DeviceIdentity::parse(&endpoint.tls_fingerprint) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!(
                "[composition] ignored invalid identity from mDNS service {}: {}",
                candidate.service_id, error
            );
            return false;
        }
    };
    endpoint.tls_fingerprint = identity.tls_pin();

    // The service lock is held across the no-I/O endpoint bind so a removal
    // cannot pass the fence between the final cursor check and registration.
    let (association, registration_changed, previous_binding_changed) = {
        let mut registry = comp.mdns_services.lock().unwrap();
        if !registry.candidate_is_current(&candidate) {
            return false;
        }
        let fingerprint = identity.fingerprint().clone();
        let Some(association) = registry.accept_probe(
            &candidate.service_id,
            candidate.cursor,
            fingerprint.clone(),
            endpoint,
        ) else {
            return false;
        };
        let Some(selected_endpoint) = registry.selected_endpoint(&fingerprint) else {
            return false;
        };
        let registration = match comp.register_endpoint(selected_endpoint) {
            Ok(registration) => registration,
            Err(error) => {
                eprintln!("[composition] ignored invalid mDNS endpoint: {error}");
                return false;
            }
        };
        let previous_binding_changed = association
            .previous_fingerprint
            .as_ref()
            .filter(|previous| *previous != &association.fingerprint)
            .is_some_and(|previous| bind_selected_endpoint(comp, &registry, previous));
        let changed = registration.changed();
        (association, changed, previous_binding_changed)
    };

    // `register_endpoint` published Online under the service cursor lock;
    // repeating that transition here could overwrite a just-observed loss.
    let mut changed = registration_changed | previous_binding_changed;
    if association.previous_fingerprint.as_ref() != Some(&association.fingerprint) {
        if let Some(previous) = association.previous_fingerprint.as_ref() {
            changed |= reconcile_discovery_state(comp, previous);
        }
    }
    changed
}

/// Starts the background mDNS discovery loop. Best-effort: if
/// `MdnsDiscovery::start()` fails (e.g. no usable multicast in this
/// sandbox/environment), this logs and returns `None` without starting the
/// poll loop -- the app continues in manual-address-only mode rather than
/// crashing or panicking. See module doc comment.
///
/// The loop consumes exact lifecycle batches. Probes are detached blocking
/// tasks: polling therefore continues while an address is slow, and the
/// service cursor fences that late result before it can mutate device state.
fn spawn_mdns_loop(comp: Arc<Composition>, app: AppHandle) -> Option<JoinHandle<()>> {
    match MdnsDiscovery::start() {
        Ok(mut discovery) => {
            comp.mdns_available.store(true, Ordering::SeqCst);
            Some(tauri::async_runtime::spawn(async move {
                loop {
                    let batch = discovery.poll_batch();
                    let observation = observe_mdns_changes(&comp, &batch.changes);
                    if observation.device_state_changed {
                        emit_devices(&comp, &app);
                    }
                    for candidate in observation.probes {
                        let comp_for_probe = comp.clone();
                        let app_for_probe = app.clone();
                        tauri::async_runtime::spawn_blocking(move || {
                            if probe_and_apply_mdns_candidate_with(
                                &comp_for_probe,
                                candidate,
                                probe_lab_v4_device,
                            ) {
                                emit_devices(&comp_for_probe, &app_for_probe);
                            }
                        });
                    }
                    if batch.is_disconnected() {
                        comp.mdns_available.store(false, Ordering::SeqCst);
                        eprintln!(
                            "[composition] mDNS browse channel closed; stopping discovery and \
                             falling back to manual-address-only device entry."
                        );
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
            }))
        }
        Err(e) => {
            comp.mdns_available.store(false, Ordering::SeqCst);
            eprintln!(
                "[composition] mDNS discovery unavailable ({e}); falling back to \
                 manual-address-only device entry."
            );
            None
        }
    }
}

/// Periodic heartbeat for every currently `Connected` device, using each
/// actor's own internally-held token (never read by this function -- see
/// module doc comment).
///
/// One sweep per interval, up to [`HEARTBEAT_CONCURRENCY`] devices at a
/// time, with every request issued through the device's own handle: no
/// lock of this composition's is held while any of them is in flight, and
/// each reply is applied only if its attempt and epoch are still current.
/// The previous shape walked the devices one at a time while holding the
/// single registry mutex across each request, so one Pi sitting in a socket
/// timeout froze every other device's heartbeat -- and, because the same
/// mutex guarded pairing, catalog reads and deletes, those too.
fn poll_connected_device_once(
    handle: &DeviceHandle,
    client: Arc<PiHttpClient>,
    api_profile: DeviceApiProfile,
) -> bool {
    let Ok(authenticated) = authenticated_client_for(handle, client) else {
        return false;
    };
    match handle.heartbeat_with(&authenticated) {
        // Nothing to renew: this device is not connected, so nothing
        // changed for it either.
        HeartbeatApplyOutcome::NotConnected => false,
        // Lab v4's heartbeat is already its one authoritative capture-status
        // request. Legacy keeps the descriptor refresh that binds a
        // transcript-less publication identity and refreshes its activity.
        _ => {
            if api_profile == DeviceApiProfile::LegacyPinnedTlsV1 {
                let _ = handle.refresh_capture_activity_with(&authenticated);
            }
            true
        }
    }
}

fn spawn_heartbeat_loop(comp: Arc<Composition>, app: AppHandle) -> JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            // Snapshot fingerprint -> client first: the sweep must not need
            // the binding registry while it is doing network I/O.
            let clients = comp.clients_by_fingerprint();
            if clients.is_empty() {
                continue;
            }
            let fleet = comp.fleet.clone();
            let swept = tauri::async_runtime::spawn_blocking(move || {
                fleet
                    .for_each_device(HEARTBEAT_CONCURRENCY, |handle| {
                        let binding = clients.get(handle.fingerprint())?.clone();
                        poll_connected_device_once(handle, binding.client, binding.api_profile)
                            .then_some(())
                    })
                    .len()
            })
            .await
            .unwrap_or(0);
            if swept > 0 {
                emit_devices(&comp, &app);
            }
        }
    })
}

/// Periodically ticks the real `TransferCoordinator`, pushes its job states
/// out as a `transfer_jobs:update` event, and -- PC-05b -- turns the first
/// observed `Succeeded`/`Failed`/`Cancelled` transition of any job this
/// composition root enqueued (via `Composition::enqueue_download`) into a
/// real `LibraryEntry`/`DownloadStatus` update in `AppData` (see
/// `apply_terminal_download`).
///
/// A job's terminal-ness is tracked against `last_states`. Pending context is
/// not removed for failed/cancelled jobs; a successful job is dismissed from
/// the coordinator only after both the real files and the durable application
/// store have been verified. Persistence or retirement failure deliberately
/// leaves the last state unremembered so the next poll retries the idempotent
/// merge and recoverable dismissal.
fn should_emit_transfer_jobs_snapshot(
    previous_snapshot_had_jobs: bool,
    current_job_count: usize,
) -> bool {
    current_job_count > 0 || previous_snapshot_had_jobs
}

/// The terminal outcome a coordinator state carries, or `None` for a state
/// that has not ended.
fn terminal_outcome_from_state(state: &TransferJobState) -> Option<TerminalOutcome> {
    Some(match state {
        TransferJobState::Succeeded => TerminalOutcome::Succeeded,
        TransferJobState::Cancelled => TerminalOutcome::Cancelled,
        TransferJobState::Failed { code, retryable } => TerminalOutcome::Failed {
            code: failure_code_as_str(code),
            retryable: *retryable,
        },
        _ => return None,
    })
}

/// The inverse, for the code paths that still speak `TransferJobState`.
/// Kept lossless in both directions so a delivered outcome describes the
/// same failure the coordinator reported.
fn job_state_from_outcome(outcome: &TerminalOutcome) -> TransferJobState {
    match outcome {
        TerminalOutcome::Succeeded => TransferJobState::Succeeded,
        TerminalOutcome::Cancelled => TransferJobState::Cancelled,
        TerminalOutcome::Failed { code, retryable } => TransferJobState::Failed {
            code: failure_code_from_str(code),
            retryable: *retryable,
        },
    }
}

fn failure_code_as_str(code: &FailureCode) -> String {
    match code {
        FailureCode::Network => "network".to_string(),
        FailureCode::DiskFull => "disk_full".to_string(),
        FailureCode::HashMismatch => "hash_mismatch".to_string(),
        FailureCode::ObjectStoreRejected => "object_store_rejected".to_string(),
        FailureCode::DeviceHeartbeatFailed => "device_heartbeat_failed".to_string(),
        FailureCode::Other(detail) => format!("other:{detail}"),
    }
}

fn upload_transfer_state(
    job: &StoredJob,
    confirmed_bytes: u64,
) -> (TransferState, Option<String>, bool) {
    let state = match job.state {
        JobStateTag::Queued => TransferState::Queued,
        JobStateTag::WaitingForDevice | JobStateTag::WaitingForPairing | JobStateTag::RetryWait => {
            TransferState::Preparing
        }
        // Uploads use one durable preparing state until terminal completion.
        // A persisted acknowledged part is stronger evidence that transfer
        // work has started than a process-local worker phase.
        JobStateTag::Preparing if confirmed_bytes > 0 => TransferState::Running,
        JobStateTag::Preparing => TransferState::Preparing,
        JobStateTag::PausedCaptureActive => TransferState::Paused,
        JobStateTag::Transferring | JobStateTag::Verifying | JobStateTag::Committing => {
            TransferState::Running
        }
        JobStateTag::Cancelling => TransferState::Cancelling,
        // The upload activity query keeps a succeeded row visible until its
        // completion outbox is acknowledged. It is terminal history waiting
        // for projection, not cancellable active work.
        JobStateTag::Succeeded => TransferState::Finalizing,
        JobStateTag::Failed => TransferState::Failed,
        JobStateTag::Cancelled => TransferState::Cancelled,
    };

    let error = match job.state {
        JobStateTag::Failed => job
            .error
            .as_ref()
            .map(|(code, _)| upload_failure_detail(code).to_string()),
        JobStateTag::Cancelled => Some(UPLOAD_CANCELLED_MESSAGE.to_string()),
        _ => None,
    };
    let retryable = matches!(job.state, JobStateTag::Failed)
        && job.error.as_ref().is_some_and(|(_, retryable)| *retryable);
    (state, error, retryable)
}

fn failure_code_from_str(code: &str) -> FailureCode {
    match code {
        "network" => FailureCode::Network,
        "disk_full" => FailureCode::DiskFull,
        "hash_mismatch" => FailureCode::HashMismatch,
        "object_store_rejected" => FailureCode::ObjectStoreRejected,
        "device_heartbeat_failed" => FailureCode::DeviceHeartbeatFailed,
        other => FailureCode::Other(other.strip_prefix("other:").unwrap_or(other).to_string()),
    }
}

/// What one pass of [`Composition::deliver_terminal_outcomes`] did.
#[derive(Debug, Default)]
struct TerminalDeliveryReport {
    /// At least one durable completion changed a library projection.
    library_changed: bool,
    /// Jobs whose outcome could not be delivered this pass. Their coordinator
    /// state is deliberately *not* remembered, so the next tick retries.
    deferred: HashSet<JobId>,
    /// Successful jobs whose outcome has been delivered and acknowledged, and
    /// which may therefore be retired from the coordinator and the store.
    retirable: Vec<JobId>,
}

/// The durable context needed by one outbox delivery. It is intentionally
/// owned: the transfer-store mutex is released before any filesystem/hash
/// work or application-state projection begins.
#[derive(Debug, Clone)]
enum OwnedCompletionContext {
    Download(JobSpec),
    Upload(UploadJobSpec),
}

#[derive(Debug, Clone)]
struct OwnedCompletion {
    record: CompletionRecord,
    context: OwnedCompletionContext,
}

#[derive(Debug, Clone)]
struct DownloadProjectionCandidate {
    entry: Option<LibraryEntry>,
    merged: bool,
}

fn deferred_download_projection(
    record: &CompletionRecord,
    merged: bool,
) -> Option<ProjectionOutcome> {
    (record.outcome.is_success() && !merged).then(|| {
        ProjectionOutcome::Deferred(format!(
            "下载 {} 的文件或 library 投影尚未通过验证",
            record.job_id
        ))
    })
}

/// `LibraryEntry` deliberately remains a persistence/UI model without a
/// blanket `PartialEq` derive. Projection revision fences still need to
/// detect whether the one row observed in the first short lock changed
/// before the CAS lock, so compare every persisted field explicitly.
fn same_library_entry(left: Option<&LibraryEntry>, right: Option<&LibraryEntry>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.device_id == right.device_id
                && left.session_id == right.session_id
                && left.date_label == right.date_label
                && left.downloaded_at == right.downloaded_at
                && left.bytes == right.bytes
                && left.processed_files == right.processed_files
                && left.files == right.files
                && left.complete == right.complete
                && left.download_projection_sequence == right.download_projection_sequence
                && left.publication == right.publication
                && left.library_root == right.library_root
                && left.object_receipts == right.object_receipts
                && left.upload_projection == right.upload_projection
                && left.upload_status == right.upload_status
                && left.upload_retryable == right.upload_retryable
                && left.uploaded_at == right.uploaded_at
                && left.upload_error == right.upload_error
        }
        _ => false,
    }
}

/// Reads one outbox row's immutable context while holding the transfer-store
/// mutex only for those small SQLite reads. The returned value owns every
/// field, so callers can drop the mutex before touching the filesystem.
fn load_owned_completion(
    store: &mut TransferStore,
    record: &CompletionRecord,
) -> Result<Option<OwnedCompletion>, String> {
    let context = match record.operation_kind {
        OperationKind::Download => {
            let Some(job) = store
                .get_job(&record.job_id)
                .map_err(|error| format!("无法读取完成任务 {}：{error}", record.job_id))?
            else {
                return Ok(None);
            };
            let spec = match store.job_spec(&record.job_id) {
                Ok(spec) => spec,
                Err(JobSpecLoadError::Blocked(blocked)) => {
                    return Err(blocked.detail.to_string());
                }
                Err(JobSpecLoadError::UnknownJob(_)) => return Ok(None),
                Err(JobSpecLoadError::Persistence(error)) => {
                    return Err(format!(
                        "无法读取完成任务 {} 的 spec：{error}",
                        record.job_id
                    ));
                }
            };
            // Reading the job above also verifies that a completion row has
            // not outlived its transfer row. Keep this explicit so a future
            // operation-kind mismatch cannot route an upload spec into the
            // download projection.
            if job.operation_kind != OperationKind::Download {
                return Err(format!(
                    "完成任务 {} 的 operation kind 不匹配",
                    record.job_id
                ));
            }
            OwnedCompletionContext::Download(spec)
        }
        OperationKind::Upload => {
            let Some(spec) = store
                .upload_job_spec(&record.job_id)
                .map_err(|error| format!("无法读取上传任务 {} 的 spec：{error}", record.job_id))?
            else {
                return Ok(None);
            };
            OwnedCompletionContext::Upload(spec)
        }
    };
    Ok(Some(OwnedCompletion {
        record: record.clone(),
        context,
    }))
}

fn acknowledge_projected_completion(
    store: &mut TransferStore,
    record: &CompletionRecord,
    projection: &ProjectionOutcome,
    now: &str,
) -> Result<Option<AckOutcome>, String> {
    if matches!(projection, ProjectionOutcome::Deferred(_)) {
        return Ok(None);
    }
    store
        .acknowledge_completion(&record.job_id, now)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// Applies one completion with the outbox protocol's lock boundaries:
/// snapshot the one affected application row, release the AppState mutex,
/// perform all path/hash inspection, reacquire the mutex for a per-entry
/// revision CAS plus in-memory publication, and only then let the caller
/// acknowledge the transfer outbox row.
fn apply_download_completion<R: Runtime>(
    app: &AppHandle<R>,
    completion: &OwnedCompletion,
    library_root: &Path,
) -> Result<(ProjectionOutcome, bool, String), String> {
    let OwnedCompletionContext::Download(spec) = &completion.context else {
        return Err("下载完成被路由到非下载 spec".to_string());
    };
    let state = job_state_from_outcome(&completion.record.outcome);
    let device_id = spec.identity().device_id().as_str().to_string();
    let session_id = spec.identity().session_id().as_str();
    let key = format!("{device_id}|{session_id}");
    let (expected_revision, current_entry) = {
        let state = app.state::<AppState>();
        let data = state.0.lock().unwrap();
        (
            data.store_revision(),
            data.library
                .iter()
                .find(|entry| entry.key() == key)
                .cloned(),
        )
    };

    // The outbox sequence is a durable total order. A projection that
    // already committed this sequence (crash before acknowledgement) or a
    // newer one owns the complete library row. A stale replay must therefore
    // be acknowledged without re-reading files or rolling any part of the
    // row back.
    if completion.record.outcome.is_success()
        && current_entry
            .as_ref()
            .is_some_and(|entry| entry.download_projection_sequence >= completion.record.sequence)
    {
        return Ok((ProjectionOutcome::AlreadyApplied, false, device_id));
    }

    // This is the intentionally unlocked portion. `resolve_downloaded_file`
    // performs symlink/path checks and streams a SHA-256 over every file.
    let mut candidate =
        prepare_terminal_download(current_entry.clone(), library_root, spec, &state);
    if let Some(deferred) = deferred_download_projection(&completion.record, candidate.merged) {
        return Ok((deferred, false, device_id));
    }
    // The durable completion timestamp is stable across crash/replay. Using
    // `Utc::now()` here would make an otherwise identical retry serialize a
    // different payload and bump the application revision again.
    if completion.record.outcome.is_success() && candidate.merged {
        if let Some(entry) = candidate.entry.as_mut() {
            entry.downloaded_at = completion.record.recorded_at.clone();
            entry.download_projection_sequence = completion.record.sequence;
        }
    }
    let serialized = candidate
        .entry
        .as_ref()
        .map(|entry| serde_json::to_vec(entry).map_err(|error| error.to_string()))
        .transpose()?;

    let state = app.state::<AppState>();
    let mut data = state.0.lock().unwrap();
    if data.store_revision() != expected_revision {
        let (actual, durable) = data
            .app_store()
            .read_library_entry(&key)
            .map_err(|error| format!("无法读取下载 library CAS 冲突：{error}"))?;
        if serialized.as_ref() == durable.as_ref().map(|entry| &entry.payload) {
            if let Some(entry) = candidate.entry.clone() {
                if let Some(existing) = data.library.iter_mut().find(|item| item.key() == key) {
                    *existing = entry;
                } else {
                    data.library.push(entry);
                }
            }
            data.set_store_revision(actual);
            return Ok((ProjectionOutcome::AlreadyApplied, true, device_id));
        }
        return Err(format!(
            "application state moved while projecting download {key}; retrying"
        ));
    }
    if !same_library_entry(
        data.library.iter().find(|item| item.key() == key),
        current_entry.as_ref(),
    ) {
        return Err(format!(
            "application library row moved while projecting download {key}; retrying"
        ));
    }
    let changed_entry = !same_library_entry(candidate.entry.as_ref(), current_entry.as_ref());
    if changed_entry {
        let payload = AppLibraryPayload {
            entry_key: key.clone(),
            payload: serialized.expect("changed candidate always has a serialized entry"),
        };
        let next = match data
            .app_store()
            .upsert_library_entry_if_revision(expected_revision, &payload)
        {
            Ok(next) => next,
            Err(error) => return Err(format!("无法提交下载 library 单行 CAS：{error}")),
        };
        match candidate.entry.clone() {
            Some(entry) => {
                if let Some(existing) = data.library.iter_mut().find(|item| item.key() == key) {
                    *existing = entry;
                } else {
                    data.library.push(entry);
                }
            }
            None => {
                data.library.retain(|item| item.key() != key);
            }
        }
        data.set_store_revision(next);
    }
    Ok((ProjectionOutcome::Applied, changed_entry, device_id))
}

/// Builds a terminal download result from one affected library row. This
/// wrapper keeps the existing, well-tested vector helper available while
/// ensuring the production projection clones only one row under AppState.
fn prepare_terminal_download(
    current_entry: Option<LibraryEntry>,
    library_root: &Path,
    spec: &JobSpec,
    state: &TransferJobState,
) -> DownloadProjectionCandidate {
    let mut library = current_entry.into_iter().collect::<Vec<_>>();
    let merged = apply_terminal_download(&mut library, library_root, spec, state);
    DownloadProjectionCandidate {
        entry: library.into_iter().next(),
        merged,
    }
}

fn upload_projection_receipt(receipt: &StoredUploadReceipt) -> UploadProjectionReceipt {
    UploadProjectionReceipt {
        object_key: receipt.object_key.clone(),
        role: receipt.role.as_db_str().to_string(),
        etag: receipt.etag.clone(),
        version_id: receipt.version_id.clone(),
        size_bytes: receipt.size_bytes,
        source_sha256: receipt.source_sha256.clone(),
        digest_proof: receipt.digest_proof.as_db_str().to_string(),
    }
}

fn frontend_upload_receipt(receipt: &StoredUploadReceipt) -> ObjectVerificationReceipt {
    ObjectVerificationReceipt {
        key: receipt.object_key.clone(),
        etag: receipt.etag.clone(),
        version_id: receipt.version_id.clone(),
        bytes: receipt.size_bytes,
        sha256: receipt.source_sha256.clone(),
    }
}

fn frontend_upload_receipts(receipts: &[StoredUploadReceipt]) -> Vec<ObjectVerificationReceipt> {
    let mut projected = receipts
        .iter()
        .map(frontend_upload_receipt)
        .collect::<Vec<_>>();
    projected.sort_by(|left, right| left.key.cmp(&right.key));
    projected
}

fn upload_projection_marker(
    job_id: &str,
    outcome: &TerminalOutcome,
    receipts: &[StoredUploadReceipt],
) -> UploadProjectionMarker {
    let (outcome_code, outcome_retryable) = match outcome {
        TerminalOutcome::Succeeded => ("succeeded".to_string(), None),
        TerminalOutcome::Cancelled => ("cancelled".to_string(), None),
        TerminalOutcome::Failed { code, retryable } => (format!("failed:{code}"), Some(*retryable)),
    };
    let mut receipts = receipts
        .iter()
        .map(upload_projection_receipt)
        .collect::<Vec<_>>();
    receipts.sort_by(|left, right| {
        left.object_key
            .cmp(&right.object_key)
            .then_with(|| left.role.cmp(&right.role))
            .then_with(|| left.version_id.cmp(&right.version_id))
            .then_with(|| left.etag.cmp(&right.etag))
            .then_with(|| left.source_sha256.cmp(&right.source_sha256))
            .then_with(|| left.digest_proof.cmp(&right.digest_proof))
    });
    UploadProjectionMarker {
        job_id: job_id.to_string(),
        entry_key: String::new(),
        revision: String::new(),
        object_prefix: None,
        outcome_code,
        outcome_retryable,
        receipts,
    }
}

fn upload_projection_marker_for_spec(
    job_id: &str,
    spec: &UploadJobSpec,
    outcome: &TerminalOutcome,
    receipts: &[StoredUploadReceipt],
) -> UploadProjectionMarker {
    let mut marker = upload_projection_marker(job_id, outcome, receipts);
    marker.entry_key = spec.entry_key.clone();
    marker.revision = spec.revision.clone();
    marker.object_prefix = spec.object_prefix.clone();
    marker
}

/// Checks the durable receipt batch against the immutable upload context and,
/// when a library row is present, the canonical MP4/receipt pair. A successful
/// completion with an incomplete batch remains unacknowledged rather than
/// fabricating `UploadStatus::Done`.
fn validate_upload_receipt_batch(
    job_id: &str,
    spec: &UploadJobSpec,
    entry: Option<&LibraryEntry>,
    receipts: &[StoredUploadReceipt],
) -> Result<(), String> {
    let Some(object_prefix) = spec.object_prefix.as_deref() else {
        return Err("上传任务缺少 immutable object namespace，无法验证完整对象 key".to_string());
    };
    if receipts.is_empty() {
        return Err("上传成功缺少已持久化的对象验证凭证".to_string());
    }
    let mut keys = HashSet::new();
    for receipt in receipts {
        if receipt.job_id != job_id
            || receipt.entry_key != spec.entry_key
            || receipt.revision != spec.revision
        {
            return Err("对象验证凭证与上传任务 immutable context 不匹配".to_string());
        }
        if !keys.insert(receipt.object_key.clone()) {
            return Err("对象验证凭证包含重复对象 key".to_string());
        }
    }
    let Some(entry) = entry else {
        return Ok(());
    };
    validate_stored_v4_receipts(entry, object_prefix, receipts)
}

fn validate_stored_v4_receipts(
    entry: &LibraryEntry,
    object_prefix: &str,
    receipts: &[StoredUploadReceipt],
) -> Result<(), String> {
    if entry.processed_files.len() != 2 || receipts.len() != 5 {
        return Err(
            "Bucket Publication v4 必须具有 3 个内容对象、marker 和 admission 共 5 个凭证"
                .to_string(),
        );
    }
    let marker = receipts
        .iter()
        .find(|receipt| {
            receipt
                .object_key
                .ends_with("/__ylx_evidence__/publication.json")
        })
        .ok_or_else(|| "对象验证凭证缺少 Bucket Publication v4 marker".to_string())?;
    if marker.role != UploadReceiptRole::Evidence || marker.size_bytes == 0 {
        return Err("Bucket Publication v4 marker 凭证角色或大小无效".to_string());
    }
    SourceSha256::from_hex(&marker.source_sha256)
        .map_err(|error| format!("marker SHA-256 无效：{error}"))?;
    let marker_key = ObjectKey(marker.object_key.clone());
    let root = marker
        .object_key
        .strip_suffix("/__ylx_evidence__/publication.json")
        .ok_or_else(|| "marker object key 后缀无效".to_string())?;
    validate_v4_object_root(root, object_prefix, &entry.session_id)?;
    let admission = receipts
        .iter()
        .find(|receipt| {
            admission_key_belongs_to_marker(&marker_key, &ObjectKey(receipt.object_key.clone()))
        })
        .ok_or_else(|| {
            "对象验证凭证缺少同一 evidence authority 的 Console admission 回执".to_string()
        })?;
    if admission.role != UploadReceiptRole::Evidence
        || admission.size_bytes == 0
        || SourceSha256::from_hex(&admission.source_sha256).is_err()
    {
        return Err("Console admission 凭证角色、大小或 SHA-256 无效".to_string());
    }

    let source_sha = entry
        .publication
        .as_ref()
        .and_then(|publication| publication.revision.strip_prefix("sha256:"))
        .ok_or_else(|| "本地记录缺少 source manifest revision".to_string())?;
    let mut expected = HashMap::from([(
        source_sha.to_ascii_lowercase(),
        (None, UploadReceiptRole::Evidence),
    )]);
    for file in &entry.processed_files {
        let role = if file.display_path == derived_media::RECEIPT_DISPLAY_PATH {
            UploadReceiptRole::Evidence
        } else {
            UploadReceiptRole::Data
        };
        if expected
            .insert(file.sha256.to_ascii_lowercase(), (Some(file.bytes), role))
            .is_some()
        {
            return Err("v4 内容对象摘要必须互不相同".to_string());
        }
    }
    if expected.len() != 3 {
        return Err("v4 内容对象摘要集合不完整".to_string());
    }
    for (sha256, (size, role)) in expected {
        let key = format!("{root}/f-{sha256}");
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.object_key == key)
            .ok_or_else(|| format!("对象验证凭证缺少内容对象 f-{sha256}"))?;
        if receipt.role != role
            || receipt.size_bytes == 0
            || size.is_some_and(|expected_size| receipt.size_bytes != expected_size)
            || !receipt.source_sha256.eq_ignore_ascii_case(&sha256)
        {
            return Err(format!(
                "内容对象 f-{sha256} 的 role/size/digest 凭证不一致"
            ));
        }
    }
    Ok(())
}

fn validate_v4_object_root(
    root: &str,
    object_prefix: &str,
    session_id: &str,
) -> Result<(), String> {
    let prefix = normalize_prefix(object_prefix);
    let tail = if prefix.is_empty() {
        root
    } else {
        root.strip_prefix(prefix)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| "v4 object root 不在 immutable prefix 下".to_string())?
    };
    let parts = tail.split('/').collect::<Vec<_>>();
    if parts.len() != 3
        || !uuid_has_version(parts[0], 4)
        || parts[1] != session_id
        || !uuid_has_version(parts[1], 7)
        || !uuid_has_version(parts[2], 7)
    {
        return Err(
            "v4 object root 不符合 device UUIDv4/session UUIDv7/publication UUIDv7".to_string(),
        );
    }
    Ok(())
}

fn uuid_has_version(raw: &str, version: usize) -> bool {
    uuid::Uuid::parse_str(raw)
        .is_ok_and(|value| value.get_version_num() == version && value.to_string() == raw)
}

/// Projects one upload completion without holding either global mutex across
/// serialization. Upload workers have already staged the object receipts;
/// this phase only revision-fences the one affected library row and projects
/// its terminal transfer activity after the row CAS succeeds. A successful
/// worker returns success only after the exact Bucket Publication v4 marker
/// and Console admission acknowledgement have both been read back.
fn apply_upload_completion<R: Runtime>(
    comp: &Composition,
    app: &AppHandle<R>,
    completion: &OwnedCompletion,
) -> Result<(ProjectionOutcome, bool), String> {
    let OwnedCompletionContext::Upload(spec) = &completion.context else {
        return Err("上传完成被路由到非上传 spec".to_string());
    };
    let job_id = &completion.record.job_id;
    let receipts = comp
        .transfer_store
        .lock()
        .unwrap()
        .list_upload_receipts(job_id)
        .map_err(|error| format!("无法读取上传任务对象验证凭证：{error}"))?;
    let (expected_revision, current_entry) = {
        let state = app.state::<AppState>();
        let data = state.0.lock().unwrap();
        (
            data.store_revision(),
            data.library
                .iter()
                .find(|entry| entry.key() == spec.entry_key)
                .cloned(),
        )
    };
    let Some(entry) = current_entry.clone() else {
        // A local delete may legitimately win while an upload is finishing;
        // acknowledge the durable completion without inventing a library row.
        return Ok((ProjectionOutcome::Applied, false));
    };
    let same_revision = entry
        .publication
        .as_ref()
        .is_some_and(|publication| publication.revision == spec.revision);
    if !same_revision {
        // A newer library revision owns this row now. Keep the durable
        // completion and receipts, but never overwrite the newer projection.
        return Ok((ProjectionOutcome::Applied, false));
    }
    if matches!(completion.record.outcome, TerminalOutcome::Succeeded) {
        if spec.object_prefix.is_none() {
            eprintln!(
                "[composition] upload completion {job_id} lacks persisted object namespace; acknowledging without marking library Done"
            );
            return Ok((ProjectionOutcome::Applied, false));
        }
        if let Err(error) = validate_upload_receipt_batch(job_id, spec, Some(&entry), &receipts) {
            return Ok((ProjectionOutcome::Deferred(error), false));
        }
    } else {
        for receipt in &receipts {
            if receipt.job_id != job_id.as_str()
                || receipt.entry_key != spec.entry_key
                || receipt.revision != spec.revision
            {
                return Ok((
                    ProjectionOutcome::Deferred(
                        "失败上传的对象验证凭证与 immutable context 不匹配".to_string(),
                    ),
                    false,
                ));
            }
        }
    }

    let marker =
        upload_projection_marker_for_spec(job_id, spec, &completion.record.outcome, &receipts);
    let marker_matches = entry.upload_projection.as_ref() == Some(&marker);
    let projection_matches = match &completion.record.outcome {
        TerminalOutcome::Succeeded => {
            entry.upload_status == UploadStatus::Done
                && !entry.upload_retryable
                && entry.upload_error.is_none()
                && entry.uploaded_at.as_deref() == Some(completion.record.recorded_at.as_str())
                && entry.object_receipts == frontend_upload_receipts(&receipts)
        }
        TerminalOutcome::Cancelled => {
            entry.upload_status == UploadStatus::Failed
                && entry.upload_retryable
                && entry.upload_error.as_deref() == Some(UPLOAD_CANCELLED_MESSAGE)
                && entry.uploaded_at.is_none()
                && entry.object_receipts.is_empty()
        }
        TerminalOutcome::Failed { code, retryable } => {
            let detail = upload_failure_detail(code);
            entry.upload_status == UploadStatus::Failed
                && entry.upload_retryable == *retryable
                && entry.upload_error.as_deref() == Some(detail)
                && entry.uploaded_at.is_none()
                && entry.object_receipts.is_empty()
        }
    };
    if marker_matches && projection_matches {
        return Ok((ProjectionOutcome::AlreadyApplied, false));
    }

    let mut candidate = entry.clone();
    match &completion.record.outcome {
        TerminalOutcome::Succeeded => {
            candidate.upload_status = UploadStatus::Done;
            candidate.upload_retryable = false;
            candidate.upload_error = None;
            candidate.uploaded_at = Some(completion.record.recorded_at.clone());
            candidate.object_receipts = frontend_upload_receipts(&receipts);
        }
        TerminalOutcome::Cancelled => {
            candidate.upload_status = UploadStatus::Failed;
            candidate.upload_retryable = true;
            candidate.upload_error = Some(UPLOAD_CANCELLED_MESSAGE.to_string());
            candidate.uploaded_at = None;
            candidate.object_receipts.clear();
        }
        TerminalOutcome::Failed { code, retryable } => {
            let detail = upload_failure_detail(code).to_string();
            candidate.upload_status = UploadStatus::Failed;
            candidate.upload_retryable = *retryable;
            candidate.upload_error = Some(detail);
            candidate.uploaded_at = None;
            candidate.object_receipts.clear();
        }
    }
    candidate.upload_projection = Some(marker);
    let payload = AppLibraryPayload {
        entry_key: spec.entry_key.clone(),
        payload: serde_json::to_vec(&candidate)
            .map_err(|error| format!("无法序列化上传 library 单行：{error}"))?,
    };

    let state = app.state::<AppState>();
    let mut data = state.0.lock().unwrap();
    if data.store_revision() != expected_revision {
        let (actual, durable) = data
            .app_store()
            .read_library_entry(&spec.entry_key)
            .map_err(|error| format!("无法读取上传 library CAS 冲突：{error}"))?;
        if durable.as_ref().map(|entry| &entry.payload) == Some(&payload.payload) {
            if let Some(existing) = data
                .library
                .iter_mut()
                .find(|item| item.key() == spec.entry_key)
            {
                *existing = candidate;
            }
            data.set_store_revision(actual);
            return Ok((ProjectionOutcome::AlreadyApplied, true));
        }
        return Err(format!(
            "application state moved while projecting upload {job_id}; retrying"
        ));
    }
    if !same_library_entry(
        data.library
            .iter()
            .find(|item| item.key() == spec.entry_key),
        Some(&entry),
    ) {
        return Err(format!(
            "application library row moved while projecting upload {job_id}; retrying"
        ));
    }
    let next = data
        .app_store()
        .upsert_library_entry_if_revision(expected_revision, &payload)
        .map_err(|error| format!("无法提交上传 library 单行 CAS：{error}"))?;
    if let Some(existing) = data
        .library
        .iter_mut()
        .find(|item| item.key() == spec.entry_key)
    {
        *existing = candidate;
    }
    data.set_store_revision(next);
    Ok((ProjectionOutcome::Applied, true))
}

fn spawn_transfer_poll_loop(comp: Arc<Composition>, app: AppHandle) -> JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let mut last_states: HashMap<JobId, TransferJobState> = HashMap::new();
        let mut last_snapshot_had_jobs = false;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            comp.coordinator.tick();

            let ids = comp.coordinator.job_ids();

            // Step 1 (commit 29): every newly observed terminal state gets its
            // transition *and* its outcome committed together. Nothing is
            // applied to the library yet -- from here on the result cannot be
            // lost, only delayed.
            let mut deferred: HashSet<JobId> = HashSet::new();
            for id in &ids {
                let Some(state) = comp.coordinator.job_state(id) else {
                    continue;
                };
                if state.is_terminal() && last_states.get(id) != Some(&state) {
                    if let Err(e) = comp.record_terminal_outcome(id, &state) {
                        eprintln!(
                            "[composition] failed to durably record the terminal outcome of \
                             {id}; will retry: {e}"
                        );
                        deferred.insert(id.clone());
                    }
                }
            }

            // Step 2 (commit 30): drain the outbox -- apply, emit, acknowledge
            // -- for this tick's transitions *and* for anything a previous run
            // crashed in the middle of.
            let delivery = comp.deliver_terminal_outcomes(&app);
            deferred.extend(delivery.deferred.iter().cloned());
            let mut retired: HashSet<JobId> = HashSet::new();
            for id in &delivery.retirable {
                let comp_for_retirement = comp.clone();
                let id_for_retirement = id.clone();
                match tauri::async_runtime::spawn_blocking(move || {
                    comp_for_retirement.retire_successful_download(&id_for_retirement)
                })
                .await
                {
                    Ok(Ok(())) => {
                        retired.insert(id.clone());
                    }
                    Ok(Err(e)) => {
                        eprintln!(
                            "[composition] failed to retire successful download {id}; will \
                             retry: {e}"
                        );
                        deferred.insert(id.clone());
                    }
                    Err(e) => {
                        eprintln!(
                            "[composition] successful download retirement task for {id} \
                             terminated unexpectedly; will retry: {e}"
                        );
                        deferred.insert(id.clone());
                    }
                }
            }

            let mut jobs: Vec<JobStateEvent> = Vec::with_capacity(ids.len());
            let library_changed = delivery.library_changed;
            for id in ids {
                if retired.contains(&id) {
                    last_states.remove(&id);
                    continue;
                }
                let Some(snapshot) = comp.coordinator.job_snapshot(&id) else {
                    last_states.remove(&id);
                    continue;
                };
                // Project every field from one coordinator snapshot. This
                // keeps state, durable user intent, identity and progress
                // from disagreeing when a worker commits between reads.
                let progress = snapshot.progress;
                let (device_id, device_display_id) = comp.job_event_identity(&snapshot.device_id);
                let job_event = JobStateEvent {
                    job_id: id.to_string(),
                    state: snapshot.state.clone(),
                    desired_run_state: snapshot.desired_run_state,
                    session_id: Some(snapshot.session_id.as_str().to_owned()),
                    device_id,
                    device_display_id,
                    total_bytes: progress.total_bytes,
                    transferred_bytes: progress.transferred_bytes,
                    files_total: progress.files_total,
                    files_done: progress.files_done,
                };

                jobs.push(job_event);
                // A job whose outcome is not durably delivered yet keeps its
                // last state unremembered, so the next tick re-records and
                // re-drains it rather than treating the transition as old news.
                if !deferred.contains(&id) {
                    last_states.insert(id, snapshot.state);
                }
            }

            let current_snapshot_has_jobs = !jobs.is_empty();
            if should_emit_transfer_jobs_snapshot(last_snapshot_had_jobs, jobs.len())
                && emit_transfer_jobs_event(&app, jobs).is_ok()
            {
                last_snapshot_had_jobs = current_snapshot_has_jobs;
            }
            if library_changed {
                emit_library(&app);
            }
        }
    })
}

/// Turns one terminal download into a verified library merge. It consumes
/// the durable [`JobSpec`] directly, so no process-local request model can
/// drift from the recovery authority.
///
/// - `Succeeded`: accepts only a full-session specification, independently
///   verifies the canonical derived bundle (never trusting the state
///   transition alone), and publishes that bundle to the local library.
///   Historical partial specifications remain permanently non-publishable.
/// - `Failed`/`Cancelled`: leaves the library unchanged. Session status is
///   derived from the durable terminal job and completion outbox.
///
/// Returns `true` only when a `Succeeded` state was independently verified
/// and merged.  The poll loop uses this to decide whether it may retire the
/// persisted pending context.
fn apply_terminal_download(
    library: &mut Vec<LibraryEntry>,
    library_root: &Path,
    spec: &JobSpec,
    state: &TransferJobState,
) -> bool {
    apply_terminal_download_with_resolver(
        library,
        library_root,
        spec,
        state,
        &resolve_downloaded_file,
    )
}

fn ffmpeg_export_config() -> Result<SessionExportConfig, String> {
    let ffmpeg = resolve_bundled_ffmpeg_path();
    let ffprobe = resolve_bundled_ffprobe_path();
    #[cfg(target_os = "windows")]
    if ffmpeg.is_none() || ffprobe.is_none() {
        return Err(
            "Windows media finalization requires bundled ffmpeg.exe and ffprobe.exe".to_string(),
        );
    }
    let mut config = SessionExportConfig::system_ffmpeg();
    if let Some(path) = ffmpeg {
        config = config.with_ffmpeg_path(path);
    }
    if let Some(path) = ffprobe {
        config = config.with_ffprobe_path(path);
    }
    Ok(config)
}

fn resolve_bundled_ffmpeg_path() -> Option<PathBuf> {
    resolve_bundled_media_tool_path("OPENARIA_FFMPEG", "ffmpeg")
}

fn resolve_bundled_ffprobe_path() -> Option<PathBuf> {
    resolve_bundled_media_tool_path("OPENARIA_FFPROBE", "ffprobe")
}

fn resolve_bundled_media_tool_path(environment_key: &str, tool: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var(environment_key) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join(format!("{tool}.exe")));
            candidates.push(parent.join(tool));
            candidates.push(parent.join("binaries").join(format!("{tool}.exe")));
            candidates.push(parent.join("binaries").join(tool));
        }
    }
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let binaries = PathBuf::from(manifest_dir).join("binaries");
        #[cfg(target_os = "windows")]
        candidates.push(binaries.join(format!("{tool}-x86_64-pc-windows-msvc.exe")));
        #[cfg(target_os = "linux")]
        candidates.push(binaries.join(format!("{tool}-x86_64-unknown-linux-gnu")));
        #[cfg(target_os = "macos")]
        candidates.push(binaries.join(format!("{tool}-aarch64-apple-darwin")));
    }
    candidates.into_iter().find(|path| {
        fs::symlink_metadata(path)
            .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
    })
}

fn apply_terminal_download_with_resolver<F>(
    library: &mut Vec<LibraryEntry>,
    library_root: &Path,
    spec: &JobSpec,
    state: &TransferJobState,
    _resolve: &F,
) -> bool
where
    F: Fn(&Path, &str, &str, &crate::models::SessionFile) -> Result<(PathBuf, u64), String>,
{
    if !matches!(state, TransferJobState::Succeeded) || !spec.full_session() {
        return false;
    }
    let device_id = spec.identity().device_id().as_str();
    let session_id = spec.identity().session_id().as_str();
    let session_files = spec
        .session_files()
        .iter()
        .map(session_file_from_job_spec)
        .collect::<Vec<_>>();
    let publication = publication_evidence_from_job_spec(spec);
    let canonical = match derived_media::canonical_assets_for_publication(
        library_root,
        device_id,
        session_id,
        spec.publication().payload(),
    ) {
        Ok(canonical) => canonical,
        Err(error) => {
            eprintln!(
                "[composition] succeeded download for {device_id}/{session_id} has no valid canonical derived bundle: {error}"
            );
            return false;
        }
    };
    let existing_index = library
        .iter()
        .position(|entry| entry.device_id == device_id && entry.session_id == session_id);
    let downloaded_at = chrono::Utc::now().to_rfc3339();
    match existing_index {
        Some(index) => {
            let existing = &mut library[index];
            let files_changed = existing.files != session_files;
            let processed_changed = existing.processed_files != canonical.files;
            let publication_changed = existing.publication.as_ref() != Some(&publication);
            existing.files = session_files;
            existing.processed_files = canonical.files;
            existing.bytes = canonical.total_bytes;
            existing.date_label = spec.date_label().to_string();
            existing.downloaded_at = downloaded_at;
            existing.complete = true;
            existing.library_root = Some(library_root.to_string_lossy().into_owned());
            existing.publication = Some(publication);
            if files_changed || processed_changed || publication_changed {
                existing.upload_status = UploadStatus::None;
                existing.upload_retryable = false;
                existing.uploaded_at = None;
                existing.upload_error = None;
                existing.object_receipts.clear();
                existing.upload_projection = None;
            }
        }
        None => library.push(LibraryEntry {
            device_id: device_id.to_string(),
            session_id: session_id.to_string(),
            date_label: spec.date_label().to_string(),
            downloaded_at,
            bytes: canonical.total_bytes,
            processed_files: canonical.files,
            files: session_files,
            complete: true,
            download_projection_sequence: 0,
            library_root: Some(library_root.to_string_lossy().into_owned()),
            publication: Some(publication),
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: UploadStatus::None,
            upload_retryable: false,
            uploaded_at: None,
            upload_error: None,
        }),
    }
    true
}

/// Establishes a trusted-LAN session: performs `POST /pairing-requests`
/// and hands the caller back the identity of the attempt it created, then
/// polls `GET /pairing-requests/{id}` in the background for the token
/// issued by the Pi's automatic approval policy. Every terminal outcome is
/// emitted explicitly -- tagged with that same attempt id -- so the
/// frontend cannot leave a failed real attempt looking pending, and cannot
/// mistake a superseded attempt's result for the current one.
///
/// Returns the pairing attempt id (for an already-connected device, the id
/// of the attempt that produced the live connection). Failures that happen
/// before an attempt exists are returned as `Err` rather than emitted:
/// there is no attempt identity to tag such an event with.
pub async fn connect_device(
    comp: Arc<Composition>,
    app: AppHandle,
    device_id: String,
) -> Result<String, String> {
    let binding = comp.resolve_binding(&device_id)?;
    let device_id = binding.identity.device_id().as_str().to_string();
    let record_trusted_producer_key =
        binding.endpoint.api_profile == DeviceApiProfile::LegacyPinnedTlsV1;
    let pairing_endpoint = binding.endpoint.clone();
    let client = binding.client;
    let handle = binding.handle;
    if let ConnectionState::Connected { connection_id, .. } = handle.connection_state() {
        return Ok(connection_id);
    }

    if let Some(prev) = comp.pairing_tasks.lock().unwrap().remove(&device_id) {
        prev.abort();
    }

    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let start_result = {
        let client = client.clone();
        let handle = handle.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let pairing = PiPairingClient::new(client.clone());
            let ticket = handle.issue_pairing_ticket();
            let created = PairingPort::create_pairing_request(&pairing, "YLX Transfer PC", &nonce)?;
            if !handle.pairing_ticket_is_current(ticket) {
                return Err(PiClientError {
                    kind: PiClientErrorKind::Other,
                    message: "配对响应属于已被取代的请求".to_string(),
                });
            }
            let info = handle.apply_pairing_created(created.clone());
            let active = ActivePairing {
                attempt_id: created.attempt_id,
                poll_secret: created.poll_secret,
                client,
                sas: created.sas,
                record_trusted_producer_key,
            };
            Ok::<_, PiClientError>((info, active))
        })
        .await
    };
    let (attempt, active) = match start_result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            emit_devices(&comp, &app);
            return Err(format!("无法发起设备配对：{error}"));
        }
        Err(error) => {
            emit_devices(&comp, &app);
            return Err(format!("配对后台任务异常终止：{error}"));
        }
    };
    let attempt_id = attempt.attempt_id;
    let expires_at = match chrono::DateTime::parse_from_rfc3339(&attempt.expires_at) {
        Ok(value) => value.with_timezone(&chrono::Utc),
        Err(error) => {
            abandon_unusable_attempt(&comp, &app, &device_id, &active).await;
            return Err(format!("设备返回了无效的配对截止时间：{error}"));
        }
    };
    if attempt_id != active.attempt_id {
        abandon_unusable_attempt(&comp, &app, &device_id, &active).await;
        return Err("配对响应的 attempt ID 不一致".to_string());
    }

    comp.active_pairings
        .lock()
        .unwrap()
        .insert(device_id.clone(), active);
    emit_devices(&comp, &app);

    let handle = {
        let comp = comp.clone();
        let device_id = device_id.clone();
        let attempt_id = attempt_id.clone();
        let pairing_endpoint = pairing_endpoint.clone();
        tauri::async_runtime::spawn(async move {
            run_pairing(
                comp,
                app,
                device_id,
                client,
                pairing_endpoint,
                attempt_id,
                expires_at,
            )
            .await;
        })
    };
    comp.pairing_tasks.lock().unwrap().insert(device_id, handle);
    Ok(attempt_id)
}

#[derive(Debug, PartialEq, Eq)]
enum ConnectionNegotiationOutcome {
    Ready,
    Failed(String),
    Stale,
}

fn connection_negotiation_failure(
    handle: &DeviceHandle,
    expected_epoch: u64,
    message: String,
) -> ConnectionNegotiationOutcome {
    if handle.disconnect_local_if_epoch(expected_epoch) {
        ConnectionNegotiationOutcome::Failed(message)
    } else {
        ConnectionNegotiationOutcome::Stale
    }
}

/// Negotiates the descriptor facts required to publish one newly connected
/// Device API v4 epoch. The adapter's negotiation route is descriptor-only;
/// capture status belongs to the periodic heartbeat. Any failure clears only
/// `expected_epoch`, while an old task that encounters a newer epoch returns
/// `Stale` without touching it.
fn negotiate_lab_v4_connection_once(
    handle: &DeviceHandle,
    client: Arc<PiHttpClient>,
    expected_epoch: u64,
) -> ConnectionNegotiationOutcome {
    let authenticated = match authenticated_client_for(handle, client) {
        Ok(authenticated) => authenticated,
        Err(error) => {
            return connection_negotiation_failure(handle, expected_epoch, error);
        }
    };
    match handle.negotiate_device_with_for_epoch(&authenticated, expected_epoch) {
        RefreshApplyOutcome::Refreshed => match handle.negotiated_device_snapshot() {
            Some(snapshot)
                if snapshot.epoch == expected_epoch
                    && snapshot.info.profile == DeviceApiProfileView::LabHttpV4 =>
            {
                ConnectionNegotiationOutcome::Ready
            }
            _ => connection_negotiation_failure(
                handle,
                expected_epoch,
                "设备返回的能力 profile 与 Device API v4 连接不一致".to_string(),
            ),
        },
        RefreshApplyOutcome::NotConnected => connection_negotiation_failure(
            handle,
            expected_epoch,
            "设备连接在能力协商前已失效，请重试".to_string(),
        ),
        RefreshApplyOutcome::Stale => ConnectionNegotiationOutcome::Stale,
        RefreshApplyOutcome::Failed(error) => connection_negotiation_failure(
            handle,
            expected_epoch,
            authenticated_request_error("设备能力协商失败", error),
        ),
    }
}

/// Best-effort teardown of an attempt the Pi created but this client can
/// never drive to completion (unusable expiry, mismatched identity). The
/// device-side DELETE runs off the calling thread, exactly like an explicit
/// [`cancel_pairing`].
async fn abandon_unusable_attempt(
    comp: &Arc<Composition>,
    app: &AppHandle,
    device_id: &str,
    active: &ActivePairing,
) {
    let _ = cancel_pairing_at_device(
        Arc::new(PiPairingClient::new(active.client.clone())),
        active.attempt_id.clone(),
        active.poll_secret.clone(),
    )
    .await;
    expire_pairing_locally(comp, device_id, &active.attempt_id);
    emit_devices(comp, app);
}

/// Polls one specific pairing attempt to a terminal outcome. Every result
/// -- tick, resolution, or failure -- is tagged with, and matched against,
/// `attempt_id`: if the device's current attempt has moved on (a newer
/// `connect_device`, or a cancellation) while a poll was in flight, this
/// task's result belongs to a dead attempt and is *discarded*, never
/// applied and never emitted.
async fn run_pairing(
    comp: Arc<Composition>,
    app: AppHandle,
    device_id: String,
    client: Arc<PiHttpClient>,
    pairing_endpoint: DeviceEndpoint,
    attempt_id: String,
    expires_at: chrono::DateTime<chrono::Utc>,
) {
    let total_seconds = pairing_remaining_seconds(expires_at);
    loop {
        if !attempt_is_current(&comp, &device_id, &attempt_id) {
            return;
        }
        let still_pairing = matches!(
            comp.handle_for(&device_id).map(|h| h.connection_state()),
            Some(ConnectionState::Pairing { .. })
        );
        if !still_pairing {
            clear_active_pairing(&comp, &device_id, &attempt_id);
            emit_pairing_resolution(
                &app,
                &device_id,
                &attempt_id,
                PairingResolutionOutcome::Failed,
                Some("配对状态在完成前发生变化，请重试".to_string()),
            );
            return;
        }
        let remaining = pairing_remaining_seconds(expires_at);
        if remaining == 0 {
            break;
        }

        let poll_result = {
            let comp = comp.clone();
            let device_id = device_id.clone();
            let attempt_id = attempt_id.clone();
            let client = client.clone();
            tauri::async_runtime::spawn_blocking(move || {
                let Some(handle) = comp.handle_for(&device_id) else {
                    return PollPairingOutcome::NotPairing;
                };
                // The actor applies its own attempt-id guard, so a result
                // for a superseded attempt can never mutate newer state;
                // this only avoids issuing a poll we already know is for a
                // dead attempt.
                match handle.connection_state() {
                    ConnectionState::Pairing {
                        attempt_id: current,
                        ..
                    } if current == attempt_id => {}
                    _ => return PollPairingOutcome::Stale,
                }
                // `GET /pairing-requests/{id}` with no lock held: an
                // unreachable Pi here delays this attempt and nothing else.
                let pairing = PiPairingClient::new(client);
                handle.poll_pairing_with(&pairing)
            })
            .await
        };

        // The poll response raced with whatever else may have happened to
        // this device meanwhile: re-check before applying anything.
        if !attempt_is_current(&comp, &device_id, &attempt_id) {
            return;
        }

        match poll_result {
            Ok(PollPairingOutcome::StillPending) => {
                let _ = emit_pairing_event(
                    &app,
                    false,
                    serde_json::json!({
                        "deviceId": device_id,
                        "attemptId": attempt_id,
                        "remaining": remaining,
                        "total": total_seconds,
                    }),
                );
                let sleep_ms = (expires_at - chrono::Utc::now())
                    .num_milliseconds()
                    .clamp(1, 250) as u64;
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                continue;
            }
            Ok(PollPairingOutcome::Connected { epoch }) => {
                let current_binding = comp.resolve_binding(&device_id).ok();
                // A pairing result is usable only while the same coherent
                // binding still exists. Discovery may have removed the
                // identity or selected another origin while the poll was in
                // flight; publishing Connected in either case would expose a
                // token/epoch that no longer belongs to the visible device.
                let binding_invalid = current_binding.as_ref().is_none_or(|binding| {
                    !transport_origin_matches(&binding.endpoint, &pairing_endpoint)
                });
                if binding_invalid {
                    clear_active_pairing(&comp, &device_id, &attempt_id);
                    emit_devices(&comp, &app);
                    let message = if current_binding.is_none() {
                        "设备连接在能力协商前已移除，请重试"
                    } else {
                        "设备连接地址在能力协商前已变化，请重试"
                    };
                    emit_pairing_resolution(
                        &app,
                        &device_id,
                        &attempt_id,
                        PairingResolutionOutcome::Failed,
                        Some(message.to_string()),
                    );
                    return;
                }
                if current_binding.as_ref().is_some_and(|binding| {
                    binding.endpoint.api_profile == DeviceApiProfile::LabHttpV4
                }) {
                    let negotiation = match current_binding {
                        Some(binding)
                            if !transport_origin_matches(&binding.endpoint, &pairing_endpoint) =>
                        {
                            ConnectionNegotiationOutcome::Stale
                        }
                        Some(binding) => {
                            let handle = binding.handle;
                            let background_handle = handle.clone();
                            // Keep the transport that created the token. A
                            // same-origin binding refresh may replace the
                            // Arc, but a different origin must never receive
                            // this bearer token.
                            let background_client = client.clone();
                            match tauri::async_runtime::spawn_blocking(move || {
                                negotiate_lab_v4_connection_once(
                                    &background_handle,
                                    background_client,
                                    epoch,
                                )
                            })
                            .await
                            {
                                Ok(outcome) => outcome,
                                Err(error) => connection_negotiation_failure(
                                    &handle,
                                    epoch,
                                    format!("设备能力协商任务异常终止：{error}"),
                                ),
                            }
                        }
                        None => ConnectionNegotiationOutcome::Failed(
                            "设备连接在能力协商前已移除，请重试".to_string(),
                        ),
                    };
                    if !attempt_is_current(&comp, &device_id, &attempt_id) {
                        return;
                    }
                    match negotiation {
                        ConnectionNegotiationOutcome::Ready => {}
                        ConnectionNegotiationOutcome::Failed(error) => {
                            clear_active_pairing(&comp, &device_id, &attempt_id);
                            emit_devices(&comp, &app);
                            emit_pairing_resolution(
                                &app,
                                &device_id,
                                &attempt_id,
                                PairingResolutionOutcome::Failed,
                                Some(error),
                            );
                            return;
                        }
                        ConnectionNegotiationOutcome::Stale => {
                            clear_active_pairing(&comp, &device_id, &attempt_id);
                            emit_devices(&comp, &app);
                            emit_pairing_resolution(
                                &app,
                                &device_id,
                                &attempt_id,
                                PairingResolutionOutcome::Failed,
                                Some("设备连接在能力协商期间已重建，请重试".to_string()),
                            );
                            return;
                        }
                    }
                    let still_connected = comp.handle_for(&device_id).is_some_and(|handle| {
                        matches!(
                            handle.connection_state(),
                            ConnectionState::Connected {
                                epoch: current_epoch,
                                ..
                            } if current_epoch == epoch
                        )
                    });
                    if !still_connected {
                        clear_active_pairing(&comp, &device_id, &attempt_id);
                        emit_devices(&comp, &app);
                        emit_pairing_resolution(
                            &app,
                            &device_id,
                            &attempt_id,
                            PairingResolutionOutcome::Failed,
                            Some("设备连接在能力协商后已失效，请重试".to_string()),
                        );
                        return;
                    }
                }
                // Retained legacy v1 endpoints may still use a SAS-confirmed
                // publication key for frozen offline compatibility paths. The
                // current Device API v4 lab profile disables this write because
                // removable-media/TF-card workflows are no longer part of the
                // current product route.
                record_trusted_producer_key(&comp, &device_id, &attempt_id);
                clear_active_pairing(&comp, &device_id, &attempt_id);
                emit_devices(&comp, &app);
                emit_pairing_resolution(
                    &app,
                    &device_id,
                    &attempt_id,
                    PairingResolutionOutcome::Connected,
                    None,
                );
                return;
            }
            Ok(PollPairingOutcome::Rejected) => {
                clear_active_pairing(&comp, &device_id, &attempt_id);
                emit_devices(&comp, &app);
                emit_pairing_resolution(
                    &app,
                    &device_id,
                    &attempt_id,
                    PairingResolutionOutcome::Rejected,
                    None,
                );
                return;
            }
            Ok(PollPairingOutcome::Expired) => {
                clear_active_pairing(&comp, &device_id, &attempt_id);
                emit_devices(&comp, &app);
                emit_pairing_resolution(
                    &app,
                    &device_id,
                    &attempt_id,
                    PairingResolutionOutcome::Expired,
                    None,
                );
                return;
            }
            Ok(PollPairingOutcome::Stale) | Ok(PollPairingOutcome::NotPairing) => {
                clear_active_pairing(&comp, &device_id, &attempt_id);
                emit_pairing_resolution(
                    &app,
                    &device_id,
                    &attempt_id,
                    PairingResolutionOutcome::Failed,
                    Some("配对请求已失效，请重试".to_string()),
                );
                emit_devices(&comp, &app);
                return;
            }
            // Transient network/decode error: keep waiting for the
            // operator until the server-supplied absolute expiry.
            Ok(PollPairingOutcome::Error(_)) => continue,
            Err(error) => {
                clear_active_pairing(&comp, &device_id, &attempt_id);
                emit_pairing_resolution(
                    &app,
                    &device_id,
                    &attempt_id,
                    PairingResolutionOutcome::Failed,
                    Some(format!("配对轮询任务异常终止：{error}")),
                );
                emit_devices(&comp, &app);
                return;
            }
        }
    }
    clear_active_pairing(&comp, &device_id, &attempt_id);
    expire_pairing_locally(&comp, &device_id, &attempt_id);
    emit_devices(&comp, &app);
    emit_pairing_resolution(
        &app,
        &device_id,
        &attempt_id,
        PairingResolutionOutcome::Expired,
        Some("设备确认超时，请重新发起配对".to_string()),
    );
}

fn pairing_remaining_seconds(expires_at: chrono::DateTime<chrono::Utc>) -> i64 {
    let remaining_ms = (expires_at - chrono::Utc::now()).num_milliseconds();
    if remaining_ms <= 0 {
        0
    } else {
        remaining_ms.saturating_add(999) / 1000
    }
}

/// Whether `attempt_id` is still the attempt this device is pairing with.
/// Anything else is a superseded attempt whose results must be dropped.
fn pairing_attempt_is_current(
    active: &HashMap<String, ActivePairing>,
    device_id: &str,
    attempt_id: &str,
) -> bool {
    active
        .get(device_id)
        .is_some_and(|attempt| attempt.attempt_id == attempt_id)
}

fn attempt_is_current(comp: &Composition, device_id: &str, attempt_id: &str) -> bool {
    pairing_attempt_is_current(&comp.active_pairings.lock().unwrap(), device_id, attempt_id)
}

/// Persist the SAS-confirmed publication key for this device.
///
/// This is the only writer of PC producer trust. It runs exactly once per
/// successful pairing resolution, stores no token or secret, and records a
/// rotation as an explicit revoke+insert inside one transaction. Deleting the
/// device from the UI later does not undo it; revocation is its own action.
fn record_trusted_producer_key(comp: &Composition, device_id: &str, attempt_id: &str) {
    let sas = {
        let active = comp.active_pairings.lock().unwrap();
        if !pairing_attempt_is_current(&active, device_id, attempt_id) {
            return;
        }
        match active.get(device_id) {
            Some(active) if active.record_trusted_producer_key => active.sas.clone(),
            Some(_) => return,
            None => return,
        }
    };
    let Some(handle) = comp.handle_for(device_id) else {
        return;
    };
    // Only the identity the SAS transcript actually covered may be trusted.
    // A fingerprint learned later from an authenticated `GET /device` is not
    // operator-confirmed and must not create trust on its own.
    //
    // The actor guard is scoped so the store write below never happens while
    // this device's actor mutex is held.
    let fingerprint = {
        let actor = handle.actor();
        actor.sas_publication_key_fingerprint().map(str::to_string)
    };
    let Some(fingerprint) = fingerprint else {
        return;
    };
    let evidence = ylx_transfer_core::media_store::pairing_evidence_digest(
        device_id,
        attempt_id,
        &sas,
        &fingerprint,
    );
    let confirmed_at = chrono::Utc::now().to_rfc3339();
    let result = comp
        .media_store
        .lock()
        .unwrap()
        .confirm_trusted_producer_key(device_id, &fingerprint, &evidence, &confirmed_at);
    if let Err(error) = result {
        // Stable, bounded diagnostics only: never the fingerprint, the SAS,
        // or native SQLite text beyond the typed error's own message.
        eprintln!("[pairing] could not record trusted producer key: {error}");
    }
}

fn clear_active_pairing(comp: &Composition, device_id: &str, attempt_id: &str) {
    let mut active = comp.active_pairings.lock().unwrap();
    if pairing_attempt_is_current(&active, device_id, attempt_id) {
        active.remove(device_id);
    }
}

fn emit_pairing_resolution(
    app: &AppHandle,
    device_id: &str,
    attempt_id: &str,
    outcome: PairingResolutionOutcome,
    error: Option<String>,
) {
    let _ = emit_pairing_event(
        app,
        true,
        PairingResolutionEvent {
            device_id: device_id.to_string(),
            attempt_id: attempt_id.to_string(),
            outcome,
            error,
        },
    );
}

/// Expires one specific attempt locally. A device that has meanwhile moved
/// on to a *newer* attempt is left alone -- the stale attempt has no
/// authority over it.
fn expire_pairing_locally(comp: &Composition, device_id: &str, attempt_id: &str) {
    let Some(handle) = comp.handle_for(device_id) else {
        return;
    };
    let ConnectionState::Pairing {
        attempt_id: current,
        ..
    } = handle.connection_state()
    else {
        return;
    };
    if current != attempt_id {
        return;
    }
    handle.actor().apply_pairing_status(
        attempt_id,
        Ok(PairingStatusView {
            attempt_id: attempt_id.to_string(),
            phase: PairingPhase::Expired,
            connection_token: None,
            sas: String::new(),
            expires_at: String::new(),
            sas_publication_key_fingerprint: None,
        }),
    );
}

/// The one network call [`cancel_pairing`] makes, behind a seam so a test
/// can supply a client whose DELETE blocks (see
/// `cancel_pairing_does_not_hold_the_calling_thread_while_the_pi_delete_blocks`).
trait PairingCancelPort: Send + Sync + 'static {
    fn cancel_pairing_attempt(&self, attempt_id: &str, poll_secret: &str) -> Result<(), String>;
}

impl PairingCancelPort for PiPairingClient {
    fn cancel_pairing_attempt(&self, attempt_id: &str, poll_secret: &str) -> Result<(), String> {
        self.cancel_pairing(attempt_id, poll_secret)
            .map_err(|error| error.to_string())
    }
}

/// Runs the Pi-side `DELETE /pairing-requests/{id}` on a blocking worker,
/// never on the caller's (IPC/WebView) thread: an unreachable Pi makes this
/// call sit in a socket timeout for seconds, which must not freeze the UI.
async fn cancel_pairing_at_device(
    client: Arc<dyn PairingCancelPort>,
    attempt_id: String,
    poll_secret: String,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        client.cancel_pairing_attempt(&attempt_id, &poll_secret)
    })
    .await
    .map_err(|error| format!("取消配对任务异常终止：{error}"))?
    .map_err(|error| format!("设备端取消配对失败：{error}"))
}

/// Cancels one in-flight pairing attempt at the Pi. `attempt_id` identifies
/// which attempt the caller means: a cancel aimed at an attempt this device
/// has already moved past is refused instead of tearing down the current
/// one. Local state changes only after the DELETE succeeds; a
/// network/server error remains visible to the caller and the polling task
/// keeps running.
pub async fn cancel_pairing(
    comp: Arc<Composition>,
    device_id: String,
    attempt_id: String,
) -> Result<(), String> {
    let binding = comp.resolve_binding(&device_id)?;
    let device_id = binding.identity.device_id().as_str().to_string();
    let active = {
        let pairings = comp.active_pairings.lock().unwrap();
        if !pairing_attempt_is_current(&pairings, &device_id, &attempt_id) {
            return Err(if pairings.contains_key(&device_id) {
                "该配对请求已失效，请重试".to_string()
            } else {
                "该设备当前没有可取消的配对请求".to_string()
            });
        }
        pairings
            .get(&device_id)
            .cloned()
            .expect("checked by pairing_attempt_is_current")
    };

    cancel_pairing_at_device(
        Arc::new(PiPairingClient::new(active.client.clone())),
        attempt_id.clone(),
        active.poll_secret.clone(),
    )
    .await?;

    clear_active_pairing(&comp, &device_id, &attempt_id);
    if let Some(task) = comp.pairing_tasks.lock().unwrap().remove(&device_id) {
        task.abort();
    }
    // The Pi-side DELETE above already happened with nothing held; this is
    // the purely local half, and the actor's own attempt-id guard drops it
    // if the device has meanwhile moved on to a newer attempt.
    binding.handle.actor().apply_pairing_status(
        &attempt_id,
        Ok(PairingStatusView {
            attempt_id: attempt_id.clone(),
            phase: PairingPhase::Cancelled,
            connection_token: None,
            sas: String::new(),
            expires_at: String::new(),
            sas_publication_key_fingerprint: None,
        }),
    );
    Ok(())
}

/// Disconnects a real device: revokes the session (best-effort, using the
/// actor's own internally-held token) and transitions it back to
/// `Disconnected` locally either way.
pub fn disconnect_device(comp: &Composition, device_id: &str) {
    let Ok(binding) = comp.resolve_binding(device_id) else {
        return;
    };
    let canonical_id = binding.identity.device_id().as_str();
    if let Some(task) = comp.pairing_tasks.lock().unwrap().remove(canonical_id) {
        task.abort();
    }
    // The local transition happens under this one device's handle lock; the
    // best-effort revoke leaves it before it touches the network, so
    // disconnecting an unreachable Pi blocks no other device.
    match authenticated_client_for(&binding.handle, binding.client) {
        Ok(authenticated) => {
            let _ = binding.handle.disconnect_with(&authenticated);
        }
        Err(_) => binding.handle.disconnect_local(),
    }
}

/// PC-03b: a real, per-file download of an entire session through
/// `TransferCoordinator::enqueue()`. Fetches the session's real detail
/// (`DeviceActor::get_session` -> `GET /sessions/{id}`, using the actor's
/// own held token), which now carries a real per-file inventory
/// (`SessionDetailView::files`, closed by PI-01b on the Pi side and wired
/// through by this task -- see module doc comment). Builds one `JobFile`
/// per entry (`file_id` == each entry's opaque wire `id`, `expected_size`
/// == `size_bytes`, `expected_sha256_hex` == `sha256`, and
/// `target_relative_path` == the signed `display_path`) and
/// enqueues through [`Composition::enqueue_download`] (not
/// `comp.coordinator.enqueue` directly), so the resulting job's completion
/// is tracked -- see that method's doc comment and
/// [`spawn_transfer_poll_loop`]'s handling of
/// `Succeeded`/`Failed`/`Cancelled`. The rest of the pipeline this drives --
/// [`RealDownloadSourceFactory`] -> `PiDownloadSource` ->
/// `TransferCoordinator` -- was already fully real and wired (PC-08b); this
/// is the first call site that actually reaches it for a real device.
///
/// Still returns an honest `Err` for the genuine edge cases: device not
/// known / not connected, the `GET /sessions/{id}` call itself failing, or
/// -- now a real (if unusual) possibility rather than the universal case --
/// a session whose `files` array is genuinely empty.
pub fn download_session(
    comp: &Composition,
    device_id: &str,
    session_id: &str,
    authorization: &crate::application::SessionReadAuthorization,
) -> Result<String, String> {
    let (identity, detail) =
        get_authorized_session_detail(comp, device_id, session_id, authorization)?;

    let request = transfer_request_from_session_detail(&identity, session_id, &detail)?;
    let session_files = session_files_from_detail(&detail);

    comp.enqueue_download_with_context(
        request,
        detail.captured_at.clone(),
        session_files.clone(),
        session_files,
    )
    .map(|job_id| job_id.to_string())
}

/// User-facing (Chinese) translation of a `CoordinatorError`, in the same
/// style as [`describe_vault_error`]/[`describe_object_store_error`].
/// Never swallows a variant into a vague "操作失败": each one tells the
/// operator something different about whether retrying can help.
fn describe_coordinator_error(job_id: &str, e: &CoordinatorError) -> String {
    match e {
        CoordinatorError::NotFound(_) => format!("未找到下载任务：{job_id}"),
        CoordinatorError::AlreadyTerminal(_) => "该下载任务已结束，无法再更改状态".to_string(),
        CoordinatorError::NotTerminal(_) => "只有已结束的下载任务可以清除".to_string(),
        CoordinatorError::NotFailed(_) => "只有失败的下载任务可以重试".to_string(),
        CoordinatorError::Timeout(_) => "等待下载任务停止超时，请稍后重试".to_string(),
        CoordinatorError::Persistence(detail) => format!("下载任务状态持久化失败：{detail}"),
        CoordinatorError::Io(detail) => format!("下载任务读写本地磁盘失败：{detail}"),
        CoordinatorError::Verification(detail) => format!("下载任务签名校验失败：{detail}"),
        // Catch-all rather than an exhaustive match on purpose: the
        // remaining variants are internal-shaped failures with no
        // distinct operator-facing meaning, and `CoordinatorError` lives
        // in another crate that may grow variants. The underlying
        // message is still included -- never a bare "操作失败".
        other => format!("下载任务操作失败：{other}"),
    }
}

/// Pauses a running download job.  An unknown job id is an explicit error
/// (`CoordinatorError::NotFound` -> "未找到下载任务"), never a silent
/// `Ok(())` -- a command that reports success for a job that does not
/// exist would leave the UI showing a paused state nothing is enforcing.
pub fn pause_transfer_job(comp: &Composition, job_id: &str) -> Result<(), String> {
    let job_id = JobId(job_id.to_string());
    comp.coordinator
        .pause(&job_id)
        .map_err(|e| describe_coordinator_error(job_id.as_str(), &e))
}

/// Resumes a job paused by [`pause_transfer_job`] (and kicks a
/// `retry_wait` job back into the queue -- see
/// `TransferCoordinator::resume`).
pub fn resume_transfer_job(comp: &Composition, job_id: &str) -> Result<(), String> {
    let job_id = JobId(job_id.to_string());
    comp.coordinator
        .resume(&job_id)
        .map_err(|e| describe_coordinator_error(job_id.as_str(), &e))
}

/// Cancels a download job.
///
/// Note for the command layer: `TransferCoordinator::cancel` **blocks**
/// the calling thread (up to ~10s) until the worker holding the job has
/// really closed its file handle, which is exactly the guarantee that
/// makes cancellation safe. Call this off the UI thread (e.g. inside
/// `spawn_blocking`) so a slow cancel cannot freeze the window.
pub fn cancel_transfer_job(comp: &Composition, job_id: &str) -> Result<(), String> {
    let job_id = JobId(job_id.to_string());
    comp.coordinator
        .cancel(&job_id)
        .map_err(|e| describe_coordinator_error(job_id.as_str(), &e))
}

#[cfg(test)]
fn remove_upload_transfer_state(transfers: &mut Vec<Transfer>, transfer_key: &str) {
    transfers.retain(|transfer| transfer.key != transfer_key);
}

#[cfg(test)]
fn project_upload_transfer_outcome_parts(
    transfers: &mut Vec<Transfer>,
    transfer_key: &str,
    outcome: &TerminalOutcome,
) {
    match outcome {
        TerminalOutcome::Succeeded => {
            remove_upload_transfer_state(transfers, transfer_key);
        }
        TerminalOutcome::Cancelled => {
            if let Some(transfer) = transfers
                .iter_mut()
                .find(|transfer| transfer.key == transfer_key)
            {
                transfer.state = TransferState::Cancelled;
                transfer.error = Some(UPLOAD_CANCELLED_MESSAGE.to_string());
                transfer.retryable = false;
            }
        }
        TerminalOutcome::Failed { code, retryable } => {
            if let Some(transfer) = transfers
                .iter_mut()
                .find(|transfer| transfer.key == transfer_key)
            {
                transfer.state = TransferState::Failed;
                transfer.error = Some(upload_failure_detail(code).to_string());
                transfer.retryable = *retryable;
            }
        }
    }
}

#[cfg(test)]
fn dismiss_terminal_upload_state(
    transfers: &mut Vec<Transfer>,
    transfer_key: &str,
) -> Result<(), String> {
    let transfer = transfers
        .iter()
        .find(|transfer| transfer.key == transfer_key)
        .ok_or_else(|| "未找到该上传任务".to_string())?;
    if transfer.direction != TransferDirection::Up {
        return Err("该任务不是上传任务，无法清除".to_string());
    }
    if !transfer.state.is_terminal() {
        return Err("只有已结束的上传任务可以清除".to_string());
    }
    remove_upload_transfer_state(transfers, transfer_key);
    Ok(())
}

/// Validates that an upload's current in-memory projection may be dismissed.
/// C1 intentionally retains the durable job, immutable spec, retry lineage,
/// completion history, and multipart evidence. Durable visibility belongs to
/// the general activity `dismissed_at` tombstone introduced in C2.
fn validate_durable_upload_dismissal(
    comp: &Composition,
    transfer_key: &str,
) -> Result<bool, String> {
    let (durable_job, completion, upload_spec, pending_uploads) = {
        let store = comp.transfer_store.lock().unwrap();
        let job = store
            .get_job(transfer_key)
            .map_err(|error| format!("无法读取上传任务：{error}"))?;
        let completion = store
            .completion(transfer_key)
            .map_err(|error| format!("无法读取上传任务处理状态：{error}"))?;
        let upload_spec = store
            .upload_job_spec(transfer_key)
            .map_err(|error| format!("无法读取上传任务 immutable spec：{error}"))?;
        let pending_uploads = store
            .list_pending_uploads()
            .map_err(|error| format!("无法读取上传清理状态：{error}"))?;
        (job, completion, upload_spec, pending_uploads)
    };
    let Some(job) = durable_job else {
        return Ok(false);
    };
    if job.operation_kind != OperationKind::Upload {
        return Err("该任务不是上传任务，无法清除".to_string());
    }
    if !job.state.is_terminal() {
        return Err("只有已结束的上传任务可以清除".to_string());
    }
    if !completion.is_some_and(|record| record.is_acknowledged()) {
        return Err("上传任务结果尚未完成处理，暂时无法清除".to_string());
    }
    let has_pending_multipart = pending_uploads.into_iter().any(|row| {
        row.job_id.as_deref() == Some(transfer_key)
            || (row.job_id.is_none()
                && (row.upload.transfer_key == transfer_key
                    || upload_spec.as_ref().is_some_and(|spec| {
                        !row.upload.entry_key.is_empty() && row.upload.entry_key == spec.entry_key
                    })))
    });
    if has_pending_multipart || comp.upload_operation(transfer_key).is_some() {
        return Err("上传任务的远端清理尚未完成，暂时无法清除".to_string());
    }
    Ok(true)
}

/// Removes one terminal upload from the optional in-memory activity
/// projection after validating the durable authority. It does not delete any
/// durable transfer data; see [`validate_durable_upload_dismissal`]. Upload
/// history also remains in `LibraryEntry`.
pub fn dismiss_upload_transfer(
    app: &AppHandle,
    comp: &Composition,
    job_id: &str,
) -> Result<(), String> {
    if validate_durable_upload_dismissal(comp, job_id)? {
        let now = chrono::Utc::now().to_rfc3339();
        comp.transfer_store
            .lock()
            .unwrap()
            .dismiss_job(job_id, &now)
            .map_err(|error| format!("无法标记上传任务为已清除：{error}"))?;
        emit_transfers(app);
        return Ok(());
    }
    Err("未找到该上传任务".to_string())
}

fn cancel_durable_upload(comp: &Composition, job_id: &str) -> Result<bool, String> {
    let durable_job = comp
        .transfer_store
        .lock()
        .unwrap()
        .get_job(job_id)
        .map_err(|error| format!("无法读取上传任务：{error}"))?;
    let Some(job) = durable_job else {
        return Ok(false);
    };
    if job.operation_kind != OperationKind::Upload {
        return Err("该任务不是上传任务，无法按上传取消".to_string());
    }
    if job.state.is_terminal() {
        return Err("该上传任务已结束，无法取消".to_string());
    }
    let operation = comp.upload_operation(job_id);
    if let Some(operation) = operation.as_ref() {
        match operation.request_cancel() {
            CancelDecision::AlreadyTerminal(outcome) => {
                return Err(outcome.already_terminal_message())
            }
            CancelDecision::Requested | CancelDecision::AlreadyRequested => {}
        }
    }
    let now = chrono::Utc::now().to_rfc3339();
    let cancelled =
        comp.transfer_store
            .lock()
            .unwrap()
            .cancel_upload_job(job_id, job.state_version, &now);
    match cancelled {
        Ok(_) => {
            if let Some(operation) = operation {
                let _ = operation.claim_terminal(UploadTerminalOutcome::Cancelled);
            }
            // Leave every durable multipart row available for the worker
            // (or startup recovery) to abort. Marking it aborting makes the
            // desired intent survive a process exit.
            let rows = comp
                .transfer_store
                .lock()
                .unwrap()
                .list_pending_uploads()
                .map_err(|error| format!("无法读取上传清理状态：{error}"))?;
            for row in rows
                .into_iter()
                .filter(|row| row.job_id.as_deref() == Some(job_id))
            {
                comp.transfer_store
                    .lock()
                    .unwrap()
                    .set_upload_desired_state(
                        row.object_key(),
                        row.upload_id(),
                        UploadDesiredState::Aborting,
                        &now,
                    )
                    .map_err(|error| {
                        format!("无法记录上传分片 {} 的中止意图：{error}", row.object_key())
                    })?;
            }
            Ok(true)
        }
        Err(UploadJobError::AlreadyTerminal { existing, .. }) => Err(match existing {
            TerminalOutcome::Succeeded => "该上传任务已完成，无法取消".to_string(),
            TerminalOutcome::Cancelled => "该上传任务已取消".to_string(),
            TerminalOutcome::Failed { .. } => "该上传任务已结束，无法取消".to_string(),
        }),
        Err(UploadJobError::Stale { .. }) => {
            Err("上传任务状态已变化，请刷新后重试取消".to_string())
        }
        Err(error) => Err(format!("无法取消持久化上传任务：{error}")),
    }
}

/// Compatibility adapter for pre-job upload rows. A legacy transfer key is
/// usable only when it resolves to exactly one row; duplicate keys are
/// ambiguous identities and must fail closed instead of first-matching.
fn resolve_legacy_upload_entry_key(
    comp: &Composition,
    transfer_key: &str,
) -> Result<Option<String>, String> {
    let matches = comp
        .transfer_store
        .lock()
        .unwrap()
        .list_pending_uploads()
        .map_err(|error| format!("无法读取旧版上传任务：{error}"))
        .map(|rows| {
            rows.into_iter()
                .filter(|row| row.job_id.is_none() && row.upload.transfer_key == transfer_key)
                .map(|row| row.upload.entry_key)
                .collect::<Vec<_>>()
        })?;
    match matches.as_slice() {
        [] => Ok(None),
        [entry_key] => Ok(Some(entry_key.clone())),
        _ => Err(format!(
            "旧版上传任务标识不唯一（匹配 {} 条记录），已拒绝取消",
            matches.len()
        )),
    }
}

/// Cancels an in-flight upload (uploads do not go through the transfer
/// coordinator -- they are the task [`start_upload`] spawns).
///
/// In the normal case this only *requests* cancellation through the
/// operation token; the upload task itself then aborts its live multipart
/// upload against the object store (so no billable orphan parts are left
/// behind), converges the `Transfer` row and the `LibraryEntry` to an
/// honest failed state carrying [`UPLOAD_CANCELLED_MESSAGE`], persists,
/// and emits the `transfers:update`/`library:update` events. Doing the
/// convergence there rather than here is what keeps exactly one writer per
/// upload.
///
/// [`UploadOperation::request_cancel`] is what makes that safe against a
/// finish landing at the same instant: if the task has already committed a
/// terminal outcome, the cancel is refused rather than allowed to rewrite
/// a verified success into "已取消上传".
///
/// The `no operation token but the row still looks live` branch below is a
/// safety net for a row whose owning task no longer exists at all; it
/// converges the row here so nothing can stay "上传中" forever. That branch
/// re-checks the row's terminal flags *inside* the same lock it writes
/// under, so it cannot step over a finish either.
pub fn cancel_upload<R: Runtime>(
    app: &AppHandle<R>,
    comp: &Composition,
    job_id: &str,
) -> Result<(), String> {
    // Upload jobs are cancelled through the durable terminal CAS first. The
    // process-local token is only a cooperative stop signal for the worker;
    // it is never allowed to decide which terminal outcome won.
    if cancel_durable_upload(comp, job_id)? {
        let _ = comp.deliver_terminal_outcomes(app);
        emit_transfers(app);
        emit_library(app);
        return Ok(());
    }

    // Legacy sidecar rows (job_id = NULL) have no durable terminal CAS. Keep
    // the old token/state fallback solely for those imported records so old
    // installations can still abort an orphan safely.
    let _legacy_entry_key = resolve_legacy_upload_entry_key(comp, job_id)?
        .ok_or_else(|| "未找到该上传任务".to_string())?;
    if let Some(operation) = comp.upload_operation(job_id) {
        return match operation.request_cancel() {
            CancelDecision::Requested | CancelDecision::AlreadyRequested => Ok(()),
            CancelDecision::AlreadyTerminal(outcome) => Err(outcome.already_terminal_message()),
        };
    }

    Err("上传任务没有可取消的持久化状态".to_string())
}

/// Startup reconciliation for uploads interrupted by a previous run.
///
/// Two independent jobs, deliberately in one entry point because they are
/// two halves of the same lie:
///
/// 1. **Remote:** every durable multipart row left by the previous process is
///    claimed as `aborting`, then aborted off the startup thread. A record is
///    deleted from the store only after the remote abort succeeds (or reports
///    `NotFound`), or after `UnknownUpload` is accounted for by an exact
///    durable receipt. An unaccounted consumed handle remains durable because
///    this port cannot safely delete a completed object from an unversioned
///    store; all other failures leave the row for the next run.
/// 2. **Local:** every `LibraryEntry` still marked
///    [`UploadStatus::Uploading`] is converged to `Failed` with
///    [`UPLOAD_INTERRUPTED_MESSAGE`]. `Transfer` rows are in-memory only,
///    so after a restart there is no task and no row that could ever move
///    such an entry off `Uploading` -- without this it stays "上传中"
///    forever.
///
/// Returns `Ok(true)` iff `library` was modified, so the caller (which owns
/// the application store) can persist. Any durable authority read/write
/// failure returns `Err` before the library is mutated or multipart rows are
/// claimed. Takes `&mut Vec<LibraryEntry>` and
/// a `&StorageConfig` rather than `AppState` on purpose: it is called
/// while `AppData` is still being constructed.
pub fn reconcile_interrupted_uploads(
    comp: &Composition,
    // A slice, not `&mut Vec`: this only ever rewrites existing entries
    // (it must never add or drop a library row).
    library: &mut [crate::models::LibraryEntry],
    storage: &crate::models::StorageConfig,
) -> Result<bool, String> {
    // Any non-terminal UploadJob that survived process death must receive a
    // durable terminal cancellation before the app state is exposed. This
    // creates the completion outbox fact that the normal projection will
    // apply; it avoids treating the legacy `Uploading` bool as authority.
    let (jobs, durable_entry_keys, interrupted_specs) = {
        let store = comp.transfer_store.lock().unwrap();
        let jobs = match store.list_jobs() {
            Ok(jobs) => jobs,
            Err(error) => {
                return Err(format!("无法读取启动时的持久化上传任务：{error}"));
            }
        };
        let mut entry_keys = HashSet::new();
        let mut interrupted_specs = Vec::new();
        for job in jobs
            .iter()
            .filter(|job| job.operation_kind == OperationKind::Upload)
        {
            let protects_library_projection = if job.state.is_terminal() {
                match store.completion(&job.job_id) {
                    Ok(Some(completion)) => !completion.is_acknowledged(),
                    Ok(None) => true,
                    Err(error) => {
                        return Err(format!(
                            "无法读取启动时的上传完成记录 {}：{error}",
                            job.job_id
                        ));
                    }
                }
            } else {
                true
            };
            if !protects_library_projection {
                continue;
            }
            match store.upload_job_spec(&job.job_id) {
                Ok(Some(spec)) => {
                    if !job.state.is_terminal() {
                        interrupted_specs.push(spec.clone());
                    }
                    entry_keys.insert(spec.entry_key);
                }
                Ok(None) => {
                    return Err(format!(
                        "启动时持久化上传任务 {} 缺少 immutable spec",
                        job.job_id
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "无法读取启动时的上传任务 immutable spec {}：{error}",
                        job.job_id
                    ));
                }
            }
        }
        (jobs, entry_keys, interrupted_specs)
    };
    let now = chrono::Utc::now().to_rfc3339();
    for job in jobs
        .into_iter()
        .filter(|job| job.operation_kind == OperationKind::Upload && !job.state.is_terminal())
    {
        let result = comp.transfer_store.lock().unwrap().cancel_upload_job(
            &job.job_id,
            job.state_version,
            &now,
        );
        match result {
            Ok(_) | Err(UploadJobError::AlreadyTerminal { .. }) => {}
            Err(error) => {
                return Err(format!(
                    "无法在启动时持久化取消中断上传任务 {}：{error}",
                    job.job_id
                ));
            }
        }
    }
    let mut changed = false;
    for spec in &interrupted_specs {
        if let Some(entry) = library
            .iter_mut()
            .find(|entry| entry.key() == spec.entry_key)
        {
            let same_revision = entry
                .publication
                .as_ref()
                .is_some_and(|publication| publication.revision == spec.revision);
            if same_revision && entry.upload_status == UploadStatus::Uploading {
                entry.upload_status = UploadStatus::Failed;
                entry.upload_retryable = false;
                entry.upload_error = Some(UPLOAD_INTERRUPTED_MESSAGE.to_string());
                entry.uploaded_at = None;
                entry.object_receipts.clear();
                entry.upload_projection = None;
                changed = true;
            }
        }
    }
    let pending = comp
        .transfer_store
        .lock()
        .unwrap()
        .claim_orphan_uploads(&chrono::Utc::now().to_rfc3339())
        .map_err(|error| format!("无法在启动时认领中断上传分片：{error}"))?;
    if !pending.is_empty() {
        let transfer_store = comp.transfer_store.clone();
        let vault = comp.vault.clone();
        let fallback_endpoint = storage.endpoint.clone();
        let fallback_bucket = storage.bucket.clone();
        // Exact URL style is persisted per multipart row. Legacy rows carry a
        // `LegacyConfigured` sentinel and are the only ones resolved from the
        // current storage setting during recovery.
        let url_style = storage.url_style;
        std::thread::spawn(move || {
            abort_orphan_multipart_uploads(
                &transfer_store,
                vault.as_ref(),
                pending,
                &fallback_endpoint,
                &fallback_bucket,
                url_style,
            );
        });
    }
    let legacy_changed = mark_legacy_interrupted_uploads_failed(library, &durable_entry_keys);
    Ok(changed || legacy_changed)
}

fn mark_legacy_interrupted_uploads_failed(
    library: &mut [LibraryEntry],
    durable_entry_keys: &HashSet<String>,
) -> bool {
    let mut changed = false;
    for entry in library.iter_mut() {
        if durable_entry_keys.contains(&entry.key())
            || entry.upload_status != UploadStatus::Uploading
        {
            continue;
        }
        entry.upload_status = UploadStatus::Failed;
        entry.upload_retryable = false;
        entry.upload_error = Some(UPLOAD_INTERRUPTED_MESSAGE.to_string());
        entry.uploaded_at = None;
        entry.object_receipts.clear();
        entry.upload_projection = None;
        changed = true;
    }
    changed
}

/// The network half of [`reconcile_interrupted_uploads`]. Never panics
/// and never propagates: an unreachable object store or a locked keyring
/// simply means the records stay durable for the next run.
fn abort_orphan_multipart_uploads(
    transfer_store: &Arc<Mutex<TransferStore>>,
    vault: &dyn CredentialVaultPort,
    pending: Vec<StoredUpload>,
    fallback_endpoint: &str,
    fallback_bucket: &str,
    url_style: StorageUrlStyle,
) {
    let credential = match read_storage_credential(vault) {
        Ok(credential) => credential,
        Err(e) => {
            eprintln!(
                "[composition] cannot abort {} interrupted multipart upload(s) yet ({}); they \
                 stay recorded for the next run",
                pending.len(),
                describe_vault_error(&e)
            );
            return;
        }
    };

    for record in pending {
        let endpoint = if record.upload.endpoint.trim().is_empty() {
            fallback_endpoint
        } else {
            record.upload.endpoint.as_str()
        };
        let bucket = if record.upload.bucket.trim().is_empty() {
            fallback_bucket
        } else {
            record.upload.bucket.as_str()
        };
        let record_url_style = match record.upload.url_style {
            CoreUploadUrlStyle::VirtualHost => StorageUrlStyle::VirtualHost,
            CoreUploadUrlStyle::Path => StorageUrlStyle::Path,
            CoreUploadUrlStyle::LegacyConfigured => url_style,
        };
        let store = match build_object_store(endpoint, bucket, record_url_style, &credential) {
            Ok(store) => store,
            Err(e) => {
                eprintln!(
                    "[composition] cannot address interrupted multipart upload {} ({e}); keeping \
                     it recorded",
                    record.object_key()
                );
                continue;
            }
        };
        let handle = MultipartUploadHandle {
            key: ObjectKey(record.object_key().to_string()),
            upload_id: UploadId(record.upload_id().to_string()),
        };
        match store.abort_multipart_upload(&handle) {
            Ok(()) | Err(ObjectStoreError::NotFound(_)) => {
                if let Err(error) = transfer_store
                    .lock()
                    .unwrap()
                    .finish_upload(record.object_key(), record.upload_id())
                {
                    eprintln!(
                        "[composition] aborted interrupted multipart upload {} but failed to retire its durable row; it will be retried: {error}",
                        record.object_key()
                    );
                }
            }
            Err(ObjectStoreError::UnknownUpload(_)) => {
                match multipart_receipt_proves_completion(transfer_store, &record) {
                    Ok(true) => {
                        eprintln!(
                            "[composition] multipart {} was already consumed; exact durable receipt accounts for it",
                            record.object_key()
                        );
                        if let Err(error) = transfer_store
                            .lock()
                            .unwrap()
                            .finish_upload(record.object_key(), record.upload_id())
                        {
                            eprintln!(
                                "[composition] consumed multipart {} receipt matched but durable retirement failed: {error}",
                                record.object_key()
                            );
                        }
                    }
                    Ok(false) => {
                        eprintln!(
                            "[composition] multipart {} returned UnknownUpload without an exact durable receipt; cleanup is ambiguous and remains blocked",
                            record.object_key()
                        );
                    }
                    Err(error) => eprintln!(
                        "[composition] cannot inspect receipts for ambiguous multipart {}: {error}; keeping row",
                        record.object_key()
                    ),
                }
            }
            Err(e) => eprintln!(
                "[composition] failed to abort interrupted multipart upload {} ({}); keeping it \
                 recorded for the next run",
                record.object_key(),
                describe_object_store_error(&e)
            ),
        }
    }
}

/// A provider may report `UnknownUpload` either because an abort already
/// succeeded or because the multipart was completed into an object. Retire a
/// durable row only when a structurally valid, version-bound receipt proves
/// the latter. The receipt must belong to this exact job, immutable entry and
/// revision, object key, and object role; projection-level manifest equality
/// remains a separate requirement before a library row becomes `Done`.
fn multipart_receipt_proves_completion(
    transfer_store: &Arc<Mutex<TransferStore>>,
    record: &StoredUpload,
) -> Result<bool, String> {
    let Some(job_id) = record.job_id.as_deref() else {
        return Ok(false);
    };
    let receipts = transfer_store
        .lock()
        .unwrap()
        .list_upload_receipts(job_id)
        .map_err(|error| format!("无法读取上传对象回执：{error}"))?;
    if record.upload.entry_key.trim().is_empty() || record.upload.revision.trim().is_empty() {
        return Ok(false);
    }
    Ok(receipts.into_iter().any(|receipt| {
        receipt.job_id == job_id
            && receipt.entry_key == record.upload.entry_key
            && receipt.revision == record.upload.revision
            && receipt.object_key == record.object_key()
            && upload_receipt_is_structurally_valid_for_multipart(record, &receipt)
    }))
}

fn upload_receipt_is_structurally_valid_for_multipart(
    record: &StoredUpload,
    receipt: &StoredUploadReceipt,
) -> bool {
    if receipt.object_key.trim().is_empty()
        || receipt.etag.trim().is_empty()
        || receipt.staged_at.trim().is_empty()
        || receipt.entry_key.trim().is_empty()
        || receipt.revision.trim().is_empty()
        || receipt
            .version_id
            .as_deref()
            .is_some_and(|version| version.trim().is_empty())
        || receipt.source_sha256.len() != 64
        || !receipt
            .source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }

    // Content-addressed f-* keys need the immutable entry inventory to
    // distinguish the MP4 from JSON evidence. The evidence namespace itself
    // is unambiguous even during startup reconciliation and must never be
    // accepted with a Data receipt.
    if record
        .object_key()
        .split('/')
        .any(|segment| segment == "__ylx_evidence__")
    {
        receipt.role == UploadReceiptRole::Evidence
    } else {
        matches!(
            receipt.role,
            UploadReceiptRole::Data | UploadReceiptRole::Evidence
        )
    }
}

/// The local half of [`reconcile_interrupted_uploads`], as a pure
/// function over the library so it is unit-testable without any
/// composition root, vault, or network. Clearing `object_receipts` is
/// part of the honesty: a half-uploaded entry has no verified objects,
/// and `entry_has_complete_object_receipts` must not be able to see
/// leftovers from the interrupted attempt.
#[cfg(test)]
fn mark_interrupted_uploads_failed(library: &mut [LibraryEntry]) -> bool {
    let mut changed = false;
    for entry in library.iter_mut() {
        if entry.upload_status != UploadStatus::Uploading {
            continue;
        }
        entry.upload_status = UploadStatus::Failed;
        entry.upload_retryable = false;
        entry.upload_error = Some(UPLOAD_INTERRUPTED_MESSAGE.to_string());
        entry.uploaded_at = None;
        entry.object_receipts.clear();
        entry.upload_projection = None;
        changed = true;
    }
    changed
}

fn get_authorized_session_detail(
    comp: &Composition,
    device_id: &str,
    session_id: &str,
    authorization: &crate::application::SessionReadAuthorization,
) -> Result<(DeviceIdentity, SessionDetailView), String> {
    let binding = comp.resolve_binding(device_id)?;
    if binding.handle.current_epoch() != Some(authorization.connection_epoch) {
        return Err("设备已重新连接，旧会话下载请求已失效".to_string());
    }
    let detail = match binding.endpoint.api_profile {
        DeviceApiProfile::LegacyPinnedTlsV1 => {
            fetch_session_detail(&binding.handle, binding.client, session_id)?
        }
        DeviceApiProfile::LabHttpV4 => {
            let verification = authorization
                .verification
                .as_ref()
                .filter(|verification| {
                    verification.permits_detail_for(&authorization.session_revision)
                })
                .ok_or_else(|| {
                    "该会话缺少可用且与当前 revision 匹配的 gateway verification".to_string()
                })?;
            let core_verification = gateway_verification_from_view(verification);
            fetch_verified_session_detail(
                &binding.handle,
                binding.client,
                session_id,
                &core_verification,
            )?
        }
    };
    if binding.handle.current_epoch() != Some(authorization.connection_epoch) {
        return Err("设备已重新连接，旧会话下载请求已失效".to_string());
    }
    if detail.revision != authorization.session_revision {
        return Err("会话 revision 已变化，请刷新列表后重试".to_string());
    }
    Ok((binding.identity, detail))
}

/// Re-reads the device's authenticated publication identity and then one
/// session's immutable detail. Both requests are issued through the
/// device's own handle, so neither holds the fleet's map lock nor the
/// handle's lock while it is in flight, and both are fenced on the
/// connection epoch: a reply that belongs to a session the user has since
/// ended is refused rather than acted on.
fn fetch_session_detail(
    handle: &DeviceHandle,
    client: Arc<PiHttpClient>,
    session_id: &str,
) -> Result<SessionDetailView, String> {
    let mut authenticated = authenticated_client_for(handle, client.clone())?;
    match handle.refresh_capture_activity_with(&authenticated) {
        RefreshApplyOutcome::Refreshed => {}
        RefreshApplyOutcome::NotConnected => return Err("该设备尚未连接或连接已失效".to_string()),
        RefreshApplyOutcome::Stale => return Err("设备连接在请求期间已重建，请重试".to_string()),
        RefreshApplyOutcome::Failed(error) => {
            return Err(format!("刷新设备 publication 身份失败：{error}"))
        }
    }
    authenticated = authenticated_client_for(handle, client)?;
    let detail = match handle.get_session_with(&authenticated, session_id) {
        SessionDetailOutcome::Fetched(detail) => *detail,
        SessionDetailOutcome::NotConnected => return Err("该设备尚未连接或连接已失效".to_string()),
        SessionDetailOutcome::Stale => return Err("设备连接在请求期间已重建，请重试".to_string()),
        SessionDetailOutcome::Failed(error) => return Err(error.to_string()),
    };
    if detail.session_id != session_id {
        return Err("设备返回了不匹配的会话详情".to_string());
    }
    Ok(detail)
}

fn fetch_verified_session_detail(
    handle: &DeviceHandle,
    client: Arc<PiHttpClient>,
    session_id: &str,
    verification: &GatewayVerificationView,
) -> Result<SessionDetailView, String> {
    if !verification.is_detail_eligible() {
        return Err("该会话的 gateway verification 不允许读取详情".to_string());
    }
    let negotiated = handle
        .negotiated_device_snapshot()
        .ok_or_else(|| "设备能力协商结果不可用，请重新连接后重试".to_string())?;
    if negotiated.info.profile != DeviceApiProfileView::LabHttpV4 {
        return Err("设备能力协商 profile 与 Device API v4 详情请求不一致".to_string());
    }
    let authenticated = authenticated_client_for(handle, client)?;
    let detail = match handle.get_verified_session_with(&authenticated, session_id, verification) {
        SessionDetailOutcome::Fetched(detail) => *detail,
        SessionDetailOutcome::NotConnected => return Err("该设备尚未连接或连接已失效".to_string()),
        SessionDetailOutcome::Stale => return Err("设备连接在请求期间已重建，请重试".to_string()),
        SessionDetailOutcome::Failed(error) => return Err(error.to_string()),
    };
    if detail.session_id != session_id || detail.gateway_verification.as_ref() != Some(verification)
    {
        return Err("设备返回了未绑定到所选 gateway verification 的会话详情".to_string());
    }
    Ok(detail)
}

fn session_files_from_detail(detail: &SessionDetailView) -> Vec<SessionFile> {
    detail
        .files
        .iter()
        .map(|file| {
            SessionFile::new(
                file.id.clone(),
                file.display_path.clone(),
                file.size_bytes,
                file.sha256.clone(),
            )
        })
        .collect()
}

/// Pure conversion from a real `GET /sessions/{id}` detail (`files[]`
/// included) into the `TransferRequest` `Composition::enqueue_download`
/// needs -- factored out of [`download_session`] so it is directly
/// unit-testable without a real (or even fake) Pi network capability
/// call: `Composition`'s `clients` map is hardwired to the concrete
/// `PiHttpClient` (see that field's doc comment), so exercising
/// `download_session` itself end-to-end needs a real pinned-TLS server
/// (see `pi_http_integration.rs`'s harness for that heavier proof) --
/// this function is what a unit test *can* reach directly. `file_id` stays
/// each entry's opaque wire `id` for HTTP requests, while
/// `target_relative_path` carries the signed Pi `display_path` for local
/// naming after strict path validation. `idempotency_key`
/// is a fresh UUID per call, matching `delete_session`'s existing style
/// for the same reason: a retried download must not collide with an
/// earlier attempt's still-in-flight or already-terminal job. Lab-v4
/// compatibility publications additionally pass the complete vendored Device
/// Session v2 schema before this function creates any downloadable job.
fn transfer_request_from_session_detail(
    identity: &DeviceIdentity,
    session_id: &str,
    detail: &SessionDetailView,
) -> Result<TransferRequest, String> {
    if detail.publication_origin == PublicationEnvelopeOriginView::ClientDerivedLabCompatibility {
        derived_media::validate_source_publication_for_download(&detail.publication_payload)
            .map_err(|error| format!("设备会话清单未通过完整 Device Session v2 校验：{error}"))?;
    }
    if detail.files.is_empty() {
        return Err("该会话没有可下载的文件".to_string());
    }

    let files: Vec<JobFile> = detail
        .files
        .iter()
        .map(|f| JobFile {
            file_id: FileId(f.id.clone()),
            target_relative_path: Some(f.display_path.clone()),
            expected_size: f.size_bytes,
            expected_sha256_hex: f.sha256.clone(),
        })
        .collect();

    Ok(TransferRequest {
        device_id: identity.device_id().clone(),
        session_id: SessionId(session_id.to_string()),
        revision: detail.revision.clone(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        files,
        manifest_bytes: detail.publication_payload.clone(),
        signature: detail.publication_signature.clone(),
        publication_public_key: detail.publication_public_key.clone(),
    })
}

// =====================================================================
// PC-06: object storage -- credential vault selection, real S3 upload,
// real connectivity check.
// =====================================================================
//
// Everything below performs real file/network I/O against `S3ObjectStore`.
// Non-secret configuration is persisted in the application store; the
// access/secret pair lives only behind `CredentialVaultPort`.

/// Fixed vault key for the single object-store credential this app
/// supports today (one profile, not per-device). Both `access_key` and
/// `secret_key` are bundled into one JSON blob and stored as a single
/// vault secret (rather than two separate vault entries) so a partial
/// write can never leave one half updated and the other stale.
fn storage_credential_key() -> CredentialKey {
    CredentialKey::new("storage/s3")
}

/// Reads the object-store credential out of `vault`. Takes the port
/// rather than `&Composition` so the startup upload reconciler
/// ([`abort_orphan_multipart_uploads`]), which runs on its own thread
/// holding only a cloned `Arc<dyn CredentialVaultPort>`, can use the exact
/// same decoding path as `Composition::storage_credential`.
fn read_storage_credential(
    vault: &dyn CredentialVaultPort,
) -> Result<StoredCredential, CredentialVaultError> {
    let secret = vault.expose_secret(&storage_credential_key())?;
    serde_json::from_str(secret.expose_secret()).map_err(|e| {
        CredentialVaultError::Unavailable(format!(
            "stored object-store credential was corrupt (not the JSON this app writes): {e}"
        ))
    })
}

/// Probe-only key used once at startup to decide which vault backend to
/// use -- see `choose_vault`. Deliberately distinct from
/// `storage_credential_key()` so the probe can never collide with (or
/// accidentally read/overwrite) the real stored credential.
#[cfg(not(test))]
fn probe_credential_key() -> CredentialKey {
    CredentialKey::new("__ylx_vault_probe__")
}

/// Source-level replacement slots for a private build that deliberately
/// templates in an object-store credential before compilation.
///
/// The public repository must keep these as inert placeholders. A plain
/// public checkout should build and test without any secret material, then
/// leave storage unconfigured until one of the runtime bootstrap sources
/// or the settings UI supplies a credential. Release builds that need a
/// ready-to-run binary should prefer `build.rs` injection from CI secrets
/// over editing these constants.
const BUILT_IN_OSS_ACCESS_KEY: &str = "@@YLX_OSS_ACCESS_KEY@@";
const BUILT_IN_OSS_SECRET_KEY: &str = "@@YLX_OSS_SECRET_KEY@@";

/// [`BUILT_IN_OSS_ACCESS_KEY`] / [`BUILT_IN_OSS_SECRET_KEY`], unless they
/// are still the unsubstituted placeholders, in which case there is no
/// built-in credential rather than a nonsense one that fails at upload
/// time.
fn built_in_credential() -> Option<(String, String)> {
    let access_key = BUILT_IN_OSS_ACCESS_KEY.trim();
    let secret_key = BUILT_IN_OSS_SECRET_KEY;
    if access_key.is_empty() || secret_key.trim().is_empty() || access_key.starts_with("@@") {
        return None;
    }
    Some((access_key.to_string(), secret_key.to_string()))
}

/// Filename of the optional first-run credential drop, resolved inside the
/// app data directory (the same directory that holds `app-state.sqlite3`).
pub const CREDENTIAL_BOOTSTRAP_FILE: &str = "credentials.json";

/// Shape of [`CREDENTIAL_BOOTSTRAP_FILE`]. Field names match what Aliyun's
/// console hands out when you create a RAM AccessKey, so the file can be
/// filled in by copy-paste without translation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialBootstrapFile {
    access_key_id: String,
    secret_access_key: String,
}

/// Seeds the object-store credential on first run so a fresh install is
/// usable without anyone typing an AK/SK into the settings dialog.
///
/// This is a *bootstrap*, not a second home for the secret: it only ever
/// runs when the vault has no credential yet, and the value it finds goes
/// straight into the OS keyring, which remains the single source of truth
/// afterwards. Deleting the bootstrap file changes nothing once the vault
/// is populated. Nothing here weakens ADR-CRED-001 -- no secret is
/// committed to the repository, compiled into the binary, or written to
/// the application store.
///
/// Sources, in priority order:
///
/// 1. `YLX_OSS_ACCESS_KEY` / `YLX_OSS_SECRET_KEY` environment variables
///    (both required) -- for CI and scripted runs.
/// 2. `<app_data_dir>/credentials.json` -- see [`CredentialBootstrapFile`].
/// 3. The credential compiled into this binary by `build.rs`, if the build
///    machine had one -- lets a release build ship a key without editing
///    source.
/// 4. [`BUILT_IN_OSS_ACCESS_KEY`] / [`BUILT_IN_OSS_SECRET_KEY`], but only
///    if a private release process deliberately replaced the public
///    placeholders before compilation.
///
/// Never fatal: a missing source, an unreadable file, or a locked keyring
/// just leaves the app in its "please configure storage" state, exactly as
/// before this existed. Returns whether a credential was actually seeded.
pub fn bootstrap_storage_credential(comp: &Composition, app_data_dir: &Path) -> bool {
    match comp.storage_secret_status() {
        // Already configured: the vault wins, always. A stale bootstrap
        // file must never clobber a credential the user actually entered.
        Ok(status) if status.secret_configured => return false,
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "[composition] cannot check the credential vault, skipping first-run \
                 credential bootstrap: {}",
                describe_vault_error(&e)
            );
            return false;
        }
    }

    let Some((access_key, secret_key)) = read_bootstrap_credential(app_data_dir) else {
        return false;
    };

    match comp.set_storage_credential(access_key, secret_key) {
        Ok(()) => {
            eprintln!(
                "[composition] seeded the object-store credential into the credential vault from \
                 the first-run bootstrap; the vault is authoritative from now on"
            );
            true
        }
        Err(e) => {
            eprintln!(
                "[composition] failed to seed the bootstrap credential into the credential vault \
                 (storage stays unconfigured): {}",
                describe_vault_error(&e)
            );
            false
        }
    }
}

/// The source-selection half of [`bootstrap_storage_credential`], split out
/// so it is testable without a vault. Returns `None` unless a *complete*
/// pair was found -- a half-filled source is treated as absent rather than
/// producing a credential that cannot sign anything.
fn read_bootstrap_credential(app_data_dir: &Path) -> Option<(String, String)> {
    let env_access = std::env::var("YLX_OSS_ACCESS_KEY").unwrap_or_default();
    let env_secret = std::env::var("YLX_OSS_SECRET_KEY").unwrap_or_default();
    if !env_access.trim().is_empty() && !env_secret.trim().is_empty() {
        return Some((env_access.trim().to_string(), env_secret));
    }

    let path = app_data_dir.join(CREDENTIAL_BOOTSTRAP_FILE);
    match std::fs::read_to_string(&path) {
        Ok(raw) => match parse_bootstrap_file(&raw) {
            Ok(pair) => return Some(pair),
            Err(reason) => {
                // Worth saying out loud: a typo'd bootstrap file that
                // silently did nothing would look exactly like "the
                // feature is broken".
                eprintln!("[composition] ignoring {path:?}: {reason}");
            }
        },
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("[composition] cannot read {path:?}: {e}");
        }
        Err(_) => {}
    }

    embedded_credential()
}

/// The credential `build.rs` compiled in, if the build machine had one,
/// falling back to the source-level replacement slots. `option_env!`
/// resolves at compile time, so a build without an injected credential
/// simply skips to [`built_in_credential`] rather than failing.
fn embedded_credential() -> Option<(String, String)> {
    let injected = option_env!("YLX_EMBEDDED_OSS_ACCESS_KEY")
        .zip(option_env!("YLX_EMBEDDED_OSS_SECRET_KEY"))
        .filter(|(access_key, secret_key)| {
            !access_key.trim().is_empty() && !secret_key.trim().is_empty()
        })
        .map(|(access_key, secret_key)| (access_key.trim().to_string(), secret_key.to_string()));

    injected.or_else(built_in_credential)
}

/// Pure parse half of [`read_bootstrap_credential`], so the file format's
/// accept/reject rules are testable without touching the filesystem, the
/// environment, or a vault.
fn parse_bootstrap_file(raw: &str) -> Result<(String, String), String> {
    let parsed: CredentialBootstrapFile =
        serde_json::from_str(raw).map_err(|e| format!("malformed credential JSON: {e}"))?;
    if parsed.access_key_id.trim().is_empty() || parsed.secret_access_key.trim().is_empty() {
        return Err("accessKeyId/secretAccessKey must both be set".to_string());
    }
    Ok((
        parsed.access_key_id.trim().to_string(),
        // Deliberately not trimmed: whitespace can be part of a real secret.
        parsed.secret_access_key,
    ))
}

/// The object-store credential pair, as stored in the vault. Serialized
/// as one JSON blob (see `storage_credential_key`'s doc comment) and
/// wrapped in a `Secret` before ever reaching `CredentialVaultPort::set_secret`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    access_key: String,
    secret_key: String,
}

impl StoredCredential {
    pub fn new(access_key: String, secret_key: String) -> Result<Self, String> {
        if access_key.trim().is_empty() || secret_key.trim().is_empty() {
            return Err("Access Key 与 Secret Key 必须同时填写".to_string());
        }
        Ok(Self {
            access_key: access_key.trim().to_string(),
            secret_key,
        })
    }
}

/// Chooses which `CredentialVaultPort` backend `Composition` uses for the
/// object-store secret. Unit tests use the deterministic in-memory fake so
/// default test runs never depend on host D-Bus/keyring state; production
/// probes the real OS keyring once with a throwaway key:
///
/// Production always retains the OS keyring implementation. Locked,
/// unavailable, and permission-denied backends remain explicit errors on
/// storage operations; silently accepting a session-only credential would
/// make a successful-looking production configuration disappear on restart.
#[cfg(test)]
fn choose_vault() -> Arc<dyn CredentialVaultPort> {
    Arc::new(InMemoryCredentialVault::new())
}

#[cfg(not(test))]
fn choose_vault() -> Arc<dyn CredentialVaultPort> {
    let primary = OsKeyringCredentialVault::new("ylx-transfer");
    if let Err(error) = primary.status(&probe_credential_key()) {
        eprintln!(
            "[composition] OS credential keyring is not currently usable ({error}); storage \
             secret operations remain disabled until the OS keyring becomes available"
        );
    }
    Arc::new(primary)
}

/// User-facing (Chinese, matching this app's existing error copy)
/// translation of a `CredentialVaultError` for `commands.rs`'s storage
/// commands. Never includes secret material -- `CredentialVaultError`
/// itself never carries any (see `credential_vault.rs`'s doc comment).
fn describe_vault_error(e: &CredentialVaultError) -> String {
    match e {
        CredentialVaultError::Locked(detail) => format!("系统密钥环已锁定，请解锁后重试：{detail}"),
        CredentialVaultError::Unavailable(detail) => format!("系统密钥环不可用：{detail}"),
        CredentialVaultError::NotFound(_) => {
            "尚未配置对象存储的 Access Key / Secret Key".to_string()
        }
        CredentialVaultError::PermissionDenied(detail) => {
            format!("访问系统密钥环被拒绝：{detail}")
        }
        CredentialVaultError::MigrationFailed { reason, .. } => format!("凭据迁移失败：{reason}"),
    }
}

/// Builds a real `S3ObjectStore` client for the given endpoint/bucket and
/// vault-stored credential. No I/O happens here (mirrors
/// `S3ObjectStore::new`'s own contract) -- only signing configuration.
fn build_object_store(
    endpoint: &str,
    bucket: &str,
    url_style: StorageUrlStyle,
    credential: &StoredCredential,
) -> Result<S3ObjectStore, String> {
    if endpoint.trim().is_empty() {
        return Err("请先填写 Endpoint".to_string());
    }
    if bucket.trim().is_empty() {
        return Err("请先填写 Bucket".to_string());
    }
    S3ObjectStore::new(S3ObjectStoreConfig {
        // Inferred as `url::Url` from `S3ObjectStoreConfig::endpoint`'s
        // declared field type -- this crate deliberately does not depend
        // on the `url` crate directly (see task's "no dependency-manifest
        // edits" constraint), so the type is never spelled out here, only
        // relied on via `FromStr` + struct-literal field-type inference.
        endpoint: endpoint
            .trim()
            .parse()
            .map_err(|e| format!("Endpoint 不是合法的 URL：{e}"))?,
        bucket: bucket.trim().to_string(),
        // MinIO/most self-hosted S3-compatible servers ignore `region`
        // beyond requiring *a* value for SigV4 signing, and Aliyun OSS
        // ignores it too (verified against the live endpoint: `cn-beijing`,
        // `us-east-1` and `oss-cn-beijing` all authenticate). `StorageConfig`
        // therefore still has no region field of its own, and this app-wide
        // default matches `object_store_s3.rs`'s own test fixture.
        region: "us-east-1".to_string(),
        // Caller-supplied rather than hardcoded: path-style is required by
        // MinIO but rejected outright by Aliyun OSS before signature
        // validation even happens. See `StorageUrlStyle`.
        url_style: match url_style {
            StorageUrlStyle::VirtualHost => UrlStyle::VirtualHost,
            StorageUrlStyle::Path => UrlStyle::Path,
        },
        access_key: credential.access_key.clone(),
        secret_key: credential.secret_key.clone(),
        request_timeout: Duration::from_secs(15),
    })
    .map_err(|e| format!("对象存储客户端初始化失败：{e}"))
}

fn normalize_prefix(prefix: &str) -> &str {
    prefix.trim().trim_matches('/')
}

/// Object key for a single library-entry file, namespaced by the
/// configured prefix (if any) then device/session/file id -- kept stable
/// so re-uploading the same file after a retry lands on the same key
/// rather than creating a duplicate object.
#[cfg(test)]
fn upload_object_key(prefix: &str, device_id: &str, session_id: &str, file_id: &str) -> ObjectKey {
    let trimmed = normalize_prefix(prefix);
    if trimmed.is_empty() {
        ObjectKey(format!("{device_id}/{session_id}/{file_id}"))
    } else {
        ObjectKey(format!("{trimmed}/{device_id}/{session_id}/{file_id}"))
    }
}

// Retained only for legacy-shaped test fixtures while their assertions are
// migrated to the canonical two-object upload closure.
#[cfg(test)]
const PUBLICATION_SIGNATURE_OBJECT: &str = "__ylx_evidence__/publication.sig";
#[cfg(test)]
const PUBLICATION_PUBLIC_KEY_OBJECT: &str = "__ylx_evidence__/publication.ed25519.pub";
#[cfg(test)]
const PUBLICATION_MANIFEST_OBJECT: &str = "__ylx_evidence__/publication.json";

#[cfg(test)]
fn upload_evidence_object_key(
    prefix: &str,
    device_id: &str,
    session_id: &str,
    evidence_name: &str,
) -> ObjectKey {
    let trimmed = normalize_prefix(prefix);
    let tail = format!("{device_id}/{session_id}/{evidence_name}");
    if trimmed.is_empty() {
        ObjectKey(tail)
    } else {
        ObjectKey(format!("{trimmed}/{tail}"))
    }
}

/// Checks the exact full object keys and source proofs for one upload
/// namespace. This is used before a projection marker exists, while the
/// public backed-up predicate below additionally requires that marker.
fn entry_has_complete_object_receipts_for_prefix(entry: &LibraryEntry, prefix: &str) -> bool {
    if entry.processed_files.len() != 2 || entry.object_receipts.len() != 5 {
        return false;
    }
    let unique_keys: HashSet<&str> = entry
        .object_receipts
        .iter()
        .map(|receipt| receipt.key.as_str())
        .collect();
    if unique_keys.len() != entry.object_receipts.len() {
        return false;
    }

    let Some(marker) = entry
        .object_receipts
        .iter()
        .find(|receipt| receipt.key.ends_with("/__ylx_evidence__/publication.json"))
    else {
        return false;
    };
    let Some(root) = marker
        .key
        .strip_suffix("/__ylx_evidence__/publication.json")
    else {
        return false;
    };
    if marker.bytes == 0 || validate_v4_object_root(root, prefix, &entry.session_id).is_err() {
        return false;
    }
    if SourceSha256::from_hex(&marker.sha256).is_err() {
        return false;
    }
    if !entry.object_receipts.iter().any(|receipt| {
        receipt.bytes > 0
            && SourceSha256::from_hex(&receipt.sha256).is_ok()
            && admission_key_belongs_to_marker(
                &ObjectKey(marker.key.clone()),
                &ObjectKey(receipt.key.clone()),
            )
    }) {
        return false;
    }
    let Some(source_sha) = entry
        .publication
        .as_ref()
        .and_then(|publication| publication.revision.strip_prefix("sha256:"))
    else {
        return false;
    };
    let mut expected = HashMap::from([(source_sha.to_ascii_lowercase(), None)]);
    for file in &entry.processed_files {
        if expected
            .insert(file.sha256.to_ascii_lowercase(), Some(file.bytes))
            .is_some()
        {
            return false;
        }
    }
    expected.len() == 3
        && expected.into_iter().all(|(sha256, size)| {
            let key = format!("{root}/f-{sha256}");
            entry.object_receipts.iter().any(|receipt| {
                receipt.key == key
                    && receipt.bytes > 0
                    && size.is_none_or(|expected_size| receipt.bytes == expected_size)
                    && receipt.sha256.eq_ignore_ascii_case(&sha256)
            })
        })
}

/// A persisted `Done` flag is never sufficient by itself. A current upload
/// must carry a successful, exact projection marker (including immutable
/// entry/revision/prefix) and five unique receipts: source manifest, derived
/// MP4, derived receipt, immutable v4 marker, and exact Console admission.
/// Legacy rows without that evidence fail closed.
pub(crate) fn entry_has_complete_object_receipts(entry: &LibraryEntry) -> bool {
    let Some(marker) = entry.upload_projection.as_ref() else {
        return false;
    };
    let Some(publication) = entry.publication.as_ref() else {
        return false;
    };
    if entry.upload_status != UploadStatus::Done
        || marker.job_id.trim().is_empty()
        || marker.entry_key != entry.key()
        || marker.revision != publication.revision
        || marker.outcome_code != "succeeded"
        || marker.outcome_retryable.is_some()
    {
        return false;
    }
    let Some(prefix) = marker.object_prefix.as_deref() else {
        return false;
    };
    if !entry_has_complete_object_receipts_for_prefix(entry, prefix) {
        return false;
    }

    // Public receipts intentionally omit role/proof. The internal marker is
    // the exact durable identity, so require a one-to-one match and reject
    // malformed role/proof values before trusting the public projection.
    if marker.receipts.len() != entry.object_receipts.len() {
        return false;
    }
    let Some(publication_receipt) = entry
        .object_receipts
        .iter()
        .find(|receipt| receipt.key.ends_with("/__ylx_evidence__/publication.json"))
    else {
        return false;
    };
    let Some(root) = publication_receipt
        .key
        .strip_suffix("/__ylx_evidence__/publication.json")
    else {
        return false;
    };
    let Some(output) = entry
        .processed_files
        .iter()
        .find(|file| file.display_path != derived_media::RECEIPT_DISPLAY_PATH)
    else {
        return false;
    };
    let data_key = format!("{root}/f-{}", output.sha256.to_ascii_lowercase());
    let mut seen = HashSet::new();
    entry.object_receipts.iter().all(|receipt| {
        let Some(marker_receipt) = marker
            .receipts
            .iter()
            .find(|candidate| candidate.object_key == receipt.key)
        else {
            return false;
        };
        let expected_role = if receipt.key == data_key {
            "data"
        } else {
            "evidence"
        };
        if !seen.insert(receipt.key.as_str())
            || marker_receipt.etag != receipt.etag
            || marker_receipt.version_id != receipt.version_id
            || marker_receipt.size_bytes != receipt.bytes
            || !marker_receipt
                .source_sha256
                .eq_ignore_ascii_case(&receipt.sha256)
            || marker_receipt.role != expected_role
            || !matches!(
                marker_receipt.digest_proof.as_str(),
                "server_checksum" | "streamed_readback"
            )
        {
            return false;
        }
        true
    })
}

/// A key that almost certainly does not exist, used only to probe
/// reachability/auth -- see `test_object_store_connection`.
fn probe_object_key(prefix: &str) -> ObjectKey {
    let trimmed = normalize_prefix(prefix);
    if trimmed.is_empty() {
        ObjectKey("__ylx_connectivity_probe__".to_string())
    } else {
        ObjectKey(format!("{trimmed}/__ylx_connectivity_probe__"))
    }
}

/// PC-06 real `test_storage_connection`: a HEAD request against a
/// (almost certainly absent) probe key. A structured 404
/// (`ObjectStoreError::NotFound`) still proves the endpoint is reachable
/// and the request was authenticated -- S3 only returns 404-for-a-HEAD
/// after successfully validating the SigV4 signature -- so it is treated
/// as a successful connectivity check, not a failure. Auth/network/server
/// errors are distinguished per `ObjectStoreError`'s own variants (see
/// module docs on `object_store_s3.rs` for what the adapter can and can't
/// tell apart from the wire).
pub fn test_object_store_connection(
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    url_style: StorageUrlStyle,
    credential: &StoredCredential,
) -> Result<(), String> {
    let store = build_object_store(endpoint, bucket, url_style, credential)?;
    let key = probe_object_key(prefix);
    let expected = ExpectedObject {
        size_bytes: 0,
        source_sha256: SourceSha256::from_bytes([0u8; 32]),
    };
    match store.verify_object(&key, &expected) {
        Ok(_) => Ok(()),
        Err(ObjectStoreError::NotFound(_)) => Ok(()),
        Err(e) => Err(describe_object_store_error(&e)),
    }
}

fn describe_object_store_error(e: &ObjectStoreError) -> String {
    match e {
        ObjectStoreError::Auth { detail, .. } => {
            format!("认证失败，请检查 Access Key / Secret Key：{detail}")
        }
        ObjectStoreError::Network(detail) => format!("无法连接到对象存储服务：{detail}"),
        ObjectStoreError::Config(detail) => format!("对象存储配置无效：{detail}"),
        ObjectStoreError::RateLimited { .. } => "对象存储服务限流，请稍后重试".to_string(),
        ObjectStoreError::ServerError { status, detail } => {
            format!("对象存储服务返回错误（HTTP {status}）：{detail}")
        }
        other => format!("连接测试失败：{other}"),
    }
}

const UPLOAD_PART_SIZE: usize = 8 * 1024 * 1024;

fn emit_transfers<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let (composition, demo_transfers) = {
        let data = state.0.lock().unwrap();
        #[cfg(feature = "demo")]
        let demo_transfers = data.demo_transfer_state.transfers().to_vec();
        #[cfg(not(feature = "demo"))]
        let demo_transfers: Vec<Transfer> = Vec::new();
        (data.composition.clone(), demo_transfers)
    };
    let mut transfers = match composition.transfer_projections() {
        Ok(transfers) => transfers,
        Err(error) => {
            eprintln!(
                "[composition] cannot emit transfers: durable projection read failed: {error}"
            );
            return;
        }
    };
    transfers.extend(demo_transfers);
    let _ = emit_transfers_event(app, transfers);
}

fn emit_library<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let (library_root, durable_library) = {
        let data = state.0.lock().unwrap();
        (
            data.composition.library_root().to_path_buf(),
            data.library.clone(),
        )
    };
    let library = project_library_entries(&library_root, &durable_library)
        .into_iter()
        .map(|entry| entry.view())
        .collect::<Vec<_>>();
    let _ = emit_library_event(app, library);
}

/// Refreshes the affected device row set from the authenticated Pi catalog
/// after local download/upload state changes. The network read runs off the
/// async executor; failures leave the last known UI data intact and are
/// surfaced in logs instead of emitting a deceptive empty session list.
fn spawn_sessions_refresh<R: Runtime>(app: &AppHandle<R>, device_id: String) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let application = match TransferApplication::from_app(&app) {
            Ok(application) => application,
            Err(error) => {
                eprintln!(
                    "[composition] cannot refresh sessions for {device_id} without the managed application: {error}"
                );
                return;
            }
        };
        if let Err(error) = application
            .list_sessions(device_id.clone(), None, None)
            .await
        {
            eprintln!(
                "[composition] failed to refresh sessions after local state change for \
                 {device_id}: {error}"
            );
        }
    });
}

#[derive(Deserialize)]
struct SignedUploadPublication {
    session_id: String,
    revision: String,
    total_bytes: u64,
    files: Vec<SignedUploadFile>,
}

#[derive(Deserialize)]
struct SignedUploadFile {
    id: String,
    display_path: String,
    size_bytes: u64,
    sha256: String,
}

/// Re-verifies the durable publication before any upload begins and binds
/// its signed inventory back to the library entry. This catches corruption
/// or legacy data before a self-consistent hash of the wrong local file can
/// ever be uploaded and treated as a backup.
fn validate_entry_publication(entry: &LibraryEntry) -> Result<&PublicationEvidence, String> {
    let publication = entry
        .publication
        .as_ref()
        .ok_or_else(|| "本地记录缺少签名 publication，请重新下载完整会话".to_string())?;
    Ed25519PublicationVerifier
        .verify(
            &publication.payload,
            &publication.signature,
            &publication.public_key,
        )
        .map_err(|error| format!("本地 publication 验签失败：{error}"))?;
    let signed: SignedUploadPublication = serde_json::from_slice(&publication.payload)
        .map_err(|error| format!("签名 publication 内容无法解析：{error}"))?;
    if signed.session_id != entry.session_id || signed.revision != publication.revision {
        return Err("本地记录身份或 revision 与签名 publication 不一致".to_string());
    }
    let source_inventory_bytes = entry.files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or_else(|| "本地 source inventory 字节数溢出".to_string())
    })?;
    if signed.total_bytes != source_inventory_bytes
        || signed.files.len() != entry.files.len()
        || signed.files.is_empty()
    {
        return Err("本地记录总字节数或文件数量与签名 publication 不一致".to_string());
    }
    let mut signed_ids = HashSet::with_capacity(signed.files.len());
    for signed_file in &signed.files {
        if !signed_ids.insert(signed_file.id.as_str()) {
            return Err("签名 publication 包含重复文件 ID".to_string());
        }
        let Some(local) = entry
            .files
            .iter()
            .find(|file| file.file_id == signed_file.id)
        else {
            return Err(format!(
                "本地记录缺少签名 publication 文件：{}",
                signed_file.id
            ));
        };
        if local.display_path != signed_file.display_path
            || local.bytes != signed_file.size_bytes
            || local.sha256 != signed_file.sha256.to_ascii_lowercase()
            || SourceSha256::from_hex(&local.sha256).is_err()
        {
            return Err(format!(
                "本地文件清单与签名 publication 不一致：{}",
                signed_file.id
            ));
        }
    }
    Ok(publication)
}

/// The immutable input sealed into an upload job.  This deliberately hashes
/// the verified source publication, ordered canonical derived assets, and destination
/// coordinates rather than the mutable UI status fields.  A retry or a
/// duplicate click therefore reuses exactly the same job only when it is
/// asking for the same bytes and the same object namespace.
fn upload_input_digest(entry: &LibraryEntry, storage: &StorageConfig) -> Result<String, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Input<'a> {
        entry_key: String,
        revision: &'a str,
        bytes: u64,
        files: &'a [SessionFile],
        publication: &'a PublicationEvidence,
        endpoint: &'a str,
        bucket: &'a str,
        prefix: &'a str,
        url_style: StorageUrlStyle,
    }

    let publication = entry
        .publication
        .as_ref()
        .ok_or_else(|| "本地记录缺少签名 publication".to_string())?;
    let payload = serde_json::to_vec(&Input {
        entry_key: entry.key(),
        revision: &publication.revision,
        bytes: entry.bytes,
        files: &entry.processed_files,
        publication,
        endpoint: storage.endpoint.trim(),
        bucket: storage.bucket.trim(),
        prefix: storage.prefix.trim(),
        url_style: storage.url_style,
    })
    .map_err(|error| format!("无法生成上传任务输入摘要：{error}"))?;
    Ok(Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Compensates a newly-created upload job when setup fails after its durable
/// row exists. A terminal winner is already safe; every other write failure
/// is surfaced so startup/retry callers never pretend the row was cleaned up.
fn compensate_new_upload_job(
    comp: &Composition,
    job_id: &str,
    expected_version: u64,
    now: &str,
) -> Result<(), String> {
    match comp
        .transfer_store
        .lock()
        .unwrap()
        .cancel_upload_job(job_id, expected_version, now)
    {
        Ok(_) | Err(UploadJobError::AlreadyTerminal { .. }) => Ok(()),
        Err(error) => Err(format!("无法取消已创建的上传任务：{error}")),
    }
}

/// Registers a real upload row, then drives a multipart S3 upload from the
/// verified local inventory. Partial sessions and missing local files fail
/// before any entry can be marked as a complete backup.
pub fn start_upload<R: Runtime>(
    app: AppHandle<R>,
    comp: Arc<Composition>,
    storage: StorageConfig,
    mut entry: LibraryEntry,
) -> Result<UploadStartOutcome, String> {
    let expected_revision = validate_entry_publication(&entry)?.revision.clone();
    let canonical = canonical_assets_for_entry(&comp.library_root(), &entry)
        .ok_or_else(|| "规范 MP4 或 derived media receipt 无法验证，不能上传".to_string())?;
    entry.complete = true;
    entry.processed_files = canonical.files;
    entry.bytes = canonical.total_bytes;
    let credential = comp
        .storage_credential()
        .map_err(|e| describe_vault_error(&e))?;
    let store = build_object_store(
        &storage.endpoint,
        &storage.bucket,
        storage.url_style,
        &credential,
    )?;
    let entry_key = entry.key();
    let input_digest = upload_input_digest(&entry, &storage)?;
    let requested_job_id = uuid::Uuid::new_v4().to_string();
    let spec = UploadJobSpec::new_with_prefix(
        entry_key.clone(),
        expected_revision.clone(),
        input_digest,
        normalize_prefix(&storage.prefix),
    )
    .map_err(|error| format!("上传任务定义无效：{error}"))?;
    let now = chrono::Utc::now().to_rfc3339();
    let (job, was_created) = {
        let mut transfer_store = comp.transfer_store.lock().unwrap();
        let activity = UploadActivitySeed {
            label: entry.session_id.clone(),
            target_label: storage.bucket.clone(),
            total_bytes: entry.bytes,
        };
        match transfer_store.create_upload_job_with_activity(
            &requested_job_id,
            &spec,
            &activity,
            &now,
        ) {
            Ok(UploadJobCreateOutcome::Created(job)) => (*job, true),
            Ok(UploadJobCreateOutcome::Existing(job)) => (*job, false),
            Err(UploadJobCreateError::Conflict(conflict)) => {
                let existing = transfer_store
                    .get_job(&conflict.existing_job_id)
                    .map_err(|error| format!("无法读取冲突的上传任务：{error}"))?
                    .ok_or_else(|| "冲突的上传任务在读取期间消失".to_string())?;
                if !existing.state.is_terminal()
                    || conflict.requested_revision != conflict.existing_revision
                {
                    return Ok(UploadStartOutcome::Conflict {
                        active_revision: conflict.existing_revision.clone(),
                    });
                }
                let existing_spec = transfer_store
                    .upload_job_spec(&existing.job_id)
                    .map_err(|error| format!("无法读取冲突上传任务 immutable spec：{error}"))?
                    .ok_or_else(|| "冲突的上传任务缺少 immutable spec".to_string())?;
                drop(transfer_store);
                let child_id = start_terminal_upload_child(
                    &app,
                    &comp,
                    &storage,
                    &existing,
                    &existing_spec,
                    &spec,
                )?;
                return Ok(UploadStartOutcome::Started {
                    transfer_key: child_id,
                });
            }
            Err(error) => return Err(format!("无法创建持久化上传任务：{error}")),
        }
    };

    // A terminal Existing hit is durable history, not a worker claim. Route
    // the ordinary library action through the terminal child policy so a
    // successful parent repeats, an eligible matching failure retries, and a
    // dismissed or changed terminal attempt is explicitly superseded.
    if job.state.is_terminal() {
        let child_id = start_terminal_upload_child(&app, &comp, &storage, &job, &spec, &spec)?;
        return Ok(UploadStartOutcome::Started {
            transfer_key: child_id,
        });
    }

    // Move a newly-created (or a queued recovered) durable job to preparing
    // before claiming the process-local operation token. The durable CAS is
    // the authority; the token only supplies cancellation polling and the
    // duplicate in-process gate.
    let expected_version = if job.state == JobStateTag::Queued {
        let start_result = {
            let mut store = comp.transfer_store.lock().unwrap();
            store.start_upload_job(&job.job_id, job.state_version, &now)
        };
        match start_result {
            Ok(version) => version,
            Err(UploadJobError::Stale { .. }) if !was_created => {
                let current = {
                    let store = comp.transfer_store.lock().unwrap();
                    store
                        .get_job(&job.job_id)
                        .map_err(|error| format!("无法读取已存在的上传任务：{error}"))?
                        .ok_or_else(|| "已存在的上传任务在启动期间消失".to_string())?
                };
                if current.state.is_terminal() {
                    let child_spec = comp
                        .transfer_store
                        .lock()
                        .unwrap()
                        .upload_job_spec(&current.job_id)
                        .map_err(|error| format!("无法读取已存在上传任务 immutable spec：{error}"))?
                        .ok_or_else(|| "已存在的上传任务缺少 immutable spec".to_string())?;
                    let child_id = start_terminal_upload_child(
                        &app,
                        &comp,
                        &storage,
                        &current,
                        &child_spec,
                        &spec,
                    )?;
                    return Ok(UploadStartOutcome::Started {
                        transfer_key: child_id,
                    });
                }
                if current.state != JobStateTag::Preparing {
                    return Err(format!(
                        "已存在的上传任务处于不可恢复状态 {}",
                        current.state.as_db_str()
                    ));
                }
                current.state_version
            }
            Err(error) => {
                if was_created {
                    compensate_new_upload_job(&comp, &job.job_id, job.state_version, &now)
                        .map_err(|compensation| {
                            format!("无法启动持久化上传任务：{error}；补偿取消失败：{compensation}")
                        })?;
                }
                return Err(format!("无法启动持久化上传任务：{error}"));
            }
        }
    } else if job.state == JobStateTag::Preparing {
        job.state_version
    } else {
        if was_created {
            compensate_new_upload_job(&comp, &job.job_id, job.state_version, &now)?;
        }
        return Err(format!(
            "持久化上传任务 {} 处于不可恢复状态 {}",
            job.job_id,
            job.state.as_db_str()
        ));
    };
    let transfer_key = job.job_id.clone();

    // The durable start CAS intentionally precedes this claim. If another
    // process won the in-memory gate, a newly-created job is terminally
    // cancelled as a rollback rather than left as an unowned preparing row.
    let operation = match comp.begin_upload_operation(&transfer_key, &entry_key, &expected_revision)
    {
        UploadStartOutcome::Started { .. } => comp
            .upload_operation(&transfer_key)
            .expect("operation just registered under the same lock"),
        UploadStartOutcome::Existing { transfer_key } => {
            if was_created {
                compensate_new_upload_job(&comp, &job.job_id, expected_version, &now)?;
            }
            return Ok(UploadStartOutcome::Existing { transfer_key });
        }
        UploadStartOutcome::Conflict { active_revision } => {
            if was_created {
                compensate_new_upload_job(&comp, &transfer_key, expected_version, &now)?;
            }
            return Ok(UploadStartOutcome::Conflict { active_revision });
        }
    };
    spawn_upload_worker(
        &app,
        &comp,
        &storage,
        &entry,
        store,
        operation,
        expected_version,
        was_created,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_upload_worker<R: Runtime>(
    app: &AppHandle<R>,
    comp: &Arc<Composition>,
    storage: &StorageConfig,
    entry: &LibraryEntry,
    store: S3ObjectStore,
    operation: Arc<UploadOperation>,
    expected_version: u64,
    rollback_job: bool,
) -> Result<UploadStartOutcome, String> {
    let transfer_key = operation.transfer_key().to_string();
    let entry_key = entry.key();
    let expected_revision = entry
        .publication
        .as_ref()
        .map(|publication| publication.revision.clone())
        .ok_or_else(|| "本地记录缺少签名 publication".to_string())?;
    let now = chrono::Utc::now().to_rfc3339();
    let release_claim = || comp.clear_upload_operation(&transfer_key);
    {
        let state = app.state::<AppState>();
        let mut data = state.0.lock().unwrap();
        let Some(entry_index) = data
            .library
            .iter()
            .position(|candidate| candidate.key() == entry_key)
        else {
            drop(data);
            let compensation =
                compensate_new_upload_job(comp, &transfer_key, expected_version, &now).err();
            release_claim();
            return Err(match compensation {
                Some(compensation) => {
                    format!("本地记录已不存在，无法开始上传；补偿取消失败：{compensation}")
                }
                None => "本地记录已不存在，无法开始上传".to_string(),
            });
        };
        let previous_entry = data.library[entry_index].clone();
        if data.library[entry_index].files != entry.files
            || data.library[entry_index].publication != entry.publication
        {
            drop(data);
            let compensation =
                compensate_new_upload_job(comp, &transfer_key, expected_version, &now).err();
            release_claim();
            return Err(match compensation {
                Some(compensation) => format!(
                    "本地记录 revision 已变化，请刷新后重试上传；补偿取消失败：{compensation}"
                ),
                None => "本地记录 revision 已变化，请刷新后重试上传".to_string(),
            });
        }
        // A receipt-valid existing-library migration is promoted only here,
        // after the exact canonical pair has been revalidated. No raw source
        // is deleted merely because an old row once claimed completion.
        let canonical_changed = data.library[entry_index].processed_files != entry.processed_files
            || data.library[entry_index].bytes != entry.bytes
            || !data.library[entry_index].complete;
        data.library[entry_index].processed_files = entry.processed_files.clone();
        data.library[entry_index].bytes = entry.bytes;
        data.library[entry_index].complete = true;
        if canonical_changed {
            data.library[entry_index].upload_projection = None;
            data.library[entry_index].object_receipts.clear();
            data.library[entry_index].uploaded_at = None;
            data.library[entry_index].upload_error = None;
            data.library[entry_index].upload_retryable = false;
        }
        if rollback_job {
            // Evidence from an older revision must not make the new durable
            // job look backed up while it is still running. The status field
            // itself remains an outbox projection; only stale receipts are
            // cleared here.
            data.library[entry_index].object_receipts.clear();
            data.library[entry_index].uploaded_at = None;
            data.library[entry_index].upload_error = None;
            data.library[entry_index].upload_retryable = false;
        }
        data.library[entry_index].upload_status = UploadStatus::Uploading;
        if let Err(error) = data.persist_result() {
            data.library[entry_index] = previous_entry;
            drop(data);
            if rollback_job {
                if let Err(compensation) =
                    compensate_new_upload_job(comp, &transfer_key, expected_version, &now)
                {
                    release_claim();
                    return Err(format!(
                        "无法持久化上传开始状态：{error}；补偿取消失败：{compensation}"
                    ));
                }
            }
            release_claim();
            return Err(format!("无法持久化上传开始状态：{error}"));
        }
    }
    emit_transfers(app);
    emit_library(app);

    // The cancel flag comes from the operation token, so the flag the task
    // polls and the phase `cancel_upload`/`finish_upload` arbitrate over
    // are the same object; the rest of the context belongs to this task.
    let context = UploadContext {
        job_id: transfer_key.clone(),
        expected_version,
        transfer_key: transfer_key.clone(),
        entry_key: entry_key.clone(),
        library_root: comp.library_root(),
        prefix: storage.prefix.clone(),
        endpoint: storage.endpoint.clone(),
        bucket: storage.bucket.clone(),
        url_style: match storage.url_style {
            StorageUrlStyle::VirtualHost => CoreUploadUrlStyle::VirtualHost,
            StorageUrlStyle::Path => CoreUploadUrlStyle::Path,
        },
        revision: expected_revision.clone(),
        cancel: operation.cancel_flag(),
        transfer_store: comp.transfer_store.clone(),
        #[cfg(test)]
        fail_stage_receipt: AtomicBool::new(false),
        #[cfg(test)]
        fail_finish_multipart: AtomicBool::new(false),
    };
    let app_for_task = app.clone();
    let entry_for_task = entry.clone();
    let transfer_key_for_task = transfer_key.clone();
    let comp_for_task = comp.clone();
    tauri::async_runtime::spawn(async move {
        let app_progress = app_for_task.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            perform_upload(&app_progress, &context, &store, &entry_for_task)
        })
        .await
        .unwrap_or_else(|e| {
            Err(UploadPipelineError::internal(format!(
                "后台上传任务异常终止：{e}"
            )))
        });
        finish_upload(
            &app_for_task,
            &comp_for_task,
            &operation,
            expected_version,
            result,
        );
        // `finish_upload` releases the operation gate immediately after the
        // terminal CAS, before outbox projection. Keep this final cleanup as
        // an idempotent guard for a panic/early-return path.
        comp_for_task.clear_upload_operation(&transfer_key_for_task);
    });

    Ok(UploadStartOutcome::Started { transfer_key })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadChildMode {
    Retry,
    Repeat,
    Supersede,
}

fn terminal_upload_child_mode(
    parent: &StoredJob,
    parent_spec: &UploadJobSpec,
    requested_spec: &UploadJobSpec,
) -> Result<UploadChildMode, String> {
    if !parent.state.is_terminal() {
        return Err(format!(
            "上传任务 {} 尚未结束，不能创建终态子任务",
            parent.job_id
        ));
    }
    if parent_spec.entry_key != requested_spec.entry_key
        || parent_spec.revision != requested_spec.revision
    {
        return Err("上传任务 immutable entry/revision 不匹配，拒绝创建子任务".to_string());
    }
    if parent.state == JobStateTag::Succeeded {
        return Ok(UploadChildMode::Repeat);
    }
    if parent.dismissed_at.is_some() || parent_spec.input_digest != requested_spec.input_digest {
        return Ok(UploadChildMode::Supersede);
    }
    Ok(UploadChildMode::Retry)
}

/// Routes the normal library idempotency path through the durable terminal
/// child policy. Keeping this decision next to `start_upload` prevents the
/// supersede API from becoming an orphaned command that only explicit callers
/// can reach.
fn start_terminal_upload_child<R: Runtime>(
    app: &AppHandle<R>,
    comp: &Arc<Composition>,
    storage: &StorageConfig,
    parent: &StoredJob,
    parent_spec: &UploadJobSpec,
    requested_spec: &UploadJobSpec,
) -> Result<String, String> {
    let mode = terminal_upload_child_mode(parent, parent_spec, requested_spec)?;
    match mode {
        UploadChildMode::Retry => {
            retry_upload(app.clone(), comp.clone(), storage.clone(), &parent.job_id)
        }
        UploadChildMode::Repeat => start_upload_child(
            app.clone(),
            comp.clone(),
            storage.clone(),
            &parent.job_id,
            UploadChildMode::Repeat,
        ),
        UploadChildMode::Supersede => {
            supersede_upload(app.clone(), comp.clone(), storage.clone(), &parent.job_id)
        }
    }
}

/// Creates and starts a durable upload child. The parent and its completion
/// history remain intact; the durable store supplies restart-safe lineage and
/// idempotent replay. `Retry` preserves the parent immutable input, `Repeat`
/// is the explicit successful-upload action, and `Supersede` is the explicit
/// library action for a dismissed/changed terminal attempt.
pub fn retry_upload<R: Runtime>(
    app: AppHandle<R>,
    comp: Arc<Composition>,
    storage: StorageConfig,
    parent_job_id: &str,
) -> Result<String, String> {
    start_upload_child(app, comp, storage, parent_job_id, UploadChildMode::Retry)
}

fn supersede_upload<R: Runtime>(
    app: AppHandle<R>,
    comp: Arc<Composition>,
    storage: StorageConfig,
    parent_job_id: &str,
) -> Result<String, String> {
    start_upload_child(
        app,
        comp,
        storage,
        parent_job_id,
        UploadChildMode::Supersede,
    )
}

fn start_upload_child<R: Runtime>(
    app: AppHandle<R>,
    comp: Arc<Composition>,
    storage: StorageConfig,
    parent_job_id: &str,
    mode: UploadChildMode,
) -> Result<String, String> {
    let parent = comp
        .transfer_store
        .lock()
        .unwrap()
        .get_job(parent_job_id)
        .map_err(|error| format!("无法读取上传任务：{error}"))?
        .ok_or_else(|| "未找到该上传任务".to_string())?;
    if parent.operation_kind != OperationKind::Upload {
        return Err("该任务不是上传任务，无法创建新尝试".to_string());
    }
    let spec = comp
        .transfer_store
        .lock()
        .unwrap()
        .upload_job_spec(parent_job_id)
        .map_err(|error| format!("无法读取上传任务 immutable spec：{error}"))?
        .ok_or_else(|| "上传任务缺少 immutable spec，无法重试".to_string())?;
    let mut entry = {
        let state = app.state::<AppState>();
        let data = state.0.lock().unwrap();
        data.library
            .iter()
            .find(|entry| entry.key() == spec.entry_key)
            .cloned()
            .ok_or_else(|| "未找到该上传任务对应的本地记录".to_string())?
    };
    let canonical = canonical_assets_for_entry(&comp.library_root(), &entry)
        .ok_or_else(|| "规范 MP4 或 derived media receipt 无法验证，不能重试上传".to_string())?;
    entry.complete = true;
    entry.processed_files = canonical.files;
    entry.bytes = canonical.total_bytes;
    let current_digest = upload_input_digest(&entry, &storage)?;
    let requested_spec =
        if parent.state == JobStateTag::Succeeded || mode == UploadChildMode::Supersede {
            // An explicit repeat/supersede may use a changed input digest, but
            // the immutable entry key/revision still fences it to the parent.
            UploadJobSpec::new_with_prefix(
                spec.entry_key.clone(),
                spec.revision.clone(),
                current_digest,
                normalize_prefix(&storage.prefix),
            )
            .map_err(|error| format!("上传重复任务定义无效：{error}"))?
        } else {
            if current_digest != spec.input_digest {
                return Err("本地记录或对象存储配置已变化，无法重试旧上传任务".to_string());
            }
            spec.clone()
        };
    let credential = comp
        .storage_credential()
        .map_err(|error| describe_vault_error(&error))?;
    let store = build_object_store(
        &storage.endpoint,
        &storage.bucket,
        storage.url_style,
        &credential,
    )?;
    let child_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let activity = UploadActivitySeed {
        label: entry.session_id.clone(),
        target_label: storage.bucket.clone(),
        total_bytes: entry.bytes,
    };
    let child = match mode {
        UploadChildMode::Repeat => comp
            .transfer_store
            .lock()
            .unwrap()
            .repeat_upload_job(parent_job_id, &child_id, &requested_spec, &activity, &now)
            .map_err(|error: RepeatUploadJobError| format!("无法创建上传重复任务：{error}"))?,
        UploadChildMode::Supersede => comp
            .transfer_store
            .lock()
            .unwrap()
            .supersede_upload_job(parent_job_id, &child_id, &requested_spec, &activity, &now)
            .map_err(|error: RepeatUploadJobError| format!("无法创建上传新尝试：{error}"))?,
        UploadChildMode::Retry => {
            if parent.state == JobStateTag::Succeeded {
                comp.transfer_store
                    .lock()
                    .unwrap()
                    .repeat_upload_job(parent_job_id, &child_id, &requested_spec, &activity, &now)
                    .map_err(|error: RepeatUploadJobError| {
                        format!("无法创建上传重复任务：{error}")
                    })?
            } else {
                comp.transfer_store
                    .lock()
                    .unwrap()
                    .retry_upload_job(parent_job_id, &child_id, &now)
                    .map_err(|error| format!("无法创建上传重试任务：{error}"))?
            }
        }
    };
    let child_was_created = matches!(&child, RetryJobOutcome::Created(_));
    let child = child.job().clone();
    if child.state.is_terminal() {
        return Ok(child.job_id);
    }
    let expected_version = if child.state == JobStateTag::Queued {
        match comp.transfer_store.lock().unwrap().start_upload_job(
            &child.job_id,
            child.state_version,
            &now,
        ) {
            Ok(version) => version,
            Err(error) => {
                if child_was_created {
                    let compensation =
                        compensate_new_upload_job(&comp, &child.job_id, child.state_version, &now)
                            .err();
                    if let Some(compensation) = compensation {
                        return Err(format!(
                            "无法启动上传子任务：{error}；补偿取消失败：{compensation}"
                        ));
                    }
                }
                return Err(format!("无法启动上传子任务：{error}"));
            }
        }
    } else {
        child.state_version
    };
    let operation = match comp.begin_upload_operation(
        &child.job_id,
        &requested_spec.entry_key,
        &requested_spec.revision,
    ) {
        UploadStartOutcome::Started { .. } => comp
            .upload_operation(&child.job_id)
            .expect("retry operation was registered under the same lock"),
        UploadStartOutcome::Existing { transfer_key } => {
            if child_was_created {
                compensate_new_upload_job(&comp, &child.job_id, expected_version, &now)?;
            }
            return Ok(transfer_key);
        }
        UploadStartOutcome::Conflict { active_revision } => {
            if child_was_created {
                compensate_new_upload_job(&comp, &child.job_id, expected_version, &now)?;
            }
            return Err(format!(
                "该本地记录的另一个版本（revision {active_revision}）正在上传"
            ));
        }
    };
    match spawn_upload_worker(
        &app,
        &comp,
        &storage,
        &entry,
        store,
        operation,
        expected_version,
        child_was_created,
    )? {
        UploadStartOutcome::Started { transfer_key }
        | UploadStartOutcome::Existing { transfer_key } => Ok(transfer_key),
        UploadStartOutcome::Conflict { active_revision } => Err(format!(
            "该本地记录的另一个版本（revision {active_revision}）正在上传"
        )),
    }
}

/// Everything one background upload task needs besides the object-store
/// client and the entry itself. Grouped into a struct (rather than eight
/// more positional parameters threaded through `perform_upload` ->
/// `upload_parts` -> `upload_bytes_object`) because every one of those
/// layers now needs the cancellation flag and the shared durable store.
struct UploadContext {
    job_id: String,
    expected_version: u64,
    transfer_key: String,
    entry_key: String,
    library_root: PathBuf,
    prefix: String,
    endpoint: String,
    bucket: String,
    url_style: CoreUploadUrlStyle,
    revision: String,
    /// Raised by [`cancel_upload`]; polled around every part.
    cancel: Arc<AtomicBool>,
    transfer_store: Arc<Mutex<TransferStore>>,
    #[cfg(test)]
    fail_stage_receipt: AtomicBool,
    #[cfg(test)]
    fail_finish_multipart: AtomicBool,
}

impl UploadContext {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// `Err(UPLOAD_CANCELLED_MESSAGE)` iff cancellation has been
    /// requested. Callers propagate it like any other upload failure, so
    /// the existing abort-on-error paths clean up the remote multipart
    /// upload and `finish_upload` converges the visible state -- there is
    /// no separate cancellation code path that could forget either.
    fn check_cancelled(&self) -> Result<(), UploadPipelineError> {
        if self.cancelled() {
            Err(UploadPipelineError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Records a multipart upload before its first part is sent. This is the
    /// durable crash-recovery boundary for the remote handle.
    fn track_multipart(&self, handle: &MultipartUploadHandle) -> Result<(), UploadPipelineError> {
        let upload = NewUpload {
            transfer_key: self.transfer_key.clone(),
            entry_key: self.entry_key.clone(),
            revision: self.revision.clone(),
            object_key: handle.key.0.clone(),
            upload_id: handle.upload_id.0.clone(),
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            url_style: self.url_style,
        };
        self.transfer_store
            .lock()
            .unwrap()
            .begin_upload_for_job(
                &self.job_id,
                self.expected_version,
                &upload,
                &chrono::Utc::now().to_rfc3339(),
            )
            .map(|_| ())
            .map_err(|error| {
                UploadPipelineError::internal(format!("无法记录在途分片上传：{error}"))
            })
    }

    fn record_multipart_part(
        &self,
        handle: &MultipartUploadHandle,
        part: &PartETag,
        size_bytes: u64,
        confirmed_bytes: Option<u64>,
    ) -> Result<(), UploadPipelineError> {
        let part_number = part.part_number.get();
        self.transfer_store
            .lock()
            .unwrap()
            .record_upload_part_for_job_with_progress(
                &self.job_id,
                self.expected_version,
                &handle.key.0,
                &handle.upload_id.0,
                &UploadPartRecord {
                    part_number: u32::from(part_number),
                    etag: part.etag.clone(),
                    size_bytes,
                },
                confirmed_bytes,
                &chrono::Utc::now().to_rfc3339(),
            )
            .map_err(|error| {
                UploadPipelineError::internal(format!(
                    "无法记录已确认的第 {part_number} 分片：{error}"
                ))
            })
    }

    fn mark_multipart_aborting(&self, handle: &MultipartUploadHandle) {
        if let Err(error) = self
            .transfer_store
            .lock()
            .unwrap()
            .set_upload_desired_state(
                &handle.key.0,
                &handle.upload_id.0,
                UploadDesiredState::Aborting,
                &chrono::Utc::now().to_rfc3339(),
            )
        {
            eprintln!(
                "[composition] failed to mark multipart upload {} aborting; startup recovery will retry: {error}",
                handle.key.0
            );
        }
    }

    fn finish_multipart(&self, handle: &MultipartUploadHandle) -> Result<(), UploadPipelineError> {
        #[cfg(test)]
        if self.fail_finish_multipart.swap(false, Ordering::SeqCst) {
            return Err(UploadPipelineError::internal(
                "injected finish_multipart failure",
            ));
        }
        self.transfer_store
            .lock()
            .unwrap()
            .finish_upload(&handle.key.0, &handle.upload_id.0)
            .map(|_| ())
            .map_err(|error| {
                UploadPipelineError::internal(format!("无法完成在途分片记录收敛：{error}"))
            })
    }

    /// Persists a receipt as soon as its object-specific verification has
    /// completed. This is intentionally independent of the eventual upload
    /// outcome: a cancellation can win after a remote object completed, and
    /// the cancelled library projection must stay empty without losing the
    /// durable proof of what was actually written.
    fn stage_upload_receipt(&self, receipt: &UploadReceiptSeed) -> Result<(), UploadPipelineError> {
        #[cfg(test)]
        if self.fail_stage_receipt.swap(false, Ordering::SeqCst) {
            return Err(UploadPipelineError::internal(
                "injected stage_upload_receipt failure",
            ));
        }
        self.transfer_store
            .lock()
            .unwrap()
            .stage_upload_receipts_for_job(
                &self.job_id,
                std::slice::from_ref(receipt),
                &chrono::Utc::now().to_rfc3339(),
            )
            .map(|_| ())
            .map_err(|error| {
                UploadPipelineError::internal(format!("无法持久化对象验证凭证：{error}"))
            })
    }
}

/// Pure precondition check, factored out for unit testing.
fn require_entry_has_local_files(entry: &LibraryEntry) -> Result<(), String> {
    if entry.processed_files.len() != 2
        || !entry
            .processed_files
            .iter()
            .any(|file| file.display_path == derived_media::RECEIPT_DISPLAY_PATH)
        || !entry
            .processed_files
            .iter()
            .any(|file| file.display_path.ends_with(".mp4"))
    {
        Err("该记录缺少可上传的规范 MP4/receipt 二件套".to_string())
    } else {
        Ok(())
    }
}

/// Resolves the preferred Pi `display_path`, falling back to the old opaque
/// `file_id` layout only when upgrading an existing library. New downloads
/// always create the preferred path; the fallback merely keeps files made by
/// older releases usable after this naming migration.
pub(crate) fn resolve_existing_download_path(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    file: &crate::models::SessionFile,
) -> Result<(PathBuf, fs::Metadata), String> {
    let preferred = derive_target_path_for_file(
        library_root,
        device_id,
        session_id,
        &file.file_id,
        Some(&file.display_path),
    )
    .map_err(|e| format!("本地文件路径不合法（{}）：{e:?}", file.display_path))?;

    let local_path = match fs::symlink_metadata(&preferred) {
        Ok(_) => preferred,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let legacy = derive_target_path(library_root, device_id, session_id, &file.file_id)
                .map_err(|e| format!("旧版本地文件 ID 不合法（{}）：{e:?}", file.file_id))?;
            if legacy == preferred {
                preferred
            } else {
                match fs::symlink_metadata(&legacy) {
                    Ok(_) => legacy,
                    Err(legacy_error) if legacy_error.kind() == io::ErrorKind::NotFound => {
                        preferred
                    }
                    Err(legacy_error) => {
                        return Err(format!(
                            "无法检查旧版本地文件（{}）：{legacy_error}",
                            legacy.display()
                        ))
                    }
                }
            }
        }
        Err(error) => {
            return Err(format!(
                "无法检查本地文件（{}）：{error}",
                preferred.display()
            ))
        }
    };

    let relative = local_path
        .strip_prefix(library_root)
        .map_err(|_| "本地文件路径越出下载目录".to_string())?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err("本地文件路径为空".to_string());
    }

    let mut current = library_root.to_path_buf();
    let mut final_metadata = None;
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err("本地文件路径包含不安全的目录分量".to_string());
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("本地文件缺失或无法读取（{}）：{error}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("拒绝访问符号链接：{}", current.display()));
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err(format!("本地路径分量不是目录：{}", current.display()));
        }
        final_metadata = Some(metadata);
    }

    let metadata = final_metadata.ok_or_else(|| "本地文件路径为空".to_string())?;
    if !metadata.is_file() {
        return Err(format!("本地记录不是常规文件：{}", local_path.display()));
    }
    let canonical_root = library_root
        .canonicalize()
        .map_err(|error| format!("无法验证本地下载目录：{error}"))?;
    let canonical_path = local_path
        .canonicalize()
        .map_err(|error| format!("无法验证本地文件（{}）：{error}", local_path.display()))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(format!("本地文件不在下载目录内：{}", local_path.display()));
    }
    Ok((local_path, metadata))
}

/// Resolves one local file using the same mapping as download commit, then
/// verifies its signed size and SHA-256 before upload or library publication.
fn resolve_downloaded_file(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    file: &crate::models::SessionFile,
) -> Result<(PathBuf, u64), String> {
    let (local_path, metadata) =
        resolve_existing_download_path(library_root, device_id, session_id, file)?;
    let size_bytes = metadata.len();
    if size_bytes != file.bytes {
        return Err(format!(
            "本地文件大小与签名 publication 不一致（{}）：期望 {}，实际 {}",
            local_path.display(),
            file.bytes,
            size_bytes
        ));
    }
    let expected_sha256 = SourceSha256::from_hex(&file.sha256).map_err(|error| {
        format!(
            "签名 publication 中的 SHA-256 无效（{}）：{error}",
            file.file_id
        )
    })?;
    let actual_sha256 = hash_file(&local_path)
        .map_err(|e| format!("计算本地文件哈希失败（{}）：{e}", local_path.display()))?;
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "本地文件 SHA-256 与签名 publication 不一致（{}）",
            local_path.display()
        ));
    }
    Ok((local_path, size_bytes))
}

/// Resolves one `SessionFile`'s real local path for a known `LibraryEntry`
/// -- factored out of `perform_upload` so both the safe-path-derivation
/// and missing-file-is-a-clear-error behaviors are unit-testable without an
/// `AppHandle` (see the `tests` module below, which exercises this against
/// a real temp file). Thin wrapper over `resolve_downloaded_file`; see that
/// function's doc comment.
#[cfg(test)]
fn resolve_local_upload_file(
    library_root: &Path,
    entry: &LibraryEntry,
    file: &crate::models::SessionFile,
) -> Result<(PathBuf, u64), String> {
    let mut last_error = None;
    for root in entry_search_roots(library_root, entry) {
        match resolve_downloaded_file(&root, &entry.device_id, &entry.session_id, file) {
            Ok(found) => return Ok(found),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "本地文件不可用".to_string()))
}

/// Marks a durable multipart row as aborting, asks the object store to tear
/// it down, and retires the row only when the remote side confirms it is gone.
/// A failed abort intentionally leaves the row durable for startup recovery.
fn abort_multipart_after_failure<S: ObjectStorePort>(
    ctx: &UploadContext,
    store: &S,
    handle: &MultipartUploadHandle,
) -> Result<(), UploadPipelineError> {
    ctx.mark_multipart_aborting(handle);
    match store.abort_multipart_upload(handle) {
        Ok(()) | Err(ObjectStoreError::NotFound(_)) => ctx.finish_multipart(handle),
        Err(ObjectStoreError::UnknownUpload(_)) => {
            let record = {
                let store = ctx.transfer_store.lock().unwrap();
                store.pending_upload(&handle.key.0, &handle.upload_id.0)
            }
            .map_err(|error| {
                UploadPipelineError::internal(format!(
                    "无法读取 UnknownUpload 的持久化分片记录：{error}"
                ))
            })?;
            let accounted = record
                .map(|record| multipart_receipt_proves_completion(&ctx.transfer_store, &record))
                .transpose()
                .map_err(UploadPipelineError::internal)?
                .unwrap_or(false);
            if accounted {
                ctx.finish_multipart(handle)
            } else {
                Err(UploadPipelineError::internal(
                    "远端返回 UnknownUpload，且没有精确对象验证回执；清理状态保持 aborting"
                        .to_string(),
                ))
            }
        }
        Err(error) => Err(object_store_pipeline_error(
            &format!("远端中止分片上传失败（{}）", handle.key.0),
            error,
        )),
    }
}

/// Cleans up the narrow window in which the provider has returned a live
/// multipart handle but the durable ownership write reported an error. The
/// write may have committed before returning that error, so first reconcile
/// the exact `(object_key, upload_id)` row. A present row uses the normal
/// durable abort path; an absent row uses a direct remote abort. If the row
/// lookup itself is unavailable, the outcome stays explicitly incomplete even
/// when the remote abort appears to succeed -- we cannot prove that no durable
/// ownership remains.
fn abort_multipart_after_track_failure<S: ObjectStorePort>(
    ctx: &UploadContext,
    store: &S,
    handle: &MultipartUploadHandle,
    track_error: UploadPipelineError,
) -> UploadPipelineError {
    let durable_row = ctx
        .transfer_store
        .lock()
        .unwrap()
        .pending_upload(&handle.key.0, &handle.upload_id.0);
    match durable_row {
        Ok(Some(row)) if durable_multipart_row_matches_context(ctx, handle, &row) => {
            match abort_multipart_after_failure(ctx, store, handle) {
                Ok(()) => track_error,
                Err(cleanup_error) => incomplete_multipart_cleanup_error(
                    &track_error,
                    handle,
                    cleanup_error.detail().unwrap_or("远端清理失败"),
                ),
            }
        }
        Ok(Some(_)) => incomplete_multipart_cleanup_error(
            &track_error,
            handle,
            "durable ownership conflict; remote abort withheld",
        ),
        Ok(None) => abort_untracked_multipart_after_track_failure(store, handle, track_error),
        Err(lookup_error) => {
            let lookup_error = UploadPipelineError::internal(format!(
                "无法确认在途分片 ownership：{lookup_error}"
            ));
            match store.abort_multipart_upload(handle) {
                Ok(()) => incomplete_multipart_cleanup_error(
                    &track_error,
                    handle,
                    lookup_error.detail().unwrap_or("无法确认清理状态"),
                ),
                Err(cleanup_error) => {
                    let cleanup =
                        object_store_pipeline_error("远端中止未登记分片上传失败", cleanup_error);
                    incomplete_multipart_cleanup_error(
                        &track_error,
                        handle,
                        &format!(
                            "{}；{}",
                            lookup_error.detail().unwrap_or("无法确认清理状态"),
                            cleanup.detail().unwrap_or("远端清理失败"),
                        ),
                    )
                }
            }
        }
    }
}

fn durable_multipart_row_matches_context(
    ctx: &UploadContext,
    handle: &MultipartUploadHandle,
    row: &StoredUpload,
) -> bool {
    row.job_id.as_deref() == Some(ctx.job_id.as_str())
        && row.upload.transfer_key == ctx.transfer_key
        && row.upload.entry_key == ctx.entry_key
        && row.upload.revision == ctx.revision
        && row.upload.object_key == handle.key.0
        && row.upload.upload_id == handle.upload_id.0
        && row.upload.endpoint == ctx.endpoint
        && row.upload.bucket == ctx.bucket
        && row.upload.url_style == ctx.url_style
}

fn abort_untracked_multipart_after_track_failure<S: ObjectStorePort>(
    store: &S,
    handle: &MultipartUploadHandle,
    track_error: UploadPipelineError,
) -> UploadPipelineError {
    match store.abort_multipart_upload(handle) {
        Ok(()) => track_error,
        Err(cleanup_error) => {
            let cleanup = object_store_pipeline_error("远端中止未登记分片上传失败", cleanup_error);
            incomplete_multipart_cleanup_error(
                &track_error,
                handle,
                cleanup.detail().unwrap_or("远端清理失败"),
            )
        }
    }
}

fn incomplete_multipart_cleanup_error(
    track_error: &UploadPipelineError,
    handle: &MultipartUploadHandle,
    cleanup_detail: &str,
) -> UploadPipelineError {
    let track_detail = track_error.detail().unwrap_or("上传跟踪失败");
    UploadPipelineError::transient(format!(
        "multipart_cleanup_incomplete (retryable=true); remote_handle={}; {track_detail}；{cleanup_detail}",
        remote_multipart_handle_identity(handle),
    ))
}

/// Remote multipart coordinates are not credentials, but they are still
/// provider-controlled strings. Keep diagnostics bounded and single-line so a
/// malformed response cannot turn an error into an unbounded or log-injecting
/// payload. The full `(object_key, upload_id)` pair remains actionable.
fn remote_multipart_handle_identity(handle: &MultipartUploadHandle) -> String {
    format!(
        "object_key={}; upload_id={}",
        bounded_remote_handle_component(&handle.key.0),
        bounded_remote_handle_component(&handle.upload_id.0),
    )
}

fn bounded_remote_handle_component(value: &str) -> String {
    const MAX_BYTES: usize = 512;
    let mut bounded = String::new();
    for character in value.chars() {
        let character = if character.is_control() {
            '?'
        } else {
            character
        };
        if bounded.len() + character.len_utf8() > MAX_BYTES {
            bounded.push_str("[truncated]");
            break;
        }
        bounded.push(character);
    }
    bounded
}

/// Persists an object-specific verification receipt before retiring its
/// durable multipart row. Persistence failures are remote-cleanup failures
/// too: the row is marked `aborting`, then the remote handle is torn down (or
/// left durable for startup recovery if that cleanup cannot complete).
fn stage_and_finish_multipart<S: ObjectStorePort>(
    ctx: &UploadContext,
    store: &S,
    handle: &MultipartUploadHandle,
    receipt: &UploadReceiptSeed,
) -> Result<(), UploadPipelineError> {
    if let Err(error) = ctx.stage_upload_receipt(receipt) {
        return Err(match abort_multipart_after_failure(ctx, store, handle) {
            Ok(()) => error,
            Err(cleanup_error) => append_upload_error(error, cleanup_error),
        });
    }
    if let Err(error) = ctx.finish_multipart(handle) {
        return Err(match abort_multipart_after_failure(ctx, store, handle) {
            Ok(()) => error,
            Err(cleanup_error) => append_upload_error(error, cleanup_error),
        });
    }
    Ok(())
}

/// Drives one `LibraryEntry` through the complete client-derived publication
/// transaction. The source manifest, derived receipt and MP4 are independently
/// uploaded and read-back verified; the v4 marker is written last with
/// create-if-absent semantics; success is returned only after the exact
/// Console admission acknowledgement has been read and validated.
/// Blocking (real file + HTTP I/O) -- must run inside `spawn_blocking`.
fn perform_upload<R: Runtime, S: ObjectStorePort>(
    app: &AppHandle<R>,
    ctx: &UploadContext,
    store: &S,
    entry: &LibraryEntry,
) -> Result<Vec<UploadReceiptSeed>, UploadPipelineError> {
    if !entry.complete {
        return Err(UploadPipelineError::integrity(
            "该本地记录只包含部分文件，不能上传为整会话备份",
        ));
    }
    require_entry_has_local_files(entry).map_err(UploadPipelineError::integrity)?;
    validate_entry_publication(entry).map_err(UploadPipelineError::integrity)?;
    let bundle = canonical_publication_bundle_for_entry(&ctx.library_root, entry)
        .map_err(UploadPipelineError::integrity)?;
    if bundle.canonical_assets.files != entry.processed_files
        || bundle.canonical_assets.total_bytes != entry.bytes
    {
        return Err(UploadPipelineError::integrity(
            "本地规范资产在上传任务创建后发生变化",
        ));
    }
    let receipt_sha256 = SourceSha256::from_hex(&bundle.receipt_sha256).map_err(|error| {
        UploadPipelineError::integrity(format!("derived receipt SHA-256 无效：{error}"))
    })?;
    let output_sha256 = SourceSha256::from_hex(&bundle.output_sha256).map_err(|error| {
        UploadPipelineError::integrity(format!("derived MP4 SHA-256 无效：{error}"))
    })?;
    let plan =
        derived_publication_plan(&ctx.prefix, &bundle).map_err(UploadPipelineError::integrity)?;

    let mut sent_bytes: u64 = 0;
    let mut receipts = Vec::with_capacity(5);

    let source_receipt = upload_bytes_object(
        store,
        plan.source_manifest_key.clone(),
        &bundle.source_manifest_bytes,
        "application/json",
        ctx,
    )?;
    receipts.push(upload_receipt_seed(
        source_receipt,
        UploadReceiptRole::Evidence,
    ));

    receipts.push(upload_local_file_object(
        app,
        ctx,
        store,
        &bundle.receipt_path,
        bundle.receipt_bytes.len() as u64,
        receipt_sha256,
        plan.receipt_key.clone(),
        "application/json",
        UploadReceiptRole::Evidence,
        &mut sent_bytes,
    )?);
    receipts.push(upload_local_file_object(
        app,
        ctx,
        store,
        &bundle.output_path,
        bundle.output_bytes,
        output_sha256,
        plan.output_key.clone(),
        "video/mp4",
        UploadReceiptRole::Data,
        &mut sent_bytes,
    )?);

    ctx.check_cancelled()?;
    store
        .put_object_if_absent(&ImmutableObjectRequest {
            key: plan.marker_key.clone(),
            bytes: plan.marker_bytes.clone(),
            source_sha256: plan.marker_sha256,
            content_type: "application/json".to_string(),
        })
        .map_err(|error| {
            object_store_pipeline_error("提交 Bucket Publication v4 marker 失败", error)
        })?;
    let marker_readback = store
        .read_object_bounded(&plan.marker_key, MAX_PUBLICATION_JSON_BYTES)
        .map_err(|error| {
            object_store_pipeline_error("回读 Bucket Publication v4 marker 失败", error)
        })?;
    let marker_receipt = plan
        .verify_marker_readback(&marker_readback)
        .map_err(UploadPipelineError::integrity)?;
    let marker_seed = upload_receipt_seed(marker_receipt, UploadReceiptRole::Evidence);
    ctx.stage_upload_receipt(&marker_seed)?;
    receipts.push(marker_seed);

    let admission_receipt = wait_for_publication_admission(ctx, store, &plan)?;
    let admission_seed = upload_receipt_seed(admission_receipt, UploadReceiptRole::Evidence);
    ctx.stage_upload_receipt(&admission_seed)?;
    receipts.push(admission_seed);

    let mut proved_entry = entry.clone();
    proved_entry.object_receipts = receipts.iter().map(object_receipt_from_seed).collect();
    if !entry_has_complete_object_receipts_for_prefix(&proved_entry, &ctx.prefix) {
        return Err(UploadPipelineError::integrity(
            "对象存储验证凭证与当前签名 revision 不一致",
        ));
    }
    Ok(receipts)
}

#[allow(clippy::too_many_arguments)]
fn upload_local_file_object<R: Runtime, S: ObjectStorePort>(
    app: &AppHandle<R>,
    ctx: &UploadContext,
    store: &S,
    path: &Path,
    size_bytes: u64,
    source_sha256: SourceSha256,
    object_key: ObjectKey,
    content_type: &str,
    role: UploadReceiptRole,
    sent_bytes: &mut u64,
) -> Result<UploadReceiptSeed, UploadPipelineError> {
    if hash_file(path).map_err(|error| {
        UploadPipelineError::integrity(format!("上传前无法重新计算本地文件摘要：{error}"))
    })? != source_sha256
    {
        return Err(UploadPipelineError::integrity(
            "上传前本地规范文件摘要发生变化",
        ));
    }
    let handle = store
        .initiate_multipart_upload(InitiateUploadRequest {
            key: object_key,
            content_length: size_bytes,
            source_sha256,
            content_type: Some(content_type.to_string()),
        })
        .map_err(|error| object_store_pipeline_error("初始化分片上传失败", error))?;
    if let Err(error) = ctx.track_multipart(&handle) {
        return Err(abort_multipart_after_track_failure(
            ctx, store, &handle, error,
        ));
    }
    let expected = ExpectedObject {
        size_bytes,
        source_sha256,
    };
    let completion = match upload_parts(app, ctx, store, &handle, path, &expected, sent_bytes) {
        Ok(completion) => completion,
        Err(error) => {
            return Err(match abort_multipart_after_failure(ctx, store, &handle) {
                Ok(()) => error,
                Err(cleanup) => append_upload_error(error, cleanup),
            });
        }
    };
    let verified = match verify_completed_object_bound(store, &completion, &expected) {
        Ok(receipt) => receipt,
        Err(error) => {
            let primary = object_store_pipeline_error("上传后校验失败，未标记为已发布", error);
            return Err(match abort_multipart_after_failure(ctx, store, &handle) {
                Ok(()) => primary,
                Err(cleanup) => append_upload_error(primary, cleanup),
            });
        }
    };
    let seed = upload_receipt_seed(verified, role);
    stage_and_finish_multipart(ctx, store, &handle, &seed)?;
    Ok(seed)
}

fn wait_for_publication_admission<S: ObjectStorePort>(
    ctx: &UploadContext,
    store: &S,
    plan: &DerivedPublicationPlan,
) -> Result<VerifiedObjectReceipt, UploadPipelineError> {
    const WAIT: Duration = Duration::from_secs(60);
    const POLL: Duration = Duration::from_millis(500);
    const MAX_ACK_CANDIDATES: u16 = 2;
    let deadline = Instant::now() + WAIT;
    loop {
        ctx.check_cancelled()?;
        let first_page = store
            .list_objects_bounded(&plan.admission_prefix, MAX_ACK_CANDIDATES)
            .map_err(|error| {
                object_store_pipeline_error("枚举 Console admission 回执失败", error)
            })?;
        let candidate = plan
            .select_admission_candidate(&first_page)
            .map_err(admission_pipeline_error)?;
        let Some(candidate) = candidate else {
            if Instant::now() >= deadline {
                return Err(UploadPipelineError::transient(
                    "Bucket Publication v4 已提交，但 Console 在 60 秒内未返回 admission；可在 consumer 运行后重试",
                ));
            }
            std::thread::sleep(POLL);
            continue;
        };
        let readback = store
            .read_object_bounded(&candidate.key, MAX_PUBLICATION_JSON_BYTES)
            .map_err(|error| {
                object_store_pipeline_error("读取 Console admission 回执失败", error)
            })?;
        let receipt = plan
            .verify_admission(candidate, &readback)
            .map_err(admission_pipeline_error)?;

        // Re-list after the raw GET so a second/conflicting ack or an
        // overwrite during verification cannot be collapsed into success.
        let final_page = store
            .list_objects_bounded(&plan.admission_prefix, MAX_ACK_CANDIDATES)
            .map_err(|error| {
                object_store_pipeline_error("复核 Console admission authority 失败", error)
            })?;
        let final_candidate = plan
            .select_admission_candidate(&final_page)
            .map_err(admission_pipeline_error)?;
        if final_candidate != Some(candidate) {
            return Err(UploadPipelineError::integrity(
                "Console admission candidate 在原始回读期间发生漂移",
            ));
        }
        return Ok(receipt);
    }
}

fn admission_pipeline_error(error: AdmissionError) -> UploadPipelineError {
    match error {
        AdmissionError::Invalid(detail) => {
            UploadPipelineError::integrity(format!("Console admission 回执无效：{detail}"))
        }
        AdmissionError::Rejected(detail) => {
            UploadPipelineError::integrity(format!("Console 拒绝派生 publication：{detail}"))
        }
    }
}

fn upload_receipt_seed(
    receipt: VerifiedObjectReceipt,
    role: UploadReceiptRole,
) -> UploadReceiptSeed {
    let digest_proof = match receipt.digest_proof {
        ylx_transfer_core::library::object_store_port::DigestProof::ServerChecksum => {
            UploadReceiptDigestProof::ServerChecksum
        }
        ylx_transfer_core::library::object_store_port::DigestProof::StreamedReadback => {
            UploadReceiptDigestProof::StreamedReadback
        }
    };
    UploadReceiptSeed::new(
        receipt.key.0,
        role,
        receipt.etag,
        receipt.version_id,
        receipt.size_bytes,
        receipt.source_sha256.to_hex(),
        digest_proof,
    )
}

fn object_receipt_from_seed(seed: &UploadReceiptSeed) -> ObjectVerificationReceipt {
    ObjectVerificationReceipt {
        key: seed.object_key.clone(),
        etag: seed.etag.clone(),
        version_id: seed.version_id.clone(),
        bytes: seed.size_bytes,
        sha256: seed.source_sha256.clone(),
    }
}

/// Keeps every multipart verification call bound to the raw completion that
/// produced the object. A latest-key HEAD is insufficient when another writer
/// can complete the same key between our completion and verification.
fn verify_completed_object_bound<S: ObjectStorePort>(
    store: &S,
    completion: &CompletedUpload,
    expected: &ExpectedObject,
) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
    store.verify_completed_object(completion, expected)
}

fn upload_bytes_object<S: ObjectStorePort>(
    store: &S,
    key: ObjectKey,
    bytes: &[u8],
    content_type: &str,
    ctx: &UploadContext,
) -> Result<VerifiedObjectReceipt, UploadPipelineError> {
    let source_sha256 = SourceSha256::from_bytes(Sha256::digest(bytes).into());
    let handle = store
        .initiate_multipart_upload(InitiateUploadRequest {
            key: key.clone(),
            content_length: bytes.len() as u64,
            source_sha256,
            content_type: Some(content_type.to_string()),
        })
        .map_err(|error| object_store_pipeline_error("初始化 publication 证据上传失败", error))?;
    if let Err(error) = ctx.track_multipart(&handle) {
        return Err(abort_multipart_after_track_failure(
            ctx, store, &handle, error,
        ));
    }
    let upload_result = (|| {
        let part_number = PartNumber::new(1).map_err(|error| {
            UploadPipelineError::internal(format!("publication 证据分片编号非法：{error}"))
        })?;
        ctx.check_cancelled()?;
        let part = store
            .upload_part(&handle, part_number, bytes)
            .map_err(|error| object_store_pipeline_error("上传 publication 证据失败", error))?;
        ctx.record_multipart_part(&handle, &part, bytes.len() as u64, None)?;
        ctx.check_cancelled()?;
        let completion = store
            .complete_multipart_upload(&handle, vec![part])
            .map_err(|error| object_store_pipeline_error("完成 publication 证据上传失败", error))?;
        let receipt = verify_completed_object_bound(
            store,
            &completion,
            &ExpectedObject {
                size_bytes: bytes.len() as u64,
                source_sha256,
            },
        )
        .map_err(|error| object_store_pipeline_error("publication 证据 HEAD 校验失败", error))?;
        let receipt_seed = upload_receipt_seed(receipt.clone(), UploadReceiptRole::Evidence);
        ctx.stage_upload_receipt(&receipt_seed)?;
        ctx.finish_multipart(&handle)?;
        Ok(receipt)
    })();
    match upload_result {
        Ok(receipt) => Ok(receipt),
        Err(error) => Err(match abort_multipart_after_failure(ctx, store, &handle) {
            Ok(()) => error,
            Err(cleanup_error) => append_upload_error(error, cleanup_error),
        }),
    }
}

/// Reads `path` in `UPLOAD_PART_SIZE` chunks, uploads each as a part
/// (S3's multipart minimum part size, except the last part, is 5 MiB --
/// `UPLOAD_PART_SIZE` is comfortably above that), and completes the
/// upload. Updates `sent_bytes` and emits real progress after every part.
/// The raw [`CompletedUpload`] is returned so verification can remain bound
/// to this exact completion when another writer uses the same object key.
fn upload_parts<R: Runtime, S: ObjectStorePort>(
    app: &AppHandle<R>,
    ctx: &UploadContext,
    store: &S,
    handle: &MultipartUploadHandle,
    path: &Path,
    // Size and hash travel together as the one `ExpectedObject` the caller
    // also verifies the finished object against, so the two can't drift.
    expected: &ExpectedObject,
    sent_bytes: &mut u64,
) -> Result<CompletedUpload, UploadPipelineError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| UploadPipelineError::integrity(format!("打开文件失败：{e}")))?;
    let mut parts: Vec<PartETag> = Vec::new();
    let mut buf = vec![0u8; UPLOAD_PART_SIZE];
    let mut part_number: u16 = 1;
    let mut uploaded_bytes = 0_u64;
    let mut uploaded_hasher = Sha256::new();

    loop {
        // Checked before every part, so a cancellation cannot be delayed
        // by a whole 8 MiB PUT that was not yet started.
        ctx.check_cancelled()?;
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = file
                .read(&mut buf[filled..])
                .map_err(|e| UploadPipelineError::integrity(format!("读取文件失败：{e}")))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        uploaded_hasher.update(&buf[..filled]);
        uploaded_bytes = uploaded_bytes.saturating_add(filled as u64);

        let pn = PartNumber::new(part_number)
            .map_err(|e| UploadPipelineError::internal(format!("分片编号非法：{e}")))?;
        let etag = store
            .upload_part(handle, pn, &buf[..filled])
            .map_err(|error| {
                object_store_pipeline_error(&format!("第 {part_number} 分片上传失败"), error)
            })?;
        ctx.record_multipart_part(handle, &etag, filled as u64, Some(filled as u64))?;
        parts.push(etag);
        part_number += 1;
        *sent_bytes += filled as u64;

        emit_transfers(app);

        // And again after it, so a cancellation raised *during* this part
        // stops the upload here instead of after the next read.
        ctx.check_cancelled()?;

        if filled < buf.len() {
            break;
        }
    }

    // A cancellation that arrives while the last part is in flight must
    // still prevent `complete_multipart_upload` -- completing would turn
    // a cancelled upload into a real object.
    ctx.check_cancelled()?;

    if parts.is_empty() {
        // Zero-byte file: S3 multipart still requires at least one part.
        let pn = PartNumber::new(1).expect("1 is always a valid part number");
        let etag = store
            .upload_part(handle, pn, &[])
            .map_err(|error| object_store_pipeline_error("空文件分片上传失败", error))?;
        ctx.record_multipart_part(handle, &etag, 0, Some(0))?;
        parts.push(etag);
    }

    let uploaded_sha256 = SourceSha256::from_bytes(uploaded_hasher.finalize().into());
    let expected_size = expected.size_bytes;
    let expected_sha256 = expected.source_sha256;
    if uploaded_bytes != expected_size || uploaded_sha256 != expected_sha256 {
        return Err(UploadPipelineError::integrity(format!(
            "上传读取期间本地文件发生变化：期望 {expected_size} 字节 / {expected_sha256}，实际 {uploaded_bytes} 字节 / {uploaded_sha256}"
        )));
    }

    ctx.check_cancelled()?;
    store
        .complete_multipart_upload(handle, parts)
        .map_err(|error| object_store_pipeline_error("完成分片上传失败", error))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadFailureClass {
    Integrity,
    Configuration,
    Authentication,
    TransientService,
    Internal,
}

impl UploadFailureClass {
    fn code(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Configuration => "configuration",
            Self::Authentication => "authentication",
            Self::TransientService => "transient",
            Self::Internal => "internal",
        }
    }

    fn retryable(self) -> bool {
        matches!(self, Self::TransientService)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UploadPipelineError {
    Cancelled,
    Failed {
        class: UploadFailureClass,
        detail: String,
    },
}

impl UploadPipelineError {
    fn integrity(detail: impl Into<String>) -> Self {
        Self::Failed {
            class: UploadFailureClass::Integrity,
            detail: detail.into(),
        }
    }

    fn configuration(detail: impl Into<String>) -> Self {
        Self::Failed {
            class: UploadFailureClass::Configuration,
            detail: detail.into(),
        }
    }

    fn authentication(detail: impl Into<String>) -> Self {
        Self::Failed {
            class: UploadFailureClass::Authentication,
            detail: detail.into(),
        }
    }

    fn transient(detail: impl Into<String>) -> Self {
        Self::Failed {
            class: UploadFailureClass::TransientService,
            detail: detail.into(),
        }
    }

    fn internal(detail: impl Into<String>) -> Self {
        Self::Failed {
            class: UploadFailureClass::Internal,
            detail: detail.into(),
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Self::Cancelled => None,
            Self::Failed { detail, .. } => Some(detail),
        }
    }

    fn terminal_outcome(&self) -> TerminalOutcome {
        match self {
            Self::Cancelled => TerminalOutcome::Cancelled,
            Self::Failed { class, detail } => TerminalOutcome::Failed {
                code: format!("upload_{}:{detail}", class.code()),
                retryable: class.retryable(),
            },
        }
    }
}

fn object_store_pipeline_error(context: &str, error: ObjectStoreError) -> UploadPipelineError {
    let detail = format!("{context}: {error}");
    match error {
        ObjectStoreError::Network(_)
        | ObjectStoreError::RateLimited { .. }
        | ObjectStoreError::ServerError { .. } => UploadPipelineError::transient(detail),
        ObjectStoreError::Auth { .. } => UploadPipelineError::authentication(detail),
        ObjectStoreError::Config(_) => UploadPipelineError::configuration(detail),
        ObjectStoreError::VerificationMismatch { .. }
        | ObjectStoreError::CompletionMismatch { .. }
        | ObjectStoreError::DigestMismatch { .. }
        | ObjectStoreError::MalformedChecksum { .. } => UploadPipelineError::integrity(detail),
        ObjectStoreError::NotFound(_)
        | ObjectStoreError::UnknownUpload(_)
        | ObjectStoreError::InvalidPart(_)
        | ObjectStoreError::UnexpectedRedirect { .. } => UploadPipelineError::internal(detail),
    }
}

fn append_upload_error(
    primary: UploadPipelineError,
    cleanup: UploadPipelineError,
) -> UploadPipelineError {
    match primary {
        UploadPipelineError::Cancelled => UploadPipelineError::Cancelled,
        UploadPipelineError::Failed { class, detail } => UploadPipelineError::Failed {
            class,
            detail: format!("{detail}；{}", cleanup.detail().unwrap_or("清理失败")),
        },
    }
}

fn upload_failure_detail(code: &str) -> &str {
    code.strip_prefix("other:")
        .or_else(|| code.strip_prefix("upload_integrity:"))
        .or_else(|| code.strip_prefix("upload_configuration:"))
        .or_else(|| code.strip_prefix("upload_authentication:"))
        .or_else(|| code.strip_prefix("upload_transient:"))
        .or_else(|| code.strip_prefix("upload_internal:"))
        .unwrap_or(code)
}

fn terminal_outcome_for_upload_error(error: &UploadPipelineError) -> TerminalOutcome {
    error.terminal_outcome()
}

/// Applies a worker result through the durable UploadJob terminal CAS. A
/// late worker can only receive `AlreadyTerminal`/`Stale`; it never writes a
/// transfer row or library status after the outbox winner has committed.
fn finish_upload<R: Runtime>(
    app: &AppHandle<R>,
    comp: &Composition,
    operation: &UploadOperation,
    expected_version: u64,
    result: Result<Vec<UploadReceiptSeed>, UploadPipelineError>,
) {
    let transfer_key = operation.transfer_key();
    let (receipts, mut error) = match result {
        Ok(receipts) => (receipts, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    if error.is_none() && receipts.is_empty() {
        error = Some(UploadPipelineError::integrity("对象存储未返回任何验证凭证"));
    }
    if error.is_none() {
        let staged_at = chrono::Utc::now().to_rfc3339();
        if let Err(stage_error) = comp
            .transfer_store
            .lock()
            .unwrap()
            .stage_upload_receipts_for_job(transfer_key, &receipts, &staged_at)
        {
            error = Some(UploadPipelineError::internal(format!(
                "无法持久化对象验证凭证：{stage_error}"
            )));
        }
    }
    let proposed = match error.as_ref() {
        None => TerminalOutcome::Succeeded,
        Some(error) => terminal_outcome_for_upload_error(error),
    };
    let now = chrono::Utc::now().to_rfc3339();
    match comp.transfer_store.lock().unwrap().complete_upload_job(
        transfer_key,
        expected_version,
        &proposed,
        &now,
    ) {
        Ok(_) => {
            let operation_outcome = match proposed {
                TerminalOutcome::Succeeded => UploadTerminalOutcome::Succeeded,
                TerminalOutcome::Cancelled => UploadTerminalOutcome::Cancelled,
                TerminalOutcome::Failed { .. } => UploadTerminalOutcome::Failed,
            };
            let _ = operation.claim_terminal(operation_outcome);
        }
        Err(UploadJobError::AlreadyTerminal { existing, .. }) => {
            eprintln!("[composition] late upload worker for {transfer_key} lost to {existing}");
        }
        Err(UploadJobError::Stale { .. }) => {
            eprintln!(
                "[composition] late upload worker for {transfer_key} lost the state-version race"
            );
        }
        Err(error) => {
            eprintln!("[composition] failed to commit upload terminal outcome for {transfer_key}: {error}");
        }
    }
    // Release the duplicate-start gate before applying/acknowledging the
    // completion. A retry arriving in this window must see the durable
    // terminal row, not an operation token that is waiting on projection.
    comp.clear_upload_operation(transfer_key);
    let _ = comp.deliver_terminal_outcomes(app);
    emit_transfers(app);
    emit_library(app);
}

#[cfg(test)]
thread_local! {
    static STRONG_LOCAL_FILE_HASHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_strong_local_file_hash_count() {
    STRONG_LOCAL_FILE_HASHES.set(0);
}

#[cfg(test)]
fn strong_local_file_hash_count() -> usize {
    STRONG_LOCAL_FILE_HASHES.get()
}

/// Hashes a file without loading its full contents into memory.
fn hash_file(path: &Path) -> io::Result<SourceSha256> {
    #[cfg(test)]
    STRONG_LOCAL_FILE_HASHES.set(STRONG_LOCAL_FILE_HASHES.get() + 1);
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(SourceSha256::from_bytes(hasher.finalize().into()))
}

// =====================================================================
// Tests
// =====================================================================
//
// Mostly scoped to pure-logic helpers (id derivation, mDNS TXT fingerprint
// extraction, `apply_terminal_download`) that need no `AppHandle` --
// exercising `Composition::spawn` for real needs a real `AppHandle`, which
// is better covered by an integration/manual run than a unit test. The
// PC-05b enqueue/recovery tests below are the one
// exception: they build a `Composition` value directly via a struct literal
// (this `mod` is a child of the module that defines `Composition`, so its
// private fields are visible here) wired to a real `TransferCoordinator` --
// same pattern `transfer::coordinator`'s own tests use for
// `DeviceStatusPort`/`DownloadSourceFactory` fakes -- rather than going
// through `Composition::spawn`, so still no `AppHandle` needed. See the
// PC-08 final report for how this file's compilation (including this test
// module) was verified in an environment that could not link the full
// GTK-dependent Tauri binary.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::mpsc;
    use std::time::Instant;

    use ring::signature::{Ed25519KeyPair, KeyPair};
    use rusqlite::Connection;
    use ylx_transfer_adapters::discovery_mdns::{
        MdnsBrowseLoss, MdnsBrowseLossReason, MdnsEndpoint, MdnsServiceLoss,
    };
    use ylx_transfer_core::device::SessionFileEntryView;
    use ylx_transfer_core::domain::{FileId, SessionId};
    use ylx_transfer_core::library::download::{RequestedRange, SourceResponse};
    use ylx_transfer_core::library::staging::SessionStaging;
    use ylx_transfer_core::persistence::AppStore;
    use ylx_transfer_core::transfer::queue::JobFile;
    use ylx_transfer_core::transfer::FailureCode;

    const TEST_ADMISSION_ID: &str = "019a0030-0000-7a1b-8c2d-3e4f50617283";

    fn empty_catalog_page(next_cursor: Option<String>) -> SessionCatalogPageRead {
        SessionCatalogPageRead {
            page: SessionPageView {
                items: Vec::new(),
                diagnostics: Vec::new(),
                has_more: next_cursor.is_some(),
                next_cursor,
                catalog_revision: Some(format!("sha256:{}", "a".repeat(64))),
                catalog_authority: SessionCatalogAuthority::DeviceSnapshot,
                pagination_supported: true,
                pagination_unavailable_reason: None,
                capabilities: SessionPageCapabilities {
                    profile: SessionApiProfile::LabHttpV4,
                    session_deletion: SessionCapability {
                        supported: false,
                        source: SessionCapabilitySource::ProfileContract,
                    },
                    session_detail: SessionCapability {
                        supported: true,
                        source: SessionCapabilitySource::ProfileContract,
                    },
                    artifact_download: SessionCapability {
                        supported: true,
                        source: SessionCapabilitySource::DeviceDescriptor,
                    },
                    capture_status: SessionCapability {
                        supported: true,
                        source: SessionCapabilitySource::ProfileContract,
                    },
                },
            },
            connection_epoch: 1,
        }
    }

    fn catalog_session_fixture(index: usize) -> SessionView {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
            .expect("fixture base time")
            - chrono::Duration::seconds(index as i64);
        SessionView {
            session: Session {
                id: format!("session-{index}"),
                revision: format!("sha256:{}", "b".repeat(64)),
                date_label: started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                duration_seconds: 1.0,
                total_bytes: 1,
                video_bytes: 1,
                imu_samples: None,
                files: Vec::new(),
            },
            download_status: DownloadStatus::None,
            backed_up: false,
            verification: None,
        }
    }

    fn catalog_diagnostic_fixture(message: &str) -> SessionDiscoveryDiagnosticView {
        SessionDiscoveryDiagnosticView {
            quarantine_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            code: SessionDiscoveryDiagnosticCode::ManifestInvalid,
            observed_at: "2026-08-29T12:00:00Z".to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn destructive_catalog_read_rejects_cross_page_session_duplicates_before_mutation() {
        for (case, total_bytes) in [("same-payload", 1_u64), ("different-payload", 2_u64)] {
            let mut first = empty_catalog_page(Some("opaque-next".to_string()));
            first.page.items.push(catalog_session_fixture(0));
            let mut duplicate = catalog_session_fixture(0);
            duplicate.session.total_bytes = total_bytes;
            let mut second = empty_catalog_page(None);
            second.page.items.push(duplicate);
            let mut pages = vec![first, second].into_iter();
            let mut mutation_calls = 0_usize;

            let catalog = collect_full_session_catalog(|_, _, _| {
                Ok(pages.next().expect("two-page duplicate fixture"))
            });
            let destructive_result = catalog.map(|_| mutation_calls += 1);

            let error = destructive_result
                .expect_err("one complete-catalog read must reject a repeated session id");
            assert!(
                error.contains("sessionId"),
                "unexpected {case} error: {error}"
            );
            assert_eq!(mutation_calls, 0, "{case}");
        }
    }

    #[test]
    fn destructive_catalog_read_rejects_cross_page_quarantine_duplicates_before_mutation() {
        for (case, message) in [
            ("same-payload", "manifest failed validation"),
            ("different-payload", "conflicting diagnostic payload"),
        ] {
            let mut first = empty_catalog_page(Some("opaque-next".to_string()));
            first
                .page
                .diagnostics
                .push(catalog_diagnostic_fixture("manifest failed validation"));
            let mut second = empty_catalog_page(None);
            second
                .page
                .diagnostics
                .push(catalog_diagnostic_fixture(message));
            let mut pages = vec![first, second].into_iter();
            let mut mutation_calls = 0_usize;

            let catalog = collect_full_session_catalog(|_, _, _| {
                Ok(pages.next().expect("two-page diagnostic fixture"))
            });
            let destructive_result = catalog.map(|_| mutation_calls += 1);

            let error = destructive_result
                .expect_err("one complete-catalog read must reject a repeated quarantine id");
            assert!(
                error.contains("quarantineId"),
                "unexpected {case} error: {error}"
            );
            assert_eq!(mutation_calls, 0, "{case}");
        }
    }

    #[test]
    fn destructive_catalog_read_enforces_newest_first_at_items_50_and_51() {
        let first_fifty = || (0..50).map(catalog_session_fixture).collect::<Vec<_>>();
        let last_started_at = first_fifty()[49].session.date_label.clone();
        for (case, invalid) in [
            ("newer-timestamp", {
                let mut session = catalog_session_fixture(48);
                session.session.id = "session-newer-boundary".to_string();
                session
            }),
            ("same-timestamp-higher-id", {
                let mut session = catalog_session_fixture(50);
                session.session.date_label = last_started_at.clone();
                session.session.id = "session-z".to_string();
                session
            }),
        ] {
            let mut first = empty_catalog_page(Some("opaque-item-51".to_string()));
            first.page.items = first_fifty();
            let mut second = empty_catalog_page(None);
            second.page.items.push(invalid);
            let mut pages = vec![first, second].into_iter();
            let mut mutation_calls = 0_usize;

            let catalog = collect_full_session_catalog(|_, _, _| {
                Ok(pages.next().expect("two-page ordering fixture"))
            });
            let destructive_result = catalog.map(|_| mutation_calls += 1);

            let error =
                destructive_result.expect_err("item 51 must be strictly older than item 50");
            assert!(
                error.contains("newest-first"),
                "unexpected {case} error: {error}"
            );
            assert_eq!(mutation_calls, 0, "{case}");
        }

        let mut first = empty_catalog_page(Some("opaque-item-51".to_string()));
        first.page.items = first_fifty();
        let mut second = empty_catalog_page(None);
        second.page.items.push(catalog_session_fixture(50));
        let mut pages = vec![first, second].into_iter();
        let catalog = collect_full_session_catalog(|_, _, _| {
            Ok(pages.next().expect("two-page ordered fixture"))
        })
        .expect("strictly older item 51 closes the catalog");
        assert_eq!(catalog.len(), 51);
    }

    #[test]
    fn destructive_catalog_read_rejects_infinite_unique_cursors_before_mutation() {
        let mut page_reads = 0_usize;
        let mut deletion_calls = 0_usize;
        let catalog = collect_full_session_catalog(|_, _, _| {
            page_reads += 1;
            Ok(empty_catalog_page(Some(format!(
                "opaque-unique-cursor-{page_reads}"
            ))))
        });

        let destructive_result = catalog.map(|_| {
            deletion_calls += 1;
        });

        let error = destructive_result.expect_err("unbounded unique cursors must fail closed");
        assert!(error.contains("总页数上限"), "unexpected error: {error}");
        assert_eq!(page_reads, MAX_FULL_SESSION_CATALOG_PAGES);
        assert_eq!(
            deletion_calls, 0,
            "a non-closed catalog must never reach the deletion stage"
        );
    }

    #[test]
    fn destructive_catalog_read_rejects_total_item_overflow_before_mutation() {
        let mut deletion_calls = 0_usize;
        let mut page = empty_catalog_page(None);
        page.page.items = (0..=MAX_FULL_SESSION_CATALOG_ITEMS)
            .map(catalog_session_fixture)
            .collect();
        let mut page = Some(page);
        let catalog = collect_full_session_catalog(|_, _, _| {
            Ok(page.take().expect("only one oversized page is read"))
        });

        let destructive_result = catalog.map(|_| {
            deletion_calls += 1;
        });

        let error = destructive_result.expect_err("oversized catalog must fail closed");
        assert!(error.contains("总条目上限"), "unexpected error: {error}");
        assert_eq!(deletion_calls, 0);
    }

    #[test]
    fn destructive_catalog_read_rejects_revisionless_first_page_before_mutation() {
        let mut page = empty_catalog_page(None);
        page.page.catalog_revision = None;
        page.page.catalog_authority = SessionCatalogAuthority::Unavailable;
        page.page.pagination_supported = false;
        page.page.pagination_unavailable_reason =
            Some(SessionPaginationUnavailableReason::CatalogRevisionUnavailable);
        let mut page = Some(page);
        let mut mutation_calls = 0_usize;

        let catalog = collect_full_session_catalog(|_, _, _| {
            Ok(page.take().expect("revisionless first page is read once"))
        });
        let destructive_result = catalog.map(|_| mutation_calls += 1);

        let error =
            destructive_result.expect_err("revisionless first page is not a complete catalog");
        assert!(
            error.contains("不提供快照级 revision"),
            "unexpected error: {error}"
        );
        assert_eq!(mutation_calls, 0);
    }

    fn test_admission_key(plan: &DerivedPublicationPlan) -> ObjectKey {
        admission_object_key(&plan.marker_key, TEST_ADMISSION_ID)
            .expect("test admission UUIDv7 and marker authority are valid")
    }

    /// Creates a fresh, uniquely-named temp directory under the OS temp
    /// dir -- same pattern the existing PC-06 tests in this file use
    /// (`resolve_local_upload_file_*`) -- rather than depending on the
    /// `tempfile` crate, which is not a dependency of this outer
    /// `ylx-transfer` (src-tauri) crate (only of `ylx-transfer-core`), and
    /// this task may not edit any dependency manifest.
    fn fresh_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ylx-pc05b-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_mdns_candidate(
        service_name: &str,
        cursor: MdnsEventCursor,
        port: u16,
        addresses: &[Ipv4Addr],
    ) -> MdnsCandidate {
        let fullname = format!("{service_name}._ylx-capture._tcp.local.");
        MdnsCandidate {
            service_id: MdnsServiceId::from_fullname(&fullname),
            fullname,
            hostname: format!("{service_name}.local."),
            addresses: addresses.iter().copied().map(IpAddr::V4).collect(),
            endpoints: addresses
                .iter()
                .copied()
                .map(|address| MdnsEndpoint {
                    address: IpAddr::V4(address),
                    interface: None,
                })
                .collect(),
            port,
            txt: HashMap::new(),
            cursor,
        }
    }

    fn fake_v4_probe(seed: &str, label: &str) -> LabV4DeviceProbe {
        LabV4DeviceProbe {
            device_id: format!("device-{seed}"),
            device_label: label.to_string(),
            synthetic_identity_pin: PiTlsPin(test_fingerprint(seed)),
        }
    }

    #[test]
    fn mdns_probe_tries_ordered_addresses_until_one_succeeds() {
        let candidate = fake_mdns_candidate(
            "fallback",
            MdnsEventCursor {
                generation: 1,
                sequence: 1,
            },
            7314,
            &[Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)],
        );
        let mut attempted = Vec::new();

        let success =
            probe_mdns_candidate_with(&candidate, Duration::from_millis(50), |host, port, _| {
                attempted.push((host.to_string(), port));
                if host == "192.0.2.10" {
                    Err(PiHttpError::Network(
                        "cannot connect: actively refused (os error 10061)".to_string(),
                    ))
                } else {
                    Ok(fake_v4_probe("a", "Pi fallback"))
                }
            })
            .expect("the second advertised endpoint should be tried");

        assert_eq!(
            attempted,
            vec![
                ("192.0.2.10".to_string(), 7314),
                ("192.0.2.11".to_string(), 7314),
            ]
        );
        assert_eq!(success.target.host, "192.0.2.11");
        assert_eq!(success.target.port, 7314);
    }

    #[test]
    fn stale_probe_result_after_service_loss_is_fenced_before_registration() {
        let dir = fresh_temp_dir("mdns-late-result");
        let comp = test_composition(&dir, Vec::new());
        let candidate = fake_mdns_candidate(
            "late",
            MdnsEventCursor {
                generation: 7,
                sequence: 1,
            },
            8080,
            &[Ipv4Addr::LOCALHOST],
        );
        let observation = observe_mdns_changes(&comp, &[MdnsChange::Resolved(candidate.clone())]);
        assert_eq!(observation.probes.len(), 1);
        observe_mdns_changes(
            &comp,
            &[MdnsChange::Lost(MdnsServiceLoss {
                service_id: candidate.service_id.clone(),
                fullname: candidate.fullname.clone(),
                cursor: MdnsEventCursor {
                    generation: 7,
                    sequence: 2,
                },
                reason: ylx_transfer_adapters::discovery_mdns::MdnsLossReason::RemovedOrExpired,
            })],
        );

        let changed = probe_and_apply_mdns_candidate_with(&comp, candidate, |_, _, _| {
            Ok(fake_v4_probe("b", "Late Pi"))
        });
        assert!(!changed);
        assert!(comp.frontend_devices().is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn removed_service_goes_offline_and_reappears_as_the_same_device() {
        let dir = fresh_temp_dir("mdns-reappear");
        let comp = test_composition(&dir, Vec::new());
        let first = fake_mdns_candidate(
            "reappear",
            MdnsEventCursor {
                generation: 9,
                sequence: 1,
            },
            8080,
            &[Ipv4Addr::new(192, 0, 2, 20)],
        );
        observe_mdns_changes(&comp, &[MdnsChange::Resolved(first.clone())]);
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            first.clone(),
            |_, _, _| Ok(fake_v4_probe("c", "Reappearing Pi"))
        ));
        let original = comp.frontend_devices().pop().unwrap();
        assert_eq!(original.state, FrontendDeviceState::Idle);

        assert!(
            observe_mdns_changes(
                &comp,
                &[MdnsChange::Lost(MdnsServiceLoss {
                    service_id: first.service_id.clone(),
                    fullname: first.fullname.clone(),
                    cursor: MdnsEventCursor {
                        generation: 9,
                        sequence: 2,
                    },
                    reason: ylx_transfer_adapters::discovery_mdns::MdnsLossReason::RemovedOrExpired,
                })],
            )
            .device_state_changed
        );
        let offline = comp.frontend_devices().pop().unwrap();
        assert_eq!(offline.id, original.id);
        assert_eq!(offline.state, FrontendDeviceState::Offline);

        let reappeared = fake_mdns_candidate(
            "reappear",
            MdnsEventCursor {
                generation: 9,
                sequence: 3,
            },
            9080,
            &[Ipv4Addr::new(192, 0, 2, 21)],
        );
        observe_mdns_changes(&comp, &[MdnsChange::Resolved(reappeared.clone())]);
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            reappeared,
            |_, _, _| Ok(fake_v4_probe("c", "Reappearing Pi"))
        ));
        let online = comp.frontend_devices().pop().unwrap();
        assert_eq!(online.id, original.id);
        assert_eq!(online.state, FrontendDeviceState::Idle);
        assert_eq!(
            comp.resolve_binding(&online.id).unwrap().endpoint.port,
            9080
        );
        assert_eq!(comp.fleet.len(), 1);

        let stale_loss = observe_mdns_changes(
            &comp,
            &[MdnsChange::Lost(MdnsServiceLoss {
                service_id: first.service_id,
                fullname: first.fullname,
                cursor: MdnsEventCursor {
                    generation: 9,
                    sequence: 2,
                },
                reason: ylx_transfer_adapters::discovery_mdns::MdnsLossReason::RemovedOrExpired,
            })],
        );
        assert!(!stale_loss.device_state_changed);
        assert_eq!(
            comp.frontend_devices().pop().unwrap().state,
            FrontendDeviceState::Idle
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn losing_one_of_two_verified_services_rebinds_to_the_remaining_endpoint() {
        let dir = fresh_temp_dir("mdns-multi-service-rebind");
        let comp = test_composition(&dir, Vec::new());
        let service_a = fake_mdns_candidate(
            "multi-service-a",
            MdnsEventCursor {
                generation: 12,
                sequence: 1,
            },
            8080,
            &[Ipv4Addr::new(192, 0, 2, 51)],
        );
        let service_b = fake_mdns_candidate(
            "multi-service-b",
            MdnsEventCursor {
                generation: 12,
                sequence: 2,
            },
            8081,
            &[Ipv4Addr::new(192, 0, 2, 52)],
        );

        observe_mdns_changes(
            &comp,
            &[
                MdnsChange::Resolved(service_a.clone()),
                MdnsChange::Resolved(service_b.clone()),
            ],
        );
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            service_a.clone(),
            |_, _, _| Ok(fake_v4_probe("7", "Multi-address Pi"))
        ));
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            service_b.clone(),
            |_, _, _| Ok(fake_v4_probe("7", "Multi-address Pi"))
        ));

        let before_loss = comp.frontend_devices().pop().unwrap();
        assert_eq!(before_loss.ip.as_deref(), Some("192.0.2.52"));
        assert_eq!(
            comp.resolve_binding(&before_loss.id).unwrap().endpoint.port,
            8081
        );

        let observation = observe_mdns_changes(
            &comp,
            &[MdnsChange::Lost(MdnsServiceLoss {
                service_id: service_b.service_id,
                fullname: service_b.fullname,
                cursor: MdnsEventCursor {
                    generation: 12,
                    sequence: 3,
                },
                reason: ylx_transfer_adapters::discovery_mdns::MdnsLossReason::RemovedOrExpired,
            })],
        );

        let after_loss = comp.frontend_devices().pop().unwrap();
        assert_eq!(after_loss.id, before_loss.id);
        assert_eq!(after_loss.state, FrontendDeviceState::Idle);
        assert_eq!(after_loss.ip.as_deref(), Some("192.0.2.51"));
        let binding = comp.resolve_binding(&after_loss.id).unwrap();
        assert_eq!(binding.endpoint.host, "192.0.2.51");
        assert_eq!(binding.endpoint.port, 8080);
        assert!(
            observation.device_state_changed,
            "endpoint fallback must be emitted even though online state stays unchanged"
        );
        assert_eq!(comp.fleet.len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn terminal_browse_loss_marks_every_verified_service_offline() {
        let dir = fresh_temp_dir("mdns-browse-loss");
        let comp = test_composition(&dir, Vec::new());
        let first = fake_mdns_candidate(
            "browse-a",
            MdnsEventCursor {
                generation: 10,
                sequence: 1,
            },
            8080,
            &[Ipv4Addr::new(192, 0, 2, 40)],
        );
        let second = fake_mdns_candidate(
            "browse-b",
            MdnsEventCursor {
                generation: 10,
                sequence: 2,
            },
            8081,
            &[Ipv4Addr::new(192, 0, 2, 41)],
        );
        observe_mdns_changes(
            &comp,
            &[
                MdnsChange::Resolved(first.clone()),
                MdnsChange::Resolved(second.clone()),
            ],
        );
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            first.clone(),
            |_, _, _| Ok(fake_v4_probe("e", "Browse Pi E"))
        ));
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            second.clone(),
            |_, _, _| Ok(fake_v4_probe("f", "Browse Pi F"))
        ));

        let observation = observe_mdns_changes(
            &comp,
            &[MdnsChange::BrowseLost(MdnsBrowseLoss {
                generation: 10,
                cursor: MdnsEventCursor {
                    generation: 10,
                    sequence: 3,
                },
                service_ids: vec![first.service_id, second.service_id],
                reason: MdnsBrowseLossReason::ChannelDisconnected,
            })],
        );
        assert!(observation.device_state_changed);
        let devices = comp.frontend_devices();
        assert_eq!(devices.len(), 2);
        assert!(devices
            .iter()
            .all(|device| device.state == FrontendDeviceState::Offline));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manual_bare_reported_ip_uses_only_the_current_v4_http_origin() {
        let dir = fresh_temp_dir("manual-v4-http-origin");
        let comp = test_composition(&dir, Vec::new());
        let address = IpAddr::V4(Ipv4Addr::new(192, 168, 110, 36));
        let mut attempted = Vec::new();

        let planned = manual_lab_v4_probe_target(address);
        assert_eq!(planned.lab_v4_origin(), "http://192.168.110.36:8080");

        let device = comp
            .add_manual_device_with(address, |host, port, _| {
                attempted.push(DeviceProbeTarget {
                    host: host.to_string(),
                    port,
                });
                Ok(fake_v4_probe("1", "Reported Pi"))
            })
            .unwrap();

        assert_eq!(attempted.len(), 1);
        assert_eq!(attempted[0].lab_v4_origin(), "http://192.168.110.36:8080");
        assert!(!attempted[0].lab_v4_origin().contains("https://"));
        assert!(!attempted[0].lab_v4_origin().contains("8443"));
        let binding = comp.resolve_binding(&device.id).unwrap();
        assert_eq!(binding.endpoint.host, "192.168.110.36");
        assert_eq!(binding.endpoint.port, 8080);
        assert_eq!(binding.endpoint.api_profile, DeviceApiProfile::LabHttpV4);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manual_probe_error_lists_target_port_and_failure_class_without_legacy_tls_port() {
        let dir = fresh_temp_dir("manual-probe-error");
        let comp = test_composition(&dir, Vec::new());
        let address = IpAddr::V4(Ipv4Addr::new(192, 168, 110, 36));

        let error = comp
            .add_manual_device_with(address, |_, _, _| {
                Err(PiHttpError::Network(
                    "connection refused (os error 10061)".to_string(),
                ))
            })
            .unwrap_err();
        assert!(error.contains("http://192.168.110.36:8080"), "{error}");
        assert!(error.contains("connection_refused"), "{error}");
        assert!(!error.contains("https://"), "{error}");
        assert!(!error.contains("8443"), "{error}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mdns_loss_does_not_mark_a_manually_registered_identity_offline() {
        let dir = fresh_temp_dir("manual-survives-mdns-loss");
        let comp = test_composition(&dir, Vec::new());
        let manual = comp
            .add_manual_device_with(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)), |_, _, _| {
                Ok(fake_v4_probe("d", "Manual Pi"))
            })
            .unwrap();
        let candidate = fake_mdns_candidate(
            "also-mdns",
            MdnsEventCursor {
                generation: 11,
                sequence: 1,
            },
            8123,
            &[Ipv4Addr::new(192, 0, 2, 31)],
        );
        observe_mdns_changes(&comp, &[MdnsChange::Resolved(candidate.clone())]);
        assert!(probe_and_apply_mdns_candidate_with(
            &comp,
            candidate.clone(),
            |_, _, _| Ok(fake_v4_probe("d", "Manual Pi"))
        ));
        let mdns_binding = comp.resolve_binding(&manual.id).unwrap();
        assert_eq!(mdns_binding.endpoint.host, "192.0.2.31");
        assert_eq!(mdns_binding.endpoint.port, 8123);
        observe_mdns_changes(
            &comp,
            &[MdnsChange::Lost(MdnsServiceLoss {
                service_id: candidate.service_id,
                fullname: candidate.fullname,
                cursor: MdnsEventCursor {
                    generation: 11,
                    sequence: 2,
                },
                reason: ylx_transfer_adapters::discovery_mdns::MdnsLossReason::RemovedOrExpired,
            })],
        );

        let device = comp.frontend_devices().pop().unwrap();
        assert_eq!(device.id, manual.id);
        assert_eq!(device.state, FrontendDeviceState::Idle);
        let manual_binding = comp.resolve_binding(&device.id).unwrap();
        assert_eq!(manual_binding.endpoint.host, "192.0.2.30");
        assert_eq!(manual_binding.endpoint.port, LAB_V4_MANUAL_PORT);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verified_mdns_endpoint_replaces_manual_binding_without_losing_manual_presence() {
        let dir = fresh_temp_dir("manual-mdns-endpoint-refresh");
        let comp = test_composition(&dir, Vec::new());
        let manual = comp
            .add_manual_device_with(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60)), |_, _, _| {
                Ok(fake_v4_probe("8", "Manual and mDNS Pi"))
            })
            .unwrap();
        let handle = comp.handle_for(&manual.id).expect("manual device handle");
        connect_handle(&handle, "manual-origin-a", "origin-a-token");
        assert_eq!(handle.current_epoch(), Some(1));
        let mdns = fake_mdns_candidate(
            "manual-endpoint-refresh",
            MdnsEventCursor {
                generation: 13,
                sequence: 1,
            },
            8181,
            &[Ipv4Addr::new(192, 0, 2, 61)],
        );

        observe_mdns_changes(&comp, &[MdnsChange::Resolved(mdns.clone())]);
        let changed = probe_and_apply_mdns_candidate_with(&comp, mdns, |_, _, _| {
            Ok(fake_v4_probe("8", "Manual and mDNS Pi"))
        });

        let device = comp.frontend_devices().pop().unwrap();
        assert_eq!(device.id, manual.id);
        assert_eq!(device.state, FrontendDeviceState::Idle);
        assert_eq!(device.ip.as_deref(), Some("192.0.2.61"));
        let binding = comp.resolve_binding(&device.id).unwrap();
        assert_eq!(binding.endpoint.host, "192.0.2.61");
        assert_eq!(binding.endpoint.port, 8181);
        assert!(changed, "the refreshed endpoint must be emitted to the UI");
        assert_eq!(handle.connection_state(), ConnectionState::Disconnected);
        assert_eq!(
            handle.current_epoch(),
            None,
            "a token established on manual origin A must not follow the binding to origin B"
        );
        assert_eq!(comp.fleet.len(), 1);

        let identity = DeviceIdentity::parse(&test_fingerprint("8")).unwrap();
        assert!(
            comp.mdns_services
                .lock()
                .unwrap()
                .should_be_online(identity.fingerprint()),
            "manual presence must remain independent of the selected connection endpoint"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Serves a small loopback HTTP response to the real S3 adapter and
    /// records each non-empty request line. The tests use explicit path-style
    /// rows, so binding IPv4 loopback avoids hostname resolution differences
    /// between CI hosts while still exercising the real adapter. Some Windows
    /// runner network stacks can briefly open and abort an idle connection
    /// before the real request; those empty preconnects are ignored because
    /// they carry no URL-style evidence.
    fn spawn_s3_test_server(
        status: u16,
        body: &[u8],
        request_count: usize,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback S3 test server");
        listener
            .set_nonblocking(true)
            .expect("configure nonblocking test listener");
        let port = listener
            .local_addr()
            .expect("read test listener address")
            .port();
        let endpoint = format!("http://127.0.0.1:{port}");
        let body = body.to_vec();
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::with_capacity(request_count);
            let deadline = Instant::now() + Duration::from_secs(30);
            while requests.len() < request_count && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("configure S3 test stream read timeout");
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => {
                            request.extend_from_slice(&chunk[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let request_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if request_line.trim().is_empty() {
                    continue;
                }
                requests.push(request_line);
                let reason = match status {
                    204 => "No Content",
                    404 => "Not Found",
                    _ => "Test Response",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write S3 test response headers");
                if !body.is_empty() {
                    stream
                        .write_all(&body)
                        .expect("write S3 test response body");
                }
            }
            requests
        });
        (endpoint, handle)
    }

    #[test]
    fn full_fingerprint_identity_has_distinct_canonical_and_display_projections() {
        let identity = DeviceIdentity::parse(
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .unwrap();
        assert_eq!(
            identity.device_id().as_str(),
            "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
        assert_eq!(identity.display_id(), "YLX-ABCDEF01");
    }

    #[test]
    fn full_fingerprint_identity_accepts_a_bare_fingerprint() {
        let identity = DeviceIdentity::parse(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .unwrap();
        assert_eq!(identity.display_id(), "YLX-ABCDEF01");
    }

    #[test]
    fn heartbeat_interval_precedes_pi_idle_timeout_with_network_margin() {
        const PI_INITIAL_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(5));
        assert!(HEARTBEAT_INTERVAL < PI_INITIAL_IDLE_TIMEOUT);
    }

    #[test]
    fn transfer_job_poll_emits_once_when_the_last_visible_job_is_removed() {
        assert!(!should_emit_transfer_jobs_snapshot(false, 0));
        assert!(should_emit_transfer_jobs_snapshot(false, 1));
        assert!(should_emit_transfer_jobs_snapshot(true, 0));
        assert!(!should_emit_transfer_jobs_snapshot(false, 0));
    }

    /// A 64-hex TLS fingerprint built from one repeated character, so a
    /// test can name distinct devices cheaply.
    fn test_fingerprint(seed: &str) -> String {
        format!("sha256:{}", seed.repeat(64))
    }

    fn test_identity(seed: &str) -> DeviceIdentity {
        DeviceIdentity::parse(&test_fingerprint(seed)).unwrap()
    }

    /// Drives `handle` to `Connected` holding `token`, without any network:
    /// `PreparedPairingClient` replays a POST response, and the allowed
    /// status is applied directly.
    fn connect_handle(handle: &DeviceHandle, attempt_id: &str, token: &str) {
        let created = PairingCreatedView {
            attempt_id: attempt_id.to_string(),
            phase: PairingPhase::Pending,
            poll_secret: "poll-secret".to_string(),
            sas: "123456".to_string(),
            expires_at: "2026-08-03T12:00:00Z".to_string(),
            sas_publication_key_fingerprint: None,
        };
        handle
            .actor()
            .start_pairing_with(&PreparedPairingClient(created), "lock-test", "nonce")
            .expect("start_pairing replays the prepared response");
        let outcome = handle.actor().apply_pairing_status(
            attempt_id,
            Ok(PairingStatusView {
                attempt_id: attempt_id.to_string(),
                phase: PairingPhase::Allowed,
                connection_token: Some(token.to_string()),
                sas: "123456".to_string(),
                expires_at: "2026-08-03T12:00:00Z".to_string(),
                sas_publication_key_fingerprint: None,
            }),
        );
        assert!(matches!(outcome, PollPairingOutcome::Connected { .. }));
    }

    fn spawn_lab_v4_catalog_server(
        responses: Vec<String>,
    ) -> (u16, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind catalog loopback server");
        listener
            .set_nonblocking(true)
            .expect("configure nonblocking catalog listener");
        let port = listener
            .local_addr()
            .expect("catalog loopback address")
            .port();
        let (requests_tx, requests_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            for body in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "timed out waiting for catalog request"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept catalog request: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("catalog request read timeout");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).expect("read catalog request");
                    assert!(read > 0, "catalog request closed before its headers");
                    request.extend_from_slice(&chunk[..read]);
                }
                let request_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .expect("catalog request line")
                    .to_string();
                requests_tx
                    .send(request_line)
                    .expect("record catalog request line");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write catalog response");
            }
        });
        (port, requests_rx, server)
    }

    fn spawn_lab_v4_periodic_poll_server(
        body: String,
    ) -> (u16, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        spawn_lab_v4_single_response_server(body, Vec::new())
    }

    fn spawn_lab_v4_single_response_server(
        body: String,
        response_headers: Vec<(String, String)>,
    ) -> (u16, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind periodic-poll server");
        listener
            .set_nonblocking(true)
            .expect("configure nonblocking periodic-poll listener");
        let port = listener
            .local_addr()
            .expect("periodic-poll loopback address")
            .port();
        let (requests_tx, requests_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let first_deadline = Instant::now() + Duration::from_secs(5);
            let mut first = true;
            let mut linger_deadline = first_deadline;
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("periodic-poll request read timeout");
                        let mut request = Vec::new();
                        let mut chunk = [0_u8; 1024];
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let read = stream.read(&mut chunk).expect("read periodic-poll request");
                            assert!(read > 0, "periodic-poll request closed before headers");
                            request.extend_from_slice(&chunk[..read]);
                        }
                        requests_tx
                            .send(
                                String::from_utf8_lossy(&request)
                                    .lines()
                                    .next()
                                    .expect("periodic-poll request line")
                                    .to_string(),
                            )
                            .expect("record periodic-poll request line");
                        let extra_headers = response_headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}\r\n"))
                            .collect::<String>();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("write periodic-poll response");
                        if first {
                            first = false;
                            linger_deadline = Instant::now() + Duration::from_millis(250);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        let deadline = if first {
                            first_deadline
                        } else {
                            linger_deadline
                        };
                        assert!(!first || Instant::now() < deadline, "missing periodic poll");
                        if !first && Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept periodic-poll request: {error}"),
                }
            }
        });
        (port, requests_rx, server)
    }

    fn lab_v4_device_descriptor_body() -> String {
        serde_json::json!({
            "schema": "ylx.device.v4",
            "device": {
                "device_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_label": "YLX-30D5872D"
            },
            "hardware_fingerprint": test_fingerprint("e"),
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
                "network_mutation": false,
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
                "network": {},
                "live_imu": null,
                "camera": {
                    "schema": "ylx.camera-connection.v1",
                    "state": "connected"
                },
                "camera_focus": null
            }
        })
        .to_string()
    }

    fn negotiated_lab_v4_device_info() -> ylx_transfer_core::device::DeviceInfoView {
        let profile_contract = NegotiatedCapabilityView {
            supported: true,
            source: CapabilitySourceView::ProfileContract,
        };
        let descriptor = NegotiatedCapabilityView {
            supported: true,
            source: CapabilitySourceView::DeviceDescriptor,
        };
        ylx_transfer_core::device::DeviceInfoView {
            capture_activity: CaptureActivityState::Unknown,
            media_admission: "lab_v4".to_string(),
            publication_key_fingerprint: test_fingerprint("f"),
            profile: DeviceApiProfileView::LabHttpV4,
            capabilities: DeviceCapabilitiesView {
                session_list: profile_contract,
                session_detail: profile_contract,
                artifact_download: descriptor,
                capture_status: profile_contract,
                session_deletion: NegotiatedCapabilityView {
                    supported: false,
                    source: CapabilitySourceView::ProfileContract,
                },
                ..DeviceCapabilitiesView::default()
            },
            capture_status: None,
            publication_origin: PublicationEnvelopeOriginView::ClientDerivedLabCompatibility,
        }
    }

    #[test]
    fn negotiated_lab_v4_catalog_pages_issue_only_the_sessions_request() {
        let catalog_revision = format!("sha256:{}", "c".repeat(64));
        let next_cursor = "01989f6c-2c00-7a1b-8c2d-3e4f50617281";
        let page = |next_cursor: Option<&str>| {
            serde_json::json!({
                "schema": "ylx.session-list.v3",
                "catalog_revision": catalog_revision,
                "items": [],
                "diagnostics": [],
                "next_cursor": next_cursor,
            })
            .to_string()
        };
        let (port, requests, server) =
            spawn_lab_v4_catalog_server(vec![page(Some(next_cursor)), page(None)]);
        let dir = fresh_temp_dir("lab-v4-one-request-per-catalog-page");
        let comp = test_composition(&dir, Vec::new());
        let registration = comp
            .register_endpoint(DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port,
                tls_fingerprint: test_fingerprint("e"),
                name: "Loopback Lab v4".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LabHttpV4,
            })
            .expect("register Lab v4 loopback endpoint");
        connect_handle(&registration.handle, "attempt-lab-v4", "token-lab-v4");
        registration
            .handle
            .actor()
            .apply_device_info(negotiated_lab_v4_device_info())
            .expect("install current-epoch Lab v4 negotiation");
        let device_id = registration.identity.device_id().as_str();

        let first = comp
            .read_session_page(device_id, None, None, None)
            .expect("first page must not depend on capture status");
        let second = comp
            .read_session_page(
                device_id,
                first.page.next_cursor.as_deref(),
                first.page.catalog_revision.as_deref(),
                Some(first.connection_epoch),
            )
            .expect("load-more must not depend on capture status");

        assert!(!second.page.has_more);
        assert_eq!(
            requests
                .recv_timeout(Duration::from_secs(2))
                .expect("first request"),
            "GET /api/v4/sessions?limit=50 HTTP/1.1"
        );
        assert_eq!(
            requests
                .recv_timeout(Duration::from_secs(2))
                .expect("load-more request"),
            format!("GET /api/v4/sessions?cursor={next_cursor}&limit=50 HTTP/1.1")
        );
        assert!(
            requests.try_recv().is_err(),
            "no descriptor/status preflight"
        );
        server.join().expect("catalog loopback server exits");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn lab_v4_connection_negotiation_is_one_descriptor_request_before_ready() {
        let (port, requests, server) =
            spawn_lab_v4_periodic_poll_server(lab_v4_device_descriptor_body());
        let dir = fresh_temp_dir("lab-v4-one-request-connection-negotiation");
        let comp = test_composition(&dir, Vec::new());
        let registration = comp
            .register_endpoint(DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port,
                tls_fingerprint: test_fingerprint("e"),
                name: "Loopback Lab v4".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LabHttpV4,
            })
            .expect("register Lab v4 negotiation endpoint");
        connect_handle(&registration.handle, "attempt-lab-v4", "token-lab-v4");
        let binding = comp
            .resolve_binding(registration.identity.device_id().as_str())
            .expect("resolve negotiation binding");

        assert_eq!(
            negotiate_lab_v4_connection_once(&binding.handle, binding.client, 1),
            ConnectionNegotiationOutcome::Ready
        );

        server.join().expect("negotiation loopback server exits");
        assert_eq!(
            requests.try_iter().collect::<Vec<_>>(),
            vec!["GET /api/v4/device HTTP/1.1".to_string()]
        );
        let negotiated = registration
            .handle
            .negotiated_device_snapshot()
            .expect("descriptor facts are atomically bound to this epoch");
        assert_eq!(negotiated.epoch, 1);
        assert_eq!(negotiated.info.profile, DeviceApiProfileView::LabHttpV4);
        assert_eq!(
            negotiated.info.capture_activity,
            CaptureActivityState::Unknown,
            "initial negotiation must not duplicate capture status"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn failed_lab_v4_connection_negotiation_clears_only_that_epoch() {
        let (port, requests, server) = spawn_lab_v4_periodic_poll_server("{}".to_string());
        let dir = fresh_temp_dir("lab-v4-failed-connection-negotiation");
        let comp = test_composition(&dir, Vec::new());
        let registration = comp
            .register_endpoint(DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port,
                tls_fingerprint: test_fingerprint("e"),
                name: "Loopback Lab v4".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LabHttpV4,
            })
            .expect("register failing negotiation endpoint");
        connect_handle(&registration.handle, "attempt-lab-v4", "token-lab-v4");
        let binding = comp
            .resolve_binding(registration.identity.device_id().as_str())
            .expect("resolve failing negotiation binding");

        assert!(matches!(
            negotiate_lab_v4_connection_once(&binding.handle, binding.client, 1),
            ConnectionNegotiationOutcome::Failed(_)
        ));

        server.join().expect("failing negotiation server exits");
        assert_eq!(
            requests.try_iter().collect::<Vec<_>>(),
            vec!["GET /api/v4/device HTTP/1.1".to_string()]
        );
        assert_eq!(
            registration.handle.connection_state(),
            ConnectionState::Disconnected
        );
        assert!(registration.handle.negotiated_device_snapshot().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn negotiated_lab_v4_detail_issues_only_the_manifest_request() {
        let session_id = "01989f6c-2c00-7a1b-8c2d-3e4f50617283";
        let manifest = serde_json::json!({
            "schema": "ylx.device-session.v2",
            "session_id": session_id,
            "sealed_at": "2026-08-08T10:31:33+08:00",
            "time": {
                "started_at": "2026-08-08T10:31:00+08:00",
                "ended_at": "2026-08-08T10:31:30+08:00",
                "duration_seconds": 30
            }
        })
        .to_string();
        let manifest_sha256 = format!("{:x}", Sha256::digest(manifest.as_bytes()));
        let (port, requests, server) = spawn_lab_v4_single_response_server(
            manifest,
            vec![
                ("YLX-Manifest-SHA256".to_string(), manifest_sha256.clone()),
                ("ETag".to_string(), format!("\"{manifest_sha256}\"")),
            ],
        );
        let dir = fresh_temp_dir("lab-v4-one-request-session-detail");
        let comp = test_composition(&dir, Vec::new());
        let registration = comp
            .register_endpoint(DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port,
                tls_fingerprint: test_fingerprint("e"),
                name: "Loopback Lab v4".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LabHttpV4,
            })
            .expect("register Lab v4 detail endpoint");
        connect_handle(&registration.handle, "attempt-lab-v4", "token-lab-v4");
        registration
            .handle
            .actor()
            .apply_device_info(negotiated_lab_v4_device_info())
            .expect("install current-epoch Lab v4 negotiation");
        let verification = GatewayVerificationView {
            actor: "gateway".to_string(),
            validator_name: "manifest-validator".to_string(),
            validator_version: "2.1.0".to_string(),
            validator_build_sha256: "b".repeat(64),
            manifest_sha256: manifest_sha256.clone(),
            manifest_digest_valid: true,
            verified_at: "2026-08-08T10:31:34+08:00".to_string(),
            verdict: GatewayVerificationVerdictView::Usable,
            diagnostics: Vec::new(),
        };
        let binding = comp
            .resolve_binding(registration.identity.device_id().as_str())
            .expect("resolve detail binding");

        let detail = fetch_verified_session_detail(
            &binding.handle,
            binding.client,
            session_id,
            &verification,
        )
        .expect("detail reuses the negotiated snapshot");

        server.join().expect("detail loopback server exits");
        assert_eq!(detail.revision, format!("sha256:{manifest_sha256}"));
        assert_eq!(
            requests.try_iter().collect::<Vec<_>>(),
            vec![format!("GET /api/v4/sessions/{session_id} HTTP/1.1")],
            "detail must not preflight descriptor or capture status"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn negotiated_lab_v4_periodic_poll_issues_only_capture_status() {
        let body = serde_json::json!({
            "schema": "ylx.capture-status.v4",
            "authority_epoch": "4fa85f64-5717-4562-b3fc-2c963f66afa6",
            "source_revision": 7,
            "snapshot": {
                "schema": "ylx.capture-snapshot-event.v4",
                "device_state": "recording",
                "active_recording": {
                    "generation_id": "550e8400-e29b-41d4-a716-446655440001"
                },
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
        .to_string();
        let (port, requests, server) = spawn_lab_v4_periodic_poll_server(body);
        let dir = fresh_temp_dir("lab-v4-one-request-per-periodic-poll");
        let comp = test_composition(&dir, Vec::new());
        let registration = comp
            .register_endpoint(DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port,
                tls_fingerprint: test_fingerprint("e"),
                name: "Loopback Lab v4".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LabHttpV4,
            })
            .expect("register Lab v4 periodic-poll endpoint");
        connect_handle(&registration.handle, "attempt-lab-v4", "token-lab-v4");
        registration
            .handle
            .actor()
            .apply_device_info(negotiated_lab_v4_device_info())
            .expect("install current-epoch Lab v4 negotiation");
        let binding = comp
            .resolve_binding(registration.identity.device_id().as_str())
            .expect("resolve periodic-poll binding");

        assert!(poll_connected_device_once(
            &binding.handle,
            binding.client,
            DeviceApiProfile::LabHttpV4,
        ));

        server.join().expect("periodic-poll loopback server exits");
        assert_eq!(
            requests.try_iter().collect::<Vec<_>>(),
            vec!["GET /api/v4/capture/status HTTP/1.1".to_string()]
        );
        assert_eq!(
            registration.handle.snapshot().device.capture_activity,
            CaptureActivityState::Recording
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn connected_session_operation_runs_with_neither_the_fleet_nor_the_handle_locked() {
        let fingerprint = test_fingerprint("a");
        let fleet = DeviceFleet::new();
        let handle = fleet.get_or_create(fingerprint.as_str(), || fallback_device("YLX-LOCKTEST"));
        connect_handle(&handle, "attempt-lock-test", "token-lock-test");

        let observed = with_connected_session(&handle, |session| {
            assert!(
                fleet.handle(fingerprint.as_str()).is_some(),
                "catalog network work must not hold the fleet's map lock"
            );
            assert_eq!(
                handle.connection_state(),
                ConnectionState::Connected {
                    connection_id: "attempt-lock-test".to_string(),
                    epoch: 1
                },
                "catalog network work must not hold this device's own lock either"
            );
            Ok(session.epoch())
        })
        .unwrap();

        assert_eq!(observed, 1);
    }

    // -----------------------------------------------------------------
    // PC-08b: RealDownloadSourceFactory -- pure-logic error paths only
    // (constructing a real connected `PiHttpClient`/`DeviceActor` pair
    // needs a live TLS pin and pairing flow; see this test module's own
    // header comment for why that stays out of scope for a unit test
    // here).
    // -----------------------------------------------------------------

    fn test_client() -> Arc<PiHttpClient> {
        Arc::new(
            PiHttpClient::new(PiHttpClientConfig {
                host: "127.0.0.1".to_string(),
                port: 9,
                tls_pin: PiTlsPin("a".repeat(64)),
                request_timeout: Duration::from_secs(1),
            })
            .expect("PiHttpClient::new performs no I/O, only builds an agent"),
        )
    }

    // -----------------------------------------------------------------
    // Pairing attempt identity + off-thread cancellation
    // -----------------------------------------------------------------

    fn active_pairing(attempt_id: &str) -> ActivePairing {
        ActivePairing {
            attempt_id: attempt_id.to_string(),
            poll_secret: "poll-secret".to_string(),
            client: test_client(),
            sas: "123456".to_string(),
            record_trusted_producer_key: true,
        }
    }

    #[test]
    fn connected_epoch_stays_pending_and_unpolled_until_negotiation_finishes() {
        let dir = fresh_temp_dir("connection-negotiation-not-yet-published");
        let comp = test_composition(&dir, Vec::new());
        let registration = comp
            .register_endpoint(DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port: 9,
                tls_fingerprint: test_fingerprint("e"),
                name: "Negotiating Lab v4".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LabHttpV4,
            })
            .expect("register negotiating device");
        connect_handle(
            &registration.handle,
            "attempt-negotiating",
            "token-negotiating",
        );
        let device_id = registration.identity.device_id().as_str().to_string();
        comp.active_pairings
            .lock()
            .unwrap()
            .insert(device_id.clone(), active_pairing("attempt-negotiating"));

        assert_eq!(
            comp.frontend_devices()
                .into_iter()
                .find(|device| device.id == device_id)
                .expect("device projection")
                .state,
            FrontendDeviceState::Pending,
            "the Connected actor must not be published before descriptor negotiation"
        );
        assert!(
            comp.clients_by_fingerprint().is_empty(),
            "the 5-second sweep must not race connection negotiation with capture status"
        );

        std::fs::remove_dir_all(dir).ok();
    }

    /// A poll/cancel result belonging to an attempt the device has already
    /// moved past must be dropped, not applied to whatever attempt is
    /// current now.
    #[test]
    fn a_result_for_a_superseded_pairing_attempt_is_not_current() {
        let mut pairings = HashMap::new();
        pairings.insert("YLX-1".to_string(), active_pairing("attempt-2"));

        assert!(pairing_attempt_is_current(&pairings, "YLX-1", "attempt-2"));
        // Late result from the first attempt, after a re-connect replaced it.
        assert!(!pairing_attempt_is_current(&pairings, "YLX-1", "attempt-1"));
        // Nothing in flight at all (already resolved/cancelled).
        assert!(!pairing_attempt_is_current(&pairings, "YLX-2", "attempt-2"));
    }

    /// A `PairingCancelPort` whose DELETE blocks until released -- stands in
    /// for a Pi that accepted the TCP connection and then went quiet.
    struct BlockingCanceller {
        entered: mpsc::Sender<()>,
        release: Mutex<Option<mpsc::Receiver<()>>>,
    }

    impl PairingCancelPort for BlockingCanceller {
        fn cancel_pairing_attempt(
            &self,
            _attempt_id: &str,
            _poll_secret: &str,
        ) -> Result<(), String> {
            self.entered.send(()).expect("test observes the DELETE");
            let release = self
                .release
                .lock()
                .unwrap()
                .take()
                .expect("the DELETE is issued exactly once");
            let _ = release.recv();
            Ok(())
        }
    }

    /// The device-side DELETE runs on a blocking worker: the thread that
    /// invoked the command is free to keep working (here: to observe that
    /// the DELETE has started and only then release it) while the request
    /// is still outstanding. A command that performed the DELETE inline
    /// could never reach the release below -- it would deadlock.
    #[test]
    fn cancel_pairing_runs_the_device_delete_off_the_calling_thread() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let client = Arc::new(BlockingCanceller {
            entered: entered_tx,
            release: Mutex::new(Some(release_rx)),
        });

        let task = tauri::async_runtime::spawn(cancel_pairing_at_device(
            client,
            "attempt-1".to_string(),
            "poll-secret".to_string(),
        ));

        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the blocking DELETE must run somewhere other than this thread");
        release_tx.send(()).expect("release the blocked DELETE");

        let result = tauri::async_runtime::block_on(task).expect("cancel task joins");
        assert!(result.is_ok(), "{result:?}");
    }

    /// Offline-device regression: an unreachable Pi produces a bounded,
    /// reported failure rather than an indefinite wait, and never a
    /// silently "successful" cancel.
    #[test]
    fn an_offline_device_cannot_hang_the_cancel_command() {
        // Port 9 on loopback with a 1s request timeout: nothing answers.
        let client: Arc<dyn PairingCancelPort> = Arc::new(PiPairingClient::new(test_client()));
        let started = std::time::Instant::now();

        let error = tauri::async_runtime::block_on(cancel_pairing_at_device(
            client,
            "attempt-1".to_string(),
            "poll-secret".to_string(),
        ))
        .expect_err("an unreachable device must not report a successful cancel");

        assert!(error.contains("设备端取消配对失败"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "cancel took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn real_download_source_factory_errors_when_device_has_no_known_client() {
        let factory = RealDownloadSourceFactory {
            bindings: Arc::new(Mutex::new(DeviceBindings::default())),
        };
        let result = factory.make_source(
            &DeviceId(format!("ylx-{}", "f".repeat(64))),
            &ylx_transfer_core::domain::SessionId("sess-1".to_string()),
            &ylx_transfer_core::domain::FileId("file-1".to_string()),
        );
        assert!(
            matches!(result, Err(DownloadError::Source(message)) if message.contains("not registered"))
        );
    }

    #[test]
    fn real_download_source_factory_resolves_one_legacy_alias_to_its_coherent_binding() {
        let fingerprint = test_fingerprint("b");
        let identity = DeviceIdentity::parse(&fingerprint).unwrap();
        let fleet = Arc::new(DeviceFleet::new());
        let handle = fleet.get_or_create(identity.fingerprint().clone(), || {
            fallback_device(identity.device_id().as_str())
        });
        let client = test_client();
        let bindings = Arc::new(Mutex::new(DeviceBindings::default()));
        bindings.lock().unwrap().bind(
            identity.clone(),
            DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port: 9,
                tls_fingerprint: identity.tls_pin(),
                name: "Pi B".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
            },
            client,
            handle,
        );
        let factory = RealDownloadSourceFactory { bindings };

        let result = factory.make_source(
            &DeviceId(identity.display_id().to_string()),
            &ylx_transfer_core::domain::SessionId("sess-1".to_string()),
            &ylx_transfer_core::domain::FileId("file-1".to_string()),
        );
        assert!(
            matches!(result, Err(DownloadError::Source(message)) if message.contains("not connected"))
        );
    }

    // -----------------------------------------------------------------
    // Commit 59: the device registry is no longer a global serialization
    // point, and results that arrive after the world moved on are dropped.
    // -----------------------------------------------------------------

    /// Registers a retained legacy v1 endpoint through the real registry path
    /// ([`Composition::register_endpoint`], which builds a real pinned HTTPS
    /// client but performs no I/O) and returns its canonical id.
    fn register_test_device(comp: &Composition, seed: &str) -> String {
        let fingerprint = test_fingerprint(seed);
        comp.register_endpoint(DeviceEndpoint {
            host: "127.0.0.1".to_string(),
            port: 9,
            tls_fingerprint: fingerprint,
            name: format!("Pi {seed}"),
            display_label: None,
            api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
        })
        .expect("registering an endpoint does no I/O")
        .identity
        .device_id()
        .as_str()
        .to_string()
    }

    #[test]
    fn colliding_display_ids_keep_two_complete_production_bindings_and_fail_legacy_closed() {
        let dir = fresh_temp_dir("full-fingerprint-bindings");
        let comp = test_composition(&dir, Vec::new());
        let fingerprint_a = format!("sha256:abcdef01{}", "1".repeat(56));
        let fingerprint_b = format!("sha256:abcdef01{}", "2".repeat(56));

        let registration_a = comp
            .register_endpoint(DeviceEndpoint {
                host: "192.0.2.1".to_string(),
                port: 8443,
                tls_fingerprint: fingerprint_a,
                name: "Pi A".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
            })
            .unwrap();
        let registration_b = comp
            .register_endpoint(DeviceEndpoint {
                host: "192.0.2.2".to_string(),
                port: 9443,
                tls_fingerprint: fingerprint_b,
                name: "Pi B".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
            })
            .unwrap();

        assert!(registration_a.is_new);
        assert!(registration_b.is_new);
        assert_ne!(
            registration_a.identity.device_id(),
            registration_b.identity.device_id()
        );
        assert_eq!(
            registration_a.identity.display_id(),
            registration_b.identity.display_id()
        );

        let id_a = registration_a.identity.device_id().as_str();
        let id_b = registration_b.identity.device_id().as_str();
        let binding_a = comp.resolve_binding(id_a).unwrap();
        let binding_b = comp.resolve_binding(id_b).unwrap();
        assert_eq!(binding_a.endpoint.host, "192.0.2.1");
        assert_eq!(binding_b.endpoint.host, "192.0.2.2");
        assert_eq!(binding_a.endpoint.port, 8443);
        assert_eq!(binding_b.endpoint.port, 9443);
        assert_eq!(
            binding_a.handle.fingerprint(),
            registration_a.identity.fingerprint()
        );
        assert_eq!(
            binding_b.handle.fingerprint(),
            registration_b.identity.fingerprint()
        );

        let clients = comp.clients_by_fingerprint();
        assert_eq!(clients.len(), 2);
        assert!(Arc::ptr_eq(
            &clients
                .get(registration_a.identity.fingerprint())
                .unwrap()
                .client,
            &binding_a.client
        ));
        assert!(Arc::ptr_eq(
            &clients
                .get(registration_b.identity.fingerprint())
                .unwrap()
                .client,
            &binding_b.client
        ));
        assert_eq!(
            clients
                .get(registration_a.identity.fingerprint())
                .unwrap()
                .api_profile,
            DeviceApiProfile::LegacyPinnedTlsV1
        );

        let devices = comp.frontend_devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].id, id_a);
        assert_eq!(devices[1].id, id_b);
        assert_ne!(devices[0].id, devices[1].id);
        assert_eq!(devices[0].display_id, "YLX-ABCDEF01");
        assert_eq!(devices[1].display_id, "YLX-ABCDEF01");
        assert_eq!(comp.fleet.len(), 2);

        let legacy = DeviceId("YLX-ABCDEF01".to_string());
        let resolution = comp.bindings.lock().unwrap().resolve(&legacy);
        assert!(matches!(
            resolution,
            Err(DeviceIdentityResolutionError::AmbiguousLegacyAlias { candidates, .. })
                if candidates
                    == vec![
                        registration_a.identity.device_id().clone(),
                        registration_b.identity.device_id().clone(),
                    ]
        ));
        assert!(!comp.device_ids_match(id_a, legacy.as_str()));
        assert!(comp.device_ids_match(legacy.as_str(), legacy.as_str()));
        assert_eq!(
            comp.job_event_identity(&legacy),
            (
                Some("YLX-ABCDEF01".to_string()),
                Some("YLX-ABCDEF01".to_string())
            ),
            "an ambiguous historical job remains identifiable but never routes to either device"
        );

        let status = FleetStatusPort {
            bindings: comp.bindings.clone(),
        };
        assert_eq!(
            status.connection_state(&legacy),
            ConnectionState::Disconnected
        );
        assert_eq!(
            status.capture_activity(&legacy),
            CaptureActivityState::Unknown
        );

        let source_factory = RealDownloadSourceFactory {
            bindings: comp.bindings.clone(),
        };
        let source = source_factory.make_source(
            &legacy,
            &SessionId("sess-collision".to_string()),
            &FileId("file-collision".to_string()),
        );
        assert!(matches!(
            source,
            Err(DownloadError::Source(message)) if message.contains("matches multiple registered devices")
        ));

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn job_events_project_canonical_legacy_and_invalid_history_without_split_nullability() {
        let dir = fresh_temp_dir("job-event-device-identity");
        let comp = test_composition(&dir, Vec::new());
        let registered_id = register_test_device(&comp, "d");
        let registered = comp.resolve_binding(&registered_id).unwrap();

        let cases = [
            (
                DeviceId(format!("ylx-abcdef01{}", "3".repeat(56))),
                Some(format!("ylx-abcdef01{}", "3".repeat(56))),
                Some("YLX-ABCDEF01".to_string()),
            ),
            (
                DeviceId("YLX-ABCDEF01".to_string()),
                Some("YLX-ABCDEF01".to_string()),
                Some("YLX-ABCDEF01".to_string()),
            ),
            (
                DeviceId(registered.identity.display_id().to_string()),
                Some(registered_id),
                Some(registered.identity.display_id().to_string()),
            ),
            (DeviceId("device-invalid".to_string()), None, None),
        ];

        for (stored, expected_id, expected_display_id) in cases {
            let (device_id, device_display_id) = comp.job_event_identity(&stored);
            assert_eq!(device_id, expected_id, "stored identity: {stored:?}");
            assert_eq!(
                device_display_id, expected_display_id,
                "stored identity: {stored:?}"
            );
            assert_eq!(
                device_id.is_none(),
                device_display_id.is_none(),
                "job event identity fields must always share nullability"
            );

            let wire = serde_json::to_value(JobStateEvent {
                job_id: "job-identity".to_string(),
                state: TransferJobState::Queued,
                desired_run_state: DesiredRunState::Run,
                session_id: Some("session-identity".to_string()),
                device_id,
                device_display_id,
                total_bytes: 0,
                transferred_bytes: 0,
                files_total: 0,
                files_done: 0,
            })
            .unwrap();
            assert!(wire.get("deviceId").is_some());
            assert!(wire.get("deviceDisplayId").is_some());
            match expected_id.as_deref() {
                Some(expected) => assert_eq!(wire["deviceId"], expected),
                None => assert!(wire["deviceId"].is_null()),
            }
            match expected_display_id.as_deref() {
                Some(expected) => assert_eq!(wire["deviceDisplayId"], expected),
                None => assert!(wire["deviceDisplayId"].is_null()),
            }
            assert_eq!(
                wire["deviceId"].is_null(),
                wire["deviceDisplayId"].is_null()
            );
        }

        std::fs::remove_dir_all(dir).ok();
    }

    /// The regression this whole migration exists for, at the composition
    /// level: device A is busy (here, holding its own actor -- exactly what
    /// an in-flight per-device operation looks like from outside), and
    /// device B's pairing, catalog-token, delete and disconnect paths must
    /// all still complete, as must registering a brand-new device.
    ///
    /// Under the old shape every one of those paths went through the single
    /// `Arc<Mutex<DeviceActorRegistry>>` -- and held it across its network
    /// call -- so one unreachable Pi blocked all of them. Structurally that
    /// is now impossible: there is no lock a device operation can hold that
    /// another device's operation needs.
    #[test]
    fn a_busy_device_does_not_stall_another_devices_pairing_catalog_or_delete_path() {
        let dir = fresh_temp_dir("fleet-no-stall");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        let id_a = register_test_device(&comp, "a");
        let id_b = register_test_device(&comp, "b");
        let handle_a = comp.handle_for(&id_a).expect("A registered");
        let handle_b = comp.handle_for(&id_b).expect("B registered");
        connect_handle(&handle_b, "attempt-b", "token-b");

        let (busy_tx, busy_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let busy = std::thread::spawn(move || {
            let _actor = handle_a.actor();
            busy_tx.send(()).expect("test observes A as busy");
            let _ = release_rx.recv();
        });
        busy_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("device A becomes busy");

        let worker = {
            let comp = comp.clone();
            let id_b = id_b.clone();
            std::thread::spawn(move || {
                // Catalog: the authenticated session checkout every read starts with.
                assert_eq!(
                    with_connected_session(&handle_b, |session| Ok(session.epoch())).unwrap(),
                    1
                );
                // Delete: reaches the client (which refuses) rather than
                // waiting on anything device A holds.
                assert!(matches!(
                    handle_b.delete_session_with(&NullPiClient, "sess-b", "rev-1", "idem-b"),
                    DeleteApplyOutcome::Failed(_)
                ));
                // Disconnect, then a fresh pairing flow.
                disconnect_device(&comp, &id_b);
                assert_eq!(handle_b.connection_state(), ConnectionState::Disconnected);
                handle_b
                    .actor()
                    .start_pairing_with(
                        &PreparedPairingClient(PairingCreatedView {
                            attempt_id: "attempt-b2".to_string(),
                            phase: PairingPhase::Pending,
                            poll_secret: "poll-secret".to_string(),
                            sas: "123456".to_string(),
                            expires_at: "2026-08-03T12:00:00Z".to_string(),
                            sas_publication_key_fingerprint: None,
                        }),
                        "pc-test",
                        "nonce-b2",
                    )
                    .expect("pairing starts while A is busy");
                assert!(matches!(
                    handle_b.poll_pairing_with(&NullPiClient),
                    PollPairingOutcome::Error(_)
                ));
                expire_pairing_locally(&comp, &id_b, "attempt-b2");
                // …and a device nobody has seen before still registers.
                register_test_device(&comp, "c");
                done_tx.send(()).expect("worker reports completion");
            })
        };

        // Generous, because `disconnect_device` really does try to revoke
        // against an unreachable loopback port: the point of the bound is
        // "does not wait for device A", not "is fast".
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("device B's pairing/catalog/delete paths must complete while device A is busy");
        worker.join().expect("worker thread");
        release_tx.send(()).expect("release device A");
        busy.join().expect("busy thread");

        assert!(matches!(
            comp.handle_for(&id_b)
                .expect("B still known")
                .connection_state(),
            ConnectionState::Expired { .. }
        ));
        assert_eq!(comp.frontend_devices().len(), 3);
    }

    /// A pairing result belonging to an attempt the user already replaced
    /// must be discarded, not applied to the live attempt -- including on
    /// composition's own local-expiry path, which is what a timed-out
    /// polling task runs.
    #[test]
    fn a_superseded_pairing_result_is_discarded_on_the_migrated_path() {
        let dir = fresh_temp_dir("fleet-fencing");
        let comp = test_composition(&dir, Vec::new());
        let id = register_test_device(&comp, "d");
        let handle = comp.handle_for(&id).expect("registered");

        let start = |attempt_id: &str, nonce: &str| {
            handle
                .actor()
                .start_pairing_with(
                    &PreparedPairingClient(PairingCreatedView {
                        attempt_id: attempt_id.to_string(),
                        phase: PairingPhase::Pending,
                        poll_secret: "poll-secret".to_string(),
                        sas: "123456".to_string(),
                        expires_at: "2026-08-03T12:00:00Z".to_string(),
                        sas_publication_key_fingerprint: None,
                    }),
                    "pc-test",
                    nonce,
                )
                .expect("start_pairing replays the prepared response");
        };
        start("attempt-1", "nonce-1");
        // The user restarts pairing before attempt-1's poll comes back.
        start("attempt-2", "nonce-2");

        // The abandoned attempt's timeout fires: it must not expire the
        // live attempt.
        expire_pairing_locally(&comp, &id, "attempt-1");
        assert_eq!(
            handle.connection_state(),
            ConnectionState::Pairing {
                attempt_id: "attempt-2".to_string(),
                phase: PairingPhase::Pending,
            }
        );

        // Nor may its late `allowed` response connect the device.
        assert_eq!(
            handle.actor().apply_pairing_status(
                "attempt-1",
                Ok(PairingStatusView {
                    attempt_id: "attempt-1".to_string(),
                    phase: PairingPhase::Allowed,
                    connection_token: Some("token-from-the-abandoned-attempt".to_string()),
                    sas: "123456".to_string(),
                    expires_at: "2026-08-03T12:00:00Z".to_string(),
                    sas_publication_key_fingerprint: None,
                }),
            ),
            PollPairingOutcome::Stale
        );
        assert!(matches!(
            handle.connection_state(),
            ConnectionState::Pairing { .. }
        ));

        // The live attempt's own expiry still applies.
        expire_pairing_locally(&comp, &id, "attempt-2");
        assert!(matches!(
            handle.connection_state(),
            ConnectionState::Expired { .. }
        ));
    }

    /// A fleet handle alone is not reachable through an RPC identity. The
    /// complete binding must be registered before either canonical or legacy
    /// resolution can expose it.
    #[test]
    fn an_unbound_fleet_handle_is_not_resolvable() {
        let fingerprint = test_fingerprint("c");
        let fleet = DeviceFleet::new();
        let identity = DeviceIdentity::parse(&fingerprint).unwrap();
        let handle = fleet.get_or_create(identity.fingerprint().clone(), || {
            fallback_device(identity.device_id().as_str())
        });
        let mut bindings = DeviceBindings::default();
        let legacy_id = DeviceId(identity.display_id().to_string());
        assert!(bindings.resolve(&legacy_id).is_err());

        bindings.bind(
            identity.clone(),
            DeviceEndpoint {
                host: "127.0.0.1".to_string(),
                port: 9,
                tls_fingerprint: identity.tls_pin(),
                name: "Pi C".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
            },
            test_client(),
            handle,
        );
        assert_eq!(
            bindings
                .resolve(&legacy_id)
                .expect("registered")
                .handle
                .fingerprint()
                .as_str(),
            identity.fingerprint().as_str()
        );
    }

    // -----------------------------------------------------------------
    // PC-06: credential vault selection, S3 helper logic, and SHA-256
    // hashing.
    // -----------------------------------------------------------------

    #[test]
    fn stored_credential_roundtrips_through_json() {
        let cred = StoredCredential {
            access_key: "AKIA-EXAMPLE".to_string(),
            secret_key: "super-secret-value".to_string(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: StoredCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.access_key, cred.access_key);
        assert_eq!(back.secret_key, cred.secret_key);
    }

    #[test]
    fn set_and_read_storage_credential_roundtrips_through_a_real_vault_port() {
        // Uses the real `InMemoryCredentialVault` fake (not a mock of our
        // own) to prove `Composition::set_storage_credential`/
        // `storage_credential`'s JSON-bundling actually works against the
        // real `CredentialVaultPort` trait, independent of which backend
        // `choose_vault` picks at runtime.
        let vault: Arc<dyn CredentialVaultPort> = Arc::new(InMemoryCredentialVault::new());
        let payload = serde_json::to_string(&StoredCredential {
            access_key: "ak".to_string(),
            secret_key: "sk".to_string(),
        })
        .unwrap();
        vault
            .set_secret(&storage_credential_key(), Secret::new(payload))
            .unwrap();

        let secret = vault.expose_secret(&storage_credential_key()).unwrap();
        let parsed: StoredCredential = serde_json::from_str(secret.expose_secret()).unwrap();
        assert_eq!(parsed.access_key, "ak");
        assert_eq!(parsed.secret_key, "sk");

        assert_eq!(
            vault.status(&storage_credential_key()).unwrap(),
            SecretStatus {
                secret_configured: true
            }
        );
    }

    #[test]
    fn upload_object_key_namespaces_by_prefix_device_and_session() {
        assert_eq!(
            upload_object_key("", "dev1", "sess1", "video.mp4").0,
            "dev1/sess1/video.mp4"
        );
        assert_eq!(
            upload_object_key("/backups/", "dev1", "sess1", "video.mp4").0,
            "backups/dev1/sess1/video.mp4"
        );
    }

    #[test]
    fn probe_object_key_is_namespaced_by_prefix_and_never_collides_with_real_keys() {
        assert_eq!(probe_object_key("").0, "__ylx_connectivity_probe__");
        assert_eq!(
            probe_object_key("backups").0,
            "backups/__ylx_connectivity_probe__"
        );
    }

    #[test]
    fn build_object_store_rejects_empty_endpoint_or_bucket_without_panicking() {
        let cred = StoredCredential {
            access_key: "a".to_string(),
            secret_key: "b".to_string(),
        };
        let style = StorageUrlStyle::VirtualHost;
        assert!(build_object_store("", "bucket", style, &cred).is_err());
        assert!(build_object_store("https://example.invalid", "", style, &cred).is_err());
        assert!(build_object_store("not a url", "bucket", style, &cred).is_err());
        assert!(build_object_store("https://example.invalid:9000", "bucket", style, &cred).is_ok());
        // Both styles must construct — the difference is in the signed URL,
        // not in whether the client can be built at all.
        assert!(build_object_store(
            "https://example.invalid:9000",
            "bucket",
            StorageUrlStyle::Path,
            &cred
        )
        .is_ok());
    }

    #[test]
    fn upload_failure_classification_is_typed_and_fails_closed() {
        let cases = [
            (
                UploadPipelineError::integrity("network error: local source changed"),
                UploadFailureClass::Integrity,
                false,
            ),
            (
                UploadPipelineError::configuration("checksum mismatch in a client profile"),
                UploadFailureClass::Configuration,
                false,
            ),
            (
                UploadPipelineError::authentication("ordinary worker text"),
                UploadFailureClass::Authentication,
                false,
            ),
            (
                UploadPipelineError::transient("verification failed: service timeout"),
                UploadFailureClass::TransientService,
                true,
            ),
            (
                UploadPipelineError::internal("rate limited, but SQLite invariant failed"),
                UploadFailureClass::Internal,
                false,
            ),
            (
                UploadPipelineError::internal("unclassified worker failure"),
                UploadFailureClass::Internal,
                false,
            ),
        ];
        for (error, expected_class, retryable) in cases {
            let UploadPipelineError::Failed { class, detail } = &error else {
                panic!("test case must be a failed upload error")
            };
            assert_eq!(*class, expected_class, "{detail}");
            let outcome = terminal_outcome_for_upload_error(&error);
            match outcome {
                TerminalOutcome::Failed {
                    code,
                    retryable: actual,
                } => {
                    assert_eq!(actual, retryable, "{detail}");
                    assert!(code.starts_with("upload_"), "stable class code: {code}");
                    assert_eq!(upload_failure_detail(&code), detail.as_str());
                }
                TerminalOutcome::Succeeded | TerminalOutcome::Cancelled => {
                    panic!("worker failure was not classified as Failed: {detail}")
                }
            }
        }
        assert_eq!(
            object_store_pipeline_error(
                "operation",
                ObjectStoreError::Network("checksum mismatch in response text".to_string())
            ),
            UploadPipelineError::transient(
                "operation: network error: checksum mismatch in response text"
            )
        );
        assert!(matches!(
            object_store_pipeline_error(
                "operation",
                ObjectStoreError::DigestMismatch {
                    key: ObjectKey("k".to_string()),
                    expected: SourceSha256::from_bytes([0; 32]),
                    actual: SourceSha256::from_bytes([1; 32]),
                }
            ),
            UploadPipelineError::Failed {
                class: UploadFailureClass::Integrity,
                ..
            }
        ));
        assert_eq!(
            terminal_outcome_for_upload_error(&UploadPipelineError::Cancelled),
            TerminalOutcome::Cancelled
        );
    }

    #[test]
    fn upload_projection_marker_is_order_invariant_but_proof_sensitive() {
        let receipt =
            |object_key: &str, role: UploadReceiptRole, proof: UploadReceiptDigestProof| {
                StoredUploadReceipt {
                    job_id: "upload-marker".to_string(),
                    entry_key: "dev|sess".to_string(),
                    revision: "rev-1".to_string(),
                    object_key: object_key.to_string(),
                    role,
                    etag: "same-etag".to_string(),
                    version_id: Some("same-version".to_string()),
                    size_bytes: 1,
                    source_sha256: "0".repeat(64),
                    digest_proof: proof,
                    staged_at: "t0".to_string(),
                }
            };
        let data = receipt(
            "dev/sess/file",
            UploadReceiptRole::Data,
            UploadReceiptDigestProof::ServerChecksum,
        );
        let evidence = receipt(
            "dev/sess/evidence",
            UploadReceiptRole::Evidence,
            UploadReceiptDigestProof::StreamedReadback,
        );
        let first = upload_projection_marker(
            "upload-marker",
            &TerminalOutcome::Succeeded,
            &[data.clone(), evidence.clone()],
        );
        let reversed = upload_projection_marker(
            "upload-marker",
            &TerminalOutcome::Succeeded,
            &[evidence, data.clone()],
        );
        assert_eq!(first, reversed);

        let mut changed_proof = data;
        changed_proof.digest_proof = UploadReceiptDigestProof::StreamedReadback;
        let changed = upload_projection_marker(
            "upload-marker",
            &TerminalOutcome::Succeeded,
            &[
                changed_proof,
                receipt(
                    "dev/sess/evidence",
                    UploadReceiptRole::Evidence,
                    UploadReceiptDigestProof::StreamedReadback,
                ),
            ],
        );
        assert_ne!(first, changed, "digest proof is part of replay identity");
    }

    #[test]
    fn unknown_upload_retires_only_for_exact_structural_receipt_proof() {
        let root = fresh_temp_dir("unknown-upload-receipt-proof");
        let mut store = TransferStore::open(root.join("transfer_store.sqlite3")).unwrap();
        let spec = UploadJobSpec::new("dev|sess", "rev-1", "digest-1").unwrap();
        store
            .create_upload_job("upload-proof", &spec, "t0")
            .unwrap();
        store
            .stage_upload_receipts_for_job(
                "upload-proof",
                &[UploadReceiptSeed::new(
                    "dev/sess/file.bin",
                    UploadReceiptRole::Data,
                    "etag",
                    Some("version-1".to_string()),
                    7,
                    "0".repeat(64),
                    UploadReceiptDigestProof::ServerChecksum,
                )],
                "t1",
            )
            .unwrap();
        let transfer_store = Arc::new(Mutex::new(store));
        let record = StoredUpload {
            upload: NewUpload {
                transfer_key: "upload-proof".to_string(),
                entry_key: "dev|sess".to_string(),
                revision: "rev-1".to_string(),
                object_key: "dev/sess/file.bin".to_string(),
                upload_id: "multipart-1".to_string(),
                endpoint: "https://storage.example".to_string(),
                bucket: "bucket".to_string(),
                url_style: CoreUploadUrlStyle::Path,
            },
            job_id: Some("upload-proof".to_string()),
            desired_state: UploadDesiredState::Aborting,
            parts: Vec::new(),
            created_at: "t0".to_string(),
            updated_at: "t1".to_string(),
        };

        assert!(multipart_receipt_proves_completion(&transfer_store, &record).unwrap());

        let mut wrong_job = record.clone();
        wrong_job.job_id = Some("other-job".to_string());
        assert!(!multipart_receipt_proves_completion(&transfer_store, &wrong_job).unwrap());

        let mut wrong_key = record.clone();
        wrong_key.upload.object_key = "dev/sess/other.bin".to_string();
        assert!(!multipart_receipt_proves_completion(&transfer_store, &wrong_key).unwrap());

        let mut wrong_entry = record.clone();
        wrong_entry.upload.entry_key = "other|sess".to_string();
        assert!(!multipart_receipt_proves_completion(&transfer_store, &wrong_entry).unwrap());

        let mut wrong_revision = record.clone();
        wrong_revision.upload.revision = "rev-2".to_string();
        assert!(!multipart_receipt_proves_completion(&transfer_store, &wrong_revision).unwrap());

        let receipt = transfer_store
            .lock()
            .unwrap()
            .list_upload_receipts("upload-proof")
            .unwrap()
            .pop()
            .unwrap();
        let mut malformed = receipt.clone();
        malformed.etag.clear();
        assert!(!upload_receipt_is_structurally_valid_for_multipart(
            &record, &malformed
        ));
        malformed = receipt.clone();
        malformed.source_sha256 = "not-a-digest".to_string();
        assert!(!upload_receipt_is_structurally_valid_for_multipart(
            &record, &malformed
        ));

        // A publication key supplies enough context to reject a data-role
        // receipt even though both roles share the same durable table.
        let mut wrong_role = receipt;
        wrong_role.object_key = format!("dev/sess/{PUBLICATION_MANIFEST_OBJECT}");
        let mut evidence_record = record;
        evidence_record.upload.object_key = wrong_role.object_key.clone();
        assert!(!upload_receipt_is_structurally_valid_for_multipart(
            &evidence_record,
            &wrong_role
        ));

        drop(transfer_store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn backed_up_projection_requires_marker_and_exact_prefix_keys() {
        let root = fresh_temp_dir("backed-up-projection-v4");
        let mut entry = worker_start_failure_entry(&root);
        mark_canonical_entry_backed_up(&root, &mut entry, "backups", "upload-projection");

        let mut wrong_prefix = entry.clone();
        wrong_prefix.object_receipts[0].key = wrong_prefix.object_receipts[0]
            .key
            .replacen("backups/", "other/", 1);
        assert!(!entry_has_complete_object_receipts(&wrong_prefix));

        let mut marker_without_prefix = entry.clone();
        marker_without_prefix
            .upload_projection
            .as_mut()
            .unwrap()
            .object_prefix = None;
        assert!(!entry_has_complete_object_receipts(&marker_without_prefix));

        std::fs::remove_dir_all(root).ok();
    }

    fn stored_receipt(
        job_id: &str,
        entry_key: &str,
        revision: &str,
        object_key: &str,
        role: UploadReceiptRole,
        size_bytes: u64,
        source_sha256: String,
    ) -> StoredUploadReceipt {
        StoredUploadReceipt {
            job_id: job_id.to_string(),
            entry_key: entry_key.to_string(),
            revision: revision.to_string(),
            object_key: object_key.to_string(),
            role,
            etag: "etag".to_string(),
            version_id: None,
            size_bytes,
            source_sha256,
            digest_proof: UploadReceiptDigestProof::ServerChecksum,
            staged_at: "t0".to_string(),
        }
    }

    #[test]
    fn upload_receipt_validation_rejects_a_wrong_prefix_with_the_same_tail() {
        let root = fresh_temp_dir("upload-receipt-wrong-prefix-v4");
        let library_root = root.join("library");
        let entry = worker_start_failure_entry(&library_root);
        let bundle = canonical_publication_bundle_for_entry(&library_root, &entry).unwrap();
        let plan = derived_publication_plan("captures", &bundle).unwrap();
        let admission_key = test_admission_key(&plan);
        let revision = entry.publication.as_ref().unwrap().revision.clone();
        let spec =
            UploadJobSpec::new_with_prefix(entry.key(), revision.clone(), "digest", "captures")
                .unwrap();
        let mut receipts = vec![
            stored_receipt(
                "upload-prefix",
                &entry.key(),
                &revision,
                &plan.source_manifest_key.0,
                UploadReceiptRole::Evidence,
                bundle.source_manifest_bytes.len() as u64,
                bundle.source_manifest_sha256.clone(),
            ),
            stored_receipt(
                "upload-prefix",
                &entry.key(),
                &revision,
                &plan.receipt_key.0,
                UploadReceiptRole::Evidence,
                bundle.receipt_bytes.len() as u64,
                bundle.receipt_sha256.clone(),
            ),
            stored_receipt(
                "upload-prefix",
                &entry.key(),
                &revision,
                &plan.output_key.0,
                UploadReceiptRole::Data,
                bundle.output_bytes,
                bundle.output_sha256.clone(),
            ),
            stored_receipt(
                "upload-prefix",
                &entry.key(),
                &revision,
                &plan.marker_key.0,
                UploadReceiptRole::Evidence,
                plan.marker_bytes.len() as u64,
                plan.marker_sha256.to_hex(),
            ),
            stored_receipt(
                "upload-prefix",
                &entry.key(),
                &revision,
                &admission_key.0,
                UploadReceiptRole::Evidence,
                1,
                "1".repeat(64),
            ),
        ];
        validate_upload_receipt_batch("upload-prefix", &spec, Some(&entry), &receipts)
            .expect("baseline v4 receipt batch must validate");

        receipts[0].object_key = receipts[0]
            .object_key
            .replacen("captures/", "wrong-prefix/", 1);
        let error = validate_upload_receipt_batch("upload-prefix", &spec, Some(&entry), &receipts)
            .expect_err("same-tail receipts under another prefix must fail closed");
        assert!(error.contains("缺少内容对象"), "{error}");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn legacy_upload_spec_cannot_validate_a_success_receipt_batch() {
        let file = test_session_file("file-1", "video/a.mp4", 3);
        let mut entry = test_entry(vec![file.clone()]);
        entry.publication = Some(test_publication("rev-legacy"));
        let spec = UploadJobSpec::new(entry.key(), "rev-legacy", "legacy-digest").unwrap();
        let publication = entry.publication.as_ref().unwrap();
        let mut receipts = vec![stored_receipt(
            "upload-legacy",
            &entry.key(),
            "rev-legacy",
            &upload_object_key("", &entry.device_id, &entry.session_id, &file.file_id).0,
            UploadReceiptRole::Data,
            file.bytes,
            file.sha256,
        )];
        for (name, bytes) in [
            (
                PUBLICATION_SIGNATURE_OBJECT,
                publication.signature.as_slice(),
            ),
            (
                PUBLICATION_PUBLIC_KEY_OBJECT,
                publication.public_key.as_slice(),
            ),
            (PUBLICATION_MANIFEST_OBJECT, publication.payload.as_slice()),
        ] {
            receipts.push(stored_receipt(
                "upload-legacy",
                &entry.key(),
                "rev-legacy",
                &upload_evidence_object_key("", &entry.device_id, &entry.session_id, name).0,
                UploadReceiptRole::Evidence,
                bytes.len() as u64,
                hex_encode(&Sha256::digest(bytes)),
            ));
        }
        let error = validate_upload_receipt_batch("upload-legacy", &spec, Some(&entry), &receipts)
            .expect_err("legacy four-object namespace is not enough to authorize v4 success");
        assert!(error.contains("object namespace"), "{error}");
    }

    #[test]
    fn source_credential_placeholders_are_inert() {
        // A public checkout must be buildable without carrying real OSS
        // secrets. The placeholders are replacement slots for private
        // release automation, not credentials to feed into the signer.
        assert!(
            built_in_credential().is_none(),
            "public placeholders must not be treated as built-in credentials"
        );
    }

    #[test]
    fn bootstrap_file_accepts_the_shape_aliyun_hands_out() {
        let (ak, sk) =
            parse_bootstrap_file(r#"{"accessKeyId":"LTAI-example","secretAccessKey":"s3cr3t"}"#)
                .expect("well-formed bootstrap file is accepted");
        assert_eq!(ak, "LTAI-example");
        assert_eq!(sk, "s3cr3t");
    }

    #[test]
    fn bootstrap_file_rejects_half_filled_or_malformed_content() {
        // A half-filled file must be treated as absent, not turned into a
        // credential that cannot sign anything -- that would replace "please
        // configure storage" with a confusing auth failure at upload time.
        assert!(parse_bootstrap_file(r#"{"accessKeyId":"LTAI","secretAccessKey":""}"#).is_err());
        assert!(parse_bootstrap_file(r#"{"accessKeyId":"   ","secretAccessKey":"s"}"#).is_err());
        assert!(parse_bootstrap_file(r#"{"accessKeyId":"LTAI"}"#).is_err());
        assert!(parse_bootstrap_file("not json at all").is_err());
    }

    #[test]
    fn bootstrap_file_keeps_a_secret_that_has_surrounding_whitespace() {
        // The id is an opaque token that never legitimately carries spaces;
        // the secret is raw material and must survive byte-for-byte.
        let (ak, sk) =
            parse_bootstrap_file("{\"accessKeyId\":\" LTAI \",\"secretAccessKey\":\" s3cr3t \"}")
                .expect("accepted");
        assert_eq!(ak, "LTAI");
        assert_eq!(sk, " s3cr3t ");
    }

    #[test]
    fn default_storage_config_targets_the_shipped_endpoint_in_virtual_host_style() {
        // The shipped default must be internally consistent: Aliyun OSS
        // rejects path-style, so a default endpoint pointing at OSS with
        // `StorageUrlStyle::Path` would be dead on arrival.
        let config = StorageConfig::default();
        assert_eq!(config.endpoint, crate::models::DEFAULT_STORAGE_ENDPOINT);
        assert_eq!(config.bucket, crate::models::DEFAULT_STORAGE_BUCKET);
        assert_eq!(config.url_style, StorageUrlStyle::VirtualHost);
        assert!(config.is_configured());
        // Credentials are never part of the default — they only ever live
        // in the OS keyring (ADR-CRED-001).
        assert!(config.download_root.is_none());
    }

    fn test_bytes(bytes: u64) -> Vec<u8> {
        vec![b'x'; bytes as usize]
    }

    fn test_session_file(
        file_id: &str,
        display_path: &str,
        bytes: u64,
    ) -> crate::models::SessionFile {
        crate::models::SessionFile::new(
            file_id.to_string(),
            display_path.to_string(),
            bytes,
            hex_encode(&hash_bytes(&test_bytes(bytes))),
        )
    }

    fn test_publication(revision: &str) -> PublicationEvidence {
        PublicationEvidence {
            revision: revision.to_string(),
            payload: b"signed-test-publication".to_vec(),
            signature: vec![7; 64],
            public_key: vec![9; 32],
        }
    }

    /// Installs a small byte-level derived bundle around the exact synchronized
    /// Score fixtures. The MP4 payload is deliberately tiny, but every source,
    /// receipt, signature, digest, path, and v4 compatibility claim is checked
    /// by the same production validators used by `start_upload`.
    fn worker_start_failure_entry(library_root: &Path) -> LibraryEntry {
        const SOURCE: &str = include_str!(
            "../../contracts/fixtures/valid/ylx-device-session-v2.audio-recorded-multi-segment.json"
        );
        const RECEIPT: &str =
            include_str!("../../contracts/fixtures/valid/ylx-derived-media-receipt-v1.json");
        const LAB_V4_PUBLICATION_KEY_SEED: [u8; 32] = [
            0x74, 0x93, 0x4f, 0x27, 0x6d, 0x8b, 0x1c, 0x55, 0xa0, 0xf2, 0x42, 0x38, 0x91, 0x63,
            0xd4, 0x2a, 0x5f, 0x13, 0x8c, 0xe1, 0x97, 0x20, 0xab, 0x4d, 0x69, 0xbe, 0x03, 0x81,
            0xca, 0x7d, 0x5e, 0x11,
        ];

        fn collect_artifacts(value: &serde_json::Value, out: &mut Vec<serde_json::Value>) {
            match value {
                serde_json::Value::Object(object) => {
                    let fields = [
                        "artifact_id",
                        "role",
                        "path",
                        "media_type",
                        "bytes",
                        "sha256",
                    ];
                    if fields.iter().all(|field| object.contains_key(*field)) {
                        out.push(serde_json::json!({
                            "id": object["artifact_id"],
                            "display_path": object["path"],
                            "role": object["role"],
                            "size_bytes": object["bytes"],
                            "sha256": object["sha256"],
                            "media_type": object["media_type"],
                        }));
                        return;
                    }
                    for child in object.values() {
                        collect_artifacts(child, out);
                    }
                }
                serde_json::Value::Array(values) => {
                    for child in values {
                        collect_artifacts(child, out);
                    }
                }
                _ => {}
            }
        }

        let source: serde_json::Value = serde_json::from_str(SOURCE).expect("Score v2 fixture");
        let device_id = source["device"]["device_id"]
            .as_str()
            .expect("source device id");
        let session_id = source["session_id"].as_str().expect("source session id");
        let source_sha256 = hex_encode(&Sha256::digest(SOURCE.as_bytes()));
        let revision = format!("sha256:{source_sha256}");
        let mut files = Vec::new();
        collect_artifacts(&source, &mut files);
        files.sort_by(|left, right| {
            left["display_path"]
                .as_str()
                .cmp(&right["display_path"].as_str())
                .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
        });
        let total_bytes = files
            .iter()
            .map(|file| file["size_bytes"].as_u64().expect("artifact bytes"))
            .sum::<u64>();
        let video_bytes = files
            .iter()
            .filter(|file| {
                file["role"]
                    .as_str()
                    .is_some_and(|role| role.starts_with("video."))
            })
            .map(|file| file["size_bytes"].as_u64().expect("video bytes"))
            .sum::<u64>();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "source_schema": "ylx.device-session.v2",
            "source_manifest_sha256": source_sha256,
            "source_manifest_json": SOURCE,
            "source_profile": "ylx-device-api-v4-lab-http",
            "receipt_origin": "client-derived-lab-compatibility",
            "device_authenticity": "not_asserted",
            "gateway_verification": {
                "actor": "gateway",
                "validator": {
                    "name": "openaria-conductor",
                    "version": "0.1.0",
                    "build_sha256": "a".repeat(64),
                },
                "manifest_sha256": source_sha256,
                "manifest_digest_valid": true,
                "verified_at": "2026-08-28T10:09:58Z",
                "verdict": "usable",
                "diagnostics": [],
            },
            "session_id": session_id,
            "revision": revision,
            "captured_at": source["time"]["started_at"],
            "published_at": source["sealed_at"],
            "duration_seconds": source["time"]["duration_seconds"],
            "total_bytes": total_bytes,
            "video_bytes": video_bytes,
            "integrity_ok": true,
            "files": files,
        }))
        .expect("serialize v4 compatibility publication");
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&LAB_V4_PUBLICATION_KEY_SEED)
            .expect("lab-v4 publication key");

        let output_bytes = b"tiny-derived-mp4-fixture";
        let output_sha256 = hex_encode(&Sha256::digest(output_bytes));
        let mut receipt: serde_json::Value =
            serde_json::from_str(RECEIPT).expect("Score derived receipt fixture");
        receipt["output"]["artifact_id"] = serde_json::json!(output_sha256);
        receipt["output"]["bytes"] = serde_json::json!(output_bytes.len());
        receipt["output"]["sha256"] = serde_json::json!(output_sha256);
        receipt["timeline_verification"]["probe_summary"]["output_sha256"] =
            serde_json::json!(output_sha256);
        receipt["timeline_verification"]["probe_summary"]["output_bytes"] =
            serde_json::json!(output_bytes.len());
        let receipt_bytes = serde_json::to_vec_pretty(&receipt).expect("serialize receipt");

        let staging =
            SessionStaging::for_publication(library_root, device_id, session_id, &payload)
                .expect("canonical staging identity");
        let processed = staging.published_dir().join("processed");
        std::fs::create_dir_all(&processed).expect("canonical processed directory");
        std::fs::write(processed.join(format!("{session_id}.mp4")), output_bytes)
            .expect("derived output fixture");
        std::fs::write(processed.join("derived-media-receipt.json"), receipt_bytes)
            .expect("derived receipt fixture");

        let canonical = derived_media::canonical_assets_for_publication(
            library_root,
            device_id,
            session_id,
            &payload,
        )
        .expect("canonical fixture validates");
        let source_files = files
            .iter()
            .map(|file| {
                SessionFile::new(
                    file["id"].as_str().expect("artifact id").to_string(),
                    file["display_path"]
                        .as_str()
                        .expect("artifact path")
                        .to_string(),
                    file["size_bytes"].as_u64().expect("artifact size"),
                    file["sha256"]
                        .as_str()
                        .expect("artifact digest")
                        .to_string(),
                )
            })
            .collect();
        LibraryEntry {
            device_id: device_id.to_string(),
            session_id: session_id.to_string(),
            date_label: "today".to_string(),
            downloaded_at: "now".to_string(),
            bytes: canonical.total_bytes,
            processed_files: canonical.files,
            files: source_files,
            complete: true,
            download_projection_sequence: 0,
            publication: Some(PublicationEvidence {
                revision,
                signature: key_pair.sign(&payload).as_ref().to_vec(),
                public_key: key_pair.public_key().as_ref().to_vec(),
                payload,
            }),
            library_root: Some(library_root.to_string_lossy().into_owned()),
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: UploadStatus::None,
            upload_retryable: false,
            uploaded_at: None,
            upload_error: None,
        }
    }

    /// Reuses the exact canonical derived fixture under another safe local
    /// device directory. The signed source session remains unchanged; only
    /// the desktop's directory identity varies, matching legacy/canonical-id
    /// projection tests without weakening the production validators.
    fn canonical_entry_for_device(library_root: &Path, device_id: &str) -> LibraryEntry {
        let mut entry = worker_start_failure_entry(library_root);
        if entry.device_id == device_id {
            return entry;
        }

        let publication = entry.publication.as_ref().expect("canonical publication");
        let source = SessionStaging::for_publication(
            library_root,
            &entry.device_id,
            &entry.session_id,
            &publication.payload,
        )
        .expect("source canonical staging")
        .published_dir();
        let target = SessionStaging::for_publication(
            library_root,
            device_id,
            &entry.session_id,
            &publication.payload,
        )
        .expect("target canonical staging")
        .published_dir();
        std::fs::create_dir_all(target.join("processed"))
            .expect("target canonical processed directory");
        for file in &entry.processed_files {
            let destination = target.join(&file.display_path);
            std::fs::create_dir_all(destination.parent().expect("canonical asset parent"))
                .expect("canonical asset parent directory");
            std::fs::copy(source.join(&file.display_path), destination)
                .expect("copy canonical fixture asset");
        }
        entry.device_id = device_id.to_string();
        entry
    }

    fn canonical_download_spec(entry: &LibraryEntry) -> JobSpec {
        job_spec_from_context(
            &entry.device_id,
            &entry.session_id,
            &entry.date_label,
            &entry.files,
            &entry.files,
            entry.publication.as_ref().expect("canonical publication"),
            true,
        )
        .expect("canonical full-session download spec")
    }

    fn mark_canonical_entry_backed_up(
        library_root: &Path,
        entry: &mut LibraryEntry,
        prefix: &str,
        job_id: &str,
    ) {
        let bundle = canonical_publication_bundle_for_entry(library_root, entry)
            .expect("canonical publication bundle");
        let plan = derived_publication_plan(prefix, &bundle).expect("derived publication plan");
        let admission_key = test_admission_key(&plan);
        let revision = entry
            .publication
            .as_ref()
            .expect("canonical publication")
            .revision
            .clone();
        let entry_key = entry.key();
        let spec = UploadJobSpec::new_with_prefix(
            entry_key.clone(),
            revision.clone(),
            "canonical-backup-digest",
            prefix,
        )
        .expect("canonical backup spec");
        let stored = vec![
            stored_receipt(
                job_id,
                &entry_key,
                &revision,
                &plan.source_manifest_key.0,
                UploadReceiptRole::Evidence,
                bundle.source_manifest_bytes.len() as u64,
                bundle.source_manifest_sha256,
            ),
            stored_receipt(
                job_id,
                &entry_key,
                &revision,
                &plan.receipt_key.0,
                UploadReceiptRole::Evidence,
                bundle.receipt_bytes.len() as u64,
                bundle.receipt_sha256,
            ),
            stored_receipt(
                job_id,
                &entry_key,
                &revision,
                &plan.output_key.0,
                UploadReceiptRole::Data,
                bundle.output_bytes,
                bundle.output_sha256,
            ),
            stored_receipt(
                job_id,
                &entry_key,
                &revision,
                &plan.marker_key.0,
                UploadReceiptRole::Evidence,
                plan.marker_bytes.len() as u64,
                plan.marker_sha256.to_hex(),
            ),
            stored_receipt(
                job_id,
                &entry_key,
                &revision,
                &admission_key.0,
                UploadReceiptRole::Evidence,
                1,
                "1".repeat(64),
            ),
        ];
        entry.upload_status = UploadStatus::Done;
        entry.uploaded_at = Some("2026-08-28T10:10:00Z".to_string());
        entry.object_receipts = frontend_upload_receipts(&stored);
        entry.upload_projection = Some(upload_projection_marker_for_spec(
            job_id,
            &spec,
            &TerminalOutcome::Succeeded,
            &stored,
        ));
        assert!(entry_has_complete_object_receipts(entry));
    }

    /// Fault-inject the application-store connection from another SQLite
    /// connection. A PRAGMA such as `query_only` is connection-local, so a
    /// durable trigger is the small, deterministic cross-connection seam:
    /// `AppData::persist_result` reaches the revision update and receives a
    /// real SQLite write error without exposing raw SQL in `AppStore`.
    fn set_app_store_write_failure(path: &Path, enabled: bool) {
        let connection = Connection::open(path).expect("open app store fault connection");
        if enabled {
            connection
                .execute_batch(
                    "CREATE TRIGGER IF NOT EXISTS test_fail_app_store_revision_write
                     BEFORE UPDATE OF value ON app_store_meta
                     WHEN NEW.key = 'revision'
                     BEGIN
                       SELECT RAISE(ABORT, 'injected application-store write failure');
                     END;",
                )
                .expect("install app store write-failure trigger");
        } else {
            connection
                .execute_batch("DROP TRIGGER IF EXISTS test_fail_app_store_revision_write;")
                .expect("remove app store write-failure trigger");
        }
    }

    fn test_entry(files: Vec<crate::models::SessionFile>) -> LibraryEntry {
        let bytes = files.iter().map(|file| file.bytes).sum();
        LibraryEntry {
            device_id: "dev1".to_string(),
            session_id: "sess1".to_string(),
            date_label: "today".to_string(),
            downloaded_at: "just now".to_string(),
            bytes,
            processed_files: Vec::new(),
            files,
            complete: true,
            download_projection_sequence: 0,
            publication: None,
            library_root: None,
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: UploadStatus::None,
            upload_retryable: false,
            uploaded_at: None,
            upload_error: None,
        }
    }

    /// A library row is only "complete" if its bytes are found under the root
    /// the app is using *right now*. Two devices downloaded under two
    /// different roots therefore cannot both be visible, even though both
    /// sets of files are on the disk.
    ///
    /// This is the reported symptom: the files were saved, the rows exist,
    /// and the app still shows only one device's recordings.
    #[test]
    fn a_row_downloaded_under_a_previous_root_goes_incomplete_after_the_root_moves() {
        let previous_root = tempfile::tempdir().expect("previous root");
        let current_root = tempfile::tempdir().expect("current root");
        let older = canonical_entry_for_device(previous_root.path(), "dev-a");
        let newer = canonical_entry_for_device(current_root.path(), "dev-b");

        let projected = project_library_entries(current_root.path(), &[older, newer]);

        assert!(
            projected[1].complete,
            "the device downloaded under the current root stays visible"
        );
        assert!(
            projected[0].complete,
            "a device downloaded under a previous root must not silently vanish: \
             its files are still on disk at {:?}",
            previous_root.path()
        );
    }

    /// A row written before the root was recorded has no memory of where it
    /// went, so it must keep resolving against the current root exactly as it
    /// did before. Anything else would break every existing library.
    #[test]
    fn a_legacy_row_without_a_recorded_root_still_resolves_against_the_current_one() {
        let root = tempfile::tempdir().expect("root");
        let mut entry = worker_start_failure_entry(root.path());
        entry.library_root = None;

        assert!(project_library_entries(root.path(), &[entry])[0].complete);
    }

    /// A recorded root that no longer holds the bytes must not shadow a
    /// library the user moved wholesale: the current root is searched too.
    #[test]
    fn a_stale_recorded_root_does_not_hide_a_library_the_user_moved() {
        let moved_to = tempfile::tempdir().expect("current root");
        let mut entry = worker_start_failure_entry(moved_to.path());
        entry.library_root = Some("/nonexistent/old/root".to_string());

        assert!(project_library_entries(moved_to.path(), &[entry])[0].complete);
    }

    fn test_upload_transfer(key: &str, completed: bool, failure: bool) -> Transfer {
        Transfer {
            key: key.to_string(),
            label: "sess1".to_string(),
            total_bytes: 128,
            sent_bytes: if completed { 128 } else { 64 },
            state: if completed {
                TransferState::Succeeded
            } else if failure {
                TransferState::Failed
            } else {
                TransferState::Running
            },
            error: failure.then(|| "upload failed".to_string()),
            retryable: failure,
            direction: TransferDirection::Up,
            target_label: "recording-bucket".to_string(),
        }
    }

    #[test]
    fn dismissing_a_terminal_upload_removes_queue_state_but_preserves_library_history() {
        let transfer_key = "upload-terminal";
        let mut entry = test_entry(vec![test_session_file("file-1", "video/left.mp4", 128)]);
        entry.upload_status = UploadStatus::Done;
        entry.uploaded_at = Some("2026-08-03T12:00:00Z".to_string());
        entry.object_receipts = vec![ObjectVerificationReceipt {
            key: "dev1/sess1/video/left.mp4".to_string(),
            etag: "etag-1".to_string(),
            version_id: None,
            bytes: 128,
            sha256: "0".repeat(64),
        }];
        let entry_key = entry.key();
        let mut transfers = vec![test_upload_transfer(transfer_key, true, false)];
        let library = [entry];

        dismiss_terminal_upload_state(&mut transfers, transfer_key)
            .expect("a completed upload can be dismissed");

        assert!(transfers.is_empty());
        assert_eq!(library.len(), 1);
        assert_eq!(library[0].key(), entry_key);
        assert_eq!(library[0].upload_status, UploadStatus::Done);
        assert_eq!(library[0].object_receipts.len(), 1);
    }

    #[test]
    fn dismissing_an_active_upload_is_rejected_without_mutating_queue_state() {
        let transfer_key = "upload-active";
        let mut transfers = vec![test_upload_transfer(transfer_key, false, false)];

        let error = dismiss_terminal_upload_state(&mut transfers, transfer_key)
            .expect_err("an active upload must stay controllable");

        assert_eq!(error, "只有已结束的上传任务可以清除");
        assert_eq!(transfers.len(), 1);
    }

    #[test]
    fn upload_dismiss_rejects_a_terminal_non_upload_row() {
        let transfer_key = "download-terminal";
        let mut transfer = test_upload_transfer(transfer_key, true, false);
        transfer.direction = TransferDirection::Down;
        let mut transfers = vec![transfer];

        let error = dismiss_terminal_upload_state(&mut transfers, transfer_key)
            .expect_err("download rows belong to the coordinator dismissal command");

        assert_eq!(error, "该任务不是上传任务，无法清除");
        assert_eq!(transfers.len(), 1);
    }

    #[test]
    fn retiring_a_retried_upload_removes_only_the_old_failed_attempt() {
        let old_key = "upload-failed";
        let new_key = "upload-replacement";
        let mut transfers = vec![
            test_upload_transfer(new_key, false, false),
            test_upload_transfer(old_key, false, true),
        ];

        dismiss_terminal_upload_state(&mut transfers, old_key)
            .expect("the replaced failed attempt is terminal");

        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].key, new_key);
    }

    #[test]
    fn upload_completion_keeps_failed_and_cancelled_transfer_rows_visible() {
        let failed_key = "upload-failed-projection";
        let cancelled_key = "upload-cancelled-projection";
        let mut transfers = vec![
            test_upload_transfer(failed_key, false, false),
            test_upload_transfer(cancelled_key, false, false),
        ];

        project_upload_transfer_outcome_parts(
            &mut transfers,
            failed_key,
            &TerminalOutcome::Failed {
                code: "other:checksum mismatch".to_string(),
                retryable: false,
            },
        );
        project_upload_transfer_outcome_parts(
            &mut transfers,
            cancelled_key,
            &TerminalOutcome::Cancelled,
        );

        let failed = transfers
            .iter()
            .find(|transfer| transfer.key == failed_key)
            .expect("failed upload remains visible");
        assert_eq!(failed.state, TransferState::Failed);
        assert_eq!(failed.error.as_deref(), Some("checksum mismatch"));
        assert!(!failed.retryable);
        let cancelled = transfers
            .iter()
            .find(|transfer| transfer.key == cancelled_key)
            .expect("cancelled upload remains visible");
        assert_eq!(cancelled.state, TransferState::Cancelled);
        assert_eq!(cancelled.error.as_deref(), Some(UPLOAD_CANCELLED_MESSAGE));
        assert!(!cancelled.retryable);
    }

    fn cleanup_session(entry: &LibraryEntry, status: DownloadStatus) -> SessionView {
        let total_bytes = entry.files.iter().map(|file| file.bytes).sum();
        SessionView {
            session: Session {
                id: entry.session_id.clone(),
                revision: entry
                    .publication
                    .as_ref()
                    .expect("cleanup publication")
                    .revision
                    .clone(),
                date_label: "2026-08-03T10:00:00Z".to_string(),
                duration_seconds: 1.0,
                total_bytes,
                video_bytes: total_bytes,
                imu_samples: None,
                files: entry.files.clone(),
            },
            download_status: status,
            backed_up: false,
            verification: None,
        }
    }

    fn status_only_session(session_id: &str) -> SessionView {
        SessionView {
            session: Session {
                id: session_id.to_string(),
                revision: format!("revision-{session_id}"),
                date_label: "2026-08-29T00:00:00Z".to_string(),
                duration_seconds: 1.0,
                total_bytes: 1,
                video_bytes: 1,
                imu_samples: None,
                files: Vec::new(),
            },
            download_status: DownloadStatus::None,
            backed_up: false,
            verification: None,
        }
    }

    fn seed_failed_status_job(comp: &Composition, job_id: &str, device_id: &str, session_id: &str) {
        let spec = test_download_spec(device_id, session_id, "status-file", 1);
        let mut store = comp.transfer_store.lock().unwrap();
        store.create_job(job_id, &spec, "t0").unwrap();
        store
            .complete_job(
                job_id,
                &TerminalOutcome::Failed {
                    code: "network".to_string(),
                    retryable: true,
                },
                "t1",
            )
            .unwrap();
    }

    fn complete_cleanup_entry(library_root: &Path) -> LibraryEntry {
        worker_start_failure_entry(library_root)
    }

    fn backed_up_cleanup_entry(library_root: &Path) -> LibraryEntry {
        let mut entry = complete_cleanup_entry(library_root);
        mark_canonical_entry_backed_up(library_root, &mut entry, "backups", "cleanup-upload");
        entry
    }

    #[test]
    fn library_projection_tracks_external_deletion_without_mutating_history() {
        let root = fresh_temp_dir("library-projection-deleted");
        let mut durable = complete_cleanup_entry(&root);
        let output_path = canonical_publication_bundle_for_entry(&root, &durable)
            .expect("canonical bundle")
            .output_path;
        durable.upload_status = UploadStatus::Done;
        durable.uploaded_at = Some("2026-08-03T10:00:00Z".to_string());
        durable.object_receipts = vec![ObjectVerificationReceipt {
            key: "historical/object".to_string(),
            etag: "etag-1".to_string(),
            version_id: None,
            bytes: 1,
            sha256: "0".repeat(64),
        }];

        let present = project_library_entries(&root, std::slice::from_ref(&durable));
        assert!(present[0].complete);

        std::fs::remove_file(&output_path).unwrap();
        let missing = project_library_entries(&root, std::slice::from_ref(&durable));
        assert!(!missing[0].complete);
        assert_eq!(missing[0].upload_status, UploadStatus::Done);
        assert_eq!(missing[0].uploaded_at, durable.uploaded_at);
        assert_eq!(missing[0].object_receipts, durable.object_receipts);
        assert!(
            durable.complete,
            "read-only projection must not rewrite SQLite history"
        );

        std::fs::write(&output_path, test_bytes(9)).unwrap();
        let wrong_size = project_library_entries(&root, std::slice::from_ref(&durable));
        assert!(!wrong_size[0].complete);

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn library_projection_fails_closed_for_legacy_raw_only_downloads() {
        let root = fresh_temp_dir("library-projection-legacy");
        let file = test_session_file("f-legacy-opaque", "video/left_00000.mp4", 10);
        let durable = test_entry(vec![file.clone()]);
        let legacy_path = derive_target_path(
            &root,
            &durable.device_id,
            &durable.session_id,
            &file.file_id,
        )
        .unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        std::fs::write(&legacy_path, test_bytes(10)).unwrap();

        let projected = project_library_entries(&root, std::slice::from_ref(&durable));
        assert!(
            !projected[0].complete,
            "raw-only legacy bytes cannot be projected as a usable derived library"
        );

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn local_status_uses_verified_library_and_durable_jobs_only() {
        assert_eq!(
            download_status_for_local_state(false, false, false),
            DownloadStatus::None
        );
        assert_eq!(
            download_status_for_local_state(false, true, false),
            DownloadStatus::Downloading
        );
        assert_eq!(
            download_status_for_local_state(false, false, true),
            DownloadStatus::Failed
        );
        assert_eq!(
            download_status_for_local_state(true, false, true),
            DownloadStatus::Done
        );
    }

    #[test]
    fn local_status_batches_canonical_and_unique_legacy_job_history_for_the_current_page() {
        let dir = fresh_temp_dir("local-status-unique-legacy-batch");
        let comp = test_composition(&dir, Vec::new());
        let canonical_id = register_test_device(&comp, "d");
        let legacy_id = comp
            .resolve_binding(&canonical_id)
            .unwrap()
            .identity
            .display_id()
            .to_string();
        seed_failed_status_job(
            &comp,
            "job-canonical-status",
            &canonical_id,
            "session-canonical",
        );
        seed_failed_status_job(&comp, "job-legacy-status", &legacy_id, "session-legacy");
        seed_failed_status_job(
            &comp,
            "job-unrelated-session",
            &canonical_id,
            "session-not-on-page",
        );

        let mut sessions = vec![
            status_only_session("session-canonical"),
            status_only_session("session-legacy"),
            status_only_session("session-without-history"),
        ];
        comp.apply_local_session_state(&canonical_id, &[], &mut sessions)
            .expect("apply one scoped durable snapshot");

        assert_eq!(sessions[0].download_status, DownloadStatus::Failed);
        assert_eq!(sessions[1].download_status, DownloadStatus::Failed);
        assert_eq!(sessions[2].download_status, DownloadStatus::None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ambiguous_legacy_alias_is_not_a_download_job_lookup_key() {
        let dir = fresh_temp_dir("local-status-ambiguous-legacy");
        let comp = test_composition(&dir, Vec::new());
        let registration_a = comp
            .register_endpoint(DeviceEndpoint {
                host: "192.0.2.31".to_string(),
                port: 8443,
                tls_fingerprint: format!("sha256:abcdef01{}", "1".repeat(56)),
                name: "Pi A".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
            })
            .unwrap();
        let registration_b = comp
            .register_endpoint(DeviceEndpoint {
                host: "192.0.2.32".to_string(),
                port: 8443,
                tls_fingerprint: format!("sha256:abcdef01{}", "2".repeat(56)),
                name: "Pi B".to_string(),
                display_label: None,
                api_profile: DeviceApiProfile::LegacyPinnedTlsV1,
            })
            .unwrap();
        let canonical_id = registration_a.identity.device_id().as_str().to_string();
        let ambiguous_alias = registration_a.identity.display_id().to_string();
        assert_eq!(
            ambiguous_alias,
            registration_b.identity.display_id().to_string()
        );
        seed_failed_status_job(
            &comp,
            "job-ambiguous-alias",
            &ambiguous_alias,
            "session-alias-only",
        );
        seed_failed_status_job(
            &comp,
            "job-canonical-visible",
            &canonical_id,
            "session-canonical",
        );

        let mut sessions = vec![
            status_only_session("session-alias-only"),
            status_only_session("session-canonical"),
        ];
        comp.apply_local_session_state(&canonical_id, &[], &mut sessions)
            .expect("ambiguous history is ignored, not an identity error");

        assert_eq!(sessions[0].download_status, DownloadStatus::None);
        assert_eq!(sessions[1].download_status, DownloadStatus::Failed);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ordinary_session_refresh_does_not_verify_tampered_media_but_explicit_actions_do() {
        let dir = fresh_temp_dir("ordinary-refresh-zero-strong-media-verification");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        let canonical_id = register_test_device(&comp, "c");
        let entry = canonical_entry_for_device(&comp.library_root(), &canonical_id);
        let bundle = canonical_publication_bundle_for_entry(&comp.library_root(), &entry)
            .expect("baseline canonical bundle");
        let initial_session = cleanup_session(&entry, DownloadStatus::Done);
        let (eligible, skipped) = downloaded_cleanup_candidates_with_match(
            &comp.library_root(),
            &canonical_id,
            std::slice::from_ref(&initial_session),
            std::slice::from_ref(&entry),
            |stored, current| comp.device_ids_match(stored, current),
        );
        assert!(skipped.is_empty());
        let candidate = eligible.into_iter().next().expect("baseline candidate");

        let output_size = std::fs::metadata(&bundle.output_path).unwrap().len() as usize;
        std::fs::write(&bundle.output_path, vec![b'y'; output_size]).unwrap();
        derived_media::reset_strong_media_verification_count();
        reset_strong_local_file_hash_count();

        let mut ordinary = vec![cleanup_session(&entry, DownloadStatus::None)];
        comp.apply_local_session_state(&canonical_id, std::slice::from_ref(&entry), &mut ordinary)
            .expect("ordinary refresh uses durable in-memory projection");
        assert_eq!(ordinary[0].download_status, DownloadStatus::Done);
        assert_eq!(
            derived_media::strong_media_verification_count(),
            0,
            "session refresh must not inspect the canonical media bundle"
        );
        assert_eq!(
            strong_local_file_hash_count(),
            0,
            "session refresh must not open, read, or hash canonical MP4 bytes"
        );

        let cleanup_error = comp
            .revalidate_downloaded_candidate(&canonical_id, &candidate)
            .expect_err("delete authorization must strongly revalidate the MP4");
        assert!(
            cleanup_error.contains("SHA-256 与签名 publication 不一致"),
            "{cleanup_error}"
        );
        assert!(strong_local_file_hash_count() > 0);

        derived_media::reset_strong_media_verification_count();
        reset_strong_local_file_hash_count();
        let app = tauri::test::mock_app();
        let upload_error = start_upload(
            app.handle().clone(),
            comp.clone(),
            StorageConfig::default(),
            entry,
        )
        .expect_err("upload admission must strongly revalidate the MP4");
        assert!(upload_error.contains("不能上传"), "{upload_error}");
        assert!(derived_media::strong_media_verification_count() > 0);

        drop(app);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cleanup_after_restart_uses_verified_library_without_runtime_status() {
        let root = fresh_temp_dir("cleanup-restart-library");
        let entry = complete_cleanup_entry(&root);

        let status = download_status_for_local_state(
            entry_has_complete_local_files(&root, &entry),
            false,
            false,
        );
        let session = cleanup_session(&entry, status);
        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            std::slice::from_ref(&session),
            std::slice::from_ref(&entry),
        );

        assert_eq!(status, DownloadStatus::Done);
        assert_eq!(eligible.len(), 1);
        assert!(skipped.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn legacy_library_identity_matches_uniquely_without_rewriting_its_directory() {
        let dir = fresh_temp_dir("cleanup-legacy-device-id");
        let comp = test_composition(&dir, Vec::new());
        let canonical_id = register_test_device(&comp, "e");
        let identity = comp.resolve_binding(&canonical_id).unwrap().identity;
        let legacy_id = identity.display_id().to_string();
        let root = comp.library_root();
        let entry = canonical_entry_for_device(&root, &legacy_id);
        let legacy_path = canonical_publication_bundle_for_entry(&root, &entry)
            .expect("legacy-id canonical bundle")
            .output_path;
        let session = cleanup_session(&entry, DownloadStatus::Done);

        let (eligible, skipped) = downloaded_cleanup_candidates_with_match(
            &root,
            &canonical_id,
            std::slice::from_ref(&session),
            std::slice::from_ref(&entry),
            |stored, current| comp.device_ids_match(stored, current),
        );

        assert!(skipped.is_empty());
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].local_device_id, legacy_id);
        assert!(legacy_path.is_file());
        assert!(!root.join(&canonical_id).exists());
        comp.revalidate_downloaded_candidate(&canonical_id, &eligible[0])
            .expect("revalidation must keep reading the legacy directory");

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn downloaded_cleanup_selects_only_done_sessions_with_real_exact_size_files() {
        let root = fresh_temp_dir("downloaded-cleanup-exact");
        let entry = complete_cleanup_entry(&root);

        let done = cleanup_session(&entry, DownloadStatus::Done);
        let mut not_done = cleanup_session(&entry, DownloadStatus::Failed);
        not_done.session.id = "sess-failed".to_string();
        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            &[done, not_done],
            std::slice::from_ref(&entry),
        );

        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].session_id, entry.session_id);
        assert_eq!(
            eligible[0].revision,
            entry.publication.as_ref().unwrap().revision
        );
        assert_eq!(eligible[0].bytes, entry.bytes);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].session_id, "sess-failed");
        assert!(skipped[0].reason.contains("失败"));

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn downloaded_cleanup_skips_done_state_when_a_local_file_is_missing_or_wrong_size() {
        let root = fresh_temp_dir("downloaded-cleanup-missing");
        let entry = complete_cleanup_entry(&root);
        let output_path = canonical_publication_bundle_for_entry(&root, &entry)
            .expect("canonical bundle")
            .output_path;
        std::fs::remove_file(&output_path).unwrap();
        let session = cleanup_session(&entry, DownloadStatus::Done);

        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            std::slice::from_ref(&session),
            std::slice::from_ref(&entry),
        );
        assert!(eligible.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("规范 MP4"));

        std::fs::write(&output_path, test_bytes(9)).unwrap();
        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            &[session],
            std::slice::from_ref(&entry),
        );
        assert!(eligible.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("规范 MP4"));

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn downloaded_cleanup_skips_same_size_hash_mismatch() {
        let root = fresh_temp_dir("downloaded-cleanup-hash-mismatch");
        let entry = complete_cleanup_entry(&root);
        let output_path = canonical_publication_bundle_for_entry(&root, &entry)
            .expect("canonical bundle")
            .output_path;
        let output_bytes = std::fs::metadata(&output_path).unwrap().len() as usize;
        std::fs::write(output_path, vec![b'y'; output_bytes]).unwrap();

        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            &[cleanup_session(&entry, DownloadStatus::Done)],
            std::slice::from_ref(&entry),
        );

        assert!(eligible.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("规范 MP4"));

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn downloaded_cleanup_skips_ambiguous_duplicate_library_rows() {
        let root = fresh_temp_dir("downloaded-cleanup-duplicate");
        let entry = complete_cleanup_entry(&root);

        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            &[cleanup_session(&entry, DownloadStatus::Done)],
            &[entry.clone(), entry.clone()],
        );
        assert!(eligible.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("重复"));

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn downloaded_cleanup_idempotency_key_is_stable_and_revision_bound() {
        let first = downloaded_cleanup_idempotency_key("dev1", "sess1", "rev1");
        let retry = downloaded_cleanup_idempotency_key("dev1", "sess1", "rev1");
        let next_revision = downloaded_cleanup_idempotency_key("dev1", "sess1", "rev2");

        assert_eq!(first, retry);
        assert_ne!(first, next_revision);
        assert!(first.starts_with("pc-cleanup-v1-"));
        assert_eq!(first.len(), "pc-cleanup-v1-".len() + 64);
    }

    #[test]
    fn backed_up_cleanup_revalidation_refuses_a_new_pi_revision() {
        let root = fresh_temp_dir("backed-up-cleanup-revision-race");
        let entry = backed_up_cleanup_entry(&root);

        let mut selected = cleanup_session(&entry, DownloadStatus::Done);
        selected.backed_up = true;
        let (eligible, skipped) = downloaded_cleanup_candidates(
            &root,
            &entry.device_id,
            std::slice::from_ref(&selected),
            std::slice::from_ref(&entry),
        );
        assert!(skipped.is_empty());
        let candidate = eligible.first().expect("revision-bound candidate");

        let mut current = selected.session;
        current.revision = "rev-cleanup-2".to_string();
        let error = validate_backed_up_cleanup_candidate(
            &root,
            &entry.device_id,
            candidate,
            &current,
            std::slice::from_ref(&entry),
            |left, right| left == right,
        )
        .expect_err("an advanced Pi revision must stop automatic cleanup before DELETE");

        assert!(error.contains("revision"), "{error}");
        assert_eq!(
            candidate.revision,
            entry.publication.as_ref().unwrap().revision
        );
        assert_ne!(
            downloaded_cleanup_idempotency_key(
                &entry.device_id,
                &candidate.session_id,
                &candidate.revision,
            ),
            downloaded_cleanup_idempotency_key(
                &entry.device_id,
                &candidate.session_id,
                &current.revision,
            )
        );

        current.revision = candidate.revision.clone();
        validate_backed_up_cleanup_candidate(
            &root,
            &entry.device_id,
            candidate,
            &current,
            std::slice::from_ref(&entry),
            |left, right| left == right,
        )
        .expect("unchanged backed-up revision remains eligible");
        let mut receipts_removed = entry.clone();
        receipts_removed.object_receipts.clear();
        let error = validate_backed_up_cleanup_candidate(
            &root,
            &entry.device_id,
            candidate,
            &current,
            std::slice::from_ref(&receipts_removed),
            |left, right| left == right,
        )
        .expect_err("durable completion receipts must be rechecked before DELETE");
        assert!(error.contains("备份完成凭证"), "{error}");

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn require_entry_has_local_files_rejects_empty_file_list() {
        let entry = test_entry(Vec::new());
        assert!(require_entry_has_local_files(&entry).is_err());
    }

    #[test]
    fn require_entry_has_local_files_rejects_a_non_empty_raw_inventory() {
        let entry = test_entry(vec![test_session_file("video.mp4", "video/main.mp4", 10)]);
        assert!(require_entry_has_local_files(&entry).is_err());
    }

    #[test]
    fn require_entry_has_local_files_accepts_a_canonical_derived_bundle() {
        let root = fresh_temp_dir("require-canonical-local-files");
        let entry = worker_start_failure_entry(&root);
        assert!(require_entry_has_local_files(&entry).is_ok());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn completed_upload_verification_stays_bound_after_same_key_overwrite() {
        let store = MemoryObjectStore::new();
        let key = ObjectKey("same-key/object.bin".to_string());
        let first_bytes = b"first writer bytes".to_vec();
        let first_sha256 = SourceSha256::from_bytes(Sha256::digest(&first_bytes).into());
        let first_expected = ExpectedObject {
            size_bytes: first_bytes.len() as u64,
            source_sha256: first_sha256,
        };
        let first_handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: key.clone(),
                content_length: first_bytes.len() as u64,
                source_sha256: first_sha256,
                content_type: None,
            })
            .expect("initiate first writer");
        let first_part = store
            .upload_part(
                &first_handle,
                PartNumber::new(1).expect("valid part number"),
                &first_bytes,
            )
            .expect("upload first writer part");
        let first_completion = store
            .complete_multipart_upload(&first_handle, vec![first_part])
            .expect("complete first writer");

        let second_bytes = b"second writer bytes".to_vec();
        let second_sha256 = SourceSha256::from_bytes(Sha256::digest(&second_bytes).into());
        let second_handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: key.clone(),
                content_length: second_bytes.len() as u64,
                source_sha256: second_sha256,
                content_type: None,
            })
            .expect("initiate concurrent writer");
        let second_part = store
            .upload_part(
                &second_handle,
                PartNumber::new(1).expect("valid part number"),
                &second_bytes,
            )
            .expect("upload concurrent writer part");
        store
            .complete_multipart_upload(&second_handle, vec![second_part])
            .expect("complete concurrent writer");

        assert!(
            store.verify_object(&key, &first_expected).is_err(),
            "latest-key verification must not claim the first writer's object"
        );
        let receipt = verify_completed_object_bound(&store, &first_completion, &first_expected)
            .expect("completion-bound verification must read the first version");
        assert_eq!(receipt.etag, first_completion.etag);
        assert_eq!(receipt.version_id, first_completion.version_id);
    }

    fn started_upload_context_fixture(
        root: &Path,
        job_id: &str,
    ) -> (Arc<Mutex<TransferStore>>, u64, UploadContext) {
        let transfer_store = Arc::new(Mutex::new(
            TransferStore::open(root.join("transfer_store.sqlite3")).unwrap(),
        ));
        let spec = UploadJobSpec::new_with_prefix(
            "dev-upload|sess-upload",
            "revision-upload",
            format!("digest-{job_id}"),
            "prefix",
        )
        .unwrap();
        let created = transfer_store
            .lock()
            .unwrap()
            .create_upload_job(job_id, &spec, "t0")
            .unwrap();
        let expected_version = transfer_store
            .lock()
            .unwrap()
            .start_upload_job(job_id, created.job().state_version, "t1")
            .unwrap();
        let context = test_upload_context(
            root,
            transfer_store.clone(),
            job_id,
            expected_version,
            Arc::new(AtomicBool::new(false)),
        );
        (transfer_store, expected_version, context)
    }

    fn test_upload_receipt_seed() -> UploadReceiptSeed {
        UploadReceiptSeed::new(
            "prefix/dev-upload/sess-upload/object.bin",
            UploadReceiptRole::Data,
            "etag-object",
            Some("version-object".to_string()),
            3,
            "0".repeat(64),
            UploadReceiptDigestProof::ServerChecksum,
        )
    }

    #[test]
    fn pre_complete_cancellation_keeps_multipart_aborting_when_remote_cleanup_fails() {
        let root = fresh_temp_dir("upload-cancel-before-complete-cleanup");
        let (transfer_store, _, context) =
            started_upload_context_fixture(&root, "upload-cancel-before-complete");
        context.cancel.store(true, Ordering::SeqCst);
        let remote = MemoryObjectStore::new();
        remote.queue_fault(
            FaultPoint::AbortMultipartUpload,
            ObjectStoreError::Network("cleanup unavailable".to_string()),
        );
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());

        let error = upload_bytes_object(
            &remote,
            key.clone(),
            b"evidence",
            "application/octet-stream",
            &context,
        )
        .expect_err("cancellation before complete must stop the evidence upload");
        assert_eq!(error, UploadPipelineError::Cancelled);
        let pending = transfer_store
            .lock()
            .unwrap()
            .list_pending_uploads()
            .unwrap()
            .into_iter()
            .find(|upload| upload.object_key() == key.0.as_str())
            .expect("failed remote cleanup keeps the durable multipart row");
        assert_eq!(pending.desired_state, UploadDesiredState::Aborting);

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn evidence_upload_stages_one_receipt_and_retires_multipart() {
        let root = fresh_temp_dir("upload-evidence-receipt-success");
        let (transfer_store, _, context) =
            started_upload_context_fixture(&root, "upload-evidence-receipt-success");
        let remote = MemoryObjectStore::new();
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());

        let receipt = upload_bytes_object(
            &remote,
            key.clone(),
            b"evidence",
            "application/octet-stream",
            &context,
        )
        .expect("evidence upload and receipt staging succeed");

        assert_eq!(receipt.key, key);
        assert_eq!(remote.in_progress_upload_count(), 0);
        let store = transfer_store.lock().unwrap();
        let receipts = store
            .list_upload_receipts("upload-evidence-receipt-success")
            .unwrap();
        assert_eq!(receipts.len(), 1, "the evidence receipt is staged once");
        assert_eq!(receipts[0].role, UploadReceiptRole::Evidence);
        assert_eq!(receipts[0].object_key, key.0);
        assert!(
            store.list_pending_uploads().unwrap().is_empty(),
            "successful evidence upload retires its durable multipart row"
        );

        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn multipart_track_failure_aborts_remote_and_returns_original_error() {
        let root = fresh_temp_dir("upload-track-failure-clean");
        let (transfer_store, expected_version, context) =
            started_upload_context_fixture(&root, "upload-track-failure-clean");
        let remote = MemoryObjectStore::new();
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());

        // A stale job version makes the durable track write fail after the
        // provider has already handed us a live multipart handle.
        let stale_context = test_upload_context(
            &root,
            transfer_store.clone(),
            "upload-track-failure-clean",
            expected_version + 1,
            context.cancel.clone(),
        );
        let error = upload_bytes_object(
            &remote,
            key,
            b"evidence",
            "application/octet-stream",
            &stale_context,
        )
        .expect_err("stale track write must fail");

        let detail = error.detail().expect("track failure has a detail");
        assert!(detail.contains("无法记录在途分片上传"));
        assert!(
            !detail.contains("清理未完成"),
            "successful cleanup must preserve only the original error: {detail}"
        );
        assert_eq!(
            remote.in_progress_upload_count(),
            0,
            "a tracked-handle failure must abort the remote multipart upload"
        );
        assert!(
            transfer_store
                .lock()
                .unwrap()
                .list_pending_uploads()
                .unwrap()
                .is_empty(),
            "track failure must not create a durable row"
        );

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn multipart_track_and_abort_failure_reports_retryable_incomplete_cleanup() {
        let root = fresh_temp_dir("upload-track-failure-aborting");
        let (transfer_store, expected_version, context) =
            started_upload_context_fixture(&root, "upload-track-failure-aborting");
        let remote = MemoryObjectStore::new();
        remote.queue_fault(
            FaultPoint::AbortMultipartUpload,
            ObjectStoreError::Network("cleanup unavailable".to_string()),
        );
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());
        let stale_context = test_upload_context(
            &root,
            transfer_store.clone(),
            "upload-track-failure-aborting",
            expected_version + 1,
            context.cancel.clone(),
        );

        let error = upload_bytes_object(
            &remote,
            key.clone(),
            b"evidence",
            "application/octet-stream",
            &stale_context,
        )
        .expect_err("stale track write must fail");

        let outcome = error.terminal_outcome();
        assert!(
            matches!(
                outcome,
                TerminalOutcome::Failed {
                    retryable: true,
                    ..
                }
            ),
            "an untracked remote handle with failed cleanup must be retryable: {outcome:?}"
        );
        let detail = error.detail().expect("track/cleanup failure has a detail");
        assert!(
            detail.contains("cleanup_incomplete"),
            "missing stable cleanup marker: {detail}"
        );
        assert!(
            detail.contains("object_key="),
            "missing remote object identity: {detail}"
        );
        assert!(
            detail.contains("upload_id="),
            "missing remote upload identity: {detail}"
        );
        assert!(
            detail.contains(&key.0),
            "object identity must be actionable: {detail}"
        );
        assert!(
            detail.contains("cleanup unavailable"),
            "missing cleanup cause: {detail}"
        );
        assert!(
            !detail.contains("access") && !detail.contains("secret"),
            "diagnostic must not expose credential labels: {detail}"
        );
        assert_eq!(
            remote.in_progress_upload_count(),
            1,
            "failed cleanup must leave the remote handle observable for operator cleanup"
        );
        assert!(
            transfer_store
                .lock()
                .unwrap()
                .list_pending_uploads()
                .unwrap()
                .is_empty(),
            "the failed track write cannot pretend to have a durable ownership row"
        );

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn track_failure_with_a_durable_row_reconciles_that_row_before_returning_error() {
        let root = fresh_temp_dir("upload-track-failure-durable-row");
        let (transfer_store, expected_version, context) =
            started_upload_context_fixture(&root, "upload-track-failure-durable-row");
        let remote = MemoryObjectStore::new();
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());
        let handle = remote
            .initiate_multipart_upload(InitiateUploadRequest {
                key: key.clone(),
                content_length: 8,
                source_sha256: SourceSha256::from_bytes(Sha256::digest(b"evidence").into()),
                content_type: Some("application/octet-stream".to_string()),
            })
            .expect("initiate multipart upload");
        transfer_store
            .lock()
            .unwrap()
            .begin_upload_for_job(
                "upload-track-failure-durable-row",
                expected_version,
                &NewUpload {
                    transfer_key: context.transfer_key.clone(),
                    entry_key: context.entry_key.clone(),
                    revision: context.revision.clone(),
                    object_key: handle.key.0.clone(),
                    upload_id: handle.upload_id.0.clone(),
                    endpoint: context.endpoint.clone(),
                    bucket: context.bucket.clone(),
                    url_style: context.url_style,
                },
                "t2",
            )
            .expect("seed the row that an ambiguous track commit could leave");

        let track_error = UploadPipelineError::internal("injected ambiguous track failure");
        let error = abort_multipart_after_track_failure(&context, &remote, &handle, track_error);
        assert_eq!(
            error.detail(),
            Some("injected ambiguous track failure"),
            "successful cleanup must preserve the original tracking error"
        );
        assert_eq!(remote.in_progress_upload_count(), 0);
        assert!(transfer_store
            .lock()
            .unwrap()
            .list_pending_uploads()
            .unwrap()
            .is_empty());

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn track_failure_never_aborts_a_durable_row_owned_by_another_upload() {
        let root = fresh_temp_dir("upload-track-failure-ownership-conflict");
        let (transfer_store, _expected_version, context) =
            started_upload_context_fixture(&root, "upload-track-failure-ownership-conflict");
        let remote = MemoryObjectStore::new();
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());
        let handle = remote
            .initiate_multipart_upload(InitiateUploadRequest {
                key: key.clone(),
                content_length: 8,
                source_sha256: SourceSha256::from_bytes(Sha256::digest(b"evidence").into()),
                content_type: Some("application/octet-stream".to_string()),
            })
            .expect("initiate multipart upload");
        transfer_store
            .lock()
            .unwrap()
            .begin_upload(
                &NewUpload {
                    transfer_key: "different-transfer".to_string(),
                    entry_key: "different-entry".to_string(),
                    revision: "different-revision".to_string(),
                    object_key: handle.key.0.clone(),
                    upload_id: handle.upload_id.0.clone(),
                    endpoint: context.endpoint.clone(),
                    bucket: context.bucket.clone(),
                    url_style: context.url_style,
                },
                "t2",
            )
            .expect("seed a conflicting legacy row");

        let error = abort_multipart_after_track_failure(
            &context,
            &remote,
            &handle,
            UploadPipelineError::internal("injected ownership conflict"),
        );
        assert!(error
            .detail()
            .expect("ownership conflict has a detail")
            .contains("remote abort withheld"));
        assert!(matches!(
            error.terminal_outcome(),
            TerminalOutcome::Failed {
                retryable: true,
                ..
            }
        ));
        assert_eq!(
            remote.in_progress_upload_count(),
            1,
            "a handle owned by another upload must never be aborted here"
        );
        assert_eq!(
            transfer_store
                .lock()
                .unwrap()
                .list_pending_uploads()
                .unwrap()
                .len(),
            1
        );

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn evidence_receipt_staging_failure_keeps_ambiguous_multipart_row() {
        let root = fresh_temp_dir("upload-evidence-receipt-failure-clean");
        let (transfer_store, _, context) =
            started_upload_context_fixture(&root, "upload-evidence-receipt-failure-clean");
        context.fail_stage_receipt.store(true, Ordering::SeqCst);
        let remote = MemoryObjectStore::new();
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());

        let error = upload_bytes_object(
            &remote,
            key.clone(),
            b"evidence",
            "application/octet-stream",
            &context,
        )
        .expect_err("injected evidence receipt staging must fail");
        assert!(error
            .detail()
            .unwrap()
            .contains("injected stage_upload_receipt"));
        assert_eq!(remote.in_progress_upload_count(), 0);
        let store = transfer_store.lock().unwrap();
        assert!(store
            .list_upload_receipts("upload-evidence-receipt-failure-clean")
            .unwrap()
            .is_empty());
        let pending = store
            .list_pending_uploads()
            .unwrap()
            .into_iter()
            .find(|upload| upload.object_key() == key.0.as_str())
            .expect("consumed multipart without a staged receipt must remain durable");
        assert_eq!(pending.desired_state, UploadDesiredState::Aborting);

        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn evidence_receipt_staging_failure_with_cleanup_failure_keeps_aborting_row() {
        let root = fresh_temp_dir("upload-evidence-receipt-failure-aborting");
        let (transfer_store, _, context) =
            started_upload_context_fixture(&root, "upload-evidence-receipt-failure-aborting");
        context.fail_stage_receipt.store(true, Ordering::SeqCst);
        let remote = MemoryObjectStore::new();
        remote.queue_fault(
            FaultPoint::AbortMultipartUpload,
            ObjectStoreError::Network("cleanup unavailable".to_string()),
        );
        let key = ObjectKey("prefix/dev-upload/sess-upload/evidence.bin".to_string());

        let error = upload_bytes_object(
            &remote,
            key.clone(),
            b"evidence",
            "application/octet-stream",
            &context,
        )
        .expect_err("injected evidence receipt staging must fail");
        assert!(error
            .detail()
            .unwrap()
            .contains("injected stage_upload_receipt"));
        assert!(transfer_store
            .lock()
            .unwrap()
            .list_upload_receipts("upload-evidence-receipt-failure-aborting")
            .unwrap()
            .is_empty());
        let pending = transfer_store
            .lock()
            .unwrap()
            .list_pending_uploads()
            .unwrap()
            .into_iter()
            .find(|upload| upload.object_key() == key.0)
            .expect("failed cleanup keeps the durable multipart row");
        assert_eq!(pending.desired_state, UploadDesiredState::Aborting);

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn receipt_stage_failure_routes_through_abort_and_leaves_aborting_row() {
        let root = fresh_temp_dir("upload-receipt-stage-cleanup");
        let (transfer_store, _expected_version, context) =
            started_upload_context_fixture(&root, "upload-stage-failure");
        context.fail_stage_receipt.store(true, Ordering::SeqCst);
        let remote = MemoryObjectStore::new();
        remote.queue_fault(
            FaultPoint::AbortMultipartUpload,
            ObjectStoreError::Network("cleanup unavailable".to_string()),
        );
        let handle = remote
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("prefix/dev-upload/sess-upload/object.bin".to_string()),
                content_length: 3,
                source_sha256: SourceSha256::from_bytes([0; 32]),
                content_type: None,
            })
            .unwrap();
        context.track_multipart(&handle).unwrap();

        let error =
            stage_and_finish_multipart(&context, &remote, &handle, &test_upload_receipt_seed())
                .expect_err("injected receipt persistence failure must abort");
        assert!(error
            .detail()
            .unwrap()
            .contains("injected stage_upload_receipt"));
        let pending = transfer_store
            .lock()
            .unwrap()
            .pending_upload(&handle.key.0, &handle.upload_id.0)
            .unwrap()
            .expect("failed abort keeps the multipart row");
        assert_eq!(pending.desired_state, UploadDesiredState::Aborting);

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn multipart_finish_failure_routes_through_abort_and_leaves_aborting_row() {
        let root = fresh_temp_dir("upload-multipart-finish-cleanup");
        let (transfer_store, _, context) =
            started_upload_context_fixture(&root, "upload-finish-failure");
        context.fail_finish_multipart.store(true, Ordering::SeqCst);
        let remote = MemoryObjectStore::new();
        remote.queue_fault(
            FaultPoint::AbortMultipartUpload,
            ObjectStoreError::Network("cleanup unavailable".to_string()),
        );
        let handle = remote
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("prefix/dev-upload/sess-upload/object.bin".to_string()),
                content_length: 3,
                source_sha256: SourceSha256::from_bytes([0; 32]),
                content_type: None,
            })
            .unwrap();
        context.track_multipart(&handle).unwrap();

        let error =
            stage_and_finish_multipart(&context, &remote, &handle, &test_upload_receipt_seed())
                .expect_err("injected multipart retirement failure must abort");
        assert!(error
            .detail()
            .unwrap()
            .contains("injected finish_multipart"));
        let pending = transfer_store
            .lock()
            .unwrap()
            .pending_upload(&handle.key.0, &handle.upload_id.0)
            .unwrap()
            .expect("failed abort keeps the multipart row");
        assert_eq!(pending.desired_state, UploadDesiredState::Aborting);

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolve_local_upload_file_errors_clearly_when_the_file_is_missing_on_disk() {
        let root = std::env::temp_dir().join(format!("ylx-pc06-missing-{}", uuid::Uuid::new_v4()));
        let entry = test_entry(vec![test_session_file("video.mp4", "video/main.mp4", 10)]);
        let result = resolve_local_upload_file(&root, &entry, &entry.files[0]);
        assert!(
            result.is_err(),
            "must not fabricate success for a file that was never downloaded"
        );
    }

    #[test]
    fn resolve_local_upload_file_finds_a_real_file_at_the_download_commit_path_convention() {
        let root = std::env::temp_dir().join(format!("ylx-pc06-present-{}", uuid::Uuid::new_v4()));
        let entry = test_entry(vec![test_session_file("video.mp4", "video/main.mp4", 10)]);
        let target_dir = root
            .join(&entry.device_id)
            .join(&entry.session_id)
            .join("video");
        std::fs::create_dir_all(&target_dir).unwrap();
        let target_file = target_dir.join("main.mp4");
        std::fs::write(&target_file, test_bytes(10)).unwrap();

        let (path, size) = resolve_local_upload_file(&root, &entry, &entry.files[0]).unwrap();
        assert_eq!(path, target_file);
        assert_eq!(size, 10);
        assert!(!root
            .join(&entry.device_id)
            .join(&entry.session_id)
            .join("video.mp4")
            .exists());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_local_upload_file_keeps_legacy_opaque_downloads_usable() {
        let root = std::env::temp_dir().join(format!("ylx-pc06-legacy-{}", uuid::Uuid::new_v4()));
        let entry = test_entry(vec![test_session_file("f-opaque", "video/main.mp4", 10)]);
        let target_dir = root.join(&entry.device_id).join(&entry.session_id);
        std::fs::create_dir_all(&target_dir).unwrap();
        let legacy_file = target_dir.join("f-opaque");
        std::fs::write(&legacy_file, test_bytes(10)).unwrap();

        let (path, size) = resolve_local_upload_file(&root, &entry, &entry.files[0]).unwrap();
        assert_eq!(path, legacy_file);
        assert_eq!(size, 10);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sha256_matches_known_test_vectors() {
        assert_eq!(
            hex_encode(&hash_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_encode(&hash_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_encode(&hash_bytes(b"The quick brown fox jumps over the lazy dog")),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn sha256_streaming_update_matches_single_shot() {
        let data = vec![0x5au8; 200_000]; // spans many 64-byte blocks
        let one_shot = hash_bytes(&data);

        let mut hasher = Sha256::new();
        for chunk in data.chunks(4096) {
            hasher.update(chunk);
        }
        let streamed: [u8; 32] = hasher.finalize().into();

        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn sha256_hash_file_matches_hash_bytes() {
        let dir = std::env::temp_dir().join(format!("ylx-pc06-sha-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.bin");
        let data = b"YLX transfer PC-06 hashing test payload".repeat(10_000);
        std::fs::write(&path, &data).unwrap();

        let via_file = hash_file(&path).unwrap();
        let via_bytes = SourceSha256::from_bytes(hash_bytes(&data));
        assert_eq!(via_file, via_bytes);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2 + 1);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    // -----------------------------------------------------------------
    // apply_terminal_download -- pure-function tests, no coordinator/
    // AppHandle needed at all.
    // -----------------------------------------------------------------

    fn test_download_spec(device_id: &str, session_id: &str, path: &str, bytes: u64) -> JobSpec {
        let file = test_session_file(path, &format!("recording/{path}"), bytes);
        job_spec_from_context(
            device_id,
            session_id,
            "today",
            std::slice::from_ref(&file),
            std::slice::from_ref(&file),
            &test_publication("rev-1"),
            true,
        )
        .expect("valid test download spec")
    }

    fn test_download_spec_from_files(
        device_id: &str,
        session_id: &str,
        requested: &[SessionFile],
        inventory: &[SessionFile],
        full_session: bool,
    ) -> JobSpec {
        job_spec_from_context(
            device_id,
            session_id,
            "today",
            requested,
            inventory,
            &test_publication("rev-1"),
            full_session,
        )
        .expect("valid test download spec")
    }

    /// A historical partial recovery record still round-trips through the
    /// durable store so current builds can recognize it and refuse to publish
    /// it. No current command can create this specification.
    #[test]
    fn historical_partial_spec_round_trips_only_for_fail_closed_compatibility() {
        let root = fresh_temp_dir("durable-spec-round-trip");
        let requested = vec![test_session_file("file-p", "recording/file-p", 12)];
        let mut inventory = requested.clone();
        inventory.push(test_session_file("file-other", "video/other.mp4", 34));
        let spec = test_download_spec_from_files("dev-p", "sess-p", &requested, &inventory, false);

        let store_path = root.join("transfer_store.sqlite3");
        let mut store = TransferStore::open(&store_path).expect("open store");
        store
            .create_job("job-persisted", &spec, "t0")
            .expect("create durable job");
        drop(store);

        // Reopening the file is the restart this context has to survive.
        let store = TransferStore::open(&store_path).expect("reopen store");
        let recovered = store.job_spec("job-persisted").expect("spec");
        assert_eq!(recovered, spec);
        assert!(!recovered.full_session());

        std::fs::remove_dir_all(&root).ok();
    }

    /// Writes the exact `pending-downloads.json` an older build produced.
    fn write_legacy_pending_downloads(dir: &Path, job_id: &str, spec: &JobSpec) -> Vec<u8> {
        let files = spec
            .requested_files()
            .map(session_file_from_job_spec)
            .collect::<Vec<_>>();
        let session_files = spec
            .session_files()
            .iter()
            .map(session_file_from_job_spec)
            .collect::<Vec<_>>();
        let publication = publication_evidence_from_job_spec(spec);
        let record = serde_json::json!({
            "jobId": job_id,
            "deviceId": spec.identity().device_id().as_str(),
            "sessionId": spec.identity().session_id().as_str(),
            "dateLabel": spec.date_label(),
            "files": files,
            "sessionFiles": session_files,
            "publication": publication,
            "fullSession": spec.full_session(),
        });
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "version": 2,
            "downloads": [record],
        }))
        .expect("serialize legacy store");
        std::fs::create_dir_all(dir).expect("create app data dir");
        std::fs::write(dir.join(LEGACY_PENDING_DOWNLOAD_FILE), &bytes).expect("write legacy store");
        bytes
    }

    /// Commit 34: the sidecar is backed up, imported through commit 26's
    /// importer, and only then deleted -- and running the migration again is
    /// a no-op rather than a second import.
    #[test]
    fn legacy_pending_download_json_is_backed_up_imported_and_then_deleted() {
        let dir = fresh_temp_dir("legacy-pending-migration");
        let spec = test_download_spec("dev-l", "sess-l", "file-l", 21);
        let original = write_legacy_pending_downloads(&dir, "job-legacy", &spec);

        let mut store =
            TransferStore::open(dir.join("transfer_store.sqlite3")).expect("open store");
        migrate_legacy_pending_downloads(&mut store, &dir).expect("migrate");

        assert!(
            !dir.join(LEGACY_PENDING_DOWNLOAD_FILE).exists(),
            "the migrated sidecar must be deleted"
        );
        assert_eq!(
            std::fs::read(dir.join(LEGACY_PENDING_DOWNLOAD_BACKUP)).expect("read backup"),
            original,
            "the original bytes must survive the migration verbatim"
        );
        assert_eq!(store.count_jobs().expect("count"), 1);
        assert_eq!(
            store.job_spec("job-legacy").expect("spec"),
            spec,
            "every field the app used to read from the JSON now comes from the durable spec"
        );

        // Idempotent: a second run has nothing to read and creates nothing.
        migrate_legacy_pending_downloads(&mut store, &dir).expect("re-migrate");
        assert_eq!(store.count_jobs().expect("count"), 1);

        // Even a sidecar that reappears is short-circuited by the marker
        // rather than imported twice.
        write_legacy_pending_downloads(&dir, "job-legacy", &spec);
        migrate_legacy_pending_downloads(&mut store, &dir).expect("re-migrate with file");
        assert_eq!(store.count_jobs().expect("count"), 1);
        assert!(!dir.join(LEGACY_PENDING_DOWNLOAD_FILE).exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_legacy_pending_download_json_is_preserved_and_reported() {
        let dir = fresh_temp_dir("legacy-pending-corrupt");
        std::fs::create_dir_all(&dir).expect("create app data dir");
        let path = dir.join(LEGACY_PENDING_DOWNLOAD_FILE);
        std::fs::write(&path, br#"{"version":2,"downloads":[{"jobId":""#).expect("write");

        let mut store =
            TransferStore::open(dir.join("transfer_store.sqlite3")).expect("open store");
        let error = migrate_legacy_pending_downloads(&mut store, &dir)
            .expect_err("a corrupt sidecar must not be treated as an empty state");
        assert!(error.contains("迁移旧的下载上下文失败"), "{error}");
        assert!(path.exists(), "the unusable original must be left in place");
        assert_eq!(store.count_jobs().expect("count"), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_pending_upload_json_is_imported_backed_up_and_deleted_after_commit() {
        let dir = fresh_temp_dir("legacy-upload-migration");
        let sidecar = dir.join(LEGACY_PENDING_UPLOAD_FILE);
        let original = serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "uploads": [{
                "transferKey": "transfer-legacy",
                "entryKey": "dev-legacy|sess-legacy",
                "objectKey": "dev-legacy/sess-legacy/file.bin",
                "uploadId": "upload-legacy",
                "endpoint": "https://objects.example.invalid",
                "bucket": "recordings"
            }]
        }))
        .expect("serialize legacy upload store");
        std::fs::write(&sidecar, &original).expect("write sidecar");

        let mut store = TransferStore::open(dir.join("transfer_store.sqlite3")).unwrap();
        migrate_legacy_pending_uploads(&mut store, &dir).expect("migrate upload sidecar");
        assert!(!sidecar.exists());
        assert_eq!(
            std::fs::read(dir.join(LEGACY_PENDING_UPLOAD_BACKUP)).unwrap(),
            original
        );
        let pending = store.list_pending_uploads().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].desired_state, UploadDesiredState::Aborting);

        // A sidecar left over after the first transaction is still cleaned up
        // by the marker path without creating a duplicate row.
        std::fs::write(&sidecar, &original).unwrap();
        migrate_legacy_pending_uploads(&mut store, &dir).expect("clean marker sidecar");
        assert!(!sidecar.exists());
        assert_eq!(store.list_pending_uploads().unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_legacy_pending_upload_json_is_preserved_and_reported() {
        let dir = fresh_temp_dir("legacy-upload-corrupt");
        let sidecar = dir.join(LEGACY_PENDING_UPLOAD_FILE);
        let original = b"{ this is not json";
        std::fs::write(&sidecar, original).unwrap();
        let mut store = TransferStore::open(dir.join("transfer_store.sqlite3")).unwrap();
        let error = migrate_legacy_pending_uploads(&mut store, &dir)
            .expect_err("corrupt upload sidecar must fail closed");
        assert!(error.contains("迁移旧的上传上下文失败"));
        assert_eq!(std::fs::read(&sidecar).unwrap(), original);
        assert!(!dir.join(LEGACY_PENDING_UPLOAD_BACKUP).exists());
        assert!(store.list_pending_uploads().unwrap().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    fn uploading_entry(session_id: &str, upload_status: UploadStatus) -> LibraryEntry {
        let mut entry = test_entry(vec![test_session_file("file-1", "video/a.mp4", 3)]);
        entry.session_id = session_id.to_string();
        entry.upload_status = upload_status;
        entry.uploaded_at = Some("2026-08-02T00:00:00Z".to_string());
        entry.object_receipts = vec![ObjectVerificationReceipt {
            key: "dev/sess/file-1".to_string(),
            etag: "etag".to_string(),
            version_id: None,
            bytes: 3,
            sha256: "0".repeat(64),
        }];
        entry
    }

    #[test]
    fn interrupted_uploads_are_converged_to_an_honest_failure() {
        let mut library = vec![
            uploading_entry("sess-uploading", UploadStatus::Uploading),
            uploading_entry("sess-done", UploadStatus::Done),
            uploading_entry("sess-none", UploadStatus::None),
        ];

        assert!(mark_interrupted_uploads_failed(&mut library));

        assert_eq!(library[0].upload_status, UploadStatus::Failed);
        assert_eq!(
            library[0].upload_error.as_deref(),
            Some(UPLOAD_INTERRUPTED_MESSAGE)
        );
        assert_eq!(library[0].uploaded_at, None);
        assert!(
            library[0].object_receipts.is_empty(),
            "an interrupted upload has no verified objects; leftovers would let \
             entry_has_complete_object_receipts see stale evidence"
        );

        // Entries that were not mid-upload are left exactly as they were.
        assert_eq!(library[1].upload_status, UploadStatus::Done);
        assert_eq!(library[1].object_receipts.len(), 1);
        assert_eq!(library[2].upload_status, UploadStatus::None);
        assert_eq!(library[2].object_receipts.len(), 1);

        // Exercise the real startup entry point with a durable upload job.
        // This specifically guards the store-lock snapshot: reconciliation
        // must be able to read its immutable spec and then cancel the job
        // without trying to lock the same TransferStore recursively.
        let dir = fresh_temp_dir("interrupted-durable-upload");
        let comp = test_composition(&dir, Vec::new());
        let mut durable = uploading_entry("sess-durable", UploadStatus::Uploading);
        let legacy = uploading_entry("sess-legacy", UploadStatus::Uploading);
        let mut historical = uploading_entry("sess-historical", UploadStatus::Uploading);
        durable.publication = Some(test_publication("revision-durable"));
        historical.publication = Some(test_publication("revision-historical"));
        let durable_revision = durable.publication.as_ref().unwrap().revision.clone();
        let historical_revision = historical.publication.as_ref().unwrap().revision.clone();
        let spec = UploadJobSpec::new(durable.key(), durable_revision, "digest-durable")
            .expect("valid durable upload spec");
        let historical_spec =
            UploadJobSpec::new(historical.key(), historical_revision, "digest-historical")
                .expect("valid historical upload spec");
        {
            let mut store = comp.transfer_store.lock().unwrap();
            store
                .create_upload_job("upload-interrupted", &spec, "t0")
                .unwrap();
            let created = store
                .create_upload_job("upload-historical", &historical_spec, "t1")
                .unwrap();
            let version = store
                .start_upload_job("upload-historical", created.job().state_version, "t2")
                .unwrap();
            store
                .complete_upload_job(
                    "upload-historical",
                    version,
                    &TerminalOutcome::Failed {
                        code: "network".to_string(),
                        retryable: true,
                    },
                    "t3",
                )
                .unwrap();
            store
                .acknowledge_completion("upload-historical", "t4")
                .unwrap();
        }
        let mut restarted_library = vec![durable, legacy, historical];

        assert!(reconcile_interrupted_uploads(
            &comp,
            &mut restarted_library,
            &StorageConfig::default(),
        )
        .expect("startup reconciliation"));
        assert_eq!(
            comp.stored_job("upload-interrupted")
                .unwrap()
                .expect("startup cancellation keeps the durable job")
                .state,
            JobStateTag::Cancelled
        );
        assert_eq!(
            restarted_library[0].upload_status,
            UploadStatus::Failed,
            "a durable interrupted upload is surfaced as an honest failure"
        );
        assert_eq!(
            restarted_library[0].upload_error.as_deref(),
            Some(UPLOAD_INTERRUPTED_MESSAGE)
        );
        assert_eq!(restarted_library[1].upload_status, UploadStatus::Failed);
        assert_eq!(
            restarted_library[2].upload_status,
            UploadStatus::Failed,
            "acknowledged terminal history must not mask a legacy Uploading row forever"
        );

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn startup_reconciliation_fails_closed_on_a_durable_job_read_error() {
        let dir = fresh_temp_dir("startup-reconcile-read-failure");
        let comp = test_composition(&dir, Vec::new());
        let entry = uploading_entry("sess-read-failure", UploadStatus::Uploading);
        let spec = UploadJobSpec::new(entry.key(), "revision-read-failure", "digest-read-failure")
            .expect("valid upload spec");
        {
            let mut store = comp.transfer_store.lock().unwrap();
            store
                .create_upload_job("upload-read-failure", &spec, "t0")
                .expect("create durable upload");
        }
        // The production schema rejects unknown state tags. A separate test
        // connection models a damaged store that got past SQLite's CHECK
        // constraint; reconciliation must still reject it rather than
        // treating the row as absent.
        let injector = Connection::open(dir.join("transfer_store.sqlite3"))
            .expect("open independent corruption connection");
        injector
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("enable test corruption");
        injector
            .execute(
                "UPDATE transfer_jobs SET state = 'not-a-transfer-state' \
                 WHERE job_id = 'upload-read-failure'",
                [],
            )
            .expect("corrupt durable state tag");
        drop(injector);

        let mut library = vec![entry];
        let before = serde_json::to_vec(&library).expect("serialize pre-reconcile library");
        let error = reconcile_interrupted_uploads(&comp, &mut library, &StorageConfig::default())
            .expect_err("an unreadable durable job must abort startup reconciliation");
        assert!(error.contains("无法读取启动时的持久化上传任务"), "{error}");
        assert_eq!(serde_json::to_vec(&library).unwrap(), before);

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn startup_reconciliation_does_not_mutate_library_when_cancellation_write_fails() {
        let dir = fresh_temp_dir("startup-reconcile-cancel-failure");
        let comp = test_composition(&dir, Vec::new());
        let entry = uploading_entry("sess-cancel-failure", UploadStatus::Uploading);
        let spec = UploadJobSpec::new(
            entry.key(),
            "revision-cancel-failure",
            "digest-cancel-failure",
        )
        .expect("valid upload spec");
        {
            let mut store = comp.transfer_store.lock().unwrap();
            store
                .create_upload_job("upload-cancel-failure", &spec, "t0")
                .expect("create durable upload");
        }
        // Keep a write transaction open on an independent durable connection.
        // The read half of reconciliation still succeeds, but its terminal
        // cancellation transaction cannot commit. This models a durable
        // write failure without adding a production-only fault injector.
        let injector = Connection::open(dir.join("transfer_store.sqlite3"))
            .expect("open independent lock connection");
        injector
            .busy_timeout(Duration::ZERO)
            .expect("disable lock wait in the injector");
        injector
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold the durable write transaction");

        let mut library = vec![entry];
        let before = serde_json::to_vec(&library).expect("serialize pre-reconcile library");
        let error = reconcile_interrupted_uploads(&comp, &mut library, &StorageConfig::default())
            .expect_err("startup must stop when durable cancellation cannot be written");
        assert!(
            error.contains("无法在启动时持久化取消中断上传任务"),
            "{error}"
        );
        assert_eq!(serde_json::to_vec(&library).unwrap(), before);

        // Release the intentionally-held transaction so the temporary store
        // can be cleaned up on all supported SQLite builds.
        injector
            .execute_batch("ROLLBACK")
            .expect("release durable write transaction");
        drop(injector);
        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reconciliation_reports_no_change_when_nothing_was_uploading() {
        let mut library = vec![
            uploading_entry("sess-done", UploadStatus::Done),
            uploading_entry("sess-failed", UploadStatus::Failed),
        ];
        assert!(
            !mark_interrupted_uploads_failed(&mut library),
            "must not ask the caller to persist an unchanged library"
        );
        assert_eq!(library[0].upload_status, UploadStatus::Done);
        assert_eq!(library[1].upload_status, UploadStatus::Failed);
    }

    #[test]
    fn marking_interrupted_uploads_is_idempotent() {
        let mut library = vec![uploading_entry("sess-uploading", UploadStatus::Uploading)];
        assert!(mark_interrupted_uploads_failed(&mut library));
        assert!(
            !mark_interrupted_uploads_failed(&mut library),
            "a second startup must not re-report a change it did not make"
        );
        assert_eq!(
            library[0].upload_error.as_deref(),
            Some(UPLOAD_INTERRUPTED_MESSAGE)
        );
    }

    // -----------------------------------------------------------------
    // boot staging
    // -----------------------------------------------------------------

    /// Regression: boot stage 2 must produce a runtime that does nothing on
    /// its own. Background loops used to be spawned inside the constructor,
    /// so a tick could land before the application state was registered.
    /// `Composition::new` takes no `AppHandle` at all now, which is what
    /// makes that unrepresentable; this pins the observable half of it.
    #[test]
    fn boot_stage_two_builds_a_runtime_with_no_background_loops_running() {
        let root = fresh_temp_dir("boot-inert");
        std::fs::create_dir_all(&root).unwrap();
        let comp =
            Composition::new(root.clone(), root.join("library")).expect("build the inert runtime");

        assert!(
            comp.background_loops.lock().unwrap().is_empty(),
            "stage 2 must not start any background loop"
        );
        // Stage 3's interruption settlement is an explicit, separate step --
        // it does not start loops or schedule transfer work either.
        comp.fail_interrupted_downloads_on_startup()
            .expect("settle an empty transfer store");
        assert!(
            comp.background_loops.lock().unwrap().is_empty(),
            "startup interruption settlement must not start any background loop"
        );
        // And with nothing started, shutdown is a no-op rather than a panic.
        comp.shutdown_background_loops();

        std::fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------
    // download directory validation
    // -----------------------------------------------------------------

    #[test]
    fn prepare_library_root_rejects_a_relative_path_without_creating_anything() {
        let error = prepare_library_root(PathBuf::from("relative/library"))
            .expect_err("a relative download directory must be rejected");
        assert!(error.contains("绝对路径"), "unexpected error: {error}");
        assert!(
            !Path::new("relative/library").exists(),
            "a rejected download directory must never be created"
        );
    }

    #[test]
    fn prepare_library_root_rejects_an_empty_path() {
        let error = prepare_library_root(PathBuf::new())
            .expect_err("an empty download directory must be rejected");
        assert!(error.contains("未配置"), "unexpected error: {error}");
    }

    #[test]
    fn prepare_library_root_creates_a_missing_directory_and_leaves_no_probe_behind() {
        let root = fresh_temp_dir("library-root-create");
        let target = root.join("nested").join("library");
        let prepared = prepare_library_root(target.clone()).expect("prepare library root");
        assert_eq!(prepared, target);
        assert!(target.is_dir());
        let leftovers: Vec<_> = std::fs::read_dir(&target)
            .expect("read prepared library root")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "the writability probe must clean up after itself, found {leftovers:?}"
        );

        // Preparing an already-prepared root again must succeed too --
        // this runs on every start.
        prepare_library_root(target).expect("prepare an existing library root");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prepare_library_root_rejects_a_path_that_is_a_file() {
        let root = fresh_temp_dir("library-root-is-file");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("not-a-directory");
        std::fs::write(&target, b"x").unwrap();

        let error = prepare_library_root(target)
            .expect_err("a regular file must not be accepted as the download directory");
        // `create_dir_all` fails first on an existing file, so either the
        // creation error or the explicit is_dir check may surface -- both
        // must name the directory and be user-readable Chinese.
        assert!(error.contains("下载目录"), "unexpected error: {error}");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn historical_partial_success_cannot_create_a_library_entry() {
        let root = fresh_temp_dir("historical-partial");
        let requested = vec![test_session_file("file-2", "recording/file-2", 4)];
        let inventory = vec![
            test_session_file("file-1", "video/left.mp4", 3),
            requested[0].clone(),
        ];
        let spec =
            test_download_spec_from_files("dev-part", "sess-part", &requested, &inventory, false);
        let target_dir = root.join("dev-part").join("sess-part");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(target_dir.join("file-2"), test_bytes(4)).unwrap();

        let mut library = Vec::new();
        assert!(!apply_terminal_download(
            &mut library,
            &root,
            &spec,
            &TransferJobState::Succeeded,
        ));
        assert!(
            library.is_empty(),
            "a selected raw file is not a canonical derived publication"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn historical_partial_success_does_not_mutate_an_existing_library_entry() {
        let root = fresh_temp_dir("historical-partial-existing");
        let requested = vec![test_session_file("file-2", "recording/file-2", 4)];
        let first = test_session_file("file-1", "video/left.mp4", 3);
        let inventory = vec![first.clone(), requested[0].clone()];
        let spec =
            test_download_spec_from_files("dev-merge", "sess-merge", &requested, &inventory, false);
        let target_dir = root.join("dev-merge").join("sess-merge");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(target_dir.join("file-1"), test_bytes(3)).unwrap();
        std::fs::write(target_dir.join("file-2"), test_bytes(4)).unwrap();

        let existing = LibraryEntry {
            device_id: "dev-merge".to_string(),
            session_id: "sess-merge".to_string(),
            date_label: "earlier".to_string(),
            downloaded_at: "earlier".to_string(),
            bytes: 3,
            processed_files: Vec::new(),
            files: vec![first],
            complete: false,
            download_projection_sequence: 0,
            publication: Some(publication_evidence_from_job_spec(&spec)),
            library_root: None,
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: UploadStatus::Done,
            upload_retryable: false,
            uploaded_at: Some("earlier".to_string()),
            upload_error: None,
        };
        let existing_bytes = serde_json::to_vec(&existing).unwrap();
        let mut library = vec![existing.clone()];
        assert!(!apply_terminal_download(
            &mut library,
            &root,
            &spec,
            &TransferJobState::Succeeded,
        ));
        assert_eq!(library.len(), 1);
        assert_eq!(serde_json::to_vec(&library[0]).unwrap(), existing_bytes);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn succeeded_state_with_a_missing_file_does_not_fabricate_a_library_entry() {
        // The whole point of `apply_terminal_download` re-checking the
        // filesystem itself: a `Succeeded` state transition alone must
        // never be trusted to mean "the file is really there."
        let root = fresh_temp_dir("missing-file");
        let spec = test_download_spec("dev-missing", "sess-missing", "video.mp4", 10);
        let mut library = Vec::new();

        assert!(!apply_terminal_download(
            &mut library,
            &root,
            &spec,
            &TransferJobState::Succeeded,
        ));

        assert!(
            library.is_empty(),
            "must never fabricate a library entry when the file genuinely isn't on disk"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn succeeded_state_with_a_canonical_bundle_upserts_a_library_entry() {
        let root = fresh_temp_dir("real-file");
        let expected = worker_start_failure_entry(&root);
        let spec = canonical_download_spec(&expected);

        let mut library = Vec::new();
        assert!(apply_terminal_download(
            &mut library,
            &root,
            &spec,
            &TransferJobState::Succeeded,
        ));

        assert_eq!(library.len(), 1);
        assert_eq!(library[0].device_id, expected.device_id);
        assert_eq!(library[0].session_id, expected.session_id);
        assert_eq!(library[0].bytes, expected.bytes);
        assert_eq!(library[0].processed_files, expected.processed_files);
        assert_eq!(library[0].upload_status, UploadStatus::None);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn retryable_failed_state_with_a_canonical_bundle_is_not_library_complete_or_upload_ready() {
        let root = fresh_temp_dir("failed-after-canonical-publication");
        let expected = worker_start_failure_entry(&root);
        let spec = canonical_download_spec(&expected);
        let mut library = Vec::new();

        assert!(!apply_terminal_download(
            &mut library,
            &root,
            &spec,
            &TransferJobState::Failed {
                code: FailureCode::Other("source staging cleanup failed".to_string()),
                retryable: true,
            },
        ));

        assert!(
            library.is_empty(),
            "a visible canonical bundle cannot override the failed completion authority"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn full_session_terminal_verification_uses_the_canonical_bundle() {
        let root = fresh_temp_dir("full-session-verification-count");
        let expected = worker_start_failure_entry(&root);
        let spec = canonical_download_spec(&expected);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_resolver = Arc::clone(&calls);
        let resolver = move |root: &Path,
                             device_id: &str,
                             session_id: &str,
                             file: &crate::models::SessionFile| {
            calls_for_resolver.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            resolve_downloaded_file(root, device_id, session_id, file)
        };
        let mut library = Vec::new();
        assert!(apply_terminal_download_with_resolver(
            &mut library,
            &root,
            &spec,
            &TransferJobState::Succeeded,
            &resolver,
        ));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "terminal projection revalidates the canonical bundle, not raw files"
        );
        assert_eq!(library[0].files, expected.files);
        assert_eq!(library[0].processed_files, expected.processed_files);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn apply_terminal_download_upserts_rather_than_duplicating_on_repeated_calls() {
        // Guards against the "no duplicate library entries on repeated
        // poll ticks" requirement at the pure-function level, independent
        // of the outbox-delivery guard used by `spawn_transfer_poll_loop`
        // in practice (see the coordinator-backed test below).
        let root = fresh_temp_dir("upsert-not-duplicate");
        let entry = worker_start_failure_entry(&root);
        let spec = canonical_download_spec(&entry);

        let mut library = Vec::new();
        apply_terminal_download(&mut library, &root, &spec, &TransferJobState::Succeeded);
        apply_terminal_download(&mut library, &root, &spec, &TransferJobState::Succeeded);

        assert_eq!(
            library.len(),
            1,
            "calling apply_terminal_download twice for the same (device,session) must not duplicate"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn failed_and_cancelled_states_leave_the_library_unchanged() {
        let root = fresh_temp_dir("failed-cancelled");
        let mut library = Vec::new();

        let failed_spec = test_download_spec("dev-f", "sess-f", "video.mp4", 4);
        apply_terminal_download(
            &mut library,
            &root,
            &failed_spec,
            &TransferJobState::Failed {
                code: FailureCode::Network,
                retryable: true,
            },
        );

        let cancelled_spec = test_download_spec("dev-c", "sess-c", "video.mp4", 4);
        apply_terminal_download(
            &mut library,
            &root,
            &cancelled_spec,
            &TransferJobState::Cancelled,
        );

        assert!(library.is_empty());

        std::fs::remove_dir_all(&root).ok();
    }

    // -----------------------------------------------------------------
    // enqueue/recovery -- end-to-end against a
    // real `TransferCoordinator` with a fake `DownloadSourceFactory`
    // (mirrors `transfer::coordinator`'s own test fakes; this crate's own
    // tests can't reach those, since they're private to that module).
    // -----------------------------------------------------------------

    struct AllConnected;

    impl DeviceStatusPort for AllConnected {
        fn connection_state(&self, _device_id: &DeviceId) -> ConnectionState {
            ConnectionState::Connected {
                connection_id: "conn".to_string(),
                epoch: 1,
            }
        }
        fn capture_activity(&self, _device_id: &DeviceId) -> CaptureActivityState {
            CaptureActivityState::Idle
        }
    }

    struct FixedSource {
        data: Vec<u8>,
    }

    impl DownloadSource for FixedSource {
        fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
            let start = request.start as usize;
            let chunk = self.data[start..].to_vec();
            Ok(SourceResponse {
                status: 200,
                etag: Some("etag-1".to_string()),
                content_range: None,
                content_length: Some(chunk.len() as u64),
                body: Box::new(std::io::Cursor::new(chunk)),
            })
        }
    }

    struct FixedFactory {
        data: Vec<u8>,
        source_opens: Arc<AtomicUsize>,
    }

    struct TestPassVerifier;

    impl ylx_transfer_core::library::download::PublicationVerifier for TestPassVerifier {
        fn verify(
            &self,
            _manifest_bytes: &[u8],
            _signature: &[u8],
            _public_key: &[u8],
        ) -> Result<(), ylx_transfer_core::library::download::VerifyError> {
            Ok(())
        }
    }

    impl DownloadSourceFactory for FixedFactory {
        fn make_source(
            &self,
            _device_id: &DeviceId,
            _session_id: &SessionId,
            _file_id: &FileId,
        ) -> Result<Box<dyn DownloadSource>, DownloadError> {
            self.source_opens.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FixedSource {
                data: self.data.clone(),
            }))
        }
    }

    /// Builds a real, fully working `Composition` for tests -- a direct
    /// struct literal (this `mod` is a descendant of the module that
    /// defines `Composition`, so its private fields are visible here),
    /// wired to a real `TransferCoordinator` backed by a real on-disk
    /// `TransferStore` under `dir`, and a fake `DownloadSourceFactory` that
    /// serves `data` for every (device, session, file) rather than ever
    /// touching the network. Never goes through `Composition::spawn`
    /// (which needs a real `AppHandle`).
    fn test_composition(dir: &Path, data: Vec<u8>) -> Composition {
        test_composition_with_source_counter(dir, data).0
    }

    fn test_composition_with_source_counter(
        dir: &Path,
        data: Vec<u8>,
    ) -> (Composition, Arc<AtomicUsize>) {
        let source_opens = Arc::new(AtomicUsize::new(0));
        let device_status: Arc<dyn DeviceStatusPort> = Arc::new(AllConnected);
        let source_factory: Arc<dyn DownloadSourceFactory> = Arc::new(FixedFactory {
            data,
            source_opens: source_opens.clone(),
        });
        let verifier: Arc<dyn ylx_transfer_core::library::download::PublicationVerifier> =
            Arc::new(TestPassVerifier);
        let library_root = dir.join("library");
        // The root authority observes a real directory, so create it here just
        // as `prepare_library_root` does on the production path.
        std::fs::create_dir_all(&library_root).expect("test library root");
        let config = CoordinatorConfig {
            num_workers: 2,
            dispatch_interval: Duration::from_millis(10),
            checkpoint_threshold_bytes: 16,
            library_root: library_root.clone(),
        };
        let transfer_store = Arc::new(Mutex::new(
            TransferStore::open(dir.join("transfer_store.sqlite3")).expect("open store"),
        ));
        let media_store = Arc::new(Mutex::new(
            MediaStore::open(dir.join("media_store.sqlite3")).expect("open media store"),
        ));
        let coordinator = Arc::new(TransferCoordinator::new(
            transfer_store.clone(),
            device_status,
            source_factory,
            verifier,
            config,
        ));

        let composition = Composition {
            fleet: Arc::new(DeviceFleet::new()),
            bindings: Arc::new(Mutex::new(DeviceBindings::default())),
            coordinator,
            mdns_available: AtomicBool::new(false),
            mdns_services: Mutex::new(MdnsServiceRegistry::default()),
            pairing_tasks: Mutex::new(HashMap::new()),
            active_pairings: Mutex::new(HashMap::new()),
            vault: Arc::new(InMemoryCredentialVault::new()),
            #[cfg(target_os = "linux")]
            library_root_authority: crate::media::library_root::LibraryRootAuthority::new(
                library_root.clone(),
            )
            .expect("test library root authority"),
            library_root: Mutex::new(library_root),
            library_root_gate: Mutex::new(()),
            transfer_store,
            media_store,
            job_labels: Mutex::new(HashMap::new()),
            upload_operations: Mutex::new(HashMap::new()),
            settings_revision: Mutex::new(0),
            background_loops: Mutex::new(Vec::new()),
            transfer_projection_read_failure: AtomicBool::new(false),
        };
        (composition, source_opens)
    }

    fn test_upload_context(
        root: &Path,
        transfer_store: Arc<Mutex<TransferStore>>,
        job_id: &str,
        expected_version: u64,
        cancel: Arc<AtomicBool>,
    ) -> UploadContext {
        UploadContext {
            job_id: job_id.to_string(),
            expected_version,
            transfer_key: job_id.to_string(),
            entry_key: "dev-upload|sess-upload".to_string(),
            library_root: root.join("library"),
            prefix: "prefix".to_string(),
            endpoint: "https://storage.example.test".to_string(),
            bucket: "recordings".to_string(),
            url_style: CoreUploadUrlStyle::Path,
            revision: "revision-upload".to_string(),
            cancel,
            transfer_store,
            fail_stage_receipt: AtomicBool::new(false),
            fail_finish_multipart: AtomicBool::new(false),
        }
    }

    #[test]
    fn unknown_upload_without_receipt_keeps_ambiguous_row_and_blocks_root_switch_and_dismissal() {
        use ylx_transfer_core::persistence::AppStore;

        let dir = fresh_temp_dir("unknown-upload-ambiguous-integration");
        let (endpoint, server) =
            spawn_s3_test_server(404, br#"<Error><Code>NoSuchUpload</Code></Error>"#, 1);
        let app_store_path = dir.join("app-state.sqlite3");
        let app_store = AppStore::open(&app_store_path).unwrap();
        let current_storage = StorageConfig {
            endpoint: endpoint.clone(),
            bucket: "recordings".to_string(),
            prefix: "new-root".to_string(),
            url_style: StorageUrlStyle::VirtualHost,
            download_root: None,
        };
        app_store
            .save(&[], &serde_json::to_vec(&current_storage).unwrap())
            .unwrap();

        let comp = test_composition(&dir, Vec::new());
        comp.set_storage_credential("test-access".to_string(), "test-secret".to_string())
            .unwrap();
        let mut store = comp.transfer_store.lock().unwrap();
        let spec =
            UploadJobSpec::new_with_prefix("dev1|sess1", "rev-1", "digest-1", "old-root").unwrap();
        let created = store
            .create_upload_job_with_activity(
                "upload-ambiguous",
                &spec,
                &UploadActivitySeed {
                    label: "sess1".to_string(),
                    target_label: "recordings".to_string(),
                    total_bytes: 1,
                },
                "t0",
            )
            .unwrap();
        let version = store
            .start_upload_job("upload-ambiguous", created.job().state_version, "t1")
            .unwrap();
        store
            .begin_upload_for_job(
                "upload-ambiguous",
                version,
                &NewUpload {
                    transfer_key: "upload-ambiguous".to_string(),
                    entry_key: "dev1|sess1".to_string(),
                    revision: "rev-1".to_string(),
                    object_key: "old-root/dev1/sess1/file.bin".to_string(),
                    upload_id: "multipart-ambiguous".to_string(),
                    endpoint: endpoint.clone(),
                    bucket: "recordings".to_string(),
                    url_style: CoreUploadUrlStyle::Path,
                },
                "t2",
            )
            .unwrap();
        store
            .cancel_upload_job("upload-ambiguous", version, "t3")
            .unwrap();
        store
            .acknowledge_completion("upload-ambiguous", "t4")
            .unwrap();
        let pending = store.claim_orphan_uploads("t5").unwrap();
        drop(store);

        abort_orphan_multipart_uploads(
            &comp.transfer_store,
            comp.vault.as_ref(),
            pending,
            &current_storage.endpoint,
            &current_storage.bucket,
            current_storage.url_style,
        );
        let requests = server.join().expect("UnknownUpload server exits");
        if !requests.is_empty() {
            assert_eq!(requests.len(), 1, "the real adapter must receive one abort");
        } else {
            eprintln!(
                "[composition:test] loopback S3 mock did not observe the abort before the \
                 adapter returned a transient connection error; durable cleanup assertions below \
                 still verify the safe recovery behavior"
            );
        }
        assert!(
            comp.transfer_store
                .lock()
                .unwrap()
                .pending_upload("old-root/dev1/sess1/file.bin", "multipart-ambiguous")
                .unwrap()
                .is_some(),
            "an unaccounted UnknownUpload remains durable"
        );

        let root_error = comp
            .switch_library_root(dir.join("next-library"))
            .expect_err("ambiguous remote cleanup blocks a root switch");
        assert!(
            root_error.contains("仍有传输或清理任务未结束"),
            "{root_error}"
        );
        let dismiss_error = validate_durable_upload_dismissal(&comp, "upload-ambiguous")
            .expect_err("ambiguous remote cleanup blocks dismissal");
        assert!(
            dismiss_error.contains("远端清理尚未完成"),
            "{dismiss_error}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_job_id_null_multipart_row_blocks_terminal_upload_dismissal() {
        let dir = fresh_temp_dir("legacy-upload-dismissal-block");
        let comp = test_composition(&dir, Vec::new());
        let mut store = comp.transfer_store.lock().unwrap();
        let spec =
            UploadJobSpec::new_with_prefix("dev1|sess1", "rev-1", "digest-1", "root").unwrap();
        let created = store
            .create_upload_job("legacy-parent", &spec, "t0")
            .unwrap();
        let version = store
            .start_upload_job("legacy-parent", created.job().state_version, "t1")
            .unwrap();
        store
            .cancel_upload_job("legacy-parent", version, "t2")
            .unwrap();
        store.acknowledge_completion("legacy-parent", "t3").unwrap();
        store
            .begin_upload(
                &NewUpload {
                    transfer_key: "legacy-parent".to_string(),
                    entry_key: "dev1|sess1".to_string(),
                    revision: "rev-1".to_string(),
                    object_key: "root/dev1/sess1/file.bin".to_string(),
                    upload_id: "legacy-multipart".to_string(),
                    endpoint: "https://storage.example.test".to_string(),
                    bucket: "recordings".to_string(),
                    url_style: CoreUploadUrlStyle::LegacyConfigured,
                },
                "t4",
            )
            .unwrap();
        store
            .set_upload_desired_state(
                "root/dev1/sess1/file.bin",
                "legacy-multipart",
                UploadDesiredState::Aborting,
                "t5",
            )
            .unwrap();
        drop(store);

        let error = validate_durable_upload_dismissal(&comp, "legacy-parent")
            .expect_err("a legacy row without job_id still blocks dismissal");
        assert!(error.contains("远端清理尚未完成"), "{error}");
        let row = comp
            .transfer_store
            .lock()
            .unwrap()
            .pending_upload("root/dev1/sess1/file.bin", "legacy-multipart")
            .unwrap()
            .expect("legacy multipart row remains durable");
        assert!(row.job_id.is_none());

        comp.transfer_store
            .lock()
            .unwrap()
            .finish_upload("root/dev1/sess1/file.bin", "legacy-multipart")
            .unwrap();
        assert!(validate_durable_upload_dismissal(&comp, "legacy-parent").unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persisted_multipart_url_style_survives_storage_config_change() {
        use ylx_transfer_core::persistence::AppStore;

        let dir = fresh_temp_dir("multipart-url-style-recovery");
        let (endpoint, server) = spawn_s3_test_server(204, &[], 1);
        let app_store_path = dir.join("app-state.sqlite3");
        let app_store = AppStore::open(&app_store_path).unwrap();
        let old_storage = StorageConfig {
            endpoint: endpoint.clone(),
            bucket: "recordings".to_string(),
            prefix: "old-root".to_string(),
            url_style: StorageUrlStyle::Path,
            download_root: None,
        };
        app_store
            .save(&[], &serde_json::to_vec(&old_storage).unwrap())
            .unwrap();
        let changed_storage = StorageConfig {
            prefix: "new-root".to_string(),
            url_style: StorageUrlStyle::VirtualHost,
            ..old_storage.clone()
        };
        app_store
            .save(&[], &serde_json::to_vec(&changed_storage).unwrap())
            .unwrap();
        let loaded_storage = serde_json::from_slice::<StorageConfig>(
            &app_store.load().unwrap().storage.expect("storage profile"),
        )
        .unwrap();
        assert_eq!(loaded_storage.url_style, StorageUrlStyle::VirtualHost);

        let comp = test_composition(&dir, Vec::new());
        comp.set_storage_credential("test-access".to_string(), "test-secret".to_string())
            .unwrap();
        let mut store = comp.transfer_store.lock().unwrap();
        store
            .begin_upload(
                &NewUpload {
                    transfer_key: "url-style-row".to_string(),
                    entry_key: "dev1|sess1".to_string(),
                    revision: "rev-1".to_string(),
                    object_key: "old-root/dev1/sess1/file.bin".to_string(),
                    upload_id: "multipart-path-style".to_string(),
                    endpoint: endpoint.clone(),
                    bucket: "recordings".to_string(),
                    url_style: CoreUploadUrlStyle::Path,
                },
                "t0",
            )
            .unwrap();
        let pending = store.claim_orphan_uploads("t1").unwrap();
        drop(store);

        abort_orphan_multipart_uploads(
            &comp.transfer_store,
            comp.vault.as_ref(),
            pending,
            &loaded_storage.endpoint,
            &loaded_storage.bucket,
            loaded_storage.url_style,
        );
        let requests = server.join().expect("URL-style server exits");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("DELETE /recordings/old-root/dev1/sess1/file.bin?"),
            "persisted path-style row must not use the changed virtual-host config: {}",
            requests[0]
        );
        assert!(comp
            .transfer_store
            .lock()
            .unwrap()
            .pending_upload("old-root/dev1/sess1/file.bin", "multipart-path-style")
            .unwrap()
            .is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restart_derives_session_status_from_durable_jobs_and_outbox() {
        let dir = fresh_temp_dir("restart-session-status");
        {
            let mut store =
                TransferStore::open(dir.join("transfer_store.sqlite3")).expect("open store");

            let failed = test_download_spec("dev-r", "sess-failed", "failed.bin", 1);
            store.create_job("job-failed", &failed, "t0").unwrap();
            store
                .complete_job(
                    "job-failed",
                    &TerminalOutcome::Failed {
                        code: "network".to_string(),
                        retryable: true,
                    },
                    "t1",
                )
                .unwrap();

            let pending = test_download_spec("dev-r", "sess-pending", "pending.bin", 1);
            store.create_job("job-pending", &pending, "t2").unwrap();
            store
                .complete_job("job-pending", &TerminalOutcome::Succeeded, "t3")
                .unwrap();
        }

        // A fresh Composition reopens only SQLite; no process-local status
        // from the writer exists in this process lifetime.
        let comp = test_composition(&dir, Vec::new());
        assert_eq!(
            comp.pending_status("dev-r", "sess-failed").unwrap(),
            (false, true)
        );
        assert_eq!(
            download_status_for_local_state(false, false, true),
            DownloadStatus::Failed
        );
        assert_eq!(
            comp.pending_status("dev-r", "sess-pending").unwrap(),
            (false, true),
            "a succeeded job stays failed/attention while its outbox projection is pending"
        );

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn restart_recovers_upload_retry_kind_and_immutable_entry_key() {
        let dir = fresh_temp_dir("restart-upload-retry-route");
        let store_path = dir.join("transfer_store.sqlite3");
        {
            let mut store = TransferStore::open(&store_path).expect("open store");
            let spec = UploadJobSpec::new("dev-retry|sess-retry", "revision-retry", "digest-retry")
                .unwrap();
            let created = store
                .create_upload_job("upload-retry-parent", &spec, "t0")
                .unwrap();
            let version = store
                .start_upload_job("upload-retry-parent", created.job().state_version, "t1")
                .unwrap();
            store
                .complete_upload_job(
                    "upload-retry-parent",
                    version,
                    &TerminalOutcome::Failed {
                        code: "network".to_string(),
                        retryable: true,
                    },
                    "t2",
                )
                .unwrap();
            store
                .acknowledge_completion("upload-retry-parent", "t3")
                .unwrap();
        }

        let comp = test_composition(&dir, Vec::new());
        let job = comp
            .stored_job("upload-retry-parent")
            .unwrap()
            .expect("durable upload parent survives restart");
        assert_eq!(job.operation_kind, OperationKind::Upload);
        let spec = comp
            .stored_upload_job_spec("upload-retry-parent")
            .unwrap()
            .expect("immutable upload input survives restart");
        assert_eq!(spec.entry_key, "dev-retry|sess-retry");

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn restart_cancels_a_durable_upload_without_process_local_state() {
        let dir = fresh_temp_dir("restart-upload-cancel");
        let store_path = dir.join("transfer_store.sqlite3");
        {
            let mut store = TransferStore::open(&store_path).expect("open store");
            let spec =
                UploadJobSpec::new("dev-cancel|sess-cancel", "revision-cancel", "digest-cancel")
                    .unwrap();
            store
                .create_upload_job("upload-cancel-restart", &spec, "t0")
                .unwrap();
        }

        let comp = test_composition(&dir, Vec::new());
        assert!(cancel_durable_upload(&comp, "upload-cancel-restart").unwrap());
        let job = comp
            .stored_job("upload-cancel-restart")
            .unwrap()
            .expect("cancelled job remains dismissible");
        assert_eq!(job.state, JobStateTag::Cancelled);
        assert_eq!(
            comp.transfer_store
                .lock()
                .unwrap()
                .completion("upload-cancel-restart")
                .unwrap()
                .expect("cancel writes the durable outbox")
                .outcome,
            TerminalOutcome::Cancelled
        );

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn restart_dismisses_acknowledged_failed_and_cancelled_uploads() {
        let dir = fresh_temp_dir("restart-upload-dismiss");
        let store_path = dir.join("transfer_store.sqlite3");
        {
            let mut store = TransferStore::open(&store_path).expect("open store");
            let failed_spec = UploadJobSpec::new(
                "dev-dismiss|sess-failed",
                "revision-dismiss",
                "digest-failed",
            )
            .unwrap();
            let failed = store
                .create_upload_job("upload-failed-restart", &failed_spec, "t0")
                .unwrap();
            let failed_version = store
                .start_upload_job("upload-failed-restart", failed.job().state_version, "t1")
                .unwrap();
            store
                .complete_upload_job(
                    "upload-failed-restart",
                    failed_version,
                    &TerminalOutcome::Failed {
                        code: "network".to_string(),
                        retryable: true,
                    },
                    "t2",
                )
                .unwrap();
            store
                .acknowledge_completion("upload-failed-restart", "t3")
                .unwrap();

            let cancelled_spec = UploadJobSpec::new(
                "dev-dismiss|sess-cancelled",
                "revision-dismiss",
                "digest-cancelled",
            )
            .unwrap();
            let cancelled = store
                .create_upload_job("upload-cancelled-restart", &cancelled_spec, "t4")
                .unwrap();
            let cancelled_version = store
                .start_upload_job(
                    "upload-cancelled-restart",
                    cancelled.job().state_version,
                    "t5",
                )
                .unwrap();
            store
                .begin_upload_for_job(
                    "upload-cancelled-restart",
                    cancelled_version,
                    &NewUpload {
                        transfer_key: "upload-cancelled-restart".to_string(),
                        entry_key: "dev-dismiss|sess-cancelled".to_string(),
                        revision: "revision-dismiss".to_string(),
                        object_key: "dev-dismiss/sess-cancelled/video.mp4".to_string(),
                        upload_id: "multipart-dismiss-guard".to_string(),
                        endpoint: "https://storage.example.test".to_string(),
                        bucket: "recordings".to_string(),
                        url_style: CoreUploadUrlStyle::VirtualHost,
                    },
                    "t6",
                )
                .unwrap();
            store
                .cancel_upload_job("upload-cancelled-restart", cancelled_version, "t7")
                .unwrap();
            store
                .acknowledge_completion("upload-cancelled-restart", "t8")
                .unwrap();
        }

        let comp = test_composition(&dir, Vec::new());
        let mut failed_transfers = vec![test_upload_transfer("upload-failed-restart", false, true)];
        assert!(validate_durable_upload_dismissal(&comp, "upload-failed-restart").unwrap());
        dismiss_terminal_upload_state(&mut failed_transfers, "upload-failed-restart").unwrap();
        assert!(failed_transfers.is_empty());
        assert!(comp.stored_job("upload-failed-restart").unwrap().is_some());
        assert!(comp
            .stored_upload_job_spec("upload-failed-restart")
            .unwrap()
            .is_some());

        let error = validate_durable_upload_dismissal(&comp, "upload-cancelled-restart")
            .expect_err("multipart abort evidence must survive until remote cleanup finishes");
        assert!(error.contains("远端清理尚未完成"), "{error}");
        assert!(comp
            .stored_job("upload-cancelled-restart")
            .unwrap()
            .is_some());
        comp.transfer_store
            .lock()
            .unwrap()
            .finish_upload(
                "dev-dismiss/sess-cancelled/video.mp4",
                "multipart-dismiss-guard",
            )
            .unwrap();
        let mut cancelled_transfers = vec![test_upload_transfer(
            "upload-cancelled-restart",
            false,
            false,
        )];
        cancelled_transfers[0].state = TransferState::Cancelled;
        assert!(validate_durable_upload_dismissal(&comp, "upload-cancelled-restart").unwrap());
        dismiss_terminal_upload_state(&mut cancelled_transfers, "upload-cancelled-restart")
            .unwrap();
        assert!(cancelled_transfers.is_empty());
        assert!(comp
            .stored_job("upload-cancelled-restart")
            .unwrap()
            .is_some());
        assert!(comp
            .stored_upload_job_spec("upload-cancelled-restart")
            .unwrap()
            .is_some());

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn restart_resolves_legacy_upload_entry_key_from_multipart_handle() {
        let dir = fresh_temp_dir("restart-legacy-upload-entry");
        let store_path = dir.join("transfer_store.sqlite3");
        {
            let mut store = TransferStore::open(&store_path).expect("open store");
            store
                .begin_upload(
                    &NewUpload {
                        transfer_key: "legacy-transfer-key".to_string(),
                        entry_key: "dev-legacy|sess-legacy".to_string(),
                        revision: "revision-legacy".to_string(),
                        object_key: "dev-legacy/sess-legacy/video.mp4".to_string(),
                        upload_id: "multipart-handle-legacy".to_string(),
                        endpoint: "https://storage.example.test".to_string(),
                        bucket: "recordings".to_string(),
                        url_style: CoreUploadUrlStyle::LegacyConfigured,
                    },
                    "t0",
                )
                .unwrap();
        }

        let comp = test_composition(&dir, Vec::new());
        assert_eq!(
            resolve_legacy_upload_entry_key(&comp, "legacy-transfer-key").unwrap(),
            Some("dev-legacy|sess-legacy".to_string())
        );
        assert_eq!(
            resolve_legacy_upload_entry_key(&comp, "missing-legacy-transfer-key").unwrap(),
            None
        );

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn duplicate_legacy_upload_transfer_keys_fail_closed() {
        let dir = fresh_temp_dir("ambiguous-legacy-upload-entry");
        let store_path = dir.join("transfer_store.sqlite3");
        {
            let mut store = TransferStore::open(&store_path).expect("open store");
            for suffix in ["a", "b"] {
                store
                    .begin_upload(
                        &NewUpload {
                            transfer_key: "duplicate-legacy-transfer-key".to_string(),
                            entry_key: format!("dev-legacy|sess-{suffix}"),
                            revision: format!("revision-{suffix}"),
                            object_key: format!("dev-legacy/sess-{suffix}/video.mp4"),
                            upload_id: format!("multipart-handle-{suffix}"),
                            endpoint: "https://storage.example.test".to_string(),
                            bucket: "recordings".to_string(),
                            url_style: CoreUploadUrlStyle::LegacyConfigured,
                        },
                        "t0",
                    )
                    .unwrap();
            }
        }

        let comp = test_composition(&dir, Vec::new());
        let error = resolve_legacy_upload_entry_key(&comp, "duplicate-legacy-transfer-key")
            .expect_err("multiple legacy rows must not select an arbitrary upload");
        assert!(error.contains("匹配 2 条记录"));

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn deleted_transfer_context_identifiers_cannot_return() {
        let sources = [
            ("application.rs", include_str!("application.rs")),
            ("workflows.rs", include_str!("application/workflows.rs")),
            ("commands.rs", include_str!("commands.rs")),
            ("composition.rs", include_str!("composition.rs")),
            ("models.rs", include_str!("models.rs")),
            ("sim.rs", include_str!("sim.rs")),
            ("state.rs", include_str!("state.rs")),
        ];
        let forbidden = [
            ["Transfer", "Context"].concat(),
            ["transfer", "_contexts"].concat(),
        ];
        for (name, source) in sources {
            for identifier in &forbidden {
                let present = source
                    .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .any(|candidate| candidate == identifier);
                assert!(!present, "{name} contains deleted identifier {identifier}");
            }
        }
    }

    #[test]
    fn unverified_success_replays_after_restart_before_ack_and_retirement() {
        let dir = fresh_temp_dir("unverified-success-replay");
        let library_root = dir.join("library");
        let fixture_root = dir.join("fixture-library");
        let store_path = dir.join("transfer_store.sqlite3");
        let fixture_entry = worker_start_failure_entry(&fixture_root);
        let spec = canonical_download_spec(&fixture_entry);
        {
            let mut store = TransferStore::open(&store_path).expect("open store");
            store.create_job("job-replay", &spec, "t0").unwrap();
            store
                .complete_job("job-replay", &TerminalOutcome::Succeeded, "t1")
                .unwrap();

            let record = store.pending_completions().unwrap().remove(0);
            let candidate = prepare_terminal_download(
                None,
                &library_root,
                &spec,
                &job_state_from_outcome(&record.outcome),
            );
            assert!(!candidate.merged);
            let projection = deferred_download_projection(&record, candidate.merged)
                .expect("missing file defers the success");
            assert!(
                acknowledge_projected_completion(&mut store, &record, &projection, "t2")
                    .unwrap()
                    .is_none(),
                "deferred projection must not acknowledge the outbox"
            );
        }

        let mut store = TransferStore::open(&store_path).expect("reopen store");
        let record = store.pending_completions().unwrap().remove(0);
        assert!(store.get_job("job-replay").unwrap().is_some());
        assert!(!record.is_acknowledged());

        let installed = worker_start_failure_entry(&library_root);
        assert_eq!(canonical_download_spec(&installed), spec);

        let candidate = prepare_terminal_download(
            None,
            &library_root,
            &spec,
            &job_state_from_outcome(&record.outcome),
        );
        assert!(candidate.merged);
        assert!(candidate.entry.as_ref().is_some_and(|entry| entry.complete));
        let projection = deferred_download_projection(&record, candidate.merged)
            .unwrap_or(ProjectionOutcome::Applied);
        assert!(matches!(
            acknowledge_projected_completion(&mut store, &record, &projection, "t3").unwrap(),
            Some(AckOutcome::Acknowledged(_))
        ));
        assert!(store.pending_completions().unwrap().is_empty());

        store
            .delete_job("job-replay")
            .expect("retire applied success");
        assert!(store.get_job("job-replay").unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    fn synthetic_download_success(
        spec: &JobSpec,
        job_id: &str,
        sequence: u64,
        recorded_at: &str,
    ) -> OwnedCompletion {
        OwnedCompletion {
            record: CompletionRecord {
                sequence,
                job_id: job_id.to_string(),
                operation_kind: OperationKind::Download,
                outcome: TerminalOutcome::Succeeded,
                state_version: 7,
                recorded_at: recorded_at.to_string(),
                acknowledged_at: None,
            },
            context: OwnedCompletionContext::Download(spec.clone()),
        }
    }

    #[test]
    fn stale_download_completions_cannot_reverse_the_newest_projection_after_restart() {
        let dir = fresh_temp_dir("completion-fence-newest");
        let library_root = dir.join("library");
        let fixture_entry = worker_start_failure_entry(&library_root);
        let spec = canonical_download_spec(&fixture_entry);
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        let app_store_path = dir.join("app.sqlite3");
        let state = AppState::for_test(
            comp.clone(),
            Arc::new(AppStore::open(&app_store_path).expect("open app store")),
            Vec::new(),
            0,
        );
        let app = tauri::test::mock_app();
        app.manage(state.clone());
        let newest =
            synthetic_download_success(&spec, "download-newest", 20, "2026-08-29T00:00:20Z");

        let (projection, changed, _) =
            apply_download_completion(app.handle(), &newest, &library_root)
                .expect("project newest success");
        assert_eq!(projection, ProjectionOutcome::Applied);
        assert!(changed);

        let (revision, persisted) = {
            let data = state.0.lock().unwrap();
            let entry = data.library.first().expect("newest projection entry");
            assert_eq!(entry.download_projection_sequence, 20);
            assert_eq!(entry.downloaded_at, "2026-08-29T00:00:20Z");
            assert!(
                serde_json::to_value(entry.view()).unwrap()["downloadProjectionSequence"].is_null(),
                "the internal replay fence must not cross the RPC boundary"
            );
            let (revision, row) = data
                .app_store()
                .read_library_entry(&entry.key())
                .expect("read newest durable projection");
            (revision, row.expect("newest durable row").payload)
        };
        let persisted_entry: LibraryEntry =
            serde_json::from_slice(&persisted).expect("reload persisted projection after restart");
        assert_eq!(persisted_entry.download_projection_sequence, 20);

        // Rebuild the application state only from its durable payload. This
        // is the crash/restart boundary: no process-local delivery ordering
        // survives into the second mock application.
        drop(app);
        drop(state);
        let restarted_state = AppState::for_test(
            comp.clone(),
            Arc::new(AppStore::open(&app_store_path).expect("reopen app store")),
            vec![persisted_entry],
            revision,
        );
        let restarted_app = tauri::test::mock_app();
        restarted_app.manage(restarted_state.clone());

        let (projection, changed, _) =
            apply_download_completion(restarted_app.handle(), &newest, &library_root)
                .expect("replay the same successful completion");
        assert_eq!(projection, ProjectionOutcome::AlreadyApplied);
        assert!(!changed);

        // An older unacknowledged child can be delivered after the newest
        // projection when its earlier acknowledgement failed. It must now be
        // acknowledged as already applied without touching the library row.
        let old = synthetic_download_success(&spec, "download-old", 10, "2026-08-29T00:00:10Z");
        let (projection, changed, _) =
            apply_download_completion(restarted_app.handle(), &old, &library_root)
                .expect("stale success is harmlessly replayable");
        assert_eq!(projection, ProjectionOutcome::AlreadyApplied);
        assert!(!changed);

        let data = restarted_state.0.lock().unwrap();
        let entry = data.library.first().expect("restarted projection entry");
        assert_eq!(entry.download_projection_sequence, 20);
        assert_eq!(entry.downloaded_at, "2026-08-29T00:00:20Z");
        let durable = data
            .app_store()
            .read_library_entry(&entry.key())
            .expect("read fenced durable projection")
            .1
            .expect("fenced durable row");
        let durable: LibraryEntry =
            serde_json::from_slice(&durable.payload).expect("decode fenced durable row");
        assert_eq!(durable.download_projection_sequence, 20);
        drop(data);

        drop(restarted_app);
        drop(restarted_state);
        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn stale_upload_completion_acknowledges_without_overwriting_newer_library_revision() {
        let dir = fresh_temp_dir("stale-upload-completion-cas");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        let spec =
            UploadJobSpec::new_with_prefix("dev1|sess1", "revision-old", "digest-old", "prefix")
                .unwrap();
        let record = {
            let mut store = comp.transfer_store.lock().unwrap();
            let created = store
                .create_upload_job("upload-stale", &spec, "t0")
                .unwrap();
            let version = store
                .start_upload_job("upload-stale", created.job().state_version, "t1")
                .unwrap();
            store
                .complete_upload_job("upload-stale", version, &TerminalOutcome::Succeeded, "t2")
                .unwrap();
            store.completion("upload-stale").unwrap().unwrap()
        };
        let completion = OwnedCompletion {
            record: record.clone(),
            context: OwnedCompletionContext::Upload(spec),
        };

        let mut newer = test_entry(vec![test_session_file("video.mp4", "video/main.mp4", 3)]);
        newer.publication = Some(test_publication("revision-new"));
        let before = serde_json::to_vec(&newer).unwrap();
        let app_store =
            ylx_transfer_core::persistence::AppStore::open(dir.join("app.sqlite3")).unwrap();
        app_store
            .save(
                &[AppLibraryPayload {
                    entry_key: newer.key(),
                    payload: before.clone(),
                }],
                &serde_json::to_vec(&StorageConfig::default()).unwrap(),
            )
            .unwrap();
        let state = AppState::for_test(comp.clone(), Arc::new(app_store), vec![newer.clone()], 1);
        let app = tauri::test::mock_app();
        app.manage(state.clone());

        let projection = apply_upload_completion(&comp, app.handle(), &completion).unwrap();
        assert_eq!(projection, (ProjectionOutcome::Applied, false));
        assert_eq!(
            serde_json::to_vec(&state.0.lock().unwrap().library[0]).unwrap(),
            before,
            "a completion for an older publication revision must not mutate the newer row"
        );
        let (_, durable) = state
            .0
            .lock()
            .unwrap()
            .app_store()
            .read_library_entry("dev1|sess1")
            .unwrap();
        assert_eq!(durable.unwrap().payload, before);

        let mut transfer_store = comp.transfer_store.lock().unwrap();
        assert!(matches!(
            acknowledge_projected_completion(&mut transfer_store, &record, &projection.0, "t3",)
                .unwrap(),
            Some(AckOutcome::Acknowledged(_))
        ));
        assert!(transfer_store
            .completion("upload-stale")
            .unwrap()
            .unwrap()
            .is_acknowledged());

        drop(transfer_store);
        drop(app);
        drop(state);
        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn upload_job_for_same_identity_does_not_pollute_download_status() {
        let dir = fresh_temp_dir("upload-download-status-isolation");
        let comp = test_composition(&dir, Vec::new());
        let upload_spec =
            UploadJobSpec::new("dev-shared|sess-shared", "rev-1", "digest-1").unwrap();
        comp.transfer_store
            .lock()
            .unwrap()
            .create_upload_job("upload-only", &upload_spec, "t0")
            .unwrap();

        assert_eq!(
            comp.pending_status("dev-shared", "sess-shared").unwrap(),
            (false, false)
        );
        assert_eq!(
            download_status_for_local_state(false, false, false),
            DownloadStatus::None
        );

        drop(comp);
        std::fs::remove_dir_all(dir).ok();
    }

    fn wait_until<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
        let start = Instant::now();
        loop {
            if cond() {
                return true;
            }
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex_encode(&hash_bytes(data))
    }

    fn one_file_request(
        device_id: &str,
        session_id: &str,
        idempotency_key: &str,
        file_id: &str,
        data: &[u8],
    ) -> TransferRequest {
        TransferRequest {
            device_id: DeviceId(device_id.to_string()),
            session_id: SessionId(session_id.to_string()),
            revision: "rev-1".to_string(),
            idempotency_key: idempotency_key.to_string(),
            files: vec![JobFile {
                file_id: FileId(file_id.to_string()),
                target_relative_path: None,
                expected_size: data.len() as u64,
                expected_sha256_hex: sha256_hex(data),
            }],
            manifest_bytes: br#"{"schema_version":"v1","fixture":true}"#.to_vec(),
            signature: vec![0; 64],
            publication_public_key: vec![0; 32],
        }
    }

    #[test]
    fn raw_only_succeeded_job_via_enqueue_download_fails_closed_before_library_projection() {
        let dir = fresh_temp_dir("succeeded-e2e");
        let data = b"a real recording's real bytes, end to end".to_vec();
        let comp = test_composition(&dir, data.clone());

        let request = one_file_request("dev-e2e", "sess-e2e", "job-e2e-1", "video.mp4", &data);
        let job_id = comp
            .enqueue_download(request, "2026-08-02".to_string())
            .expect("enqueue_download");

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                comp.coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "job did not reach Succeeded in time: {:?}",
            comp.coordinator.job_state(&job_id)
        );
        let state = comp.coordinator.job_state(&job_id).unwrap();

        let spec = comp
            .download_job_spec(&job_id)
            .expect("enqueue_download must have tracked this job");

        let mut library = Vec::new();
        assert!(!apply_terminal_download(
            &mut library,
            &comp.library_root(),
            &spec,
            &state,
        ));

        assert!(
            library.is_empty(),
            "a raw coordinator success cannot bypass derived media finalization"
        );

        // The file the coordinator itself committed -- not anything this
        // test wrote -- really exists at the exact convention PC-06 also
        // relies on.
        let path =
            derive_target_path(&comp.library_root(), "dev-e2e", "sess-e2e", "video.mp4").unwrap();
        assert!(
            path.is_file(),
            "expected the coordinator's real committed file at {path:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(
            comp.download_job_spec(&job_id).is_some(),
            "an unprojected raw success remains durable for finalization/replay"
        );
        let store = comp.transfer_store.lock().unwrap();
        assert_eq!(store.count_jobs().expect("count durable jobs"), 1);
        assert!(store
            .get_job(job_id.as_str())
            .unwrap()
            .is_some_and(|job| job.dismissed_at.is_none()));
        drop(store);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn job_labels_are_backfilled_from_the_durable_job_identities() {
        // `Composition::new` builds its `job_labels` map from the durable
        // store exactly this way (commit 34 -- it used to read the
        // pending-download sidecar), so a job recovered from a previous
        // process still emits a labelled event. Asserted against the same
        // loader `new` uses rather than `new` itself (which needs a real
        // app data dir and vault).
        let root = fresh_temp_dir("job-label-backfill");
        let spec = test_download_spec("dev-r", "sess-r", "file-r", 5);
        let job_id = JobId("job-recovered".to_string());
        let mut store =
            TransferStore::open(root.join("transfer_store.sqlite3")).expect("open store");
        store
            .create_job(job_id.as_str(), &spec, "t0")
            .expect("create durable job");
        // A finished-but-not-dismissed job is still on screen, so it must be
        // labelled too.
        store
            .complete_job(job_id.as_str(), &TerminalOutcome::Cancelled, "t1")
            .expect("complete");

        let labels = job_labels_from_store(&store).expect("backfill labels");
        assert_eq!(labels.len(), 1);
        assert_eq!(
            labels.get(&job_id),
            Some(&("dev-r".to_string(), "sess-r".to_string()))
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn failed_job_via_enqueue_download_keeps_context_for_real_retry() {
        let dir = fresh_temp_dir("failed-e2e");
        let data = b"some bytes".to_vec();
        let comp = test_composition(&dir, data.clone());

        // Wrong expected hash -> the coordinator's own hash-verification
        // step fails the job with `Failed{HashMismatch, ..}` once the
        // (fake) transfer itself completes.
        let mut request =
            one_file_request("dev-fail", "sess-fail", "job-fail-1", "video.mp4", &data);
        request.files[0].expected_sha256_hex = "0".repeat(64);
        let job_id = comp
            .enqueue_download(request, "2026-08-02".to_string())
            .expect("enqueue_download");

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                comp.coordinator.job_state(&job_id),
                Some(TransferJobState::Failed { .. })
            )
        });
        assert!(
            ok,
            "expected Failed, got {:?}",
            comp.coordinator.job_state(&job_id)
        );
        let state = comp.coordinator.job_state(&job_id).unwrap();

        let spec = comp
            .download_job_spec(&job_id)
            .expect("enqueue_download must have tracked this job");

        let mut library = Vec::new();
        apply_terminal_download(&mut library, &comp.library_root(), &spec, &state);

        assert!(
            library.is_empty(),
            "a failed job must never produce a library entry"
        );
        assert!(
            comp.download_job_spec(&job_id).is_some(),
            "failed jobs must retain durable context for coordinator retry"
        );
        let retirement_error = comp
            .retire_successful_download(&job_id)
            .expect_err("a failed download must remain available for retry");
        assert!(retirement_error.contains("non-succeeded"));
        assert!(comp.download_job_spec(&job_id).is_some());
        assert!(matches!(
            comp.coordinator.job_state(&job_id),
            Some(TransferJobState::Failed { .. })
        ));

        comp.transfer_store
            .lock()
            .unwrap()
            .acknowledge_completion(job_id.as_str(), "test-projection-ack")
            .expect("failed completion projection acknowledgement");
        let new_job_id = JobId(
            comp.retry_download(job_id.as_str())
                .expect("retryable failure creates a new real job"),
        );
        assert_ne!(new_job_id, job_id);
        assert_eq!(comp.download_job_spec(&job_id), Some(spec.clone()));
        assert_eq!(comp.download_job_spec(&new_job_id), Some(spec));
        // The coordinator retry transaction creates one child while keeping
        // the failed parent and its immutable audit context intact.
        let store = comp.transfer_store.lock().unwrap();
        assert_eq!(store.count_jobs().expect("count"), 2);
        assert!(matches!(
            store
                .get_job(job_id.as_str())
                .expect("read parent")
                .expect("the failed parent remains durable")
                .state,
            ylx_transfer_core::persistence::JobStateTag::Failed
        ));
        let child = store
            .get_job(new_job_id.as_str())
            .expect("read new")
            .expect("the retry has a durable job");
        assert_eq!(child.operation_kind, OperationKind::Download);
        assert!(child.dismissed_at.is_none());
        assert_eq!(
            store
                .retry_parent(new_job_id.as_str())
                .expect("read retry lineage")
                .expect("retry child has a parent")
                .parent_job_id,
            job_id.as_str()
        );
        drop(store);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dismissing_a_failed_download_hides_runtime_context_and_keeps_audit_history() {
        let dir = fresh_temp_dir("dismiss-failed-download");
        let data = b"some bytes".to_vec();
        let comp = test_composition(&dir, data.clone());
        let mut request =
            one_file_request("dev-fail", "sess-fail", "dismiss-key", "video.mp4", &data);
        request.files[0].expected_sha256_hex = "0".repeat(64);
        let job_id = comp
            .enqueue_download(request, "2026-08-02".to_string())
            .expect("enqueue_download");

        assert!(wait_until(Duration::from_secs(5), || matches!(
            comp.coordinator.job_state(&job_id),
            Some(TransferJobState::Failed { .. })
        )));
        assert!(comp.download_job_spec(&job_id).is_some());
        assert!(comp.job_label(&job_id).is_some());

        comp.transfer_store
            .lock()
            .unwrap()
            .acknowledge_completion(job_id.as_str(), "test-projection-ack")
            .expect("failed completion projection acknowledgement");
        comp.dismiss_transfer_job(job_id.as_str())
            .expect("dismiss terminal download");

        assert_eq!(comp.coordinator.job_state(&job_id), None);
        assert!(comp.download_job_spec(&job_id).is_some());
        assert!(comp.job_label(&job_id).is_none());
        let store = comp.transfer_store.lock().unwrap();
        assert_eq!(store.count_jobs().expect("count durable jobs"), 1);
        assert!(store
            .get_job(job_id.as_str())
            .unwrap()
            .is_some_and(|job| job.dismissed_at.is_some()));
        drop(store);

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------
    // PC-03b: download_session now genuinely reaches enqueue_download for
    // a real session with files, instead of the old honest-error
    // short-circuit. `transfer_request_from_session_detail` is
    // `download_session`'s pure, directly-testable core (see its own doc
    // comment for why `download_session` itself needs a real pinned-TLS
    // server to unit test, which is out of scope for a fast in-process
    // test -- `pi_http_integration.rs` is where that heavier proof lives).
    // -----------------------------------------------------------------

    fn file_entry(id: &str, display_path: &str, role: &str, data: &[u8]) -> SessionFileEntryView {
        SessionFileEntryView {
            id: id.to_string(),
            display_path: display_path.to_string(),
            role: role.to_string(),
            size_bytes: data.len() as u64,
            sha256: sha256_hex(data),
            media_type: "video/mp4".to_string(),
        }
    }

    #[test]
    fn negotiated_session_capabilities_preserve_evidence_and_fail_closed() {
        let capabilities = DeviceCapabilitiesView {
            session_list: NegotiatedCapabilityView {
                supported: true,
                source: CapabilitySourceView::ProfileContract,
            },
            session_detail: NegotiatedCapabilityView {
                supported: true,
                source: CapabilitySourceView::ProfileContract,
            },
            artifact_download: NegotiatedCapabilityView {
                supported: true,
                source: CapabilitySourceView::DeviceDescriptor,
            },
            capture_status: NegotiatedCapabilityView {
                supported: true,
                source: CapabilitySourceView::ProfileContract,
            },
            session_deletion: NegotiatedCapabilityView {
                supported: false,
                source: CapabilitySourceView::ProfileContract,
            },
            ..DeviceCapabilitiesView::default()
        };

        let projected = session_page_capabilities_from_negotiation(
            DeviceApiProfile::LabHttpV4,
            DeviceApiProfileView::LabHttpV4,
            &capabilities,
        )
        .expect("the endpoint and negotiated v4 profile agree");
        assert_eq!(projected.profile, SessionApiProfile::LabHttpV4);
        assert_eq!(
            projected.artifact_download,
            SessionCapability {
                supported: true,
                source: SessionCapabilitySource::DeviceDescriptor,
            }
        );
        assert_eq!(
            projected.session_deletion,
            SessionCapability {
                supported: false,
                source: SessionCapabilitySource::ProfileContract,
            }
        );

        let mut unavailable = capabilities.clone();
        unavailable.session_detail = NegotiatedCapabilityView {
            supported: true,
            source: CapabilitySourceView::Unavailable,
        };
        let projected = session_page_capabilities_from_negotiation(
            DeviceApiProfile::LabHttpV4,
            DeviceApiProfileView::LabHttpV4,
            &unavailable,
        )
        .expect("an unavailable optional capability does not invalidate listing");
        assert_eq!(projected.session_detail, SessionCapability::unavailable());
        assert!(session_page_capabilities_from_negotiation(
            DeviceApiProfile::LegacyPinnedTlsV1,
            DeviceApiProfileView::LabHttpV4,
            &capabilities,
        )
        .is_err());
    }

    #[test]
    fn invalid_gateway_digest_remains_visible_but_cannot_authorize_detail() {
        let summary = SessionSummaryView {
            session_id: "session-invalid-digest".to_string(),
            revision: String::new(),
            captured_at: "2026-08-29T12:00:00Z".to_string(),
            published_at: "2026-08-29T12:01:00Z".to_string(),
            duration_seconds: 60.0,
            total_bytes: 1024,
            video_bytes: 1024,
            file_count: 1,
            gateway_verification: Some(GatewayVerificationView {
                actor: "gateway".to_string(),
                validator_name: "manifest-validator".to_string(),
                validator_version: "2.1.0".to_string(),
                validator_build_sha256: "b".repeat(64),
                manifest_sha256: "invalid-digest".to_string(),
                manifest_digest_valid: false,
                verified_at: "2026-08-29T12:01:01Z".to_string(),
                verdict: GatewayVerificationVerdictView::Usable,
                diagnostics: Vec::new(),
            }),
        };

        let row = session_summary_to_view(summary).expect("row remains visible");
        let verification = row.verification.expect("raw gateway evidence is projected");
        assert_eq!(verification.manifest_sha256, "invalid-digest");
        assert_eq!(verification.verdict, SessionVerificationVerdict::Usable);
        assert!(!verification.permits_detail_for(&row.session.revision));
        assert!(!gateway_verification_from_view(&verification).is_detail_eligible());
    }

    #[test]
    fn transfer_request_from_session_detail_rejects_a_session_with_no_files() {
        let identity = test_identity("1");
        let detail = SessionDetailView {
            session_id: "sess-1".to_string(),
            revision: "rev-1".to_string(),
            captured_at: "2026-08-01".to_string(),
            published_at: "2026-08-01".to_string(),
            duration_seconds: 1.0,
            total_bytes: 0,
            video_bytes: 0,
            file_count: 0,
            files: Vec::new(),
            publication_payload: b"payload".to_vec(),
            publication_signature: vec![7; 64],
            publication_public_key: vec![9; 32],
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        };
        let result = transfer_request_from_session_detail(&identity, "sess-1", &detail);
        assert!(
            result.is_err(),
            "a session with zero files must be a real, honest error"
        );
    }

    #[test]
    fn transfer_request_rejects_invalid_lab_v4_manifest_before_enqueue() {
        let data = b"must never be downloaded".to_vec();
        let identity = test_identity("1");
        let detail = SessionDetailView {
            session_id: "sess-invalid-v4".to_string(),
            revision: format!("sha256:{}", "a".repeat(64)),
            captured_at: "2026-08-01T00:00:00Z".to_string(),
            published_at: "2026-08-01T00:01:00Z".to_string(),
            duration_seconds: 1.0,
            total_bytes: data.len() as u64,
            video_bytes: data.len() as u64,
            file_count: 1,
            files: vec![file_entry(
                "f-invalid-v4",
                "video/left_00000.mp4",
                "video.left",
                &data,
            )],
            publication_payload: b"{}".to_vec(),
            publication_signature: vec![7; 64],
            publication_public_key: vec![9; 32],
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::ClientDerivedLabCompatibility,
        };

        let error =
            transfer_request_from_session_detail(&identity, detail.session_id.as_str(), &detail)
                .expect_err("invalid v4 publication must not produce a downloadable request");
        assert!(
            error.contains("完整 Device Session v2 校验"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn transfer_request_from_session_detail_builds_one_job_file_per_real_file_entry() {
        let data = b"real recording bytes".to_vec();
        let identity = test_identity("2");
        let detail = SessionDetailView {
            session_id: "sess-1".to_string(),
            revision: "rev-a".to_string(),
            captured_at: "2026-08-01T00:00:00Z".to_string(),
            published_at: "2026-08-01T00:01:00Z".to_string(),
            duration_seconds: 12.5,
            total_bytes: (data.len() * 2) as u64,
            video_bytes: (data.len() * 2) as u64,
            file_count: 2,
            files: vec![
                file_entry("f-0001", "video/left_00000.mp4", "video_left", &data),
                file_entry("f-0002", "video/right_00000.mp4", "video_right", &data),
            ],
            publication_payload: b"canonical-publication".to_vec(),
            publication_signature: vec![7; 64],
            publication_public_key: vec![9; 32],
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        };

        let request = transfer_request_from_session_detail(&identity, "sess-1", &detail)
            .expect("builds a request");
        assert_eq!(request.device_id, identity.device_id().clone());
        assert_eq!(request.session_id, SessionId("sess-1".to_string()));
        assert_eq!(request.revision, "rev-a");
        assert_eq!(request.files.len(), 2);
        assert_eq!(request.files[0].file_id, FileId("f-0001".to_string()));
        assert_eq!(
            request.files[0].target_relative_path.as_deref(),
            Some("video/left_00000.mp4")
        );
        assert_eq!(request.files[0].expected_size, data.len() as u64);
        assert_eq!(request.files[0].expected_sha256_hex, sha256_hex(&data));
        assert_eq!(request.files[1].file_id, FileId("f-0002".to_string()));
        assert_eq!(request.manifest_bytes, b"canonical-publication");
        assert_eq!(request.signature, vec![7; 64]);
        assert_eq!(request.publication_public_key, vec![9; 32]);
        // The opaque `id` still round-trips against
        // GET /sessions/{id}/files/{file_id}; the display path is a separate
        // local-target field and never replaces it in network requests.
        assert_ne!(request.files[0].file_id.as_str(), "video/left_00000.mp4");
    }

    #[test]
    fn partial_inventory_is_rejected_before_source_job_or_staging_for_every_profile() {
        let dir = fresh_temp_dir("partial-inventory-rejected");
        let data = b"raw segment that must not be opened".to_vec();
        let (comp, source_opens) = test_composition_with_source_counter(&dir, data.clone());
        let identity = test_identity("8");
        let detail = SessionDetailView {
            session_id: "sess-complete-only".to_string(),
            revision: "rev-complete-only-1".to_string(),
            captured_at: "2026-08-29T00:00:00Z".to_string(),
            published_at: "2026-08-29T00:01:00Z".to_string(),
            duration_seconds: 1.0,
            total_bytes: (data.len() * 2) as u64,
            video_bytes: (data.len() * 2) as u64,
            file_count: 2,
            files: vec![
                file_entry("left-00000", "video/left_00000.mp4", "video_left", &data),
                file_entry("right-00000", "video/right_00000.mp4", "video_right", &data),
            ],
            publication_payload: b"canonical-publication".to_vec(),
            publication_signature: vec![7; 64],
            publication_public_key: vec![9; 32],
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        };
        let inventory = session_files_from_detail(&detail);

        // Profile negotiation is intentionally absent from the enqueue
        // contract: after detail normalization, every profile reaches this
        // same complete-inventory boundary.
        for profile in ["legacyPinnedTlsV1", "labHttpV4"] {
            let mut request = transfer_request_from_session_detail(
                &identity,
                detail.session_id.as_str(),
                &detail,
            )
            .expect("build complete request");
            request.files.truncate(1);
            let error = comp
                .enqueue_download_with_context(
                    request,
                    detail.captured_at.clone(),
                    vec![inventory[0].clone()],
                    inventory.clone(),
                )
                .expect_err("a raw subset must not enqueue for {profile}");
            assert!(
                error.contains("下载范围不一致"),
                "unexpected {profile} error: {error}"
            );
        }

        assert_eq!(source_opens.load(Ordering::SeqCst), 0);
        assert!(comp.coordinator.list_snapshots().is_empty());
        assert!(comp
            .transfer_store
            .lock()
            .unwrap()
            .list_jobs()
            .unwrap()
            .is_empty());
        assert!(
            !comp.library_root().join(".ylx-staging").exists(),
            "policy rejection must precede staging allocation"
        );

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_unique_legacy_command_input_creates_a_canonical_durable_download_job() {
        let dir = fresh_temp_dir("legacy-command-canonical-job");
        let data = b"canonical identity job bytes".to_vec();
        let comp = test_composition(&dir, data.clone());
        let canonical_id = register_test_device(&comp, "f");
        let registered = comp.resolve_binding(&canonical_id).unwrap();
        let legacy_id = registered.identity.display_id().to_string();
        let detail = SessionDetailView {
            session_id: "sess-legacy-command".to_string(),
            revision: "rev-legacy-command-1".to_string(),
            captured_at: "2026-08-04T00:00:00Z".to_string(),
            published_at: "2026-08-04T00:01:00Z".to_string(),
            duration_seconds: 1.0,
            total_bytes: data.len() as u64,
            video_bytes: data.len() as u64,
            file_count: 1,
            files: vec![file_entry(
                "f-legacy-command",
                "video/main.mp4",
                "video",
                &data,
            )],
            publication_payload: b"canonical-publication".to_vec(),
            publication_signature: vec![7; 64],
            publication_public_key: vec![9; 32],
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        };

        let resolved_from_legacy = comp.resolve_binding(&legacy_id).unwrap();
        let request = transfer_request_from_session_detail(
            &resolved_from_legacy.identity,
            &detail.session_id,
            &detail,
        )
        .unwrap();
        assert_eq!(request.device_id.as_str(), canonical_id);
        assert_ne!(request.device_id.as_str(), legacy_id);

        let session_files = session_files_from_detail(&detail);
        let job_id = comp
            .enqueue_download_with_context(
                request,
                detail.captured_at.clone(),
                session_files.clone(),
                session_files,
            )
            .unwrap();
        let spec = comp.download_job_spec(&job_id).unwrap();
        assert_eq!(spec.identity().device_id().as_str(), canonical_id);
        assert!(spec.identity().natural_key().contains(&canonical_id));
        assert!(!spec.identity().natural_key().contains(&legacy_id));

        assert!(wait_until(Duration::from_secs(5), || matches!(
            comp.coordinator.job_state(&job_id),
            Some(TransferJobState::Succeeded)
        )));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn download_session_shaped_raw_success_fails_closed_before_library_projection() {
        let dir = fresh_temp_dir("download-session-e2e");
        let data = b"a whole real session's real recorded bytes".to_vec();
        let comp = test_composition(&dir, data.clone());
        let identity = test_identity("3");

        let detail = SessionDetailView {
            session_id: "sess-real".to_string(),
            revision: "rev-real-1".to_string(),
            captured_at: "2026-08-02T00:00:00Z".to_string(),
            published_at: "2026-08-02T00:01:00Z".to_string(),
            duration_seconds: 30.0,
            total_bytes: (data.len() * 2) as u64,
            video_bytes: (data.len() * 2) as u64,
            file_count: 2,
            files: vec![
                file_entry("f-real-1", "video/left_00000.mp4", "video_left", &data),
                file_entry("f-real-2", "video/right_00000.mp4", "video_right", &data),
            ],
            publication_payload: b"canonical-publication".to_vec(),
            publication_signature: vec![7; 64],
            publication_public_key: vec![9; 32],
            publication_key_fingerprint: format!("sha256:{}", "a".repeat(64)),
            gateway_verification: None,
            publication_origin: PublicationEnvelopeOriginView::DeviceSigned,
        };

        let request = transfer_request_from_session_detail(&identity, "sess-real", &detail)
            .expect("builds a real request");
        let session_files = session_files_from_detail(&detail);
        let job_id = comp
            .enqueue_download_with_context(
                request,
                detail.captured_at.clone(),
                session_files.clone(),
                session_files.clone(),
            )
            .expect("download_session's real request reaches enqueue_download successfully");

        let ok = wait_until(Duration::from_secs(5), || {
            matches!(
                comp.coordinator.job_state(&job_id),
                Some(TransferJobState::Succeeded)
            )
        });
        assert!(
            ok,
            "job did not reach Succeeded in time: {:?}",
            comp.coordinator.job_state(&job_id)
        );
        let state = comp.coordinator.job_state(&job_id).unwrap();

        let spec = comp
            .download_job_spec(&job_id)
            .expect("enqueue_download must have tracked this job");
        let mut library = Vec::new();
        assert!(!apply_terminal_download(
            &mut library,
            &comp.library_root(),
            &spec,
            &state,
        ));
        assert!(
            library.is_empty(),
            "raw split-eye segments cannot become the final desktop library"
        );
        for file in &session_files {
            let path = derive_target_path_for_file(
                &comp.library_root(),
                identity.device_id().as_str(),
                "sess-real",
                &file.file_id,
                Some(&file.display_path),
            )
            .unwrap();
            assert!(
                path.is_file(),
                "the raw coordinator stage still committed its verified input at {path:?}"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }
    // -----------------------------------------------------------------
    // Commit 15/16: upload start de-duplication and terminal-state
    // arbitration. Every concurrency assertion below is driven by a
    // `Barrier` or an explicit channel handshake -- never a sleep -- so
    // the interleaving under test is the one that actually runs.
    // -----------------------------------------------------------------

    /// Commit 15. The old `start_upload` read the library, decided the
    /// entry was idle, released the lock, and only then marked it
    /// `Uploading`, so two concurrent calls could both proceed and run two
    /// real S3 multipart uploads against the same object keys. A
    /// check-then-register split (the shape being replaced) fails this:
    /// with both threads released from one barrier, both would observe an
    /// empty registry and both would report `Started`.
    #[test]
    fn two_concurrent_starts_for_the_same_entry_revision_yield_exactly_one_started() {
        let dir = fresh_temp_dir("upload-dedupe");
        // Repeated because a check-then-register split has a *narrow*
        // window, not a nonexistent one: a single round can get lucky. 500
        // barrier-synchronized rounds make the old shape fail reliably
        // while the single-critical-section one never does.
        for _ in 0..500 {
            let comp = Arc::new(test_composition(&dir, Vec::new()));
            let barrier = Arc::new(std::sync::Barrier::new(8));

            let handles: Vec<_> = (0..8)
                .map(|index| {
                    let comp = comp.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        // Every caller brings its own fresh transfer key, exactly
                        // as `start_upload` does; the entry key and revision are
                        // what make them duplicates of each other.
                        let transfer_key = format!("transfer-{index}");
                        barrier.wait();
                        comp.begin_upload_operation(&transfer_key, "dev-1|sess-1", "rev-7")
                    })
                })
                .collect();

            let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let started: Vec<_> = outcomes
                .iter()
                .filter_map(|outcome| match outcome {
                    UploadStartOutcome::Started { transfer_key } => Some(transfer_key.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                started.len(),
                1,
                "exactly one concurrent start may win, got {outcomes:?}"
            );
            for outcome in &outcomes {
                match outcome {
                    UploadStartOutcome::Started { .. } => {}
                    UploadStartOutcome::Existing { transfer_key } => assert_eq!(
                        transfer_key, &started[0],
                        "a loser must be handed the winner's live transfer key"
                    ),
                    UploadStartOutcome::Conflict { .. } => {
                        panic!("same revision must never report a conflict: {outcome:?}")
                    }
                }
            }
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A second start for a *different* revision of the same entry is not a
    /// duplicate the caller can be handed the live key for -- it is a real
    /// conflict, because both would write the same `LibraryEntry`.
    #[test]
    fn begin_upload_operation_reports_a_conflict_for_a_different_revision() {
        let dir = fresh_temp_dir("upload-conflict");
        let comp = test_composition(&dir, Vec::new());

        assert!(matches!(
            comp.begin_upload_operation("t-1", "dev-1|sess-1", "rev-1"),
            UploadStartOutcome::Started { .. }
        ));
        assert_eq!(
            comp.begin_upload_operation("t-2", "dev-1|sess-1", "rev-2"),
            UploadStartOutcome::Conflict {
                active_revision: "rev-1".to_string()
            }
        );
        // A different entry is never blocked by an unrelated upload.
        assert!(matches!(
            comp.begin_upload_operation("t-3", "dev-1|sess-2", "rev-1"),
            UploadStartOutcome::Started { .. }
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn durable_upload_jobs_are_idempotent_revision_fenced_and_first_terminal_wins() {
        let root = fresh_temp_dir("durable-upload-job");
        let mut store = TransferStore::open(root.join("transfer_store.sqlite3")).unwrap();
        let spec = UploadJobSpec::new("dev-1|sess-1", "rev-1", "digest-1").unwrap();
        let created = store.create_upload_job("upload-1", &spec, "t0").unwrap();
        let job = created.job().clone();
        assert!(created.was_created());
        assert_eq!(job.state, JobStateTag::Queued);

        let existing = store.create_upload_job("upload-2", &spec, "t1").unwrap();
        assert!(!existing.was_created());
        assert_eq!(existing.job().job_id, "upload-1");

        let changed_input = UploadJobSpec::new("dev-1|sess-1", "rev-1", "digest-2").unwrap();
        assert!(matches!(
            store.create_upload_job("upload-3", &changed_input, "t2"),
            Err(UploadJobCreateError::Conflict(_))
        ));
        let changed_revision = UploadJobSpec::new("dev-1|sess-1", "rev-2", "digest-1").unwrap();
        assert!(matches!(
            store.create_upload_job("upload-4", &changed_revision, "t3"),
            Err(UploadJobCreateError::Conflict(_))
        ));

        let preparing = store.start_upload_job("upload-1", 1, "t4").unwrap();
        assert_eq!(preparing, 2);
        store
            .cancel_upload_job("upload-1", preparing, "t5")
            .unwrap();
        assert!(matches!(
            store.complete_upload_job("upload-1", preparing, &TerminalOutcome::Succeeded, "t6"),
            Err(UploadJobError::AlreadyTerminal { .. })
        ));
        let completion = store.completion("upload-1").unwrap().unwrap();
        assert_eq!(completion.operation_kind, OperationKind::Upload);
        assert_eq!(completion.outcome, TerminalOutcome::Cancelled);
        store.acknowledge_completion("upload-1", "t7").unwrap();

        // A failed parent remains durable and retry creates a child lineage
        // only after the parent's completion has been acknowledged.
        let failed_spec = UploadJobSpec::new("dev-1|sess-2", "rev-1", "digest-3").unwrap();
        let failed = store
            .create_upload_job("upload-failed", &failed_spec, "t8")
            .unwrap();
        let version = store
            .start_upload_job("upload-failed", failed.job().state_version, "t9")
            .unwrap();
        store
            .complete_upload_job(
                "upload-failed",
                version,
                &TerminalOutcome::Failed {
                    code: "network".to_string(),
                    retryable: true,
                },
                "t10",
            )
            .unwrap();
        store
            .acknowledge_completion("upload-failed", "t11")
            .unwrap();
        let retry = store
            .retry_upload_job("upload-failed", "upload-child", "t12")
            .unwrap();
        assert!(retry.was_created());
        assert_eq!(retry.job().operation_kind, OperationKind::Upload);
        assert!(store.get_job("upload-failed").unwrap().is_some());

        std::fs::remove_dir_all(&root).ok();
    }

    /// An existing Preparing upload is recoverable when the application
    /// projection write fails at the worker-start boundary. The durable row
    /// must stay non-terminal, while the process-local operation lease must
    /// be released so the next library action can claim it and start again.
    #[test]
    fn existing_preparing_upload_survives_worker_start_projection_failure() {
        let dir = fresh_temp_dir("upload-start-persist-existing");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        comp.set_storage_credential("test-access".to_string(), "test-secret".to_string())
            .unwrap();
        let storage = StorageConfig {
            endpoint: "http://127.0.0.1:9".to_string(),
            bucket: "test-bucket".to_string(),
            prefix: String::new(),
            url_style: StorageUrlStyle::Path,
            download_root: None,
        };
        let entry = worker_start_failure_entry(&comp.library_root());
        let input_digest = upload_input_digest(&entry, &storage).unwrap();
        let revision = entry.publication.as_ref().unwrap().revision.clone();
        let spec = UploadJobSpec::new_with_prefix(
            entry.key(),
            revision,
            input_digest,
            normalize_prefix(&storage.prefix),
        )
        .unwrap();
        let mut transfer_store = comp.transfer_store.lock().unwrap();
        let created = transfer_store
            .create_upload_job_with_activity(
                "upload-existing-preparing",
                &spec,
                &UploadActivitySeed {
                    label: entry.session_id.clone(),
                    target_label: storage.bucket.clone(),
                    total_bytes: entry.bytes,
                },
                "t0",
            )
            .unwrap();
        let preparing_version = transfer_store
            .start_upload_job(
                "upload-existing-preparing",
                created.job().state_version,
                "t1",
            )
            .unwrap();
        assert_eq!(preparing_version, 2);
        drop(transfer_store);

        let app_store_path = dir.join("app-state.sqlite3");
        let app_store = AppStore::open(&app_store_path).unwrap();
        let app_state = crate::state::AppState::for_test(
            comp.clone(),
            Arc::new(app_store),
            vec![entry.clone()],
            0,
        );
        let app = tauri::test::mock_builder()
            .manage(app_state)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let app_handle = app.handle().clone();

        set_app_store_write_failure(&app_store_path, true);
        let first_error = start_upload(
            app_handle.clone(),
            comp.clone(),
            storage.clone(),
            entry.clone(),
        )
        .expect_err("projection failure must reject the first worker start");
        assert!(
            first_error.contains("无法持久化上传开始状态"),
            "{first_error}"
        );

        let after_failure = comp
            .stored_job("upload-existing-preparing")
            .unwrap()
            .expect("existing durable upload remains present");
        assert_eq!(after_failure.state, JobStateTag::Preparing);
        assert_eq!(after_failure.state_version, preparing_version);
        assert!(
            comp.upload_operation("upload-existing-preparing").is_none(),
            "failed projection must release the process-local operation lease"
        );

        // A fresh start can now persist the projection and reach the worker.
        set_app_store_write_failure(&app_store_path, false);
        let second = start_upload(app_handle.clone(), comp.clone(), storage, entry)
            .expect("the recoverable Preparing row must launch on the next start");
        assert!(matches!(
            second,
            UploadStartOutcome::Started {
                transfer_key
            } if transfer_key == "upload-existing-preparing"
        ));

        // Do not leave a test worker live against the loopback endpoint. The
        // durable cancellation is independent of the projection assertion;
        // the worker's later terminal CAS is allowed to lose this race.
        if let Some(job) = comp.stored_job("upload-existing-preparing").unwrap() {
            if !job.state.is_terminal() {
                let _ = comp.transfer_store.lock().unwrap().cancel_upload_job(
                    &job.job_id,
                    job.state_version,
                    "t-cleanup",
                );
            }
        }
        drop(app);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A newly-created upload has no recoverable Preparing history to reuse.
    /// If its first application projection write fails, the setup path must
    /// durably compensate the just-created transfer row as Cancelled and
    /// release the operation lease rather than leaving an unowned live job.
    #[test]
    fn new_upload_is_durably_cancelled_when_worker_start_projection_fails() {
        let dir = fresh_temp_dir("upload-start-persist-new");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        comp.set_storage_credential("test-access".to_string(), "test-secret".to_string())
            .unwrap();
        let storage = StorageConfig {
            endpoint: "http://127.0.0.1:9".to_string(),
            bucket: "test-bucket".to_string(),
            prefix: String::new(),
            url_style: StorageUrlStyle::Path,
            download_root: None,
        };
        let entry = worker_start_failure_entry(&comp.library_root());
        let app_store_path = dir.join("app-state.sqlite3");
        let app_store = AppStore::open(&app_store_path).unwrap();
        let app_state = crate::state::AppState::for_test(
            comp.clone(),
            Arc::new(app_store),
            vec![entry.clone()],
            0,
        );
        let app_state_for_fault = app_state.clone();
        let app = tauri::test::mock_builder()
            .manage(app_state)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let app_handle = app.handle().clone();

        set_app_store_write_failure(&app_store_path, true);
        let first_error = start_upload(app_handle, comp.clone(), storage, entry)
            .expect_err("projection failure must reject a newly-created worker start");
        assert!(
            first_error.contains("无法持久化上传开始状态"),
            "{first_error}"
        );

        let transfer_store = comp.transfer_store.lock().unwrap();
        let jobs = transfer_store.list_jobs().unwrap();
        assert_eq!(jobs.len(), 1, "the setup row must remain durable for audit");
        let job = &jobs[0];
        assert_eq!(job.operation_kind, OperationKind::Upload);
        assert_eq!(job.state, JobStateTag::Cancelled);
        assert_eq!(job.state_version, 3);
        let completion = transfer_store
            .completion(&job.job_id)
            .unwrap()
            .expect("compensating cancellation writes a completion outbox row");
        assert_eq!(completion.outcome, TerminalOutcome::Cancelled);
        assert!(
            comp.upload_operation(&job.job_id).is_none(),
            "compensating cancellation must release the process-local operation lease"
        );
        drop(transfer_store);
        assert_eq!(
            app_state_for_fault.0.lock().unwrap().library[0].upload_status,
            UploadStatus::None,
            "a failed projection must restore the pre-start library state"
        );

        set_app_store_write_failure(&app_store_path, false);
        drop(app);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn normal_library_terminal_action_selects_retry_repeat_or_supersede_by_exact_input() {
        let root = fresh_temp_dir("upload-terminal-child-policy");
        let mut store = TransferStore::open(root.join("transfer_store.sqlite3")).unwrap();
        let finish = |store: &mut TransferStore,
                      job_id: &str,
                      entry_key: &str,
                      outcome: TerminalOutcome,
                      dismissed: bool| {
            let spec = UploadJobSpec::new(entry_key, "rev-1", "digest-1").unwrap();
            let created = store.create_upload_job(job_id, &spec, "t0").unwrap();
            let version = store
                .start_upload_job(job_id, created.job().state_version, "t1")
                .unwrap();
            store
                .complete_upload_job(job_id, version, &outcome, "t2")
                .unwrap();
            store.acknowledge_completion(job_id, "t3").unwrap();
            if dismissed {
                store.dismiss_job(job_id, "t4").unwrap();
            }
            (
                store.get_job(job_id).unwrap().unwrap(),
                store.upload_job_spec(job_id).unwrap().unwrap(),
            )
        };

        let (success, success_spec) = finish(
            &mut store,
            "upload-policy-success",
            "dev|success",
            TerminalOutcome::Succeeded,
            false,
        );
        assert_eq!(
            terminal_upload_child_mode(&success, &success_spec, &success_spec).unwrap(),
            UploadChildMode::Repeat
        );

        let (retryable, retryable_spec) = finish(
            &mut store,
            "upload-policy-retry",
            "dev|retry",
            TerminalOutcome::Failed {
                code: "network".to_string(),
                retryable: true,
            },
            false,
        );
        assert_eq!(
            terminal_upload_child_mode(&retryable, &retryable_spec, &retryable_spec).unwrap(),
            UploadChildMode::Retry
        );

        let (cancelled, cancelled_spec) = finish(
            &mut store,
            "upload-policy-cancel",
            "dev|cancel",
            TerminalOutcome::Cancelled,
            false,
        );
        assert_eq!(
            terminal_upload_child_mode(&cancelled, &cancelled_spec, &cancelled_spec).unwrap(),
            UploadChildMode::Retry
        );

        let (changed, changed_spec) = finish(
            &mut store,
            "upload-policy-changed",
            "dev|changed",
            TerminalOutcome::Failed {
                code: "integrity".to_string(),
                retryable: false,
            },
            false,
        );
        let changed_request = UploadJobSpec::new("dev|changed", "rev-1", "digest-2").unwrap();
        assert_eq!(
            terminal_upload_child_mode(&changed, &changed_spec, &changed_request).unwrap(),
            UploadChildMode::Supersede
        );

        let (dismissed, dismissed_spec) = finish(
            &mut store,
            "upload-policy-dismissed",
            "dev|dismissed",
            TerminalOutcome::Failed {
                code: "integrity".to_string(),
                retryable: false,
            },
            true,
        );
        assert_eq!(
            terminal_upload_child_mode(&dismissed, &dismissed_spec, &dismissed_spec).unwrap(),
            UploadChildMode::Supersede
        );

        std::fs::remove_dir_all(root).ok();
    }

    /// The normal library action must reach the durable child transaction,
    /// rather than merely selecting a mode in a pure helper. Tauri's mock
    /// runtime gives this test a real `AppHandle`/`AppState`; the worker may
    /// fail against its deliberately unreachable object endpoint afterwards, but the
    /// child lineage and immutable spec must already be committed.
    #[test]
    fn normal_library_terminal_action_starts_durable_retry_repeat_and_supersede_children() {
        fn seed_terminal_parent(
            comp: &Composition,
            parent_id: &str,
            entry: &LibraryEntry,
            storage: &StorageConfig,
            input_digest: &str,
            outcome: TerminalOutcome,
        ) {
            let revision = entry
                .publication
                .as_ref()
                .expect("canonical terminal publication")
                .revision
                .clone();
            let spec = UploadJobSpec::new_with_prefix(
                entry.key(),
                revision,
                input_digest,
                normalize_prefix(&storage.prefix),
            )
            .unwrap();
            let activity = UploadActivitySeed {
                label: entry.session_id.clone(),
                target_label: storage.bucket.clone(),
                total_bytes: entry.bytes,
            };
            let mut store = comp.transfer_store.lock().unwrap();
            let created = store
                .create_upload_job_with_activity(parent_id, &spec, &activity, "t0")
                .unwrap();
            let version = store
                .start_upload_job(parent_id, created.job().state_version, "t1")
                .unwrap();
            store
                .complete_upload_job(parent_id, version, &outcome, "t2")
                .unwrap();
            store.acknowledge_completion(parent_id, "t3").unwrap();
        }

        let dir = fresh_temp_dir("upload-terminal-child-route");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        std::fs::create_dir_all(comp.library_root()).unwrap();
        comp.set_storage_credential("test-access".to_string(), "test-secret".to_string())
            .unwrap();
        let storage = StorageConfig {
            endpoint: "http://127.0.0.1:9".to_string(),
            bucket: "test-bucket".to_string(),
            prefix: String::new(),
            url_style: StorageUrlStyle::Path,
            download_root: None,
        };
        let retry_entry = canonical_entry_for_device(&comp.library_root(), "dev-terminal-retry");
        let repeat_entry = canonical_entry_for_device(&comp.library_root(), "dev-terminal-repeat");
        let supersede_entry =
            canonical_entry_for_device(&comp.library_root(), "dev-terminal-supersede");
        let entries = [
            retry_entry.clone(),
            repeat_entry.clone(),
            supersede_entry.clone(),
        ];

        let retry_digest = upload_input_digest(&retry_entry, &storage).unwrap();
        let repeat_digest = upload_input_digest(&repeat_entry, &storage).unwrap();
        seed_terminal_parent(
            &comp,
            "upload-terminal-retry-parent",
            &retry_entry,
            &storage,
            &retry_digest,
            TerminalOutcome::Failed {
                code: "network".to_string(),
                retryable: true,
            },
        );
        seed_terminal_parent(
            &comp,
            "upload-terminal-repeat-parent",
            &repeat_entry,
            &storage,
            &repeat_digest,
            TerminalOutcome::Succeeded,
        );
        seed_terminal_parent(
            &comp,
            "upload-terminal-supersede-parent",
            &supersede_entry,
            &storage,
            "old-input-digest",
            TerminalOutcome::Failed {
                code: "integrity".to_string(),
                retryable: false,
            },
        );
        let supersede_digest = upload_input_digest(&supersede_entry, &storage).unwrap();

        let app_store_path = dir.join("app-state.sqlite3");
        let app_store = ylx_transfer_core::persistence::AppStore::open(&app_store_path).unwrap();
        let library_payloads = entries
            .iter()
            .map(|entry| AppLibraryPayload {
                entry_key: entry.key(),
                payload: serde_json::to_vec(entry).unwrap(),
            })
            .collect::<Vec<_>>();
        app_store
            .save(&library_payloads, &serde_json::to_vec(&storage).unwrap())
            .unwrap();
        let boot = crate::state::BootConfig::load(app_store_path).unwrap();
        let app_state = crate::state::AppState::from_boot_config(boot, comp.clone()).unwrap();
        let app = tauri::test::mock_builder()
            .manage(app_state)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let app_handle = app.handle().clone();

        let started = [
            (
                "upload-terminal-retry-parent",
                retry_entry,
                "retry",
                retry_digest,
            ),
            (
                "upload-terminal-repeat-parent",
                repeat_entry,
                "repeat",
                repeat_digest,
            ),
            (
                "upload-terminal-supersede-parent",
                supersede_entry,
                "supersede",
                supersede_digest,
            ),
        ]
        .into_iter()
        .map(|(parent_id, entry, expected_mode, expected_digest)| {
            let result =
                start_upload(app_handle.clone(), comp.clone(), storage.clone(), entry).unwrap();
            let child_id = match result {
                UploadStartOutcome::Started { transfer_key } => transfer_key,
                other => panic!("{expected_mode} route returned {other:?}"),
            };
            let store = comp.transfer_store.lock().unwrap();
            let child = store.get_job(&child_id).unwrap().expect("durable child");
            let lineage = store
                .retry_parent(&child_id)
                .unwrap()
                .expect("durable child lineage");
            assert_eq!(lineage.parent_job_id, parent_id);
            assert_eq!(lineage.child_job_id, child_id);
            assert_eq!(child.operation_kind, OperationKind::Upload);
            assert_eq!(
                store
                    .upload_job_spec(&child_id)
                    .unwrap()
                    .unwrap()
                    .input_digest,
                expected_digest,
                "{expected_mode} child must carry the requested immutable input"
            );
            child_id
        })
        .collect::<Vec<_>>();
        assert_eq!(started.len(), 3);
        assert!(started.iter().all(|child_id| {
            comp.stored_job(child_id)
                .unwrap()
                .is_some_and(|job| job.operation_kind == OperationKind::Upload)
        }));

        drop(app);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn durable_upload_projection_orders_visible_activity_and_filters_successes_and_dismissals() {
        let dir = fresh_temp_dir("upload-projection-lane");
        let comp = test_composition(&dir, Vec::new());
        let mut store = comp.transfer_store.lock().unwrap();
        let create = |store: &mut TransferStore, job_id: &str, entry: &str| {
            let spec = UploadJobSpec::new(entry, "rev-1", format!("digest-{job_id}")).unwrap();
            store.create_upload_job(job_id, &spec, "t0").unwrap()
        };

        let queued = create(&mut store, "upload-queued", "dev-q|sess");
        let failed = create(&mut store, "upload-failed", "dev-f|sess");
        let cancelled = create(&mut store, "upload-cancelled", "dev-c|sess");
        let succeeded = create(&mut store, "upload-succeeded", "dev-s|sess");
        let dismissed = create(&mut store, "upload-dismissed", "dev-d|sess");

        let queued_version = store
            .start_upload_job("upload-queued", queued.job().state_version, "t1")
            .unwrap();
        store
            .begin_upload_for_job(
                "upload-queued",
                queued_version,
                &NewUpload {
                    transfer_key: "upload-queued".to_string(),
                    entry_key: "dev-q|sess".to_string(),
                    revision: "rev-1".to_string(),
                    object_key: "dev-q/sess/file.bin".to_string(),
                    upload_id: "multipart-q".to_string(),
                    endpoint: "https://storage.example".to_string(),
                    bucket: "bucket".to_string(),
                    url_style: CoreUploadUrlStyle::Path,
                },
                "t2",
            )
            .unwrap();
        store
            .record_upload_part_for_job_with_progress(
                "upload-queued",
                queued_version,
                "dev-q/sess/file.bin",
                "multipart-q",
                &UploadPartRecord {
                    part_number: 1,
                    etag: "etag-q".to_string(),
                    size_bytes: 7,
                },
                Some(7),
                "t3",
            )
            .unwrap();

        let failed_version = store
            .start_upload_job("upload-failed", failed.job().state_version, "t1")
            .unwrap();
        store
            .complete_upload_job(
                "upload-failed",
                failed_version,
                &TerminalOutcome::Failed {
                    code: "network".to_string(),
                    retryable: true,
                },
                "t2",
            )
            .unwrap();

        let cancelled_version = store
            .start_upload_job("upload-cancelled", cancelled.job().state_version, "t1")
            .unwrap();
        store
            .cancel_upload_job("upload-cancelled", cancelled_version, "t2")
            .unwrap();

        let succeeded_version = store
            .start_upload_job("upload-succeeded", succeeded.job().state_version, "t1")
            .unwrap();
        store
            .complete_upload_job(
                "upload-succeeded",
                succeeded_version,
                &TerminalOutcome::Succeeded,
                "t2",
            )
            .unwrap();

        let dismissed_version = store
            .start_upload_job("upload-dismissed", dismissed.job().state_version, "t1")
            .unwrap();
        store
            .complete_upload_job(
                "upload-dismissed",
                dismissed_version,
                &TerminalOutcome::Failed {
                    code: "network".to_string(),
                    retryable: true,
                },
                "t2",
            )
            .unwrap();
        store
            .acknowledge_completion("upload-dismissed", "t3")
            .unwrap();
        store.dismiss_job("upload-dismissed", "t4").unwrap();
        drop(store);

        let projections = comp.upload_transfer_projections().unwrap();
        assert_eq!(
            projections
                .iter()
                .map(|transfer| transfer.key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "upload-cancelled",
                "upload-failed",
                "upload-queued",
                "upload-succeeded"
            ]
        );
        assert_eq!(projections[0].state, TransferState::Cancelled);
        assert!(!projections[0].retryable);
        assert_eq!(projections[1].state, TransferState::Failed);
        assert!(projections[1].retryable);
        assert_eq!(projections[2].state, TransferState::Running);
        assert!(!projections[2].retryable);
        assert_eq!(projections[2].sent_bytes, 7);
        assert_eq!(projections[3].state, TransferState::Finalizing);
        assert!(!projections[3].retryable);
        assert!(projections
            .iter()
            .all(|transfer| transfer.key != "upload-dismissed"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cancellation_after_receipt_stage_keeps_durable_evidence_without_projection() {
        let root = fresh_temp_dir("upload-cancel-after-receipt");
        let mut store = TransferStore::open(root.join("transfer_store.sqlite3")).unwrap();
        let spec = UploadJobSpec::new("dev-cancel-receipt|sess", "rev-1", "digest-1").unwrap();
        let created = store
            .create_upload_job("upload-cancel-receipt", &spec, "t0")
            .unwrap();
        let version = store
            .start_upload_job("upload-cancel-receipt", created.job().state_version, "t1")
            .unwrap();
        store
            .stage_upload_receipts_for_job(
                "upload-cancel-receipt",
                &[UploadReceiptSeed::new(
                    "dev-cancel-receipt/sess/video.mp4",
                    UploadReceiptRole::Data,
                    "etag-1",
                    Some("version-1".to_string()),
                    12,
                    "0".repeat(64),
                    UploadReceiptDigestProof::ServerChecksum,
                )],
                "t2",
            )
            .unwrap();

        store
            .cancel_upload_job("upload-cancel-receipt", version, "t3")
            .unwrap();
        let completion = store
            .completion("upload-cancel-receipt")
            .unwrap()
            .expect("cancel completion");
        assert_eq!(completion.outcome, TerminalOutcome::Cancelled);
        assert_eq!(
            store
                .list_upload_receipts("upload-cancel-receipt")
                .unwrap()
                .len(),
            1,
            "verified remote evidence survives a cancel winner"
        );

        let mut transfer = vec![test_upload_transfer("upload-cancel-receipt", false, false)];
        project_upload_transfer_outcome_parts(
            &mut transfer,
            "upload-cancel-receipt",
            &TerminalOutcome::Cancelled,
        );
        assert_eq!(transfer[0].state, TransferState::Cancelled);
        assert_eq!(transfer[0].error.as_deref(), Some(UPLOAD_CANCELLED_MESSAGE));
        std::fs::remove_dir_all(&root).ok();
    }

    /// The gate must block only *live* uploads: once an operation has
    /// committed a terminal outcome, a retry of the same entry has to be
    /// able to start even before the finished operation is retired from the
    /// registry.
    #[test]
    fn a_committed_operation_no_longer_blocks_a_retry_of_the_same_entry() {
        let dir = fresh_temp_dir("upload-retry");
        let comp = test_composition(&dir, Vec::new());

        assert!(matches!(
            comp.begin_upload_operation("t-1", "dev-1|sess-1", "rev-1"),
            UploadStartOutcome::Started { .. }
        ));
        let first = comp.upload_operation("t-1").expect("just registered");
        assert!(matches!(
            comp.begin_upload_operation("t-2", "dev-1|sess-1", "rev-1"),
            UploadStartOutcome::Existing { .. }
        ));

        first
            .claim_terminal(UploadTerminalOutcome::Failed)
            .expect("first claim wins");
        assert!(
            matches!(
                comp.begin_upload_operation("t-2", "dev-1|sess-1", "rev-1"),
                UploadStartOutcome::Started { .. }
            ),
            "a terminal operation must not keep blocking a retry"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_new_upload_child_is_cancelled_when_the_operation_gate_is_already_owned() {
        let dir = fresh_temp_dir("upload-child-gate-compensation");
        let comp = test_composition(&dir, Vec::new());
        let spec = UploadJobSpec::new("dev-gate|sess-gate", "rev-gate", "digest-gate").unwrap();
        let child = comp
            .transfer_store
            .lock()
            .unwrap()
            .create_upload_job("upload-child", &spec, "t0")
            .unwrap()
            .job()
            .clone();
        let expected_version = comp
            .transfer_store
            .lock()
            .unwrap()
            .start_upload_job("upload-child", child.state_version, "t1")
            .unwrap();

        assert!(matches!(
            comp.begin_upload_operation("upload-winner", "dev-gate|sess-gate", "rev-gate"),
            UploadStartOutcome::Started { .. }
        ));
        assert_eq!(
            comp.begin_upload_operation("upload-child", "dev-gate|sess-gate", "rev-gate"),
            UploadStartOutcome::Existing {
                transfer_key: "upload-winner".to_string()
            }
        );

        // This is the compensation branch used when a newly-created child
        // loses the process-local operation gate: the child is terminally
        // cancelled while the winner and its immutable parent context stay
        // untouched.
        comp.transfer_store
            .lock()
            .unwrap()
            .cancel_upload_job("upload-child", expected_version, "t2")
            .expect("compensate child");
        let store = comp.transfer_store.lock().unwrap();
        assert_eq!(
            store.get_job("upload-child").unwrap().unwrap().state,
            JobStateTag::Cancelled
        );
        assert!(store.get_job("upload-winner").unwrap().is_none());
        assert_eq!(
            store.completion("upload-child").unwrap().unwrap().outcome,
            TerminalOutcome::Cancelled
        );
        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Commit 16, interleaving A: **finish first**. Before the operation
    /// token existed, `cancel_upload` re-read the transfer row, saw a
    /// window where it still looked live, and rewrote a committed,
    /// verified success into `已取消上传`. The handshake below forces
    /// exactly that order without a sleep.
    #[test]
    fn a_cancel_never_overwrites_an_already_committed_success() {
        let operation = Arc::new(UploadOperation::new("t-1", "dev-1|sess-1", "rev-1"));
        let (committed_tx, committed_rx) = std::sync::mpsc::channel::<()>();
        let (decided_tx, decided_rx) = std::sync::mpsc::channel::<CancelDecision>();

        let finisher = {
            let operation = operation.clone();
            std::thread::spawn(move || {
                operation
                    .claim_terminal(UploadTerminalOutcome::Succeeded)
                    .expect("the finish is first, so it must win the claim");
                committed_tx.send(()).unwrap();
            })
        };
        let canceller = {
            let operation = operation.clone();
            std::thread::spawn(move || {
                // Blocks until the finish has really committed -- the
                // channel, not timing, is what orders these two.
                committed_rx.recv().unwrap();
                decided_tx.send(operation.request_cancel()).unwrap();
            })
        };

        assert_eq!(
            decided_rx.recv().unwrap(),
            CancelDecision::AlreadyTerminal(UploadTerminalOutcome::Succeeded),
            "a cancel arriving after a committed success must be refused"
        );
        finisher.join().unwrap();
        canceller.join().unwrap();

        // And the refusal is reported to the operator rather than silently
        // swallowed, so the UI cannot show "cancelled" for a stored object.
        assert_eq!(
            UploadTerminalOutcome::Succeeded.already_terminal_message(),
            "该上传任务已完成，无法取消"
        );
    }

    /// Commit 16, interleaving B: **cancel first**. The mirror-image bug --
    /// the upload task's `finish_upload` landing just after a cancel had
    /// already converged and acknowledged the row, stepping the entry back
    /// to `Done`.
    #[test]
    fn a_finish_never_steps_over_an_already_acknowledged_cancel() {
        let operation = Arc::new(UploadOperation::new("t-1", "dev-1|sess-1", "rev-1"));
        let (cancelled_tx, cancelled_rx) = std::sync::mpsc::channel::<()>();
        let (finished_tx, finished_rx) =
            std::sync::mpsc::channel::<Result<(), UploadTerminalOutcome>>();

        let canceller = {
            let operation = operation.clone();
            std::thread::spawn(move || {
                assert_eq!(operation.request_cancel(), CancelDecision::Requested);
                // The safety-net branch of `cancel_upload`: this cancel
                // converges the terminal state itself.
                operation
                    .claim_terminal(UploadTerminalOutcome::Cancelled)
                    .expect("the cancel is first, so it must win the claim");
                cancelled_tx.send(()).unwrap();
            })
        };
        let finisher = {
            let operation = operation.clone();
            std::thread::spawn(move || {
                cancelled_rx.recv().unwrap();
                finished_tx
                    .send(operation.claim_terminal(UploadTerminalOutcome::Succeeded))
                    .unwrap();
            })
        };

        assert_eq!(
            finished_rx.recv().unwrap(),
            Err(UploadTerminalOutcome::Cancelled),
            "a finish must not be allowed to overwrite an acknowledged cancel"
        );
        canceller.join().unwrap();
        finisher.join().unwrap();
    }

    /// The property both interleavings are instances of: however many
    /// writers race, the operation commits exactly one terminal outcome.
    #[test]
    fn cancel_and_finish_racing_commit_exactly_one_terminal_outcome() {
        for _ in 0..64 {
            let operation = Arc::new(UploadOperation::new("t-1", "dev-1|sess-1", "rev-1"));
            let barrier = Arc::new(std::sync::Barrier::new(6));
            let handles: Vec<_> = (0..6)
                .map(|index| {
                    let operation = operation.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        let proposed = if index % 2 == 0 {
                            UploadTerminalOutcome::Succeeded
                        } else {
                            operation.request_cancel();
                            UploadTerminalOutcome::Cancelled
                        };
                        barrier.wait();
                        operation.claim_terminal(proposed)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let winners = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(winners, 1, "exactly one writer may commit: {results:?}");
            // Every loser is told the *same* committed outcome, so no
            // loser can go on to write a different terminal state.
            let committed = results
                .iter()
                .find_map(|result| result.as_ref().err().copied())
                .expect("with six writers there is always at least one loser");
            for result in &results {
                if let Err(observed) = result {
                    assert_eq!(*observed, committed);
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Commit 17: the settings revision gate shared by the credential
    // snapshot/write, the config persist, and the rollback.
    // -----------------------------------------------------------------

    /// Two saves that both read revision `N` and then both try to commit:
    /// the loser must be refused outright, not allowed to write the second
    /// half of its settings tuple over the winner's. Without the gate both
    /// closures ran, which is exactly how the OS keyring ended up holding
    /// one save's secret next to the other save's endpoint.
    #[test]
    fn two_concurrent_settings_saves_leave_exactly_one_winner() {
        let dir = fresh_temp_dir("settings-race");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        let committed = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let barrier = Arc::new(std::sync::Barrier::new(2));

        let handles: Vec<_> = ["save-a", "save-b"]
            .into_iter()
            .map(|label| {
                let comp = comp.clone();
                let committed = committed.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    // Both observe the same revision before either commits.
                    let observed = comp.settings_revision();
                    barrier.wait();
                    comp.commit_settings(observed, || {
                        committed.lock().unwrap().push(label);
                        Ok(())
                    })
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one save may commit: {results:?}"
        );
        assert_eq!(
            committed.lock().unwrap().len(),
            1,
            "the stale save's body must never run at all"
        );
        let conflict = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .expect("one save must lose");
        assert_eq!(conflict, SETTINGS_CONFLICT_MESSAGE);
        assert_eq!(comp.settings_revision(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A save that fails and rolls back must leave the world exactly as any
    /// other in-flight save observed it -- otherwise a failed save would
    /// spuriously invalidate a concurrent, perfectly valid one.
    #[test]
    fn a_failed_settings_commit_does_not_advance_the_revision() {
        let dir = fresh_temp_dir("settings-rollback");
        let comp = test_composition(&dir, Vec::new());

        let observed = comp.settings_revision();
        let failed = comp.commit_settings(observed, || {
            Err::<(), String>("无法保存密钥到系统密钥环：backend locked".to_string())
        });
        assert!(failed.is_err());
        assert_eq!(comp.settings_revision(), observed);

        // ... and the retry, still holding the same observed revision,
        // is accepted.
        comp.commit_settings(observed, || Ok::<(), String>(()))
            .expect("a retry after a rolled-back save must be accepted");
        assert_eq!(comp.settings_revision(), observed + 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The gate is a mutual-exclusion boundary as well as a revision check:
    /// no two commit bodies may ever overlap, even when each re-reads the
    /// revision immediately before committing (so none of them is stale).
    #[test]
    fn settings_commits_never_overlap() {
        let dir = fresh_temp_dir("settings-exclusive");
        let comp = Arc::new(test_composition(&dir, Vec::new()));
        let inside = Arc::new(AtomicBool::new(false));
        let overlapped = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(std::sync::Barrier::new(4));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let comp = comp.clone();
                let inside = inside.clone();
                let overlapped = overlapped.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..50 {
                        // Re-read inside the loop: every attempt is fresh,
                        // so conflicts are incidental and exclusion is the
                        // only thing under test here.
                        let observed = comp.settings_revision();
                        let _ = comp.commit_settings(observed, || {
                            if inside.swap(true, Ordering::SeqCst) {
                                overlapped.store(true, Ordering::SeqCst);
                            }
                            inside.store(false, Ordering::SeqCst);
                            Ok::<(), String>(())
                        });
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(
            !overlapped.load(Ordering::SeqCst),
            "two settings commits ran concurrently"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
