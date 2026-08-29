//! Application boundary for the desktop runtime.
//!
//! `Composition` owns the device and transfer effects, while this module owns
//! the application-facing protocol: lifecycle, snapshots, subscriptions,
//! resource revisions, event delivery, and input/error shapes. Tauri commands
//! should only adapt their wire DTOs to methods on [`TransferApplication`];
//! they must not make persistence or network decisions themselves.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::composition::Composition;
use crate::models::{
    Device, LibraryView, SessionCatalogAuthority, SessionDiscoveryDiagnosticView,
    SessionPageCapabilities, SessionPageView, SessionPaginationUnavailableReason,
    SessionVerificationView, SessionView, StorageConfig, StorageConfigView, Transfer,
};
use crate::state::AppData;

/// Maximum number of values accepted by a batch RPC. Keeping this at the
/// boundary prevents an untrusted WebView from turning one command into an
/// unbounded amount of work or an oversized error response.
pub const MAX_BATCH_ITEMS: usize = 256;

/// Maximum UTF-8 byte length of a scalar RPC string.
pub const MAX_RPC_STRING_BYTES: usize = 4096;

/// Stable machine-readable error returned by command adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl RpcError {
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
        details: Option<Value>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable,
            details,
        }
    }

    #[must_use]
    pub fn invalid_input(field: &str, reason: &str) -> Self {
        Self::new(
            "invalid_input",
            format!("invalid {field}: {reason}"),
            false,
            Some(serde_json::json!({ "field": field, "reason": reason })),
        )
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RpcError {}

/// Validate one scalar command value.
pub fn validate_string(field: &str, value: &str) -> Result<(), RpcError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RpcError::invalid_input(field, "must not be empty"));
    }
    if value.len() > MAX_RPC_STRING_BYTES {
        return Err(RpcError::invalid_input(
            field,
            &format!("must be at most {MAX_RPC_STRING_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Validate a batch before deduplication. The limit applies to caller input,
/// not only to the number of unique values, so repeated entries cannot be
/// used to bypass the work budget.
pub fn validate_batch(field: &str, values: &[String]) -> Result<(), RpcError> {
    if values.is_empty() {
        return Err(RpcError::invalid_input(field, "must not be empty"));
    }
    if values.len() > MAX_BATCH_ITEMS {
        return Err(RpcError::invalid_input(
            field,
            &format!("must contain at most {MAX_BATCH_ITEMS} items"),
        ));
    }
    for value in values {
        validate_string(field, value)?;
    }
    Ok(())
}

/// Payload delivered by every revisioned resource event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Revisioned<T> {
    pub revision: u64,
    pub value: T,
}

impl<T> Revisioned<T> {
    #[must_use]
    pub fn new(revision: u64, value: T) -> Self {
        Self { revision, value }
    }
}

/// Events use the existing names so old clients can still subscribe, while
/// the payload is now a comparable revision envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    Devices,
    Sessions,
    Library,
    Transfers,
    TransferJobs,
    Storage,
    Pairing,
}

impl Resource {
    #[must_use]
    pub fn event_name(self, pairing_resolved: bool) -> &'static str {
        match self {
            Self::Devices => "devices:update",
            Self::Sessions => "sessions:update",
            Self::Library => "library:update",
            Self::Transfers => "transfers:update",
            Self::TransferJobs => "transfer_jobs:update",
            Self::Storage => "storage:update",
            Self::Pairing if pairing_resolved => "pairing:resolved",
            Self::Pairing => "pairing:tick",
        }
    }
}

/// The immutable resource projections captured by one server-side snapshot.
/// The outer [`Revisioned`] envelope is the publication point; each inner
/// envelope retains the exact resource revision used by startup replay.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSnapshot {
    pub devices: Revisioned<Vec<Device>>,
    pub library: Revisioned<Vec<LibraryView>>,
    pub transfers: Revisioned<Vec<Transfer>>,
    pub storage: Revisioned<StorageConfigView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionsUpdatePayload {
    device_id: String,
    sessions: Vec<SessionView>,
    diagnostics: Vec<SessionDiscoveryDiagnosticView>,
    catalog_revision: Option<String>,
    next_cursor: Option<String>,
    has_more: bool,
    catalog_authority: SessionCatalogAuthority,
    pagination_supported: bool,
    pagination_unavailable_reason: Option<SessionPaginationUnavailableReason>,
    capabilities: SessionPageCapabilities,
}

/// The outcome for one item in a non-dispatching batch command. Keeping the
/// item and verdict in one tagged value makes positional association
/// unnecessary on every RPC consumer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum BatchItemResult {
    Success { item: String },
    Failure { item: String, error: RpcError },
}

impl BatchItemResult {
    #[must_use]
    pub fn success(item: impl Into<String>) -> Self {
        Self::Success { item: item.into() }
    }

    #[must_use]
    pub fn failure(item: impl Into<String>, error: RpcError) -> Self {
        Self::Failure {
            item: item.into(),
            error,
        }
    }
}

/// The outcome for one item in a batch command that creates durable jobs.
/// A successful item must carry its own job ID; an incomplete parallel-array
/// response cannot be represented by this type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum BatchJobItemResult {
    Success {
        item: String,
        #[serde(rename = "jobId")]
        job_id: String,
    },
    Failure {
        item: String,
        error: RpcError,
    },
}

impl BatchJobItemResult {
    #[must_use]
    pub fn success(item: impl Into<String>, job_id: impl Into<String>) -> Self {
        Self::Success {
            item: item.into(),
            job_id: job_id.into(),
        }
    }

    #[must_use]
    pub fn failure(item: impl Into<String>, error: RpcError) -> Self {
        Self::Failure {
            item: item.into(),
            error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchJobResult {
    pub results: Vec<BatchJobItemResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMutationResult {
    pub results: Vec<BatchItemResult>,
    pub sessions: Option<Vec<SessionView>>,
    /// A preflight or post-mutation refresh failure that does not belong to
    /// any requested session. It must never be disguised as an item result.
    pub operation_error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedCleanupItem {
    pub session_id: String,
    pub date_label: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedCleanupSkipDetail {
    pub session_id: String,
    pub date_label: String,
    pub bytes: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedCleanupFailure {
    pub session_id: String,
    pub error: RpcError,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedCleanupPreview {
    pub eligible: Vec<DownloadedCleanupItem>,
    pub skipped: Vec<DownloadedCleanupSkipDetail>,
    pub eligible_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedCleanupResult {
    pub eligible: Vec<DownloadedCleanupItem>,
    pub deleted: Vec<DownloadedCleanupItem>,
    pub failed: Vec<DownloadedCleanupFailure>,
    pub skipped: Vec<DownloadedCleanupSkipDetail>,
    pub sessions: Vec<SessionView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryMutationResult {
    pub results: Vec<BatchItemResult>,
    pub library: Vec<LibraryView>,
}

/// Project persisted storage coordinates into the read-only wire view. The
/// internal `StorageConfig` intentionally retains an optional configured path
/// and never stores credentials; neither detail is a frontend contract.
fn storage_view_from(storage: &StorageConfig, composition: &Composition) -> StorageConfigView {
    let active_download_root = composition.library_root().to_string_lossy().into_owned();
    let secret_configured = composition
        .storage_secret_status()
        .map(|status| status.secret_configured)
        .unwrap_or(false);
    StorageConfigView {
        endpoint: storage.endpoint.clone(),
        bucket: storage.bucket.clone(),
        prefix: storage.prefix.clone(),
        url_style: storage.url_style,
        download_root: storage.download_root.clone().unwrap_or_default(),
        active_download_root,
        secret_configured,
    }
}

fn storage_view(data: &AppData) -> StorageConfigView {
    storage_view_from(&data.storage, &data.composition)
}

/// A serializable recording of one event, useful for contract tests and
/// diagnostics without depending on a live Tauri runtime.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedEvent {
    pub name: String,
    pub payload: Value,
}

/// Event delivery boundary. The Tauri implementation is supplied at boot;
/// tests can use [`RecordingEventSink`] or their own deterministic sink.
pub trait EventSink: Send + Sync {
    fn emit(&self, name: &str, payload: Value) -> Result<(), RpcError>;
}

/// A deterministic in-memory sink for application contract tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingEventSink {
    events: Mutex<Vec<RecordedEvent>>,
}

#[cfg(test)]
impl RecordingEventSink {
    #[must_use]
    pub fn events(&self) -> Vec<RecordedEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
impl EventSink for RecordingEventSink {
    fn emit(&self, name: &str, payload: Value) -> Result<(), RpcError> {
        self.events
            .lock()
            .map_err(|_| RpcError::new("sink_poisoned", "event sink is unavailable", true, None))?
            .push(RecordedEvent {
                name: name.to_string(),
                payload,
            });
        Ok(())
    }
}

struct TauriEventSink(AppHandle);

impl EventSink for TauriEventSink {
    fn emit(&self, name: &str, payload: Value) -> Result<(), RpcError> {
        self.0
            .emit(name, payload)
            .map_err(|error| RpcError::new("event_delivery_failed", error.to_string(), true, None))
    }
}

#[derive(Debug)]
struct LocalProjection {
    devices: Vec<Device>,
    library: Vec<LibraryView>,
    transfers: Vec<Transfer>,
    storage: StorageConfigView,
}

#[derive(Debug, Clone)]
struct PublishedSessionCatalog {
    catalog_revision: Option<String>,
    connection_epoch: u64,
    next_cursor: Option<String>,
    diagnostics: Vec<SessionDiscoveryDiagnosticView>,
    seen_cursors: HashSet<String>,
    catalog_authority: SessionCatalogAuthority,
    pagination_supported: bool,
    pagination_unavailable_reason: Option<SessionPaginationUnavailableReason>,
    capabilities: SessionPageCapabilities,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionReadAuthorization {
    pub connection_epoch: u64,
    pub session_revision: String,
    pub verification: Option<SessionVerificationView>,
}

/// The only state exposed by the atomic snapshot and non-session revisioned
/// reads. `list_sessions` is the one scoped refresh exception: it performs its
/// device I/O without this lock, then publishes and returns the exact fetched
/// value through the per-device cache below. Updating each published value and
/// its revision under this one lock makes a mixed pair unrepresentable.
#[derive(Debug)]
struct PublishedResources {
    global_revision: u64,
    devices: Revisioned<Vec<Device>>,
    library: Revisioned<Vec<LibraryView>>,
    transfers: Revisioned<Vec<Transfer>>,
    storage: Revisioned<StorageConfigView>,
    sessions: HashMap<String, Revisioned<Vec<SessionView>>>,
    session_catalogs: HashMap<String, PublishedSessionCatalog>,
    session_revisions: HashMap<String, u64>,
    auxiliary_revisions: HashMap<Resource, u64>,
}

impl PublishedResources {
    fn seeded(projection: LocalProjection) -> Self {
        Self {
            global_revision: 0,
            devices: Revisioned::new(0, projection.devices),
            library: Revisioned::new(0, projection.library),
            transfers: Revisioned::new(0, projection.transfers),
            storage: Revisioned::new(0, projection.storage),
            sessions: HashMap::new(),
            session_catalogs: HashMap::new(),
            session_revisions: HashMap::new(),
            auxiliary_revisions: HashMap::new(),
        }
    }

    fn allocate_resource(&mut self, resource: Resource) -> u64 {
        self.global_revision = self.global_revision.saturating_add(1);
        let revision = self.global_revision;
        self.auxiliary_revisions.insert(resource, revision);
        revision
    }

    fn allocate_session(&mut self, device_id: &str) -> u64 {
        self.global_revision = self.global_revision.saturating_add(1);
        let revision = self.global_revision;
        self.session_revisions
            .insert(device_id.to_string(), revision);
        revision
    }
}

#[derive(Debug, Clone)]
pub struct Publication {
    pub revision: u64,
    pub delivery_error: Option<RpcError>,
}

impl Publication {
    fn into_result(self) -> Result<u64, RpcError> {
        match self.delivery_error {
            Some(error) => Err(error),
            None => Ok(self.revision),
        }
    }
}

pub(crate) struct ApplicationInner {
    pub(crate) state: Arc<Mutex<AppData>>,
    pub(crate) composition: Arc<Composition>,
    pub(crate) app_data_dir: PathBuf,
    publications: Mutex<PublishedResources>,
    session_operation_gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    subscribers: Mutex<HashMap<u64, Arc<dyn EventSink>>>,
    next_subscriber: AtomicU64,
    tauri_subscription: Mutex<Option<Subscription>>,
    started: AtomicBool,
}

/// The sole application boundary used by Tauri composition and commands.
#[derive(Clone)]
pub struct TransferApplication(pub(crate) Arc<ApplicationInner>);

impl TransferApplication {
    pub fn from_app<R: Runtime>(app: &AppHandle<R>) -> Result<Self, RpcError> {
        app.try_state::<Self>()
            .map(|state| state.inner().clone())
            .ok_or_else(|| {
                RpcError::new("application_unavailable", "应用门面尚未初始化", false, None)
            })
    }

    pub fn new_with_app_data_dir(
        state: Arc<Mutex<AppData>>,
        composition: Arc<Composition>,
        app_data_dir: PathBuf,
    ) -> Result<Self, String> {
        // Unexpected process interruption is not a supported recovery path.
        // Close every old non-terminal download before the first immutable
        // publication, so startup can never replay or schedule stale work.
        let interrupted = composition.fail_interrupted_downloads_on_startup()?;
        if interrupted > 0 {
            eprintln!(
                "[application] marked {interrupted} download job(s) interrupted by the previous process as failed"
            );
        }
        // This seed happens before `start()` enables background writers. It
        // is the first immutable publication visible to RPC.
        let projection = Self::project_local_resources(&state, &composition)?;
        Ok(Self(Arc::new(ApplicationInner {
            state,
            composition,
            app_data_dir,
            publications: Mutex::new(PublishedResources::seeded(projection)),
            session_operation_gates: Mutex::new(HashMap::new()),
            subscribers: Mutex::new(HashMap::new()),
            next_subscriber: AtomicU64::new(1),
            tauri_subscription: Mutex::new(None),
            started: AtomicBool::new(false),
        })))
    }

    fn resolve_session_operation_scope(&self, device_id: &str) -> Result<String, String> {
        #[cfg(feature = "demo")]
        {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if data.sessions.contains_key(device_id) {
                return Ok(device_id.to_string());
            }
        }
        self.0.composition.canonical_device_id(device_id)
    }

    /// Serialize catalog reads and mutations for one physical device while
    /// retaining concurrency across devices. Identity resolution and the gate
    /// map lock both finish before the async wait; the returned guard is the
    /// only lock callers may retain across network I/O and publication.
    pub(crate) async fn acquire_session_operation(
        &self,
        device_id: &str,
    ) -> Result<(String, tokio::sync::OwnedMutexGuard<()>), String> {
        let canonical_id = self.resolve_session_operation_scope(device_id)?;
        let gate = {
            let mut gates = self
                .0
                .session_operation_gates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(
                gates
                    .entry(canonical_id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let guard = gate.lock_owned().await;
        Ok((canonical_id, guard))
    }

    fn project_local_resources(
        state: &Arc<Mutex<AppData>>,
        composition: &Arc<Composition>,
    ) -> Result<LocalProjection, String> {
        let (library_entries, storage) = {
            let data = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (data.library.clone(), data.storage.clone())
        };

        let devices = composition.frontend_devices();
        #[cfg(feature = "demo")]
        let devices = {
            let mut devices = devices;
            let data = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            devices.extend(data.devices.clone());
            devices
        };

        let library_root = composition.library_root();
        let library = crate::composition::project_library_entries(&library_root, &library_entries)
            .into_iter()
            .map(|entry| entry.view())
            .collect();

        let transfers = composition
            .transfer_projections()
            .map_err(|error| format!("无法读取持久化传输投影：{error}"))?;
        #[cfg(feature = "demo")]
        let transfers = {
            let mut transfers = transfers;
            let data = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            transfers.extend(data.demo_transfer_state.transfers().iter().cloned());
            transfers
        };

        Ok(LocalProjection {
            devices,
            library,
            transfers,
            storage: storage_view_from(&storage, composition),
        })
    }

    /// One atomic startup view of every resource published by the backend.
    /// No underlying store is consulted here; publication writers update the
    /// exact values and their revisions under the same mutex.
    #[must_use]
    pub fn read_snapshot(&self) -> Revisioned<ApplicationSnapshot> {
        let published = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Revisioned::new(
            published.global_revision,
            ApplicationSnapshot {
                devices: published.devices.clone(),
                library: published.library.clone(),
                transfers: published.transfers.clone(),
                storage: published.storage.clone(),
            },
        )
    }

    #[must_use]
    pub fn read_devices(&self) -> Revisioned<Vec<Device>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .devices
            .clone()
    }

    #[must_use]
    pub fn read_library(&self) -> Revisioned<Vec<LibraryView>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .library
            .clone()
    }

    #[must_use]
    pub fn read_transfers(&self) -> Revisioned<Vec<Transfer>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .transfers
            .clone()
    }

    #[must_use]
    pub fn read_storage(&self) -> Revisioned<StorageConfigView> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .storage
            .clone()
    }

    /// Live device projection used only by resource publishers after an
    /// underlying effect changes the authoritative composition state.
    pub fn try_devices(&self) -> Result<Vec<Device>, String> {
        let composition = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .composition
            .clone();
        #[allow(unused_mut)]
        let mut devices = composition.frontend_devices();
        #[cfg(feature = "demo")]
        {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            devices.extend(data.devices.clone());
        }
        Ok(devices)
    }

    /// Live storage projection used only after a settings mutation commits.
    pub fn try_storage(&self) -> Result<StorageConfigView, String> {
        let data = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(storage_view(&data))
    }

    /// Register a sink and return an idempotent subscription handle. A failed
    /// sink does not poison other subscribers; all subscribers are attempted.
    pub fn subscribe(&self, sink: Arc<dyn EventSink>) -> Subscription {
        let id = self.0.next_subscriber.fetch_add(1, Ordering::Relaxed);
        self.0
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, sink);
        Subscription {
            owner: Arc::downgrade(&self.0),
            id,
            disposed: AtomicBool::new(false),
        }
    }

    /// Bind the process-local Tauri transport once, before background loops
    /// start producing events.
    pub fn bind_tauri(&self, app: &AppHandle) -> Subscription {
        self.subscribe(Arc::new(TauriEventSink(app.clone())))
    }

    /// Start background loops exactly once, after managed state and the event
    /// sink have been registered. Previous-process downloads were already
    /// failed before the initial snapshot; this method never replays them.
    pub fn start(&self, app: AppHandle) {
        if !self.0.started.swap(true, Ordering::SeqCst) {
            let subscription = self.bind_tauri(&app);
            self.0
                .tauri_subscription
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .replace(subscription);
            self.0.composition.start_background_loops(app);
        }
    }

    pub fn stop(&self) {
        if self.0.started.swap(false, Ordering::SeqCst) {
            self.0.composition.shutdown_background_loops();
            self.0
                .tauri_subscription
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        }
    }

    fn deliver<T: Serialize>(&self, name: &str, envelope: &Revisioned<T>) -> Publication {
        let revision = envelope.revision;
        let payload = match serde_json::to_value(envelope) {
            Ok(payload) => payload,
            Err(error) => {
                let error = RpcError::new(
                    "serialization_failed",
                    error.to_string(),
                    false,
                    Some(serde_json::json!({ "event": name, "revision": revision })),
                );
                eprintln!(
                    "[application] published {name} revision {revision}, but serialization failed: {error}"
                );
                return Publication {
                    revision,
                    delivery_error: Some(error),
                };
            }
        };
        let subscribers = self
            .0
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for sink in subscribers {
            if let Err(error) = sink.emit(name, payload.clone()) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = &first_error {
            eprintln!(
                "[application] published {name} revision {revision}, but event delivery failed: {error}"
            );
        }
        Publication {
            revision,
            delivery_error: first_error,
        }
    }

    pub fn publish_devices(&self, value: Vec<Device>) -> Publication {
        let envelope = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let revision = published.allocate_resource(Resource::Devices);
            let envelope = Revisioned::new(revision, value);
            published.devices = envelope.clone();
            envelope
        };
        self.deliver(Resource::Devices.event_name(false), &envelope)
    }

    pub fn publish_library(&self, value: Vec<LibraryView>) -> Publication {
        let envelope = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let revision = published.allocate_resource(Resource::Library);
            let envelope = Revisioned::new(revision, value);
            published.library = envelope.clone();
            envelope
        };
        self.deliver(Resource::Library.event_name(false), &envelope)
    }

    pub fn publish_transfers(&self, value: Vec<Transfer>) -> Publication {
        let envelope = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let revision = published.allocate_resource(Resource::Transfers);
            let envelope = Revisioned::new(revision, value);
            published.transfers = envelope.clone();
            envelope
        };
        self.deliver(Resource::Transfers.event_name(false), &envelope)
    }

    pub fn publish_storage(&self, value: StorageConfigView) -> Publication {
        let envelope = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let revision = published.allocate_resource(Resource::Storage);
            let envelope = Revisioned::new(revision, value);
            published.storage = envelope.clone();
            envelope
        };
        self.deliver(Resource::Storage.event_name(false), &envelope)
    }

    /// Transfer-job events have revisions but are not part of the startup
    /// snapshot. Keeping this entry point resource-specific makes it
    /// impossible for a cached resource to bypass its typed publisher.
    fn emit_transfer_jobs<T: Serialize>(&self, value: T) -> Result<u64, RpcError> {
        let resource = Resource::TransferJobs;
        let revision = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allocate_resource(resource);
        self.deliver(
            resource.event_name(false),
            &Revisioned::new(revision, value),
        )
        .into_result()
    }

    /// Pairing events have two wire names but share one resource revision.
    pub fn emit_pairing<T: Serialize>(&self, resolved: bool, value: T) -> Result<u64, RpcError> {
        let revision = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allocate_resource(Resource::Pairing);
        self.deliver(
            Resource::Pairing.event_name(resolved),
            &Revisioned::new(revision, value),
        )
        .into_result()
    }

    /// Publish one device's complete session projection. Device A and device B
    /// keep independent watermarks even though both draw from the same global
    /// monotonic sequence.
    pub fn publish_sessions(&self, device_id: &str, sessions: Vec<SessionView>) -> Publication {
        let (revision, sessions, capabilities) = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let revision = published.allocate_session(device_id);
            let envelope = Revisioned::new(revision, sessions);
            published
                .sessions
                .insert(device_id.to_string(), envelope.clone());
            let capabilities = published
                .session_catalogs
                .get(device_id)
                .map(|catalog| catalog.capabilities.clone())
                .unwrap_or_default();
            published.session_catalogs.remove(device_id);
            (revision, envelope.value, capabilities)
        };
        let payload = SessionsUpdatePayload {
            device_id: device_id.to_string(),
            sessions,
            diagnostics: Vec::new(),
            catalog_revision: None,
            next_cursor: None,
            has_more: false,
            catalog_authority: SessionCatalogAuthority::Unavailable,
            pagination_supported: false,
            pagination_unavailable_reason: Some(
                SessionPaginationUnavailableReason::CatalogRevisionUnavailable,
            ),
            capabilities,
        };
        self.deliver(
            Resource::Sessions.event_name(false),
            &Revisioned::new(revision, payload),
        )
    }

    pub(crate) fn validate_session_page_request(
        &self,
        device_id: &str,
        cursor: Option<&str>,
        catalog_revision: Option<&str>,
    ) -> Result<Option<u64>, String> {
        match (cursor, catalog_revision) {
            (None, None) => Ok(None),
            (Some(cursor), Some(catalog_revision)) => {
                if cursor.is_empty() || catalog_revision.is_empty() {
                    return Err("会话分页 cursor 和 catalogRevision 不能为空".to_string());
                }
                let published = self
                    .0
                    .publications
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let catalog = published
                    .session_catalogs
                    .get(device_id)
                    .ok_or_else(|| "会话分页快照已失效，请从第一页重新刷新".to_string())?;
                if catalog.catalog_revision.as_deref() != Some(catalog_revision) {
                    return Err("设备会话目录 revision 已变化，请从第一页重新刷新".to_string());
                }
                if !catalog.pagination_supported {
                    return Err("当前设备会话目录没有快照级 revision，无法安全加载更多".to_string());
                }
                if catalog.next_cursor.as_deref() != Some(cursor)
                    || catalog.seen_cursors.contains(cursor)
                {
                    return Err("会话分页 cursor 已失效或已使用，请从第一页重新刷新".to_string());
                }
                Ok(Some(catalog.connection_epoch))
            }
            _ => Err(
                "首次会话刷新不得携带分页状态；加载更多必须同时提供 cursor 和 catalogRevision"
                    .to_string(),
            ),
        }
    }

    pub(crate) fn validate_session_detail_request(
        &self,
        device_id: &str,
        session_id: &str,
        session_revision: &str,
        catalog_revision: Option<&str>,
    ) -> Result<SessionReadAuthorization, String> {
        let published = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let catalog = published
            .session_catalogs
            .get(device_id)
            .ok_or_else(|| "会话目录快照已失效，请先刷新列表".to_string())?;
        if catalog.catalog_revision.as_deref() != catalog_revision {
            return Err("设备会话目录 revision 已变化，请刷新列表后重试".to_string());
        }
        if !catalog.capabilities.session_detail.supported {
            return Err("当前设备协商结果不支持读取会话详情".to_string());
        }
        let summary = published
            .sessions
            .get(device_id)
            .and_then(|sessions| {
                sessions
                    .value
                    .iter()
                    .find(|item| item.session.id == session_id)
            })
            .ok_or_else(|| "会话不在当前已加载目录中，请刷新或加载对应页面".to_string())?;
        if summary.session.revision != session_revision {
            return Err("会话 revision 已变化，请刷新列表后重试".to_string());
        }
        validate_session_verification(catalog, summary)?;
        Ok(SessionReadAuthorization {
            connection_epoch: catalog.connection_epoch,
            session_revision: summary.session.revision.clone(),
            verification: summary.verification.clone(),
        })
    }

    pub(crate) fn authorize_session_artifact_request(
        &self,
        device_id: &str,
        session_id: &str,
    ) -> Result<SessionReadAuthorization, String> {
        let published = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let catalog = published
            .session_catalogs
            .get(device_id)
            .ok_or_else(|| "会话目录快照已失效，请先刷新列表".to_string())?;
        if !catalog.capabilities.artifact_download.supported
            || !catalog.capabilities.session_detail.supported
        {
            return Err("当前设备协商结果不支持读取并下载会话工件".to_string());
        }
        let summary = published
            .sessions
            .get(device_id)
            .and_then(|sessions| {
                sessions
                    .value
                    .iter()
                    .find(|item| item.session.id == session_id)
            })
            .ok_or_else(|| "会话不在当前已加载目录中，请刷新或加载对应页面".to_string())?;
        validate_session_verification(catalog, summary)?;
        Ok(SessionReadAuthorization {
            connection_epoch: catalog.connection_epoch,
            session_revision: summary.session.revision.clone(),
            verification: summary.verification.clone(),
        })
    }

    pub(crate) fn publish_session_page(
        &self,
        device_id: &str,
        request_cursor: Option<&str>,
        expected_catalog_revision: Option<&str>,
        connection_epoch: u64,
        page: SessionPageView,
    ) -> Result<(Publication, SessionPageView), String> {
        let catalog_identity_valid = match page.catalog_authority {
            SessionCatalogAuthority::DeviceSnapshot => {
                page.catalog_revision
                    .as_deref()
                    .is_some_and(|revision| !revision.is_empty())
                    && page.pagination_supported
                    && page.pagination_unavailable_reason.is_none()
            }
            SessionCatalogAuthority::Unavailable => {
                page.catalog_revision.is_none()
                    && !page.pagination_supported
                    && page.pagination_unavailable_reason
                        == Some(SessionPaginationUnavailableReason::CatalogRevisionUnavailable)
            }
        };
        if !catalog_identity_valid
            || page.has_more != page.next_cursor.is_some()
            || page.next_cursor.as_deref().is_some_and(str::is_empty)
            || !page.pagination_supported && (page.has_more || page.next_cursor.is_some())
        {
            return Err("设备返回了无效的会话分页元数据".to_string());
        }

        let response = page.clone();
        let (revision, sessions, catalog) = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (mut sessions, mut seen_cursors, mut diagnostics) = match request_cursor {
                None => (Vec::new(), HashSet::new(), Vec::new()),
                Some(cursor) => {
                    let expected = expected_catalog_revision
                        .ok_or_else(|| "加载更多缺少 catalogRevision，请重新刷新".to_string())?;
                    let current = published
                        .session_catalogs
                        .get(device_id)
                        .ok_or_else(|| "会话分页快照已失效，请重新刷新".to_string())?;
                    if current.catalog_revision.as_deref() != Some(expected)
                        || page.catalog_revision.as_deref() != Some(expected)
                        || current.connection_epoch != connection_epoch
                        || current.catalog_authority != page.catalog_authority
                        || current.pagination_supported != page.pagination_supported
                        || current.pagination_unavailable_reason
                            != page.pagination_unavailable_reason
                        || current.capabilities != page.capabilities
                        || current.next_cursor.as_deref() != Some(cursor)
                        || current.seen_cursors.contains(cursor)
                    {
                        return Err("会话分页快照已变化或 cursor 已失效，请重新刷新".to_string());
                    }
                    let sessions = published
                        .sessions
                        .get(device_id)
                        .map(|value| value.value.clone())
                        .ok_or_else(|| "会话分页缓存已失效，请重新刷新".to_string())?;
                    let mut seen = current.seen_cursors.clone();
                    seen.insert(cursor.to_string());
                    (sessions, seen, current.diagnostics.clone())
                }
            };
            if request_cursor.is_none() && expected_catalog_revision.is_some()
                || request_cursor.is_some()
                    && expected_catalog_revision != page.catalog_revision.as_deref()
            {
                return Err("会话分页请求与目录 revision 不一致".to_string());
            }
            if page
                .next_cursor
                .as_ref()
                .is_some_and(|next| seen_cursors.contains(next))
            {
                return Err("设备返回了重复的会话分页 cursor".to_string());
            }
            if let Err(error) = merge_session_views(&mut sessions, page.items.clone()) {
                if request_cursor.is_some() {
                    published.session_catalogs.remove(device_id);
                }
                return Err(error);
            }
            if let Err(error) =
                merge_session_diagnostics(&mut diagnostics, page.diagnostics.clone())
            {
                if request_cursor.is_some() {
                    published.session_catalogs.remove(device_id);
                }
                return Err(error);
            }
            let catalog = PublishedSessionCatalog {
                catalog_revision: page.catalog_revision.clone(),
                connection_epoch,
                next_cursor: page.next_cursor.clone(),
                diagnostics,
                seen_cursors: std::mem::take(&mut seen_cursors),
                catalog_authority: page.catalog_authority,
                pagination_supported: page.pagination_supported,
                pagination_unavailable_reason: page.pagination_unavailable_reason,
                capabilities: page.capabilities.clone(),
            };
            let revision = published.allocate_session(device_id);
            published.sessions.insert(
                device_id.to_string(),
                Revisioned::new(revision, sessions.clone()),
            );
            published
                .session_catalogs
                .insert(device_id.to_string(), catalog.clone());
            (revision, sessions, catalog)
        };
        let publication = self.deliver(
            Resource::Sessions.event_name(false),
            &Revisioned::new(
                revision,
                SessionsUpdatePayload {
                    device_id: device_id.to_string(),
                    sessions,
                    diagnostics: catalog.diagnostics.clone(),
                    catalog_revision: catalog.catalog_revision.clone(),
                    next_cursor: catalog.next_cursor.clone(),
                    has_more: catalog.next_cursor.is_some(),
                    catalog_authority: catalog.catalog_authority,
                    pagination_supported: catalog.pagination_supported,
                    pagination_unavailable_reason: catalog.pagination_unavailable_reason,
                    capabilities: catalog.capabilities,
                },
            ),
        );
        Ok((publication, response))
    }

    pub(crate) fn publish_session_detail(
        &self,
        device_id: &str,
        catalog_revision: Option<&str>,
        expected_connection_epoch: u64,
        detail: SessionView,
    ) -> Result<Publication, String> {
        let (revision, sessions, catalog) = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let catalog = published
                .session_catalogs
                .get(device_id)
                .filter(|catalog| {
                    catalog.catalog_revision.as_deref() == catalog_revision
                        && catalog.connection_epoch == expected_connection_epoch
                })
                .cloned()
                .ok_or_else(|| "会话目录快照或设备连接已变化，详情结果已丢弃".to_string())?;
            let mut sessions = published
                .sessions
                .get(device_id)
                .map(|value| value.value.clone())
                .ok_or_else(|| "会话目录缓存已失效，详情结果已丢弃".to_string())?;
            let position = sessions
                .iter()
                .position(|item| item.session.id == detail.session.id)
                .ok_or_else(|| "会话不在当前已加载目录中，详情结果已丢弃".to_string())?;
            if sessions[position].session.revision != detail.session.revision {
                return Err("会话 revision 已变化，详情结果已丢弃".to_string());
            }
            if sessions[position].verification != detail.verification {
                return Err("会话 gateway verification 已变化，详情结果已丢弃".to_string());
            }
            sessions[position] = detail;
            let revision = published.allocate_session(device_id);
            published.sessions.insert(
                device_id.to_string(),
                Revisioned::new(revision, sessions.clone()),
            );
            (revision, sessions, catalog)
        };
        Ok(self.deliver(
            Resource::Sessions.event_name(false),
            &Revisioned::new(
                revision,
                SessionsUpdatePayload {
                    device_id: device_id.to_string(),
                    sessions,
                    diagnostics: catalog.diagnostics.clone(),
                    catalog_revision: catalog.catalog_revision.clone(),
                    next_cursor: catalog.next_cursor.clone(),
                    has_more: catalog.next_cursor.is_some(),
                    catalog_authority: catalog.catalog_authority,
                    pagination_supported: catalog.pagination_supported,
                    pagination_unavailable_reason: catalog.pagination_unavailable_reason,
                    capabilities: catalog.capabilities,
                },
            ),
        ))
    }

    /// Reserve a session-scope revision when a mutation committed but its
    /// post-mutation catalog could not be read. There is intentionally no
    /// value/event to cache; the next successful refresh receives a newer
    /// device-scoped revision.
    pub fn advance_session_revision(&self, device_id: &str) -> u64 {
        let mut published = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        published.session_catalogs.remove(device_id);
        published.allocate_session(device_id)
    }

    /// Retires opaque cursors and revision-bound details when a connection
    /// lifecycle transition begins. Rows may remain visible while offline,
    /// but no operation can append to or fetch detail against that cache.
    pub(crate) fn invalidate_session_catalog(&self, device_id: &str) {
        let canonical_id = self
            .resolve_session_operation_scope(device_id)
            .unwrap_or_else(|_| device_id.to_string());
        let mut published = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        published.session_catalogs.remove(&canonical_id);
        published.allocate_session(&canonical_id);
    }
}

fn merge_session_views(
    existing: &mut Vec<SessionView>,
    incoming: Vec<SessionView>,
) -> Result<(), String> {
    let mut seen = existing
        .iter()
        .map(|item| item.session.id.as_str())
        .collect::<HashSet<_>>();
    for candidate in &incoming {
        if !seen.insert(candidate.session.id.as_str()) {
            return Err(format!(
                "设备在同一个会话目录 cursor chain 中重复返回 sessionId {}",
                candidate.session.id
            ));
        }
    }
    drop(seen);
    validate_session_page_order(existing, &incoming)?;
    existing.extend(incoming);
    Ok(())
}

fn validate_session_page_order(
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

fn merge_session_diagnostics(
    existing: &mut Vec<SessionDiscoveryDiagnosticView>,
    incoming: Vec<SessionDiscoveryDiagnosticView>,
) -> Result<(), String> {
    for diagnostic in incoming {
        if existing
            .iter()
            .any(|current| current.quarantine_id == diagnostic.quarantine_id)
        {
            return Err(format!(
                "设备在同一个会话目录 cursor chain 中重复返回 quarantineId {}",
                diagnostic.quarantine_id
            ));
        }
        existing.push(diagnostic);
    }
    Ok(())
}

fn validate_session_verification(
    catalog: &PublishedSessionCatalog,
    summary: &SessionView,
) -> Result<(), String> {
    match catalog.capabilities.profile {
        crate::models::SessionApiProfile::LegacyPinnedTlsV1 => Ok(()),
        crate::models::SessionApiProfile::LabHttpV4 => summary
            .verification
            .as_ref()
            .filter(|verification| verification.permits_detail_for(&summary.session.revision))
            .map(|_| ())
            .ok_or_else(|| {
                "该会话缺少可用且与当前 revision 匹配的 gateway verification".to_string()
            }),
        crate::models::SessionApiProfile::Unknown => {
            Err("设备 API profile 未知，不能读取会话详情或下载工件".to_string())
        }
    }
}

/// Idempotent listener disposer. Dropping it unsubscribes as well, which keeps
/// hot reload and test teardown from leaking a sink.
pub struct Subscription {
    owner: Weak<ApplicationInner>,
    id: u64,
    disposed: AtomicBool,
}

impl Subscription {
    pub fn dispose(&self) {
        if self.disposed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(owner) = self.owner.upgrade() {
            owner
                .subscribers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&self.id);
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
fn emit_unmanaged_for_test<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    name: &str,
    value: T,
) -> Result<u64, RpcError> {
    let revisioned = serde_json::to_value(Revisioned::new(1, value))
        .map_err(|error| RpcError::new("serialization_failed", error.to_string(), false, None))?;
    app.emit(name, revisioned)
        .map(|_| 1)
        .map_err(|error| RpcError::new("event_delivery_failed", error.to_string(), true, None))
}

fn emit_without_managed_application<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    name: &str,
    value: T,
) -> Result<u64, RpcError> {
    #[cfg(test)]
    {
        emit_unmanaged_for_test(app, name, value)
    }
    #[cfg(not(test))]
    {
        let _ = (app, value);
        Err(RpcError::new(
            "application_unavailable",
            "应用门面尚未初始化，无法发布事件",
            false,
            Some(serde_json::json!({ "event": name })),
        ))
    }
}

/// Typed resource bridges keep composition independent from the concrete sink
/// while making cache-bypassing publication impossible in managed production.
pub fn emit_devices_event<R: Runtime>(
    app: &AppHandle<R>,
    value: Vec<Device>,
) -> Result<u64, RpcError> {
    if let Some(application) = app.try_state::<TransferApplication>() {
        return application.publish_devices(value).into_result();
    }
    emit_without_managed_application(app, Resource::Devices.event_name(false), value)
}

pub fn emit_library_event<R: Runtime>(
    app: &AppHandle<R>,
    value: Vec<LibraryView>,
) -> Result<u64, RpcError> {
    if let Some(application) = app.try_state::<TransferApplication>() {
        return application.publish_library(value).into_result();
    }
    emit_without_managed_application(app, Resource::Library.event_name(false), value)
}

pub fn emit_transfers_event<R: Runtime>(
    app: &AppHandle<R>,
    value: Vec<Transfer>,
) -> Result<u64, RpcError> {
    if let Some(application) = app.try_state::<TransferApplication>() {
        return application.publish_transfers(value).into_result();
    }
    emit_without_managed_application(app, Resource::Transfers.event_name(false), value)
}

pub fn emit_transfer_jobs_event<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    value: T,
) -> Result<u64, RpcError> {
    if let Some(application) = app.try_state::<TransferApplication>() {
        return application.emit_transfer_jobs(value);
    }
    emit_without_managed_application(app, Resource::TransferJobs.event_name(false), value)
}

pub fn emit_pairing_event<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    resolved: bool,
    value: T,
) -> Result<u64, RpcError> {
    if let Some(application) = app.try_state::<TransferApplication>() {
        return application.emit_pairing(resolved, value);
    }
    emit_without_managed_application(app, Resource::Pairing.event_name(resolved), value)
}

#[cfg(feature = "demo")]
pub fn emit_sessions_event<R: Runtime>(
    app: &AppHandle<R>,
    device_id: &str,
    sessions: Vec<SessionView>,
) -> Result<u64, RpcError> {
    if let Some(application) = app.try_state::<TransferApplication>() {
        return application
            .publish_sessions(device_id, sessions)
            .into_result();
    }
    emit_without_managed_application(
        app,
        Resource::Sessions.event_name(false),
        SessionsUpdatePayload {
            device_id: device_id.to_string(),
            sessions,
            diagnostics: Vec::new(),
            catalog_revision: None,
            next_cursor: None,
            has_more: false,
            catalog_authority: SessionCatalogAuthority::Unavailable,
            pagination_supported: false,
            pagination_unavailable_reason: Some(
                SessionPaginationUnavailableReason::CatalogRevisionUnavailable,
            ),
            capabilities: SessionPageCapabilities::default(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DeviceState, DownloadStatus, Session, SessionApiProfile, SessionCapability,
        SessionCapabilitySource, SessionFile, SessionVerificationValidatorView,
        SessionVerificationVerdict, StorageUrlStyle, TransferDirection, TransferState,
        UploadStatus,
    };
    use ylx_transfer_core::domain::{
        DeviceId as DomainDeviceId, FileId as DomainFileId, JobFileSpec, JobIdentity, JobSpec,
        PublicationMaterial, SessionId as DomainSessionId,
    };
    use ylx_transfer_core::persistence::{JobStateTag, TerminalOutcome, TransferStore};
    use ylx_transfer_core::transfer::recovery::INTERRUPTED_DOWNLOAD_FAILURE_CODE;

    const RPC_FIXTURE: &str = include_str!("../../fixtures/rpc/application_contract.json");
    const DEVICE_A: &str = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const DEVICE_B: &str = "ylx-abcdef0198765432abcdef0198765432abcdef0198765432abcdef0198765432";
    const DISPLAY: &str = "YLX-ABCDEF01";

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RpcFixtureBundle {
        transfer: Transfer,
        revisioned_event: RecordedEvent,
        snapshot: Revisioned<ApplicationSnapshot>,
        manual_device: Revisioned<Device>,
        batch_jobs: BatchJobResult,
        session_mutation: Revisioned<SessionMutationResult>,
        library_mutation: Revisioned<LibraryMutationResult>,
        downloaded_cleanup_result: Revisioned<DownloadedCleanupResult>,
        rpc_error: RpcError,
    }

    fn fixture_transfer_a() -> Transfer {
        Transfer {
            key: "transfer-fixture-a".to_string(),
            label: "capture-session-a".to_string(),
            total_bytes: 4096,
            sent_bytes: 1024,
            state: TransferState::Running,
            error: None,
            retryable: false,
            direction: TransferDirection::Down,
            target_label: DISPLAY.to_string(),
        }
    }

    fn fixture_transfer_b() -> Transfer {
        Transfer {
            key: "transfer-fixture-b".to_string(),
            label: "capture-session-b".to_string(),
            total_bytes: 2048,
            sent_bytes: 512,
            state: TransferState::Running,
            error: None,
            retryable: false,
            direction: TransferDirection::Down,
            target_label: DISPLAY.to_string(),
        }
    }

    fn fixture_device_a() -> Device {
        Device {
            id: DEVICE_A.to_string(),
            display_id: DISPLAY.to_string(),
            ip: Some("192.0.2.10".to_string()),
            state: DeviceState::Connected,
            last_seen: Some("2026-08-03T10:10:11Z".to_string()),
        }
    }

    fn fixture_device_b() -> Device {
        Device {
            id: DEVICE_B.to_string(),
            display_id: DISPLAY.to_string(),
            ip: Some("192.0.2.11".to_string()),
            state: DeviceState::Idle,
            last_seen: Some("2026-08-03T10:10:12Z".to_string()),
        }
    }

    fn fixture_session(id: &str) -> SessionView {
        let manifest_sha256 = "a".repeat(64);
        SessionView {
            session: Session {
                id: id.to_string(),
                revision: format!("sha256:{manifest_sha256}"),
                date_label: "2026-08-04T00:00:00Z".to_string(),
                duration_seconds: 1.0,
                total_bytes: 1,
                video_bytes: 1,
                imu_samples: None,
                files: Vec::new(),
            },
            download_status: DownloadStatus::None,
            backed_up: false,
            verification: Some(SessionVerificationView {
                verdict: SessionVerificationVerdict::Usable,
                actor: "gateway".to_string(),
                validator: SessionVerificationValidatorView {
                    name: "fixture-validator".to_string(),
                    version: "1".to_string(),
                    build_sha256: "b".repeat(64),
                },
                manifest_sha256,
                verified_at: "2026-08-04T00:00:00Z".to_string(),
                diagnostics: Vec::new(),
                manifest_digest_valid: true,
            }),
        }
    }

    fn fixture_session_at(id: &str, started_at: &str) -> SessionView {
        let mut session = fixture_session(id);
        session.session.date_label = started_at.to_string();
        session
    }

    fn fixture_diagnostic(id: &str, message: &str) -> SessionDiscoveryDiagnosticView {
        SessionDiscoveryDiagnosticView {
            quarantine_id: id.to_string(),
            code: crate::models::SessionDiscoveryDiagnosticCode::ManifestInvalid,
            observed_at: "2026-08-29T12:00:00Z".to_string(),
            message: message.to_string(),
        }
    }

    fn fixture_file_a() -> SessionFile {
        SessionFile::new(
            "file-fixture-a".to_string(),
            "video/left.mp4".to_string(),
            2048,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        )
    }

    fn fixture_file_b() -> SessionFile {
        SessionFile::new(
            "file-fixture-b".to_string(),
            "video/right.mp4".to_string(),
            1024,
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
        )
    }

    fn fixture_library_a() -> LibraryView {
        LibraryView {
            device_id: DEVICE_A.to_string(),
            device_display_id: DISPLAY.to_string(),
            session_id: "session-fixture-a".to_string(),
            date_label: "2026-08-03".to_string(),
            downloaded_at: "2026-08-03T10:11:12Z".to_string(),
            bytes: 2048,
            files: vec![fixture_file_a()],
            complete: true,
            upload_status: UploadStatus::Done,
            upload_retryable: false,
            uploaded_at: Some("2026-08-03T10:12:13Z".to_string()),
            upload_error: None,
        }
    }

    fn fixture_library_b() -> LibraryView {
        LibraryView {
            device_id: DEVICE_B.to_string(),
            device_display_id: DISPLAY.to_string(),
            session_id: "session-fixture-b".to_string(),
            date_label: "2026-08-03".to_string(),
            downloaded_at: "2026-08-03T10:13:12Z".to_string(),
            bytes: 1024,
            files: vec![fixture_file_b()],
            complete: true,
            upload_status: UploadStatus::None,
            upload_retryable: false,
            uploaded_at: None,
            upload_error: None,
        }
    }

    fn fixture_snapshot() -> Revisioned<ApplicationSnapshot> {
        let transfers = vec![fixture_transfer_a(), fixture_transfer_b()];
        Revisioned::new(
            18,
            ApplicationSnapshot {
                devices: Revisioned::new(15, vec![fixture_device_a(), fixture_device_b()]),
                library: Revisioned::new(16, vec![fixture_library_a(), fixture_library_b()]),
                transfers: Revisioned::new(18, transfers),
                storage: Revisioned::new(
                    17,
                    StorageConfigView {
                        endpoint: "https://oss-cn-beijing.aliyuncs.com".to_string(),
                        bucket: "ylx-recordings".to_string(),
                        prefix: "fixture".to_string(),
                        url_style: StorageUrlStyle::VirtualHost,
                        download_root: "/srv/ylx-recordings".to_string(),
                        active_download_root: "/srv/ylx-recordings".to_string(),
                        secret_configured: false,
                    },
                ),
            },
        )
    }

    fn fixture_bundle() -> RpcFixtureBundle {
        let transfer = fixture_transfer_a();
        let event_payload = serde_json::to_value(Revisioned::new(
            18,
            vec![transfer.clone(), fixture_transfer_b()],
        ))
        .expect("transfer event serializes");
        RpcFixtureBundle {
            transfer,
            revisioned_event: RecordedEvent {
                name: Resource::Transfers.event_name(false).to_string(),
                payload: event_payload,
            },
            snapshot: fixture_snapshot(),
            manual_device: Revisioned::new(22, fixture_device_a()),
            batch_jobs: BatchJobResult {
                results: vec![
                    BatchJobItemResult::success("session-fixture-b", "download-job-fixture-b"),
                    BatchJobItemResult::failure(
                        "session-fixture-a",
                        RpcError::new(
                            "download_enqueue_failed",
                            "设备离线",
                            true,
                            Some(serde_json::json!({
                                "deviceId": DEVICE_A,
                                "sessionId": "session-fixture-a",
                            })),
                        ),
                    ),
                ],
            },
            session_mutation: Revisioned::new(
                19,
                SessionMutationResult {
                    results: Vec::new(),
                    sessions: None,
                    operation_error: Some(RpcError::new(
                        "cleanup_catalog_unavailable",
                        "无法读取设备会话清单",
                        true,
                        Some(serde_json::json!({ "deviceId": DEVICE_A })),
                    )),
                },
            ),
            library_mutation: Revisioned::new(
                20,
                LibraryMutationResult {
                    results: vec![
                        BatchItemResult::success(format!("{DEVICE_B}|session-fixture-b")),
                        BatchItemResult::failure(
                            format!("{DEVICE_A}|session-fixture-a"),
                            RpcError::new(
                                "library_delete_busy",
                                "传输进行中，无法删除",
                                true,
                                Some(serde_json::json!({
                                    "deviceId": DEVICE_A,
                                    "sessionId": "session-fixture-a",
                                })),
                            ),
                        ),
                    ],
                    library: vec![fixture_library_a(), fixture_library_b()],
                },
            ),
            downloaded_cleanup_result: Revisioned::new(
                21,
                DownloadedCleanupResult {
                    eligible: vec![DownloadedCleanupItem {
                        session_id: "session-fixture-a".to_string(),
                        date_label: "2026-08-03".to_string(),
                        bytes: 2048,
                    }],
                    deleted: Vec::new(),
                    failed: vec![DownloadedCleanupFailure {
                        session_id: "session-fixture-a".to_string(),
                        error: RpcError::new(
                            "downloaded_cleanup_delete_failed",
                            "设备拒绝删除已下载会话",
                            false,
                            Some(serde_json::json!({
                                "deviceId": DEVICE_A,
                                "sessionId": "session-fixture-a",
                            })),
                        ),
                    }],
                    skipped: vec![DownloadedCleanupSkipDetail {
                        session_id: "session-fixture-b".to_string(),
                        date_label: "2026-08-03".to_string(),
                        bytes: 1024,
                        reason: "尚未完成对象存储备份".to_string(),
                    }],
                    sessions: Vec::new(),
                },
            ),
            rpc_error: RpcError::invalid_input("sessionIds", "must not be empty"),
        }
    }

    #[test]
    fn rpc_fixture_bundle_matches_canonical_bytes() {
        let actual = format!(
            "{}\n",
            serde_json::to_string_pretty(&fixture_bundle()).expect("fixture DTOs serialize")
        );
        assert_eq!(
            actual, RPC_FIXTURE,
            "Rust DTO serialization drifted from shared fixture"
        );
    }

    #[test]
    fn validation_rejects_empty_long_and_oversized_batches() {
        assert!(validate_string("id", " ").is_err());
        assert!(validate_string("id", &"x".repeat(MAX_RPC_STRING_BYTES + 1)).is_err());
        let values = (0..=MAX_BATCH_ITEMS)
            .map(|index| format!("id-{index}"))
            .collect::<Vec<_>>();
        assert!(validate_batch("ids", &values).is_err());
    }

    #[test]
    fn recording_sink_preserves_revisioned_event_payload() {
        let sink = RecordingEventSink::default();
        sink.emit(
            "devices:update",
            serde_json::to_value(Revisioned::new(4, vec!["device"])).unwrap(),
        )
        .unwrap();
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "devices:update");
        assert_eq!(events[0].payload["revision"], 4);
        assert_eq!(events[0].payload["value"][0], "device");
    }

    #[test]
    fn rpc_error_serializes_machine_code_and_details() {
        let error = RpcError::invalid_input("sessionIds", "must not be empty");
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], "invalid_input");
        assert_eq!(value["retryable"], false);
        assert_eq!(value["details"]["field"], "sessionIds");
        assert_eq!(value["details"]["reason"], "must not be empty");
    }

    #[test]
    fn session_revisions_are_independent_per_device() {
        let mut published = PublishedResources::seeded(LocalProjection {
            devices: Vec::new(),
            library: Vec::new(),
            transfers: Vec::new(),
            storage: fixture_snapshot().value.storage.value,
        });
        let first_a = published.allocate_session("device-a");
        let second_a = published.allocate_session("device-a");
        let first_b = published.allocate_session("device-b");
        let third_a = published.allocate_session("device-a");
        assert_eq!((first_a, second_a, first_b, third_a), (1, 2, 3, 4));
        assert_eq!(published.global_revision, 4);
        assert_eq!(published.session_revisions.get("device-a"), Some(&4));
        assert_eq!(published.session_revisions.get("device-b"), Some(&3));
    }

    fn fixture_session_page(
        items: Vec<SessionView>,
        next_cursor: Option<&str>,
        catalog_revision: &str,
    ) -> SessionPageView {
        SessionPageView {
            items,
            diagnostics: Vec::new(),
            next_cursor: next_cursor.map(str::to_string),
            has_more: next_cursor.is_some(),
            catalog_revision: Some(catalog_revision.to_string()),
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
        }
    }

    #[test]
    fn stable_page_merge_reaches_session_boundaries_without_reordering() {
        for total in [1_usize, 50, 51, 200] {
            let source = (0..total)
                .map(|index| {
                    let started_at = chrono::DateTime::parse_from_rfc3339("2026-08-04T12:00:00Z")
                        .unwrap()
                        - chrono::Duration::seconds(index as i64);
                    fixture_session_at(
                        &format!("session-{index:04}"),
                        &started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    )
                })
                .collect::<Vec<_>>();
            let mut merged = Vec::new();
            for page in source.chunks(50) {
                merge_session_views(&mut merged, page.to_vec()).unwrap();
            }
            assert_eq!(merged.len(), total, "all {total} sessions remain reachable");
            assert_eq!(
                merged
                    .iter()
                    .map(|item| item.session.id.as_str())
                    .collect::<Vec<_>>(),
                source
                    .iter()
                    .map(|item| item.session.id.as_str())
                    .collect::<Vec<_>>(),
                "server order remains stable at the {total}-item boundary"
            );
        }
    }

    #[test]
    fn quarantine_diagnostics_reject_same_or_different_payload_for_one_identity() {
        let diagnostic = fixture_diagnostic(
            "550e8400-e29b-41d4-a716-446655440000",
            "manifest failed validation",
        );
        let mut merged = Vec::new();
        merge_session_diagnostics(&mut merged, vec![diagnostic.clone()]).unwrap();
        assert!(merge_session_diagnostics(&mut merged, vec![diagnostic.clone()]).is_err());
        assert_eq!(merged, vec![diagnostic.clone()]);

        let mut conflict = diagnostic;
        conflict.message = "different observation for the same stable id".to_string();
        assert!(merge_session_diagnostics(&mut merged, vec![conflict]).is_err());
    }

    #[test]
    fn one_cursor_chain_rejects_same_or_different_payload_for_one_session_identity() {
        let mut original = fixture_session("session-a");
        original.session.files = vec![fixture_file_a()];
        let mut merged = vec![original.clone()];

        let same = merge_session_views(&mut merged, vec![original.clone()]);
        assert!(same.is_err());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].session.files, vec![fixture_file_a()]);

        let mut changed = fixture_session("session-a");
        changed.session.revision = format!("sha256:{}", "c".repeat(64));
        changed.verification.as_mut().unwrap().manifest_sha256 = "c".repeat(64);
        let different = merge_session_views(&mut merged, vec![changed]);
        assert!(different.is_err());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].session.revision, original.session.revision);
        assert_eq!(merged[0].session.files, vec![fixture_file_a()]);
    }

    #[test]
    fn opaque_cursor_is_exactly_replayed_once_then_invalidated() {
        let (root, application) = test_application("session-page-opaque-cursor");
        let cursor = "opaque:%2Fnot-an-offset?token=a+b==";
        let catalog_revision = format!("sha256:{}", "a".repeat(64));
        let first = fixture_session_page(
            vec![fixture_session_at("session-a", "2026-08-04T00:00:02Z")],
            Some(cursor),
            &catalog_revision,
        );
        application
            .publish_session_page(DEVICE_A, None, None, 7, first)
            .expect("publish first page");
        application
            .validate_session_page_request(DEVICE_A, Some(cursor), Some(&catalog_revision))
            .expect("opaque cursor is accepted without decoding");

        let second = fixture_session_page(
            vec![fixture_session_at("session-b", "2026-08-04T00:00:01Z")],
            None,
            &catalog_revision,
        );
        application
            .publish_session_page(DEVICE_A, Some(cursor), Some(&catalog_revision), 7, second)
            .expect("append second page");

        let published = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            published.sessions[DEVICE_A]
                .value
                .iter()
                .map(|item| item.session.id.as_str())
                .collect::<Vec<_>>(),
            vec!["session-a", "session-b"]
        );
        drop(published);
        assert!(application
            .validate_session_page_request(DEVICE_A, Some(cursor), Some(&catalog_revision),)
            .is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cross_page_duplicate_session_retires_only_the_cursor_chain_before_publication() {
        let (root, application) = test_application("session-page-duplicate-identity");
        let sink = Arc::new(RecordingEventSink::default());
        let _subscription = application.subscribe(sink.clone());
        let cursor = "opaque-next";
        let revision_a = format!("sha256:{}", "a".repeat(64));
        application
            .publish_session_page(
                DEVICE_A,
                None,
                None,
                7,
                fixture_session_page(
                    vec![fixture_session("session-a")],
                    Some(cursor),
                    &revision_a,
                ),
            )
            .expect("publish first page");

        let (before_revision, before_value, before_global_revision) = {
            let published = application
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let sessions = published
                .sessions
                .get(DEVICE_A)
                .expect("published first page");
            (
                sessions.revision,
                serde_json::to_value(&sessions.value).expect("serialize first page"),
                published.global_revision,
            )
        };
        let error = application
            .publish_session_page(
                DEVICE_A,
                Some(cursor),
                Some(&revision_a),
                7,
                fixture_session_page(vec![fixture_session("session-a")], None, &revision_a),
            )
            .expect_err("one cursor chain must reject a repeated session id");
        assert!(error.contains("sessionId"), "unexpected error: {error}");

        let published = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let sessions = published
            .sessions
            .get(DEVICE_A)
            .expect("first page remains visible");
        assert_eq!(sessions.revision, before_revision);
        assert_eq!(
            serde_json::to_value(&sessions.value).expect("serialize rejected state"),
            before_value
        );
        assert_eq!(published.global_revision, before_global_revision);
        assert!(!published.session_catalogs.contains_key(DEVICE_A));
        drop(published);
        assert_eq!(
            sink.events().len(),
            1,
            "the rejected page must not emit an event"
        );
        assert!(application
            .validate_session_page_request(DEVICE_A, Some(cursor), Some(&revision_a))
            .is_err());
        assert!(application
            .validate_session_detail_request(
                DEVICE_A,
                "session-a",
                &format!("sha256:{}", "a".repeat(64)),
                Some(&revision_a),
            )
            .is_err());

        let revision_b = format!("sha256:{}", "b".repeat(64));
        let mut replacement = fixture_session("session-a");
        replacement.session.revision = format!("sha256:{}", "c".repeat(64));
        replacement.session.total_bytes = 2;
        replacement.verification.as_mut().unwrap().manifest_sha256 = "c".repeat(64);
        application
            .publish_session_page(
                DEVICE_A,
                None,
                None,
                8,
                fixture_session_page(vec![replacement], None, &revision_b),
            )
            .expect("a fresh catalog revision may replace the same session id");
        let published = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(published.sessions[DEVICE_A].value[0].session.total_bytes, 2);
        assert_eq!(
            published.session_catalogs[DEVICE_A].catalog_revision,
            Some(revision_b)
        );
        drop(published);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cross_page_duplicate_quarantine_identity_rejects_same_and_different_payloads_atomically() {
        for (case, duplicate_message) in [
            ("same", "manifest failed validation"),
            ("different", "conflicting diagnostic payload"),
        ] {
            let (root, application) = test_application(&format!("diagnostic-duplicate-{case}"));
            let sink = Arc::new(RecordingEventSink::default());
            let _subscription = application.subscribe(sink.clone());
            let cursor = "opaque-next";
            let catalog_revision = format!("sha256:{}", "d".repeat(64));
            let quarantine_id = "550e8400-e29b-41d4-a716-446655440000";
            let mut first = fixture_session_page(
                vec![fixture_session_at("session-a", "2026-08-04T00:00:02Z")],
                Some(cursor),
                &catalog_revision,
            );
            first.diagnostics.push(fixture_diagnostic(
                quarantine_id,
                "manifest failed validation",
            ));
            application
                .publish_session_page(DEVICE_A, None, None, 7, first)
                .expect("publish first page");

            let (before_revision, before_value, before_global_revision) = {
                let published = application
                    .0
                    .publications
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let sessions = published
                    .sessions
                    .get(DEVICE_A)
                    .expect("published first page");
                (
                    sessions.revision,
                    serde_json::to_value(&sessions.value).expect("serialize first page"),
                    published.global_revision,
                )
            };
            let mut duplicate = fixture_session_page(
                vec![fixture_session_at("session-b", "2026-08-04T00:00:01Z")],
                None,
                &catalog_revision,
            );
            duplicate
                .diagnostics
                .push(fixture_diagnostic(quarantine_id, duplicate_message));
            let error = application
                .publish_session_page(
                    DEVICE_A,
                    Some(cursor),
                    Some(&catalog_revision),
                    7,
                    duplicate,
                )
                .expect_err("one cursor chain must reject a repeated quarantine id");
            assert!(
                error.contains("quarantineId"),
                "unexpected {case} error: {error}"
            );

            let published = application
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let sessions = published
                .sessions
                .get(DEVICE_A)
                .expect("first page remains visible");
            assert_eq!(sessions.revision, before_revision, "{case}");
            assert_eq!(
                serde_json::to_value(&sessions.value).expect("serialize rejected state"),
                before_value,
                "{case}"
            );
            assert_eq!(published.global_revision, before_global_revision, "{case}");
            assert!(!published.session_catalogs.contains_key(DEVICE_A), "{case}");
            drop(published);
            assert_eq!(
                sink.events().len(),
                1,
                "{case} rejected page emitted an event"
            );
            assert!(application
                .validate_session_page_request(DEVICE_A, Some(cursor), Some(&catalog_revision),)
                .is_err());
            assert!(application
                .validate_session_detail_request(
                    DEVICE_A,
                    "session-a",
                    &format!("sha256:{}", "a".repeat(64)),
                    Some(&catalog_revision),
                )
                .is_err());
            std::fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn cross_page_newest_first_boundary_is_strict_at_items_50_and_51() {
        let first_fifty = || {
            (0..50)
                .map(|index| {
                    let id = if index == 49 {
                        "session-boundary-b".to_string()
                    } else {
                        format!("session-{index:02}")
                    };
                    fixture_session_at(&id, &format!("2026-08-04T00:00:{:02}Z", 59 - index))
                })
                .collect::<Vec<_>>()
        };

        for (case, invalid) in [
            (
                "newer-timestamp",
                fixture_session_at("session-boundary-a", "2026-08-04T00:00:11Z"),
            ),
            (
                "same-timestamp-higher-id",
                fixture_session_at("session-boundary-c", "2026-08-04T00:00:10Z"),
            ),
        ] {
            let (root, application) = test_application(&format!("newest-first-{case}"));
            let sink = Arc::new(RecordingEventSink::default());
            let _subscription = application.subscribe(sink.clone());
            let cursor = "opaque-item-51";
            let catalog_revision = format!("sha256:{}", "e".repeat(64));
            application
                .publish_session_page(
                    DEVICE_A,
                    None,
                    None,
                    7,
                    fixture_session_page(first_fifty(), Some(cursor), &catalog_revision),
                )
                .expect("publish the first 50 ordered sessions");
            let (before_revision, before_value, before_global_revision) = {
                let published = application
                    .0
                    .publications
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let sessions = published
                    .sessions
                    .get(DEVICE_A)
                    .expect("published first page");
                (
                    sessions.revision,
                    serde_json::to_value(&sessions.value).expect("serialize first page"),
                    published.global_revision,
                )
            };

            let error = application
                .publish_session_page(
                    DEVICE_A,
                    Some(cursor),
                    Some(&catalog_revision),
                    7,
                    fixture_session_page(vec![invalid], None, &catalog_revision),
                )
                .expect_err("item 51 must remain strictly older than item 50");
            assert!(
                error.contains("newest-first"),
                "unexpected {case} error: {error}"
            );
            let published = application
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let sessions = published
                .sessions
                .get(DEVICE_A)
                .expect("first page remains visible");
            assert_eq!(sessions.revision, before_revision, "{case}");
            assert_eq!(
                serde_json::to_value(&sessions.value).expect("serialize rejected state"),
                before_value,
                "{case}"
            );
            assert_eq!(published.global_revision, before_global_revision, "{case}");
            assert!(!published.session_catalogs.contains_key(DEVICE_A), "{case}");
            drop(published);
            assert_eq!(
                sink.events().len(),
                1,
                "{case} rejected page emitted an event"
            );
            assert!(application
                .validate_session_page_request(DEVICE_A, Some(cursor), Some(&catalog_revision),)
                .is_err());
            std::fs::remove_dir_all(root).ok();
        }

        let (root, application) = test_application("newest-first-valid-item-51");
        let catalog_revision = format!("sha256:{}", "f".repeat(64));
        application
            .publish_session_page(
                DEVICE_A,
                None,
                None,
                7,
                fixture_session_page(first_fifty(), Some("opaque-item-51"), &catalog_revision),
            )
            .expect("publish first 50 sessions");
        application
            .publish_session_page(
                DEVICE_A,
                Some("opaque-item-51"),
                Some(&catalog_revision),
                7,
                fixture_session_page(
                    vec![fixture_session_at(
                        "session-boundary-z",
                        "2026-08-04T00:00:09Z",
                    )],
                    None,
                    &catalog_revision,
                ),
            )
            .expect("a strictly older item 51 completes the chain");
        let published = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(published.sessions[DEVICE_A].value.len(), 51);
        drop(published);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pagination_rejects_catalog_drift_and_repeated_next_cursor() {
        let (root, application) = test_application("session-page-revision-drift");
        let cursor = "opaque-next";
        let revision_a = format!("sha256:{}", "a".repeat(64));
        let revision_b = format!("sha256:{}", "b".repeat(64));
        application
            .publish_session_page(
                DEVICE_A,
                None,
                None,
                7,
                fixture_session_page(
                    vec![fixture_session("session-a")],
                    Some(cursor),
                    &revision_a,
                ),
            )
            .expect("publish first page");

        assert!(application
            .validate_session_page_request(DEVICE_A, Some(cursor), Some(&revision_b))
            .is_err());
        assert!(application
            .publish_session_page(
                DEVICE_A,
                Some(cursor),
                Some(&revision_a),
                8,
                fixture_session_page(vec![fixture_session("session-b")], None, &revision_a,),
            )
            .is_err());
        assert!(application
            .publish_session_page(
                DEVICE_A,
                Some(cursor),
                Some(&revision_a),
                7,
                fixture_session_page(
                    vec![fixture_session("session-b")],
                    Some(cursor),
                    &revision_a,
                ),
            )
            .is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn session_detail_is_bound_to_catalog_and_session_revisions() {
        let (root, application) = test_application("session-detail-revision");
        let catalog_revision = format!("sha256:{}", "c".repeat(64));
        application
            .publish_session_page(
                DEVICE_A,
                None,
                None,
                7,
                fixture_session_page(vec![fixture_session("session-a")], None, &catalog_revision),
            )
            .expect("publish current catalog");

        assert!(application
            .validate_session_detail_request(
                DEVICE_A,
                "session-a",
                &format!("sha256:{}", "c".repeat(64)),
                Some(&catalog_revision),
            )
            .is_err());
        let authorization = application
            .validate_session_detail_request(
                DEVICE_A,
                "session-a",
                &format!("sha256:{}", "a".repeat(64)),
                Some(&catalog_revision),
            )
            .expect("usable verification authorizes the exact listed revision");
        assert_eq!(authorization.connection_epoch, 7);
        assert!(authorization.verification.is_some());
        assert!(application
            .validate_session_detail_request(
                DEVICE_A,
                "session-a",
                &format!("sha256:{}", "a".repeat(64)),
                Some(&format!("sha256:{}", "d".repeat(64))),
            )
            .is_err());

        let mut mismatched = fixture_session("session-a");
        mismatched.session.revision = format!("sha256:{}", "c".repeat(64));
        mismatched.verification.as_mut().unwrap().manifest_sha256 = "c".repeat(64);
        assert!(application
            .publish_session_detail(DEVICE_A, Some(&catalog_revision), 7, mismatched)
            .is_err());

        let mut detail = fixture_session("session-a");
        detail.session.files = vec![fixture_file_a()];
        assert!(application
            .publish_session_detail(DEVICE_A, Some(&catalog_revision), 8, detail.clone())
            .is_err());
        application
            .publish_session_detail(DEVICE_A, Some(&catalog_revision), 7, detail)
            .expect("publish matching immutable detail");
        let published = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(published.sessions[DEVICE_A].value[0].session.files.len(), 1);
        drop(published);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn v4_missing_unusable_or_invalid_verification_keeps_rows_but_denies_detail_and_download() {
        let (root, application) = test_application("session-verification-gating");
        let cases = ["missing", "unusable", "invalid-digest"];
        for (index, case) in cases.into_iter().enumerate() {
            let mut row = fixture_session("session-a");
            match case {
                "missing" => {
                    row.session.revision.clear();
                    row.verification = None;
                }
                "unusable" => {
                    row.verification.as_mut().unwrap().verdict =
                        SessionVerificationVerdict::Unusable;
                    row.verification.as_mut().unwrap().diagnostics =
                        vec![crate::models::SessionVerificationDiagnosticView::Structured {
                            code: crate::models::SessionVerificationDiagnosticCode::ManifestInvalid,
                            summary: "manifest failed verification".to_string(),
                        }];
                }
                "invalid-digest" => {
                    row.session.revision.clear();
                    let verification = row.verification.as_mut().unwrap();
                    verification.manifest_sha256 = "invalid".to_string();
                    verification.manifest_digest_valid = false;
                }
                _ => unreachable!(),
            }
            let catalog_revision = format!("sha256:{:064x}", index + 10);
            application
                .publish_session_page(
                    DEVICE_A,
                    None,
                    None,
                    7,
                    fixture_session_page(vec![row.clone()], None, &catalog_revision),
                )
                .expect("unsafe row remains visible in the catalog");
            assert!(
                application
                    .validate_session_detail_request(
                        DEVICE_A,
                        "session-a",
                        &row.session.revision,
                        Some(&catalog_revision),
                    )
                    .is_err(),
                "{case} verification must deny detail"
            );
            assert!(
                application
                    .authorize_session_artifact_request(DEVICE_A, "session-a")
                    .is_err(),
                "{case} verification must deny downloads"
            );
        }
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn connection_transition_invalidates_cursor_and_detail_generation() {
        let (root, application) = test_application("session-connection-generation");
        let catalog_revision = format!("sha256:{}", "e".repeat(64));
        application
            .publish_session_page(
                DEVICE_A,
                None,
                None,
                7,
                fixture_session_page(
                    vec![fixture_session("session-a")],
                    Some("opaque-next"),
                    &catalog_revision,
                ),
            )
            .expect("publish connected catalog");

        application.invalidate_session_catalog(DEVICE_A);

        assert!(application
            .validate_session_page_request(DEVICE_A, Some("opaque-next"), Some(&catalog_revision),)
            .is_err());
        assert!(application
            .validate_session_detail_request(
                DEVICE_A,
                "session-a",
                &format!("sha256:{}", "a".repeat(64)),
                Some(&catalog_revision),
            )
            .is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn revisionless_catalog_allows_first_page_detail_but_never_load_more() {
        let (root, application) = test_application("session-revisionless-catalog");
        let sink = Arc::new(RecordingEventSink::default());
        let _subscription = application.subscribe(sink.clone());
        let mut page = fixture_session_page(
            vec![fixture_session("session-a")],
            None,
            &format!("sha256:{}", "a".repeat(64)),
        );
        page.catalog_revision = None;
        page.catalog_authority = SessionCatalogAuthority::Unavailable;
        page.pagination_supported = false;
        page.pagination_unavailable_reason =
            Some(SessionPaginationUnavailableReason::CatalogRevisionUnavailable);

        let mut unavailable_with_fabricated_revision = page.clone();
        unavailable_with_fabricated_revision.catalog_revision =
            Some("fabricated-revision".to_string());
        assert!(application
            .publish_session_page(
                DEVICE_B,
                None,
                None,
                4,
                unavailable_with_fabricated_revision,
            )
            .is_err());

        let mut snapshot_without_revision = fixture_session_page(
            vec![fixture_session("session-a")],
            None,
            &format!("sha256:{}", "b".repeat(64)),
        );
        snapshot_without_revision.catalog_revision = None;
        assert!(application
            .publish_session_page(DEVICE_B, None, None, 4, snapshot_without_revision)
            .is_err());

        let (_publication, response) = application
            .publish_session_page(DEVICE_A, None, None, 7, page)
            .expect("publish safe first-page compatibility projection");
        assert_eq!(response.catalog_revision, None);
        let list_event = sink.events().pop().expect("revisionless sessions update");
        assert_eq!(
            list_event.payload["value"]["catalogRevision"],
            serde_json::Value::Null
        );
        application
            .validate_session_detail_request(
                DEVICE_A,
                "session-a",
                &format!("sha256:{}", "a".repeat(64)),
                None,
            )
            .expect("detail remains bound to the visible first-page row");
        assert!(application
            .validate_session_page_request(DEVICE_A, Some("unsafe-next"), Some("forged-revision"))
            .is_err());

        let mut detail = fixture_session("session-a");
        detail.session.files = vec![fixture_file_a()];
        application
            .publish_session_detail(DEVICE_A, None, 7, detail)
            .expect("revisionless detail remains bound by row identity and connection epoch");
        let detail_event = sink.events().pop().expect("revisionless detail update");
        assert_eq!(
            detail_event.payload["value"]["catalogRevision"],
            serde_json::Value::Null
        );

        let mut unsafe_page = fixture_session_page(
            vec![fixture_session("session-a")],
            Some("unsafe-next"),
            &format!("sha256:{}", "b".repeat(64)),
        );
        unsafe_page.catalog_revision = None;
        unsafe_page.catalog_authority = SessionCatalogAuthority::Unavailable;
        unsafe_page.pagination_supported = false;
        unsafe_page.pagination_unavailable_reason =
            Some(SessionPaginationUnavailableReason::CatalogRevisionUnavailable);
        assert!(application
            .publish_session_page(DEVICE_B, None, None, 4, unsafe_page)
            .is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn canonical_and_unique_legacy_session_operations_publish_in_gate_order() {
        let (root, application) = test_application("session-operation-alias");
        let fingerprint = format!("sha256:abcdef01{}", "1".repeat(56));
        let (canonical_id, legacy_id) = application
            .0
            .composition
            .register_session_gate_device_for_test(fingerprint, "192.0.2.10".to_string())
            .expect("register one resolvable device");

        let (old_revision, mutation_revision) = tauri::async_runtime::block_on(async {
            let (old_ready_send, old_ready_receive) = tokio::sync::oneshot::channel();
            let (release_old_send, release_old_receive) = tokio::sync::oneshot::channel();
            let old_application = application.clone();
            let old_id = canonical_id.clone();
            let old_task = tauri::async_runtime::spawn(async move {
                let (scope, _operation) = old_application
                    .acquire_session_operation(&old_id)
                    .await
                    .expect("canonical id acquires its gate");
                old_ready_send.send(()).expect("announce old catalog read");
                release_old_receive.await.expect("release old catalog read");
                old_application
                    .publish_sessions(&scope, vec![fixture_session("old-catalog")])
                    .revision
            });
            old_ready_receive
                .await
                .expect("old catalog read holds gate");

            let (attempt_send, attempt_receive) = tokio::sync::oneshot::channel();
            let (acquired_send, mut acquired_receive) = tokio::sync::oneshot::channel();
            let mutation_application = application.clone();
            let mutation_alias = legacy_id.clone();
            let mutation_task = tauri::async_runtime::spawn(async move {
                attempt_send
                    .send(())
                    .expect("announce mutation gate attempt");
                let (scope, _operation) = mutation_application
                    .acquire_session_operation(&mutation_alias)
                    .await
                    .expect("unique legacy alias resolves to the canonical gate");
                acquired_send
                    .send(scope.clone())
                    .expect("announce mutation gate acquisition");
                mutation_application
                    .publish_sessions(&scope, vec![fixture_session("after-delete")])
                    .revision
            });
            attempt_receive.await.expect("mutation attempted the gate");
            assert!(matches!(
                acquired_receive.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));

            release_old_send.send(()).expect("finish old catalog read");
            let old_revision = old_task.await.expect("old catalog task exits");
            assert_eq!(
                acquired_receive
                    .await
                    .expect("mutation acquires after old read"),
                canonical_id
            );
            let mutation_revision = mutation_task.await.expect("mutation task exits");
            (old_revision, mutation_revision)
        });

        assert!(old_revision < mutation_revision);
        let published = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let sessions = published
            .sessions
            .get(&canonical_id)
            .expect("mutation publication remains cached");
        assert_eq!(sessions.revision, mutation_revision);
        assert_eq!(sessions.value[0].session.id, "after-delete");
        drop(published);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn different_device_session_operations_remain_parallel() {
        let (root, application) = test_application("session-operation-parallel");
        let (device_a, _) = application
            .0
            .composition
            .register_session_gate_device_for_test(
                format!("sha256:a1b2c3d4{}", "1".repeat(56)),
                "192.0.2.11".to_string(),
            )
            .expect("register device A");
        let (device_b, _) = application
            .0
            .composition
            .register_session_gate_device_for_test(
                format!("sha256:b1c2d3e4{}", "2".repeat(56)),
                "192.0.2.12".to_string(),
            )
            .expect("register device B");

        tauri::async_runtime::block_on(async {
            let (_, _device_a_operation) = application
                .acquire_session_operation(&device_a)
                .await
                .expect("device A acquires its gate");
            let (scope, _device_b_operation) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                application.acquire_session_operation(&device_b),
            )
            .await
            .expect("device B must not wait for device A")
            .expect("device B resolves");
            assert_eq!(scope, device_b);
        });

        assert_eq!(
            application
                .0
                .session_operation_gates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            2
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn unknown_and_ambiguous_session_identities_create_no_gate() {
        let (root, application) = test_application("session-operation-fail-closed");
        for (suffix, host) in [('1', "192.0.2.21"), ('2', "192.0.2.22")] {
            application
                .0
                .composition
                .register_session_gate_device_for_test(
                    format!("sha256:abcdef01{}", suffix.to_string().repeat(56)),
                    host.to_string(),
                )
                .expect("register colliding display identity");
        }

        tauri::async_runtime::block_on(async {
            assert!(application
                .acquire_session_operation("YLX-ABCDEF01")
                .await
                .is_err());
            assert!(application
                .acquire_session_operation(&format!("ylx-{}", "f".repeat(64)))
                .await
                .is_err());
        });
        assert!(
            application
                .0
                .session_operation_gates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty(),
            "identity resolution must fail before allocating a gate"
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn startup_seed_propagates_transfer_projection_failure() {
        let root = std::env::temp_dir().join(format!(
            "ylx-application-snapshot-failure-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).expect("create test app-data directory");
        let app_data_dir = root.join("app-data");
        std::fs::create_dir_all(&app_data_dir).expect("create app-data directory");

        let boot = crate::state::BootConfig::load(app_data_dir.join("app-state.sqlite3"))
            .expect("load empty boot config");
        let composition = Composition::new(app_data_dir.clone(), app_data_dir.join("library"))
            .expect("create composition");
        let state = crate::state::AppState::from_boot_config(boot, composition.clone())
            .expect("build app state");
        composition.fail_transfer_projections_for_test();

        let error = match TransferApplication::new_with_app_data_dir(
            state.0.clone(),
            composition,
            app_data_dir,
        ) {
            Ok(_) => panic!("transfer projection failure must abort the initial publication"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            "无法读取持久化传输投影：injected transfer projection read failure"
        );

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn production_startup_fails_previous_process_download_without_replaying_it() {
        let root = std::env::temp_dir().join(format!(
            "ylx-application-interrupted-download-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let app_data_dir = root.join("app-data");
        std::fs::create_dir_all(&app_data_dir).expect("create app-data directory");
        let transfer_store_path = app_data_dir.join("transfer_store.sqlite3");
        let file_id = DomainFileId("left-00000".to_string());
        let identity = JobIdentity::new(
            DomainDeviceId("device-startup".to_string()),
            DomainSessionId("session-startup".to_string()),
            "revision-startup",
        )
        .expect("valid startup fixture identity");
        let publication = PublicationMaterial::new(
            "revision-startup",
            vec![1, 2, 3, 4],
            vec![7; 64],
            vec![9; 32],
        )
        .expect("valid startup fixture publication");
        let file = JobFileSpec::new(file_id.clone(), "video/left_00000.mp4", 4, "ab".repeat(32))
            .expect("valid startup fixture file");
        let spec = JobSpec::new(
            identity,
            publication,
            vec![file],
            &[file_id],
            true,
            "2026-08-29",
        )
        .expect("valid startup fixture spec");
        {
            let mut store = TransferStore::open(&transfer_store_path).expect("open transfer store");
            store
                .create_job("job-interrupted", &spec, "t0")
                .expect("seed previous-process non-terminal job");
        }

        let composition = Composition::new(app_data_dir.clone(), app_data_dir.join("library"))
            .expect("create inert composition");
        let app_store =
            ylx_transfer_core::persistence::AppStore::open(app_data_dir.join("app-state.sqlite3"))
                .expect("open application store");
        let state = crate::state::AppState::for_test(
            composition.clone(),
            std::sync::Arc::new(app_store),
            Vec::new(),
            0,
        );
        let application =
            TransferApplication::new_with_app_data_dir(state.0.clone(), composition, app_data_dir)
                .expect("startup settles interrupted downloads");

        let job = application
            .0
            .composition
            .stored_job("job-interrupted")
            .expect("read settled job")
            .expect("settled job remains durable");
        assert_eq!(job.state, JobStateTag::Failed);
        assert_eq!(
            job.error,
            Some((INTERRUPTED_DOWNLOAD_FAILURE_CODE.to_string(), true))
        );
        let store = TransferStore::open(&transfer_store_path).expect("reopen transfer store");
        assert!(
            store
                .list_recoverable_jobs()
                .expect("list non-terminal jobs")
                .is_empty(),
            "production startup must leave no previous-process download eligible for scheduling"
        );
        assert_eq!(
            store
                .completion("job-interrupted")
                .expect("read terminal completion")
                .expect("interruption is an observable terminal outcome")
                .outcome,
            TerminalOutcome::Failed {
                code: INTERRUPTED_DOWNLOAD_FAILURE_CODE.to_string(),
                retryable: true,
            }
        );

        let source = include_str!("application.rs");
        let start = source
            .split("pub fn start(&self, app: AppHandle)")
            .nth(1)
            .and_then(|body| body.split("pub fn stop(&self)").next())
            .expect("locate production start method");
        assert!(
            !start.contains("recover_on_startup"),
            "production start must never call the compatibility recovery dispatcher"
        );

        drop(store);
        drop(application);
        std::fs::remove_dir_all(root).ok();
    }

    fn test_application(label: &str) -> (PathBuf, TransferApplication) {
        let root = std::env::temp_dir().join(format!(
            "ylx-application-publication-{label}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let app_data_dir = root.join("app-data");
        std::fs::create_dir_all(&app_data_dir).expect("create app-data directory");
        let composition = Composition::new(app_data_dir.clone(), app_data_dir.join("library"))
            .expect("create composition");
        let app_store =
            ylx_transfer_core::persistence::AppStore::open(app_data_dir.join("app-state.sqlite3"))
                .expect("open application store");
        let state = crate::state::AppState::for_test(
            composition.clone(),
            std::sync::Arc::new(app_store),
            Vec::new(),
            0,
        );
        let application =
            TransferApplication::new_with_app_data_dir(state.0.clone(), composition, app_data_dir)
                .expect("seed published resources");
        (root, application)
    }

    #[derive(Default)]
    struct FailingEventSink {
        attempts: AtomicU64,
    }

    impl EventSink for FailingEventSink {
        fn emit(&self, name: &str, _payload: Value) -> Result<(), RpcError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(RpcError::new(
                "event_delivery_failed",
                format!("injected failure for {name}"),
                true,
                None,
            ))
        }
    }

    #[test]
    fn durable_storage_save_keeps_response_and_cache_when_event_delivery_fails() {
        let (root, application) = test_application("delivery-failure");
        let sink = Arc::new(FailingEventSink::default());
        let _subscription = application.subscribe(sink.clone());

        let response =
            tauri::async_runtime::block_on(application.save_download_root(String::new()))
                .expect("durable save must not be rolled back by event delivery");

        assert_eq!(sink.attempts.load(Ordering::SeqCst), 1);
        let cached = application.read_storage();
        assert_eq!(cached.revision, response.revision);
        assert_eq!(
            serde_json::to_value(cached.value).unwrap(),
            serde_json::to_value(&response.value).unwrap()
        );
        let snapshot_storage = application.read_snapshot().value.storage;
        assert_eq!(snapshot_storage.revision, response.revision);
        assert_eq!(
            serde_json::to_value(snapshot_storage.value).unwrap(),
            serde_json::to_value(&response.value).unwrap()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn mutation_response_and_storage_event_share_one_revision() {
        let (root, application) = test_application("response-event-revision");
        let sink = Arc::new(RecordingEventSink::default());
        let _subscription = application.subscribe(sink.clone());

        let response =
            tauri::async_runtime::block_on(application.save_download_root(String::new()))
                .expect("save storage config");
        let event = sink.events().pop().expect("storage event");

        assert_eq!(event.name, "storage:update");
        assert_eq!(event.payload["revision"], response.revision);
        assert_eq!(
            event.payload["value"],
            serde_json::to_value(&response.value).unwrap()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn snapshot_reader_cannot_observe_a_partial_publication() {
        let (root, application) = test_application("atomic-snapshot");
        let mut publication = application
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let reader = application.clone();
        let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(0);
        let (snapshot_send, snapshot_receive) = std::sync::mpsc::sync_channel(0);
        let task = std::thread::spawn(move || {
            ready_send.send(()).expect("announce snapshot read");
            snapshot_send
                .send(reader.read_snapshot())
                .expect("return snapshot");
        });
        ready_receive.recv().expect("reader started");
        assert!(
            snapshot_receive.try_recv().is_err(),
            "the snapshot read must wait for the publication mutex"
        );

        let devices = vec![Device {
            id: DEVICE_A.to_string(),
            display_id: DISPLAY.to_string(),
            ip: None,
            state: DeviceState::Connected,
            last_seen: None,
        }];
        let revision = publication.allocate_resource(Resource::Devices);
        publication.devices = Revisioned::new(revision, devices.clone());
        let library_revision = publication.allocate_resource(Resource::Library);
        let library = vec![fixture_library_a()];
        publication.library = Revisioned::new(library_revision, library.clone());
        drop(publication);

        let snapshot = snapshot_receive.recv().expect("atomic snapshot");
        task.join().expect("snapshot reader exits");
        assert_eq!(snapshot.revision, library_revision);
        assert_eq!(snapshot.value.devices.revision, revision);
        assert_eq!(
            serde_json::to_value(snapshot.value.devices.value).unwrap(),
            serde_json::to_value(devices).unwrap()
        );
        assert_eq!(snapshot.value.library.revision, library_revision);
        assert_eq!(
            serde_json::to_value(snapshot.value.library.value).unwrap(),
            serde_json::to_value(library).unwrap()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn shared_fixture_deserializes_the_outer_atomic_snapshot_envelope() {
        let bundle: Value = serde_json::from_str(RPC_FIXTURE).expect("parse shared fixture");
        let snapshot: Revisioned<Value> =
            serde_json::from_value(bundle["snapshot"].clone()).expect("decode atomic snapshot");
        assert_eq!(snapshot.revision, 18);
        assert_eq!(snapshot.value["devices"]["revision"], 15);
        assert_eq!(snapshot.value["library"]["revision"], 16);
        assert_eq!(snapshot.value["storage"]["revision"], 17);
        assert_eq!(snapshot.value["transfers"]["revision"], 18);
        let manual_device: Revisioned<Device> =
            serde_json::from_value(bundle["manualDevice"].clone())
                .expect("decode revisioned manual device response");
        assert_eq!(manual_device.revision, 22);
        assert_eq!(manual_device.value.id, DEVICE_A);
    }

    fn contains_rust_identifier(source: &str, identifier: &str) -> bool {
        source.match_indices(identifier).any(|(start, _)| {
            let is_identifier_character =
                |character: char| character == '_' || character.is_ascii_alphanumeric();
            let before = source[..start].chars().next_back();
            let end = start + identifier.len();
            let after = source[end..].chars().next();
            !before.is_some_and(is_identifier_character)
                && !after.is_some_and(is_identifier_character)
        })
    }

    #[test]
    fn command_and_production_source_architecture_is_enforced() {
        let command_source = include_str!("commands.rs");
        let forbidden_command_tokens = [
            [".", "lock", "("].concat(),
            ["App", "State"].concat(),
            ["App", "Store"].concat(),
            ["Transfer", "Store"].concat(),
            ["Stored", "Job"].concat(),
            ["File", "Ledger", "Entry"].concat(),
            ["Completion", "Record"].concat(),
            ["Upload", "Job", "Spec"].concat(),
            ["Stored", "Upload"].concat(),
            ["Upload", "Part", "Record"].concat(),
            ["App", "Library", "Payload"].concat(),
            ["App", "Store", "Snapshot"].concat(),
            ["Library", "Entry"].concat(),
            ["Job", "State", "Tag"].concat(),
            ["Terminal", "Outcome"].concat(),
            ["Operation", "Lease"].concat(),
            ["Library", "Delete", "Intent"].concat(),
            ["ylx_transfer_core", ":", ":", "persistence"].concat(),
            ["persistence", ":", ":"].concat(),
            ["std", ":", ":", "fs"].concat(),
            ["std", ":", ":", "process"].concat(),
            ["spawn", "_blocking"].concat(),
            ["async_runtime", ":", ":", "spawn"].concat(),
            ["std", ":", ":", "thread"].concat(),
            ["composition", ":", ":"].concat(),
            ["sim", ":", ":"].concat(),
            ["Transfer", "Coordinator"].concat(),
            ["Device", "Fleet"].concat(),
            ["Pi", "Http", "Client"].concat(),
            ["persist", "_result"].concat(),
            ["persist", "("].concat(),
        ];
        for token in forbidden_command_tokens {
            assert!(
                !command_source.contains(&token),
                "commands.rs contains forbidden orchestration or persistence token {token}"
            );
        }

        for forbidden_read in [
            ".try_devices(",
            ".try_transfers(",
            ".try_storage(",
            ".devices()",
            ".transfers()",
            ".storage()",
            ".list_library()",
            ".storage_config()",
        ] {
            assert!(
                !command_source.contains(forbidden_read),
                "commands.rs bypasses the immutable publication cache through {forbidden_read}"
            );
        }
        for required_cached_read in [
            ".read_snapshot()",
            ".read_devices()",
            ".read_library()",
            ".read_transfers()",
            ".read_storage()",
        ] {
            assert!(
                command_source.contains(required_cached_read),
                "commands.rs no longer uses required cached read {required_cached_read}"
            );
        }
        assert!(
            command_source.contains(".list_sessions(device_id, cursor, catalog_revision)"),
            "list_sessions must remain the sole device-scoped refresh-and-publish read"
        );
        let lib_source = include_str!("lib.rs");
        assert!(
            lib_source.contains("commands::list_sessions,\n            commands::get_session_detail,"),
            "the lazy session-detail command must remain registered immediately after list_sessions"
        );
        for (name, source) in [
            ("commands", command_source),
            ("workflows", include_str!("application/workflows.rs")),
            ("composition", include_str!("composition.rs")),
            ("registration", lib_source),
        ] {
            assert!(
                !source.contains("download_file"),
                "the retired selected-file product lane remains in {name}"
            );
        }
        for bare_return in [
            "Result<Device, RpcError>",
            "Result<Vec<Device>, RpcError>",
            "Result<Vec<SessionView>, RpcError>",
            "Result<Vec<LibraryView>, RpcError>",
            "Result<Vec<Transfer>, RpcError>",
            "Result<StorageConfigView, RpcError>",
            "Result<SessionMutationResult, RpcError>",
            "Result<LibraryMutationResult, RpcError>",
            "Result<DownloadedCleanupResult, RpcError>",
        ] {
            assert!(
                !command_source.contains(bare_return),
                "commands.rs exposes unrevisioned production response {bare_return}"
            );
        }

        let application_source = include_str!("application.rs").replace("\r\n", "\n");
        let workflow_source = include_str!("application/workflows.rs");
        let composition_source = include_str!("composition.rs");
        let generic_event_bridge = ["pub fn ", "emit_event"].concat();
        assert!(
            !application_source.contains(&generic_event_bridge),
            "application.rs reintroduced a generic cache-bypassing resource bridge"
        );
        assert!(
            application_source.contains("#[cfg(test)]\nfn emit_unmanaged_for_test"),
            "the unmanaged fixed-revision bridge must remain test-only"
        );
        assert!(
            application_source.contains("#[cfg(not(test))]")
                && application_source.contains("\"application_unavailable\""),
            "production must reject publication without the managed application facade"
        );
        assert!(
            !workflow_source.contains(".emit("),
            "application workflows must publish cached resources through typed publishers"
        );
        assert!(
            !workflow_source.contains("emit_transfer_jobs("),
            "cached-resource workflows must never publish transfer-job events"
        );
        assert_eq!(
            workflow_source
                .matches("acquire_session_operation(&device_id)")
                .count(),
            8,
            "every session catalog read/mutation/complete-session download must enter the per-device operation gate once"
        );
        let refresh_source = composition_source
            .split("fn spawn_sessions_refresh")
            .nth(1)
            .and_then(|source| source.split("#[derive(Deserialize)]").next())
            .expect("locate the background session refresh helper");
        assert!(
            refresh_source.contains(".list_sessions(device_id.clone(), None, None)"),
            "background session refresh must use the gated application path"
        );
        assert!(
            !refresh_source.contains("list_sessions_with_local_state"),
            "background session refresh bypasses the per-device operation gate"
        );

        let production_sources = [
            ("desktop/application.rs", include_str!("application.rs")),
            (
                "desktop/application/workflows.rs",
                include_str!("application/workflows.rs"),
            ),
            ("desktop/commands.rs", command_source),
            ("desktop/composition.rs", composition_source),
            ("desktop/lib.rs", include_str!("lib.rs")),
            (
                "desktop/library_delete.rs",
                include_str!("library_delete.rs"),
            ),
            ("desktop/main.rs", include_str!("main.rs")),
            ("desktop/models.rs", include_str!("models.rs")),
            ("desktop/state.rs", include_str!("state.rs")),
            (
                "core/credential_vault.rs",
                include_str!("../crates/ylx-transfer-core/src/credential_vault.rs"),
            ),
            (
                "core/device/actor.rs",
                include_str!("../crates/ylx-transfer-core/src/device/actor.rs"),
            ),
            (
                "core/device/fleet.rs",
                include_str!("../crates/ylx-transfer-core/src/device/fleet.rs"),
            ),
            (
                "core/device/identity.rs",
                include_str!("../crates/ylx-transfer-core/src/device/identity.rs"),
            ),
            (
                "core/device/mod.rs",
                include_str!("../crates/ylx-transfer-core/src/device/mod.rs"),
            ),
            (
                "core/domain/mod.rs",
                include_str!("../crates/ylx-transfer-core/src/domain/mod.rs"),
            ),
            (
                "core/library/artifact.rs",
                include_str!("../crates/ylx-transfer-core/src/library/artifact.rs"),
            ),
            (
                "core/library/download.rs",
                include_str!("../crates/ylx-transfer-core/src/library/download.rs"),
            ),
            (
                "core/library/download_contract.rs",
                include_str!("../crates/ylx-transfer-core/src/library/download_contract.rs"),
            ),
            (
                "core/library/mod.rs",
                include_str!("../crates/ylx-transfer-core/src/library/mod.rs"),
            ),
            (
                "core/library/object_store_contract.rs",
                include_str!("../crates/ylx-transfer-core/src/library/object_store_contract.rs"),
            ),
            (
                "core/library/object_store_port.rs",
                include_str!("../crates/ylx-transfer-core/src/library/object_store_port.rs"),
            ),
            (
                "core/library/staging.rs",
                include_str!("../crates/ylx-transfer-core/src/library/staging.rs"),
            ),
            (
                "core/lib.rs",
                include_str!("../crates/ylx-transfer-core/src/lib.rs"),
            ),
            (
                "core/persistence/app_store.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/app_store.rs"),
            ),
            (
                "core/persistence/completion_consumer.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/completion_consumer.rs"),
            ),
            (
                "core/persistence/error.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/error.rs"),
            ),
            (
                "core/persistence/legacy_import.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/legacy_import.rs"),
            ),
            (
                "core/persistence/mod.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/mod.rs"),
            ),
            (
                "core/persistence/schema.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/schema.rs"),
            ),
            (
                "core/persistence/transfer_store.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/transfer_store.rs"),
            ),
            (
                "core/persistence/upload_store.rs",
                include_str!("../crates/ylx-transfer-core/src/persistence/upload_store.rs"),
            ),
            (
                "core/publication.rs",
                include_str!("../crates/ylx-transfer-core/src/publication.rs"),
            ),
            (
                "core/secret.rs",
                include_str!("../crates/ylx-transfer-core/src/secret.rs"),
            ),
            (
                "core/transfer/aggregate.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/aggregate.rs"),
            ),
            (
                "core/transfer/coordinator.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/coordinator.rs"),
            ),
            (
                "core/transfer/fault.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/fault.rs"),
            ),
            (
                "core/transfer/mod.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/mod.rs"),
            ),
            (
                "core/transfer/progress.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/progress.rs"),
            ),
            (
                "core/transfer/queue.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/queue.rs"),
            ),
            (
                "core/transfer/recovery.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/recovery.rs"),
            ),
            (
                "core/transfer/scheduler.rs",
                include_str!("../crates/ylx-transfer-core/src/transfer/scheduler.rs"),
            ),
            (
                "adapters/credential_keyring.rs",
                include_str!("../crates/ylx-transfer-adapters/src/credential_keyring.rs"),
            ),
            (
                "adapters/discovery_mdns.rs",
                include_str!("../crates/ylx-transfer-adapters/src/discovery_mdns.rs"),
            ),
            (
                "adapters/lib.rs",
                include_str!("../crates/ylx-transfer-adapters/src/lib.rs"),
            ),
            (
                "adapters/object_store_s3.rs",
                include_str!("../crates/ylx-transfer-adapters/src/object_store_s3.rs"),
            ),
            (
                "adapters/pi_client_port.rs",
                include_str!("../crates/ylx-transfer-adapters/src/pi_client_port.rs"),
            ),
            (
                "adapters/pi_download_source.rs",
                include_str!("../crates/ylx-transfer-adapters/src/pi_download_source.rs"),
            ),
            (
                "adapters/pi_http.rs",
                include_str!("../crates/ylx-transfer-adapters/src/pi_http.rs"),
            ),
            (
                "adapters/pi_session.rs",
                include_str!("../crates/ylx-transfer-adapters/src/pi_session.rs"),
            ),
            (
                "adapters/publication_verifier.rs",
                include_str!("../crates/ylx-transfer-adapters/src/publication_verifier.rs"),
            ),
        ];
        let pending_download_info = ["Pending", "Download", "Info"].concat();
        let forbidden_identifiers = [
            ["Journal", "Store"].concat(),
            ["Job", "Files", "Sidecar"].concat(),
            pending_download_info.clone(),
            ["download", "_state"].concat(),
            ["Transfer", "Context"].concat(),
            ["transfer", "_contexts"].concat(),
            ["Pi", "Client", "Port"].concat(),
        ];
        let forbidden_paths = [
            ["job", "_store", ":", ":"].concat(),
            ["App", "Data", ".", "transfers"].concat(),
        ];
        for (name, source) in production_sources {
            for identifier in &forbidden_identifiers {
                let allowed_one_shot_import_shape = name == "core/persistence/legacy_import.rs"
                    && identifier == &pending_download_info;
                assert!(
                    allowed_one_shot_import_shape || !contains_rust_identifier(source, identifier),
                    "{name} contains retired production identifier {identifier}"
                );
            }
            for path in &forbidden_paths {
                assert!(
                    !source.contains(path),
                    "{name} contains retired production path {path}"
                );
            }
        }
    }

    fn assert_immediately_demo_gated(source_name: &str, source: &str, declaration: &str) {
        let mut occurrences = 0;
        for (offset, _) in source.match_indices(declaration) {
            occurrences += 1;
            let previous = source[..offset]
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::trim);
            assert_eq!(
                previous,
                Some("#[cfg(feature = \"demo\")]"),
                "{source_name} exposes demo-only declaration {declaration} without a feature gate"
            );
        }
        assert!(
            occurrences > 0,
            "{source_name} no longer contains expected demo declaration {declaration}"
        );
    }

    #[test]
    fn default_production_build_excludes_demo_runtime() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            !manifest
                .lines()
                .any(|line| line.trim_start().starts_with("default =")),
            "the desktop crate must not enable demo, directly or indirectly, by default"
        );
        assert!(manifest.contains("demo = [\"dep:rand\"]"));
        assert!(manifest.contains("rand = { version = \"0.8\", optional = true }"));

        let lib_source = include_str!("lib.rs");
        assert_immediately_demo_gated("lib.rs", lib_source, "mod demo;");
        assert_immediately_demo_gated("lib.rs", lib_source, "mod sim;");

        let state_source = include_str!("state.rs");
        assert_immediately_demo_gated("state.rs", state_source, "pub devices: Vec<Device>,");
        assert_immediately_demo_gated(
            "state.rs",
            state_source,
            "pub sessions: HashMap<String, Vec<Session>>",
        );
        assert_immediately_demo_gated(
            "state.rs",
            state_source,
            "pub demo_transfer_state: crate::sim::DemoTransferState,",
        );

        let workflow_source = include_str!("application/workflows.rs");
        assert_immediately_demo_gated(
            "application/workflows.rs",
            workflow_source,
            "use crate::sim::{self, DemoTransferContext, StartTransferArgs};",
        );
    }
}
