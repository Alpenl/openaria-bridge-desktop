//! Application boundary for removable-media import and video normalization.
//!
//! Concrete filesystem, SQLite, FFmpeg, and object-store implementations stay
//! behind the small ports in [`ports`]. This facade owns only RPC validation,
//! lifecycle, immutable published projections, comparable resource revisions,
//! subscriptions, and orchestration entry points. In particular, no effect is
//! performed while the publication or subscriber mutex is held.

pub mod adapters;
pub mod commands;
pub mod ports;
#[cfg(target_os = "linux")]
pub mod trust;
pub mod types;

// The removable-media MVP is intentionally limited to already-mounted Linux
// volumes. Keep its concrete adapters out of non-Linux builds so those
// platforms retain the composition root's explicit fail-closed port set.
#[cfg(target_os = "linux")]
pub mod approved_profiles;
#[cfg(target_os = "linux")]
pub mod library_root;
#[cfg(target_os = "linux")]
pub mod ubuntu;
#[cfg(target_os = "linux")]
pub mod ubuntu_derivation;
#[cfg(target_os = "linux")]
pub mod ubuntu_ingestor;
#[cfg(target_os = "linux")]
pub mod ubuntu_lifecycle;
#[cfg(target_os = "linux")]
pub mod ubuntu_normalizer;
#[cfg(target_os = "linux")]
pub mod ubuntu_pipeline;
#[cfg(target_os = "linux")]
pub mod ubuntu_projection;
#[cfg(target_os = "linux")]
pub mod ubuntu_projector;
#[cfg(target_os = "linux")]
pub mod ubuntu_uploader;
#[cfg(target_os = "linux")]
pub mod ubuntu_workers;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::application::{Revisioned, RpcError, MAX_BATCH_ITEMS, MAX_RPC_STRING_BYTES};

use ports::{
    MediaEffect, MediaLifecyclePort, MediaNormalizerPort, MediaPortError, MediaProjectionDelta,
    MediaProjectionSet, MediaProjectionSink, MediaScannerPort, MediaTrustPort, Observed,
    RecordingIngestorPort, SessionPipelinePort,
};
use types::{
    CandidateId, DerivationJob, DerivationJobId, ImportBatchItemResult, ImportBatchOutcome,
    ImportJob, ImportJobId, MediaId, MediaJobCommand, MediaLibraryEntryProjection,
    MediaScanSnapshot, MediaTrustedProducerRevocation, PipelineBatchItemResult,
    PipelineBatchOutcome, PipelineCommand, PipelineId, PipelineSession, ScanRequest, ScanSource,
    StartDerivationRequest, StartImportRequest, StartPipelineRequest,
};

const MAX_RECORDED_DELIVERY_FAILURES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaResource {
    Scan,
    Imports,
    Derivations,
    Pipelines,
    Library,
}

impl MediaResource {
    #[must_use]
    pub fn event_name(self) -> &'static str {
        match self {
            Self::Scan => "media:scan:update",
            Self::Imports => "media:imports:update",
            Self::Derivations => "media:derivations:update",
            Self::Pipelines => "media:pipelines:update",
            Self::Library => "media:library:update",
        }
    }
}

/// Atomic startup view. Inner revisions are the watermarks clients compare
/// when replaying events that raced with the snapshot request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaApplicationSnapshot {
    pub scan: Revisioned<MediaScanSnapshot>,
    pub imports: Revisioned<Vec<ImportJob>>,
    pub derivations: Revisioned<Vec<DerivationJob>>,
    pub pipelines: Revisioned<Vec<PipelineSession>>,
    pub library: Revisioned<Vec<MediaLibraryEntryProjection>>,
}

/// Event delivery boundary. Sinks are independent: one failed WebView or
/// diagnostic listener cannot prevent the remaining sinks from observing a
/// committed publication.
pub trait MediaEventSink: Send + Sync {
    fn emit(&self, name: &str, payload: Value) -> Result<(), RpcError>;
}

struct TauriMediaEventSink(AppHandle);

impl MediaEventSink for TauriMediaEventSink {
    fn emit(&self, name: &str, payload: Value) -> Result<(), RpcError> {
        self.0.emit(name, payload).map_err(|error| {
            RpcError::new(
                "event_delivery_failed",
                bounded_message(&error.to_string()),
                true,
                Some(serde_json::json!({ "event": name })),
            )
        })
    }
}

#[derive(Debug, Clone)]
struct PublishedSlot<T> {
    source_version: u64,
    envelope: Revisioned<T>,
}

impl<T> PublishedSlot<T> {
    fn seeded(observed: Observed<T>) -> Self {
        Self {
            source_version: observed.source_version,
            envelope: Revisioned::new(0, observed.value),
        }
    }
}

#[derive(Debug)]
struct PublishedMediaResources {
    global_revision: u64,
    scan: PublishedSlot<MediaScanSnapshot>,
    imports: PublishedSlot<Vec<ImportJob>>,
    derivations: PublishedSlot<Vec<DerivationJob>>,
    pipelines: PublishedSlot<Vec<PipelineSession>>,
    library: PublishedSlot<Vec<MediaLibraryEntryProjection>>,
}

impl PublishedMediaResources {
    fn seeded(initial: MediaProjectionSet) -> Self {
        Self {
            global_revision: 0,
            scan: PublishedSlot::seeded(initial.scan),
            imports: PublishedSlot::seeded(initial.imports),
            derivations: PublishedSlot::seeded(initial.derivations),
            pipelines: PublishedSlot::seeded(initial.pipelines),
            library: PublishedSlot::seeded(initial.library),
        }
    }
}

enum PendingEvent {
    Scan(Revisioned<MediaScanSnapshot>),
    Imports(Revisioned<Vec<ImportJob>>),
    Derivations(Revisioned<Vec<DerivationJob>>),
    Pipelines(Revisioned<Vec<PipelineSession>>),
    Library(Revisioned<Vec<MediaLibraryEntryProjection>>),
}

impl PendingEvent {
    fn resource(&self) -> MediaResource {
        match self {
            Self::Scan(_) => MediaResource::Scan,
            Self::Imports(_) => MediaResource::Imports,
            Self::Derivations(_) => MediaResource::Derivations,
            Self::Pipelines(_) => MediaResource::Pipelines,
            Self::Library(_) => MediaResource::Library,
        }
    }

    fn revision(&self) -> u64 {
        match self {
            Self::Scan(envelope) => envelope.revision,
            Self::Imports(envelope) => envelope.revision,
            Self::Derivations(envelope) => envelope.revision,
            Self::Pipelines(envelope) => envelope.revision,
            Self::Library(envelope) => envelope.revision,
        }
    }

    fn payload(&self) -> Result<Value, serde_json::Error> {
        match self {
            Self::Scan(envelope) => serde_json::to_value(envelope),
            Self::Imports(envelope) => serde_json::to_value(envelope),
            Self::Derivations(envelope) => serde_json::to_value(envelope),
            Self::Pipelines(envelope) => serde_json::to_value(envelope),
            Self::Library(envelope) => serde_json::to_value(envelope),
        }
    }
}

#[derive(Debug, Clone)]
struct DeliveryFailure {
    event: &'static str,
    revision: u64,
    error: RpcError,
}

#[derive(Clone)]
pub struct MediaApplicationPorts {
    scanner: Arc<dyn MediaScannerPort>,
    ingestor: Arc<dyn RecordingIngestorPort>,
    normalizer: Arc<dyn MediaNormalizerPort>,
    pipeline: Arc<dyn SessionPipelinePort>,
    trust: Arc<dyn MediaTrustPort>,
    lifecycle: Arc<dyn MediaLifecyclePort>,
}

impl MediaApplicationPorts {
    #[must_use]
    pub fn new(
        scanner: Arc<dyn MediaScannerPort>,
        ingestor: Arc<dyn RecordingIngestorPort>,
        normalizer: Arc<dyn MediaNormalizerPort>,
        pipeline: Arc<dyn SessionPipelinePort>,
        trust: Arc<dyn MediaTrustPort>,
        lifecycle: Arc<dyn MediaLifecyclePort>,
    ) -> Self {
        Self {
            scanner,
            ingestor,
            normalizer,
            pipeline,
            trust,
            lifecycle,
        }
    }
}

struct MediaApplicationInner {
    ports: MediaApplicationPorts,
    publications: Mutex<PublishedMediaResources>,
    subscribers: Mutex<HashMap<u64, Arc<dyn MediaEventSink>>>,
    next_subscriber: AtomicU64,
    tauri_subscription: Mutex<Option<MediaSubscription>>,
    delivery_failures: Mutex<VecDeque<DeliveryFailure>>,
    lifecycle_gate: Mutex<()>,
    started: AtomicBool,
    stop_complete: AtomicBool,
    lifecycle_epoch: AtomicU64,
}

/// Sole application-facing facade for media discovery, import,
/// normalization, and pipeline policy orchestration.
#[derive(Clone)]
pub struct MediaApplication(Arc<MediaApplicationInner>);

impl MediaApplication {
    #[must_use]
    pub fn new(initial: MediaProjectionSet, ports: MediaApplicationPorts) -> Self {
        Self(Arc::new(MediaApplicationInner {
            ports,
            publications: Mutex::new(PublishedMediaResources::seeded(initial)),
            subscribers: Mutex::new(HashMap::new()),
            next_subscriber: AtomicU64::new(1),
            tauri_subscription: Mutex::new(None),
            delivery_failures: Mutex::new(VecDeque::new()),
            lifecycle_gate: Mutex::new(()),
            started: AtomicBool::new(false),
            stop_complete: AtomicBool::new(false),
            lifecycle_epoch: AtomicU64::new(0),
        }))
    }

    pub fn from_app<R: Runtime>(app: &AppHandle<R>) -> Result<Self, RpcError> {
        app.try_state::<Self>()
            .map(|state| state.inner().clone())
            .ok_or_else(|| {
                RpcError::new(
                    "application_unavailable",
                    "媒体应用门面尚未初始化",
                    false,
                    None,
                )
            })
    }

    /// Read one already-published startup view. No scanner, database, file,
    /// network, or FFmpeg effect is performed by this method.
    #[must_use]
    pub fn read_snapshot(&self) -> Revisioned<MediaApplicationSnapshot> {
        let published = self
            .0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Revisioned::new(
            published.global_revision,
            MediaApplicationSnapshot {
                scan: published.scan.envelope.clone(),
                imports: published.imports.envelope.clone(),
                derivations: published.derivations.envelope.clone(),
                pipelines: published.pipelines.envelope.clone(),
                library: published.library.envelope.clone(),
            },
        )
    }

    #[must_use]
    pub fn read_scan_candidates(&self) -> Revisioned<MediaScanSnapshot> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .scan
            .envelope
            .clone()
    }

    #[must_use]
    pub fn read_import_jobs(&self) -> Revisioned<Vec<ImportJob>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .imports
            .envelope
            .clone()
    }

    #[must_use]
    pub fn read_derivation_jobs(&self) -> Revisioned<Vec<DerivationJob>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .derivations
            .envelope
            .clone()
    }

    #[must_use]
    pub fn read_pipeline_sessions(&self) -> Revisioned<Vec<PipelineSession>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pipelines
            .envelope
            .clone()
    }

    #[must_use]
    pub fn read_library_projections(&self) -> Revisioned<Vec<MediaLibraryEntryProjection>> {
        self.0
            .publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .library
            .envelope
            .clone()
    }

    pub fn subscribe(&self, sink: Arc<dyn MediaEventSink>) -> MediaSubscription {
        let id = self.0.next_subscriber.fetch_add(1, Ordering::Relaxed);
        self.0
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, sink);
        MediaSubscription {
            owner: Arc::downgrade(&self.0),
            id,
            disposed: AtomicBool::new(false),
        }
    }

    pub fn bind_tauri(&self, app: &AppHandle) -> MediaSubscription {
        self.subscribe(Arc::new(TauriMediaEventSink(app.clone())))
    }

    /// Bind event delivery, recover durable jobs, and start watchers/workers
    /// exactly once. Recovery and startup run on the blocking pool. A stop
    /// racing with recovery advances the lifecycle epoch, fencing the late
    /// result and preventing the worker set from being started afterward.
    pub fn start(&self, app: AppHandle) {
        if self.0.started.swap(true, Ordering::SeqCst) {
            return;
        }
        self.0.stop_complete.store(false, Ordering::SeqCst);

        let subscription = self.bind_tauri(&app);
        self.0
            .tauri_subscription
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replace(subscription);

        let epoch = self
            .0
            .lifecycle_epoch
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let application = self.clone();
        let lifecycle = Arc::clone(&self.0.ports.lifecycle);
        let _recovery_task = tauri::async_runtime::spawn_blocking(move || {
            match lifecycle.recover() {
                Ok(projection) if application.lifecycle_is_current(epoch) => {
                    application.publish_delta(projection.into_delta());
                }
                Ok(_) => return,
                Err(error) => {
                    application.record_background_error("media:recovery", 0, error);
                    return;
                }
            }

            let _lifecycle_guard = application
                .0
                .lifecycle_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !application.lifecycle_is_current(epoch) {
                return;
            }
            let sink: Arc<dyn MediaProjectionSink> = Arc::new(ApplicationProjectionSink {
                owner: Arc::downgrade(&application.0),
                epoch,
            });
            if let Err(error) = lifecycle.start(sink) {
                application.record_background_error("media:lifecycle", 0, error);
            }
        });
    }

    /// Stop discovery and job workers before dropping the Tauri event sink.
    /// The lifecycle port must not acknowledge until owned worker/process
    /// resources and removable-media handles have been released.
    pub fn stop(&self) -> Result<(), RpcError> {
        self.0.started.store(false, Ordering::SeqCst);
        self.0.lifecycle_epoch.fetch_add(1, Ordering::SeqCst);
        let _lifecycle_guard = self
            .0
            .lifecycle_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.0.stop_complete.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.0
            .ports
            .lifecycle
            .stop()
            .map_err(MediaPortError::into_rpc)?;

        // Fence a start that raced the blocking lifecycle stop so no late
        // recovery result or worker start is treated as current.
        self.0.started.store(false, Ordering::SeqCst);
        self.0.lifecycle_epoch.fetch_add(1, Ordering::SeqCst);
        self.0
            .tauri_subscription
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let retained_failures = self.delivery_failures();
        if !retained_failures.is_empty() {
            eprintln!(
                "[media] {} bounded event-delivery failures retained at shutdown",
                retained_failures.len()
            );
        }
        self.0.stop_complete.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn scan(
        &self,
        request: ScanRequest,
    ) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
        validate_scan_request(&request)?;
        let scanner = Arc::clone(&self.0.ports.scanner);
        let observed = run_blocking("scan_failed", move || scanner.scan(request)).await?;
        self.publish_delta(MediaProjectionDelta::scan(observed));
        Ok(self.read_scan_candidates())
    }

    pub async fn release_media_handles(
        &self,
        media_id: MediaId,
    ) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
        validate_identifier("mediaId", media_id.as_str())?;
        let scanner = Arc::clone(&self.0.ports.scanner);
        let observed = run_blocking("media_unavailable", move || {
            scanner.release_media_handles(media_id)
        })
        .await?;
        self.publish_delta(MediaProjectionDelta::scan(observed));
        Ok(self.read_scan_candidates())
    }

    pub async fn eject_media(
        &self,
        media_id: MediaId,
    ) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
        validate_identifier("mediaId", media_id.as_str())?;
        let scanner = Arc::clone(&self.0.ports.scanner);
        let observed =
            run_blocking("media_unavailable", move || scanner.eject_media(media_id)).await?;
        self.publish_delta(MediaProjectionDelta::scan(observed));
        Ok(self.read_scan_candidates())
    }

    pub async fn start_import(
        &self,
        request: StartImportRequest,
    ) -> Result<Revisioned<ImportJob>, RpcError> {
        validate_start_import(&request)?;
        let ingestor = Arc::clone(&self.0.ports.ingestor);
        let effect = run_blocking("import_start_failed", move || {
            ingestor.start_import(request)
        })
        .await?;
        self.publish_import_effect(effect)
    }

    pub async fn start_import_batch(
        &self,
        requests: Vec<StartImportRequest>,
    ) -> Result<Revisioned<ImportBatchOutcome>, RpcError> {
        validate_import_batch(&requests)?;
        let ingestor = Arc::clone(&self.0.ports.ingestor);
        let attempted = run_batch_blocking("import_start_failed", move || {
            let mut outcomes = Vec::with_capacity(requests.len());
            let mut projections = MediaProjectionDelta::default();
            for request in requests {
                let item = request.candidate_id.clone();
                match ingestor.start_import(request) {
                    Ok(effect) => {
                        let job_id = effect.result.id;
                        projections.merge(effect.projections);
                        outcomes.push((item, Ok(job_id)));
                    }
                    Err(error) => outcomes.push((item, Err(error.into_rpc()))),
                }
            }
            (outcomes, projections)
        })
        .await?;

        self.publish_delta(attempted.1);
        let imports = self.read_import_jobs();
        let visible_job_ids = imports
            .value
            .iter()
            .map(|job| job.id.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut projection_missing = false;
        let results = attempted
            .0
            .into_iter()
            .map(|(item, outcome)| match outcome {
                Ok(job_id) if visible_job_ids.contains(&job_id) => {
                    ImportBatchItemResult::Success { item, job_id }
                }
                Ok(job_id) => {
                    projection_missing = true;
                    ImportBatchItemResult::Failure {
                        item,
                        error: missing_projection_error("imports", job_id.as_str()),
                    }
                }
                Err(error) => ImportBatchItemResult::Failure { item, error },
            })
            .collect();
        Ok(Revisioned::new(
            imports.revision,
            ImportBatchOutcome {
                results,
                operation_error: projection_missing.then_some(import_batch_contract_error()),
            },
        ))
    }

    pub async fn command_import(
        &self,
        job_id: ImportJobId,
        command: MediaJobCommand,
    ) -> Result<Revisioned<ImportJob>, RpcError> {
        validate_identifier("jobId", job_id.as_str())?;
        let ingestor = Arc::clone(&self.0.ports.ingestor);
        let effect = run_blocking("import_command_failed", move || {
            ingestor.command_import(job_id, command)
        })
        .await?;
        self.publish_import_effect(effect)
    }

    pub async fn start_derivation(
        &self,
        request: StartDerivationRequest,
    ) -> Result<Revisioned<DerivationJob>, RpcError> {
        validate_start_derivation(&request)?;
        let normalizer = Arc::clone(&self.0.ports.normalizer);
        let effect = run_blocking("derivation_start_failed", move || {
            normalizer.start_derivation(request)
        })
        .await?;
        self.publish_derivation_effect(effect)
    }

    pub async fn command_derivation(
        &self,
        job_id: DerivationJobId,
        command: MediaJobCommand,
    ) -> Result<Revisioned<DerivationJob>, RpcError> {
        validate_identifier("jobId", job_id.as_str())?;
        let normalizer = Arc::clone(&self.0.ports.normalizer);
        let effect = run_blocking("derivation_command_failed", move || {
            normalizer.command_derivation(job_id, command)
        })
        .await?;
        self.publish_derivation_effect(effect)
    }

    pub async fn start_pipeline(
        &self,
        request: StartPipelineRequest,
    ) -> Result<Revisioned<PipelineSession>, RpcError> {
        validate_start_pipeline(&request)?;
        let pipeline = Arc::clone(&self.0.ports.pipeline);
        let effect = run_blocking("pipeline_start_failed", move || {
            pipeline.start_pipeline(request)
        })
        .await?;
        self.publish_pipeline_effect(effect)
    }

    pub async fn start_pipeline_batch(
        &self,
        requests: Vec<StartPipelineRequest>,
    ) -> Result<Revisioned<PipelineBatchOutcome>, RpcError> {
        validate_pipeline_batch(&requests)?;
        let requested_items = requests
            .iter()
            .map(|request| request.candidate_id.clone())
            .collect::<Vec<_>>();
        let pipeline = Arc::clone(&self.0.ports.pipeline);
        let effect = run_blocking("pipeline_start_failed", move || {
            pipeline.start_pipeline_batch(requests)
        })
        .await?;

        let mut outcome = normalize_pipeline_batch_outcome(requested_items, effect.result);
        self.publish_delta(effect.projections);
        let pipelines = self.read_pipeline_sessions();
        let visible_pipeline_ids = pipelines
            .value
            .iter()
            .map(|pipeline| pipeline.id.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut projection_missing = false;
        outcome.results = outcome
            .results
            .into_iter()
            .map(|result| match result {
                PipelineBatchItemResult::Success { item, job_id }
                    if visible_pipeline_ids.contains(&job_id) =>
                {
                    PipelineBatchItemResult::Success { item, job_id }
                }
                PipelineBatchItemResult::Success { item, job_id } => {
                    projection_missing = true;
                    PipelineBatchItemResult::Failure {
                        item,
                        error: missing_projection_error("pipelines", job_id.as_str()),
                    }
                }
                failure @ PipelineBatchItemResult::Failure { .. } => failure,
            })
            .collect();
        if projection_missing {
            outcome
                .operation_error
                .get_or_insert_with(batch_contract_error);
        }
        Ok(Revisioned::new(pipelines.revision, outcome))
    }

    pub async fn command_pipeline(
        &self,
        pipeline_id: PipelineId,
        command: PipelineCommand,
    ) -> Result<Revisioned<PipelineSession>, RpcError> {
        validate_identifier("pipelineId", pipeline_id.as_str())?;
        let pipeline = Arc::clone(&self.0.ports.pipeline);
        let effect = run_blocking("pipeline_command_failed", move || {
            pipeline.command_pipeline(pipeline_id, command)
        })
        .await?;
        self.publish_pipeline_effect(effect)
    }

    pub async fn retry_derived_upload(&self, parent_job_id: String) -> Result<String, RpcError> {
        validate_identifier("jobId", &parent_job_id)?;
        let pipeline = Arc::clone(&self.0.ports.pipeline);
        let effect = run_blocking("pipeline_command_failed", move || {
            pipeline.retry_derived_upload(&parent_job_id)
        })
        .await?;
        self.publish_delta(effect.projections);
        Ok(effect.result)
    }

    pub async fn revoke_trusted_producer(
        &self,
        key_fingerprint: String,
    ) -> Result<MediaTrustedProducerRevocation, RpcError> {
        validate_identifier("keyFingerprint", &key_fingerprint)?;
        let trust = Arc::clone(&self.0.ports.trust);
        run_blocking("operation_conflict", move || {
            trust.revoke_trusted_producer(&key_fingerprint)
        })
        .await
    }

    fn publish_import_effect(
        &self,
        effect: MediaEffect<ImportJob>,
    ) -> Result<Revisioned<ImportJob>, RpcError> {
        let job_id = effect.result.id;
        self.publish_delta(effect.projections);
        let imports = self.read_import_jobs();
        let job = imports
            .value
            .into_iter()
            .find(|job| job.id == job_id)
            .ok_or_else(|| missing_projection_error("imports", job_id.as_str()))?;
        Ok(Revisioned::new(imports.revision, job))
    }

    fn publish_derivation_effect(
        &self,
        effect: MediaEffect<DerivationJob>,
    ) -> Result<Revisioned<DerivationJob>, RpcError> {
        let job_id = effect.result.id;
        self.publish_delta(effect.projections);
        let derivations = self.read_derivation_jobs();
        let job = derivations
            .value
            .into_iter()
            .find(|job| job.id == job_id)
            .ok_or_else(|| missing_projection_error("derivations", job_id.as_str()))?;
        Ok(Revisioned::new(derivations.revision, job))
    }

    fn publish_pipeline_effect(
        &self,
        effect: MediaEffect<PipelineSession>,
    ) -> Result<Revisioned<PipelineSession>, RpcError> {
        let pipeline_id = effect.result.id;
        self.publish_delta(effect.projections);
        let pipelines = self.read_pipeline_sessions();
        let pipeline = pipelines
            .value
            .into_iter()
            .find(|pipeline| pipeline.id == pipeline_id)
            .ok_or_else(|| missing_projection_error("pipelines", pipeline_id.as_str()))?;
        Ok(Revisioned::new(pipelines.revision, pipeline))
    }

    fn lifecycle_is_current(&self, epoch: u64) -> bool {
        self.0.started.load(Ordering::SeqCst)
            && self.0.lifecycle_epoch.load(Ordering::SeqCst) == epoch
    }

    /// Update exact values and their wire revisions under one lock, release
    /// it, then attempt event delivery. All resources accepted from one delta
    /// receive one revision, so a snapshot cannot expose half of that delta.
    fn publish_delta(&self, delta: MediaProjectionDelta) {
        let events = {
            let mut published = self
                .0
                .publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            let accept_scan = delta
                .scan
                .as_ref()
                .is_some_and(|value| value.source_version > published.scan.source_version);
            let accept_imports = delta
                .imports
                .as_ref()
                .is_some_and(|value| value.source_version > published.imports.source_version);
            let accept_derivations = delta
                .derivations
                .as_ref()
                .is_some_and(|value| value.source_version > published.derivations.source_version);
            let accept_pipelines = delta
                .pipelines
                .as_ref()
                .is_some_and(|value| value.source_version > published.pipelines.source_version);
            let accept_library = delta
                .library
                .as_ref()
                .is_some_and(|value| value.source_version > published.library.source_version);

            if !(accept_scan
                || accept_imports
                || accept_derivations
                || accept_pipelines
                || accept_library)
            {
                return;
            }

            published.global_revision = published.global_revision.saturating_add(1);
            let revision = published.global_revision;
            let mut events = Vec::with_capacity(5);

            if accept_scan {
                if let Some(observed) = delta.scan {
                    published.scan.source_version = observed.source_version;
                    published.scan.envelope = Revisioned::new(revision, observed.value);
                    events.push(PendingEvent::Scan(published.scan.envelope.clone()));
                }
            }
            if accept_imports {
                if let Some(observed) = delta.imports {
                    published.imports.source_version = observed.source_version;
                    published.imports.envelope = Revisioned::new(revision, observed.value);
                    events.push(PendingEvent::Imports(published.imports.envelope.clone()));
                }
            }
            if accept_derivations {
                if let Some(observed) = delta.derivations {
                    published.derivations.source_version = observed.source_version;
                    published.derivations.envelope = Revisioned::new(revision, observed.value);
                    events.push(PendingEvent::Derivations(
                        published.derivations.envelope.clone(),
                    ));
                }
            }
            if accept_pipelines {
                if let Some(observed) = delta.pipelines {
                    published.pipelines.source_version = observed.source_version;
                    published.pipelines.envelope = Revisioned::new(revision, observed.value);
                    events.push(PendingEvent::Pipelines(
                        published.pipelines.envelope.clone(),
                    ));
                }
            }
            if accept_library {
                if let Some(observed) = delta.library {
                    published.library.source_version = observed.source_version;
                    published.library.envelope = Revisioned::new(revision, observed.value);
                    events.push(PendingEvent::Library(published.library.envelope.clone()));
                }
            }

            events
        };

        for event in events {
            self.deliver(event);
        }
    }

    fn deliver(&self, event: PendingEvent) {
        let event_name = event.resource().event_name();
        let revision = event.revision();
        let payload = match event.payload() {
            Ok(payload) => payload,
            Err(error) => {
                self.record_delivery_failure(
                    event_name,
                    revision,
                    RpcError::new(
                        "event_delivery_failed",
                        bounded_message(&error.to_string()),
                        false,
                        Some(serde_json::json!({
                            "event": event_name,
                            "revision": revision,
                            "stage": "serialize"
                        })),
                    ),
                );
                return;
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
        for sink in subscribers {
            if let Err(error) = sink.emit(event_name, payload.clone()) {
                self.record_delivery_failure(event_name, revision, error);
            }
        }
    }

    fn record_delivery_failure(&self, event: &'static str, revision: u64, error: RpcError) {
        eprintln!("[media] published {event} revision {revision}, but delivery failed: {error}");
        let mut failures = self
            .0
            .delivery_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failures.len() == MAX_RECORDED_DELIVERY_FAILURES {
            failures.pop_front();
        }
        failures.push_back(DeliveryFailure {
            event,
            revision,
            error,
        });
    }

    fn record_background_error(&self, event: &'static str, revision: u64, error: MediaPortError) {
        self.record_delivery_failure(event, revision, error.into_rpc());
    }

    /// Bounded diagnostic view consumed during shutdown. It deliberately
    /// returns structured errors rather than raw adapter output.
    #[must_use]
    pub fn delivery_failures(&self) -> Vec<(String, u64, RpcError)> {
        self.0
            .delivery_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|failure| {
                (
                    failure.event.to_string(),
                    failure.revision,
                    failure.error.clone(),
                )
            })
            .collect()
    }
}

/// Weak publication bridge for producers that are assembled before the
/// application facade is registered as managed Tauri state. The projector
/// lane keeps only this bridge, so dropping the application cannot leave a
/// strong reference cycle or publish into a torn-down WebView.
#[derive(Debug, Default)]
pub struct MediaProjectionBridge {
    owner: Mutex<Option<Weak<MediaApplicationInner>>>,
}

impl MediaProjectionBridge {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn attach(&self, application: &MediaApplication) {
        *self
            .owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Arc::downgrade(&application.0));
    }
}

impl MediaProjectionSink for MediaProjectionBridge {
    fn publish(&self, delta: MediaProjectionDelta) -> Result<(), MediaPortError> {
        let owner = self
            .owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                MediaPortError::new(
                    ports::MediaErrorCode::OperationConflict,
                    "media application is no longer available",
                )
                .with_retryable(false)
            })?;
        let application = MediaApplication(owner);
        if !application.0.started.load(Ordering::SeqCst) {
            return Err(MediaPortError::new(
                ports::MediaErrorCode::OperationConflict,
                "media application is not active",
            )
            .with_retryable(false));
        }
        application.publish_delta(delta);
        Ok(())
    }
}

// Non-Linux builds retain the fail-closed media facade, but their lifecycle
// adapter never invokes this Ubuntu-owned publication callback.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ApplicationProjectionSink {
    owner: Weak<MediaApplicationInner>,
    epoch: u64,
}

impl MediaProjectionSink for ApplicationProjectionSink {
    fn publish(&self, delta: MediaProjectionDelta) -> Result<(), MediaPortError> {
        let owner = self.owner.upgrade().ok_or_else(|| {
            MediaPortError::new(
                ports::MediaErrorCode::OperationConflict,
                "media application is no longer available",
            )
            .with_retryable(false)
        })?;
        let application = MediaApplication(owner);
        if !application.lifecycle_is_current(self.epoch) {
            return Err(MediaPortError::new(
                ports::MediaErrorCode::OperationConflict,
                "media lifecycle publication is stale",
            )
            .with_retryable(false));
        }
        application.publish_delta(delta);
        Ok(())
    }
}

/// Idempotent listener disposer. Dropping the handle also unsubscribes.
pub struct MediaSubscription {
    owner: Weak<MediaApplicationInner>,
    id: u64,
    disposed: AtomicBool,
}

impl MediaSubscription {
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

impl Drop for MediaSubscription {
    fn drop(&mut self) {
        self.dispose();
    }
}

async fn run_blocking<T, F>(join_error_code: &'static str, task: F) -> Result<T, RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, MediaPortError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| {
            RpcError::new(
                join_error_code,
                bounded_message(&format!("media worker terminated unexpectedly: {error}")),
                true,
                None,
            )
        })?
        .map_err(MediaPortError::into_rpc)
}

async fn run_batch_blocking<T, F>(join_error_code: &'static str, task: F) -> Result<T, RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| {
            RpcError::new(
                join_error_code,
                bounded_message(&format!(
                    "media batch worker terminated unexpectedly: {error}"
                )),
                true,
                None,
            )
        })
}

fn validate_scan_request(request: &ScanRequest) -> Result<(), RpcError> {
    match &request.source {
        ScanSource::MountedVolumes => Ok(()),
        ScanSource::SelectedFolder { path } => validate_text("path", path),
    }
}

fn validate_start_import(request: &StartImportRequest) -> Result<(), RpcError> {
    validate_identifier("candidateId", request.candidate_id.as_str())
}

fn validate_start_derivation(request: &StartDerivationRequest) -> Result<(), RpcError> {
    validate_identifier("sourceId", request.source_id.as_str())?;
    validate_identifier("profileId", request.profile_id.as_str())
}

fn validate_start_pipeline(request: &StartPipelineRequest) -> Result<(), RpcError> {
    validate_identifier("candidateId", request.candidate_id.as_str())?;
    if request.policy.upload_source_video {
        return Err(RpcError::invalid_input(
            "policy.uploadSourceVideo",
            "source video archival is not available in V1",
        ));
    }
    if request.policy.auto_upload_derived && !request.policy.auto_normalize {
        return Err(RpcError::invalid_input(
            "policy.autoUploadDerived",
            "requires autoNormalize for a candidate pipeline",
        ));
    }
    if request.policy.unsigned_upload_approved {
        return Err(RpcError::invalid_input(
            "policy.unsignedUploadApproved",
            "must be false; approval is issued only by approve_unsigned_upload",
        ));
    }
    Ok(())
}

fn validate_import_batch(requests: &[StartImportRequest]) -> Result<(), RpcError> {
    if requests.is_empty() {
        return Err(RpcError::invalid_input("requests", "must not be empty"));
    }
    if requests.len() > MAX_BATCH_ITEMS {
        return Err(RpcError::invalid_input(
            "requests",
            &format!("must contain at most {MAX_BATCH_ITEMS} items"),
        ));
    }
    let mut candidates = std::collections::HashSet::with_capacity(requests.len());
    for request in requests {
        validate_start_import(request)?;
        if !candidates.insert(request.candidate_id.as_str()) {
            return Err(RpcError::invalid_input(
                "requests",
                "candidateId values must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_pipeline_batch(requests: &[StartPipelineRequest]) -> Result<(), RpcError> {
    if requests.is_empty() {
        return Err(RpcError::invalid_input("requests", "must not be empty"));
    }
    if requests.len() > MAX_BATCH_ITEMS {
        return Err(RpcError::invalid_input(
            "requests",
            &format!("must contain at most {MAX_BATCH_ITEMS} items"),
        ));
    }
    let mut candidates = std::collections::HashSet::with_capacity(requests.len());
    for request in requests {
        validate_start_pipeline(request)?;
        if !candidates.insert(request.candidate_id.as_str()) {
            return Err(RpcError::invalid_input(
                "requests",
                "candidateId values must be unique",
            ));
        }
    }
    Ok(())
}

fn normalize_pipeline_batch_outcome(
    requested_items: Vec<CandidateId>,
    mut outcome: PipelineBatchOutcome,
) -> PipelineBatchOutcome {
    let requested = requested_items
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let mut returned = HashMap::with_capacity(outcome.results.len());
    let mut invalid_items = std::collections::HashSet::new();
    let mut contract_violation = false;
    for result in outcome.results {
        let item = match &result {
            PipelineBatchItemResult::Success { item, .. }
            | PipelineBatchItemResult::Failure { item, .. } => item.clone(),
        };
        if !requested.contains(&item) {
            contract_violation = true;
            continue;
        }
        if returned.insert(item.clone(), result).is_some() {
            invalid_items.insert(item);
            contract_violation = true;
        }
    }

    let results = requested_items
        .into_iter()
        .map(
            |item| match (invalid_items.contains(&item), returned.remove(&item)) {
                (true, _) => PipelineBatchItemResult::Failure {
                    item,
                    error: batch_contract_error(),
                },
                (false, Some(result)) => result,
                (false, None) => {
                    contract_violation = true;
                    PipelineBatchItemResult::Failure {
                        item,
                        error: batch_contract_error(),
                    }
                }
            },
        )
        .collect();
    if contract_violation || !returned.is_empty() {
        outcome
            .operation_error
            .get_or_insert_with(batch_contract_error);
    }
    outcome.results = results;
    outcome
}

fn validate_identifier(field: &str, value: &str) -> Result<(), RpcError> {
    validate_text(field, value)?;
    if value.chars().any(char::is_control) {
        return Err(RpcError::invalid_input(
            field,
            "must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<(), RpcError> {
    if value.trim().is_empty() {
        return Err(RpcError::invalid_input(field, "must not be empty"));
    }
    if value.len() > MAX_RPC_STRING_BYTES {
        return Err(RpcError::invalid_input(
            field,
            &format!("must be at most {MAX_RPC_STRING_BYTES} bytes"),
        ));
    }
    if value.contains('\0') {
        return Err(RpcError::invalid_input(field, "must not contain NUL"));
    }
    Ok(())
}

fn missing_projection_error(resource: &str, id: &str) -> RpcError {
    RpcError::new(
        "operation_conflict",
        "媒体操作已提交，但对应的发布投影不可用",
        true,
        Some(serde_json::json!({ "resource": resource, "id": id })),
    )
}

fn batch_contract_error() -> RpcError {
    RpcError::new(
        "operation_conflict",
        "媒体批处理结果与请求集合不一致",
        true,
        Some(serde_json::json!({ "operation": "startPipelineBatch" })),
    )
}

fn import_batch_contract_error() -> RpcError {
    RpcError::new(
        "operation_conflict",
        "媒体导入批处理结果与已提交投影不一致",
        true,
        Some(serde_json::json!({ "operation": "startImportBatch" })),
    )
}

fn bounded_message(value: &str) -> String {
    const MAX_BYTES: usize = 1024;
    let mut output = String::new();
    for character in value.chars() {
        if output.len() + character.len_utf8() > MAX_BYTES {
            break;
        }
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.push(' ');
        }
    }
    if output.trim().is_empty() {
        "media operation failed".to_string()
    } else {
        output
    }
}

#[cfg(test)]
mod request_validation_tests {
    use super::types::PipelinePolicy;
    use super::*;

    fn request(policy: PipelinePolicy) -> StartPipelineRequest {
        StartPipelineRequest {
            candidate_id: CandidateId::new("candidate-1"),
            approve_unsigned: false,
            policy,
        }
    }

    fn policy() -> PipelinePolicy {
        PipelinePolicy {
            auto_normalize: false,
            auto_upload_derived: false,
            upload_source_video: false,
            unsigned_upload_approved: false,
        }
    }

    #[test]
    fn start_pipeline_policy_rejects_unavailable_or_unbound_upload_modes() {
        let mut source_archival = policy();
        source_archival.upload_source_video = true;
        assert_eq!(
            validate_start_pipeline(&request(source_archival))
                .expect_err("source archival must fail")
                .details
                .and_then(|details| details.get("field").cloned()),
            Some(serde_json::json!("policy.uploadSourceVideo")),
        );

        let mut derived_without_normalization = policy();
        derived_without_normalization.auto_upload_derived = true;
        assert_eq!(
            validate_start_pipeline(&request(derived_without_normalization))
                .expect_err("derived upload without normalization must fail")
                .details
                .and_then(|details| details.get("field").cloned()),
            Some(serde_json::json!("policy.autoUploadDerived")),
        );

        let mut caller_asserted_approval = policy();
        caller_asserted_approval.unsigned_upload_approved = true;
        assert_eq!(
            validate_start_pipeline(&request(caller_asserted_approval))
                .expect_err("caller asserted upload approval must fail")
                .details
                .and_then(|details| details.get("field").cloned()),
            Some(serde_json::json!("policy.unsignedUploadApproved")),
        );
    }

    #[test]
    fn start_pipeline_policy_accepts_import_normalize_and_derived_upload_modes() {
        assert!(validate_start_pipeline(&request(policy())).is_ok());

        let mut normalize = policy();
        normalize.auto_normalize = true;
        assert!(validate_start_pipeline(&request(normalize.clone())).is_ok());

        normalize.auto_upload_derived = true;
        assert!(validate_start_pipeline(&request(normalize)).is_ok());
    }
}
