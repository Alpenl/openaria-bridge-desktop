//! Ubuntu-only bridge from the durable recording-ingest executor to the
//! application media port.
//!
//! This module deliberately depends only on the core `CandidateCatalog` and
//! `ArtifactSourceResolver` traits. The Linux volume runtime owns concrete
//! mount discovery, candidate caching, admission, and fenced file handles;
//! this bridge owns the durable import executor, the background worker entry
//! point, local-space admission, and app projection mapping.
//!
//! Commands here never copy bytes. They validate, commit durable intent, wake
//! the import lane, and return the resulting projection. `run_import_once` is
//! the only method that performs copy I/O, and it runs on the lane's thread
//! under a shared library-root lease.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{SecondsFormat, Utc};
use ylx_transfer_core::ingest::{
    CandidateId as CoreCandidateId, ImportCommandOutcome as CoreImportCommandOutcome,
    ImportControlCommand as CoreImportControlCommand, ImportDesiredState as CoreImportDesiredState,
    ImportFailure as CoreImportFailure, ImportFailureCode as CoreImportFailureCode,
    ImportJobId as CoreImportJobId, ImportJobState as CoreImportJobState, ImportPolicy, ImportSpec,
    ImportSpecError, IngestError as CoreIngestError, RecordingIngestor as CoreRecordingIngestor,
    SourceRecording, UnsignedImportPolicy,
};
use ylx_transfer_core::media_store::{MediaStore, Recoverable, StoredImportJob};
use ylx_transfer_core::recording_ingestor::{
    ArtifactSourceResolver, CandidateCatalog, ImportNotificationSink, ImportRepository,
    ImportScheduler, IngestClock, IngestPortError, LocalSpace, MediaStoreImportRepository,
    MediaStoreSourcePublishLeases, RecordingIngestConfig, RecordingIngestExecutor,
    RecordingIngestorError, SourcePublishLeases,
};

use crate::application::RpcError;

use super::library_root::LibraryRootLease;
use super::ports::{
    MediaEffect, MediaErrorCode, MediaPortError, MediaProjectionDelta, Observed,
    RecordingIngestorPort,
};
use super::types::{
    CandidateId, DesiredRunState, ImportJob, ImportJobId, ImportJobState, ImportProgress, MediaId,
    MediaJobCommand, SourceId, StartImportRequest,
};
use super::ubuntu::UbuntuDestinationGuard;
use super::ubuntu_workers::{EnqueueOutcome, MediaWakeQueue};

const DEFAULT_SAFETY_MARGIN_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAXIMUM_WORKER_STEPS: usize = 65_536;
/// Bound on how many times one worker turn may re-enter the executor for the
/// same job before the lane declares it stuck rather than spinning forever.
const MAXIMUM_WORKER_TURNS: usize = 64;
const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Non-path configuration owned by the desktop composition. The current
/// library root is supplied under the root-switch gate for every operation.
#[derive(Debug, Clone)]
pub struct UbuntuIngestConfig {
    pub safety_margin_bytes: u64,
    pub derivation_working_set_reserve_bytes: u64,
    pub checkpoint_interval_bytes: u64,
    pub maximum_worker_steps: usize,
}

impl UbuntuIngestConfig {
    #[must_use]
    pub fn new() -> Self {
        let defaults = RecordingIngestConfig::new();
        Self {
            safety_margin_bytes: DEFAULT_SAFETY_MARGIN_BYTES,
            derivation_working_set_reserve_bytes: 0,
            checkpoint_interval_bytes: defaults.checkpoint_interval_bytes,
            maximum_worker_steps: DEFAULT_MAXIMUM_WORKER_STEPS,
        }
    }

    fn executor_config(&self) -> RecordingIngestConfig {
        RecordingIngestConfig {
            checkpoint_interval_bytes: self.checkpoint_interval_bytes,
            derivation_working_set_reserve_bytes: self.derivation_working_set_reserve_bytes,
            maximum_worker_steps: self.maximum_worker_steps,
        }
    }
}

/// Owner of the mutable PC library-root fence.
///
/// Two shapes, for two very different operations:
///
/// * `with_library_root` is the short exclusive form. Implementations retain
///   their root-switch lock until the callback returns, so it must only wrap
///   bounded work — preflight, a durable create, a projection read.
/// * `acquire_shared_library_root` is the long form. It returns a lease that
///   many holders may share, so an import copying for an hour never blocks a
///   pause command or another worker. The lease pins the root's identity and
///   must be re-asserted at every I/O stage boundary.
pub trait UbuntuLibraryRootGate: Send + Sync + 'static {
    fn with_library_root<T>(&self, operation: impl FnOnce(&Path) -> T) -> T;

    fn acquire_shared_library_root(&self, owner: &str) -> Result<LibraryRootLease, MediaPortError>;
}

/// Production local-space implementation for the Ubuntu-only initial scope.
///
/// `df -Pk` is used rather than an unbounded recursive size walk. The path is
/// passed as an argument after `--`, never interpolated into a shell command.
#[derive(Debug, Default)]
pub struct UbuntuLocalSpace;

impl LocalSpace for UbuntuLocalSpace {
    fn available_bytes(&self, library_root: &Path) -> Result<u64, IngestPortError> {
        let output = Command::new("df")
            .args(["-Pk", "--"])
            .arg(library_root)
            .output()
            .map_err(|error| {
                IngestPortError::new(
                    "local_space",
                    format!("cannot inspect local free space: {error}"),
                )
            })?;
        if !output.status.success() {
            return Err(IngestPortError::new(
                "local_space",
                format!(
                    "df did not report free space for the library root: {}",
                    output.status
                ),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let available_blocks = stdout
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .last()
            .and_then(|line| line.split_whitespace().nth(3))
            .ok_or_else(|| {
                IngestPortError::new(
                    "local_space",
                    "df output did not contain an available-blocks field",
                )
            })?
            .parse::<u64>()
            .map_err(|error| {
                IngestPortError::new(
                    "local_space",
                    format!("df available-blocks field was invalid: {error}"),
                )
            })?;
        available_blocks.checked_mul(1024).ok_or_else(|| {
            IngestPortError::new(
                "local_space",
                "available local-space value overflowed bytes",
            )
        })
    }
}

#[derive(Debug, Default)]
struct SystemIngestClock;

impl IngestClock for SystemIngestClock {
    fn now_rfc3339(&self) -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    }
}

/// Scheduler that only wakes the background import lane.
///
/// It deliberately performs no work of its own. A command persists durable
/// intent and then puts the job id here; the copy happens on the worker thread.
/// A full queue is not an error the command must surface either — the durable
/// row is still there, so startup recovery or the next command finds it.
#[derive(Debug)]
struct ImportWakeScheduler {
    queue: Arc<MediaWakeQueue>,
}

impl ImportWakeScheduler {
    fn new(queue: Arc<MediaWakeQueue>) -> Self {
        Self { queue }
    }

    fn wake(&self, job_id: &CoreImportJobId) -> Result<(), IngestPortError> {
        match self.queue.enqueue(job_id.as_str()) {
            EnqueueOutcome::Queued | EnqueueOutcome::AlreadyPending => Ok(()),
            // Both remaining cases leave a durable queued job behind, which is
            // why neither is reported as a failure of the command that created
            // it. Losing a wake-up costs latency; losing the row would cost the
            // import.
            EnqueueOutcome::Full | EnqueueOutcome::Stopped => Ok(()),
        }
    }
}

impl ImportScheduler for ImportWakeScheduler {
    fn enqueue(&self, job_id: &CoreImportJobId) -> Result<(), IngestPortError> {
        self.wake(job_id)
    }

    fn enqueue_retry(&self, job_id: &CoreImportJobId) -> Result<(), IngestPortError> {
        self.wake(job_id)
    }
}

/// Completion notifications are intentionally only a wake-up hint. The
/// SQLite import collection revision remains the authoritative projection;
/// command handlers always re-read it after the worker drain.
#[derive(Debug, Default)]
struct ImportProjectionNotifier;

impl ImportNotificationSink for ImportProjectionNotifier {
    fn local_verified(
        &self,
        _job_id: &CoreImportJobId,
        _receipt: &ylx_transfer_core::ingest::LocalSourceReceipt,
    ) -> Result<(), IngestPortError> {
        Ok(())
    }
}

/// Real `RecordingIngestorPort` backed by `RecordingIngestExecutor` and the
/// shared `MediaStore`.
///
/// `C` is normally `crate::media::ubuntu::UbuntuMediaRuntime`. Keeping the
/// bridge generic is deliberate: the runtime owns native volume observation
/// and may evolve independently as long as it continues to satisfy the two
/// narrow core ports.
pub struct UbuntuRecordingIngestor<C, R> {
    executor: Arc<RecordingIngestExecutor<C>>,
    candidates: Arc<C>,
    root_gate: Arc<R>,
    store: Arc<Mutex<MediaStore>>,
    config: UbuntuIngestConfig,
    space: Arc<UbuntuLocalSpace>,
    scheduler: Arc<ImportWakeScheduler>,
    /// The lane's queue, shared with the scheduler above. The composition
    /// spawns the worker thread over it; commands only ever push to it.
    wake_queue: Arc<MediaWakeQueue>,
}

/// Fully preflighted import intent retained in typed core form until the
/// pipeline owner commits it. Preparing this value performs no durable
/// mutation and starts no worker.
pub struct PreparedPipelineImport {
    pub spec: ImportSpec,
    pub source: SourceRecording,
}

impl<C, R> UbuntuRecordingIngestor<C, R>
where
    C: CandidateCatalog + ArtifactSourceResolver + UbuntuDestinationGuard + Send + Sync + 'static,
    R: UbuntuLibraryRootGate,
{
    /// Construct the complete durable ingest worker graph. `runtime` must be
    /// the same object for candidate admission and artifact resolution so a
    /// candidate's scanned media generation remains fenced through copying.
    pub fn new(
        runtime: Arc<C>,
        store: Arc<Mutex<MediaStore>>,
        root_gate: Arc<R>,
        config: UbuntuIngestConfig,
    ) -> Result<Self, MediaPortError> {
        let clock: Arc<dyn IngestClock> = Arc::new(SystemIngestClock);
        let repository: Arc<dyn ImportRepository> = Arc::new(MediaStoreImportRepository::new(
            Arc::clone(&store),
            Arc::clone(&clock),
        ));
        let sources: Arc<dyn ArtifactSourceResolver> = runtime.clone();
        let space = Arc::new(UbuntuLocalSpace);
        let local_space: Arc<dyn LocalSpace> = space.clone();
        let wake_queue = MediaWakeQueue::new(super::ubuntu_workers::DEFAULT_QUEUE_CAPACITY);
        let scheduler = Arc::new(ImportWakeScheduler::new(Arc::clone(&wake_queue)));
        let import_scheduler: Arc<dyn ImportScheduler> = scheduler.clone();
        let publish_leases: Arc<dyn SourcePublishLeases> =
            Arc::new(MediaStoreSourcePublishLeases::new(Arc::clone(&store)));
        let notifications: Arc<dyn ImportNotificationSink> = Arc::new(ImportProjectionNotifier);

        let executor = RecordingIngestExecutor::new(
            config.executor_config(),
            Arc::clone(&runtime),
            repository,
            sources,
            local_space,
            import_scheduler,
            clock,
            publish_leases,
            notifications,
        )
        .map_err(|error| executor_error("construct recording ingestor", error))?;

        Ok(Self {
            executor: Arc::new(executor),
            candidates: runtime,
            root_gate,
            store,
            config,
            space,
            scheduler,
            wake_queue,
        })
    }

    /// The import lane's wake queue, so the composition can spawn exactly one
    /// worker thread over it and stop it during shutdown.
    #[must_use]
    pub fn wake_queue(&self) -> Arc<MediaWakeQueue> {
        Arc::clone(&self.wake_queue)
    }

    /// Hold the composition's root-switch fence for one complete synchronous
    /// operation. Callers must not return deferred work from the callback.
    pub fn with_library_root<T>(&self, operation: impl FnOnce(&Path) -> T) -> T {
        self.root_gate.with_library_root(operation)
    }

    /// Read the full durable import collection using its SQLite collection
    /// revision as the application projection version.
    pub fn imports_projection(&self) -> Result<Observed<Vec<ImportJob>>, MediaPortError> {
        let collection = lock(&self.store)
            .import_projection()
            .map_err(|error| store_error("read import projection", error))?;
        ensure_wire_safe_u64("import collection revision", collection.revision)?;
        let jobs = collection
            .items
            .iter()
            .map(map_import_job)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Observed::new(collection.revision, jobs))
    }

    /// Synchronously resume durable imports that were in an active worker
    /// phase before restart. Waiting, paused, cancelled, and retry-waiting
    /// jobs retain their explicit durable intent and are not silently run.
    ///
    /// A card that disappeared while a job was active is not treated as a
    /// worker error here. The core executor resolves its durable locator in
    /// preflight/copy and converts an unavailable resolver result into the
    /// durable `waiting_for_media` state before this method returns.
    pub fn recover_pending_imports(&self) -> Result<Observed<Vec<ImportJob>>, MediaPortError> {
        self.with_library_root(|library_root| self.recover_pending_imports_at(library_root))
    }

    fn recover_pending_imports_at(
        &self,
        library_root: &Path,
    ) -> Result<Observed<Vec<ImportJob>>, MediaPortError> {
        self.candidates.ensure_pc_destination(library_root)?;
        let recoverable = lock(&self.store)
            .list_recoverable_imports()
            .map_err(|error| store_error("read import recovery state", error))?;
        for item in recoverable {
            match item {
                Recoverable::Ready(stored) if should_resume_on_worker(stored.snapshot.state()) => {
                    // Recovery only re-establishes intent. The background
                    // lane performs the work, so startup is not held open by
                    // an interrupted multi-gigabyte copy.
                    self.scheduler
                        .enqueue(stored.spec.job_id())
                        .map_err(|error| scheduler_error("recover import", error))?;
                }
                Recoverable::Ready(_) => {}
                Recoverable::Blocked(blocked) => {
                    return Err(MediaPortError::new(
                        MediaErrorCode::ResourceStuck,
                        format!(
                            "cannot safely recover import {}: {:?}: {}",
                            blocked.job_id, blocked.reason, blocked.detail
                        ),
                    )
                    .with_retryable(false));
                }
            }
        }
        self.imports_projection()
    }

    /// Resolve policy, local space, candidate freshness and source admission
    /// without creating an import row. The pipeline adapter uses the returned
    /// typed values for its atomic import+pipeline transaction.
    pub fn prepare_import_for_pipeline_at(
        &self,
        candidate_id: CandidateId,
        approve_unsigned: bool,
        library_root: &Path,
    ) -> Result<PreparedPipelineImport, MediaPortError> {
        self.candidates.ensure_pc_destination(library_root)?;
        let candidate_id = CoreCandidateId::parse(candidate_id.as_str()).map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::CandidateNotFound,
                format!("candidate id is invalid: {error}"),
            )
            .with_retryable(false)
        })?;
        let policy = self.policy_for(approve_unsigned, library_root)?;
        if self
            .candidates
            .candidate(&candidate_id)
            .map_err(|error| candidate_catalog_error("inspect import candidate", error))?
            .is_none()
        {
            return Err(MediaPortError::new(
                MediaErrorCode::CandidateNotFound,
                "scan candidate was not found or is stale",
            )
            .with_retryable(false));
        }
        let source = self
            .candidates
            .admit(&candidate_id, &policy)
            .map_err(|error| candidate_catalog_error("admit import candidate", error))?;
        let spec = ImportSpec::new(CoreImportJobId::new(), source.clone(), policy)
            .map_err(import_spec_error)?;
        Ok(PreparedPipelineImport { spec, source })
    }

    /// Best-effort execution after the import and owning pipeline are already
    /// committed. A worker/scheduler failure is intentionally represented by
    /// the latest durable queued/waiting projection so the caller can publish
    /// the mutation and startup recovery can retry it; it is never returned as
    /// an error that would hide the committed intent.
    pub fn continue_import_for_pipeline_at(
        &self,
        stored: &StoredImportJob,
        source: &SourceRecording,
        library_root: &Path,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        let job_id = stored.spec.job_id();
        // Waking the lane is best effort by design: the pipeline and the import
        // row are already committed, so a failure here delays the copy rather
        // than losing it. Reporting it as an error would hide durable intent
        // that the caller must still be able to see.
        match stored.snapshot.state() {
            CoreImportJobState::WaitingForMedia { .. } => {
                drop(self.executor.source_available(job_id, source, library_root));
            }
            state if should_resume_on_worker(state) => {
                drop(self.scheduler.enqueue(job_id));
            }
            _ => {}
        }
        self.import_effect(job_id)
    }

    fn policy_for(
        &self,
        approve_unsigned: bool,
        library_root: &Path,
    ) -> Result<ImportPolicy, MediaPortError> {
        let available = self
            .space
            .available_bytes(library_root)
            .map_err(|error| scheduler_error("check local import space", error))?;
        let unsigned = if approve_unsigned {
            // The Linux runtime issues a typed admission receipt only for an
            // explicit user approval; ImportSpec checks that receipt again.
            UnsignedImportPolicy::RequireAdmissionReceipt
        } else {
            UnsignedImportPolicy::Reject
        };
        Ok(ImportPolicy::new(
            unsigned,
            available,
            self.config.safety_margin_bytes,
        ))
    }

    fn start_import_effect_at(
        &self,
        request: StartImportRequest,
        library_root: &Path,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        self.candidates.ensure_pc_destination(library_root)?;
        let candidate_id =
            CoreCandidateId::parse(request.candidate_id.as_str()).map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::CandidateNotFound,
                    format!("candidate id is invalid: {error}"),
                )
                .with_retryable(false)
            })?;
        let policy = self.policy_for(request.approve_unsigned, library_root)?;
        let outcome = self
            .executor
            .start_import_at(candidate_id, policy, library_root)
            .map_err(|error| ingest_error("start import", error))?;
        let job_id = match outcome {
            ylx_transfer_core::ingest::ImportStartOutcome::Created { job_id }
            | ylx_transfer_core::ingest::ImportStartOutcome::Existing { job_id } => job_id,
            ylx_transfer_core::ingest::ImportStartOutcome::Conflict {
                existing_job_id,
                reason,
            } => {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    format!(
                        "candidate conflicts with existing import {}: {reason}",
                        existing_job_id.as_str()
                    ),
                )
                .with_retryable(false));
            }
        };
        // The durable job exists and is queued. Returning now is what keeps a
        // large session import from holding the Tauri command open.
        self.import_effect(&job_id)
    }

    pub fn command_import_effect_at(
        &self,
        job_id: ImportJobId,
        command: MediaJobCommand,
        library_root: &Path,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        self.candidates.ensure_pc_destination(library_root)?;
        let core_job_id = CoreImportJobId::parse(job_id.as_str()).map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::OperationConflict,
                format!("import job id is invalid: {error}"),
            )
            .with_retryable(false)
        })?;
        let command = match command {
            MediaJobCommand::Pause => CoreImportControlCommand::Pause,
            MediaJobCommand::Resume => CoreImportControlCommand::Resume,
            MediaJobCommand::Cancel => CoreImportControlCommand::Cancel,
            MediaJobCommand::Retry => CoreImportControlCommand::Retry,
        };
        match CoreRecordingIngestor::command(&*self.executor, core_job_id.clone(), command)
            .map_err(|error| ingest_error("command import", error))?
        {
            CoreImportCommandOutcome::Rejected(reason) => {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    format!("import command was rejected: {reason:?}"),
                )
                .with_retryable(false));
            }
            CoreImportCommandOutcome::Applied | CoreImportCommandOutcome::NoChange => {}
        }
        // Pause/cancel/resume/retry are desired-state writes plus a wake-up.
        // They deliberately do not run the worker inline, so a pause issued
        // during a copy is answered immediately instead of queueing behind it.
        self.import_effect(&core_job_id)
    }

    /// Run one dequeued import to quiescence on the background lane.
    ///
    /// This is the only place that performs copy I/O. It takes a **shared**
    /// library-root lease rather than the exclusive callback gate, so a
    /// multi-gigabyte copy no longer blocks pause, cancel, or another lane.
    /// The lease is re-asserted before the executor starts, and its generation
    /// fence means a root switch that slipped through invalidates the operation
    /// instead of writing into the new root with the old root's assumptions.
    ///
    /// Failures are not propagated to a caller because there is no caller: the
    /// authoritative outcome is the durable job row, which the executor has
    /// already updated. They are surfaced through the projection instead.
    pub fn run_import_once(&self, job_id: &str) -> Result<(), MediaPortError> {
        let Ok(job_id) = CoreImportJobId::parse(job_id) else {
            // A queue entry that is not a job id cannot be acted on and cannot
            // be repaired by retrying it.
            return Ok(());
        };
        let lease = self
            .root_gate
            .acquire_shared_library_root("media_import_worker")?;
        lease.assert_current()?;
        let destination_fence = self.candidates.destination_fence(lease.root())?;

        for _ in 0..MAXIMUM_WORKER_TURNS {
            // Re-assert at every executor turn: the executor itself checks the
            // media generation per chunk, and this is the matching check for
            // the destination side.
            lease.assert_current()?;
            let root_fence = || {
                lease
                    .assert_current()
                    .map_err(|error| RecordingIngestorError::Filesystem(error.to_string()))?;
                self.candidates
                    .assert_pc_destination(lease.root(), &destination_fence)
                    .map_err(|error| RecordingIngestorError::Filesystem(error.to_string()))
            };
            self.executor
                .run_to_quiescence_fenced(&job_id, lease.root(), &root_fence)
                .map_err(|error| executor_error("run recording import", error))?;
            // `run_to_quiescence` re-schedules the job when it has more work
            // to do; anything still pending is picked up by the next loop turn.
            if self.wake_queue.take(job_id.as_str()) {
                continue;
            }
            return Ok(());
        }
        Err(MediaPortError::new(
            MediaErrorCode::ResourceStuck,
            "recording import repeatedly scheduled itself without reaching quiescence",
        )
        .with_retryable(true))
    }

    fn import_effect(
        &self,
        core_job_id: &CoreImportJobId,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        let imports = self.imports_projection()?;
        let app_job_id = ImportJobId::new(core_job_id.as_str());
        let job = imports
            .value
            .iter()
            .find(|job| job.id == app_job_id)
            .cloned()
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    format!(
                        "durable import {} is missing from its projection",
                        core_job_id
                    ),
                )
                .with_retryable(true)
            })?;
        Ok(MediaEffect::new(
            job,
            MediaProjectionDelta {
                imports: Some(imports),
                ..MediaProjectionDelta::default()
            },
        ))
    }
}

impl<C, R> RecordingIngestorPort for UbuntuRecordingIngestor<C, R>
where
    C: CandidateCatalog + ArtifactSourceResolver + UbuntuDestinationGuard + Send + Sync + 'static,
    R: UbuntuLibraryRootGate,
{
    fn start_import(
        &self,
        request: StartImportRequest,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        self.with_library_root(|library_root| self.start_import_effect_at(request, library_root))
    }

    fn command_import(
        &self,
        job_id: ImportJobId,
        command: MediaJobCommand,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        self.with_library_root(|library_root| {
            self.command_import_effect_at(job_id, command, library_root)
        })
    }
}

fn should_resume_on_worker(state: &CoreImportJobState) -> bool {
    matches!(
        state,
        CoreImportJobState::Queued
            | CoreImportJobState::Preflighting
            | CoreImportJobState::Copying
            | CoreImportJobState::Verifying
            | CoreImportJobState::Committing
    )
}

fn map_import_job(stored: &StoredImportJob) -> Result<ImportJob, MediaPortError> {
    let source = stored.spec.source();
    let snapshot = &stored.snapshot;
    let copied_bytes = snapshot.durable_bytes();
    let total_bytes = stored.spec.total_bytes();
    ensure_wire_safe_u64("import copied bytes", copied_bytes)?;
    ensure_wire_safe_u64("import total bytes", total_bytes)?;
    let current_locator = &stored.locator.locator;
    let media_id = current_locator
        .media_generation_id()
        .map(|generation| MediaId::new(generation.as_str()))
        .unwrap_or_else(|| MediaId::new(format!("source:{}", current_locator.source_id())));
    let current_file = stored
        .spec
        .files()
        .iter()
        .zip(snapshot.checkpoints())
        .find(|(_, checkpoint)| !checkpoint.verified())
        .map(|(file, _)| file.relative_path().as_str().to_string());

    Ok(ImportJob {
        id: ImportJobId::new(snapshot.job_id().as_str()),
        candidate_id: CandidateId::new(source.candidate_id().as_str()),
        media_id,
        // A candidate is not a durable source identity. Only publish a
        // source id once verification supplied a stable content revision.
        source_id: snapshot
            .content_revision()
            .map(|revision| SourceId::new(revision.as_str())),
        state: map_import_state(snapshot.state()),
        desired_run_state: map_desired_state(snapshot.desired_state()),
        progress: ImportProgress {
            current_file,
            copied_bytes,
            total_bytes,
            throughput_bytes_per_second: None,
            eta_seconds: None,
        },
        failure: snapshot.failure().map(map_import_failure),
        retry_at: None,
        created_at: stored.created_at.clone(),
        updated_at: stored.updated_at.clone(),
    })
}

fn map_import_state(state: &CoreImportJobState) -> ImportJobState {
    match state {
        CoreImportJobState::Queued => ImportJobState::Queued,
        CoreImportJobState::WaitingForMedia { .. } => ImportJobState::WaitingForMedia,
        CoreImportJobState::Preflighting => ImportJobState::Preflighting,
        CoreImportJobState::Copying => ImportJobState::Copying,
        CoreImportJobState::Verifying => ImportJobState::Verifying,
        CoreImportJobState::Committing => ImportJobState::Committing,
        CoreImportJobState::LocalVerified => ImportJobState::LocalVerified,
        CoreImportJobState::RetryWait { .. } => ImportJobState::RetryWait,
        CoreImportJobState::Pausing { .. } => ImportJobState::Pausing,
        CoreImportJobState::Paused { .. } => ImportJobState::Paused,
        CoreImportJobState::Cancelling => ImportJobState::Cancelling,
        CoreImportJobState::Cancelled => ImportJobState::Cancelled,
        CoreImportJobState::Failed => ImportJobState::Failed,
    }
}

fn map_desired_state(state: CoreImportDesiredState) -> DesiredRunState {
    match state {
        CoreImportDesiredState::Running => DesiredRunState::Run,
        CoreImportDesiredState::Paused => DesiredRunState::Paused,
        CoreImportDesiredState::Cancelled => DesiredRunState::Cancelled,
    }
}

fn map_import_failure(failure: &CoreImportFailure) -> RpcError {
    let code = match failure.code() {
        CoreImportFailureCode::SourceUnavailable => MediaErrorCode::MediaUnavailable,
        CoreImportFailureCode::MediaChanged => MediaErrorCode::MediaChanged,
        CoreImportFailureCode::UnsafePath => MediaErrorCode::UnsafePath,
        CoreImportFailureCode::PermissionDenied => MediaErrorCode::MediaUnavailable,
        CoreImportFailureCode::InsufficientLocalSpace => MediaErrorCode::InsufficientLocalSpace,
        CoreImportFailureCode::IntegrityMismatch => MediaErrorCode::IntegrityFailed,
        CoreImportFailureCode::SourceRevisionMismatch => MediaErrorCode::SourceRevisionMismatch,
        CoreImportFailureCode::CommitFailed => MediaErrorCode::ImportCommandFailed,
        CoreImportFailureCode::ResourceStuck => MediaErrorCode::ResourceStuck,
        CoreImportFailureCode::Internal => MediaErrorCode::ImportCommandFailed,
    };
    MediaPortError::new(code, failure.message())
        .with_retryable(failure.retryable())
        .into_rpc()
}

fn ingest_error(operation: &str, error: CoreIngestError) -> MediaPortError {
    let (code, retryable) = match &error {
        CoreIngestError::CandidateUnavailable => (MediaErrorCode::CandidateNotFound, false),
        CoreIngestError::JobNotFound => (MediaErrorCode::OperationConflict, false),
        CoreIngestError::PolicyApprovalRequired { .. } => {
            (MediaErrorCode::PolicyApprovalRequired, false)
        }
        CoreIngestError::Conflict { .. } => (MediaErrorCode::OperationConflict, false),
        CoreIngestError::Persistence { .. } => (MediaErrorCode::ImportStartFailed, true),
        CoreIngestError::Unavailable { .. } => (MediaErrorCode::MediaUnavailable, true),
        CoreIngestError::Internal { .. } => (MediaErrorCode::ImportStartFailed, true),
    };
    MediaPortError::new(code, format!("{operation}: {error}")).with_retryable(retryable)
}

fn candidate_catalog_error(operation: &str, error: IngestPortError) -> MediaPortError {
    let (code, retryable) = match error.code() {
        "policy_approval_required" => (MediaErrorCode::PolicyApprovalRequired, false),
        "candidate_unavailable" => (MediaErrorCode::CandidateNotFound, false),
        "unsafe_path" => (MediaErrorCode::UnsafePath, false),
        "source_unavailable" => (MediaErrorCode::MediaUnavailable, true),
        _ => (MediaErrorCode::ImportStartFailed, true),
    };
    MediaPortError::new(code, format!("{operation}: {}", error.message())).with_retryable(retryable)
}

fn import_spec_error(error: ImportSpecError) -> MediaPortError {
    let (code, retryable) = match &error {
        ImportSpecError::InsufficientLocalSpace { .. } => {
            (MediaErrorCode::InsufficientLocalSpace, true)
        }
        ImportSpecError::UnsignedRejected | ImportSpecError::UnsignedReceiptRequired => {
            (MediaErrorCode::PolicyApprovalRequired, false)
        }
        _ => (MediaErrorCode::OperationConflict, false),
    };
    MediaPortError::new(code, format!("cannot prepare durable import: {error}"))
        .with_retryable(retryable)
}

fn executor_error(operation: &str, error: RecordingIngestorError) -> MediaPortError {
    let (code, retryable) = if matches!(&error, RecordingIngestorError::WorkerStepLimit) {
        (MediaErrorCode::ResourceStuck, true)
    } else {
        (MediaErrorCode::ImportStartFailed, true)
    };
    MediaPortError::new(code, format!("{operation}: {error}")).with_retryable(retryable)
}

fn scheduler_error(operation: &str, error: IngestPortError) -> MediaPortError {
    let code = match error.code() {
        "local_space" => MediaErrorCode::InsufficientLocalSpace,
        "source_unavailable" | "scheduler_unavailable" => MediaErrorCode::MediaUnavailable,
        _ => MediaErrorCode::ImportStartFailed,
    };
    MediaPortError::new(code, format!("{operation}: {}", error.message()))
        .with_retryable(code != MediaErrorCode::OperationConflict)
}

fn store_error(
    operation: &str,
    error: ylx_transfer_core::media_store::MediaStoreError,
) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::ImportStartFailed,
        format!("{operation}: {error}"),
    )
    .with_retryable(true)
}

fn ensure_wire_safe_u64(field: &str, value: u64) -> Result<(), MediaPortError> {
    if value <= MAXIMUM_JAVASCRIPT_SAFE_INTEGER {
        return Ok(());
    }
    Err(MediaPortError::new(
        MediaErrorCode::OperationConflict,
        format!("{field} exceeds JavaScript's exact integer range"),
    )
    .with_retryable(false))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
