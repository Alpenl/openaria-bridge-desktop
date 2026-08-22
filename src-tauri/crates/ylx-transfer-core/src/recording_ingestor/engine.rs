use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::ingest::{
    classify_body_read_error, ArtifactOpenOutcome, ArtifactReadFailure, ArtifactReadRequest,
    ArtifactSource, ArtifactSourceError, CandidateId, ImportCommand, ImportCommandOutcome,
    ImportControlCommand, ImportEffect, ImportFailure, ImportFailureCode, ImportFileCheckpoint,
    ImportFileSpec, ImportJob, ImportJobError, ImportJobId, ImportJobState, ImportPolicy,
    ImportRejectReason, ImportSnapshot, ImportSpec, ImportSpecError, ImportStartOutcome,
    IngestError, InventoryDigest, LocalSourceReceipt, MediaLocator, RecordingIngestor,
    SafeRelativePath, ScanRequest, ScanSnapshot, SourceArtifactId, SourceProvenance,
    SourceRecording,
};
use crate::library::artifact::{ArtifactInspector, ArtifactStatus, ExpectedArtifact};
use crate::library::download::{recover_resume_offset, DownloadJournal};
use crate::library::staging::{PublishOutcome, RevisionId, SessionManifest, SessionStaging};

use super::ports::{
    ArtifactSourceResolver, CandidateCatalog, CompareAndSwapOutcome, CreateStoredImportOutcome,
    ImportNotificationSink, ImportRepository, ImportScheduler, IngestClock, IngestPortError,
    LocalSpace, ResolvedArtifactSource, SourcePublishLeases, StoredImport,
};
use super::reader_gate::{
    lock, JobControl, JobControlRegistry, PhysicalMediaKey, ReaderGateRegistry,
};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAXIMUM_COMMAND_CAS_ATTEMPTS: usize = 8;

#[derive(Debug, Clone)]
pub struct RecordingIngestConfig {
    pub checkpoint_interval_bytes: u64,
    pub derivation_working_set_reserve_bytes: u64,
    pub maximum_worker_steps: usize,
}

impl RecordingIngestConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkpoint_interval_bytes: 256 * 1024,
            derivation_working_set_reserve_bytes: 0,
            maximum_worker_steps: 32,
        }
    }

    fn validate(&self) -> Result<(), RecordingIngestorError> {
        if self.checkpoint_interval_bytes == 0 {
            return Err(RecordingIngestorError::InvalidConfiguration(
                "checkpoint interval must be greater than zero".to_string(),
            ));
        }
        if self.maximum_worker_steps == 0 {
            return Err(RecordingIngestorError::InvalidConfiguration(
                "maximum worker steps must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for RecordingIngestConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestRunOutcome {
    Progressed(ImportSnapshot),
    WaitingForMedia(ImportSnapshot),
    Paused(ImportSnapshot),
    RetryWaiting(ImportSnapshot),
    Stopped(ImportSnapshot),
    Terminal(ImportSnapshot),
}

#[derive(Debug, thiserror::Error)]
pub enum RecordingIngestorError {
    #[error(transparent)]
    Port(#[from] IngestPortError),
    #[error(transparent)]
    Spec(#[from] ImportSpecError),
    #[error(transparent)]
    Job(#[from] ImportJobError),
    #[error("import job {0} was not found")]
    JobNotFound(String),
    #[error("scan candidate {0} was not found or is stale")]
    CandidateUnavailable(String),
    #[error("import command was rejected: {0:?}")]
    CommandRejected(ImportRejectReason),
    #[error("import snapshot lost its expected-version compare-and-swap")]
    PersistenceConflict,
    #[error("invalid recording-ingest configuration: {0}")]
    InvalidConfiguration(String),
    #[error("filesystem operation failed: {0}")]
    Filesystem(String),
    #[error("staged publication failed: {0}")]
    Publication(String),
    #[error("source protocol failed: {0}")]
    SourceProtocol(String),
    #[error("worker exceeded its bounded transition loop")]
    WorkerStepLimit,
}

pub struct RecordingIngestExecutor<C> {
    config: RecordingIngestConfig,
    candidates: Arc<C>,
    repository: Arc<dyn ImportRepository>,
    sources: Arc<dyn ArtifactSourceResolver>,
    space: Arc<dyn LocalSpace>,
    scheduler: Arc<dyn ImportScheduler>,
    clock: Arc<dyn IngestClock>,
    publish_leases: Arc<dyn SourcePublishLeases>,
    notifications: Arc<dyn ImportNotificationSink>,
    reader_gates: ReaderGateRegistry,
    job_controls: JobControlRegistry,
}

impl<C> RecordingIngestExecutor<C>
where
    C: CandidateCatalog,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: RecordingIngestConfig,
        candidates: Arc<C>,
        repository: Arc<dyn ImportRepository>,
        sources: Arc<dyn ArtifactSourceResolver>,
        space: Arc<dyn LocalSpace>,
        scheduler: Arc<dyn ImportScheduler>,
        clock: Arc<dyn IngestClock>,
        publish_leases: Arc<dyn SourcePublishLeases>,
        notifications: Arc<dyn ImportNotificationSink>,
    ) -> Result<Self, RecordingIngestorError> {
        config.validate()?;
        Ok(Self {
            config,
            candidates,
            repository,
            sources,
            space,
            scheduler,
            clock,
            publish_leases,
            notifications,
            reader_gates: ReaderGateRegistry::default(),
            job_controls: JobControlRegistry::default(),
        })
    }

    pub fn run_to_quiescence(
        &self,
        job_id: &ImportJobId,
        library_root: &Path,
    ) -> Result<IngestRunOutcome, RecordingIngestorError> {
        self.run_to_quiescence_fenced(job_id, library_root, &|| Ok(()))
    }

    /// Run one import while a caller-owned destination fence is re-asserted
    /// at every filesystem stage. The core executor does not know how a
    /// platform identifies a root, so the adapter supplies this callback.
    pub fn run_to_quiescence_fenced(
        &self,
        job_id: &ImportJobId,
        library_root: &Path,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<IngestRunOutcome, RecordingIngestorError> {
        let mut copied_evidence = HashMap::new();

        for _ in 0..self.config.maximum_worker_steps {
            root_fence()?;
            let stored = self.load(job_id)?;
            let snapshot = stored.snapshot.clone();
            let control = self.job_controls.control_for(job_id);
            if control.should_stop() {
                return Ok(IngestRunOutcome::Stopped(snapshot));
            }

            match stored.snapshot.state() {
                ImportJobState::Queued => {
                    self.apply_internal(job_id, ImportCommand::Start)?;
                }
                ImportJobState::Preflighting => {
                    self.run_preflight(stored, &control, library_root, root_fence)?;
                }
                ImportJobState::Copying => {
                    let outcome = self.run_copy(stored, &control, library_root, root_fence)?;
                    copied_evidence = outcome.evidence;
                    match outcome.snapshot.state() {
                        ImportJobState::WaitingForMedia { .. } => {
                            return Ok(IngestRunOutcome::WaitingForMedia(outcome.snapshot))
                        }
                        ImportJobState::RetryWait { .. } => {
                            return Ok(IngestRunOutcome::RetryWaiting(outcome.snapshot))
                        }
                        ImportJobState::Failed
                        | ImportJobState::Cancelled
                        | ImportJobState::LocalVerified => {
                            return Ok(IngestRunOutcome::Terminal(outcome.snapshot))
                        }
                        _ => {}
                    }
                }
                ImportJobState::Verifying => {
                    self.run_verification(stored, &control, &mut copied_evidence, root_fence)?;
                }
                ImportJobState::Committing => {
                    self.run_commit(stored, &control, library_root, root_fence)?;
                }
                ImportJobState::WaitingForMedia { .. } => {
                    return Ok(IngestRunOutcome::WaitingForMedia(snapshot));
                }
                ImportJobState::Pausing { .. } | ImportJobState::Cancelling => {
                    return Ok(IngestRunOutcome::Stopped(snapshot));
                }
                ImportJobState::Paused { .. } => return Ok(IngestRunOutcome::Paused(snapshot)),
                ImportJobState::RetryWait { .. } => {
                    return Ok(IngestRunOutcome::RetryWaiting(snapshot));
                }
                ImportJobState::LocalVerified
                | ImportJobState::Cancelled
                | ImportJobState::Failed => return Ok(IngestRunOutcome::Terminal(snapshot)),
            }
        }
        Err(RecordingIngestorError::WorkerStepLimit)
    }

    /// Starts/adopts an import with an operation-scoped library root. The
    /// root is used only if an existing waiting job must discard weakly-bound
    /// staging before a replacement source is activated.
    pub fn start_import_at(
        &self,
        candidate_id: CandidateId,
        policy: ImportPolicy,
        library_root: &Path,
    ) -> Result<ImportStartOutcome, IngestError> {
        self.start_import_impl(&candidate_id, policy, Some(library_root))
            .map_err(map_engine_to_ingest)
    }

    /// Install a newly admitted locator into the same waiting job. Weak
    /// provisional identity cannot authorize byte-range continuation across
    /// acquisition fences, so its durable progress and hidden staging tree
    /// are discarded before the replacement locator becomes runnable.
    pub fn source_available(
        &self,
        job_id: &ImportJobId,
        source: &SourceRecording,
        library_root: &Path,
    ) -> Result<ImportSnapshot, RecordingIngestorError> {
        let control = self.job_controls.control_for(job_id);
        // Keep reset, staging discard and locator activation inside the
        // single-writer interval. A worker scheduled by SourceAvailable
        // cannot observe the staging tree until this guard is released.
        let _writer = control.writer();
        let stored = self.load(job_id)?;
        ensure_same_source(&stored.spec, source)?;

        if acquisition_fence_changed(&stored.locator, source.locator())
            && !has_strong_resume_identity(&stored.spec)
        {
            let reset = self.apply_external(
                job_id,
                ImportCommand::ResetProgressForSource {
                    revision_claim: source.revision_claim().clone(),
                },
            )?;
            if let ImportCommandOutcome::Rejected(reason) = reset.outcome {
                return Err(RecordingIngestorError::CommandRejected(reason));
            }

            let staging = staging_for_spec(library_root, &stored.spec)?;
            staging.discard().map_err(|error| {
                RecordingIngestorError::Filesystem(bounded_text(format!(
                    "discard staging before source replacement: {error}"
                )))
            })?;
        }

        let available = self.apply_external(
            job_id,
            ImportCommand::SourceAvailable {
                locator: source.locator().clone(),
                revision_claim: source.revision_claim().clone(),
            },
        )?;
        match available.outcome {
            ImportCommandOutcome::Applied | ImportCommandOutcome::NoChange => {
                Ok(available.snapshot)
            }
            ImportCommandOutcome::Rejected(reason) => {
                Err(RecordingIngestorError::CommandRejected(reason))
            }
        }
    }

    fn load(&self, job_id: &ImportJobId) -> Result<StoredImport, RecordingIngestorError> {
        self.repository
            .load_import(job_id)?
            .ok_or_else(|| RecordingIngestorError::JobNotFound(job_id.as_str().to_string()))
    }

    fn start_import_impl(
        &self,
        candidate_id: &CandidateId,
        policy: ImportPolicy,
        library_root: Option<&Path>,
    ) -> Result<ImportStartOutcome, RecordingIngestorError> {
        if self.candidates.candidate(candidate_id)?.is_none() {
            return Err(RecordingIngestorError::CandidateUnavailable(
                candidate_id.as_str().to_string(),
            ));
        }
        let source = self.candidates.admit(candidate_id, &policy)?;
        let spec = ImportSpec::new(ImportJobId::new(), source.clone(), policy)?;
        let initial = ImportJob::new(spec.clone()).snapshot().clone();

        match self.repository.create_import(&spec, &initial)? {
            CreateStoredImportOutcome::Created(stored) => {
                if stored.spec != spec || stored.snapshot != initial {
                    return Err(RecordingIngestorError::PersistenceConflict);
                }
                let applied = self.apply_external(spec.job_id(), ImportCommand::Start)?;
                if matches!(applied.outcome, ImportCommandOutcome::Rejected(_)) {
                    return Err(RecordingIngestorError::PersistenceConflict);
                }
                Ok(ImportStartOutcome::Created {
                    job_id: spec.job_id().clone(),
                })
            }
            CreateStoredImportOutcome::Existing(stored) => {
                if matches!(
                    stored.snapshot.state(),
                    ImportJobState::WaitingForMedia { .. }
                ) && ensure_same_source(&stored.spec, &source).is_ok()
                {
                    if let Some(library_root) = library_root {
                        self.source_available(stored.spec.job_id(), &source, library_root)?;
                    }
                }
                Ok(ImportStartOutcome::Existing {
                    job_id: stored.spec.job_id().clone(),
                })
            }
            CreateStoredImportOutcome::Conflict {
                existing_job_id,
                reason,
            } => Ok(ImportStartOutcome::Conflict {
                existing_job_id,
                reason: bounded_text(reason),
            }),
        }
    }

    fn command_impl(
        &self,
        job_id: &ImportJobId,
        command: ImportControlCommand,
    ) -> Result<ImportCommandOutcome, RecordingIngestorError> {
        let applied = self.apply_external(job_id, command.into())?;
        if !matches!(applied.outcome, ImportCommandOutcome::Applied) {
            return Ok(applied.outcome);
        }

        let acknowledgement = match command {
            ImportControlCommand::Pause => Some(ImportCommand::PauseCompleted),
            ImportControlCommand::Cancel => Some(ImportCommand::CancellationCompleted),
            ImportControlCommand::Resume | ImportControlCommand::Retry => None,
        };
        let Some(acknowledgement) = acknowledgement else {
            return Ok(applied.outcome);
        };

        let control = self.job_controls.control_for(job_id);
        let _writer = control.writer();
        let acknowledged = self.apply_external(job_id, acknowledgement)?;
        match acknowledged.outcome {
            ImportCommandOutcome::Applied | ImportCommandOutcome::NoChange => Ok(applied.outcome),
            ImportCommandOutcome::Rejected(reason) => {
                Err(RecordingIngestorError::CommandRejected(reason))
            }
        }
    }

    fn apply_internal(
        &self,
        job_id: &ImportJobId,
        command: ImportCommand,
    ) -> Result<ImportSnapshot, RecordingIngestorError> {
        let applied = self.apply_external(job_id, command)?;
        Ok(applied.snapshot)
    }

    fn apply_external(
        &self,
        job_id: &ImportJobId,
        command: ImportCommand,
    ) -> Result<AppliedCommand, RecordingIngestorError> {
        let clear_stop = matches!(
            &command,
            ImportCommand::Resume | ImportCommand::Retry | ImportCommand::SourceAvailable { .. }
        );
        for _ in 0..MAXIMUM_COMMAND_CAS_ATTEMPTS {
            let stored = self.load(job_id)?;
            let expected_version = stored.snapshot.version();
            let mut aggregate = ImportJob::from_snapshot(stored.spec, stored.snapshot)?;
            let decision = aggregate.decide(command.clone());
            let outcome = decision.outcome().clone();
            let next = decision.snapshot().clone();
            let effects = decision.effects().to_vec();

            match &outcome {
                ImportCommandOutcome::NoChange | ImportCommandOutcome::Rejected(_) => {
                    return Ok(AppliedCommand {
                        outcome,
                        snapshot: next,
                    });
                }
                ImportCommandOutcome::Applied => {}
            }

            let persisted = if let Some(receipt) = effects.iter().find_map(|effect| match effect {
                ImportEffect::PublishLocalVerified { receipt } => Some(receipt),
                _ => None,
            }) {
                self.repository
                    .commit_local_verified(job_id, expected_version, &next, receipt)?
            } else {
                self.repository
                    .compare_and_swap(job_id, expected_version, &next)?
            };

            match persisted {
                CompareAndSwapOutcome::Applied(persisted) => {
                    if persisted != next {
                        return Err(RecordingIngestorError::PersistenceConflict);
                    }
                    if clear_stop {
                        self.job_controls.control_for(job_id).clear_stop();
                    }
                    self.execute_post_persist_effects(job_id, &effects)?;
                    return Ok(AppliedCommand {
                        outcome,
                        snapshot: persisted,
                    });
                }
                CompareAndSwapOutcome::Conflict(_) => continue,
                CompareAndSwapOutcome::Missing => {
                    return Err(RecordingIngestorError::JobNotFound(
                        job_id.as_str().to_string(),
                    ));
                }
            }
        }
        Err(RecordingIngestorError::PersistenceConflict)
    }

    fn execute_post_persist_effects(
        &self,
        job_id: &ImportJobId,
        effects: &[ImportEffect],
    ) -> Result<(), RecordingIngestorError> {
        for effect in effects {
            match effect {
                ImportEffect::PersistSnapshot => {}
                ImportEffect::CancelIo => {
                    self.job_controls.control_for(job_id).request_stop();
                }
                ImportEffect::Schedule
                | ImportEffect::StartPreflight { .. }
                | ImportEffect::StartCopy { .. }
                | ImportEffect::StartVerification
                | ImportEffect::StartCommit { .. } => self.scheduler.enqueue(job_id)?,
                ImportEffect::ScheduleRetry => self.scheduler.enqueue_retry(job_id)?,
                ImportEffect::PublishLocalVerified { receipt } => {
                    self.notifications.local_verified(job_id, receipt)?;
                }
            }
        }
        Ok(())
    }

    fn run_preflight(
        &self,
        stored: StoredImport,
        control: &Arc<JobControl>,
        library_root: &Path,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<ImportSnapshot, RecordingIngestorError> {
        root_fence()?;
        let Some(locator) = stored.snapshot.active_locator().cloned() else {
            return self.apply_internal(stored.spec.job_id(), ImportCommand::SourceUnavailable);
        };
        let media_gate =
            PhysicalMediaKey::from_locator(&locator).map(|key| self.reader_gates.gate_for(&key));
        let _media_reader = media_gate.as_ref().map(|gate| lock(gate));
        let _writer = control.writer();
        if control.should_stop() {
            return Ok(self.load(stored.spec.job_id())?.snapshot);
        }

        let fresh = self.load(stored.spec.job_id())?;
        if !matches!(fresh.snapshot.state(), ImportJobState::Preflighting) {
            return Ok(fresh.snapshot);
        }
        if fresh.snapshot.active_locator() != Some(&locator) {
            // A source-switch command won the durable CAS while this worker
            // was waiting for the physical-reader gate. Release this old
            // gate and let the next bounded step acquire the new one.
            return Ok(fresh.snapshot);
        }
        let Some(locator) = fresh.snapshot.active_locator().cloned() else {
            return self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable);
        };
        root_fence()?;

        let remaining_source = fresh
            .spec
            .total_bytes()
            .saturating_sub(fresh.snapshot.durable_bytes());
        let required = remaining_source
            .checked_add(self.config.derivation_working_set_reserve_bytes)
            .and_then(|bytes| bytes.checked_add(fresh.spec.policy().safety_margin_bytes()));
        let Some(required) = required else {
            return self.apply_failure(
                fresh.spec.job_id(),
                ImportFailureCode::InsufficientLocalSpace,
                "local-space requirement overflowed u64",
                false,
            );
        };
        let available = match self.space.available_bytes(library_root) {
            Ok(available) => available.min(fresh.spec.policy().local_space_budget_bytes()),
            Err(error) => {
                return self.apply_failure(
                    fresh.spec.job_id(),
                    ImportFailureCode::Internal,
                    format!("local-space preflight failed: {}", error.message()),
                    true,
                )
            }
        };
        if available < required {
            return self.apply_failure(
                fresh.spec.job_id(),
                ImportFailureCode::InsufficientLocalSpace,
                format!("local import needs {required} bytes but {available} are available"),
                true,
            );
        }

        let resolved = match self.sources.resolve(&locator) {
            Ok(resolved) => resolved,
            Err(_) => {
                return self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable)
            }
        };
        root_fence()?;
        if !generation_matches(&locator, &resolved) {
            drop(resolved);
            return self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable);
        }
        drop(resolved);
        self.apply_internal(fresh.spec.job_id(), ImportCommand::PreflightPassed)
    }

    fn run_verification(
        &self,
        stored: StoredImport,
        control: &Arc<JobControl>,
        copied_evidence: &mut HashMap<SourceArtifactId, FileCopyEvidence>,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<ImportSnapshot, RecordingIngestorError> {
        root_fence()?;
        let _writer = control.writer();
        if control.should_stop() {
            return Ok(self.load(stored.spec.job_id())?.snapshot);
        }
        let mut fresh = self.load(stored.spec.job_id())?;
        if !matches!(fresh.snapshot.state(), ImportJobState::Verifying) {
            return Ok(fresh.snapshot);
        }

        for checkpoint in fresh.snapshot.checkpoints() {
            if let (Some(source_sha256), Some(target_sha256)) =
                (checkpoint.source_sha256(), checkpoint.target_sha256())
            {
                copied_evidence.insert(
                    checkpoint.file_id().clone(),
                    FileCopyEvidence {
                        file_id: checkpoint.file_id().clone(),
                        source_sha256: source_sha256.to_string(),
                        target_sha256: target_sha256.to_string(),
                    },
                );
            }
        }

        for file in fresh.spec.files() {
            root_fence()?;
            let Some(evidence) = copied_evidence.get(file.file_id()).cloned() else {
                return self.apply_failure(
                    fresh.spec.job_id(),
                    ImportFailureCode::SourceUnavailable,
                    "copy evidence was interrupted before durable verification; retry from the source",
                    true,
                );
            };
            let checkpoint = fresh
                .snapshot
                .checkpoints()
                .iter()
                .find(|checkpoint| checkpoint.file_id() == file.file_id())
                .ok_or(RecordingIngestorError::PersistenceConflict)?;
            if checkpoint.verified() {
                continue;
            }
            fresh.snapshot = self.apply_internal(
                fresh.spec.job_id(),
                ImportCommand::FileVerified {
                    file_id: evidence.file_id,
                    source_sha256: evidence.source_sha256,
                    target_sha256: evidence.target_sha256,
                },
            )?;
            if !matches!(fresh.snapshot.state(), ImportJobState::Verifying) {
                return Ok(fresh.snapshot);
            }
        }

        fresh = self.load(fresh.spec.job_id())?;
        root_fence()?;
        let inventory_digest = inventory_digest(&fresh.spec, &fresh.snapshot)?;
        self.apply_internal(
            fresh.spec.job_id(),
            ImportCommand::VerificationPassed { inventory_digest },
        )
    }

    fn run_copy(
        &self,
        stored: StoredImport,
        control: &Arc<JobControl>,
        library_root: &Path,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<CopyPhaseOutcome, RecordingIngestorError> {
        root_fence()?;
        let Some(locator) = stored.snapshot.active_locator().cloned() else {
            let snapshot =
                self.apply_internal(stored.spec.job_id(), ImportCommand::SourceUnavailable)?;
            return Ok(CopyPhaseOutcome {
                snapshot,
                evidence: HashMap::new(),
            });
        };
        let media_gate =
            PhysicalMediaKey::from_locator(&locator).map(|key| self.reader_gates.gate_for(&key));
        let _media_reader = media_gate.as_ref().map(|gate| lock(gate));
        let _writer = control.writer();
        if control.should_stop() {
            return Ok(CopyPhaseOutcome {
                snapshot: self.load(stored.spec.job_id())?.snapshot,
                evidence: HashMap::new(),
            });
        }

        let mut fresh = self.load(stored.spec.job_id())?;
        if !matches!(fresh.snapshot.state(), ImportJobState::Copying) {
            return Ok(CopyPhaseOutcome {
                snapshot: fresh.snapshot,
                evidence: HashMap::new(),
            });
        }
        if fresh.snapshot.active_locator() != Some(&locator) {
            return Ok(CopyPhaseOutcome {
                snapshot: fresh.snapshot,
                evidence: HashMap::new(),
            });
        }
        let Some(locator) = fresh.snapshot.active_locator().cloned() else {
            let snapshot =
                self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable)?;
            return Ok(CopyPhaseOutcome {
                snapshot,
                evidence: HashMap::new(),
            });
        };
        let resolved = match self.sources.resolve(&locator) {
            Ok(resolved) if generation_matches(&locator, &resolved) => resolved,
            Ok(resolved) => {
                drop(resolved);
                let snapshot =
                    self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable)?;
                return Ok(CopyPhaseOutcome {
                    snapshot,
                    evidence: HashMap::new(),
                });
            }
            Err(_) => {
                let snapshot =
                    self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable)?;
                return Ok(CopyPhaseOutcome {
                    snapshot,
                    evidence: HashMap::new(),
                });
            }
        };
        root_fence()?;

        let staging = staging_for_spec(library_root, &fresh.spec)?;
        root_fence()?;
        staging
            .prepare()
            .map_err(|error| RecordingIngestorError::Filesystem(bounded_text(error.to_string())))?;
        let mut evidence = HashMap::new();

        let files = fresh.spec.files().to_vec();
        for file in &files {
            root_fence()?;
            if control.should_stop() {
                return Ok(CopyPhaseOutcome {
                    snapshot: self.load(fresh.spec.job_id())?.snapshot,
                    evidence,
                });
            }
            fresh = self.load(fresh.spec.job_id())?;
            if !matches!(fresh.snapshot.state(), ImportJobState::Copying) {
                return Ok(CopyPhaseOutcome {
                    snapshot: fresh.snapshot,
                    evidence,
                });
            }
            let checkpoint = fresh
                .snapshot
                .checkpoints()
                .iter()
                .find(|checkpoint| checkpoint.file_id() == file.file_id())
                .cloned()
                .ok_or(RecordingIngestorError::PersistenceConflict)?;
            if checkpoint.verified() {
                evidence.insert(file.file_id().clone(), checkpoint_evidence(&checkpoint)?);
                continue;
            }

            match self.copy_one_file(
                &fresh.spec,
                &staging,
                &resolved,
                &locator,
                file,
                &checkpoint,
                control,
                root_fence,
            ) {
                Ok(file_evidence) => {
                    evidence.insert(file.file_id().clone(), file_evidence);
                }
                Err(PhaseFailure::Stopped) => {
                    return Ok(CopyPhaseOutcome {
                        snapshot: self.load(fresh.spec.job_id())?.snapshot,
                        evidence,
                    });
                }
                Err(PhaseFailure::WaitingForSource) => {
                    drop(resolved);
                    let snapshot =
                        self.apply_internal(fresh.spec.job_id(), ImportCommand::SourceUnavailable)?;
                    return Ok(CopyPhaseOutcome { snapshot, evidence });
                }
                Err(PhaseFailure::Failure {
                    code,
                    message,
                    retryable,
                }) => {
                    drop(resolved);
                    let snapshot =
                        self.apply_failure(fresh.spec.job_id(), code, message, retryable)?;
                    return Ok(CopyPhaseOutcome { snapshot, evidence });
                }
                Err(PhaseFailure::Engine(error)) => return Err(error),
            }
        }

        drop(resolved);
        let snapshot = self.apply_internal(fresh.spec.job_id(), ImportCommand::CopyFinished)?;
        Ok(CopyPhaseOutcome { snapshot, evidence })
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_one_file(
        &self,
        spec: &ImportSpec,
        staging: &SessionStaging,
        resolved: &ResolvedArtifactSource,
        locator: &MediaLocator,
        file: &ImportFileSpec,
        checkpoint: &ImportFileCheckpoint,
        control: &JobControl,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<FileCopyEvidence, PhaseFailure> {
        root_fence().map_err(PhaseFailure::Engine)?;
        let expected = expected_artifact(file, checkpoint);
        let inspector = ArtifactInspector::new(
            staging.file_root(),
            staging.device_id(),
            staging.session_id(),
        );
        let existing = inspector.inspect(&expected);
        let target = existing.target.ok_or_else(|| PhaseFailure::Failure {
            code: ImportFailureCode::UnsafePath,
            message: "staging target path could not be derived safely".to_string(),
            retryable: false,
        })?;
        ensure_staging_parent(staging, file.relative_path())?;

        let discard_unbound_target = matches!(&existing.status, ArtifactStatus::Verified)
            && expected.expected_sha256_hex.is_none()
            && checkpoint.durable_offset() == 0;
        if discard_unbound_target {
            // A progress reset is the durable authority. If a crash made an
            // un-hashed target reappear after staging cleanup, size alone
            // must not let bytes from the previous acquisition fence survive.
            remove_invalid_staged_target(&target)?;
        } else if matches!(&existing.status, ArtifactStatus::Verified)
            && expected.expected_sha256_hex.is_some()
        {
            let digest = expected
                .expected_sha256_hex
                .expect("checked expected digest presence");
            let source_digest = file
                .expected_source_sha256()
                .or(checkpoint.source_sha256())
                .unwrap_or(digest.as_str())
                .to_string();
            self.persist_checkpoint(spec.job_id(), file.file_id(), file.expected_size(), control)?;
            return Ok(FileCopyEvidence {
                file_id: file.file_id().clone(),
                source_sha256: source_digest,
                target_sha256: digest,
            });
        }

        if !discard_unbound_target && matches!(&existing.status, ArtifactStatus::Verified) {
            let source_sha256 = hash_source_exact(
                resolved.source.as_ref(),
                spec,
                locator,
                file,
                control,
                root_fence,
            )?;
            root_fence().map_err(PhaseFailure::Engine)?;
            let target_sha256 = sha256_file(&target)?;
            verify_digests(file, &source_sha256, &target_sha256)?;
            self.persist_checkpoint(spec.job_id(), file.file_id(), file.expected_size(), control)?;
            return Ok(FileCopyEvidence {
                file_id: file.file_id().clone(),
                source_sha256,
                target_sha256,
            });
        }

        if matches!(&existing.status, ArtifactStatus::Invalid { .. }) {
            remove_invalid_staged_target(&target)?;
        }

        let part = part_path(&target);
        let journal = journal_path(&target);
        reject_link(&part)?;
        reject_link(&journal)?;
        let sidecar = DownloadJournal::read(&journal)
            .map_err(|error| PhaseFailure::filesystem(error.to_string()))?;
        let journal_offset = recover_resume_offset(&part, sidecar.as_ref())
            .map_err(|error| PhaseFailure::filesystem(error.to_string()))?;
        let durable_offset = checkpoint
            .durable_offset()
            .min(journal_offset)
            .min(file.expected_size());
        truncate_partial(&part, durable_offset)?;

        let (source_sha256, target_sha256) = self.copy_source_to_partial(
            spec,
            resolved.source.as_ref(),
            locator,
            file,
            &part,
            &journal,
            durable_offset,
            control,
            root_fence,
        )?;
        verify_digests(file, &source_sha256, &target_sha256)?;
        if control.should_stop() {
            return Err(PhaseFailure::Stopped);
        }
        root_fence().map_err(PhaseFailure::Engine)?;
        fs::rename(&part, &target)
            .map_err(|error| PhaseFailure::filesystem(format!("commit partial: {error}")))?;
        fsync_parent(&target)?;
        let _ = fs::remove_file(&journal);
        Ok(FileCopyEvidence {
            file_id: file.file_id().clone(),
            source_sha256,
            target_sha256,
        })
    }

    fn persist_checkpoint(
        &self,
        job_id: &ImportJobId,
        file_id: &SourceArtifactId,
        durable_offset: u64,
        control: &JobControl,
    ) -> Result<(), PhaseFailure> {
        if control.should_stop() {
            return Err(PhaseFailure::Stopped);
        }
        let snapshot = self
            .apply_internal(
                job_id,
                ImportCommand::CopyCheckpoint {
                    file_id: file_id.clone(),
                    durable_offset,
                },
            )
            .map_err(PhaseFailure::Engine)?;
        if !matches!(snapshot.state(), ImportJobState::Copying) {
            return Err(PhaseFailure::Stopped);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_source_to_partial(
        &self,
        spec: &ImportSpec,
        source: &dyn ArtifactSource,
        locator: &MediaLocator,
        file: &ImportFileSpec,
        part: &Path,
        journal_path: &Path,
        durable_offset: u64,
        control: &JobControl,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<(String, String), PhaseFailure> {
        root_fence().map_err(PhaseFailure::Engine)?;
        let mut source_hasher = Sha256::new();
        if durable_offset > 0 {
            let source_context = SourceReadContext {
                source,
                spec,
                locator,
                file,
                control,
                root_fence,
            };
            hash_source_prefix(&source_context, durable_offset, &mut source_hasher)?;
        }

        root_fence().map_err(PhaseFailure::Engine)?;
        let mut target = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(part)
            .map_err(|error| PhaseFailure::filesystem(format!("open partial: {error}")))?;
        target
            .seek(SeekFrom::Start(durable_offset))
            .map_err(|error| PhaseFailure::filesystem(format!("seek partial: {error}")))?;
        let journal_digest = journal_binding_digest(spec, file);
        let mut offset = durable_offset;
        let mut since_checkpoint = 0u64;
        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];

        while offset < file.expected_size() {
            root_fence().map_err(PhaseFailure::Engine)?;
            if control.should_stop() {
                return Err(PhaseFailure::Stopped);
            }
            let mut chunk = open_source_chunk(source, spec, locator, file, offset)?;
            if chunk.start == 0 && offset > 0 {
                // A 200 response to a resumed request is not appendable. Keep
                // the durable partial intact and wait for a locator that can
                // honor the range contract.
                return Err(PhaseFailure::WaitingForSource);
            }
            while chunk.remaining() > 0 {
                root_fence().map_err(PhaseFailure::Engine)?;
                if control.should_stop() {
                    return Err(PhaseFailure::Stopped);
                }
                let limit = usize::try_from(chunk.remaining().min(buffer.len() as u64))
                    .expect("buffer-bounded read length fits usize");
                let read = chunk
                    .body
                    .read(&mut buffer[..limit])
                    .map_err(classify_body_failure)?;
                if read == 0 {
                    return Err(PhaseFailure::WaitingForSource);
                }
                source_hasher.update(&buffer[..read]);
                target
                    .write_all(&buffer[..read])
                    .map_err(|error| PhaseFailure::filesystem(format!("write partial: {error}")))?;
                chunk.consumed = chunk.consumed.saturating_add(read as u64);
                offset = offset.saturating_add(read as u64);
                since_checkpoint = since_checkpoint.saturating_add(read as u64);

                if since_checkpoint >= self.config.checkpoint_interval_bytes {
                    target.sync_all().map_err(|error| {
                        PhaseFailure::filesystem(format!("flush partial: {error}"))
                    })?;
                    DownloadJournal::advance(
                        journal_path,
                        part,
                        &DownloadJournal {
                            confirmed_offset: offset,
                            expected_size: file.expected_size(),
                            expected_sha256_hex: journal_digest.clone(),
                            etag: None,
                        },
                    )
                    .map_err(|error| PhaseFailure::filesystem(error.to_string()))?;
                    self.persist_checkpoint(spec.job_id(), file.file_id(), offset, control)?;
                    since_checkpoint = 0;
                }
            }
        }

        target
            .sync_all()
            .map_err(|error| PhaseFailure::filesystem(format!("flush partial: {error}")))?;
        DownloadJournal::advance(
            journal_path,
            part,
            &DownloadJournal {
                confirmed_offset: offset,
                expected_size: file.expected_size(),
                expected_sha256_hex: journal_digest,
                etag: None,
            },
        )
        .map_err(|error| PhaseFailure::filesystem(error.to_string()))?;
        self.persist_checkpoint(spec.job_id(), file.file_id(), offset, control)?;
        drop(target);

        let source_sha256 = format!("{:x}", source_hasher.finalize());
        // This is intentionally a new read handle after the writer was
        // flushed and closed. It is independent target evidence, not a hash
        // recycled from the source/copy buffer.
        let target_sha256 = sha256_file(part)?;
        Ok((source_sha256, target_sha256))
    }

    fn run_commit(
        &self,
        stored: StoredImport,
        control: &Arc<JobControl>,
        library_root: &Path,
        root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
    ) -> Result<ImportSnapshot, RecordingIngestorError> {
        root_fence()?;
        let _writer = control.writer();
        if control.should_stop() {
            return Ok(self.load(stored.spec.job_id())?.snapshot);
        }
        let fresh = self.load(stored.spec.job_id())?;
        if !matches!(fresh.snapshot.state(), ImportJobState::Committing) {
            return Ok(fresh.snapshot);
        }
        let source = fresh
            .snapshot
            .verified_source()
            .cloned()
            .ok_or(RecordingIngestorError::PersistenceConflict)?;
        let source_revision = source
            .content_revision()
            .ok_or(RecordingIngestorError::PersistenceConflict)?;
        let staging = staging_for_spec(library_root, &fresh.spec)?;
        root_fence()?;
        let manifest = manifest_from_verified(&fresh.spec, &fresh.snapshot, &staging)?;
        let mut lease = self
            .publish_leases
            .acquire_exclusive(source_revision.as_str(), fresh.spec.job_id())?;
        root_fence()?;
        let sealed = staging.seal(&manifest).map_err(|error| {
            RecordingIngestorError::Publication(bounded_text(error.to_string()))
        })?;
        if control.should_stop() {
            return Ok(self.load(fresh.spec.job_id())?.snapshot);
        }
        root_fence()?;
        // The durable fencing token is checked at the last possible point
        // before the directory rename. An expired worker can seal hidden
        // staging, but it cannot make that tree visible.
        lease.assert_current()?;
        root_fence()?;
        let published = sealed.publish().map_err(|error| {
            RecordingIngestorError::Publication(bounded_text(error.to_string()))
        })?;
        let sealed_relative_path =
            SafeRelativePath::parse(format!("{}/{}", staging.device_id(), staging.session_id()))
                .map_err(|error| RecordingIngestorError::Publication(error.to_string()))?;
        let receipt = LocalSourceReceipt::new(
            &source,
            sealed_relative_path,
            match published {
                PublishOutcome::Published { revision } => {
                    format!("published:{}", revision.as_str())
                }
                PublishOutcome::AlreadyPublished { revision } => {
                    format!("replayed:{}", revision.as_str())
                }
            },
            self.clock.now_rfc3339(),
        )
        .map_err(|error| RecordingIngestorError::Publication(error.to_string()))?;
        self.apply_internal(
            fresh.spec.job_id(),
            ImportCommand::CommitSucceeded { receipt },
        )
    }

    fn apply_failure(
        &self,
        job_id: &ImportJobId,
        code: ImportFailureCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<ImportSnapshot, RecordingIngestorError> {
        let failure = ImportFailure::new(code, bounded_text(message.into()), retryable)?;
        self.apply_internal(
            job_id,
            if retryable {
                ImportCommand::RetryableFailure { failure }
            } else {
                ImportCommand::PermanentFailure { failure }
            },
        )
    }
}

#[derive(Debug)]
struct AppliedCommand {
    outcome: ImportCommandOutcome,
    snapshot: ImportSnapshot,
}

#[derive(Debug, Clone)]
struct FileCopyEvidence {
    file_id: SourceArtifactId,
    source_sha256: String,
    target_sha256: String,
}

#[derive(Debug)]
struct CopyPhaseOutcome {
    snapshot: ImportSnapshot,
    evidence: HashMap<SourceArtifactId, FileCopyEvidence>,
}

struct SourceChunk {
    start: u64,
    end_inclusive: u64,
    consumed: u64,
    body: Box<dyn Read + Send>,
}

impl SourceChunk {
    fn remaining(&self) -> u64 {
        self.end_inclusive
            .saturating_sub(self.start)
            .saturating_add(1)
            .saturating_sub(self.consumed)
    }
}

#[derive(Debug)]
enum PhaseFailure {
    Stopped,
    WaitingForSource,
    Failure {
        code: ImportFailureCode,
        message: String,
        retryable: bool,
    },
    Engine(RecordingIngestorError),
}

impl PhaseFailure {
    fn filesystem(message: impl Into<String>) -> Self {
        Self::Failure {
            code: ImportFailureCode::Internal,
            message: bounded_text(message.into()),
            retryable: true,
        }
    }
}

fn open_source_chunk(
    source: &dyn ArtifactSource,
    spec: &ImportSpec,
    locator: &MediaLocator,
    file: &ImportFileSpec,
    offset: u64,
) -> Result<SourceChunk, PhaseFailure> {
    let request = ArtifactReadRequest::new(
        file.file_id().clone(),
        spec.source().revision_claim().clone(),
        locator.media_generation_id().cloned(),
        offset,
    );
    let outcome = source
        .open(request.clone())
        .map_err(classify_open_failure)?;
    outcome
        .validate_against(&request)
        .map_err(classify_open_failure)?;

    match outcome {
        ArtifactOpenOutcome::FullFromZero {
            total_bytes, body, ..
        } => {
            if total_bytes != file.expected_size() || total_bytes == 0 {
                return Err(PhaseFailure::WaitingForSource);
            }
            Ok(SourceChunk {
                start: 0,
                end_inclusive: total_bytes - 1,
                consumed: 0,
                body,
            })
        }
        ArtifactOpenOutcome::Partial {
            start,
            end_inclusive,
            total_bytes,
            body,
            ..
        } => {
            if total_bytes != file.expected_size() {
                return Err(PhaseFailure::WaitingForSource);
            }
            Ok(SourceChunk {
                start,
                end_inclusive,
                consumed: 0,
                body,
            })
        }
        ArtifactOpenOutcome::EndOfFile { total_bytes, .. }
            if offset == total_bytes && total_bytes == file.expected_size() =>
        {
            Err(PhaseFailure::WaitingForSource)
        }
        ArtifactOpenOutcome::EndOfFile { .. }
        | ArtifactOpenOutcome::PreconditionFailed { .. }
        | ArtifactOpenOutcome::NotSatisfiable { .. }
        | ArtifactOpenOutcome::MediaChanged { .. } => Err(PhaseFailure::WaitingForSource),
    }
}

struct SourceReadContext<'a> {
    source: &'a dyn ArtifactSource,
    spec: &'a ImportSpec,
    locator: &'a MediaLocator,
    file: &'a ImportFileSpec,
    control: &'a JobControl,
    root_fence: &'a dyn Fn() -> Result<(), RecordingIngestorError>,
}

fn hash_source_prefix(
    context: &SourceReadContext<'_>,
    limit: u64,
    hasher: &mut Sha256,
) -> Result<(), PhaseFailure> {
    let mut offset = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    while offset < limit {
        (context.root_fence)().map_err(PhaseFailure::Engine)?;
        if context.control.should_stop() {
            return Err(PhaseFailure::Stopped);
        }
        let mut chunk = open_source_chunk(
            context.source,
            context.spec,
            context.locator,
            context.file,
            offset,
        )?;
        if chunk.start != offset {
            return Err(PhaseFailure::WaitingForSource);
        }
        while chunk.remaining() > 0 && offset < limit {
            (context.root_fence)().map_err(PhaseFailure::Engine)?;
            let wanted = chunk
                .remaining()
                .min(limit - offset)
                .min(buffer.len() as u64);
            let wanted = usize::try_from(wanted).expect("buffer-bounded read length fits usize");
            let read = chunk
                .body
                .read(&mut buffer[..wanted])
                .map_err(classify_body_failure)?;
            if read == 0 {
                return Err(PhaseFailure::WaitingForSource);
            }
            hasher.update(&buffer[..read]);
            chunk.consumed = chunk.consumed.saturating_add(read as u64);
            offset = offset.saturating_add(read as u64);
        }
    }
    Ok(())
}

fn hash_source_exact(
    source: &dyn ArtifactSource,
    spec: &ImportSpec,
    locator: &MediaLocator,
    file: &ImportFileSpec,
    control: &JobControl,
    root_fence: &dyn Fn() -> Result<(), RecordingIngestorError>,
) -> Result<String, PhaseFailure> {
    let mut hasher = Sha256::new();
    let context = SourceReadContext {
        source,
        spec,
        locator,
        file,
        control,
        root_fence,
    };
    hash_source_prefix(&context, file.expected_size(), &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn classify_open_failure(error: ArtifactSourceError) -> PhaseFailure {
    match error {
        ArtifactSourceError::Unavailable { .. } | ArtifactSourceError::Io { .. } => {
            PhaseFailure::WaitingForSource
        }
        ArtifactSourceError::PermissionDenied => PhaseFailure::Failure {
            code: ImportFailureCode::PermissionDenied,
            message: "permission denied while reading the source".to_string(),
            retryable: false,
        },
        ArtifactSourceError::UnsafeArtifact { .. } => PhaseFailure::Failure {
            code: ImportFailureCode::UnsafePath,
            message: "source artifact failed the safe-file contract".to_string(),
            retryable: false,
        },
        ArtifactSourceError::ProtocolViolation { message } => PhaseFailure::Failure {
            code: ImportFailureCode::SourceRevisionMismatch,
            message: bounded_text(message),
            retryable: false,
        },
    }
}

fn classify_body_failure(error: io::Error) -> PhaseFailure {
    match classify_body_read_error(&error) {
        ArtifactReadFailure::SourceUnavailable
        | ArtifactReadFailure::MediaChanged { .. }
        | ArtifactReadFailure::PreconditionFailed { .. }
        | ArtifactReadFailure::Io { .. } => PhaseFailure::WaitingForSource,
        ArtifactReadFailure::PermissionDenied => PhaseFailure::Failure {
            code: ImportFailureCode::PermissionDenied,
            message: "permission denied while streaming the source".to_string(),
            retryable: false,
        },
    }
}

fn expected_artifact(file: &ImportFileSpec, checkpoint: &ImportFileCheckpoint) -> ExpectedArtifact {
    let digest = checkpoint.target_sha256().or(file.expected_source_sha256());
    match digest {
        Some(digest) => ExpectedArtifact::new(
            file.file_id().as_str(),
            Some(file.relative_path().as_str().to_string()),
            file.expected_size(),
            digest,
        ),
        None => ExpectedArtifact::without_digest(
            file.file_id().as_str(),
            Some(file.relative_path().as_str().to_string()),
            file.expected_size(),
        ),
    }
}

fn checkpoint_evidence(
    checkpoint: &ImportFileCheckpoint,
) -> Result<FileCopyEvidence, RecordingIngestorError> {
    Ok(FileCopyEvidence {
        file_id: checkpoint.file_id().clone(),
        source_sha256: checkpoint
            .source_sha256()
            .ok_or(RecordingIngestorError::PersistenceConflict)?
            .to_string(),
        target_sha256: checkpoint
            .target_sha256()
            .ok_or(RecordingIngestorError::PersistenceConflict)?
            .to_string(),
    })
}

fn verify_digests(
    file: &ImportFileSpec,
    source_sha256: &str,
    target_sha256: &str,
) -> Result<(), PhaseFailure> {
    if source_sha256 != target_sha256
        || file
            .expected_source_sha256()
            .is_some_and(|expected| expected != source_sha256)
    {
        return Err(PhaseFailure::Failure {
            code: ImportFailureCode::IntegrityMismatch,
            message: "source stream and independently re-read target hashes do not agree"
                .to_string(),
            retryable: false,
        });
    }
    Ok(())
}

fn journal_binding_digest(spec: &ImportSpec, file: &ImportFileSpec) -> String {
    file.expected_source_sha256()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(b"ylx-import-unsigned-checkpoint-v1\0");
            hasher.update(spec.request_digest().as_bytes());
            hasher.update(b"\0");
            hasher.update(file.file_id().as_str().as_bytes());
            format!("{:x}", hasher.finalize())
        })
}

fn part_path(target: &Path) -> PathBuf {
    let mut path = target.as_os_str().to_os_string();
    path.push(".part");
    PathBuf::from(path)
}

fn journal_path(target: &Path) -> PathBuf {
    let mut path = part_path(target).into_os_string();
    path.push(".journal");
    PathBuf::from(path)
}

fn truncate_partial(path: &Path, offset: u64) -> Result<(), PhaseFailure> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| PhaseFailure::filesystem(format!("open partial: {error}")))?;
    file.set_len(offset)
        .map_err(|error| PhaseFailure::filesystem(format!("truncate partial: {error}")))?;
    file.sync_all()
        .map_err(|error| PhaseFailure::filesystem(format!("flush partial: {error}")))
}

fn sha256_file(path: &Path) -> Result<String, PhaseFailure> {
    let mut file = File::open(path)
        .map_err(|error| PhaseFailure::filesystem(format!("open staged target: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| PhaseFailure::filesystem(format!("read staged target: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn ensure_staging_parent(
    staging: &SessionStaging,
    relative_path: &SafeRelativePath,
) -> Result<(), PhaseFailure> {
    let mut current = staging.revision_dir();
    let components: Vec<&str> = relative_path.components().collect();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(PhaseFailure::Failure {
                    code: ImportFailureCode::UnsafePath,
                    message: "staging parent contains a link or non-directory entry".to_string(),
                    retryable: false,
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    PhaseFailure::filesystem(format!("create staging directory: {error}"))
                })?;
            }
            Err(error) => {
                return Err(PhaseFailure::filesystem(format!(
                    "inspect staging directory: {error}"
                )))
            }
        }
    }
    Ok(())
}

fn reject_link(path: &Path) -> Result<(), PhaseFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(PhaseFailure::Failure {
                code: ImportFailureCode::UnsafePath,
                message: "staging evidence path is a link or special entry".to_string(),
                retryable: false,
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PhaseFailure::filesystem(format!(
            "inspect staging evidence: {error}"
        ))),
    }
}

fn remove_invalid_staged_target(path: &Path) -> Result<(), PhaseFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|error| {
                PhaseFailure::filesystem(format!("remove invalid target: {error}"))
            })
        }
        Ok(_) => Err(PhaseFailure::Failure {
            code: ImportFailureCode::UnsafePath,
            message: "invalid staging target is not a removable regular-file entry".to_string(),
            retryable: false,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PhaseFailure::filesystem(format!(
            "inspect invalid target: {error}"
        ))),
    }
}

fn fsync_parent(path: &Path) -> Result<(), PhaseFailure> {
    let parent = path.parent().ok_or_else(|| PhaseFailure::Failure {
        code: ImportFailureCode::UnsafePath,
        message: "staging target has no parent directory".to_string(),
        retryable: false,
    })?;
    fsync_directory(parent)
}

#[cfg(unix)]
fn fsync_directory(path: &Path) -> Result<(), PhaseFailure> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| PhaseFailure::filesystem(format!("flush staging directory: {error}")))
}

#[cfg(not(unix))]
fn fsync_directory(_path: &Path) -> Result<(), PhaseFailure> {
    Ok(())
}

fn staging_for_spec(
    library_root: &Path,
    spec: &ImportSpec,
) -> Result<SessionStaging, RecordingIngestorError> {
    let mut session_hasher = Sha256::new();
    session_hasher.update(b"ylx-source-session-v1\0");
    let natural_key = serde_json::to_vec(spec.natural_key())
        .map_err(|error| RecordingIngestorError::Publication(error.to_string()))?;
    session_hasher.update(natural_key);
    let session_id = format!("source-{:x}", session_hasher.finalize());
    let revision = RevisionId::from_publication(spec.request_digest().as_bytes());
    SessionStaging::new(library_root, "sources", session_id, revision)
        .map_err(|error| RecordingIngestorError::Publication(error.to_string()))
}

fn manifest_from_verified(
    spec: &ImportSpec,
    snapshot: &ImportSnapshot,
    staging: &SessionStaging,
) -> Result<SessionManifest, RecordingIngestorError> {
    let files = spec
        .files()
        .iter()
        .map(|file| {
            let checkpoint = snapshot
                .checkpoints()
                .iter()
                .find(|checkpoint| checkpoint.file_id() == file.file_id())
                .ok_or(RecordingIngestorError::PersistenceConflict)?;
            if !checkpoint.verified() {
                return Err(RecordingIngestorError::PersistenceConflict);
            }
            let digest = checkpoint
                .target_sha256()
                .ok_or(RecordingIngestorError::PersistenceConflict)?;
            Ok(ExpectedArtifact::new(
                file.file_id().as_str(),
                Some(file.relative_path().as_str().to_string()),
                file.expected_size(),
                digest,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SessionManifest::new(
        staging.device_id(),
        staging.session_id(),
        files,
    ))
}

fn inventory_digest(
    spec: &ImportSpec,
    snapshot: &ImportSnapshot,
) -> Result<InventoryDigest, RecordingIngestorError> {
    let mut hasher = Sha256::new();
    hasher.update(b"ylx-source-inventory-v1\0");
    for file in spec.files() {
        let checkpoint = snapshot
            .checkpoints()
            .iter()
            .find(|checkpoint| checkpoint.file_id() == file.file_id())
            .ok_or(RecordingIngestorError::PersistenceConflict)?;
        let digest = checkpoint
            .target_sha256()
            .ok_or(RecordingIngestorError::PersistenceConflict)?;
        hash_inventory_field(&mut hasher, file.file_id().as_str());
        hash_inventory_field(&mut hasher, file.relative_path().as_str());
        hasher.update(file.expected_size().to_le_bytes());
        hash_inventory_field(&mut hasher, digest);
    }
    Ok(InventoryDigest::from_digest(hasher.finalize().into()))
}

fn hash_inventory_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn generation_matches(locator: &MediaLocator, resolved: &ResolvedArtifactSource) -> bool {
    locator.media_generation_id() == resolved.observed_generation.as_ref()
}

fn acquisition_fence_changed(current: &MediaLocator, replacement: &MediaLocator) -> bool {
    current != replacement
}

fn has_strong_resume_identity(spec: &ImportSpec) -> bool {
    matches!(
        spec.source().provenance(),
        SourceProvenance::DeviceSigned(_)
    ) && spec.source().revision_claim().stable().is_some()
        && spec
            .files()
            .iter()
            .all(|file| file.expected_source_sha256().is_some())
}

fn ensure_same_source(
    spec: &ImportSpec,
    source: &SourceRecording,
) -> Result<(), RecordingIngestorError> {
    let expected = spec.source();
    if expected.revision_claim() != source.revision_claim()
        || expected.session_id() != source.session_id()
        || expected.schema() != source.schema()
        || expected.inventory() != source.inventory()
        || expected.media_plan() != source.media_plan()
        || !same_source_provenance(expected.provenance(), source.provenance())
    {
        return Err(RecordingIngestorError::CommandRejected(
            ImportRejectReason::IntegrityMismatch,
        ));
    }
    Ok(())
}

/// Re-admission must confirm immutable source evidence while permitting a
/// fresh explicit authorization decision for locally validated unsigned media.
/// `SourceRecording::admit_unsigned` has already proved that the new receipt
/// binds the currently observed candidate and generation. Comparing those
/// acquisition fields with the old receipt here would make an exact card
/// reinsert impossible because both IDs intentionally change. The provisional
/// revision remains the content fence; `source_available` separately resets
/// progress and staging whenever the acquisition locator changes.
fn same_source_provenance(expected: &SourceProvenance, observed: &SourceProvenance) -> bool {
    match (expected, observed) {
        (SourceProvenance::DeviceSigned(expected), SourceProvenance::DeviceSigned(observed)) => {
            expected == observed
        }
        (
            SourceProvenance::LocallyValidatedUnsigned(expected),
            SourceProvenance::LocallyValidatedUnsigned(observed),
        ) => {
            if expected.source_schema() != observed.source_schema()
                || expected.validation_report() != observed.validation_report()
                || expected.computed_inventory_digest() != observed.computed_inventory_digest()
            {
                return false;
            }
            match (
                expected.user_admission_receipt(),
                observed.user_admission_receipt(),
            ) {
                (Some(expected), Some(observed)) => {
                    expected.candidate_revision() == observed.candidate_revision()
                }
                // A previously unapproved source may receive its first
                // explicit receipt during re-admission. The reverse
                // transition is rejected by the import policy before this
                // helper is used.
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => true,
            }
        }
        _ => false,
    }
}

pub(super) fn bounded_text(mut message: String) -> String {
    message.retain(|character| !character.is_control() || character == ' ');
    if message.len() <= 1_024 {
        return message;
    }
    let mut boundary = 1_024;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}

fn map_port_to_ingest(error: IngestPortError) -> IngestError {
    match error.code() {
        "candidate_unavailable" => IngestError::CandidateUnavailable,
        "policy_approval_required" => IngestError::PolicyApprovalRequired {
            message: bounded_text(error.message().to_string()),
        },
        "persistence" | "conflict" | "corrupt" => IngestError::Persistence {
            message: bounded_text(error.message().to_string()),
        },
        "source_unavailable" | "scheduler_unavailable" => IngestError::Unavailable {
            message: bounded_text(error.message().to_string()),
        },
        _ => IngestError::Internal {
            message: bounded_text(error.message().to_string()),
        },
    }
}

fn map_engine_to_ingest(error: RecordingIngestorError) -> IngestError {
    match error {
        RecordingIngestorError::Port(error) => map_port_to_ingest(error),
        RecordingIngestorError::CandidateUnavailable(_) => IngestError::CandidateUnavailable,
        RecordingIngestorError::JobNotFound(_) => IngestError::JobNotFound,
        RecordingIngestorError::CommandRejected(reason) => IngestError::Conflict {
            message: format!("{reason:?}"),
        },
        RecordingIngestorError::PersistenceConflict => IngestError::Persistence {
            message: "import snapshot lost its expected-version update".to_string(),
        },
        RecordingIngestorError::Spec(
            error @ (ImportSpecError::UnsignedRejected | ImportSpecError::UnsignedReceiptRequired),
        ) => IngestError::PolicyApprovalRequired {
            message: bounded_text(error.to_string()),
        },
        RecordingIngestorError::Spec(error) => IngestError::Conflict {
            message: bounded_text(error.to_string()),
        },
        other => IngestError::Internal {
            message: bounded_text(other.to_string()),
        },
    }
}

impl<C> RecordingIngestor for RecordingIngestExecutor<C>
where
    C: CandidateCatalog,
{
    fn scan(&self, request: ScanRequest) -> Result<ScanSnapshot, IngestError> {
        self.candidates.scan(request).map_err(map_port_to_ingest)
    }

    fn start_import(
        &self,
        candidate_id: CandidateId,
        policy: ImportPolicy,
    ) -> Result<ImportStartOutcome, IngestError> {
        self.start_import_impl(&candidate_id, policy, None)
            .map_err(map_engine_to_ingest)
    }

    fn command(
        &self,
        job_id: ImportJobId,
        command: ImportControlCommand,
    ) -> Result<ImportCommandOutcome, IngestError> {
        self.command_impl(&job_id, command)
            .map_err(map_engine_to_ingest)
    }

    fn snapshots(&self) -> Result<Vec<ImportSnapshot>, IngestError> {
        self.repository
            .list_import_snapshots()
            .map_err(map_port_to_ingest)
    }
}

#[cfg(test)]
mod reinsert_tests {
    use super::*;
    use crate::ingest::{
        AcquisitionSourceId, CandidateId, CandidateReadiness, CandidateRevision, FrameRate,
        MediaGeneration, ScanCandidate, SourceArtifactClaim, SourceArtifactId, SourceArtifactRole,
        SourceKind, SourceMediaPlan, SourceRevisionClaim, SourceSchema, SourceTrustVerdicts,
        SourceVideoCodec, StereoLayout, UnsignedImportPolicy, UnsignedSourceAdmissionReceipt,
        ValidationCheck, ValidationReport,
    };

    fn unsigned_source(
        candidate_material: &[u8],
        observation_epoch: u64,
        revision_material: &[u8],
        expected_size: u64,
    ) -> SourceRecording {
        let acquisition = AcquisitionSourceId::parse("fixture-card").expect("source id");
        let generation = MediaGeneration::new(
            acquisition.clone(),
            "fixture-volume",
            InventoryDigest::from_material(b"fixture-root"),
            observation_epoch,
        )
        .expect("media generation");
        let locator = MediaLocator::new(acquisition, Some(generation), None);
        let candidate_id = CandidateId::from_material(candidate_material);
        let revision = CandidateRevision::from_material(revision_material);
        let claim = SourceArtifactClaim::new(
            SourceArtifactId::parse("video-left").expect("artifact id"),
            SafeRelativePath::parse("video/left.mp4").expect("artifact path"),
            SourceArtifactRole::VideoLeft,
            expected_size,
            None,
            Some("video/mp4".to_string()),
        )
        .expect("artifact");
        let plan = SourceMediaPlan::new(
            StereoLayout::SeparateEyes,
            SourceVideoCodec::H264,
            Some(FrameRate::new(30, 1).expect("frame rate")),
            Some(1920),
            Some(1080),
            1,
            false,
        )
        .expect("media plan");
        let report = ValidationReport::new(vec![ValidationCheck::new(
            "complete",
            true,
            "fixture is complete",
        )
        .expect("validation check")])
        .expect("validation report");
        let candidate = ScanCandidate::new(
            candidate_id.clone(),
            SourceRevisionClaim::Provisional(revision.clone()),
            SourceKind::RemovableMedia,
            SourceSchema::UnsignedPublicationV1,
            "fixture-session".to_string(),
            locator,
            vec![claim],
            plan,
            SourceTrustVerdicts::pending_unsigned(),
            CandidateReadiness::ReadyUnsignedRequiresPolicy,
            report,
            None,
        )
        .expect("candidate");
        let receipt = UnsignedSourceAdmissionReceipt::new(
            format!("receipt-{observation_epoch}"),
            candidate_id,
            candidate.locator().media_generation_id().cloned(),
            revision,
            "policy-v1",
            "2026-08-11T00:00:00Z",
        )
        .expect("receipt");
        SourceRecording::admit_unsigned(candidate, Some(receipt)).expect("unsigned admission")
    }

    #[test]
    fn exact_unsigned_reinsert_accepts_a_fresh_acquisition_receipt() {
        let first = unsigned_source(b"candidate-first", 1, b"same-revision", 5);
        let reinserted = unsigned_source(b"candidate-reinserted", 2, b"same-revision", 5);
        let policy = ImportPolicy::new(UnsignedImportPolicy::RequireAdmissionReceipt, 100, 1);
        let spec = ImportSpec::new(ImportJobId::new(), first, policy).expect("import spec");

        ensure_same_source(&spec, &reinserted).expect("same content must be re-admissible");
        assert!(acquisition_fence_changed(
            spec.locator(),
            reinserted.locator()
        ));
        assert!(!has_strong_resume_identity(&spec));
    }

    #[test]
    fn unsigned_replacement_with_changed_content_is_rejected() {
        let first = unsigned_source(b"candidate-first", 1, b"revision-one", 5);
        let changed_revision = unsigned_source(b"candidate-second", 2, b"revision-two", 5);
        let changed_inventory = unsigned_source(b"candidate-third", 3, b"revision-one", 6);
        let policy = ImportPolicy::new(UnsignedImportPolicy::RequireAdmissionReceipt, 100, 1);
        let spec = ImportSpec::new(ImportJobId::new(), first, policy).expect("import spec");

        assert!(ensure_same_source(&spec, &changed_revision).is_err());
        assert!(ensure_same_source(&spec, &changed_inventory).is_err());
    }
}
