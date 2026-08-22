use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::normalization::{
    DerivationCommand, DerivationEffect, DerivationFailureCode, DerivationJob, DerivationJobId,
    DerivationJobState, DerivationOutcome, DerivationSnapshot, DerivationSpec, DerivedCompletion,
    DerivedManifest, DerivedManifestBuilder, EncodeSegmentPairRequest, EncodedSegmentPair,
    EncoderStatistics, MediaEncoder, MediaNormalizer, MediaNormalizerError, MediaOperationControl,
    MediaPlanner, MediaProbe, MediaProcessFailureCode, MediaProcessOutcome, ProbeRequest,
    ProcessStopReason, SegmentValidationRequest, ValidatedSegmentPair,
};

use super::control::{JobRuntime, JobRuntimeRegistry};
use super::ports::{
    CompletionNotificationSink, CreateDerivationOutcome, DerivationRepository,
    DerivedCommitEvidence, MediaNormalizerClock, MediaNormalizerPortError,
    MediaNormalizerScheduler, SegmentQualityAnalyzer, SnapshotSwapOutcome, SourceReadLeases,
};
use super::staging::{DerivedStaging, StagingError};

/// Runtime dependencies of the effect interpreter. The adapter traits are
/// object-safe, so production uses FFmpeg/S3-backed implementations while
/// contract tests can inject deterministic fakes.
pub struct MediaNormalizerConfig {
    pub repository: Arc<dyn DerivationRepository>,
    pub probe: Arc<dyn MediaProbe>,
    pub encoder: Arc<dyn MediaEncoder>,
    pub quality: Arc<dyn SegmentQualityAnalyzer>,
    pub leases: Arc<dyn SourceReadLeases>,
    pub scheduler: Arc<dyn MediaNormalizerScheduler>,
    pub clock: Arc<dyn MediaNormalizerClock>,
    pub staging: DerivedStaging,
    pub process_deadline: crate::normalization::ProcessDeadline,
    pub notifications: Option<Arc<dyn CompletionNotificationSink>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizerRunOutcome {
    Idle(DerivationSnapshot),
    Completed(DerivationSnapshot),
    WaitingForSource(DerivationSnapshot),
    Paused(DerivationSnapshot),
    Cancelled(DerivationSnapshot),
    Failed {
        snapshot: Option<DerivationSnapshot>,
        detail: String,
    },
}

/// One in-process owner of all normalization effects. Durable CAS remains
/// authoritative across processes; the runtime registry supplies the missing
/// per-job serialization and process-stop rendezvous inside this process.
pub struct MediaNormalizerExecutor {
    repository: Arc<dyn DerivationRepository>,
    probe: Arc<dyn MediaProbe>,
    encoder: Arc<dyn MediaEncoder>,
    quality: Arc<dyn SegmentQualityAnalyzer>,
    leases: Arc<dyn SourceReadLeases>,
    scheduler: Arc<dyn MediaNormalizerScheduler>,
    clock: Arc<dyn MediaNormalizerClock>,
    notifications: Option<Arc<dyn CompletionNotificationSink>>,
    staging: DerivedStaging,
    runtimes: JobRuntimeRegistry,
    shutting_down: AtomicBool,
}

impl MediaNormalizerExecutor {
    pub fn new(config: MediaNormalizerConfig) -> Self {
        Self {
            repository: config.repository,
            probe: config.probe,
            encoder: config.encoder,
            quality: config.quality,
            leases: config.leases,
            scheduler: config.scheduler,
            clock: config.clock,
            notifications: config.notifications,
            staging: config.staging,
            runtimes: JobRuntimeRegistry::new(config.process_deadline),
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Scheduler entry point. Duplicate enqueue is harmless: the worker gate
    /// permits only one active owner and the durable CAS rejects stale reports.
    pub fn run_one(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<NormalizerRunOutcome, MediaNormalizerError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(MediaNormalizerError::ShuttingDown);
        }
        let runtime = self.runtimes.runtime_for(job_id);
        let _worker = runtime.worker();
        let Some(stored) = self.load(job_id)? else {
            return Err(MediaNormalizerError::NotFound(job_id.clone()));
        };
        let mut snapshot = stored.snapshot;
        if snapshot.state().is_terminal() {
            return Ok(terminal_outcome(snapshot));
        }
        if snapshot.desired_state() == crate::normalization::DerivationDesiredState::Paused {
            return Ok(NormalizerRunOutcome::Paused(snapshot));
        }

        let mut lease = match self
            .leases
            .acquire_shared(snapshot.spec().source_revision(), job_id)
        {
            Ok(lease) => lease,
            Err(_error) => {
                let reduced = self.reduce(job_id, DerivationCommand::SourceUnavailable, false)?;
                return Ok(NormalizerRunOutcome::WaitingForSource(
                    reduced.unwrap_or(snapshot),
                ));
            }
        };
        lease
            .assert_current()
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;

        self.staging
            .prepare_job(job_id)
            .map_err(staging_error_to_normalizer)?;
        if let Err(error) = self.reconcile_checkpoint_files(job_id, &snapshot) {
            return Ok(self.fail_from_run(job_id, snapshot, error.to_string(), false));
        }

        loop {
            if self.shutting_down.load(Ordering::Acquire) {
                let reduced = self.reduce(
                    job_id,
                    DerivationCommand::Worker(
                        crate::normalization::DerivationWorkerReport::ProcessStopped(
                            ProcessStopReason::Shutdown,
                        ),
                    ),
                    false,
                )?;
                return Ok(NormalizerRunOutcome::Paused(reduced.unwrap_or(snapshot)));
            }
            let Some(current) = self.load(job_id)? else {
                return Err(MediaNormalizerError::NotFound(job_id.clone()));
            };
            snapshot = current.snapshot;
            if snapshot.state().is_terminal() {
                return Ok(terminal_outcome(snapshot));
            }
            if snapshot.desired_state() == crate::normalization::DerivationDesiredState::Paused {
                return Ok(NormalizerRunOutcome::Paused(snapshot));
            }
            lease
                .assert_current()
                .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;

            match snapshot.state() {
                DerivationJobState::Queued
                | DerivationJobState::RetryWait
                | DerivationJobState::WaitingForSource => {
                    let _ = self.reduce(job_id, DerivationCommand::SourceAvailable, false)?;
                }
                DerivationJobState::Probing => {
                    self.run_probe(job_id, &runtime)?;
                }
                DerivationJobState::Planning => {
                    self.run_plan(job_id)?;
                }
                DerivationJobState::Encoding => {
                    self.run_next_pair(job_id, &runtime, &mut lease)?;
                }
                DerivationJobState::Validating => {
                    self.run_validation_gate(job_id)?;
                }
                DerivationJobState::Committing => {
                    self.run_commit(job_id, &mut lease)?;
                }
                DerivationJobState::Cancelling => {
                    let _ = self.reduce(
                        job_id,
                        DerivationCommand::Worker(
                            crate::normalization::DerivationWorkerReport::ProcessStopped(
                                ProcessStopReason::Cancel,
                            ),
                        ),
                        false,
                    )?;
                }
                DerivationJobState::DerivedVerified
                | DerivationJobState::Failed { .. }
                | DerivationJobState::Cancelled => return Ok(terminal_outcome(snapshot)),
            }
        }
    }

    fn run_probe(
        &self,
        job_id: &DerivationJobId,
        runtime: &Arc<JobRuntime>,
    ) -> Result<(), MediaNormalizerError> {
        let Some(stored) = self.load(job_id)? else {
            return Err(MediaNormalizerError::NotFound(job_id.clone()));
        };
        let snapshot = stored.snapshot;
        let request = ProbeRequest::new(
            snapshot.spec().local_source().clone(),
            snapshot.spec().input().clone(),
        );
        let operation = {
            let _guard = runtime.command();
            let Some(current) = self.load(job_id)? else {
                return Err(MediaNormalizerError::NotFound(job_id.clone()));
            };
            if current.snapshot.state() != &DerivationJobState::Probing {
                return Ok(());
            }
            if let Some(reason) = runtime.process.stop_requested() {
                drop(_guard);
                let _ = self.reduce(
                    job_id,
                    DerivationCommand::Worker(
                        crate::normalization::DerivationWorkerReport::ProcessStopped(reason),
                    ),
                    false,
                )?;
                return Ok(());
            }
            if current.snapshot.desired_state()
                == crate::normalization::DerivationDesiredState::Paused
            {
                return Ok(());
            }
            runtime.process.begin()
        };
        let outcome = self.probe.probe(&request, runtime.process.as_ref());
        self.reduce_process_outcome(
            job_id,
            runtime,
            operation,
            outcome,
            crate::normalization::DerivationWorkerReport::ProbeCompleted,
            DerivationFailureCode::ProbeFailed,
        )
    }

    fn run_plan(&self, job_id: &DerivationJobId) -> Result<(), MediaNormalizerError> {
        let Some(stored) = self.load(job_id)? else {
            return Err(MediaNormalizerError::NotFound(job_id.clone()));
        };
        let snapshot = stored.snapshot;
        let Some(probe) = snapshot.probe_report() else {
            return self.fail_stage(job_id, DerivationFailureCode::PlanRejected, false);
        };
        let plan =
            match MediaPlanner::plan(snapshot.spec().input(), probe, snapshot.spec().profile()) {
                Ok(plan) => plan,
                Err(error) => {
                    return self.fail_stage_with_detail(
                        job_id,
                        DerivationFailureCode::PlanRejected,
                        false,
                        error.to_string(),
                    )
                }
            };
        let _ = self.reduce(
            job_id,
            DerivationCommand::Worker(crate::normalization::DerivationWorkerReport::PlanCompleted(
                plan,
            )),
            false,
        )?;
        Ok(())
    }

    fn run_next_pair(
        &self,
        job_id: &DerivationJobId,
        runtime: &Arc<JobRuntime>,
        lease: &mut Box<dyn super::ports::SourceReadLease>,
    ) -> Result<(), MediaNormalizerError> {
        let Some(stored) = self.load(job_id)? else {
            return Err(MediaNormalizerError::NotFound(job_id.clone()));
        };
        let snapshot = stored.snapshot;
        let Some(plan) = snapshot.media_plan() else {
            return self.fail_stage(job_id, DerivationFailureCode::PlanRejected, false);
        };
        let index = u32::try_from(snapshot.checkpoints().len())
            .map_err(|_| MediaNormalizerError::Worker("segment index overflow".to_string()))?;
        let Some(pair_plan) = plan.segment_pair(index) else {
            return self.fail_stage(job_id, DerivationFailureCode::Internal, false);
        };

        let recovered = self
            .staging
            .recover_uncheckpointed_pair(job_id, index)
            .map_err(staging_error_to_normalizer)?;
        let reused_pair = recovered.is_some();
        let workspace = match recovered {
            Some(workspace) => workspace,
            None => self
                .staging
                .prepare_pair(job_id, index)
                .map_err(staging_error_to_normalizer)?,
        };
        let _ = self.reduce(
            job_id,
            DerivationCommand::Worker(crate::normalization::DerivationWorkerReport::PairStarted {
                segment_index: index,
            }),
            false,
        )?;
        let request = EncodeSegmentPairRequest::from_media_plan(
            snapshot.spec().local_source().clone(),
            snapshot.spec().input().clone(),
            plan,
            index,
            snapshot.spec().profile().clone(),
            snapshot.spec().encoder_build().clone(),
            workspace.left_partial().to_path_buf(),
            workspace.right_partial().to_path_buf(),
        )
        .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;

        let operation = {
            let _guard = runtime.command();
            let Some(current) = self.load(job_id)? else {
                return Err(MediaNormalizerError::NotFound(job_id.clone()));
            };
            if current.snapshot.state() != &DerivationJobState::Encoding {
                return Ok(());
            }
            if let Some(reason) = runtime.process.stop_requested() {
                drop(_guard);
                let _ = self.reduce(
                    job_id,
                    DerivationCommand::Worker(
                        crate::normalization::DerivationWorkerReport::ProcessStopped(reason),
                    ),
                    false,
                )?;
                return Ok(());
            }
            if current.snapshot.desired_state()
                == crate::normalization::DerivationDesiredState::Paused
            {
                return Ok(());
            }
            runtime.process.begin()
        };
        let encoded = if reused_pair {
            let stats = EncoderStatistics::new(
                pair_plan.frame_count(),
                pair_plan.duration_ticks(),
                1,
                1,
                None,
            )
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
            EncodedSegmentPair::from_request(&request, stats)
                .map_err(|error| MediaNormalizerError::Worker(error.to_string()))
        } else {
            match self
                .encoder
                .encode_segment_pair(&request, runtime.process.as_ref())
            {
                MediaProcessOutcome::Completed { value, .. } => Ok(value),
                MediaProcessOutcome::Stopped { reason, .. } => {
                    let result = self.reduce_worker_stopped(job_id, runtime, operation, reason);
                    return result;
                }
                MediaProcessOutcome::Failed { failure, .. } => {
                    let code = map_process_failure(failure.code());
                    return self.reduce_worker_failed(
                        job_id,
                        runtime,
                        operation,
                        code,
                        failure.retryable(),
                        failure.sanitized_detail(),
                    );
                }
            }
        }?;

        if let Some(reason) = runtime.process.stop_requested() {
            let result = self.reduce_worker_stopped(job_id, runtime, operation, reason);
            return result;
        }
        let quality =
            match self
                .quality
                .analyze_segment_pair(&request, &encoded, runtime.process.as_ref())
            {
                MediaProcessOutcome::Completed { value, .. } => value,
                MediaProcessOutcome::Stopped { reason, .. } => {
                    let result = self.reduce_worker_stopped(job_id, runtime, operation, reason);
                    return result;
                }
                MediaProcessOutcome::Failed { failure, .. } => {
                    let code = map_process_failure(failure.code());
                    return self.reduce_worker_failed(
                        job_id,
                        runtime,
                        operation,
                        code,
                        failure.retryable(),
                        failure.sanitized_detail(),
                    );
                }
            };
        let validation_request = SegmentValidationRequest::new(
            &request,
            encoded,
            quality.left().clone(),
            quality.right().clone(),
        )
        .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let report = match self
            .probe
            .validate_segment_pair(&validation_request, runtime.process.as_ref())
        {
            MediaProcessOutcome::Completed { value, .. } => value,
            MediaProcessOutcome::Stopped { reason, .. } => {
                let result = self.reduce_worker_stopped(job_id, runtime, operation, reason);
                return result;
            }
            MediaProcessOutcome::Failed { failure, .. } => {
                let code = map_process_failure(failure.code());
                return self.reduce_worker_failed(
                    job_id,
                    runtime,
                    operation,
                    code,
                    failure.retryable(),
                    failure.sanitized_detail(),
                );
            }
        };
        if let Some(reason) = runtime.process.stop_requested() {
            self.staging
                .discard_pair(job_id, index)
                .map_err(staging_error_to_normalizer)?;
            let result = self.reduce_worker_stopped(job_id, runtime, operation, reason);
            return result;
        }
        let validated = match ValidatedSegmentPair::try_from_report(report) {
            Ok(value) => value,
            Err(error) => {
                return self.reduce_worker_failed(
                    job_id,
                    runtime,
                    operation,
                    DerivationFailureCode::ValidationFailed,
                    false,
                    &error.to_string(),
                )
            }
        };
        lease
            .assert_current()
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let left_sha = validated.report().left().sha256().as_str().to_string();
        let right_sha = validated.report().right().sha256().as_str().to_string();
        let published = self
            .staging
            .publish_validated_pair(job_id, index, &left_sha, &right_sha)
            .map_err(staging_error_to_normalizer)?;
        let checkpoint = crate::normalization::SegmentPairCheckpoint::from_validated_pair(
            pair_plan,
            validated,
            snapshot.spec().profile(),
            snapshot.spec().encoder_build(),
            published.relative_path,
            published.commit_receipt,
        )
        .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let result = self.reduce(
            job_id,
            DerivationCommand::Worker(
                crate::normalization::DerivationWorkerReport::PairCheckpointed(checkpoint),
            ),
            false,
        );
        operation.finish();
        result.map(|_| ())
    }

    fn run_validation_gate(&self, job_id: &DerivationJobId) -> Result<(), MediaNormalizerError> {
        let Some(stored) = self.load(job_id)? else {
            return Err(MediaNormalizerError::NotFound(job_id.clone()));
        };
        for checkpoint in stored.snapshot.checkpoints() {
            self.staging
                .verify_checkpoint(job_id, checkpoint)
                .map_err(staging_error_to_normalizer)?;
        }
        let _ = self.reduce(
            job_id,
            DerivationCommand::Worker(
                crate::normalization::DerivationWorkerReport::ValidationCompleted,
            ),
            false,
        )?;
        Ok(())
    }

    fn run_commit(
        &self,
        job_id: &DerivationJobId,
        lease: &mut Box<dyn super::ports::SourceReadLease>,
    ) -> Result<(), MediaNormalizerError> {
        let Some(stored) = self.load(job_id)? else {
            return Err(MediaNormalizerError::NotFound(job_id.clone()));
        };
        let snapshot = stored.snapshot;
        let Some(plan) = snapshot.media_plan().cloned() else {
            return self.fail_stage(job_id, DerivationFailureCode::Internal, false);
        };
        lease
            .assert_current()
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let mut builder = DerivedManifestBuilder::new(
            snapshot.spec().subject().clone(),
            snapshot.spec().local_source().clone(),
            snapshot.spec().source_manifest_digest().clone(),
            snapshot.spec().input().clone(),
            plan,
            snapshot.spec().profile().clone(),
            snapshot.spec().encoder_build().clone(),
            snapshot.spec().created_at(),
        )
        .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        for checkpoint in snapshot.checkpoints() {
            builder
                .add_checkpoint(checkpoint.clone())
                .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        }
        let manifest = builder
            .build()
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let commit = self
            .staging
            .commit_derivative(
                job_id,
                snapshot.spec().source_revision(),
                snapshot.spec().profile_revision(),
                &manifest,
            )
            .map_err(staging_error_to_normalizer)?;
        let completion = DerivedCompletion::new(
            &manifest,
            commit.local_relative_path.clone(),
            commit.local_commit_receipt.clone(),
            self.clock.now_rfc3339(),
        )
        .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let evidence = DerivedCommitEvidence {
            manifest_sha256: commit.manifest_sha256,
            output_inventory_sha256: commit.output_inventory_sha256,
            local_relative_path: commit.local_relative_path,
            local_commit_receipt: commit.local_commit_receipt,
        };
        let _ = self.reduce_with_commit(job_id, completion.clone(), manifest, evidence, false)?;
        if let Some(sink) = &self.notifications {
            let _ = sink.derived_verified(job_id, &completion);
        }
        Ok(())
    }

    fn reconcile_checkpoint_files(
        &self,
        job_id: &DerivationJobId,
        snapshot: &DerivationSnapshot,
    ) -> Result<(), StagingError> {
        for checkpoint in snapshot.checkpoints() {
            self.staging.verify_checkpoint(job_id, checkpoint)?;
        }
        Ok(())
    }

    fn reduce_process_outcome<T, F>(
        &self,
        job_id: &DerivationJobId,
        runtime: &Arc<JobRuntime>,
        operation: super::control::ActiveOperation,
        outcome: MediaProcessOutcome<T>,
        report: F,
        failure_code: DerivationFailureCode,
    ) -> Result<(), MediaNormalizerError>
    where
        F: FnOnce(T) -> crate::normalization::DerivationWorkerReport,
    {
        match outcome {
            MediaProcessOutcome::Completed { value, .. } => {
                let result = self.reduce(job_id, DerivationCommand::Worker(report(value)), false);
                operation.finish();
                result.map(|_| ())
            }
            MediaProcessOutcome::Stopped { reason, .. } => {
                self.reduce_worker_stopped(job_id, runtime, operation, reason)
            }
            MediaProcessOutcome::Failed { failure, .. } => self.reduce_worker_failed(
                job_id,
                runtime,
                operation,
                failure_code,
                failure.retryable(),
                failure.sanitized_detail(),
            ),
        }
    }

    fn reduce_worker_stopped(
        &self,
        job_id: &DerivationJobId,
        _runtime: &Arc<JobRuntime>,
        operation: super::control::ActiveOperation,
        reason: ProcessStopReason,
    ) -> Result<(), MediaNormalizerError> {
        let result = self.reduce(
            job_id,
            DerivationCommand::Worker(
                crate::normalization::DerivationWorkerReport::ProcessStopped(reason),
            ),
            false,
        );
        operation.finish();
        result.map(|_| ())
    }

    fn reduce_worker_failed(
        &self,
        job_id: &DerivationJobId,
        _runtime: &Arc<JobRuntime>,
        operation: super::control::ActiveOperation,
        code: DerivationFailureCode,
        retryable: bool,
        detail: &str,
    ) -> Result<(), MediaNormalizerError> {
        let result = self.reduce(
            job_id,
            DerivationCommand::Worker(crate::normalization::DerivationWorkerReport::StageFailed {
                code,
                retryable,
            }),
            false,
        );
        operation.finish();
        result.map(|_| ()).map_err(|error| match error {
            MediaNormalizerError::Worker(_) => error,
            _ => MediaNormalizerError::Worker(detail.to_string()),
        })
    }

    fn fail_stage(
        &self,
        job_id: &DerivationJobId,
        code: DerivationFailureCode,
        retryable: bool,
    ) -> Result<(), MediaNormalizerError> {
        self.fail_stage_with_detail(
            job_id,
            code,
            retryable,
            "normalization stage failed".to_string(),
        )
    }

    fn fail_stage_with_detail(
        &self,
        job_id: &DerivationJobId,
        code: DerivationFailureCode,
        retryable: bool,
        detail: String,
    ) -> Result<(), MediaNormalizerError> {
        let _ = self.reduce(
            job_id,
            DerivationCommand::Worker(crate::normalization::DerivationWorkerReport::StageFailed {
                code,
                retryable,
            }),
            false,
        )?;
        let _ = detail;
        Ok(())
    }

    fn fail_from_run(
        &self,
        job_id: &DerivationJobId,
        snapshot: DerivationSnapshot,
        detail: String,
        retryable: bool,
    ) -> NormalizerRunOutcome {
        let code = DerivationFailureCode::IntegrityMismatch;
        let _ = self.reduce(
            job_id,
            DerivationCommand::Worker(crate::normalization::DerivationWorkerReport::StageFailed {
                code,
                retryable,
            }),
            false,
        );
        NormalizerRunOutcome::Failed {
            snapshot: Some(snapshot),
            detail,
        }
    }

    fn load(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<Option<super::ports::StoredDerivation>, MediaNormalizerError> {
        self.repository
            .load_derivation(job_id)
            .map_err(repository_error)
    }

    /// Reduce one public/internal command. Persistent effects are first
    /// interpreted by `DerivationJob::apply_committed_effect`, then CASed;
    /// non-persistent effects are handled only after the durable effect list
    /// reaches the matching version.
    fn reduce(
        &self,
        job_id: &DerivationJobId,
        command: DerivationCommand,
        schedule: bool,
    ) -> Result<Option<DerivationSnapshot>, MediaNormalizerError> {
        self.reduce_inner(job_id, command, schedule, None)
    }

    fn reduce_with_commit(
        &self,
        job_id: &DerivationJobId,
        completion: DerivedCompletion,
        manifest: DerivedManifest,
        evidence: DerivedCommitEvidence,
        schedule: bool,
    ) -> Result<Option<DerivationSnapshot>, MediaNormalizerError> {
        self.reduce_inner(
            job_id,
            DerivationCommand::Worker(
                crate::normalization::DerivationWorkerReport::CommitCompleted(completion),
            ),
            schedule,
            Some(CommitContext {
                completion_manifest: manifest,
                evidence,
            }),
        )
    }

    fn reduce_inner(
        &self,
        job_id: &DerivationJobId,
        command: DerivationCommand,
        schedule: bool,
        commit_context: Option<CommitContext>,
    ) -> Result<Option<DerivationSnapshot>, MediaNormalizerError> {
        let runtime = self.runtimes.runtime_for(job_id);
        let mut should_dispatch = false;
        let mut await_reap = false;
        let mut remove = false;
        let mut stop_reason = None;
        let mut snapshot_after = None;
        {
            let _guard = runtime.command();
            let Some(stored) = self.load(job_id)? else {
                return Err(MediaNormalizerError::NotFound(job_id.clone()));
            };
            if matches!(
                &command,
                DerivationCommand::Resume | DerivationCommand::SourceAvailable
            ) {
                runtime.process.clear_stop();
            }
            let mut domain = rehydrate(&stored.snapshot)
                .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
            let decision = domain.decide(command);
            match decision.outcome() {
                DerivationOutcome::Rejected(reason) => {
                    return Err(MediaNormalizerError::Rejected(reason.clone()))
                }
                DerivationOutcome::NoOp => return Ok(Some(stored.snapshot)),
                DerivationOutcome::Accepted => {}
            }
            for effect in decision.effects() {
                match effect {
                    DerivationEffect::CommitState { .. }
                    | DerivationEffect::SetDesiredState { .. }
                    | DerivationEffect::PersistProbe { .. }
                    | DerivationEffect::PersistPlan { .. }
                    | DerivationEffect::SetCurrentPair { .. }
                    | DerivationEffect::CommitPairCheckpoint { .. } => {
                        let next = domain
                            .apply_committed_effect(effect)
                            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
                        let outcome = self
                            .repository
                            .compare_and_swap(
                                job_id,
                                effect_expected_version(effect),
                                &next,
                                &self.clock.now_rfc3339(),
                            )
                            .map_err(repository_error)?;
                        let accepted = match outcome {
                            SnapshotSwapOutcome::Applied(value)
                            | SnapshotSwapOutcome::AlreadyApplied(value) => value,
                            SnapshotSwapOutcome::Stale(value) => {
                                return Err(MediaNormalizerError::Stale {
                                    expected: effect_expected_version(effect),
                                    actual: value.snapshot.version(),
                                })
                            }
                            SnapshotSwapOutcome::Missing => {
                                return Err(MediaNormalizerError::NotFound(job_id.clone()))
                            }
                        };
                        domain = rehydrate(&accepted.snapshot)
                            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
                        snapshot_after = Some(accepted.snapshot);
                    }
                    DerivationEffect::PublishCompletion { .. } => {
                        let context = commit_context.as_ref().ok_or_else(|| {
                            MediaNormalizerError::Worker(
                                "publish completion missing manifest context".to_string(),
                            )
                        })?;
                        let next = domain
                            .apply_committed_effect(effect)
                            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
                        let completion = match effect {
                            DerivationEffect::PublishCompletion { completion, .. } => completion,
                            _ => unreachable!(),
                        };
                        let outcome = self
                            .repository
                            .commit_derived_verified(
                                job_id,
                                effect_expected_version(effect),
                                &next,
                                completion,
                                &context.completion_manifest,
                                &context.evidence,
                                &self.clock.now_rfc3339(),
                            )
                            .map_err(repository_error)?;
                        let accepted = match outcome {
                            SnapshotSwapOutcome::Applied(value)
                            | SnapshotSwapOutcome::AlreadyApplied(value) => value,
                            SnapshotSwapOutcome::Stale(value) => {
                                return Err(MediaNormalizerError::Stale {
                                    expected: effect_expected_version(effect),
                                    actual: value.snapshot.version(),
                                })
                            }
                            SnapshotSwapOutcome::Missing => {
                                return Err(MediaNormalizerError::NotFound(job_id.clone()))
                            }
                        };
                        snapshot_after = Some(accepted.snapshot.clone());
                        domain = rehydrate(&accepted.snapshot)
                            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
                    }
                    DerivationEffect::RequestProcessStop(reason) => {
                        stop_reason = Some(*reason);
                        runtime.process.request_stop(*reason);
                    }
                    DerivationEffect::AwaitProcessReap => await_reap = true,
                    DerivationEffect::DiscardCurrentPartialPair { segment_index } => {
                        self.staging
                            .discard_pair(job_id, *segment_index)
                            .map_err(staging_error_to_normalizer)?;
                    }
                    DerivationEffect::Dispatch => should_dispatch = true,
                    DerivationEffect::RemoveJob => remove = true,
                }
            }
            if remove {
                self.repository
                    .retire_derivation(job_id)
                    .map_err(repository_error)?;
                self.runtimes.remove(job_id);
            }

            // If no child has started yet, settle a stop under the same job
            // mutex. A worker racing to begin must observe the resulting
            // RetryWait/Cancelled state and cannot spawn after acknowledgement.
            if await_reap && !runtime.process.is_active() {
                if let Some(reason) = stop_reason {
                    drop(_guard);
                    let _ = self.reduce(
                        job_id,
                        DerivationCommand::Worker(
                            crate::normalization::DerivationWorkerReport::ProcessStopped(reason),
                        ),
                        false,
                    )?;
                    await_reap = false;
                }
            }
        }

        if await_reap {
            let deadline = Instant::now() + runtime.process.stop_wait_timeout();
            if !runtime.process.wait_until_idle_until(deadline) {
                return Err(MediaNormalizerError::ResourceStuck(format!(
                    "derivation job {job_id} did not become idle after a process stop request"
                )));
            }
        }
        if should_dispatch && schedule {
            self.scheduler.enqueue(job_id).map_err(repository_error)?;
        }
        let snapshot = self.load(job_id)?.map(|stored| stored.snapshot);
        Ok(snapshot.or(snapshot_after))
    }
}

impl MediaNormalizer for MediaNormalizerExecutor {
    fn start(
        &self,
        spec: DerivationSpec,
    ) -> Result<crate::normalization::DerivationStartOutcome, MediaNormalizerError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(MediaNormalizerError::ShuttingDown);
        }
        spec.profile()
            .require_approved()
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let expected_build = self.encoder.encoder_build();
        if expected_build != spec.encoder_build().clone() {
            return Err(MediaNormalizerError::Worker(
                "encoder build does not match approved derivation spec".to_string(),
            ));
        }
        let job = DerivationJob::new(spec.clone())
            .map_err(|error| MediaNormalizerError::Worker(error.to_string()))?;
        let initial = job.snapshot();
        let outcome = self
            .repository
            .create_derivation(&spec, &initial, &self.clock.now_rfc3339())
            .map_err(repository_error)?;
        let (result, should_enqueue) = match outcome {
            CreateDerivationOutcome::Created(stored) => (
                crate::normalization::DerivationStartOutcome::Created {
                    job_id: stored.snapshot.spec().job_id().clone(),
                },
                true,
            ),
            CreateDerivationOutcome::Existing(stored) => (
                crate::normalization::DerivationStartOutcome::Existing {
                    job_id: stored.snapshot.spec().job_id().clone(),
                },
                !stored.snapshot.state().is_terminal()
                    && stored.snapshot.desired_state()
                        == crate::normalization::DerivationDesiredState::Run,
            ),
            CreateDerivationOutcome::Conflict {
                existing_job_id, ..
            } => (
                crate::normalization::DerivationStartOutcome::Conflict { existing_job_id },
                false,
            ),
        };
        if should_enqueue {
            let job_id = match &result {
                crate::normalization::DerivationStartOutcome::Created { job_id }
                | crate::normalization::DerivationStartOutcome::Existing { job_id } => job_id,
                crate::normalization::DerivationStartOutcome::Conflict { .. } => unreachable!(),
            };
            self.scheduler.enqueue(job_id).map_err(repository_error)?;
        }
        Ok(result)
    }

    fn command(
        &self,
        job_id: &DerivationJobId,
        command: DerivationCommand,
    ) -> Result<DerivationSnapshot, MediaNormalizerError> {
        if self.shutting_down.load(Ordering::Acquire)
            && !matches!(&command, DerivationCommand::Cancel)
        {
            return Err(MediaNormalizerError::ShuttingDown);
        }
        let snapshot = self
            .reduce(job_id, command, true)?
            .ok_or_else(|| MediaNormalizerError::NotFound(job_id.clone()))?;
        if let DerivationJobState::Failed {
            code: DerivationFailureCode::ResourceStuck,
            ..
        } = snapshot.state()
        {
            return Err(MediaNormalizerError::Worker(
                "encoder process remained alive after terminate/kill deadlines".to_string(),
            ));
        }
        Ok(snapshot)
    }

    fn snapshot(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<Option<DerivationSnapshot>, MediaNormalizerError> {
        self.load(job_id)
            .map(|stored| stored.map(|stored| stored.snapshot))
    }

    fn snapshots(&self) -> Result<Vec<DerivationSnapshot>, MediaNormalizerError> {
        self.repository
            .list_derivations()
            .map_err(repository_error)
            .map(|items| items.into_iter().map(|item| item.snapshot).collect())
    }

    fn recover(&self) -> Result<Vec<DerivationSnapshot>, MediaNormalizerError> {
        let items = self
            .repository
            .list_derivations()
            .map_err(repository_error)?;
        let mut snapshots = Vec::with_capacity(items.len());
        for item in items {
            let snapshot = item.snapshot;
            let job_id = snapshot.spec().job_id().clone();
            if !snapshot.state().is_terminal()
                && snapshot.desired_state() == crate::normalization::DerivationDesiredState::Run
            {
                self.scheduler.enqueue(&job_id).map_err(repository_error)?;
            }
            snapshots.push(snapshot);
        }
        Ok(snapshots)
    }

    fn shutdown(&self) -> Result<(), MediaNormalizerError> {
        self.shutting_down.store(true, Ordering::Release);
        let runtimes = self.runtimes.all();
        for runtime in &runtimes {
            runtime.process.request_stop(ProcessStopReason::Shutdown);
        }
        let timeout = runtimes
            .first()
            .map(|runtime| runtime.process.stop_wait_timeout())
            .unwrap_or_default();
        let deadline = Instant::now() + timeout;
        for runtime in runtimes {
            if !runtime.process.wait_until_idle_until(deadline) {
                return Err(MediaNormalizerError::ResourceStuck(
                    "an active normalization operation did not stop before the shutdown deadline"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

struct CommitContext {
    completion_manifest: DerivedManifest,
    evidence: DerivedCommitEvidence,
}

fn effect_expected_version(effect: &DerivationEffect) -> u64 {
    match effect {
        DerivationEffect::CommitState {
            expected_version, ..
        }
        | DerivationEffect::SetDesiredState {
            expected_version, ..
        }
        | DerivationEffect::PersistProbe {
            expected_version, ..
        }
        | DerivationEffect::PersistPlan {
            expected_version, ..
        }
        | DerivationEffect::SetCurrentPair {
            expected_version, ..
        }
        | DerivationEffect::CommitPairCheckpoint {
            expected_version, ..
        }
        | DerivationEffect::PublishCompletion {
            expected_version, ..
        } => *expected_version,
        _ => 0,
    }
}

fn map_process_failure(code: MediaProcessFailureCode) -> DerivationFailureCode {
    match code {
        MediaProcessFailureCode::ExecutableUnavailable
        | MediaProcessFailureCode::SpawnRejected
        | MediaProcessFailureCode::EncodeRejected => DerivationFailureCode::EncoderFailed,
        MediaProcessFailureCode::ProbeRejected => DerivationFailureCode::ProbeFailed,
        MediaProcessFailureCode::ValidationRejected | MediaProcessFailureCode::InvalidOutput => {
            DerivationFailureCode::ValidationFailed
        }
        MediaProcessFailureCode::DeadlineExceeded => DerivationFailureCode::DeadlineExceeded,
        MediaProcessFailureCode::ResourceStuck => DerivationFailureCode::ResourceStuck,
        MediaProcessFailureCode::Io => DerivationFailureCode::Disk,
        MediaProcessFailureCode::Internal => DerivationFailureCode::Internal,
    }
}

fn terminal_outcome(snapshot: DerivationSnapshot) -> NormalizerRunOutcome {
    match snapshot.state() {
        DerivationJobState::DerivedVerified => NormalizerRunOutcome::Completed(snapshot),
        DerivationJobState::Cancelled => NormalizerRunOutcome::Cancelled(snapshot),
        DerivationJobState::Failed { .. } => NormalizerRunOutcome::Failed {
            snapshot: Some(snapshot),
            detail: "derivation job failed".to_string(),
        },
        _ => NormalizerRunOutcome::Idle(snapshot),
    }
}

fn repository_error(error: MediaNormalizerPortError) -> MediaNormalizerError {
    MediaNormalizerError::Repository(error.to_string())
}

fn staging_error_to_normalizer(error: StagingError) -> MediaNormalizerError {
    MediaNormalizerError::Worker(error.to_string())
}

fn rehydrate(
    snapshot: &DerivationSnapshot,
) -> Result<DerivationJob, crate::normalization::DerivationSpecError> {
    DerivationJob::rehydrate(
        snapshot.spec().clone(),
        snapshot.state().clone(),
        snapshot.desired_state(),
        snapshot.version(),
        snapshot.probe_report().cloned(),
        snapshot.media_plan().cloned(),
        snapshot.checkpoints().to_vec(),
        snapshot.current_pair(),
        snapshot.completion().cloned(),
    )
}
