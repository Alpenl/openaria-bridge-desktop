//! Ubuntu session-pipeline adapter for the removable-media MVP.
//!
//! This adapter owns the cross-job admission boundary, not the child workers.
//! It atomically persists a real durable import and one core
//! [`SessionPipeline`] that refers to that exact admitted source and import
//! job before any worker starts. The current Ubuntu composition deliberately
//! has no reviewed quality evaluator, so normalize/upload policies are
//! retained as durable intent but are blocked by a persisted policy action
//! rather than by invented derived or upload jobs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{SecondsFormat, Utc};
use serde_json::json;
use ylx_transfer_adapters::derived_upload::{
    DerivedUploadAdapter, ObjectUploadPhase, UploadBundleCheckpoint,
};
use ylx_transfer_core::ingest::{
    LocalSourceReceipt, SafeRelativePath, SourceProvenance, SourceRecording, SourceVideoCodec,
};
use ylx_transfer_core::media_pipeline::{
    DerivationNaturalKey, FrozenUploadBundle, LocalDerivedReceipt, PipelineActionRequired,
    PipelineCommand as CorePipelineCommand, PipelineEvidence, PipelinePolicy as CorePipelinePolicy,
    RestartReplayDecision, SessionPipeline, StorageProfileIdentity,
};
use ylx_transfer_core::media_store::{
    CreateImportJobError, LibraryImportReceipt, MediaStore, MediaStoreError, PipelineSnapshot,
};
use ylx_transfer_core::normalization::{
    DerivationJobState as CoreDerivationJobState, NormalizationProfile, ProfileRevision,
};
use ylx_transfer_core::persistence::{JobStateTag, StoredJob, TransferStore};
use ylx_transfer_core::recording_ingestor::{ArtifactSourceResolver, CandidateCatalog};

use super::ports::{
    MediaEffect, MediaErrorCode, MediaNormalizerPort, MediaPortError, MediaProjectionDelta,
    MediaProjectionSet, Observed, SessionPipelinePort,
};
use super::types::{
    CandidateId, DerivationJobId as WireDerivationJobId, DerivationJobState, DerivedLayer,
    DerivedLayerState, ImportJob, ImportJobId, ImportJobState, MediaScanSnapshot,
    PipelineBatchItemResult, PipelineBatchOutcome, PipelineCommand, PipelineId, PipelinePolicy,
    PipelineSession, ProfileId, RemoteLayer, RemoteLayerState, RequiredAction, RequiredActionKind,
    SourceId, SourceLayer, SourceLayerState, SourceRetentionState, StartDerivationRequest,
    StartPipelineRequest, UploadBundleId, UploadProgress,
};
use super::ubuntu::UbuntuDestinationGuard;
use super::ubuntu_ingestor::{UbuntuLibraryRootGate, UbuntuRecordingIngestor};
use super::ubuntu_projection::{
    map_derivation_collection, map_derivation_job, map_import_job, map_pipeline_source_summary,
    MAX_JAVASCRIPT_SAFE_INTEGER,
};
use super::ubuntu_uploader::UbuntuDerivedUploader;

const QUALITY_ACTION_CODE: &str = "quality_evaluation_required";
const QUALITY_ACTION_MESSAGE: &str =
    "Normalization is blocked until an approved profile and a configured VMAF, SSIM, or domain quality evaluator are available; no derivation job has been created";

/// Composition configuration that is safe to retain in the durable pipeline.
///
/// `storage_profile_identity` is deliberately optional. An automatic derived
/// upload cannot be admitted without an identity bound to a real storage
/// configuration, so a missing value is rejected before the import mutates.
#[derive(Debug, Clone, Default)]
pub struct UbuntuPipelineConfig {
    storage_profile_identity: Option<StorageProfileIdentity>,
}

impl UbuntuPipelineConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_storage_profile_identity(identity: StorageProfileIdentity) -> Self {
        Self {
            storage_profile_identity: Some(identity),
        }
    }

    #[must_use]
    pub fn storage_profile_identity(&self) -> Option<&StorageProfileIdentity> {
        self.storage_profile_identity.as_ref()
    }
}

/// Real first-stage Ubuntu implementation of [`SessionPipelinePort`].
///
/// The generic runtime is the same candidate/admission and artifact resolver
/// used by [`UbuntuRecordingIngestor`]. It is never reconstructed from wire
/// DTOs, which keeps source identity and the mounted-media generation fence
/// intact through import admission.
pub struct UbuntuPipelinePort<C, R> {
    ingestor: Arc<UbuntuRecordingIngestor<C, R>>,
    store: Arc<Mutex<MediaStore>>,
    transfer_store: Mutex<Option<Arc<Mutex<TransferStore>>>>,
    config: UbuntuPipelineConfig,
    normalizer: Mutex<Option<Arc<dyn MediaNormalizerPort>>>,
    uploader: Mutex<Option<Arc<UbuntuDerivedUploader>>>,
    operation_gate: Mutex<()>,
}

impl<C, R> UbuntuPipelinePort<C, R>
where
    C: CandidateCatalog + ArtifactSourceResolver + UbuntuDestinationGuard + Send + Sync + 'static,
    R: UbuntuLibraryRootGate,
{
    /// Creates the pipeline adapter around the already assembled durable
    /// import executor and its exact `MediaStore` owner.
    #[must_use]
    pub fn new(
        ingestor: Arc<UbuntuRecordingIngestor<C, R>>,
        store: Arc<Mutex<MediaStore>>,
        config: UbuntuPipelineConfig,
    ) -> Self {
        Self {
            ingestor,
            store,
            transfer_store: Mutex::new(None),
            config,
            normalizer: Mutex::new(None),
            uploader: Mutex::new(None),
            operation_gate: Mutex::new(()),
        }
    }

    /// Connects the pipeline aggregate to the concrete downstream owners once
    /// composition has finished probing the optional Ubuntu normalizer.
    /// Import admission remains usable when the normalizer is unavailable;
    /// the owner then retains a durable policy action instead of creating a
    /// fake derivation job.
    pub fn set_downstream_owners(
        &self,
        normalizer: Arc<dyn MediaNormalizerPort>,
        uploader: Arc<UbuntuDerivedUploader>,
        transfer_store: Arc<Mutex<TransferStore>>,
    ) {
        *lock(&self.normalizer) = Some(normalizer);
        *lock(&self.uploader) = Some(uploader);
        *lock(&self.transfer_store) = Some(transfer_store);
    }

    /// Reconciles every durable pipeline after a worker commits progress.
    /// The aggregate and each dependent job remain separate durable records;
    /// this method only attaches exact natural-key dependencies and republishes
    /// the aggregate through its expected-version CAS.
    pub fn reconcile_all(&self) -> Result<(), MediaPortError> {
        let _gate = lock(&self.operation_gate);
        self.reconcile_all_locked()
    }

    /// Erases a shared adapter without giving up its recovery projection API.
    ///
    /// The composition root keeps this `Arc` while building the lifecycle,
    /// then passes the returned trait object to `MediaApplicationPorts`.
    #[must_use]
    pub fn as_port(self: &Arc<Self>) -> Arc<dyn SessionPipelinePort> {
        self.clone()
    }

    /// Reads complete pipeline projections from their authoritative durable
    /// collection revision. The import layer is read from the same process
    /// owner and embedded only as a projection; its job state is never copied
    /// into the core `SessionPipeline` aggregate.
    pub fn pipelines_projection(&self) -> Result<Observed<Vec<PipelineSession>>, MediaPortError> {
        let imports = self.ingestor.imports_projection()?;
        self.pipelines_projection_for_imports(&imports)
    }

    /// Reads every durable projection needed by Ubuntu startup after the
    /// caller has supplied its scanner-owned observation. This supersedes the
    /// older generic recovery mapper once pipeline rows exist: pipeline
    /// lifecycle state is mapped here alongside the import projection that it
    /// embeds.
    pub fn durable_projections(
        &self,
        scan: Observed<MediaScanSnapshot>,
    ) -> Result<MediaProjectionSet, MediaPortError> {
        ensure_wire_safe("scan collection revision", scan.source_version)?;
        let imports = self.ingestor.imports_projection()?;
        let collection = lock(&self.store)
            .derivation_projection()
            .map_err(|error| pipeline_store_error("read derivation projection", error))?;
        let derivations = map_derivation_collection(&collection)?;
        let pipelines = self.pipelines_projection_for_imports(&imports)?;
        Ok(MediaProjectionSet {
            scan,
            imports,
            derivations,
            pipelines,
            // The application-owned projector supplies this independent
            // collection from AppStore during lifecycle recovery.
            library: Observed::new(0, Vec::new()),
        })
    }

    fn pipelines_projection_for_imports(
        &self,
        imports: &Observed<Vec<ImportJob>>,
    ) -> Result<Observed<Vec<PipelineSession>>, MediaPortError> {
        let collection = lock(&self.store)
            .pipeline_projection()
            .map_err(|error| pipeline_store_error("read pipeline projection", error))?;
        ensure_wire_safe("pipeline collection revision", collection.revision)?;

        let imports_by_id = imports
            .value
            .iter()
            .map(|job| (job.id.as_str(), job))
            .collect::<HashMap<_, _>>();
        let sessions = collection
            .items
            .iter()
            .map(|snapshot| self.map_pipeline_snapshot(snapshot, &imports_by_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Observed::new(collection.revision, sessions))
    }

    fn start_pipeline_effect(
        &self,
        request: StartPipelineRequest,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        self.ingestor
            .with_library_root(|library_root| self.start_pipeline_effect_at(request, library_root))
    }

    fn start_pipeline_effect_at(
        &self,
        request: StartPipelineRequest,
        library_root: &std::path::Path,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        // There is no safe storage-profile placeholder. Refuse before source
        // admission so this error never hides a newly-created import.
        if request.policy.auto_upload_derived && self.config.storage_profile_identity().is_none() {
            return Err(storage_not_configured(&request.candidate_id));
        }

        let _gate = lock(&self.operation_gate);
        let prepared = self.ingestor.prepare_import_for_pipeline_at(
            request.candidate_id.clone(),
            request.approve_unsigned,
            library_root,
        )?;
        let core_policy = core_policy_for(&request.policy, &prepared.source, &self.config)?;
        // Everything needed for the mandatory post-commit result is checked
        // before admission. Once the transaction returns, ordinary adapter or
        // projection failures must not hide the durable import and pipeline.
        map_pipeline_source_summary(&prepared.source)?;
        // Import-only pipelines are complete after their import dependency;
        // only policies that request a derivation carry the durable quality
        // evaluator blocker.
        let requested_action = (!matches!(&core_policy, CorePipelinePolicy::ImportOnly))
            .then(quality_action)
            .transpose()?;
        let action = self.preflight_existing_pipeline(
            &prepared.source,
            &core_policy,
            requested_action.as_ref(),
        )?;

        let (admitted, mut session) = lock(&self.store)
            .create_import_job_and_session_pipeline_validated(
                &prepared.spec,
                &prepared.source,
                &core_policy,
                action.as_ref(),
                &now_rfc3339(),
                |outcome| {
                    let import = map_import_job(&outcome.import)
                        .map_err(|_| atomic_projection_validation_error())?;
                    let imports = HashMap::from([(import.id.as_str(), &import)]);
                    map_pipeline_snapshot_basic(&outcome.pipeline, &imports)
                        .map_err(|_| atomic_projection_validation_error())
                },
            )
            .map_err(pipeline_import_store_error)?;

        // The durable intent now exists. Build the mandatory response from
        // the atomic outcome, then treat worker advancement and complete
        // collection reads as best effort. A single row is never published as
        // though it were an authoritative complete collection.
        let mut projections = MediaProjectionDelta::default();

        if let Ok(import_effect) = self.ingestor.continue_import_for_pipeline_at(
            &admitted.import,
            &prepared.source,
            library_root,
        ) {
            session.desired_run_state = import_effect.result.desired_run_state;
            session.source_summary.media_id = import_effect.result.media_id.clone();
            session.source_summary.source_id = import_effect.result.source_id.clone();
            session.source = source_layer(&import_effect.result);
            projections.merge(import_effect.projections);
        }

        let _ = self.reconcile_pipeline_locked(&admitted.pipeline);
        let _ = self.refresh_pipeline_projection(&admitted.pipeline);
        if let Ok(pipelines) = self.pipelines_projection() {
            if let Some(latest) = pipelines
                .value
                .iter()
                .find(|pipeline| pipeline.id.as_str() == admitted.pipeline.pipeline_id)
                .cloned()
            {
                session = latest;
                projections.merge(MediaProjectionDelta {
                    pipelines: Some(pipelines),
                    ..MediaProjectionDelta::default()
                });
            }
        }
        Ok(MediaEffect::new(session, projections))
    }

    fn command_pipeline_effect(
        &self,
        pipeline_id: PipelineId,
        command: PipelineCommand,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        self.ingestor.with_library_root(|library_root| {
            self.command_pipeline_effect_at(pipeline_id, command, library_root)
        })
    }

    fn command_pipeline_effect_at(
        &self,
        pipeline_id: PipelineId,
        command: PipelineCommand,
        library_root: &std::path::Path,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        let _gate = lock(&self.operation_gate);
        let snapshot = self.pipeline_snapshot(&pipeline_id)?;
        if matches!(command, PipelineCommand::ApproveUnsignedUpload) {
            let import_id = snapshot.pipeline.import_dependency().job_id().as_str();
            let receipt = lock(&self.store)
                .import_receipt_for_job(import_id)
                .map_err(|error| {
                    pipeline_store_error("read source receipt for upload approval", error)
                })?
                .ok_or_else(|| {
                    MediaPortError::new(
                        MediaErrorCode::PolicyApprovalRequired,
                        "unsigned upload approval requires a locally verified source receipt",
                    )
                    .with_retryable(false)
                })?;
            let local = local_source_receipt(snapshot.pipeline.source(), &receipt)?;
            if !matches!(
                local.provenance(),
                SourceProvenance::LocallyValidatedUnsigned(_)
            ) {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    "unsigned upload approval applies only to locally validated unsigned sources",
                )
                .with_retryable(false));
            }
            let CorePipelinePolicy::AutoUpload {
                storage_profile_identity,
                source_archival,
                ..
            } = snapshot.pipeline.policy()
            else {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    "unsigned upload approval requires an automatic upload policy",
                )
                .with_retryable(false));
            };
            let derivation_job_id = snapshot
                .pipeline
                .derivation_dependency()
                .ok_or_else(|| {
                    MediaPortError::new(
                        MediaErrorCode::PolicyApprovalRequired,
                        "unsigned upload approval requires a verified derivation",
                    )
                    .with_retryable(false)
                })?
                .job_id()
                .as_str();
            let uploader = lock(&self.uploader).clone().ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::StorageNotConfigured,
                    "unsigned upload approval requires the configured derived uploader",
                )
                .with_retryable(false)
            })?;
            let request = uploader.approval_request_for_derivation(
                derivation_job_id,
                storage_profile_identity.clone(),
                source_archival.clone(),
            )?;
            if request.source_revision() != local.content_revision()
                || request.inventory_digest() != local.inventory_digest()
            {
                return Err(MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "unsigned upload approval request differs from the pipeline source receipt",
                )
                .with_retryable(false));
            }
            let admission = request
                .admit("desktop-user", now_rfc3339())
                .map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::PolicyApprovalRequired,
                        format!("cannot issue unsigned upload admission receipt: {error}"),
                    )
                    .with_retryable(false)
                })?;
            let mut pipeline = snapshot.pipeline.clone();
            match pipeline.command(CorePipelineCommand::RecordUnsignedAdmission {
                receipt: Box::new(admission),
            }) {
                ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Attached
                | ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Existing => {}
                ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Conflict { reason } => {
                    return Err(MediaPortError::new(
                        MediaErrorCode::OperationConflict,
                        format!("cannot record unsigned upload admission: {reason:?}"),
                    )
                    .with_retryable(false));
                }
            }
            let updated = lock(&self.store)
                .replace_pipeline_projection(
                    &snapshot.pipeline_id,
                    snapshot.pipeline_version,
                    &pipeline,
                    None,
                    &now_rfc3339(),
                )
                .map_err(|error| pipeline_store_error("record unsigned upload admission", error))?;
            let _ = self.reconcile_pipeline_locked(&updated);
            let pipelines = self.pipelines_projection()?;
            let session = find_pipeline_session(&pipelines, pipeline_id.as_str())?;
            return Ok(MediaEffect::new(
                session,
                MediaProjectionDelta {
                    pipelines: Some(pipelines),
                    ..MediaProjectionDelta::default()
                },
            ));
        }

        let import_command = match command {
            PipelineCommand::Pause => super::types::MediaJobCommand::Pause,
            PipelineCommand::Resume => super::types::MediaJobCommand::Resume,
            PipelineCommand::Cancel => super::types::MediaJobCommand::Cancel,
            PipelineCommand::Retry => super::types::MediaJobCommand::Retry,
            PipelineCommand::ApproveUnsignedUpload => unreachable!("handled above"),
        };
        let import_effect = self.ingestor.command_import_effect_at(
            ImportJobId::new(snapshot.pipeline.import_dependency().job_id().as_str()),
            import_command,
            library_root,
        )?;
        let refreshed = self.refresh_pipeline_projection(&snapshot)?;
        let _ = self.reconcile_pipeline_locked(&refreshed);
        let pipelines = self.pipelines_projection()?;
        let session = find_pipeline_session(&pipelines, &refreshed.pipeline_id)?;
        let mut projections = import_effect.projections;
        projections.merge(MediaProjectionDelta {
            pipelines: Some(pipelines),
            ..MediaProjectionDelta::default()
        });
        Ok(MediaEffect::new(session, projections))
    }

    fn retry_derived_upload_effect(
        &self,
        parent_job_id: &str,
    ) -> Result<MediaEffect<String>, MediaPortError> {
        let _gate = lock(&self.operation_gate);
        let uploader = lock(&self.uploader).clone().ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::StorageNotConfigured,
                "derived upload retry is unavailable because no uploader is configured",
            )
            .with_retryable(false)
            .with_detail("capability", json!("derived_upload_retry"))
        })?;
        // This transaction creates (or reuses) a dormant typed child. It must
        // remain dormant until the pipeline dependency CAS below is durable.
        let prepared = uploader.prepare_retry(parent_job_id)?;
        let retry_job_id = ylx_transfer_core::transfer::JobId(prepared.job_id.clone());
        let expected_parent = ylx_transfer_core::transfer::JobId(parent_job_id.to_string());

        let snapshots = lock(&self.store)
            .list_pipeline_snapshots()
            .map_err(|error| pipeline_store_error("locate derived upload retry owner", error))?;
        let mut owners = snapshots.into_iter().filter(|snapshot| {
            snapshot
                .pipeline
                .upload_dependency()
                .is_some_and(|dependency| {
                    dependency.job_id() == &expected_parent || dependency.job_id() == &retry_job_id
                })
        });
        let snapshot = owners.next().ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "derived upload retry parent is not attached to a durable pipeline",
            )
            .with_retryable(false)
            .with_detail("parent_job_id", json!(parent_job_id))
            .with_detail("retry_job_id", json!(prepared.job_id.clone()))
        })?;
        if owners.next().is_some() {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "derived upload retry is referenced by more than one durable pipeline",
            )
            .with_retryable(false)
            .with_detail("parent_job_id", json!(parent_job_id))
            .with_detail("retry_job_id", json!(prepared.job_id.clone())));
        }

        let natural_key = snapshot
            .pipeline
            .upload_dependency()
            .expect("owner selection requires an upload dependency")
            .natural_key()
            .clone();
        if natural_key.upload_bundle_revision.as_str() != prepared.bundle_revision {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "derived upload retry bundle revision differs from its pipeline dependency",
            )
            .with_retryable(false)
            .with_detail("pipeline_id", json!(snapshot.pipeline_id))
            .with_detail("retry_job_id", json!(prepared.job_id.clone())));
        }

        let mut pipeline = snapshot.pipeline.clone();
        match pipeline.replace_upload_attempt(&expected_parent, natural_key, retry_job_id) {
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Attached => {
                lock(&self.store)
                    .replace_pipeline_projection(
                        &snapshot.pipeline_id,
                        snapshot.pipeline_version,
                        &pipeline,
                        snapshot.action_required.as_ref(),
                        &now_rfc3339(),
                    )
                    .map_err(|error| {
                        pipeline_store_error("attach derived upload retry dependency", error)
                    })?;
            }
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Existing => {}
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Conflict { reason } => {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    format!("cannot attach derived upload retry dependency: {reason:?}"),
                )
                .with_retryable(false)
                .with_detail("pipeline_id", json!(snapshot.pipeline_id))
                .with_detail("retry_job_id", json!(prepared.job_id.clone())));
            }
        }

        // Build the complete owner projection before releasing the worker. If
        // this read fails, the durable child stays dormant and a replayed retry
        // can safely reuse it and try publication again.
        let pipelines = self.pipelines_projection()?;
        uploader.wake_upload(&prepared.job_id)?;
        Ok(MediaEffect::new(
            prepared.job_id,
            MediaProjectionDelta {
                pipelines: Some(pipelines),
                ..MediaProjectionDelta::default()
            },
        ))
    }

    fn pipeline_snapshot(
        &self,
        pipeline_id: &PipelineId,
    ) -> Result<PipelineSnapshot, MediaPortError> {
        lock(&self.store)
            .pipeline_snapshot(pipeline_id.as_str())
            .map_err(|error| pipeline_store_error("read session pipeline", error))?
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::PipelineCommandFailed,
                    "the requested durable session pipeline does not exist",
                )
                .with_retryable(false)
                .with_detail("pipeline_id", json!(pipeline_id.as_str()))
            })
    }

    fn pipeline_snapshot_for_source(
        &self,
        source: &SourceRecording,
    ) -> Result<Option<PipelineSnapshot>, MediaPortError> {
        let source_key = source.revision_claim().as_str();
        let collection = lock(&self.store)
            .pipeline_projection()
            .map_err(|error| pipeline_store_error("read pipeline admission", error))?;
        Ok(collection
            .items
            .into_iter()
            .find(|snapshot| snapshot.source_key == source_key))
    }

    fn preflight_existing_pipeline(
        &self,
        source: &SourceRecording,
        policy: &CorePipelinePolicy,
        action: Option<&PipelineActionRequired>,
    ) -> Result<Option<PipelineActionRequired>, MediaPortError> {
        let Some(existing) = self.pipeline_snapshot_for_source(source)? else {
            return Ok(action.cloned());
        };
        if existing.pipeline.policy() != policy {
            return Err(MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "the requested policy conflicts with the existing durable source pipeline",
            )
            .with_retryable(false)
            .with_detail("pipeline_id", json!(existing.pipeline_id))
            .with_detail("capability", json!("pipeline_policy")));
        }
        // An existing pipeline may already have advanced from the initial
        // quality blocker to a derivation, unsigned-admission, or upload
        // state. Re-admission must reuse its exact durable action, including
        // `None` after the blocker was resolved; reintroducing the original
        // preflight action would make an idempotent re-admission conflict with
        // normal lifecycle progress.
        Ok(existing.action_required.clone())
    }

    fn reconcile_all_locked(&self) -> Result<(), MediaPortError> {
        let snapshots = lock(&self.store)
            .list_pipeline_snapshots()
            .map_err(|error| pipeline_store_error("list session pipelines for replay", error))?;
        for snapshot in snapshots {
            self.reconcile_pipeline_locked(&snapshot)?;
        }
        Ok(())
    }

    fn reconcile_pipeline_locked(
        &self,
        snapshot: &PipelineSnapshot,
    ) -> Result<PipelineSnapshot, MediaPortError> {
        if matches!(snapshot.pipeline.policy(), CorePipelinePolicy::ImportOnly) {
            return Ok(snapshot.clone());
        }

        let import_id = snapshot.pipeline.import_dependency().job_id().as_str();
        let Some(import) = lock(&self.store)
            .import_receipt_for_job(import_id)
            .map_err(|error| {
                pipeline_store_error("read source import receipt for replay", error)
            })?
        else {
            // The import completion outbox is still the authority for the
            // local-verified transition. Until it exists, replay remains
            // `Awaiting Import` and creates no downstream job.
            return Ok(snapshot.clone());
        };
        let local_source = local_source_receipt(snapshot.pipeline.source(), &import)?;
        let source_revision = local_source.content_revision().clone();
        let profile_revision = snapshot
            .pipeline
            .policy()
            .profile_revision()
            .expect("non-import policy always has a profile revision")
            .clone();
        let derivation_key = DerivationNaturalKey {
            source_revision,
            profile_revision,
        };

        let mut current = self.pipeline_snapshot(&PipelineId::new(&snapshot.pipeline_id))?;
        if current.pipeline.derivation_dependency().is_none() {
            let decision = current
                .pipeline
                .replay(PipelineEvidence {
                    source: Some(&local_source),
                    derived: None,
                    unsigned_upload_request: None,
                    bundle: None,
                    remote: None,
                })
                .map_err(|error| pipeline_replay_error("replay derivation admission", error))?;
            if let RestartReplayDecision::EnqueueDerivation { natural_key } = decision {
                if !self.ensure_derivation_locked(&current, natural_key)? {
                    return Ok(current);
                }
                current = self.pipeline_snapshot(&PipelineId::new(&snapshot.pipeline_id))?;
            }
        }

        let Some(derivation_dependency) = current.pipeline.derivation_dependency() else {
            return Ok(current);
        };
        if derivation_dependency.natural_key() != &derivation_key {
            return Err(MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "the durable derivation dependency does not match the current source/profile natural key",
            )
            .with_retryable(false)
            .with_detail("pipeline_id", json!(current.pipeline_id))
            .with_detail("capability", json!("derivation_natural_key")));
        }
        let Some(derived) = self.local_derived_receipt(derivation_dependency.job_id())? else {
            // The dependency is attached before its completion receipt exists;
            // no policy action is needed while the real derivation job runs.
            return self.replace_pipeline_action_if_needed(&current, None);
        };

        if matches!(
            current.pipeline.policy(),
            CorePipelinePolicy::AutoNormalize { .. }
        ) {
            return self.replace_pipeline_action_if_needed(&current, None);
        }

        let (bundle, remote) = self.upload_evidence(&current)?;
        let unsigned_upload_request = if matches!(
            local_source.provenance(),
            SourceProvenance::LocallyValidatedUnsigned(_)
        ) {
            Some(match bundle.as_ref() {
                Some(bundle) => bundle
                    .unsigned_upload_admission_request()
                    .map_err(|error| {
                        MediaPortError::new(
                            MediaErrorCode::IntegrityFailed,
                            format!("cannot rebuild durable upload approval request: {error}"),
                        )
                        .with_retryable(false)
                    })?,
                None => {
                    let uploader = lock(&self.uploader).clone().ok_or_else(|| {
                        MediaPortError::new(
                            MediaErrorCode::StorageNotConfigured,
                            "unsigned upload replay requires the configured derived uploader",
                        )
                        .with_retryable(false)
                    })?;
                    let CorePipelinePolicy::AutoUpload {
                        storage_profile_identity,
                        source_archival,
                        ..
                    } = current.pipeline.policy()
                    else {
                        return Err(MediaPortError::new(
                            MediaErrorCode::OperationConflict,
                            "unsigned upload replay requires an automatic upload policy",
                        )
                        .with_retryable(false));
                    };
                    uploader.approval_request_for_derivation(
                        derivation_dependency.job_id().as_str(),
                        storage_profile_identity.clone(),
                        source_archival.clone(),
                    )?
                }
            })
        } else {
            None
        };
        let decision = current
            .pipeline
            .replay(PipelineEvidence {
                source: Some(&local_source),
                derived: Some(&derived),
                unsigned_upload_request: unsigned_upload_request.as_ref(),
                bundle: bundle.as_ref(),
                remote: remote.as_ref(),
            })
            .map_err(|error| pipeline_replay_error("replay upload admission", error))?;
        match decision {
            RestartReplayDecision::ActionRequired { action } => {
                self.replace_pipeline_action_if_needed(&current, Some(action))
            }
            RestartReplayDecision::FreezeUploadBundle { .. }
            | RestartReplayDecision::EnqueueUpload { .. } => {
                if !self.ensure_upload_locked(&current, &derived, &local_source)? {
                    return Ok(current);
                }
                Ok(self.pipeline_snapshot(&PipelineId::new(&snapshot.pipeline_id))?)
            }
            RestartReplayDecision::Awaiting { .. } | RestartReplayDecision::Complete => {
                self.replace_pipeline_action_if_needed(&current, None)
            }
            RestartReplayDecision::EnqueueDerivation { natural_key } => {
                if self.ensure_derivation_locked(&current, natural_key)? {
                    self.pipeline_snapshot(&PipelineId::new(&snapshot.pipeline_id))
                } else {
                    Ok(current)
                }
            }
        }
    }

    fn ensure_derivation_locked(
        &self,
        snapshot: &PipelineSnapshot,
        natural_key: DerivationNaturalKey,
    ) -> Result<bool, MediaPortError> {
        if snapshot.pipeline.derivation_dependency().is_some() {
            return Ok(true);
        }
        let source_id = SourceId::new(natural_key.source_revision.as_str());
        let request = StartDerivationRequest {
            source_id,
            profile_id: ProfileId::new(natural_key.profile_revision.as_str()),
        };
        let existing = lock(&self.store)
            .derivation_projection()
            .map_err(|error| pipeline_store_error("read derivation natural-key replay", error))?
            .items
            .into_iter()
            .find(|job| {
                job.spec.source_revision() == &natural_key.source_revision
                    && job.spec.profile_revision() == &natural_key.profile_revision
            });
        let job_id = if let Some(existing) = existing {
            existing.spec.job_id().clone()
        } else {
            let Some(normalizer) = lock(&self.normalizer).clone() else {
                return Ok(false);
            };
            let effect = match normalizer.start_derivation(request) {
                Ok(effect) => effect,
                Err(_) => {
                    // Capability/profile failure is represented by the
                    // already durable policy action. Do not manufacture a
                    // derivation row just to make the pipeline look active.
                    return Ok(false);
                }
            };
            ylx_transfer_core::normalization::DerivationJobId::parse(effect.result.id.as_str())
                .map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        format!("normalizer returned an invalid durable job id: {error}"),
                    )
                    .with_retryable(false)
                })?
        };

        let mut pipeline = snapshot.pipeline.clone();
        match pipeline.attach_derivation(natural_key, job_id) {
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Attached
            | ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Existing => {}
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Conflict { reason } => {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    format!("cannot attach derivation dependency: {reason:?}"),
                )
                .with_retryable(false));
            }
        }
        lock(&self.store)
            .replace_pipeline_projection(
                &snapshot.pipeline_id,
                snapshot.pipeline_version,
                &pipeline,
                None,
                &now_rfc3339(),
            )
            .map_err(|error| pipeline_store_error("attach derivation dependency", error))?;
        Ok(true)
    }

    fn ensure_upload_locked(
        &self,
        snapshot: &PipelineSnapshot,
        _derived: &LocalDerivedReceipt,
        local_source: &LocalSourceReceipt,
    ) -> Result<bool, MediaPortError> {
        let Some(uploader) = lock(&self.uploader).clone() else {
            return Ok(false);
        };
        let CorePipelinePolicy::AutoUpload {
            storage_profile_identity,
            source_archival,
            ..
        } = snapshot.pipeline.policy()
        else {
            return Ok(false);
        };
        let unsigned_admission = snapshot.pipeline.unsigned_admission().cloned();
        let derivation_job_id = snapshot
            .pipeline
            .derivation_dependency()
            .expect("upload policy requires a derivation dependency")
            .job_id()
            .as_str();
        let prepared = uploader.prepare_for_derivation(
            derivation_job_id,
            storage_profile_identity.clone(),
            source_archival.clone(),
            unsigned_admission,
        )?;
        let transfer_store = lock(&self.transfer_store).clone().ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::StorageNotConfigured,
                "derived upload owner has no transfer-store recovery handle",
            )
            .with_retryable(false)
        })?;
        let stored = lock(&transfer_store)
            .derived_upload_job(&prepared.job_id)
            .map_err(|error| pipeline_external_store_error("read frozen upload bundle", error))?
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "derived upload enqueue returned no durable sidecar",
                )
                .with_retryable(false)
            })?;
        let bundle: FrozenUploadBundle =
            serde_json::from_str(&stored.frozen_bundle_json).map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    format!("frozen upload bundle cannot be decoded: {error}"),
                )
                .with_retryable(false)
            })?;
        if bundle.source_revision() != local_source.content_revision() {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "frozen upload bundle source revision differs from the verified import",
            )
            .with_retryable(false));
        }
        if bundle.storage_profile_identity() != storage_profile_identity {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "frozen upload bundle destination differs from the pipeline policy",
            )
            .with_retryable(false));
        }
        let natural_key = bundle.natural_key();
        let job_id = ylx_transfer_core::transfer::JobId(prepared.job_id.clone());
        let mut pipeline = snapshot.pipeline.clone();
        match pipeline.attach_upload(natural_key, job_id) {
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Attached
            | ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Existing => {}
            ylx_transfer_core::media_pipeline::DependencyAttachOutcome::Conflict { reason } => {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    format!("cannot attach upload dependency: {reason:?}"),
                )
                .with_retryable(false));
            }
        }
        let result = lock(&self.store)
            .replace_pipeline_projection(
                &snapshot.pipeline_id,
                snapshot.pipeline_version,
                &pipeline,
                None,
                &now_rfc3339(),
            )
            .map_err(|error| pipeline_store_error("attach upload dependency", error))?;
        // The worker is released only after the pipeline dependency CAS is
        // durable. A crash before this point leaves a harmless prepared row;
        // replay will attach it before issuing the wake-up.
        uploader.wake_upload(&prepared.job_id)?;
        let _ = result;
        Ok(true)
    }

    fn local_derived_receipt(
        &self,
        job_id: &ylx_transfer_core::normalization::DerivationJobId,
    ) -> Result<Option<LocalDerivedReceipt>, MediaPortError> {
        let stored = lock(&self.store)
            .derivation_job(job_id)
            .map_err(|error| pipeline_store_error("read derivation completion", error))?;
        let Some(stored) = stored else {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "pipeline derivation dependency refers to a missing durable job",
            )
            .with_retryable(false));
        };
        if stored.snapshot.state() != &CoreDerivationJobState::DerivedVerified {
            return Ok(None);
        }
        let completion = stored.snapshot.completion().ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "verified derivation has no durable completion evidence",
            )
            .with_retryable(false)
        })?;
        let receipt = lock(&self.store)
            .derived_receipt_for_job(job_id.as_str())
            .map_err(|error| pipeline_store_error("read derived completion receipt", error))?;
        if receipt.is_none() {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "verified derivation has no durable local receipt",
            )
            .with_retryable(false));
        }
        LocalDerivedReceipt::from_completion(job_id.clone(), completion)
            .map(Some)
            .map_err(|error| pipeline_replay_error("build local derived receipt", error))
    }

    fn upload_evidence(
        &self,
        snapshot: &PipelineSnapshot,
    ) -> Result<
        (
            Option<FrozenUploadBundle>,
            Option<ylx_transfer_core::media_pipeline::RemoteBundleReceipt>,
        ),
        MediaPortError,
    > {
        let Some(dependency) = snapshot.pipeline.upload_dependency() else {
            return Ok((None, None));
        };
        let transfer_store = lock(&self.transfer_store).clone().ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::StorageNotConfigured,
                "pipeline upload dependency has no transfer-store owner",
            )
            .with_retryable(false)
        })?;
        let stored = lock(&transfer_store)
            .derived_upload_job(dependency.job_id().as_str())
            .map_err(|error| pipeline_external_store_error("read upload replay sidecar", error))?
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "pipeline upload dependency refers to a missing durable sidecar",
                )
                .with_retryable(false)
            })?;
        let bundle: FrozenUploadBundle =
            serde_json::from_str(&stored.frozen_bundle_json).map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    format!("upload replay bundle is invalid: {error}"),
                )
                .with_retryable(false)
            })?;
        let stored_storage_identity = StorageProfileIdentity::parse(
            stored.storage_profile_identity.clone(),
        )
        .map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                format!("upload replay storage identity is invalid: {error}"),
            )
            .with_retryable(false)
        })?;
        if bundle.storage_profile_identity() != &stored_storage_identity
            || bundle.natural_key() != *dependency.natural_key()
        {
            return Err(MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "upload sidecar natural key differs from the pipeline dependency",
            )
            .with_retryable(false));
        }
        let job = lock(&transfer_store)
            .get_job(dependency.job_id().as_str())
            .map_err(|error| pipeline_external_store_error("read upload replay state", error))?
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "pipeline upload dependency refers to a missing transfer job",
                )
                .with_retryable(false)
            })?;
        let checkpoint: UploadBundleCheckpoint = serde_json::from_str(&stored.checkpoint_json)
            .map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    format!("upload replay checkpoint is invalid: {error}"),
                )
                .with_retryable(false)
            })?;
        let remote = if job.state == JobStateTag::Succeeded {
            Some(
                DerivedUploadAdapter::remote_bundle_from_checkpoint(
                    &bundle,
                    StorageProfileIdentity::parse(stored.storage_profile_identity.clone())
                        .map_err(|error| {
                            MediaPortError::new(
                                MediaErrorCode::IntegrityFailed,
                                format!("upload replay storage identity is invalid: {error}"),
                            )
                            .with_retryable(false)
                        })?,
                    &checkpoint,
                )
                .map_err(|error| pipeline_replay_error("rebuild remote upload receipt", error))?,
            )
        } else {
            None
        };
        Ok((Some(bundle), remote))
    }

    fn map_pipeline_snapshot(
        &self,
        snapshot: &PipelineSnapshot,
        imports_by_id: &HashMap<&str, &ImportJob>,
    ) -> Result<PipelineSession, MediaPortError> {
        let import_id = snapshot.pipeline.import_dependency().job_id().as_str();
        let import = imports_by_id.get(import_id).copied().ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "a durable pipeline refers to an import absent from the import projection",
            )
            .with_retryable(true)
            .with_detail("pipeline_id", json!(snapshot.pipeline_id))
            .with_detail("import_job_id", json!(import_id))
        })?;
        let (derived, remote) = self.map_dependent_layers(snapshot, import)?;
        let policy = map_wire_policy(&snapshot.pipeline);
        let mut source_summary = map_pipeline_source_summary(snapshot.pipeline.source())?;
        source_summary.media_id = import.media_id.clone();
        if import.source_id.is_some() {
            source_summary.source_id = import.source_id.clone();
        }
        Ok(PipelineSession {
            id: PipelineId::new(&snapshot.pipeline_id),
            candidate_id: CandidateId::new(snapshot.pipeline.source().candidate_id().as_str()),
            source_summary,
            policy,
            desired_run_state: import.desired_run_state,
            source: source_layer(import),
            derived,
            remote,
            created_at: snapshot.created_at.clone(),
            updated_at: snapshot.updated_at.clone(),
        })
    }

    fn map_dependent_layers(
        &self,
        snapshot: &PipelineSnapshot,
        import: &ImportJob,
    ) -> Result<(DerivedLayer, RemoteLayer), MediaPortError> {
        if matches!(snapshot.pipeline.policy(), CorePipelinePolicy::ImportOnly) {
            return Ok((
                DerivedLayer {
                    state: DerivedLayerState::NotStarted,
                    derived_id: None,
                    job_id: None,
                    progress: None,
                    validation: None,
                    action: None,
                    failure: None,
                },
                RemoteLayer {
                    state: RemoteLayerState::Disabled,
                    bundle_id: None,
                    upload_job_id: None,
                    progress: None,
                    action: None,
                    failure: None,
                },
            ));
        }

        let required_action = snapshot.action_required.as_ref().map(map_required_action);
        let derived = if let Some(dependency) = snapshot.pipeline.derivation_dependency() {
            let job_id = ylx_transfer_core::normalization::DerivationJobId::parse(
                dependency.job_id().as_str(),
            )
            .map_err(|error| pipeline_replay_error("parse derivation dependency", error))?;
            let stored = lock(&self.store)
                .derivation_job(&job_id)
                .map_err(|error| {
                    pipeline_store_error("read derivation pipeline projection", error)
                })?
                .ok_or_else(|| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        "pipeline derivation dependency has no durable job row",
                    )
                    .with_retryable(false)
                })?;
            let projected = map_derivation_job(&stored)?;
            DerivedLayer {
                state: if !matches!(import.state, ImportJobState::LocalVerified) {
                    DerivedLayerState::WaitingForSource
                } else {
                    map_derived_layer_state(projected.state)
                },
                derived_id: projected.derived_id,
                job_id: Some(projected.id),
                progress: Some(projected.progress),
                validation: Some(projected.validation),
                action: None,
                failure: projected.failure,
            }
        } else if let Some(action) = required_action.clone() {
            DerivedLayer {
                state: if matches!(import.state, ImportJobState::LocalVerified) {
                    DerivedLayerState::ActionRequired
                } else {
                    DerivedLayerState::WaitingForSource
                },
                derived_id: None,
                job_id: None,
                progress: None,
                validation: None,
                action: Some(action),
                failure: None,
            }
        } else {
            DerivedLayer {
                state: if matches!(import.state, ImportJobState::LocalVerified) {
                    DerivedLayerState::Queued
                } else {
                    DerivedLayerState::WaitingForSource
                },
                derived_id: None,
                job_id: None,
                progress: None,
                validation: None,
                action: None,
                failure: None,
            }
        };

        let remote = if !matches!(
            snapshot.pipeline.policy(),
            CorePipelinePolicy::AutoUpload { .. }
        ) {
            RemoteLayer {
                state: RemoteLayerState::Disabled,
                bundle_id: None,
                upload_job_id: None,
                progress: None,
                action: None,
                failure: None,
            }
        } else if let Some(dependency) = snapshot.pipeline.upload_dependency() {
            let (bundle, remote_evidence) = self.upload_evidence(snapshot)?;
            let bundle = bundle.ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "upload dependency has no frozen bundle",
                )
                .with_retryable(false)
            })?;
            let transfer_store = lock(&self.transfer_store).clone().ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::StorageNotConfigured,
                    "upload projection has no transfer-store owner",
                )
                .with_retryable(false)
            })?;
            let stored = lock(&transfer_store)
                .derived_upload_job(dependency.job_id().as_str())
                .map_err(|error| {
                    pipeline_external_store_error("read upload pipeline projection", error)
                })?
                .ok_or_else(|| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        "upload dependency has no durable sidecar",
                    )
                    .with_retryable(false)
                })?;
            let checkpoint: UploadBundleCheckpoint = serde_json::from_str(&stored.checkpoint_json)
                .map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        format!("upload checkpoint cannot be projected: {error}"),
                    )
                    .with_retryable(false)
                })?;
            let job = lock(&transfer_store)
                .get_job(dependency.job_id().as_str())
                .map_err(|error| {
                    pipeline_external_store_error("read upload transfer state", error)
                })?
                .ok_or_else(|| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        "upload dependency has no transfer job row",
                    )
                    .with_retryable(false)
                })?;
            let state = if remote_evidence.is_some() {
                RemoteLayerState::ObjectStoreVerified
            } else {
                map_remote_layer_state(job.state)
            };
            let progress = upload_progress(&checkpoint)?;
            RemoteLayer {
                state,
                bundle_id: Some(UploadBundleId::new(bundle.revision().as_str())),
                upload_job_id: Some(dependency.job_id().as_str().to_string()),
                progress: Some(progress),
                action: if matches!(state, RemoteLayerState::ActionRequired) {
                    required_action
                } else {
                    None
                },
                failure: map_upload_failure(&job),
            }
        } else {
            RemoteLayer {
                state: if matches!(derived.state, DerivedLayerState::DerivedVerified) {
                    if required_action.is_some() {
                        RemoteLayerState::ActionRequired
                    } else {
                        RemoteLayerState::WaitingForDerived
                    }
                } else {
                    RemoteLayerState::WaitingForDerived
                },
                bundle_id: None,
                upload_job_id: None,
                progress: None,
                action: required_action,
                failure: None,
            }
        };
        Ok((derived, remote))
    }

    fn replace_pipeline_action_if_needed(
        &self,
        snapshot: &PipelineSnapshot,
        action: Option<PipelineActionRequired>,
    ) -> Result<PipelineSnapshot, MediaPortError> {
        if snapshot.action_required == action {
            return Ok(snapshot.clone());
        }
        lock(&self.store)
            .replace_pipeline_projection(
                &snapshot.pipeline_id,
                snapshot.pipeline_version,
                &snapshot.pipeline,
                action.as_ref(),
                &now_rfc3339(),
            )
            .map_err(|error| pipeline_store_error("update pipeline action", error))
    }

    /// Bump the core pipeline collection revision after a committed import
    /// dependency transition. The aggregate remains unchanged, but the app
    /// projection embeds the import's durable state, so its owner publishes a
    /// new complete snapshot via the documented expected-version CAS.
    fn refresh_pipeline_projection(
        &self,
        snapshot: &PipelineSnapshot,
    ) -> Result<PipelineSnapshot, MediaPortError> {
        lock(&self.store)
            .replace_pipeline_projection(
                &snapshot.pipeline_id,
                snapshot.pipeline_version,
                &snapshot.pipeline,
                snapshot.action_required.as_ref(),
                &now_rfc3339(),
            )
            .map_err(|error| pipeline_store_error("refresh session pipeline projection", error))
    }
}

impl<C, R> SessionPipelinePort for UbuntuPipelinePort<C, R>
where
    C: CandidateCatalog + ArtifactSourceResolver + UbuntuDestinationGuard + Send + Sync + 'static,
    R: UbuntuLibraryRootGate,
{
    fn start_pipeline(
        &self,
        request: StartPipelineRequest,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        self.start_pipeline_effect(request)
    }

    fn start_pipeline_batch(
        &self,
        requests: Vec<StartPipelineRequest>,
    ) -> Result<MediaEffect<PipelineBatchOutcome>, MediaPortError> {
        let mut projections = MediaProjectionDelta::default();
        let mut results = Vec::with_capacity(requests.len());

        for request in requests {
            let item = request.candidate_id.clone();
            match self.start_pipeline_effect(request) {
                Ok(effect) => {
                    let job_id = effect.result.id.clone();
                    projections.merge(effect.projections);
                    results.push(PipelineBatchItemResult::Success { item, job_id });
                }
                Err(error) => results.push(PipelineBatchItemResult::Failure {
                    item,
                    error: error.into_rpc(),
                }),
            }
        }

        // Every request above was evaluated independently. There is no
        // batch-wide preflight failure, so `operation_error` remains reserved
        // for a true operation-level fault rather than being copied into every
        // tagged item error.
        Ok(MediaEffect::new(
            PipelineBatchOutcome {
                results,
                operation_error: None,
            },
            projections,
        ))
    }

    fn command_pipeline(
        &self,
        pipeline_id: PipelineId,
        command: PipelineCommand,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        self.command_pipeline_effect(pipeline_id, command)
    }

    fn retry_derived_upload(
        &self,
        parent_job_id: &str,
    ) -> Result<MediaEffect<String>, MediaPortError> {
        self.retry_derived_upload_effect(parent_job_id)
    }
}

fn core_policy_for(
    request: &PipelinePolicy,
    source: &SourceRecording,
    config: &UbuntuPipelineConfig,
) -> Result<CorePipelinePolicy, MediaPortError> {
    if !request.auto_normalize {
        return Ok(CorePipelinePolicy::ImportOnly);
    }

    let profile_revision = profile_revision_for(source)?;
    if request.auto_upload_derived {
        let storage_profile_identity =
            config.storage_profile_identity().cloned().ok_or_else(|| {
                // This is normally caught before import admission. Retain the
                // guard here so a future direct caller cannot introduce a fake
                // storage identity.
                storage_not_configured(&CandidateId::new(source.candidate_id().as_str()))
            })?;
        Ok(CorePipelinePolicy::auto_upload(
            profile_revision,
            storage_profile_identity,
        ))
    } else {
        Ok(CorePipelinePolicy::AutoNormalize { profile_revision })
    }
}

fn profile_revision_for(source: &SourceRecording) -> Result<ProfileRevision, MediaPortError> {
    let profile = match source.media_plan().codec() {
        SourceVideoCodec::Mjpeg => NormalizationProfile::candidate_mjpeg_x265_slow_v1(),
        SourceVideoCodec::H264 => NormalizationProfile::candidate_h264_x265_slow_v1(),
    }
    .map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::PipelineStartFailed,
            format!("cannot construct the Ubuntu normalization policy: {error}"),
        )
        .with_retryable(false)
        .with_detail("capability", json!("normalization_profile"))
    })?;
    Ok(profile.profile_revision().clone())
}

fn quality_action() -> Result<PipelineActionRequired, MediaPortError> {
    PipelineActionRequired::resolve_policy(QUALITY_ACTION_CODE, QUALITY_ACTION_MESSAGE).map_err(
        |error| {
            MediaPortError::new(
                MediaErrorCode::PipelineStartFailed,
                format!("cannot persist the Ubuntu quality-policy blocker: {error}"),
            )
            .with_retryable(false)
        },
    )
}

fn map_pipeline_snapshot_basic(
    snapshot: &PipelineSnapshot,
    imports_by_id: &HashMap<&str, &ImportJob>,
) -> Result<PipelineSession, MediaPortError> {
    let import_id = snapshot.pipeline.import_dependency().job_id().as_str();
    let import = imports_by_id.get(import_id).copied().ok_or_else(|| {
        MediaPortError::new(
            MediaErrorCode::OperationConflict,
            "a durable pipeline refers to an import absent from the import projection",
        )
        .with_retryable(true)
        .with_detail("pipeline_id", json!(snapshot.pipeline_id))
        .with_detail("import_job_id", json!(import_id))
    })?;
    let policy = map_wire_policy(&snapshot.pipeline);
    let source = source_layer(import);
    let (derived, remote) = basic_dependent_layers(snapshot);
    let mut source_summary = map_pipeline_source_summary(snapshot.pipeline.source())?;
    source_summary.media_id = import.media_id.clone();
    if import.source_id.is_some() {
        source_summary.source_id = import.source_id.clone();
    }

    Ok(PipelineSession {
        id: PipelineId::new(&snapshot.pipeline_id),
        candidate_id: CandidateId::new(snapshot.pipeline.source().candidate_id().as_str()),
        source_summary,
        policy,
        desired_run_state: import.desired_run_state,
        source,
        derived,
        remote,
        created_at: snapshot.created_at.clone(),
        updated_at: snapshot.updated_at.clone(),
    })
}

fn map_wire_policy(pipeline: &SessionPipeline) -> PipelinePolicy {
    let policy = pipeline.policy();
    PipelinePolicy {
        auto_normalize: !matches!(policy, CorePipelinePolicy::ImportOnly),
        auto_upload_derived: matches!(policy, CorePipelinePolicy::AutoUpload { .. }),
        upload_source_video: false,
        // A user checkbox is not a valid unsigned upload admission. Only a
        // receipt bound to verified source bytes may make this true.
        unsigned_upload_approved: pipeline.unsigned_admission().is_some(),
    }
}

fn source_layer(import: &ImportJob) -> SourceLayer {
    SourceLayer {
        state: match import.state {
            ImportJobState::Queued => SourceLayerState::Queued,
            ImportJobState::WaitingForMedia => SourceLayerState::WaitingForMedia,
            ImportJobState::Preflighting => SourceLayerState::Preflighting,
            ImportJobState::Copying => SourceLayerState::Copying,
            ImportJobState::Verifying => SourceLayerState::Verifying,
            ImportJobState::Committing => SourceLayerState::Committing,
            ImportJobState::LocalVerified => SourceLayerState::LocalVerified,
            ImportJobState::RetryWait => SourceLayerState::RetryWait,
            ImportJobState::Pausing => SourceLayerState::Pausing,
            ImportJobState::Paused => SourceLayerState::Paused,
            ImportJobState::Cancelling => SourceLayerState::Cancelling,
            ImportJobState::Cancelled => SourceLayerState::Cancelled,
            ImportJobState::Failed => SourceLayerState::Failed,
        },
        source_id: import.source_id.clone(),
        job_id: Some(import.id.clone()),
        retention_state: if matches!(import.state, ImportJobState::LocalVerified) {
            SourceRetentionState::Retained
        } else {
            // Import state alone cannot prove source-tree absence or removal.
            SourceRetentionState::Unknown
        },
        progress: Some(import.progress.clone()),
        failure: import.failure.clone(),
    }
}

fn basic_dependent_layers(snapshot: &PipelineSnapshot) -> (DerivedLayer, RemoteLayer) {
    let policy = snapshot.pipeline.policy();
    let action = snapshot.action_required.as_ref();
    if matches!(policy, CorePipelinePolicy::ImportOnly) {
        return (
            DerivedLayer {
                state: DerivedLayerState::NotStarted,
                derived_id: None,
                job_id: None,
                progress: None,
                validation: None,
                action: None,
                failure: None,
            },
            RemoteLayer {
                state: RemoteLayerState::Disabled,
                bundle_id: None,
                upload_job_id: None,
                progress: None,
                action: None,
                failure: None,
            },
        );
    }
    let action = action.map(map_required_action);
    let derived = DerivedLayer {
        state: if snapshot.pipeline.derivation_dependency().is_some() {
            DerivedLayerState::Queued
        } else if action.is_some() {
            DerivedLayerState::ActionRequired
        } else {
            DerivedLayerState::WaitingForSource
        },
        derived_id: None,
        job_id: snapshot
            .pipeline
            .derivation_dependency()
            .map(|dependency| WireDerivationJobId::new(dependency.job_id().as_str())),
        progress: None,
        validation: None,
        action,
        failure: None,
    };
    let remote = RemoteLayer {
        // A durable storage identity may be present for AutoUpload, but a
        // verified derived artifact does not exist yet and no upload was
        // enqueued. This is intentionally not `queued` or `uploading`.
        state: if matches!(policy, CorePipelinePolicy::AutoUpload { .. }) {
            RemoteLayerState::WaitingForDerived
        } else {
            RemoteLayerState::Disabled
        },
        bundle_id: None,
        upload_job_id: None,
        progress: None,
        action: None,
        failure: None,
    };
    (derived, remote)
}

fn map_derived_layer_state(state: DerivationJobState) -> DerivedLayerState {
    match state {
        DerivationJobState::Queued => DerivedLayerState::Queued,
        DerivationJobState::WaitingForSource => DerivedLayerState::WaitingForSource,
        DerivationJobState::Probing => DerivedLayerState::Probing,
        DerivationJobState::Planning => DerivedLayerState::Planning,
        DerivationJobState::Encoding => DerivedLayerState::Encoding,
        DerivationJobState::Validating => DerivedLayerState::Validating,
        DerivationJobState::Committing => DerivedLayerState::Committing,
        DerivationJobState::DerivedVerified => DerivedLayerState::DerivedVerified,
        DerivationJobState::RetryWait => DerivedLayerState::RetryWait,
        DerivationJobState::Pausing => DerivedLayerState::Pausing,
        DerivationJobState::Paused => DerivedLayerState::Paused,
        DerivationJobState::Cancelling => DerivedLayerState::Cancelling,
        DerivationJobState::Cancelled => DerivedLayerState::Cancelled,
        DerivationJobState::Failed => DerivedLayerState::Failed,
    }
}

fn map_remote_layer_state(state: JobStateTag) -> RemoteLayerState {
    match state {
        JobStateTag::Queued
        | JobStateTag::WaitingForDevice
        | JobStateTag::WaitingForPairing
        | JobStateTag::Preparing => RemoteLayerState::Queued,
        JobStateTag::PausedCaptureActive => RemoteLayerState::Paused,
        JobStateTag::Transferring => RemoteLayerState::Uploading,
        JobStateTag::Verifying | JobStateTag::Committing => RemoteLayerState::Verifying,
        JobStateTag::RetryWait => RemoteLayerState::RetryWait,
        JobStateTag::Cancelling => RemoteLayerState::Cancelling,
        JobStateTag::Succeeded => RemoteLayerState::ObjectStoreVerified,
        JobStateTag::Failed => RemoteLayerState::Failed,
        JobStateTag::Cancelled => RemoteLayerState::Cancelled,
    }
}

fn map_upload_failure(job: &StoredJob) -> Option<crate::application::RpcError> {
    let Some((code, retryable)) = &job.error else {
        return None;
    };
    Some(
        MediaPortError::new(
            MediaErrorCode::RemoteVerificationFailed,
            "derived upload failed",
        )
        .with_retryable(*retryable)
        .with_detail("upload_failure", json!(code))
        .into_rpc(),
    )
}

fn upload_progress(checkpoint: &UploadBundleCheckpoint) -> Result<UploadProgress, MediaPortError> {
    let mut uploaded_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut current_part = None;
    let mut total_parts = None;
    for object in checkpoint.objects() {
        total_bytes = total_bytes
            .checked_add(object.size_bytes())
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "derived upload progress exceeds the u64 range",
                )
                .with_retryable(false)
            })?;
        match object.phase() {
            ObjectUploadPhase::Pending => {}
            ObjectUploadPhase::Uploading {
                part_size_bytes,
                completed_parts,
                ..
            } => {
                if *part_size_bytes == 0 {
                    return Err(MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        "derived upload checkpoint has a zero part size",
                    )
                    .with_retryable(false));
                }
                let completed = u64::try_from(completed_parts.len()).map_err(|_| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        "derived upload part count exceeds the u64 range",
                    )
                    .with_retryable(false)
                })?;
                uploaded_bytes = uploaded_bytes.saturating_add(
                    completed
                        .saturating_mul(*part_size_bytes)
                        .min(object.size_bytes()),
                );
                current_part = u32::try_from(completed.saturating_add(1)).ok();
                let parts = object
                    .size_bytes()
                    .checked_add(*part_size_bytes)
                    .and_then(|value| value.checked_sub(1))
                    .ok_or_else(|| {
                        MediaPortError::new(
                            MediaErrorCode::IntegrityFailed,
                            "derived upload part count exceeds the u64 range",
                        )
                        .with_retryable(false)
                    })?
                    / *part_size_bytes;
                total_parts = u32::try_from(parts).ok();
            }
            ObjectUploadPhase::Completed { .. } | ObjectUploadPhase::Verified { .. } => {
                uploaded_bytes = uploaded_bytes.saturating_add(object.size_bytes());
            }
        }
    }
    ensure_pipeline_javascript_safe(uploaded_bytes, "pipeline.remote.progress.uploaded_bytes")?;
    ensure_pipeline_javascript_safe(total_bytes, "pipeline.remote.progress.total_bytes")?;
    Ok(UploadProgress {
        uploaded_bytes,
        total_bytes,
        current_part,
        total_parts,
        throughput_bytes_per_second: None,
        eta_seconds: None,
    })
}

fn ensure_pipeline_javascript_safe(value: u64, field: &'static str) -> Result<(), MediaPortError> {
    if value <= MAX_JAVASCRIPT_SAFE_INTEGER {
        return Ok(());
    }
    Err(MediaPortError::new(
        MediaErrorCode::IntegrityFailed,
        "durable pipeline value exceeds the JavaScript safe integer range",
    )
    .with_retryable(false)
    .with_detail("field", json!(field))
    .with_detail("value", json!(value.to_string())))
}

fn map_required_action(action: &PipelineActionRequired) -> RequiredAction {
    let (kind, fallback) = match action.code() {
        Some(QUALITY_ACTION_CODE) => (
            RequiredActionKind::ResolvePolicy,
            "An approved quality-evaluation policy is required",
        ),
        Some(_) => (
            RequiredActionKind::ResolvePolicy,
            "A durable pipeline policy must be resolved",
        ),
        None => (
            RequiredActionKind::ApproveUnsignedSource,
            "Explicit approval is required before an unsigned source may be uploaded",
        ),
    };
    RequiredAction {
        kind,
        message: action.message().unwrap_or(fallback).to_string(),
    }
}

fn find_pipeline_session(
    pipelines: &Observed<Vec<PipelineSession>>,
    pipeline_id: &str,
) -> Result<PipelineSession, MediaPortError> {
    pipelines
        .value
        .iter()
        .find(|pipeline| pipeline.id.as_str() == pipeline_id)
        .cloned()
        .ok_or_else(|| {
            MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "a durable pipeline was not present in its collection projection",
            )
            .with_retryable(true)
            .with_detail("pipeline_id", json!(pipeline_id))
        })
}

fn storage_not_configured(candidate_id: &CandidateId) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::StorageNotConfigured,
        "automatic derived upload requires a configuration-bound storage profile identity",
    )
    .with_retryable(false)
    .with_detail("candidate_id", json!(candidate_id.as_str()))
    .with_detail("capability", json!("storage_profile_identity"))
    .with_detail("operation", json!("media_start_pipeline"))
}

fn local_source_receipt(
    source: &SourceRecording,
    import: &LibraryImportReceipt,
) -> Result<LocalSourceReceipt, MediaPortError> {
    if source
        .content_revision()
        .is_none_or(|revision| revision.as_str() != import.source_revision)
    {
        return Err(MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "durable import receipt does not match the pipeline source revision",
        )
        .with_retryable(false));
    }
    let persisted_provenance: SourceProvenance = serde_json::from_value(import.provenance.clone())
        .map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                format!("durable import provenance is invalid: {error}"),
            )
            .with_retryable(false)
        })?;
    if &persisted_provenance != source.provenance() {
        return Err(MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "durable import provenance does not match the admitted pipeline source",
        )
        .with_retryable(false));
    }
    let relative_path = SafeRelativePath::parse(import.local_path.clone()).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("durable import local path is unsafe: {error}"),
        )
        .with_retryable(false)
    })?;
    let commit_receipt = serde_json::to_string(&import.commit_receipt).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("durable import commit evidence is invalid: {error}"),
        )
        .with_retryable(false)
    })?;
    LocalSourceReceipt::new(
        source,
        relative_path,
        commit_receipt,
        import.committed_at.clone(),
    )
    .map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("cannot rebuild the local source receipt: {error}"),
        )
        .with_retryable(false)
    })
}

fn pipeline_replay_error(operation: &'static str, error: impl std::fmt::Display) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::IntegrityFailed,
        format!("{operation} failed: {error}"),
    )
    .with_retryable(false)
}

fn pipeline_store_error(operation: &'static str, error: MediaStoreError) -> MediaPortError {
    let (code, retryable) = match &error {
        MediaStoreError::Conflict { .. } => (MediaErrorCode::OperationConflict, false),
        MediaStoreError::NotFound { .. } => (MediaErrorCode::PipelineCommandFailed, false),
        _ => (MediaErrorCode::PipelineStartFailed, true),
    };
    MediaPortError::new(code, format!("{operation}: {error}"))
        .with_retryable(retryable)
        .with_detail("operation", json!(operation))
        .with_detail("capability", json!("media_store_pipeline"))
}

fn pipeline_external_store_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::PipelineCommandFailed,
        format!("{operation}: {error}"),
    )
    .with_retryable(true)
    .with_detail("operation", json!(operation))
    .with_detail("capability", json!("durable_upload_recovery"))
}

fn pipeline_import_store_error(error: CreateImportJobError) -> MediaPortError {
    match error {
        CreateImportJobError::Conflict(conflict) => MediaPortError::new(
            MediaErrorCode::OperationConflict,
            format!("atomic import and pipeline admission conflicts: {conflict}"),
        )
        .with_retryable(false)
        .with_detail("operation", json!("create_import_job_and_session_pipeline"))
        .with_detail("capability", json!("media_store_atomic_pipeline_admission")),
        CreateImportJobError::Store(error) => {
            pipeline_store_error("atomically create import and session pipeline", error)
        }
    }
}

fn atomic_projection_validation_error() -> MediaStoreError {
    MediaStoreError::Conflict {
        detail: "atomic import and pipeline intent cannot be represented by the Ubuntu projection"
            .to_string(),
    }
}

fn ensure_wire_safe(field: &'static str, value: u64) -> Result<(), MediaPortError> {
    if value > MAX_JAVASCRIPT_SAFE_INTEGER {
        return Err(MediaPortError::new(
            MediaErrorCode::OperationConflict,
            format!("{field} exceeds the JavaScript safe-integer range"),
        )
        .with_retryable(false)
        .with_detail("field", json!(field)));
    }
    Ok(())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use ylx_transfer_core::ingest::{
        AcquisitionSourceId, ConstrainedScanner, InventoryDigest, MediaGeneration, ScanItemOutcome,
        ScanLimits, ScanRequest, ScanSnapshot, SourceKind, SourceRecording, SourceRevisionClaim,
        UnsignedSourceAdmissionReceipt,
    };
    use ylx_transfer_core::recording_ingestor::{
        ArtifactSourceResolver, CandidateCatalog, IngestPortError, ResolvedArtifactSource,
    };

    struct InertCatalog;

    impl CandidateCatalog for InertCatalog {
        fn scan(&self, _request: ScanRequest) -> Result<ScanSnapshot, IngestPortError> {
            panic!("the pipeline preflight test does not scan through the inert catalog")
        }

        fn candidate(
            &self,
            _candidate_id: &ylx_transfer_core::ingest::CandidateId,
        ) -> Result<Option<ylx_transfer_core::ingest::ScanCandidate>, IngestPortError> {
            panic!("the pipeline preflight test does not inspect the inert catalog")
        }

        fn admit(
            &self,
            _candidate_id: &ylx_transfer_core::ingest::CandidateId,
            _policy: &ylx_transfer_core::ingest::ImportPolicy,
        ) -> Result<SourceRecording, IngestPortError> {
            panic!("the pipeline preflight test does not admit through the inert catalog")
        }
    }

    impl ArtifactSourceResolver for InertCatalog {
        fn resolve(
            &self,
            _locator: &ylx_transfer_core::ingest::MediaLocator,
        ) -> Result<ResolvedArtifactSource, IngestPortError> {
            panic!("the pipeline preflight test does not resolve source bytes")
        }
    }

    impl UbuntuDestinationGuard for InertCatalog {
        fn ensure_pc_destination(&self, _library_root: &Path) -> Result<(), MediaPortError> {
            Ok(())
        }
    }

    struct TestRootGate {
        authority: Arc<super::super::library_root::LibraryRootAuthority>,
    }

    impl UbuntuLibraryRootGate for TestRootGate {
        fn with_library_root<T>(&self, operation: impl FnOnce(&Path) -> T) -> T {
            let root = self.authority.current_root();
            operation(&root)
        }

        fn acquire_shared_library_root(
            &self,
            owner: &str,
        ) -> Result<super::super::library_root::LibraryRootLease, MediaPortError> {
            self.authority.acquire_shared(owner)
        }
    }

    fn admitted_source() -> SourceRecording {
        let card = tempfile::tempdir().expect("card tempdir");
        let root = card.path();
        fs::create_dir_all(root.join("video")).expect("video directory");

        let video = b"synthetic-video";
        let session = serde_json::to_vec(&serde_json::json!({
            "schema_version": 7,
            "camera": {
                "width": 1920,
                "height": 1080,
                "fps": 30,
                "layout": "left_right_side_by_side",
                "video_codec": "mjpeg"
            }
        }))
        .expect("session JSON");
        fs::write(root.join("video/stereo_00000.mp4"), video).expect("video");
        fs::write(root.join("session.json"), &session).expect("session");

        let video_digest = format!("{:x}", Sha256::digest(video));
        let session_digest = format!("{:x}", Sha256::digest(&session));
        let manifest = serde_json::json!({
            "schema_version": 1,
            "session_id": "pipeline-preflight-test",
            "revision": format!("sha256:{:x}", Sha256::digest(b"manifest-revision")),
            "captured_at": "2026-08-06T00:00:00Z",
            "published_at": "2026-08-06T00:00:01Z",
            "duration_seconds": 1.0,
            "total_bytes": video.len() + session.len(),
            "video_bytes": video.len(),
            "integrity_ok": true,
            "files": [
                {
                    "id": "video-stereo",
                    "display_path": "video/stereo_00000.mp4",
                    "role": "video_stereo",
                    "size_bytes": video.len(),
                    "sha256": video_digest,
                    "media_type": "video/mp4"
                },
                {
                    "id": "session",
                    "display_path": "session.json",
                    "role": "metadata",
                    "size_bytes": session.len(),
                    "sha256": session_digest,
                    "media_type": "application/json"
                }
            ]
        });
        fs::write(
            root.join("publication_manifest.json"),
            serde_json::to_vec(&manifest).expect("publication manifest"),
        )
        .expect("publication manifest file");

        let source_id = AcquisitionSourceId::parse("pipeline-test-source").expect("source id");
        let request = ScanRequest::selected_directory(
            root,
            source_id.clone(),
            SourceKind::RemovableMedia,
            Some(
                MediaGeneration::new(
                    source_id,
                    "pipeline-test-volume",
                    InventoryDigest::from_material(b"pipeline-test-marker"),
                    1,
                )
                .expect("media generation"),
            ),
        )
        .expect("scan request");
        let snapshot = ConstrainedScanner::new(ScanLimits::default()).scan(&request);
        let ScanItemOutcome::Candidate { candidate } = snapshot
            .items()
            .first()
            .expect("candidate")
            .outcome()
            .clone()
        else {
            panic!("synthetic publication must produce an unsigned candidate")
        };
        let candidate_revision = match candidate.revision_claim() {
            SourceRevisionClaim::Provisional(revision) => revision.clone(),
            SourceRevisionClaim::Published(_) => panic!("unsigned candidate must be provisional"),
        };
        let receipt = UnsignedSourceAdmissionReceipt::new(
            "pipeline-preflight-receipt",
            candidate.id().clone(),
            candidate.locator().media_generation_id().cloned(),
            candidate_revision,
            "pipeline-test-policy",
            "2026-08-06T00:00:00Z",
        )
        .expect("unsigned admission receipt");
        SourceRecording::admit_unsigned(*candidate, Some(receipt))
            .expect("unsigned source admission")
            .with_verified_inventory(InventoryDigest::from_material(b"pipeline-test-inventory"))
    }

    fn pipeline_port(
        root: &TempDir,
    ) -> (
        UbuntuPipelinePort<InertCatalog, TestRootGate>,
        Arc<Mutex<MediaStore>>,
    ) {
        let store = Arc::new(Mutex::new(
            MediaStore::open(root.path().join("media.sqlite3")).expect("media store"),
        ));
        let authority =
            super::super::library_root::LibraryRootAuthority::new(root.path().to_path_buf())
                .expect("root authority");
        let ingestor = Arc::new(
            UbuntuRecordingIngestor::new(
                Arc::new(InertCatalog),
                Arc::clone(&store),
                Arc::new(TestRootGate { authority }),
                super::super::ubuntu_ingestor::UbuntuIngestConfig::new(),
            )
            .expect("ingestor"),
        );
        (
            UbuntuPipelinePort::new(ingestor, Arc::clone(&store), UbuntuPipelineConfig::new()),
            store,
        )
    }

    #[test]
    fn preflight_reuses_cleared_action_for_existing_pipeline() {
        let root = tempfile::tempdir().expect("library tempdir");
        let source = admitted_source();
        let profile_revision = profile_revision_for(&source).expect("profile revision");
        let policy = CorePipelinePolicy::AutoNormalize { profile_revision };
        let import_policy = ylx_transfer_core::ingest::ImportPolicy::new(
            ylx_transfer_core::ingest::UnsignedImportPolicy::RequireAdmissionReceipt,
            u64::MAX,
            0,
        );
        let spec = ylx_transfer_core::ingest::ImportSpec::new(
            ylx_transfer_core::ingest::ImportJobId::new(),
            source.clone(),
            import_policy,
        )
        .expect("import spec");
        let action = quality_action().expect("quality action");
        let (port, store) = pipeline_port(&root);
        let admitted = lock(&store)
            .create_import_job_and_session_pipeline(
                &spec,
                &source,
                &policy,
                Some(&action),
                "2026-08-06T00:00:00Z",
            )
            .expect("atomic pipeline admission");
        let cleared = lock(&store)
            .replace_pipeline_projection(
                &admitted.pipeline.pipeline_id,
                admitted.pipeline.pipeline_version,
                &admitted.pipeline.pipeline,
                None,
                "2026-08-06T00:00:01Z",
            )
            .expect("clear quality action");
        assert!(cleared.action_required.is_none());

        let requested_again = quality_action().expect("quality action");
        let reused = port
            .preflight_existing_pipeline(&source, &policy, Some(&requested_again))
            .expect("existing pipeline preflight");
        assert!(reused.is_none());

        let existing = lock(&store)
            .pipeline_snapshot(&admitted.pipeline.pipeline_id)
            .expect("read pipeline")
            .expect("pipeline remains durable");
        assert_eq!(existing.pipeline_id, admitted.pipeline.pipeline_id);
        assert!(existing.action_required.is_none());
    }
}
