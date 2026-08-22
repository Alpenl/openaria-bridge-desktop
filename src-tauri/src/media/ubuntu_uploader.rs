//! Ubuntu durable owner for derived-media uploads.
//!
//! This module is intentionally an orchestration owner, not a second object
//! store implementation. It builds an immutable bundle from the durable
//! import/derivation evidence, stores that bundle and its checkpoint in the
//! shared `TransferStore`, and lets `DerivedUploadAdapter` perform the actual
//! multipart protocol. A worker turn reloads every durable input before it
//! talks to the network, so a restart or a changed storage setting cannot
//! silently reinterpret an old upload.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{Cursor, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ylx_transfer_adapters::derived_upload::{
    ArtifactReadError, CheckpointPersistenceError, DerivedUploadAdapter, DerivedUploadError,
    LocalArtifactSource, ObjectUploadPhase, UploadBundleCheckpoint, UploadCheckpointSink,
    DEFAULT_MULTIPART_PART_SIZE_BYTES,
};
use ylx_transfer_core::ingest::{
    SafeRelativePath, SourceArtifactClaim, SourceArtifactRole, SourceContentRevision,
    SourceProvenance, SourceRecording,
};
use ylx_transfer_core::library::object_store_port::{DigestProof, SourceSha256};
use ylx_transfer_core::media_library::LibraryEntryKey;
use ylx_transfer_core::media_pipeline::{
    FrozenUploadBundle, LocalArtifactRef, ObjectNamespace, SourceArchivalPolicy,
    StorageProfileIdentity, UnsignedUploadAdmissionReceipt, UnsignedUploadAdmissionRequest,
    UploadBundleInput, UploadObjectInput, UploadObjectRole, DERIVED_UPLOAD_POLICY_REVISION,
};
use ylx_transfer_core::media_store::MediaStore;
use ylx_transfer_core::normalization::{DerivationJobId, DerivationJobState, DerivedOutputRole};
use ylx_transfer_core::persistence::{
    CheckpointSwapOutcome, DerivedUploadJobSpec, DerivedUploadRetryOutcome, JobStateTag,
    TerminalOutcome, TransferStore, UploadActivitySeed, UploadJobError, UploadReceiptDigestProof,
    UploadReceiptRole, UploadReceiptSeed,
};

use crate::composition::Composition;
use crate::models::{StorageConfig, StorageUrlStyle};

use super::library_root::LibraryRootAuthority;
use super::ports::{MediaErrorCode, MediaPortError};
use super::ubuntu_workers::MediaWakeQueue;

const DERIVED_MANIFEST_NAME: &str = "derived_manifest.json";
const GENERATED_PROVENANCE_REF: &str = "generated:provenance-report.json";
const GENERATED_DERIVED_MANIFEST_REF: &str = "generated:derived-manifest.json";
const UPLOAD_WORKER_OWNER: &str = "media_derived_upload_worker";
const PROVENANCE_REPORT_SCHEMA_VERSION: u32 = 1;

const ALLOWLISTED_SOURCE_MARKER_ROLES: [SourceArtifactRole; 5] = [
    SourceArtifactRole::PublicationManifest,
    SourceArtifactRole::SessionManifest,
    SourceArtifactRole::CaptureManifest,
    SourceArtifactRole::CaptureCommit,
    SourceArtifactRole::SpoolIndex,
];

/// Result returned after a frozen bundle was durably prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPrepareResult {
    pub job_id: String,
    pub bundle_revision: String,
    pub created: bool,
}

/// Durable owner of Ubuntu derived-bundle upload jobs.
pub struct UbuntuDerivedUploader {
    media_store: Arc<Mutex<MediaStore>>,
    transfer_store: Arc<Mutex<TransferStore>>,
    app_store: Arc<ylx_transfer_core::persistence::AppStore>,
    composition: Arc<Composition>,
    library_root_authority: Arc<LibraryRootAuthority>,
    queue: Arc<MediaWakeQueue>,
}

impl std::fmt::Debug for UbuntuDerivedUploader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UbuntuDerivedUploader")
            .finish_non_exhaustive()
    }
}

impl UbuntuDerivedUploader {
    #[must_use]
    pub fn new(
        media_store: Arc<Mutex<MediaStore>>,
        transfer_store: Arc<Mutex<TransferStore>>,
        app_store: Arc<ylx_transfer_core::persistence::AppStore>,
        composition: Arc<Composition>,
    ) -> Arc<Self> {
        Arc::new(Self {
            media_store,
            transfer_store,
            app_store,
            library_root_authority: composition.library_root_authority(),
            composition,
            queue: MediaWakeQueue::new(super::ubuntu_workers::DEFAULT_QUEUE_CAPACITY),
        })
    }

    #[must_use]
    pub fn wake_queue(&self) -> Arc<MediaWakeQueue> {
        Arc::clone(&self.queue)
    }

    /// Builds and durably prepares one upload from a terminal derivation.
    ///
    /// `storage_profile_identity` is supplied by the pipeline admission
    /// boundary, but it is checked against the current non-secret storage
    /// coordinates before the bundle is created. The worker repeats that
    /// check on every turn. `source_archival` is accepted as an explicit
    /// policy input so a caller cannot accidentally omit the policy boundary;
    /// V1 rejects every enabled archival policy because this owner creates
    /// derived-only bundles.
    ///
    /// Preparation deliberately does not wake the worker. The owning pipeline
    /// must first attach this exact job with its expected-version CAS, then
    /// call [`Self::wake_upload`]. This keeps a failed attach from allowing an
    /// orphan transfer row to mutate the remote store.
    pub fn prepare_for_derivation(
        &self,
        derivation_job_id: &str,
        storage_profile_identity: StorageProfileIdentity,
        source_archival: SourceArchivalPolicy,
        unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
    ) -> Result<UploadPrepareResult, MediaPortError> {
        if !matches!(source_archival, SourceArchivalPolicy::Disabled) {
            return Err(upload_error(
                MediaErrorCode::OperationConflict,
                "Ubuntu V1 derived uploads do not enable source-video archival",
                false,
            ));
        }

        let storage = self.current_storage_config()?;
        let actual_identity = storage_profile_identity_for(&storage)
            .map_err(|detail| upload_error(MediaErrorCode::StorageNotConfigured, detail, false))?;
        if actual_identity != storage_profile_identity {
            return Err(storage_profile_changed());
        }

        let lease = self
            .library_root_authority
            .acquire_shared(UPLOAD_WORKER_OWNER)
            .map_err(|error| upload_error(MediaErrorCode::ImportCommandFailed, error, true))?;
        lease
            .assert_current()
            .map_err(|error| upload_error(MediaErrorCode::ImportCommandFailed, error, true))?;

        let (bundle, entry_key, total_bytes, label) = self
            .build_bundle(
                derivation_job_id,
                &storage,
                lease.root(),
                storage_profile_identity.clone(),
                source_archival,
                unsigned_admission,
            )
            .map_err(|error| upload_error(MediaErrorCode::IntegrityFailed, error, false))?;

        // `checkpoint_for` is pure and does not perform remote I/O. The
        // factory is still used here so the exact same production adapter
        // validates the storage configuration and credential boundary as the
        // worker will use after a restart.
        let object_store = self
            .composition
            .build_object_store_for_media(&storage)
            .map_err(|detail| upload_error(MediaErrorCode::StorageNotConfigured, detail, true))?;
        let adapter = DerivedUploadAdapter::new(
            &object_store,
            &NoopArtifactSource,
            storage_profile_identity.clone(),
            DEFAULT_MULTIPART_PART_SIZE_BYTES,
        )
        .map_err(|error| upload_error(MediaErrorCode::IntegrityFailed, error, false))?;
        let checkpoint = adapter
            .checkpoint_for(&bundle)
            .map_err(|error| upload_error(MediaErrorCode::IntegrityFailed, error, false))?;
        let frozen_bundle_json = serde_json::to_string(&bundle).map_err(|error| {
            upload_error(
                MediaErrorCode::IntegrityFailed,
                format!("cannot serialize frozen upload bundle: {error}"),
                false,
            )
        })?;
        let checkpoint_json = serde_json::to_string(&checkpoint).map_err(|error| {
            upload_error(
                MediaErrorCode::IntegrityFailed,
                format!("cannot serialize initial upload checkpoint: {error}"),
                false,
            )
        })?;
        let job_id = uuid::Uuid::new_v4().simple().to_string();
        let spec = DerivedUploadJobSpec {
            media_library_entry_key: entry_key.as_str().to_string(),
            upload_bundle_revision: bundle.revision().as_str().to_string(),
            storage_profile_identity: storage_profile_identity.as_str().to_string(),
            frozen_bundle_json,
            checkpoint_json,
        };
        let activity = UploadActivitySeed {
            label,
            target_label: storage.bucket.trim().to_string(),
            total_bytes,
        };
        let outcome = lock(&self.transfer_store)
            .create_derived_upload_job(&job_id, &spec, &activity, &now_rfc3339())
            .map_err(|error| {
                upload_error(
                    MediaErrorCode::ImportCommandFailed,
                    format!("cannot create durable derived upload: {error}"),
                    true,
                )
            })?;
        let (job_id, created) = match outcome {
            ylx_transfer_core::persistence::DerivedUploadCreateOutcome::Created(job) => {
                (job.job.job_id.clone(), true)
            }
            ylx_transfer_core::persistence::DerivedUploadCreateOutcome::Existing(job) => {
                (job.job.job_id.clone(), false)
            }
        };
        Ok(UploadPrepareResult {
            job_id,
            bundle_revision: bundle.revision().as_str().to_string(),
            created,
        })
    }

    /// Builds the exact pre-freeze request shown to the operator before an
    /// unsigned upload is approved. This performs the same durable derivation
    /// and local-file checks as real bundle preparation but does not create a
    /// transfer row or contact the object store.
    pub fn approval_request_for_derivation(
        &self,
        derivation_job_id: &str,
        storage_profile_identity: StorageProfileIdentity,
        source_archival: SourceArchivalPolicy,
    ) -> Result<UnsignedUploadAdmissionRequest, MediaPortError> {
        if !matches!(source_archival, SourceArchivalPolicy::Disabled) {
            return Err(upload_error(
                MediaErrorCode::OperationConflict,
                "Ubuntu V1 derived uploads do not enable source-video archival",
                false,
            ));
        }
        let storage = self.current_storage_config()?;
        let actual_identity = storage_profile_identity_for(&storage)
            .map_err(|detail| upload_error(MediaErrorCode::StorageNotConfigured, detail, false))?;
        if actual_identity != storage_profile_identity {
            return Err(storage_profile_changed());
        }
        let lease = self
            .library_root_authority
            .acquire_shared(UPLOAD_WORKER_OWNER)
            .map_err(|error| upload_error(MediaErrorCode::ImportCommandFailed, error, true))?;
        lease
            .assert_current()
            .map_err(|error| upload_error(MediaErrorCode::ImportCommandFailed, error, true))?;
        let (input, _) = self
            .build_bundle_input(
                derivation_job_id,
                &storage,
                lease.root(),
                storage_profile_identity,
                source_archival,
                None,
            )
            .map_err(|error| upload_error(MediaErrorCode::IntegrityFailed, error, false))?;
        input.unsigned_upload_admission_request().map_err(|error| {
            upload_error(
                MediaErrorCode::IntegrityFailed,
                format!("cannot build unsigned upload approval request: {error}"),
                false,
            )
        })
    }

    /// Re-enqueues every non-terminal derived upload that is already claimed
    /// by a durable pipeline dependency. A prepared-but-unattached job is
    /// intentionally left dormant; pipeline reconciliation either attaches
    /// and wakes it or reports the conflicting durable state.
    pub fn recover_pending_uploads(&self) -> Result<(), MediaPortError> {
        let attached = self.attached_upload_job_ids()?;
        let jobs = lock(&self.transfer_store)
            .list_active_derived_upload_jobs()
            .map_err(|error| {
                upload_error(
                    MediaErrorCode::ImportCommandFailed,
                    format!("cannot read derived upload recovery state: {error}"),
                    true,
                )
            })?;
        for job in jobs
            .into_iter()
            .filter(|job| attached.contains(&job.job.job_id))
        {
            let _ = self.queue.enqueue(&job.job.job_id);
        }
        Ok(())
    }

    /// Creates or reuses a fresh typed retry attempt without waking it.
    ///
    /// The owning pipeline must replace its failed dependency under CAS before
    /// calling [`Self::wake_upload`]. The parent checkpoint is never copied:
    /// retry starts from a checkpoint rebuilt from the immutable frozen bundle.
    pub fn prepare_retry(
        &self,
        parent_job_id: &str,
    ) -> Result<UploadPrepareResult, MediaPortError> {
        let parent = lock(&self.transfer_store)
            .derived_upload_job(parent_job_id)
            .map_err(|error| {
                upload_error(
                    MediaErrorCode::ImportCommandFailed,
                    format!("cannot read derived upload retry parent: {error}"),
                    true,
                )
            })?
            .ok_or_else(|| {
                upload_error(
                    MediaErrorCode::OperationConflict,
                    "the requested transfer is not a derived-bundle upload",
                    false,
                )
            })?;
        let bundle: FrozenUploadBundle =
            serde_json::from_str(&parent.frozen_bundle_json).map_err(|error| {
                upload_error(
                    MediaErrorCode::IntegrityFailed,
                    format!("derived upload retry bundle is invalid: {error}"),
                    false,
                )
            })?;
        if bundle.revision().as_str() != parent.upload_bundle_revision {
            return Err(upload_error(
                MediaErrorCode::IntegrityFailed,
                "derived upload retry bundle differs from its durable revision",
                false,
            ));
        }
        let stored_identity = StorageProfileIdentity::parse(
            parent.storage_profile_identity.clone(),
        )
        .map_err(|error| {
            upload_error(
                MediaErrorCode::IntegrityFailed,
                format!("derived upload retry storage identity is invalid: {error}"),
                false,
            )
        })?;
        let storage = self.current_storage_config()?;
        let current_identity = storage_profile_identity_for(&storage)
            .map_err(|detail| upload_error(MediaErrorCode::StorageNotConfigured, detail, false))?;
        if current_identity != stored_identity {
            return Err(storage_profile_changed());
        }
        let object_store = self
            .composition
            .build_object_store_for_media(&storage)
            .map_err(|detail| upload_error(MediaErrorCode::StorageNotConfigured, detail, true))?;
        let adapter = DerivedUploadAdapter::new(
            &object_store,
            &NoopArtifactSource,
            stored_identity,
            DEFAULT_MULTIPART_PART_SIZE_BYTES,
        )
        .map_err(|error| upload_error(MediaErrorCode::IntegrityFailed, error, false))?;
        let checkpoint = adapter
            .checkpoint_for(&bundle)
            .map_err(|error| upload_error(MediaErrorCode::IntegrityFailed, error, false))?;
        let checkpoint_json = serde_json::to_string(&checkpoint).map_err(|error| {
            upload_error(
                MediaErrorCode::IntegrityFailed,
                format!("cannot serialize fresh derived upload checkpoint: {error}"),
                false,
            )
        })?;
        let requested_child_id = uuid::Uuid::new_v4().simple().to_string();
        let outcome = lock(&self.transfer_store)
            .retry_derived_upload_job(
                parent_job_id,
                &requested_child_id,
                &checkpoint_json,
                &now_rfc3339(),
            )
            .map_err(|error| {
                upload_error(
                    MediaErrorCode::ImportCommandFailed,
                    format!("cannot create typed derived upload retry: {error}"),
                    false,
                )
            })?;
        let (job_id, created) = match outcome {
            DerivedUploadRetryOutcome::Created(job) => (job.job.job_id.clone(), true),
            DerivedUploadRetryOutcome::Existing(job) => (job.job.job_id.clone(), false),
        };
        Ok(UploadPrepareResult {
            job_id,
            bundle_revision: bundle.revision().as_str().to_string(),
            created,
        })
    }

    /// Wakes an already-attached durable upload after a pipeline replay. The
    /// queue is only a hint; the transfer row and its checkpoint remain the
    /// recovery authority. Re-checking the pipeline claim here keeps this
    /// public wake boundary from turning a prepared orphan into executable
    /// work if a caller gets the ordering wrong.
    pub fn wake_upload(&self, job_id: &str) -> Result<(), MediaPortError> {
        let attached = self.attached_upload_job_ids()?;
        enqueue_attached_upload(&self.queue, &attached, job_id)
    }

    /// Executes one queued upload turn. The worker always reloads the sidecar
    /// and current storage coordinates. A checkpoint CAS conflict is not a
    /// terminal upload failure: the current turn stops and the durable job is
    /// requeued so the newer checkpoint becomes the only source of truth.
    pub fn run_upload_once(&self, job_id: &str) -> Result<(), MediaPortError> {
        self.queue.take(job_id);
        if !self.upload_is_attached(job_id)? {
            return Err(upload_error(
                MediaErrorCode::OperationConflict,
                "derived upload has not been attached to a durable pipeline",
                true,
            ));
        }
        match self.execute_upload(job_id) {
            Ok(()) => Ok(()),
            Err(UploadTurnFailure::StaleCheckpoint) => {
                let _ = self.queue.enqueue(job_id);
                Ok(())
            }
            Err(UploadTurnFailure::StaleTransferJob) => {
                let _ = self.queue.enqueue(job_id);
                Ok(())
            }
            Err(UploadTurnFailure::Terminal {
                code,
                retryable,
                detail,
            }) => {
                self.complete_failed(job_id, code, retryable)?;
                Err(upload_error(
                    MediaErrorCode::RemoteVerificationFailed,
                    detail,
                    retryable,
                ))
            }
        }
    }

    fn attached_upload_job_ids(&self) -> Result<HashSet<String>, MediaPortError> {
        let pipelines = lock(&self.media_store)
            .list_pipeline_snapshots()
            .map_err(|error| {
                upload_error(
                    MediaErrorCode::ImportCommandFailed,
                    format!("cannot read durable upload ownership: {error}"),
                    true,
                )
            })?;
        Ok(pipelines
            .into_iter()
            .filter_map(|snapshot| {
                snapshot
                    .pipeline
                    .upload_dependency()
                    .map(|dependency| dependency.job_id().as_str().to_string())
            })
            .collect())
    }

    fn upload_is_attached(&self, job_id: &str) -> Result<bool, MediaPortError> {
        Ok(self.attached_upload_job_ids()?.contains(job_id))
    }

    fn execute_upload(&self, job_id: &str) -> Result<(), UploadTurnFailure> {
        let _started_state_version = self.start_or_resume_transfer(job_id)?;
        let stored = lock(&self.transfer_store)
            .derived_upload_job(job_id)
            .map_err(|error| terminal_failure("upload_store_failed", true, error.to_string()))?
            .ok_or_else(|| {
                terminal_failure(
                    "integrity_failed",
                    false,
                    "derived upload sidecar is missing",
                )
            })?;
        let bundle: FrozenUploadBundle =
            serde_json::from_str(&stored.frozen_bundle_json).map_err(|error| {
                terminal_failure(
                    "integrity_failed",
                    false,
                    format!("frozen bundle is invalid: {error}"),
                )
            })?;
        if bundle.revision().as_str() != stored.upload_bundle_revision {
            return Err(terminal_failure(
                "integrity_failed",
                false,
                "frozen bundle revision differs from its durable identity",
            ));
        }
        let mut checkpoint: UploadBundleCheckpoint = serde_json::from_str(&stored.checkpoint_json)
            .map_err(|error| {
                terminal_failure(
                    "integrity_failed",
                    false,
                    format!("upload checkpoint is invalid: {error}"),
                )
            })?;
        let stored_identity = StorageProfileIdentity::parse(
            stored.storage_profile_identity.clone(),
        )
        .map_err(|error| {
            terminal_failure(
                "integrity_failed",
                false,
                format!("stored storage identity is invalid: {error}"),
            )
        })?;

        let lease = self
            .library_root_authority
            .acquire_shared(UPLOAD_WORKER_OWNER)
            .map_err(|error| terminal_failure("upload_store_failed", true, error.to_string()))?;
        lease
            .assert_current()
            .map_err(|error| terminal_failure("upload_store_failed", true, error.to_string()))?;

        let storage = self.current_storage_config().map_err(|error| {
            terminal_failure("storage_not_configured", false, error.to_string())
        })?;
        let current_identity = storage_profile_identity_for(&storage)
            .map_err(|detail| terminal_failure("storage_not_configured", false, detail))?;
        if current_identity != stored_identity {
            return Err(terminal_failure(
                "storage_profile_changed",
                false,
                "durable upload destination differs from the current storage profile; explicit re-admission is required",
            ));
        }

        let object_store = self
            .composition
            .build_object_store_for_media(&storage)
            .map_err(|error| terminal_failure("storage_not_configured", true, error))?;
        let derived_receipt = lock(&self.media_store)
            .derived_receipt(bundle.derived_revision().as_str())
            .map_err(|error| terminal_failure("upload_store_failed", true, error.to_string()))?
            .ok_or_else(|| {
                terminal_failure(
                    "integrity_failed",
                    false,
                    "derived local receipt is missing",
                )
            })?;
        if derived_receipt.source_revision != bundle.source_revision().as_str()
            || derived_receipt.profile_revision != bundle.profile_revision().as_str()
            || derived_receipt.derived_revision != bundle.derived_revision().as_str()
        {
            return Err(terminal_failure(
                "integrity_failed",
                false,
                "derived local receipt does not match the frozen upload bundle",
            ));
        }
        let derived_manifest_relative =
            join_relative_path(&derived_receipt.local_path, DERIVED_MANIFEST_NAME)
                .map_err(|detail| terminal_failure("integrity_failed", false, detail))?;
        let provenance = provenance_report(
            bundle.source_revision(),
            &bundle.source_inventory_digest().clone(),
            bundle.source_provenance(),
        )
        .map_err(|detail| terminal_failure("integrity_failed", false, detail))?;
        let artifacts = FilesystemArtifactSource::new(
            lease.root().to_path_buf(),
            provenance,
            derived_manifest_relative,
        );
        let adapter = DerivedUploadAdapter::new(
            &object_store,
            &artifacts,
            stored_identity,
            DEFAULT_MULTIPART_PART_SIZE_BYTES,
        )
        .map_err(|error| terminal_failure("integrity_failed", false, error.to_string()))?;
        let sink = CasCheckpointSink::new(
            Arc::clone(&self.transfer_store),
            job_id.to_string(),
            stored.checkpoint_version,
        );
        adapter
            .upload_bundle(&bundle, &mut checkpoint, &sink)
            .map_err(|error| {
                if sink.was_stale() {
                    UploadTurnFailure::StaleCheckpoint
                } else {
                    let (code, retryable) = classify_upload_error(&error);
                    terminal_failure(code, retryable, error.to_string())
                }
            })?;

        let receipts = upload_receipt_seeds(&bundle, &checkpoint)
            .map_err(|detail| terminal_failure("integrity_failed", false, detail))?;
        {
            let mut transfer_store = lock(&self.transfer_store);
            transfer_store
                .stage_upload_receipts_for_job(job_id, &receipts, &now_rfc3339())
                .map_err(|error| {
                    terminal_failure("upload_store_failed", true, error.to_string())
                })?;
            let current = transfer_store
                .get_job(job_id)
                .map_err(|error| terminal_failure("upload_store_failed", true, error.to_string()))?
                .ok_or_else(|| {
                    terminal_failure(
                        "upload_store_failed",
                        true,
                        "upload job vanished before completion",
                    )
                })?;
            let completion = transfer_store.complete_upload_job(
                job_id,
                current.state_version,
                &TerminalOutcome::Succeeded,
                &now_rfc3339(),
            );
            match completion {
                Ok(_) => {}
                Err(UploadJobError::Stale { .. }) => {
                    return Err(UploadTurnFailure::StaleTransferJob);
                }
                Err(UploadJobError::AlreadyTerminal { existing, .. }) if existing.is_success() => {}
                Err(error) => {
                    return Err(terminal_failure(
                        "upload_store_failed",
                        true,
                        error.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn start_or_resume_transfer(&self, job_id: &str) -> Result<u64, UploadTurnFailure> {
        let mut transfer_store = lock(&self.transfer_store);
        let job = transfer_store
            .get_job(job_id)
            .map_err(|error| terminal_failure("upload_store_failed", true, error.to_string()))?
            .ok_or_else(|| {
                terminal_failure("upload_store_failed", true, "upload job is missing")
            })?;
        if job.operation_kind != ylx_transfer_core::persistence::OperationKind::Upload {
            return Err(terminal_failure(
                "integrity_failed",
                false,
                "derived upload sidecar is attached to a non-upload transfer job",
            ));
        }
        if job.state.is_terminal() {
            return Ok(job.state_version);
        }
        if !matches!(job.state, JobStateTag::Queued) {
            return Ok(job.state_version);
        }
        match transfer_store.start_upload_job(job_id, job.state_version, &now_rfc3339()) {
            Ok(version) => Ok(version),
            Err(UploadJobError::Stale { .. }) => Err(UploadTurnFailure::StaleTransferJob),
            Err(error) => Err(terminal_failure(
                "upload_store_failed",
                true,
                error.to_string(),
            )),
        }
    }

    fn complete_failed(
        &self,
        job_id: &str,
        code: &'static str,
        retryable: bool,
    ) -> Result<(), MediaPortError> {
        let mut transfer_store = lock(&self.transfer_store);
        let Some(job) = transfer_store.get_job(job_id).map_err(|error| {
            upload_error(
                MediaErrorCode::ImportCommandFailed,
                format!("cannot read derived upload failure state: {error}"),
                true,
            )
        })?
        else {
            return Ok(());
        };
        if job.state.is_terminal() {
            return Ok(());
        }
        transfer_store
            .complete_upload_job(
                job_id,
                job.state_version,
                &TerminalOutcome::Failed {
                    code: code.to_string(),
                    retryable,
                },
                &now_rfc3339(),
            )
            .map_err(|error| {
                upload_error(
                    MediaErrorCode::ImportCommandFailed,
                    format!("cannot record derived upload failure: {error}"),
                    true,
                )
            })?;
        Ok(())
    }

    fn build_bundle(
        &self,
        derivation_job_id: &str,
        storage: &StorageConfig,
        library_root: &Path,
        storage_profile_identity: StorageProfileIdentity,
        source_archival: SourceArchivalPolicy,
        unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
    ) -> Result<(FrozenUploadBundle, LibraryEntryKey, u64, String), String> {
        let (input, entry_key) = self.build_bundle_input(
            derivation_job_id,
            storage,
            library_root,
            storage_profile_identity,
            source_archival,
            unsigned_admission,
        )?;
        let bundle = FrozenUploadBundle::freeze(input)
            .map_err(|error| format!("cannot freeze derived upload bundle: {error}"))?;
        let total_bytes = bundle.objects().iter().try_fold(0_u64, |total, object| {
            total
                .checked_add(object.size_bytes())
                .ok_or_else(|| "derived upload size exceeds u64".to_string())
        })?;
        let label = format!("derived:{}", bundle.derived_revision().as_str());
        Ok((bundle, entry_key, total_bytes, label))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_bundle_input(
        &self,
        derivation_job_id: &str,
        storage: &StorageConfig,
        library_root: &Path,
        storage_profile_identity: StorageProfileIdentity,
        source_archival: SourceArchivalPolicy,
        unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
    ) -> Result<(UploadBundleInput, LibraryEntryKey), String> {
        let job_id = DerivationJobId::parse(derivation_job_id.to_string())
            .map_err(|error| format!("derivation job id is invalid: {error}"))?;
        let (derivation, source, local_source, import_receipt) = {
            let mut store = lock(&self.media_store);
            let derivation = store
                .derivation_job(&job_id)
                .map_err(|error| format!("cannot read derivation job: {error}"))?
                .ok_or_else(|| "derivation job is missing".to_string())?;
            if derivation.snapshot.state() != &DerivationJobState::DerivedVerified {
                return Err("derived upload requires a verified derivation completion".to_string());
            }
            let completion = derivation
                .snapshot
                .completion()
                .ok_or_else(|| "verified derivation has no completion evidence".to_string())?;
            let source_revision = completion.source_content_revision().as_str();
            let import = store
                .import_projection()
                .map_err(|error| format!("cannot read source import projection: {error}"))?
                .items
                .into_iter()
                .find(|item| {
                    item.snapshot
                        .content_revision()
                        .is_some_and(|revision| revision.as_str() == source_revision)
                })
                .ok_or_else(|| {
                    "no verified import matches the derived source revision".to_string()
                })?;
            let source =
                import.snapshot.verified_source().cloned().ok_or_else(|| {
                    "matching import has no verified source recording".to_string()
                })?;
            let local_source = import
                .snapshot
                .local_receipt()
                .cloned()
                .ok_or_else(|| "matching import has no local source receipt".to_string())?;
            let import_receipt = store
                .import_receipt_by_source_revision(source_revision)
                .map_err(|error| format!("cannot read source import receipt: {error}"))?
                .ok_or_else(|| "matching source has no durable import receipt".to_string())?;
            (derivation, source, local_source, import_receipt)
        };
        let completion = derivation
            .snapshot
            .completion()
            .ok_or_else(|| "verified derivation has no completion evidence".to_string())?;
        let manifest_input = completion.upload_bundle_input();
        if manifest_input.source_content_revision() != local_source.content_revision()
            || manifest_input.source_provenance() != local_source.provenance()
        {
            return Err(
                "derived manifest source evidence differs from the imported source".to_string(),
            );
        }

        let entry_key = LibraryEntryKey::for_source(
            &import_receipt.source_identity,
            local_source.content_revision(),
        )
        .map_err(|error| format!("cannot derive media-library entry key: {error}"))?;
        let namespace = namespace_for(storage)?;
        let marker = select_source_manifest(&source)?;
        let source_marker_relative = join_relative_path(
            local_source.sealed_relative_path().as_str(),
            marker.relative_path().as_str(),
        )?;
        validate_regular_file(library_root, &source_marker_relative, marker.size_bytes())?;
        let source_digest = source_digest(marker)?;
        let source_manifest_ref = LocalArtifactRef::parse(source_marker_relative.as_str())
            .map_err(|error| format!("source manifest local reference is invalid: {error}"))?;
        let source_manifest_media_type = marker.media_type().unwrap_or("application/json");
        let mut objects = vec![UploadObjectInput::new(
            UploadObjectRole::SourceManifest,
            source_manifest_ref,
            marker.size_bytes(),
            source_digest,
            source_manifest_media_type,
        )
        .map_err(|error| format!("source manifest object is invalid: {error}"))?];

        let provenance = provenance_report(
            local_source.content_revision(),
            local_source.inventory_digest(),
            manifest_input.source_provenance(),
        )?;
        let provenance_digest = SourceSha256::from_bytes(Sha256::digest(&provenance).into());
        objects.push(
            UploadObjectInput::new(
                UploadObjectRole::ProvenanceReport,
                LocalArtifactRef::parse(GENERATED_PROVENANCE_REF)
                    .map_err(|error| format!("provenance local reference is invalid: {error}"))?,
                u64::try_from(provenance.len())
                    .map_err(|_| "provenance report is too large".to_string())?,
                provenance_digest,
                "application/json",
            )
            .map_err(|error| format!("provenance report object is invalid: {error}"))?,
        );

        for output in manifest_input.output_inventory() {
            let output_relative = SafeRelativePath::parse(output.relative_path().to_string())
                .map_err(|error| format!("derived output path is unsafe: {error}"))?;
            let local_relative =
                join_relative_path(completion.local_relative_path(), output_relative.as_str())?;
            validate_regular_file(library_root, &local_relative, output.size_bytes())?;
            let digest = SourceSha256::from_hex(output.sha256().as_str())
                .map_err(|error| format!("derived output digest is invalid: {error}"))?;
            let eye = match output.role() {
                DerivedOutputRole::VideoLeft => "left",
                DerivedOutputRole::VideoRight => "right",
            };
            let opaque_file_id = format!("segment-{:05}-{eye}", output.segment_index());
            objects.push(
                UploadObjectInput::new(
                    UploadObjectRole::DerivedMedia { opaque_file_id },
                    LocalArtifactRef::parse(local_relative.as_str()).map_err(|error| {
                        format!("derived output local reference is invalid: {error}")
                    })?,
                    output.size_bytes(),
                    digest,
                    output.media_type(),
                )
                .map_err(|error| format!("derived output object is invalid: {error}"))?,
            );
        }

        let manifest_bytes = manifest_input.derived_manifest_canonical_bytes();
        let manifest_digest = SourceSha256::from_bytes(Sha256::digest(manifest_bytes).into());
        objects.push(
            UploadObjectInput::new(
                UploadObjectRole::DerivedManifest,
                LocalArtifactRef::parse(GENERATED_DERIVED_MANIFEST_REF).map_err(|error| {
                    format!("derived manifest local reference is invalid: {error}")
                })?,
                u64::try_from(manifest_bytes.len())
                    .map_err(|_| "derived manifest is too large".to_string())?,
                manifest_digest,
                "application/json",
            )
            .map_err(|error| format!("derived manifest object is invalid: {error}"))?,
        );

        let input = UploadBundleInput {
            namespace,
            origin_identity: manifest_input.subject().origin_identity().to_string(),
            session_or_source_id: manifest_input.subject().session_identity().to_string(),
            source_revision: local_source.content_revision().clone(),
            source_provenance: manifest_input.source_provenance().clone(),
            source_inventory_digest: local_source.inventory_digest().clone(),
            unsigned_admission,
            profile_revision: manifest_input.profile_revision().clone(),
            derived_revision: manifest_input.derived_revision().clone(),
            storage_profile_identity,
            source_archival,
            upload_policy_revision: DERIVED_UPLOAD_POLICY_REVISION.to_string(),
            objects,
        };
        Ok((input, entry_key))
    }

    fn current_storage_config(&self) -> Result<StorageConfig, MediaPortError> {
        let snapshot = self
            .app_store
            .load()
            .map_err(|error| upload_error(MediaErrorCode::StorageNotConfigured, error, true))?;
        let bytes = snapshot.storage.ok_or_else(|| {
            upload_error(
                MediaErrorCode::StorageNotConfigured,
                "no storage configuration has been persisted",
                false,
            )
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            upload_error(
                MediaErrorCode::StorageNotConfigured,
                format!("persisted storage configuration is invalid: {error}"),
                false,
            )
        })
    }
}

enum UploadTurnFailure {
    StaleCheckpoint,
    StaleTransferJob,
    Terminal {
        code: &'static str,
        retryable: bool,
        detail: String,
    },
}

fn terminal_failure(
    code: &'static str,
    retryable: bool,
    detail: impl Into<String>,
) -> UploadTurnFailure {
    UploadTurnFailure::Terminal {
        code,
        retryable,
        detail: detail.into(),
    }
}

fn classify_upload_error(error: &DerivedUploadError) -> (&'static str, bool) {
    match error {
        DerivedUploadError::InvalidConfiguration(_)
        | DerivedUploadError::InvalidFrozenBundle(_)
        | DerivedUploadError::SourceArchivalMustRemainDisabled
        | DerivedUploadError::UnsignedAdmissionMissingOrMismatched
        | DerivedUploadError::CheckpointMismatch(_)
        | DerivedUploadError::LocalEvidenceMismatch { .. }
        | DerivedUploadError::RemoteBundleVerification(_) => ("integrity_failed", false),
        DerivedUploadError::ArtifactOpen { .. }
        | DerivedUploadError::ArtifactRead { .. }
        | DerivedUploadError::ObjectStore { .. }
        | DerivedUploadError::AmbiguousRemoteState { .. }
        | DerivedUploadError::CleanupAfterEvidenceFailure { .. } => {
            ("remote_verification_failed", true)
        }
        DerivedUploadError::CheckpointPersistence { .. } => ("upload_store_failed", true),
    }
}

fn upload_receipt_seeds(
    bundle: &FrozenUploadBundle,
    checkpoint: &UploadBundleCheckpoint,
) -> Result<Vec<UploadReceiptSeed>, String> {
    if bundle.objects().len() != checkpoint.objects().len() {
        return Err("upload checkpoint object count differs from the frozen bundle".to_string());
    }
    bundle
        .objects()
        .iter()
        .zip(checkpoint.objects())
        .map(|(object, checkpoint)| {
            let (completion, verification) = match checkpoint.phase() {
                ObjectUploadPhase::Verified {
                    completion,
                    verification,
                } => (completion, verification),
                _ => {
                    return Err(format!(
                        "object {:?} lacks completion-bound verification evidence",
                        checkpoint.key()
                    ));
                }
            };
            if checkpoint.key() != object.object_key()
                || verification.key != *object.object_key()
                || verification.size_bytes != object.size_bytes()
                || verification.source_sha256 != object.sha256()
            {
                return Err(format!(
                    "verified upload evidence does not match object {:?}",
                    object.object_key()
                ));
            }
            let proof = match verification.digest_proof {
                DigestProof::ServerChecksum => UploadReceiptDigestProof::ServerChecksum,
                DigestProof::StreamedReadback => UploadReceiptDigestProof::StreamedReadback,
            };
            Ok(UploadReceiptSeed::new(
                object.object_key().0.clone(),
                upload_receipt_role(object.role()),
                completion.etag.clone(),
                completion.version_id.clone(),
                verification.size_bytes,
                verification.source_sha256.to_hex(),
                proof,
            ))
        })
        .collect()
}

fn upload_receipt_role(role: &UploadObjectRole) -> UploadReceiptRole {
    match role {
        UploadObjectRole::DerivedMedia { .. }
        | UploadObjectRole::DerivedMetadata { .. }
        | UploadObjectRole::SourceVideoArchive { .. } => UploadReceiptRole::Data,
        UploadObjectRole::DerivedManifest
        | UploadObjectRole::SourceManifest
        | UploadObjectRole::SourceMetadata { .. }
        | UploadObjectRole::ProvenanceReport => UploadReceiptRole::Evidence,
    }
}

struct CasCheckpointSink {
    transfer_store: Arc<Mutex<TransferStore>>,
    job_id: String,
    expected_version: Mutex<u64>,
    stale: AtomicBool,
}

impl CasCheckpointSink {
    fn new(
        transfer_store: Arc<Mutex<TransferStore>>,
        job_id: String,
        expected_version: u64,
    ) -> Self {
        Self {
            transfer_store,
            job_id,
            expected_version: Mutex::new(expected_version),
            stale: AtomicBool::new(false),
        }
    }

    fn was_stale(&self) -> bool {
        self.stale.load(Ordering::Acquire)
    }
}

impl UploadCheckpointSink for CasCheckpointSink {
    fn persist(
        &self,
        checkpoint: &UploadBundleCheckpoint,
    ) -> Result<(), CheckpointPersistenceError> {
        let checkpoint_json = serde_json::to_string(checkpoint).map_err(|error| {
            CheckpointPersistenceError::new(format!("serialize checkpoint: {error}"))
        })?;
        let mut expected = lock(&self.expected_version);
        let outcome = lock(&self.transfer_store)
            .compare_and_swap_derived_upload_checkpoint(
                &self.job_id,
                *expected,
                &checkpoint_json,
                &now_rfc3339(),
            )
            .map_err(|error| CheckpointPersistenceError::new(error.to_string()))?;
        match outcome {
            CheckpointSwapOutcome::Applied { checkpoint_version } => {
                *expected = checkpoint_version;
                Ok(())
            }
            CheckpointSwapOutcome::Stale { actual_version } => {
                self.stale.store(true, Ordering::Release);
                Err(CheckpointPersistenceError::new(format!(
                    "checkpoint CAS is stale; durable version is {actual_version}"
                )))
            }
        }
    }
}

/// Filesystem-backed logical artifact resolver. Generated provenance is kept
/// as bytes because it is immutable derived evidence; the generated manifest
/// reference resolves to the already-published deterministic manifest path,
/// never to a temporary staging path.
struct FilesystemArtifactSource {
    root: PathBuf,
    provenance: Vec<u8>,
    derived_manifest_relative: SafeRelativePath,
}

impl FilesystemArtifactSource {
    fn new(
        root: PathBuf,
        provenance: Vec<u8>,
        derived_manifest_relative: SafeRelativePath,
    ) -> Self {
        Self {
            root,
            provenance,
            derived_manifest_relative,
        }
    }
}

impl LocalArtifactSource for FilesystemArtifactSource {
    fn open(&self, artifact: &LocalArtifactRef) -> Result<Box<dyn Read + Send>, ArtifactReadError> {
        if artifact.as_str() == GENERATED_PROVENANCE_REF {
            return Ok(Box::new(Cursor::new(self.provenance.clone())));
        }
        let relative = if artifact.as_str() == GENERATED_DERIVED_MANIFEST_REF {
            self.derived_manifest_relative.clone()
        } else {
            SafeRelativePath::parse(artifact.as_str().to_string())
                .map_err(|_| ArtifactReadError::new("local artifact reference is unsafe"))?
        };
        let file = open_regular_beneath(&self.root, &relative).map_err(|_| {
            ArtifactReadError::new("local artifact is missing or not a regular no-link file")
        })?;
        Ok(Box::new(file))
    }
}

/// Used only for the pure `checkpoint_for` call during enqueue.
struct NoopArtifactSource;

impl LocalArtifactSource for NoopArtifactSource {
    fn open(
        &self,
        _artifact: &LocalArtifactRef,
    ) -> Result<Box<dyn Read + Send>, ArtifactReadError> {
        Err(ArtifactReadError::new(
            "artifact source is unavailable during enqueue",
        ))
    }
}

/// Opens a regular artifact through directory descriptors rooted at the
/// trusted library root. Each component is opened with `O_NOFOLLOW`; the
/// returned descriptor is therefore bound to the object that will actually
/// be uploaded, rather than to a path that an attacker can exchange after a
/// preflight `stat`.
fn open_regular_beneath(root: &Path, relative: &SafeRelativePath) -> std::io::Result<File> {
    let mut directory = File::open(root)?;
    let components = Path::new(relative.as_str())
        .components()
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe path component",
            ));
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL path component")
        })?;
        let leaf = index + 1 == components.len();
        let flags = if leaf {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY
        };
        // SAFETY: `directory` owns a live directory fd and `name` is NUL-terminated.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a newly-owned fd.
        let next = unsafe { File::from_raw_fd(fd) };
        if leaf && !next.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact is not regular",
            ));
        }
        directory = next;
    }
    Ok(directory)
}

fn select_source_manifest(source: &SourceRecording) -> Result<&SourceArtifactClaim, String> {
    select_source_manifest_from_inventory(source.inventory())
}

fn select_source_manifest_from_inventory(
    inventory: &[SourceArtifactClaim],
) -> Result<&SourceArtifactClaim, String> {
    let candidates = inventory
        .iter()
        .filter(|claim| ALLOWLISTED_SOURCE_MARKER_ROLES.contains(&claim.role()))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [claim] => Ok(claim),
        [] => Err(
            "source inventory has no allowlisted publication/session/capture marker".to_string(),
        ),
        _ => Err(
            "source inventory has multiple allowlisted markers; manifest identity is ambiguous"
                .to_string(),
        ),
    }
}

fn source_digest(claim: &SourceArtifactClaim) -> Result<SourceSha256, String> {
    let digest = claim
        .source_sha256()
        .ok_or_else(|| "source manifest marker has no digest".to_string())?;
    SourceSha256::from_hex(digest)
        .map_err(|error| format!("source manifest digest is invalid: {error}"))
}

fn validate_regular_file(
    root: &Path,
    relative: &SafeRelativePath,
    expected_size: u64,
) -> Result<(), String> {
    let file = open_regular_beneath(root, relative)
        .map_err(|error| format!("local upload artifact is unsafe or missing: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("local upload artifact cannot be inspected: {error}"))?;
    if metadata.len() != expected_size {
        return Err(format!(
            "local upload artifact size differs from durable evidence: expected {expected_size}, got {}",
            metadata.len()
        ));
    }
    Ok(())
}

fn join_relative_path(base: &str, child: &str) -> Result<SafeRelativePath, String> {
    let base = SafeRelativePath::parse(base.to_string())
        .map_err(|error| format!("base relative path is unsafe: {error}"))?;
    let child = SafeRelativePath::parse(child.to_string())
        .map_err(|error| format!("child relative path is unsafe: {error}"))?;
    SafeRelativePath::parse(format!("{}/{}", base.as_str(), child.as_str()))
        .map_err(|error| format!("joined relative path is unsafe: {error}"))
}

#[derive(Serialize)]
struct DerivedProvenanceReport<'a> {
    schema_version: u32,
    evidence_kind: &'static str,
    source_revision: &'a str,
    source_inventory_digest: &'a str,
    producer_signed: bool,
    provenance: &'a SourceProvenance,
}

/// This is immutable derived-upload evidence, not a producer-signed
/// provenance statement. It deliberately has no current time, random id, or
/// filesystem path, so rebuilding it after a restart produces identical
/// bytes and the frozen digest remains meaningful.
fn provenance_report(
    source_revision: &SourceContentRevision,
    inventory_digest: &ylx_transfer_core::ingest::InventoryDigest,
    provenance: &SourceProvenance,
) -> Result<Vec<u8>, String> {
    let report = DerivedProvenanceReport {
        schema_version: PROVENANCE_REPORT_SCHEMA_VERSION,
        evidence_kind: "immutable_derived_upload_evidence",
        source_revision: source_revision.as_str(),
        source_inventory_digest: inventory_digest.as_str(),
        producer_signed: matches!(provenance, SourceProvenance::DeviceSigned(_)),
        provenance,
    };
    serde_json::to_vec(&report)
        .map_err(|error| format!("cannot serialize provenance report: {error}"))
}

/// Compute the profile identity without reading or retaining credentials.
/// Endpoint, bucket, normalized prefix segments, and addressing style are
/// length-delimited before hashing so ambiguous concatenations cannot collide.
pub fn storage_profile_identity_for(
    storage: &StorageConfig,
) -> Result<StorageProfileIdentity, String> {
    let endpoint = normalize_endpoint(&storage.endpoint)?;
    let bucket = storage.bucket.trim();
    if bucket.is_empty() || bucket.chars().any(char::is_control) {
        return Err("storage bucket is empty or contains control characters".to_string());
    }
    let prefix_segments = normalized_prefix_segments(&storage.prefix)?;
    let style = match storage.url_style {
        StorageUrlStyle::VirtualHost => "virtual_host",
        StorageUrlStyle::Path => "path",
    };
    let mut hasher = Sha256::new();
    hasher.update(b"ylx-transfer/storage-profile-v1\0");
    hash_field(&mut hasher, endpoint.as_bytes());
    hash_field(&mut hasher, bucket.as_bytes());
    hash_field(&mut hasher, style.as_bytes());
    hash_field(&mut hasher, &(prefix_segments.len() as u64).to_be_bytes());
    for segment in &prefix_segments {
        hash_field(&mut hasher, segment.as_bytes());
    }
    StorageProfileIdentity::parse(format!("storage-profile-v1:sha256:{:x}", hasher.finalize()))
        .map_err(|error| format!("storage profile identity is invalid: {error}"))
}

fn namespace_for(storage: &StorageConfig) -> Result<ObjectNamespace, String> {
    let mut segments = vec!["ylx-transfer".to_string()];
    segments.extend(normalized_prefix_segments(&storage.prefix)?);
    ObjectNamespace::from_raw_segments(segments)
        .map_err(|error| format!("storage object namespace is invalid: {error}"))
}

fn normalized_prefix_segments(prefix: &str) -> Result<Vec<String>, String> {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    trimmed
        .split('/')
        .map(|segment| {
            if segment.is_empty() {
                return Err("storage prefix contains an empty segment".to_string());
            }
            SafeRelativePath::parse(segment.to_string())
                .map_err(|error| format!("storage prefix segment is unsafe: {error}"))?;
            Ok(segment.to_string())
        })
        .collect()
}

fn normalize_endpoint(endpoint: &str) -> Result<String, String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.chars().any(char::is_control) {
        return Err("storage endpoint is empty or contains control characters".to_string());
    }
    let endpoint = endpoint.trim_end_matches('/');
    let lower = endpoint.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("storage endpoint must use http:// or https://".to_string());
    }
    let authority = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or_default();
    if lower.contains('?') || lower.contains('#') || authority.contains('/') {
        return Err("storage endpoint must not contain a path, query, or fragment".to_string());
    }
    if lower.contains('@') || lower.ends_with("://") {
        return Err(
            "storage endpoint must not contain userinfo and must include a host".to_string(),
        );
    }
    Ok(lower)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn storage_profile_changed() -> MediaPortError {
    upload_error(
        MediaErrorCode::OperationConflict,
        "durable upload destination differs from the current storage profile; explicit re-admission is required",
        false,
    )
}

fn upload_error(
    code: MediaErrorCode,
    detail: impl std::fmt::Display,
    retryable: bool,
) -> MediaPortError {
    MediaPortError::new(code, detail.to_string()).with_retryable(retryable)
}

fn enqueue_attached_upload(
    queue: &MediaWakeQueue,
    attached_job_ids: &HashSet<String>,
    job_id: &str,
) -> Result<(), MediaPortError> {
    if !attached_job_ids.contains(job_id) {
        return Err(upload_error(
            MediaErrorCode::OperationConflict,
            "derived upload has not been attached to a durable pipeline",
            true,
        ));
    }
    // A full/stopped queue is a lost wake-up, not a lost durable job. Startup
    // recovery and the next reconciliation will discover the row again.
    let _ = queue.enqueue(job_id);
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
    use std::collections::HashSet;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::*;

    fn artifact(role: SourceArtifactRole, path: &str) -> SourceArtifactClaim {
        SourceArtifactClaim::new(
            ylx_transfer_core::ingest::SourceArtifactId::parse("artifact-1").expect("artifact id"),
            SafeRelativePath::parse(path.to_string()).expect("artifact path"),
            role,
            1,
            Some("a".repeat(64)),
            Some("application/json".to_string()),
        )
        .expect("artifact claim")
    }

    fn storage(prefix: &str) -> StorageConfig {
        StorageConfig {
            endpoint: "HTTPS://Example.COM:9000/".to_string(),
            bucket: "media".to_string(),
            prefix: prefix.to_string(),
            url_style: StorageUrlStyle::Path,
            download_root: None,
        }
    }

    #[test]
    fn storage_profile_identity_is_deterministic_and_credential_free() {
        let first = storage_profile_identity_for(&storage("/one/two/")).expect("identity");
        let second = storage_profile_identity_for(&storage("one/two")).expect("identity");
        assert_eq!(first, second);
        assert!(first.as_str().starts_with("storage-profile-v1:sha256:"));
        assert_eq!(
            first.as_str().len(),
            "storage-profile-v1:sha256:".len() + 64
        );
    }

    #[test]
    fn prefix_segments_are_not_passed_as_one_slash_delimited_segment() {
        let namespace = namespace_for(&storage("alpha/beta")).expect("namespace");
        assert!(serde_json::to_string(&namespace)
            .expect("namespace JSON")
            .contains("alpha"));
        assert!(normalized_prefix_segments("alpha//beta").is_err());
        assert!(normalized_prefix_segments("../escape").is_err());
    }

    #[test]
    fn endpoint_identity_rejects_path_query_and_userinfo() {
        let credentialed_endpoint = ["https://", "user", ":", "secret", "@example.test"].concat();
        for endpoint in [
            "https://example.test/path",
            "https://example.test?bucket=x",
            credentialed_endpoint.as_str(),
        ] {
            let mut config = storage("");
            config.endpoint = endpoint.to_string();
            assert!(storage_profile_identity_for(&config).is_err());
        }
    }

    #[test]
    fn source_manifest_selection_requires_one_allowlisted_marker() {
        let ordinary = artifact(SourceArtifactRole::VideoStereo, "video/source.mp4");
        assert!(select_source_manifest_from_inventory(&[ordinary]).is_err());

        let publication = artifact(
            SourceArtifactRole::PublicationManifest,
            "publication_manifest.json",
        );
        let session = artifact(SourceArtifactRole::SessionManifest, "session.json");
        let error = select_source_manifest_from_inventory(&[publication, session])
            .expect_err("two source markers must be ambiguous");
        assert!(error.contains("multiple allowlisted markers"));
    }

    #[test]
    fn source_manifest_digest_is_required_and_validated() {
        let claim = SourceArtifactClaim::new(
            ylx_transfer_core::ingest::SourceArtifactId::parse("publication").expect("id"),
            SafeRelativePath::parse("publication_manifest.json").expect("path"),
            SourceArtifactRole::PublicationManifest,
            1,
            None,
            Some("application/json".to_string()),
        )
        .expect("claim");
        let error = source_digest(&claim).expect_err("marker without digest must fail");
        assert!(error.contains("has no digest"));

        let invalid: SourceArtifactClaim = serde_json::from_value(serde_json::json!({
            "id": "artifact-invalid",
            "relative_path": "publication.json",
            "role": "publication_manifest",
            "size_bytes": 1,
            "source_sha256": "not-a-digest",
            "media_type": "application/json",
        }))
        .expect("deserializing a malformed durable claim should be possible");
        let error = source_digest(&invalid).expect_err("invalid digest must fail");
        assert!(error.contains("digest is invalid"));
    }

    #[test]
    fn provenance_report_bytes_are_deterministic_and_path_free() {
        let provenance: SourceProvenance = serde_json::from_value(serde_json::json!({
            "kind": "device_signed",
            "evidence": {
                "publication_key_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "publication_revision": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "publication_payload": [1, 2, 3],
                "publication_signature": [4, 5, 6],
                "publication_public_key": [7, 8, 9]
            }
        }))
        .expect("provenance fixture");
        let source_revision =
            ylx_transfer_core::ingest::SourceContentRevision::from_material(b"source");
        let inventory_digest =
            ylx_transfer_core::ingest::InventoryDigest::from_material(b"inventory");

        let first = provenance_report(&source_revision, &inventory_digest, &provenance)
            .expect("first report");
        let second = provenance_report(&source_revision, &inventory_digest, &provenance)
            .expect("second report");
        assert_eq!(first, second);
        let report = String::from_utf8(first).expect("UTF-8 report");
        assert!(report.contains("immutable_derived_upload_evidence"));
        assert!(!report.contains("/"));
        assert!(!report.contains("credential"));
    }

    #[test]
    fn local_artifact_validation_rejects_missing_wrong_size_and_symlink_files() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path();
        let relative = SafeRelativePath::parse("derived/output.mp4").expect("relative path");
        let path = root.join(relative.as_str());
        fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
        fs::write(&path, b"video").expect("artifact");

        validate_regular_file(root, &relative, 5).expect("regular file should validate");
        assert!(validate_regular_file(root, &relative, 4)
            .expect_err("wrong size must fail")
            .contains("size differs"));

        let link = root.join("derived/link.mp4");
        symlink("output.mp4", &link).expect("symlink");
        let link_relative = SafeRelativePath::parse("derived/link.mp4").expect("link path");
        assert!(validate_regular_file(root, &link_relative, 5).is_err());

        let missing = SafeRelativePath::parse("derived/missing.mp4").expect("missing path");
        assert!(validate_regular_file(root, &missing, 1).is_err());
    }

    #[test]
    fn dirfd_artifact_open_rejects_a_parent_directory_symlink() {
        let directory = tempdir().expect("temporary directory");
        let outside = tempdir().expect("outside directory");
        fs::write(outside.path().join("output.mp4"), b"video").expect("outside artifact");
        symlink(outside.path(), directory.path().join("derived")).expect("parent symlink");
        let relative = SafeRelativePath::parse("derived/output.mp4").expect("relative path");

        assert!(validate_regular_file(directory.path(), &relative, 5).is_err());
        assert!(open_regular_beneath(directory.path(), &relative).is_err());
    }

    #[test]
    fn filesystem_artifact_source_keeps_generated_evidence_and_rejects_missing_files() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path();
        fs::write(root.join("derived_manifest.json"), b"manifest").expect("manifest");
        let manifest = SafeRelativePath::parse("derived_manifest.json").expect("manifest path");
        let source =
            FilesystemArtifactSource::new(root.to_path_buf(), b"provenance".to_vec(), manifest);

        let mut provenance = String::new();
        source
            .open(&LocalArtifactRef::parse(GENERATED_PROVENANCE_REF).expect("provenance ref"))
            .expect("provenance")
            .read_to_string(&mut provenance)
            .expect("read provenance");
        assert_eq!(provenance, "provenance");

        let mut manifest_bytes = String::new();
        source
            .open(&LocalArtifactRef::parse(GENERATED_DERIVED_MANIFEST_REF).expect("manifest ref"))
            .expect("manifest")
            .read_to_string(&mut manifest_bytes)
            .expect("read manifest");
        assert_eq!(manifest_bytes, "manifest");

        assert!(source
            .open(&LocalArtifactRef::parse("missing.mp4").expect("missing ref"))
            .is_err());
    }

    #[test]
    fn stale_checkpoint_sink_cannot_advance_or_replace_a_newer_checkpoint() {
        let directory = tempdir().expect("temporary directory");
        let transfer_store = Arc::new(Mutex::new(
            TransferStore::open(directory.path().join("transfers.sqlite3"))
                .expect("transfer store"),
        ));
        let initial_checkpoint = r#"{"schema_version":1,"natural_key":{"upload_bundle_revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","storage_profile_identity":"profile-a"},"objects":[]}"#;
        let spec = DerivedUploadJobSpec {
            media_library_entry_key: format!("media-library-v1:{}", "a".repeat(64)),
            upload_bundle_revision: "sha256:bundle".to_string(),
            storage_profile_identity: "profile-a".to_string(),
            frozen_bundle_json: r#"{"schema_version":1,"objects":[]}"#.to_string(),
            checkpoint_json: initial_checkpoint.to_string(),
        };
        let seed = UploadActivitySeed {
            label: "derived upload".to_string(),
            target_label: "test bucket".to_string(),
            total_bytes: 0,
        };
        lock(&transfer_store)
            .create_derived_upload_job("job-1", &spec, &seed, "2026-08-11T00:00:00Z")
            .expect("create derived upload job");
        let checkpoint: UploadBundleCheckpoint =
            serde_json::from_str(initial_checkpoint).expect("checkpoint fixture");
        let first_worker =
            CasCheckpointSink::new(Arc::clone(&transfer_store), "job-1".to_string(), 1);
        let stale_worker =
            CasCheckpointSink::new(Arc::clone(&transfer_store), "job-1".to_string(), 1);

        first_worker
            .persist(&checkpoint)
            .expect("first worker advances checkpoint");
        let after_first = lock(&transfer_store)
            .derived_upload_job("job-1")
            .expect("load job")
            .expect("stored job");
        assert_eq!(after_first.checkpoint_version, 2);

        let stale_error = stale_worker
            .persist(&checkpoint)
            .expect_err("old checkpoint generation must not overwrite newer state");
        assert!(stale_error.detail().contains("durable version is 2"));
        assert!(stale_worker.was_stale());
        let after_stale = lock(&transfer_store)
            .derived_upload_job("job-1")
            .expect("load job")
            .expect("stored job");
        assert_eq!(after_stale.checkpoint_version, 2);
        assert_eq!(after_stale.checkpoint_json, after_first.checkpoint_json);
    }

    #[test]
    fn wake_does_not_enqueue_a_prepared_but_unattached_job() {
        let queue = MediaWakeQueue::new(4);
        let attached = HashSet::new();

        let error = enqueue_attached_upload(&queue, &attached, "prepared-job")
            .expect_err("an orphaned prepared job must stay dormant");
        assert!(error
            .to_string()
            .contains("has not been attached to a durable pipeline"));
        assert_eq!(queue.depth(), 0);

        let attached = HashSet::from(["prepared-job".to_string()]);
        enqueue_attached_upload(&queue, &attached, "prepared-job")
            .expect("an attached job may be woken");
        assert_eq!(queue.depth(), 1);
    }
}
