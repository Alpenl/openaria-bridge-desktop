//! Execution adapter for immutable derived-media upload bundles.
//!
//! This module deliberately does not implement an object store. It consumes
//! [`FrozenUploadBundle`] values from core and delegates every remote
//! operation, including completion-bound byte verification, to the existing
//! [`ObjectStorePort`]. The important ordering and recovery rules are:
//!
//! - each multipart handle, completed part, completion receipt, and verified
//!   receipt is checkpointed independently;
//! - already verified objects are never uploaded again after restart;
//! - a completion is verified through
//!   [`ObjectStorePort::verify_completed_object`], never through a latest-key
//!   HEAD;
//! - the final derived manifest is uploaded only after every data object has
//!   a verified receipt; and
//! - V1 accepts derived-only bundles. Source-video archival remains an
//!   explicit disabled policy and a derived receipt is never described as a
//!   source backup.

use std::fmt;
use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ylx_transfer_core::ingest::SourceProvenance;
use ylx_transfer_core::library::object_store_port::{
    CompletedUpload, ExpectedObject, InitiateUploadRequest, MultipartUploadHandle, ObjectKey,
    ObjectStoreError, ObjectStorePort, PartETag, PartNumber, SourceSha256, VerifiedObjectReceipt,
};
use ylx_transfer_core::media_pipeline::{
    CompletionBoundObjectReceipt, FrozenUploadBundle, FrozenUploadObject, LocalArtifactRef,
    RemoteBundleReceipt, RemoteVerificationError, SourceArchivalPolicy, StorageProfileIdentity,
    UploadJobNaturalKey, UploadObjectRole, DERIVED_UPLOAD_POLICY_REVISION,
};

/// S3 requires every non-final multipart part to be at least 5 MiB.
pub const MIN_MULTIPART_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024;

/// Keeps one caller-controlled allocation bounded while still allowing
/// efficient uploads on fast links.
pub const MAX_MULTIPART_PART_SIZE_BYTES: u64 = 128 * 1024 * 1024;

/// Conservative default with valid S3 multipart semantics.
pub const DEFAULT_MULTIPART_PART_SIZE_BYTES: u64 = 8 * 1024 * 1024;

const UPLOAD_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

/// Opens an immutable local artifact while retaining whatever library lease
/// prevents its revision from being replaced during the read.
///
/// The adapter intentionally receives a logical [`LocalArtifactRef`] rather
/// than a filesystem path. The media-store adapter remains responsible for
/// resolving that reference inside the sealed local-library tree.
pub trait LocalArtifactSource: Send + Sync {
    fn open(&self, artifact: &LocalArtifactRef) -> Result<Box<dyn Read + Send>, ArtifactReadError>;
}

/// Bounded, path-free failure returned by [`LocalArtifactSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReadError {
    detail: String,
}

impl ArtifactReadError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: sanitize_local_detail(detail.into()),
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ArtifactReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ArtifactReadError {}

/// Durable sink owned by the application/persistence layer.
///
/// `persist` is called before the first remote mutation and after every
/// successful initiate, part upload, completion, and verification. A sink
/// failure stops execution immediately; the in-memory checkpoint still
/// contains the newest state so the caller can report it without pretending
/// the durable checkpoint advanced.
pub trait UploadCheckpointSink: Send + Sync {
    fn persist(
        &self,
        checkpoint: &UploadBundleCheckpoint,
    ) -> Result<(), CheckpointPersistenceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPersistenceError {
    detail: String,
}

impl CheckpointPersistenceError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: sanitize_local_detail(detail.into()),
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CheckpointPersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for CheckpointPersistenceError {}

/// Restart-safe phase for one frozen object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum ObjectUploadPhase {
    Pending,
    Uploading {
        handle: MultipartUploadHandle,
        part_size_bytes: u64,
        completed_parts: Vec<PartETag>,
    },
    Completed {
        completion: CompletedUpload,
    },
    Verified {
        completion: CompletedUpload,
        verification: VerifiedObjectReceipt,
    },
}

/// Durable per-item progress bound to the frozen object's exact evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectUploadCheckpoint {
    key: ObjectKey,
    size_bytes: u64,
    sha256: SourceSha256,
    media_type: String,
    phase: ObjectUploadPhase,
}

impl ObjectUploadCheckpoint {
    #[must_use]
    pub fn key(&self) -> &ObjectKey {
        &self.key
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> SourceSha256 {
        self.sha256
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub fn phase(&self) -> &ObjectUploadPhase {
        &self.phase
    }
}

/// Serializable upload progress for one `(bundle revision, storage profile)`
/// natural key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadBundleCheckpoint {
    schema_version: u32,
    natural_key: UploadJobNaturalKey,
    objects: Vec<ObjectUploadCheckpoint>,
}

impl UploadBundleCheckpoint {
    #[must_use]
    pub fn natural_key(&self) -> &UploadJobNaturalKey {
        &self.natural_key
    }

    #[must_use]
    pub fn objects(&self) -> &[ObjectUploadCheckpoint] {
        &self.objects
    }
}

/// Full derived-bundle receipt plus ordered per-item completion evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DerivedUploadReceipt {
    remote_bundle: RemoteBundleReceipt,
}

impl DerivedUploadReceipt {
    #[must_use]
    pub fn remote_bundle(&self) -> &RemoteBundleReceipt {
        &self.remote_bundle
    }

    #[must_use]
    pub fn object_receipts(&self) -> &[CompletionBoundObjectReceipt] {
        self.remote_bundle.object_receipts()
    }
}

#[derive(Debug)]
pub enum DerivedUploadError {
    InvalidConfiguration(String),
    InvalidFrozenBundle(String),
    SourceArchivalMustRemainDisabled,
    UnsignedAdmissionMissingOrMismatched,
    CheckpointMismatch(String),
    ArtifactOpen {
        key: ObjectKey,
        source: ArtifactReadError,
    },
    ArtifactRead {
        key: ObjectKey,
        detail: String,
    },
    LocalEvidenceMismatch {
        key: ObjectKey,
        detail: String,
    },
    ObjectStore {
        key: ObjectKey,
        operation: &'static str,
        source: Box<ObjectStoreError>,
    },
    AmbiguousRemoteState {
        key: ObjectKey,
        detail: String,
    },
    CleanupAfterEvidenceFailure {
        key: ObjectKey,
        detail: String,
        cleanup: Box<ObjectStoreError>,
    },
    CheckpointPersistence {
        key: Option<ObjectKey>,
        source: CheckpointPersistenceError,
    },
    RemoteBundleVerification(RemoteVerificationError),
}

impl fmt::Display for DerivedUploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(f, "invalid derived-upload configuration: {detail}")
            }
            Self::InvalidFrozenBundle(detail) => write!(f, "invalid frozen bundle: {detail}"),
            Self::SourceArchivalMustRemainDisabled => {
                f.write_str("source archival is disabled for the derived-upload V1 adapter")
            }
            Self::UnsignedAdmissionMissingOrMismatched => f.write_str(
                "unsigned source upload admission is missing or does not bind this source revision",
            ),
            Self::CheckpointMismatch(detail) => {
                write!(f, "upload checkpoint does not match the frozen bundle: {detail}")
            }
            Self::ArtifactOpen { key, source } => {
                write!(f, "cannot open local artifact for {key:?}: {source}")
            }
            Self::ArtifactRead { key, detail } => {
                write!(f, "cannot read local artifact for {key:?}: {detail}")
            }
            Self::LocalEvidenceMismatch { key, detail } => {
                write!(f, "local artifact evidence mismatch for {key:?}: {detail}")
            }
            Self::ObjectStore {
                key,
                operation,
                source,
            } => write!(f, "object-store {operation} failed for {key:?}: {source}"),
            Self::AmbiguousRemoteState { key, detail } => {
                write!(f, "ambiguous remote state for {key:?}: {detail}")
            }
            Self::CleanupAfterEvidenceFailure {
                key,
                detail,
                cleanup,
            } => write!(
                f,
                "local evidence failed for {key:?} ({detail}) and multipart cleanup failed: {cleanup}"
            ),
            Self::CheckpointPersistence { key, source } => match key {
                Some(key) => write!(f, "cannot persist upload checkpoint for {key:?}: {source}"),
                None => write!(f, "cannot persist upload checkpoint: {source}"),
            },
            Self::RemoteBundleVerification(source) => {
                write!(f, "frozen bundle rejected verified object receipts: {source}")
            }
        }
    }
}

impl std::error::Error for DerivedUploadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ArtifactOpen { source, .. } => Some(source),
            Self::ObjectStore { source, .. } => Some(source.as_ref()),
            Self::CleanupAfterEvidenceFailure { cleanup, .. } => Some(cleanup.as_ref()),
            Self::CheckpointPersistence { source, .. } => Some(source),
            Self::RemoteBundleVerification(source) => Some(source),
            Self::InvalidConfiguration(_)
            | Self::InvalidFrozenBundle(_)
            | Self::SourceArchivalMustRemainDisabled
            | Self::UnsignedAdmissionMissingOrMismatched
            | Self::CheckpointMismatch(_)
            | Self::ArtifactRead { .. }
            | Self::LocalEvidenceMismatch { .. }
            | Self::AmbiguousRemoteState { .. } => None,
        }
    }
}

/// Thin orchestration over an existing [`ObjectStorePort`].
pub struct DerivedUploadAdapter<'a> {
    object_store: &'a dyn ObjectStorePort,
    artifacts: &'a dyn LocalArtifactSource,
    storage_profile_identity: StorageProfileIdentity,
    multipart_part_size_bytes: u64,
}

impl<'a> DerivedUploadAdapter<'a> {
    pub fn new(
        object_store: &'a dyn ObjectStorePort,
        artifacts: &'a dyn LocalArtifactSource,
        storage_profile_identity: StorageProfileIdentity,
        multipart_part_size_bytes: u64,
    ) -> Result<Self, DerivedUploadError> {
        validate_part_size(multipart_part_size_bytes)?;
        Ok(Self {
            object_store,
            artifacts,
            storage_profile_identity,
            multipart_part_size_bytes,
        })
    }

    /// Creates the exact durable projection that must be saved before remote
    /// work starts.
    pub fn checkpoint_for(
        &self,
        bundle: &FrozenUploadBundle,
    ) -> Result<UploadBundleCheckpoint, DerivedUploadError> {
        validate_frozen_bundle(bundle, &self.storage_profile_identity)?;
        let objects = bundle
            .objects()
            .iter()
            .map(|object| ObjectUploadCheckpoint {
                key: object.object_key().clone(),
                size_bytes: object.size_bytes(),
                sha256: object.sha256(),
                media_type: object.media_type().to_string(),
                phase: ObjectUploadPhase::Pending,
            })
            .collect();
        Ok(UploadBundleCheckpoint {
            schema_version: UPLOAD_CHECKPOINT_SCHEMA_VERSION,
            natural_key: bundle.natural_key(),
            objects,
        })
    }

    /// Rebuilds completion-bound remote evidence from a durable checkpoint.
    ///
    /// A projector recovering an already successful upload must use the exact
    /// completion and verification receipts persisted by the worker. It must
    /// never certify a latest-key HEAD as a substitute for that evidence.
    pub fn remote_bundle_from_checkpoint(
        bundle: &FrozenUploadBundle,
        storage_profile_identity: StorageProfileIdentity,
        checkpoint: &UploadBundleCheckpoint,
    ) -> Result<RemoteBundleReceipt, DerivedUploadError> {
        validate_frozen_bundle(bundle, &storage_profile_identity)?;
        validate_checkpoint_shape(bundle, storage_profile_identity.clone(), checkpoint)?;
        let object_receipts = checkpoint
            .objects
            .iter()
            .map(receipt_from_checkpoint)
            .collect::<Result<Vec<_>, _>>()?;
        bundle
            .verify_remote(storage_profile_identity, object_receipts)
            .map_err(DerivedUploadError::RemoteBundleVerification)
    }

    /// Uploads or resumes a frozen bundle. The final element is known by core
    /// to be the derived manifest and is therefore reached only after every
    /// prior object's `Verified` checkpoint is durable.
    pub fn upload_bundle(
        &self,
        bundle: &FrozenUploadBundle,
        checkpoint: &mut UploadBundleCheckpoint,
        sink: &dyn UploadCheckpointSink,
    ) -> Result<DerivedUploadReceipt, DerivedUploadError> {
        validate_frozen_bundle(bundle, &self.storage_profile_identity)?;
        self.validate_checkpoint(bundle, checkpoint)?;
        persist_checkpoint(sink, checkpoint, None)?;

        let manifest_index = bundle.objects().len() - 1;
        if !matches!(
            &checkpoint.objects[manifest_index].phase,
            ObjectUploadPhase::Pending
        ) && checkpoint.objects[..manifest_index]
            .iter()
            .any(|item| !matches!(&item.phase, ObjectUploadPhase::Verified { .. }))
        {
            return Err(DerivedUploadError::CheckpointMismatch(
                "final manifest has remote progress before every data object is verified"
                    .to_string(),
            ));
        }

        for (index, object) in bundle.objects().iter().enumerate() {
            self.upload_object(object, checkpoint, index, sink)?;
        }

        let remote_bundle = Self::remote_bundle_from_checkpoint(
            bundle,
            self.storage_profile_identity.clone(),
            checkpoint,
        )?;

        if remote_bundle.is_source_backup() {
            return Err(DerivedUploadError::SourceArchivalMustRemainDisabled);
        }

        Ok(DerivedUploadReceipt { remote_bundle })
    }

    fn upload_object(
        &self,
        object: &FrozenUploadObject,
        checkpoint: &mut UploadBundleCheckpoint,
        index: usize,
        sink: &dyn UploadCheckpointSink,
    ) -> Result<(), DerivedUploadError> {
        loop {
            match checkpoint.objects[index].phase.clone() {
                ObjectUploadPhase::Pending => {
                    let key = object.object_key().clone();
                    let handle = self
                        .object_store
                        .initiate_multipart_upload(InitiateUploadRequest {
                            key: key.clone(),
                            content_length: object.size_bytes(),
                            source_sha256: object.sha256(),
                            content_type: Some(object.media_type().to_string()),
                        })
                        .map_err(|source| {
                            store_failure(&key, "initiate multipart upload", source)
                        })?;
                    checkpoint.objects[index].phase = ObjectUploadPhase::Uploading {
                        handle,
                        part_size_bytes: self.multipart_part_size_bytes,
                        completed_parts: Vec::new(),
                    };
                    persist_checkpoint(sink, checkpoint, Some(&key))?;
                }
                ObjectUploadPhase::Uploading {
                    handle,
                    part_size_bytes,
                    completed_parts,
                } => {
                    self.upload_remaining_parts(
                        object,
                        checkpoint,
                        index,
                        sink,
                        handle,
                        part_size_bytes,
                        completed_parts,
                    )?;
                }
                ObjectUploadPhase::Completed { completion } => {
                    let key = object.object_key().clone();
                    let verification = self
                        .object_store
                        .verify_completed_object(
                            &completion,
                            &ExpectedObject {
                                size_bytes: object.size_bytes(),
                                source_sha256: object.sha256(),
                            },
                        )
                        .map_err(|source| store_failure(&key, "verify completed object", source))?;
                    checkpoint.objects[index].phase = ObjectUploadPhase::Verified {
                        completion,
                        verification,
                    };
                    persist_checkpoint(sink, checkpoint, Some(&key))?;
                }
                ObjectUploadPhase::Verified {
                    completion,
                    verification,
                } => {
                    CompletionBoundObjectReceipt::bind(completion, verification)
                        .map_err(DerivedUploadError::RemoteBundleVerification)?;
                    return Ok(());
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn upload_remaining_parts(
        &self,
        object: &FrozenUploadObject,
        checkpoint: &mut UploadBundleCheckpoint,
        index: usize,
        sink: &dyn UploadCheckpointSink,
        handle: MultipartUploadHandle,
        part_size_bytes: u64,
        mut completed_parts: Vec<PartETag>,
    ) -> Result<(), DerivedUploadError> {
        validate_part_size(part_size_bytes)?;
        let key = object.object_key().clone();
        let part_count = expected_part_count(object.size_bytes(), part_size_bytes)?;
        validate_completed_parts(&key, &completed_parts, part_count)?;

        let mut reader = self
            .artifacts
            .open(object.local_artifact())
            .map_err(|source| DerivedUploadError::ArtifactOpen {
                key: key.clone(),
                source,
            })?;
        let mut hasher = Sha256::new();
        let mut remaining = object.size_bytes();

        for zero_based_part in 0..part_count {
            let wanted = remaining.min(part_size_bytes);
            let mut bytes = vec![
                0_u8;
                usize::try_from(wanted).map_err(|_| {
                    DerivedUploadError::InvalidConfiguration(
                        "multipart part size does not fit this platform".to_string(),
                    )
                })?
            ];
            let read = read_fully(&mut *reader, &mut bytes).map_err(|source| {
                DerivedUploadError::ArtifactRead {
                    key: key.clone(),
                    detail: sanitize_local_detail(source.to_string()),
                }
            })?;
            if read != bytes.len() {
                let detail = format!(
                    "expected {} bytes in part {}, reached EOF after {read}",
                    bytes.len(),
                    zero_based_part + 1
                );
                return self.abort_after_evidence_failure(checkpoint, index, sink, &handle, detail);
            }
            hasher.update(&bytes);
            remaining -= wanted;

            if zero_based_part >= completed_parts.len() {
                let raw_part_number = u16::try_from(zero_based_part + 1).map_err(|_| {
                    DerivedUploadError::InvalidConfiguration(
                        "multipart upload exceeds the 10,000-part limit".to_string(),
                    )
                })?;
                let part_number = PartNumber::new(raw_part_number)
                    .map_err(|source| store_failure(&key, "create part number", source))?;
                let part = self
                    .object_store
                    .upload_part(&handle, part_number, &bytes)
                    .map_err(|source| store_failure(&key, "upload part", source))?;
                completed_parts.push(part);
                checkpoint.objects[index].phase = ObjectUploadPhase::Uploading {
                    handle: handle.clone(),
                    part_size_bytes,
                    completed_parts: completed_parts.clone(),
                };
                persist_checkpoint(sink, checkpoint, Some(&key))?;
            }
        }

        let mut trailing = [0_u8; 1];
        let trailing_read =
            read_retry_interrupted(&mut *reader, &mut trailing).map_err(|source| {
                DerivedUploadError::ArtifactRead {
                    key: key.clone(),
                    detail: sanitize_local_detail(source.to_string()),
                }
            })?;
        if trailing_read != 0 {
            return self.abort_after_evidence_failure(
                checkpoint,
                index,
                sink,
                &handle,
                format!(
                    "artifact contains more than the frozen {} bytes",
                    object.size_bytes()
                ),
            );
        }

        let actual = SourceSha256::from_bytes(hasher.finalize().into());
        if actual != object.sha256() {
            return self.abort_after_evidence_failure(
                checkpoint,
                index,
                sink,
                &handle,
                format!(
                    "expected SHA-256 {}, local bytes hash to {actual}",
                    object.sha256()
                ),
            );
        }

        let completion = match self
            .object_store
            .complete_multipart_upload(&handle, completed_parts)
        {
            Ok(completion) => completion,
            // The remote service may have committed the completion just before
            // its response was lost.  There is no completion-bound receipt to
            // persist in that case, so retrying or accepting a latest-key HEAD
            // would either overwrite an immutable object or certify another
            // writer's version.  Leave the durable Uploading checkpoint intact
            // and make the operator/recovery owner resolve the ambiguity.
            Err(ObjectStoreError::UnknownUpload(_)) => {
                return Err(DerivedUploadError::AmbiguousRemoteState {
                    key,
                    detail: "multipart completion response was lost or the upload vanished; no completion-bound receipt is available".to_string(),
                });
            }
            Err(source) => return Err(store_failure(&key, "complete multipart upload", source)),
        };
        checkpoint.objects[index].phase = ObjectUploadPhase::Completed { completion };
        persist_checkpoint(sink, checkpoint, Some(&key))?;
        Ok(())
    }

    fn abort_after_evidence_failure(
        &self,
        checkpoint: &mut UploadBundleCheckpoint,
        index: usize,
        sink: &dyn UploadCheckpointSink,
        handle: &MultipartUploadHandle,
        detail: String,
    ) -> Result<(), DerivedUploadError> {
        let key = handle.key.clone();
        match self.object_store.abort_multipart_upload(handle) {
            Ok(()) => {
                checkpoint.objects[index].phase = ObjectUploadPhase::Pending;
                persist_checkpoint(sink, checkpoint, Some(&key))?;
                Err(DerivedUploadError::LocalEvidenceMismatch {
                    key,
                    detail,
                })
            }
            Err(ObjectStoreError::UnknownUpload(_)) => {
                Err(DerivedUploadError::AmbiguousRemoteState {
                    key,
                    detail: format!(
                        "local evidence failed ({detail}), but the multipart upload is already finalized or absent; refusing to overwrite the immutable key"
                    ),
                })
            }
            Err(cleanup) => Err(DerivedUploadError::CleanupAfterEvidenceFailure {
                key,
                detail,
                cleanup: Box::new(cleanup),
            }),
        }
    }

    fn validate_checkpoint(
        &self,
        bundle: &FrozenUploadBundle,
        checkpoint: &UploadBundleCheckpoint,
    ) -> Result<(), DerivedUploadError> {
        validate_checkpoint_shape(bundle, self.storage_profile_identity.clone(), checkpoint)
    }
}

fn validate_checkpoint_shape(
    bundle: &FrozenUploadBundle,
    storage_profile_identity: StorageProfileIdentity,
    checkpoint: &UploadBundleCheckpoint,
) -> Result<(), DerivedUploadError> {
    if checkpoint.schema_version != UPLOAD_CHECKPOINT_SCHEMA_VERSION {
        return Err(DerivedUploadError::CheckpointMismatch(format!(
            "unsupported checkpoint schema {}, expected {UPLOAD_CHECKPOINT_SCHEMA_VERSION}",
            checkpoint.schema_version
        )));
    }
    if bundle.storage_profile_identity() != &storage_profile_identity {
        return Err(DerivedUploadError::CheckpointMismatch(
            "storage profile differs from the frozen bundle".to_string(),
        ));
    }
    let expected_natural_key = bundle.natural_key();
    if checkpoint.natural_key != expected_natural_key {
        return Err(DerivedUploadError::CheckpointMismatch(
            "natural key differs".to_string(),
        ));
    }
    if checkpoint.objects.len() != bundle.objects().len() {
        return Err(DerivedUploadError::CheckpointMismatch(format!(
            "expected {} object checkpoints, found {}",
            bundle.objects().len(),
            checkpoint.objects.len()
        )));
    }

    for (object, item) in bundle.objects().iter().zip(&checkpoint.objects) {
        if item.key != *object.object_key()
            || item.size_bytes != object.size_bytes()
            || item.sha256 != object.sha256()
            || item.media_type != object.media_type()
        {
            return Err(DerivedUploadError::CheckpointMismatch(format!(
                "object evidence differs for {:?}",
                object.object_key()
            )));
        }
        validate_object_phase(object, &item.phase)?;
    }
    Ok(())
}

fn validate_frozen_bundle(
    bundle: &FrozenUploadBundle,
    expected_storage_profile_identity: &StorageProfileIdentity,
) -> Result<(), DerivedUploadError> {
    if bundle.storage_profile_identity() != expected_storage_profile_identity {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "storage profile identity differs from the configured adapter".to_string(),
        ));
    }
    if bundle.upload_policy_revision() != DERIVED_UPLOAD_POLICY_REVISION {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "upload policy revision is not supported by this adapter".to_string(),
        ));
    }
    if !matches!(bundle.source_archival(), SourceArchivalPolicy::Disabled) {
        return Err(DerivedUploadError::SourceArchivalMustRemainDisabled);
    }
    if bundle
        .objects()
        .iter()
        .any(|object| matches!(object.role(), UploadObjectRole::SourceVideoArchive { .. }))
    {
        return Err(DerivedUploadError::SourceArchivalMustRemainDisabled);
    }
    match bundle.source_provenance() {
        SourceProvenance::DeviceSigned(_) if bundle.unsigned_admission().is_none() => {}
        SourceProvenance::LocallyValidatedUnsigned(_) => {
            let request = bundle
                .unsigned_upload_admission_request()
                .map_err(|error| DerivedUploadError::InvalidFrozenBundle(error.to_string()))?;
            if !bundle
                .unsigned_admission()
                .is_some_and(|receipt| receipt.matches(&request))
            {
                return Err(DerivedUploadError::UnsignedAdmissionMissingOrMismatched);
            }
        }
        SourceProvenance::DeviceSigned(_) => {
            return Err(DerivedUploadError::InvalidFrozenBundle(
                "signed source unexpectedly carries an unsigned admission receipt".to_string(),
            ));
        }
    }

    let Some((manifest, data_objects)) = bundle.objects().split_last() else {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "bundle has no objects".to_string(),
        ));
    };
    if !matches!(manifest.role(), UploadObjectRole::DerivedManifest) {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "final object is not the derived manifest".to_string(),
        ));
    }
    if data_objects
        .iter()
        .any(|object| matches!(object.role(), UploadObjectRole::DerivedManifest))
    {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "derived manifest appears before the final object".to_string(),
        ));
    }
    if !data_objects
        .iter()
        .any(|object| matches!(object.role(), UploadObjectRole::DerivedMedia { .. }))
    {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "bundle contains no derived media".to_string(),
        ));
    }
    Ok(())
}

fn validate_object_phase(
    object: &FrozenUploadObject,
    phase: &ObjectUploadPhase,
) -> Result<(), DerivedUploadError> {
    let key = object.object_key();
    match phase {
        ObjectUploadPhase::Pending => Ok(()),
        ObjectUploadPhase::Uploading {
            handle,
            part_size_bytes,
            completed_parts,
        } => {
            if handle.key != *key {
                return Err(DerivedUploadError::CheckpointMismatch(format!(
                    "multipart handle key differs for {key:?}"
                )));
            }
            validate_part_size(*part_size_bytes)?;
            let part_count = expected_part_count(object.size_bytes(), *part_size_bytes)?;
            validate_completed_parts(key, completed_parts, part_count)
        }
        ObjectUploadPhase::Completed { completion } => validate_completion_key(key, completion),
        ObjectUploadPhase::Verified {
            completion,
            verification,
        } => {
            validate_completion_key(key, completion)?;
            if verification.key != *key
                || verification.size_bytes != object.size_bytes()
                || verification.source_sha256 != object.sha256()
                || verification.etag != completion.etag
                || verification.version_id != completion.version_id
            {
                return Err(DerivedUploadError::CheckpointMismatch(format!(
                    "verified receipt is not bound to completion/evidence for {key:?}"
                )));
            }
            Ok(())
        }
    }
}

fn validate_completion_key(
    expected_key: &ObjectKey,
    completion: &CompletedUpload,
) -> Result<(), DerivedUploadError> {
    if completion.key != *expected_key {
        return Err(DerivedUploadError::CheckpointMismatch(format!(
            "completion key differs for {expected_key:?}"
        )));
    }
    Ok(())
}

fn validate_part_size(part_size_bytes: u64) -> Result<(), DerivedUploadError> {
    if !(MIN_MULTIPART_PART_SIZE_BYTES..=MAX_MULTIPART_PART_SIZE_BYTES).contains(&part_size_bytes) {
        return Err(DerivedUploadError::InvalidConfiguration(format!(
            "multipart part size must be between {MIN_MULTIPART_PART_SIZE_BYTES} and {MAX_MULTIPART_PART_SIZE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn expected_part_count(size_bytes: u64, part_size_bytes: u64) -> Result<usize, DerivedUploadError> {
    if size_bytes == 0 {
        return Err(DerivedUploadError::InvalidFrozenBundle(
            "zero-length multipart object".to_string(),
        ));
    }
    let count = ((size_bytes - 1) / part_size_bytes) + 1;
    if count > u64::from(PartNumber::MAX) {
        return Err(DerivedUploadError::InvalidConfiguration(format!(
            "object requires {count} multipart parts, exceeding {}",
            PartNumber::MAX
        )));
    }
    usize::try_from(count).map_err(|_| {
        DerivedUploadError::InvalidConfiguration(
            "multipart part count does not fit this platform".to_string(),
        )
    })
}

fn validate_completed_parts(
    key: &ObjectKey,
    parts: &[PartETag],
    expected_part_count: usize,
) -> Result<(), DerivedUploadError> {
    if parts.len() > expected_part_count {
        return Err(DerivedUploadError::CheckpointMismatch(format!(
            "too many completed parts for {key:?}"
        )));
    }
    for (index, part) in parts.iter().enumerate() {
        let expected = u16::try_from(index + 1).map_err(|_| {
            DerivedUploadError::CheckpointMismatch(format!("part number does not fit for {key:?}"))
        })?;
        if part.part_number.get() != expected || part.etag.is_empty() {
            return Err(DerivedUploadError::CheckpointMismatch(format!(
                "completed parts are not contiguous with non-empty ETags for {key:?}"
            )));
        }
    }
    Ok(())
}

fn receipt_from_checkpoint(
    checkpoint: &ObjectUploadCheckpoint,
) -> Result<CompletionBoundObjectReceipt, DerivedUploadError> {
    match &checkpoint.phase {
        ObjectUploadPhase::Verified {
            completion,
            verification,
        } => CompletionBoundObjectReceipt::bind(completion.clone(), verification.clone())
            .map_err(DerivedUploadError::RemoteBundleVerification),
        _ => Err(DerivedUploadError::CheckpointMismatch(format!(
            "object {:?} is not verified after upload execution",
            checkpoint.key
        ))),
    }
}

fn persist_checkpoint(
    sink: &dyn UploadCheckpointSink,
    checkpoint: &UploadBundleCheckpoint,
    key: Option<&ObjectKey>,
) -> Result<(), DerivedUploadError> {
    sink.persist(checkpoint)
        .map_err(|source| DerivedUploadError::CheckpointPersistence {
            key: key.cloned(),
            source,
        })
}

fn store_failure(
    key: &ObjectKey,
    operation: &'static str,
    source: ObjectStoreError,
) -> DerivedUploadError {
    if matches!(&source, ObjectStoreError::UnknownUpload(_)) {
        DerivedUploadError::AmbiguousRemoteState {
            key: key.clone(),
            detail: format!(
                "{operation} reported an unknown/finalized upload id; a completion receipt was not available, so latest-key verification or overwrite would not be completion-bound"
            ),
        }
    } else {
        DerivedUploadError::ObjectStore {
            key: key.clone(),
            operation,
            source: Box::new(source),
        }
    }
}

fn read_fully(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn read_retry_interrupted(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn sanitize_local_detail(detail: String) -> String {
    const MAX_DETAIL_BYTES: usize = 1_024;
    let mut sanitized = String::with_capacity(detail.len().min(MAX_DETAIL_BYTES));
    for character in detail.chars() {
        if sanitized.len() + character.len_utf8() > MAX_DETAIL_BYTES {
            break;
        }
        sanitized.push(if character.is_control() {
            '\u{fffd}'
        } else {
            character
        });
    }
    if detail.len() > sanitized.len() {
        sanitized.push_str("...[truncated]");
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use ylx_transfer_core::ingest::{InventoryDigest, SourceContentRevision};
    use ylx_transfer_core::library::object_store_port::{
        FaultPoint, ImmutableObjectRequest, MemoryObjectStore, ObjectListPage, ObjectReadback,
    };
    use ylx_transfer_core::media_pipeline::{
        ObjectNamespace, UploadBundleInput, UploadObjectInput,
    };
    use ylx_transfer_core::normalization::{DerivedRevision, ProfileRevision};

    struct BytesArtifacts(BTreeMap<String, Vec<u8>>);

    impl LocalArtifactSource for BytesArtifacts {
        fn open(
            &self,
            artifact: &LocalArtifactRef,
        ) -> Result<Box<dyn Read + Send>, ArtifactReadError> {
            self.0
                .get(artifact.as_str())
                .cloned()
                .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read + Send>)
                .ok_or_else(|| ArtifactReadError::new("test artifact is absent"))
        }
    }

    #[derive(Default)]
    struct RecordingCheckpointSink;

    impl UploadCheckpointSink for RecordingCheckpointSink {
        fn persist(&self, _: &UploadBundleCheckpoint) -> Result<(), CheckpointPersistenceError> {
            Ok(())
        }
    }

    struct ObservedStore {
        inner: MemoryObjectStore,
        lose_completion_response: AtomicBool,
        initiate_keys: Mutex<Vec<ObjectKey>>,
        latest_key_checks: AtomicUsize,
    }

    impl ObservedStore {
        fn new(lose_completion_response: bool) -> Self {
            Self {
                inner: MemoryObjectStore::new(),
                lose_completion_response: AtomicBool::new(lose_completion_response),
                initiate_keys: Mutex::new(Vec::new()),
                latest_key_checks: AtomicUsize::new(0),
            }
        }
    }

    impl ObjectStorePort for ObservedStore {
        fn put_object_if_absent(
            &self,
            request: &ImmutableObjectRequest,
        ) -> Result<bool, ObjectStoreError> {
            self.inner.put_object_if_absent(request)
        }

        fn read_object_bounded(
            &self,
            key: &ObjectKey,
            maximum_bytes: u64,
        ) -> Result<ObjectReadback, ObjectStoreError> {
            self.inner.read_object_bounded(key, maximum_bytes)
        }

        fn list_objects_bounded(
            &self,
            prefix: &str,
            maximum_keys: u16,
        ) -> Result<ObjectListPage, ObjectStoreError> {
            self.inner.list_objects_bounded(prefix, maximum_keys)
        }

        fn initiate_multipart_upload(
            &self,
            request: InitiateUploadRequest,
        ) -> Result<MultipartUploadHandle, ObjectStoreError> {
            self.initiate_keys
                .lock()
                .expect("initiate keys")
                .push(request.key.clone());
            self.inner.initiate_multipart_upload(request)
        }

        fn upload_part(
            &self,
            handle: &MultipartUploadHandle,
            part_number: PartNumber,
            bytes: &[u8],
        ) -> Result<PartETag, ObjectStoreError> {
            self.inner.upload_part(handle, part_number, bytes)
        }

        fn complete_multipart_upload(
            &self,
            handle: &MultipartUploadHandle,
            parts: Vec<PartETag>,
        ) -> Result<CompletedUpload, ObjectStoreError> {
            let completion = self.inner.complete_multipart_upload(handle, parts)?;
            if self.lose_completion_response.swap(false, Ordering::AcqRel) {
                return Err(ObjectStoreError::UnknownUpload(handle.upload_id.clone()));
            }
            Ok(completion)
        }

        fn abort_multipart_upload(
            &self,
            handle: &MultipartUploadHandle,
        ) -> Result<(), ObjectStoreError> {
            self.inner.abort_multipart_upload(handle)
        }

        fn verify_object(
            &self,
            key: &ObjectKey,
            expected: &ExpectedObject,
        ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
            self.latest_key_checks.fetch_add(1, Ordering::AcqRel);
            self.inner.verify_object(key, expected)
        }

        fn verify_completed_object(
            &self,
            completion: &CompletedUpload,
            expected: &ExpectedObject,
        ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
            self.inner.verify_completed_object(completion, expected)
        }
    }

    fn fixture_bundle() -> (FrozenUploadBundle, BytesArtifacts) {
        let objects = [
            (
                UploadObjectRole::SourceManifest,
                "source-manifest",
                b"source".as_slice(),
            ),
            (
                UploadObjectRole::ProvenanceReport,
                "provenance",
                b"provenance".as_slice(),
            ),
            (
                UploadObjectRole::DerivedMedia {
                    opaque_file_id: "segment-1".to_string(),
                },
                "derived-media",
                b"derived-media".as_slice(),
            ),
            (
                UploadObjectRole::DerivedManifest,
                "derived-manifest",
                b"manifest".as_slice(),
            ),
        ];
        let artifacts = BytesArtifacts(
            objects
                .iter()
                .map(|(_, name, bytes)| (name.to_string(), bytes.to_vec()))
                .collect(),
        );
        let inputs = objects
            .iter()
            .map(|(role, name, bytes)| {
                UploadObjectInput::new(
                    role.clone(),
                    LocalArtifactRef::parse(*name).expect("artifact reference"),
                    bytes.len() as u64,
                    SourceSha256::from_bytes(Sha256::digest(bytes).into()),
                    "application/octet-stream",
                )
                .expect("upload object")
            })
            .collect();
        let source_provenance = serde_json::from_value(serde_json::json!({
            "kind": "device_signed",
            "evidence": {
                "publication_key_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "publication_revision": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "publication_payload": [1], "publication_signature": [2], "publication_public_key": [3]
            }
        }))
        .expect("source provenance");
        let bundle = FrozenUploadBundle::freeze(UploadBundleInput {
            namespace: ObjectNamespace::from_raw_segments(["test"]).expect("namespace"),
            origin_identity: "origin-1".to_string(),
            session_or_source_id: "session-1".to_string(),
            source_revision: SourceContentRevision::from_material(b"source revision"),
            source_provenance,
            source_inventory_digest: InventoryDigest::from_material(b"inventory"),
            unsigned_admission: None,
            profile_revision: ProfileRevision::from_canonical_bytes(b"profile"),
            derived_revision: DerivedRevision::from_canonical_bytes(b"derived"),
            storage_profile_identity: storage_identity(),
            source_archival: SourceArchivalPolicy::Disabled,
            upload_policy_revision: DERIVED_UPLOAD_POLICY_REVISION.to_string(),
            objects: inputs,
        })
        .expect("frozen bundle");
        (bundle, artifacts)
    }

    fn storage_identity() -> StorageProfileIdentity {
        StorageProfileIdentity::parse("test-storage-profile").expect("storage identity")
    }

    #[test]
    fn lost_completion_response_is_ambiguous_without_latest_key_recovery_or_overwrite() {
        let (bundle, artifacts) = fixture_bundle();
        let store = ObservedStore::new(true);
        let adapter = DerivedUploadAdapter::new(
            &store,
            &artifacts,
            storage_identity(),
            MIN_MULTIPART_PART_SIZE_BYTES,
        )
        .expect("adapter");
        let mut checkpoint = adapter.checkpoint_for(&bundle).expect("checkpoint");
        let sink = RecordingCheckpointSink;

        let error = adapter
            .upload_bundle(&bundle, &mut checkpoint, &sink)
            .expect_err("lost completion response must remain ambiguous");
        assert!(matches!(
            error,
            DerivedUploadError::AmbiguousRemoteState { .. }
        ));
        assert_eq!(store.latest_key_checks.load(Ordering::Acquire), 0);
        assert_eq!(store.inner.object_count(), 1);
        assert!(matches!(
            checkpoint.objects()[0].phase(),
            ObjectUploadPhase::Uploading { .. }
        ));

        let retry = adapter.upload_bundle(&bundle, &mut checkpoint, &sink);
        assert!(matches!(
            retry,
            Err(DerivedUploadError::AmbiguousRemoteState { .. })
        ));
        assert_eq!(
            store.inner.object_count(),
            1,
            "retry must not overwrite the committed key"
        );
        assert_eq!(store.initiate_keys.lock().expect("initiate keys").len(), 1);
        assert_eq!(store.latest_key_checks.load(Ordering::Acquire), 0);
    }

    #[test]
    fn manifest_is_never_initiated_until_every_data_object_is_verified_and_stays_last_on_resume() {
        let (bundle, artifacts) = fixture_bundle();
        let store = ObservedStore::new(false);
        store.inner.queue_fault(
            FaultPoint::VerifyObject,
            ObjectStoreError::Network("verification interrupted".to_string()),
        );
        let adapter = DerivedUploadAdapter::new(
            &store,
            &artifacts,
            storage_identity(),
            MIN_MULTIPART_PART_SIZE_BYTES,
        )
        .expect("adapter");
        let mut checkpoint = adapter.checkpoint_for(&bundle).expect("checkpoint");
        let sink = RecordingCheckpointSink;

        assert!(matches!(
            adapter.upload_bundle(&bundle, &mut checkpoint, &sink),
            Err(DerivedUploadError::ObjectStore {
                operation: "verify completed object",
                ..
            })
        ));
        let manifest_key = bundle
            .objects()
            .last()
            .expect("manifest")
            .object_key()
            .clone();
        assert!(!store
            .initiate_keys
            .lock()
            .expect("initiate keys")
            .contains(&manifest_key));
        assert!(matches!(
            checkpoint.objects()[0].phase(),
            ObjectUploadPhase::Completed { .. }
        ));
        assert!(matches!(
            checkpoint.objects().last().expect("manifest").phase(),
            ObjectUploadPhase::Pending
        ));

        adapter
            .upload_bundle(&bundle, &mut checkpoint, &sink)
            .expect("resume upload");
        let initiated = store.initiate_keys.lock().expect("initiate keys").clone();
        assert_eq!(initiated.last(), Some(&manifest_key));
        assert_eq!(
            initiated.iter().filter(|key| **key == manifest_key).count(),
            1
        );
        assert!(checkpoint
            .objects()
            .iter()
            .all(|item| matches!(item.phase(), ObjectUploadPhase::Verified { .. })));
    }
}
