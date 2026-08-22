use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::ingest::{
    ImportJobId, LocalSourceReceipt, SourceContentRevision, SourceProvenance, SourceRecording,
};
use crate::normalization::{
    DerivationJobId, DerivedCompletion, DerivedRevision, ProfileRevision, SourceManifestDigest,
};
use crate::transfer::JobId as UploadJobId;

use super::{
    FrozenUploadBundle, LocalArtifactRef, RemoteBundleReceipt, SourceArchivalPolicy,
    SourceRetentionPolicy, StorageProfileIdentity, UnsignedUploadAdmissionReceipt,
    UnsignedUploadAdmissionRequest, UploadBundleRevision, UploadJobNaturalKey,
    DERIVED_UPLOAD_POLICY_REVISION,
};

/// Opaque durable identity for one session pipeline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SessionPipelineId(String);

impl SessionPipelineId {
    #[must_use]
    pub fn new() -> Self {
        Self(format!("media-pipeline-{}", uuid::Uuid::new_v4()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, PipelineError> {
        let value = value.into();
        validate_reference("session_pipeline_id", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SessionPipelineId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

impl Default for SessionPipelineId {
    fn default() -> Self {
        Self::new()
    }
}

/// User policy for the dependency chain. Upload always includes
/// normalization; there is no direct source-to-object-store shortcut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum PipelinePolicy {
    ImportOnly,
    AutoNormalize {
        profile_revision: ProfileRevision,
    },
    AutoUpload {
        profile_revision: ProfileRevision,
        storage_profile_identity: StorageProfileIdentity,
        source_archival: SourceArchivalPolicy,
        source_retention: SourceRetentionPolicy,
    },
}

impl PipelinePolicy {
    #[must_use]
    pub fn auto_upload(
        profile_revision: ProfileRevision,
        storage_profile_identity: StorageProfileIdentity,
    ) -> Self {
        Self::AutoUpload {
            profile_revision,
            storage_profile_identity,
            source_archival: SourceArchivalPolicy::default(),
            source_retention: SourceRetentionPolicy::default(),
        }
    }

    #[must_use]
    pub fn profile_revision(&self) -> Option<&ProfileRevision> {
        match self {
            Self::ImportOnly => None,
            Self::AutoNormalize { profile_revision }
            | Self::AutoUpload {
                profile_revision, ..
            } => Some(profile_revision),
        }
    }

    #[must_use]
    pub fn storage_profile_identity(&self) -> Option<&StorageProfileIdentity> {
        match self {
            Self::AutoUpload {
                storage_profile_identity,
                ..
            } => Some(storage_profile_identity),
            Self::ImportOnly | Self::AutoNormalize { .. } => None,
        }
    }

    #[must_use]
    pub fn source_archival(&self) -> &SourceArchivalPolicy {
        match self {
            Self::AutoUpload {
                source_archival, ..
            } => source_archival,
            Self::ImportOnly | Self::AutoNormalize { .. } => {
                static DISABLED: SourceArchivalPolicy = SourceArchivalPolicy::Disabled;
                &DISABLED
            }
        }
    }

    #[must_use]
    pub fn source_retention(&self) -> &SourceRetentionPolicy {
        match self {
            Self::AutoUpload {
                source_retention, ..
            } => source_retention,
            Self::ImportOnly | Self::AutoNormalize { .. } => {
                static DISABLED: SourceRetentionPolicy = SourceRetentionPolicy::Disabled;
                &DISABLED
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStartRequest {
    pipeline_id: SessionPipelineId,
    source: SourceRecording,
    import_job_id: ImportJobId,
    policy: PipelinePolicy,
}

impl PipelineStartRequest {
    #[must_use]
    pub fn new(
        source: SourceRecording,
        import_job_id: ImportJobId,
        policy: PipelinePolicy,
    ) -> Self {
        Self {
            pipeline_id: SessionPipelineId::new(),
            source,
            import_job_id,
            policy,
        }
    }

    #[must_use]
    pub fn with_pipeline_id(
        pipeline_id: SessionPipelineId,
        source: SourceRecording,
        import_job_id: ImportJobId,
        policy: PipelinePolicy,
    ) -> Self {
        Self {
            pipeline_id,
            source,
            import_job_id,
            policy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDependency {
    job_id: ImportJobId,
}

impl ImportDependency {
    #[must_use]
    pub fn job_id(&self) -> &ImportJobId {
        &self.job_id
    }
}

/// Exact natural key of a derivation request. Encoder build and exact input
/// inventory remain part of the normalizer's own spec/conflict check; this
/// dependency key expresses the pipeline policy boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DerivationNaturalKey {
    pub source_revision: SourceContentRevision,
    pub profile_revision: ProfileRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationDependency {
    natural_key: DerivationNaturalKey,
    job_id: DerivationJobId,
}

impl DerivationDependency {
    #[must_use]
    pub fn natural_key(&self) -> &DerivationNaturalKey {
        &self.natural_key
    }

    #[must_use]
    pub fn job_id(&self) -> &DerivationJobId {
        &self.job_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadDependency {
    natural_key: UploadJobNaturalKey,
    job_id: UploadJobId,
}

impl UploadDependency {
    #[must_use]
    pub fn natural_key(&self) -> &UploadJobNaturalKey {
        &self.natural_key
    }

    #[must_use]
    pub fn job_id(&self) -> &UploadJobId {
        &self.job_id
    }
}

/// Durable pipeline aggregate. It stores dependency references, never copies
/// an underlying job state, progress counter, desired state, or terminal
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPipeline {
    id: SessionPipelineId,
    source: SourceRecording,
    policy: PipelinePolicy,
    import: ImportDependency,
    derivation: Option<DerivationDependency>,
    upload: Option<UploadDependency>,
    unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
}

impl SessionPipeline {
    /// Reconciles a start against the row found by the import dependency's
    /// unique key. The repository must perform this under its normal CAS or
    /// unique constraint; this pure result tells it whether to insert, reuse,
    /// or surface a policy conflict.
    #[must_use]
    pub fn start(
        request: PipelineStartRequest,
        existing: Option<&SessionPipeline>,
    ) -> PipelineStartOutcome {
        if let Some(existing) = existing {
            if existing.import.job_id != request.import_job_id {
                return PipelineStartOutcome::Conflict {
                    existing_pipeline_id: existing.id.clone(),
                    reason: PipelineConflictReason::ImportDependencyMismatch,
                };
            }
            if existing.policy != request.policy {
                return PipelineStartOutcome::Conflict {
                    existing_pipeline_id: existing.id.clone(),
                    reason: PipelineConflictReason::PolicyMismatch,
                };
            }
            return PipelineStartOutcome::Existing {
                pipeline_id: existing.id.clone(),
            };
        }

        PipelineStartOutcome::Created {
            pipeline: Box::new(Self {
                id: request.pipeline_id,
                source: request.source,
                policy: request.policy,
                import: ImportDependency {
                    job_id: request.import_job_id,
                },
                derivation: None,
                upload: None,
                unsigned_admission: None,
            }),
        }
    }

    #[must_use]
    pub fn id(&self) -> &SessionPipelineId {
        &self.id
    }

    #[must_use]
    pub fn source(&self) -> &SourceRecording {
        &self.source
    }

    #[must_use]
    pub fn policy(&self) -> &PipelinePolicy {
        &self.policy
    }

    #[must_use]
    pub fn import_dependency(&self) -> &ImportDependency {
        &self.import
    }

    #[must_use]
    pub fn derivation_dependency(&self) -> Option<&DerivationDependency> {
        self.derivation.as_ref()
    }

    #[must_use]
    pub fn upload_dependency(&self) -> Option<&UploadDependency> {
        self.upload.as_ref()
    }

    #[must_use]
    pub fn unsigned_admission(&self) -> Option<&UnsignedUploadAdmissionReceipt> {
        self.unsigned_admission.as_ref()
    }

    /// Idempotently installs the result of a normalizer enqueue. The caller
    /// must persist this aggregate with expected-version CAS after the
    /// normalizer has returned Created or Existing for the same natural key.
    pub fn attach_derivation(
        &mut self,
        natural_key: DerivationNaturalKey,
        job_id: DerivationJobId,
    ) -> DependencyAttachOutcome {
        if self.policy.profile_revision() != Some(&natural_key.profile_revision) {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::PolicyMismatch,
            };
        }
        match &self.derivation {
            None => {
                self.derivation = Some(DerivationDependency {
                    natural_key,
                    job_id,
                });
                DependencyAttachOutcome::Attached
            }
            Some(existing) if existing.natural_key == natural_key && existing.job_id == job_id => {
                DependencyAttachOutcome::Existing
            }
            Some(_) => DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::DerivationDependencyMismatch,
            },
        }
    }

    /// Idempotently installs the result of a frozen-bundle upload enqueue.
    pub fn attach_upload(
        &mut self,
        natural_key: UploadJobNaturalKey,
        job_id: UploadJobId,
    ) -> DependencyAttachOutcome {
        if self.policy.storage_profile_identity() != Some(&natural_key.storage_profile_identity) {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::StorageProfileMismatch,
            };
        }
        match &self.upload {
            None => {
                self.upload = Some(UploadDependency {
                    natural_key,
                    job_id,
                });
                DependencyAttachOutcome::Attached
            }
            Some(existing) if existing.natural_key == natural_key && existing.job_id == job_id => {
                DependencyAttachOutcome::Existing
            }
            Some(_) => DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UploadDependencyMismatch,
            },
        }
    }

    /// Replaces one failed upload attempt with a fresh retry for the exact
    /// same frozen-bundle natural key. The expected parent id prevents a stale
    /// command from replacing a newer attempt that another caller attached.
    pub fn replace_upload_attempt(
        &mut self,
        expected_job_id: &UploadJobId,
        natural_key: UploadJobNaturalKey,
        retry_job_id: UploadJobId,
    ) -> DependencyAttachOutcome {
        if self.policy.storage_profile_identity() != Some(&natural_key.storage_profile_identity) {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::StorageProfileMismatch,
            };
        }
        match &mut self.upload {
            Some(existing)
                if existing.natural_key == natural_key && existing.job_id == *expected_job_id =>
            {
                existing.job_id = retry_job_id;
                DependencyAttachOutcome::Attached
            }
            Some(existing)
                if existing.natural_key == natural_key && existing.job_id == retry_job_id =>
            {
                DependencyAttachOutcome::Existing
            }
            Some(_) | None => DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UploadDependencyMismatch,
            },
        }
    }

    pub fn command(&mut self, command: PipelineCommand) -> DependencyAttachOutcome {
        match command {
            PipelineCommand::AttachDerivation {
                natural_key,
                job_id,
            } => self.attach_derivation(natural_key, job_id),
            PipelineCommand::AttachUpload {
                natural_key,
                job_id,
            } => self.attach_upload(natural_key, job_id),
            PipelineCommand::RecordUnsignedAdmission { receipt } => {
                self.record_unsigned_admission(*receipt)
            }
        }
    }

    /// Replays durable completion evidence after startup and returns exactly
    /// one next action. Repeating this method with unchanged evidence returns
    /// the same result and never enqueues by itself.
    pub fn recover(
        &self,
        evidence: PipelineEvidence<'_>,
    ) -> Result<RestartReplayDecision, PipelineError> {
        let Some(source) = evidence.source else {
            return Ok(RestartReplayDecision::Awaiting {
                dependency: AwaitingDependency::Import {
                    job_id: self.import.job_id.clone(),
                },
            });
        };
        validate_local_source_receipt(&self.source, source)?;

        if matches!(&self.policy, PipelinePolicy::ImportOnly) {
            return Ok(RestartReplayDecision::Complete);
        }

        let profile_revision = self
            .policy
            .profile_revision()
            .expect("non-import policy always has a profile revision");
        let derivation_key = DerivationNaturalKey {
            source_revision: source.content_revision().clone(),
            profile_revision: profile_revision.clone(),
        };
        let Some(derivation) = &self.derivation else {
            return Ok(RestartReplayDecision::EnqueueDerivation {
                natural_key: derivation_key,
            });
        };
        if derivation.natural_key != derivation_key {
            return Err(PipelineError::DependencyConflict(
                PipelineConflictReason::DerivationDependencyMismatch,
            ));
        }

        let Some(derived) = evidence.derived else {
            return Ok(RestartReplayDecision::Awaiting {
                dependency: AwaitingDependency::Derivation {
                    job_id: derivation.job_id.clone(),
                },
            });
        };
        derived.validate_against(&derivation_key, &derivation.job_id)?;

        if matches!(&self.policy, PipelinePolicy::AutoNormalize { .. }) {
            return Ok(RestartReplayDecision::Complete);
        }

        let storage_profile_identity = self
            .policy
            .storage_profile_identity()
            .expect("auto-upload policy always has storage identity");
        if matches!(
            source.provenance(),
            SourceProvenance::LocallyValidatedUnsigned(_)
        ) {
            let request = evidence
                .unsigned_upload_request
                .ok_or(PipelineError::UnsignedAdmissionRequestMissing)?;
            self.validate_unsigned_upload_request(source, derived, request)?;
            if !self
                .unsigned_admission
                .as_ref()
                .is_some_and(|receipt| receipt.matches(request))
            {
                return Ok(RestartReplayDecision::ActionRequired {
                    action: PipelineActionRequired::AdmitUnsignedUpload {
                        request: request.clone(),
                    },
                });
            }
        }

        let Some(bundle) = evidence.bundle else {
            return Ok(RestartReplayDecision::FreezeUploadBundle {
                source_revision: source.content_revision().clone(),
                derived_revision: derived.derived_revision.clone(),
                storage_profile_identity: storage_profile_identity.clone(),
            });
        };
        self.validate_bundle(source, derived, bundle)?;
        let upload_key = bundle.natural_key();

        let Some(upload) = &self.upload else {
            return Ok(RestartReplayDecision::EnqueueUpload {
                natural_key: upload_key,
            });
        };
        if upload.natural_key != upload_key {
            return Err(PipelineError::DependencyConflict(
                PipelineConflictReason::UploadDependencyMismatch,
            ));
        }

        let Some(remote) = evidence.remote else {
            return Ok(RestartReplayDecision::Awaiting {
                dependency: AwaitingDependency::RemoteVerification {
                    job_id: upload.job_id.clone(),
                    upload_bundle_revision: bundle.revision().clone(),
                },
            });
        };
        validate_remote_receipt(source, derived, &upload_key, remote)?;
        Ok(RestartReplayDecision::Complete)
    }

    /// Normal runtime dependency replay is identical to startup recovery.
    /// Keeping one decision function prevents restart-only orchestration from
    /// drifting away from the live path.
    pub fn replay(
        &self,
        evidence: PipelineEvidence<'_>,
    ) -> Result<RestartReplayDecision, PipelineError> {
        self.recover(evidence)
    }

    #[must_use]
    pub fn stop(&self) -> PipelineStopPlan {
        PipelineStopPlan {
            import_job_id: self.import.job_id.clone(),
            derivation_job_id: self
                .derivation
                .as_ref()
                .map(|dependency| dependency.job_id.clone()),
            upload_job_id: self
                .upload
                .as_ref()
                .map(|dependency| dependency.job_id.clone()),
        }
    }

    fn record_unsigned_admission(
        &mut self,
        receipt: UnsignedUploadAdmissionReceipt,
    ) -> DependencyAttachOutcome {
        if !matches!(&self.policy, PipelinePolicy::AutoUpload { .. }) {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::PolicyMismatch,
            };
        }
        if !matches!(
            self.source.provenance(),
            SourceProvenance::LocallyValidatedUnsigned(_)
        ) {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UnsignedAdmissionMismatch,
            };
        }
        if let Some(derivation) = &self.derivation {
            if receipt.source_revision() != &derivation.natural_key.source_revision {
                return DependencyAttachOutcome::Conflict {
                    reason: PipelineConflictReason::UnsignedAdmissionMismatch,
                };
            }
        } else {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UnsignedAdmissionMismatch,
            };
        }
        if self.policy.storage_profile_identity() != Some(receipt.storage_profile_identity())
            || self.policy.source_archival() != receipt.source_archival()
            || receipt.policy_revision() != DERIVED_UPLOAD_POLICY_REVISION
        {
            return DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UnsignedAdmissionMismatch,
            };
        }
        match &self.unsigned_admission {
            None => {
                self.unsigned_admission = Some(receipt);
                DependencyAttachOutcome::Attached
            }
            Some(existing) if existing == &receipt => DependencyAttachOutcome::Existing,
            Some(_) => DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UnsignedAdmissionMismatch,
            },
        }
    }

    fn validate_bundle(
        &self,
        source: &LocalSourceReceipt,
        derived: &LocalDerivedReceipt,
        bundle: &FrozenUploadBundle,
    ) -> Result<(), PipelineError> {
        if bundle.source_revision() != source.content_revision()
            || bundle.source_inventory_digest() != source.inventory_digest()
            || bundle.source_provenance() != source.provenance()
            || bundle.profile_revision() != &derived.profile_revision
            || bundle.derived_revision() != &derived.derived_revision
            || Some(bundle.storage_profile_identity()) != self.policy.storage_profile_identity()
            || bundle.source_archival() != self.policy.source_archival()
            || bundle.upload_policy_revision() != DERIVED_UPLOAD_POLICY_REVISION
        {
            return Err(PipelineError::BundleMismatch);
        }
        if matches!(
            source.provenance(),
            SourceProvenance::LocallyValidatedUnsigned(_)
        ) {
            let request = bundle
                .unsigned_upload_admission_request()
                .map_err(|_| PipelineError::UnsignedAdmissionMismatch)?;
            if bundle.unsigned_admission() != self.unsigned_admission.as_ref()
                || !self
                    .unsigned_admission
                    .as_ref()
                    .is_some_and(|receipt| receipt.matches(&request))
            {
                return Err(PipelineError::UnsignedAdmissionMismatch);
            }
        }
        Ok(())
    }

    fn validate_unsigned_upload_request(
        &self,
        source: &LocalSourceReceipt,
        derived: &LocalDerivedReceipt,
        request: &UnsignedUploadAdmissionRequest,
    ) -> Result<(), PipelineError> {
        if request.source_revision() != source.content_revision()
            || request.inventory_digest() != source.inventory_digest()
            || request.derived_revision() != &derived.derived_revision
            || Some(request.storage_profile_identity()) != self.policy.storage_profile_identity()
            || request.source_archival() != self.policy.source_archival()
            || request.policy_revision() != DERIVED_UPLOAD_POLICY_REVISION
        {
            return Err(PipelineError::UnsignedAdmissionRequestMismatch);
        }
        Ok(())
    }
}

/// Durable local derivative completion evidence. It carries immutable commit
/// coordinates, not a copy of `DerivationJobState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDerivedReceipt {
    derivation_job_id: DerivationJobId,
    source_revision: SourceContentRevision,
    source_manifest_digest: SourceManifestDigest,
    profile_revision: ProfileRevision,
    derived_revision: DerivedRevision,
    sealed_artifact: LocalArtifactRef,
    commit_receipt: String,
    committed_at: String,
}

impl LocalDerivedReceipt {
    pub fn from_completion(
        derivation_job_id: DerivationJobId,
        completion: &DerivedCompletion,
    ) -> Result<Self, PipelineError> {
        Self::new(
            derivation_job_id,
            completion.source_content_revision().clone(),
            completion
                .upload_bundle_input()
                .source_manifest_digest()
                .clone(),
            completion.profile_revision().clone(),
            completion.derived_revision().clone(),
            LocalArtifactRef::parse(completion.local_relative_path())
                .map_err(|_| PipelineError::InvalidReference("derived_local_relative_path"))?,
            completion.local_commit_receipt(),
            completion.committed_at(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        derivation_job_id: DerivationJobId,
        source_revision: SourceContentRevision,
        source_manifest_digest: SourceManifestDigest,
        profile_revision: ProfileRevision,
        derived_revision: DerivedRevision,
        sealed_artifact: LocalArtifactRef,
        commit_receipt: impl Into<String>,
        committed_at: impl Into<String>,
    ) -> Result<Self, PipelineError> {
        let commit_receipt = commit_receipt.into();
        let committed_at = committed_at.into();
        validate_reference("derived_commit_receipt", &commit_receipt)?;
        validate_reference("derived_committed_at", &committed_at)?;
        Ok(Self {
            derivation_job_id,
            source_revision,
            source_manifest_digest,
            profile_revision,
            derived_revision,
            sealed_artifact,
            commit_receipt,
            committed_at,
        })
    }

    #[must_use]
    pub fn derivation_job_id(&self) -> &DerivationJobId {
        &self.derivation_job_id
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn source_manifest_digest(&self) -> &SourceManifestDigest {
        &self.source_manifest_digest
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn sealed_artifact(&self) -> &LocalArtifactRef {
        &self.sealed_artifact
    }

    #[must_use]
    pub fn commit_receipt(&self) -> &str {
        &self.commit_receipt
    }

    #[must_use]
    pub fn committed_at(&self) -> &str {
        &self.committed_at
    }

    fn validate_against(
        &self,
        key: &DerivationNaturalKey,
        job_id: &DerivationJobId,
    ) -> Result<(), PipelineError> {
        if &self.derivation_job_id != job_id
            || self.source_revision != key.source_revision
            || self.profile_revision != key.profile_revision
        {
            return Err(PipelineError::DerivedReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineEvidence<'a> {
    pub source: Option<&'a LocalSourceReceipt>,
    pub derived: Option<&'a LocalDerivedReceipt>,
    pub unsigned_upload_request: Option<&'a UnsignedUploadAdmissionRequest>,
    pub bundle: Option<&'a FrozenUploadBundle>,
    pub remote: Option<&'a RemoteBundleReceipt>,
}

impl PipelineEvidence<'_> {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            source: None,
            derived: None,
            unsigned_upload_request: None,
            bundle: None,
            remote: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
// Start results own a complete pipeline so repositories can persist them atomically.
pub enum PipelineStartOutcome {
    Created {
        pipeline: Box<SessionPipeline>,
    },
    Existing {
        pipeline_id: SessionPipelineId,
    },
    Conflict {
        existing_pipeline_id: SessionPipelineId,
        reason: PipelineConflictReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum PipelineCommand {
    AttachDerivation {
        natural_key: DerivationNaturalKey,
        job_id: DerivationJobId,
    },
    AttachUpload {
        natural_key: UploadJobNaturalKey,
        job_id: UploadJobId,
    },
    RecordUnsignedAdmission {
        receipt: Box<UnsignedUploadAdmissionReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DependencyAttachOutcome {
    Attached,
    Existing,
    Conflict { reason: PipelineConflictReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RestartReplayDecision {
    Awaiting {
        dependency: AwaitingDependency,
    },
    EnqueueDerivation {
        natural_key: DerivationNaturalKey,
    },
    ActionRequired {
        action: PipelineActionRequired,
    },
    FreezeUploadBundle {
        source_revision: SourceContentRevision,
        derived_revision: DerivedRevision,
        storage_profile_identity: StorageProfileIdentity,
    },
    EnqueueUpload {
        natural_key: UploadJobNaturalKey,
    },
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "dependency", rename_all = "snake_case")]
pub enum AwaitingDependency {
    Import {
        job_id: ImportJobId,
    },
    Derivation {
        job_id: DerivationJobId,
    },
    RemoteVerification {
        job_id: UploadJobId,
        upload_bundle_revision: UploadBundleRevision,
    },
}

const PIPELINE_ACTION_CODE_MAX_BYTES: usize = 128;
const PIPELINE_ACTION_MESSAGE_MAX_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PipelineActionRequired {
    AdmitUnsignedUpload {
        request: UnsignedUploadAdmissionRequest,
    },
    /// A durable operational blocker that must be resolved before policy
    /// orchestration can continue. `code` is stable machine-readable identity;
    /// `message` is bounded operator-facing context, not the source of truth.
    #[non_exhaustive]
    ResolvePolicy { code: String, message: String },
}

impl PipelineActionRequired {
    pub fn resolve_policy(
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, PipelineError> {
        let code = code.into();
        let message = message.into();
        validate_pipeline_action_field(
            "pipeline_action_code",
            &code,
            PIPELINE_ACTION_CODE_MAX_BYTES,
        )?;
        validate_pipeline_action_field(
            "pipeline_action_message",
            &message,
            PIPELINE_ACTION_MESSAGE_MAX_BYTES,
        )?;
        Ok(Self::ResolvePolicy { code, message })
    }

    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::AdmitUnsignedUpload { .. } => None,
            Self::ResolvePolicy { code, .. } => Some(code),
        }
    }

    #[must_use]
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::AdmitUnsignedUpload { .. } => None,
            Self::ResolvePolicy { message, .. } => Some(message),
        }
    }
}

impl<'de> Deserialize<'de> for PipelineActionRequired {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match PipelineActionRequiredWire::deserialize(deserializer)? {
            PipelineActionRequiredWire::AdmitUnsignedUpload { request } => {
                Ok(Self::AdmitUnsignedUpload { request })
            }
            PipelineActionRequiredWire::ResolvePolicy { code, message } => {
                Self::resolve_policy(code, message).map_err(D::Error::custom)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum PipelineActionRequiredWire {
    AdmitUnsignedUpload {
        request: UnsignedUploadAdmissionRequest,
    },
    ResolvePolicy {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStopPlan {
    pub import_job_id: ImportJobId,
    pub derivation_job_id: Option<DerivationJobId>,
    pub upload_job_id: Option<UploadJobId>,
}

/// Stable tagged batch result: one bad source never erases another item's
/// Created, Existing, or ActionRequired result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaggedPipelineOutcome {
    pub item_id: String,
    pub outcome: PipelineBatchOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineBatchResult {
    pub items: Vec<TaggedPipelineOutcome>,
    /// Reserved for a failure that prevents the batch operation itself from
    /// running. Per-item failures never populate this field.
    pub operation_error: Option<PipelineOperationError>,
}

impl PipelineBatchResult {
    #[must_use]
    pub fn start(items: Vec<PipelineBatchStartItem>) -> Self {
        let items = items
            .into_iter()
            .map(|item| {
                let item_id = item.item_id;
                if validate_reference("batch_item_id", &item_id).is_err() {
                    return TaggedPipelineOutcome {
                        item_id,
                        outcome: PipelineBatchOutcome::Rejected {
                            code: "invalid_item_id".to_string(),
                            retryable: false,
                        },
                    };
                }
                let outcome = match SessionPipeline::start(item.request, item.existing.as_ref()) {
                    PipelineStartOutcome::Created { pipeline } => {
                        PipelineBatchOutcome::Created { pipeline }
                    }
                    PipelineStartOutcome::Existing { pipeline_id } => {
                        PipelineBatchOutcome::Existing { pipeline_id }
                    }
                    PipelineStartOutcome::Conflict { reason, .. } => {
                        PipelineBatchOutcome::Conflict { reason }
                    }
                };
                TaggedPipelineOutcome { item_id, outcome }
            })
            .collect();
        Self {
            items,
            operation_error: None,
        }
    }

    #[must_use]
    pub fn from_replay<I, S>(items: I) -> Self
    where
        I: IntoIterator<
            Item = (
                S,
                SessionPipelineId,
                Result<RestartReplayDecision, PipelineError>,
            ),
        >,
        S: Into<String>,
    {
        let items = items
            .into_iter()
            .map(|(item_id, pipeline_id, replay)| TaggedPipelineOutcome {
                item_id: item_id.into(),
                outcome: match replay {
                    Ok(RestartReplayDecision::Complete) => {
                        PipelineBatchOutcome::Complete { pipeline_id }
                    }
                    Ok(RestartReplayDecision::ActionRequired { action }) => {
                        PipelineBatchOutcome::ActionRequired { action }
                    }
                    Ok(decision) => PipelineBatchOutcome::Processing {
                        pipeline_id,
                        decision,
                    },
                    Err(error) => PipelineBatchOutcome::Rejected {
                        code: error.code().to_string(),
                        retryable: false,
                    },
                },
            })
            .collect();
        Self {
            items,
            operation_error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineBatchStartItem {
    pub item_id: String,
    pub request: PipelineStartRequest,
    pub existing: Option<SessionPipeline>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineOperationError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
// Batch items preserve the same complete created-pipeline result as single starts.
pub enum PipelineBatchOutcome {
    Created {
        pipeline: Box<SessionPipeline>,
    },
    Existing {
        pipeline_id: SessionPipelineId,
    },
    Processing {
        pipeline_id: SessionPipelineId,
        decision: RestartReplayDecision,
    },
    ActionRequired {
        action: PipelineActionRequired,
    },
    Complete {
        pipeline_id: SessionPipelineId,
    },
    Conflict {
        reason: PipelineConflictReason,
    },
    Rejected {
        code: String,
        retryable: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineConflictReason {
    ImportDependencyMismatch,
    PolicyMismatch,
    DerivationDependencyMismatch,
    UploadDependencyMismatch,
    StorageProfileMismatch,
    UnsignedAdmissionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipelineError {
    #[error("{0} must not be empty or contain control characters")]
    InvalidReference(&'static str),
    #[error(
        "{field} must be non-empty, at most {maximum} bytes, and contain no control characters"
    )]
    InvalidActionField { field: &'static str, maximum: usize },
    #[error("pipeline dependency conflicts with durable evidence: {0:?}")]
    DependencyConflict(PipelineConflictReason),
    #[error("local derived receipt does not match the requested source/profile")]
    DerivedReceiptMismatch,
    #[error("local source receipt does not match the admitted source recording")]
    SourceReceiptMismatch,
    #[error("frozen upload bundle does not match pipeline completion evidence")]
    BundleMismatch,
    #[error("unsigned upload admission is absent or bound to different source bytes")]
    UnsignedAdmissionMismatch,
    #[error("unsigned upload pre-freeze approval request evidence is missing")]
    UnsignedAdmissionRequestMissing,
    #[error("unsigned upload pre-freeze approval request conflicts with pipeline evidence")]
    UnsignedAdmissionRequestMismatch,
    #[error("remote bundle receipt does not match the exact upload natural key")]
    RemoteReceiptMismatch,
}

impl PipelineError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidReference(_) => "invalid_reference",
            Self::InvalidActionField { .. } => "invalid_action_field",
            Self::DependencyConflict(_) => "dependency_conflict",
            Self::SourceReceiptMismatch => "source_receipt_mismatch",
            Self::DerivedReceiptMismatch => "derived_receipt_mismatch",
            Self::BundleMismatch => "upload_bundle_mismatch",
            Self::UnsignedAdmissionMismatch => "unsigned_admission_mismatch",
            Self::UnsignedAdmissionRequestMissing => "unsigned_admission_request_missing",
            Self::UnsignedAdmissionRequestMismatch => "unsigned_admission_request_mismatch",
            Self::RemoteReceiptMismatch => "remote_receipt_mismatch",
        }
    }
}

fn validate_local_source_receipt(
    recording: &SourceRecording,
    receipt: &LocalSourceReceipt,
) -> Result<(), PipelineError> {
    if recording
        .content_revision()
        .is_some_and(|expected| expected != receipt.content_revision())
    {
        return Err(PipelineError::SourceReceiptMismatch);
    }
    match (recording.provenance(), receipt.provenance()) {
        (SourceProvenance::DeviceSigned(expected), SourceProvenance::DeviceSigned(actual))
            if expected == actual =>
        {
            Ok(())
        }
        (
            SourceProvenance::LocallyValidatedUnsigned(expected),
            SourceProvenance::LocallyValidatedUnsigned(actual),
        ) if expected.source_schema() == actual.source_schema()
            && expected.validation_report() == actual.validation_report()
            && expected.user_admission_receipt() == actual.user_admission_receipt() =>
        {
            Ok(())
        }
        _ => Err(PipelineError::SourceReceiptMismatch),
    }
}

fn validate_reference(field: &'static str, value: &str) -> Result<(), PipelineError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err(PipelineError::InvalidReference(field))
    } else {
        Ok(())
    }
}

fn validate_pipeline_action_field(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), PipelineError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(PipelineError::InvalidActionField { field, maximum })
    } else {
        Ok(())
    }
}

fn validate_remote_receipt(
    source: &LocalSourceReceipt,
    derived: &LocalDerivedReceipt,
    expected_key: &UploadJobNaturalKey,
    remote: &RemoteBundleReceipt,
) -> Result<(), PipelineError> {
    if remote.natural_key() != expected_key
        || remote.source_revision() != source.content_revision()
        || remote.derived_revision() != &derived.derived_revision
    {
        return Err(PipelineError::RemoteReceiptMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod action_required_tests {
    use crate::ingest::InventoryDigest;

    use super::*;

    #[test]
    fn resolve_policy_has_stable_wire_shape_and_round_trips() {
        let action = PipelineActionRequired::resolve_policy(
            "approved_profile_required",
            "Approve a normalization profile before continuing",
        )
        .expect("fixture action must be valid");

        let encoded = serde_json::to_string(&action).expect("action must serialize");
        assert_eq!(
            encoded,
            r#"{"action":"resolve_policy","code":"approved_profile_required","message":"Approve a normalization profile before continuing"}"#
        );
        assert_eq!(
            serde_json::from_str::<PipelineActionRequired>(&encoded)
                .expect("persisted action must restore"),
            action
        );
    }

    #[test]
    fn unsigned_admission_wire_shape_remains_compatible() {
        let action = PipelineActionRequired::AdmitUnsignedUpload {
            request: UnsignedUploadAdmissionRequest::new(
                SourceContentRevision::from_material(b"source"),
                InventoryDigest::from_material(b"inventory"),
                DerivedRevision::from_canonical_bytes(b"derived"),
                crate::media_pipeline::PreFreezeUploadRequestDigest::from_digest([7; 32]),
                StorageProfileIdentity::parse("storage-a").expect("storage identity"),
                SourceArchivalPolicy::Disabled,
                DERIVED_UPLOAD_POLICY_REVISION,
            )
            .expect("admission request"),
        };

        let encoded = serde_json::to_value(&action).expect("action must serialize");
        assert_eq!(encoded["action"], "admit_unsigned_upload");
        assert_eq!(
            serde_json::from_value::<PipelineActionRequired>(encoded)
                .expect("legacy action must restore"),
            action
        );
    }

    #[test]
    fn resolve_policy_rejects_unbounded_or_unsafe_fields() {
        assert!(PipelineActionRequired::resolve_policy("", "message").is_err());
        assert!(PipelineActionRequired::resolve_policy("code", "").is_err());
        assert!(PipelineActionRequired::resolve_policy("bad\ncode", "message").is_err());
        assert!(PipelineActionRequired::resolve_policy("code", "bad\nmessage").is_err());
        assert!(PipelineActionRequired::resolve_policy(
            "c".repeat(PIPELINE_ACTION_CODE_MAX_BYTES + 1),
            "message",
        )
        .is_err());
        assert!(PipelineActionRequired::resolve_policy(
            "code",
            "m".repeat(PIPELINE_ACTION_MESSAGE_MAX_BYTES + 1),
        )
        .is_err());
    }

    #[test]
    fn persisted_resolve_policy_cannot_bypass_constructor_validation() {
        let encoded = serde_json::json!({
            "action": "resolve_policy",
            "code": "",
            "message": "Resolve the missing policy",
        });

        let error = serde_json::from_value::<PipelineActionRequired>(encoded)
            .expect_err("invalid persisted action must fail closed");
        assert!(error.to_string().contains("pipeline_action_code"));
    }
}

#[cfg(test)]
mod upload_retry_tests {
    use crate::ingest::{ImportJobId, SourceRecording};
    use crate::normalization::ProfileRevision;

    use super::*;

    fn source() -> SourceRecording {
        let digest = format!("sha256:{}", "a".repeat(64));
        serde_json::from_value(serde_json::json!({
            "candidate_id": format!("candidate:sha256:{}", "b".repeat(64)),
            "revision_claim": {"kind": "published", "revision": digest},
            "content_revision": digest,
            "source_kind": "removable_media",
            "schema": "raw_capture_v2",
            "session_id": "session-1",
            "locator": {
                "source_id": "source-1",
                "media_generation": null,
                "candidate_relative_path": null
            },
            "inventory": [],
            "media_plan": {
                "layout": "left_right_side_by_side",
                "codec": "mjpeg",
                "frame_rate": null,
                "frame_width": null,
                "frame_height": null,
                "segment_count": 1,
                "reset_timestamps_per_segment": false,
                "raw_frame_count": null,
                "legacy_total_frames": null
            },
            "provenance": {
                "kind": "locally_validated_unsigned",
                "evidence": {
                    "source_schema": "raw_capture_v2",
                    "validation_report": {
                        "checks": [{"code": "fixture", "passed": true, "detail": "valid"}]
                    },
                    "computed_inventory_digest": digest,
                    "user_admission_receipt": null
                }
            },
            "trust_verdicts": {
                "inventory_hashes": {"status": "valid", "digest": digest},
                "manifest_signature": {"status": "not_applicable"},
                "producer_key": {"status": "not_applicable"}
            }
        }))
        .expect("source fixture")
    }

    fn upload_key(bundle_digit: char, storage: &str) -> UploadJobNaturalKey {
        UploadJobNaturalKey {
            upload_bundle_revision: UploadBundleRevision::parse(format!(
                "sha256:{}",
                bundle_digit.to_string().repeat(64)
            ))
            .expect("bundle revision"),
            storage_profile_identity: StorageProfileIdentity::parse(storage)
                .expect("storage identity"),
        }
    }

    fn pipeline_with_upload(parent_job_id: &str) -> (SessionPipeline, UploadJobNaturalKey) {
        let storage = StorageProfileIdentity::parse("storage-a").expect("storage identity");
        let request = PipelineStartRequest::with_pipeline_id(
            SessionPipelineId::parse("pipeline-1").expect("pipeline id"),
            source(),
            ImportJobId::parse("import-1").expect("import job id"),
            PipelinePolicy::auto_upload(
                ProfileRevision::parse(format!("sha256:{}", "c".repeat(64)))
                    .expect("profile revision"),
                storage,
            ),
        );
        let PipelineStartOutcome::Created { pipeline } = SessionPipeline::start(request, None)
        else {
            panic!("new pipeline must be created");
        };
        let mut pipeline = *pipeline;
        let natural_key = upload_key('d', "storage-a");
        assert_eq!(
            pipeline.attach_upload(natural_key.clone(), UploadJobId(parent_job_id.to_string()),),
            DependencyAttachOutcome::Attached
        );
        (pipeline, natural_key)
    }

    #[test]
    fn retry_replaces_the_exact_parent_for_the_same_natural_key() {
        let (mut pipeline, natural_key) = pipeline_with_upload("upload-parent");

        assert_eq!(
            pipeline.replace_upload_attempt(
                &UploadJobId("upload-parent".to_string()),
                natural_key.clone(),
                UploadJobId("upload-child".to_string()),
            ),
            DependencyAttachOutcome::Attached
        );
        let dependency = pipeline.upload_dependency().expect("upload dependency");
        assert_eq!(dependency.natural_key(), &natural_key);
        assert_eq!(dependency.job_id().as_str(), "upload-child");
    }

    #[test]
    fn retry_rejects_a_stale_parent_without_replacing_the_current_attempt() {
        let (mut pipeline, natural_key) = pipeline_with_upload("upload-parent");
        assert_eq!(
            pipeline.replace_upload_attempt(
                &UploadJobId("upload-parent".to_string()),
                natural_key.clone(),
                UploadJobId("upload-child".to_string()),
            ),
            DependencyAttachOutcome::Attached
        );

        assert_eq!(
            pipeline.replace_upload_attempt(
                &UploadJobId("upload-parent".to_string()),
                natural_key,
                UploadJobId("upload-newer-child".to_string()),
            ),
            DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UploadDependencyMismatch,
            }
        );
        assert_eq!(
            pipeline
                .upload_dependency()
                .expect("upload dependency")
                .job_id()
                .as_str(),
            "upload-child"
        );
    }

    #[test]
    fn retry_rejects_changed_bundle_or_storage_identity() {
        let (mut pipeline, _) = pipeline_with_upload("upload-parent");

        assert_eq!(
            pipeline.replace_upload_attempt(
                &UploadJobId("upload-parent".to_string()),
                upload_key('e', "storage-a"),
                UploadJobId("upload-child".to_string()),
            ),
            DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::UploadDependencyMismatch,
            }
        );
        assert_eq!(
            pipeline.replace_upload_attempt(
                &UploadJobId("upload-parent".to_string()),
                upload_key('d', "storage-b"),
                UploadJobId("upload-child".to_string()),
            ),
            DependencyAttachOutcome::Conflict {
                reason: PipelineConflictReason::StorageProfileMismatch,
            }
        );
        assert_eq!(
            pipeline
                .upload_dependency()
                .expect("upload dependency")
                .job_id()
                .as_str(),
            "upload-parent"
        );
    }

    #[test]
    fn retry_replay_is_idempotent_after_the_child_is_attached() {
        let (mut pipeline, natural_key) = pipeline_with_upload("upload-parent");
        let parent = UploadJobId("upload-parent".to_string());
        let child = UploadJobId("upload-child".to_string());
        assert_eq!(
            pipeline.replace_upload_attempt(&parent, natural_key.clone(), child.clone()),
            DependencyAttachOutcome::Attached
        );

        assert_eq!(
            pipeline.replace_upload_attempt(&parent, natural_key, child),
            DependencyAttachOutcome::Existing
        );
    }
}
