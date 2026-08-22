use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

pub use crate::ingest::SourceProvenance as ManifestSourceProvenance;
use crate::ingest::{
    InventoryDigest, LocalSourceReceipt, SourceArtifactId, SourceContentRevision, SourceProvenance,
};

use super::identity::{
    canonical_json, ContentSha256, DerivedRevision, EncoderBuildFingerprint, IdentityError,
    ProfileRevision, SourceManifestDigest,
};
use super::plan::{MediaPlan, NormalizationInput, SegmentPairPlan};
use super::profile::{EncoderBuild, NormalizationProfile, ProfileError, TranscodeGeneration};
use super::validation::{
    FullDecodeVerdict, QualityEvidence, QualityVerdict, SegmentValidationReport, StereoSyncVerdict,
    StructuralVerdict, ValidatedSegmentPair,
};

pub const DERIVED_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedSubject {
    origin_identity: String,
    session_identity: String,
}

impl DerivedSubject {
    pub fn new(
        origin_identity: impl Into<String>,
        session_identity: impl Into<String>,
    ) -> Result<Self, DerivedManifestError> {
        let origin_identity = origin_identity.into();
        let session_identity = session_identity.into();
        validate_opaque_identity("origin_identity", &origin_identity)?;
        validate_opaque_identity("session_identity", &session_identity)?;
        Ok(Self {
            origin_identity,
            session_identity,
        })
    }

    #[must_use]
    pub fn origin_identity(&self) -> &str {
        &self.origin_identity
    }

    #[must_use]
    pub fn session_identity(&self) -> &str {
        &self.session_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputInventoryEntry {
    artifact_id: SourceArtifactId,
    manifest_relative_path: String,
    size_bytes: u64,
    sha256: ContentSha256,
}

impl InputInventoryEntry {
    #[must_use]
    pub fn artifact_id(&self) -> &SourceArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub fn manifest_relative_path(&self) -> &str {
        &self.manifest_relative_path
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &ContentSha256 {
        &self.sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedOutputRole {
    VideoLeft,
    VideoRight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedOutputEntry {
    relative_path: String,
    role: DerivedOutputRole,
    segment_index: u32,
    first_frame: u64,
    frame_count: u64,
    start_ticks: u64,
    duration_ticks: u64,
    size_bytes: u64,
    sha256: ContentSha256,
    media_type: String,
}

impl DerivedOutputEntry {
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub fn role(&self) -> DerivedOutputRole {
        self.role
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn first_frame(&self) -> u64 {
        self.first_frame
    }

    #[must_use]
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    #[must_use]
    pub fn duration_ticks(&self) -> u64 {
        self.duration_ticks
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &ContentSha256 {
        &self.sha256
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentValidationSummary {
    segment_index: u32,
    structural: StructuralVerdict,
    full_decode: FullDecodeVerdict,
    sync: StereoSyncVerdict,
    quality: QualityVerdict,
    left_quality: QualityEvidence,
    right_quality: QualityEvidence,
}

impl SegmentValidationSummary {
    fn from_report(report: &SegmentValidationReport) -> Self {
        Self {
            segment_index: report.segment_index(),
            structural: report.structural().clone(),
            full_decode: report.full_decode().clone(),
            sync: report.sync().clone(),
            quality: report.quality().clone(),
            left_quality: report.left_quality().clone(),
            right_quality: report.right_quality().clone(),
        }
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.structural.passed()
            && self.full_decode.passed()
            && self.sync.passed()
            && self.quality.passed()
    }

    #[must_use]
    pub fn left_quality(&self) -> &QualityEvidence {
        &self.left_quality
    }

    #[must_use]
    pub fn right_quality(&self) -> &QualityEvidence {
        &self.right_quality
    }
}

/// Durable evidence for one published pair. It can only be created from a
/// `ValidatedSegmentPair`, so no left-only or right-only checkpoint exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentPairCheckpoint {
    segment_index: u32,
    profile_revision: ProfileRevision,
    encoder_build_fingerprint: EncoderBuildFingerprint,
    left: DerivedOutputEntry,
    right: DerivedOutputEntry,
    validation: SegmentValidationSummary,
    published_pair_relative_path: String,
    pair_commit_receipt: String,
}

impl SegmentPairCheckpoint {
    pub fn from_validated_pair(
        plan: &SegmentPairPlan,
        validated: ValidatedSegmentPair,
        profile: &NormalizationProfile,
        encoder_build: &EncoderBuild,
        published_pair_relative_path: impl Into<String>,
        pair_commit_receipt: impl Into<String>,
    ) -> Result<Self, DerivedManifestError> {
        if plan.segment_index() != validated.segment_index() {
            return Err(DerivedManifestError::CheckpointPlanMismatch {
                segment_index: validated.segment_index(),
            });
        }
        profile.require_compatible_encoder(encoder_build)?;
        let published_pair_relative_path = published_pair_relative_path.into();
        validate_relative_path(&published_pair_relative_path)?;
        let pair_commit_receipt = pair_commit_receipt.into();
        validate_bounded_text("pair_commit_receipt", &pair_commit_receipt, 512)?;
        let report = validated.into_report();
        let left = output_entry(plan, report.left(), DerivedOutputRole::VideoLeft);
        let right = output_entry(plan, report.right(), DerivedOutputRole::VideoRight);
        let validation = SegmentValidationSummary::from_report(&report);
        if !validation.passed() {
            return Err(DerivedManifestError::ValidationFailed {
                segment_index: plan.segment_index(),
            });
        }
        Ok(Self {
            segment_index: plan.segment_index(),
            profile_revision: profile.profile_revision().clone(),
            encoder_build_fingerprint: encoder_build.build_fingerprint().clone(),
            left,
            right,
            validation,
            published_pair_relative_path,
            pair_commit_receipt,
        })
    }

    #[must_use]
    pub fn segment_index(&self) -> u32 {
        self.segment_index
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }

    #[must_use]
    pub fn encoder_build_fingerprint(&self) -> &EncoderBuildFingerprint {
        &self.encoder_build_fingerprint
    }

    #[must_use]
    pub fn left(&self) -> &DerivedOutputEntry {
        &self.left
    }

    #[must_use]
    pub fn right(&self) -> &DerivedOutputEntry {
        &self.right
    }

    #[must_use]
    pub fn validation(&self) -> &SegmentValidationSummary {
        &self.validation
    }

    #[must_use]
    pub fn published_pair_relative_path(&self) -> &str {
        &self.published_pair_relative_path
    }

    #[must_use]
    pub fn pair_commit_receipt(&self) -> &str {
        &self.pair_commit_receipt
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DerivedManifestMaterial {
    schema_version: u32,
    subject: DerivedSubject,
    source_content_revision: SourceContentRevision,
    source_provenance: SourceProvenance,
    source_inventory_digest: InventoryDigest,
    source_manifest_digest: SourceManifestDigest,
    normalization_profile_revision: ProfileRevision,
    encoder: EncoderBuild,
    media_plan: MediaPlan,
    input_inventory: Vec<InputInventoryEntry>,
    output_inventory: Vec<DerivedOutputEntry>,
    segment_validation: Vec<SegmentValidationSummary>,
    transcode_generation: TranscodeGeneration,
    created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DerivedManifestDocument {
    #[serde(flatten)]
    material: DerivedManifestMaterial,
    derived_revision: DerivedRevision,
}

/// Field-private, self-hashing derived manifest. It has no public unchecked
/// constructor and no unchecked `Deserialize` implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedManifest {
    material: DerivedManifestMaterial,
    derived_revision: DerivedRevision,
    canonical_bytes: Vec<u8>,
}

impl DerivedManifest {
    pub fn parse_verified(bytes: &[u8]) -> Result<Self, DerivedManifestError> {
        let document: DerivedManifestDocument = serde_json::from_slice(bytes)
            .map_err(|error| DerivedManifestError::Malformed(error.to_string()))?;
        if document.material.schema_version != DERIVED_MANIFEST_SCHEMA_VERSION {
            return Err(DerivedManifestError::UnsupportedSchema(
                document.material.schema_version,
            ));
        }
        let expected = DerivedRevision::from_canonical_bytes(&canonical_json(&document.material)?);
        if expected != document.derived_revision {
            return Err(DerivedManifestError::RevisionMismatch {
                expected,
                actual: document.derived_revision,
            });
        }
        let canonical_bytes = canonical_json(&document)?;
        if canonical_bytes != bytes {
            return Err(DerivedManifestError::NonCanonical);
        }
        validate_manifest_inventory(&document.material)?;
        Ok(Self {
            material: document.material,
            derived_revision: document.derived_revision,
            canonical_bytes,
        })
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn source_content_revision(&self) -> &SourceContentRevision {
        &self.material.source_content_revision
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.material.normalization_profile_revision
    }

    #[must_use]
    pub fn subject(&self) -> &DerivedSubject {
        &self.material.subject
    }

    #[must_use]
    pub fn source_provenance(&self) -> &SourceProvenance {
        &self.material.source_provenance
    }

    #[must_use]
    pub fn encoder_build(&self) -> &EncoderBuild {
        &self.material.encoder
    }

    #[must_use]
    pub fn media_plan(&self) -> &MediaPlan {
        &self.material.media_plan
    }

    #[must_use]
    pub fn input_inventory(&self) -> &[InputInventoryEntry] {
        &self.material.input_inventory
    }

    #[must_use]
    pub fn output_inventory(&self) -> &[DerivedOutputEntry] {
        &self.material.output_inventory
    }

    #[must_use]
    pub fn segment_validation(&self) -> &[SegmentValidationSummary] {
        &self.material.segment_validation
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn upload_bundle_input(&self) -> UploadBundleManifestInput {
        UploadBundleManifestInput {
            subject: self.material.subject.clone(),
            source_content_revision: self.material.source_content_revision.clone(),
            source_provenance: self.material.source_provenance.clone(),
            source_manifest_digest: self.material.source_manifest_digest.clone(),
            profile_revision: self.material.normalization_profile_revision.clone(),
            derived_revision: self.derived_revision.clone(),
            output_inventory: self.material.output_inventory.clone(),
            derived_manifest_canonical_bytes: self.canonical_bytes.clone(),
        }
    }
}

pub struct DerivedManifestBuilder {
    subject: DerivedSubject,
    local_source: LocalSourceReceipt,
    source_manifest_digest: SourceManifestDigest,
    input: NormalizationInput,
    media_plan: MediaPlan,
    profile: NormalizationProfile,
    encoder_build: EncoderBuild,
    created_at: String,
    checkpoints: BTreeMap<u32, SegmentPairCheckpoint>,
}

impl DerivedManifestBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: DerivedSubject,
        local_source: LocalSourceReceipt,
        source_manifest_digest: SourceManifestDigest,
        input: NormalizationInput,
        media_plan: MediaPlan,
        profile: NormalizationProfile,
        encoder_build: EncoderBuild,
        created_at: impl Into<String>,
    ) -> Result<Self, DerivedManifestError> {
        if input.kind() != media_plan.source_kind()
            || media_plan.profile_revision() != profile.profile_revision()
        {
            return Err(DerivedManifestError::PlanProfileMismatch);
        }
        profile.require_compatible_encoder(&encoder_build)?;
        let created_at = created_at.into();
        validate_bounded_text("derived_created_at", &created_at, 128)?;
        Ok(Self {
            subject,
            local_source,
            source_manifest_digest,
            input,
            media_plan,
            profile,
            encoder_build,
            created_at,
            checkpoints: BTreeMap::new(),
        })
    }

    pub fn add_checkpoint(
        &mut self,
        checkpoint: SegmentPairCheckpoint,
    ) -> Result<(), DerivedManifestError> {
        if checkpoint.profile_revision() != self.profile.profile_revision()
            || checkpoint.encoder_build_fingerprint() != self.encoder_build.build_fingerprint()
            || self
                .media_plan
                .segment_pair(checkpoint.segment_index())
                .is_none()
        {
            return Err(DerivedManifestError::CheckpointPlanMismatch {
                segment_index: checkpoint.segment_index(),
            });
        }
        if self
            .checkpoints
            .insert(checkpoint.segment_index(), checkpoint)
            .is_some()
        {
            return Err(DerivedManifestError::DuplicateCheckpoint);
        }
        Ok(())
    }

    pub fn build(self) -> Result<DerivedManifest, DerivedManifestError> {
        self.profile.require_approved()?;
        self.profile
            .require_compatible_encoder(&self.encoder_build)?;
        if self.checkpoints.len() != self.media_plan.segment_pairs().len()
            || self
                .media_plan
                .segment_pairs()
                .iter()
                .any(|pair| !self.checkpoints.contains_key(&pair.segment_index()))
        {
            return Err(DerivedManifestError::IncompleteCheckpoints {
                expected: self.media_plan.segment_pairs().len(),
                actual: self.checkpoints.len(),
            });
        }

        let input_inventory = self
            .input
            .artifacts()
            .into_iter()
            .map(|artifact| InputInventoryEntry {
                artifact_id: artifact.id().clone(),
                manifest_relative_path: artifact.manifest_relative_path().to_string(),
                size_bytes: artifact.expected_size_bytes(),
                sha256: artifact.expected_sha256().clone(),
            })
            .collect::<Vec<_>>();
        let checkpoints = self.checkpoints.into_values().collect::<Vec<_>>();
        let output_inventory = checkpoints
            .iter()
            .flat_map(|checkpoint| [checkpoint.left.clone(), checkpoint.right.clone()])
            .collect::<Vec<_>>();
        let segment_validation = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.validation.clone())
            .collect::<Vec<_>>();
        let material = DerivedManifestMaterial {
            schema_version: DERIVED_MANIFEST_SCHEMA_VERSION,
            subject: self.subject,
            source_content_revision: self.local_source.content_revision().clone(),
            source_provenance: self.local_source.provenance().clone(),
            source_inventory_digest: self.local_source.inventory_digest().clone(),
            source_manifest_digest: self.source_manifest_digest,
            normalization_profile_revision: self.profile.profile_revision().clone(),
            encoder: self.encoder_build,
            media_plan: self.media_plan,
            input_inventory,
            output_inventory,
            segment_validation,
            transcode_generation: self.profile.transcode_generation(),
            created_at: self.created_at,
        };
        validate_manifest_inventory(&material)?;
        let derived_revision = DerivedRevision::from_canonical_bytes(&canonical_json(&material)?);
        let document = DerivedManifestDocument {
            material: material.clone(),
            derived_revision: derived_revision.clone(),
        };
        let canonical_bytes = canonical_json(&document)?;
        Ok(DerivedManifest {
            material,
            derived_revision,
            canonical_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadBundleManifestInput {
    subject: DerivedSubject,
    source_content_revision: SourceContentRevision,
    source_provenance: SourceProvenance,
    source_manifest_digest: SourceManifestDigest,
    profile_revision: ProfileRevision,
    derived_revision: DerivedRevision,
    output_inventory: Vec<DerivedOutputEntry>,
    derived_manifest_canonical_bytes: Vec<u8>,
}

impl UploadBundleManifestInput {
    #[must_use]
    pub fn subject(&self) -> &DerivedSubject {
        &self.subject
    }

    #[must_use]
    pub fn source_content_revision(&self) -> &SourceContentRevision {
        &self.source_content_revision
    }

    #[must_use]
    pub fn source_provenance(&self) -> &SourceProvenance {
        &self.source_provenance
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
    pub fn output_inventory(&self) -> &[DerivedOutputEntry] {
        &self.output_inventory
    }

    #[must_use]
    pub fn derived_manifest_canonical_bytes(&self) -> &[u8] {
        &self.derived_manifest_canonical_bytes
    }
}

/// Evidence published only after the entire derivative staging directory and
/// manifest have been flushed, atomically renamed, and directory-fsynced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedCompletion {
    source_content_revision: SourceContentRevision,
    profile_revision: ProfileRevision,
    derived_revision: DerivedRevision,
    local_relative_path: String,
    local_commit_receipt: String,
    committed_at: String,
    upload_bundle_input: UploadBundleManifestInput,
}

impl DerivedCompletion {
    pub fn new(
        manifest: &DerivedManifest,
        local_relative_path: impl Into<String>,
        local_commit_receipt: impl Into<String>,
        committed_at: impl Into<String>,
    ) -> Result<Self, DerivedManifestError> {
        let local_relative_path = local_relative_path.into();
        validate_relative_path(&local_relative_path)?;
        let local_commit_receipt = local_commit_receipt.into();
        let committed_at = committed_at.into();
        validate_bounded_text("derived_local_commit_receipt", &local_commit_receipt, 512)?;
        validate_bounded_text("derived_committed_at", &committed_at, 128)?;
        Ok(Self {
            source_content_revision: manifest.source_content_revision().clone(),
            profile_revision: manifest.profile_revision().clone(),
            derived_revision: manifest.derived_revision().clone(),
            local_relative_path,
            local_commit_receipt,
            committed_at,
            upload_bundle_input: manifest.upload_bundle_input(),
        })
    }

    #[must_use]
    pub fn source_content_revision(&self) -> &SourceContentRevision {
        &self.source_content_revision
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
    pub fn local_relative_path(&self) -> &str {
        &self.local_relative_path
    }

    #[must_use]
    pub fn local_commit_receipt(&self) -> &str {
        &self.local_commit_receipt
    }

    #[must_use]
    pub fn committed_at(&self) -> &str {
        &self.committed_at
    }

    #[must_use]
    pub fn upload_bundle_input(&self) -> &UploadBundleManifestInput {
        &self.upload_bundle_input
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DerivedManifestError {
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("unsafe manifest-relative path {0:?}")]
    UnsafeRelativePath(String),
    #[error("media plan, input, and profile revisions do not match")]
    PlanProfileMismatch,
    #[error("checkpoint for segment {segment_index} does not match the plan/profile/encoder")]
    CheckpointPlanMismatch { segment_index: u32 },
    #[error("segment checkpoint already exists")]
    DuplicateCheckpoint,
    #[error("expected {expected} segment-pair checkpoints, found {actual}")]
    IncompleteCheckpoints { expected: usize, actual: usize },
    #[error("validation failed for segment pair {segment_index}")]
    ValidationFailed { segment_index: u32 },
    #[error("derived manifest has duplicate or inconsistent input/output inventory")]
    InvalidInventory,
    #[error("unsupported derived manifest schema version {0}")]
    UnsupportedSchema(u32),
    #[error("derived manifest JSON is malformed: {0}")]
    Malformed(String),
    #[error("derived manifest is not in canonical JSON form")]
    NonCanonical,
    #[error("derived revision mismatch: expected {expected}, found {actual}")]
    RevisionMismatch {
        expected: DerivedRevision,
        actual: DerivedRevision,
    },
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

fn output_entry(
    plan: &SegmentPairPlan,
    output: &super::OutputMediaEvidence,
    role: DerivedOutputRole,
) -> DerivedOutputEntry {
    DerivedOutputEntry {
        relative_path: output.manifest_relative_path().to_string(),
        role,
        segment_index: plan.segment_index(),
        first_frame: plan.first_frame(),
        frame_count: plan.frame_count(),
        start_ticks: plan.start_ticks(),
        duration_ticks: output.duration_ticks(),
        size_bytes: output.size_bytes(),
        sha256: output.sha256().clone(),
        media_type: "video/mp4".to_string(),
    }
}

fn validate_manifest_inventory(
    material: &DerivedManifestMaterial,
) -> Result<(), DerivedManifestError> {
    let input_ids = material
        .input_inventory
        .iter()
        .map(|entry| entry.artifact_id.clone())
        .collect::<BTreeSet<_>>();
    let output_paths = material
        .output_inventory
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let expected_outputs = material
        .media_plan
        .segment_pairs()
        .len()
        .checked_mul(2)
        .ok_or(DerivedManifestError::InvalidInventory)?;
    if input_ids.len() != material.input_inventory.len()
        || output_paths.len() != material.output_inventory.len()
        || material.output_inventory.len() != expected_outputs
        || material.segment_validation.len() != material.media_plan.segment_pairs().len()
        || material
            .segment_validation
            .iter()
            .any(|summary| !summary.passed())
    {
        return Err(DerivedManifestError::InvalidInventory);
    }
    for pair in material.media_plan.segment_pairs() {
        let outputs = material
            .output_inventory
            .iter()
            .filter(|output| output.segment_index == pair.segment_index())
            .collect::<Vec<_>>();
        if outputs.len() != 2
            || !outputs
                .iter()
                .any(|output| output.role == DerivedOutputRole::VideoLeft)
            || !outputs
                .iter()
                .any(|output| output.role == DerivedOutputRole::VideoRight)
            || outputs.iter().any(|output| {
                output.first_frame != pair.first_frame()
                    || output.frame_count != pair.frame_count()
                    || output.start_ticks != pair.start_ticks()
            })
        {
            return Err(DerivedManifestError::InvalidInventory);
        }
    }
    Ok(())
}

fn validate_opaque_identity(field: &'static str, value: &str) -> Result<(), DerivedManifestError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        Err(DerivedManifestError::InvalidField {
            field,
            reason: "expected a non-empty opaque identity without path separators".to_string(),
        })
    } else {
        Ok(())
    }
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), DerivedManifestError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(DerivedManifestError::InvalidField {
            field,
            reason: format!("expected 1-{maximum} non-control characters"),
        })
    } else {
        Ok(())
    }
}

fn validate_relative_path(value: &str) -> Result<(), DerivedManifestError> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains('\0')
        || Path::new(value).is_absolute()
        || value.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.starts_with('.')
        })
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(DerivedManifestError::UnsafeRelativePath(value.to_string()))
    } else {
        Ok(())
    }
}
