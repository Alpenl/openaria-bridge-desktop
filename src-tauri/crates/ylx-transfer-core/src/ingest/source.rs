//! Admitted recording model and provenance boundary.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::publication::{PublicationEnvelope, PublicationFileClaim, VerifiedPublication};

use super::identity::{
    AcquisitionSourceId, CandidateId, CandidateRevision, IdentityError, InventoryDigest,
    MediaGeneration, MediaGenerationId, SourceArtifactId, SourceContentRevision,
    SourceRevisionClaim,
};
use super::path::SafeRelativePath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Lan,
    RemovableMedia,
    LocalFolder,
    LegacyRemovableMedia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSchema {
    DeviceSessionV1,
    DeviceSessionV2,
    SignedPublicationV1,
    /// A complete publication manifest that carries no detached signature.
    ///
    /// The recorder published a full, self-describing inventory but did not
    /// leave the detached Ed25519 artifacts beside it, so every integrity claim
    /// in the manifest can still be checked while its origin cannot. This is a
    /// locally validated unsigned source and is admitted only under
    /// [`crate::ingest::UnsignedImportPolicy`], never on the signed path.
    UnsignedPublicationV1,
    RawCaptureV2,
    LegacyMjpegSessionV5,
    CompleteUnpublishedV6,
    ApplianceSpoolV6,
}

impl SourceSchema {
    #[must_use]
    pub fn is_signed(self) -> bool {
        matches!(self, Self::SignedPublicationV1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceArtifactRole {
    VideoLeft,
    VideoRight,
    VideoStereo,
    Audio,
    Imu,
    FrameIndex,
    SessionManifest,
    CaptureManifest,
    CaptureCommit,
    EncodingState,
    PublicationManifest,
    SpoolIndex,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceArtifactClaim {
    id: SourceArtifactId,
    relative_path: SafeRelativePath,
    role: SourceArtifactRole,
    size_bytes: u64,
    source_sha256: Option<String>,
    media_type: Option<String>,
}

impl SourceArtifactClaim {
    pub fn new(
        id: SourceArtifactId,
        relative_path: SafeRelativePath,
        role: SourceArtifactRole,
        size_bytes: u64,
        source_sha256: Option<String>,
        media_type: Option<String>,
    ) -> Result<Self, SourceModelError> {
        if size_bytes == 0
            && matches!(
                role,
                SourceArtifactRole::VideoLeft
                    | SourceArtifactRole::VideoRight
                    | SourceArtifactRole::VideoStereo
            )
        {
            return Err(SourceModelError::EmptyVideo {
                path: relative_path.as_str().to_string(),
            });
        }
        if let Some(digest) = source_sha256.as_deref() {
            validate_sha256_hex("source artifact sha256", digest)?;
        }
        if let Some(media_type) = media_type.as_deref() {
            if media_type.is_empty()
                || media_type.len() > 256
                || media_type.chars().any(char::is_control)
            {
                return Err(SourceModelError::InvalidMediaType);
            }
        }
        Ok(Self {
            id,
            relative_path,
            role,
            size_bytes,
            source_sha256,
            media_type,
        })
    }

    #[must_use]
    pub fn id(&self) -> &SourceArtifactId {
        &self.id
    }

    #[must_use]
    pub fn relative_path(&self) -> &SafeRelativePath {
        &self.relative_path
    }

    #[must_use]
    pub fn role(&self) -> SourceArtifactRole {
        self.role
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }

    #[must_use]
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StereoLayout {
    LeftRightSideBySide,
    SeparateEyes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceVideoCodec {
    Mjpeg,
    H264,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FrameRate {
    numerator: u32,
    denominator: u32,
}

impl FrameRate {
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, SourceModelError> {
        if numerator == 0 || denominator == 0 {
            return Err(SourceModelError::InvalidFrameRate);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    #[must_use]
    pub fn numerator(self) -> u32 {
        self.numerator
    }

    #[must_use]
    pub fn denominator(self) -> u32 {
        self.denominator
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMediaPlan {
    layout: StereoLayout,
    codec: SourceVideoCodec,
    frame_rate: Option<FrameRate>,
    frame_width: Option<u32>,
    frame_height: Option<u32>,
    segment_count: u32,
    reset_timestamps_per_segment: bool,
    #[serde(default)]
    raw_frame_count: Option<u64>,
    #[serde(default)]
    legacy_total_frames: Option<u64>,
}

impl SourceMediaPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        layout: StereoLayout,
        codec: SourceVideoCodec,
        frame_rate: Option<FrameRate>,
        frame_width: Option<u32>,
        frame_height: Option<u32>,
        segment_count: u32,
        reset_timestamps_per_segment: bool,
    ) -> Result<Self, SourceModelError> {
        if segment_count == 0 {
            return Err(SourceModelError::NoVideoSegments);
        }
        if frame_width == Some(0) || frame_height == Some(0) {
            return Err(SourceModelError::InvalidGeometry);
        }
        Ok(Self {
            layout,
            codec,
            frame_rate,
            frame_width,
            frame_height,
            segment_count,
            reset_timestamps_per_segment,
            raw_frame_count: None,
            legacy_total_frames: None,
        })
    }

    #[must_use]
    pub fn layout(&self) -> StereoLayout {
        self.layout
    }

    #[must_use]
    pub fn codec(&self) -> SourceVideoCodec {
        self.codec
    }

    #[must_use]
    pub fn frame_rate(&self) -> Option<FrameRate> {
        self.frame_rate
    }

    #[must_use]
    pub fn frame_dimensions(&self) -> Option<(u32, u32)> {
        self.frame_width.zip(self.frame_height)
    }

    #[must_use]
    pub fn segment_count(&self) -> u32 {
        self.segment_count
    }

    #[must_use]
    pub fn reset_timestamps_per_segment(&self) -> bool {
        self.reset_timestamps_per_segment
    }

    #[must_use]
    pub fn raw_frame_count(&self) -> Option<u64> {
        self.raw_frame_count
    }

    #[must_use]
    pub fn legacy_total_frames(&self) -> Option<u64> {
        self.legacy_total_frames
    }

    /// Attach the frame-index evidence that the raw detector validated. It is
    /// kept on the frozen source plan so a later normalization builder does not
    /// have to infer frame count from artifact size or an FFmpeg probe.
    #[must_use]
    pub fn with_raw_frame_count(mut self, frame_count: u64) -> Self {
        self.raw_frame_count = Some(frame_count);
        self
    }

    /// Attach the complete legacy v5 frame total after its frame index and
    /// per-segment reset-PTS contract have been checked by the detector.
    #[must_use]
    pub fn with_legacy_total_frames(mut self, frame_count: u64) -> Self {
        self.legacy_total_frames = Some(frame_count);
        self
    }
}

/// Acquisition locator for one attempt. It deliberately omits the absolute
/// mount path; the adapter owning the matching `AcquisitionSourceId` resolves
/// that platform detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaLocator {
    source_id: AcquisitionSourceId,
    media_generation: Option<MediaGeneration>,
    /// `None` means the acquisition source root itself (the user-selected
    /// directory). Mounted-volume candidates always carry a bounded relative
    /// path such as `recordings/<direct-child>`.
    candidate_relative_path: Option<SafeRelativePath>,
}

impl MediaLocator {
    #[must_use]
    pub fn new(
        source_id: AcquisitionSourceId,
        media_generation: Option<MediaGeneration>,
        candidate_relative_path: Option<SafeRelativePath>,
    ) -> Self {
        Self {
            source_id,
            media_generation,
            candidate_relative_path,
        }
    }

    #[must_use]
    pub fn source_id(&self) -> &AcquisitionSourceId {
        &self.source_id
    }

    #[must_use]
    pub fn media_generation(&self) -> Option<&MediaGeneration> {
        self.media_generation.as_ref()
    }

    #[must_use]
    pub fn media_generation_id(&self) -> Option<&MediaGenerationId> {
        self.media_generation.as_ref().map(MediaGeneration::id)
    }

    #[must_use]
    pub fn candidate_relative_path(&self) -> Option<&SafeRelativePath> {
        self.candidate_relative_path.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateReadiness {
    ReadySigned,
    ReadyUnsignedRequiresPolicy,
    PendingArtifactValidation,
    AlreadyImported,
    WaitingForPairingKey,
    RecordingOrEncodingIncomplete,
    UnsupportedSchema,
    UnsafePath,
    InsufficientLocalSpace,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCheck {
    code: String,
    passed: bool,
    detail: String,
}

impl ValidationCheck {
    pub fn new(
        code: impl Into<String>,
        passed: bool,
        detail: impl Into<String>,
    ) -> Result<Self, SourceModelError> {
        let code = code.into();
        let detail = detail.into();
        validate_short_text("validation check code", &code, 128)?;
        validate_short_text("validation check detail", &detail, 1_024)?;
        Ok(Self {
            code,
            passed,
            detail,
        })
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.passed
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    checks: Vec<ValidationCheck>,
}

impl ValidationReport {
    pub fn new(checks: Vec<ValidationCheck>) -> Result<Self, SourceModelError> {
        if checks.is_empty() {
            return Err(SourceModelError::EmptyValidationReport);
        }
        Ok(Self { checks })
    }

    #[must_use]
    pub fn checks(&self) -> &[ValidationCheck] {
        &self.checks
    }

    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.checks.iter().all(ValidationCheck::passed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InventoryHashesVerdict {
    Pending,
    Valid { digest: InventoryDigest },
    Invalid { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ManifestSignatureVerdict {
    NotApplicable,
    Pending,
    Valid { key_fingerprint: String },
    Invalid { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProducerKeyTrustVerdict {
    NotApplicable,
    Unknown { key_fingerprint: String },
    Trusted { key_fingerprint: String },
    Rejected { key_fingerprint: String },
}

/// The three independent questions that must never collapse into `trusted:
/// bool`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceTrustVerdicts {
    inventory_hashes: InventoryHashesVerdict,
    manifest_signature: ManifestSignatureVerdict,
    producer_key: ProducerKeyTrustVerdict,
}

impl SourceTrustVerdicts {
    #[must_use]
    pub fn pending_signed(key_fingerprint: impl Into<String>) -> Self {
        let key_fingerprint = key_fingerprint.into();
        Self {
            inventory_hashes: InventoryHashesVerdict::Pending,
            manifest_signature: ManifestSignatureVerdict::Pending,
            producer_key: ProducerKeyTrustVerdict::Unknown { key_fingerprint },
        }
    }

    #[must_use]
    pub fn pending_unsigned() -> Self {
        Self {
            inventory_hashes: InventoryHashesVerdict::Pending,
            manifest_signature: ManifestSignatureVerdict::NotApplicable,
            producer_key: ProducerKeyTrustVerdict::NotApplicable,
        }
    }

    #[must_use]
    pub fn inventory_hashes(&self) -> &InventoryHashesVerdict {
        &self.inventory_hashes
    }

    #[must_use]
    pub fn manifest_signature(&self) -> &ManifestSignatureVerdict {
        &self.manifest_signature
    }

    #[must_use]
    pub fn producer_key(&self) -> &ProducerKeyTrustVerdict {
        &self.producer_key
    }
}

/// Provenance that can only be produced from [`VerifiedPublication`] through
/// [`SourceRecording::admit_device_signed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSigned {
    publication_key_fingerprint: String,
    publication_revision: SourceContentRevision,
    publication_payload: Vec<u8>,
    publication_signature: Vec<u8>,
    publication_public_key: Vec<u8>,
}

impl DeviceSigned {
    #[must_use]
    pub fn publication_key_fingerprint(&self) -> &str {
        &self.publication_key_fingerprint
    }

    #[must_use]
    pub fn publication_revision(&self) -> &SourceContentRevision {
        &self.publication_revision
    }

    #[must_use]
    pub fn publication_payload(&self) -> &[u8] {
        &self.publication_payload
    }

    #[must_use]
    pub fn publication_signature(&self) -> &[u8] {
        &self.publication_signature
    }

    #[must_use]
    pub fn publication_public_key(&self) -> &[u8] {
        &self.publication_public_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedSourceAdmissionReceipt {
    receipt_id: String,
    candidate_id: CandidateId,
    media_generation_id: Option<MediaGenerationId>,
    candidate_revision: CandidateRevision,
    policy_revision: String,
    admitted_at: String,
}

impl UnsignedSourceAdmissionReceipt {
    /// Bind a user decision to the exact scan observation it authorizes.
    ///
    /// The receipt is serialized into the durable import/pipeline source, so
    /// these fields remain available when a card is reinserted or a waiting
    /// job is replayed. A receipt id and policy revision alone are not an
    /// authorization boundary: they could otherwise be replayed for a
    /// different candidate or media generation.
    pub fn new(
        receipt_id: impl Into<String>,
        candidate_id: CandidateId,
        media_generation_id: Option<MediaGenerationId>,
        candidate_revision: CandidateRevision,
        policy_revision: impl Into<String>,
        admitted_at: impl Into<String>,
    ) -> Result<Self, SourceModelError> {
        let receipt_id = receipt_id.into();
        let policy_revision = policy_revision.into();
        let admitted_at = admitted_at.into();
        validate_short_text("unsigned admission receipt id", &receipt_id, 256)?;
        validate_short_text("unsigned admission policy revision", &policy_revision, 256)?;
        validate_short_text("unsigned admission timestamp", &admitted_at, 128)?;
        Ok(Self {
            receipt_id,
            candidate_id,
            media_generation_id,
            candidate_revision,
            policy_revision,
            admitted_at,
        })
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    #[must_use]
    pub fn media_generation_id(&self) -> Option<&MediaGenerationId> {
        self.media_generation_id.as_ref()
    }

    #[must_use]
    pub fn candidate_revision(&self) -> &CandidateRevision {
        &self.candidate_revision
    }

    #[must_use]
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    #[must_use]
    pub fn admitted_at(&self) -> &str {
        &self.admitted_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocallyValidatedUnsigned {
    source_schema: SourceSchema,
    validation_report: ValidationReport,
    computed_inventory_digest: Option<InventoryDigest>,
    user_admission_receipt: Option<UnsignedSourceAdmissionReceipt>,
}

impl LocallyValidatedUnsigned {
    #[must_use]
    pub fn source_schema(&self) -> SourceSchema {
        self.source_schema
    }

    #[must_use]
    pub fn validation_report(&self) -> &ValidationReport {
        &self.validation_report
    }

    #[must_use]
    pub fn computed_inventory_digest(&self) -> Option<&InventoryDigest> {
        self.computed_inventory_digest.as_ref()
    }

    #[must_use]
    pub fn user_admission_receipt(&self) -> Option<&UnsignedSourceAdmissionReceipt> {
        self.user_admission_receipt.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
pub enum SourceProvenance {
    DeviceSigned(DeviceSigned),
    LocallyValidatedUnsigned(LocallyValidatedUnsigned),
}

/// Exact detached-signature material discovered on removable media. It is
/// explicitly untrusted; callers pass [`SignedPublicationMaterial::envelope`]
/// through the existing `PublicationTrust` seam with an externally paired key
/// fingerprint before `DeviceSigned` can be constructed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedPublicationMaterial {
    session_id: String,
    revision: String,
    captured_at: String,
    published_at: String,
    duration_seconds: f64,
    total_bytes: u64,
    video_bytes: u64,
    files: Vec<SignedPublicationFileClaim>,
    publication_payload: String,
    publication_signature_hex: String,
    publication_public_key_hex: String,
    presented_key_fingerprint: String,
    /// RP inline envelopes carry no public key.  Their key version is bound
    /// to an externally authenticated device registry at admission time.
    inline_key_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignedPublicationFileClaim {
    id: String,
    display_path: String,
    role: String,
    size_bytes: u64,
    sha256: String,
    media_type: String,
}

impl SignedPublicationMaterial {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        session_id: String,
        revision: String,
        captured_at: String,
        published_at: String,
        duration_seconds: f64,
        total_bytes: u64,
        video_bytes: u64,
        files: Vec<(String, String, String, u64, String, String)>,
        publication_payload: String,
        publication_signature_hex: String,
        publication_public_key_hex: String,
        presented_key_fingerprint: String,
    ) -> Self {
        Self {
            session_id,
            revision,
            captured_at,
            published_at,
            duration_seconds,
            total_bytes,
            video_bytes,
            files: files
                .into_iter()
                .map(|(id, display_path, role, size_bytes, sha256, media_type)| {
                    SignedPublicationFileClaim {
                        id,
                        display_path,
                        role,
                        size_bytes,
                        sha256,
                        media_type,
                    }
                })
                .collect(),
            publication_payload,
            publication_signature_hex,
            publication_public_key_hex,
            presented_key_fingerprint,
            inline_key_version: None,
        }
    }

    #[must_use]
    pub fn presented_key_fingerprint(&self) -> &str {
        &self.presented_key_fingerprint
    }

    #[must_use]
    pub fn inline_key_version(&self) -> Option<u64> {
        self.inline_key_version
    }

    /// Mark this material as RP's inline-signature profile. The supplied
    /// public-key slot is deliberately empty until the PC registry resolves
    /// the authenticated device identity and key version.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn inline(
        session_id: String,
        revision: String,
        captured_at: String,
        published_at: String,
        duration_seconds: f64,
        total_bytes: u64,
        video_bytes: u64,
        files: Vec<(String, String, String, u64, String, String)>,
        canonical_payload: String,
        signature_hex: String,
        fingerprint: String,
        key_version: u64,
    ) -> Self {
        let mut material = Self::new(
            session_id,
            revision,
            captured_at,
            published_at,
            duration_seconds,
            total_bytes,
            video_bytes,
            files,
            canonical_payload,
            signature_hex,
            String::new(),
            fingerprint,
        );
        material.inline_key_version = Some(key_version);
        material
    }

    #[must_use]
    pub fn envelope_with_registry_public_key(&self, public_key_hex: String) -> PublicationEnvelope {
        let mut envelope = self.envelope();
        envelope.publication_public_key_hex = public_key_hex;
        envelope
    }

    #[must_use]
    pub fn envelope(&self) -> PublicationEnvelope {
        PublicationEnvelope {
            session_id: self.session_id.clone(),
            revision: self.revision.clone(),
            captured_at: self.captured_at.clone(),
            published_at: self.published_at.clone(),
            duration_seconds: self.duration_seconds,
            total_bytes: self.total_bytes,
            video_bytes: self.video_bytes,
            file_count: self.files.len() as u64,
            files: self
                .files
                .iter()
                .map(|file| PublicationFileClaim {
                    id: file.id.clone(),
                    display_path: file.display_path.clone(),
                    role: file.role.clone(),
                    size_bytes: file.size_bytes,
                    sha256: file.sha256.clone(),
                    media_type: file.media_type.clone(),
                })
                .collect(),
            publication_payload: self.publication_payload.clone(),
            publication_signature_hex: self.publication_signature_hex.clone(),
            publication_public_key_hex: self.publication_public_key_hex.clone(),
            publication_key_fingerprint: self.presented_key_fingerprint.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanCandidate {
    id: CandidateId,
    revision_claim: SourceRevisionClaim,
    source_kind: SourceKind,
    schema: SourceSchema,
    session_id: String,
    locator: MediaLocator,
    inventory: Vec<SourceArtifactClaim>,
    media_plan: SourceMediaPlan,
    trust_verdicts: SourceTrustVerdicts,
    readiness: CandidateReadiness,
    validation_report: ValidationReport,
    signed_publication: Option<SignedPublicationMaterial>,
}

impl ScanCandidate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: CandidateId,
        revision_claim: SourceRevisionClaim,
        source_kind: SourceKind,
        schema: SourceSchema,
        session_id: String,
        locator: MediaLocator,
        inventory: Vec<SourceArtifactClaim>,
        media_plan: SourceMediaPlan,
        trust_verdicts: SourceTrustVerdicts,
        readiness: CandidateReadiness,
        validation_report: ValidationReport,
        signed_publication: Option<SignedPublicationMaterial>,
    ) -> Result<Self, SourceModelError> {
        validate_short_text("source session id", &session_id, 256)?;
        validate_inventory(&inventory)?;
        if schema.is_signed() != signed_publication.is_some() {
            return Err(SourceModelError::SignedMaterialMismatch);
        }
        if validation_report.is_accepted()
            && matches!(
                readiness,
                CandidateReadiness::Corrupt
                    | CandidateReadiness::UnsafePath
                    | CandidateReadiness::UnsupportedSchema
                    | CandidateReadiness::RecordingOrEncodingIncomplete
            )
        {
            return Err(SourceModelError::ReadinessContradictsValidation);
        }
        Ok(Self {
            id,
            revision_claim,
            source_kind,
            schema,
            session_id,
            locator,
            inventory,
            media_plan,
            trust_verdicts,
            readiness,
            validation_report,
            signed_publication,
        })
    }

    #[must_use]
    pub fn id(&self) -> &CandidateId {
        &self.id
    }

    #[must_use]
    pub fn revision_claim(&self) -> &SourceRevisionClaim {
        &self.revision_claim
    }

    #[must_use]
    pub fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    #[must_use]
    pub fn schema(&self) -> SourceSchema {
        self.schema
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn locator(&self) -> &MediaLocator {
        &self.locator
    }

    #[must_use]
    pub fn inventory(&self) -> &[SourceArtifactClaim] {
        &self.inventory
    }

    #[must_use]
    pub fn media_plan(&self) -> &SourceMediaPlan {
        &self.media_plan
    }

    #[must_use]
    pub fn trust_verdicts(&self) -> &SourceTrustVerdicts {
        &self.trust_verdicts
    }

    #[must_use]
    pub fn readiness(&self) -> CandidateReadiness {
        self.readiness
    }

    #[must_use]
    pub fn validation_report(&self) -> &ValidationReport {
        &self.validation_report
    }

    #[must_use]
    pub fn signed_publication(&self) -> Option<&SignedPublicationMaterial> {
        self.signed_publication.as_ref()
    }
}

/// The only source value an import job may accept. Its fields are private and
/// its public constructors require either a `VerifiedPublication` or a
/// successful unsigned validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecording {
    candidate_id: CandidateId,
    revision_claim: SourceRevisionClaim,
    content_revision: Option<SourceContentRevision>,
    source_kind: SourceKind,
    schema: SourceSchema,
    session_id: String,
    locator: MediaLocator,
    inventory: Vec<SourceArtifactClaim>,
    media_plan: SourceMediaPlan,
    provenance: SourceProvenance,
    trust_verdicts: SourceTrustVerdicts,
}

impl SourceRecording {
    pub fn admit_device_signed(
        candidate: ScanCandidate,
        verified: &VerifiedPublication,
    ) -> Result<Self, AdmissionError> {
        if candidate.schema != SourceSchema::SignedPublicationV1 {
            return Err(AdmissionError::WrongProvenanceForSchema);
        }
        if candidate.session_id != verified.session_id_str() {
            return Err(AdmissionError::VerifiedPublicationMismatch(
                "session id differs from the scanned candidate".to_string(),
            ));
        }
        let Some(signed_material) = candidate.signed_publication.as_ref() else {
            return Err(AdmissionError::VerifiedPublicationMismatch(
                "candidate is missing exact signed publication material".to_string(),
            ));
        };
        let envelope = signed_material.envelope();
        if envelope.publication_payload.as_bytes() != verified.payload()
            || envelope.publication_signature_hex != encode_lower_hex(verified.signature())
            || (signed_material.inline_key_version.is_none()
                && envelope.publication_public_key_hex != encode_lower_hex(verified.public_key()))
            || envelope.publication_key_fingerprint != verified.key_fingerprint()
        {
            return Err(AdmissionError::VerifiedPublicationMismatch(
                "verified publication is not the exact card publication".to_string(),
            ));
        }
        let publication_revision = SourceContentRevision::parse(verified.revision())?;
        if candidate.revision_claim.stable() != Some(&publication_revision) {
            return Err(AdmissionError::VerifiedPublicationMismatch(
                "publication revision differs from the scanned candidate".to_string(),
            ));
        }
        if candidate.inventory.len() != verified.files().len()
            || candidate
                .inventory
                .iter()
                .zip(verified.files())
                .any(|(claim, file)| {
                    claim.id.as_str() != file.id()
                        || claim.relative_path.as_str() != file.display_path()
                        || claim.size_bytes != file.size_bytes()
                        || claim.source_sha256.as_deref() != Some(file.sha256())
                })
        {
            return Err(AdmissionError::VerifiedPublicationMismatch(
                "signed inventory differs from the scanned candidate".to_string(),
            ));
        }
        let fingerprint = verified.key_fingerprint().to_string();
        Ok(Self {
            candidate_id: candidate.id,
            revision_claim: SourceRevisionClaim::Published(publication_revision.clone()),
            content_revision: Some(publication_revision.clone()),
            source_kind: candidate.source_kind,
            schema: candidate.schema,
            session_id: candidate.session_id,
            locator: candidate.locator,
            inventory: candidate.inventory,
            media_plan: candidate.media_plan,
            provenance: SourceProvenance::DeviceSigned(DeviceSigned {
                publication_key_fingerprint: fingerprint.clone(),
                publication_revision,
                publication_payload: verified.payload().to_vec(),
                publication_signature: verified.signature().to_vec(),
                publication_public_key: verified.public_key().to_vec(),
            }),
            trust_verdicts: SourceTrustVerdicts {
                inventory_hashes: InventoryHashesVerdict::Pending,
                manifest_signature: ManifestSignatureVerdict::Valid {
                    key_fingerprint: fingerprint.clone(),
                },
                producer_key: ProducerKeyTrustVerdict::Trusted {
                    key_fingerprint: fingerprint,
                },
            },
        })
    }

    pub fn admit_unsigned(
        candidate: ScanCandidate,
        user_admission_receipt: Option<UnsignedSourceAdmissionReceipt>,
    ) -> Result<Self, AdmissionError> {
        if candidate.schema.is_signed() {
            return Err(AdmissionError::WrongProvenanceForSchema);
        }
        if !matches!(
            &candidate.revision_claim,
            SourceRevisionClaim::Provisional(_)
        ) {
            return Err(AdmissionError::UnsignedCandidateAlreadyPublished);
        }
        let admissible_unsigned = matches!(
            candidate.readiness,
            CandidateReadiness::ReadyUnsignedRequiresPolicy
                | CandidateReadiness::PendingArtifactValidation
        );
        if !candidate.validation_report.is_accepted() || !admissible_unsigned {
            return Err(AdmissionError::CandidateNotAdmissible {
                readiness: candidate.readiness,
            });
        }
        if let Some(receipt) = user_admission_receipt.as_ref() {
            let SourceRevisionClaim::Provisional(candidate_revision) = &candidate.revision_claim
            else {
                return Err(AdmissionError::UnsignedCandidateAlreadyPublished);
            };
            if receipt.candidate_id() != &candidate.id {
                return Err(AdmissionError::UnsignedAdmissionReceiptMismatch(
                    "candidate id differs from the receipt".to_string(),
                ));
            }
            if receipt.media_generation_id() != candidate.locator.media_generation_id() {
                return Err(AdmissionError::UnsignedAdmissionReceiptMismatch(
                    "media generation differs from the receipt".to_string(),
                ));
            }
            if receipt.candidate_revision() != candidate_revision {
                return Err(AdmissionError::UnsignedAdmissionReceiptMismatch(
                    "provisional candidate revision differs from the receipt".to_string(),
                ));
            }
        }
        let validation_report = candidate.validation_report;
        Ok(Self {
            candidate_id: candidate.id,
            revision_claim: candidate.revision_claim,
            content_revision: None,
            source_kind: candidate.source_kind,
            schema: candidate.schema,
            session_id: candidate.session_id,
            locator: candidate.locator,
            inventory: candidate.inventory,
            media_plan: candidate.media_plan,
            provenance: SourceProvenance::LocallyValidatedUnsigned(LocallyValidatedUnsigned {
                source_schema: candidate.schema,
                validation_report,
                computed_inventory_digest: None,
                user_admission_receipt,
            }),
            trust_verdicts: SourceTrustVerdicts::pending_unsigned(),
        })
    }

    /// Freeze the inventory verdict after all source bytes were copied and
    /// the PC staging copy was independently re-read. For unsigned input this
    /// is also the first point at which a stable content revision exists.
    pub fn with_verified_inventory(mut self, digest: InventoryDigest) -> Self {
        self.trust_verdicts.inventory_hashes = InventoryHashesVerdict::Valid {
            digest: digest.clone(),
        };
        if let SourceProvenance::LocallyValidatedUnsigned(unsigned) = &mut self.provenance {
            unsigned.computed_inventory_digest = Some(digest.clone());
            let revision = SourceContentRevision::parse(digest.as_str())
                .expect("InventoryDigest and SourceContentRevision share the same validated shape");
            self.revision_claim = SourceRevisionClaim::Published(revision.clone());
            self.content_revision = Some(revision);
        }
        self
    }

    #[must_use]
    pub fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    #[must_use]
    pub fn revision_claim(&self) -> &SourceRevisionClaim {
        &self.revision_claim
    }

    #[must_use]
    pub fn content_revision(&self) -> Option<&SourceContentRevision> {
        self.content_revision.as_ref()
    }

    #[must_use]
    pub fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    #[must_use]
    pub fn schema(&self) -> SourceSchema {
        self.schema
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn locator(&self) -> &MediaLocator {
        &self.locator
    }

    #[must_use]
    pub fn inventory(&self) -> &[SourceArtifactClaim] {
        &self.inventory
    }

    #[must_use]
    pub fn media_plan(&self) -> &SourceMediaPlan {
        &self.media_plan
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn trust_verdicts(&self) -> &SourceTrustVerdicts {
        &self.trust_verdicts
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.inventory.iter().fold(0u64, |total, artifact| {
            total.saturating_add(artifact.size_bytes)
        })
    }
}

/// Durable handle passed to normalization after a source tree has been
/// independently verified and atomically published in the PC library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSourceReceipt {
    content_revision: SourceContentRevision,
    inventory_digest: InventoryDigest,
    sealed_relative_path: SafeRelativePath,
    commit_receipt: String,
    provenance: SourceProvenance,
    committed_at: String,
}

impl LocalSourceReceipt {
    pub fn new(
        recording: &SourceRecording,
        sealed_relative_path: SafeRelativePath,
        commit_receipt: impl Into<String>,
        committed_at: impl Into<String>,
    ) -> Result<Self, SourceModelError> {
        let content_revision = recording
            .content_revision
            .clone()
            .ok_or(SourceModelError::InventoryNotVerified)?;
        let InventoryHashesVerdict::Valid { digest } = &recording.trust_verdicts.inventory_hashes
        else {
            return Err(SourceModelError::InventoryNotVerified);
        };
        let commit_receipt = commit_receipt.into();
        let committed_at = committed_at.into();
        validate_short_text("local source commit receipt", &commit_receipt, 512)?;
        validate_short_text("local source committed_at", &committed_at, 128)?;
        Ok(Self {
            content_revision,
            inventory_digest: digest.clone(),
            sealed_relative_path,
            commit_receipt,
            provenance: recording.provenance.clone(),
            committed_at,
        })
    }

    #[must_use]
    pub fn content_revision(&self) -> &SourceContentRevision {
        &self.content_revision
    }

    #[must_use]
    pub fn inventory_digest(&self) -> &InventoryDigest {
        &self.inventory_digest
    }

    #[must_use]
    pub fn sealed_relative_path(&self) -> &SafeRelativePath {
        &self.sealed_relative_path
    }

    #[must_use]
    pub fn commit_receipt(&self) -> &str {
        &self.commit_receipt
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn committed_at(&self) -> &str {
        &self.committed_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceModelError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("video artifact {path:?} must not be empty")]
    EmptyVideo { path: String },
    #[error("artifact media type is empty, too long, or contains control characters")]
    InvalidMediaType,
    #[error("frame-rate numerator and denominator must both be non-zero")]
    InvalidFrameRate,
    #[error("frame dimensions must be non-zero")]
    InvalidGeometry,
    #[error("media plan must contain at least one video segment")]
    NoVideoSegments,
    #[error("validation report must contain at least one explicit check")]
    EmptyValidationReport,
    #[error("{field} is empty, too long, or contains control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must be exactly 64 lowercase hexadecimal characters")]
    InvalidSha256 { field: &'static str },
    #[error("source inventory must not be empty")]
    EmptyInventory,
    #[error("source inventory contains duplicate artifact id {id:?}")]
    DuplicateArtifactId { id: String },
    #[error("source inventory contains duplicate path {path:?}")]
    DuplicateArtifactPath { path: String },
    #[error("candidate readiness contradicts its successful validation report")]
    ReadinessContradictsValidation,
    #[error("signed publication material presence does not match candidate schema")]
    SignedMaterialMismatch,
    #[error("source inventory has not passed copy-and-reread verification")]
    InventoryNotVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("candidate provenance does not match its schema")]
    WrongProvenanceForSchema,
    #[error("verified publication does not match candidate: {0}")]
    VerifiedPublicationMismatch(String),
    #[error("unsigned candidates must remain provisional until local inventory verification")]
    UnsignedCandidateAlreadyPublished,
    #[error("candidate is not admissible in state {readiness:?}")]
    CandidateNotAdmissible { readiness: CandidateReadiness },
    #[error("unsigned admission receipt is not bound to this exact candidate observation: {0}")]
    UnsignedAdmissionReceiptMismatch(String),
}

fn validate_inventory(inventory: &[SourceArtifactClaim]) -> Result<(), SourceModelError> {
    if inventory.is_empty() {
        return Err(SourceModelError::EmptyInventory);
    }
    let mut ids = HashSet::with_capacity(inventory.len());
    let mut paths = HashSet::with_capacity(inventory.len());
    for artifact in inventory {
        if !ids.insert(artifact.id.as_str()) {
            return Err(SourceModelError::DuplicateArtifactId {
                id: artifact.id.as_str().to_string(),
            });
        }
        if !paths.insert(artifact.relative_path.as_str()) {
            return Err(SourceModelError::DuplicateArtifactPath {
                path: artifact.relative_path.as_str().to_string(),
            });
        }
    }
    Ok(())
}

fn validate_sha256_hex(field: &'static str, digest: &str) -> Result<(), SourceModelError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SourceModelError::InvalidSha256 { field });
    }
    Ok(())
}

fn validate_short_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), SourceModelError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(SourceModelError::InvalidText { field });
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
