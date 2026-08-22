//! Stable application/RPC types for removable-media import and normalization.
//!
//! These are deliberately projections rather than persistence records. They
//! preserve the three independent truths a client needs to render: whether
//! source bytes are local and verified, whether a normalized derivative is
//! verified, and whether the exact derived upload bundle is remotely verified.

use serde::{Deserialize, Serialize};

use crate::application::RpcError;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

opaque_id!(MediaId);
opaque_id!(CandidateId);
opaque_id!(SourceId);
opaque_id!(ImportJobId);
opaque_id!(DerivationJobId);
opaque_id!(PipelineId);
opaque_id!(ProfileId);
opaque_id!(DerivedId);
opaque_id!(UploadBundleId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSchema {
    DeviceSessionV1,
    DeviceSessionV2,
    RawCaptureV2,
    LegacyMjpegSessionV5,
    CompleteUnpublishedV6,
    ApplianceSpoolV6,
    UnsignedPublicationV1,
    SignedPublicationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsignedSourceSchema {
    DeviceSessionV1,
    DeviceSessionV2,
    RawCaptureV2,
    LegacyMjpegSessionV5,
    CompleteUnpublishedV6,
    ApplianceSpoolV6,
    UnsignedPublicationV1,
}

impl From<UnsignedSourceSchema> for SourceSchema {
    fn from(value: UnsignedSourceSchema) -> Self {
        match value {
            UnsignedSourceSchema::DeviceSessionV1 => Self::DeviceSessionV1,
            UnsignedSourceSchema::DeviceSessionV2 => Self::DeviceSessionV2,
            UnsignedSourceSchema::RawCaptureV2 => Self::RawCaptureV2,
            UnsignedSourceSchema::LegacyMjpegSessionV5 => Self::LegacyMjpegSessionV5,
            UnsignedSourceSchema::CompleteUnpublishedV6 => Self::CompleteUnpublishedV6,
            UnsignedSourceSchema::ApplianceSpoolV6 => Self::ApplianceSpoolV6,
            UnsignedSourceSchema::UnsignedPublicationV1 => Self::UnsignedPublicationV1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    RemovableMedia,
    LegacyRemovableMedia,
    LocalFolder,
    Lan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaPresence {
    Present,
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaHandleState {
    InUse,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaEjectState {
    Unsupported,
    Blocked,
    Available,
    Ejecting,
    Ejected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaDescriptor {
    pub id: MediaId,
    pub display_name: String,
    pub mount_path: Option<String>,
    pub filesystem: Option<String>,
    pub presence: MediaPresence,
    pub reader_count: u32,
    pub handle_state: MediaHandleState,
    pub eject_state: MediaEjectState,
    pub eject_veto: Option<String>,
    /// Why this card is mounted and recognized yet still shows nothing, when
    /// the reason is about access rather than content. `None` means no such
    /// obstacle was observed, which is not a promise that the card holds
    /// recordings.
    pub access_issue: Option<String>,
    pub observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateVerdict {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerdict {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerKeyTrust {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryIntegrity {
    Pending,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsignedAdmission {
    Required,
    Approved,
}

/// Provenance is a discriminated union so unsigned media can never be made
/// device-signed by flipping a boolean in an application DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceProvenance {
    DeviceSigned {
        #[serde(rename = "publicationKeyFingerprint")]
        publication_key_fingerprint: String,
        #[serde(rename = "manifestSignature")]
        manifest_signature: SignatureVerdict,
        #[serde(rename = "producerKeyTrust")]
        producer_key_trust: ProducerKeyTrust,
        #[serde(rename = "inventoryIntegrity")]
        inventory_integrity: InventoryIntegrity,
    },
    LocallyValidatedUnsigned {
        #[serde(rename = "sourceSchema")]
        source_schema: UnsignedSourceSchema,
        #[serde(rename = "validationReportId")]
        validation_report_id: Option<String>,
        #[serde(rename = "inventoryDigest")]
        inventory_digest: Option<String>,
        admission: UnsignedAdmission,
    },
}

/// Bounded application projection of one durable media-library entry.
///
/// This is intentionally not a serialization of the core projection. Core
/// receipts contain commit metadata and, for signed sources, publication
/// bytes and cryptographic material that must never cross the RPC boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaLibraryEntryProjection {
    pub entry_key: String,
    pub source_identity: String,
    pub source_revision: String,
    pub source_local: MediaLibrarySourceLocalProjection,
    pub derived_local: Vec<MediaLibraryDerivedProjection>,
    pub upload_bundles: Vec<MediaLibraryUploadProjection>,
    pub card_presence: MediaLibraryCardPresence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTrustedProducerRevocation {
    pub key_fingerprint: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MediaExportResult {
    Cancelled,
    #[serde(rename_all = "camelCase")]
    Completed {
        output_path: String,
        video_segment_count: usize,
        audio_segment_count: usize,
        output_size_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
pub enum MediaLibrarySourceLocalProjection {
    Verified {
        #[serde(rename = "importReceiptId")]
        import_receipt_id: String,
        #[serde(rename = "importJobId")]
        import_job_id: String,
        #[serde(rename = "relativePath")]
        relative_path: String,
        #[serde(rename = "sealedInventoryDigest")]
        sealed_inventory_digest: String,
        provenance: SourceProvenance,
        #[serde(rename = "committedAt")]
        committed_at: String,
    },
    Removed {
        #[serde(rename = "relativePath")]
        relative_path: String,
        #[serde(rename = "policyRevision")]
        policy_revision: String,
        #[serde(rename = "removedAt")]
        removed_at: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaLibraryDerivedProjection {
    pub derivation_job_id: String,
    pub profile_revision: String,
    pub derived_revision: String,
    pub relative_path: String,
    pub source_manifest_digest: String,
    pub committed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaLibraryUploadProjection {
    pub bundle_revision: String,
    pub storage_profile_identity: String,
    pub source_revision: String,
    pub derived_revision: String,
    pub remote: MediaLibraryRemoteState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
pub enum MediaLibraryRemoteState {
    NotVerified,
    Failed {
        code: String,
        retryable: bool,
    },
    Verified {
        #[serde(rename = "remoteReceiptDigest")]
        remote_receipt_digest: String,
        #[serde(rename = "verifiedAtMs")]
        verified_at_ms: u64,
        #[serde(rename = "sourceArchive")]
        source_archive: MediaLibrarySourceArchive,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MediaLibrarySourceArchive {
    NotIncluded,
    Verified {
        #[serde(rename = "policyRevision")]
        policy_revision: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MediaLibraryCardPresence {
    Unknown,
    Present {
        #[serde(rename = "mediaGenerationId")]
        media_generation_id: String,
        #[serde(rename = "observationSequence")]
        observation_sequence: u64,
        #[serde(rename = "observedAtMs")]
        observed_at_ms: u64,
    },
    Absent {
        #[serde(rename = "lastMediaGenerationId")]
        last_media_generation_id: Option<String>,
        #[serde(rename = "observationSequence")]
        observation_sequence: u64,
        #[serde(rename = "observedAtMs")]
        observed_at_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCandidate {
    pub id: CandidateId,
    pub source_key: String,
    pub media_id: MediaId,
    pub source_id: Option<SourceId>,
    pub session_id: Option<String>,
    pub display_name: String,
    pub relative_path: String,
    pub source_kind: SourceKind,
    pub schema: SourceSchema,
    pub verdict: CandidateVerdict,
    pub reason: Option<RpcError>,
    pub provenance: SourceProvenance,
    pub bytes: u64,
    pub duration_seconds: Option<f64>,
    pub media_required: bool,
}

/// Immutable candidate facts retained by the durable pipeline after the
/// scanner removes a candidate because its card is no longer mounted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineSourceSummary {
    pub source_key: String,
    pub media_id: MediaId,
    pub source_id: Option<SourceId>,
    pub display_name: String,
    pub session_id: Option<String>,
    pub schema: SourceSchema,
    pub source_kind: SourceKind,
    pub provenance: SourceProvenance,
    pub relative_path: String,
    pub bytes: u64,
    pub duration_seconds: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaScanState {
    Idle,
    Scanning,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaScanSnapshot {
    pub scan_id: String,
    pub status: MediaScanState,
    pub media: Vec<MediaDescriptor>,
    pub candidates: Vec<ScanCandidate>,
    /// A scan can complete for already-mounted volumes while UDisks2 refuses
    /// an attach request for an inserted-but-unmounted card. Keep that
    /// capability result separate from per-volume recording access issues so
    /// the UI cannot turn an authorization failure into an empty-card state.
    pub attach_issue: Option<RpcError>,
    pub completed_at: Option<String>,
}

impl Default for MediaScanSnapshot {
    fn default() -> Self {
        Self {
            scan_id: String::new(),
            status: MediaScanState::Idle,
            media: Vec::new(),
            candidates: Vec::new(),
            attach_issue: None,
            completed_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportJobState {
    Queued,
    WaitingForMedia,
    Preflighting,
    Copying,
    Verifying,
    Committing,
    LocalVerified,
    RetryWait,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProgress {
    pub current_file: Option<String>,
    pub copied_bytes: u64,
    pub total_bytes: u64,
    pub throughput_bytes_per_second: Option<f64>,
    pub eta_seconds: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredRunState {
    Run,
    Paused,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportJob {
    pub id: ImportJobId,
    pub candidate_id: CandidateId,
    pub media_id: MediaId,
    pub source_id: Option<SourceId>,
    pub state: ImportJobState,
    pub desired_run_state: DesiredRunState,
    pub progress: ImportProgress,
    pub failure: Option<RpcError>,
    pub retry_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationJobState {
    Queued,
    WaitingForSource,
    Probing,
    Planning,
    Encoding,
    Validating,
    Committing,
    DerivedVerified,
    RetryWait,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivationProgress {
    pub current_segment_pair: Option<u32>,
    pub total_segment_pairs: Option<u32>,
    pub processed_frames: u64,
    pub total_frames: Option<u64>,
    pub encoding_fps: Option<f64>,
    pub eta_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationProgress {
    pub decoded_segment_pairs: u32,
    pub total_segment_pairs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivationJob {
    pub id: DerivationJobId,
    pub source_id: SourceId,
    pub profile_id: ProfileId,
    pub derived_id: Option<DerivedId>,
    pub state: DerivationJobState,
    pub desired_run_state: DesiredRunState,
    pub progress: DerivationProgress,
    pub validation: ValidationProgress,
    pub failure: Option<RpcError>,
    pub retry_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadProgress {
    pub uploaded_bytes: u64,
    pub total_bytes: u64,
    pub current_part: Option<u32>,
    pub total_parts: Option<u32>,
    pub throughput_bytes_per_second: Option<f64>,
    pub eta_seconds: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredActionKind {
    ApproveUnsignedSource,
    ConfigureStorage,
    InstallSupportedEncoder,
    ResolvePolicy,
    RetryRemoteVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredAction {
    pub kind: RequiredActionKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLayerState {
    NotStarted,
    Queued,
    WaitingForMedia,
    Preflighting,
    Copying,
    Verifying,
    Committing,
    LocalVerified,
    RetryWait,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRetentionState {
    Retained,
    NotRetained,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLayer {
    pub state: SourceLayerState,
    pub source_id: Option<SourceId>,
    pub job_id: Option<ImportJobId>,
    pub retention_state: SourceRetentionState,
    pub progress: Option<ImportProgress>,
    pub failure: Option<RpcError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedLayerState {
    NotStarted,
    WaitingForSource,
    Queued,
    Probing,
    Planning,
    Encoding,
    Validating,
    Committing,
    DerivedVerified,
    ActionRequired,
    RetryWait,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedLayer {
    pub state: DerivedLayerState,
    pub derived_id: Option<DerivedId>,
    pub job_id: Option<DerivationJobId>,
    pub progress: Option<DerivationProgress>,
    pub validation: Option<ValidationProgress>,
    pub action: Option<RequiredAction>,
    pub failure: Option<RpcError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLayerState {
    Disabled,
    WaitingForDerived,
    Queued,
    Uploading,
    Verifying,
    ObjectStoreVerified,
    ActionRequired,
    RetryWait,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteLayer {
    pub state: RemoteLayerState,
    pub bundle_id: Option<UploadBundleId>,
    pub upload_job_id: Option<String>,
    pub progress: Option<UploadProgress>,
    pub action: Option<RequiredAction>,
    pub failure: Option<RpcError>,
}

/// V1 accepts only `upload_source_video == false`. Keeping the field on the
/// wire makes the product decision explicit and lets validation fail closed
/// instead of silently treating a derived upload as a source archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelinePolicy {
    pub auto_normalize: bool,
    pub auto_upload_derived: bool,
    pub upload_source_video: bool,
    pub unsigned_upload_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineSession {
    pub id: PipelineId,
    pub candidate_id: CandidateId,
    pub source_summary: PipelineSourceSummary,
    pub policy: PipelinePolicy,
    pub desired_run_state: DesiredRunState,
    pub source: SourceLayer,
    pub derived: DerivedLayer,
    pub remote: RemoteLayer,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanSource {
    MountedVolumes,
    SelectedFolder { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub source: ScanSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartImportRequest {
    pub candidate_id: CandidateId,
    pub approve_unsigned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartDerivationRequest {
    pub source_id: SourceId,
    pub profile_id: ProfileId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPipelineRequest {
    pub candidate_id: CandidateId,
    pub approve_unsigned: bool,
    pub policy: PipelinePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaJobCommand {
    Pause,
    Resume,
    Cancel,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineCommand {
    Pause,
    Resume,
    Cancel,
    Retry,
    ApproveUnsignedUpload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ImportBatchItemResult {
    Success {
        item: CandidateId,
        #[serde(rename = "jobId")]
        job_id: ImportJobId,
    },
    Failure {
        item: CandidateId,
        error: RpcError,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportBatchOutcome {
    pub results: Vec<ImportBatchItemResult>,
    pub operation_error: Option<RpcError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PipelineBatchItemResult {
    Success {
        item: CandidateId,
        #[serde(rename = "jobId")]
        job_id: PipelineId,
    },
    Failure {
        item: CandidateId,
        error: RpcError,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineBatchOutcome {
    pub results: Vec<PipelineBatchItemResult>,
    pub operation_error: Option<RpcError>,
}
