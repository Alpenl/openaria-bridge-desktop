//! Read-only recording admission and durable local import.
//!
//! This module owns the complexity that must not leak into Tauri commands or
//! UI state: constrained discovery, schema admission, provenance, source
//! fencing, resumable byte acquisition, and the import aggregate.

mod artifact_source;
mod detector;
mod identity;
mod job;
mod path;
mod scan;
mod source;

pub use artifact_source::{
    classify_body_read_error, ArtifactBodyReadError, ArtifactOpenOutcome, ArtifactReadFailure,
    ArtifactReadRequest, ArtifactSource, ArtifactSourceError,
};
pub use detector::{
    ApplianceSpoolV6Detector, DeviceSessionV1Detector, LegacyMjpegSessionV5Detector,
    RawCaptureV2Detector, SignedPublicationV1Detector,
};
pub use identity::{
    AcquisitionSourceId, CandidateId, CandidateRevision, IdentityError, ImportJobId,
    InventoryDigest, MediaGeneration, MediaGenerationId, SourceArtifactId, SourceContentRevision,
    SourceRevisionClaim,
};
pub use job::{
    ImportCommand, ImportCommandOutcome, ImportControlCommand, ImportDecision, ImportDesiredState,
    ImportEffect, ImportFailure, ImportFailureCode, ImportFileCheckpoint, ImportFileSpec,
    ImportJob, ImportJobError, ImportJobState, ImportNaturalKey, ImportPolicy, ImportRejectReason,
    ImportResumePoint, ImportSnapshot, ImportSpec, ImportSpecError, ImportStartOutcome,
    UnsignedImportPolicy,
};
pub use path::{
    open_regular_file_beneath, resolve_directory_no_links, resolve_regular_file_no_links,
    validate_relative_path, FileIdentity, OpenedRegularFile, PathSafetyError, SafeRelativePath,
};
pub use scan::{
    ConstrainedScanner, ScanConfigurationError, ScanDiagnostic, ScanDiagnosticCode,
    ScanDiagnosticSeverity, ScanItem, ScanItemOutcome, ScanLimits, ScanRequest, ScanScope,
    ScanSnapshot, ScanStatistics, MOUNTED_VOLUME_RECORDING_CONTAINERS,
};
pub use source::{
    AdmissionError, CandidateReadiness, DeviceSigned, FrameRate, InventoryHashesVerdict,
    LocalSourceReceipt, LocallyValidatedUnsigned, ManifestSignatureVerdict, MediaLocator,
    ProducerKeyTrustVerdict, ScanCandidate, SignedPublicationMaterial, SourceArtifactClaim,
    SourceArtifactRole, SourceKind, SourceMediaPlan, SourceModelError, SourceProvenance,
    SourceRecording, SourceSchema, SourceTrustVerdicts, SourceVideoCodec, StereoLayout,
    UnsignedSourceAdmissionReceipt, ValidationCheck, ValidationReport,
};

/// Application-facing interface. Platform discovery/eject, worker scheduling,
/// and persistence remain implementation details; callers only see snapshots
/// and tagged command outcomes.
pub trait RecordingIngestor: Send + Sync {
    fn scan(&self, request: ScanRequest) -> Result<ScanSnapshot, IngestError>;

    fn start_import(
        &self,
        candidate_id: CandidateId,
        policy: ImportPolicy,
    ) -> Result<ImportStartOutcome, IngestError>;

    fn command(
        &self,
        job_id: ImportJobId,
        command: ImportControlCommand,
    ) -> Result<ImportCommandOutcome, IngestError>;

    fn snapshots(&self) -> Result<Vec<ImportSnapshot>, IngestError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IngestError {
    #[error("scan candidate was not found or is stale")]
    CandidateUnavailable,
    #[error("import job was not found")]
    JobNotFound,
    #[error("ingest policy approval is required: {message}")]
    PolicyApprovalRequired { message: String },
    #[error("import request conflicts with an existing job: {message}")]
    Conflict { message: String },
    #[error("ingest persistence failed: {message}")]
    Persistence { message: String },
    #[error("ingest worker is unavailable: {message}")]
    Unavailable { message: String },
    #[error("ingest operation failed: {message}")]
    Internal { message: String },
}
