//! Narrow effect ports consumed by [`super::MediaApplication`].
//!
//! The adapters behind these traits map the concrete core modules
//! (`ingest`, `normalization`, `media_store`, and `media_pipeline`) into one
//! application projection contract. All methods may perform blocking disk,
//! network, or process work; the facade always invokes them outside its
//! publication and subscriber locks.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::application::RpcError;

use super::types::{
    DerivationJob, DerivationJobId, ImportJob, ImportJobId, MediaId, MediaJobCommand,
    MediaLibraryEntryProjection, MediaScanSnapshot, MediaTrustedProducerRevocation,
    PipelineBatchOutcome, PipelineCommand, PipelineId, PipelineSession, ScanRequest,
    StartDerivationRequest, StartImportRequest, StartPipelineRequest,
};

const MAX_ERROR_MESSAGE_BYTES: usize = 1024;
const MAX_ERROR_DETAILS: usize = 32;
const MAX_ERROR_DETAIL_KEY_BYTES: usize = 64;
const MAX_ERROR_DETAIL_STRING_BYTES: usize = 512;

/// Stable media error codes accepted by the strict frontend decoder.
// Non-Linux builds expose the same fail-closed wire vocabulary even though
// several Ubuntu-only failures cannot be produced by their unavailable ports.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaErrorCode {
    ScanFailed,
    MediaNotFound,
    MediaChanged,
    MediaUnavailable,
    CandidateNotFound,
    // Stable frontend wire code retained for fail-closed stale projections.
    #[allow(dead_code)]
    CandidateStale,
    SourceRevisionMismatch,
    UnsafePath,
    UnsupportedSchema,
    InsufficientLocalSpace,
    IntegrityFailed,
    ImportStartFailed,
    ImportCommandFailed,
    // Stable frontend wire code retained for the unavailable normalizer port.
    #[allow(dead_code)]
    DerivationStartFailed,
    DerivationCommandFailed,
    EncoderUnavailable,
    ResourceStuck,
    PipelineStartFailed,
    PipelineCommandFailed,
    PolicyApprovalRequired,
    StorageNotConfigured,
    // Stable frontend wire code retained for the unavailable upload port.
    #[allow(dead_code)]
    RemoteVerificationFailed,
    OperationConflict,
}

impl MediaErrorCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanFailed => "scan_failed",
            Self::MediaNotFound => "media_not_found",
            Self::MediaChanged => "media_changed",
            Self::MediaUnavailable => "media_unavailable",
            Self::CandidateNotFound => "candidate_not_found",
            Self::CandidateStale => "candidate_stale",
            Self::SourceRevisionMismatch => "source_revision_mismatch",
            Self::UnsafePath => "unsafe_path",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InsufficientLocalSpace => "insufficient_local_space",
            Self::IntegrityFailed => "integrity_failed",
            Self::ImportStartFailed => "import_start_failed",
            Self::ImportCommandFailed => "import_command_failed",
            Self::DerivationStartFailed => "derivation_start_failed",
            Self::DerivationCommandFailed => "derivation_command_failed",
            Self::EncoderUnavailable => "encoder_unavailable",
            Self::ResourceStuck => "resource_stuck",
            Self::PipelineStartFailed => "pipeline_start_failed",
            Self::PipelineCommandFailed => "pipeline_command_failed",
            Self::PolicyApprovalRequired => "policy_approval_required",
            Self::StorageNotConfigured => "storage_not_configured",
            Self::RemoteVerificationFailed => "remote_verification_failed",
            Self::OperationConflict => "operation_conflict",
        }
    }

    #[must_use]
    fn default_retryable(self) -> bool {
        matches!(
            self,
            Self::ScanFailed
                | Self::MediaChanged
                | Self::MediaUnavailable
                | Self::InsufficientLocalSpace
                | Self::ImportStartFailed
                | Self::DerivationStartFailed
                | Self::ResourceStuck
                | Self::RemoteVerificationFailed
        )
    }
}

/// Error returned by an injected media port. Details are kept structured and
/// converted only to a bounded JSON object at the RPC boundary.
#[derive(Debug, Clone)]
pub struct MediaPortError {
    code: MediaErrorCode,
    message: String,
    retryable: bool,
    details: BTreeMap<String, Value>,
}

impl MediaPortError {
    #[must_use]
    pub fn new(code: MediaErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.default_retryable(),
            details: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }

    #[must_use]
    pub fn into_rpc(self) -> RpcError {
        let details = bounded_details(self.details);
        RpcError::new(
            self.code.as_str(),
            sanitize_text(&self.message, MAX_ERROR_MESSAGE_BYTES),
            self.retryable,
            (!details.is_empty()).then_some(Value::Object(details)),
        )
    }
}

impl std::fmt::Display for MediaPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&sanitize_text(&self.message, MAX_ERROR_MESSAGE_BYTES))
    }
}

impl std::error::Error for MediaPortError {}

fn bounded_details(details: BTreeMap<String, Value>) -> Map<String, Value> {
    details
        .into_iter()
        .take(MAX_ERROR_DETAILS)
        .filter_map(|(key, value)| {
            if key.is_empty() || key.len() > MAX_ERROR_DETAIL_KEY_BYTES {
                return None;
            }
            let value = match value {
                Value::Null | Value::Bool(_) | Value::Number(_) => value,
                Value::String(value) => {
                    Value::String(sanitize_text(&value, MAX_ERROR_DETAIL_STRING_BYTES))
                }
                // Deep/large values are deliberately excluded. RPC details
                // are diagnostics, never an unbounded copy of probe output.
                Value::Array(_) | Value::Object(_) => return None,
            };
            Some((key, value))
        })
        .collect()
}

fn sanitize_text(value: &str, max_bytes: usize) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if output.len() + character.len_utf8() > max_bytes {
            break;
        }
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.push(' ');
        }
    }
    if output.trim().is_empty() {
        "media operation failed".to_string()
    } else {
        output
    }
}

/// A projection read from its authoritative owner. `source_version` is the
/// owner's monotonic durable version (or scanner observation sequence), not
/// the WebView revision. It prevents a late operation result from replacing a
/// newer projection with an older value.
#[derive(Debug, Clone)]
pub struct Observed<T> {
    pub source_version: u64,
    pub value: T,
}

impl<T> Observed<T> {
    #[must_use]
    pub fn new(source_version: u64, value: T) -> Self {
        Self {
            source_version,
            value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MediaProjectionSet {
    pub scan: Observed<MediaScanSnapshot>,
    pub imports: Observed<Vec<ImportJob>>,
    pub derivations: Observed<Vec<DerivationJob>>,
    pub pipelines: Observed<Vec<PipelineSession>>,
    pub library: Observed<Vec<MediaLibraryEntryProjection>>,
}

impl MediaProjectionSet {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            scan: Observed::new(0, MediaScanSnapshot::default()),
            imports: Observed::new(0, Vec::new()),
            derivations: Observed::new(0, Vec::new()),
            pipelines: Observed::new(0, Vec::new()),
            library: Observed::new(0, Vec::new()),
        }
    }

    #[must_use]
    pub fn into_delta(self) -> MediaProjectionDelta {
        MediaProjectionDelta {
            scan: Some(self.scan),
            imports: Some(self.imports),
            derivations: Some(self.derivations),
            pipelines: Some(self.pipelines),
            library: Some(self.library),
        }
    }
}

/// Complete replacement values for the resources changed by one durable
/// operation. No delta contains partial job rows or incremental progress.
#[derive(Debug, Clone, Default)]
pub struct MediaProjectionDelta {
    pub scan: Option<Observed<MediaScanSnapshot>>,
    pub imports: Option<Observed<Vec<ImportJob>>>,
    pub derivations: Option<Observed<Vec<DerivationJob>>>,
    pub pipelines: Option<Observed<Vec<PipelineSession>>>,
    pub library: Option<Observed<Vec<MediaLibraryEntryProjection>>>,
}

impl MediaProjectionDelta {
    #[must_use]
    pub fn scan(scan: Observed<MediaScanSnapshot>) -> Self {
        Self {
            scan: Some(scan),
            ..Self::default()
        }
    }

    pub fn merge(&mut self, other: Self) {
        merge_observed(&mut self.scan, other.scan);
        merge_observed(&mut self.imports, other.imports);
        merge_observed(&mut self.derivations, other.derivations);
        merge_observed(&mut self.pipelines, other.pipelines);
        merge_observed(&mut self.library, other.library);
    }
}

fn merge_observed<T>(target: &mut Option<Observed<T>>, incoming: Option<Observed<T>>) {
    let Some(incoming) = incoming else {
        return;
    };
    let replace = target
        .as_ref()
        .map(|current| incoming.source_version > current.source_version)
        .unwrap_or(true);
    if replace {
        *target = Some(incoming);
    }
}

/// Exact command result plus every complete projection changed by the same
/// committed operation. This removes the read-after-mutation race from the
/// application layer.
#[derive(Debug, Clone)]
pub struct MediaEffect<T> {
    pub result: T,
    pub projections: MediaProjectionDelta,
}

impl<T> MediaEffect<T> {
    #[must_use]
    pub fn new(result: T, projections: MediaProjectionDelta) -> Self {
        Self {
            result,
            projections,
        }
    }
}

pub trait MediaScannerPort: Send + Sync {
    fn scan(&self, request: ScanRequest) -> Result<Observed<MediaScanSnapshot>, MediaPortError>;

    fn release_media_handles(
        &self,
        media_id: MediaId,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError>;

    fn eject_media(&self, media_id: MediaId)
        -> Result<Observed<MediaScanSnapshot>, MediaPortError>;
}

/// Application mapping for core `ingest::RecordingIngestor`.
pub trait RecordingIngestorPort: Send + Sync {
    fn start_import(
        &self,
        request: StartImportRequest,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError>;

    fn command_import(
        &self,
        job_id: ImportJobId,
        command: MediaJobCommand,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError>;
}

/// Application mapping for core `normalization::MediaNormalizer`.
pub trait MediaNormalizerPort: Send + Sync {
    fn start_derivation(
        &self,
        request: StartDerivationRequest,
    ) -> Result<MediaEffect<DerivationJob>, MediaPortError>;

    fn command_derivation(
        &self,
        job_id: DerivationJobId,
        command: MediaJobCommand,
    ) -> Result<MediaEffect<DerivationJob>, MediaPortError>;
}

/// Application mapping for core `media_pipeline::SessionPipeline`. Upload
/// starts/retries are policy decisions here; the facade never calls an object
/// store or FFmpeg adapter directly.
pub trait SessionPipelinePort: Send + Sync {
    fn start_pipeline(
        &self,
        request: StartPipelineRequest,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError>;

    fn start_pipeline_batch(
        &self,
        requests: Vec<StartPipelineRequest>,
    ) -> Result<MediaEffect<PipelineBatchOutcome>, MediaPortError>;

    fn command_pipeline(
        &self,
        pipeline_id: PipelineId,
        command: PipelineCommand,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError>;

    fn retry_derived_upload(
        &self,
        parent_job_id: &str,
    ) -> Result<MediaEffect<String>, MediaPortError>;
}

/// Narrow trust-management seam. The application may revoke one exact
/// fingerprint, but it cannot enumerate the trust store or receive pairing
/// evidence and key material.
pub trait MediaTrustPort: Send + Sync {
    fn revoke_trusted_producer(
        &self,
        key_fingerprint: &str,
    ) -> Result<MediaTrustedProducerRevocation, MediaPortError>;
}

/// Background owners publish only after their durable transition commits.
pub trait MediaProjectionSink: Send + Sync {
    // The fail-closed non-Linux lifecycle accepts this port to preserve the
    // common interface, but only the Ubuntu lifecycle publishes through it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn publish(&self, delta: MediaProjectionDelta) -> Result<(), MediaPortError>;
}

/// Recovery and watcher/worker lifecycle. `recover` may access SQLite and the
/// filesystem; `start` may create worker threads. Both are called from a
/// blocking task and never while an application lock is held.
pub trait MediaLifecyclePort: Send + Sync {
    fn recover(&self) -> Result<MediaProjectionSet, MediaPortError>;

    fn start(&self, sink: Arc<dyn MediaProjectionSink>) -> Result<(), MediaPortError>;

    fn stop(&self) -> Result<(), MediaPortError>;
}
