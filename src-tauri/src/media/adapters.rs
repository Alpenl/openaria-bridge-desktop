//! Concrete media port sets used by the Tauri composition root.
//!
//! This module intentionally starts with a fail-closed implementation. It is a
//! real set of application ports, so the media facade can be constructed and
//! registered without lying about scanner, ingest, FFmpeg, or upload effects
//! that are not yet wired into the production composition. Commands surface a
//! stable typed error and never publish synthetic job success.

use std::sync::Arc;

use serde_json::json;

use super::ports::{
    MediaEffect, MediaErrorCode, MediaLifecyclePort, MediaNormalizerPort, MediaPortError,
    MediaProjectionDelta, MediaProjectionSet, MediaProjectionSink, MediaScannerPort,
    MediaTrustPort, Observed, RecordingIngestorPort, SessionPipelinePort,
};
use super::types::{
    DerivationJob, DerivationJobId, ImportJob, ImportJobId, MediaId, MediaJobCommand,
    MediaScanSnapshot, MediaTrustedProducerRevocation, PipelineBatchItemResult,
    PipelineBatchOutcome, PipelineCommand, PipelineId, PipelineSession, ScanRequest,
    StartDerivationRequest, StartImportRequest, StartPipelineRequest,
};

use super::MediaApplicationPorts;

/// Build a conservative media port set for composition phases where the
/// facade must be present but the concrete scanner/worker graph is not yet
/// assembled.
///
/// Recover returns the exact seed projection supplied by the composition root.
/// All mutating operations fail with typed non-retryable errors and no
/// projection delta, except pipeline batch, which returns the command's tagged
/// batch shape with per-item failures plus a batch-level operation error.
#[must_use]
pub fn fail_closed_media_ports(initial: MediaProjectionSet) -> MediaApplicationPorts {
    FailClosedMediaPorts::into_ports(initial)
}

#[derive(Debug, Clone)]
pub struct FailClosedMediaPorts {
    initial: MediaProjectionSet,
}

impl FailClosedMediaPorts {
    #[must_use]
    pub fn into_ports(initial: MediaProjectionSet) -> MediaApplicationPorts {
        let shared = Arc::new(Self { initial });
        let scanner: Arc<dyn MediaScannerPort> = shared.clone();
        let ingestor: Arc<dyn RecordingIngestorPort> = shared.clone();
        let normalizer: Arc<dyn MediaNormalizerPort> = shared.clone();
        let pipeline: Arc<dyn SessionPipelinePort> = shared.clone();
        let trust: Arc<dyn MediaTrustPort> = shared.clone();
        let lifecycle: Arc<dyn MediaLifecyclePort> = shared;
        MediaApplicationPorts::new(scanner, ingestor, normalizer, pipeline, trust, lifecycle)
    }

    fn unavailable(
        &self,
        code: MediaErrorCode,
        operation: &'static str,
        capability: &'static str,
    ) -> MediaPortError {
        MediaPortError::new(
            code,
            format!("media {capability} is not wired into the production composition yet"),
        )
        .with_retryable(false)
        .with_detail("operation", json!(operation))
        .with_detail("capability", json!(capability))
    }
}

impl MediaScannerPort for FailClosedMediaPorts {
    fn scan(&self, _request: ScanRequest) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        Err(self.unavailable(MediaErrorCode::ScanFailed, "media_scan", "scanner"))
    }

    fn release_media_handles(
        &self,
        _media_id: MediaId,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::MediaUnavailable,
            "media_release_handles",
            "volume lifecycle",
        ))
    }

    fn eject_media(
        &self,
        _media_id: MediaId,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::MediaUnavailable,
            "media_eject",
            "platform eject",
        ))
    }
}

impl RecordingIngestorPort for FailClosedMediaPorts {
    fn start_import(
        &self,
        _request: StartImportRequest,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::ImportStartFailed,
            "media_start_import",
            "recording ingestor",
        ))
    }

    fn command_import(
        &self,
        _job_id: ImportJobId,
        _command: MediaJobCommand,
    ) -> Result<MediaEffect<ImportJob>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::ImportCommandFailed,
            "media_command_import",
            "recording ingestor",
        ))
    }
}

impl MediaNormalizerPort for FailClosedMediaPorts {
    fn start_derivation(
        &self,
        _request: StartDerivationRequest,
    ) -> Result<MediaEffect<DerivationJob>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::EncoderUnavailable,
            "media_start_derivation",
            "media normalizer",
        ))
    }

    fn command_derivation(
        &self,
        _job_id: DerivationJobId,
        _command: MediaJobCommand,
    ) -> Result<MediaEffect<DerivationJob>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::DerivationCommandFailed,
            "media_command_derivation",
            "media normalizer",
        ))
    }
}

impl SessionPipelinePort for FailClosedMediaPorts {
    fn start_pipeline(
        &self,
        _request: StartPipelineRequest,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::PipelineStartFailed,
            "media_start_pipeline",
            "session pipeline",
        ))
    }

    fn start_pipeline_batch(
        &self,
        requests: Vec<StartPipelineRequest>,
    ) -> Result<MediaEffect<PipelineBatchOutcome>, MediaPortError> {
        let results = requests
            .into_iter()
            .map(|request| PipelineBatchItemResult::Failure {
                item: request.candidate_id,
                error: self
                    .unavailable(
                        MediaErrorCode::PipelineStartFailed,
                        "media_start_pipeline_batch",
                        "session pipeline",
                    )
                    .into_rpc(),
            })
            .collect();
        Ok(MediaEffect::new(
            PipelineBatchOutcome {
                results,
                operation_error: Some(
                    self.unavailable(
                        MediaErrorCode::PipelineStartFailed,
                        "media_start_pipeline_batch",
                        "session pipeline",
                    )
                    .into_rpc(),
                ),
            },
            MediaProjectionDelta::default(),
        ))
    }

    fn command_pipeline(
        &self,
        _pipeline_id: PipelineId,
        _command: PipelineCommand,
    ) -> Result<MediaEffect<PipelineSession>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::PipelineCommandFailed,
            "media_command_pipeline",
            "session pipeline",
        ))
    }

    fn retry_derived_upload(
        &self,
        _parent_job_id: &str,
    ) -> Result<MediaEffect<String>, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::PipelineCommandFailed,
            "retry_transfer",
            "derived upload pipeline",
        ))
    }
}

impl MediaTrustPort for FailClosedMediaPorts {
    fn revoke_trusted_producer(
        &self,
        _key_fingerprint: &str,
    ) -> Result<MediaTrustedProducerRevocation, MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::OperationConflict,
            "media_revoke_trusted_producer",
            "trusted producer registry",
        ))
    }
}

impl MediaLifecyclePort for FailClosedMediaPorts {
    fn recover(&self) -> Result<MediaProjectionSet, MediaPortError> {
        Ok(self.initial.clone())
    }

    fn start(&self, _sink: Arc<dyn MediaProjectionSink>) -> Result<(), MediaPortError> {
        Err(self.unavailable(
            MediaErrorCode::ResourceStuck,
            "media_lifecycle_start",
            "media background workers",
        ))
    }

    fn stop(&self) -> Result<(), MediaPortError> {
        Ok(())
    }
}
