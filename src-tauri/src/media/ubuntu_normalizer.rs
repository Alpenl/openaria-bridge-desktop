//! Fail-closed Ubuntu normalization boundary for the import-only MVP.
//!
//! The current milestone does not own codec probing, encoding, quality
//! evaluation, or derivation recovery. Keep the application port present so
//! the shared media facade has a complete graph, but reject every derivation
//! mutation with a typed, non-retryable capability error.

use std::sync::Arc;

use serde_json::json;

use super::ports::{MediaEffect, MediaErrorCode, MediaNormalizerPort, MediaPortError};
use super::types::{DerivationJob, DerivationJobId, MediaJobCommand, StartDerivationRequest};

#[must_use]
pub fn ubuntu_mvp_normalizer_port() -> Arc<dyn MediaNormalizerPort> {
    Arc::new(UbuntuNormalizationUnavailable)
}

#[derive(Debug, Clone, Copy, Default)]
struct UbuntuNormalizationUnavailable;

impl MediaNormalizerPort for UbuntuNormalizationUnavailable {
    fn start_derivation(
        &self,
        _request: StartDerivationRequest,
    ) -> Result<MediaEffect<DerivationJob>, MediaPortError> {
        Err(normalization_unavailable("media_start_derivation"))
    }

    fn command_derivation(
        &self,
        _job_id: DerivationJobId,
        _command: MediaJobCommand,
    ) -> Result<MediaEffect<DerivationJob>, MediaPortError> {
        Err(normalization_unavailable("media_command_derivation"))
    }
}

fn normalization_unavailable(operation: &'static str) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::EncoderUnavailable,
        "video normalization is outside the Ubuntu local-import milestone",
    )
    .with_retryable(false)
    .with_detail("operation", json!(operation))
    .with_detail("capability", json!("video_normalization"))
    .with_detail("platform", json!("ubuntu"))
}
