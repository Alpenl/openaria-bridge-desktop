//! Production trusted-producer registry backed by `MediaStore`.
//!
//! Admission asks one question — "is this exact fingerprint currently trusted
//! on this PC?" — and gets back either a confirmation receipt or nothing. The
//! caller never learns which table answered, cannot enumerate trust, and
//! cannot write trust: confirmations are made only by the pairing flow, which
//! holds the store directly.

use std::sync::{Arc, Mutex};

use ylx_transfer_core::media_store::{
    MediaStore, TrustedInlinePublicationKey, TrustedProducerError, TrustedProducerKeyReceipt,
    TrustedProducerRegistry,
};

use crate::composition::Composition;

use super::ports::{MediaErrorCode, MediaPortError, MediaTrustPort};
use super::types::MediaTrustedProducerRevocation;

/// `MediaStore`-backed implementation of the core registry seam.
pub struct MediaStoreTrustedProducerRegistry {
    media_store: Arc<Mutex<MediaStore>>,
}

impl MediaStoreTrustedProducerRegistry {
    #[must_use]
    pub fn new(media_store: Arc<Mutex<MediaStore>>) -> Arc<Self> {
        Arc::new(Self { media_store })
    }
}

impl TrustedProducerRegistry for MediaStoreTrustedProducerRegistry {
    fn resolve_active(
        &self,
        fingerprint: &str,
    ) -> Result<Option<TrustedProducerKeyReceipt>, TrustedProducerError> {
        self.media_store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_trusted_producer_key(fingerprint)
    }

    fn resolve_inline_active(
        &self,
        external_device_identity: &str,
        key_version: u64,
    ) -> Result<Option<TrustedInlinePublicationKey>, TrustedProducerError> {
        self.media_store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .active_inline_publication_key(
                external_device_identity,
                key_version,
                &chrono::Utc::now().to_rfc3339(),
            )
    }
}

/// Application-facing trust writer. It accepts only an exact public-key
/// fingerprint, resolves the owning producer through the existing narrow read
/// seam, and then delegates the audited identity-based revoke to Composition.
pub struct CompositionMediaTrustPort {
    composition: Arc<Composition>,
}

impl CompositionMediaTrustPort {
    #[must_use]
    pub fn new(composition: Arc<Composition>) -> Arc<Self> {
        Arc::new(Self { composition })
    }
}

impl MediaTrustPort for CompositionMediaTrustPort {
    fn revoke_trusted_producer(
        &self,
        key_fingerprint: &str,
    ) -> Result<MediaTrustedProducerRevocation, MediaPortError> {
        ylx_transfer_core::media_store::validate_producer_key_fingerprint(key_fingerprint)
            .map_err(map_trust_error)?;
        let active = self
            .composition
            .media_store()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_trusted_producer_key(key_fingerprint)
            .map_err(map_trust_error)?;
        let Some(active) = active else {
            return Ok(MediaTrustedProducerRevocation {
                key_fingerprint: key_fingerprint.to_string(),
                revoked: false,
            });
        };
        let revoked_at = chrono::Utc::now().to_rfc3339();
        let revoked = self
            .composition
            .revoke_trusted_producer_key(active.producer_identity(), &revoked_at)
            .map_err(map_trust_error)?;
        if revoked.is_none() {
            return Err(MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "trusted producer changed before revocation completed",
            )
            .with_retryable(true));
        }
        Ok(MediaTrustedProducerRevocation {
            key_fingerprint: key_fingerprint.to_string(),
            revoked: true,
        })
    }
}

fn map_trust_error(error: TrustedProducerError) -> MediaPortError {
    match error {
        TrustedProducerError::MalformedFingerprint { .. }
        | TrustedProducerError::MalformedIdentity { .. } => MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "trusted producer identity is malformed",
        )
        .with_retryable(false),
        TrustedProducerError::Unavailable(_) => MediaPortError::new(
            MediaErrorCode::OperationConflict,
            "trusted producer registry is temporarily unavailable",
        )
        .with_retryable(true),
    }
}
