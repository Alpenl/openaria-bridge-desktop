//! Adapter-side publication boundary.
//!
//! The Pi response is untrusted wire input.  This module only translates
//! that input into core's [`ylx_transfer_core::publication::PublicationEnvelope`]
//! and invokes the one authoritative [`PublicationTrust`] verifier.  It does
//! not maintain a second schema or a second inventory/path validator.

use ring::signature::{UnparsedPublicKey, ED25519};
use ylx_transfer_core::library::download::{PublicationVerifier, VerifyError};
use ylx_transfer_core::publication::{
    ensure_publication_key_identity_matches as core_ensure_publication_key_identity_matches,
    validate_publication_key_fingerprint as core_validate_publication_key_fingerprint,
    PublicationEnvelope, PublicationFileClaim, PublicationTrust,
};

use crate::pi_http::{SessionDetail, SessionFileEntry};

/// Raw Ed25519 public keys are exactly 32 bytes and signatures exactly 64.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Production publication verifier backed by `ring` 0.17.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519PublicationVerifier;

impl PublicationVerifier for Ed25519PublicationVerifier {
    fn verify(
        &self,
        manifest_bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), VerifyError> {
        if public_key.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(VerifyError::Rejected(format!(
                "Ed25519 public key must be {ED25519_PUBLIC_KEY_LENGTH} bytes, got {}",
                public_key.len()
            )));
        }
        if signature.len() != ED25519_SIGNATURE_LENGTH {
            return Err(VerifyError::Rejected(format!(
                "Ed25519 signature must be {ED25519_SIGNATURE_LENGTH} bytes, got {}",
                signature.len()
            )));
        }

        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(manifest_bytes, signature)
            .map_err(|_| VerifyError::Rejected("invalid Ed25519 publication signature".to_string()))
    }
}

/// Publication material accepted by the core trust boundary.
///
/// This compatibility value is deliberately a byte-only projection.  The
/// signed inventory and scalar claims remain owned by core's private
/// `VerifiedPublication`; callers cannot use this type to rebuild a transfer
/// plan with a different file list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSessionPublication {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_fingerprint: String,
}

/// Validate the wire form used for publication-key identities.
pub fn validate_publication_key_fingerprint(value: &str) -> Result<(), VerifyError> {
    core_validate_publication_key_fingerprint(value).map_err(core_error)
}

/// Fail closed unless the response presents the SAS-confirmed key identity.
pub fn ensure_publication_key_identity_matches(
    expected: &str,
    observed: &str,
) -> Result<(), VerifyError> {
    core_ensure_publication_key_identity_matches(expected, observed).map_err(core_error)
}

fn core_error(error: impl std::fmt::Display) -> VerifyError {
    VerifyError::Rejected(error.to_string())
}

fn publication_envelope(detail: &SessionDetail) -> PublicationEnvelope {
    PublicationEnvelope {
        session_id: detail.session_id.as_str().to_string(),
        revision: detail.revision.clone(),
        captured_at: detail.captured_at.clone(),
        published_at: detail.published_at.clone(),
        duration_seconds: detail.duration_seconds,
        total_bytes: detail.total_bytes,
        video_bytes: detail.video_bytes,
        file_count: detail.file_count,
        files: detail.files.iter().map(publication_file_claim).collect(),
        publication_payload: detail.publication_payload.clone(),
        publication_signature_hex: detail.publication_signature.clone(),
        publication_public_key_hex: detail.publication_public_key.clone(),
        publication_key_fingerprint: detail.publication_key_fingerprint.clone(),
    }
}

fn publication_file_claim(file: &SessionFileEntry) -> PublicationFileClaim {
    PublicationFileClaim {
        id: file.id.clone(),
        display_path: file.display_path.clone(),
        role: file.role.clone(),
        size_bytes: file.size_bytes,
        sha256: file.sha256.clone(),
        media_type: file.media_type.clone(),
    }
}

/// Verify one session-detail response against the independently supplied
/// authenticated publication-key identity.
pub(crate) fn validate_session_detail_publication(
    detail: &SessionDetail,
    requested_session_id: &str,
    expected_publication_key_fingerprint: &str,
) -> Result<VerifiedSessionPublication, VerifyError> {
    let envelope = publication_envelope(detail);
    let verified = PublicationTrust::new(&Ed25519PublicationVerifier)
        .verify(
            &envelope,
            requested_session_id,
            expected_publication_key_fingerprint,
        )
        .map_err(core_error)?;

    Ok(VerifiedSessionPublication {
        payload: verified.payload().to_vec(),
        signature: verified.signature().to_vec(),
        public_key: verified.public_key().to_vec(),
        key_fingerprint: verified.key_fingerprint().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_publication_key_identity_is_accepted() {
        let identity = format!("sha256:{}", "a".repeat(64));
        assert!(ensure_publication_key_identity_matches(&identity, &identity).is_ok());
    }

    #[test]
    fn a_changed_publication_key_identity_is_rejected() {
        let confirmed = format!("sha256:{}", "a".repeat(64));
        let rotated = format!("sha256:{}", "b".repeat(64));
        let VerifyError::Rejected(message) =
            ensure_publication_key_identity_matches(&confirmed, &rotated)
                .expect_err("a rotated key must fail closed");
        assert!(message.contains("SAS-confirmed"), "{message}");
    }

    #[test]
    fn a_malformed_publication_key_identity_is_rejected_on_either_side() {
        let valid = format!("sha256:{}", "a".repeat(64));
        assert!(ensure_publication_key_identity_matches("not-a-fingerprint", &valid).is_err());
        assert!(ensure_publication_key_identity_matches(&valid, "sha256:XYZ").is_err());
    }
}
