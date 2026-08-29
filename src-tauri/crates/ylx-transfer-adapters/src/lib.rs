//! Production adapters for Device API networking, storage, credentials,
//! removable media, and publication authenticity:
//!
//! - `pi_http` (PC-03): real Device API client. Current RDK X5 lab/internal
//!   devices use HTTP `/api/v4` on port 8080; retained legacy v1 devices use
//!   HTTPS `/api/v1` with a fingerprint-pinned `rustls` `ClientConfig`. See
//!   that module's doc comment for the transport profiles and error mapping.
//! - `discovery_mdns` (PC-03): real `mdns-sd`-backed browser for
//!   `_ylx-capture._tcp.local.` candidates — discovery-only, never a trust
//!   anchor (ADR-DISC-001); see that module's doc comment for scope.
//! - `object_store_s3`: real S3-compatible multipart-upload
//!   adapter (`rusty-s3` + `ureq`).
//! - `credential_keyring`: real OS keyring adapter
//!   (`keyring`).
//! - `pi_client_port` (PC-02): direct pairing, authenticated-device,
//!   session-catalog, and download capability implementations for the real
//!   `pi_http::PiHttpClient`, so core can drive a real network client without
//!   reversing the dependency direction.
//! - `pi_download_source` (PC-05): thin `ylx_transfer_core::library::
//!   download::DownloadSource` impl for the real `pi_http::PiHttpClient`
//!   (wraps `get_file`/`head_file`), so PC-05's `TransferCoordinator` can
//!   drive real downloads without this crate's core dependency direction
//!   reversing — same rationale as `pi_client_port`, one layer down. See
//!   that module's doc comment for the full crate-boundary explanation.
//! - `publication_verifier`: fail-closed Ed25519 verification with `ring`,
//!   plus signed session-detail/schema/inventory checks bound to the
//!   authenticated publication key identity returned by `GET /device`.
//!
//! Both PC-03 modules are directly unit-testable on their own; `pi_http`
//! is additionally integration-tested against the real Pi daemon (see
//! `tests/pi_http_integration.rs`).

pub mod credential_keyring;
pub mod derived_upload;
pub mod discovery_mdns;
pub mod media_normalizer;
pub mod mounted_file;
pub mod object_store_s3;
pub mod pi_client_port;
pub mod pi_download_source;
pub mod pi_http;
pub mod publication_verifier;
pub mod removable_media;
pub mod session_export;

#[cfg(test)]
mod publication_verifier_contract_tests {
    use ylx_transfer_core::library::download::PublicationVerifier;

    use crate::publication_verifier::Ed25519PublicationVerifier;

    fn decode_hex(value: &str) -> Vec<u8> {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len() / 2);
        for index in (0..bytes.len()).step_by(2) {
            let high = (bytes[index] as char).to_digit(16).expect("hex") as u8;
            let low = (bytes[index + 1] as char).to_digit(16).expect("hex") as u8;
            decoded.push((high << 4) | low);
        }
        decoded
    }

    #[test]
    fn ed25519_verifier_accepts_rfc8032_vector_and_rejects_tampering_or_empty_key() {
        // RFC 8032 section 7.1, TEST 1: signature over the empty message.
        let public_key =
            decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = decode_hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ));
        let verifier = Ed25519PublicationVerifier;

        verifier
            .verify(b"", &signature, &public_key)
            .expect("the published RFC 8032 vector verifies");
        assert!(verifier
            .verify(b"tampered", &signature, &public_key)
            .is_err());
        assert!(verifier.verify(b"", &signature, &[]).is_err());
        assert!(verifier.verify(b"", &[], &public_key).is_err());
        assert!(verifier.verify(b"", &signature[..63], &public_key).is_err());
    }
}
