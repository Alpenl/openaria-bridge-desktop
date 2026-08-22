//! Core capability-port implementations for the real [`PiHttpClient`].
//!
//! Pairing is deliberately unauthenticated. Every other capability accepts
//! an `AuthenticatedPiSession`, verifies that its TLS pin belongs to this
//! transport, and borrows its bearer token for exactly one wire call. The
//! catalog mapping also verifies signed publication data against the
//! session-bound publication identity.

/// Session-bound convenience façades live next to the direct capability
/// implementations so existing callers retain one adapter entry point.
/// Keeping this as a child module also preserves the public import path.
///
/// The authenticated façade binds the core
/// `ylx_transfer_core::device::actor::AuthenticatedPiSession`; raw bearer
/// endpoints and wire DTOs remain private to this adapter crate.
#[path = "pi_session.rs"]
pub mod session;
pub use session::{AuthenticatedPiClient, PiPairingClient};

use ylx_transfer_core::device::{
    AuthenticatedDevicePort, AuthenticatedPiSession, ByteRangeRequest, DeleteSessionReceiptView,
    DeviceInfoView, DownloadTransportPort, FileDownloadView, FileHeadView, FileStreamView,
    HeartbeatOutcomeView, PairingCreatedView, PairingPort, PairingStatusView, PiClientError,
    PiClientErrorKind, SessionCatalogPort, SessionDetailView, SessionFileEntryView,
    SessionSummaryView, SessionsPageView,
};
use ylx_transfer_core::domain::{FileId, SessionId};

use crate::pi_http::{
    ApiError, PiApiErrorCode, PiHttpClient, PiHttpError, RangeRequest, SessionDetail,
    SessionFileEntry, SessionSummary,
};
use crate::publication_verifier::validate_session_detail_publication;

fn map_error(err: PiHttpError) -> PiClientError {
    let kind = match &err {
        PiHttpError::Api(ApiError {
            code: PiApiErrorCode::Unauthorized,
            ..
        }) => PiClientErrorKind::Unauthorized,
        PiHttpError::Network(msg)
            if msg.to_lowercase().contains("timed out")
                || msg.to_lowercase().contains("timeout") =>
        {
            PiClientErrorKind::Timeout
        }
        _ => PiClientErrorKind::Other,
    };
    PiClientError {
        kind,
        message: err.to_string(),
    }
}

fn to_range_request(range: ByteRangeRequest) -> RangeRequest {
    match range {
        ByteRangeRequest::From { start } => RangeRequest::From { start },
        ByteRangeRequest::Bounded { start, end } => RangeRequest::Bounded { start, end },
        ByteRangeRequest::Suffix { length } => RangeRequest::Suffix { length },
    }
}

fn to_session_summary_view(s: SessionSummary) -> SessionSummaryView {
    SessionSummaryView {
        session_id: s.session_id.as_str().to_string(),
        revision: s.revision,
        captured_at: s.captured_at,
        published_at: s.published_at,
        duration_seconds: s.duration_seconds,
        total_bytes: s.total_bytes,
        video_bytes: s.video_bytes,
        file_count: s.file_count,
    }
}

fn to_session_file_entry_view(f: SessionFileEntry) -> SessionFileEntryView {
    SessionFileEntryView {
        id: f.id,
        display_path: f.display_path,
        role: f.role,
        size_bytes: f.size_bytes,
        sha256: f.sha256,
        media_type: f.media_type,
    }
}

fn verification_error(error: impl std::fmt::Display) -> PiClientError {
    PiClientError {
        kind: PiClientErrorKind::Other,
        message: format!("publication verification failed: {error}"),
    }
}

fn validate_session_transport(
    client: &PiHttpClient,
    session: &AuthenticatedPiSession,
) -> Result<(), PiClientError> {
    if client.accepts_session_tls_pin(session.tls_pin()) {
        Ok(())
    } else {
        Err(PiClientError {
            kind: PiClientErrorKind::Other,
            message: "authenticated Pi session TLS pin does not match the transport".to_string(),
        })
    }
}

fn required_publication_key(session: &AuthenticatedPiSession) -> Result<&str, PiClientError> {
    session
        .publication_key_fingerprint()
        .ok_or_else(|| PiClientError {
            kind: PiClientErrorKind::Other,
            message: "authenticated Pi session has no SAS-confirmed publication key".to_string(),
        })
}

fn to_session_detail_view(
    d: SessionDetail,
    requested_session_id: &str,
    expected_publication_key_fingerprint: &str,
) -> Result<SessionDetailView, PiClientError> {
    let publication = validate_session_detail_publication(
        &d,
        requested_session_id,
        expected_publication_key_fingerprint,
    )
    .map_err(verification_error)?;
    Ok(SessionDetailView {
        session_id: d.session_id.as_str().to_string(),
        revision: d.revision,
        captured_at: d.captured_at,
        published_at: d.published_at,
        duration_seconds: d.duration_seconds,
        total_bytes: d.total_bytes,
        video_bytes: d.video_bytes,
        file_count: d.file_count,
        files: d
            .files
            .into_iter()
            .map(to_session_file_entry_view)
            .collect(),
        publication_payload: publication.payload,
        publication_signature: publication.signature,
        publication_public_key: publication.public_key,
        publication_key_fingerprint: publication.key_fingerprint,
    })
}

impl PairingPort for PiHttpClient {
    fn create_pairing_request(
        &self,
        client_name: &str,
        client_nonce: &str,
    ) -> Result<PairingCreatedView, PiClientError> {
        self.create_pairing_request(client_name, client_nonce)
            .map(|c| PairingCreatedView {
                attempt_id: c.attempt_id,
                phase: c.phase,
                poll_secret: c.poll_secret,
                sas: c.sas,
                expires_at: c.expires_at,
                // The transcript this SAS was independently derived from
                // (already validated by `PiHttpClient`) names exactly one
                // publication key -- that is the identity the user's
                // confirmation covers, so it has to reach the actor.
                sas_publication_key_fingerprint: c
                    .sas_transcript
                    .map(|transcript| transcript.publication_key_fingerprint),
            })
            .map_err(map_error)
    }

    fn get_pairing_status(
        &self,
        attempt_id: &str,
        poll_secret: &str,
    ) -> Result<PairingStatusView, PiClientError> {
        self.get_pairing_status(attempt_id, poll_secret)
            .map(|s| PairingStatusView {
                attempt_id: s.attempt_id,
                phase: s.phase,
                connection_token: s.connection_token,
                sas: s.sas,
                expires_at: s.expires_at,
                sas_publication_key_fingerprint: s
                    .sas_transcript
                    .map(|transcript| transcript.publication_key_fingerprint),
            })
            .map_err(map_error)
    }
}

impl AuthenticatedDevicePort for PiHttpClient {
    fn heartbeat(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<HeartbeatOutcomeView, PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| PiHttpClient::heartbeat(self, token))
            .map(|h| HeartbeatOutcomeView {
                idle_timeout_ms: h.idle_timeout_ms,
                absolute_expires_at: h.absolute_expires_at,
            })
            .map_err(map_error)
    }

    fn revoke_session(&self, session: &AuthenticatedPiSession) -> Result<(), PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| PiHttpClient::revoke_session(self, token))
            .map_err(map_error)
    }

    fn get_device(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<DeviceInfoView, PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| PiHttpClient::get_device(self, token))
            .map_err(map_error)
            .and_then(|d| {
                session
                    .ensure_publication_key(&d.publication_key_fingerprint)
                    .map_err(verification_error)?;
                Ok(DeviceInfoView {
                    capture_activity: d.capture_activity,
                    media_admission: d.media_admission,
                    publication_key_fingerprint: d.publication_key_fingerprint,
                })
            })
    }
}

impl SessionCatalogPort for PiHttpClient {
    fn list_sessions(
        &self,
        session: &AuthenticatedPiSession,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| {
                PiHttpClient::list_sessions(self, token, cursor, limit)
            })
            .map(|p| SessionsPageView {
                catalog_revision: p.catalog_revision,
                sessions: p
                    .sessions
                    .into_iter()
                    .map(to_session_summary_view)
                    .collect(),
                next_cursor: p.next_cursor,
            })
            .map_err(map_error)
    }

    fn get_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
    ) -> Result<SessionDetailView, PiClientError> {
        validate_session_transport(self, session)?;
        let expected_publication_key_fingerprint = required_publication_key(session)?;
        session
            .with_authenticated_token(|token| {
                PiHttpClient::get_session(self, token, &SessionId(session_id.to_string()))
            })
            .map_err(map_error)
            .and_then(|detail| {
                to_session_detail_view(detail, session_id, expected_publication_key_fingerprint)
            })
    }

    fn delete_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> Result<DeleteSessionReceiptView, PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| {
                PiHttpClient::delete_session(
                    self,
                    token,
                    &SessionId(session_id.to_string()),
                    if_match_revision,
                    idempotency_key,
                )
            })
            .map(|r| DeleteSessionReceiptView {
                session_id: r.session_id,
                revision: r.revision,
                deleted_at: r.deleted_at,
            })
            .map_err(map_error)
    }
}

impl DownloadTransportPort for PiHttpClient {
    fn get_file(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileDownloadView, PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| {
                PiHttpClient::get_file(
                    self,
                    token,
                    &SessionId(session_id.to_string()),
                    &FileId(file_id.to_string()),
                    if_match,
                    range.map(to_range_request),
                )
            })
            .map(|r| FileDownloadView {
                status: r.status,
                etag: r.etag,
                media_type: r.media_type,
                content_length: r.content_length,
                content_range: r.content_range.map(|cr| (cr.start, cr.end, cr.total_size)),
                body: r.body,
            })
            .map_err(map_error)
    }

    fn head_file(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
    ) -> Result<FileHeadView, PiClientError> {
        validate_session_transport(self, session)?;
        session
            .with_authenticated_token(|token| {
                PiHttpClient::head_file(
                    self,
                    token,
                    &SessionId(session_id.to_string()),
                    &FileId(file_id.to_string()),
                    if_match,
                )
            })
            .map(|r| FileHeadView {
                etag: r.etag,
                media_type: r.media_type,
                content_length: r.content_length,
            })
            .map_err(map_error)
    }

    fn get_file_stream(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileStreamView, PiClientError> {
        validate_session_transport(self, session)?;
        let response = session
            .with_authenticated_token(|token| {
                PiHttpClient::get_file_stream(
                    self,
                    token,
                    &SessionId(session_id.to_string()),
                    &FileId(file_id.to_string()),
                    if_match,
                    range.map(to_range_request),
                )
            })
            .map_err(map_error)?;
        Ok(FileStreamView {
            status: response.status,
            etag: response.etag,
            media_type: response.media_type,
            content_length: response.content_length,
            content_range: response
                .content_range
                .map(|range| (range.start, range.end, range.total_size)),
            body: response.body,
        })
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use tiny_http::{Response as TinyResponse, Server};
    use ylx_transfer_core::publication::canonicalize_rp_manifest;

    use super::*;

    fn authenticated_session(
        publication_key_fingerprint: Option<String>,
    ) -> AuthenticatedPiSession {
        AuthenticatedPiSession::new(
            "token",
            "test-insecure-transport",
            publication_key_fingerprint,
            1,
        )
        .expect("valid authenticated test session")
    }

    fn signed_session_detail_body() -> (String, Vec<u8>, Vec<u8>, String) {
        let files = serde_json::json!([
            {
                "id": "f-0001",
                "display_path": "video/left_00000.mp4",
                "role": "video_left",
                "size_bytes": 100,
                "sha256": "b".repeat(64),
                "media_type": "video/mp4",
            },
            {
                "id": "f-0002",
                "display_path": "imu/imu_00000.csv",
                "role": "imu",
                "size_bytes": 20,
                "sha256": "c".repeat(64),
                "media_type": "text/csv",
            },
        ]);
        let mut payload = serde_json::json!({
            "schema_version": 1,
            "session_id": "sess-1",
            "revision": "",
            "captured_at": "2026-08-01T00:00:00Z",
            "published_at": "2026-08-01T00:01:00Z",
            "duration_seconds": 12.5,
            "total_bytes": 120,
            "video_bytes": 100,
            "integrity_ok": true,
            "files": files.clone(),
        });
        refresh_payload_revision(&mut payload);
        let revision = payload["revision"].clone();
        let payload = payload.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).expect("valid test seed");
        let public_key = key_pair.public_key().as_ref().to_vec();
        let signature = key_pair.sign(payload.as_bytes()).as_ref().to_vec();
        let fingerprint = format!("sha256:{:x}", Sha256::digest(&public_key));
        let body = serde_json::json!({
            "session_id": "sess-1",
            "revision": revision,
            "captured_at": "2026-08-01T00:00:00Z",
            "published_at": "2026-08-01T00:01:00Z",
            "duration_seconds": 12.5,
            "total_bytes": 120,
            "video_bytes": 100,
            "file_count": 2,
            "files": files,
            "publication_payload": payload,
            "publication_signature": signature.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "publication_public_key": public_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "publication_key_fingerprint": fingerprint,
        })
        .to_string();
        (body, public_key, signature, fingerprint)
    }

    fn get_session_from_body(
        body: String,
        requested_session_id: &str,
        expected_fingerprint: &str,
    ) -> Result<SessionDetailView, PiClientError> {
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let port = server
            .server_addr()
            .to_ip()
            .expect("loopback server has an IP addr")
            .port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");
        let handle = std::thread::spawn(move || {
            let request = server.recv().expect("received a request");
            request
                .respond(TinyResponse::from_string(body).with_status_code(200))
                .expect("respond to the captured request");
        });
        let client = PiHttpClient::new_insecure_for_test(base_url, Duration::from_secs(5));
        let session = authenticated_session(Some(expected_fingerprint.to_string()));
        let result = SessionCatalogPort::get_session(&client, &session, requested_session_id);
        handle.join().expect("fake server thread exits cleanly");
        result
    }

    fn resign_payload(body: &mut serde_json::Value) {
        let payload = body["publication_payload"]
            .as_str()
            .expect("fixture has a payload");
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).expect("valid test seed");
        body["publication_signature"] = serde_json::Value::String(
            key_pair
                .sign(payload.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
    }

    fn refresh_payload_revision(payload: &mut serde_json::Value) {
        let revision_manifest = serde_json::json!({
            "schema_version": payload["schema_version"].clone(),
            "session_id": payload["session_id"].clone(),
            "captured_at": payload["captured_at"].clone(),
            "duration_seconds": payload["duration_seconds"].clone(),
            "total_bytes": payload["total_bytes"].clone(),
            "video_bytes": payload["video_bytes"].clone(),
            "integrity_ok": payload["integrity_ok"].clone(),
            "files": payload["files"].clone(),
            "publication_signature": null,
        });
        let canonical = canonicalize_rp_manifest(&revision_manifest)
            .expect("fixture revision material is canonicalizable");
        payload["revision"] =
            serde_json::Value::String(format!("sha256:{:x}", Sha256::digest(canonical)));
    }

    fn mutate_signed_payload(
        body: &mut serde_json::Value,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) {
        let mut payload: serde_json::Value = serde_json::from_str(
            body["publication_payload"]
                .as_str()
                .expect("fixture has a payload"),
        )
        .expect("fixture payload is JSON");
        mutate(&mut payload);
        refresh_payload_revision(&mut payload);
        body["revision"] = payload["revision"].clone();
        body["publication_payload"] = serde_json::Value::String(payload.to_string());
        resign_payload(body);
    }

    /// PC-03b: exercises the *whole* real path -- a real loopback HTTP
    /// server serving a `GET /sessions/{id}` body shaped exactly like the
    /// real Pi handler's response (same fixture shape as
    /// `pi_http.rs`'s own `get_session_parses_the_real_per_file_inventory`
    /// test), through `PiHttpClient::get_session`'s real JSON parsing
    /// *and* this file's direct `SessionCatalogPort for PiHttpClient` conversion
    /// -- proving the new `files[]` field survives both layers intact,
    /// not just one of them in isolation.
    #[test]
    fn get_session_via_catalog_port_delegates_and_carries_files_through() {
        let (body, expected_public_key, expected_signature, expected_fingerprint) =
            signed_session_detail_body();
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let addr = server.server_addr();
        let port = addr.to_ip().expect("loopback server has an IP addr").port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");

        let handle = std::thread::spawn(move || {
            let request = server.recv().expect("received a request");
            let response = TinyResponse::from_string(body).with_status_code(200);
            request
                .respond(response)
                .expect("respond to the captured request");
        });

        let client = PiHttpClient::new_insecure_for_test(base_url, Duration::from_secs(5));
        let session = authenticated_session(Some(expected_fingerprint));
        let port_client: &dyn SessionCatalogPort = &client;
        let detail = port_client
            .get_session(&session, "sess-1")
            .expect("get_session succeeds through the catalog capability");

        handle.join().expect("fake server thread exits cleanly");

        assert_eq!(detail.session_id, "sess-1");
        let signed_payload: serde_json::Value =
            serde_json::from_slice(&detail.publication_payload).expect("verified payload is JSON");
        assert_eq!(detail.revision, signed_payload["revision"]);
        assert_eq!(detail.file_count, 2);
        assert_eq!(detail.files.len(), 2);
        assert_eq!(detail.files[0].id, "f-0001");
        assert_eq!(detail.files[0].display_path, "video/left_00000.mp4");
        assert_eq!(detail.files[0].role, "video_left");
        assert_eq!(detail.files[0].size_bytes, 100);
        assert_eq!(detail.files[0].sha256, "b".repeat(64));
        assert_eq!(detail.files[0].media_type, "video/mp4");
        assert_eq!(detail.files[1].id, "f-0002");
        assert_eq!(detail.files[1].role, "imu");
        assert_eq!(detail.files[1].media_type, "text/csv");
        assert!(!detail.publication_payload.is_empty());
        assert_eq!(detail.publication_signature, expected_signature);
        assert_eq!(detail.publication_public_key, expected_public_key);
    }

    #[test]
    fn get_session_accepts_signed_video_stereo_as_a_schema_v1_video_role() {
        let (valid_body, _, _, expected_fingerprint) = signed_session_detail_body();
        let mut body: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        body["files"][0]["display_path"] = serde_json::json!("spool/source_00000.mp4");
        body["files"][0]["role"] = serde_json::json!("video_stereo");
        mutate_signed_payload(&mut body, |payload| {
            payload["files"][0]["display_path"] = serde_json::json!("spool/source_00000.mp4");
            payload["files"][0]["role"] = serde_json::json!("video_stereo");
        });

        let detail = get_session_from_body(body.to_string(), "sess-1", &expected_fingerprint)
            .expect("schema v1 accepts the Pi's stereo muxed video role");

        assert_eq!(detail.files[0].display_path, "spool/source_00000.mp4");
        assert_eq!(detail.files[0].role, "video_stereo");
    }

    #[test]
    fn get_session_rejects_every_publication_identity_and_payload_mismatch() {
        let (valid_body, _, _, expected_fingerprint) = signed_session_detail_body();

        for required_field in [
            "publication_payload",
            "publication_signature",
            "publication_public_key",
            "publication_key_fingerprint",
        ] {
            let mut missing: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
            missing
                .as_object_mut()
                .unwrap()
                .remove(required_field)
                .expect("fixture contains required field");
            let error = get_session_from_body(missing.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("missing publication envelope field must fail closed");
            assert!(
                error.message.contains(required_field),
                "error for {required_field} was {}",
                error.message
            );
        }

        let wrong_authenticated_fingerprint = format!("sha256:{}", "0".repeat(64));
        let error = get_session_from_body(
            valid_body.clone(),
            "sess-1",
            &wrong_authenticated_fingerprint,
        )
        .expect_err("detail fingerprint cannot authenticate itself");
        assert!(error.message.contains("authenticated /device identity"));

        let mut wrong_key: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        wrong_key["publication_public_key"] = serde_json::Value::String("00".repeat(32));
        let error = get_session_from_body(wrong_key.to_string(), "sess-1", &expected_fingerprint)
            .expect_err("public key must hash to the authenticated fingerprint");
        assert!(error.message.contains("public key hash"));

        let mut uppercase_signature: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        uppercase_signature["publication_signature"] = serde_json::Value::String(
            uppercase_signature["publication_signature"]
                .as_str()
                .unwrap()
                .to_uppercase(),
        );
        let error = get_session_from_body(
            uppercase_signature.to_string(),
            "sess-1",
            &expected_fingerprint,
        )
        .expect_err("wire signature must use the frozen lowercase encoding");
        assert!(error.message.contains("lowercase hex"));

        let mut tampered_signature: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        let mut signature = tampered_signature["publication_signature"]
            .as_str()
            .unwrap()
            .to_string();
        signature.replace_range(0..1, if signature.starts_with('0') { "1" } else { "0" });
        tampered_signature["publication_signature"] = serde_json::Value::String(signature);
        let error = get_session_from_body(
            tampered_signature.to_string(),
            "sess-1",
            &expected_fingerprint,
        )
        .expect_err("modified signature must fail closed");
        assert!(error.message.contains("invalid Ed25519"));

        let mut changed_inventory: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        changed_inventory["files"][0]["size_bytes"] = serde_json::json!(101);
        let error = get_session_from_body(
            changed_inventory.to_string(),
            "sess-1",
            &expected_fingerprint,
        )
        .expect_err("unsigned detail inventory cannot replace signed inventory");
        assert!(error.message.contains("file inventory"));

        let mut unknown_schema: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_str(unknown_schema["publication_payload"].as_str().unwrap()).unwrap();
        payload["schema_version"] = serde_json::json!(2);
        unknown_schema["publication_payload"] = serde_json::Value::String(payload.to_string());
        resign_payload(&mut unknown_schema);
        let error =
            get_session_from_body(unknown_schema.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("a valid signature does not make an unknown schema trustworthy");
        assert!(error
            .message
            .contains("unsupported publication schema_version 2"));
    }

    #[test]
    fn get_session_rejects_signed_but_semantically_invalid_publication_fields() {
        let (valid_body, _, _, expected_fingerprint) = signed_session_detail_body();

        let mut invalid_timestamp: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        invalid_timestamp["captured_at"] = serde_json::json!("not-rfc3339");
        mutate_signed_payload(&mut invalid_timestamp, |payload| {
            payload["captured_at"] = serde_json::json!("not-rfc3339");
        });
        let error = get_session_from_body(
            invalid_timestamp.to_string(),
            "sess-1",
            &expected_fingerprint,
        )
        .expect_err("a signed invalid timestamp must fail closed");
        assert!(error.message.contains("RFC3339"), "{}", error.message);

        let mut reversed_time: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        reversed_time["published_at"] = serde_json::json!("2025-07-31T23:59:59Z");
        mutate_signed_payload(&mut reversed_time, |payload| {
            payload["published_at"] = serde_json::json!("2025-07-31T23:59:59Z");
        });
        let error =
            get_session_from_body(reversed_time.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("publication cannot predate capture even when signed");
        assert!(error.message.contains("earlier"), "{}", error.message);

        let mut negative_duration: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        negative_duration["duration_seconds"] = serde_json::json!(-0.5);
        mutate_signed_payload(&mut negative_duration, |payload| {
            payload["duration_seconds"] = serde_json::json!(-0.5);
        });
        let error = get_session_from_body(
            negative_duration.to_string(),
            "sess-1",
            &expected_fingerprint,
        )
        .expect_err("negative signed duration must fail closed");
        assert!(
            error.message.contains("duration_seconds"),
            "{}",
            error.message
        );

        let mut empty_inventory: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        empty_inventory["files"] = serde_json::json!([]);
        empty_inventory["file_count"] = serde_json::json!(0);
        empty_inventory["total_bytes"] = serde_json::json!(0);
        empty_inventory["video_bytes"] = serde_json::json!(0);
        mutate_signed_payload(&mut empty_inventory, |payload| {
            payload["files"] = serde_json::json!([]);
            payload["total_bytes"] = serde_json::json!(0);
            payload["video_bytes"] = serde_json::json!(0);
        });
        let error =
            get_session_from_body(empty_inventory.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("schema v1 requires at least one signed file");
        assert!(
            error.message.contains("file inventory"),
            "{}",
            error.message
        );

        for invalid_path in [
            String::new(),
            "/absolute.mp4".to_string(),
            "video/../secret".to_string(),
            "video\\left.mp4".to_string(),
            ".hidden".to_string(),
            "é.mp4".to_string(),
            format!("a{}", "b".repeat(4096)),
        ] {
            let mut body: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
            body["files"][0]["display_path"] = serde_json::json!(invalid_path.clone());
            mutate_signed_payload(&mut body, |payload| {
                payload["files"][0]["display_path"] = serde_json::json!(invalid_path);
            });
            let error = get_session_from_body(body.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("signed display_path outside schema v1 must fail closed");
            assert!(error.message.contains("display_path"), "{}", error.message);
        }

        for invalid_media_type in [String::new(), "x".repeat(256)] {
            let mut body: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
            body["files"][0]["media_type"] = serde_json::json!(invalid_media_type.clone());
            mutate_signed_payload(&mut body, |payload| {
                payload["files"][0]["media_type"] = serde_json::json!(invalid_media_type);
            });
            let error = get_session_from_body(body.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("signed media_type outside schema v1 must fail closed");
            assert!(error.message.contains("media_type"), "{}", error.message);
        }

        let mut unknown_role: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        unknown_role["files"][0]["role"] = serde_json::json!("video_unknown");
        mutate_signed_payload(&mut unknown_role, |payload| {
            payload["files"][0]["role"] = serde_json::json!("video_unknown");
        });
        let error =
            get_session_from_body(unknown_role.to_string(), "sess-1", &expected_fingerprint)
                .expect_err("signed role outside schema v1 must fail closed");
        assert!(error.message.contains("file role"), "{}", error.message);
    }

    #[test]
    fn get_session_accepts_v1_string_boundaries_and_unknown_minor_extensions() {
        let (valid_body, _, _, expected_fingerprint) = signed_session_detail_body();
        let mut body: serde_json::Value = serde_json::from_str(&valid_body).unwrap();
        let max_display_path = format!("a{}", "b".repeat(4095));
        let max_media_type = "x".repeat(255);
        body["files"][0]["display_path"] = serde_json::json!(max_display_path.clone());
        body["files"][0]["media_type"] = serde_json::json!(max_media_type.clone());
        mutate_signed_payload(&mut body, |payload| {
            payload["files"][0]["display_path"] = serde_json::json!(max_display_path);
            payload["files"][0]["media_type"] = serde_json::json!(max_media_type);
            payload["files"][0]["future_file_field"] = serde_json::json!("ignored");
            payload["future_manifest_field"] = serde_json::json!({"value": 1});
        });

        let detail = get_session_from_body(body.to_string(), "sess-1", &expected_fingerprint)
            .expect("known-v1 unknown fields and exact schema boundaries remain compatible");
        assert_eq!(detail.files[0].display_path.len(), 4096);
        assert_eq!(detail.files[0].media_type.len(), 255);
    }

    fn serve_once(body: String) -> (PiHttpClient, std::thread::JoinHandle<()>) {
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let port = server.server_addr().to_ip().unwrap().port();
        let handle = std::thread::spawn(move || {
            let request = server.recv().expect("received a request");
            request
                .respond(TinyResponse::from_string(body).with_status_code(202))
                .expect("respond to the captured request");
        });
        (
            PiHttpClient::new_insecure_for_test(
                format!("http://127.0.0.1:{port}/api/v1"),
                Duration::from_secs(5),
            ),
            handle,
        )
    }

    /// The publication key identity the SAS transcript binds is what the
    /// user actually confirms out of band, so it has to survive the port
    /// mapping into `PairingCreatedView` -- otherwise the core actor has
    /// nothing to bind the resulting session to.
    #[test]
    fn create_pairing_request_carries_the_sas_confirmed_publication_key_identity() {
        let publication_key_fingerprint = format!("sha256:{}", "2".repeat(64));
        let body = serde_json::json!({
            "attempt_id": "attempt-0001",
            "phase": "pending",
            "poll_secret_configured": true,
            "poll_secret": "poll-secret",
            "expires_at": "2026-08-01T05:00:00Z",
            "sas": "123456",
            "sas_transcript": {
                "tls_cert_fingerprint": format!("sha256:{}", "1".repeat(64)),
                "publication_key_fingerprint": publication_key_fingerprint,
                "client_nonce": "nonce-1",
                "pi_nonce": "pi-nonce-1",
                "device_name": "YLX Pi",
                "protocol_version": "1.0",
                "request_digest": "a".repeat(64),
            },
        })
        .to_string();
        let (client, handle) = serve_once(body);

        let created = PairingPort::create_pairing_request(&client, "YLX Transfer PC", "nonce-1")
            .expect("pairing request succeeds");
        handle.join().expect("fake server exits");

        assert_eq!(created.attempt_id, "attempt-0001");
        assert_eq!(
            created.sas_publication_key_fingerprint,
            Some(publication_key_fingerprint)
        );
    }

    #[test]
    fn get_device_carries_authenticated_publication_key_identity() {
        let fingerprint = format!("sha256:{}", "a".repeat(64));
        let body = serde_json::json!({
            "protocol_major": 1,
            "protocol_minor": 0,
            "capabilities": [],
            "storage": {"free_bytes": 100, "total_bytes": 200},
            "capture_activity": "idle",
            "media_admission": "allowed",
            "publication_key_fingerprint": fingerprint,
        })
        .to_string();
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let port = server.server_addr().to_ip().unwrap().port();
        let handle = std::thread::spawn(move || {
            let request = server.recv().expect("received a request");
            request
                .respond(TinyResponse::from_string(body).with_status_code(200))
                .expect("respond to the captured request");
        });
        let client = PiHttpClient::new_insecure_for_test(
            format!("http://127.0.0.1:{port}/api/v1"),
            Duration::from_secs(5),
        );

        let session = authenticated_session(Some(format!("sha256:{}", "a".repeat(64))));
        let info = AuthenticatedDevicePort::get_device(&client, &session)
            .expect("valid identity accepted");
        handle.join().expect("fake server exits");

        assert_eq!(
            info.publication_key_fingerprint,
            format!("sha256:{}", "a".repeat(64))
        );
    }
}
