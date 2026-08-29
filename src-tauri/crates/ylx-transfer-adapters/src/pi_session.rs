//! Session-bound Pi capability façade.
//!
//! [`PiHttpClient`] directly implements the core capability ports. This
//! façade additionally binds one immutable [`AuthenticatedPiSession`] to an
//! `Arc<PiHttpClient>` so application callers do not have to pass the same
//! session on every authenticated/catalog/download call.

use std::sync::Arc;

use ylx_transfer_core::device::actor::{
    AuthenticatedDevicePort, AuthenticatedPiSession, ByteRangeRequest, DeleteSessionReceiptView,
    DeviceInfoView, DownloadTransportPort, FileDownloadView, FileHeadView, FileStreamView,
    GatewayVerificationView, HeartbeatOutcomeView, PairingCreatedView, PairingPort,
    PairingStatusView, PiClientError, SessionCatalogPort, SessionDetailView, SessionsPageView,
};

use crate::pi_http::{PiHttpClient, PiHttpError, RangeRequest};

fn session_error(message: impl Into<String>) -> PiClientError {
    PiClientError {
        kind: ylx_transfer_core::device::PiClientErrorKind::Other,
        message: message.into(),
    }
}

fn to_range_request(range: ByteRangeRequest) -> RangeRequest {
    match range {
        ByteRangeRequest::From { start } => RangeRequest::From { start },
        ByteRangeRequest::Bounded { start, end } => RangeRequest::Bounded { start, end },
        ByteRangeRequest::Suffix { length } => RangeRequest::Suffix { length },
    }
}

/// Pairing-only adapter capability.  Pairing has no authenticated session,
/// so it intentionally owns only the two unauthenticated endpoints.
#[derive(Clone)]
pub struct PiPairingClient {
    client: Arc<PiHttpClient>,
}

impl PiPairingClient {
    #[must_use]
    pub fn new(client: Arc<PiHttpClient>) -> Self {
        Self { client }
    }

    /// Cancel an outstanding pairing attempt. Cancellation remains part of
    /// the pairing capability, but the wire DTO and endpoint stay inside the
    /// adapter rather than becoming a public `PiHttpClient` method.
    pub fn cancel_pairing(&self, attempt_id: &str, poll_secret: &str) -> Result<(), PiClientError> {
        self.client
            .cancel_pairing_request(attempt_id, poll_secret)
            .map_err(|error| PiClientError {
                kind: ylx_transfer_core::device::PiClientErrorKind::Other,
                message: error.to_string(),
            })
    }
}

impl PairingPort for PiPairingClient {
    fn create_pairing_request(
        &self,
        client_name: &str,
        client_nonce: &str,
    ) -> Result<PairingCreatedView, PiClientError> {
        PairingPort::create_pairing_request(self.client.as_ref(), client_name, client_nonce)
    }

    fn get_pairing_status(
        &self,
        attempt_id: &str,
        poll_secret: &str,
    ) -> Result<PairingStatusView, PiClientError> {
        PairingPort::get_pairing_status(self.client.as_ref(), attempt_id, poll_secret)
    }
}

/// Authenticated, session-bound Pi adapter.
///
/// The wrapper checks that its transport was built for the same TLS identity
/// as the session before delegating to `PiHttpClient`'s direct capability
/// implementations.
#[derive(Clone)]
pub struct AuthenticatedPiClient {
    client: Arc<PiHttpClient>,
    session: AuthenticatedPiSession,
}

impl AuthenticatedPiClient {
    /// Bind one immutable session to one pinned transport.
    pub fn new(
        client: Arc<PiHttpClient>,
        session: AuthenticatedPiSession,
    ) -> Result<Self, PiClientError> {
        if !client.accepts_session_tls_pin(session.tls_pin()) {
            return Err(session_error(
                "authenticated Pi session TLS pin does not match the transport",
            ));
        }
        Ok(Self { client, session })
    }

    #[must_use]
    pub fn session(&self) -> &AuthenticatedPiSession {
        &self.session
    }

    /// Return a new façade after binding the first authenticated `/device`
    /// publication identity for a legacy transcript-less pairing. Once the
    /// session already has a key, core only accepts the same value.
    pub fn bind_publication_key(&self, observed: impl Into<String>) -> Result<Self, PiClientError> {
        let session = self
            .session
            .bind_publication_key(observed)
            .map_err(PiClientError::from)?;
        Self::new(self.client.clone(), session)
    }

    fn check_session(&self, session: &AuthenticatedPiSession) -> Result<(), PiClientError> {
        if session.epoch() != self.session.epoch() {
            return Err(session_error(
                "authenticated Pi session epoch does not match this transport",
            ));
        }
        if session.tls_pin() != self.session.tls_pin()
            || !self.client.accepts_session_tls_pin(session.tls_pin())
        {
            return Err(session_error(
                "authenticated Pi session TLS pin does not match the transport",
            ));
        }
        // `AuthenticatedPiSession`'s equality includes the redacted token
        // and SAS-confirmed publication identity.  Requiring the complete
        // value here prevents a caller from reusing this wrapper with a
        // different bearer token or a different key under the same epoch.
        if session != &self.session {
            return Err(session_error(
                "authenticated Pi session identity does not match this transport",
            ));
        }
        Ok(())
    }

    /// Adapter-local typed streaming response used by `PiDownloadSource`.
    /// It retains `PiHttpError` so that HTTP 412/416 remain distinguishable
    /// for the resumable-download state machine.
    pub(crate) fn get_file_stream_raw(
        &self,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<crate::pi_http::FileStreamResponse, PiHttpError> {
        self.session.with_authenticated_token(|token| {
            self.client.get_file_stream(
                token,
                &ylx_transfer_core::domain::SessionId(session_id.to_string()),
                &ylx_transfer_core::domain::FileId(file_id.to_string()),
                if_match,
                range.map(to_range_request),
            )
        })
    }

    pub fn heartbeat(&self) -> Result<HeartbeatOutcomeView, PiClientError> {
        <Self as AuthenticatedDevicePort>::heartbeat(self, &self.session)
    }

    pub fn revoke_session(&self) -> Result<(), PiClientError> {
        <Self as AuthenticatedDevicePort>::revoke_session(self, &self.session)
    }

    pub fn get_device(&self) -> Result<DeviceInfoView, PiClientError> {
        <Self as AuthenticatedDevicePort>::get_device(self, &self.session)
    }

    pub fn negotiate_device(&self) -> Result<DeviceInfoView, PiClientError> {
        <Self as AuthenticatedDevicePort>::negotiate_device(self, &self.session)
    }

    pub fn list_sessions(
        &self,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError> {
        <Self as SessionCatalogPort>::list_sessions(self, &self.session, cursor, limit)
    }

    pub fn get_session(&self, session_id: &str) -> Result<SessionDetailView, PiClientError> {
        <Self as SessionCatalogPort>::get_session(self, &self.session, session_id)
    }

    pub fn get_verified_session(
        &self,
        session_id: &str,
        verification: &GatewayVerificationView,
    ) -> Result<SessionDetailView, PiClientError> {
        <Self as SessionCatalogPort>::get_verified_session(
            self,
            &self.session,
            session_id,
            verification,
        )
    }

    pub fn delete_session(
        &self,
        session_id: &str,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> Result<DeleteSessionReceiptView, PiClientError> {
        <Self as SessionCatalogPort>::delete_session(
            self,
            &self.session,
            session_id,
            if_match_revision,
            idempotency_key,
        )
    }

    pub fn get_file(
        &self,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileDownloadView, PiClientError> {
        <Self as DownloadTransportPort>::get_file(
            self,
            &self.session,
            session_id,
            file_id,
            if_match,
            range,
        )
    }

    pub fn head_file(
        &self,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
    ) -> Result<FileHeadView, PiClientError> {
        <Self as DownloadTransportPort>::head_file(
            self,
            &self.session,
            session_id,
            file_id,
            if_match,
        )
    }
}

impl AuthenticatedDevicePort for AuthenticatedPiClient {
    fn heartbeat(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<HeartbeatOutcomeView, PiClientError> {
        self.check_session(session)?;
        AuthenticatedDevicePort::heartbeat(self.client.as_ref(), session)
    }

    fn revoke_session(&self, session: &AuthenticatedPiSession) -> Result<(), PiClientError> {
        self.check_session(session)?;
        AuthenticatedDevicePort::revoke_session(self.client.as_ref(), session)
    }

    fn get_device(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<DeviceInfoView, PiClientError> {
        self.check_session(session)?;
        AuthenticatedDevicePort::get_device(self.client.as_ref(), session)
    }

    fn negotiate_device(
        &self,
        session: &AuthenticatedPiSession,
    ) -> Result<DeviceInfoView, PiClientError> {
        self.check_session(session)?;
        AuthenticatedDevicePort::negotiate_device(self.client.as_ref(), session)
    }
}

impl SessionCatalogPort for AuthenticatedPiClient {
    fn list_sessions(
        &self,
        session: &AuthenticatedPiSession,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SessionsPageView, PiClientError> {
        self.check_session(session)?;
        SessionCatalogPort::list_sessions(self.client.as_ref(), session, cursor, limit)
    }

    fn get_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
    ) -> Result<SessionDetailView, PiClientError> {
        self.check_session(session)?;
        SessionCatalogPort::get_session(self.client.as_ref(), session, session_id)
    }

    fn get_verified_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        verification: &GatewayVerificationView,
    ) -> Result<SessionDetailView, PiClientError> {
        self.check_session(session)?;
        SessionCatalogPort::get_verified_session(
            self.client.as_ref(),
            session,
            session_id,
            verification,
        )
    }

    fn delete_session(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        if_match_revision: &str,
        idempotency_key: &str,
    ) -> Result<DeleteSessionReceiptView, PiClientError> {
        self.check_session(session)?;
        SessionCatalogPort::delete_session(
            self.client.as_ref(),
            session,
            session_id,
            if_match_revision,
            idempotency_key,
        )
    }
}

impl DownloadTransportPort for AuthenticatedPiClient {
    fn get_file(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileDownloadView, PiClientError> {
        self.check_session(session)?;
        DownloadTransportPort::get_file(
            self.client.as_ref(),
            session,
            session_id,
            file_id,
            if_match,
            range,
        )
    }

    fn head_file(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
    ) -> Result<FileHeadView, PiClientError> {
        self.check_session(session)?;
        DownloadTransportPort::head_file(
            self.client.as_ref(),
            session,
            session_id,
            file_id,
            if_match,
        )
    }

    fn get_file_stream(
        &self,
        session: &AuthenticatedPiSession,
        session_id: &str,
        file_id: &str,
        if_match: Option<&str>,
        range: Option<ByteRangeRequest>,
    ) -> Result<FileStreamView, PiClientError> {
        self.check_session(session)?;
        DownloadTransportPort::get_file_stream(
            self.client.as_ref(),
            session,
            session_id,
            file_id,
            if_match,
            range,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn session(tls_pin: &str, epoch: u64) -> AuthenticatedPiSession {
        AuthenticatedPiSession::new("token", tls_pin, None, epoch).expect("valid session")
    }

    #[test]
    fn pairing_client_is_a_pairing_only_capability() {
        let client = Arc::new(PiHttpClient::new_insecure_for_test(
            "http://127.0.0.1:1/api/v1".to_string(),
            Duration::from_secs(1),
        ));
        let pairing = PiPairingClient::new(client);
        let _: &dyn PairingPort = &pairing;
    }

    #[test]
    fn authenticated_client_rejects_a_transport_with_a_different_pin() {
        let client = Arc::new(PiHttpClient::new_insecure_for_test(
            "http://127.0.0.1:1/api/v1".to_string(),
            Duration::from_secs(1),
        ));
        let result =
            AuthenticatedPiClient::new(client, session(&format!("sha256:{}", "a".repeat(64)), 1));
        assert!(result.is_ok(), "insecure test transport accepts a test pin");
    }

    #[test]
    fn authenticated_client_rejects_a_stale_epoch_argument() {
        let client = Arc::new(PiHttpClient::new_insecure_for_test(
            "http://127.0.0.1:1/api/v1".to_string(),
            Duration::from_secs(1),
        ));
        let bound =
            AuthenticatedPiClient::new(client, session(&format!("sha256:{}", "a".repeat(64)), 1))
                .expect("wrapper builds");
        let stale = session(&format!("sha256:{}", "a".repeat(64)), 2);
        let error = <AuthenticatedPiClient as AuthenticatedDevicePort>::heartbeat(&bound, &stale)
            .expect_err("stale epoch must be fenced");
        assert!(error.message.contains("epoch"));
    }
}
