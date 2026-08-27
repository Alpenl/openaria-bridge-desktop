//! Explicit live-Pi diagnostic for the current Device API v4 download path.
//!
//! This test is ignored by default because it requires a trusted-LAN Pi.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ylx_transfer_adapters::pi_client_port::session::{AuthenticatedPiClient, PiPairingClient};
use ylx_transfer_adapters::pi_download_source::PiDownloadSource;
use ylx_transfer_adapters::pi_http::{probe_lab_v4_device, PiHttpClient};
use ylx_transfer_core::device::actor::{AuthenticatedPiSession, PairingPort};
use ylx_transfer_core::device::SessionFileEntryView;
use ylx_transfer_core::domain::{FileId, SessionId};
use ylx_transfer_core::library::download::{download_file, FilePlan};

#[test]
#[ignore = "requires YLX_LIVE_PI_HOST and a reachable trusted-LAN Pi"]
fn production_download_path_fetches_a_real_pi_file() {
    let host = std::env::var("YLX_LIVE_PI_HOST")
        .expect("set YLX_LIVE_PI_HOST to the trusted-LAN Pi address");
    let port = std::env::var("YLX_LIVE_PI_PORT")
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .expect("YLX_LIVE_PI_PORT must be a u16")
        })
        .unwrap_or(8080);
    let device_id =
        std::env::var("YLX_LIVE_PI_DEVICE_ID").unwrap_or_else(|_| "30D5872D".to_string());
    let timeout = Duration::from_secs(10);
    let probe = probe_lab_v4_device(&host, port, timeout).expect("probe live Pi Device API v4");
    let session_pin = probe.synthetic_identity_pin.0.clone();
    let client = Arc::new(
        PiHttpClient::new_lab_v4_http(host, port, probe.synthetic_identity_pin, timeout)
            .expect("construct Device API v4 PiHttpClient"),
    );

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos()
        .to_string();
    let pairing = PiPairingClient::new(client.clone());
    let created =
        PairingPort::create_pairing_request(&pairing, "ylx-live-download-diagnostic", &nonce)
            .expect("create local Device API v4 compatibility pairing request");
    let deadline = Instant::now() + Duration::from_secs(5);
    let (token, sas_publication_key_fingerprint) = loop {
        let status =
            PairingPort::get_pairing_status(&pairing, &created.attempt_id, &created.poll_secret)
                .expect("poll local Device API v4 compatibility pairing request");
        if let Some(token) = status.connection_token {
            break (token, status.sas_publication_key_fingerprint);
        }
        assert!(
            Instant::now() < deadline,
            "Device API v4 compatibility pairing did not return a connection token"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let session =
        AuthenticatedPiSession::new(token, session_pin, sas_publication_key_fingerprint, 1)
            .expect("live Pi pairing yields a valid authenticated session");
    let authenticated = AuthenticatedPiClient::new(client.clone(), session)
        .expect("live Pi transport pin matches session");

    // Cover the desktop's five-second heartbeat cadence before downloading.
    // In the current lab v4 profile this is a compatibility liveness check
    // against `/api/v4/device`, not an authenticated token renewal.
    for renewal in 1..=4 {
        std::thread::sleep(Duration::from_secs(5));
        let heartbeat = authenticated
            .heartbeat()
            .unwrap_or_else(|error| panic!("heartbeat renewal {renewal} failed: {error}"));
        eprintln!(
            "live download diagnostic: renewal={renewal} idle_timeout_ms={}",
            heartbeat.idle_timeout_ms
        );
    }

    let _device = authenticated
        .get_device()
        .expect("read authenticated live Pi device identity");
    let catalog = authenticated
        .list_sessions(None, Some(100))
        .expect("list live Pi sessions");
    assert!(!catalog.sessions.is_empty(), "live Pi catalog is empty");

    let mut selected: Option<(String, SessionFileEntryView)> = None;
    for summary in catalog.sessions.iter().take(20) {
        let detail = authenticated
            .get_session(summary.session_id.as_str())
            .expect("verify a live Pi session detail");
        for file in &detail.files {
            let candidate = (detail.session_id.clone(), file.clone());
            if selected
                .as_ref()
                .is_none_or(|(_, current)| file.size_bytes < current.size_bytes)
            {
                selected = Some(candidate);
            }
        }
    }
    let (session_id, file) = selected.expect("live Pi sessions contain at least one file");
    eprintln!(
        "live download diagnostic: session={session_id} file={} bytes={}",
        file.id, file.size_bytes
    );

    let source = PiDownloadSource::new(
        client,
        authenticated.session().clone(),
        SessionId(session_id.clone()),
        FileId(file.id.clone()),
    )
    .expect("live Pi session binds to transport");
    let destination = tempfile::tempdir().expect("create diagnostic download directory");
    let verified = download_file(
        &source,
        &FilePlan {
            device_id,
            session_id,
            file_id: file.id,
            target_relative_path: Some(file.display_path),
            expected_size: file.size_bytes,
            expected_sha256_hex: file.sha256,
        },
        destination.path(),
    )
    .expect("production download path must fetch and verify a real Pi file");

    assert_eq!(verified.size_bytes, file.size_bytes);
    assert!(verified.path.is_file());
}
