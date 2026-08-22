//! PC-05 task-card item 1: a real
//! `ylx_transfer_core::library::download::DownloadSource` adapter wrapping
//! the file GET/HEAD operations on [`PiHttpClient`] (`pi_http.rs`, only the
//! adapter's internal transport API is called).
//!
//! # Why this lives here, not in `ylx-transfer-core::transfer::queue`
//!
//! `ylx-transfer-core` has zero dependency on any network crate (see that
//! crate's root doc comment) and `ylx-transfer-adapters` (this crate,
//! which owns `PiHttpClient`/`reqwest`-equivalent `ureq`) depends on
//! `ylx-transfer-core`, never the reverse — a `DownloadSource` impl that
//! names `PiHttpClient` therefore cannot live in `ylx-transfer-core`
//! without either reversing that edge (impossible, Cargo has no cycles)
//! or pulling `ureq`/`rustls`/`mdns-sd` into a crate whose entire stated
//! purpose is staying free of them. This mirrors `pi_client_port.rs`'s
//! own doc comment exactly (same crate-boundary reasoning, one layer
//! down, for the download-source seam instead of the core capability
//! ports) — see that file for the precedent. `ylx_transfer_core::transfer::coordinator::
//! TransferCoordinator` is generic over `DownloadSource` (already defined
//! in core) precisely so it never has to know this adapter exists; a real
//! composition root (PC-08) builds a `PiDownloadSource` per (device,
//! session, file) and hands it to the coordinator through a small
//! `DownloadSourceFactory` impl there.
//!
//! # What this adapter does and does not do
//!
//! [`PiDownloadSource::fetch_range`] issues exactly one `GET .../files/
//! {file_id}` call per invocation (optionally `Range`/`If-Match`), and
//! reconstructs the raw `Content-Range` header text
//! `library::download::interpret_range_response` expects from
//! `PiHttpClient`'s already-parsed content-range value — `pi_http.rs` parses
//! that header once on the wire side; this adapter un-parses it back to
//! text rather than duplicating `library::download`'s own parser or
//! changing that module's `DownloadSource`/`SourceResponse` shape (both
//! off-limits to modify). The response body is the owned `ureq` socket
//! reader returned by `get_file_stream`, so multi-gigabyte media remains
//! bounded by the coordinator's copy buffer instead of file size.
//!
//! Statuses `412` (the object changed since the checkpoint's validator)
//! and `416` (range no longer satisfiable) are handed back as ordinary
//! [`SourceResponse`]s carrying that exact status — not as
//! `DownloadError`s — because `library::download`'s resume state machine
//! owns the decision of what they mean. Issue #1 commit 10: this adapter
//! previously collapsed both into `DownloadError::Source(String)`, which
//! made those two branches of the engine unreachable in production. The
//! shared contract suite in
//! `ylx_transfer_core::library::download_contract` pins that behavior for
//! every `DownloadSource` implementation; this module's tests run it
//! against a real loopback HTTP server.
//!
use std::io;
use std::sync::Arc;

use ylx_transfer_core::device::actor::AuthenticatedPiSession;
use ylx_transfer_core::device::DeviceHandle;
use ylx_transfer_core::domain::{FileId, SessionId};
use ylx_transfer_core::library::download::{
    DownloadError, DownloadSource, RequestedRange, SourceResponse,
};

use crate::pi_client_port::session::AuthenticatedPiClient;
use crate::pi_http::{PiHttpClient, PiHttpError};

/// One (device-session-scoped) file's download source, bound to an
/// [`AuthenticatedPiSession`]. The bearer credential remains private to the
/// authenticated adapter; callers cannot construct this source from a raw
/// token or accidentally detach it from its TLS/publication/epoch binding.
pub struct PiDownloadSource {
    client: AuthenticatedPiClient,
    handle: Option<DeviceHandle>,
    session_id: SessionId,
    file_id: FileId,
}

impl PiDownloadSource {
    /// Bind a source to one authenticated session and its pinned transport.
    /// The constructor rejects a TLS pin mismatch before any transfer starts.
    pub fn new(
        client: Arc<PiHttpClient>,
        session: AuthenticatedPiSession,
        session_id: SessionId,
        file_id: FileId,
    ) -> Result<Self, PiHttpError> {
        let client = AuthenticatedPiClient::new(client, session)
            .map_err(|error| PiHttpError::InvalidArgument(error.to_string()))?;
        Ok(Self {
            client,
            handle: None,
            session_id,
            file_id,
        })
    }

    /// Bind a source to a live device handle as well as the authenticated
    /// transport. Each ranged request is fenced before and after I/O against
    /// that handle's current epoch, so a disconnect/reconnect invalidates a
    /// source that was created for the old session.
    pub fn new_with_handle(
        client: Arc<PiHttpClient>,
        handle: DeviceHandle,
        session: AuthenticatedPiSession,
        session_id: SessionId,
        file_id: FileId,
    ) -> Result<Self, PiHttpError> {
        let mut source = Self::new(client, session, session_id, file_id)?;
        source.handle = Some(handle);
        Ok(source)
    }
}

impl DownloadSource for PiDownloadSource {
    fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
        let epoch_ticket = if let Some(handle) = &self.handle {
            let expected_epoch = self.client.session().epoch();
            let Some(epoch) = handle.current_epoch() else {
                return Err(DownloadError::Source(
                    "authenticated Pi session is no longer connected".to_string(),
                ));
            };
            if epoch != expected_epoch {
                return Err(DownloadError::Source(
                    "authenticated Pi session epoch is stale".to_string(),
                ));
            }
            Some(epoch)
        } else {
            None
        };
        let range = if request.start == 0 && request.if_match_etag.is_none() {
            None
        } else {
            Some(ylx_transfer_core::device::ByteRangeRequest::From {
                start: request.start,
            })
        };
        let resp = match self.client.get_file_stream_raw(
            self.session_id.as_str(),
            self.file_id.as_str(),
            request.if_match_etag.as_deref(),
            range,
        ) {
            Ok(resp) => resp,
            // 412/416 are *answers*, not transport failures: `library::
            // download`'s state machine has a dedicated branch for each
            // (discard-and-restart on a changed object; "maybe the local
            // partial is already complete" on an unsatisfiable range).
            // Collapsing them into `DownloadError::Source(String)` — as
            // this adapter used to — made both branches unreachable in
            // production, so they are handed back verbatim as a
            // `SourceResponse` carrying the real status instead. Neither
            // status carries file bytes, so the body is empty: a
            // problem+json detail is never smuggled through as if it were
            // part of the object.
            Err(PiHttpError::PreconditionFailed { etag, .. }) => {
                return Ok(SourceResponse {
                    status: 412,
                    etag,
                    content_range: None,
                    content_length: None,
                    body: Box::new(io::empty()),
                });
            }
            Err(PiHttpError::RangeNotSatisfiable {
                content_range,
                etag,
                ..
            }) => {
                return Ok(SourceResponse {
                    status: 416,
                    etag,
                    content_range,
                    content_length: None,
                    body: Box::new(io::empty()),
                });
            }
            Err(other) => return Err(DownloadError::Source(other.to_string())),
        };

        if let (Some(handle), Some(epoch)) = (&self.handle, epoch_ticket) {
            if handle.current_epoch() != Some(epoch) {
                return Err(DownloadError::Source(
                    "authenticated Pi session epoch changed during download request".to_string(),
                ));
            }
        }

        // Un-parse `pi_http`'s already-structured `ContentRange` back into
        // the raw `Content-Range: bytes start-end/total` text
        // `library::download::interpret_range_response` parses itself —
        // see module doc comment for why this adapter does not hand that
        // module a pre-parsed value.
        let content_range = resp
            .content_range
            .map(|range| format!("bytes {}-{}/{}", range.start, range.end, range.total_size));

        Ok(SourceResponse {
            status: resp.status,
            etag: Some(resp.etag),
            content_range,
            content_length: Some(resp.content_length),
            body: resp.body,
        })
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    //! The production side of core's shared `DownloadSource` contract
    //! suite (issue #1, commit 10): the exact same assertions core runs
    //! against its in-memory fake, run here against the real adapter
    //! stack (`PiDownloadSource` -> `PiHttpClient` -> a real HTTP/1.1
    //! conversation on a loopback socket). Plain `http://`, as
    //! `pi_http.rs`'s own unit tests do — TLS pinning is proven by
    //! `tests/pi_http_integration.rs`, not here.

    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use tiny_http::{Header, Response as TinyResponse, Server, StatusCode};
    use ylx_transfer_core::library::download_contract::{
        assert_download_source_contract, contract_total, ContractCase,
        DownloadSourceContractHarness, CONTRACT_BODY, CONTRACT_ETAG,
    };

    use super::*;

    fn problem_json(code: &str, status: u16) -> Vec<u8> {
        serde_json::json!({
            "error_schema_version": 1,
            "code": code,
            "status": status,
            "request_id": "req-contract-1",
            "retryable": false,
            "detail": format!("contract-server detail for {code}"),
        })
        .to_string()
        .into_bytes()
    }

    fn header_value(request: &tiny_http::Request, name: &str) -> Option<String> {
        request
            .headers()
            .iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str().to_string())
    }

    /// A minimal but *honest* file endpoint: it derives its answer from the
    /// request the adapter actually sent (`If-Match`/`Range`), so the four
    /// contract statuses are produced by real HTTP conditional/range
    /// semantics rather than blindly replayed in a fixed order. `bytes=0-`
    /// is answered with a plain `200` (a server is allowed to ignore a
    /// range request — that is precisely `RangeOutcome::FullFromZero`).
    fn spawn_contract_server(request_count: usize) -> (String, JoinHandle<()>) {
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let port = server
            .server_addr()
            .to_ip()
            .expect("loopback server has an IP addr")
            .port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");

        let handle = std::thread::spawn(move || {
            let total = contract_total();
            for _ in 0..request_count {
                let request = match server.recv_timeout(Duration::from_secs(5)) {
                    Ok(Some(request)) => request,
                    _ => break,
                };
                let if_match = header_value(&request, "If-Match");
                let range_start: u64 = header_value(&request, "Range")
                    .and_then(|v| {
                        v.strip_prefix("bytes=")
                            .map(|r| r.trim_end_matches('-').to_string())
                    })
                    .and_then(|start| start.parse().ok())
                    .unwrap_or(0);

                let (status, headers, body) =
                    if if_match.as_deref().is_some_and(|tag| tag != CONTRACT_ETAG) {
                        (
                            412,
                            vec![("Content-Type", "application/problem+json".to_string())],
                            problem_json("precondition_failed", 412),
                        )
                    } else if range_start >= total {
                        (
                            416,
                            vec![
                                ("Content-Type", "application/problem+json".to_string()),
                                ("Content-Range", format!("bytes */{total}")),
                                ("ETag", CONTRACT_ETAG.to_string()),
                            ],
                            problem_json("range_not_satisfiable", 416),
                        )
                    } else if range_start == 0 {
                        (
                            200,
                            vec![
                                ("Content-Type", "application/octet-stream".to_string()),
                                ("ETag", CONTRACT_ETAG.to_string()),
                            ],
                            CONTRACT_BODY.to_vec(),
                        )
                    } else {
                        (
                            206,
                            vec![
                                ("Content-Type", "application/octet-stream".to_string()),
                                ("ETag", CONTRACT_ETAG.to_string()),
                                (
                                    "Content-Range",
                                    format!("bytes {range_start}-{}/{total}", total - 1),
                                ),
                            ],
                            CONTRACT_BODY[range_start as usize..].to_vec(),
                        )
                    };

                let mut response = TinyResponse::from_data(body)
                    .with_status_code(StatusCode(status))
                    .with_chunked_threshold(usize::MAX);
                for (name, value) in headers {
                    if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                        response.add_header(header);
                    }
                }
                let _ = request.respond(response);
            }
        });

        (base_url, handle)
    }

    struct PiDownloadSourceContractHarness {
        client: Arc<PiHttpClient>,
        server: Mutex<Option<JoinHandle<()>>>,
    }

    impl PiDownloadSourceContractHarness {
        fn start() -> Self {
            let (base_url, server) = spawn_contract_server(ContractCase::ALL.len());
            PiDownloadSourceContractHarness {
                client: Arc::new(PiHttpClient::new_insecure_for_test(
                    base_url,
                    Duration::from_secs(5),
                )),
                server: Mutex::new(Some(server)),
            }
        }

        fn join_server(&self) {
            if let Some(handle) = self.server.lock().unwrap().take() {
                handle.join().expect("contract server thread exits cleanly");
            }
        }
    }

    impl DownloadSourceContractHarness for PiDownloadSourceContractHarness {
        fn name(&self) -> &str {
            "pi_download_source::PiDownloadSource"
        }

        fn source_for(&self, _case: ContractCase) -> Box<dyn DownloadSource> {
            let session = AuthenticatedPiSession::new(
                "contract-token",
                format!("sha256:{}", "a".repeat(64)),
                Some(format!("sha256:{}", "b".repeat(64))),
                1,
            )
            .expect("valid contract session");
            Box::new(
                PiDownloadSource::new(
                    self.client.clone(),
                    session,
                    SessionId("sess-contract".to_string()),
                    FileId("file-contract".to_string()),
                )
                .expect("contract session binds to test transport"),
            )
        }
    }

    #[test]
    fn pi_download_source_satisfies_the_download_source_contract() {
        let harness = PiDownloadSourceContractHarness::start();
        assert_download_source_contract(&harness);
        harness.join_server();
    }

    #[test]
    fn fresh_zero_byte_download_omits_range_and_accepts_full_200() {
        let server = Server::http("127.0.0.1:0").expect("bind zero-byte loopback server");
        let port = server
            .server_addr()
            .to_ip()
            .expect("loopback server has an IP addr")
            .port();
        let base_url = format!("http://127.0.0.1:{port}/api/v1");
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let server_handle = std::thread::spawn(move || {
            let request = server
                .recv_timeout(Duration::from_secs(5))
                .expect("receive zero-byte request")
                .expect("zero-byte request is present");
            let range = header_value(&request, "Range");
            request_tx
                .send(range.clone())
                .expect("capture Range header");

            let (status, headers, body) = if range.is_some() {
                (
                    416,
                    vec![
                        ("Content-Type", "application/problem+json".to_string()),
                        ("Content-Range", "bytes */0".to_string()),
                        ("ETag", CONTRACT_ETAG.to_string()),
                    ],
                    problem_json("range_not_satisfiable", 416),
                )
            } else {
                (
                    200,
                    vec![
                        ("Content-Type", "application/octet-stream".to_string()),
                        ("Content-Length", "0".to_string()),
                        ("ETag", CONTRACT_ETAG.to_string()),
                    ],
                    Vec::new(),
                )
            };

            let mut response = TinyResponse::from_data(body)
                .with_status_code(StatusCode(status))
                .with_chunked_threshold(usize::MAX);
            for (name, value) in headers {
                response.add_header(
                    Header::from_bytes(name.as_bytes(), value.as_bytes())
                        .expect("valid response header"),
                );
            }
            request.respond(response).expect("send zero-byte response");
        });

        let client = Arc::new(PiHttpClient::new_insecure_for_test(
            base_url,
            Duration::from_secs(2),
        ));
        let session = AuthenticatedPiSession::new(
            "zero-byte-token",
            format!("sha256:{}", "a".repeat(64)),
            Some(format!("sha256:{}", "b".repeat(64))),
            1,
        )
        .expect("valid zero-byte session");
        let source = PiDownloadSource::new(
            client,
            session,
            SessionId("sess-zero".to_string()),
            FileId("file-zero".to_string()),
        )
        .expect("bind zero-byte source");

        let mut response = source
            .fetch_range(RequestedRange {
                start: 0,
                if_match_etag: None,
            })
            .expect("zero-byte response reaches the core engine");
        let mut body = Vec::new();
        response
            .body
            .read_to_end(&mut body)
            .expect("read zero-byte body");
        server_handle
            .join()
            .expect("zero-byte server exits cleanly");

        assert_eq!(request_rx.recv().expect("captured Range header"), None);
        assert_eq!(response.status, 200);
        assert_eq!(response.content_length, Some(0));
        assert!(body.is_empty());
    }
}
