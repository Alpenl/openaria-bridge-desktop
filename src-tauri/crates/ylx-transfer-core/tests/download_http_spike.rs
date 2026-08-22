//! SPIKE-PC-DOWNLOAD integration test: prove `library::download`'s
//! Range-response interpretation against **real bytes on a real loopback
//! HTTP/1.1 socket**, not just hand-crafted header strings passed directly
//! to `interpret_range_response` (see the unit tests in
//! `src/library/download.rs` for those).
//!
//! This spins up a real `tiny_http` server (same dev-dependency and
//! pattern already used by `ylx-transfer-adapters::object_store_s3`'s
//! tests — see that module's test-module doc comment for the same
//! honesty note that applies here) and a small hand-rolled HTTP/1.1 GET
//! client — deliberately hand-rolled rather than pulling in `ureq`/
//! `reqwest`, because this crate's whole point (see `src/lib.rs`) is
//! having **zero** dependency on a general-purpose HTTP client; adding one
//! just for this one test file would undermine that. The client only
//! supports exactly what these tests need: a `GET` with a `Range`/
//! `If-Match` request header, a status line, `\r\n`-terminated headers,
//! and a `Content-Length`-delimited body. It does not handle chunked
//! transfer-encoding, redirects, or keep-alive reuse across requests —
//! not needed here and explicitly out of scope.
//!
//! **What this does and does not prove** (same honesty framing as
//! `object_store_s3.rs`'s test docs): `tiny_http` does not validate Range
//! semantics itself — it is scripted per test to return exactly the
//! status/headers/body under test. This proves the *client-side*
//! interpretation logic (`interpret_range_response` /
//! `download_file`) correctly parses real HTTP responses byte-for-byte off
//! a real socket; it does not prove any particular real Pi server
//! implementation is spec-compliant — that is PC-03's job (golden fake
//! server tests against the real `pi_http.rs` adapter).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tiny_http::{Header, Response as TinyResponse, Server, StatusCode};

use ylx_transfer_core::library::download::{
    download_file, journal_path, part_path, DownloadError, DownloadSource, FilePlan,
    RequestedRange, SourceResponse,
};

/// One scripted response: status code, extra headers, body bytes.
type ScriptedResponse = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// Spawn a `tiny_http` server on an OS-assigned loopback port that serves
/// exactly one scripted response, then shuts down. Returns the port.
fn spawn_one_shot_server(response: ScriptedResponse) -> (u16, std::thread::JoinHandle<()>) {
    let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
    let addr = server.server_addr();
    let port = addr.to_ip().expect("loopback server has an IP addr").port();

    let handle = std::thread::spawn(move || {
        let request = match server.recv_timeout(Duration::from_secs(5)) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let (status, headers, body) = response;
        let mut resp = TinyResponse::from_data(body).with_status_code(StatusCode(status));
        for (name, value) in headers {
            if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                resp.add_header(header);
            }
        }
        let _ = request.respond(resp);
    });

    (port, handle)
}

/// Minimal hand-rolled `DownloadSource` speaking real HTTP/1.1 GET over a
/// real TCP socket to a loopback test server. See module doc comment for
/// what it deliberately does not support.
struct RawHttpSource {
    port: u16,
}

impl DownloadSource for RawHttpSource {
    fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port))
            .map_err(|e| DownloadError::Source(format!("connect failed: {e}")))?;

        let mut req = format!(
            "GET /file HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes={}-\r\nConnection: close\r\n",
            request.start
        );
        if let Some(etag) = &request.if_match_etag {
            req.push_str(&format!("If-Match: {etag}\r\n"));
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .map_err(|e| DownloadError::Source(format!("write failed: {e}")))?;

        let mut reader = BufReader::new(stream);

        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|e| DownloadError::Source(format!("read status line failed: {e}")))?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| DownloadError::Source(format!("bad status line: {status_line:?}")))?;

        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| DownloadError::Source(format!("read header failed: {e}")))?;
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let body_bytes = if let Some(len) = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        {
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| DownloadError::Source(format!("short body read: {e}")))?;
            buf
        } else {
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .map_err(|e| DownloadError::Source(format!("read body failed: {e}")))?;
            buf
        };

        Ok(SourceResponse {
            status,
            etag: headers.get("etag").cloned(),
            content_range: headers.get("content-range").cloned(),
            content_length: headers.get("content-length").and_then(|v| v.parse().ok()),
            body: Box::new(std::io::Cursor::new(body_bytes)),
        })
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn plan_for(data: &[u8]) -> FilePlan {
    FilePlan {
        device_id: "dev1".to_string(),
        session_id: "sess1".to_string(),
        file_id: "file1".to_string(),
        target_relative_path: None,
        expected_size: data.len() as u64,
        expected_sha256_hex: sha256_hex(data),
    }
}

#[test]
fn real_http_206_full_download_verifies_and_commits() {
    let data = b"hello over real http, from a real 206 partial-content response".to_vec();
    let (port, handle) = spawn_one_shot_server((
        206,
        vec![
            ("ETag", "\"real-etag-1\"".to_string()),
            (
                "Content-Range",
                format!("bytes 0-{}/{}", data.len() - 1, data.len()),
            ),
        ],
        data.clone(),
    ));

    let root = tempdir().expect("tempdir");
    let source = RawHttpSource { port };
    let plan = plan_for(&data);

    let verified =
        download_file(&source, &plan, root.path()).expect("real HTTP 206 download succeeds");
    assert_eq!(std::fs::read(&verified.path).unwrap(), data);
    assert_eq!(verified.etag.as_deref(), Some("\"real-etag-1\""));

    handle.join().expect("server thread joins cleanly");
}

#[test]
fn real_http_200_fallback_ignores_range_and_restarts_from_zero() {
    let data = b"the server ignored our Range header and sent everything".to_vec();
    let (port, handle) = spawn_one_shot_server((
        200,
        vec![("ETag", "\"real-etag-2\"".to_string())],
        data.clone(),
    ));

    let root = tempdir().expect("tempdir");

    // Seed a stale, wrong partial + journal claiming we'd already confirmed
    // some bytes — a real 200 response must discard this, not append to it.
    let target = ylx_transfer_core::library::download::derive_target_path(
        root.path(),
        "dev1",
        "sess1",
        "file1",
    )
    .unwrap();
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(part_path(&target), b"WRONG-STALE-BYTES").unwrap();
    // (No journal written: recover_resume_offset will treat confirmed
    // offset as 0 given no journal, so the engine will request `bytes=0-`
    // regardless — the real point under test is that the *response*
    // arriving as 200 must not be appended to the stale `.part` on disk.)

    let source = RawHttpSource { port };
    let plan = plan_for(&data);
    let verified =
        download_file(&source, &plan, root.path()).expect("200 fallback download succeeds");
    assert_eq!(std::fs::read(&verified.path).unwrap(), data);
    assert!(!part_path(&target).exists());
    assert!(!journal_path(&target).exists());

    handle.join().expect("server thread joins cleanly");
}

#[test]
fn real_http_416_range_not_satisfiable_is_a_hard_error() {
    let (port, handle) = spawn_one_shot_server((
        416,
        vec![("Content-Range", "bytes */10".to_string())],
        vec![],
    ));

    let root = tempdir().expect("tempdir");
    let source = RawHttpSource { port };
    let plan = plan_for(b"irrelevant-expected-content");

    let err = download_file(&source, &plan, root.path()).expect_err("416 must be a hard error");
    assert!(matches!(err, DownloadError::RangeNotSatisfiable));

    handle.join().expect("server thread joins cleanly");
}

#[test]
fn real_http_malformed_content_range_is_rejected_not_misinterpreted() {
    // A real server sending a 206 with a garbage Content-Range header
    // (e.g. a buggy proxy, or a deliberately hostile device on the LAN).
    let (port, handle) = spawn_one_shot_server((
        206,
        vec![("Content-Range", "not-a-valid-range-header".to_string())],
        b"some bytes that must never be trusted".to_vec(),
    ));

    let root = tempdir().expect("tempdir");
    let source = RawHttpSource { port };
    let plan = plan_for(b"irrelevant-expected-content");

    let err = download_file(&source, &plan, root.path())
        .expect_err("malformed Content-Range over real HTTP must be rejected");
    assert!(matches!(err, DownloadError::MalformedContentRange(_)));

    let target = ylx_transfer_core::library::download::derive_target_path(
        root.path(),
        "dev1",
        "sess1",
        "file1",
    )
    .unwrap();
    assert!(
        !target.exists(),
        "must not commit anything from a malformed response"
    );

    handle.join().expect("server thread joins cleanly");
}
