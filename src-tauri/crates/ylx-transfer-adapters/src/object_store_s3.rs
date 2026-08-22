//! Production S3-compatible [`ObjectStorePort`] adapter.
//!
//! The desktop composition root uses this implementation for multipart
//! uploads and completion-bound verification. Unit tests exercise real SigV4
//! HTTP traffic against a deterministic loopback server; the shared contract
//! suite also runs against MinIO in CI.
//!
//! # What this implements
//!
//! `CreateMultipartUpload` → `UploadPart` (per part) → `CompleteMultipartUpload`
//! → `HeadObject`-based `verify_object`, plus `AbortMultipartUpload` for
//! cleanup. Uses [`rusty_s3`] (a Sans-IO SigV4 signing library — it builds
//! and signs presigned URLs but performs no I/O itself) to do the actual
//! request signing, and [`ureq`] (a small blocking HTTP client, rustls by
//! default, no async runtime) to send them. This keeps the adapter blocking
//! and endpoint-neutral without bringing an asynchronous AWS runtime into the
//! desktop process.
//!
//! `source_sha256` (plan 9.3: "上传 SHA-256 metadata") is sent as the
//! `x-amz-meta-source-sha256` object metadata header at
//! `CreateMultipartUpload` time and read back by `verify_object`'s HEAD
//! request — never derived from or compared to the multipart `ETag`.
//!
//! # Completion binding and real digests (issue #1, commits 69/70)
//!
//! [`ObjectStorePort::verify_completed_object`] issues its HEAD (and, when
//! it needs one, its GET) **at the completion's `versionId`** and rejects
//! any read-back whose ETag/version id is not the one
//! `CompleteMultipartUpload` returned. On a bucket without versioning
//! there is no version to pin, so the ETag comparison is the whole
//! defence — and it fails explicitly
//! ([`ObjectStoreError::CompletionMismatch`]) rather than certifying
//! whatever another writer left at the key.
//!
//! Content digests are never taken on faith from metadata: if HEAD
//! reports a trusted **full-object** `x-amz-checksum-sha256` it is used,
//! otherwise the object is streamed back through a SHA-256 hasher (64 KiB
//! at a time, never buffered whole). A checksum header that is present but
//! unusable is [`ObjectStoreError::MalformedChecksum`] — fail closed.
//!
//! # Transport policy pinned by this adapter
//!
//! - **Non-HTTPS endpoints are refused** at construction, except on
//!   loopback (`127.0.0.1`/`::1`/`localhost`), where a plaintext MinIO is
//!   a normal development and CI setup and no traffic leaves the host.
//! - **Redirects are never followed.** A presigned request's signature
//!   covers a specific host and path; following a `3xx` would both hand
//!   the presigned URL to whatever host the redirect names and verify
//!   bytes that host chose. Any `3xx` is
//!   [`ObjectStoreError::UnexpectedRedirect`].

use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rusty_s3::actions::{
    AbortMultipartUpload, CompleteMultipartUpload, CreateMultipartUpload, GetObject, HeadObject,
    UploadPart as S3UploadPartAction,
};
use rusty_s3::{Bucket, Credentials, S3Action};
use sha2::{Digest, Sha256};
use ureq::{http, Agent};

pub use rusty_s3::UrlStyle;
use ylx_transfer_core::library::object_store_port::{
    CompletedUpload, DigestProof, ExpectedObject, InitiateUploadRequest, MultipartUploadHandle,
    ObjectKey, ObjectStoreError, ObjectStorePort, PartETag, PartNumber, SourceSha256, UploadId,
    VerifiedObjectReceipt,
};

/// Object metadata header carrying the caller-computed source hash.
/// Never compared against a multipart ETag — see module docs.
const SOURCE_SHA256_META_HEADER: &str = "x-amz-meta-source-sha256";

/// S3's own server-side SHA-256 checksum of the stored object, when the
/// backend keeps one. Base64, not hex.
const CHECKSUM_SHA256_HEADER: &str = "x-amz-checksum-sha256";

/// `FULL_OBJECT` or `COMPOSITE`. Only a full-object checksum describes the
/// bytes; a composite one is a checksum *of part checksums*, exactly the
/// trap a multipart ETag is.
const CHECKSUM_TYPE_HEADER: &str = "x-amz-checksum-type";

/// Read-back chunk size for the streamed digest path. Large enough to keep
/// syscall overhead down, small enough that a multi-GiB object never lands
/// in memory.
const DIGEST_READ_CHUNK: usize = 64 * 1024;

/// Maximum body bytes retained from any buffered S3 response. S3 control
/// responses are small XML documents (or empty), so the same 64 KiB ceiling
/// used by the Pi HTTP adapter is ample while keeping a hostile/erroring
/// endpoint from forcing an unbounded allocation.
const MAX_BUFFERED_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// Maximum remote-controlled text retained in an [`ObjectStoreError`]. This
/// intentionally matches the Pi HTTP adapter's user/log-facing text budget.
const MAX_REMOTE_ERROR_TEXT_BYTES: usize = 1024;

const REMOTE_TEXT_TRUNCATION_MARKER: &str = "...[truncated]";
const RESPONSE_BODY_TRUNCATION_MARKER: &str = "[response body truncated at 65536 bytes]";

/// Presigned-URL validity window. Generous enough to cover a slow part
/// upload over a weak connection; each action is signed fresh right
/// before it is sent, so this is not a cumulative session TTL.
const SIGNED_URL_TTL: Duration = Duration::from_secs(300);

/// Completing a large multipart object can require substantially more time
/// than an ordinary S3 control request while the backend assembles parts.
/// Keep that operation bounded, but do not reuse the short request timeout
/// that protects metadata calls.
const MIN_MULTIPART_COMPLETION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct S3ObjectStoreConfig {
    /// Scheme + host (+ optional port) of the S3-compatible endpoint,
    /// e.g. `https://minio.example.internal:9000`. Must not include a
    /// path or the bucket name.
    pub endpoint: url::Url,
    pub bucket: String,
    pub region: String,
    /// `UrlStyle::Path` is required for most self-hosted S3-compatible
    /// servers (MinIO's default); `UrlStyle::VirtualHost` matches AWS S3
    /// convention. Re-exported from `rusty_s3` directly rather than
    /// wrapped, since this type only exists at the adapters-crate
    /// boundary, not in core.
    pub url_style: UrlStyle,
    pub access_key: String,
    pub secret_key: String,
    /// Total timeout for bounded control calls; connect/header and blocked
    /// read/write timeout for multipart parts and streamed verification. It
    /// is never a cumulative whole-part or whole-object deadline.
    pub request_timeout: Duration,
}

impl fmt::Debug for S3ObjectStoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redact secret_key so this type remains safe to
        // Debug-print in logs and error messages.
        f.debug_struct("S3ObjectStoreConfig")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("url_style", &self.url_style)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

/// Production S3-compatible `ObjectStorePort` adapter.
pub struct S3ObjectStore {
    bucket: Bucket,
    credentials: Credentials,
    control_agent: Agent,
    upload_agent: Agent,
    completion_agent: Agent,
    readback_agent: Agent,
}

/// Whether this endpoint may be spoken to in plaintext. Only loopback
/// qualifies: a local MinIO (dev box, CI service container) never puts
/// bytes or a presigned URL on a network anyone else can read.
fn is_loopback_endpoint(endpoint: &url::Url) -> bool {
    match endpoint.host_str() {
        Some("localhost") => true,
        Some(host) => {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        }
        None => false,
    }
}

/// Issue #1, commit 70: credentials, presigned URLs and the object bytes
/// themselves must not travel in the clear.
fn require_secure_endpoint(endpoint: &url::Url) -> Result<(), ObjectStoreError> {
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_endpoint(endpoint) => Ok(()),
        scheme => Err(ObjectStoreError::Config(format!(
            "object-store endpoint {endpoint} uses {scheme}://; only https:// is allowed \
             (plain http is permitted for loopback endpoints only)"
        ))),
    }
}

impl S3ObjectStore {
    pub fn new(config: S3ObjectStoreConfig) -> Result<Self, ObjectStoreError> {
        require_secure_endpoint(&config.endpoint)?;
        let bucket = Bucket::new(
            config.endpoint,
            config.url_style,
            config.bucket,
            config.region,
        )
        .map_err(|e| {
            ObjectStoreError::Config(format!("invalid S3 bucket/endpoint config: {e:?}"))
        })?;
        let credentials = Credentials::new(config.access_key, config.secret_key);
        let control_config = Agent::config_builder()
            .timeout_global(Some(config.request_timeout))
            // We want the response body/headers even on 4xx/5xx (to parse
            // S3's error XML into a structured ObjectStoreError), so
            // ureq's default "turn HTTP errors into Err" is disabled and
            // we branch on status ourselves.
            .http_status_as_error(false)
            // Redirects are a failure mode here, not a transport detail —
            // see the module docs. 0 means "hand the 3xx back", which
            // `check_no_redirect` then turns into a structured error.
            .max_redirects(0)
            .build();
        let upload_config = Agent::config_builder()
            // ureq propagates predecessor deadlines into later phases.
            // For a request with a body, send_body therefore provides both
            // an idle write timeout and a response-header timeout measured
            // from the completed body. A send_request timeout here would
            // also cover the whole body and break large multipart parts.
            .timeout_resolve(Some(config.request_timeout))
            .timeout_connect(Some(config.request_timeout))
            .timeout_send_body(Some(config.request_timeout))
            .timeout_recv_body(Some(config.request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let completion_timeout =
            std::cmp::max(config.request_timeout, MIN_MULTIPART_COMPLETION_TIMEOUT);
        let completion_config = Agent::config_builder()
            .timeout_resolve(Some(config.request_timeout))
            .timeout_connect(Some(config.request_timeout))
            // RecvResponse inherits the SendBody deadline in ureq 3.3, so
            // both phases need the completion-specific ceiling. A short
            // SendBody timeout would silently reintroduce that same short
            // deadline while waiting for the completion response headers.
            .timeout_send_body(Some(completion_timeout))
            .timeout_recv_response(Some(completion_timeout))
            .timeout_recv_body(Some(config.request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let readback_config = Agent::config_builder()
            // GET has no SendBody phase, so its response-header wait must be
            // bounded by send_request. RecvBody only inherits RecvResponse,
            // which is deliberately unset: the object may take hours while
            // every individual read still has an idle timeout.
            .timeout_resolve(Some(config.request_timeout))
            .timeout_connect(Some(config.request_timeout))
            .timeout_send_request(Some(config.request_timeout))
            .timeout_recv_body(Some(config.request_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        let control_agent: Agent = control_config.into();
        let upload_agent: Agent = upload_config.into();
        let completion_agent: Agent = completion_config.into();
        let readback_agent: Agent = readback_config.into();
        Ok(Self {
            bucket,
            credentials,
            control_agent,
            upload_agent,
            completion_agent,
            readback_agent,
        })
    }

    fn send(
        &self,
        method: http::Method,
        url: url::Url,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<RawResponse, ObjectStoreError> {
        self.send_with_agent(&self.control_agent, method, url, headers, body)
    }

    fn send_upload(
        &self,
        method: http::Method,
        url: url::Url,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<RawResponse, ObjectStoreError> {
        self.send_with_agent(&self.upload_agent, method, url, headers, body)
    }

    fn send_completion(
        &self,
        method: http::Method,
        url: url::Url,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<RawResponse, ObjectStoreError> {
        self.send_with_agent(&self.completion_agent, method, url, headers, body)
    }

    fn send_with_agent(
        &self,
        agent: &Agent,
        method: http::Method,
        url: url::Url,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<RawResponse, ObjectStoreError> {
        let response_has_body = method != http::Method::HEAD;
        let mut builder = http::Request::builder().method(method).uri(url.as_str());
        if !response_has_body {
            // ureq advertises gzip by default and strips Content-Length when
            // a response is encoded. HEAD has no body to decode, and S3's
            // object length is required for verification, so request the
            // original representation headers explicitly.
            builder = builder.header(http::header::ACCEPT_ENCODING, "identity");
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(body)
            .map_err(|e| ObjectStoreError::Config(format!("failed to build HTTP request: {e}")))?;
        let mut response = agent
            .run(request)
            .map_err(|e| self.network_error("object-store request failed", &e))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        check_no_redirect(status, &headers, &self.credentials)?;
        let (body, body_truncated) = if response_has_body {
            read_bounded_response_body(response.body_mut().as_reader())
                .map_err(|e| self.network_error("failed reading object-store response body", &e))?
        } else {
            (Vec::new(), false)
        };

        // A successful control response must be complete before it is parsed
        // or accepted. Error responses retain their status/typed semantics
        // even when their diagnostic body is truncated.
        if (200..300).contains(&status) && body_truncated {
            return Err(ObjectStoreError::ServerError {
                status,
                detail: format!(
                    "object-store success response body exceeds the {MAX_BUFFERED_RESPONSE_BODY_BYTES} byte limit"
                ),
            });
        }
        Ok(RawResponse {
            status,
            headers,
            body,
            body_truncated,
        })
    }

    fn network_error(&self, context: &str, error: &dyn fmt::Display) -> ObjectStoreError {
        let raw = format!("{context}: {error}");
        ObjectStoreError::Network(sanitize_remote_text(raw.as_bytes(), &self.credentials))
    }

    /// Streams the object back through a SHA-256 hasher without ever
    /// holding it in memory. This is commit 70's fallback for backends
    /// with no trusted full-object checksum, and it reads exactly the
    /// version it is asked for.
    fn streamed_content_digest(
        &self,
        key: &ObjectKey,
        version_id: Option<&str>,
    ) -> Result<(SourceSha256, u64), ObjectStoreError> {
        let mut action = GetObject::new(&self.bucket, Some(&self.credentials), &key.0);
        if let Some(version) = version_id {
            action.query_mut().insert("versionId", version.to_string());
        }
        let url = action.sign(SIGNED_URL_TTL);

        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(url.as_str())
            // The digest must be of the stored representation, not of a
            // transport-decoded one.
            .header(http::header::ACCEPT_ENCODING, "identity")
            .body(Vec::new())
            .map_err(|e| ObjectStoreError::Config(format!("failed to build GET request: {e}")))?;
        let mut response = self
            .readback_agent
            .run(request)
            .map_err(|e| self.network_error("object-store read-back request failed", &e))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        check_no_redirect(status, &headers, &self.credentials)?;
        if status != 200 {
            let (body, body_truncated) =
                read_bounded_response_body(response.body_mut().as_reader()).map_err(|e| {
                    self.network_error("failed reading object-store error response body", &e)
                })?;
            return Err(map_error_response(
                &RawResponse {
                    status,
                    headers,
                    body,
                    body_truncated,
                },
                ErrorContext::Key(key),
                &self.credentials,
            ));
        }

        let mut reader = response.body_mut().as_reader();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; DIGEST_READ_CHUNK];
        let mut total: u64 = 0;
        loop {
            let read = reader.read(&mut buffer).map_err(|e| {
                ObjectStoreError::Network(format!("failed reading object for digest: {e}"))
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            total = total.saturating_add(read as u64);
        }
        Ok((SourceSha256::from_bytes(hasher.finalize().into()), total))
    }

    /// Removes an object (all of it — no version pinning). Not part of
    /// [`ObjectStorePort`]: the app never deletes remote objects, this
    /// exists so the contract suite can clean up after itself against a
    /// real bucket.
    pub fn delete_object(&self, key: &ObjectKey) -> Result<(), ObjectStoreError> {
        let action =
            rusty_s3::actions::DeleteObject::new(&self.bucket, Some(&self.credentials), &key.0);
        let url = action.sign(SIGNED_URL_TTL);
        let resp = self.send(http::Method::DELETE, url, &[], Vec::new())?;
        if resp.status == 204 || resp.status == 200 || resp.status == 404 {
            Ok(())
        } else {
            Err(map_error_response(
                &resp,
                ErrorContext::Key(key),
                &self.credentials,
            ))
        }
    }
}

/// A signed request answered with a redirect is a failure, never a hop to
/// follow — see module docs.
fn check_no_redirect(
    status: u16,
    headers: &http::HeaderMap,
    credentials: &Credentials,
) -> Result<(), ObjectStoreError> {
    if (300..400).contains(&status) {
        return Err(ObjectStoreError::UnexpectedRedirect {
            status,
            location: headers
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(|value| sanitize_redirect_location(value, credentials)),
        });
    }
    Ok(())
}

struct RawResponse {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
    body_truncated: bool,
}

fn read_bounded_response_body(mut reader: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut body = Vec::with_capacity(MAX_BUFFERED_RESPONSE_BODY_BYTES + 1);
    reader
        .by_ref()
        .take((MAX_BUFFERED_RESPONSE_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)?;
    let truncated = body.len() > MAX_BUFFERED_RESPONSE_BODY_BYTES;
    body.truncate(MAX_BUFFERED_RESPONSE_BODY_BYTES);
    Ok((body, truncated))
}

/// Bound, sanitize and redact text controlled by an object-store endpoint
/// before it reaches an error, log line or RPC error. The actual configured
/// access/secret values are removed even if a backend echoes them in XML.
fn sanitize_remote_text(raw: &[u8], credentials: &Credentials) -> String {
    let mut decoded = String::from_utf8_lossy(raw).into_owned();
    for sensitive in [
        Some(credentials.key()),
        Some(credentials.secret()),
        credentials.token(),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.is_empty())
    {
        decoded = decoded.replace(sensitive, "<redacted>");
    }

    let bytes = decoded.as_bytes();
    let kept = bytes.len().min(MAX_REMOTE_ERROR_TEXT_BYTES);
    let mut safe = String::with_capacity(kept + REMOTE_TEXT_TRUNCATION_MARKER.len());
    for ch in String::from_utf8_lossy(&bytes[..kept]).chars() {
        let dangerous = ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}');
        safe.push(if dangerous { '\u{fffd}' } else { ch });
    }
    if bytes.len() > kept {
        safe.push_str(REMOTE_TEXT_TRUNCATION_MARKER);
    }
    safe
}

fn sanitize_redirect_location(raw: &str, credentials: &Credentials) -> String {
    let safe = sanitize_remote_text(raw.as_bytes(), credentials);
    match safe.find('?') {
        Some(query_start) => format!("{}?[query redacted]", &safe[..query_start]),
        None => safe,
    }
}

/// What an error response is "about", so [`map_error_response`] can
/// produce the right structured variant (a 404 means different things
/// for "this object key" vs. "this multipart upload id").
enum ErrorContext<'a> {
    Key(&'a ObjectKey),
    Upload(&'a UploadId),
}

/// Minimal, deliberately non-general XML tag extraction for S3's fixed,
/// well-known error/response tag set (`<Code>`, `<Message>`, `<ETag>`).
/// Not a real XML parser: no namespace handling, no entity decoding, no
/// nested-tag disambiguation. This deliberately avoids a second XML dependency
/// alongside `rusty_s3`'s own bundled `instant-xml` (which is not
/// exposed for arbitrary parsing, only for the two response shapes
/// `rusty_s3` itself defines).
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = &xml[start..];
    let end = rest.find(&close)?;
    Some(rest[..end].to_string())
}

/// Normalize the only XML entities that are valid around an S3 ETag.
///
/// MinIO currently emits decimal numeric entities (`&#34;`), while AWS S3
/// commonly emits `&quot;`. Keep this deliberately narrower than general XML
/// entity decoding because the surrounding response parser is intentionally
/// minimal as well.
fn normalize_completed_etag(raw: &str) -> String {
    raw.replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#x22;", "\"")
        .replace("&#X22;", "\"")
        .trim_matches('"')
        .to_string()
}

fn error_response_detail(
    resp: &RawResponse,
    credentials: &Credentials,
    include_code: bool,
    suffix: Option<&str>,
) -> String {
    let body_str = String::from_utf8_lossy(&resp.body);
    let code = extract_xml_tag(&body_str, "Code");
    let message = extract_xml_tag(&body_str, "Message").unwrap_or_else(|| {
        if body_str.trim().is_empty() {
            format!(
                "HTTP {} (no response body — expected for HEAD errors)",
                resp.status
            )
        } else {
            body_str.trim().to_string()
        }
    });
    let mut raw = if include_code {
        code.map_or(message.clone(), |code| format!("{code}: {message}"))
    } else {
        message
    };
    if let Some(suffix) = suffix {
        raw.push_str(suffix);
    }
    let mut detail = sanitize_remote_text(raw.as_bytes(), credentials);
    if resp.body_truncated {
        if !detail.is_empty() {
            detail.push(' ');
        }
        detail.push_str(RESPONSE_BODY_TRUNCATION_MARKER);
    }
    detail
}

fn map_error_response(
    resp: &RawResponse,
    ctx: ErrorContext<'_>,
    credentials: &Credentials,
) -> ObjectStoreError {
    match resp.status {
        401 | 403 => ObjectStoreError::Auth {
            status: resp.status,
            detail: error_response_detail(resp, credentials, false, None),
        },
        404 => match ctx {
            // Real S3 uses this status+code for "the multipart upload id
            // is unknown" (never created, aborted, or already completed —
            // see the crash-resume contract in the port module docs).
            ErrorContext::Upload(id) => ObjectStoreError::UnknownUpload(id.clone()),
            ErrorContext::Key(key) => ObjectStoreError::NotFound(key.clone()),
        },
        429 => {
            let retry_after_ms = resp
                .headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|secs| secs.saturating_mul(1000));
            ObjectStoreError::RateLimited { retry_after_ms }
        }
        500..=599 => ObjectStoreError::ServerError {
            status: resp.status,
            detail: error_response_detail(resp, credentials, false, None),
        },
        other => ObjectStoreError::ServerError {
            status: other,
            detail: error_response_detail(resp, credentials, true, None),
        },
    }
}

fn validate_contiguous(parts: &[PartETag]) -> Result<(), ObjectStoreError> {
    if parts.is_empty() {
        return Err(ObjectStoreError::InvalidPart(
            "no parts supplied to complete_multipart_upload".to_string(),
        ));
    }
    for (index, part) in parts.iter().enumerate() {
        let expected = u16::try_from(index).expect("part count fits u16") + 1;
        if part.part_number.get() != expected {
            return Err(ObjectStoreError::InvalidPart(format!(
                "part numbers must be contiguous starting at 1; expected {expected}, got {}",
                part.part_number.get()
            )));
        }
    }
    Ok(())
}

impl ObjectStorePort for S3ObjectStore {
    fn initiate_multipart_upload(
        &self,
        request: InitiateUploadRequest,
    ) -> Result<MultipartUploadHandle, ObjectStoreError> {
        let sha_hex = request.source_sha256.to_hex();
        let mut action =
            CreateMultipartUpload::new(&self.bucket, Some(&self.credentials), &request.key.0);
        action
            .headers_mut()
            .insert(SOURCE_SHA256_META_HEADER, sha_hex.clone());
        if let Some(content_type) = &request.content_type {
            action
                .headers_mut()
                .insert("content-type", content_type.clone());
        }
        let url = action.sign(SIGNED_URL_TTL);

        // Headers signed via headers_mut() above MUST be present, with
        // the same value, on the actual request we send (rusty_s3's own
        // documented contract) — duplicated here rather than derived
        // from `action` because `action.headers_mut()` was already
        // consumed into the signature and isn't re-readable in a form
        // convenient to iterate generically.
        let mut send_headers = vec![(SOURCE_SHA256_META_HEADER, sha_hex.as_str())];
        if let Some(content_type) = &request.content_type {
            send_headers.push(("content-type", content_type.as_str()));
        }

        let resp = self.send(http::Method::POST, url, &send_headers, Vec::new())?;
        if resp.status != 200 {
            return Err(map_error_response(
                &resp,
                ErrorContext::Key(&request.key),
                &self.credentials,
            ));
        }
        let body_str = String::from_utf8_lossy(&resp.body);
        let parsed = CreateMultipartUpload::parse_response(&body_str).map_err(|e| {
            ObjectStoreError::ServerError {
                status: resp.status,
                detail: format!("malformed CreateMultipartUpload XML response: {e}"),
            }
        })?;

        Ok(MultipartUploadHandle {
            key: request.key,
            upload_id: UploadId(parsed.upload_id().to_string()),
        })
    }

    fn upload_part(
        &self,
        handle: &MultipartUploadHandle,
        part_number: PartNumber,
        bytes: &[u8],
    ) -> Result<PartETag, ObjectStoreError> {
        let action = S3UploadPartAction::new(
            &self.bucket,
            Some(&self.credentials),
            &handle.key.0,
            part_number.get(),
            &handle.upload_id.0,
        );
        let url = action.sign(SIGNED_URL_TTL);
        let resp = self.send_upload(http::Method::PUT, url, &[], bytes.to_vec())?;
        if resp.status != 200 {
            return Err(map_error_response(
                &resp,
                ErrorContext::Upload(&handle.upload_id),
                &self.credentials,
            ));
        }
        let etag = resp
            .headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .ok_or_else(|| ObjectStoreError::ServerError {
                status: resp.status,
                detail: "UploadPart response missing ETag header".to_string(),
            })?;
        Ok(PartETag { part_number, etag })
    }

    fn complete_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
        mut parts: Vec<PartETag>,
    ) -> Result<CompletedUpload, ObjectStoreError> {
        parts.sort_by_key(|p| p.part_number.get());
        validate_contiguous(&parts)?;

        let etags: Vec<String> = parts.iter().map(|p| p.etag.clone()).collect();
        let action = CompleteMultipartUpload::new(
            &self.bucket,
            Some(&self.credentials),
            &handle.key.0,
            &handle.upload_id.0,
            etags.iter().map(String::as_str),
        );
        let url = action.sign(SIGNED_URL_TTL);
        let body_xml = action.body();

        // Complete may spend longer than a short control-call deadline while
        // the backend assembles the object. The dedicated agent keeps that
        // wait bounded without applying the ordinary metadata-call budget.
        let resp = self.send_completion(http::Method::POST, url, &[], body_xml.into_bytes())?;
        if resp.status != 200 {
            return Err(map_error_response(
                &resp,
                ErrorContext::Upload(&handle.upload_id),
                &self.credentials,
            ));
        }

        let body_str = String::from_utf8_lossy(&resp.body);
        // S3's documented quirk: CompleteMultipartUpload can return HTTP
        // 200 with an `<Error>` body if something failed mid-stream after
        // headers were already sent. Must not be treated as success.
        if extract_xml_tag(&body_str, "Code").is_some() {
            return Err(ObjectStoreError::ServerError {
                status: resp.status,
                detail: error_response_detail(
                    &resp,
                    &self.credentials,
                    true,
                    Some(" (200 OK response carried an <Error> body)"),
                ),
            });
        }
        let etag = extract_xml_tag(&body_str, "ETag")
            .map(|raw| normalize_completed_etag(&raw))
            .ok_or_else(|| ObjectStoreError::ServerError {
                status: resp.status,
                detail: "CompleteMultipartUpload response missing <ETag>".to_string(),
            })?;
        let version_id = resp
            .headers
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        Ok(CompletedUpload {
            key: handle.key.clone(),
            upload_id: handle.upload_id.clone(),
            etag,
            version_id,
        })
    }

    fn abort_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
    ) -> Result<(), ObjectStoreError> {
        let action = AbortMultipartUpload::new(
            &self.bucket,
            Some(&self.credentials),
            &handle.key.0,
            &handle.upload_id.0,
        );
        let url = action.sign(SIGNED_URL_TTL);
        let resp = self.send(http::Method::DELETE, url, &[], Vec::new())?;
        if resp.status == 204 || resp.status == 200 {
            Ok(())
        } else {
            Err(map_error_response(
                &resp,
                ErrorContext::Upload(&handle.upload_id),
                &self.credentials,
            ))
        }
    }

    fn verify_object(
        &self,
        key: &ObjectKey,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        let head = self.head_object(key, None)?;
        self.verify_head(key, head, expected)
    }

    fn verify_completed_object(
        &self,
        completion: &CompletedUpload,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        let key = &completion.key;
        // Commit 69: read the version this completion produced, not
        // "latest". On an unversioned bucket there is nothing to pin and
        // the ETag check below is the only thing that can catch another
        // writer's object.
        let head = self.head_object(key, completion.version_id.as_deref())?;

        if head.etag != completion.etag {
            return Err(ObjectStoreError::CompletionMismatch {
                key: key.clone(),
                detail: format!(
                    "etag mismatch: this multipart completion produced {:?}, the object read back is {:?} \
                     (another writer completed a different object on the same key)",
                    completion.etag, head.etag
                ),
            });
        }
        if let Some(expected_version) = completion.version_id.as_deref() {
            if head.version_id.as_deref() != Some(expected_version) {
                return Err(ObjectStoreError::CompletionMismatch {
                    key: key.clone(),
                    detail: format!(
                        "version mismatch: this multipart completion produced version {:?}, read back {:?}",
                        expected_version, head.version_id
                    ),
                });
            }
        }

        self.verify_head(key, head, expected)
    }
}

/// What a HEAD told us about one specific object version.
struct HeadFacts {
    content_length: u64,
    etag: String,
    version_id: Option<String>,
    /// The client-written `x-amz-meta-source-sha256`. A claim, not proof.
    source_sha256: SourceSha256,
    server_checksum: ServerChecksum,
}

/// What the backend's own checksum headers are worth for this object.
enum ServerChecksum {
    /// A trusted digest of the whole object's bytes.
    FullObject(SourceSha256),
    /// Either absent, or present but scoped to parts (`COMPOSITE`) — which
    /// says nothing about the object's content, exactly like a multipart
    /// ETag. Falls through to the streamed read-back.
    Unusable,
}

fn header_str<'h>(headers: &'h http::HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Commit 70's "malformed/absent checksum" semantics, pinned in one place:
/// absent (or composite) means *fall back to reading the bytes*; present
/// but unparseable means **fail closed**, because a backend or proxy that
/// emits a checksum header nobody can read is not one to trust silently.
fn parse_server_checksum(
    key: &ObjectKey,
    headers: &http::HeaderMap,
) -> Result<ServerChecksum, ObjectStoreError> {
    let Some(raw) = header_str(headers, CHECKSUM_SHA256_HEADER) else {
        return Ok(ServerChecksum::Unusable);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ObjectStoreError::MalformedChecksum {
            key: key.clone(),
            detail: format!("{CHECKSUM_SHA256_HEADER} is present but empty"),
        });
    }
    if let Some(kind) = header_str(headers, CHECKSUM_TYPE_HEADER) {
        if !kind.trim().eq_ignore_ascii_case("FULL_OBJECT") {
            return Ok(ServerChecksum::Unusable);
        }
    }
    if raw.contains('-') {
        // `<base64>-<parts>`: a checksum of part checksums.
        return Ok(ServerChecksum::Unusable);
    }
    let decoded = BASE64
        .decode(raw)
        .map_err(|e| ObjectStoreError::MalformedChecksum {
            key: key.clone(),
            detail: format!("{CHECKSUM_SHA256_HEADER} is not valid base64: {e}"),
        })?;
    let bytes: [u8; 32] =
        decoded
            .try_into()
            .map_err(|decoded: Vec<u8>| ObjectStoreError::MalformedChecksum {
                key: key.clone(),
                detail: format!(
                    "{CHECKSUM_SHA256_HEADER} decoded to {} bytes, expected a 32-byte SHA-256",
                    decoded.len()
                ),
            })?;
    Ok(ServerChecksum::FullObject(SourceSha256::from_bytes(bytes)))
}

impl S3ObjectStore {
    fn head_object(
        &self,
        key: &ObjectKey,
        version_id: Option<&str>,
    ) -> Result<HeadFacts, ObjectStoreError> {
        let mut action = HeadObject::new(&self.bucket, Some(&self.credentials), &key.0);
        if let Some(version) = version_id {
            action.query_mut().insert("versionId", version.to_string());
        }
        let url = action.sign(SIGNED_URL_TTL);
        let resp = self.send(http::Method::HEAD, url, &[], Vec::new())?;

        if resp.status == 404 {
            return Err(ObjectStoreError::NotFound(key.clone()));
        }
        if resp.status != 200 {
            // HEAD error responses carry no body per HTTP semantics
            // (S3 included) — map_error_response falls back to the
            // status code alone, which is all that's available.
            return Err(map_error_response(
                &resp,
                ErrorContext::Key(key),
                &self.credentials,
            ));
        }

        let content_length: u64 = header_str(&resp.headers, "content-length")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ObjectStoreError::ServerError {
                status: resp.status,
                detail: "HEAD response missing Content-Length".to_string(),
            })?;
        let etag = header_str(&resp.headers, "etag")
            .map(|s| s.trim_matches('"').to_string())
            .ok_or_else(|| ObjectStoreError::ServerError {
                status: resp.status,
                detail: "HEAD response missing ETag".to_string(),
            })?;
        let source_sha256_header = header_str(&resp.headers, SOURCE_SHA256_META_HEADER)
            .ok_or_else(|| ObjectStoreError::MalformedChecksum {
                key: key.clone(),
                detail: format!(
                    "object carries no {SOURCE_SHA256_META_HEADER} metadata — refusing to treat it as verified"
                ),
            })?;
        let source_sha256 = SourceSha256::from_hex(source_sha256_header).map_err(|e| {
            ObjectStoreError::MalformedChecksum {
                key: key.clone(),
                detail: format!("{SOURCE_SHA256_META_HEADER} is not a valid SHA-256: {e}"),
            }
        })?;

        Ok(HeadFacts {
            content_length,
            etag,
            version_id: header_str(&resp.headers, "x-amz-version-id").map(str::to_string),
            source_sha256,
            server_checksum: parse_server_checksum(key, &resp.headers)?,
        })
    }

    /// Metadata checks first (cheap, and they catch the common mistakes),
    /// then commit 70's proof that the remote *bytes* are what they claim.
    fn verify_head(
        &self,
        key: &ObjectKey,
        head: HeadFacts,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        if head.content_length != expected.size_bytes {
            return Err(ObjectStoreError::VerificationMismatch {
                key: key.clone(),
                detail: format!(
                    "size mismatch: expected {} bytes, HEAD reports {} bytes",
                    expected.size_bytes, head.content_length
                ),
            });
        }
        if head.source_sha256 != expected.source_sha256 {
            return Err(ObjectStoreError::VerificationMismatch {
                key: key.clone(),
                detail: format!(
                    "source_sha256 metadata mismatch: expected {}, HEAD reports {}",
                    expected.source_sha256, head.source_sha256
                ),
            });
        }

        let (actual, proof) = match head.server_checksum {
            ServerChecksum::FullObject(digest) => (digest, DigestProof::ServerChecksum),
            ServerChecksum::Unusable => {
                let (digest, streamed_len) =
                    self.streamed_content_digest(key, head.version_id.as_deref())?;
                if streamed_len != head.content_length {
                    return Err(ObjectStoreError::VerificationMismatch {
                        key: key.clone(),
                        detail: format!(
                            "read-back returned {streamed_len} bytes but HEAD reported {} — the object changed under us",
                            head.content_length
                        ),
                    });
                }
                (digest, DigestProof::StreamedReadback)
            }
        };
        if actual != expected.source_sha256 {
            return Err(ObjectStoreError::DigestMismatch {
                key: key.clone(),
                expected: expected.source_sha256,
                actual,
            });
        }

        Ok(VerifiedObjectReceipt {
            key: key.clone(),
            etag: head.etag,
            version_id: head.version_id,
            size_bytes: head.content_length,
            source_sha256: head.source_sha256,
            digest_proof: proof,
        })
    }
}

#[cfg(test)]
mod tests {
    //! These tests run a real `tiny_http` server on loopback and send
    //! real signed HTTP requests to it — proving `S3ObjectStore`'s
    //! request construction (method, path, query signature params,
    //! header propagation) and response parsing (success XML, error XML,
    //! HEAD headers) are internally correct and self-consistent.
    //!
    //! `tiny_http` does not implement SigV4 verification, so the separate
    //! shared adapter contract runs against MinIO in CI to cover an
    //! independent S3-compatible validator.

    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use tiny_http::{Header, Response as TinyResponse, Server, StatusCode};
    use url::Url;
    use ylx_transfer_core::library::object_store_port::{
        CompletedUpload, DigestProof, ExpectedObject, InitiateUploadRequest, MultipartUploadHandle,
        ObjectKey, ObjectStoreError, ObjectStorePort, PartNumber, SourceSha256, UploadId,
    };

    use super::{
        read_bounded_response_body, S3ObjectStore, S3ObjectStoreConfig, UrlStyle, BASE64,
        MAX_BUFFERED_RESPONSE_BODY_BYTES, MAX_REMOTE_ERROR_TEXT_BYTES,
        REMOTE_TEXT_TRUNCATION_MARKER, RESPONSE_BODY_TRUNCATION_MARKER,
    };

    /// One HTTP request as `tiny_http` observed it, captured for
    /// assertions.
    struct CapturedRequest {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    /// One scripted response: status code, headers, and body bytes.
    type ScriptedResponse = (u16, Vec<(&'static str, String)>, Vec<u8>);

    /// Spawns a `tiny_http` server on an OS-assigned loopback port,
    /// serves exactly `scripted_responses.len()` requests (one per
    /// element, in order), records each request, then shuts down.
    /// Returns the endpoint URL, a receiver for captured requests, and
    /// the join handle.
    fn spawn_fake_s3_server(
        scripted_responses: Vec<ScriptedResponse>,
    ) -> (
        Url,
        mpsc::Receiver<CapturedRequest>,
        std::thread::JoinHandle<()>,
    ) {
        let server = Server::http("127.0.0.1:0").expect("bind loopback test server");
        let addr = server.server_addr();
        let port = addr.to_ip().expect("loopback server has an IP addr").port();
        let endpoint =
            Url::parse(&format!("http://127.0.0.1:{port}")).expect("valid test endpoint url");

        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            for (status, headers, body) in scripted_responses {
                let mut request = match server.recv_timeout(Duration::from_secs(5)) {
                    Ok(Some(r)) => r,
                    _ => break,
                };

                let mut captured_body = Vec::new();
                request
                    .as_reader()
                    .read_to_end(&mut captured_body)
                    .expect("read request body");
                let captured = CapturedRequest {
                    method: request.method().as_str().to_string(),
                    url: request.url().to_string(),
                    headers: request
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.as_str().as_str().to_string(),
                                h.value.as_str().to_string(),
                            )
                        })
                        .collect(),
                    body: captured_body,
                };
                let _ = tx.send(captured);

                let mut response =
                    TinyResponse::from_data(body).with_status_code(StatusCode(status));
                for (name, value) in headers {
                    if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                        response.add_header(header);
                    }
                }
                let _ = request.respond(response);
            }
        });

        (endpoint, rx, handle)
    }

    fn spawn_delayed_s3_response(
        delay: Duration,
        scripted_response: ScriptedResponse,
    ) -> (
        Url,
        mpsc::Receiver<CapturedRequest>,
        std::thread::JoinHandle<()>,
    ) {
        let server = Server::http("127.0.0.1:0").expect("bind delayed S3 test server");
        let port = server
            .server_addr()
            .to_ip()
            .expect("loopback server has an IP addr")
            .port();
        let endpoint =
            Url::parse(&format!("http://127.0.0.1:{port}")).expect("valid test endpoint url");
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut request = server
                .recv_timeout(Duration::from_secs(5))
                .expect("receive delayed S3 request")
                .expect("delayed S3 request is present");
            let mut captured_body = Vec::new();
            request
                .as_reader()
                .read_to_end(&mut captured_body)
                .expect("read delayed S3 request body");
            tx.send(CapturedRequest {
                method: request.method().as_str().to_string(),
                url: request.url().to_string(),
                headers: request
                    .headers()
                    .iter()
                    .map(|header| {
                        (
                            header.field.as_str().as_str().to_string(),
                            header.value.as_str().to_string(),
                        )
                    })
                    .collect(),
                body: captured_body,
            })
            .expect("capture delayed S3 request");

            std::thread::sleep(delay);
            let (status, headers, body) = scripted_response;
            let mut response = TinyResponse::from_data(body).with_status_code(StatusCode(status));
            for (name, value) in headers {
                response.add_header(
                    Header::from_bytes(name.as_bytes(), value.as_bytes())
                        .expect("valid delayed S3 response header"),
                );
            }
            request.respond(response).expect("send delayed S3 response");
        });
        (endpoint, rx, handle)
    }

    fn test_config(endpoint: Url) -> S3ObjectStoreConfig {
        S3ObjectStoreConfig {
            endpoint,
            bucket: "ylx-test-bucket".to_string(),
            region: "us-east-1".to_string(),
            url_style: UrlStyle::Path,
            access_key: "TESTKEYID".to_string(),
            secret_key: "test-secret-key-value".to_string(),
            request_timeout: Duration::from_secs(5),
        }
    }

    fn spawn_slow_s3_body_server(chunk_gap: Duration) -> (Url, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind slow S3 server");
        let endpoint = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("read S3 server address")
        ))
        .expect("valid slow S3 endpoint");
        let handle = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let (mut stream, _) = listener.accept().expect("accept signed GET");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set request read timeout");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).expect("read signed GET headers");
                if count == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..count]);
            }

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\nConnection: close\r\n\r\na",
                )
                .expect("write first stored byte");
            stream.flush().expect("flush first stored byte");
            std::thread::sleep(chunk_gap);
            if stream.write_all(b"b").is_err() {
                return;
            }
            let _ = stream.flush();
            std::thread::sleep(chunk_gap);
            let _ = stream.write_all(b"c");
            let _ = stream.flush();
        });
        (endpoint, handle)
    }

    #[test]
    fn streamed_readback_timeout_is_idle_not_total_transfer_duration() {
        let idle_timeout = Duration::from_secs(1);
        let chunk_gap = Duration::from_millis(600);
        assert!(chunk_gap < idle_timeout);

        let (endpoint, server) = spawn_slow_s3_body_server(chunk_gap);
        let mut config = test_config(endpoint);
        config.request_timeout = idle_timeout;
        let store = S3ObjectStore::new(config).expect("adapter constructs");

        let started_at = std::time::Instant::now();
        let (digest, size) = store
            .streamed_content_digest(&ObjectKey("session/video.mp4".to_string()), None)
            .expect("regular read progress must keep S3 verification alive");
        let elapsed = started_at.elapsed();
        server.join().expect("slow S3 server exits cleanly");

        assert!(
            elapsed > idle_timeout,
            "test transfer must exceed the configured idle timeout to prove it is not cumulative"
        );
        assert_eq!(size, 3);
        assert_eq!(
            digest,
            SourceSha256::from_bytes(Sha256::digest(b"abc").into())
        );
    }

    #[test]
    fn initiate_signs_and_sends_source_sha256_metadata_header() {
        let create_response_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>ylx-test-bucket</Bucket>
  <Key>session/video.mp4</Key>
  <UploadId>fake-upload-id-1</UploadId>
</InitiateMultipartUploadResult>"#
            .to_vec();

        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(200, vec![], create_response_xml)]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let sha = SourceSha256::from_bytes([0x42; 32]);
        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("session/video.mp4".to_string()),
            content_length: 100,
            source_sha256: sha,
            content_type: Some("video/mp4".to_string()),
        });

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let handle_result = result.expect("initiate succeeds against the fake server");
        assert_eq!(handle_result.upload_id.0, "fake-upload-id-1");

        assert_eq!(captured.method, "POST");
        assert!(
            captured.url.contains("uploads=1"),
            "url was {}",
            captured.url
        );
        assert!(
            captured.url.contains("X-Amz-Signature="),
            "request must be SigV4-signed: {}",
            captured.url
        );
        let sha_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(super::SOURCE_SHA256_META_HEADER));
        assert_eq!(
            sha_header.map(|(_, v)| v.as_str()),
            Some(sha.to_hex().as_str()),
            "the exact header signed via headers_mut() must be present on the wire request"
        );
    }

    #[test]
    fn upload_part_reads_etag_from_response_header() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![("ETag", "\"part-etag-value\"".to_string())],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let upload_handle = MultipartUploadHandle {
            key: ObjectKey("session/video.mp4".to_string()),
            upload_id: UploadId("fake-upload-id-1".to_string()),
        };
        let part_number = PartNumber::new(1).expect("valid part number");
        let result = store.upload_part(&upload_handle, part_number, b"some part bytes");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let part_etag = result.expect("upload_part succeeds against the fake server");
        assert_eq!(
            part_etag.etag, "part-etag-value",
            "surrounding quotes must be stripped"
        );
        assert_eq!(captured.method, "PUT");
        assert!(
            captured.url.contains("partNumber=1"),
            "url was {}",
            captured.url
        );
        assert!(
            captured.url.contains("uploadId=fake-upload-id-1"),
            "url was {}",
            captured.url
        );
        assert_eq!(captured.body, b"some part bytes");
    }

    #[test]
    fn simulated_403_maps_to_structured_auth_error_not_panic() {
        let error_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match</Message>
</Error>"#
            .to_vec();
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(403, vec![], error_xml)]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: SourceSha256::from_bytes([1; 32]),
            content_type: None,
        });

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(ObjectStoreError::Auth {
                status: 403,
                detail,
            }) => {
                assert_eq!(detail, "The request signature we calculated does not match");
            }
            other => panic!("expected structured Auth error, got {other:?}"),
        }
    }

    struct CountingReader {
        remaining: usize,
        bytes_read: Arc<AtomicUsize>,
    }

    impl std::io::Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = buffer.len().min(self.remaining);
            buffer[..read].fill(b'Z');
            self.remaining -= read;
            self.bytes_read.fetch_add(read, Ordering::Relaxed);
            Ok(read)
        }
    }

    #[test]
    fn buffered_response_reader_never_consumes_more_than_the_limit_probe() {
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: MAX_BUFFERED_RESPONSE_BODY_BYTES * 64,
            bytes_read: Arc::clone(&bytes_read),
        };

        let (body, truncated) =
            read_bounded_response_body(reader).expect("bounded reader succeeds");

        assert!(truncated);
        assert_eq!(body.len(), MAX_BUFFERED_RESPONSE_BODY_BYTES);
        assert_eq!(
            bytes_read.load(Ordering::Relaxed),
            MAX_BUFFERED_RESPONSE_BODY_BYTES + 1,
            "one extra byte is the complete truncation probe; the rest is never read"
        );
    }

    #[test]
    fn oversized_server_error_body_is_bounded_and_reports_truncation() {
        let body = vec![b'Z'; MAX_BUFFERED_RESPONSE_BODY_BYTES * 16];
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(503, vec![], body)]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: SourceSha256::from_bytes([1; 32]),
            content_type: None,
        });

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(ObjectStoreError::ServerError {
                status: 503,
                detail,
            }) => {
                assert_eq!(
                    detail.len(),
                    MAX_REMOTE_ERROR_TEXT_BYTES
                        + REMOTE_TEXT_TRUNCATION_MARKER.len()
                        + 1
                        + RESPONSE_BODY_TRUNCATION_MARKER.len()
                );
                assert!(detail.contains(REMOTE_TEXT_TRUNCATION_MARKER));
                assert!(detail.ends_with(RESPONSE_BODY_TRUNCATION_MARKER));
            }
            other => panic!("expected bounded ServerError, got {other:?}"),
        }
    }

    #[test]
    fn malformed_error_bytes_are_lossy_and_control_characters_are_sanitized() {
        let body = b"backend \xff\xfe failed\r\n\x1b[2J".to_vec();
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(500, vec![], body)]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: SourceSha256::from_bytes([1; 32]),
            content_type: None,
        });

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(ObjectStoreError::ServerError { detail, .. }) => {
                assert!(detail.contains("backend"));
                assert!(detail.contains('\u{fffd}'));
                assert!(!detail.chars().any(char::is_control), "detail: {detail:?}");
            }
            other => panic!("expected sanitized ServerError, got {other:?}"),
        }
    }

    #[test]
    fn error_xml_cannot_echo_configured_credentials_or_terminal_controls() {
        let error_xml = b"<Error><Code>InternalError</Code><Message>access=TESTKEYID secret=test-secret-key-value \x1b[31mforged\x1b[0m</Message></Error>".to_vec();
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(500, vec![], error_xml)]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: SourceSha256::from_bytes([1; 32]),
            content_type: None,
        });

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        match result {
            Err(ObjectStoreError::ServerError { detail, .. }) => {
                assert!(!detail.contains("TESTKEYID"), "detail: {detail:?}");
                assert!(
                    !detail.contains("test-secret-key-value"),
                    "detail: {detail:?}"
                );
                assert_eq!(detail.matches("<redacted>").count(), 2);
                assert!(detail.contains("forged"));
                assert!(!detail.chars().any(char::is_control), "detail: {detail:?}");
            }
            other => panic!("expected credential-safe ServerError, got {other:?}"),
        }
    }

    #[test]
    fn simulated_500_maps_to_structured_server_error_not_panic() {
        let error_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InternalError</Code>
  <Message>We encountered an internal error</Message>
</Error>"#
            .to_vec();
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(500, vec![], error_xml)]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: SourceSha256::from_bytes([1; 32]),
            content_type: None,
        });

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        assert!(matches!(
            result,
            Err(ObjectStoreError::ServerError { status: 500, .. })
        ));
    }

    #[test]
    fn simulated_429_maps_to_rate_limited_with_retry_after() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            429,
            vec![("Retry-After", "2".to_string())],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: SourceSha256::from_bytes([1; 32]),
            content_type: None,
        });

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        assert_eq!(
            result,
            Err(ObjectStoreError::RateLimited {
                retry_after_ms: Some(2000)
            })
        );
    }

    #[test]
    fn head_object_404_maps_to_not_found() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(404, vec![], Vec::new())]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.verify_object(
            &ObjectKey("missing".to_string()),
            &ExpectedObject {
                size_bytes: 1,
                source_sha256: SourceSha256::from_bytes([1; 32]),
            },
        );

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        assert_eq!(
            result,
            Err(ObjectStoreError::NotFound(ObjectKey("missing".to_string())))
        );
    }

    #[test]
    fn head_response_with_gzip_encoding_and_no_body_is_not_read() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                ("Content-Length", "1479".to_string()),
                ("Content-Encoding", "gzip".to_string()),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint.clone())).expect("adapter constructs");

        let result = store.send(
            ureq::http::Method::HEAD,
            endpoint
                .join("/ylx-test-bucket/session/publication.json")
                .expect("valid object URL"),
            &[],
            Vec::new(),
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let response = result.expect(
            "HEAD has no response body, so Content-Encoding must not trigger body decompression",
        );
        assert_eq!(captured.method, "HEAD");
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
        assert_eq!(
            captured
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
                .map(|(_, value)| value.as_str()),
            Some("identity"),
            "HEAD must not advertise transparent compression because verification needs the original Content-Length"
        );
    }

    /// Issue #1, commit 70: credentials, presigned URLs and object bytes
    /// must not travel in plaintext — except on loopback, where a local
    /// MinIO is a normal dev/CI setup.
    #[test]
    fn plaintext_remote_endpoints_are_refused_but_loopback_is_allowed() {
        let mut plaintext_remote =
            test_config(Url::parse("http://minio.example.internal:9000").expect("valid test url"));
        plaintext_remote.url_style = UrlStyle::Path;
        match S3ObjectStore::new(plaintext_remote) {
            Err(ObjectStoreError::Config(detail)) => {
                assert!(
                    detail.contains("https"),
                    "the rejection must say what is required, got {detail}"
                );
            }
            Err(other) => panic!("expected a Config rejection, got {other:?}"),
            Ok(_) => panic!("a plaintext remote endpoint must be refused"),
        }

        assert!(S3ObjectStore::new(test_config(
            Url::parse("https://minio.example.internal:9000").expect("valid test url")
        ))
        .is_ok());
        assert!(S3ObjectStore::new(test_config(
            Url::parse("http://127.0.0.1:9000").expect("valid test url")
        ))
        .is_ok());
        assert!(S3ObjectStore::new(test_config(
            Url::parse("http://localhost:9000").expect("valid test url")
        ))
        .is_ok());
        assert!(S3ObjectStore::new(test_config(
            Url::parse("http://[::1]:9000").expect("valid test url")
        ))
        .is_ok());
    }

    /// A presigned request's signature covers one host and path. Following
    /// a redirect would hand that URL to whatever host the redirect names
    /// and verify bytes that host chose — so a 3xx is a hard failure.
    #[test]
    fn a_redirect_is_an_explicit_failure_and_is_never_followed() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            302,
            vec![(
                "Location",
                "https://attacker.example/ylx-test-bucket/session/video.mp4".to_string(),
            )],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.verify_object(
            &ObjectKey("session/video.mp4".to_string()),
            &ExpectedObject {
                size_bytes: 4,
                source_sha256: SourceSha256::from_bytes([1; 32]),
            },
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        assert_eq!(captured.method, "HEAD");
        match result {
            Err(ObjectStoreError::UnexpectedRedirect { status, location }) => {
                assert_eq!(status, 302);
                assert_eq!(
                    location.as_deref(),
                    Some("https://attacker.example/ylx-test-bucket/session/video.mp4")
                );
            }
            other => panic!("a redirect must fail explicitly, got {other:?}"),
        }
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "the redirect target must never be requested"
        );
    }

    /// Commit 70: matching metadata is not proof. With no server-side
    /// checksum the adapter must read the object back and re-hash it.
    #[test]
    fn metadata_that_matches_but_bytes_that_do_not_fails_on_content_digest() {
        let stored = b"the bytes actually stored".to_vec();
        let claimed = SourceSha256::from_bytes(Sha256::digest(b"what the metadata claims").into());
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![
            (
                200,
                vec![
                    ("ETag", "\"etag-1\"".to_string()),
                    ("Content-Length", stored.len().to_string()),
                    (super::SOURCE_SHA256_META_HEADER, claimed.to_hex()),
                ],
                Vec::new(),
            ),
            (200, vec![], stored.clone()),
        ]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.verify_object(
            &ObjectKey("session/video.mp4".to_string()),
            &ExpectedObject {
                size_bytes: stored.len() as u64,
                source_sha256: claimed,
            },
        );

        let head = rx.recv_timeout(Duration::from_secs(5)).expect("HEAD sent");
        let get = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the object must be streamed back when no server checksum exists");
        handle.join().expect("server thread exits cleanly");

        assert_eq!(head.method, "HEAD");
        assert_eq!(get.method, "GET");
        match result {
            Err(ObjectStoreError::DigestMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(expected, claimed);
                assert_eq!(
                    actual,
                    SourceSha256::from_bytes(Sha256::digest(&stored).into())
                );
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    /// A trusted full-object checksum makes the extra read unnecessary —
    /// and the receipt says which proof was used.
    #[test]
    fn a_full_object_server_checksum_is_trusted_and_skips_the_read_back() {
        let content = b"server-checksummed object".to_vec();
        let digest = SourceSha256::from_bytes(Sha256::digest(&content).into());
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                ("ETag", "\"etag-1\"".to_string()),
                ("Content-Length", content.len().to_string()),
                (super::SOURCE_SHA256_META_HEADER, digest.to_hex()),
                (super::CHECKSUM_SHA256_HEADER, BASE64.encode(digest.0)),
                (super::CHECKSUM_TYPE_HEADER, "FULL_OBJECT".to_string()),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let receipt = store
            .verify_object(
                &ObjectKey("session/video.mp4".to_string()),
                &ExpectedObject {
                    size_bytes: content.len() as u64,
                    source_sha256: digest,
                },
            )
            .expect("a matching trusted checksum verifies");

        let _ = rx.recv_timeout(Duration::from_secs(5)).expect("HEAD sent");
        handle.join().expect("server thread exits cleanly");

        assert_eq!(receipt.digest_proof, DigestProof::ServerChecksum);
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "a trusted full-object checksum must not trigger a read-back"
        );
    }

    /// A *composite* checksum is a checksum of part checksums — the same
    /// trap a multipart ETag is. It must not be mistaken for content.
    #[test]
    fn a_composite_server_checksum_falls_back_to_the_streamed_read_back() {
        let content = b"composite-checksummed object".to_vec();
        let digest = SourceSha256::from_bytes(Sha256::digest(&content).into());
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![
            (
                200,
                vec![
                    ("ETag", "\"etag-2\"".to_string()),
                    ("Content-Length", content.len().to_string()),
                    (super::SOURCE_SHA256_META_HEADER, digest.to_hex()),
                    (
                        super::CHECKSUM_SHA256_HEADER,
                        format!("{}-2", BASE64.encode([0u8; 32])),
                    ),
                ],
                Vec::new(),
            ),
            (200, vec![], content.clone()),
        ]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let receipt = store
            .verify_object(
                &ObjectKey("session/video.mp4".to_string()),
                &ExpectedObject {
                    size_bytes: content.len() as u64,
                    source_sha256: digest,
                },
            )
            .expect("the streamed read-back proves the content");

        let _ = rx.recv_timeout(Duration::from_secs(5)).expect("HEAD sent");
        let get = rx.recv_timeout(Duration::from_secs(5)).expect("GET sent");
        handle.join().expect("server thread exits cleanly");

        assert_eq!(get.method, "GET");
        assert_eq!(receipt.digest_proof, DigestProof::StreamedReadback);
    }

    /// Present-but-unusable checksum material fails closed rather than
    /// quietly downgrading to a metadata-only "verification".
    #[test]
    fn malformed_or_absent_checksum_material_fails_closed() {
        let content = b"x".to_vec();
        let digest = SourceSha256::from_bytes(Sha256::digest(&content).into());

        // 1. A checksum header nobody can decode.
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                ("ETag", "\"etag-3\"".to_string()),
                ("Content-Length", "1".to_string()),
                (super::SOURCE_SHA256_META_HEADER, digest.to_hex()),
                (super::CHECKSUM_SHA256_HEADER, "@@@notbase64@@@".to_string()),
                (super::CHECKSUM_TYPE_HEADER, "FULL_OBJECT".to_string()),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");
        let result = store.verify_object(
            &ObjectKey("k".to_string()),
            &ExpectedObject {
                size_bytes: 1,
                source_sha256: digest,
            },
        );
        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");
        assert!(
            matches!(result, Err(ObjectStoreError::MalformedChecksum { .. })),
            "undecodable checksum must fail closed, got {result:?}"
        );

        // 2. A base64 value that is not a SHA-256 at all.
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                ("ETag", "\"etag-4\"".to_string()),
                ("Content-Length", "1".to_string()),
                (super::SOURCE_SHA256_META_HEADER, digest.to_hex()),
                (super::CHECKSUM_SHA256_HEADER, BASE64.encode([0u8; 8])),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");
        let result = store.verify_object(
            &ObjectKey("k".to_string()),
            &ExpectedObject {
                size_bytes: 1,
                source_sha256: digest,
            },
        );
        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");
        assert!(
            matches!(result, Err(ObjectStoreError::MalformedChecksum { .. })),
            "a short checksum must fail closed, got {result:?}"
        );

        // 3. No source digest metadata at all.
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                ("ETag", "\"etag-5\"".to_string()),
                ("Content-Length", "1".to_string()),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");
        let result = store.verify_object(
            &ObjectKey("k".to_string()),
            &ExpectedObject {
                size_bytes: 1,
                source_sha256: digest,
            },
        );
        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");
        assert!(
            matches!(result, Err(ObjectStoreError::MalformedChecksum { .. })),
            "an object with no source digest must fail closed, got {result:?}"
        );
    }

    /// Commit 69: the HEAD must be pinned to the completion's version, and
    /// an object that is not the completed one must be rejected outright.
    #[test]
    fn verify_completed_object_pins_the_version_and_rejects_another_writers_object() {
        let content = b"mine".to_vec();
        let digest = SourceSha256::from_bytes(Sha256::digest(&content).into());
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                // What is at the key now is someone else's object.
                ("ETag", "\"their-etag\"".to_string()),
                ("Content-Length", content.len().to_string()),
                ("x-amz-version-id", "v-theirs".to_string()),
                (super::SOURCE_SHA256_META_HEADER, digest.to_hex()),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let completion = CompletedUpload {
            key: ObjectKey("session/video.mp4".to_string()),
            upload_id: UploadId("upload-1".to_string()),
            etag: "my-etag".to_string(),
            version_id: Some("v-mine".to_string()),
        };
        let result = store.verify_completed_object(
            &completion,
            &ExpectedObject {
                size_bytes: content.len() as u64,
                source_sha256: digest,
            },
        );

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        assert!(
            captured.url.contains("versionId=v-mine"),
            "the read must be pinned to the completed version, url was {}",
            captured.url
        );
        assert!(
            matches!(result, Err(ObjectStoreError::CompletionMismatch { .. })),
            "another writer's object must be an explicit binding failure, got {result:?}"
        );
    }

    #[test]
    fn head_object_metadata_mismatch_fails_verification_not_silently_accepted() {
        let sha = SourceSha256::from_bytes([9; 32]);
        let wrong_sha = SourceSha256::from_bytes([0xAA; 32]);
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![
                ("ETag", "\"deadbeef-2\"".to_string()),
                ("Content-Length", "42".to_string()),
                (super::SOURCE_SHA256_META_HEADER, wrong_sha.to_hex()),
            ],
            Vec::new(),
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let result = store.verify_object(
            &ObjectKey("session/video.mp4".to_string()),
            &ExpectedObject {
                size_bytes: 42,
                source_sha256: sha,
            },
        );

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        assert!(matches!(
            result,
            Err(ObjectStoreError::VerificationMismatch { .. })
        ));
    }

    #[test]
    fn complete_multipart_upload_parses_etag_and_sends_xml_body() {
        let complete_response_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://127.0.0.1/ylx-test-bucket/session/video.mp4</Location>
  <Bucket>ylx-test-bucket</Bucket>
  <Key>session/video.mp4</Key>
  <ETag>&#34;combined-etag-value-2&#34;</ETag>
</CompleteMultipartUploadResult>"#
            .to_vec();
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(
            200,
            vec![("x-amz-version-id", "v1".to_string())],
            complete_response_xml,
        )]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let upload_handle = MultipartUploadHandle {
            key: ObjectKey("session/video.mp4".to_string()),
            upload_id: UploadId("fake-upload-id-1".to_string()),
        };
        let parts = vec![
            ylx_transfer_core::library::object_store_port::PartETag {
                part_number: PartNumber::new(1).unwrap(),
                etag: "etag-part-1".to_string(),
            },
            ylx_transfer_core::library::object_store_port::PartETag {
                part_number: PartNumber::new(2).unwrap(),
                etag: "etag-part-2".to_string(),
            },
        ];

        let result = store.complete_multipart_upload(&upload_handle, parts);

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        let completed = result.expect("complete succeeds against the fake server");
        assert_eq!(completed.etag, "combined-etag-value-2");
        assert_eq!(completed.version_id.as_deref(), Some("v1"));
        assert_eq!(captured.method, "POST");
        assert!(captured.url.contains("uploadId=fake-upload-id-1"));
        let body_str = String::from_utf8_lossy(&captured.body);
        assert!(
            body_str.contains("<ETag>etag-part-1</ETag>"),
            "body was {body_str}"
        );
        assert!(
            body_str.contains("<PartNumber>2</PartNumber>"),
            "body was {body_str}"
        );
    }

    #[test]
    fn complete_multipart_upload_is_not_limited_by_short_control_timeout() {
        let response = br#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://127.0.0.1/ylx-test-bucket/session/video.mp4</Location>
  <Bucket>ylx-test-bucket</Bucket>
  <Key>session/video.mp4</Key>
  <ETag>&#34;delayed-complete-etag-1&#34;</ETag>
</CompleteMultipartUploadResult>"#
            .to_vec();
        let (endpoint, rx, server) =
            spawn_delayed_s3_response(Duration::from_millis(250), (200, vec![], response));
        let mut config = test_config(endpoint);
        config.request_timeout = Duration::from_millis(100);
        let store = S3ObjectStore::new(config).expect("adapter constructs");
        let upload = MultipartUploadHandle {
            key: ObjectKey("session/video.mp4".to_string()),
            upload_id: UploadId("delayed-complete-upload".to_string()),
        };

        let completed = store
            .complete_multipart_upload(
                &upload,
                vec![ylx_transfer_core::library::object_store_port::PartETag {
                    part_number: PartNumber::new(1).unwrap(),
                    etag: "part-one".to_string(),
                }],
            )
            .expect("remote multipart assembly may outlive the control-call timeout");

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured delayed completion request");
        server.join().expect("delayed S3 server exits cleanly");
        assert_eq!(captured.method, "POST");
        assert_eq!(completed.etag, "delayed-complete-etag-1");
    }

    #[test]
    fn completed_etag_normalizes_aws_and_numeric_quote_entities() {
        for raw in [
            "&quot;combined-etag-2&quot;",
            "&#34;combined-etag-2&#34;",
            "&#x22;combined-etag-2&#x22;",
            "\"combined-etag-2\"",
        ] {
            assert_eq!(super::normalize_completed_etag(raw), "combined-etag-2");
        }
    }

    #[test]
    fn abort_multipart_upload_sends_delete_and_treats_204_as_success() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(204, vec![], Vec::new())]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let upload_handle = MultipartUploadHandle {
            key: ObjectKey("session/video.mp4".to_string()),
            upload_id: UploadId("fake-upload-id-1".to_string()),
        };
        let result = store.abort_multipart_upload(&upload_handle);

        let captured = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server captured a request");
        handle.join().expect("server thread exits cleanly");

        assert!(result.is_ok());
        assert_eq!(captured.method, "DELETE");
        assert!(captured.url.contains("uploadId=fake-upload-id-1"));
    }

    #[test]
    fn abort_multipart_upload_404_maps_to_unknown_upload_not_panic() {
        let (endpoint, rx, handle) = spawn_fake_s3_server(vec![(404, vec![], Vec::new())]);
        let store = S3ObjectStore::new(test_config(endpoint)).expect("adapter constructs");

        let upload_handle = MultipartUploadHandle {
            key: ObjectKey("session/video.mp4".to_string()),
            upload_id: UploadId("gone-upload-id".to_string()),
        };
        let result = store.abort_multipart_upload(&upload_handle);

        let _ = rx.recv_timeout(Duration::from_secs(5));
        handle.join().expect("server thread exits cleanly");

        assert_eq!(
            result,
            Err(ObjectStoreError::UnknownUpload(UploadId(
                "gone-upload-id".to_string()
            )))
        );
    }
}
