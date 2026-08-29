//! An in-process S3-compatible backend, good enough to run the whole
//! `ObjectStorePort` contract against the *production* `S3ObjectStore`
//! (issue #1, commits 69/70).
//!
//! The adapter's own unit tests script one canned response per request,
//! which proves wire-format handling but cannot express a multi-request
//! property like "verify the version this completion produced, after
//! someone else overwrote the key". This module is therefore a real (if
//! small) stateful backend: multipart uploads, parts, completions, object
//! versions, HEAD, GET, DELETE — reached over a real loopback socket by
//! real presigned SigV4 requests.
//!
//! It also does the one thing a real MinIO cannot be asked to do directly:
//! fail on command. [`FakeS3::arm`] makes the next request of a given kind
//! answer `429`, `500`, or simply die mid-flight, which lets the default lane
//! run the shared contract suite's retry/network-loss cases quickly. The
//! ignored MinIO lane has an equivalent [`FaultProxy`] when its runner sets
//! `YLX_MINIO_FAULT_PROXY=1`, so those cases still use real MinIO multipart
//! semantics rather than being quietly counted as passed.
//!
//! What it deliberately does **not** do: validate SigV4. Independent
//! verification that a real S3-compatible server accepts these requests is
//! the MinIO lane's job (and the pre-existing `oss_real_integration`
//! probe's).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rusty_s3::actions::{CreateBucket, DeleteBucket, S3Action};
use rusty_s3::{Bucket, Credentials};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Request, Response, Server, StatusCode};
use ureq::http;
use ureq::Agent;
use url::Url;
use ylx_transfer_adapters::object_store_s3::{S3ObjectStore, S3ObjectStoreConfig, UrlStyle};
use ylx_transfer_core::library::object_store_contract::{
    ContractFault, ContractFaultInjector, ContractOp, ObjectStoreContractHarness,
};
use ylx_transfer_core::library::object_store_port::{
    CompletedUpload, ExpectedObject, ImmutableObjectRequest, InitiateUploadRequest,
    MultipartUploadHandle, ObjectKey, ObjectListPage, ObjectReadback, ObjectStoreError,
    ObjectStorePort, PartETag, PartNumber, VerifiedObjectReceipt,
};

pub const BUCKET: &str = "ylx-contract-bucket";
const SOURCE_SHA256_META_HEADER: &str = "x-amz-meta-source-sha256";

/// Whether completions hand back a version id. Both shapes are real (S3
/// with versioning on, plain MinIO/OSS without) and commit 69's binding
/// resolves differently — but always explicitly — on each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Versioning {
    Enabled,
    Disabled,
}

/// Which kind of request a fault applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Op {
    Initiate,
    UploadPart,
    Complete,
    Head,
}

#[derive(Debug, Clone, Copy)]
enum Fault {
    RateLimited,
    ServerError,
    NetworkLoss,
}

#[derive(Debug, Clone)]
struct StoredObject {
    bytes: Vec<u8>,
    etag: String,
    version_id: Option<String>,
    meta_sha: Option<String>,
}

#[derive(Debug, Default)]
struct Upload {
    key: String,
    meta_sha: Option<String>,
    parts: BTreeMap<u16, Vec<u8>>,
}

#[derive(Default)]
struct State {
    uploads: HashMap<String, Upload>,
    objects: HashMap<String, Vec<StoredObject>>,
    faults: HashMap<Op, VecDeque<Fault>>,
    seq: u64,
}

pub struct FakeS3 {
    endpoint: Url,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl FakeS3 {
    pub fn start(versioning: Versioning) -> Self {
        let server = Server::http("127.0.0.1:0").expect("bind loopback fake S3");
        let port = server
            .server_addr()
            .to_ip()
            .expect("loopback server has an IP addr")
            .port();
        let endpoint = Url::parse(&format!("http://127.0.0.1:{port}")).expect("valid endpoint url");

        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match server.recv_timeout(Duration::from_millis(50)) {
                    Ok(Some(request)) => handle(request, &thread_state, versioning),
                    Ok(None) => continue,
                    Err(_) => break,
                }
            }
        });

        Self {
            endpoint,
            state,
            stop,
            join: Some(join),
        }
    }

    pub fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn arm(&self, op: Op, fault: Fault) {
        self.state
            .lock()
            .expect("fake S3 state")
            .faults
            .entry(op)
            .or_default()
            .push_back(fault);
    }
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// A loopback HTTP fault proxy for the real MinIO lane.
///
/// MinIO is intentionally not made flaky by changing the server itself. The
/// proxy sits between the adapter and MinIO, forwards signed requests without
/// changing their path/query/Host, and can fail one operation at a time with
/// the same transport outcomes the shared contract suite expects. Keeping the
/// fault injection here means the MinIO lane still exercises real SigV4
/// signing, MinIO's multipart implementation, and streamed read-back.
struct FaultProxy {
    endpoint: Url,
    state: Arc<Mutex<ProxyState>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct ProxyState {
    faults: HashMap<Op, VecDeque<Fault>>,
}

impl FaultProxy {
    fn start(upstream: Url) -> Self {
        let server = Server::http("127.0.0.1:0").expect("bind MinIO fault proxy");
        let port = server
            .server_addr()
            .to_ip()
            .expect("fault proxy has an IP addr")
            .port();
        let endpoint = Url::parse(&format!("http://127.0.0.1:{port}"))
            .expect("fault proxy endpoint is a valid URL");
        let state = Arc::new(Mutex::new(ProxyState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let agent = Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .build()
                .into();
            while !thread_stop.load(Ordering::Relaxed) {
                match server.recv_timeout(Duration::from_millis(50)) {
                    Ok(Some(request)) => proxy_request(request, &upstream, &agent, &thread_state),
                    Ok(None) => continue,
                    Err(_) => break,
                }
            }
        });

        Self {
            endpoint,
            state,
            stop,
            join: Some(join),
        }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn arm(&self, op: Op, fault: Fault) {
        self.state
            .lock()
            .expect("MinIO fault proxy state")
            .faults
            .entry(op)
            .or_default()
            .push_back(fault);
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn proxy_request(
    mut request: Request,
    upstream: &Url,
    agent: &Agent,
    state: &Arc<Mutex<ProxyState>>,
) {
    let raw_url = request.url().to_string();
    let method = request.method().as_str().to_string();
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let (_path, query) = split_query(&raw_url);
    let op = classify(&method, &query);

    let mut body = Vec::new();
    if request.as_reader().read_to_end(&mut body).is_err() {
        drop(request.into_writer());
        return;
    }

    if let Some(op) = op {
        let fault = state
            .lock()
            .expect("MinIO fault proxy state")
            .faults
            .get_mut(&op)
            .and_then(VecDeque::pop_front);
        match fault {
            Some(Fault::NetworkLoss) => {
                // A dropped writer is deliberately different from an HTTP
                // 5xx: the adapter must classify it as ObjectStoreError::Network.
                drop(request.into_writer());
                return;
            }
            Some(Fault::RateLimited) => {
                respond(
                    request,
                    429,
                    vec![("Retry-After", "1".to_string())],
                    error_xml("SlowDown", "fault proxy rate limit"),
                );
                return;
            }
            Some(Fault::ServerError) => {
                respond(
                    request,
                    503,
                    vec![],
                    error_xml("InternalError", "fault proxy server error"),
                );
                return;
            }
            None => {}
        }
    }

    let target = format!("{}{}", upstream.as_str().trim_end_matches('/'), raw_url);
    let mut builder = http::Request::builder().method(method.as_str()).uri(target);
    for header in request.headers() {
        let name = header.field.as_str().as_str();
        let value = header.value.as_str();
        // ureq derives Content-Length from the body. Duplicating the incoming
        // value can make an upstream parser reject a perfectly valid signed
        // request; every signed header that matters (especially Host) is
        // preserved below.
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(name, value);
    }
    let upstream_request = match builder.body(body) {
        Ok(request) => request,
        Err(_) => {
            respond(
                request,
                502,
                vec![],
                error_xml("BadGateway", "fault proxy request body error"),
            );
            return;
        }
    };
    let mut response = match agent.run(upstream_request) {
        Ok(response) => response,
        Err(_) => {
            respond(
                request,
                502,
                vec![],
                error_xml("BadGateway", "fault proxy could not reach MinIO"),
            );
            return;
        }
    };
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_body = response.body_mut().read_to_vec().unwrap_or_default();
    let mut proxied = Response::from_data(response_body).with_status_code(StatusCode(status));
    for (name, value) in &response_headers {
        // tiny_http computes the body length for body-bearing responses.
        // HEAD is different: its empty response body still carries the size
        // of the selected object, so preserve the upstream Content-Length.
        // Transfer-Encoding belongs to the ureq-to-proxy hop and must never
        // be replayed to the adapter.
        if name.as_str().eq_ignore_ascii_case("transfer-encoding")
            || (name.as_str().eq_ignore_ascii_case("content-length") && !is_head)
        {
            continue;
        }
        if let Ok(header) = Header::from_bytes(name.as_str().as_bytes(), value.as_bytes()) {
            proxied.add_header(header);
        }
    }
    if is_head {
        // tiny_http otherwise switches known lengths >= 32 KiB to chunked
        // transfer and omits Content-Length. A HEAD response has no body to
        // chunk, and its Content-Length describes the selected representation.
        proxied = proxied.with_chunked_threshold(usize::MAX);
    }
    let _ = request.respond(proxied);
}

// ---------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------

fn handle(mut request: Request, state: &Arc<Mutex<State>>, versioning: Versioning) {
    let raw_url = request.url().to_string();
    let method = request.method().as_str().to_string();
    let (path, query) = split_query(&raw_url);
    let key = object_key_from_path(&path);
    let meta_sha = request
        .headers()
        .iter()
        .find(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case(SOURCE_SHA256_META_HEADER)
        })
        .map(|h| h.value.as_str().to_string());

    let mut body = Vec::new();
    let _ = request.as_reader().read_to_end(&mut body);

    let op = classify(&method, &query);
    if let Some(op) = op {
        let fault = state
            .lock()
            .expect("fake S3 state")
            .faults
            .get_mut(&op)
            .and_then(VecDeque::pop_front);
        match fault {
            Some(Fault::NetworkLoss) => {
                // Take the raw socket away from tiny_http and drop the
                // writer without answering. The client is left waiting on
                // a request that will never be completed — a partition,
                // the form of network loss that has no status code and no
                // clean FIN — and must surface it as a structured
                // `Network` error once its own timeout expires, not as a
                // panic or a bogus status. (Dropping the `Request` itself
                // would make tiny_http politely send an empty 500, which
                // is a *server error*, not connection loss.)
                drop(request.into_writer());
                return;
            }
            Some(Fault::RateLimited) => {
                respond(
                    request,
                    429,
                    vec![("Retry-After", "1".to_string())],
                    error_xml("SlowDown", "Please reduce your request rate"),
                );
                return;
            }
            Some(Fault::ServerError) => {
                respond(
                    request,
                    503,
                    vec![],
                    error_xml("InternalError", "simulated backend failure"),
                );
                return;
            }
            None => {}
        }
    }

    let mut state = state.lock().expect("fake S3 state");
    match (method.as_str(), op) {
        ("POST", Some(Op::Initiate)) => {
            state.seq += 1;
            let upload_id = format!("fake-upload-{}", state.seq);
            state.uploads.insert(
                upload_id.clone(),
                Upload {
                    key: key.clone(),
                    meta_sha,
                    parts: BTreeMap::new(),
                },
            );
            respond(
                request,
                200,
                vec![],
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{BUCKET}</Bucket>\
                     <Key>{key}</Key><UploadId>{upload_id}</UploadId>\
                     </InitiateMultipartUploadResult>"
                )
                .into_bytes(),
            );
        }
        ("PUT", Some(Op::UploadPart)) => {
            let Some(upload_id) = query_value(&query, "uploadId") else {
                respond(
                    request,
                    400,
                    vec![],
                    error_xml("InvalidRequest", "no uploadId"),
                );
                return;
            };
            let part_number: u16 = query_value(&query, "partNumber")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            match state.uploads.get_mut(&upload_id) {
                Some(upload) => {
                    let etag = hash_hex(&body);
                    upload.parts.insert(part_number, body);
                    respond(
                        request,
                        200,
                        vec![("ETag", format!("\"{etag}\""))],
                        Vec::new(),
                    );
                }
                None => respond(
                    request,
                    404,
                    vec![],
                    error_xml("NoSuchUpload", "unknown upload id"),
                ),
            }
        }
        ("POST", Some(Op::Complete)) => {
            let upload_id = query_value(&query, "uploadId").unwrap_or_default();
            let Some(upload) = state.uploads.remove(&upload_id) else {
                respond(
                    request,
                    404,
                    vec![],
                    error_xml("NoSuchUpload", "unknown upload id"),
                );
                return;
            };
            let mut bytes = Vec::new();
            let mut part_etags = String::new();
            for chunk in upload.parts.values() {
                bytes.extend_from_slice(chunk);
                part_etags.push_str(&hash_hex(chunk));
            }
            let etag = format!("{}-{}", hash_hex(part_etags.as_bytes()), upload.parts.len());
            state.seq += 1;
            let version_id = match versioning {
                Versioning::Enabled => Some(format!("v{}", state.seq)),
                Versioning::Disabled => None,
            };
            state
                .objects
                .entry(upload.key.clone())
                .or_default()
                .push(StoredObject {
                    bytes,
                    etag: etag.clone(),
                    version_id: version_id.clone(),
                    meta_sha: upload.meta_sha,
                });

            let mut headers = Vec::new();
            if let Some(version) = &version_id {
                headers.push(("x-amz-version-id", version.clone()));
            }
            respond(
                request,
                200,
                headers,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{BUCKET}</Bucket>\
                     <Key>{}</Key><ETag>&quot;{etag}&quot;</ETag>\
                     </CompleteMultipartUploadResult>",
                    upload.key
                )
                .into_bytes(),
            );
        }
        ("DELETE", None) if query_value(&query, "uploadId").is_some() => {
            let upload_id = query_value(&query, "uploadId").unwrap_or_default();
            if state.uploads.remove(&upload_id).is_some() {
                respond(request, 204, vec![], Vec::new());
            } else {
                respond(
                    request,
                    404,
                    vec![],
                    error_xml("NoSuchUpload", "unknown upload id"),
                );
            }
        }
        ("DELETE", None) => {
            state.objects.remove(&key);
            respond(request, 204, vec![], Vec::new());
        }
        ("HEAD", Some(Op::Head)) | ("GET", None) => {
            let wanted_version = query_value(&query, "versionId");
            let found =
                state
                    .objects
                    .get(&key)
                    .and_then(|versions| match wanted_version.as_deref() {
                        Some(version) => versions
                            .iter()
                            .find(|object| object.version_id.as_deref() == Some(version)),
                        None => versions.last(),
                    });
            let Some(object) = found else {
                respond(request, 404, vec![], error_xml("NoSuchKey", "no such key"));
                return;
            };
            let mut headers = vec![
                ("ETag", format!("\"{}\"", object.etag)),
                ("Content-Length", object.bytes.len().to_string()),
            ];
            if let Some(version) = &object.version_id {
                headers.push(("x-amz-version-id", version.clone()));
            }
            if let Some(sha) = &object.meta_sha {
                headers.push((SOURCE_SHA256_META_HEADER, sha.clone()));
            }
            let body = if method == "HEAD" {
                Vec::new()
            } else {
                object.bytes.clone()
            };
            respond(request, 200, headers, body);
        }
        _ => respond(
            request,
            400,
            vec![],
            error_xml("InvalidRequest", "fake S3 does not implement this call"),
        ),
    }
}

fn classify(method: &str, query: &[(String, String)]) -> Option<Op> {
    match method {
        "POST" if query.iter().any(|(name, _)| name == "uploads") => Some(Op::Initiate),
        "POST" if query.iter().any(|(name, _)| name == "uploadId") => Some(Op::Complete),
        "PUT" if query.iter().any(|(name, _)| name == "partNumber") => Some(Op::UploadPart),
        "HEAD" => Some(Op::Head),
        _ => None,
    }
}

fn respond(request: Request, status: u16, headers: Vec<(&str, String)>, body: Vec<u8>) {
    let mut response = Response::from_data(body).with_status_code(StatusCode(status));
    for (name, value) in headers {
        if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
    let _ = request.respond(response);
}

fn error_xml(code: &str, message: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>")
        .into_bytes()
}

fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

fn split_query(raw_url: &str) -> (String, Vec<(String, String)>) {
    match raw_url.split_once('?') {
        Some((path, query)) => (
            path.to_string(),
            query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| match pair.split_once('=') {
                    Some((name, value)) => (name.to_string(), percent_decode(value)),
                    None => (pair.to_string(), String::new()),
                })
                .collect(),
        ),
        None => (raw_url.to_string(), Vec::new()),
    }
}

fn query_value(query: &[(String, String)], name: &str) -> Option<String> {
    query
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

/// Strips the leading `/bucket/` a path-style request carries, and undoes
/// the percent-encoding rusty-s3 applies to key segments.
fn object_key_from_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    let without_bucket = trimmed
        .strip_prefix(BUCKET)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or(trimmed);
    percent_decode(without_bucket)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------
// Harnesses
// ---------------------------------------------------------------------

/// The production adapter, pointed at the in-process fake.
pub struct FakeBackedHarness {
    name: String,
    store: S3ObjectStore,
    server: FakeS3,
    seq: AtomicU64,
}

impl FakeBackedHarness {
    pub fn new(versioning: Versioning) -> Self {
        let server = FakeS3::start(versioning);
        let store = S3ObjectStore::new(S3ObjectStoreConfig {
            endpoint: server.endpoint(),
            bucket: BUCKET.to_string(),
            region: "us-east-1".to_string(),
            url_style: UrlStyle::Path,
            access_key: "TESTKEYID".to_string(),
            secret_key: "test-secret-key-value".to_string(),
            // Deliberately short: the connection-loss case proves the
            // adapter reports a structured `Network` error rather than
            // hanging or panicking, and this is what bounds how long that
            // takes on loopback.
            request_timeout: Duration::from_secs(3),
        })
        .expect("loopback http endpoint is allowed");
        Self {
            name: format!("S3ObjectStore@fake-s3({versioning:?})"),
            store,
            server,
            seq: AtomicU64::new(0),
        }
    }
}

impl ContractFaultInjector for FakeBackedHarness {
    fn arm(&self, op: ContractOp, fault: ContractFault) {
        let op = match op {
            ContractOp::InitiateMultipartUpload => Op::Initiate,
            ContractOp::UploadPart => Op::UploadPart,
            ContractOp::CompleteMultipartUpload => Op::Complete,
            ContractOp::VerifyObject => Op::Head,
        };
        let fault = match fault {
            ContractFault::RateLimited => Fault::RateLimited,
            ContractFault::ServerError => Fault::ServerError,
            ContractFault::NetworkLoss => Fault::NetworkLoss,
        };
        self.server.arm(op, fault);
    }
}

impl ObjectStoreContractHarness for FakeBackedHarness {
    fn name(&self) -> &str {
        &self.name
    }

    fn store(&self) -> &dyn ObjectStorePort {
        &self.store
    }

    fn unique_key(&self, label: &str) -> ObjectKey {
        ObjectKey(format!(
            "contract/{label}-{}.bin",
            self.seq.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn cleanup(&self, key: &ObjectKey) {
        let _ = self.store.delete_object(key);
    }

    fn fault_injector(&self) -> Option<&dyn ContractFaultInjector> {
        Some(self)
    }
}

/// Tracks in-flight handles around the production adapter so a panic or an
/// assertion failure cannot leave billable multipart parts in a shared bucket.
/// The wrapper is test-only and intentionally exposes the exact same port,
/// keeping the contract suite oblivious to cleanup bookkeeping.
struct TrackingStore {
    inner: S3ObjectStore,
    pending: Mutex<HashMap<String, MultipartUploadHandle>>,
}

impl TrackingStore {
    fn new(inner: S3ObjectStore) -> Self {
        Self {
            inner,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn pending_len(&self) -> usize {
        self.pending.lock().expect("pending MinIO uploads").len()
    }

    fn abort_pending(&self) -> usize {
        let handles: Vec<_> = self
            .pending
            .lock()
            .expect("pending MinIO uploads")
            .values()
            .cloned()
            .collect();
        let mut aborted = 0;
        for handle in handles {
            match self.inner.abort_multipart_upload(&handle) {
                Ok(()) | Err(ObjectStoreError::UnknownUpload(_)) => {
                    self.pending
                        .lock()
                        .expect("pending MinIO uploads")
                        .remove(&handle.upload_id.0);
                    aborted += 1;
                }
                Err(_) => {}
            }
        }
        aborted
    }
}

impl ObjectStorePort for TrackingStore {
    fn put_object_if_absent(
        &self,
        request: &ImmutableObjectRequest,
    ) -> Result<bool, ObjectStoreError> {
        self.inner.put_object_if_absent(request)
    }

    fn read_object_bounded(
        &self,
        key: &ObjectKey,
        maximum_bytes: u64,
    ) -> Result<ObjectReadback, ObjectStoreError> {
        self.inner.read_object_bounded(key, maximum_bytes)
    }

    fn list_objects_bounded(
        &self,
        prefix: &str,
        maximum_keys: u16,
    ) -> Result<ObjectListPage, ObjectStoreError> {
        self.inner.list_objects_bounded(prefix, maximum_keys)
    }

    fn initiate_multipart_upload(
        &self,
        request: InitiateUploadRequest,
    ) -> Result<MultipartUploadHandle, ObjectStoreError> {
        let handle = self.inner.initiate_multipart_upload(request)?;
        self.pending
            .lock()
            .expect("pending MinIO uploads")
            .insert(handle.upload_id.0.clone(), handle.clone());
        Ok(handle)
    }

    fn upload_part(
        &self,
        handle: &MultipartUploadHandle,
        part_number: PartNumber,
        bytes: &[u8],
    ) -> Result<PartETag, ObjectStoreError> {
        self.inner.upload_part(handle, part_number, bytes)
    }

    fn complete_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
        parts: Vec<PartETag>,
    ) -> Result<CompletedUpload, ObjectStoreError> {
        let result = self.inner.complete_multipart_upload(handle, parts);
        if result.is_ok() {
            self.pending
                .lock()
                .expect("pending MinIO uploads")
                .remove(&handle.upload_id.0);
        }
        result
    }

    fn abort_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
    ) -> Result<(), ObjectStoreError> {
        let result = self.inner.abort_multipart_upload(handle);
        if matches!(result, Ok(()) | Err(ObjectStoreError::UnknownUpload(_))) {
            self.pending
                .lock()
                .expect("pending MinIO uploads")
                .remove(&handle.upload_id.0);
        }
        result
    }

    fn verify_object(
        &self,
        key: &ObjectKey,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        self.inner.verify_object(key, expected)
    }

    fn verify_completed_object(
        &self,
        completion: &CompletedUpload,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        self.inner.verify_completed_object(completion, expected)
    }
}

/// The production adapter against a real MinIO (or any S3-compatible
/// server). Only constructed by the `#[ignore]`d lane. When
/// `YLX_MINIO_FAULT_PROXY=1`, requests are routed through a loopback proxy so
/// the real MinIO lane also executes 429/5xx/network-loss cases. Without that
/// opt-in, those cases are reported as skipped with a visible reason.
pub struct MinioHarness {
    name: String,
    store: TrackingStore,
    endpoint: Url,
    bucket: String,
    credentials: Credentials,
    region: String,
    url_style: UrlStyle,
    prefix: String,
    keys: Mutex<HashSet<ObjectKey>>,
    seq: AtomicU64,
    owned_bucket: bool,
    proxy: Option<FaultProxy>,
}

impl MinioHarness {
    /// The endpoint and credentials identify the MinIO service. Bucket and
    /// prefix are intentionally optional: when the bucket is omitted, the
    /// harness creates a fresh random bucket and removes it on drop. This is
    /// what makes the standalone runner safe to execute concurrently.
    pub fn from_env() -> Self {
        let upstream: Url = env("YLX_MINIO_ENDPOINT")
            .parse()
            .expect("YLX_MINIO_ENDPOINT is a valid URL");
        let requested_style = match std::env::var("YLX_MINIO_URL_STYLE").as_deref() {
            Ok("virtual-host") => UrlStyle::VirtualHost,
            _ => UrlStyle::Path,
        };
        let region = std::env::var("YLX_MINIO_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let access_key = env("YLX_MINIO_ACCESS_KEY");
        let secret_key = env("YLX_MINIO_SECRET_KEY");
        let credentials = Credentials::new(access_key, secret_key);
        let explicit_bucket = std::env::var("YLX_MINIO_BUCKET")
            .ok()
            .filter(|bucket| !bucket.trim().is_empty());
        let bucket = explicit_bucket
            .clone()
            .unwrap_or_else(|| format!("ylx-contract-{}", nonce()));
        let owned_bucket = explicit_bucket.is_none();
        let url_style = if owned_bucket && matches!(requested_style, UrlStyle::VirtualHost) {
            panic!(
                "random MinIO buckets require YLX_MINIO_URL_STYLE=path; virtual-host style needs a pre-created bucket"
            );
        } else {
            requested_style
        };
        let bucket_ref = Bucket::new(upstream.clone(), url_style, bucket.clone(), region.clone())
            .expect("MinIO bucket configuration is valid");
        let admin_agent = http_agent(Duration::from_secs(30));
        if owned_bucket {
            create_bucket(&admin_agent, &bucket_ref, &credentials);
        }

        let proxy = if env_flag("YLX_MINIO_FAULT_PROXY") {
            Some(FaultProxy::start(upstream.clone()))
        } else {
            None
        };
        let endpoint = proxy
            .as_ref()
            .map_or_else(|| upstream.clone(), FaultProxy::endpoint);
        let store = S3ObjectStore::new(S3ObjectStoreConfig {
            endpoint: endpoint.clone(),
            bucket: bucket.clone(),
            region: region.clone(),
            url_style,
            access_key: credentials.key().to_string(),
            secret_key: credentials.secret().to_string(),
            request_timeout: Duration::from_secs(
                std::env::var("YLX_MINIO_REQUEST_TIMEOUT_SECS")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(60),
            ),
        })
        .expect("MinIO adapter constructs");
        let base_prefix = std::env::var("YLX_MINIO_PREFIX")
            .unwrap_or_else(|_| "ylx-contract".to_string())
            .trim_matches('/')
            .to_string();
        let prefix = format!("{base_prefix}/{}", nonce());
        let name = format!(
            "S3ObjectStore@minio(bucket={bucket}, prefix={prefix}, fault_proxy={})",
            proxy.is_some()
        );
        Self {
            name,
            store: TrackingStore::new(store),
            endpoint: upstream,
            bucket,
            credentials,
            region,
            url_style,
            prefix,
            keys: Mutex::new(HashSet::new()),
            seq: AtomicU64::new(0),
            owned_bucket,
            proxy,
        }
    }

    /// A visible evidence line consumed by CI logs and local runs. This is
    /// intentionally separate from `Drop`, so the test can print it while
    /// all `ContractKey` guards have already removed their objects.
    pub fn cleanup_evidence(&self) -> String {
        format!(
            "bucket={} prefix={} tracked_keys={} pending_uploads={}",
            self.bucket,
            self.prefix,
            self.keys.lock().expect("MinIO cleanup keys").len(),
            self.store.pending_len()
        )
    }
}

impl ContractFaultInjector for MinioHarness {
    fn arm(&self, op: ContractOp, fault: ContractFault) {
        let Some(proxy) = self.proxy.as_ref() else {
            return;
        };
        let op = match op {
            ContractOp::InitiateMultipartUpload => Op::Initiate,
            ContractOp::UploadPart => Op::UploadPart,
            ContractOp::CompleteMultipartUpload => Op::Complete,
            ContractOp::VerifyObject => Op::Head,
        };
        let fault = match fault {
            ContractFault::RateLimited => Fault::RateLimited,
            ContractFault::ServerError => Fault::ServerError,
            ContractFault::NetworkLoss => Fault::NetworkLoss,
        };
        proxy.arm(op, fault);
    }
}

impl ObjectStoreContractHarness for MinioHarness {
    fn name(&self) -> &str {
        &self.name
    }

    fn store(&self) -> &dyn ObjectStorePort {
        &self.store
    }

    fn unique_key(&self, label: &str) -> ObjectKey {
        let key = ObjectKey(format!(
            "{}/{label}-{}.bin",
            self.prefix,
            self.seq.fetch_add(1, Ordering::Relaxed)
        ));
        self.keys
            .lock()
            .expect("MinIO cleanup keys")
            .insert(key.clone());
        key
    }

    fn cleanup(&self, key: &ObjectKey) {
        let _ = self.store.inner.delete_object(key);
        self.keys.lock().expect("MinIO cleanup keys").remove(key);
    }

    /// Real S3-compatible servers reject non-final parts under 5 MiB, so
    /// this lane pays for genuinely multi-part uploads.
    fn part_size(&self) -> usize {
        5 * 1024 * 1024
    }

    fn fault_injector(&self) -> Option<&dyn ContractFaultInjector> {
        self.proxy
            .as_ref()
            .map(|_| self as &dyn ContractFaultInjector)
    }
}

impl Drop for MinioHarness {
    fn drop(&mut self) {
        let pending_before = self.store.pending_len();
        let aborted = self.store.abort_pending();
        let keys: Vec<_> = self
            .keys
            .lock()
            .expect("MinIO cleanup keys")
            .iter()
            .cloned()
            .collect();
        let mut deleted = 0;
        for key in keys {
            if self.store.inner.delete_object(&key).is_ok() {
                deleted += 1;
            }
        }
        let bucket_deleted = if self.owned_bucket {
            let bucket_ref = Bucket::new(
                self.endpoint.clone(),
                self.url_style,
                self.bucket.clone(),
                self.region.clone(),
            );
            match bucket_ref {
                Ok(bucket_ref) => delete_bucket(
                    &http_agent(Duration::from_secs(30)),
                    &bucket_ref,
                    &self.credentials,
                ),
                Err(_) => false,
            }
        } else {
            false
        };
        eprintln!(
            "MinIO contract cleanup: bucket={} prefix={} pending_before={} uploads_aborted={} objects_deleted={} bucket_deleted={} remaining_keys={}",
            self.bucket,
            self.prefix,
            pending_before,
            aborted,
            deleted,
            bucket_deleted,
            self.keys.lock().expect("MinIO cleanup keys").len()
        );
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} must be set to run the MinIO object-store contract lane")
    })
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("on")
    )
}

fn nonce() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let count = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_nanos();
    format!("{:x}{count:x}", nanos)
}

fn http_agent(timeout: Duration) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into()
}

fn signed_admin_request(agent: &Agent, method: http::Method, url: Url) -> Option<u16> {
    let request = http::Request::builder()
        .method(method)
        .uri(url.as_str())
        .body(Vec::new())
        .ok()?;
    let mut response = agent.run(request).ok()?;
    let status = response.status().as_u16();
    let _ = response.body_mut().read_to_vec();
    Some(status)
}

fn create_bucket(agent: &Agent, bucket: &Bucket, credentials: &Credentials) {
    let action = CreateBucket::new(bucket, credentials);
    let status = signed_admin_request(
        agent,
        http::Method::PUT,
        action.sign(Duration::from_secs(60)),
    )
    .expect("MinIO CreateBucket request completed");
    assert!(
        matches!(status, 200 | 204 | 409),
        "MinIO CreateBucket returned unexpected status {status}"
    );
}

fn delete_bucket(agent: &Agent, bucket: &Bucket, credentials: &Credentials) -> bool {
    let action = DeleteBucket::new(bucket, credentials);
    let Some(status) = signed_admin_request(
        agent,
        http::Method::DELETE,
        action.sign(Duration::from_secs(60)),
    ) else {
        return false;
    };
    matches!(status, 200 | 204 | 404)
}
