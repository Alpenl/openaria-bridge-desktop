//! `ObjectStorePort` — SPIKE-PC-S3 (pre-PC-00/PC-06 preparatory spike).
//!
//! ## Status
//!
//! This is **not** the frozen PC-06 port. Per plan section 12.1, the real
//! `ObjectStore port` shape is owned by PC-00 (freeze `F6`) and the real
//! production adapter is owned by PC-06 (plan section 16), both gated
//! behind Wave 2's Pi API freeze. This spike was explicitly authorized to
//! run early because the S3-facing seam does not need to know the Pi wire
//! protocol at all — only a generic object-store abstraction (multipart
//! upload/verify) — mirroring the W0-06 persistence spike
//! (`docs/adr/ADR-PC-001-persistence.md`) and the CAP-02/CAP-05
//! spike-then-production pattern on the RP-YLX side. PC-00/PC-06 may
//! revise every type and method signature here; nothing in this module is
//! wired into any production Tauri command, and nothing outside this
//! spike's own tests depends on it.
//!
//! ## What this is for (plan section 9.3)
//!
//! > ObjectStore port provides memory/mock adapter; production adapter
//! > supports S3-compatible endpoint and multipart. multipart upload ID,
//! > completed part ETags and source hash must be durable, supporting
//! > crash resume and cancel/abort. multipart ETag must not be treated as
//! > a file's MD5 — upload SHA-256 as metadata, verify bytes/metadata/
//! > version-id/ETag via HEAD after completion. Only after all objects and
//! > the final manifest are verified is `object_store_verified` written.
//!
//! Two properties this module is deliberately built around:
//!
//! 1. **"Upload succeeded" is not "verified".** [`ObjectStorePort::complete_multipart_upload`]
//!    returns a raw [`CompletedUpload`] with S3's own multipart `ETag` —
//!    which is *not* comparable to any content hash (a multipart ETag is
//!    `md5(md5(part1) || md5(part2) || ...) + "-" + part_count`, an
//!    artifact of how the object was chunked, not of its bytes). Only
//!    [`ObjectStorePort::verify_object`] — a HEAD-equivalent read-back
//!    that compares size, the `source_sha256` metadata the caller set at
//!    upload time, and the object's ETag/version-id — can produce a
//!    [`VerifiedObjectReceipt`]. Callers MUST NOT synthesize a
//!    `VerifiedObjectReceipt` from a `CompletedUpload` alone.
//! 2. **The source hash lives in object metadata, never in the ETag.**
//!    [`InitiateUploadRequest::source_sha256`] is written as S3 object
//!    metadata (`x-amz-meta-source-sha256` in the production adapter) at
//!    `CreateMultipartUpload` time and read back unchanged by
//!    `verify_object`. It is completely independent of the multipart
//!    ETag's own bookkeeping.
//!
//! ## Durability shape (plan 9.3 item 3), not persistence itself
//!
//! [`MultipartUploadRecord`] is the shape a future persistence layer
//! (the application's/transfer's SQLite stores, or PC-01's durable journal
//! schema) could serialize as one row without redesigning these types — see
//! `docs/adr/ADR-PC-001-persistence.md` for the sibling spike this is
//! meant to plug into later. **No actual persistence integration happens
//! in this crate**: nothing here reads or writes SQLite/JSON. Wiring a
//! real adapter's in-progress-upload state to durable storage (so it
//! survives an app restart, not just an in-process retry) is PC-01/PC-06
//! work, out of this spike's scope.
//!
//! ## Crash-resume contract (plan 9.3 item 3 / test requirement)
//!
//! A genuine `ListMultipartUploads`/`ListParts`-based resume (discovering
//! and continuing an in-progress upload after the process that started it
//! is gone) is **not implemented** in this spike — that is real PC-06
//! work. What this spike *does* guarantee, and test, is the safe fallback
//! shape:
//!
//! - [`ObjectStorePort::abort_multipart_upload`] always leaves the object
//!   store in a clean state (no orphaned parts, no orphaned upload id) —
//!   this is the "clear abort+cleanup path" the task card allows as a
//!   substitute for true resume.
//! - Calling [`ObjectStorePort::complete_multipart_upload`] a second time
//!   for an upload id that already completed (e.g. because the client
//!   crashed/disconnected between S3 committing the completion and the
//!   client observing the response) returns the structured
//!   [`ObjectStoreError::UnknownUpload`] — never a panic, never a false
//!   "success". The documented recovery move for a caller in that
//!   situation is: call [`ObjectStorePort::verify_object`] with the
//!   `ExpectedObject` it remembers from before the (ambiguous) complete
//!   call. If it matches, the previous attempt actually succeeded and the
//!   job can proceed to being marked verified; if [`ObjectStoreError::NotFound`]
//!   comes back, no object landed and it is safe to start a fresh
//!   multipart upload for the same key.
//!
//! ## Completion-bound verification (issue #1, commit 69)
//!
//! [`ObjectStorePort::verify_object`] reads whatever is *currently* at a
//! key. With concurrent writers on the same key that is not necessarily
//! the object this process just completed, so a plain "latest" read can
//! only ever prove "some object that looks right is at this key" — never
//! "the multipart completion I hold a receipt for is what landed".
//!
//! [`ObjectStorePort::verify_completed_object`] takes the
//! [`CompletedUpload`] receipt itself and binds the read to it:
//!
//! - when the backend reported a `version_id`, the object is read **at
//!   that version** (`?versionId=`) rather than at "latest";
//! - the read-back object's ETag must equal the completion's ETag, and its
//!   version id (when the completion carries one) must equal the
//!   completion's version id;
//! - any divergence is [`ObjectStoreError::CompletionMismatch`] — an
//!   explicit failure, never a silent fallback to the latest object.
//!
//! ## Real content digest (issue #1, commit 70)
//!
//! Metadata does not prove bytes: `x-amz-meta-source-sha256` is a string
//! the *client* wrote, so an object whose stored bytes do not match it
//! passes every metadata-only check. Both verification entry points
//! therefore prove the object's real content digest before returning a
//! [`VerifiedObjectReceipt`]:
//!
//! - if the backend exposes a **trusted server-side full-object checksum**
//!   it is used ([`DigestProof::ServerChecksum`]);
//! - otherwise the object is **streamed back and re-hashed locally**
//!   ([`DigestProof::StreamedReadback`]). This costs one extra read, which
//!   the issue's decision document explicitly accepts: "对象存储验证必须绑
//!   定本次 multipart completion。服务端无可信 checksum 时允许额外读取验
//!   证，以正确性优先于节省一次读取。"
//!
//! A malformed or unusable server-side checksum is
//! [`ObjectStoreError::MalformedChecksum`] (fail closed), never a silent
//! downgrade to "metadata looked fine".

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Core value types
// ---------------------------------------------------------------------

/// SHA-256 of the *source* file, computed by the caller (LocalLibrary /
/// TransferCoordinator, in the real system) before or while uploading.
/// Deliberately never derived from a multipart `ETag` — see module docs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceSha256(pub [u8; 32]);

impl SourceSha256 {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    pub fn from_hex(s: &str) -> Result<Self, ObjectStoreError> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(ObjectStoreError::Config(format!(
                "source sha256 hex must be exactly 64 chars, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let byte_str = s.get(i * 2..i * 2 + 2).ok_or_else(|| {
                ObjectStoreError::Config("source sha256 hex has invalid length".to_string())
            })?;
            *slot = u8::from_str_radix(byte_str, 16).map_err(|e| {
                ObjectStoreError::Config(format!("invalid hex digit in source sha256: {e}"))
            })?;
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for SourceSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceSha256({})", self.to_hex())
    }
}

impl fmt::Display for SourceSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Bucket-scoped object key. Bucket itself is adapter configuration, not
/// part of this domain-level key (mirrors how S3 SDKs separate bucket
/// config from per-object key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectKey(pub String);

/// Multipart upload identifier, as returned by `CreateMultipartUpload`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UploadId(pub String);

/// 1-based S3 multipart part number. Valid range is `1..=10_000` per the
/// S3 API contract; constructing an out-of-range value is a caller bug,
/// not an adapter-detected runtime failure, so it is rejected at
/// construction rather than deferred to `upload_part`/`complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PartNumber(u16);

impl PartNumber {
    pub const MIN: u16 = 1;
    pub const MAX: u16 = 10_000;

    pub fn new(value: u16) -> Result<Self, ObjectStoreError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(ObjectStoreError::InvalidPart(format!(
                "part number {value} out of range {}..={}",
                Self::MIN,
                Self::MAX
            )));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// One completed part's server-assigned ETag, keyed by part number. This
/// is the shape `CompleteMultipartUpload` needs; part numbers must be
/// contiguous starting at 1 when passed to
/// [`ObjectStorePort::complete_multipart_upload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartETag {
    pub part_number: PartNumber,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitiateUploadRequest {
    pub key: ObjectKey,
    /// Total expected object size. Not sent to S3 directly (multipart
    /// uploads don't declare size up front) but retained so adapters and
    /// tests can cross-check the sum of uploaded part sizes.
    pub content_length: u64,
    /// Written as object metadata at initiate time (production adapter:
    /// `x-amz-meta-source-sha256`), read back unchanged by
    /// `verify_object`. Never compared against the multipart ETag.
    pub source_sha256: SourceSha256,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartUploadHandle {
    pub key: ObjectKey,
    pub upload_id: UploadId,
}

/// The raw result of `CompleteMultipartUpload`. Deliberately NOT called
/// "verified" — see module docs. `etag` is S3's own multipart ETag
/// bookkeeping value, not a content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedUpload {
    pub key: ObjectKey,
    pub upload_id: UploadId,
    pub etag: String,
    pub version_id: Option<String>,
}

/// What the caller expects an object to be, for `verify_object` to check
/// against. Comes from the caller's own accounting (e.g. LocalLibrary's
/// re-hashed source file), never trusted blindly from a prior receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedObject {
    pub size_bytes: u64,
    pub source_sha256: SourceSha256,
}

/// How a [`VerifiedObjectReceipt`]'s content digest was actually proven
/// (issue #1, commit 70). Metadata alone never counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestProof {
    /// The backend reported a trusted **full-object** checksum of the
    /// stored bytes (e.g. S3's `x-amz-checksum-sha256` with
    /// `x-amz-checksum-type: FULL_OBJECT`) and it matched.
    ServerChecksum,
    /// The backend exposes no trusted full-object checksum, so the object
    /// was read back in full and re-hashed locally.
    StreamedReadback,
}

/// Evidence for the plan's `object_store_verified` milestone (section
/// 5.1: "全部对象与最终 manifest 上传并经 HEAD/metadata/version 验证") —
/// only constructed by [`ObjectStorePort::verify_object`] /
/// [`ObjectStorePort::verify_completed_object`] after size, the
/// `source_sha256` metadata **and the object's real content digest** have
/// all been confirmed. Never constructed from a [`CompletedUpload`] alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedObjectReceipt {
    pub key: ObjectKey,
    pub etag: String,
    pub version_id: Option<String>,
    pub size_bytes: u64,
    /// The digest the object's real bytes were proven to hash to — equal
    /// to both the caller's [`ExpectedObject::source_sha256`] and the
    /// object's own `source_sha256` metadata, or this receipt would not
    /// exist.
    pub source_sha256: SourceSha256,
    /// How `source_sha256` was proven against the remote bytes.
    pub digest_proof: DigestProof,
}

// ---------------------------------------------------------------------
// Durable-shaped tracking record (plan 9.3 item 3) — not persisted here
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultipartUploadStatus {
    InProgress,
    Completed {
        etag: String,
        version_id: Option<String>,
    },
    Aborted,
}

/// A snapshot of one multipart upload's progress, shaped so a future
/// persistence layer could serialize it as a single row (`upload_id` as
/// primary key, `completed_parts` as a JSON column or a child table) —
/// see module docs. This spike only constructs it in memory / for tests;
/// it is never read from or written to disk here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartUploadRecord {
    pub key: ObjectKey,
    pub upload_id: UploadId,
    pub content_length: u64,
    pub source_sha256: SourceSha256,
    pub status: MultipartUploadStatus,
    pub completed_parts: Vec<PartETag>,
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Structured object-store errors. Every [`ObjectStorePort`] method
/// returns one of these instead of panicking — this is exercised
/// explicitly by the fault-injection tests below (5xx/429/auth failures
/// must come back as one of these variants, never as an unwrap panic).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("network error: {0}")]
    Network(String),

    #[error("authentication/authorization failed (status {status}): {detail}")]
    Auth { status: u16, detail: String },

    #[error("rate limited{}", format_retry_after(*retry_after_ms))]
    RateLimited { retry_after_ms: Option<u64> },

    #[error("server error (status {status}): {detail}")]
    ServerError { status: u16, detail: String },

    #[error("object not found: {0:?}")]
    NotFound(ObjectKey),

    /// The multipart upload id is unknown to the store — either it was
    /// never created, was already aborted, or (per the crash-resume
    /// contract in the module docs) was already completed and is now
    /// single-use-consumed. Callers recover via `verify_object`, not by
    /// retrying the same call.
    #[error("unknown or already-finalized multipart upload: {0:?}")]
    UnknownUpload(UploadId),

    #[error("invalid part: {0}")]
    InvalidPart(String),

    /// `verify_object` ran successfully but the object's *metadata* does
    /// not match what the caller expected (size, declared source hash).
    /// This must fail closed — see module docs point 1 ("upload
    /// succeeded" is not "verified").
    #[error("verification failed for {key:?}: {detail}")]
    VerificationMismatch { key: ObjectKey, detail: String },

    /// The object read back is not the one the held
    /// [`CompletedUpload`] receipt describes — different version id or
    /// different ETag (issue #1, commit 69). Always explicit: a caller
    /// must never fall back to "well, *something* correct-looking is at
    /// that key".
    #[error("completion binding failed for {key:?}: {detail}")]
    CompletionMismatch { key: ObjectKey, detail: String },

    /// The remote object's **real bytes** hash to something other than
    /// what the caller expected (issue #1, commit 70) — regardless of
    /// what its metadata claims.
    #[error(
        "content digest mismatch for {key:?}: expected {expected}, remote content is {actual}"
    )]
    DigestMismatch {
        key: ObjectKey,
        expected: SourceSha256,
        actual: SourceSha256,
    },

    /// The object carries no usable source digest at all, or one that
    /// cannot be parsed. Fails closed rather than downgrading to a
    /// metadata-only "verification".
    #[error("missing or malformed checksum for {key:?}: {detail}")]
    MalformedChecksum { key: ObjectKey, detail: String },

    /// A signed object-store request was answered with a redirect. Never
    /// followed: the redirect target is outside the signature's scope, so
    /// following it would both leak the presigned URL and verify bytes
    /// that some other host chose.
    #[error("unexpected redirect (status {status}) to {location:?}")]
    UnexpectedRedirect {
        status: u16,
        location: Option<String>,
    },

    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Recomputes the SHA-256 of a full byte buffer. Shared by the in-memory
/// store and by adapters' streamed read-back path (which feeds the same
/// hasher incrementally).
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> SourceSha256 {
    SourceSha256::from_bytes(Sha256::digest(bytes).into())
}

fn format_retry_after(retry_after_ms: Option<u64>) -> String {
    match retry_after_ms {
        Some(ms) => format!(", retry after {ms}ms"),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------

/// Outbound seam for S3-compatible object storage. Memory/mock
/// implementation ([`MemoryObjectStore`]) lives in this crate for tests;
/// the production S3-compatible implementation
/// (`ylx-transfer-adapters::object_store_s3::S3ObjectStore`) lives in the
/// adapters crate, per the plan's ports/adapters split (section 7.1,
/// option D).
pub trait ObjectStorePort: Send + Sync {
    /// Start a multipart upload. `request.source_sha256` is written as
    /// object metadata now — production adapters must send it as a
    /// signed header on `CreateMultipartUpload` so it lands in the
    /// object's metadata at completion time.
    fn initiate_multipart_upload(
        &self,
        request: InitiateUploadRequest,
    ) -> Result<MultipartUploadHandle, ObjectStoreError>;

    /// Upload one part. Returns the server-assigned ETag for that part,
    /// which must be passed back unchanged to `complete_multipart_upload`.
    fn upload_part(
        &self,
        handle: &MultipartUploadHandle,
        part_number: PartNumber,
        bytes: &[u8],
    ) -> Result<PartETag, ObjectStoreError>;

    /// Finish the multipart upload. `parts` must be contiguous starting
    /// at part 1 (implementations should sort by part number and reject
    /// gaps/duplicates as [`ObjectStoreError::InvalidPart`]).
    ///
    /// Returns [`ObjectStoreError::UnknownUpload`] if `handle.upload_id`
    /// is not a currently in-progress upload — including the "already
    /// completed" crash-resume case described in the module docs. This
    /// is intentional and must not be treated as a fatal error by
    /// callers without first trying `verify_object`.
    fn complete_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
        parts: Vec<PartETag>,
    ) -> Result<CompletedUpload, ObjectStoreError>;

    /// Abort an in-progress multipart upload and release any uploaded
    /// parts. Must be safe to call as a cleanup path after a disconnect —
    /// see the crash-resume contract in the module docs.
    fn abort_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
    ) -> Result<(), ObjectStoreError>;

    /// Verify whatever object is **currently** at `key`. Compares size and
    /// the `source_sha256` metadata (never the multipart ETag) against
    /// `expected`, and proves the object's real content digest per commit
    /// 70 (server-side trusted checksum where available, streamed
    /// read-back otherwise). Fails closed on any mismatch.
    ///
    /// This is a "latest object" read: it can only prove that *an* object
    /// matching `expected` is at that key right now. After a multipart
    /// completion, use [`ObjectStorePort::verify_completed_object`]
    /// instead — with concurrent writers on the same key, "latest" may not
    /// be the object this process completed.
    fn verify_object(
        &self,
        key: &ObjectKey,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError>;

    /// Verify **the specific object version this multipart completion
    /// produced** (issue #1, commit 69) and prove its real content digest
    /// (commit 70).
    ///
    /// Implementations must:
    ///
    /// 1. read the object at `completion.version_id` when the backend
    ///    reported one, instead of at "latest";
    /// 2. reject a read-back whose ETag differs from `completion.etag`, or
    ///    whose version id differs from `completion.version_id`, with
    ///    [`ObjectStoreError::CompletionMismatch`];
    /// 3. check size and `source_sha256` metadata against `expected`
    ///    ([`ObjectStoreError::VerificationMismatch`]); and
    /// 4. prove the object's real bytes hash to `expected.source_sha256`
    ///    ([`ObjectStoreError::DigestMismatch`] otherwise), recording how
    ///    in [`VerifiedObjectReceipt::digest_proof`].
    fn verify_completed_object(
        &self,
        completion: &CompletedUpload,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError>;
}

// ---------------------------------------------------------------------
// MemoryObjectStore — deterministic mock/fake adapter for tests
// ---------------------------------------------------------------------

/// Which [`ObjectStorePort`] method a queued fault applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    InitiateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    VerifyObject,
}

#[derive(Debug, Clone)]
struct StoredObject {
    /// The bytes the mock "server" actually holds. Verification re-hashes
    /// these, exactly like a real adapter's streamed read-back does — so
    /// metadata that lies about the content is caught here too.
    bytes: Vec<u8>,
    etag: String,
    version_id: Option<String>,
    /// What the mock "server" actually has on file as the object's
    /// `source_sha256` metadata — deliberately mutable only via
    /// [`MemoryObjectStore::corrupt_stored_metadata`], to model metadata
    /// drifting from what the client originally declared.
    source_sha256_metadata: SourceSha256,
}

impl StoredObject {
    fn size_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
}

#[derive(Debug, Clone)]
struct PartRecord {
    etag: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct InProgressUpload {
    key: ObjectKey,
    declared_source_sha256: SourceSha256,
    parts: BTreeMap<u16, PartRecord>,
}

#[derive(Default)]
struct MemoryState {
    /// Version history per key, oldest first; the last element is
    /// "latest". Modelled as a history (not a single slot) so
    /// `verify_completed_object` can read *the version a completion
    /// produced* even after another writer overwrote the key.
    objects: HashMap<String, Vec<StoredObject>>,
    uploads: HashMap<String, InProgressUpload>,
    faults: HashMap<FaultPoint, VecDeque<ObjectStoreError>>,
    next_seq: u64,
}

/// Deterministic in-memory fake of an S3-compatible object store. Used
/// for unit tests in this crate and in the adapters crate's own tests;
/// NOT a stand-in for a real S3 endpoint in production — that is
/// `ylx-transfer-adapters::object_store_s3::S3ObjectStore`.
///
/// Supports fault injection ([`MemoryObjectStore::queue_fault`]) so tests
/// can prove 5xx/429/auth failures come back as structured
/// [`ObjectStoreError`] values instead of panics, and metadata corruption
/// ([`MemoryObjectStore::corrupt_stored_metadata`]) so tests can prove
/// `verify_object` fails closed instead of trusting a matching ETag
/// alone.
pub struct MemoryObjectStore {
    state: Mutex<MemoryState>,
    /// Whether completions hand back a `version_id`. Both shapes exist in
    /// the wild (S3 with versioning on vs. a plain MinIO/OSS bucket) and
    /// commit 69's completion binding has a different — but equally
    /// explicit — outcome on each, so both are modelled.
    versioned: bool,
}

impl Default for MemoryObjectStore {
    fn default() -> Self {
        Self {
            state: Mutex::new(MemoryState::default()),
            versioned: true,
        }
    }
}

impl MemoryObjectStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store whose completions carry no `version_id`, like a bucket with
    /// versioning disabled. On such a backend an overwrite of the same key
    /// makes the earlier completion unverifiable — which must surface as
    /// [`ObjectStoreError::CompletionMismatch`], not as a pass.
    #[must_use]
    pub fn unversioned() -> Self {
        Self {
            state: Mutex::new(MemoryState::default()),
            versioned: false,
        }
    }

    /// Queue `error` to be returned on the *next* call to the method
    /// identified by `point`, then clear (each queued fault fires once,
    /// in FIFO order, per point).
    pub fn queue_fault(&self, point: FaultPoint, error: ObjectStoreError) {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        state.faults.entry(point).or_default().push_back(error);
    }

    fn take_fault(state: &mut MemoryState, point: FaultPoint) -> Option<ObjectStoreError> {
        state.faults.get_mut(&point).and_then(VecDeque::pop_front)
    }

    /// Test-only hook: overwrite what the mock "server" reports as an
    /// already-completed object's `source_sha256` metadata, without
    /// touching its bytes/size/etag. Models the object store returning
    /// metadata that no longer matches what the client uploaded (bug,
    /// tamper, or a different file having been written to the same key
    /// out of band) — used to prove `verify_object` fails closed.
    pub fn corrupt_stored_metadata(&self, key: &ObjectKey, wrong_sha256: SourceSha256) {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(object) = state.objects.get_mut(&key.0).and_then(|v| v.last_mut()) {
            object.source_sha256_metadata = wrong_sha256;
        }
    }

    /// Test-only hook: swap the bytes the mock "server" holds for a key
    /// while leaving its declared `source_sha256` metadata, size and ETag
    /// untouched. Models the one thing metadata can never catch — the
    /// stored content not being what the object claims (commit 70).
    pub fn corrupt_stored_bytes(&self, key: &ObjectKey, bytes: Vec<u8>) {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(object) = state.objects.get_mut(&key.0).and_then(|v| v.last_mut()) {
            object.bytes = bytes;
        }
    }

    /// Drop every version of `key` — the in-memory equivalent of the
    /// cleanup a real backend needs after a contract run.
    pub fn delete_object(&self, key: &ObjectKey) {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        state.objects.remove(&key.0);
    }

    #[must_use]
    pub fn object_count(&self) -> usize {
        self.state
            .lock()
            .expect("MemoryObjectStore lock poisoned")
            .objects
            .len()
    }

    #[must_use]
    pub fn in_progress_upload_count(&self) -> usize {
        self.state
            .lock()
            .expect("MemoryObjectStore lock poisoned")
            .uploads
            .len()
    }

    /// Durable-shaped export of one in-progress upload's current state —
    /// demonstrates that [`MultipartUploadRecord`] is actually
    /// constructible from this mock's internal bookkeeping (plan 9.3 item
    /// 3), without this crate wiring it to real persistence.
    #[must_use]
    pub fn export_upload_record(&self, upload_id: &UploadId) -> Option<MultipartUploadRecord> {
        let state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        let upload = state.uploads.get(&upload_id.0)?;
        let mut completed_parts: Vec<PartETag> = upload
            .parts
            .iter()
            .map(|(number, record)| PartETag {
                part_number: PartNumber::new(*number).expect("stored part numbers are valid"),
                etag: record.etag.clone(),
            })
            .collect();
        completed_parts.sort_by_key(|p| p.part_number.get());
        let content_length = completed_parts
            .iter()
            .filter_map(|p| {
                upload
                    .parts
                    .get(&p.part_number.get())
                    .map(|r| r.bytes.len() as u64)
            })
            .sum();
        Some(MultipartUploadRecord {
            key: upload.key.clone(),
            upload_id: upload_id.clone(),
            content_length,
            source_sha256: upload.declared_source_sha256,
            status: MultipartUploadStatus::InProgress,
            completed_parts,
        })
    }
}

/// Deterministic, content-derived stand-in for an S3 ETag. NOT a real MD5
/// (deliberately avoids pulling an MD5 crate into this mock) and NOT
/// meant to resemble a real S3 ETag's exact byte format — only to be
/// stable, content-sensitive, and cheap for tests to assert against.
fn fake_etag(bytes: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn validate_parts_against_record(
    parts: &[PartETag],
    recorded: &BTreeMap<u16, PartRecord>,
) -> Result<(), ObjectStoreError> {
    if parts.is_empty() {
        return Err(ObjectStoreError::InvalidPart(
            "no parts supplied to complete_multipart_upload".to_string(),
        ));
    }
    for (index, part) in parts.iter().enumerate() {
        let expected_number = u16::try_from(index).expect("part count fits u16") + 1;
        if part.part_number.get() != expected_number {
            return Err(ObjectStoreError::InvalidPart(format!(
                "part numbers must be contiguous starting at 1; expected {expected_number}, got {}",
                part.part_number.get()
            )));
        }
        match recorded.get(&part.part_number.get()) {
            Some(record) if record.etag == part.etag => {}
            Some(record) => {
                return Err(ObjectStoreError::InvalidPart(format!(
                    "etag mismatch for part {}: caller supplied {:?}, store has {:?}",
                    part.part_number.get(),
                    part.etag,
                    record.etag
                )));
            }
            None => {
                return Err(ObjectStoreError::InvalidPart(format!(
                    "part {} was never uploaded to this upload id",
                    part.part_number.get()
                )));
            }
        }
    }
    Ok(())
}

impl ObjectStorePort for MemoryObjectStore {
    fn initiate_multipart_upload(
        &self,
        request: InitiateUploadRequest,
    ) -> Result<MultipartUploadHandle, ObjectStoreError> {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(err) = Self::take_fault(&mut state, FaultPoint::InitiateMultipartUpload) {
            return Err(err);
        }
        state.next_seq += 1;
        let upload_id = UploadId(format!("mem-upload-{}", state.next_seq));
        state.uploads.insert(
            upload_id.0.clone(),
            InProgressUpload {
                key: request.key.clone(),
                declared_source_sha256: request.source_sha256,
                parts: BTreeMap::new(),
            },
        );
        Ok(MultipartUploadHandle {
            key: request.key,
            upload_id,
        })
    }

    fn upload_part(
        &self,
        handle: &MultipartUploadHandle,
        part_number: PartNumber,
        bytes: &[u8],
    ) -> Result<PartETag, ObjectStoreError> {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(err) = Self::take_fault(&mut state, FaultPoint::UploadPart) {
            return Err(err);
        }
        let upload = state
            .uploads
            .get_mut(&handle.upload_id.0)
            .ok_or_else(|| ObjectStoreError::UnknownUpload(handle.upload_id.clone()))?;
        let etag = fake_etag(bytes);
        upload.parts.insert(
            part_number.get(),
            PartRecord {
                etag: etag.clone(),
                bytes: bytes.to_vec(),
            },
        );
        Ok(PartETag { part_number, etag })
    }

    fn complete_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
        mut parts: Vec<PartETag>,
    ) -> Result<CompletedUpload, ObjectStoreError> {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(err) = Self::take_fault(&mut state, FaultPoint::CompleteMultipartUpload) {
            return Err(err);
        }
        let upload = match state.uploads.remove(&handle.upload_id.0) {
            Some(upload) => upload,
            None => return Err(ObjectStoreError::UnknownUpload(handle.upload_id.clone())),
        };

        parts.sort_by_key(|p| p.part_number.get());

        if let Err(err) = validate_parts_against_record(&parts, &upload.parts) {
            // An invalid Complete call must not destroy upload state —
            // put it back so the caller can retry with a corrected part
            // list or explicitly abort.
            state.uploads.insert(handle.upload_id.0.clone(), upload);
            return Err(err);
        }

        let mut object_bytes: Vec<u8> = Vec::new();
        for part in &parts {
            if let Some(record) = upload.parts.get(&part.part_number.get()) {
                object_bytes.extend_from_slice(&record.bytes);
            }
        }
        let combined_input: String = parts.iter().map(|p| p.etag.as_str()).collect();
        let etag = format!("{}-{}", fake_etag(combined_input.as_bytes()), parts.len());
        state.next_seq += 1;
        let version_id = if self.versioned {
            Some(format!("mem-version-{}", state.next_seq))
        } else {
            None
        };

        state
            .objects
            .entry(upload.key.0.clone())
            .or_default()
            .push(StoredObject {
                bytes: object_bytes,
                etag: etag.clone(),
                version_id: version_id.clone(),
                source_sha256_metadata: upload.declared_source_sha256,
            });

        Ok(CompletedUpload {
            key: upload.key,
            upload_id: handle.upload_id.clone(),
            etag,
            version_id,
        })
    }

    fn abort_multipart_upload(
        &self,
        handle: &MultipartUploadHandle,
    ) -> Result<(), ObjectStoreError> {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(err) = Self::take_fault(&mut state, FaultPoint::AbortMultipartUpload) {
            return Err(err);
        }
        match state.uploads.remove(&handle.upload_id.0) {
            Some(_) => Ok(()),
            None => Err(ObjectStoreError::UnknownUpload(handle.upload_id.clone())),
        }
    }

    fn verify_object(
        &self,
        key: &ObjectKey,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(err) = Self::take_fault(&mut state, FaultPoint::VerifyObject) {
            return Err(err);
        }
        let object = state
            .objects
            .get(&key.0)
            .and_then(|versions| versions.last())
            .ok_or_else(|| ObjectStoreError::NotFound(key.clone()))?;
        verify_stored_object(key, object, expected)
    }

    fn verify_completed_object(
        &self,
        completion: &CompletedUpload,
        expected: &ExpectedObject,
    ) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
        let key = &completion.key;
        let mut state = self.state.lock().expect("MemoryObjectStore lock poisoned");
        if let Some(err) = Self::take_fault(&mut state, FaultPoint::VerifyObject) {
            return Err(err);
        }
        let versions = state
            .objects
            .get(&key.0)
            .ok_or_else(|| ObjectStoreError::NotFound(key.clone()))?;

        // Commit 69: read *the completion's own version* when the backend
        // hands out version ids; only an unversioned backend is forced to
        // fall back to "latest" (and then the ETag check below is the only
        // thing standing between the caller and another writer's object).
        let object = match completion.version_id.as_deref() {
            Some(wanted) => versions
                .iter()
                .find(|candidate| candidate.version_id.as_deref() == Some(wanted))
                .ok_or_else(|| ObjectStoreError::CompletionMismatch {
                    key: key.clone(),
                    detail: format!("completed version {wanted} is no longer present at this key"),
                })?,
            None => versions
                .last()
                .ok_or_else(|| ObjectStoreError::NotFound(key.clone()))?,
        };

        check_completion_binding(
            completion,
            object.etag.as_str(),
            object.version_id.as_deref(),
        )?;
        verify_stored_object(key, object, expected)
    }
}

/// Shared "is this the object the receipt describes" check, applied to
/// whatever the backend actually returned.
fn check_completion_binding(
    completion: &CompletedUpload,
    actual_etag: &str,
    actual_version_id: Option<&str>,
) -> Result<(), ObjectStoreError> {
    if actual_etag != completion.etag {
        return Err(ObjectStoreError::CompletionMismatch {
            key: completion.key.clone(),
            detail: format!(
                "etag mismatch: this multipart completion produced {:?}, the object at this key is {:?} \
                 (another writer completed a different object on the same key)",
                completion.etag, actual_etag
            ),
        });
    }
    if let Some(expected_version) = completion.version_id.as_deref() {
        if actual_version_id != Some(expected_version) {
            return Err(ObjectStoreError::CompletionMismatch {
                key: completion.key.clone(),
                detail: format!(
                    "version mismatch: this multipart completion produced version {expected_version:?}, \
                     read back version {actual_version_id:?}"
                ),
            });
        }
    }
    Ok(())
}

fn verify_stored_object(
    key: &ObjectKey,
    object: &StoredObject,
    expected: &ExpectedObject,
) -> Result<VerifiedObjectReceipt, ObjectStoreError> {
    if object.size_bytes() != expected.size_bytes {
        return Err(ObjectStoreError::VerificationMismatch {
            key: key.clone(),
            detail: format!(
                "size mismatch: expected {} bytes, object store reports {} bytes",
                expected.size_bytes,
                object.size_bytes()
            ),
        });
    }
    if object.source_sha256_metadata != expected.source_sha256 {
        return Err(ObjectStoreError::VerificationMismatch {
            key: key.clone(),
            detail: format!(
                "source_sha256 metadata mismatch: expected {}, object store metadata says {}",
                expected.source_sha256, object.source_sha256_metadata
            ),
        });
    }

    // Commit 70: metadata agreeing with the caller proves nothing about
    // the stored bytes. This mock has no server-side checksum, so it does
    // what a real adapter does in that case — reads the object back and
    // re-hashes it.
    let actual = sha256_of(&object.bytes);
    if actual != expected.source_sha256 {
        return Err(ObjectStoreError::DigestMismatch {
            key: key.clone(),
            expected: expected.source_sha256,
            actual,
        });
    }

    Ok(VerifiedObjectReceipt {
        key: key.clone(),
        etag: object.etag.clone(),
        version_id: object.version_id.clone(),
        size_bytes: object.size_bytes(),
        source_sha256: object.source_sha256_metadata,
        digest_proof: DigestProof::StreamedReadback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha_of(byte: u8) -> SourceSha256 {
        SourceSha256::from_bytes([byte; 32])
    }

    fn part_number(n: u16) -> PartNumber {
        PartNumber::new(n).expect("valid part number in test")
    }

    /// The honest digest of the object a two-part upload produces — what a
    /// caller that actually hashed its source file would declare.
    fn sha_of_parts(part_a: &[u8], part_b: &[u8]) -> SourceSha256 {
        let mut joined = part_a.to_vec();
        joined.extend_from_slice(part_b);
        sha256_of(&joined)
    }

    fn upload_two_parts(
        store: &MemoryObjectStore,
        key: &str,
        source_sha256: SourceSha256,
        part_a: &[u8],
        part_b: &[u8],
    ) -> (MultipartUploadHandle, CompletedUpload) {
        let handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey(key.to_string()),
                content_length: (part_a.len() + part_b.len()) as u64,
                source_sha256,
                content_type: Some("video/mp4".to_string()),
            })
            .expect("initiate succeeds");

        let etag1 = store
            .upload_part(&handle, part_number(1), part_a)
            .expect("upload part 1 succeeds");
        let etag2 = store
            .upload_part(&handle, part_number(2), part_b)
            .expect("upload part 2 succeeds");

        let completed = store
            .complete_multipart_upload(&handle, vec![etag1, etag2])
            .expect("complete succeeds");

        (handle, completed)
    }

    #[test]
    fn source_sha256_hex_round_trips() {
        let sha = sha_of(0xAB);
        let hex = sha.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = SourceSha256::from_hex(&hex).expect("valid hex parses");
        assert_eq!(parsed, sha);
    }

    #[test]
    fn part_number_rejects_out_of_range_values() {
        assert!(PartNumber::new(0).is_err());
        assert!(PartNumber::new(10_001).is_err());
        assert!(PartNumber::new(1).is_ok());
        assert!(PartNumber::new(10_000).is_ok());
    }

    #[test]
    fn normal_upload_completes_and_verifies() {
        let store = MemoryObjectStore::new();
        let sha = sha_of_parts(b"hello ", b"world");
        let (_, completed) =
            upload_two_parts(&store, "session/video.mp4", sha, b"hello ", b"world");

        // Requirement: multipart ETag must never stand in for the source
        // hash — assert they are visibly different values.
        assert_ne!(completed.etag, sha.to_hex());

        let receipt = store
            .verify_object(
                &ObjectKey("session/video.mp4".to_string()),
                &ExpectedObject {
                    size_bytes: 11,
                    source_sha256: sha,
                },
            )
            .expect("verify succeeds for a correctly uploaded object");

        assert_eq!(receipt.size_bytes, 11);
        assert_eq!(receipt.source_sha256, sha);
        assert_eq!(receipt.etag, completed.etag);
        assert_eq!(receipt.version_id, completed.version_id);
    }

    #[test]
    fn idempotent_reupload_of_same_source_converges_to_matching_receipt() {
        let store = MemoryObjectStore::new();
        let sha = sha_of_parts(b"same-", b"bytes!!");
        let key = "session/video.mp4";

        let (_, first) = upload_two_parts(&store, key, sha, b"same-", b"bytes!!");
        let expected = ExpectedObject {
            size_bytes: 12,
            source_sha256: sha,
        };
        let first_receipt = store
            .verify_object(&ObjectKey(key.to_string()), &expected)
            .expect("first verify succeeds");

        // Re-run the whole upload workflow for the identical source file
        // (as a coordinator retrying a job it isn't sure completed would
        // do). This must converge to an object that verifies identically
        // on the properties that matter (size, source hash) even though
        // the multipart ETag legitimately differs (fresh upload id/parts).
        let (_, second) = upload_two_parts(&store, key, sha, b"same-", b"bytes!!");
        let second_receipt = store
            .verify_object(&ObjectKey(key.to_string()), &expected)
            .expect("second verify succeeds");

        assert_eq!(first_receipt.size_bytes, second_receipt.size_bytes);
        assert_eq!(first_receipt.source_sha256, second_receipt.source_sha256);
        assert_ne!(first.upload_id, second.upload_id);
    }

    #[test]
    fn retrying_complete_after_success_is_structured_not_a_panic_and_verify_recovers() {
        let store = MemoryObjectStore::new();
        let sha = sha_of_parts(b"abc", b"def");
        let key = "session/video.mp4";
        let (handle, completed) = upload_two_parts(&store, key, sha, b"abc", b"def");

        // Simulate the client not having observed the first Complete
        // response (crash/disconnect) and retrying with the same handle
        // and parts it remembers.
        let etag1 = PartETag {
            part_number: part_number(1),
            etag: fake_etag(b"abc"),
        };
        let etag2 = PartETag {
            part_number: part_number(2),
            etag: fake_etag(b"def"),
        };
        let retry = store.complete_multipart_upload(&handle, vec![etag1, etag2]);
        assert_eq!(
            retry,
            Err(ObjectStoreError::UnknownUpload(handle.upload_id.clone()))
        );

        // Documented recovery: fall back to verify_object with the
        // caller's own remembered expectation.
        let receipt = store
            .verify_object(
                &ObjectKey(key.to_string()),
                &ExpectedObject {
                    size_bytes: 6,
                    source_sha256: sha,
                },
            )
            .expect("verify_object confirms the earlier completion actually landed");
        assert_eq!(receipt.etag, completed.etag);
    }

    #[test]
    fn simulated_server_error_is_structured_not_a_panic() {
        let store = MemoryObjectStore::new();
        store.queue_fault(
            FaultPoint::InitiateMultipartUpload,
            ObjectStoreError::ServerError {
                status: 500,
                detail: "internal error".to_string(),
            },
        );

        let result = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: sha_of(1),
            content_type: None,
        });

        assert_eq!(
            result,
            Err(ObjectStoreError::ServerError {
                status: 500,
                detail: "internal error".to_string(),
            })
        );

        // The fault only fires once — the next call succeeds normally,
        // proving the mock doesn't wedge into a permanent failure state.
        let retried = store.initiate_multipart_upload(InitiateUploadRequest {
            key: ObjectKey("x".to_string()),
            content_length: 1,
            source_sha256: sha_of(1),
            content_type: None,
        });
        assert!(retried.is_ok());
    }

    #[test]
    fn simulated_rate_limit_is_structured_not_a_panic() {
        let store = MemoryObjectStore::new();
        let handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("x".to_string()),
                content_length: 1,
                source_sha256: sha_of(1),
                content_type: None,
            })
            .expect("initiate succeeds");

        store.queue_fault(
            FaultPoint::UploadPart,
            ObjectStoreError::RateLimited {
                retry_after_ms: Some(250),
            },
        );

        let result = store.upload_part(&handle, part_number(1), b"data");
        assert_eq!(
            result,
            Err(ObjectStoreError::RateLimited {
                retry_after_ms: Some(250)
            })
        );
    }

    #[test]
    fn simulated_auth_failure_is_structured_not_a_panic() {
        let store = MemoryObjectStore::new();
        let handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("x".to_string()),
                content_length: 1,
                source_sha256: sha_of(1),
                content_type: None,
            })
            .expect("initiate succeeds");
        let etag = store
            .upload_part(&handle, part_number(1), b"data")
            .expect("upload part succeeds");

        store.queue_fault(
            FaultPoint::CompleteMultipartUpload,
            ObjectStoreError::Auth {
                status: 403,
                detail: "signature invalid".to_string(),
            },
        );

        let result = store.complete_multipart_upload(&handle, vec![etag]);
        assert_eq!(
            result,
            Err(ObjectStoreError::Auth {
                status: 403,
                detail: "signature invalid".to_string(),
            })
        );
    }

    #[test]
    fn disconnect_mid_multipart_then_abort_cleans_up_state() {
        let store = MemoryObjectStore::new();
        let handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("session/video.mp4".to_string()),
                content_length: 100,
                source_sha256: sha_of(4),
                content_type: None,
            })
            .expect("initiate succeeds");
        store
            .upload_part(&handle, part_number(1), b"partial-data-before-disconnect")
            .expect("first part uploads before the simulated disconnect");

        assert_eq!(store.in_progress_upload_count(), 1);

        // "restart": the client has lost its in-memory upload progress
        // and, per the module docs, does not attempt true resume in this
        // spike — it aborts and starts fresh.
        store
            .abort_multipart_upload(&handle)
            .expect("abort cleans up");
        assert_eq!(store.in_progress_upload_count(), 0);
        assert_eq!(store.object_count(), 0);

        // Post-abort operations on the same handle come back as
        // structured errors, not panics, and not silent success.
        let upload_after_abort = store.upload_part(&handle, part_number(2), b"more");
        assert_eq!(
            upload_after_abort,
            Err(ObjectStoreError::UnknownUpload(handle.upload_id.clone()))
        );
        let complete_after_abort = store.complete_multipart_upload(&handle, vec![]);
        assert_eq!(
            complete_after_abort,
            Err(ObjectStoreError::UnknownUpload(handle.upload_id.clone()))
        );
    }

    #[test]
    fn metadata_mismatch_after_upload_fails_verification_not_silently_accepted() {
        let store = MemoryObjectStore::new();
        let sha = sha_of_parts(b"abc", b"def");
        let key = "session/video.mp4";
        upload_two_parts(&store, key, sha, b"abc", b"def");

        // Simulate the object store's metadata drifting from what was
        // actually declared at upload time.
        store.corrupt_stored_metadata(&ObjectKey(key.to_string()), sha_of(0xFF));

        let result = store.verify_object(
            &ObjectKey(key.to_string()),
            &ExpectedObject {
                size_bytes: 6,
                source_sha256: sha,
            },
        );

        assert!(matches!(
            result,
            Err(ObjectStoreError::VerificationMismatch { .. })
        ));
    }

    #[test]
    fn size_mismatch_after_upload_fails_verification() {
        let store = MemoryObjectStore::new();
        let sha = sha_of_parts(b"abc", b"def");
        let key = "session/video.mp4";
        upload_two_parts(&store, key, sha, b"abc", b"def");

        let result = store.verify_object(
            &ObjectKey(key.to_string()),
            &ExpectedObject {
                size_bytes: 999,
                source_sha256: sha,
            },
        );

        assert!(matches!(
            result,
            Err(ObjectStoreError::VerificationMismatch { .. })
        ));
    }

    #[test]
    fn verify_object_for_missing_key_returns_not_found() {
        let store = MemoryObjectStore::new();
        let result = store.verify_object(
            &ObjectKey("never-uploaded".to_string()),
            &ExpectedObject {
                size_bytes: 1,
                source_sha256: sha_of(7),
            },
        );
        assert_eq!(
            result,
            Err(ObjectStoreError::NotFound(ObjectKey(
                "never-uploaded".to_string()
            )))
        );
    }

    #[test]
    fn complete_with_non_contiguous_parts_is_rejected_but_upload_survives() {
        let store = MemoryObjectStore::new();
        let handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("session/video.mp4".to_string()),
                content_length: 6,
                source_sha256: sha_of(8),
                content_type: None,
            })
            .expect("initiate succeeds");
        let etag1 = store
            .upload_part(&handle, part_number(1), b"abc")
            .expect("part 1 uploads");
        let etag3 = PartETag {
            part_number: part_number(3),
            etag: "bogus".to_string(),
        };

        let result = store.complete_multipart_upload(&handle, vec![etag1.clone(), etag3]);
        assert!(matches!(result, Err(ObjectStoreError::InvalidPart(_))));

        // The failed Complete must not have destroyed the in-progress
        // upload — a corrected Complete call still works.
        let etag2 = store
            .upload_part(&handle, part_number(2), b"def")
            .expect("part 2 still uploadable after the rejected complete");
        let completed = store
            .complete_multipart_upload(&handle, vec![etag1, etag2])
            .expect("complete succeeds with a correct, contiguous part list");
        assert_eq!(completed.key, ObjectKey("session/video.mp4".to_string()));
    }

    #[test]
    fn multipart_upload_record_is_durable_shaped_and_serializes() {
        let store = MemoryObjectStore::new();
        let handle = store
            .initiate_multipart_upload(InitiateUploadRequest {
                key: ObjectKey("session/video.mp4".to_string()),
                content_length: 6,
                source_sha256: sha_of(9),
                content_type: None,
            })
            .expect("initiate succeeds");
        store
            .upload_part(&handle, part_number(1), b"abc")
            .expect("part uploads");

        let record = store
            .export_upload_record(&handle.upload_id)
            .expect("in-progress upload has an exportable record");
        assert_eq!(record.status, MultipartUploadStatus::InProgress);
        assert_eq!(record.completed_parts.len(), 1);

        // Prove the shape actually round-trips through serde — this is
        // what a future persistence layer would rely on.
        let json = serde_json::to_string(&record).expect("record serializes");
        let round_tripped: MultipartUploadRecord =
            serde_json::from_str(&json).expect("record deserializes");
        assert_eq!(round_tripped, record);
    }
}
