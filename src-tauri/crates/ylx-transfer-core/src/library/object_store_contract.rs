//! Shared [`ObjectStorePort`] contract suite (issue #1, commits 69/70,
//! and the object-store half of commit 94).
//!
//! The guarantees commits 69 and 70 add — "the object I verify is the one
//! *this* multipart completion produced" and "its real bytes hash to what
//! I expect" — are properties of the **seam**, not of any single
//! implementation. An in-memory fake that gets them right while the
//! production S3 adapter quietly falls back to a latest-HEAD would be
//! worse than useless, so the properties are asserted once here and run
//! against every implementation:
//!
//! - [`MemoryObjectStore`] (both versioned and unversioned modes),
//! - the production `ylx_transfer_adapters::object_store_s3::S3ObjectStore`
//!   driven against a real HTTP S3 fake on loopback, and
//! - the same adapter against a real MinIO, in an `#[ignore]`d lane.
//!
//! # Honest reporting
//!
//! Two cases (transport faults, connection loss) need a fault injector the
//! harness may not have — a real MinIO cannot be told to answer the next
//! `UploadPart` with `429`. Those cases are **skipped, not silently
//! passed**: [`run_object_store_contract`] records them in
//! [`ContractReport::skipped`] with a reason, and callers assert on that
//! list. Nothing in this suite reports a case as executed unless it ran
//! (commit 04's CI honesty rule).
//!
//! # Cleanup
//!
//! Every key the suite touches is handed out through [`ContractKey`],
//! which calls [`ObjectStoreContractHarness::cleanup`] on drop — including
//! on a panic — so a run against a real bucket leaves nothing behind.
//!
//! Compiled only for test builds (`cfg(test)`) or when the `test-support`
//! feature is enabled, so this scaffolding never ships in the app binary.

use super::object_store_port::{
    sha256_of, CompletedUpload, ExpectedObject, InitiateUploadRequest, MultipartUploadHandle,
    ObjectKey, ObjectStoreError, ObjectStorePort, PartETag, PartNumber, SourceSha256,
};

// ---------------------------------------------------------------------
// Harness seam
// ---------------------------------------------------------------------

/// Which port method a queued fault applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractOp {
    InitiateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    VerifyObject,
}

/// A transport-level failure a backend can be made to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractFault {
    /// HTTP 429 (or the backend's equivalent).
    RateLimited,
    /// HTTP 5xx.
    ServerError,
    /// The connection dies mid-request — no status code at all.
    NetworkLoss,
}

/// Optional harness capability: make the *next* call to `op` fail with
/// `fault`, exactly once.
pub trait ContractFaultInjector {
    fn arm(&self, op: ContractOp, fault: ContractFault);
}

/// One implementation under test, plus the bookkeeping the suite needs to
/// run against a real bucket without leaking objects.
pub trait ObjectStoreContractHarness {
    /// Human-readable name, used in failure messages.
    fn name(&self) -> &str;

    /// The implementation under test.
    fn store(&self) -> &dyn ObjectStorePort;

    /// A key nothing else in this process (or any concurrent run) uses.
    fn unique_key(&self, label: &str) -> ObjectKey;

    /// Best-effort removal of everything stored at `key`. Called for every
    /// key the suite hands out, including on failure.
    fn cleanup(&self, key: &ObjectKey);

    /// Bytes per non-final part. Real S3-compatible backends reject
    /// non-final parts below 5 MiB, so real-endpoint harnesses override
    /// this; fakes keep it small and fast.
    fn part_size(&self) -> usize {
        8 * 1024
    }

    /// Fault injection, when the backend supports it.
    fn fault_injector(&self) -> Option<&dyn ContractFaultInjector> {
        None
    }
}

/// A key that cleans itself up. Obtained from [`ContractKey::acquire`].
pub struct ContractKey<'h> {
    harness: &'h dyn ObjectStoreContractHarness,
    key: ObjectKey,
}

impl<'h> ContractKey<'h> {
    #[must_use]
    pub fn acquire(harness: &'h dyn ObjectStoreContractHarness, label: &str) -> Self {
        Self {
            key: harness.unique_key(label),
            harness,
        }
    }

    #[must_use]
    pub fn key(&self) -> &ObjectKey {
        &self.key
    }
}

impl Drop for ContractKey<'_> {
    fn drop(&mut self) {
        self.harness.cleanup(&self.key);
    }
}

// ---------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------

/// What actually ran. `executed` and `skipped` are disjoint and together
/// cover [`CONTRACT_CASES`]; `failures` is empty on success.
#[derive(Debug, Clone)]
pub struct ContractReport {
    pub harness: String,
    pub executed: Vec<&'static str>,
    pub skipped: Vec<(&'static str, &'static str)>,
    pub failures: Vec<String>,
}

impl ContractReport {
    /// Panics with every failure listed, so one run reports every broken
    /// property instead of only the first.
    pub fn assert_success(&self) {
        assert!(
            self.failures.is_empty(),
            "object-store contract failed for {}:\n  - {}",
            self.harness,
            self.failures.join("\n  - ")
        );
        assert!(
            !self.executed.is_empty(),
            "object-store contract for {} executed no cases at all",
            self.harness
        );
    }

    #[must_use]
    pub fn was_executed(&self, case: &str) -> bool {
        self.executed.contains(&case)
    }

    #[must_use]
    pub fn was_skipped(&self, case: &str) -> bool {
        self.skipped.iter().any(|(name, _)| *name == case)
    }
}

/// Every case name the suite knows about, in run order.
pub const CONTRACT_CASES: [&str; 8] = [
    "multipart_upload_and_completion_bound_verify",
    "resume_after_interrupted_parts",
    "abort_releases_upload_and_leaves_no_object",
    "completion_binding_survives_concurrent_overwrite",
    "metadata_mismatch_fails_closed",
    "content_digest_mismatch_fails_closed",
    "rate_limit_and_server_error_are_structured_and_retryable",
    "network_loss_is_structured_and_retryable",
];

/// The two cases that need [`ContractFaultInjector`].
pub const FAULT_CASES: [&str; 2] = [
    "rate_limit_and_server_error_are_structured_and_retryable",
    "network_loss_is_structured_and_retryable",
];

const NO_INJECTOR: &str = "harness has no fault injector (real backend cannot be told to fail)";

// ---------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------

/// Runs the whole suite. Never panics on a contract violation — the
/// caller decides, via [`ContractReport::assert_success`].
pub fn run_object_store_contract(harness: &dyn ObjectStoreContractHarness) -> ContractReport {
    let mut report = ContractReport {
        harness: harness.name().to_string(),
        executed: Vec::new(),
        skipped: Vec::new(),
        failures: Vec::new(),
    };

    let cases: [(&'static str, ContractCaseFn); 8] = [
        (
            CONTRACT_CASES[0],
            case_multipart_and_completion_bound_verify,
        ),
        (CONTRACT_CASES[1], case_resume_after_interrupted_parts),
        (CONTRACT_CASES[2], case_abort_leaves_no_object),
        (CONTRACT_CASES[3], case_completion_binding_under_overwrite),
        (CONTRACT_CASES[4], case_metadata_mismatch_fails_closed),
        (CONTRACT_CASES[5], case_content_digest_mismatch_fails_closed),
        (CONTRACT_CASES[6], case_transport_faults_are_retryable),
        (CONTRACT_CASES[7], case_network_loss_is_retryable),
    ];

    for (name, case) in cases {
        match case(harness) {
            CaseResult::Passed => report.executed.push(name),
            CaseResult::Failed(detail) => {
                report.executed.push(name);
                report.failures.push(format!("[{name}] {detail}"));
            }
            CaseResult::Skipped(reason) => report.skipped.push((name, reason)),
        }
    }

    report
}

/// One contract case: everything it needs comes from the harness.
type ContractCaseFn = fn(&dyn ObjectStoreContractHarness) -> CaseResult;

enum CaseResult {
    Passed,
    Failed(String),
    Skipped(&'static str),
}

/// `?`-style early return for a case body.
macro_rules! require {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            return CaseResult::Failed(format!($($arg)*));
        }
    };
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// Deterministic, non-uniform bytes (so a truncated or swapped part
/// changes the digest).
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

struct UploadedObject {
    completion: CompletedUpload,
    expected: ExpectedObject,
    content: Vec<u8>,
}

/// Runs a full two-part multipart upload of `content`, declaring
/// `declared_sha` as the object's `source_sha256` metadata (normally the
/// honest digest of `content`; deliberately wrong in the digest-mismatch
/// case).
fn upload_object(
    harness: &dyn ObjectStoreContractHarness,
    key: &ObjectKey,
    content: Vec<u8>,
    declared_sha: SourceSha256,
) -> Result<UploadedObject, String> {
    let store = harness.store();
    let split = harness.part_size().min(content.len());
    let handle = store
        .initiate_multipart_upload(InitiateUploadRequest {
            key: key.clone(),
            content_length: content.len() as u64,
            source_sha256: declared_sha,
            content_type: Some("application/octet-stream".to_string()),
        })
        .map_err(|e| format!("initiate failed: {e}"))?;

    let mut parts = Vec::new();
    for (index, chunk) in [&content[..split], &content[split..]]
        .into_iter()
        .filter(|chunk| !chunk.is_empty())
        .enumerate()
    {
        let number = PartNumber::new(u16::try_from(index).expect("part index fits u16") + 1)
            .map_err(|e| format!("part number rejected: {e}"))?;
        parts.push(
            store
                .upload_part(&handle, number, chunk)
                .map_err(|e| format!("upload_part {} failed: {e}", number.get()))?,
        );
    }

    let completion = store
        .complete_multipart_upload(&handle, parts)
        .map_err(|e| format!("complete failed: {e}"))?;

    Ok(UploadedObject {
        expected: ExpectedObject {
            size_bytes: content.len() as u64,
            source_sha256: declared_sha,
        },
        completion,
        content,
    })
}

/// A two-part upload of honest bytes.
fn upload_honest_object(
    harness: &dyn ObjectStoreContractHarness,
    key: &ObjectKey,
    seed: u8,
) -> Result<UploadedObject, String> {
    let content = payload(seed, harness.part_size() + 1024);
    let sha = sha256_of(&content);
    upload_object(harness, key, content, sha)
}

// ---------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------

/// The happy path, end to end — and the one place the *positive* shape of
/// a completion-bound receipt is pinned: same ETag, same version id, real
/// content digest.
fn case_multipart_and_completion_bound_verify(
    harness: &dyn ObjectStoreContractHarness,
) -> CaseResult {
    let guard = ContractKey::acquire(harness, "multipart");
    let uploaded = match upload_honest_object(harness, guard.key(), 0x11) {
        Ok(uploaded) => uploaded,
        Err(e) => return CaseResult::Failed(e),
    };

    require!(
        !uploaded.completion.etag.trim().is_empty(),
        "completion carried an empty ETag, so nothing can be bound to it"
    );

    let receipt = match harness
        .store()
        .verify_completed_object(&uploaded.completion, &uploaded.expected)
    {
        Ok(receipt) => receipt,
        Err(e) => {
            return CaseResult::Failed(format!(
                "verify_completed_object rejected the upload it just made: {e}"
            ))
        }
    };

    require!(
        receipt.key == *guard.key(),
        "receipt is for {:?}, expected {:?}",
        receipt.key,
        guard.key()
    );
    require!(
        receipt.etag == uploaded.completion.etag,
        "receipt ETag {:?} is not the completion's ETag {:?}",
        receipt.etag,
        uploaded.completion.etag
    );
    require!(
        uploaded.completion.version_id.is_none()
            || receipt.version_id == uploaded.completion.version_id,
        "receipt version {:?} is not the completion's version {:?}",
        receipt.version_id,
        uploaded.completion.version_id
    );
    require!(
        receipt.size_bytes == uploaded.expected.size_bytes,
        "receipt size {} != expected {}",
        receipt.size_bytes,
        uploaded.expected.size_bytes
    );
    require!(
        receipt.source_sha256 == uploaded.expected.source_sha256,
        "receipt digest {} != expected {}",
        receipt.source_sha256,
        uploaded.expected.source_sha256
    );
    require!(
        receipt.source_sha256 == sha256_of(&uploaded.content),
        "receipt digest does not match the bytes that were uploaded"
    );

    CaseResult::Passed
}

/// A client that lost its in-flight state re-sends a part it is not sure
/// landed, then completes. The re-sent part must supersede the first
/// attempt, and the finished object must still hash correctly.
fn case_resume_after_interrupted_parts(harness: &dyn ObjectStoreContractHarness) -> CaseResult {
    let guard = ContractKey::acquire(harness, "resume");
    let store = harness.store();
    let split = harness.part_size();
    let content = payload(0x22, split + 2048);
    let sha = sha256_of(&content);

    let handle = match store.initiate_multipart_upload(InitiateUploadRequest {
        key: guard.key().clone(),
        content_length: content.len() as u64,
        source_sha256: sha,
        content_type: None,
    }) {
        Ok(handle) => handle,
        Err(e) => return CaseResult::Failed(format!("initiate failed: {e}")),
    };

    let first = match store.upload_part(&handle, part(1), &content[..split]) {
        Ok(part) => part,
        Err(e) => return CaseResult::Failed(format!("upload_part 1 failed: {e}")),
    };
    // The response to this one is "lost": the client never sees the ETag.
    if let Err(e) = store.upload_part(&handle, part(2), &content[split..]) {
        return CaseResult::Failed(format!("upload_part 2 failed: {e}"));
    }
    // Resume: re-send the same part and keep the ETag from the retry.
    let second = match store.upload_part(&handle, part(2), &content[split..]) {
        Ok(part) => part,
        Err(e) => return CaseResult::Failed(format!("resumed upload_part 2 failed: {e}")),
    };

    let completion = match store.complete_multipart_upload(&handle, vec![first, second]) {
        Ok(completion) => completion,
        Err(e) => return CaseResult::Failed(format!("complete after resume failed: {e}")),
    };
    let expected = ExpectedObject {
        size_bytes: content.len() as u64,
        source_sha256: sha,
    };
    match store.verify_completed_object(&completion, &expected) {
        Ok(receipt) => {
            require!(
                receipt.source_sha256 == sha,
                "resumed object verified to the wrong digest"
            );
            CaseResult::Passed
        }
        Err(e) => CaseResult::Failed(format!("resumed upload failed verification: {e}")),
    }
}

/// Abort must leave no object and no usable upload id.
fn case_abort_leaves_no_object(harness: &dyn ObjectStoreContractHarness) -> CaseResult {
    let guard = ContractKey::acquire(harness, "abort");
    let store = harness.store();
    let content = payload(0x33, harness.part_size());

    let handle = match store.initiate_multipart_upload(InitiateUploadRequest {
        key: guard.key().clone(),
        content_length: content.len() as u64,
        source_sha256: sha256_of(&content),
        content_type: None,
    }) {
        Ok(handle) => handle,
        Err(e) => return CaseResult::Failed(format!("initiate failed: {e}")),
    };
    if let Err(e) = store.upload_part(&handle, part(1), &content) {
        return CaseResult::Failed(format!("upload_part failed: {e}"));
    }
    if let Err(e) = store.abort_multipart_upload(&handle) {
        return CaseResult::Failed(format!("abort failed: {e}"));
    }

    match store.verify_object(
        guard.key(),
        &ExpectedObject {
            size_bytes: content.len() as u64,
            source_sha256: sha256_of(&content),
        },
    ) {
        Err(ObjectStoreError::NotFound(_)) => {}
        other => {
            return CaseResult::Failed(format!(
                "aborted upload must leave no object, got {other:?}"
            ))
        }
    }

    match store.complete_multipart_upload(
        &handle,
        vec![PartETag {
            part_number: part(1),
            etag: "whatever".to_string(),
        }],
    ) {
        Err(ObjectStoreError::UnknownUpload(_)) | Err(ObjectStoreError::InvalidPart(_)) => {}
        other => {
            return CaseResult::Failed(format!(
                "completing an aborted upload must fail structurally, got {other:?}"
            ))
        }
    }

    CaseResult::Passed
}

/// Commit 69's core property. Another writer completes a *different*
/// object on the same key, declaring the very same size and
/// `source_sha256` metadata (so every metadata-only check still passes).
/// Verifying the first completion must never hand back a receipt for the
/// second writer's bytes.
fn case_completion_binding_under_overwrite(harness: &dyn ObjectStoreContractHarness) -> CaseResult {
    let guard = ContractKey::acquire(harness, "overwrite");
    let store = harness.store();

    let mine = match upload_honest_object(harness, guard.key(), 0x44) {
        Ok(uploaded) => uploaded,
        Err(e) => return CaseResult::Failed(e),
    };
    // Same key, same length, same declared metadata — different bytes.
    let theirs_content = payload(0x99, mine.content.len());
    let theirs = match upload_object(
        harness,
        guard.key(),
        theirs_content,
        mine.expected.source_sha256,
    ) {
        Ok(uploaded) => uploaded,
        Err(e) => return CaseResult::Failed(format!("concurrent writer's upload failed: {e}")),
    };
    require!(
        theirs.completion.etag != mine.completion.etag
            || theirs.completion.version_id != mine.completion.version_id,
        "the two writers' completions are indistinguishable, so this case proves nothing"
    );

    match store.verify_completed_object(&mine.completion, &mine.expected) {
        // Versioned backend: my version is still readable, and it is mine.
        Ok(receipt) => {
            require!(
                receipt.etag == mine.completion.etag,
                "verify_completed_object returned the other writer's object ({:?} != {:?})",
                receipt.etag,
                mine.completion.etag
            );
            require!(
                receipt.version_id == mine.completion.version_id,
                "verify_completed_object returned version {:?}, my completion produced {:?}",
                receipt.version_id,
                mine.completion.version_id
            );
            require!(
                receipt.source_sha256 == sha256_of(&mine.content),
                "receipt claims a digest the verified version's bytes do not have"
            );
        }
        // Unversioned backend: my object is simply gone. That must be an
        // explicit binding failure, never a pass on the newest object.
        Err(ObjectStoreError::CompletionMismatch { .. }) | Err(ObjectStoreError::NotFound(_)) => {}
        Err(other) => {
            return CaseResult::Failed(format!(
                "overwrite must fail as CompletionMismatch/NotFound, got {other:?}"
            ))
        }
    }

    // The *unbound* read is the one commit 69 says is not a substitute:
    // it is looking at the other writer's object. It must still refuse to
    // certify it (commit 70's digest check catches the lying metadata).
    match store.verify_object(guard.key(), &mine.expected) {
        Err(ObjectStoreError::DigestMismatch { .. }) => {}
        other => {
            return CaseResult::Failed(format!(
                "a latest-object read of another writer's bytes must fail on content digest, got {other:?}"
            ))
        }
    }

    CaseResult::Passed
}

/// Wrong size or wrong expected digest must fail closed on metadata alone,
/// before any content is trusted.
fn case_metadata_mismatch_fails_closed(harness: &dyn ObjectStoreContractHarness) -> CaseResult {
    let guard = ContractKey::acquire(harness, "metadata");
    let store = harness.store();
    let uploaded = match upload_honest_object(harness, guard.key(), 0x55) {
        Ok(uploaded) => uploaded,
        Err(e) => return CaseResult::Failed(e),
    };

    let wrong_size = ExpectedObject {
        size_bytes: uploaded.expected.size_bytes + 1,
        source_sha256: uploaded.expected.source_sha256,
    };
    match store.verify_completed_object(&uploaded.completion, &wrong_size) {
        Err(ObjectStoreError::VerificationMismatch { .. }) => {}
        other => {
            return CaseResult::Failed(format!("size mismatch must fail closed, got {other:?}"))
        }
    }

    let wrong_sha = ExpectedObject {
        size_bytes: uploaded.expected.size_bytes,
        source_sha256: SourceSha256::from_bytes([0xEE; 32]),
    };
    match store.verify_completed_object(&uploaded.completion, &wrong_sha) {
        Err(ObjectStoreError::VerificationMismatch { .. })
        | Err(ObjectStoreError::DigestMismatch { .. }) => {}
        other => {
            return CaseResult::Failed(format!("digest mismatch must fail closed, got {other:?}"))
        }
    }

    CaseResult::Passed
}

/// Commit 70's core property: an object whose stored bytes disagree with
/// its own declared `source_sha256` passes every metadata check and must
/// still be rejected.
fn case_content_digest_mismatch_fails_closed(
    harness: &dyn ObjectStoreContractHarness,
) -> CaseResult {
    let guard = ContractKey::acquire(harness, "digest");
    let store = harness.store();

    let content = payload(0x66, harness.part_size() + 512);
    // The caller declares (and the object therefore advertises) the digest
    // of *different* bytes — a corrupted read, a swapped file, a bug.
    let lied_about = sha256_of(&payload(0x67, content.len()));
    let uploaded = match upload_object(harness, guard.key(), content, lied_about) {
        Ok(uploaded) => uploaded,
        Err(e) => return CaseResult::Failed(e),
    };

    match store.verify_completed_object(&uploaded.completion, &uploaded.expected) {
        Err(ObjectStoreError::DigestMismatch { expected, actual, .. }) => {
            require!(
                expected == lied_about && actual == sha256_of(&uploaded.content),
                "DigestMismatch reported expected={expected} actual={actual}, which does not describe the real object"
            );
            CaseResult::Passed
        }
        other => CaseResult::Failed(format!(
            "metadata matched but the bytes did not; verification must fail on content digest, got {other:?}"
        )),
    }
}

/// 429 and 5xx must arrive as structured, retryable errors that leave the
/// upload usable — never a panic, never a wedged upload id.
fn case_transport_faults_are_retryable(harness: &dyn ObjectStoreContractHarness) -> CaseResult {
    let Some(injector) = harness.fault_injector() else {
        return CaseResult::Skipped(NO_INJECTOR);
    };
    let guard = ContractKey::acquire(harness, "throttled");
    let store = harness.store();
    let split = harness.part_size();
    let content = payload(0x77, split + 128);
    let sha = sha256_of(&content);

    let handle = match store.initiate_multipart_upload(InitiateUploadRequest {
        key: guard.key().clone(),
        content_length: content.len() as u64,
        source_sha256: sha,
        content_type: None,
    }) {
        Ok(handle) => handle,
        Err(e) => return CaseResult::Failed(format!("initiate failed: {e}")),
    };

    injector.arm(ContractOp::UploadPart, ContractFault::RateLimited);
    match store.upload_part(&handle, part(1), &content[..split]) {
        Err(ObjectStoreError::RateLimited { .. }) => {}
        other => {
            return CaseResult::Failed(format!("429 must map to RateLimited, got {other:?}"));
        }
    }
    let first = match store.upload_part(&handle, part(1), &content[..split]) {
        Ok(part) => part,
        Err(e) => return CaseResult::Failed(format!("retry after 429 must succeed, got {e}")),
    };

    injector.arm(ContractOp::UploadPart, ContractFault::ServerError);
    match store.upload_part(&handle, part(2), &content[split..]) {
        Err(ObjectStoreError::ServerError { status, .. }) => {
            require!(
                (500..=599).contains(&status),
                "5xx fault surfaced as status {status}"
            );
        }
        other => {
            return CaseResult::Failed(format!("5xx must map to ServerError, got {other:?}"));
        }
    }
    let second = match store.upload_part(&handle, part(2), &content[split..]) {
        Ok(part) => part,
        Err(e) => return CaseResult::Failed(format!("retry after 5xx must succeed, got {e}")),
    };

    injector.arm(
        ContractOp::CompleteMultipartUpload,
        ContractFault::ServerError,
    );
    match store.complete_multipart_upload(&handle, vec![first.clone(), second.clone()]) {
        Err(ObjectStoreError::ServerError { .. }) => {}
        other => {
            return CaseResult::Failed(format!(
                "a 5xx on complete must map to ServerError, got {other:?}"
            ));
        }
    }
    let completion = match store.complete_multipart_upload(&handle, vec![first, second]) {
        Ok(completion) => completion,
        Err(e) => {
            return CaseResult::Failed(format!(
                "a failed complete must leave the upload retryable, got {e}"
            ))
        }
    };

    match store.verify_completed_object(
        &completion,
        &ExpectedObject {
            size_bytes: content.len() as u64,
            source_sha256: sha,
        },
    ) {
        Ok(_) => CaseResult::Passed,
        Err(e) => CaseResult::Failed(format!("object uploaded through faults failed verify: {e}")),
    }
}

/// A connection that dies mid-request has no status code at all — it must
/// still come back as a structured [`ObjectStoreError::Network`], and the
/// upload must survive it.
fn case_network_loss_is_retryable(harness: &dyn ObjectStoreContractHarness) -> CaseResult {
    let Some(injector) = harness.fault_injector() else {
        return CaseResult::Skipped(NO_INJECTOR);
    };
    let guard = ContractKey::acquire(harness, "netloss");
    let store = harness.store();
    let content = payload(0x88, harness.part_size());
    let sha = sha256_of(&content);

    let handle = match store.initiate_multipart_upload(InitiateUploadRequest {
        key: guard.key().clone(),
        content_length: content.len() as u64,
        source_sha256: sha,
        content_type: None,
    }) {
        Ok(handle) => handle,
        Err(e) => return CaseResult::Failed(format!("initiate failed: {e}")),
    };

    injector.arm(ContractOp::UploadPart, ContractFault::NetworkLoss);
    match store.upload_part(&handle, part(1), &content) {
        Err(ObjectStoreError::Network(_)) => {}
        other => {
            return CaseResult::Failed(format!(
                "a dropped connection must map to Network, got {other:?}"
            ));
        }
    }

    let retried = match store.upload_part(&handle, part(1), &content) {
        Ok(part) => part,
        Err(e) => {
            return CaseResult::Failed(format!("retry after connection loss must succeed, got {e}"))
        }
    };
    let completion = match store.complete_multipart_upload(&handle, vec![retried]) {
        Ok(completion) => completion,
        Err(e) => return CaseResult::Failed(format!("complete after connection loss failed: {e}")),
    };
    match store.verify_completed_object(
        &completion,
        &ExpectedObject {
            size_bytes: content.len() as u64,
            source_sha256: sha,
        },
    ) {
        Ok(_) => CaseResult::Passed,
        Err(e) => CaseResult::Failed(format!("object recovered from connection loss failed: {e}")),
    }
}

fn part(n: u16) -> PartNumber {
    PartNumber::new(n).expect("contract suite uses valid part numbers")
}

/// Convenience for harnesses that want the handle type without importing
/// the whole port module.
pub type ContractHandle = MultipartUploadHandle;

// ---------------------------------------------------------------------
// The in-memory implementation's own run of the suite
// ---------------------------------------------------------------------

#[cfg(test)]
mod memory_lane {
    use super::*;
    use crate::library::object_store_port::{FaultPoint, MemoryObjectStore};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct MemoryHarness {
        name: &'static str,
        store: MemoryObjectStore,
        seq: AtomicU64,
    }

    impl ContractFaultInjector for MemoryHarness {
        fn arm(&self, op: ContractOp, fault: ContractFault) {
            let point = match op {
                ContractOp::InitiateMultipartUpload => FaultPoint::InitiateMultipartUpload,
                ContractOp::UploadPart => FaultPoint::UploadPart,
                ContractOp::CompleteMultipartUpload => FaultPoint::CompleteMultipartUpload,
                ContractOp::VerifyObject => FaultPoint::VerifyObject,
            };
            let error = match fault {
                ContractFault::RateLimited => ObjectStoreError::RateLimited {
                    retry_after_ms: Some(50),
                },
                ContractFault::ServerError => ObjectStoreError::ServerError {
                    status: 503,
                    detail: "simulated".to_string(),
                },
                ContractFault::NetworkLoss => {
                    ObjectStoreError::Network("simulated connection reset".to_string())
                }
            };
            self.store.queue_fault(point, error);
        }
    }

    impl ObjectStoreContractHarness for MemoryHarness {
        fn name(&self) -> &str {
            self.name
        }

        fn store(&self) -> &dyn ObjectStorePort {
            &self.store
        }

        fn unique_key(&self, label: &str) -> ObjectKey {
            let n = self.seq.fetch_add(1, Ordering::Relaxed);
            ObjectKey(format!("contract/{label}-{n}.bin"))
        }

        fn cleanup(&self, key: &ObjectKey) {
            self.store.delete_object(key);
        }

        fn fault_injector(&self) -> Option<&dyn ContractFaultInjector> {
            Some(self)
        }
    }

    #[test]
    fn memory_object_store_satisfies_the_contract() {
        for (name, store) in [
            ("MemoryObjectStore(versioned)", MemoryObjectStore::new()),
            (
                "MemoryObjectStore(unversioned)",
                MemoryObjectStore::unversioned(),
            ),
        ] {
            let harness = MemoryHarness {
                name,
                store,
                seq: AtomicU64::new(0),
            };
            let report = run_object_store_contract(&harness);
            report.assert_success();
            assert_eq!(
                report.executed.len(),
                CONTRACT_CASES.len(),
                "{name} has a fault injector, so no case may be skipped: {:?}",
                report.skipped
            );
        }
    }

    #[test]
    fn a_harness_without_fault_injection_reports_skips_instead_of_passes() {
        struct NoFaults(MemoryHarness);
        impl ObjectStoreContractHarness for NoFaults {
            fn name(&self) -> &str {
                "MemoryObjectStore(no fault injector)"
            }
            fn store(&self) -> &dyn ObjectStorePort {
                self.0.store()
            }
            fn unique_key(&self, label: &str) -> ObjectKey {
                self.0.unique_key(label)
            }
            fn cleanup(&self, key: &ObjectKey) {
                self.0.cleanup(key);
            }
        }

        let harness = NoFaults(MemoryHarness {
            name: "inner",
            store: MemoryObjectStore::new(),
            seq: AtomicU64::new(0),
        });
        let report = run_object_store_contract(&harness);
        report.assert_success();

        for case in FAULT_CASES {
            assert!(
                report.was_skipped(case) && !report.was_executed(case),
                "{case} must be reported skipped, never quietly passed"
            );
        }
        assert_eq!(
            report.executed.len(),
            CONTRACT_CASES.len() - FAULT_CASES.len()
        );
    }

    #[test]
    fn contract_keys_are_cleaned_up_even_when_a_case_fails() {
        let harness = MemoryHarness {
            name: "cleanup",
            store: MemoryObjectStore::new(),
            seq: AtomicU64::new(0),
        };
        let report = run_object_store_contract(&harness);
        report.assert_success();
        assert_eq!(
            harness.store.object_count(),
            0,
            "every contract object must be removed by its ContractKey guard"
        );
        assert_eq!(
            harness.store.in_progress_upload_count(),
            0,
            "no multipart upload may be left in progress"
        );
    }
}
