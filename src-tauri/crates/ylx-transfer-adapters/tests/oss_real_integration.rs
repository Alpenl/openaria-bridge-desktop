//! Real-endpoint integration probe for `S3ObjectStore` against Aliyun OSS.
//!
//! `object_store_s3.rs`'s module docs call out that its unit tests run
//! against a self-hosted `tiny_http` fake, which proves the adapter's
//! request/response wire-format logic is self-consistent but is *not*
//! independent verification against a real S3-compatible implementation's
//! SigV4 validator. This file closes exactly that gap for one concrete
//! backend.
//!
//! `#[ignore]` by default: it performs real network I/O and writes a real
//! object, so it never runs in a normal `cargo test`. Run it explicitly
//! with credentials in the environment:
//!
//! ```text
//! YLX_OSS_ENDPOINT=https://oss-cn-beijing.aliyuncs.com \
//! YLX_OSS_BUCKET=<bucket> \
//! YLX_OSS_ACCESS_KEY=<ak> \
//! YLX_OSS_SECRET_KEY=<sk> \
//! cargo test -p ylx-transfer-adapters --test oss_real_integration -- --ignored --nocapture
//! ```
//!
//! Credentials are read from the environment only — never committed, and
//! never written to the repo (ADR-CRED-001).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use ylx_transfer_adapters::object_store_s3::{S3ObjectStore, S3ObjectStoreConfig, UrlStyle};
use ylx_transfer_core::library::object_store_port::{
    ExpectedObject, InitiateUploadRequest, ObjectKey, ObjectStorePort, PartNumber, SourceSha256,
};

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set to run this probe"))
}

fn config(url_style: UrlStyle) -> S3ObjectStoreConfig {
    S3ObjectStoreConfig {
        endpoint: env_var("YLX_OSS_ENDPOINT")
            .parse()
            .expect("YLX_OSS_ENDPOINT is a valid URL"),
        bucket: env_var("YLX_OSS_BUCKET"),
        // OSS ignores the SigV4 credential-scope region entirely (verified:
        // `cn-beijing`, `us-east-1` and `oss-cn-beijing` all authenticate),
        // so this keeps composition.rs's app-wide default rather than
        // introducing a region field the settings form does not have.
        region: "us-east-1".to_string(),
        url_style,
        access_key: env_var("YLX_OSS_ACCESS_KEY"),
        secret_key: env_var("YLX_OSS_SECRET_KEY"),
        request_timeout: Duration::from_secs(30),
    }
}

fn probe_key(label: &str) -> ObjectKey {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_nanos();
    let prefix = std::env::var("YLX_OSS_PREFIX").unwrap_or_else(|_| "ylx-transfer-probe".into());
    ObjectKey(format!("{prefix}/{label}-{nonce}.bin"))
}

/// Full `initiate -> upload_part -> complete -> verify` round trip against
/// the real endpoint, proving OSS accepts rusty-s3's presigned SigV4 URLs
/// and round-trips the `x-amz-meta-source-sha256` metadata header.
#[test]
#[ignore = "performs real network I/O against Aliyun OSS; needs YLX_OSS_* credentials"]
fn virtual_host_style_multipart_round_trip_against_real_oss() {
    let store = S3ObjectStore::new(config(UrlStyle::VirtualHost)).expect("adapter constructs");

    // 1 MiB of non-uniform bytes: a single part is allowed to be under
    // S3's 5 MiB minimum because it is also the last part.
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let sha256 = SourceSha256::from_bytes(Sha256::digest(&payload).into());
    let key = probe_key("multipart");

    let handle = store
        .initiate_multipart_upload(InitiateUploadRequest {
            key: key.clone(),
            content_length: payload.len() as u64,
            source_sha256: sha256,
            content_type: Some("application/octet-stream".to_string()),
        })
        .expect("OSS accepts the signed CreateMultipartUpload");
    println!("upload_id = {}", handle.upload_id.0);

    let part = store
        .upload_part(&handle, PartNumber::new(1).unwrap(), &payload)
        .expect("OSS accepts the signed UploadPart");
    println!("part 1 etag = {}", part.etag);

    let completed = store
        .complete_multipart_upload(&handle, vec![part])
        .expect("OSS accepts the signed CompleteMultipartUpload");
    println!("object etag = {}", completed.etag);

    let receipt = store
        .verify_object(
            &key,
            &ExpectedObject {
                size_bytes: payload.len() as u64,
                source_sha256: sha256,
            },
        )
        .expect("HEAD verifies size and source-sha256 metadata");
    assert_eq!(receipt.size_bytes, payload.len() as u64);
    assert_eq!(receipt.source_sha256, sha256);
    println!("VERIFIED key = {}", receipt.key.0);
}

/// `abort` must really release the multipart upload on the live endpoint,
/// not just return `Ok` locally.
#[test]
#[ignore = "performs real network I/O against Aliyun OSS; needs YLX_OSS_* credentials"]
fn abort_releases_a_real_multipart_upload() {
    let store = S3ObjectStore::new(config(UrlStyle::VirtualHost)).expect("adapter constructs");
    let key = probe_key("aborted");

    let handle = store
        .initiate_multipart_upload(InitiateUploadRequest {
            key: key.clone(),
            content_length: 0,
            source_sha256: SourceSha256::from_bytes([0u8; 32]),
            content_type: None,
        })
        .expect("OSS accepts the signed CreateMultipartUpload");

    store
        .abort_multipart_upload(&handle)
        .expect("OSS accepts the signed AbortMultipartUpload");
    println!("aborted upload_id = {}", handle.upload_id.0);
}

/// Documents why `composition.rs` cannot keep its hardcoded
/// `UrlStyle::Path`: OSS rejects second-level-domain (path-style) access
/// outright, before any signature check.
#[test]
#[ignore = "performs real network I/O against Aliyun OSS; needs YLX_OSS_* credentials"]
fn path_style_is_rejected_by_oss() {
    let store = S3ObjectStore::new(config(UrlStyle::Path)).expect("adapter constructs");
    let key = probe_key("path-style");

    let err = store
        .initiate_multipart_upload(InitiateUploadRequest {
            key,
            content_length: 0,
            source_sha256: SourceSha256::from_bytes([0u8; 32]),
            content_type: None,
        })
        .expect_err("OSS refuses path-style access");
    println!("path-style error = {err:?}");

    // Assert on OSS's actual refusal, not merely "some error": with a
    // dead proxy in the environment this test passed on a
    // `Network("io: Connection refused")` that never reached OSS at all.
    let detail = format!("{err:?}");
    assert!(
        detail.contains("virtual hosted style"),
        "expected OSS's SecondLevelDomainForbidden refusal, got: {detail}"
    );
}
