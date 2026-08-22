//! The production `S3ObjectStore`'s run of the shared `ObjectStorePort`
//! contract (issue #1, commits 69/70; object-store half of commit 94).
//!
//! Same suite, same assertions as the in-memory store runs in
//! `ylx-transfer-core` — that is the point. Completion binding, real
//! content digests, resume, abort, metadata/checksum mismatch, 429/5xx
//! retry and connection loss are properties of the seam, so an
//! implementation that only satisfies them in a fake would be caught here.
//!
//! Two lanes:
//!
//! - the **default lane** drives the real adapter (real signing, real
//!   HTTP, real streaming read-back) against the in-process S3 backend in
//!   `object_store_support`, once with bucket versioning on and once with
//!   it off, because commit 69's binding resolves differently — but always
//!   explicitly — on each;
//! - the **MinIO lane** drives the same adapter against a real
//!   S3-compatible server. It is `#[ignore]`d and requires `YLX_MINIO_*`
//!   in the environment, so it can never be counted as passed when it did
//!   not run (commit 04's honesty rule). The hermetic runner starts a fresh
//!   MinIO with random root credentials; the harness then creates a random
//!   bucket/prefix and removes both on drop. Run it with:
//!
//!   ```text
//!   tests/support/run_minio_object_store_contract.sh
//!   ```
//!
//!   Every object it writes is removed by the suite's cleanup guards. With
//!   `YLX_MINIO_FAULT_PROXY=1` (the runner's default), 429/5xx/network-loss
//!   cases execute through a loopback fault proxy; without it those cases are
//!   reported as skipped, never silently counted as passed.

mod object_store_support;

use object_store_support::{FakeBackedHarness, MinioHarness, Versioning};
use ylx_transfer_core::library::object_store_contract::{
    run_object_store_contract, ObjectStoreContractHarness, CONTRACT_CASES, FAULT_CASES,
};

#[test]
fn production_adapter_satisfies_the_contract_on_a_versioned_backend() {
    let harness = FakeBackedHarness::new(Versioning::Enabled);
    let report = run_object_store_contract(&harness);
    report.assert_success();
    assert_eq!(
        report.executed.len(),
        CONTRACT_CASES.len(),
        "the fake backend can inject faults, so every case must actually run; skipped: {:?}",
        report.skipped
    );
}

/// Without versioning there is nothing to pin a read to, so an overwrite
/// of the same key must surface as an explicit completion-binding failure
/// rather than as a pass on someone else's object.
#[test]
fn production_adapter_satisfies_the_contract_on_an_unversioned_backend() {
    let harness = FakeBackedHarness::new(Versioning::Disabled);
    let report = run_object_store_contract(&harness);
    report.assert_success();
    assert_eq!(
        report.executed.len(),
        CONTRACT_CASES.len(),
        "the fake backend can inject faults, so every case must actually run; skipped: {:?}",
        report.skipped
    );
}

/// A real S3-compatible server. `#[ignore]`d: it needs credentials and a
/// live endpoint, and a lane that did not run must never look like a lane
/// that passed.
#[test]
#[ignore = "needs a live S3-compatible server; use tests/support/run_minio_object_store_contract.sh"]
fn production_adapter_satisfies_the_contract_against_real_minio() {
    let harness = MinioHarness::from_env();
    let has_fault_proxy = harness.fault_injector().is_some();
    let report = run_object_store_contract(&harness);
    report.assert_success();

    if has_fault_proxy {
        for case in FAULT_CASES {
            assert!(
                report.was_executed(case),
                "fault proxy was enabled, so {case} must execute rather than be skipped"
            );
        }
    } else {
        // A plain real server cannot be told to answer the next PUT with a
        // 429/5xx or drop a connection. Those cases are still reported
        // explicitly as ignored evidence, never folded into the pass count.
        for case in FAULT_CASES {
            assert!(
                report.was_skipped(case),
                "{case} needs fault injection; it must be reported as skipped"
            );
        }
    }
    let expected_executed = if has_fault_proxy {
        CONTRACT_CASES.len()
    } else {
        CONTRACT_CASES.len() - FAULT_CASES.len()
    };
    assert_eq!(
        report.executed.len(),
        expected_executed,
        "executed {:?}, skipped {:?}",
        report.executed,
        report.skipped
    );
    println!(
        "MinIO lane: executed {:?}; skipped {:?}; cleanup={}",
        report.executed,
        report.skipped,
        harness.cleanup_evidence()
    );
}
