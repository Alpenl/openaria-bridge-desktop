//! Commit 08 regression test: job ids must survive a process restart.
//!
//! `Coordinator::next_job_id` used to be a process-local `AtomicU64`
//! counter formatted as `job-{seq:016x}`. The counter restarts at zero on
//! every launch, but the `jobs` table does not: the first enqueue after a
//! restart re-proposed `job-0000000000000000`, an id the previous run had
//! already committed. The insert then tripped the `jobs` primary key, the
//! old enqueue path mistook that for an idempotency hit, re-queried by the
//! (brand-new, unseen) idempotency key, found nothing, and returned a
//! bogus `NotFound` — a perfectly valid enqueue failing purely because the
//! app had been restarted.
//!
//! This test drives the real thing end to end: enqueue, drop the
//! coordinator (closing the SQLite connection), reopen from the *same*
//! file, recover, enqueue again.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ylx_transfer_core::device::{CaptureActivityState, ConnectionState};
use ylx_transfer_core::domain::{DeviceId, FileId, SessionId};
use ylx_transfer_core::library::download::{
    DownloadError, DownloadSource, PublicationVerifier, VerifyError,
};
use ylx_transfer_core::persistence::TransferStore;
use ylx_transfer_core::transfer::coordinator::{
    CoordinatorConfig, DeviceStatusPort, DownloadSourceFactory, TransferCoordinator,
};
use ylx_transfer_core::transfer::queue::{JobFile, TransferRequest};
use ylx_transfer_core::transfer::JobId;

/// Always offline: every job parks in `waiting_for_device` and no worker
/// ever reaches the download path, so this test observes id assignment and
/// recovery only — no network, no files, no timing.
struct OfflineDevice;

impl DeviceStatusPort for OfflineDevice {
    fn connection_state(&self, _device_id: &DeviceId) -> ConnectionState {
        ConnectionState::Disconnected
    }
    fn capture_activity(&self, _device_id: &DeviceId) -> CaptureActivityState {
        CaptureActivityState::Idle
    }
}

struct UnusedFactory;

impl DownloadSourceFactory for UnusedFactory {
    fn make_source(
        &self,
        _device_id: &DeviceId,
        _session_id: &SessionId,
        _file_id: &FileId,
    ) -> Result<Box<dyn DownloadSource>, DownloadError> {
        Err(DownloadError::Source(
            "device is offline in this test; no source should ever be built".to_string(),
        ))
    }
}

struct PassVerifier;

impl PublicationVerifier for PassVerifier {
    fn verify(&self, _manifest: &[u8], _signature: &[u8], _key: &[u8]) -> Result<(), VerifyError> {
        Ok(())
    }
}

fn coordinator(root: &Path) -> TransferCoordinator {
    TransferCoordinator::new(
        Arc::new(Mutex::new(
            TransferStore::open(root.join("transfer.sqlite3")).expect("open transfer store"),
        )),
        Arc::new(OfflineDevice),
        Arc::new(UnusedFactory),
        Arc::new(PassVerifier),
        CoordinatorConfig {
            num_workers: 1,
            dispatch_interval: Duration::from_millis(10),
            checkpoint_threshold_bytes: 16,
            library_root: root.join("library"),
        },
    )
}

fn request(key: &str) -> TransferRequest {
    TransferRequest {
        device_id: DeviceId("pi-01".to_string()),
        session_id: SessionId("session-x".to_string()),
        revision: format!("rev-{key}"),
        idempotency_key: key.to_string(),
        files: vec![JobFile {
            file_id: FileId("f1".to_string()),
            target_relative_path: None,
            expected_size: 4,
            expected_sha256_hex: "0".repeat(64),
        }],
        manifest_bytes: vec![1],
        signature: vec![2; 64],
        publication_public_key: vec![3; 32],
    }
}

#[test]
fn a_job_id_minted_after_restart_never_collides_with_a_persisted_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // --- run 1 ---------------------------------------------------------
    let first_id = {
        let coordinator = coordinator(root);
        coordinator
            .enqueue(request("key-1"))
            .expect("first enqueue")
    }; // coordinator dropped: workers joined, SQLite connection closed.

    // --- run 2, same SQLite file + same sidecar ------------------------
    let coordinator = coordinator(root);
    let recovered = coordinator.recover_on_startup().expect("recover");
    assert_eq!(
        recovered,
        vec![first_id.clone()],
        "recovery must rehydrate exactly the job the previous run persisted"
    );

    // On the old counter-based implementation this call reproposed
    // `job-0000000000000000` and failed with NotFound.
    let second_id = coordinator
        .enqueue(request("key-2"))
        .expect("enqueue after restart must succeed");

    assert_ne!(
        second_id, first_id,
        "a restarted process must not re-mint an id the previous run already persisted"
    );

    let mut ids = coordinator.job_ids();
    ids.sort();
    let mut expected = vec![first_id.clone(), second_id.clone()];
    expected.sort();
    assert_eq!(ids, expected, "both jobs are live after the restart");

    // Both ids really are distinct rows in the durable transfer authority.
    let store = TransferStore::open(root.join("transfer.sqlite3")).expect("reopen transfer store");
    for id in [&first_id, &second_id] {
        let row = store
            .get_job(id.as_str())
            .expect("query")
            .unwrap_or_else(|| panic!("{id} has no durable row"));
        assert_eq!(&row.job_id, id.as_str());
    }
    assert_eq!(store.count_jobs().expect("count durable rows"), 2);
}

#[test]
fn minted_job_ids_are_opaque_and_unique_within_one_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let coordinator = coordinator(dir.path());

    let ids: Vec<JobId> = (0..32)
        .map(|i| {
            coordinator
                .enqueue(request(&format!("key-{i}")))
                .expect("enqueue")
        })
        .collect();

    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "ids must be unique");

    for id in &ids {
        let raw = id.as_str().strip_prefix("job-").expect("job- prefix");
        // UUID v4, hyphenated: 8-4-4-4-12, version nibble 4.
        assert_eq!(raw.len(), 36, "{id} is not a hyphenated UUID");
        assert_eq!(raw.as_bytes()[14], b'4', "{id} is not a v4 UUID");
        // Opaque: carries no enqueue ordinal a caller could rely on.
        assert!(
            !raw.chars().all(|c| c == '0' || c.is_ascii_digit()),
            "{id} looks like a counter, not a random id"
        );
    }
}
