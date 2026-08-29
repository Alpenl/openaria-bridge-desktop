use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ylx_transfer_core::device::{CaptureActivityState, ConnectionState};
use ylx_transfer_core::domain::{
    DeviceId, FileId, JobFileSpec, JobIdentity, JobSpec, PublicationMaterial, SessionId,
};
use ylx_transfer_core::library::download::{
    derive_target_path_for_file, journal_path, part_path, DownloadError, DownloadJournal,
    DownloadSource, PublicationVerifier, RequestedRange, SourceResponse, VerifyError,
};
use ylx_transfer_core::library::staging::{RevisionState, SessionStaging};
use ylx_transfer_core::persistence::{
    FileLedgerStatus, JobStateTag, TerminalOutcome, TransferStore,
};
use ylx_transfer_core::transfer::coordinator::{
    CoordinatorConfig, DeviceStatusPort, DownloadSourceFactory, TransferCoordinator,
};
use ylx_transfer_core::transfer::recovery::INTERRUPTED_DOWNLOAD_FAILURE_CODE;
use ylx_transfer_core::transfer::{FailureCode, JobId, TransferJobState};

struct SwitchableDevice {
    online: Arc<AtomicBool>,
}

impl DeviceStatusPort for SwitchableDevice {
    fn connection_state(&self, _device_id: &DeviceId) -> ConnectionState {
        if self.online.load(Ordering::SeqCst) {
            ConnectionState::Connected {
                connection_id: "startup-policy-test".to_string(),
                epoch: 1,
            }
        } else {
            ConnectionState::Disconnected
        }
    }

    fn capture_activity(&self, _device_id: &DeviceId) -> CaptureActivityState {
        CaptureActivityState::Idle
    }
}

struct CountingFactory {
    opens: Arc<AtomicUsize>,
    requested_starts: Arc<Mutex<Vec<u64>>>,
}

impl DownloadSourceFactory for CountingFactory {
    fn make_source(
        &self,
        _device_id: &DeviceId,
        _session_id: &SessionId,
        _file_id: &FileId,
    ) -> Result<Box<dyn DownloadSource>, DownloadError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(RecordingSource {
            requested_starts: Arc::clone(&self.requested_starts),
        }))
    }
}

struct RecordingSource {
    requested_starts: Arc<Mutex<Vec<u64>>>,
}

impl DownloadSource for RecordingSource {
    fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
        self.requested_starts.lock().unwrap().push(request.start);
        Err(DownloadError::Source(
            "range was recorded; no response body is needed".to_string(),
        ))
    }
}

struct PassVerifier;

impl PublicationVerifier for PassVerifier {
    fn verify(&self, _manifest: &[u8], _signature: &[u8], _key: &[u8]) -> Result<(), VerifyError> {
        Ok(())
    }
}

fn interrupted_spec() -> JobSpec {
    let file_id = FileId("left-00000".to_string());
    JobSpec::new(
        JobIdentity::new(
            DeviceId("device-startup".to_string()),
            SessionId("session-startup".to_string()),
            "revision-startup",
        )
        .expect("valid identity"),
        PublicationMaterial::new(
            "revision-startup",
            vec![1, 2, 3, 4],
            vec![7; 64],
            vec![9; 32],
        )
        .expect("valid publication"),
        vec![
            JobFileSpec::new(file_id.clone(), "video/left_00000.mp4", 4, "ab".repeat(32))
                .expect("valid file"),
        ],
        &[file_id],
        true,
        "2026-08-29",
    )
    .expect("valid job spec")
}

fn coordinator(
    root: &Path,
    store: Arc<Mutex<TransferStore>>,
    online: Arc<AtomicBool>,
    opens: Arc<AtomicUsize>,
    requested_starts: Arc<Mutex<Vec<u64>>>,
) -> TransferCoordinator {
    TransferCoordinator::new(
        store,
        Arc::new(SwitchableDevice { online }),
        Arc::new(CountingFactory {
            opens,
            requested_starts,
        }),
        Arc::new(PassVerifier),
        CoordinatorConfig {
            num_workers: 1,
            dispatch_interval: Duration::from_millis(5),
            checkpoint_threshold_bytes: 16,
            library_root: root.join("library"),
        },
    )
}

#[test]
fn startup_interruption_retry_discards_partial_and_starts_from_byte_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let library_root = dir.path().join("library");
    let store = Arc::new(Mutex::new(
        TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open transfer store"),
    ));
    let spec = interrupted_spec();
    store
        .lock()
        .unwrap()
        .create_job("job-interrupted", &spec, "t0")
        .expect("seed previous-process job");
    let file_id = FileId("left-00000".to_string());
    store
        .lock()
        .unwrap()
        .update_file_ledger(
            "job-interrupted",
            &file_id,
            FileLedgerStatus::Partial,
            2,
            None,
            "t0-partial",
        )
        .expect("seed durable partial ledger");

    let staging = SessionStaging::for_publication(
        &library_root,
        spec.identity().device_id().as_str(),
        spec.identity().session_id().as_str(),
        spec.publication().payload(),
    )
    .expect("derive interrupted staging");
    staging.prepare().expect("prepare interrupted staging");
    let target = derive_target_path_for_file(
        &staging.file_root(),
        spec.identity().device_id().as_str(),
        spec.identity().session_id().as_str(),
        file_id.as_str(),
        Some("video/left_00000.mp4"),
    )
    .expect("derive staged target");
    fs::create_dir_all(target.parent().expect("target parent")).expect("create target parent");
    let partial = part_path(&target);
    fs::write(&partial, b"ab").expect("write interrupted partial bytes");
    DownloadJournal::advance(
        &journal_path(&target),
        &partial,
        &DownloadJournal {
            confirmed_offset: 2,
            expected_size: 4,
            expected_sha256_hex: "ab".repeat(32),
            etag: Some("old-etag".to_string()),
        },
    )
    .expect("write interrupted journal");
    assert_eq!(staging.state(), RevisionState::Staged);

    let online = Arc::new(AtomicBool::new(true));
    let opens = Arc::new(AtomicUsize::new(0));
    let requested_starts = Arc::new(Mutex::new(Vec::new()));
    let coordinator = coordinator(
        dir.path(),
        Arc::clone(&store),
        Arc::clone(&online),
        Arc::clone(&opens),
        Arc::clone(&requested_starts),
    );
    let settled = coordinator
        .fail_interrupted_jobs_on_startup()
        .expect("fail interrupted startup jobs");
    let job_id = JobId("job-interrupted".to_string());
    assert_eq!(settled, vec![job_id.clone()]);
    assert_eq!(
        coordinator.job_state(&job_id),
        Some(TransferJobState::Failed {
            code: FailureCode::Other(
                INTERRUPTED_DOWNLOAD_FAILURE_CODE
                    .strip_prefix("other:")
                    .unwrap()
                    .to_string()
            ),
            retryable: true,
        })
    );
    assert_eq!(staging.state(), RevisionState::Absent);
    assert!(!partial.exists(), "startup must discard old partial bytes");
    assert!(
        !journal_path(&target).exists(),
        "startup must discard the old resume journal"
    );

    coordinator.tick();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        opens.load(Ordering::SeqCst),
        0,
        "startup settlement must not open a source even while the device is online"
    );
    let durable = store
        .lock()
        .unwrap()
        .get_job(job_id.as_str())
        .expect("read job")
        .expect("durable job remains");
    assert_eq!(durable.state, JobStateTag::Failed);
    assert_eq!(
        durable.error,
        Some((INTERRUPTED_DOWNLOAD_FAILURE_CODE.to_string(), true))
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .completion(job_id.as_str())
            .expect("read completion")
            .expect("terminal outcome is observable")
            .outcome,
        TerminalOutcome::Failed {
            code: INTERRUPTED_DOWNLOAD_FAILURE_CODE.to_string(),
            retryable: true,
        }
    );

    online.store(false, Ordering::SeqCst);
    store
        .lock()
        .unwrap()
        .acknowledge_completion(job_id.as_str(), "t1")
        .expect("acknowledge projected startup failure");
    let child = coordinator
        .retry(&job_id)
        .expect("an explicit retry remains available in this process");
    assert_ne!(child, job_id);
    let child_ledger = store
        .lock()
        .unwrap()
        .file_ledger(child.as_str())
        .expect("read fresh retry ledger");
    assert_eq!(child_ledger.len(), 1);
    assert_eq!(child_ledger[0].status, FileLedgerStatus::Missing);
    assert_eq!(child_ledger[0].bytes_confirmed, 0);
    assert_eq!(child_ledger[0].verified_sha256, None);

    online.store(true, Ordering::SeqCst);
    coordinator.tick();
    let deadline = Instant::now() + Duration::from_secs(1);
    while requested_starts.lock().unwrap().is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        opens.load(Ordering::SeqCst) > 0,
        "only the explicit retry should schedule a new source request"
    );
    assert_eq!(
        requested_starts.lock().unwrap().first().copied(),
        Some(0),
        "an explicit post-startup retry is a new download, not a Range resume"
    );
}
