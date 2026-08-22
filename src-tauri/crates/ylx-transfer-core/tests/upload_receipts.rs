//! Durable verified-object receipt staging (v17).

use ylx_transfer_core::persistence::{
    TerminalOutcome, TransferStore, UploadJobSpec, UploadReceiptDigestProof, UploadReceiptError,
    UploadReceiptRole, UploadReceiptSeed,
};

fn open(path: &std::path::Path) -> TransferStore {
    TransferStore::open(path).expect("open transfer store")
}

fn spec(revision: &str) -> UploadJobSpec {
    UploadJobSpec::new("device-1|session-1", revision, "bundle-digest").expect("valid upload spec")
}

fn receipt(key: &str, role: UploadReceiptRole, etag: &str, seed: u8) -> UploadReceiptSeed {
    UploadReceiptSeed::new(
        key,
        role,
        etag,
        Some(format!("version-{seed}")),
        u64::from(seed),
        format!("{seed:02x}").repeat(32),
        UploadReceiptDigestProof::StreamedReadback,
    )
}

#[test]
fn v17_receipt_table_is_part_of_the_transfer_schema_and_upload_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("transfer.sqlite3"));

    assert!(TransferStore::transfer_tables().contains(&"transfer_upload_receipts"));
    assert!(TransferStore::upload_tables().contains(&"transfer_upload_receipts"));
    for expected in [
        "job_id",
        "entry_key",
        "revision",
        "object_key",
        "object_role",
        "etag",
        "version_id",
        "size_bytes",
        "source_sha256",
        "digest_proof",
        "staged_at",
    ] {
        assert!(
            store
                .table_columns("transfer_upload_receipts")
                .unwrap()
                .iter()
                .any(|column| column == expected),
            "receipt table is missing {expected}"
        );
    }
}

#[test]
fn receipt_batch_is_bound_to_job_context_and_round_trips_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_upload_job("upload-1", &spec("rev-1"), "t0")
        .unwrap();

    let staged = store
        .stage_upload_receipts(
            "upload-1",
            "device-1|session-1",
            "rev-1",
            &[
                receipt(
                    "objects/file.bin",
                    UploadReceiptRole::Data,
                    "etag-file",
                    0x11,
                ),
                receipt(
                    "objects/manifest.json",
                    UploadReceiptRole::Evidence,
                    "etag-manifest",
                    0x22,
                ),
            ],
            "t1",
        )
        .unwrap();
    assert_eq!(staged.len(), 2);
    assert_eq!(staged[0].job_id, "upload-1");
    assert_eq!(staged[0].entry_key, "device-1|session-1");
    assert_eq!(staged[0].revision, "rev-1");
    assert_eq!(staged[0].role, UploadReceiptRole::Data);
    assert_eq!(staged[1].role, UploadReceiptRole::Evidence);
    assert_eq!(staged[0].staged_at, "t1");

    drop(store);
    let reopened = open(&path);
    assert_eq!(reopened.list_upload_receipts("upload-1").unwrap(), staged);
}

#[test]
fn receipt_batch_replay_is_idempotent_but_any_changed_evidence_rolls_back_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job("upload-1", &spec("rev-1"), "t0")
        .unwrap();
    let first = receipt(
        "objects/file.bin",
        UploadReceiptRole::Data,
        "etag-file",
        0x11,
    );
    let second = receipt(
        "objects/manifest.json",
        UploadReceiptRole::Evidence,
        "etag-manifest",
        0x22,
    );
    let initial = store
        .stage_upload_receipts_for_job("upload-1", &[first.clone(), second.clone()], "t1")
        .unwrap();
    let replay = store
        .stage_upload_receipts_for_job("upload-1", &[first.clone(), second.clone()], "t2")
        .unwrap();
    assert_eq!(replay, initial, "a retry must not rewrite staged_at");

    let mut changed_role = first.clone();
    changed_role.role = UploadReceiptRole::Evidence;
    let role_error = store
        .stage_upload_receipts_for_job("upload-1", &[changed_role], "t2-role")
        .unwrap_err();
    assert!(matches!(role_error, UploadReceiptError::Conflict { .. }));

    let mut changed = first;
    changed.etag = "different-etag".to_string();
    let error = store
        .stage_upload_receipts_for_job(
            "upload-1",
            &[
                changed,
                receipt("objects/new.bin", UploadReceiptRole::Data, "etag-new", 0x33),
            ],
            "t3",
        )
        .unwrap_err();
    assert!(matches!(error, UploadReceiptError::Conflict { .. }));
    assert!(store
        .upload_receipt("upload-1", "objects/new.bin")
        .unwrap()
        .is_none());
    assert_eq!(store.list_upload_receipts("upload-1").unwrap(), initial);
}

#[test]
fn receipt_context_and_input_validation_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job("upload-1", &spec("rev-1"), "t0")
        .unwrap();
    let context = store
        .stage_upload_receipts(
            "upload-1",
            "device-1|session-1",
            "rev-other",
            &[receipt(
                "objects/file.bin",
                UploadReceiptRole::Data,
                "etag",
                0x11,
            )],
            "t1",
        )
        .unwrap_err();
    assert!(matches!(
        context,
        UploadReceiptError::JobContextMismatch { .. }
    ));

    let mut malformed = receipt("objects/bad.bin", UploadReceiptRole::Data, "etag", 0x11);
    malformed.source_sha256 = "not-a-sha".to_string();
    let invalid = store
        .stage_upload_receipts_for_job("upload-1", &[malformed], "t2")
        .unwrap_err();
    assert!(matches!(invalid, UploadReceiptError::Invalid(_)));
    assert!(store.list_upload_receipts("upload-1").unwrap().is_empty());
}

#[test]
fn receipts_survive_multipart_retirement_and_dismissal() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job("upload-1", &spec("rev-1"), "t0")
        .unwrap();
    let version = store.start_upload_job("upload-1", 1, "t1").unwrap();
    let upload = ylx_transfer_core::persistence::NewUpload {
        transfer_key: "transfer-1".to_string(),
        entry_key: "device-1|session-1".to_string(),
        revision: "rev-1".to_string(),
        object_key: "objects/file.bin".to_string(),
        upload_id: "multipart-1".to_string(),
        endpoint: "https://objects.example.test".to_string(),
        bucket: "captures".to_string(),
        url_style: ylx_transfer_core::persistence::UploadUrlStyle::VirtualHost,
    };
    store
        .begin_upload_for_job("upload-1", version, &upload, "t2")
        .unwrap();
    store
        .stage_upload_receipts_for_job(
            "upload-1",
            &[receipt(
                "objects/file.bin",
                UploadReceiptRole::Data,
                "etag",
                0x11,
            )],
            "t3",
        )
        .unwrap();
    assert!(store
        .finish_upload(&upload.object_key, &upload.upload_id)
        .unwrap());
    assert_eq!(store.list_upload_receipts("upload-1").unwrap().len(), 1);

    store
        .complete_upload_job("upload-1", version, &TerminalOutcome::Succeeded, "t4")
        .unwrap();
    store.acknowledge_completion("upload-1", "t5").unwrap();
    assert!(store.dismiss_job("upload-1", "t6").is_ok());
    assert_eq!(store.list_upload_receipts("upload-1").unwrap().len(), 1);
    assert!(!store
        .dismiss_job("upload-1", "t7")
        .expect("repeat dismissal is a no-op"));
}
