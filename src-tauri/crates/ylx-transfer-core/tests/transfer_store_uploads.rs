//! Commit 35/36: durable pending-upload context and legacy sidecar import.
//!
//! These tests exercise the public TransferStore seam rather than the SQL
//! implementation: a multipart handle is durable before any part is sent,
//! part evidence is immutable, startup claims orphaned work, and importing
//! the old JSON sidecar is one-shot and never rewrites the source file.

use std::fs;

use rusqlite::Connection;
use serde_json::json;
use ylx_transfer_core::persistence::{
    LegacyUploadImportOutcome, NewUpload, TransferStore, UploadDesiredState, UploadPartRecord,
    UploadStoreError, UploadUrlStyle, LEGACY_PENDING_UPLOAD_MARKER,
};

fn open(path: &std::path::Path) -> TransferStore {
    TransferStore::open(path).expect("open transfer store")
}

fn upload() -> NewUpload {
    NewUpload {
        transfer_key: "transfer-1".to_string(),
        entry_key: "device-1|session-1".to_string(),
        revision: "rev-1".to_string(),
        object_key: "device-1/session-1/capture.bin".to_string(),
        upload_id: "upload-1".to_string(),
        endpoint: "https://objects.example.test".to_string(),
        bucket: "captures".to_string(),
        url_style: UploadUrlStyle::VirtualHost,
    }
}

#[test]
fn begin_is_durable_and_idempotent_but_a_different_handle_owner_conflicts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let first = store.begin_upload(&upload(), "t0").unwrap();
    assert_eq!(first.desired_state, UploadDesiredState::Running);
    assert!(first.parts.is_empty());

    let repeated = store.begin_upload(&upload(), "t1").unwrap();
    assert_eq!(
        repeated, first,
        "retrying begin must not reset timestamps/state"
    );

    let mut different = upload();
    different.transfer_key = "transfer-other".to_string();
    let error = store.begin_upload(&different, "t2").unwrap_err();
    assert!(matches!(error, UploadStoreError::Conflict { .. }));

    drop(store);
    let reopened = open(&path);
    assert_eq!(
        reopened
            .pending_upload(&upload().object_key, &upload().upload_id)
            .unwrap(),
        Some(first)
    );
}

#[test]
fn multipart_url_style_survives_restart_and_is_part_of_handle_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut path_style = upload();
    path_style.url_style = UploadUrlStyle::Path;
    {
        let mut store = open(&path);
        let stored = store.begin_upload(&path_style, "t0").unwrap();
        assert_eq!(stored.upload.url_style, UploadUrlStyle::Path);
    }

    let mut reopened = open(&path);
    let recovered = reopened
        .pending_upload(&path_style.object_key, &path_style.upload_id)
        .unwrap()
        .expect("multipart row survives restart");
    assert_eq!(recovered.upload.url_style, UploadUrlStyle::Path);

    let mut wrong_style = path_style.clone();
    wrong_style.url_style = UploadUrlStyle::VirtualHost;
    assert!(matches!(
        reopened.begin_upload(&wrong_style, "t1"),
        Err(UploadStoreError::Conflict { detail, .. }) if detail.contains("url style")
    ));
}

#[test]
fn legacy_configured_style_round_trips_without_being_confused_with_virtual_host() {
    assert_eq!(
        UploadUrlStyle::from_db_str("legacy_configured"),
        Some(UploadUrlStyle::LegacyConfigured)
    );
    assert_ne!(
        UploadUrlStyle::LegacyConfigured,
        UploadUrlStyle::VirtualHost
    );
}

#[test]
fn part_evidence_is_write_once_and_orphan_claim_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let item = upload();
    store.begin_upload(&item, "t0").unwrap();
    let part = UploadPartRecord {
        part_number: 1,
        etag: "etag-a".to_string(),
        size_bytes: 10,
    };
    store
        .record_upload_part(&item.object_key, &item.upload_id, &part, "t1")
        .unwrap();
    store
        .record_upload_part(&item.object_key, &item.upload_id, &part, "t2")
        .unwrap();
    let mut changed = part.clone();
    changed.etag = "etag-b".to_string();
    assert!(matches!(
        store.record_upload_part(&item.object_key, &item.upload_id, &changed, "t3"),
        Err(UploadStoreError::PartConflict { .. })
    ));

    let claimed = store.claim_orphan_uploads("t4").unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].desired_state, UploadDesiredState::Aborting);
    assert_eq!(claimed[0].confirmed_bytes(), 10);
    assert!(
        store
            .pending_upload(&item.object_key, &item.upload_id)
            .unwrap()
            .unwrap()
            .desired_state
            == UploadDesiredState::Aborting
    );
    assert!(store
        .finish_upload(&item.object_key, &item.upload_id)
        .unwrap());
    assert!(store
        .pending_upload(&item.object_key, &item.upload_id)
        .unwrap()
        .is_none());
}

#[test]
fn legacy_sidecar_import_is_one_shot_and_preserves_source_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let sidecar = dir.path().join("pending-uploads.json");
    let bytes = serde_json::to_vec(&json!({
        "version": 1,
        "uploads": [{
            "transferKey": "transfer-legacy",
            "entryKey": "device-legacy|session-legacy",
            "objectKey": "device-legacy/session-legacy/capture.bin",
            "uploadId": "upload-legacy",
            "endpoint": "https://objects.example.test",
            "bucket": "captures"
        }]
    }))
    .unwrap();
    fs::write(&sidecar, &bytes).unwrap();

    let mut store = open(&path);
    let outcome = store.import_legacy_pending_uploads(&sidecar, "t0").unwrap();
    assert!(matches!(outcome, LegacyUploadImportOutcome::Imported(_)));
    assert_eq!(fs::read(&sidecar).unwrap(), bytes);
    let imported = store.list_pending_uploads().unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].desired_state, UploadDesiredState::Aborting);
    assert_eq!(
        imported[0].upload.url_style,
        UploadUrlStyle::LegacyConfigured,
        "legacy rows must preserve the unknown-style sentinel"
    );

    let repeat = store.import_legacy_pending_uploads(&sidecar, "t1").unwrap();
    assert!(matches!(
        repeat,
        LegacyUploadImportOutcome::AlreadyImported(_)
    ));
    let marker = store
        .migration_marker(LEGACY_PENDING_UPLOAD_MARKER)
        .unwrap()
        .expect("import marker");
    assert!(marker.detail.contains("imported 1"));
}

#[test]
fn corrupt_legacy_sidecar_is_not_treated_as_empty_state() {
    let dir = tempfile::tempdir().unwrap();
    let sidecar = dir.path().join("pending-uploads.json");
    fs::write(&sidecar, b"not-json").unwrap();
    let original = fs::read(&sidecar).unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    assert!(store.import_legacy_pending_uploads(&sidecar, "t0").is_err());
    assert_eq!(fs::read(&sidecar).unwrap(), original);
    assert!(store.list_pending_uploads().unwrap().is_empty());
}

#[test]
fn upload_schema_has_no_credential_columns() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("transfer.sqlite3"));
    let conn = Connection::open(dir.path().join("transfer.sqlite3")).unwrap();
    for table in TransferStore::upload_tables() {
        assert!(
            TransferStore::transfer_tables().contains(table),
            "upload table {table} must be part of the TransferStore inventory"
        );
    }
    for table in TransferStore::upload_tables() {
        let mut statement = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for column in columns {
            let lower = column.to_ascii_lowercase();
            assert!(!lower.contains("secret"));
            assert!(!lower.contains("password"));
            assert!(!lower.contains("credential"));
        }
    }
    drop(store);
}
