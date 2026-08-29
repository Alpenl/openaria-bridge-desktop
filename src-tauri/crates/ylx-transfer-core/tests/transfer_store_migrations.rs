//! Commit 22: the versioned job-spec + file-ledger schema.
//!
//! Every case below runs against a real SQLite file in a tempdir:
//!
//! - a fresh database migrates to the latest version and creates every new
//!   table;
//! - a database left at *each* older schema version resumes cleanly;
//! - a database recorded at a **future** version is not opened at all, and
//!   returns a diagnostic naming both versions;
//! - running migrations repeatedly is a no-op.

use rusqlite::Connection;
use ylx_transfer_core::persistence::{
    latest_schema_version, PersistenceError, TransferStore, TRANSFER_MIGRATIONS,
};

fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get::<_, i64>(0),
    )
    .expect("query sqlite_master")
        > 0
}

fn index_sql(conn: &Connection, index: &str) -> Option<String> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
        [index],
        |row| row.get(0),
    )
    .ok()
}

/// Hand-builds a database left exactly at `stop_at` — i.e. what an older
/// build of this app would have written — by applying the migration list
/// itself, the same way the runner does.
fn build_database_at_version(path: &std::path::Path, stop_at: u32) {
    let conn = Connection::open(path).expect("open raw");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .expect("bootstrap schema_migrations");
    for (version, sql) in TRANSFER_MIGRATIONS {
        if *version > stop_at {
            break;
        }
        conn.execute_batch(sql)
            .unwrap_or_else(|e| panic!("apply migration {version}: {e}"));
        conn.execute(
            "INSERT INTO schema_migrations (version) VALUES (?1)",
            [*version],
        )
        .unwrap_or_else(|e| panic!("record migration {version}: {e}"));
    }
}

// ---------------------------------------------------------------------
// fresh
// ---------------------------------------------------------------------

#[test]
fn a_fresh_database_migrates_to_the_latest_version_and_creates_every_transfer_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let store = TransferStore::open(&path).expect("open fresh");

    assert_eq!(
        store.schema_version().expect("version"),
        latest_schema_version()
    );

    let conn = Connection::open(&path).expect("raw open");
    for table in TransferStore::transfer_tables() {
        assert!(table_exists(&conn, table), "missing table {table}");
    }
}

#[test]
fn v21_adds_the_download_session_lookup_as_a_partial_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    build_database_at_version(&path, 20);

    let store = TransferStore::open(&path).expect("migrate v20 to latest");
    assert_eq!(store.schema_version().expect("version"), 21);
    drop(store);

    let conn = Connection::open(&path).expect("raw open");
    let sql = index_sql(&conn, "transfer_jobs_download_device_session_idx")
        .expect("v21 download-session index");
    let normalized = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized.contains("ON transfer_jobs (device_id, session_id, created_at, job_id)"),
        "unexpected index columns: {normalized}"
    );
    assert!(
        normalized.contains("WHERE operation_kind = 'download'"),
        "index must exclude the upload lane: {normalized}"
    );
}

#[test]
fn the_new_tables_have_the_columns_the_ledger_and_state_version_need() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open");

    let jobs = store.table_columns("transfer_jobs").expect("columns");
    for expected in [
        "job_id",
        "natural_key",
        "device_id",
        "session_id",
        "revision",
        "request_digest",
        "state",
        "state_version",
    ] {
        assert!(
            jobs.iter().any(|c| c == expected),
            "transfer_jobs is missing {expected}, has {jobs:?}"
        );
    }

    let files = store.table_columns("transfer_job_files").expect("columns");
    for expected in ["inventory_index", "request_index", "file_id", "sha256"] {
        assert!(files.iter().any(|c| c == expected), "files: {files:?}");
    }

    let ledger = store
        .table_columns("transfer_file_ledger")
        .expect("columns");
    for expected in ["status", "bytes_confirmed", "verified_sha256"] {
        assert!(ledger.iter().any(|c| c == expected), "ledger: {ledger:?}");
    }
}

#[test]
fn multipart_rows_from_pre_v18_retain_legacy_configured_style() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    build_database_at_version(&path, 17);
    let conn = Connection::open(&path).expect("raw open");
    conn.execute(
        r#"INSERT INTO transfer_uploads (
             object_key, upload_id, transfer_key, entry_key, revision, endpoint, bucket,
             desired_state, created_at, updated_at
           ) VALUES ('objects/pre-v18.bin', 'upload-pre-v18', 'transfer-pre-v18',
                     'device|session', 'rev-1', 'https://objects.example.test', 'captures',
                     'aborting', 't0', 't0')"#,
        [],
    )
    .expect("insert pre-v18 row");

    let store = TransferStore::open(&path).expect("migrate v17 to latest");
    let row = store
        .pending_upload("objects/pre-v18.bin", "upload-pre-v18")
        .expect("read migrated row")
        .expect("row exists");
    assert_eq!(
        row.upload.url_style,
        ylx_transfer_core::persistence::UploadUrlStyle::LegacyConfigured
    );
}

#[test]
fn v18_upload_specs_gain_an_explicit_unknown_object_prefix_at_v19() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    build_database_at_version(&path, 18);
    let conn = Connection::open(&path).expect("raw open");
    conn.execute(
        r#"INSERT INTO transfer_jobs (
             job_id, natural_key, device_id, session_id, revision, request_digest,
             state, state_version, error_code, error_retryable, desired_run_state,
             created_at, updated_at, operation_kind
           ) VALUES ('upload-v18', 'upload:v18', '__upload__', 'device|session', 'rev-v18', ?1,
                     'queued', 1, NULL, NULL, 'run', 't0', 't0', 'upload')"#,
        ["0000000000000000000000000000000000000000000000000000000000000000"],
    )
    .expect("insert v18 upload job");
    conn.execute(
        r#"INSERT INTO transfer_upload_job_specs (job_id, entry_key, revision, input_digest)
           VALUES ('upload-v18', 'device|session', 'rev-v18', 'legacy-input')"#,
        [],
    )
    .expect("insert v18 upload spec");
    drop(conn);

    let store = TransferStore::open(&path).expect("migrate v18 to v19");
    let columns = store
        .table_columns("transfer_upload_job_specs")
        .expect("spec columns");
    assert!(columns.iter().any(|column| column == "object_prefix"));
    assert_eq!(
        store
            .upload_job_spec("upload-v18")
            .expect("read migrated spec")
            .expect("spec exists")
            .object_prefix,
        None,
        "pre-v19 rows cannot authorize an exact destination namespace"
    );
}

#[test]
fn no_transfer_table_grows_a_secret_shaped_column() {
    // Same machine-checked claim `journal_spike::schema_has_no_secret_columns`
    // makes for the older tables, extended to the ones commit 22 adds.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open");

    let suspicious = [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "api_key",
        "apikey",
        "private_key",
    ];
    for table in TransferStore::transfer_tables() {
        for column in store.table_columns(table).expect("table_info") {
            let lower = column.to_lowercase();
            for bad in suspicious {
                assert!(
                    !lower.contains(bad),
                    "table {table} column {column:?} looks like it holds a secret ({bad:?})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------
// every older version
// ---------------------------------------------------------------------

#[test]
fn a_database_left_at_any_older_schema_version_resumes_cleanly() {
    for (stop_at, _) in TRANSFER_MIGRATIONS {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("transfer.sqlite3");
        build_database_at_version(&path, *stop_at);

        let store = TransferStore::open(&path)
            .unwrap_or_else(|e| panic!("resuming from version {stop_at} must succeed: {e}"));
        assert_eq!(
            store.schema_version().expect("version"),
            latest_schema_version(),
            "resuming from version {stop_at} must reach the latest version"
        );

        let conn = Connection::open(&path).expect("raw open");
        for table in TransferStore::transfer_tables() {
            assert!(
                table_exists(&conn, table),
                "table {table} missing after resuming from version {stop_at}"
            );
        }
    }
}

#[test]
fn a_database_at_version_zero_is_indistinguishable_from_a_fresh_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    build_database_at_version(&path, 0);
    let store = TransferStore::open(&path).expect("open");
    assert_eq!(
        store.schema_version().expect("version"),
        latest_schema_version()
    );
}

// ---------------------------------------------------------------------
// idempotence
// ---------------------------------------------------------------------

#[test]
fn running_migrations_repeatedly_is_a_no_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");

    let mut applied_rows = Vec::new();
    for _ in 0..3 {
        let store = TransferStore::open(&path).expect("open");
        assert_eq!(
            store.schema_version().expect("version"),
            latest_schema_version()
        );
        drop(store);
        let conn = Connection::open(&path).expect("raw open");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count migrations");
        applied_rows.push(count);
    }
    assert_eq!(
        applied_rows,
        vec![
            i64::from(latest_schema_version()),
            i64::from(latest_schema_version()),
            i64::from(latest_schema_version())
        ],
        "re-opening must not re-apply or duplicate migration rows"
    );
}

#[test]
fn data_written_before_a_reopen_survives_the_no_op_migration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    {
        let store = TransferStore::open(&path).expect("open");
        store
            .raw_execute(
                "INSERT INTO transfer_migration_markers (marker, applied_at, detail) \
                 VALUES ('probe', 't0', 'written before reopen')",
            )
            .expect("insert marker");
    }
    let store = TransferStore::open(&path).expect("reopen");
    let marker = store
        .migration_marker("probe")
        .expect("read")
        .expect("present");
    assert_eq!(marker.applied_at, "t0");
}

// ---------------------------------------------------------------------
// future version: refuse to open
// ---------------------------------------------------------------------

#[test]
fn a_database_from_a_newer_build_is_not_opened_and_returns_a_diagnostic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let future = latest_schema_version() + 7;
    {
        // A fully-migrated file, then a marker claiming a newer build wrote
        // it (exactly what a downgrade would leave behind).
        TransferStore::open(&path).expect("open fresh");
        let conn = Connection::open(&path).expect("raw open");
        conn.execute(
            "INSERT INTO schema_migrations (version) VALUES (?1)",
            [future],
        )
        .expect("record a future version");
    }

    let error = TransferStore::open(&path).expect_err("a newer file must not be opened");
    match error {
        PersistenceError::UnsupportedSchemaVersion {
            found, supported, ..
        } => {
            assert_eq!(found, future);
            assert_eq!(supported, latest_schema_version());
        }
        other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
    }
}

#[test]
fn refusing_a_future_database_does_not_modify_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    let future = latest_schema_version() + 1;
    {
        TransferStore::open(&path).expect("open fresh");
        let conn = Connection::open(&path).expect("raw open");
        conn.execute(
            "INSERT INTO schema_migrations (version) VALUES (?1)",
            [future],
        )
        .expect("record a future version");
        conn.execute(
            "INSERT INTO transfer_migration_markers (marker, applied_at, detail) \
             VALUES ('written-by-newer-build', 't9', 'must survive')",
            [],
        )
        .expect("seed a row only the newer build knows about");
    }

    TransferStore::open(&path).expect_err("must refuse");

    let conn = Connection::open(&path).expect("raw open");
    let max: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("read version");
    assert_eq!(
        max,
        i64::from(future),
        "the refused open must not downgrade"
    );
    let detail: String = conn
        .query_row(
            "SELECT detail FROM transfer_migration_markers WHERE marker = 'written-by-newer-build'",
            [],
            |row| row.get(0),
        )
        .expect("row survives");
    assert_eq!(detail, "must survive");
}

#[test]
fn v15_upload_jobs_are_backfilled_with_lossless_activity_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    build_database_at_version(&path, 15);
    {
        let conn = Connection::open(&path).expect("raw open");
        conn.execute(
            r#"INSERT INTO transfer_jobs (
                 job_id, natural_key, device_id, session_id, revision, request_digest,
                 state, state_version, error_code, error_retryable, desired_run_state,
                 created_at, updated_at, operation_kind
             ) VALUES ('upload-old', 'upload:old', '__upload__', 'device|session', 'rev-old', ?1,
                       'failed', 2, 'legacy-error', 1, 'run', 't0', 't1', 'upload')"#,
            ["0000000000000000000000000000000000000000000000000000000000000000"],
        )
        .expect("insert v15 upload job");
        conn.execute(
            r#"INSERT INTO transfer_upload_job_specs (job_id, entry_key, revision, input_digest)
             VALUES ('upload-old', 'device|session', 'rev-old', 'legacy-input')"#,
            [],
        )
        .expect("insert v15 upload spec");
        conn.execute(
            r#"INSERT INTO transfer_uploads (
                 object_key, upload_id, transfer_key, entry_key, revision, endpoint, bucket,
                 desired_state, created_at, updated_at, job_id
             ) VALUES ('device/session/a', 'multipart-old', 'transfer-old', 'device|session',
                       'rev-old', 'https://objects.example.test', 'bucket-old', 'aborting',
                       't0', 't2', 'upload-old')"#,
            [],
        )
        .expect("insert v15 multipart row");
        conn.execute(
            r#"INSERT INTO transfer_upload_parts (
                 object_key, upload_id, part_number, etag, size_bytes, recorded_at
             ) VALUES ('device/session/a', 'multipart-old', 1, 'etag-old', 999, 't2')"#,
            [],
        )
        .expect("insert v15 part");
    }

    let store = TransferStore::open(&path).expect("migrate v15");
    let activity = store
        .upload_activity("upload-old")
        .expect("activity read")
        .expect("activity row");
    assert_eq!(activity.label, "device|session");
    assert_eq!(activity.target_label, "bucket-old");
    assert_eq!(activity.total_bytes, 0);
    assert_eq!(activity.confirmed_bytes, 0);
    assert!(activity.job.dismissed_at.is_none());

    drop(store);
    let reopened = TransferStore::open(&path).expect("reopen migrated store");
    assert_eq!(
        reopened
            .upload_activity("upload-old")
            .expect("reopened activity")
            .expect("activity")
            .confirmed_bytes,
        0
    );
}
