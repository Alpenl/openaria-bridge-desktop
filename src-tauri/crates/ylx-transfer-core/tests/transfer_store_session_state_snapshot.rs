#[allow(dead_code)]
mod transfer_store_support;

use rusqlite::Connection;
use transfer_store_support::full_session_spec;
use ylx_transfer_core::persistence::transfer_store::{
    CompletionDeliveryState, DownloadSessionJobState,
};
use ylx_transfer_core::persistence::{PersistenceError, TerminalOutcome, TransferStore};

fn create_job(
    store: &mut TransferStore,
    job_id: &str,
    device_id: &str,
    session_id: &str,
    revision: &str,
    created_at: &str,
) {
    let spec = full_session_spec(
        device_id,
        session_id,
        revision,
        &[("artifact-0001", 1, 0x11)],
    );
    store
        .create_job(job_id, &spec, created_at)
        .expect("create fixture job");
}

fn projected(
    states: &[DownloadSessionJobState],
) -> Vec<(&str, &str, &str, CompletionDeliveryState)> {
    states
        .iter()
        .map(|state| {
            (
                state.job.identity.device_id().as_str(),
                state.job.identity.session_id().as_str(),
                state.job.job_id.as_str(),
                state.completion,
            )
        })
        .collect()
}

#[test]
fn snapshot_returns_only_requested_devices_and_sessions_in_deterministic_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store =
        TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open transfer store");

    create_job(
        &mut store,
        "job-b-s2-missing",
        "pi-b",
        "session-2",
        "rev-1",
        "t3",
    );
    create_job(
        &mut store,
        "job-a-s2-pending",
        "pi-a",
        "session-2",
        "rev-1",
        "t2",
    );
    store
        .complete_job("job-a-s2-pending", &TerminalOutcome::Succeeded, "t4")
        .expect("record pending completion");
    create_job(
        &mut store,
        "job-a-s1-z-acknowledged",
        "pi-a",
        "session-1",
        "rev-2",
        "t1",
    );
    store
        .complete_job("job-a-s1-z-acknowledged", &TerminalOutcome::Succeeded, "t4")
        .expect("record acknowledged completion");
    store
        .acknowledge_completion("job-a-s1-z-acknowledged", "t5")
        .expect("acknowledge completion");
    create_job(
        &mut store,
        "job-a-s1-a-missing",
        "pi-a",
        "session-1",
        "rev-1",
        "t1",
    );

    create_job(
        &mut store,
        "job-upload-excluded",
        "pi-0",
        "session-0",
        "rev-1",
        "t0",
    );
    store
        .raw_execute(
            "UPDATE transfer_jobs SET operation_kind = 'upload' \
             WHERE job_id = 'job-upload-excluded'",
        )
        .expect("retag upload fixture");

    let states = store
        .list_download_session_job_states_for_sessions(
            &["pi-a".to_string()],
            &["session-1".to_string()],
        )
        .expect("read snapshot");
    assert_eq!(
        projected(&states),
        vec![
            (
                "pi-a",
                "session-1",
                "job-a-s1-a-missing",
                CompletionDeliveryState::Missing,
            ),
            (
                "pi-a",
                "session-1",
                "job-a-s1-z-acknowledged",
                CompletionDeliveryState::Acknowledged,
            ),
        ]
    );
}

#[test]
fn snapshot_rejects_a_completion_from_the_wrong_operation_lane() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store =
        TransferStore::open(dir.path().join("transfer.sqlite3")).expect("open transfer store");
    create_job(&mut store, "job-a", "pi-a", "session-a", "rev-1", "t0");
    store
        .complete_job("job-a", &TerminalOutcome::Succeeded, "t1")
        .expect("complete");
    store
        .raw_execute(
            "UPDATE transfer_completion_outbox SET operation_kind = 'upload' \
             WHERE job_id = 'job-a'",
        )
        .expect("corrupt operation lane");

    let error = store
        .list_download_session_job_states_for_sessions(
            &["pi-a".to_string()],
            &["session-a".to_string()],
        )
        .expect_err("lane mismatch must not be hidden");
    assert!(
        matches!(error, PersistenceError::Corrupt { .. }),
        "unexpected error: {error}"
    );
}

fn seed_scale_fixture(path: &std::path::Path, job_count: usize) {
    let mut conn = Connection::open(path).expect("open raw fixture connection");
    conn.pragma_update(None, "foreign_keys", "ON")
        .expect("enable foreign keys");
    let tx = conn.transaction().expect("begin fixture transaction");
    {
        let mut insert_job = tx
            .prepare(
                "INSERT INTO transfer_jobs (
                    job_id, natural_key, device_id, session_id, revision,
                    request_digest, state, state_version, error_code,
                    error_retryable, created_at, updated_at, desired_run_state,
                    operation_kind
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL,
                    ?9, ?9, 'run', 'download'
                 )",
            )
            .expect("prepare job insert");
        let mut insert_completion = tx
            .prepare(
                "INSERT INTO transfer_completion_outbox (
                    job_id, outcome, error_code, error_retryable,
                    state_version, recorded_at, acknowledged_at, operation_kind
                 ) VALUES (?1, 'succeeded', NULL, NULL, 2, 'completed', ?2, 'download')",
            )
            .expect("prepare completion insert");
        let request_digest = "0".repeat(64);

        for index in 0..job_count {
            let job_id = format!("job-{index:04}");
            let natural_key = format!("natural-{index:04}");
            let device_id = format!("pi-{:02}", (index * 7) % 11);
            let session_id = format!("session-{:04}", job_count - index);
            let revision = format!("rev-{index:04}");
            let created_at = format!("t-{:04}", index % 37);
            let has_completion = index % 3 != 0;
            let state = if has_completion {
                "succeeded"
            } else {
                "queued"
            };
            let state_version = if has_completion { 2_i64 } else { 1_i64 };
            insert_job
                .execute(rusqlite::params![
                    job_id,
                    natural_key,
                    device_id,
                    session_id,
                    revision,
                    request_digest,
                    state,
                    state_version,
                    created_at,
                ])
                .expect("insert fixture job");
            if has_completion {
                let acknowledged_at = (index % 3 == 2).then_some("acknowledged");
                insert_completion
                    .execute(rusqlite::params![job_id, acknowledged_at])
                    .expect("insert fixture completion");
            }
        }
    }
    tx.commit().expect("commit fixture");
}

#[test]
fn snapshot_result_is_independent_of_ten_thousand_unrelated_jobs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    drop(TransferStore::open(&path).expect("create schema"));
    seed_scale_fixture(&path, 10_000);

    let mut store = TransferStore::open(&path).expect("reopen fixture");
    create_job(
        &mut store,
        "job-visible",
        "pi-visible",
        "session-visible",
        "rev-visible",
        "visible-created-at",
    );
    let states = store
        .list_download_session_job_states_for_sessions(
            &["pi-visible".to_string()],
            &["session-visible".to_string()],
        )
        .expect("read scoped snapshot");

    assert_eq!(
        projected(&states),
        vec![(
            "pi-visible",
            "session-visible",
            "job-visible",
            CompletionDeliveryState::Missing,
        )]
    );
}

#[test]
fn snapshot_accepts_more_than_sqlites_positional_bind_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("transfer.sqlite3");
    drop(TransferStore::open(&path).expect("create schema"));
    seed_scale_fixture(&path, 1_200);

    let store = TransferStore::open(&path).expect("reopen fixture");
    let device_ids = (0..11)
        .map(|index| format!("pi-{index:02}"))
        .collect::<Vec<_>>();
    let session_ids = (1..=1_200)
        .map(|index| format!("session-{index:04}"))
        .collect::<Vec<_>>();
    let states = store
        .list_download_session_job_states_for_sessions(&device_ids, &session_ids)
        .expect("JSON set parameters avoid SQLite's positional bind limit");

    assert_eq!(states.len(), 1_200);
    let keys = states
        .iter()
        .map(|state| {
            (
                state.job.identity.device_id().as_str(),
                state.job.identity.session_id().as_str(),
                state.job.created_at.as_str(),
                state.job.job_id.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert!(keys.windows(2).all(|window| window[0] <= window[1]));
}
