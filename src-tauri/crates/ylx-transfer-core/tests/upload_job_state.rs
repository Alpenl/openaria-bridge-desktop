//! Durable tagged upload-job contract (issue #1 C68).
//!
//! These tests intentionally exercise the public core seam. They prove that
//! upload identity and multipart evidence are durable independently of the
//! application composition, and that all terminal writers converge through
//! expected-version CAS plus the shared completion outbox.

use ylx_transfer_core::persistence::{
    CompleteJobOutcome, DismissJobError, OperationKind, RetryJobOutcome, TerminalOutcome,
    TransferStore, UploadActivitySeed, UploadJobCreateAbort, UploadJobCreateError, UploadJobError,
    UploadJobSpec, UploadPartRecord, UploadReceiptDigestProof, UploadReceiptRole,
    UploadReceiptSeed, UploadStoreError,
};

fn open(path: &std::path::Path) -> TransferStore {
    TransferStore::open(path).expect("open transfer store")
}

fn spec(revision: &str, input: &str) -> UploadJobSpec {
    UploadJobSpec::new("device-1|session-1", revision, input).expect("valid upload spec")
}

fn spec_with_prefix(revision: &str, input: &str, prefix: &str) -> UploadJobSpec {
    UploadJobSpec::new_with_prefix("device-1|session-1", revision, input, prefix)
        .expect("valid prefixed upload spec")
}

fn failed() -> TerminalOutcome {
    TerminalOutcome::Failed {
        code: "object_store_rejected".to_string(),
        retryable: true,
    }
}

#[test]
fn upload_spec_prefix_is_normalized_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let prefixed = spec_with_prefix("rev-prefix", "bundle-prefix", "/captures/");
    assert_eq!(prefixed.object_prefix.as_deref(), Some("captures"));
    store
        .create_upload_job("upload-prefix", &prefixed, "t0")
        .unwrap();
    drop(store);

    let reopened = open(&path);
    assert_eq!(
        reopened
            .upload_job_spec("upload-prefix")
            .unwrap()
            .unwrap()
            .object_prefix
            .as_deref(),
        Some("captures")
    );
}

#[test]
fn upload_spec_can_prove_the_root_namespace_without_a_prefix() {
    let spec = spec_with_prefix("rev-root-prefix", "bundle-root-prefix", "///");
    assert_eq!(spec.object_prefix.as_deref(), Some(""));
}

#[test]
fn upload_spec_rejects_an_un_normalized_prefix_when_constructed_directly() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let mut invalid = spec("rev-prefix-invalid", "bundle-prefix-invalid");
    invalid.object_prefix = Some("/captures/".to_string());
    let error = store
        .create_upload_job("upload-prefix-invalid", &invalid, "t0")
        .unwrap_err();
    assert!(matches!(
        error,
        UploadJobCreateError::Invalid(detail) if detail.contains("object_prefix")
    ));
}

#[test]
fn failed_retry_copies_the_parent_object_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let parent_spec = spec_with_prefix("rev-retry-prefix", "bundle-retry-prefix", "captures/v1");
    store
        .create_upload_job("upload-prefix-parent", &parent_spec, "t0")
        .unwrap();
    let version = store
        .start_upload_job("upload-prefix-parent", 1, "t1")
        .unwrap();
    store
        .complete_upload_job("upload-prefix-parent", version, &failed(), "t2")
        .unwrap();
    store
        .acknowledge_completion("upload-prefix-parent", "t3")
        .unwrap();

    let child = store
        .retry_upload_job("upload-prefix-parent", "upload-prefix-child", "t4")
        .unwrap();
    assert!(child.was_created());
    assert_eq!(
        store
            .upload_job_spec("upload-prefix-child")
            .unwrap()
            .unwrap()
            .object_prefix
            .as_deref(),
        Some("captures/v1")
    );
}

#[test]
fn successful_repeat_persists_a_changed_object_prefix_and_fences_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let parent_spec = spec_with_prefix("rev-repeat-prefix", "bundle-parent", "captures/old");
    store
        .create_upload_job("upload-repeat-prefix-parent", &parent_spec, "t0")
        .unwrap();
    let version = store
        .start_upload_job("upload-repeat-prefix-parent", 1, "t1")
        .unwrap();
    store
        .complete_upload_job(
            "upload-repeat-prefix-parent",
            version,
            &TerminalOutcome::Succeeded,
            "t2",
        )
        .unwrap();
    store
        .acknowledge_completion("upload-repeat-prefix-parent", "t3")
        .unwrap();

    let child_spec = spec_with_prefix("rev-repeat-prefix", "bundle-child", "captures/new");
    let activity = UploadActivitySeed {
        label: "session.bin".to_string(),
        target_label: "bucket".to_string(),
        total_bytes: 7,
    };
    let first = store
        .repeat_upload_job(
            "upload-repeat-prefix-parent",
            "upload-repeat-prefix-child",
            &child_spec,
            &activity,
            "t4",
        )
        .unwrap();
    assert!(first.was_created());
    assert_eq!(
        store
            .upload_job_spec("upload-repeat-prefix-child")
            .unwrap()
            .unwrap()
            .object_prefix
            .as_deref(),
        Some("captures/new")
    );

    let conflicting = spec_with_prefix("rev-repeat-prefix", "bundle-other", "captures/other");
    let error = store
        .repeat_upload_job(
            "upload-repeat-prefix-parent",
            "upload-repeat-prefix-duplicate",
            &conflicting,
            &activity,
            "t5",
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ylx_transfer_core::persistence::RepeatUploadJobError::ChildConflict { .. }
    ));
}

#[test]
fn entry_revision_is_idempotent_but_immutable_input_and_live_revision_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));

    let first = store
        .create_upload_job("upload-a", &spec("rev-1", "bundle-a"), "t0")
        .unwrap();
    assert!(first.was_created());
    assert_eq!(first.job().operation_kind, OperationKind::Upload);

    let existing = store
        .create_upload_job("different-id", &spec("rev-1", "bundle-a"), "t1")
        .unwrap();
    assert!(!existing.was_created());
    assert_eq!(existing.job().job_id, "upload-a");

    let changed = store
        .create_upload_job("upload-b", &spec("rev-1", "bundle-b"), "t2")
        .unwrap_err();
    assert!(matches!(changed, UploadJobCreateError::Conflict(_)));

    let live_revision = store
        .create_upload_job("upload-c", &spec("rev-2", "bundle-c"), "t3")
        .unwrap_err();
    assert!(matches!(live_revision, UploadJobCreateError::Conflict(_)));
}

#[test]
fn upload_jobs_are_not_download_recovery_candidates_and_parts_carry_job_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let created = store
        .create_upload_job("upload-a", &spec("rev-1", "bundle-a"), "t0")
        .unwrap();
    let version = store
        .start_upload_job(&created.job().job_id, 1, "t1")
        .unwrap();
    let upload = upload_fixture();
    let stored = store
        .begin_upload_for_job(&created.job().job_id, version, &upload, "t2")
        .unwrap();
    assert_eq!(stored.job_id.as_deref(), Some("upload-a"));

    store
        .record_upload_part_for_job(
            "upload-a",
            version,
            &upload.object_key,
            &upload.upload_id,
            &UploadPartRecord {
                part_number: 1,
                etag: "etag-1".to_string(),
                size_bytes: 42,
            },
            "t3",
        )
        .unwrap();

    assert!(store.list_recoverable_jobs().unwrap().is_empty());
    drop(store);
    let reopened = open(&path);
    assert_eq!(
        reopened
            .pending_upload(&upload.object_key, &upload.upload_id)
            .unwrap()
            .unwrap()
            .job_id
            .as_deref(),
        Some("upload-a")
    );
}

#[test]
fn terminal_first_wins_and_late_part_writer_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job("upload-a", &spec("rev-1", "bundle-a"), "t0")
        .unwrap();
    let version = store.start_upload_job("upload-a", 1, "t1").unwrap();
    let upload = upload_fixture();
    store
        .begin_upload_for_job("upload-a", version, &upload, "t2")
        .unwrap();

    let cancelled = store.cancel_upload_job("upload-a", version, "t3").unwrap();
    assert!(matches!(cancelled, CompleteJobOutcome::Recorded(_)));
    let late_finish = store
        .complete_upload_job("upload-a", version, &TerminalOutcome::Succeeded, "t4")
        .unwrap_err();
    assert!(matches!(
        late_finish,
        UploadJobError::AlreadyTerminal { .. }
    ));
    let late_part = store
        .record_upload_part_for_job(
            "upload-a",
            version,
            &upload.object_key,
            &upload.upload_id,
            &UploadPartRecord {
                part_number: 1,
                etag: "late".to_string(),
                size_bytes: 1,
            },
            "t5",
        )
        .unwrap_err();
    assert!(matches!(
        late_part,
        UploadJobError::AlreadyTerminal { .. } | UploadJobError::Stale { .. }
    ));

    let pending = store.pending_completions().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_kind, OperationKind::Upload);
    assert_eq!(pending[0].outcome, TerminalOutcome::Cancelled);
}

#[test]
fn stale_start_is_rejected_and_retry_keeps_upload_parent_and_lineage() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job("upload-a", &spec("rev-1", "bundle-a"), "t0")
        .unwrap();
    let version = store.start_upload_job("upload-a", 1, "t1").unwrap();
    let stale = store.start_upload_job("upload-a", 1, "t2").unwrap_err();
    assert!(matches!(stale, UploadJobError::Stale { .. }));

    store
        .complete_upload_job("upload-a", version, &failed(), "t3")
        .unwrap();
    store.acknowledge_completion("upload-a", "t4").unwrap();
    let retry = store
        .retry_upload_job("upload-a", "upload-b", "t5")
        .unwrap();
    assert!(matches!(retry, RetryJobOutcome::Created(_)));
    assert_eq!(retry.job().operation_kind, OperationKind::Upload);
    assert_eq!(
        store
            .get_job("upload-a")
            .unwrap()
            .unwrap()
            .state
            .as_db_str(),
        "failed"
    );
    assert_eq!(
        store
            .upload_job_spec("upload-b")
            .unwrap()
            .unwrap()
            .input_digest,
        "bundle-a"
    );
    assert_eq!(
        store
            .latest_retry_child("upload-a")
            .unwrap()
            .unwrap()
            .job_id,
        "upload-b"
    );
}

#[test]
fn acknowledged_cancelled_upload_retries_as_a_fresh_zero_progress_child() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_upload_job_with_activity(
            "upload-cancelled-parent",
            &spec("rev-cancelled", "bundle-cancelled"),
            &UploadActivitySeed {
                label: "capture.bin".to_string(),
                target_label: "bucket".to_string(),
                total_bytes: 42,
            },
            "t0",
        )
        .unwrap();
    let version = store
        .start_upload_job("upload-cancelled-parent", 1, "t1")
        .unwrap();
    store
        .stage_upload_receipts_for_job(
            "upload-cancelled-parent",
            &[UploadReceiptSeed::new(
                "objects/capture.bin",
                UploadReceiptRole::Data,
                "etag-parent",
                None,
                42,
                "a".repeat(64),
                UploadReceiptDigestProof::ServerChecksum,
            )],
            "t2",
        )
        .unwrap();
    store
        .cancel_upload_job("upload-cancelled-parent", version, "t3")
        .unwrap();
    store
        .acknowledge_completion("upload-cancelled-parent", "t4")
        .unwrap();

    let child = store
        .retry_upload_job("upload-cancelled-parent", "upload-cancelled-child", "t5")
        .unwrap();
    assert!(matches!(child, RetryJobOutcome::Created(_)));
    assert_eq!(child.job().state.as_db_str(), "queued");
    assert_eq!(child.job().operation_kind, OperationKind::Upload);
    let activity = store
        .upload_activity("upload-cancelled-child")
        .unwrap()
        .unwrap();
    assert_eq!(activity.total_bytes, 42);
    assert_eq!(activity.confirmed_bytes, 0);
    assert!(store
        .list_upload_receipts("upload-cancelled-child")
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_upload_receipts("upload-cancelled-parent")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .retry_parent("upload-cancelled-child")
            .unwrap()
            .unwrap()
            .attempt,
        1
    );

    drop(store);
    let reopened = open(&path);
    assert_eq!(
        reopened
            .get_job("upload-cancelled-parent")
            .unwrap()
            .unwrap()
            .state
            .as_db_str(),
        "cancelled"
    );
    assert_eq!(
        reopened
            .retry_parent("upload-cancelled-child")
            .unwrap()
            .unwrap()
            .parent_job_id,
        "upload-cancelled-parent"
    );
    assert_eq!(
        reopened
            .upload_activity("upload-cancelled-child")
            .unwrap()
            .unwrap()
            .confirmed_bytes,
        0
    );
}

#[test]
fn cancelled_upload_retry_requires_acknowledgement_and_rejects_dismissed_parents() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job("upload-cancelled-guard", &spec("rev-guard", "bundle"), "t0")
        .unwrap();
    let version = store
        .start_upload_job("upload-cancelled-guard", 1, "t1")
        .unwrap();
    store
        .cancel_upload_job("upload-cancelled-guard", version, "t2")
        .unwrap();
    assert!(matches!(
        store.retry_upload_job("upload-cancelled-guard", "child-unacked", "t3"),
        Err(ylx_transfer_core::persistence::RetryJobError::UnacknowledgedParent { .. })
    ));
    store
        .acknowledge_completion("upload-cancelled-guard", "t4")
        .unwrap();
    assert!(store.dismiss_job("upload-cancelled-guard", "t5").unwrap());
    assert!(matches!(
        store.retry_upload_job("upload-cancelled-guard", "child-dismissed", "t6"),
        Err(ylx_transfer_core::persistence::RetryJobError::DismissedParent { .. })
    ));
}

#[test]
fn cancelled_upload_retry_preserves_active_child_and_successful_descendant_fences() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job(
            "upload-cancelled-fences",
            &spec("rev-fences", "bundle-fences"),
            "t0",
        )
        .unwrap();
    let version = store
        .start_upload_job("upload-cancelled-fences", 1, "t1")
        .unwrap();
    store
        .cancel_upload_job("upload-cancelled-fences", version, "t2")
        .unwrap();
    store
        .acknowledge_completion("upload-cancelled-fences", "t3")
        .unwrap();

    let first = store
        .retry_upload_job("upload-cancelled-fences", "cancelled-fence-child", "t4")
        .unwrap();
    assert!(matches!(first, RetryJobOutcome::Created(_)));
    let duplicate = store
        .retry_upload_job("upload-cancelled-fences", "cancelled-fence-duplicate", "t5")
        .unwrap();
    assert!(matches!(duplicate, RetryJobOutcome::Existing(_)));
    assert_eq!(duplicate.job().job_id, "cancelled-fence-child");

    let child_version = store
        .start_upload_job("cancelled-fence-child", 1, "t6")
        .unwrap();
    store
        .complete_upload_job(
            "cancelled-fence-child",
            child_version,
            &TerminalOutcome::Succeeded,
            "t7",
        )
        .unwrap();
    store
        .acknowledge_completion("cancelled-fence-child", "t8")
        .unwrap();
    assert!(matches!(
        store.retry_upload_job("upload-cancelled-fences", "cancelled-fence-again", "t9"),
        Err(ylx_transfer_core::persistence::RetryJobError::SuccessfulDescendant { .. })
    ));
}

#[test]
fn successful_upload_repeat_allows_changed_input_same_revision_and_starts_clean() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let parent_spec = spec("rev-repeat", "destination-a");
    store
        .create_upload_job_with_activity(
            "upload-repeat-parent",
            &parent_spec,
            &UploadActivitySeed {
                label: "session.bin".to_string(),
                target_label: "bucket-a".to_string(),
                total_bytes: 42,
            },
            "t0",
        )
        .unwrap();
    let version = store
        .start_upload_job("upload-repeat-parent", 1, "t1")
        .unwrap();
    store
        .stage_upload_receipts_for_job(
            "upload-repeat-parent",
            &[UploadReceiptSeed::new(
                "session.bin",
                UploadReceiptRole::Data,
                "etag-parent",
                None,
                42,
                "a".repeat(64),
                UploadReceiptDigestProof::ServerChecksum,
            )],
            "t2",
        )
        .unwrap();
    store
        .complete_upload_job(
            "upload-repeat-parent",
            version,
            &TerminalOutcome::Succeeded,
            "t3",
        )
        .unwrap();
    store
        .acknowledge_completion("upload-repeat-parent", "t4")
        .unwrap();

    let child_spec = spec("rev-repeat", "destination-b");
    let child = store
        .repeat_upload_job(
            "upload-repeat-parent",
            "upload-repeat-child",
            &child_spec,
            &UploadActivitySeed {
                label: "session.bin".to_string(),
                target_label: "bucket-b".to_string(),
                total_bytes: 99,
            },
            "t5",
        )
        .unwrap();
    assert!(matches!(child, RetryJobOutcome::Created(_)));
    assert_eq!(child.job().job_id, "upload-repeat-child");
    assert_eq!(child.job().operation_kind, OperationKind::Upload);
    assert_eq!(child.job().state.as_db_str(), "queued");
    assert_eq!(
        store
            .upload_job_spec("upload-repeat-child")
            .unwrap()
            .unwrap()
            .input_digest,
        "destination-b"
    );
    let child_activity = store
        .upload_activity("upload-repeat-child")
        .unwrap()
        .unwrap();
    assert_eq!(child_activity.confirmed_bytes, 0);
    assert_eq!(child_activity.total_bytes, 99);
    assert_eq!(child_activity.target_label, "bucket-b");
    assert!(store
        .list_upload_receipts("upload-repeat-child")
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_upload_receipts("upload-repeat-parent")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .retry_parent("upload-repeat-child")
            .unwrap()
            .unwrap()
            .attempt,
        1
    );

    drop(store);
    let reopened = open(&path);
    let child_activity = reopened
        .upload_activity("upload-repeat-child")
        .unwrap()
        .unwrap();
    assert_eq!(child_activity.confirmed_bytes, 0);
    assert_eq!(
        reopened
            .upload_job_spec("upload-repeat-child")
            .unwrap()
            .unwrap()
            .input_digest,
        "destination-b"
    );
    assert_eq!(
        reopened
            .retry_parent("upload-repeat-child")
            .unwrap()
            .unwrap()
            .parent_job_id,
        "upload-repeat-parent"
    );
    assert_eq!(
        reopened
            .get_job("upload-repeat-parent")
            .unwrap()
            .unwrap()
            .state
            .as_db_str(),
        "succeeded"
    );
}

#[test]
fn dismissed_successful_parent_can_be_repeated_and_duplicate_calls_share_active_child() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let parent_spec = spec("rev-dismiss-repeat", "destination-a");
    store
        .create_upload_job("upload-dismiss-repeat-parent", &parent_spec, "t0")
        .unwrap();
    let version = store
        .start_upload_job("upload-dismiss-repeat-parent", 1, "t1")
        .unwrap();
    store
        .complete_upload_job(
            "upload-dismiss-repeat-parent",
            version,
            &TerminalOutcome::Succeeded,
            "t2",
        )
        .unwrap();
    store
        .acknowledge_completion("upload-dismiss-repeat-parent", "t3")
        .unwrap();
    assert!(store
        .dismiss_job("upload-dismiss-repeat-parent", "t4")
        .unwrap());

    let first = store
        .repeat_upload_job(
            "upload-dismiss-repeat-parent",
            "upload-repeat-active",
            &spec("rev-dismiss-repeat", "destination-b"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-b".to_string(),
                total_bytes: 7,
            },
            "t5",
        )
        .unwrap();
    assert!(matches!(first, RetryJobOutcome::Created(_)));

    // A second call with a fresh id and the same immutable input/activity
    // returns the already-live child; it must not leave a second queued child.
    let duplicate = store
        .repeat_upload_job(
            "upload-dismiss-repeat-parent",
            "upload-repeat-duplicate",
            &spec("rev-dismiss-repeat", "destination-b"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-b".to_string(),
                total_bytes: 7,
            },
            "t6",
        )
        .unwrap();
    assert!(matches!(duplicate, RetryJobOutcome::Existing(_)));
    assert_eq!(duplicate.job().job_id, "upload-repeat-active");
    assert_eq!(store.list_jobs().unwrap().len(), 2);
    assert_eq!(
        store
            .get_job("upload-dismiss-repeat-parent")
            .unwrap()
            .unwrap()
            .dismissed_at
            .as_deref(),
        Some("t4")
    );

    let conflicting_active = store
        .repeat_upload_job(
            "upload-dismiss-repeat-parent",
            "upload-repeat-conflicting",
            &spec("rev-dismiss-repeat", "destination-c"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-c".to_string(),
                total_bytes: 8,
            },
            "t6-conflict",
        )
        .unwrap_err();
    assert!(matches!(
        conflicting_active,
        ylx_transfer_core::persistence::RepeatUploadJobError::ChildConflict { ref job_id, .. }
            if job_id == "upload-repeat-active"
    ));

    // Replaying the exact child id with the same immutable input is
    // idempotent even while it is live.
    let replay = store
        .repeat_upload_job(
            "upload-dismiss-repeat-parent",
            "upload-repeat-active",
            &spec("rev-dismiss-repeat", "destination-b"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-b".to_string(),
                total_bytes: 7,
            },
            "t7",
        )
        .unwrap();
    assert!(matches!(replay, RetryJobOutcome::Existing(_)));
    assert_eq!(replay.job().job_id, "upload-repeat-active");

    let conflicting_replay = store
        .repeat_upload_job(
            "upload-dismiss-repeat-parent",
            "upload-repeat-active",
            &spec("rev-dismiss-repeat", "destination-c"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-c".to_string(),
                total_bytes: 8,
            },
            "t7-conflict",
        )
        .unwrap_err();
    assert!(matches!(
        conflicting_replay,
        ylx_transfer_core::persistence::RepeatUploadJobError::ChildConflict { ref job_id, .. }
            if job_id == "upload-repeat-active"
    ));
}

#[test]
fn successful_repeat_allows_a_new_child_after_the_previous_child_is_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let parent_spec = spec("rev-multiple-repeat", "destination-a");
    store
        .create_upload_job("upload-multiple-parent", &parent_spec, "t0")
        .unwrap();
    let parent_version = store
        .start_upload_job("upload-multiple-parent", 1, "t1")
        .unwrap();
    store
        .complete_upload_job(
            "upload-multiple-parent",
            parent_version,
            &TerminalOutcome::Succeeded,
            "t2",
        )
        .unwrap();
    store
        .acknowledge_completion("upload-multiple-parent", "t3")
        .unwrap();
    let first = store
        .repeat_upload_job(
            "upload-multiple-parent",
            "upload-multiple-child-1",
            &spec("rev-multiple-repeat", "destination-b"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-b".to_string(),
                total_bytes: 1,
            },
            "t4",
        )
        .unwrap();
    let first_version = store
        .start_upload_job(&first.job().job_id, first.job().state_version, "t5")
        .unwrap();
    store
        .complete_upload_job(
            "upload-multiple-child-1",
            first_version,
            &TerminalOutcome::Succeeded,
            "t6",
        )
        .unwrap();
    store
        .acknowledge_completion("upload-multiple-child-1", "t7")
        .unwrap();

    let second = store
        .repeat_upload_job(
            "upload-multiple-parent",
            "upload-multiple-child-2",
            &spec("rev-multiple-repeat", "destination-c"),
            &UploadActivitySeed {
                label: "repeat.bin".to_string(),
                target_label: "bucket-c".to_string(),
                total_bytes: 2,
            },
            "t8",
        )
        .unwrap();
    assert!(matches!(second, RetryJobOutcome::Created(_)));
    assert_eq!(
        store
            .retry_parent("upload-multiple-child-2")
            .unwrap()
            .unwrap()
            .attempt,
        2
    );
    assert_eq!(store.list_jobs().unwrap().len(), 3);
}

fn upload_fixture() -> ylx_transfer_core::persistence::NewUpload {
    ylx_transfer_core::persistence::NewUpload {
        transfer_key: "transfer-upload-a".to_string(),
        entry_key: "device-1|session-1".to_string(),
        revision: "rev-1".to_string(),
        object_key: "device-1/session-1/file.bin".to_string(),
        upload_id: "multipart-1".to_string(),
        endpoint: "https://objects.example.test".to_string(),
        bucket: "captures".to_string(),
        url_style: ylx_transfer_core::persistence::UploadUrlStyle::VirtualHost,
    }
}

#[test]
fn upload_job_activity_creation_rolls_back_job_spec_and_activity_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    let activity = UploadActivitySeed {
        label: "capture.bin".to_string(),
        target_label: "captures".to_string(),
        total_bytes: 123,
    };
    for (job_id, abort) in [
        ("upload-abort-job", UploadJobCreateAbort::AfterJob),
        ("upload-abort-spec", UploadJobCreateAbort::AfterSpec),
        ("upload-abort-activity", UploadJobCreateAbort::AfterActivity),
    ] {
        assert!(store
            .create_upload_job_with_activity_aborting_after(
                job_id,
                &spec(job_id, "bundle"),
                &activity,
                "t0",
                abort,
            )
            .is_err());
        assert!(store.get_job(job_id).unwrap().is_none());
        assert!(store.upload_job_spec(job_id).unwrap().is_none());
        assert!(store.upload_activity(job_id).unwrap().is_none());
    }
    let created = store
        .create_upload_job_with_activity(
            "upload-created",
            &spec("rev-created", "bundle-created"),
            &activity,
            "t1",
        )
        .unwrap();
    assert!(created.was_created());
    let stored = store.upload_activity("upload-created").unwrap().unwrap();
    assert_eq!(stored.label, "capture.bin");
    assert_eq!(stored.target_label, "captures");
    assert_eq!(stored.total_bytes, 123);
    assert_eq!(stored.confirmed_bytes, 0);
}

#[test]
fn data_part_progress_is_durable_idempotent_and_excludes_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_upload_job_with_activity(
            "upload-progress",
            &spec("rev-progress", "bundle-progress"),
            &UploadActivitySeed {
                label: "video.mp4".to_string(),
                target_label: "bucket".to_string(),
                total_bytes: 30,
            },
            "t0",
        )
        .unwrap();
    let version = store.start_upload_job("upload-progress", 1, "t1").unwrap();
    let upload = upload_fixture();
    store
        .begin_upload_for_job("upload-progress", version, &upload, "t2")
        .unwrap();
    let data_part = UploadPartRecord {
        part_number: 1,
        etag: "data-etag".to_string(),
        size_bytes: 10,
    };
    store
        .record_upload_part_for_job_with_progress(
            "upload-progress",
            version,
            &upload.object_key,
            &upload.upload_id,
            &data_part,
            Some(10),
            "t3",
        )
        .unwrap();
    store
        .record_upload_part_for_job_with_progress(
            "upload-progress",
            version,
            &upload.object_key,
            &upload.upload_id,
            &data_part,
            Some(10),
            "t4",
        )
        .unwrap();
    let evidence = UploadPartRecord {
        part_number: 2,
        etag: "manifest-etag".to_string(),
        size_bytes: 999,
    };
    store
        .record_upload_part_for_job_with_progress(
            "upload-progress",
            version,
            &upload.object_key,
            &upload.upload_id,
            &evidence,
            None,
            "t5",
        )
        .unwrap();
    let activity = store.upload_activity("upload-progress").unwrap().unwrap();
    assert_eq!(activity.confirmed_bytes, 10);
    assert_eq!(activity.total_bytes, 30);

    let mut conflicting = data_part.clone();
    conflicting.etag = "different".to_string();
    let error = store
        .record_upload_part_for_job_with_progress(
            "upload-progress",
            version,
            &upload.object_key,
            &upload.upload_id,
            &conflicting,
            Some(10),
            "t6",
        )
        .unwrap_err();
    assert!(matches!(
        error,
        UploadJobError::Part(UploadStoreError::PartConflict { .. })
    ));
    assert!(store
        .finish_upload(&upload.object_key, &upload.upload_id)
        .unwrap());
    assert_eq!(
        store
            .upload_activity("upload-progress")
            .unwrap()
            .unwrap()
            .confirmed_bytes,
        10,
        "aggregate progress survives multipart evidence cleanup"
    );
}

#[test]
fn completion_ack_then_dismiss_tombstones_upload_without_deleting_lineage_or_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer.sqlite3");
    let mut store = open(&path);
    store
        .create_upload_job_with_activity(
            "upload-dismiss-parent",
            &spec("rev-dismiss", "bundle-dismiss"),
            &UploadActivitySeed {
                label: "dismiss-me".to_string(),
                target_label: "bucket".to_string(),
                total_bytes: 1,
            },
            "t0",
        )
        .unwrap();
    let version = store
        .start_upload_job("upload-dismiss-parent", 1, "t1")
        .unwrap();
    let upload = upload_fixture();
    store
        .begin_upload_for_job("upload-dismiss-parent", version, &upload, "t2")
        .unwrap();
    assert!(matches!(
        store.dismiss_job("upload-dismiss-parent", "t2-active"),
        Err(DismissJobError::NotTerminal { .. })
    ));
    store
        .complete_upload_job("upload-dismiss-parent", version, &failed(), "t3")
        .unwrap();
    assert!(matches!(
        store.dismiss_job("upload-dismiss-parent", "t4"),
        Err(DismissJobError::Unacknowledged { .. })
    ));
    store
        .acknowledge_completion("upload-dismiss-parent", "t5")
        .unwrap();
    assert!(matches!(
        store.dismiss_job("upload-dismiss-parent", "t6"),
        Err(DismissJobError::PendingMultipart { .. })
    ));
    store
        .finish_upload(&upload.object_key, &upload.upload_id)
        .unwrap();
    let child = store
        .retry_upload_job("upload-dismiss-parent", "upload-dismiss-child", "t7")
        .unwrap();
    assert!(matches!(child, RetryJobOutcome::Created(_)));
    assert!(store.dismiss_job("upload-dismiss-parent", "t8").unwrap());
    assert!(!store.dismiss_job("upload-dismiss-parent", "t9").unwrap());
    let parent = store.get_job("upload-dismiss-parent").unwrap().unwrap();
    assert_eq!(parent.dismissed_at.as_deref(), Some("t8"));
    assert_eq!(store.list_upload_activities().unwrap().len(), 1);
    assert!(store
        .upload_activity("upload-dismiss-parent")
        .unwrap()
        .is_some());

    drop(store);
    let store = open(&path);
    assert_eq!(
        store
            .get_job("upload-dismiss-parent")
            .unwrap()
            .unwrap()
            .dismissed_at
            .as_deref(),
        Some("t8")
    );

    let child_activity = store
        .upload_activity("upload-dismiss-child")
        .unwrap()
        .unwrap();
    assert_eq!(child_activity.confirmed_bytes, 0);
    assert_eq!(child_activity.total_bytes, 1);
    assert_eq!(
        store
            .retry_parent("upload-dismiss-child")
            .unwrap()
            .unwrap()
            .parent_job_id,
        "upload-dismiss-parent"
    );
    assert_eq!(
        store
            .upload_job_spec("upload-dismiss-child")
            .unwrap()
            .unwrap()
            .input_digest,
        "bundle-dismiss"
    );
    assert!(store.get_job("upload-dismiss-parent").unwrap().is_some());
}

#[test]
fn dismissed_upload_jobs_remain_in_audit_list_but_not_visible_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    // Use the upload path to create a compact terminal job; the tombstone API
    // is lane-neutral and the visibility contract is identical for download.
    store
        .create_upload_job(
            "upload-visible",
            &spec("rev-visible", "bundle-visible"),
            "t0",
        )
        .unwrap();
    let version = store.start_upload_job("upload-visible", 1, "t1").unwrap();
    store
        .complete_upload_job("upload-visible", version, &failed(), "t2")
        .unwrap();
    store
        .acknowledge_completion("upload-visible", "t3")
        .unwrap();
    assert_eq!(store.list_visible_jobs().unwrap().len(), 1);
    store.dismiss_job("upload-visible", "t4").unwrap();
    assert!(store.list_visible_jobs().unwrap().is_empty());
    assert_eq!(store.list_jobs().unwrap().len(), 1);
}

#[test]
fn a_successful_upload_descendant_blocks_another_retry_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    store
        .create_upload_job(
            "upload-descendant-parent",
            &spec("rev-desc", "bundle-desc"),
            "t0",
        )
        .unwrap();
    let parent_version = store
        .start_upload_job("upload-descendant-parent", 1, "t1")
        .unwrap();
    store
        .complete_upload_job("upload-descendant-parent", parent_version, &failed(), "t2")
        .unwrap();
    store
        .acknowledge_completion("upload-descendant-parent", "t3")
        .unwrap();
    let child = store
        .retry_upload_job("upload-descendant-parent", "upload-descendant-child", "t4")
        .unwrap();
    assert!(matches!(child, RetryJobOutcome::Created(_)));
    let child_version = store
        .start_upload_job("upload-descendant-child", 1, "t5")
        .unwrap();
    store
        .complete_upload_job(
            "upload-descendant-child",
            child_version,
            &TerminalOutcome::Succeeded,
            "t6",
        )
        .unwrap();
    store
        .acknowledge_completion("upload-descendant-child", "t7")
        .unwrap();
    let error = store
        .retry_upload_job("upload-descendant-parent", "upload-descendant-again", "t8")
        .unwrap_err();
    assert!(matches!(
        error,
        ylx_transfer_core::persistence::RetryJobError::SuccessfulDescendant { .. }
    ));
}

#[test]
fn unacknowledged_successful_upload_stays_visible_until_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(&dir.path().join("transfer.sqlite3"));
    let created = store
        .create_upload_job(
            "upload-finalizing",
            &spec("rev-finalizing", "bundle-finalizing"),
            "t0",
        )
        .unwrap();
    let version = store
        .start_upload_job("upload-finalizing", created.job().state_version, "t1")
        .unwrap();
    store
        .complete_upload_job(
            "upload-finalizing",
            version,
            &TerminalOutcome::Succeeded,
            "t2",
        )
        .unwrap();
    assert_eq!(
        store
            .list_upload_activities()
            .unwrap()
            .iter()
            .map(|activity| activity.job.job_id.as_str())
            .collect::<Vec<_>>(),
        vec!["upload-finalizing"]
    );

    store
        .acknowledge_completion("upload-finalizing", "t3")
        .unwrap();
    assert!(store.list_upload_activities().unwrap().is_empty());

    drop(store);
    let store = open(&dir.path().join("transfer.sqlite3"));
    assert!(store.list_upload_activities().unwrap().is_empty());
}
