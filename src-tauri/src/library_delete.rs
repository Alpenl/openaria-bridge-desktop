//! Crash-recoverable local-library deletion.
//!
//! A delete is a small transaction spanning two authorities: the filesystem
//! and `AppStore`.  The visible session directory is first renamed into a
//! hidden directory below the same library root.  Only after that rename is
//! a durable SQLite intent recorded.  The AppStore revision CAS is the
//! linearization point; staged intents roll back to the original path while
//! committed intents only clean trash.  A marker in every trash operation
//! directory closes the tiny crash window between rename and intent insert.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use ylx_transfer_core::library::download::derive_target_path;
use ylx_transfer_core::persistence::app_store::{
    LibraryDeleteIntent, LibraryDeleteIntentState, OperationLeaseOutcome,
};
use ylx_transfer_core::persistence::{AppStore, OperationKind, TransferStore};

use crate::models::LibraryEntry;

const TRASH_DIR_NAME: &str = ".ylx-library-trash";
const MARKER_PREFIX: &str = ".ylx-delete-marker-";
const PAYLOAD_PREFIX: &str = "payload-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntry {
    pub key: String,
    pub device_id: String,
    pub session_id: String,
}

impl DeleteEntry {
    pub fn from_library(entry: &LibraryEntry) -> Self {
        Self {
            key: entry.key(),
            device_id: entry.device_id.clone(),
            session_id: entry.session_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOutcome {
    pub operation_id: String,
    pub committed_revision: u64,
    /// Cleanup is deliberately retryable. `false` means metadata is already
    /// committed but the hidden trash remains for startup/background retry.
    pub cleanup_complete: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub rolled_back: usize,
    pub finalized: usize,
    pub orphan_markers: usize,
    pub stale_upload_leases: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrashMarker {
    operation_id: String,
    entry_key: String,
    source_path: String,
    payload_path: String,
}

#[derive(Debug, Clone)]
struct StagedPath {
    entry_key: String,
    source_path: PathBuf,
    trash_path: PathBuf,
    marker_path: PathBuf,
}

/// Performs one or more entry deletions. The caller supplies the AppStore
/// revision captured while it held the application-state lock. No in-memory
/// state is touched here, so a persistence failure can safely restore files.
pub fn delete_entries(
    store: &AppStore,
    library_root: &Path,
    expected_revision: u64,
    entries: &[DeleteEntry],
) -> Result<DeleteOutcome, String> {
    if entries.is_empty() {
        return Err("删除操作缺少本地记录".to_string());
    }
    let mut unique_entries: Vec<DeleteEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(existing) = unique_entries
            .iter()
            .find(|candidate| candidate.key == entry.key)
        {
            if existing != entry {
                return Err(format!(
                    "同一删除批次中的 key 对应多个本地路径：{}",
                    entry.key
                ));
            }
            continue;
        }
        unique_entries.push(entry.clone());
    }
    let entries = unique_entries;
    validate_library_root(library_root)?;
    let operation_id = format!("delete-{}", uuid::Uuid::new_v4().simple());
    let keys = entries
        .iter()
        .map(|entry| entry.key.clone())
        .collect::<Vec<_>>();
    let now = chrono::Utc::now().to_rfc3339();
    let leases = store
        .acquire_operation_leases(&operation_id, &keys, "delete", &now)
        .map_err(|error| format!("无法获取本地记录删除租约：{error}"))?;
    if let Some(existing) = leases.iter().find_map(|outcome| match outcome {
        OperationLeaseOutcome::Existing(existing) => Some(existing),
        OperationLeaseOutcome::Acquired => None,
    }) {
        return Err(format!(
            "本地记录正在执行 {} 操作（{}），请稍后重试",
            existing.kind, existing.operation_id
        ));
    }

    let staged = match stage_entries(library_root, &operation_id, &entries) {
        Ok(staged) => staged,
        Err(error) => {
            // No SQLite intent exists yet. The marker is the recovery record
            // for this narrow window, so use the same validated scanner to
            // restore any entries staged before the failure.
            let recovery = recover_orphan_markers(store, library_root);
            let _ = store.release_operation_leases(&operation_id);
            return Err(match recovery {
                Ok(_) => error,
                Err(recovery) => format!("{error}；部分文件回滚失败：{recovery}"),
            });
        }
    };
    let intents = staged
        .iter()
        .map(|path| LibraryDeleteIntent {
            operation_id: operation_id.clone(),
            entry_key: path.entry_key.clone(),
            source_path: path.source_path.clone(),
            trash_path: path.trash_path.clone(),
            expected_revision,
            state: LibraryDeleteIntentState::Staged,
            created_at: now.clone(),
        })
        .collect::<Vec<_>>();
    if let Err(error) = store.record_library_delete_intents(&intents) {
        let rollback = rollback_staged(library_root, &staged);
        let _ = store.abort_library_delete(&operation_id);
        return Err(format_delete_failure(
            "无法记录本地删除意图",
            error,
            rollback,
        ));
    }

    let committed_revision =
        match store.commit_library_delete_if_revision(expected_revision, &operation_id, &keys) {
            Ok(revision) => revision,
            Err(error) => {
                let rollback = rollback_staged(library_root, &staged);
                if rollback.is_ok() {
                    let _ = store.abort_library_delete(&operation_id);
                }
                return Err(format_delete_failure(
                    "无法提交本地资料库删除",
                    error,
                    rollback,
                ));
            }
        };

    // Cleanup is intentionally best effort. The committed intent remains
    // durable until every payload is gone, so startup recovery retries it.
    let cleanup_complete = cleanup_committed_delete(store, library_root, &operation_id, &staged);
    Ok(DeleteOutcome {
        operation_id,
        committed_revision,
        cleanup_complete,
    })
}

fn format_delete_failure(
    prefix: &str,
    persistence: impl std::fmt::Display,
    rollback: Result<(), String>,
) -> String {
    match rollback {
        Ok(()) => format!("{prefix}，已恢复本地文件：{persistence}"),
        Err(rollback) => format!(
            "{prefix}，文件回滚未完成；删除意图已保留供启动恢复（{persistence}；回滚：{rollback}）"
        ),
    }
}

fn stage_entries(
    library_root: &Path,
    operation_id: &str,
    entries: &[DeleteEntry],
) -> Result<Vec<StagedPath>, String> {
    let trash_root = library_root.join(TRASH_DIR_NAME);
    reject_symlink(&trash_root)?;
    fs::create_dir_all(&trash_root)
        .map_err(|error| format!("无法创建资料库 trash 目录：{error}"))?;
    reject_symlink(&trash_root)?;
    let operation_dir = trash_root.join(operation_id);
    fs::create_dir(&operation_dir)
        .map_err(|error| format!("无法创建删除操作目录 {operation_dir:?}：{error}"))?;
    sync_directory(&trash_root)?;

    let mut staged = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let source_path = entry_session_dir(library_root, entry)?;
        validate_source_path(library_root, &source_path)?;
        let marker_path = operation_dir.join(format!("{MARKER_PREFIX}{index}"));
        let trash_path = operation_dir.join(format!("{PAYLOAD_PREFIX}{index}"));
        let marker = TrashMarker {
            operation_id: operation_id.to_string(),
            entry_key: entry.key.clone(),
            source_path: source_path.to_string_lossy().into_owned(),
            payload_path: trash_path.to_string_lossy().into_owned(),
        };
        write_marker(&marker_path, &marker)?;
        // `File::sync_all` makes the marker contents durable, while the
        // parent directory sync makes its directory entry durable before the
        // payload can be renamed away from the visible tree.
        sync_directory(&operation_dir)?;

        match fs::symlink_metadata(&source_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("拒绝删除符号链接：{}", source_path.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("本地会话路径不是目录：{}", source_path.display()));
            }
            Ok(_) => {
                // Both paths are below library_root, therefore rename cannot
                // cross filesystems unless a mount point was placed below the
                // root. Check that explicitly on Unix; Windows' rename call
                // itself rejects a cross-volume move and we never copy.
                ensure_same_filesystem(&source_path, &trash_path)?;
                fs::rename(&source_path, &trash_path).map_err(|error| {
                    format!(
                        "无法将本地会话移入同盘 trash（{} -> {}）：{error}",
                        source_path.display(),
                        trash_path.display()
                    )
                })?;
                sync_directory(&operation_dir)?;
                sync_directory(
                    source_path
                        .parent()
                        .ok_or_else(|| "本地会话目录缺少父目录".to_string())?,
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Metadata can outlive an externally removed local copy. The
                // durable intent still removes metadata atomically and is
                // idempotent on retry; there is simply no payload to restore.
            }
            Err(error) => {
                return Err(format!(
                    "无法检查本地会话目录 {}：{error}",
                    source_path.display()
                ));
            }
        }
        staged.push(StagedPath {
            entry_key: entry.key.clone(),
            source_path,
            trash_path,
            marker_path,
        });
    }
    Ok(staged)
}

fn rollback_staged(library_root: &Path, staged: &[StagedPath]) -> Result<(), String> {
    let mut errors = Vec::new();
    for path in staged.iter().rev() {
        match fs::symlink_metadata(&path.trash_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                errors.push(format!(
                    "trash payload 是符号链接：{}",
                    path.trash_path.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                errors.push(format!(
                    "trash payload 不是目录：{}",
                    path.trash_path.display()
                ));
            }
            Ok(_) => {
                if fs::symlink_metadata(&path.source_path).is_ok() {
                    errors.push(format!(
                        "回滚目标已存在，拒绝覆盖：{}",
                        path.source_path.display()
                    ));
                } else if let Err(error) = fs::rename(&path.trash_path, &path.source_path) {
                    errors.push(format!(
                        "无法将 trash 恢复到 {}：{error}",
                        path.source_path.display()
                    ));
                } else if let Some(parent) = path.source_path.parent() {
                    if let Err(error) = sync_directory(parent) {
                        errors.push(error);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!("无法检查 trash payload：{error}")),
        }
        if let Err(error) = remove_if_exists(&path.marker_path) {
            errors.push(error);
        }
    }
    if let Some(operation_dir) = staged.first().and_then(|path| path.trash_path.parent()) {
        if let Err(error) = remove_empty_tree(operation_dir, &library_root.join(TRASH_DIR_NAME)) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

/// Best-effort cleanup after a committed CAS. Returning `false` leaves the
/// SQLite intent in place for retry; no metadata is reinserted after commit.
fn cleanup_committed_delete(
    store: &AppStore,
    library_root: &Path,
    operation_id: &str,
    staged: &[StagedPath],
) -> bool {
    if staged.iter().any(|path| {
        remove_if_exists(&path.marker_path).is_err()
            || remove_dir_if_exists(&path.trash_path).is_err()
    }) {
        return false;
    }
    let Some(operation_dir) = staged.first().and_then(|path| path.trash_path.parent()) else {
        return store.finalize_library_delete(operation_id).is_ok();
    };
    if remove_empty_tree(operation_dir, &library_root.join(TRASH_DIR_NAME)).is_err() {
        return false;
    }
    store.finalize_library_delete(operation_id).is_ok()
}

/// Reconciles all intents and unreferenced marker directories at startup.
/// Staged work rolls back, committed work finalizes. A malformed or unsafe
/// intent returns an error rather than silently deleting or moving data.
pub fn recover_pending_deletes(
    store: &AppStore,
    library_root: &Path,
) -> Result<RecoveryReport, String> {
    validate_library_root(library_root)?;
    let intents = store
        .list_library_delete_intents()
        .map_err(|error| format!("无法读取本地删除恢复意图：{error}"))?;
    let mut report = RecoveryReport::default();
    let mut by_operation: HashMap<String, Vec<LibraryDeleteIntent>> = HashMap::new();
    for intent in intents {
        validate_intent_paths(
            library_root,
            &intent.operation_id,
            &intent.source_path,
            &intent.trash_path,
        )?;
        by_operation
            .entry(intent.operation_id.clone())
            .or_default()
            .push(intent);
    }
    for (operation_id, intents) in by_operation {
        let first_state = intents.first().map(|intent| intent.state);
        if intents
            .iter()
            .any(|intent| Some(intent.state) != first_state)
        {
            return Err(format!(
                "删除操作 {operation_id} 同时包含 staged/committed 意图，拒绝猜测恢复"
            ));
        }
        match first_state {
            Some(LibraryDeleteIntentState::Staged) => {
                for intent in &intents {
                    restore_intent(library_root, intent)?;
                }
                store
                    .abort_library_delete(&operation_id)
                    .map_err(|error| format!("无法清除已回滚删除意图：{error}"))?;
                report.rolled_back += intents.len();
            }
            Some(LibraryDeleteIntentState::Committed) => {
                for intent in &intents {
                    remove_dir_if_exists(&intent.trash_path)?;
                    remove_if_exists(
                        &intent
                            .trash_path
                            .with_file_name(marker_name_for(&intent.trash_path)),
                    )?;
                }
                store
                    .finalize_library_delete(&operation_id)
                    .map_err(|error| format!("无法完成本地删除恢复：{error}"))?;
                report.finalized += intents.len();
            }
            None => {}
        }
    }
    report.orphan_markers += recover_orphan_markers(store, library_root)?;
    // A crash before the first marker was durable can leave only a delete
    // lease. No intent or marker means there is no filesystem operation to
    // protect, so release that orphaned process-local claim.
    let referenced_delete_operations = store
        .list_library_delete_intents()
        .map_err(|error| format!("无法读取删除租约关联：{error}"))?
        .into_iter()
        .map(|intent| intent.operation_id)
        .collect::<HashSet<_>>();
    for lease in store
        .list_operation_leases()
        .map_err(|error| format!("无法读取删除租约：{error}"))?
    {
        if lease.kind == "delete" && !referenced_delete_operations.contains(&lease.operation_id) {
            store
                .release_operation_leases(&lease.operation_id)
                .map_err(|error| format!("无法释放孤立删除租约：{error}"))?;
        }
    }
    report.stale_upload_leases = reconcile_upload_leases(store)?;
    Ok(report)
}

/// Removes upload leases left by a crashed command once durable transfer rows
/// prove there is no active upload for the entry. Active rows are never
/// guessed from the in-memory UI queue.
pub fn reconcile_upload_leases(store: &AppStore) -> Result<usize, String> {
    let transfer_path = store
        .path()
        .parent()
        .ok_or_else(|| "application store path has no parent".to_string())?
        .join("transfer_store.sqlite3");
    let transfer_store = TransferStore::open(&transfer_path)
        .map_err(|error| format!("无法打开 durable transfer store 以恢复上传租约：{error}"))?;
    let jobs = transfer_store
        .list_jobs()
        .map_err(|error| format!("无法枚举 durable 上传任务：{error}"))?;
    let mut active_entries = HashSet::new();
    for job in jobs {
        if job.operation_kind != OperationKind::Upload || job.state.is_terminal() {
            continue;
        }
        if let Some(spec) = transfer_store
            .upload_job_spec(&job.job_id)
            .map_err(|error| format!("无法读取上传任务 {}：{error}", job.job_id))?
        {
            active_entries.insert(spec.entry_key);
        }
    }
    let leases = store
        .list_operation_leases()
        .map_err(|error| format!("无法读取 operation lease：{error}"))?;
    let mut removed = 0;
    for lease in leases {
        if lease.kind == "upload" && !active_entries.contains(&lease.entry_key) {
            removed += store
                .release_operation_leases(&lease.operation_id)
                .map_err(|error| format!("无法释放过期上传租约：{error}"))?
                as usize;
        }
    }
    Ok(removed)
}

/// Returns a durable busy reason for a delete command. It checks both the
/// lease table and transfer-store upload rows to cover old/direct callers
/// that predate the command-side lease wrapper.
pub fn entry_busy_reason(store: &AppStore, entry_key: &str) -> Result<Option<String>, String> {
    if let Some(lease) = store
        .list_operation_leases()
        .map_err(|error| format!("无法读取 operation lease：{error}"))?
        .into_iter()
        .find(|lease| lease.entry_key == entry_key)
    {
        return Ok(Some(format!(
            "本地记录正在执行 {} 操作（{}）",
            lease.kind, lease.operation_id
        )));
    }
    let transfer_path = store
        .path()
        .parent()
        .ok_or_else(|| "application store path has no parent".to_string())?
        .join("transfer_store.sqlite3");
    let transfer_store = TransferStore::open(&transfer_path)
        .map_err(|error| format!("无法读取 durable 上传任务：{error}"))?;
    for job in transfer_store
        .list_jobs()
        .map_err(|error| format!("无法枚举 durable 上传任务：{error}"))?
    {
        if job.operation_kind != OperationKind::Upload || job.state.is_terminal() {
            continue;
        }
        if transfer_store
            .upload_job_spec(&job.job_id)
            .map_err(|error| format!("无法读取上传任务 {}：{error}", job.job_id))?
            .is_some_and(|spec| spec.entry_key == entry_key)
        {
            return Ok(Some(format!("本地记录正在上传（{}）", job.job_id)));
        }
    }
    Ok(None)
}

/// Acquires a command-side upload lease. The caller keeps the opaque id until
/// the durable upload row reaches a terminal state.
pub fn acquire_upload_lease(store: &AppStore, entry_key: &str) -> Result<String, String> {
    let operation_id = format!("upload-{}", uuid::Uuid::new_v4().simple());
    let now = chrono::Utc::now().to_rfc3339();
    let outcomes = store
        .acquire_operation_leases(&operation_id, &[entry_key.to_string()], "upload", &now)
        .map_err(|error| format!("无法获取上传租约：{error}"))?;
    if let Some(OperationLeaseOutcome::Existing(existing)) = outcomes.first() {
        return Err(format!(
            "本地记录正在执行 {} 操作（{}）",
            existing.kind, existing.operation_id
        ));
    }
    Ok(operation_id)
}

pub fn release_upload_lease(store: &AppStore, operation_id: &str) {
    let _ = store.release_operation_leases(operation_id);
}

/// Reaper used by command-side upload starts. The durable startup pass is the
/// crash fallback; this thread merely shortens the lifetime of a completed
/// lease so a new operation need not wait for restart.
pub fn spawn_upload_lease_reaper(
    app_store_path: PathBuf,
    transfer_store_path: PathBuf,
    operation_id: String,
    transfer_key: String,
) {
    thread::spawn(move || {
        for _ in 0..2400 {
            let terminal = TransferStore::open(&transfer_store_path)
                .ok()
                .and_then(|store| store.get_job(&transfer_key).ok().flatten())
                .map(|job| job.state.is_terminal())
                .unwrap_or(false);
            if terminal {
                if let Ok(store) = AppStore::open(&app_store_path) {
                    let _ = store.release_operation_leases(&operation_id);
                }
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
}

fn recover_orphan_markers(store: &AppStore, library_root: &Path) -> Result<usize, String> {
    let trash_root = library_root.join(TRASH_DIR_NAME);
    reject_symlink(&trash_root)?;
    let entries = match fs::read_dir(&trash_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("无法扫描资料库 trash：{error}")),
    };
    let known = store
        .list_library_delete_intents()
        .map_err(|error| format!("无法读取删除恢复意图：{error}"))?
        .into_iter()
        .map(|intent| (intent.operation_id, intent.entry_key))
        .collect::<HashSet<_>>();
    let mut recovered = 0;
    for operation in entries {
        let operation = operation.map_err(|error| format!("无法枚举 trash 操作：{error}"))?;
        let operation_type = operation
            .file_type()
            .map_err(|error| format!("无法检查 trash 操作：{error}"))?;
        if operation_type.is_symlink() {
            return Err(format!(
                "拒绝扫描符号链接 trash 操作：{}",
                operation.path().display()
            ));
        }
        if !operation_type.is_dir() {
            continue;
        }
        let operation_dir = operation.path();
        let markers = fs::read_dir(&operation_dir)
            .map_err(|error| format!("无法读取 trash 操作目录：{error}"))?;
        for marker in markers {
            let marker = marker.map_err(|error| format!("无法枚举 trash marker：{error}"))?;
            let name = marker.file_name().to_string_lossy().into_owned();
            if !name.starts_with(MARKER_PREFIX) {
                continue;
            }
            let marker_path = marker.path();
            let marker_metadata = fs::symlink_metadata(&marker_path)
                .map_err(|error| format!("无法检查 trash marker：{error}"))?;
            if marker_metadata.file_type().is_symlink() {
                return Err(format!(
                    "拒绝读取符号链接 trash marker：{}",
                    marker_path.display()
                ));
            }
            if !marker_metadata.is_file() {
                return Err(format!("trash marker 不是文件：{}", marker_path.display()));
            }
            let parsed = read_marker(&marker_path)?;
            validate_marker(library_root, &operation_dir, &parsed)?;
            if known.contains(&(parsed.operation_id.clone(), parsed.entry_key.clone())) {
                continue;
            }
            let source = PathBuf::from(parsed.source_path);
            let payload = PathBuf::from(parsed.payload_path);
            match fs::symlink_metadata(&payload) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "拒绝恢复符号链接 trash payload：{}",
                        payload.display()
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(format!("trash payload 不是目录：{}", payload.display()));
                }
                Ok(_) => {
                    if fs::symlink_metadata(&source).is_ok() {
                        return Err(format!(
                            "未登记 trash 与原路径同时存在，拒绝猜测恢复：{}",
                            source.display()
                        ));
                    }
                    ensure_same_filesystem(&source, &payload)?;
                    fs::rename(&payload, &source)
                        .map_err(|error| format!("无法恢复未登记 trash：{error}"))?;
                    if let Some(parent) = source.parent() {
                        sync_directory(parent)?;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("无法检查未登记 trash payload：{error}"));
                }
            }
            remove_if_exists(&marker_path)?;
            recovered += 1;
        }
        remove_empty_tree(&operation_dir, &trash_root)?;
    }
    Ok(recovered)
}

fn validate_marker(
    library_root: &Path,
    operation_dir: &Path,
    marker: &TrashMarker,
) -> Result<(), String> {
    let operation_name = operation_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("trash 操作目录名称无效：{}", operation_dir.display()))?;
    if marker.operation_id != operation_name {
        return Err(format!(
            "trash marker operation id 与目录不匹配：{}",
            operation_dir.display()
        ));
    }
    let source = Path::new(&marker.source_path);
    let payload = Path::new(&marker.payload_path);
    validate_source_path(library_root, source)?;
    validate_source_chain(library_root, payload)?;
    if payload.parent() != Some(operation_dir)
        || !payload
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(PAYLOAD_PREFIX))
    {
        return Err(format!(
            "trash marker payload 路径不属于操作目录：{}",
            payload.display()
        ));
    }
    Ok(())
}

fn restore_intent(library_root: &Path, intent: &LibraryDeleteIntent) -> Result<(), String> {
    validate_intent_paths(
        library_root,
        &intent.operation_id,
        &intent.source_path,
        &intent.trash_path,
    )?;
    match fs::symlink_metadata(&intent.trash_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "拒绝恢复符号链接 trash：{}",
                intent.trash_path.display()
            ))
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(format!(
                "trash payload 不是目录：{}",
                intent.trash_path.display()
            ))
        }
        Ok(_) => {
            if fs::symlink_metadata(&intent.source_path).is_ok() {
                return Err(format!(
                    "恢复目标已存在，拒绝覆盖：{}",
                    intent.source_path.display()
                ));
            }
            ensure_same_filesystem(&intent.source_path, &intent.trash_path)?;
            fs::rename(&intent.trash_path, &intent.source_path)
                .map_err(|error| format!("无法恢复删除前目录：{error}"))?;
            if let Some(parent) = intent.source_path.parent() {
                sync_directory(parent)?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("无法检查删除 trash：{error}")),
    }
    Ok(())
}

fn entry_session_dir(library_root: &Path, entry: &DeleteEntry) -> Result<PathBuf, String> {
    let marker = derive_target_path(
        library_root,
        &entry.device_id,
        &entry.session_id,
        "__session_marker__",
    )
    .map_err(|error| format!("本地记录包含不安全的标识：{error}"))?;
    marker
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "无法解析本地会话目录".to_string())
}

fn validate_library_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!("资料库根目录必须是绝对路径：{}", root.display()));
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("无法检查本地资料库根目录 {}：{error}", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("拒绝使用符号链接资料库根目录：{}", root.display()));
    }
    if !metadata.is_dir() {
        return Err(format!("资料库根目录不是目录：{}", root.display()));
    }
    Ok(())
}

fn validate_source_chain(root: &Path, path: &Path) -> Result<(), String> {
    validate_recovery_path(root, path)?;
    let mut current = root.to_path_buf();
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "本地路径越出资料库根目录".to_string())?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(format!("本地路径包含不安全组件：{}", path.display()));
        };
        current.push(name);
        reject_symlink(&current)?;
    }
    Ok(())
}

fn validate_source_path(root: &Path, path: &Path) -> Result<(), String> {
    validate_source_chain(root, path)?;
    let trash_root = root.join(TRASH_DIR_NAME);
    if path.starts_with(&trash_root) {
        return Err(format!("本地源路径不得位于 trash 目录：{}", path.display()));
    }
    Ok(())
}

fn validate_intent_paths(
    root: &Path,
    operation_id: &str,
    source: &Path,
    trash: &Path,
) -> Result<(), String> {
    let operation_components = Path::new(operation_id).components().collect::<Vec<_>>();
    if operation_components.len() != 1
        || !matches!(operation_components.first(), Some(Component::Normal(_)))
    {
        return Err(format!("删除操作 id 不安全：{operation_id:?}"));
    }
    validate_source_path(root, source)?;
    validate_source_chain(root, trash)?;
    let operation_dir = root.join(TRASH_DIR_NAME).join(operation_id);
    if trash.parent() != Some(operation_dir.as_path())
        || !trash
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(PAYLOAD_PREFIX))
    {
        return Err(format!(
            "删除意图 trash 路径不属于操作目录：{}",
            trash.display()
        ));
    }
    Ok(())
}

fn validate_recovery_path(root: &Path, path: &Path) -> Result<(), String> {
    if !path.is_absolute() || !path.starts_with(root) {
        return Err(format!("恢复路径越出资料库根目录：{}", path.display()));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "恢复路径越出资料库根目录".to_string())?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("恢复路径包含不安全组件：{}", path.display()));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("拒绝访问符号链接：{}", path.display()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("无法检查本地路径 {}：{error}", path.display())),
    }
}

fn ensure_same_filesystem(source: &Path, target: &Path) -> Result<(), String> {
    let source_parent = source
        .parent()
        .ok_or_else(|| format!("源路径缺少父目录：{}", source.display()))?;
    let target_parent = target
        .parent()
        .ok_or_else(|| format!("trash 路径缺少父目录：{}", target.display()))?;
    let source_metadata =
        fs::metadata(source_parent).map_err(|error| format!("无法检查源目录文件系统：{error}"))?;
    let target_metadata =
        fs::metadata(target_parent).map_err(|error| format!("无法检查 trash 文件系统：{error}"))?;
    #[cfg(unix)]
    if source_metadata.dev() != target_metadata.dev() {
        return Err(format!(
            "拒绝跨文件系统移动本地会话（{} -> {}）",
            source.display(),
            target.display()
        ));
    }
    #[cfg(not(unix))]
    {
        // Windows' fs::rename is the authority for volume identity and
        // returns an error for cross-volume moves. Keep the metadata reads
        // above so the source/target parents are still validated.
        let _ = (source_metadata, target_metadata);
    }
    Ok(())
}

fn write_marker(path: &Path, marker: &TrashMarker) -> Result<(), String> {
    let raw =
        serde_json::to_vec(marker).map_err(|error| format!("无法编码删除 marker：{error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("无法创建删除 marker {}：{error}", path.display()))?;
    file.write_all(&raw)
        .map_err(|error| format!("无法写入删除 marker：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("无法同步删除 marker：{error}"))?;
    Ok(())
}

fn read_marker(path: &Path) -> Result<TrashMarker, String> {
    let mut raw = Vec::new();
    File::open(path)
        .map_err(|error| format!("无法打开删除 marker：{error}"))?
        .read_to_end(&mut raw)
        .map_err(|error| format!("无法读取删除 marker：{error}"))?;
    serde_json::from_slice(&raw).map_err(|error| format!("删除 marker 损坏：{error}"))
}

fn marker_name_for(payload: &Path) -> String {
    payload
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(PAYLOAD_PREFIX))
        .map(|suffix| format!("{MARKER_PREFIX}{suffix}"))
        .unwrap_or_else(|| format!("{MARKER_PREFIX}unknown"))
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("无法删除 {}：{error}", path.display())),
    }
}

fn remove_dir_if_exists(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("无法检查 trash {}：{error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "拒绝清理符号链接 trash payload：{}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!("trash payload 不是目录：{}", path.display()));
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("无法清理 trash {}：{error}", path.display())),
    }
}

fn remove_empty_tree(path: &Path, stop_at: &Path) -> Result<(), String> {
    let mut current = Some(path.to_path_buf());
    while let Some(dir) = current {
        if dir == stop_at || !dir.starts_with(stop_at) {
            break;
        }
        match fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("拒绝清理符号链接 trash 目录：{}", dir.display()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = dir.parent().map(Path::to_path_buf);
                continue;
            }
            Err(error) => {
                return Err(format!("无法检查 trash 目录 {}：{error}", dir.display()));
            }
        }
        match fs::remove_dir(&dir) {
            Ok(()) => current = dir.parent().map(Path::to_path_buf),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = dir.parent().map(Path::to_path_buf)
            }
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => break,
            Err(error) => return Err(format!("无法清理空 trash 目录 {}：{error}", dir.display())),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("无法同步本地目录 {}：{error}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ylx_transfer_core::persistence::{AppLibraryPayload, AppStore, UploadJobSpec};

    struct TestDir(PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl TestDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    fn store_and_root() -> (TestDir, AppStore, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("ylx-delete-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&path).unwrap();
        let dir = TestDir(path);
        let store = AppStore::open(dir.path().join("app-state.sqlite3")).unwrap();
        let root = dir.path().join("library");
        fs::create_dir_all(&root).unwrap();
        (dir, store, root)
    }

    #[test]
    fn interrupted_upload_cancellation_releases_its_lease_for_delete_and_new_upload() {
        let (_dir, store, _root) = store_and_root();
        let transfer_path = store
            .path()
            .parent()
            .unwrap()
            .join("transfer_store.sqlite3");
        let spec = UploadJobSpec::new("device|session", "rev-1", "digest-1").unwrap();
        let created = {
            let mut transfer = TransferStore::open(&transfer_path).unwrap();
            transfer
                .create_upload_job("upload-crashed", &spec, "t0")
                .unwrap()
        };
        store
            .acquire_operation_leases(
                "upload-crashed",
                &["device|session".to_string()],
                "upload",
                "t0",
            )
            .unwrap();

        assert_eq!(reconcile_upload_leases(&store).unwrap(), 0);
        assert_eq!(store.list_operation_leases().unwrap().len(), 1);

        {
            let mut transfer = TransferStore::open(&transfer_path).unwrap();
            let version = transfer
                .start_upload_job("upload-crashed", created.job().state_version, "t1")
                .unwrap();
            transfer
                .cancel_upload_job("upload-crashed", version, "t2")
                .unwrap();
        }

        assert_eq!(reconcile_upload_leases(&store).unwrap(), 1);
        assert!(store.list_operation_leases().unwrap().is_empty());
    }

    #[test]
    fn rename_commit_and_cleanup_are_atomic_from_the_callers_view() {
        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();
        let entry = DeleteEntry {
            key: "device|session".to_string(),
            device_id: "device".to_string(),
            session_id: "session".to_string(),
        };
        let outcome = delete_entries(&store, &root, 1, &[entry.clone(), entry]).unwrap();
        assert_eq!(outcome.committed_revision, 2);
        assert!(!source.exists());
        assert!(store.list_library_delete_intents().unwrap().is_empty());
        assert!(store.load().unwrap().library.is_empty());

        // A retry after the first commit is a no-op: it must not advance the
        // snapshot revision again, and it must still converge its marker.
        let retry = delete_entries(
            &store,
            &root,
            outcome.committed_revision,
            &[DeleteEntry {
                key: "device|session".to_string(),
                device_id: "device".to_string(),
                session_id: "session".to_string(),
            }],
        )
        .unwrap();
        assert_eq!(retry.committed_revision, outcome.committed_revision);
        assert_eq!(store.load().unwrap().revision, outcome.committed_revision);
        assert!(store.list_library_delete_intents().unwrap().is_empty());
    }

    #[test]
    fn stale_revision_restores_the_renamed_directory() {
        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();
        let error = delete_entries(
            &store,
            &root,
            0,
            &[DeleteEntry {
                key: "device|session".to_string(),
                device_id: "device".to_string(),
                session_id: "session".to_string(),
            }],
        )
        .unwrap_err();
        assert!(error.contains("已恢复本地文件"));
        assert!(source.join("video.mp4").exists());
        assert!(store.load().unwrap().library.len() == 1);
    }

    #[test]
    fn staged_intent_recovery_rolls_back_after_a_simulated_crash() {
        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();
        let op = "delete-crash";
        store
            .acquire_operation_leases(op, &["device|session".to_string()], "delete", "now")
            .unwrap();
        let staged = stage_entries(
            &root,
            op,
            &[DeleteEntry {
                key: "device|session".to_string(),
                device_id: "device".to_string(),
                session_id: "session".to_string(),
            }],
        )
        .unwrap();
        store
            .record_library_delete_intents(&[LibraryDeleteIntent {
                operation_id: op.to_string(),
                entry_key: "device|session".to_string(),
                source_path: staged[0].source_path.clone(),
                trash_path: staged[0].trash_path.clone(),
                expected_revision: 1,
                state: LibraryDeleteIntentState::Staged,
                created_at: "now".to_string(),
            }])
            .unwrap();
        recover_pending_deletes(&store, &root).unwrap();
        assert!(source.join("video.mp4").exists());
        assert!(store.list_library_delete_intents().unwrap().is_empty());
    }

    #[test]
    fn malformed_intent_trash_path_fails_closed_before_any_move() {
        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();
        let operation_id = "delete-malformed";
        store
            .acquire_operation_leases(
                operation_id,
                &["device|session".to_string()],
                "delete",
                "now",
            )
            .unwrap();
        store
            .record_library_delete_intents(&[LibraryDeleteIntent {
                operation_id: operation_id.to_string(),
                entry_key: "device|session".to_string(),
                source_path: source.clone(),
                trash_path: root.join("unrelated").join("payload-0"),
                expected_revision: 1,
                state: LibraryDeleteIntentState::Staged,
                created_at: "now".to_string(),
            }])
            .unwrap();

        let error = recover_pending_deletes(&store, &root).unwrap_err();
        assert!(error.contains("trash 路径"));
        assert!(source.exists());
        assert_eq!(store.list_library_delete_intents().unwrap().len(), 1);
    }

    #[test]
    fn rename_before_intent_is_recovered_from_the_trash_marker() {
        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        let staged = stage_entries(
            &root,
            "delete-marker-crash",
            &[DeleteEntry {
                key: "device|session".to_string(),
                device_id: "device".to_string(),
                session_id: "session".to_string(),
            }],
        )
        .unwrap();
        assert!(!source.exists());
        assert!(staged[0].marker_path.exists());
        recover_pending_deletes(&store, &root).unwrap();
        assert!(source.join("video.mp4").exists());
        let trash_root = root.join(TRASH_DIR_NAME);
        assert!(trash_root.is_dir());
        assert_eq!(fs::read_dir(trash_root).unwrap().count(), 0);
    }

    #[test]
    fn committed_intent_recovery_finalizes_without_reinserting_metadata() {
        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();
        let operation_id = "delete-committed-crash";
        store
            .acquire_operation_leases(
                operation_id,
                &["device|session".to_string()],
                "delete",
                "now",
            )
            .unwrap();
        let staged = stage_entries(
            &root,
            operation_id,
            &[DeleteEntry {
                key: "device|session".to_string(),
                device_id: "device".to_string(),
                session_id: "session".to_string(),
            }],
        )
        .unwrap();
        store
            .record_library_delete_intents(&[LibraryDeleteIntent {
                operation_id: operation_id.to_string(),
                entry_key: "device|session".to_string(),
                source_path: staged[0].source_path.clone(),
                trash_path: staged[0].trash_path.clone(),
                expected_revision: 1,
                state: LibraryDeleteIntentState::Staged,
                created_at: "now".to_string(),
            }])
            .unwrap();
        store
            .commit_library_delete_if_revision(1, operation_id, &["device|session".to_string()])
            .unwrap();
        assert!(!source.exists());
        recover_pending_deletes(&store, &root).unwrap();
        assert!(!source.exists());
        assert!(store.load().unwrap().library.is_empty());
        assert!(store.list_library_delete_intents().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_session_directory_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let (_dir, store, root) = store_and_root();
        let outside = root.parent().unwrap().join("outside-session");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("video.mp4"), b"bytes").unwrap();
        let device = root.join("device");
        fs::create_dir_all(&device).unwrap();
        symlink(&outside, device.join("session")).unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();
        let error = delete_entries(
            &store,
            &root,
            1,
            &[DeleteEntry {
                key: "device|session".to_string(),
                device_id: "device".to_string(),
                session_id: "session".to_string(),
            }],
        )
        .unwrap_err();
        assert!(error.contains("符号链接"));
        assert!(outside.join("video.mp4").exists());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_library_root_is_rejected_without_leaking_a_lease() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, store, root) = store_and_root();
        let source = root.join("device").join("session");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        store
            .save(
                &[AppLibraryPayload {
                    entry_key: "device|session".to_string(),
                    payload: b"entry".to_vec(),
                }],
                b"storage",
            )
            .unwrap();

        let original_mode = fs::metadata(&root).unwrap().permissions().mode();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
        // Privileged test runners can still create files in a mode-0555
        // directory. In that environment this capability test is skipped.
        let probe = root.join(".write-probe");
        let permission_denied = match OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(_) => {
                let _ = fs::remove_file(&probe);
                false
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => true,
            Err(error) => panic!("unexpected read-only probe error: {error}"),
        };
        if permission_denied {
            let error = delete_entries(
                &store,
                &root,
                1,
                &[DeleteEntry {
                    key: "device|session".to_string(),
                    device_id: "device".to_string(),
                    session_id: "session".to_string(),
                }],
            )
            .unwrap_err();
            assert!(error.contains("无法创建资料库 trash"));
            assert!(store.list_operation_leases().unwrap().is_empty());
            assert!(source.join("video.mp4").exists());
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(original_mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cross_filesystem_rename_is_refused_without_copying() {
        let source_root = std::env::temp_dir().join(format!(
            "ylx-delete-cross-source-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&source_root).unwrap();
        let target_parent = PathBuf::from("/dev/shm").join(format!(
            "ylx-delete-cross-target-{}",
            uuid::Uuid::new_v4().simple()
        ));
        if !target_parent
            .parent()
            .and_then(|parent| fs::metadata(parent).ok())
            .is_some_and(|metadata| metadata.is_dir())
        {
            let _ = fs::remove_dir_all(&source_root);
            return;
        }
        if let Err(error) = fs::create_dir_all(&target_parent) {
            let _ = fs::remove_dir_all(&source_root);
            if error.kind() == io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("unable to create cross-filesystem test directory: {error}");
        }
        let source = source_root.join("session");
        let target = target_parent.join("payload");
        let source_device = fs::metadata(&source_root).unwrap().dev();
        let target_device = fs::metadata(&target_parent).unwrap().dev();
        if source_device == target_device {
            let _ = fs::remove_dir_all(&source_root);
            let _ = fs::remove_dir_all(&target_parent);
            return;
        }
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("video.mp4"), b"bytes").unwrap();
        let error = ensure_same_filesystem(&source, &target).unwrap_err();
        assert!(error.contains("跨文件系统"));
        assert!(source.join("video.mp4").exists());
        assert!(!target.exists());
        let _ = fs::remove_dir_all(&source_root);
        let _ = fs::remove_dir_all(&target_parent);
    }
}
