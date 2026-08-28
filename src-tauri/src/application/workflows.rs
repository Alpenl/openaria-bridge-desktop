//! Domain workflows owned by [`TransferApplication`].
//!
//! The Tauri command module is deliberately only an input/output adapter. All
//! state snapshots, persistence, filesystem checks, network calls, and worker
//! boundaries live here so they can be exercised without invoking a command.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use tauri::AppHandle;
use ylx_transfer_core::persistence::transfer_store::OperationKind;

use crate::application::{
    BatchItemResult, BatchJobItemResult, BatchJobResult, DownloadedCleanupFailure,
    DownloadedCleanupItem, DownloadedCleanupPreview, DownloadedCleanupResult,
    DownloadedCleanupSkipDetail, LibraryMutationResult, Revisioned, RpcError,
    SessionMutationResult, TransferApplication,
};
use crate::composition;
use crate::models::{
    LibraryEntry, SaveStorageConfigInput, SessionView, StorageConfig, StorageConfigView,
};
use crate::state::AppData;

#[cfg(feature = "demo")]
use crate::models::{DeviceState, TransferDirection, TransferState};
#[cfg(feature = "demo")]
use crate::sim::{self, DemoTransferContext, StartTransferArgs};

#[derive(Debug, PartialEq, Eq)]
enum CredentialUpdate {
    Keep,
    Replace {
        access_key: String,
        secret_key: String,
    },
}

async fn run_blocking<T, F>(operation: &str, task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| format!("内部错误（{operation}任务异常终止）：{error}"))?
}

fn unique_items(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

fn item_error(
    code: &'static str,
    message: impl Into<String>,
    retryable: bool,
    details: serde_json::Value,
) -> RpcError {
    RpcError::new(code, message, retryable, Some(details))
}

impl TransferApplication {
    pub fn active_library_root(&self) -> PathBuf {
        self.0.composition.library_root()
    }

    pub fn set_notifications_enabled(&self, enabled: bool) -> bool {
        let mut data = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        data.notify_enabled = enabled;
        enabled
    }

    pub fn set_notifications_enabled_with_app(
        &self,
        app: AppHandle,
        enabled: bool,
    ) -> Result<bool, String> {
        use tauri_plugin_notification::{NotificationExt, PermissionState};

        if !enabled {
            return Ok(self.set_notifications_enabled(false));
        }
        let granted = match app
            .notification()
            .permission_state()
            .map_err(|error| error.to_string())?
        {
            PermissionState::Granted => true,
            _ => matches!(
                app.notification().request_permission(),
                Ok(PermissionState::Granted)
            ),
        };
        Ok(self.set_notifications_enabled(granted))
    }

    pub async fn connect_device(
        &self,
        app: AppHandle,
        device_id: String,
    ) -> Result<String, String> {
        #[cfg(feature = "demo")]
        {
            let is_demo = {
                let data = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                data.devices
                    .iter()
                    .any(|device| device.id == device_id && device.state != DeviceState::Offline)
            };
            if is_demo {
                let attempt_id = format!("demo-{device_id}");
                tauri::async_runtime::spawn(sim::run_pairing(app, device_id, attempt_id.clone()));
                return Ok(attempt_id);
            }
        }
        composition::connect_device(self.0.composition.clone(), app, device_id).await
    }

    pub async fn cancel_pairing(
        &self,
        device_id: String,
        attempt_id: String,
    ) -> Result<(), String> {
        #[cfg(feature = "demo")]
        {
            let handled = {
                let mut data = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match data
                    .devices
                    .iter_mut()
                    .find(|device| device.id == device_id)
                {
                    Some(device) => {
                        if device.state == DeviceState::Pending {
                            device.state = DeviceState::Idle;
                        }
                        true
                    }
                    None => false,
                }
            };
            if handled {
                if let Ok(devices) = self.try_devices() {
                    self.publish_devices(devices);
                }
                return Ok(());
            }
        }
        composition::cancel_pairing(self.0.composition.clone(), device_id, attempt_id).await?;
        if let Ok(devices) = self.try_devices() {
            self.publish_devices(devices);
        }
        Ok(())
    }

    pub async fn add_manual_device(
        &self,
        ip: String,
    ) -> Result<Revisioned<crate::models::Device>, String> {
        let composition = self.0.composition.clone();
        let device = run_blocking("手动设备 TLS 探测", move || {
            composition.add_manual_device(ip)
        })
        .await?;
        self.publish_added_device(device)
    }

    fn publish_added_device(
        &self,
        device: crate::models::Device,
    ) -> Result<Revisioned<crate::models::Device>, String> {
        let devices = self.try_devices()?;
        let publication = self.publish_devices(devices);
        Ok(Revisioned::new(publication.revision, device))
    }

    pub async fn disconnect_device(&self, device_id: String) -> Result<(), String> {
        #[cfg(feature = "demo")]
        {
            let handled = {
                let mut data = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match data
                    .devices
                    .iter_mut()
                    .find(|device| device.id == device_id)
                {
                    Some(device) => {
                        device.state = DeviceState::Idle;
                        true
                    }
                    None => false,
                }
            };
            if handled {
                if let Ok(devices) = self.try_devices() {
                    self.publish_devices(devices);
                }
                return Ok(());
            }
        }
        let composition = self.0.composition.clone();
        run_blocking("断开设备连接", move || {
            composition::disconnect_device(&composition, &device_id);
            Ok(())
        })
        .await?;
        if let Ok(devices) = self.try_devices() {
            self.publish_devices(devices);
        }
        Ok(())
    }

    /// Sessions are intentionally absent from the startup snapshot. This is
    /// the sole effectful read: fetch without the publication lock, then
    /// publish and return that exact device-scoped value and revision.
    pub async fn list_sessions(
        &self,
        device_id: String,
    ) -> Result<Revisioned<Vec<SessionView>>, String> {
        let (device_id, session_operation) = self.acquire_session_operation(&device_id).await?;
        let application = self.clone();
        run_blocking("刷新设备会话", move || {
            let _session_operation = session_operation;
            let sessions = application.list_sessions_sync(&device_id)?;
            let publication = application.publish_sessions(&device_id, sessions.clone());
            Ok(Revisioned::new(publication.revision, sessions))
        })
        .await
    }

    fn list_sessions_sync(&self, device_id: &str) -> Result<Vec<SessionView>, String> {
        let data = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        #[cfg(feature = "demo")]
        if data.sessions.contains_key(device_id) {
            return Ok(data.session_views(device_id));
        }
        let composition = data.composition.clone();
        let library = data.library.clone();
        drop(data);
        composition.list_sessions_with_local_state(device_id, &library)
    }

    pub async fn delete_sessions(
        &self,
        device_id: String,
        session_ids: Vec<String>,
    ) -> Result<Revisioned<SessionMutationResult>, String> {
        let (device_id, session_operation) = self.acquire_session_operation(&device_id).await?;
        let application = self.clone();
        let device_id_for_mutation = device_id.clone();
        let result = run_blocking("删除 Pi 会话", move || {
            let _session_operation = session_operation;
            let result = application.delete_sessions_sync(device_id_for_mutation, session_ids);
            Ok(application.revision_session_mutation(&device_id, result))
        })
        .await?;
        Ok(result)
    }

    fn delete_sessions_sync(
        &self,
        device_id: String,
        session_ids: Vec<String>,
    ) -> SessionMutationResult {
        let session_ids = unique_items(session_ids);
        #[cfg(feature = "demo")]
        {
            let mut data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if data.sessions.contains_key(&device_id) {
                let existing = data
                    .sessions
                    .get(&device_id)
                    .into_iter()
                    .flatten()
                    .map(|session| session.id.clone())
                    .collect::<HashSet<_>>();
                if let Some(list) = data.sessions.get_mut(&device_id) {
                    list.retain(|session| !session_ids.contains(&session.id));
                }
                let results = session_ids
                    .into_iter()
                    .map(|item| {
                        if existing.contains(&item) {
                            BatchItemResult::success(item)
                        } else {
                            let error = item_error(
                                "session_not_found",
                                "未找到该会话",
                                false,
                                serde_json::json!({
                                    "deviceId": device_id,
                                    "sessionId": item,
                                }),
                            );
                            BatchItemResult::failure(item, error)
                        }
                    })
                    .collect();
                return SessionMutationResult {
                    results,
                    sessions: Some(data.session_views(&device_id)),
                    operation_error: None,
                };
            }
        }
        let composition = {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            data.composition.clone()
        };
        let mut results = Vec::new();
        for session_id in session_ids {
            match composition.delete_session(&device_id, &session_id) {
                Ok(()) => results.push(BatchItemResult::success(session_id)),
                Err(message) => {
                    let error = item_error(
                        "session_delete_failed",
                        message,
                        false,
                        serde_json::json!({
                            "deviceId": device_id,
                            "sessionId": session_id,
                        }),
                    );
                    results.push(BatchItemResult::failure(session_id, error));
                }
            }
        }
        let library = {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            data.library.clone()
        };
        let (sessions, operation_error) =
            match composition.list_sessions_with_local_state(&device_id, &library) {
                Ok(sessions) => (Some(sessions), None),
                Err(message) => (
                    None,
                    Some(item_error(
                        "session_refresh_failed",
                        format!("删除完成，但刷新设备会话失败：{message}"),
                        true,
                        serde_json::json!({
                            "deviceId": device_id,
                            "cause": message,
                        }),
                    )),
                ),
            };
        SessionMutationResult {
            results,
            sessions,
            operation_error,
        }
    }

    pub async fn cleanup_backed_up(
        &self,
        device_id: String,
    ) -> Result<Revisioned<SessionMutationResult>, String> {
        let (device_id, session_operation) = self.acquire_session_operation(&device_id).await?;
        let application = self.clone();
        let device_id_for_mutation = device_id.clone();
        let result = run_blocking("清理 Pi 已备份会话", move || {
            let _session_operation = session_operation;
            let result = application.cleanup_backed_up_sync(device_id_for_mutation);
            Ok(application.revision_session_mutation(&device_id, result))
        })
        .await?;
        Ok(result)
    }

    fn cleanup_backed_up_sync(&self, device_id: String) -> SessionMutationResult {
        #[cfg(feature = "demo")]
        {
            let mut data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if data.sessions.contains_key(&device_id) {
                let backed_up = data
                    .sessions
                    .get(&device_id)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|session| data.is_backed_up(&device_id, &session.id))
                    .map(|session| session.id)
                    .collect::<Vec<_>>();
                if let Some(list) = data.sessions.get_mut(&device_id) {
                    list.retain(|session| !backed_up.contains(&session.id));
                }
                return SessionMutationResult {
                    results: backed_up
                        .into_iter()
                        .map(BatchItemResult::success)
                        .collect(),
                    sessions: Some(data.session_views(&device_id)),
                    operation_error: None,
                };
            }
        }
        let (composition, library) = {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (data.composition.clone(), data.library.clone())
        };
        let plan = match composition.plan_downloaded_cleanup(&device_id, &library) {
            Ok(plan) => plan,
            Err(message) => {
                return SessionMutationResult {
                    results: Vec::new(),
                    sessions: None,
                    operation_error: Some(item_error(
                        "cleanup_catalog_unavailable",
                        format!("无法读取设备会话清单，未执行清理：{message}"),
                        true,
                        serde_json::json!({
                            "deviceId": device_id,
                            "cause": message,
                        }),
                    )),
                }
            }
        };
        let backed_up_revisions = plan
            .sessions
            .iter()
            .filter(|session| session.backed_up)
            .map(|session| (session.session.id.clone(), session.session.revision.clone()))
            .collect::<HashSet<_>>();
        let candidates = plan
            .eligible
            .into_iter()
            .filter(|candidate| {
                backed_up_revisions
                    .contains(&(candidate.session_id.clone(), candidate.revision.clone()))
            })
            .collect::<Vec<_>>();
        let mut results = Vec::new();
        for candidate in candidates {
            let session_id = candidate.session_id.clone();
            let current_library = {
                let data = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                data.library.clone()
            };
            match composition.delete_backed_up_candidate(&device_id, &candidate, &current_library) {
                Ok(()) => results.push(BatchItemResult::success(session_id)),
                Err(message) => {
                    let error = item_error(
                        "session_delete_failed",
                        message.clone(),
                        false,
                        serde_json::json!({
                            "deviceId": device_id,
                            "sessionId": session_id,
                            "revision": candidate.revision,
                            "cause": message,
                        }),
                    );
                    results.push(BatchItemResult::failure(session_id, error));
                }
            }
        }
        let library = {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            data.library.clone()
        };
        let (sessions, operation_error) =
            match composition.list_sessions_with_local_state(&device_id, &library) {
                Ok(sessions) => (Some(sessions), None),
                Err(message) => (
                    None,
                    Some(item_error(
                        "session_refresh_failed",
                        format!("清理完成，但刷新设备会话失败：{message}"),
                        true,
                        serde_json::json!({
                            "deviceId": device_id,
                            "cause": message,
                        }),
                    )),
                ),
            };
        SessionMutationResult {
            results,
            sessions,
            operation_error,
        }
    }

    pub async fn preview_downloaded_cleanup(
        &self,
        device_id: String,
    ) -> Result<DownloadedCleanupPreview, String> {
        let (device_id, session_operation) = self.acquire_session_operation(&device_id).await?;
        let application = self.clone();
        run_blocking("预览 Pi 清理任务", move || {
            let _session_operation = session_operation;
            let (composition, library) = application.cleanup_snapshot();
            let plan = composition.plan_downloaded_cleanup(&device_id, &library)?;
            Ok(DownloadedCleanupPreview {
                eligible: plan.eligible.iter().map(downloaded_cleanup_item).collect(),
                skipped: plan.skipped.iter().map(downloaded_cleanup_skip).collect(),
                eligible_bytes: plan.eligible_bytes,
            })
        })
        .await
    }

    pub async fn cleanup_downloaded(
        &self,
        device_id: String,
    ) -> Result<Revisioned<DownloadedCleanupResult>, String> {
        let (device_id, session_operation) = self.acquire_session_operation(&device_id).await?;
        let application = self.clone();
        let device_id_for_mutation = device_id.clone();
        let result = run_blocking("执行 Pi 清理任务", move || {
            let _session_operation = session_operation;
            let (composition, library) = application.cleanup_snapshot();
            let mut plan =
                composition.plan_downloaded_cleanup(&device_id_for_mutation, &library)?;
            let eligible = plan
                .eligible
                .iter()
                .map(downloaded_cleanup_item)
                .collect::<Vec<_>>();
            let mut deleted = Vec::new();
            let mut failed = Vec::new();
            let mut skipped = plan
                .skipped
                .iter()
                .map(downloaded_cleanup_skip)
                .collect::<Vec<_>>();
            for candidate in &plan.eligible {
                if let Err(reason) =
                    composition.revalidate_downloaded_candidate(&device_id_for_mutation, candidate)
                {
                    skipped.push(DownloadedCleanupSkipDetail {
                        session_id: candidate.session_id.clone(),
                        date_label: candidate.date_label.clone(),
                        bytes: candidate.bytes,
                        reason,
                    });
                    continue;
                }
                match composition.delete_downloaded_candidate(&device_id_for_mutation, candidate) {
                    Ok(()) => deleted.push(downloaded_cleanup_item(candidate)),
                    Err(message) => {
                        failed.push(DownloadedCleanupFailure {
                            session_id: candidate.session_id.clone(),
                            error: item_error(
                                "downloaded_cleanup_delete_failed",
                                message.clone(),
                                false,
                                serde_json::json!({
                                    "deviceId": device_id_for_mutation,
                                    "sessionId": candidate.session_id,
                                    "cause": message,
                                }),
                            ),
                        });
                    }
                }
            }
            let deleted_ids = deleted
                .iter()
                .map(|item| item.session_id.as_str())
                .collect::<HashSet<_>>();
            plan.sessions
                .retain(|session| !deleted_ids.contains(session.session.id.as_str()));
            let result = DownloadedCleanupResult {
                eligible,
                deleted,
                failed,
                skipped,
                sessions: plan.sessions,
            };
            let publication = application.publish_sessions(&device_id, result.sessions.clone());
            Ok(Revisioned::new(publication.revision, result))
        })
        .await?;
        Ok(result)
    }

    fn revision_session_mutation(
        &self,
        device_id: &str,
        result: SessionMutationResult,
    ) -> Revisioned<SessionMutationResult> {
        let revision = match result.sessions.as_ref() {
            Some(sessions) => self.publish_sessions(device_id, sessions.clone()).revision,
            None => self.advance_session_revision(device_id),
        };
        Revisioned::new(revision, result)
    }

    fn cleanup_snapshot(&self) -> (std::sync::Arc<composition::Composition>, Vec<LibraryEntry>) {
        let data = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (data.composition.clone(), data.library.clone())
    }

    pub async fn remove_library_entries(
        &self,
        keys: Vec<String>,
    ) -> Result<Revisioned<LibraryMutationResult>, String> {
        let application = self.clone();
        let result = run_blocking("删除本地资料库文件", move || {
            Ok(application.remove_library_entries_sync(keys))
        })
        .await?;
        let publication = self.publish_library(result.library.clone());
        Ok(Revisioned::new(publication.revision, result))
    }

    fn remove_library_entries_sync(&self, keys: Vec<String>) -> LibraryMutationResult {
        enum DeleteBatchError {
            Busy(String),
            Failed(String),
        }

        let keys = unique_items(keys);
        let mut results = Vec::new();
        let (library_root, expected_revision, store_path, candidates) = {
            let mut data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let library_root = data.composition.library_root();
            let expected_revision = data.store_revision();
            let store_path = data.app_store().path().to_path_buf();
            let mut candidates = Vec::new();
            let mut candidate_keys = Vec::new();
            for key in keys {
                let entry = data
                    .library
                    .iter()
                    .find(|entry| entry.key() == key)
                    .cloned();
                let Some(entry) = entry else {
                    results.push(BatchItemResult::success(key));
                    continue;
                };
                candidates.push(crate::library_delete::DeleteEntry::from_library(&entry));
                candidate_keys.push(key);
            }
            if let Err(message) = data.claim_library_delete_keys(&candidate_keys) {
                results.extend(candidate_keys.into_iter().map(|item| {
                    BatchItemResult::failure(
                        item.clone(),
                        item_error(
                            "library_delete_busy",
                            message.clone(),
                            true,
                            serde_json::json!({
                                "key": item,
                                "cause": message,
                            }),
                        ),
                    )
                }));
                candidates.clear();
            }
            (library_root, expected_revision, store_path, candidates)
        };
        let candidate_keys = candidates
            .iter()
            .map(|entry| entry.key.clone())
            .collect::<Vec<_>>();
        if !candidates.is_empty() {
            let result = (|| -> Result<crate::library_delete::DeleteOutcome, DeleteBatchError> {
                let store = ylx_transfer_core::persistence::AppStore::open(&store_path).map_err(
                    |error| DeleteBatchError::Failed(format!("无法打开本地资料库存储：{error}")),
                )?;
                for key in &candidate_keys {
                    if let Some(reason) = crate::library_delete::entry_busy_reason(&store, key)
                        .map_err(DeleteBatchError::Failed)?
                    {
                        return Err(DeleteBatchError::Busy(reason));
                    }
                }
                crate::library_delete::delete_entries(
                    &store,
                    &library_root,
                    expected_revision,
                    &candidates,
                )
                .map_err(DeleteBatchError::Failed)
            })();
            match result {
                Ok(outcome) => {
                    let mut data = self
                        .0
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    data.library
                        .retain(|entry| !candidate_keys.iter().any(|key| key == &entry.key()));
                    data.set_store_revision(outcome.committed_revision);
                    data.release_library_delete_keys(&candidate_keys);
                    results.extend(candidate_keys.iter().cloned().map(BatchItemResult::success));
                }
                Err(error) => {
                    let mut data = self
                        .0
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    data.release_library_delete_keys(&candidate_keys);
                    let (code, message, retryable) = match error {
                        DeleteBatchError::Busy(message) => ("library_delete_busy", message, true),
                        DeleteBatchError::Failed(message) => {
                            ("library_delete_failed", message, false)
                        }
                    };
                    results.extend(candidate_keys.into_iter().map(|item| {
                        BatchItemResult::failure(
                            item.clone(),
                            item_error(
                                code,
                                message.clone(),
                                retryable,
                                serde_json::json!({
                                    "key": item,
                                    "cause": message,
                                }),
                            ),
                        )
                    }));
                }
            }
        }
        let durable_library = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .library
            .clone();
        let library = composition::project_library_entries(&library_root, &durable_library)
            .into_iter()
            .map(|entry| entry.view())
            .collect();
        LibraryMutationResult { results, library }
    }

    pub async fn reveal_library_file(&self, key: String, file_id: String) -> Result<(), String> {
        let application = self.clone();
        run_blocking("在文件管理器中定位文件", move || {
            let (library_root, entry) = {
                let data = application
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let entry = data
                    .library
                    .iter()
                    .find(|entry| entry.key() == key)
                    .cloned()
                    .ok_or_else(|| "未找到该本地记录".to_string())?;
                (data.composition.library_root(), entry)
            };
            let path = checked_library_file_path(&library_root, &entry, &file_id)?;
            open_in_file_manager(&path)
        })
        .await
    }

    pub async fn download_session(
        &self,
        app: AppHandle,
        device_id: String,
        session_id: String,
    ) -> Result<String, String> {
        let application = self.clone();
        run_blocking("创建会话下载任务", move || {
            application.download_session_sync(&app, device_id, session_id)
        })
        .await
    }

    fn download_session_sync(
        &self,
        app: &AppHandle,
        device_id: String,
        session_id: String,
    ) -> Result<String, String> {
        #[cfg(feature = "demo")]
        {
            let session = {
                let data = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                data.sessions.get(&device_id).and_then(|sessions| {
                    sessions
                        .iter()
                        .find(|session| session.id == session_id)
                        .cloned()
                })
            };
            if let Some(session) = session {
                return Ok(sim::start_transfer(
                    app,
                    StartTransferArgs {
                        label: session.id.clone(),
                        total_bytes: session.video_bytes,
                        direction: TransferDirection::Down,
                        target_label: device_id.clone(),
                        context: DemoTransferContext::DownloadSession {
                            device_id,
                            session_id,
                        },
                    },
                ));
            }
        }
        #[cfg(not(feature = "demo"))]
        let _app = app;
        composition::download_session(&self.0.composition, &device_id, &session_id)
    }

    pub async fn download_sessions(
        &self,
        app: AppHandle,
        device_id: String,
        session_ids: Vec<String>,
    ) -> Result<BatchJobResult, String> {
        let application = self.clone();
        run_blocking("批量创建会话下载任务", move || {
            let mut results = Vec::new();
            for session_id in unique_items(session_ids) {
                match application.download_session_sync(&app, device_id.clone(), session_id.clone())
                {
                    Ok(job_id) => results.push(BatchJobItemResult::success(session_id, job_id)),
                    Err(message) => {
                        let error = item_error(
                            "download_enqueue_failed",
                            message,
                            false,
                            serde_json::json!({
                                "deviceId": device_id,
                                "sessionId": session_id,
                            }),
                        );
                        results.push(BatchJobItemResult::failure(session_id, error));
                    }
                }
            }
            Ok(BatchJobResult { results })
        })
        .await
    }

    pub async fn download_file(
        &self,
        app: AppHandle,
        device_id: String,
        session_id: String,
        file_id: String,
    ) -> Result<String, String> {
        let application = self.clone();
        run_blocking("创建文件下载任务", move || {
            #[cfg(feature = "demo")]
            {
                let file = {
                    let data = application
                        .0
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    data.sessions
                        .get(&device_id)
                        .and_then(|sessions| {
                            sessions.iter().find(|session| session.id == session_id)
                        })
                        .and_then(|session| {
                            session.files.iter().find(|file| file.file_id == file_id)
                        })
                        .cloned()
                };
                if let Some(file) = file {
                    return Ok(sim::start_transfer(
                        &app,
                        StartTransferArgs {
                            label: format!("{session_id}/{file_id}"),
                            total_bytes: file.bytes,
                            direction: TransferDirection::Down,
                            target_label: device_id,
                            context: DemoTransferContext::DownloadFile,
                        },
                    ));
                }
            }
            #[cfg(not(feature = "demo"))]
            let _app = app;
            composition::download_file(
                &application.0.composition,
                &device_id,
                &session_id,
                &file_id,
            )
        })
        .await
    }

    pub async fn upload_entry(&self, app: AppHandle, key: String) -> Result<String, String> {
        let application = self.clone();
        run_blocking("创建对象存储上传任务", move || {
            application.upload_entry_sync(app, key)
        })
        .await
    }

    fn upload_entry_sync(&self, app: AppHandle, key: String) -> Result<String, String> {
        let (composition, storage, entry, app_store_path, transfer_store_path) = {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !data.storage.is_configured() {
                return Err("请先配置对象存储".to_string());
            }
            if data.library_delete_keys.contains(&key) {
                return Err("本地记录正在删除，请稍后重试".to_string());
            }
            let entry = data
                .library
                .iter()
                .find(|entry| entry.key() == key)
                .cloned();
            let Some(entry) = entry else {
                return Err("未找到该本地记录".to_string());
            };
            let app_store_path = data.app_store().path().to_path_buf();
            let transfer_store_path = data
                .app_store()
                .path()
                .parent()
                .ok_or_else(|| "application store path has no parent".to_string())?
                .join("transfer_store.sqlite3");
            (
                data.composition.clone(),
                data.storage.clone(),
                entry,
                app_store_path,
                transfer_store_path,
            )
        };
        let lease_store = ylx_transfer_core::persistence::AppStore::open(&app_store_path)
            .map_err(|error| format!("无法打开本地资料库存储：{error}"))?;
        let lease_id = crate::library_delete::acquire_upload_lease(&lease_store, &key)?;
        match composition::start_upload(app.clone(), composition, storage, entry) {
            Ok(composition::UploadStartOutcome::Started { transfer_key })
            | Ok(composition::UploadStartOutcome::Existing { transfer_key }) => {
                crate::library_delete::spawn_upload_lease_reaper(
                    app_store_path,
                    transfer_store_path,
                    lease_id,
                    transfer_key.clone(),
                );
                Ok(transfer_key)
            }
            Ok(composition::UploadStartOutcome::Conflict { active_revision }) => {
                crate::library_delete::release_upload_lease(&lease_store, &lease_id);
                Err(format!(
                    "该本地记录的另一个版本（revision {active_revision}）正在上传，请等待其结束后重试"
                ))
            }
            Err(error) => {
                crate::library_delete::release_upload_lease(&lease_store, &lease_id);
                Err(error)
            }
        }
    }

    pub async fn upload_entries(
        &self,
        app: AppHandle,
        keys: Vec<String>,
    ) -> Result<BatchJobResult, String> {
        let application = self.clone();
        run_blocking("批量创建对象存储上传任务", move || {
            let mut results = Vec::new();
            for key in unique_items(keys) {
                match application.upload_entry_sync(app.clone(), key.clone()) {
                    Ok(job_id) => results.push(BatchJobItemResult::success(key, job_id)),
                    Err(message) => {
                        let error = item_error(
                            "upload_enqueue_failed",
                            message,
                            false,
                            serde_json::json!({ "key": key }),
                        );
                        results.push(BatchJobItemResult::failure(key, error));
                    }
                }
            }
            Ok(BatchJobResult { results })
        })
        .await
    }

    pub async fn retry_transfer(&self, app: AppHandle, job_id: String) -> Result<String, String> {
        let application = self.clone();
        run_blocking("重试传输任务", move || {
            application.retry_transfer_sync(app, job_id)
        })
        .await
    }

    pub fn is_derived_upload_job(&self, job_id: &str) -> Result<bool, String> {
        self.0.composition.is_derived_upload_job(job_id)
    }

    fn retry_transfer_sync(&self, app: AppHandle, job_id: String) -> Result<String, String> {
        enum RetryTarget {
            Download,
            Upload {
                job_id: String,
                entry_key: String,
            },
            #[cfg(feature = "demo")]
            Demo,
        }
        let (composition, storage, app_store_path) = {
            let data = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                data.composition.clone(),
                data.storage.clone(),
                data.app_store().path().to_path_buf(),
            )
        };
        if composition.is_derived_upload_job(&job_id)? {
            return Err(
                "派生视频上传必须通过其会话流水线重试，不能使用资料库上传重试路径".to_string(),
            );
        }
        let target = match composition.stored_job(&job_id)? {
            Some(job) if job.operation_kind == OperationKind::Download => RetryTarget::Download,
            Some(job) if job.operation_kind == OperationKind::Upload => {
                let spec = composition
                    .stored_upload_job_spec(&job_id)?
                    .ok_or_else(|| "上传任务缺少 immutable spec，无法重试".to_string())?;
                RetryTarget::Upload {
                    job_id: job_id.clone(),
                    entry_key: spec.entry_key,
                }
            }
            Some(_) => return Err("无法识别该传输任务类型".to_string()),
            None => {
                #[cfg(feature = "demo")]
                {
                    let data = self
                        .0
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let retryable_demo = data.demo_transfer_state.contains(&job_id)
                        && data.demo_transfer_state.transfers().iter().any(|transfer| {
                            transfer.key == job_id && transfer.state == TransferState::Failed
                        });
                    if retryable_demo {
                        RetryTarget::Demo
                    } else {
                        return Err("未找到传输任务".to_string());
                    }
                }
                #[cfg(not(feature = "demo"))]
                return Err("未找到传输任务".to_string());
            }
        };
        match target {
            RetryTarget::Download => composition.retry_download(&job_id),
            RetryTarget::Upload { job_id, entry_key } => {
                {
                    let data = self
                        .0
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if data.library_delete_keys.contains(&entry_key) {
                        return Err("本地记录正在删除，请稍后重试".to_string());
                    }
                }
                let lease_store = ylx_transfer_core::persistence::AppStore::open(&app_store_path)
                    .map_err(|error| format!("无法打开本地资料库存储：{error}"))?;
                let lease_id =
                    crate::library_delete::acquire_upload_lease(&lease_store, &entry_key)?;
                let transfer_store_path = app_store_path
                    .parent()
                    .ok_or_else(|| "application store path has no parent".to_string())?
                    .join("transfer_store.sqlite3");
                match composition::retry_upload(app.clone(), composition, storage, &job_id) {
                    Ok(transfer_key) => {
                        crate::library_delete::spawn_upload_lease_reaper(
                            app_store_path,
                            transfer_store_path,
                            lease_id,
                            transfer_key.clone(),
                        );
                        Ok(transfer_key)
                    }
                    Err(error) => {
                        crate::library_delete::release_upload_lease(&lease_store, &lease_id);
                        Err(error)
                    }
                }
            }
            #[cfg(feature = "demo")]
            RetryTarget::Demo => {
                if sim::retry_transfer(&app, &job_id) {
                    Ok(job_id)
                } else {
                    Err("演示传输任务状态已变化，无法重试".to_string())
                }
            }
        }
    }

    pub async fn pause_transfer_job(&self, job_id: String) -> Result<(), String> {
        let composition = self.0.composition.clone();
        run_blocking("暂停下载任务", move || {
            composition::pause_transfer_job(&composition, &job_id)
        })
        .await
    }

    pub async fn resume_transfer_job(&self, job_id: String) -> Result<(), String> {
        let composition = self.0.composition.clone();
        run_blocking("恢复下载任务", move || {
            composition::resume_transfer_job(&composition, &job_id)
        })
        .await
    }

    pub async fn cancel_transfer_job(&self, job_id: String) -> Result<(), String> {
        let composition = self.0.composition.clone();
        run_blocking("取消下载任务", move || {
            composition::cancel_transfer_job(&composition, &job_id)
        })
        .await
    }

    pub async fn dismiss_transfer_job(&self, job_id: String) -> Result<(), String> {
        let composition = self.0.composition.clone();
        run_blocking("清除下载任务", move || {
            composition.dismiss_transfer_job(&job_id)
        })
        .await
    }

    pub async fn dismiss_upload_transfer(
        &self,
        app: AppHandle,
        job_id: String,
    ) -> Result<(), String> {
        let composition = self.0.composition.clone();
        run_blocking("清除上传任务", move || {
            composition::dismiss_upload_transfer(&app, &composition, &job_id)
        })
        .await
    }

    pub async fn cancel_upload(&self, app: AppHandle, job_id: String) -> Result<(), String> {
        let composition = self.0.composition.clone();
        run_blocking("取消上传任务", move || {
            composition::cancel_upload(&app, &composition, &job_id)
        })
        .await
    }

    pub fn normalize_download_root(raw: &str) -> Result<Option<String>, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let path = Path::new(trimmed);
        if !path.is_absolute() {
            return Err("下载目录必须是绝对路径".to_string());
        }
        match path.metadata() {
            Ok(metadata) if metadata.is_dir() => Ok(Some(trimmed.to_string())),
            Ok(_) => Err("下载目录已被一个同名文件占用".to_string()),
            Err(_) => match path.ancestors().skip(1).find(|ancestor| ancestor.exists()) {
                Some(existing) if existing.is_dir() => Ok(Some(trimmed.to_string())),
                _ => Err("下载目录不存在，且其上级目录也不存在".to_string()),
            },
        }
    }

    pub async fn validate_download_root(&self, raw: String) -> Result<Option<String>, String> {
        run_blocking("检查下载目录", move || {
            Self::normalize_download_root(&raw)
        })
        .await
    }

    fn default_download_root(&self) -> PathBuf {
        self.0.app_data_dir.join("library")
    }

    fn requested_download_root_path(&self, download_root: &Option<String>) -> PathBuf {
        download_root
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.default_download_root())
    }

    fn ensure_download_root_change_is_safe(
        root_is_changing: bool,
        has_library_entries: bool,
    ) -> Result<(), String> {
        if root_is_changing && has_library_entries {
            return Err(
                "本地数据不为空，无法切换下载目录。请先完成上传并清除本地数据，再修改保存位置"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn persist_download_root_change(
        data: &mut AppData,
        requested_active_root: PathBuf,
        new_storage: StorageConfig,
    ) -> Result<(), String> {
        let previous_storage = data.storage.clone();
        let previous_active_root = data.composition.library_root();
        let root_is_changing = previous_active_root != requested_active_root;
        Self::ensure_download_root_change_is_safe(root_is_changing, !data.library.is_empty())?;
        if root_is_changing {
            data.composition
                .switch_library_root(requested_active_root)?;
        }
        data.storage = new_storage;
        match data.persist_result() {
            Ok(()) => Ok(()),
            Err(error) => {
                data.storage = previous_storage;
                let rollback_error = if root_is_changing {
                    data.composition
                        .switch_library_root(previous_active_root)
                        .err()
                } else {
                    None
                };
                match rollback_error {
                    None => Err(error),
                    Some(rollback) => Err(format!("{error}；同时无法回滚本机保存位置：{rollback}")),
                }
            }
        }
    }

    pub async fn save_download_root(
        &self,
        raw_download_root: String,
    ) -> Result<Revisioned<StorageConfigView>, String> {
        let application = self.clone();
        run_blocking("保存本机保存位置", move || {
            application.save_download_root_sync(raw_download_root)
        })
        .await
    }

    fn save_download_root_sync(
        &self,
        raw_download_root: String,
    ) -> Result<Revisioned<StorageConfigView>, String> {
        let download_root = Self::normalize_download_root(&raw_download_root)?;
        let requested_active_root = self.requested_download_root_path(&download_root);
        let composition = self.0.composition.clone();
        let observed_revision = composition.settings_revision();
        let application = self.clone();
        composition.commit_settings(observed_revision, || {
            let mut data = application
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut new_storage = data.storage.clone();
            new_storage.download_root = download_root;
            Self::persist_download_root_change(&mut data, requested_active_root, new_storage)
        })?;
        let result = self.try_storage()?;
        let publication = self.publish_storage(result.clone());
        Ok(Revisioned::new(publication.revision, result))
    }

    fn plan_credential_update(
        raw_access_key: &str,
        raw_secret_key: String,
    ) -> Result<CredentialUpdate, String> {
        let access_key = raw_access_key.trim().to_string();
        let secret_key = raw_secret_key;
        if access_key.is_empty() && secret_key.trim().is_empty() {
            return Ok(CredentialUpdate::Keep);
        }
        if access_key.is_empty() || secret_key.trim().is_empty() {
            return Err("Access Key 与 Secret Key 必须同时填写".to_string());
        }
        Ok(CredentialUpdate::Replace {
            access_key,
            secret_key,
        })
    }

    pub async fn save_storage_config(
        &self,
        config: SaveStorageConfigInput,
    ) -> Result<Revisioned<StorageConfigView>, String> {
        let application = self.clone();
        run_blocking("保存对象存储设置", move || {
            application.save_storage_config_sync(config)
        })
        .await
    }

    fn save_storage_config_sync(
        &self,
        config: SaveStorageConfigInput,
    ) -> Result<Revisioned<StorageConfigView>, String> {
        let endpoint = config.endpoint.trim().to_string();
        let bucket = config.bucket.trim().to_string();
        let prefix = config.prefix.trim().to_string();
        if endpoint.is_empty() || bucket.is_empty() {
            return Err("Endpoint 和 Bucket 不能为空".to_string());
        }
        let download_root = Self::normalize_download_root(&config.download_root)?;
        let requested_active_root = self.requested_download_root_path(&download_root);
        let credential_update =
            Self::plan_credential_update(&config.access_key, config.secret_key)?;
        let composition = self.0.composition.clone();
        let observed_revision = composition.settings_revision();
        let new_storage = StorageConfig {
            endpoint,
            bucket,
            prefix,
            url_style: config.url_style,
            download_root,
        };
        let application = self.clone();
        composition.commit_settings(observed_revision, || {
            let credential_snapshot = match credential_update {
                CredentialUpdate::Keep => None,
                CredentialUpdate::Replace {
                    access_key,
                    secret_key,
                } => {
                    let snapshot = composition.storage_credential_snapshot().map_err(|error| {
                        format!("无法读取原对象存储密钥以准备原子更新：{error}")
                    })?;
                    composition
                        .set_storage_credential(access_key, secret_key)
                        .map_err(|error| format!("无法保存密钥到系统密钥环：{error}"))?;
                    Some(snapshot)
                }
            };
            let mut data = application
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match Self::persist_download_root_change(&mut data, requested_active_root, new_storage)
            {
                Ok(()) => Ok(()),
                Err(error) => {
                    drop(data);
                    let rollback_error = credential_snapshot.and_then(|snapshot| {
                        composition
                            .restore_storage_credential(snapshot)
                            .err()
                            .map(|rollback| rollback.to_string())
                    });
                    match rollback_error {
                        None => Err(format!("无法持久化对象存储配置：{error}")),
                        Some(rollback) => Err(format!(
                            "无法持久化对象存储配置：{error}；同时无法回滚系统密钥环：{rollback}"
                        )),
                    }
                }
            }
        })?;
        let storage = self.try_storage()?;
        let publication = self.publish_storage(storage.clone());
        Ok(Revisioned::new(publication.revision, storage))
    }

    pub async fn test_storage_connection(
        &self,
        config: SaveStorageConfigInput,
    ) -> Result<(), String> {
        let application = self.clone();
        run_blocking("对象存储连接测试", move || {
            application.test_storage_connection_sync(config)
        })
        .await
    }

    fn test_storage_connection_sync(&self, config: SaveStorageConfigInput) -> Result<(), String> {
        let endpoint = config.endpoint.trim().to_string();
        let bucket = config.bucket.trim().to_string();
        let prefix = config.prefix.trim().to_string();
        if endpoint.is_empty() || bucket.is_empty() {
            return Err("Endpoint 和 Bucket 不能为空".to_string());
        }
        let composition = self.0.composition.clone();
        let access_key = config.access_key.trim().to_string();
        let secret_key = config.secret_key;
        let credential = if access_key.is_empty() && secret_key.trim().is_empty() {
            composition
                .storage_credential()
                .map_err(|error| format!("无法读取对象存储密钥：{error}"))?
        } else {
            composition::StoredCredential::new(access_key, secret_key)?
        };
        composition::test_object_store_connection(
            &endpoint,
            &bucket,
            &prefix,
            config.url_style,
            &credential,
        )
    }
}

fn downloaded_cleanup_item(
    candidate: &composition::DownloadedCleanupCandidate,
) -> DownloadedCleanupItem {
    DownloadedCleanupItem {
        session_id: candidate.session_id.clone(),
        date_label: candidate.date_label.clone(),
        bytes: candidate.bytes,
    }
}

fn downloaded_cleanup_skip(
    skip: &composition::DownloadedCleanupSkip,
) -> DownloadedCleanupSkipDetail {
    DownloadedCleanupSkipDetail {
        session_id: skip.session_id.clone(),
        date_label: skip.date_label.clone(),
        bytes: skip.bytes,
        reason: skip.reason.clone(),
    }
}

fn checked_library_file_path(
    library_root: &Path,
    entry: &LibraryEntry,
    file_id: &str,
) -> Result<PathBuf, String> {
    let file = entry
        .display_files()
        .iter()
        .find(|file| file.file_id == file_id)
        .ok_or_else(|| "该文件不属于所选本地记录".to_string())?;
    composition::resolve_existing_download_path_for_entry(library_root, entry, file)
        .map(|(path, _)| path)
}

#[cfg(target_os = "linux")]
fn open_in_file_manager(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "本地文件缺少父目录".to_string())?;
    spawn_file_manager(Command::new("xdg-open").arg(parent))
}

#[cfg(target_os = "macos")]
fn open_in_file_manager(path: &Path) -> Result<(), String> {
    spawn_file_manager(Command::new("open").arg("-R").arg(path))
}

#[cfg(target_os = "windows")]
fn open_in_file_manager(path: &Path) -> Result<(), String> {
    spawn_file_manager(Command::new("explorer.exe").arg("/select,").arg(path))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn open_in_file_manager(_path: &Path) -> Result<(), String> {
    Err("当前平台不支持在文件管理器中定位".to_string())
}

fn spawn_file_manager(command: &mut Command) -> Result<(), String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动系统文件管理器：{error}"))?;
    std::thread::Builder::new()
        .name("ylx-file-manager-wait".to_string())
        .spawn(move || {
            let _ = child.wait();
        })
        .map_err(|error| format!("无法监控系统文件管理器进程：{error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "demo")]
    use crate::application::RecordingEventSink;
    use crate::models::SessionFile;
    #[cfg(feature = "demo")]
    use std::sync::Arc;

    fn test_application(label: &str) -> (PathBuf, TransferApplication) {
        let root = std::env::temp_dir().join(format!(
            "ylx-application-workflow-{label}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let app_data_dir = root.join("app-data");
        std::fs::create_dir_all(&app_data_dir).expect("create test app-data directory");
        let composition =
            crate::composition::Composition::new(app_data_dir.clone(), root.join("library"))
                .expect("create inert production composition");
        let app_store =
            ylx_transfer_core::persistence::AppStore::open(app_data_dir.join("app-state.sqlite3"))
                .expect("open test application store");
        let state = crate::state::AppState::for_test(
            composition.clone(),
            std::sync::Arc::new(app_store),
            Vec::new(),
            0,
        );
        let application =
            TransferApplication::new_with_app_data_dir(state.0.clone(), composition, app_data_dir)
                .expect("seed published application resources");
        (root, application)
    }

    fn unavailable_device_id() -> String {
        format!("ylx-{}", "a".repeat(64))
    }

    fn test_entry() -> LibraryEntry {
        LibraryEntry {
            device_id: "device-1".to_string(),
            session_id: "session-1".to_string(),
            date_label: "2026-08-03".to_string(),
            downloaded_at: "2026-08-03T12:00:00Z".to_string(),
            bytes: 4,
            processed_files: Vec::new(),
            files: vec![SessionFile::new(
                "file-1".to_string(),
                "video/left.mp4".to_string(),
                4,
                String::new(),
            )],
            complete: true,
            publication: None,
            library_root: None,
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: crate::models::UploadStatus::Done,
            upload_retryable: false,
            uploaded_at: None,
            upload_error: None,
        }
    }

    #[test]
    fn blank_credential_fields_keep_the_stored_secret() {
        assert_eq!(
            TransferApplication::plan_credential_update("", String::new()).unwrap(),
            CredentialUpdate::Keep
        );
        assert_eq!(
            TransferApplication::plan_credential_update("   ", "  ".to_string()).unwrap(),
            CredentialUpdate::Keep
        );
    }

    #[test]
    fn batch_inputs_are_deduplicated_without_reordering() {
        assert_eq!(
            unique_items(vec![
                "first".to_string(),
                "second".to_string(),
                "first".to_string(),
                "third".to_string(),
            ]),
            vec!["first", "second", "third"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_half_filled_credential_pair_is_rejected() {
        assert!(TransferApplication::plan_credential_update("AKIA", String::new()).is_err());
        assert!(TransferApplication::plan_credential_update("", "secret".to_string()).is_err());
    }

    #[test]
    fn a_complete_credential_pair_preserves_secret_whitespace() {
        assert_eq!(
            TransferApplication::plan_credential_update("  AKIA  ", " sec ret ".to_string())
                .unwrap(),
            CredentialUpdate::Replace {
                access_key: "AKIA".to_string(),
                secret_key: " sec ret ".to_string(),
            }
        );
    }

    #[test]
    fn download_root_validation_preserves_default_and_rejects_relative_paths() {
        assert_eq!(
            TransferApplication::normalize_download_root("").unwrap(),
            None
        );
        assert_eq!(
            TransferApplication::normalize_download_root("   ").unwrap(),
            None
        );
        assert!(TransferApplication::normalize_download_root("recordings").is_err());
    }

    #[test]
    fn download_root_change_is_rejected_when_the_library_is_not_empty() {
        assert!(TransferApplication::ensure_download_root_change_is_safe(true, true).is_err());
        assert!(TransferApplication::ensure_download_root_change_is_safe(true, false).is_ok());
        assert!(TransferApplication::ensure_download_root_change_is_safe(false, true).is_ok());
    }

    #[test]
    fn reveal_rejects_a_file_id_not_recorded_in_the_library_entry() {
        let error =
            checked_library_file_path(Path::new("/tmp/ylx-test-library"), &test_entry(), "file-2")
                .unwrap_err();
        assert_eq!(error, "该文件不属于所选本地记录");
    }

    #[test]
    fn reveal_accepts_the_processed_display_file() {
        let root = tempfile::tempdir().expect("library root");
        let mut entry = test_entry();
        entry.processed_files = vec![SessionFile::new(
            "processed-sbs-mp4".to_string(),
            "processed/sbs.mp4".to_string(),
            4,
            String::new(),
        )];
        let path = root
            .path()
            .join(&entry.device_id)
            .join(&entry.session_id)
            .join("processed/sbs.mp4");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"abcd").unwrap();

        let resolved = checked_library_file_path(root.path(), &entry, "processed-sbs-mp4")
            .expect("processed display file resolves");

        assert_eq!(resolved, path);
    }

    #[test]
    fn reveal_rejects_raw_segments_once_a_processed_display_file_exists() {
        let root = tempfile::tempdir().expect("library root");
        let mut entry = test_entry();
        entry.processed_files = vec![SessionFile::new(
            "processed-sbs-mp4".to_string(),
            "processed/sbs.mp4".to_string(),
            4,
            String::new(),
        )];

        let error = checked_library_file_path(root.path(), &entry, "file-1").unwrap_err();

        assert_eq!(error, "该文件不属于所选本地记录");
    }

    #[test]
    fn blocking_boundary_reports_worker_panics() {
        let panicking = || -> Result<(), String> { panic!("worker exploded") };
        let error = tauri::async_runtime::block_on(run_blocking("测试", panicking))
            .expect_err("a panicking worker must surface as an error");
        assert!(error.contains("测试"));
    }

    #[test]
    fn instantiated_application_rejects_an_unknown_pairing_device() {
        let (root, application) = test_application("cancel-pairing");
        let error = tauri::async_runtime::block_on(
            application.cancel_pairing(unavailable_device_id(), "attempt-not-active".to_string()),
        )
        .expect_err("an unknown device must fail before pairing-attempt lookup");
        assert!(error.contains("设备身份解析失败"), "{error}");

        drop(application);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn instantiated_application_rejects_an_unknown_session_delete_scope() {
        let (root, application) = test_application("delete-sessions");
        let device_id = unavailable_device_id();
        let error = tauri::async_runtime::block_on(application.delete_sessions(
            device_id.clone(),
            vec![
                "session-a".to_string(),
                "session-a".to_string(),
                "session-b".to_string(),
            ],
        ))
        .expect_err("an unknown device must fail before allocating a gate or doing network I/O");
        assert!(error.contains("设备身份解析失败"), "{error}");

        drop(application);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn instantiated_application_rejects_an_unknown_backed_up_cleanup_scope() {
        let (root, application) = test_application("cleanup-backed-up");
        let device_id = unavailable_device_id();
        let error =
            tauri::async_runtime::block_on(application.cleanup_backed_up(device_id.clone()))
                .expect_err("an unknown device must fail before catalog I/O");
        assert!(error.contains("设备身份解析失败"), "{error}");

        drop(application);
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(feature = "demo")]
    #[test]
    fn manual_device_response_and_full_device_event_share_one_revision() {
        let (root, application) = test_application("manual-device-revision");
        let device = application
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .devices[0]
            .clone();
        let sink = Arc::new(RecordingEventSink::default());
        let _subscription = application.subscribe(sink.clone());

        let response = application
            .publish_added_device(device.clone())
            .expect("publish complete device projection");
        let event = sink.events().pop().expect("devices update");

        assert_eq!(event.name, "devices:update");
        assert_eq!(event.payload["revision"], response.revision);
        assert_eq!(
            serde_json::to_value(&response.value).unwrap(),
            serde_json::to_value(device).unwrap()
        );
        assert!(event.payload["value"]
            .as_array()
            .expect("full device projection")
            .iter()
            .any(|item| item["id"] == response.value.id));

        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(feature = "demo")]
    #[test]
    fn session_refresh_response_and_event_share_the_device_revision() {
        let (root, application) = test_application("session-refresh-revision");
        let device_id = application
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sessions
            .keys()
            .next()
            .cloned()
            .expect("demo device with sessions");
        let sink = Arc::new(RecordingEventSink::default());
        let _subscription = application.subscribe(sink.clone());

        let response = tauri::async_runtime::block_on(application.list_sessions(device_id.clone()))
            .expect("refresh sessions");
        let event = sink.events().pop().expect("sessions update");

        assert_eq!(event.name, "sessions:update");
        assert_eq!(event.payload["revision"], response.revision);
        assert_eq!(event.payload["value"]["deviceId"], device_id);
        assert_eq!(
            event.payload["value"]["sessions"],
            serde_json::to_value(&response.value).unwrap()
        );

        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(feature = "demo")]
    #[test]
    fn session_mutation_response_and_event_share_the_device_revision() {
        let (root, application) = test_application("session-mutation-revision");
        let device_id = application
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sessions
            .keys()
            .next()
            .cloned()
            .expect("demo device with sessions");
        let sink = Arc::new(RecordingEventSink::default());
        let _subscription = application.subscribe(sink.clone());

        let response =
            tauri::async_runtime::block_on(application.cleanup_backed_up(device_id.clone()))
                .expect("return structured session mutation");
        let event = sink.events().pop().expect("sessions update");

        assert_eq!(event.name, "sessions:update");
        assert_eq!(event.payload["revision"], response.revision);
        assert_eq!(event.payload["value"]["deviceId"], device_id);
        assert_eq!(
            event.payload["value"]["sessions"],
            serde_json::to_value(response.value.sessions.expect("refreshed sessions")).unwrap()
        );

        std::fs::remove_dir_all(root).ok();
    }
}
