//! Thin Tauri adapters for the desktop RPC surface.
//!
//! Commands validate untrusted wire values, select the managed application
//! facade, and adapt its errors to [`RpcError`]. The application workflow
//! implementation lives in `application/workflows.rs`.

use std::net::IpAddr;

use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

use crate::application::{
    validate_batch, validate_string, ApplicationSnapshot, BatchJobResult, DownloadedCleanupPreview,
    DownloadedCleanupResult, LibraryMutationResult, Revisioned, RpcError, SessionMutationResult,
    TransferApplication,
};
use crate::media::MediaApplication;
use crate::models::{
    Device, LibraryView, SaveStorageConfigInput, SessionView, StorageConfigView, Transfer,
};

fn application(app: &AppHandle) -> Result<TransferApplication, RpcError> {
    TransferApplication::from_app(app)
}

fn validate_command_string(field: &str, value: &str) -> Result<(), RpcError> {
    validate_string(field, value)
}

fn validate_command_batch(field: &str, values: &[String]) -> Result<(), RpcError> {
    validate_batch(field, values)
}

fn command_failure(code: &'static str, message: String, retryable: bool) -> RpcError {
    RpcError::new(code, message, retryable, None)
}

fn validate_storage_input(config: &SaveStorageConfigInput) -> Result<(), RpcError> {
    validate_command_string("endpoint", &config.endpoint)?;
    validate_command_string("bucket", &config.bucket)?;
    if !config.prefix.trim().is_empty() {
        validate_command_string("prefix", &config.prefix)?;
    }
    if !config.download_root.trim().is_empty() {
        validate_command_string("downloadRoot", &config.download_root)?;
    }
    if !config.access_key.trim().is_empty() {
        validate_command_string("accessKey", &config.access_key)?;
    }
    if !config.secret_key.trim().is_empty() {
        validate_command_string("secretKey", &config.secret_key)?;
    }
    if config.access_key.trim().is_empty() != config.secret_key.trim().is_empty() {
        return Err(RpcError::invalid_input(
            "credentials",
            "accessKey and secretKey must be supplied together",
        ));
    }
    Ok(())
}

#[tauri::command]
pub fn read_snapshot(app: AppHandle) -> Result<Revisioned<ApplicationSnapshot>, RpcError> {
    Ok(application(&app)?.read_snapshot())
}

#[tauri::command]
pub fn list_devices(app: AppHandle) -> Result<Revisioned<Vec<Device>>, RpcError> {
    Ok(application(&app)?.read_devices())
}

#[tauri::command]
pub async fn connect_device(app: AppHandle, device_id: String) -> Result<String, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    application(&app)?
        .connect_device(app, device_id)
        .await
        .map_err(|message| command_failure("device_connect_failed", message, true))
}

#[tauri::command]
pub async fn cancel_pairing(
    app: AppHandle,
    device_id: String,
    attempt_id: String,
) -> Result<(), RpcError> {
    validate_command_string("deviceId", &device_id)?;
    validate_command_string("attemptId", &attempt_id)?;
    application(&app)?
        .cancel_pairing(device_id, attempt_id)
        .await
        .map_err(|message| command_failure("pairing_cancel_failed", message, false))
}

#[tauri::command]
pub async fn add_manual_device(app: AppHandle, ip: String) -> Result<Revisioned<Device>, RpcError> {
    validate_command_string("ip", &ip)?;
    ip.trim()
        .parse::<IpAddr>()
        .map_err(|_| RpcError::invalid_input("ip", "must be a valid IPv4 or IPv6 address"))?;
    application(&app)?
        .add_manual_device(ip)
        .await
        .map_err(|message| command_failure("manual_device_add_failed", message, true))
}

#[tauri::command]
pub async fn disconnect_device(app: AppHandle, device_id: String) -> Result<(), RpcError> {
    validate_command_string("deviceId", &device_id)?;
    application(&app)?
        .disconnect_device(device_id)
        .await
        .map_err(|message| command_failure("device_disconnect_failed", message, false))
}

#[tauri::command]
pub async fn list_sessions(
    app: AppHandle,
    device_id: String,
) -> Result<Revisioned<Vec<SessionView>>, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    application(&app)?
        .list_sessions(device_id)
        .await
        .map_err(|message| command_failure("session_list_failed", message, true))
}

#[tauri::command]
pub async fn delete_sessions(
    app: AppHandle,
    device_id: String,
    session_ids: Vec<String>,
) -> Result<Revisioned<SessionMutationResult>, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    validate_command_batch("sessionIds", &session_ids)?;
    application(&app)?
        .delete_sessions(device_id, session_ids)
        .await
        .map_err(|message| command_failure("session_batch_failed", message, false))
}

#[tauri::command]
pub async fn cleanup_backed_up(
    app: AppHandle,
    device_id: String,
) -> Result<Revisioned<SessionMutationResult>, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    application(&app)?
        .cleanup_backed_up(device_id)
        .await
        .map_err(|message| command_failure("session_batch_failed", message, false))
}

#[tauri::command]
pub async fn preview_downloaded_cleanup(
    app: AppHandle,
    device_id: String,
) -> Result<DownloadedCleanupPreview, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    application(&app)?
        .preview_downloaded_cleanup(device_id)
        .await
        .map_err(|message| command_failure("downloaded_cleanup_preview_failed", message, true))
}

#[tauri::command]
pub async fn cleanup_downloaded(
    app: AppHandle,
    device_id: String,
) -> Result<Revisioned<DownloadedCleanupResult>, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    application(&app)?
        .cleanup_downloaded(device_id)
        .await
        .map_err(|message| command_failure("downloaded_cleanup_failed", message, true))
}

#[tauri::command]
pub async fn list_library(app: AppHandle) -> Result<Revisioned<Vec<LibraryView>>, RpcError> {
    Ok(application(&app)?.read_library())
}

#[tauri::command]
pub async fn remove_library_entries(
    app: AppHandle,
    keys: Vec<String>,
) -> Result<Revisioned<LibraryMutationResult>, RpcError> {
    validate_command_batch("keys", &keys)?;
    application(&app)?
        .remove_library_entries(keys)
        .await
        .map_err(|message| command_failure("library_batch_failed", message, false))
}

#[tauri::command]
pub fn list_transfers(app: AppHandle) -> Result<Revisioned<Vec<Transfer>>, RpcError> {
    Ok(application(&app)?.read_transfers())
}

#[tauri::command]
pub async fn download_session(
    app: AppHandle,
    device_id: String,
    session_id: String,
) -> Result<String, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    validate_command_string("sessionId", &session_id)?;
    application(&app)?
        .download_session(app, device_id, session_id)
        .await
        .map_err(|message| command_failure("download_enqueue_failed", message, false))
}

#[tauri::command]
pub async fn download_sessions(
    app: AppHandle,
    device_id: String,
    session_ids: Vec<String>,
) -> Result<BatchJobResult, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    validate_command_batch("sessionIds", &session_ids)?;
    application(&app)?
        .download_sessions(app, device_id, session_ids)
        .await
        .map_err(|message| command_failure("download_enqueue_failed", message, false))
}

#[tauri::command]
pub async fn download_file(
    app: AppHandle,
    device_id: String,
    session_id: String,
    file_id: String,
) -> Result<String, RpcError> {
    validate_command_string("deviceId", &device_id)?;
    validate_command_string("sessionId", &session_id)?;
    validate_command_string("fileId", &file_id)?;
    application(&app)?
        .download_file(app, device_id, session_id, file_id)
        .await
        .map_err(|message| command_failure("download_enqueue_failed", message, false))
}

#[tauri::command]
pub async fn upload_entry(app: AppHandle, key: String) -> Result<String, RpcError> {
    validate_command_string("key", &key)?;
    application(&app)?
        .upload_entry(app, key)
        .await
        .map_err(|message| command_failure("upload_enqueue_failed", message, false))
}

#[tauri::command]
pub async fn upload_entries(app: AppHandle, keys: Vec<String>) -> Result<BatchJobResult, RpcError> {
    validate_command_batch("keys", &keys)?;
    application(&app)?
        .upload_entries(app, keys)
        .await
        .map_err(|message| command_failure("upload_enqueue_failed", message, false))
}

#[tauri::command]
pub async fn retry_transfer(app: AppHandle, job_id: String) -> Result<String, RpcError> {
    validate_command_string("jobId", &job_id)?;
    let transfer_application = application(&app)?;
    let is_derived = transfer_application
        .is_derived_upload_job(&job_id)
        .map_err(|message| command_failure("transfer_retry_failed", message, false))?;
    if is_derived {
        return MediaApplication::from_app(&app)?
            .retry_derived_upload(job_id)
            .await;
    }
    transfer_application
        .retry_transfer(app, job_id)
        .await
        .map_err(|message| command_failure("transfer_retry_failed", message, false))
}

#[tauri::command]
pub async fn pause_transfer_job(app: AppHandle, job_id: String) -> Result<(), RpcError> {
    validate_command_string("jobId", &job_id)?;
    application(&app)?
        .pause_transfer_job(job_id)
        .await
        .map_err(|message| command_failure("transfer_pause_failed", message, false))
}

#[tauri::command]
pub async fn resume_transfer_job(app: AppHandle, job_id: String) -> Result<(), RpcError> {
    validate_command_string("jobId", &job_id)?;
    application(&app)?
        .resume_transfer_job(job_id)
        .await
        .map_err(|message| command_failure("transfer_resume_failed", message, false))
}

#[tauri::command]
pub async fn cancel_transfer_job(app: AppHandle, job_id: String) -> Result<(), RpcError> {
    validate_command_string("jobId", &job_id)?;
    application(&app)?
        .cancel_transfer_job(job_id)
        .await
        .map_err(|message| command_failure("transfer_cancel_failed", message, false))
}

#[tauri::command]
pub async fn dismiss_transfer_job(app: AppHandle, job_id: String) -> Result<(), RpcError> {
    validate_command_string("jobId", &job_id)?;
    application(&app)?
        .dismiss_transfer_job(job_id)
        .await
        .map_err(|message| command_failure("transfer_dismiss_failed", message, false))
}

#[tauri::command]
pub async fn dismiss_upload_transfer(app: AppHandle, job_id: String) -> Result<(), RpcError> {
    validate_command_string("jobId", &job_id)?;
    application(&app)?
        .dismiss_upload_transfer(app, job_id)
        .await
        .map_err(|message| command_failure("upload_dismiss_failed", message, false))
}

#[tauri::command]
pub async fn cancel_upload(app: AppHandle, job_id: String) -> Result<(), RpcError> {
    validate_command_string("jobId", &job_id)?;
    application(&app)?
        .cancel_upload(app, job_id)
        .await
        .map_err(|message| command_failure("upload_cancel_failed", message, false))
}

#[tauri::command]
pub async fn reveal_library_file(
    app: AppHandle,
    key: String,
    file_id: String,
) -> Result<(), RpcError> {
    validate_command_string("key", &key)?;
    validate_command_string("fileId", &file_id)?;
    application(&app)?
        .reveal_library_file(key, file_id)
        .await
        .map_err(|message| command_failure("library_reveal_failed", message, false))
}

#[tauri::command]
pub async fn get_storage_config(app: AppHandle) -> Result<Revisioned<StorageConfigView>, RpcError> {
    Ok(application(&app)?.read_storage())
}

#[tauri::command]
pub async fn select_download_root(app: AppHandle) -> Result<Option<String>, RpcError> {
    let application = application(&app)?;
    let (send, receive) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("选择本地下载目录")
        .set_directory(application.active_library_root())
        .pick_folder(move |selected| {
            let _ = send.send(selected);
        });
    let selected = receive.await.map_err(|_| {
        command_failure(
            "download_root_selection_failed",
            "目录选择窗口意外关闭".to_string(),
            false,
        )
    })?;
    let Some(selection) = selected else {
        return Ok(None);
    };
    let path = selection.into_path().map_err(|error| {
        command_failure(
            "download_root_selection_failed",
            format!("无法读取所选目录：{error}"),
            false,
        )
    })?;
    let path = path
        .to_str()
        .ok_or_else(|| {
            command_failure(
                "download_root_selection_failed",
                "所选目录路径包含无法识别的字符".to_string(),
                false,
            )
        })?
        .to_string();
    application
        .validate_download_root(path)
        .await
        .map_err(|message| command_failure("download_root_validation_failed", message, false))?
        .ok_or_else(|| {
            command_failure(
                "download_root_validation_failed",
                "未选择下载目录".to_string(),
                false,
            )
        })
        .map(Some)
}

#[tauri::command]
pub async fn save_download_root(
    app: AppHandle,
    download_root: String,
) -> Result<Revisioned<StorageConfigView>, RpcError> {
    if !download_root.trim().is_empty() {
        validate_command_string("downloadRoot", &download_root)?;
    }
    application(&app)?
        .save_download_root(download_root)
        .await
        .map_err(|message| command_failure("download_root_save_failed", message, false))
}

#[tauri::command]
pub async fn save_storage_config(
    app: AppHandle,
    config: SaveStorageConfigInput,
) -> Result<Revisioned<StorageConfigView>, RpcError> {
    validate_storage_input(&config)?;
    application(&app)?
        .save_storage_config(config)
        .await
        .map_err(|message| command_failure("storage_config_save_failed", message, false))
}

#[tauri::command]
pub async fn test_storage_connection(
    app: AppHandle,
    config: SaveStorageConfigInput,
) -> Result<(), RpcError> {
    validate_storage_input(&config)?;
    application(&app)?
        .test_storage_connection(config)
        .await
        .map_err(|message| command_failure("storage_connection_test_failed", message, true))
}

#[tauri::command]
pub fn set_notifications_enabled(app: AppHandle, enabled: bool) -> Result<bool, RpcError> {
    application(&app)?
        .set_notifications_enabled_with_app(app, enabled)
        .map_err(|message| command_failure("notification_update_failed", message, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::MAX_RPC_STRING_BYTES;
    use crate::models::StorageUrlStyle;

    fn storage_input(access_key: &str, secret_key: &str) -> SaveStorageConfigInput {
        SaveStorageConfigInput {
            endpoint: "https://oss-cn-beijing.aliyuncs.com".to_string(),
            bucket: "ylx-recordings".to_string(),
            prefix: "fixture".to_string(),
            url_style: StorageUrlStyle::VirtualHost,
            download_root: "/srv/ylx-recordings".to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    fn assert_invalid_field(error: RpcError, expected: &str) {
        assert_eq!(error.code, "invalid_input");
        assert!(!error.retryable);
        assert_eq!(
            error
                .details
                .as_ref()
                .and_then(|details| details["field"].as_str()),
            Some(expected)
        );
    }

    #[test]
    fn storage_credentials_must_be_supplied_as_a_pair() {
        for config in [storage_input("access", ""), storage_input("", "secret")] {
            assert_invalid_field(
                validate_storage_input(&config).expect_err("one-sided credentials must fail"),
                "credentials",
            );
        }
        assert!(validate_storage_input(&storage_input("", "")).is_ok());
        assert!(validate_storage_input(&storage_input("access", "secret")).is_ok());
    }

    #[test]
    fn command_validation_reports_camel_case_wire_fields() {
        assert_invalid_field(
            validate_command_batch("sessionIds", &[]).expect_err("empty batch must fail"),
            "sessionIds",
        );

        let mut config = storage_input("", "");
        config.download_root = "x".repeat(MAX_RPC_STRING_BYTES + 1);
        assert_invalid_field(
            validate_storage_input(&config).expect_err("oversized path must fail"),
            "downloadRoot",
        );

        config.download_root.clear();
        config.access_key = "x".repeat(MAX_RPC_STRING_BYTES + 1);
        config.secret_key = "secret".to_string();
        assert_invalid_field(
            validate_storage_input(&config).expect_err("oversized access key must fail"),
            "accessKey",
        );
    }
}
