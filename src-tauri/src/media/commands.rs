//! Thin Tauri adapters for the media application protocol.
//!
//! Validation, effects, projection publication, and lifecycle all live in
//! [`super::MediaApplication`]. The root invoke handler only needs to register
//! these functions under their stable names.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::Value;
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;
use ylx_transfer_adapters::session_export::{
    FfmpegSessionExporter, SessionExportConfig, SessionExportReceipt, SessionExportRequest,
};
use ylx_transfer_core::ingest::SafeRelativePath;

use crate::application::{validate_string, Revisioned, RpcError, TransferApplication};

use super::types::{
    DerivationJob, DerivationJobId, ImportBatchOutcome, ImportJob, ImportJobId, MediaExportResult,
    MediaId, MediaJobCommand, MediaLibraryEntryProjection, MediaLibrarySourceLocalProjection,
    MediaScanSnapshot, MediaTrustedProducerRevocation, PipelineBatchOutcome, PipelineCommand,
    PipelineId, PipelineSession, ScanRequest, StartDerivationRequest, StartImportRequest,
    StartPipelineRequest,
};
use super::{MediaApplication, MediaApplicationSnapshot};

fn application(app: &AppHandle) -> Result<MediaApplication, RpcError> {
    MediaApplication::from_app(app)
}

fn transfer_application(app: &AppHandle) -> Result<TransferApplication, RpcError> {
    TransferApplication::from_app(app)
}

fn command_failure(code: &'static str, message: impl Into<String>, retryable: bool) -> RpcError {
    RpcError::new(code, message.into(), retryable, None)
}

fn decode_input<T: DeserializeOwned>(field: &str, value: Value) -> Result<T, RpcError> {
    serde_json::from_value(value).map_err(|_| {
        RpcError::invalid_input(field, "must match the documented media command shape")
    })
}

fn decode_media_job_command(command: &str) -> Result<MediaJobCommand, RpcError> {
    match command {
        "pause" => Ok(MediaJobCommand::Pause),
        "resume" => Ok(MediaJobCommand::Resume),
        "cancel" => Ok(MediaJobCommand::Cancel),
        "retry" => Ok(MediaJobCommand::Retry),
        _ => Err(RpcError::invalid_input(
            "command",
            "must be pause, resume, cancel, or retry",
        )),
    }
}

fn decode_pipeline_command(command: &str) -> Result<PipelineCommand, RpcError> {
    match command {
        "pause" => Ok(PipelineCommand::Pause),
        "resume" => Ok(PipelineCommand::Resume),
        "cancel" => Ok(PipelineCommand::Cancel),
        "retry" => Ok(PipelineCommand::Retry),
        "approve_unsigned_upload" => Ok(PipelineCommand::ApproveUnsignedUpload),
        _ => Err(RpcError::invalid_input(
            "command",
            "must be pause, resume, cancel, retry, or approve_unsigned_upload",
        )),
    }
}

async fn select_export_path(
    app: &AppHandle,
    directory: PathBuf,
    default_file_name: String,
) -> Result<Option<PathBuf>, RpcError> {
    let (send, receive) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("导出 SBS MP4")
        .set_directory(directory)
        .set_file_name(default_file_name)
        .add_filter("MP4 video", &["mp4"])
        .save_file(move |selected| {
            let _ = send.send(selected);
        });
    let selected = receive.await.map_err(|_| {
        command_failure(
            "media_export_selection_failed",
            "保存文件窗口意外关闭",
            false,
        )
    })?;
    let Some(selection) = selected else {
        return Ok(None);
    };
    selection.into_path().map(Some).map_err(|error| {
        command_failure(
            "media_export_selection_failed",
            format!("无法读取所选导出路径：{error}"),
            false,
        )
    })
}

fn default_export_file_name(entry: &MediaLibraryEntryProjection) -> String {
    let digest = entry
        .source_revision
        .strip_prefix("sha256:")
        .unwrap_or(&entry.source_revision);
    let short_digest: String = digest
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(12)
        .collect();
    if short_digest.is_empty() {
        format!("{}-sbs.mp4", sanitize_file_stem(&entry.entry_key))
    } else {
        format!("ylx-{short_digest}-sbs.mp4")
    }
}

fn sanitize_file_stem(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars().take(48) {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
            output.push(character);
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    let output = output.trim_matches('-');
    if output.is_empty() {
        "ylx-export".to_string()
    } else {
        output.to_string()
    }
}

fn source_relative_path(entry: &MediaLibraryEntryProjection) -> Result<String, RpcError> {
    match &entry.source_local {
        MediaLibrarySourceLocalProjection::Verified { relative_path, .. } => {
            Ok(relative_path.clone())
        }
        MediaLibrarySourceLocalProjection::Removed { .. } => Err(command_failure(
            "media_export_source_unavailable",
            "源素材已从本地库移除，无法导出",
            false,
        )),
    }
}

fn export_result(receipt: SessionExportReceipt) -> Result<MediaExportResult, RpcError> {
    Ok(MediaExportResult::Completed {
        output_path: path_to_string(&receipt.output_path)?,
        video_segment_count: receipt.video_segment_count,
        audio_segment_count: receipt.audio_segment_count,
        output_size_bytes: receipt.output_size_bytes,
    })
}

fn path_to_string(path: &Path) -> Result<String, RpcError> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        command_failure(
            "media_export_failed",
            "导出路径不是有效的 UTF-8 路径",
            false,
        )
    })
}

#[tauri::command]
pub fn media_read_snapshot(
    app: AppHandle,
) -> Result<Revisioned<MediaApplicationSnapshot>, RpcError> {
    Ok(application(&app)?.read_snapshot())
}

#[tauri::command]
pub fn media_read_scan_candidates(
    app: AppHandle,
) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
    Ok(application(&app)?.read_scan_candidates())
}

#[tauri::command]
pub fn media_read_import_jobs(app: AppHandle) -> Result<Revisioned<Vec<ImportJob>>, RpcError> {
    Ok(application(&app)?.read_import_jobs())
}

#[tauri::command]
pub fn media_read_derivation_jobs(
    app: AppHandle,
) -> Result<Revisioned<Vec<DerivationJob>>, RpcError> {
    Ok(application(&app)?.read_derivation_jobs())
}

#[tauri::command]
pub fn media_read_pipeline_sessions(
    app: AppHandle,
) -> Result<Revisioned<Vec<PipelineSession>>, RpcError> {
    Ok(application(&app)?.read_pipeline_sessions())
}

#[tauri::command]
pub fn media_read_library_projections(
    app: AppHandle,
) -> Result<Revisioned<Vec<MediaLibraryEntryProjection>>, RpcError> {
    Ok(application(&app)?.read_library_projections())
}

#[tauri::command]
pub async fn media_revoke_trusted_producer(
    app: AppHandle,
    key_fingerprint: String,
) -> Result<MediaTrustedProducerRevocation, RpcError> {
    application(&app)?
        .revoke_trusted_producer(key_fingerprint)
        .await
}

#[tauri::command]
pub async fn media_scan(
    app: AppHandle,
    request: Value,
) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
    application(&app)?
        .scan(decode_input::<ScanRequest>("request", request)?)
        .await
}

#[tauri::command]
pub async fn media_start_import(
    app: AppHandle,
    request: Value,
) -> Result<Revisioned<ImportJob>, RpcError> {
    application(&app)?
        .start_import(decode_input::<StartImportRequest>("request", request)?)
        .await
}

#[tauri::command]
pub async fn media_start_import_batch(
    app: AppHandle,
    requests: Value,
) -> Result<Revisioned<ImportBatchOutcome>, RpcError> {
    application(&app)?
        .start_import_batch(decode_input::<Vec<StartImportRequest>>(
            "requests", requests,
        )?)
        .await
}

#[tauri::command]
pub async fn media_start_derivation(
    app: AppHandle,
    request: Value,
) -> Result<Revisioned<DerivationJob>, RpcError> {
    application(&app)?
        .start_derivation(decode_input::<StartDerivationRequest>("request", request)?)
        .await
}

#[tauri::command]
pub async fn media_start_pipeline(
    app: AppHandle,
    request: Value,
) -> Result<Revisioned<PipelineSession>, RpcError> {
    application(&app)?
        .start_pipeline(decode_input::<StartPipelineRequest>("request", request)?)
        .await
}

#[tauri::command]
pub async fn media_start_pipeline_batch(
    app: AppHandle,
    requests: Value,
) -> Result<Revisioned<PipelineBatchOutcome>, RpcError> {
    application(&app)?
        .start_pipeline_batch(decode_input::<Vec<StartPipelineRequest>>(
            "requests", requests,
        )?)
        .await
}

#[tauri::command]
pub async fn media_export_library_entry(
    app: AppHandle,
    entry_key: String,
) -> Result<MediaExportResult, RpcError> {
    validate_string("entryKey", &entry_key)?;
    let library = application(&app)?.read_library_projections().value;
    let entry = library
        .into_iter()
        .find(|entry| entry.entry_key == entry_key)
        .ok_or_else(|| {
            command_failure(
                "media_export_source_unavailable",
                "未找到要导出的媒体库条目",
                false,
            )
        })?;
    let relative_path = source_relative_path(&entry)?;
    let default_file_name = default_export_file_name(&entry);
    let library_root = transfer_application(&app)?.active_library_root();
    let Some(output_path) =
        select_export_path(&app, library_root.clone(), default_file_name).await?
    else {
        return Ok(MediaExportResult::Cancelled);
    };
    let source_relative = SafeRelativePath::parse(relative_path).map_err(|error| {
        command_failure(
            "media_export_source_unavailable",
            format!("媒体库源路径不安全，无法导出：{error}"),
            false,
        )
    })?;
    let source_root = source_relative.join_to(&library_root);
    let request = SessionExportRequest::new(source_root, output_path).with_overwrite(true);
    let receipt = tauri::async_runtime::spawn_blocking(move || {
        FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_source_tree(&request)
    })
    .await
    .map_err(|error| {
        command_failure(
            "media_export_failed",
            format!("导出任务异常终止：{error}"),
            true,
        )
    })?
    .map_err(|error| command_failure("media_export_failed", error.to_string(), true))?;
    export_result(receipt)
}

#[tauri::command]
pub async fn media_command_import(
    app: AppHandle,
    job_id: String,
    command: String,
) -> Result<Revisioned<ImportJob>, RpcError> {
    application(&app)?
        .command_import(
            ImportJobId::new(job_id),
            decode_media_job_command(&command)?,
        )
        .await
}

#[tauri::command]
pub async fn media_command_derivation(
    app: AppHandle,
    job_id: String,
    command: String,
) -> Result<Revisioned<DerivationJob>, RpcError> {
    application(&app)?
        .command_derivation(
            DerivationJobId::new(job_id),
            decode_media_job_command(&command)?,
        )
        .await
}

#[tauri::command]
pub async fn media_command_pipeline(
    app: AppHandle,
    pipeline_id: String,
    command: String,
) -> Result<Revisioned<PipelineSession>, RpcError> {
    application(&app)?
        .command_pipeline(
            PipelineId::new(pipeline_id),
            decode_pipeline_command(&command)?,
        )
        .await
}

#[tauri::command]
pub async fn media_release_handles(
    app: AppHandle,
    media_id: String,
) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
    application(&app)?
        .release_media_handles(MediaId::new(media_id))
        .await
}

#[tauri::command]
pub async fn media_eject(
    app: AppHandle,
    media_id: String,
) -> Result<Revisioned<MediaScanSnapshot>, RpcError> {
    application(&app)?.eject_media(MediaId::new(media_id)).await
}
