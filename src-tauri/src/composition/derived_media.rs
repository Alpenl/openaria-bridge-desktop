use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Number;
use sha2::{Digest, Sha256};
use ylx_transfer_adapters::session_export::{
    verify_session_export_output, FfmpegSessionExporter, ManifestAudioTimeline,
    ManifestSessionTimeline, SessionExportConfig, SessionExportError, SessionExportOutputMedia,
    SessionExportPlan, SessionExportReceipt, SessionExportTimelineVerification,
    SessionTimelineClock, TimedAudioSegment, TimedVideoSegment, TimelineTime,
    TimelineVerificationVerdict,
};
use ylx_transfer_core::domain::PublicationScope;
use ylx_transfer_core::library::staging::SessionStaging;
use ylx_transfer_core::publication::parse_strict_json;
use ylx_transfer_core::transfer::commit::{
    DownloadCommitControl, DownloadCommitFailure, DownloadCommitOutcome, DownloadCommitPort,
    DownloadCommitRequest,
};
use ylx_transfer_core::transfer::FailureCode;

use crate::models::SessionFile;

use super::derived_publication::validate_source_manifest_schema;

const RECEIPT_SCHEMA: &str = "ylx.derived-media-receipt.v1";
const SOURCE_SCHEMA: &str = "ylx.device-session.v2";
const RECIPE_ID: &str = "openaria.stereo-derived-mp4";
const RECEIPT_FILENAME: &str = "derived-media-receipt.json";
pub(super) const RECEIPT_DISPLAY_PATH: &str = "processed/derived-media-receipt.json";
const MAX_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;
const BACKUP_OWNERSHIP_SCHEMA: &str = "ylx.derived-media-backup-owner.v1";
const BACKUP_OWNERSHIP_FILENAME: &str = "ownership.json";
const BACKUP_PREVIOUS_DIRNAME: &str = "previous";
const BACKUP_PREVIOUS_TOKEN_FILENAME: &str = ".ylx-owner-token";
const MAX_BACKUP_OWNERSHIP_BYTES: u64 = 16 * 1024;
const MAX_BACKUP_PREVIOUS_TOKEN_BYTES: u64 = 128;

#[cfg(test)]
thread_local! {
    static STRONG_MEDIA_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_strong_media_verification_count() {
    STRONG_MEDIA_VERIFICATIONS.set(0);
}

#[cfg(test)]
pub(super) fn strong_media_verification_count() -> usize {
    STRONG_MEDIA_VERIFICATIONS.get()
}

trait SessionExporterPort: Send + Sync {
    fn export(
        &self,
        plan: &SessionExportPlan,
        control: &DownloadCommitControl,
    ) -> Result<SessionExportReceipt, DownloadCommitFailure>;

    fn inspect_existing(&self, plan: &SessionExportPlan) -> Result<SessionExportReceipt, String>;
}

struct RealSessionExporter {
    exporter: FfmpegSessionExporter,
}

impl SessionExporterPort for RealSessionExporter {
    fn export(
        &self,
        plan: &SessionExportPlan,
        control: &DownloadCommitControl,
    ) -> Result<SessionExportReceipt, DownloadCommitFailure> {
        self.exporter
            .export_plan_cancellable(plan, || control.is_cancel_requested())
            .map_err(|error| match error {
                SessionExportError::Cancelled => DownloadCommitFailure::cancelled(),
                error => DownloadCommitFailure::retryable(format!("media export failed: {error}")),
            })
    }

    fn inspect_existing(&self, plan: &SessionExportPlan) -> Result<SessionExportReceipt, String> {
        let output_path = plan.output_path().to_path_buf();
        let probe = self
            .exporter
            .probe_output(&output_path)
            .map_err(|error| error.to_string())?;
        let timeline_verification = verify_session_export_output(plan, &output_path, &probe)
            .map_err(|error| error.to_string())?;
        let output_media = probe.output_media().map_err(|error| error.to_string())?;
        let output_size_bytes = regular_file_metadata(&output_path)
            .map_err(|error| format!("inspect existing derived output: {error}"))?
            .len();
        Ok(SessionExportReceipt {
            output_path,
            video_segment_count: plan.video_segment_count(),
            audio_segment_count: plan.audio_segment_count(),
            output_size_bytes,
            timeline_verification: Some(timeline_verification),
            output_media: Some(output_media),
        })
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFailure {
    ReceiptWrite,
    CanonicalPublish,
    BackupCleanup,
    SourceStagingCleanup,
}

/// Desktop's production finalizer. The coordinator does not report success
/// until this implementation has exported, probed, receipted, and atomically
/// published the canonical two-file bundle.
pub(super) struct DerivedMediaCommitter {
    exporter: Arc<dyn SessionExporterPort>,
    #[cfg(test)]
    injected_failure: Option<InjectedFailure>,
}

impl DerivedMediaCommitter {
    pub(super) fn new(config: SessionExportConfig) -> Self {
        Self {
            exporter: Arc::new(RealSessionExporter {
                exporter: FfmpegSessionExporter::new(config),
            }),
            #[cfg(test)]
            injected_failure: None,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_exporter(
        exporter: Arc<dyn SessionExporterPort>,
        injected_failure: Option<InjectedFailure>,
    ) -> Self {
        Self {
            exporter,
            injected_failure,
        }
    }
}

impl DownloadCommitPort for DerivedMediaCommitter {
    fn commit(
        &self,
        input: &DownloadCommitRequest,
    ) -> Result<DownloadCommitOutcome, DownloadCommitFailure> {
        self.commit_cancellable(input, &DownloadCommitControl::default())
    }

    fn commit_cancellable(
        &self,
        input: &DownloadCommitRequest,
        control: &DownloadCommitControl,
    ) -> Result<DownloadCommitOutcome, DownloadCommitFailure> {
        ensure_commit_not_cancelled(control)?;
        if input.publication_scope != PublicationScope::FullSession {
            return Err(DownloadCommitFailure::permanent(
                "a usable derived download requires a complete Device Session v2 inventory",
            ));
        }

        let source = parse_source_publication(&input.request.manifest_bytes)
            .map_err(DownloadCommitFailure::permanent)?;
        if source.manifest.session_id != input.request.session_id.as_str() {
            return Err(DownloadCommitFailure::permanent(
                "source manifest session_id does not match the transfer request",
            ));
        }
        if input.request.revision != format!("sha256:{}", source.sha256) {
            return Err(DownloadCommitFailure::permanent(
                "source manifest digest does not match the transfer revision",
            ));
        }

        let staging = SessionStaging::for_publication(
            &input.library_root,
            input.request.device_id.as_str(),
            input.request.session_id.as_str(),
            &input.request.manifest_bytes,
        )
        .map_err(|error| DownloadCommitFailure::permanent(error.to_string()))?;

        // A process may have published the canonical bundle and stopped before
        // the coordinator's durable CommitComplete. Reuse the exact validated
        // bundle, but do not report success until source cleanup also finishes.
        match canonical_assets_in_session_dir(&staging.published_dir(), &source) {
            Ok(_) => {
                control.begin_irreversible()?;
                cleanup_previous_canonical_backup(
                    &staging,
                    &source,
                    input.job_id.as_str(),
                    self.backup_cleanup_failure_injected(),
                )?;
                return cleanup_source_staging(
                    &staging,
                    self.source_staging_cleanup_failure_injected(),
                );
            }
            Err(validation_error) => {
                if inspect_previous_canonical_backup(&staging, &source, input.job_id.as_str())?
                    != PreviousCanonicalBackup::Absent
                {
                    return Err(DownloadCommitFailure::retryable(format!(
                        "canonical bundle failed revalidation while an ownership-bound previous backup awaits cleanup: {validation_error}"
                    )));
                }
            }
        }

        bind_and_verify_inputs(input, &source, &staging.revision_dir())?;
        let attempt = derived_attempt_dir(&staging, input.job_id.as_str());
        prepare_empty_attempt(&attempt)?;
        let result = self.prepare_and_publish(input, &source, &staging, &attempt, control);
        if result.is_err() {
            cleanup_failed_attempt(&attempt);
        }
        result
    }
}

impl DerivedMediaCommitter {
    fn prepare_and_publish(
        &self,
        input: &DownloadCommitRequest,
        source: &ParsedSource,
        staging: &SessionStaging,
        attempt: &Path,
        control: &DownloadCommitControl,
    ) -> Result<DownloadCommitOutcome, DownloadCommitFailure> {
        ensure_commit_not_cancelled(control)?;
        let processed = attempt.join("processed");
        fs::create_dir_all(&processed).map_err(|error| retryable_io("create attempt", error))?;
        reject_link_or_non_directory(&processed).map_err(DownloadCommitFailure::permanent)?;

        let output_filename = format!("{}.mp4", source.manifest.session_id);
        let output_path = processed.join(&output_filename);
        let timeline = source
            .manifest
            .export_timeline(&source.sha256)
            .map_err(DownloadCommitFailure::permanent)?;
        let plan = SessionExportPlan::from_manifest_timeline(
            staging.revision_dir(),
            output_path.clone(),
            false,
            timeline,
        )
        .map_err(|error| DownloadCommitFailure::permanent(error.to_string()))?;
        let exported = self.exporter.export(&plan, control)?;

        // The frames index is part of the transform receipt even though it is
        // not an FFmpeg input, so verify every declared transform input again
        // after the exporter returns.
        ensure_commit_not_cancelled(control)?;
        bind_and_verify_inputs(input, source, &staging.revision_dir())?;
        ensure_commit_not_cancelled(control)?;
        let document = build_receipt(
            source,
            &output_filename,
            &output_path,
            &exported,
            "new-download",
        )?;
        let receipt_path = processed.join(RECEIPT_FILENAME);
        #[cfg(test)]
        if self.injected_failure == Some(InjectedFailure::ReceiptWrite) {
            return Err(DownloadCommitFailure::retryable(
                "injected derived receipt write failure",
            ));
        }
        write_receipt_atomically(&receipt_path, &document)?;
        canonical_assets_in_session_dir(attempt, source)
            .map_err(DownloadCommitFailure::permanent)?;
        ensure_commit_not_cancelled(control)?;

        #[cfg(test)]
        if self.injected_failure == Some(InjectedFailure::CanonicalPublish) {
            return Err(DownloadCommitFailure::retryable(
                "injected canonical derived publish failure",
            ));
        }
        control.begin_irreversible()?;
        publish_attempt(
            attempt,
            staging,
            input.job_id.as_str(),
            source,
            self.backup_cleanup_failure_injected(),
        )?;

        cleanup_source_staging(staging, self.source_staging_cleanup_failure_injected())
    }

    fn source_staging_cleanup_failure_injected(&self) -> bool {
        #[cfg(test)]
        {
            self.injected_failure == Some(InjectedFailure::SourceStagingCleanup)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    fn backup_cleanup_failure_injected(&self) -> bool {
        #[cfg(test)]
        {
            self.injected_failure == Some(InjectedFailure::BackupCleanup)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    pub(super) fn migrate_existing(
        &self,
        library_root: &Path,
        device_id: &str,
        session_id: &str,
        publication_payload: &[u8],
        legacy_processed_files: &[SessionFile],
    ) -> Result<Option<CanonicalDerivedAssets>, String> {
        let source = parse_source_publication(publication_payload)?;
        if source.manifest.session_id != session_id {
            return Err("source manifest session_id does not match the legacy entry".to_string());
        }
        let staging = SessionStaging::for_publication(
            library_root,
            device_id,
            session_id,
            publication_payload,
        )
        .map_err(|error| error.to_string())?;
        let published = staging.published_dir();
        let migration_id = format!("migration:{}:{}", device_id, source.sha256);
        if let Ok(canonical) = canonical_assets_in_session_dir(&published, &source) {
            let backup = previous_canonical_backup_dir(&staging, &migration_id);
            if fs::symlink_metadata(&backup).is_ok() {
                cleanup_previous_canonical_backup(
                    &staging,
                    &source,
                    &migration_id,
                    self.backup_cleanup_failure_injected(),
                )
                .map_err(commit_failure_message)?;
                staging.discard().map_err(|error| {
                    format!("cleanup migration backup ownership scope: {error}")
                })?;
            }
            return Ok(Some(canonical));
        }
        verify_manifest_files_in_root(&source.manifest, &published)?;
        let legacy_output =
            find_legacy_processed_output(&published, session_id, legacy_processed_files)?
                .ok_or_else(|| {
                    "legacy library entry has no receipt-verifiable processed MP4 to promote"
                        .to_string()
                })?;

        let attempt = staging.staging_root().join(format!(
            "migration-{}",
            sha256_bytes(format!("{device_id}\0{session_id}\0{}", source.sha256).as_bytes())
        ));
        prepare_empty_attempt(&attempt).map_err(commit_failure_message)?;
        let result = self.prepare_existing_migration(
            &source,
            &published,
            &legacy_output,
            &attempt,
            &migration_id,
            &staging,
        );
        if result.is_err() {
            cleanup_failed_attempt(&attempt);
        }
        result.map(Some).map_err(commit_failure_message)
    }

    fn prepare_existing_migration(
        &self,
        source: &ParsedSource,
        source_root: &Path,
        legacy_output: &Path,
        attempt: &Path,
        migration_id: &str,
        staging: &SessionStaging,
    ) -> Result<CanonicalDerivedAssets, DownloadCommitFailure> {
        let processed = attempt.join("processed");
        fs::create_dir_all(&processed).map_err(|error| retryable_io("create migration", error))?;
        reject_link_or_non_directory(&processed).map_err(DownloadCommitFailure::permanent)?;
        let output_filename = format!("{}.mp4", source.manifest.session_id);
        let output_path = processed.join(&output_filename);
        copy_regular_file_durably(legacy_output, &output_path)?;

        let timeline = source
            .manifest
            .export_timeline(&source.sha256)
            .map_err(DownloadCommitFailure::permanent)?;
        let plan = SessionExportPlan::from_manifest_timeline(
            source_root,
            output_path.clone(),
            true,
            timeline,
        )
        .map_err(|error| DownloadCommitFailure::permanent(error.to_string()))?;
        let inspected = self.exporter.inspect_existing(&plan).map_err(|error| {
            DownloadCommitFailure::retryable(format!(
                "existing processed media verification failed: {error}"
            ))
        })?;
        verify_manifest_files_in_root(&source.manifest, source_root)
            .map_err(DownloadCommitFailure::retryable)?;
        let receipt = build_receipt(
            source,
            &output_filename,
            &output_path,
            &inspected,
            "existing-library-migration",
        )?;
        write_receipt_atomically(&processed.join(RECEIPT_FILENAME), &receipt)?;
        canonical_assets_in_session_dir(attempt, source)
            .map_err(DownloadCommitFailure::permanent)?;
        publish_attempt(
            attempt,
            staging,
            migration_id,
            source,
            self.backup_cleanup_failure_injected(),
        )?;
        staging
            .discard()
            .map_err(|error| DownloadCommitFailure::retryable(error.to_string()))?;
        canonical_assets_in_session_dir(source_root, source)
            .map_err(DownloadCommitFailure::permanent)
    }
}

#[derive(Debug, Clone)]
pub(super) struct CanonicalDerivedAssets {
    pub files: Vec<SessionFile>,
    pub total_bytes: u64,
}

/// Exact, revalidated local inputs for Bucket Publication v4. Source bytes
/// remain the Device Session v2 document nested in the compatibility
/// envelope; the compatibility envelope itself is never uploaded.
#[derive(Debug, Clone)]
pub(super) struct CanonicalPublicationBundle {
    pub source_device_id: String,
    pub source_device_label: String,
    pub source_manifest_id: String,
    pub source_session_id: String,
    pub source_volume_id: String,
    pub source_manifest_bytes: Vec<u8>,
    pub source_manifest_sha256: String,
    pub receipt_id: String,
    pub receipt_path: PathBuf,
    pub receipt_bytes: Vec<u8>,
    pub receipt_sha256: String,
    pub output_artifact_id: String,
    pub output_path: PathBuf,
    pub output_bytes: u64,
    pub output_sha256: String,
    pub published_at: String,
    pub canonical_assets: CanonicalDerivedAssets,
}

pub(super) fn canonical_assets_for_publication(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    publication_payload: &[u8],
) -> Result<CanonicalDerivedAssets, String> {
    canonical_publication_bundle_for_entry(library_root, device_id, session_id, publication_payload)
        .map(|bundle| bundle.canonical_assets)
}

pub(super) fn canonical_publication_bundle_for_entry(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    publication_payload: &[u8],
) -> Result<CanonicalPublicationBundle, String> {
    #[cfg(test)]
    STRONG_MEDIA_VERIFICATIONS.set(STRONG_MEDIA_VERIFICATIONS.get() + 1);
    reject_link_or_non_directory(library_root)?;
    let canonical_root = fs::canonicalize(library_root)
        .map_err(|error| format!("canonicalize library root: {error}"))?;
    let source = parse_source_publication(publication_payload)?;
    if source.manifest.session_id != session_id {
        return Err("source manifest session_id does not match the library entry".to_string());
    }
    let staging =
        SessionStaging::for_publication(library_root, device_id, session_id, publication_payload)
            .map_err(|error| error.to_string())?;
    let published = staging.published_dir();
    reject_link_or_non_directory(&published)?;
    let canonical_published = fs::canonicalize(&published)
        .map_err(|error| format!("canonicalize published session: {error}"))?;
    if !canonical_published.starts_with(&canonical_root) {
        return Err("published session escapes the configured library root".to_string());
    }
    canonical_publication_bundle_in_session_dir(&canonical_published, &source)
}

fn canonical_assets_in_session_dir(
    session_dir: &Path,
    source: &ParsedSource,
) -> Result<CanonicalDerivedAssets, String> {
    canonical_publication_bundle_in_session_dir(session_dir, source)
        .map(|bundle| bundle.canonical_assets)
}

fn canonical_publication_bundle_in_session_dir(
    session_dir: &Path,
    source: &ParsedSource,
) -> Result<CanonicalPublicationBundle, String> {
    reject_link_or_non_directory(session_dir)?;
    let output_filename = format!("{}.mp4", source.manifest.session_id);
    let processed = session_dir.join("processed");
    reject_link_or_non_directory(&processed)?;
    ensure_exact_canonical_layout(session_dir, &output_filename)?;
    let output_path = processed.join(&output_filename);
    let receipt_path = processed.join(RECEIPT_FILENAME);
    let output_metadata = regular_file_metadata(&output_path)?;
    let receipt_metadata = regular_file_metadata(&receipt_path)?;
    if receipt_metadata.len() == 0 || receipt_metadata.len() > MAX_RECEIPT_BYTES {
        return Err("derived media receipt has an invalid byte length".to_string());
    }
    let receipt_bytes = read_bounded(&receipt_path, receipt_metadata.len())?;
    let receipt_value = parse_strict_json(&receipt_bytes)
        .map_err(|error| format!("invalid derived media receipt JSON: {error}"))?;
    validate_receipt_json_shape(&receipt_value)?;
    let receipt: DerivedMediaReceipt = serde_json::from_value(receipt_value)
        .map_err(|error| format!("invalid derived media receipt shape: {error}"))?;
    validate_receipt(
        &receipt,
        source,
        &output_filename,
        &output_path,
        output_metadata.len(),
    )?;

    let receipt_sha256 = sha256_bytes(&receipt_bytes);
    let total_bytes = output_metadata
        .len()
        .checked_add(receipt_metadata.len())
        .ok_or_else(|| "canonical derived byte count overflowed".to_string())?;
    let canonical_assets = CanonicalDerivedAssets {
        files: vec![
            SessionFile::new(
                receipt.output.sha256.clone(),
                format!("processed/{output_filename}"),
                output_metadata.len(),
                receipt.output.sha256.clone(),
            ),
            SessionFile::new(
                receipt_sha256.clone(),
                RECEIPT_DISPLAY_PATH.to_string(),
                receipt_metadata.len(),
                receipt_sha256.clone(),
            ),
        ],
        total_bytes,
    };
    Ok(CanonicalPublicationBundle {
        source_device_id: source.manifest.device.device_id.clone(),
        source_device_label: source.manifest.device.device_label.clone(),
        source_manifest_id: source.manifest.manifest_id.clone(),
        source_session_id: source.manifest.session_id.clone(),
        source_volume_id: source.manifest.volume_id.clone(),
        source_manifest_bytes: source.manifest_bytes.clone(),
        source_manifest_sha256: source.sha256.clone(),
        receipt_id: receipt.receipt_id.clone(),
        receipt_path,
        receipt_bytes,
        receipt_sha256,
        output_artifact_id: receipt.output.artifact_id.clone(),
        output_path,
        output_bytes: output_metadata.len(),
        output_sha256: receipt.output.sha256.clone(),
        published_at: receipt.canonicalization.committed_at.clone(),
        canonical_assets,
    })
}

fn ensure_exact_canonical_layout(session_dir: &Path, output_filename: &str) -> Result<(), String> {
    let session_entries = fs::read_dir(session_dir)
        .map_err(|error| format!("read canonical session directory: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("read canonical session entry: {error}"))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "canonical session entry name is not UTF-8".to_string())
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if session_entries != BTreeSet::from(["processed".to_string()]) {
        return Err("canonical session directory contains non-canonical source inputs".to_string());
    }
    let processed_entries = fs::read_dir(session_dir.join("processed"))
        .map_err(|error| format!("read canonical processed directory: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("read canonical processed entry: {error}"))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "canonical processed entry name is not UTF-8".to_string())
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = BTreeSet::from([output_filename.to_string(), RECEIPT_FILENAME.to_string()]);
    if processed_entries != expected {
        return Err("canonical processed directory is not the exact MP4/receipt pair".to_string());
    }
    Ok(())
}

fn validate_receipt_json_shape(value: &serde_json::Value) -> Result<(), String> {
    require_exact_object_keys(
        value,
        "receipt",
        &[
            "schema",
            "receipt_id",
            "created_at",
            "origin",
            "source_manifest",
            "input_artifacts",
            "transformer",
            "output",
            "timeline_verification",
            "canonicalization",
            "provenance",
        ],
    )?;
    require_exact_object_keys(
        &value["source_manifest"],
        "source_manifest",
        &[
            "schema",
            "manifest_id",
            "session_id",
            "volume_id",
            "bytes",
            "sha256",
        ],
    )?;
    let inputs = value["input_artifacts"]
        .as_array()
        .ok_or_else(|| "input_artifacts is not an array".to_string())?;
    for (index, input) in inputs.iter().enumerate() {
        require_exact_object_keys(
            input,
            &format!("input_artifacts[{index}]"),
            &["artifact_id", "role", "bytes", "sha256"],
        )?;
    }
    require_exact_object_keys(
        &value["transformer"],
        "transformer",
        &["name", "version", "recipe_id", "recipe_version"],
    )?;
    require_exact_object_keys(
        &value["output"],
        "output",
        &[
            "artifact_id",
            "role",
            "filename",
            "media_type",
            "bytes",
            "sha256",
            "container",
            "video_codec",
            "layout",
            "width",
            "eye_width",
            "height",
            "audio",
        ],
    )?;
    let audio = &value["output"]["audio"];
    match audio.get("state").and_then(serde_json::Value::as_str) {
        Some("present") => require_exact_object_keys(
            audio,
            "output.audio",
            &["state", "codec", "sample_rate", "channels"],
        )?,
        Some("absent") => require_exact_object_keys(audio, "output.audio", &["state", "reason"])?,
        _ => return Err("output.audio has an unknown state".to_string()),
    }
    require_exact_object_keys(
        &value["timeline_verification"],
        "timeline_verification",
        &[
            "policy_id",
            "verdict",
            "source_manifest_sha256",
            "left_right_pairing",
            "paired_frames",
            "video_start_residual_ns",
            "video_end_residual_ns",
            "audio_start_residual_ns",
            "audio_end_residual_ns",
            "source_video_tick_ns",
            "encoding_audio_frame_ns",
            "allowed_residual_ns",
            "preserved_leading_gap_ns",
            "verified_at",
            "probe_summary",
        ],
    )?;
    require_exact_object_keys(
        &value["timeline_verification"]["probe_summary"],
        "timeline_verification.probe_summary",
        &[
            "output_sha256",
            "output_bytes",
            "video_streams",
            "audio_streams",
            "frame_count",
            "duration_ns",
            "report_sha256",
        ],
    )?;
    require_exact_object_keys(
        &value["canonicalization"],
        "canonicalization",
        &[
            "state",
            "committed_at",
            "local_asset",
            "required_upload_assets",
            "source_inputs",
        ],
    )?;
    require_exact_object_keys(
        &value["provenance"],
        "provenance",
        &[
            "derived_authorship",
            "source_manifest_signature",
            "device_signature_inheritance",
            "derived_output_signature",
        ],
    )?;
    Ok(())
}

fn require_exact_object_keys(
    value: &serde_json::Value,
    label: &str,
    expected: &[&str],
) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is not an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{label} does not have the exact receipt schema fields"
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CompatPublication {
    schema_version: u32,
    session_id: String,
    revision: String,
    total_bytes: u64,
    files: Vec<CompatPublicationFile>,
    source_schema: String,
    source_manifest_sha256: String,
    source_manifest_json: String,
    source_profile: String,
    receipt_origin: String,
    device_authenticity: String,
    integrity_ok: bool,
    gateway_verification: Option<CompatGatewayVerification>,
}

#[derive(Debug, Deserialize)]
struct CompatPublicationFile {
    id: String,
    display_path: String,
    role: String,
    size_bytes: u64,
    sha256: String,
    media_type: String,
}

#[derive(Debug, Deserialize)]
struct CompatGatewayVerification {
    actor: String,
    validator: CompatGatewayValidator,
    manifest_sha256: String,
    manifest_digest_valid: bool,
    verified_at: String,
    verdict: String,
    diagnostics: Vec<CompatGatewayDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct CompatGatewayValidator {
    name: String,
    version: String,
    build_sha256: String,
}

#[derive(Debug, Deserialize)]
struct CompatGatewayDiagnostic {
    code: String,
    summary: String,
}

#[derive(Debug, Clone)]
struct ParsedSource {
    manifest: DeviceSessionManifest,
    manifest_bytes: Vec<u8>,
    bytes: u64,
    sha256: String,
    inputs: Vec<ReceiptInputArtifact>,
}

fn parse_source_publication(payload: &[u8]) -> Result<ParsedSource, String> {
    let publication_value = parse_strict_json(payload)
        .map_err(|error| format!("invalid compatibility publication JSON: {error}"))?;
    let publication: CompatPublication = serde_json::from_value(publication_value)
        .map_err(|error| format!("invalid compatibility publication shape: {error}"))?;
    if publication.schema_version != 1
        || publication.source_profile != "ylx-device-api-v4-lab-http"
        || publication.receipt_origin != "client-derived-lab-compatibility"
        || publication.device_authenticity != "not_asserted"
        || !publication.integrity_ok
        || publication.source_schema != SOURCE_SCHEMA
    {
        return Err(format!(
            "usable derived media requires an eligible {SOURCE_SCHEMA} v4 compatibility publication, found {}",
            publication.source_schema
        ));
    }
    validate_sha256(
        &publication.source_manifest_sha256,
        "source manifest digest",
    )?;
    let manifest_bytes = publication.source_manifest_json.as_bytes();
    if manifest_bytes.is_empty() {
        return Err("source_manifest_json is empty".to_string());
    }
    let actual_sha256 = sha256_bytes(manifest_bytes);
    if actual_sha256 != publication.source_manifest_sha256 {
        return Err("source_manifest_json bytes do not match source_manifest_sha256".to_string());
    }
    validate_gateway_verification(&publication, &actual_sha256)?;
    let manifest_value = parse_strict_json(manifest_bytes)
        .map_err(|error| format!("invalid Device Session v2 JSON: {error}"))?;
    validate_source_manifest_schema(&manifest_value)?;
    let manifest: DeviceSessionManifest = serde_json::from_value(manifest_value)
        .map_err(|error| format!("invalid Device Session v2 manifest: {error}"))?;
    manifest.validate()?;
    if publication.session_id != manifest.session_id
        || publication.revision != format!("sha256:{actual_sha256}")
    {
        return Err(
            "compatibility publication identity or revision differs from its source manifest"
                .to_string(),
        );
    }
    validate_compat_inventory(&publication, &manifest)?;
    let mut inputs = manifest.receipt_inputs()?;
    inputs.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let unique = inputs
        .iter()
        .map(|input| input.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() != inputs.len() {
        return Err("transform input artifact_id values are not unique".to_string());
    }
    Ok(ParsedSource {
        manifest,
        manifest_bytes: manifest_bytes.to_vec(),
        bytes: u64::try_from(manifest_bytes.len())
            .map_err(|_| "source manifest byte count overflowed".to_string())?,
        sha256: actual_sha256,
        inputs,
    })
}

pub(super) fn validate_source_publication_for_download(payload: &[u8]) -> Result<(), String> {
    parse_source_publication(payload).map(|_| ())
}

fn validate_gateway_verification(
    publication: &CompatPublication,
    source_manifest_sha256: &str,
) -> Result<(), String> {
    let verification = publication.gateway_verification.as_ref().ok_or_else(|| {
        "v4 compatibility publication has no gateway verification receipt".to_string()
    })?;
    if verification.actor != "gateway"
        || verification.verdict != "usable"
        || !verification.manifest_digest_valid
        || verification.manifest_sha256 != source_manifest_sha256
        || verification.validator.name.trim().is_empty()
        || verification.validator.version.trim().is_empty()
    {
        return Err(
            "v4 compatibility publication is not bound to a usable gateway verification"
                .to_string(),
        );
    }
    validate_sha256(
        &verification.validator.build_sha256,
        "gateway validator build digest",
    )?;
    parse_timestamp(
        &verification.verified_at,
        "gateway verification verified_at",
    )?;
    if verification
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code.trim().is_empty() || diagnostic.summary.trim().is_empty())
    {
        return Err("gateway verification contains an invalid diagnostic".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct DeviceSessionManifest {
    schema: String,
    manifest_id: String,
    sealed: bool,
    sealed_at: String,
    session_id: String,
    volume_id: String,
    device: ManifestDevice,
    camera: ManifestCamera,
    video: ManifestVideo,
    imu: ManifestImu,
    frames: ManifestFrames,
    audio: ManifestAudio,
    logs: Vec<ManifestArtifact>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestDevice {
    device_id: String,
    device_label: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestCamera {
    width: u32,
    height: u32,
    eye_width: u32,
    effective_fps: Number,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestVideo {
    layout: String,
    codec: String,
    container: String,
    segments: Vec<ManifestVideoSegment>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestVideoSegment {
    index: u32,
    start_frame: u64,
    end_frame: u64,
    start_time_seconds: Number,
    end_time_seconds: Number,
    artifacts: ManifestEyeArtifacts,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestEyeArtifacts {
    left: ManifestArtifact,
    right: ManifestArtifact,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestFrames {
    artifact: ManifestArtifact,
    count: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestImu {
    artifact: ManifestArtifact,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "state")]
enum ManifestAudio {
    #[serde(rename = "recorded")]
    Recorded {
        sample_rate: u32,
        channels: u32,
        sample_count: u64,
        sync: ManifestAudioSync,
        segments: Vec<ManifestAudioSegment>,
    },
    #[serde(rename = "not_recorded")]
    NotRecorded,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestAudioSync {
    time_base: String,
    start_time_seconds: Number,
    end_time_seconds: Number,
    video_time_reference: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestAudioSegment {
    index: u32,
    start_sample: u64,
    end_sample: u64,
    start_time_seconds: Number,
    end_time_seconds: Number,
    artifact: ManifestArtifact,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestArtifact {
    artifact_id: String,
    role: String,
    path: PathBuf,
    media_type: String,
    bytes: u64,
    sha256: String,
}

impl DeviceSessionManifest {
    fn validate(&self) -> Result<(), String> {
        if self.schema != SOURCE_SCHEMA || !self.sealed {
            return Err("source must be a sealed Device Session v2 manifest".to_string());
        }
        validate_uuid_v7(&self.manifest_id, "manifest_id")?;
        validate_uuid_v7(&self.session_id, "session_id")?;
        validate_uuid_v4(&self.volume_id, "volume_id")?;
        validate_uuid_v4(&self.device.device_id, "device.device_id")?;
        if self.device.device_label.len() != 12
            || !self.device.device_label.starts_with("YLX-")
            || !self.device.device_label[4..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        {
            return Err("source device_label is not YLX-<8 uppercase hex>".to_string());
        }
        parse_timestamp(&self.sealed_at, "sealed_at")?;
        if self.camera.width == 0
            || self.camera.height == 0
            || self.camera.eye_width == 0
            || self.camera.eye_width.checked_mul(2) != Some(self.camera.width)
        {
            return Err("source camera dimensions must be positive".to_string());
        }
        if self.video.layout != "split-eyes"
            || self.video.codec != "h264"
            || self.video.container != "mp4"
        {
            return Err(
                "source video must use the Device Session v2 split-eyes H.264/MP4 contract"
                    .to_string(),
            );
        }
        if self.video.segments.is_empty() {
            return Err("source video has no segments".to_string());
        }
        let video_tick =
            reciprocal_decimal_rate(&self.camera.effective_fps, "camera.effective_fps")?;

        let mut expected_start_frame = 0_u64;
        let mut expected_index = 0_u32;
        for segment in &self.video.segments {
            if segment.index != expected_index
                || segment.start_frame != expected_start_frame
                || segment.end_frame <= segment.start_frame
            {
                return Err("video segment frame ranges are not contiguous".to_string());
            }
            let start = decimal_time(&segment.start_time_seconds)?;
            let end = decimal_time(&segment.end_time_seconds)?;
            if end <= start {
                return Err("video segment time range is not positive".to_string());
            }
            validate_artifact(&segment.artifacts.left, "video.left", "video/mp4", true)?;
            validate_artifact(&segment.artifacts.right, "video.right", "video/mp4", true)?;
            expected_start_frame = segment.end_frame;
            expected_index = expected_index
                .checked_add(1)
                .ok_or_else(|| "video segment index overflowed".to_string())?;
        }
        if expected_start_frame != self.frames.count || self.frames.count == 0 {
            return Err("frames.count does not equal the paired video frame range".to_string());
        }
        validate_artifact(
            &self.frames.artifact,
            "frames.index",
            "application/x-ndjson",
            true,
        )?;
        validate_artifact(
            &self.imu.artifact,
            "imu.samples",
            "application/x-ndjson",
            false,
        )?;
        for artifact in &self.logs {
            if !artifact.role.starts_with("log.") {
                return Err("source log artifact has an invalid role".to_string());
            }
            validate_artifact(artifact, &artifact.role, &artifact.media_type, false)?;
        }

        match &self.audio {
            ManifestAudio::NotRecorded => {}
            ManifestAudio::Recorded {
                sample_rate,
                channels,
                sample_count,
                sync,
                segments,
            } => {
                if *sample_rate == 0 || *channels == 0 || *sample_count == 0 {
                    return Err("recorded audio has invalid scalar metadata".to_string());
                }
                if sync.time_base != "host_monotonic"
                    || sync.video_time_reference != "session_time_seconds"
                {
                    return Err(
                        "recorded audio must use the host_monotonic session clock".to_string()
                    );
                }
                let sync_start_ns = exact_decimal_nanoseconds(&sync.start_time_seconds)?;
                let sync_end_ns = exact_decimal_nanoseconds(&sync.end_time_seconds)?;
                if sync_end_ns <= sync_start_ns {
                    return Err("recorded audio sync range is not positive".to_string());
                }
                if segments.is_empty() {
                    return Err("recorded audio has no segments".to_string());
                }
                let mut expected_sample = 0_u64;
                let mut expected_index = 0_u32;
                let mut previous_end_ns = None;
                let sample_tolerance_ns =
                    ceil_ratio_u64(1_000_000_000, u128::from(*sample_rate))?.saturating_add(1);
                for segment in segments {
                    if segment.index != expected_index
                        || segment.start_sample != expected_sample
                        || segment.end_sample <= segment.start_sample
                    {
                        return Err("audio sample ranges are not contiguous".to_string());
                    }
                    let declared_start_ns =
                        rounded_decimal_nanoseconds(&segment.start_time_seconds)?;
                    let declared_end_ns = rounded_decimal_nanoseconds(&segment.end_time_seconds)?;
                    if declared_end_ns <= declared_start_ns
                        || previous_end_ns
                            .is_some_and(|end: i64| end.abs_diff(declared_start_ns) > 1)
                        || !sample_clock_position_matches(
                            declared_start_ns,
                            0,
                            segment.start_sample,
                            *sample_rate,
                            sample_tolerance_ns,
                        )?
                        || !sample_clock_position_matches(
                            declared_end_ns,
                            0,
                            segment.end_sample,
                            *sample_rate,
                            sample_tolerance_ns,
                        )?
                    {
                        return Err("audio-clock times contradict their sample ranges".to_string());
                    }
                    validate_artifact(&segment.artifact, "audio.wav", "audio/wav", true)?;
                    expected_sample = segment.end_sample;
                    previous_end_ns = Some(declared_end_ns);
                    expected_index = expected_index
                        .checked_add(1)
                        .ok_or_else(|| "audio segment index overflowed".to_string())?;
                }
                if expected_sample != *sample_count {
                    return Err("audio.sample_count does not equal its segment ranges".to_string());
                }
                let sync_tolerance_ns = ceil_positive_timeline_nanoseconds(video_tick)?.max(
                    ceil_ratio_u64(1_024_u128 * 1_000_000_000_u128, u128::from(*sample_rate))?,
                );
                if !sample_clock_position_matches(
                    sync_end_ns,
                    sync_start_ns,
                    *sample_count,
                    *sample_rate,
                    sync_tolerance_ns,
                )? {
                    return Err("audio sync duration contradicts its sample range".to_string());
                }
            }
        }
        let all_artifacts = self.all_artifacts();
        let unique_ids = all_artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<BTreeSet<_>>();
        if unique_ids.len() != all_artifacts.len() {
            return Err("source manifest contains duplicate artifact_id values".to_string());
        }
        let unique_paths = all_artifacts
            .iter()
            .map(|artifact| artifact.path.as_path())
            .collect::<BTreeSet<_>>();
        if unique_paths.len() != all_artifacts.len() {
            return Err("source manifest contains duplicate artifact paths".to_string());
        }
        Ok(())
    }

    fn receipt_inputs(&self) -> Result<Vec<ReceiptInputArtifact>, String> {
        let mut inputs = Vec::new();
        for segment in &self.video.segments {
            inputs.push(ReceiptInputArtifact::from(&segment.artifacts.left));
            inputs.push(ReceiptInputArtifact::from(&segment.artifacts.right));
        }
        inputs.push(ReceiptInputArtifact::from(&self.frames.artifact));
        if let ManifestAudio::Recorded { segments, .. } = &self.audio {
            inputs.extend(
                segments
                    .iter()
                    .map(|segment| ReceiptInputArtifact::from(&segment.artifact)),
            );
        }
        Ok(inputs)
    }

    fn export_timeline(&self, source_sha256: &str) -> Result<ManifestSessionTimeline, String> {
        let video_tick =
            reciprocal_decimal_rate(&self.camera.effective_fps, "camera.effective_fps")?;
        let mut left_segments = Vec::new();
        let mut right_segments = Vec::new();
        for segment in &self.video.segments {
            let start_time = decimal_time(&segment.start_time_seconds)?;
            let end_time = decimal_time(&segment.end_time_seconds)?;
            left_segments.push(TimedVideoSegment {
                index: segment.index,
                path: segment.artifacts.left.path.clone(),
                bytes: segment.artifacts.left.bytes,
                sha256: segment.artifacts.left.sha256.clone(),
                start_frame: segment.start_frame,
                end_frame: segment.end_frame,
                start_time,
                end_time,
            });
            right_segments.push(TimedVideoSegment {
                index: segment.index,
                path: segment.artifacts.right.path.clone(),
                bytes: segment.artifacts.right.bytes,
                sha256: segment.artifacts.right.sha256.clone(),
                start_frame: segment.start_frame,
                end_frame: segment.end_frame,
                start_time,
                end_time,
            });
        }
        let audio = match &self.audio {
            ManifestAudio::NotRecorded => None,
            ManifestAudio::Recorded {
                sample_rate,
                channels,
                sample_count,
                sync,
                segments,
            } => {
                let session_start_ns = exact_decimal_nanoseconds(&sync.start_time_seconds)?;
                Some(ManifestAudioTimeline {
                    sample_rate_hz: *sample_rate,
                    channels: *channels,
                    sample_count: *sample_count,
                    session_start_offset: TimelineTime::from_nanoseconds(session_start_ns)
                        .map_err(|error| error.to_string())?,
                    session_stop_offset: decimal_time(&sync.end_time_seconds)?,
                    segments: segments
                        .iter()
                        .map(|segment| {
                            Ok(TimedAudioSegment {
                                index: segment.index,
                                path: segment.artifact.path.clone(),
                                bytes: segment.artifact.bytes,
                                sha256: segment.artifact.sha256.clone(),
                                start_sample: segment.start_sample,
                                end_sample: segment.end_sample,
                                start_time: session_time_from_audio_sample(
                                    session_start_ns,
                                    segment.start_sample,
                                    *sample_rate,
                                )?,
                                end_time: session_time_from_audio_sample(
                                    session_start_ns,
                                    segment.end_sample,
                                    *sample_rate,
                                )?,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?,
                })
            }
        };
        Ok(ManifestSessionTimeline {
            source_manifest_sha256: source_sha256.to_string(),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick,
            eye_width: self.camera.eye_width,
            eye_height: self.camera.height,
            left_segments,
            right_segments,
            audio,
        })
    }
}

fn validate_artifact(
    artifact: &ManifestArtifact,
    expected_role: &str,
    expected_media_type: &str,
    require_nonempty: bool,
) -> Result<(), String> {
    if artifact.role != expected_role {
        return Err(format!(
            "manifest artifact role {} does not match {expected_role}",
            artifact.role
        ));
    }
    validate_sha256(&artifact.artifact_id, "artifact_id")?;
    validate_sha256(&artifact.sha256, "artifact sha256")?;
    if artifact.artifact_id != artifact.sha256 || (require_nonempty && artifact.bytes == 0) {
        return Err("manifest artifact identity or byte count is invalid".to_string());
    }
    if artifact.media_type != expected_media_type {
        return Err(format!(
            "manifest artifact media type {} does not match {expected_media_type}",
            artifact.media_type
        ));
    }
    validate_relative_artifact_path(&artifact.path)?;
    Ok(())
}

fn bind_and_verify_inputs(
    input: &DownloadCommitRequest,
    source: &ParsedSource,
    source_root: &Path,
) -> Result<(), DownloadCommitFailure> {
    if input.verified_files.len() != input.request.files.len() {
        return Err(DownloadCommitFailure::retryable(
            "the finalizer did not receive every requested verified file",
        ));
    }
    let canonical_source_root = fs::canonicalize(source_root)
        .map_err(|error| retryable_io("canonicalize source staging root", error))?;
    let requests = input
        .request
        .files
        .iter()
        .map(|file| (file.file_id.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let verified = input
        .verified_files
        .iter()
        .map(|file| (file.file_id.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let artifacts = source.manifest.all_artifacts();
    if requests.len() != input.request.files.len()
        || verified.len() != input.verified_files.len()
        || artifacts.len() != requests.len()
    {
        return Err(DownloadCommitFailure::permanent(
            "the complete source manifest, request, and verified inventory do not have the same identity set",
        ));
    }
    for artifact in artifacts {
        let request = requests.get(artifact.artifact_id.as_str()).ok_or_else(|| {
            DownloadCommitFailure::permanent(format!(
                "source transform artifact {} is not in the full-session request",
                artifact.artifact_id
            ))
        })?;
        if request.target_relative_path.as_deref() != artifact.path.to_str()
            || request.expected_size != artifact.bytes
            || request.expected_sha256_hex != artifact.sha256
        {
            return Err(DownloadCommitFailure::permanent(
                "source manifest artifact does not match the signed transfer inventory",
            ));
        }
        let file = verified.get(artifact.artifact_id.as_str()).ok_or_else(|| {
            DownloadCommitFailure::retryable("a transform artifact has no verified local file")
        })?;
        if file.size_bytes != artifact.bytes || file.sha256_hex != artifact.sha256 {
            return Err(DownloadCommitFailure::new(FailureCode::HashMismatch, true));
        }
        let expected_path = source_root.join(&artifact.path);
        let expected_path = fs::canonicalize(&expected_path)
            .map_err(|error| retryable_io("canonicalize transform artifact", error))?;
        let actual_path = fs::canonicalize(&file.path)
            .map_err(|error| retryable_io("canonicalize verified artifact", error))?;
        if expected_path != actual_path || !actual_path.starts_with(&canonical_source_root) {
            return Err(DownloadCommitFailure::permanent(
                "verified transform artifact escaped or disagreed with its staging path",
            ));
        }
        let metadata =
            plain_regular_file_metadata(&actual_path).map_err(DownloadCommitFailure::retryable)?;
        if metadata.len() != artifact.bytes
            || hash_file(&actual_path).map_err(DownloadCommitFailure::retryable)? != artifact.sha256
        {
            return Err(DownloadCommitFailure::new(FailureCode::HashMismatch, true));
        }
    }
    Ok(())
}

impl DeviceSessionManifest {
    fn all_artifacts(&self) -> Vec<&ManifestArtifact> {
        let mut artifacts = Vec::new();
        for segment in &self.video.segments {
            artifacts.push(&segment.artifacts.left);
            artifacts.push(&segment.artifacts.right);
        }
        artifacts.push(&self.imu.artifact);
        artifacts.push(&self.frames.artifact);
        if let ManifestAudio::Recorded { segments, .. } = &self.audio {
            artifacts.extend(segments.iter().map(|segment| &segment.artifact));
        }
        artifacts.extend(self.logs.iter());
        artifacts
    }
}

fn validate_compat_inventory(
    publication: &CompatPublication,
    manifest: &DeviceSessionManifest,
) -> Result<(), String> {
    let artifacts = manifest.all_artifacts();
    let total_bytes = artifacts.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.bytes)
            .ok_or_else(|| "source artifact byte count overflowed".to_string())
    })?;
    if publication.total_bytes != total_bytes || publication.files.len() != artifacts.len() {
        return Err(
            "compatibility publication total bytes or file count differs from its source manifest"
                .to_string(),
        );
    }
    let mut ids = BTreeSet::new();
    for file in &publication.files {
        if !ids.insert(file.id.as_str()) {
            return Err("compatibility publication contains duplicate file ids".to_string());
        }
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == file.id)
            .ok_or_else(|| {
                format!(
                    "compatibility publication contains an unknown source artifact {}",
                    file.id
                )
            })?;
        if artifact.path.to_str() != Some(file.display_path.as_str())
            || artifact.role != file.role
            || artifact.media_type != file.media_type
            || artifact.bytes != file.size_bytes
            || artifact.sha256 != file.sha256
        {
            return Err(format!(
                "compatibility publication descriptor differs from source artifact {}",
                file.id
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptInputArtifact {
    artifact_id: String,
    role: String,
    bytes: u64,
    sha256: String,
}

impl From<&ManifestArtifact> for ReceiptInputArtifact {
    fn from(artifact: &ManifestArtifact) -> Self {
        Self {
            artifact_id: artifact.artifact_id.clone(),
            role: artifact.role.clone(),
            bytes: artifact.bytes,
            sha256: artifact.sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedMediaReceipt {
    schema: String,
    receipt_id: String,
    created_at: String,
    origin: String,
    source_manifest: ReceiptSourceManifest,
    input_artifacts: Vec<ReceiptInputArtifact>,
    transformer: ReceiptTransformer,
    output: ReceiptOutput,
    timeline_verification: SessionExportTimelineVerification,
    canonicalization: ReceiptCanonicalization,
    provenance: ReceiptProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSourceManifest {
    schema: String,
    manifest_id: String,
    session_id: String,
    volume_id: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptTransformer {
    name: String,
    version: String,
    recipe_id: String,
    recipe_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptOutput {
    artifact_id: String,
    role: String,
    filename: String,
    media_type: String,
    bytes: u64,
    sha256: String,
    container: String,
    video_codec: String,
    layout: String,
    eye_width: u32,
    width: u32,
    height: u32,
    audio: ReceiptOutputAudio,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum ReceiptOutputAudio {
    #[serde(rename = "present")]
    Present {
        codec: String,
        sample_rate: u32,
        channels: u32,
    },
    #[serde(rename = "absent")]
    Absent { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptCanonicalization {
    state: String,
    committed_at: String,
    local_asset: String,
    required_upload_assets: Vec<String>,
    source_inputs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptProvenance {
    derived_authorship: String,
    source_manifest_signature: String,
    device_signature_inheritance: String,
    derived_output_signature: String,
}

fn build_receipt(
    source: &ParsedSource,
    output_filename: &str,
    output_path: &Path,
    exported: &SessionExportReceipt,
    origin: &str,
) -> Result<DerivedMediaReceipt, DownloadCommitFailure> {
    if !matches!(origin, "new-download" | "existing-library-migration") {
        return Err(DownloadCommitFailure::permanent(
            "derived receipt origin is unsupported",
        ));
    }
    if exported.output_path != output_path || exported.output_size_bytes == 0 {
        return Err(DownloadCommitFailure::retryable(
            "exporter receipt does not identify the staged output",
        ));
    }
    let output_sha256 = hash_file(output_path).map_err(DownloadCommitFailure::retryable)?;
    let timeline = exported.timeline_verification.clone().ok_or_else(|| {
        DownloadCommitFailure::retryable("manifest-driven export returned no timeline verdict")
    })?;
    let output_media = exported.output_media.clone().ok_or_else(|| {
        DownloadCommitFailure::retryable("manifest-driven export returned no output media probe")
    })?;
    if output_media.video_codec != "h264"
        || output_media.layout != "left-right-side-by-side"
        || output_media.width != source.manifest.camera.width
        || output_media.eye_width != source.manifest.camera.eye_width
        || output_media.height != source.manifest.camera.height
        || output_media.eye_width.checked_mul(2) != Some(output_media.width)
    {
        return Err(DownloadCommitFailure::retryable(
            "derived output geometry or codec differs from the exact source camera contract",
        ));
    }
    if timeline.verdict != TimelineVerificationVerdict::Pass
        || timeline.left_right_pairing != TimelineVerificationVerdict::Pass
        || timeline.source_manifest_sha256 != source.sha256
        || timeline.paired_frames != source.manifest.frames.count
        || timeline.probe_summary.output_sha256 != output_sha256
        || timeline.probe_summary.output_bytes != exported.output_size_bytes
        || timeline.probe_summary.frame_count != source.manifest.frames.count
    {
        return Err(DownloadCommitFailure::retryable(
            "export timeline verdict does not bind the exact source and output",
        ));
    }
    if source
        .inputs
        .iter()
        .any(|input| input.sha256 == output_sha256)
        || output_sha256 == source.sha256
    {
        return Err(DownloadCommitFailure::permanent(
            "derived output digest reuses source identity",
        ));
    }
    let audio = receipt_audio(&source.manifest.audio, &output_media)?;
    let now = chrono::Utc::now().to_rfc3339();
    Ok(DerivedMediaReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        receipt_id: new_uuid_v7(),
        created_at: now.clone(),
        origin: origin.to_string(),
        source_manifest: ReceiptSourceManifest {
            schema: SOURCE_SCHEMA.to_string(),
            manifest_id: source.manifest.manifest_id.clone(),
            session_id: source.manifest.session_id.clone(),
            volume_id: source.manifest.volume_id.clone(),
            bytes: source.bytes,
            sha256: source.sha256.clone(),
        },
        input_artifacts: source.inputs.clone(),
        transformer: ReceiptTransformer {
            name: "openaria-bridge-desktop".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            recipe_id: RECIPE_ID.to_string(),
            recipe_version: 1,
        },
        output: ReceiptOutput {
            artifact_id: output_sha256.clone(),
            role: "media.derived".to_string(),
            filename: output_filename.to_string(),
            media_type: "video/mp4".to_string(),
            bytes: exported.output_size_bytes,
            sha256: output_sha256,
            container: "mp4".to_string(),
            video_codec: output_media.video_codec,
            layout: output_media.layout,
            eye_width: output_media.eye_width,
            width: output_media.width,
            height: output_media.height,
            audio,
        },
        timeline_verification: timeline,
        canonicalization: ReceiptCanonicalization {
            state: "committed".to_string(),
            committed_at: now,
            local_asset: "derived-output".to_string(),
            required_upload_assets: vec![
                "derived-output".to_string(),
                "derived-media-receipt".to_string(),
            ],
            source_inputs: "temporary-delete-after-commit".to_string(),
        },
        provenance: ReceiptProvenance {
            derived_authorship: "openaria-bridge-desktop".to_string(),
            source_manifest_signature: "not-declared-by-device-session-v2".to_string(),
            device_signature_inheritance: "forbidden".to_string(),
            derived_output_signature: "not-device-signed".to_string(),
        },
    })
}

fn receipt_audio(
    source: &ManifestAudio,
    output: &SessionExportOutputMedia,
) -> Result<ReceiptOutputAudio, DownloadCommitFailure> {
    match (source, output.audio.as_ref()) {
        (
            ManifestAudio::Recorded {
                sample_rate,
                channels,
                ..
            },
            Some(audio),
        ) if audio.sample_rate_hz == *sample_rate && audio.channels == *channels => {
            if audio.codec != "aac" {
                return Err(DownloadCommitFailure::retryable(
                    "derived output audio is not AAC",
                ));
            }
            Ok(ReceiptOutputAudio::Present {
                codec: audio.codec.clone(),
                sample_rate: audio.sample_rate_hz,
                channels: audio.channels,
            })
        }
        (ManifestAudio::NotRecorded, None) => Ok(ReceiptOutputAudio::Absent {
            reason: "source-not-recorded".to_string(),
        }),
        _ => Err(DownloadCommitFailure::retryable(
            "derived output audio does not match source recording state",
        )),
    }
}

fn validate_receipt(
    receipt: &DerivedMediaReceipt,
    source: &ParsedSource,
    output_filename: &str,
    output_path: &Path,
    output_bytes: u64,
) -> Result<(), String> {
    validate_uuid_v7(&receipt.receipt_id, "receipt_id")?;
    if receipt.schema != RECEIPT_SCHEMA
        || (receipt.origin != "new-download" && receipt.origin != "existing-library-migration")
        || receipt.source_manifest.schema != SOURCE_SCHEMA
        || receipt.source_manifest.manifest_id != source.manifest.manifest_id
        || receipt.source_manifest.session_id != source.manifest.session_id
        || receipt.source_manifest.volume_id != source.manifest.volume_id
        || receipt.source_manifest.bytes != source.bytes
        || receipt.source_manifest.sha256 != source.sha256
        || receipt.input_artifacts != source.inputs
        || receipt.transformer.name != "openaria-bridge-desktop"
        || receipt.transformer.recipe_id != RECIPE_ID
        || receipt.transformer.recipe_version != 1
        || !is_semver(&receipt.transformer.version)
    {
        return Err("derived media receipt source or transformer binding is invalid".to_string());
    }
    let actual_output_sha256 = hash_file(output_path)?;
    if receipt.output.artifact_id != receipt.output.sha256
        || receipt.output.sha256 != actual_output_sha256
        || receipt.output.filename != output_filename
        || receipt.output.role != "media.derived"
        || receipt.output.media_type != "video/mp4"
        || receipt.output.container != "mp4"
        || receipt.output.bytes != output_bytes
        || receipt.output.video_codec != "h264"
        || receipt.output.layout != "left-right-side-by-side"
        || receipt.output.eye_width != source.manifest.camera.eye_width
        || receipt.output.width != source.manifest.camera.width
        || receipt.output.height != source.manifest.camera.height
        || receipt.output.eye_width.checked_mul(2) != Some(receipt.output.width)
        || receipt.output.sha256 == source.sha256
        || source
            .inputs
            .iter()
            .any(|input| input.sha256 == receipt.output.sha256)
    {
        return Err("derived media receipt output binding is invalid".to_string());
    }
    validate_receipt_audio(&receipt.output.audio, &source.manifest.audio)?;

    let timeline = &receipt.timeline_verification;
    validate_timeline_receipt(timeline, source, &receipt.output)?;
    if receipt.canonicalization.state != "committed"
        || receipt.canonicalization.local_asset != "derived-output"
        || receipt.canonicalization.required_upload_assets
            != ["derived-output", "derived-media-receipt"]
        || receipt.canonicalization.source_inputs != "temporary-delete-after-commit"
        || receipt.provenance.derived_authorship != "openaria-bridge-desktop"
        || receipt.provenance.source_manifest_signature != "not-declared-by-device-session-v2"
        || receipt.provenance.device_signature_inheritance != "forbidden"
        || receipt.provenance.derived_output_signature != "not-device-signed"
    {
        return Err("derived media receipt canonicalization or provenance is invalid".to_string());
    }
    let sealed_at = parse_timestamp(&source.manifest.sealed_at, "sealed_at")?;
    let verified_at = parse_timestamp(&timeline.verified_at, "verified_at")?;
    let created_at = parse_timestamp(&receipt.created_at, "created_at")?;
    let committed_at = parse_timestamp(
        &receipt.canonicalization.committed_at,
        "canonicalization.committed_at",
    )?;
    if sealed_at > verified_at || verified_at > created_at || created_at > committed_at {
        return Err("derived media receipt timestamps are out of order".to_string());
    }
    Ok(())
}

fn validate_timeline_receipt(
    timeline: &SessionExportTimelineVerification,
    source: &ParsedSource,
    output: &ReceiptOutput,
) -> Result<(), String> {
    let source_video_tick_ns = ceil_positive_timeline_nanoseconds(reciprocal_decimal_rate(
        &source.manifest.camera.effective_fps,
        "camera.effective_fps",
    )?)?;
    let encoding_audio_frame_ns = match &source.manifest.audio {
        ManifestAudio::Recorded { sample_rate, .. } => Some(ceil_ratio_u64(
            1_024_u128 * 1_000_000_000_u128,
            u128::from(*sample_rate),
        )?),
        ManifestAudio::NotRecorded => None,
    };
    let allowed_residual_ns = source_video_tick_ns.max(encoding_audio_frame_ns.unwrap_or(0));
    let source_video_start_ns = source
        .manifest
        .video
        .segments
        .iter()
        .map(|segment| exact_decimal_nanoseconds(&segment.start_time_seconds))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or_else(|| "source video timeline is empty".to_string())?;
    let source_video_end_ns = source
        .manifest
        .video
        .segments
        .iter()
        .map(|segment| exact_decimal_nanoseconds(&segment.end_time_seconds))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| "source video timeline is empty".to_string())?;
    let (expected_leading_gap_ns, source_audio_range) = match &source.manifest.audio {
        ManifestAudio::Recorded { sync, .. } => {
            let start = exact_decimal_nanoseconds(&sync.start_time_seconds)?;
            let end = exact_decimal_nanoseconds(&sync.end_time_seconds)?;
            (
                u64::try_from((start - source_video_start_ns).max(0))
                    .map_err(|_| "audio leading gap exceeds u64".to_string())?,
                Some((start, end)),
            )
        }
        ManifestAudio::NotRecorded => (0, None),
    };

    if timeline.policy_id != "openaria.manifest-timeline.v1"
        || timeline.verdict != TimelineVerificationVerdict::Pass
        || timeline.left_right_pairing != TimelineVerificationVerdict::Pass
        || timeline.source_manifest_sha256 != source.sha256
        || timeline.paired_frames != source.manifest.frames.count
        || timeline.probe_summary.output_sha256 != output.sha256
        || timeline.probe_summary.output_bytes != output.bytes
        || timeline.probe_summary.video_streams != 1
        || timeline.probe_summary.frame_count != source.manifest.frames.count
        || timeline.source_video_tick_ns != source_video_tick_ns
        || timeline.encoding_audio_frame_ns != encoding_audio_frame_ns
        || timeline.allowed_residual_ns != allowed_residual_ns
        || timeline.preserved_leading_gap_ns != expected_leading_gap_ns
        || timeline.video_start_residual_ns.unsigned_abs() > allowed_residual_ns
        || timeline.video_end_residual_ns.unsigned_abs() > allowed_residual_ns
        || timeline
            .audio_start_residual_ns
            .is_some_and(|value| value.unsigned_abs() > allowed_residual_ns)
        || timeline
            .audio_end_residual_ns
            .is_some_and(|value| value.unsigned_abs() > allowed_residual_ns)
    {
        return Err("derived media receipt timeline verdict is invalid".to_string());
    }
    match &source.manifest.audio {
        ManifestAudio::Recorded { .. }
            if timeline.probe_summary.audio_streams == 1
                && timeline.audio_start_residual_ns.is_some()
                && timeline.audio_end_residual_ns.is_some() => {}
        ManifestAudio::NotRecorded
            if timeline.probe_summary.audio_streams == 0
                && timeline.audio_start_residual_ns.is_none()
                && timeline.audio_end_residual_ns.is_none() => {}
        _ => return Err("derived media receipt audio timeline state is invalid".to_string()),
    }
    validate_sha256(
        &timeline.probe_summary.report_sha256,
        "timeline probe report digest",
    )?;

    let mut probed_starts =
        vec![i128::from(source_video_start_ns) + i128::from(timeline.video_start_residual_ns)];
    let mut probed_ends =
        vec![i128::from(source_video_end_ns) + i128::from(timeline.video_end_residual_ns)];
    if let Some((source_audio_start, source_audio_end)) = source_audio_range {
        let audio_start_residual = timeline
            .audio_start_residual_ns
            .ok_or_else(|| "recorded audio lacks a start residual".to_string())?;
        let audio_end_residual = timeline
            .audio_end_residual_ns
            .ok_or_else(|| "recorded audio lacks an end residual".to_string())?;
        probed_starts.push(i128::from(source_audio_start) + i128::from(audio_start_residual));
        probed_ends.push(i128::from(source_audio_end) + i128::from(audio_end_residual));
    }
    let first = probed_starts
        .into_iter()
        .min()
        .ok_or_else(|| "derived probe has no stream start".to_string())?;
    let last = probed_ends
        .into_iter()
        .max()
        .ok_or_else(|| "derived probe has no stream end".to_string())?;
    let duration_ns = u64::try_from(last - first)
        .ok()
        .filter(|duration| *duration > 0)
        .ok_or_else(|| "derived probe duration is invalid".to_string())?;
    if timeline.probe_summary.duration_ns != duration_ns {
        return Err("derived media receipt probe duration is not timeline-derived".to_string());
    }
    Ok(())
}

fn validate_receipt_audio(
    audio: &ReceiptOutputAudio,
    source: &ManifestAudio,
) -> Result<(), String> {
    match (audio, source) {
        (
            ReceiptOutputAudio::Present {
                codec,
                sample_rate,
                channels,
            },
            ManifestAudio::Recorded {
                sample_rate: source_rate,
                channels: source_channels,
                ..
            },
        ) if codec == "aac" && *sample_rate == *source_rate && *channels == *source_channels => {
            Ok(())
        }
        (ReceiptOutputAudio::Absent { reason }, ManifestAudio::NotRecorded)
            if reason == "source-not-recorded" =>
        {
            Ok(())
        }
        _ => Err("derived media receipt audio output is invalid".to_string()),
    }
}

fn write_receipt_atomically(
    path: &Path,
    receipt: &DerivedMediaReceipt,
) -> Result<(), DownloadCommitFailure> {
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|error| {
        DownloadCommitFailure::permanent(format!("serialize derived media receipt: {error}"))
    })?;
    let temporary = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| retryable_io("create receipt staging file", error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| retryable_io("write receipt staging file", error))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| retryable_io("publish receipt file", error))?;
    Ok(())
}

fn publish_attempt(
    attempt: &Path,
    staging: &SessionStaging,
    job_id: &str,
    source: &ParsedSource,
    inject_backup_cleanup_failure: bool,
) -> Result<(), DownloadCommitFailure> {
    let published = staging.published_dir();
    let parent = published
        .parent()
        .ok_or_else(|| DownloadCommitFailure::permanent("published session path has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| retryable_io("create device library", error))?;
    reject_link_or_non_directory(parent).map_err(DownloadCommitFailure::permanent)?;
    let backup = previous_canonical_backup_dir(staging, job_id);

    let had_published = match fs::symlink_metadata(&published) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(DownloadCommitFailure::permanent(
                    "existing published session is not a real directory",
                ));
            }
            let ownership = create_backup_ownership_scope(staging, source, job_id)?;
            let previous = backup.join(BACKUP_PREVIOUS_DIRNAME);
            fs::rename(&published, &previous)
                .map_err(|error| retryable_io("stage previous canonical session", error))?;
            write_previous_directory_ownership_token(&previous, &ownership.previous_token)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(retryable_io("inspect published session", error)),
    };

    if let Err(error) = fs::rename(attempt, &published) {
        if had_published {
            if let Err(restore_error) = fs::rename(backup.join(BACKUP_PREVIOUS_DIRNAME), &published)
            {
                return Err(DownloadCommitFailure::permanent(format!(
                    "canonical publish failed ({error}) and previous session restore failed ({restore_error}); backup is {}",
                    backup.display()
                )));
            }
        }
        return Err(retryable_io("publish canonical derived session", error));
    }

    if let Err(validation_error) = canonical_assets_in_session_dir(&published, source) {
        let remove_result = fs::remove_dir_all(&published);
        let restore_result = if had_published {
            fs::rename(backup.join(BACKUP_PREVIOUS_DIRNAME), &published)
        } else {
            Ok(())
        };
        if let Err(error) = remove_result {
            return Err(DownloadCommitFailure::permanent(format!(
                "published canonical validation failed ({validation_error}) and invalid output cleanup failed ({error})"
            )));
        }
        if let Err(error) = restore_result {
            return Err(DownloadCommitFailure::permanent(format!(
                "published canonical validation failed ({validation_error}) and previous session restore failed ({error}); backup is {}",
                backup.display()
            )));
        }
        return Err(DownloadCommitFailure::retryable(format!(
            "published canonical validation failed: {validation_error}"
        )));
    }

    if had_published {
        cleanup_previous_canonical_backup(staging, source, job_id, inject_backup_cleanup_failure)?;
    }
    Ok(())
}

fn create_backup_ownership_scope(
    staging: &SessionStaging,
    source: &ParsedSource,
    job_id: &str,
) -> Result<BackupOwnership, DownloadCommitFailure> {
    let revision_dir = staging.revision_dir();
    fs::create_dir_all(&revision_dir)
        .map_err(|error| retryable_io("create backup ownership parent", error))?;
    reject_link_or_non_directory(&revision_dir).map_err(DownloadCommitFailure::permanent)?;
    let backup = previous_canonical_backup_dir(staging, job_id);
    match fs::symlink_metadata(&backup) {
        Ok(_) => {
            return Err(DownloadCommitFailure::retryable(
                "a previous canonical backup still requires ownership-bound retry",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(retryable_io("inspect canonical backup scope", error)),
    }
    fs::create_dir(&backup)
        .map_err(|error| retryable_io("create canonical backup scope", error))?;
    let ownership = new_backup_ownership(staging, source, job_id);
    let ownership_bytes = serde_json::to_vec_pretty(&ownership).map_err(|error| {
        DownloadCommitFailure::permanent(format!(
            "serialize previous canonical backup ownership: {error}"
        ))
    })?;
    let ownership_path = backup.join(BACKUP_OWNERSHIP_FILENAME);
    let write_result = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&ownership_path)
        .and_then(|mut file| {
            file.write_all(&ownership_bytes)?;
            file.sync_all()
        });
    if let Err(error) = write_result {
        let _ = fs::remove_dir_all(&backup);
        return Err(retryable_io(
            "write previous canonical backup ownership",
            error,
        ));
    }
    Ok(ownership)
}

fn write_previous_directory_ownership_token(
    previous: &Path,
    token: &str,
) -> Result<(), DownloadCommitFailure> {
    let token_path = previous.join(BACKUP_PREVIOUS_TOKEN_FILENAME);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&token_path)
        .map_err(|error| retryable_io("create previous directory ownership token", error))?;
    file.write_all(token.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| retryable_io("write previous directory ownership token", error))?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupOwnership {
    schema: String,
    job_id_sha256: String,
    source_manifest_sha256: String,
    device_id: String,
    session_id: String,
    previous_token: String,
}

fn new_backup_ownership(
    staging: &SessionStaging,
    source: &ParsedSource,
    job_id: &str,
) -> BackupOwnership {
    BackupOwnership {
        schema: BACKUP_OWNERSHIP_SCHEMA.to_string(),
        job_id_sha256: sha256_bytes(job_id.as_bytes()),
        source_manifest_sha256: source.sha256.clone(),
        device_id: staging.device_id().to_string(),
        session_id: staging.session_id().to_string(),
        previous_token: new_uuid_v7(),
    }
}

fn backup_ownership_matches_commit(
    ownership: &BackupOwnership,
    staging: &SessionStaging,
    source: &ParsedSource,
    job_id: &str,
) -> bool {
    ownership.schema == BACKUP_OWNERSHIP_SCHEMA
        && ownership.job_id_sha256 == sha256_bytes(job_id.as_bytes())
        && ownership.source_manifest_sha256 == source.sha256
        && ownership.device_id == staging.device_id()
        && ownership.session_id == staging.session_id()
        && validate_uuid_v7(&ownership.previous_token, "backup previous_token").is_ok()
}

fn previous_canonical_backup_dir(staging: &SessionStaging, job_id: &str) -> PathBuf {
    staging
        .revision_dir()
        .join(format!(".ylx-backup-{}", sha256_bytes(job_id.as_bytes())))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviousCanonicalBackup {
    Absent,
    OwnershipOnly,
    WithPrevious,
}

fn inspect_previous_canonical_backup(
    staging: &SessionStaging,
    source: &ParsedSource,
    job_id: &str,
) -> Result<PreviousCanonicalBackup, DownloadCommitFailure> {
    let backup = previous_canonical_backup_dir(staging, job_id);
    let metadata = match fs::symlink_metadata(&backup) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PreviousCanonicalBackup::Absent);
        }
        Err(error) => return Err(retryable_io("inspect previous canonical backup", error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DownloadCommitFailure::permanent(
            "previous canonical backup is not an ownership-scoped real directory",
        ));
    }

    let entries = fs::read_dir(&backup)
        .map_err(|error| retryable_io("read previous canonical backup", error))?
        .map(|entry| {
            entry
                .map_err(|error| retryable_io("read previous canonical backup entry", error))
                .and_then(|entry| {
                    entry.file_name().into_string().map_err(|_| {
                        DownloadCommitFailure::permanent(
                            "previous canonical backup contains a non-UTF-8 entry",
                        )
                    })
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let marker_only = BTreeSet::from([BACKUP_OWNERSHIP_FILENAME.to_string()]);
    let with_previous = BTreeSet::from([
        BACKUP_OWNERSHIP_FILENAME.to_string(),
        BACKUP_PREVIOUS_DIRNAME.to_string(),
    ]);
    if entries != marker_only && entries != with_previous {
        return Err(DownloadCommitFailure::permanent(
            "previous canonical backup contains foreign entries",
        ));
    }

    let ownership_path = backup.join(BACKUP_OWNERSHIP_FILENAME);
    let ownership_metadata =
        plain_regular_file_metadata(&ownership_path).map_err(DownloadCommitFailure::permanent)?;
    if ownership_metadata.len() == 0 || ownership_metadata.len() > MAX_BACKUP_OWNERSHIP_BYTES {
        return Err(DownloadCommitFailure::permanent(
            "previous canonical backup ownership marker has an invalid byte length",
        ));
    }
    let ownership_bytes = read_bounded(&ownership_path, ownership_metadata.len())
        .map_err(DownloadCommitFailure::retryable)?;
    let ownership_value = parse_strict_json(&ownership_bytes).map_err(|error| {
        DownloadCommitFailure::permanent(format!(
            "invalid previous canonical backup ownership JSON: {error}"
        ))
    })?;
    let ownership: BackupOwnership = serde_json::from_value(ownership_value).map_err(|error| {
        DownloadCommitFailure::permanent(format!(
            "invalid previous canonical backup ownership shape: {error}"
        ))
    })?;
    if !backup_ownership_matches_commit(&ownership, staging, source, job_id) {
        return Err(DownloadCommitFailure::permanent(
            "previous canonical backup ownership does not match this commit",
        ));
    }

    if entries == with_previous {
        let previous = backup.join(BACKUP_PREVIOUS_DIRNAME);
        reject_link_or_non_directory(&previous).map_err(DownloadCommitFailure::permanent)?;
        let token_path = previous.join(BACKUP_PREVIOUS_TOKEN_FILENAME);
        let token_metadata = plain_regular_file_metadata(&token_path).map_err(|error| {
            DownloadCommitFailure::permanent(format!(
                "previous directory ownership token is invalid: {error}"
            ))
        })?;
        if token_metadata.len() == 0 || token_metadata.len() > MAX_BACKUP_PREVIOUS_TOKEN_BYTES {
            return Err(DownloadCommitFailure::permanent(
                "previous directory ownership token has an invalid byte length",
            ));
        }
        let token = read_bounded(&token_path, token_metadata.len()).map_err(|error| {
            DownloadCommitFailure::retryable(format!(
                "read previous directory ownership token: {error}"
            ))
        })?;
        if token != ownership.previous_token.as_bytes() {
            return Err(DownloadCommitFailure::permanent(
                "previous directory ownership token does not match its wrapper",
            ));
        }
        Ok(PreviousCanonicalBackup::WithPrevious)
    } else {
        Ok(PreviousCanonicalBackup::OwnershipOnly)
    }
}

fn cleanup_previous_canonical_backup(
    staging: &SessionStaging,
    source: &ParsedSource,
    job_id: &str,
    inject_failure: bool,
) -> Result<(), DownloadCommitFailure> {
    if inspect_previous_canonical_backup(staging, source, job_id)?
        != PreviousCanonicalBackup::WithPrevious
    {
        return Ok(());
    }
    if inject_failure {
        return Err(DownloadCommitFailure::retryable(
            "previous canonical backup cleanup failed after canonical publication; retry will validate the existing bundle and retry cleanup: injected backup cleanup failure",
        ));
    }
    let previous = previous_canonical_backup_dir(staging, job_id).join(BACKUP_PREVIOUS_DIRNAME);
    fs::remove_dir_all(&previous).map_err(|error| {
        DownloadCommitFailure::retryable(format!(
            "previous canonical backup cleanup failed after canonical publication; retry will validate the existing bundle and retry cleanup: {error}"
        ))
    })?;
    Ok(())
}

fn cleanup_source_staging(
    staging: &SessionStaging,
    inject_failure: bool,
) -> Result<DownloadCommitOutcome, DownloadCommitFailure> {
    let cleanup = if inject_failure {
        Err("injected source staging cleanup failure".to_string())
    } else {
        staging.discard().map_err(|error| error.to_string())
    };
    if let Err(error) = cleanup {
        eprintln!(
            "[composition] canonical derived session committed, but source staging cleanup failed for {}/{}: {}",
            staging.device_id(),
            staging.session_id(),
            error
        );
        return Err(DownloadCommitFailure::retryable(format!(
            "source staging cleanup failed after canonical publication; retry will validate the existing bundle and retry cleanup: {error}"
        )));
    }
    Ok(DownloadCommitOutcome::clean())
}

fn derived_attempt_dir(staging: &SessionStaging, job_id: &str) -> PathBuf {
    staging
        .staging_root()
        .join(format!("derived-{}", sha256_bytes(job_id.as_bytes())))
}

fn prepare_empty_attempt(path: &Path) -> Result<(), DownloadCommitFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(DownloadCommitFailure::permanent(
                "derived attempt path is not a real directory",
            ));
        }
        Ok(_) => fs::remove_dir_all(path)
            .map_err(|error| retryable_io("clear prior derived attempt", error))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(retryable_io("inspect derived attempt", error)),
    }
    fs::create_dir_all(path).map_err(|error| retryable_io("create derived attempt", error))?;
    Ok(())
}

fn cleanup_failed_attempt(path: &Path) {
    if let Err(error) = fs::remove_dir_all(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "[composition] failed derived attempt cleanup at {}: {}",
                path.display(),
                error
            );
        }
    }
}

fn verify_manifest_files_in_root(
    manifest: &DeviceSessionManifest,
    source_root: &Path,
) -> Result<(), String> {
    reject_link_or_non_directory(source_root)?;
    let canonical_root = fs::canonicalize(source_root)
        .map_err(|error| format!("canonicalize legacy source root: {error}"))?;
    for artifact in manifest.all_artifacts() {
        let path = resolve_relative_regular_file(&canonical_root, &artifact.path, false)?;
        let metadata = plain_regular_file_metadata(&path)?;
        if metadata.len() != artifact.bytes || hash_file(&path)? != artifact.sha256 {
            return Err(format!(
                "legacy source artifact no longer matches the exact manifest: {}",
                artifact.artifact_id
            ));
        }
    }
    Ok(())
}

fn find_legacy_processed_output(
    session_root: &Path,
    session_id: &str,
    legacy_processed_files: &[SessionFile],
) -> Result<Option<PathBuf>, String> {
    reject_link_or_non_directory(session_root)?;
    let canonical_root = fs::canonicalize(session_root)
        .map_err(|error| format!("canonicalize legacy session root: {error}"))?;
    let mut candidates = Vec::new();
    for file in legacy_processed_files.iter().filter(|file| {
        file.display_path.ends_with(".mp4")
            && file.display_path != RECEIPT_DISPLAY_PATH
            && file.display_path.starts_with("processed/")
    }) {
        let relative = Path::new(&file.display_path);
        let path = resolve_relative_regular_file(&canonical_root, relative, true)?;
        let metadata = regular_file_metadata(&path)?;
        if metadata.len() != file.bytes || hash_file(&path)? != file.sha256 {
            return Err(format!(
                "legacy processed output differs from its durable descriptor: {}",
                file.display_path
            ));
        }
        candidates.push(path);
    }
    if candidates.is_empty() {
        for relative in [
            PathBuf::from(format!("processed/{session_id}.mp4")),
            PathBuf::from("processed/sbs.mp4"),
        ] {
            match resolve_relative_regular_file(&canonical_root, &relative, true) {
                Ok(path) => candidates.push(path),
                Err(error) if error.contains("does not exist") => {}
                Err(error) => return Err(error),
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [] => Ok(None),
        [candidate] => Ok(Some(candidate.clone())),
        _ => Err("legacy library contains multiple ambiguous processed MP4 candidates".to_string()),
    }
}

fn resolve_relative_regular_file(
    canonical_root: &Path,
    relative: &Path,
    nonempty: bool,
) -> Result<PathBuf, String> {
    validate_relative_artifact_path(relative)?;
    let candidate = canonical_root.join(relative);
    let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        format!(
            "legacy file {} does not exist or is unreadable: {error}",
            candidate.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || (nonempty && metadata.len() == 0)
    {
        return Err(format!(
            "legacy file is not a suitable regular file: {}",
            candidate.display()
        ));
    }
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| format!("canonicalize legacy file {}: {error}", candidate.display()))?;
    if !canonical.starts_with(canonical_root) {
        return Err(format!(
            "legacy file escapes the session root: {}",
            candidate.display()
        ));
    }
    Ok(canonical)
}

fn copy_regular_file_durably(
    source: &Path,
    destination: &Path,
) -> Result<(), DownloadCommitFailure> {
    regular_file_metadata(source).map_err(DownloadCommitFailure::permanent)?;
    let mut input = fs::File::open(source)
        .map_err(|error| retryable_io("open legacy processed output", error))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| retryable_io("create canonical migration output", error))?;
    std::io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|error| retryable_io("copy canonical migration output", error))?;
    Ok(())
}

fn commit_failure_message(error: DownloadCommitFailure) -> String {
    match error.code {
        FailureCode::Other(detail) => detail,
        code => format!("derived commit failed with {code:?}"),
    }
}

fn plain_regular_file_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect regular file {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "expected a regular file without symlinks: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = plain_regular_file_metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("expected a non-empty file: {}", path.display()));
    }
    Ok(metadata)
}

fn reject_link_or_non_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect directory {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("expected a real directory: {}", path.display()));
    }
    Ok(())
}

fn read_bounded(path: &Path, length: u64) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(length).map_err(|_| "file is too large to read".to_string())?;
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(length.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() != capacity {
        return Err(format!(
            "file size changed while reading {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open {} for SHA-256: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {} for SHA-256: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase SHA-256 digest"))
    }
}

fn validate_uuid_v7(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let punctuation = bytes.len() == 36
        && bytes.get(8) == Some(&b'-')
        && bytes.get(13) == Some(&b'-')
        && bytes.get(18) == Some(&b'-')
        && bytes.get(23) == Some(&b'-');
    let hexadecimal = bytes.iter().enumerate().all(|(index, byte)| {
        matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
    });
    if punctuation
        && hexadecimal
        && bytes.get(14) == Some(&b'7')
        && bytes
            .get(19)
            .is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase RFC 9562 UUIDv7"))
    }
}

fn validate_uuid_v4(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let punctuation = bytes.len() == 36
        && bytes.get(8) == Some(&b'-')
        && bytes.get(13) == Some(&b'-')
        && bytes.get(18) == Some(&b'-')
        && bytes.get(23) == Some(&b'-');
    let hexadecimal = bytes.iter().enumerate().all(|(index, byte)| {
        matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
    });
    if punctuation
        && hexadecimal
        && bytes.get(14) == Some(&b'4')
        && bytes
            .get(19)
            .is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase RFC 9562 UUIDv4"))
    }
}

fn new_uuid_v7() -> String {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut bytes = *uuid::Uuid::new_v4().as_bytes();
    let timestamp = milliseconds.to_be_bytes();
    bytes[..6].copy_from_slice(&timestamp[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn decimal_time(number: &Number) -> Result<TimelineTime, String> {
    TimelineTime::from_nanoseconds(exact_decimal_nanoseconds(number)?)
        .map_err(|error| error.to_string())
}

fn exact_decimal_nanoseconds(number: &Number) -> Result<i64, String> {
    let (numerator, denominator) = decimal_ratio(number)?;
    let scaled = numerator
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "decimal time exceeds the supported range".to_string())?;
    if scaled % denominator != 0 {
        return Err(format!(
            "manifest decimal time {} does not resolve to exact integer nanoseconds",
            number
        ));
    }
    i64::try_from(scaled / denominator)
        .map_err(|_| "decimal time exceeds the supported range".to_string())
}

fn rounded_decimal_nanoseconds(number: &Number) -> Result<i64, String> {
    let (numerator, denominator) = decimal_ratio(number)?;
    let nanoseconds = rounded_scaled_ratio(numerator, denominator, 1_000_000_000)
        .ok_or_else(|| "decimal time exceeds the supported range".to_string())?;
    i64::try_from(nanoseconds).map_err(|_| "decimal time exceeds the supported range".to_string())
}

fn session_time_from_audio_sample(
    session_start_ns: i64,
    sample: u64,
    sample_rate: u32,
) -> Result<TimelineTime, String> {
    let offset_ns =
        rounded_scaled_ratio(u128::from(sample), u128::from(sample_rate), 1_000_000_000)
            .ok_or_else(|| "audio sample time exceeds the supported range".to_string())?;
    let offset_ns = i64::try_from(offset_ns)
        .map_err(|_| "audio sample time exceeds the supported range".to_string())?;
    let session_time_ns = session_start_ns
        .checked_add(offset_ns)
        .ok_or_else(|| "audio session time exceeds the supported range".to_string())?;
    TimelineTime::from_nanoseconds(session_time_ns).map_err(|error| error.to_string())
}

fn rounded_scaled_ratio(numerator: u128, denominator: u128, scale: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    let scale_divisor = greatest_common_divisor(scale, denominator);
    let scaled_numerator = numerator.checked_mul(scale / scale_divisor)?;
    let scaled_denominator = denominator / scale_divisor;
    let quotient = scaled_numerator / scaled_denominator;
    let remainder = scaled_numerator % scaled_denominator;
    quotient.checked_add(u128::from(
        remainder >= scaled_denominator - scaled_denominator / 2,
    ))
}

fn reciprocal_decimal_rate(number: &Number, label: &str) -> Result<TimelineTime, String> {
    let (numerator, denominator) = decimal_ratio(number)?;
    if numerator == 0 {
        return Err(format!("{label} must be positive"));
    }
    let divisor = greatest_common_divisor(denominator, numerator);
    let reduced_numerator = denominator / divisor;
    let reduced_denominator = numerator / divisor;
    if reduced_denominator <= 1_000_000_000 {
        return TimelineTime::new(
            i64::try_from(reduced_numerator)
                .map_err(|_| format!("{label} exceeds the supported range"))?,
            u64::try_from(reduced_denominator)
                .map_err(|_| format!("{label} exceeds the supported range"))?,
        )
        .map_err(|error| error.to_string());
    }

    let tick_nanoseconds = rounded_scaled_ratio(denominator, numerator, 1_000_000_000)
        .ok_or_else(|| format!("{label} exceeds the supported range"))?;
    if tick_nanoseconds == 0 {
        return Err(format!(
            "{label} exceeds the supported nanosecond timeline precision"
        ));
    }
    TimelineTime::from_nanoseconds(
        i64::try_from(tick_nanoseconds)
            .map_err(|_| format!("{label} exceeds the supported range"))?,
    )
    .map_err(|error| error.to_string())
}

fn decimal_ratio(number: &Number) -> Result<(u128, u128), String> {
    let text = number.to_string();
    if text.starts_with('-') {
        return Err(format!("decimal value {text} must be non-negative"));
    }
    let exponent_index = text.find(['e', 'E']);
    let (mantissa, exponent) = exponent_index.map_or((text.as_str(), 0_i32), |index| {
        let (mantissa, exponent) = text.split_at(index);
        let exponent = exponent[1..].parse::<i32>().unwrap_or(i32::MIN);
        (mantissa, exponent)
    });
    if exponent == i32::MIN {
        return Err(format!("decimal value {text} has an invalid exponent"));
    }
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("decimal value {text} has an invalid mantissa"));
    }
    let digits = format!("{whole}{fraction}");
    let mut numerator = digits
        .parse::<u128>()
        .map_err(|_| format!("decimal value {text} exceeds the supported range"))?;
    let decimal_places = i32::try_from(fraction.len())
        .map_err(|_| format!("decimal value {text} exceeds the supported range"))?;
    let scale = decimal_places
        .checked_sub(exponent)
        .ok_or_else(|| format!("decimal value {text} exceeds the supported range"))?;
    let denominator = if scale >= 0 {
        10_u128
            .checked_pow(
                u32::try_from(scale)
                    .map_err(|_| format!("decimal value {text} exceeds the supported range"))?,
            )
            .ok_or_else(|| format!("decimal value {text} exceeds the supported range"))?
    } else {
        let multiplier = 10_u128
            .checked_pow(scale.unsigned_abs())
            .ok_or_else(|| format!("decimal value {text} exceeds the supported range"))?;
        numerator = numerator
            .checked_mul(multiplier)
            .ok_or_else(|| format!("decimal value {text} exceeds the supported range"))?;
        1
    };
    let divisor = greatest_common_divisor(numerator, denominator);
    Ok((numerator / divisor, denominator / divisor))
}

const fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    if left == 0 {
        1
    } else {
        left
    }
}

fn ceil_positive_timeline_nanoseconds(value: TimelineTime) -> Result<u64, String> {
    if value.numerator() <= 0 {
        return Err("timeline duration must be positive".to_string());
    }
    ceil_ratio_u64(
        u128::try_from(value.numerator())
            .map_err(|_| "timeline duration is negative".to_string())?
            .checked_mul(1_000_000_000)
            .ok_or_else(|| "timeline duration exceeds the supported range".to_string())?,
        u128::from(value.denominator()),
    )
}

fn ceil_ratio_u64(numerator: u128, denominator: u128) -> Result<u64, String> {
    if denominator == 0 || numerator == 0 {
        return Err("positive ratio is required".to_string());
    }
    let quotient = numerator
        .checked_add(denominator - 1)
        .ok_or_else(|| "ratio exceeds the supported range".to_string())?
        / denominator;
    u64::try_from(quotient).map_err(|_| "ratio exceeds the supported range".to_string())
}

fn sample_clock_position_matches(
    declared_ns: i64,
    sync_start_ns: i64,
    sample: u64,
    sample_rate: u32,
    tolerance_ns: u64,
) -> Result<bool, String> {
    let rate = i128::from(sample_rate);
    let declared = i128::from(declared_ns)
        .checked_mul(rate)
        .ok_or_else(|| "audio clock position exceeds the supported range".to_string())?;
    let expected = i128::from(sync_start_ns)
        .checked_mul(rate)
        .and_then(|base| {
            i128::from(sample)
                .checked_mul(1_000_000_000)
                .and_then(|offset| base.checked_add(offset))
        })
        .ok_or_else(|| "audio sample position exceeds the supported range".to_string())?;
    let tolerance = i128::from(tolerance_ns)
        .checked_mul(rate)
        .ok_or_else(|| "audio tolerance exceeds the supported range".to_string())?;
    Ok((declared - expected).unsigned_abs() <= tolerance.unsigned_abs())
}

fn validate_relative_artifact_path(path: &Path) -> Result<(), String> {
    let raw = path
        .to_str()
        .ok_or_else(|| "manifest artifact path is not UTF-8".to_string())?;
    if raw.is_empty()
        || raw.len() > 1024
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
        || raw == "manifest.json"
        || raw == "recording.json"
        || raw.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || segment == "manifest.json"
                || segment == "recording.json"
                || segment.contains(".tmp")
        })
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "manifest artifact path is not a safe schema-relative path: {raw:?}"
        ));
    }
    Ok(())
}

fn parse_timestamp(
    value: &str,
    label: &str,
) -> Result<chrono::DateTime<chrono::FixedOffset>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|error| format!("{label} is not an RFC 3339 timestamp: {error}"))
}

fn is_semver(value: &str) -> bool {
    let (numeric, suffix) = value
        .split_once('-')
        .map_or((value, None), |(numeric, suffix)| (numeric, Some(suffix)));
    if suffix.is_some_and(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        return false;
    }
    let mut parts = numeric.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    valid && parts.next().is_none()
}

fn retryable_io(context: &str, error: std::io::Error) -> DownloadCommitFailure {
    DownloadCommitFailure::retryable(format!("{context}: {error}"))
}

fn ensure_commit_not_cancelled(
    control: &DownloadCommitControl,
) -> Result<(), DownloadCommitFailure> {
    if control.is_cancel_requested() {
        Err(DownloadCommitFailure::cancelled())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ylx_transfer_adapters::session_export::{
        SessionExportOutputAudio, SessionExportProbeSummary,
    };
    use ylx_transfer_core::domain::{DeviceId, FileId, SessionId};
    use ylx_transfer_core::library::download::VerifiedFile;
    use ylx_transfer_core::transfer::queue::{JobFile, TransferRequest};

    const SOURCE_MANIFEST: &str = include_str!(
        "../../../contracts/fixtures/valid/ylx-device-session-v2.audio-recorded-multi-segment.json"
    );

    fn collect_artifacts(value: &serde_json::Value, artifacts: &mut Vec<serde_json::Value>) {
        match value {
            serde_json::Value::Object(object) => {
                let fields = [
                    "artifact_id",
                    "role",
                    "path",
                    "media_type",
                    "bytes",
                    "sha256",
                ];
                if fields.iter().all(|field| object.contains_key(*field)) {
                    artifacts.push(serde_json::json!({
                        "id": object["artifact_id"],
                        "display_path": object["path"],
                        "role": object["role"],
                        "size_bytes": object["bytes"],
                        "sha256": object["sha256"],
                        "media_type": object["media_type"],
                    }));
                    return;
                }
                for child in object.values() {
                    collect_artifacts(child, artifacts);
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    collect_artifacts(child, artifacts);
                }
            }
            _ => {}
        }
    }

    fn compatibility_publication(manifest: &serde_json::Value) -> Vec<u8> {
        let source_manifest_json =
            serde_json::to_string(manifest).expect("serialize source manifest fixture");
        let source_manifest_sha256 = sha256_bytes(source_manifest_json.as_bytes());
        let mut files = Vec::new();
        collect_artifacts(manifest, &mut files);
        files.sort_by(|left, right| {
            left["display_path"]
                .as_str()
                .cmp(&right["display_path"].as_str())
                .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
        });
        let total_bytes = files
            .iter()
            .map(|file| file["size_bytes"].as_u64().expect("artifact byte count"))
            .sum::<u64>();
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "session_id": manifest["session_id"],
            "revision": format!("sha256:{source_manifest_sha256}"),
            "total_bytes": total_bytes,
            "files": files,
            "source_schema": SOURCE_SCHEMA,
            "source_manifest_sha256": source_manifest_sha256,
            "source_manifest_json": source_manifest_json,
            "source_profile": "ylx-device-api-v4-lab-http",
            "receipt_origin": "client-derived-lab-compatibility",
            "device_authenticity": "not_asserted",
            "integrity_ok": true,
            "gateway_verification": {
                "actor": "gateway",
                "validator": {
                    "name": "openaria-conductor",
                    "version": "0.1.0",
                    "build_sha256": "a".repeat(64),
                },
                "manifest_sha256": source_manifest_sha256,
                "manifest_digest_valid": true,
                "verified_at": "2026-08-28T10:09:58Z",
                "verdict": "usable",
                "diagnostics": [],
            },
        }))
        .expect("serialize compatibility publication fixture")
    }

    fn source_manifest() -> serde_json::Value {
        serde_json::from_str(SOURCE_MANIFEST).expect("parse vendored valid source manifest")
    }

    struct ExportMustNotRun;

    impl SessionExporterPort for ExportMustNotRun {
        fn export(
            &self,
            _plan: &SessionExportPlan,
            _control: &DownloadCommitControl,
        ) -> Result<SessionExportReceipt, DownloadCommitFailure> {
            panic!("an idempotent cleanup retry must not export media again")
        }

        fn inspect_existing(
            &self,
            _plan: &SessionExportPlan,
        ) -> Result<SessionExportReceipt, String> {
            panic!("an idempotent cleanup retry must not inspect legacy media")
        }
    }

    struct SuccessfulTestExporter;

    impl SessionExporterPort for SuccessfulTestExporter {
        fn export(
            &self,
            plan: &SessionExportPlan,
            _control: &DownloadCommitControl,
        ) -> Result<SessionExportReceipt, DownloadCommitFailure> {
            fs::write(plan.output_path(), b"new canonical derived MP4")
                .map_err(|error| retryable_io("write test export", error))?;
            let output_size_bytes = fs::metadata(plan.output_path())
                .map_err(|error| retryable_io("inspect test export", error))?
                .len();
            let output_sha256 =
                hash_file(plan.output_path()).map_err(DownloadCommitFailure::retryable)?;
            let timing = plan.timing().expect("manifest-driven test export timing");
            let manifest = timing.manifest();
            let audio = manifest
                .audio
                .as_ref()
                .map(|audio| SessionExportOutputAudio {
                    codec: "aac".to_string(),
                    sample_rate_hz: audio.sample_rate_hz,
                    channels: audio.channels,
                });
            Ok(SessionExportReceipt {
                output_path: plan.output_path().to_path_buf(),
                video_segment_count: plan.video_segment_count(),
                audio_segment_count: plan.audio_segment_count(),
                output_size_bytes,
                timeline_verification: Some(SessionExportTimelineVerification {
                    policy_id: "openaria.manifest-timeline.v1".to_string(),
                    verdict: TimelineVerificationVerdict::Pass,
                    source_manifest_sha256: timing.source_manifest_sha256().to_string(),
                    left_right_pairing: TimelineVerificationVerdict::Pass,
                    paired_frames: timing.paired_frames(),
                    video_start_residual_ns: 0,
                    video_end_residual_ns: 0,
                    audio_start_residual_ns: audio.as_ref().map(|_| 0),
                    audio_end_residual_ns: audio.as_ref().map(|_| 0),
                    source_video_tick_ns: 33_333_334,
                    encoding_audio_frame_ns: audio.as_ref().map(|_| 21_333_334),
                    allowed_residual_ns: 33_333_334,
                    preserved_leading_gap_ns: 0,
                    verified_at: chrono::Utc::now().to_rfc3339(),
                    probe_summary: SessionExportProbeSummary {
                        output_sha256,
                        output_bytes: output_size_bytes,
                        video_streams: 1,
                        audio_streams: u32::from(audio.is_some()),
                        frame_count: timing.paired_frames(),
                        duration_ns: 30_000_000_000,
                        report_sha256: "d".repeat(64),
                    },
                }),
                output_media: Some(SessionExportOutputMedia {
                    video_codec: "h264".to_string(),
                    layout: "left-right-side-by-side".to_string(),
                    width: manifest.eye_width * 2,
                    eye_width: manifest.eye_width,
                    height: manifest.eye_height,
                    audio,
                }),
            })
        }

        fn inspect_existing(
            &self,
            _plan: &SessionExportPlan,
        ) -> Result<SessionExportReceipt, String> {
            panic!("new-download test exporter must not inspect legacy media")
        }
    }

    fn test_artifact_bytes(path: &str) -> Vec<u8> {
        format!("verified test artifact: {path}").into_bytes()
    }

    fn rewrite_artifacts_as_small_test_files(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                let is_artifact = [
                    "artifact_id",
                    "role",
                    "path",
                    "media_type",
                    "bytes",
                    "sha256",
                ]
                .iter()
                .all(|field| object.contains_key(*field));
                if is_artifact {
                    let path = object["path"].as_str().expect("artifact path");
                    let bytes = test_artifact_bytes(path);
                    let digest = sha256_bytes(&bytes);
                    object.insert("bytes".to_string(), serde_json::json!(bytes.len()));
                    object.insert("artifact_id".to_string(), serde_json::json!(digest));
                    object.insert("sha256".to_string(), serde_json::json!(digest));
                    return;
                }
                for child in object.values_mut() {
                    rewrite_artifacts_as_small_test_files(child);
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    rewrite_artifacts_as_small_test_files(child);
                }
            }
            _ => {}
        }
    }

    fn prepared_commit_request(
        library_root: &Path,
    ) -> (ParsedSource, SessionStaging, DownloadCommitRequest) {
        let mut manifest = source_manifest();
        rewrite_artifacts_as_small_test_files(&mut manifest);
        let payload = compatibility_publication(&manifest);
        let source = parse_source_publication(&payload).expect("parse compact source publication");
        let staging = SessionStaging::for_publication(
            library_root,
            &source.manifest.device.device_id,
            &source.manifest.session_id,
            &payload,
        )
        .expect("staging");
        fs::create_dir_all(staging.revision_dir()).expect("create compact source staging");

        let mut files = Vec::new();
        let mut verified_files = Vec::new();
        for artifact in source.manifest.all_artifacts() {
            let path = staging.revision_dir().join(&artifact.path);
            fs::create_dir_all(path.parent().expect("artifact parent"))
                .expect("create artifact parent");
            fs::write(
                &path,
                test_artifact_bytes(artifact.path.to_str().expect("UTF-8 path")),
            )
            .expect("write compact artifact");
            files.push(JobFile {
                file_id: FileId(artifact.artifact_id.clone()),
                target_relative_path: Some(artifact.path.to_string_lossy().into_owned()),
                expected_size: artifact.bytes,
                expected_sha256_hex: artifact.sha256.clone(),
            });
            verified_files.push(VerifiedFile {
                device_id: source.manifest.device.device_id.clone(),
                session_id: source.manifest.session_id.clone(),
                file_id: artifact.artifact_id.clone(),
                path,
                size_bytes: artifact.bytes,
                sha256_hex: artifact.sha256.clone(),
                etag: None,
            });
        }
        let request = DownloadCommitRequest {
            job_id: ylx_transfer_core::transfer::JobId("publish-backup-job".to_string()),
            request: TransferRequest {
                device_id: DeviceId(source.manifest.device.device_id.clone()),
                session_id: SessionId(source.manifest.session_id.clone()),
                revision: format!("sha256:{}", source.sha256),
                idempotency_key: "publish-backup".to_string(),
                files,
                manifest_bytes: payload,
                signature: Vec::new(),
                publication_public_key: Vec::new(),
            },
            publication_scope: PublicationScope::FullSession,
            verified_files,
            library_root: library_root.to_path_buf(),
        };
        (source, staging, request)
    }

    fn blocked_first_publish_state(
        library_root: &Path,
    ) -> (
        ParsedSource,
        SessionStaging,
        DownloadCommitRequest,
        DownloadCommitFailure,
    ) {
        let (source, staging, request) = prepared_commit_request(library_root);
        fs::create_dir_all(staging.published_dir()).expect("create previous published session");
        fs::write(
            staging.published_dir().join("old-canonical.keep"),
            b"previous canonical session",
        )
        .expect("write previous published fixture");
        let blocked = DerivedMediaCommitter::with_exporter(
            Arc::new(SuccessfulTestExporter),
            Some(InjectedFailure::BackupCleanup),
        );
        let failure = blocked
            .commit(&request)
            .expect_err("backup cleanup failure must keep the commit incomplete");
        (source, staging, request, failure)
    }

    fn install_test_canonical_bundle(staging: &SessionStaging, source: &ParsedSource) {
        let processed = staging.published_dir().join("processed");
        fs::create_dir_all(&processed).expect("create canonical processed directory");
        let output_path = processed.join(format!("{}.mp4", source.manifest.session_id));
        fs::write(&output_path, b"canonical derived MP4 test fixture")
            .expect("write canonical output");
        let output_bytes = fs::metadata(&output_path).expect("output metadata").len();
        let output_sha256 = hash_file(&output_path).expect("hash canonical output");
        let receipt = build_receipt(
            source,
            &format!("{}.mp4", source.manifest.session_id),
            &output_path,
            &SessionExportReceipt {
                output_path: output_path.clone(),
                video_segment_count: 1,
                audio_segment_count: 2,
                output_size_bytes: output_bytes,
                timeline_verification: Some(SessionExportTimelineVerification {
                    policy_id: "openaria.manifest-timeline.v1".to_string(),
                    verdict: TimelineVerificationVerdict::Pass,
                    source_manifest_sha256: source.sha256.clone(),
                    left_right_pairing: TimelineVerificationVerdict::Pass,
                    paired_frames: 900,
                    video_start_residual_ns: 0,
                    video_end_residual_ns: 0,
                    audio_start_residual_ns: Some(0),
                    audio_end_residual_ns: Some(0),
                    source_video_tick_ns: 33_333_334,
                    encoding_audio_frame_ns: Some(21_333_334),
                    allowed_residual_ns: 33_333_334,
                    preserved_leading_gap_ns: 0,
                    verified_at: "2026-08-28T10:10:00Z".to_string(),
                    probe_summary: SessionExportProbeSummary {
                        output_sha256,
                        output_bytes,
                        video_streams: 1,
                        audio_streams: 1,
                        frame_count: 900,
                        duration_ns: 30_000_000_000,
                        report_sha256: "c".repeat(64),
                    },
                }),
                output_media: Some(SessionExportOutputMedia {
                    video_codec: "h264".to_string(),
                    layout: "left-right-side-by-side".to_string(),
                    width: 3_840,
                    eye_width: 1_920,
                    height: 1_080,
                    audio: Some(SessionExportOutputAudio {
                        codec: "aac".to_string(),
                        sample_rate_hz: 48_000,
                        channels: 2,
                    }),
                }),
            },
            "new-download",
        )
        .expect("build canonical receipt");
        write_receipt_atomically(&processed.join(RECEIPT_FILENAME), &receipt)
            .expect("write canonical receipt");
        canonical_assets_in_session_dir(&staging.published_dir(), source)
            .expect("installed canonical bundle is valid");
    }

    fn cleanup_retry_request(
        library_root: &Path,
        payload: Vec<u8>,
        source: &ParsedSource,
    ) -> DownloadCommitRequest {
        DownloadCommitRequest {
            job_id: ylx_transfer_core::transfer::JobId("cleanup-retry-job".to_string()),
            request: TransferRequest {
                device_id: DeviceId(source.manifest.device.device_id.clone()),
                session_id: SessionId(source.manifest.session_id.clone()),
                revision: format!("sha256:{}", source.sha256),
                idempotency_key: "cleanup-retry".to_string(),
                files: Vec::new(),
                manifest_bytes: payload,
                signature: Vec::new(),
                publication_public_key: Vec::new(),
            },
            publication_scope: PublicationScope::FullSession,
            verified_files: Vec::new(),
            library_root: library_root.to_path_buf(),
        }
    }

    fn install_test_owned_backup(
        staging: &SessionStaging,
        source: &ParsedSource,
        job_id: &str,
    ) -> PathBuf {
        let backup = staging
            .revision_dir()
            .join(format!(".ylx-backup-{}", sha256_bytes(job_id.as_bytes())));
        let previous = backup.join("previous");
        fs::create_dir_all(&previous).expect("create owned previous-session backup");
        fs::write(previous.join("old-canonical.keep"), b"previous canonical")
            .expect("write previous canonical fixture");
        let previous_token = "018f5c7e-6d4b-7a2f-8c1e-123456789abc";
        fs::write(
            previous.join(BACKUP_PREVIOUS_TOKEN_FILENAME),
            previous_token,
        )
        .expect("write previous directory ownership token fixture");
        let ownership = serde_json::json!({
            "schema": "ylx.derived-media-backup-owner.v1",
            "job_id_sha256": sha256_bytes(job_id.as_bytes()),
            "source_manifest_sha256": source.sha256,
            "device_id": staging.device_id(),
            "session_id": staging.session_id(),
            "previous_token": previous_token,
        });
        fs::write(
            backup.join("ownership.json"),
            serde_json::to_vec_pretty(&ownership).expect("serialize backup ownership fixture"),
        )
        .expect("write backup ownership fixture");
        backup
    }

    #[test]
    fn source_manifest_fixture_passes_derived_download_admission() {
        let payload = compatibility_publication(&source_manifest());
        parse_source_publication(&payload).expect("valid vendored manifest is admitted");
    }

    #[test]
    fn real_device_timeline_is_admitted_and_mapped_to_session_clock() {
        let mut manifest = source_manifest();
        manifest["time"]["duration_seconds"] =
            serde_json::from_str("30.369608587").expect("real device duration");
        manifest["camera"]["effective_fps"] =
            serde_json::from_str("28.219000503248076").expect("real device effective_fps");
        manifest["frames"]["count"] = serde_json::json!(857);
        manifest["video"]["segments"][0]["end_frame"] = serde_json::json!(857);
        manifest["video"]["segments"][0]["start_time_seconds"] =
            serde_json::from_str("0.98904022").expect("real video start");
        manifest["video"]["segments"][0]["end_time_seconds"] =
            serde_json::from_str("30.369608587").expect("real video end");

        manifest["audio"]["sample_count"] = serde_json::json!(1_398_784);
        manifest["audio"]["sync"]["start_time_seconds"] =
            serde_json::from_str("0.973346574").expect("real audio sync start");
        manifest["audio"]["sync"]["end_time_seconds"] =
            serde_json::from_str("30.108364855").expect("real audio sync end");
        manifest["audio"]["segments"]
            .as_array_mut()
            .expect("audio segments")
            .truncate(1);
        let audio_segment = &mut manifest["audio"]["segments"][0];
        audio_segment["end_sample"] = serde_json::json!(1_398_784);
        audio_segment["end_time_seconds"] =
            serde_json::from_str("29.141333333333332").expect("real audio segment end");
        audio_segment["pcm_payload_bytes"] = serde_json::json!(5_595_136);
        audio_segment["wav_header_bytes"] = serde_json::json!(44);
        audio_segment["artifact"]["bytes"] = serde_json::json!(5_595_180);

        let payload = compatibility_publication(&manifest);

        validate_source_publication_for_download(&payload).unwrap_or_else(|error| {
            panic!(
                "real Device Session v2 must remain downloadable instead of exceeding the \
                 1000000000 timeline denominator limit: {error}"
            )
        });
        let source = parse_source_publication(&payload).expect("admitted real device manifest");
        let timeline = source
            .manifest
            .export_timeline(&source.sha256)
            .expect("real device export timeline");

        assert_eq!(
            timeline.video_tick,
            TimelineTime::from_nanoseconds(35_437_116).expect("nanosecond video tick")
        );
        assert_eq!(
            timeline.left_segments[0].start_time,
            TimelineTime::from_nanoseconds(989_040_220).expect("video start")
        );
        assert_eq!(
            timeline.left_segments[0].end_time,
            TimelineTime::from_nanoseconds(30_369_608_587).expect("video end")
        );
        let audio = timeline.audio.expect("recorded audio timeline");
        assert_eq!(
            audio.session_start_offset,
            TimelineTime::from_nanoseconds(973_346_574).expect("audio sync start")
        );
        assert_eq!(
            audio.session_stop_offset,
            TimelineTime::from_nanoseconds(30_108_364_855).expect("audio sync end")
        );
        assert_eq!(audio.segments[0].start_time, audio.session_start_offset);
        assert_eq!(
            audio.segments[0].end_time,
            TimelineTime::from_nanoseconds(30_114_679_907).expect("sample-derived audio end")
        );
    }

    #[test]
    fn timeline_quantization_preserves_exact_rates_and_rounds_to_nearest_nanosecond() {
        let exact_rate = serde_json::from_str("30.0").expect("exact frame rate");
        assert_eq!(
            reciprocal_decimal_rate(&exact_rate, "camera.effective_fps").expect("exact tick"),
            TimelineTime::new(1, 30).expect("one thirtieth of a second")
        );

        let below_half = serde_json::from_str("0.0000000004").expect("sub-half nanosecond");
        let at_half = serde_json::from_str("0.0000000005").expect("half nanosecond");
        assert_eq!(rounded_decimal_nanoseconds(&below_half).unwrap(), 0);
        assert_eq!(rounded_decimal_nanoseconds(&at_half).unwrap(), 1);

        let unsupported_rate =
            serde_json::from_str("2000000001").expect("sub-nanosecond frame period");
        let error = reciprocal_decimal_rate(&unsupported_rate, "camera.effective_fps")
            .expect_err("a frame period below half a nanosecond must fail closed");
        assert!(
            error.contains("nanosecond timeline precision"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn export_timeline_preserves_declared_audio_channels() {
        let payload = compatibility_publication(&source_manifest());
        let source = parse_source_publication(&payload).expect("valid vendored manifest");

        let timeline = source
            .manifest
            .export_timeline(&source.sha256)
            .expect("export timeline");

        assert_eq!((timeline.eye_width, timeline.eye_height), (1_920, 1_080));
        assert_eq!(timeline.audio.expect("recorded audio timeline").channels, 2);
    }

    #[test]
    fn source_manifest_missing_schema_required_field_fails_closed() {
        let mut manifest = source_manifest();
        manifest
            .as_object_mut()
            .expect("manifest object")
            .remove("capture_mode");
        let error = parse_source_publication(&compatibility_publication(&manifest))
            .expect_err("missing schema-required capture_mode must fail before export");
        assert!(error.contains("exact schema"), "unexpected error: {error}");
    }

    #[test]
    fn source_manifest_extra_field_fails_closed() {
        let mut manifest = source_manifest();
        manifest["unexpected_desktop_hint"] = serde_json::json!(true);
        let error = parse_source_publication(&compatibility_publication(&manifest))
            .expect_err("closed Device Session v2 schema must reject extra fields");
        assert!(error.contains("exact schema"), "unexpected error: {error}");
    }

    #[test]
    fn canonical_backup_cleanup_failure_is_retryable_and_preserves_source_staging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = compatibility_publication(&source_manifest());
        let source = parse_source_publication(&payload).expect("parse source publication");
        let staging = SessionStaging::for_publication(
            dir.path(),
            &source.manifest.device.device_id,
            &source.manifest.session_id,
            &payload,
        )
        .expect("staging");
        fs::create_dir_all(staging.revision_dir()).expect("create source staging");
        let source_file = staging.revision_dir().join("raw-source.keep");
        fs::write(&source_file, b"source staging required for retry")
            .expect("write source staging fixture");
        install_test_canonical_bundle(&staging, &source);
        let request = cleanup_retry_request(dir.path(), payload, &source);
        let backup = install_test_owned_backup(&staging, &source, request.job_id.as_str());
        let output_path = staging
            .published_dir()
            .join("processed")
            .join(format!("{}.mp4", source.manifest.session_id));
        let receipt_path = staging
            .published_dir()
            .join("processed")
            .join(RECEIPT_FILENAME);
        let canonical_output_before = fs::read(&output_path).expect("read canonical output");
        let canonical_receipt_before = fs::read(&receipt_path).expect("read canonical receipt");

        let blocked = DerivedMediaCommitter::with_exporter(
            Arc::new(ExportMustNotRun),
            Some(InjectedFailure::BackupCleanup),
        );
        let failure = blocked
            .commit(&request)
            .expect_err("a previous canonical backup cleanup failure must remain retryable");

        assert!(failure.retryable);
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail)
                if detail.contains("previous canonical backup cleanup failed")
        ));
        assert!(
            source_file.exists(),
            "backup cleanup failure must retain source staging for retry"
        );
        assert!(
            backup.exists(),
            "failed cleanup must retain the owned backup"
        );
        assert!(backup.join("previous/old-canonical.keep").exists());
        assert_eq!(fs::read(&output_path).unwrap(), canonical_output_before);
        assert_eq!(fs::read(&receipt_path).unwrap(), canonical_receipt_before);
        canonical_assets_in_session_dir(&staging.published_dir(), &source)
            .expect("backup cleanup failure preserves the exact canonical bundle");
    }

    #[test]
    fn first_publish_backup_cleanup_failure_is_retryable_and_retains_owned_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let foreign_file = dir.path().join(".ylx-staging/foreign-owner.keep");
        fs::create_dir_all(foreign_file.parent().expect("foreign fixture parent"))
            .expect("create foreign fixture parent");
        fs::write(&foreign_file, b"not owned by this commit").expect("write foreign fixture");
        let (source, staging, request, failure) = blocked_first_publish_state(dir.path());

        assert!(failure.retryable);
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail)
                if detail.contains("previous canonical backup cleanup failed")
        ));
        let backup = previous_canonical_backup_dir(&staging, request.job_id.as_str());
        assert!(backup.join(BACKUP_OWNERSHIP_FILENAME).is_file());
        assert!(
            backup
                .join(BACKUP_PREVIOUS_DIRNAME)
                .join("old-canonical.keep")
                .is_file(),
            "the previous published session remains available for a bounded retry"
        );
        assert!(
            staging.revision_dir().exists(),
            "source staging must remain until backup cleanup completes"
        );
        canonical_assets_in_session_dir(&staging.published_dir(), &source)
            .expect("the new canonical pair is already visible and valid");

        let retry = DerivedMediaCommitter::with_exporter(Arc::new(ExportMustNotRun), None);
        let outcome = retry
            .commit(&request)
            .expect("explicit retry revalidates canonical assets and completes cleanup");

        assert_eq!(outcome, DownloadCommitOutcome::clean());
        assert!(!staging.revision_dir().exists());
        assert!(!backup.exists());
        assert!(
            foreign_file.exists(),
            "retry must not clean foreign staging"
        );
        ensure_exact_canonical_layout(
            &staging.published_dir(),
            &format!("{}.mp4", source.manifest.session_id),
        )
        .expect("successful retry leaves only the canonical MP4 and receipt");
    }

    #[test]
    fn retry_refuses_foreign_replacement_of_owned_backup_scope() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (source, staging, request, _) = blocked_first_publish_state(dir.path());
        let backup = previous_canonical_backup_dir(&staging, request.job_id.as_str());
        fs::remove_dir_all(&backup).expect("remove owned backup to simulate replacement");
        fs::create_dir(&backup).expect("install foreign replacement directory");
        let foreign = backup.join("foreign.keep");
        fs::write(&foreign, b"foreign replacement").expect("write foreign replacement");

        let retry = DerivedMediaCommitter::with_exporter(Arc::new(ExportMustNotRun), None);
        let failure = retry
            .commit(&request)
            .expect_err("retry must reject an unowned replacement backup");

        assert!(
            !failure.retryable,
            "foreign ownership is not safe to retry blindly"
        );
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail) if detail.contains("foreign entries")
        ));
        assert!(foreign.exists(), "foreign replacement must not be deleted");
        assert!(staging.revision_dir().exists());
        canonical_assets_in_session_dir(&staging.published_dir(), &source)
            .expect("foreign backup replacement cannot alter canonical assets");
    }

    #[test]
    fn retry_revalidates_canonical_before_owned_backup_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (source, staging, request, _) = blocked_first_publish_state(dir.path());
        let backup = previous_canonical_backup_dir(&staging, request.job_id.as_str());
        let previous_file = backup
            .join(BACKUP_PREVIOUS_DIRNAME)
            .join("old-canonical.keep");
        let output = staging
            .published_dir()
            .join("processed")
            .join(format!("{}.mp4", source.manifest.session_id));
        fs::write(&output, b"tampered canonical output").expect("tamper canonical output");

        let retry = DerivedMediaCommitter::with_exporter(Arc::new(ExportMustNotRun), None);
        let failure = retry.commit(&request).expect_err(
            "retry must fail closed before cleaning a backup for invalid canonical data",
        );

        assert!(failure.retryable);
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail)
                if detail.contains("canonical bundle failed revalidation")
        ));
        assert!(
            previous_file.exists(),
            "revalidation failure retains old backup"
        );
        assert!(
            staging.revision_dir().exists(),
            "revalidation failure retains source staging"
        );
    }

    #[test]
    fn retry_refuses_regular_replacement_of_owned_previous_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (source, staging, request, _) = blocked_first_publish_state(dir.path());
        let backup = previous_canonical_backup_dir(&staging, request.job_id.as_str());
        let previous = backup.join(BACKUP_PREVIOUS_DIRNAME);
        fs::remove_dir_all(&previous).expect("remove previous payload to simulate replacement");
        fs::create_dir(&previous).expect("install regular foreign replacement");
        let foreign = previous.join("foreign.keep");
        fs::write(&foreign, b"foreign regular replacement").expect("write foreign replacement");

        let retry = DerivedMediaCommitter::with_exporter(Arc::new(ExportMustNotRun), None);
        let failure = retry
            .commit(&request)
            .expect_err("retry must reject a replaced regular previous-session directory");

        assert!(
            !failure.retryable,
            "unbound replacement requires inspection"
        );
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail)
                if detail.contains("previous directory ownership token")
        ));
        assert!(
            foreign.exists(),
            "regular foreign replacement must not be deleted"
        );
        assert!(staging.revision_dir().exists());
        canonical_assets_in_session_dir(&staging.published_dir(), &source)
            .expect("regular replacement cannot alter canonical assets");
    }

    #[cfg(unix)]
    #[test]
    fn retry_refuses_symlink_replacement_of_owned_previous_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let (source, staging, request, _) = blocked_first_publish_state(dir.path());
        let backup = previous_canonical_backup_dir(&staging, request.job_id.as_str());
        let previous = backup.join(BACKUP_PREVIOUS_DIRNAME);
        fs::remove_dir_all(&previous).expect("remove previous payload to simulate replacement");
        let foreign = staging.staging_root().join("foreign-backup-target");
        fs::create_dir(&foreign).expect("create foreign symlink target");
        let foreign_file = foreign.join("foreign.keep");
        fs::write(&foreign_file, b"foreign symlink target").expect("write foreign target");
        symlink(&foreign, &previous).expect("replace previous directory with symlink");

        let retry = DerivedMediaCommitter::with_exporter(Arc::new(ExportMustNotRun), None);
        let failure = retry
            .commit(&request)
            .expect_err("retry must reject a symlinked previous-session backup");

        assert!(
            !failure.retryable,
            "symlink replacement requires inspection"
        );
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail) if detail.contains("expected a real directory")
        ));
        assert!(previous.is_symlink());
        assert!(foreign_file.exists(), "symlink target must not be deleted");
        assert!(staging.revision_dir().exists());
        canonical_assets_in_session_dir(&staging.published_dir(), &source)
            .expect("symlink replacement cannot alter canonical assets");
    }

    #[test]
    fn published_bundle_cleanup_lock_is_retryable_and_retry_only_cleans_owned_staging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = compatibility_publication(&source_manifest());
        let source = parse_source_publication(&payload).expect("parse source publication");
        let staging = SessionStaging::for_publication(
            dir.path(),
            &source.manifest.device.device_id,
            &source.manifest.session_id,
            &payload,
        )
        .expect("staging");
        fs::create_dir_all(staging.revision_dir()).expect("create source staging");
        let locked_source = staging.revision_dir().join("video/left_00000.mp4");
        fs::create_dir_all(locked_source.parent().expect("locked source parent"))
            .expect("create source video directory");
        fs::write(
            &locked_source,
            b"raw source held open by another Windows process",
        )
        .expect("write locked source fixture");
        let foreign_file = staging.staging_root().join("foreign-owner.keep");
        fs::write(&foreign_file, b"not owned by this revision").expect("write foreign fixture");
        install_test_canonical_bundle(&staging, &source);
        let request = cleanup_retry_request(dir.path(), payload, &source);
        let output_path = staging
            .published_dir()
            .join("processed")
            .join(format!("{}.mp4", source.manifest.session_id));
        let receipt_path = staging
            .published_dir()
            .join("processed")
            .join(RECEIPT_FILENAME);
        let canonical_output_before = fs::read(&output_path).expect("read output before failure");
        let canonical_receipt_before =
            fs::read(&receipt_path).expect("read receipt before failure");

        let blocked = DerivedMediaCommitter::with_exporter(
            Arc::new(ExportMustNotRun),
            Some(InjectedFailure::SourceStagingCleanup),
        );
        let failure = blocked
            .commit(&request)
            .expect_err("a Windows-style staging cleanup failure must remain retryable");

        assert!(failure.retryable);
        assert!(matches!(
            failure.code,
            FailureCode::Other(ref detail) if detail.contains("source staging cleanup failed")
        ));
        assert!(
            locked_source.exists(),
            "a failed cleanup must leave the owned source staging available for retry"
        );
        assert!(
            foreign_file.exists(),
            "failure must not delete foreign files"
        );
        assert_eq!(fs::read(&output_path).unwrap(), canonical_output_before);
        assert_eq!(fs::read(&receipt_path).unwrap(), canonical_receipt_before);

        let retry = DerivedMediaCommitter::with_exporter(Arc::new(ExportMustNotRun), None);
        let outcome = retry
            .commit(&request)
            .expect("retry validates the published bundle and finishes staging cleanup");

        assert_eq!(outcome, DownloadCommitOutcome::clean());
        assert!(!staging.revision_dir().exists());
        assert!(foreign_file.exists(), "retry must not delete foreign files");
        assert_eq!(fs::read(&output_path).unwrap(), canonical_output_before);
        assert_eq!(fs::read(&receipt_path).unwrap(), canonical_receipt_before);
        canonical_assets_in_session_dir(&staging.published_dir(), &source)
            .expect("retry preserves the exact valid canonical bundle");
    }

    #[test]
    fn successful_source_cleanup_returns_clean_success_and_preserves_canonical_assets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staging = SessionStaging::for_publication(
            dir.path(),
            "device-clean",
            "session-clean",
            b"signed publication",
        )
        .expect("staging");
        fs::create_dir_all(staging.revision_dir()).expect("create source staging");
        fs::write(staging.revision_dir().join("raw.segment"), b"raw")
            .expect("write source staging");
        fs::create_dir_all(staging.published_dir().join("processed"))
            .expect("create canonical tree");
        fs::write(
            staging.published_dir().join("processed/canonical.mp4"),
            b"canonical",
        )
        .expect("write canonical file");

        let outcome = cleanup_source_staging(&staging, false).expect("clean source staging");

        assert_eq!(outcome, DownloadCommitOutcome::clean());
        assert!(!staging.revision_dir().exists());
        assert!(staging
            .published_dir()
            .join("processed/canonical.mp4")
            .exists());
    }
}
