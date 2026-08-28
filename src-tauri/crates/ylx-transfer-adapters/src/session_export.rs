//! User-facing session export helpers.
//!
//! The media normalizer produces durable derived assets for the library
//! contract. This module is intentionally narrower: it turns one already
//! admitted source tree into a playable side-by-side MP4 for a user-selected
//! destination.

use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ylx_transfer_core::ingest::{
    resolve_regular_file_no_links, AcquisitionSourceId, CandidateReadiness, ConstrainedScanner,
    SafeRelativePath, ScanLimits, ScanRequest, SourceArtifactRole, SourceKind, SourceVideoCodec,
};

const STDERR_PREVIEW_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExportConfig {
    ffmpeg_path: PathBuf,
}

impl Default for SessionExportConfig {
    fn default() -> Self {
        Self::system_ffmpeg()
    }
}

impl SessionExportConfig {
    #[must_use]
    pub fn system_ffmpeg() -> Self {
        Self {
            ffmpeg_path: PathBuf::from("ffmpeg"),
        }
    }

    #[must_use]
    pub fn with_ffmpeg_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ffmpeg_path = path.into();
        self
    }

    #[must_use]
    pub fn ffmpeg_path(&self) -> &Path {
        &self.ffmpeg_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExportRequest {
    source_root: PathBuf,
    output_path: PathBuf,
    overwrite: bool,
}

impl SessionExportRequest {
    #[must_use]
    pub fn new(source_root: impl Into<PathBuf>, output_path: impl Into<PathBuf>) -> Self {
        Self {
            source_root: source_root.into(),
            output_path: output_path.into(),
            overwrite: false,
        }
    }

    #[must_use]
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    #[must_use]
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    #[must_use]
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    #[must_use]
    pub fn overwrite(&self) -> bool {
        self.overwrite
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionExportVideoInput {
    SeparateEyes {
        left_segments: Vec<PathBuf>,
        right_segments: Vec<PathBuf>,
    },
    SideBySide {
        segments: Vec<PathBuf>,
        copy_video: bool,
    },
}

impl SessionExportVideoInput {
    #[must_use]
    pub fn segment_count(&self) -> usize {
        match self {
            Self::SeparateEyes { left_segments, .. } => left_segments.len(),
            Self::SideBySide { segments, .. } => segments.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExportPlan {
    source_root: PathBuf,
    output_path: PathBuf,
    overwrite: bool,
    video: SessionExportVideoInput,
    audio_segments: Vec<PathBuf>,
}

impl SessionExportPlan {
    pub fn from_resolved_segments(
        source_root: impl Into<PathBuf>,
        output_path: impl Into<PathBuf>,
        overwrite: bool,
        mut video: SessionExportVideoInput,
        mut audio_segments: Vec<PathBuf>,
    ) -> Result<Self, SessionExportError> {
        let source_root = canonical_source_root(&source_root.into())?;
        let output_path = validate_output_path(&output_path.into(), overwrite)?;
        match &mut video {
            SessionExportVideoInput::SeparateEyes {
                left_segments,
                right_segments,
            } => {
                sort_segment_paths(left_segments);
                sort_segment_paths(right_segments);
                if left_segments.is_empty() || right_segments.is_empty() {
                    return Err(SessionExportError::UnsupportedSource(
                        "source must contain both left-eye and right-eye video segments"
                            .to_string(),
                    ));
                }
                if left_segments.len() != right_segments.len() {
                    return Err(SessionExportError::UnsupportedSource(format!(
                        "left/right segment counts differ: {} left, {} right",
                        left_segments.len(),
                        right_segments.len()
                    )));
                }
                validate_separate_eye_pairing(left_segments, right_segments)?;
            }
            SessionExportVideoInput::SideBySide { segments, .. } => {
                sort_segment_paths(segments);
                if segments.is_empty() {
                    return Err(SessionExportError::UnsupportedSource(
                        "source has no side-by-side video segments".to_string(),
                    ));
                }
            }
        }
        sort_segment_paths(&mut audio_segments);

        Ok(SessionExportPlan {
            source_root,
            output_path,
            overwrite,
            video,
            audio_segments,
        })
    }

    #[must_use]
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    #[must_use]
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    #[must_use]
    pub fn overwrite(&self) -> bool {
        self.overwrite
    }

    #[must_use]
    pub fn video(&self) -> &SessionExportVideoInput {
        &self.video
    }

    #[must_use]
    pub fn video_segment_count(&self) -> usize {
        self.video.segment_count()
    }

    #[must_use]
    pub fn audio_segments(&self) -> &[PathBuf] {
        &self.audio_segments
    }

    #[must_use]
    pub fn audio_segment_count(&self) -> usize {
        self.audio_segments.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionExportReceipt {
    pub output_path: PathBuf,
    pub video_segment_count: usize,
    pub audio_segment_count: usize,
    pub output_size_bytes: u64,
}

#[derive(Debug)]
pub enum SessionExportError {
    InvalidRequest(String),
    SourceRejected(String),
    UnsupportedSource(String),
    Io {
        context: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    FfmpegFailed {
        status: String,
        stderr: String,
    },
}

impl fmt::Display for SessionExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::SourceRejected(message)
            | Self::UnsupportedSource(message) => formatter.write_str(message),
            Self::Io {
                context,
                path,
                source,
            } => write!(
                formatter,
                "{context} failed at {}: {source}",
                path.display()
            ),
            Self::FfmpegFailed { status, stderr } => {
                if stderr.is_empty() {
                    write!(formatter, "ffmpeg export failed with {status}")
                } else {
                    write!(formatter, "ffmpeg export failed with {status}: {stderr}")
                }
            }
        }
    }
}

impl Error for SessionExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FfmpegSessionExporter {
    config: SessionExportConfig,
}

impl FfmpegSessionExporter {
    #[must_use]
    pub fn new(config: SessionExportConfig) -> Self {
        Self { config }
    }

    pub fn build_plan(
        &self,
        request: &SessionExportRequest,
    ) -> Result<SessionExportPlan, SessionExportError> {
        let source_root = canonical_source_root(request.source_root())?;
        let output_path = validate_output_path(request.output_path(), request.overwrite())?;
        let candidate = detect_source_candidate(&source_root)?;

        let mut left_segments = Vec::new();
        let mut right_segments = Vec::new();
        let mut stereo_segments = Vec::new();
        for claim in candidate.inventory() {
            let target = match claim.role() {
                SourceArtifactRole::VideoLeft => Some(&mut left_segments),
                SourceArtifactRole::VideoRight => Some(&mut right_segments),
                SourceArtifactRole::VideoStereo => Some(&mut stereo_segments),
                _ => None,
            };
            if let Some(target) = target {
                target.push(
                    resolve_regular_file_no_links(&source_root, claim.relative_path()).map_err(
                        |error| {
                            SessionExportError::InvalidRequest(format!(
                                "source video path {} is not exportable: {error}",
                                claim.relative_path()
                            ))
                        },
                    )?,
                );
            }
        }

        sort_segment_paths(&mut left_segments);
        sort_segment_paths(&mut right_segments);
        sort_segment_paths(&mut stereo_segments);

        let video = if !stereo_segments.is_empty()
            && (!left_segments.is_empty() || !right_segments.is_empty())
        {
            return Err(SessionExportError::UnsupportedSource(
                "source mixes side-by-side and separate-eye video segments".to_string(),
            ));
        } else if !stereo_segments.is_empty() {
            SessionExportVideoInput::SideBySide {
                segments: stereo_segments,
                copy_video: candidate.media_plan().codec() == SourceVideoCodec::H264,
            }
        } else if !left_segments.is_empty() || !right_segments.is_empty() {
            if left_segments.is_empty() || right_segments.is_empty() {
                return Err(SessionExportError::UnsupportedSource(
                    "source must contain both left-eye and right-eye video segments".to_string(),
                ));
            }
            if left_segments.len() != right_segments.len() {
                return Err(SessionExportError::UnsupportedSource(format!(
                    "left/right segment counts differ: {} left, {} right",
                    left_segments.len(),
                    right_segments.len()
                )));
            }
            validate_separate_eye_pairing(&left_segments, &right_segments)?;
            SessionExportVideoInput::SeparateEyes {
                left_segments,
                right_segments,
            }
        } else {
            return Err(SessionExportError::UnsupportedSource(
                "source has no exportable video segments".to_string(),
            ));
        };

        let audio_segments = discover_audio_segments(&source_root)?;

        Ok(SessionExportPlan {
            source_root,
            output_path,
            overwrite: request.overwrite(),
            video,
            audio_segments,
        })
    }

    pub fn export_source_tree(
        &self,
        request: &SessionExportRequest,
    ) -> Result<SessionExportReceipt, SessionExportError> {
        let plan = self.build_plan(request)?;
        self.export_plan(&plan)
    }

    pub fn export_plan(
        &self,
        plan: &SessionExportPlan,
    ) -> Result<SessionExportReceipt, SessionExportError> {
        let final_output_path = plan.output_path.clone();
        let staging = TempExportDir::create_for(&final_output_path)?;
        let staged_output_path = staging.path().join("output.mp4");
        let mut run_plan = plan.clone();
        run_plan.output_path = staged_output_path.clone();
        let args = build_ffmpeg_args(&run_plan, staging.path())?;

        let completed = Command::new(self.config.ffmpeg_path())
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| SessionExportError::Io {
                context: "start ffmpeg export",
                path: self.config.ffmpeg_path().to_path_buf(),
                source: error,
            })?;
        if !completed.status.success() {
            return Err(SessionExportError::FfmpegFailed {
                status: completed.status.to_string(),
                stderr: stderr_preview(&completed.stderr),
            });
        }

        let staged_metadata = inspect_regular_staged_output(&staged_output_path)?;
        if staged_metadata.len() == 0 {
            return Err(SessionExportError::UnsupportedSource(format!(
                "ffmpeg did not produce a non-empty mp4 at {}",
                staged_output_path.display()
            )));
        }
        replace_with_staged_output(&staged_output_path, &final_output_path)?;
        let metadata =
            fs::metadata(&final_output_path).map_err(|error| SessionExportError::Io {
                context: "inspect exported mp4",
                path: final_output_path.clone(),
                source: error,
            })?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(SessionExportError::UnsupportedSource(format!(
                "export did not produce a non-empty mp4 at {}",
                final_output_path.display()
            )));
        }

        Ok(SessionExportReceipt {
            output_path: final_output_path,
            video_segment_count: plan.video_segment_count(),
            audio_segment_count: plan.audio_segment_count(),
            output_size_bytes: metadata.len(),
        })
    }
}

fn canonical_source_root(source_root: &Path) -> Result<PathBuf, SessionExportError> {
    let metadata = fs::symlink_metadata(source_root).map_err(|error| SessionExportError::Io {
        context: "inspect source root",
        path: source_root.to_path_buf(),
        source: error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SessionExportError::InvalidRequest(format!(
            "source root must be a real directory: {}",
            source_root.display()
        )));
    }
    fs::canonicalize(source_root).map_err(|error| SessionExportError::Io {
        context: "canonicalize source root",
        path: source_root.to_path_buf(),
        source: error,
    })
}

fn validate_output_path(
    output_path: &Path,
    overwrite: bool,
) -> Result<PathBuf, SessionExportError> {
    let file_name = output_path.file_name().ok_or_else(|| {
        SessionExportError::InvalidRequest("output path must include a file name".to_string())
    })?;
    let parent = output_path.parent().ok_or_else(|| {
        SessionExportError::InvalidRequest(
            "output path must include a parent directory".to_string(),
        )
    })?;
    let parent = fs::canonicalize(parent).map_err(|error| SessionExportError::Io {
        context: "canonicalize output directory",
        path: parent.to_path_buf(),
        source: error,
    })?;
    let normalized = parent.join(file_name);
    match fs::symlink_metadata(&normalized) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(SessionExportError::InvalidRequest(format!(
                    "output path must be a regular file target: {}",
                    normalized.display()
                )));
            }
            if !overwrite {
                return Err(SessionExportError::InvalidRequest(format!(
                    "output file already exists: {}",
                    normalized.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(SessionExportError::Io {
                context: "inspect output path",
                path: normalized,
                source: error,
            });
        }
    }
    Ok(normalized)
}

fn inspect_regular_staged_output(path: &Path) -> Result<fs::Metadata, SessionExportError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| SessionExportError::Io {
        context: "inspect staged exported mp4",
        path: path.to_path_buf(),
        source: error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SessionExportError::UnsupportedSource(format!(
            "ffmpeg did not produce a regular mp4 at {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn replace_with_staged_output(
    staged_output_path: &Path,
    final_output_path: &Path,
) -> Result<(), SessionExportError> {
    replace_with_staged_output_impl(
        staged_output_path,
        final_output_path,
        &mut |source, target| fs::rename(source, target),
    )
}

fn replace_with_staged_output_impl(
    staged_output_path: &Path,
    final_output_path: &Path,
    rename: &mut dyn FnMut(&Path, &Path) -> io::Result<()>,
) -> Result<(), SessionExportError> {
    let backup_path = match fs::symlink_metadata(final_output_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(SessionExportError::InvalidRequest(format!(
                    "output path must be a regular file target: {}",
                    final_output_path.display()
                )));
            }
            let backup_path = allocate_replace_backup_path(final_output_path)?;
            rename(final_output_path, &backup_path).map_err(|error| SessionExportError::Io {
                context: "backup existing exported mp4",
                path: final_output_path.to_path_buf(),
                source: error,
            })?;
            Some(backup_path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(SessionExportError::Io {
                context: "inspect output path",
                path: final_output_path.to_path_buf(),
                source: error,
            });
        }
    };

    match rename(staged_output_path, final_output_path) {
        Ok(()) => {
            if let Some(backup_path) = backup_path {
                fs::remove_file(&backup_path).map_err(|error| SessionExportError::Io {
                    context: "remove replaced export backup",
                    path: backup_path,
                    source: error,
                })?;
            }
            Ok(())
        }
        Err(commit_error) => {
            if let Some(backup_path) = backup_path {
                rename(&backup_path, final_output_path).map_err(|restore_error| {
                    SessionExportError::Io {
                        context: "restore existing exported mp4 after failed commit",
                        path: final_output_path.to_path_buf(),
                        source: restore_error,
                    }
                })?;
            }
            Err(SessionExportError::Io {
                context: "commit exported mp4",
                path: final_output_path.to_path_buf(),
                source: commit_error,
            })
        }
    }
}

fn allocate_replace_backup_path(final_output_path: &Path) -> Result<PathBuf, SessionExportError> {
    let parent = final_output_path.parent().ok_or_else(|| {
        SessionExportError::InvalidRequest(
            "output path must include a parent directory".to_string(),
        )
    })?;
    let file_name = final_output_path.file_name().ok_or_else(|| {
        SessionExportError::InvalidRequest("output path must include a file name".to_string())
    })?;
    for attempt in 0..100 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let mut backup_name = OsString::from(".");
        backup_name.push(file_name);
        backup_name.push(format!(
            ".ylx-replace-backup-{}-{now}-{attempt}",
            std::process::id()
        ));
        let path = parent.join(backup_name);
        match fs::symlink_metadata(&path) {
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path),
            Err(error) => {
                return Err(SessionExportError::Io {
                    context: "inspect export backup path",
                    path,
                    source: error,
                });
            }
        }
    }
    Err(SessionExportError::InvalidRequest(
        "could not allocate a unique export backup path".to_string(),
    ))
}

fn detect_source_candidate(
    source_root: &Path,
) -> Result<ylx_transfer_core::ingest::ScanCandidate, SessionExportError> {
    let source_id = AcquisitionSourceId::parse("session-export").map_err(|error| {
        SessionExportError::InvalidRequest(format!("cannot construct export source id: {error}"))
    })?;
    let request = ScanRequest::selected_directory(
        source_root.to_path_buf(),
        source_id,
        SourceKind::LocalFolder,
        None,
    )
    .map_err(|error| {
        SessionExportError::InvalidRequest(format!("cannot construct scan request: {error}"))
    })?;
    let snapshot = ConstrainedScanner::new(ScanLimits::default()).scan(&request);
    let mut rejected = Vec::new();
    for diagnostic in snapshot.root_diagnostics() {
        rejected.push(format!("{:?}: {}", diagnostic.code(), diagnostic.message()));
    }
    for candidate in snapshot.candidates() {
        if !candidate.validation_report().is_accepted() {
            rejected.push(format!(
                "candidate {} failed validation",
                candidate.id().as_str()
            ));
            continue;
        }
        if matches!(
            candidate.readiness(),
            CandidateReadiness::Corrupt
                | CandidateReadiness::UnsafePath
                | CandidateReadiness::UnsupportedSchema
                | CandidateReadiness::RecordingOrEncodingIncomplete
        ) {
            rejected.push(format!(
                "candidate {} is not ready: {:?}",
                candidate.id().as_str(),
                candidate.readiness()
            ));
            continue;
        }
        return Ok(candidate.clone());
    }
    Err(SessionExportError::SourceRejected(if rejected.is_empty() {
        "source tree did not contain an exportable recording".to_string()
    } else {
        format!("source tree did not contain an exportable recording: {rejected:?}")
    }))
}

fn discover_audio_segments(source_root: &Path) -> Result<Vec<PathBuf>, SessionExportError> {
    let mut paths = BTreeSet::new();
    discover_manifest_audio_segments(source_root, &mut paths)?;
    discover_audio_directory_segments(source_root, &mut paths)?;
    let mut paths: Vec<_> = paths.into_iter().collect();
    sort_segment_paths(&mut paths);
    Ok(paths)
}

fn discover_manifest_audio_segments(
    source_root: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<(), SessionExportError> {
    let manifest_path = source_root.join("publication_manifest.json");
    let bytes = match fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SessionExportError::Io {
                context: "read publication manifest",
                path: manifest_path,
                source: error,
            });
        }
    };
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|error| {
        SessionExportError::InvalidRequest(format!("publication_manifest.json is invalid: {error}"))
    })?;
    let Some(files) = manifest.get("files").and_then(Value::as_array) else {
        return Ok(());
    };
    for file in files {
        let Some(display_path) = file.get("display_path").and_then(Value::as_str) else {
            continue;
        };
        if !is_audio_manifest_claim(file, display_path) {
            continue;
        }
        let relative = SafeRelativePath::parse(display_path.to_string()).map_err(|error| {
            SessionExportError::InvalidRequest(format!(
                "audio path {display_path:?} is unsafe: {error}"
            ))
        })?;
        let path = resolve_regular_file_no_links(source_root, &relative).map_err(|error| {
            SessionExportError::InvalidRequest(format!(
                "audio path {display_path:?} is not exportable: {error}"
            ))
        })?;
        paths.insert(path);
    }
    Ok(())
}

fn discover_audio_directory_segments(
    source_root: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<(), SessionExportError> {
    let audio_dir = source_root.join("audio");
    let metadata = match fs::symlink_metadata(&audio_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SessionExportError::Io {
                context: "inspect audio directory",
                path: audio_dir,
                source: error,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(SessionExportError::InvalidRequest(format!(
            "audio directory must not be a link: {}",
            audio_dir.display()
        )));
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(&audio_dir).map_err(|error| SessionExportError::Io {
        context: "read audio directory",
        path: audio_dir.clone(),
        source: error,
    })? {
        let entry = entry.map_err(|error| SessionExportError::Io {
            context: "read audio directory entry",
            path: audio_dir.clone(),
            source: error,
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !has_audio_extension(Path::new(file_name)) {
            continue;
        }
        let relative = SafeRelativePath::parse(format!("audio/{file_name}")).map_err(|error| {
            SessionExportError::InvalidRequest(format!(
                "audio path audio/{file_name:?} is unsafe: {error}"
            ))
        })?;
        let path = resolve_regular_file_no_links(source_root, &relative).map_err(|error| {
            SessionExportError::InvalidRequest(format!(
                "audio path audio/{file_name:?} is not exportable: {error}"
            ))
        })?;
        paths.insert(path);
    }
    Ok(())
}

fn is_audio_manifest_claim(file: &Value, display_path: &str) -> bool {
    file.get("media_type")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("audio/"))
        || file
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("audio"))
        || display_path.starts_with("audio/")
        || has_audio_extension(Path::new(display_path))
}

fn has_audio_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "aac" | "m4a" | "wav"
            )
        })
        .unwrap_or(false)
}

fn build_ffmpeg_args(
    plan: &SessionExportPlan,
    staging_dir: &Path,
) -> Result<Vec<String>, SessionExportError> {
    let audio_list = if plan.audio_segments.is_empty() {
        None
    } else {
        Some(write_concat_list(
            staging_dir,
            "audio.ffconcat",
            &plan.audio_segments,
        )?)
    };

    let mut args = vec![
        "-hide_banner".to_string(),
        "-nostdin".to_string(),
        if plan.overwrite { "-y" } else { "-n" }.to_string(),
    ];

    match &plan.video {
        SessionExportVideoInput::SeparateEyes {
            left_segments,
            right_segments,
        } => {
            let left_list = write_concat_list(staging_dir, "left.ffconcat", left_segments)?;
            let right_list = write_concat_list(staging_dir, "right.ffconcat", right_segments)?;
            append_concat_input(&mut args, &left_list);
            append_concat_input(&mut args, &right_list);
            if let Some(audio_list) = audio_list.as_ref() {
                append_concat_input(&mut args, audio_list);
            }
            args.extend([
                "-filter_complex".to_string(),
                "[0:v:0]setpts=PTS-STARTPTS[l];[1:v:0]setpts=PTS-STARTPTS[r];[l][r]hstack=inputs=2[v]"
                    .to_string(),
                "-map".to_string(),
                "[v]".to_string(),
            ]);
            if audio_list.is_some() {
                args.extend(["-map".to_string(), "2:a:0".to_string()]);
            } else {
                args.push("-an".to_string());
            }
            append_h264_video_output_args(&mut args);
        }
        SessionExportVideoInput::SideBySide {
            segments,
            copy_video,
        } => {
            let video_list = write_concat_list(staging_dir, "video.ffconcat", segments)?;
            append_concat_input(&mut args, &video_list);
            if let Some(audio_list) = audio_list.as_ref() {
                append_concat_input(&mut args, audio_list);
            }
            args.extend(["-map".to_string(), "0:v:0".to_string()]);
            if audio_list.is_some() {
                args.extend(["-map".to_string(), "1:a:0".to_string()]);
            } else {
                args.push("-an".to_string());
            }
            if *copy_video {
                args.extend(["-c:v".to_string(), "copy".to_string()]);
            } else {
                append_h264_video_output_args(&mut args);
            }
        }
    }
    if audio_list.is_some() {
        args.extend([
            "-af".to_string(),
            "aresample=async=1:first_pts=0".to_string(),
            "-c:a".to_string(),
            "aac".to_string(),
            "-b:a".to_string(),
            "192k".to_string(),
            "-shortest".to_string(),
        ]);
    }
    args.extend([
        "-sn".to_string(),
        "-dn".to_string(),
        "-movflags".to_string(),
        "+faststart".to_string(),
        plan.output_path.to_string_lossy().into_owned(),
    ]);
    Ok(args)
}

fn append_concat_input(args: &mut Vec<String>, list_path: &Path) {
    args.extend([
        "-f".to_string(),
        "concat".to_string(),
        "-safe".to_string(),
        "0".to_string(),
        "-i".to_string(),
        list_path.to_string_lossy().into_owned(),
    ]);
}

fn append_h264_video_output_args(args: &mut Vec<String>) {
    args.extend([
        "-c:v".to_string(),
        "libx264".to_string(),
        "-preset".to_string(),
        "veryfast".to_string(),
        "-crf".to_string(),
        "18".to_string(),
        "-pix_fmt".to_string(),
        "yuv420p".to_string(),
    ]);
}

fn write_concat_list(
    staging_dir: &Path,
    file_name: &str,
    segments: &[PathBuf],
) -> Result<PathBuf, SessionExportError> {
    if segments.is_empty() {
        return Err(SessionExportError::UnsupportedSource(format!(
            "concat list {file_name} has no segments"
        )));
    }
    let path = staging_dir.join(file_name);
    let mut body = String::new();
    for segment in segments {
        body.push_str("file '");
        body.push_str(&escape_concat_path(segment));
        body.push_str("'\n");
    }
    fs::write(&path, body).map_err(|error| SessionExportError::Io {
        context: "write ffmpeg concat list",
        path: path.clone(),
        source: error,
    })?;
    Ok(path)
}

fn escape_concat_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "'\\''")
}

fn sort_segment_paths(paths: &mut [PathBuf]) {
    paths.sort_by(|left, right| {
        segment_number(left)
            .cmp(&segment_number(right))
            .then_with(|| left.to_string_lossy().cmp(&right.to_string_lossy()))
    });
}

fn validate_separate_eye_pairing(
    left_segments: &[PathBuf],
    right_segments: &[PathBuf],
) -> Result<(), SessionExportError> {
    for (index, (left, right)) in left_segments.iter().zip(right_segments).enumerate() {
        let left_number = segment_number(left);
        let right_number = segment_number(right);
        if left_number != right_number {
            return Err(SessionExportError::UnsupportedSource(format!(
                "left/right segment numbers differ at pair {index}: {} vs {}",
                segment_number_label(left_number),
                segment_number_label(right_number)
            )));
        }
    }
    Ok(())
}

fn segment_number_label(value: Option<u64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| "no numeric suffix".to_string())
}

fn segment_number(path: &Path) -> Option<u64> {
    let stem = path.file_stem()?.to_string_lossy();
    let digits: String = stem
        .chars()
        .rev()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn stderr_preview(bytes: &[u8]) -> String {
    let keep = bytes.len().min(STDERR_PREVIEW_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..keep]).to_string();
    if bytes.len() > keep {
        text.push_str("...");
    }
    text
}

struct TempExportDir {
    path: PathBuf,
}

impl TempExportDir {
    fn create_for(output_path: &Path) -> Result<Self, SessionExportError> {
        let parent = output_path.parent().ok_or_else(|| {
            SessionExportError::InvalidRequest(
                "output path must include a parent directory".to_string(),
            )
        })?;
        for attempt in 0..100 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = parent.join(format!(
                ".ylx-session-export-{}-{now}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(SessionExportError::Io {
                        context: "create export staging directory",
                        path,
                        source: error,
                    });
                }
            }
        }
        Err(SessionExportError::InvalidRequest(
            "could not allocate a unique export staging directory".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempExportDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::{Command, Stdio};

    use sha2::{Digest, Sha256};

    use super::*;

    const SESSION_ID: &str = "20260803T060347_023247_0000-28f96b7c5a19";

    struct Artifact {
        path: &'static str,
        role: &'static str,
        media_type: &'static str,
        bytes: &'static [u8],
    }

    fn write_publication(root: &Path, codec: &str, video: &[Artifact]) {
        fs::create_dir_all(root.join("video")).expect("video directory");
        fs::create_dir_all(root.join("spool")).expect("spool directory");
        fs::create_dir_all(root.join("audio")).expect("audio directory");

        let session = serde_json::json!({
            "schema_version": 7,
            "state": "complete",
            "camera": {
                "width": 3840,
                "height": 1080,
                "fps": 30,
                "layout": "left_right_side_by_side",
                "left_size": [1920, 1080],
                "source_video_codec": "mjpeg",
                "video_codec": codec,
            },
        });
        let session_bytes = serde_json::to_vec_pretty(&session).expect("session json");
        fs::write(root.join("session.json"), &session_bytes).expect("write session");

        let mut files = Vec::new();
        let mut total = 0u64;
        let mut video_bytes = 0u64;
        for artifact in video {
            fs::write(root.join(artifact.path), artifact.bytes).expect("write artifact");
            files.push(file_claim(
                artifact.path,
                artifact.role,
                artifact.media_type,
                artifact.bytes,
            ));
            total += artifact.bytes.len() as u64;
            video_bytes += artifact.bytes.len() as u64;
        }
        files.push(file_claim(
            "session.json",
            "metadata",
            "application/json",
            &session_bytes,
        ));
        total += session_bytes.len() as u64;

        let manifest = serde_json::json!({
            "schema_version": 1,
            "session_id": SESSION_ID,
            "revision": format!("sha256:{:x}", Sha256::digest(b"revision-material")),
            "captured_at": "2026-08-03T06:05:11.130061+00:00",
            "published_at": "2026-08-03T06:06:25.822799Z",
            "duration_seconds": 68.8,
            "total_bytes": total,
            "video_bytes": video_bytes,
            "integrity_ok": true,
            "files": files,
        });
        fs::write(
            root.join("publication_manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest json"),
        )
        .expect("write manifest");
    }

    fn write_publication_for_existing_video(
        root: &Path,
        codec: &str,
        video: &[(&str, &str, &str)],
        extra_files: &[(&str, &str, &str)],
    ) {
        let session = serde_json::json!({
            "schema_version": 7,
            "state": "complete",
            "camera": {
                "width": 3840,
                "height": 1080,
                "fps": 30,
                "layout": "left_right_side_by_side",
                "left_size": [1920, 1080],
                "source_video_codec": "mjpeg",
                "video_codec": codec,
            },
        });
        let session_bytes = serde_json::to_vec_pretty(&session).expect("session json");
        fs::write(root.join("session.json"), &session_bytes).expect("write session");

        let mut files = Vec::new();
        let mut total = 0u64;
        let mut video_bytes = 0u64;
        for (path, role, media_type) in video {
            let bytes = fs::read(root.join(path)).expect("read video artifact");
            files.push(file_claim(path, role, media_type, &bytes));
            total += bytes.len() as u64;
            video_bytes += bytes.len() as u64;
        }
        for (path, role, media_type) in extra_files {
            let bytes = fs::read(root.join(path)).expect("read extra artifact");
            files.push(file_claim(path, role, media_type, &bytes));
            total += bytes.len() as u64;
        }
        files.push(file_claim(
            "session.json",
            "metadata",
            "application/json",
            &session_bytes,
        ));
        total += session_bytes.len() as u64;

        let manifest = serde_json::json!({
            "schema_version": 1,
            "session_id": SESSION_ID,
            "revision": format!("sha256:{:x}", Sha256::digest(b"revision-material")),
            "captured_at": "2026-08-03T06:05:11.130061+00:00",
            "published_at": "2026-08-03T06:06:25.822799Z",
            "duration_seconds": 0.6,
            "total_bytes": total,
            "video_bytes": video_bytes,
            "integrity_ok": true,
            "files": files,
        });
        fs::write(
            root.join("publication_manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest json"),
        )
        .expect("write manifest");
    }

    fn file_claim(path: &str, role: &str, media_type: &str, bytes: &[u8]) -> Value {
        serde_json::json!({
            "id": format!("f-{}", &format!("{:x}", Sha256::digest(path.as_bytes()))[..32]),
            "display_path": path,
            "role": role,
            "size_bytes": bytes.len() as u64,
            "sha256": format!("{:x}", Sha256::digest(bytes)),
            "media_type": media_type,
        })
    }

    fn separate_eyes_h264() -> Vec<Artifact> {
        vec![
            Artifact {
                path: "video/left_00002.mp4",
                role: "video_left",
                media_type: "video/mp4",
                bytes: b"left-eye-two",
            },
            Artifact {
                path: "video/right_00002.mp4",
                role: "video_right",
                media_type: "video/mp4",
                bytes: b"right-eye-two",
            },
            Artifact {
                path: "video/left_00001.mp4",
                role: "video_left",
                media_type: "video/mp4",
                bytes: b"left-eye-one",
            },
            Artifact {
                path: "video/right_00001.mp4",
                role: "video_right",
                media_type: "video/mp4",
                bytes: b"right-eye-one",
            },
        ]
    }

    fn ffmpeg_available() -> bool {
        Command::new("ffmpeg")
            .arg("-version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn ffprobe_available() -> bool {
        Command::new("ffprobe")
            .arg("-version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn run_ffmpeg(args: &[&str]) {
        let output = Command::new("ffmpeg")
            .args(["-hide_banner", "-loglevel", "error", "-nostdin", "-y"])
            .args(args)
            .output()
            .expect("start ffmpeg");
        assert!(
            output.status.success(),
            "ffmpeg failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn generate_h264_clip(path: &Path, color: &str) {
        fs::create_dir_all(path.parent().expect("clip parent")).expect("clip parent");
        let source = format!("color=c={color}:size=32x32:rate=10:duration=0.6");
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            &source,
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn generate_wav(path: &Path) {
        fs::create_dir_all(path.parent().expect("wav parent")).expect("wav parent");
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=0.6",
            "-c:a",
            "pcm_s16le",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn staging_dirs(parent: &Path) -> Vec<String> {
        fs::read_dir(parent)
            .expect("read output parent")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with(".ylx-session-export-"))
            .collect()
    }

    fn replace_backup_files(parent: &Path) -> Vec<String> {
        fs::read_dir(parent)
            .expect("read output parent")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.contains(".ylx-replace-backup-"))
            .collect()
    }

    #[test]
    fn plans_split_eye_h264_export_with_audio_sidecar() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(directory.path(), "h264", &separate_eyes_h264());
        fs::write(
            directory.path().join("audio/audio_00001.wav"),
            b"fake-wav-one",
        )
        .expect("write audio");
        fs::write(
            directory.path().join("audio/audio_00002.wav"),
            b"fake-wav-two",
        )
        .expect("write audio");
        let output = directory.path().join("export.mp4");

        let exporter = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg());
        let plan = exporter
            .build_plan(&SessionExportRequest::new(directory.path(), &output).with_overwrite(true))
            .expect("build export plan");

        assert_eq!(plan.video_segment_count(), 2);
        assert_eq!(plan.audio_segment_count(), 2);
        match plan.video() {
            SessionExportVideoInput::SeparateEyes {
                left_segments,
                right_segments,
            } => {
                assert!(left_segments[0].ends_with("video/left_00001.mp4"));
                assert!(left_segments[1].ends_with("video/left_00002.mp4"));
                assert!(right_segments[0].ends_with("video/right_00001.mp4"));
                assert!(right_segments[1].ends_with("video/right_00002.mp4"));
            }
            other => panic!("unexpected video input: {other:?}"),
        }

        let staging = tempfile::tempdir().expect("staging");
        let args = build_ffmpeg_args(&plan, staging.path()).expect("ffmpeg args");
        assert!(args.windows(2).any(|window| window
            == [
                "-filter_complex",
                "[0:v:0]setpts=PTS-STARTPTS[l];[1:v:0]setpts=PTS-STARTPTS[r];[l][r]hstack=inputs=2[v]",
            ]));
        assert!(args.windows(2).any(|window| window == ["-map", "2:a:0"]));
        assert!(args.windows(2).any(|window| window == ["-c:v", "libx264"]));
        assert!(args
            .windows(2)
            .any(|window| window == ["-af", "aresample=async=1:first_pts=0"]));
        assert!(args.windows(2).any(|window| window == ["-c:a", "aac"]));
        assert!(args.contains(&"-shortest".to_string()));
    }

    #[test]
    fn rejects_split_eye_segments_with_mismatched_numbers() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(
            directory.path(),
            "h264",
            &[
                Artifact {
                    path: "video/left_00001.mp4",
                    role: "video_left",
                    media_type: "video/mp4",
                    bytes: b"left-eye-one",
                },
                Artifact {
                    path: "video/left_00003.mp4",
                    role: "video_left",
                    media_type: "video/mp4",
                    bytes: b"left-eye-three",
                },
                Artifact {
                    path: "video/right_00001.mp4",
                    role: "video_right",
                    media_type: "video/mp4",
                    bytes: b"right-eye-one",
                },
                Artifact {
                    path: "video/right_00002.mp4",
                    role: "video_right",
                    media_type: "video/mp4",
                    bytes: b"right-eye-two",
                },
            ],
        );
        let output = directory.path().join("export.mp4");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .build_plan(&SessionExportRequest::new(directory.path(), &output).with_overwrite(true))
            .expect_err("mismatched eye segment numbers should be rejected");

        assert!(matches!(error, SessionExportError::UnsupportedSource(_)));
        assert!(error.to_string().contains("segment numbers differ"));
    }

    #[test]
    fn rejects_mixed_stereo_and_split_eye_inventory() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(
            directory.path(),
            "h264",
            &[
                Artifact {
                    path: "spool/source_00000.mp4",
                    role: "video_stereo",
                    media_type: "video/mp4",
                    bytes: b"sbs-h264-zero",
                },
                Artifact {
                    path: "video/left_00000.mp4",
                    role: "video_left",
                    media_type: "video/mp4",
                    bytes: b"left-eye-zero",
                },
                Artifact {
                    path: "video/right_00000.mp4",
                    role: "video_right",
                    media_type: "video/mp4",
                    bytes: b"right-eye-zero",
                },
            ],
        );
        let output = directory.path().join("export.mp4");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .build_plan(&SessionExportRequest::new(directory.path(), &output).with_overwrite(true))
            .expect_err("mixed video layouts should be rejected");

        assert!(matches!(error, SessionExportError::UnsupportedSource(_)));
        assert!(error.to_string().contains("mixes side-by-side"));
    }

    #[test]
    fn discovers_manifest_declared_audio_segments() {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(directory.path().join("video")).expect("video dir");
        fs::create_dir_all(directory.path().join("sound")).expect("sound dir");
        fs::write(directory.path().join("video/left_00000.mp4"), b"left").expect("left");
        fs::write(directory.path().join("video/right_00000.mp4"), b"right").expect("right");
        let audio_path = directory.path().join("sound/capture.wav");
        fs::write(&audio_path, b"fake-wav").expect("write audio");
        write_publication_for_existing_video(
            directory.path(),
            "h264",
            &[
                ("video/left_00000.mp4", "video_left", "video/mp4"),
                ("video/right_00000.mp4", "video_right", "video/mp4"),
            ],
            &[("sound/capture.wav", "metadata", "audio/wav")],
        );

        let exporter = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg());
        let plan = exporter
            .build_plan(
                &SessionExportRequest::new(directory.path(), directory.path().join("export.mp4"))
                    .with_overwrite(true),
            )
            .expect("build export plan");

        assert_eq!(plan.audio_segment_count(), 1);
        assert!(plan.audio_segments()[0].ends_with("sound/capture.wav"));
    }

    #[test]
    fn plans_existing_h264_sbs_export_as_video_copy() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(
            directory.path(),
            "h264",
            &[Artifact {
                path: "spool/source_00000.mp4",
                role: "video_stereo",
                media_type: "video/mp4",
                bytes: b"sbs-h264-zero",
            }],
        );
        let output = directory.path().join("export.mp4");

        let exporter = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg());
        let plan = exporter
            .build_plan(&SessionExportRequest::new(directory.path(), &output).with_overwrite(true))
            .expect("build export plan");

        match plan.video() {
            SessionExportVideoInput::SideBySide {
                segments,
                copy_video,
            } => {
                assert_eq!(segments.len(), 1);
                assert!(*copy_video);
            }
            other => panic!("unexpected video input: {other:?}"),
        }
        let staging = tempfile::tempdir().expect("staging");
        let args = build_ffmpeg_args(&plan, staging.path()).expect("ffmpeg args");
        assert!(args.windows(2).any(|window| window == ["-c:v", "copy"]));
        assert!(args.contains(&"-an".to_string()));
    }

    #[test]
    fn escapes_ffmpeg_concat_paths() {
        let escaped = escape_concat_path(Path::new("/tmp/odd 'name'/clip\\01.mp4"));
        assert_eq!(escaped, "/tmp/odd '\\''name'\\''/clip\\01.mp4");
    }

    #[test]
    fn refuses_existing_output_without_overwrite() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(directory.path(), "h264", &separate_eyes_h264());
        let output = directory.path().join("export.mp4");
        fs::write(&output, b"existing").expect("write existing output");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .build_plan(&SessionExportRequest::new(directory.path(), &output))
            .expect_err("existing output should require overwrite");

        assert!(matches!(error, SessionExportError::InvalidRequest(_)));
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn replace_commit_failure_restores_existing_output() {
        let directory = tempfile::tempdir().expect("tempdir");
        let staged = directory.path().join("staged.mp4");
        let output = directory.path().join("export.mp4");
        fs::write(&staged, b"new output").expect("write staged output");
        fs::write(&output, b"old output").expect("write existing output");

        let staged_for_failure = staged.clone();
        let mut rename = |source: &Path, target: &Path| {
            if source == staged_for_failure.as_path() {
                Err(std::io::Error::other("commit boom"))
            } else {
                fs::rename(source, target)
            }
        };

        let error = replace_with_staged_output_impl(&staged, &output, &mut rename)
            .expect_err("commit should fail");

        assert!(matches!(error, SessionExportError::Io { .. }));
        assert!(error.to_string().contains("commit boom"));
        assert_eq!(
            fs::read(&output).expect("read restored output"),
            b"old output"
        );
        assert_eq!(
            fs::read(&staged).expect("read staged output"),
            b"new output"
        );
        assert_eq!(replace_backup_files(directory.path()), Vec::<String>::new());
    }

    #[cfg(unix)]
    #[test]
    fn failed_ffmpeg_export_leaves_no_output_or_staging_directory() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(directory.path(), "h264", &separate_eyes_h264());
        let output_dir = directory.path().join("exports");
        fs::create_dir(&output_dir).expect("output dir");
        let output = output_dir.join("failed.mp4");
        let fake_ffmpeg = directory.path().join("fake-ffmpeg.sh");
        fs::write(&fake_ffmpeg, "#!/bin/sh\necho ffmpeg-boom >&2\nexit 9\n")
            .expect("write fake ffmpeg");
        let mut permissions = fs::metadata(&fake_ffmpeg)
            .expect("fake metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ffmpeg, permissions).expect("chmod fake ffmpeg");

        let error = FfmpegSessionExporter::new(
            SessionExportConfig::system_ffmpeg().with_ffmpeg_path(&fake_ffmpeg),
        )
        .export_source_tree(
            &SessionExportRequest::new(directory.path(), &output).with_overwrite(true),
        )
        .expect_err("fake ffmpeg should fail");

        assert!(matches!(error, SessionExportError::FfmpegFailed { .. }));
        assert!(error.to_string().contains("ffmpeg-boom"));
        assert!(
            !output.exists(),
            "failed export must not leave target output"
        );
        assert_eq!(staging_dirs(&output_dir), Vec::<String>::new());
    }

    #[test]
    fn exports_real_split_eye_h264_and_wav_to_sbs_mp4() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping real ffmpeg export smoke because ffmpeg/ffprobe is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source 'quote");
        fs::create_dir(&source).expect("source dir");
        generate_h264_clip(&source.join("video/left_00000.mp4"), "red");
        generate_h264_clip(&source.join("video/right_00000.mp4"), "blue");
        generate_wav(&source.join("audio/audio_00000.wav"));
        write_publication_for_existing_video(
            &source,
            "h264",
            &[
                ("video/left_00000.mp4", "video_left", "video/mp4"),
                ("video/right_00000.mp4", "video_right", "video/mp4"),
            ],
            &[],
        );
        let output_dir = directory.path().join("exports");
        fs::create_dir(&output_dir).expect("output dir");
        let output = output_dir.join("sbs.mp4");

        let receipt = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_source_tree(&SessionExportRequest::new(&source, &output).with_overwrite(true))
            .expect("export source tree");

        assert_eq!(
            receipt.output_path.canonicalize().expect("receipt path"),
            output.canonicalize().expect("output path")
        );
        assert_eq!(receipt.video_segment_count, 1);
        assert_eq!(receipt.audio_segment_count, 1);
        assert!(receipt.output_size_bytes > 0);
        assert_eq!(staging_dirs(&output_dir), Vec::<String>::new());

        let probe = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-print_format",
                "json",
                "-show_streams",
                output.to_str().expect("output path utf8"),
            ])
            .output()
            .expect("start ffprobe");
        assert!(
            probe.status.success(),
            "ffprobe failed: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        let report: Value = serde_json::from_slice(&probe.stdout).expect("ffprobe json");
        let streams = report["streams"].as_array().expect("streams array");
        let video = streams
            .iter()
            .find(|stream| stream["codec_type"] == "video")
            .expect("video stream");
        let audio = streams
            .iter()
            .find(|stream| stream["codec_type"] == "audio")
            .expect("audio stream");
        assert_eq!(video["codec_name"], "h264");
        assert_eq!(video["width"].as_u64(), Some(64));
        assert_eq!(video["height"].as_u64(), Some(32));
        assert_eq!(audio["codec_name"], "aac");
    }
}
