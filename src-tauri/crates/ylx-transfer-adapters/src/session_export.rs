//! User-facing session export helpers.
//!
//! The media normalizer produces durable derived assets for the library
//! contract. This module is intentionally narrower: it turns one already
//! admitted source tree into a playable side-by-side MP4 for a user-selected
//! destination.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ylx_transfer_core::ingest::{
    resolve_regular_file_no_links, AcquisitionSourceId, CandidateReadiness, ConstrainedScanner,
    SafeRelativePath, ScanLimits, ScanRequest, SourceArtifactRole, SourceKind, SourceVideoCodec,
};

const STDERR_PREVIEW_BYTES: usize = 4 * 1024;
const PROCESS_STDERR_LIMIT_BYTES: usize = 64 * 1024;
const FFPROBE_CONTROL_STDOUT_LIMIT_BYTES: usize = 64 * 1024;
const FFPROBE_STDOUT_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_TIMELINE_DENOMINATOR: u64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExportConfig {
    ffmpeg_path: PathBuf,
    ffprobe_path: PathBuf,
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
            ffprobe_path: PathBuf::from("ffprobe"),
        }
    }

    #[must_use]
    pub fn with_ffmpeg_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ffmpeg_path = path.into();
        self
    }

    #[must_use]
    pub fn with_ffprobe_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ffprobe_path = path.into();
        self
    }

    #[must_use]
    pub fn ffmpeg_path(&self) -> &Path {
        &self.ffmpeg_path
    }

    #[must_use]
    pub fn ffprobe_path(&self) -> &Path {
        &self.ffprobe_path
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

/// An exact point or duration on the source session timeline.
///
/// Device Session manifests expose both nanosecond clock values and sample-based
/// positions. Keeping the value rational avoids introducing floating-point
/// drift while the export plan is validated and translated to FFmpeg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TimelineTime {
    numerator: i64,
    denominator: u64,
}

impl TimelineTime {
    pub fn new(numerator: i64, denominator: u64) -> Result<Self, SessionExportError> {
        Self::from_wide_ratio(i128::from(numerator), u128::from(denominator))
    }

    fn from_wide_ratio(numerator: i128, denominator: u128) -> Result<Self, SessionExportError> {
        if denominator == 0 {
            return Err(SessionExportError::InvalidTimeline(
                "timeline denominator must be nonzero".to_string(),
            ));
        }
        if numerator == 0 {
            return Ok(Self::zero());
        }
        let divisor = greatest_common_divisor(numerator.unsigned_abs(), denominator);
        let denominator = denominator / divisor;
        if denominator > u128::from(MAX_TIMELINE_DENOMINATOR) {
            return Err(SessionExportError::InvalidTimeline(format!(
                "reduced timeline denominator exceeds {MAX_TIMELINE_DENOMINATOR}"
            )));
        }
        let divisor = i128::try_from(divisor).map_err(|_| {
            SessionExportError::InvalidTimeline(
                "timeline reduction divisor exceeds the supported range".to_string(),
            )
        })?;
        let numerator = numerator / divisor;
        Ok(Self {
            numerator: i64::try_from(numerator).map_err(|_| {
                SessionExportError::InvalidTimeline(
                    "reduced timeline numerator exceeds the supported range".to_string(),
                )
            })?,
            denominator: u64::try_from(denominator).map_err(|_| {
                SessionExportError::InvalidTimeline(
                    "timeline denominator exceeds the supported range".to_string(),
                )
            })?,
        })
    }

    #[must_use]
    pub const fn zero() -> Self {
        Self {
            numerator: 0,
            denominator: 1,
        }
    }

    pub fn from_nanoseconds(nanoseconds: i64) -> Result<Self, SessionExportError> {
        Self::new(nanoseconds, 1_000_000_000)
    }

    pub fn from_decimal_seconds(value: &str) -> Result<Self, SessionExportError> {
        let nanoseconds = parse_decimal_nanoseconds(value).map_err(|message| {
            SessionExportError::InvalidTimeline(format!(
                "manifest decimal time {value:?} is invalid: {message}"
            ))
        })?;
        Self::from_nanoseconds(nanoseconds)
    }

    pub fn from_samples(samples: u64, sample_rate_hz: u32) -> Result<Self, SessionExportError> {
        let samples = i64::try_from(samples).map_err(|_| {
            SessionExportError::InvalidTimeline(
                "audio sample position exceeds the supported timeline range".to_string(),
            )
        })?;
        Self::new(samples, u64::from(sample_rate_hz))
    }

    #[must_use]
    pub const fn numerator(self) -> i64 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }

    fn checked_add(self, other: Self) -> Result<Self, SessionExportError> {
        let denominator = u128::from(self.denominator) * u128::from(other.denominator);
        let left = i128::from(self.numerator)
            .checked_mul(i128::from(other.denominator))
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "timeline numerator overflowed while adding values".to_string(),
                )
            })?;
        let right = i128::from(other.numerator)
            .checked_mul(i128::from(self.denominator))
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "timeline numerator overflowed while adding values".to_string(),
                )
            })?;
        let numerator = left.checked_add(right).ok_or_else(|| {
            SessionExportError::InvalidTimeline(
                "timeline numerator overflowed while adding values".to_string(),
            )
        })?;
        Self::from_wide_ratio(numerator, denominator)
    }

    fn checked_sub(self, other: Self) -> Result<Self, SessionExportError> {
        let denominator = u128::from(self.denominator) * u128::from(other.denominator);
        let left = i128::from(self.numerator)
            .checked_mul(i128::from(other.denominator))
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "timeline numerator overflowed while subtracting values".to_string(),
                )
            })?;
        let right = i128::from(other.numerator)
            .checked_mul(i128::from(self.denominator))
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "timeline numerator overflowed while subtracting values".to_string(),
                )
            })?;
        let numerator = left.checked_sub(right).ok_or_else(|| {
            SessionExportError::InvalidTimeline(
                "timeline numerator overflowed while subtracting values".to_string(),
            )
        })?;
        Self::from_wide_ratio(numerator, denominator)
    }

    fn checked_mul_integer(self, value: i64) -> Result<Self, SessionExportError> {
        let numerator = i128::from(self.numerator) * i128::from(value);
        Self::from_wide_ratio(numerator, u128::from(self.denominator))
    }

    fn checked_mul_u64(self, value: u64) -> Result<Self, SessionExportError> {
        let numerator = i128::from(self.numerator)
            .checked_mul(i128::from(value))
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "timeline numerator overflowed while multiplying values".to_string(),
                )
            })?;
        Self::from_wide_ratio(numerator, u128::from(self.denominator))
    }

    fn checked_div_u64(self, value: u64) -> Result<Self, SessionExportError> {
        if value == 0 {
            return Err(SessionExportError::InvalidTimeline(
                "timeline divisor must be nonzero".to_string(),
            ));
        }
        let denominator = u128::from(self.denominator)
            .checked_mul(u128::from(value))
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "timeline denominator overflowed while dividing values".to_string(),
                )
            })?;
        Self::from_wide_ratio(i128::from(self.numerator), denominator)
    }

    fn rounded_nanoseconds(self) -> Result<i64, SessionExportError> {
        let scaled = i128::from(self.numerator) * 1_000_000_000_i128;
        let denominator = i128::from(self.denominator);
        let rounded = if scaled >= 0 {
            (scaled + denominator / 2) / denominator
        } else {
            (scaled - denominator / 2) / denominator
        };
        i64::try_from(rounded).map_err(|_| {
            SessionExportError::InvalidTimeline(
                "timeline value exceeds the supported nanosecond range".to_string(),
            )
        })
    }

    fn ceil_nanoseconds(self) -> Result<u64, SessionExportError> {
        if self <= Self::zero() {
            return Err(SessionExportError::InvalidTimeline(
                "timeline duration must be positive".to_string(),
            ));
        }
        let scaled = i128::from(self.numerator) * 1_000_000_000_i128;
        let denominator = i128::from(self.denominator);
        u64::try_from((scaled + denominator - 1) / denominator).map_err(|_| {
            SessionExportError::InvalidTimeline(
                "timeline duration exceeds the supported nanosecond range".to_string(),
            )
        })
    }

    fn ffmpeg_seconds(self) -> Result<String, SessionExportError> {
        let nanoseconds = i128::from(self.rounded_nanoseconds()?);
        let sign = if nanoseconds < 0 { "-" } else { "" };
        let absolute = nanoseconds.abs();
        let seconds = absolute / 1_000_000_000;
        let subsecond = absolute % 1_000_000_000;
        Ok(format!("{sign}{seconds}.{subsecond:09}"))
    }
}

impl PartialOrd for TimelineTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimelineTime {
    fn cmp(&self, other: &Self) -> Ordering {
        (i128::from(self.numerator) * i128::from(other.denominator))
            .cmp(&(i128::from(other.numerator) * i128::from(self.denominator)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTimelineClock {
    HostMonotonic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedVideoSegment {
    pub index: u32,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub start_frame: u64,
    pub end_frame: u64,
    pub start_time: TimelineTime,
    pub end_time: TimelineTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedAudioSegment {
    pub index: u32,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub start_sample: u64,
    pub end_sample: u64,
    /// Common session-clock time: `session_start_offset + start_sample / sample_rate_hz`.
    pub start_time: TimelineTime,
    /// Common session-clock time: `session_start_offset + end_sample / sample_rate_hz`.
    pub end_time: TimelineTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestAudioTimeline {
    pub sample_rate_hz: u32,
    pub channels: u32,
    pub sample_count: u64,
    /// Audio start on the common session clock.
    pub session_start_offset: TimelineTime,
    /// Audio recorder stop on the common session clock.
    pub session_stop_offset: TimelineTime,
    pub segments: Vec<TimedAudioSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSessionTimeline {
    pub source_manifest_sha256: String,
    pub clock: SessionTimelineClock,
    pub video_tick: TimelineTime,
    pub eye_width: u32,
    pub eye_height: u32,
    pub left_segments: Vec<TimedVideoSegment>,
    pub right_segments: Vec<TimedVideoSegment>,
    pub audio: Option<ManifestAudioTimeline>,
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
    timing: Option<SessionExportTimingPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExportTimingPlan {
    manifest: ManifestSessionTimeline,
    paired_frames: u64,
    video_start: TimelineTime,
    video_end: TimelineTime,
    audio_start: Option<TimelineTime>,
    audio_end: Option<TimelineTime>,
}

impl SessionExportTimingPlan {
    #[must_use]
    pub fn source_manifest_sha256(&self) -> &str {
        &self.manifest.source_manifest_sha256
    }

    #[must_use]
    pub const fn paired_frames(&self) -> u64 {
        self.paired_frames
    }

    #[must_use]
    pub const fn video_start(&self) -> TimelineTime {
        self.video_start
    }

    #[must_use]
    pub const fn video_end(&self) -> TimelineTime {
        self.video_end
    }

    #[must_use]
    pub const fn video_tick(&self) -> TimelineTime {
        self.manifest.video_tick
    }

    #[must_use]
    pub const fn audio_start_offset(&self) -> Option<TimelineTime> {
        self.audio_start
    }

    #[must_use]
    pub const fn audio_end(&self) -> Option<TimelineTime> {
        self.audio_end
    }

    #[must_use]
    pub fn manifest(&self) -> &ManifestSessionTimeline {
        &self.manifest
    }
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
            timing: None,
        })
    }

    pub fn from_manifest_timeline(
        source_root: impl Into<PathBuf>,
        output_path: impl Into<PathBuf>,
        overwrite: bool,
        mut timeline: ManifestSessionTimeline,
    ) -> Result<Self, SessionExportError> {
        let source_root = canonical_source_root(&source_root.into())?;
        let output_path = validate_output_path(&output_path.into(), overwrite)?;
        validate_and_resolve_manifest_artifacts(&source_root, &mut timeline)?;
        let timing = validate_manifest_timeline(&timeline)?;
        let video = SessionExportVideoInput::SeparateEyes {
            left_segments: timeline
                .left_segments
                .iter()
                .map(|segment| segment.path.clone())
                .collect(),
            right_segments: timeline
                .right_segments
                .iter()
                .map(|segment| segment.path.clone())
                .collect(),
        };
        let audio_segments = timeline
            .audio
            .as_ref()
            .map(|audio| {
                audio
                    .segments
                    .iter()
                    .map(|segment| segment.path.clone())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            source_root,
            output_path,
            overwrite,
            video,
            audio_segments,
            timing: Some(timing),
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

    #[must_use]
    pub fn timing(&self) -> Option<&SessionExportTimingPlan> {
        self.timing.as_ref()
    }
}

fn validate_manifest_timeline(
    manifest: &ManifestSessionTimeline,
) -> Result<SessionExportTimingPlan, SessionExportError> {
    if manifest.source_manifest_sha256.len() != 64
        || !manifest
            .source_manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SessionExportError::InvalidTimeline(
            "source manifest digest must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    if manifest.video_tick <= TimelineTime::zero() {
        return Err(SessionExportError::InvalidTimeline(
            "source video tick must be positive".to_string(),
        ));
    }
    if manifest.eye_width == 0 || manifest.eye_height == 0 {
        return Err(SessionExportError::InvalidTimeline(
            "source eye dimensions must be positive".to_string(),
        ));
    }

    let left = validate_video_eye("left", &manifest.left_segments)?;
    let right = validate_video_eye("right", &manifest.right_segments)?;
    if manifest.left_segments.len() != manifest.right_segments.len() {
        return Err(SessionExportError::InvalidTimeline(format!(
            "left/right segment counts differ: {} left, {} right",
            manifest.left_segments.len(),
            manifest.right_segments.len()
        )));
    }
    for (pair_index, (left, right)) in manifest
        .left_segments
        .iter()
        .zip(&manifest.right_segments)
        .enumerate()
    {
        if left.index != right.index
            || left.start_frame != right.start_frame
            || left.end_frame != right.end_frame
            || left.start_time != right.start_time
            || left.end_time != right.end_time
        {
            return Err(SessionExportError::InvalidTimeline(format!(
                "left/right frame and time coverage differs at segment pair {pair_index}"
            )));
        }
    }
    if left != right {
        return Err(SessionExportError::InvalidTimeline(
            "left/right aggregate frame and time coverage differs".to_string(),
        ));
    }

    let (audio_start, audio_end) = match manifest.audio.as_ref() {
        Some(audio) => {
            validate_audio_timeline(audio, manifest.video_tick)?;
            (
                Some(audio.session_start_offset),
                Some(audio.session_stop_offset),
            )
        }
        None => (None, None),
    };

    Ok(SessionExportTimingPlan {
        manifest: manifest.clone(),
        paired_frames: left.frames,
        video_start: left.start,
        video_end: left.end,
        audio_start,
        audio_end,
    })
}

fn validate_and_resolve_manifest_artifacts(
    source_root: &Path,
    manifest: &mut ManifestSessionTimeline,
) -> Result<(), SessionExportError> {
    let mut seen = BTreeSet::new();
    for segment in &mut manifest.left_segments {
        segment.path = validate_bound_artifact(
            source_root,
            &segment.path,
            segment.bytes,
            &segment.sha256,
            "left-eye video",
            &mut seen,
        )?;
    }
    for segment in &mut manifest.right_segments {
        segment.path = validate_bound_artifact(
            source_root,
            &segment.path,
            segment.bytes,
            &segment.sha256,
            "right-eye video",
            &mut seen,
        )?;
    }
    if let Some(audio) = &mut manifest.audio {
        for segment in &mut audio.segments {
            segment.path = validate_bound_artifact(
                source_root,
                &segment.path,
                segment.bytes,
                &segment.sha256,
                "audio",
                &mut seen,
            )?;
        }
    }
    Ok(())
}

fn verify_manifest_artifacts(
    source_root: &Path,
    manifest: &ManifestSessionTimeline,
) -> Result<(), SessionExportError> {
    let mut seen = BTreeSet::new();
    for segment in &manifest.left_segments {
        validate_bound_artifact(
            source_root,
            &segment.path,
            segment.bytes,
            &segment.sha256,
            "left-eye video",
            &mut seen,
        )?;
    }
    for segment in &manifest.right_segments {
        validate_bound_artifact(
            source_root,
            &segment.path,
            segment.bytes,
            &segment.sha256,
            "right-eye video",
            &mut seen,
        )?;
    }
    if let Some(audio) = &manifest.audio {
        for segment in &audio.segments {
            validate_bound_artifact(
                source_root,
                &segment.path,
                segment.bytes,
                &segment.sha256,
                "audio",
                &mut seen,
            )?;
        }
    }
    Ok(())
}

fn validate_bound_artifact(
    source_root: &Path,
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    role: &str,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<PathBuf, SessionExportError> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SessionExportError::InvalidTimeline(format!(
            "{role} artifact digest must be 64 lowercase hexadecimal characters"
        )));
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        source_root.join(path)
    };
    let link_metadata =
        fs::symlink_metadata(&candidate).map_err(|error| SessionExportError::Io {
            context: "inspect timeline artifact",
            path: candidate.clone(),
            source: error,
        })?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(SessionExportError::InvalidTimeline(format!(
            "{role} timeline artifact must be a regular file without a final symlink: {}",
            candidate.display()
        )));
    }
    let canonical = fs::canonicalize(&candidate).map_err(|error| SessionExportError::Io {
        context: "canonicalize timeline artifact",
        path: candidate.clone(),
        source: error,
    })?;
    if !canonical.starts_with(source_root) {
        return Err(SessionExportError::InvalidTimeline(format!(
            "{role} timeline artifact escapes the source root: {}",
            candidate.display()
        )));
    }
    if !seen.insert(canonical.clone()) {
        return Err(SessionExportError::InvalidTimeline(format!(
            "timeline artifact is bound more than once: {}",
            canonical.display()
        )));
    }
    if link_metadata.len() != expected_bytes {
        return Err(SessionExportError::InvalidTimeline(format!(
            "{role} artifact byte count changed: expected {expected_bytes}, found {}",
            link_metadata.len()
        )));
    }
    let actual_sha256 = sha256_file(&canonical)?;
    if actual_sha256 != expected_sha256 {
        return Err(SessionExportError::InvalidTimeline(format!(
            "{role} artifact digest changed before export"
        )));
    }
    Ok(canonical)
}

fn sha256_file(path: &Path) -> Result<String, SessionExportError> {
    let mut file = fs::File::open(path).map_err(|error| SessionExportError::Io {
        context: "open file for sha256",
        path: path.to_path_buf(),
        source: error,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| SessionExportError::Io {
                context: "read file for sha256",
                path: path.to_path_buf(),
                source: error,
            })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VideoEyeCoverage {
    start: TimelineTime,
    end: TimelineTime,
    frames: u64,
}

fn validate_video_eye(
    eye: &str,
    segments: &[TimedVideoSegment],
) -> Result<VideoEyeCoverage, SessionExportError> {
    let first = segments.first().ok_or_else(|| {
        SessionExportError::InvalidTimeline(format!(
            "manifest timeline has no {eye}-eye video segments"
        ))
    })?;
    let mut previous_end_frame = None;
    let mut previous_end_time = None;
    let mut frames = 0_u64;
    for (position, segment) in segments.iter().enumerate() {
        if usize::try_from(segment.index).ok() != Some(position) {
            return Err(SessionExportError::InvalidTimeline(format!(
                "{eye}-eye segment index {} is not the expected {position}",
                segment.index
            )));
        }
        if segment.end_frame <= segment.start_frame {
            return Err(SessionExportError::InvalidTimeline(format!(
                "{eye}-eye segment {position} has an empty frame range"
            )));
        }
        if segment.start_time < TimelineTime::zero() || segment.end_time <= segment.start_time {
            return Err(SessionExportError::InvalidTimeline(format!(
                "{eye}-eye segment {position} has an invalid time range"
            )));
        }
        if previous_end_frame.is_some_and(|end| end != segment.start_frame) {
            return Err(SessionExportError::InvalidTimeline(format!(
                "{eye}-eye frame coverage is not contiguous at segment {position}"
            )));
        }
        if previous_end_time.is_some_and(|end| end != segment.start_time) {
            return Err(SessionExportError::InvalidTimeline(format!(
                "{eye}-eye time coverage is not contiguous at segment {position}"
            )));
        }
        frames = frames
            .checked_add(segment.end_frame - segment.start_frame)
            .ok_or_else(|| {
                SessionExportError::InvalidTimeline(
                    "video frame count overflowed while validating the manifest".to_string(),
                )
            })?;
        previous_end_frame = Some(segment.end_frame);
        previous_end_time = Some(segment.end_time);
    }

    Ok(VideoEyeCoverage {
        start: first.start_time,
        end: previous_end_time.expect("non-empty segments have an end time"),
        frames,
    })
}

fn validate_audio_timeline(
    audio: &ManifestAudioTimeline,
    video_tick: TimelineTime,
) -> Result<(), SessionExportError> {
    if audio.sample_rate_hz == 0
        || !(1..=8).contains(&audio.channels)
        || audio.sample_count == 0
        || audio.segments.is_empty()
    {
        return Err(SessionExportError::InvalidTimeline(
            "audio timeline must contain a supported sample rate, channel count, samples, and segments".to_string(),
        ));
    }
    if audio.session_start_offset < TimelineTime::zero()
        || audio.session_stop_offset <= audio.session_start_offset
    {
        return Err(SessionExportError::InvalidTimeline(
            "audio common-clock offsets are invalid".to_string(),
        ));
    }

    let one_nanosecond = TimelineTime::from_nanoseconds(1)?;
    let mut previous_end_sample = 0_u64;
    let mut previous_end_time = None;
    for (position, segment) in audio.segments.iter().enumerate() {
        if usize::try_from(segment.index).ok() != Some(position) {
            return Err(SessionExportError::InvalidTimeline(format!(
                "audio segment index {} is not the expected {position}",
                segment.index
            )));
        }
        if segment.start_sample != previous_end_sample || segment.end_sample <= segment.start_sample
        {
            return Err(SessionExportError::InvalidTimeline(format!(
                "audio sample coverage is not contiguous at segment {position}"
            )));
        }
        if previous_end_time.is_some_and(|end| segment.start_time != end)
            || segment.end_time <= segment.start_time
        {
            return Err(SessionExportError::InvalidTimeline(format!(
                "audio time coverage is not contiguous at segment {position}"
            )));
        }
        let expected_start = audio
            .session_start_offset
            .checked_add(TimelineTime::from_samples(
                segment.start_sample,
                audio.sample_rate_hz,
            )?)?;
        let expected_end = audio
            .session_start_offset
            .checked_add(TimelineTime::from_samples(
                segment.end_sample,
                audio.sample_rate_hz,
            )?)?;
        if timeline_abs_difference(segment.start_time, expected_start)? > one_nanosecond
            || timeline_abs_difference(segment.end_time, expected_end)? > one_nanosecond
        {
            return Err(SessionExportError::InvalidTimeline(format!(
                "audio segment {position} time range does not match its sample range"
            )));
        }
        previous_end_sample = segment.end_sample;
        previous_end_time = Some(segment.end_time);
    }
    if previous_end_sample != audio.sample_count {
        return Err(SessionExportError::InvalidTimeline(format!(
            "audio segments end at sample {previous_end_sample}, expected {}",
            audio.sample_count
        )));
    }

    let final_segment_end = previous_end_time.expect("non-empty audio segments have an end time");
    let audio_frame = TimelineTime::from_samples(1024, audio.sample_rate_hz)?;
    let allowed_stop_residual_ns = video_tick
        .ceil_nanoseconds()?
        .max(audio_frame.ceil_nanoseconds()?);
    let stop_residual = timeline_abs_difference(audio.session_stop_offset, final_segment_end)?;
    let stop_residual_ns = if stop_residual == TimelineTime::zero() {
        0
    } else {
        stop_residual.ceil_nanoseconds()?
    };
    if stop_residual_ns > allowed_stop_residual_ns {
        return Err(SessionExportError::InvalidTimeline(format!(
            "audio stop offset differs from the final segment end by {stop_residual_ns} ns, exceeding the allowed {allowed_stop_residual_ns} ns"
        )));
    }
    Ok(())
}

fn timeline_abs_difference(
    left: TimelineTime,
    right: TimelineTime,
) -> Result<TimelineTime, SessionExportError> {
    if left >= right {
        left.checked_sub(right)
    } else {
        right.checked_sub(left)
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionExportReceipt {
    pub output_path: PathBuf,
    pub video_segment_count: usize,
    pub audio_segment_count: usize,
    pub output_size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline_verification: Option<SessionExportTimelineVerification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_media: Option<SessionExportOutputMedia>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExportOutputMedia {
    pub video_codec: String,
    pub layout: String,
    pub width: u32,
    pub eye_width: u32,
    pub height: u32,
    pub audio: Option<SessionExportOutputAudio>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExportOutputAudio {
    pub codec: String,
    pub sample_rate_hz: u32,
    pub channels: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineVerificationVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExportProbeSummary {
    pub output_sha256: String,
    pub output_bytes: u64,
    pub video_streams: u32,
    pub audio_streams: u32,
    pub frame_count: u64,
    pub duration_ns: u64,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExportTimelineVerification {
    pub policy_id: String,
    pub verdict: TimelineVerificationVerdict,
    pub source_manifest_sha256: String,
    pub left_right_pairing: TimelineVerificationVerdict,
    pub paired_frames: u64,
    pub video_start_residual_ns: i64,
    pub video_end_residual_ns: i64,
    pub audio_start_residual_ns: Option<i64>,
    pub audio_end_residual_ns: Option<i64>,
    pub source_video_tick_ns: u64,
    pub encoding_audio_frame_ns: Option<u64>,
    pub allowed_residual_ns: u64,
    pub preserved_leading_gap_ns: u64,
    pub verified_at: String,
    pub probe_summary: SessionExportProbeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputMediaProbe {
    video_streams: Vec<OutputStreamProbe>,
    audio_streams: Vec<OutputStreamProbe>,
    video_frame_timeline: Option<OutputVideoFrameTimelineProbe>,
    audio_frame_timeline: Option<OutputAudioFrameTimelineProbe>,
    report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputStreamProbe {
    codec_name: String,
    time_base: TimelineTime,
    start: TimelineTime,
    end: TimelineTime,
    frame_count: Option<u64>,
    sample_rate_hz: Option<u32>,
    channels: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputVideoFrameTimelineProbe {
    frame_count: u64,
    inferred_tick: TimelineTime,
    timestamp_tolerance_ns: u64,
    max_timestamp_residual_ns: i64,
    max_timestamp_residual_frame: u64,
    report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputAudioFrameTimelineProbe {
    frame_count: u64,
    decoded_sample_frames: u64,
    timestamp_tolerance_ns: u64,
    max_timestamp_residual_ns: i64,
    max_timestamp_residual_frame: u64,
    report_sha256: String,
}

impl OutputMediaProbe {
    pub fn from_ffprobe_json(bytes: &[u8]) -> Result<Self, SessionExportError> {
        let report: Value = serde_json::from_slice(bytes).map_err(|error| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe returned invalid JSON: {error}"
            ))
        })?;
        let streams = report
            .get("streams")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(
                    "ffprobe report has no streams array".to_string(),
                )
            })?;
        let mut video_streams = Vec::new();
        let mut audio_streams = Vec::new();
        for stream in streams {
            let codec_type = required_probe_string(stream, "codec_type")?;
            if codec_type != "video" && codec_type != "audio" {
                continue;
            }
            let time_base = parse_probe_time_base(required_probe_string(stream, "time_base")?)?;
            let start = probe_stream_time(stream, "start_pts", "start_time", time_base)?;
            let duration = probe_stream_time(stream, "duration_ts", "duration", time_base)?;
            if duration <= TimelineTime::zero() {
                return Err(SessionExportError::OutputVerificationFailed(format!(
                    "ffprobe {codec_type} stream has a non-positive duration"
                )));
            }
            let parsed = OutputStreamProbe {
                codec_name: required_probe_string(stream, "codec_name")?.to_string(),
                time_base,
                start,
                end: start.checked_add(duration)?,
                frame_count: optional_probe_u64(stream, "nb_read_frames")?
                    .or(optional_probe_u64(stream, "nb_frames")?),
                sample_rate_hz: optional_probe_u64(stream, "sample_rate")?
                    .map(|value| {
                        u32::try_from(value).map_err(|_| {
                            SessionExportError::OutputVerificationFailed(
                                "ffprobe sample rate exceeds the supported range".to_string(),
                            )
                        })
                    })
                    .transpose()?,
                channels: optional_probe_u64(stream, "channels")?
                    .map(|value| {
                        u32::try_from(value).map_err(|_| {
                            SessionExportError::OutputVerificationFailed(
                                "ffprobe channel count exceeds the supported range".to_string(),
                            )
                        })
                    })
                    .transpose()?,
                width: optional_probe_u64(stream, "width")?
                    .map(|value| {
                        u32::try_from(value).map_err(|_| {
                            SessionExportError::OutputVerificationFailed(
                                "ffprobe width exceeds the supported range".to_string(),
                            )
                        })
                    })
                    .transpose()?,
                height: optional_probe_u64(stream, "height")?
                    .map(|value| {
                        u32::try_from(value).map_err(|_| {
                            SessionExportError::OutputVerificationFailed(
                                "ffprobe height exceeds the supported range".to_string(),
                            )
                        })
                    })
                    .transpose()?,
            };
            if codec_type == "video" {
                video_streams.push(parsed);
            } else {
                audio_streams.push(parsed);
            }
        }
        Ok(Self {
            video_streams,
            audio_streams,
            video_frame_timeline: None,
            audio_frame_timeline: None,
            report_sha256: sha256_bytes(bytes),
        })
    }

    #[must_use]
    pub fn video_stream_count(&self) -> usize {
        self.video_streams.len()
    }

    #[must_use]
    pub fn audio_stream_count(&self) -> usize {
        self.audio_streams.len()
    }

    #[must_use]
    pub fn report_sha256(&self) -> &str {
        &self.report_sha256
    }

    #[cfg(test)]
    fn with_uniform_video_frame_evidence_for_test(mut self) -> Result<Self, SessionExportError> {
        let video = self.video_streams.first().ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "test probe has no video stream".to_string(),
            )
        })?;
        let frame_count = video
            .frame_count
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(
                    "test probe has no positive video frame count".to_string(),
                )
            })?;
        let inferred_tick = video
            .end
            .checked_sub(video.start)?
            .checked_div_u64(frame_count)?;
        let frame_report_sha256 = sha256_bytes(b"uniform-test-video-frame-evidence");
        self.video_frame_timeline = Some(OutputVideoFrameTimelineProbe {
            frame_count,
            inferred_tick,
            timestamp_tolerance_ns: video.time_base.ceil_nanoseconds()?.div_ceil(2),
            max_timestamp_residual_ns: 0,
            max_timestamp_residual_frame: 0,
            report_sha256: frame_report_sha256.clone(),
        });
        self.report_sha256 =
            combined_probe_report_sha256(self.report_sha256.as_str(), frame_report_sha256.as_str());
        if let Some(audio) = self.audio_streams.first() {
            let sample_rate_hz =
                audio
                    .sample_rate_hz
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        SessionExportError::OutputVerificationFailed(
                            "test probe has no positive audio sample rate".to_string(),
                        )
                    })?;
            let frame_report_sha256 = sha256_bytes(b"uniform-test-audio-frame-evidence");
            self.audio_frame_timeline = Some(OutputAudioFrameTimelineProbe {
                frame_count: 1,
                decoded_sample_frames: u64::from(sample_rate_hz),
                timestamp_tolerance_ns: audio.time_base.ceil_nanoseconds()?.div_ceil(2),
                max_timestamp_residual_ns: 0,
                max_timestamp_residual_frame: 0,
                report_sha256: frame_report_sha256.clone(),
            });
            self.report_sha256 = combined_audio_probe_report_sha256(
                self.report_sha256.as_str(),
                frame_report_sha256.as_str(),
            );
        }
        Ok(self)
    }

    pub fn output_media(&self) -> Result<SessionExportOutputMedia, SessionExportError> {
        if self.video_streams.len() != 1 || self.audio_streams.len() > 1 {
            return Err(SessionExportError::OutputVerificationFailed(
                "output media properties require exactly one video and at most one audio stream"
                    .to_string(),
            ));
        }
        let video = &self.video_streams[0];
        let width = video.width.filter(|value| *value > 0).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe did not report a positive video width".to_string(),
            )
        })?;
        let height = video.height.filter(|value| *value > 0).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe did not report a positive video height".to_string(),
            )
        })?;
        let eye_width = side_by_side_eye_width(width)?;
        let audio = self
            .audio_streams
            .first()
            .map(|audio| {
                Ok(SessionExportOutputAudio {
                    codec: audio.codec_name.clone(),
                    sample_rate_hz: audio.sample_rate_hz.filter(|value| *value > 0).ok_or_else(
                        || {
                            SessionExportError::OutputVerificationFailed(
                                "ffprobe did not report a positive audio sample rate".to_string(),
                            )
                        },
                    )?,
                    channels: audio.channels.filter(|value| *value > 0).ok_or_else(|| {
                        SessionExportError::OutputVerificationFailed(
                            "ffprobe did not report a positive audio channel count".to_string(),
                        )
                    })?,
                })
            })
            .transpose()?;
        Ok(SessionExportOutputMedia {
            video_codec: video.codec_name.clone(),
            layout: "left-right-side-by-side".to_string(),
            width,
            eye_width,
            height,
            audio,
        })
    }
}

fn read_video_frame_timeline_probe(
    reader: impl Read,
    media_path: &Path,
    time_base: TimelineTime,
    stream_start: TimelineTime,
    stream_end: TimelineTime,
    expected_frame_count: u64,
) -> Result<OutputVideoFrameTimelineProbe, SessionExportError> {
    if expected_frame_count == 0 {
        return Err(SessionExportError::OutputVerificationFailed(
            "ffprobe reported a zero video frame count".to_string(),
        ));
    }
    let inferred_tick = stream_end
        .checked_sub(stream_start)?
        .checked_div_u64(expected_frame_count)?;
    let timestamp_tolerance_ns = time_base.ceil_nanoseconds()?.div_ceil(2);
    let mut reader = BufReader::new(reader);
    let mut report_hasher = Sha256::new();
    let mut line = Vec::with_capacity(32);
    let mut frame_count = 0_u64;
    let mut max_timestamp_residual_ns = 0_i64;
    let mut max_timestamp_residual_frame = 0_u64;
    loop {
        line.clear();
        let read = Read::by_ref(&mut reader)
            .take(257)
            .read_until(b'\n', &mut line)
            .map_err(|error| SessionExportError::Io {
                context: "read ffprobe video frame timestamps",
                path: media_path.to_path_buf(),
                source: error,
            })?;
        if read == 0 {
            break;
        }
        if line.len() > 256 {
            return Err(SessionExportError::OutputVerificationFailed(
                "ffprobe video frame timestamp line exceeds 256 bytes".to_string(),
            ));
        }
        report_hasher.update(&line);
        let text = std::str::from_utf8(&line).map_err(|_| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe video frame timestamps are not UTF-8".to_string(),
            )
        })?;
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let (field, value) = text.split_once('=').ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe video frame field {text:?} is not a key/value pair"
            ))
        })?;
        let field = field.trim();
        let value = value.trim();
        if field.contains("_side_data_list_") {
            if !field.starts_with("frames_frame_") {
                return Err(SessionExportError::OutputVerificationFailed(format!(
                    "ffprobe video frame side-data field {field:?} has an unexpected name"
                )));
            }
            continue;
        }
        let Some(frame_index) = field
            .strip_prefix("frames_frame_")
            .and_then(|field| field.strip_suffix("_best_effort_timestamp"))
            .and_then(|field| field.parse::<u64>().ok())
        else {
            return Err(SessionExportError::OutputVerificationFailed(format!(
                "ffprobe video frame field {field:?} is not a timestamp"
            )));
        };
        if frame_index != frame_count {
            return Err(SessionExportError::OutputVerificationFailed(format!(
                "ffprobe video frame timestamp index {frame_index} is not the expected {frame_count}"
            )));
        }
        let ticks = value.parse::<i64>().map_err(|_| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe video frame timestamp {value:?} is not an integer"
            ))
        })?;
        let actual = time_base.checked_mul_integer(ticks)?;
        let expected = stream_start.checked_add(inferred_tick.checked_mul_u64(frame_count)?)?;
        let residual = timeline_residual_ns(actual, expected)?;
        if residual.unsigned_abs() > max_timestamp_residual_ns.unsigned_abs() {
            max_timestamp_residual_ns = residual;
            max_timestamp_residual_frame = frame_count;
        }
        frame_count = frame_count.checked_add(1).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe video frame count overflowed".to_string(),
            )
        })?;
    }
    Ok(OutputVideoFrameTimelineProbe {
        frame_count,
        inferred_tick,
        timestamp_tolerance_ns,
        max_timestamp_residual_ns,
        max_timestamp_residual_frame,
        report_sha256: format!("{:x}", report_hasher.finalize()),
    })
}

fn read_audio_frame_timeline_probe(
    reader: impl Read,
    media_path: &Path,
    time_base: TimelineTime,
    stream_start: TimelineTime,
    sample_rate_hz: u32,
) -> Result<OutputAudioFrameTimelineProbe, SessionExportError> {
    let timestamp_tolerance_ns = time_base.ceil_nanoseconds()?.div_ceil(2);
    let mut reader = BufReader::new(reader);
    let mut report_hasher = Sha256::new();
    let mut line = Vec::with_capacity(48);
    let mut frame_count = 0_u64;
    let mut decoded_sample_frames = 0_u64;
    let mut expected_timestamp = stream_start;
    let mut max_timestamp_residual_ns = 0_i64;
    let mut max_timestamp_residual_frame = 0_u64;
    loop {
        line.clear();
        let read = Read::by_ref(&mut reader)
            .take(129)
            .read_until(b'\n', &mut line)
            .map_err(|error| SessionExportError::Io {
                context: "read ffprobe audio frame timestamps",
                path: media_path.to_path_buf(),
                source: error,
            })?;
        if read == 0 {
            break;
        }
        if line.len() > 128 {
            return Err(SessionExportError::OutputVerificationFailed(
                "ffprobe audio frame timestamp line exceeds 128 bytes".to_string(),
            ));
        }
        report_hasher.update(&line);
        let text = std::str::from_utf8(&line).map_err(|_| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe audio frame timestamps are not UTF-8".to_string(),
            )
        })?;
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let mut fields = text.split(',');
        let ticks = fields
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(format!(
                    "ffprobe audio frame timestamp in {text:?} is not an integer"
                ))
            })?;
        let samples = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(format!(
                    "ffprobe audio frame sample count in {text:?} is not a positive integer"
                ))
            })?;
        if fields.next().is_some() {
            return Err(SessionExportError::OutputVerificationFailed(format!(
                "ffprobe audio frame report {text:?} has unexpected fields"
            )));
        }
        let actual_timestamp = time_base.checked_mul_integer(ticks)?;
        let residual = timeline_residual_ns(actual_timestamp, expected_timestamp)?;
        if residual.unsigned_abs() > max_timestamp_residual_ns.unsigned_abs() {
            max_timestamp_residual_ns = residual;
            max_timestamp_residual_frame = frame_count;
        }
        expected_timestamp =
            actual_timestamp.checked_add(TimelineTime::from_samples(samples, sample_rate_hz)?)?;
        decoded_sample_frames = decoded_sample_frames.checked_add(samples).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe decoded output audio sample frame count overflowed".to_string(),
            )
        })?;
        frame_count = frame_count.checked_add(1).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe decoded output audio frame count overflowed".to_string(),
            )
        })?;
    }
    if frame_count == 0 {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "ffprobe reported no decoded audio frames for {}",
            media_path.display()
        )));
    }
    Ok(OutputAudioFrameTimelineProbe {
        frame_count,
        decoded_sample_frames,
        timestamp_tolerance_ns,
        max_timestamp_residual_ns,
        max_timestamp_residual_frame,
        report_sha256: format!("{:x}", report_hasher.finalize()),
    })
}

fn combined_probe_report_sha256(stream_report_sha256: &str, frame_report_sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"openaria.ffprobe.streams.v1\0");
    hasher.update(stream_report_sha256.as_bytes());
    hasher.update(b"\0openaria.ffprobe.video-frames.v1\0");
    hasher.update(frame_report_sha256.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn combined_audio_probe_report_sha256(
    prior_report_sha256: &str,
    frame_report_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"openaria.ffprobe.prior-evidence.v1\0");
    hasher.update(prior_report_sha256.as_bytes());
    hasher.update(b"\0openaria.ffprobe.audio-frames.v1\0");
    hasher.update(frame_report_sha256.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn side_by_side_eye_width(width: u32) -> Result<u32, SessionExportError> {
    if width == 0 || !width.is_multiple_of(2) {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived SBS output width {width} cannot be divided into two equal eye widths"
        )));
    }
    Ok(width / 2)
}

pub fn verify_session_export_output(
    plan: &SessionExportPlan,
    output_path: &Path,
    probe: &OutputMediaProbe,
) -> Result<SessionExportTimelineVerification, SessionExportError> {
    let timing = plan.timing().ok_or_else(|| {
        SessionExportError::InvalidRequest(
            "output timing verification requires a manifest timeline plan".to_string(),
        )
    })?;
    if probe.video_streams.len() != 1 {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived output has {} video streams; expected exactly one",
            probe.video_streams.len()
        )));
    }
    let expected_audio_streams = usize::from(timing.manifest.audio.is_some());
    if probe.audio_streams.len() != expected_audio_streams {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived output has {} audio streams; expected {expected_audio_streams}",
            probe.audio_streams.len()
        )));
    }

    let video = &probe.video_streams[0];
    if video.codec_name != "h264" {
        return Err(SessionExportError::OutputVerificationFailed(
            "derived output video stream is not a non-empty H.264 stream".to_string(),
        ));
    }
    let video_width = video.width.filter(|width| *width > 0).ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(
            "derived output video stream has no positive width".to_string(),
        )
    })?;
    if video.height.is_none_or(|height| height == 0) {
        return Err(SessionExportError::OutputVerificationFailed(
            "derived output video stream has no positive height".to_string(),
        ));
    }
    side_by_side_eye_width(video_width)?;
    let expected_width = timing.manifest().eye_width.checked_mul(2).ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(
            "declared side-by-side output width overflowed".to_string(),
        )
    })?;
    if video_width != expected_width || video.height != Some(timing.manifest().eye_height) {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived SBS dimensions {}x{} do not match declared {}x{}",
            video_width,
            video.height.unwrap_or_default(),
            expected_width,
            timing.manifest().eye_height
        )));
    }
    let frame_count = video.frame_count.ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(
            "ffprobe did not report a decoded video frame count".to_string(),
        )
    })?;
    if frame_count != timing.paired_frames {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived output frame count {frame_count} does not match {} paired source frames",
            timing.paired_frames
        )));
    }
    let source_video_tick_ns = timing.video_tick().ceil_nanoseconds()?;
    let video_start_residual_ns = timeline_residual_ns(video.start, timing.video_start)?;
    let video_end_residual_ns = timeline_residual_ns(video.end, timing.video_end)?;
    if video_start_residual_ns.unsigned_abs() > source_video_tick_ns
        || video_end_residual_ns.unsigned_abs() > source_video_tick_ns
    {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived video timing residual exceeds one source video tick ({source_video_tick_ns} ns)"
        )));
    }
    let frame_timeline = probe.video_frame_timeline.as_ref().ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(
            "ffprobe did not provide per-frame video timestamp evidence".to_string(),
        )
    })?;
    if frame_timeline.frame_count != frame_count {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "ffprobe per-frame timestamp count {} does not match decoded video frame count {frame_count}",
            frame_timeline.frame_count
        )));
    }
    if frame_timeline.max_timestamp_residual_ns.unsigned_abs()
        > frame_timeline.timestamp_tolerance_ns
    {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived output frame timestamp {} has residual {} ns from its stream clock; allowed {} ns",
            frame_timeline.max_timestamp_residual_frame,
            frame_timeline.max_timestamp_residual_ns,
            frame_timeline.timestamp_tolerance_ns
        )));
    }
    let observed_timestamp_uncertainty = frame_timeline.max_timestamp_residual_ns.unsigned_abs();
    // The streaming reader compared every raw PTS with the stream's arithmetic
    // clock and retained its worst error. Combining that bound with each
    // stream-clock/manifest-clock residual proves every frame without storing
    // an attacker-controlled number of timestamps in memory.
    for frame_index in 0..timing.paired_frames {
        let output_clock_timestamp = video
            .start
            .checked_add(frame_timeline.inferred_tick.checked_mul_u64(frame_index)?)?;
        let manifest_timestamp = timing
            .video_start
            .checked_add(timing.video_tick().checked_mul_u64(frame_index)?)?;
        let clock_residual =
            timeline_residual_ns(output_clock_timestamp, manifest_timestamp)?.unsigned_abs();
        let proven_residual = clock_residual
            .checked_add(observed_timestamp_uncertainty)
            .ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(
                    "derived output frame timestamp residual overflowed".to_string(),
                )
            })?;
        if proven_residual > frame_timeline.timestamp_tolerance_ns {
            return Err(SessionExportError::OutputVerificationFailed(format!(
                "derived output frame timestamp {frame_index} differs from the manifest clock by at least {proven_residual} ns; allowed {} ns",
                frame_timeline.timestamp_tolerance_ns
            )));
        }
    }

    let (audio_start_residual_ns, audio_end_residual_ns, encoding_audio_frame_ns) = match (
        timing.manifest.audio.as_ref(),
        probe.audio_streams.first(),
    ) {
        (Some(source), Some(audio)) => {
            if audio.codec_name != "aac"
                || audio.sample_rate_hz != Some(source.sample_rate_hz)
                || audio.channels != Some(source.channels)
            {
                return Err(SessionExportError::OutputVerificationFailed(
                        "derived output audio stream does not match the source rate, channels, or AAC contract".to_string(),
                    ));
            }
            let frame_timeline = probe.audio_frame_timeline.as_ref().ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(
                    "ffprobe did not provide per-frame audio timestamp evidence".to_string(),
                )
            })?;
            if frame_timeline.frame_count == 0 || frame_timeline.decoded_sample_frames == 0 {
                return Err(SessionExportError::OutputVerificationFailed(
                    "ffprobe per-frame audio evidence has no decoded samples".to_string(),
                ));
            }
            if frame_timeline.max_timestamp_residual_ns.unsigned_abs()
                > frame_timeline.timestamp_tolerance_ns
            {
                return Err(SessionExportError::OutputVerificationFailed(format!(
                        "derived output audio frame timestamp {} has continuity residual {} ns; allowed {} ns",
                        frame_timeline.max_timestamp_residual_frame,
                        frame_timeline.max_timestamp_residual_ns,
                        frame_timeline.timestamp_tolerance_ns
                    )));
            }
            let expected_start = timing.audio_start.expect("audio timing has a start");
            let expected_end = timing.audio_end.expect("audio timing has an end");
            let frame_ns =
                TimelineTime::from_samples(1024, source.sample_rate_hz)?.ceil_nanoseconds()?;
            (
                Some(timeline_residual_ns(audio.start, expected_start)?),
                Some(timeline_residual_ns(audio.end, expected_end)?),
                Some(frame_ns),
            )
        }
        (None, None) => (None, None, None),
        _ => unreachable!("audio stream count was checked above"),
    };
    let allowed_residual_ns = encoding_audio_frame_ns.map_or(source_video_tick_ns, |audio_frame| {
        source_video_tick_ns.max(audio_frame)
    });
    if audio_start_residual_ns.is_some_and(|residual| residual.unsigned_abs() > allowed_residual_ns)
        || audio_end_residual_ns
            .is_some_and(|residual| residual.unsigned_abs() > allowed_residual_ns)
    {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "derived audio timing residual exceeds the allowed {allowed_residual_ns} ns"
        )));
    }

    let metadata = fs::symlink_metadata(output_path).map_err(|error| SessionExportError::Io {
        context: "inspect probed output",
        path: output_path.to_path_buf(),
        source: error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "probed output is not a non-empty regular file: {}",
            output_path.display()
        )));
    }
    let output_sha256 = sha256_file(output_path)?;
    let stream_start = probe
        .audio_streams
        .first()
        .map_or(video.start, |audio| video.start.min(audio.start));
    let stream_end = probe
        .audio_streams
        .first()
        .map_or(video.end, |audio| video.end.max(audio.end));
    let duration_ns = u64::try_from(
        stream_end
            .checked_sub(stream_start)?
            .rounded_nanoseconds()?,
    )
    .map_err(|_| {
        SessionExportError::OutputVerificationFailed(
            "derived output has a non-positive or unsupported duration".to_string(),
        )
    })?;
    if duration_ns == 0 {
        return Err(SessionExportError::OutputVerificationFailed(
            "derived output duration is zero".to_string(),
        ));
    }
    let preserved_leading_gap_ns = match timing.audio_start {
        Some(audio_start) if audio_start > timing.video_start => u64::try_from(
            audio_start
                .checked_sub(timing.video_start)?
                .rounded_nanoseconds()?,
        )
        .map_err(|_| {
            SessionExportError::InvalidTimeline(
                "audio leading gap exceeds the supported range".to_string(),
            )
        })?,
        _ => 0,
    };

    Ok(SessionExportTimelineVerification {
        policy_id: "openaria.manifest-timeline.v1".to_string(),
        verdict: TimelineVerificationVerdict::Pass,
        source_manifest_sha256: timing.source_manifest_sha256().to_string(),
        left_right_pairing: TimelineVerificationVerdict::Pass,
        paired_frames: timing.paired_frames,
        video_start_residual_ns,
        video_end_residual_ns,
        audio_start_residual_ns,
        audio_end_residual_ns,
        source_video_tick_ns,
        encoding_audio_frame_ns,
        allowed_residual_ns,
        preserved_leading_gap_ns,
        verified_at: jiff::Timestamp::now().to_string(),
        probe_summary: SessionExportProbeSummary {
            output_sha256,
            output_bytes: metadata.len(),
            video_streams: 1,
            audio_streams: u32::try_from(expected_audio_streams).unwrap_or(0),
            frame_count,
            duration_ns,
            report_sha256: probe.report_sha256.clone(),
        },
    })
}

fn required_probe_string<'a>(
    object: &'a Value,
    field: &str,
) -> Result<&'a str, SessionExportError> {
    object.get(field).and_then(Value::as_str).ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(format!(
            "ffprobe stream field {field} is missing or invalid"
        ))
    })
}

fn optional_probe_u64(object: &Value, field: &str) -> Result<Option<u64>, SessionExportError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    if value.is_null() || value.as_str() == Some("N/A") {
        return Ok(None);
    }
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .map(Some)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe stream field {field} is not an unsigned integer"
            ))
        })
}

fn optional_probe_i64(object: &Value, field: &str) -> Result<Option<i64>, SessionExportError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    if value.is_null() || value.as_str() == Some("N/A") {
        return Ok(None);
    }
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .map(Some)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe stream field {field} is not an integer"
            ))
        })
}

fn parse_probe_time_base(value: &str) -> Result<TimelineTime, SessionExportError> {
    let (numerator, denominator) = value.split_once('/').ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(
            "ffprobe stream time_base is not a rational value".to_string(),
        )
    })?;
    let numerator = numerator.parse::<i64>().map_err(|_| {
        SessionExportError::OutputVerificationFailed(
            "ffprobe stream time_base numerator is invalid".to_string(),
        )
    })?;
    let denominator = denominator.parse::<u64>().map_err(|_| {
        SessionExportError::OutputVerificationFailed(
            "ffprobe stream time_base denominator is invalid".to_string(),
        )
    })?;
    let time_base = TimelineTime::new(numerator, denominator)?;
    if time_base <= TimelineTime::zero() {
        return Err(SessionExportError::OutputVerificationFailed(
            "ffprobe stream time_base must be positive".to_string(),
        ));
    }
    Ok(time_base)
}

fn probe_stream_time(
    stream: &Value,
    ticks_field: &str,
    decimal_field: &str,
    time_base: TimelineTime,
) -> Result<TimelineTime, SessionExportError> {
    if let Some(ticks) = optional_probe_i64(stream, ticks_field)? {
        return time_base.checked_mul_integer(ticks);
    }
    let decimal = required_probe_string(stream, decimal_field)?;
    parse_decimal_timeline_time(decimal)
}

fn parse_decimal_timeline_time(value: &str) -> Result<TimelineTime, SessionExportError> {
    let nanoseconds = parse_decimal_nanoseconds(value).map_err(|message| {
        SessionExportError::OutputVerificationFailed(format!(
            "ffprobe decimal time {value:?} is invalid: {message}"
        ))
    })?;
    TimelineTime::from_nanoseconds(nanoseconds)
}

fn parse_decimal_nanoseconds(value: &str) -> Result<i64, String> {
    let (negative, unsigned) = if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = value.strip_prefix('+') {
        (false, rest)
    } else {
        (false, value)
    };

    let exponent_index = unsigned.find(['e', 'E']);
    let (mantissa, exponent) = if let Some(index) = exponent_index {
        let (mantissa, exponent) = unsigned.split_at(index);
        let exponent = &exponent[1..];
        if exponent.bytes().any(|byte| matches!(byte, b'e' | b'E')) {
            return Err("decimal time contains more than one exponent".to_string());
        }
        (mantissa, parse_decimal_exponent(exponent)?)
    } else {
        (unsigned, 0)
    };

    let (seconds, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.contains('.')
    {
        return Err("expected decimal digits with an optional fraction and exponent".to_string());
    }

    let digits = format!("{seconds}{fraction}");
    let magnitude = digits
        .parse::<u128>()
        .map_err(|_| "decimal mantissa exceeds the supported range".to_string())?;
    if magnitude == 0 {
        return Ok(0);
    }

    // Convert seconds to nanoseconds before narrowing. Device JSON may use
    // more than nine fractional digits or scientific notation, so round once
    // at the nanosecond boundary instead of rejecting a valid timestamp.
    let decimal_power = i64::from(exponent)
        - i64::try_from(fraction.len())
            .map_err(|_| "decimal fraction exceeds the supported range".to_string())?
        + 9;
    let nanoseconds = if decimal_power >= 0 {
        let power = u32::try_from(decimal_power)
            .map_err(|_| "decimal exponent exceeds the supported range".to_string())?;
        let scale = 10_u128
            .checked_pow(power)
            .ok_or_else(|| "decimal time exceeds the supported range".to_string())?;
        magnitude
            .checked_mul(scale)
            .ok_or_else(|| "decimal time exceeds the supported range".to_string())?
    } else {
        let divisor_power = decimal_power.unsigned_abs();
        if divisor_power > 38 {
            0
        } else {
            let divisor = 10_u128
                .checked_pow(
                    u32::try_from(divisor_power)
                        .map_err(|_| "decimal exponent exceeds the supported range".to_string())?,
                )
                .ok_or_else(|| "decimal exponent exceeds the supported range".to_string())?;
            let quotient = magnitude / divisor;
            let remainder = magnitude % divisor;
            quotient
                .checked_add(u128::from(remainder >= divisor / 2))
                .ok_or_else(|| "decimal time exceeds the supported range".to_string())?
        }
    };

    if negative {
        let minimum_magnitude = u128::from(i64::MAX as u64) + 1;
        if nanoseconds > minimum_magnitude {
            return Err("decimal time exceeds the supported range".to_string());
        }
        if nanoseconds == minimum_magnitude {
            Ok(i64::MIN)
        } else {
            Ok(-i64::try_from(nanoseconds)
                .map_err(|_| "decimal time exceeds the supported range".to_string())?)
        }
    } else {
        i64::try_from(nanoseconds)
            .map_err(|_| "decimal time exceeds the supported range".to_string())
    }
}

fn parse_decimal_exponent(value: &str) -> Result<i32, String> {
    let digits = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("decimal exponent is invalid".to_string());
    }
    value
        .parse::<i32>()
        .map_err(|_| "decimal exponent exceeds the supported range".to_string())
}

fn timeline_residual_ns(
    actual: TimelineTime,
    expected: TimelineTime,
) -> Result<i64, SessionExportError> {
    actual.checked_sub(expected)?.rounded_nanoseconds()
}

#[derive(Debug)]
pub enum SessionExportError {
    InvalidRequest(String),
    InvalidTimeline(String),
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
    FfprobeFailed {
        status: String,
        stderr: String,
    },
    ProcessOutputLimit {
        process: &'static str,
        stream: &'static str,
        limit_bytes: usize,
        diagnostic: String,
    },
    Cancelled,
    OutputVerificationFailed(String),
}

impl fmt::Display for SessionExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::InvalidTimeline(message)
            | Self::SourceRejected(message)
            | Self::UnsupportedSource(message)
            | Self::OutputVerificationFailed(message) => formatter.write_str(message),
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
            Self::FfprobeFailed { status, stderr } => {
                if stderr.is_empty() {
                    write!(formatter, "ffprobe failed with {status}")
                } else {
                    write!(formatter, "ffprobe failed with {status}: {stderr}")
                }
            }
            Self::ProcessOutputLimit {
                process,
                stream,
                limit_bytes,
                diagnostic,
            } => {
                write!(
                    formatter,
                    "{process} {stream} exceeded the runtime limit of {limit_bytes} bytes"
                )?;
                if !diagnostic.is_empty() {
                    write!(formatter, ": {diagnostic}")?;
                }
                Ok(())
            }
            Self::Cancelled => formatter.write_str("session export cancelled"),
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
            timing: None,
        })
    }

    pub fn export_source_tree(
        &self,
        request: &SessionExportRequest,
    ) -> Result<SessionExportReceipt, SessionExportError> {
        let plan = self.build_plan(request)?;
        self.export_plan(&plan)
    }

    pub fn probe_output(&self, path: &Path) -> Result<OutputMediaProbe, SessionExportError> {
        self.probe_output_cancellable(path, || false)
    }

    pub fn probe_output_cancellable<F>(
        &self,
        path: &Path,
        is_cancelled: F,
    ) -> Result<OutputMediaProbe, SessionExportError>
    where
        F: Fn() -> bool,
    {
        let mut command = Command::new(self.config.ffprobe_path());
        command
            .args([
                "-v",
                "error",
                "-print_format",
                "json",
                "-count_frames",
                "-show_entries",
                "stream=codec_type,codec_name,time_base,start_pts,start_time,duration_ts,duration,nb_frames,nb_read_frames,sample_rate,channels,width,height",
                "-show_streams",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let completed = run_bounded_command(
            &mut command,
            "ffprobe",
            self.config.ffprobe_path(),
            FFPROBE_STDOUT_LIMIT_BYTES,
            PROCESS_STDERR_LIMIT_BYTES,
            &is_cancelled,
        )?;
        if !completed.status.success() {
            return Err(SessionExportError::FfprobeFailed {
                status: completed.status.to_string(),
                stderr: stderr_preview(&completed.stderr),
            });
        }
        let mut probe = OutputMediaProbe::from_ffprobe_json(&completed.stdout)?;
        if probe.video_streams.len() == 1 {
            let video = &probe.video_streams[0];
            if let Some(frame_count) = video.frame_count.filter(|count| *count > 0) {
                let frame_timeline = self.probe_video_frame_timeline_cancellable(
                    path,
                    video,
                    frame_count,
                    &is_cancelled,
                )?;
                probe.report_sha256 = combined_probe_report_sha256(
                    probe.report_sha256.as_str(),
                    frame_timeline.report_sha256.as_str(),
                );
                probe.video_frame_timeline = Some(frame_timeline);
            }
        }
        if probe.audio_streams.len() == 1 {
            let audio = &probe.audio_streams[0];
            let sample_rate_hz =
                audio
                    .sample_rate_hz
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        SessionExportError::OutputVerificationFailed(
                            "ffprobe did not report a positive output audio sample rate"
                                .to_string(),
                        )
                    })?;
            let frame_timeline = self.probe_audio_frame_timeline_cancellable(
                path,
                audio.time_base,
                audio.start,
                sample_rate_hz,
                &is_cancelled,
            )?;
            probe.report_sha256 = combined_audio_probe_report_sha256(
                probe.report_sha256.as_str(),
                frame_timeline.report_sha256.as_str(),
            );
            probe.audio_frame_timeline = Some(frame_timeline);
        }
        Ok(probe)
    }

    fn probe_video_frame_timeline_cancellable(
        &self,
        path: &Path,
        video: &OutputStreamProbe,
        expected_frame_count: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<OutputVideoFrameTimelineProbe, SessionExportError> {
        let mut command = Command::new(self.config.ffprobe_path());
        command
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_frames",
                "-show_entries",
                "frame=best_effort_timestamp",
                "-of",
                "flat=s=_",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_frame_timeline_command(
            &mut command,
            self.config.ffprobe_path(),
            path,
            video.time_base,
            video.start,
            video.end,
            expected_frame_count,
            is_cancelled,
        )
    }

    fn probe_audio_frame_timeline_cancellable(
        &self,
        path: &Path,
        time_base: TimelineTime,
        stream_start: TimelineTime,
        sample_rate_hz: u32,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<OutputAudioFrameTimelineProbe, SessionExportError> {
        let mut command = Command::new(self.config.ffprobe_path());
        command
            .args([
                "-v",
                "error",
                "-select_streams",
                "a:0",
                "-show_frames",
                "-show_entries",
                "frame=best_effort_timestamp,nb_samples:side_data=",
                "-of",
                "csv=p=0",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let media_path = path.to_path_buf();
        run_streaming_ffprobe_command(
            &mut command,
            self.config.ffprobe_path(),
            "audio frame timestamp",
            move |stdout| {
                read_audio_frame_timeline_probe(
                    stdout,
                    &media_path,
                    time_base,
                    stream_start,
                    sample_rate_hz,
                )
            },
            is_cancelled,
        )
    }

    fn verify_manifest_video_segments(
        &self,
        timing: &SessionExportTimingPlan,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SessionExportError> {
        for (eye, segments) in [
            ("left", timing.manifest().left_segments.as_slice()),
            ("right", timing.manifest().right_segments.as_slice()),
        ] {
            for (position, segment) in segments.iter().enumerate() {
                if is_cancelled() {
                    return Err(SessionExportError::Cancelled);
                }
                let expected = segment.end_frame - segment.start_frame;
                let actual = self.probe_source_video_segment(
                    &segment.path,
                    eye,
                    position,
                    timing.manifest().eye_width,
                    timing.manifest().eye_height,
                    is_cancelled,
                )?;
                if actual != expected {
                    return Err(SessionExportError::OutputVerificationFailed(format!(
                        "{eye}-eye segment {position} decoded frame count {actual} does not match declared {expected}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn verify_manifest_audio_segments(
        &self,
        timing: &SessionExportTimingPlan,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), SessionExportError> {
        let Some(audio) = timing.manifest().audio.as_ref() else {
            return Ok(());
        };
        for (position, segment) in audio.segments.iter().enumerate() {
            if is_cancelled() {
                return Err(SessionExportError::Cancelled);
            }
            let metadata = self.probe_pcm_audio_stream(&segment.path, is_cancelled)?;
            if metadata.sample_rate_hz != audio.sample_rate_hz {
                return Err(SessionExportError::OutputVerificationFailed(format!(
                    "audio segment {position} sample rate {} does not match declared {}",
                    metadata.sample_rate_hz, audio.sample_rate_hz
                )));
            }
            if metadata.channels != audio.channels {
                return Err(SessionExportError::OutputVerificationFailed(format!(
                    "audio segment {position} channel count {} does not match declared {}",
                    metadata.channels, audio.channels
                )));
            }

            let expected = segment.end_sample - segment.start_sample;
            let actual =
                self.probe_decoded_audio_sample_frame_count(&segment.path, is_cancelled)?;
            if actual != expected {
                return Err(SessionExportError::OutputVerificationFailed(format!(
                    "audio segment {position} decoded sample frame count {actual} does not match declared {expected}"
                )));
            }
        }
        Ok(())
    }

    fn probe_pcm_audio_stream(
        &self,
        path: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<SourceAudioStreamProbe, SessionExportError> {
        let mut command = Command::new(self.config.ffprobe_path());
        command
            .args([
                "-v",
                "error",
                "-show_entries",
                "format=format_name:stream=codec_type,codec_name,sample_fmt,sample_rate,channels",
                "-show_format",
                "-show_streams",
                "-of",
                "json",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let completed = run_bounded_command(
            &mut command,
            "ffprobe",
            self.config.ffprobe_path(),
            FFPROBE_CONTROL_STDOUT_LIMIT_BYTES,
            PROCESS_STDERR_LIMIT_BYTES,
            is_cancelled,
        )?;
        if !completed.status.success() {
            return Err(SessionExportError::FfprobeFailed {
                status: completed.status.to_string(),
                stderr: stderr_preview(&completed.stderr),
            });
        }
        parse_source_audio_stream_probe(&completed.stdout, path)
    }

    fn probe_decoded_audio_sample_frame_count(
        &self,
        path: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<u64, SessionExportError> {
        let mut command = Command::new(self.config.ffprobe_path());
        command
            .args([
                "-v",
                "error",
                "-select_streams",
                "a:0",
                "-show_frames",
                "-show_entries",
                "frame=nb_samples:side_data=",
                "-of",
                "csv=p=0",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let media_path = path.to_path_buf();
        run_streaming_ffprobe_command(
            &mut command,
            self.config.ffprobe_path(),
            "audio sample frame",
            move |stdout| read_decoded_audio_sample_frame_count(stdout, &media_path),
            is_cancelled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn probe_source_video_segment(
        &self,
        path: &Path,
        eye: &str,
        position: usize,
        expected_width: u32,
        expected_height: u32,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<u64, SessionExportError> {
        let mut command = Command::new(self.config.ffprobe_path());
        command
            .args([
                "-v",
                "error",
                "-count_frames",
                "-show_entries",
                "format=format_name:stream=codec_type,codec_name,width,height,nb_read_frames",
                "-show_format",
                "-show_streams",
                "-print_format",
                "json",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let completed = run_bounded_command(
            &mut command,
            "ffprobe",
            self.config.ffprobe_path(),
            FFPROBE_CONTROL_STDOUT_LIMIT_BYTES,
            PROCESS_STDERR_LIMIT_BYTES,
            is_cancelled,
        )?;
        if !completed.status.success() {
            return Err(SessionExportError::FfprobeFailed {
                status: completed.status.to_string(),
                stderr: stderr_preview(&completed.stderr),
            });
        }
        parse_source_video_segment_probe(
            &completed.stdout,
            path,
            eye,
            position,
            expected_width,
            expected_height,
        )
    }

    pub fn export_plan(
        &self,
        plan: &SessionExportPlan,
    ) -> Result<SessionExportReceipt, SessionExportError> {
        self.export_plan_cancellable(plan, || false)
    }

    pub fn export_plan_cancellable<F>(
        &self,
        plan: &SessionExportPlan,
        is_cancelled: F,
    ) -> Result<SessionExportReceipt, SessionExportError>
    where
        F: Fn() -> bool,
    {
        if is_cancelled() {
            return Err(SessionExportError::Cancelled);
        }
        if let Some(timing) = plan.timing() {
            verify_manifest_artifacts(plan.source_root(), timing.manifest())?;
            self.verify_manifest_video_segments(timing, &is_cancelled)?;
            self.verify_manifest_audio_segments(timing, &is_cancelled)?;
        }
        let final_output_path = plan.output_path.clone();
        let staging = TempExportDir::create_for(&final_output_path)?;
        let staged_output_path = staging.path().join("output.mp4");
        let mut run_plan = plan.clone();
        run_plan.output_path = staged_output_path.clone();
        let args = build_ffmpeg_args(&run_plan, staging.path())?;

        let mut command = Command::new(self.config.ffmpeg_path());
        command
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let completed = run_bounded_command(
            &mut command,
            "ffmpeg",
            self.config.ffmpeg_path(),
            0,
            PROCESS_STDERR_LIMIT_BYTES,
            &is_cancelled,
        )?;
        if !completed.status.success() {
            return Err(SessionExportError::FfmpegFailed {
                status: completed.status.to_string(),
                stderr: stderr_preview(&completed.stderr),
            });
        }
        if is_cancelled() {
            return Err(SessionExportError::Cancelled);
        }
        if let Some(timing) = plan.timing() {
            verify_manifest_artifacts(plan.source_root(), timing.manifest())?;
        }

        let staged_metadata = inspect_regular_staged_output(&staged_output_path)?;
        if staged_metadata.len() == 0 {
            return Err(SessionExportError::UnsupportedSource(format!(
                "ffmpeg did not produce a non-empty mp4 at {}",
                staged_output_path.display()
            )));
        }
        let (timeline_verification, output_media) = if plan.timing().is_some() {
            let probe = self.probe_output_cancellable(&staged_output_path, &is_cancelled)?;
            let verification = verify_session_export_output(plan, &staged_output_path, &probe)?;
            (Some(verification), Some(probe.output_media()?))
        } else {
            (None, None)
        };
        if is_cancelled() {
            return Err(SessionExportError::Cancelled);
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
            timeline_verification,
            output_media,
        })
    }
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceAudioStreamProbe {
    sample_rate_hz: u32,
    channels: u32,
}

#[allow(clippy::too_many_arguments)]
fn parse_source_video_segment_probe(
    bytes: &[u8],
    path: &Path,
    eye: &str,
    position: usize,
    expected_width: u32,
    expected_height: u32,
) -> Result<u64, SessionExportError> {
    let report: Value = serde_json::from_slice(bytes).map_err(|error| {
        SessionExportError::OutputVerificationFailed(format!(
            "{eye}-eye segment {position} ffprobe returned invalid source-video JSON for {}: {error}",
            path.display()
        ))
    })?;
    let format_name = report
        .get("format")
        .and_then(|format| format.get("format_name"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "{eye}-eye segment {position} ffprobe did not report a container format"
            ))
        })?;
    if !format_name.split(',').any(|name| name == "mp4") {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "{eye}-eye segment {position} is not an MP4 container (ffprobe reported {format_name})"
        )));
    }
    let streams = report
        .get("streams")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "{eye}-eye segment {position} ffprobe report for {} has no streams array",
                path.display()
            ))
        })?;
    if streams.len() != 1 {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "{eye}-eye segment {position} must contain exactly one H.264 video stream and no other streams; found {} streams",
            streams.len()
        )));
    }
    let stream = &streams[0];
    if required_probe_string(stream, "codec_type")? != "video"
        || required_probe_string(stream, "codec_name")? != "h264"
    {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "{eye}-eye segment {position} must contain exactly one H.264 video stream"
        )));
    }
    let width = optional_probe_u64(stream, "width")?
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "{eye}-eye segment {position} ffprobe did not report a supported width"
            ))
        })?;
    let height = optional_probe_u64(stream, "height")?
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "{eye}-eye segment {position} ffprobe did not report a supported height"
            ))
        })?;
    if width != expected_width || height != expected_height {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "{eye}-eye segment {position} dimensions {width}x{height} do not match declared {expected_width}x{expected_height}"
        )));
    }
    optional_probe_u64(stream, "nb_read_frames")?.ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(format!(
            "{eye}-eye segment {position} ffprobe did not report a decoded frame count for {}",
            path.display()
        ))
    })
}

fn parse_source_audio_stream_probe(
    bytes: &[u8],
    path: &Path,
) -> Result<SourceAudioStreamProbe, SessionExportError> {
    let report: Value = serde_json::from_slice(bytes).map_err(|error| {
        SessionExportError::OutputVerificationFailed(format!(
            "ffprobe returned invalid audio stream JSON for {}: {error}",
            path.display()
        ))
    })?;
    let format = report.get("format").ok_or_else(|| {
        SessionExportError::OutputVerificationFailed(format!(
            "ffprobe audio stream report for {} has no format object",
            path.display()
        ))
    })?;
    let streams = report
        .get("streams")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe audio stream report for {} has no streams array",
                path.display()
            ))
        })?;
    if required_probe_string(format, "format_name")? != "wav"
        || streams.len() != 1
        || required_probe_string(&streams[0], "codec_type")? != "audio"
        || required_probe_string(&streams[0], "codec_name")? != "pcm_s16le"
        || required_probe_string(&streams[0], "sample_fmt")? != "s16"
    {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "audio source {} must contain exactly one RIFF/WAVE PCM S16_LE stream",
            path.display()
        )));
    }
    let sample_rate_hz = optional_probe_u64(&streams[0], "sample_rate")?
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe did not report a supported audio sample rate for {}",
                path.display()
            ))
        })?;
    let channels = optional_probe_u64(&streams[0], "channels")?
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| (1..=8).contains(value))
        .ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(format!(
                "ffprobe did not report an audio channel count from 1 through 8 for {}",
                path.display()
            ))
        })?;
    Ok(SourceAudioStreamProbe {
        sample_rate_hz,
        channels,
    })
}

fn read_decoded_audio_sample_frame_count(
    reader: impl Read,
    media_path: &Path,
) -> Result<u64, SessionExportError> {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::with_capacity(32);
    let mut decoded_sample_frames = 0_u64;
    let mut decoded_frames = 0_u64;
    loop {
        line.clear();
        let read = Read::by_ref(&mut reader)
            .take(129)
            .read_until(b'\n', &mut line)
            .map_err(|error| SessionExportError::Io {
                context: "read ffprobe audio sample frames",
                path: media_path.to_path_buf(),
                source: error,
            })?;
        if read == 0 {
            break;
        }
        if line.len() > 128 {
            return Err(SessionExportError::OutputVerificationFailed(
                "ffprobe audio sample frame line exceeds 128 bytes".to_string(),
            ));
        }
        let text = std::str::from_utf8(&line).map_err(|_| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe audio sample frames are not UTF-8".to_string(),
            )
        })?;
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let samples = text
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                SessionExportError::OutputVerificationFailed(format!(
                    "ffprobe audio sample frame {text:?} is not a positive integer"
                ))
            })?;
        decoded_sample_frames = decoded_sample_frames.checked_add(samples).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe decoded audio sample frame count overflowed".to_string(),
            )
        })?;
        decoded_frames = decoded_frames.checked_add(1).ok_or_else(|| {
            SessionExportError::OutputVerificationFailed(
                "ffprobe decoded audio frame count overflowed".to_string(),
            )
        })?;
    }
    if decoded_frames == 0 {
        return Err(SessionExportError::OutputVerificationFailed(format!(
            "ffprobe reported no decoded audio frames for {}",
            media_path.display()
        )));
    }
    Ok(decoded_sample_frames)
}

#[allow(clippy::too_many_arguments)]
fn run_frame_timeline_command(
    command: &mut Command,
    executable: &Path,
    media_path: &Path,
    time_base: TimelineTime,
    stream_start: TimelineTime,
    stream_end: TimelineTime,
    expected_frame_count: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<OutputVideoFrameTimelineProbe, SessionExportError> {
    let media_path = media_path.to_path_buf();
    run_streaming_ffprobe_command(
        command,
        executable,
        "video frame timestamp",
        move |stdout| {
            read_video_frame_timeline_probe(
                stdout,
                &media_path,
                time_base,
                stream_start,
                stream_end,
                expected_frame_count,
            )
        },
        is_cancelled,
    )
}

fn run_streaming_ffprobe_command<T>(
    command: &mut Command,
    executable: &Path,
    reader_description: &'static str,
    read_stdout: impl FnOnce(ChildStdout) -> Result<T, SessionExportError> + Send + 'static,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<T, SessionExportError>
where
    T: Send + 'static,
{
    let mut child = command.spawn().map_err(|error| SessionExportError::Io {
        context: "start media subprocess",
        path: executable.to_path_buf(),
        source: error,
    })?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(SessionExportError::InvalidRequest(format!(
            "ffprobe {reader_description} stdout was not piped"
        )));
    };
    let stdout_reader = thread::spawn(move || read_stdout(stdout));
    let exceeded = Arc::new(AtomicU8::new(0));
    let stderr_reader = spawn_bounded_reader(
        child.stderr.take(),
        PROCESS_STDERR_LIMIT_BYTES,
        exceeded.clone(),
        2,
    );

    let mut status = None;
    let abort = loop {
        if is_cancelled() {
            break Some(SessionExportError::Cancelled);
        }
        if exceeded.load(AtomicOrdering::SeqCst) != 0 {
            break Some(SessionExportError::ProcessOutputLimit {
                process: "ffprobe",
                stream: "stderr",
                limit_bytes: PROCESS_STDERR_LIMIT_BYTES,
                diagnostic: String::new(),
            });
        }
        match child.try_wait() {
            Ok(Some(completed)) => {
                status = Some(completed);
                break None;
            }
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(error) => {
                break Some(SessionExportError::Io {
                    context: "wait for media subprocess",
                    path: executable.to_path_buf(),
                    source: error,
                })
            }
        }
    };

    if abort.is_some() {
        terminate_and_reap(&mut child);
    }
    let stdout_result = stdout_reader.join().map_err(|_| {
        SessionExportError::InvalidRequest(format!("ffprobe {reader_description} reader panicked"))
    })?;
    let stderr_result = join_bounded_reader(stderr_reader, executable);
    if let Some(mut error) = abort {
        let stderr = stderr_result.unwrap_or_default();
        if let SessionExportError::ProcessOutputLimit { diagnostic, .. } = &mut error {
            *diagnostic = stderr_preview(&stderr);
        }
        return Err(error);
    }
    let parsed_stdout = stdout_result?;
    let stderr = stderr_result?;
    if exceeded.load(AtomicOrdering::SeqCst) != 0 {
        return Err(SessionExportError::ProcessOutputLimit {
            process: "ffprobe",
            stream: "stderr",
            limit_bytes: PROCESS_STDERR_LIMIT_BYTES,
            diagnostic: stderr_preview(&stderr),
        });
    }
    if is_cancelled() {
        return Err(SessionExportError::Cancelled);
    }
    let status = status.expect("completed ffprobe subprocess has an exit status");
    if !status.success() {
        return Err(SessionExportError::FfprobeFailed {
            status: status.to_string(),
            stderr: stderr_preview(&stderr),
        });
    }
    Ok(parsed_stdout)
}

fn run_bounded_command(
    command: &mut Command,
    process: &'static str,
    executable: &Path,
    stdout_limit: usize,
    stderr_limit: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BoundedCommandOutput, SessionExportError> {
    let mut child = command.spawn().map_err(|error| SessionExportError::Io {
        context: "start media subprocess",
        path: executable.to_path_buf(),
        source: error,
    })?;
    let exceeded = Arc::new(AtomicU8::new(0));
    let stdout_reader =
        spawn_bounded_reader(child.stdout.take(), stdout_limit, exceeded.clone(), 1);
    let stderr_reader =
        spawn_bounded_reader(child.stderr.take(), stderr_limit, exceeded.clone(), 2);

    let mut status = None;
    let abort = loop {
        if is_cancelled() {
            break Some(SessionExportError::Cancelled);
        }
        let stream = exceeded.load(AtomicOrdering::SeqCst);
        if stream != 0 {
            break Some(SessionExportError::ProcessOutputLimit {
                process,
                stream: if stream == 1 { "stdout" } else { "stderr" },
                limit_bytes: if stream == 1 {
                    stdout_limit
                } else {
                    stderr_limit
                },
                diagnostic: String::new(),
            });
        }
        match child.try_wait() {
            Ok(Some(completed)) => {
                status = Some(completed);
                break None;
            }
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(error) => {
                break Some(SessionExportError::Io {
                    context: "wait for media subprocess",
                    path: executable.to_path_buf(),
                    source: error,
                })
            }
        }
    };

    if abort.is_some() {
        terminate_and_reap(&mut child);
    }
    let stdout_result = join_bounded_reader(stdout_reader, executable);
    let stderr_result = join_bounded_reader(stderr_reader, executable);

    if let Some(mut error) = abort {
        let _stdout = stdout_result.unwrap_or_default();
        let stderr = stderr_result.unwrap_or_default();
        if let SessionExportError::ProcessOutputLimit { diagnostic, .. } = &mut error {
            *diagnostic = stderr_preview(&stderr);
        }
        return Err(error);
    }
    let stdout = stdout_result?;
    let stderr = stderr_result?;
    let stream = exceeded.load(AtomicOrdering::SeqCst);
    if stream != 0 {
        return Err(SessionExportError::ProcessOutputLimit {
            process,
            stream: if stream == 1 { "stdout" } else { "stderr" },
            limit_bytes: if stream == 1 {
                stdout_limit
            } else {
                stderr_limit
            },
            diagnostic: stderr_preview(&stderr),
        });
    }
    if is_cancelled() {
        return Err(SessionExportError::Cancelled);
    }
    Ok(BoundedCommandOutput {
        status: status.expect("completed media subprocess has an exit status"),
        stdout,
        stderr,
    })
}

fn spawn_bounded_reader(
    pipe: Option<impl Read + Send + 'static>,
    limit: usize,
    exceeded: Arc<AtomicU8>,
    stream: u8,
) -> Option<JoinHandle<io::Result<Vec<u8>>>> {
    pipe.map(|mut pipe| {
        thread::spawn(move || {
            let mut captured = Vec::with_capacity(limit.min(64 * 1024));
            let mut buffer = [0_u8; 8 * 1024];
            loop {
                let read = pipe.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let remaining = limit.saturating_sub(captured.len());
                let keep = remaining.min(read);
                captured.extend_from_slice(&buffer[..keep]);
                if read > keep {
                    let _ = exceeded.compare_exchange(
                        0,
                        stream,
                        AtomicOrdering::SeqCst,
                        AtomicOrdering::SeqCst,
                    );
                    break;
                }
            }
            Ok(captured)
        })
    })
}

fn join_bounded_reader(
    reader: Option<JoinHandle<io::Result<Vec<u8>>>>,
    executable: &Path,
) -> Result<Vec<u8>, SessionExportError> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    reader
        .join()
        .map_err(|_| {
            SessionExportError::InvalidRequest("media output reader panicked".to_string())
        })?
        .map_err(|error| SessionExportError::Io {
            context: "read media subprocess output",
            path: executable.to_path_buf(),
            source: error,
        })
}

fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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
    if let Some(timing) = plan.timing() {
        return build_timeline_ffmpeg_args(plan, timing, staging_dir);
    }
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
        "-loglevel".to_string(),
        "error".to_string(),
        "-nostats".to_string(),
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

fn build_timeline_ffmpeg_args(
    plan: &SessionExportPlan,
    timing: &SessionExportTimingPlan,
    staging_dir: &Path,
) -> Result<Vec<String>, SessionExportError> {
    let manifest = timing.manifest();
    let left_list =
        write_timed_video_concat_list(staging_dir, "left.ffconcat", &manifest.left_segments)?;
    let right_list =
        write_timed_video_concat_list(staging_dir, "right.ffconcat", &manifest.right_segments)?;
    let audio_list = manifest
        .audio
        .as_ref()
        .map(|audio| write_timed_audio_concat_list(staging_dir, "audio.ffconcat", &audio.segments))
        .transpose()?;

    let mut args = vec![
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "error".to_string(),
        "-nostats".to_string(),
        "-nostdin".to_string(),
        if plan.overwrite { "-y" } else { "-n" }.to_string(),
    ];
    append_concat_input(&mut args, &left_list);
    append_concat_input(&mut args, &right_list);
    if let Some(audio_list) = audio_list.as_ref() {
        append_concat_input(&mut args, audio_list);
    }

    let video_start = timing.video_start().ffmpeg_seconds()?;
    let video_tick = timing.video_tick();
    let video_clock = format!(
        "N*{}/({}*TB)+{video_start}/TB",
        video_tick.numerator(),
        video_tick.denominator()
    );
    let mut filter = format!(
        "[0:v:0]setpts={video_clock}[l];\
         [1:v:0]setpts={video_clock}[r];\
         [l][r]hstack=inputs=2:shortest=1[v]"
    );
    if let Some(audio_start) = timing.audio_start_offset() {
        let audio_duration = timing
            .audio_end()
            .expect("audio timing has a manifest stop")
            .checked_sub(audio_start)?;
        filter.push_str(&format!(
            ";[2:a:0]aresample=async=0:first_pts=0,\
             atrim=duration={},\
             asetpts=PTS-STARTPTS+{}/TB[a]",
            audio_duration.ffmpeg_seconds()?,
            audio_start.ffmpeg_seconds()?
        ));
    }
    args.extend([
        "-filter_complex".to_string(),
        filter,
        "-map".to_string(),
        "[v]".to_string(),
    ]);
    if audio_list.is_some() {
        args.extend(["-map".to_string(), "[a]".to_string()]);
    } else {
        args.push("-an".to_string());
    }
    append_h264_video_output_args(&mut args);
    args.extend(["-vsync".to_string(), "0".to_string()]);
    if audio_list.is_some() {
        args.extend([
            "-c:a".to_string(),
            "aac".to_string(),
            "-b:a".to_string(),
            "192k".to_string(),
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

fn write_timed_video_concat_list(
    staging_dir: &Path,
    file_name: &str,
    segments: &[TimedVideoSegment],
) -> Result<PathBuf, SessionExportError> {
    let entries = segments
        .iter()
        .map(|segment| {
            Ok((
                segment.path.as_path(),
                segment.end_time.checked_sub(segment.start_time)?,
            ))
        })
        .collect::<Result<Vec<_>, SessionExportError>>()?;
    write_timed_concat_list(staging_dir, file_name, &entries)
}

fn write_timed_audio_concat_list(
    staging_dir: &Path,
    file_name: &str,
    segments: &[TimedAudioSegment],
) -> Result<PathBuf, SessionExportError> {
    let entries = segments
        .iter()
        .map(|segment| {
            Ok((
                segment.path.as_path(),
                segment.end_time.checked_sub(segment.start_time)?,
            ))
        })
        .collect::<Result<Vec<_>, SessionExportError>>()?;
    write_timed_concat_list(staging_dir, file_name, &entries)
}

fn write_timed_concat_list(
    staging_dir: &Path,
    file_name: &str,
    entries: &[(&Path, TimelineTime)],
) -> Result<PathBuf, SessionExportError> {
    if entries.is_empty() {
        return Err(SessionExportError::InvalidTimeline(format!(
            "timed concat list {file_name} has no segments"
        )));
    }
    let path = staging_dir.join(file_name);
    let mut body = "ffconcat version 1.0\n".to_string();
    for (segment, duration) in entries {
        body.push_str("file '");
        body.push_str(&escape_concat_path(segment));
        body.push_str("'\nduration ");
        body.push_str(&duration.ffmpeg_seconds()?);
        body.push('\n');
    }
    fs::write(&path, body).map_err(|error| SessionExportError::Io {
        context: "write timed ffmpeg concat list",
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

    fn generate_timeline_h264_clip(path: &Path, color: &str, with_pts_gap: bool) {
        fs::create_dir_all(path.parent().expect("clip parent")).expect("clip parent");
        let source = format!("color=c={color}:size=32x32:rate=30:duration=1");
        let mut args = vec!["-f", "lavfi", "-i", source.as_str()];
        if with_pts_gap {
            args.extend([
                "-vf",
                r"setpts=if(gte(N\,10)\,PTS+6/(30*TB)\,PTS)",
                "-vsync",
                "0",
            ]);
        }
        args.extend([
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            path.to_str().expect("test path utf8"),
        ]);
        run_ffmpeg(&args);
    }

    fn generate_timeline_wav(path: &Path) {
        fs::create_dir_all(path.parent().expect("wav parent")).expect("wav parent");
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000:duration=2",
            "-ac",
            "2",
            "-c:a",
            "pcm_s16le",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn generate_fixed_sample_stereo_wav(path: &Path, sample_frames: u64) {
        generate_fixed_sample_wav(path, sample_frames, 2);
    }

    fn generate_fixed_sample_wav(path: &Path, sample_frames: u64, channels: u32) {
        fs::create_dir_all(path.parent().expect("wav parent")).expect("wav parent");
        let trim = format!("atrim=end_sample={sample_frames},asetpts=N/SR/TB");
        let channels = channels.to_string();
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000",
            "-af",
            &trim,
            "-ar",
            "48000",
            "-ac",
            &channels,
            "-c:a",
            "pcm_s16le",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn generate_fixed_frame_h264_clip(path: &Path, color: &str, frame_count: u64) {
        generate_fixed_frame_h264_clip_with_size(path, color, frame_count, "32x32");
    }

    fn generate_fixed_frame_h264_clip_with_size(
        path: &Path,
        color: &str,
        frame_count: u64,
        size: &str,
    ) {
        fs::create_dir_all(path.parent().expect("clip parent")).expect("clip parent");
        let source = format!("color=c={color}:size={size}:rate=30");
        let frame_count = frame_count.to_string();
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            &source,
            "-frames:v",
            &frame_count,
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn generate_fixed_frame_mpeg4_clip(path: &Path, color: &str, frame_count: u64) {
        fs::create_dir_all(path.parent().expect("clip parent")).expect("clip parent");
        let source = format!("color=c={color}:size=32x32:rate=30");
        let frame_count = frame_count.to_string();
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            &source,
            "-frames:v",
            &frame_count,
            "-c:v",
            "mpeg4",
            "-pix_fmt",
            "yuv420p",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn generate_matroska_h264_clip_with_mp4_name(path: &Path, color: &str, frame_count: u64) {
        fs::create_dir_all(path.parent().expect("clip parent")).expect("clip parent");
        let source = format!("color=c={color}:size=32x32:rate=30");
        let frame_count = frame_count.to_string();
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            &source,
            "-frames:v",
            &frame_count,
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-f",
            "matroska",
            path.to_str().expect("test path utf8"),
        ]);
    }

    fn generate_h264_clip_with_extra_audio_stream(path: &Path, color: &str, frame_count: u64) {
        fs::create_dir_all(path.parent().expect("clip parent")).expect("clip parent");
        let source = format!("color=c={color}:size=32x32:rate=30");
        let frame_count = frame_count.to_string();
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            &source,
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000:duration=1",
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-frames:v",
            &frame_count,
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
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
            "-ac",
            "2",
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

    fn timeline_time(numerator: i64, denominator: u64) -> TimelineTime {
        TimelineTime::new(numerator, denominator).expect("valid test timeline time")
    }

    fn timed_video_segment(
        index: u32,
        path: PathBuf,
        start_frame: u64,
        end_frame: u64,
        start_seconds: i64,
        end_seconds: i64,
    ) -> TimedVideoSegment {
        let bytes = fs::metadata(&path).expect("video metadata").len();
        let sha256 = sha256_file(&path).expect("video digest");
        TimedVideoSegment {
            index,
            path,
            bytes,
            sha256,
            start_frame,
            end_frame,
            start_time: timeline_time(start_seconds, 1),
            end_time: timeline_time(end_seconds, 1),
        }
    }

    fn single_segment_video_timeline(left: PathBuf, right: PathBuf) -> ManifestSessionTimeline {
        ManifestSessionTimeline {
            source_manifest_sha256: "6".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![timed_video_segment(0, left, 0, 30, 0, 1)],
            right_segments: vec![timed_video_segment(0, right, 0, 30, 0, 1)],
            audio: None,
        }
    }

    fn manifest_timeline_fixture(root: &Path, with_audio: bool) -> ManifestSessionTimeline {
        let left = root.join("video/left_00000.mp4");
        let right = root.join("video/right_00000.mp4");
        fs::create_dir_all(left.parent().expect("video parent")).expect("video directory");
        fs::write(&left, b"left").expect("left segment");
        fs::write(&right, b"right").expect("right segment");
        let audio = if with_audio {
            let path = root.join("audio/audio_00000.wav");
            fs::create_dir_all(path.parent().expect("audio parent")).expect("audio directory");
            fs::write(&path, b"audio").expect("audio segment");
            Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: timeline_time(1, 2),
                session_stop_offset: timeline_time(5, 2),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&path).expect("audio metadata").len(),
                    sha256: sha256_file(&path).expect("audio digest"),
                    path,
                    start_sample: 0,
                    end_sample: 96_000,
                    start_time: timeline_time(1, 2),
                    end_time: timeline_time(5, 2),
                }],
            })
        } else {
            None
        };
        ManifestSessionTimeline {
            source_manifest_sha256: "d".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![timed_video_segment(0, left, 0, 60, 0, 2)],
            right_segments: vec![timed_video_segment(0, right, 0, 60, 0, 2)],
            audio,
        }
    }

    #[test]
    fn manifest_timeline_plan_preserves_nonzero_audio_offset() {
        let directory = tempfile::tempdir().expect("tempdir");
        let left = directory.path().join("video/left_00000.mp4");
        let right = directory.path().join("video/right_00000.mp4");
        let audio = directory.path().join("audio/audio_00000.wav");
        fs::create_dir_all(left.parent().expect("video parent")).expect("video directory");
        fs::create_dir_all(audio.parent().expect("audio parent")).expect("audio directory");
        fs::write(&left, b"left").expect("left segment");
        fs::write(&right, b"right").expect("right segment");
        fs::write(&audio, b"audio").expect("audio segment");

        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "a".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![timed_video_segment(0, left, 0, 60, 0, 2)],
            right_segments: vec![timed_video_segment(0, right, 0, 60, 0, 2)],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: timeline_time(1, 2),
                session_stop_offset: timeline_time(5, 2),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&audio).expect("audio metadata").len(),
                    sha256: sha256_file(&audio).expect("audio digest"),
                    path: audio,
                    start_sample: 0,
                    end_sample: 96_000,
                    start_time: timeline_time(1, 2),
                    end_time: timeline_time(5, 2),
                }],
            }),
        };

        let plan = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("derived.mp4"),
            true,
            timeline,
        )
        .expect("valid manifest timeline plan");
        let timing = plan.timing().expect("manifest timing");

        assert_eq!(timing.source_manifest_sha256(), "a".repeat(64));
        assert_eq!(timing.paired_frames(), 60);
        assert_eq!(timing.audio_start_offset(), Some(timeline_time(1, 2)));
        assert_eq!(timing.audio_end(), Some(timeline_time(5, 2)));
    }

    #[test]
    fn manifest_timeline_builds_deterministic_offset_preserving_ffmpeg_plan() {
        let directory = tempfile::tempdir().expect("tempdir");
        let left = directory.path().join("video/left_00000.mp4");
        let right = directory.path().join("video/right_00000.mp4");
        let audio = directory.path().join("audio/audio_00000.wav");
        fs::create_dir_all(left.parent().expect("video parent")).expect("video directory");
        fs::create_dir_all(audio.parent().expect("audio parent")).expect("audio directory");
        fs::write(&left, b"left").expect("left segment");
        fs::write(&right, b"right").expect("right segment");
        fs::write(&audio, b"audio").expect("audio segment");
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "b".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![timed_video_segment(0, left, 0, 60, 0, 2)],
            right_segments: vec![timed_video_segment(0, right, 0, 60, 0, 2)],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: timeline_time(1, 2),
                session_stop_offset: timeline_time(249, 100),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&audio).expect("audio metadata").len(),
                    sha256: sha256_file(&audio).expect("audio digest"),
                    path: audio,
                    start_sample: 0,
                    end_sample: 96_000,
                    start_time: timeline_time(1, 2),
                    end_time: timeline_time(5, 2),
                }],
            }),
        };
        let plan = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("derived.mp4"),
            true,
            timeline,
        )
        .expect("valid manifest timeline plan");
        let staging = tempfile::tempdir().expect("staging");

        let args = build_ffmpeg_args(&plan, staging.path()).expect("ffmpeg args");
        let filter = args
            .windows(2)
            .find_map(|window| (window[0] == "-filter_complex").then_some(window[1].as_str()))
            .expect("timeline filter graph");

        assert_eq!(
            filter.matches("setpts=N*1/(30*TB)+0.000000000/TB").count(),
            2,
            "both eyes must use the same manifest frame clock"
        );
        assert!(filter.contains("hstack=inputs=2:shortest=1"));
        assert!(filter.contains("aresample=async=0:first_pts=0"));
        assert!(filter.contains("atrim=duration=1.990000000"));
        assert!(filter.contains("asetpts=PTS-STARTPTS+0.500000000/TB"));
        assert!(!args.iter().any(|argument| argument == "-shortest"));
        assert!(args.windows(2).any(|window| window == ["-vsync", "0"]));
        assert!(fs::read_to_string(staging.path().join("left.ffconcat"))
            .expect("left concat list")
            .contains("duration 2.000000000"));
        assert!(fs::read_to_string(staging.path().join("audio.ffconcat"))
            .expect("audio concat list")
            .contains("duration 2.000000000"));
    }

    #[test]
    fn independent_probe_produces_contract_timeline_verification() {
        let directory = tempfile::tempdir().expect("tempdir");
        let left = directory.path().join("video/left_00000.mp4");
        let right = directory.path().join("video/right_00000.mp4");
        let audio = directory.path().join("audio/audio_00000.wav");
        fs::create_dir_all(left.parent().expect("video parent")).expect("video directory");
        fs::create_dir_all(audio.parent().expect("audio parent")).expect("audio directory");
        fs::write(&left, b"left").expect("left segment");
        fs::write(&right, b"right").expect("right segment");
        fs::write(&audio, b"audio").expect("audio segment");
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "c".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![timed_video_segment(0, left, 0, 60, 0, 2)],
            right_segments: vec![timed_video_segment(0, right, 0, 60, 0, 2)],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: timeline_time(1, 2),
                session_stop_offset: timeline_time(5, 2),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&audio).expect("audio metadata").len(),
                    sha256: sha256_file(&audio).expect("audio digest"),
                    path: audio,
                    start_sample: 0,
                    end_sample: 96_000,
                    start_time: timeline_time(1, 2),
                    end_time: timeline_time(5, 2),
                }],
            }),
        };
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("valid manifest timeline plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{
              "streams": [
                {"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":64,"height":32},
                {"codec_type":"audio","codec_name":"aac","time_base":"1/48000","start_pts":24000,"duration_ts":96000,"sample_rate":"48000","channels":2}
              ]
            }"#,
        )
        .expect("valid probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let verification = verify_session_export_output(&plan, &output, &probe)
            .expect("probe should satisfy manifest timing");

        assert_eq!(verification.verdict, TimelineVerificationVerdict::Pass);
        assert_eq!(
            verification.left_right_pairing,
            TimelineVerificationVerdict::Pass
        );
        assert_eq!(verification.paired_frames, 60);
        assert_eq!(verification.video_start_residual_ns, 0);
        assert_eq!(verification.video_end_residual_ns, 0);
        assert_eq!(verification.audio_start_residual_ns, Some(0));
        assert_eq!(verification.audio_end_residual_ns, Some(0));
        assert_eq!(verification.source_video_tick_ns, 33_333_334);
        assert_eq!(verification.encoding_audio_frame_ns, Some(21_333_334));
        assert_eq!(verification.allowed_residual_ns, 33_333_334);
        assert_eq!(verification.preserved_leading_gap_ns, 500_000_000);
        assert_eq!(verification.probe_summary.frame_count, 60);
        assert_eq!(verification.probe_summary.duration_ns, 2_500_000_000);
        let media = probe.output_media().expect("verified output media");
        assert_eq!(media.layout, "left-right-side-by-side");
        assert_eq!(media.eye_width, 32);
        assert_eq!(media.width, media.eye_width * 2);
    }

    #[test]
    fn accepts_audio_stop_residual_at_allowed_boundary_and_binds_receipt_to_manifest_stop() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), true);
        let audio = timeline.audio.as_mut().expect("audio timeline");
        audio.session_stop_offset = timeline_time(38, 15);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("one video tick of audio stop residual is allowed");

        assert_eq!(
            plan.timing().expect("manifest timing").audio_end(),
            Some(timeline_time(38, 15))
        );

        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{
              "streams": [
                {"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":64,"height":32},
                {"codec_type":"audio","codec_name":"aac","time_base":"1/48000","start_pts":24000,"duration_ts":96000,"sample_rate":"48000","channels":2}
              ]
            }"#,
        )
        .expect("valid probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");
        let verification = verify_session_export_output(&plan, &output, &probe)
            .expect("boundary residual should verify");

        assert_eq!(verification.audio_end_residual_ns, Some(-33_333_333));
        assert_eq!(verification.allowed_residual_ns, 33_333_334);
    }

    #[test]
    fn rejects_manifest_audio_stop_that_contradicts_last_segment_end() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), true);
        timeline
            .audio
            .as_mut()
            .expect("audio timeline")
            .session_stop_offset = timeline_time(13, 5);

        let error = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("derived.mp4"),
            true,
            timeline,
        )
        .expect_err("100 ms audio stop contradiction must fail closed");

        assert!(matches!(error, SessionExportError::InvalidTimeline(_)));
        assert!(error.to_string().contains("audio stop"));
    }

    #[test]
    fn rejects_output_media_with_non_integral_eye_width() {
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[{"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":63,"height":32}]}"#,
        )
        .expect("valid probe report");

        let error = probe
            .output_media()
            .expect_err("odd SBS width cannot describe two equal eyes");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error.to_string().contains("two equal eye widths"));
    }

    #[test]
    fn verifier_rejects_output_dimensions_that_differ_from_manifest_geometry() {
        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), false);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("manifest plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[{"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":80,"height":32}]}"#,
        )
        .expect("probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let error = verify_session_export_output(&plan, &output, &probe)
            .expect_err("80x32 output must not satisfy declared 64x32 SBS geometry");

        assert!(error.to_string().contains("derived SBS dimensions"));
    }

    #[test]
    fn verifier_rejects_output_audio_channels_that_differ_from_manifest() {
        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), true);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("manifest plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[
              {"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":64,"height":32},
              {"codec_type":"audio","codec_name":"aac","time_base":"1/48000","start_pts":24000,"duration_ts":96000,"sample_rate":"48000","channels":1}
            ]}"#,
        )
        .expect("probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let error = verify_session_export_output(&plan, &output, &probe)
            .expect_err("mono AAC must not satisfy a declared stereo source timeline");

        assert!(error.to_string().contains("source rate, channels"));
    }

    #[test]
    fn rejects_equal_count_eyes_with_different_manifest_coverage() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), false);
        timeline.right_segments[0].end_frame = 59;

        let error = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("derived.mp4"),
            true,
            timeline,
        )
        .expect_err("mismatched frame coverage must fail closed");

        assert!(matches!(error, SessionExportError::InvalidTimeline(_)));
        assert!(error.to_string().contains("coverage differs"));
    }

    #[test]
    fn rejects_non_contiguous_audio_sample_timeline() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), true);
        let audio = timeline.audio.as_mut().expect("audio timeline");
        audio.segments[0].start_sample = 1;

        let error = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("derived.mp4"),
            true,
            timeline,
        )
        .expect_err("audio sample gap must fail closed");

        assert!(matches!(error, SessionExportError::InvalidTimeline(_)));
        assert!(error
            .to_string()
            .contains("sample coverage is not contiguous"));
    }

    #[test]
    fn rejects_manifest_bound_input_changed_after_planning() {
        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), false);
        let changed = timeline.left_segments[0].path.clone();
        let output = directory.path().join("derived.mp4");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("valid plan");
        fs::write(&changed, b"LEFT").expect("replace source with same-length bytes");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("changed source digest must fail before ffmpeg");

        assert!(matches!(error, SessionExportError::InvalidTimeline(_)));
        assert!(error.to_string().contains("digest changed"));
        assert!(!output.exists());
    }

    #[test]
    fn rejects_probe_timing_beyond_contract_threshold() {
        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), false);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("valid plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[{"codec_type":"video","codec_name":"h264","time_base":"1/30","start_time":"0.100000000","duration":"2.000000000","nb_read_frames":"60","width":64,"height":32}]}"#,
        )
        .expect("valid probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let error = verify_session_export_output(&plan, &output, &probe)
            .expect_err("100ms start residual must fail");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error.to_string().contains("video timing residual"));
    }

    #[test]
    fn timeline_verifier_requires_per_frame_timestamp_evidence() {
        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), false);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("valid plan");
        let stream_only_probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[{"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":64,"height":32}]}"#,
        )
        .expect("stream-only probe report");

        let error = verify_session_export_output(&plan, &output, &stream_only_probe)
            .expect_err("aggregate stream evidence must not authorize a Pass receipt");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error
            .to_string()
            .contains("per-frame video timestamp evidence"));
    }

    #[test]
    fn verifies_manifest_timeline_without_source_audio() {
        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), false);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("valid plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[{"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":64,"height":32}]}"#,
        )
        .expect("valid probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let verification = verify_session_export_output(&plan, &output, &probe)
            .expect("video-only output should verify");

        assert_eq!(verification.audio_start_residual_ns, None);
        assert_eq!(verification.audio_end_residual_ns, None);
        assert_eq!(verification.encoding_audio_frame_ns, None);
        assert_eq!(verification.allowed_residual_ns, 33_333_334);
        assert_eq!(verification.preserved_leading_gap_ns, 0);
        assert_eq!(verification.probe_summary.audio_streams, 0);
        assert_eq!(verification.probe_summary.duration_ns, 2_000_000_000);
    }

    #[test]
    fn verifies_audio_that_legitimately_ends_before_video() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), true);
        let audio = timeline.audio.as_mut().expect("audio timeline");
        audio.sample_count = 48_000;
        audio.session_start_offset = timeline_time(1, 4);
        audio.session_stop_offset = timeline_time(5, 4);
        audio.segments[0].end_sample = 48_000;
        audio.segments[0].start_time = timeline_time(1, 4);
        audio.segments[0].end_time = timeline_time(5, 4);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("valid plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[
              {"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":60,"nb_read_frames":"60","width":64,"height":32},
              {"codec_type":"audio","codec_name":"aac","time_base":"1/48000","start_pts":12000,"duration_ts":48000,"sample_rate":"48000","channels":2}
            ]}"#,
        )
        .expect("valid probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let verification = verify_session_export_output(&plan, &output, &probe)
            .expect("early-ending audio should preserve video duration");

        assert_eq!(verification.audio_start_residual_ns, Some(0));
        assert_eq!(verification.audio_end_residual_ns, Some(0));
        assert_eq!(verification.preserved_leading_gap_ns, 250_000_000);
        assert_eq!(verification.probe_summary.duration_ns, 2_000_000_000);
    }

    #[test]
    fn validates_multiple_contiguous_video_and_audio_segments() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), true);
        let left_second = directory.path().join("video/left_00001.mp4");
        let right_second = directory.path().join("video/right_00001.mp4");
        let audio_second = directory.path().join("audio/audio_00001.wav");
        fs::write(&left_second, b"left second").expect("left second");
        fs::write(&right_second, b"right second").expect("right second");
        fs::write(&audio_second, b"audio second").expect("audio second");
        timeline.left_segments[0].end_frame = 30;
        timeline.left_segments[0].end_time = timeline_time(1, 1);
        timeline.right_segments[0].end_frame = 30;
        timeline.right_segments[0].end_time = timeline_time(1, 1);
        timeline
            .left_segments
            .push(timed_video_segment(1, left_second, 30, 60, 1, 2));
        timeline
            .right_segments
            .push(timed_video_segment(1, right_second, 30, 60, 1, 2));
        let audio = timeline.audio.as_mut().expect("audio timeline");
        audio.segments[0].end_sample = 48_000;
        audio.segments[0].end_time = timeline_time(3, 2);
        audio.segments.push(TimedAudioSegment {
            index: 1,
            bytes: fs::metadata(&audio_second)
                .expect("audio second metadata")
                .len(),
            sha256: sha256_file(&audio_second).expect("audio second digest"),
            path: audio_second,
            start_sample: 48_000,
            end_sample: 96_000,
            start_time: timeline_time(3, 2),
            end_time: timeline_time(5, 2),
        });

        let plan = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("derived.mp4"),
            true,
            timeline,
        )
        .expect("contiguous multi-segment timeline");

        assert_eq!(plan.video_segment_count(), 2);
        assert_eq!(plan.audio_segment_count(), 2);
        assert_eq!(plan.timing().expect("timing").paired_frames(), 60);
    }

    #[test]
    fn verifies_hour_long_timeline_without_accumulated_float_drift() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), false);
        timeline.left_segments[0].end_frame = 108_000;
        timeline.left_segments[0].end_time = timeline_time(3_600, 1);
        timeline.right_segments[0].end_frame = 108_000;
        timeline.right_segments[0].end_time = timeline_time(3_600, 1);
        let output = directory.path().join("derived.mp4");
        fs::write(&output, b"derived bytes").expect("derived output");
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("long timeline plan");
        let probe = OutputMediaProbe::from_ffprobe_json(
            br#"{"streams":[{"codec_type":"video","codec_name":"h264","time_base":"1/30","start_pts":0,"duration_ts":108000,"nb_read_frames":"108000","width":64,"height":32}]}"#,
        )
        .expect("long probe report")
        .with_uniform_video_frame_evidence_for_test()
        .expect("uniform frame evidence");

        let verification = verify_session_export_output(&plan, &output, &probe)
            .expect("long rational timeline should verify exactly");

        assert_eq!(verification.video_end_residual_ns, 0);
        assert_eq!(verification.paired_frames, 108_000);
        assert_eq!(verification.probe_summary.duration_ns, 3_600_000_000_000);
    }

    #[test]
    fn subtracts_high_precision_long_session_boundaries_before_narrowing() {
        let start = TimelineTime::from_decimal_seconds("3570.123456789").expect("start time");
        let end = TimelineTime::from_decimal_seconds("3600.123456789").expect("end time");

        let duration = end.checked_sub(start).expect("exact duration");

        assert_eq!(duration, timeline_time(30, 1));
        assert_eq!(
            duration.rounded_nanoseconds().expect("duration ns"),
            30_000_000_000
        );
    }

    #[test]
    fn accepts_json_precision_and_scientific_timeline_seconds() {
        let expected = TimelineTime::from_nanoseconds(33_333_333).expect("expected time");

        assert_eq!(
            TimelineTime::from_decimal_seconds("0.03333333333333333")
                .expect("high precision decimal"),
            expected
        );
        assert_eq!(
            TimelineTime::from_decimal_seconds("3.333333333333333e-2").expect("scientific decimal"),
            expected
        );
        assert_eq!(
            TimelineTime::from_decimal_seconds("1e-9").expect("one nanosecond"),
            TimelineTime::from_nanoseconds(1).expect("expected nanosecond")
        );
    }

    #[test]
    fn rounds_subnanosecond_timeline_seconds_away_from_zero_at_half() {
        assert_eq!(
            TimelineTime::from_decimal_seconds("0.0000000005").expect("positive half"),
            TimelineTime::from_nanoseconds(1).expect("positive nanosecond")
        );
        assert_eq!(
            TimelineTime::from_decimal_seconds("-5e-10").expect("negative half"),
            TimelineTime::from_nanoseconds(-1).expect("negative nanosecond")
        );
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

    #[cfg(unix)]
    #[test]
    fn production_ffmpeg_plans_disable_periodic_stats_before_inputs() {
        use std::os::unix::fs::PermissionsExt;

        fn run_fake_ffmpeg(
            executable: &Path,
            args: &[String],
        ) -> Result<BoundedCommandOutput, SessionExportError> {
            let mut command = Command::new(executable);
            command
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            run_bounded_command(
                &mut command,
                "ffmpeg",
                executable,
                0,
                PROCESS_STDERR_LIMIT_BYTES,
                &|| false,
            )
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let fake_ffmpeg = directory.path().join("periodic-stats-ffmpeg.sh");
        fs::write(
            &fake_ffmpeg,
            r#"#!/bin/sh
loglevel_error=0
nostats=0
previous=
for argument in "$@"; do
    if [ "$previous" = "-loglevel" ] && [ "$argument" = "error" ]; then
        loglevel_error=1
    fi
    if [ "$argument" = "-nostats" ]; then
        nostats=1
    fi
    previous=$argument
done
if [ "$loglevel_error" -eq 1 ] && [ "$nostats" -eq 1 ]; then
    exit 0
fi
while :; do
    printf 'frame=12345 fps=30.0 q=28.0 size=123456KiB time=01:23:45.67 bitrate=1234.5kbits/s speed=1.00x\r' >&2
done
"#,
        )
        .expect("write fake ffmpeg");
        let mut permissions = fs::metadata(&fake_ffmpeg)
            .expect("fake ffmpeg metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ffmpeg, permissions).expect("chmod fake ffmpeg");

        let default_args = vec!["-hide_banner".to_string(), "-nostdin".to_string()];
        let default_error = match run_fake_ffmpeg(&fake_ffmpeg, &default_args) {
            Ok(_) => panic!("default periodic stats must exceed the bounded stderr budget"),
            Err(error) => error,
        };
        assert!(matches!(
            default_error,
            SessionExportError::ProcessOutputLimit {
                process: "ffmpeg",
                stream: "stderr",
                limit_bytes: PROCESS_STDERR_LIMIT_BYTES,
                ..
            }
        ));

        write_publication(directory.path(), "h264", &separate_eyes_h264());
        let legacy_plan = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .build_plan(
                &SessionExportRequest::new(
                    directory.path(),
                    directory.path().join("legacy-output.mp4"),
                )
                .with_overwrite(true),
            )
            .expect("legacy plan");
        let legacy_staging = tempfile::tempdir().expect("legacy staging");
        let legacy_args =
            build_ffmpeg_args(&legacy_plan, legacy_staging.path()).expect("legacy ffmpeg args");

        let timeline_plan = SessionExportPlan::from_manifest_timeline(
            directory.path(),
            directory.path().join("timeline-output.mp4"),
            true,
            manifest_timeline_fixture(directory.path(), true),
        )
        .expect("timeline plan");
        let timeline_staging = tempfile::tempdir().expect("timeline staging");
        let timeline_args = build_ffmpeg_args(&timeline_plan, timeline_staging.path())
            .expect("timeline ffmpeg args");

        for (kind, args) in [("legacy", legacy_args), ("timeline", timeline_args)] {
            let completed = run_fake_ffmpeg(&fake_ffmpeg, &args)
                .unwrap_or_else(|error| panic!("{kind} production args leaked stats: {error}"));
            assert!(completed.status.success(), "{kind} fake ffmpeg failed");
            let first_input = args
                .iter()
                .position(|argument| argument == "-i")
                .expect("ffmpeg input");
            let loglevel = args
                .windows(2)
                .position(|window| window == ["-loglevel", "error"])
                .expect("quiet ffmpeg loglevel");
            let nostats = args
                .iter()
                .position(|argument| argument == "-nostats")
                .expect("disabled ffmpeg periodic stats");
            assert!(loglevel < first_input, "{kind} loglevel must be global");
            assert!(nostats < first_input, "{kind} nostats must be global");
        }
    }

    #[cfg(unix)]
    #[test]
    fn sustained_ffmpeg_stderr_is_killed_at_the_runtime_output_limit() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(directory.path(), "h264", &separate_eyes_h264());
        let output_dir = directory.path().join("exports");
        fs::create_dir(&output_dir).expect("output dir");
        let output = output_dir.join("bounded.mp4");
        let fake_ffmpeg = directory.path().join("unbounded-stderr-ffmpeg.sh");
        fs::write(
            &fake_ffmpeg,
            "#!/bin/sh\nwhile :; do printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' >&2; done\n",
        )
        .expect("write fake ffmpeg");
        let mut permissions = fs::metadata(&fake_ffmpeg)
            .expect("fake metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ffmpeg, permissions).expect("chmod fake ffmpeg");

        let started = Instant::now();
        let error = FfmpegSessionExporter::new(
            SessionExportConfig::system_ffmpeg().with_ffmpeg_path(&fake_ffmpeg),
        )
        .export_source_tree(
            &SessionExportRequest::new(directory.path(), &output).with_overwrite(true),
        )
        .expect_err("unbounded ffmpeg stderr must be terminated");

        match error {
            SessionExportError::ProcessOutputLimit {
                process,
                stream,
                limit_bytes,
                diagnostic,
            } => {
                assert_eq!(process, "ffmpeg");
                assert_eq!(stream, "stderr");
                assert_eq!(limit_bytes, PROCESS_STDERR_LIMIT_BYTES);
                assert!(diagnostic.len() <= STDERR_PREVIEW_BYTES + 3);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stderr overflow did not terminate ffmpeg promptly"
        );
        assert!(!output.exists());
        assert_eq!(staging_dirs(&output_dir), Vec::<String>::new());
    }

    #[cfg(unix)]
    #[test]
    fn sustained_frame_probe_stderr_is_killed_at_the_runtime_output_limit() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let directory = tempfile::tempdir().expect("tempdir");
        let fake_ffprobe = directory.path().join("unbounded-stderr-ffprobe.sh");
        fs::write(
            &fake_ffprobe,
            "#!/bin/sh\nwhile :; do printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' >&2; done\n",
        )
        .expect("write fake ffprobe");
        let mut permissions = fs::metadata(&fake_ffprobe)
            .expect("fake metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ffprobe, permissions).expect("chmod fake ffprobe");
        let mut command = Command::new(&fake_ffprobe);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let error = run_frame_timeline_command(
            &mut command,
            &fake_ffprobe,
            directory.path().join("derived.mp4").as_path(),
            timeline_time(1, 30),
            TimelineTime::zero(),
            timeline_time(2, 1),
            60,
            &|| false,
        )
        .expect_err("unbounded ffprobe stderr must be terminated");

        match error {
            SessionExportError::ProcessOutputLimit {
                process,
                stream,
                limit_bytes,
                diagnostic,
            } => {
                assert_eq!(process, "ffprobe");
                assert_eq!(stream, "stderr");
                assert_eq!(limit_bytes, PROCESS_STDERR_LIMIT_BYTES);
                assert!(diagnostic.len() <= STDERR_PREVIEW_BYTES + 3);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stderr overflow did not terminate and reap ffprobe promptly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_a_running_ffmpeg_without_publishing_output() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        let directory = tempfile::tempdir().expect("tempdir");
        write_publication(directory.path(), "h264", &separate_eyes_h264());
        let output_dir = directory.path().join("exports");
        fs::create_dir(&output_dir).expect("output dir");
        let output = output_dir.join("cancelled.mp4");
        let started_marker = directory.path().join("ffmpeg-started");
        let fake_ffmpeg = directory.path().join("blocking-ffmpeg.sh");
        fs::write(
            &fake_ffmpeg,
            format!(
                "#!/bin/sh\n: > \"{}\"\nwhile :; do :; done\n",
                started_marker.display()
            ),
        )
        .expect("write fake ffmpeg");
        let mut permissions = fs::metadata(&fake_ffmpeg)
            .expect("fake metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ffmpeg, permissions).expect("chmod fake ffmpeg");

        let exporter = FfmpegSessionExporter::new(
            SessionExportConfig::system_ffmpeg().with_ffmpeg_path(&fake_ffmpeg),
        );
        let plan = exporter
            .build_plan(&SessionExportRequest::new(directory.path(), &output).with_overwrite(true))
            .expect("build export plan");
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let worker = thread::spawn(move || {
            exporter.export_plan_cancellable(&plan, || worker_cancelled.load(Ordering::SeqCst))
        });

        let wait_started = Instant::now();
        while !started_marker.exists() && wait_started.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(started_marker.exists(), "fake ffmpeg did not start");
        let cancel_started = Instant::now();
        cancelled.store(true, Ordering::SeqCst);
        let error = worker
            .join()
            .expect("export worker must not panic")
            .expect_err("cancelled ffmpeg must not export");

        assert!(matches!(error, SessionExportError::Cancelled));
        assert!(
            cancel_started.elapsed() < Duration::from_secs(2),
            "cancellation did not terminate and reap ffmpeg promptly"
        );
        assert!(!output.exists());
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

    #[test]
    fn exports_and_verifies_real_manifest_timeline_with_late_audio() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping manifest timeline export because ffmpeg/ffprobe is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        let audio = source.join("audio/audio_00000.wav");
        generate_h264_clip(&left, "red");
        generate_h264_clip(&right, "blue");
        generate_wav(&audio);
        let video_segment = |path: PathBuf| TimedVideoSegment {
            index: 0,
            bytes: fs::metadata(&path).expect("video metadata").len(),
            sha256: sha256_file(&path).expect("video digest"),
            path,
            start_frame: 0,
            end_frame: 6,
            start_time: TimelineTime::zero(),
            end_time: timeline_time(3, 5),
        };
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "e".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 10),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![video_segment(left)],
            right_segments: vec![video_segment(right)],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 44_100,
                channels: 2,
                sample_count: 26_460,
                session_start_offset: timeline_time(1, 5),
                session_stop_offset: timeline_time(7, 10),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&audio).expect("audio metadata").len(),
                    sha256: sha256_file(&audio).expect("audio digest"),
                    path: audio,
                    start_sample: 0,
                    end_sample: 26_460,
                    start_time: timeline_time(1, 5),
                    end_time: timeline_time(4, 5),
                }],
            }),
        };
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(&source, &output, false, timeline)
            .expect("manifest plan");

        let receipt = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect("verified timeline export");

        let verification = receipt
            .timeline_verification
            .expect("timeline verification receipt");
        assert_eq!(verification.verdict, TimelineVerificationVerdict::Pass);
        assert_eq!(verification.paired_frames, 6);
        assert_eq!(verification.preserved_leading_gap_ns, 200_000_000);
        assert!(
            verification.probe_summary.duration_ns < 800_000_000,
            "manifest stop must truncate the 800 ms sample-derived audio end"
        );
        assert_eq!(
            verification.probe_summary.output_bytes,
            receipt.output_size_bytes
        );
        assert_eq!(
            verification.probe_summary.output_sha256,
            sha256_file(&output).expect("output digest")
        );
        let media = receipt.output_media.expect("output media properties");
        assert_eq!(media.video_codec, "h264");
        assert_eq!((media.width, media.height), (64, 32));
        assert_eq!(media.layout, "left-right-side-by-side");
        assert_eq!(media.eye_width, 32);
        assert_eq!(media.width, media.eye_width * 2);
        let audio = media.audio.expect("output audio properties");
        assert_eq!(audio.codec, "aac");
        assert_eq!(audio.sample_rate_hz, 44_100);
        assert!(output.is_file());
        assert_eq!(staging_dirs(directory.path()), Vec::<String>::new());
    }

    #[test]
    fn real_timeline_export_retimes_each_manifest_frame_across_source_pts_gap() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping source PTS-gap regression because ffmpeg/ffprobe is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left_first = source.join("video/left_00000.mp4");
        let left_second = source.join("video/left_00001.mp4");
        let right_first = source.join("video/right_00000.mp4");
        let right_second = source.join("video/right_00001.mp4");
        let audio = source.join("audio/audio_00000.wav");
        generate_timeline_h264_clip(&left_first, "red", true);
        generate_timeline_h264_clip(&left_second, "red", false);
        generate_timeline_h264_clip(&right_first, "blue", true);
        generate_timeline_h264_clip(&right_second, "blue", false);
        generate_timeline_wav(&audio);

        let video_segment =
            |index: u32, path: PathBuf, start_frame: u64, end_frame: u64| TimedVideoSegment {
                index,
                bytes: fs::metadata(&path).expect("video metadata").len(),
                sha256: sha256_file(&path).expect("video digest"),
                path,
                start_frame,
                end_frame,
                start_time: timeline_time(i64::from(index), 1),
                end_time: timeline_time(i64::from(index) + 1, 1),
            };
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "f".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![
                video_segment(0, left_first, 0, 30),
                video_segment(1, left_second, 30, 60),
            ],
            right_segments: vec![
                video_segment(0, right_first, 0, 30),
                video_segment(1, right_second, 30, 60),
            ],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: TimelineTime::zero(),
                session_stop_offset: timeline_time(2, 1),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&audio).expect("audio metadata").len(),
                    sha256: sha256_file(&audio).expect("audio digest"),
                    path: audio,
                    start_sample: 0,
                    end_sample: 96_000,
                    start_time: TimelineTime::zero(),
                    end_time: timeline_time(2, 1),
                }],
            }),
        };
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(&source, &output, false, timeline)
            .expect("manifest plan");

        let receipt = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect("timeline export currently signs the aggregate timing");
        let verification = receipt
            .timeline_verification
            .as_ref()
            .expect("timeline verification");
        assert_eq!(
            verification.left_right_pairing,
            TimelineVerificationVerdict::Pass
        );
        assert!(verification
            .audio_start_residual_ns
            .is_some_and(|residual| residual.unsigned_abs() <= verification.allowed_residual_ns));
        assert!(verification
            .audio_end_residual_ns
            .is_some_and(|residual| residual.unsigned_abs() <= verification.allowed_residual_ns));
        assert!(receipt
            .output_media
            .as_ref()
            .and_then(|media| media.audio.as_ref())
            .is_some());

        let frames = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "frame=best_effort_timestamp_time",
                "-of",
                "flat=s=_",
            ])
            .arg(&output)
            .output()
            .expect("probe output frames");
        assert!(
            frames.status.success(),
            "frame probe failed: {}",
            String::from_utf8_lossy(&frames.stderr)
        );
        let timestamps = String::from_utf8(frames.stdout)
            .expect("frame timestamps utf8")
            .lines()
            .filter(|line| !line.is_empty())
            .filter(|line| line.contains("_best_effort_timestamp_time="))
            .map(|line| {
                parse_decimal_timeline_time(
                    line.split_once('=')
                        .expect("timestamp key/value")
                        .1
                        .trim_matches('"'),
                )
                .expect("valid frame timestamp")
            })
            .collect::<Vec<_>>();
        assert_eq!(timestamps.len(), 60, "decoded output frame count");
        for (index, actual) in timestamps.into_iter().enumerate() {
            let expected = timeline_time(i64::try_from(index).expect("frame index"), 30);
            let residual = timeline_residual_ns(actual, expected).expect("frame residual");
            assert!(
                residual.unsigned_abs() <= 1_000,
                "output frame {index} has timestamp residual {residual} ns"
            );
        }
    }

    #[test]
    fn timeline_verifier_rejects_irregular_internal_frame_timestamps() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping irregular output verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let timeline = manifest_timeline_fixture(directory.path(), false);
        let output = directory.path().join("irregular-derived.mp4");
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            "color=c=purple:size=64x32:rate=30",
            "-vf",
            r"setpts=if(lt(N\,10)\,N/(30*TB)\,if(lt(N\,20)\,(0.5+(N-10)*0.01)/TB\,N/(30*TB)))",
            "-vsync",
            "0",
            "-frames:v",
            "60",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            output.to_str().expect("test path utf8"),
        ]);
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("manifest plan");
        let probe = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .probe_output(&output)
            .expect("aggregate output probe");

        let error = verify_session_export_output(&plan, &output, &probe)
            .expect_err("irregular internal frame timestamps must never receive a Pass receipt");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error.to_string().contains("frame timestamp"));
    }

    #[test]
    fn timeline_verifier_rejects_irregular_internal_audio_timestamps() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping irregular audio verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let mut timeline = manifest_timeline_fixture(directory.path(), true);
        let source_audio = timeline.audio.as_mut().expect("audio timeline");
        source_audio.session_start_offset = TimelineTime::zero();
        source_audio.session_stop_offset = timeline_time(2, 1);
        source_audio.segments[0].start_time = TimelineTime::zero();
        source_audio.segments[0].end_time = timeline_time(2, 1);
        let irregular_audio = directory.path().join("irregular.m4a");
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000:duration=2",
            "-af",
            r"asetpts=if(lt(T\,0.5)\,PTS\,(1+(T-0.5)*2/3)/TB)",
            "-ac",
            "2",
            "-c:a",
            "aac",
            irregular_audio.to_str().expect("audio path utf8"),
        ]);
        let output = directory.path().join("irregular-audio-derived.mp4");
        run_ffmpeg(&[
            "-f",
            "lavfi",
            "-i",
            "color=c=purple:size=64x32:rate=30:duration=2",
            "-i",
            irregular_audio.to_str().expect("audio path utf8"),
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "copy",
            output.to_str().expect("output path utf8"),
        ]);
        let plan =
            SessionExportPlan::from_manifest_timeline(directory.path(), &output, true, timeline)
                .expect("manifest plan");
        let probe = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .probe_output(&output)
            .expect("aggregate output probe");

        let error = verify_session_export_output(&plan, &output, &probe)
            .expect_err("irregular internal audio timestamps must never receive a Pass receipt");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error.to_string().contains("audio frame timestamp"));
    }

    #[test]
    fn source_video_contract_rejects_non_h264_mp4_segment() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping source video codec verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        generate_fixed_frame_mpeg4_clip(&left, "red", 30);
        generate_fixed_frame_h264_clip(&right, "blue", 30);
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(
            &source,
            &output,
            false,
            single_segment_video_timeline(left, right),
        )
        .expect("manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("MPEG-4 Part 2 must not satisfy the declared H.264 source contract");

        assert!(error.to_string().contains("left-eye segment 0"));
        assert!(error.to_string().contains("H.264"));
        assert!(!output.exists());
    }

    #[test]
    fn source_video_contract_rejects_non_mp4_container_content() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping source video container verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        generate_matroska_h264_clip_with_mp4_name(&left, "red", 30);
        generate_fixed_frame_h264_clip(&right, "blue", 30);
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(
            &source,
            &output,
            false,
            single_segment_video_timeline(left, right),
        )
        .expect("manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("Matroska content renamed .mp4 must not satisfy the MP4 source contract");

        assert!(error.to_string().contains("left-eye segment 0"));
        assert!(error.to_string().contains("MP4"));
        assert!(!output.exists());
    }

    #[test]
    fn source_video_contract_rejects_segment_with_extra_stream() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping source video stream verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        generate_h264_clip_with_extra_audio_stream(&left, "red", 30);
        generate_fixed_frame_h264_clip(&right, "blue", 30);
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(
            &source,
            &output,
            false,
            single_segment_video_timeline(left, right),
        )
        .expect("manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("a source video segment with an extra audio stream must fail closed");

        assert!(error.to_string().contains("left-eye segment 0"));
        assert!(error.to_string().contains("exactly one"));
        assert!(!output.exists());
    }

    #[test]
    fn source_video_contract_rejects_wrong_eye_dimensions() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping source video dimension verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        generate_fixed_frame_h264_clip_with_size(&left, "red", 30, "48x32");
        generate_fixed_frame_h264_clip(&right, "blue", 30);
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(
            &source,
            &output,
            false,
            single_segment_video_timeline(left, right),
        )
        .expect("manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("48x32 source must not satisfy a declared 32x32 eye geometry");

        assert!(error.to_string().contains("left-eye segment 0"));
        assert!(error.to_string().contains("48x32"));
        assert!(error.to_string().contains("32x32"));
        assert!(!output.exists());
    }

    #[test]
    fn timeline_export_rejects_per_segment_decoded_frame_compensation() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!(
                "skipping per-segment frame count verification because ffmpeg is unavailable"
            );
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left_first = source.join("video/left_00000.mp4");
        let left_second = source.join("video/left_00001.mp4");
        let right_first = source.join("video/right_00000.mp4");
        let right_second = source.join("video/right_00001.mp4");
        generate_fixed_frame_h264_clip(&left_first, "red", 29);
        generate_fixed_frame_h264_clip(&left_second, "red", 31);
        generate_fixed_frame_h264_clip(&right_first, "blue", 29);
        generate_fixed_frame_h264_clip(&right_second, "blue", 31);
        let video_segment =
            |index: u32, path: PathBuf, start_frame: u64, end_frame: u64| TimedVideoSegment {
                index,
                bytes: fs::metadata(&path).expect("video metadata").len(),
                sha256: sha256_file(&path).expect("video digest"),
                path,
                start_frame,
                end_frame,
                start_time: timeline_time(i64::from(index), 1),
                end_time: timeline_time(i64::from(index) + 1, 1),
            };
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "9".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![
                video_segment(0, left_first, 0, 30),
                video_segment(1, left_second, 30, 60),
            ],
            right_segments: vec![
                video_segment(0, right_first, 0, 30),
                video_segment(1, right_second, 30, 60),
            ],
            audio: None,
        };
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(&source, &output, false, timeline)
            .expect("aggregate manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("29+31 decoded frames must not satisfy two declared 30-frame segments");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error
            .to_string()
            .contains("left-eye segment 0 decoded frame count 29 does not match declared 30"));
        assert!(!output.exists());
    }

    #[test]
    fn timeline_export_rejects_per_segment_decoded_audio_sample_compensation() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!(
                "skipping per-segment audio sample verification because ffmpeg is unavailable"
            );
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        let audio_short = source.join("audio/audio_00000.wav");
        let audio_long = source.join("audio/audio_00001.wav");
        generate_fixed_frame_h264_clip(&left, "red", 60);
        generate_fixed_frame_h264_clip(&right, "blue", 60);
        generate_fixed_sample_stereo_wav(&audio_short, 24_000);
        generate_fixed_sample_stereo_wav(&audio_long, 72_000);
        let video_segment = |path: PathBuf| TimedVideoSegment {
            index: 0,
            bytes: fs::metadata(&path).expect("video metadata").len(),
            sha256: sha256_file(&path).expect("video digest"),
            path,
            start_frame: 0,
            end_frame: 60,
            start_time: TimelineTime::zero(),
            end_time: timeline_time(2, 1),
        };
        let audio_segment =
            |index: u32, path: PathBuf, start_sample: u64, end_sample: u64| TimedAudioSegment {
                index,
                bytes: fs::metadata(&path).expect("audio metadata").len(),
                sha256: sha256_file(&path).expect("audio digest"),
                path,
                start_sample,
                end_sample,
                start_time: timeline_time(i64::from(index), 1),
                end_time: timeline_time(i64::from(index) + 1, 1),
            };
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "8".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![video_segment(left)],
            right_segments: vec![video_segment(right)],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: TimelineTime::zero(),
                session_stop_offset: timeline_time(2, 1),
                segments: vec![
                    audio_segment(0, audio_short, 0, 48_000),
                    audio_segment(1, audio_long, 48_000, 96_000),
                ],
            }),
        };
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(&source, &output, false, timeline)
            .expect("aggregate manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err(
                "24,000+72,000 decoded sample frames must not satisfy two declared 48,000-frame segments",
            );

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error.to_string().contains(
            "audio segment 0 decoded sample frame count 24000 does not match declared 48000"
        ));
        assert!(!output.exists());
    }

    #[test]
    fn timeline_export_rejects_audio_segments_with_declared_channel_mismatch() {
        if !ffmpeg_available() || !ffprobe_available() {
            eprintln!("skipping declared audio channel verification because ffmpeg is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("source");
        let left = source.join("video/left_00000.mp4");
        let right = source.join("video/right_00000.mp4");
        let audio = source.join("audio/audio_00000.wav");
        generate_fixed_frame_h264_clip(&left, "red", 60);
        generate_fixed_frame_h264_clip(&right, "blue", 60);
        generate_fixed_sample_wav(&audio, 96_000, 1);
        let video_segment = |path: PathBuf| TimedVideoSegment {
            index: 0,
            bytes: fs::metadata(&path).expect("video metadata").len(),
            sha256: sha256_file(&path).expect("video digest"),
            path,
            start_frame: 0,
            end_frame: 60,
            start_time: TimelineTime::zero(),
            end_time: timeline_time(2, 1),
        };
        let timeline = ManifestSessionTimeline {
            source_manifest_sha256: "7".repeat(64),
            clock: SessionTimelineClock::HostMonotonic,
            video_tick: timeline_time(1, 30),
            eye_width: 32,
            eye_height: 32,
            left_segments: vec![video_segment(left)],
            right_segments: vec![video_segment(right)],
            audio: Some(ManifestAudioTimeline {
                sample_rate_hz: 48_000,
                channels: 2,
                sample_count: 96_000,
                session_start_offset: TimelineTime::zero(),
                session_stop_offset: timeline_time(2, 1),
                segments: vec![TimedAudioSegment {
                    index: 0,
                    bytes: fs::metadata(&audio).expect("audio metadata").len(),
                    sha256: sha256_file(&audio).expect("audio digest"),
                    path: audio,
                    start_sample: 0,
                    end_sample: 96_000,
                    start_time: TimelineTime::zero(),
                    end_time: timeline_time(2, 1),
                }],
            }),
        };
        let output = directory.path().join("derived.mp4");
        let plan = SessionExportPlan::from_manifest_timeline(&source, &output, false, timeline)
            .expect("aggregate manifest plan");

        let error = FfmpegSessionExporter::new(SessionExportConfig::system_ffmpeg())
            .export_plan(&plan)
            .expect_err("mono audio must not satisfy a declared stereo source timeline");

        assert!(matches!(
            error,
            SessionExportError::OutputVerificationFailed(_)
        ));
        assert!(error
            .to_string()
            .contains("audio segment 0 channel count 1 does not match declared 2"));
        assert!(!output.exists());
    }
}
