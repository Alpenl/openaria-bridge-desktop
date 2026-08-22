//! Production FFmpeg/ffprobe effects for media normalization.
//!
//! This module deliberately keeps every process detail on the adapter side:
//! callers provide a frozen media plan and exact encoding profile, while this
//! adapter owns argument construction, the child process from spawn through
//! reap, bounded diagnostics, and validation of the closed partial outputs.
//! No command is passed through a shell.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ylx_transfer_core::media_normalizer::{PairQualityEvidence, SegmentQualityAnalyzer};
use ylx_transfer_core::normalization::{
    ContainerFormat, ContentSha256, Dimensions, EncodeSegmentPairRequest, EncodedSegmentPair,
    EncoderBuild, EncoderBuildFingerprint, EncoderCompatibilityClass, EncoderStatistics, Eye,
    FrameSlice, HevcProfile, MediaEncoder, MediaOperationControl, MediaProbe, MediaProcessFailure,
    MediaProcessFailureCode, MediaProcessOutcome, NormalizationInput, NormalizationProfile,
    OutputMediaEvidence, PixelFormat, ProbeReport, ProbeRequest, ProbedArtifact,
    ProcessDisposition, ProcessReapReport, ProcessStopReason, Rational, ReapReceipt,
    ResolvedSourceArtifact, SampleEntry, SegmentValidationReport, SegmentValidationRequest,
    SourceArtifactId, SourceMediaKind, VideoCodec,
};

/// Maximum ffprobe JSON retained in memory. A segment probe is structured but
/// can contain one frame record per decoded frame, so it needs a larger bound
/// than human-facing diagnostics.
pub const MAX_PROBE_JSON_BYTES: usize = 16 * 1024 * 1024;

/// Maximum raw stderr retained while still continuously draining the pipe.
pub const MAX_CAPTURED_STDERR_BYTES: usize = 64 * 1024;

/// Maximum process-controlled text exposed in an error or log record.
pub const MAX_PROCESS_DIAGNOSTIC_BYTES: usize = 1024;

pub const PROCESS_TEXT_TRUNCATION_MARKER: &str = "...[truncated]";

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(2);

/// Explicit executable/process policy. Encoding parameters do not live here:
/// they must arrive on each frozen profile, so configuration can never guess
/// a CRF or silently select a different quality variant.
#[derive(Debug, Clone)]
pub struct FfmpegNormalizerConfig {
    pub ffmpeg_path: PathBuf,
    pub ffprobe_path: PathBuf,
    pub capability_deadline: Duration,
    pub poll_interval: Duration,
    pub stop_grace: Duration,
}

impl FfmpegNormalizerConfig {
    pub fn system_path() -> Self {
        Self {
            ffmpeg_path: PathBuf::from("ffmpeg"),
            ffprobe_path: PathBuf::from("ffprobe"),
            capability_deadline: Duration::from_secs(10),
            poll_interval: DEFAULT_POLL_INTERVAL,
            stop_grace: DEFAULT_STOP_GRACE,
        }
    }

    fn validate(&self) -> Result<(), FfmpegInitError> {
        if self.ffmpeg_path.as_os_str().is_empty() {
            return Err(FfmpegInitError::InvalidConfig(
                "ffmpeg executable path is empty".to_string(),
            ));
        }
        if self.ffprobe_path.as_os_str().is_empty() {
            return Err(FfmpegInitError::InvalidConfig(
                "ffprobe executable path is empty".to_string(),
            ));
        }
        if self.capability_deadline.is_zero() {
            return Err(FfmpegInitError::InvalidConfig(
                "capability deadline must be positive".to_string(),
            ));
        }
        if self.poll_interval.is_zero() {
            return Err(FfmpegInitError::InvalidConfig(
                "process poll interval must be positive".to_string(),
            ));
        }
        if self.stop_grace.is_zero() {
            return Err(FfmpegInitError::InvalidConfig(
                "process stop grace must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfmpegBuildObservation {
    pub implementation: String,
    pub version_line: String,
    pub build_fingerprint: String,
}

/// What this adapter could establish about the FFmpeg metrics filters during
/// construction. It intentionally does not have a "ready" state: the core
/// profile requires stereo/CV domain evidence as well as VMAF and SSIM, and
/// that evaluator plus durable report storage are separate capabilities that
/// FFmpeg cannot supply on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FfmpegQualityEvidenceCapability {
    MetricsFiltersUnavailable { detail: String },
    MetricsFiltersAvailableButDomainEvidenceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FfmpegInitError {
    InvalidConfig(String),
    Capability(String),
}

impl fmt::Display for FfmpegInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(detail) => write!(f, "invalid FFmpeg configuration: {detail}"),
            Self::Capability(detail) => write!(f, "FFmpeg capability check failed: {detail}"),
        }
    }
}

impl std::error::Error for FfmpegInitError {}

/// Production adapter. Construction fingerprints the exact FFmpeg build and
/// verifies that `libx265` is actually present. A configured but unavailable
/// encoder is therefore a capability failure, never a runtime codec fallback.
#[derive(Debug, Clone)]
pub struct FfmpegMediaNormalizer {
    config: FfmpegNormalizerConfig,
    build_observation: FfmpegBuildObservation,
    encoder_build: EncoderBuild,
    quality_evidence_capability: FfmpegQualityEvidenceCapability,
}

impl FfmpegMediaNormalizer {
    pub fn new(config: FfmpegNormalizerConfig) -> Result<Self, FfmpegInitError> {
        config.validate()?;
        let build_observation = inspect_encoder_build(&config)?;
        let quality_evidence_capability = inspect_quality_evidence_capability(&config);
        let fingerprint =
            EncoderBuildFingerprint::parse(build_observation.build_fingerprint.clone())
                .map_err(|error| FfmpegInitError::Capability(error.to_string()))?;
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "fingerprint_scheme".to_string(),
            "ffmpeg-version-and-libx265-help-v1".to_string(),
        );
        let encoder_build = EncoderBuild::new(
            build_observation.implementation.clone(),
            build_observation.version_line.clone(),
            fingerprint,
            EncoderCompatibilityClass::x265_software_v1(),
            parameters,
        )
        .map_err(|error| FfmpegInitError::Capability(error.to_string()))?;
        Ok(Self {
            config,
            build_observation,
            encoder_build,
            quality_evidence_capability,
        })
    }

    pub fn build_observation(&self) -> &FfmpegBuildObservation {
        &self.build_observation
    }

    /// Reports the result of the non-invasive FFmpeg metrics-filter probe.
    ///
    /// A caller must still provide a real stereo/CV evaluator and a durable
    /// report archive before this adapter can emit `QualityEvidence`.
    pub fn quality_evidence_capability(&self) -> &FfmpegQualityEvidenceCapability {
        &self.quality_evidence_capability
    }

    fn validate_pair(
        &self,
        request: &SegmentValidationRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<SegmentValidationReport> {
        if request.encoder_build() != &self.encoder_build {
            return failure_without_process(
                MediaProcessFailureCode::ValidationRejected,
                false,
                "validation request targets a different encoder build fingerprint",
            );
        }
        let timing = match operation_timing(control) {
            Ok(timing) => timing,
            Err(detail) => {
                return failure_without_process(MediaProcessFailureCode::Internal, false, detail)
            }
        };
        let frame_rate = match FrameRate::try_from(request.pair_plan().source_fps()) {
            Ok(frame_rate) => frame_rate,
            Err(detail) => {
                return failure_without_process(
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    detail,
                )
            }
        };
        let profile = match ExactEncodingProfile::from_core(request.profile()) {
            Ok(profile) => profile,
            Err(detail) => {
                return failure_without_process(
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    detail,
                )
            }
        };
        let expected = ExpectedOutputContract {
            frame_rate,
            frame_count: request.pair_plan().frame_count(),
            eye_width: request.pair_plan().eye_dimensions().width(),
            eye_height: request.pair_plan().eye_dimensions().height(),
            profile,
        };
        let mut receipts = Vec::new();
        let left = match self.validate_output_file::<SegmentValidationReport>(
            request.encoded().left_partial_path(),
            &expected,
            timing,
            control,
            &mut receipts,
        ) {
            Ok(output) => output,
            Err(outcome) => return outcome,
        };
        let right = match self.validate_output_file::<SegmentValidationReport>(
            request.encoded().right_partial_path(),
            &expected,
            timing,
            control,
            &mut receipts,
        ) {
            Ok(output) => output,
            Err(outcome) => return outcome,
        };
        if let Err(detail) = validate_duration_pair(&left.inspected, &right.inspected, frame_rate) {
            return failure_after_reap(
                &receipts,
                MediaProcessFailureCode::ValidationRejected,
                false,
                detail,
            );
        }
        let left_evidence = match output_media_evidence(request, Eye::Left, left) {
            Ok(evidence) => evidence,
            Err(detail) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    detail,
                )
            }
        };
        let right_evidence = match output_media_evidence(request, Eye::Right, right) {
            Ok(evidence) => evidence,
            Err(detail) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    detail,
                )
            }
        };
        let report = match SegmentValidationReport::evaluate(
            request.pair_plan(),
            request.profile(),
            left_evidence,
            right_evidence,
            request.left_quality().clone(),
            request.right_quality().clone(),
        ) {
            Ok(report) => report,
            Err(error) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    error.to_string(),
                )
            }
        };
        MediaProcessOutcome::completed(report, reap_report(&receipts))
    }

    fn validate_output_file<T>(
        &self,
        path: &Path,
        expected: &ExpectedOutputContract,
        timing: OperationTiming,
        control: &dyn MediaOperationControl,
        receipts: &mut Vec<ReapReceipt>,
    ) -> Result<ValidatedOutputFile, MediaProcessOutcome<T>> {
        if !path.is_absolute() {
            return Err(if receipts.is_empty() {
                failure_without_process(
                    MediaProcessFailureCode::InvalidOutput,
                    false,
                    "partial output path is not absolute",
                )
            } else {
                failure_after_reap(
                    receipts,
                    MediaProcessFailureCode::InvalidOutput,
                    false,
                    "partial output path is not absolute",
                )
            });
        }
        if let Err(detail) = ensure_closed_nonempty_regular_file(path) {
            return Err(if receipts.is_empty() {
                failure_without_process(MediaProcessFailureCode::InvalidOutput, false, detail)
            } else {
                failure_after_reap(
                    receipts,
                    MediaProcessFailureCode::InvalidOutput,
                    false,
                    detail,
                )
            });
        }
        let probe = run_core_process::<T>(
            &self.config.ffprobe_path,
            &probe_args(path, true, None),
            Some(MAX_PROBE_JSON_BYTES),
            timing,
            self.config.poll_interval,
            control,
            receipts,
            MediaProcessFailureCode::ValidationRejected,
            false,
        )?;
        let document = parse_probe_document(&probe.stdout).map_err(|detail| {
            failure_after_reap(
                receipts,
                MediaProcessFailureCode::ValidationRejected,
                false,
                detail,
            )
        })?;
        let inspected = inspect_normalized_output(&document, expected).map_err(|detail| {
            failure_after_reap(
                receipts,
                MediaProcessFailureCode::ValidationRejected,
                false,
                detail,
            )
        })?;
        let decode = run_core_process::<T>(
            &self.config.ffmpeg_path,
            &full_decode_args(path),
            Some(1024 * 1024),
            timing,
            self.config.poll_interval,
            control,
            receipts,
            MediaProcessFailureCode::ValidationRejected,
            false,
        )?;
        let decoded_frames = decoded_frame_count(&decode.stdout).map_err(|detail| {
            failure_after_reap(
                receipts,
                MediaProcessFailureCode::ValidationRejected,
                false,
                detail,
            )
        })?;
        if decoded_frames != expected.frame_count {
            return Err(failure_after_reap(
                receipts,
                MediaProcessFailureCode::ValidationRejected,
                false,
                format!(
                    "full decode produced {decoded_frames} frames, expected {}",
                    expected.frame_count
                ),
            ));
        }
        let (sha256, size_bytes) = sha256_and_sync(path).map_err(|error| {
            failure_after_reap(
                receipts,
                MediaProcessFailureCode::Io,
                true,
                format!(
                    "could not hash and durably flush {}: {}",
                    path.display(),
                    sanitize_process_diagnostic(error.to_string().as_bytes())
                ),
            )
        })?;
        Ok(ValidatedOutputFile {
            path: path.to_path_buf(),
            inspected,
            decoded_frames,
            sha256,
            size_bytes,
        })
    }
}

#[derive(Debug)]
struct ValidatedOutputFile {
    path: PathBuf,
    inspected: InspectedOutput,
    decoded_frames: u64,
    sha256: String,
    size_bytes: u64,
}

fn output_media_evidence(
    request: &SegmentValidationRequest,
    eye: Eye,
    output: ValidatedOutputFile,
) -> Result<OutputMediaEvidence, String> {
    let sha256 = ContentSha256::parse(output.sha256).map_err(|error| error.to_string())?;
    OutputMediaEvidence::new(
        eye,
        output.path,
        request.pair_plan().output_relative_path(eye),
        request.profile().profile_revision().clone(),
        output.size_bytes,
        sha256,
        VideoCodec::Hevc,
        HevcProfile::Main,
        ContainerFormat::Mp4,
        SampleEntry::Hvc1,
        PixelFormat::Yuv420p,
        request.pair_plan().eye_dimensions(),
        request.pair_plan().source_fps(),
        request.profile().time_base(),
        output.inspected.frame_count,
        output.inspected.duration_ticks,
        1,
        0,
        true,
        true,
        false,
        output.inspected.keyframe_frames,
        true,
        output.decoded_frames,
    )
    .map_err(|error| error.to_string())
}

/// Sanitizes bytes controlled by an external executable before they cross the
/// adapter boundary. Invalid UTF-8 is replaced, terminal controls and bidi
/// formatting are neutralized, and the retained byte prefix is bounded.
pub fn sanitize_process_diagnostic(raw: &[u8]) -> String {
    let kept = raw.len().min(MAX_PROCESS_DIAGNOSTIC_BYTES);
    let mut value = String::with_capacity(kept);
    for ch in String::from_utf8_lossy(&raw[..kept]).chars() {
        let unsafe_for_log = ch.is_control()
            || matches!(
                ch,
                '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{feff}'
            );
        value.push(if unsafe_for_log { '\u{fffd}' } else { ch });
    }
    if raw.len() > kept {
        value.push_str(PROCESS_TEXT_TRUNCATION_MARKER);
    }
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedStop {
    Pause,
    Cancel,
    Shutdown,
    SourceUnavailable,
}

#[derive(Debug)]
struct CapturedPipe {
    bytes: Vec<u8>,
    truncated: bool,
    retained_limit: usize,
}

fn drain_bounded<R>(mut reader: R, retained_limit: usize) -> io::Result<CapturedPipe>
where
    R: Read,
{
    let mut retained = Vec::with_capacity(retained_limit.min(64 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = retained_limit.saturating_sub(retained.len());
        let keep = count.min(remaining);
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep != count;
    }
    Ok(CapturedPipe {
        bytes: retained,
        truncated,
        retained_limit,
    })
}

struct CaptureThread {
    stream_name: &'static str,
    join: Option<JoinHandle<io::Result<CapturedPipe>>>,
}

#[derive(Debug)]
struct CaptureFailure {
    stream: &'static str,
    detail: String,
}

impl CaptureThread {
    fn spawn<R>(stream_name: &'static str, reader: R, retained_limit: usize) -> Self
    where
        R: Read + Send + 'static,
    {
        Self {
            stream_name,
            join: Some(thread::spawn(move || drain_bounded(reader, retained_limit))),
        }
    }

    fn finish(mut self) -> Result<CapturedPipe, CaptureFailure> {
        let join = self.join.take().expect("capture thread consumed once");
        match join.join() {
            Ok(Ok(captured)) => Ok(captured),
            Ok(Err(error)) => Err(CaptureFailure {
                stream: self.stream_name,
                detail: sanitize_process_diagnostic(error.to_string().as_bytes()),
            }),
            Err(_) => Err(CaptureFailure {
                stream: self.stream_name,
                detail: "capture thread panicked".to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessReceipt {
    process_id: u32,
    status_code: Option<i32>,
    success: bool,
    terminate_requested: bool,
    kill_requested: bool,
    stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessRunError {
    Spawn {
        program: String,
        unavailable: bool,
        detail: String,
    },
    Wait {
        process_id: u32,
        detail: String,
    },
    PipeRead {
        receipt: ProcessReceipt,
        stream: &'static str,
        detail: String,
    },
    OutputTooLarge {
        receipt: ProcessReceipt,
        stream: &'static str,
        limit: usize,
    },
    Failed {
        receipt: ProcessReceipt,
    },
    Deadline {
        receipt: ProcessReceipt,
    },
    Stopped {
        reason: RequestedStop,
        receipt: ProcessReceipt,
    },
    ResourceStuck {
        process_id: u32,
        terminate_requested: bool,
        kill_requested: bool,
    },
}

impl fmt::Display for ProcessRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn {
                program, detail, ..
            } => {
                write!(f, "could not spawn {program}: {detail}")
            }
            Self::Wait { process_id, detail } => {
                write!(f, "could not reap process {process_id}: {detail}")
            }
            Self::PipeRead { stream, detail, .. } => {
                write!(f, "could not drain child {stream}: {detail}")
            }
            Self::OutputTooLarge { stream, limit, .. } => {
                write!(f, "child {stream} exceeded the {limit} byte limit")
            }
            Self::Failed { receipt } => write!(
                f,
                "process {} failed with status {:?}: {}",
                receipt.process_id, receipt.status_code, receipt.stderr
            ),
            Self::Deadline { receipt } => write!(
                f,
                "process {} exceeded its deadline: {}",
                receipt.process_id, receipt.stderr
            ),
            Self::Stopped { reason, receipt } => write!(
                f,
                "process {} stopped for {reason:?}: {}",
                receipt.process_id, receipt.stderr
            ),
            Self::ResourceStuck { process_id, .. } => write!(
                f,
                "process {process_id} did not exit after terminate and kill deadlines"
            ),
        }
    }
}

impl std::error::Error for ProcessRunError {}

struct RunningChild {
    child: Option<Child>,
    process_tree: ProcessTree,
    stdout: Option<CaptureThread>,
    stderr: Option<CaptureThread>,
}

impl RunningChild {
    fn spawn(
        program: &Path,
        args: &[OsString],
        stdout_limit: Option<usize>,
        controllable_stdin: bool,
    ) -> Result<Self, ProcessRunError> {
        let mut command = Command::new(program);
        command.args(args);
        command.stdin(if controllable_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(if stdout_limit.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stderr(Stdio::piped());

        // A dedicated process group lets Unix teardown signal the complete
        // FFmpeg tree. libx265 normally runs in-process, but this also covers
        // platform builds that launch a helper.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let mut child = command.spawn().map_err(|error| ProcessRunError::Spawn {
            program: program.to_string_lossy().into_owned(),
            unavailable: error.kind() == io::ErrorKind::NotFound,
            detail: sanitize_process_diagnostic(error.to_string().as_bytes()),
        })?;

        let process_tree = match ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessRunError::Spawn {
                    program: program.to_string_lossy().into_owned(),
                    unavailable: false,
                    detail: sanitize_process_diagnostic(error.to_string().as_bytes()),
                });
            }
        };

        let stdout = match (stdout_limit, child.stdout.take()) {
            (Some(limit), Some(pipe)) => Some(CaptureThread::spawn("stdout", pipe, limit)),
            _ => None,
        };
        let stderr = child
            .stderr
            .take()
            .map(|pipe| CaptureThread::spawn("stderr", pipe, MAX_CAPTURED_STDERR_BYTES));

        Ok(Self {
            child: Some(child),
            process_tree,
            stdout,
            stderr,
        })
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("live child").id()
    }

    fn write_stdin(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut stdin = self
            .child
            .as_mut()
            .expect("live child")
            .stdin
            .take()
            .ok_or_else(|| "child stdin is not available".to_string())?;
        stdin
            .write_all(bytes)
            .and_then(|()| stdin.flush())
            .map_err(|error| sanitize_process_diagnostic(error.to_string().as_bytes()))
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, ProcessRunError> {
        let process_id = self.id();
        self.child
            .as_mut()
            .expect("live child")
            .try_wait()
            .map_err(|error| ProcessRunError::Wait {
                process_id,
                detail: sanitize_process_diagnostic(error.to_string().as_bytes()),
            })
    }

    fn request_graceful_stop(&mut self) {
        if let Some(mut stdin) = self.child.as_mut().expect("live child").stdin.take() {
            // FFmpeg treats `q` on stdin as an orderly stop. Closing the pipe
            // afterwards ensures an executable that ignores it cannot keep
            // this adapter's handle alive.
            let _ = stdin.write_all(b"q\n");
            let _ = stdin.flush();
        }

        #[cfg(unix)]
        signal_process_group(self.id(), UNIX_SIGTERM);
    }

    fn force_stop(&mut self) {
        #[cfg(unix)]
        signal_process_group(self.id(), UNIX_SIGKILL);
        self.process_tree.force_stop();
        let _ = self.child.as_mut().expect("live child").kill();
    }

    fn wait_for_exit_until(
        &mut self,
        deadline: Instant,
        poll_interval: Duration,
    ) -> Result<Option<ExitStatus>, ProcessRunError> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    fn reap(
        mut self,
        status: ExitStatus,
        terminate_requested: bool,
        kill_requested: bool,
    ) -> Result<(ProcessReceipt, Vec<u8>), ProcessRunError> {
        let process_id = self.id();
        // `try_wait` has already reaped the OS process. Dropping Child is now
        // safe. Terminating any lingering process-tree members before joining
        // both drainers proves inherited pipe handles cannot outlive the ack.
        #[cfg(unix)]
        signal_process_group(process_id, UNIX_SIGKILL);
        self.process_tree.force_stop();
        self.child.take();
        let bare_receipt = ProcessReceipt {
            process_id,
            status_code: status.code(),
            success: status.success(),
            terminate_requested,
            kill_requested,
            stderr: String::new(),
        };
        let stdout = match self.stdout.take() {
            Some(capture) => capture
                .finish()
                .map_err(|failure| ProcessRunError::PipeRead {
                    receipt: bare_receipt.clone(),
                    stream: failure.stream,
                    detail: failure.detail,
                })?,
            None => CapturedPipe {
                bytes: Vec::new(),
                truncated: false,
                retained_limit: 0,
            },
        };
        let stderr = match self.stderr.take() {
            Some(capture) => capture
                .finish()
                .map_err(|failure| ProcessRunError::PipeRead {
                    receipt: bare_receipt.clone(),
                    stream: failure.stream,
                    detail: failure.detail,
                })?,
            None => CapturedPipe {
                bytes: Vec::new(),
                truncated: false,
                retained_limit: 0,
            },
        };
        let mut diagnostic = sanitize_process_diagnostic(&stderr.bytes);
        if stderr.truncated && !diagnostic.ends_with(PROCESS_TEXT_TRUNCATION_MARKER) {
            diagnostic.push_str(PROCESS_TEXT_TRUNCATION_MARKER);
        }
        let receipt = ProcessReceipt {
            stderr: diagnostic,
            ..bare_receipt
        };
        if stdout.truncated {
            return Err(ProcessRunError::OutputTooLarge {
                receipt,
                stream: "stdout",
                limit: stdout.retained_limit,
            });
        }
        Ok((receipt, stdout.bytes))
    }

    fn hand_off_stuck_reaper(mut self) {
        // The public call must not block forever after both stop deadlines.
        // Ownership is transferred, never duplicated: this thread remains the
        // sole Child owner until the OS eventually permits wait/reap.
        let _ = thread::Builder::new()
            .name("ylx-media-stuck-reaper".to_string())
            .spawn(move || {
                self.force_stop();
                let status = self.child.as_mut().and_then(|child| child.wait().ok());
                if let Some(status) = status {
                    let _ = self.reap(status, true, true);
                }
            });
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            #[cfg(unix)]
            signal_process_group(child.id(), UNIX_SIGKILL);
            self.process_tree.force_stop();
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(capture) = self.stdout.take() {
            let _ = capture.finish();
        }
        if let Some(capture) = self.stderr.take() {
            let _ = capture.finish();
        }
    }
}

#[cfg(not(windows))]
struct ProcessTree;

#[cfg(not(windows))]
impl ProcessTree {
    fn attach(_child: &Child) -> io::Result<Self> {
        Ok(Self)
    }

    fn force_stop(&self) {}
}

#[cfg(windows)]
struct ProcessTree {
    job: *mut std::ffi::c_void,
}

// SAFETY: a Windows job HANDLE is an opaque, kernel-managed value. This type
// owns exactly one reference, does not dereference the pointer, and only moves
// it to the unique fallback reaper thread before closing it there.
#[cfg(windows)]
unsafe impl Send for ProcessTree {}

#[cfg(windows)]
impl ProcessTree {
    fn attach(child: &Child) -> io::Result<Self> {
        use std::mem::{size_of, zeroed};
        use std::os::windows::io::AsRawHandle;

        let job = unsafe { windows_job::CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut limits: windows_job::JobObjectExtendedLimitInformation = unsafe { zeroed() };
        limits.basic_limit_information.limit_flags =
            windows_job::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            windows_job::SetInformationJobObject(
                job,
                windows_job::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                (&limits as *const windows_job::JobObjectExtendedLimitInformation).cast(),
                size_of::<windows_job::JobObjectExtendedLimitInformation>() as u32,
            )
        };
        if configured == 0 {
            let error = io::Error::last_os_error();
            unsafe {
                windows_job::CloseHandle(job);
            }
            return Err(error);
        }
        let assigned =
            unsafe { windows_job::AssignProcessToJobObject(job, child.as_raw_handle().cast()) };
        if assigned == 0 {
            let error = io::Error::last_os_error();
            unsafe {
                windows_job::CloseHandle(job);
            }
            return Err(error);
        }
        Ok(Self { job })
    }

    fn force_stop(&self) {
        unsafe {
            let _ = windows_job::TerminateJobObject(self.job, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_job::CloseHandle(self.job);
        }
    }
}

#[cfg(windows)]
#[allow(non_camel_case_types, non_snake_case)]
mod windows_job {
    use std::ffi::c_void;

    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    pub struct JobObjectBasicLimitInformation {
        pub per_process_user_time_limit: i64,
        pub per_job_user_time_limit: i64,
        pub limit_flags: u32,
        pub minimum_working_set_size: usize,
        pub maximum_working_set_size: usize,
        pub active_process_limit: u32,
        pub affinity: usize,
        pub priority_class: u32,
        pub scheduling_class: u32,
    }

    #[repr(C)]
    pub struct IoCounters {
        pub read_operation_count: u64,
        pub write_operation_count: u64,
        pub other_operation_count: u64,
        pub read_transfer_count: u64,
        pub write_transfer_count: u64,
        pub other_transfer_count: u64,
    }

    #[repr(C)]
    pub struct JobObjectExtendedLimitInformation {
        pub basic_limit_information: JobObjectBasicLimitInformation,
        pub io_info: IoCounters,
        pub process_memory_limit: usize,
        pub job_memory_limit: usize,
        pub peak_process_memory_used: usize,
        pub peak_job_memory_used: usize,
    }

    unsafe extern "system" {
        pub fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> *mut c_void;
        pub fn SetInformationJobObject(
            job: *mut c_void,
            information_class: i32,
            information: *const c_void,
            information_length: u32,
        ) -> i32;
        pub fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        pub fn TerminateJobObject(job: *mut c_void, exit_code: u32) -> i32;
        pub fn CloseHandle(object: *mut c_void) -> i32;
    }
}

#[cfg(unix)]
const UNIX_SIGTERM: i32 = 15;
#[cfg(unix)]
const UNIX_SIGKILL: i32 = 9;

#[cfg(unix)]
fn signal_process_group(process_id: u32, signal: i32) {
    unsafe extern "C" {
        fn kill(process: i32, signal: i32) -> i32;
    }

    if let Ok(group) = i32::try_from(process_id) {
        // SAFETY: `kill` receives scalar values only. The child was placed in
        // a new process group whose id equals its pid; a negative id addresses
        // that group without ever involving the shell.
        let _ = unsafe { kill(-group, signal) };
    }
}

#[derive(Debug)]
struct CompletedProcess {
    receipt: ProcessReceipt,
    stdout: Vec<u8>,
}

impl ProcessReceipt {
    fn into_core(self) -> ReapReceipt {
        ReapReceipt::new(
            self.process_id,
            self.status_code,
            self.terminate_requested,
            self.kill_requested,
        )
    }
}

impl RequestedStop {
    fn from_core(reason: ProcessStopReason) -> Self {
        match reason {
            ProcessStopReason::Pause => Self::Pause,
            ProcessStopReason::Cancel => Self::Cancel,
            ProcessStopReason::Shutdown => Self::Shutdown,
            ProcessStopReason::SourceUnavailable => Self::SourceUnavailable,
        }
    }

    fn into_core(self) -> ProcessStopReason {
        match self {
            Self::Pause => ProcessStopReason::Pause,
            Self::Cancel => ProcessStopReason::Cancel,
            Self::Shutdown => ProcessStopReason::Shutdown,
            Self::SourceUnavailable => ProcessStopReason::SourceUnavailable,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_process(
    program: &Path,
    args: &[OsString],
    stdout_limit: Option<usize>,
    deadline: Instant,
    terminate_grace: Duration,
    kill_grace: Duration,
    poll_interval: Duration,
    stop_requested: impl Fn() -> Option<RequestedStop>,
) -> Result<CompletedProcess, ProcessRunError> {
    run_process_with_input(
        program,
        args,
        stdout_limit,
        deadline,
        terminate_grace,
        kill_grace,
        poll_interval,
        None,
        stop_requested,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_process_with_input(
    program: &Path,
    args: &[OsString],
    stdout_limit: Option<usize>,
    deadline: Instant,
    terminate_grace: Duration,
    kill_grace: Duration,
    poll_interval: Duration,
    stdin: Option<&[u8]>,
    stop_requested: impl Fn() -> Option<RequestedStop>,
) -> Result<CompletedProcess, ProcessRunError> {
    let mut running = RunningChild::spawn(program, args, stdout_limit, true)?;

    if let Some(stdin) = stdin {
        if let Err(detail) = running.write_stdin(stdin) {
            let process_id = running.id();
            running.request_graceful_stop();
            let _ = running.wait_for_exit_until(Instant::now() + terminate_grace, poll_interval);
            return Err(ProcessRunError::Wait { process_id, detail });
        }
    }

    loop {
        if let Some(status) = running.try_wait()? {
            let (receipt, stdout) = running.reap(status, false, false)?;
            if !receipt.success {
                return Err(ProcessRunError::Failed { receipt });
            }
            return Ok(CompletedProcess { receipt, stdout });
        }

        let stop = stop_requested();
        let deadline_elapsed = Instant::now() >= deadline;
        if stop.is_some() || deadline_elapsed {
            running.request_graceful_stop();
            let terminate_deadline = Instant::now() + terminate_grace;
            let (status, kill_requested) =
                match running.wait_for_exit_until(terminate_deadline, poll_interval)? {
                    Some(status) => (status, false),
                    None => {
                        running.force_stop();
                        let kill_deadline = Instant::now() + kill_grace;
                        match running.wait_for_exit_until(kill_deadline, poll_interval)? {
                            Some(status) => (status, true),
                            None => {
                                let process_id = running.id();
                                running.hand_off_stuck_reaper();
                                return Err(ProcessRunError::ResourceStuck {
                                    process_id,
                                    terminate_requested: true,
                                    kill_requested: true,
                                });
                            }
                        }
                    }
                };
            let (receipt, _) = running.reap(status, true, kill_requested)?;
            return match stop {
                Some(reason) => Err(ProcessRunError::Stopped { reason, receipt }),
                None => Err(ProcessRunError::Deadline { receipt }),
            };
        }

        thread::sleep(poll_interval);
    }
}

#[derive(Debug, Clone, Copy)]
struct OperationTiming {
    deadline: Instant,
    terminate_grace: Duration,
    kill_grace: Duration,
}

fn operation_timing(control: &dyn MediaOperationControl) -> Result<OperationTiming, String> {
    let policy = control.deadline();
    if policy.timeout_ms() == 0 || policy.terminate_grace_ms() == 0 || policy.kill_grace_ms() == 0 {
        return Err("media process deadline and reap grace periods must be non-zero".to_string());
    }
    let timeout = Duration::from_millis(policy.timeout_ms());
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "media process deadline overflowed".to_string())?;
    Ok(OperationTiming {
        deadline,
        terminate_grace: Duration::from_millis(policy.terminate_grace_ms()),
        kill_grace: Duration::from_millis(policy.kill_grace_ms()),
    })
}

fn reap_report(receipts: &[ReapReceipt]) -> ProcessReapReport {
    if receipts.len() == 1 {
        ProcessReapReport::one(receipts[0].clone())
    } else {
        ProcessReapReport::new(receipts.to_vec())
            .expect("a process outcome always contains at least one reap receipt")
    }
}

fn reaped_or_not_spawned(receipts: &[ReapReceipt]) -> ProcessDisposition {
    if receipts.is_empty() {
        ProcessDisposition::NotSpawned
    } else {
        ProcessDisposition::reaped(reap_report(receipts))
    }
}

fn failure_without_process<T>(
    code: MediaProcessFailureCode,
    retryable: bool,
    detail: impl AsRef<str>,
) -> MediaProcessOutcome<T> {
    MediaProcessOutcome::failed(
        MediaProcessFailure::new(code, retryable, detail),
        ProcessDisposition::NotSpawned,
    )
}

fn failure_after_reap<T>(
    receipts: &[ReapReceipt],
    code: MediaProcessFailureCode,
    retryable: bool,
    detail: impl AsRef<str>,
) -> MediaProcessOutcome<T> {
    MediaProcessOutcome::failed(
        MediaProcessFailure::new(code, retryable, detail),
        ProcessDisposition::reaped(reap_report(receipts)),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_core_process<T>(
    program: &Path,
    args: &[OsString],
    stdout_limit: Option<usize>,
    timing: OperationTiming,
    poll_interval: Duration,
    control: &dyn MediaOperationControl,
    receipts: &mut Vec<ReapReceipt>,
    process_failure_code: MediaProcessFailureCode,
    process_failure_retryable: bool,
) -> Result<CompletedProcess, MediaProcessOutcome<T>> {
    if let Some(reason) = control.stop_requested() {
        return Err(if receipts.is_empty() {
            failure_without_process(
                MediaProcessFailureCode::Internal,
                true,
                format!("{reason:?} was requested before a media process was spawned"),
            )
        } else {
            MediaProcessOutcome::stopped(reason, reap_report(receipts))
        });
    }
    if Instant::now() >= timing.deadline {
        return Err(MediaProcessOutcome::failed(
            MediaProcessFailure::new(
                MediaProcessFailureCode::DeadlineExceeded,
                true,
                "media operation deadline elapsed before the next process was spawned",
            ),
            reaped_or_not_spawned(receipts),
        ));
    }
    match run_process(
        program,
        args,
        stdout_limit,
        timing.deadline,
        timing.terminate_grace,
        timing.kill_grace,
        poll_interval,
        || control.stop_requested().map(RequestedStop::from_core),
    ) {
        Ok(completed) => {
            receipts.push(completed.receipt.clone().into_core());
            Ok(completed)
        }
        Err(ProcessRunError::Stopped { reason, receipt }) => {
            receipts.push(receipt.into_core());
            Err(MediaProcessOutcome::stopped(
                reason.into_core(),
                reap_report(receipts),
            ))
        }
        Err(ProcessRunError::Deadline { receipt }) => {
            receipts.push(receipt.into_core());
            Err(MediaProcessOutcome::failed(
                MediaProcessFailure::new(
                    MediaProcessFailureCode::DeadlineExceeded,
                    true,
                    "media process exceeded its operation deadline",
                ),
                ProcessDisposition::reaped(reap_report(receipts)),
            ))
        }
        Err(ProcessRunError::Failed { receipt }) => {
            let detail = format!(
                "media process exited with status {:?}: {}",
                receipt.status_code, receipt.stderr
            );
            receipts.push(receipt.into_core());
            Err(MediaProcessOutcome::failed(
                MediaProcessFailure::new(process_failure_code, process_failure_retryable, detail),
                ProcessDisposition::reaped(reap_report(receipts)),
            ))
        }
        Err(ProcessRunError::Spawn {
            unavailable,
            detail,
            ..
        }) => Err(MediaProcessOutcome::failed(
            MediaProcessFailure::new(
                if unavailable {
                    MediaProcessFailureCode::ExecutableUnavailable
                } else {
                    MediaProcessFailureCode::SpawnRejected
                },
                false,
                detail,
            ),
            reaped_or_not_spawned(receipts),
        )),
        Err(ProcessRunError::PipeRead {
            receipt,
            stream,
            detail,
        }) => {
            receipts.push(receipt.into_core());
            Err(MediaProcessOutcome::failed(
                MediaProcessFailure::new(
                    MediaProcessFailureCode::Io,
                    true,
                    format!("failed draining process {stream}: {detail}"),
                ),
                ProcessDisposition::reaped(reap_report(receipts)),
            ))
        }
        Err(ProcessRunError::OutputTooLarge {
            receipt,
            stream,
            limit,
        }) => {
            receipts.push(receipt.into_core());
            Err(MediaProcessOutcome::failed(
                MediaProcessFailure::new(
                    MediaProcessFailureCode::InvalidOutput,
                    false,
                    format!("process {stream} exceeded the {limit} byte limit"),
                ),
                ProcessDisposition::reaped(reap_report(receipts)),
            ))
        }
        Err(ProcessRunError::ResourceStuck {
            process_id,
            terminate_requested,
            kill_requested,
        }) => Err(MediaProcessOutcome::failed(
            MediaProcessFailure::resource_stuck(process_id),
            ProcessDisposition::ResourceStuck {
                process_id,
                terminate_requested,
                kill_requested,
            },
        )),
        Err(ProcessRunError::Wait { process_id, detail }) => Err(MediaProcessOutcome::failed(
            MediaProcessFailure::new(MediaProcessFailureCode::Internal, true, detail),
            ProcessDisposition::ResourceStuck {
                process_id,
                terminate_requested: false,
                kill_requested: false,
            },
        )),
    }
}

fn inspect_encoder_build(
    config: &FfmpegNormalizerConfig,
) -> Result<FfmpegBuildObservation, FfmpegInitError> {
    let deadline = Instant::now()
        .checked_add(config.capability_deadline)
        .ok_or_else(|| {
            FfmpegInitError::Capability("FFmpeg capability deadline overflowed".to_string())
        })?;
    let version = run_process(
        &config.ffmpeg_path,
        &[os("-hide_banner"), os("-version")],
        Some(MAX_PROBE_JSON_BYTES),
        deadline,
        config.stop_grace,
        config.stop_grace,
        config.poll_interval,
        || None,
    )
    .map_err(|error| FfmpegInitError::Capability(error.to_string()))?;
    let encoder = run_process(
        &config.ffmpeg_path,
        &[os("-hide_banner"), os("-help"), os("encoder=libx265")],
        Some(MAX_PROBE_JSON_BYTES),
        deadline,
        config.stop_grace,
        config.stop_grace,
        config.poll_interval,
        || None,
    )
    .map_err(|error| FfmpegInitError::Capability(error.to_string()))?;

    let encoder_help = String::from_utf8_lossy(&encoder.stdout);
    if !encoder_help.contains("libx265") {
        return Err(FfmpegInitError::Capability(
            "configured FFmpeg build does not expose encoder libx265".to_string(),
        ));
    }
    let version_text = String::from_utf8_lossy(&version.stdout);
    let raw_version_line = version_text
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| {
            FfmpegInitError::Capability(
                "FFmpeg version output did not contain a version line".to_string(),
            )
        })?;
    let version_line = sanitize_bounded_text(raw_version_line.as_bytes(), 256);

    let mut fingerprint = Sha256::new();
    fingerprint.update(b"ylx.ffmpeg.libx265-build.v1\0");
    fingerprint.update(&version.stdout);
    fingerprint.update(b"\0encoder-help\0");
    fingerprint.update(&encoder.stdout);
    Ok(FfmpegBuildObservation {
        implementation: "ffmpeg/libx265".to_string(),
        version_line,
        build_fingerprint: format!("sha256:{:x}", fingerprint.finalize()),
    })
}

fn inspect_quality_evidence_capability(
    config: &FfmpegNormalizerConfig,
) -> FfmpegQualityEvidenceCapability {
    let deadline = match Instant::now().checked_add(config.capability_deadline) {
        Some(deadline) => deadline,
        None => {
            return FfmpegQualityEvidenceCapability::MetricsFiltersUnavailable {
                detail: "FFmpeg quality-filter capability deadline overflowed".to_string(),
            }
        }
    };
    let filters = match run_process(
        &config.ffmpeg_path,
        &[os("-hide_banner"), os("-filters")],
        Some(MAX_PROBE_JSON_BYTES),
        deadline,
        config.stop_grace,
        config.stop_grace,
        config.poll_interval,
        || None,
    ) {
        Ok(filters) => filters,
        Err(error) => {
            return FfmpegQualityEvidenceCapability::MetricsFiltersUnavailable {
                detail: sanitize_process_diagnostic(error.to_string().as_bytes()),
            }
        }
    };
    let filter_list = String::from_utf8_lossy(&filters.stdout);
    let missing = ["libvmaf", "ssim"]
        .into_iter()
        .filter(|expected| {
            !filter_list
                .lines()
                .any(|line| line.split_whitespace().any(|name| name == *expected))
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        FfmpegQualityEvidenceCapability::MetricsFiltersAvailableButDomainEvidenceUnavailable
    } else {
        FfmpegQualityEvidenceCapability::MetricsFiltersUnavailable {
            detail: format!(
                "configured FFmpeg build does not expose required quality filter(s): {}",
                missing.join(", ")
            ),
        }
    }
}

impl MediaProbe for FfmpegMediaNormalizer {
    fn probe(
        &self,
        request: &ProbeRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<ProbeReport> {
        let timing = match operation_timing(control) {
            Ok(timing) => timing,
            Err(detail) => {
                return failure_without_process(MediaProcessFailureCode::Internal, false, detail)
            }
        };
        let raw_frame_rate = match raw_probe_frame_rate(request.input()) {
            Ok(frame_rate) => frame_rate,
            Err(detail) => {
                return failure_without_process(
                    MediaProcessFailureCode::ProbeRejected,
                    false,
                    detail,
                )
            }
        };
        let source_kind = request.input().kind();
        let source_artifacts = request.input().artifacts();
        if source_artifacts.is_empty() {
            return failure_without_process(
                MediaProcessFailureCode::ProbeRejected,
                false,
                "normalization input contains no source artifacts",
            );
        }
        let mut receipts = Vec::new();
        let mut artifacts = Vec::new();
        for artifact in source_artifacts {
            if !artifact.local_path().is_absolute() {
                let detail = format!(
                    "resolved source artifact {} does not use an absolute local path",
                    artifact.id()
                );
                return if receipts.is_empty() {
                    failure_without_process(MediaProcessFailureCode::ProbeRejected, false, detail)
                } else {
                    failure_after_reap(
                        &receipts,
                        MediaProcessFailureCode::ProbeRejected,
                        false,
                        detail,
                    )
                };
            }
            if let Err(detail) = ensure_source_artifact_file(artifact) {
                return if receipts.is_empty() {
                    failure_without_process(MediaProcessFailureCode::ProbeRejected, false, detail)
                } else {
                    failure_after_reap(
                        &receipts,
                        MediaProcessFailureCode::ProbeRejected,
                        false,
                        detail,
                    )
                };
            }
            let args = probe_args(artifact.local_path(), false, raw_frame_rate);
            let completed = match run_core_process::<ProbeReport>(
                &self.config.ffprobe_path,
                &args,
                Some(MAX_PROBE_JSON_BYTES),
                timing,
                self.config.poll_interval,
                control,
                &mut receipts,
                MediaProcessFailureCode::ProbeRejected,
                false,
            ) {
                Ok(completed) => completed,
                Err(outcome) => return outcome,
            };
            let document = match parse_probe_document(&completed.stdout) {
                Ok(document) => document,
                Err(detail) => {
                    return failure_after_reap(
                        &receipts,
                        MediaProcessFailureCode::ProbeRejected,
                        false,
                        detail,
                    )
                }
            };
            let probed = match probed_source_artifact(artifact.id(), source_kind, &document) {
                Ok(probed) => probed,
                Err(detail) => {
                    return failure_after_reap(
                        &receipts,
                        MediaProcessFailureCode::ProbeRejected,
                        false,
                        detail,
                    )
                }
            };
            artifacts.push(probed);
        }
        let report = match ProbeReport::new(artifacts) {
            Ok(report) => report,
            Err(error) => {
                if receipts.is_empty() {
                    return failure_without_process(
                        MediaProcessFailureCode::ProbeRejected,
                        false,
                        error.to_string(),
                    );
                }
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::ProbeRejected,
                    false,
                    error.to_string(),
                );
            }
        };
        MediaProcessOutcome::completed(report, reap_report(&receipts))
    }

    fn validate_segment_pair(
        &self,
        request: &SegmentValidationRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<SegmentValidationReport> {
        self.validate_pair(request, control)
    }
}

impl SegmentQualityAnalyzer for FfmpegMediaNormalizer {
    fn analyze_segment_pair(
        &self,
        request: &EncodeSegmentPairRequest,
        encoded: &EncodedSegmentPair,
        _control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<PairQualityEvidence> {
        let capability_detail = match self.quality_evidence_capability() {
            FfmpegQualityEvidenceCapability::MetricsFiltersUnavailable { detail } => format!(
                "FFmpeg cannot measure VMAF/SSIM because its quality filters are unavailable: {detail}"
            ),
            FfmpegQualityEvidenceCapability::MetricsFiltersAvailableButDomainEvidenceUnavailable => {
                "FFmpeg exposes libvmaf and ssim, but no stereo/CV domain evaluator or durable quality-report archive is configured".to_string()
            }
        };
        failure_without_process(
            MediaProcessFailureCode::ValidationRejected,
            false,
            format!(
                "quality evidence is unavailable for segment {} ({}, {}): {capability_detail}; refusing to manufacture VMAF/SSIM/domain evidence",
                request.pair_plan().segment_index(),
                encoded.left_partial_path().display(),
                encoded.right_partial_path().display()
            ),
        )
    }
}

impl MediaEncoder for FfmpegMediaNormalizer {
    fn encoder_build(&self) -> EncoderBuild {
        self.encoder_build.clone()
    }

    fn encode_segment_pair(
        &self,
        request: &EncodeSegmentPairRequest,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<EncodedSegmentPair> {
        if request.encoder_build() != &self.encoder_build {
            return failure_without_process(
                MediaProcessFailureCode::EncodeRejected,
                false,
                "encode request targets a different encoder build fingerprint",
            );
        }
        let timing = match operation_timing(control) {
            Ok(timing) => timing,
            Err(detail) => {
                return failure_without_process(MediaProcessFailureCode::Internal, false, detail)
            }
        };
        let command_request = match EncodeCommandRequest::from_core(request) {
            Ok(request) => request,
            Err(detail) => {
                return failure_without_process(
                    MediaProcessFailureCode::EncodeRejected,
                    false,
                    detail,
                )
            }
        };
        if let Err(detail) =
            prepare_partial_pair(request.left_partial_path(), request.right_partial_path())
        {
            return failure_without_process(MediaProcessFailureCode::Io, true, detail);
        }
        let args = match build_encode_args(&command_request) {
            Ok(args) => args,
            Err(detail) => {
                return failure_without_process(
                    MediaProcessFailureCode::EncodeRejected,
                    false,
                    detail,
                )
            }
        };

        let started = Instant::now();
        let mut receipts = Vec::new();
        let completed = match run_core_process::<EncodedSegmentPair>(
            &self.config.ffmpeg_path,
            &args,
            Some(1024 * 1024),
            timing,
            self.config.poll_interval,
            control,
            &mut receipts,
            MediaProcessFailureCode::EncodeRejected,
            true,
        ) {
            Ok(completed) => completed,
            Err(outcome) => return outcome,
        };
        let actual_frames = match decoded_frame_count(&completed.stdout) {
            Ok(frames) => frames,
            Err(detail) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::InvalidOutput,
                    false,
                    detail,
                )
            }
        };
        if actual_frames != request.pair_plan().frame_count() {
            return failure_after_reap(
                &receipts,
                MediaProcessFailureCode::InvalidOutput,
                false,
                format!(
                    "encoder reported {actual_frames} frames, expected {}",
                    request.pair_plan().frame_count()
                ),
            );
        }
        for path in [request.left_partial_path(), request.right_partial_path()] {
            if let Err(detail) = ensure_closed_nonempty_regular_file(path) {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::InvalidOutput,
                    false,
                    detail,
                );
            }
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let encoding_fps_milli = request
            .pair_plan()
            .frame_count()
            .saturating_mul(1_000_000)
            .checked_div(elapsed_ms)
            .unwrap_or(0);
        let statistics = match EncoderStatistics::new(
            actual_frames,
            request.pair_plan().duration_ticks(),
            elapsed_ms,
            encoding_fps_milli,
            None,
        ) {
            Ok(statistics) => statistics,
            Err(error) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::Internal,
                    false,
                    error.to_string(),
                )
            }
        };
        let encoded = match EncodedSegmentPair::from_request(request, statistics) {
            Ok(encoded) => encoded,
            Err(error) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::Internal,
                    false,
                    error.to_string(),
                )
            }
        };
        MediaProcessOutcome::completed(encoded, reap_report(&receipts))
    }
}

fn raw_probe_frame_rate(input: &NormalizationInput) -> Result<Option<FrameRate>, String> {
    match input {
        NormalizationInput::RawCaptureV2 { frame_evidence, .. } => {
            FrameRate::try_from(frame_evidence.declared_source_fps()).map(Some)
        }
        NormalizationInput::LegacyMjpegSessionV5 { .. }
        | NormalizationInput::ApplianceSpoolV6 { .. }
        | NormalizationInput::CompleteUnpublishedV6 { .. }
        | NormalizationInput::PairedH264PublicationV1 { .. }
        | NormalizationInput::UnsignedPairedH264PublicationV1 { .. }
        | NormalizationInput::UnsignedMjpegPublicationV1 { .. } => Ok(None),
    }
}

fn sanitize_bounded_text(raw: &[u8], maximum_bytes: usize) -> String {
    let mut value = String::new();
    for ch in String::from_utf8_lossy(raw).chars() {
        let ch = if ch.is_control()
            || matches!(
                ch,
                '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{feff}'
            ) {
            '\u{fffd}'
        } else {
            ch
        };
        if value.len() + ch.len_utf8() > maximum_bytes {
            break;
        }
        value.push(ch);
    }
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameRate {
    numerator: u32,
    denominator: u32,
}

impl FrameRate {
    fn checked(numerator: u32, denominator: u32) -> Result<Self, String> {
        if numerator == 0 || denominator == 0 {
            return Err("frame rate numerator and denominator must be positive".to_string());
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    fn ffmpeg_value(self) -> String {
        format!("{}/{}", self.numerator, self.denominator)
    }

    fn frames_for_seconds(self, seconds: u32) -> Result<u32, String> {
        let scaled = u64::from(self.numerator)
            .checked_mul(u64::from(seconds))
            .ok_or_else(|| "frame-rate multiplication overflowed".to_string())?;
        if scaled % u64::from(self.denominator) != 0 {
            return Err(format!(
                "{seconds}s is not an integral frame boundary at {}",
                self.ffmpeg_value()
            ));
        }
        u32::try_from(scaled / u64::from(self.denominator))
            .map_err(|_| "frame count does not fit in u32".to_string())
    }

    fn ticks_per_frame(self, time_base_denominator: u32) -> Result<u32, String> {
        let ticks = u64::from(time_base_denominator)
            .checked_mul(u64::from(self.denominator))
            .ok_or_else(|| "time-base multiplication overflowed".to_string())?;
        if ticks % u64::from(self.numerator) != 0 {
            return Err(format!(
                "1/{time_base_denominator} cannot represent {} exactly",
                self.ffmpeg_value()
            ));
        }
        u32::try_from(ticks / u64::from(self.numerator))
            .map_err(|_| "ticks per frame do not fit in u32".to_string())
    }
}

impl TryFrom<Rational> for FrameRate {
    type Error = String;

    fn try_from(value: Rational) -> Result<Self, Self::Error> {
        Self::checked(value.numerator(), value.denominator())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceSlice {
    path: PathBuf,
    start_frame: u64,
    end_frame_exclusive: u64,
    raw_mjpeg: bool,
}

impl SourceSlice {
    fn frame_count(&self) -> Result<u64, String> {
        self.end_frame_exclusive
            .checked_sub(self.start_frame)
            .filter(|count| *count > 0)
            .ok_or_else(|| "source slice must contain at least one frame".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SegmentInput {
    RawStereoMjpeg(Vec<SourceSlice>),
    LegacyV5StereoMjpeg(Vec<SourceSlice>),
    SpoolV6StereoMjpeg(Vec<SourceSlice>),
    PublishedStereoPairs {
        left: Vec<SourceSlice>,
        right: Vec<SourceSlice>,
    },
}

#[derive(Debug, Clone)]
struct ExactEncodingProfile {
    revision: String,
    encoder: String,
    codec_profile: String,
    pixel_format: String,
    sample_entry: String,
    preset: String,
    crf: u8,
    time_base_denominator: u32,
    gop_seconds: u32,
    segment_seconds: u32,
}

impl ExactEncodingProfile {
    fn validate(&self, frame_rate: FrameRate) -> Result<(u32, u32), String> {
        if self.revision.trim().is_empty() {
            return Err("profile revision is required".to_string());
        }
        if self.encoder != "libx265" {
            return Err(format!(
                "profile {} requires unsupported encoder {}",
                self.revision, self.encoder
            ));
        }
        if self.codec_profile != "main" {
            return Err("the production profile must require HEVC Main".to_string());
        }
        if self.pixel_format != "yuv420p" {
            return Err("the production profile must require yuv420p".to_string());
        }
        if self.sample_entry != "hvc1" {
            return Err("the production profile must require the hvc1 sample entry".to_string());
        }
        if self.time_base_denominator != 90_000 {
            return Err("the production profile must use a 1/90000 time base".to_string());
        }
        if self.gop_seconds != 2 {
            return Err("the production profile must use a fixed two-second GOP".to_string());
        }
        if self.segment_seconds != 30 {
            return Err("the production profile must use thirty-second segments".to_string());
        }
        if self.crf > 51 {
            return Err("x265 CRF must be in the inclusive range 0..=51".to_string());
        }
        require_encoder_token("preset", &self.preset)?;
        let gop_frames = frame_rate.frames_for_seconds(self.gop_seconds)?;
        let segment_frames = frame_rate.frames_for_seconds(self.segment_seconds)?;
        let _ = frame_rate.ticks_per_frame(self.time_base_denominator)?;
        Ok((gop_frames, segment_frames))
    }

    fn from_core(profile: &NormalizationProfile) -> Result<Self, String> {
        if profile.codec() != VideoCodec::Hevc
            || profile.codec_profile() != HevcProfile::Main
            || profile.pixel_format() != PixelFormat::Yuv420p
            || profile.container() != ContainerFormat::Mp4
            || profile.sample_entry() != SampleEntry::Hvc1
            || profile.time_base() != Rational::new(1, 90_000).map_err(|e| e.to_string())?
            || !profile.closed_gop()
            || profile.scene_cut_keyframes()
            || profile.encoder_compatibility_class()
                != &EncoderCompatibilityClass::x265_software_v1()
        {
            return Err(format!(
                "profile {} is not the supported x265 HEVC Main normalization contract",
                profile.profile_revision()
            ));
        }
        Ok(Self {
            revision: profile.profile_revision().to_string(),
            encoder: "libx265".to_string(),
            codec_profile: "main".to_string(),
            pixel_format: "yuv420p".to_string(),
            sample_entry: "hvc1".to_string(),
            preset: profile.preset().to_string(),
            crf: profile.crf(),
            time_base_denominator: profile.time_base().denominator(),
            gop_seconds: profile.gop_seconds(),
            segment_seconds: profile.segment_seconds(),
        })
    }
}

fn require_encoder_token(name: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(format!("profile {name} contains unsupported characters"))
    }
}

#[derive(Debug, Clone)]
struct EncodeCommandRequest {
    input: SegmentInput,
    frame_rate: FrameRate,
    eye_width: u32,
    eye_height: u32,
    expected_frames: u64,
    profile: ExactEncodingProfile,
    left_partial: PathBuf,
    right_partial: PathBuf,
}

impl EncodeCommandRequest {
    fn from_core(request: &EncodeSegmentPairRequest) -> Result<Self, String> {
        let plan = request.pair_plan();
        let frame_rate = FrameRate::try_from(plan.source_fps())?;
        let dimensions = plan.eye_dimensions();
        let input = segment_input_from_core(request.input(), plan)?;
        Ok(Self {
            input,
            frame_rate,
            eye_width: dimensions.width(),
            eye_height: dimensions.height(),
            expected_frames: plan.frame_count(),
            profile: ExactEncodingProfile::from_core(request.profile())?,
            left_partial: request.left_partial_path().to_path_buf(),
            right_partial: request.right_partial_path().to_path_buf(),
        })
    }
}

fn segment_input_from_core(
    input: &NormalizationInput,
    plan: &ylx_transfer_core::normalization::SegmentPairPlan,
) -> Result<SegmentInput, String> {
    match input.kind() {
        SourceMediaKind::RawCaptureV2
        | SourceMediaKind::LegacyMjpegSessionV5
        | SourceMediaKind::ApplianceSpoolV6
        | SourceMediaKind::UnsignedMjpegPublicationV1 => {
            if plan.left().slices() != plan.right().slices() {
                return Err(
                    "side-by-side eye plans must reference identical frame slices".to_string(),
                );
            }
            validate_stereo_crops(plan)?;
            let raw_mjpeg = input.kind() == SourceMediaKind::RawCaptureV2;
            let slices = plan
                .left()
                .slices()
                .iter()
                .map(|slice| source_slice_from_core(input, slice, raw_mjpeg))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(match input.kind() {
                SourceMediaKind::RawCaptureV2 => SegmentInput::RawStereoMjpeg(slices),
                SourceMediaKind::LegacyMjpegSessionV5 => SegmentInput::LegacyV5StereoMjpeg(slices),
                SourceMediaKind::ApplianceSpoolV6 | SourceMediaKind::UnsignedMjpegPublicationV1 => {
                    SegmentInput::SpoolV6StereoMjpeg(slices)
                }
                SourceMediaKind::CompleteUnpublishedV6
                | SourceMediaKind::PairedH264PublicationV1
                | SourceMediaKind::UnsignedPairedH264PublicationV1 => {
                    unreachable!("matched above")
                }
            })
        }
        SourceMediaKind::CompleteUnpublishedV6
        | SourceMediaKind::PairedH264PublicationV1
        | SourceMediaKind::UnsignedPairedH264PublicationV1 => {
            if plan.left().crop().is_some() || plan.right().crop().is_some() {
                return Err("paired source eye plans must not contain crop operations".to_string());
            }
            let left = plan
                .left()
                .slices()
                .iter()
                .map(|slice| source_slice_from_core(input, slice, false))
                .collect::<Result<Vec<_>, _>>()?;
            let right = plan
                .right()
                .slices()
                .iter()
                .map(|slice| source_slice_from_core(input, slice, false))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SegmentInput::PublishedStereoPairs { left, right })
        }
    }
}

fn source_slice_from_core(
    input: &NormalizationInput,
    slice: &FrameSlice,
    raw_mjpeg: bool,
) -> Result<SourceSlice, String> {
    let artifact = input
        .artifacts()
        .into_iter()
        .find(|artifact| artifact.id() == slice.artifact_id())
        .ok_or_else(|| {
            format!(
                "frame plan references unknown source artifact {}",
                slice.artifact_id()
            )
        })?;
    if !artifact.local_path().is_absolute() {
        return Err(format!(
            "resolved source artifact {} does not use an absolute local path",
            artifact.id()
        ));
    }
    ensure_source_artifact_file(artifact)?;
    let end_frame_exclusive = slice
        .first_frame_in_artifact()
        .checked_add(slice.frame_count())
        .ok_or_else(|| "source frame slice overflowed".to_string())?;
    Ok(SourceSlice {
        path: artifact.local_path().to_path_buf(),
        start_frame: slice.first_frame_in_artifact(),
        end_frame_exclusive,
        raw_mjpeg,
    })
}

fn ensure_source_artifact_file(artifact: &ResolvedSourceArtifact) -> Result<(), String> {
    let mut file = open_read_only_no_follow(artifact.local_path()).map_err(|error| {
        format!(
            "could not open source artifact {} without following links: {}",
            artifact.id(),
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "could not inspect opened source artifact {}: {}",
            artifact.id(),
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "source artifact {} is not a regular file",
            artifact.id()
        ));
    }
    if metadata.len() != artifact.expected_size_bytes() {
        return Err(format!(
            "source artifact {} size {} does not match the sealed claim {}",
            artifact.id(),
            metadata.len(),
            artifact.expected_size_bytes()
        ));
    }

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            format!(
                "could not hash source artifact {}: {}",
                artifact.id(),
                sanitize_process_diagnostic(error.to_string().as_bytes())
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| format!("source artifact {} size overflowed", artifact.id()))?;
    }
    if total != artifact.expected_size_bytes() {
        return Err(format!(
            "source artifact {} changed size while being hashed: expected {}, got {}",
            artifact.id(),
            artifact.expected_size_bytes(),
            total
        ));
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != artifact.expected_sha256().as_str() {
        return Err(format!(
            "source artifact {} digest does not match the sealed claim",
            artifact.id()
        ));
    }
    Ok(())
}

fn open_read_only_no_follow(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        const O_NOFOLLOW: i32 = 0x0002_0000;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        const O_NOFOLLOW: i32 = 0x0000_0100;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )))]
        const O_NOFOLLOW: i32 = 0;

        options.custom_flags(O_NOFOLLOW);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    options.open(path)
}

fn validate_stereo_crops(
    plan: &ylx_transfer_core::normalization::SegmentPairPlan,
) -> Result<(), String> {
    let dimensions = plan.eye_dimensions();
    let left = plan
        .left()
        .crop()
        .ok_or_else(|| "side-by-side left eye plan is missing its crop".to_string())?;
    let right = plan
        .right()
        .crop()
        .ok_or_else(|| "side-by-side right eye plan is missing its crop".to_string())?;
    let valid_left = left.x() == 0
        && left.y() == 0
        && left.width() == dimensions.width()
        && left.height() == dimensions.height();
    let valid_right = right.x() == dimensions.width()
        && right.y() == 0
        && right.width() == dimensions.width()
        && right.height() == dimensions.height();
    if valid_left && valid_right {
        Ok(())
    } else {
        Err("side-by-side crop rectangles do not match the frozen eye geometry".to_string())
    }
}

fn build_encode_args(request: &EncodeCommandRequest) -> Result<Vec<OsString>, String> {
    let (gop_frames, segment_frames) = request.profile.validate(request.frame_rate)?;
    if request.eye_width == 0 || request.eye_height == 0 {
        return Err("eye dimensions must be positive".to_string());
    }
    if request.expected_frames == 0 || request.expected_frames > u64::from(segment_frames) {
        return Err(format!(
            "segment frame count {} is outside 1..={segment_frames}",
            request.expected_frames
        ));
    }
    if request.left_partial == request.right_partial {
        return Err("left and right partial paths must be distinct".to_string());
    }

    let mut args = vec![
        OsString::from("-hide_banner"),
        OsString::from("-loglevel"),
        OsString::from("warning"),
        OsString::from("-nostats"),
        OsString::from("-progress"),
        OsString::from("pipe:1"),
        OsString::from("-xerror"),
        OsString::from("-y"),
    ];

    let filter = match &request.input {
        SegmentInput::RawStereoMjpeg(slices)
        | SegmentInput::LegacyV5StereoMjpeg(slices)
        | SegmentInput::SpoolV6StereoMjpeg(slices) => {
            append_inputs(&mut args, slices, request.frame_rate)?;
            ensure_expected_frames(slices, request.expected_frames)?;
            side_by_side_filter(slices, request)
        }
        SegmentInput::PublishedStereoPairs { left, right } => {
            if left.len() != right.len() || left.is_empty() {
                return Err(
                    "published stereo plan requires matched non-empty eye slices".to_string(),
                );
            }
            append_stereo_pair_inputs(&mut args, left, right, request.frame_rate)?;
            ensure_expected_frames(left, request.expected_frames)?;
            ensure_expected_frames(right, request.expected_frames)?;
            stereo_pair_filter(left, right, request.frame_rate)
        }
    }?;

    args.extend([OsString::from("-filter_complex"), OsString::from(filter)]);
    append_output(
        &mut args,
        "[left_out]",
        &request.left_partial,
        &request.profile,
        gop_frames,
    );
    append_output(
        &mut args,
        "[right_out]",
        &request.right_partial,
        &request.profile,
        gop_frames,
    );
    Ok(args)
}

fn append_inputs(
    args: &mut Vec<OsString>,
    slices: &[SourceSlice],
    frame_rate: FrameRate,
) -> Result<(), String> {
    if slices.is_empty() {
        return Err("segment plan requires at least one source slice".to_string());
    }
    for slice in slices {
        let _ = slice.frame_count()?;
        if slice.raw_mjpeg {
            args.extend([
                OsString::from("-f"),
                OsString::from("mjpeg"),
                OsString::from("-framerate"),
                OsString::from(frame_rate.ffmpeg_value()),
            ]);
        }
        args.push(OsString::from("-i"));
        args.push(slice.path.as_os_str().to_owned());
    }
    Ok(())
}

fn append_stereo_pair_inputs(
    args: &mut Vec<OsString>,
    left: &[SourceSlice],
    right: &[SourceSlice],
    frame_rate: FrameRate,
) -> Result<(), String> {
    for (left_slice, right_slice) in left.iter().zip(right) {
        append_inputs(args, std::slice::from_ref(left_slice), frame_rate)?;
        append_inputs(args, std::slice::from_ref(right_slice), frame_rate)?;
    }
    Ok(())
}

fn ensure_expected_frames(slices: &[SourceSlice], expected: u64) -> Result<(), String> {
    let mut total = 0_u64;
    for slice in slices {
        total = total
            .checked_add(slice.frame_count()?)
            .ok_or_else(|| "segment frame count overflowed".to_string())?;
    }
    if total == expected {
        Ok(())
    } else {
        Err(format!(
            "source slices contain {total} frames but the frozen plan requires {expected}"
        ))
    }
}

fn trim_filter(input: usize, output: &str, slice: &SourceSlice, rate: FrameRate) -> String {
    format!(
        "[{input}:v:0]trim=start_frame={}:end_frame={},setpts=N*{}/({}*TB)[{output}]",
        slice.start_frame, slice.end_frame_exclusive, rate.denominator, rate.numerator
    )
}

fn concat_filter(labels: &[String], output: &str) -> String {
    if labels.len() == 1 {
        format!("[{}]null[{output}]", labels[0])
    } else {
        let inputs = labels
            .iter()
            .map(|label| format!("[{label}]"))
            .collect::<String>();
        format!("{inputs}concat=n={}:v=1:a=0[{output}]", labels.len())
    }
}

fn side_by_side_filter(
    slices: &[SourceSlice],
    request: &EncodeCommandRequest,
) -> Result<String, String> {
    let _stereo_width = request
        .eye_width
        .checked_mul(2)
        .ok_or_else(|| "stereo width overflowed".to_string())?;
    let mut filters = Vec::new();
    let mut labels = Vec::new();
    for (index, slice) in slices.iter().enumerate() {
        let label = format!("stereo_part_{index}");
        filters.push(trim_filter(index, &label, slice, request.frame_rate));
        labels.push(label);
    }
    filters.push(concat_filter(&labels, "stereo_joined"));
    filters.push("[stereo_joined]split=2[stereo_left][stereo_right]".to_string());
    filters.push(format!(
        "[stereo_left]crop={}:{}:0:0[left_out]",
        request.eye_width, request.eye_height
    ));
    filters.push(format!(
        "[stereo_right]crop={}:{}:{}:0[right_out]",
        request.eye_width, request.eye_height, request.eye_width
    ));
    Ok(filters.join(";"))
}

fn stereo_pair_filter(
    left: &[SourceSlice],
    right: &[SourceSlice],
    frame_rate: FrameRate,
) -> Result<String, String> {
    let mut filters = Vec::new();
    let mut left_labels = Vec::new();
    let mut right_labels = Vec::new();
    for (index, (left_slice, right_slice)) in left.iter().zip(right).enumerate() {
        let left_label = format!("left_part_{index}");
        let right_label = format!("right_part_{index}");
        filters.push(trim_filter(index * 2, &left_label, left_slice, frame_rate));
        filters.push(trim_filter(
            index * 2 + 1,
            &right_label,
            right_slice,
            frame_rate,
        ));
        left_labels.push(left_label);
        right_labels.push(right_label);
    }
    filters.push(concat_filter(&left_labels, "left_out"));
    filters.push(concat_filter(&right_labels, "right_out"));
    Ok(filters.join(";"))
}

fn append_output(
    args: &mut Vec<OsString>,
    map: &str,
    path: &Path,
    profile: &ExactEncodingProfile,
    gop_frames: u32,
) {
    let x265_parameters =
        format!("keyint={gop_frames}:min-keyint={gop_frames}:scenecut=0:open-gop=0");
    args.extend([
        OsString::from("-map"),
        OsString::from(map),
        OsString::from("-map_metadata"),
        OsString::from("-1"),
        OsString::from("-map_chapters"),
        OsString::from("-1"),
        OsString::from("-an"),
        OsString::from("-sn"),
        OsString::from("-dn"),
        OsString::from("-c:v"),
        OsString::from(&profile.encoder),
        OsString::from("-profile:v"),
        OsString::from(&profile.codec_profile),
        OsString::from("-pix_fmt"),
        OsString::from(&profile.pixel_format),
        OsString::from("-preset"),
        OsString::from(&profile.preset),
        OsString::from("-crf"),
        OsString::from(profile.crf.to_string()),
        OsString::from("-g"),
        OsString::from(gop_frames.to_string()),
        OsString::from("-keyint_min"),
        OsString::from(gop_frames.to_string()),
        OsString::from("-sc_threshold"),
        OsString::from("0"),
        OsString::from("-x265-params"),
        OsString::from(x265_parameters),
        OsString::from("-tag:v"),
        OsString::from(&profile.sample_entry),
        OsString::from("-fps_mode"),
        OsString::from("passthrough"),
        OsString::from("-video_track_timescale"),
        OsString::from(profile.time_base_denominator.to_string()),
        OsString::from("-movflags"),
        OsString::from("+faststart"),
        OsString::from("-f"),
        OsString::from("mp4"),
        path.as_os_str().to_owned(),
    ]);
}

#[derive(Debug, Deserialize)]
struct ProbeDocument {
    #[serde(default)]
    streams: Vec<ProbeStream>,
    #[serde(default)]
    frames: Vec<ProbeFrame>,
    format: Option<ProbeFormat>,
}

#[derive(Debug, Deserialize)]
struct ProbeStream {
    index: u32,
    codec_name: Option<String>,
    codec_type: Option<String>,
    profile: Option<String>,
    codec_tag_string: Option<String>,
    pix_fmt: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    r_frame_rate: Option<String>,
    avg_frame_rate: Option<String>,
    time_base: Option<String>,
    start_pts: Option<i64>,
    duration_ts: Option<i64>,
    nb_read_frames: Option<String>,
    duration: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProbeFrame {
    media_type: Option<String>,
    #[serde(default)]
    key_frame: i32,
    best_effort_timestamp: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ProbeFormat {
    format_name: Option<String>,
    duration: Option<String>,
}

fn probe_args(
    path: &Path,
    include_frames: bool,
    raw_mjpeg_frame_rate: Option<FrameRate>,
) -> Vec<OsString> {
    let mut args = vec![OsString::from("-v"), OsString::from("error")];
    if let Some(frame_rate) = raw_mjpeg_frame_rate {
        args.extend([
            OsString::from("-f"),
            OsString::from("mjpeg"),
            OsString::from("-framerate"),
            OsString::from(frame_rate.ffmpeg_value()),
        ]);
    }
    args.extend([
        OsString::from("-print_format"),
        OsString::from("json"),
        OsString::from("-count_frames"),
        OsString::from("-show_streams"),
        OsString::from("-show_format"),
        OsString::from("-show_entries"),
        OsString::from(if include_frames {
            concat!(
                "stream=index,codec_name,codec_type,profile,codec_tag_string,pix_fmt,width,height,",
                "r_frame_rate,avg_frame_rate,time_base,start_pts,duration_ts,nb_read_frames,duration:",
                "format=format_name,duration:frame=media_type,key_frame,best_effort_timestamp"
            )
        } else {
            concat!(
                "stream=index,codec_name,codec_type,profile,codec_tag_string,pix_fmt,width,height,",
                "r_frame_rate,avg_frame_rate,time_base,start_pts,duration_ts,nb_read_frames,duration:",
                "format=format_name,duration"
            )
        }),
    ]);
    if include_frames {
        args.push(OsString::from("-show_frames"));
    }
    args.extend([OsString::from("-i"), path.as_os_str().to_owned()]);
    args
}

fn full_decode_args(path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("-hide_banner"),
        OsString::from("-v"),
        OsString::from("error"),
        OsString::from("-nostats"),
        OsString::from("-progress"),
        OsString::from("pipe:1"),
        OsString::from("-xerror"),
        OsString::from("-i"),
        path.as_os_str().to_owned(),
        OsString::from("-map"),
        OsString::from("0:v:0"),
        OsString::from("-an"),
        OsString::from("-sn"),
        OsString::from("-dn"),
        OsString::from("-f"),
        OsString::from("null"),
        OsString::from("-"),
    ]
}

fn decoded_frame_count(progress: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(progress)
        .map_err(|_| "FFmpeg decode progress was not valid UTF-8".to_string())?;
    if !text.lines().any(|line| line.trim() == "progress=end") {
        return Err("FFmpeg progress did not contain its final end marker".to_string());
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("frame="))
        .filter_map(|value| value.trim().parse::<u64>().ok())
        .next_back()
        .ok_or_else(|| "FFmpeg decode progress omitted the decoded frame count".to_string())
}

fn parse_probe_document(bytes: &[u8]) -> Result<ProbeDocument, String> {
    serde_json::from_slice(bytes).map_err(|error| {
        format!(
            "ffprobe returned invalid JSON: {}",
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })
}

fn probed_source_artifact(
    artifact_id: &SourceArtifactId,
    source_kind: SourceMediaKind,
    document: &ProbeDocument,
) -> Result<ProbedArtifact, String> {
    let video_streams = document
        .streams
        .iter()
        .filter(|stream| stream.codec_type.as_deref() == Some("video"))
        .collect::<Vec<_>>();
    let audio_track_count = document
        .streams
        .iter()
        .filter(|stream| stream.codec_type.as_deref() == Some("audio"))
        .count();
    let video = video_streams
        .first()
        .copied()
        .ok_or_else(|| format!("source artifact {artifact_id} has no video stream"))?;
    let video_track_count = u8::try_from(video_streams.len())
        .map_err(|_| "source video track count does not fit in u8".to_string())?;
    let audio_track_count = u8::try_from(audio_track_count)
        .map_err(|_| "source audio track count does not fit in u8".to_string())?;

    let codec = match video.codec_name.as_deref() {
        Some("mjpeg") => VideoCodec::Mjpeg,
        Some("h264") => VideoCodec::H264,
        Some("hevc") | Some("h265") => VideoCodec::Hevc,
        Some(codec) => return Err(format!("unsupported source codec {codec}")),
        None => return Err("ffprobe omitted source codec".to_string()),
    };
    let format_name = document
        .format
        .as_ref()
        .and_then(|format| format.format_name.as_deref())
        .ok_or_else(|| "ffprobe omitted source container".to_string())?;
    let is_mp4 = format_name
        .split(',')
        .any(|name| matches!(name, "mov" | "mp4"));
    let container = match source_kind {
        SourceMediaKind::RawCaptureV2 if format_name == "mjpeg" => ContainerFormat::MjpegElementary,
        SourceMediaKind::LegacyMjpegSessionV5 | SourceMediaKind::ApplianceSpoolV6 if is_mp4 => {
            ContainerFormat::FragmentedMp4
        }
        SourceMediaKind::CompleteUnpublishedV6
        | SourceMediaKind::PairedH264PublicationV1
        | SourceMediaKind::UnsignedPairedH264PublicationV1
            if is_mp4 =>
        {
            ContainerFormat::Mp4
        }
        SourceMediaKind::UnsignedMjpegPublicationV1 if format_name == "mjpeg" => {
            ContainerFormat::MjpegElementary
        }
        SourceMediaKind::UnsignedMjpegPublicationV1 if is_mp4 => ContainerFormat::FragmentedMp4,
        _ => {
            return Err(format!(
                "source container {format_name} is incompatible with {source_kind:?}"
            ))
        }
    };
    let pixel_format = match video.pix_fmt.as_deref() {
        Some("yuv420p" | "yuvj420p") => PixelFormat::Yuv420p,
        Some("yuv422p" | "yuvj422p") => PixelFormat::Yuv422p,
        Some(_) | None => PixelFormat::Unknown,
    };
    let width = video
        .width
        .ok_or_else(|| "ffprobe omitted source width".to_string())?;
    let height = video
        .height
        .ok_or_else(|| "ffprobe omitted source height".to_string())?;
    let dimensions = Dimensions::new(width, height).map_err(|error| error.to_string())?;
    let frame_rate = parse_core_rate(video.avg_frame_rate.as_deref(), "source frame rate")
        .or_else(|_| parse_core_rate(video.r_frame_rate.as_deref(), "source frame rate"))?;
    let time_base = parse_core_rate(video.time_base.as_deref(), "source time base")?;
    let first_pts = video
        .start_pts
        .ok_or_else(|| "ffprobe omitted source start_pts".to_string())?;
    let frame_count = parse_frame_count(video)?;
    let duration_ticks = match video.duration_ts {
        Some(value) if value > 0 => value as u64,
        _ => frame_rate
            .ticks_for_frames(frame_count, time_base)
            .map_err(|error| error.to_string())?,
    };
    let codec_profile = video
        .profile
        .as_deref()
        .map(|value| sanitize_bounded_text(value.as_bytes(), 128));
    let sample_entry = video.codec_tag_string.as_deref().and_then(|value| {
        if value.is_empty() || value == "[0][0][0][0]" {
            None
        } else {
            Some(sanitize_bounded_text(value.as_bytes(), 32))
        }
    });

    ProbedArtifact::new(
        artifact_id.clone(),
        codec,
        codec_profile,
        container,
        sample_entry,
        pixel_format,
        dimensions,
        frame_rate,
        time_base,
        first_pts,
        frame_count,
        duration_ticks,
        video_track_count,
        audio_track_count,
        Vec::new(),
    )
    .map_err(|error| error.to_string())
}

fn parse_frame_count(stream: &ProbeStream) -> Result<u64, String> {
    stream
        .nb_read_frames
        .as_deref()
        .ok_or_else(|| "ffprobe omitted nb_read_frames".to_string())?
        .parse::<u64>()
        .map_err(|_| "ffprobe returned a non-numeric nb_read_frames".to_string())
}

fn parse_core_rate(value: Option<&str>, field: &str) -> Result<Rational, String> {
    let value = value.ok_or_else(|| format!("ffprobe omitted {field}"))?;
    let (numerator, denominator) = value
        .split_once('/')
        .ok_or_else(|| format!("ffprobe returned malformed {field}"))?;
    let numerator = numerator
        .parse::<u32>()
        .map_err(|_| format!("ffprobe returned malformed {field}"))?;
    let denominator = denominator
        .parse::<u32>()
        .map_err(|_| format!("ffprobe returned malformed {field}"))?;
    Rational::new(numerator, denominator).map_err(|error| error.to_string())
}

fn sha256_and_sync(path: &Path) -> io::Result<(String, u64)> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "normalizer output is not a regular file",
        ));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("output size overflowed"))?;
    }
    // This happens only after FFmpeg exited and the file was reopened for a
    // complete read, so it is independent evidence about closed output bytes.
    file.sync_all()?;
    drop(file);
    Ok((format!("{:x}", hasher.finalize()), total))
}

#[derive(Debug, Clone)]
struct ExpectedOutputContract {
    frame_rate: FrameRate,
    frame_count: u64,
    eye_width: u32,
    eye_height: u32,
    profile: ExactEncodingProfile,
}

#[derive(Debug, Clone, PartialEq)]
struct InspectedOutput {
    frame_count: u64,
    duration_ticks: u64,
    duration_seconds: f64,
    keyframe_frames: Vec<u64>,
}

fn inspect_normalized_output(
    document: &ProbeDocument,
    expected: &ExpectedOutputContract,
) -> Result<InspectedOutput, String> {
    let (gop_frames, _) = expected.profile.validate(expected.frame_rate)?;
    if document.streams.len() != 1 {
        return Err(format!(
            "normalized output must contain exactly one stream, observed {}",
            document.streams.len()
        ));
    }
    let stream = &document.streams[0];
    if stream.index != 0 || stream.codec_type.as_deref() != Some("video") {
        return Err("normalized output stream 0 must be the sole video stream".to_string());
    }
    require_probe_field("codec", stream.codec_name.as_deref(), "hevc", false)?;
    require_probe_field(
        "profile",
        stream.profile.as_deref(),
        &expected.profile.codec_profile,
        true,
    )?;
    require_probe_field(
        "sample entry",
        stream.codec_tag_string.as_deref(),
        &expected.profile.sample_entry,
        false,
    )?;
    require_probe_field(
        "pixel format",
        stream.pix_fmt.as_deref(),
        &expected.profile.pixel_format,
        false,
    )?;
    if stream.width != Some(expected.eye_width) || stream.height != Some(expected.eye_height) {
        return Err(format!(
            "normalized dimensions are {:?}x{:?}, expected {}x{}",
            stream.width, stream.height, expected.eye_width, expected.eye_height
        ));
    }

    let expected_rate = expected.frame_rate;
    let average_rate = parse_rate(
        stream.avg_frame_rate.as_deref(),
        "average output frame rate",
    )?;
    let real_rate = parse_rate(stream.r_frame_rate.as_deref(), "real output frame rate")?;
    if average_rate != expected_rate || real_rate != expected_rate {
        return Err(format!(
            "output rates {}/{} and {}/{} do not match planned {}/{}",
            average_rate.numerator,
            average_rate.denominator,
            real_rate.numerator,
            real_rate.denominator,
            expected_rate.numerator,
            expected_rate.denominator
        ));
    }
    let time_base = stream
        .time_base
        .as_deref()
        .ok_or_else(|| "ffprobe omitted output time_base".to_string())?;
    if time_base != format!("1/{}", expected.profile.time_base_denominator) {
        return Err(format!(
            "output time_base {time_base} does not match 1/{}",
            expected.profile.time_base_denominator
        ));
    }

    let frame_count = stream
        .nb_read_frames
        .as_deref()
        .ok_or_else(|| "ffprobe omitted nb_read_frames".to_string())?
        .parse::<u64>()
        .map_err(|_| "ffprobe returned a non-numeric nb_read_frames".to_string())?;
    if frame_count != expected.frame_count {
        return Err(format!(
            "output contains {frame_count} frames, expected {}",
            expected.frame_count
        ));
    }
    if document.frames.len() as u64 != expected.frame_count {
        return Err(format!(
            "ffprobe returned {} frame records, expected {}",
            document.frames.len(),
            expected.frame_count
        ));
    }

    let ticks_per_frame = i64::from(
        expected
            .frame_rate
            .ticks_per_frame(expected.profile.time_base_denominator)?,
    );
    let mut keyframe_frames = Vec::new();
    for (index, frame) in document.frames.iter().enumerate() {
        if frame
            .media_type
            .as_deref()
            .is_some_and(|kind| kind != "video")
        {
            return Err(format!("ffprobe frame {index} is not video"));
        }
        let should_be_key = index % gop_frames as usize == 0;
        if (frame.key_frame == 1) != should_be_key {
            return Err(format!(
                "frame {index} key-frame flag violates the fixed {gop_frames}-frame closed GOP"
            ));
        }
        if frame.key_frame == 1 {
            keyframe_frames.push(index as u64);
        }
        let expected_timestamp = i64::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(ticks_per_frame))
            .ok_or_else(|| "expected frame timestamp overflowed".to_string())?;
        if frame.best_effort_timestamp != Some(expected_timestamp) {
            return Err(format!(
                "frame {index} timestamp {:?} does not match planned {expected_timestamp}",
                frame.best_effort_timestamp
            ));
        }
    }

    let format = document
        .format
        .as_ref()
        .ok_or_else(|| "ffprobe omitted output format".to_string())?;
    let format_name = format
        .format_name
        .as_deref()
        .ok_or_else(|| "ffprobe omitted output container name".to_string())?;
    if !format_name
        .split(',')
        .any(|name| matches!(name, "mov" | "mp4"))
    {
        return Err(format!("output container {format_name} is not MP4"));
    }
    let duration_seconds = stream
        .duration
        .as_deref()
        .and_then(|value| value.parse::<f64>().ok())
        .or_else(|| {
            format
                .duration
                .as_deref()
                .and_then(|value| value.parse::<f64>().ok())
        })
        .ok_or_else(|| "ffprobe omitted a numeric output duration".to_string())?;
    let duration_ticks = stream
        .duration_ts
        .filter(|ticks| *ticks > 0)
        .map(|ticks| ticks as u64)
        .ok_or_else(|| "ffprobe omitted positive output duration_ts".to_string())?;
    if !duration_seconds.is_finite() || duration_seconds <= 0.0 {
        return Err("output duration must be finite and positive".to_string());
    }
    let planned_duration = expected.frame_count as f64 * f64::from(expected.frame_rate.denominator)
        / f64::from(expected.frame_rate.numerator);
    let one_frame =
        f64::from(expected.frame_rate.denominator) / f64::from(expected.frame_rate.numerator);
    if (duration_seconds - planned_duration).abs() > one_frame + 0.01 {
        return Err(format!(
            "output duration {duration_seconds:.6}s differs from planned {planned_duration:.6}s by more than one frame plus 0.01s"
        ));
    }

    Ok(InspectedOutput {
        frame_count,
        duration_ticks,
        duration_seconds,
        keyframe_frames,
    })
}

fn require_probe_field(
    field: &str,
    actual: Option<&str>,
    expected: &str,
    ascii_case_insensitive: bool,
) -> Result<(), String> {
    let matches = actual.is_some_and(|value| {
        if ascii_case_insensitive {
            value.eq_ignore_ascii_case(expected)
        } else {
            value == expected
        }
    });
    if matches {
        Ok(())
    } else {
        Err(format!(
            "output {field} {:?} does not match {expected}",
            actual
        ))
    }
}

fn parse_rate(value: Option<&str>, field: &str) -> Result<FrameRate, String> {
    let value = value.ok_or_else(|| format!("ffprobe omitted {field}"))?;
    let (numerator, denominator) = value
        .split_once('/')
        .ok_or_else(|| format!("ffprobe returned malformed {field}"))?;
    let numerator = numerator
        .parse::<u32>()
        .map_err(|_| format!("ffprobe returned malformed {field}"))?;
    let denominator = denominator
        .parse::<u32>()
        .map_err(|_| format!("ffprobe returned malformed {field}"))?;
    FrameRate::checked(numerator, denominator)
}

fn validate_duration_pair(
    left: &InspectedOutput,
    right: &InspectedOutput,
    frame_rate: FrameRate,
) -> Result<(), String> {
    let one_frame = f64::from(frame_rate.denominator) / f64::from(frame_rate.numerator);
    if (left.duration_seconds - right.duration_seconds).abs() > one_frame {
        return Err(format!(
            "left/right durations {:.6}s/{:.6}s differ by more than one frame",
            left.duration_seconds, right.duration_seconds
        ));
    }
    Ok(())
}

fn ensure_closed_nonempty_regular_file(path: &Path) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "could not inspect output {}: {}",
            path.display(),
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "normalizer output {} is not a regular file",
            path.display()
        ));
    }
    if metadata.len() == 0 {
        return Err(format!("normalizer output {} is empty", path.display()));
    }
    Ok(metadata.len())
}

fn prepare_partial_output(path: &Path) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "partial output must have a UTF-8 file name".to_string())?;
    if !name.ends_with(".partial.mp4") {
        return Err(format!(
            "partial output {} must end in .partial.mp4",
            path.display()
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "refusing to replace non-regular partial output {}",
            path.display()
        )),
        Ok(_) => fs::remove_file(path).map_err(|error| {
            format!(
                "could not remove stale partial {}: {}",
                path.display(),
                sanitize_process_diagnostic(error.to_string().as_bytes())
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect partial output {}: {}",
            path.display(),
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )),
    }
}

fn prepare_partial_pair(left: &Path, right: &Path) -> Result<(), String> {
    if !left.is_absolute() || !right.is_absolute() {
        return Err("partial output paths must be absolute".to_string());
    }
    let parent = left
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "partial output is missing its pair staging directory".to_string())?;
    if right.parent() != Some(parent) {
        return Err("partial outputs must share one pair staging directory".to_string());
    }
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        format!(
            "could not inspect pair staging directory {}: {}",
            parent.display(),
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "pair staging path {} is not a real directory",
            parent.display()
        ));
    }
    prepare_partial_output(left)?;
    prepare_partial_output(right)
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_owned()
}

// ---------------------------------------------------------------------------
// Real per-eye quality evidence
// ---------------------------------------------------------------------------

/// Maximum per-frame VMAF samples retained in one archived report. A 30 second
/// pair at 60 fps is 1,800 frames; the cap only exists so a mis-planned segment
/// cannot write an unbounded report into the derived tree.
pub const MAX_ARCHIVED_QUALITY_FRAMES: usize = 8_192;

/// Maximum libvmaf JSON accepted from one measurement run.
pub const MAX_QUALITY_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// The exact VMAF model this adapter is allowed to request. A different model
/// is a different quality contract and therefore a different profile revision,
/// never a runtime substitution.
pub const VMAF_NEG_MODEL_VERSION: &str = "vmaf_v0.6.1neg";

const QUALITY_REPORT_SCHEMA: &str = "ylx-transfer/segment-quality-report";
const QUALITY_REPORT_SCHEMA_VERSION: u32 = 1;

/// Input handed to the stereo/CV domain evaluator once FFmpeg has produced
/// per-frame reference metrics for both eyes.
#[derive(Debug, Clone)]
pub struct StereoDomainRequest<'a> {
    pub segment_index: u32,
    pub source_revision: &'a str,
    pub profile_revision: &'a str,
    pub eye_width: u32,
    pub eye_height: u32,
    pub frame_count: u64,
    pub left_reference: &'a EyeMetrics,
    pub right_reference: &'a EyeMetrics,
    pub left_output_path: &'a Path,
    pub right_output_path: &'a Path,
}

/// Verdict returned by the algorithm owner's evaluator. `metrics` is archived
/// verbatim inside the canonical report, so the numbers behind the verdict stay
/// auditable rather than collapsing into one boolean.
#[derive(Debug, Clone, PartialEq)]
pub struct StereoDomainVerdict {
    pub passed: bool,
    pub metrics: BTreeMap<String, i64>,
}

/// The stereo/CV domain evaluator seam.
///
/// There is deliberately no default implementation in this crate. §9.6 of the
/// Ubuntu pipeline specification makes a real, owner-approved evaluator a
/// release hard gate: without one, normalization stays capability-unavailable
/// rather than emitting a constant `true`.
pub trait StereoDomainEvaluator: Send + Sync {
    /// Stable evaluator identity, e.g. `"ylx-stereo-cv/v1"`.
    fn evaluator_identity(&self) -> &str;

    /// Revision of the approved algorithm and thresholds.
    fn evaluator_revision(&self) -> &str;

    fn evaluate_pair(
        &self,
        request: &StereoDomainRequest<'_>,
    ) -> Result<StereoDomainVerdict, String>;
}

/// Versioned process protocol for the algorithm owner that evaluates stereo
/// domain evidence. The media adapter owns process supervision and validates
/// the response; the executable owns the actual CV algorithm and thresholds.
/// Keeping that boundary explicit lets the shipped application fail closed
/// when the reviewed evaluator is not installed instead of quietly replacing
/// it with a heuristic or a constant verdict.
pub const STEREO_DOMAIN_PROTOCOL: &str = "ylx-transfer/stereo-domain-evaluator-v1";
pub const MAX_STEREO_DOMAIN_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STEREO_DOMAIN_METRICS: usize = 64;
const MAX_STEREO_DOMAIN_METRIC_KEY_BYTES: usize = 128;

#[derive(Debug, Clone)]
pub struct ExternalStereoDomainEvaluator {
    executable: PathBuf,
    identity: String,
    revision: String,
    timeout: Duration,
    poll_interval: Duration,
}

impl ExternalStereoDomainEvaluator {
    pub fn new(
        executable: impl Into<PathBuf>,
        identity: impl Into<String>,
        revision: impl Into<String>,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, String> {
        let executable = executable.into();
        let identity = identity.into();
        let revision = revision.into();
        if executable.as_os_str().is_empty() {
            return Err("stereo domain evaluator executable is empty".to_string());
        }
        if identity.trim().is_empty() || revision.trim().is_empty() {
            return Err(
                "stereo domain evaluator identity and revision must both be configured".to_string(),
            );
        }
        if identity.chars().any(|character| character.is_control())
            || revision.chars().any(|character| character.is_control())
        {
            return Err(
                "stereo domain evaluator identity contains a control character".to_string(),
            );
        }
        if timeout.is_zero() || poll_interval.is_zero() {
            return Err("stereo domain evaluator timing must be positive".to_string());
        }
        Ok(Self {
            executable,
            identity,
            revision,
            timeout,
            poll_interval,
        })
    }

    /// Production composition source. All three values are required so a
    /// deployment cannot accidentally run an executable under an unreviewed
    /// identity or revision.
    pub fn from_environment() -> Result<Self, String> {
        let executable = std::env::var_os("YLX_STEREO_DOMAIN_EVALUATOR").map(PathBuf::from);
        let identity = std::env::var("YLX_STEREO_DOMAIN_EVALUATOR_ID").ok();
        let revision = std::env::var("YLX_STEREO_DOMAIN_EVALUATOR_REVISION").ok();
        let timeout = parse_evaluator_duration(
            "YLX_STEREO_DOMAIN_EVALUATOR_TIMEOUT_MS",
            Duration::from_secs(30 * 60),
        )?;
        Self::from_environment_values(executable, identity, revision, timeout)
    }

    fn from_environment_values(
        executable: Option<PathBuf>,
        identity: Option<String>,
        revision: Option<String>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let executable = executable
            .ok_or_else(|| "YLX_STEREO_DOMAIN_EVALUATOR is not configured".to_string())?;
        let identity = identity
            .ok_or_else(|| "YLX_STEREO_DOMAIN_EVALUATOR_ID is not configured".to_string())?;
        let revision = revision
            .ok_or_else(|| "YLX_STEREO_DOMAIN_EVALUATOR_REVISION is not configured".to_string())?;
        Self::new(
            executable,
            identity,
            revision,
            timeout,
            DEFAULT_POLL_INTERVAL,
        )
    }
}

impl StereoDomainEvaluator for ExternalStereoDomainEvaluator {
    fn evaluator_identity(&self) -> &str {
        &self.identity
    }

    fn evaluator_revision(&self) -> &str {
        &self.revision
    }

    fn evaluate_pair(
        &self,
        request: &StereoDomainRequest<'_>,
    ) -> Result<StereoDomainVerdict, String> {
        let wire = StereoDomainWireRequest::from_request(request)?;
        let payload = serde_json::to_vec(&wire)
            .map_err(|error| format!("could not serialize stereo domain request: {error}"))?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| "stereo domain evaluator deadline overflowed".to_string())?;
        let completed = run_process_with_input(
            &self.executable,
            &[
                OsString::from("--protocol"),
                OsString::from(STEREO_DOMAIN_PROTOCOL),
            ],
            Some(MAX_STEREO_DOMAIN_OUTPUT_BYTES),
            deadline,
            DEFAULT_STOP_GRACE,
            DEFAULT_STOP_GRACE,
            self.poll_interval,
            Some(&payload),
            || None,
        )
        .map_err(|error| {
            format!(
                "stereo domain evaluator process failed: {}",
                sanitize_process_diagnostic(error.to_string().as_bytes())
            )
        })?;
        let response: StereoDomainWireResponse = serde_json::from_slice(&completed.stdout)
            .map_err(|error| {
                format!(
                    "stereo domain evaluator returned invalid JSON: {}",
                    sanitize_process_diagnostic(error.to_string().as_bytes())
                )
            })?;
        validate_stereo_domain_response(response, &self.identity, &self.revision)
    }
}

#[derive(Debug, Serialize)]
struct StereoDomainWireRequest {
    protocol: &'static str,
    segment_index: u32,
    source_revision: String,
    profile_revision: String,
    eye_width: u32,
    eye_height: u32,
    frame_count: u64,
    left_reference: StereoEyeWireMetrics,
    right_reference: StereoEyeWireMetrics,
    left_output_path: String,
    right_output_path: String,
}

#[derive(Debug, Serialize)]
struct StereoEyeWireMetrics {
    vmaf_mean_milli: u32,
    vmaf_frame_p01_milli: u32,
    ssim_mean_millionths: u32,
    frame_vmaf_milli: Vec<u32>,
    frames_complete: bool,
    output_sha256: String,
    output_size_bytes: u64,
}

impl StereoDomainWireRequest {
    fn from_request(request: &StereoDomainRequest<'_>) -> Result<Self, String> {
        let left_output_path = request
            .left_output_path
            .to_str()
            .ok_or_else(|| "left stereo output path is not valid UTF-8".to_string())?;
        let right_output_path = request
            .right_output_path
            .to_str()
            .ok_or_else(|| "right stereo output path is not valid UTF-8".to_string())?;
        Ok(Self {
            protocol: STEREO_DOMAIN_PROTOCOL,
            segment_index: request.segment_index,
            source_revision: request.source_revision.to_string(),
            profile_revision: request.profile_revision.to_string(),
            eye_width: request.eye_width,
            eye_height: request.eye_height,
            frame_count: request.frame_count,
            left_reference: StereoEyeWireMetrics::from_metrics(request.left_reference),
            right_reference: StereoEyeWireMetrics::from_metrics(request.right_reference),
            left_output_path: left_output_path.to_string(),
            right_output_path: right_output_path.to_string(),
        })
    }
}

impl StereoEyeWireMetrics {
    fn from_metrics(metrics: &EyeMetrics) -> Self {
        Self {
            vmaf_mean_milli: metrics.vmaf_mean_milli,
            vmaf_frame_p01_milli: metrics.vmaf_frame_p01_milli,
            ssim_mean_millionths: metrics.ssim_mean_millionths,
            frame_vmaf_milli: metrics.frame_vmaf_milli.clone(),
            frames_complete: metrics.frames_complete,
            output_sha256: metrics.output_sha256.clone(),
            output_size_bytes: metrics.output_size_bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
struct StereoDomainWireResponse {
    protocol: String,
    evaluator_identity: String,
    evaluator_revision: String,
    passed: bool,
    metrics: BTreeMap<String, i64>,
}

fn validate_stereo_domain_response(
    response: StereoDomainWireResponse,
    expected_identity: &str,
    expected_revision: &str,
) -> Result<StereoDomainVerdict, String> {
    if response.protocol != STEREO_DOMAIN_PROTOCOL {
        return Err("stereo domain evaluator protocol revision mismatch".to_string());
    }
    if response.evaluator_identity != expected_identity
        || response.evaluator_revision != expected_revision
    {
        return Err("stereo domain evaluator identity or revision mismatch".to_string());
    }
    if response.metrics.is_empty() || response.metrics.len() > MAX_STEREO_DOMAIN_METRICS {
        return Err("stereo domain evaluator returned an invalid metric set".to_string());
    }
    if response.metrics.keys().any(|key| {
        key.is_empty()
            || key.len() > MAX_STEREO_DOMAIN_METRIC_KEY_BYTES
            || key.chars().any(|character| character.is_control())
    }) {
        return Err("stereo domain evaluator returned an unsafe metric key".to_string());
    }
    Ok(StereoDomainVerdict {
        passed: response.passed,
        metrics: response.metrics,
    })
}

fn parse_evaluator_duration(name: &str, default: Duration) -> Result<Duration, String> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(default);
    };
    let value = value
        .to_str()
        .ok_or_else(|| format!("{name} is not valid UTF-8"))?;
    let millis = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned millisecond count"))?;
    let duration = Duration::from_millis(millis);
    if duration.is_zero() {
        return Err(format!("{name} must be positive"));
    }
    Ok(duration)
}

/// Fixed-point per-eye reference metrics measured against the sealed source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EyeMetrics {
    pub eye: Eye,
    pub vmaf_mean_milli: u32,
    pub vmaf_frame_p01_milli: u32,
    pub ssim_mean_millionths: u32,
    pub frame_vmaf_milli: Vec<u32>,
    /// Whether `frame_vmaf_milli` holds every measured frame. A truncated
    /// series is recorded as such instead of being silently shortened.
    pub frames_complete: bool,
    pub output_sha256: String,
    pub output_size_bytes: u64,
}

/// Real source-referenced quality analyzer.
///
/// It measures each eye against the same decoded/cropped source frames the
/// encoder consumed, archives a canonical bounded report into the derivation's
/// staging tree, and returns `QualityEvidence` whose `report_digest` is the
/// SHA-256 of exactly those archived bytes.
pub struct FfmpegQualityAnalyzer {
    normalizer: FfmpegMediaNormalizer,
    report_root: PathBuf,
    stereo_evaluator: std::sync::Arc<dyn StereoDomainEvaluator>,
}

impl fmt::Debug for FfmpegQualityAnalyzer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FfmpegQualityAnalyzer")
            .field("report_root", &self.report_root)
            .field(
                "stereo_evaluator",
                &self.stereo_evaluator.evaluator_identity(),
            )
            .finish()
    }
}

impl FfmpegQualityAnalyzer {
    /// Construct the analyzer.
    ///
    /// Construction fails closed when the configured FFmpeg build does not
    /// actually expose `libvmaf` and `ssim`: a build that cannot measure
    /// quality must not be able to produce quality evidence.
    pub fn new(
        normalizer: FfmpegMediaNormalizer,
        report_root: impl Into<PathBuf>,
        stereo_evaluator: std::sync::Arc<dyn StereoDomainEvaluator>,
    ) -> Result<Self, FfmpegInitError> {
        if let FfmpegQualityEvidenceCapability::MetricsFiltersUnavailable { detail } =
            normalizer.quality_evidence_capability()
        {
            return Err(FfmpegInitError::Capability(format!(
                "FFmpeg cannot measure VMAF/SSIM: {detail}"
            )));
        }
        let report_root = report_root.into();
        if !report_root.is_absolute() {
            return Err(FfmpegInitError::InvalidConfig(
                "quality report root must be an absolute path".to_string(),
            ));
        }
        if !path_is_filter_safe(&report_root) {
            return Err(FfmpegInitError::InvalidConfig(
                "quality report root contains characters that cannot be expressed in an FFmpeg \
                 filter argument"
                    .to_string(),
            ));
        }
        Ok(Self {
            normalizer,
            report_root,
            stereo_evaluator,
        })
    }

    fn measure_eye(
        &self,
        command: &EncodeCommandRequest,
        target: EyeMeasurement<'_>,
        timing: OperationTiming,
        control: &dyn MediaOperationControl,
        receipts: &mut Vec<ReapReceipt>,
    ) -> Result<EyeMetrics, Box<MediaProcessOutcome<PairQualityEvidence>>> {
        let EyeMeasurement {
            eye,
            output_path,
            log_path,
        } = target;
        let rejected = |receipts: &[ReapReceipt],
                        code: MediaProcessFailureCode,
                        detail: String|
         -> Box<MediaProcessOutcome<PairQualityEvidence>> {
            Box::new(failure_after_reap(receipts, code, false, detail))
        };

        let args = build_quality_args(command, eye, output_path, log_path).map_err(|detail| {
            rejected(
                receipts,
                MediaProcessFailureCode::ValidationRejected,
                detail,
            )
        })?;
        run_core_process::<PairQualityEvidence>(
            &self.normalizer.config.ffmpeg_path,
            &args,
            Some(MAX_PROCESS_DIAGNOSTIC_BYTES),
            timing,
            self.normalizer.config.poll_interval,
            control,
            receipts,
            MediaProcessFailureCode::ValidationRejected,
            false,
        )
        .map_err(Box::new)?;

        let log = read_bounded_file(log_path, MAX_QUALITY_LOG_BYTES)
            .map_err(|detail| rejected(receipts, MediaProcessFailureCode::InvalidOutput, detail))?;
        let (output_sha256, output_size_bytes) = sha256_and_sync(output_path).map_err(|error| {
            rejected(
                receipts,
                MediaProcessFailureCode::Io,
                format!(
                    "could not re-read the encoded eye output for quality evidence: {}",
                    sanitize_process_diagnostic(error.to_string().as_bytes())
                ),
            )
        })?;
        parse_vmaf_log(&log, eye, output_sha256, output_size_bytes)
            .map_err(|detail| rejected(receipts, MediaProcessFailureCode::InvalidOutput, detail))
    }
}

/// One eye's measurement target: which encoded output is compared, and where
/// libvmaf must write its structured log.
#[derive(Debug, Clone, Copy)]
struct EyeMeasurement<'a> {
    eye: Eye,
    output_path: &'a Path,
    log_path: &'a Path,
}

impl SegmentQualityAnalyzer for FfmpegQualityAnalyzer {
    fn analyze_segment_pair(
        &self,
        request: &EncodeSegmentPairRequest,
        encoded: &EncodedSegmentPair,
        control: &dyn MediaOperationControl,
    ) -> MediaProcessOutcome<PairQualityEvidence> {
        if request.encoder_build() != &self.normalizer.encoder_build {
            return failure_without_process(
                MediaProcessFailureCode::ValidationRejected,
                false,
                "quality request targets a different encoder build fingerprint",
            );
        }
        let timing = match operation_timing(control) {
            Ok(timing) => timing,
            Err(detail) => {
                return failure_without_process(MediaProcessFailureCode::Internal, false, detail)
            }
        };
        // The same frozen plan the encoder used. Re-deriving it here is what
        // makes this a source-reference measurement rather than a comparison
        // against some other decode of the card.
        let command = match EncodeCommandRequest::from_core(request) {
            Ok(command) => command,
            Err(detail) => {
                return failure_without_process(
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    detail,
                )
            }
        };
        let segment_index = encoded.segment_index();
        let staging = match self.prepare_segment_report_dir(encoded) {
            Ok(staging) => staging,
            Err(detail) => {
                return failure_without_process(MediaProcessFailureCode::Io, false, detail)
            }
        };

        let mut receipts: Vec<ReapReceipt> = Vec::new();
        let left_log = staging.join("left.vmaf.json");
        let right_log = staging.join("right.vmaf.json");
        let left = match self.measure_eye(
            &command,
            EyeMeasurement {
                eye: Eye::Left,
                output_path: encoded.left_partial_path(),
                log_path: &left_log,
            },
            timing,
            control,
            &mut receipts,
        ) {
            Ok(metrics) => metrics,
            Err(outcome) => return *outcome,
        };
        let right = match self.measure_eye(
            &command,
            EyeMeasurement {
                eye: Eye::Right,
                output_path: encoded.right_partial_path(),
                log_path: &right_log,
            },
            timing,
            control,
            &mut receipts,
        ) {
            Ok(metrics) => metrics,
            Err(outcome) => return *outcome,
        };

        // The stereo/CV verdict is an owner-approved algorithm, never a
        // constant. A failing evaluator is a validation failure, not a reason
        // to publish evidence without a domain verdict.
        let domain_request = StereoDomainRequest {
            segment_index,
            source_revision: request.source_revision().as_str(),
            profile_revision: request.profile().profile_revision().as_str(),
            eye_width: command.eye_width,
            eye_height: command.eye_height,
            frame_count: command.expected_frames,
            left_reference: &left,
            right_reference: &right,
            left_output_path: encoded.left_partial_path(),
            right_output_path: encoded.right_partial_path(),
        };
        let verdict = match self.stereo_evaluator.evaluate_pair(&domain_request) {
            Ok(verdict) => verdict,
            Err(detail) => {
                return failure_after_reap(
                    &receipts,
                    MediaProcessFailureCode::ValidationRejected,
                    false,
                    format!(
                        "the stereo/CV domain evaluator rejected segment {segment_index}: {}",
                        sanitize_process_diagnostic(detail.as_bytes())
                    ),
                )
            }
        };

        let mut evidence = Vec::new();
        for metrics in [&left, &right] {
            let report = self.render_report(request, encoded, metrics, &verdict, &command);
            let digest = match self.archive_report(&staging, metrics.eye, &report) {
                Ok(digest) => digest,
                Err(detail) => {
                    return failure_after_reap(
                        &receipts,
                        MediaProcessFailureCode::Io,
                        false,
                        detail,
                    )
                }
            };
            let quality = ylx_transfer_core::normalization::QualityEvidence::new(
                metrics.eye,
                VMAF_NEG_MODEL_VERSION,
                metrics.vmaf_mean_milli,
                metrics.vmaf_frame_p01_milli,
                metrics.ssim_mean_millionths,
                verdict.passed,
                digest,
            );
            match quality {
                Ok(quality) => evidence.push(quality),
                Err(error) => {
                    return failure_after_reap(
                        &receipts,
                        MediaProcessFailureCode::ValidationRejected,
                        false,
                        error.to_string(),
                    )
                }
            }
        }
        let mut evidence = evidence.into_iter();
        let (Some(left_evidence), Some(right_evidence)) = (evidence.next(), evidence.next()) else {
            return failure_after_reap(
                &receipts,
                MediaProcessFailureCode::Internal,
                false,
                "quality analysis did not produce both eyes",
            );
        };
        match PairQualityEvidence::new(left_evidence, right_evidence) {
            Ok(pair) => MediaProcessOutcome::completed(pair, reap_report(&receipts)),
            Err(error) => failure_after_reap(
                &receipts,
                MediaProcessFailureCode::ValidationRejected,
                false,
                error.to_string(),
            ),
        }
    }
}

impl FfmpegQualityAnalyzer {
    fn prepare_segment_report_dir(&self, encoded: &EncodedSegmentPair) -> Result<PathBuf, String> {
        let pair_root = encoded
            .left_partial_path()
            .parent()
            .ok_or_else(|| "encoded left output has no staging directory".to_string())?;
        if encoded.right_partial_path().parent() != Some(pair_root) {
            return Err("encoded eye outputs do not share one staging directory".to_string());
        }
        if !pair_root.is_absolute() || !pair_root.starts_with(&self.report_root) {
            return Err(
                "encoded quality output is outside the configured derived staging root".to_string(),
            );
        }
        // Keep the report beside the pair outputs. The pair directory is
        // atomically renamed after validation, so the report follows the
        // exact derived revision instead of living in a global sidecar tree.
        let directory = pair_root.join("quality-report");
        fs::create_dir_all(&directory).map_err(|error| {
            format!(
                "could not create the quality-report staging directory: {}",
                sanitize_process_diagnostic(error.to_string().as_bytes())
            )
        })?;
        if !path_is_filter_safe(&directory) {
            return Err("quality-report staging path is not filter-argument safe".to_string());
        }
        Ok(directory)
    }

    fn render_report(
        &self,
        request: &EncodeSegmentPairRequest,
        encoded: &EncodedSegmentPair,
        metrics: &EyeMetrics,
        verdict: &StereoDomainVerdict,
        command: &EncodeCommandRequest,
    ) -> Vec<u8> {
        let thresholds = request.profile().quality_thresholds();
        let report = serde_json::json!({
            "schema": QUALITY_REPORT_SCHEMA,
            "schema_version": QUALITY_REPORT_SCHEMA_VERSION,
            "segment_index": encoded.segment_index(),
            "eye": match metrics.eye {
                Eye::Left => "left",
                Eye::Right => "right",
            },
            "source_revision": request.source_revision().as_str(),
            "source_inventory_digest": request.local_source().inventory_digest().as_str(),
            "profile_revision": request.profile().profile_revision().as_str(),
            "encoder_build": {
                "implementation": self.normalizer.encoder_build.implementation(),
                "version": self.normalizer.encoder_build.version(),
                "fingerprint": self.normalizer.encoder_build.build_fingerprint().as_str(),
                "compatibility_class":
                    self.normalizer.encoder_build.compatibility_class().as_str(),
            },
            "tool": {
                "implementation": self.normalizer.build_observation.implementation,
                "version_line": self.normalizer.build_observation.version_line,
                "vmaf_model": VMAF_NEG_MODEL_VERSION,
            },
            "geometry": {
                "eye_width": command.eye_width,
                "eye_height": command.eye_height,
                "frame_count": command.expected_frames,
            },
            "output": {
                "sha256": metrics.output_sha256,
                "size_bytes": metrics.output_size_bytes,
            },
            "vmaf": {
                "mean_milli": metrics.vmaf_mean_milli,
                "frame_p01_milli": metrics.vmaf_frame_p01_milli,
                "frames_complete": metrics.frames_complete,
                "frame_milli": metrics.frame_vmaf_milli,
            },
            "ssim": {
                "mean_millionths": metrics.ssim_mean_millionths,
            },
            "stereo_domain": {
                "evaluator": self.stereo_evaluator.evaluator_identity(),
                "revision": self.stereo_evaluator.evaluator_revision(),
                "passed": verdict.passed,
                "metrics": verdict.metrics,
            },
            "thresholds": {
                "vmaf_neg_model": thresholds.vmaf_neg_model(),
                "vmaf_mean_milli_min": thresholds.vmaf_mean_milli_min(),
                "vmaf_frame_p01_milli_min": thresholds.vmaf_frame_p01_milli_min(),
                "ssim_mean_millionths_min": thresholds.ssim_mean_millionths_min(),
                "stereo_domain_metrics_required": thresholds.stereo_domain_metrics_required(),
            },
        });
        // `serde_json::Value` serializes maps in sorted key order, so this is
        // already canonical for a fixed schema.
        let mut bytes = serde_json::to_vec(&report).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    }

    /// Write the report into derived staging, fsync both the file and its
    /// directory, then return the digest of exactly those bytes. The evidence
    /// digest must describe archived bytes, not an in-memory value that a
    /// later crash could leave unwritten.
    fn archive_report(
        &self,
        staging: &Path,
        eye: Eye,
        bytes: &[u8],
    ) -> Result<ContentSha256, String> {
        let name = match eye {
            Eye::Left => "left.quality-report.json",
            Eye::Right => "right.quality-report.json",
        };
        let path = staging.join(name);
        let io_error = |error: io::Error| {
            format!(
                "could not archive the quality report: {}",
                sanitize_process_diagnostic(error.to_string().as_bytes())
            )
        };
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        if let Ok(directory) = OpenOptions::new().read(true).open(staging) {
            let _ = directory.sync_all();
        }
        ContentSha256::parse(format!("{:x}", Sha256::digest(bytes)))
            .map_err(|error| error.to_string())
    }
}

/// Build one eye's measurement command.
///
/// Inputs 0..n are the same sealed source artifacts and the same trim/concat/
/// crop graph the encoder used, so `[ref]` is exactly the frames that were
/// encoded. The encoded partial is appended as the last input and becomes
/// `[dist]`. Nothing is passed through a shell and no path is interpolated
/// into a larger command string.
fn build_quality_args(
    command: &EncodeCommandRequest,
    eye: Eye,
    output_path: &Path,
    log_path: &Path,
) -> Result<Vec<OsString>, String> {
    if !path_is_filter_safe(log_path) {
        return Err("quality log path is not filter-argument safe".to_string());
    }
    let log_path = log_path
        .to_str()
        .ok_or_else(|| "quality log path is not valid UTF-8".to_string())?;

    let mut args = vec![
        OsString::from("-hide_banner"),
        OsString::from("-loglevel"),
        OsString::from("warning"),
        OsString::from("-nostats"),
        OsString::from("-xerror"),
    ];

    let (reference_filter, reference_input_count) = match &command.input {
        SegmentInput::RawStereoMjpeg(slices)
        | SegmentInput::LegacyV5StereoMjpeg(slices)
        | SegmentInput::SpoolV6StereoMjpeg(slices) => {
            append_inputs(&mut args, slices, command.frame_rate)?;
            ensure_expected_frames(slices, command.expected_frames)?;
            (side_by_side_filter(slices, command)?, slices.len())
        }
        SegmentInput::PublishedStereoPairs { left, right } => {
            if left.len() != right.len() || left.is_empty() {
                return Err(
                    "published stereo plan requires matched non-empty eye slices".to_string(),
                );
            }
            append_stereo_pair_inputs(&mut args, left, right, command.frame_rate)?;
            ensure_expected_frames(left, command.expected_frames)?;
            ensure_expected_frames(right, command.expected_frames)?;
            (
                stereo_pair_filter(left, right, command.frame_rate)?,
                left.len() + right.len(),
            )
        }
    };

    args.push(OsString::from("-i"));
    args.push(output_path.as_os_str().to_owned());
    let distorted_input = reference_input_count;

    let (measured, discarded) = match eye {
        Eye::Left => ("left_out", "right_out"),
        Eye::Right => ("right_out", "left_out"),
    };
    // Both streams are put on a common time base with a zeroed start PTS so
    // libvmaf compares frame N against frame N. A quality score computed from
    // misaligned frames would be evidence of nothing.
    let filter = format!(
        "{reference_filter};[{discarded}]nullsink;\
         [{measured}]settb=AVTB,setpts=PTS-STARTPTS,format=yuv420p[quality_ref];\
         [{distorted_input}:v:0]settb=AVTB,setpts=PTS-STARTPTS,format=yuv420p[quality_dist];\
         [quality_dist][quality_ref]libvmaf=\
         model='version={VMAF_NEG_MODEL_VERSION}':\
         feature='name=float_ssim':\
         log_fmt=json:log_path='{log_path}':shortest=1[quality_out]"
    );
    args.extend([OsString::from("-filter_complex"), OsString::from(filter)]);
    args.extend([
        OsString::from("-map"),
        OsString::from("[quality_out]"),
        OsString::from("-an"),
        OsString::from("-sn"),
        OsString::from("-dn"),
        OsString::from("-f"),
        OsString::from("null"),
        OsString::from("-"),
    ]);
    Ok(args)
}

/// FFmpeg filter arguments use `:`, `'`, `\`, `[`, `]` and `,` as syntax. A
/// path containing any of them cannot be embedded unambiguously, so it is
/// rejected rather than escaped by hand.
fn path_is_filter_safe(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    !text.is_empty()
        && !text.chars().any(|character| {
            character.is_control()
                || matches!(character, ':' | '\'' | '\\' | '[' | ']' | ',' | ';' | '=')
        })
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "could not inspect the quality measurement log: {}",
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("the quality measurement log is not a regular file".to_string());
    }
    if metadata.len() > limit {
        return Err(format!(
            "the quality measurement log exceeded its {limit} byte bound"
        ));
    }
    fs::read(path).map_err(|error| {
        format!(
            "could not read the quality measurement log: {}",
            sanitize_process_diagnostic(error.to_string().as_bytes())
        )
    })
}

#[derive(Debug, Deserialize)]
struct VmafLog {
    #[serde(default)]
    frames: Vec<VmafFrame>,
    #[serde(default)]
    pooled_metrics: BTreeMap<String, VmafPooled>,
}

#[derive(Debug, Deserialize)]
struct VmafFrame {
    #[serde(default)]
    metrics: BTreeMap<String, f64>,
}

#[derive(Debug, Deserialize)]
struct VmafPooled {
    #[serde(default)]
    mean: Option<f64>,
}

/// Convert one libvmaf JSON log into fixed-point evidence.
///
/// Every value is derived from the structured document; nothing is inferred by
/// pattern-matching FFmpeg's human-readable output. Missing or non-finite
/// metrics fail closed instead of defaulting to a passing score.
fn parse_vmaf_log(
    bytes: &[u8],
    eye: Eye,
    output_sha256: String,
    output_size_bytes: u64,
) -> Result<EyeMetrics, String> {
    let log: VmafLog = serde_json::from_slice(bytes)
        .map_err(|error| format!("quality measurement log was not valid JSON: {error}"))?;
    if log.frames.is_empty() {
        return Err("quality measurement log contained no frames".to_string());
    }

    let mut frame_vmaf_milli =
        Vec::with_capacity(log.frames.len().min(MAX_ARCHIVED_QUALITY_FRAMES));
    let mut all_frames = Vec::with_capacity(log.frames.len());
    for (index, frame) in log.frames.iter().enumerate() {
        let score = frame
            .metrics
            .get("vmaf")
            .copied()
            .ok_or_else(|| format!("frame {index} is missing its vmaf metric"))?;
        let milli = to_fixed_point(score, 0.0, 100.0, 1_000.0)
            .ok_or_else(|| format!("frame {index} reported an out-of-range vmaf score"))?;
        all_frames.push(milli);
        if frame_vmaf_milli.len() < MAX_ARCHIVED_QUALITY_FRAMES {
            frame_vmaf_milli.push(milli);
        }
    }
    let frames_complete = frame_vmaf_milli.len() == all_frames.len();

    // Pool from the structured document when libvmaf provides it, and
    // otherwise from the exact per-frame series just parsed.
    let vmaf_mean_milli = match log
        .pooled_metrics
        .get("vmaf")
        .and_then(|pooled| pooled.mean)
    {
        Some(mean) => to_fixed_point(mean, 0.0, 100.0, 1_000.0)
            .ok_or_else(|| "pooled vmaf mean is out of range".to_string())?,
        None => mean_fixed_point(&all_frames),
    };
    let ssim_mean = log
        .pooled_metrics
        .get("float_ssim")
        .or_else(|| log.pooled_metrics.get("ssim"))
        .and_then(|pooled| pooled.mean)
        .ok_or_else(|| "quality measurement log did not report a pooled SSIM mean".to_string())?;
    let ssim_mean_millionths = to_fixed_point(ssim_mean, 0.0, 1.0, 1_000_000.0)
        .ok_or_else(|| "pooled SSIM mean is out of range".to_string())?;

    Ok(EyeMetrics {
        eye,
        vmaf_mean_milli,
        vmaf_frame_p01_milli: frame_percentile_milli(&all_frames, 1),
        ssim_mean_millionths,
        frame_vmaf_milli,
        frames_complete,
        output_sha256,
        output_size_bytes,
    })
}

fn to_fixed_point(value: f64, minimum: f64, maximum: f64, scale: f64) -> Option<u32> {
    if !value.is_finite() || value < minimum - f64::EPSILON || value > maximum + f64::EPSILON {
        return None;
    }
    let clamped = value.clamp(minimum, maximum);
    let scaled = (clamped * scale).round();
    if scaled < 0.0 || scaled > f64::from(u32::MAX) {
        return None;
    }
    Some(scaled as u32)
}

fn mean_fixed_point(values: &[u32]) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let total: u64 = values.iter().map(|value| u64::from(*value)).sum();
    u32::try_from(total / values.len() as u64).unwrap_or(u32::MAX)
}

/// Lower-tail frame percentile. `p01` is the score 1% of frames fall below,
/// which is what catches a short, badly-encoded burst that a mean hides.
fn frame_percentile_milli(values: &[u32], percentile: u32) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() as u64 - 1) * u64::from(percentile) / 100) as usize;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(crf: u8) -> ExactEncodingProfile {
        ExactEncodingProfile {
            revision: format!("fixture-crf-{crf}"),
            encoder: "libx265".to_string(),
            codec_profile: "main".to_string(),
            pixel_format: "yuv420p".to_string(),
            sample_entry: "hvc1".to_string(),
            preset: "slow".to_string(),
            crf,
            time_base_denominator: 90_000,
            gop_seconds: 2,
            segment_seconds: 30,
        }
    }

    fn slice(path: &str, start: u64, end: u64, raw_mjpeg: bool) -> SourceSlice {
        SourceSlice {
            path: PathBuf::from(path),
            start_frame: start,
            end_frame_exclusive: end,
            raw_mjpeg,
        }
    }

    fn request(input: SegmentInput, crf: u8) -> EncodeCommandRequest {
        EncodeCommandRequest {
            input,
            frame_rate: FrameRate::checked(30, 1).unwrap(),
            eye_width: 1920,
            eye_height: 1080,
            expected_frames: 900,
            profile: profile(crf),
            left_partial: PathBuf::from("left.partial.mp4"),
            right_partial: PathBuf::from("right.partial.mp4"),
        }
    }

    fn utf8_args(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn source_preflight_hashes_the_no_follow_handle_against_the_sealed_digest() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("source.mp4");
        let bytes = b"source-bytes";
        std::fs::write(&path, bytes).expect("write source");
        let digest = ContentSha256::parse(format!("{:x}", Sha256::digest(bytes))).expect("digest");
        let artifact = ResolvedSourceArtifact::new(
            SourceArtifactId::parse("source").expect("artifact id"),
            path.clone(),
            "video/source.mp4",
            bytes.len() as u64,
            digest,
        )
        .expect("artifact");

        ensure_source_artifact_file(&artifact).expect("matching bytes pass");
        std::fs::write(&path, b"tamperXbytes").expect("tamper source");
        let error = ensure_source_artifact_file(&artifact).expect_err("digest mismatch");
        assert!(error.contains("digest does not match"));
    }

    #[test]
    #[cfg(unix)]
    fn source_preflight_rejects_a_leaf_symlink_before_hashing() {
        let directory = tempfile::tempdir().expect("tempdir");
        let target = directory.path().join("target.mp4");
        let link = directory.path().join("link.mp4");
        std::fs::write(&target, b"source-bytes").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let digest =
            ContentSha256::parse(format!("{:x}", Sha256::digest(b"source-bytes"))).expect("digest");
        let artifact = ResolvedSourceArtifact::new(
            SourceArtifactId::parse("link").expect("artifact id"),
            link,
            "video/link.mp4",
            12,
            digest,
        )
        .expect("artifact");

        let error = ensure_source_artifact_file(&artifact).expect_err("symlink rejected");
        assert!(error.contains("without following links"));
    }

    #[test]
    fn raw_mjpeg_plan_decodes_once_then_crops_both_eyes() {
        let args = utf8_args(
            &build_encode_args(&request(
                SegmentInput::RawStereoMjpeg(vec![slice("stereo.mjpeg", 0, 900, true)]),
                20,
            ))
            .unwrap(),
        );
        assert!(args.windows(2).any(|pair| pair == ["-f", "mjpeg"]));
        let filters = args
            .windows(2)
            .find(|pair| pair[0] == "-filter_complex")
            .unwrap()[1]
            .clone();
        assert!(filters.contains("split=2"));
        assert!(filters.contains("crop=1920:1080:0:0"));
        assert!(filters.contains("crop=1920:1080:1920:0"));
    }

    #[test]
    fn every_source_family_uses_real_libx265_encode_with_profile_crf() {
        let families = [
            SegmentInput::RawStereoMjpeg(vec![slice("raw.mjpeg", 0, 900, true)]),
            SegmentInput::LegacyV5StereoMjpeg(vec![slice("legacy.mp4", 0, 900, false)]),
            SegmentInput::SpoolV6StereoMjpeg(vec![slice("spool.mp4", 0, 900, false)]),
            SegmentInput::PublishedStereoPairs {
                left: vec![slice("left.mp4", 0, 900, false)],
                right: vec![slice("right.mp4", 0, 900, false)],
            },
        ];
        for input in families {
            let args = utf8_args(&build_encode_args(&request(input, 17)).unwrap());
            assert_eq!(args.iter().filter(|arg| *arg == "libx265").count(), 2);
            assert_eq!(args.iter().filter(|arg| *arg == "17").count(), 2);
            assert!(!args.iter().any(|arg| arg == "copy"));
        }
    }

    #[test]
    fn output_contract_is_closed_gop_hvc1_yuv420p_and_ninety_khz() {
        let args = utf8_args(
            &build_encode_args(&request(
                SegmentInput::SpoolV6StereoMjpeg(vec![slice("spool.mp4", 0, 900, false)]),
                20,
            ))
            .unwrap(),
        );
        let joined = args.join(" ");
        assert!(joined.contains("-profile:v main"));
        assert!(joined.contains("-pix_fmt yuv420p"));
        assert!(joined.contains("-tag:v hvc1"));
        assert!(joined.contains("-video_track_timescale 90000"));
        assert!(joined.contains("keyint=60:min-keyint=60:scenecut=0:open-gop=0"));
    }

    #[test]
    fn crf_has_no_implicit_default_or_generation_guess() {
        let mut missing = profile(20);
        missing.preset.clear();
        let mut request = request(
            SegmentInput::RawStereoMjpeg(vec![slice("raw.mjpeg", 0, 900, true)]),
            20,
        );
        request.profile = missing;
        assert!(build_encode_args(&request).is_err());
    }

    #[test]
    fn process_diagnostics_are_bounded_and_terminal_safe() {
        let mut raw = b"failure\n\x1b[31m".to_vec();
        raw.extend(std::iter::repeat_n(b'x', MAX_PROCESS_DIAGNOSTIC_BYTES + 10));
        let sanitized = sanitize_process_diagnostic(&raw);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\u{1b}'));
        assert!(sanitized.ends_with(PROCESS_TEXT_TRUNCATION_MARKER));
    }

    #[test]
    fn ffprobe_is_always_requested_as_structured_json() {
        let args = utf8_args(&probe_args(Path::new("segment.mp4"), true, None));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-print_format", "json"]));
        assert!(args.iter().any(|arg| arg == "-show_streams"));
        assert!(args.iter().any(|arg| arg == "-show_frames"));
    }

    #[test]
    fn paths_are_individual_os_arguments_not_a_shell_command() {
        let unusual = "source name; touch SHOULD_NOT_EXIST.mp4";
        let args = build_encode_args(&request(
            SegmentInput::RawStereoMjpeg(vec![slice(unusual, 0, 900, true)]),
            20,
        ))
        .unwrap();
        assert!(args.iter().any(|arg| arg == OsStr::new(unusual)));
        assert!(!args.iter().any(|arg| arg == OsStr::new("sh")));
    }

    fn stereo_response(metrics: BTreeMap<String, i64>) -> StereoDomainWireResponse {
        StereoDomainWireResponse {
            protocol: STEREO_DOMAIN_PROTOCOL.to_string(),
            evaluator_identity: "test-evaluator".to_string(),
            evaluator_revision: "test-revision".to_string(),
            passed: true,
            metrics,
        }
    }

    #[test]
    fn external_evaluator_requires_all_environment_identity_fields() {
        let error = ExternalStereoDomainEvaluator::from_environment_values(
            None,
            Some("test-evaluator".to_string()),
            Some("test-revision".to_string()),
            Duration::from_secs(1),
        )
        .expect_err("missing executable must remain a capability failure");
        assert_eq!(error, "YLX_STEREO_DOMAIN_EVALUATOR is not configured");

        let error = ExternalStereoDomainEvaluator::from_environment_values(
            Some(PathBuf::from("evaluator")),
            None,
            Some("test-revision".to_string()),
            Duration::from_secs(1),
        )
        .expect_err("missing identity must remain a capability failure");
        assert_eq!(error, "YLX_STEREO_DOMAIN_EVALUATOR_ID is not configured");
    }

    #[test]
    fn external_evaluator_rejects_identity_revision_and_protocol_mismatch() {
        let mut response = stereo_response(BTreeMap::from([(String::from("score"), 1)]));
        response.evaluator_identity = "other".to_string();
        assert!(
            validate_stereo_domain_response(response, "test-evaluator", "test-revision")
                .expect_err("identity mismatch must fail closed")
                .contains("identity or revision")
        );

        let mut response = stereo_response(BTreeMap::from([(String::from("score"), 1)]));
        response.evaluator_revision = "other".to_string();
        assert!(
            validate_stereo_domain_response(response, "test-evaluator", "test-revision")
                .expect_err("revision mismatch must fail closed")
                .contains("identity or revision")
        );

        let mut response = stereo_response(BTreeMap::from([(String::from("score"), 1)]));
        response.protocol = "ylx-transfer/stereo-domain-evaluator-v0".to_string();
        assert!(
            validate_stereo_domain_response(response, "test-evaluator", "test-revision")
                .expect_err("protocol mismatch must fail closed")
                .contains("protocol revision")
        );
    }

    #[test]
    fn external_evaluator_rejects_empty_oversized_and_unsafe_metrics() {
        let empty = stereo_response(BTreeMap::new());
        assert!(
            validate_stereo_domain_response(empty, "test-evaluator", "test-revision")
                .expect_err("empty metrics must fail closed")
                .contains("invalid metric set")
        );

        let oversized = stereo_response(
            (0..=MAX_STEREO_DOMAIN_METRICS)
                .map(|index| (format!("metric-{index}"), index as i64))
                .collect(),
        );
        assert!(
            validate_stereo_domain_response(oversized, "test-evaluator", "test-revision",)
                .expect_err("oversized metrics must fail closed")
                .contains("invalid metric set")
        );

        let unsafe_key = stereo_response(BTreeMap::from([("bad\nkey".to_string(), 1)]));
        assert!(
            validate_stereo_domain_response(unsafe_key, "test-evaluator", "test-revision",)
                .expect_err("unsafe metric keys must fail closed")
                .contains("unsafe metric key")
        );
    }

    #[test]
    fn external_evaluator_rejects_malformed_wire_response() {
        let error = serde_json::from_slice::<StereoDomainWireResponse>(b"not-json")
            .expect_err("malformed evaluator output must not decode");
        assert!(!error.to_string().is_empty());
    }
}
