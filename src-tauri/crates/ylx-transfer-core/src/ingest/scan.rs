//! Bounded, non-recursive discovery of recording candidates.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::detector::{detect_candidate, DetectionContext, DetectionResult};
use super::identity::{AcquisitionSourceId, MediaGeneration};
use super::path::{resolve_directory_no_links, SafeRelativePath};
use super::source::{CandidateReadiness, ScanCandidate, SourceKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanLimits {
    maximum_directory_entries: usize,
    maximum_candidates: usize,
    maximum_manifest_bytes: u64,
    maximum_auxiliary_index_bytes: u64,
    maximum_index_records: usize,
    maximum_files_per_candidate: usize,
    maximum_path_bytes: usize,
    maximum_path_components: usize,
    maximum_declared_bytes_per_candidate: u64,
}

impl ScanLimits {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maximum_directory_entries: usize,
        maximum_candidates: usize,
        maximum_manifest_bytes: u64,
        maximum_auxiliary_index_bytes: u64,
        maximum_index_records: usize,
        maximum_files_per_candidate: usize,
        maximum_path_bytes: usize,
        maximum_path_components: usize,
        maximum_declared_bytes_per_candidate: u64,
    ) -> Result<Self, ScanConfigurationError> {
        if maximum_directory_entries == 0
            || maximum_candidates == 0
            || maximum_manifest_bytes == 0
            || maximum_auxiliary_index_bytes == 0
            || maximum_index_records == 0
            || maximum_files_per_candidate == 0
            || maximum_path_bytes == 0
            || maximum_path_components == 0
            || maximum_declared_bytes_per_candidate == 0
        {
            return Err(ScanConfigurationError::ZeroLimit);
        }
        Ok(Self {
            maximum_directory_entries,
            maximum_candidates,
            maximum_manifest_bytes,
            maximum_auxiliary_index_bytes,
            maximum_index_records,
            maximum_files_per_candidate,
            maximum_path_bytes,
            maximum_path_components,
            maximum_declared_bytes_per_candidate,
        })
    }

    pub(crate) fn maximum_manifest_bytes(&self) -> u64 {
        self.maximum_manifest_bytes
    }

    pub(crate) fn maximum_auxiliary_index_bytes(&self) -> u64 {
        self.maximum_auxiliary_index_bytes
    }

    pub(crate) fn maximum_index_records(&self) -> usize {
        self.maximum_index_records
    }

    pub(crate) fn maximum_files_per_candidate(&self) -> usize {
        self.maximum_files_per_candidate
    }

    pub(crate) fn maximum_path_bytes(&self) -> usize {
        self.maximum_path_bytes
    }

    pub(crate) fn maximum_path_components(&self) -> usize {
        self.maximum_path_components
    }

    pub(crate) fn maximum_declared_bytes_per_candidate(&self) -> u64 {
        self.maximum_declared_bytes_per_candidate
    }
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            maximum_directory_entries: 2_048,
            maximum_candidates: 512,
            maximum_manifest_bytes: 2 * 1024 * 1024,
            maximum_auxiliary_index_bytes: 64 * 1024 * 1024,
            maximum_index_records: 5_000_000,
            maximum_files_per_candidate: 20_000,
            maximum_path_bytes: 1_024,
            maximum_path_components: 32,
            maximum_declared_bytes_per_candidate: 16 * 1024 * 1024 * 1024 * 1024,
        }
    }
}

/// The fixed recording containers probed at the root of a mounted volume, in
/// probe order. A mounted-volume scan never walks a card recursively, so every
/// supported layout has to be named here explicitly.
///
/// `recordings/` and `YLX_RECORDINGS/` are the flat layouts written by a card
/// dedicated to capture. The third entry is the Ubuntu Core layout: there the
/// volume root is the `ubuntu-data` partition root, and the capture snap's
/// writable data lives under `system-data/`, so its recordings sit five
/// components below the mount point rather than directly under it.
pub const MOUNTED_VOLUME_RECORDING_CONTAINERS: &[&str] = &[
    "recordings",
    "YLX_RECORDINGS",
    "system-data/var/snap/ylx-capture/common/recordings",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanScope {
    MountedVolume,
    SelectedDirectory,
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    root: PathBuf,
    source_id: AcquisitionSourceId,
    media_generation: Option<MediaGeneration>,
    source_kind: SourceKind,
    scope: ScanScope,
}

impl ScanRequest {
    pub fn mounted_volume(
        root: impl Into<PathBuf>,
        source_id: AcquisitionSourceId,
        media_generation: MediaGeneration,
    ) -> Result<Self, ScanConfigurationError> {
        Self::new(
            root.into(),
            source_id,
            Some(media_generation),
            SourceKind::RemovableMedia,
            ScanScope::MountedVolume,
        )
    }

    pub fn selected_directory(
        root: impl Into<PathBuf>,
        source_id: AcquisitionSourceId,
        source_kind: SourceKind,
        media_generation: Option<MediaGeneration>,
    ) -> Result<Self, ScanConfigurationError> {
        Self::new(
            root.into(),
            source_id,
            media_generation,
            source_kind,
            ScanScope::SelectedDirectory,
        )
    }

    fn new(
        root: PathBuf,
        source_id: AcquisitionSourceId,
        media_generation: Option<MediaGeneration>,
        source_kind: SourceKind,
        scope: ScanScope,
    ) -> Result<Self, ScanConfigurationError> {
        if !root.is_absolute() {
            return Err(ScanConfigurationError::RootMustBeAbsolute);
        }
        if matches!(scope, ScanScope::MountedVolume) && media_generation.is_none() {
            return Err(ScanConfigurationError::MountedVolumeNeedsGeneration);
        }
        Ok(Self {
            root,
            source_id,
            media_generation,
            source_kind,
            scope,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn source_id(&self) -> &AcquisitionSourceId {
        &self.source_id
    }

    #[must_use]
    pub fn media_generation(&self) -> Option<&MediaGeneration> {
        self.media_generation.as_ref()
    }

    #[must_use]
    pub fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    #[must_use]
    pub fn scope(&self) -> ScanScope {
        self.scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDiagnosticCode {
    RootUnavailable,
    DirectoryEntryLimitExceeded,
    CandidateLimitExceeded,
    ManifestTooLarge,
    AuxiliaryIndexTooLarge,
    FileCountLimitExceeded,
    DeclaredBytesLimitExceeded,
    UnsafeRelativePath,
    NonRegularFile,
    MissingRequiredFile,
    SizeMismatch,
    InvalidManifest,
    InvalidFrameIndex,
    IncompleteRecording,
    UnsupportedLegacySchema,
    UnknownSchema,
    NoRecognizedMarker,
    ConflictingEvidence,
    /// The recording container exists but the current user may not read it.
    /// This is kept apart from `Io` because it is the one scan failure that is
    /// about who is asking rather than about the card, and it is the difference
    /// between "this card holds nothing" and "this card will not show you what
    /// it holds".
    PermissionDenied,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDiagnostic {
    code: ScanDiagnosticCode,
    severity: ScanDiagnosticSeverity,
    message: String,
}

impl ScanDiagnostic {
    #[must_use]
    pub(crate) fn error(code: ScanDiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: ScanDiagnosticSeverity::Error,
            message: bounded_message(message.into()),
        }
    }

    #[must_use]
    pub(crate) fn warning(code: ScanDiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: ScanDiagnosticSeverity::Warning,
            message: bounded_message(message.into()),
        }
    }

    #[must_use]
    pub fn code(&self) -> ScanDiagnosticCode {
        self.code
    }

    #[must_use]
    pub fn severity(&self) -> ScanDiagnosticSeverity {
        self.severity
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ScanItemOutcome {
    Candidate {
        candidate: Box<ScanCandidate>,
    },
    Rejected {
        readiness: CandidateReadiness,
        diagnostics: Vec<ScanDiagnostic>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanItem {
    candidate_relative_path: Option<SafeRelativePath>,
    outcome: ScanItemOutcome,
}

impl ScanItem {
    #[must_use]
    pub fn candidate_relative_path(&self) -> Option<&SafeRelativePath> {
        self.candidate_relative_path.as_ref()
    }

    #[must_use]
    pub fn outcome(&self) -> &ScanItemOutcome {
        &self.outcome
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScanStatistics {
    directories_observed: usize,
    candidates_examined: usize,
    candidates_admissible: usize,
    candidates_rejected: usize,
}

impl ScanStatistics {
    #[must_use]
    pub fn directories_observed(&self) -> usize {
        self.directories_observed
    }

    #[must_use]
    pub fn candidates_examined(&self) -> usize {
        self.candidates_examined
    }

    #[must_use]
    pub fn candidates_admissible(&self) -> usize {
        self.candidates_admissible
    }

    #[must_use]
    pub fn candidates_rejected(&self) -> usize {
        self.candidates_rejected
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanSnapshot {
    source_id: AcquisitionSourceId,
    media_generation: Option<MediaGeneration>,
    items: Vec<ScanItem>,
    root_diagnostics: Vec<ScanDiagnostic>,
    statistics: ScanStatistics,
    truncated: bool,
}

impl ScanSnapshot {
    #[must_use]
    pub fn source_id(&self) -> &AcquisitionSourceId {
        &self.source_id
    }

    #[must_use]
    pub fn media_generation(&self) -> Option<&MediaGeneration> {
        self.media_generation.as_ref()
    }

    #[must_use]
    pub fn items(&self) -> &[ScanItem] {
        &self.items
    }

    pub fn candidates(&self) -> impl Iterator<Item = &ScanCandidate> {
        self.items.iter().filter_map(|item| match &item.outcome {
            ScanItemOutcome::Candidate { candidate } => Some(candidate.as_ref()),
            ScanItemOutcome::Rejected { .. } => None,
        })
    }

    #[must_use]
    pub fn root_diagnostics(&self) -> &[ScanDiagnostic] {
        &self.root_diagnostics
    }

    #[must_use]
    pub fn statistics(&self) -> &ScanStatistics {
        &self.statistics
    }

    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Debug, Clone)]
pub struct ConstrainedScanner {
    limits: ScanLimits,
}

impl ConstrainedScanner {
    #[must_use]
    pub fn new(limits: ScanLimits) -> Self {
        Self { limits }
    }

    #[must_use]
    pub fn limits(&self) -> &ScanLimits {
        &self.limits
    }

    /// Scan either exactly one user-selected directory or the fixed recording
    /// containers in [`MOUNTED_VOLUME_RECORDING_CONTAINERS`] and their direct
    /// children. It never recursively walks a card and never opens an artifact
    /// not named by a recognized schema.
    #[must_use]
    pub fn scan(&self, request: &ScanRequest) -> ScanSnapshot {
        let mut snapshot = ScanSnapshot {
            source_id: request.source_id.clone(),
            media_generation: request.media_generation.clone(),
            items: Vec::new(),
            root_diagnostics: Vec::new(),
            statistics: ScanStatistics::default(),
            truncated: false,
        };

        let root_metadata = match fs::symlink_metadata(&request.root) {
            Ok(metadata) => metadata,
            Err(error) => {
                snapshot.root_diagnostics.push(ScanDiagnostic::error(
                    ScanDiagnosticCode::RootUnavailable,
                    format!("scan root is unavailable: {error}"),
                ));
                return snapshot;
            }
        };
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            snapshot.root_diagnostics.push(ScanDiagnostic::error(
                ScanDiagnosticCode::RootUnavailable,
                "scan root must be a real directory, not a link or special entry",
            ));
            return snapshot;
        }

        match request.scope {
            ScanScope::SelectedDirectory => {
                self.inspect_candidate(request, None, &request.root, &mut snapshot);
            }
            ScanScope::MountedVolume => {
                for container_name in MOUNTED_VOLUME_RECORDING_CONTAINERS.iter().copied() {
                    if snapshot.truncated {
                        break;
                    }
                    self.scan_container(request, container_name, &mut snapshot);
                }
            }
        }
        snapshot
    }

    fn scan_container(
        &self,
        request: &ScanRequest,
        container_name: &str,
        snapshot: &mut ScanSnapshot,
    ) {
        let container_relative = SafeRelativePath::parse(container_name)
            .expect("fixed recording-root name is a safe path");
        let container = match resolve_directory_no_links(&request.root, &container_relative) {
            Ok(path) => path,
            Err(super::path::PathSafetyError::Inspection { .. }) => return,
            Err(error) => {
                snapshot.root_diagnostics.push(ScanDiagnostic::error(
                    ScanDiagnosticCode::NonRegularFile,
                    format!("recording root {container_name:?} is unsafe: {error}"),
                ));
                return;
            }
        };

        let entries = match fs::read_dir(&container) {
            Ok(entries) => entries,
            Err(error) => {
                let code = if error.kind() == io::ErrorKind::PermissionDenied {
                    ScanDiagnosticCode::PermissionDenied
                } else {
                    ScanDiagnosticCode::Io
                };
                snapshot.root_diagnostics.push(ScanDiagnostic::error(
                    code,
                    format!("recording root {container_name:?} cannot be listed: {error}"),
                ));
                return;
            }
        };
        let mut children = Vec::new();
        for entry in entries {
            snapshot.statistics.directories_observed =
                snapshot.statistics.directories_observed.saturating_add(1);
            if snapshot.statistics.directories_observed > self.limits.maximum_directory_entries {
                snapshot.root_diagnostics.push(ScanDiagnostic::error(
                    ScanDiagnosticCode::DirectoryEntryLimitExceeded,
                    "mounted-volume directory-entry limit was exceeded",
                ));
                snapshot.truncated = true;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    snapshot.root_diagnostics.push(ScanDiagnostic::warning(
                        ScanDiagnosticCode::Io,
                        format!("one recording directory entry could not be read: {error}"),
                    ));
                    continue;
                }
            };
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                snapshot.root_diagnostics.push(ScanDiagnostic::warning(
                    ScanDiagnosticCode::UnsafeRelativePath,
                    "one recording directory name is not valid UTF-8",
                ));
                continue;
            };
            let relative_text = format!("{container_name}/{name}");
            let relative = match SafeRelativePath::parse(relative_text.clone()) {
                Ok(relative) => relative,
                Err(error) => {
                    snapshot.items.push(ScanItem {
                        candidate_relative_path: None,
                        outcome: ScanItemOutcome::Rejected {
                            readiness: CandidateReadiness::UnsafePath,
                            diagnostics: vec![ScanDiagnostic::error(
                                ScanDiagnosticCode::UnsafeRelativePath,
                                format!("candidate path {relative_text:?} is unsafe: {error}"),
                            )],
                        },
                    });
                    continue;
                }
            };
            match resolve_directory_no_links(&request.root, &relative) {
                Ok(path) => children.push((relative, path)),
                Err(error) => snapshot.items.push(ScanItem {
                    candidate_relative_path: Some(relative),
                    outcome: ScanItemOutcome::Rejected {
                        readiness: CandidateReadiness::UnsafePath,
                        diagnostics: vec![ScanDiagnostic::error(
                            ScanDiagnosticCode::NonRegularFile,
                            format!("candidate entry is not a safe directory: {error}"),
                        )],
                    },
                }),
            }
        }
        children.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        for (relative, path) in children {
            if snapshot.statistics.candidates_examined >= self.limits.maximum_candidates {
                snapshot.root_diagnostics.push(ScanDiagnostic::error(
                    ScanDiagnosticCode::CandidateLimitExceeded,
                    "mounted-volume candidate limit was exceeded",
                ));
                snapshot.truncated = true;
                break;
            }
            self.inspect_candidate(request, Some(relative), &path, snapshot);
        }
    }

    fn inspect_candidate(
        &self,
        request: &ScanRequest,
        candidate_relative_path: Option<SafeRelativePath>,
        candidate_root: &Path,
        snapshot: &mut ScanSnapshot,
    ) {
        snapshot.statistics.candidates_examined =
            snapshot.statistics.candidates_examined.saturating_add(1);
        let context = DetectionContext {
            candidate_root,
            candidate_relative_path: candidate_relative_path.clone(),
            source_id: &request.source_id,
            media_generation: request.media_generation.as_ref(),
            source_kind: request.source_kind,
            limits: &self.limits,
        };
        let outcome = match detect_candidate(&context) {
            DetectionResult::Candidate(candidate) => {
                snapshot.statistics.candidates_admissible =
                    snapshot.statistics.candidates_admissible.saturating_add(1);
                ScanItemOutcome::Candidate { candidate }
            }
            DetectionResult::Rejected {
                readiness,
                diagnostics,
            } => {
                snapshot.statistics.candidates_rejected =
                    snapshot.statistics.candidates_rejected.saturating_add(1);
                ScanItemOutcome::Rejected {
                    readiness,
                    diagnostics,
                }
            }
        };
        snapshot.items.push(ScanItem {
            candidate_relative_path,
            outcome,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanConfigurationError {
    #[error("all scan limits must be greater than zero")]
    ZeroLimit,
    #[error("scan root must be an absolute path")]
    RootMustBeAbsolute,
    #[error("mounted-volume scans require a media-generation fence")]
    MountedVolumeNeedsGeneration,
}

fn bounded_message(mut message: String) -> String {
    const MAXIMUM_MESSAGE_BYTES: usize = 1_024;
    message.retain(|character| !character.is_control() || character == ' ');
    if message.len() <= MAXIMUM_MESSAGE_BYTES {
        return message;
    }
    let mut boundary = MAXIMUM_MESSAGE_BYTES;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}
