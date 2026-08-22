//! Read-only [`ArtifactSource`] for an already-admitted mounted recording.
//!
//! This adapter deliberately starts after volume discovery and recording
//! admission.  It receives an allowlist of [`SourceArtifactClaim`] values and
//! never treats an opaque artifact id as a path.  Every open is fenced by the
//! admitted source revision and one live media-generation lease, resolves the
//! claim's relative path component by component without following links, and
//! opens only a regular file for reading.
//!
//! The response body owns the volume read lease for exactly as long as it owns
//! the file handle.  Reads are capped, and both the media generation and the
//! open file's metadata identity are checked before and after each operating
//! system read.  Dropping the body closes the file before releasing the lease;
//! this is the cancellation boundary used by import jobs and safe eject.
//!
//! No code in this module creates, truncates, renames, removes, or otherwise
//! opens a source path for writing.  Checkpoints, partial files, hashes, and
//! revision commits belong on the PC staging volume, outside this adapter.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use ylx_transfer_core::ingest::{
    open_regular_file_beneath, ArtifactBodyReadError, ArtifactOpenOutcome, ArtifactReadRequest,
    ArtifactSource, ArtifactSourceError, MediaGenerationId, PathSafetyError, SourceArtifactClaim,
    SourceArtifactId, SourceRevisionClaim,
};

/// Maximum number of source bytes passed to one operating-system read.
///
/// A caller can provide a larger buffer, but removable-media latency and
/// cancellation remain bounded by this chunk.  The import coordinator is free
/// to use a smaller buffer.
pub const MAX_MOUNTED_READ_BYTES: usize = 256 * 1024;

/// Live state of the exact mounted-media generation protected by a read lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaFenceStatus {
    Current,
    Unavailable,
    Changed { observed: Option<MediaGenerationId> },
}

/// Failure to acquire a reader for an expected mounted-media generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaFenceError {
    Unavailable { message: String },
    Changed { observed: Option<MediaGenerationId> },
    Io { message: String },
}

impl fmt::Display for MediaFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { message } => {
                write!(formatter, "mounted media is unavailable: {message}")
            }
            Self::Changed { .. } => formatter.write_str("mounted media generation changed"),
            Self::Io { message } => write!(formatter, "media catalog failed: {message}"),
        }
    }
}

impl Error for MediaFenceError {}

/// Generation-scoped lease held by an open artifact body.
///
/// Implementations should make removal/release visible through [`Self::status`]
/// and decrement their active-reader count on `Drop`.
pub trait MediaReadLease: Send {
    fn generation(&self) -> &MediaGenerationId;
    fn status(&self) -> MediaFenceStatus;
}

/// Port supplied by mounted-volume discovery/ownership.
///
/// It is intentionally expressed only in terms of generation identity and a
/// reader lease.  Mount paths, bus type, drive letters, raw devices, and eject
/// APIs do not cross the artifact-byte seam.
pub trait MediaReadLeaseProvider: Send + Sync {
    fn acquire(
        &self,
        expected: &MediaGenerationId,
    ) -> Result<Box<dyn MediaReadLease>, MediaFenceError>;

    /// Authorize the root reparse point used by a Windows directory-mounted
    /// volume.  The default rejects it.  A volume catalog may return `true`
    /// only when `root` is one of the OS-enumerated mount paths bound to the
    /// exact admitted generation; user-selected directories never opt in.
    fn allows_volume_mount_reparse_root(
        &self,
        _expected: &MediaGenerationId,
        _root: &Path,
    ) -> bool {
        false
    }
}

/// Invalid adapter construction.  Construction is pure: it validates the
/// immutable allowlist but does not require the card to be present, which is
/// what lets a durable job remain in `waiting_for_media` across restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountedFileConfigError {
    RootMustBeAbsolute,
    EmptyInventory,
    DuplicateArtifact { file_id: SourceArtifactId },
}

impl fmt::Display for MountedFileConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMustBeAbsolute => {
                formatter.write_str("mounted media root must be an absolute path")
            }
            Self::EmptyInventory => formatter.write_str("mounted artifact inventory is empty"),
            Self::DuplicateArtifact { file_id } => {
                write!(formatter, "duplicate mounted artifact id {file_id}")
            }
        }
    }
}

impl Error for MountedFileConfigError {}

/// File-level byte adapter for one admitted recording on one media generation.
pub struct MountedFileArtifactAdapter {
    mount_root: PathBuf,
    media_generation: MediaGenerationId,
    source_revision: SourceRevisionClaim,
    artifacts: BTreeMap<SourceArtifactId, SourceArtifactClaim>,
    leases: Arc<dyn MediaReadLeaseProvider>,
}

impl fmt::Debug for MountedFileArtifactAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MountedFileArtifactAdapter")
            .field("media_generation", &self.media_generation)
            .field("source_revision", &self.source_revision)
            .field("artifact_count", &self.artifacts.len())
            .finish_non_exhaustive()
    }
}

impl MountedFileArtifactAdapter {
    /// Bind an admitted inventory to its current mount locator and generation.
    ///
    /// `mount_root` is a platform file-level mount path.  This module never
    /// opens a physical disk, raw volume, or privileged device handle.
    pub fn new<I>(
        mount_root: impl Into<PathBuf>,
        media_generation: MediaGenerationId,
        source_revision: SourceRevisionClaim,
        artifacts: I,
        leases: Arc<dyn MediaReadLeaseProvider>,
    ) -> Result<Self, MountedFileConfigError>
    where
        I: IntoIterator<Item = SourceArtifactClaim>,
    {
        let mount_root = mount_root.into();
        if !mount_root.is_absolute() {
            return Err(MountedFileConfigError::RootMustBeAbsolute);
        }

        let mut by_id = BTreeMap::new();
        for artifact in artifacts {
            let file_id = artifact.id().clone();
            if by_id.insert(file_id.clone(), artifact).is_some() {
                return Err(MountedFileConfigError::DuplicateArtifact { file_id });
            }
        }
        if by_id.is_empty() {
            return Err(MountedFileConfigError::EmptyInventory);
        }

        Ok(Self {
            mount_root,
            media_generation,
            source_revision,
            artifacts: by_id,
            leases,
        })
    }

    #[must_use]
    pub fn media_generation(&self) -> &MediaGenerationId {
        &self.media_generation
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceRevisionClaim {
        &self.source_revision
    }

    /// Return the frozen size/hash/path claim used for this id.  This is
    /// evidence for the import owner's streaming SHA-256 verification; the
    /// adapter itself never performs a second unbounded pre-read of the card.
    #[must_use]
    pub fn artifact_claim(&self, file_id: &SourceArtifactId) -> Option<&SourceArtifactClaim> {
        self.artifacts.get(file_id)
    }

    fn acquire_lease(
        &self,
        expected: &MediaGenerationId,
    ) -> Result<Box<dyn MediaReadLease>, OpenInterruption> {
        let lease = self.leases.acquire(expected).map_err(|error| match error {
            MediaFenceError::Unavailable { message } => {
                OpenInterruption::Error(ArtifactSourceError::Unavailable { message })
            }
            MediaFenceError::Changed { observed } => {
                OpenInterruption::Outcome(ArtifactOpenOutcome::MediaChanged {
                    observed_generation: observed,
                })
            }
            MediaFenceError::Io { message } => {
                OpenInterruption::Error(ArtifactSourceError::Io { message })
            }
        })?;

        if lease.generation() != expected {
            return Err(OpenInterruption::Outcome(
                ArtifactOpenOutcome::MediaChanged {
                    observed_generation: Some(lease.generation().clone()),
                },
            ));
        }
        match lease.status() {
            MediaFenceStatus::Current => Ok(lease),
            MediaFenceStatus::Unavailable => {
                Err(OpenInterruption::Error(ArtifactSourceError::Unavailable {
                    message: "mounted media disappeared before the artifact was opened".to_string(),
                }))
            }
            MediaFenceStatus::Changed { observed } => Err(OpenInterruption::Outcome(
                ArtifactOpenOutcome::MediaChanged {
                    observed_generation: observed,
                },
            )),
        }
    }
}

impl ArtifactSource for MountedFileArtifactAdapter {
    fn open(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<ArtifactOpenOutcome, ArtifactSourceError> {
        let Some(expected_generation) = request.expected_media_generation.as_ref() else {
            return Err(ArtifactSourceError::ProtocolViolation {
                message: "mounted artifact read omitted its media-generation fence".to_string(),
            });
        };

        if expected_generation != &self.media_generation {
            return Ok(ArtifactOpenOutcome::MediaChanged {
                observed_generation: Some(self.media_generation.clone()),
            });
        }
        if request.expected_revision != self.source_revision {
            return Ok(ArtifactOpenOutcome::PreconditionFailed {
                current_revision: Some(self.source_revision.clone()),
            });
        }

        let Some(claim) = self.artifacts.get(&request.file_id) else {
            return Err(ArtifactSourceError::UnsafeArtifact {
                file_id: request.file_id,
                reason: "artifact id is not in the admitted inventory allowlist".to_string(),
            });
        };

        let lease = match self.acquire_lease(expected_generation) {
            Ok(lease) => lease,
            Err(interruption) => return interruption.finish(),
        };
        let mut opened = match open_regular_file_beneath(&self.mount_root, claim.relative_path()) {
            Ok(opened) => opened,
            Err(error) if path_safety_error_is_open_io(&error) => {
                return classify_open_io(
                    &*lease,
                    expected_generation,
                    &request.expected_revision,
                    path_safety_io_error(&error),
                    true,
                )
                .finish()
            }
            Err(error) => {
                return Err(ArtifactSourceError::UnsafeArtifact {
                    file_id: request.file_id,
                    reason: error.to_string(),
                })
            }
        };

        if opened.len() != claim.size_bytes() {
            return Ok(ArtifactOpenOutcome::PreconditionFailed {
                current_revision: None,
            });
        }

        let handle_metadata = match opened.file_mut().metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                return classify_open_io(
                    &*lease,
                    expected_generation,
                    &request.expected_revision,
                    error,
                    true,
                )
                .finish()
            }
        };

        if !handle_metadata.is_file() || handle_metadata.len() != claim.size_bytes() {
            return Ok(ArtifactOpenOutcome::PreconditionFailed {
                current_revision: None,
            });
        }

        match lease.status() {
            MediaFenceStatus::Current => {}
            MediaFenceStatus::Unavailable => {
                return Err(ArtifactSourceError::Unavailable {
                    message: "mounted media disappeared while opening the artifact".to_string(),
                })
            }
            MediaFenceStatus::Changed { observed } => {
                return Ok(ArtifactOpenOutcome::MediaChanged {
                    observed_generation: observed,
                })
            }
        }

        let total_bytes = claim.size_bytes();
        if request.offset > total_bytes {
            return Ok(ArtifactOpenOutcome::NotSatisfiable {
                total_bytes: Some(total_bytes),
            });
        }
        if request.offset == total_bytes {
            return Ok(ArtifactOpenOutcome::EndOfFile {
                revision: self.source_revision.clone(),
                total_bytes,
            });
        }
        let mut file = opened.into_file();
        if let Err(error) = file.seek(SeekFrom::Start(request.offset)) {
            return classify_open_io(
                &*lease,
                expected_generation,
                &request.expected_revision,
                error,
                true,
            )
            .finish();
        }

        let body = MountedArtifactBody {
            // Drop order is made explicit by `Drop`: close the file first,
            // then release the generation reader lease.
            file: Some(file),
            lease: Some(lease),
            expected_generation: expected_generation.clone(),
            expected_revision: self.source_revision.clone(),
            expected_sha256: claim.source_sha256().map(str::to_owned),
            full_hasher: (request.offset == 0 && claim.source_sha256().is_some()).then(Sha256::new),
            fingerprint: FileFingerprint::from_metadata(&handle_metadata),
            position: request.offset,
            total_bytes,
        };

        if request.offset == 0 {
            Ok(ArtifactOpenOutcome::FullFromZero {
                revision: self.source_revision.clone(),
                total_bytes,
                body: Box::new(body),
            })
        } else {
            Ok(ArtifactOpenOutcome::Partial {
                revision: self.source_revision.clone(),
                start: request.offset,
                end_inclusive: total_bytes - 1,
                total_bytes,
                body: Box::new(body),
            })
        }
    }
}

enum OpenInterruption {
    Outcome(ArtifactOpenOutcome),
    Error(ArtifactSourceError),
}

impl OpenInterruption {
    fn finish(self) -> Result<ArtifactOpenOutcome, ArtifactSourceError> {
        match self {
            Self::Outcome(outcome) => Ok(outcome),
            Self::Error(error) => Err(error),
        }
    }
}

fn path_safety_io_error(error: &PathSafetyError) -> io::Error {
    match error {
        PathSafetyError::Inspection { kind, message, .. } => io::Error::new(*kind, message.clone()),
        _ => io::Error::new(io::ErrorKind::InvalidData, error.to_string()),
    }
}

fn path_safety_error_is_open_io(error: &PathSafetyError) -> bool {
    let PathSafetyError::Inspection { kind, message, .. } = error else {
        return false;
    };
    matches!(
        kind,
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) || {
        let io_error = io::Error::new(*kind, message.clone());
        is_media_changed_error(&io_error) || is_media_unavailable_error(&io_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(unix)]
    hardlinks: u64,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(windows)]
        use std::os::windows::fs::MetadataExt;

        Self {
            len: metadata.len(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
            #[cfg(unix)]
            hardlinks: metadata.nlink(),
            #[cfg(windows)]
            creation_time: metadata.creation_time(),
            #[cfg(windows)]
            last_write_time: metadata.last_write_time(),
        }
    }
}

fn classify_open_io(
    lease: &dyn MediaReadLease,
    expected_generation: &MediaGenerationId,
    expected_revision: &SourceRevisionClaim,
    error: io::Error,
    missing_means_precondition: bool,
) -> OpenInterruption {
    match lease.status() {
        MediaFenceStatus::Unavailable => {
            return OpenInterruption::Error(ArtifactSourceError::Unavailable {
                message: "mounted media disappeared during artifact open".to_string(),
            })
        }
        MediaFenceStatus::Changed { observed } => {
            return OpenInterruption::Outcome(ArtifactOpenOutcome::MediaChanged {
                observed_generation: observed,
            })
        }
        MediaFenceStatus::Current => {}
    }

    if is_media_changed_error(&error) {
        return OpenInterruption::Outcome(ArtifactOpenOutcome::MediaChanged {
            observed_generation: None,
        });
    }
    if is_media_unavailable_error(&error) {
        return OpenInterruption::Error(ArtifactSourceError::Unavailable {
            message: "mounted media became unavailable during artifact open".to_string(),
        });
    }
    if error.kind() == io::ErrorKind::PermissionDenied {
        return OpenInterruption::Error(ArtifactSourceError::PermissionDenied);
    }
    if missing_means_precondition && error.kind() == io::ErrorKind::NotFound {
        return OpenInterruption::Outcome(ArtifactOpenOutcome::PreconditionFailed {
            current_revision: None,
        });
    }
    if !missing_means_precondition && error.kind() == io::ErrorKind::NotFound {
        return OpenInterruption::Error(ArtifactSourceError::Unavailable {
            message: "mounted media root is no longer available".to_string(),
        });
    }

    // The arguments are intentionally referenced here even on platforms
    // whose native error code did not classify the failure.  They document
    // which fence was active without leaking a mount path into the message.
    let _ = (expected_generation, expected_revision);
    OpenInterruption::Error(ArtifactSourceError::Io {
        message: sanitized_io_message(&error),
    })
}

fn is_media_unavailable_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe
    ) {
        return true;
    }

    #[cfg(windows)]
    {
        const ERROR_NOT_READY: i32 = 21;
        const ERROR_DEVICE_NOT_CONNECTED: i32 = 1167;
        const ERROR_NO_MEDIA_IN_DRIVE: i32 = 1112;
        matches!(
            error.raw_os_error(),
            Some(ERROR_NOT_READY | ERROR_DEVICE_NOT_CONNECTED | ERROR_NO_MEDIA_IN_DRIVE)
        )
    }

    #[cfg(unix)]
    {
        const EIO: i32 = 5;
        const ENXIO: i32 = 6;
        const ENODEV: i32 = 19;
        matches!(error.raw_os_error(), Some(EIO | ENXIO | ENODEV))
    }

    #[cfg(not(any(unix, windows)))]
    false
}

fn is_media_changed_error(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        const ERROR_MEDIA_CHANGED: i32 = 1110;
        error.raw_os_error() == Some(ERROR_MEDIA_CHANGED)
    }

    #[cfg(target_os = "linux")]
    {
        const ESTALE: i32 = 116;
        error.raw_os_error() == Some(ESTALE)
    }

    #[cfg(target_os = "macos")]
    {
        const ESTALE: i32 = 70;
        error.raw_os_error() == Some(ESTALE)
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    false
}

fn sanitized_io_message(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => format!("source I/O error ({:?}, os code {code})", error.kind()),
        None => format!("source I/O error ({:?})", error.kind()),
    }
}

struct MountedArtifactBody {
    file: Option<File>,
    lease: Option<Box<dyn MediaReadLease>>,
    expected_generation: MediaGenerationId,
    expected_revision: SourceRevisionClaim,
    expected_sha256: Option<String>,
    full_hasher: Option<Sha256>,
    fingerprint: FileFingerprint,
    position: u64,
    total_bytes: u64,
}

impl MountedArtifactBody {
    fn ensure_media_current(&self) -> io::Result<()> {
        let Some(lease) = self.lease.as_deref() else {
            return Err(typed_body_io(
                io::ErrorKind::NotConnected,
                ArtifactBodyReadError::SourceUnavailable,
            ));
        };
        if lease.generation() != &self.expected_generation {
            return Err(typed_body_io(
                io::ErrorKind::InvalidData,
                ArtifactBodyReadError::MediaChanged {
                    expected: self.expected_generation.clone(),
                    observed: Some(lease.generation().clone()),
                },
            ));
        }
        match lease.status() {
            MediaFenceStatus::Current => Ok(()),
            MediaFenceStatus::Unavailable => Err(typed_body_io(
                io::ErrorKind::NotConnected,
                ArtifactBodyReadError::SourceUnavailable,
            )),
            MediaFenceStatus::Changed { observed } => Err(typed_body_io(
                io::ErrorKind::InvalidData,
                ArtifactBodyReadError::MediaChanged {
                    expected: self.expected_generation.clone(),
                    observed,
                },
            )),
        }
    }

    fn ensure_file_unchanged(&self) -> io::Result<()> {
        let Some(file) = self.file.as_ref() else {
            return Err(typed_body_io(
                io::ErrorKind::NotConnected,
                ArtifactBodyReadError::SourceUnavailable,
            ));
        };
        let metadata = file.metadata().map_err(|error| self.classify_io(error))?;
        if !metadata.is_file()
            || metadata.len() != self.total_bytes
            || FileFingerprint::from_metadata(&metadata) != self.fingerprint
        {
            return Err(typed_body_io(
                io::ErrorKind::InvalidData,
                ArtifactBodyReadError::PreconditionFailed {
                    expected: self.expected_revision.clone(),
                    current: None,
                },
            ));
        }
        Ok(())
    }

    fn classify_io(&self, error: io::Error) -> io::Error {
        if let Err(fence_error) = self.ensure_media_current() {
            return fence_error;
        }
        if is_media_changed_error(&error) {
            return typed_body_io(
                io::ErrorKind::InvalidData,
                ArtifactBodyReadError::MediaChanged {
                    expected: self.expected_generation.clone(),
                    observed: None,
                },
            );
        }
        if is_media_unavailable_error(&error) {
            return typed_body_io(
                io::ErrorKind::NotConnected,
                ArtifactBodyReadError::SourceUnavailable,
            );
        }
        if error.kind() == io::ErrorKind::PermissionDenied {
            return error;
        }
        let kind = error.kind();
        typed_body_io(
            kind,
            ArtifactBodyReadError::Io {
                message: sanitized_io_message(&error),
            },
        )
    }
}

impl Read for MountedArtifactBody {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.ensure_media_current()?;
        self.ensure_file_unchanged()?;

        if self.position == self.total_bytes {
            return Ok(0);
        }
        if self.position > self.total_bytes {
            return Err(typed_body_io(
                io::ErrorKind::InvalidData,
                ArtifactBodyReadError::PreconditionFailed {
                    expected: self.expected_revision.clone(),
                    current: None,
                },
            ));
        }

        let remaining = self.total_bytes - self.position;
        let limit = buffer
            .len()
            .min(MAX_MOUNTED_READ_BYTES)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let Some(file) = self.file.as_mut() else {
            return Err(typed_body_io(
                io::ErrorKind::NotConnected,
                ArtifactBodyReadError::SourceUnavailable,
            ));
        };
        let result = file.read(&mut buffer[..limit]);
        let read = match result {
            Ok(0) => {
                return Err(typed_body_io(
                    io::ErrorKind::UnexpectedEof,
                    ArtifactBodyReadError::PreconditionFailed {
                        expected: self.expected_revision.clone(),
                        current: None,
                    },
                ))
            }
            Ok(read) => read,
            Err(error) => return Err(self.classify_io(error)),
        };

        if let Some(hasher) = self.full_hasher.as_mut() {
            hasher.update(&buffer[..read]);
        }
        self.position = self.position.saturating_add(read as u64);
        self.ensure_media_current()?;
        self.ensure_file_unchanged()?;
        if self.position == self.total_bytes {
            if let (Some(expected), Some(hasher)) =
                (self.expected_sha256.as_deref(), self.full_hasher.take())
            {
                let digest = hasher.finalize();
                let actual = encode_sha256(&digest);
                if actual != expected {
                    return Err(typed_body_io(
                        io::ErrorKind::InvalidData,
                        ArtifactBodyReadError::PreconditionFailed {
                            expected: self.expected_revision.clone(),
                            current: None,
                        },
                    ));
                }
            }
        }
        Ok(read)
    }
}

impl Drop for MountedArtifactBody {
    fn drop(&mut self) {
        // Safe eject must never observe zero readers while this process still
        // owns a file handle into the generation.
        drop(self.file.take());
        drop(self.lease.take());
    }
}

fn typed_body_io(kind: io::ErrorKind, error: ArtifactBodyReadError) -> io::Error {
    io::Error::new(kind, error)
}

fn encode_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use tempfile::TempDir;
    use ylx_transfer_core::ingest::{
        classify_body_read_error, ArtifactReadFailure, SafeRelativePath, SourceArtifactRole,
        SourceContentRevision,
    };

    use super::*;

    #[derive(Clone)]
    struct FakeLeaseProvider {
        generation: MediaGenerationId,
        status: Arc<Mutex<MediaFenceStatus>>,
        active_readers: Arc<AtomicUsize>,
    }

    impl FakeLeaseProvider {
        fn new(generation: MediaGenerationId) -> Self {
            Self {
                generation,
                status: Arc::new(Mutex::new(MediaFenceStatus::Current)),
                active_readers: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_status(&self, status: MediaFenceStatus) {
            *self.status.lock().expect("fake status lock") = status;
        }

        fn active_readers(&self) -> usize {
            self.active_readers.load(Ordering::SeqCst)
        }
    }

    struct FakeLease {
        generation: MediaGenerationId,
        status: Arc<Mutex<MediaFenceStatus>>,
        active_readers: Arc<AtomicUsize>,
    }

    impl MediaReadLease for FakeLease {
        fn generation(&self) -> &MediaGenerationId {
            &self.generation
        }

        fn status(&self) -> MediaFenceStatus {
            self.status.lock().expect("fake status lock").clone()
        }
    }

    impl Drop for FakeLease {
        fn drop(&mut self) {
            self.active_readers.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl MediaReadLeaseProvider for FakeLeaseProvider {
        fn acquire(
            &self,
            expected: &MediaGenerationId,
        ) -> Result<Box<dyn MediaReadLease>, MediaFenceError> {
            if expected != &self.generation {
                return Err(MediaFenceError::Changed {
                    observed: Some(self.generation.clone()),
                });
            }
            match self.status.lock().expect("fake status lock").clone() {
                MediaFenceStatus::Current => {}
                MediaFenceStatus::Unavailable => {
                    return Err(MediaFenceError::Unavailable {
                        message: "fixture media is absent".to_string(),
                    })
                }
                MediaFenceStatus::Changed { observed } => {
                    return Err(MediaFenceError::Changed { observed })
                }
            }
            self.active_readers.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeLease {
                generation: self.generation.clone(),
                status: self.status.clone(),
                active_readers: self.active_readers.clone(),
            }))
        }
    }

    struct Fixture {
        _temp: TempDir,
        file_path: PathBuf,
        file_id: SourceArtifactId,
        generation: MediaGenerationId,
        revision: SourceRevisionClaim,
        provider: Arc<FakeLeaseProvider>,
        adapter: MountedFileArtifactAdapter,
    }

    fn fixture(bytes: &[u8]) -> Fixture {
        let temp = tempfile::tempdir().expect("temp mounted volume");
        let relative =
            SafeRelativePath::parse("recordings/session-1/video.bin").expect("safe fixture path");
        let file_path = relative.join_to(temp.path());
        fs::create_dir_all(file_path.parent().expect("file parent")).expect("create fixture dirs");
        fs::write(&file_path, bytes).expect("write fixture source");

        let file_id = SourceArtifactId::parse("video-1").expect("fixture file id");
        let claim = SourceArtifactClaim::new(
            file_id.clone(),
            relative,
            SourceArtifactRole::VideoStereo,
            bytes.len() as u64,
            Some(encode_sha256(&Sha256::digest(bytes))),
            Some("application/octet-stream".to_string()),
        )
        .expect("fixture claim");
        let generation = MediaGenerationId::from_material(b"mounted-fixture-generation");
        let revision = SourceRevisionClaim::Published(SourceContentRevision::from_material(
            b"mounted-fixture-revision",
        ));
        let provider = Arc::new(FakeLeaseProvider::new(generation.clone()));
        let adapter = MountedFileArtifactAdapter::new(
            temp.path(),
            generation.clone(),
            revision.clone(),
            [claim],
            provider.clone(),
        )
        .expect("fixture adapter");

        Fixture {
            _temp: temp,
            file_path,
            file_id,
            generation,
            revision,
            provider,
            adapter,
        }
    }

    fn request(fixture: &Fixture, offset: u64) -> ArtifactReadRequest {
        ArtifactReadRequest::new(
            fixture.file_id.clone(),
            fixture.revision.clone(),
            Some(fixture.generation.clone()),
            offset,
        )
    }

    #[test]
    fn full_read_is_bounded_and_dropping_body_releases_its_reader_lease() {
        let bytes = vec![0x5a; MAX_MOUNTED_READ_BYTES + 17];
        let fixture = fixture(&bytes);
        let outcome = fixture.adapter.open(request(&fixture, 0)).expect("open");
        let ArtifactOpenOutcome::FullFromZero {
            total_bytes,
            mut body,
            ..
        } = outcome
        else {
            panic!("expected full body");
        };
        assert_eq!(total_bytes, bytes.len() as u64);
        assert_eq!(fixture.provider.active_readers(), 1);

        let mut oversized = vec![0; MAX_MOUNTED_READ_BYTES * 2];
        let read = body.read(&mut oversized).expect("bounded source read");
        assert_eq!(read, MAX_MOUNTED_READ_BYTES);
        assert_eq!(&oversized[..read], &bytes[..read]);

        drop(body);
        assert_eq!(fixture.provider.active_readers(), 0);
    }

    #[test]
    fn seek_partial_exact_eof_and_past_eof_have_distinct_outcomes() {
        let fixture = fixture(b"abcdef");
        let outcome = fixture.adapter.open(request(&fixture, 2)).expect("partial");
        let ArtifactOpenOutcome::Partial {
            start,
            end_inclusive,
            total_bytes,
            mut body,
            ..
        } = outcome
        else {
            panic!("expected partial body");
        };
        assert_eq!((start, end_inclusive, total_bytes), (2, 5, 6));
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).expect("read partial");
        assert_eq!(bytes, b"cdef");
        drop(body);
        assert_eq!(fixture.provider.active_readers(), 0);

        assert!(matches!(
            fixture.adapter.open(request(&fixture, 6)).expect("EOF"),
            ArtifactOpenOutcome::EndOfFile { total_bytes: 6, .. }
        ));
        assert!(matches!(
            fixture
                .adapter
                .open(request(&fixture, 7))
                .expect("not satisfiable"),
            ArtifactOpenOutcome::NotSatisfiable {
                total_bytes: Some(6)
            }
        ));
        assert_eq!(fixture.provider.active_readers(), 0);
    }

    #[test]
    fn wrong_revision_and_generation_fail_closed_before_reading() {
        let fixture = fixture(b"source");
        let wrong_revision = SourceRevisionClaim::Published(SourceContentRevision::from_material(
            b"another revision",
        ));
        let revision_outcome = fixture
            .adapter
            .open(ArtifactReadRequest::new(
                fixture.file_id.clone(),
                wrong_revision,
                Some(fixture.generation.clone()),
                0,
            ))
            .expect("revision outcome");
        assert!(matches!(
            revision_outcome,
            ArtifactOpenOutcome::PreconditionFailed {
                current_revision: Some(_)
            }
        ));

        let generation_outcome = fixture
            .adapter
            .open(ArtifactReadRequest::new(
                fixture.file_id.clone(),
                fixture.revision.clone(),
                Some(MediaGenerationId::from_material(b"replacement card")),
                0,
            ))
            .expect("generation outcome");
        assert!(matches!(
            generation_outcome,
            ArtifactOpenOutcome::MediaChanged {
                observed_generation: Some(_)
            }
        ));
        assert_eq!(fixture.provider.active_readers(), 0);
    }

    #[test]
    fn removal_after_open_is_a_typed_waiting_for_media_read_failure() {
        let fixture = fixture(b"source bytes");
        let outcome = fixture.adapter.open(request(&fixture, 0)).expect("open");
        let ArtifactOpenOutcome::FullFromZero { mut body, .. } = outcome else {
            panic!("expected body");
        };
        fixture.provider.set_status(MediaFenceStatus::Unavailable);
        let error = body.read(&mut [0; 1]).expect_err("removed media fails");
        assert_eq!(
            classify_body_read_error(&error),
            ArtifactReadFailure::SourceUnavailable
        );
    }

    #[test]
    fn replacement_after_open_preserves_the_observed_generation() {
        let fixture = fixture(b"source bytes");
        let outcome = fixture.adapter.open(request(&fixture, 0)).expect("open");
        let ArtifactOpenOutcome::FullFromZero { mut body, .. } = outcome else {
            panic!("expected body");
        };
        let replacement = MediaGenerationId::from_material(b"replacement generation");
        fixture.provider.set_status(MediaFenceStatus::Changed {
            observed: Some(replacement.clone()),
        });
        let error = body.read(&mut [0; 1]).expect_err("replaced media fails");
        assert_eq!(
            classify_body_read_error(&error),
            ArtifactReadFailure::MediaChanged {
                expected: fixture.generation.clone(),
                observed: Some(replacement),
            }
        );
    }

    #[test]
    fn file_change_after_open_is_a_typed_precondition_failure() {
        let fixture = fixture(b"source bytes");
        let outcome = fixture.adapter.open(request(&fixture, 0)).expect("open");
        let ArtifactOpenOutcome::FullFromZero { mut body, .. } = outcome else {
            panic!("expected body");
        };
        fs::write(&fixture.file_path, b"different length").expect("mutate fixture source");
        let error = body.read(&mut [0; 1]).expect_err("changed file fails");
        assert_eq!(
            classify_body_read_error(&error),
            ArtifactReadFailure::PreconditionFailed {
                expected: fixture.revision.clone(),
                current: None,
            }
        );
    }

    #[test]
    fn same_size_wrong_content_fails_the_frozen_hash_claim() {
        let fixture = fixture(b"source bytes");
        fs::write(&fixture.file_path, b"wrong! bytes").expect("replace with same-size content");
        let outcome = fixture.adapter.open(request(&fixture, 0)).expect("open");
        let ArtifactOpenOutcome::FullFromZero { mut body, .. } = outcome else {
            panic!("expected body");
        };
        let mut discarded = Vec::new();
        let error = body
            .read_to_end(&mut discarded)
            .expect_err("wrong source digest must fail");
        assert_eq!(
            classify_body_read_error(&error),
            ArtifactReadFailure::PreconditionFailed {
                expected: fixture.revision.clone(),
                current: None,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_artifact_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp mounted volume");
        let outside = temp.path().join("outside.bin");
        fs::write(&outside, b"outside").expect("outside fixture");
        let recording = temp.path().join("recordings/session-1");
        fs::create_dir_all(&recording).expect("recording dir");
        symlink(&outside, recording.join("video.bin")).expect("source symlink");

        let file_id = SourceArtifactId::parse("video-1").expect("file id");
        let claim = SourceArtifactClaim::new(
            file_id.clone(),
            SafeRelativePath::parse("recordings/session-1/video.bin").expect("relative path"),
            SourceArtifactRole::VideoStereo,
            7,
            Some("a".repeat(64)),
            None,
        )
        .expect("claim");
        let generation = MediaGenerationId::from_material(b"symlink generation");
        let revision = SourceRevisionClaim::Published(SourceContentRevision::from_material(
            b"symlink revision",
        ));
        let provider = Arc::new(FakeLeaseProvider::new(generation.clone()));
        let adapter = MountedFileArtifactAdapter::new(
            temp.path(),
            generation.clone(),
            revision.clone(),
            [claim],
            provider.clone(),
        )
        .expect("adapter");

        let error = adapter
            .open(ArtifactReadRequest::new(
                file_id,
                revision,
                Some(generation),
                0,
            ))
            .expect_err("symlink must fail");
        assert!(matches!(error, ArtifactSourceError::UnsafeArtifact { .. }));
        assert_eq!(provider.active_readers(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parent_directory_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp mounted volume");
        let outside_session = temp.path().join("outside/session-1");
        fs::create_dir_all(&outside_session).expect("outside session dir");
        fs::write(outside_session.join("video.bin"), b"outside").expect("outside video");
        fs::create_dir_all(temp.path().join("recordings")).expect("recordings dir");
        symlink(
            temp.path().join("outside"),
            temp.path().join("recordings/link"),
        )
        .expect("parent symlink");

        let file_id = SourceArtifactId::parse("video-1").expect("file id");
        let claim = SourceArtifactClaim::new(
            file_id.clone(),
            SafeRelativePath::parse("recordings/link/session-1/video.bin").expect("relative path"),
            SourceArtifactRole::VideoStereo,
            7,
            Some("a".repeat(64)),
            None,
        )
        .expect("claim");
        let generation = MediaGenerationId::from_material(b"parent symlink generation");
        let revision = SourceRevisionClaim::Published(SourceContentRevision::from_material(
            b"parent symlink revision",
        ));
        let provider = Arc::new(FakeLeaseProvider::new(generation.clone()));
        let adapter = MountedFileArtifactAdapter::new(
            temp.path(),
            generation.clone(),
            revision.clone(),
            [claim],
            provider.clone(),
        )
        .expect("adapter");

        let error = adapter
            .open(ArtifactReadRequest::new(
                file_id,
                revision,
                Some(generation),
                0,
            ))
            .expect_err("parent symlink must fail");
        assert!(matches!(error, ArtifactSourceError::UnsafeArtifact { .. }));
        assert_eq!(provider.active_readers(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_artifact_is_rejected_before_reading() {
        let temp = tempfile::tempdir().expect("temp mounted volume");
        let original = temp.path().join("original.bin");
        fs::write(&original, b"hardlink").expect("original");
        let artifact = temp.path().join("recordings/session-1/video.bin");
        fs::create_dir_all(artifact.parent().expect("artifact parent")).expect("artifact dirs");
        fs::hard_link(&original, &artifact).expect("artifact hardlink");

        let file_id = SourceArtifactId::parse("video-1").expect("file id");
        let claim = SourceArtifactClaim::new(
            file_id.clone(),
            SafeRelativePath::parse("recordings/session-1/video.bin").expect("relative path"),
            SourceArtifactRole::VideoStereo,
            8,
            Some(encode_sha256(&Sha256::digest(b"hardlink"))),
            None,
        )
        .expect("claim");
        let generation = MediaGenerationId::from_material(b"hardlink generation");
        let revision = SourceRevisionClaim::Published(SourceContentRevision::from_material(
            b"hardlink revision",
        ));
        let provider = Arc::new(FakeLeaseProvider::new(generation.clone()));
        let adapter = MountedFileArtifactAdapter::new(
            temp.path(),
            generation.clone(),
            revision.clone(),
            [claim],
            provider.clone(),
        )
        .expect("adapter");

        let error = adapter
            .open(ArtifactReadRequest::new(
                file_id,
                revision,
                Some(generation),
                0,
            ))
            .expect_err("hardlink must fail");
        assert!(matches!(error, ArtifactSourceError::UnsafeArtifact { .. }));
        assert_eq!(provider.active_readers(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_added_after_open_is_a_typed_precondition_failure() {
        let fixture = fixture(b"source bytes");
        let outcome = fixture.adapter.open(request(&fixture, 0)).expect("open");
        let ArtifactOpenOutcome::FullFromZero { mut body, .. } = outcome else {
            panic!("expected body");
        };
        fs::hard_link(
            &fixture.file_path,
            fixture.file_path.with_extension("linked"),
        )
        .expect("add hardlink after open");

        let error = body.read(&mut [0; 1]).expect_err("hardlink race fails");
        assert_eq!(
            classify_body_read_error(&error),
            ArtifactReadFailure::PreconditionFailed {
                expected: fixture.revision.clone(),
                current: None,
            }
        );
    }
}
