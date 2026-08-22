//! Narrow byte-source seam shared by LAN and mounted-media acquisition.

use std::fmt;
use std::io::{self, Read};

use super::identity::{MediaGenerationId, SourceArtifactId, SourceRevisionClaim};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReadRequest {
    pub file_id: SourceArtifactId,
    pub expected_revision: SourceRevisionClaim,
    pub expected_media_generation: Option<MediaGenerationId>,
    pub offset: u64,
}

impl ArtifactReadRequest {
    #[must_use]
    pub fn new(
        file_id: SourceArtifactId,
        expected_revision: SourceRevisionClaim,
        expected_media_generation: Option<MediaGenerationId>,
        offset: u64,
    ) -> Self {
        Self {
            file_id,
            expected_revision,
            expected_media_generation,
            offset,
        }
    }
}

/// Outcome of opening one artifact at an offset. These variants are the common
/// language for HTTP Range and seekable files:
///
/// - HTTP 200 maps to `FullFromZero`;
/// - HTTP 206 maps to `Partial`;
/// - HTTP 412 maps to `PreconditionFailed`;
/// - HTTP 416 maps to `NotSatisfiable`;
/// - an exact local seek to file length maps to `EndOfFile`;
/// - generation or metadata-fingerprint changes map to `MediaChanged` or
///   `PreconditionFailed`, never a generic network error.
pub enum ArtifactOpenOutcome {
    FullFromZero {
        revision: SourceRevisionClaim,
        total_bytes: u64,
        body: Box<dyn Read + Send>,
    },
    Partial {
        revision: SourceRevisionClaim,
        start: u64,
        end_inclusive: u64,
        total_bytes: u64,
        body: Box<dyn Read + Send>,
    },
    PreconditionFailed {
        current_revision: Option<SourceRevisionClaim>,
    },
    NotSatisfiable {
        total_bytes: Option<u64>,
    },
    EndOfFile {
        revision: SourceRevisionClaim,
        total_bytes: u64,
    },
    MediaChanged {
        observed_generation: Option<MediaGenerationId>,
    },
}

impl ArtifactOpenOutcome {
    /// Validate adapter output against the request before any byte is appended
    /// to a partial file.
    pub fn validate_against(
        &self,
        request: &ArtifactReadRequest,
    ) -> Result<(), ArtifactSourceError> {
        match self {
            Self::FullFromZero { revision, .. } => {
                ensure_revision(revision, &request.expected_revision)
            }
            Self::Partial {
                revision,
                start,
                end_inclusive,
                total_bytes,
                ..
            } => {
                ensure_revision(revision, &request.expected_revision)?;
                if *start != request.offset
                    || start > end_inclusive
                    || *end_inclusive >= *total_bytes
                {
                    return Err(ArtifactSourceError::ProtocolViolation {
                        message: format!(
                            "invalid partial range {start}-{end_inclusive}/{total_bytes} for requested offset {}",
                            request.offset
                        ),
                    });
                }
                Ok(())
            }
            Self::EndOfFile {
                revision,
                total_bytes,
            } => {
                ensure_revision(revision, &request.expected_revision)?;
                if request.offset != *total_bytes {
                    return Err(ArtifactSourceError::ProtocolViolation {
                        message: format!(
                            "EOF at {total_bytes} does not match requested offset {}",
                            request.offset
                        ),
                    });
                }
                Ok(())
            }
            Self::PreconditionFailed { .. }
            | Self::NotSatisfiable { .. }
            | Self::MediaChanged { .. } => Ok(()),
        }
    }

    #[must_use]
    pub fn has_body(&self) -> bool {
        matches!(self, Self::FullFromZero { .. } | Self::Partial { .. })
    }
}

impl fmt::Debug for ArtifactOpenOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullFromZero {
                revision,
                total_bytes,
                ..
            } => formatter
                .debug_struct("FullFromZero")
                .field("revision", revision)
                .field("total_bytes", total_bytes)
                .finish_non_exhaustive(),
            Self::Partial {
                revision,
                start,
                end_inclusive,
                total_bytes,
                ..
            } => formatter
                .debug_struct("Partial")
                .field("revision", revision)
                .field("start", start)
                .field("end_inclusive", end_inclusive)
                .field("total_bytes", total_bytes)
                .finish_non_exhaustive(),
            Self::PreconditionFailed { current_revision } => formatter
                .debug_struct("PreconditionFailed")
                .field("current_revision", current_revision)
                .finish(),
            Self::NotSatisfiable { total_bytes } => formatter
                .debug_struct("NotSatisfiable")
                .field("total_bytes", total_bytes)
                .finish(),
            Self::EndOfFile {
                revision,
                total_bytes,
            } => formatter
                .debug_struct("EndOfFile")
                .field("revision", revision)
                .field("total_bytes", total_bytes)
                .finish(),
            Self::MediaChanged {
                observed_generation,
            } => formatter
                .debug_struct("MediaChanged")
                .field("observed_generation", observed_generation)
                .finish(),
        }
    }
}

pub trait ArtifactSource: Send + Sync {
    fn open(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<ArtifactOpenOutcome, ArtifactSourceError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactSourceError {
    #[error("artifact source is unavailable: {message}")]
    Unavailable { message: String },
    #[error("permission denied while opening source artifact")]
    PermissionDenied,
    #[error("unsafe source artifact {file_id}: {reason}")]
    UnsafeArtifact {
        file_id: SourceArtifactId,
        reason: String,
    },
    #[error("artifact source I/O failed: {message}")]
    Io { message: String },
    #[error("artifact source violated its range/revision contract: {message}")]
    ProtocolViolation { message: String },
}

/// Typed payload adapters embed in `io::Error` when a source changes after
/// `open` returned but before the response body is exhausted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactBodyReadError {
    #[error("artifact source disappeared while reading")]
    SourceUnavailable,
    #[error("media generation changed while reading")]
    MediaChanged {
        expected: MediaGenerationId,
        observed: Option<MediaGenerationId>,
    },
    #[error("artifact revision changed while reading")]
    PreconditionFailed {
        expected: SourceRevisionClaim,
        current: Option<SourceRevisionClaim>,
    },
    #[error("artifact body I/O failed: {message}")]
    Io { message: String },
}

/// State-machine classification of a body read error. Unlike `io::ErrorKind`,
/// it preserves the revision/generation fence that determines whether a job
/// waits for the card or discards its partial bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactReadFailure {
    SourceUnavailable,
    MediaChanged {
        expected: MediaGenerationId,
        observed: Option<MediaGenerationId>,
    },
    PreconditionFailed {
        expected: SourceRevisionClaim,
        current: Option<SourceRevisionClaim>,
    },
    PermissionDenied,
    Io {
        message: String,
    },
}

#[must_use]
pub fn classify_body_read_error(error: &io::Error) -> ArtifactReadFailure {
    if let Some(typed) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ArtifactBodyReadError>())
    {
        return match typed {
            ArtifactBodyReadError::SourceUnavailable => ArtifactReadFailure::SourceUnavailable,
            ArtifactBodyReadError::MediaChanged { expected, observed } => {
                ArtifactReadFailure::MediaChanged {
                    expected: expected.clone(),
                    observed: observed.clone(),
                }
            }
            ArtifactBodyReadError::PreconditionFailed { expected, current } => {
                ArtifactReadFailure::PreconditionFailed {
                    expected: expected.clone(),
                    current: current.clone(),
                }
            }
            ArtifactBodyReadError::Io { message } => ArtifactReadFailure::Io {
                message: message.clone(),
            },
        };
    }

    match error.kind() {
        io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe => {
            ArtifactReadFailure::SourceUnavailable
        }
        io::ErrorKind::PermissionDenied => ArtifactReadFailure::PermissionDenied,
        _ => ArtifactReadFailure::Io {
            message: error.to_string(),
        },
    }
}

fn ensure_revision(
    actual: &SourceRevisionClaim,
    expected: &SourceRevisionClaim,
) -> Result<(), ArtifactSourceError> {
    if actual != expected {
        return Err(ArtifactSourceError::ProtocolViolation {
            message: format!(
                "source returned revision {:?}, expected {:?}",
                actual.as_str(),
                expected.as_str()
            ),
        });
    }
    Ok(())
}
