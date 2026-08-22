//! Safe, resumable local download engine.
//!
//! The production transfer coordinator uses this module for target-path
//! validation, range handling, hash verification, atomic commit, publication
//! verification, and crash recovery through a generic [`DownloadSource`].
//!
//! ## Publication authenticity (plan 9.2 point 7)
//!
//! [`PublicationVerifier`] is the production seam for detached Ed25519
//! verification over the Pi's exact canonical publication payload. The
//! caller must supply the raw public key as well as the payload and
//! signature; [`commit_session`] refuses to publish whenever verification
//! fails. The concrete cryptographic implementation lives in
//! `ylx-transfer-adapters`, keeping this core crate independent of a crypto
//! backend. Test-only pass/fail fakes remain available under `cfg(test)`.
//!
//! ## Download contract
//!
//! 1. [`derive_target_path_for_file`] — a pure, paranoid function deriving
//!    a filesystem path from opaque device/session IDs and the verified Pi
//!    publication's relative `display_path`. It rejects `..`, absolute
//!    components, empty components, UNC/drive-letter markers, NUL bytes,
//!    Windows-reserved device names, and (via
//!    [`check_case_insensitive_collision`]) case-insensitive collisions.
//!    Legacy jobs without a persisted display path safely fall back to the
//!    opaque file ID.
//! 2. A `.part` sibling file ([`part_path`]) plus a small durable sidecar
//!    journal ([`DownloadJournal`], [`journal_path`]) recording the
//!    confirmed byte offset and expected size/hash/ETag — written with the
//!    same tmp-write/fsync/rename/fsync-parent-dir pattern as the durable
//!    file helper in this module, so a corrupt or missing journal fails safe
//!    (treated as "0 confirmed"), never as trusted resume data.
//! 3. [`interpret_range_response`] / [`download_file`] handle `206` (exact
//!    `Content-Range` cross-check against the requested start), `200`
//!    fallback (never appended to an existing partial — always restarts at
//!    byte 0), `416`, `412` (ETag precondition failure), and malformed/
//!    unexpected `Content-Range` headers (hard error, never guessed at).
//!    An ETag mismatch discovered any other way (a `206` that numerically
//!    matches the requested offset but carries a different ETag than the
//!    journal remembers) is treated the same as an explicit `412`.
//!    A `416` answering a *resumed* request (`Range: bytes=N-`, `N > 0`)
//!    is not automatically fatal: it also means "there is nothing left to
//!    send", which is the truth when the local `.part` is already the
//!    whole object. That case continues to the ordinary size AND hash
//!    verification (and commits only if both pass); a partial that is not
//!    exactly the expected size is discarded and the `416` reported, and a
//!    same-size partial whose digest disagrees fails with
//!    [`DownloadError::HashMismatch`] — never a silent commit.
//! 4. [`download_file`] fsyncs the `.part` file and atomically renames it
//!    into place only after both size AND hash verify; [`commit_session`]
//!    fsyncs the session directory and only then returns a
//!    [`LocalLibraryEntry`] in [`LocalLibraryState::Committed`]. The
//!    coordinator persists the resulting durable state.
//! 5. [`recover_resume_offset`] implements the crash-recovery contract:
//!    given a `.part` file of real length `L` and a journal claiming
//!    (possibly desynced) confirmed offset `J`, the trusted resume point is
//!    always `min(L, J)`, with any excess on-disk tail beyond that point
//!    truncated before resuming.
//!
//! ## Journal granularity
//!
//! The engine checkpoints the journal
//! **once per HTTP response, plus every [`JOURNAL_CHECKPOINT_INTERVAL`]
//! bytes within a single very large response** (fsync the `.part` file's
//! new bytes, then durably rewrite the journal) rather than after every
//! single `read()` call. This is still safe under the plan's stated
//! contract even between checkpoints: [`recover_resume_offset`]'s `min(L,
//! J)` logic only ever *trusts less* than what is truly durable — a crash
//! between checkpoints costs some re-download, never data corruption or a
//! false "confirmed" claim. Callers may choose a different durable job
//! checkpoint cadence; nothing here depends on this specific interval.
//!
//! ## Layer boundaries
//!
//! - The concrete Ed25519 backend lives in `ylx-transfer-adapters`; this core
//!   module owns only the verification seam and commit policy.
//! - **Durable job-store integration.** [`DownloadJournal`] remains this
//!   module's self-contained sidecar-file journal. The transfer persistence
//!   layer owns the durable job/checkpoint rows; an integration layer may
//!   project the same fields (confirmed offset, expected size, expected
//!   SHA-256, and ETag) into that schema without changing the download
//!   protocol.
//! - Queueing/concurrency, the production Device API client, and Tauri wiring
//!   live in their owning modules.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::PublicationScope;

use super::artifact::{ArtifactInspector, ArtifactStatus, ExpectedArtifact};
use super::staging::{
    RevisionId, SessionManifest, SessionStaging, REVISION_MARKER_NAME, SELECTED_MARKER_NAME,
    STAGING_DIR_NAME,
};

/// Buffer size used for both reading a response body and hashing a
/// finished `.part` file. Not a durability boundary by itself — see
/// [`JOURNAL_CHECKPOINT_INTERVAL`] for that.
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// How many new bytes may accumulate in a single response before the
/// engine fsyncs the `.part` file and durably rewrites the journal. See
/// the module doc comment ("Journal granularity") for why this is safe at
/// any value, including "never" (checkpointing always still happens once
/// at the end of a response).
const JOURNAL_CHECKPOINT_INTERVAL: u64 = 256 * 1024;

/// A resumed request loop that keeps hitting `412`/ETag-mismatch restarts
/// without ever making progress is almost certainly a misbehaving source,
/// not a legitimate transient condition — bail out with a structured error
/// instead of looping forever.
const MAX_ETAG_RESTART_ATTEMPTS: u8 = 3;

// =====================================================================
// 1. Target path safety (plan 9.2 step 2)
// =====================================================================

/// Errors from path-safety validation. This is a real security boundary —
/// every variant corresponds to a specific attack/foot-gun class, not a
/// generic "bad input" bucket, so tests and callers can assert exactly
/// which protection fired.
#[derive(Debug, thiserror::Error)]
pub enum PathSafetyError {
    #[error("id segment must not be empty")]
    Empty,
    #[error("id segment contains a NUL byte")]
    NulByte,
    #[error("id segment is '.' or '..'")]
    DotDot,
    #[error("id segment '{0}' is reserved for this library's internal bookkeeping")]
    ReservedInternalName(String),
    #[error("id segment contains a path separator ('/' or '\\\\')")]
    PathSeparator,
    #[error("id segment contains ':' (Windows drive letter or NTFS alternate-data-stream marker)")]
    DriveOrColon,
    #[error("id segment contains a character forbidden in Windows filenames")]
    ForbiddenWindowsCharacter,
    #[error("id segment '{0}' is a Windows-reserved device name")]
    ReservedDeviceName(String),
    #[error("id segment has an unsafe trailing '.' or space (Windows silently strips these)")]
    TrailingDotOrSpace,
    #[error("derived path unexpectedly escapes the library root (internal invariant violated)")]
    EscapesRoot,
    #[error(
        "case-insensitive filename collision: candidate {candidate:?} collides with existing entry {existing:?}"
    )]
    CaseInsensitiveCollision { candidate: String, existing: String },
    #[error("refusing to read/write through a symlink at {0}")]
    SymlinkNotAllowed(PathBuf),
    #[error("io error while checking path safety at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Windows reserved device names (case-insensitive, with or without a
/// trailing extension — `NUL.txt` is just as reserved as `NUL`).
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CLOCK$",
    "CONIN$", "CONOUT$",
];

/// Validate one opaque ID (device/session/file ID) as a single, safe path
/// segment. Deliberately paranoid: this is the only thing standing between
/// a compromised/buggy catalog response and an arbitrary filesystem write.
///
/// This function is pure (no I/O) and total — it never panics on any input,
/// including non-ASCII, empty, or adversarial strings.
pub fn validate_id_segment(segment: &str) -> Result<(), PathSafetyError> {
    if segment.is_empty() {
        return Err(PathSafetyError::Empty);
    }
    if segment.contains('\0') {
        return Err(PathSafetyError::NulByte);
    }
    if segment == "." || segment == ".." {
        return Err(PathSafetyError::DotDot);
    }
    // The hidden staging root and the revision seal are this library's own
    // names. Rejecting them here — for device ids, session ids *and* every
    // segment of a signed `display_path` — is what makes it impossible for
    // a publication to collide with staging or to forge a "this session is
    // complete" marker. See `library::staging`.
    if segment.eq_ignore_ascii_case(STAGING_DIR_NAME)
        || segment.eq_ignore_ascii_case(REVISION_MARKER_NAME)
        || segment.eq_ignore_ascii_case(SELECTED_MARKER_NAME)
    {
        return Err(PathSafetyError::ReservedInternalName(segment.to_string()));
    }
    if segment.contains('/') || segment.contains('\\') {
        return Err(PathSafetyError::PathSeparator);
    }
    if segment.contains(':') {
        return Err(PathSafetyError::DriveOrColon);
    }
    if segment
        .chars()
        .any(|c| c < ' ' || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(PathSafetyError::ForbiddenWindowsCharacter);
    }
    let upper = segment.to_ascii_uppercase();
    let base = upper.split('.').next().unwrap_or(&upper);
    if WINDOWS_RESERVED_NAMES.contains(&base) {
        return Err(PathSafetyError::ReservedDeviceName(segment.to_string()));
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        return Err(PathSafetyError::TrailingDotOrSpace);
    }
    Ok(())
}

/// Validate a Pi publication `display_path` as a portable, session-relative
/// path. Pi paths always use `/`; accepting `\\` as an alternate separator
/// would make the same bytes mean different things on Unix and Windows, so
/// backslashes are rejected rather than normalized.
pub fn validate_relative_path(relative_path: &str) -> Result<(), PathSafetyError> {
    if relative_path.is_empty() {
        return Err(PathSafetyError::Empty);
    }
    if relative_path.contains('\\') {
        return Err(PathSafetyError::PathSeparator);
    }

    // Splitting manually makes leading/trailing slashes and `//` visible as
    // empty segments on every target OS. It also keeps Windows drive syntax
    // (`C:/...`) subject to the same colon rejection when tests run on Unix.
    for segment in relative_path.split('/') {
        validate_id_segment(segment)?;
    }
    Ok(())
}

/// Derive the on-disk target path for a file, from opaque IDs only — never
/// from a caller-supplied path. Every ID is validated with
/// [`validate_id_segment`]; the joined path is then re-walked component by
/// component as a defense-in-depth check that it did not escape
/// `library_root` (this should be unreachable given the segment validation
/// above, but costs nothing to double-check for a security boundary).
pub fn derive_target_path(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    file_id: &str,
) -> Result<PathBuf, PathSafetyError> {
    derive_target_path_for_file(library_root, device_id, session_id, file_id, None)
}

/// Derive the target for one published file. `target_relative_path` is the
/// signed Pi `display_path`; `None` is accepted solely for old persisted jobs
/// and falls back to the opaque `file_id`. The opaque ID remains the network
/// API identifier in both cases and is never rewritten.
pub fn derive_target_path_for_file(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    file_id: &str,
    target_relative_path: Option<&str>,
) -> Result<PathBuf, PathSafetyError> {
    validate_id_segment(device_id)?;
    validate_id_segment(session_id)?;
    validate_id_segment(file_id)?;

    let session_root = library_root.join(device_id).join(session_id);
    let candidate = match target_relative_path {
        Some(relative_path) => {
            validate_relative_path(relative_path)?;
            session_root.join(relative_path)
        }
        None => session_root.join(file_id),
    };

    let relative = candidate
        .strip_prefix(library_root)
        .map_err(|_| PathSafetyError::EscapesRoot)?;
    for component in relative.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => return Err(PathSafetyError::EscapesRoot),
        }
    }

    Ok(candidate)
}

/// Create the target's parent directories one component at a time while
/// refusing symlinks and portable case-folding collisions at every level.
/// Doing this only for the final filename would still permit `video/` and
/// `Video/` to become two different trees on Linux and one tree on Windows.
pub(crate) fn prepare_target_parent(
    library_root: &Path,
    target: &Path,
) -> Result<(), DownloadError> {
    fs::create_dir_all(library_root).map_err(|e| DownloadError::io(library_root, e))?;

    let relative = target
        .strip_prefix(library_root)
        .map_err(|_| PathSafetyError::EscapesRoot)?;
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        return Err(PathSafetyError::EscapesRoot.into());
    }

    let mut parent = library_root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(PathSafetyError::EscapesRoot.into());
        };
        let name = name.to_string_lossy();
        check_case_insensitive_collision(&parent, &name)?;

        let candidate = parent.join(name.as_ref());
        reject_symlink(&candidate)?;
        if index + 1 == components.len() {
            return Ok(());
        }

        match fs::create_dir(&candidate) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::metadata(&candidate)
                    .map_err(|source| DownloadError::io(&candidate, source))?;
                if !metadata.is_dir() {
                    return Err(DownloadError::io(
                        &candidate,
                        io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "target path component exists but is not a directory",
                        ),
                    ));
                }
            }
            Err(e) => return Err(DownloadError::io(&candidate, e)),
        }
        // Recheck after creation to avoid trusting an entry that changed
        // between the preflight metadata check and `create_dir`.
        reject_symlink(&candidate)?;
        parent = candidate;
    }
    Err(PathSafetyError::EscapesRoot.into())
}

/// Check whether `candidate_file_name` would collide, case-insensitively,
/// with an existing entry in `dir` under a *different* exact name. On a
/// case-sensitive filesystem two such names are distinct files, but a
/// LocalLibrary entry that is safe on Linux must not silently corrupt
/// itself when the same profile/library is later used (or synced) on a
/// case-insensitive one (default macOS, Windows) — so this is enforced
/// unconditionally, not only on filesystems detected as case-insensitive.
pub fn check_case_insensitive_collision(
    dir: &Path,
    candidate_file_name: &str,
) -> Result<(), PathSafetyError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(PathSafetyError::Io {
                path: dir.to_path_buf(),
                source: e,
            })
        }
    };

    let candidate_lower = candidate_file_name.to_lowercase();
    for entry in entries {
        let entry = entry.map_err(|e| PathSafetyError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != candidate_file_name && name.to_lowercase() == candidate_lower {
            return Err(PathSafetyError::CaseInsensitiveCollision {
                candidate: candidate_file_name.to_string(),
                existing: name,
            });
        }
    }
    Ok(())
}

/// Refuse to operate on `path` if it already exists as a symlink. Called on
/// every intermediate directory component and on the final `.part`/target
/// paths before this module ever opens them for writing, so a pre-planted
/// symlink (attacker or racing process) cannot redirect a write outside the
/// intended library tree.
pub(crate) fn reject_symlink(path: &Path) -> Result<(), PathSafetyError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(PathSafetyError::SymlinkNotAllowed(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PathSafetyError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// `<target>.part` — where bytes land while a download is in progress.
pub fn part_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

/// `<target>.part.journal` — the durable sidecar recording confirmed
/// progress for the in-progress `.part` file.
pub fn journal_path(target: &Path) -> PathBuf {
    let mut s = part_path(target).into_os_string();
    s.push(".journal");
    PathBuf::from(s)
}

// =====================================================================
// 2. Durable journal (plan 9.2 step 3)
// =====================================================================

/// Why a proposed checkpoint was refused (issue #1, commit 31).
///
/// Every variant is a violated invariant, not a transient I/O problem —
/// a caller that sees one of these has a bug (or is looking at a journal
/// that belongs to different content), and silently overwriting would turn
/// that bug into a false "these bytes are durable" claim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error(
        "checkpoint offset must never move backwards: recorded {recorded}, proposed {proposed}"
    )]
    NonMonotonic { recorded: u64, proposed: u64 },
    #[error(
        "checkpoint offset {proposed} exceeds the {durable} bytes actually written and flushed to {path}"
    )]
    ExceedsDurableBytes {
        path: PathBuf,
        proposed: u64,
        durable: u64,
    },
    #[error("checkpoint field `{field}` is immutable after creation: recorded {recorded}, proposed {proposed}")]
    ImmutableField {
        field: &'static str,
        recorded: String,
        proposed: String,
    },
}

/// Durable sidecar recording what has actually been confirmed written to a
/// `.part` file, plus the expectations the eventual commit must satisfy.
/// See the module doc comment ("Journal granularity") for the write cadence
/// and persistence boundary.
///
/// # What a checkpoint means (issue #1, commit 31)
///
/// `confirmed_offset` is a *durability* claim, not a bookkeeping counter:
/// "the first `confirmed_offset` bytes of the `.part` file are written and
/// flushed, and a resume may start there without re-reading them". Three
/// invariants keep that claim true, all enforced by
/// [`DownloadJournal::advance`] — the only method the download engine uses
/// to move a checkpoint forward:
///
/// 1. **Never ahead of the bytes.** A proposed offset above the `.part`
///    file's real length is refused ([`CheckpointError::ExceedsDurableBytes`]).
///    Callers must `sync_all` the `.part` file *before* advancing, which is
///    exactly the flush the resume path relies on.
/// 2. **Never backwards.** A proposed offset below the recorded one is
///    refused ([`CheckpointError::NonMonotonic`]). Recovery's legitimate
///    *downward* correction is a different operation with a different name
///    ([`DownloadJournal::reset_to`]) so it can never be mistaken for an
///    advance.
/// 3. **Expectations are immutable.** `expected_size`, `expected_sha256_hex`
///    and (once recorded) `etag` describe *which content* this partial is;
///    rewriting them would silently re-point an existing partial at
///    different content. An attempt is [`CheckpointError::ImmutableField`],
///    not an overwrite. (`etag: None` means "never recorded" — the first
///    response to actually carry one may record it; changing a recorded
///    one is refused.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadJournal {
    pub confirmed_offset: u64,
    pub expected_size: u64,
    pub expected_sha256_hex: String,
    pub etag: Option<String>,
}

impl DownloadJournal {
    /// Read the journal at `path`. A missing file is `Ok(None)`. A file
    /// that exists but fails to parse is **also** `Ok(None)` — a corrupt
    /// journal is untrustworthy, and the safe fallback is to treat it as
    /// "no confirmed offset known" (0), never to guess at its intent. This
    /// mirrors [`recover_resume_offset`]'s conservative `min()` contract.
    pub fn read(path: &Path) -> Result<Option<Self>, DownloadError> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(DownloadError::io(path, e)),
        };
        Ok(serde_json::from_str::<DownloadJournal>(&raw).ok())
    }

    /// Durably advance the checkpoint at `path` for the `.part` file at
    /// `part`, enforcing all three invariants documented on
    /// [`DownloadJournal`]. This is the **only** way the download engine
    /// moves a checkpoint forward.
    ///
    /// Call it *after* the new bytes have been written and flushed; the
    /// `.part` file's real length is what "durable" is measured against.
    pub fn advance(
        path: &Path,
        part: &Path,
        proposed: &DownloadJournal,
    ) -> Result<(), DownloadError> {
        let durable = match fs::metadata(part) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            Err(e) => return Err(DownloadError::io(part, e)),
        };
        if proposed.confirmed_offset > durable {
            return Err(CheckpointError::ExceedsDurableBytes {
                path: part.to_path_buf(),
                proposed: proposed.confirmed_offset,
                durable,
            }
            .into());
        }

        if let Some(recorded) = Self::read(path)? {
            if proposed.confirmed_offset < recorded.confirmed_offset {
                return Err(CheckpointError::NonMonotonic {
                    recorded: recorded.confirmed_offset,
                    proposed: proposed.confirmed_offset,
                }
                .into());
            }
            if recorded.expected_size != proposed.expected_size {
                return Err(CheckpointError::ImmutableField {
                    field: "expected_size",
                    recorded: recorded.expected_size.to_string(),
                    proposed: proposed.expected_size.to_string(),
                }
                .into());
            }
            if recorded.expected_sha256_hex != proposed.expected_sha256_hex {
                return Err(CheckpointError::ImmutableField {
                    field: "expected_sha256_hex",
                    recorded: recorded.expected_sha256_hex.clone(),
                    proposed: proposed.expected_sha256_hex.clone(),
                }
                .into());
            }
            // `None` recorded = never recorded, so the first response that
            // carries an ETag may set it. A recorded one is frozen.
            if let Some(recorded_etag) = recorded.etag.as_deref() {
                if proposed.etag.as_deref() != Some(recorded_etag) {
                    return Err(CheckpointError::ImmutableField {
                        field: "etag",
                        recorded: recorded_etag.to_string(),
                        proposed: format!("{:?}", proposed.etag),
                    }
                    .into());
                }
            }
        }

        Self::write(path, proposed)
    }

    /// Recovery's *downward* correction: rewrite an existing journal so its
    /// `confirmed_offset` matches what the `.part` file can actually back.
    ///
    /// This is deliberately **not** [`DownloadJournal::advance`]. A journal
    /// claiming more than the `.part` holds (a crash between the flush and
    /// the journal write, or a tampered/desynced sidecar) is not evidence
    /// of progress; `recover_resume_offset` already truncates the file down
    /// to `min(length, claim)`, and this brings the recorded claim down to
    /// the same truth so every later checkpoint really is an advance.
    /// Refuses to move the offset *up* — that is what `advance` is for.
    pub fn reset_to(
        path: &Path,
        journal: &DownloadJournal,
        durable_offset: u64,
    ) -> Result<DownloadJournal, DownloadError> {
        if durable_offset > journal.confirmed_offset {
            return Err(CheckpointError::NonMonotonic {
                recorded: journal.confirmed_offset,
                proposed: durable_offset,
            }
            .into());
        }
        let corrected = DownloadJournal {
            confirmed_offset: durable_offset,
            ..journal.clone()
        };
        Self::write(path, &corrected)?;
        Ok(corrected)
    }

    /// Write the journal durably: tmp-write, fsync the tmp file, rename
    /// over the real path, fsync the parent directory. Mirrors
    /// The module's tmp-write/fsync/rename/fsync-parent-dir pattern.
    ///
    /// This is the low-level durable-write primitive: it *creates* a
    /// journal and is how [`DownloadJournal::advance`] and
    /// [`DownloadJournal::reset_to`] persist an already-checked value.
    /// Production checkpoint movement must go through those two, which is
    /// where the durability/monotonicity/immutability invariants live.
    pub fn write(path: &Path, journal: &DownloadJournal) -> Result<(), DownloadError> {
        let json = serde_json::to_string(journal)
            .map_err(|e| DownloadError::Serialization(e.to_string()))?;
        write_file_durably(path, json.as_bytes())
    }
}

/// Write `bytes` to `path` durably: tmp-write, fsync the tmp file, rename
/// over the real path, fsync the parent directory. Mirrors
/// The module's tmp-write/fsync/rename/fsync-parent-dir pattern.
///
/// The shared primitive behind [`DownloadJournal::write`] and
/// `library::staging`'s revision seal — a half-written journal and a
/// half-written seal would both be read back as trusted state, so they use
/// the identical write.
pub(crate) fn write_file_durably(path: &Path, bytes: &[u8]) -> Result<(), DownloadError> {
    let parent = path.parent().ok_or_else(|| {
        DownloadError::Serialization("durable write path has no parent directory".to_string())
    })?;
    fs::create_dir_all(parent).map_err(|e| DownloadError::io(parent, e))?;

    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    // Keep a writable handle for the flush. On Windows, `File::open`
    // creates a read-only handle and `sync_all`/FlushFileBuffers rejects
    // that handle with ERROR_ACCESS_DENIED.
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|e| DownloadError::io(&tmp, e))?;
    f.write_all(bytes).map_err(|e| DownloadError::io(&tmp, e))?;
    f.sync_all().map_err(|e| DownloadError::io(&tmp, e))?;
    drop(f);

    fs::rename(&tmp, path).map_err(|e| DownloadError::io(path, e))?;
    fsync_dir(parent)?;
    Ok(())
}

/// Best-effort-but-checked directory fsync so a rename survives a power
/// loss, not just a process crash. POSIX-only — no portable way to
/// open+fsync a directory handle on Windows (same residual gap
/// (Directory handles are not portable on every target.)
#[cfg(unix)]
pub(crate) fn fsync_dir(dir: &Path) -> Result<(), DownloadError> {
    let d = File::open(dir).map_err(|e| DownloadError::io(dir, e))?;
    d.sync_all().map_err(|e| DownloadError::io(dir, e))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn fsync_dir(_dir: &Path) -> Result<(), DownloadError> {
    Ok(())
}

/// Remove a `.part` file and its journal, if present. Used both when a
/// resume attempt must be discarded (200 fallback, ETag change) and when a
/// finished download fails size/hash verification.
fn discard_partial(part: &Path, jpath: &Path) -> Result<(), DownloadError> {
    for p in [part, jpath] {
        match fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(DownloadError::io(p, e)),
        }
    }
    Ok(())
}

// =====================================================================
// 3. Crash recovery (plan 9.2 step 6)
// =====================================================================

/// Compute the trustworthy resume offset for a `.part` file at `part_path`
/// given an optional journal, per the plan's crash-recovery contract: the
/// real, on-disk `.part` length `L` and the journal's claimed
/// `confirmed_offset` `J` may disagree (crash between a write and a
/// journal checkpoint, or a corrupted/tampered journal); the only safe
/// choice is `min(L, J)`. Any bytes in the `.part` file beyond that point
/// are truncated (and the truncation itself fsynced) before returning, so
/// callers can always trust "the `.part` file's length equals the returned
/// offset" as a post-condition.
pub fn recover_resume_offset(
    part_path: &Path,
    journal: Option<&DownloadJournal>,
) -> Result<u64, DownloadError> {
    let actual_len = match fs::metadata(part_path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(DownloadError::io(part_path, e)),
    };
    let claimed = journal.map(|j| j.confirmed_offset).unwrap_or(0);
    let safe_offset = actual_len.min(claimed);

    if safe_offset < actual_len {
        let file = OpenOptions::new()
            .write(true)
            .open(part_path)
            .map_err(|e| DownloadError::io(part_path, e))?;
        file.set_len(safe_offset)
            .map_err(|e| DownloadError::io(part_path, e))?;
        file.sync_all()
            .map_err(|e| DownloadError::io(part_path, e))?;
    }

    Ok(safe_offset)
}

// =====================================================================
// 4. Range response handling (plan 9.2 step 4, section 10.3)
// =====================================================================

/// What [`download_file`] asks a [`DownloadSource`] for: a byte range
/// starting at `start` (open-ended — "give me everything from here"), with
/// an optional `If-Match` ETag when resuming a previously-seen partial.
#[derive(Debug, Clone)]
pub struct RequestedRange {
    pub start: u64,
    pub if_match_etag: Option<String>,
}

/// The outbound seam this module is built against. The production adapter
/// speaks HTTP to a device; tests use an in-memory fake ([`tests` module]) plus one
/// integration test against a real loopback HTTP server
/// (`tests/download_http_spike.rs`) to prove the wire-level parsing.
///
/// Deliberately status-code/header shaped (not pre-interpreted into
/// "resumed or not") so [`interpret_range_response`] — not the source
/// implementation — is the single place that decides what a given
/// response means. A source must never pre-digest the semantics; it only
/// reports what the server actually said.
pub trait DownloadSource: Send + Sync {
    fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError>;
}

/// Raw, uninterpreted response shape from a [`DownloadSource`].
pub struct SourceResponse {
    pub status: u16,
    pub etag: Option<String>,
    /// Raw `Content-Range` header value, if present. Parsed (never
    /// pattern-matched loosely) by [`interpret_range_response`].
    pub content_range: Option<String>,
    pub content_length: Option<u64>,
    pub body: Box<dyn Read + Send>,
}

/// The interpreted meaning of a range response, per plan section 10.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeOutcome {
    /// `206 Partial Content` with an exact, well-formed `Content-Range:
    /// bytes start-end/total` that matches the requested start.
    Partial {
        start: u64,
        end_inclusive: u64,
        total: u64,
    },
    /// `200 OK` — the server ignored the Range request (or none was sent).
    /// Callers MUST restart from byte 0, never append.
    FullFromZero { total: Option<u64> },
    /// `416 Range Not Satisfiable`.
    NotSatisfiable { total: Option<u64> },
    /// `412 Precondition Failed` — the `If-Match` ETag no longer matches;
    /// the resource changed. Callers must discard any local partial state.
    PreconditionFailed,
}

/// Parse and validate a range response's status/headers against the
/// requested start offset. This is the single place that decides what an
/// HTTP response *means* for the download state machine — a hard error for
/// anything malformed or unexpected, never a best-effort guess.
pub fn interpret_range_response(
    status: u16,
    content_range: Option<&str>,
    content_length: Option<u64>,
    requested_start: u64,
) -> Result<RangeOutcome, DownloadError> {
    match status {
        206 => {
            let header = content_range.ok_or_else(|| {
                DownloadError::MalformedContentRange(
                    "206 response is missing a Content-Range header".to_string(),
                )
            })?;
            let (start, end, total) = parse_content_range_header(header)?;
            if start != requested_start {
                return Err(DownloadError::RangeMismatch {
                    requested_start,
                    got_start: start,
                });
            }
            Ok(RangeOutcome::Partial {
                start,
                end_inclusive: end,
                total,
            })
        }
        200 => Ok(RangeOutcome::FullFromZero {
            total: content_length,
        }),
        416 => {
            let total = content_range.and_then(parse_unsatisfiable_total);
            Ok(RangeOutcome::NotSatisfiable { total })
        }
        412 => Ok(RangeOutcome::PreconditionFailed),
        other => Err(DownloadError::UnexpectedStatus(other)),
    }
}

/// Strictly parse a `Content-Range: bytes start-end/total` header. Rejects:
/// wrong prefix, missing `/`, non-numeric or overflowing numbers (which
/// also naturally rejects multi-range lists like `bytes 0-10,20-30/100`,
/// since the segment after the first `-` fails to parse as a plain `u64`),
/// `total == "*"` (v1 requires an exact total, per plan section 10.3), and
/// any `start > end` or `end >= total` nonsense.
fn parse_content_range_header(header: &str) -> Result<(u64, u64, u64), DownloadError> {
    let malformed = || DownloadError::MalformedContentRange(header.to_string());

    let rest = header.strip_prefix("bytes ").ok_or_else(malformed)?;
    let (range_part, total_part) = rest.split_once('/').ok_or_else(malformed)?;
    if total_part == "*" {
        return Err(malformed());
    }
    let total: u64 = total_part.parse().map_err(|_| malformed())?;
    let (start_s, end_s) = range_part.split_once('-').ok_or_else(malformed)?;
    let start: u64 = start_s.parse().map_err(|_| malformed())?;
    let end: u64 = end_s.parse().map_err(|_| malformed())?;
    if start > end || end >= total {
        return Err(malformed());
    }
    Ok((start, end, total))
}

/// Parse the `total` out of a `416`'s `Content-Range: bytes */total`
/// header, if present and well-formed. `None` (not an error) if absent or
/// malformed — a `416`'s meaning ("not satisfiable") does not depend on
/// this optional total being parseable.
fn parse_unsatisfiable_total(header: &str) -> Option<u64> {
    header.strip_prefix("bytes */")?.parse::<u64>().ok()
}

// =====================================================================
// 5. Errors
// =====================================================================

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("unsafe target path: {0}")]
    PathSafety(#[from] PathSafetyError),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("error reading from download source: {0}")]
    SourceIo(String),

    #[error("download source reported an error: {0}")]
    Source(String),

    #[error("invalid download plan: {0}")]
    InvalidPlan(String),

    #[error("malformed Content-Range header: {0:?}")]
    MalformedContentRange(String),

    #[error("server returned Content-Range start {got_start} but {requested_start} was requested")]
    RangeMismatch {
        requested_start: u64,
        got_start: u64,
    },

    #[error("server returned 416 Range Not Satisfiable")]
    RangeNotSatisfiable,

    #[error("unexpected HTTP status {0} for a range request")]
    UnexpectedStatus(u16),

    #[error("gave up after {MAX_ETAG_RESTART_ATTEMPTS} ETag-change/precondition-failed restarts")]
    TooManyRestarts,

    #[error("response body ended early: expected {expected} bytes, got {actual}")]
    ShortBody { expected: u64, actual: u64 },

    #[error("response body exceeded its declared Content-Range/Content-Length")]
    UnexpectedExtraBytes,

    #[error("downloaded file size mismatch: expected {expected} bytes, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },

    #[error("downloaded file hash mismatch: expected sha256 {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("checkpoint refused: {0}")]
    Checkpoint(#[from] CheckpointError),

    #[error(transparent)]
    Verification(#[from] VerifyError),
}

impl DownloadError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        DownloadError::Io {
            path: path.into(),
            source,
        }
    }
}

// =====================================================================
// 6. Single-file download orchestration (plan 9.2 steps 2-6 end to end)
// =====================================================================

/// What the caller wants downloaded, identified by opaque API IDs plus the
/// expectations and relative display path from a verified signed catalog.
#[derive(Debug, Clone)]
pub struct FilePlan {
    pub device_id: String,
    pub session_id: String,
    pub file_id: String,
    /// Signed Pi `display_path`. `None` means a legacy recovered job and
    /// safely falls back to `file_id`; it must not be used for new jobs.
    pub target_relative_path: Option<String>,
    pub expected_size: u64,
    /// Lowercase hex-encoded SHA-256, exactly 64 characters.
    pub expected_sha256_hex: String,
}

/// Evidence that one file downloaded, verified (size AND hash), and was
/// atomically committed into place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFile {
    pub device_id: String,
    pub session_id: String,
    pub file_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256_hex: String,
    pub etag: Option<String>,
}

fn validate_plan(plan: &FilePlan) -> Result<(), DownloadError> {
    let hex = &plan.expected_sha256_hex;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DownloadError::InvalidPlan(format!(
            "expected_sha256_hex must be exactly 64 hex characters, got {hex:?}"
        )));
    }
    Ok(())
}

/// Which ETag (if any) to send as `If-Match` for the *next* request. Only
/// meaningful when actually resuming (`resume_offset > 0`) — a fresh,
/// from-scratch request has no prior ETag to assert against.
fn expected_etag_for_resume(
    resume_offset: u64,
    journal: Option<&DownloadJournal>,
) -> Option<String> {
    if resume_offset == 0 {
        return None;
    }
    journal.and_then(|j| j.etag.clone())
}

/// Download one file end to end: derive its safe target path, resume from
/// any existing (crash-recovered) `.part`/journal state, drive the
/// [`DownloadSource`] through the `206`/`200`/`416`/`412`/malformed-header
/// state machine, verify size AND hash, and atomically commit. Returns a
/// [`VerifiedFile`] only once every one of those steps has succeeded — on
/// any failure, nothing is committed (see individual error variants for
/// what state is left on disk, which is always safe to retry).
pub fn download_file(
    source: &dyn DownloadSource,
    plan: &FilePlan,
    library_root: &Path,
) -> Result<VerifiedFile, DownloadError> {
    validate_plan(plan)?;

    let target = derive_target_path_for_file(
        library_root,
        &plan.device_id,
        &plan.session_id,
        &plan.file_id,
        plan.target_relative_path.as_deref(),
    )?;
    let parent = target
        .parent()
        .ok_or(PathSafetyError::EscapesRoot)
        .map_err(DownloadError::from)?;

    // Symlink and case-collision checks cover every directory component,
    // including nested Pi display paths, before any file is opened.
    prepare_target_parent(library_root, &target)?;

    let part = part_path(&target);
    if let Some(name) = part.file_name() {
        check_case_insensitive_collision(parent, &name.to_string_lossy())?;
    }
    reject_symlink(&part)?;
    let jpath = journal_path(&target);

    // --- what do we already have? (issue #1, commit 32) --------------
    //
    // A single judge (`ArtifactInspector`) decides, from the committed
    // target, the `.part` partial and the journal together. Recovery then
    // re-downloads only what is missing or invalid:
    //
    // * `Verified` — the file is already here, correct size *and* digest.
    //   Reuse it. Without this a recovered job re-fetched every byte of a
    //   file it had already committed, and on Windows the final `rename`
    //   onto that existing target fails outright.
    // * `Invalid` — a committed file that is wrong (short, or same-size
    //   with a different digest). It can never become right by being left
    //   alone, and leaving it in place would block the commit `rename`, so
    //   it is removed and downloaded again from zero.
    // * `Missing` / `Partial` — the ordinary paths below.
    let expected = ExpectedArtifact::from(plan);
    let evidence =
        ArtifactInspector::new(library_root, &plan.device_id, &plan.session_id).inspect(&expected);
    match &evidence.status {
        ArtifactStatus::Verified => {
            // Any leftover `.part`/journal describes work that is already
            // committed; dropping them keeps a later inspection cheap.
            let _ = discard_partial(&part, &jpath);
            return Ok(VerifiedFile {
                device_id: plan.device_id.clone(),
                session_id: plan.session_id.clone(),
                file_id: plan.file_id.clone(),
                path: target,
                size_bytes: plan.expected_size,
                sha256_hex: plan.expected_sha256_hex.to_ascii_lowercase(),
                etag: None,
            });
        }
        ArtifactStatus::Invalid { .. } => {
            reject_symlink(&target)?;
            match fs::remove_file(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(DownloadError::io(&target, e)),
            }
        }
        ArtifactStatus::Missing | ArtifactStatus::Partial { .. } => {}
    }

    let mut journal_opt = DownloadJournal::read(&jpath)?;
    let mut resume_offset = recover_resume_offset(&part, journal_opt.as_ref())?;
    // If the journal claimed more than the `.part` file could back, the
    // recovery above truncated the file; bring the *recorded* claim down to
    // the same truth (a downward correction, never an "advance") so every
    // checkpoint from here on really is monotonic — see commit 31.
    if let Some(journal) = journal_opt.as_ref() {
        if journal.confirmed_offset > resume_offset {
            journal_opt = Some(DownloadJournal::reset_to(&jpath, journal, resume_offset)?);
        }
    }

    let final_etag: Option<String>;
    let mut attempts: u8 = 0;
    loop {
        attempts += 1;
        if attempts > MAX_ETAG_RESTART_ATTEMPTS {
            return Err(DownloadError::TooManyRestarts);
        }

        let if_match = expected_etag_for_resume(resume_offset, journal_opt.as_ref());
        let response = source.fetch_range(RequestedRange {
            start: resume_offset,
            if_match_etag: if_match,
        })?;
        let outcome = interpret_range_response(
            response.status,
            response.content_range.as_deref(),
            response.content_length,
            resume_offset,
        )?;

        match outcome {
            RangeOutcome::PreconditionFailed => {
                discard_partial(&part, &jpath)?;
                journal_opt = None;
                resume_offset = 0;
                continue;
            }
            RangeOutcome::NotSatisfiable { .. } => {
                // A `416` for `Range: bytes=N-` with `N > 0` has a
                // legitimate, common meaning: there is nothing left to
                // send because the local `.part` is *already* the whole
                // object (the previous response's last bytes landed but
                // the process died before the commit). Re-downloading is
                // not merely wasteful there, it is impossible — the server
                // will keep answering 416.
                //
                // This is only safe to act on when the local partial is
                // exactly the expected size; and even then the file is
                // still put through the ordinary size AND hash
                // verification below before anything is committed (a
                // mismatch there discards the partial and fails with
                // `HashMismatch`, never a silent commit of bad bytes).
                if resume_offset == 0 {
                    return Err(DownloadError::RangeNotSatisfiable);
                }
                let actual_len = match fs::metadata(&part) {
                    Ok(meta) => meta.len(),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
                    Err(e) => return Err(DownloadError::io(&part, e)),
                };
                if actual_len != plan.expected_size {
                    // The remote range is gone but our partial is not the
                    // whole file: the object shrank/changed under us.
                    // Discard the stale partial so a retry restarts from
                    // byte 0, and say exactly why rather than committing
                    // or looping.
                    discard_partial(&part, &jpath)?;
                    return Err(DownloadError::RangeNotSatisfiable);
                }
                final_etag = journal_opt.as_ref().and_then(|j| j.etag.clone());
                break;
            }
            RangeOutcome::FullFromZero { total } => {
                // The server ignored our Range request (or we asked for
                // none). Regardless of any local partial state, this
                // response's bytes describe the file from byte 0 — never
                // append to whatever is already on disk.
                discard_partial(&part, &jpath)?;
                let written = write_response_body(
                    &part,
                    &jpath,
                    0,
                    response.body,
                    total,
                    plan.expected_size,
                    &plan.expected_sha256_hex,
                    response.etag.as_deref(),
                )?;
                let journal = DownloadJournal {
                    confirmed_offset: written,
                    expected_size: plan.expected_size,
                    expected_sha256_hex: plan.expected_sha256_hex.clone(),
                    etag: response.etag.clone(),
                };
                DownloadJournal::advance(&jpath, &part, &journal)?;
                final_etag = response.etag;
                break;
            }
            RangeOutcome::Partial {
                start,
                end_inclusive,
                ..
            } => {
                // ETag-changed safety net: even without an explicit 412, a
                // 206 that numerically matches our requested start is not
                // trustworthy if the server's ETag for it differs from what
                // we remember — those bytes may belong to a different file
                // revision entirely. Discard and restart clean.
                if let Some(prev_etag) =
                    expected_etag_for_resume(resume_offset, journal_opt.as_ref())
                {
                    if response.etag.as_deref() != Some(prev_etag.as_str()) {
                        discard_partial(&part, &jpath)?;
                        journal_opt = None;
                        resume_offset = 0;
                        continue;
                    }
                }
                let expected_chunk_len = end_inclusive - start + 1;
                let written = write_response_body(
                    &part,
                    &jpath,
                    start,
                    response.body,
                    Some(expected_chunk_len),
                    plan.expected_size,
                    &plan.expected_sha256_hex,
                    response.etag.as_deref(),
                )?;
                let new_offset = start + written;
                let journal = DownloadJournal {
                    confirmed_offset: new_offset,
                    expected_size: plan.expected_size,
                    expected_sha256_hex: plan.expected_sha256_hex.clone(),
                    etag: response.etag.clone(),
                };
                DownloadJournal::advance(&jpath, &part, &journal)?;
                final_etag = response.etag;
                break;
            }
        }
    }

    // --- verify size AND hash before ever touching the committed name ---
    let meta = fs::metadata(&part).map_err(|e| DownloadError::io(&part, e))?;
    if meta.len() != plan.expected_size {
        discard_partial(&part, &jpath)?;
        return Err(DownloadError::SizeMismatch {
            expected: plan.expected_size,
            actual: meta.len(),
        });
    }
    let actual_hash = sha256_of_file(&part)?;
    let expected_hash = plan.expected_sha256_hex.to_ascii_lowercase();
    if actual_hash != expected_hash {
        discard_partial(&part, &jpath)?;
        return Err(DownloadError::HashMismatch {
            expected: expected_hash,
            actual: actual_hash,
        });
    }

    // --- atomic commit: fsync .part, rename into place, fsync parent dir ---
    {
        // FlushFileBuffers requires a writable Windows handle even though
        // no further bytes are written at this commit boundary.
        let f = OpenOptions::new()
            .write(true)
            .open(&part)
            .map_err(|e| DownloadError::io(&part, e))?;
        f.sync_all().map_err(|e| DownloadError::io(&part, e))?;
    }
    fs::rename(&part, &target).map_err(|e| DownloadError::io(&target, e))?;
    fsync_dir(parent)?;
    // Stale journal next to a now-fully-committed file is harmless (the
    // `.part` it described no longer exists), but remove it anyway to keep
    // the library directory clean. Best-effort: a failure here does not
    // undo the already-durable commit above.
    let _ = fs::remove_file(&jpath);

    Ok(VerifiedFile {
        device_id: plan.device_id.clone(),
        session_id: plan.session_id.clone(),
        file_id: plan.file_id.clone(),
        path: target,
        size_bytes: meta.len(),
        sha256_hex: actual_hash,
        etag: final_etag,
    })
}

/// Write one response body's bytes to `part` starting at `start_offset`
/// (truncating to fresh-empty first when `start_offset == 0`, otherwise
/// seeking — never a blind append, since [`recover_resume_offset`]
/// guarantees `part`'s length already equals `start_offset` on entry).
/// Enforces `expected_len` exactly, when known (catches both a short body
/// and a body that overruns its declared length). Checkpoints the journal
/// durably every [`JOURNAL_CHECKPOINT_INTERVAL`] bytes and once more at the
/// end. Returns the number of bytes actually written.
#[allow(clippy::too_many_arguments)]
fn write_response_body(
    part: &Path,
    jpath: &Path,
    start_offset: u64,
    mut body: Box<dyn Read + Send>,
    expected_len: Option<u64>,
    expected_size: u64,
    expected_sha256_hex: &str,
    response_etag: Option<&str>,
) -> Result<u64, DownloadError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(start_offset == 0)
        .open(part)
        .map_err(|e| DownloadError::io(part, e))?;
    if start_offset > 0 {
        file.seek(SeekFrom::Start(start_offset))
            .map_err(|e| DownloadError::io(part, e))?;
    }

    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];
    let mut written: u64 = 0;
    let mut since_checkpoint: u64 = 0;

    loop {
        let n = body
            .read(&mut buf)
            .map_err(|e| DownloadError::SourceIo(e.to_string()))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| DownloadError::io(part, e))?;
        written += n as u64;
        since_checkpoint += n as u64;

        if let Some(limit) = expected_len {
            if written > limit {
                return Err(DownloadError::UnexpectedExtraBytes);
            }
        }

        if since_checkpoint >= JOURNAL_CHECKPOINT_INTERVAL {
            // Flush first, *then* advance the checkpoint: the offset may
            // only claim bytes that have already reached the durability
            // level the resume path relies on (commit 31).
            file.sync_all().map_err(|e| DownloadError::io(part, e))?;
            let checkpoint = DownloadJournal {
                confirmed_offset: start_offset + written,
                expected_size,
                expected_sha256_hex: expected_sha256_hex.to_string(),
                etag: response_etag.map(str::to_string),
            };
            DownloadJournal::advance(jpath, part, &checkpoint)?;
            since_checkpoint = 0;
        }
    }

    if let Some(limit) = expected_len {
        if written != limit {
            return Err(DownloadError::ShortBody {
                expected: limit,
                actual: written,
            });
        }
    }

    file.sync_all().map_err(|e| DownloadError::io(part, e))?;
    Ok(written)
}

/// Lowercase hex SHA-256 of a whole file. `pub(crate)` so
/// [`super::artifact::ArtifactInspector`] can tell a correct committed
/// file from a same-size wrong one using the identical digest routine this
/// module commits with — two implementations would be two chances to
/// disagree.
pub(crate) fn sha256_of_file(path: &Path) -> Result<String, DownloadError> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path).map_err(|e| DownloadError::io(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| DownloadError::io(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// =====================================================================
// 7. Publication verifier (plan 9.2 step 7)
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("publication verification failed: {0}")]
    Rejected(String),
}

/// Integration seam for publication-signature verification (plan 9.2
/// point 7 / 6.1 invariant 8). Implementations receive the exact signed
/// payload, detached signature, and raw Ed25519 public key. They must reject
/// missing, malformed, or invalid material; [`commit_session`] always calls
/// this before publishing the session.
pub trait PublicationVerifier: Send + Sync {
    fn verify(
        &self,
        manifest_bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), VerifyError>;
}

/// Borrowed detached-signature envelope supplied atomically to a commit.
/// Grouping these fields prevents callers from accidentally omitting or
/// reordering one of the three security-critical byte strings.
#[derive(Debug, Clone, Copy)]
pub struct PublicationMaterial<'a> {
    pub payload: &'a [u8],
    pub signature: &'a [u8],
    pub public_key: &'a [u8],
}

/// Test-only fake. Production dependants cannot import or construct it.
#[cfg(test)]
pub struct AlwaysPassVerifierStub;

#[cfg(test)]
impl PublicationVerifier for AlwaysPassVerifierStub {
    fn verify(
        &self,
        _manifest_bytes: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> Result<(), VerifyError> {
        Ok(())
    }
}

/// Test-only rejecting fake used to prove the commit path fails closed.
#[cfg(test)]
pub struct AlwaysFailVerifierStub(pub String);

#[cfg(test)]
impl PublicationVerifier for AlwaysFailVerifierStub {
    fn verify(
        &self,
        _manifest_bytes: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> Result<(), VerifyError> {
        Err(VerifyError::Rejected(self.0.clone()))
    }
}

// =====================================================================
// 8. Session-level commit (plan 9.2 step 5, second half)
// =====================================================================

/// In-memory result of an atomic local-library commit. The production
/// coordinator persists this result only after every file hash has verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalLibraryState {
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLibraryEntry {
    pub device_id: String,
    pub session_id: String,
    pub files: Vec<VerifiedFile>,
    pub state: LocalLibraryState,
}

/// Commit a whole session assembled in [`SessionStaging`] into a
/// [`LocalLibraryEntry`].
///
/// This is the production commit boundary. Publication material is verified,
/// the staging identity and complete manifest are cross-checked, and only
/// then does [`SessionStaging::publish`] seal and atomically rename the whole
/// session into the visible library. There is deliberately no visible-tree
/// fallback here: a caller that did not stage its bytes must fail closed.
#[allow(clippy::too_many_arguments)]
pub fn commit_staged_session(
    staging: &SessionStaging,
    device_id: String,
    session_id: String,
    files: Vec<VerifiedFile>,
    manifest: &SessionManifest,
    publication: PublicationMaterial<'_>,
    verifier: &dyn PublicationVerifier,
    publication_scope: PublicationScope,
) -> Result<LocalLibraryEntry, DownloadError> {
    verifier.verify(
        publication.payload,
        publication.signature,
        publication.public_key,
    )?;

    let expected_revision = RevisionId::from_publication(publication.payload);
    if staging.revision() != &expected_revision {
        return Err(DownloadError::InvalidPlan(format!(
            "staging revision {} does not match publication revision {}",
            staging.revision(),
            expected_revision
        )));
    }
    if staging.device_id() != device_id
        || staging.session_id() != session_id
        || manifest.device_id != device_id
        || manifest.session_id != session_id
    {
        return Err(DownloadError::InvalidPlan(
            "staged publication identity does not match its session manifest".to_string(),
        ));
    }

    // Empty sessions still get a hidden revision directory and a seal. This
    // keeps their durable state machine identical to multi-file sessions.
    staging.prepare()?;
    match publication_scope {
        PublicationScope::FullSession => staging.publish(manifest),
        PublicationScope::SelectedFiles => staging.publish_selected(manifest),
    }
    .map_err(DownloadError::from)?;
    Ok(LocalLibraryEntry {
        device_id,
        session_id,
        files,
        state: LocalLibraryState::Committed,
    })
}

/// Commit a staged session when the caller has only the verified-file list
/// (the compatibility shape used by older core callers). Production code
/// should prefer [`commit_staged_session`] with the original plans so a file
/// omitted from the verified list cannot be silently accepted.
pub fn commit_session(
    session_dir: &Path,
    device_id: String,
    session_id: String,
    files: Vec<VerifiedFile>,
    publication: PublicationMaterial<'_>,
    verifier: &dyn PublicationVerifier,
) -> Result<LocalLibraryEntry, DownloadError> {
    let library_root = library_root_of(session_dir, &device_id, &session_id).ok_or_else(|| {
        DownloadError::InvalidPlan(
            "staged commit requires a <library>/<device>/<session> path".to_string(),
        )
    })?;
    let staging = SessionStaging::for_publication(
        library_root,
        &device_id,
        &session_id,
        publication.payload,
    )?;
    let manifest =
        SessionManifest::from_verified(&device_id, &session_id, &staging.revision_dir(), &files);
    commit_staged_session(
        &staging,
        device_id,
        session_id,
        files,
        &manifest,
        publication,
        verifier,
        PublicationScope::FullSession,
    )
}

/// Explicit legacy recovery for a pre-staging job whose bytes are already in
/// the visible session directory. This is intentionally a separate API so a
/// production transfer cannot accidentally publish a mixed tree by omitting
/// staging. New jobs must use [`commit_staged_session`] or [`commit_session`].
pub fn commit_legacy_session(
    session_dir: &Path,
    device_id: String,
    session_id: String,
    files: Vec<VerifiedFile>,
    publication: PublicationMaterial<'_>,
    verifier: &dyn PublicationVerifier,
) -> Result<LocalLibraryEntry, DownloadError> {
    verifier.verify(
        publication.payload,
        publication.signature,
        publication.public_key,
    )?;
    fsync_dir(session_dir)?;
    Ok(LocalLibraryEntry {
        device_id,
        session_id,
        files,
        state: LocalLibraryState::Committed,
    })
}

/// Recover the library root from a `<library_root>/<device>/<session>` path.
/// `None` when `session_dir` does not have that exact shape.
fn library_root_of(session_dir: &Path, device_id: &str, session_id: &str) -> Option<PathBuf> {
    let device_dir = session_dir.parent()?;
    if session_dir.file_name()? != std::ffi::OsStr::new(session_id)
        || device_dir.file_name()? != std::ffi::OsStr::new(device_id)
    {
        return None;
    }
    Some(device_dir.parent()?.to_path_buf())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::download_contract::{
        assert_download_source_contract, contract_total, ContractCase,
        DownloadSourceContractHarness, CONTRACT_BODY, CONTRACT_ETAG, CONTRACT_RESUME_START,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tempfile::tempdir;

    // -----------------------------------------------------------------
    // Path safety
    // -----------------------------------------------------------------

    #[test]
    fn validate_id_segment_accepts_ordinary_ids() {
        assert!(validate_id_segment("device-123").is_ok());
        assert!(validate_id_segment("session_ABC.99").is_ok());
    }

    #[test]
    fn validate_id_segment_rejects_dotdot_and_dot() {
        assert!(matches!(
            validate_id_segment(".."),
            Err(PathSafetyError::DotDot)
        ));
        assert!(matches!(
            validate_id_segment("."),
            Err(PathSafetyError::DotDot)
        ));
    }

    #[test]
    fn validate_id_segment_rejects_separators_and_absolute_looking_ids() {
        assert!(matches!(
            validate_id_segment("a/b"),
            Err(PathSafetyError::PathSeparator)
        ));
        assert!(matches!(
            validate_id_segment("a\\b"),
            Err(PathSafetyError::PathSeparator)
        ));
        assert!(matches!(
            validate_id_segment("/etc/passwd"),
            Err(PathSafetyError::PathSeparator)
        ));
        assert!(matches!(
            validate_id_segment("\\\\server\\share"),
            Err(PathSafetyError::PathSeparator)
        ));
    }

    #[test]
    fn validate_id_segment_rejects_drive_letters_and_nul() {
        assert!(matches!(
            validate_id_segment("C:"),
            Err(PathSafetyError::DriveOrColon)
        ));
        assert!(matches!(
            validate_id_segment("a\0b"),
            Err(PathSafetyError::NulByte)
        ));
    }

    #[test]
    fn validate_id_segment_rejects_windows_forbidden_characters() {
        for name in [
            "bad<name",
            "bad>name",
            "bad\"name",
            "bad|name",
            "bad?name",
            "bad*name",
            "bad\u{1f}name",
        ] {
            assert!(matches!(
                validate_id_segment(name),
                Err(PathSafetyError::ForbiddenWindowsCharacter)
            ));
        }
    }

    #[test]
    fn validate_id_segment_rejects_reserved_windows_names_case_insensitively() {
        for name in [
            "CON",
            "con",
            "NUL",
            "nul.txt",
            "COM1",
            "lpt9",
            "Com3.mp4",
            "CLOCK$",
            "conin$.txt",
        ] {
            assert!(
                matches!(
                    validate_id_segment(name),
                    Err(PathSafetyError::ReservedDeviceName(_))
                ),
                "expected {name:?} to be rejected as reserved"
            );
        }
        // Not reserved: a name that merely starts with a reserved prefix.
        assert!(validate_id_segment("CONFIG").is_ok());
        assert!(validate_id_segment("COM10").is_ok());
    }

    #[test]
    fn validate_relative_path_accepts_portable_nested_pi_paths() {
        for path in ["video/left_00000.mp4", "imu/imu_00000.csv", "session.json"] {
            assert!(validate_relative_path(path).is_ok(), "{path:?}");
        }
    }

    #[test]
    fn validate_relative_path_rejects_escape_absolute_and_empty_segments() {
        for path in [
            "",
            "/video/left.mp4",
            "video/left.mp4/",
            "video//left.mp4",
            "./left.mp4",
            "../left.mp4",
            "video/../left.mp4",
            "C:/Windows/file.mp4",
            "\\\\server\\share\\file.mp4",
            "video/NUL.mp4",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "unsafe relative path {path:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_id_segment_rejects_trailing_dot_or_space() {
        assert!(matches!(
            validate_id_segment("file."),
            Err(PathSafetyError::TrailingDotOrSpace)
        ));
        assert!(matches!(
            validate_id_segment("file "),
            Err(PathSafetyError::TrailingDotOrSpace)
        ));
    }

    #[test]
    fn derive_target_path_builds_expected_layout_for_safe_ids() {
        let root = tempdir().expect("tempdir");
        let path = derive_target_path(root.path(), "dev1", "sess1", "file1.mp4")
            .expect("safe ids should derive a path");
        assert_eq!(
            path,
            root.path().join("dev1").join("sess1").join("file1.mp4")
        );
    }

    #[test]
    fn derive_target_path_propagates_segment_validation_errors() {
        let root = tempdir().expect("tempdir");
        assert!(derive_target_path(root.path(), "..", "sess1", "file1").is_err());
        assert!(derive_target_path(root.path(), "dev1", "sess1", "../../etc/passwd").is_err());
    }

    #[test]
    fn derive_target_path_uses_pi_relative_path_and_legacy_jobs_fall_back_to_file_id() {
        let root = tempdir().expect("tempdir");
        let published = derive_target_path_for_file(
            root.path(),
            "dev1",
            "sess1",
            "opaque-file-id",
            Some("video/left_00000.mp4"),
        )
        .expect("signed relative path is safe");
        assert_eq!(
            published,
            root.path()
                .join("dev1")
                .join("sess1")
                .join("video")
                .join("left_00000.mp4")
        );

        let legacy =
            derive_target_path_for_file(root.path(), "dev1", "sess1", "opaque-file-id", None)
                .expect("legacy fallback is safe");
        assert_eq!(
            legacy,
            root.path()
                .join("dev1")
                .join("sess1")
                .join("opaque-file-id")
        );
    }

    #[test]
    fn case_insensitive_collision_is_detected() {
        let root = tempdir().expect("tempdir");
        fs::write(root.path().join("File.MP4"), b"existing").expect("seed file");
        let err = check_case_insensitive_collision(root.path(), "file.mp4")
            .expect_err("differently-cased collision must be rejected");
        assert!(matches!(
            err,
            PathSafetyError::CaseInsensitiveCollision { .. }
        ));
        // Exact-name match (e.g. re-downloading the same file) is fine.
        assert!(check_case_insensitive_collision(root.path(), "File.MP4").is_ok());
    }

    #[test]
    fn nested_directory_case_collision_is_rejected_before_download() {
        let root = tempdir().expect("tempdir");
        fs::create_dir_all(root.path().join("dev1").join("sess1").join("Video"))
            .expect("seed differently-cased directory");

        let data = b"hello world";
        let source = FakeSource::new(vec![full_response(data, "etag-1")]);
        let mut plan = plan_for(data);
        plan.target_relative_path = Some("video/left.mp4".to_string());
        let err = download_file(&source, &plan, root.path())
            .expect_err("differently-cased directory must be rejected");
        assert!(matches!(
            err,
            DownloadError::PathSafety(PathSafetyError::CaseInsensitiveCollision { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_part_path_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("tempdir");
        let secret = root.path().join("secret.txt");
        fs::write(&secret, b"do not touch").expect("seed secret file");

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        symlink(&secret, &part).expect("create symlink");

        let source = FakeSource::new(vec![full_response(b"hello world", "etag-1")]);
        let plan = plan_for(b"hello world");
        let err =
            download_file(&source, &plan, root.path()).expect_err("must reject symlinked .part");
        assert!(matches!(
            err,
            DownloadError::PathSafety(PathSafetyError::SymlinkNotAllowed(_))
        ));
        // The secret file must be untouched.
        assert_eq!(fs::read(&secret).unwrap(), b"do not touch");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_intermediate_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("tempdir");
        let elsewhere = tempdir().expect("elsewhere");
        symlink(elsewhere.path(), root.path().join("dev1")).expect("symlink device dir");

        let source = FakeSource::new(vec![full_response(b"hello world", "etag-1")]);
        let plan = plan_for(b"hello world");
        let err = download_file(&source, &plan, root.path())
            .expect_err("must reject a symlinked intermediate directory");
        assert!(matches!(
            err,
            DownloadError::PathSafety(PathSafetyError::SymlinkNotAllowed(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_nested_display_path_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("tempdir");
        let elsewhere = tempdir().expect("elsewhere");
        let session = root.path().join("dev1").join("sess1");
        fs::create_dir_all(&session).expect("create session directory");
        symlink(elsewhere.path(), session.join("video")).expect("symlink nested directory");

        let data = b"hello world";
        let source = FakeSource::new(vec![full_response(data, "etag-1")]);
        let mut plan = plan_for(data);
        plan.target_relative_path = Some("video/left.mp4".to_string());
        let err = download_file(&source, &plan, root.path())
            .expect_err("nested symlink must be rejected");
        assert!(matches!(
            err,
            DownloadError::PathSafety(PathSafetyError::SymlinkNotAllowed(_))
        ));
    }

    // -----------------------------------------------------------------
    // Crash recovery
    // -----------------------------------------------------------------

    #[test]
    fn recover_resume_offset_truncates_to_the_smaller_of_actual_and_claimed() {
        let dir = tempdir().expect("tempdir");
        let part = dir.path().join("f.part");

        // actual (200 bytes) > claimed (50): must truncate down to 50.
        fs::write(&part, vec![7u8; 200]).unwrap();
        let journal = DownloadJournal {
            confirmed_offset: 50,
            expected_size: 200,
            expected_sha256_hex: "0".repeat(64),
            etag: Some("e".to_string()),
        };
        let offset = recover_resume_offset(&part, Some(&journal)).expect("recover succeeds");
        assert_eq!(offset, 50);
        assert_eq!(fs::metadata(&part).unwrap().len(), 50);

        // actual (50 bytes, post-truncation) < claimed (150): min is the
        // actual on-disk length; no further truncation needed/possible.
        let journal2 = DownloadJournal {
            confirmed_offset: 150,
            ..journal
        };
        let offset2 = recover_resume_offset(&part, Some(&journal2)).expect("recover succeeds");
        assert_eq!(offset2, 50);
        assert_eq!(fs::metadata(&part).unwrap().len(), 50);
    }

    #[test]
    fn recover_resume_offset_treats_missing_journal_as_zero_confirmed() {
        let dir = tempdir().expect("tempdir");
        let part = dir.path().join("f.part");
        fs::write(&part, vec![1u8; 30]).unwrap();

        let offset = recover_resume_offset(&part, None).expect("recover succeeds");
        assert_eq!(offset, 0);
        assert_eq!(fs::metadata(&part).unwrap().len(), 0);
    }

    #[test]
    fn corrupt_journal_is_read_as_none_and_recovery_falls_back_to_zero() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("f");
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, vec![9u8; 40]).unwrap();
        fs::write(&jpath, b"{ this is not valid json").unwrap();

        let read_back = DownloadJournal::read(&jpath).expect("read does not error on corruption");
        assert!(read_back.is_none());

        let offset = recover_resume_offset(&part, read_back.as_ref()).expect("recover succeeds");
        assert_eq!(offset, 0);
        assert_eq!(fs::metadata(&part).unwrap().len(), 0);
    }

    // -----------------------------------------------------------------
    // Content-Range parsing (pure)
    // -----------------------------------------------------------------

    #[test]
    fn interpret_range_response_accepts_well_formed_206() {
        let outcome =
            interpret_range_response(206, Some("bytes 10-19/100"), None, 10).expect("parses");
        assert_eq!(
            outcome,
            RangeOutcome::Partial {
                start: 10,
                end_inclusive: 19,
                total: 100
            }
        );
    }

    #[test]
    fn interpret_range_response_rejects_206_with_mismatched_start() {
        let err = interpret_range_response(206, Some("bytes 10-19/100"), None, 0)
            .expect_err("start mismatch must be rejected");
        assert!(matches!(err, DownloadError::RangeMismatch { .. }));
    }

    #[test]
    fn interpret_range_response_rejects_missing_content_range_on_206() {
        let err = interpret_range_response(206, None, None, 0).expect_err("must be rejected");
        assert!(matches!(err, DownloadError::MalformedContentRange(_)));
    }

    #[test]
    fn interpret_range_response_rejects_malformed_headers() {
        for bad in [
            "not-bytes 0-9/10",
            "bytes 0-9",                              // missing total
            "bytes 0-9/*",                            // v1 requires an exact total
            "bytes 9-0/10",                           // start > end
            "bytes 0-99/10",                          // end >= total
            "bytes 0-10,20-30/40",                    // multi-range
            "bytes abc-def/10",                       // non-numeric
            "bytes 0-99999999999999999999999999/100", // overflow
        ] {
            let err = interpret_range_response(206, Some(bad), None, 0)
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(
                matches!(err, DownloadError::MalformedContentRange(_)),
                "wrong error for {bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn interpret_range_response_handles_200_416_412() {
        assert_eq!(
            interpret_range_response(200, None, Some(42), 0).unwrap(),
            RangeOutcome::FullFromZero { total: Some(42) }
        );
        assert_eq!(
            interpret_range_response(416, Some("bytes */7"), None, 999).unwrap(),
            RangeOutcome::NotSatisfiable { total: Some(7) }
        );
        assert_eq!(
            interpret_range_response(412, None, None, 5).unwrap(),
            RangeOutcome::PreconditionFailed
        );
    }

    #[test]
    fn interpret_range_response_rejects_unexpected_status() {
        let err = interpret_range_response(503, None, None, 0).expect_err("must be rejected");
        assert!(matches!(err, DownloadError::UnexpectedStatus(503)));
    }

    // -----------------------------------------------------------------
    // Fake DownloadSource for full download_file() orchestration tests
    // -----------------------------------------------------------------

    struct ScriptedResponse {
        status: u16,
        etag: Option<String>,
        content_range: Option<String>,
        content_length: Option<u64>,
        body: Vec<u8>,
        /// If set, the body reader errors out after this many bytes,
        /// simulating a dropped connection / truncated stream.
        fail_after: Option<usize>,
    }

    struct FailingReader {
        data: Vec<u8>,
        pos: usize,
        fail_after: Option<usize>,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(limit) = self.fail_after {
                if self.pos >= limit {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "simulated drop",
                    ));
                }
            }
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let mut n = (self.data.len() - self.pos).min(buf.len());
            if let Some(limit) = self.fail_after {
                n = n.min(limit - self.pos);
            }
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    struct FakeSource {
        responses: Mutex<VecDeque<ScriptedResponse>>,
        requests: Mutex<Vec<RequestedRange>>,
    }

    impl FakeSource {
        fn new(responses: Vec<ScriptedResponse>) -> Self {
            FakeSource {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn recorded_requests(&self) -> Vec<RequestedRange> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| RequestedRange {
                    start: r.start,
                    if_match_etag: r.if_match_etag.clone(),
                })
                .collect()
        }
    }

    impl DownloadSource for FakeSource {
        fn fetch_range(&self, request: RequestedRange) -> Result<SourceResponse, DownloadError> {
            self.requests.lock().unwrap().push(RequestedRange {
                start: request.start,
                if_match_etag: request.if_match_etag.clone(),
            });
            let scripted = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake source ran out of scripted responses");
            let body: Box<dyn Read + Send> = Box::new(FailingReader {
                data: scripted.body,
                pos: 0,
                fail_after: scripted.fail_after,
            });
            Ok(SourceResponse {
                status: scripted.status,
                etag: scripted.etag,
                content_range: scripted.content_range,
                content_length: scripted.content_length,
                body,
            })
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    fn plan_for(data: &[u8]) -> FilePlan {
        FilePlan {
            device_id: "dev1".to_string(),
            session_id: "sess1".to_string(),
            file_id: "file1".to_string(),
            target_relative_path: None,
            expected_size: data.len() as u64,
            expected_sha256_hex: sha256_hex(data),
        }
    }

    fn full_response(data: &[u8], etag: &str) -> ScriptedResponse {
        ScriptedResponse {
            status: 206,
            etag: Some(etag.to_string()),
            content_range: Some(format!("bytes 0-{}/{}", data.len() - 1, data.len())),
            content_length: Some(data.len() as u64),
            body: data.to_vec(),
            fail_after: None,
        }
    }

    // -----------------------------------------------------------------
    // download_file() orchestration
    // -----------------------------------------------------------------

    #[test]
    fn download_commits_with_pi_filename_extension_and_subdirectories() {
        let root = tempdir().expect("tempdir");
        let data = b"original Pi file bytes".to_vec();
        let source = FakeSource::new(vec![full_response(&data, "etag-1")]);
        let mut plan = plan_for(&data);
        plan.file_id = "f-opaque-api-id".to_string();
        plan.target_relative_path = Some("video/left_00000.mp4".to_string());

        let verified = download_file(&source, &plan, root.path()).expect("download succeeds");
        let expected = root
            .path()
            .join("dev1")
            .join("sess1")
            .join("video")
            .join("left_00000.mp4");
        assert_eq!(verified.file_id, "f-opaque-api-id");
        assert_eq!(verified.path, expected);
        assert_eq!(fs::read(&verified.path).unwrap(), data);
        assert!(!root
            .path()
            .join("dev1")
            .join("sess1")
            .join("f-opaque-api-id")
            .exists());
    }

    #[test]
    fn normal_full_download_verifies_and_commits() {
        let root = tempdir().expect("tempdir");
        let data = b"the quick brown fox jumps over the lazy dog".to_vec();
        let source = FakeSource::new(vec![full_response(&data, "etag-1")]);
        let plan = plan_for(&data);

        let verified = download_file(&source, &plan, root.path()).expect("download succeeds");

        assert_eq!(verified.size_bytes, data.len() as u64);
        assert_eq!(verified.sha256_hex, sha256_hex(&data));
        assert_eq!(verified.etag.as_deref(), Some("etag-1"));
        assert_eq!(fs::read(&verified.path).unwrap(), data);
        assert!(
            !part_path(&verified.path).exists(),
            ".part must be gone after commit"
        );
        assert!(
            !journal_path(&verified.path).exists(),
            "journal must be gone after commit"
        );
    }

    #[test]
    fn resume_from_partial_sends_206_from_the_confirmed_offset() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789ABCDEFGHIJ".to_vec(); // 20 bytes
        let already = &full[..8];
        let rest = &full[8..];

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, already).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                confirmed_offset: 8,
                expected_size: full.len() as u64,
                expected_sha256_hex: sha256_hex(&full),
                etag: Some("etag-1".to_string()),
            },
        )
        .unwrap();

        let resp = ScriptedResponse {
            status: 206,
            etag: Some("etag-1".to_string()),
            content_range: Some(format!("bytes 8-{}/{}", full.len() - 1, full.len())),
            content_length: Some(rest.len() as u64),
            body: rest.to_vec(),
            fail_after: None,
        };
        let source = FakeSource::new(vec![resp]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path()).expect("resume succeeds");

        assert_eq!(fs::read(&verified.path).unwrap(), full);
        let requests = source.recorded_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].start, 8,
            "must resume from the confirmed offset, not 0"
        );
        assert_eq!(requests[0].if_match_etag.as_deref(), Some("etag-1"));
    }

    #[test]
    fn server_ignoring_range_returns_200_and_engine_restarts_from_zero() {
        let root = tempdir().expect("tempdir");
        let full = b"AAAAAAAAAABBBBBBBBBB".to_vec(); // 20 bytes
        let stale_garbage = b"XXXXXXXX"; // NOT a prefix of `full` — if the
                                         // engine wrongly appended instead
                                         // of restarting, the final hash
                                         // would not match.

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, stale_garbage).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                confirmed_offset: stale_garbage.len() as u64,
                expected_size: full.len() as u64,
                expected_sha256_hex: sha256_hex(&full),
                etag: Some("etag-old".to_string()),
            },
        )
        .unwrap();

        let resp = ScriptedResponse {
            status: 200,
            etag: Some("etag-new".to_string()),
            content_range: None,
            content_length: Some(full.len() as u64),
            body: full.clone(),
            fail_after: None,
        };
        let source = FakeSource::new(vec![resp]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path()).expect("download succeeds");
        assert_eq!(fs::read(&verified.path).unwrap(), full);
        assert_eq!(verified.etag.as_deref(), Some("etag-new"));
    }

    #[test]
    fn range_not_satisfiable_416_is_a_hard_error() {
        let root = tempdir().expect("tempdir");
        let plan = plan_for(b"irrelevant");
        let source = FakeSource::new(vec![ScriptedResponse {
            status: 416,
            etag: None,
            content_range: Some("bytes */10".to_string()),
            content_length: None,
            body: vec![],
            fail_after: None,
        }]);

        let err = download_file(&source, &plan, root.path()).expect_err("416 must fail");
        assert!(matches!(err, DownloadError::RangeNotSatisfiable));
    }

    #[test]
    fn malformed_content_range_is_a_hard_error() {
        let root = tempdir().expect("tempdir");
        let plan = plan_for(b"irrelevant");
        let source = FakeSource::new(vec![ScriptedResponse {
            status: 206,
            etag: Some("e".to_string()),
            content_range: Some("bytes 0-10,20-30/100".to_string()),
            content_length: None,
            body: vec![],
            fail_after: None,
        }]);

        let err =
            download_file(&source, &plan, root.path()).expect_err("malformed header must fail");
        assert!(matches!(err, DownloadError::MalformedContentRange(_)));
    }

    #[test]
    fn short_body_fails_verification_and_does_not_commit() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789".to_vec();
        // Content-Range promises all 10 bytes, but the body reader only
        // actually has 5 before EOF — a short/dropped stream.
        let resp = ScriptedResponse {
            status: 206,
            etag: Some("e".to_string()),
            content_range: Some(format!("bytes 0-{}/{}", full.len() - 1, full.len())),
            content_length: Some(full.len() as u64),
            body: full[..5].to_vec(),
            fail_after: None,
        };
        let source = FakeSource::new(vec![resp]);
        let plan = plan_for(&full);

        let err = download_file(&source, &plan, root.path()).expect_err("short body must fail");
        assert!(matches!(
            err,
            DownloadError::ShortBody {
                expected: 10,
                actual: 5
            }
        ));

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        assert!(!target.exists(), "must not commit on a short body");
    }

    #[test]
    fn hash_mismatch_fails_verification_and_does_not_commit() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789".to_vec();
        let resp = full_response(&full, "e");
        let source = FakeSource::new(vec![resp]);
        let mut plan = plan_for(&full);
        plan.expected_sha256_hex = "0".repeat(64); // deliberately wrong

        let err = download_file(&source, &plan, root.path()).expect_err("hash mismatch must fail");
        assert!(matches!(err, DownloadError::HashMismatch { .. }));

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        assert!(!target.exists());
        assert!(
            !part_path(&target).exists(),
            "corrupt .part must be discarded, not left around"
        );
    }

    #[test]
    fn size_mismatch_fails_verification_and_does_not_commit() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789".to_vec();
        let resp = full_response(&full, "e");
        let source = FakeSource::new(vec![resp]);
        let mut plan = plan_for(&full);
        plan.expected_size = 999; // deliberately wrong

        let err = download_file(&source, &plan, root.path()).expect_err("size mismatch must fail");
        assert!(matches!(
            err,
            DownloadError::SizeMismatch {
                expected: 999,
                actual: 10
            }
        ));
    }

    #[test]
    fn etag_change_mid_flight_discards_partial_and_restarts_via_412() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789ABCDEFGHIJ".to_vec();

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, &full[..8]).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                confirmed_offset: 8,
                expected_size: full.len() as u64,
                expected_sha256_hex: sha256_hex(&full),
                etag: Some("etag-old".to_string()),
            },
        )
        .unwrap();

        // First request (resuming from offset 8, If-Match etag-old) is told
        // the precondition failed (server-side content changed). Second
        // request (fresh, from 0) succeeds with the new content/etag.
        let source = FakeSource::new(vec![
            ScriptedResponse {
                status: 412,
                etag: None,
                content_range: None,
                content_length: None,
                body: vec![],
                fail_after: None,
            },
            full_response(&full, "etag-new"),
        ]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path()).expect("restart succeeds");
        assert_eq!(verified.etag.as_deref(), Some("etag-new"));
        assert_eq!(fs::read(&verified.path).unwrap(), full);

        let requests = source.recorded_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].start, 8);
        assert_eq!(requests[0].if_match_etag.as_deref(), Some("etag-old"));
        assert_eq!(
            requests[1].start, 0,
            "must restart from 0 after precondition failure"
        );
        assert_eq!(requests[1].if_match_etag, None);
    }

    #[test]
    fn etag_mismatch_on_a_numerically_matching_206_is_also_treated_as_a_restart() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789ABCDEFGHIJ".to_vec();

        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, &full[..8]).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                confirmed_offset: 8,
                expected_size: full.len() as u64,
                expected_sha256_hex: sha256_hex(&full),
                etag: Some("etag-old".to_string()),
            },
        )
        .unwrap();

        // No explicit 412 here: the server answers 206 at the numerically
        // requested offset, but with a *different* ETag than we remember.
        // The engine must not trust it as a real resume.
        let source = FakeSource::new(vec![
            ScriptedResponse {
                status: 206,
                etag: Some("etag-new".to_string()),
                content_range: Some(format!("bytes 8-{}/{}", full.len() - 1, full.len())),
                content_length: Some((full.len() - 8) as u64),
                body: full[8..].to_vec(),
                fail_after: None,
            },
            full_response(&full, "etag-new"),
        ]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path()).expect("restart succeeds");
        assert_eq!(fs::read(&verified.path).unwrap(), full);

        let requests = source.recorded_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].start, 0,
            "must restart from 0, not trust the mismatched-etag 206"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_directory_surfaces_a_structured_io_error_not_a_panic() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().expect("tempdir");
        let locked = root.path().join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap(); // r-x, no write

        // A device-id directory nested under the read-only directory: the
        // engine must fail to create it and surface a structured Io error.
        let plan = plan_for(b"irrelevant");
        let source = FakeSource::new(vec![full_response(b"irrelevant", "e")]);
        let result = download_file(&source, &plan, &locked);

        // Restore permissions unconditionally so tempdir cleanup succeeds.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            Err(DownloadError::Io { .. }) => {}
            Err(DownloadError::PathSafety(PathSafetyError::Io { .. })) => {}
            Ok(_) => {
                // Running as root (or on a filesystem that ignores the
                // permission bits) can make writes succeed anyway — don't
                // fail the test in that environment, but do make it loud.
                eprintln!(
                    "WARNING: write into a chmod 0o500 directory unexpectedly succeeded \
                     (likely running as root) — permission-error path not exercised"
                );
            }
            Err(other) => panic!("expected a structured Io error, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Publication verifier
    // -----------------------------------------------------------------

    #[test]
    fn publication_verifier_stub_pass_commits_session() {
        let root = tempdir().expect("tempdir");
        let entry = commit_legacy_session(
            root.path(),
            "dev1".to_string(),
            "sess1".to_string(),
            vec![],
            PublicationMaterial {
                payload: b"manifest-bytes",
                signature: b"signature-bytes",
                public_key: b"public-key-bytes",
            },
            &AlwaysPassVerifierStub,
        )
        .expect("pass-stub allows commit");
        assert_eq!(entry.state, LocalLibraryState::Committed);
    }

    #[test]
    fn publication_verifier_stub_fail_blocks_commit() {
        let root = tempdir().expect("tempdir");
        let err = commit_legacy_session(
            root.path(),
            "dev1".to_string(),
            "sess1".to_string(),
            vec![],
            PublicationMaterial {
                payload: b"manifest-bytes",
                signature: b"signature-bytes",
                public_key: b"public-key-bytes",
            },
            &AlwaysFailVerifierStub("simulated signature rejection".to_string()),
        )
        .expect_err("fail-stub must block commit");
        assert!(matches!(err, DownloadError::Verification(_)));
    }

    #[test]
    fn publication_verifier_receives_payload_signature_and_public_key() {
        type SeenPublication = (Vec<u8>, Vec<u8>, Vec<u8>);

        struct RecordingVerifier {
            seen: Mutex<Vec<SeenPublication>>,
        }
        impl PublicationVerifier for RecordingVerifier {
            fn verify(
                &self,
                manifest_bytes: &[u8],
                signature: &[u8],
                public_key: &[u8],
            ) -> Result<(), VerifyError> {
                self.seen.lock().unwrap().push((
                    manifest_bytes.to_vec(),
                    signature.to_vec(),
                    public_key.to_vec(),
                ));
                Ok(())
            }
        }

        let root = tempdir().expect("tempdir");
        let verifier = RecordingVerifier {
            seen: Mutex::new(Vec::new()),
        };
        commit_legacy_session(
            root.path(),
            "dev1".to_string(),
            "sess1".to_string(),
            vec![],
            PublicationMaterial {
                payload: b"the-manifest",
                signature: b"the-signature",
                public_key: b"the-public-key",
            },
            &verifier,
        )
        .expect("commit succeeds");

        let seen = verifier.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, b"the-manifest");
        assert_eq!(seen[0].1, b"the-signature");
        assert_eq!(seen[0].2, b"the-public-key");
    }

    // -----------------------------------------------------------------
    // Shared DownloadSource contract (issue #1 commit 10) — this crate's
    // in-memory fake side. The production `PiDownloadSource` side lives in
    // `ylx-transfer-adapters` and runs the identical suite.
    // -----------------------------------------------------------------

    struct FakeSourceContractHarness;

    impl DownloadSourceContractHarness for FakeSourceContractHarness {
        fn name(&self) -> &str {
            "library::download::tests::FakeSource"
        }

        fn source_for(&self, case: ContractCase) -> Box<dyn DownloadSource> {
            let total = contract_total();
            let scripted = match case {
                ContractCase::FullFromZero => ScriptedResponse {
                    status: 200,
                    etag: Some(CONTRACT_ETAG.to_string()),
                    content_range: None,
                    content_length: Some(total),
                    body: CONTRACT_BODY.to_vec(),
                    fail_after: None,
                },
                ContractCase::PartialFromOffset => ScriptedResponse {
                    status: 206,
                    etag: Some(CONTRACT_ETAG.to_string()),
                    content_range: Some(format!(
                        "bytes {}-{}/{}",
                        CONTRACT_RESUME_START,
                        total - 1,
                        total
                    )),
                    content_length: Some(total - CONTRACT_RESUME_START),
                    body: CONTRACT_BODY[CONTRACT_RESUME_START as usize..].to_vec(),
                    fail_after: None,
                },
                ContractCase::PreconditionFailed => ScriptedResponse {
                    status: 412,
                    etag: None,
                    content_range: None,
                    content_length: None,
                    body: Vec::new(),
                    fail_after: None,
                },
                ContractCase::RangeNotSatisfiable => ScriptedResponse {
                    status: 416,
                    etag: None,
                    content_range: Some(format!("bytes */{total}")),
                    content_length: None,
                    body: Vec::new(),
                    fail_after: None,
                },
            };
            Box::new(FakeSource::new(vec![scripted]))
        }
    }

    #[test]
    fn in_memory_fake_source_satisfies_the_download_source_contract() {
        assert_download_source_contract(&FakeSourceContractHarness);
    }

    // -----------------------------------------------------------------
    // 416 on a resumed request (issue #1 commit 11)
    // -----------------------------------------------------------------

    /// Seed a `.part` file plus a journal claiming every one of its bytes
    /// is confirmed, as a crashed-just-before-commit run would leave them.
    fn seed_partial(root: &Path, bytes: &[u8], expected: &[u8], etag: &str) -> PathBuf {
        let target = derive_target_path(root, "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        fs::write(&part, bytes).unwrap();
        DownloadJournal::write(
            &journal_path(&target),
            &DownloadJournal {
                confirmed_offset: bytes.len() as u64,
                expected_size: expected.len() as u64,
                expected_sha256_hex: sha256_hex(expected),
                etag: Some(etag.to_string()),
            },
        )
        .unwrap();
        target
    }

    fn unsatisfiable_response(total: u64) -> ScriptedResponse {
        ScriptedResponse {
            status: 416,
            etag: None,
            content_range: Some(format!("bytes */{total}")),
            content_length: None,
            body: Vec::new(),
            fail_after: None,
        }
    }

    #[test]
    fn resume_416_on_an_already_complete_partial_verifies_and_commits() {
        let root = tempdir().expect("tempdir");
        let full = b"a complete file that the server has nothing left to send".to_vec();
        let target = seed_partial(root.path(), &full, &full, "etag-1");

        let source = FakeSource::new(vec![unsatisfiable_response(full.len() as u64)]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path())
            .expect("an exact-size, correct-digest partial must commit, not re-download");

        assert_eq!(verified.path, target);
        assert_eq!(fs::read(&target).unwrap(), full);
        assert_eq!(verified.sha256_hex, sha256_hex(&full));
        assert_eq!(
            verified.etag.as_deref(),
            Some("etag-1"),
            "the committed ETag must come from the checkpoint, not be invented"
        );
        assert!(!part_path(&target).exists());
        assert!(!journal_path(&target).exists());
        assert_eq!(
            source.recorded_requests().len(),
            1,
            "must not re-request after a 416 it can satisfy locally"
        );
    }

    #[test]
    fn resume_416_with_exact_size_but_wrong_digest_fails_and_discards_the_partial() {
        let root = tempdir().expect("tempdir");
        let full = b"the real bytes of this file, all of them here".to_vec();
        // Same length, different content: a naive "416 means we're done"
        // implementation would commit this corrupt file.
        let corrupt: Vec<u8> = full.iter().map(|b| b ^ 0x20).collect();
        assert_eq!(corrupt.len(), full.len());
        let target = seed_partial(root.path(), &corrupt, &full, "etag-1");

        let source = FakeSource::new(vec![unsatisfiable_response(full.len() as u64)]);
        let plan = plan_for(&full);

        let err = download_file(&source, &plan, root.path())
            .expect_err("a wrong-digest partial must never be committed");
        assert!(
            matches!(err, DownloadError::HashMismatch { .. }),
            "expected an explicit hash mismatch, got {err:?}"
        );
        assert!(!target.exists(), "nothing may be committed");
        assert!(
            !part_path(&target).exists() && !journal_path(&target).exists(),
            "the bad partial must be discarded so a retry restarts from zero"
        );
    }

    #[test]
    fn resume_416_with_a_short_partial_fails_explicitly_and_discards_it() {
        let root = tempdir().expect("tempdir");
        let full = b"twenty-four bytes of real payload plus more".to_vec();
        let short = &full[..10];
        let target = seed_partial(root.path(), short, &full, "etag-1");

        let source = FakeSource::new(vec![unsatisfiable_response(full.len() as u64)]);
        let plan = plan_for(&full);

        let err = download_file(&source, &plan, root.path())
            .expect_err("a short partial plus 416 must fail explicitly");
        assert!(
            matches!(err, DownloadError::RangeNotSatisfiable),
            "expected an explicit RangeNotSatisfiable, got {err:?}"
        );
        assert!(!target.exists(), "nothing may be committed");
        assert!(
            !part_path(&target).exists() && !journal_path(&target).exists(),
            "the stale partial must be discarded so a retry restarts from zero"
        );
    }

    // -----------------------------------------------------------------
    // Durable checkpoint semantics (issue #1, commit 31)
    // -----------------------------------------------------------------

    /// A `.part` file of `len` bytes plus a journal recording `confirmed`,
    /// as a mid-download checkpoint would leave them.
    fn seed_checkpoint(dir: &Path, len: usize, confirmed: u64) -> (PathBuf, PathBuf) {
        let target = dir.join("f");
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, vec![1u8; len]).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                confirmed_offset: confirmed,
                expected_size: 1000,
                expected_sha256_hex: "a".repeat(64),
                etag: Some("etag-1".to_string()),
            },
        )
        .unwrap();
        (part, jpath)
    }

    fn checkpoint_at(offset: u64) -> DownloadJournal {
        DownloadJournal {
            confirmed_offset: offset,
            expected_size: 1000,
            expected_sha256_hex: "a".repeat(64),
            etag: Some("etag-1".to_string()),
        }
    }

    #[test]
    fn a_checkpoint_may_not_move_backwards() {
        let dir = tempdir().expect("tempdir");
        let (part, jpath) = seed_checkpoint(dir.path(), 500, 400);

        let err = DownloadJournal::advance(&jpath, &part, &checkpoint_at(399))
            .expect_err("a backwards checkpoint must be refused");
        assert!(
            matches!(
                err,
                DownloadError::Checkpoint(CheckpointError::NonMonotonic {
                    recorded: 400,
                    proposed: 399
                })
            ),
            "got {err:?}"
        );
        assert_eq!(
            DownloadJournal::read(&jpath)
                .unwrap()
                .unwrap()
                .confirmed_offset,
            400,
            "the refused advance must not have rewritten the journal"
        );

        // Standing still and moving forward are both fine.
        DownloadJournal::advance(&jpath, &part, &checkpoint_at(400)).expect("equal is allowed");
        DownloadJournal::advance(&jpath, &part, &checkpoint_at(500)).expect("forward is allowed");
        assert_eq!(
            DownloadJournal::read(&jpath)
                .unwrap()
                .unwrap()
                .confirmed_offset,
            500
        );
    }

    #[test]
    fn a_checkpoint_may_never_claim_more_bytes_than_are_durably_written() {
        let dir = tempdir().expect("tempdir");
        // 500 bytes flushed to the `.part` file; 400 checkpointed.
        let (part, jpath) = seed_checkpoint(dir.path(), 500, 400);

        let err = DownloadJournal::advance(&jpath, &part, &checkpoint_at(501))
            .expect_err("a checkpoint ahead of the written bytes must be refused");
        assert!(
            matches!(
                err,
                DownloadError::Checkpoint(CheckpointError::ExceedsDurableBytes {
                    proposed: 501,
                    durable: 500,
                    ..
                })
            ),
            "got {err:?}"
        );
        assert_eq!(
            DownloadJournal::read(&jpath)
                .unwrap()
                .unwrap()
                .confirmed_offset,
            400
        );

        // Exactly the durable length is the highest legal claim.
        DownloadJournal::advance(&jpath, &part, &checkpoint_at(500))
            .expect("claiming exactly the flushed bytes is allowed");
    }

    #[test]
    fn a_checkpoint_with_no_part_file_yet_cannot_claim_any_bytes() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("f");
        let err = DownloadJournal::advance(
            &journal_path(&target),
            &part_path(&target),
            &checkpoint_at(1),
        )
        .expect_err("nothing is durable when there is no .part file");
        assert!(matches!(
            err,
            DownloadError::Checkpoint(CheckpointError::ExceedsDurableBytes { durable: 0, .. })
        ));
    }

    #[test]
    fn rewriting_an_immutable_checkpoint_field_is_an_error_not_an_overwrite() {
        let dir = tempdir().expect("tempdir");
        let (part, jpath) = seed_checkpoint(dir.path(), 500, 400);

        for (field, proposed) in [
            (
                "expected_size",
                DownloadJournal {
                    expected_size: 999,
                    ..checkpoint_at(450)
                },
            ),
            (
                "expected_sha256_hex",
                DownloadJournal {
                    expected_sha256_hex: "b".repeat(64),
                    ..checkpoint_at(450)
                },
            ),
            (
                "etag",
                DownloadJournal {
                    etag: Some("etag-2".to_string()),
                    ..checkpoint_at(450)
                },
            ),
            (
                "etag",
                DownloadJournal {
                    etag: None,
                    ..checkpoint_at(450)
                },
            ),
        ] {
            let err = DownloadJournal::advance(&jpath, &part, &proposed)
                .expect_err("rewriting an immutable field must be refused");
            match err {
                DownloadError::Checkpoint(CheckpointError::ImmutableField {
                    field: got, ..
                }) => assert_eq!(got, field),
                other => panic!("expected an ImmutableField error for {field}, got {other:?}"),
            }
        }

        // Nothing was overwritten by any of those attempts.
        assert_eq!(
            DownloadJournal::read(&jpath).unwrap().unwrap(),
            DownloadJournal {
                confirmed_offset: 400,
                expected_size: 1000,
                expected_sha256_hex: "a".repeat(64),
                etag: Some("etag-1".to_string()),
            }
        );
    }

    #[test]
    fn an_etag_that_was_never_recorded_may_be_recorded_once_then_frozen() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("f");
        let part = part_path(&target);
        let jpath = journal_path(&target);
        fs::write(&part, vec![1u8; 500]).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                etag: None,
                ..checkpoint_at(100)
            },
        )
        .unwrap();

        DownloadJournal::advance(&jpath, &part, &checkpoint_at(200))
            .expect("a first ETag may be recorded");
        let err = DownloadJournal::advance(
            &jpath,
            &part,
            &DownloadJournal {
                etag: Some("etag-2".to_string()),
                ..checkpoint_at(300)
            },
        )
        .expect_err("a recorded ETag is frozen");
        assert!(matches!(
            err,
            DownloadError::Checkpoint(CheckpointError::ImmutableField { field: "etag", .. })
        ));
    }

    #[test]
    fn reset_to_corrects_a_desynced_claim_downwards_but_never_upwards() {
        let dir = tempdir().expect("tempdir");
        let (_part, jpath) = seed_checkpoint(dir.path(), 500, 400);
        let journal = DownloadJournal::read(&jpath).unwrap().unwrap();

        let corrected = DownloadJournal::reset_to(&jpath, &journal, 120).expect("downward is fine");
        assert_eq!(corrected.confirmed_offset, 120);
        assert_eq!(
            DownloadJournal::read(&jpath)
                .unwrap()
                .unwrap()
                .confirmed_offset,
            120
        );

        let err = DownloadJournal::reset_to(&jpath, &corrected, 300)
            .expect_err("reset_to must never be usable as a backdoor advance");
        assert!(matches!(
            err,
            DownloadError::Checkpoint(CheckpointError::NonMonotonic { .. })
        ));
    }

    #[test]
    fn a_desynced_journal_is_reset_to_the_truncated_length_before_resuming() {
        let root = tempdir().expect("tempdir");
        let full = b"0123456789ABCDEFGHIJ".to_vec(); // 20 bytes
        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let part = part_path(&target);
        let jpath = journal_path(&target);

        // The journal claims 15 confirmed bytes but only 8 are on disk —
        // exactly the desync `recover_resume_offset` exists for. Before
        // commit 31, the claim was left at 15 while the file was truncated
        // to 8, so the very next checkpoint (at 20) still "advanced" from a
        // number no byte on disk ever backed.
        fs::write(&part, &full[..8]).unwrap();
        DownloadJournal::write(
            &jpath,
            &DownloadJournal {
                confirmed_offset: 15,
                expected_size: full.len() as u64,
                expected_sha256_hex: sha256_hex(&full),
                etag: Some("etag-1".to_string()),
            },
        )
        .unwrap();

        let source = FakeSource::new(vec![ScriptedResponse {
            status: 206,
            etag: Some("etag-1".to_string()),
            content_range: Some(format!("bytes 8-{}/{}", full.len() - 1, full.len())),
            content_length: Some((full.len() - 8) as u64),
            body: full[8..].to_vec(),
            fail_after: None,
        }]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path()).expect("resume succeeds");
        assert_eq!(fs::read(&verified.path).unwrap(), full);
        assert_eq!(source.recorded_requests()[0].start, 8);
    }

    // -----------------------------------------------------------------
    // ArtifactInspector-driven recovery (issue #1, commit 32)
    // -----------------------------------------------------------------

    #[test]
    fn an_already_verified_target_is_reused_without_contacting_the_source() {
        let root = tempdir().expect("tempdir");
        let full = b"a file this job already finished downloading".to_vec();
        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, &full).unwrap();

        // No scripted responses at all: the fake source panics if asked.
        let source = FakeSource::new(vec![]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path())
            .expect("an already-verified file must be reused, not re-downloaded");
        assert_eq!(verified.path, target);
        assert_eq!(verified.size_bytes, full.len() as u64);
        assert_eq!(verified.sha256_hex, sha256_hex(&full));
        assert!(
            source.recorded_requests().is_empty(),
            "recovery must not re-download a verified file"
        );
        assert_eq!(fs::read(&target).unwrap(), full);
    }

    #[test]
    fn a_verified_target_reuse_also_clears_a_leftover_partial_and_journal() {
        let root = tempdir().expect("tempdir");
        let full = b"committed, but the .part was never cleaned up".to_vec();
        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, &full).unwrap();
        fs::write(part_path(&target), &full[..5]).unwrap();
        DownloadJournal::write(
            &journal_path(&target),
            &DownloadJournal {
                confirmed_offset: 5,
                expected_size: full.len() as u64,
                expected_sha256_hex: sha256_hex(&full),
                etag: Some("etag-1".to_string()),
            },
        )
        .unwrap();

        let source = FakeSource::new(vec![]);
        let plan = plan_for(&full);
        download_file(&source, &plan, root.path()).expect("reuse succeeds");

        assert!(!part_path(&target).exists());
        assert!(!journal_path(&target).exists());
        assert_eq!(fs::read(&target).unwrap(), full);
    }

    #[test]
    fn a_pre_existing_wrong_target_is_replaced_rather_than_blocking_the_commit() {
        // The Windows "target already exists" case: `rename` onto an
        // existing file fails there, so a leftover/stale target must be
        // judged and cleared instead of assumed absent. Expressed as a
        // pre-existing target file so it runs on every platform.
        let root = tempdir().expect("tempdir");
        let full = b"what this job is supposed to produce".to_vec();
        let stale = b"an older file that happens to sit at the same name".to_vec();
        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, &stale).unwrap();

        let source = FakeSource::new(vec![full_response(&full, "etag-1")]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path())
            .expect("an invalid pre-existing target must be re-downloaded");
        assert_eq!(verified.path, target);
        assert_eq!(fs::read(&target).unwrap(), full);
        assert_eq!(source.recorded_requests().len(), 1);
    }

    #[test]
    fn a_same_size_but_wrong_digest_target_is_re_downloaded_not_reused() {
        let root = tempdir().expect("tempdir");
        let full = b"the genuine bytes of this particular file".to_vec();
        let corrupt: Vec<u8> = full.iter().map(|b| b ^ 0x20).collect();
        assert_eq!(corrupt.len(), full.len());
        let target = derive_target_path(root.path(), "dev1", "sess1", "file1").unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, &corrupt).unwrap();

        let source = FakeSource::new(vec![full_response(&full, "etag-1")]);
        let plan = plan_for(&full);

        let verified = download_file(&source, &plan, root.path())
            .expect("a same-size, wrong-digest target must be re-downloaded");
        assert_eq!(
            fs::read(&verified.path).unwrap(),
            full,
            "a size-only check would have kept the corrupt file"
        );
        assert_eq!(source.recorded_requests().len(), 1);
    }

    #[test]
    fn fresh_download_answered_with_416_is_still_a_hard_error() {
        let root = tempdir().expect("tempdir");
        let full = b"never downloaded a single byte of this".to_vec();
        let source = FakeSource::new(vec![unsatisfiable_response(full.len() as u64)]);
        let plan = plan_for(&full);

        let err = download_file(&source, &plan, root.path())
            .expect_err("a 416 with no local partial cannot mean 'already complete'");
        assert!(matches!(err, DownloadError::RangeNotSatisfiable));
    }
}
