//! `staging` — revision-scoped staging (issue #1, commit 63) and atomic
//! publication of a complete session revision (commit 64).
//!
//! # The problem this module fixes
//!
//! Before it, a whole-session download assembled *directly into the
//! visible library tree*: `download_file` renamed each finished file onto
//! its final `<library_root>/<device>/<session>/<display_path>` name as
//! soon as that one file verified. A session that was 3 files into a 40
//! file publication was therefore indistinguishable, from the outside,
//! from a session that had finished — the library tree showed a partially
//! populated session directory and nothing recorded that the *session*
//! was incomplete. There was no moment at which the session became
//! visible; it leaked into view one file at a time.
//!
//! # The layout
//!
//! ```text
//! <library_root>/
//!   .ylx-staging/                      <- hidden; never a published session
//!     <revision>/                      <- `file_root()`: a whole revision
//!       <device_id>/
//!         <session_id>/                <- `revision_dir()`: the unit that is renamed
//!           video/left_00000.mp4
//!           imu/imu_00000.csv
//!           .ylx-revision              <- the seal (written last, before the rename)
//!     .superseded/                     <- an older published dir moved out of the way
//!   <device_id>/
//!     <session_id>/                    <- `published_dir()`: the visible session
//!       .ylx-selected                  <- selected-file publication marker, when present
//! ```
//!
//! The revision directory is nested `<revision>/<device>/<session>` rather
//! than `<device>/<session>/<revision>` for one concrete reason: it makes
//! `file_root()` — `<library_root>/.ylx-staging/<revision>` — a *drop-in
//! replacement for the library root*. Every existing path-safety, `.part`,
//! journal, resume and per-file-atomic-rename guarantee in
//! [`super::download`] applies unchanged inside staging; nothing about
//! them had to be reimplemented or relaxed. [`SessionStaging::download_into`]
//! is literally `download_file(source, plan, &self.file_root())`.
//!
//! `.ylx-staging`, `.ylx-revision` and `.ylx-selected` are rejected by
//! [`super::download::validate_id_segment`], so no device id, session id or
//! signed `display_path` can collide with (or forge) any of them.
//!
//! # The publish protocol (commit 64)
//!
//! Publication is deliberately two named steps, because "did we crash
//! before or after the rename?" is exactly the question recovery has to
//! answer and a single opaque `publish()` gives it nothing to look at:
//!
//! 1. **seal** ([`SessionStaging::seal`]) — verify the manifest against
//!    *every* file actually present in the revision directory (each one
//!    must be [`ArtifactStatus::Verified`], and there must be no file that
//!    the manifest does not list — a leftover `.part`, a stray extra
//!    artifact and a missing file all refuse publication), write the
//!    `.ylx-revision` marker durably, then fsync every directory in the
//!    revision tree so the per-file renames themselves are durable.
//! 2. **publish** ([`SealedRevision::publish`]) — one `rename` of the
//!    sealed revision directory onto the visible session path, then an
//!    fsync of its parent.
//!
//! [`SessionStaging::state`] reads that protocol back off the disk:
//!
//! | [`RevisionState`] | what happened | what a rerun does |
//! |---|---|---|
//! | [`Absent`](RevisionState::Absent) | nothing staged | download again |
//! | [`Staged`](RevisionState::Staged) | crashed *during assembly* | resume, then seal |
//! | [`Sealed`](RevisionState::Sealed) | crashed *before the rename* | rename now |
//! | [`Published`](RevisionState::Published) | crashed *after the rename* | nothing — [`PublishOutcome::AlreadyPublished`] |
//! | [`SelectedPublished`](RevisionState::SelectedPublished) | selected targets and their marker are visible | verify/repair selected targets, then continue |
//!
//! Both crash points converge on the same visible tree, and a rerun after
//! a completed publish is a no-op rather than a duplicate or an error.
//!
//! # Selected-file publication
//!
//! A selected-file job uses [`SessionStaging::publish_selected`] instead of
//! replacing the visible session directory. Each requested artifact is
//! copied from the sealed revision into a same-directory temporary file,
//! flushed, hash-checked and atomically renamed into place. An existing
//! target is first moved to same-volume trash so replacement remains
//! recoverable on Windows; sibling files and an existing `.ylx-revision`
//! marker are preserved. Only after every requested target is verified is a
//! `.ylx-selected` marker written. That marker records the revision, totals
//! and a digest of the ordered selected projection, so recovery can
//! distinguish an exact completed subset from a different request with the
//! same count and byte total. A retry repairs a missing or corrupted target
//! even when a matching selected marker is already present.
//!
//! # Revision identity
//!
//! A [`RevisionId`] is derived from the *signed publication payload*
//! ([`RevisionId::from_publication`]), so it is stable across restarts
//! (a retry lands in the same staging directory and resumes it) and
//! different whenever the Pi republishes different content. The marker
//! written into the published directory is therefore also the answer to
//! "is this session complete, and at which revision?" —
//! [`published_revision`]. A single-file download, which by design never
//! seals a revision, can never make that function return `Some`.
//!
//! # The pre-existing target directory
//!
//! `rename` onto an existing directory fails on Windows always, and on
//! Unix whenever the destination is non-empty. A previously published
//! revision of the same session is exactly that case. It is handled by
//! moving the old directory aside into `.ylx-staging/.superseded/...`
//! *before* the rename, and deleting it only after the rename and the
//! parent fsync have succeeded. A crash in between leaves no published
//! directory and an intact sealed revision — the retry re-runs the same
//! two moves and converges. (The superseded copy is left on disk in that
//! window rather than deleted eagerly, so a crash can never destroy the
//! old revision without the new one being durably in place.)

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::{Deserialize, Serialize};

use super::artifact::{ArtifactInspector, ArtifactStatus, ExpectedArtifact};
use super::download::{
    derive_target_path_for_file, download_file, fsync_dir, prepare_target_parent, reject_symlink,
    sha256_of_file, validate_id_segment, write_file_durably, DownloadError, DownloadSource,
    FilePlan, PathSafetyError, VerifiedFile,
};

/// The hidden staging root under the library root. Rejected by
/// [`validate_id_segment`], so it can never also be a device id.
pub const STAGING_DIR_NAME: &str = ".ylx-staging";

/// The seal written into a revision directory once every manifest file has
/// been verified, and carried by the rename into the published session
/// directory. Rejected by [`validate_id_segment`], so no signed
/// `display_path` can forge one.
pub const REVISION_MARKER_NAME: &str = ".ylx-revision";

/// The marker written by selected-file publication. Unlike
/// [`REVISION_MARKER_NAME`], this marker never claims that the whole session
/// is present: it records only the requested-file projection that was
/// published by one job. Keeping a distinct name is what lets an existing
/// full-session marker remain authoritative for the sibling files it covers.
pub const SELECTED_MARKER_NAME: &str = ".ylx-selected";

/// Where a previously published session directory is moved so the rename
/// has somewhere to land. See the module doc.
const SUPERSEDED_DIR_NAME: &str = ".superseded";

/// Per-file trash used while replacing selected-file targets. It lives under
/// the same library root as both source and destination, so every move is a
/// same-volume rename on platforms where `rename` cannot overwrite an open
/// or existing file (notably Windows).
const SELECTED_TRASH_DIR_NAME: &str = ".selected-trash";

// =====================================================================
// Revision identity
// =====================================================================

/// The identity of one publication of one session.
///
/// Derived from the signed publication payload rather than allocated, so
/// it is *stable across restarts*: a retried job computes the same id,
/// finds the same staging directory, and resumes it instead of starting a
/// second copy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RevisionId(String);

impl RevisionId {
    /// The revision of the session described by `publication_payload` —
    /// the exact bytes a [`super::download::PublicationVerifier`] checks
    /// the signature over.
    #[must_use]
    pub fn from_publication(publication_payload: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(publication_payload);
        let hex = format!("{:x}", hasher.finalize());
        RevisionId(format!("rev-{}", &hex[..32]))
    }

    /// A revision id read back from disk or from a durable job record.
    /// Validated as a single safe path segment — a revision id is a
    /// directory name, so it is subject to exactly the same paranoia as
    /// every other id this crate turns into a path.
    pub fn parse(raw: &str) -> Result<Self, PathSafetyError> {
        validate_id_segment(raw)?;
        Ok(RevisionId(raw.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The on-disk seal. Its presence in a *published* directory is this
/// crate's only claim that a whole session is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionMarker {
    pub revision: String,
    pub file_count: u32,
    pub total_bytes: u64,
}

/// The durable scope marker for a selected-file publication. `scope` is
/// intentionally serialized as a string rather than inferred from the
/// marker filename alone: a recovery tool can reject an unknown scope
/// instead of accidentally treating a future marker format as trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedMarker {
    pub scope: String,
    pub revision: String,
    pub file_count: u32,
    pub total_bytes: u64,
    /// Ordered digest of the requested file projection. The revision is
    /// derived from the signed publication, but one publication can produce
    /// multiple selected subsets; this binds the marker to the exact subset
    /// rather than only to its count and byte total.
    pub manifest_digest: String,
}

/// Read the revision marker sitting in `dir`, if it has one. A missing,
/// unreadable or unparseable marker is `None` — never a guess, and never
/// an error the caller has to invent a policy for: "not sealed" is the
/// only safe reading of a marker that cannot be trusted.
#[must_use]
pub fn read_revision_marker(dir: &Path) -> Option<RevisionMarker> {
    let raw = fs::read_to_string(dir.join(REVISION_MARKER_NAME)).ok()?;
    serde_json::from_str::<RevisionMarker>(&raw).ok()
}

/// Read a selected-file marker sitting in `dir`, if it is structurally
/// valid. Unknown scopes are not accepted as selected publication state.
#[must_use]
pub fn read_selected_marker(dir: &Path) -> Option<SelectedMarker> {
    let raw = fs::read_to_string(dir.join(SELECTED_MARKER_NAME)).ok()?;
    let marker = serde_json::from_str::<SelectedMarker>(&raw).ok()?;
    (marker.scope == "selected_files").then_some(marker)
}

/// The revision the visible library tree currently holds for this session,
/// or `None` if no complete session has ever been published there.
///
/// This is the session-completeness claim. It is written by exactly one
/// operation ([`SealedRevision::publish`]); a per-file download can put a
/// file into the tree, but it cannot make this return `Some`.
#[must_use]
pub fn published_revision(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
) -> Option<RevisionId> {
    let marker = read_revision_marker(&library_root.join(device_id).join(session_id))?;
    RevisionId::parse(&marker.revision).ok()
}

// =====================================================================
// Manifest
// =====================================================================

/// Every file a published session revision must contain — nothing more and
/// nothing less. Reuses [`ExpectedArtifact`] so the manifest check and
/// commit 32's recovery inspection judge a file by the identical rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionManifest {
    pub device_id: String,
    pub session_id: String,
    pub files: Vec<ExpectedArtifact>,
}

impl SessionManifest {
    #[must_use]
    pub fn new(
        device_id: impl Into<String>,
        session_id: impl Into<String>,
        files: Vec<ExpectedArtifact>,
    ) -> Self {
        SessionManifest {
            device_id: device_id.into(),
            session_id: session_id.into(),
            files,
        }
    }

    /// The manifest implied by the file plans a job was created with —
    /// the normal way to build one, since the plans come straight from the
    /// verified publication.
    #[must_use]
    pub fn from_plans(
        device_id: impl Into<String>,
        session_id: impl Into<String>,
        plans: &[FilePlan],
    ) -> Self {
        SessionManifest::new(
            device_id,
            session_id,
            plans.iter().map(ExpectedArtifact::from).collect(),
        )
    }

    /// The manifest implied by what a job actually downloaded, with each
    /// file's display path recovered relative to `base_dir`.
    ///
    /// Used by [`super::download::commit_session`], whose caller hands it
    /// [`VerifiedFile`]s rather than plans. Note what this *cannot* catch:
    /// a file the job never attempted is not in this list, so it is the
    /// caller's list of verified files — not this constructor — that
    /// decides whether the session is complete. Prefer
    /// [`SessionManifest::from_plans`] where the plans are available.
    #[must_use]
    pub fn from_verified(
        device_id: impl Into<String>,
        session_id: impl Into<String>,
        base_dir: &Path,
        files: &[VerifiedFile],
    ) -> Self {
        let artifacts = files
            .iter()
            .map(|f| ExpectedArtifact {
                file_id: f.file_id.clone(),
                target_relative_path: relative_display_path(base_dir, &f.path),
                expected_size: f.size_bytes,
                expected_sha256_hex: Some(f.sha256_hex.clone()),
            })
            .collect();
        SessionManifest::new(device_id, session_id, artifacts)
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.expected_size))
    }

    /// Stable digest of the ordered requested-file projection. Every field
    /// is length-prefixed before hashing so adjacent strings cannot be
    /// rearranged into the same preimage.
    #[must_use]
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hash_manifest_component(&mut hasher, &self.device_id);
        hash_manifest_component(&mut hasher, &self.session_id);
        for file in &self.files {
            hash_manifest_component(&mut hasher, &file.file_id);
            hash_manifest_component(
                &mut hasher,
                file.target_relative_path.as_deref().unwrap_or(""),
            );
            hasher.update([file.target_relative_path.is_some() as u8]);
            hasher.update(file.expected_size.to_le_bytes());
            match &file.expected_sha256_hex {
                Some(hash) => {
                    hasher.update([1]);
                    hash_manifest_component(&mut hasher, hash);
                }
                None => hasher.update([0]),
            }
        }
        format!("{:x}", hasher.finalize())
    }
}

fn hash_manifest_component(hasher: &mut impl sha2::Digest, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// `base_dir`-relative, `/`-separated display path of `path`, or `None`
/// when `path` is not under `base_dir` (in which case the opaque file id
/// fallback documented on [`derive_target_path_for_file`] applies).
fn relative_display_path(base_dir: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(base_dir).ok()?;
    let mut segments = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        segments.push(name.to_string_lossy().into_owned());
    }
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

// =====================================================================
// Errors / outcomes
// =====================================================================

/// Why a session revision could not be sealed or published.
///
/// Deliberately a distinct type from [`DownloadError`] rather than a new
/// variant of it: `DownloadError` is matched exhaustively by
/// `transfer::coordinator`, and a publication refusal is a different kind
/// of event from "a byte range went wrong" anyway.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error(transparent)]
    Download(#[from] DownloadError),

    #[error("no staged revision {revision} to publish at {path}")]
    NothingStaged { revision: RevisionId, path: PathBuf },

    #[error("staged revision {revision} is not sealed; seal it before publishing")]
    NotSealed { revision: RevisionId },

    #[error("staged revision {revision} does not match its manifest: {}", .problems.join("; "))]
    ManifestMismatch {
        revision: RevisionId,
        problems: Vec<String>,
    },
}

impl From<PathSafetyError> for PublishError {
    fn from(e: PathSafetyError) -> Self {
        PublishError::Download(DownloadError::from(e))
    }
}

impl From<PublishError> for DownloadError {
    /// Fold a publication refusal back into the download error channel
    /// `commit_session` must speak. A refusal is never retryable and never
    /// a transport problem, so it maps to [`DownloadError::InvalidPlan`] —
    /// the existing "this job cannot succeed as described" variant. (A
    /// dedicated `DownloadError::Publish` variant would be clearer; adding
    /// one is a breaking change for `transfer::coordinator`'s exhaustive
    /// `classify_download_error` match and is left to that module's owner.)
    fn from(e: PublishError) -> Self {
        match e {
            PublishError::Download(inner) => inner,
            other => DownloadError::InvalidPlan(other.to_string()),
        }
    }
}

/// What a publish attempt actually did. Both variants mean "the visible
/// tree now holds this revision"; they differ only in whether *this* call
/// is what put it there, which is what makes a rerun a no-op instead of an
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    Published { revision: RevisionId },
    AlreadyPublished { revision: RevisionId },
}

impl PublishOutcome {
    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        match self {
            PublishOutcome::Published { revision }
            | PublishOutcome::AlreadyPublished { revision } => revision,
        }
    }
}

/// Where one revision is in the publish protocol, read back off the disk.
/// See the table in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionState {
    Absent,
    Staged,
    Sealed,
    Published,
    /// The requested-file projection was published, while the rest of the
    /// session (if any) remains whatever it was before this job ran.
    SelectedPublished,
}

// =====================================================================
// SessionStaging
// =====================================================================

/// A revision-scoped staging area for one session of one device.
///
/// Construction is pure — it validates the ids and computes paths but
/// touches no filesystem, so [`SessionStaging::state`] can be used to
/// *ask* about a revision (including one that was never started) without
/// creating anything.
#[derive(Debug, Clone)]
pub struct SessionStaging {
    library_root: PathBuf,
    device_id: String,
    session_id: String,
    revision: RevisionId,
}

impl SessionStaging {
    /// A staging area for an explicit revision.
    pub fn new(
        library_root: impl Into<PathBuf>,
        device_id: impl Into<String>,
        session_id: impl Into<String>,
        revision: RevisionId,
    ) -> Result<Self, PathSafetyError> {
        let device_id = device_id.into();
        let session_id = session_id.into();
        validate_id_segment(&device_id)?;
        validate_id_segment(&session_id)?;
        Ok(SessionStaging {
            library_root: library_root.into(),
            device_id,
            session_id,
            revision,
        })
    }

    /// A staging area for the revision implied by a signed publication
    /// payload — the normal constructor.
    pub fn for_publication(
        library_root: impl Into<PathBuf>,
        device_id: impl Into<String>,
        session_id: impl Into<String>,
        publication_payload: &[u8],
    ) -> Result<Self, PathSafetyError> {
        let revision = RevisionId::from_publication(publication_payload);
        SessionStaging::new(library_root, device_id, session_id, revision)
    }

    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    #[must_use]
    pub fn library_root(&self) -> &Path {
        &self.library_root
    }

    /// The opaque device id this revision belongs to.
    ///
    /// Keeping the identity on the staging handle (rather than making
    /// callers reconstruct it from paths) lets the staged commit path reject
    /// a manifest/session mix-up before it touches the filesystem.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The opaque session id this revision belongs to.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// `<library_root>/.ylx-staging`.
    #[must_use]
    pub fn staging_root(&self) -> PathBuf {
        self.library_root.join(STAGING_DIR_NAME)
    }

    /// The root to hand to [`download_file`] in place of the library root.
    /// Everything below it mirrors the real library layout exactly.
    #[must_use]
    pub fn file_root(&self) -> PathBuf {
        self.staging_root().join(self.revision.as_str())
    }

    /// The directory that a single `rename` turns into the published
    /// session.
    #[must_use]
    pub fn revision_dir(&self) -> PathBuf {
        self.file_root()
            .join(&self.device_id)
            .join(&self.session_id)
    }

    /// Materialize this revision's hidden directory before a transfer starts.
    ///
    /// `download_into` also creates the directory tree as a consequence of
    /// opening the first `.part` file, but production callers invoke this
    /// explicit step before asking a source for any network bytes. It makes
    /// the staging boundary true even for an empty session and leaves a
    /// durable, restart-discoverable skeleton for a job that is interrupted
    /// before its first file completes.
    pub fn prepare(&self) -> Result<(), DownloadError> {
        let revision_dir = self.revision_dir();
        fs::create_dir_all(&revision_dir).map_err(|e| DownloadError::io(&revision_dir, e))?;
        fsync_dir(&revision_dir)?;
        Ok(())
    }

    /// The visible session directory this revision publishes to.
    #[must_use]
    pub fn published_dir(&self) -> PathBuf {
        self.library_root
            .join(&self.device_id)
            .join(&self.session_id)
    }

    /// Download one of this session's files **into staging**, never into
    /// the visible tree. This is the whole of commit 63: the per-file
    /// atomic rename still happens, but it lands inside the hidden
    /// revision directory, so no part of the session becomes visible
    /// before [`SealedRevision::publish`].
    pub fn download_into(
        &self,
        source: &dyn DownloadSource,
        plan: &FilePlan,
    ) -> Result<VerifiedFile, DownloadError> {
        if plan.device_id != self.device_id || plan.session_id != self.session_id {
            return Err(DownloadError::InvalidPlan(format!(
                "plan is for {}/{} but this staging area is for {}/{}",
                plan.device_id, plan.session_id, self.device_id, self.session_id
            )));
        }
        download_file(source, plan, &self.file_root())
    }

    /// Where this revision is in the publish protocol. This is the
    /// crash-recovery discriminator: `Sealed` means the process died
    /// *before* the rename, `Published` means it died *after* it.
    #[must_use]
    pub fn state(&self) -> RevisionState {
        if self.is_published() {
            return RevisionState::Published;
        }
        if self.is_selected_published() {
            return RevisionState::SelectedPublished;
        }
        match fs::metadata(self.revision_dir()) {
            Ok(meta) if meta.is_dir() => {
                if self.marker_matches(&self.revision_dir())
                    || self.selected_marker_matches(&self.revision_dir())
                {
                    RevisionState::Sealed
                } else {
                    RevisionState::Staged
                }
            }
            _ => RevisionState::Absent,
        }
    }

    /// Whether the visible session directory already carries *this*
    /// revision's seal.
    #[must_use]
    pub fn is_published(&self) -> bool {
        self.marker_matches(&self.published_dir())
    }

    /// Whether the visible session carries this revision's selected-file
    /// marker. The marker is only written after every requested file has
    /// been verified in the visible tree; callers that need to validate a
    /// particular manifest should additionally use
    /// [`SessionStaging::visible_manifest_is_complete`].
    #[must_use]
    pub fn is_selected_published(&self) -> bool {
        self.selected_marker_matches(&self.published_dir())
    }

    fn marker_matches(&self, dir: &Path) -> bool {
        read_revision_marker(dir).is_some_and(|m| m.revision == self.revision.0)
    }

    fn selected_marker_matches(&self, dir: &Path) -> bool {
        read_selected_marker(dir).is_some_and(|m| m.revision == self.revision.0)
    }

    /// Verify the manifest against every file in the revision directory,
    /// then write and fsync the seal. See the module doc for what is
    /// checked and why the marker is written *before* the rename.
    ///
    /// Idempotent: sealing an already-published revision succeeds without
    /// touching anything, so a rerun can go straight on to
    /// [`SealedRevision::publish`] and get
    /// [`PublishOutcome::AlreadyPublished`].
    pub fn seal(&self, manifest: &SessionManifest) -> Result<SealedRevision, PublishError> {
        let sealed = SealedRevision {
            staging: self.clone(),
        };
        if self.is_published() {
            return Ok(sealed);
        }

        let revision_dir = self.revision_dir();
        if !revision_dir.is_dir() {
            return Err(PublishError::NothingStaged {
                revision: self.revision.clone(),
                path: revision_dir,
            });
        }

        self.cleanup_marker_temp_files();
        self.verify_manifest(manifest)?;

        let marker = RevisionMarker {
            revision: self.revision.0.clone(),
            file_count: manifest.files.len() as u32,
            total_bytes: manifest.total_bytes(),
        };
        let json =
            serde_json::to_vec(&marker).map_err(|e| DownloadError::Serialization(e.to_string()))?;
        rewrite_internal_marker(&revision_dir.join(REVISION_MARKER_NAME), &json)?;
        // The per-file renames inside the tree are only durable once the
        // directories that recorded them are fsynced — do that before the
        // one rename that makes all of it visible at once.
        fsync_tree(&revision_dir)?;

        Ok(sealed)
    }

    /// [`SessionStaging::seal`] followed immediately by
    /// [`SealedRevision::publish`] — the ordinary, non-crashing path.
    pub fn publish(&self, manifest: &SessionManifest) -> Result<PublishOutcome, PublishError> {
        self.seal(manifest)?.publish()
    }

    /// Seal and publish only the files listed in `manifest`. The revision
    /// stays hidden while each file is copied into a sibling temporary file;
    /// no directory-level rename occurs, so existing files in the same
    /// session remain untouched.
    pub fn publish_selected(
        &self,
        manifest: &SessionManifest,
    ) -> Result<PublishOutcome, PublishError> {
        self.seal_selected(manifest)?.publish_selected(manifest)
    }

    /// Throw away this revision's staged bytes (an abandoned or superseded
    /// job). Never touches the visible tree.
    pub fn discard(&self) -> Result<(), DownloadError> {
        let revision_dir = self.revision_dir();
        match fs::remove_dir_all(&revision_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(DownloadError::io(&revision_dir, e)),
        }
        prune_empty_parents(&revision_dir, &self.staging_root());
        Ok(())
    }

    /// Every manifest file must be `Verified` in staging, and every file
    /// in staging must be in the manifest.
    fn verify_manifest(&self, manifest: &SessionManifest) -> Result<(), PublishError> {
        let file_root = self.file_root();
        let inspector = ArtifactInspector::new(&file_root, &self.device_id, &self.session_id);
        let mut problems = Vec::new();
        let mut expected_paths = BTreeSet::new();

        for evidence in inspector.plan_recovery(&manifest.files).evidence {
            match &evidence.status {
                ArtifactStatus::Verified => {}
                ArtifactStatus::Missing => problems.push(format!(
                    "{}: missing from the staged revision",
                    evidence.file_id
                )),
                ArtifactStatus::Partial { durable_offset } => problems.push(format!(
                    "{}: only {durable_offset} of {} bytes staged",
                    evidence.file_id, evidence.expected_size
                )),
                ArtifactStatus::Invalid { reason } => {
                    problems.push(format!("{}: {reason}", evidence.file_id))
                }
            }
            if let Some(target) = evidence.target {
                expected_paths.insert(target);
            }
        }

        let revision_dir = self.revision_dir();
        let marker_path = revision_dir.join(REVISION_MARKER_NAME);
        let mut present = Vec::new();
        collect_files(&revision_dir, &mut present)
            .map_err(|e| DownloadError::io(&revision_dir, e))?;
        for path in present {
            let selected_marker_path = revision_dir.join(SELECTED_MARKER_NAME);
            if path == marker_path || path == selected_marker_path || expected_paths.contains(&path)
            {
                continue;
            }
            let shown = path
                .strip_prefix(&revision_dir)
                .unwrap_or(&path)
                .display()
                .to_string();
            problems.push(format!(
                "{shown}: present in staging but not in the manifest"
            ));
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(PublishError::ManifestMismatch {
                revision: self.revision.clone(),
                problems,
            })
        }
    }

    /// Selected-file equivalent of [`SessionStaging::seal`]. Its marker is
    /// kept inside hidden staging and is never moved into place as a
    /// whole-session claim. `publish_selected` writes the visible marker
    /// only after all requested targets have been checked.
    pub fn seal_selected(
        &self,
        manifest: &SessionManifest,
    ) -> Result<SealedRevision, PublishError> {
        let sealed = SealedRevision {
            staging: self.clone(),
        };
        self.validate_selected_manifest(manifest)?;
        if self.selected_marker_matches_manifest(manifest)
            && self.visible_manifest_is_complete(manifest)
        {
            return Ok(sealed);
        }

        let revision_dir = self.revision_dir();
        if !revision_dir.is_dir() {
            return Err(PublishError::NothingStaged {
                revision: self.revision.clone(),
                path: revision_dir,
            });
        }

        self.cleanup_marker_temp_files();
        self.verify_manifest(manifest)?;
        let marker = SelectedMarker {
            scope: "selected_files".to_string(),
            revision: self.revision.0.clone(),
            file_count: manifest.files.len() as u32,
            total_bytes: manifest.total_bytes(),
            manifest_digest: manifest.digest(),
        };
        let json =
            serde_json::to_vec(&marker).map_err(|e| DownloadError::Serialization(e.to_string()))?;
        rewrite_internal_marker(&revision_dir.join(SELECTED_MARKER_NAME), &json)?;
        fsync_tree(&revision_dir)?;
        Ok(sealed)
    }

    /// Whether every requested file is present and hash/size verified in
    /// the visible session tree. Extra sibling files are deliberately
    /// ignored: selected publication must preserve them.
    fn visible_manifest_is_complete(&self, manifest: &SessionManifest) -> bool {
        let inspector =
            ArtifactInspector::new(&self.library_root, &self.device_id, &self.session_id);
        inspector
            .plan_recovery(&manifest.files)
            .evidence
            .iter()
            .all(|evidence| evidence.is_verified())
    }

    fn validate_selected_manifest(&self, manifest: &SessionManifest) -> Result<(), PublishError> {
        if manifest.device_id != self.device_id || manifest.session_id != self.session_id {
            return Err(DownloadError::InvalidPlan(
                "selected manifest identity does not match its staging area".to_string(),
            )
            .into());
        }

        let mut exact = BTreeSet::new();
        let mut folded = BTreeSet::new();
        let mut problems = Vec::new();
        for expected in &manifest.files {
            let target = derive_target_path_for_file(
                &self.library_root,
                &self.device_id,
                &self.session_id,
                &expected.file_id,
                expected.target_relative_path.as_deref(),
            )?;
            let shown = target
                .strip_prefix(&self.library_root)
                .unwrap_or(&target)
                .display()
                .to_string();
            if !exact.insert(target.clone()) {
                problems.push(format!("{shown}: duplicate selected target path"));
            }
            let portable = shown.to_lowercase();
            if !folded.insert(portable) {
                problems.push(format!(
                    "{shown}: case-insensitive duplicate selected target path"
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(PublishError::ManifestMismatch {
                revision: self.revision.clone(),
                problems,
            })
        }
    }

    fn cleanup_marker_temp_files(&self) {
        for marker in [
            self.revision_dir().join(REVISION_MARKER_NAME),
            self.revision_dir().join(SELECTED_MARKER_NAME),
        ] {
            let _ = fs::remove_file(durable_temp_path(&marker));
        }
    }
}

// =====================================================================
// SealedRevision
// =====================================================================

/// A revision whose every file has been verified against the manifest and
/// whose seal is durably on disk. The only thing left is to make it
/// visible.
///
/// Holding one is the in-memory counterpart of [`RevisionState::Sealed`]:
/// a process that dies here restarts, re-derives the same
/// [`SessionStaging`], sees `Sealed`, and finishes the rename.
#[derive(Debug, Clone)]
pub struct SealedRevision {
    staging: SessionStaging,
}

impl SealedRevision {
    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        self.staging.revision()
    }

    #[must_use]
    pub fn staging(&self) -> &SessionStaging {
        &self.staging
    }

    /// Publish the sealed revision with a single `rename`.
    ///
    /// Converges from either crash point and is a no-op on a rerun after a
    /// completed publish — see the module doc for the full protocol and
    /// for how a pre-existing published directory is moved out of the
    /// rename's way.
    pub fn publish(&self) -> Result<PublishOutcome, PublishError> {
        let revision = self.staging.revision.clone();

        // Crashed *after* the rename (or simply run twice): the visible
        // tree already carries this exact seal. Not a duplicate and not an
        // error — just tidy up whatever staging skeleton is left.
        if self.staging.is_published() {
            self.staging.cleanup_staging_skeleton();
            return Ok(PublishOutcome::AlreadyPublished { revision });
        }

        let revision_dir = self.staging.revision_dir();
        if !revision_dir.is_dir() {
            return Err(PublishError::NothingStaged {
                revision,
                path: revision_dir,
            });
        }
        if !self.staging.marker_matches(&revision_dir) {
            return Err(PublishError::NotSealed { revision });
        }

        let published_dir = self.staging.published_dir();
        let published_parent = published_dir
            .parent()
            .ok_or(PathSafetyError::EscapesRoot)
            .map_err(DownloadError::from)?;
        fs::create_dir_all(published_parent).map_err(|e| DownloadError::io(published_parent, e))?;

        let superseded = self.staging.superseded_dir();
        if fs::symlink_metadata(&published_dir).is_ok() {
            // A previous revision (or a stray file/symlink) is sitting on
            // the destination name. `rename` cannot go through it on
            // Windows at all, nor on Unix when it is a non-empty
            // directory, so move it aside first. Any leftover from an
            // earlier interrupted attempt is cleared, not merged.
            match fs::remove_dir_all(&superseded) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(DownloadError::io(&superseded, e).into()),
            }
            if let Some(parent) = superseded.parent() {
                fs::create_dir_all(parent).map_err(|e| DownloadError::io(parent, e))?;
            }
            fs::rename(&published_dir, &superseded)
                .map_err(|e| DownloadError::io(&published_dir, e))?;
            fsync_dir(published_parent)?;
        }

        // --- the single rename that publishes the whole session ---
        if let Err(error) = fs::rename(&revision_dir, &published_dir) {
            // The old target was moved out of the way so the publish rename
            // is portable on Windows. If that second rename fails (for
            // example a transient sharing violation), restore the previous
            // visible tree before returning. A restart can still retry the
            // sealed revision, but callers never observe a needless hole in
            // the visible library after an ordinary error return.
            if superseded.exists() && !published_dir.exists() {
                if let Err(rollback) = fs::rename(&superseded, &published_dir) {
                    return Err(DownloadError::io(
                        &published_dir,
                        io::Error::new(
                            rollback.kind(),
                            format!(
                                "publish rename failed ({error}); rollback failed ({rollback})"
                            ),
                        ),
                    )
                    .into());
                }
                let _ = fsync_dir(published_parent);
            }
            return Err(DownloadError::io(&published_dir, error).into());
        }
        fsync_dir(published_parent)?;

        // Only now is the old revision provably replaceable.
        let _ = fs::remove_dir_all(&superseded);
        self.staging.cleanup_staging_skeleton();
        Ok(PublishOutcome::Published { revision })
    }

    /// Publish the selected-file projection without replacing the visible
    /// session directory. Each source file remains in hidden staging until
    /// the destination file has been durably copied and renamed, which
    /// leaves enough evidence to resume after any crash window.
    pub fn publish_selected(
        &self,
        manifest: &SessionManifest,
    ) -> Result<PublishOutcome, PublishError> {
        let revision = self.staging.revision.clone();

        // A matching marker plus a complete visible projection is the
        // post-marker crash window. It is safe to discard hidden staging and
        // report a no-op even when the process that wrote the marker died
        // before its cleanup phase.
        if self.staging.selected_marker_matches_manifest(manifest)
            && self.staging.visible_manifest_is_complete(manifest)
        {
            self.staging.cleanup_selected_staging();
            return Ok(PublishOutcome::AlreadyPublished { revision });
        }

        let revision_dir = self.staging.revision_dir();
        if !revision_dir.is_dir() {
            return Err(PublishError::NothingStaged {
                revision,
                path: revision_dir,
            });
        }
        if !self
            .staging
            .selected_marker_matches_manifest_at(&revision_dir, manifest)
        {
            return Err(PublishError::NotSealed { revision });
        }

        // Re-check the source tree before copying. This protects a retry
        // from trusting a damaged staging tree even if its seal marker was
        // left behind by an interrupted write or an external edit.
        self.staging.verify_manifest(manifest)?;

        for (index, expected) in manifest.files.iter().enumerate() {
            self.publish_selected_file(index, expected)?;
        }

        // The visible marker is the final selected-publication commit
        // record. It is deliberately distinct from `.ylx-revision`, which
        // continues to describe only a whole-session directory publish.
        let marker = SelectedMarker {
            scope: "selected_files".to_string(),
            revision: self.staging.revision.0.clone(),
            file_count: manifest.files.len() as u32,
            total_bytes: manifest.total_bytes(),
            manifest_digest: manifest.digest(),
        };
        let json =
            serde_json::to_vec(&marker).map_err(|e| DownloadError::Serialization(e.to_string()))?;
        let published_dir = self.staging.published_dir();
        self.staging.replace_selected_marker(&json)?;
        // `write_file_durably` fsyncs the session directory. Sync the device
        // directory as well so creation of a previously absent session name
        // is durable before cleanup removes the only staged copy.
        if let Some(parent) = published_dir.parent() {
            fsync_dir(parent)?;
        }

        self.staging.cleanup_selected_staging();
        Ok(PublishOutcome::Published { revision })
    }

    fn publish_selected_file(
        &self,
        index: usize,
        expected: &ExpectedArtifact,
    ) -> Result<(), PublishError> {
        let source = derive_target_path_for_file(
            &self.staging.file_root(),
            &self.staging.device_id,
            &self.staging.session_id,
            &expected.file_id,
            expected.target_relative_path.as_deref(),
        )?;
        let target = derive_target_path_for_file(
            &self.staging.library_root,
            &self.staging.device_id,
            &self.staging.session_id,
            &expected.file_id,
            expected.target_relative_path.as_deref(),
        )?;
        let parent = target.parent().ok_or(PathSafetyError::EscapesRoot)?;

        prepare_target_parent(&self.staging.library_root, &target)?;
        reject_symlink(&source)?;

        let inspector = ArtifactInspector::new(
            &self.staging.library_root,
            &self.staging.device_id,
            &self.staging.session_id,
        );
        if inspector.inspect(expected).is_verified() {
            self.staging.cleanup_selected_file_artifacts(index, &target);
            return Ok(());
        }

        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => reject_symlink(&target)?,
            Ok(metadata) if !metadata.is_file() => {
                return Err(DownloadError::InvalidPlan(format!(
                    "selected target is not a regular file: {}",
                    target.display()
                ))
                .into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(DownloadError::io(&target, error).into()),
        }

        let trash = self.staging.selected_trash_path(index);
        let temp = selected_temp_path(&target, self.staging.revision.as_str(), index);
        remove_any(&temp)?;

        // If a previous attempt moved the old target aside and died before
        // replacing it, restore that old target before beginning this try.
        // This preserves the pre-job sibling on ordinary copy failures.
        let target_exists = match fs::symlink_metadata(&target) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(DownloadError::io(&target, error).into()),
        };
        if !target_exists && fs::symlink_metadata(&trash).is_ok() {
            if let Some(trash_parent) = trash.parent() {
                fs::create_dir_all(trash_parent).map_err(|e| DownloadError::io(trash_parent, e))?;
            }
            fs::rename(&trash, &target).map_err(|e| DownloadError::io(&target, e))?;
            fsync_dir(parent)?;
            if let Some(trash_parent) = trash.parent() {
                fsync_dir(trash_parent)?;
            }
        }

        copy_file_durably(&source, &temp)?;
        verify_selected_temp(&temp, expected, &self.staging.revision)?;

        let had_target = match fs::symlink_metadata(&target) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(DownloadError::io(&target, error).into()),
        };
        if had_target {
            reject_symlink(&target)?;
            remove_any(&trash)?;
            if let Some(trash_parent) = trash.parent() {
                fs::create_dir_all(trash_parent).map_err(|e| DownloadError::io(trash_parent, e))?;
            }
            fs::rename(&target, &trash).map_err(|e| DownloadError::io(&target, e))?;
            fsync_dir(parent)?;
            if let Some(trash_parent) = trash.parent() {
                fsync_dir(trash_parent)?;
            }
        }

        if let Err(error) = fs::rename(&temp, &target) {
            if had_target && fs::symlink_metadata(&trash).is_ok() {
                if let Err(rollback) = fs::rename(&trash, &target) {
                    return Err(DownloadError::io(
                        &target,
                        io::Error::new(
                            rollback.kind(),
                            format!(
                                "selected-file rename failed ({error}); rollback failed ({rollback})"
                            ),
                        ),
                    )
                    .into());
                }
                let _ = fsync_dir(parent);
                if let Some(trash_parent) = trash.parent() {
                    let _ = fsync_dir(trash_parent);
                }
            }
            let _ = fs::remove_file(&temp);
            return Err(DownloadError::io(&target, error).into());
        }
        fsync_dir(parent)?;

        // The new target is durable and the source remains in staging, so
        // the old copy is no longer needed for rollback. A crash before this
        // cleanup is harmless: a retry sees a valid target and removes it.
        remove_any(&trash)?;
        Ok(())
    }
}

impl SessionStaging {
    fn superseded_dir(&self) -> PathBuf {
        self.staging_root()
            .join(SUPERSEDED_DIR_NAME)
            .join(self.revision.as_str())
            .join(&self.device_id)
            .join(&self.session_id)
    }

    fn selected_trash_dir(&self) -> PathBuf {
        self.staging_root()
            .join(SELECTED_TRASH_DIR_NAME)
            .join(self.revision.as_str())
            .join(&self.device_id)
            .join(&self.session_id)
    }

    fn selected_trash_path(&self, index: usize) -> PathBuf {
        self.selected_trash_dir().join(format!("file-{index}"))
    }

    fn selected_marker_trash_path(&self) -> PathBuf {
        self.selected_trash_dir().join("marker")
    }

    fn selected_marker_matches_manifest(&self, manifest: &SessionManifest) -> bool {
        self.selected_marker_matches_manifest_at(&self.published_dir(), manifest)
    }

    fn selected_marker_matches_manifest_at(&self, dir: &Path, manifest: &SessionManifest) -> bool {
        read_selected_marker(dir).is_some_and(|marker| {
            marker.revision == self.revision.0
                && marker.file_count == manifest.files.len() as u32
                && marker.total_bytes == manifest.total_bytes()
                && marker.manifest_digest == manifest.digest()
        })
    }

    /// Best-effort removal of the now-empty `<revision>/<device>` chain
    /// the rename left behind, plus this revision's crash-window trash.
    /// Failure is never fatal: an orphaned empty directory under
    /// `.ylx-staging` costs nothing and cannot be mistaken for a session.
    fn cleanup_staging_skeleton(&self) {
        let revision_dir = self.revision_dir();
        let _ = fs::remove_dir_all(&revision_dir);
        prune_empty_parents(&revision_dir, &self.staging_root());
        // The old published tree may have been moved aside just before a
        // crash. `remove_dir` cannot remove its non-empty contents, leaving
        // `.superseded` behind forever and making a successful recovery look
        // incomplete. The trash is keyed by this revision, so recursively
        // removing it cannot affect another session/revision.
        let superseded = self.superseded_dir();
        let _ = fs::remove_dir_all(&superseded);
        prune_empty_parents(&superseded, &self.staging_root().join(SUPERSEDED_DIR_NAME));
        let _ = fs::remove_dir(self.staging_root().join(SUPERSEDED_DIR_NAME));
        let _ = fs::remove_dir(self.staging_root());
    }

    /// Cleanup for selected publication. Unlike full-session cleanup this
    /// must never remove a visible session directory or its old
    /// `.ylx-revision` marker.
    fn cleanup_selected_staging(&self) {
        let revision_dir = self.revision_dir();
        let _ = fs::remove_dir_all(&revision_dir);
        prune_empty_parents(&revision_dir, &self.staging_root());

        let trash = self.selected_trash_dir();
        let _ = fs::remove_dir_all(&trash);
        prune_empty_parents(&trash, &self.staging_root().join(SELECTED_TRASH_DIR_NAME));
        let _ = fs::remove_dir(self.staging_root().join(SELECTED_TRASH_DIR_NAME));
        let _ = fs::remove_dir(self.staging_root());
    }

    fn cleanup_selected_file_artifacts(&self, index: usize, target: &Path) {
        let _ = fs::remove_file(selected_temp_path(target, self.revision.as_str(), index));
        let _ = remove_any(&self.selected_trash_path(index));
    }

    fn replace_selected_marker(&self, bytes: &[u8]) -> Result<(), PublishError> {
        let published_dir = self.published_dir();
        let marker_path = published_dir.join(SELECTED_MARKER_NAME);
        // This creates only the validated device/session parents and checks
        // that neither is a symlink; the marker itself is handled by the
        // durable replacement helper below.
        prepare_target_parent(&self.library_root, &marker_path)?;
        reject_symlink(&published_dir)?;
        replace_file_durably(bytes, &marker_path, &self.selected_marker_trash_path())?;
        Ok(())
    }
}

// =====================================================================
// Filesystem helpers
// =====================================================================

/// Remove `path`'s ancestors, deepest first, while they are empty and
/// still strictly below `stop_at`. Best effort by construction:
/// `remove_dir` on a non-empty directory simply fails and ends the walk.
fn prune_empty_parents(path: &Path, stop_at: &Path) {
    let mut current = path.parent().map(Path::to_path_buf);
    while let Some(dir) = current {
        if dir == stop_at || !dir.starts_with(stop_at) || fs::remove_dir(&dir).is_err() {
            return;
        }
        current = dir.parent().map(Path::to_path_buf);
    }
}

/// The temporary sibling name used by `download::write_file_durably`.
fn durable_temp_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(".tmp");
    PathBuf::from(raw)
}

/// Remove either a regular file, a symlink, or a directory without following
/// a symlink. Selected publication uses this for deterministic temporary and
/// trash names left by an interrupted attempt.
fn remove_any(path: &Path) -> Result<(), DownloadError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(DownloadError::io(path, error)),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).map_err(|error| DownloadError::io(path, error))
    } else {
        fs::remove_file(path).map_err(|error| DownloadError::io(path, error))
    }
}

/// Deterministic same-directory temporary name for one selected target. The
/// revision and manifest index make concurrent revisions/jobs independent;
/// the path is still below the already validated target parent.
fn selected_temp_path(target: &Path, revision: &str, index: usize) -> PathBuf {
    let filename = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    target.with_file_name(format!(".{filename}.ylx-selected-{revision}-{index}.tmp"))
}

/// Copy one sealed staging file to a same-directory temporary file and flush
/// the bytes before the caller renames it into the visible target.
fn copy_file_durably(source: &Path, temp: &Path) -> Result<(), PublishError> {
    reject_symlink(source)?;
    let source_meta = fs::metadata(source).map_err(|error| DownloadError::io(source, error))?;
    if !source_meta.is_file() {
        return Err(DownloadError::InvalidPlan(format!(
            "{}: staged source is not a regular file",
            source.display()
        ))
        .into());
    }

    let parent = temp.parent().ok_or_else(|| {
        DownloadError::Serialization("selected temporary path has no parent directory".to_string())
    })?;
    fs::create_dir_all(parent).map_err(|error| DownloadError::io(parent, error))?;
    reject_symlink(temp)?;
    let mut input = fs::File::open(source).map_err(|error| DownloadError::io(source, error))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(|error| DownloadError::io(temp, error))?;
    io::copy(&mut input, &mut output).map_err(|error| DownloadError::io(temp, error))?;
    output
        .sync_all()
        .map_err(|error| DownloadError::io(temp, error))?;
    drop(output);
    Ok(())
}

fn verify_selected_temp(
    temp: &Path,
    expected: &ExpectedArtifact,
    revision: &RevisionId,
) -> Result<(), PublishError> {
    let metadata = fs::metadata(temp).map_err(|error| DownloadError::io(temp, error))?;
    if !metadata.is_file() || metadata.len() != expected.expected_size {
        return Err(PublishError::ManifestMismatch {
            revision: revision.clone(),
            problems: vec![format!(
                "{}: copied temporary file has unexpected size",
                expected.file_id
            )],
        });
    }
    if let Some(expected_hash) = &expected.expected_sha256_hex {
        let actual = sha256_of_file(temp)?;
        if !actual.eq_ignore_ascii_case(expected_hash) {
            return Err(PublishError::ManifestMismatch {
                revision: revision.clone(),
                problems: vec![format!(
                    "{}: copied temporary file has sha256 {actual}, expected {expected_hash}",
                    expected.file_id
                )],
            });
        }
    }
    Ok(())
}

/// Rewrite a hidden seal marker without relying on Unix's rename-over-existing
/// behavior. The marker contains only derived metadata; if a process dies
/// after removing it, the revision is conservatively observed as `Staged` and
/// the next seal attempt recreates it from the already verified files.
fn rewrite_internal_marker(path: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => reject_symlink(path)?,
        Ok(metadata) if !metadata.is_file() => {
            return Err(DownloadError::InvalidPlan(format!(
                "internal marker is not a regular file: {}",
                path.display()
            ))
            .into())
        }
        Ok(_) => {
            fs::remove_file(path).map_err(|error| DownloadError::io(path, error))?;
            if let Some(parent) = path.parent() {
                fsync_dir(parent)?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(DownloadError::io(path, error).into()),
    }
    write_file_durably(path, bytes).map_err(PublishError::from)
}

/// Durably replace one marker file while remaining portable on platforms
/// where `rename(source, existing)` refuses to overwrite. The old marker is
/// moved to same-volume trash first, and restored if installing the new
/// marker fails.
fn replace_file_durably(bytes: &[u8], path: &Path, backup: &Path) -> Result<(), PublishError> {
    let parent = path.parent().ok_or_else(|| {
        DownloadError::Serialization("durable replacement path has no parent directory".to_string())
    })?;
    fs::create_dir_all(parent).map_err(|error| DownloadError::io(parent, error))?;
    reject_symlink(path)?;
    let temp = durable_temp_path(path);
    remove_any(&temp)?;

    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| DownloadError::io(&temp, error))?;
    output
        .write_all(bytes)
        .map_err(|error| DownloadError::io(&temp, error))?;
    output
        .sync_all()
        .map_err(|error| DownloadError::io(&temp, error))?;
    drop(output);

    let had_old = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(DownloadError::InvalidPlan(format!(
                    "selected marker path is not a regular file: {}",
                    path.display()
                ))
                .into());
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(DownloadError::io(path, error).into()),
    };

    if had_old {
        remove_any(backup)?;
        let backup_parent = backup.parent().ok_or_else(|| {
            DownloadError::Serialization("marker backup path has no parent directory".to_string())
        })?;
        fs::create_dir_all(backup_parent)
            .map_err(|error| DownloadError::io(backup_parent, error))?;
        fs::rename(path, backup).map_err(|error| DownloadError::io(path, error))?;
        fsync_dir(parent)?;
        fsync_dir(backup_parent)?;
    }

    if let Err(error) = fs::rename(&temp, path) {
        if had_old && fs::symlink_metadata(backup).is_ok() {
            if let Err(rollback) = fs::rename(backup, path) {
                return Err(DownloadError::io(
                    path,
                    io::Error::new(
                        rollback.kind(),
                        format!(
                            "selected marker install failed ({error}); rollback failed ({rollback})"
                        ),
                    ),
                )
                .into());
            }
            let _ = fsync_dir(parent);
        }
        let _ = fs::remove_file(&temp);
        return Err(DownloadError::io(path, error).into());
    }
    fsync_dir(parent)?;
    if had_old {
        let _ = remove_any(backup);
    }
    Ok(())
}

/// Every regular file at or below `dir`, absolute. Symlinks are collected
/// as themselves (never followed) so a symlink planted in staging shows up
/// as an unexpected file rather than silently passing the manifest check.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), io::Error> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files(&entry.path(), out)?;
        } else {
            out.push(entry.path());
        }
    }
    Ok(())
}

/// fsync every directory at or below `dir`. The `.part` files themselves
/// were already fsynced before their per-file rename; what is not yet
/// durable is the *directory entries* those renames created.
fn fsync_tree(dir: &Path) -> Result<(), DownloadError> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = fs::read_dir(&current).map_err(|e| DownloadError::io(&current, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| DownloadError::io(&current, e))?;
            let file_type = entry
                .file_type()
                .map_err(|e| DownloadError::io(entry.path(), e))?;
            if file_type.is_dir() {
                stack.push(entry.path());
            }
        }
        fsync_dir(&current)?;
    }
    Ok(())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::download::{
        derive_target_path_for_file, journal_path, part_path, DownloadJournal, RequestedRange,
        SourceResponse,
    };
    use crate::testing::FaultPoint;
    use std::io::Cursor;
    use tempfile::{tempdir, TempDir};

    const DEVICE: &str = "dev-1";
    const SESSION: &str = "sess-1";
    const PAYLOAD: &[u8] = b"signed publication payload for sess-1 revision A";

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// A source that always answers `200 OK` with the whole object, and
    /// that can be armed to fail instead — the deterministic stand-in for
    /// "the network died in the middle of a session".
    struct WholeObjectSource {
        body: Vec<u8>,
        fault: FaultPoint<String>,
    }

    impl WholeObjectSource {
        fn new(body: &[u8]) -> Self {
            WholeObjectSource {
                body: body.to_vec(),
                fault: FaultPoint::new(),
            }
        }
    }

    impl DownloadSource for WholeObjectSource {
        fn fetch_range(&self, _request: RequestedRange) -> Result<SourceResponse, DownloadError> {
            self.fault.check().map_err(DownloadError::Source)?;
            Ok(SourceResponse {
                status: 200,
                etag: Some("etag-1".to_string()),
                content_range: None,
                content_length: Some(self.body.len() as u64),
                body: Box::new(Cursor::new(self.body.clone())),
            })
        }
    }

    struct Session {
        root: TempDir,
        files: Vec<(String, String, Vec<u8>)>,
    }

    impl Session {
        /// A session of `n` files with distinct nested display paths.
        fn new(n: usize) -> Self {
            let files = (0..n)
                .map(|i| {
                    (
                        format!("file-id-{i}"),
                        format!("video/left_{i:05}.mp4"),
                        format!("payload for file {i}").into_bytes(),
                    )
                })
                .collect();
            Session {
                root: tempdir().expect("tempdir"),
                files,
            }
        }

        fn root(&self) -> &Path {
            self.root.path()
        }

        fn staging(&self) -> SessionStaging {
            SessionStaging::for_publication(self.root(), DEVICE, SESSION, PAYLOAD).expect("staging")
        }

        fn plans(&self) -> Vec<FilePlan> {
            self.files
                .iter()
                .map(|(id, rel, body)| FilePlan {
                    device_id: DEVICE.to_string(),
                    session_id: SESSION.to_string(),
                    file_id: id.clone(),
                    target_relative_path: Some(rel.clone()),
                    expected_size: body.len() as u64,
                    expected_sha256_hex: sha256_hex(body),
                })
                .collect()
        }

        fn manifest(&self) -> SessionManifest {
            SessionManifest::from_plans(DEVICE, SESSION, &self.plans())
        }

        /// Download every file into staging. Returns the staging area.
        fn stage_all(&self) -> SessionStaging {
            let staging = self.staging();
            for (plan, (_, _, body)) in self.plans().iter().zip(&self.files) {
                let source = WholeObjectSource::new(body);
                staging.download_into(&source, plan).expect("staged file");
            }
            staging
        }

        /// Everything visible under `<root>/<device>`, relative and
        /// `/`-joined — the exact set a user's file browser would show.
        fn visible(&self) -> Vec<String> {
            let mut out = Vec::new();
            collect_files(&self.root().join(DEVICE), &mut out).expect("walk");
            let mut shown: Vec<String> = out
                .iter()
                .filter_map(|p| relative_display_path(&self.root().join(DEVICE), p))
                .collect();
            shown.sort();
            shown
        }
    }

    // -----------------------------------------------------------------
    // Commit 63 — a session assembles out of sight
    // -----------------------------------------------------------------

    #[test]
    fn a_full_session_download_is_invisible_until_the_revision_is_published() {
        let session = Session::new(3);
        let staging = session.stage_all();

        // Every byte is on disk...
        assert_eq!(staging.state(), RevisionState::Staged);
        for (_, rel, body) in &session.files {
            let staged = staging
                .revision_dir()
                .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
            assert_eq!(fs::read(&staged).expect("staged bytes"), *body);
        }
        // ...and none of it is visible.
        assert!(
            session.visible().is_empty(),
            "a partially assembled session must not leak into the library tree: {:?}",
            session.visible()
        );
        assert_eq!(published_revision(session.root(), DEVICE, SESSION), None);
        assert!(!session.root().join(DEVICE).join(SESSION).exists());

        let outcome = staging.publish(&session.manifest()).expect("publish");
        assert_eq!(
            outcome,
            PublishOutcome::Published {
                revision: staging.revision().clone()
            }
        );
        assert_eq!(
            session.visible(),
            vec![
                format!("{SESSION}/{REVISION_MARKER_NAME}"),
                format!("{SESSION}/video/left_00000.mp4"),
                format!("{SESSION}/video/left_00001.mp4"),
                format!("{SESSION}/video/left_00002.mp4"),
            ]
        );
        assert_eq!(
            published_revision(session.root(), DEVICE, SESSION).as_ref(),
            Some(staging.revision())
        );
    }

    #[test]
    fn a_session_interrupted_mid_assembly_leaves_the_library_tree_empty_and_resumes() {
        let session = Session::new(3);
        let staging = session.staging();
        let plans = session.plans();

        // File 0 lands; file 1's source fails permanently — the session is
        // abandoned half-assembled.
        let ok = WholeObjectSource::new(&session.files[0].2);
        staging.download_into(&ok, &plans[0]).expect("first file");

        let broken = WholeObjectSource::new(&session.files[1].2);
        broken.fault.fail_always("connection reset".to_string());
        assert!(staging.download_into(&broken, &plans[1]).is_err());
        assert_eq!(broken.fault.failures(), 1);

        assert!(session.visible().is_empty(), "nothing may be visible yet");
        assert!(matches!(
            staging.publish(&session.manifest()),
            Err(PublishError::ManifestMismatch { .. })
        ));
        assert!(
            session.visible().is_empty(),
            "a refused publish must not have touched the library tree"
        );

        // The retry resumes into the same revision directory and finishes.
        broken.fault.disarm();
        staging.download_into(&broken, &plans[1]).expect("retry");
        let last = WholeObjectSource::new(&session.files[2].2);
        staging.download_into(&last, &plans[2]).expect("third file");
        staging.publish(&session.manifest()).expect("publish");
        assert_eq!(session.visible().len(), 4);
    }

    // -----------------------------------------------------------------
    // Commit 64 — crash before / after the rename
    // -----------------------------------------------------------------

    #[test]
    fn a_crash_before_the_rename_leaves_the_visible_tree_untouched_and_the_retry_converges() {
        let session = Session::new(2);
        let staging = session.stage_all();

        // Seal, then "crash": the sealed revision is durably on disk but
        // the rename never happened.
        let sealed = staging.seal(&session.manifest()).expect("seal");
        drop(sealed);
        // A retry may enter sealing again before it reaches the rename. The
        // hidden marker rewrite must remain portable when that marker already
        // exists (Windows does not generally allow rename-over-existing).
        staging.seal(&session.manifest()).expect("re-seal");
        assert_eq!(
            staging.state(),
            RevisionState::Sealed,
            "recovery must be able to see that the crash was *before* the rename"
        );
        assert!(
            session.visible().is_empty(),
            "a sealed-but-unpublished revision is still invisible"
        );
        assert_eq!(published_revision(session.root(), DEVICE, SESSION), None);

        // Restart: a freshly derived staging area finds and finishes it.
        let restarted = session.staging();
        assert_eq!(restarted.state(), RevisionState::Sealed);
        let outcome = restarted.publish(&session.manifest()).expect("retry");
        assert_eq!(
            outcome,
            PublishOutcome::Published {
                revision: restarted.revision().clone()
            }
        );
        assert_eq!(session.visible().len(), 3);
        assert_eq!(restarted.state(), RevisionState::Published);
    }

    #[test]
    fn a_crash_after_the_rename_converges_to_the_same_state_with_no_duplicate() {
        let session = Session::new(2);
        let staging = session.stage_all();
        staging.publish(&session.manifest()).expect("publish");
        let after_first = session.visible();
        assert_eq!(after_first.len(), 3);
        assert_eq!(staging.state(), RevisionState::Published);

        // "Crash" right after the rename: rerun the whole publish from a
        // freshly derived staging area, exactly as a restarted process
        // would.
        let restarted = session.staging();
        assert_eq!(
            restarted.state(),
            RevisionState::Published,
            "recovery must be able to see that the crash was *after* the rename"
        );
        let outcome = restarted.publish(&session.manifest()).expect("rerun");
        assert_eq!(
            outcome,
            PublishOutcome::AlreadyPublished {
                revision: restarted.revision().clone()
            },
            "a rerun after a completed publish is a no-op, not an error"
        );
        assert_eq!(session.visible(), after_first, "no duplicate, no change");

        // And a third run still says the same thing.
        assert!(matches!(
            session.staging().publish(&session.manifest()),
            Ok(PublishOutcome::AlreadyPublished { .. })
        ));
        assert_eq!(session.visible(), after_first);
    }

    // -----------------------------------------------------------------
    // Commit 63 — a single file is not a session
    // -----------------------------------------------------------------

    #[test]
    fn a_single_file_download_publishes_that_file_but_never_the_session() {
        let session = Session::new(2);
        let plans = session.plans();

        // The legacy single-file path: straight into the visible tree.
        let source = WholeObjectSource::new(&session.files[0].2);
        let verified =
            download_file(&source, &plans[0], session.root()).expect("single file downloads");
        assert_eq!(
            fs::read(&verified.path).expect("committed bytes"),
            session.files[0].2
        );
        assert_eq!(session.visible(), vec!["sess-1/video/left_00000.mp4"]);

        // ...but it has not claimed the session is complete.
        assert_eq!(
            published_revision(session.root(), DEVICE, SESSION),
            None,
            "one committed file must never mark the whole session published"
        );
        let staging = session.staging();
        assert_eq!(staging.state(), RevisionState::Absent);

        // And nothing lets it: publishing the session refuses, because the
        // manifest's files are not in a staged revision.
        let err = staging.publish(&session.manifest()).expect_err("refused");
        assert!(
            matches!(err, PublishError::NothingStaged { .. }),
            "got {err:?}"
        );
        assert_eq!(published_revision(session.root(), DEVICE, SESSION), None);
    }

    // -----------------------------------------------------------------
    // Selected-file publication
    // -----------------------------------------------------------------

    #[test]
    fn selected_publication_preserves_siblings_and_the_full_session_marker() {
        let session = Session::new(2);
        let plans = session.plans();
        let visible_session = session.root().join(DEVICE).join(SESSION);
        fs::create_dir_all(visible_session.join("video")).unwrap();
        fs::write(
            visible_session.join("video").join("left_00000.mp4"),
            b"older sibling",
        )
        .unwrap();
        let old_revision = RevisionMarker {
            revision: "rev-old-full-session".to_string(),
            file_count: 1,
            total_bytes: 14,
        };
        fs::write(
            visible_session.join(REVISION_MARKER_NAME),
            serde_json::to_vec(&old_revision).unwrap(),
        )
        .unwrap();

        let selected_plan = plans[1].clone();
        let selected_manifest =
            SessionManifest::from_plans(DEVICE, SESSION, std::slice::from_ref(&selected_plan));
        let staging = SessionStaging::for_publication(
            session.root(),
            DEVICE,
            SESSION,
            b"selected publication B",
        )
        .unwrap();
        staging
            .download_into(&WholeObjectSource::new(&session.files[1].2), &selected_plan)
            .unwrap();

        assert_eq!(
            fs::read(visible_session.join("video").join("left_00000.mp4")).unwrap(),
            b"older sibling"
        );
        assert!(!visible_session
            .join("video")
            .join("left_00001.mp4")
            .exists());

        let outcome = staging.publish_selected(&selected_manifest).unwrap();
        assert_eq!(
            outcome,
            PublishOutcome::Published {
                revision: staging.revision().clone()
            }
        );
        assert_eq!(
            fs::read(visible_session.join("video").join("left_00000.mp4")).unwrap(),
            b"older sibling"
        );
        assert_eq!(
            fs::read(visible_session.join("video").join("left_00001.mp4")).unwrap(),
            session.files[1].2
        );
        assert_eq!(
            read_revision_marker(&visible_session).unwrap(),
            old_revision,
            "selected publication must not rewrite the whole-session claim"
        );
        let selected_marker = read_selected_marker(&visible_session).unwrap();
        assert_eq!(selected_marker.scope, "selected_files");
        assert_eq!(selected_marker.revision, staging.revision().as_str());
        assert_eq!(selected_marker.file_count, 1);
        assert_eq!(selected_marker.total_bytes, selected_manifest.total_bytes());
        assert_eq!(selected_marker.manifest_digest, selected_manifest.digest());
        assert_eq!(
            published_revision(session.root(), DEVICE, SESSION)
                .unwrap()
                .as_str(),
            "rev-old-full-session"
        );
        assert_eq!(staging.state(), RevisionState::SelectedPublished);
        assert!(!staging.staging_root().exists());

        // The post-marker crash window is idempotent even after staging was
        // cleaned: the visible projection and matching marker are enough.
        assert_eq!(
            staging.publish_selected(&selected_manifest).unwrap(),
            PublishOutcome::AlreadyPublished {
                revision: staging.revision().clone()
            }
        );
    }

    #[test]
    fn selected_publication_repairs_a_corrupted_target_with_the_same_marker_revision() {
        let session = Session::new(1);
        let plan = session.plans().remove(0);
        let manifest = SessionManifest::from_plans(DEVICE, SESSION, std::slice::from_ref(&plan));
        let payload = b"selected repair payload";
        let staging =
            SessionStaging::for_publication(session.root(), DEVICE, SESSION, payload).unwrap();
        staging
            .download_into(&WholeObjectSource::new(&session.files[0].2), &plan)
            .unwrap();
        staging.publish_selected(&manifest).unwrap();

        let target = session
            .root()
            .join(DEVICE)
            .join(SESSION)
            .join("video")
            .join("left_00000.mp4");
        fs::write(&target, b"corrupt but same size").unwrap();
        let retry =
            SessionStaging::for_publication(session.root(), DEVICE, SESSION, payload).unwrap();
        retry
            .download_into(&WholeObjectSource::new(&session.files[0].2), &plan)
            .unwrap();
        assert_eq!(
            retry.publish_selected(&manifest).unwrap(),
            PublishOutcome::Published {
                revision: retry.revision().clone()
            }
        );
        assert_eq!(fs::read(target).unwrap(), session.files[0].2);
        assert_eq!(retry.state(), RevisionState::SelectedPublished);
    }

    #[test]
    fn selected_publication_resumes_after_one_target_rename_before_marker() {
        let session = Session::new(2);
        let plans = session.plans();
        let manifest = SessionManifest::from_plans(DEVICE, SESSION, &plans);
        let staging = SessionStaging::for_publication(
            session.root(),
            DEVICE,
            SESSION,
            b"selected crash after one file",
        )
        .unwrap();
        for (plan, (_, _, body)) in plans.iter().zip(&session.files) {
            staging
                .download_into(&WholeObjectSource::new(body), plan)
                .unwrap();
        }

        // Simulate a process dying immediately after the first per-file
        // rename. The staging seal and source bytes remain, but the visible
        // selected marker has not been written yet.
        let sealed = staging.seal_selected(&manifest).unwrap();
        sealed.publish_selected_file(0, &manifest.files[0]).unwrap();
        assert!(!staging.published_dir().join(SELECTED_MARKER_NAME).exists());
        assert_eq!(staging.state(), RevisionState::Sealed);

        let restarted = SessionStaging::for_publication(
            session.root(),
            DEVICE,
            SESSION,
            b"selected crash after one file",
        )
        .unwrap();
        assert_eq!(
            restarted.publish_selected(&manifest).unwrap(),
            PublishOutcome::Published {
                revision: restarted.revision().clone()
            }
        );
        assert_eq!(session.visible().len(), 3);
        assert_eq!(restarted.state(), RevisionState::SelectedPublished);
    }

    #[test]
    fn selected_publication_rejects_duplicate_case_folded_targets_before_touching_staging() {
        let session = Session::new(2);
        let mut plans = session.plans();
        plans[0].target_relative_path = Some("video/duplicate.bin".to_string());
        plans[1].target_relative_path = Some("video/DUPLICATE.bin".to_string());
        let manifest = SessionManifest::from_plans(DEVICE, SESSION, &plans);
        let staging = SessionStaging::for_publication(
            session.root(),
            DEVICE,
            SESSION,
            b"duplicate selected payload",
        )
        .unwrap();
        let error = staging
            .publish_selected(&manifest)
            .expect_err("duplicate target");
        assert!(matches!(error, PublishError::ManifestMismatch { .. }));
        assert!(!staging.staging_root().exists());
        assert!(session.visible().is_empty());
    }

    // -----------------------------------------------------------------
    // Commit 64 — the manifest is checked against every file
    // -----------------------------------------------------------------

    #[test]
    fn a_manifest_listing_a_file_that_was_never_staged_refuses_to_publish() {
        let session = Session::new(2);
        let staging = session.stage_all();

        let mut manifest = session.manifest();
        manifest.files.push(ExpectedArtifact::new(
            "file-id-never-fetched",
            Some("imu/imu_00000.csv".to_string()),
            42,
            sha256_hex(b"never downloaded"),
        ));

        let err = staging.publish(&manifest).expect_err("refused");
        let PublishError::ManifestMismatch { problems, .. } = &err else {
            panic!("expected a manifest mismatch, got {err:?}");
        };
        assert!(
            problems.iter().any(|p| p.contains("file-id-never-fetched")),
            "problems: {problems:?}"
        );
        assert!(session.visible().is_empty());
        assert_eq!(staging.state(), RevisionState::Staged, "still unsealed");
    }

    #[test]
    fn a_staged_file_the_manifest_does_not_list_refuses_to_publish() {
        let session = Session::new(2);
        let staging = session.stage_all();
        fs::write(
            staging.revision_dir().join("smuggled.bin"),
            b"not in the manifest",
        )
        .unwrap();

        let err = staging.publish(&session.manifest()).expect_err("refused");
        let PublishError::ManifestMismatch { problems, .. } = &err else {
            panic!("expected a manifest mismatch, got {err:?}");
        };
        assert!(
            problems.iter().any(|p| p.contains("smuggled.bin")),
            "problems: {problems:?}"
        );
        assert!(session.visible().is_empty());
    }

    #[test]
    fn a_leftover_part_file_refuses_to_publish() {
        let session = Session::new(2);
        let staging = session.stage_all();
        // A third file that never finished: `.part` plus journal, exactly
        // what a crash mid-file leaves behind.
        let unfinished = staging.revision_dir().join("video").join("left_00002.mp4");
        fs::write(part_path(&unfinished), b"half a file").unwrap();
        DownloadJournal::write(
            &journal_path(&unfinished),
            &DownloadJournal {
                confirmed_offset: 11,
                expected_size: 100,
                expected_sha256_hex: sha256_hex(b"whole"),
                etag: None,
            },
        )
        .unwrap();

        assert!(matches!(
            staging.publish(&session.manifest()),
            Err(PublishError::ManifestMismatch { .. })
        ));
        assert!(session.visible().is_empty());
    }

    #[test]
    fn a_staged_file_whose_bytes_were_corrupted_refuses_to_publish() {
        let session = Session::new(2);
        let staging = session.stage_all();
        let target = staging.revision_dir().join("video").join("left_00001.mp4");
        let corrupt: Vec<u8> = session.files[1].2.iter().map(|b| b ^ 0x20).collect();
        fs::write(&target, &corrupt).unwrap();

        let err = staging.publish(&session.manifest()).expect_err("refused");
        let PublishError::ManifestMismatch { problems, .. } = &err else {
            panic!("expected a manifest mismatch, got {err:?}");
        };
        assert!(
            problems.iter().any(|p| p.contains("sha256")),
            "problems: {problems:?}"
        );
        assert!(session.visible().is_empty());
    }

    #[test]
    fn an_unsealed_revision_cannot_be_published_behind_the_manifest_check() {
        let session = Session::new(1);
        let staging = session.stage_all();
        // Fabricate a `SealedRevision` for a revision that was never
        // sealed: the rename must still refuse.
        let forged = SealedRevision {
            staging: staging.clone(),
        };
        assert!(matches!(
            forged.publish(),
            Err(PublishError::NotSealed { .. })
        ));
        assert!(session.visible().is_empty());
    }

    // -----------------------------------------------------------------
    // Commit 64 — the pre-existing target directory
    // -----------------------------------------------------------------

    #[test]
    fn a_pre_existing_session_directory_is_moved_aside_not_left_to_block_the_rename() {
        // `rename` onto an existing directory fails on Windows always and
        // on Unix whenever the destination is non-empty. Expressed here as
        // a pre-existing path so it runs everywhere.
        let session = Session::new(2);
        let stale_dir = session.root().join(DEVICE).join(SESSION);
        fs::create_dir_all(stale_dir.join("video")).unwrap();
        fs::write(
            stale_dir.join("video").join("left_00000.mp4"),
            b"an older revision",
        )
        .unwrap();
        fs::write(stale_dir.join("stray.txt"), b"junk from a previous life").unwrap();

        let staging = session.stage_all();
        let outcome = staging.publish(&session.manifest()).expect("publish");
        assert!(matches!(outcome, PublishOutcome::Published { .. }));

        // The visible tree is exactly the new revision — the old files are
        // gone, not merged with the new ones.
        assert_eq!(
            session.visible(),
            vec![
                format!("{SESSION}/{REVISION_MARKER_NAME}"),
                format!("{SESSION}/video/left_00000.mp4"),
                format!("{SESSION}/video/left_00001.mp4"),
            ]
        );
        assert_eq!(
            fs::read(stale_dir.join("video").join("left_00000.mp4")).unwrap(),
            session.files[0].2
        );
        assert!(!staging.staging_root().exists(), "staging is cleaned up");
    }

    #[test]
    fn a_pre_existing_file_at_the_session_path_does_not_block_the_rename() {
        let session = Session::new(1);
        let stale = session.root().join(DEVICE).join(SESSION);
        fs::create_dir_all(stale.parent().unwrap()).unwrap();
        fs::write(&stale, b"a plain file where a session directory belongs").unwrap();

        let staging = session.stage_all();
        staging.publish(&session.manifest()).expect("publish");
        assert!(stale.is_dir());
        assert_eq!(session.visible().len(), 2);
    }

    // -----------------------------------------------------------------
    // Identity / safety
    // -----------------------------------------------------------------

    #[test]
    fn the_revision_id_is_derived_from_the_publication_and_is_a_safe_path_segment() {
        let a = RevisionId::from_publication(b"payload A");
        let b = RevisionId::from_publication(b"payload B");
        assert_ne!(a, b);
        assert_eq!(a, RevisionId::from_publication(b"payload A"));
        assert!(validate_id_segment(a.as_str()).is_ok());
        assert_eq!(RevisionId::parse(a.as_str()).unwrap(), a);
    }

    #[test]
    fn a_staging_area_refuses_a_plan_belonging_to_another_session() {
        let session = Session::new(1);
        let staging = session.staging();
        let mut plan = session.plans().remove(0);
        plan.session_id = "someone-elses-session".to_string();
        assert!(matches!(
            staging.download_into(&WholeObjectSource::new(b"x"), &plan),
            Err(DownloadError::InvalidPlan(_))
        ));
    }

    #[test]
    fn the_staging_and_marker_names_cannot_be_used_as_ids_or_display_paths() {
        for reserved in [STAGING_DIR_NAME, REVISION_MARKER_NAME] {
            assert!(
                matches!(
                    validate_id_segment(reserved),
                    Err(PathSafetyError::ReservedInternalName(_))
                ),
                "{reserved} must be reserved"
            );
        }
        let root = tempdir().unwrap();
        assert!(derive_target_path_for_file(
            root.path(),
            DEVICE,
            SESSION,
            "f1",
            Some("video/.ylx-revision"),
        )
        .is_err());
    }

    #[test]
    fn discarding_a_revision_removes_its_staging_and_nothing_else() {
        let session = Session::new(2);
        let staging = session.stage_all();
        staging.discard().expect("discard");
        assert_eq!(staging.state(), RevisionState::Absent);
        assert!(session.visible().is_empty());
        // Idempotent.
        staging.discard().expect("discard again");
    }
}
