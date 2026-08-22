//! PC-00 core domain types — plan section 5.4 / section 16 "F6" freeze.
//!
//! This module is the real, frozen replacement for the W0-06 stub that
//! used to live here (see git history — its doc comment explicitly said
//! "the real domain module ... is owned by PC-00"). It defines:
//!
//! - Opaque identifier newtypes ([`DeviceId`], [`SessionId`], [`FileId`])
//!   matching the id shapes the Pi transfer-daemon actually returns —
//!   verified against the RP-YLX repo's machine-readable contract at
//!   `capture/docs/transfer-api/v1/schemas/*.json` (canonical source per
//!   plan section 10.2) rather than guessed from prose.
//! - [`PublicationManifest`] and its nested types, mirroring
//!   `publication-manifest.schema.json` field-for-field (`session_id`,
//!   `revision`, `files[]` with `id`/`role`/`size_bytes`/`sha256`, and
//!   `publication_signature`), so a real Pi response can deserialize
//!   directly into this type with `serde` (see the `tests` module for a
//!   round-trip against the RP-YLX fixture
//!   `capture/docs/transfer-api/v1/fixtures/success/publication-manifest.json`).
//!
//! Device state ([`crate::device`]) and transfer job state
//! ([`crate::transfer`]) live in their own sibling modules per the plan
//! section 16 crate layout; this module only holds the shared identifiers
//! and the wire-shaped publication manifest both of them reference.
//!
//! Timestamps (`captured_at`/`published_at`) are kept as opaque RFC 3339
//! `String`s rather than a parsed date-time type — this crate does not
//! currently depend on `chrono`/`time` and the task forbids adding new
//! dependencies, and no logic here needs to do date arithmetic, only
//! carry the value through.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Opaque identifiers
// ---------------------------------------------------------------------

/// Opaque device identifier (paired-device scope, PC-assigned once a
/// device is known — distinct from the Pi's own TLS identity fingerprint,
/// which lives on [`crate::device::Device::tls_fingerprint`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub String);

/// Opaque recording-session identifier. Matches
/// `publication-manifest.schema.json`'s `session_id`: `^[A-Za-z0-9_-]{1,128}$`,
/// never a filesystem path (ADR-PATH-001).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionId(pub String);

/// Opaque per-file identifier within a session. Matches the manifest's
/// `files[].id`: same `^[A-Za-z0-9_-]{1,128}$` shape as `session_id`. The
/// HTTP layer resolves this to a real file descriptor via an allowlist —
/// it is never joined onto a path directly (ADR-PATH-001), which is also
/// why `library::download`'s `derive_target_path` treats it as an opaque
/// path *segment*, not a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileId(pub String);

impl DeviceId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SessionId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FileId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------
// Publication manifest (mirrors publication-manifest.schema.json)
// ---------------------------------------------------------------------

/// A file's role within a recording session. Exact value set from
/// `publication-manifest.schema.json`'s `$defs.fileEntry.role` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    VideoLeft,
    VideoRight,
    VideoMono,
    VideoStereo,
    Imu,
    Metadata,
    Other,
}

/// One entry in [`PublicationManifest::files`]. Field names/shapes mirror
/// `publication-manifest.schema.json`'s `$defs.fileEntry` exactly so this
/// type can `serde_json::from_str` a real Pi response body unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub id: FileId,
    pub display_path: String,
    pub role: FileRole,
    pub size_bytes: u64,
    /// Lowercase hex-encoded SHA-256, exactly 64 characters (schema
    /// pattern `^[0-9a-f]{64}$`). Kept as a plain `String` here — parsing
    /// into raw bytes is a caller concern (see
    /// `library::object_store_port::SourceSha256` for that shape).
    pub sha256: String,
    pub media_type: String,
}

/// The Ed25519 publication signature block, mirroring
/// `publication-manifest.schema.json`'s `$defs.publicationSignature`.
/// `algorithm` is carried as a `String` (schema only pins it to the
/// constant `"ed25519"` for now; keeping it a string rather than a unit
/// enum avoids a hard-fail on a future signature-algorithm addition that
/// a minor protocol bump might introduce).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationSignature {
    pub algorithm: String,
    pub key_version: u32,
    /// `sha256:<64 lowercase hex>` fingerprint of the raw public key.
    pub public_key_fingerprint: String,
    /// Hex-encoded 64-byte Ed25519 signature (128 hex chars).
    pub signature: String,
}

/// Canonical durable publication manifest for one recording session,
/// mirroring `publication-manifest.schema.json` (schema major version 1)
/// field-for-field. See `tests::publication_manifest_matches_rp_ylx_fixture`
/// for a round-trip against the real RP-YLX fixture JSON.
///
/// Per the schema's `x-ylx-versioning` rule, a consumer MUST fail closed
/// (reject) on any `schema_version` it doesn't know and on any missing
/// required field for a known version, while ignoring unknown *additional*
/// properties for a known version. This type only captures the required
/// v1 fields; unknown additional properties are silently dropped by
/// `serde_json` deserialization (the "ignore unknown minor fields" half of
/// that rule). The "fail closed on unknown major version" half is a
/// caller-side check on `schema_version` before trusting the rest of the
/// manifest — deliberately not enforced inside `Deserialize` itself, so a
/// caller can still inspect `schema_version` on a manifest it is about to
/// reject (e.g. for logging/diagnostics) rather than getting an opaque
/// serde error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationManifest {
    pub schema_version: u32,
    pub session_id: SessionId,
    /// `sha256:<64 lowercase hex>` of the canonical file inventory.
    pub revision: String,
    /// UTC RFC 3339 timestamp.
    pub captured_at: String,
    /// UTC RFC 3339 timestamp.
    pub published_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    pub integrity_ok: bool,
    pub files: Vec<ManifestFileEntry>,
    pub publication_signature: PublicationSignature,
}

/// The only `schema_version` this type currently understands. See the
/// [`PublicationManifest`] doc comment for the fail-closed contract this
/// backs.
pub const PUBLICATION_MANIFEST_KNOWN_MAJOR_VERSIONS: &[u32] = &[1];

impl PublicationManifest {
    /// Whether `schema_version` is one this build knows how to trust. Per
    /// the schema's versioning rule, callers MUST reject (not guess at) a
    /// manifest where this returns `false`, even though the rest of the
    /// struct may have deserialized successfully.
    #[must_use]
    pub fn has_known_schema_version(&self) -> bool {
        PUBLICATION_MANIFEST_KNOWN_MAJOR_VERSIONS.contains(&self.schema_version)
    }
}

/// The publication unit a durable download job is allowed to make visible.
///
/// `JobSpec` keeps this bit as the versioned `full_session` column for
/// backwards-compatible SQLite storage. Exposing the two legal meanings as
/// an enum at the execution boundary prevents a selected-file job from being
/// accidentally routed through whole-directory replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PublicationScope {
    #[default]
    FullSession,
    SelectedFiles,
}

impl PublicationScope {
    #[must_use]
    pub fn is_full_session(self) -> bool {
        matches!(self, PublicationScope::FullSession)
    }
}

impl From<bool> for PublicationScope {
    fn from(full_session: bool) -> Self {
        if full_session {
            PublicationScope::FullSession
        } else {
            PublicationScope::SelectedFiles
        }
    }
}

// ---------------------------------------------------------------------
// Commit 21: JobIdentity / JobSpec — the durable request a TransferStore
// row is created from.
// ---------------------------------------------------------------------

/// Everything that can be wrong with a [`JobIdentity`], [`JobFileSpec`],
/// [`PublicationMaterial`] or [`JobSpec`] construction attempt.
///
/// Deliberately structured (not a `String`): the persistence layer turns
/// these into the diagnostic a `RecoveryBlocked` row or a rejected
/// `create_job` carries, and tests assert on the variant rather than on
/// message wording.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JobSpecError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },

    #[error("{field} must be 64 lowercase hex characters, got {value:?}")]
    NotSha256Hex { field: &'static str, value: String },

    #[error("{field} must be exactly {expected} bytes, got {actual}")]
    BadLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("the session inventory lists file {file_id:?} more than once")]
    DuplicateInventoryFile { file_id: String },

    #[error("the requested file plan lists file {file_id:?} more than once")]
    DuplicateRequestedFile { file_id: String },

    #[error("requested file {file_id:?} is not part of the signed session inventory")]
    RequestedFileNotInInventory { file_id: String },

    #[error(
        "publication revision {publication_revision:?} does not match the job identity revision \
         {identity_revision:?}"
    )]
    RevisionMismatch {
        identity_revision: String,
        publication_revision: String,
    },

    #[error(
        "a full-session job must request the complete inventory ({inventory} files), but only \
         {requested} were requested"
    )]
    IncompleteFullSession { inventory: usize, requested: usize },
}

/// The natural key of a transfer job: **(device, session, revision)**.
///
/// Fields are private and there is no `Deserialize`: an identity can only
/// come from [`JobIdentity::new`], which rejects empty components. That
/// makes "two jobs with the same natural key are the same logical
/// transfer" a property of the type rather than of every call site that
/// happens to format the three strings the same way.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct JobIdentity {
    device_id: DeviceId,
    session_id: SessionId,
    revision: String,
}

impl JobIdentity {
    /// The only way to build an identity. Every component must be
    /// non-empty — a blank device or session id would let two unrelated
    /// transfers collide on one natural key.
    pub fn new(
        device_id: DeviceId,
        session_id: SessionId,
        revision: impl Into<String>,
    ) -> Result<Self, JobSpecError> {
        let revision = revision.into();
        require_non_empty("device_id", device_id.as_str())?;
        require_non_empty("session_id", session_id.as_str())?;
        require_non_empty("revision", &revision)?;
        Ok(JobIdentity {
            device_id,
            session_id,
            revision,
        })
    }

    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Canonical, collision-free encoding of the natural key, suitable for
    /// a SQL `UNIQUE` column.
    ///
    /// Each component is length-prefixed rather than separator-joined, so
    /// a device id containing the separator cannot forge another job's
    /// key (`"a|b" + "c"` and `"a" + "b|c"` produce different strings
    /// here, unlike a naive `format!("{a}|{b}")`).
    #[must_use]
    pub fn natural_key(&self) -> String {
        let mut key = String::new();
        for part in [
            self.device_id.as_str(),
            self.session_id.as_str(),
            self.revision.as_str(),
        ] {
            key.push_str(&part.len().to_string());
            key.push(':');
            key.push_str(part);
        }
        key
    }
}

impl fmt::Display for JobIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}@{}",
            self.device_id.as_str(),
            self.session_id.as_str(),
            self.revision
        )
    }
}

/// One file of a job's plan, as signed by the Pi's publication manifest.
///
/// Fields are private so a caller cannot take a verified entry and swap
/// its `sha256` or `size_bytes` afterwards; the only way to change one is
/// to build a new value through the validating constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobFileSpec {
    file_id: FileId,
    display_path: String,
    size_bytes: u64,
    sha256: String,
}

impl JobFileSpec {
    /// `sha256` must be exactly 64 lowercase hex characters (the manifest
    /// schema's `^[0-9a-f]{64}$`). `display_path` is the signed
    /// session-relative path; it is never joined onto a filesystem path
    /// here (ADR-PATH-001) — that is the download engine's job.
    pub fn new(
        file_id: FileId,
        display_path: impl Into<String>,
        size_bytes: u64,
        sha256: impl Into<String>,
    ) -> Result<Self, JobSpecError> {
        let display_path = display_path.into();
        let sha256 = sha256.into();
        require_non_empty("file_id", file_id.as_str())?;
        require_non_empty("display_path", &display_path)?;
        require_sha256_hex("sha256", &sha256)?;
        Ok(JobFileSpec {
            file_id,
            display_path,
            size_bytes,
            sha256,
        })
    }

    #[must_use]
    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }

    #[must_use]
    pub fn display_path(&self) -> &str {
        &self.display_path
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// The raw, signed publication material a job's plan was derived from:
/// the exact bytes that were signed, the Ed25519 signature over them, and
/// the public key the pairing transcript confirmed.
///
/// This type does **not** verify the signature (that is `PublicationTrust`
/// in a later phase); it only guarantees the material is structurally
/// complete and internally consistent with the job's revision, so a
/// half-populated envelope can never be stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicationMaterial {
    revision: String,
    payload: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}

/// Length of a raw Ed25519 signature.
pub const PUBLICATION_SIGNATURE_LEN: usize = 64;
/// Length of a raw Ed25519 public key.
pub const PUBLICATION_PUBLIC_KEY_LEN: usize = 32;

impl PublicationMaterial {
    pub fn new(
        revision: impl Into<String>,
        payload: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<Self, JobSpecError> {
        let revision = revision.into();
        require_non_empty("publication.revision", &revision)?;
        if payload.is_empty() {
            return Err(JobSpecError::Empty {
                field: "publication.payload",
            });
        }
        require_len(
            "publication.signature",
            PUBLICATION_SIGNATURE_LEN,
            signature.len(),
        )?;
        require_len(
            "publication.public_key",
            PUBLICATION_PUBLIC_KEY_LEN,
            public_key.len(),
        )?;
        Ok(PublicationMaterial {
            revision,
            payload,
            signature,
            public_key,
        })
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// A complete, self-consistent description of one logical transfer:
/// identity, the signed session inventory, which of those files this job
/// actually transfers, and the publication material the plan came from.
///
/// **There is no piecemeal assembly path.** [`JobSpec::new`] is the only
/// constructor, it takes the file plan and the publication material
/// together, and it rejects any combination that would let a caller pair
/// a legitimate signature with a file list it does not cover. Nothing is
/// `pub` and there is no `Deserialize`, so a spec read back out of the
/// database has to go through the same validation as one built in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobSpec {
    identity: JobIdentity,
    publication: PublicationMaterial,
    /// The complete signed inventory, in manifest order.
    session_files: Vec<JobFileSpec>,
    /// Indices into `session_files`, in request order. Storing indices
    /// rather than a second copy of the file entries is what makes
    /// "a requested file always has the signed size/hash" unrepresentable
    /// otherwise.
    requested: Vec<usize>,
    full_session: bool,
    date_label: String,
}

impl JobSpec {
    /// Build a complete spec.
    ///
    /// `requested_file_ids` selects the transferred subset *out of*
    /// `session_files`; every id must be present in the inventory, so a
    /// requested file physically cannot carry a size/hash that differs
    /// from the signed one. Pass every inventory id (and `full_session =
    /// true`) for a whole-session job.
    ///
    /// `date_label` is a cosmetic display hint only. It is deliberately
    /// **not** part of [`JobSpec::request_digest`] — two enqueues of the
    /// same transfer that disagree only about a display label are the
    /// same request, not a conflict.
    pub fn new(
        identity: JobIdentity,
        publication: PublicationMaterial,
        session_files: Vec<JobFileSpec>,
        requested_file_ids: &[FileId],
        full_session: bool,
        date_label: impl Into<String>,
    ) -> Result<Self, JobSpecError> {
        if publication.revision() != identity.revision() {
            return Err(JobSpecError::RevisionMismatch {
                identity_revision: identity.revision().to_string(),
                publication_revision: publication.revision().to_string(),
            });
        }
        if session_files.is_empty() {
            return Err(JobSpecError::Empty {
                field: "session_files",
            });
        }
        if requested_file_ids.is_empty() {
            return Err(JobSpecError::Empty {
                field: "requested_file_ids",
            });
        }

        let mut index_of: Vec<(&str, usize)> = Vec::with_capacity(session_files.len());
        for (position, file) in session_files.iter().enumerate() {
            let id = file.file_id().as_str();
            if index_of.iter().any(|(seen, _)| *seen == id) {
                return Err(JobSpecError::DuplicateInventoryFile {
                    file_id: id.to_string(),
                });
            }
            index_of.push((id, position));
        }

        let mut requested = Vec::with_capacity(requested_file_ids.len());
        for id in requested_file_ids {
            let Some((_, position)) = index_of.iter().find(|(seen, _)| *seen == id.as_str()) else {
                return Err(JobSpecError::RequestedFileNotInInventory {
                    file_id: id.0.clone(),
                });
            };
            if requested.contains(position) {
                return Err(JobSpecError::DuplicateRequestedFile {
                    file_id: id.0.clone(),
                });
            }
            requested.push(*position);
        }

        if full_session && requested.len() != session_files.len() {
            return Err(JobSpecError::IncompleteFullSession {
                inventory: session_files.len(),
                requested: requested.len(),
            });
        }

        Ok(JobSpec {
            identity,
            publication,
            session_files,
            requested,
            full_session,
            date_label: date_label.into(),
        })
    }

    #[must_use]
    pub fn identity(&self) -> &JobIdentity {
        &self.identity
    }

    #[must_use]
    pub fn publication(&self) -> &PublicationMaterial {
        &self.publication
    }

    /// The complete signed inventory, in manifest order.
    #[must_use]
    pub fn session_files(&self) -> &[JobFileSpec] {
        &self.session_files
    }

    /// The ordered file plan this job actually transfers.
    pub fn requested_files(&self) -> impl Iterator<Item = &JobFileSpec> {
        self.requested.iter().map(|i| &self.session_files[*i])
    }

    /// Position of `file_id` in the request order, if it is requested.
    #[must_use]
    pub fn request_position(&self, file_id: &FileId) -> Option<usize> {
        self.requested
            .iter()
            .position(|i| self.session_files[*i].file_id() == file_id)
    }

    #[must_use]
    pub fn full_session(&self) -> bool {
        self.full_session
    }

    /// The execution-level scope represented by the durable `full_session`
    /// bit. This is intentionally derived rather than stored a second time,
    /// so recovery cannot observe two independent scope authorities.
    #[must_use]
    pub fn publication_scope(&self) -> PublicationScope {
        PublicationScope::from(self.full_session)
    }

    #[must_use]
    pub fn date_label(&self) -> &str {
        &self.date_label
    }

    /// Stable content digest of the *request* this spec represents.
    ///
    /// Two specs digest equal iff they ask for the same bytes under the
    /// same signed publication. Every field is length-prefixed before
    /// hashing so no rearrangement of adjacent strings can produce the
    /// same preimage. `date_label` is excluded on purpose — see
    /// [`JobSpec::new`].
    #[must_use]
    pub fn request_digest(&self) -> RequestDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"ylx.job-spec.v1\0");

        // Length-prefixed framing, so concatenation stays injective.
        let absorb = |hasher: &mut Sha256, bytes: &[u8]| {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };

        absorb(&mut hasher, self.identity.device_id.as_str().as_bytes());
        absorb(&mut hasher, self.identity.session_id.as_str().as_bytes());
        absorb(&mut hasher, self.identity.revision.as_bytes());
        absorb(&mut hasher, self.publication.revision.as_bytes());
        absorb(&mut hasher, &self.publication.payload);
        absorb(&mut hasher, &self.publication.signature);
        absorb(&mut hasher, &self.publication.public_key);
        hasher.update([u8::from(self.full_session)]);

        hasher.update((self.session_files.len() as u64).to_be_bytes());
        for file in &self.session_files {
            absorb(&mut hasher, file.file_id.as_str().as_bytes());
            absorb(&mut hasher, file.display_path.as_bytes());
            hasher.update(file.size_bytes.to_be_bytes());
            absorb(&mut hasher, file.sha256.as_bytes());
        }

        hasher.update((self.requested.len() as u64).to_be_bytes());
        for index in &self.requested {
            absorb(
                &mut hasher,
                self.session_files[*index].file_id.as_str().as_bytes(),
            );
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hasher.finalize());
        RequestDigest(digest)
    }
}

/// SHA-256 digest of a [`JobSpec`]'s request content. Opaque on purpose:
/// the only supported operations are equality, hex round-tripping and
/// display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    pub fn from_hex(value: &str) -> Result<Self, JobSpecError> {
        require_sha256_hex("request_digest", value)?;
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| {
                JobSpecError::NotSha256Hex {
                    field: "request_digest",
                    value: value.to_string(),
                }
            })?;
        }
        Ok(RequestDigest(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), JobSpecError> {
    if value.trim().is_empty() {
        return Err(JobSpecError::Empty { field });
    }
    Ok(())
}

fn require_sha256_hex(field: &'static str, value: &str) -> Result<(), JobSpecError> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ok {
        Ok(())
    } else {
        Err(JobSpecError::NotSha256Hex {
            field,
            value: value.to_string(),
        })
    }
}

fn require_len(field: &'static str, expected: usize, actual: usize) -> Result<(), JobSpecError> {
    if expected == actual {
        Ok(())
    } else {
        Err(JobSpecError::BadLength {
            field,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim copy of
    /// `capture/docs/transfer-api/v1/fixtures/success/publication-manifest.json`
    /// from the RP-YLX repo (the canonical source per plan section 10.2) —
    /// proves this type deserializes a real Pi-produced manifest, not just
    /// a hand-rolled one that happens to match our own field names.
    const RP_YLX_FIXTURE: &str = r#"{
      "schema_version": 1,
      "session_id": "sess-0001",
      "revision": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "captured_at": "2026-08-01T04:00:00Z",
      "published_at": "2026-08-01T04:10:00Z",
      "duration_seconds": 121.4,
      "total_bytes": 483921234,
      "video_bytes": 483920112,
      "integrity_ok": true,
      "files": [
        {
          "id": "f-0001",
          "display_path": "video/left_00000.mp4",
          "role": "video_left",
          "size_bytes": 483920112,
          "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "media_type": "video/mp4"
        },
        {
          "id": "f-0002",
          "display_path": "session.json",
          "role": "metadata",
          "size_bytes": 1122,
          "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "media_type": "application/json"
        }
      ],
      "publication_signature": {
        "algorithm": "ed25519",
        "key_version": 1,
        "public_key_fingerprint": "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
        "signature": "65c2242b0035b99a0759ae2b97b97c5ade42184275b5c0b6211d389e181774606d2afbb58651b735becace3271f198d4122218a9d74af786eae4a7cbb7d62506"
      }
    }"#;

    #[test]
    fn publication_manifest_matches_rp_ylx_fixture() {
        let manifest: PublicationManifest =
            serde_json::from_str(RP_YLX_FIXTURE).expect("real Pi fixture deserializes");

        assert_eq!(manifest.schema_version, 1);
        assert!(manifest.has_known_schema_version());
        assert_eq!(manifest.session_id, SessionId("sess-0001".to_string()));
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[0].id, FileId("f-0001".to_string()));
        assert_eq!(manifest.files[0].role, FileRole::VideoLeft);
        assert_eq!(manifest.files[1].role, FileRole::Metadata);
        assert_eq!(manifest.publication_signature.algorithm, "ed25519");
    }

    #[test]
    fn publication_manifest_round_trips_through_json() {
        let manifest: PublicationManifest =
            serde_json::from_str(RP_YLX_FIXTURE).expect("fixture deserializes");
        let json = serde_json::to_string(&manifest).expect("manifest serializes");
        let round_tripped: PublicationManifest =
            serde_json::from_str(&json).expect("re-deserializes");
        assert_eq!(manifest, round_tripped);
    }

    #[test]
    fn unknown_major_schema_version_is_flagged_for_fail_closed_rejection() {
        let mut manifest: PublicationManifest =
            serde_json::from_str(RP_YLX_FIXTURE).expect("fixture deserializes");
        manifest.schema_version = 2;
        assert!(
            !manifest.has_known_schema_version(),
            "callers must reject an unknown major version rather than guessing"
        );
    }

    #[test]
    fn publication_scope_is_derived_without_guessing_from_requested_file_count() {
        assert_eq!(PublicationScope::from(true), PublicationScope::FullSession);
        assert_eq!(
            PublicationScope::from(false),
            PublicationScope::SelectedFiles
        );
        assert!(PublicationScope::FullSession.is_full_session());
        assert!(!PublicationScope::SelectedFiles.is_full_session());
        assert_eq!(PublicationScope::default(), PublicationScope::FullSession);
    }

    #[test]
    fn file_role_serializes_to_wire_snake_case_values() {
        // Exact set from publication-manifest.schema.json's role enum.
        let roles = [
            (FileRole::VideoLeft, "\"video_left\""),
            (FileRole::VideoRight, "\"video_right\""),
            (FileRole::VideoMono, "\"video_mono\""),
            (FileRole::VideoStereo, "\"video_stereo\""),
            (FileRole::Imu, "\"imu\""),
            (FileRole::Metadata, "\"metadata\""),
            (FileRole::Other, "\"other\""),
        ];
        for (role, expected_json) in roles {
            assert_eq!(serde_json::to_string(&role).unwrap(), expected_json);
        }
    }

    #[test]
    fn device_session_file_id_newtypes_round_trip_through_json_as_plain_strings() {
        let id = DeviceId("dev-123".to_string());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"dev-123\"");
        let back: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
