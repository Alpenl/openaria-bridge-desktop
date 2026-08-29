//! Shared data types for the YLX Transfer backend.
//!
//! These wire DTOs are mirrored by the frontend's `src/types.ts`. Field names
//! are serialized as camelCase so TypeScript can consume them without
//! translation.

use serde::{Deserialize, Deserializer, Serialize};
use ylx_transfer_core::device::StoredDeviceIdentity;
use ylx_transfer_core::domain::DeviceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    Connected,
    Idle,
    Offline,
    Pending,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub display_id: String,
    pub ip: Option<String>,
    pub state: DeviceState,
    pub last_seen: Option<String>,
}

/// One file in a published session.
///
/// `file_id` is the opaque identifier accepted by the Pi download endpoint.
/// `display_path` is the signed, session-relative Pi path used for the local
/// directory and filename only after `library::download` validates every
/// component; it is never substituted into a Pi API request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionFile {
    pub file_id: String,
    pub display_path: String,
    pub bytes: u64,
    /// SHA-256 from the authenticated, signature-verified publication.
    /// Legacy entries deserialize as empty and therefore fail closed when
    /// checked for completeness or uploaded.
    #[serde(default)]
    pub sha256: String,
}

impl SessionFile {
    pub fn new(file_id: String, display_path: String, bytes: u64, sha256: String) -> Self {
        let display_path = if display_path.is_empty() {
            file_id.clone()
        } else {
            display_path
        };
        SessionFile {
            file_id,
            display_path,
            bytes,
            sha256: sha256.to_ascii_lowercase(),
        }
    }
}

impl<'de> Deserialize<'de> for SessionFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SessionFileWire {
            /// `path` is the pre-real-data store.json field.  It contained
            /// the opaque file id, despite its ambiguous name.
            #[serde(default, alias = "path")]
            file_id: String,
            #[serde(default)]
            display_path: String,
            bytes: u64,
            #[serde(default)]
            sha256: String,
        }

        let wire = SessionFileWire::deserialize(deserializer)?;
        Ok(SessionFile::new(
            wire.file_id,
            wire.display_path,
            wire.bytes,
            wire.sha256,
        ))
    }
}

/// A completed recording session in the desktop/frontend view contract.
/// Current Device API v4 and retained legacy v1 wire shapes are normalized
/// before this struct is constructed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub revision: String,
    pub date_label: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    /// The current Pi publication protocol does not expose a sample count.
    /// `None` is therefore the honest production value; demo data may carry
    /// `Some(..)` without making a real response look like a measured zero.
    pub imu_samples: Option<u64>,
    pub files: Vec<SessionFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadStatus {
    None,
    Downloading,
    Done,
    Failed,
}

/// `Session` plus the two bits of derived state the frontend needs per row
/// (download progress, whether it's already safely in object storage) —
/// returned by `list_sessions` and the `sessions:update` event so the
/// frontend never has to make N+1 status queries per row.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    #[serde(flatten)]
    pub session: Session,
    pub download_status: DownloadStatus,
    pub backed_up: bool,
    /// Gateway evidence for the exact Device API v4 manifest revision.
    /// `None` is an explicit missing verdict, not an optimistic default.
    pub verification: Option<SessionVerificationView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionVerificationVerdict {
    Usable,
    Unusable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionVerificationValidatorView {
    pub name: String,
    pub version: String,
    pub build_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionVerificationDiagnosticCode {
    ArtifactDigestMismatch,
    ArtifactInvalid,
    ManifestInvalid,
    VerificationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SessionVerificationDiagnosticView {
    LegacyMessage(String),
    Structured {
        code: SessionVerificationDiagnosticCode,
        summary: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionVerificationView {
    pub verdict: SessionVerificationVerdict,
    pub actor: String,
    pub validator: SessionVerificationValidatorView,
    pub manifest_sha256: String,
    pub verified_at: String,
    pub diagnostics: Vec<SessionVerificationDiagnosticView>,
    /// Adapter-validated state used only by the trusted backend. It is
    /// deliberately absent from the wire so a WebView cannot present an
    /// eligibility boolean as authorization.
    #[serde(skip)]
    pub(crate) manifest_digest_valid: bool,
}

impl SessionVerificationView {
    #[must_use]
    pub(crate) fn permits_detail_for(&self, revision: &str) -> bool {
        self.verdict == SessionVerificationVerdict::Usable
            && self.manifest_digest_valid
            && revision == format!("sha256:{}", self.manifest_sha256)
    }
}

/// One bounded page of the device session catalog.
///
/// `next_cursor` is an opaque transport token. Callers must return it
/// unchanged together with `catalog_revision`; decoding it as an offset would
/// make pagination depend on one particular device implementation. When
/// `catalog_authority` is unavailable, `catalog_revision` and `next_cursor`
/// are both absent. Local UI request generations are deliberately separate
/// from this device-owned identity. Session detail remains absent from
/// summary-only rows until an explicit detail RPC.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPageView {
    pub items: Vec<SessionView>,
    pub diagnostics: Vec<SessionDiscoveryDiagnosticView>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub catalog_revision: Option<String>,
    pub catalog_authority: SessionCatalogAuthority,
    pub pagination_supported: bool,
    pub pagination_unavailable_reason: Option<SessionPaginationUnavailableReason>,
    pub capabilities: SessionPageCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDiscoveryDiagnosticCode {
    ManifestUnreadable,
    UnsupportedSchema,
    ManifestInvalid,
    ManifestNotSealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDiscoveryDiagnosticView {
    pub quarantine_id: String,
    pub code: SessionDiscoveryDiagnosticCode,
    pub observed_at: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionCatalogAuthority {
    /// The device promises one immutable catalog revision across all cursors.
    DeviceSnapshot,
    /// The response has no authority that can fence two different pages.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionPaginationUnavailableReason {
    /// The endpoint can show a first page but cannot prove snapshot-consistent
    /// traversal. Current Device API v2 falls into this compatibility mode.
    CatalogRevisionUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionCapabilitySource {
    DeviceDescriptor,
    ProfileContract,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionApiProfile {
    LegacyPinnedTlsV1,
    LabHttpV4,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCapability {
    pub supported: bool,
    pub source: SessionCapabilitySource,
}

impl SessionCapability {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            supported: false,
            source: SessionCapabilitySource::Unavailable,
        }
    }
}

/// Explicit command/query capabilities attached to a catalog page. Keeping
/// the evidence source beside every boolean prevents the UI from turning an
/// absent descriptor or an empty artifact list into an optimistic guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPageCapabilities {
    pub profile: SessionApiProfile,
    pub session_deletion: SessionCapability,
    pub session_detail: SessionCapability,
    pub artifact_download: SessionCapability,
    pub capture_status: SessionCapability,
}

impl Default for SessionPageCapabilities {
    fn default() -> Self {
        Self {
            profile: SessionApiProfile::Unknown,
            session_deletion: SessionCapability::unavailable(),
            session_detail: SessionCapability::unavailable(),
            artifact_download: SessionCapability::unavailable(),
            capture_status: SessionCapability::unavailable(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadStatus {
    None,
    Uploading,
    Done,
    Failed,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// A session that has been downloaded to local disk. It lives independently
/// of the source device and must keep working if that device is later deleted
/// or offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryEntry {
    pub device_id: String,
    pub session_id: String,
    pub date_label: String,
    pub downloaded_at: String,
    pub bytes: u64,
    /// User-facing, locally derived files produced after a complete session
    /// download. These are deliberately separate from `files`: uploads,
    /// backup proofs, and Pi-cleanup eligibility continue to use the original
    /// signed session inventory, while the library view can show the playable
    /// preprocessed result first.
    #[serde(default)]
    pub processed_files: Vec<SessionFile>,
    pub files: Vec<SessionFile>,
    /// Whether `files` covers the complete immutable Pi session inventory.
    /// Legacy entries have no signed revision/hash evidence, so absence of
    /// this field migrates to `false` and cannot authorize upload/deletion.
    #[serde(default)]
    pub complete: bool,
    /// Monotonic `transfer_completion_outbox.sequence` of the newest
    /// successful full-session projection committed into this row. It is
    /// persisted with the row but intentionally omitted from `LibraryView`;
    /// completion replay uses it to prevent an older attempt from rolling
    /// back newer files, publication evidence, timestamps, or completion state.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) download_projection_sequence: u64,
    /// Signed publication material accepted by the download coordinator.
    /// A legacy entry without this evidence cannot be uploaded or treated
    /// as a complete immutable revision.
    #[serde(default)]
    pub publication: Option<PublicationEvidence>,
    /// The library root these files were actually written under.
    ///
    /// The configured root can move — a user reconfiguration, or the startup
    /// fallback when a configured directory is briefly unusable — and a row
    /// that only knew today's root would report its own bytes missing while
    /// they sat on disk under yesterday's. Absent on rows written before this
    /// was recorded, which resolve against the current root exactly as before.
    #[serde(default)]
    pub library_root: Option<String>,
    /// HEAD-verified evidence for every uploaded data/evidence object.
    #[serde(default)]
    pub object_receipts: Vec<ObjectVerificationReceipt>,
    /// Internal idempotency evidence for the last durable upload projection.
    /// This never crosses the `LibraryView`/RPC boundary.
    #[serde(default)]
    pub(crate) upload_projection: Option<UploadProjectionMarker>,
    pub upload_status: UploadStatus,
    /// Whether the exact terminal upload outcome authorizes a fresh retry.
    /// This is durable typed state, not text inferred from `upload_error`.
    #[serde(default)]
    pub upload_retryable: bool,
    pub uploaded_at: Option<String>,
    pub upload_error: Option<String>,
}

/// Exact durable identity of one staged upload receipt. The public library
/// receipt intentionally remains compact; this marker retains role/proof so
/// an outbox replay can distinguish the same projection from a coincidental
/// matching status or object key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UploadProjectionReceipt {
    pub object_key: String,
    pub role: String,
    pub etag: String,
    pub version_id: Option<String>,
    pub size_bytes: u64,
    pub source_sha256: String,
    pub digest_proof: String,
}

/// Persisted idempotency marker for one upload completion projection.
/// `outcome_code` is the exact durable terminal tag (`succeeded`/`cancelled`
/// or `failed:<code>`), and `outcome_retryable` preserves the failed outcome
/// payload without exposing it through the frontend library view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UploadProjectionMarker {
    pub job_id: String,
    /// Immutable library identity and destination namespace proved by the
    /// durable upload spec when this marker was written. Missing values from
    /// pre-marker legacy rows fail closed in backed-up projections.
    #[serde(default)]
    pub entry_key: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub object_prefix: Option<String>,
    pub outcome_code: String,
    pub outcome_retryable: Option<bool>,
    pub receipts: Vec<UploadProjectionReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationEvidence {
    pub revision: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectVerificationReceipt {
    pub key: String,
    pub etag: String,
    pub version_id: Option<String>,
    pub bytes: u64,
    pub sha256: String,
}

impl LibraryEntry {
    pub fn key(&self) -> String {
        format!("{}|{}", self.device_id, self.session_id)
    }

    pub fn display_files(&self) -> &[SessionFile] {
        if self.processed_files.is_empty() {
            &self.files
        } else {
            &self.processed_files
        }
    }

    pub fn display_bytes(&self) -> u64 {
        if self.processed_files.is_empty() {
            self.bytes
        } else {
            self.processed_files
                .iter()
                .fold(0_u64, |total, file| total.saturating_add(file.bytes))
        }
    }

    /// The persistence record is intentionally richer than the RPC view.
    /// Publication bytes, signatures, public keys, and object-store receipts
    /// are backend evidence used to authorize future work; they are not UI
    /// data and must not cross the Tauri/WebView boundary.
    pub fn view(&self) -> LibraryView {
        let device_display_id = StoredDeviceIdentity::parse(&DeviceId(self.device_id.clone()))
            .map(|identity| identity.display_id().to_string())
            // This field is required on the wire. Preserve malformed
            // evidence so the strict RPC decoder rejects the snapshot;
            // never invent a valid-looking identity or panic here.
            .unwrap_or_else(|_| self.device_id.clone());
        LibraryView {
            // RPC actions address the durable `device_id|session_id` key.
            // Preserve that identity byte-for-byte; display normalization
            // must never manufacture a different operational key.
            device_id: self.device_id.clone(),
            device_display_id,
            session_id: self.session_id.clone(),
            date_label: self.date_label.clone(),
            downloaded_at: self.downloaded_at.clone(),
            bytes: self.display_bytes(),
            files: self.display_files().to_vec(),
            complete: self.complete,
            upload_status: self.upload_status,
            upload_retryable: self.upload_retryable,
            uploaded_at: self.uploaded_at.clone(),
            upload_error: self.upload_error.clone(),
        }
    }
}

/// Safe outward projection of a durable [`LibraryEntry`]. Keep this shape
/// deliberately independent from the persistence row so adding evidence to
/// the backend cannot accidentally expose it through an RPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryView {
    pub device_id: String,
    pub device_display_id: String,
    pub session_id: String,
    pub date_label: String,
    pub downloaded_at: String,
    pub bytes: u64,
    pub files: Vec<SessionFile>,
    pub complete: bool,
    pub upload_status: UploadStatus,
    pub upload_retryable: bool,
    pub uploaded_at: Option<String>,
    pub upload_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Down,
    Up,
}

/// Durable transfer lifecycle projected to the RPC boundary.  The previous
/// four booleans allowed impossible combinations (`done && failed`, or a
/// queued job that was also running); one tagged state is the only authority
/// now. Progress and the optional error remain orthogonal read-only fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Queued,
    Preparing,
    /// A terminal upload outcome is durable but its completion projection has
    /// not been acknowledged yet. This state is visible for recovery and is
    /// never cancellable as active work.
    Finalizing,
    Running,
    Paused,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl TransferState {
    #[must_use]
    #[cfg(test)]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Finalizing | Self::Failed | Self::Cancelled
        )
    }
}

/// Outward-facing transfer DTO — this is what the frontend sees, over both
/// commands and the `transfers:update` event. Never deserialized (the
/// frontend never constructs one), so it doesn't need `Deserialize`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
    pub key: String,
    pub label: String,
    pub total_bytes: u64,
    pub sent_bytes: u64,
    pub state: TransferState,
    pub error: Option<String>,
    /// True only when the durable failed outcome explicitly authorizes a
    /// retry. Success, cancellation, active work, and non-retryable failures
    /// stay false; callers must not infer this from the error text.
    pub retryable: bool,
    pub direction: TransferDirection,
    pub target_label: String,
}

/// Which addressing form the S3-compatible endpoint requires. This is not
/// cosmetic and cannot be guessed from the endpoint alone: Aliyun OSS
/// rejects path-style outright, *before* any signature check
/// (`SecondLevelDomainForbidden: "Please use virtual hosted style to
/// access."` — verified against the live endpoint by
/// `ylx-transfer-adapters/tests/oss_real_integration.rs`), while MinIO and
/// most self-hosted servers only work path-style.
///
/// The `Default` here is the *fresh install* answer (matching the shipped
/// default endpoint, which is OSS). It is deliberately NOT what a
/// `StorageConfig` missing the field deserializes to — see that field's
/// own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum StorageUrlStyle {
    #[default]
    VirtualHost,
    Path,
}

/// PC-06 security fix: this struct is what actually gets serialized into
/// `PersistedStore`/`store.json` (see `state.rs`'s `AppData::persist`) --
/// it deliberately has NO `access_key`/`secret_key` fields anymore. Those
/// were previously plain `String` fields here, which meant every save
/// wrote raw S3 credentials straight into the app's on-disk JSON store in
/// plaintext -- exactly the anti-pattern enforced by
/// `ylx-transfer-adapters::credential_keyring`. The real secret
/// now lives only in the OS credential vault (`Composition::vault`,
/// `composition.rs`), addressed by a single fixed `CredentialKey` --
/// never on this struct, never in `PersistedStore`. See `commands.rs`'s
/// `get_storage_config`/`save_storage_config` and `StorageConfigView`/
/// `SaveStorageConfigInput` below for the write-only/status-only shapes
/// the frontend actually talks to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageConfig {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    /// See [`StorageUrlStyle`]. Deliberately defaults to *`Path`* on
    /// deserialization rather than to the type's own `VirtualHost`
    /// default: every store written before this field existed was signed
    /// with the then-hardcoded `UrlStyle::Path`, so a missing field means
    /// "an old path-style store" (very likely a local MinIO), and silently
    /// promoting those to virtual-host would break a working setup on
    /// upgrade. New stores always serialize the field explicitly, so this
    /// fallback only ever applies to genuinely pre-existing ones -- while
    /// `StorageConfig::default()` (fresh installs) still gets
    /// `VirtualHost` to match the shipped default endpoint.
    #[serde(default = "legacy_url_style")]
    pub url_style: StorageUrlStyle,
    /// Where verified downloads are written (`composition`'s
    /// `library_root`). `None` -- and every persisted blob written before
    /// this field existed, hence `serde(default)` -- means "use the
    /// platform app-data default". Only ever an absolute path: the
    /// validation lives in `commands::save_storage_config`, and
    /// `state::BootConfig::download_root` re-checks it at startup so a
    /// hand-edited store can never relocate the library to a relative
    /// path resolved against the process's working directory.
    #[serde(default)]
    pub download_root: Option<String>,
}

/// The addressing style every pre-`url_style` store was implicitly using.
/// See the field's own doc comment for why this is not the type default.
fn legacy_url_style() -> StorageUrlStyle {
    StorageUrlStyle::Path
}

/// Ships a working object-store target so a fresh install is not staring
/// at four empty fields. Only non-secret coordinates are defaulted: the
/// AK/SK still have to be entered once in the settings dialog and go
/// straight to the OS credential vault, never here and never to disk
/// (ADR-CRED-001). `is_configured` deliberately does not consider the
/// credential — see its own doc comment.
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_STORAGE_ENDPOINT.to_string(),
            bucket: DEFAULT_STORAGE_BUCKET.to_string(),
            prefix: String::new(),
            url_style: StorageUrlStyle::VirtualHost,
            download_root: None,
        }
    }
}

/// Aliyun OSS, cn-beijing. Region is deliberately absent from
/// `StorageConfig`: OSS ignores the SigV4 credential-scope region
/// entirely (`cn-beijing`, `us-east-1` and `oss-cn-beijing` all
/// authenticate against the live endpoint), so `composition.rs`'s
/// app-wide constant is sufficient and the settings form stays at
/// endpoint/bucket/prefix/style.
pub const DEFAULT_STORAGE_ENDPOINT: &str = "https://oss-cn-beijing.aliyuncs.com";
/// Private-ACL bucket dedicated to recordings, kept separate from any
/// other workload in the same account.
pub const DEFAULT_STORAGE_BUCKET: &str = "ylx-recordings";

impl StorageConfig {
    /// Whether the *coordinates* are filled in. Says nothing about
    /// whether a credential exists — that lives in the OS keyring and is
    /// reported separately by `storage_secret_status`. Callers that need
    /// both (e.g. the upload path) check the vault themselves.
    pub fn is_configured(&self) -> bool {
        !self.endpoint.trim().is_empty() && !self.bucket.trim().is_empty()
    }
}

/// Outward-facing DTO for `get_storage_config` -- endpoint/bucket/prefix
/// plus a `secret_configured` existence flag, never the raw secret (per
/// `CredentialVaultPort::status`'s own "existence-only" contract, which
/// this mirrors at the Tauri command boundary). Never `Deserialize`: the
/// frontend never constructs one, only receives it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageConfigView {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    pub url_style: StorageUrlStyle,
    /// The configured download directory, or `""` when the platform
    /// app-data default is in use. Flattening `Option<String>` to a plain
    /// string here keeps the frontend form (which can only ever hold a
    /// string) from having to distinguish `null` from `""`.
    pub download_root: String,
    /// The directory used by the currently running transfer coordinator
    /// for new downloads.
    pub active_download_root: String,
    pub secret_configured: bool,
}

/// Inbound DTO for `save_storage_config`. `access_key`/`secret_key` are
/// write-only: forwarded straight to the credential vault by
/// `commands::save_storage_config` and never stored on `AppData::storage`
/// or persisted to disk. An empty string for either means "leave the
/// vault's existing secret untouched" -- so saving an unrelated field
/// (e.g. `prefix`) doesn't force re-entering credentials every time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveStorageConfigInput {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    /// `serde(default)` for the same reason as the other optional fields
    /// here: `test_storage_connection` reuses this DTO and older frontend
    /// bundles may not send the field at all.
    #[serde(default)]
    pub url_style: StorageUrlStyle,
    /// Absolute download directory, or `""` for "keep the default".
    /// `serde(default)` so `test_storage_connection` -- which reuses this
    /// DTO purely for endpoint/bucket/prefix/credentials -- keeps working
    /// whether or not the caller bothers to send the field.
    #[serde(default)]
    pub download_root: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
}

/// What gets persisted to disk between launches (see `state.rs`). Discovered
/// devices, their sessions, download state, and in-flight transfers are all
/// ephemeral — they're rebuilt each launch from (eventually) real mDNS/HTTP
/// calls, so they are intentionally not part of this struct.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PersistedStore {
    pub library: Vec<LibraryEntry>,
    pub storage: StorageConfig,
}

#[cfg(test)]
mod tests {
    use super::{
        Device, DeviceState, LibraryEntry, ObjectVerificationReceipt, PublicationEvidence,
        SessionApiProfile, SessionCapability, SessionCapabilitySource, SessionCatalogAuthority,
        SessionDiscoveryDiagnosticCode, SessionDiscoveryDiagnosticView, SessionFile,
        SessionPageCapabilities, SessionPageView, SessionVerificationDiagnosticCode,
        SessionVerificationDiagnosticView, SessionVerificationValidatorView,
        SessionVerificationVerdict, SessionVerificationView, StorageConfig, StorageUrlStyle,
        Transfer, TransferDirection, TransferState, UploadStatus,
    };

    const RPC_FIXTURE: &str = include_str!("../../fixtures/rpc/application_contract.json");

    fn empty_library_entry(device_id: &str) -> LibraryEntry {
        LibraryEntry {
            device_id: device_id.to_string(),
            session_id: "session-legacy".to_string(),
            date_label: "2026-08-03".to_string(),
            downloaded_at: "just now".to_string(),
            bytes: 0,
            processed_files: Vec::new(),
            files: Vec::new(),
            complete: false,
            download_projection_sequence: 0,
            publication: None,
            library_root: None,
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: UploadStatus::None,
            upload_retryable: false,
            uploaded_at: None,
            upload_error: None,
        }
    }

    #[test]
    fn storage_config_written_before_download_root_existed_still_loads() {
        let config: StorageConfig =
            serde_json::from_str(r#"{"endpoint":"https://s3.example","bucket":"b","prefix":"p"}"#)
                .unwrap();
        assert_eq!(config.download_root, None);
    }

    #[test]
    fn session_page_capabilities_serialize_with_explicit_profile_and_sources() {
        let page = SessionPageView {
            items: Vec::new(),
            diagnostics: Vec::new(),
            next_cursor: Some("opaque/cursor==".to_string()),
            has_more: true,
            catalog_revision: Some(format!("sha256:{}", "a".repeat(64))),
            catalog_authority: SessionCatalogAuthority::DeviceSnapshot,
            pagination_supported: true,
            pagination_unavailable_reason: None,
            capabilities: SessionPageCapabilities {
                profile: SessionApiProfile::LabHttpV4,
                session_deletion: SessionCapability {
                    supported: false,
                    source: SessionCapabilitySource::ProfileContract,
                },
                session_detail: SessionCapability {
                    supported: true,
                    source: SessionCapabilitySource::ProfileContract,
                },
                artifact_download: SessionCapability {
                    supported: true,
                    source: SessionCapabilitySource::DeviceDescriptor,
                },
                capture_status: SessionCapability {
                    supported: true,
                    source: SessionCapabilitySource::ProfileContract,
                },
            },
        };

        let value = serde_json::to_value(page).unwrap();
        assert_eq!(value["nextCursor"], "opaque/cursor==");
        assert_eq!(value["hasMore"], true);
        assert_eq!(value["catalogAuthority"], "deviceSnapshot");
        assert_eq!(value["paginationSupported"], true);
        assert_eq!(
            value["paginationUnavailableReason"],
            serde_json::Value::Null
        );
        assert_eq!(value["capabilities"]["profile"], "labHttpV4");
        assert_eq!(
            value["capabilities"]["sessionDeletion"]["source"],
            "profileContract"
        );
        assert_eq!(
            value["capabilities"]["artifactDownload"]["source"],
            "deviceDescriptor"
        );
    }

    #[test]
    fn session_verification_and_quarantine_diagnostics_keep_the_exact_wire_shape() {
        let verification = SessionVerificationView {
            verdict: SessionVerificationVerdict::Unusable,
            actor: "gateway".to_string(),
            validator: SessionVerificationValidatorView {
                name: "manifest-validator".to_string(),
                version: "2.1.0".to_string(),
                build_sha256: "b".repeat(64),
            },
            manifest_sha256: "not-a-valid-digest".to_string(),
            verified_at: "2026-08-29T12:34:56Z".to_string(),
            diagnostics: vec![SessionVerificationDiagnosticView::Structured {
                code: SessionVerificationDiagnosticCode::ManifestInvalid,
                summary: "manifest failed closed validation".to_string(),
            }],
            manifest_digest_valid: false,
        };
        let value = serde_json::to_value(verification).unwrap();
        assert_eq!(value["verdict"], "unusable");
        assert_eq!(value["validator"]["buildSha256"], "b".repeat(64));
        assert_eq!(value["diagnostics"][0]["code"], "manifest_invalid");
        assert!(value.get("manifestDigestValid").is_none());
        assert_eq!(
            serde_json::to_value(SessionVerificationDiagnosticView::LegacyMessage(
                "legacy verifier message".to_string()
            ))
            .unwrap(),
            serde_json::json!("legacy verifier message")
        );

        let diagnostic = SessionDiscoveryDiagnosticView {
            quarantine_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            code: SessionDiscoveryDiagnosticCode::ManifestNotSealed,
            observed_at: "2026-08-29T12:34:56Z".to_string(),
            message: "publication is not sealed".to_string(),
        };
        let value = serde_json::to_value(diagnostic).unwrap();
        assert_eq!(
            value["quarantineId"],
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(value["code"], "manifest_not_sealed");
        assert_eq!(value["observedAt"], "2026-08-29T12:34:56Z");
    }

    #[test]
    fn storage_config_written_before_url_style_existed_keeps_path_style() {
        // Upgrade safety: those stores were signed with the then-hardcoded
        // path style. Loading them as virtual-host would break a working
        // MinIO setup on first launch after the upgrade.
        let config: StorageConfig = serde_json::from_str(
            r#"{"endpoint":"https://minio.internal:9000","bucket":"b","prefix":""}"#,
        )
        .unwrap();
        assert_eq!(config.url_style, StorageUrlStyle::Path);
        // ...while a fresh install gets the style its shipped default
        // endpoint actually requires.
        assert_eq!(
            StorageConfig::default().url_style,
            StorageUrlStyle::VirtualHost
        );
    }

    #[test]
    fn storage_url_style_round_trips_as_camel_case() {
        let config = StorageConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""urlStyle":"virtualHost""#), "{json}");
        let parsed: StorageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url_style, StorageUrlStyle::VirtualHost);
    }

    #[test]
    fn storage_config_round_trips_the_download_root_as_camel_case() {
        let config = StorageConfig {
            endpoint: "https://s3.example".to_string(),
            bucket: "b".to_string(),
            prefix: "p".to_string(),
            url_style: StorageUrlStyle::Path,
            download_root: Some("/srv/recordings".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains(r#""downloadRoot":"/srv/recordings""#),
            "{json}"
        );
        let parsed: StorageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.download_root.as_deref(), Some("/srv/recordings"));
    }

    #[test]
    fn session_file_migrates_legacy_path_to_real_id_and_display_path() {
        let file: SessionFile = serde_json::from_str(r#"{"path":"opaque-1","bytes":42}"#).unwrap();
        assert_eq!(file.file_id, "opaque-1");
        assert_eq!(file.display_path, "opaque-1");
        assert_eq!(file.bytes, 42);
        assert_eq!(file.sha256, "");

        let serialized = serde_json::to_value(&file).unwrap();
        assert_eq!(serialized["fileId"], "opaque-1");
        assert_eq!(serialized["displayPath"], "opaque-1");
        assert!(serialized.get("path").is_none());
    }

    #[test]
    fn session_file_keeps_opaque_id_separate_from_display_path() {
        let file: SessionFile = serde_json::from_str(
            r#"{"fileId":"opaque-2","displayPath":"video/left.mp4","bytes":99,"sha256":"ABCDEF"}"#,
        )
        .unwrap();
        assert_eq!(file.file_id, "opaque-2");
        assert_eq!(file.display_path, "video/left.mp4");
        assert_eq!(file.sha256, "abcdef");
    }

    #[test]
    fn library_view_excludes_publication_and_object_store_receipts() {
        let canonical_device_id = format!("ylx-abcdef01{}", "1".repeat(56));
        let entry = LibraryEntry {
            device_id: canonical_device_id.clone(),
            session_id: "session-1".to_string(),
            date_label: "2026-08-03".to_string(),
            downloaded_at: "just now".to_string(),
            bytes: 42,
            processed_files: Vec::new(),
            files: vec![SessionFile::new(
                "file-1".to_string(),
                "video/file.mp4".to_string(),
                42,
                "a".repeat(64),
            )],
            complete: true,
            download_projection_sequence: 0,
            publication: Some(PublicationEvidence {
                revision: "rev-1".to_string(),
                payload: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                public_key: vec![7, 8, 9],
            }),
            library_root: None,
            object_receipts: vec![ObjectVerificationReceipt {
                key: format!("{canonical_device_id}/session-1/file-1"),
                etag: "etag".to_string(),
                version_id: None,
                bytes: 42,
                sha256: "b".repeat(64),
            }],
            upload_projection: None,
            upload_status: UploadStatus::Done,
            upload_retryable: false,
            uploaded_at: Some("just now".to_string()),
            upload_error: None,
        };

        let value = serde_json::to_value(entry.view()).unwrap();
        assert_eq!(value["deviceId"], canonical_device_id);
        assert_eq!(value["deviceDisplayId"], "YLX-ABCDEF01");
        assert_eq!(value["uploadRetryable"], false);
        assert!(value.get("publication").is_none());
        assert!(value.get("objectReceipts").is_none());
        assert!(value.get("payload").is_none());
        assert!(value.get("signature").is_none());
        assert!(value.get("publicKey").is_none());
        assert!(value.get("downloadProjectionSequence").is_none());
    }

    #[test]
    fn library_view_prefers_processed_files_without_losing_signed_inventory() {
        let mut entry = empty_library_entry(&format!("ylx-abcdef01{}", "1".repeat(56)));
        entry.bytes = 100;
        entry.files = vec![SessionFile::new(
            "raw-left".to_string(),
            "video/left_00000.mp4".to_string(),
            100,
            "a".repeat(64),
        )];
        entry.processed_files = vec![SessionFile::new(
            "processed-sbs-mp4".to_string(),
            "processed/sbs.mp4".to_string(),
            40,
            "b".repeat(64),
        )];

        let view = entry.view();

        assert_eq!(entry.files[0].display_path, "video/left_00000.mp4");
        assert_eq!(view.bytes, 40);
        assert_eq!(view.files.len(), 1);
        assert_eq!(view.files[0].display_path, "processed/sbs.mp4");
    }

    #[test]
    fn device_and_legacy_library_views_separate_identity_from_display() {
        let canonical_device_id = format!("ylx-abcdef01{}", "2".repeat(56));
        let device = Device {
            id: canonical_device_id,
            display_id: "YLX-ABCDEF01".to_string(),
            ip: None,
            state: DeviceState::Offline,
            last_seen: None,
        };
        let device_value = serde_json::to_value(device).unwrap();
        assert_eq!(device_value["displayId"], "YLX-ABCDEF01");

        let entry = empty_library_entry("YLX-ABCDEF01");
        let library_value = serde_json::to_value(entry.view()).unwrap();
        assert_eq!(entry.device_id, "YLX-ABCDEF01");
        assert_eq!(library_value["deviceId"], "YLX-ABCDEF01");
        assert_eq!(library_value["deviceDisplayId"], "YLX-ABCDEF01");
    }

    #[test]
    fn library_view_never_manufactures_an_operational_key_from_noncanonical_history() {
        let lowercase = empty_library_entry("ylx-abcdef01");
        let lowercase_value = serde_json::to_value(lowercase.view()).unwrap();
        assert_eq!(lowercase_value["deviceId"], "ylx-abcdef01");
        assert_eq!(lowercase_value["deviceDisplayId"], "YLX-ABCDEF01");

        let malformed = empty_library_entry("device-unknown");
        let malformed_value = serde_json::to_value(malformed.view()).unwrap();
        assert_eq!(malformed_value["deviceId"], "device-unknown");
        assert_eq!(malformed_value["deviceDisplayId"], "device-unknown");
    }

    #[test]
    fn transfer_wire_shape_uses_one_tagged_state() {
        let transfer = Transfer {
            key: "upload-1".to_string(),
            label: "sess-1".to_string(),
            total_bytes: 10,
            sent_bytes: 5,
            state: TransferState::Running,
            error: None,
            retryable: false,
            direction: TransferDirection::Up,
            target_label: "bucket".to_string(),
        };
        let value = serde_json::to_value(transfer).unwrap();
        assert_eq!(value["state"], "running");
        assert!(value.get("done").is_none());
        assert!(value.get("failed").is_none());
        assert!(value.get("queued").is_none());
        assert!(value.get("resumed").is_none());
    }

    #[test]
    fn transfer_fixture_matches_the_shared_rpc_bundle() {
        let transfer = Transfer {
            key: "transfer-fixture-a".to_string(),
            label: "capture-session-a".to_string(),
            total_bytes: 4096,
            sent_bytes: 1024,
            state: TransferState::Running,
            error: None,
            retryable: false,
            direction: TransferDirection::Down,
            target_label: "YLX-ABCDEF01".to_string(),
        };
        let fixture: serde_json::Value =
            serde_json::from_str(RPC_FIXTURE).expect("shared RPC fixture is valid JSON");
        assert_eq!(
            serde_json::to_value(transfer).expect("transfer serializes"),
            fixture["transfer"]
        );
    }
}
