//! Discovery and safe-release adapter for file systems that the operating
//! system has already mounted.
//!
//! This module deliberately stops at the mounted-volume boundary. It never
//! opens a raw block device, mounts or repairs a file system, assigns a drive
//! letter, asks for elevation, or decides that a volume contains YLX data.
//! Callers scan the constrained recording roots and authenticate manifests in
//! higher layers.
//!
//! # Event ordering
//!
//! [`RemovableMediaAdapter::start`] subscribes before its first enumeration.
//! Compositions that must finish publishing their dependency graph before any
//! worker starts can instead construct [`RemovableMediaAdapter::inactive`] and
//! call [`RemovableMediaAdapter::activate_and_refresh`] during recovery.
//! Native arrival/removal notifications are only invalidation hints: they are
//! drained and followed by an authoritative full enumeration. Applying event
//! deltas directly would make duplicate, lost, and out-of-order notifications
//! correctness-critical. Reconciliation instead makes those cases idempotent;
//! callers can also invoke [`RemovableMediaAdapter::refresh`] at startup
//! recovery or for a user-requested refresh.
//!
//! # Identity and generations
//!
//! [`VolumeIdentity`] is an opaque platform value and is never a mount path.
//! A snapshot carries every currently readable mount path plus file-system,
//! read-only, removable, and capacity hints. Any material observation change
//! produces a new [`VolumeGeneration`]. The generation fences active readers,
//! but remains only a source-locator hint: a resumed import must still verify
//! the dataset/session identity, manifest digest, and file claims.
//!
//! # Safe release
//!
//! Readers acquire a [`VolumeReadLease`]. Removal, a generation change, or an
//! explicit [`RemovableMediaAdapter::release_media_handles`] request cancels
//! all leases for the old generation. Handle release remains busy until those
//! leases have been dropped, at which point the event subscription and
//! platform backend release any adapter-owned references. It never asks the
//! OS to eject the volume. [`RemovableMediaAdapter::safe_eject`] may reuse that
//! completed release boundary, but it is solely responsible for making one
//! non-forced native eject request. A backend without a trustworthy native
//! eject operation returns [`SafeEjectOutcome::ReleasedForSystemEject`]; it
//! must never report [`SafeEjectOutcome::Ejected`] merely because this
//! application closed its own handles.
//!
//! # Platform boundary
//!
//! Linux has a dependency-free `/proc/self/mountinfo` reconciliation backend
//! below. It observes already-mounted block-backed file systems and derives
//! only best-effort hints; it cannot perform a native eject. The
//! [`linux::UDisks2Api`] seam is the production boundary for UDisks2 object
//! manager events, Drive/Block/Filesystem metadata, and Drive.Eject/PowerOff.
//! Windows and macOS expose similarly narrow, target-gated bridge traits for
//! Volume GUID/PnP and mounted-volume URL/Disk Arbitration integrations. This
//! keeps unsafe FFI and native framework ownership outside the state machine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
#[cfg(any(test, target_os = "linux"))]
use std::thread::JoinHandle;
#[cfg(any(test, target_os = "linux"))]
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use ylx_transfer_core::ingest::MediaGenerationId;

use crate::mounted_file::{
    MediaFenceError, MediaFenceStatus, MediaReadLease, MediaReadLeaseProvider,
};

const MAX_IDENTITY_BYTES: usize = 512;
const MAX_HINT_BYTES: usize = 128;
const MAX_PLATFORM_MESSAGE_BYTES: usize = 512;
#[cfg(target_os = "linux")]
const SUBSCRIPTION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(test, target_os = "linux"))]
const SUBSCRIPTION_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// An opaque operating-system volume identity or a namespaced digest of one.
///
/// It may represent a Windows Volume GUID, a UDisks2-resolved stable block
/// identity, or a macOS volume resource identity. Consumers must compare it as
/// an opaque value and must not infer a path or a trusted recording identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VolumeIdentity(String);

impl VolumeIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self, RemovableMediaError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_IDENTITY_BYTES
            && !value
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\'));
        if !valid {
            return Err(RemovableMediaError::InvalidObservation(
                "platform volume identity is empty, too long, or contains unsafe characters"
                    .to_string(),
            ));
        }
        Ok(Self(value))
    }

    /// Turn a native identifier containing path separators or other platform
    /// syntax into a bounded, safe, opaque identity. `namespace` is a stable
    /// adapter name such as `windows-volume` or `macos-volume`.
    pub fn from_native(
        namespace: &str,
        native_identity: &[u8],
    ) -> Result<Self, RemovableMediaError> {
        let namespace_ok = !namespace.is_empty()
            && namespace.len() <= 32
            && namespace
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !namespace_ok || native_identity.is_empty() || native_identity.len() > 4096 {
            return Err(RemovableMediaError::InvalidObservation(
                "native volume identity namespace or value was invalid".to_string(),
            ));
        }
        let digest = Sha256::digest(native_identity);
        Ok(Self(format!(
            "{namespace}:sha256:{}",
            lowercase_hex(&digest)
        )))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VolumeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic process-local observation epoch.
///
/// The epoch is a fence, not a durable media identity. It is intentionally
/// changed whenever the canonical observation for a volume changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationEpoch(u64);

impl ObservationEpoch {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One exact, process-local mounted-media observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VolumeGeneration {
    identity: VolumeIdentity,
    epoch: ObservationEpoch,
}

impl VolumeGeneration {
    #[must_use]
    pub fn identity(&self) -> &VolumeIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn epoch(&self) -> ObservationEpoch {
        self.epoch
    }

    /// Stable, fixed-width token for this platform-locator fence.
    ///
    /// This is deliberately **not** a core `MediaGenerationId`: the core ID
    /// also binds the admitted root-marker digest, which is unavailable during
    /// OS volume discovery. Admission must explicitly bind both identities in
    /// [`VolumeCatalog::bind_media_generation`].
    #[must_use]
    pub fn locator_fence_token(&self) -> String {
        let material = format!("{}\n{}", self.identity.as_str(), self.epoch.get());
        let digest = Sha256::digest(material.as_bytes());
        format!("volume-fence:sha256:{}", lowercase_hex(&digest))
    }
}

fn lowercase_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for &byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// A platform-derived boolean hint. `Unknown` is not equivalent to `No`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceHint {
    Yes,
    No,
    Unknown,
}

impl EvidenceHint {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, value) | (value, Self::Unknown) => value,
            (left, right) if left == right => left,
            _ => Self::Unknown,
        }
    }
}

/// One volume in an immutable published snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedVolume {
    pub generation: VolumeGeneration,
    /// All mount roots returned by the OS that were directories readable by
    /// the current, ordinary user at reconciliation time.
    pub mount_paths: Vec<PathBuf>,
    pub filesystem: Option<String>,
    pub read_only: EvidenceHint,
    pub removable: EvidenceHint,
    pub capacity_bytes: Option<u64>,
}

/// Immutable mounted-volume projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedVolumeSnapshot {
    pub epoch: ObservationEpoch,
    pub volumes: Vec<MountedVolume>,
}

impl MountedVolumeSnapshot {
    #[must_use]
    pub fn get(&self, identity: &VolumeIdentity) -> Option<&MountedVolume> {
        self.volumes
            .binary_search_by(|volume| volume.generation.identity().cmp(identity))
            .ok()
            .map(|index| &self.volumes[index])
    }

    #[must_use]
    pub fn contains_generation(&self, generation: &VolumeGeneration) -> bool {
        self.get(generation.identity())
            .is_some_and(|volume| &volume.generation == generation)
    }

    #[must_use]
    pub fn generation_by_locator_fence(&self, value: &str) -> Option<&VolumeGeneration> {
        self.volumes
            .iter()
            .map(|volume| &volume.generation)
            .find(|generation| generation.locator_fence_token() == value)
    }
}

/// Raw, already-mounted volume observation supplied by a platform backend.
///
/// Backends should return one record with all known mount paths. The adapter
/// also merges duplicate records by opaque identity so a mountinfo-style
/// source can report one record per mount point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformMountedVolume {
    identity: VolumeIdentity,
    mount_paths: Vec<PathBuf>,
    filesystem: Option<String>,
    read_only: EvidenceHint,
    removable: EvidenceHint,
    capacity_bytes: Option<u64>,
    /// Optional platform instance marker. If available, this must change when
    /// an identity disappears and is observed again, even if its paths and
    /// metadata are identical. It is never published outside this module.
    presence_marker: Option<String>,
}

impl PlatformMountedVolume {
    #[must_use]
    pub fn new(identity: VolumeIdentity, mount_paths: Vec<PathBuf>) -> Self {
        Self {
            identity,
            mount_paths,
            filesystem: None,
            read_only: EvidenceHint::Unknown,
            removable: EvidenceHint::Unknown,
            capacity_bytes: None,
            presence_marker: None,
        }
    }

    #[must_use]
    pub fn with_filesystem(mut self, filesystem: impl Into<String>) -> Self {
        self.filesystem = normalized_hint(filesystem.into());
        self
    }

    #[must_use]
    pub const fn with_read_only(mut self, read_only: EvidenceHint) -> Self {
        self.read_only = read_only;
        self
    }

    #[must_use]
    pub const fn with_removable(mut self, removable: EvidenceHint) -> Self {
        self.removable = removable;
        self
    }

    #[must_use]
    pub const fn with_capacity_bytes(mut self, capacity_bytes: Option<u64>) -> Self {
        self.capacity_bytes = capacity_bytes;
        self
    }

    #[must_use]
    pub fn with_presence_marker(mut self, marker: impl Into<String>) -> Self {
        self.presence_marker = normalized_hint(marker.into());
        self
    }
}

/// Sanitized adapter error. Platform error text is bounded before storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovableMediaError {
    Subscription(String),
    Enumeration(String),
    InvalidObservation(String),
    Release(String),
    Eject(String),
    CatalogUnavailable,
    EpochExhausted,
}

impl fmt::Display for RemovableMediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subscription(message) => write!(f, "volume event subscription failed: {message}"),
            Self::Enumeration(message) => write!(f, "mounted-volume enumeration failed: {message}"),
            Self::InvalidObservation(message) => {
                write!(f, "invalid mounted-volume observation: {message}")
            }
            Self::Release(message) => write!(f, "volume release failed: {message}"),
            Self::Eject(message) => write!(f, "volume eject failed: {message}"),
            Self::CatalogUnavailable => f.write_str("mounted-volume catalog unavailable"),
            Self::EpochExhausted => f.write_str("mounted-volume observation epoch exhausted"),
        }
    }
}

impl std::error::Error for RemovableMediaError {}

#[cfg(any(test, target_os = "linux"))]
fn shutdown_subscription_worker(
    worker: &mut Option<JoinHandle<()>>,
    timeout: Duration,
    worker_name: &str,
) -> Result<(), RemovableMediaError> {
    let deadline = Instant::now() + timeout;
    loop {
        let Some(current) = worker.as_ref() else {
            return Ok(());
        };
        if current.is_finished() {
            let current = worker.take().expect("finished worker remains installed");
            return current.join().map_err(|_| {
                RemovableMediaError::Subscription(format!(
                    "{worker_name} terminated unexpectedly during shutdown"
                ))
            });
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(RemovableMediaError::Subscription(format!(
                "{worker_name} did not stop within {} milliseconds",
                timeout.as_millis()
            )));
        }
        std::thread::sleep(
            SUBSCRIPTION_SHUTDOWN_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
        );
    }
}

#[cfg(target_os = "linux")]
fn platform_error(
    constructor: impl FnOnce(String) -> RemovableMediaError,
    message: impl fmt::Display,
) -> RemovableMediaError {
    constructor(sanitize_platform_message(&message.to_string()))
}

fn sanitize_platform_message(message: &str) -> String {
    let mut sanitized = String::with_capacity(message.len().min(MAX_PLATFORM_MESSAGE_BYTES));
    for character in message.chars() {
        if sanitized.len() >= MAX_PLATFORM_MESSAGE_BYTES {
            break;
        }
        sanitized.push(if character.is_control() && character != ' ' {
            ' '
        } else {
            character
        });
    }
    sanitized.trim().to_string()
}

fn sanitize_eject_reason(reason: EjectUnavailableReason) -> EjectUnavailableReason {
    match reason {
        EjectUnavailableReason::Other(message) => {
            EjectUnavailableReason::Other(sanitize_platform_message(&message))
        }
        other => other,
    }
}

fn normalized_hint(value: String) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_HINT_BYTES || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_string())
    }
}

/// Result of draining a native event source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubscriptionDrain {
    /// Number of coalesced invalidations. Event identity/order is intentionally
    /// irrelevant because every non-zero batch triggers full reconciliation.
    pub invalidations: usize,
    /// No future event can arrive. The adapter still performs one last scan;
    /// the caller should then call `restart_subscription_and_refresh`.
    pub disconnected: bool,
}

/// Native event registration held for the complete monitor lifetime.
pub trait VolumeEventSubscription: Send {
    fn drain(&mut self) -> Result<SubscriptionDrain, RemovableMediaError>;

    /// Release subscription-owned references to this volume as part of the
    /// adapter-only handle-release boundary. Most global event sources hold
    /// none and can keep the default no-op. This must never request an eject.
    /// Calls for the same generation must be safe to retry after an error.
    fn release_volume(
        &mut self,
        _generation: &VolumeGeneration,
    ) -> Result<(), RemovableMediaError> {
        Ok(())
    }

    /// Stop the native event source and join every subscription-owned worker.
    /// This is a terminal, idempotent operation: a stopped subscription must
    /// not be restarted or report that it can deliver future invalidations.
    fn shutdown(&mut self) -> Result<(), RemovableMediaError> {
        Ok(())
    }
}

/// Why the OS declined to attach an unmounted removable filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachRefusalReason {
    /// The caller is not authorized to ask for the mount. On Linux this is the
    /// polkit verdict, which a local active desktop session normally passes and
    /// a remote or non-seat session normally does not.
    PermissionDenied,
    NativeServiceUnavailable,
    /// Sanitized, bounded platform explanation.
    Other(String),
}

/// What one attach pass actually did. `mounted` counts only filesystems the OS
/// confirmed it mounted, never ones that merely looked eligible.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformAttachReport {
    pub eligible: usize,
    pub mounted: usize,
    pub refusals: Vec<AttachRefusalReason>,
}

impl PlatformAttachReport {
    /// The report of a platform that cannot attach anything at all.
    #[must_use]
    pub fn unsupported() -> Self {
        Self::default()
    }
}

/// Platform boundary. Implementations enumerate only file systems already
/// mounted by the OS. Apart from `attach_removable_filesystems`, whose contract
/// is spelled out on the method itself, no method here authorizes mount,
/// unlock, repair, or raw device access.
pub trait PlatformVolumeBackend: Send {
    type Subscription: VolumeEventSubscription;

    /// Register native notifications. `RemovableMediaAdapter::start` calls
    /// this before `enumerate_mounted_readable` and retains the subscription.
    fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError>;

    /// Enumerate OS-mounted file systems and all mount paths known for each.
    /// The adapter performs a final ordinary-user readability check.
    fn enumerate_mounted_readable(
        &mut self,
    ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError>;

    /// Close any backend-owned directory handles, watchers, or outstanding I/O
    /// for this generation. This runs only after all reader leases have ended
    /// and must never request a native eject. Calls for the same generation
    /// must be safe to retry after an error.
    fn release_volume_handles(
        &mut self,
        _generation: &VolumeGeneration,
    ) -> Result<(), RemovableMediaError> {
        Ok(())
    }

    /// Ask the OS for a non-forced eject. Unsupported/permission-limited
    /// implementations return `ReleasedForSystemEject`, never fake `Ejected`.
    fn request_eject(
        &mut self,
        _volume: &MountedVolume,
    ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
        Ok(PlatformEjectOutcome::ReleasedForSystemEject {
            reason: EjectUnavailableReason::Unsupported,
        })
    }

    /// Ask the OS to mount removable file systems that are present but not
    /// mounted, so inserting a card is enough to make it discoverable.
    ///
    /// This is the one method here that authorizes a mount, and the contract is
    /// deliberately narrow. An implementation may only offer file systems the
    /// platform itself attests are removable and non-system; it must delegate
    /// to the OS mount service under the ordinary user's authorization rather
    /// than to any privileged helper of ours; and it must never unlock, repair,
    /// or touch raw devices. A refusal is reported, never worked around.
    ///
    /// Attaching does not publish anything: the catalog still shows only what a
    /// subsequent `enumerate_mounted_readable` finds actually mounted.
    ///
    /// The default is a platform that cannot attach anything.
    fn attach_removable_filesystems(
        &mut self,
    ) -> Result<PlatformAttachReport, RemovableMediaError> {
        Ok(PlatformAttachReport::unsupported())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EjectUnavailableReason {
    Unsupported,
    PermissionDenied,
    NativeServiceUnavailable,
    /// Sanitized, bounded platform explanation.
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformEjectOutcome {
    /// A native API explicitly confirmed a successful non-forced eject.
    Ejected,
    /// Application references are closed, but the user must use the OS eject
    /// UI. This is the only valid unsupported-adapter success result.
    ReleasedForSystemEject { reason: EjectUnavailableReason },
    /// The OS refused eject. On Windows, `code` carries the PNP veto type and
    /// `reason` carries the bounded veto name/reason supplied by the API.
    Vetoed { code: Option<u32>, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeEjectOutcome {
    /// Cancellation has been requested. The caller must wait for readers to
    /// close their handles and retry; no platform release or native eject was
    /// attempted.
    Busy {
        active_readers: usize,
    },
    Ejected,
    ReleasedForSystemEject {
        reason: EjectUnavailableReason,
    },
    Vetoed {
        code: Option<u32>,
        reason: String,
    },
}

/// Result of releasing only this application's access to a mounted volume.
///
/// `Released` means the adapter has closed its subscription/backend-owned
/// references for the generation. It does not say that the operating system
/// unmounted, powered off, or ejected anything. A caller that needs a native
/// non-forced eject must subsequently call [`RemovableMediaAdapter::safe_eject`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseMediaHandlesOutcome {
    /// Lease cancellation has been requested. The caller must wait for every
    /// active reader to drop its handle and retry; no platform release or
    /// eject operation has run yet.
    Busy { active_readers: usize },
    /// This adapter no longer owns per-volume handles. The volume may still
    /// be mounted and must not be presented as physically ejected.
    Released,
}

/// A native eject result that is final for one live volume generation. Only
/// confirmed success and the explicit "use the system eject control" outcome
/// are cached. A veto leaves the released handle boundary in place so the
/// caller can decide whether to retry later; an unknown native failure is
/// marked indeterminate rather than triggering a second physical operation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompletedEjectOutcome {
    Ejected,
    ReleasedForSystemEject { reason: EjectUnavailableReason },
}

impl From<CompletedEjectOutcome> for SafeEjectOutcome {
    fn from(outcome: CompletedEjectOutcome) -> Self {
        match outcome {
            CompletedEjectOutcome::Ejected => Self::Ejected,
            CompletedEjectOutcome::ReleasedForSystemEject { reason } => {
                Self::ReleasedForSystemEject { reason }
            }
        }
    }
}

/// Per-generation progress for a release/eject sequence.
///
/// Every phase remains a reader fence. The external handle-release hooks may
/// be irreversible, so their successful progress is never rolled back merely
/// because a later hook or native eject operation fails. Subscription release
/// is additionally scoped to one adapter subscription epoch: a replacement
/// subscription must release its own references before an old phase can be
/// reused.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReleasePhase {
    Draining,
    SubscriptionReleased {
        subscription_epoch: u64,
    },
    HandlesReleased {
        subscription_epoch: u64,
    },
    EjectCompleted {
        subscription_epoch: u64,
        outcome: CompletedEjectOutcome,
    },
    EjectIndeterminate {
        subscription_epoch: u64,
        message: String,
    },
}

impl ReleasePhase {
    fn subscription_epoch(&self) -> Option<u64> {
        match self {
            Self::Draining => None,
            Self::SubscriptionReleased { subscription_epoch }
            | Self::HandlesReleased { subscription_epoch }
            | Self::EjectCompleted {
                subscription_epoch, ..
            }
            | Self::EjectIndeterminate {
                subscription_epoch, ..
            } => Some(*subscription_epoch),
        }
    }

    fn record_subscription_release(&mut self, current_epoch: u64) {
        match self {
            Self::Draining => {
                *self = Self::SubscriptionReleased {
                    subscription_epoch: current_epoch,
                };
            }
            Self::SubscriptionReleased { subscription_epoch }
            | Self::HandlesReleased { subscription_epoch }
            | Self::EjectCompleted {
                subscription_epoch, ..
            }
            | Self::EjectIndeterminate {
                subscription_epoch, ..
            } => *subscription_epoch = current_epoch,
        }
    }

    fn handles_released(&self) -> bool {
        matches!(
            self,
            Self::HandlesReleased { .. }
                | Self::EjectCompleted { .. }
                | Self::EjectIndeterminate { .. }
        )
    }

    fn completed_eject(&self) -> Option<CompletedEjectOutcome> {
        match self {
            Self::EjectCompleted { outcome, .. } => Some(outcome.clone()),
            Self::Draining
            | Self::SubscriptionReleased { .. }
            | Self::HandlesReleased { .. }
            | Self::EjectIndeterminate { .. } => None,
        }
    }

    fn indeterminate_eject_message(&self) -> Option<&str> {
        match self {
            Self::EjectIndeterminate { message, .. } => Some(message),
            Self::Draining
            | Self::SubscriptionReleased { .. }
            | Self::HandlesReleased { .. }
            | Self::EjectCompleted { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireVolumeError {
    UnknownVolume {
        identity: VolumeIdentity,
    },
    StaleGeneration {
        requested: VolumeGeneration,
        current: Option<ObservationEpoch>,
    },
    Releasing {
        generation: VolumeGeneration,
    },
    ConflictingBinding {
        media_generation: MediaGenerationId,
        existing: VolumeGeneration,
    },
    CatalogUnavailable,
}

impl fmt::Display for AcquireVolumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVolume { identity } => write!(f, "volume {identity} is not mounted"),
            Self::StaleGeneration { requested, current } => write!(
                f,
                "volume generation {} at epoch {} is stale (current epoch: {})",
                requested.identity(),
                requested.epoch().get(),
                current
                    .map(|epoch| epoch.get().to_string())
                    .unwrap_or_else(|| "absent".to_string())
            ),
            Self::Releasing { generation } => write!(
                f,
                "volume {} at epoch {} is being released",
                generation.identity(),
                generation.epoch().get()
            ),
            Self::ConflictingBinding {
                media_generation,
                existing,
            } => write!(
                f,
                "media generation {media_generation} is already bound to volume {} at epoch {}",
                existing.identity(),
                existing.epoch().get()
            ),
            Self::CatalogUnavailable => f.write_str("mounted-volume catalog unavailable"),
        }
    }
}

impl std::error::Error for AcquireVolumeError {}

#[derive(Debug)]
struct ReaderState {
    active: usize,
    cancelled: Arc<AtomicBool>,
}

#[derive(Debug)]
struct CatalogState {
    snapshot: Arc<MountedVolumeSnapshot>,
    readers: BTreeMap<VolumeGeneration, ReaderState>,
    /// A release phase is also a read fence. It stays present through any
    /// partial external release because those resources cannot be safely
    /// assumed to be reopenable after an error.
    releasing: BTreeMap<VolumeGeneration, ReleasePhase>,
    /// Explicit admission result. Discovery cannot derive a core media ID
    /// because it does not know the authenticated root-marker digest.
    media_bindings: BTreeMap<MediaGenerationId, VolumeGeneration>,
}

#[derive(Debug, Clone)]
struct ReleaseBegin {
    active_readers: usize,
    phase: ReleasePhase,
}

/// Cloneable live projection used by mounted-file readers.
///
/// Snapshot replacement, reader acquisition, and release fencing share one
/// short mutex. No file or platform I/O occurs while it is held.
#[derive(Debug, Clone)]
pub struct VolumeCatalog {
    inner: Arc<Mutex<CatalogState>>,
}

impl VolumeCatalog {
    fn new(snapshot: Arc<MountedVolumeSnapshot>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CatalogState {
                snapshot,
                readers: BTreeMap::new(),
                releasing: BTreeMap::new(),
                media_bindings: BTreeMap::new(),
            })),
        }
    }

    pub fn snapshot(&self) -> Result<Arc<MountedVolumeSnapshot>, RemovableMediaError> {
        self.inner
            .lock()
            .map(|state| state.snapshot.clone())
            .map_err(|_| RemovableMediaError::CatalogUnavailable)
    }

    pub fn current_generation(
        &self,
        identity: &VolumeIdentity,
    ) -> Result<Option<VolumeGeneration>, RemovableMediaError> {
        Ok(self
            .snapshot()?
            .get(identity)
            .map(|volume| volume.generation.clone()))
    }

    pub fn contains_generation(
        &self,
        generation: &VolumeGeneration,
    ) -> Result<bool, RemovableMediaError> {
        Ok(self.snapshot()?.contains_generation(generation))
    }

    /// Return the live reader count for one exact, currently mounted
    /// generation. A stale or absent generation is rejected rather than
    /// returning a count that could be attributed to a reinserted volume.
    pub fn active_reader_count(
        &self,
        generation: &VolumeGeneration,
    ) -> Result<usize, RemovableMediaError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        let current = state
            .snapshot
            .get(generation.identity())
            .map(|volume| &volume.generation);
        if current != Some(generation) {
            return Err(RemovableMediaError::Release(format!(
                "volume generation {} at epoch {} is no longer current",
                generation.identity(),
                generation.epoch().get()
            )));
        }
        Ok(state
            .readers
            .get(generation)
            .map_or(0, |reader| reader.active))
    }

    /// Cancel every tracked lease and return the total number still active.
    /// Unlike `active_reader_count`, this includes leases for observations
    /// that have already disappeared from the current mount snapshot. Those
    /// stale leases can still own open file handles and therefore remain part
    /// of the process shutdown boundary.
    pub fn cancel_all_readers(&self) -> Result<usize, RemovableMediaError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        Ok(state.readers.values().fold(0usize, |total, reader| {
            reader.cancelled.store(true, Ordering::Release);
            total.saturating_add(reader.active)
        }))
    }

    pub fn mount_paths(
        &self,
        generation: &VolumeGeneration,
    ) -> Result<Option<Vec<PathBuf>>, RemovableMediaError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        if state.releasing.contains_key(generation) {
            return Ok(None);
        }
        Ok(state
            .snapshot
            .get(generation.identity())
            .filter(|volume| &volume.generation == generation)
            .map(|volume| volume.mount_paths.clone()))
    }

    /// Bind a content-aware core media generation to the exact live platform
    /// observation that admission scanned. Repeating the same binding is
    /// idempotent; rebinding one core ID to another observation fails closed.
    pub fn bind_media_generation(
        &self,
        media_generation: MediaGenerationId,
        generation: &VolumeGeneration,
    ) -> Result<(), AcquireVolumeError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| AcquireVolumeError::CatalogUnavailable)?;
        let current = state
            .snapshot
            .get(generation.identity())
            .map(|volume| volume.generation.clone());
        let Some(current) = current else {
            return Err(AcquireVolumeError::UnknownVolume {
                identity: generation.identity().clone(),
            });
        };
        if &current != generation {
            return Err(AcquireVolumeError::StaleGeneration {
                requested: generation.clone(),
                current: Some(current.epoch()),
            });
        }
        if state.releasing.contains_key(generation) {
            return Err(AcquireVolumeError::Releasing {
                generation: generation.clone(),
            });
        }

        if let Some(existing) = state.media_bindings.get(&media_generation) {
            if existing == generation {
                return Ok(());
            }
            return Err(AcquireVolumeError::ConflictingBinding {
                media_generation,
                existing: existing.clone(),
            });
        }
        state
            .media_bindings
            .insert(media_generation, generation.clone());
        Ok(())
    }

    /// Forget an admission binding after its durable import job is retired.
    /// Active leases retain their own generation value and remain fenced.
    pub fn forget_media_generation(
        &self,
        media_generation: &MediaGenerationId,
    ) -> Result<bool, RemovableMediaError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        Ok(state.media_bindings.remove(media_generation).is_some())
    }

    fn acquire_bound_reader(
        &self,
        media_generation: &MediaGenerationId,
    ) -> Result<VolumeReadLease, MediaFenceError> {
        let mut state = self.inner.lock().map_err(|_| MediaFenceError::Io {
            message: "mounted-volume catalog lock is unavailable".to_string(),
        })?;
        let generation = state
            .media_bindings
            .get(media_generation)
            .cloned()
            .ok_or_else(|| MediaFenceError::Unavailable {
                message: "media generation has no admitted mounted-volume binding".to_string(),
            })?;
        let current = state
            .snapshot
            .get(generation.identity())
            .map(|volume| volume.generation.clone());
        let Some(current) = current else {
            return Err(MediaFenceError::Unavailable {
                message: "the admitted volume is not mounted".to_string(),
            });
        };
        if current != generation {
            return Err(MediaFenceError::Changed {
                observed: observed_media_generation(&state, &current),
            });
        }
        if state.releasing.contains_key(&generation) {
            return Err(MediaFenceError::Unavailable {
                message: "the admitted volume is being released".to_string(),
            });
        }

        let reader = state
            .readers
            .entry(generation.clone())
            .or_insert_with(|| ReaderState {
                active: 0,
                cancelled: Arc::new(AtomicBool::new(false)),
            });
        reader.active = reader.active.saturating_add(1);
        Ok(VolumeReadLease {
            catalog: Arc::downgrade(&self.inner),
            media_generation: media_generation.clone(),
            volume_generation: generation,
            cancelled: reader.cancelled.clone(),
        })
    }

    fn publish(&self, snapshot: Arc<MountedVolumeSnapshot>) -> Result<(), RemovableMediaError> {
        let current: BTreeSet<VolumeGeneration> = snapshot
            .volumes
            .iter()
            .map(|volume| volume.generation.clone())
            .collect();
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        for (generation, reader) in &state.readers {
            if !current.contains(generation) {
                reader.cancelled.store(true, Ordering::Release);
            }
        }
        state
            .readers
            .retain(|generation, reader| reader.active > 0 || current.contains(generation));
        state
            .releasing
            .retain(|generation, _| current.contains(generation));
        state.snapshot = snapshot;
        Ok(())
    }

    fn begin_release(
        &self,
        generation: &VolumeGeneration,
    ) -> Result<ReleaseBegin, AcquireVolumeError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| AcquireVolumeError::CatalogUnavailable)?;
        let current = state
            .snapshot
            .get(generation.identity())
            .cloned()
            .ok_or_else(|| AcquireVolumeError::UnknownVolume {
                identity: generation.identity().clone(),
            })?;
        if &current.generation != generation {
            return Err(AcquireVolumeError::StaleGeneration {
                requested: generation.clone(),
                current: Some(current.generation.epoch()),
            });
        }
        let phase = state
            .releasing
            .entry(generation.clone())
            .or_insert(ReleasePhase::Draining)
            .clone();
        let active = state.readers.get(generation).map_or(0, |reader| {
            reader.cancelled.store(true, Ordering::Release);
            reader.active
        });
        Ok(ReleaseBegin {
            active_readers: active,
            phase,
        })
    }

    fn mark_subscription_released(
        &self,
        generation: &VolumeGeneration,
        subscription_epoch: u64,
    ) -> Result<ReleasePhase, RemovableMediaError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        let phase = state.releasing.get_mut(generation).ok_or_else(|| {
            RemovableMediaError::Release(
                "mounted-volume release was no longer fenced before subscription release completed"
                    .to_string(),
            )
        })?;
        phase.record_subscription_release(subscription_epoch);
        Ok(phase.clone())
    }

    fn mark_handles_released(
        &self,
        generation: &VolumeGeneration,
    ) -> Result<ReleasePhase, RemovableMediaError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        let phase = state.releasing.get_mut(generation).ok_or_else(|| {
            RemovableMediaError::Release(
                "mounted-volume release was no longer fenced before backend handles closed"
                    .to_string(),
            )
        })?;
        match phase {
            ReleasePhase::Draining => {
                return Err(RemovableMediaError::Release(
                    "backend handles cannot be released before the subscription release completes"
                        .to_string(),
                ));
            }
            ReleasePhase::SubscriptionReleased { subscription_epoch } => {
                let subscription_epoch = *subscription_epoch;
                *phase = ReleasePhase::HandlesReleased { subscription_epoch };
            }
            ReleasePhase::HandlesReleased { .. }
            | ReleasePhase::EjectCompleted { .. }
            | ReleasePhase::EjectIndeterminate { .. } => {}
        }
        Ok(phase.clone())
    }

    fn mark_eject_completed(
        &self,
        generation: &VolumeGeneration,
        outcome: CompletedEjectOutcome,
    ) -> Result<(), RemovableMediaError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        let phase = state.releasing.get_mut(generation).ok_or_else(|| {
            RemovableMediaError::Eject(
                "mounted-volume release fence disappeared before the native eject result was recorded"
                    .to_string(),
            )
        })?;
        if !phase.handles_released() {
            return Err(RemovableMediaError::Eject(
                "native eject completed before adapter-owned handles were released".to_string(),
            ));
        }
        let subscription_epoch = phase.subscription_epoch().ok_or_else(|| {
            RemovableMediaError::Eject(
                "native eject completed before the active subscription was released".to_string(),
            )
        })?;
        *phase = ReleasePhase::EjectCompleted {
            subscription_epoch,
            outcome,
        };
        Ok(())
    }

    fn mark_eject_indeterminate(
        &self,
        generation: &VolumeGeneration,
        message: String,
    ) -> Result<(), RemovableMediaError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| RemovableMediaError::CatalogUnavailable)?;
        let phase = state.releasing.get_mut(generation).ok_or_else(|| {
            RemovableMediaError::Eject(
                "mounted-volume release fence disappeared after an unknown native eject result"
                    .to_string(),
            )
        })?;
        if !phase.handles_released() {
            return Err(RemovableMediaError::Eject(
                "native eject failed before adapter-owned handles were released".to_string(),
            ));
        }
        let subscription_epoch = phase.subscription_epoch().ok_or_else(|| {
            RemovableMediaError::Eject(
                "native eject failed before the active subscription was released".to_string(),
            )
        })?;
        *phase = ReleasePhase::EjectIndeterminate {
            subscription_epoch,
            message,
        };
        Ok(())
    }
}

/// Active reader fence. The file response/body must retain this value until
/// EOF or drop and check `is_cancelled` before and after blocking reads.
#[derive(Debug)]
pub struct VolumeReadLease {
    catalog: Weak<Mutex<CatalogState>>,
    media_generation: MediaGenerationId,
    volume_generation: VolumeGeneration,
    cancelled: Arc<AtomicBool>,
}

impl VolumeReadLease {
    #[must_use]
    pub fn volume_generation(&self) -> &VolumeGeneration {
        &self.volume_generation
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Drop for VolumeReadLease {
    fn drop(&mut self) {
        let Some(catalog) = self.catalog.upgrade() else {
            return;
        };
        let Ok(mut state) = catalog.lock() else {
            return;
        };
        let remove = if let Some(reader) = state.readers.get_mut(&self.volume_generation) {
            reader.active = reader.active.saturating_sub(1);
            reader.active == 0
        } else {
            false
        };
        if remove {
            state.readers.remove(&self.volume_generation);
        }
    }
}

impl MediaReadLease for VolumeReadLease {
    fn generation(&self) -> &MediaGenerationId {
        &self.media_generation
    }

    fn status(&self) -> MediaFenceStatus {
        let Some(catalog) = self.catalog.upgrade() else {
            return MediaFenceStatus::Unavailable;
        };
        let Ok(state) = catalog.lock() else {
            return MediaFenceStatus::Unavailable;
        };
        let current = state
            .snapshot
            .get(self.volume_generation.identity())
            .map(|volume| &volume.generation);
        match current {
            None => MediaFenceStatus::Unavailable,
            Some(current) if current != &self.volume_generation => MediaFenceStatus::Changed {
                observed: observed_media_generation(&state, current),
            },
            Some(_) if state.releasing.contains_key(&self.volume_generation) => {
                MediaFenceStatus::Unavailable
            }
            Some(_) if self.cancelled.load(Ordering::Acquire) => MediaFenceStatus::Unavailable,
            Some(_) => MediaFenceStatus::Current,
        }
    }
}

impl MediaReadLeaseProvider for VolumeCatalog {
    fn acquire(
        &self,
        expected: &MediaGenerationId,
    ) -> Result<Box<dyn MediaReadLease>, MediaFenceError> {
        self.acquire_bound_reader(expected)
            .map(|lease| Box::new(lease) as Box<dyn MediaReadLease>)
    }

    fn allows_volume_mount_reparse_root(&self, expected: &MediaGenerationId, root: &Path) -> bool {
        let Ok(state) = self.inner.lock() else {
            return false;
        };
        let Some(generation) = state.media_bindings.get(expected) else {
            return false;
        };
        if state.releasing.contains_key(generation) {
            return false;
        }
        state
            .snapshot
            .get(generation.identity())
            .filter(|volume| &volume.generation == generation)
            .is_some_and(|volume| volume.mount_paths.iter().any(|path| path == root))
    }
}

fn observed_media_generation(
    state: &CatalogState,
    generation: &VolumeGeneration,
) -> Option<MediaGenerationId> {
    state
        .media_bindings
        .iter()
        .find_map(|(media, volume)| (volume == generation).then(|| media.clone()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeChange {
    Added(MountedVolume),
    Updated {
        previous: MountedVolume,
        current: MountedVolume,
    },
    Removed(MountedVolume),
}

#[derive(Debug, Clone)]
pub struct ReconcileReport {
    pub snapshot: Arc<MountedVolumeSnapshot>,
    pub changes: Vec<VolumeChange>,
}

#[derive(Debug, Clone)]
pub struct EventPollReport {
    pub snapshot: Arc<MountedVolumeSnapshot>,
    pub changes: Vec<VolumeChange>,
    pub invalidations: usize,
    pub subscription_disconnected: bool,
    pub refreshed: bool,
}

/// Subscribe-first coordinator around one platform backend.
pub struct RemovableMediaAdapter<B: PlatformVolumeBackend> {
    backend: B,
    subscription: Option<B::Subscription>,
    subscription_closed: bool,
    /// Monotonic identity of the installed subscription. Release progress is
    /// tied to this value so replacing a disconnected subscription cannot
    /// inherit the prior subscription's `release_volume` result.
    subscription_epoch: u64,
    descriptors: BTreeMap<VolumeIdentity, PlatformMountedVolume>,
    catalog: VolumeCatalog,
    last_epoch: ObservationEpoch,
}

impl<B: PlatformVolumeBackend> RemovableMediaAdapter<B> {
    /// Construct an empty adapter without registering native notifications or
    /// enumerating mounted volumes. The first activation retains subscribe-
    /// before-enumerate ordering and publishes observation epoch one.
    #[must_use]
    pub fn inactive(backend: B) -> Self {
        let descriptors = BTreeMap::new();
        let epoch = ObservationEpoch(0);
        let snapshot = Arc::new(snapshot_from_descriptors(&descriptors, None, epoch));
        Self {
            backend,
            subscription: None,
            subscription_closed: false,
            subscription_epoch: 0,
            descriptors,
            catalog: VolumeCatalog::new(snapshot),
            last_epoch: epoch,
        }
    }

    pub fn start(backend: B) -> Result<Self, RemovableMediaError> {
        let mut adapter = Self::inactive(backend);
        adapter.activate_and_refresh()?;
        Ok(adapter)
    }

    /// Register the native event source once, then publish the first complete
    /// mounted-volume enumeration. A failed enumeration retains the active
    /// subscription so retrying cannot create an event-delivery gap.
    pub fn activate_and_refresh(&mut self) -> Result<ReconcileReport, RemovableMediaError> {
        self.ensure_not_closed()?;
        if self.last_epoch.get() > 0 {
            return Ok(ReconcileReport {
                snapshot: self.catalog.snapshot()?,
                changes: Vec::new(),
            });
        }
        if self.subscription.is_none() {
            self.subscription = Some(self.backend.subscribe()?);
            self.subscription_epoch = 1;
        }
        let next = canonicalize(self.backend.enumerate_mounted_readable()?)?;
        let epoch = ObservationEpoch(1);
        let snapshot = Arc::new(snapshot_from_descriptors(&next, None, epoch));
        let previous = self.catalog.snapshot()?;
        let changes = diff_snapshots(&previous, &snapshot);
        self.catalog.publish(snapshot.clone())?;
        self.descriptors = next;
        self.last_epoch = epoch;
        Ok(ReconcileReport { snapshot, changes })
    }

    #[must_use]
    pub fn catalog(&self) -> VolumeCatalog {
        self.catalog.clone()
    }

    /// Read the currently selected platform backend without exposing mutable
    /// adapter state. A composition may use this after `start` or a
    /// subscription restart to project live platform capabilities, such as
    /// whether Linux remained on UDisks2 or fell back to mountinfo.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn snapshot(&self) -> Result<Arc<MountedVolumeSnapshot>, RemovableMediaError> {
        self.catalog.snapshot()
    }

    /// Offer the OS a chance to mount removable media that is inserted but
    /// unmounted. This only asks; the caller must still `refresh` to learn what
    /// the OS actually mounted, and a refusal leaves the catalog unchanged.
    pub fn attach_removable_filesystems(
        &mut self,
    ) -> Result<PlatformAttachReport, RemovableMediaError> {
        self.ensure_subscription_active()?;
        self.backend.attach_removable_filesystems()
    }

    /// Startup recovery, event-loss recovery, and user-triggered full refresh.
    pub fn refresh(&mut self) -> Result<ReconcileReport, RemovableMediaError> {
        self.ensure_subscription_active()?;
        let next = canonicalize(self.backend.enumerate_mounted_readable()?)?;
        self.publish_reconciled(next)
    }

    /// Drain native notifications. Any non-empty batch, including a terminal
    /// disconnect, causes exactly one authoritative full refresh.
    pub fn poll_events(&mut self) -> Result<EventPollReport, RemovableMediaError> {
        self.ensure_subscription_active()?;
        let drained = self
            .subscription
            .as_mut()
            .expect("active subscription checked above")
            .drain()?;
        if drained.invalidations == 0 && !drained.disconnected {
            return Ok(EventPollReport {
                snapshot: self.catalog.snapshot()?,
                changes: Vec::new(),
                invalidations: 0,
                subscription_disconnected: false,
                refreshed: false,
            });
        }
        let report = self.refresh()?;
        Ok(EventPollReport {
            snapshot: report.snapshot,
            changes: report.changes,
            invalidations: drained.invalidations,
            subscription_disconnected: drained.disconnected,
            refreshed: true,
        })
    }

    /// Replace a dead subscription without creating an enumeration gap. The
    /// new subscription is registered first, the OS is then enumerated, and
    /// only after both succeed is the old subscription dropped.
    pub fn restart_subscription_and_refresh(
        &mut self,
    ) -> Result<ReconcileReport, RemovableMediaError> {
        self.ensure_subscription_active()?;
        let subscription_epoch = self.subscription_epoch.checked_add(1).ok_or_else(|| {
            RemovableMediaError::Subscription(
                "mounted-volume subscription epoch exhausted".to_string(),
            )
        })?;
        let subscription = self.backend.subscribe()?;
        let next = canonicalize(self.backend.enumerate_mounted_readable()?)?;
        self.subscription = Some(subscription);
        self.subscription_epoch = subscription_epoch;
        self.publish_reconciled(next)
    }

    /// Permanently close and join the native event subscription without
    /// ejecting, unmounting, or otherwise changing operating-system state.
    /// Per-generation releases should normally complete first. If shutdown
    /// follows a reader-drain timeout, a later release retry treats this
    /// closed global subscription as having no remaining volume references.
    pub fn shutdown_event_subscription(&mut self) -> Result<(), RemovableMediaError> {
        if self.subscription_closed {
            return Ok(());
        }
        if let Some(subscription) = self.subscription.as_mut() {
            subscription.shutdown()?;
        }
        self.subscription = None;
        self.subscription_closed = true;
        Ok(())
    }

    /// Cancel readers and release only this adapter's per-volume handles.
    ///
    /// This is intentionally separate from [`Self::safe_eject`]: it never
    /// calls [`PlatformVolumeBackend::request_eject`], never unmounts, and
    /// never reports that the operating system ejected a volume. Once it
    /// returns `Released`, the exact generation remains reader-fenced until a
    /// later reconciliation observes it absent or changed.
    pub fn release_media_handles(
        &mut self,
        generation: &VolumeGeneration,
    ) -> Result<ReleaseMediaHandlesOutcome, RemovableMediaError> {
        let release = self.begin_handle_release(generation)?;
        if release.active_readers > 0 {
            return Ok(ReleaseMediaHandlesOutcome::Busy {
                active_readers: release.active_readers,
            });
        }
        self.complete_handle_release(generation, release.phase)?;
        Ok(ReleaseMediaHandlesOutcome::Released)
    }

    /// Cancel active readers, complete the adapter-only handle release, then
    /// make at most one non-forced native eject request for this exact live
    /// generation. It reuses a prior [`Self::release_media_handles`] boundary
    /// without re-running completed release hooks, except that a replacement
    /// subscription must release its own references.
    pub fn safe_eject(
        &mut self,
        generation: &VolumeGeneration,
    ) -> Result<SafeEjectOutcome, RemovableMediaError> {
        self.ensure_subscription_active()?;
        let ReleaseBegin {
            active_readers,
            phase,
            ..
        } = self.begin_handle_release(generation)?;
        if active_readers > 0 {
            return Ok(SafeEjectOutcome::Busy { active_readers });
        }
        let completed_eject = phase.completed_eject();
        let indeterminate_eject = phase.indeterminate_eject_message().map(str::to_string);
        self.complete_handle_release(generation, phase)?;
        if let Some(outcome) = completed_eject {
            return Ok(outcome.into());
        }
        if let Some(message) = indeterminate_eject {
            return Err(RemovableMediaError::Eject(format!(
                "the prior native eject result is indeterminate; reconcile the mounted volume before another eject request: {message}"
            )));
        }
        let volume = self.refresh_exact_generation_for_eject(generation)?;

        let outcome = match self.backend.request_eject(&volume) {
            Ok(outcome) => outcome,
            Err(error) => {
                let message = sanitize_platform_message(&error.to_string());
                self.catalog
                    .mark_eject_indeterminate(generation, message.clone())?;
                return Err(RemovableMediaError::Eject(format!(
                    "native eject returned an indeterminate error; reconcile before retrying: {message}"
                )));
            }
        };
        match outcome {
            PlatformEjectOutcome::Ejected => {
                let completed = CompletedEjectOutcome::Ejected;
                self.catalog
                    .mark_eject_completed(generation, completed.clone())?;
                Ok(completed.into())
            }
            PlatformEjectOutcome::ReleasedForSystemEject { reason } => {
                let completed = CompletedEjectOutcome::ReleasedForSystemEject {
                    reason: sanitize_eject_reason(reason),
                };
                self.catalog
                    .mark_eject_completed(generation, completed.clone())?;
                Ok(completed.into())
            }
            PlatformEjectOutcome::Vetoed { code, reason } => {
                // The native service refused, but the adapter-only release
                // already succeeded. Keep the exact generation fenced rather
                // than reopening readers whose platform handles were closed.
                Ok(SafeEjectOutcome::Vetoed {
                    code,
                    reason: sanitize_platform_message(&reason),
                })
            }
        }
    }

    fn begin_handle_release(
        &self,
        generation: &VolumeGeneration,
    ) -> Result<ReleaseBegin, RemovableMediaError> {
        self.catalog
            .begin_release(generation)
            .map_err(|error| RemovableMediaError::Release(error.to_string()))
    }

    /// Advance exactly the still-pending external release hooks. Each phase is
    /// persisted in the catalog only after its hook returns successfully, so
    /// a failed second hook is retried without releasing the same subscription
    /// a second time or reopening reader access. A newer subscription epoch is
    /// a distinct owner and must execute its own release hook.
    fn complete_handle_release(
        &mut self,
        generation: &VolumeGeneration,
        mut phase: ReleasePhase,
    ) -> Result<(), RemovableMediaError> {
        if phase.subscription_epoch() != Some(self.subscription_epoch) {
            if let Some(subscription) = self.subscription.as_mut() {
                subscription.release_volume(generation)?;
            }
            phase = self
                .catalog
                .mark_subscription_released(generation, self.subscription_epoch)?;
        }
        if matches!(&phase, ReleasePhase::SubscriptionReleased { .. }) {
            self.backend.release_volume_handles(generation)?;
            phase = self.catalog.mark_handles_released(generation)?;
        }
        if !phase.handles_released() {
            return Err(RemovableMediaError::Release(
                "mounted-volume handle release did not reach a released phase".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_subscription_active(&self) -> Result<(), RemovableMediaError> {
        if self.subscription.is_some() && !self.subscription_closed {
            Ok(())
        } else {
            Err(RemovableMediaError::Subscription(
                if self.subscription_closed {
                    "mounted-volume subscription was shut down and cannot be restarted"
                } else {
                    "mounted-volume subscription has not been activated"
                }
                .to_string(),
            ))
        }
    }

    fn ensure_not_closed(&self) -> Result<(), RemovableMediaError> {
        if self.subscription_closed {
            Err(RemovableMediaError::Subscription(
                "mounted-volume subscription was shut down and cannot be restarted".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Reconcile immediately before a native action. This both refreshes
    /// backend-owned native targets and closes the stale-generation window
    /// between handle release and a physical eject request.
    fn refresh_exact_generation_for_eject(
        &mut self,
        generation: &VolumeGeneration,
    ) -> Result<MountedVolume, RemovableMediaError> {
        self.refresh()?;
        self.catalog
            .snapshot()?
            .get(generation.identity())
            .filter(|volume| &volume.generation == generation)
            .cloned()
            .ok_or_else(|| {
                RemovableMediaError::Eject(format!(
                    "mounted-volume generation {} at epoch {} changed before native eject",
                    generation.identity(),
                    generation.epoch().get()
                ))
            })
    }

    fn publish_reconciled(
        &mut self,
        next: BTreeMap<VolumeIdentity, PlatformMountedVolume>,
    ) -> Result<ReconcileReport, RemovableMediaError> {
        if next == self.descriptors {
            return Ok(ReconcileReport {
                snapshot: self.catalog.snapshot()?,
                changes: Vec::new(),
            });
        }
        let next_value = self
            .last_epoch
            .get()
            .checked_add(1)
            .ok_or(RemovableMediaError::EpochExhausted)?;
        let epoch = ObservationEpoch(next_value);
        let previous = self.catalog.snapshot()?;
        let snapshot = Arc::new(snapshot_from_descriptors(
            &next,
            Some((&self.descriptors, &previous)),
            epoch,
        ));
        let changes = diff_snapshots(&previous, &snapshot);

        // Publish to live readers before replacing the coordinator's private
        // descriptor state. A catalog failure therefore leaves the last good
        // coordinator observation intact and retryable.
        self.catalog.publish(snapshot.clone())?;
        self.descriptors = next;
        self.last_epoch = epoch;
        Ok(ReconcileReport { snapshot, changes })
    }
}

fn canonicalize(
    observations: Vec<PlatformMountedVolume>,
) -> Result<BTreeMap<VolumeIdentity, PlatformMountedVolume>, RemovableMediaError> {
    let mut canonical = BTreeMap::<VolumeIdentity, PlatformMountedVolume>::new();
    for mut observation in observations {
        observation.mount_paths.sort();
        observation.mount_paths.dedup();
        observation
            .mount_paths
            .retain(|path| ordinary_user_can_read_mount(path));
        if observation.mount_paths.is_empty() {
            continue;
        }

        match canonical.get_mut(&observation.identity) {
            None => {
                canonical.insert(observation.identity.clone(), observation);
            }
            Some(existing) => merge_observation(existing, observation)?,
        }
    }
    Ok(canonical)
}

fn ordinary_user_can_read_mount(path: &Path) -> bool {
    path.is_absolute()
        && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
        && std::fs::read_dir(path).is_ok()
}

fn merge_observation(
    existing: &mut PlatformMountedVolume,
    mut other: PlatformMountedVolume,
) -> Result<(), RemovableMediaError> {
    if existing.filesystem.is_some()
        && other.filesystem.is_some()
        && existing.filesystem != other.filesystem
    {
        return Err(RemovableMediaError::InvalidObservation(format!(
            "volume {} was reported with conflicting filesystem hints",
            existing.identity
        )));
    }
    if existing.capacity_bytes.is_some()
        && other.capacity_bytes.is_some()
        && existing.capacity_bytes != other.capacity_bytes
    {
        return Err(RemovableMediaError::InvalidObservation(format!(
            "volume {} was reported with conflicting capacities",
            existing.identity
        )));
    }
    if existing.presence_marker.is_some()
        && other.presence_marker.is_some()
        && existing.presence_marker != other.presence_marker
    {
        return Err(RemovableMediaError::InvalidObservation(format!(
            "volume {} was reported with conflicting presence markers",
            existing.identity
        )));
    }

    existing.mount_paths.append(&mut other.mount_paths);
    existing.mount_paths.sort();
    existing.mount_paths.dedup();
    existing.filesystem = existing.filesystem.take().or(other.filesystem);
    existing.capacity_bytes = existing.capacity_bytes.or(other.capacity_bytes);
    existing.presence_marker = existing.presence_marker.take().or(other.presence_marker);
    existing.read_only = existing.read_only.merge(other.read_only);
    existing.removable = existing.removable.merge(other.removable);
    Ok(())
}

fn snapshot_from_descriptors(
    descriptors: &BTreeMap<VolumeIdentity, PlatformMountedVolume>,
    previous: Option<(
        &BTreeMap<VolumeIdentity, PlatformMountedVolume>,
        &MountedVolumeSnapshot,
    )>,
    epoch: ObservationEpoch,
) -> MountedVolumeSnapshot {
    let volumes = descriptors
        .iter()
        .map(|(identity, descriptor)| {
            let preserved = previous.and_then(|(previous_descriptors, previous_snapshot)| {
                (previous_descriptors.get(identity) == Some(descriptor))
                    .then(|| previous_snapshot.get(identity))
                    .flatten()
                    .map(|volume| volume.generation.clone())
            });
            MountedVolume {
                generation: preserved.unwrap_or_else(|| VolumeGeneration {
                    identity: identity.clone(),
                    epoch,
                }),
                mount_paths: descriptor.mount_paths.clone(),
                filesystem: descriptor.filesystem.clone(),
                read_only: descriptor.read_only,
                removable: descriptor.removable,
                capacity_bytes: descriptor.capacity_bytes,
            }
        })
        .collect();
    MountedVolumeSnapshot { epoch, volumes }
}

fn diff_snapshots(
    previous: &MountedVolumeSnapshot,
    current: &MountedVolumeSnapshot,
) -> Vec<VolumeChange> {
    let mut changes = Vec::new();
    for old in &previous.volumes {
        match current.get(old.generation.identity()) {
            None => changes.push(VolumeChange::Removed(old.clone())),
            Some(new) if new != old => changes.push(VolumeChange::Updated {
                previous: old.clone(),
                current: new.clone(),
            }),
            Some(_) => {}
        }
    }
    for new in &current.volumes {
        if previous.get(new.generation.identity()).is_none() {
            changes.push(VolumeChange::Added(new.clone()));
        }
    }
    changes
}

/// Linux backends and their explicit UDisks2 availability boundary.
#[cfg(target_os = "linux")]
mod linux_fallback {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::{
        platform_error, shutdown_subscription_worker, EjectUnavailableReason, EvidenceHint,
        PlatformEjectOutcome, PlatformMountedVolume, PlatformVolumeBackend, RemovableMediaError,
        SubscriptionDrain, VolumeEventSubscription, VolumeGeneration, VolumeIdentity,
        SUBSCRIPTION_SHUTDOWN_TIMEOUT,
    };

    const DEFAULT_MOUNTINFO: &str = "/proc/self/mountinfo";

    /// Dependency-free Linux fallback. It polls mountinfo changes and performs
    /// full reconciliation; removable status is a best-effort sysfs hint.
    /// It cannot subscribe to UDisks2 object identity or perform native eject.
    pub struct LinuxMountInfoBackend {
        mountinfo_path: PathBuf,
        poll_interval: Duration,
    }

    impl Default for LinuxMountInfoBackend {
        fn default() -> Self {
            Self {
                mountinfo_path: PathBuf::from(DEFAULT_MOUNTINFO),
                poll_interval: Duration::from_millis(750),
            }
        }
    }

    impl LinuxMountInfoBackend {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Alternate path/period for containerized hosts and deterministic
        /// adapter contract tests. No path is ever opened for writing.
        #[must_use]
        pub fn with_mountinfo(path: PathBuf, poll_interval: Duration) -> Self {
            Self {
                mountinfo_path: path,
                poll_interval: poll_interval.max(Duration::from_millis(50)),
            }
        }
    }

    pub struct MountInfoSubscription {
        invalidations: Receiver<()>,
        stop: mpsc::Sender<()>,
        worker: Option<JoinHandle<()>>,
    }

    impl VolumeEventSubscription for MountInfoSubscription {
        fn drain(&mut self) -> Result<SubscriptionDrain, RemovableMediaError> {
            let mut invalidations = 0usize;
            loop {
                match self.invalidations.try_recv() {
                    Ok(()) => invalidations = invalidations.saturating_add(1),
                    Err(TryRecvError::Empty) => {
                        return Ok(SubscriptionDrain {
                            invalidations,
                            disconnected: false,
                        });
                    }
                    Err(TryRecvError::Disconnected) => {
                        return Ok(SubscriptionDrain {
                            invalidations,
                            disconnected: true,
                        });
                    }
                }
            }
        }

        fn shutdown(&mut self) -> Result<(), RemovableMediaError> {
            let _ = self.stop.send(());
            shutdown_subscription_worker(
                &mut self.worker,
                SUBSCRIPTION_SHUTDOWN_TIMEOUT,
                "mountinfo event worker",
            )
        }
    }

    impl Drop for MountInfoSubscription {
        fn drop(&mut self) {
            let _ = self.shutdown();
        }
    }

    impl PlatformVolumeBackend for LinuxMountInfoBackend {
        type Subscription = MountInfoSubscription;

        fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
            let mut previous = fs::read(&self.mountinfo_path)
                .map_err(|error| platform_error(RemovableMediaError::Subscription, error))?;
            let path = self.mountinfo_path.clone();
            let interval = self.poll_interval;
            let (notify_tx, notify_rx) = mpsc::sync_channel(1);
            let (stop_tx, stop_rx) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("ylx-mountinfo-watch".to_string())
                .spawn(move || {
                    mountinfo_watch_loop(path, interval, &mut previous, notify_tx, stop_rx)
                })
                .map_err(|error| platform_error(RemovableMediaError::Subscription, error))?;
            Ok(MountInfoSubscription {
                invalidations: notify_rx,
                stop: stop_tx,
                worker: Some(worker),
            })
        }

        fn enumerate_mounted_readable(
            &mut self,
        ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
            let value = fs::read(&self.mountinfo_path)
                .map_err(|error| platform_error(RemovableMediaError::Enumeration, error))?;
            parse_mountinfo(&value)
        }

        fn request_eject(
            &mut self,
            _volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
            Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::NativeServiceUnavailable,
            })
        }
    }

    fn mountinfo_watch_loop(
        path: PathBuf,
        interval: Duration,
        previous: &mut Vec<u8>,
        notify: SyncSender<()>,
        stop: Receiver<()>,
    ) {
        loop {
            match stop.recv_timeout(interval) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let Ok(current) = fs::read(&path) else {
                // Dropping the sender marks the event source disconnected.
                return;
            };
            if current != *previous {
                *previous = current;
                // A bounded channel coalesces bursts; reconciliation never
                // depends on an exact native event count.
                let _ = notify.try_send(());
            }
        }
    }

    fn parse_mountinfo(value: &[u8]) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
        let text = std::str::from_utf8(value).map_err(|_| {
            RemovableMediaError::Enumeration("mountinfo was not valid UTF-8".to_string())
        })?;
        let mut volumes = Vec::new();
        for line in text.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                return Err(RemovableMediaError::Enumeration(
                    "mountinfo record lacked separator".to_string(),
                ));
            };
            let left: Vec<&str> = left.split_ascii_whitespace().collect();
            let right: Vec<&str> = right.split_ascii_whitespace().collect();
            if left.len() < 6 || right.len() < 3 {
                return Err(RemovableMediaError::Enumeration(
                    "mountinfo record was truncated".to_string(),
                ));
            }
            let device = left[2];
            if !valid_major_minor(device) {
                return Err(RemovableMediaError::Enumeration(
                    "mountinfo device number was malformed".to_string(),
                ));
            }
            let mount_path = decode_mountinfo_path(left[4])?;
            let filesystem = right[0];
            let source = right[1];
            if !volume_backed_mount(filesystem, source, &mount_path) {
                continue;
            }
            let identity = VolumeIdentity::new(format!("linux-block:{device}"))?;
            let read_only = if left[5].split(',').any(|option| option == "ro") {
                EvidenceHint::Yes
            } else if left[5].split(',').any(|option| option == "rw") {
                EvidenceHint::No
            } else {
                EvidenceHint::Unknown
            };
            volumes.push(
                PlatformMountedVolume::new(identity, vec![mount_path])
                    .with_filesystem(filesystem)
                    .with_read_only(read_only)
                    .with_removable(sysfs_removable_hint(device)),
            );
        }
        Ok(volumes)
    }

    fn valid_major_minor(value: &str) -> bool {
        let Some((major, minor)) = value.split_once(':') else {
            return false;
        };
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|byte| byte.is_ascii_digit())
            && minor.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn decode_mountinfo_path(value: &str) -> Result<PathBuf, RemovableMediaError> {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                if index + 3 >= bytes.len()
                    || !bytes[index + 1..index + 4]
                        .iter()
                        .all(|byte| matches!(byte, b'0'..=b'7'))
                {
                    return Err(RemovableMediaError::Enumeration(
                        "mountinfo path contained malformed escape".to_string(),
                    ));
                }
                let byte = (bytes[index + 1] - b'0') * 64
                    + (bytes[index + 2] - b'0') * 8
                    + (bytes[index + 3] - b'0');
                decoded.push(byte);
                index += 4;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        if decoded.contains(&0) {
            return Err(RemovableMediaError::Enumeration(
                "mountinfo path contained NUL".to_string(),
            ));
        }
        Ok(PathBuf::from(OsString::from_vec(decoded)))
    }

    fn volume_backed_mount(filesystem: &str, source: &str, mount_path: &Path) -> bool {
        if mount_path == Path::new("/") || !source.starts_with("/dev/") {
            return false;
        }
        let source_name = source.rsplit('/').next().unwrap_or(source);
        if source_name.starts_with("loop") || source_name.starts_with("zram") {
            return false;
        }
        !matches!(
            filesystem,
            "proc"
                | "sysfs"
                | "devtmpfs"
                | "devpts"
                | "tmpfs"
                | "cgroup"
                | "cgroup2"
                | "overlay"
                | "squashfs"
                | "autofs"
                | "fusectl"
                | "securityfs"
                | "debugfs"
                | "tracefs"
                | "configfs"
                | "pstore"
                | "mqueue"
                | "hugetlbfs"
                | "bpf"
                | "nsfs"
        )
    }

    fn sysfs_removable_hint(device: &str) -> EvidenceHint {
        let path = PathBuf::from("/sys/dev/block").join(device);
        let Ok(mut current) = fs::canonicalize(path) else {
            return EvidenceHint::Unknown;
        };
        loop {
            let candidate = current.join("removable");
            if let Ok(value) = fs::read_to_string(candidate) {
                return match value.trim() {
                    "1" => EvidenceHint::Yes,
                    "0" => EvidenceHint::No,
                    _ => EvidenceHint::Unknown,
                };
            }
            if !current.pop() {
                return EvidenceHint::Unknown;
            }
        }
    }

    /// Low-level UDisks2 record. A real bridge obtains these only from
    /// Filesystem objects with non-empty MountPoints; it does not call Mount.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UDisks2Filesystem {
        pub identity: VolumeIdentity,
        pub mount_points: Vec<Vec<u8>>,
        pub filesystem: Option<String>,
        pub read_only: EvidenceHint,
        pub removable: EvidenceHint,
        pub capacity_bytes: Option<u64>,
        pub presence_marker: Option<String>,
        pub hint_system: bool,
        pub hint_ignore: bool,
    }

    /// Dependency seam for a `zbus` UDisks2 ObjectManager implementation.
    /// `subscribe_filesystem_changes` must register InterfacesAdded/Removed
    /// and PropertiesChanged before `enumerate_mounted_filesystems` runs.
    pub trait UDisks2Api: Send {
        type Subscription: VolumeEventSubscription;

        fn subscribe_filesystem_changes(
            &mut self,
        ) -> Result<Self::Subscription, RemovableMediaError>;
        fn enumerate_mounted_filesystems(
            &mut self,
        ) -> Result<Vec<UDisks2Filesystem>, RemovableMediaError>;
        fn release_volume_handles(
            &mut self,
            _generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            Ok(())
        }
        fn request_drive_eject(
            &mut self,
            volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError>;
    }

    pub struct UDisks2Backend<A> {
        api: A,
    }

    impl<A> UDisks2Backend<A> {
        #[must_use]
        pub const fn new(api: A) -> Self {
            Self { api }
        }
    }

    impl<A: UDisks2Api> PlatformVolumeBackend for UDisks2Backend<A> {
        type Subscription = A::Subscription;

        fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
            self.api.subscribe_filesystem_changes()
        }

        fn enumerate_mounted_readable(
            &mut self,
        ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
            self.api
                .enumerate_mounted_filesystems()?
                .into_iter()
                .filter(|volume| !volume.hint_system && !volume.hint_ignore)
                .map(udisks2_observation)
                .collect()
        }

        fn release_volume_handles(
            &mut self,
            generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            self.api.release_volume_handles(generation)
        }

        fn request_eject(
            &mut self,
            volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
            self.api.request_drive_eject(volume)
        }
    }

    fn udisks2_observation(
        volume: UDisks2Filesystem,
    ) -> Result<PlatformMountedVolume, RemovableMediaError> {
        let mut mount_paths = Vec::with_capacity(volume.mount_points.len());
        for mut bytes in volume.mount_points {
            if bytes.last() == Some(&0) {
                bytes.pop();
            }
            if bytes.is_empty() || bytes.contains(&0) {
                return Err(RemovableMediaError::InvalidObservation(
                    "UDisks2 mount point was empty or contained NUL".to_string(),
                ));
            }
            mount_paths.push(PathBuf::from(OsString::from_vec(bytes)));
        }
        let mut observation = PlatformMountedVolume::new(volume.identity, mount_paths)
            .with_read_only(volume.read_only)
            .with_removable(volume.removable)
            .with_capacity_bytes(volume.capacity_bytes);
        if let Some(filesystem) = volume.filesystem {
            observation = observation.with_filesystem(filesystem);
        }
        if let Some(marker) = volume.presence_marker {
            observation = observation.with_presence_marker(marker);
        }
        Ok(observation)
    }
}

#[cfg(target_os = "linux")]
#[path = "removable_media/linux.rs"]
pub mod linux;

/// Target-gated dependency seam for Windows Volume GUID enumeration and PnP
/// notifications/eject. A concrete bridge should use `FindFirstVolumeW`,
/// `GetVolumePathNamesForVolumeNameW`, `CM_Register_Notification`, and
/// `CM_Request_Device_EjectW`; it must never force-dismount a volume.
#[cfg(target_os = "windows")]
mod windows_seam {
    use std::path::PathBuf;

    use super::{
        EvidenceHint, PlatformEjectOutcome, PlatformMountedVolume, PlatformVolumeBackend,
        RemovableMediaError, VolumeEventSubscription, VolumeGeneration, VolumeIdentity,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WindowsMountedVolume {
        /// Canonical `\\?\Volume{GUID}\` string returned by the volume API.
        pub volume_guid: String,
        /// Every drive-letter and directory mount point returned by
        /// `GetVolumePathNamesForVolumeNameW`.
        pub mount_paths: Vec<PathBuf>,
        pub filesystem: Option<String>,
        pub read_only: EvidenceHint,
        pub removable: EvidenceHint,
        pub capacity_bytes: Option<u64>,
        pub device_instance_marker: Option<String>,
    }

    pub trait WindowsVolumeApi: Send {
        type Subscription: VolumeEventSubscription;

        fn register_pnp_notifications(&mut self)
            -> Result<Self::Subscription, RemovableMediaError>;
        fn enumerate_volume_guids(
            &mut self,
        ) -> Result<Vec<WindowsMountedVolume>, RemovableMediaError>;
        fn release_volume_handles(
            &mut self,
            _generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            Ok(())
        }
        /// Map `CR_SUCCESS` to Ejected and `PNP_VetoType`/veto name to
        /// Vetoed. Access-denied/unsupported paths map to
        /// ReleasedForSystemEject, not Ejected.
        fn request_pnp_eject(
            &mut self,
            volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError>;
    }

    pub struct WindowsVolumeBackend<A> {
        api: A,
    }

    impl<A> WindowsVolumeBackend<A> {
        #[must_use]
        pub const fn new(api: A) -> Self {
            Self { api }
        }
    }

    impl<A: WindowsVolumeApi> PlatformVolumeBackend for WindowsVolumeBackend<A> {
        type Subscription = A::Subscription;

        fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
            self.api.register_pnp_notifications()
        }

        fn enumerate_mounted_readable(
            &mut self,
        ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
            self.api
                .enumerate_volume_guids()?
                .into_iter()
                .map(|volume| {
                    let identity = VolumeIdentity::from_native(
                        "windows-volume",
                        volume.volume_guid.as_bytes(),
                    )?;
                    let mut observation = PlatformMountedVolume::new(identity, volume.mount_paths)
                        .with_read_only(volume.read_only)
                        .with_removable(volume.removable)
                        .with_capacity_bytes(volume.capacity_bytes);
                    if let Some(filesystem) = volume.filesystem {
                        observation = observation.with_filesystem(filesystem);
                    }
                    if let Some(marker) = volume.device_instance_marker {
                        observation = observation.with_presence_marker(marker);
                    }
                    Ok(observation)
                })
                .collect()
        }

        fn release_volume_handles(
            &mut self,
            generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            self.api.release_volume_handles(generation)
        }

        fn request_eject(
            &mut self,
            volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
            self.api.request_pnp_eject(volume)
        }
    }
}

#[cfg(target_os = "windows")]
#[path = "removable_media/windows.rs"]
pub mod windows;

/// Target-gated dependency seam for mounted-volume URL enumeration and Disk
/// Arbitration notifications/eject on macOS. The concrete bridge owns
/// security-scoped access and reports permission denial explicitly.
#[cfg(target_os = "macos")]
mod macos_seam {
    use std::path::PathBuf;

    use super::{
        EvidenceHint, PlatformEjectOutcome, PlatformMountedVolume, PlatformVolumeBackend,
        RemovableMediaError, VolumeEventSubscription, VolumeGeneration, VolumeIdentity,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MacOsMountedVolume {
        /// Opaque resource identity resolved from mounted-volume URL resource
        /// values and its Disk Arbitration disk, never `/Volumes/...` text.
        pub volume_identity: String,
        pub mounted_urls: Vec<PathBuf>,
        pub filesystem: Option<String>,
        pub read_only: EvidenceHint,
        pub removable: EvidenceHint,
        pub capacity_bytes: Option<u64>,
        pub disk_instance_marker: Option<String>,
    }

    pub trait MacOsVolumeApi: Send {
        type Subscription: VolumeEventSubscription;

        fn register_disk_arbitration_callbacks(
            &mut self,
        ) -> Result<Self::Subscription, RemovableMediaError>;
        fn enumerate_mounted_volume_urls(
            &mut self,
        ) -> Result<Vec<MacOsMountedVolume>, RemovableMediaError>;
        fn release_volume_handles(
            &mut self,
            _generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            Ok(())
        }
        fn request_disk_arbitration_eject(
            &mut self,
            volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError>;
    }

    pub struct MacOsVolumeBackend<A> {
        api: A,
    }

    impl<A> MacOsVolumeBackend<A> {
        #[must_use]
        pub const fn new(api: A) -> Self {
            Self { api }
        }
    }

    impl<A: MacOsVolumeApi> PlatformVolumeBackend for MacOsVolumeBackend<A> {
        type Subscription = A::Subscription;

        fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
            self.api.register_disk_arbitration_callbacks()
        }

        fn enumerate_mounted_readable(
            &mut self,
        ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
            self.api
                .enumerate_mounted_volume_urls()?
                .into_iter()
                .map(|volume| {
                    let identity = VolumeIdentity::from_native(
                        "macos-volume",
                        volume.volume_identity.as_bytes(),
                    )?;
                    let mut observation = PlatformMountedVolume::new(identity, volume.mounted_urls)
                        .with_read_only(volume.read_only)
                        .with_removable(volume.removable)
                        .with_capacity_bytes(volume.capacity_bytes);
                    if let Some(filesystem) = volume.filesystem {
                        observation = observation.with_filesystem(filesystem);
                    }
                    if let Some(marker) = volume.disk_instance_marker {
                        observation = observation.with_presence_marker(marker);
                    }
                    Ok(observation)
                })
                .collect()
        }

        fn release_volume_handles(
            &mut self,
            generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            self.api.release_volume_handles(generation)
        }

        fn request_eject(
            &mut self,
            volume: &super::MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
            self.api.request_disk_arbitration_eject(volume)
        }
    }
}

#[cfg(target_os = "macos")]
#[path = "removable_media/macos.rs"]
pub mod macos;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    struct FakeSubscription {
        drains: VecDeque<SubscriptionDrain>,
        released: Arc<Mutex<Vec<VolumeGeneration>>>,
    }

    impl VolumeEventSubscription for FakeSubscription {
        fn drain(&mut self) -> Result<SubscriptionDrain, RemovableMediaError> {
            Ok(self.drains.pop_front().unwrap_or_default())
        }

        fn release_volume(
            &mut self,
            generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            self.released
                .lock()
                .expect("release log")
                .push(generation.clone());
            Ok(())
        }
    }

    struct FakeBackend {
        call_order: Arc<Mutex<Vec<&'static str>>>,
        enumerations: VecDeque<Vec<PlatformMountedVolume>>,
        subscription: Option<FakeSubscription>,
        release_failures: VecDeque<RemovableMediaError>,
        eject: PlatformEjectOutcome,
    }

    impl PlatformVolumeBackend for FakeBackend {
        type Subscription = FakeSubscription;

        fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
            self.call_order.lock().expect("call log").push("subscribe");
            self.subscription.take().ok_or_else(|| {
                RemovableMediaError::Subscription("subscription already taken".to_string())
            })
        }

        fn enumerate_mounted_readable(
            &mut self,
        ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
            self.call_order.lock().expect("call log").push("enumerate");
            self.enumerations
                .pop_front()
                .ok_or_else(|| RemovableMediaError::Enumeration("no fake enumeration".to_string()))
        }

        fn release_volume_handles(
            &mut self,
            _generation: &VolumeGeneration,
        ) -> Result<(), RemovableMediaError> {
            self.call_order
                .lock()
                .expect("call log")
                .push("release_backend");
            match self.release_failures.pop_front() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn request_eject(
            &mut self,
            _volume: &MountedVolume,
        ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
            self.call_order.lock().expect("call log").push("eject");
            Ok(self.eject.clone())
        }
    }

    struct TestMount {
        path: PathBuf,
    }

    impl TestMount {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("ylx-removable-media-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create test mount");
            Self { path }
        }
    }

    impl Drop for TestMount {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn observation(identity: &str, path: PathBuf) -> PlatformMountedVolume {
        PlatformMountedVolume::new(VolumeIdentity::new(identity).expect("identity"), vec![path])
            .with_filesystem("exfat")
            .with_read_only(EvidenceHint::No)
            .with_removable(EvidenceHint::Yes)
    }

    fn backend(
        enumerations: Vec<Vec<PlatformMountedVolume>>,
        drains: Vec<SubscriptionDrain>,
        eject: PlatformEjectOutcome,
    ) -> (FakeBackend, Arc<Mutex<Vec<&'static str>>>) {
        let call_order = Arc::new(Mutex::new(Vec::new()));
        (
            FakeBackend {
                call_order: call_order.clone(),
                enumerations: enumerations.into(),
                subscription: Some(FakeSubscription {
                    drains: drains.into(),
                    released: Arc::new(Mutex::new(Vec::new())),
                }),
                release_failures: VecDeque::new(),
                eject,
            },
            call_order,
        )
    }

    #[test]
    fn start_subscribes_before_enumerating() {
        let mount = TestMount::new("subscribe-first");
        let (backend, calls) = backend(
            vec![vec![observation("volume-a", mount.path.clone())]],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let adapter = RemovableMediaAdapter::start(backend).expect("start");
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            ["subscribe", "enumerate"]
        );
        assert_eq!(adapter.snapshot().expect("snapshot").volumes.len(), 1);
    }

    #[test]
    fn inactive_adapter_defers_and_idempotently_activates_native_discovery() {
        let mount = TestMount::new("deferred-activation");
        let (backend, calls) = backend(
            vec![vec![observation("volume-a", mount.path.clone())]],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::inactive(backend);

        assert!(calls.lock().expect("call log").is_empty());
        assert!(adapter.snapshot().expect("snapshot").volumes.is_empty());

        let first = adapter.activate_and_refresh().expect("activate");
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            ["subscribe", "enumerate"]
        );
        assert_eq!(first.snapshot.volumes.len(), 1);

        let second = adapter.activate_and_refresh().expect("idempotent activate");
        assert_eq!(second.snapshot, first.snapshot);
        assert!(second.changes.is_empty());
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            ["subscribe", "enumerate"]
        );
    }

    #[test]
    fn inactive_adapter_can_shutdown_without_starting_native_discovery() {
        let (backend, calls) = backend(
            Vec::new(),
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::inactive(backend);

        adapter
            .shutdown_event_subscription()
            .expect("shutdown inactive adapter");
        adapter
            .shutdown_event_subscription()
            .expect("shutdown remains idempotent");
        assert!(calls.lock().expect("call log").is_empty());
        assert!(matches!(
            adapter.activate_and_refresh(),
            Err(RemovableMediaError::Subscription(_))
        ));
    }

    #[test]
    fn subscription_worker_timeout_retains_the_handle_for_a_later_retry() {
        let (release, blocked) = std::sync::mpsc::channel();
        let mut worker = Some(std::thread::spawn(move || {
            let _ = blocked.recv();
        }));

        assert!(shutdown_subscription_worker(
            &mut worker,
            Duration::from_millis(5),
            "test subscription worker",
        )
        .is_err());
        assert!(worker.is_some());

        release.send(()).expect("release worker");
        shutdown_subscription_worker(
            &mut worker,
            Duration::from_secs(1),
            "test subscription worker",
        )
        .expect("retry shutdown");
        assert!(worker.is_none());
    }

    #[test]
    fn duplicate_and_out_of_order_hints_are_idempotent() {
        let mount = TestMount::new("idempotent");
        let same = vec![observation("volume-a", mount.path.clone())];
        let (backend, _) = backend(
            vec![same.clone(), same],
            vec![SubscriptionDrain {
                invalidations: 7,
                disconnected: false,
            }],
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let initial = adapter.snapshot().expect("snapshot");
        let report = adapter.poll_events().expect("poll");
        assert!(report.refreshed);
        assert!(report.changes.is_empty());
        assert_eq!(report.snapshot.epoch, initial.epoch);
        assert_eq!(
            report.snapshot.volumes[0].generation,
            initial.volumes[0].generation
        );
    }

    #[test]
    fn path_reuse_by_another_identity_cancels_old_reader() {
        let mount = TestMount::new("path-reuse");
        let (backend, _) = backend(
            vec![
                vec![observation("volume-a", mount.path.clone())],
                vec![observation("volume-b", mount.path.clone())],
            ],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let first = adapter.snapshot().expect("snapshot").volumes[0]
            .generation
            .clone();
        let catalog = adapter.catalog();
        let media = MediaGenerationId::from_material(b"path-reuse-media");
        catalog
            .bind_media_generation(media.clone(), &first)
            .expect("bind generation");
        let lease = catalog.acquire_bound_reader(&media).expect("lease");
        let report = adapter.refresh().expect("refresh");
        assert!(lease.is_cancelled());
        assert!(!report.snapshot.contains_generation(&first));
        assert_eq!(
            report.snapshot.volumes[0].generation.identity().as_str(),
            "volume-b"
        );
    }

    #[test]
    fn eject_waits_for_reader_then_reports_unsupported_honestly() {
        let mount = TestMount::new("safe-eject");
        let same = vec![observation("volume-a", mount.path.clone())];
        let (backend, calls) = backend(
            vec![same.clone(), same],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let generation = adapter.snapshot().expect("snapshot").volumes[0]
            .generation
            .clone();
        let catalog = adapter.catalog();
        let media = MediaGenerationId::from_material(b"safe-eject-media");
        catalog
            .bind_media_generation(media.clone(), &generation)
            .expect("bind generation");
        let lease = catalog.acquire_bound_reader(&media).expect("lease");
        assert_eq!(
            adapter.safe_eject(&generation).expect("busy"),
            SafeEjectOutcome::Busy { active_readers: 1 }
        );
        assert!(lease.is_cancelled());
        drop(lease);
        assert_eq!(
            adapter.safe_eject(&generation).expect("release"),
            SafeEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported
            }
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            [
                "subscribe",
                "enumerate",
                "release_backend",
                "enumerate",
                "eject"
            ]
        );
    }

    #[test]
    fn release_handles_cancels_readers_without_requesting_native_eject() {
        let mount = TestMount::new("release-only-busy");
        let (backend, calls) = backend(
            vec![vec![observation("volume-a", mount.path.clone())]],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let generation = adapter.snapshot().expect("snapshot").volumes[0]
            .generation
            .clone();
        let catalog = adapter.catalog();
        let media = MediaGenerationId::from_material(b"release-only-busy-media");
        catalog
            .bind_media_generation(media.clone(), &generation)
            .expect("bind generation");
        let lease = catalog.acquire_bound_reader(&media).expect("lease");

        assert_eq!(
            adapter.release_media_handles(&generation).expect("busy"),
            ReleaseMediaHandlesOutcome::Busy { active_readers: 1 }
        );
        assert!(lease.is_cancelled());
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            ["subscribe", "enumerate"]
        );

        drop(lease);
        assert_eq!(
            adapter.release_media_handles(&generation).expect("release"),
            ReleaseMediaHandlesOutcome::Released
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            ["subscribe", "enumerate", "release_backend"]
        );
    }

    #[test]
    fn safe_eject_after_release_is_native_once_and_never_fakes_ejection() {
        let mount = TestMount::new("release-then-eject");
        let same = vec![observation("volume-a", mount.path.clone())];
        let (backend, calls) = backend(
            vec![same.clone(), same],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let generation = adapter.snapshot().expect("snapshot").volumes[0]
            .generation
            .clone();
        let released = Arc::clone(
            &adapter
                .subscription
                .as_ref()
                .expect("active subscription")
                .released,
        );

        assert_eq!(
            adapter.release_media_handles(&generation).expect("release"),
            ReleaseMediaHandlesOutcome::Released
        );
        assert_eq!(
            released.lock().expect("release log").as_slice(),
            std::slice::from_ref(&generation)
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            ["subscribe", "enumerate", "release_backend"]
        );

        let expected = SafeEjectOutcome::ReleasedForSystemEject {
            reason: EjectUnavailableReason::Unsupported,
        };
        assert_eq!(
            adapter.safe_eject(&generation).expect("native eject"),
            expected
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            [
                "subscribe",
                "enumerate",
                "release_backend",
                "enumerate",
                "eject"
            ]
        );
        assert_eq!(
            released.lock().expect("release log").as_slice(),
            std::slice::from_ref(&generation)
        );

        assert_eq!(
            adapter
                .safe_eject(&generation)
                .expect("cached eject result"),
            expected
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            [
                "subscribe",
                "enumerate",
                "release_backend",
                "enumerate",
                "eject"
            ]
        );
    }

    #[test]
    fn partial_handle_release_failure_keeps_the_generation_fenced_for_retry() {
        let mount = TestMount::new("partial-release-retry");
        let (backend, calls) = backend(
            vec![vec![observation("volume-a", mount.path.clone())]],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let generation = adapter.snapshot().expect("snapshot").volumes[0]
            .generation
            .clone();
        let catalog = adapter.catalog();
        let media = MediaGenerationId::from_material(b"partial-release-retry-media");
        catalog
            .bind_media_generation(media.clone(), &generation)
            .expect("bind generation");
        let released = Arc::clone(
            &adapter
                .subscription
                .as_ref()
                .expect("active subscription")
                .released,
        );
        adapter
            .backend
            .release_failures
            .push_back(RemovableMediaError::Release(
                "simulated backend release failure".to_string(),
            ));

        assert!(matches!(
            adapter.release_media_handles(&generation),
            Err(RemovableMediaError::Release(_))
        ));
        assert_eq!(
            released.lock().expect("release log").as_slice(),
            std::slice::from_ref(&generation)
        );
        assert!(matches!(
            catalog.acquire_bound_reader(&media),
            Err(MediaFenceError::Unavailable { .. })
        ));

        assert_eq!(
            adapter
                .release_media_handles(&generation)
                .expect("retry release"),
            ReleaseMediaHandlesOutcome::Released
        );
        assert_eq!(
            released.lock().expect("release log").as_slice(),
            std::slice::from_ref(&generation)
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            [
                "subscribe",
                "enumerate",
                "release_backend",
                "release_backend"
            ]
        );
    }

    #[test]
    fn partial_release_releases_replacement_subscription_before_retry_completes() {
        let mount = TestMount::new("partial-release-subscription-restart");
        let same = vec![observation("volume-a", mount.path.clone())];
        let (backend, calls) = backend(
            vec![same.clone(), same],
            Vec::new(),
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            },
        );
        let mut adapter = RemovableMediaAdapter::start(backend).expect("start");
        let generation = adapter.snapshot().expect("snapshot").volumes[0]
            .generation
            .clone();
        let first_releases = Arc::clone(
            &adapter
                .subscription
                .as_ref()
                .expect("active subscription")
                .released,
        );
        adapter
            .backend
            .release_failures
            .push_back(RemovableMediaError::Release(
                "simulated backend release failure".to_string(),
            ));

        assert!(matches!(
            adapter.release_media_handles(&generation),
            Err(RemovableMediaError::Release(_))
        ));
        assert_eq!(
            first_releases.lock().expect("first release log").as_slice(),
            std::slice::from_ref(&generation)
        );

        let replacement_releases = Arc::new(Mutex::new(Vec::new()));
        adapter.backend.subscription = Some(FakeSubscription {
            drains: VecDeque::new(),
            released: Arc::clone(&replacement_releases),
        });
        adapter
            .restart_subscription_and_refresh()
            .expect("restart subscription");

        assert_eq!(
            adapter
                .release_media_handles(&generation)
                .expect("retry release"),
            ReleaseMediaHandlesOutcome::Released
        );
        assert_eq!(
            first_releases.lock().expect("first release log").as_slice(),
            std::slice::from_ref(&generation)
        );
        assert_eq!(
            replacement_releases
                .lock()
                .expect("replacement release log")
                .as_slice(),
            [generation]
        );
        assert_eq!(
            calls.lock().expect("call log").as_slice(),
            [
                "subscribe",
                "enumerate",
                "release_backend",
                "subscribe",
                "enumerate",
                "release_backend"
            ]
        );
    }
}
