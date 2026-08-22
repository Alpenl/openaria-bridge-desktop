//! Ubuntu-only runtime for already-mounted removable recording media.
//!
//! This module deliberately stops at the ordinary Linux mounted-volume
//! boundary. It neither opens raw block devices nor mounts, repairs, writes,
//! or deletes anything on a card. The only discovery scope is the two
//! recording roots owned by the constrained core scanner. Every cached
//! candidate is bound to both a content-aware [`MediaGeneration`] and the
//! live Linux [`VolumeGeneration`] that supplied its bytes.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use ylx_transfer_adapters::mounted_file::{MediaReadLeaseProvider, MountedFileArtifactAdapter};
use ylx_transfer_adapters::publication_verifier::Ed25519PublicationVerifier;
use ylx_transfer_adapters::removable_media::linux::{
    supported_linux_native_filesystem, LinuxBackendKind, LinuxNativeBackend,
};
use ylx_transfer_adapters::removable_media::{
    AttachRefusalReason, EjectUnavailableReason, EvidenceHint, MountedVolume,
    MountedVolumeSnapshot, PlatformAttachReport, ReleaseMediaHandlesOutcome, RemovableMediaAdapter,
    RemovableMediaError, SafeEjectOutcome, VolumeCatalog, VolumeGeneration,
};
use ylx_transfer_core::ingest::{
    resolve_directory_no_links, resolve_regular_file_no_links, AcquisitionSourceId,
    CandidateId as CoreCandidateId, CandidateReadiness as CoreCandidateReadiness,
    ConstrainedScanner, ImportPolicy, InventoryDigest, InventoryHashesVerdict,
    ManifestSignatureVerdict, MediaGeneration, MediaGenerationId, MediaLocator,
    ProducerKeyTrustVerdict, SafeRelativePath, ScanCandidate as CoreScanCandidate, ScanDiagnostic,
    ScanDiagnosticCode, ScanLimits, ScanRequest as CoreScanRequest, ScanScope,
    ScanSnapshot as CoreScanSnapshot, SourceKind as CoreSourceKind, SourceRecording,
    SourceRevisionClaim, SourceSchema as CoreSourceSchema, UnsignedImportPolicy,
    UnsignedSourceAdmissionReceipt, MOUNTED_VOLUME_RECORDING_CONTAINERS,
};
use ylx_transfer_core::library::staging::STAGING_DIR_NAME;
use ylx_transfer_core::media_store::{MediaStore, TrustedProducerError, TrustedProducerRegistry};
use ylx_transfer_core::publication::PublicationTrust;
use ylx_transfer_core::recording_ingestor::{
    ArtifactSourceResolver, CandidateCatalog, IngestPortError, ResolvedArtifactSource,
};

use crate::application::RpcError;

use super::ports::{MediaErrorCode, MediaPortError, MediaScannerPort, Observed};
use super::types::{
    CandidateId as AppCandidateId, CandidateVerdict, InventoryIntegrity, MediaDescriptor,
    MediaEjectState, MediaHandleState, MediaId, MediaPresence, MediaScanSnapshot, MediaScanState,
    ProducerKeyTrust, ScanCandidate as AppScanCandidate, ScanRequest as AppScanRequest, ScanSource,
    SignatureVerdict, SourceKind as AppSourceKind, SourceProvenance as AppSourceProvenance,
    SourceSchema as AppSourceSchema, UnsignedAdmission, UnsignedSourceSchema,
};

const MAX_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_ROOT_MARKER_ENTRIES: usize = 2_048;
const MAX_ROOT_MARKER_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ROOT_MARKER_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const RUNTIME_RUNNING: u8 = 0;
const RUNTIME_STOPPING: u8 = 1;
const RUNTIME_STOPPED: u8 = 2;
const SHUTDOWN_READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_READER_POLL_INTERVAL: Duration = Duration::from_millis(20);
const ROOT_MARKERS: &[&str] = &[
    "publication_manifest.json",
    "capture.commit.json",
    "session.json",
    "encoding.json",
    "capture.json",
];

/// Synchronous Ubuntu import guard for proving that local output stays on a
/// PC filesystem rather than the source card (or another discovered volume).
///
/// Implementations must refresh mounted-volume discovery and fail closed when
/// either side's Linux filesystem identity cannot be established. Callers
/// hold the composition library-root gate around this check and all following
/// preflight, durable admission, staging, copy, and publication work.
pub trait UbuntuDestinationGuard: Send + Sync {
    fn ensure_pc_destination(&self, library_root: &Path) -> Result<(), MediaPortError>;

    fn destination_fence(
        &self,
        library_root: &Path,
    ) -> Result<UbuntuDestinationFence, MediaPortError> {
        self.ensure_pc_destination(library_root)?;
        Ok(UbuntuDestinationFence::new(0))
    }

    fn assert_pc_destination(
        &self,
        library_root: &Path,
        _fence: &UbuntuDestinationFence,
    ) -> Result<(), MediaPortError> {
        self.ensure_pc_destination(library_root)
    }
}

/// Process-local observation fence for the qualified removable-volume set.
/// The root-authority lease separately fences the configured library path;
/// this value avoids reopening every mount on each copy buffer while still
/// forcing a full destination check whenever native discovery advances.
#[derive(Debug)]
pub struct UbuntuDestinationFence {
    volume_epoch: AtomicU64,
}

impl UbuntuDestinationFence {
    fn new(volume_epoch: u64) -> Self {
        Self {
            volume_epoch: AtomicU64::new(volume_epoch),
        }
    }
}

/// One opened Linux directory and the identity observed through that handle.
/// Retaining the handle until the complete comparison finishes prevents an
/// unmount/path reuse from silently changing the meaning of an earlier stat.
struct OpenLinuxDirectory {
    canonical_path: PathBuf,
    device: u64,
    _inode: u64,
    _handle: File,
}

/// One core candidate plus the live Linux locator that was current while it
/// was scanned. The mount path never becomes part of a durable identity; it
/// is merely the current byte-acquisition detail guarded by `volume_generation`.
#[derive(Clone)]
struct CachedCandidate {
    candidate: CoreScanCandidate,
    volume_generation: VolumeGeneration,
    media_id: MediaId,
    wire_safe_bytes: bool,
    /// Whether the PC trusted-producer registry currently has an active
    /// confirmation for this signed candidate's presented fingerprint. It is
    /// a projection input only: admission re-resolves the registry rather
    /// than trusting this cached observation.
    producer_key_trusted: bool,
}

/// Current location for an admitted core media generation. This is retained
/// separately from the visible candidate list so an import executor can
/// resolve the exact accepted locator while that candidate remains live.
#[derive(Clone)]
struct CachedLocator {
    mount_root: PathBuf,
    volume_generation: VolumeGeneration,
}

#[derive(Clone)]
struct MediaBinding {
    volume_generation: VolumeGeneration,
}

#[derive(Clone)]
struct VolumeUiState {
    reader_count: u32,
    handle_state: MediaHandleState,
    eject_state: MediaEjectState,
    eject_veto: Option<String>,
}

impl VolumeUiState {
    fn initial(native_eject: bool) -> Self {
        Self {
            reader_count: 0,
            handle_state: MediaHandleState::InUse,
            eject_state: if native_eject {
                MediaEjectState::Available
            } else {
                // The mountinfo fallback can release this application's
                // readers, but must never claim that it can eject a card.
                MediaEjectState::Unsupported
            },
            eject_veto: None,
        }
    }

    fn blocks_rescan(&self) -> bool {
        matches!(
            self.eject_state,
            MediaEjectState::Blocked | MediaEjectState::Ejecting | MediaEjectState::Ejected
        ) || matches!(self.handle_state, MediaHandleState::Released)
    }
}

#[derive(Default)]
struct RuntimeState {
    candidates: HashMap<CoreCandidateId, CachedCandidate>,
    locators: HashMap<MediaGenerationId, CachedLocator>,
    bindings: HashMap<MediaId, MediaBinding>,
    volume_states: HashMap<MediaId, VolumeUiState>,
    snapshot: MediaScanSnapshot,
}

/// Shared Ubuntu media runtime.
///
/// It implements both core ingest seams (`CandidateCatalog` and
/// `ArtifactSourceResolver`) and the app-facing scanner port. Keep the value
/// behind an [`Arc`]; all callers then use the same cache, volume catalog, and
/// durable media-generation observation boundary.
pub struct UbuntuMediaRuntime {
    scanner: ConstrainedScanner,
    scan_gate: Mutex<()>,
    volume_adapter: Mutex<RemovableMediaAdapter<LinuxNativeBackend>>,
    catalog: VolumeCatalog,
    media_store: Arc<Mutex<MediaStore>>,
    /// PC-owned trust. The card's own key material never decides admission;
    /// this registry answers whether the presented fingerprint was confirmed
    /// through SAS on this machine, which works while the producer is offline.
    trusted_producers: Arc<dyn TrustedProducerRegistry>,
    state: Mutex<RuntimeState>,
    observation: AtomicU64,
    lifecycle_state: AtomicU8,
}

impl UbuntuMediaRuntime {
    /// Construct Linux mounted-volume discovery without starting native
    /// watchers. Recovery activates the adapter only after application state
    /// has been published to Tauri's managed-state registry.
    pub fn start(
        media_store: Arc<Mutex<MediaStore>>,
        trusted_producers: Arc<dyn TrustedProducerRegistry>,
    ) -> Result<Arc<Self>, MediaPortError> {
        let backend = LinuxNativeBackend::new();
        let adapter = RemovableMediaAdapter::inactive(backend);
        let catalog = adapter.catalog();

        Ok(Arc::new(Self {
            scanner: ConstrainedScanner::new(ScanLimits::default()),
            scan_gate: Mutex::new(()),
            volume_adapter: Mutex::new(adapter),
            catalog,
            media_store,
            trusted_producers,
            state: Mutex::new(RuntimeState::default()),
            observation: AtomicU64::new(0),
            lifecycle_state: AtomicU8::new(RUNTIME_RUNNING),
        }))
    }

    /// Return this runtime through the app scanner seam without constructing a
    /// second cache or a second volume subscription.
    #[must_use]
    pub fn scanner_port(self: &Arc<Self>) -> Arc<dyn MediaScannerPort> {
        self.clone()
    }

    /// Permanently stop mounted-media access without asking Linux to eject or
    /// unmount anything. New scans and admissions fail as soon as shutdown is
    /// requested. Existing leases are cancelled generation by generation and
    /// given a bounded interval to close before adapter handles and the native
    /// subscription worker are released.
    pub fn shutdown(&self) -> Result<(), MediaPortError> {
        if self.lifecycle_state.load(Ordering::Acquire) == RUNTIME_STOPPED {
            return Ok(());
        }
        let _ = self.lifecycle_state.compare_exchange(
            RUNTIME_RUNNING,
            RUNTIME_STOPPING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.lifecycle_state.load(Ordering::Acquire) == RUNTIME_STOPPED {
            return Ok(());
        }

        let mut first_error = None;
        let generations = {
            let adapter = self
                .volume_adapter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match adapter.snapshot() {
                Ok(snapshot) => snapshot
                    .volumes
                    .iter()
                    .map(|volume| volume.generation.clone())
                    .collect::<Vec<_>>(),
                Err(error) => {
                    first_error = Some(MediaPortError::new(
                        MediaErrorCode::ResourceStuck,
                        format!(
                            "cannot enumerate live mounted-media generations during shutdown: {error}"
                        ),
                    ));
                    Vec::new()
                }
            }
        };

        let deadline = Instant::now() + SHUTDOWN_READER_DRAIN_TIMEOUT;
        loop {
            let mut release_waiting_for_readers = false;
            let mut release_error = None;
            {
                let mut adapter = self
                    .volume_adapter
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for generation in &generations {
                    match adapter.release_media_handles(generation) {
                        Ok(ReleaseMediaHandlesOutcome::Released) => {}
                        Ok(ReleaseMediaHandlesOutcome::Busy { active_readers: _ }) => {
                            release_waiting_for_readers = true;
                        }
                        Err(error) => {
                            if release_error.is_none() {
                                release_error = Some(MediaPortError::new(
                                    MediaErrorCode::ResourceStuck,
                                    format!(
                                        "cannot release mounted-media generation {} at epoch {} during shutdown: {error}",
                                        generation.identity(),
                                        generation.epoch().get()
                                    ),
                                ));
                            }
                        }
                    }
                }
            }

            let active_readers = match self.catalog.cancel_all_readers() {
                Ok(count) => count,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(MediaPortError::new(
                            MediaErrorCode::ResourceStuck,
                            format!(
                                "cannot cancel all removable-media readers during shutdown: {error}"
                            ),
                        ));
                    }
                    0
                }
            };

            if active_readers == 0 {
                // A lease may have closed after the adapter observed `Busy`
                // but before the catalog-wide count. Run one final release
                // pass so every generation reaches its backend hook.
                if release_waiting_for_readers {
                    continue;
                }
                if first_error.is_none() {
                    first_error = release_error;
                }
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                if first_error.is_none() {
                    first_error = Some(MediaPortError::new(
                        MediaErrorCode::ResourceStuck,
                        format!(
                            "{active_readers} removable-media reader(s) did not close within {} seconds",
                            SHUTDOWN_READER_DRAIN_TIMEOUT.as_secs()
                        ),
                    ));
                }
                break;
            }
            thread::sleep(
                SHUTDOWN_READER_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
            );
        }

        let subscription_result = self
            .volume_adapter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutdown_event_subscription();
        if let Err(error) = subscription_result {
            if first_error.is_none() {
                first_error = Some(MediaPortError::new(
                    MediaErrorCode::ResourceStuck,
                    format!("cannot stop the mounted-media event subscription: {error}"),
                ));
            }
        }

        if let Some(error) = first_error {
            return Err(error);
        }
        self.lifecycle_state
            .store(RUNTIME_STOPPED, Ordering::Release);
        Ok(())
    }

    /// Read the last complete scanner projection without touching the mount
    /// table, filesystem, or durable store.
    #[must_use]
    pub fn scan_snapshot(&self) -> Observed<MediaScanSnapshot> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Observed::new(
            self.observation.load(Ordering::Acquire),
            state.snapshot.clone(),
        )
    }

    /// Composition recovery and explicit scan entry point. The core scanner
    /// only receives already-mounted roots and retains its fixed
    /// [`MOUNTED_VOLUME_RECORDING_CONTAINERS`] traversal boundary.
    pub fn refresh_mounted_volumes(&self) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        self.scan_mounted_volumes()
    }

    /// Reconcile queued Linux mount notifications and, when the observation
    /// changed, publish a fresh bounded scan. A composition-owned lifecycle
    /// worker should call this periodically; notification delivery is only an
    /// invalidation hint, so every non-empty batch is followed by a full root
    /// marker scan before callers may reuse cached candidates or locators.
    ///
    /// `None` means no event was pending. When a subscription disconnects,
    /// the adapter registers its replacement before enumerating again, then
    /// this method performs the same full scanner/persistence reconciliation.
    pub fn poll_mounted_volume_events(
        &self,
    ) -> Result<Option<Observed<MediaScanSnapshot>>, MediaPortError> {
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_running()?;
        let needs_scan = {
            let mut adapter = self
                .volume_adapter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let report = adapter.poll_events().map_err(removable_scan_error)?;
            if report.subscription_disconnected {
                adapter
                    .restart_subscription_and_refresh()
                    .map_err(removable_scan_error)?;
                true
            } else {
                report.refreshed
            }
        };

        if needs_scan {
            self.scan_mounted_volumes_locked().map(Some)
        } else {
            Ok(None)
        }
    }

    fn scan_mounted_volumes(&self) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.scan_mounted_volumes_locked()
    }

    /// Run one complete mounted-volume observation while `scan_gate` is held.
    /// The gate must cover discovery, filesystem inspection, durable presence
    /// reconciliation, and publication so no older scan can commit last.
    fn scan_mounted_volumes_locked(&self) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        self.ensure_running()?;
        let (volume_snapshot, attach_issue) = {
            let mut adapter = self
                .volume_adapter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            adapter
                .activate_and_refresh()
                .map_err(removable_scan_error)?;
            // Offer to mount an inserted-but-unmounted card first, then retain
            // the typed refusal/capability result while enumerating whatever
            // the OS actually mounted. A refused attach is a visible scan
            // issue, never an empty-card success.
            let attach_issue = match adapter.attach_removable_filesystems() {
                Ok(report) => attach_issue_for(adapter.backend().kind(), &report),
                Err(error) => Some(attach_error(error)),
            };
            let snapshot = adapter.refresh().map_err(removable_scan_error)?.snapshot;
            (snapshot, attach_issue)
        };

        let observed_at = now_rfc3339();
        let mut next_candidates = HashMap::new();
        let mut next_bindings = HashMap::new();
        let mut next_locators = HashMap::new();
        let mut media = Vec::new();
        let mut candidates = Vec::new();
        let mut current_generations = Vec::new();
        let mut access_issues: HashMap<MediaId, String> = HashMap::new();

        for volume in &volume_snapshot.volumes {
            // Discovery stays broader than import eligibility so the
            // destination guard can reject every mounted removable device.
            // Candidate scanning itself is Ubuntu-MVP Linux-native only. A
            // missing hint is not evidence that a filesystem is safe, and the
            // removable hint is never promoted into content/source identity.
            if !supported_linux_native_filesystem(volume.filesystem.as_deref()) {
                continue;
            }
            // Only positively-attested removable media may become an
            // importable TF card. `Unknown` is not weaker evidence than `No`
            // here: both leave a second internal SSD indistinguishable from a
            // card reader, so both stay out of the candidate list entirely.
            if volume.removable != EvidenceHint::Yes {
                continue;
            }
            let Some(mount_root) = volume.mount_paths.first().cloned() else {
                continue;
            };

            let source_id = source_id_for_volume(&volume.generation)?;
            let root_marker_digest = root_marker_digest(&mount_root);
            let media_generation = MediaGeneration::new(
                source_id,
                volume.generation.identity().as_str(),
                root_marker_digest,
                volume.generation.epoch().get(),
            )
            .map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::ScanFailed,
                    format!("cannot create mounted-media generation: {error}"),
                )
                .with_retryable(false)
            })?;
            let media_id = MediaId::new(media_generation.id().as_str());
            let mut state_for_volume = self.volume_state(&media_id);
            state_for_volume.reader_count = self.reader_count(&volume.generation)?;

            current_generations.push(media_generation.clone());
            next_bindings.insert(
                media_id.clone(),
                MediaBinding {
                    volume_generation: volume.generation.clone(),
                },
            );

            media.push(media_descriptor(
                media_id.clone(),
                volume,
                &state_for_volume,
                &observed_at,
            ));

            // A release/eject request cancels all existing leases. Do not
            // reopen directories or create a fresh generation binding until
            // the OS has reconciled a new mounted observation.
            if state_for_volume.blocks_rescan() {
                continue;
            }

            self.catalog
                .bind_media_generation(media_generation.id().clone(), &volume.generation)
                .map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::MediaChanged,
                        format!("mounted volume changed while preparing its scan: {error}"),
                    )
                })?;

            let request = CoreScanRequest::mounted_volume(
                mount_root.clone(),
                media_generation.source_id().clone(),
                media_generation.clone(),
            )
            .map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::ScanFailed,
                    format!("mounted-volume scan configuration is invalid: {error}"),
                )
                .with_retryable(false)
            })?;
            let snapshot = self.scanner.scan(&request);
            if let Some(issue) = access_issue_message(snapshot.root_diagnostics()) {
                access_issues.insert(media_id.clone(), issue);
            }

            next_locators.insert(
                media_generation.id().clone(),
                CachedLocator {
                    mount_root: mount_root.clone(),
                    volume_generation: volume.generation.clone(),
                },
            );

            for candidate in snapshot.candidates() {
                let wire_safe_bytes = candidate_total_bytes(candidate)
                    .is_some_and(|bytes| bytes <= MAX_JAVASCRIPT_SAFE_INTEGER);
                let cache = CachedCandidate {
                    candidate: candidate.clone(),
                    volume_generation: volume.generation.clone(),
                    media_id: media_id.clone(),
                    wire_safe_bytes,
                    producer_key_trusted: self.producer_key_is_trusted(candidate),
                };
                candidates.push(project_candidate(&cache));
                next_candidates.insert(candidate.id().clone(), cache);
            }
        }

        self.persist_complete_generation_observation(&current_generations, &observed_at)?;

        media.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        candidates.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));

        let mut snapshot = MediaScanSnapshot {
            scan_id: String::new(),
            status: MediaScanState::Complete,
            media,
            candidates,
            attach_issue,
            completed_at: Some(observed_at),
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.candidates = next_candidates;
        state.locators.extend(next_locators);
        state.bindings = next_bindings;
        let visible_media = state.bindings.keys().cloned().collect::<HashSet<_>>();
        state
            .volume_states
            .retain(|media_id, _| visible_media.contains(media_id));
        // A release/eject operation can complete while the bounded filesystem
        // scan and durable presence update above are in progress. Preserve the
        // later operation's state rather than publishing the pre-scan copy
        // that was used only to decide whether this volume could be reopened.
        for descriptor in &mut snapshot.media {
            if let Some(volume_state) = state.volume_states.get_mut(&descriptor.id) {
                let operation_state_unchanged = descriptor.handle_state
                    == volume_state.handle_state
                    && descriptor.eject_state == volume_state.eject_state
                    && descriptor.eject_veto == volume_state.eject_veto;
                if operation_state_unchanged {
                    // No release/eject publication raced this scan. Refresh a
                    // previously stored Busy count from the live catalog so a
                    // dropped reader does not remain visible indefinitely.
                    volume_state.reader_count = descriptor.reader_count;
                }
                descriptor.handle_state = volume_state.handle_state;
                descriptor.reader_count = volume_state.reader_count;
                descriptor.eject_state = volume_state.eject_state;
                descriptor.eject_veto = volume_state.eject_veto.clone();
            }
            descriptor.access_issue = access_issues.remove(&descriptor.id);
        }
        // Scans are gate-ordered, while allocating the sequence under the
        // state mutex also orders publication against concurrent eject state.
        let version = self.next_observation();
        snapshot.scan_id = format!("ubuntu-mounted-{version}");
        state.snapshot = snapshot.clone();
        Ok(Observed::new(version, snapshot))
    }

    fn scan_core_request(
        &self,
        request: CoreScanRequest,
    ) -> Result<CoreScanSnapshot, IngestPortError> {
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.scan_core_request_locked(request)
    }

    fn scan_core_request_locked(
        &self,
        request: CoreScanRequest,
    ) -> Result<CoreScanSnapshot, IngestPortError> {
        self.ensure_ingest_running()?;
        if request.scope() != ScanScope::MountedVolume {
            return Err(IngestPortError::new(
                "unsupported_scan_scope",
                "the Ubuntu removable-media runtime only accepts mounted-volume scans",
            ));
        }
        let media_generation = request.media_generation().ok_or_else(|| {
            IngestPortError::new(
                "candidate_unavailable",
                "mounted-volume scan omitted its media-generation fence",
            )
        })?;
        let volume_generation = self.volume_generation_for(media_generation, request.root())?;
        self.catalog
            .bind_media_generation(media_generation.id().clone(), &volume_generation)
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?;

        let snapshot = self.scanner.scan(&request);
        self.observe_one_generation(media_generation)?;
        self.cache_core_snapshot(&snapshot, request.root(), volume_generation);
        Ok(snapshot)
    }

    fn cache_core_snapshot(
        &self,
        snapshot: &CoreScanSnapshot,
        mount_root: &Path,
        volume_generation: VolumeGeneration,
    ) {
        let Some(media_generation) = snapshot.media_generation() else {
            return;
        };
        let media_id = MediaId::new(media_generation.id().as_str());
        // Resolve PC trust before taking the cache lock so the state mutex is
        // never held across a media-store query.
        let trusted: Vec<bool> = snapshot
            .candidates()
            .map(|candidate| self.producer_key_is_trusted(candidate))
            .collect();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.candidates.retain(|_, cached| {
            cached.candidate.locator().media_generation_id() != Some(media_generation.id())
        });
        state.locators.insert(
            media_generation.id().clone(),
            CachedLocator {
                mount_root: mount_root.to_path_buf(),
                volume_generation: volume_generation.clone(),
            },
        );
        state.bindings.insert(
            media_id.clone(),
            MediaBinding {
                volume_generation: volume_generation.clone(),
            },
        );
        for (index, candidate) in snapshot.candidates().cloned().enumerate() {
            let wire_safe_bytes = candidate_total_bytes(&candidate)
                .is_some_and(|bytes| bytes <= MAX_JAVASCRIPT_SAFE_INTEGER);
            let producer_key_trusted = trusted.get(index).copied().unwrap_or(false);
            state.candidates.insert(
                candidate.id().clone(),
                CachedCandidate {
                    candidate,
                    volume_generation: volume_generation.clone(),
                    media_id: media_id.clone(),
                    wire_safe_bytes,
                    producer_key_trusted,
                },
            );
        }
    }

    fn volume_generation_for(
        &self,
        media_generation: &MediaGeneration,
        root: &Path,
    ) -> Result<VolumeGeneration, IngestPortError> {
        let snapshot = self
            .catalog
            .snapshot()
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?;
        snapshot
            .volumes
            .iter()
            .find(|volume| {
                supported_linux_native_filesystem(volume.filesystem.as_deref())
                    && volume.removable == EvidenceHint::Yes
                    && volume.generation.identity().as_str()
                    == media_generation.platform_volume_identity()
                    && volume.generation.epoch().get() == media_generation.observation_epoch()
                    && volume.mount_paths.iter().any(|path| path == root)
            })
            .map(|volume| volume.generation.clone())
            .ok_or_else(|| {
                IngestPortError::new(
                    "candidate_unavailable",
                    "the requested scan root no longer belongs to its admitted Linux volume generation",
                )
            })
    }

    fn live_cached_candidate(
        &self,
        candidate_id: &CoreCandidateId,
    ) -> Result<Option<CachedCandidate>, IngestPortError> {
        self.ensure_ingest_running()?;
        let cached = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .candidates
            .get(candidate_id)
            .cloned();
        let Some(cached) = cached else {
            return Ok(None);
        };
        let current = self
            .catalog
            .contains_generation(&cached.volume_generation)
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?;
        Ok(current.then_some(cached))
    }

    fn observe_one_generation(&self, generation: &MediaGeneration) -> Result<(), IngestPortError> {
        let observed_at = now_rfc3339();
        self.media_store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_media_generation(generation, &observed_at)
            .map_err(|error| IngestPortError::new("persistence", error.to_string()))?;
        Ok(())
    }

    fn persist_complete_generation_observation(
        &self,
        current_generations: &[MediaGeneration],
        observed_at: &str,
    ) -> Result<(), MediaPortError> {
        let result = self
            .media_store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reconcile_media_generations(current_generations, observed_at);
        result.map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::ScanFailed,
                format!("cannot reconcile mounted media generations: {error}"),
            )
        })
    }

    fn volume_state(&self, media_id: &MediaId) -> VolumeUiState {
        let existing = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .volume_states
            .get(media_id)
            .cloned();
        existing.unwrap_or_else(|| VolumeUiState::initial(self.native_eject_available()))
    }

    fn reader_count(&self, generation: &VolumeGeneration) -> Result<u32, MediaPortError> {
        let count = self
            .catalog
            .active_reader_count(generation)
            .map_err(removable_scan_error)?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    fn native_eject_available(&self) -> bool {
        let adapter = self
            .volume_adapter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        matches!(adapter.backend().kind(), LinuxBackendKind::UDisks2)
    }

    fn volume_generation(&self, media_id: &MediaId) -> Result<VolumeGeneration, MediaPortError> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .bindings
            .get(media_id)
            .map(|binding| binding.volume_generation.clone())
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::MediaNotFound,
                    "the requested mounted-media generation is no longer visible",
                )
                .with_retryable(false)
            })
    }

    fn safe_eject(&self, media_id: MediaId) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_running()?;
        let generation = self.volume_generation(&media_id)?;
        let outcome = {
            let mut adapter = self
                .volume_adapter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            adapter.safe_eject(&generation)
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                self.publish_release_failure(
                    media_id.clone(),
                    "Linux could not release/eject the mounted volume",
                    &error,
                );
                return Err(MediaPortError::new(
                    MediaErrorCode::MediaUnavailable,
                    format!("Linux could not release/eject the mounted volume: {error}"),
                ));
            }
        };

        let state = match outcome {
            SafeEjectOutcome::Busy { active_readers } => VolumeUiState {
                reader_count: wire_reader_count(active_readers),
                handle_state: MediaHandleState::InUse,
                eject_state: MediaEjectState::Blocked,
                eject_veto: Some(format!(
                    "waiting for {} active removable-media reader(s) to close",
                    active_readers
                )),
            },
            SafeEjectOutcome::Ejected => VolumeUiState {
                reader_count: 0,
                handle_state: MediaHandleState::Released,
                eject_state: MediaEjectState::Ejected,
                eject_veto: None,
            },
            SafeEjectOutcome::ReleasedForSystemEject { reason } => VolumeUiState {
                reader_count: 0,
                handle_state: MediaHandleState::Released,
                eject_state: MediaEjectState::Unsupported,
                eject_veto: Some(format!(
                    "application handles released; use the system eject control ({})",
                    eject_unavailable_reason(reason)
                )),
            },
            SafeEjectOutcome::Vetoed { code, reason } => VolumeUiState {
                // The native service refused after the adapter had already
                // closed its handles. Keep the generation reader-fenced;
                // reopening it would violate the release boundary.
                reader_count: 0,
                handle_state: MediaHandleState::Released,
                eject_state: MediaEjectState::Blocked,
                eject_veto: Some(match code {
                    Some(code) => format!("Linux eject veto {code}: {reason}"),
                    None => format!("Linux eject veto: {reason}"),
                }),
            },
        };
        self.update_volume_state(media_id, state)
    }

    fn release_media_handles_only(
        &self,
        media_id: MediaId,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_running()?;
        let generation = self.volume_generation(&media_id)?;
        let release = {
            let mut adapter = self
                .volume_adapter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let outcome = adapter.release_media_handles(&generation);
            let native_eject = matches!(adapter.backend().kind(), LinuxBackendKind::UDisks2);
            (outcome, native_eject)
        };
        let (outcome, native_eject) = release;
        let state = match outcome {
            Ok(ReleaseMediaHandlesOutcome::Busy { active_readers }) => VolumeUiState {
                reader_count: wire_reader_count(active_readers),
                handle_state: MediaHandleState::InUse,
                eject_state: MediaEjectState::Blocked,
                eject_veto: Some(format!(
                    "waiting for {} active removable-media reader(s) to close",
                    active_readers
                )),
            },
            Ok(ReleaseMediaHandlesOutcome::Released) => VolumeUiState {
                reader_count: 0,
                handle_state: MediaHandleState::Released,
                eject_state: if native_eject {
                    MediaEjectState::Available
                } else {
                    MediaEjectState::Unsupported
                },
                eject_veto: (!native_eject).then_some(
                    "application handles released; use the system eject control (platform eject is unavailable)"
                        .to_string(),
                ),
            },
            Err(error) => {
                self.publish_release_failure(
                    media_id.clone(),
                    "Linux could not release mounted-volume handles",
                    &error,
                );
                return Err(MediaPortError::new(
                    MediaErrorCode::MediaUnavailable,
                    format!("Linux could not release mounted-volume handles: {error}"),
                ));
            }
        };
        self.update_volume_state(media_id, state)
    }

    fn publish_release_failure(
        &self,
        media_id: MediaId,
        operation: &str,
        error: &RemovableMediaError,
    ) {
        // A release can fail after one external hook has already closed. The
        // catalog keeps that generation fenced, so project a conservative
        // released/failed state instead of advertising new source readers.
        let _ = self.update_volume_state(
            media_id,
            VolumeUiState {
                reader_count: 0,
                handle_state: MediaHandleState::Released,
                eject_state: MediaEjectState::Failed,
                eject_veto: Some(format!("{operation}: {error}")),
            },
        );
    }

    fn update_volume_state(
        &self,
        media_id: MediaId,
        volume_state: VolumeUiState,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        let observed_at = now_rfc3339();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let descriptor = state
            .snapshot
            .media
            .iter_mut()
            .find(|descriptor| descriptor.id == media_id)
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::MediaNotFound,
                    "the mounted media disappeared before its state could be published",
                )
                .with_retryable(false)
            })?;
        descriptor.handle_state = volume_state.handle_state;
        descriptor.reader_count = volume_state.reader_count;
        descriptor.eject_state = volume_state.eject_state;
        descriptor.eject_veto = volume_state.eject_veto.clone();
        descriptor.observed_at = observed_at.clone();
        state.volume_states.insert(media_id, volume_state);
        let version = self.next_observation();
        state.snapshot.scan_id = format!("ubuntu-mounted-{version}");
        state.snapshot.status = MediaScanState::Complete;
        state.snapshot.completed_at = Some(observed_at);
        Ok(Observed::new(version, state.snapshot.clone()))
    }

    fn next_observation(&self) -> u64 {
        self.observation.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn ensure_running(&self) -> Result<(), MediaPortError> {
        if self.lifecycle_state.load(Ordering::Acquire) == RUNTIME_RUNNING {
            Ok(())
        } else {
            Err(MediaPortError::new(
                MediaErrorCode::ResourceStuck,
                "the Ubuntu mounted-media runtime is shutting down and cannot be restarted",
            )
            .with_retryable(false))
        }
    }

    /// Whether this signed candidate's presented fingerprint currently
    /// resolves to an active PC confirmation. Unsigned candidates and any
    /// registry failure answer `false`: readiness may only ever be upgraded by
    /// positive evidence.
    fn producer_key_is_trusted(&self, candidate: &CoreScanCandidate) -> bool {
        let Some(material) = candidate.signed_publication() else {
            return false;
        };
        self.trusted_producers
            .resolve_active(material.presented_key_fingerprint())
            .ok()
            .flatten()
            .is_some()
    }

    /// Admit one `SignedPublicationV1` candidate.
    ///
    /// The order below is fixed and every step is fail-closed. Nothing here
    /// can fall back to unsigned admission, and the Pi does not need to be
    /// reachable: the expected identity comes from this PC's registry, and the
    /// signature material comes from the card.
    fn admit_signed(&self, cached: CachedCandidate) -> Result<SourceRecording, IngestPortError> {
        // 1. Exact signed material from the cached candidate.
        let material = cached.candidate.signed_publication().ok_or_else(|| {
            IngestPortError::new(
                "integrity_failed",
                "the signed candidate is missing its exact publication material",
            )
        })?;

        // 2. The candidate generation must still be live. `live_cached_candidate`
        //    established this; re-assert it against the catalog so a card that
        //    was swapped between scan and admit cannot be admitted.
        if !self
            .catalog
            .contains_generation(&cached.volume_generation)
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?
        {
            return Err(IngestPortError::new(
                "source_unavailable",
                "the signed candidate's removable-media generation is no longer mounted",
            ));
        }

        // 3. Parse the presented fingerprint. A malformed identity is an
        //    integrity failure, not a missing-pairing prompt.
        let presented = material.presented_key_fingerprint();
        ylx_transfer_core::media_store::validate_producer_key_fingerprint(presented).map_err(
            |error| {
                IngestPortError::new(
                    "integrity_failed",
                    format!("the card presented a malformed publication key identity: {error}"),
                )
            },
        )?;

        // 4/5. Resolve PC trust. An unknown key is a pairing action for the
        //      user, never a retryable transient failure.
        let receipt = match self.trusted_producers.resolve_active(presented) {
            Ok(Some(receipt)) => receipt,
            Ok(None) => {
                return Err(IngestPortError::new(
                    "policy_approval_required",
                    "the signed publication is waiting for its paired trusted producer key",
                ));
            }
            Err(TrustedProducerError::MalformedFingerprint { detail })
            | Err(TrustedProducerError::MalformedIdentity { detail }) => {
                return Err(IngestPortError::new(
                    "integrity_failed",
                    format!("the presented producer key identity is malformed: {detail}"),
                ));
            }
            Err(TrustedProducerError::Unavailable(detail)) => {
                return Err(IngestPortError::new(
                    "persistence",
                    format!("the trusted producer registry is unavailable: {detail}"),
                ));
            }
        };

        // 6/7/8. The registry's fingerprint — never the card's — is the
        //        expected identity handed to the one authoritative verifier.
        //        `PublicationTrust` binds session id, re-derives SHA-256 over
        //        the raw public key, and checks the detached signature over
        //        the exact payload.
        let envelope = if let Some(key_version) = material.inline_key_version() {
            let registry_key = self
                .trusted_producers
                .resolve_inline_active(receipt.producer_identity(), key_version)
                .map_err(|error| IngestPortError::new(
                    "persistence",
                    format!("the trusted inline publication-key registry is unavailable: {error}"),
                ))?
                .ok_or_else(|| IngestPortError::new(
                    "policy_approval_required",
                    "the signed publication key version is not active for this authenticated device",
                ))?;
            if registry_key.producer_identity != receipt.producer_identity()
                || registry_key.key_version != key_version
                || registry_key.fingerprint != presented
            {
                return Err(IngestPortError::new(
                    "integrity_failed",
                    "the inline publication key registry binding does not match the external device identity, version, and fingerprint",
                ));
            }
            material.envelope_with_registry_public_key(registry_key.public_key_hex)
        } else {
            // Detached cards carry the exact payload, signature and public
            // key discovered together by the detector. Half-present pairs
            // and mixed inline/sidecar profiles never reach this branch.
            material.envelope()
        };
        let verified = PublicationTrust::new(&Ed25519PublicationVerifier)
            .verify(
                &envelope,
                cached.candidate.session_id(),
                receipt.key_fingerprint(),
            )
            .map_err(|error| {
                IngestPortError::new(
                    "integrity_failed",
                    format!("the card publication failed trusted verification: {error}"),
                )
            })?;

        // 9/10. `admit_device_signed` re-checks revision, inventory, paths,
        //       sizes and digests against the scanned candidate, and is the
        //       only constructor that can produce DeviceSigned provenance.
        SourceRecording::admit_device_signed(cached.candidate, &verified)
            .map_err(|error| IngestPortError::new("integrity_failed", error.to_string()))
    }

    fn ensure_ingest_running(&self) -> Result<(), IngestPortError> {
        if self.lifecycle_state.load(Ordering::Acquire) == RUNTIME_RUNNING {
            Ok(())
        } else {
            Err(IngestPortError::new(
                "source_unavailable",
                "the Ubuntu mounted-media runtime is shutting down and cannot be restarted",
            ))
        }
    }
}

impl UbuntuDestinationGuard for UbuntuMediaRuntime {
    fn ensure_pc_destination(&self, library_root: &Path) -> Result<(), MediaPortError> {
        self.observe_pc_destination(library_root).map(|_| ())
    }

    fn destination_fence(
        &self,
        library_root: &Path,
    ) -> Result<UbuntuDestinationFence, MediaPortError> {
        self.observe_pc_destination(library_root)
            .map(UbuntuDestinationFence::new)
    }

    fn assert_pc_destination(
        &self,
        library_root: &Path,
        fence: &UbuntuDestinationFence,
    ) -> Result<(), MediaPortError> {
        // Event polling is non-blocking when no native invalidation is queued.
        // If a mount changed, it performs the authoritative refresh first and
        // advances the catalog epoch before the next destination write.
        let _ = self.poll_mounted_volume_events()?;
        let snapshot = self.catalog.snapshot().map_err(|_| {
            destination_guard_error(
                "mounted_volume_snapshot_unavailable",
                "the current mounted-volume set could not be verified for local import",
            )
        })?;
        let epoch = snapshot.epoch.get();
        if fence.volume_epoch.load(Ordering::Acquire) == epoch {
            return Ok(());
        }
        validate_pc_destination(library_root, &snapshot)?;
        fence.volume_epoch.store(epoch, Ordering::Release);
        Ok(())
    }
}

impl UbuntuMediaRuntime {
    fn observe_pc_destination(&self, library_root: &Path) -> Result<u64, MediaPortError> {
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_running()?;

        // An import check is an authoritative observation, not a read of the
        // last UI snapshot. Publishing this refresh through the shared catalog
        // also fences a candidate whose source generation changed since scan.
        let volume_snapshot = self
            .volume_adapter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .refresh()
            .map_err(|_| {
                destination_guard_error(
                    "mounted_volume_refresh_failed",
                    "the current mounted-volume set could not be verified for local import",
                )
            })?
            .snapshot;

        validate_pc_destination(library_root, &volume_snapshot)?;
        Ok(volume_snapshot.epoch.get())
    }
}

fn validate_pc_destination(
    library_root: &Path,
    volume_snapshot: &MountedVolumeSnapshot,
) -> Result<(), MediaPortError> {
    let library = open_linux_directory_identity(library_root).map_err(|_| {
        destination_guard_error(
            "library_root_identity_unavailable",
            "the configured local media library has no stable Linux filesystem identity",
        )
    })?;
    let staging_path = library_root.join(STAGING_DIR_NAME);
    let staging = match fs::symlink_metadata(&staging_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(destination_guard_error(
                    "staging_identity_unavailable",
                    "the local import staging path is not a stable directory",
                ));
            }
            Some(open_linux_directory_identity(&staging_path).map_err(|_| {
                destination_guard_error(
                    "staging_identity_unavailable",
                    "the local import staging path has no stable Linux filesystem identity",
                )
            })?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            return Err(destination_guard_error(
                "staging_identity_unavailable",
                "the local import staging path could not be inspected safely",
            ));
        }
    };

    let mut mounted_directories = Vec::new();
    for volume in &volume_snapshot.volumes {
        if !destination_guard_considers(volume) {
            continue;
        }
        if volume.mount_paths.is_empty() {
            return Err(destination_guard_error(
                "mounted_volume_identity_unavailable",
                "a discovered removable volume has no verifiable mount identity",
            ));
        }

        let mut volume_device = None;
        for mount_path in &volume.mount_paths {
            let mounted = open_linux_directory_identity(mount_path).map_err(|_| {
                destination_guard_error(
                    "mounted_volume_identity_unavailable",
                    "a discovered removable volume has no stable Linux filesystem identity",
                )
            })?;
            if volume_device.is_some_and(|device| device != mounted.device) {
                return Err(destination_guard_error(
                        "mounted_volume_identity_inconsistent",
                        "one discovered removable volume resolved to conflicting Linux device identities",
                    ));
            }
            volume_device = Some(mounted.device);
            mounted_directories.push(mounted);
        }
    }

    for destination in std::iter::once(&library).chain(staging.as_ref()) {
        for mounted in &mounted_directories {
            if destination.device == mounted.device {
                return Err(destination_guard_error(
                        "destination_on_removable_filesystem",
                        "the local media library or staging area is on a discovered removable filesystem",
                    ));
            }
            if canonical_paths_overlap(&destination.canonical_path, &mounted.canonical_path) {
                return Err(destination_guard_error(
                    "destination_overlaps_removable_mount",
                    "the local media library or staging area overlaps a discovered removable mount",
                ));
            }
        }
    }

    Ok(())
}

fn destination_guard_considers(volume: &MountedVolume) -> bool {
    destination_guard_considers_facts(volume.removable, volume.filesystem.as_deref())
}

fn destination_guard_considers_facts(removable: EvidenceHint, filesystem: Option<&str>) -> bool {
    removable == EvidenceHint::Yes && supported_linux_native_filesystem(filesystem)
}

impl MediaScannerPort for UbuntuMediaRuntime {
    fn scan(&self, request: AppScanRequest) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        match request.source {
            ScanSource::MountedVolumes => self.scan_mounted_volumes(),
            ScanSource::SelectedFolder { .. } => Err(MediaPortError::new(
                MediaErrorCode::MediaUnavailable,
                "the Ubuntu removable-media MVP only scans recording roots on OS-mounted volumes",
            )
            .with_retryable(false)
            .with_detail("source", json!("selected_folder"))
            .with_detail("platform", json!("ubuntu"))),
        }
    }

    fn release_media_handles(
        &self,
        media_id: MediaId,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        self.release_media_handles_only(media_id)
    }

    fn eject_media(
        &self,
        media_id: MediaId,
    ) -> Result<Observed<MediaScanSnapshot>, MediaPortError> {
        self.safe_eject(media_id)
    }
}

impl CandidateCatalog for UbuntuMediaRuntime {
    fn scan(&self, request: CoreScanRequest) -> Result<CoreScanSnapshot, IngestPortError> {
        self.scan_core_request(request)
    }

    fn candidate(
        &self,
        candidate_id: &CoreCandidateId,
    ) -> Result<Option<CoreScanCandidate>, IngestPortError> {
        Ok(self
            .live_cached_candidate(candidate_id)?
            .map(|cached| cached.candidate))
    }

    fn admit(
        &self,
        candidate_id: &CoreCandidateId,
        policy: &ImportPolicy,
    ) -> Result<SourceRecording, IngestPortError> {
        let cached = self.live_cached_candidate(candidate_id)?.ok_or_else(|| {
            IngestPortError::new(
                "candidate_unavailable",
                "the scanned removable-media candidate is no longer present",
            )
        })?;
        if !cached.wire_safe_bytes {
            return Err(IngestPortError::new(
                "candidate_unavailable",
                "candidate byte count exceeds the JavaScript-safe wire limit",
            ));
        }
        if cached.candidate.schema().is_signed() {
            return self.admit_signed(cached);
        }
        let admissible_unsigned = matches!(
            cached.candidate.readiness(),
            CoreCandidateReadiness::ReadyUnsignedRequiresPolicy
                | CoreCandidateReadiness::PendingArtifactValidation
        );
        if !admissible_unsigned {
            return Err(IngestPortError::new(
                "candidate_unavailable",
                format!(
                    "candidate is not admissible in its current readiness state: {:?}",
                    cached.candidate.readiness()
                ),
            ));
        }

        let candidate_revision = match cached.candidate.revision_claim() {
            SourceRevisionClaim::Provisional(revision) => revision.clone(),
            SourceRevisionClaim::Published(_) => {
                return Err(IngestPortError::new(
                    "candidate_unavailable",
                    "unsigned candidate unexpectedly carries a published revision",
                ));
            }
        };
        let media_generation_id = cached.candidate.locator().media_generation_id().cloned();
        let receipt = match policy.unsigned() {
            UnsignedImportPolicy::Reject => {
                return Err(IngestPortError::new(
                    "policy_approval_required",
                    "this locally validated unsigned recording requires explicit user approval",
                ));
            }
            UnsignedImportPolicy::RequireAdmissionReceipt
            | UnsignedImportPolicy::AllowExplicitSelection => Some(
                UnsignedSourceAdmissionReceipt::new(
                    format!("ubuntu-removable-admission-{}", candidate_id.as_str()),
                    candidate_id.clone(),
                    media_generation_id,
                    candidate_revision,
                    "ubuntu-removable-media-v1",
                    now_rfc3339(),
                )
                .map_err(|error| {
                    IngestPortError::new("policy_approval_required", error.to_string())
                })?,
            ),
        };

        SourceRecording::admit_unsigned(cached.candidate, receipt)
            .map_err(|error| IngestPortError::new("candidate_unavailable", error.to_string()))
    }
}

impl ArtifactSourceResolver for UbuntuMediaRuntime {
    fn resolve(&self, locator: &MediaLocator) -> Result<ResolvedArtifactSource, IngestPortError> {
        // The lifecycle watcher normally reconciles arrival/removal events.
        // Resolve is the last fence before an import opens source bytes, so
        // it also performs an authoritative scan: a card can be replaced at
        // the same mount path between watcher ticks or after an event loss.
        // If the observed root marker/candidate changed, the old locator no
        // longer matches the rebuilt cache and the ingest engine transitions
        // the durable job to `waiting_for_media`.
        let _scan_guard = self
            .scan_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.scan_mounted_volumes_locked()
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?;
        let expected_generation = locator.media_generation_id().ok_or_else(|| {
            IngestPortError::new(
                "source_unavailable",
                "the Ubuntu mounted-file resolver requires a media-generation locator",
            )
        })?;
        let (cached, source_location) = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let cached = state
                .candidates
                .values()
                .find(|cached| cached.candidate.locator() == locator)
                .cloned()
                .ok_or_else(|| {
                    IngestPortError::new(
                        "source_unavailable",
                        "no current scanned candidate matches the durable import locator",
                    )
                })?;
            let source_location = state
                .locators
                .get(expected_generation)
                .cloned()
                .ok_or_else(|| {
                    IngestPortError::new(
                        "source_unavailable",
                        "the admitted media generation no longer has a mounted source locator",
                    )
                })?;
            (cached, source_location)
        };
        if cached.candidate.locator().media_generation_id() != Some(expected_generation) {
            return Err(IngestPortError::new(
                "source_unavailable",
                "candidate locator disagrees with its requested media generation",
            ));
        }
        if !self
            .catalog
            .contains_generation(&source_location.volume_generation)
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?
        {
            return Err(IngestPortError::new(
                "source_unavailable",
                "the admitted removable-media generation is no longer mounted",
            ));
        }
        self.catalog
            .bind_media_generation(
                expected_generation.clone(),
                &source_location.volume_generation,
            )
            .map_err(|error| IngestPortError::new("source_unavailable", error.to_string()))?;

        let relative_candidate_root = locator.candidate_relative_path().ok_or_else(|| {
            IngestPortError::new(
                "unsafe_path",
                "mounted removable-media locator omitted its candidate-relative path",
            )
        })?;
        let candidate_root =
            resolve_directory_no_links(&source_location.mount_root, relative_candidate_root)
                .map_err(|error| IngestPortError::new("unsafe_path", error.to_string()))?;
        let leases: Arc<dyn MediaReadLeaseProvider> = Arc::new(self.catalog.clone());
        let source = MountedFileArtifactAdapter::new(
            candidate_root,
            expected_generation.clone(),
            cached.candidate.revision_claim().clone(),
            cached.candidate.inventory().iter().cloned(),
            leases,
        )
        .map_err(|error| IngestPortError::new("unsafe_path", error.to_string()))?;

        Ok(ResolvedArtifactSource {
            source: Arc::new(source),
            observed_generation: Some(expected_generation.clone()),
        })
    }
}

fn open_linux_directory_identity(path: &Path) -> io::Result<OpenLinuxDirectory> {
    const O_DIRECTORY: i32 = 0x0001_0000;
    const O_NOFOLLOW: i32 = 0x0002_0000;
    const O_CLOEXEC: i32 = 0x0008_0000;

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory identity requires an absolute path",
        ));
    }

    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity path is not a no-follow directory",
        ));
    }
    let canonical_path = fs::canonicalize(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    let handle = options.open(&canonical_path)?;
    let opened = handle.metadata()?;
    let after = fs::symlink_metadata(path)?;
    let canonical_after = fs::canonicalize(path)?;
    if canonical_path != canonical_after
        || !same_directory_identity(&before, &opened)
        || !same_directory_identity(&opened, &after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory identity changed while it was being inspected",
        ));
    }

    Ok(OpenLinuxDirectory {
        canonical_path,
        device: opened.dev(),
        _inode: opened.ino(),
        _handle: handle,
    })
}

fn same_directory_identity(left: &Metadata, right: &Metadata) -> bool {
    left.is_dir()
        && right.is_dir()
        && !left.file_type().is_symlink()
        && !right.file_type().is_symlink()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
}

fn canonical_paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn attach_issue_for(backend: LinuxBackendKind, report: &PlatformAttachReport) -> Option<RpcError> {
    if !matches!(backend, LinuxBackendKind::UDisks2) {
        return Some(RpcError::new(
            MediaErrorCode::MediaUnavailable.as_str(),
            "UDisks2 mount authorization is unavailable; only already-mounted removable volumes can be observed",
            true,
            Some(json!({
                "capability": "udisks2_mount",
                "backend": "mountinfo",
                "eligible": report.eligible,
                "mounted": report.mounted,
            })),
        ));
    }

    let first = report.refusals.first()?;
    let (reason, message) = match first {
        AttachRefusalReason::PermissionDenied => (
            "authorization_required",
            "UDisks2 refused to mount an inserted removable volume because this session is not authorized",
        ),
        AttachRefusalReason::NativeServiceUnavailable => (
            "udisks2_unavailable",
            "UDisks2 could not mount an inserted removable volume because the native service is unavailable",
        ),
        AttachRefusalReason::Other(_) => (
            "attach_refused",
            "UDisks2 refused to mount an inserted removable volume for an unspecified platform reason",
        ),
    };
    Some(RpcError::new(
        MediaErrorCode::MediaUnavailable.as_str(),
        message,
        true,
        Some(json!({
            "capability": "udisks2_mount",
            "reason": reason,
            "eligible": report.eligible,
            "mounted": report.mounted,
            "refusalCount": report.refusals.len(),
        })),
    ))
}

fn attach_error(error: RemovableMediaError) -> RpcError {
    RpcError::new(
        MediaErrorCode::MediaUnavailable.as_str(),
        format!("UDisks2 mount request could not be evaluated: {error}"),
        true,
        Some(json!({
            "capability": "udisks2_mount",
            "reason": "attach_error",
        })),
    )
}

fn destination_guard_error(reason: &'static str, message: &'static str) -> MediaPortError {
    MediaPortError::new(MediaErrorCode::StorageNotConfigured, message)
        .with_retryable(false)
        .with_detail("operation", json!("validate_local_media_destination"))
        .with_detail("capability", json!("pc_filesystem_destination"))
        .with_detail("reason", json!(reason))
}

fn source_id_for_volume(
    volume_generation: &VolumeGeneration,
) -> Result<AcquisitionSourceId, MediaPortError> {
    let identity = InventoryDigest::from_material(volume_generation.identity().as_str().as_bytes());
    AcquisitionSourceId::parse(format!("ubuntu-volume-{}", identity.as_str())).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::ScanFailed,
            format!("cannot construct a safe Linux acquisition-source identity: {error}"),
        )
        .with_retryable(false)
    })
}

fn root_marker_digest(root: &Path) -> InventoryDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ylx-ubuntu-mounted-root-marker-v2\0");
    hash_metadata(&mut hasher, b"root", root);
    let mut remaining_marker_bytes = MAX_ROOT_MARKER_TOTAL_BYTES;

    for container_name in MOUNTED_VOLUME_RECORDING_CONTAINERS {
        hasher.update(b"container\0");
        hasher.update(container_name.as_bytes());
        let Ok(container_relative) = SafeRelativePath::parse(container_name.to_owned()) else {
            hasher.update(b"container-unsafe-relative-path\0");
            continue;
        };
        let container = container_relative.join_to(root);
        if !hash_metadata(&mut hasher, b"container-meta", &container) {
            continue;
        }
        let entries = match fs::read_dir(&container) {
            Ok(entries) => entries,
            Err(error) => {
                hasher.update(b"read-dir-error\0");
                hash_io_error_kind(&mut hasher, error.kind());
                continue;
            }
        };
        let mut children = Vec::new();
        let mut truncated = false;
        for entry in entries {
            if children.len() >= MAX_ROOT_MARKER_ENTRIES {
                truncated = true;
                break;
            }
            match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    children.push((name.as_bytes().to_vec(), entry.path()));
                }
                Err(error) => {
                    hasher.update(b"entry-error\0");
                    hash_io_error_kind(&mut hasher, error.kind());
                }
            }
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        if truncated {
            hasher.update(b"entries-truncated\0");
        }
        for (name, candidate_root) in children {
            hasher.update(b"candidate\0");
            hasher.update((name.len() as u64).to_be_bytes());
            hasher.update(name);
            if !hash_metadata(&mut hasher, b"candidate-meta", &candidate_root) {
                continue;
            }
            for marker in ROOT_MARKERS {
                hasher.update(b"marker\0");
                hasher.update(marker.as_bytes());
                hash_root_marker(
                    &mut hasher,
                    root,
                    &candidate_root,
                    marker,
                    &mut remaining_marker_bytes,
                );
            }
        }
    }
    InventoryDigest::from_digest(hasher.finalize().into())
}

/// Add a fixed recording marker's metadata and bounded bytes to the mounted
/// generation fence. The core path resolver rejects links in every component;
/// `O_NOFOLLOW` and the handle/path fingerprint checks close the leaf
/// check/open race before any bytes become identity material.
fn hash_root_marker(
    hasher: &mut Sha256,
    root: &Path,
    candidate_root: &Path,
    marker: &str,
    remaining_marker_bytes: &mut u64,
) {
    if !ROOT_MARKERS.contains(&marker) {
        hasher.update(b"marker-not-allowlisted\0");
        return;
    }

    let marker_path = candidate_root.join(marker);
    hash_metadata(hasher, b"marker-meta", &marker_path);

    let relative = match marker_path
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .and_then(|path| SafeRelativePath::parse(path.to_owned()).ok())
    {
        Some(relative) => relative,
        None => {
            hasher.update(b"marker-unsafe-relative-path\0");
            return;
        }
    };
    let resolved = match resolve_regular_file_no_links(root, &relative) {
        Ok(path) => path,
        Err(_) => {
            hasher.update(b"marker-not-readable-regular-file\0");
            return;
        }
    };
    let before_open = match fs::symlink_metadata(&resolved) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            hasher.update(b"marker-not-regular-file\0");
            return;
        }
        Err(error) => {
            hasher.update(b"marker-pre-open-inspection-error\0");
            hash_io_error_kind(hasher, error.kind());
            return;
        }
    };
    let mut file = match open_root_marker_no_follow(&resolved) {
        Ok(file) => file,
        Err(error) => {
            hasher.update(b"marker-open-error\0");
            hash_io_error_kind(hasher, error.kind());
            return;
        }
    };
    let handle_before = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            hasher.update(b"marker-handle-inspection-error\0");
            hash_io_error_kind(hasher, error.kind());
            return;
        }
    };
    let after_open = match resolve_marker_metadata(root, &relative) {
        Ok(metadata) => metadata,
        Err(error) => {
            hasher.update(b"marker-post-open-inspection-error\0");
            hash_io_error_kind(hasher, error.kind());
            return;
        }
    };
    if !same_regular_file(&before_open, &handle_before)
        || !same_regular_file(&handle_before, &after_open)
    {
        hasher.update(b"marker-changed-during-open\0");
        return;
    }

    let read_limit = before_open
        .len()
        .min(MAX_ROOT_MARKER_BYTES)
        .min(*remaining_marker_bytes);
    *remaining_marker_bytes -= read_limit;
    hasher.update(b"marker-read-limit\0");
    hasher.update(read_limit.to_be_bytes());
    if before_open.len() > 0 && read_limit == 0 {
        hasher.update(b"marker-total-budget-exhausted\0");
        return;
    }

    let mut bytes = Vec::with_capacity(read_limit as usize);
    let read_result = {
        let mut bounded = (&mut file).take(read_limit);
        bounded.read_to_end(&mut bytes)
    };
    if let Err(error) = read_result {
        hasher.update(b"marker-read-error\0");
        hash_io_error_kind(hasher, error.kind());
        return;
    }
    if bytes.len() as u64 != read_limit {
        hasher.update(b"marker-short-read\0");
        hasher.update((bytes.len() as u64).to_be_bytes());
        return;
    }

    let handle_after = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            hasher.update(b"marker-post-read-handle-error\0");
            hash_io_error_kind(hasher, error.kind());
            return;
        }
    };
    let after_read = match resolve_marker_metadata(root, &relative) {
        Ok(metadata) => metadata,
        Err(error) => {
            hasher.update(b"marker-post-read-inspection-error\0");
            hash_io_error_kind(hasher, error.kind());
            return;
        }
    };
    if !same_regular_file(&handle_before, &handle_after)
        || !same_regular_file(&handle_after, &after_read)
    {
        hasher.update(b"marker-changed-during-read\0");
        return;
    }

    hasher.update(if before_open.len() > read_limit {
        b"marker-content-prefix\0".as_slice()
    } else {
        b"marker-content-complete\0".as_slice()
    });
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(Sha256::digest(&bytes));
}

fn resolve_marker_metadata(root: &Path, relative: &SafeRelativePath) -> io::Result<Metadata> {
    let path = resolve_regular_file_no_links(root, relative)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "unsafe marker path"))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(metadata)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "marker is not a regular file",
        ))
    }
}

fn open_root_marker_no_follow(path: &Path) -> io::Result<File> {
    const O_NOFOLLOW: i32 = 0x0002_0000;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(O_NOFOLLOW);
    options.open(path)
}

fn same_regular_file(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

/// Hash bounded filesystem metadata. Marker contents are added separately
/// through the fixed allowlist and bounded no-follow reader above; every other
/// entry remains metadata-only so this observation never becomes a recursive
/// arbitrary-file scan.
fn hash_metadata(hasher: &mut Sha256, label: &[u8], path: &Path) -> bool {
    hasher.update(label);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let kind = if metadata.file_type().is_symlink() {
                1u8
            } else if metadata.is_dir() {
                2u8
            } else if metadata.is_file() {
                3u8
            } else {
                4u8
            };
            hasher.update([kind]);
            hasher.update(metadata.dev().to_be_bytes());
            hasher.update(metadata.ino().to_be_bytes());
            hasher.update(metadata.len().to_be_bytes());
            hasher.update(metadata.mtime().to_be_bytes());
            hasher.update(metadata.mtime_nsec().to_be_bytes());
            kind == 2
        }
        Err(error) => {
            hasher.update([0]);
            hash_io_error_kind(hasher, error.kind());
            false
        }
    }
}

fn hash_io_error_kind(hasher: &mut Sha256, kind: std::io::ErrorKind) {
    // The error category, rather than an unbounded filesystem message, is
    // enough to make the observation change while keeping path/error details
    // out of a durable identity input.
    hasher.update(format!("{kind:?}").as_bytes());
}

fn candidate_total_bytes(candidate: &CoreScanCandidate) -> Option<u64> {
    candidate
        .inventory()
        .iter()
        .try_fold(0u64, |total, artifact| {
            total.checked_add(artifact.size_bytes())
        })
}

fn project_candidate(cached: &CachedCandidate) -> AppScanCandidate {
    let candidate = &cached.candidate;
    let bytes = candidate_total_bytes(candidate)
        .filter(|bytes| *bytes <= MAX_JAVASCRIPT_SAFE_INTEGER)
        .unwrap_or(0);
    let bytes_are_safe = cached.wire_safe_bytes;
    // The scanner cannot know PC trust, so it always reports a signed card as
    // waiting for a pairing key. Upgrade that readiness only when the registry
    // actually holds an active confirmation for the presented fingerprint.
    let readiness = if cached.producer_key_trusted
        && candidate.readiness() == CoreCandidateReadiness::WaitingForPairingKey
    {
        CoreCandidateReadiness::ReadySigned
    } else {
        candidate.readiness()
    };
    let verdict = if bytes_are_safe {
        map_candidate_verdict(readiness)
    } else {
        CandidateVerdict::Corrupt
    };
    let reason = if !bytes_are_safe {
        Some(
            MediaPortError::new(
                MediaErrorCode::IntegrityFailed,
                "candidate byte count exceeds the JavaScript-safe wire limit and is not importable",
            )
            .with_retryable(false)
            .into_rpc(),
        )
    } else {
        candidate_reason(readiness)
    };
    let relative_path = candidate
        .locator()
        .candidate_relative_path()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| ".".to_string());

    AppScanCandidate {
        id: AppCandidateId::new(candidate.id().as_str()),
        source_key: candidate.revision_claim().as_str().to_string(),
        media_id: cached.media_id.clone(),
        // An unsigned candidate has only a provisional revision. A signed
        // card's claimed revision is likewise not a verified local source
        // identity until the paired trust boundary has admitted it.
        source_id: None,
        session_id: Some(candidate.session_id().to_string()),
        display_name: candidate.session_id().to_string(),
        relative_path,
        source_kind: map_source_kind(candidate.source_kind()),
        schema: map_source_schema(candidate.schema()),
        verdict,
        reason,
        provenance: project_provenance(candidate, cached.producer_key_trusted),
        bytes,
        duration_seconds: None,
        media_required: true,
    }
}

fn candidate_reason(readiness: CoreCandidateReadiness) -> Option<RpcError> {
    let error = match readiness {
        CoreCandidateReadiness::ReadySigned
        | CoreCandidateReadiness::ReadyUnsignedRequiresPolicy
        | CoreCandidateReadiness::PendingArtifactValidation
        | CoreCandidateReadiness::AlreadyImported => return None,
        CoreCandidateReadiness::WaitingForPairingKey => MediaPortError::new(
            MediaErrorCode::PolicyApprovalRequired,
            "the signed publication is waiting for a paired trusted producer key",
        )
        .with_retryable(false),
        CoreCandidateReadiness::RecordingOrEncodingIncomplete => MediaPortError::new(
            MediaErrorCode::MediaUnavailable,
            "recording or encoding has not reached its durable completion boundary",
        )
        .with_retryable(false),
        CoreCandidateReadiness::UnsupportedSchema => MediaPortError::new(
            MediaErrorCode::UnsupportedSchema,
            "the removable-media recording schema is unsupported",
        )
        .with_retryable(false),
        CoreCandidateReadiness::UnsafePath => MediaPortError::new(
            MediaErrorCode::UnsafePath,
            "the removable-media candidate contains an unsafe path or filesystem entry",
        )
        .with_retryable(false),
        CoreCandidateReadiness::InsufficientLocalSpace => MediaPortError::new(
            MediaErrorCode::InsufficientLocalSpace,
            "the candidate exceeds the available local import space",
        ),
        CoreCandidateReadiness::Corrupt => MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "the removable-media candidate failed structural or integrity validation",
        )
        .with_retryable(false),
    };
    Some(error.into_rpc())
}

fn project_provenance(
    candidate: &CoreScanCandidate,
    producer_key_trusted: bool,
) -> AppSourceProvenance {
    if candidate.schema().is_signed() {
        let fingerprint = candidate
            .signed_publication()
            .map(|publication| publication.presented_key_fingerprint().to_string())
            .unwrap_or_else(|| "unavailable-signed-publication".to_string());
        // The strict wire type has no `pending` signature state. Pending or
        // unavailable verification is represented conservatively as invalid,
        // together with WaitingForPairingKey, so this adapter never claims a
        // card-supplied signature or key is trusted.
        let manifest_signature = match candidate.trust_verdicts().manifest_signature() {
            ManifestSignatureVerdict::Valid { .. } => SignatureVerdict::Valid,
            ManifestSignatureVerdict::NotApplicable
            | ManifestSignatureVerdict::Pending
            | ManifestSignatureVerdict::Invalid { .. } => SignatureVerdict::Invalid,
        };
        let producer_key_trust = match candidate.trust_verdicts().producer_key() {
            ProducerKeyTrustVerdict::Trusted { .. } => ProducerKeyTrust::Trusted,
            ProducerKeyTrustVerdict::Rejected { .. } => ProducerKeyTrust::Untrusted,
            // The scan verdict is card-derived and therefore always unknown.
            // Only this PC's confirmed registry entry may raise it to trusted,
            // and it says nothing about the signature itself.
            ProducerKeyTrustVerdict::NotApplicable | ProducerKeyTrustVerdict::Unknown { .. } => {
                if producer_key_trusted {
                    ProducerKeyTrust::Trusted
                } else {
                    ProducerKeyTrust::Unknown
                }
            }
        };
        AppSourceProvenance::DeviceSigned {
            publication_key_fingerprint: fingerprint,
            manifest_signature,
            producer_key_trust,
            inventory_integrity: map_inventory_integrity(
                candidate.trust_verdicts().inventory_hashes(),
            ),
        }
    } else {
        AppSourceProvenance::LocallyValidatedUnsigned {
            source_schema: map_unsigned_schema(candidate.schema()),
            validation_report_id: None,
            inventory_digest: match candidate.trust_verdicts().inventory_hashes() {
                InventoryHashesVerdict::Valid { digest } => Some(digest.as_str().to_string()),
                InventoryHashesVerdict::Pending | InventoryHashesVerdict::Invalid { .. } => None,
            },
            admission: UnsignedAdmission::Required,
        }
    }
}

fn map_inventory_integrity(value: &InventoryHashesVerdict) -> InventoryIntegrity {
    match value {
        InventoryHashesVerdict::Pending => InventoryIntegrity::Pending,
        InventoryHashesVerdict::Valid { .. } => InventoryIntegrity::Valid,
        InventoryHashesVerdict::Invalid { .. } => InventoryIntegrity::Invalid,
    }
}

fn map_candidate_verdict(value: CoreCandidateReadiness) -> CandidateVerdict {
    match value {
        CoreCandidateReadiness::ReadySigned => CandidateVerdict::ReadySigned,
        CoreCandidateReadiness::ReadyUnsignedRequiresPolicy => {
            CandidateVerdict::ReadyUnsignedRequiresPolicy
        }
        CoreCandidateReadiness::PendingArtifactValidation => {
            CandidateVerdict::PendingArtifactValidation
        }
        CoreCandidateReadiness::AlreadyImported => CandidateVerdict::AlreadyImported,
        CoreCandidateReadiness::WaitingForPairingKey => CandidateVerdict::WaitingForPairingKey,
        CoreCandidateReadiness::RecordingOrEncodingIncomplete => {
            CandidateVerdict::RecordingOrEncodingIncomplete
        }
        CoreCandidateReadiness::UnsupportedSchema => CandidateVerdict::UnsupportedSchema,
        CoreCandidateReadiness::UnsafePath => CandidateVerdict::UnsafePath,
        CoreCandidateReadiness::InsufficientLocalSpace => CandidateVerdict::InsufficientLocalSpace,
        CoreCandidateReadiness::Corrupt => CandidateVerdict::Corrupt,
    }
}

fn map_source_kind(value: CoreSourceKind) -> AppSourceKind {
    match value {
        CoreSourceKind::RemovableMedia => AppSourceKind::RemovableMedia,
        CoreSourceKind::LegacyRemovableMedia => AppSourceKind::LegacyRemovableMedia,
        CoreSourceKind::LocalFolder => AppSourceKind::LocalFolder,
        CoreSourceKind::Lan => AppSourceKind::Lan,
    }
}

fn map_source_schema(value: CoreSourceSchema) -> AppSourceSchema {
    match value {
        CoreSourceSchema::DeviceSessionV1 => AppSourceSchema::DeviceSessionV1,
        CoreSourceSchema::DeviceSessionV2 => AppSourceSchema::DeviceSessionV2,
        CoreSourceSchema::RawCaptureV2 => AppSourceSchema::RawCaptureV2,
        CoreSourceSchema::LegacyMjpegSessionV5 => AppSourceSchema::LegacyMjpegSessionV5,
        CoreSourceSchema::CompleteUnpublishedV6 => AppSourceSchema::CompleteUnpublishedV6,
        CoreSourceSchema::ApplianceSpoolV6 => AppSourceSchema::ApplianceSpoolV6,
        CoreSourceSchema::UnsignedPublicationV1 => AppSourceSchema::UnsignedPublicationV1,
        CoreSourceSchema::SignedPublicationV1 => AppSourceSchema::SignedPublicationV1,
    }
}

fn map_unsigned_schema(value: CoreSourceSchema) -> UnsignedSourceSchema {
    match value {
        CoreSourceSchema::DeviceSessionV1 => UnsignedSourceSchema::DeviceSessionV1,
        CoreSourceSchema::DeviceSessionV2 => UnsignedSourceSchema::DeviceSessionV2,
        CoreSourceSchema::RawCaptureV2 => UnsignedSourceSchema::RawCaptureV2,
        CoreSourceSchema::LegacyMjpegSessionV5 => UnsignedSourceSchema::LegacyMjpegSessionV5,
        CoreSourceSchema::CompleteUnpublishedV6 => UnsignedSourceSchema::CompleteUnpublishedV6,
        CoreSourceSchema::ApplianceSpoolV6 => UnsignedSourceSchema::ApplianceSpoolV6,
        CoreSourceSchema::UnsignedPublicationV1 => UnsignedSourceSchema::UnsignedPublicationV1,
        CoreSourceSchema::SignedPublicationV1 => {
            unreachable!("signed candidates never use unsigned provenance")
        }
    }
}

fn media_descriptor(
    media_id: MediaId,
    volume: &ylx_transfer_adapters::removable_media::MountedVolume,
    state: &VolumeUiState,
    observed_at: &str,
) -> MediaDescriptor {
    let mount_path = volume.mount_paths.first().map(|path| wire_path(path));
    let display_name = mount_path
        .as_deref()
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(|name| format!("Ubuntu mounted volume ({name})"))
        .unwrap_or_else(|| "Ubuntu mounted removable volume".to_string());
    MediaDescriptor {
        id: media_id,
        display_name,
        mount_path,
        filesystem: volume.filesystem.clone(),
        presence: MediaPresence::Present,
        reader_count: state.reader_count,
        handle_state: state.handle_state,
        eject_state: state.eject_state,
        eject_veto: state.eject_veto.clone(),
        // Nothing has been scanned yet at descriptor-construction time; the
        // scan fills this in for the volumes it actually reaches.
        access_issue: None,
        observed_at: observed_at.to_string(),
    }
}

/// Explain a card that mounted and matched but refused to list its recordings.
///
/// The card grants read access to one specific numeric user id — the one the
/// recorder ran as — so the same card can be readable on one PC and opaque on
/// the next. Without this the UI would show an empty, indistinguishable "no
/// recordings found", which sends the user looking at the card instead of at
/// the account.
fn access_issue_message(diagnostics: &[ScanDiagnostic]) -> Option<String> {
    if !diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code() == ScanDiagnosticCode::PermissionDenied)
    {
        return None;
    }
    let user = current_user_id().map_or_else(
        || "this account".to_string(),
        |user_id| format!("user id {user_id}"),
    );
    Some(format!(
        "This card is mounted, but its recording folder will not open for {user}. \
         The card grants read access to the single user id the recorder ran as, \
         so this computer's account is not that one."
    ))
}

/// The real user id of this process, read from procfs so no extra dependency is
/// needed. `None` when procfs is unavailable.
fn current_user_id() -> Option<u32> {
    fs::metadata("/proc/self")
        .ok()
        .map(|metadata| metadata.uid())
}

fn wire_path(path: &Path) -> String {
    bounded_display(&path.to_string_lossy())
}

fn wire_reader_count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn bounded_display(value: &str) -> String {
    const MAX_BYTES: usize = 1_024;
    let mut output = String::new();
    for character in value.chars() {
        if output.len() + character.len_utf8() > MAX_BYTES {
            break;
        }
        output.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    if output.trim().is_empty() {
        "mounted volume".to_string()
    } else {
        output
    }
}

fn eject_unavailable_reason(reason: EjectUnavailableReason) -> &'static str {
    match reason {
        EjectUnavailableReason::Unsupported => "platform eject is unavailable",
        EjectUnavailableReason::PermissionDenied => "permission denied",
        EjectUnavailableReason::NativeServiceUnavailable => "native eject service unavailable",
        EjectUnavailableReason::Other(_) => "platform eject was not available",
    }
}

fn removable_scan_error(error: impl std::fmt::Display) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::ScanFailed,
        format!("Ubuntu mounted-volume discovery failed: {error}"),
    )
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attach_report(refusal: AttachRefusalReason) -> PlatformAttachReport {
        PlatformAttachReport {
            eligible: 2,
            mounted: 1,
            refusals: vec![refusal],
        }
    }

    #[test]
    fn destination_guard_only_considers_qualified_removable_native_filesystems() {
        assert!(destination_guard_considers_facts(
            EvidenceHint::Yes,
            Some("ext4")
        ));
        assert!(!destination_guard_considers_facts(
            EvidenceHint::No,
            Some("ext4")
        ));
        assert!(!destination_guard_considers_facts(
            EvidenceHint::Unknown,
            Some("ext4")
        ));
        assert!(!destination_guard_considers_facts(
            EvidenceHint::Yes,
            Some("vfat")
        ));
        assert!(!destination_guard_considers_facts(EvidenceHint::Yes, None));
    }

    #[test]
    fn mountinfo_fallback_reports_missing_mount_authority() {
        let issue = attach_issue_for(
            LinuxBackendKind::MountInfoFallback,
            &PlatformAttachReport::default(),
        )
        .expect("fallback must explain its missing attach capability");

        assert_eq!(issue.code, MediaErrorCode::MediaUnavailable.as_str());
        assert!(issue.retryable);
        assert!(issue.message.contains("already-mounted removable volumes"));
        assert_eq!(
            issue.details,
            Some(json!({
                "capability": "udisks2_mount",
                "backend": "mountinfo",
                "eligible": 0,
                "mounted": 0,
            }))
        );
    }

    #[test]
    fn udisks_permission_refusal_is_typed_as_authorization_required() {
        let issue = attach_issue_for(
            LinuxBackendKind::UDisks2,
            &attach_report(AttachRefusalReason::PermissionDenied),
        )
        .expect("permission refusal must be visible");

        assert_eq!(issue.code, MediaErrorCode::MediaUnavailable.as_str());
        assert_eq!(
            issue.details,
            Some(json!({
                "capability": "udisks2_mount",
                "reason": "authorization_required",
                "eligible": 2,
                "mounted": 1,
                "refusalCount": 1,
            }))
        );
    }

    #[test]
    fn udisks_service_refusal_is_typed_as_unavailable() {
        let issue = attach_issue_for(
            LinuxBackendKind::UDisks2,
            &attach_report(AttachRefusalReason::NativeServiceUnavailable),
        )
        .expect("service refusal must be visible");

        assert_eq!(
            issue.details,
            Some(json!({
                "capability": "udisks2_mount",
                "reason": "udisks2_unavailable",
                "eligible": 2,
                "mounted": 1,
                "refusalCount": 1,
            }))
        );
    }

    #[test]
    fn unknown_attach_refusal_does_not_expose_platform_text() {
        let secret = "/run/secrets/storage-key";
        let issue = attach_issue_for(
            LinuxBackendKind::UDisks2,
            &attach_report(AttachRefusalReason::Other(format!(
                "native failure at {secret}"
            ))),
        )
        .expect("unknown refusal must be visible");

        assert_eq!(
            issue.message,
            "UDisks2 refused to mount an inserted removable volume for an unspecified platform reason"
        );
        assert!(!issue.message.contains(secret));
        assert_eq!(
            issue.details,
            Some(json!({
                "capability": "udisks2_mount",
                "reason": "attach_refused",
                "eligible": 2,
                "mounted": 1,
                "refusalCount": 1,
            }))
        );
    }

    #[test]
    fn attach_errors_are_retryable_without_platform_payload_details() {
        let issue = attach_error(RemovableMediaError::CatalogUnavailable);

        assert_eq!(issue.code, MediaErrorCode::MediaUnavailable.as_str());
        assert!(issue.retryable);
        assert!(issue.message.contains("could not be evaluated"));
        assert_eq!(
            issue.details,
            Some(json!({
                "capability": "udisks2_mount",
                "reason": "attach_error",
            }))
        );
    }
}
