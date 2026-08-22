//! Concrete adapters from the effect ports to `media_store`.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::media_store::{
    AcquireLeaseOutcome, AcquireLibraryLease, CompareAndSwapOutcome, CreateDerivationJobError,
    CreateJobOutcome, LibraryLeaseMode, LibraryRevisionKind, MediaStore,
};
use crate::normalization::{
    DerivationJobId, DerivationSnapshot, DerivationSpec, DerivedCompletion, DerivedManifest,
    SourceContentRevision,
};

use super::ports::{
    CreateDerivationOutcome, DerivationRepository, DerivedCommitEvidence, MediaNormalizerPortError,
    SnapshotSwapOutcome, SourceReadLease, SourceReadLeases, StoredDerivation,
};

const SOURCE_LEASE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone)]
pub struct MediaStoreDerivationRepository {
    store: Arc<Mutex<MediaStore>>,
}

impl MediaStoreDerivationRepository {
    #[must_use]
    pub fn new(store: Arc<Mutex<MediaStore>>) -> Self {
        Self { store }
    }

    #[must_use]
    pub fn store(&self) -> &Arc<Mutex<MediaStore>> {
        &self.store
    }
}

impl DerivationRepository for MediaStoreDerivationRepository {
    fn create_derivation(
        &self,
        spec: &DerivationSpec,
        _initial: &DerivationSnapshot,
        now: &str,
    ) -> Result<CreateDerivationOutcome, MediaNormalizerPortError> {
        let mut store = lock(&self.store);
        let created = match store.create_derivation_job(spec, now) {
            Ok(value) => value,
            Err(CreateDerivationJobError::Conflict(conflict)) => {
                return Ok(match conflict {
                    crate::media_store::CreateJobConflict::RequestDigestMismatch {
                        existing_job_id,
                        ..
                    } => CreateDerivationOutcome::Conflict {
                        existing_job_id: DerivationJobId::parse(existing_job_id).map_err(|_| {
                            MediaNormalizerPortError::new(
                                "media_store_corrupt",
                                "conflict referenced an invalid job id",
                            )
                        })?,
                        reason: "natural key request digest differs".to_string(),
                    },
                    crate::media_store::CreateJobConflict::JobIdCollision {
                        job_id,
                        existing_natural_key,
                    } => {
                        return Err(MediaNormalizerPortError::new(
                            "job_id_collision",
                            format!(
                                "job id {job_id:?} is already used by natural key {existing_natural_key:?}"
                            ),
                        ))
                    }
                });
            }
            Err(CreateDerivationJobError::Store(error)) => return Err(store_error(error)),
        };
        match created {
            CreateJobOutcome::Created(job) => {
                Ok(CreateDerivationOutcome::Created(StoredDerivation {
                    snapshot: job.snapshot,
                }))
            }
            CreateJobOutcome::Existing(job) => {
                if job.snapshot.spec() != spec || job.snapshot.version() == 0 {
                    return Err(MediaNormalizerPortError::new(
                        "natural_key_corrupt",
                        "existing derivation does not match requested immutable spec",
                    ));
                }
                Ok(CreateDerivationOutcome::Existing(StoredDerivation {
                    snapshot: job.snapshot,
                }))
            }
        }
    }

    fn load_derivation(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<Option<StoredDerivation>, MediaNormalizerPortError> {
        lock(&self.store)
            .derivation_job(job_id)
            .map_err(store_error)
            .map(|job| {
                job.map(|job| StoredDerivation {
                    snapshot: job.snapshot,
                })
            })
    }

    fn list_derivations(&self) -> Result<Vec<StoredDerivation>, MediaNormalizerPortError> {
        lock(&self.store)
            .derivation_projection()
            .map_err(store_error)
            .map(|collection| {
                collection
                    .items
                    .into_iter()
                    .map(|job| StoredDerivation {
                        snapshot: job.snapshot,
                    })
                    .collect()
            })
    }

    fn compare_and_swap(
        &self,
        _job_id: &DerivationJobId,
        expected_version: u64,
        next: &DerivationSnapshot,
        now: &str,
    ) -> Result<SnapshotSwapOutcome, MediaNormalizerPortError> {
        let mut store = lock(&self.store);
        match store.compare_and_swap_derivation_snapshot(expected_version, next, now) {
            Ok(CompareAndSwapOutcome::Applied(job)) => {
                Ok(SnapshotSwapOutcome::Applied(StoredDerivation {
                    snapshot: job.snapshot,
                }))
            }
            Ok(CompareAndSwapOutcome::AlreadyApplied(job)) => {
                Ok(SnapshotSwapOutcome::AlreadyApplied(StoredDerivation {
                    snapshot: job.snapshot,
                }))
            }
            Err(error) => map_cas_error(&mut store, next.spec().job_id(), expected_version, error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_derived_verified(
        &self,
        _job_id: &DerivationJobId,
        expected_version: u64,
        next: &DerivationSnapshot,
        completion: &DerivedCompletion,
        manifest: &DerivedManifest,
        evidence: &DerivedCommitEvidence,
        now: &str,
    ) -> Result<SnapshotSwapOutcome, MediaNormalizerPortError> {
        validate_commit_evidence(completion, manifest, evidence)?;
        let mut store = lock(&self.store);
        match store.complete_derivation_job(expected_version, next, now) {
            Ok(outcome) => {
                let crate::media_store::CompleteDerivationOutcome {
                    job,
                    completion: completion_outcome,
                } = outcome;
                let stored = StoredDerivation {
                    snapshot: job.snapshot,
                };
                match completion_outcome {
                    crate::media_store::CompleteOutcome::Recorded(_) => {
                        Ok(SnapshotSwapOutcome::Applied(stored))
                    }
                    crate::media_store::CompleteOutcome::AlreadyRecorded(_) => {
                        Ok(SnapshotSwapOutcome::AlreadyApplied(stored))
                    }
                }
            }
            Err(error) => map_cas_error(&mut store, next.spec().job_id(), expected_version, error),
        }
    }

    fn retire_derivation(&self, _job_id: &DerivationJobId) -> Result<(), MediaNormalizerPortError> {
        // The current MediaStore keeps terminal rows as replayable outbox
        // evidence. Retirement is therefore an intentional no-op at this
        // layer; a future vacuum may delete only acknowledged rows while
        // retaining immutable derived receipts.
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MediaStoreSourceReadLeases {
    store: Arc<Mutex<MediaStore>>,
    ttl_ms: u64,
}

impl MediaStoreSourceReadLeases {
    #[must_use]
    pub fn new(store: Arc<Mutex<MediaStore>>) -> Self {
        Self {
            store,
            ttl_ms: SOURCE_LEASE_TTL_MS,
        }
    }

    #[must_use]
    pub fn with_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = ttl_ms.max(1);
        self
    }
}

impl SourceReadLeases for MediaStoreSourceReadLeases {
    fn acquire_shared(
        &self,
        source_revision: &SourceContentRevision,
        owner_job_id: &DerivationJobId,
    ) -> Result<Box<dyn SourceReadLease>, MediaNormalizerPortError> {
        let now_ms = unix_millis();
        let expires_at_ms = now_ms.saturating_add(self.ttl_ms);
        let lease_id = format!(
            "normalizer-source-{}-{}",
            owner_job_id.as_str(),
            uuid::Uuid::new_v4()
        );
        let now = now_ms.to_string();
        let request = AcquireLibraryLease {
            lease_id: &lease_id,
            revision_kind: LibraryRevisionKind::Source,
            revision_id: source_revision.as_str(),
            owner_id: owner_job_id.as_str(),
            mode: LibraryLeaseMode::Shared,
            now: &now,
            now_ms,
            expires_at_ms,
        };
        let lease = match lock(&self.store)
            .acquire_library_revision_lease(&request)
            .map_err(store_error)?
        {
            AcquireLeaseOutcome::Acquired(lease) | AcquireLeaseOutcome::Existing(lease) => lease,
            AcquireLeaseOutcome::Conflict(_) => {
                return Err(MediaNormalizerPortError::new(
                    "source_lease_busy",
                    "source revision is held by an exclusive library operation",
                ))
            }
        };
        Ok(Box::new(MediaStoreSourceReadLease {
            store: Arc::clone(&self.store),
            lease_id: lease.lease_id,
            owner_id: lease.owner_id,
            fencing_token: lease.fencing_token,
            expires_at_ms: lease.expires_at_ms,
            ttl_ms: self.ttl_ms,
        }))
    }
}

struct MediaStoreSourceReadLease {
    store: Arc<Mutex<MediaStore>>,
    lease_id: String,
    owner_id: String,
    fencing_token: u64,
    expires_at_ms: u64,
    ttl_ms: u64,
}

impl SourceReadLease for MediaStoreSourceReadLease {
    fn assert_current(&mut self) -> Result<(), MediaNormalizerPortError> {
        let now_ms = unix_millis();
        if now_ms.saturating_add(self.ttl_ms / 3) >= self.expires_at_ms {
            let now = now_ms.to_string();
            let renewed = lock(&self.store)
                .renew_library_revision_lease(
                    &self.lease_id,
                    &self.owner_id,
                    self.fencing_token,
                    &now,
                    now_ms,
                    now_ms.saturating_add(self.ttl_ms),
                )
                .map_err(store_error)?;
            self.expires_at_ms = renewed.expires_at_ms;
        } else {
            lock(&self.store)
                .assert_library_revision_lease(
                    &self.lease_id,
                    &self.owner_id,
                    self.fencing_token,
                    LibraryLeaseMode::Shared,
                    now_ms,
                )
                .map_err(store_error)?;
        }
        Ok(())
    }
}

impl Drop for MediaStoreSourceReadLease {
    fn drop(&mut self) {
        let _ = lock(&self.store).release_library_revision_lease(
            &self.lease_id,
            &self.owner_id,
            self.fencing_token,
        );
    }
}

fn validate_commit_evidence(
    completion: &DerivedCompletion,
    manifest: &DerivedManifest,
    evidence: &DerivedCommitEvidence,
) -> Result<(), MediaNormalizerPortError> {
    let manifest_sha = format!("{:x}", Sha256::digest(manifest.canonical_bytes()));
    if manifest_sha != evidence.manifest_sha256
        || output_inventory_sha256(manifest) != evidence.output_inventory_sha256
        || completion.derived_revision() != manifest.derived_revision()
        || completion.local_relative_path() != evidence.local_relative_path
        || completion.local_commit_receipt() != evidence.local_commit_receipt
    {
        return Err(MediaNormalizerPortError::new(
            "commit_evidence_mismatch",
            "filesystem commit evidence differs from canonical completion",
        ));
    }
    Ok(())
}

fn output_inventory_sha256(manifest: &DerivedManifest) -> String {
    let bytes = serde_json::to_vec(manifest.output_inventory()).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

fn map_cas_error(
    store: &mut MediaStore,
    job_id: &DerivationJobId,
    expected_version: u64,
    error: crate::media_store::MediaStoreError,
) -> Result<SnapshotSwapOutcome, MediaNormalizerPortError> {
    if let Ok(Some(current)) = store.derivation_job(job_id) {
        if current.snapshot.version() != expected_version {
            return Ok(SnapshotSwapOutcome::Stale(StoredDerivation {
                snapshot: current.snapshot,
            }));
        }
    }
    Err(store_error(error))
}

fn store_error(error: crate::media_store::MediaStoreError) -> MediaNormalizerPortError {
    MediaNormalizerPortError::new("media_store", error.to_string())
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
