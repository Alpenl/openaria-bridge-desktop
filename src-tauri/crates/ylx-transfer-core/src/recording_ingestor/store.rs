//! Concrete adapters from recording-ingest effect ports to `MediaStore`.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ingest::{
    ImportJobId, ImportSnapshot, ImportSpec, LocalSourceReceipt, SourceProvenance, SourceSchema,
};
use crate::media_store::{
    AcquireLeaseOutcome, AcquireLibraryLease, CompareAndSwapOutcome as StoreSwapOutcome,
    CompleteOutcome, CreateImportJobError, CreateJobConflict, CreateJobOutcome,
    ImportCommitProjection, ImportLocatorUpdate, LibraryLeaseMode, LibraryRevisionKind, MediaStore,
    StoredImportJob,
};

use super::ports::{
    CompareAndSwapOutcome, CreateStoredImportOutcome, ImportRepository, IngestClock,
    IngestPortError, SourcePublishLease, SourcePublishLeases, StoredImport,
};

const SOURCE_PUBLISH_LEASE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone)]
pub struct MediaStoreImportRepository {
    store: Arc<Mutex<MediaStore>>,
    clock: Arc<dyn IngestClock>,
}

impl MediaStoreImportRepository {
    #[must_use]
    pub fn new(store: Arc<Mutex<MediaStore>>, clock: Arc<dyn IngestClock>) -> Self {
        Self { store, clock }
    }

    #[must_use]
    pub fn store(&self) -> &Arc<Mutex<MediaStore>> {
        &self.store
    }
}

impl ImportRepository for MediaStoreImportRepository {
    fn create_import(
        &self,
        spec: &ImportSpec,
        _initial_snapshot: &ImportSnapshot,
    ) -> Result<CreateStoredImportOutcome, IngestPortError> {
        let now = self.clock.now_rfc3339();
        let mut store = lock(&self.store);
        match store.create_import_job(spec, &now) {
            Ok(CreateJobOutcome::Created(job)) => {
                Ok(CreateStoredImportOutcome::Created(stored_import(job)))
            }
            Ok(CreateJobOutcome::Existing(job)) => {
                Ok(CreateStoredImportOutcome::Existing(stored_import(job)))
            }
            Err(CreateImportJobError::Conflict(conflict)) => map_create_conflict(conflict),
            Err(CreateImportJobError::Store(error)) => Err(store_error(error)),
        }
    }

    fn load_import(&self, job_id: &ImportJobId) -> Result<Option<StoredImport>, IngestPortError> {
        lock(&self.store)
            .import_job(job_id)
            .map_err(store_error)
            .map(|job| job.map(stored_import))
    }

    fn list_import_snapshots(&self) -> Result<Vec<ImportSnapshot>, IngestPortError> {
        lock(&self.store)
            .import_projection()
            .map_err(store_error)
            .map(|collection| {
                collection
                    .items
                    .into_iter()
                    .map(|job| job.snapshot)
                    .collect()
            })
    }

    fn compare_and_swap(
        &self,
        job_id: &ImportJobId,
        expected_version: u64,
        next: &ImportSnapshot,
    ) -> Result<CompareAndSwapOutcome, IngestPortError> {
        let now = self.clock.now_rfc3339();
        let mut store = lock(&self.store);
        let current = store.import_job(job_id).map_err(store_error)?;
        let Some(current) = current else {
            return Ok(CompareAndSwapOutcome::Missing);
        };
        let locator_update = locator_update(&current, next);
        match store.compare_and_swap_import_snapshot(expected_version, next, locator_update, &now) {
            Ok(StoreSwapOutcome::Applied(job)) => Ok(CompareAndSwapOutcome::Applied(job.snapshot)),
            Ok(StoreSwapOutcome::AlreadyApplied(job)) => {
                Ok(CompareAndSwapOutcome::Applied(job.snapshot))
            }
            Err(error) => map_cas_error(&mut store, job_id, expected_version, error),
        }
    }

    fn commit_local_verified(
        &self,
        job_id: &ImportJobId,
        expected_version: u64,
        next: &ImportSnapshot,
        receipt: &LocalSourceReceipt,
    ) -> Result<CompareAndSwapOutcome, IngestPortError> {
        let now = self.clock.now_rfc3339();
        let mut store = lock(&self.store);
        let current = store.import_job(job_id).map_err(store_error)?;
        let Some(current) = current else {
            return Ok(CompareAndSwapOutcome::Missing);
        };
        let locator_update = locator_update(&current, next);
        let receipt_id = import_receipt_id(job_id);
        let source_identity = source_identity(&current.spec, receipt);
        let projection = ImportCommitProjection {
            receipt_id: &receipt_id,
            source_identity: &source_identity,
        };
        match store.complete_import_job(
            expected_version,
            next,
            locator_update,
            Some(projection),
            &now,
        ) {
            Ok(outcome) => match outcome.completion {
                CompleteOutcome::Recorded(_) => {
                    Ok(CompareAndSwapOutcome::Applied(outcome.job.snapshot))
                }
                CompleteOutcome::AlreadyRecorded(_) => {
                    Ok(CompareAndSwapOutcome::Applied(outcome.job.snapshot))
                }
            },
            Err(error) => map_cas_error(&mut store, job_id, expected_version, error),
        }
    }
}

#[derive(Clone)]
pub struct MediaStoreSourcePublishLeases {
    store: Arc<Mutex<MediaStore>>,
    ttl_ms: u64,
}

impl MediaStoreSourcePublishLeases {
    #[must_use]
    pub fn new(store: Arc<Mutex<MediaStore>>) -> Self {
        Self {
            store,
            ttl_ms: SOURCE_PUBLISH_LEASE_TTL_MS,
        }
    }

    #[must_use]
    pub fn with_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = ttl_ms.max(1);
        self
    }
}

impl SourcePublishLeases for MediaStoreSourcePublishLeases {
    fn acquire_exclusive(
        &self,
        source_revision: &str,
        owner_job_id: &ImportJobId,
    ) -> Result<Box<dyn SourcePublishLease>, IngestPortError> {
        let now_ms = unix_millis();
        let expires_at_ms = now_ms.saturating_add(self.ttl_ms);
        let now = now_ms.to_string();
        let lease_id = format!(
            "recording-ingest-source-{}-{}",
            owner_job_id.as_str(),
            uuid::Uuid::new_v4()
        );
        let request = AcquireLibraryLease {
            lease_id: &lease_id,
            revision_kind: LibraryRevisionKind::Source,
            revision_id: source_revision,
            owner_id: owner_job_id.as_str(),
            mode: LibraryLeaseMode::Exclusive,
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
                return Err(IngestPortError::new(
                    "source_publish_lease_busy",
                    "source revision is already held by another library operation",
                ))
            }
        };
        Ok(Box::new(MediaStoreSourcePublishLease {
            store: Arc::clone(&self.store),
            lease_id: lease.lease_id,
            owner_id: lease.owner_id,
            fencing_token: lease.fencing_token,
            expires_at_ms: lease.expires_at_ms,
            ttl_ms: self.ttl_ms,
        }))
    }
}

struct MediaStoreSourcePublishLease {
    store: Arc<Mutex<MediaStore>>,
    lease_id: String,
    owner_id: String,
    fencing_token: u64,
    expires_at_ms: u64,
    ttl_ms: u64,
}

impl SourcePublishLease for MediaStoreSourcePublishLease {
    fn assert_current(&mut self) -> Result<(), IngestPortError> {
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
            return Ok(());
        }
        lock(&self.store)
            .assert_library_revision_lease(
                &self.lease_id,
                &self.owner_id,
                self.fencing_token,
                LibraryLeaseMode::Exclusive,
                now_ms,
            )
            .map_err(store_error)?;
        Ok(())
    }
}

impl Drop for MediaStoreSourcePublishLease {
    fn drop(&mut self) {
        let _ = lock(&self.store).release_library_revision_lease(
            &self.lease_id,
            &self.owner_id,
            self.fencing_token,
        );
    }
}

fn stored_import(job: StoredImportJob) -> StoredImport {
    let crate::media_store::ImportLocatorSnapshot {
        locator, version, ..
    } = job.locator;
    StoredImport {
        spec: job.spec,
        snapshot: job.snapshot,
        locator,
        locator_version: version,
    }
}

fn locator_update<'a>(
    current: &StoredImportJob,
    next: &'a ImportSnapshot,
) -> Option<ImportLocatorUpdate<'a>> {
    let active = next.active_locator()?;
    if active == &current.locator.locator {
        return None;
    }
    Some(ImportLocatorUpdate {
        expected_version: current.locator.version,
        locator: active,
    })
}

fn map_create_conflict(
    conflict: CreateJobConflict,
) -> Result<CreateStoredImportOutcome, IngestPortError> {
    match conflict {
        CreateJobConflict::RequestDigestMismatch {
            existing_job_id, ..
        } => Ok(CreateStoredImportOutcome::Conflict {
            existing_job_id: ImportJobId::parse(existing_job_id)
                .map_err(|error| IngestPortError::new("media_store_corrupt", error.to_string()))?,
            reason: "natural key request digest differs".to_string(),
        }),
        CreateJobConflict::JobIdCollision {
            job_id,
            existing_natural_key,
        } => Err(IngestPortError::new(
            "job_id_collision",
            format!("job id {job_id:?} is already used by natural key {existing_natural_key:?}"),
        )),
    }
}

fn map_cas_error(
    store: &mut MediaStore,
    job_id: &ImportJobId,
    expected_version: u64,
    error: crate::media_store::MediaStoreError,
) -> Result<CompareAndSwapOutcome, IngestPortError> {
    if let Ok(Some(current)) = store.import_job(job_id) {
        if current.snapshot.version() != expected_version {
            return Ok(CompareAndSwapOutcome::Conflict(current.snapshot));
        }
    }
    Err(store_error(error))
}

fn source_identity(spec: &ImportSpec, receipt: &LocalSourceReceipt) -> String {
    match receipt.provenance() {
        SourceProvenance::DeviceSigned(signed) => {
            let mut identity = String::from("source-device-signed-v1:");
            append_component(&mut identity, signed.publication_key_fingerprint());
            append_component(&mut identity, spec.source().session_id());
            identity
        }
        SourceProvenance::LocallyValidatedUnsigned(unsigned) => {
            let mut identity = String::from("source-unsigned-local-v1:");
            append_component(&mut identity, source_schema_str(unsigned.source_schema()));
            identity
        }
    }
}

fn source_schema_str(schema: SourceSchema) -> &'static str {
    match schema {
        SourceSchema::DeviceSessionV1 => "device_session_v1",
        SourceSchema::DeviceSessionV2 => "device_session_v2",
        SourceSchema::SignedPublicationV1 => "signed_publication_v1",
        SourceSchema::UnsignedPublicationV1 => "unsigned_publication_v1",
        SourceSchema::RawCaptureV2 => "raw_capture_v2",
        SourceSchema::LegacyMjpegSessionV5 => "legacy_mjpeg_session_v5",
        SourceSchema::CompleteUnpublishedV6 => "complete_unpublished_v6",
        SourceSchema::ApplianceSpoolV6 => "appliance_spool_v6",
    }
}

fn import_receipt_id(job_id: &ImportJobId) -> String {
    format!("local-source-import-v1:{}", job_id.as_str())
}

fn append_component(output: &mut String, component: &str) {
    use std::fmt::Write as _;

    let _ = write!(output, "{}:{}", component.len(), component);
}

fn store_error(error: crate::media_store::MediaStoreError) -> IngestPortError {
    IngestPortError::new("media_store", error.to_string())
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
