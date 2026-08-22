//! Idempotent completion projector for the Ubuntu media pipeline.
//!
//! `MediaStore` and `AppStore` are separate SQLite files, so a job's terminal
//! transaction and the library projection it implies cannot commit together.
//! The completion outbox is the seam: the job writes its outbox row atomically
//! with its terminal state, and this projector consumes that row, applies the
//! projection, and only then acknowledges. A pseudo-atomic double write would
//! be a lie in both crash directions.
//!
//! Two rules make replay safe:
//!
//! * Commands are rebuilt from the long-lived immutable receipt, never from the
//!   outbox payload. An event carries a snapshot; the receipt carries the
//!   evidence. Trusting the event would let a stale or tampered payload decide
//!   what the library says.
//! * Acknowledging happens only after the AppStore committed, or after it
//!   reported the exact same state as already applied. A crash before the
//!   acknowledgement replays the envelope; a crash after it has already
//!   produced the projection.

use std::sync::{Arc, Mutex, MutexGuard};

use chrono::DateTime;
use ylx_transfer_adapters::derived_upload::DerivedUploadAdapter;
use ylx_transfer_core::media_library::{
    AppStoreMediaLibraryProjectionRepository, ExpectedProjectionRevision, LibraryEntryKey,
    LibraryProjectionCommand, LibraryProjectionRepository, LibraryProjector,
    MediaLibraryProjection, ProjectionError,
};
use ylx_transfer_core::media_pipeline::{FrozenUploadBundle, StorageProfileIdentity};
use ylx_transfer_core::media_store::{
    AcknowledgeOutcome, LibraryImportReceipt, MediaStore, MediaStoreError,
};
use ylx_transfer_core::normalization::DerivationJobId;
use ylx_transfer_core::persistence::{AckOutcome, OperationKind, TransferStore};

use super::ports::{MediaErrorCode, MediaPortError};

/// How many times one envelope may be recomputed after a compare-and-swap
/// conflict before the drain gives up on it and moves on. The row stays
/// unacknowledged, so the next drain retries it.
const MAX_CAS_ATTEMPTS: usize = 8;

/// What one drain pass did. Counts are diagnostics; correctness comes from the
/// outbox rows themselves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectionDrainReport {
    pub imports_projected: usize,
    pub derivations_projected: usize,
    pub uploads_projected: usize,
    pub deferred: usize,
}

/// Consumes media-store completion outboxes into the AppStore media library.
pub struct UbuntuMediaCompletionProjector {
    media_store: Arc<Mutex<MediaStore>>,
    transfer_store: Arc<Mutex<TransferStore>>,
    projector: Mutex<LibraryProjector<AppStoreMediaLibraryProjectionRepository>>,
    now: Arc<dyn Fn() -> String + Send + Sync>,
}

impl std::fmt::Debug for UbuntuMediaCompletionProjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UbuntuMediaCompletionProjector")
            .finish_non_exhaustive()
    }
}

impl UbuntuMediaCompletionProjector {
    #[must_use]
    pub fn new(
        media_store: Arc<Mutex<MediaStore>>,
        transfer_store: Arc<Mutex<TransferStore>>,
        repository: AppStoreMediaLibraryProjectionRepository,
        now: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            media_store,
            transfer_store,
            projector: Mutex::new(LibraryProjector::new(repository)),
            now,
        })
    }

    /// Complete media-library view plus the AppStore revision that guarded
    /// the read. The revision is the application publication watermark; an
    /// individual projection revision is not a collection revision.
    pub fn projection_snapshot(
        &self,
    ) -> Result<(u64, Vec<MediaLibraryProjection>), MediaPortError> {
        lock(&self.projector)
            .repository()
            .load_all_with_revision()
            .map_err(|error| projection_store_error("read media library projections", &error))
    }

    /// Drain both lanes in dependency order: an import must be projected before
    /// the derivation that depends on it, otherwise the derived command would
    /// find no entry to attach to.
    pub fn drain(&self) -> Result<ProjectionDrainReport, MediaPortError> {
        let mut report = ProjectionDrainReport::default();
        self.drain_imports(&mut report)?;
        self.drain_derivations(&mut report)?;
        self.drain_uploads(&mut report)?;
        Ok(report)
    }

    fn drain_imports(&self, report: &mut ProjectionDrainReport) -> Result<(), MediaPortError> {
        let pending = self
            .media_store()
            .pending_import_completions()
            .map_err(|error| store_error("read pending import completions", &error))?;
        for envelope in pending {
            // The event payload is not evidence. Re-read the immutable import
            // receipt that the same terminal transaction wrote.
            let receipt = self
                .media_store()
                .import_receipt_for_job(&envelope.job_id)
                .map_err(|error| store_error("read import receipt", &error))?;
            let Some(receipt) = receipt else {
                // A completion without its receipt is not something to
                // acknowledge away; it is durable evidence of an inconsistency
                // that must stay visible until it is repaired.
                report.deferred += 1;
                continue;
            };
            let entry_key = import_entry_key(&receipt)?;
            let applied = self.apply(&entry_key, || LibraryProjectionCommand::RecordImport {
                receipt: receipt.clone(),
            })?;
            if !applied {
                report.deferred += 1;
                continue;
            }
            let job_id = parse_import_job_id(&envelope.job_id)?;
            match self
                .media_store()
                .acknowledge_import_completion(&job_id, &(self.now)())
                .map_err(|error| store_error("acknowledge import completion", &error))?
            {
                AcknowledgeOutcome::Acknowledged(_)
                | AcknowledgeOutcome::AlreadyAcknowledged(_) => {
                    report.imports_projected += 1;
                }
                // A vanished row means someone else acknowledged it; the
                // projection above is still correct and idempotent.
                AcknowledgeOutcome::Unknown => report.imports_projected += 1,
            }
        }
        Ok(())
    }

    fn drain_derivations(&self, report: &mut ProjectionDrainReport) -> Result<(), MediaPortError> {
        let pending = self
            .media_store()
            .pending_derivation_completions()
            .map_err(|error| store_error("read pending derivation completions", &error))?;
        for envelope in pending {
            let derived = self
                .media_store()
                .derived_receipt_for_job(&envelope.job_id)
                .map_err(|error| store_error("read derived receipt", &error))?;
            let Some(derived) = derived else {
                report.deferred += 1;
                continue;
            };
            // A derived entry belongs to the source it was derived from, so
            // the entry key comes from the source's import receipt rather than
            // from anything the derivation itself asserts.
            let source = self
                .media_store()
                .import_receipt_by_source_revision(&derived.source_revision)
                .map_err(|error| store_error("read source import receipt", &error))?;
            let Some(source) = source else {
                report.deferred += 1;
                continue;
            };
            let entry_key = import_entry_key(&source)?;
            let applied = self.apply(&entry_key, || LibraryProjectionCommand::RecordDerived {
                receipt: derived.clone(),
            })?;
            if !applied {
                report.deferred += 1;
                continue;
            }
            let job_id = parse_derivation_job_id(&envelope.job_id)?;
            match self
                .media_store()
                .acknowledge_derivation_completion(&job_id, &(self.now)())
                .map_err(|error| store_error("acknowledge derivation completion", &error))?
            {
                AcknowledgeOutcome::Acknowledged(_)
                | AcknowledgeOutcome::AlreadyAcknowledged(_)
                | AcknowledgeOutcome::Unknown => report.derivations_projected += 1,
            }
        }
        Ok(())
    }

    /// Consume only the derived-upload subset of the shared transfer outbox.
    /// Legacy publication uploads have a different receipt authority and are
    /// deliberately left for their existing transfer owner. A successful
    /// derived upload is accepted only when its frozen bundle and exact
    /// completion-bound object receipts reconstruct a `RemoteBundleReceipt`;
    /// a latest-key HEAD is never a substitute.
    fn drain_uploads(&self, report: &mut ProjectionDrainReport) -> Result<(), MediaPortError> {
        let pending = lock(&self.transfer_store)
            .pending_completions()
            .map_err(|error| transfer_error("read pending upload completions", &error))?;
        for envelope in pending {
            if envelope.operation_kind != OperationKind::Upload {
                continue;
            }
            let stored = lock(&self.transfer_store)
                .derived_upload_job(&envelope.job_id)
                .map_err(|error| transfer_error("read derived upload sidecar", &error))?;
            let Some(stored) = stored else {
                // The existing LAN publication uploader owns upload jobs that
                // have no derived sidecar. Do not acknowledge another lane's
                // completion merely because it shares this SQLite outbox.
                continue;
            };

            if !envelope.outcome.is_success() {
                acknowledge_transfer_completion(
                    &self.transfer_store,
                    &envelope.job_id,
                    &(self.now)(),
                )?;
                continue;
            }

            let bundle: FrozenUploadBundle = serde_json::from_str(&stored.frozen_bundle_json)
                .map_err(|error| {
                    integrity_error(format!("frozen upload bundle is invalid: {error}"))
                })?;
            if bundle.revision().as_str() != stored.upload_bundle_revision {
                return Err(integrity_error(
                    "frozen upload bundle revision differs from its durable identity",
                ));
            }
            let identity = StorageProfileIdentity::parse(stored.storage_profile_identity.clone())
                .map_err(|error| {
                integrity_error(format!("storage profile identity is invalid: {error}"))
            })?;
            let checkpoint = serde_json::from_str(&stored.checkpoint_json).map_err(|error| {
                integrity_error(format!("upload checkpoint is invalid: {error}"))
            })?;
            let remote =
                DerivedUploadAdapter::remote_bundle_from_checkpoint(&bundle, identity, &checkpoint)
                    .map_err(|error| {
                        integrity_error(format!(
                    "derived upload completion lacks completion-bound verified evidence: {error}"
                ))
                    })?;

            let source = self
                .media_store()
                .import_receipt_by_source_revision(bundle.source_revision().as_str())
                .map_err(|error| store_error("read source import receipt for upload", &error))?;
            let Some(source) = source else {
                report.deferred += 1;
                continue;
            };
            let entry_key = import_entry_key(&source)?;
            if entry_key.as_str() != stored.media_library_entry_key {
                return Err(integrity_error(
                    "derived upload sidecar points at a different media-library entry",
                ));
            }
            let verified_at_ms = completion_time_ms(&envelope.recorded_at)?;
            let applied = self.apply(&entry_key, || {
                LibraryProjectionCommand::RecordRemoteBundleVerified {
                    receipt: remote.clone(),
                    verified_at_ms,
                }
            })?;
            if !applied {
                report.deferred += 1;
                continue;
            }
            acknowledge_transfer_completion(&self.transfer_store, &envelope.job_id, &(self.now)())?;
            report.uploads_projected += 1;
        }
        Ok(())
    }

    /// Apply one command with bounded reload-and-retry.
    ///
    /// A revision conflict is expected under concurrency and is resolved by
    /// re-reading and recomputing. A conflict about the immutable evidence
    /// itself is not: that means two different receipts claim the same entry,
    /// which must stop rather than be resolved by retrying.
    fn apply(
        &self,
        entry_key: &LibraryEntryKey,
        command: impl Fn() -> LibraryProjectionCommand,
    ) -> Result<bool, MediaPortError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let mut projector = lock(&self.projector);
            let loaded = projector
                .repository()
                .load_projection(entry_key)
                .map_err(|error| projection_store_error("load media library projection", &error))?;
            let expected = ExpectedProjectionRevision {
                store_revision: loaded.store_revision,
                projection_revision: loaded
                    .projection
                    .as_ref()
                    .map(|projection| projection.projection_revision),
            };
            match projector.project(entry_key, expected, command()) {
                Ok(_) => return Ok(true),
                Err(ProjectionError::StoreRevisionConflict { .. })
                | Err(ProjectionError::ProjectionRevisionConflict { .. }) => continue,
                Err(ProjectionError::Store(error)) => {
                    return Err(projection_store_error("commit media library entry", &error));
                }
                Err(other) => {
                    // Immutable-evidence disagreement. Leave the outbox row
                    // unacknowledged so the inconsistency stays visible.
                    return Err(MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        format!("media library projection was rejected: {other}"),
                    )
                    .with_retryable(false));
                }
            }
        }
        Ok(false)
    }

    fn media_store(&self) -> MutexGuard<'_, MediaStore> {
        lock(&self.media_store)
    }
}

fn acknowledge_transfer_completion(
    store: &Arc<Mutex<TransferStore>>,
    job_id: &str,
    now: &str,
) -> Result<(), MediaPortError> {
    match lock(store)
        .acknowledge_completion(job_id, now)
        .map_err(|error| transfer_error("acknowledge upload completion", &error))?
    {
        AckOutcome::Acknowledged(_) | AckOutcome::AlreadyAcknowledged(_) | AckOutcome::Unknown => {
            Ok(())
        }
    }
}

fn completion_time_ms(value: &str) -> Result<u64, MediaPortError> {
    let timestamp = DateTime::parse_from_rfc3339(value).map_err(|error| {
        integrity_error(format!("upload completion timestamp is invalid: {error}"))
    })?;
    u64::try_from(timestamp.timestamp_millis())
        .map_err(|_| integrity_error("upload completion timestamp is before the Unix epoch"))
}

fn import_entry_key(receipt: &LibraryImportReceipt) -> Result<LibraryEntryKey, MediaPortError> {
    let revision =
        ylx_transfer_core::ingest::SourceContentRevision::parse(receipt.source_revision.clone())
            .map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    format!("import receipt has an invalid source revision: {error}"),
                )
                .with_retryable(false)
            })?;
    LibraryEntryKey::for_source(&receipt.source_identity, &revision).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("import receipt has an invalid source identity: {error}"),
        )
        .with_retryable(false)
    })
}

fn parse_import_job_id(
    value: &str,
) -> Result<ylx_transfer_core::ingest::ImportJobId, MediaPortError> {
    ylx_transfer_core::ingest::ImportJobId::parse(value).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("import completion carries an invalid job id: {error}"),
        )
        .with_retryable(false)
    })
}

fn parse_derivation_job_id(value: &str) -> Result<DerivationJobId, MediaPortError> {
    DerivationJobId::parse(value).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("derivation completion carries an invalid job id: {error}"),
        )
        .with_retryable(false)
    })
}

fn store_error(operation: &str, error: &MediaStoreError) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::ImportCommandFailed,
        format!("{operation}: {error}"),
    )
    .with_retryable(true)
}

fn projection_store_error(
    operation: &str,
    error: &ylx_transfer_core::media_library::ProjectionStoreError,
) -> MediaPortError {
    use ylx_transfer_core::media_library::ProjectionStoreError;
    let retryable = matches!(error, ProjectionStoreError::Busy);
    MediaPortError::new(
        MediaErrorCode::ImportCommandFailed,
        format!("{operation}: {error}"),
    )
    .with_retryable(retryable)
}

fn transfer_error(operation: &str, error: &dyn std::fmt::Display) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::ImportCommandFailed,
        format!("{operation}: {error}"),
    )
    .with_retryable(true)
}

fn integrity_error(detail: impl Into<String>) -> MediaPortError {
    MediaPortError::new(MediaErrorCode::IntegrityFailed, detail).with_retryable(false)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
