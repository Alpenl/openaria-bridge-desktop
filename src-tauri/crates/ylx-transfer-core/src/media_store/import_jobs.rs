use rusqlite::OptionalExtension;

use crate::ingest::{
    ImportFileCheckpoint, ImportFileSpec, ImportJob, ImportJobId, ImportJobState,
    ImportResumePoint, ImportSnapshot, ImportSpec, MediaLocator,
};

use super::error::MediaStoreError;
use super::generations::observe_generation_tx;
use super::model::{
    AcknowledgeOutcome, CompareAndSwapOutcome, CompleteImportOutcome, CompletionEnvelope,
    CreateImportJobError, CreateJobConflict, CreateJobOutcome, ImportCommitProjection,
    ImportLocatorSnapshot, ImportLocatorUpdate, Recoverable, RecoveryBlocked,
    RecoveryBlockedReason, RevisionedCollection, StoredImportJob,
};
use super::outbox::{self, OutboxLane};
use super::projection::{bump_projection_revision, read_projection_revision, ProjectionResource};
use super::receipts::{insert_import_receipt, insert_source_receipt, local_source_receipt_rows};
use super::schema::CURRENT_IMPORT_SPEC_VERSION;
use super::store::{checked_i64, checked_u64, require_non_empty, require_sha256, MediaStore};

impl MediaStore {
    /// Atomically creates the immutable import spec, ordered file plan,
    /// initial checkpoints and acquisition locator.
    pub fn create_import_job(
        &mut self,
        spec: &ImportSpec,
        now: &str,
    ) -> Result<CreateJobOutcome<StoredImportJob>, CreateImportJobError> {
        require_non_empty(now, "now")?;
        let initial = ImportJob::new(spec.clone()).snapshot().clone();
        let natural_key = spec.natural_key().canonical_key();
        let tx = self.conn.transaction()?;

        if let Some((existing_id, existing_digest)) = find_import_identity(&tx, &natural_key)? {
            if existing_digest != spec.request_digest() {
                return Err(CreateJobConflict::RequestDigestMismatch {
                    natural_key,
                    existing_job_id: existing_id,
                    existing_digest,
                    requested_digest: spec.request_digest().to_string(),
                }
                .into());
            }
            let existing =
                read_import_job(&tx, &existing_id)?.ok_or_else(|| MediaStoreError::NotFound {
                    detail: format!("existing import job {existing_id:?} vanished"),
                })?;
            return Ok(CreateJobOutcome::Existing(existing));
        }
        if let Some(existing_natural_key) = import_natural_key_for_id(&tx, spec.job_id())? {
            return Err(CreateJobConflict::JobIdCollision {
                job_id: spec.job_id().as_str().to_string(),
                existing_natural_key,
            }
            .into());
        }

        insert_new_import_job(&tx, spec, &initial, now)?;
        bump_projection_revision(&tx, ProjectionResource::Imports)?;
        let stored = read_import_job(&tx, spec.job_id().as_str())?.ok_or_else(|| {
            MediaStoreError::NotFound {
                detail: format!(
                    "import job {:?} vanished immediately after insertion",
                    spec.job_id().as_str()
                ),
            }
        })?;
        tx.commit()?;
        Ok(CreateJobOutcome::Created(stored))
    }

    /// Reads spec, snapshot, locator, file plan and checkpoint ledger from a
    /// single SQLite read transaction.
    pub fn import_job(
        &mut self,
        job_id: &ImportJobId,
    ) -> Result<Option<StoredImportJob>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let job = read_import_job(&tx, job_id.as_str())?;
        tx.commit()?;
        Ok(job)
    }

    pub fn compare_and_swap_import_snapshot(
        &mut self,
        expected_version: u64,
        next: &ImportSnapshot,
        locator_update: Option<ImportLocatorUpdate<'_>>,
        now: &str,
    ) -> Result<CompareAndSwapOutcome<StoredImportJob>, MediaStoreError> {
        if next.is_terminal() {
            return Err(MediaStoreError::Conflict {
                detail: "terminal import snapshots must use complete_import_job".to_string(),
            });
        }
        let tx = self.conn.transaction()?;
        let current = require_import_job(&tx, next.job_id().as_str())?;
        if current.snapshot == *next {
            tx.commit()?;
            return Ok(CompareAndSwapOutcome::AlreadyApplied(current));
        }
        persist_import_snapshot(&tx, &current, expected_version, next, locator_update, now)?;
        bump_projection_revision(&tx, ProjectionResource::Imports)?;
        let stored = require_import_job(&tx, next.job_id().as_str())?;
        tx.commit()?;
        Ok(CompareAndSwapOutcome::Applied(stored))
    }

    /// Commits a terminal snapshot and its completion outbox atomically.
    /// For `LocalVerified`, the source/import receipts are included in the
    /// same transaction so neither completion nor the duplicate-import fence
    /// can exist alone.
    pub fn complete_import_job(
        &mut self,
        expected_version: u64,
        next: &ImportSnapshot,
        locator_update: Option<ImportLocatorUpdate<'_>>,
        projection: Option<ImportCommitProjection<'_>>,
        now: &str,
    ) -> Result<CompleteImportOutcome, MediaStoreError> {
        if !next.is_terminal() {
            return Err(MediaStoreError::Conflict {
                detail: "non-terminal import snapshots must use compare_and_swap_import_snapshot"
                    .to_string(),
            });
        }
        let tx = self.conn.transaction()?;
        let current = require_import_job(&tx, next.job_id().as_str())?;
        let replay = current.snapshot == *next;
        if !replay {
            persist_import_snapshot(&tx, &current, expected_version, next, locator_update, now)?;
        }

        match (next.local_receipt(), projection) {
            (Some(local), Some(projection)) => {
                let (source, import) = local_source_receipt_rows(
                    projection.receipt_id,
                    next.job_id(),
                    projection.source_identity,
                    local,
                )?;
                insert_source_receipt(&tx, &source)?;
                insert_import_receipt(&tx, &import)?;
            }
            (Some(_), None) => {
                return Err(MediaStoreError::Conflict {
                    detail: "a local-verified import requires its library projection keys"
                        .to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(MediaStoreError::Conflict {
                    detail: "library projection keys require a local source receipt".to_string(),
                });
            }
            (None, None) => {}
        }
        let completion = outbox::insert_completion(
            &tx,
            OutboxLane::Import,
            next.job_id().as_str(),
            next,
            next.version(),
            now,
        )?;
        if !replay || matches!(&completion, super::model::CompleteOutcome::Recorded(_)) {
            bump_projection_revision(&tx, ProjectionResource::Imports)?;
        }
        let job = require_import_job(&tx, next.job_id().as_str())?;
        tx.commit()?;
        Ok(CompleteImportOutcome { job, completion })
    }

    pub fn pending_import_completions(
        &self,
    ) -> Result<Vec<CompletionEnvelope<ImportSnapshot>>, MediaStoreError> {
        outbox::read_pending_completions(&self.conn, OutboxLane::Import)
    }

    pub fn acknowledge_import_completion(
        &mut self,
        job_id: &ImportJobId,
        now: &str,
    ) -> Result<AcknowledgeOutcome<CompletionEnvelope<ImportSnapshot>>, MediaStoreError> {
        require_non_empty(now, "now")?;
        let tx = self.conn.transaction()?;
        let outcome =
            outbox::acknowledge_completion(&tx, OutboxLane::Import, job_id.as_str(), now)?;
        if matches!(&outcome, AcknowledgeOutcome::Acknowledged(_)) {
            bump_projection_revision(&tx, ProjectionResource::Imports)?;
        }
        tx.commit()?;
        Ok(outcome)
    }

    pub fn import_projection(
        &mut self,
    ) -> Result<RevisionedCollection<StoredImportJob>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let revision = read_projection_revision(&tx, ProjectionResource::Imports)?;
        let mut statement =
            tx.prepare("SELECT job_id FROM media_import_jobs ORDER BY created_at, job_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let items = ids
            .into_iter()
            .map(|job_id| require_import_job(&tx, &job_id))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit()?;
        Ok(RevisionedCollection { revision, items })
    }

    /// Enumerates every non-terminal job without silently dropping a row
    /// whose durable spec or ledger is unusable.
    pub fn list_recoverable_imports(
        &mut self,
    ) -> Result<Vec<Recoverable<StoredImportJob>>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let mut statement = tx.prepare(
            "SELECT job_id FROM media_import_jobs
             WHERE is_terminal = 0 ORDER BY created_at, job_id",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let jobs = ids
            .into_iter()
            .map(|job_id| match read_import_job(&tx, &job_id) {
                Ok(Some(job)) => Ok(Recoverable::Ready(job)),
                Ok(None) => Ok(Recoverable::Blocked(RecoveryBlocked {
                    job_id,
                    reason: RecoveryBlockedReason::MissingSpec,
                    detail: "job row vanished during recovery snapshot".to_string(),
                })),
                Err(MediaStoreError::Corrupt { detail, .. }) => {
                    Ok(Recoverable::Blocked(RecoveryBlocked {
                        job_id,
                        reason: RecoveryBlockedReason::CorruptSpec,
                        detail,
                    }))
                }
                Err(MediaStoreError::NotFound { detail }) => {
                    Ok(Recoverable::Blocked(RecoveryBlocked {
                        job_id,
                        reason: RecoveryBlockedReason::MissingSpec,
                        detail,
                    }))
                }
                Err(error) => Err(error),
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit()?;
        Ok(jobs)
    }
}

/// Inserts every row owned by a new import without committing or bumping a
/// collection revision. The caller owns the surrounding transaction so this
/// can be composed atomically with a session-pipeline intent.
pub(super) fn insert_new_import_job(
    tx: &rusqlite::Transaction<'_>,
    spec: &ImportSpec,
    initial: &ImportSnapshot,
    now: &str,
) -> Result<(), MediaStoreError> {
    if let Some(generation) = spec.locator().media_generation() {
        observe_generation_tx(tx, generation, now)?;
    }
    tx.execute(
        "INSERT INTO media_import_jobs (
             job_id, natural_key, request_digest, snapshot_json, state_version,
             is_terminal, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        rusqlite::params![
            spec.job_id().as_str(),
            spec.natural_key().canonical_key(),
            spec.request_digest(),
            serde_json::to_string(initial)?,
            checked_i64(initial.version(), "state_version")?,
            i64::from(initial.is_terminal()),
            now,
        ],
    )?;
    tx.execute(
        "INSERT INTO media_import_specs (job_id, spec_version, spec_json)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![
            spec.job_id().as_str(),
            i64::from(CURRENT_IMPORT_SPEC_VERSION),
            serde_json::to_string(spec)?,
        ],
    )?;
    insert_import_files_and_checkpoints(tx, spec, initial, now)?;
    tx.execute(
        "INSERT INTO media_import_locators (
             job_id, media_generation_id, locator_version, locator_json,
             installed_at, updated_at
         ) VALUES (?1, ?2, 1, ?3, ?4, ?4)",
        rusqlite::params![
            spec.job_id().as_str(),
            spec.locator()
                .media_generation_id()
                .map(|generation| generation.as_str()),
            serde_json::to_string(spec.locator())?,
            now,
        ],
    )?;
    Ok(())
}

fn persist_import_snapshot(
    tx: &rusqlite::Transaction<'_>,
    current: &StoredImportJob,
    expected_version: u64,
    next: &ImportSnapshot,
    locator_update: Option<ImportLocatorUpdate<'_>>,
    now: &str,
) -> Result<(), MediaStoreError> {
    require_non_empty(now, "now")?;
    if current.snapshot.version() != expected_version {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "import job {:?} expected version {expected_version}, current version is {}",
                next.job_id().as_str(),
                current.snapshot.version()
            ),
        });
    }
    let expected_next =
        expected_version
            .checked_add(1)
            .ok_or_else(|| MediaStoreError::Conflict {
                detail: format!(
                    "import job {:?} exhausted the u64 version range",
                    next.job_id().as_str()
                ),
            })?;
    if next.version() != expected_next {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "import snapshot version {} is not expected next version {expected_next}",
                next.version()
            ),
        });
    }
    ImportJob::from_snapshot(current.spec.clone(), next.clone()).map_err(|error| {
        MediaStoreError::Conflict {
            detail: format!("import snapshot does not match its immutable spec: {error}"),
        }
    })?;
    validate_checkpoint_monotonicity(&current.snapshot, next)?;

    let changed = tx.execute(
        "UPDATE media_import_jobs
         SET snapshot_json = ?2, state_version = ?3, is_terminal = ?4, updated_at = ?5
         WHERE job_id = ?1 AND state_version = ?6",
        rusqlite::params![
            next.job_id().as_str(),
            serde_json::to_string(next)?,
            checked_i64(next.version(), "state_version")?,
            i64::from(next.is_terminal()),
            now,
            checked_i64(expected_version, "expected_version")?,
        ],
    )?;
    if changed != 1 {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "import job {:?} lost expected-version CAS {expected_version}",
                next.job_id().as_str()
            ),
        });
    }
    for checkpoint in next.checkpoints() {
        write_import_checkpoint(tx, next.job_id(), checkpoint, now)?;
    }
    if let Some(update) = locator_update {
        update_import_locator(tx, next, current, update, now)?;
    } else if next.active_locator().is_some()
        && next.active_locator() != Some(&current.locator.locator)
    {
        return Err(MediaStoreError::Conflict {
            detail: "snapshot activates a new source locator without a locator CAS".to_string(),
        });
    }
    Ok(())
}

fn update_import_locator(
    tx: &rusqlite::Transaction<'_>,
    next: &ImportSnapshot,
    current: &StoredImportJob,
    update: ImportLocatorUpdate<'_>,
    now: &str,
) -> Result<(), MediaStoreError> {
    if current.locator.version != update.expected_version {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "import locator expected version {}, current version is {}",
                update.expected_version, current.locator.version
            ),
        });
    }
    if next.active_locator() != Some(update.locator) {
        return Err(MediaStoreError::Conflict {
            detail: "active source locator does not match the installed locator".to_string(),
        });
    }
    if current.locator.locator == *update.locator {
        return Ok(());
    }
    if let Some(generation) = update.locator.media_generation() {
        observe_generation_tx(tx, generation, now)?;
    }
    let next_locator_version =
        update
            .expected_version
            .checked_add(1)
            .ok_or_else(|| MediaStoreError::Conflict {
                detail: "import locator version exhausted u64 range".to_string(),
            })?;
    let changed = tx.execute(
        "UPDATE media_import_locators
         SET media_generation_id = ?2, locator_version = ?3,
             locator_json = ?4, updated_at = ?5
         WHERE job_id = ?1 AND locator_version = ?6",
        rusqlite::params![
            next.job_id().as_str(),
            update
                .locator
                .media_generation_id()
                .map(|generation| generation.as_str()),
            checked_i64(next_locator_version, "locator_version")?,
            serde_json::to_string(update.locator)?,
            now,
            checked_i64(update.expected_version, "expected_locator_version")?,
        ],
    )?;
    if changed != 1 {
        return Err(MediaStoreError::Conflict {
            detail: "import locator lost its expected-version CAS".to_string(),
        });
    }
    Ok(())
}

fn insert_import_files_and_checkpoints(
    tx: &rusqlite::Transaction<'_>,
    spec: &ImportSpec,
    snapshot: &ImportSnapshot,
    now: &str,
) -> Result<(), MediaStoreError> {
    if spec.files().len() != snapshot.checkpoints().len() {
        return Err(MediaStoreError::Conflict {
            detail: "initial import checkpoint count differs from file plan".to_string(),
        });
    }
    for (ordinal, (file, checkpoint)) in spec.files().iter().zip(snapshot.checkpoints()).enumerate()
    {
        if file.file_id() != checkpoint.file_id()
            || file.expected_size() != checkpoint.expected_size()
        {
            return Err(MediaStoreError::Conflict {
                detail: "initial import checkpoint differs from file plan".to_string(),
            });
        }
        tx.execute(
            "INSERT INTO media_import_files (
                 job_id, ordinal, file_id, expected_size, expected_sha256, file_spec_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                spec.job_id().as_str(),
                checked_i64(
                    u64::try_from(ordinal).map_err(|_| MediaStoreError::Conflict {
                        detail: "import file count exceeds u64".to_string(),
                    })?,
                    "file ordinal",
                )?,
                file.file_id().as_str(),
                checked_i64(file.expected_size(), "expected_size")?,
                file.expected_source_sha256(),
                serde_json::to_string(file)?,
            ],
        )?;
        insert_import_checkpoint(tx, spec.job_id(), checkpoint, now)?;
    }
    Ok(())
}

fn insert_import_checkpoint(
    tx: &rusqlite::Transaction<'_>,
    job_id: &ImportJobId,
    checkpoint: &ImportFileCheckpoint,
    now: &str,
) -> Result<(), MediaStoreError> {
    validate_checkpoint(checkpoint)?;
    tx.execute(
        "INSERT INTO media_import_checkpoints (
             job_id, file_id, durable_offset, expected_size, source_sha256,
             target_sha256, verified, checkpoint_json, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            job_id.as_str(),
            checkpoint.file_id().as_str(),
            checked_i64(checkpoint.durable_offset(), "durable_offset")?,
            checked_i64(checkpoint.expected_size(), "expected_size")?,
            checkpoint.source_sha256(),
            checkpoint.target_sha256(),
            i64::from(checkpoint.verified()),
            serde_json::to_string(checkpoint)?,
            now,
        ],
    )?;
    Ok(())
}

fn write_import_checkpoint(
    tx: &rusqlite::Transaction<'_>,
    job_id: &ImportJobId,
    checkpoint: &ImportFileCheckpoint,
    now: &str,
) -> Result<(), MediaStoreError> {
    validate_checkpoint(checkpoint)?;
    let changed = tx.execute(
        "UPDATE media_import_checkpoints
         SET durable_offset = ?3, source_sha256 = ?4, target_sha256 = ?5,
             verified = ?6, checkpoint_json = ?7, updated_at = ?8
         WHERE job_id = ?1 AND file_id = ?2 AND expected_size = ?9",
        rusqlite::params![
            job_id.as_str(),
            checkpoint.file_id().as_str(),
            checked_i64(checkpoint.durable_offset(), "durable_offset")?,
            checkpoint.source_sha256(),
            checkpoint.target_sha256(),
            i64::from(checkpoint.verified()),
            serde_json::to_string(checkpoint)?,
            now,
            checked_i64(checkpoint.expected_size(), "expected_size")?,
        ],
    )?;
    if changed != 1 {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "checkpoint file {:?} is absent or has a different expected size",
                checkpoint.file_id().as_str()
            ),
        });
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &ImportFileCheckpoint) -> Result<(), MediaStoreError> {
    if checkpoint.durable_offset() > checkpoint.expected_size() {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "checkpoint for {:?} exceeds its expected size",
                checkpoint.file_id().as_str()
            ),
        });
    }
    for (field, digest) in [
        ("source_sha256", checkpoint.source_sha256()),
        ("target_sha256", checkpoint.target_sha256()),
    ] {
        if let Some(digest) = digest {
            require_sha256(digest, field)?;
        }
    }
    if checkpoint.verified()
        && (checkpoint.durable_offset() != checkpoint.expected_size()
            || checkpoint.source_sha256().is_none()
            || checkpoint.target_sha256().is_none())
    {
        return Err(MediaStoreError::Conflict {
            detail: "a verified checkpoint requires full length and both digests".to_string(),
        });
    }
    Ok(())
}

fn validate_checkpoint_monotonicity(
    current: &ImportSnapshot,
    next: &ImportSnapshot,
) -> Result<(), MediaStoreError> {
    if current.checkpoints().len() != next.checkpoints().len() {
        return Err(MediaStoreError::Conflict {
            detail: "import checkpoint count cannot change".to_string(),
        });
    }
    if is_legal_source_progress_reset(current, next) {
        return Ok(());
    }
    for (old, new) in current.checkpoints().iter().zip(next.checkpoints()) {
        if old.file_id() != new.file_id()
            || old.expected_size() != new.expected_size()
            || new.durable_offset() < old.durable_offset()
            || (old.verified() && old != new)
        {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "checkpoint evidence for {:?} regressed or changed identity",
                    old.file_id().as_str()
                ),
            });
        }
    }
    Ok(())
}

/// The only legal checkpoint regression is the aggregate's explicit weak-
/// identity source reset. It is a single CAS from waiting-for-media back to a
/// preflight resume point and clears every byte/hash/verification claim
/// atomically; all other snapshot fields remain unchanged except failure,
/// which the reducer deliberately clears for the fresh acquisition.
fn is_legal_source_progress_reset(current: &ImportSnapshot, next: &ImportSnapshot) -> bool {
    matches!(current.state(), ImportJobState::WaitingForMedia { .. })
        && matches!(
            next.state(),
            ImportJobState::WaitingForMedia {
                resume_from: ImportResumePoint::Preflight
            }
        )
        && current.desired_state() == next.desired_state()
        && current.attempt() == next.attempt()
        && current.active_locator().is_none()
        && next.active_locator().is_none()
        && current.verified_source().is_none()
        && next.verified_source().is_none()
        && current.local_receipt().is_none()
        && next.local_receipt().is_none()
        && next.failure().is_none()
        && current
            .checkpoints()
            .iter()
            .zip(next.checkpoints())
            .all(|(old, reset)| {
                old.file_id() == reset.file_id()
                    && old.expected_size() == reset.expected_size()
                    && reset.durable_offset() == 0
                    && reset.source_sha256().is_none()
                    && reset.target_sha256().is_none()
                    && !reset.verified()
            })
}

pub(super) fn find_import_identity(
    conn: &rusqlite::Connection,
    natural_key: &str,
) -> Result<Option<(String, String)>, MediaStoreError> {
    conn.query_row(
        "SELECT job_id, request_digest FROM media_import_jobs WHERE natural_key = ?1",
        [natural_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(Into::into)
}

pub(super) fn import_natural_key_for_id(
    conn: &rusqlite::Connection,
    job_id: &ImportJobId,
) -> Result<Option<String>, MediaStoreError> {
    conn.query_row(
        "SELECT natural_key FROM media_import_jobs WHERE job_id = ?1",
        [job_id.as_str()],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn require_import_job(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<StoredImportJob, MediaStoreError> {
    read_import_job(conn, job_id)?.ok_or_else(|| MediaStoreError::NotFound {
        detail: format!("import job {job_id:?}"),
    })
}

pub(super) fn read_import_job(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<Option<StoredImportJob>, MediaStoreError> {
    let header: Option<(String, String, String, i64, i64, String, String)> = conn
        .query_row(
            "SELECT natural_key, request_digest, snapshot_json, state_version,
                    is_terminal, created_at, updated_at
             FROM media_import_jobs WHERE job_id = ?1",
            [job_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some(header) = header else {
        return Ok(None);
    };
    let spec_row: Option<(i64, String)> = conn
        .query_row(
            "SELECT spec_version, spec_json FROM media_import_specs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((spec_version, spec_json)) = spec_row else {
        return Err(MediaStoreError::NotFound {
            detail: format!("import job {job_id:?} has no spec row"),
        });
    };
    let spec_version = checked_u64(spec_version, "media_import_specs", "spec_version")?;
    if spec_version != u64::from(CURRENT_IMPORT_SPEC_VERSION) {
        return Err(MediaStoreError::corrupt(
            "media_import_specs",
            format!("job {job_id:?} has unsupported spec version {spec_version}"),
        ));
    }
    let spec: ImportSpec = serde_json::from_str(&spec_json)
        .map_err(|error| MediaStoreError::corrupt("media_import_specs", error.to_string()))?;
    let snapshot: ImportSnapshot = serde_json::from_str(&header.2)
        .map_err(|error| MediaStoreError::corrupt("media_import_jobs", error.to_string()))?;
    let indexed_version = checked_u64(header.3, "media_import_jobs", "state_version")?;
    let indexed_terminal = parse_bool(header.4, "media_import_jobs", "is_terminal")?;
    if spec.job_id().as_str() != job_id
        || spec.natural_key().canonical_key() != header.0
        || spec.request_digest() != header.1
        || snapshot.job_id().as_str() != job_id
        || snapshot.natural_key() != spec.natural_key()
        || snapshot.request_digest() != spec.request_digest()
        || snapshot.version() != indexed_version
        || snapshot.is_terminal() != indexed_terminal
    {
        return Err(MediaStoreError::corrupt(
            "media_import_jobs",
            format!("job {job_id:?} indexed identity disagrees with its typed payload"),
        ));
    }
    ImportJob::from_snapshot(spec.clone(), snapshot.clone()).map_err(|error| {
        MediaStoreError::corrupt(
            "media_import_jobs",
            format!("job {job_id:?} cannot be rehydrated: {error}"),
        )
    })?;
    validate_stored_files(conn, job_id, &spec)?;
    validate_stored_checkpoints(conn, job_id, &snapshot)?;
    let locator = read_import_locator(conn, job_id)?.ok_or_else(|| MediaStoreError::NotFound {
        detail: format!("import job {job_id:?} has no locator row"),
    })?;
    Ok(Some(StoredImportJob {
        spec,
        snapshot,
        locator,
        created_at: header.5,
        updated_at: header.6,
    }))
}

fn validate_stored_files(
    conn: &rusqlite::Connection,
    job_id: &str,
    spec: &ImportSpec,
) -> Result<(), MediaStoreError> {
    let mut statement = conn.prepare(
        "SELECT file_spec_json, file_id, expected_size, expected_sha256
         FROM media_import_files WHERE job_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([job_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != spec.files().len() {
        return Err(MediaStoreError::corrupt(
            "media_import_files",
            format!("job {job_id:?} file count differs from its spec"),
        ));
    }
    for (raw, expected) in rows.into_iter().zip(spec.files()) {
        let file: ImportFileSpec = serde_json::from_str(&raw.0)
            .map_err(|error| MediaStoreError::corrupt("media_import_files", error.to_string()))?;
        let size = checked_u64(raw.2, "media_import_files", "expected_size")?;
        if file != *expected
            || file.file_id().as_str() != raw.1
            || file.expected_size() != size
            || file.expected_source_sha256() != raw.3.as_deref()
        {
            return Err(MediaStoreError::corrupt(
                "media_import_files",
                format!("job {job_id:?} normalized file row disagrees with its spec"),
            ));
        }
    }
    Ok(())
}

fn validate_stored_checkpoints(
    conn: &rusqlite::Connection,
    job_id: &str,
    snapshot: &ImportSnapshot,
) -> Result<(), MediaStoreError> {
    let mut statement = conn.prepare(
        "SELECT c.checkpoint_json, c.file_id, c.durable_offset, c.expected_size,
                c.source_sha256, c.target_sha256, c.verified
         FROM media_import_checkpoints c
         JOIN media_import_files f ON f.job_id = c.job_id AND f.file_id = c.file_id
         WHERE c.job_id = ?1 ORDER BY f.ordinal",
    )?;
    let rows = statement
        .query_map([job_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != snapshot.checkpoints().len() {
        return Err(MediaStoreError::corrupt(
            "media_import_checkpoints",
            format!("job {job_id:?} checkpoint count differs from its snapshot"),
        ));
    }
    for (raw, expected) in rows.into_iter().zip(snapshot.checkpoints()) {
        let checkpoint: ImportFileCheckpoint = serde_json::from_str(&raw.0).map_err(|error| {
            MediaStoreError::corrupt("media_import_checkpoints", error.to_string())
        })?;
        if checkpoint != *expected
            || checkpoint.file_id().as_str() != raw.1
            || checkpoint.durable_offset()
                != checked_u64(raw.2, "media_import_checkpoints", "durable_offset")?
            || checkpoint.expected_size()
                != checked_u64(raw.3, "media_import_checkpoints", "expected_size")?
            || checkpoint.source_sha256() != raw.4.as_deref()
            || checkpoint.target_sha256() != raw.5.as_deref()
            || checkpoint.verified() != parse_bool(raw.6, "media_import_checkpoints", "verified")?
        {
            return Err(MediaStoreError::corrupt(
                "media_import_checkpoints",
                format!("job {job_id:?} normalized checkpoint disagrees with snapshot"),
            ));
        }
    }
    Ok(())
}

fn read_import_locator(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<Option<ImportLocatorSnapshot>, MediaStoreError> {
    let row: Option<(Option<String>, i64, String, String, String)> = conn
        .query_row(
            "SELECT media_generation_id, locator_version, locator_json,
                    installed_at, updated_at
             FROM media_import_locators WHERE job_id = ?1",
            [job_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let locator: MediaLocator = serde_json::from_str(&row.2).map_err(|error| {
            MediaStoreError::corrupt("media_import_locators", error.to_string())
        })?;
        if locator.media_generation_id().map(|id| id.as_str()) != row.0.as_deref() {
            return Err(MediaStoreError::corrupt(
                "media_import_locators",
                format!("job {job_id:?} locator generation index disagrees with JSON"),
            ));
        }
        Ok(ImportLocatorSnapshot {
            locator,
            version: checked_u64(row.1, "media_import_locators", "locator_version")?,
            installed_at: row.3,
            updated_at: row.4,
        })
    })
    .transpose()
}

fn parse_bool(value: i64, table: &str, field: &str) -> Result<bool, MediaStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MediaStoreError::corrupt(
            table,
            format!("{field} has invalid boolean value {value}"),
        )),
    }
}
