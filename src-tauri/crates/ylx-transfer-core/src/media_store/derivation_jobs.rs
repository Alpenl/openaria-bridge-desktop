use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

use crate::media_pipeline::LocalDerivedReceipt;
use crate::normalization::{
    DerivationJob, DerivationJobId, DerivationJobState, DerivationSnapshot, DerivationSpec,
    DerivedCompletion, DerivedManifest, DerivedOutputRole, SegmentPairCheckpoint,
};

use super::error::MediaStoreError;
use super::model::{
    AcknowledgeOutcome, CompareAndSwapOutcome, CompleteDerivationOutcome, CompletionEnvelope,
    CreateDerivationJobError, CreateJobConflict, CreateJobOutcome, Recoverable, RecoveryBlocked,
    RecoveryBlockedReason, RevisionedCollection, StoredDerivationJob,
};
use super::outbox::{self, OutboxLane};
use super::projection::{bump_projection_revision, read_projection_revision, ProjectionResource};
use super::receipts::{insert_derived_receipt, local_derived_receipt_row, read_derived_receipt};
use super::schema::CURRENT_DERIVATION_SPEC_VERSION;
use super::store::{checked_i64, checked_u64, require_non_empty, MediaStore};

impl MediaStore {
    /// Atomically creates the immutable derivation request and its initial,
    /// empty segment-pair ledger.
    pub fn create_derivation_job(
        &mut self,
        spec: &DerivationSpec,
        now: &str,
    ) -> Result<CreateJobOutcome<StoredDerivationJob>, CreateDerivationJobError> {
        require_non_empty(now, "now")?;
        let initial = DerivationJob::new(spec.clone())
            .map_err(|error| MediaStoreError::Conflict {
                detail: format!("invalid derivation spec: {error}"),
            })?
            .snapshot();
        let natural_key = derivation_natural_key(spec);
        let request_digest = derivation_request_digest(spec)?;
        let tx = self.conn.transaction()?;

        if let Some((existing_id, existing_digest)) = find_derivation_identity(&tx, &natural_key)? {
            if existing_digest != request_digest {
                return Err(CreateJobConflict::RequestDigestMismatch {
                    natural_key,
                    existing_job_id: existing_id,
                    existing_digest,
                    requested_digest: request_digest,
                }
                .into());
            }
            let existing = read_derivation_job(&tx, &existing_id)?.ok_or_else(|| {
                MediaStoreError::NotFound {
                    detail: format!("existing derivation job {existing_id:?} vanished"),
                }
            })?;
            return Ok(CreateJobOutcome::Existing(existing));
        }
        if let Some(existing_natural_key) = derivation_natural_key_for_id(&tx, spec.job_id())? {
            return Err(CreateJobConflict::JobIdCollision {
                job_id: spec.job_id().as_str().to_string(),
                existing_natural_key,
            }
            .into());
        }

        tx.execute(
            "INSERT INTO media_derivation_jobs (
                 job_id, natural_key, request_digest, snapshot_json, state_version,
                 is_terminal, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            rusqlite::params![
                spec.job_id().as_str(),
                natural_key,
                request_digest,
                serde_json::to_string(&initial)?,
                checked_i64(initial.version(), "state_version")?,
                i64::from(initial.state().is_terminal()),
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO media_derivation_specs (
                 job_id, source_revision, profile_revision, spec_version, spec_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                spec.job_id().as_str(),
                spec.source_revision().as_str(),
                spec.profile_revision().as_str(),
                i64::from(CURRENT_DERIVATION_SPEC_VERSION),
                serde_json::to_string(spec)?,
            ],
        )?;
        bump_projection_revision(&tx, ProjectionResource::Derivations)?;
        let stored = require_derivation_job(&tx, spec.job_id().as_str())?;
        tx.commit()?;
        Ok(CreateJobOutcome::Created(stored))
    }

    /// Reads the immutable spec, authoritative snapshot and normalized pair
    /// ledger from one SQLite transaction.
    pub fn derivation_job(
        &mut self,
        job_id: &DerivationJobId,
    ) -> Result<Option<StoredDerivationJob>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let job = read_derivation_job(&tx, job_id.as_str())?;
        tx.commit()?;
        Ok(job)
    }

    pub fn compare_and_swap_derivation_snapshot(
        &mut self,
        expected_version: u64,
        next: &DerivationSnapshot,
        now: &str,
    ) -> Result<CompareAndSwapOutcome<StoredDerivationJob>, MediaStoreError> {
        if next.state().is_terminal() {
            return Err(MediaStoreError::Conflict {
                detail: "terminal derivation snapshots must use complete_derivation_job"
                    .to_string(),
            });
        }
        let tx = self.conn.transaction()?;
        let current = require_derivation_job(&tx, next.spec().job_id().as_str())?;
        if current.snapshot == *next {
            tx.commit()?;
            return Ok(CompareAndSwapOutcome::AlreadyApplied(current));
        }
        persist_derivation_snapshot(&tx, &current, expected_version, next, now)?;
        bump_projection_revision(&tx, ProjectionResource::Derivations)?;
        let stored = require_derivation_job(&tx, next.spec().job_id().as_str())?;
        tx.commit()?;
        Ok(CompareAndSwapOutcome::Applied(stored))
    }

    /// Commits a terminal snapshot and its completion outbox atomically.
    /// A `DerivedVerified` commit also inserts the typed, immutable local
    /// derivative receipt in the same transaction.
    pub fn complete_derivation_job(
        &mut self,
        expected_version: u64,
        next: &DerivationSnapshot,
        now: &str,
    ) -> Result<CompleteDerivationOutcome, MediaStoreError> {
        if !next.state().is_terminal() {
            return Err(MediaStoreError::Conflict {
                detail: "non-terminal derivation snapshots must use compare_and_swap_derivation_snapshot"
                    .to_string(),
            });
        }
        require_non_empty(now, "now")?;
        let tx = self.conn.transaction()?;
        let current = require_derivation_job(&tx, next.spec().job_id().as_str())?;
        let replay = current.snapshot == *next;
        if !replay {
            persist_derivation_snapshot(&tx, &current, expected_version, next, now)?;
        }

        let receipt_recorded = if next.state() == &DerivationJobState::DerivedVerified {
            let completion = next.completion().ok_or_else(|| MediaStoreError::Conflict {
                detail: "derived_verified snapshot has no completion evidence".to_string(),
            })?;
            let typed = local_derived_receipt_from_completion(next.spec().job_id(), completion)
                .map_err(|detail| MediaStoreError::Conflict { detail })?;
            insert_derived_receipt(&tx, &local_derived_receipt_row(&typed)?)?.was_recorded()
        } else {
            if next.completion().is_some() {
                return Err(MediaStoreError::Conflict {
                    detail: "non-success terminal derivation carries completion evidence"
                        .to_string(),
                });
            }
            false
        };
        let completion = outbox::insert_completion(
            &tx,
            OutboxLane::Derivation,
            next.spec().job_id().as_str(),
            next,
            next.version(),
            now,
        )?;
        if !replay
            || receipt_recorded
            || matches!(&completion, super::model::CompleteOutcome::Recorded(_))
        {
            bump_projection_revision(&tx, ProjectionResource::Derivations)?;
        }
        let job = require_derivation_job(&tx, next.spec().job_id().as_str())?;
        tx.commit()?;
        Ok(CompleteDerivationOutcome { job, completion })
    }

    pub fn pending_derivation_completions(
        &self,
    ) -> Result<Vec<CompletionEnvelope<DerivationSnapshot>>, MediaStoreError> {
        outbox::read_pending_completions(&self.conn, OutboxLane::Derivation)
    }

    pub fn acknowledge_derivation_completion(
        &mut self,
        job_id: &DerivationJobId,
        now: &str,
    ) -> Result<AcknowledgeOutcome<CompletionEnvelope<DerivationSnapshot>>, MediaStoreError> {
        require_non_empty(now, "now")?;
        let tx = self.conn.transaction()?;
        let outcome =
            outbox::acknowledge_completion(&tx, OutboxLane::Derivation, job_id.as_str(), now)?;
        if matches!(&outcome, AcknowledgeOutcome::Acknowledged(_)) {
            bump_projection_revision(&tx, ProjectionResource::Derivations)?;
        }
        tx.commit()?;
        Ok(outcome)
    }

    pub fn derivation_projection(
        &mut self,
    ) -> Result<RevisionedCollection<StoredDerivationJob>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let revision = read_projection_revision(&tx, ProjectionResource::Derivations)?;
        let mut statement =
            tx.prepare("SELECT job_id FROM media_derivation_jobs ORDER BY created_at, job_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let items = ids
            .into_iter()
            .map(|job_id| require_derivation_job(&tx, &job_id))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit()?;
        Ok(RevisionedCollection { revision, items })
    }

    /// Enumerates every non-terminal row without interpreting corrupt or
    /// incomplete durable evidence as an empty recovery set.
    pub fn list_recoverable_derivations(
        &mut self,
    ) -> Result<Vec<Recoverable<StoredDerivationJob>>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let mut statement = tx.prepare(
            "SELECT job_id FROM media_derivation_jobs
             WHERE is_terminal = 0 ORDER BY created_at, job_id",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let jobs = ids
            .into_iter()
            .map(|job_id| match read_derivation_job(&tx, &job_id) {
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

fn persist_derivation_snapshot(
    tx: &rusqlite::Transaction<'_>,
    current: &StoredDerivationJob,
    expected_version: u64,
    next: &DerivationSnapshot,
    now: &str,
) -> Result<(), MediaStoreError> {
    require_non_empty(now, "now")?;
    if current.snapshot.state().is_terminal() {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "terminal derivation job {:?} cannot be changed",
                next.spec().job_id().as_str()
            ),
        });
    }
    if current.snapshot.version() != expected_version {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "derivation job {:?} expected version {expected_version}, current version is {}",
                next.spec().job_id().as_str(),
                current.snapshot.version()
            ),
        });
    }
    let expected_next =
        expected_version
            .checked_add(1)
            .ok_or_else(|| MediaStoreError::Conflict {
                detail: format!(
                    "derivation job {:?} exhausted the u64 version range",
                    next.spec().job_id().as_str()
                ),
            })?;
    if next.version() != expected_next {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "derivation snapshot version {} is not expected next version {expected_next}",
                next.version()
            ),
        });
    }
    if next.spec() != &current.spec {
        return Err(MediaStoreError::Conflict {
            detail: "derivation snapshot changed its immutable spec".to_string(),
        });
    }
    rehydrate_derivation(&current.spec, next).map_err(|detail| MediaStoreError::Conflict {
        detail: format!("derivation snapshot is invalid: {detail}"),
    })?;
    validate_pair_monotonicity(&current.snapshot, next)?;

    let changed = tx.execute(
        "UPDATE media_derivation_jobs
         SET snapshot_json = ?2, state_version = ?3, is_terminal = ?4, updated_at = ?5
         WHERE job_id = ?1 AND state_version = ?6",
        rusqlite::params![
            next.spec().job_id().as_str(),
            serde_json::to_string(next)?,
            checked_i64(next.version(), "state_version")?,
            i64::from(next.state().is_terminal()),
            now,
            checked_i64(expected_version, "expected_version")?,
        ],
    )?;
    if changed != 1 {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "derivation job {:?} lost expected-version CAS {expected_version}",
                next.spec().job_id().as_str()
            ),
        });
    }
    for checkpoint in next
        .checkpoints()
        .iter()
        .skip(current.snapshot.checkpoints().len())
    {
        insert_segment_pair(tx, next.spec().job_id(), checkpoint, next.version(), now)?;
    }
    Ok(())
}

fn insert_segment_pair(
    tx: &rusqlite::Transaction<'_>,
    job_id: &DerivationJobId,
    checkpoint: &SegmentPairCheckpoint,
    state_version: u64,
    now: &str,
) -> Result<(), MediaStoreError> {
    tx.execute(
        "INSERT INTO media_derivation_segment_pairs (
             job_id, segment_index, pair_state, pair_version, segment_json,
             left_sha256, right_sha256, verified, updated_at
         ) VALUES (?1, ?2, 'verified', ?3, ?4, ?5, ?6, 1, ?7)",
        rusqlite::params![
            job_id.as_str(),
            i64::from(checkpoint.segment_index()),
            checked_i64(state_version, "pair_version")?,
            serde_json::to_string(checkpoint)?,
            checkpoint.left().sha256().as_str(),
            checkpoint.right().sha256().as_str(),
            now,
        ],
    )?;
    Ok(())
}

fn validate_pair_monotonicity(
    current: &DerivationSnapshot,
    next: &DerivationSnapshot,
) -> Result<(), MediaStoreError> {
    if next.checkpoints().len() < current.checkpoints().len() {
        return Err(MediaStoreError::Conflict {
            detail: "derivation segment-pair checkpoints cannot be removed".to_string(),
        });
    }
    if current
        .checkpoints()
        .iter()
        .zip(next.checkpoints())
        .any(|(old, new)| old != new)
    {
        return Err(MediaStoreError::Conflict {
            detail: "committed derivation segment-pair evidence is immutable".to_string(),
        });
    }
    for (ordinal, checkpoint) in next.checkpoints().iter().enumerate() {
        validate_segment_pair_checkpoint(checkpoint)
            .map_err(|detail| MediaStoreError::Conflict { detail })?;
        let expected = u32::try_from(ordinal).map_err(|_| MediaStoreError::Conflict {
            detail: "derivation segment-pair count exceeds u32".to_string(),
        })?;
        if checkpoint.segment_index() != expected {
            return Err(MediaStoreError::Conflict {
                detail: "derivation segment-pair checkpoints must be contiguous from zero"
                    .to_string(),
            });
        }
    }
    Ok(())
}

fn find_derivation_identity(
    conn: &rusqlite::Connection,
    natural_key: &str,
) -> Result<Option<(String, String)>, MediaStoreError> {
    conn.query_row(
        "SELECT job_id, request_digest FROM media_derivation_jobs WHERE natural_key = ?1",
        [natural_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(Into::into)
}

fn derivation_natural_key_for_id(
    conn: &rusqlite::Connection,
    job_id: &DerivationJobId,
) -> Result<Option<String>, MediaStoreError> {
    conn.query_row(
        "SELECT natural_key FROM media_derivation_jobs WHERE job_id = ?1",
        [job_id.as_str()],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn require_derivation_job(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<StoredDerivationJob, MediaStoreError> {
    read_derivation_job(conn, job_id)?.ok_or_else(|| MediaStoreError::NotFound {
        detail: format!("derivation job {job_id:?}"),
    })
}

fn read_derivation_job(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<Option<StoredDerivationJob>, MediaStoreError> {
    let header: Option<(String, String, String, i64, i64, String, String)> = conn
        .query_row(
            "SELECT natural_key, request_digest, snapshot_json, state_version,
                    is_terminal, created_at, updated_at
             FROM media_derivation_jobs WHERE job_id = ?1",
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
    let spec_row: Option<(String, String, i64, String)> = conn
        .query_row(
            "SELECT source_revision, profile_revision, spec_version, spec_json
             FROM media_derivation_specs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((source_revision, profile_revision, spec_version, spec_json)) = spec_row else {
        return Err(MediaStoreError::NotFound {
            detail: format!("derivation job {job_id:?} has no spec row"),
        });
    };
    let spec_version = checked_u64(spec_version, "media_derivation_specs", "spec_version")?;
    if spec_version != u64::from(CURRENT_DERIVATION_SPEC_VERSION) {
        return Err(MediaStoreError::corrupt(
            "media_derivation_specs",
            format!("job {job_id:?} has unsupported spec version {spec_version}"),
        ));
    }
    let spec: DerivationSpec = serde_json::from_str(&spec_json)
        .map_err(|error| MediaStoreError::corrupt("media_derivation_specs", error.to_string()))?;
    let snapshot: DerivationSnapshot = serde_json::from_str(&header.2)
        .map_err(|error| MediaStoreError::corrupt("media_derivation_jobs", error.to_string()))?;
    let indexed_version = checked_u64(header.3, "media_derivation_jobs", "state_version")?;
    let indexed_terminal = parse_bool(header.4, "media_derivation_jobs", "is_terminal")?;
    let computed_natural_key = derivation_natural_key(&spec);
    let computed_request_digest = derivation_request_digest(&spec)
        .map_err(|error| MediaStoreError::corrupt("media_derivation_specs", error.to_string()))?;
    if spec.job_id().as_str() != job_id
        || spec.source_revision().as_str() != source_revision
        || spec.profile_revision().as_str() != profile_revision
        || computed_natural_key != header.0
        || computed_request_digest != header.1
        || snapshot.spec() != &spec
        || snapshot.version() != indexed_version
        || snapshot.state().is_terminal() != indexed_terminal
    {
        return Err(MediaStoreError::corrupt(
            "media_derivation_jobs",
            format!("job {job_id:?} indexed identity disagrees with its typed payload"),
        ));
    }
    rehydrate_derivation(&spec, &snapshot).map_err(|detail| {
        MediaStoreError::corrupt(
            "media_derivation_jobs",
            format!("job {job_id:?} cannot be rehydrated: {detail}"),
        )
    })?;
    validate_stored_segment_pairs(conn, job_id, &snapshot)?;
    validate_derived_receipt_for_snapshot(conn, job_id, &snapshot)?;
    Ok(Some(StoredDerivationJob {
        spec,
        snapshot,
        natural_key: header.0,
        request_digest: header.1,
        created_at: header.5,
        updated_at: header.6,
    }))
}

fn validate_stored_segment_pairs(
    conn: &rusqlite::Connection,
    job_id: &str,
    snapshot: &DerivationSnapshot,
) -> Result<(), MediaStoreError> {
    let mut statement = conn.prepare(
        "SELECT segment_json, segment_index, pair_state, pair_version,
                left_sha256, right_sha256, verified
         FROM media_derivation_segment_pairs
         WHERE job_id = ?1 ORDER BY segment_index",
    )?;
    let rows = statement
        .query_map([job_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != snapshot.checkpoints().len() {
        return Err(MediaStoreError::corrupt(
            "media_derivation_segment_pairs",
            format!("job {job_id:?} pair count differs from its snapshot"),
        ));
    }
    for (raw, expected) in rows.into_iter().zip(snapshot.checkpoints()) {
        validate_segment_pair_checkpoint(expected).map_err(|detail| {
            MediaStoreError::corrupt(
                "media_derivation_segment_pairs",
                format!("job {job_id:?} has invalid segment-pair evidence: {detail}"),
            )
        })?;
        let checkpoint: SegmentPairCheckpoint = serde_json::from_str(&raw.0).map_err(|error| {
            MediaStoreError::corrupt("media_derivation_segment_pairs", error.to_string())
        })?;
        let segment_index = checked_u64(raw.1, "media_derivation_segment_pairs", "segment_index")?;
        let segment_index = u32::try_from(segment_index).map_err(|_| {
            MediaStoreError::corrupt(
                "media_derivation_segment_pairs",
                "segment_index exceeds u32",
            )
        })?;
        let pair_version = checked_u64(raw.3, "media_derivation_segment_pairs", "pair_version")?;
        if checkpoint != *expected
            || checkpoint.segment_index() != segment_index
            || raw.2 != "verified"
            || pair_version == 0
            || pair_version > snapshot.version()
            || raw.4.as_deref() != Some(checkpoint.left().sha256().as_str())
            || raw.5.as_deref() != Some(checkpoint.right().sha256().as_str())
            || !parse_bool(raw.6, "media_derivation_segment_pairs", "verified")?
        {
            return Err(MediaStoreError::corrupt(
                "media_derivation_segment_pairs",
                format!("job {job_id:?} normalized pair row disagrees with snapshot"),
            ));
        }
    }
    Ok(())
}

fn validate_derived_receipt_for_snapshot(
    conn: &rusqlite::Connection,
    job_id: &str,
    snapshot: &DerivationSnapshot,
) -> Result<(), MediaStoreError> {
    if snapshot.state() != &DerivationJobState::DerivedVerified {
        return Ok(());
    }
    let completion = snapshot.completion().ok_or_else(|| {
        MediaStoreError::corrupt(
            "media_derivation_jobs",
            format!("job {job_id:?} is derived_verified without completion evidence"),
        )
    })?;
    let typed = local_derived_receipt_from_completion(snapshot.spec().job_id(), completion)
        .map_err(|detail| {
            MediaStoreError::corrupt(
                "media_derivation_jobs",
                format!("job {job_id:?} has invalid completion evidence: {detail}"),
            )
        })?;
    let expected = local_derived_receipt_row(&typed).map_err(|error| {
        MediaStoreError::corrupt(
            "media_derived_receipts",
            format!("job {job_id:?} cannot construct typed receipt: {error}"),
        )
    })?;
    let actual = read_derived_receipt(conn, &expected.derived_revision)?.ok_or_else(|| {
        MediaStoreError::corrupt(
            "media_derived_receipts",
            format!("derived_verified job {job_id:?} has no local derived receipt"),
        )
    })?;
    if actual != expected {
        return Err(MediaStoreError::corrupt(
            "media_derived_receipts",
            format!("derived receipt for job {job_id:?} disagrees with completion"),
        ));
    }
    Ok(())
}

fn validate_segment_pair_checkpoint(checkpoint: &SegmentPairCheckpoint) -> Result<(), String> {
    if checkpoint.published_pair_relative_path().is_empty() {
        return Err("published_pair_relative_path must not be empty".to_string());
    }
    if checkpoint.pair_commit_receipt().is_empty() {
        return Err("pair_commit_receipt must not be empty".to_string());
    }
    if checkpoint.left().role() != DerivedOutputRole::VideoLeft
        || checkpoint.right().role() != DerivedOutputRole::VideoRight
        || checkpoint.left().segment_index() != checkpoint.segment_index()
        || checkpoint.right().segment_index() != checkpoint.segment_index()
        || checkpoint.validation().segment_index() != checkpoint.segment_index()
        || !checkpoint.validation().passed()
        || checkpoint.left().relative_path() == checkpoint.right().relative_path()
        || checkpoint.left().media_type().is_empty()
        || checkpoint.right().media_type().is_empty()
    {
        return Err(format!(
            "segment-pair checkpoint {} is internally inconsistent",
            checkpoint.segment_index()
        ));
    }
    Ok(())
}

fn local_derived_receipt_from_completion(
    job_id: &DerivationJobId,
    completion: &DerivedCompletion,
) -> Result<LocalDerivedReceipt, String> {
    let manifest = DerivedManifest::parse_verified(
        completion
            .upload_bundle_input()
            .derived_manifest_canonical_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let expected_input = manifest.upload_bundle_input();
    if &expected_input != completion.upload_bundle_input() {
        return Err("completion upload bundle input disagrees with its manifest".to_string());
    }
    LocalDerivedReceipt::from_completion(job_id.clone(), completion)
        .map_err(|error| error.to_string())
}

fn rehydrate_derivation(
    spec: &DerivationSpec,
    snapshot: &DerivationSnapshot,
) -> Result<DerivationJob, String> {
    DerivationJob::rehydrate(
        spec.clone(),
        snapshot.state().clone(),
        snapshot.desired_state(),
        snapshot.version(),
        snapshot.probe_report().cloned(),
        snapshot.media_plan().cloned(),
        snapshot.checkpoints().to_vec(),
        snapshot.current_pair(),
        snapshot.completion().cloned(),
    )
    .map_err(|error| error.to_string())
}

fn derivation_natural_key(spec: &DerivationSpec) -> String {
    let source = spec.source_revision().as_str();
    let profile = spec.profile_revision().as_str();
    format!(
        "derivation-v1|{}:{}|{}:{}",
        source.len(),
        source,
        profile.len(),
        profile
    )
}

fn derivation_request_digest(spec: &DerivationSpec) -> Result<String, MediaStoreError> {
    // Job id and creation time are attempt coordinates, not request identity.
    let payload = serde_json::to_vec(&(
        spec.subject(),
        spec.local_source(),
        spec.source_manifest_digest(),
        spec.profile(),
        spec.encoder_build(),
        spec.input(),
    ))?;
    Ok(format!("sha256:{:x}", Sha256::digest(payload)))
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
