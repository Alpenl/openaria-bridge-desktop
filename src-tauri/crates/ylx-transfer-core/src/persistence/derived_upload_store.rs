//! Durable derived-bundle upload jobs on top of the existing `TransferStore`.
//!
//! There is deliberately no second upload aggregate. A derived-bundle upload
//! reuses `transfer_jobs`, `transfer_upload_job_specs`, `transfer_upload_activity`
//! and the completion outbox; what it does not reuse is the legacy natural key.
//! A LAN publication upload is identified by `(library entry key, publication
//! revision)`; a derived bundle is identified by `(upload bundle revision,
//! storage profile identity)`, because the same frozen bytes sent to a different
//! endpoint/bucket/prefix is a different upload, and the same destination with
//! changed bytes is a conflict rather than a replay.
//!
//! The frozen bundle and its multipart checkpoint live in a sidecar row keyed to
//! the job. The bundle is immutable for the attempt's lifetime; the checkpoint
//! advances under its own version compare-and-swap, so two workers cannot
//! overwrite each other's durable handles, parts, or verified receipts.
//!
//! Bundle and checkpoint are stored as opaque JSON. Their shapes belong to the
//! pipeline and object-store adapter respectively; this module only guarantees
//! that they are written and replaced atomically with the job.

use rusqlite::{OptionalExtension, TransactionBehavior};

use super::error::PersistenceError;
use super::schema::JobStateTag;
use super::transfer_store::{read_job, OperationKind, StoredJob, TransferStore};
use super::upload_store::{
    upload_input_digest, upload_job_identity, UploadActivitySeed, UploadJobCreateError,
    UploadJobSpec,
};

pub const UPLOAD_SUBJECT_LIBRARY_PUBLICATION: &str = "library_publication";
pub const UPLOAD_SUBJECT_DERIVED_BUNDLE: &str = "derived_bundle";

/// Maximum stored bundle or checkpoint JSON. Both are bounded inventories, so a
/// larger document is malformed rather than merely big.
pub const MAX_DERIVED_UPLOAD_JSON_BYTES: usize = 8 * 1024 * 1024;

/// Immutable identity plus opaque durable payloads for one derived-bundle
/// upload attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedUploadJobSpec {
    /// Media-library context. Retained so a projection can be rebuilt, but
    /// deliberately not part of the natural key.
    pub media_library_entry_key: String,
    pub upload_bundle_revision: String,
    pub storage_profile_identity: String,
    /// Canonical JSON of the frozen bundle. Immutable for this attempt.
    pub frozen_bundle_json: String,
    /// Initial checkpoint, normally `DerivedUploadAdapter::checkpoint_for`.
    pub checkpoint_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDerivedUploadJob {
    pub job: StoredJob,
    pub media_library_entry_key: String,
    pub upload_bundle_revision: String,
    pub storage_profile_identity: String,
    pub frozen_bundle_json: String,
    pub checkpoint_json: String,
    pub checkpoint_version: u64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedUploadCreateOutcome {
    Created(Box<StoredDerivedUploadJob>),
    /// The exact same bundle is already an active attempt for this
    /// destination. Enqueueing it again is safe and idempotent.
    Existing(Box<StoredDerivedUploadJob>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedUploadRetryOutcome {
    Created(Box<StoredDerivedUploadJob>),
    Existing(Box<StoredDerivedUploadJob>),
}

impl DerivedUploadRetryOutcome {
    #[must_use]
    pub fn job(&self) -> &StoredDerivedUploadJob {
        match self {
            Self::Created(job) | Self::Existing(job) => job,
        }
    }

    #[must_use]
    pub fn was_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointSwapOutcome {
    Applied {
        checkpoint_version: u64,
    },
    /// Another worker advanced the checkpoint first. The caller must reload
    /// before it may write again; overwriting would discard durable multipart
    /// handles or verified receipts recorded by that worker.
    Stale {
        actual_version: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DerivedUploadStoreError {
    #[error("derived upload input is invalid: {0}")]
    Invalid(String),

    #[error("derived upload natural key conflict: {detail}")]
    Conflict {
        existing_job_id: String,
        detail: String,
    },

    #[error("derived upload job {0:?} does not exist")]
    UnknownJob(String),

    #[error(transparent)]
    Create(#[from] UploadJobCreateError),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

#[derive(Debug, thiserror::Error)]
pub enum DerivedUploadRetryError {
    #[error("derived upload job {0:?} does not exist")]
    UnknownJob(String),

    #[error("job {0:?} is not a derived-bundle upload")]
    NotDerivedUpload(String),

    #[error("derived upload job {job_id:?} is not retryable")]
    NotRetryable { job_id: String },

    #[error("derived upload job {job_id:?} has been dismissed")]
    DismissedParent { job_id: String },

    #[error("derived upload job {job_id:?} has an unacknowledged terminal outcome")]
    UnacknowledgedParent { job_id: String },

    #[error(
        "derived upload job {parent_job_id:?} already has a successful retry descendant {child_job_id:?}"
    )]
    SuccessfulDescendant {
        parent_job_id: String,
        child_job_id: String,
    },

    #[error("derived upload retry job id {job_id:?} is already taken")]
    JobIdCollision { job_id: String },

    #[error("derived upload retry input is invalid: {0}")]
    Invalid(String),

    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl From<rusqlite::Error> for DerivedUploadRetryError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Persistence(error.into())
    }
}

impl From<rusqlite::Error> for DerivedUploadStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Persistence(error.into())
    }
}

impl TransferStore {
    /// Create the durable job, its typed derived-bundle spec, its activity seed
    /// and the frozen-bundle/checkpoint sidecar in one transaction.
    ///
    /// `BEGIN IMMEDIATE` plus the active-attempt query below is what keeps at
    /// most one live attempt per natural key while preserving every terminal
    /// attempt as history. A terminal predecessor does not block creation here;
    /// creating that successor is an explicit retry decision made by the caller.
    pub fn create_derived_upload_job(
        &mut self,
        job_id: &str,
        spec: &DerivedUploadJobSpec,
        activity: &UploadActivitySeed,
        now: &str,
    ) -> Result<DerivedUploadCreateOutcome, DerivedUploadStoreError> {
        validate_derived_spec(spec)?;
        if job_id.trim().is_empty() {
            return Err(DerivedUploadStoreError::Invalid(
                "job_id is empty".to_string(),
            ));
        }
        // The upload spec's own validation still applies: the derived subject
        // reuses the same immutable-input row, it does not bypass it.
        let upload_spec = UploadJobSpec::new(
            spec.media_library_entry_key.clone(),
            spec.upload_bundle_revision.clone(),
            bundle_input_digest(spec),
        )
        .map_err(|error| DerivedUploadStoreError::Invalid(error.to_string()))?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(PersistenceError::from)?;

        // One active attempt per (bundle revision, storage profile identity).
        let active: Option<(String, String)> = tx
            .query_row(
                "SELECT s.job_id, s.input_digest \
                 FROM transfer_upload_job_specs s \
                 JOIN transfer_jobs j ON j.job_id = s.job_id \
                 WHERE s.subject_kind = 'derived_bundle' \
                   AND s.revision = ?1 \
                   AND s.storage_profile_identity = ?2 \
                   AND j.state NOT IN ('succeeded', 'failed', 'cancelled') \
                 ORDER BY j.created_at DESC, j.job_id DESC LIMIT 1",
                rusqlite::params![spec.upload_bundle_revision, spec.storage_profile_identity],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_id, existing_digest)) = active {
            if existing_digest == upload_spec.input_digest {
                let stored = read_derived_upload_job(&tx, &existing_id)?.ok_or_else(|| {
                    PersistenceError::corrupt(
                        "transfer_derived_upload_jobs",
                        format!("derived upload spec {existing_id} has no sidecar row"),
                    )
                })?;
                tx.commit().map_err(PersistenceError::from)?;
                return Ok(DerivedUploadCreateOutcome::Existing(Box::new(stored)));
            }
            return Err(DerivedUploadStoreError::Conflict {
                existing_job_id: existing_id,
                detail: "a different frozen bundle is already uploading to this destination"
                    .to_string(),
            });
        }

        let identity =
            upload_job_identity(&spec.media_library_entry_key, &spec.upload_bundle_revision)
                .map_err(DerivedUploadStoreError::Invalid)?;
        if read_job_id(&tx, job_id)?.is_some() {
            return Err(DerivedUploadStoreError::Invalid(format!(
                "job id {job_id:?} is already taken"
            )));
        }

        tx.execute(
            "INSERT INTO transfer_jobs (
                 job_id, operation_kind, natural_key, device_id, session_id, revision,
                 request_digest, state, state_version, desired_run_state, created_at, updated_at
             ) VALUES (?1, 'upload', ?2, ?3, ?4, ?5, ?6, 'queued', 1, 'run', ?7, ?7)",
            rusqlite::params![
                job_id,
                derived_upload_natural_key(spec),
                // The device/session columns predate derived uploads and are
                // reused verbatim through the shared upload identity helper, so
                // a derived row cannot invent its own identity encoding.
                identity.device_id().as_str(),
                identity.session_id().as_str(),
                identity.revision(),
                upload_input_digest(&upload_spec.input_digest),
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_upload_job_specs \
                 (job_id, entry_key, revision, input_digest, object_prefix, \
                  subject_kind, storage_profile_identity) \
             VALUES (?1, ?2, ?3, ?4, NULL, 'derived_bundle', ?5)",
            rusqlite::params![
                job_id,
                spec.media_library_entry_key,
                spec.upload_bundle_revision,
                upload_spec.input_digest,
                spec.storage_profile_identity,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_upload_activity (
                 job_id, label, target_label, total_bytes, confirmed_bytes, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            rusqlite::params![
                job_id,
                activity.label,
                activity.target_label,
                i64::try_from(activity.total_bytes).map_err(|_| {
                    DerivedUploadStoreError::Invalid("total_bytes exceeds SQLite range".to_string())
                })?,
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_derived_upload_jobs (
                 job_id, media_library_entry_key, upload_bundle_revision,
                 storage_profile_identity, frozen_bundle_json, checkpoint_json,
                 checkpoint_version, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
            rusqlite::params![
                job_id,
                spec.media_library_entry_key,
                spec.upload_bundle_revision,
                spec.storage_profile_identity,
                spec.frozen_bundle_json,
                spec.checkpoint_json,
                now,
            ],
        )?;
        let stored =
            read_derived_upload_job(&tx, job_id)?.ok_or_else(|| PersistenceError::NotFound {
                detail: format!("derived upload job {job_id} vanished immediately after insert"),
            })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(DerivedUploadCreateOutcome::Created(Box::new(stored)))
    }

    pub fn derived_upload_job(
        &self,
        job_id: &str,
    ) -> Result<Option<StoredDerivedUploadJob>, DerivedUploadStoreError> {
        Ok(read_derived_upload_job(&self.conn, job_id)?)
    }

    /// Classifies an upload by its durable typed subject and verifies that the
    /// required sidecar agrees. A missing/cross-wired sidecar is corruption,
    /// never permission to fall back to the legacy publication retry path.
    pub fn is_derived_upload_job(&self, job_id: &str) -> Result<bool, DerivedUploadStoreError> {
        let typed_spec: Option<(String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT subject_kind, storage_profile_identity \
                 FROM transfer_upload_job_specs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((subject_kind, storage_profile_identity)) = typed_spec else {
            return Ok(false);
        };
        match subject_kind.as_str() {
            UPLOAD_SUBJECT_LIBRARY_PUBLICATION => {
                if storage_profile_identity.is_some()
                    || read_derived_upload_job(&self.conn, job_id)?.is_some()
                {
                    return Err(PersistenceError::corrupt(
                        "transfer_upload_job_specs",
                        format!(
                            "library publication upload {job_id} carries derived-bundle context"
                        ),
                    )
                    .into());
                }
                Ok(false)
            }
            UPLOAD_SUBJECT_DERIVED_BUNDLE => {
                let stored = read_derived_upload_job(&self.conn, job_id)?.ok_or_else(|| {
                    PersistenceError::corrupt(
                        "transfer_derived_upload_jobs",
                        format!("derived-bundle upload {job_id} has no durable sidecar"),
                    )
                })?;
                if storage_profile_identity.as_deref()
                    != Some(stored.storage_profile_identity.as_str())
                {
                    return Err(PersistenceError::corrupt(
                        "transfer_upload_job_specs",
                        format!("derived-bundle upload {job_id} has mismatched storage identity"),
                    )
                    .into());
                }
                Ok(true)
            }
            other => Err(PersistenceError::corrupt(
                "transfer_upload_job_specs",
                format!("upload {job_id} has unknown subject kind {other:?}"),
            )
            .into()),
        }
    }

    /// The live attempt for one natural key, if any. Recovery uses this to
    /// re-attach a pipeline to a job that was created before a crash.
    pub fn active_derived_upload_job(
        &self,
        upload_bundle_revision: &str,
        storage_profile_identity: &str,
    ) -> Result<Option<StoredDerivedUploadJob>, DerivedUploadStoreError> {
        let job_id: Option<String> = self
            .conn
            .query_row(
                "SELECT s.job_id FROM transfer_upload_job_specs s \
                 JOIN transfer_jobs j ON j.job_id = s.job_id \
                 WHERE s.subject_kind = 'derived_bundle' \
                   AND s.revision = ?1 \
                   AND s.storage_profile_identity = ?2 \
                   AND j.state NOT IN ('succeeded', 'failed', 'cancelled') \
                 ORDER BY j.created_at DESC, j.job_id DESC LIMIT 1",
                rusqlite::params![upload_bundle_revision, storage_profile_identity],
                |row| row.get(0),
            )
            .optional()?;
        match job_id {
            Some(job_id) => self.derived_upload_job(&job_id),
            None => Ok(None),
        }
    }

    /// Every derived upload job whose transfer job is not terminal, for
    /// startup recovery.
    pub fn list_active_derived_upload_jobs(
        &self,
    ) -> Result<Vec<StoredDerivedUploadJob>, DerivedUploadStoreError> {
        let ids: Vec<String> = {
            let mut statement = self.conn.prepare(
                "SELECT d.job_id FROM transfer_derived_upload_jobs d \
                 JOIN transfer_jobs j ON j.job_id = d.job_id \
                 WHERE j.state NOT IN ('succeeded', 'failed', 'cancelled') \
                 ORDER BY d.created_at ASC, d.job_id ASC",
            )?;
            let rows = statement
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        ids.iter()
            .map(|job_id| {
                self.derived_upload_job(job_id)?
                    .ok_or_else(|| DerivedUploadStoreError::UnknownJob(job_id.clone()))
            })
            .collect()
    }

    /// Creates a fresh typed attempt for one acknowledged retryable failure.
    ///
    /// The immutable frozen bundle and destination identity are copied from
    /// the parent, while the caller-supplied checkpoint must be freshly built
    /// from that bundle. Multipart handles, verified receipts, and confirmed
    /// progress remain attached only to the terminal parent attempt.
    pub fn retry_derived_upload_job(
        &mut self,
        parent_job_id: &str,
        child_job_id: &str,
        fresh_checkpoint_json: &str,
        now: &str,
    ) -> Result<DerivedUploadRetryOutcome, DerivedUploadRetryError> {
        if child_job_id.trim().is_empty() {
            return Err(DerivedUploadRetryError::Invalid(
                "child_job_id is empty".to_string(),
            ));
        }
        validate_json_payload("fresh_checkpoint_json", fresh_checkpoint_json)
            .map_err(|error| DerivedUploadRetryError::Invalid(error.to_string()))?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(PersistenceError::from)?;
        let parent = read_job(&tx, "job_id", parent_job_id)?
            .ok_or_else(|| DerivedUploadRetryError::UnknownJob(parent_job_id.to_string()))?;
        if parent.operation_kind != OperationKind::Upload {
            return Err(DerivedUploadRetryError::NotDerivedUpload(
                parent_job_id.to_string(),
            ));
        }
        if parent.dismissed_at.is_some() {
            return Err(DerivedUploadRetryError::DismissedParent {
                job_id: parent_job_id.to_string(),
            });
        }
        let retryable = parent.state == JobStateTag::Failed
            && parent
                .error
                .as_ref()
                .is_some_and(|(_, retryable)| *retryable);
        if !retryable {
            return Err(DerivedUploadRetryError::NotRetryable {
                job_id: parent_job_id.to_string(),
            });
        }
        let acknowledged_at: Option<Option<String>> = tx
            .query_row(
                "SELECT acknowledged_at FROM transfer_completion_outbox WHERE job_id = ?1",
                [parent_job_id],
                |row| row.get(0),
            )
            .optional()?;
        if !matches!(acknowledged_at, Some(Some(_))) {
            return Err(DerivedUploadRetryError::UnacknowledgedParent {
                job_id: parent_job_id.to_string(),
            });
        }

        let parent_sidecar = read_derived_upload_job(&tx, parent_job_id)?
            .ok_or_else(|| DerivedUploadRetryError::NotDerivedUpload(parent_job_id.to_string()))?;
        let (entry_key, revision, input_digest, object_prefix, subject_kind, storage_identity): (
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        ) = tx
            .query_row(
                "SELECT entry_key, revision, input_digest, object_prefix, subject_kind, \
                        storage_profile_identity \
                 FROM transfer_upload_job_specs WHERE job_id = ?1",
                [parent_job_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(|error| {
                DerivedUploadRetryError::Persistence(PersistenceError::corrupt(
                    "transfer_upload_job_specs",
                    format!("derived upload retry parent {parent_job_id} has no spec: {error}"),
                ))
            })?;
        if subject_kind != UPLOAD_SUBJECT_DERIVED_BUNDLE
            || storage_identity.as_deref() != Some(parent_sidecar.storage_profile_identity.as_str())
            || revision != parent_sidecar.upload_bundle_revision
            || entry_key != parent_sidecar.media_library_entry_key
        {
            return Err(DerivedUploadRetryError::Persistence(
                PersistenceError::corrupt(
                    "transfer_upload_job_specs",
                    format!(
                        "derived upload retry parent {parent_job_id} has mismatched typed context"
                    ),
                ),
            ));
        }

        let successful_child: Option<String> = tx
            .query_row(
                "SELECT l.child_job_id FROM transfer_job_lineage l \
                 JOIN transfer_jobs j ON j.job_id = l.child_job_id \
                 WHERE l.parent_job_id = ?1 AND j.state = 'succeeded' \
                 ORDER BY l.attempt DESC LIMIT 1",
                [parent_job_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(child_job_id) = successful_child {
            return Err(DerivedUploadRetryError::SuccessfulDescendant {
                parent_job_id: parent_job_id.to_string(),
                child_job_id,
            });
        }

        if let Some(existing) = read_job(&tx, "job_id", child_job_id)? {
            let linked_parent: Option<String> = tx
                .query_row(
                    "SELECT parent_job_id FROM transfer_job_lineage WHERE child_job_id = ?1",
                    [child_job_id],
                    |row| row.get(0),
                )
                .optional()?;
            if linked_parent.as_deref() == Some(parent_job_id) {
                let stored = read_derived_upload_job(&tx, child_job_id)?.ok_or_else(|| {
                    DerivedUploadRetryError::Persistence(PersistenceError::corrupt(
                        "transfer_derived_upload_jobs",
                        format!("derived upload retry child {child_job_id} has no sidecar"),
                    ))
                })?;
                debug_assert_eq!(stored.job, existing);
                tx.commit().map_err(PersistenceError::from)?;
                return Ok(DerivedUploadRetryOutcome::Existing(Box::new(stored)));
            }
            return Err(DerivedUploadRetryError::JobIdCollision {
                job_id: child_job_id.to_string(),
            });
        }

        let previous_child: Option<(String, i64)> = tx
            .query_row(
                "SELECT l.child_job_id, l.attempt FROM transfer_job_lineage l \
                 JOIN transfer_jobs j ON j.job_id = l.child_job_id \
                 WHERE l.parent_job_id = ?1 ORDER BY l.attempt DESC LIMIT 1",
                [parent_job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_id, _)) = previous_child.as_ref() {
            if let Some(existing) = read_job(&tx, "job_id", existing_id)? {
                if !existing.state.is_terminal() {
                    let stored = read_derived_upload_job(&tx, existing_id)?.ok_or_else(|| {
                        DerivedUploadRetryError::Persistence(PersistenceError::corrupt(
                            "transfer_derived_upload_jobs",
                            format!("active derived retry child {existing_id} has no sidecar"),
                        ))
                    })?;
                    tx.commit().map_err(PersistenceError::from)?;
                    return Ok(DerivedUploadRetryOutcome::Existing(Box::new(stored)));
                }
            }
        }
        let attempt = match previous_child {
            Some((_, attempt)) => attempt.checked_add(1).ok_or_else(|| {
                DerivedUploadRetryError::Persistence(PersistenceError::Conflict {
                    detail: format!("retry attempt for {parent_job_id} exhausted SQLite range"),
                })
            })?,
            None => 1,
        };

        let active_job_id: Option<String> = tx
            .query_row(
                "SELECT s.job_id FROM transfer_upload_job_specs s \
                 JOIN transfer_jobs j ON j.job_id = s.job_id \
                 WHERE s.subject_kind = 'derived_bundle' \
                   AND s.revision = ?1 AND s.storage_profile_identity = ?2 \
                   AND j.state NOT IN ('succeeded', 'failed', 'cancelled') \
                 ORDER BY j.created_at DESC, j.job_id DESC LIMIT 1",
                rusqlite::params![revision, parent_sidecar.storage_profile_identity],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(active_job_id) = active_job_id {
            let stored = read_derived_upload_job(&tx, &active_job_id)?.ok_or_else(|| {
                DerivedUploadRetryError::Persistence(PersistenceError::corrupt(
                    "transfer_derived_upload_jobs",
                    format!("active derived upload {active_job_id} has no sidecar"),
                ))
            })?;
            tx.commit().map_err(PersistenceError::from)?;
            return Ok(DerivedUploadRetryOutcome::Existing(Box::new(stored)));
        }

        let (label, target_label, total_bytes): (String, String, i64) = tx
            .query_row(
                "SELECT label, target_label, total_bytes FROM transfer_upload_activity \
                 WHERE job_id = ?1",
                [parent_job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| {
                DerivedUploadRetryError::Persistence(PersistenceError::corrupt(
                    "transfer_upload_activity",
                    format!("derived upload retry parent {parent_job_id} has no activity: {error}"),
                ))
            })?;
        let natural_key = format!(
            "{}#retry:{child_job_id}",
            derived_upload_natural_key(&DerivedUploadJobSpec {
                media_library_entry_key: entry_key.clone(),
                upload_bundle_revision: revision.clone(),
                storage_profile_identity: parent_sidecar.storage_profile_identity.clone(),
                frozen_bundle_json: parent_sidecar.frozen_bundle_json.clone(),
                checkpoint_json: fresh_checkpoint_json.to_string(),
            })
        );
        tx.execute(
            "INSERT INTO transfer_jobs (
                 job_id, operation_kind, natural_key, device_id, session_id, revision,
                 request_digest, state, state_version, desired_run_state, created_at, updated_at
             ) VALUES (?1, 'upload', ?2, ?3, ?4, ?5, ?6, 'queued', 1, 'run', ?7, ?7)",
            rusqlite::params![
                child_job_id,
                natural_key,
                parent.identity.device_id().as_str(),
                parent.identity.session_id().as_str(),
                parent.identity.revision(),
                parent.request_digest.to_hex(),
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_upload_job_specs (
                 job_id, entry_key, revision, input_digest, object_prefix,
                 subject_kind, storage_profile_identity
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'derived_bundle', ?6)",
            rusqlite::params![
                child_job_id,
                entry_key,
                revision,
                input_digest,
                object_prefix,
                parent_sidecar.storage_profile_identity,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_upload_activity (
                 job_id, label, target_label, total_bytes, confirmed_bytes, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            rusqlite::params![child_job_id, label, target_label, total_bytes, now],
        )?;
        tx.execute(
            "INSERT INTO transfer_derived_upload_jobs (
                 job_id, media_library_entry_key, upload_bundle_revision,
                 storage_profile_identity, frozen_bundle_json, checkpoint_json,
                 checkpoint_version, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
            rusqlite::params![
                child_job_id,
                parent_sidecar.media_library_entry_key,
                parent_sidecar.upload_bundle_revision,
                parent_sidecar.storage_profile_identity,
                parent_sidecar.frozen_bundle_json,
                fresh_checkpoint_json,
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO transfer_job_lineage (child_job_id, parent_job_id, attempt, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![child_job_id, parent_job_id, attempt, now],
        )?;
        let stored = read_derived_upload_job(&tx, child_job_id)?.ok_or_else(|| {
            DerivedUploadRetryError::Persistence(PersistenceError::NotFound {
                detail: format!("derived upload retry child {child_job_id} vanished after insert"),
            })
        })?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(DerivedUploadRetryOutcome::Created(Box::new(stored)))
    }

    /// Replace the multipart checkpoint under an expected-version CAS.
    ///
    /// The frozen bundle is never touched here: the plan an attempt started
    /// with is the plan it finishes with.
    pub fn compare_and_swap_derived_upload_checkpoint(
        &mut self,
        job_id: &str,
        expected_version: u64,
        checkpoint_json: &str,
        now: &str,
    ) -> Result<CheckpointSwapOutcome, DerivedUploadStoreError> {
        validate_json_payload("checkpoint_json", checkpoint_json)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(PersistenceError::from)?;
        let actual: Option<i64> = tx
            .query_row(
                "SELECT checkpoint_version FROM transfer_derived_upload_jobs WHERE job_id = ?1",
                [job_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(actual) = actual else {
            return Err(DerivedUploadStoreError::UnknownJob(job_id.to_string()));
        };
        let actual = actual.max(0) as u64;
        if actual != expected_version {
            tx.commit().map_err(PersistenceError::from)?;
            return Ok(CheckpointSwapOutcome::Stale {
                actual_version: actual,
            });
        }
        let next = actual.checked_add(1).ok_or_else(|| {
            DerivedUploadStoreError::Invalid(
                "derived upload checkpoint version exhausted u64 range".to_string(),
            )
        })?;
        tx.execute(
            "UPDATE transfer_derived_upload_jobs \
             SET checkpoint_json = ?2, checkpoint_version = ?3, updated_at = ?4 \
             WHERE job_id = ?1",
            rusqlite::params![
                job_id,
                checkpoint_json,
                i64::try_from(next).map_err(|_| DerivedUploadStoreError::Invalid(
                    "checkpoint version exceeds SQLite range".to_string()
                ))?,
                now,
            ],
        )?;
        tx.commit().map_err(PersistenceError::from)?;
        Ok(CheckpointSwapOutcome::Applied {
            checkpoint_version: next,
        })
    }
}

/// Deterministic natural key text stored on the transfer job row.
fn derived_upload_natural_key(spec: &DerivedUploadJobSpec) -> String {
    format!(
        "upload:derived:{}:{}:{}:{}",
        spec.upload_bundle_revision.len(),
        spec.upload_bundle_revision,
        spec.storage_profile_identity.len(),
        spec.storage_profile_identity
    )
}

/// The immutable input that distinguishes an idempotent replay from a
/// conflicting request. It covers the frozen bundle bytes and the destination,
/// so neither can change without producing a conflict.
fn bundle_input_digest(spec: &DerivedUploadJobSpec) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ylx-transfer/derived-upload-input-v1\0");
    for field in [
        spec.upload_bundle_revision.as_str(),
        spec.storage_profile_identity.as_str(),
        spec.frozen_bundle_json.as_str(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn validate_derived_spec(spec: &DerivedUploadJobSpec) -> Result<(), DerivedUploadStoreError> {
    for (field, value) in [
        ("media_library_entry_key", &spec.media_library_entry_key),
        ("upload_bundle_revision", &spec.upload_bundle_revision),
        ("storage_profile_identity", &spec.storage_profile_identity),
    ] {
        if value.trim().is_empty() {
            return Err(DerivedUploadStoreError::Invalid(format!(
                "{field} must not be empty"
            )));
        }
    }
    validate_json_payload("frozen_bundle_json", &spec.frozen_bundle_json)?;
    validate_json_payload("checkpoint_json", &spec.checkpoint_json)
}

fn validate_json_payload(field: &str, value: &str) -> Result<(), DerivedUploadStoreError> {
    if value.len() > MAX_DERIVED_UPLOAD_JSON_BYTES {
        return Err(DerivedUploadStoreError::Invalid(format!(
            "{field} exceeded {MAX_DERIVED_UPLOAD_JSON_BYTES} bytes"
        )));
    }
    serde_json::from_str::<serde_json::Value>(value)
        .map(|_| ())
        .map_err(|error| {
            DerivedUploadStoreError::Invalid(format!("{field} is not valid JSON: {error}"))
        })
}

fn read_job_id(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<Option<String>, PersistenceError> {
    conn.query_row(
        "SELECT job_id FROM transfer_jobs WHERE job_id = ?1",
        [job_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(PersistenceError::from)
}

/// The sidecar columns, in select order.
type DerivedUploadSidecarRow = (String, String, String, String, String, i64, String, String);

fn read_derived_upload_job(
    conn: &rusqlite::Connection,
    job_id: &str,
) -> Result<Option<StoredDerivedUploadJob>, PersistenceError> {
    let row: Option<DerivedUploadSidecarRow> = conn
        .query_row(
            "SELECT media_library_entry_key, upload_bundle_revision, storage_profile_identity, \
                    frozen_bundle_json, checkpoint_json, checkpoint_version, created_at, updated_at \
             FROM transfer_derived_upload_jobs WHERE job_id = ?1",
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
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        media_library_entry_key,
        upload_bundle_revision,
        storage_profile_identity,
        frozen_bundle_json,
        checkpoint_json,
        checkpoint_version,
        created_at,
        updated_at,
    )) = row
    else {
        return Ok(None);
    };
    let Some(job) = read_job(conn, "job_id", job_id)? else {
        return Err(PersistenceError::corrupt(
            "transfer_derived_upload_jobs",
            format!("derived upload sidecar {job_id} has no transfer job"),
        ));
    };
    if job.operation_kind != OperationKind::Upload {
        return Err(PersistenceError::corrupt(
            "transfer_derived_upload_jobs",
            format!("derived upload sidecar {job_id} points at a non-upload job"),
        ));
    }
    Ok(Some(StoredDerivedUploadJob {
        job,
        media_library_entry_key,
        upload_bundle_revision,
        storage_profile_identity,
        frozen_bundle_json,
        checkpoint_json,
        checkpoint_version: checkpoint_version.max(0) as u64,
        created_at,
        updated_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TransferStore {
        let dir = tempfile::tempdir().expect("temp dir");
        TransferStore::open(dir.keep().join("transfers.sqlite3")).expect("open transfer store")
    }

    fn spec(bundle: &str, destination: &str) -> DerivedUploadJobSpec {
        DerivedUploadJobSpec {
            media_library_entry_key: format!("media-library-v1:{}", "a".repeat(64)),
            upload_bundle_revision: bundle.to_string(),
            storage_profile_identity: destination.to_string(),
            frozen_bundle_json: r#"{"schema_version":1,"objects":[]}"#.to_string(),
            checkpoint_json: r#"{"schema_version":1,"objects":[]}"#.to_string(),
        }
    }

    fn seed() -> UploadActivitySeed {
        UploadActivitySeed {
            label: "session".to_string(),
            target_label: "bucket".to_string(),
            total_bytes: 0,
        }
    }

    fn fail_and_acknowledge(store: &mut TransferStore, job_id: &str) {
        let started = store
            .start_upload_job(job_id, 1, "2026-08-05T00:00:01Z")
            .expect("start upload");
        store
            .complete_upload_job(
                job_id,
                started,
                &super::super::transfer_store::TerminalOutcome::Failed {
                    code: "temporary_remote_failure".to_string(),
                    retryable: true,
                },
                "2026-08-05T00:00:02Z",
            )
            .expect("fail upload");
        store
            .acknowledge_completion(job_id, "2026-08-05T00:00:03Z")
            .expect("acknowledge upload failure");
    }

    #[test]
    fn durable_subject_classifier_identifies_derived_uploads() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create derived upload");

        assert!(store
            .is_derived_upload_job("job-1")
            .expect("classify derived upload"));
    }

    #[test]
    fn durable_subject_classifier_rejects_legacy_publication_uploads() {
        let mut store = store();
        let publication = UploadJobSpec::new("device-1|session-1", "revision-1", "digest-1")
            .expect("valid publication upload spec");
        store
            .create_upload_job("job-1", &publication, "2026-08-05T00:00:00Z")
            .expect("create publication upload");

        assert!(!store
            .is_derived_upload_job("job-1")
            .expect("classify publication upload"));
    }

    #[test]
    fn durable_subject_classifier_fails_closed_when_derived_sidecar_is_missing() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create derived upload");
        store
            .conn
            .execute(
                "DELETE FROM transfer_derived_upload_jobs WHERE job_id = 'job-1'",
                [],
            )
            .expect("delete derived sidecar");

        assert!(matches!(
            store.is_derived_upload_job("job-1"),
            Err(DerivedUploadStoreError::Persistence(
                PersistenceError::Corrupt { .. }
            ))
        ));
    }

    #[test]
    fn the_same_bundle_and_destination_is_an_idempotent_replay() {
        let mut store = store();
        let spec = spec("sha256:bundle", "profile-a");
        store
            .create_derived_upload_job("job-1", &spec, &seed(), "2026-08-05T00:00:00Z")
            .expect("create");
        let again = store
            .create_derived_upload_job("job-2", &spec, &seed(), "2026-08-05T00:00:01Z")
            .expect("replay");
        assert!(matches!(again, DerivedUploadCreateOutcome::Existing(_)));
    }

    #[test]
    fn a_changed_bundle_for_the_same_destination_is_a_conflict() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create");
        let mut changed = spec("sha256:bundle", "profile-a");
        changed.frozen_bundle_json = r#"{"schema_version":1,"objects":[1]}"#.to_string();
        assert!(matches!(
            store.create_derived_upload_job("job-2", &changed, &seed(), "2026-08-05T00:00:01Z"),
            Err(DerivedUploadStoreError::Conflict { .. })
        ));
    }

    #[test]
    fn a_different_destination_is_a_separate_upload() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create");
        let other = store
            .create_derived_upload_job(
                "job-2",
                &spec("sha256:bundle", "profile-b"),
                &seed(),
                "2026-08-05T00:00:01Z",
            )
            .expect("second destination");
        assert!(matches!(other, DerivedUploadCreateOutcome::Created(_)));
    }

    #[test]
    fn checkpoint_replacement_requires_the_expected_version() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create");
        let applied = store
            .compare_and_swap_derived_upload_checkpoint(
                "job-1",
                1,
                r#"{"schema_version":1,"objects":[]}"#,
                "2026-08-05T00:00:02Z",
            )
            .expect("cas");
        assert_eq!(
            applied,
            CheckpointSwapOutcome::Applied {
                checkpoint_version: 2
            }
        );
        let stale = store
            .compare_and_swap_derived_upload_checkpoint(
                "job-1",
                1,
                r#"{"schema_version":1,"objects":[]}"#,
                "2026-08-05T00:00:03Z",
            )
            .expect("stale cas");
        assert_eq!(stale, CheckpointSwapOutcome::Stale { actual_version: 2 });
    }

    #[test]
    fn an_active_attempt_is_discoverable_by_its_natural_key() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create");
        let found = store
            .active_derived_upload_job("sha256:bundle", "profile-a")
            .expect("lookup")
            .expect("active attempt");
        assert_eq!(found.job.job_id, "job-1");
        assert_eq!(store.list_active_derived_upload_jobs().unwrap().len(), 1);
    }

    #[test]
    fn typed_retry_preserves_bundle_subject_and_destination_with_a_fresh_checkpoint() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create");
        store
            .compare_and_swap_derived_upload_checkpoint(
                "job-1",
                1,
                r#"{"schema_version":1,"parent_progress":"must-not-copy"}"#,
                "2026-08-05T00:00:00.500Z",
            )
            .expect("advance parent checkpoint");
        fail_and_acknowledge(&mut store, "job-1");

        let retry = store
            .retry_derived_upload_job(
                "job-1",
                "job-2",
                r#"{"schema_version":1,"fresh":true}"#,
                "2026-08-05T00:00:04Z",
            )
            .expect("retry");
        assert!(retry.was_created());
        let child = retry.job();
        assert_eq!(child.job.job_id, "job-2");
        assert_eq!(child.upload_bundle_revision, "sha256:bundle");
        assert_eq!(child.storage_profile_identity, "profile-a");
        assert_eq!(
            child.frozen_bundle_json,
            spec("sha256:bundle", "profile-a").frozen_bundle_json
        );
        assert_eq!(
            child.checkpoint_json,
            r#"{"schema_version":1,"fresh":true}"#
        );
        assert_eq!(child.checkpoint_version, 1);

        let (subject, storage, confirmed): (String, Option<String>, i64) = store
            .conn
            .query_row(
                "SELECT s.subject_kind, s.storage_profile_identity, a.confirmed_bytes \
                 FROM transfer_upload_job_specs s \
                 JOIN transfer_upload_activity a ON a.job_id = s.job_id \
                 WHERE s.job_id = 'job-2'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("typed child context");
        assert_eq!(subject, UPLOAD_SUBJECT_DERIVED_BUNDLE);
        assert_eq!(storage.as_deref(), Some("profile-a"));
        assert_eq!(confirmed, 0);
        assert_eq!(
            store.retry_parent("job-2").unwrap().unwrap().parent_job_id,
            "job-1"
        );
    }

    #[test]
    fn typed_retry_is_idempotent_while_the_child_is_active() {
        let mut store = store();
        store
            .create_derived_upload_job(
                "job-1",
                &spec("sha256:bundle", "profile-a"),
                &seed(),
                "2026-08-05T00:00:00Z",
            )
            .expect("create");
        fail_and_acknowledge(&mut store, "job-1");
        store
            .retry_derived_upload_job(
                "job-1",
                "job-2",
                r#"{"schema_version":1,"fresh":true}"#,
                "2026-08-05T00:00:04Z",
            )
            .expect("first retry");

        let replay = store
            .retry_derived_upload_job(
                "job-1",
                "job-3",
                r#"{"schema_version":1,"fresh":true}"#,
                "2026-08-05T00:00:05Z",
            )
            .expect("idempotent retry");
        assert!(!replay.was_created());
        assert_eq!(replay.job().job.job_id, "job-2");
        assert!(store.derived_upload_job("job-3").unwrap().is_none());
    }
}
