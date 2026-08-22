use std::collections::HashSet;

use rusqlite::OptionalExtension;
use serde_json::Value;

use crate::ingest::{ImportJob, ImportSpec, SourceRecording};
use crate::media_pipeline::{
    PipelineActionRequired, PipelinePolicy, PipelineStartOutcome, PipelineStartRequest,
    SessionPipeline,
};

use super::error::MediaStoreError;
use super::import_jobs::{
    find_import_identity, import_natural_key_for_id, insert_new_import_job, read_import_job,
};
use super::model::{
    CreateImportJobError, CreateImportPipelineOutcome, CreateJobConflict, CreatePipelineOutcome,
    PipelineDependency, PipelineSnapshot, PipelineStage, RevisionedCollection,
};
use super::projection::{bump_projection_revision, read_projection_revision, ProjectionResource};
use super::store::{checked_i64, checked_u64, require_non_empty, MediaStore};

type PipelineRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    String,
);

impl MediaStore {
    pub fn create_session_pipeline(
        &mut self,
        pipeline: &SessionPipeline,
        action_required: Option<&PipelineActionRequired>,
        now: &str,
    ) -> Result<CreatePipelineOutcome, MediaStoreError> {
        let snapshot = PipelineSnapshot {
            pipeline_id: pipeline.id().as_str().to_string(),
            source_key: pipeline.source().revision_claim().as_str().to_string(),
            pipeline: pipeline.clone(),
            action_required: action_required.cloned(),
            pipeline_version: 1,
            dependencies: dependencies_from_pipeline(pipeline)?,
            created_at: now.to_string(),
            updated_at: now.to_string(),
        };
        self.create_pipeline(&snapshot)
    }

    /// Atomically creates or reuses an import and creates or reuses the
    /// session-pipeline intent that owns it. No worker transition is allowed
    /// before this transaction commits, so crash recovery can always observe
    /// the queued import together with its requested policy/action graph.
    pub fn create_import_job_and_session_pipeline(
        &mut self,
        spec: &ImportSpec,
        pipeline_source: &SourceRecording,
        policy: &PipelinePolicy,
        action_required: Option<&PipelineActionRequired>,
        now: &str,
    ) -> Result<CreateImportPipelineOutcome, CreateImportJobError> {
        self.create_import_job_and_session_pipeline_validated(
            spec,
            pipeline_source,
            policy,
            action_required,
            now,
            |_| Ok(()),
        )
        .map(|(outcome, ())| outcome)
    }

    /// Creates or reuses the complete intent, then validates the exact
    /// outcome before its transaction commits. This lets an adapter prove it
    /// can publish a success result without introducing a post-commit error
    /// path that would hide an already-durable mutation.
    pub fn create_import_job_and_session_pipeline_validated<T>(
        &mut self,
        spec: &ImportSpec,
        pipeline_source: &SourceRecording,
        policy: &PipelinePolicy,
        action_required: Option<&PipelineActionRequired>,
        now: &str,
        validate: impl FnOnce(&CreateImportPipelineOutcome) -> Result<T, MediaStoreError>,
    ) -> Result<(CreateImportPipelineOutcome, T), CreateImportJobError> {
        require_non_empty(now, "now")?;
        if spec.source() != pipeline_source {
            return Err(MediaStoreError::Conflict {
                detail: "pipeline source must be the exact source admitted into its import spec"
                    .to_string(),
            }
            .into());
        }

        let initial = ImportJob::new(spec.clone()).snapshot().clone();
        let natural_key = spec.natural_key().canonical_key();
        let tx = self.conn.transaction()?;
        let (import, import_created) = if let Some((existing_id, existing_digest)) =
            find_import_identity(&tx, &natural_key)?
        {
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
            (existing, false)
        } else {
            if let Some(existing_natural_key) = import_natural_key_for_id(&tx, spec.job_id())? {
                return Err(CreateJobConflict::JobIdCollision {
                    job_id: spec.job_id().as_str().to_string(),
                    existing_natural_key,
                }
                .into());
            }
            insert_new_import_job(&tx, spec, &initial, now)?;
            let inserted = read_import_job(&tx, spec.job_id().as_str())?.ok_or_else(|| {
                MediaStoreError::NotFound {
                    detail: format!(
                        "import job {:?} vanished immediately after insertion",
                        spec.job_id().as_str()
                    ),
                }
            })?;
            (inserted, true)
        };

        // Once an existing import wins the natural-key fence, its immutable
        // admitted source is the pipeline authority. A fresh re-admission may
        // carry a new unsigned approval receipt or acquisition locator; those
        // are used only for post-commit SourceAvailable/current-locator work.
        let durable_pipeline_source = import.spec.source().clone();
        let source_key = durable_pipeline_source.revision_claim().as_str();
        let existing_pipeline = read_pipeline_by_source_key(&tx, source_key)?;
        let start = PipelineStartRequest::new(
            durable_pipeline_source,
            import.spec.job_id().clone(),
            policy.clone(),
        );
        let (pipeline, pipeline_created) = match SessionPipeline::start(
            start,
            existing_pipeline
                .as_ref()
                .map(|snapshot| &snapshot.pipeline),
        ) {
            PipelineStartOutcome::Created { pipeline } => {
                let snapshot = initial_pipeline_snapshot(&pipeline, action_required, now)?;
                if let Some(existing) = read_pipeline(&tx, &snapshot.pipeline_id)? {
                    return Err(MediaStoreError::Conflict {
                        detail: format!(
                            "pipeline id {:?} is already bound to source key {:?}",
                            snapshot.pipeline_id, existing.source_key
                        ),
                    }
                    .into());
                }
                insert_pipeline(&tx, &snapshot)?;
                (snapshot, true)
            }
            PipelineStartOutcome::Existing { .. } => {
                let existing = existing_pipeline.ok_or_else(|| MediaStoreError::Conflict {
                    detail: "pipeline admission lost its existing aggregate".to_string(),
                })?;
                if existing.action_required.as_ref() != action_required {
                    return Err(MediaStoreError::Conflict {
                        detail: format!(
                            "pipeline {:?} already has a different required policy action",
                            existing.pipeline_id
                        ),
                    }
                    .into());
                }
                (existing, false)
            }
            PipelineStartOutcome::Conflict { reason, .. } => {
                return Err(MediaStoreError::Conflict {
                    detail: format!(
                        "existing session pipeline conflicts with the requested import intent: {reason:?}"
                    ),
                }
                .into());
            }
        };

        if import_created {
            bump_projection_revision(&tx, ProjectionResource::Imports)?;
        }
        if pipeline_created {
            bump_projection_revision(&tx, ProjectionResource::Pipelines)?;
        }
        let import = read_import_job(&tx, import.spec.job_id().as_str())?.ok_or_else(|| {
            MediaStoreError::NotFound {
                detail: "import vanished before atomic pipeline admission committed".to_string(),
            }
        })?;
        let pipeline = read_pipeline(&tx, &pipeline.pipeline_id)?.ok_or_else(|| {
            MediaStoreError::NotFound {
                detail: "pipeline vanished before atomic import admission committed".to_string(),
            }
        })?;
        let outcome = CreateImportPipelineOutcome {
            import,
            pipeline,
            import_created,
            pipeline_created,
        };
        let validated = validate(&outcome)?;
        tx.commit()?;
        Ok((outcome, validated))
    }

    /// Creates the pipeline policy and its complete ordered dependency set
    /// atomically. The source key, not the transient acquisition locator, is
    /// the idempotency identity.
    pub fn create_pipeline(
        &mut self,
        snapshot: &PipelineSnapshot,
    ) -> Result<CreatePipelineOutcome, MediaStoreError> {
        validate_pipeline(snapshot)?;
        if snapshot.pipeline_version != 1 {
            return Err(MediaStoreError::Conflict {
                detail: "a new pipeline must start at version 1".to_string(),
            });
        }
        let tx = self.conn.transaction()?;
        if let Some(existing) = read_pipeline_by_source_key(&tx, &snapshot.source_key)? {
            if existing == *snapshot {
                return Ok(CreatePipelineOutcome::Existing(existing));
            }
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "pipeline source key {:?} already has a different policy or dependency graph",
                    snapshot.source_key
                ),
            });
        }
        if let Some(existing) = read_pipeline(&tx, &snapshot.pipeline_id)? {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "pipeline id {:?} is already bound to source key {:?}",
                    snapshot.pipeline_id, existing.source_key
                ),
            });
        }
        insert_pipeline(&tx, snapshot)?;
        bump_projection_revision(&tx, ProjectionResource::Pipelines)?;
        let created = read_pipeline(&tx, &snapshot.pipeline_id)?.ok_or_else(|| {
            MediaStoreError::NotFound {
                detail: format!(
                    "pipeline {:?} vanished immediately after insertion",
                    snapshot.pipeline_id
                ),
            }
        })?;
        tx.commit()?;
        Ok(CreatePipelineOutcome::Created(created))
    }

    /// Replaces policy, action-required and dependencies with one
    /// expected-version CAS. This is the pipeline's atomic publication
    /// snapshot; consumers never observe a new policy with old dependencies.
    pub fn replace_pipeline_projection(
        &mut self,
        pipeline_id: &str,
        expected_version: u64,
        pipeline: &SessionPipeline,
        action_required: Option<&PipelineActionRequired>,
        now: &str,
    ) -> Result<PipelineSnapshot, MediaStoreError> {
        require_non_empty(pipeline_id, "pipeline_id")?;
        require_non_empty(now, "now")?;
        if pipeline.id().as_str() != pipeline_id {
            return Err(MediaStoreError::Conflict {
                detail: "typed pipeline id does not match the row id".to_string(),
            });
        }
        let dependencies = dependencies_from_pipeline(pipeline)?;
        let next_version =
            expected_version
                .checked_add(1)
                .ok_or_else(|| MediaStoreError::Conflict {
                    detail: format!("pipeline {pipeline_id:?} version exhausted u64 range"),
                })?;
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "UPDATE media_pipelines
             SET pipeline_json = ?2, policy_json = ?3, action_required_json = ?4,
                 pipeline_version = ?5, updated_at = ?6
             WHERE pipeline_id = ?1 AND pipeline_version = ?7",
            rusqlite::params![
                pipeline_id,
                serde_json::to_string(pipeline)?,
                serde_json::to_string(pipeline.policy())?,
                action_required.map(serde_json::to_string).transpose()?,
                checked_i64(next_version, "pipeline_version")?,
                now,
                checked_i64(expected_version, "expected_version")?,
            ],
        )?;
        if changed != 1 {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "pipeline {pipeline_id:?} does not exist or expected version {expected_version} is stale"
                ),
            });
        }
        tx.execute(
            "DELETE FROM media_pipeline_dependencies WHERE pipeline_id = ?1",
            [pipeline_id],
        )?;
        insert_dependencies(&tx, pipeline_id, &dependencies)?;
        bump_projection_revision(&tx, ProjectionResource::Pipelines)?;
        let snapshot =
            read_pipeline(&tx, pipeline_id)?.ok_or_else(|| MediaStoreError::NotFound {
                detail: format!("pipeline {pipeline_id:?} vanished during CAS update"),
            })?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// Reads the pipeline row and every dependency from one SQLite read
    /// transaction, giving callers an indivisible policy projection.
    pub fn pipeline_snapshot(
        &mut self,
        pipeline_id: &str,
    ) -> Result<Option<PipelineSnapshot>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let snapshot = read_pipeline(&tx, pipeline_id)?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn list_pipeline_snapshots(&mut self) -> Result<Vec<PipelineSnapshot>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let mut statement =
            tx.prepare("SELECT pipeline_id FROM media_pipelines ORDER BY created_at, pipeline_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let snapshots = ids
            .into_iter()
            .map(|id| {
                read_pipeline(&tx, &id)?.ok_or_else(|| MediaStoreError::NotFound {
                    detail: format!("pipeline {id:?} vanished during snapshot enumeration"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit()?;
        Ok(snapshots)
    }

    pub fn pipeline_projection(
        &mut self,
    ) -> Result<RevisionedCollection<PipelineSnapshot>, MediaStoreError> {
        let tx = self.conn.transaction()?;
        let revision = read_projection_revision(&tx, ProjectionResource::Pipelines)?;
        let mut statement =
            tx.prepare("SELECT pipeline_id FROM media_pipelines ORDER BY created_at, pipeline_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let items = ids
            .into_iter()
            .map(|id| {
                read_pipeline(&tx, &id)?.ok_or_else(|| MediaStoreError::NotFound {
                    detail: format!("pipeline {id:?} vanished during projection read"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit()?;
        Ok(RevisionedCollection { revision, items })
    }
}

fn initial_pipeline_snapshot(
    pipeline: &SessionPipeline,
    action_required: Option<&PipelineActionRequired>,
    now: &str,
) -> Result<PipelineSnapshot, MediaStoreError> {
    let snapshot = PipelineSnapshot {
        pipeline_id: pipeline.id().as_str().to_string(),
        source_key: pipeline.source().revision_claim().as_str().to_string(),
        pipeline: pipeline.clone(),
        action_required: action_required.cloned(),
        pipeline_version: 1,
        dependencies: dependencies_from_pipeline(pipeline)?,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    };
    validate_pipeline(&snapshot)?;
    Ok(snapshot)
}

fn insert_pipeline(
    tx: &rusqlite::Transaction<'_>,
    snapshot: &PipelineSnapshot,
) -> Result<(), MediaStoreError> {
    tx.execute(
        "INSERT INTO media_pipelines (
             pipeline_id, source_key, pipeline_json, policy_json, action_required_json,
             pipeline_version, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            snapshot.pipeline_id,
            snapshot.source_key,
            serde_json::to_string(&snapshot.pipeline)?,
            serde_json::to_string(snapshot.pipeline.policy())?,
            snapshot
                .action_required
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            checked_i64(snapshot.pipeline_version, "pipeline_version")?,
            snapshot.created_at,
            snapshot.updated_at,
        ],
    )?;
    insert_dependencies(tx, &snapshot.pipeline_id, &snapshot.dependencies)
}

fn insert_dependencies(
    tx: &rusqlite::Transaction<'_>,
    pipeline_id: &str,
    dependencies: &[PipelineDependency],
) -> Result<(), MediaStoreError> {
    for (ordinal, dependency) in dependencies.iter().enumerate() {
        tx.execute(
            "INSERT INTO media_pipeline_dependencies (
                 pipeline_id, ordinal, stage, job_id, required_milestone, dependency_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                pipeline_id,
                checked_i64(
                    u64::try_from(ordinal).map_err(|_| MediaStoreError::Conflict {
                        detail: "pipeline dependency count exceeds u64".to_string(),
                    })?,
                    "dependency ordinal",
                )?,
                dependency.stage.as_db_str(),
                dependency.job_id,
                dependency.required_milestone,
                serde_json::to_string(&dependency.detail)?,
            ],
        )?;
    }
    Ok(())
}

fn read_pipeline(
    conn: &rusqlite::Connection,
    pipeline_id: &str,
) -> Result<Option<PipelineSnapshot>, MediaStoreError> {
    let row: Option<PipelineRow> = conn
        .query_row(
            "SELECT pipeline_id, source_key, pipeline_json, policy_json, action_required_json,
                    pipeline_version, created_at, updated_at
             FROM media_pipelines WHERE pipeline_id = ?1",
            [pipeline_id],
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
    row.map(|row| decode_pipeline(conn, row)).transpose()
}

fn read_pipeline_by_source_key(
    conn: &rusqlite::Connection,
    source_key: &str,
) -> Result<Option<PipelineSnapshot>, MediaStoreError> {
    let pipeline_id: Option<String> = conn
        .query_row(
            "SELECT pipeline_id FROM media_pipelines WHERE source_key = ?1",
            [source_key],
            |row| row.get(0),
        )
        .optional()?;
    pipeline_id
        .map(|pipeline_id| read_pipeline(conn, &pipeline_id))
        .transpose()
        .map(Option::flatten)
}

fn decode_pipeline(
    conn: &rusqlite::Connection,
    row: PipelineRow,
) -> Result<PipelineSnapshot, MediaStoreError> {
    let mut statement = conn.prepare(
        "SELECT stage, job_id, required_milestone, dependency_json
         FROM media_pipeline_dependencies WHERE pipeline_id = ?1 ORDER BY ordinal",
    )?;
    let raw_dependencies = statement
        .query_map([&row.0], |dependency| {
            Ok((
                dependency.get::<_, String>(0)?,
                dependency.get::<_, String>(1)?,
                dependency.get::<_, String>(2)?,
                dependency.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let dependencies = raw_dependencies
        .into_iter()
        .map(|raw| {
            Ok(PipelineDependency {
                stage: PipelineStage::from_db_str(&raw.0).ok_or_else(|| {
                    MediaStoreError::corrupt(
                        "media_pipeline_dependencies",
                        format!("unknown pipeline stage {:?}", raw.0),
                    )
                })?,
                job_id: raw.1,
                required_milestone: raw.2,
                detail: serde_json::from_str(&raw.3).map_err(|error| {
                    MediaStoreError::corrupt("media_pipeline_dependencies", error.to_string())
                })?,
            })
        })
        .collect::<Result<Vec<_>, MediaStoreError>>()?;
    let pipeline: SessionPipeline = serde_json::from_str(&row.2)
        .map_err(|error| MediaStoreError::corrupt("media_pipelines", error.to_string()))?;
    let indexed_policy: crate::media_pipeline::PipelinePolicy = serde_json::from_str(&row.3)
        .map_err(|error| MediaStoreError::corrupt("media_pipelines", error.to_string()))?;
    if pipeline.id().as_str() != row.0
        || pipeline.source().revision_claim().as_str() != row.1
        || pipeline.policy() != &indexed_policy
        || dependencies != dependencies_from_pipeline(&pipeline)?
    {
        return Err(MediaStoreError::corrupt(
            "media_pipelines",
            "typed pipeline disagrees with normalized indexes",
        ));
    }
    Ok(PipelineSnapshot {
        pipeline_id: row.0,
        source_key: row.1,
        pipeline,
        action_required: row
            .4
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|error| MediaStoreError::corrupt("media_pipelines", error.to_string()))
            })
            .transpose()?,
        pipeline_version: checked_u64(row.5, "media_pipelines", "pipeline_version")?,
        dependencies,
        created_at: row.6,
        updated_at: row.7,
    })
}

fn validate_pipeline(snapshot: &PipelineSnapshot) -> Result<(), MediaStoreError> {
    require_non_empty(&snapshot.pipeline_id, "pipeline_id")?;
    require_non_empty(&snapshot.source_key, "source_key")?;
    require_non_empty(&snapshot.created_at, "created_at")?;
    require_non_empty(&snapshot.updated_at, "updated_at")?;
    if snapshot.pipeline.id().as_str() != snapshot.pipeline_id
        || snapshot.pipeline.source().revision_claim().as_str() != snapshot.source_key
    {
        return Err(MediaStoreError::Conflict {
            detail: "typed pipeline identity disagrees with its indexes".to_string(),
        });
    }
    let expected = dependencies_from_pipeline(&snapshot.pipeline)?;
    if snapshot.dependencies != expected {
        return Err(MediaStoreError::Conflict {
            detail: "typed pipeline dependencies disagree with normalized rows".to_string(),
        });
    }
    validate_dependencies(&snapshot.dependencies)
}

fn validate_dependencies(dependencies: &[PipelineDependency]) -> Result<(), MediaStoreError> {
    let mut stages = HashSet::with_capacity(dependencies.len());
    for dependency in dependencies {
        if !stages.insert(dependency.stage) {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "pipeline contains duplicate {:?} dependencies",
                    dependency.stage
                ),
            });
        }
        require_non_empty(&dependency.job_id, "dependency job_id")?;
        require_non_empty(
            &dependency.required_milestone,
            "dependency required_milestone",
        )?;
        require_json_object(&dependency.detail, "pipeline dependency detail")?;
    }
    Ok(())
}

fn dependencies_from_pipeline(
    pipeline: &SessionPipeline,
) -> Result<Vec<PipelineDependency>, MediaStoreError> {
    let mut dependencies = vec![PipelineDependency {
        stage: PipelineStage::Import,
        job_id: pipeline.import_dependency().job_id().as_str().to_string(),
        required_milestone: "local_verified".to_string(),
        detail: serde_json::to_value(pipeline.import_dependency())?,
    }];
    if let Some(dependency) = pipeline.derivation_dependency() {
        dependencies.push(PipelineDependency {
            stage: PipelineStage::Derivation,
            job_id: dependency.job_id().as_str().to_string(),
            required_milestone: "derived_verified".to_string(),
            detail: serde_json::to_value(dependency)?,
        });
    }
    if let Some(dependency) = pipeline.upload_dependency() {
        dependencies.push(PipelineDependency {
            stage: PipelineStage::Upload,
            job_id: dependency.job_id().as_str().to_string(),
            required_milestone: "object_store_verified".to_string(),
            detail: serde_json::to_value(dependency)?,
        });
    }
    Ok(dependencies)
}

fn require_json_object(value: &Value, field: &str) -> Result<(), MediaStoreError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(MediaStoreError::Conflict {
            detail: format!("{field} must be a JSON object"),
        })
    }
}
