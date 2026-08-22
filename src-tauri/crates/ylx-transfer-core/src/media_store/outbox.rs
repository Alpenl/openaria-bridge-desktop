use rusqlite::{OptionalExtension, Transaction};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::error::MediaStoreError;
use super::model::{AcknowledgeOutcome, CompleteOutcome, CompletionEnvelope};
use super::store::{checked_i64, checked_u64};

#[derive(Debug, Clone, Copy)]
pub(crate) enum OutboxLane {
    Import,
    Derivation,
}

impl OutboxLane {
    fn table(self) -> &'static str {
        match self {
            Self::Import => "media_import_outbox",
            Self::Derivation => "media_derivation_outbox",
        }
    }
}

pub(crate) fn insert_completion<T>(
    tx: &Transaction<'_>,
    lane: OutboxLane,
    job_id: &str,
    outcome: &T,
    state_version: u64,
    recorded_at: &str,
) -> Result<CompleteOutcome<T>, MediaStoreError>
where
    T: Serialize + DeserializeOwned + Clone + PartialEq,
{
    if let Some(existing) = read_completion(tx, lane, job_id)? {
        if existing.outcome == *outcome && existing.state_version == state_version {
            return Ok(CompleteOutcome::AlreadyRecorded(existing));
        }
        return Err(MediaStoreError::Conflict {
            detail: format!("job {job_id:?} already has a different terminal completion"),
        });
    }
    let sql = format!(
        "INSERT INTO {} (job_id, outcome_json, state_version, recorded_at)
         VALUES (?1, ?2, ?3, ?4)",
        lane.table()
    );
    tx.execute(
        &sql,
        rusqlite::params![
            job_id,
            serde_json::to_string(outcome)?,
            checked_i64(state_version, "state_version")?,
            recorded_at,
        ],
    )?;
    let record = read_completion(tx, lane, job_id)?.ok_or_else(|| MediaStoreError::NotFound {
        detail: format!("completion for job {job_id:?} vanished after insertion"),
    })?;
    Ok(CompleteOutcome::Recorded(record))
}

pub(crate) fn read_completion<T>(
    conn: &rusqlite::Connection,
    lane: OutboxLane,
    job_id: &str,
) -> Result<Option<CompletionEnvelope<T>>, MediaStoreError>
where
    T: DeserializeOwned,
{
    let sql = format!(
        "SELECT sequence, job_id, outcome_json, state_version, recorded_at, acknowledged_at
         FROM {} WHERE job_id = ?1",
        lane.table()
    );
    let raw: Option<(i64, String, String, i64, String, Option<String>)> = conn
        .query_row(&sql, [job_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()?;
    raw.map(|raw| decode_completion(lane, raw)).transpose()
}

pub(crate) fn read_pending_completions<T>(
    conn: &rusqlite::Connection,
    lane: OutboxLane,
) -> Result<Vec<CompletionEnvelope<T>>, MediaStoreError>
where
    T: DeserializeOwned,
{
    let sql = format!(
        "SELECT sequence, job_id, outcome_json, state_version, recorded_at, acknowledged_at
         FROM {} WHERE acknowledged_at IS NULL ORDER BY sequence",
        lane.table()
    );
    let mut statement = conn.prepare(&sql)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|raw| decode_completion(lane, raw))
        .collect()
}

pub(crate) fn acknowledge_completion<T>(
    tx: &Transaction<'_>,
    lane: OutboxLane,
    job_id: &str,
    acknowledged_at: &str,
) -> Result<AcknowledgeOutcome<CompletionEnvelope<T>>, MediaStoreError>
where
    T: DeserializeOwned,
{
    let Some(existing) = read_completion(tx, lane, job_id)? else {
        return Ok(AcknowledgeOutcome::Unknown);
    };
    if existing.acknowledged_at.is_some() {
        return Ok(AcknowledgeOutcome::AlreadyAcknowledged(existing));
    }
    let sql = format!(
        "UPDATE {} SET acknowledged_at = ?2
         WHERE job_id = ?1 AND acknowledged_at IS NULL",
        lane.table()
    );
    let changed = tx.execute(&sql, rusqlite::params![job_id, acknowledged_at])?;
    if changed != 1 {
        return Err(MediaStoreError::Conflict {
            detail: format!("completion acknowledgement raced for job {job_id:?}"),
        });
    }
    let acknowledged =
        read_completion(tx, lane, job_id)?.ok_or_else(|| MediaStoreError::NotFound {
            detail: format!("completion for job {job_id:?} vanished during acknowledgement"),
        })?;
    Ok(AcknowledgeOutcome::Acknowledged(acknowledged))
}

fn decode_completion<T>(
    lane: OutboxLane,
    raw: (i64, String, String, i64, String, Option<String>),
) -> Result<CompletionEnvelope<T>, MediaStoreError>
where
    T: DeserializeOwned,
{
    Ok(CompletionEnvelope {
        sequence: checked_u64(raw.0, lane.table(), "sequence")?,
        job_id: raw.1,
        outcome: serde_json::from_str(&raw.2)
            .map_err(|error| MediaStoreError::corrupt(lane.table(), error.to_string()))?,
        state_version: checked_u64(raw.3, lane.table(), "state_version")?,
        recorded_at: raw.4,
        acknowledged_at: raw.5,
    })
}
