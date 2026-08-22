use rusqlite::OptionalExtension;

use crate::ingest::{MediaGeneration, MediaGenerationId};

use super::error::MediaStoreError;
use super::model::StoredMediaGeneration;
use super::store::{checked_i64, checked_u64, require_non_empty, MediaStore};

impl MediaStore {
    /// Reconcile one complete mounted-media observation atomically.
    ///
    /// Rows left present by an earlier process are marked absent in the same
    /// transaction that publishes the generations visible now. A crash cannot
    /// therefore leave a half-reconciled presence snapshot, and the first scan
    /// after restart does not need an in-memory copy of the previous process's
    /// observations.
    pub fn reconcile_media_generations(
        &mut self,
        generations: &[MediaGeneration],
        observed_at: &str,
    ) -> Result<(), MediaStoreError> {
        require_non_empty(observed_at, "observed_at")?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE media_generations SET is_present = 0, last_observed_at = ?1
             WHERE is_present = 1",
            [observed_at],
        )?;
        for generation in generations {
            observe_generation_tx(&tx, generation, observed_at)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Publishes a mounted-media observation. The generation identity is
    /// immutable; repeated arrival events update only presence/timestamps.
    pub fn observe_media_generation(
        &mut self,
        generation: &MediaGeneration,
        observed_at: &str,
    ) -> Result<StoredMediaGeneration, MediaStoreError> {
        require_non_empty(observed_at, "observed_at")?;
        let tx = self.conn.transaction()?;
        observe_generation_tx(&tx, generation, observed_at)?;
        let stored =
            read_generation(&tx, generation.id())?.ok_or_else(|| MediaStoreError::NotFound {
                detail: format!(
                    "media generation {:?} vanished during observation",
                    generation.id().as_str()
                ),
            })?;
        tx.commit()?;
        Ok(stored)
    }

    pub fn mark_media_generation_absent(
        &mut self,
        generation_id: &MediaGenerationId,
        observed_at: &str,
    ) -> Result<bool, MediaStoreError> {
        require_non_empty(observed_at, "observed_at")?;
        let changed = self.conn.execute(
            "UPDATE media_generations SET is_present = 0, last_observed_at = ?2
             WHERE generation_id = ?1",
            rusqlite::params![generation_id.as_str(), observed_at],
        )?;
        Ok(changed == 1)
    }

    pub fn media_generation(
        &self,
        generation_id: &MediaGenerationId,
    ) -> Result<Option<StoredMediaGeneration>, MediaStoreError> {
        read_generation(&self.conn, generation_id)
    }
}

pub(crate) fn observe_generation_tx(
    tx: &rusqlite::Transaction<'_>,
    generation: &MediaGeneration,
    observed_at: &str,
) -> Result<(), MediaStoreError> {
    let generation_json = serde_json::to_string(generation)?;
    let existing: Option<String> = tx
        .query_row(
            "SELECT generation_json FROM media_generations WHERE generation_id = ?1",
            [generation.id().as_str()],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(existing) if existing != generation_json => Err(MediaStoreError::Conflict {
            detail: format!(
                "media generation {:?} was observed with different identity evidence",
                generation.id().as_str()
            ),
        }),
        Some(_) => {
            tx.execute(
                "UPDATE media_generations SET is_present = 1, last_observed_at = ?2
                 WHERE generation_id = ?1",
                rusqlite::params![generation.id().as_str(), observed_at],
            )?;
            Ok(())
        }
        None => {
            tx.execute(
                "INSERT INTO media_generations (
                     generation_id, identity_digest, generation_json, observation_epoch,
                     is_present, first_observed_at, last_observed_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                rusqlite::params![
                    generation.id().as_str(),
                    generation.id().digest_hex(),
                    generation_json,
                    checked_i64(generation.observation_epoch(), "observation_epoch")?,
                    observed_at,
                ],
            )?;
            Ok(())
        }
    }
}

fn read_generation(
    conn: &rusqlite::Connection,
    generation_id: &MediaGenerationId,
) -> Result<Option<StoredMediaGeneration>, MediaStoreError> {
    let row: Option<(String, i64, i64, String, String)> = conn
        .query_row(
            "SELECT generation_json, observation_epoch, is_present,
                    first_observed_at, last_observed_at
             FROM media_generations WHERE generation_id = ?1",
            [generation_id.as_str()],
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
        let generation: MediaGeneration = serde_json::from_str(&row.0)
            .map_err(|error| MediaStoreError::corrupt("media_generations", error.to_string()))?;
        let epoch = checked_u64(row.1, "media_generations", "observation_epoch")?;
        if generation.id() != generation_id || generation.observation_epoch() != epoch {
            return Err(MediaStoreError::corrupt(
                "media_generations",
                format!(
                    "generation {:?} JSON disagrees with indexed identity or epoch",
                    generation_id.as_str()
                ),
            ));
        }
        let is_present = match row.2 {
            0 => false,
            1 => true,
            value => {
                return Err(MediaStoreError::corrupt(
                    "media_generations",
                    format!("invalid is_present value {value}"),
                ));
            }
        };
        Ok(StoredMediaGeneration {
            generation,
            is_present,
            first_observed_at: row.3,
            last_observed_at: row.4,
        })
    })
    .transpose()
}
