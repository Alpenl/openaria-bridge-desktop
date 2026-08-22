//! Transactional production snapshot store for the desktop application's
//! local library and non-secret storage profile.
//!
//! The Tauri layer owns the concrete DTOs, so this module stores each
//! library entry as an independently keyed, caller-serialized payload. The
//! storage profile is kept in a separate table and every replacement is one
//! SQLite transaction. Raw credentials do not belong in either payload.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::PersistenceError;

const APP_STORE_IDENTITY: &str = "ylx-transfer/app-store";

const MIGRATIONS: &[(u32, &str)] = &[
    (
        1,
        r#"
    CREATE TABLE app_library_entries (
        entry_key TEXT PRIMARY KEY,
        payload   BLOB NOT NULL
    );

    CREATE TABLE app_storage_config (
        id      INTEGER PRIMARY KEY CHECK (id = 0),
        payload BLOB NOT NULL
    );

    CREATE TABLE app_store_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    INSERT INTO app_store_meta (key, value) VALUES ('identity', 'ylx-transfer/app-store');
    INSERT INTO app_store_meta (key, value) VALUES ('revision', '0');
    "#,
    ),
    (
        2,
        r#"
    -- Durable per-entry operation lease. The entry key is unique, so a
    -- delete and an upload cannot both own one target across processes.
    CREATE TABLE app_operation_leases (
        entry_key    TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        kind         TEXT NOT NULL CHECK (kind IN ('delete', 'upload')),
        acquired_at  TEXT NOT NULL
    );

    -- A delete intent is recorded after the visible directory is atomically
    -- renamed into same-filesystem trash. Paths make the rename recoverable
    -- after a crash, before or after the AppStore revision CAS.
    CREATE TABLE app_library_delete_intents (
        operation_id      TEXT NOT NULL,
        entry_key         TEXT NOT NULL,
        source_path       TEXT NOT NULL,
        trash_path        TEXT NOT NULL,
        expected_revision INTEGER NOT NULL CHECK (expected_revision >= 0),
        state             TEXT NOT NULL CHECK (state IN ('staged', 'committed')),
        created_at        TEXT NOT NULL,
        PRIMARY KEY (operation_id, entry_key)
    );
    CREATE INDEX app_library_delete_intents_state
        ON app_library_delete_intents (state, operation_id);
    "#,
    ),
    (
        3,
        r#"
    -- Removable-media library projections live in their own table rather than
    -- inside `app_library_entries`. The legacy LAN payload assumes a signed
    -- publication keyed by device/session; a TF source may be unsigned raw,
    -- legacy, or spool media, so reusing that row would either lose provenance
    -- or fabricate signed evidence. The two decoders must never meet.
    CREATE TABLE app_media_library_entries (
        entry_key           TEXT PRIMARY KEY,
        projection_revision INTEGER NOT NULL CHECK (projection_revision >= 1),
        payload             BLOB NOT NULL,
        updated_at          TEXT NOT NULL
    );
    "#,
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLibraryPayload {
    pub entry_key: String,
    pub payload: Vec<u8>,
}

/// One serialized removable-media library projection plus the per-entry
/// revision that guards its replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaLibraryPayload {
    pub entry_key: String,
    pub projection_revision: u64,
    pub payload: Vec<u8>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppStoreSnapshot {
    pub revision: u64,
    pub library: Vec<AppLibraryPayload>,
    pub storage: Option<Vec<u8>>,
}

/// Details for callers that need to surface an optimistic-write conflict.
/// `PersistenceError::Conflict` remains the wire error so existing callers
/// do not need a new error conversion layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppStoreRevisionConflict {
    pub expected: u64,
    pub actual: u64,
}

/// Durable state of one library-delete rename/metadata handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryDeleteIntentState {
    Staged,
    Committed,
}

impl LibraryDeleteIntentState {
    fn as_db_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Committed => "committed",
        }
    }

    fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "staged" => Some(Self::Staged),
            "committed" => Some(Self::Committed),
            _ => None,
        }
    }
}

/// A filesystem rename that has to converge after a crash/restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryDeleteIntent {
    pub operation_id: String,
    pub entry_key: String,
    pub source_path: PathBuf,
    pub trash_path: PathBuf,
    pub expected_revision: u64,
    pub state: LibraryDeleteIntentState,
    pub created_at: String,
}

/// One durable per-entry operation lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationLease {
    pub entry_key: String,
    pub operation_id: String,
    pub kind: String,
    pub acquired_at: String,
}

/// Result of trying to claim a lease. The caller can turn `Existing` into a
/// stable busy result without inspecting SQLite error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationLeaseOutcome {
    Acquired,
    Existing(OperationLease),
}

/// SQLite authority used by the desktop composition. The connection is
/// mutex-protected so callers can keep `AppData::persist_result(&self)` and
/// still open a real transaction for every write.
pub struct AppStore {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl std::fmt::Debug for AppStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStore")
            .field("path", &self.path)
            .finish()
    }
}

impl AppStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistenceError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| PersistenceError::io(parent, error))?;
        }

        let mut conn = Connection::open(&path)?;
        let integrity = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(code, _)
                    if matches!(
                        code.code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    ) =>
                {
                    PersistenceError::Busy
                }
                other => PersistenceError::corrupt(&path, other.to_string()),
            })?;
        if integrity != "ok" {
            return Err(PersistenceError::corrupt(&path, integrity));
        }

        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        run_migrations(&mut conn, &path)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    pub fn load(&self) -> Result<AppStoreSnapshot, PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        // Keep revision, library and storage at one SQLite read point. A
        // plain sequence of SELECTs can otherwise combine rows from two
        // commits when another process writes between statements.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let revision_raw: String = tx.query_row(
            "SELECT value FROM app_store_meta WHERE key = 'revision'",
            [],
            |row| row.get(0),
        )?;
        let revision = revision_raw.parse::<u64>().map_err(|error| {
            PersistenceError::corrupt(
                &self.path,
                format!("application store revision is invalid: {error}"),
            )
        })?;

        let mut statement = tx
            .prepare("SELECT entry_key, payload FROM app_library_entries ORDER BY entry_key ASC")?;
        let library = statement
            .query_map([], |row| {
                Ok(AppLibraryPayload {
                    entry_key: row.get(0)?,
                    payload: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let storage = tx
            .query_row(
                "SELECT payload FROM app_storage_config WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .optional()?;

        drop(statement);

        let snapshot = AppStoreSnapshot {
            revision,
            library,
            storage,
        };
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn save(
        &self,
        library: &[AppLibraryPayload],
        storage: &[u8],
    ) -> Result<(), PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.replace_in_transaction(&tx, library, storage, None)?;
        tx.commit()?;
        Ok(())
    }

    /// Replace the complete application snapshot only if `expected_revision`
    /// is still current. Returns the new revision on success. A stale
    /// snapshot is reported as a typed conflict instead of overwriting newer
    /// rows from another writer.
    pub fn save_if_revision(
        &self,
        expected_revision: u64,
        library: &[AppLibraryPayload],
        storage: &[u8],
    ) -> Result<u64, PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = read_revision(&tx, &self.path)?;
        if actual != expected_revision {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "application store revision conflict: expected {expected_revision}, actual {actual}"
                ),
            });
        }
        let next = expected_revision
            .checked_add(1)
            .ok_or_else(|| PersistenceError::Conflict {
                detail: "application store revision exhausted u64 range".to_string(),
            })?;
        self.replace_in_transaction(&tx, library, storage, Some(next))?;
        tx.commit()?;
        Ok(next)
    }

    /// Upsert exactly one library row if the complete application revision
    /// is still `expected_revision`.
    ///
    /// The payload must be serialized by the caller before entering this
    /// method. The transaction only writes the named row and the revision
    /// marker; unrelated library rows and the storage profile are untouched.
    /// This is the projection path for terminal transfer outcomes, where
    /// rebuilding and replacing the complete library snapshot would hold the
    /// application state lock across unrelated SQLite work.
    pub fn upsert_library_entry_if_revision(
        &self,
        expected_revision: u64,
        entry: &AppLibraryPayload,
    ) -> Result<u64, PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = read_revision(&tx, &self.path)?;
        if actual != expected_revision {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "application store revision conflict: expected {expected_revision}, actual {actual}"
                ),
            });
        }
        let next = expected_revision
            .checked_add(1)
            .ok_or_else(|| PersistenceError::Conflict {
                detail: "application store revision exhausted u64 range".to_string(),
            })?;
        tx.execute(
            "INSERT INTO app_library_entries (entry_key, payload) VALUES (?1, ?2) \
             ON CONFLICT(entry_key) DO UPDATE SET payload = excluded.payload",
            rusqlite::params![&entry.entry_key, &entry.payload],
        )?;
        tx.execute(
            "UPDATE app_store_meta SET value = ?1 WHERE key = 'revision'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Read one library row together with the revision that guards it. The
    /// pair is read in one deferred transaction so a projection can
    /// reconcile the narrow crash window after a per-entry CAS commits but
    /// before its in-memory copy is published.
    pub fn read_library_entry(
        &self,
        entry_key: &str,
    ) -> Result<(u64, Option<AppLibraryPayload>), PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.unchecked_transaction()?;
        let revision = read_revision(&tx, &self.path)?;
        let entry = tx
            .query_row(
                "SELECT entry_key, payload FROM app_library_entries WHERE entry_key = ?1",
                [entry_key],
                |row| {
                    Ok(AppLibraryPayload {
                        entry_key: row.get(0)?,
                        payload: row.get(1)?,
                    })
                },
            )
            .optional()?;
        tx.commit()?;
        Ok((revision, entry))
    }

    /// Read one media-library projection row with the global revision that
    /// guards it. Both are read at one point so a caller can build an exact
    /// `ExpectedProjectionRevision` for the following compare-and-swap.
    pub fn read_media_library_entry(
        &self,
        entry_key: &str,
    ) -> Result<(u64, Option<MediaLibraryPayload>), PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.unchecked_transaction()?;
        let revision = read_revision(&tx, &self.path)?;
        let entry = tx
            .query_row(
                "SELECT entry_key, projection_revision, payload, updated_at \
                 FROM app_media_library_entries WHERE entry_key = ?1",
                [entry_key],
                media_library_payload_from_row,
            )
            .optional()?;
        tx.commit()?;
        Ok((revision, entry))
    }

    /// Every media-library projection, for the boot snapshot.
    pub fn read_media_library_entries(&self) -> Result<Vec<MediaLibraryPayload>, PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let mut statement = conn.prepare(
            "SELECT entry_key, projection_revision, payload, updated_at \
             FROM app_media_library_entries ORDER BY entry_key ASC",
        )?;
        let rows = statement
            .query_map([], media_library_payload_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Read every media-library projection together with the global revision
    /// that guards the same snapshot. Keeping these reads in one transaction
    /// prevents a projector from publishing a collection under a watermark
    /// that belongs to a different AppStore state.
    pub fn read_media_library_entries_with_revision(
        &self,
    ) -> Result<(u64, Vec<MediaLibraryPayload>), PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.unchecked_transaction()?;
        let revision = read_revision(&tx, &self.path)?;
        let rows = {
            let mut statement = tx.prepare(
                "SELECT entry_key, projection_revision, payload, updated_at \
                 FROM app_media_library_entries ORDER BY entry_key ASC",
            )?;
            let rows = statement
                .query_map([], media_library_payload_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        tx.commit()?;
        Ok((revision, rows))
    }

    /// Replace one media-library projection under a double compare-and-swap.
    ///
    /// Both the global store revision and the per-entry projection revision
    /// must still be exactly what the caller observed. Checking only the
    /// global revision would let two projectors that read the same entry
    /// overwrite each other whenever an unrelated write happened to advance
    /// the global counter between them.
    ///
    /// `expected_projection_revision` of `None` asserts the entry does not
    /// exist yet, which is what makes a replayed create idempotent instead of
    /// silently resurrecting an entry another writer removed.
    pub fn replace_media_library_entry_if_revision(
        &self,
        expected_revision: u64,
        expected_projection_revision: Option<u64>,
        entry: &MediaLibraryPayload,
    ) -> Result<u64, PersistenceError> {
        if entry.projection_revision == 0 {
            return Err(PersistenceError::Conflict {
                detail: "media library projection revision must be at least 1".to_string(),
            });
        }
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = read_revision(&tx, &self.path)?;
        if actual != expected_revision {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "application store revision conflict: expected {expected_revision}, actual {actual}"
                ),
            });
        }
        let actual_projection: Option<u64> = tx
            .query_row(
                "SELECT projection_revision FROM app_media_library_entries WHERE entry_key = ?1",
                [&entry.entry_key],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| value as u64);
        if actual_projection != expected_projection_revision {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "media library projection revision conflict for {}: expected {:?}, actual {:?}",
                    entry.entry_key, expected_projection_revision, actual_projection
                ),
            });
        }
        let next = expected_revision
            .checked_add(1)
            .ok_or_else(|| PersistenceError::Conflict {
                detail: "application store revision exhausted u64 range".to_string(),
            })?;
        tx.execute(
            "INSERT INTO app_media_library_entries \
                 (entry_key, projection_revision, payload, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(entry_key) DO UPDATE SET \
                 projection_revision = excluded.projection_revision, \
                 payload = excluded.payload, \
                 updated_at = excluded.updated_at",
            rusqlite::params![
                &entry.entry_key,
                checked_i64(entry.projection_revision, "projection revision")?,
                &entry.payload,
                &entry.updated_at,
            ],
        )?;
        // The global revision advances inside the same transaction, so a
        // reader can never observe a new projection under an old revision.
        tx.execute(
            "UPDATE app_store_meta SET value = ?1 WHERE key = 'revision'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Read only the current revision without materializing payloads.
    pub fn revision(&self) -> Result<u64, PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        read_revision(&conn, &self.path)
    }

    /// Filesystem location of this store. The app uses the sibling transfer
    /// database during startup recovery to reconcile upload leases.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically claims every requested entry for one operation. Any
    /// conflicting row rolls the transaction back, so a batch can never hold
    /// only a subset of its leases.
    pub fn acquire_operation_leases(
        &self,
        operation_id: &str,
        entry_keys: &[String],
        kind: &str,
        acquired_at: &str,
    ) -> Result<Vec<OperationLeaseOutcome>, PersistenceError> {
        if operation_id.trim().is_empty() || kind.trim().is_empty() {
            return Err(PersistenceError::Conflict {
                detail: "operation lease requires non-empty id and kind".to_string(),
            });
        }
        if !matches!(kind, "delete" | "upload") {
            return Err(PersistenceError::Conflict {
                detail: format!("unsupported operation lease kind {kind:?}"),
            });
        }
        let keys = entry_keys
            .iter()
            .filter(|key| !key.trim().is_empty())
            .cloned()
            .collect::<BTreeSet<_>>();
        if keys.is_empty() {
            return Err(PersistenceError::Conflict {
                detail: "operation lease requires at least one entry".to_string(),
            });
        }

        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut outcomes = Vec::with_capacity(keys.len());
        for entry_key in keys {
            let existing = tx
                .query_row(
                    "SELECT operation_id, kind, acquired_at FROM app_operation_leases \
                     WHERE entry_key = ?1",
                    [&entry_key],
                    |row| {
                        Ok(OperationLease {
                            entry_key: entry_key.clone(),
                            operation_id: row.get(0)?,
                            kind: row.get(1)?,
                            acquired_at: row.get(2)?,
                        })
                    },
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing.operation_id == operation_id && existing.kind == kind {
                    outcomes.push(OperationLeaseOutcome::Acquired);
                    continue;
                }
                outcomes.push(OperationLeaseOutcome::Existing(existing));
                tx.rollback()?;
                return Ok(outcomes);
            }
            tx.execute(
                "INSERT INTO app_operation_leases \
                 (entry_key, operation_id, kind, acquired_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![entry_key, operation_id, kind, acquired_at],
            )?;
            outcomes.push(OperationLeaseOutcome::Acquired);
        }
        tx.commit()?;
        Ok(outcomes)
    }

    /// Releases leases only when owned by `operation_id`; a late cleanup from
    /// an old operation can therefore never release a newer owner's lease.
    pub fn release_operation_leases(&self, operation_id: &str) -> Result<u64, PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM app_operation_leases WHERE operation_id = ?1",
            [operation_id],
        )?;
        tx.commit()?;
        u64::try_from(removed).map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "negative lease deletion count".to_string(),
        })
    }

    pub fn list_operation_leases(&self) -> Result<Vec<OperationLease>, PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let mut statement = conn.prepare(
            "SELECT entry_key, operation_id, kind, acquired_at \
             FROM app_operation_leases ORDER BY entry_key",
        )?;
        let result = statement
            .query_map([], |row| {
                Ok(OperationLease {
                    entry_key: row.get(0)?,
                    operation_id: row.get(1)?,
                    kind: row.get(2)?,
                    acquired_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into);
        result
    }

    /// Persists staged delete intents after the corresponding rename(s).
    /// Replaying an identical intent is idempotent; changing its paths or
    /// expected revision is a conflict rather than a silent overwrite.
    pub fn record_library_delete_intents(
        &self,
        intents: &[LibraryDeleteIntent],
    ) -> Result<(), PersistenceError> {
        if intents.is_empty() {
            return Err(PersistenceError::Conflict {
                detail: "delete intent batch is empty".to_string(),
            });
        }
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for intent in intents {
            let existing = tx
                .query_row(
                    "SELECT source_path, trash_path, expected_revision, state, created_at \
                     FROM app_library_delete_intents \
                     WHERE operation_id = ?1 AND entry_key = ?2",
                    rusqlite::params![intent.operation_id, intent.entry_key],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((source, trash, expected, state, _created)) = existing {
                let expected = u64::try_from(expected).map_err(|_| {
                    PersistenceError::corrupt(
                        &self.path,
                        format!("delete intent revision {expected} is negative"),
                    )
                })?;
                if source != intent.source_path.to_string_lossy()
                    || trash != intent.trash_path.to_string_lossy()
                    || expected != intent.expected_revision
                    || state != intent.state.as_db_str()
                {
                    return Err(PersistenceError::Conflict {
                        detail: format!(
                            "delete intent {} / {} differs from durable intent",
                            intent.operation_id, intent.entry_key
                        ),
                    });
                }
                continue;
            }
            tx.execute(
                "INSERT INTO app_library_delete_intents \
                 (operation_id, entry_key, source_path, trash_path, expected_revision, state, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    intent.operation_id,
                    intent.entry_key,
                    intent.source_path.to_string_lossy().as_ref(),
                    intent.trash_path.to_string_lossy().as_ref(),
                    checked_i64(intent.expected_revision, "delete intent revision")?,
                    intent.state.as_db_str(),
                    intent.created_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_library_delete_intents(
        &self,
    ) -> Result<Vec<LibraryDeleteIntent>, PersistenceError> {
        let conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let mut statement = conn.prepare(
            "SELECT operation_id, entry_key, source_path, trash_path, expected_revision, state, created_at \
             FROM app_library_delete_intents ORDER BY created_at, operation_id, entry_key",
        )?;
        let rows = statement
            .query_map([], |row| {
                let state: String = row.get(5)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    state,
                    row.get::<_, String>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(operation_id, entry_key, source, trash, expected, state, created_at)| {
                    let state = LibraryDeleteIntentState::from_db_str(&state).ok_or_else(|| {
                        PersistenceError::corrupt(
                            &self.path,
                            format!("unknown delete intent state {state:?}"),
                        )
                    })?;
                    let expected_revision = u64::try_from(expected).map_err(|_| {
                        PersistenceError::corrupt(
                            &self.path,
                            format!("delete intent revision {expected} is negative"),
                        )
                    })?;
                    Ok(LibraryDeleteIntent {
                        operation_id,
                        entry_key,
                        source_path: PathBuf::from(source),
                        trash_path: PathBuf::from(trash),
                        expected_revision,
                        state,
                        created_at,
                    })
                },
            )
            .collect()
    }

    /// Commits the metadata half of a staged delete and marks all intents in
    /// the same SQLite transaction. This is the linearization point: after a
    /// successful return the old library rows are gone and recovery must
    /// finalize trash cleanup rather than roll the rename back.
    pub fn commit_library_delete_if_revision(
        &self,
        expected_revision: u64,
        operation_id: &str,
        entry_keys: &[String],
    ) -> Result<u64, PersistenceError> {
        let keys = entry_keys
            .iter()
            .filter(|key| !key.trim().is_empty())
            .cloned()
            .collect::<BTreeSet<_>>();
        if operation_id.trim().is_empty() || keys.is_empty() {
            return Err(PersistenceError::Conflict {
                detail: "delete commit requires operation id and entries".to_string(),
            });
        }
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = read_revision(&tx, &self.path)?;
        let mut already_committed = true;
        for entry_key in &keys {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM app_library_delete_intents \
                     WHERE operation_id = ?1 AND entry_key = ?2",
                    rusqlite::params![operation_id, entry_key],
                    |row| row.get(0),
                )
                .optional()?;
            match state.as_deref() {
                Some("staged") => already_committed = false,
                Some("committed") => {}
                Some(other) => {
                    return Err(PersistenceError::Corrupt {
                        path: self.path.clone(),
                        detail: format!("unknown delete intent state {other:?}"),
                    })
                }
                None => {
                    return Err(PersistenceError::Conflict {
                        detail: format!("delete intent {operation_id} / {entry_key} is not staged"),
                    })
                }
            }
        }
        if already_committed {
            return Ok(actual);
        }
        if actual != expected_revision {
            return Err(PersistenceError::Conflict {
                detail: format!(
                    "application store revision conflict: expected {expected_revision}, actual {actual}"
                ),
            });
        }
        let mut removed_rows = 0usize;
        for entry_key in &keys {
            removed_rows += tx.execute(
                "DELETE FROM app_library_entries WHERE entry_key = ?1",
                [entry_key],
            )?;
        }
        if removed_rows == 0 {
            // A retried delete may legitimately find that another completed
            // attempt already removed every named metadata row. Marking the
            // intent committed still lets recovery clean its trash, but a
            // no-op must not manufacture a new snapshot revision.
            tx.execute(
                "UPDATE app_library_delete_intents SET state = 'committed' \
                 WHERE operation_id = ?1 AND state = 'staged'",
                [operation_id],
            )?;
            tx.commit()?;
            return Ok(actual);
        }
        let next = expected_revision
            .checked_add(1)
            .ok_or_else(|| PersistenceError::Conflict {
                detail: "application store revision exhausted u64 range".to_string(),
            })?;
        tx.execute(
            "UPDATE app_store_meta SET value = ?1 WHERE key = 'revision'",
            [next.to_string()],
        )?;
        tx.execute(
            "UPDATE app_library_delete_intents SET state = 'committed' \
             WHERE operation_id = ?1 AND state = 'staged'",
            [operation_id],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Drops staged intents after a filesystem rollback. Committed intents
    /// are deliberately retained until trash cleanup has succeeded.
    pub fn abort_library_delete(&self, operation_id: &str) -> Result<(), PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM app_library_delete_intents WHERE operation_id = ?1 AND state = 'staged'",
            [operation_id],
        )?;
        tx.execute(
            "DELETE FROM app_operation_leases WHERE operation_id = ?1",
            [operation_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Removes committed intents and their leases after all trash directories
    /// have been durably cleaned. Calling this repeatedly is harmless.
    pub fn finalize_library_delete(&self, operation_id: &str) -> Result<(), PersistenceError> {
        let mut conn = self.conn.lock().map_err(|_| PersistenceError::Corrupt {
            path: self.path.clone(),
            detail: "application store connection lock was poisoned".to_string(),
        })?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM app_library_delete_intents WHERE operation_id = ?1 AND state = 'committed'",
            [operation_id],
        )?;
        tx.execute(
            "DELETE FROM app_operation_leases WHERE operation_id = ?1",
            [operation_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn replace_in_transaction(
        &self,
        tx: &rusqlite::Transaction<'_>,
        library: &[AppLibraryPayload],
        storage: &[u8],
        explicit_revision: Option<u64>,
    ) -> Result<(), PersistenceError> {
        tx.execute("DELETE FROM app_library_entries", [])?;
        for entry in library {
            tx.execute(
                "INSERT INTO app_library_entries (entry_key, payload) VALUES (?1, ?2)",
                rusqlite::params![&entry.entry_key, &entry.payload],
            )?;
        }
        tx.execute("DELETE FROM app_storage_config", [])?;
        tx.execute(
            "INSERT INTO app_storage_config (id, payload) VALUES (0, ?1)",
            [storage],
        )?;
        let next = match explicit_revision {
            Some(next) => next,
            None => read_revision(tx, &self.path)?
                .checked_add(1)
                .ok_or_else(|| PersistenceError::Conflict {
                    detail: "application store revision exhausted u64 range".to_string(),
                })?,
        };
        tx.execute(
            "UPDATE app_store_meta SET value = ?1 WHERE key = 'revision'",
            [next.to_string()],
        )?;
        Ok(())
    }
}

fn media_library_payload_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<MediaLibraryPayload> {
    Ok(MediaLibraryPayload {
        entry_key: row.get(0)?,
        projection_revision: row.get::<_, i64>(1)?.max(0) as u64,
        payload: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn read_revision(
    conn: &rusqlite::Connection,
    path: &std::path::Path,
) -> Result<u64, PersistenceError> {
    let revision_raw: String = conn.query_row(
        "SELECT value FROM app_store_meta WHERE key = 'revision'",
        [],
        |row| row.get(0),
    )?;
    revision_raw.parse::<u64>().map_err(|error| {
        PersistenceError::corrupt(
            path,
            format!("application store revision is invalid: {error}"),
        )
    })
}

fn checked_i64(value: u64, field: &str) -> Result<i64, PersistenceError> {
    i64::try_from(value).map_err(|_| PersistenceError::Conflict {
        detail: format!("{field} exceeds SQLite integer range"),
    })
}

fn run_migrations(conn: &mut Connection, path: &std::path::Path) -> Result<(), PersistenceError> {
    super::schema::run_migrations_for(conn, path, APP_STORE_IDENTITY, MIGRATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_library_rows_and_storage_round_trip_transactionally() {
        let dir = tempfile::tempdir().unwrap();
        let store = AppStore::open(dir.path().join("app.sqlite3")).unwrap();
        let library = vec![
            AppLibraryPayload {
                entry_key: "device-a|session-a".to_string(),
                payload: br#"{"session":"a"}"#.to_vec(),
            },
            AppLibraryPayload {
                entry_key: "device-b|session-b".to_string(),
                payload: br#"{"session":"b"}"#.to_vec(),
            },
        ];

        store.save(&library, br#"{"bucket":"real"}"#).unwrap();
        let snapshot = store.load().unwrap();

        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.library, library);
        assert_eq!(snapshot.storage, Some(br#"{"bucket":"real"}"#.to_vec()));
    }

    #[test]
    fn duplicate_entry_keys_reject_the_whole_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.sqlite3");
        let store = AppStore::open(&path).unwrap();
        let original = vec![AppLibraryPayload {
            entry_key: "device|original".to_string(),
            payload: b"original".to_vec(),
        }];
        store.save(&original, b"storage").unwrap();
        let duplicate = vec![
            AppLibraryPayload {
                entry_key: "device|duplicate".to_string(),
                payload: b"one".to_vec(),
            },
            AppLibraryPayload {
                entry_key: "device|duplicate".to_string(),
                payload: b"two".to_vec(),
            },
        ];

        assert!(store.save(&duplicate, b"changed").is_err());
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.library, original);
        assert_eq!(snapshot.storage, Some(b"storage".to_vec()));
    }

    #[test]
    fn stale_revision_cas_rejects_without_mutating_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = AppStore::open(dir.path().join("app.sqlite3")).unwrap();
        let original = vec![AppLibraryPayload {
            entry_key: "device|session".to_string(),
            payload: b"one".to_vec(),
        }];
        assert_eq!(store.save_if_revision(0, &original, b"storage").unwrap(), 1);

        let replacement = vec![AppLibraryPayload {
            entry_key: "device|session".to_string(),
            payload: b"two".to_vec(),
        }];
        assert_eq!(store.save_if_revision(1, &replacement, b"new").unwrap(), 2);

        let stale = store.save_if_revision(1, &original, b"stale");
        assert!(matches!(
            stale,
            Err(PersistenceError::Conflict { detail })
                if detail.contains("expected 1") && detail.contains("actual 2")
        ));
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.library, replacement);
        assert_eq!(snapshot.storage, Some(b"new".to_vec()));
    }

    #[test]
    fn per_entry_upsert_is_revision_scoped_and_isolates_unrelated_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = AppStore::open(dir.path().join("app.sqlite3")).unwrap();
        let original = vec![
            AppLibraryPayload {
                entry_key: "device|a".to_string(),
                payload: b"a-1".to_vec(),
            },
            AppLibraryPayload {
                entry_key: "device|b".to_string(),
                payload: b"b-1".to_vec(),
            },
        ];
        store.save(&original, b"storage").unwrap();

        let replacement = AppLibraryPayload {
            entry_key: "device|a".to_string(),
            payload: b"a-2".to_vec(),
        };
        assert_eq!(
            store
                .upsert_library_entry_if_revision(1, &replacement)
                .unwrap(),
            2
        );
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(
            snapshot.library,
            vec![replacement.clone(), original[1].clone(),],
            "a per-entry projection must not replace or drop unrelated rows"
        );
        assert_eq!(snapshot.storage, Some(b"storage".to_vec()));
        assert_eq!(
            store.read_library_entry("device|a").unwrap(),
            (2, Some(replacement.clone()))
        );
        assert_eq!(store.read_library_entry("missing").unwrap(), (2, None));

        let stale = AppLibraryPayload {
            entry_key: "device|b".to_string(),
            payload: b"stale".to_vec(),
        };
        let error = store
            .upsert_library_entry_if_revision(1, &stale)
            .expect_err("a stale per-entry writer must fail closed");
        assert!(matches!(
            error,
            PersistenceError::Conflict { detail }
                if detail.contains("expected 1") && detail.contains("actual 2")
        ));
        let after_conflict = store.load().unwrap();
        assert_eq!(after_conflict.revision, 2);
        assert_eq!(after_conflict.library, snapshot.library);
    }

    #[test]
    fn migration_identity_and_checksum_are_persisted_and_tamper_evident() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.sqlite3");
        let store = AppStore::open(&path).unwrap();
        drop(store);

        let conn = Connection::open(&path).unwrap();
        let identity: String = conn
            .query_row(
                "SELECT value FROM schema_store_meta WHERE key = 'identity'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(identity, APP_STORE_IDENTITY);
        let checksum: String = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(checksum.len(), 64);

        conn.execute(
            "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
            [],
        )
        .unwrap();
        let error = AppStore::open(&path).expect_err("tampered migration must fail closed");
        assert!(matches!(error, PersistenceError::Corrupt { .. }));
    }

    #[test]
    fn future_schema_version_is_rejected_before_open_mutates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.sqlite3");
        let store = AppStore::open(&path).unwrap();
        drop(store);
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES (99, 'future')",
            [],
        )
        .unwrap();
        let error = AppStore::open(&path).expect_err("future schema must fail closed");
        assert!(matches!(
            error,
            PersistenceError::UnsupportedSchemaVersion {
                found: 99,
                supported: 3,
                ..
            }
        ));
    }

    #[test]
    fn delete_leases_are_batch_atomic_and_idempotent_for_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let store = AppStore::open(dir.path().join("app.sqlite3")).unwrap();
        let keys = vec!["device|a".to_string(), "device|b".to_string()];
        assert!(store
            .acquire_operation_leases("delete-1", &keys, "delete", "now")
            .unwrap()
            .iter()
            .all(|outcome| matches!(outcome, OperationLeaseOutcome::Acquired)));
        assert!(matches!(
            store
                .acquire_operation_leases(
                    "delete-2",
                    std::slice::from_ref(&keys[0]),
                    "delete",
                    "later"
                )
                .unwrap()
                .as_slice(),
            [OperationLeaseOutcome::Existing(_)]
        ));
        assert_eq!(store.list_operation_leases().unwrap().len(), 2);
        assert_eq!(store.release_operation_leases("delete-1").unwrap(), 2);
        assert!(store.list_operation_leases().unwrap().is_empty());

        store
            .acquire_operation_leases(
                "delete-existing",
                &["device|z".to_string()],
                "delete",
                "now",
            )
            .unwrap();
        let conflict = store
            .acquire_operation_leases(
                "delete-batch",
                &["device|a".to_string(), "device|z".to_string()],
                "delete",
                "later",
            )
            .unwrap();
        assert!(matches!(
            conflict.as_slice(),
            [
                OperationLeaseOutcome::Acquired,
                OperationLeaseOutcome::Existing(_)
            ]
        ));
        let leases = store.list_operation_leases().unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].entry_key, "device|z");
    }

    #[test]
    fn operation_lease_write_surfaces_sqlite_busy_without_partial_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.sqlite3");
        let store = AppStore::open(&path).unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.busy_timeout(Duration::ZERO).unwrap();
        }
        let locker = Connection::open(&path).unwrap();
        locker.busy_timeout(Duration::ZERO).unwrap();
        locker.execute_batch("BEGIN IMMEDIATE").unwrap();

        let result = store.acquire_operation_leases(
            "delete-busy",
            &["device|busy".to_string()],
            "delete",
            "now",
        );
        assert!(matches!(result, Err(PersistenceError::Busy)));
        assert!(store.list_operation_leases().unwrap().is_empty());
    }

    #[test]
    fn delete_intent_cas_removes_only_named_rows_and_can_finalize_repeatedly() {
        let dir = tempfile::tempdir().unwrap();
        let store = AppStore::open(dir.path().join("app.sqlite3")).unwrap();
        let library = vec![
            AppLibraryPayload {
                entry_key: "device|a".to_string(),
                payload: b"a".to_vec(),
            },
            AppLibraryPayload {
                entry_key: "device|b".to_string(),
                payload: b"b".to_vec(),
            },
        ];
        store.save(&library, b"storage").unwrap();
        let key = "device|a".to_string();
        store
            .acquire_operation_leases("delete-1", std::slice::from_ref(&key), "delete", "now")
            .unwrap();
        store
            .record_library_delete_intents(&[LibraryDeleteIntent {
                operation_id: "delete-1".to_string(),
                entry_key: key.clone(),
                source_path: dir.path().join("library/device/a"),
                trash_path: dir
                    .path()
                    .join("library/.ylx-library-trash/delete-1/payload-0"),
                expected_revision: 1,
                state: LibraryDeleteIntentState::Staged,
                created_at: "now".to_string(),
            }])
            .unwrap();
        assert_eq!(
            store
                .commit_library_delete_if_revision(1, "delete-1", std::slice::from_ref(&key))
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .commit_library_delete_if_revision(1, "delete-1", std::slice::from_ref(&key))
                .unwrap(),
            2,
            "replaying a committed intent is idempotent even with the old expected revision"
        );
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.library.len(), 1);
        assert_eq!(snapshot.library[0].entry_key, "device|b");
        store.finalize_library_delete("delete-1").unwrap();
        store.finalize_library_delete("delete-1").unwrap();
        assert!(store.list_library_delete_intents().unwrap().is_empty());
    }
}
