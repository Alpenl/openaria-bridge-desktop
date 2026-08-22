//! Structured, typed persistence errors.
//!
//! W0-06 merge gate: the spike must not continue "扩展单一忽错 JSON store"
//! (silently swallowing persistence errors). Every fallible operation in
//! this module returns one of these variants instead of `.ok()` /
//! `let _ =` — see `state.rs` in the existing Tauri app for the pattern
//! this is explicitly *not* allowed to repeat.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// Any I/O failure (create_dir_all, open, write, rename, fsync, ...).
    /// Carries the path so a fault-test assertion (and a real crash report)
    /// can identify exactly which file/dir failed.
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The on-disk store exists but its contents are not a valid store:
    /// truncated JSON, garbage bytes, a JSON document that doesn't match
    /// the expected schema, or a SQLite file that fails
    /// `PRAGMA integrity_check`. This is deliberately distinct from `Io` so
    /// callers (and tests) can assert "we detected corruption" instead of
    /// "some I/O call failed".
    #[error("store at {path} is corrupt: {detail}")]
    Corrupt { path: PathBuf, detail: String },

    /// JSON (de)serialization failure that is *not* a corrupt-file read —
    /// e.g. failing to serialize an in-memory snapshot before a write.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Any SQLite-layer error that isn't better classified as `Corrupt`
    /// (e.g. constraint violation, busy/locked database after the retry
    /// budget is exhausted).
    #[error("sqlite error: {0}")]
    Sqlite(rusqlite::Error),

    /// A schema migration did not apply cleanly. Carries the target
    /// version so operators can tell which migration to inspect.
    #[error("migration to schema version {version} failed: {detail}")]
    Migration { version: u32, detail: String },

    /// The store is locked by another writer/reader for longer than the
    /// caller's budget. Distinct from `Sqlite` so callers can special-case
    /// "retry later" without string-matching an error message.
    #[error("store is busy (locked by another connection)")]
    Busy,

    /// SPIKE-PC-JOURNAL: a write was rejected because it would violate a
    /// domain-level invariant the caller should have checked first —
    /// duplicate idempotency key on job insert, or an illegal job-state
    /// transition edge (`schema::is_valid_transition`). Distinct from
    /// `Sqlite` (a raw constraint-violation message) and from `Corrupt`
    /// (on-disk data cannot be trusted) so callers/tests can assert "this
    /// was a rejected-by-design conflict" precisely.
    #[error("conflict: {detail}")]
    Conflict { detail: String },

    /// Commit 22: the file on disk was written by a **newer** build than
    /// this one — its `schema_migrations` high-water mark is above the
    /// highest migration this binary knows. Opening it anyway would let an
    /// old binary write rows that violate constraints it cannot see, so
    /// the store is not opened at all and this diagnostic is returned
    /// instead. Distinct from [`PersistenceError::Migration`] (a migration
    /// that *ran* and failed) and from `Corrupt` (bytes we cannot trust).
    #[error(
        "store at {path} is at schema version {found}, but this build only understands up to \
         {supported}; refusing to open it with an older binary"
    )]
    UnsupportedSchemaVersion {
        path: PathBuf,
        found: u32,
        supported: u32,
    },

    /// SPIKE-PC-JOURNAL: the caller referenced a row (e.g. a `job_id`)
    /// that does not exist. Distinct from `Sqlite`'s
    /// `QueryReturnedNoRows` (a raw driver-level signal) so callers can
    /// match on a stable, typed variant instead of a query-shape detail.
    #[error("not found: {detail}")]
    NotFound { detail: String },
}

impl From<rusqlite::Error> for PersistenceError {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                PersistenceError::Busy
            }
            other => PersistenceError::Sqlite(other),
        }
    }
}

impl PersistenceError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        PersistenceError::Io {
            path: path.into(),
            source,
        }
    }

    pub fn corrupt(path: impl Into<PathBuf>, detail: impl Into<String>) -> Self {
        PersistenceError::Corrupt {
            path: path.into(),
            detail: detail.into(),
        }
    }

    /// True for variants that represent "the data on disk cannot be
    /// trusted", as opposed to a transient I/O or lock condition.
    pub fn is_corrupt(&self) -> bool {
        matches!(self, PersistenceError::Corrupt { .. })
    }
}
