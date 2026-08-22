use std::path::PathBuf;

/// Stable failures exposed by the durable media repository.
#[derive(Debug, thiserror::Error)]
pub enum MediaStoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("media store at {path} is corrupt: {detail}")]
    Corrupt { path: PathBuf, detail: String },

    #[error("media store SQLite error: {0}")]
    Sqlite(rusqlite::Error),

    #[error("media store serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("media store migration to version {version} failed: {detail}")]
    Migration { version: u32, detail: String },

    #[error(
        "media store at {path} is at schema version {found}, but this build supports only {supported}"
    )]
    UnsupportedSchemaVersion {
        path: PathBuf,
        found: u32,
        supported: u32,
    },

    #[error("media store conflict: {detail}")]
    Conflict { detail: String },

    #[error("media store record was not found: {detail}")]
    NotFound { detail: String },

    #[error("media store is busy")]
    Busy,
}

impl MediaStoreError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn corrupt(path: impl Into<PathBuf>, detail: impl Into<String>) -> Self {
        Self::Corrupt {
            path: path.into(),
            detail: detail.into(),
        }
    }
}

impl From<rusqlite::Error> for MediaStoreError {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                Self::Busy
            }
            other => Self::Sqlite(other),
        }
    }
}
