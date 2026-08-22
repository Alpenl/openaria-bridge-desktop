use rusqlite::Transaction;

use super::error::MediaStoreError;
use super::store::{checked_i64, checked_u64};

#[derive(Debug, Clone, Copy)]
pub(crate) enum ProjectionResource {
    Imports,
    Derivations,
    Pipelines,
}

impl ProjectionResource {
    fn as_db_str(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::Derivations => "derivations",
            Self::Pipelines => "pipelines",
        }
    }
}

pub(crate) fn bump_projection_revision(
    tx: &Transaction<'_>,
    resource: ProjectionResource,
) -> Result<u64, MediaStoreError> {
    let changed = tx.execute(
        "UPDATE media_projection_revisions SET revision = revision + 1
         WHERE resource = ?1 AND revision < 9223372036854775807",
        [resource.as_db_str()],
    )?;
    if changed != 1 {
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "{} collection revision is missing or exhausted",
                resource.as_db_str()
            ),
        });
    }
    read_projection_revision(tx, resource)
}

pub(crate) fn read_projection_revision(
    conn: &rusqlite::Connection,
    resource: ProjectionResource,
) -> Result<u64, MediaStoreError> {
    let value: i64 = conn.query_row(
        "SELECT revision FROM media_projection_revisions WHERE resource = ?1",
        [resource.as_db_str()],
        |row| row.get(0),
    )?;
    checked_u64(value, "media_projection_revisions", resource.as_db_str())
}

#[allow(dead_code)]
pub(crate) fn set_projection_revision_for_test(
    tx: &Transaction<'_>,
    resource: ProjectionResource,
    revision: u64,
) -> Result<(), MediaStoreError> {
    tx.execute(
        "UPDATE media_projection_revisions SET revision = ?2 WHERE resource = ?1",
        rusqlite::params![resource.as_db_str(), checked_i64(revision, "revision")?],
    )?;
    Ok(())
}
