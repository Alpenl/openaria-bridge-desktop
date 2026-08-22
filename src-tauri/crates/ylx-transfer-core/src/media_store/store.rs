use std::fs;
use std::path::PathBuf;

use rusqlite::Connection;

use super::error::MediaStoreError;
use super::schema;

/// Durable authority for import, normalization, pipeline and library-lease
/// records. Runtime state machines remain owned by `ingest` and
/// `normalization`; this module owns their atomic SQLite boundary.
#[derive(Debug)]
pub struct MediaStore {
    pub(crate) conn: Connection,
    pub(crate) path: PathBuf,
}

impl MediaStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, MediaStoreError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| MediaStoreError::io(parent, error))?;
        }

        let conn = Connection::open(&path)?;
        let mut store = Self { conn, path };
        store.check_integrity()?;
        store.conn.pragma_update(None, "journal_mode", "WAL")?;
        store.conn.pragma_update(None, "synchronous", "FULL")?;
        store.conn.pragma_update(None, "foreign_keys", "ON")?;

        let path = store.path.clone();
        schema::run_migrations(&mut store.conn, &path)?;
        Ok(store)
    }

    fn check_integrity(&self) -> Result<(), MediaStoreError> {
        let result = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0));
        match result {
            Ok(message) if message == "ok" => Ok(()),
            Ok(message) => Err(MediaStoreError::corrupt(&self.path, message)),
            Err(error) => Err(MediaStoreError::corrupt(&self.path, error.to_string())),
        }
    }

    pub fn schema_version(&self) -> Result<u32, MediaStoreError> {
        schema::read_schema_version(&self.conn)
    }

    /// Whether durable media workflow state has been written against the
    /// configured local-library root.
    ///
    /// This is intentionally stricter than an "active jobs" query. Import
    /// specs, checkpoints, terminal receipts, pipelines, derivations and
    /// revision leases all retain paths or identities whose meaning depends
    /// on the root that was current when they were created. Until there is a
    /// migration/cleanup operation that can rewrite or retire that evidence,
    /// any one of those rows permanently fences a runtime root switch.
    ///
    /// `media_generations` is excluded because it describes an observed
    /// removable source, not a local-library destination. Projection revision
    /// counters and schema metadata are also root-independent (and are
    /// populated even in a brand-new store).
    pub fn has_library_root_evidence(&self) -> Result<bool, MediaStoreError> {
        let present: i64 = self.conn.query_row(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM media_import_jobs
                UNION ALL SELECT 1 FROM media_import_specs
                UNION ALL SELECT 1 FROM media_import_files
                UNION ALL SELECT 1 FROM media_import_checkpoints
                UNION ALL SELECT 1 FROM media_import_locators
                UNION ALL SELECT 1 FROM media_import_outbox
                UNION ALL SELECT 1 FROM media_derivation_jobs
                UNION ALL SELECT 1 FROM media_derivation_specs
                UNION ALL SELECT 1 FROM media_derivation_segment_pairs
                UNION ALL SELECT 1 FROM media_derivation_outbox
                UNION ALL SELECT 1 FROM media_pipelines
                UNION ALL SELECT 1 FROM media_pipeline_dependencies
                UNION ALL SELECT 1 FROM media_source_receipts
                UNION ALL SELECT 1 FROM media_derived_receipts
                UNION ALL SELECT 1 FROM media_import_receipts
                UNION ALL SELECT 1 FROM media_library_lease_epochs
                UNION ALL SELECT 1 FROM media_library_revision_leases
                LIMIT 1
            )
            "#,
            [],
            |row| row.get(0),
        )?;
        match present {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(MediaStoreError::corrupt(
                &self.path,
                format!("library-root evidence query returned {value}"),
            )),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn owned_tables() -> &'static [&'static str] {
        &[
            "media_generations",
            "media_import_jobs",
            "media_import_specs",
            "media_import_files",
            "media_import_checkpoints",
            "media_import_locators",
            "media_import_outbox",
            "media_derivation_jobs",
            "media_derivation_specs",
            "media_derivation_segment_pairs",
            "media_derivation_outbox",
            "media_pipelines",
            "media_pipeline_dependencies",
            "media_source_receipts",
            "media_derived_receipts",
            "media_import_receipts",
            "media_library_lease_epochs",
            "media_library_revision_leases",
            "media_projection_revisions",
            // Producer trust is a property of the paired device, not of the
            // local library root, so it is owned here but deliberately absent
            // from `has_library_root_evidence`.
            "media_trusted_producer_keys",
            "media_trusted_producer_audit",
        ]
    }
}

pub(crate) fn checked_i64(value: u64, field: &str) -> Result<i64, MediaStoreError> {
    i64::try_from(value).map_err(|_| MediaStoreError::Conflict {
        detail: format!("{field} value {value} exceeds SQLite INTEGER range"),
    })
}

pub(crate) fn checked_u64(value: i64, table: &str, field: &str) -> Result<u64, MediaStoreError> {
    u64::try_from(value)
        .map_err(|_| MediaStoreError::corrupt(table, format!("{field} value {value} is negative")))
}

pub(crate) fn require_non_empty(value: &str, field: &str) -> Result<(), MediaStoreError> {
    if value.is_empty() {
        return Err(MediaStoreError::Conflict {
            detail: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

pub(crate) fn require_sha256(value: &str, field: &str) -> Result<(), MediaStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(MediaStoreError::Conflict {
        detail: format!("{field} must be a lowercase SHA-256 digest"),
    })
}
