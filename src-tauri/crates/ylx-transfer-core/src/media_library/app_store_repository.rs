//! `AppStore`-backed [`LibraryProjectionRepository`].
//!
//! The projection is stored in its own table (`app_media_library_entries`), not
//! in the legacy `app_library_entries` row used by LAN publications. Keeping
//! them apart is the point: the legacy payload assumes signed publication
//! evidence, so writing an unsigned TF source through that decoder would either
//! drop provenance or manufacture a signature verdict.
//!
//! Every replacement is a double compare-and-swap — the global store revision
//! *and* the per-entry projection revision — inside one transaction, so two
//! projectors that read the same entry cannot silently overwrite each other.

use std::sync::Arc;

use crate::persistence::{AppStore, MediaLibraryPayload, PersistenceError};

use super::model::{LibraryEntryKey, MediaLibraryProjection};
use super::projection::{
    CompareAndSwapOutcome, ExpectedProjectionRevision, LibraryProjectionRepository,
    LoadedProjection, ProjectionStoreError,
};

/// Maximum serialized projection accepted from or written to the store. A
/// projection is a bounded set of identities and verdicts; anything larger is
/// corrupt rather than merely large.
pub const MAX_MEDIA_LIBRARY_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct AppStoreMediaLibraryProjectionRepository {
    store: Arc<AppStore>,
    now: Arc<dyn Fn() -> String + Send + Sync>,
}

impl std::fmt::Debug for AppStoreMediaLibraryProjectionRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppStoreMediaLibraryProjectionRepository")
            .finish_non_exhaustive()
    }
}

impl AppStoreMediaLibraryProjectionRepository {
    #[must_use]
    pub fn new(store: Arc<AppStore>, now: Arc<dyn Fn() -> String + Send + Sync>) -> Self {
        Self { store, now }
    }

    /// Every stored projection, for the boot snapshot and for rebuilding the
    /// complete media-library view after recovery.
    pub fn load_all(&self) -> Result<Vec<MediaLibraryProjection>, ProjectionStoreError> {
        let rows = self
            .store
            .read_media_library_entries()
            .map_err(map_persistence_error)?;
        rows.iter().map(decode_projection).collect()
    }

    /// Load the complete projection collection and the exact AppStore
    /// revision that guarded the same read transaction.
    pub fn load_all_with_revision(
        &self,
    ) -> Result<(u64, Vec<MediaLibraryProjection>), ProjectionStoreError> {
        let (revision, rows) = self
            .store
            .read_media_library_entries_with_revision()
            .map_err(map_persistence_error)?;
        let projections = rows
            .iter()
            .map(decode_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((revision, projections))
    }
}

impl LibraryProjectionRepository for AppStoreMediaLibraryProjectionRepository {
    fn load_projection(
        &self,
        entry_key: &LibraryEntryKey,
    ) -> Result<LoadedProjection, ProjectionStoreError> {
        let (store_revision, row) = self
            .store
            .read_media_library_entry(entry_key.as_str())
            .map_err(map_persistence_error)?;
        let projection = match row {
            Some(row) => {
                let projection = decode_projection(&row)?;
                // A payload whose embedded revision disagrees with its indexed
                // revision cannot be compare-and-swapped safely, because the
                // two would guard different things. Fail closed rather than
                // choosing one of them.
                if projection.projection_revision != row.projection_revision {
                    return Err(ProjectionStoreError::Corrupt {
                        detail: format!(
                            "media library entry {} has projection revision {} in its payload but \
                             {} in its index",
                            row.entry_key, projection.projection_revision, row.projection_revision
                        ),
                    });
                }
                Some(projection)
            }
            None => None,
        };
        Ok(LoadedProjection {
            store_revision,
            projection,
        })
    }

    fn compare_and_swap_projection(
        &mut self,
        entry_key: &LibraryEntryKey,
        expected: ExpectedProjectionRevision,
        replacement: &MediaLibraryProjection,
    ) -> Result<CompareAndSwapOutcome, ProjectionStoreError> {
        if &replacement.entry_key != entry_key {
            return Err(ProjectionStoreError::Unavailable {
                detail: "replacement projection is keyed to a different library entry".to_string(),
            });
        }
        let payload =
            serde_json::to_vec(replacement).map_err(|error| ProjectionStoreError::Unavailable {
                detail: format!("could not serialize the media library projection: {error}"),
            })?;
        if payload.len() > MAX_MEDIA_LIBRARY_PAYLOAD_BYTES {
            return Err(ProjectionStoreError::Unavailable {
                detail: format!(
                    "serialized media library projection exceeded {MAX_MEDIA_LIBRARY_PAYLOAD_BYTES} bytes"
                ),
            });
        }
        let entry = MediaLibraryPayload {
            entry_key: entry_key.as_str().to_string(),
            projection_revision: replacement.projection_revision,
            payload,
            updated_at: (self.now)(),
        };
        match self.store.replace_media_library_entry_if_revision(
            expected.store_revision,
            expected.projection_revision,
            &entry,
        ) {
            Ok(store_revision) => Ok(CompareAndSwapOutcome::Committed { store_revision }),
            Err(PersistenceError::Conflict { .. }) => {
                // Report the values that are actually current so the caller can
                // reload, recompute and retry deliberately instead of guessing.
                let (actual_store_revision, row) = self
                    .store
                    .read_media_library_entry(entry_key.as_str())
                    .map_err(map_persistence_error)?;
                Ok(CompareAndSwapOutcome::Conflict {
                    actual_store_revision,
                    actual_projection_revision: row.map(|row| row.projection_revision),
                })
            }
            Err(error) => Err(map_persistence_error(error)),
        }
    }
}

fn decode_projection(
    row: &MediaLibraryPayload,
) -> Result<MediaLibraryProjection, ProjectionStoreError> {
    if row.payload.len() > MAX_MEDIA_LIBRARY_PAYLOAD_BYTES {
        return Err(ProjectionStoreError::Corrupt {
            detail: format!(
                "media library entry {} exceeded {MAX_MEDIA_LIBRARY_PAYLOAD_BYTES} bytes",
                row.entry_key
            ),
        });
    }
    serde_json::from_slice(&row.payload).map_err(|error| ProjectionStoreError::Corrupt {
        detail: format!(
            "media library entry {} could not be decoded: {error}",
            row.entry_key
        ),
    })
}

fn map_persistence_error(error: PersistenceError) -> ProjectionStoreError {
    match error {
        PersistenceError::Busy => ProjectionStoreError::Busy,
        PersistenceError::Corrupt { detail, .. } => ProjectionStoreError::Corrupt { detail },
        other => ProjectionStoreError::Unavailable {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media_store::LibraryImportReceipt;

    fn repository() -> AppStoreMediaLibraryProjectionRepository {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = AppStore::open(dir.keep().join("app-state.sqlite3")).expect("open app store");
        AppStoreMediaLibraryProjectionRepository::new(
            Arc::new(store),
            Arc::new(|| "2026-08-05T00:00:00Z".to_string()),
        )
    }

    fn projection() -> MediaLibraryProjection {
        let receipt = LibraryImportReceipt {
            receipt_id: "receipt-1".to_string(),
            import_job_id: "job-1".to_string(),
            source_identity: "source-1".to_string(),
            source_revision: format!("sha256:{}", "a".repeat(64)),
            sealed_inventory_digest: "b".repeat(64),
            provenance: serde_json::json!({
                "kind": "locally_validated_unsigned",
                "evidence": {
                    "source_schema": "raw_capture_v2",
                    "validation_report": {"accepted": true, "checks": []},
                    "computed_inventory_digest": format!("sha256:{}", "b".repeat(64)),
                    "user_admission_receipt": null,
                },
            }),
            local_path: format!("sources/{}", "a".repeat(64)),
            commit_receipt: serde_json::json!({"receipt": "commit-1"}),
            committed_at: "2026-08-05T00:00:00Z".to_string(),
        };
        MediaLibraryProjection::from_import_receipt(&receipt).expect("projection")
    }

    #[test]
    fn a_missing_entry_loads_as_absent_at_the_current_store_revision() {
        let repository = repository();
        let projection = projection();
        let loaded = repository
            .load_projection(&projection.entry_key)
            .expect("load");
        assert!(loaded.projection.is_none());
        assert_eq!(loaded.store_revision, 0);
    }

    #[test]
    fn a_create_commits_and_round_trips() {
        let mut repository = repository();
        let projection = projection();
        let outcome = repository
            .compare_and_swap_projection(
                &projection.entry_key,
                ExpectedProjectionRevision {
                    store_revision: 0,
                    projection_revision: None,
                },
                &projection,
            )
            .expect("cas");
        assert!(matches!(
            outcome,
            CompareAndSwapOutcome::Committed { store_revision: 1 }
        ));
        let loaded = repository
            .load_projection(&projection.entry_key)
            .expect("load");
        assert_eq!(loaded.store_revision, 1);
        assert_eq!(loaded.projection.as_ref(), Some(&projection));
    }

    #[test]
    fn a_stale_projection_revision_conflicts_instead_of_overwriting() {
        let mut repository = repository();
        let projection = projection();
        repository
            .compare_and_swap_projection(
                &projection.entry_key,
                ExpectedProjectionRevision {
                    store_revision: 0,
                    projection_revision: None,
                },
                &projection,
            )
            .expect("first cas");
        let outcome = repository
            .compare_and_swap_projection(
                &projection.entry_key,
                ExpectedProjectionRevision {
                    store_revision: 1,
                    projection_revision: None,
                },
                &projection,
            )
            .expect("second cas");
        assert!(matches!(
            outcome,
            CompareAndSwapOutcome::Conflict {
                actual_store_revision: 1,
                actual_projection_revision: Some(1),
            }
        ));
    }
}
