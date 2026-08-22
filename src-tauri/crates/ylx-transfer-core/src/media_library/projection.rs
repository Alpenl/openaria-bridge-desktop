use serde::{Deserialize, Serialize};

use crate::media_pipeline::{RemoteBundleReceipt, SourceRetentionPolicy};
use crate::media_store::{DerivedReceipt, LibraryImportReceipt};

use super::model::{
    CardPresence, DerivedLocalVerified, LibraryEntryKey, MediaLibraryProjection,
    ProjectionModelError, RemoteUploadState, UploadBundleProjection,
};
use super::retention::{
    evaluate_retention, RetentionBlockReason, RetentionEffectProposal, RetentionProjection,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedProjectionRevision {
    pub store_revision: u64,
    /// `None` means the projection must not exist. `Some` is the exact
    /// per-entry projection revision observed by the caller.
    pub projection_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoadedProjection {
    pub store_revision: u64,
    pub projection: Option<MediaLibraryProjection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareAndSwapOutcome {
    Committed {
        store_revision: u64,
    },
    Conflict {
        actual_store_revision: u64,
        actual_projection_revision: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionStoreError {
    #[error("projection store is busy")]
    Busy,
    #[error("projection store is unavailable: {detail}")]
    Unavailable { detail: String },
    #[error("projection store is corrupt: {detail}")]
    Corrupt { detail: String },
}

/// Persistence port for the rebuildable media-library view.
///
/// `store_revision` maps directly to the existing AppStore global revision;
/// `projection_revision` prevents an adapter from silently replacing a
/// different version of the same embedded projection. Both must participate
/// in the compare-and-swap.
pub trait LibraryProjectionRepository {
    fn load_projection(
        &self,
        entry_key: &LibraryEntryKey,
    ) -> Result<LoadedProjection, ProjectionStoreError>;

    fn compare_and_swap_projection(
        &mut self,
        entry_key: &LibraryEntryKey,
        expected: ExpectedProjectionRevision,
        replacement: &MediaLibraryProjection,
    ) -> Result<CompareAndSwapOutcome, ProjectionStoreError>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum LibraryProjectionCommand {
    /// Creates the projection from the long-lived immutable import receipt,
    /// or confirms an exact replay of the same receipt.
    RecordImport {
        receipt: LibraryImportReceipt,
    },
    RecordDerived {
        receipt: DerivedReceipt,
    },
    /// Projects only completion-bound remote verification evidence. The
    /// command carries the non-deserializable domain receipt itself, so a
    /// caller cannot promote a derived upload into a source archive by
    /// constructing projection fields.
    RecordRemoteBundleVerified {
        receipt: RemoteBundleReceipt,
        verified_at_ms: u64,
    },
    /// Projects an in-flight/failed bundle status. This path rejects a
    /// `Verified` payload; only the completion-bound command above can do so.
    ProjectUploadStatus {
        upload: UploadBundleProjection,
    },
    ObserveCard {
        presence: CardPresence,
    },
    SetRetentionPolicy {
        policy: SourceRetentionPolicy,
    },
    EvaluateRetention {
        /// Reconstructed completion-bound evidence. `RemoteBundleReceipt`
        /// intentionally cannot be deserialized directly from projection
        /// JSON; recovery must rebuild it from the frozen bundle and exact
        /// object completion receipts before retention can become eligible.
        verified_remote: Option<RemoteBundleReceipt>,
        now_ms: u64,
        proposal_id: String,
    },
}

impl LibraryProjectionCommand {
    pub fn entry_key_for_import(&self) -> Result<Option<LibraryEntryKey>, ProjectionModelError> {
        let Self::RecordImport { receipt } = self else {
            return Ok(None);
        };
        let projection = MediaLibraryProjection::from_import_receipt(receipt)?;
        Ok(Some(projection.entry_key))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectionCommit {
    Committed {
        store_revision: u64,
        projection: MediaLibraryProjection,
        retention_effect: Option<RetentionEffectProposal>,
    },
    AlreadyApplied {
        store_revision: u64,
        projection: MediaLibraryProjection,
        retention_effect: Option<RetentionEffectProposal>,
    },
}

impl ProjectionCommit {
    #[must_use]
    pub fn projection(&self) -> &MediaLibraryProjection {
        match self {
            Self::Committed { projection, .. } | Self::AlreadyApplied { projection, .. } => {
                projection
            }
        }
    }

    #[must_use]
    pub fn retention_effect(&self) -> Option<&RetentionEffectProposal> {
        match self {
            Self::Committed {
                retention_effect, ..
            }
            | Self::AlreadyApplied {
                retention_effect, ..
            } => retention_effect.as_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionError {
    #[error(transparent)]
    Model(#[from] ProjectionModelError),
    #[error(transparent)]
    Store(#[from] ProjectionStoreError),
    #[error("application store revision conflict: expected {expected}, actual {actual}")]
    StoreRevisionConflict { expected: u64, actual: u64 },
    #[error(
        "media-library projection revision conflict: expected {expected:?}, actual {actual:?}"
    )]
    ProjectionRevisionConflict {
        expected: Option<u64>,
        actual: Option<u64>,
    },
    #[error("media-library projection does not exist")]
    ProjectionNotFound,
    #[error("command entry key does not match the repository entry key")]
    EntryKeyMismatch,
    #[error("immutable {kind} evidence conflicts with the existing projection")]
    ImmutableEvidenceConflict { kind: &'static str },
    #[error("card observations with the same sequence contain different state")]
    CardObservationConflict,
}

pub struct LibraryProjector<R> {
    repository: R,
}

impl<R> LibraryProjector<R>
where
    R: LibraryProjectionRepository,
{
    #[must_use]
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    #[must_use]
    pub fn repository(&self) -> &R {
        &self.repository
    }

    #[must_use]
    pub fn repository_mut(&mut self) -> &mut R {
        &mut self.repository
    }

    #[must_use]
    pub fn into_repository(self) -> R {
        self.repository
    }

    /// Applies one event using the exact store/per-entry revisions observed
    /// by the caller. No conflict is retried with stale input inside this
    /// method; the application must reload, recompute, and deliberately CAS
    /// again.
    pub fn project(
        &mut self,
        entry_key: &LibraryEntryKey,
        expected: ExpectedProjectionRevision,
        command: LibraryProjectionCommand,
    ) -> Result<ProjectionCommit, ProjectionError> {
        let loaded = self.repository.load_projection(entry_key)?;
        if loaded.store_revision != expected.store_revision {
            return Err(ProjectionError::StoreRevisionConflict {
                expected: expected.store_revision,
                actual: loaded.store_revision,
            });
        }
        let actual_projection_revision = loaded
            .projection
            .as_ref()
            .map(|projection| projection.projection_revision);
        if actual_projection_revision != expected.projection_revision {
            return Err(ProjectionError::ProjectionRevisionConflict {
                expected: expected.projection_revision,
                actual: actual_projection_revision,
            });
        }
        if let Some(projection) = &loaded.projection {
            projection.validate()?;
            if &projection.entry_key != entry_key {
                return Err(ProjectionError::EntryKeyMismatch);
            }
        }

        let ApplyResult {
            mut projection,
            changed,
            created,
            retention_effect,
        } = apply(loaded.projection, command)?;
        if projection.entry_key != *entry_key {
            return Err(ProjectionError::EntryKeyMismatch);
        }
        if !changed {
            return Ok(ProjectionCommit::AlreadyApplied {
                store_revision: loaded.store_revision,
                projection,
                retention_effect,
            });
        }
        if !created {
            projection.advance_revision()?;
        }
        projection.validate()?;

        match self
            .repository
            .compare_and_swap_projection(entry_key, expected, &projection)?
        {
            CompareAndSwapOutcome::Committed { store_revision } => {
                Ok(ProjectionCommit::Committed {
                    store_revision,
                    projection,
                    retention_effect,
                })
            }
            CompareAndSwapOutcome::Conflict {
                actual_store_revision,
                actual_projection_revision: _,
            } if actual_store_revision != expected.store_revision => {
                Err(ProjectionError::StoreRevisionConflict {
                    expected: expected.store_revision,
                    actual: actual_store_revision,
                })
            }
            CompareAndSwapOutcome::Conflict {
                actual_projection_revision,
                ..
            } => Err(ProjectionError::ProjectionRevisionConflict {
                expected: expected.projection_revision,
                actual: actual_projection_revision,
            }),
        }
    }
}

struct ApplyResult {
    projection: MediaLibraryProjection,
    changed: bool,
    created: bool,
    retention_effect: Option<RetentionEffectProposal>,
}

fn apply(
    current: Option<MediaLibraryProjection>,
    command: LibraryProjectionCommand,
) -> Result<ApplyResult, ProjectionError> {
    match command {
        LibraryProjectionCommand::RecordImport { receipt } => {
            let candidate = MediaLibraryProjection::from_import_receipt(&receipt)?;
            let Some(current) = current else {
                return Ok(ApplyResult {
                    projection: candidate,
                    changed: true,
                    created: true,
                    retention_effect: None,
                });
            };
            if current.entry_key == candidate.entry_key
                && current.source_identity == candidate.source_identity
                && current.source_revision == candidate.source_revision
                && current.source_local == candidate.source_local
            {
                Ok(ApplyResult {
                    projection: current,
                    changed: false,
                    created: false,
                    retention_effect: None,
                })
            } else {
                Err(ProjectionError::ImmutableEvidenceConflict {
                    kind: "source import receipt",
                })
            }
        }
        LibraryProjectionCommand::RecordDerived { receipt } => {
            let mut projection = current.ok_or(ProjectionError::ProjectionNotFound)?;
            let derived = DerivedLocalVerified::from_receipt(&receipt)?;
            if derived.tree.source_revision() != &projection.source_revision {
                return Err(ProjectionError::Model(
                    ProjectionModelError::SourceRevisionMismatch,
                ));
            }
            let revision = derived.tree.derived_revision().clone();
            let changed = match projection.derived_local.get(&revision) {
                Some(existing) if existing == &derived => false,
                Some(_) => {
                    return Err(ProjectionError::ImmutableEvidenceConflict {
                        kind: "derived revision",
                    })
                }
                None => {
                    projection.derived_local.insert(revision, derived);
                    true
                }
            };
            Ok(ApplyResult {
                projection,
                changed,
                created: false,
                retention_effect: None,
            })
        }
        LibraryProjectionCommand::RecordRemoteBundleVerified {
            receipt,
            verified_at_ms,
        } => {
            let mut projection = current.ok_or(ProjectionError::ProjectionNotFound)?;
            let upload = UploadBundleProjection::verified_from_receipt(&receipt, verified_at_ms)?;
            upload.validate()?;
            if upload.source_revision != projection.source_revision {
                return Err(ProjectionError::Model(
                    ProjectionModelError::SourceRevisionMismatch,
                ));
            }
            let key = upload.bundle_revision.clone();
            let changed = match projection.upload_bundles.get(&key) {
                Some(existing) if existing == &upload => false,
                Some(existing)
                    if existing.source_revision == upload.source_revision
                        && existing.derived_revision == upload.derived_revision
                        && existing.storage_profile_identity == upload.storage_profile_identity
                        && !matches!(&existing.remote, RemoteUploadState::Verified { .. }) =>
                {
                    projection.upload_bundles.insert(key, upload.clone());
                    true
                }
                Some(_) => {
                    return Err(ProjectionError::ImmutableEvidenceConflict {
                        kind: "upload bundle",
                    })
                }
                None => {
                    projection.upload_bundles.insert(key, upload.clone());
                    true
                }
            };
            let archive_changed = projection.source_archive.record_upload(&upload)?;
            Ok(ApplyResult {
                projection,
                changed: changed || archive_changed,
                created: false,
                retention_effect: None,
            })
        }
        LibraryProjectionCommand::ProjectUploadStatus { upload } => {
            let mut projection = current.ok_or(ProjectionError::ProjectionNotFound)?;
            upload.validate()?;
            if matches!(&upload.remote, RemoteUploadState::Verified { .. }) {
                return Err(ProjectionError::ImmutableEvidenceConflict {
                    kind: "unbound remote verification",
                });
            }
            if upload.source_revision != projection.source_revision {
                return Err(ProjectionError::Model(
                    ProjectionModelError::SourceRevisionMismatch,
                ));
            }
            let key = upload.bundle_revision.clone();
            let changed = match projection.upload_bundles.get(&key) {
                Some(existing) if existing == &upload => false,
                Some(existing)
                    if existing.source_revision == upload.source_revision
                        && existing.derived_revision == upload.derived_revision
                        && existing.storage_profile_identity == upload.storage_profile_identity
                        && !matches!(&existing.remote, RemoteUploadState::Verified { .. }) =>
                {
                    projection.upload_bundles.insert(key, upload);
                    true
                }
                Some(_) => {
                    return Err(ProjectionError::ImmutableEvidenceConflict {
                        kind: "upload bundle",
                    })
                }
                None => {
                    projection.upload_bundles.insert(key, upload);
                    true
                }
            };
            Ok(ApplyResult {
                projection,
                changed,
                created: false,
                retention_effect: None,
            })
        }
        LibraryProjectionCommand::ObserveCard { presence } => {
            let mut projection = current.ok_or(ProjectionError::ProjectionNotFound)?;
            presence.validate()?;
            let incoming = presence.observation_sequence();
            let existing = projection.card_presence.observation_sequence();
            let changed = match (existing, incoming) {
                (_, None) => false,
                (Some(old), Some(new)) if new < old => false,
                (Some(old), Some(new)) if new == old => {
                    if projection.card_presence == presence {
                        false
                    } else {
                        return Err(ProjectionError::CardObservationConflict);
                    }
                }
                _ => {
                    projection.card_presence = presence;
                    true
                }
            };
            Ok(ApplyResult {
                projection,
                changed,
                created: false,
                retention_effect: None,
            })
        }
        LibraryProjectionCommand::SetRetentionPolicy { policy } => {
            let mut projection = current.ok_or(ProjectionError::ProjectionNotFound)?;
            if projection.retention_policy == policy {
                return Ok(ApplyResult {
                    projection,
                    changed: false,
                    created: false,
                    retention_effect: None,
                });
            }
            projection.retention_policy = policy;
            projection.retention = match &projection.retention_policy {
                SourceRetentionPolicy::Disabled => RetentionProjection::Disabled,
                SourceRetentionPolicy::AfterVerifiedSourceArchive { .. } => {
                    RetentionProjection::Blocked {
                        reason: RetentionBlockReason::SourceArchiveNotRemotelyVerified,
                        evaluated_at_ms: None,
                    }
                }
            };
            Ok(ApplyResult {
                projection,
                changed: true,
                created: false,
                retention_effect: None,
            })
        }
        LibraryProjectionCommand::EvaluateRetention {
            verified_remote,
            now_ms,
            proposal_id,
        } => {
            let mut projection = current.ok_or(ProjectionError::ProjectionNotFound)?;
            let evaluation = evaluate_retention(
                &projection.retention_policy,
                &projection.source_local,
                &projection.source_archive,
                verified_remote.as_ref(),
                now_ms,
                &proposal_id,
            );
            let changed = projection.retention != evaluation.projection;
            projection.retention = evaluation.projection;
            Ok(ApplyResult {
                projection,
                changed,
                created: false,
                retention_effect: evaluation.effect,
            })
        }
    }
}
