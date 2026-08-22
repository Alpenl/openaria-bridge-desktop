use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ingest::{InventoryDigest, SafeRelativePath, SourceContentRevision, SourceProvenance};
use crate::library::object_store_port::SourceSha256;
use crate::media_pipeline::{
    RemoteBundleReceipt, RemoteSourceArchive, SourceRetentionPolicy, StorageProfileIdentity,
    UploadBundleRevision,
};
use crate::media_store::{DerivedReceipt, LibraryImportReceipt};
use crate::normalization::{DerivedRevision, ProfileRevision, SourceManifestDigest};

use super::retention::RetentionProjection;

pub const MEDIA_LIBRARY_PROJECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionModelError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} is longer than {maximum} bytes")]
    TooLong { field: &'static str, maximum: usize },
    #[error("{field} contains control characters")]
    ControlCharacters { field: &'static str },
    #[error("{field} is not a valid {expected}: {detail}")]
    InvalidValue {
        field: &'static str,
        expected: &'static str,
        detail: String,
    },
    #[error("immutable {kind} tree path must be {expected:?}, got {actual:?}")]
    TreePathMismatch {
        kind: &'static str,
        expected: String,
        actual: String,
    },
    #[error("receipt source revision does not match the projected source")]
    SourceRevisionMismatch,
    #[error("immutable {kind} revision already has different evidence")]
    ImmutableEvidenceConflict { kind: &'static str },
    #[error("unsupported media-library projection schema version {found}")]
    UnsupportedSchema { found: u32 },
}

/// Stable database key for a source identity/revision pair.
///
/// Acquisition location is intentionally absent. LAN, removable media, and
/// a user-selected folder therefore converge on the same projection key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LibraryEntryKey(String);

impl LibraryEntryKey {
    pub fn for_source(
        source_identity: &str,
        source_revision: &SourceContentRevision,
    ) -> Result<Self, ProjectionModelError> {
        validate_text("source_identity", source_identity, 2_048)?;
        let mut hasher = Sha256::new();
        hasher.update(b"ylx-media-library-entry-v1\0");
        hasher.update(source_identity.as_bytes());
        hasher.update(b"\0");
        hasher.update(source_revision.as_str().as_bytes());
        Ok(Self(format!(
            "media-library-v1:{}",
            encode_hex(&hasher.finalize())
        )))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        let Some(digest) = self.0.strip_prefix("media-library-v1:") else {
            return Err(invalid(
                "library_entry_key",
                "media-library-v1:<64 lowercase hex>",
                &self.0,
            ));
        };
        validate_bare_sha256("library_entry_key", digest)
    }
}

/// Immutable locator for `library/sources/{source-revision}/...`.
///
/// The path uses the digest hex rather than the `sha256:` wire spelling so
/// it remains valid on Windows as well as macOS and Linux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceTreeLocator {
    source_revision: SourceContentRevision,
    relative_path: SafeRelativePath,
}

impl SourceTreeLocator {
    pub fn for_revision(
        source_revision: SourceContentRevision,
    ) -> Result<Self, ProjectionModelError> {
        let relative_path = safe_relative_path(
            "source_tree",
            format!("sources/{}", source_revision.digest_hex()),
        )?;
        Ok(Self {
            source_revision,
            relative_path,
        })
    }

    pub fn from_receipt(
        source_revision: SourceContentRevision,
        relative_path: SafeRelativePath,
    ) -> Result<Self, ProjectionModelError> {
        let locator = Self {
            source_revision,
            relative_path,
        };
        locator.validate()?;
        Ok(locator)
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn relative_path(&self) -> &SafeRelativePath {
        &self.relative_path
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        let expected = format!("sources/{}", self.source_revision.digest_hex());
        if self.relative_path.as_str() != expected {
            return Err(ProjectionModelError::TreePathMismatch {
                kind: "source",
                expected,
                actual: self.relative_path.as_str().to_string(),
            });
        }
        Ok(())
    }
}

/// Immutable locator for
/// `library/derivatives/{source}/{profile}/{derived}/...`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedTreeLocator {
    source_revision: SourceContentRevision,
    profile_revision: ProfileRevision,
    derived_revision: DerivedRevision,
    relative_path: SafeRelativePath,
}

impl DerivedTreeLocator {
    pub fn for_revisions(
        source_revision: SourceContentRevision,
        profile_revision: ProfileRevision,
        derived_revision: DerivedRevision,
    ) -> Result<Self, ProjectionModelError> {
        let relative_path = safe_relative_path(
            "derived_tree",
            format!(
                "derivatives/{}/{}/{}",
                source_revision.digest_hex(),
                digest_hex(profile_revision.as_str()),
                digest_hex(derived_revision.as_str())
            ),
        )?;
        Ok(Self {
            source_revision,
            profile_revision,
            derived_revision,
            relative_path,
        })
    }

    pub fn from_receipt(
        source_revision: SourceContentRevision,
        profile_revision: ProfileRevision,
        derived_revision: DerivedRevision,
        relative_path: SafeRelativePath,
    ) -> Result<Self, ProjectionModelError> {
        let locator = Self {
            source_revision,
            profile_revision,
            derived_revision,
            relative_path,
        };
        locator.validate()?;
        Ok(locator)
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn profile_revision(&self) -> &ProfileRevision {
        &self.profile_revision
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn relative_path(&self) -> &SafeRelativePath {
        &self.relative_path
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        let expected = format!(
            "derivatives/{}/{}/{}",
            self.source_revision.digest_hex(),
            digest_hex(self.profile_revision.as_str()),
            digest_hex(self.derived_revision.as_str())
        );
        if self.relative_path.as_str() != expected {
            return Err(ProjectionModelError::TreePathMismatch {
                kind: "derived",
                expected,
                actual: self.relative_path.as_str().to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "locator", rename_all = "snake_case")]
pub enum ImmutableTreeLocator {
    Source(SourceTreeLocator),
    Derived(DerivedTreeLocator),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceLocalVerified {
    pub import_receipt_id: String,
    pub import_job_id: String,
    pub tree: SourceTreeLocator,
    pub sealed_inventory_digest: InventoryDigest,
    pub provenance: SourceProvenance,
    pub commit_receipt: serde_json::Value,
    pub committed_at: String,
}

impl SourceLocalVerified {
    pub fn from_import_receipt(
        receipt: &LibraryImportReceipt,
    ) -> Result<Self, ProjectionModelError> {
        validate_text("receipt_id", &receipt.receipt_id, 256)?;
        validate_text("import_job_id", &receipt.import_job_id, 256)?;
        validate_text("source_identity", &receipt.source_identity, 2_048)?;
        validate_text("committed_at", &receipt.committed_at, 128)?;
        validate_commit_receipt(&receipt.commit_receipt)?;

        let source_revision = SourceContentRevision::parse(receipt.source_revision.clone())
            .map_err(|error| ProjectionModelError::InvalidValue {
                field: "source_revision",
                expected: "sha256:<64 lowercase hex>",
                detail: error.to_string(),
            })?;
        let sealed_inventory_digest = parse_inventory_digest(&receipt.sealed_inventory_digest)?;
        let provenance = serde_json::from_value::<SourceProvenance>(receipt.provenance.clone())
            .map_err(|error| ProjectionModelError::InvalidValue {
                field: "provenance",
                expected: "a tagged SourceProvenance value",
                detail: error.to_string(),
            })?;
        match &provenance {
            SourceProvenance::DeviceSigned(signed)
                if signed.publication_revision() != &source_revision =>
            {
                return Err(invalid(
                    "provenance",
                    "signed provenance for the exact source revision",
                    signed.publication_revision().as_str(),
                ));
            }
            SourceProvenance::LocallyValidatedUnsigned(unsigned)
                if unsigned.computed_inventory_digest() != Some(&sealed_inventory_digest) =>
            {
                return Err(invalid(
                    "provenance",
                    "unsigned provenance bound to the sealed inventory digest",
                    "missing or different computed inventory digest",
                ));
            }
            _ => {}
        }
        let relative_path = safe_relative_path("local_path", receipt.local_path.clone())?;
        let tree = SourceTreeLocator::from_receipt(source_revision, relative_path)?;

        Ok(Self {
            import_receipt_id: receipt.receipt_id.clone(),
            import_job_id: receipt.import_job_id.clone(),
            tree,
            sealed_inventory_digest,
            provenance,
            commit_receipt: receipt.commit_receipt.clone(),
            committed_at: receipt.committed_at.clone(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        validate_text("receipt_id", &self.import_receipt_id, 256)?;
        validate_text("import_job_id", &self.import_job_id, 256)?;
        validate_text("committed_at", &self.committed_at, 128)?;
        validate_commit_receipt(&self.commit_receipt)?;
        self.tree.validate()?;
        match &self.provenance {
            SourceProvenance::DeviceSigned(signed)
                if signed.publication_revision() != self.tree.source_revision() =>
            {
                Err(ProjectionModelError::SourceRevisionMismatch)
            }
            SourceProvenance::LocallyValidatedUnsigned(unsigned)
                if unsigned.computed_inventory_digest() != Some(&self.sealed_inventory_digest) =>
            {
                Err(invalid(
                    "provenance",
                    "unsigned provenance bound to the sealed inventory digest",
                    "missing or different computed inventory digest",
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
pub enum SourceLocalState {
    Verified(Box<SourceLocalVerified>),
    Removed {
        former_tree: SourceTreeLocator,
        policy_revision: String,
        removal_receipt: String,
        removed_at: String,
    },
}

impl SourceLocalState {
    #[must_use]
    pub fn verified(&self) -> Option<&SourceLocalVerified> {
        match self {
            Self::Verified(verified) => Some(verified),
            Self::Removed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivedLocalVerified {
    pub derivation_job_id: String,
    pub tree: DerivedTreeLocator,
    pub source_manifest_digest: SourceManifestDigest,
    pub commit_receipt: serde_json::Value,
    pub committed_at: String,
}

impl DerivedLocalVerified {
    pub fn from_receipt(receipt: &DerivedReceipt) -> Result<Self, ProjectionModelError> {
        validate_text("derivation_job_id", &receipt.derivation_job_id, 256)?;
        validate_text("committed_at", &receipt.committed_at, 128)?;
        validate_commit_receipt(&receipt.commit_receipt)?;
        let source_revision = parse_source_revision(&receipt.source_revision)?;
        let profile_revision = parse_profile_revision(&receipt.profile_revision)?;
        let derived_revision = parse_derived_revision(&receipt.derived_revision)?;
        let relative_path = safe_relative_path("local_path", receipt.local_path.clone())?;
        let tree = DerivedTreeLocator::from_receipt(
            source_revision,
            profile_revision,
            derived_revision,
            relative_path,
        )?;
        let source_manifest_digest = parse_manifest_digest(&receipt.source_manifest_digest)?;
        Ok(Self {
            derivation_job_id: receipt.derivation_job_id.clone(),
            tree,
            source_manifest_digest,
            commit_receipt: receipt.commit_receipt.clone(),
            committed_at: receipt.committed_at.clone(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        validate_text("derivation_job_id", &self.derivation_job_id, 256)?;
        validate_text("committed_at", &self.committed_at, 128)?;
        validate_commit_receipt(&self.commit_receipt)?;
        self.tree.validate()
    }
}

/// Explicit source coverage carried by a completion-bound remote receipt.
/// `NotIncluded` is not convertible to `Verified`; derived success therefore
/// cannot be displayed or consumed as an original/source backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProjectedSourceArchive {
    NotIncluded,
    Verified { policy_revision: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RemoteUploadState {
    NotVerified,
    Failed {
        code: String,
        retryable: bool,
    },
    Verified {
        remote_receipt_sha256: SourceSha256,
        verified_at_ms: u64,
        source_archive: ProjectedSourceArchive,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadBundleProjection {
    pub(crate) bundle_revision: UploadBundleRevision,
    pub(crate) storage_profile_identity: StorageProfileIdentity,
    pub(crate) source_revision: SourceContentRevision,
    pub(crate) derived_revision: DerivedRevision,
    pub(crate) remote: RemoteUploadState,
}

impl UploadBundleProjection {
    pub fn pending(
        bundle_revision: UploadBundleRevision,
        storage_profile_identity: StorageProfileIdentity,
        source_revision: SourceContentRevision,
        derived_revision: DerivedRevision,
    ) -> Self {
        Self {
            bundle_revision,
            storage_profile_identity,
            source_revision,
            derived_revision,
            remote: RemoteUploadState::NotVerified,
        }
    }

    pub fn failed(
        bundle_revision: UploadBundleRevision,
        storage_profile_identity: StorageProfileIdentity,
        source_revision: SourceContentRevision,
        derived_revision: DerivedRevision,
        code: String,
        retryable: bool,
    ) -> Result<Self, ProjectionModelError> {
        validate_text("upload_failure_code", &code, 128)?;
        Ok(Self {
            bundle_revision,
            storage_profile_identity,
            source_revision,
            derived_revision,
            remote: RemoteUploadState::Failed { code, retryable },
        })
    }

    pub fn verified_from_receipt(
        receipt: &RemoteBundleReceipt,
        verified_at_ms: u64,
    ) -> Result<Self, ProjectionModelError> {
        let remote_receipt_sha256 = remote_receipt_sha256(receipt)?;
        let source_archive = match receipt.source_archive() {
            RemoteSourceArchive::NotArchived => ProjectedSourceArchive::NotIncluded,
            RemoteSourceArchive::Verified { policy_revision } => {
                validate_text("archive_policy_revision", policy_revision, 256)?;
                ProjectedSourceArchive::Verified {
                    policy_revision: policy_revision.clone(),
                }
            }
        };
        Ok(Self {
            bundle_revision: receipt.natural_key().upload_bundle_revision.clone(),
            storage_profile_identity: receipt.natural_key().storage_profile_identity.clone(),
            source_revision: receipt.source_revision().clone(),
            derived_revision: receipt.derived_revision().clone(),
            remote: RemoteUploadState::Verified {
                remote_receipt_sha256,
                verified_at_ms,
                source_archive,
            },
        })
    }

    #[must_use]
    pub fn is_source_backup(&self) -> bool {
        matches!(
            &self.remote,
            RemoteUploadState::Verified {
                source_archive: ProjectedSourceArchive::Verified { .. },
                ..
            }
        )
    }

    #[must_use]
    pub fn bundle_revision(&self) -> &UploadBundleRevision {
        &self.bundle_revision
    }

    #[must_use]
    pub fn storage_profile_identity(&self) -> &StorageProfileIdentity {
        &self.storage_profile_identity
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn remote(&self) -> &RemoteUploadState {
        &self.remote
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        match &self.remote {
            RemoteUploadState::NotVerified => Ok(()),
            RemoteUploadState::Failed { code, .. } => {
                validate_text("upload_failure_code", code, 128)
            }
            RemoteUploadState::Verified {
                source_archive: ProjectedSourceArchive::Verified { policy_revision },
                ..
            } => validate_text("archive_policy_revision", policy_revision, 256),
            RemoteUploadState::Verified {
                source_archive: ProjectedSourceArchive::NotIncluded,
                ..
            } => Ok(()),
        }
    }
}

pub(crate) fn remote_receipt_sha256(
    receipt: &RemoteBundleReceipt,
) -> Result<SourceSha256, ProjectionModelError> {
    let serialized =
        serde_json::to_vec(receipt).map_err(|error| ProjectionModelError::InvalidValue {
            field: "remote_bundle_receipt",
            expected: "serializable completion-bound evidence",
            detail: error.to_string(),
        })?;
    Ok(SourceSha256::from_bytes(Sha256::digest(serialized).into()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceArchiveProof {
    pub policy_revision: String,
    pub bundle_revision: UploadBundleRevision,
    pub storage_profile_identity: StorageProfileIdentity,
    pub remote_receipt_sha256: SourceSha256,
    pub verified_at_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceArchiveProjection {
    verified_by_policy: BTreeMap<String, SourceArchiveProof>,
}

impl SourceArchiveProjection {
    #[must_use]
    pub fn verified_for_policy(&self, policy_revision: &str) -> Option<&SourceArchiveProof> {
        self.verified_by_policy.get(policy_revision)
    }

    pub fn proofs(&self) -> impl Iterator<Item = &SourceArchiveProof> {
        self.verified_by_policy.values()
    }

    pub(crate) fn validate(
        &self,
        uploads: &BTreeMap<UploadBundleRevision, UploadBundleProjection>,
    ) -> Result<(), ProjectionModelError> {
        for (policy, proof) in &self.verified_by_policy {
            validate_text("archive_policy_revision", policy, 256)?;
            if policy != &proof.policy_revision {
                return Err(ProjectionModelError::ImmutableEvidenceConflict {
                    kind: "source archive policy key",
                });
            }
            let Some(upload) = uploads.get(&proof.bundle_revision) else {
                return Err(ProjectionModelError::ImmutableEvidenceConflict {
                    kind: "source archive upload bundle",
                });
            };
            let RemoteUploadState::Verified {
                remote_receipt_sha256,
                verified_at_ms,
                source_archive: ProjectedSourceArchive::Verified { policy_revision },
                ..
            } = &upload.remote
            else {
                return Err(ProjectionModelError::ImmutableEvidenceConflict {
                    kind: "source archive remote verification",
                });
            };
            if policy_revision != policy
                || *remote_receipt_sha256 != proof.remote_receipt_sha256
                || upload.storage_profile_identity != proof.storage_profile_identity
                || *verified_at_ms != proof.verified_at_ms
            {
                return Err(ProjectionModelError::ImmutableEvidenceConflict {
                    kind: "source archive proof",
                });
            }
        }
        Ok(())
    }

    pub(crate) fn record_upload(
        &mut self,
        upload: &UploadBundleProjection,
    ) -> Result<bool, ProjectionModelError> {
        let RemoteUploadState::Verified {
            remote_receipt_sha256,
            verified_at_ms,
            source_archive: ProjectedSourceArchive::Verified { policy_revision },
        } = &upload.remote
        else {
            return Ok(false);
        };
        let proof = SourceArchiveProof {
            policy_revision: policy_revision.clone(),
            bundle_revision: upload.bundle_revision.clone(),
            storage_profile_identity: upload.storage_profile_identity.clone(),
            remote_receipt_sha256: *remote_receipt_sha256,
            verified_at_ms: *verified_at_ms,
        };
        match self.verified_by_policy.get(policy_revision) {
            Some(existing) if existing == &proof => Ok(false),
            Some(_) => Err(ProjectionModelError::ImmutableEvidenceConflict {
                kind: "source archive policy",
            }),
            None => {
                self.verified_by_policy
                    .insert(policy_revision.clone(), proof);
                Ok(true)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CardPresence {
    #[default]
    Unknown,
    Present {
        media_generation_id: String,
        observation_sequence: u64,
        observed_at_ms: u64,
    },
    Absent {
        last_media_generation_id: Option<String>,
        observation_sequence: u64,
        observed_at_ms: u64,
    },
}

impl CardPresence {
    #[must_use]
    pub fn observation_sequence(&self) -> Option<u64> {
        match self {
            Self::Unknown => None,
            Self::Present {
                observation_sequence,
                ..
            }
            | Self::Absent {
                observation_sequence,
                ..
            } => Some(*observation_sequence),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        match self {
            Self::Present {
                media_generation_id,
                ..
            } => validate_text("media_generation_id", media_generation_id, 256),
            Self::Absent {
                last_media_generation_id,
                ..
            } => {
                if let Some(generation) = last_media_generation_id {
                    validate_text("last_media_generation_id", generation, 256)?;
                }
                Ok(())
            }
            Self::Unknown => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaLibraryProjection {
    pub schema_version: u32,
    pub projection_revision: u64,
    pub entry_key: LibraryEntryKey,
    pub source_identity: String,
    pub source_revision: SourceContentRevision,
    pub source_local: SourceLocalState,
    pub derived_local: BTreeMap<DerivedRevision, DerivedLocalVerified>,
    pub upload_bundles: BTreeMap<UploadBundleRevision, UploadBundleProjection>,
    pub source_archive: SourceArchiveProjection,
    pub card_presence: CardPresence,
    pub retention_policy: SourceRetentionPolicy,
    pub retention: RetentionProjection,
}

impl MediaLibraryProjection {
    pub fn from_import_receipt(
        receipt: &LibraryImportReceipt,
    ) -> Result<Self, ProjectionModelError> {
        let source_local = SourceLocalVerified::from_import_receipt(receipt)?;
        let source_revision = source_local.tree.source_revision().clone();
        let entry_key = LibraryEntryKey::for_source(&receipt.source_identity, &source_revision)?;
        Ok(Self {
            schema_version: MEDIA_LIBRARY_PROJECTION_SCHEMA_VERSION,
            projection_revision: 1,
            entry_key,
            source_identity: receipt.source_identity.clone(),
            source_revision,
            source_local: SourceLocalState::Verified(Box::new(source_local)),
            derived_local: BTreeMap::new(),
            upload_bundles: BTreeMap::new(),
            source_archive: SourceArchiveProjection::default(),
            card_presence: CardPresence::default(),
            retention_policy: SourceRetentionPolicy::default(),
            retention: RetentionProjection::default(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ProjectionModelError> {
        if self.schema_version != MEDIA_LIBRARY_PROJECTION_SCHEMA_VERSION {
            return Err(ProjectionModelError::UnsupportedSchema {
                found: self.schema_version,
            });
        }
        if self.projection_revision == 0 {
            return Err(invalid(
                "projection_revision",
                "a positive projection revision",
                "0",
            ));
        }
        validate_text("source_identity", &self.source_identity, 2_048)?;
        self.entry_key.validate()?;
        if self.entry_key
            != LibraryEntryKey::for_source(&self.source_identity, &self.source_revision)?
        {
            return Err(invalid(
                "entry_key",
                "the hash of source identity and revision",
                self.entry_key.as_str(),
            ));
        }
        match &self.source_local {
            SourceLocalState::Verified(verified) => {
                verified.validate()?;
                if verified.tree.source_revision() != &self.source_revision {
                    return Err(ProjectionModelError::SourceRevisionMismatch);
                }
            }
            SourceLocalState::Removed {
                former_tree,
                policy_revision,
                removal_receipt,
                removed_at,
            } => {
                former_tree.validate()?;
                if former_tree.source_revision() != &self.source_revision {
                    return Err(ProjectionModelError::SourceRevisionMismatch);
                }
                validate_text("policy_revision", policy_revision, 256)?;
                validate_text("removal_receipt", removal_receipt, 512)?;
                validate_text("removed_at", removed_at, 128)?;
            }
        }
        for (revision, derived) in &self.derived_local {
            derived.validate()?;
            if revision != derived.tree.derived_revision()
                || derived.tree.source_revision() != &self.source_revision
            {
                return Err(ProjectionModelError::SourceRevisionMismatch);
            }
        }
        for (revision, upload) in &self.upload_bundles {
            if revision != &upload.bundle_revision || upload.source_revision != self.source_revision
            {
                return Err(ProjectionModelError::SourceRevisionMismatch);
            }
            upload.validate()?;
        }
        self.source_archive.validate(&self.upload_bundles)?;
        self.card_presence.validate()?;
        Ok(())
    }

    pub(crate) fn advance_revision(&mut self) -> Result<(), ProjectionModelError> {
        self.projection_revision = self.projection_revision.checked_add(1).ok_or_else(|| {
            invalid(
                "projection_revision",
                "a non-exhausted u64 revision",
                &self.projection_revision.to_string(),
            )
        })?;
        Ok(())
    }
}

pub(crate) fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProjectionModelError> {
    if value.trim().is_empty() {
        return Err(ProjectionModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ProjectionModelError::TooLong { field, maximum });
    }
    if value.chars().any(char::is_control) {
        return Err(ProjectionModelError::ControlCharacters { field });
    }
    Ok(())
}

fn safe_relative_path(
    field: &'static str,
    value: String,
) -> Result<SafeRelativePath, ProjectionModelError> {
    SafeRelativePath::parse(value).map_err(|error| ProjectionModelError::InvalidValue {
        field,
        expected: "a portable safe relative path",
        detail: error.to_string(),
    })
}

fn parse_source_revision(value: &str) -> Result<SourceContentRevision, ProjectionModelError> {
    SourceContentRevision::parse(value.to_string()).map_err(|error| {
        ProjectionModelError::InvalidValue {
            field: "source_revision",
            expected: "sha256:<64 lowercase hex>",
            detail: error.to_string(),
        }
    })
}

fn parse_profile_revision(value: &str) -> Result<ProfileRevision, ProjectionModelError> {
    ProfileRevision::parse(prefixed_sha256(value, "profile_revision")?).map_err(|error| {
        ProjectionModelError::InvalidValue {
            field: "profile_revision",
            expected: "sha256:<64 lowercase hex>",
            detail: error.to_string(),
        }
    })
}

fn parse_derived_revision(value: &str) -> Result<DerivedRevision, ProjectionModelError> {
    DerivedRevision::parse(prefixed_sha256(value, "derived_revision")?).map_err(|error| {
        ProjectionModelError::InvalidValue {
            field: "derived_revision",
            expected: "sha256:<64 lowercase hex>",
            detail: error.to_string(),
        }
    })
}

fn parse_manifest_digest(value: &str) -> Result<SourceManifestDigest, ProjectionModelError> {
    SourceManifestDigest::parse(prefixed_sha256(value, "manifest_digest")?).map_err(|error| {
        ProjectionModelError::InvalidValue {
            field: "manifest_digest",
            expected: "sha256:<64 lowercase hex>",
            detail: error.to_string(),
        }
    })
}

fn parse_inventory_digest(value: &str) -> Result<InventoryDigest, ProjectionModelError> {
    InventoryDigest::parse(prefixed_sha256(value, "inventory_digest")?).map_err(|error| {
        ProjectionModelError::InvalidValue {
            field: "inventory_digest",
            expected: "sha256:<64 lowercase hex>",
            detail: error.to_string(),
        }
    })
}

fn prefixed_sha256(value: &str, field: &'static str) -> Result<String, ProjectionModelError> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    validate_bare_sha256(field, digest)?;
    Ok(format!("sha256:{digest}"))
}

fn validate_bare_sha256(field: &'static str, value: &str) -> Result<(), ProjectionModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid(field, "64 lowercase hexadecimal characters", value))
    }
}

fn validate_commit_receipt(value: &serde_json::Value) -> Result<(), ProjectionModelError> {
    let populated = match value {
        serde_json::Value::String(value) => !value.trim().is_empty(),
        serde_json::Value::Object(value) => !value.is_empty(),
        _ => false,
    };
    if populated {
        Ok(())
    } else {
        Err(invalid(
            "commit_receipt",
            "a non-empty string or structured object",
            &value.to_string(),
        ))
    }
}

fn digest_hex(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

fn invalid(field: &'static str, expected: &'static str, actual: &str) -> ProjectionModelError {
    ProjectionModelError::InvalidValue {
        field,
        expected,
        detail: format!("got {actual:?}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
