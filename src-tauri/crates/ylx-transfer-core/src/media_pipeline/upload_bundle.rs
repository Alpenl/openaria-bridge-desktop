use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::ingest::{InventoryDigest, SourceContentRevision, SourceProvenance, SourceSchema};
use crate::library::object_store_port::{
    CompletedUpload, ObjectKey, SourceSha256, VerifiedObjectReceipt,
};
use crate::normalization::{DerivedRevision, ProfileRevision};

use super::{
    PreFreezeUploadRequestDigest, UnsignedUploadAdmissionReceipt, UnsignedUploadAdmissionRequest,
};

const UPLOAD_BUNDLE_SCHEMA_VERSION: u32 = 2;
const MAX_RAW_SEGMENT_BYTES: usize = 512;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;

/// Revision of the complete automatic derived-upload approval semantics.
/// Changing any policy meaning that is not already an explicit request field
/// requires this value to change, invalidating earlier receipts.
pub const DERIVED_UPLOAD_POLICY_REVISION: &str = "ylx.derived-upload-policy.v1";

/// Stable identity of an object-store destination configuration.
///
/// The value identifies endpoint, bucket, addressing mode, and any other
/// request semantics, but never contains credentials. A display name is not
/// a storage profile identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StorageProfileIdentity(String);

impl StorageProfileIdentity {
    pub fn parse(value: impl Into<String>) -> Result<Self, UploadBundleError> {
        let value = value.into();
        validate_opaque_value("storage_profile_identity", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StorageProfileIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// SHA-256 identity of an immutable, ordered upload bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct UploadBundleRevision(String);

impl UploadBundleRevision {
    pub fn parse(value: impl Into<String>) -> Result<Self, UploadBundleError> {
        let value = value.into();
        let valid = value.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if !valid {
            return Err(UploadBundleError::InvalidBundleRevision);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for UploadBundleRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Idempotency key for a durable upload job.
///
/// A bundle sent to two destination profiles is two different upload jobs,
/// even when every local byte and object key is identical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UploadJobNaturalKey {
    pub upload_bundle_revision: UploadBundleRevision,
    pub storage_profile_identity: StorageProfileIdentity,
}

/// Object-key prefix expressed as opaque, untrusted segments.
///
/// Callers do not pass a slash-delimited prefix. Each raw segment is encoded
/// independently, so a device, session, or configured prefix cannot inject an
/// extra object namespace level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectNamespace {
    raw_segments: Vec<String>,
}

impl ObjectNamespace {
    pub fn from_raw_segments<I, S>(segments: I) -> Result<Self, UploadBundleError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let raw_segments = segments
            .into_iter()
            .map(|segment| {
                let segment = segment.as_ref().to_string();
                encode_opaque_segment(&segment)?;
                Ok(segment)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if raw_segments.is_empty() {
            return Err(UploadBundleError::EmptyField("object_namespace"));
        }
        Ok(Self { raw_segments })
    }

    fn extend_key<I, S>(&self, segments: I) -> Result<ObjectKey, UploadBundleError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut encoded = self
            .raw_segments
            .iter()
            .map(|segment| encode_opaque_segment(segment))
            .collect::<Result<Vec<_>, _>>()?;
        for segment in segments {
            encoded.push(encode_opaque_segment(segment.as_ref())?);
        }
        let key = encoded.join("/");
        if key.len() > MAX_OBJECT_KEY_BYTES {
            return Err(UploadBundleError::ObjectKeyTooLong { actual: key.len() });
        }
        Ok(ObjectKey(key))
    }

    fn validate(&self) -> Result<(), UploadBundleError> {
        if self.raw_segments.is_empty() {
            return Err(UploadBundleError::EmptyField("object_namespace"));
        }
        for segment in &self.raw_segments {
            encode_opaque_segment(segment)?;
        }
        Ok(())
    }
}

/// Logical local artifact reference. It is intentionally not a filesystem
/// path; the local library resolves it while holding the appropriate revision
/// lease.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct LocalArtifactRef(String);

impl LocalArtifactRef {
    pub fn parse(value: impl Into<String>) -> Result<Self, UploadBundleError> {
        let value = value.into();
        validate_opaque_value("local_artifact_ref", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LocalArtifactRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// The semantic role of an object. Roles are explicit and are never inferred
/// from a key suffix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UploadObjectRole {
    DerivedMedia { opaque_file_id: String },
    DerivedMetadata { opaque_file_id: String },
    DerivedManifest,
    SourceManifest,
    SourceMetadata { opaque_file_id: String },
    ProvenanceReport,
    SourceVideoArchive { opaque_file_id: String },
}

impl UploadObjectRole {
    fn opaque_file_id(&self) -> Option<&str> {
        match self {
            Self::DerivedMedia { opaque_file_id }
            | Self::DerivedMetadata { opaque_file_id }
            | Self::SourceMetadata { opaque_file_id }
            | Self::SourceVideoArchive { opaque_file_id } => Some(opaque_file_id),
            Self::DerivedManifest | Self::SourceManifest | Self::ProvenanceReport => None,
        }
    }

    fn tag(&self) -> &'static str {
        match self {
            Self::DerivedMedia { .. } => "derived_media",
            Self::DerivedMetadata { .. } => "derived_metadata",
            Self::DerivedManifest => "derived_manifest",
            Self::SourceManifest => "source_manifest",
            Self::SourceMetadata { .. } => "source_metadata",
            Self::ProvenanceReport => "provenance_report",
            Self::SourceVideoArchive { .. } => "source_video_archive",
        }
    }
}

/// One object before its destination key is derived and the bundle is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadObjectInput {
    pub role: UploadObjectRole,
    pub local_artifact: LocalArtifactRef,
    pub size_bytes: u64,
    pub sha256: SourceSha256,
    pub media_type: String,
}

impl UploadObjectInput {
    pub fn new(
        role: UploadObjectRole,
        local_artifact: LocalArtifactRef,
        size_bytes: u64,
        sha256: SourceSha256,
        media_type: impl Into<String>,
    ) -> Result<Self, UploadBundleError> {
        if size_bytes == 0 {
            return Err(UploadBundleError::ZeroLengthObject);
        }
        let media_type = media_type.into();
        validate_opaque_value("media_type", &media_type)?;
        if let Some(file_id) = role.opaque_file_id() {
            validate_opaque_value("opaque_file_id", file_id)?;
        }
        Ok(Self {
            role,
            local_artifact,
            size_bytes,
            sha256,
            media_type,
        })
    }
}

/// Source video archival is separate from uploading a derivative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SourceArchivalPolicy {
    #[default]
    Disabled,
    Enabled {
        policy_revision: String,
        /// Exact source video inventory that must be present in this bundle
        /// before it can later be described as a verified source backup.
        expected_source_video_ids: BTreeSet<String>,
    },
}

/// Automatic local source deletion is off unless a separately versioned
/// policy explicitly opts in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SourceRetentionPolicy {
    #[default]
    Disabled,
    AfterVerifiedSourceArchive {
        archive_policy_revision: String,
        grace_period_seconds: u64,
    },
}

/// Complete input needed to freeze an upload bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadBundleInput {
    pub namespace: ObjectNamespace,
    pub origin_identity: String,
    pub session_or_source_id: String,
    pub source_revision: SourceContentRevision,
    pub source_provenance: SourceProvenance,
    pub source_inventory_digest: InventoryDigest,
    pub unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
    pub profile_revision: ProfileRevision,
    pub derived_revision: DerivedRevision,
    pub storage_profile_identity: StorageProfileIdentity,
    pub source_archival: SourceArchivalPolicy,
    pub upload_policy_revision: String,
    pub objects: Vec<UploadObjectInput>,
}

impl UploadBundleInput {
    /// Builds the exact approval request without freezing or accepting an
    /// admission receipt. The digest covers the final ordered object list and
    /// derived object keys, so the same receipt cannot authorize changed
    /// outputs or a changed destination.
    pub fn unsigned_upload_admission_request(
        &self,
    ) -> Result<UnsignedUploadAdmissionRequest, UploadBundleError> {
        let prepared = prepare_upload_bundle(self)?;
        self.admission_request_for_prepared(&prepared)
    }

    fn admission_request_for_prepared(
        &self,
        prepared: &PreparedUploadBundle,
    ) -> Result<UnsignedUploadAdmissionRequest, UploadBundleError> {
        UnsignedUploadAdmissionRequest::new(
            self.source_revision.clone(),
            self.source_inventory_digest.clone(),
            self.derived_revision.clone(),
            compute_pre_freeze_request_digest(self, prepared),
            self.storage_profile_identity.clone(),
            self.source_archival.clone(),
            self.upload_policy_revision.clone(),
        )
        .map_err(|error| UploadBundleError::InvalidAdmissionRequest(error.to_string()))
    }
}

struct PreparedUploadBundle {
    provenance_digest: SourceSha256,
    objects: Vec<FrozenUploadObject>,
}

/// One immutable object in a frozen upload bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenUploadObject {
    role: UploadObjectRole,
    local_artifact: LocalArtifactRef,
    object_key: ObjectKey,
    size_bytes: u64,
    sha256: SourceSha256,
    media_type: String,
}

impl FrozenUploadObject {
    #[must_use]
    pub fn role(&self) -> &UploadObjectRole {
        &self.role
    }

    #[must_use]
    pub fn local_artifact(&self) -> &LocalArtifactRef {
        &self.local_artifact
    }

    #[must_use]
    pub fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> SourceSha256 {
        self.sha256
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// Immutable upload plan. The final derived manifest is always the final
/// element of `objects`, so executors cannot accidentally publish the
/// authoritative entry point before its data objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenUploadBundle {
    schema_version: u32,
    revision: UploadBundleRevision,
    namespace: ObjectNamespace,
    origin_identity: String,
    session_or_source_id: String,
    source_revision: SourceContentRevision,
    source_provenance: SourceProvenance,
    source_inventory_digest: InventoryDigest,
    unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
    provenance_digest: SourceSha256,
    profile_revision: ProfileRevision,
    derived_revision: DerivedRevision,
    storage_profile_identity: StorageProfileIdentity,
    source_archival: SourceArchivalPolicy,
    upload_policy_revision: String,
    upload_request_digest: PreFreezeUploadRequestDigest,
    objects: Vec<FrozenUploadObject>,
}

impl FrozenUploadBundle {
    pub fn freeze(input: UploadBundleInput) -> Result<Self, UploadBundleError> {
        let prepared = prepare_upload_bundle(&input)?;
        let upload_request_digest = compute_pre_freeze_request_digest(&input, &prepared);
        let admission_request = if matches!(
            input.source_provenance,
            SourceProvenance::LocallyValidatedUnsigned(_)
        ) {
            Some(input.admission_request_for_prepared(&prepared)?)
        } else {
            None
        };
        validate_upload_admission(
            &input.source_provenance,
            input.unsigned_admission.as_ref(),
            admission_request.as_ref(),
        )?;
        let revision =
            compute_bundle_revision(&upload_request_digest, input.unsigned_admission.as_ref());

        Ok(Self {
            schema_version: UPLOAD_BUNDLE_SCHEMA_VERSION,
            revision,
            namespace: input.namespace,
            origin_identity: input.origin_identity,
            session_or_source_id: input.session_or_source_id,
            source_revision: input.source_revision,
            source_provenance: input.source_provenance,
            source_inventory_digest: input.source_inventory_digest,
            unsigned_admission: input.unsigned_admission,
            provenance_digest: prepared.provenance_digest,
            profile_revision: input.profile_revision,
            derived_revision: input.derived_revision,
            storage_profile_identity: input.storage_profile_identity,
            source_archival: input.source_archival,
            upload_policy_revision: input.upload_policy_revision,
            upload_request_digest,
            objects: prepared.objects,
        })
    }

    #[must_use]
    pub fn revision(&self) -> &UploadBundleRevision {
        &self.revision
    }

    #[must_use]
    pub fn namespace(&self) -> &ObjectNamespace {
        &self.namespace
    }

    #[must_use]
    pub fn origin_identity(&self) -> &str {
        &self.origin_identity
    }

    #[must_use]
    pub fn session_or_source_id(&self) -> &str {
        &self.session_or_source_id
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn source_provenance(&self) -> &SourceProvenance {
        &self.source_provenance
    }

    #[must_use]
    pub fn source_inventory_digest(&self) -> &InventoryDigest {
        &self.source_inventory_digest
    }

    #[must_use]
    pub fn unsigned_admission(&self) -> Option<&UnsignedUploadAdmissionReceipt> {
        self.unsigned_admission.as_ref()
    }

    #[must_use]
    pub fn provenance_digest(&self) -> SourceSha256 {
        self.provenance_digest
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
    pub fn storage_profile_identity(&self) -> &StorageProfileIdentity {
        &self.storage_profile_identity
    }

    #[must_use]
    pub fn source_archival(&self) -> &SourceArchivalPolicy {
        &self.source_archival
    }

    #[must_use]
    pub fn upload_policy_revision(&self) -> &str {
        &self.upload_policy_revision
    }

    #[must_use]
    pub fn upload_request_digest(&self) -> &PreFreezeUploadRequestDigest {
        &self.upload_request_digest
    }

    pub fn unsigned_upload_admission_request(
        &self,
    ) -> Result<UnsignedUploadAdmissionRequest, UploadBundleError> {
        UnsignedUploadAdmissionRequest::new(
            self.source_revision.clone(),
            self.source_inventory_digest.clone(),
            self.derived_revision.clone(),
            self.upload_request_digest.clone(),
            self.storage_profile_identity.clone(),
            self.source_archival.clone(),
            self.upload_policy_revision.clone(),
        )
        .map_err(|error| UploadBundleError::InvalidAdmissionRequest(error.to_string()))
    }

    #[must_use]
    pub fn objects(&self) -> &[FrozenUploadObject] {
        &self.objects
    }

    #[must_use]
    pub fn natural_key(&self) -> UploadJobNaturalKey {
        UploadJobNaturalKey {
            upload_bundle_revision: self.revision.clone(),
            storage_profile_identity: self.storage_profile_identity.clone(),
        }
    }

    /// Accepts only per-object receipts already produced by the existing
    /// object-store verification port. A completion response, ETag, or upload
    /// progress snapshot cannot satisfy this gate.
    pub fn verify_remote(
        &self,
        storage_profile_identity: StorageProfileIdentity,
        receipts: Vec<CompletionBoundObjectReceipt>,
    ) -> Result<RemoteBundleReceipt, RemoteVerificationError> {
        if storage_profile_identity != self.storage_profile_identity {
            return Err(RemoteVerificationError::StorageProfileMismatch {
                expected: self.storage_profile_identity.clone(),
                actual: storage_profile_identity,
            });
        }
        let mut by_key = BTreeMap::new();
        for receipt in receipts {
            let key = receipt.verified.key.0.clone();
            if by_key.insert(key.clone(), receipt).is_some() {
                return Err(RemoteVerificationError::DuplicateReceipt(ObjectKey(key)));
            }
        }

        let mut ordered_receipts = Vec::with_capacity(self.objects.len());
        for object in &self.objects {
            let receipt = by_key.remove(&object.object_key.0).ok_or_else(|| {
                RemoteVerificationError::MissingReceipt(object.object_key.clone())
            })?;
            if receipt.verified.size_bytes != object.size_bytes {
                return Err(RemoteVerificationError::SizeMismatch {
                    key: object.object_key.clone(),
                    expected: object.size_bytes,
                    actual: receipt.verified.size_bytes,
                });
            }
            if receipt.verified.source_sha256 != object.sha256 {
                return Err(RemoteVerificationError::DigestMismatch {
                    key: object.object_key.clone(),
                    expected: object.sha256,
                    actual: receipt.verified.source_sha256,
                });
            }
            ordered_receipts.push(receipt);
        }
        if let Some((unexpected, _)) = by_key.into_iter().next() {
            return Err(RemoteVerificationError::UnexpectedReceipt(ObjectKey(
                unexpected,
            )));
        }

        let source_archive = match &self.source_archival {
            SourceArchivalPolicy::Disabled => RemoteSourceArchive::NotArchived,
            SourceArchivalPolicy::Enabled {
                policy_revision, ..
            } => RemoteSourceArchive::Verified {
                policy_revision: policy_revision.clone(),
            },
        };
        Ok(RemoteBundleReceipt {
            natural_key: self.natural_key(),
            derived_revision: self.derived_revision.clone(),
            source_revision: self.source_revision.clone(),
            source_archive,
            object_receipts: ordered_receipts,
        })
    }
}

impl<'de> Deserialize<'de> for FrozenUploadBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FrozenUploadBundleWire::deserialize(deserializer)?;
        if wire.schema_version != UPLOAD_BUNDLE_SCHEMA_VERSION {
            return Err(D::Error::custom(UploadBundleError::UnsupportedSchema(
                wire.schema_version,
            )));
        }
        let inputs = wire
            .objects
            .iter()
            .map(|object| UploadObjectInput {
                role: object.role.clone(),
                local_artifact: object.local_artifact.clone(),
                size_bytes: object.size_bytes,
                sha256: object.sha256,
                media_type: object.media_type.clone(),
            })
            .collect();
        let rebuilt = FrozenUploadBundle::freeze(UploadBundleInput {
            namespace: wire.namespace,
            origin_identity: wire.origin_identity,
            session_or_source_id: wire.session_or_source_id,
            source_revision: wire.source_revision,
            source_provenance: wire.source_provenance,
            source_inventory_digest: wire.source_inventory_digest,
            unsigned_admission: wire.unsigned_admission,
            profile_revision: wire.profile_revision,
            derived_revision: wire.derived_revision,
            storage_profile_identity: wire.storage_profile_identity,
            source_archival: wire.source_archival,
            upload_policy_revision: wire.upload_policy_revision,
            objects: inputs,
        })
        .map_err(D::Error::custom)?;
        if rebuilt.revision != wire.revision
            || rebuilt.provenance_digest != wire.provenance_digest
            || rebuilt.upload_request_digest != wire.upload_request_digest
            || rebuilt.objects != wire.objects
        {
            return Err(D::Error::custom(UploadBundleError::FrozenEvidenceMismatch));
        }
        Ok(rebuilt)
    }
}

#[derive(Deserialize)]
struct FrozenUploadBundleWire {
    schema_version: u32,
    revision: UploadBundleRevision,
    namespace: ObjectNamespace,
    origin_identity: String,
    session_or_source_id: String,
    source_revision: SourceContentRevision,
    source_provenance: SourceProvenance,
    source_inventory_digest: InventoryDigest,
    unsigned_admission: Option<UnsignedUploadAdmissionReceipt>,
    provenance_digest: SourceSha256,
    profile_revision: ProfileRevision,
    derived_revision: DerivedRevision,
    storage_profile_identity: StorageProfileIdentity,
    source_archival: SourceArchivalPolicy,
    upload_policy_revision: String,
    upload_request_digest: PreFreezeUploadRequestDigest,
    objects: Vec<FrozenUploadObject>,
}

/// Remote proof for the full frozen bundle. Construction is only possible
/// after every object, including the final manifest, has a real byte-digest
/// verification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteBundleReceipt {
    natural_key: UploadJobNaturalKey,
    derived_revision: DerivedRevision,
    source_revision: SourceContentRevision,
    source_archive: RemoteSourceArchive,
    object_receipts: Vec<CompletionBoundObjectReceipt>,
}

impl RemoteBundleReceipt {
    #[must_use]
    pub fn natural_key(&self) -> &UploadJobNaturalKey {
        &self.natural_key
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn source_archive(&self) -> &RemoteSourceArchive {
        &self.source_archive
    }

    #[must_use]
    pub fn object_receipts(&self) -> &[CompletionBoundObjectReceipt] {
        &self.object_receipts
    }

    /// A derived-only upload is deliberately not reported as a source backup.
    #[must_use]
    pub fn is_source_backup(&self) -> bool {
        matches!(&self.source_archive, RemoteSourceArchive::Verified { .. })
    }
}

/// Readback proof tied to the exact multipart completion held by the upload
/// worker. A plain latest-key verification receipt is insufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompletionBoundObjectReceipt {
    completion: CompletedUpload,
    verified: VerifiedObjectReceipt,
}

impl CompletionBoundObjectReceipt {
    pub fn bind(
        completion: CompletedUpload,
        verified: VerifiedObjectReceipt,
    ) -> Result<Self, RemoteVerificationError> {
        if completion.key != verified.key
            || completion.etag != verified.etag
            || completion.version_id != verified.version_id
        {
            return Err(RemoteVerificationError::CompletionBindingMismatch {
                completion_key: completion.key,
                verified_key: verified.key,
            });
        }
        Ok(Self {
            completion,
            verified,
        })
    }

    #[must_use]
    pub fn completion(&self) -> &CompletedUpload {
        &self.completion
    }

    #[must_use]
    pub fn verified(&self) -> &VerifiedObjectReceipt {
        &self.verified
    }
}

impl<'de> Deserialize<'de> for CompletionBoundObjectReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CompletionBoundObjectReceiptWire::deserialize(deserializer)?;
        Self::bind(wire.completion, wire.verified).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
struct CompletionBoundObjectReceiptWire {
    completion: CompletedUpload,
    verified: VerifiedObjectReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RemoteSourceArchive {
    NotArchived,
    Verified { policy_revision: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum SourceRetentionDecision {
    KeepSource {
        reason: RetentionBlockReason,
    },
    EligibleAfterGracePeriod {
        archive_policy_revision: String,
        grace_period_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionBlockReason {
    DisabledByDefault,
    SourceArchiveNotRemotelyVerified,
    ArchivePolicyMismatch,
}

/// Evaluates retention without deleting anything. Even the eligible result
/// still requires the caller to enforce the grace period and obtain an
/// exclusive library revision lease.
#[must_use]
pub fn evaluate_source_retention(
    policy: &SourceRetentionPolicy,
    remote: &RemoteBundleReceipt,
) -> SourceRetentionDecision {
    let SourceRetentionPolicy::AfterVerifiedSourceArchive {
        archive_policy_revision,
        grace_period_seconds,
    } = policy
    else {
        return SourceRetentionDecision::KeepSource {
            reason: RetentionBlockReason::DisabledByDefault,
        };
    };

    match remote.source_archive() {
        RemoteSourceArchive::NotArchived => SourceRetentionDecision::KeepSource {
            reason: RetentionBlockReason::SourceArchiveNotRemotelyVerified,
        },
        RemoteSourceArchive::Verified { policy_revision }
            if policy_revision == archive_policy_revision =>
        {
            SourceRetentionDecision::EligibleAfterGracePeriod {
                archive_policy_revision: archive_policy_revision.clone(),
                grace_period_seconds: *grace_period_seconds,
            }
        }
        RemoteSourceArchive::Verified { .. } => SourceRetentionDecision::KeepSource {
            reason: RetentionBlockReason::ArchivePolicyMismatch,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UploadBundleError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("upload bundle revision must be sha256:<64 lowercase hex>")]
    InvalidBundleRevision,
    #[error("unsupported upload bundle schema version {0}")]
    UnsupportedSchema(u32),
    #[error("persisted frozen bundle key, order, or revision does not match its inputs")]
    FrozenEvidenceMismatch,
    #[error("{field} contains control characters")]
    ControlCharacter { field: &'static str },
    #[error("opaque object-key segment exceeds {MAX_RAW_SEGMENT_BYTES} bytes")]
    SegmentTooLong,
    #[error("encoded object key exceeds {MAX_OBJECT_KEY_BYTES} bytes (actual {actual})")]
    ObjectKeyTooLong { actual: usize },
    #[error("upload objects must not be empty")]
    ZeroLengthObject,
    #[error("bundle contains duplicate singleton role {0}")]
    DuplicateSingletonRole(&'static str),
    #[error("bundle requires exactly one {role}, found {actual}")]
    RequiredSingletonRole { role: &'static str, actual: usize },
    #[error("bundle requires at least one derived media object")]
    MissingDerivedMedia,
    #[error("bundle derives duplicate object key {0:?}")]
    DuplicateObjectKey(ObjectKey),
    #[error("bundle contains source video {0:?} more than once")]
    DuplicateSourceVideo(String),
    #[error("source archival is disabled but source video objects were supplied")]
    SourceArchivalDisabled,
    #[error("source archival policy must name at least one source video")]
    EmptySourceArchive,
    #[error("source archival inventory differs: expected {expected:?}, actual {actual:?}")]
    SourceArchiveInventoryMismatch {
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
    #[error("locally validated unsigned sources require an explicit upload admission receipt")]
    UnsignedAdmissionRequired,
    #[error("unsigned upload admission receipt is bound to different source bytes")]
    UnsignedAdmissionMismatch,
    #[error("device-signed sources must not carry an unsigned upload admission receipt")]
    UnexpectedUnsignedAdmission,
    #[error("unsigned upload admission request is invalid: {0}")]
    InvalidAdmissionRequest(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteVerificationError {
    #[error(
        "verified object {verified_key:?} is not bound to multipart completion {completion_key:?}"
    )]
    CompletionBindingMismatch {
        completion_key: ObjectKey,
        verified_key: ObjectKey,
    },
    #[error("remote verification storage profile mismatch: expected {expected:?}, got {actual:?}")]
    StorageProfileMismatch {
        expected: StorageProfileIdentity,
        actual: StorageProfileIdentity,
    },
    #[error("missing verified receipt for {0:?}")]
    MissingReceipt(ObjectKey),
    #[error("duplicate verified receipt for {0:?}")]
    DuplicateReceipt(ObjectKey),
    #[error("unexpected verified receipt for {0:?}")]
    UnexpectedReceipt(ObjectKey),
    #[error("remote size mismatch for {key:?}: expected {expected}, got {actual}")]
    SizeMismatch {
        key: ObjectKey,
        expected: u64,
        actual: u64,
    },
    #[error("remote digest mismatch for {key:?}: expected {expected}, got {actual}")]
    DigestMismatch {
        key: ObjectKey,
        expected: SourceSha256,
        actual: SourceSha256,
    },
}

fn derive_object_key(
    input: &UploadBundleInput,
    role: &UploadObjectRole,
) -> Result<ObjectKey, UploadBundleError> {
    let mut base = vec![
        input.origin_identity.as_str(),
        input.session_or_source_id.as_str(),
        input.source_revision.as_str(),
    ];
    match role {
        UploadObjectRole::SourceManifest => {
            base.extend(["source", "source_manifest.json"]);
        }
        UploadObjectRole::SourceMetadata { opaque_file_id } => {
            base.extend(["source", "metadata", opaque_file_id]);
        }
        UploadObjectRole::SourceVideoArchive { opaque_file_id } => {
            base.extend(["source", "archive", opaque_file_id]);
        }
        UploadObjectRole::DerivedMedia { opaque_file_id } => {
            base.extend([
                "derivatives",
                input.profile_revision.as_str(),
                input.derived_revision.as_str(),
                "video",
                opaque_file_id,
            ]);
        }
        UploadObjectRole::DerivedMetadata { opaque_file_id } => {
            base.extend([
                "derivatives",
                input.profile_revision.as_str(),
                input.derived_revision.as_str(),
                "metadata",
                opaque_file_id,
            ]);
        }
        UploadObjectRole::ProvenanceReport => {
            base.extend([
                "derivatives",
                input.profile_revision.as_str(),
                input.derived_revision.as_str(),
                "metadata",
                "provenance.json",
            ]);
        }
        UploadObjectRole::DerivedManifest => {
            base.extend([
                "derivatives",
                input.profile_revision.as_str(),
                input.derived_revision.as_str(),
                "derived_manifest.json",
            ]);
        }
    }
    input.namespace.extend_key(base)
}

fn prepare_upload_bundle(
    input: &UploadBundleInput,
) -> Result<PreparedUploadBundle, UploadBundleError> {
    input.namespace.validate()?;
    validate_opaque_value("origin_identity", &input.origin_identity)?;
    validate_opaque_value("session_or_source_id", &input.session_or_source_id)?;
    validate_opaque_value("upload_policy_revision", &input.upload_policy_revision)?;
    validate_source_archival_policy(&input.source_archival)?;
    let provenance_digest = digest_source_provenance(&input.source_provenance);

    let mut derived_manifest = None;
    let mut source_manifest_count = 0_usize;
    let mut provenance_count = 0_usize;
    let mut derived_media_count = 0_usize;
    let mut source_video_ids = BTreeSet::new();
    let mut objects = Vec::with_capacity(input.objects.len());
    let mut keys = BTreeSet::new();

    for object in &input.objects {
        validate_upload_object_input(object)?;
        match &object.role {
            UploadObjectRole::DerivedManifest => {
                if derived_manifest.is_some() {
                    return Err(UploadBundleError::DuplicateSingletonRole(
                        "derived_manifest",
                    ));
                }
            }
            UploadObjectRole::SourceManifest => source_manifest_count += 1,
            UploadObjectRole::ProvenanceReport => provenance_count += 1,
            UploadObjectRole::DerivedMedia { .. } => derived_media_count += 1,
            UploadObjectRole::SourceVideoArchive { opaque_file_id } => {
                if !source_video_ids.insert(opaque_file_id.clone()) {
                    return Err(UploadBundleError::DuplicateSourceVideo(
                        opaque_file_id.clone(),
                    ));
                }
            }
            UploadObjectRole::DerivedMetadata { .. } | UploadObjectRole::SourceMetadata { .. } => {}
        }

        let object_key = derive_object_key(input, &object.role)?;
        if !keys.insert(object_key.0.clone()) {
            return Err(UploadBundleError::DuplicateObjectKey(object_key));
        }
        let frozen = FrozenUploadObject {
            role: object.role.clone(),
            local_artifact: object.local_artifact.clone(),
            object_key,
            size_bytes: object.size_bytes,
            sha256: object.sha256,
            media_type: object.media_type.clone(),
        };
        if matches!(&frozen.role, UploadObjectRole::DerivedManifest) {
            derived_manifest = Some(frozen);
        } else {
            objects.push(frozen);
        }
    }

    if source_manifest_count != 1 {
        return Err(UploadBundleError::RequiredSingletonRole {
            role: "source_manifest",
            actual: source_manifest_count,
        });
    }
    if provenance_count != 1 {
        return Err(UploadBundleError::RequiredSingletonRole {
            role: "provenance_report",
            actual: provenance_count,
        });
    }
    if derived_media_count == 0 {
        return Err(UploadBundleError::MissingDerivedMedia);
    }
    validate_source_archive_inventory(&input.source_archival, &source_video_ids)?;
    objects.push(
        derived_manifest.ok_or(UploadBundleError::RequiredSingletonRole {
            role: "derived_manifest",
            actual: 0,
        })?,
    );

    Ok(PreparedUploadBundle {
        provenance_digest,
        objects,
    })
}

/// Every immutable field that can affect upload bytes, keys, destination, or
/// policy is visible at this deterministic pre-freeze authorization boundary.
fn compute_pre_freeze_request_digest(
    input: &UploadBundleInput,
    prepared: &PreparedUploadBundle,
) -> PreFreezeUploadRequestDigest {
    let mut digest = Sha256::new();
    digest_field(
        &mut digest,
        b"schema",
        &UPLOAD_BUNDLE_SCHEMA_VERSION.to_be_bytes(),
    );
    for segment in &input.namespace.raw_segments {
        digest_field(&mut digest, b"namespace_segment", segment.as_bytes());
    }
    digest_field(&mut digest, b"origin", input.origin_identity.as_bytes());
    digest_field(
        &mut digest,
        b"session_or_source",
        input.session_or_source_id.as_bytes(),
    );
    digest_field(
        &mut digest,
        b"source",
        input.source_revision.as_str().as_bytes(),
    );
    digest_field(
        &mut digest,
        b"source_inventory",
        input.source_inventory_digest.as_str().as_bytes(),
    );
    digest_field(&mut digest, b"provenance", &prepared.provenance_digest.0);
    digest_field(
        &mut digest,
        b"profile",
        input.profile_revision.as_str().as_bytes(),
    );
    digest_field(
        &mut digest,
        b"derived",
        input.derived_revision.as_str().as_bytes(),
    );
    digest_field(
        &mut digest,
        b"storage_profile",
        input.storage_profile_identity.as_str().as_bytes(),
    );
    digest_field(
        &mut digest,
        b"upload_policy",
        input.upload_policy_revision.as_bytes(),
    );
    digest_source_archival(&mut digest, &input.source_archival);
    for (index, object) in prepared.objects.iter().enumerate() {
        digest_field(&mut digest, b"object_index", &(index as u64).to_be_bytes());
        digest_field(&mut digest, b"role", object.role.tag().as_bytes());
        if let Some(file_id) = object.role.opaque_file_id() {
            digest_field(&mut digest, b"file_id", file_id.as_bytes());
        }
        digest_field(
            &mut digest,
            b"local_ref",
            object.local_artifact.as_str().as_bytes(),
        );
        digest_field(&mut digest, b"key", object.object_key.0.as_bytes());
        digest_field(&mut digest, b"size", &object.size_bytes.to_be_bytes());
        digest_field(&mut digest, b"sha256", &object.sha256.0);
        digest_field(&mut digest, b"media_type", object.media_type.as_bytes());
    }
    PreFreezeUploadRequestDigest::from_digest(digest.finalize().into())
}

fn compute_bundle_revision(
    upload_request_digest: &PreFreezeUploadRequestDigest,
    unsigned_admission: Option<&UnsignedUploadAdmissionReceipt>,
) -> UploadBundleRevision {
    let mut digest = Sha256::new();
    digest_field(
        &mut digest,
        b"schema",
        &UPLOAD_BUNDLE_SCHEMA_VERSION.to_be_bytes(),
    );
    digest_field(
        &mut digest,
        b"upload_request",
        upload_request_digest.as_str().as_bytes(),
    );
    if let Some(admission) = unsigned_admission {
        digest_field(
            &mut digest,
            b"unsigned_admission",
            admission.receipt_id().as_bytes(),
        );
    }
    let bytes: [u8; 32] = digest.finalize().into();
    let mut revision = String::with_capacity(71);
    revision.push_str("sha256:");
    for byte in bytes {
        write!(&mut revision, "{byte:02x}").expect("writing to String cannot fail");
    }
    UploadBundleRevision(revision)
}

fn digest_source_archival(digest: &mut Sha256, archival: &SourceArchivalPolicy) {
    match archival {
        SourceArchivalPolicy::Disabled => digest_field(digest, b"archive", b"disabled"),
        SourceArchivalPolicy::Enabled {
            policy_revision,
            expected_source_video_ids,
        } => {
            digest_field(digest, b"archive", b"enabled");
            digest_field(digest, b"archive_policy", policy_revision.as_bytes());
            for file_id in expected_source_video_ids {
                digest_field(digest, b"archive_file", file_id.as_bytes());
            }
        }
    }
}

fn digest_source_provenance(provenance: &SourceProvenance) -> SourceSha256 {
    let mut digest = Sha256::new();
    match provenance {
        SourceProvenance::DeviceSigned(signed) => {
            digest_field(&mut digest, b"kind", b"device_signed");
            digest_field(
                &mut digest,
                b"publication_key_fingerprint",
                signed.publication_key_fingerprint().as_bytes(),
            );
            digest_field(
                &mut digest,
                b"publication_revision",
                signed.publication_revision().as_str().as_bytes(),
            );
        }
        SourceProvenance::LocallyValidatedUnsigned(unsigned) => {
            digest_field(&mut digest, b"kind", b"locally_validated_unsigned");
            digest_field(
                &mut digest,
                b"source_schema",
                source_schema_tag(unsigned.source_schema()),
            );
            for check in unsigned.validation_report().checks() {
                digest_field(&mut digest, b"validation_code", check.code().as_bytes());
                digest_field(
                    &mut digest,
                    b"validation_passed",
                    &[u8::from(check.passed())],
                );
                digest_field(&mut digest, b"validation_detail", check.detail().as_bytes());
            }
            if let Some(inventory) = unsigned.computed_inventory_digest() {
                digest_field(
                    &mut digest,
                    b"computed_inventory_digest",
                    inventory.as_str().as_bytes(),
                );
            }
            if let Some(receipt) = unsigned.user_admission_receipt() {
                digest_field(
                    &mut digest,
                    b"ingest_admission_receipt_id",
                    receipt.receipt_id().as_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"ingest_admission_policy_revision",
                    receipt.policy_revision().as_bytes(),
                );
                digest_field(
                    &mut digest,
                    b"ingest_admission_timestamp",
                    receipt.admitted_at().as_bytes(),
                );
            }
        }
    }
    SourceSha256::from_bytes(digest.finalize().into())
}

fn source_schema_tag(schema: SourceSchema) -> &'static [u8] {
    match schema {
        SourceSchema::DeviceSessionV1 => b"device_session_v1",
        SourceSchema::DeviceSessionV2 => b"device_session_v2",
        SourceSchema::SignedPublicationV1 => b"signed_publication_v1",
        SourceSchema::UnsignedPublicationV1 => b"unsigned_publication_v1",
        SourceSchema::CompleteUnpublishedV6 => b"complete_unpublished_v6",
        SourceSchema::RawCaptureV2 => b"raw_capture_v2",
        SourceSchema::LegacyMjpegSessionV5 => b"legacy_mjpeg_session_v5",
        SourceSchema::ApplianceSpoolV6 => b"appliance_spool_v6",
    }
}

fn digest_field(digest: &mut Sha256, tag: &[u8], value: &[u8]) {
    digest.update((tag.len() as u64).to_be_bytes());
    digest.update(tag);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn encode_opaque_segment(value: &str) -> Result<String, UploadBundleError> {
    validate_opaque_value("object_key_segment", value)?;
    if value.len() > MAX_RAW_SEGMENT_BYTES {
        return Err(UploadBundleError::SegmentTooLong);
    }
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    Ok(encoded)
}

fn validate_opaque_value(field: &'static str, value: &str) -> Result<(), UploadBundleError> {
    if value.is_empty() {
        return Err(UploadBundleError::EmptyField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(UploadBundleError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_source_archival_policy(policy: &SourceArchivalPolicy) -> Result<(), UploadBundleError> {
    let SourceArchivalPolicy::Enabled {
        policy_revision,
        expected_source_video_ids,
    } = policy
    else {
        return Ok(());
    };
    validate_opaque_value("source_archive_policy_revision", policy_revision)?;
    if expected_source_video_ids.is_empty() {
        return Err(UploadBundleError::EmptySourceArchive);
    }
    for file_id in expected_source_video_ids {
        validate_opaque_value("source_archive_file_id", file_id)?;
    }
    Ok(())
}

fn validate_upload_object_input(object: &UploadObjectInput) -> Result<(), UploadBundleError> {
    if object.size_bytes == 0 {
        return Err(UploadBundleError::ZeroLengthObject);
    }
    validate_opaque_value("local_artifact_ref", object.local_artifact.as_str())?;
    validate_opaque_value("media_type", &object.media_type)?;
    if let Some(file_id) = object.role.opaque_file_id() {
        validate_opaque_value("opaque_file_id", file_id)?;
    }
    Ok(())
}

fn validate_source_archive_inventory(
    policy: &SourceArchivalPolicy,
    actual: &BTreeSet<String>,
) -> Result<(), UploadBundleError> {
    match policy {
        SourceArchivalPolicy::Disabled if actual.is_empty() => Ok(()),
        SourceArchivalPolicy::Disabled => Err(UploadBundleError::SourceArchivalDisabled),
        SourceArchivalPolicy::Enabled {
            expected_source_video_ids,
            ..
        } if expected_source_video_ids == actual => Ok(()),
        SourceArchivalPolicy::Enabled {
            expected_source_video_ids,
            ..
        } => Err(UploadBundleError::SourceArchiveInventoryMismatch {
            expected: expected_source_video_ids.clone(),
            actual: actual.clone(),
        }),
    }
}

fn validate_upload_admission(
    source_provenance: &SourceProvenance,
    unsigned_admission: Option<&UnsignedUploadAdmissionReceipt>,
    admission_request: Option<&UnsignedUploadAdmissionRequest>,
) -> Result<(), UploadBundleError> {
    match (source_provenance, unsigned_admission, admission_request) {
        (SourceProvenance::DeviceSigned(_), None, None) => Ok(()),
        (SourceProvenance::DeviceSigned(_), Some(_), _) => {
            Err(UploadBundleError::UnexpectedUnsignedAdmission)
        }
        (SourceProvenance::DeviceSigned(_), None, Some(_)) => {
            Err(UploadBundleError::UnexpectedUnsignedAdmission)
        }
        (SourceProvenance::LocallyValidatedUnsigned(_), None, Some(_)) => {
            Err(UploadBundleError::UnsignedAdmissionRequired)
        }
        (SourceProvenance::LocallyValidatedUnsigned(_), Some(receipt), Some(request))
            if receipt.matches(request) =>
        {
            Ok(())
        }
        (SourceProvenance::LocallyValidatedUnsigned(_), Some(_), Some(_)) => {
            Err(UploadBundleError::UnsignedAdmissionMismatch)
        }
        (SourceProvenance::LocallyValidatedUnsigned(_), _, None) => {
            Err(UploadBundleError::InvalidAdmissionRequest(
                "pre-freeze request was not constructed".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod approval_binding_tests {
    use super::*;

    fn unsigned_provenance() -> SourceProvenance {
        serde_json::from_value(serde_json::json!({
            "kind": "locally_validated_unsigned",
            "evidence": {
                "source_schema": "raw_capture_v2",
                "validation_report": {
                    "checks": [{"code": "fixture", "passed": true, "detail": "valid"}]
                },
                "computed_inventory_digest": format!("sha256:{}", "a".repeat(64)),
                "user_admission_receipt": null
            }
        }))
        .expect("unsigned provenance")
    }

    fn object(role: UploadObjectRole, local_ref: &str, digest_byte: u8) -> UploadObjectInput {
        UploadObjectInput::new(
            role,
            LocalArtifactRef::parse(local_ref).expect("local artifact"),
            10,
            SourceSha256::from_bytes([digest_byte; 32]),
            "application/octet-stream",
        )
        .expect("upload object")
    }

    fn unsigned_input() -> UploadBundleInput {
        UploadBundleInput {
            namespace: ObjectNamespace::from_raw_segments(["prefix", "bucket"]).expect("namespace"),
            origin_identity: "origin-1".to_string(),
            session_or_source_id: "session-1".to_string(),
            source_revision: SourceContentRevision::from_material(b"source"),
            source_provenance: unsigned_provenance(),
            source_inventory_digest: InventoryDigest::from_material(b"inventory"),
            unsigned_admission: None,
            profile_revision: ProfileRevision::from_canonical_bytes(b"profile"),
            derived_revision: DerivedRevision::from_canonical_bytes(b"derived"),
            storage_profile_identity: StorageProfileIdentity::parse("storage-a")
                .expect("storage identity"),
            source_archival: SourceArchivalPolicy::Disabled,
            upload_policy_revision: DERIVED_UPLOAD_POLICY_REVISION.to_string(),
            objects: vec![
                object(UploadObjectRole::SourceManifest, "source-manifest", 1),
                object(UploadObjectRole::ProvenanceReport, "provenance", 2),
                object(
                    UploadObjectRole::DerivedMedia {
                        opaque_file_id: "segment-1".to_string(),
                    },
                    "derived-media",
                    3,
                ),
                object(UploadObjectRole::DerivedManifest, "derived-manifest", 4),
            ],
        }
    }

    #[test]
    fn pre_freeze_request_digest_changes_with_every_upload_authority_boundary() {
        let input = unsigned_input();
        let request = input
            .unsigned_upload_admission_request()
            .expect("base request");

        let mut changed_derived = input.clone();
        changed_derived.derived_revision = DerivedRevision::from_canonical_bytes(b"changed");
        let changed_derived = changed_derived
            .unsigned_upload_admission_request()
            .expect("changed derived request");
        assert_ne!(
            request.upload_request_digest(),
            changed_derived.upload_request_digest()
        );

        let mut changed_storage = input.clone();
        changed_storage.storage_profile_identity =
            StorageProfileIdentity::parse("storage-b").expect("storage identity");
        let changed_storage = changed_storage
            .unsigned_upload_admission_request()
            .expect("changed storage request");
        assert_ne!(
            request.upload_request_digest(),
            changed_storage.upload_request_digest()
        );

        let mut changed_object = input.clone();
        changed_object.objects[2].sha256 = SourceSha256::from_bytes([9; 32]);
        let changed_object = changed_object
            .unsigned_upload_admission_request()
            .expect("changed object request");
        assert_ne!(
            request.upload_request_digest(),
            changed_object.upload_request_digest()
        );

        let mut changed_policy = input;
        changed_policy.upload_policy_revision = "ylx.derived-upload-policy.v2".to_string();
        let changed_policy = changed_policy
            .unsigned_upload_admission_request()
            .expect("changed policy request");
        assert_ne!(
            request.upload_request_digest(),
            changed_policy.upload_request_digest()
        );
    }

    #[test]
    fn freeze_rejects_a_receipt_after_bundle_or_destination_changes() {
        let input = unsigned_input();
        let receipt = input
            .unsigned_upload_admission_request()
            .expect("approval request")
            .admit("desktop-user", "2026-08-11T00:00:00Z")
            .expect("receipt");
        let mut approved = input;
        approved.unsigned_admission = Some(receipt);
        FrozenUploadBundle::freeze(approved.clone()).expect("exact request must freeze");

        let mut changed_storage = approved.clone();
        changed_storage.storage_profile_identity =
            StorageProfileIdentity::parse("storage-b").expect("storage identity");
        assert_eq!(
            FrozenUploadBundle::freeze(changed_storage),
            Err(UploadBundleError::UnsignedAdmissionMismatch)
        );

        let mut changed_derived = approved.clone();
        changed_derived.derived_revision = DerivedRevision::from_canonical_bytes(b"changed");
        assert_eq!(
            FrozenUploadBundle::freeze(changed_derived),
            Err(UploadBundleError::UnsignedAdmissionMismatch)
        );

        let mut changed_object = approved.clone();
        changed_object.objects[2].sha256 = SourceSha256::from_bytes([9; 32]);
        assert_eq!(
            FrozenUploadBundle::freeze(changed_object),
            Err(UploadBundleError::UnsignedAdmissionMismatch)
        );

        let mut changed_policy = approved;
        changed_policy.upload_policy_revision = "ylx.derived-upload-policy.v2".to_string();
        assert_eq!(
            FrozenUploadBundle::freeze(changed_policy),
            Err(UploadBundleError::UnsignedAdmissionMismatch)
        );
    }

    #[test]
    fn unsigned_approval_cannot_enable_source_archival() {
        let mut input = unsigned_input();
        input.source_archival = SourceArchivalPolicy::Enabled {
            policy_revision: "archive-v1".to_string(),
            expected_source_video_ids: BTreeSet::from(["video-1".to_string()]),
        };
        input.objects.push(object(
            UploadObjectRole::SourceVideoArchive {
                opaque_file_id: "video-1".to_string(),
            },
            "source-video",
            5,
        ));

        assert!(matches!(
            input.unsigned_upload_admission_request(),
            Err(UploadBundleError::InvalidAdmissionRequest(_))
        ));
    }

    #[test]
    fn persisted_receipt_rejects_tampering_and_the_old_weak_shape() {
        let receipt = unsigned_input()
            .unsigned_upload_admission_request()
            .expect("approval request")
            .admit("desktop-user", "2026-08-11T00:00:00Z")
            .expect("receipt");
        let mut tampered = serde_json::to_value(&receipt).expect("serialize receipt");
        tampered["storage_profile_identity"] = serde_json::json!("storage-b");
        assert!(serde_json::from_value::<UnsignedUploadAdmissionReceipt>(tampered).is_err());

        let weak_v1 = serde_json::json!({
            "receipt_id": receipt.receipt_id(),
            "statement": "ylx.unsigned-source-upload-admission.v1",
            "source_revision": receipt.source_revision(),
            "inventory_digest": receipt.inventory_digest(),
            "admitted_by": receipt.admitted_by(),
            "admitted_at": receipt.admitted_at()
        });
        assert!(serde_json::from_value::<UnsignedUploadAdmissionReceipt>(weak_v1).is_err());
    }
}
