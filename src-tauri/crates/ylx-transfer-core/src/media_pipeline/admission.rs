use std::fmt::Write as _;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::ingest::{InventoryDigest, SourceContentRevision};
use crate::normalization::DerivedRevision;

use super::{SourceArchivalPolicy, StorageProfileIdentity};

const UNSIGNED_ADMISSION_STATEMENT: &str = "ylx.unsigned-source-upload-admission.v2";
const MAX_ADMISSION_TEXT_BYTES: usize = 512;

/// SHA-256 of the complete immutable upload request before an unsigned
/// admission receipt is inserted into it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PreFreezeUploadRequestDigest(String);

impl PreFreezeUploadRequestDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self, AdmissionError> {
        let value = value.into();
        let valid = value.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if !valid {
            return Err(AdmissionError::InvalidRequestDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        for byte in digest {
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PreFreezeUploadRequestDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Explicit user action required before an unsigned, locally validated source
/// may enter an automatic upload policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsignedUploadAdmissionRequest {
    source_revision: SourceContentRevision,
    inventory_digest: InventoryDigest,
    derived_revision: DerivedRevision,
    upload_request_digest: PreFreezeUploadRequestDigest,
    storage_profile_identity: StorageProfileIdentity,
    source_archival: SourceArchivalPolicy,
    policy_revision: String,
}

impl UnsignedUploadAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_revision: SourceContentRevision,
        inventory_digest: InventoryDigest,
        derived_revision: DerivedRevision,
        upload_request_digest: PreFreezeUploadRequestDigest,
        storage_profile_identity: StorageProfileIdentity,
        source_archival: SourceArchivalPolicy,
        policy_revision: impl Into<String>,
    ) -> Result<Self, AdmissionError> {
        let policy_revision = policy_revision.into();
        validate_receipt_text("policy_revision", &policy_revision)?;
        if !matches!(source_archival, SourceArchivalPolicy::Disabled) {
            return Err(AdmissionError::SourceArchivalMustBeDisabled);
        }
        Ok(Self {
            source_revision,
            inventory_digest,
            derived_revision,
            upload_request_digest,
            storage_profile_identity,
            source_archival,
            policy_revision,
        })
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn inventory_digest(&self) -> &InventoryDigest {
        &self.inventory_digest
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn upload_request_digest(&self) -> &PreFreezeUploadRequestDigest {
        &self.upload_request_digest
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
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    pub fn admit(
        &self,
        admitted_by: impl Into<String>,
        admitted_at: impl Into<String>,
    ) -> Result<UnsignedUploadAdmissionReceipt, AdmissionError> {
        UnsignedUploadAdmissionReceipt::issue(self, admitted_by, admitted_at)
    }
}

impl<'de> Deserialize<'de> for UnsignedUploadAdmissionRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UnsignedUploadAdmissionRequestWire::deserialize(deserializer)?;
        Self::new(
            wire.source_revision,
            wire.inventory_digest,
            wire.derived_revision,
            wire.upload_request_digest,
            wire.storage_profile_identity,
            wire.source_archival,
            wire.policy_revision,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
struct UnsignedUploadAdmissionRequestWire {
    source_revision: SourceContentRevision,
    inventory_digest: InventoryDigest,
    derived_revision: DerivedRevision,
    upload_request_digest: PreFreezeUploadRequestDigest,
    storage_profile_identity: StorageProfileIdentity,
    source_archival: SourceArchivalPolicy,
    policy_revision: String,
}

/// Durable evidence of an explicit unsigned-source upload decision.
///
/// The receipt binds the exact verified source and derivative, the complete
/// pre-freeze object request, destination coordinates, disabled archival
/// policy, policy revision, actor, and approval time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsignedUploadAdmissionReceipt {
    receipt_id: String,
    statement: String,
    source_revision: SourceContentRevision,
    inventory_digest: InventoryDigest,
    derived_revision: DerivedRevision,
    upload_request_digest: PreFreezeUploadRequestDigest,
    storage_profile_identity: StorageProfileIdentity,
    source_archival: SourceArchivalPolicy,
    policy_revision: String,
    admitted_by: String,
    admitted_at: String,
}

impl<'de> Deserialize<'de> for UnsignedUploadAdmissionReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UnsignedUploadAdmissionReceiptWire::deserialize(deserializer)?;
        let request = UnsignedUploadAdmissionRequest::new(
            wire.source_revision,
            wire.inventory_digest,
            wire.derived_revision,
            wire.upload_request_digest,
            wire.storage_profile_identity,
            wire.source_archival,
            wire.policy_revision,
        )
        .map_err(D::Error::custom)?;
        let rebuilt = request
            .admit(wire.admitted_by, wire.admitted_at)
            .map_err(D::Error::custom)?;
        if rebuilt.receipt_id != wire.receipt_id || rebuilt.statement != wire.statement {
            return Err(D::Error::custom(AdmissionError::InvalidPersistedReceipt));
        }
        Ok(rebuilt)
    }
}

#[derive(Deserialize)]
struct UnsignedUploadAdmissionReceiptWire {
    receipt_id: String,
    statement: String,
    source_revision: SourceContentRevision,
    inventory_digest: InventoryDigest,
    derived_revision: DerivedRevision,
    upload_request_digest: PreFreezeUploadRequestDigest,
    storage_profile_identity: StorageProfileIdentity,
    source_archival: SourceArchivalPolicy,
    policy_revision: String,
    admitted_by: String,
    admitted_at: String,
}

impl UnsignedUploadAdmissionReceipt {
    fn issue(
        request: &UnsignedUploadAdmissionRequest,
        admitted_by: impl Into<String>,
        admitted_at: impl Into<String>,
    ) -> Result<Self, AdmissionError> {
        let admitted_by = admitted_by.into();
        let admitted_at = admitted_at.into();
        validate_receipt_text("admitted_by", &admitted_by)?;
        validate_receipt_text("admitted_at", &admitted_at)?;

        let mut digest = Sha256::new();
        update_field(&mut digest, UNSIGNED_ADMISSION_STATEMENT.as_bytes());
        update_field(&mut digest, request.source_revision.as_str().as_bytes());
        update_field(&mut digest, request.inventory_digest.as_str().as_bytes());
        update_field(&mut digest, request.derived_revision.as_str().as_bytes());
        update_field(
            &mut digest,
            request.upload_request_digest.as_str().as_bytes(),
        );
        update_field(
            &mut digest,
            request.storage_profile_identity.as_str().as_bytes(),
        );
        update_field(&mut digest, b"source_archival=disabled");
        update_field(&mut digest, request.policy_revision.as_bytes());
        update_field(&mut digest, admitted_by.as_bytes());
        update_field(&mut digest, admitted_at.as_bytes());
        let bytes: [u8; 32] = digest.finalize().into();
        let mut receipt_id = String::with_capacity(81);
        receipt_id.push_str("admission:sha256:");
        for byte in bytes {
            write!(&mut receipt_id, "{byte:02x}").expect("writing to String cannot fail");
        }

        Ok(Self {
            receipt_id,
            statement: UNSIGNED_ADMISSION_STATEMENT.to_string(),
            source_revision: request.source_revision.clone(),
            inventory_digest: request.inventory_digest.clone(),
            derived_revision: request.derived_revision.clone(),
            upload_request_digest: request.upload_request_digest.clone(),
            storage_profile_identity: request.storage_profile_identity.clone(),
            source_archival: request.source_archival.clone(),
            policy_revision: request.policy_revision.clone(),
            admitted_by,
            admitted_at,
        })
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn source_revision(&self) -> &SourceContentRevision {
        &self.source_revision
    }

    #[must_use]
    pub fn inventory_digest(&self) -> &InventoryDigest {
        &self.inventory_digest
    }

    #[must_use]
    pub fn derived_revision(&self) -> &DerivedRevision {
        &self.derived_revision
    }

    #[must_use]
    pub fn upload_request_digest(&self) -> &PreFreezeUploadRequestDigest {
        &self.upload_request_digest
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
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    #[must_use]
    pub fn admitted_by(&self) -> &str {
        &self.admitted_by
    }

    #[must_use]
    pub fn admitted_at(&self) -> &str {
        &self.admitted_at
    }

    #[must_use]
    pub fn matches(&self, request: &UnsignedUploadAdmissionRequest) -> bool {
        self.statement == UNSIGNED_ADMISSION_STATEMENT
            && self.source_revision == request.source_revision
            && self.inventory_digest == request.inventory_digest
            && self.derived_revision == request.derived_revision
            && self.upload_request_digest == request.upload_request_digest
            && self.storage_profile_identity == request.storage_profile_identity
            && self.source_archival == request.source_archival
            && self.policy_revision == request.policy_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} is longer than {maximum} bytes")]
    TooLong { field: &'static str, maximum: usize },
    #[error("{field} contains control characters")]
    ControlCharacter { field: &'static str },
    #[error("pre-freeze upload request digest is not a lowercase SHA-256 identity")]
    InvalidRequestDigest,
    #[error("unsigned derived upload approval requires source archival to remain disabled")]
    SourceArchivalMustBeDisabled,
    #[error("persisted unsigned upload admission receipt does not match its bound evidence")]
    InvalidPersistedReceipt,
}

fn validate_receipt_text(field: &'static str, value: &str) -> Result<(), AdmissionError> {
    if value.is_empty() {
        return Err(AdmissionError::Empty { field });
    }
    if value.len() > MAX_ADMISSION_TEXT_BYTES {
        return Err(AdmissionError::TooLong {
            field,
            maximum: MAX_ADMISSION_TEXT_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(AdmissionError::ControlCharacter { field });
    }
    Ok(())
}

fn update_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}
