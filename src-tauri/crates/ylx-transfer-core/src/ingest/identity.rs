//! Validated opaque identities used by removable-media ingest.
//!
//! Location and content identities are deliberately different types. A mount
//! path may change while the same recording content remains the same, and a
//! reused drive letter must never make a different card look like the old one.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Rejection returned when untrusted text is not a valid opaque identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} is longer than {maximum} bytes")]
    TooLong { field: &'static str, maximum: usize },
    #[error("{field} contains control characters or path separators")]
    UnsafeCharacters { field: &'static str },
    #[error("{field} must have the form {expected}")]
    InvalidShape {
        field: &'static str,
        expected: &'static str,
    },
}

fn validate_opaque(field: &'static str, value: &str, maximum: usize) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { field });
    }
    if value.len() > maximum {
        return Err(IdentityError::TooLong { field, maximum });
    }
    if value
        .chars()
        .any(|character| character.is_control() || character == '/' || character == '\\')
    {
        return Err(IdentityError::UnsafeCharacters { field });
    }
    Ok(())
}

fn validate_prefixed_sha256(
    field: &'static str,
    value: &str,
    prefix: &'static str,
) -> Result<(), IdentityError> {
    let Some(digest) = value.strip_prefix(prefix) else {
        return Err(IdentityError::InvalidShape {
            field,
            expected: "a namespaced lowercase SHA-256 identity",
        });
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(IdentityError::InvalidShape {
            field,
            expected: "a namespaced lowercase SHA-256 identity",
        });
    }
    Ok(())
}

macro_rules! opaque_identity {
    ($name:ident, $field:literal, $maximum:expr) => {
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate_opaque($field, &value, $maximum)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(D::Error::custom)
            }
        }
    };
}

opaque_identity!(AcquisitionSourceId, "acquisition source id", 256);
opaque_identity!(SourceArtifactId, "source artifact id", 128);
opaque_identity!(ImportJobId, "import job id", 128);

macro_rules! digest_identity {
    ($name:ident, $field:literal, $prefix:literal) => {
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate_prefixed_sha256($field, &value, $prefix)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn from_digest(digest: [u8; 32]) -> Self {
                Self(format!(concat!($prefix, "{}"), encode_hex(&digest)))
            }

            #[must_use]
            pub fn from_material(material: &[u8]) -> Self {
                let digest: [u8; 32] = Sha256::digest(material).into();
                Self::from_digest(digest)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest_hex(&self) -> &str {
                &self.0[$prefix.len()..]
            }

            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(D::Error::custom)
            }
        }
    };
}

digest_identity!(CandidateId, "candidate id", "candidate:sha256:");
digest_identity!(CandidateRevision, "candidate revision", "candidate:sha256:");
digest_identity!(SourceContentRevision, "source content revision", "sha256:");
digest_identity!(MediaGenerationId, "media generation id", "media:sha256:");
digest_identity!(InventoryDigest, "inventory digest", "sha256:");

/// The revision fence carried by an artifact read.
///
/// Unsigned media has only a provisional scan claim until every copied file
/// has been hashed and verified on the PC. Treating the two variants as the
/// same string would let provisional evidence masquerade as a stable content
/// revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "revision", rename_all = "snake_case")]
pub enum SourceRevisionClaim {
    Published(SourceContentRevision),
    Provisional(CandidateRevision),
}

impl SourceRevisionClaim {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Published(revision) => revision.as_str(),
            Self::Provisional(revision) => revision.as_str(),
        }
    }

    #[must_use]
    pub fn stable(&self) -> Option<&SourceContentRevision> {
        match self {
            Self::Published(revision) => Some(revision),
            Self::Provisional(_) => None,
        }
    }
}

/// A mounted-media observation, fenced by both platform identity and content
/// marker. The mount path is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MediaGeneration {
    id: MediaGenerationId,
    source_id: AcquisitionSourceId,
    platform_volume_identity: String,
    root_marker_digest: InventoryDigest,
    observation_epoch: u64,
}

impl MediaGeneration {
    pub fn new(
        source_id: AcquisitionSourceId,
        platform_volume_identity: impl Into<String>,
        root_marker_digest: InventoryDigest,
        observation_epoch: u64,
    ) -> Result<Self, IdentityError> {
        let platform_volume_identity = platform_volume_identity.into();
        validate_opaque("platform volume identity", &platform_volume_identity, 512)?;
        let material = format!(
            "{}\n{}\n{}\n{}",
            source_id.as_str(),
            platform_volume_identity,
            root_marker_digest.as_str(),
            observation_epoch
        );
        Ok(Self {
            id: MediaGenerationId::from_material(material.as_bytes()),
            source_id,
            platform_volume_identity,
            root_marker_digest,
            observation_epoch,
        })
    }

    #[must_use]
    pub fn id(&self) -> &MediaGenerationId {
        &self.id
    }

    #[must_use]
    pub fn source_id(&self) -> &AcquisitionSourceId {
        &self.source_id
    }

    #[must_use]
    pub fn platform_volume_identity(&self) -> &str {
        &self.platform_volume_identity
    }

    #[must_use]
    pub fn root_marker_digest(&self) -> &InventoryDigest {
        &self.root_marker_digest
    }

    #[must_use]
    pub fn observation_epoch(&self) -> u64 {
        self.observation_epoch
    }
}

impl ImportJobId {
    /// Create a restart-safe opaque job id. It is not part of the job's
    /// natural identity; repositories still deduplicate by the import spec.
    #[must_use]
    pub fn new() -> Self {
        Self(format!("import-{}", uuid::Uuid::new_v4()))
    }
}

impl Default for ImportJobId {
    fn default() -> Self {
        Self::new()
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
