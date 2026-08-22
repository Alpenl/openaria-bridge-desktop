use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("{field} must be sha256:<64 lowercase hex>, got {value:?}")]
    InvalidPrefixedSha256 { field: &'static str, value: String },
    #[error("{field} must be exactly 64 lowercase hex characters, got {value:?}")]
    InvalidBareSha256 { field: &'static str, value: String },
    #[error("{field} must be a non-empty opaque ASCII identifier of at most 128 characters")]
    InvalidOpaqueId { field: &'static str },
    #[error("canonical JSON serialization failed: {0}")]
    CanonicalJson(String),
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_prefixed_sha256(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, IdentityError> {
    let value = value.into();
    let valid = value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64));
    if valid {
        Ok(value)
    } else {
        Err(IdentityError::InvalidPrefixedSha256 { field, value })
    }
}

fn validate_bare_sha256(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, IdentityError> {
    let value = value.into();
    if is_lower_hex(&value, 64) {
        Ok(value)
    } else {
        Err(IdentityError::InvalidBareSha256 { field, value })
    }
}

fn validate_opaque_id(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, IdentityError> {
    let value = value.into();
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(value)
    } else {
        Err(IdentityError::InvalidOpaqueId { field })
    }
}

macro_rules! prefixed_sha256_newtype {
    ($name:ident, $field:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
                validate_prefixed_sha256($field, value).map(Self)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
                Self(sha256_prefixed(bytes))
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
                Self::parse(value).map_err(de::Error::custom)
            }
        }
    };
}

prefixed_sha256_newtype!(ProfileRevision, "profile_revision");
prefixed_sha256_newtype!(DerivedRevision, "derived_revision");
prefixed_sha256_newtype!(SourceManifestDigest, "source_manifest_digest");
prefixed_sha256_newtype!(EncoderBuildFingerprint, "encoder_build_fingerprint");

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentSha256(String);

impl ContentSha256 {
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
        validate_bare_sha256("content_sha256", value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for ContentSha256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentSha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DerivationJobId(String);

impl DerivationJobId {
    #[must_use]
    pub fn new() -> Self {
        Self(format!("derivation-{}", uuid::Uuid::new_v4()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
        validate_opaque_id("derivation_job_id", value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for DerivationJobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DerivationJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentityError> {
    let value = serde_json::to_value(value)
        .map_err(|error| IdentityError::CanonicalJson(error.to_string()))?;
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).map_err(|error| IdentityError::CanonicalJson(error.to_string()))
}

fn canonicalize_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(canonicalize_value)
                .collect::<Vec<_>>(),
        ),
        serde_json::Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonicalize_value(value));
            }
            serde_json::Value::Object(canonical)
        }
        scalar => scalar,
    }
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revisions_fail_closed_on_noncanonical_hashes() {
        assert!(ProfileRevision::parse(format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(ProfileRevision::parse("a".repeat(64)).is_err());
        assert!(ProfileRevision::parse(format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let value = serde_json::json!({"z": {"b": 2, "a": 1}, "a": true});
        assert_eq!(
            canonical_json(&value).expect("canonical JSON"),
            br#"{"a":true,"z":{"a":1,"b":2}}"#
        );
    }
}
