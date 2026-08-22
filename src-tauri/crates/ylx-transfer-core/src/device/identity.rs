//! Device identity normalization and projection.
//!
//! One full SHA-256 TLS fingerprint is the identity. Everything else is a
//! projection with a narrower purpose:
//!
//! - `ylx-<64 lowercase hex>` is the canonical, path-safe [`DeviceId`];
//! - `sha256:<64 lowercase hex>` is the TLS pin spelling;
//! - `YLX-<first 8 uppercase hex>` is a display label and legacy alias.
//!
//! Callers never slice or format fingerprint strings themselves. That keeps
//! collision handling and compatibility with persisted short aliases behind
//! this module's interface.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::domain::DeviceId;

const FINGERPRINT_HEX_LEN: usize = 64;
const DISPLAY_HEX_LEN: usize = 8;
const TLS_PREFIX: &str = "sha256:";
const DEVICE_ID_PREFIX: &str = "ylx-";
const DISPLAY_PREFIX: &str = "YLX-";

/// A rejected TLS fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceFingerprintParseError {
    #[error(
        "device fingerprint must contain exactly 64 ASCII hexadecimal characters, got {actual}"
    )]
    InvalidLength { actual: usize },
    #[error("device fingerprint contains a non-hexadecimal byte at index {index}")]
    InvalidHex { index: usize },
}

/// A device's complete SHA-256 TLS fingerprint.
///
/// The stored representation is always exactly 64 lowercase ASCII hex
/// characters with no prefix. Construction from untrusted input must use
/// [`DeviceFingerprint::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceFingerprint(String);

impl DeviceFingerprint {
    /// Parses a bare fingerprint or one with a case-insensitive `sha256:`
    /// prefix. Whitespace and every non-ASCII-hex character are rejected.
    pub fn parse(raw: &str) -> Result<Self, DeviceFingerprintParseError> {
        let hex = match raw.get(..TLS_PREFIX.len()) {
            Some(prefix) if prefix.eq_ignore_ascii_case(TLS_PREFIX) => &raw[TLS_PREFIX.len()..],
            _ => raw,
        };
        if hex.len() != FINGERPRINT_HEX_LEN {
            return Err(DeviceFingerprintParseError::InvalidLength { actual: hex.len() });
        }
        if let Some((index, _)) = hex
            .as_bytes()
            .iter()
            .enumerate()
            .find(|(_, byte)| !byte.is_ascii_hexdigit())
        {
            return Err(DeviceFingerprintParseError::InvalidHex { index });
        }
        Ok(Self(hex.to_ascii_lowercase()))
    }

    /// Infallible compatibility constructor for already-validated internal
    /// values. Inputs that can cross an I/O or RPC seam must call [`Self::parse`]
    /// and handle its error instead of relying on this assertion.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self::parse(raw).expect("DeviceFingerprint::new requires a valid SHA-256 fingerprint")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical, full-entropy and path-safe device identity.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId(format!("{DEVICE_ID_PREFIX}{}", self.0))
    }

    /// The canonical TLS pin spelling expected by the HTTPS adapter.
    #[must_use]
    pub fn tls_pin(&self) -> String {
        format!("{TLS_PREFIX}{}", self.0)
    }

    /// The short human-facing label. This is never a lookup key for new data.
    #[must_use]
    pub fn display_id(&self) -> String {
        format!(
            "{DISPLAY_PREFIX}{}",
            self.0[..DISPLAY_HEX_LEN].to_ascii_uppercase()
        )
    }

    /// Compatibility name retained for fleet callers while they migrate to
    /// the identity vocabulary.
    #[must_use]
    pub fn short_display_id(&self) -> String {
        self.display_id()
    }
}

impl fmt::Display for DeviceFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DeviceFingerprint {
    type Err = DeviceFingerprintParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl From<&str> for DeviceFingerprint {
    fn from(raw: &str) -> Self {
        Self::new(raw)
    }
}

/// All stable projections of one device identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    fingerprint: DeviceFingerprint,
    device_id: DeviceId,
    display_id: String,
}

impl DeviceIdentity {
    #[must_use]
    pub fn from_fingerprint(fingerprint: DeviceFingerprint) -> Self {
        let device_id = fingerprint.device_id();
        let display_id = fingerprint.display_id();
        Self {
            fingerprint,
            device_id,
            display_id,
        }
    }

    pub fn parse(raw_fingerprint: &str) -> Result<Self, DeviceFingerprintParseError> {
        DeviceFingerprint::parse(raw_fingerprint).map(Self::from_fingerprint)
    }

    #[must_use]
    pub fn fingerprint(&self) -> &DeviceFingerprint {
        &self.fingerprint
    }

    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    #[must_use]
    pub fn tls_pin(&self) -> String {
        self.fingerprint.tls_pin()
    }

    #[must_use]
    pub fn display_id(&self) -> &str {
        &self.display_id
    }
}

impl From<DeviceFingerprint> for DeviceIdentity {
    fn from(fingerprint: DeviceFingerprint) -> Self {
        Self::from_fingerprint(fingerprint)
    }
}

/// A durable device id projected into the two identity fields exposed at a
/// read boundary.
///
/// New rows contain a canonical full-fingerprint [`DeviceId`]. Older rows
/// may contain the historical `YLX-<8 hex>` alias and must remain readable
/// without inventing a fingerprint or rewriting their path/key. This type
/// validates and normalizes those two spellings in one place; it accepts no
/// other fallback identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeviceIdentity {
    device_id: DeviceId,
    display_id: String,
}

impl StoredDeviceIdentity {
    pub fn parse(device_id: &DeviceId) -> Result<Self, DeviceIdentityResolutionError> {
        let raw = device_id.as_str();
        if let Some(fingerprint) = parse_canonical_device_id(raw) {
            let identity = DeviceIdentity::from_fingerprint(fingerprint);
            return Ok(Self::from(&identity));
        }
        if let Some(display_id) = parse_legacy_alias(raw) {
            return Ok(Self {
                device_id: DeviceId(display_id.clone()),
                display_id,
            });
        }
        Err(DeviceIdentityResolutionError::InvalidDeviceId {
            device_id: raw.to_string(),
        })
    }

    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    #[must_use]
    pub fn display_id(&self) -> &str {
        &self.display_id
    }
}

impl From<&DeviceIdentity> for StoredDeviceIdentity {
    fn from(identity: &DeviceIdentity) -> Self {
        Self {
            device_id: identity.device_id().clone(),
            display_id: identity.display_id().to_string(),
        }
    }
}

/// Why a registered identity could not be resolved from a durable or RPC id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceIdentityResolutionError {
    #[error(
        "device id {device_id:?} is neither canonical ylx-<64 lowercase hex> nor a legacy YLX-<8 hex> alias"
    )]
    InvalidDeviceId { device_id: String },
    #[error("device id {device_id:?} is not registered")]
    Unknown { device_id: String },
    #[error("legacy device alias {alias:?} matches multiple registered devices: {candidates:?}")]
    AmbiguousLegacyAlias {
        alias: String,
        candidates: Vec<DeviceId>,
    },
}

/// Registered full identities plus the compatibility resolver for durable
/// short aliases written by older builds.
///
/// Registration never stores a short alias. Resolution accepts a canonical id
/// or a legacy display alias; a legacy alias resolves only when exactly one
/// registered fingerprint has that display projection.
#[derive(Debug, Clone, Default)]
pub struct DeviceIdentityResolver {
    identities: BTreeMap<DeviceFingerprint, DeviceIdentity>,
}

impl DeviceIdentityResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one full identity. Returns `true` only on first sight.
    pub fn insert(&mut self, identity: DeviceIdentity) -> bool {
        self.identities
            .insert(identity.fingerprint.clone(), identity)
            .is_none()
    }

    /// Resolves a canonical id or an unambiguous legacy short alias.
    pub fn resolve(
        &self,
        device_id: &DeviceId,
    ) -> Result<DeviceIdentity, DeviceIdentityResolutionError> {
        let raw = device_id.as_str();
        if let Some(fingerprint) = parse_canonical_device_id(raw) {
            return self.identities.get(&fingerprint).cloned().ok_or_else(|| {
                DeviceIdentityResolutionError::Unknown {
                    device_id: raw.to_string(),
                }
            });
        }

        let Some(alias) = parse_legacy_alias(raw) else {
            return Err(DeviceIdentityResolutionError::InvalidDeviceId {
                device_id: raw.to_string(),
            });
        };
        let matches = self
            .identities
            .values()
            .filter(|identity| identity.display_id == alias)
            .cloned()
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(DeviceIdentityResolutionError::Unknown {
                device_id: raw.to_string(),
            }),
            [identity] => Ok(identity.clone()),
            _ => Err(DeviceIdentityResolutionError::AmbiguousLegacyAlias {
                alias,
                candidates: matches
                    .into_iter()
                    .map(|identity| identity.device_id)
                    .collect(),
            }),
        }
    }

    /// Stable full-identity order for snapshots and fleet-wide work.
    #[must_use]
    pub fn identities(&self) -> Vec<DeviceIdentity> {
        self.identities.values().cloned().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

fn parse_canonical_device_id(raw: &str) -> Option<DeviceFingerprint> {
    let hex = raw.strip_prefix(DEVICE_ID_PREFIX)?;
    if hex.len() != FINGERPRINT_HEX_LEN
        || hex
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return None;
    }
    DeviceFingerprint::parse(hex).ok()
}

fn parse_legacy_alias(raw: &str) -> Option<String> {
    let prefix = raw.get(..DEVICE_ID_PREFIX.len())?;
    if !prefix.eq_ignore_ascii_case(DISPLAY_PREFIX) {
        return None;
    }
    let hex = &raw[DISPLAY_PREFIX.len()..];
    if hex.len() != DISPLAY_HEX_LEN || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(format!("{DISPLAY_PREFIX}{}", hex.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(prefix: &str, fill: char) -> DeviceFingerprint {
        DeviceFingerprint::parse(&format!("sha256:{prefix}{}", fill.to_string().repeat(56)))
            .unwrap()
    }

    #[test]
    fn parser_accepts_only_full_sha256_hex_and_normalizes_to_bare_lowercase() {
        let uppercase = "ABCDEF0123456789".repeat(4);
        let prefixed = DeviceFingerprint::parse(&format!("SHA256:{uppercase}")).unwrap();
        let bare = DeviceFingerprint::parse(&uppercase).unwrap();

        assert_eq!(prefixed, bare);
        assert_eq!(prefixed.as_str(), uppercase.to_ascii_lowercase());
        assert_eq!(prefixed.as_str().len(), FINGERPRINT_HEX_LEN);
    }

    #[test]
    fn parser_rejects_wrong_length_whitespace_non_ascii_and_non_hex() {
        assert!(matches!(
            DeviceFingerprint::parse(&"a".repeat(63)),
            Err(DeviceFingerprintParseError::InvalidLength { actual: 63 })
        ));
        assert!(DeviceFingerprint::parse(&format!(" {}", "a".repeat(64))).is_err());
        assert!(DeviceFingerprint::parse(&format!("{} ", "a".repeat(64))).is_err());
        assert!(DeviceFingerprint::parse(&format!("{}g", "a".repeat(63))).is_err());
        assert!(DeviceFingerprint::parse(&format!("{}é", "a".repeat(62))).is_err());
    }

    #[test]
    fn projections_have_one_canonical_spelling_each() {
        let fingerprint = fingerprint("abcdef01", '2');
        let identity = DeviceIdentity::from_fingerprint(fingerprint.clone());

        assert_eq!(fingerprint.as_str(), format!("abcdef01{}", "2".repeat(56)));
        assert_eq!(
            identity.device_id().as_str(),
            format!("ylx-abcdef01{}", "2".repeat(56))
        );
        assert_eq!(
            identity.tls_pin(),
            format!("sha256:abcdef01{}", "2".repeat(56))
        );
        assert_eq!(identity.display_id(), "YLX-ABCDEF01");
    }

    #[test]
    fn stored_identity_projects_canonical_and_legacy_ids_without_inventing_a_fingerprint() {
        let identity = DeviceIdentity::from_fingerprint(fingerprint("abcdef01", '2'));
        let canonical = StoredDeviceIdentity::parse(identity.device_id()).unwrap();
        assert_eq!(canonical.device_id(), identity.device_id());
        assert_eq!(canonical.display_id(), identity.display_id());

        let legacy = StoredDeviceIdentity::parse(&DeviceId("ylx-abcdef01".to_string())).unwrap();
        assert_eq!(legacy.device_id().as_str(), "YLX-ABCDEF01");
        assert_eq!(legacy.display_id(), "YLX-ABCDEF01");

        assert!(matches!(
            StoredDeviceIdentity::parse(&DeviceId("device-unknown".to_string())),
            Err(DeviceIdentityResolutionError::InvalidDeviceId { .. })
        ));
    }

    #[test]
    fn canonical_id_resolves_only_after_its_full_identity_is_registered() {
        let identity = DeviceIdentity::from_fingerprint(fingerprint("12345678", 'a'));
        let id = identity.device_id().clone();
        let mut resolver = DeviceIdentityResolver::new();

        assert!(matches!(
            resolver.resolve(&id),
            Err(DeviceIdentityResolutionError::Unknown { .. })
        ));
        assert!(resolver.insert(identity.clone()));
        assert!(!resolver.insert(identity.clone()));
        assert_eq!(resolver.resolve(&id).unwrap(), identity);
        assert_eq!(resolver.len(), 1);
    }

    #[test]
    fn legacy_alias_resolves_when_exactly_one_full_identity_matches() {
        let identity = DeviceIdentity::from_fingerprint(fingerprint("abcdef01", '1'));
        let mut resolver = DeviceIdentityResolver::new();
        resolver.insert(identity.clone());

        assert_eq!(
            resolver
                .resolve(&DeviceId("ylx-abcdef01".to_string()))
                .unwrap(),
            identity
        );
    }

    #[test]
    fn legacy_alias_reports_unknown_without_a_match() {
        let resolver = DeviceIdentityResolver::new();
        assert_eq!(
            resolver
                .resolve(&DeviceId("YLX-ABCDEF01".to_string()))
                .unwrap_err(),
            DeviceIdentityResolutionError::Unknown {
                device_id: "YLX-ABCDEF01".to_string()
            }
        );
    }

    #[test]
    fn legacy_alias_reports_every_candidate_when_short_labels_collide() {
        let a = DeviceIdentity::from_fingerprint(fingerprint("abcdef01", '1'));
        let b = DeviceIdentity::from_fingerprint(fingerprint("abcdef01", '2'));
        let mut resolver = DeviceIdentityResolver::new();
        resolver.insert(a.clone());
        resolver.insert(b.clone());

        assert_eq!(a.display_id(), b.display_id());
        assert_eq!(
            resolver
                .resolve(&DeviceId("YLX-ABCDEF01".to_string()))
                .unwrap_err(),
            DeviceIdentityResolutionError::AmbiguousLegacyAlias {
                alias: "YLX-ABCDEF01".to_string(),
                candidates: vec![a.device_id().clone(), b.device_id().clone()]
            }
        );
    }

    #[test]
    fn resolver_rejects_strings_that_are_neither_canonical_nor_legacy() {
        let resolver = DeviceIdentityResolver::new();
        assert!(matches!(
            resolver.resolve(&DeviceId("YLX-NOT-HEX".to_string())),
            Err(DeviceIdentityResolutionError::InvalidDeviceId { .. })
        ));
        assert!(matches!(
            resolver.resolve(&DeviceId(format!("ylx-{}", "A".repeat(64)))),
            Err(DeviceIdentityResolutionError::InvalidDeviceId { .. })
        ));
    }
}
