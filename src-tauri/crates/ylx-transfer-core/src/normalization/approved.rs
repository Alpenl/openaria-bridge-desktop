//! Read-only registry of production-approved normalization profiles.
//!
//! The manifest is a release artifact compiled into the binary, not a user
//! setting and not something downloaded at runtime. It carries only digests:
//! the five approval reports themselves live in versioned release evidence, so
//! a profile can never become "approved" by editing a JSON file that also
//! contains the reports it claims to be justified by.
//!
//! Loading is deliberately reconstructive. Each entry names a quality variant;
//! the registry rebuilds that exact candidate profile from code, recomputes its
//! canonical revision, and only then compares it against the revision the
//! manifest declares. A manifest therefore cannot introduce a profile whose
//! encoding parameters this build does not implement, and cannot approve a
//! revision that no longer corresponds to the parameters it was reviewed under.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::identity::{ProfileRevision, SourceManifestDigest};
use super::profile::{
    EncoderBuild, EncoderCompatibilityClass, NormalizationProfile, ProfileApprovalEvidence,
    QualityVariant,
};

pub const APPROVED_PROFILE_MANIFEST_SCHEMA: &str = "ylx-transfer/approved-normalization-profiles";
pub const APPROVED_PROFILE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Upper bound on manifest size. The manifest holds digests and timestamps, so
/// anything larger is malformed rather than merely long.
pub const MAX_APPROVED_PROFILE_MANIFEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovedProfileError {
    #[error("approved-profile manifest exceeded {MAX_APPROVED_PROFILE_MANIFEST_BYTES} bytes")]
    ManifestTooLarge,
    #[error("approved-profile manifest is not valid JSON: {0}")]
    Malformed(String),
    #[error("approved-profile manifest declares schema {found:?}, expected {expected:?}")]
    UnexpectedSchema { found: String, expected: String },
    #[error("approved-profile manifest declares schema version {found}, expected {expected}")]
    UnexpectedSchemaVersion { found: u32, expected: u32 },
    #[error("approved-profile manifest lists quality variant {variant:?} more than once")]
    DuplicateVariant { variant: String },
}

/// Why one manifest entry did not become an approved profile.
///
/// Rejections are retained rather than discarded so the capability report can
/// say which profile is unavailable and why, instead of silently presenting an
/// empty registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedApprovedProfile {
    pub quality_variant: QualityVariant,
    pub declared_revision: ProfileRevision,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
struct ApprovedProfileManifest {
    schema: String,
    schema_version: u32,
    #[serde(default)]
    entries: Vec<ApprovedProfileEntry>,
}

#[derive(Debug, Deserialize)]
struct ApprovedProfileEntry {
    quality_variant: QualityVariant,
    profile_revision: ProfileRevision,
    encoder_compatibility_class: String,
    approved_at: String,
    reports: ApprovalReportDigests,
}

/// The five reports §9.5 requires before a candidate becomes production.
#[derive(Debug, Deserialize)]
struct ApprovalReportDigests {
    quality_corpus: SourceManifestDigest,
    throughput_resource: SourceManifestDigest,
    stereo_cv: SourceManifestDigest,
    encoder_distribution_legal_review: SourceManifestDigest,
    playback_compatibility: SourceManifestDigest,
}

/// Approved profiles compatible with one running encoder build.
#[derive(Debug, Clone, Default)]
pub struct ApprovedProfileRegistry {
    profiles: BTreeMap<String, NormalizationProfile>,
    rejected: Vec<RejectedApprovedProfile>,
}

impl ApprovedProfileRegistry {
    /// An empty registry. Every normalization request fails closed against it,
    /// which is the correct state while the approval reports do not exist.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load and validate a release manifest against the running encoder build.
    ///
    /// A manifest-level problem is an error: the build's own release artifact
    /// is malformed and nothing about it can be trusted. An entry-level
    /// problem only makes that entry unavailable, so one unreviewed profile
    /// cannot disable the others.
    pub fn from_manifest_bytes(
        bytes: &[u8],
        build: &EncoderBuild,
    ) -> Result<Self, ApprovedProfileError> {
        if bytes.len() > MAX_APPROVED_PROFILE_MANIFEST_BYTES {
            return Err(ApprovedProfileError::ManifestTooLarge);
        }
        let manifest: ApprovedProfileManifest = serde_json::from_slice(bytes)
            .map_err(|error| ApprovedProfileError::Malformed(error.to_string()))?;
        if manifest.schema != APPROVED_PROFILE_MANIFEST_SCHEMA {
            return Err(ApprovedProfileError::UnexpectedSchema {
                found: manifest.schema,
                expected: APPROVED_PROFILE_MANIFEST_SCHEMA.to_string(),
            });
        }
        if manifest.schema_version != APPROVED_PROFILE_MANIFEST_SCHEMA_VERSION {
            return Err(ApprovedProfileError::UnexpectedSchemaVersion {
                found: manifest.schema_version,
                expected: APPROVED_PROFILE_MANIFEST_SCHEMA_VERSION,
            });
        }

        let mut seen = BTreeMap::new();
        let mut registry = Self::default();
        for entry in manifest.entries {
            let variant_key = format!("{:?}", entry.quality_variant);
            if seen.insert(variant_key.clone(), ()).is_some() {
                return Err(ApprovedProfileError::DuplicateVariant {
                    variant: variant_key,
                });
            }
            match approve_entry(&entry, build) {
                Ok(profile) => {
                    registry
                        .profiles
                        .insert(profile.profile_revision().as_str().to_string(), profile);
                }
                Err(reason) => registry.rejected.push(RejectedApprovedProfile {
                    quality_variant: entry.quality_variant,
                    declared_revision: entry.profile_revision,
                    reason,
                }),
            }
        }
        Ok(registry)
    }

    /// Resolve one exact revision. This is the only way a derivation may
    /// obtain a profile: an unlisted or rejected revision has no entry, so
    /// `NormalizationProfile::require_approved` is never reached with a
    /// candidate.
    #[must_use]
    pub fn resolve(&self, revision: &ProfileRevision) -> Option<&NormalizationProfile> {
        self.profiles.get(revision.as_str())
    }

    #[must_use]
    pub fn approved_profiles(&self) -> Vec<&NormalizationProfile> {
        self.profiles.values().collect()
    }

    #[must_use]
    pub fn rejected(&self) -> &[RejectedApprovedProfile] {
        &self.rejected
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

fn approve_entry(
    entry: &ApprovedProfileEntry,
    build: &EncoderBuild,
) -> Result<NormalizationProfile, String> {
    let compatibility = EncoderCompatibilityClass::parse(entry.encoder_compatibility_class.clone())
        .map_err(|error| format!("invalid encoder compatibility class: {error}"))?;

    // Rebuild the candidate from code and recompute its canonical revision.
    // If the manifest's revision disagrees, the reviewed parameters and the
    // implemented parameters are not the same thing any more.
    let candidate = NormalizationProfile::candidate(entry.quality_variant)
        .map_err(|error| format!("this build cannot construct the profile: {error}"))?;
    if candidate.profile_revision() != &entry.profile_revision {
        return Err(format!(
            "recomputed profile revision {} does not match the approved revision {}",
            candidate.profile_revision(),
            entry.profile_revision
        ));
    }
    if candidate.encoder_compatibility_class() != &compatibility {
        return Err(
            "approved encoder compatibility class does not match the profile's own class"
                .to_string(),
        );
    }
    // A profile approved for a different encoder class is not approved for
    // the encoder actually installed here. This is a qualification boundary,
    // not a runtime fallback.
    candidate
        .require_compatible_encoder(build)
        .map_err(|error| format!("the installed encoder cannot implement this profile: {error}"))?;

    let evidence = ProfileApprovalEvidence::new(
        entry.profile_revision.clone(),
        entry.reports.quality_corpus.clone(),
        entry.reports.throughput_resource.clone(),
        entry.reports.stereo_cv.clone(),
        entry.reports.encoder_distribution_legal_review.clone(),
        entry.reports.playback_compatibility.clone(),
        entry.approved_at.clone(),
    )
    .map_err(|error| format!("invalid approval evidence: {error}"))?;

    candidate
        .approve(evidence)
        .map_err(|error| format!("approval was rejected: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;

    use super::super::identity::EncoderBuildFingerprint;

    fn build() -> EncoderBuild {
        EncoderBuild::new(
            "ffmpeg",
            "ffmpeg version 7.0",
            EncoderBuildFingerprint::from_canonical_bytes(b"test-build"),
            EncoderCompatibilityClass::x265_software_v1(),
            Map::new(),
        )
        .expect("encoder build")
    }

    fn digest(seed: &str) -> String {
        format!(
            "{}",
            SourceManifestDigest::from_canonical_bytes(seed.as_bytes())
        )
    }

    fn manifest(revision: &str) -> String {
        format!(
            r#"{{
              "schema": "{APPROVED_PROFILE_MANIFEST_SCHEMA}",
              "schema_version": {APPROVED_PROFILE_MANIFEST_SCHEMA_VERSION},
              "entries": [
                {{
                  "quality_variant": "mjpeg_crf20",
                  "profile_revision": "{revision}",
                  "encoder_compatibility_class": "x265-software-hevc-main-8bit-v1",
                  "approved_at": "2026-08-05T00:00:00Z",
                  "reports": {{
                    "quality_corpus": "{}",
                    "throughput_resource": "{}",
                    "stereo_cv": "{}",
                    "encoder_distribution_legal_review": "{}",
                    "playback_compatibility": "{}"
                  }}
                }}
              ]
            }}"#,
            digest("corpus"),
            digest("throughput"),
            digest("stereo"),
            digest("legal"),
            digest("playback"),
        )
    }

    #[test]
    fn an_entry_whose_revision_matches_the_rebuilt_profile_is_approved() {
        let expected = NormalizationProfile::candidate(QualityVariant::MjpegCrf20)
            .expect("candidate")
            .profile_revision()
            .clone();
        let registry = ApprovedProfileRegistry::from_manifest_bytes(
            manifest(expected.as_str()).as_bytes(),
            &build(),
        )
        .expect("manifest");
        let profile = registry.resolve(&expected).expect("approved profile");
        assert!(profile.require_approved().is_ok());
        assert!(registry.rejected().is_empty());
    }

    #[test]
    fn a_revision_that_no_longer_matches_the_code_makes_only_that_entry_unavailable() {
        let stale = format!("sha256:{}", "1".repeat(64));
        let registry =
            ApprovedProfileRegistry::from_manifest_bytes(manifest(&stale).as_bytes(), &build())
                .expect("manifest");
        assert!(registry.is_empty());
        assert_eq!(registry.rejected().len(), 1);
    }

    #[test]
    fn an_empty_manifest_loads_and_approves_nothing() {
        let bytes = format!(
            r#"{{"schema":"{APPROVED_PROFILE_MANIFEST_SCHEMA}","schema_version":{APPROVED_PROFILE_MANIFEST_SCHEMA_VERSION},"entries":[]}}"#
        );
        let registry = ApprovedProfileRegistry::from_manifest_bytes(bytes.as_bytes(), &build())
            .expect("manifest");
        assert!(registry.is_empty());
    }

    #[test]
    fn a_foreign_schema_is_rejected_outright() {
        let bytes = r#"{"schema":"something-else","schema_version":1,"entries":[]}"#;
        assert!(matches!(
            ApprovedProfileRegistry::from_manifest_bytes(bytes.as_bytes(), &build()),
            Err(ApprovedProfileError::UnexpectedSchema { .. })
        ));
    }
}
