//! Compiled-in approved normalization profile manifest.
//!
//! The manifest is a release artifact, not a setting: it is embedded with
//! `include_bytes!`, so it cannot be edited on a user's machine and is never
//! fetched over the network. Approving a profile means shipping a new binary
//! whose manifest carries the five review-report digests for that exact
//! profile revision.
//!
//! Parsing and validation live in core (`ApprovedProfileRegistry`); this module
//! only supplies the bytes and binds them to the encoder build actually
//! installed on this machine.

use ylx_transfer_core::normalization::{
    ApprovedProfileError, ApprovedProfileRegistry, EncoderBuild,
};

/// The release manifest. Shipped empty until the HEVC V1 candidate profiles
/// have their approval reports, which is what keeps normalization
/// capability-unavailable rather than silently deriving against unreviewed
/// encoding parameters.
pub const APPROVED_PROFILE_MANIFEST: &[u8] =
    include_bytes!("../../resources/media-profiles/approved_profiles.json");

/// Load the manifest for one running encoder build.
///
/// A malformed manifest is an error, not an empty registry: this build's own
/// release artifact would be untrustworthy, and silently continuing with "no
/// approved profiles" would look identical to the legitimate empty case.
pub fn load_approved_profiles(
    build: &EncoderBuild,
) -> Result<ApprovedProfileRegistry, ApprovedProfileError> {
    ApprovedProfileRegistry::from_manifest_bytes(APPROVED_PROFILE_MANIFEST, build)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use ylx_transfer_core::normalization::{EncoderBuildFingerprint, EncoderCompatibilityClass};

    fn build() -> EncoderBuild {
        EncoderBuild::new(
            "ffmpeg",
            "ffmpeg version test",
            EncoderBuildFingerprint::from_canonical_bytes(b"test-build"),
            EncoderCompatibilityClass::x265_software_v1(),
            BTreeMap::new(),
        )
        .expect("encoder build")
    }

    #[test]
    fn the_shipped_manifest_parses_and_currently_approves_nothing() {
        let registry = load_approved_profiles(&build()).expect("shipped manifest is well formed");
        assert!(
            registry.is_empty(),
            "shipping an approved profile requires its five review reports"
        );
        assert!(registry.rejected().is_empty());
    }
}
