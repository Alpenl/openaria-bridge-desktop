//! Commit 21: `JobIdentity` / `JobSpec` are field-private and can only be
//! constructed complete.
//!
//! The natural key is (device, session, revision), and a spec's file plan
//! and publication material can only be supplied *together* — there is no
//! setter, no public field and no `Deserialize`, so a caller cannot pair a
//! legitimate signature with a file list it does not cover.

#[path = "transfer_store_support/common.rs"]
mod transfer_store_support;

use transfer_store_support::{publication, sha};
use ylx_transfer_core::domain::{
    DeviceId, FileId, JobFileSpec, JobIdentity, JobSpec, JobSpecError, PublicationMaterial,
    RequestDigest, SessionId,
};

fn identity(device: &str, session: &str, revision: &str) -> JobIdentity {
    JobIdentity::new(
        DeviceId(device.to_string()),
        SessionId(session.to_string()),
        revision,
    )
    .expect("valid identity")
}

// ---------------------------------------------------------------------
// JobIdentity
// ---------------------------------------------------------------------

#[test]
fn identity_is_exactly_device_session_revision() {
    let id = identity("pi-01", "session-x", "rev-1");
    assert_eq!(id.device_id().as_str(), "pi-01");
    assert_eq!(id.session_id().as_str(), "session-x");
    assert_eq!(id.revision(), "rev-1");
}

#[test]
fn every_identity_component_must_be_non_empty() {
    for (device, session, revision, field) in [
        ("", "s", "r", "device_id"),
        ("d", "   ", "r", "session_id"),
        ("d", "s", "", "revision"),
    ] {
        let error = JobIdentity::new(
            DeviceId(device.to_string()),
            SessionId(session.to_string()),
            revision,
        )
        .expect_err("blank identity components must be rejected");
        assert_eq!(error, JobSpecError::Empty { field });
    }
}

#[test]
fn the_natural_key_cannot_be_forged_by_moving_a_separator_between_components() {
    // A naive `format!("{device}|{session}|{revision}")` would give these
    // two *different* logical transfers the same key.
    let a = identity("pi|01", "session", "rev-1");
    let b = identity("pi", "01|session", "rev-1");
    assert_ne!(a.natural_key(), b.natural_key());

    // Same components => same key, always.
    assert_eq!(
        identity("pi-01", "session-x", "rev-1").natural_key(),
        identity("pi-01", "session-x", "rev-1").natural_key()
    );
}

// ---------------------------------------------------------------------
// JobFileSpec / PublicationMaterial
// ---------------------------------------------------------------------

#[test]
fn a_file_spec_requires_64_lowercase_hex_characters_of_digest() {
    for bad in ["", "abc", &"A".repeat(64), &"z".repeat(64), &sha(1)[..63]] {
        let error = JobFileSpec::new(FileId("f-1".into()), "video/a.mp4", 10, bad)
            .expect_err("a non-sha256 digest must be rejected");
        assert!(
            matches!(
                error,
                JobSpecError::NotSha256Hex {
                    field: "sha256",
                    ..
                }
            ),
            "unexpected error for {bad:?}: {error:?}"
        );
    }
    assert!(JobFileSpec::new(FileId("f-1".into()), "video/a.mp4", 10, sha(0xab)).is_ok());
}

#[test]
fn publication_material_is_rejected_unless_structurally_complete() {
    /// `(payload, signature, public_key, expected offending field)`.
    type Case = (Vec<u8>, Vec<u8>, Vec<u8>, &'static str);

    let cases: [Case; 3] = [
        (vec![], vec![7; 64], vec![9; 32], "publication.payload"),
        (vec![1], vec![7; 63], vec![9; 32], "publication.signature"),
        (vec![1], vec![7; 64], vec![9; 31], "publication.public_key"),
    ];
    for (payload, signature, key, field) in cases {
        let error = PublicationMaterial::new("rev-1", payload, signature, key)
            .expect_err("incomplete publication material must be rejected");
        match error {
            JobSpecError::Empty { field: got } | JobSpecError::BadLength { field: got, .. } => {
                assert_eq!(got, field)
            }
            other => panic!("unexpected error for {field}: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------
// JobSpec — construction is all-or-nothing
// ---------------------------------------------------------------------

fn inventory() -> Vec<JobFileSpec> {
    vec![
        transfer_store_support::file("f-0001", 1024, 0xaa),
        transfer_store_support::file("f-0002", 64, 0xbb),
    ]
}

fn ids(list: &[&str]) -> Vec<FileId> {
    list.iter().map(|id| FileId((*id).to_string())).collect()
}

#[test]
fn a_complete_spec_exposes_the_inventory_and_the_request_plan_separately() {
    let spec = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        inventory(),
        &ids(&["f-0002"]),
        false,
        "2026-08-01",
    )
    .expect("a partial-session spec is legal");

    assert_eq!(spec.session_files().len(), 2);
    let requested: Vec<&str> = spec
        .requested_files()
        .map(|f| f.file_id().as_str())
        .collect();
    assert_eq!(requested, ["f-0002"]);
    assert!(!spec.full_session());
    // A requested file always carries the *signed* size/digest, because it
    // is selected out of the inventory rather than supplied alongside it.
    assert_eq!(spec.requested_files().next().unwrap().size_bytes(), 64);
}

#[test]
fn the_publication_revision_must_match_the_identity_revision() {
    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-2"),
        inventory(),
        &ids(&["f-0001", "f-0002"]),
        true,
        "",
    )
    .expect_err("a signature for another revision must not be attachable");
    assert!(
        matches!(error, JobSpecError::RevisionMismatch { .. }),
        "got {error:?}"
    );
}

#[test]
fn a_requested_file_outside_the_signed_inventory_is_rejected() {
    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        inventory(),
        &ids(&["f-0001", "f-9999"]),
        false,
        "",
    )
    .expect_err("the plan may only select from the signed inventory");
    assert_eq!(
        error,
        JobSpecError::RequestedFileNotInInventory {
            file_id: "f-9999".into()
        }
    );
}

#[test]
fn duplicate_files_are_rejected_in_both_the_inventory_and_the_plan() {
    let duplicated = vec![
        transfer_store_support::file("f-0001", 1024, 0xaa),
        transfer_store_support::file("f-0001", 1024, 0xaa),
    ];
    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        duplicated,
        &ids(&["f-0001"]),
        false,
        "",
    )
    .expect_err("a duplicated inventory entry must be rejected");
    assert_eq!(
        error,
        JobSpecError::DuplicateInventoryFile {
            file_id: "f-0001".into()
        }
    );

    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        inventory(),
        &ids(&["f-0001", "f-0001"]),
        false,
        "",
    )
    .expect_err("a duplicated request entry must be rejected");
    assert_eq!(
        error,
        JobSpecError::DuplicateRequestedFile {
            file_id: "f-0001".into()
        }
    );
}

#[test]
fn a_full_session_spec_must_cover_the_whole_inventory() {
    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        inventory(),
        &ids(&["f-0001"]),
        true,
        "",
    )
    .expect_err("claiming full_session while requesting a subset must fail");
    assert_eq!(
        error,
        JobSpecError::IncompleteFullSession {
            inventory: 2,
            requested: 1
        }
    );
}

#[test]
fn empty_inventories_and_empty_plans_are_rejected() {
    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        vec![],
        &ids(&["f-0001"]),
        false,
        "",
    )
    .expect_err("a spec with no signed inventory is not a spec");
    assert_eq!(
        error,
        JobSpecError::Empty {
            field: "session_files"
        }
    );

    let error = JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        inventory(),
        &[],
        false,
        "",
    )
    .expect_err("a spec that transfers nothing is not a spec");
    assert_eq!(
        error,
        JobSpecError::Empty {
            field: "requested_file_ids"
        }
    );
}

// ---------------------------------------------------------------------
// request_digest
// ---------------------------------------------------------------------

fn spec_of(files: &[(&str, u64, u8)], requested: &[&str], full: bool, label: &str) -> JobSpec {
    JobSpec::new(
        identity("pi-01", "session-x", "rev-1"),
        publication("rev-1"),
        files
            .iter()
            .map(|(id, size, seed)| transfer_store_support::file(id, *size, *seed))
            .collect(),
        &ids(requested),
        full,
        label,
    )
    .expect("valid spec")
}

#[test]
fn the_request_digest_is_stable_for_identical_content() {
    let a = spec_of(&[("f-0001", 1024, 0xaa)], &["f-0001"], true, "label");
    let b = spec_of(&[("f-0001", 1024, 0xaa)], &["f-0001"], true, "label");
    assert_eq!(a.request_digest(), b.request_digest());
}

#[test]
fn the_request_digest_changes_when_any_transferred_content_changes() {
    let base = spec_of(
        &[("f-0001", 1024, 0xaa), ("f-0002", 64, 0xbb)],
        &["f-0001", "f-0002"],
        true,
        "label",
    );
    let variants = [
        // different expected size
        spec_of(
            &[("f-0001", 999, 0xaa), ("f-0002", 64, 0xbb)],
            &["f-0001", "f-0002"],
            true,
            "label",
        ),
        // different expected digest
        spec_of(
            &[("f-0001", 1024, 0xcc), ("f-0002", 64, 0xbb)],
            &["f-0001", "f-0002"],
            true,
            "label",
        ),
        // different request order
        spec_of(
            &[("f-0001", 1024, 0xaa), ("f-0002", 64, 0xbb)],
            &["f-0002", "f-0001"],
            true,
            "label",
        ),
        // subset instead of whole session
        spec_of(
            &[("f-0001", 1024, 0xaa), ("f-0002", 64, 0xbb)],
            &["f-0001"],
            false,
            "label",
        ),
    ];
    for (index, variant) in variants.iter().enumerate() {
        assert_ne!(
            base.request_digest(),
            variant.request_digest(),
            "variant {index} must not digest equal to the base request"
        );
    }
}

#[test]
fn the_cosmetic_date_label_is_not_part_of_the_request_digest() {
    let a = spec_of(&[("f-0001", 1024, 0xaa)], &["f-0001"], true, "2026-08-01");
    let b = spec_of(&[("f-0001", 1024, 0xaa)], &["f-0001"], true, "yesterday");
    assert_eq!(
        a.request_digest(),
        b.request_digest(),
        "a display-only label difference is the same request, not a conflict"
    );
    assert_ne!(a.date_label(), b.date_label());
}

#[test]
fn a_different_publication_signature_is_a_different_request() {
    let identity = identity("pi-01", "session-x", "rev-1");
    let other_signature =
        PublicationMaterial::new("rev-1", vec![1, 2, 3, 4], vec![8u8; 64], vec![9u8; 32])
            .expect("valid");
    let a = spec_of(&[("f-0001", 1024, 0xaa)], &["f-0001"], true, "l");
    let b = JobSpec::new(
        identity,
        other_signature,
        vec![transfer_store_support::file("f-0001", 1024, 0xaa)],
        &ids(&["f-0001"]),
        true,
        "l",
    )
    .expect("valid");
    assert_ne!(a.request_digest(), b.request_digest());
}

#[test]
fn request_digests_round_trip_through_hex() {
    let digest = spec_of(&[("f-0001", 1, 0xaa)], &["f-0001"], true, "l").request_digest();
    let hex = digest.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(RequestDigest::from_hex(&hex).expect("round trip"), digest);
    assert_eq!(hex, digest.to_string());
    assert!(RequestDigest::from_hex("not-a-digest").is_err());
}
