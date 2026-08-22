//! Shared fixtures for the issue #1 Phase 2 (`TransferStore`) tests.
//!
//! Everything here builds *valid* domain values through the real
//! constructors — no test in this batch is allowed to fabricate a
//! `JobSpec` by hand, because "a spec can only exist complete" is the
//! property commit 21 is defending.

use ylx_transfer_core::domain::{DeviceId, JobIdentity, JobSpec, SessionId};

include!("common.rs");

/// A whole-session spec over `(file_id, size, sha-seed)` triples.
pub fn full_session_spec(
    device: &str,
    session: &str,
    revision: &str,
    files: &[(&str, u64, u8)],
) -> JobSpec {
    let requested: Vec<FileId> = files
        .iter()
        .map(|(id, _, _)| FileId(id.to_string()))
        .collect();
    spec_with(device, session, revision, files, &requested, true)
}

pub fn spec_with(
    device: &str,
    session: &str,
    revision: &str,
    files: &[(&str, u64, u8)],
    requested: &[FileId],
    full_session: bool,
) -> JobSpec {
    let identity = JobIdentity::new(
        DeviceId(device.to_string()),
        SessionId(session.to_string()),
        revision,
    )
    .expect("fixture identity is valid");
    let inventory: Vec<JobFileSpec> = files
        .iter()
        .map(|(id, size, seed)| file(id, *size, *seed))
        .collect();
    JobSpec::new(
        identity,
        publication(revision),
        inventory,
        requested,
        full_session,
        "2026-08-01",
    )
    .expect("fixture spec is valid")
}

/// The canonical two-file whole-session job used by most tests.
pub fn sample_spec() -> JobSpec {
    full_session_spec(
        "pi-01",
        "session-x",
        "rev-1",
        &[("f-0001", 1024, 0xaa), ("f-0002", 64, 0xbb)],
    )
}
