//! Library-facing seams for safe local artifacts, staged publication,
//! downloads, and object-store uploads.
//!
//! `object_store_port` is the one real (non-placeholder) addition here,
//! from task SPIKE-PC-S3 — an explicitly authorized early spike for the
//! S3/ObjectStore seam (plan section 9.3), run ahead of PC-00/PC-06
//! because it does not depend on the Pi wire protocol. See that module's
//! doc comment for full status/scope. It lives under `library/` rather
//! than in `ports.rs` because it is domain-shaped (many upload/receipt
//! types, not just a get/set/delete secret seam) and because `domain/`,
//! `device/`, and `transfer/` are other future tasks' territory that
//! SPIKE-PC-S3 was not authorized to touch.

pub mod object_store_port;

/// `download` is a second real (non-placeholder) addition here, from task
/// SPIKE-PC-DOWNLOAD — an explicitly authorized early spike for the
/// download-engine seam (plan section 9.2), run ahead of PC-00/PC-04 for
/// the same reason `object_store_port` was: it does not depend on Pi's
/// real wire format, only a generic `DownloadSource` abstraction. See that
/// module's doc comment for full status/scope.
pub mod download;

/// `artifact` (issue #1, commit 32) is the single judge of what a job
/// already has on disk for each expected file — final file, `.part`
/// partial and journal/checkpoint together. Both `download::download_file`
/// (which reuses an already-verified file instead of re-fetching it) and
/// `transfer::progress` (which sums the same evidence rather than keeping
/// an independent counter) consume its verdicts, so recovery and the
/// progress bar cannot drift apart.
pub mod artifact;

/// `staging` (issue #1, commits 63/64) is where a *whole session* is
/// assembled: a hidden, revision-scoped directory under the library root
/// that becomes the visible session with one atomic `rename`, and never
/// before. It is what stops a half-finished session from leaking into the
/// library tree one file at a time, and what lets crash recovery tell
/// whether the process died before or after that rename.
pub mod staging;

/// The `DownloadSource` seam's shared contract suite (issue #1, commit 10),
/// run against both the in-memory fake used by `download`'s own tests and
/// the production `PiDownloadSource` in `ylx-transfer-adapters`. Test
/// scaffolding only: compiled for this crate's own test build, or for a
/// dependent's test build via the `test-support` feature — never in a
/// release binary.
#[cfg(any(test, feature = "test-support"))]
pub mod download_contract;

/// The `ObjectStorePort` seam's shared contract suite (issue #1, commits
/// 69/70), run against the in-memory store here and against the
/// production `S3ObjectStore` — over a real HTTP fake and, in an
/// `#[ignore]`d lane, over a real MinIO — in `ylx-transfer-adapters`.
/// Same compile gating as `download_contract`: test builds only.
#[cfg(any(test, feature = "test-support"))]
pub mod object_store_contract;
