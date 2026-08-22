//! `ylx-transfer-core` — shared domain, transfer, library, and persistence
//! primitives for the desktop application.
//!
//! The crate keeps persistence and credential storage independent from the
//! Tauri layer. `AppStore` is the secret-free application snapshot authority;
//! `TransferStore` and the related journal/upload stores own durable transfer
//! state, while the credential vault keeps raw secrets out of SQLite.

pub mod credential_vault;
pub mod device;
pub mod domain;
pub mod ingest;
pub mod library;
pub mod media_library;
pub mod media_normalizer;
pub mod media_pipeline;
pub mod media_store;
pub mod normalization;
pub mod persistence;
pub mod publication;
pub mod recording_ingestor;
pub mod secret;
pub mod transfer;

// PC-00 convenience re-exports of the now-frozen domain/device/transfer
// tagged types (plan section 5.4 / section 16 "F6"), so downstream PC-02/
// 03/05/08/09/10 tasks can `use ylx_transfer_core::{DeviceId, ...}`
// without reaching into submodules. Additive only — every name below also
// remains reachable through its owning module.
pub use device::{CaptureActivityState, ConnectionState, Device, DiscoveryState, PairingPhase};
pub use domain::{
    DeviceId, FileId, FileRole, ManifestFileEntry, PublicationManifest, PublicationSignature,
    SessionId,
};
pub use secret::Secret;
pub use transfer::{FailureCode, JobProgress, TransferJob, TransferJobState};

/// Deterministic test-support primitives (rendezvous, deferred one-shot,
/// fake clock, injectable fault point, recording event sink) shared by
/// this crate's concurrency tests. Compiled only for this crate's own
/// `cargo test` run, or for a dependant that opts in via the `testing`
/// cargo feature — never in a production build.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
