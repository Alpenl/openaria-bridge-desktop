//! Durable, truthful projection of one imported source across its local,
//! derived, remote, removable-media, and retention layers.
//!
//! This module is deliberately not a second job store. Import/derivation
//! jobs may be retired after their completion outboxes are acknowledged;
//! [`LibraryImportReceipt`] remains the long-lived duplicate-import fence,
//! while [`MediaLibraryProjection`] is the rebuildable user-facing view.
//!
//! Filesystem mutation is outside this module. Callers consume a shared or
//! exclusive revision lease through [`LibraryRevisionLeasePort`] before
//! reading, publishing, or removing an immutable tree. Retention evaluation
//! can only propose removal of a verified *local source* tree. There is no
//! card-write or card-delete effect in this API.

mod app_store_repository;
mod dedup;
mod lease;
mod model;
mod projection;
mod retention;

pub use crate::media_store::LibraryImportReceipt;

pub use app_store_repository::{
    AppStoreMediaLibraryProjectionRepository, MAX_MEDIA_LIBRARY_PAYLOAD_BYTES,
};
pub use dedup::{
    resolve_import, ImportDeduplication, ImportReceiptLookup, LocalImportEvidenceReader,
    ReceiptEvidenceFailure, ReceiptPortError, RevalidatedImportEvidence,
};
pub use lease::LibraryRevisionLeasePort;
pub use model::{
    CardPresence, DerivedLocalVerified, DerivedTreeLocator, ImmutableTreeLocator, LibraryEntryKey,
    MediaLibraryProjection, ProjectedSourceArchive, ProjectionModelError, RemoteUploadState,
    SourceArchiveProjection, SourceArchiveProof, SourceLocalState, SourceLocalVerified,
    SourceTreeLocator, UploadBundleProjection,
};
pub use projection::{
    CompareAndSwapOutcome, ExpectedProjectionRevision, LibraryProjectionCommand,
    LibraryProjectionRepository, LibraryProjector, LoadedProjection, ProjectionCommit,
    ProjectionError, ProjectionStoreError,
};
pub use retention::{
    evaluate_retention, RetentionBlockReason, RetentionEffectProposal, RetentionEvaluation,
    RetentionProjection,
};
