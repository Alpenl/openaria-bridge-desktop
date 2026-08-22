//! Durable repository for removable-media import and local normalization.
//!
//! The domain aggregates in `crate::ingest` and `crate::normalization` own
//! legal transitions. `MediaStore` owns atomic creation, expected-version
//! CAS, ordered recovery evidence, completion outboxes, immutable library
//! receipts and revision read/write leases.

mod derivation_jobs;
mod error;
mod generations;
mod import_jobs;
mod leases;
mod model;
mod outbox;
mod pipeline;
mod projection;
mod receipts;
mod schema;
mod store;
mod trust;

pub use error::MediaStoreError;
pub use model::{
    AcknowledgeOutcome, AcquireLeaseOutcome, AcquireLibraryLease, CompareAndSwapOutcome,
    CompleteDerivationOutcome, CompleteImportOutcome, CompleteOutcome, CompletionEnvelope,
    CreateDerivationJobError, CreateImportJobError, CreateImportPipelineOutcome, CreateJobConflict,
    CreateJobOutcome, CreatePipelineOutcome, DerivedReceipt, ImportCommitProjection,
    ImportLocatorSnapshot, ImportLocatorUpdate, LibraryImportReceipt, LibraryLeaseMode,
    LibraryRevisionKind, LibraryRevisionLease, PipelineDependency, PipelineSnapshot, PipelineStage,
    ReceiptWriteOutcome, Recoverable, RecoveryBlocked, RecoveryBlockedReason, ReleaseLeaseOutcome,
    RevisionedCollection, SourceReceipt, StoredDerivationJob, StoredImportJob,
    StoredMediaGeneration,
};
pub use schema::{
    latest_version as latest_schema_version, CURRENT_DERIVATION_SPEC_VERSION,
    CURRENT_IMPORT_SPEC_VERSION, MEDIA_STORE_IDENTITY, MIGRATIONS as MEDIA_STORE_MIGRATIONS,
};
pub use store::MediaStore;
pub use trust::{
    pairing_evidence_digest, validate_producer_key_fingerprint, ConfirmTrustedProducerOutcome,
    TrustedInlinePublicationKey, TrustedProducerError, TrustedProducerKeyReceipt,
    TrustedProducerRegistry,
};
