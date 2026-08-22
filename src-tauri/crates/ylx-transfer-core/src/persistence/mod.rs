//! Durable persistence seams for the desktop application and transfer core.
//!
//! `AppStore` owns the secret-free application snapshot, while
//! `TransferStore` and the upload store own all durable transfer records.
//! The schema and migration helpers are shared by those stores; credentials
//! remain behind the credential vault.

pub mod app_store;
pub mod completion_consumer;
pub mod derived_upload_store;
pub mod error;
pub(crate) mod legacy_import;
pub mod schema;
pub mod transfer_store;
pub mod upload_store;

pub use app_store::{
    AppLibraryPayload, AppStore, AppStoreRevisionConflict, AppStoreSnapshot, MediaLibraryPayload,
};
pub use error::PersistenceError;

pub use schema::{
    is_valid_transition, latest_version as latest_schema_version, FileLedgerStatus, JobStateTag,
    CURRENT_JOB_SPEC_VERSION, MIGRATIONS as TRANSFER_MIGRATIONS,
};

// Issue #1 Phase 2 (commits 22-26): `TransferStore` — the durable authority
// for job identity, spec, ordered files, per-file ledger and state/version.
pub use transfer_store::{
    CreateJobError, CreateJobOutcome, DismissJobError, FileLedgerEntry, JobOperationKind,
    JobRequestConflict, JobSpecLoadError, LegacyImportError, LegacyImportOutcome,
    LegacyImportReport, MigrationMarker, OperationKind, RecoverableJob, RecoverableJobDetail,
    RecoveryBlocked, RecoveryBlockedReason, RetryJobError, RetryJobOutcome, RetryLineageRecord,
    StoredJob, TransferStore, LEGACY_PENDING_DOWNLOAD_MARKER,
};

// Issue #1 commits 29-30: the durable completion outbox and its
// idempotent consumer. A terminal outcome and the transition that produced
// it commit together (`TransferStore::complete_job`); the consumer applies
// it to the app library, emits, and only then acknowledges.
pub use completion_consumer::{
    drain_completions, Completion, CompletionProjection, DrainReport, ProjectionOutcome,
};
pub use derived_upload_store::{
    CheckpointSwapOutcome, DerivedUploadCreateOutcome, DerivedUploadJobSpec,
    DerivedUploadRetryError, DerivedUploadRetryOutcome, DerivedUploadStoreError,
    StoredDerivedUploadJob, MAX_DERIVED_UPLOAD_JSON_BYTES, UPLOAD_SUBJECT_DERIVED_BUNDLE,
    UPLOAD_SUBJECT_LIBRARY_PUBLICATION,
};
pub use transfer_store::{
    AckOutcome, CompleteJobError, CompleteJobOutcome, CompletionRecord, TerminalOutcome,
};
pub use upload_store::RepeatUploadJobError;
pub use upload_store::{
    LegacyUploadImportError, LegacyUploadImportOutcome, LegacyUploadImportReport, NewUpload,
    NewUploadJob, ReceiptDigestProof, StoredUpload, StoredUploadActivity, StoredUploadReceipt,
    UploadActivitySeed, UploadDesiredState, UploadJobConflict, UploadJobCreateAbort,
    UploadJobCreateError, UploadJobCreateOutcome, UploadJobError, UploadJobRequest, UploadJobSpec,
    UploadObjectRole, UploadPartRecord, UploadReceiptDigestProof, UploadReceiptError,
    UploadReceiptRole, UploadReceiptSeed, UploadStoreError, UploadUrlStyle, VerifiedUploadReceipt,
    LEGACY_PENDING_UPLOAD_MARKER,
};
