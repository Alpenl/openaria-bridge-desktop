//! Deep removable-media/LAN recording-ingest implementation.
//!
//! The public domain contract lives in `crate::ingest`; this module executes
//! its effects while keeping byte copying, reader serialization, staging and
//! publication details behind that small interface.

mod engine;
mod ports;
mod reader_gate;
mod store;

pub use engine::{
    IngestRunOutcome, RecordingIngestConfig, RecordingIngestExecutor, RecordingIngestorError,
};
pub use ports::{
    ArtifactSourceResolver, CandidateCatalog, CompareAndSwapOutcome, CreateStoredImportOutcome,
    ImportNotificationSink, ImportRepository, ImportScheduler, IngestClock, IngestPortError,
    LocalSpace, ResolvedArtifactSource, SourcePublishLease, SourcePublishLeases, StoredImport,
};
pub use store::{MediaStoreImportRepository, MediaStoreSourcePublishLeases};

#[cfg(test)]
mod tests;
