//! Durable executor for the pure `normalization` domain.
//!
//! `normalization` owns the state machine, media plan, validation verdicts,
//! exact profile and derived identity. This module owns the effects: durable
//! CAS, process lifetime, pair-sized filesystem transactions and final
//! publication. FFmpeg command lines and process handles remain behind the
//! `MediaProbe`/`MediaEncoder` ports.

mod control;
mod engine;
mod ports;
mod staging;
mod store;

pub use engine::{MediaNormalizerConfig, MediaNormalizerExecutor, NormalizerRunOutcome};
pub use ports::{
    CompletionNotificationSink, CreateDerivationOutcome, DerivationRepository,
    DerivedCommitEvidence, MediaNormalizerClock, MediaNormalizerPortError,
    MediaNormalizerScheduler, PairQualityEvidence, SegmentQualityAnalyzer, SnapshotSwapOutcome,
    SourceReadLease, SourceReadLeases, StoredDerivation,
};
pub use staging::{DerivedStaging, PairWorkspace, PublishedPair, StagingCommit, StagingError};
pub use store::{MediaStoreDerivationRepository, MediaStoreSourceReadLeases};

#[cfg(test)]
mod tests;
