//! Durable, versioned PC media normalization domain.
//!
//! This module deliberately owns the policy-heavy part of normalization:
//! exact profiles, media planning, validation gates, derived identities and
//! the pure derivation-job aggregate. Platform adapters only probe media and
//! own encoder processes; they cannot manufacture a committed derivative.

mod approved;
mod identity;
mod job;
mod manifest;
mod plan;
mod ports;
mod profile;
mod rational;
mod validation;

pub use crate::ingest::{SourceArtifactId, SourceContentRevision};
pub use approved::{
    ApprovedProfileError, ApprovedProfileRegistry, RejectedApprovedProfile,
    APPROVED_PROFILE_MANIFEST_SCHEMA, APPROVED_PROFILE_MANIFEST_SCHEMA_VERSION,
    MAX_APPROVED_PROFILE_MANIFEST_BYTES,
};
pub use identity::{
    ContentSha256, DerivationJobId, DerivedRevision, EncoderBuildFingerprint, IdentityError,
    ProfileRevision, SourceManifestDigest,
};
pub use job::{
    DerivationCommand, DerivationDecision, DerivationDesiredState, DerivationEffect,
    DerivationFailureCode, DerivationJob, DerivationJobState, DerivationOutcome,
    DerivationRejectReason, DerivationSnapshot, DerivationSpec, DerivationSpecError,
    DerivationStartOutcome, DerivationWorkerReport, MediaNormalizer, MediaNormalizerError,
};
pub use manifest::{
    DerivedCompletion, DerivedManifest, DerivedManifestBuilder, DerivedManifestError,
    DerivedOutputEntry, DerivedOutputRole, DerivedSubject, InputInventoryEntry,
    ManifestSourceProvenance, SegmentPairCheckpoint, SegmentValidationSummary,
    UploadBundleManifestInput,
};
pub use plan::{
    Dimensions, Eye, EyeInputPlan, FrameSlice, LegacyTimingEvidence, MediaPlan, MediaPlanError,
    MediaPlanner, NormalizationInput, PairedSourceSegment, ProbeReport, ProbedArtifact,
    RawFrameEvidence, Rect, ResolvedSourceArtifact, SegmentPairPlan, SourceMediaKind,
    SourceSegment, TimingBasis,
};
pub use ports::{
    EncodeSegmentPairRequest, EncodedSegmentPair, EncoderStatistics, MediaEncoder,
    MediaOperationControl, MediaProbe, MediaProcessFailure, MediaProcessFailureCode,
    MediaProcessOutcome, MediaRequestError, ProbeRequest, ProcessDeadline, ProcessDisposition,
    ProcessReapReport, ProcessStopReason, ReapReceipt, SegmentValidationRequest,
};
pub use profile::{
    ContainerFormat, EncoderBuild, EncoderCompatibilityClass, HevcProfile, NormalizationProfile,
    PixelFormat, ProfileApprovalEvidence, ProfileError, ProfileReleaseStatus, QualityThresholds,
    QualityVariant, SampleEntry, TranscodeGeneration, VideoCodec,
};
pub use rational::{Rational, RationalError};
pub use validation::{
    FullDecodeVerdict, OutputMediaEvidence, QualityEvidence, QualityVerdict,
    SegmentValidationReport, StereoSyncVerdict, StructuralVerdict, ValidatedSegmentPair,
    ValidationError, ValidationIssue, ValidationIssueCode,
};
