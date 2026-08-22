//! Ubuntu derivation wiring: committed local source to core normalization.
//!
//! This module supplies the parts the core normalization executor needs and
//! the application did not yet have on Linux: a wake-queue scheduler, a clock,
//! and the translation from a committed [`SourceRecording`] into the frozen
//! [`NormalizationInput`] the planner consumes.
//!
//! It deliberately does **not** open the release gate. A derivation may only
//! run against a profile that [`ApprovedProfileRegistry`] resolves, and that
//! registry is built from the compiled-in release manifest, which ships with
//! no entries until each profile's five review reports exist. With the gate
//! closed this port answers exactly as the previous stub did — a typed,
//! non-retryable capability error — with one difference that is the whole
//! point of the change: the refusal now comes from the registry actually
//! having nothing approved, rather than from a hardcoded "unavailable", so
//! approving a profile is all it takes to make derivation run.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::json;
use ylx_transfer_adapters::media_normalizer::{
    ExternalStereoDomainEvaluator, FfmpegMediaNormalizer, FfmpegNormalizerConfig,
    FfmpegQualityAnalyzer,
};
use ylx_transfer_core::ingest::{
    LocalSourceReceipt, SourceArtifactRole, SourceKind, SourceProvenance, SourceRecording,
    SourceSchema, SourceVideoCodec, StereoLayout,
};
use ylx_transfer_core::media_normalizer::{
    DerivedStaging, MediaNormalizerClock, MediaNormalizerConfig, MediaNormalizerExecutor,
    MediaNormalizerPortError, MediaNormalizerScheduler, MediaStoreDerivationRepository,
    MediaStoreSourceReadLeases, SegmentQualityAnalyzer,
};
use ylx_transfer_core::media_store::MediaStore;
use ylx_transfer_core::normalization::{
    ApprovedProfileRegistry, ContentSha256, DerivationJobId, EncoderBuild, LegacyTimingEvidence,
    MediaEncoder, MediaPlanError, MediaProbe, NormalizationInput, NormalizationProfile,
    PairedSourceSegment, ProcessDeadline, ProfileRevision, Rational, RawFrameEvidence,
    ResolvedSourceArtifact, SourceManifestDigest, SourceSegment,
};
use ylx_transfer_core::normalization::{
    DerivationCommand, DerivationSpec, DerivationStartOutcome, DerivedSubject, MediaNormalizer,
    MediaNormalizerError,
};

use super::approved_profiles::load_approved_profiles;

/// FFmpeg gets a generous per-process ceiling because one segment pair of
/// x265 `slow` is minutes of work, not seconds; the grace periods are the
/// ordinary terminate-then-kill escalation.
fn default_process_deadline() -> ProcessDeadline {
    ProcessDeadline::new(6 * 60 * 60 * 1_000, 15_000, 5_000)
        .expect("the built-in process deadline is valid")
}

use super::ports::{
    MediaEffect, MediaErrorCode, MediaNormalizerPort, MediaPortError, MediaProjectionDelta,
};
use super::types::{
    DerivationJob as AppDerivationJob, DerivationJobId as AppDerivationJobId, MediaJobCommand,
    StartDerivationRequest,
};
use super::ubuntu_projection::map_derivation_collection;
use super::ubuntu_workers::{EnqueueOutcome, MediaWakeQueue};

/// Wakes the derivation lane when the core executor re-schedules a job.
///
/// The queue handed here must be the same one the lane thread drains, or an
/// executor re-schedule would update the durable row and then never wake
/// anybody. Overflow and shutdown are not errors: the durable job row is the
/// recovery authority, so a dropped hint costs a delay, never work.
pub struct DerivationWakeScheduler {
    queue: Arc<MediaWakeQueue>,
}

impl DerivationWakeScheduler {
    #[must_use]
    pub fn new(queue: Arc<MediaWakeQueue>) -> Self {
        Self { queue }
    }
}

impl MediaNormalizerScheduler for DerivationWakeScheduler {
    fn enqueue(&self, job_id: &DerivationJobId) -> Result<(), MediaNormalizerPortError> {
        match self.queue.enqueue(job_id.as_str()) {
            EnqueueOutcome::Queued
            | EnqueueOutcome::AlreadyPending
            | EnqueueOutcome::Full
            | EnqueueOutcome::Stopped => Ok(()),
        }
    }
}

/// Wall-clock timestamps for durable derivation rows.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDerivationClock;

impl MediaNormalizerClock for SystemDerivationClock {
    fn now_rfc3339(&self) -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

/// Resolve the approved profile this source must be normalized with.
///
/// Codec selection is a fact about the source, not a preference: MJPEG and
/// H.264 sources have separately reviewed quality variants because their
/// rate/quality behaviour differs. The candidate profile is reconstructed from
/// code and then looked up by revision, so a profile whose parameters changed
/// since approval resolves to nothing rather than silently inheriting the old
/// approval.
pub fn approved_profile_for(
    source: &SourceRecording,
    registry: &ApprovedProfileRegistry,
) -> Result<NormalizationProfile, MediaPortError> {
    let candidate = match source.media_plan().codec() {
        SourceVideoCodec::Mjpeg => NormalizationProfile::candidate_mjpeg_x265_slow_v1(),
        SourceVideoCodec::H264 => NormalizationProfile::candidate_h264_x265_slow_v1(),
    }
    .map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::PipelineStartFailed,
            format!("cannot construct the Ubuntu normalization profile: {error}"),
        )
        .with_retryable(false)
        .with_detail("capability", json!("normalization_profile"))
    })?;

    let revision: &ProfileRevision = candidate.profile_revision();
    registry.resolve(revision).cloned().ok_or_else(|| {
        MediaPortError::new(
            MediaErrorCode::EncoderUnavailable,
            "this normalization profile has no shipped approval, so no derivation may run against it",
        )
        .with_retryable(false)
        .with_detail("profile_revision", json!(revision.as_str()))
        .with_detail("capability", json!("approved_normalization_profile"))
    })
}

/// Build the frozen planner input for a committed source.
///
/// The source's own inventory is the authority for every artifact: its
/// declared size and digest were verified against the copied bytes at import
/// commit, so re-deriving them here would only invite the two to disagree.
/// Only video artifacts enter the plan; metadata and IMU travel with the
/// source, not through the encoder.
pub fn normalization_input_for(
    source: &SourceRecording,
    receipt: &LocalSourceReceipt,
    library_root: &Path,
) -> Result<NormalizationInput, MediaPortError> {
    let sealed_root = receipt.sealed_relative_path().join_to(library_root);

    let mut stereo = Vec::new();
    let mut left = Vec::new();
    let mut right = Vec::new();
    for claim in source.inventory() {
        let bucket = match claim.role() {
            SourceArtifactRole::VideoStereo => &mut stereo,
            SourceArtifactRole::VideoLeft => &mut left,
            SourceArtifactRole::VideoRight => &mut right,
            _ => continue,
        };
        bucket.push(resolved_artifact(claim, &sealed_root)?);
    }

    // The digest binds the plan to the exact manifest this source was admitted
    // under, so a re-import that changed the inventory cannot reuse a
    // derivation planned against the old one.
    let manifest_digest = source_manifest_digest(receipt)?;
    let schema = source.schema();
    let layout = source.media_plan().layout();
    let codec = source.media_plan().codec();
    if !matches!(
        source.source_kind(),
        SourceKind::RemovableMedia | SourceKind::LegacyRemovableMedia
    ) {
        return Err(MediaPortError::new(
            MediaErrorCode::DerivationStartFailed,
            "Ubuntu normalization only accepts removable-media source kinds",
        )
        .with_retryable(false)
        .with_detail("source_kind", json!(format!("{:?}", source.source_kind()))));
    }

    match schema {
        SourceSchema::DeviceSessionV1 | SourceSchema::DeviceSessionV2 => {
            ensure_unsigned_provenance(source, schema)?;
            match (layout, codec) {
                (StereoLayout::SeparateEyes, SourceVideoCodec::H264) => {
                    let segments =
                        paired_segments(left, right, source.media_plan().segment_count(), schema)?;
                    NormalizationInput::complete_unpublished_v6(segments, manifest_digest)
                        .map_err(plan_error)
                }
                (StereoLayout::LeftRightSideBySide, SourceVideoCodec::Mjpeg) => {
                    ensure_stereo_only(&stereo, &left, &right)?;
                    let frame_count = source.media_plan().raw_frame_count().ok_or_else(|| {
                        missing_input_evidence(schema, "device session frame count")
                    })?;
                    let frame_rate = source.media_plan().frame_rate().ok_or_else(|| {
                        missing_input_evidence(schema, "device session source frame rate")
                    })?;
                    let frame_rate =
                        Rational::new(frame_rate.numerator(), frame_rate.denominator()).map_err(
                            |error| {
                                MediaPortError::new(
                                    MediaErrorCode::IntegrityFailed,
                                    format!("device session frame rate is invalid: {error}"),
                                )
                                .with_retryable(false)
                            },
                        )?;
                    let evidence = RawFrameEvidence::new(frame_count, frame_rate, true, 0, 0)
                        .map_err(plan_error)?;
                    let artifact = only_stereo_artifact(stereo, schema)?;
                    Ok(NormalizationInput::raw_capture_v2(artifact, evidence))
                }
                _ => Err(invalid_media_shape(schema, layout, codec)),
            }
        }
        SourceSchema::RawCaptureV2 => {
            ensure_media_shape(
                schema,
                layout,
                codec,
                StereoLayout::LeftRightSideBySide,
                SourceVideoCodec::Mjpeg,
            )?;
            ensure_unsigned_provenance(source, schema)?;
            ensure_stereo_only(&stereo, &left, &right)?;
            let frame_count = source
                .media_plan()
                .raw_frame_count()
                .ok_or_else(|| missing_input_evidence(schema, "raw frame-index count"))?;
            let frame_rate = source
                .media_plan()
                .frame_rate()
                .ok_or_else(|| missing_input_evidence(schema, "raw source frame rate"))?;
            let frame_rate = Rational::new(frame_rate.numerator(), frame_rate.denominator())
                .map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        format!("raw source frame rate is invalid: {error}"),
                    )
                    .with_retryable(false)
                })?;
            let evidence =
                RawFrameEvidence::new(frame_count, frame_rate, true, 0, 0).map_err(plan_error)?;
            let artifact = only_stereo_artifact(stereo, schema)?;
            Ok(NormalizationInput::raw_capture_v2(artifact, evidence))
        }
        SourceSchema::LegacyMjpegSessionV5 => {
            ensure_media_shape(
                schema,
                layout,
                codec,
                StereoLayout::LeftRightSideBySide,
                SourceVideoCodec::Mjpeg,
            )?;
            ensure_unsigned_provenance(source, schema)?;
            ensure_stereo_sequence(&stereo, source.media_plan().segment_count(), schema)?;
            let total_frames = source
                .media_plan()
                .legacy_total_frames()
                .ok_or_else(|| missing_input_evidence(schema, "legacy frame-index total"))?;
            let frame_rate = source
                .media_plan()
                .frame_rate()
                .ok_or_else(|| missing_input_evidence(schema, "legacy source frame rate"))?;
            let frame_rate = Rational::new(frame_rate.numerator(), frame_rate.denominator())
                .map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        format!("legacy source frame rate is invalid: {error}"),
                    )
                    .with_retryable(false)
                })?;
            let frame_digest =
                ContentSha256::parse(receipt.inventory_digest().as_str()).map_err(|error| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        format!("legacy timing evidence digest is invalid: {error}"),
                    )
                    .with_retryable(false)
                })?;
            let evidence = LegacyTimingEvidence::new(
                frame_digest,
                total_frames,
                frame_rate,
                source.media_plan().reset_timestamps_per_segment(),
            )
            .map_err(plan_error)?;
            let segments = stereo_segments(stereo);
            NormalizationInput::legacy_mjpeg_session_v5(segments, evidence).map_err(plan_error)
        }
        SourceSchema::ApplianceSpoolV6 => {
            ensure_media_shape(
                schema,
                layout,
                codec,
                StereoLayout::LeftRightSideBySide,
                SourceVideoCodec::Mjpeg,
            )?;
            ensure_unsigned_provenance(source, schema)?;
            ensure_stereo_sequence(&stereo, source.media_plan().segment_count(), schema)?;
            let segments = stereo_segments(stereo);
            NormalizationInput::appliance_spool_v6(segments, manifest_digest).map_err(plan_error)
        }
        SourceSchema::CompleteUnpublishedV6 => {
            ensure_media_shape(
                schema,
                layout,
                codec,
                StereoLayout::SeparateEyes,
                SourceVideoCodec::H264,
            )?;
            ensure_unsigned_provenance(source, schema)?;
            let segments =
                paired_segments(left, right, source.media_plan().segment_count(), schema)?;
            NormalizationInput::complete_unpublished_v6(segments, manifest_digest)
                .map_err(plan_error)
        }
        SourceSchema::SignedPublicationV1 => {
            ensure_media_shape(
                schema,
                layout,
                codec,
                StereoLayout::SeparateEyes,
                SourceVideoCodec::H264,
            )?;
            if !matches!(source.provenance(), SourceProvenance::DeviceSigned(_)) {
                return Err(invalid_input_provenance(schema));
            }
            let segments =
                paired_segments(left, right, source.media_plan().segment_count(), schema)?;
            NormalizationInput::paired_h264_publication_v1(segments, manifest_digest)
                .map_err(plan_error)
        }
        SourceSchema::UnsignedPublicationV1 => {
            ensure_unsigned_provenance(source, schema)?;
            match (layout, codec) {
                (StereoLayout::SeparateEyes, SourceVideoCodec::H264) => {
                    let segments =
                        paired_segments(left, right, source.media_plan().segment_count(), schema)?;
                    NormalizationInput::unsigned_paired_h264_publication_v1(
                        segments,
                        manifest_digest,
                    )
                    .map_err(plan_error)
                }
                (StereoLayout::LeftRightSideBySide, SourceVideoCodec::Mjpeg) => {
                    ensure_stereo_sequence(&stereo, source.media_plan().segment_count(), schema)?;
                    NormalizationInput::unsigned_mjpeg_publication_v1(
                        stereo_segments(stereo),
                        manifest_digest,
                    )
                    .map_err(plan_error)
                }
                _ => Err(invalid_media_shape(schema, layout, codec)),
            }
        }
    }
}

fn ensure_media_shape(
    schema: SourceSchema,
    actual_layout: StereoLayout,
    actual_codec: SourceVideoCodec,
    expected_layout: StereoLayout,
    expected_codec: SourceVideoCodec,
) -> Result<(), MediaPortError> {
    if actual_layout == expected_layout && actual_codec == expected_codec {
        Ok(())
    } else {
        Err(invalid_media_shape(schema, actual_layout, actual_codec))
    }
}

fn invalid_media_shape(
    schema: SourceSchema,
    layout: StereoLayout,
    codec: SourceVideoCodec,
) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::DerivationStartFailed,
        "source schema, stereo layout, and codec do not form a supported normalization input",
    )
    .with_retryable(false)
    .with_detail("schema", json!(format!("{:?}", schema)))
    .with_detail("layout", json!(format!("{:?}", layout)))
    .with_detail("codec", json!(format!("{:?}", codec)))
}

fn invalid_input_provenance(schema: SourceSchema) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::IntegrityFailed,
        "source provenance does not match the schema-selected normalization input",
    )
    .with_retryable(false)
    .with_detail("schema", json!(format!("{:?}", schema)))
}

fn ensure_unsigned_provenance(
    source: &SourceRecording,
    schema: SourceSchema,
) -> Result<(), MediaPortError> {
    if matches!(
        source.provenance(),
        SourceProvenance::LocallyValidatedUnsigned(unsigned)
            if unsigned.source_schema() == schema
    ) {
        Ok(())
    } else {
        Err(invalid_input_provenance(schema))
    }
}

fn missing_input_evidence(schema: SourceSchema, evidence: &str) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::IntegrityFailed,
        "detector evidence required to build normalization input is missing",
    )
    .with_retryable(false)
    .with_detail("schema", json!(format!("{:?}", schema)))
    .with_detail("evidence", json!(evidence))
}

fn ensure_stereo_only(
    stereo: &[ResolvedSourceArtifact],
    left: &[ResolvedSourceArtifact],
    right: &[ResolvedSourceArtifact],
) -> Result<(), MediaPortError> {
    if stereo.len() == 1 && left.is_empty() && right.is_empty() {
        Ok(())
    } else {
        Err(conflicting_video_inventory())
    }
}

fn ensure_stereo_sequence(
    stereo: &[ResolvedSourceArtifact],
    expected_count: u32,
    schema: SourceSchema,
) -> Result<(), MediaPortError> {
    if !stereo.is_empty() && stereo.len() == usize::try_from(expected_count).unwrap_or(0) {
        Ok(())
    } else {
        Err(MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "source stereo segments do not match detector-declared segment count",
        )
        .with_retryable(false)
        .with_detail("schema", json!(format!("{:?}", schema)))
        .with_detail("expected_segments", json!(expected_count)))
    }
}

fn only_stereo_artifact(
    stereo: Vec<ResolvedSourceArtifact>,
    schema: SourceSchema,
) -> Result<ResolvedSourceArtifact, MediaPortError> {
    stereo.into_iter().next().ok_or_else(|| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "schema-selected side-by-side source has no video artifact",
        )
        .with_retryable(false)
        .with_detail("schema", json!(format!("{:?}", schema)))
    })
}

fn stereo_segments(stereo: Vec<ResolvedSourceArtifact>) -> Vec<SourceSegment> {
    stereo
        .into_iter()
        .enumerate()
        .map(|(index, artifact)| SourceSegment::new(index as u32, artifact))
        .collect()
}

fn paired_segments(
    left: Vec<ResolvedSourceArtifact>,
    right: Vec<ResolvedSourceArtifact>,
    expected_count: u32,
    schema: SourceSchema,
) -> Result<Vec<PairedSourceSegment>, MediaPortError> {
    if left.is_empty()
        || left.len() != right.len()
        || left.len() != usize::try_from(expected_count).unwrap_or(0)
    {
        return Err(MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "source eye segments are not evenly paired with the detector-declared count",
        )
        .with_retryable(false)
        .with_detail("schema", json!(format!("{:?}", schema)))
        .with_detail("expected_segments", json!(expected_count)));
    }
    left.into_iter()
        .zip(right)
        .enumerate()
        .map(|(index, (left, right))| PairedSourceSegment::new(index as u32, left, right))
        .collect::<Result<Vec<_>, _>>()
        .map_err(plan_error)
}

fn resolved_artifact(
    claim: &ylx_transfer_core::ingest::SourceArtifactClaim,
    sealed_root: &Path,
) -> Result<ResolvedSourceArtifact, MediaPortError> {
    let relative = claim.relative_path();
    let digest = claim.source_sha256().ok_or_else(|| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            "a committed video artifact has no digest to plan against",
        )
        .with_retryable(false)
        .with_detail("artifact", json!(relative.as_str()))
    })?;
    let expected_sha256 = ContentSha256::parse(digest).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("a committed video artifact has an unusable digest: {error}"),
        )
        .with_retryable(false)
        .with_detail("artifact", json!(relative.as_str()))
    })?;

    ResolvedSourceArtifact::new(
        claim.id().clone(),
        local_path(sealed_root, relative),
        relative.as_str().to_owned(),
        claim.size_bytes(),
        expected_sha256,
    )
    .map_err(plan_error)
}

fn local_path(
    sealed_root: &Path,
    relative: &ylx_transfer_core::ingest::SafeRelativePath,
) -> PathBuf {
    relative.join_to(sealed_root)
}

fn source_manifest_digest(
    receipt: &LocalSourceReceipt,
) -> Result<SourceManifestDigest, MediaPortError> {
    // The inventory digest already carries its `sha256:` prefix.
    SourceManifestDigest::parse(receipt.inventory_digest().as_str()).map_err(|error| {
        MediaPortError::new(
            MediaErrorCode::IntegrityFailed,
            format!("the committed source inventory digest is unusable: {error}"),
        )
        .with_retryable(false)
    })
}

fn conflicting_video_inventory() -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::IntegrityFailed,
        "a committed source must present either stereo segments or evenly paired eye segments",
    )
    .with_retryable(false)
    .with_detail("capability", json!("normalization_input"))
}

fn plan_error(error: MediaPlanError) -> MediaPortError {
    MediaPortError::new(
        MediaErrorCode::PipelineStartFailed,
        format!("cannot plan normalization for this source: {error}"),
    )
    .with_retryable(false)
    .with_detail("capability", json!("normalization_input"))
}

/// The Ubuntu normalization port, backed by the real core executor.
///
/// Construction is fallible on purpose. Building the FFmpeg adapter probes the
/// encoder actually installed on this machine, and the approved-profile
/// registry is validated against that exact build. A machine without a usable
/// FFmpeg therefore yields no port at all rather than one that would accept a
/// derivation and discover the problem after admitting durable work.
pub struct UbuntuDerivationPort {
    executor: Arc<MediaNormalizerExecutor>,
    store: Arc<Mutex<MediaStore>>,
    registry: ApprovedProfileRegistry,
    encoder_build: EncoderBuild,
    library_root: PathBuf,
    queue: Arc<MediaWakeQueue>,
}

impl UbuntuDerivationPort {
    pub fn start(
        store: Arc<Mutex<MediaStore>>,
        library_root: impl Into<PathBuf>,
        staging_root: impl Into<PathBuf>,
    ) -> Result<Arc<Self>, MediaPortError> {
        let library_root = library_root.into();
        let staging_root = staging_root.into();
        let ffmpeg = Arc::new(
            FfmpegMediaNormalizer::new(FfmpegNormalizerConfig::system_path()).map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::EncoderUnavailable,
                    format!("no usable FFmpeg normalization backend: {error}"),
                )
                .with_retryable(false)
                .with_detail("capability", json!("video_normalization"))
            })?,
        );
        let encoder_build = ffmpeg.encoder_build().clone();
        // A malformed release manifest is fatal rather than an empty registry:
        // this build's own artifact would be untrustworthy, and "nothing
        // approved" must stay distinguishable from "cannot tell".
        let registry = load_approved_profiles(&encoder_build).map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::EncoderUnavailable,
                format!("the shipped approved-profile manifest is unusable: {error}"),
            )
            .with_retryable(false)
            .with_detail("capability", json!("approved_normalization_profile"))
        })?;

        let stereo_evaluator = Arc::new(
            ExternalStereoDomainEvaluator::from_environment().map_err(|detail| {
                MediaPortError::new(
                    MediaErrorCode::EncoderUnavailable,
                    format!("no approved stereo/CV domain evaluator is available: {detail}"),
                )
                .with_retryable(false)
                .with_detail("capability", json!("stereo_domain_evaluator"))
            })?,
        );
        let quality = Arc::new(
            FfmpegQualityAnalyzer::new((*ffmpeg).clone(), staging_root, stereo_evaluator).map_err(
                |error| {
                    MediaPortError::new(
                        MediaErrorCode::EncoderUnavailable,
                        format!("no usable FFmpeg quality evidence backend: {error}"),
                    )
                    .with_retryable(false)
                    .with_detail("capability", json!("vmaf_ssim_quality_evidence"))
                },
            )?,
        );

        let queue = MediaWakeQueue::new(super::ubuntu_workers::DEFAULT_QUEUE_CAPACITY);
        let executor = Arc::new(MediaNormalizerExecutor::new(MediaNormalizerConfig {
            repository: Arc::new(MediaStoreDerivationRepository::new(Arc::clone(&store))),
            probe: Arc::clone(&ffmpeg) as Arc<dyn MediaProbe>,
            encoder: Arc::clone(&ffmpeg) as Arc<dyn MediaEncoder>,
            // Quality is a separate production owner. The adapter runs real
            // VMAF/SSIM processes, archives their reports beside the pair,
            // and delegates the stereo/CV verdict to the explicitly configured
            // algorithm owner; it is never the encode adapter's rejection
            // analyzer.
            quality: quality as Arc<dyn SegmentQualityAnalyzer>,
            leases: Arc::new(MediaStoreSourceReadLeases::new(Arc::clone(&store))),
            scheduler: Arc::new(DerivationWakeScheduler::new(Arc::clone(&queue))),
            clock: Arc::new(SystemDerivationClock),
            staging: DerivedStaging::new(library_root.clone()),
            process_deadline: default_process_deadline(),
            notifications: None,
        }));

        Ok(Arc::new(Self {
            executor,
            store,
            registry,
            encoder_build,
            library_root,
            queue,
        }))
    }

    /// The queue the derivation lane must drain. It has to be this one: the
    /// scheduler inside the executor pushes onto it.
    #[must_use]
    pub fn wake_queue(&self) -> Arc<MediaWakeQueue> {
        Arc::clone(&self.queue)
    }

    /// One worker turn for one durable job id.
    pub fn run_derivation_once(&self, job_id: &str) -> Result<(), MediaPortError> {
        let job_id = DerivationJobId::parse(job_id).map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::DerivationCommandFailed,
                format!("the derivation lane was handed an unusable job id: {error}"),
            )
            .with_retryable(false)
        })?;
        // Absorb a re-schedule for the job about to run, so the executor
        // asking for another turn does not wake this lane twice for work it
        // is already doing.
        self.queue.take(job_id.as_str());
        self.executor
            .run_one(&job_id)
            .map(|_| ())
            .map_err(normalizer_error)
    }

    /// Re-enqueue every durable job that has not reached a terminal state.
    pub fn recover_pending_derivations(&self) -> Result<(), MediaPortError> {
        for snapshot in self.executor.recover().map_err(normalizer_error)? {
            let _ = self.queue.enqueue(snapshot.spec().job_id().as_str());
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), MediaPortError> {
        self.executor.shutdown().map_err(normalizer_error)
    }

    /// Find the committed source a derivation names.
    ///
    /// The inventory lives on the import job's spec, which is the only place
    /// that retains the artifact digests the planner needs; the source receipt
    /// alone carries a local path but not the per-artifact claims.
    fn committed_source(
        &self,
        source_id: &str,
    ) -> Result<(SourceRecording, LocalSourceReceipt), MediaPortError> {
        let collection = lock(&self.store).import_projection().map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::CandidateNotFound,
                format!("cannot read the import projection: {error}"),
            )
            .with_retryable(true)
        })?;
        for stored in &collection.items {
            let source = stored.spec.source();
            let Some(revision) = source.content_revision() else {
                continue;
            };
            if revision.as_str() != source_id {
                continue;
            }
            let Some(receipt) = stored.snapshot.local_receipt() else {
                return Err(MediaPortError::new(
                    MediaErrorCode::SourceRevisionMismatch,
                    "this source has not finished importing, so it cannot be normalized yet",
                )
                .with_retryable(true)
                .with_detail("source_id", json!(source_id)));
            };
            return Ok((source.clone(), receipt.clone()));
        }
        Err(MediaPortError::new(
            MediaErrorCode::CandidateNotFound,
            "no committed local source matches this identity",
        )
        .with_retryable(false)
        .with_detail("source_id", json!(source_id)))
    }
}

fn normalizer_error(error: MediaNormalizerError) -> MediaPortError {
    let resource_stuck = matches!(&error, MediaNormalizerError::ResourceStuck(_));
    MediaPortError::new(
        if resource_stuck {
            MediaErrorCode::ResourceStuck
        } else {
            MediaErrorCode::DerivationCommandFailed
        },
        format!("the normalization executor refused this operation: {error}"),
    )
    .with_retryable(resource_stuck)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl MediaNormalizerPort for UbuntuDerivationPort {
    fn start_derivation(
        &self,
        request: StartDerivationRequest,
    ) -> Result<MediaEffect<AppDerivationJob>, MediaPortError> {
        let (source, receipt) = self.committed_source(request.source_id.as_str())?;

        // The release gate. With no approved profile this is where the request
        // stops, before any durable derivation row exists.
        let profile = approved_profile_for(&source, &self.registry)?;
        if profile.profile_revision().as_str() != request.profile_id.as_str() {
            return Err(MediaPortError::new(
                MediaErrorCode::DerivationStartFailed,
                "the requested profile is not the approved profile for this source's codec",
            )
            .with_retryable(false)
            .with_detail("requested", json!(request.profile_id.as_str()))
            .with_detail("approved", json!(profile.profile_revision().as_str())));
        }

        let input = normalization_input_for(&source, &receipt, &self.library_root)?;
        let subject = DerivedSubject::new(stable_origin_identity(&source)?, source.session_id())
            .map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::DerivationStartFailed,
                    format!("cannot identify the derivation subject: {error}"),
                )
                .with_retryable(false)
            })?;
        let manifest_digest = source_manifest_digest(&receipt)?;
        let spec = DerivationSpec::new(
            DerivationJobId::new(),
            subject,
            receipt,
            manifest_digest,
            profile,
            self.encoder_build.clone(),
            input,
            SystemDerivationClock.now_rfc3339(),
        )
        .map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::DerivationStartFailed,
                format!("cannot construct the derivation request: {error}"),
            )
            .with_retryable(false)
        })?;

        let job_id = match self.executor.start(spec).map_err(normalizer_error)? {
            DerivationStartOutcome::Created { job_id }
            | DerivationStartOutcome::Existing { job_id } => job_id,
            // An identical subject already deriving under different terms is a
            // conflict the caller must resolve, not one to silently join.
            DerivationStartOutcome::Conflict { existing_job_id } => {
                return Err(MediaPortError::new(
                    MediaErrorCode::OperationConflict,
                    "another derivation for this source is already running under different terms",
                )
                .with_retryable(false)
                .with_detail("existing_job_id", json!(existing_job_id.as_str())))
            }
        };
        self.effect_for(&job_id)
    }

    fn command_derivation(
        &self,
        job_id: AppDerivationJobId,
        command: MediaJobCommand,
    ) -> Result<MediaEffect<AppDerivationJob>, MediaPortError> {
        let core_id = DerivationJobId::parse(job_id.as_str()).map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::DerivationCommandFailed,
                format!("unusable derivation job id: {error}"),
            )
            .with_retryable(false)
        })?;
        let command = match command {
            MediaJobCommand::Pause => DerivationCommand::Pause,
            MediaJobCommand::Resume => DerivationCommand::Resume,
            MediaJobCommand::Cancel => DerivationCommand::Cancel,
            MediaJobCommand::Retry => DerivationCommand::Retry,
        };
        self.executor
            .command(&core_id, command)
            .map_err(normalizer_error)?;
        self.effect_for(&core_id)
    }
}

/// Identity used for immutable derivative and remote-object naming.
///
/// A candidate id contains a removable-media observation epoch. It is an
/// admission fence, deliberately invalidated by eject/reinsert, and must
/// never become a long-lived remote namespace. Signed publications have a
/// producer identity confirmed by pairing. Unsigned sources have no producer
/// assertion, so their stable volume identity is bound to the independently
/// verified content revision. This makes an exact reinsert converge while
/// keeping distinct unsigned content separate.
fn stable_origin_identity(source: &SourceRecording) -> Result<String, MediaPortError> {
    match source.provenance() {
        SourceProvenance::DeviceSigned(signed) => Ok(format!(
            "signed-producer:{}",
            signed.publication_key_fingerprint()
        )),
        SourceProvenance::LocallyValidatedUnsigned(_) => {
            let volume = source
                .locator()
                .media_generation()
                .ok_or_else(|| {
                    MediaPortError::new(
                        MediaErrorCode::IntegrityFailed,
                        "unsigned removable source has no stable volume identity",
                    )
                    .with_retryable(false)
                })?
                .platform_volume_identity();
            let revision = source.content_revision().ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::IntegrityFailed,
                    "unsigned removable source has no sealed content revision",
                )
                .with_retryable(false)
            })?;
            Ok(format!("unsigned-volume:{volume}:{}", revision.as_str()))
        }
    }
}

impl UbuntuDerivationPort {
    /// Project one job plus the whole derivation collection, so a caller sees
    /// the same revision the durable store just committed rather than a view
    /// assembled from two different reads.
    fn effect_for(
        &self,
        job_id: &DerivationJobId,
    ) -> Result<MediaEffect<AppDerivationJob>, MediaPortError> {
        let collection = lock(&self.store).derivation_projection().map_err(|error| {
            MediaPortError::new(
                MediaErrorCode::DerivationCommandFailed,
                format!("cannot read the derivation projection: {error}"),
            )
            .with_retryable(true)
        })?;
        let jobs = map_derivation_collection(&collection)?;
        let job = jobs
            .value
            .iter()
            .find(|job| job.id.as_str() == job_id.as_str())
            .cloned()
            .ok_or_else(|| {
                MediaPortError::new(
                    MediaErrorCode::DerivationCommandFailed,
                    "the derivation this operation just committed is not in its own projection",
                )
                .with_retryable(true)
            })?;
        Ok(MediaEffect::new(
            job,
            MediaProjectionDelta {
                derivations: Some(jobs),
                ..MediaProjectionDelta::default()
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use ylx_transfer_core::ingest::{
        AcquisitionSourceId, ConstrainedScanner, InventoryDigest, MediaGeneration,
        SafeRelativePath, ScanItemOutcome, ScanLimits, ScanRequest, SourceKind,
        UnsignedSourceAdmissionReceipt,
    };
    use ylx_transfer_core::normalization::SourceMediaKind;

    /// Build a committed source by the real route — write a publication, scan
    /// it, admit it — so the planner input is derived from the same inventory
    /// production code sees rather than a hand-built stand-in.
    fn committed(codec: &str, video: &[(&str, &str)]) -> (SourceRecording, LocalSourceReceipt) {
        let card = tempfile::tempdir().expect("tempdir");
        let root = card.path();
        fs::create_dir_all(root.join("spool")).expect("spool");
        fs::create_dir_all(root.join("video")).expect("video");

        let session = serde_json::json!({
            "schema_version": 7,
            "camera": { "width": 3840, "height": 1080, "fps": 30, "left_size": [1920, 1080],
                        "layout": "left_right_side_by_side", "video_codec": codec },
        });
        let session_bytes = serde_json::to_vec_pretty(&session).expect("session");
        fs::write(root.join("session.json"), &session_bytes).expect("write session");

        let mut files = Vec::new();
        let mut total = 0u64;
        let mut video_bytes = 0u64;
        for (path, role) in video {
            let bytes = path.as_bytes();
            fs::write(root.join(path), bytes).expect("write artifact");
            files.push(serde_json::json!({
                "id": format!("f-{}", &format!("{:x}", Sha256::digest(path.as_bytes()))[..32]),
                "display_path": path, "role": role, "media_type": "video/mp4",
                "size_bytes": bytes.len() as u64,
                "sha256": format!("{:x}", Sha256::digest(bytes)),
            }));
            total += bytes.len() as u64;
            video_bytes += bytes.len() as u64;
        }
        files.push(serde_json::json!({
            "id": "f-session", "display_path": "session.json", "role": "metadata",
            "media_type": "application/json", "size_bytes": session_bytes.len() as u64,
            "sha256": format!("{:x}", Sha256::digest(&session_bytes)),
        }));
        total += session_bytes.len() as u64;

        fs::write(
            root.join("publication_manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1, "session_id": "session-under-test",
                "revision": format!("sha256:{:x}", Sha256::digest(b"revision")),
                "captured_at": "2026-08-03T06:05:11.130061+00:00",
                "published_at": "2026-08-03T06:06:25.822799Z",
                "duration_seconds": 68.8, "total_bytes": total, "video_bytes": video_bytes,
                "integrity_ok": true, "files": files,
            }))
            .expect("manifest"),
        )
        .expect("write manifest");

        let source_id = AcquisitionSourceId::parse("test-source").expect("source id");
        let request = ScanRequest::selected_directory(
            root,
            source_id.clone(),
            SourceKind::RemovableMedia,
            Some(
                MediaGeneration::new(
                    source_id,
                    "test-volume",
                    InventoryDigest::from_material(b"marker"),
                    1,
                )
                .expect("generation"),
            ),
        )
        .expect("request");
        let snapshot = ConstrainedScanner::new(ScanLimits::default()).scan(&request);
        let ScanItemOutcome::Candidate { candidate } = snapshot
            .items()
            .first()
            .expect("one candidate")
            .outcome()
            .clone()
        else {
            panic!("the fixture publication must be admissible");
        };

        let candidate_revision = match candidate.revision_claim() {
            ylx_transfer_core::ingest::SourceRevisionClaim::Provisional(revision) => {
                revision.clone()
            }
            ylx_transfer_core::ingest::SourceRevisionClaim::Published(_) => {
                panic!("test candidate must be provisional")
            }
        };
        let receipt = UnsignedSourceAdmissionReceipt::new(
            "receipt",
            candidate.id().clone(),
            candidate.locator().media_generation_id().cloned(),
            candidate_revision,
            "test-policy",
            "2026-08-03T00:00:00Z",
        )
        .expect("receipt");
        let digest = InventoryDigest::from_material(b"verified-inventory");
        let recording = SourceRecording::admit_unsigned(*candidate, Some(receipt))
            .expect("unsigned admission")
            .with_verified_inventory(digest);

        let receipt = LocalSourceReceipt::new(
            &recording,
            SafeRelativePath::parse("device/session").expect("sealed path"),
            "commit-receipt",
            "2026-08-03T00:00:00Z",
        )
        .expect("local receipt");
        (recording, receipt)
    }

    #[test]
    fn stereo_segments_plan_as_a_spool_and_keep_their_order() {
        let (source, receipt) = committed(
            "mjpeg",
            &[
                ("spool/source_00000.mp4", "video_stereo"),
                ("spool/source_00001.mp4", "video_stereo"),
            ],
        );
        let input = normalization_input_for(&source, &receipt, Path::new("/library"))
            .expect("stereo source plans");

        assert_eq!(input.kind(), SourceMediaKind::UnsignedMjpegPublicationV1);
        let artifacts = input.artifacts();
        assert_eq!(artifacts.len(), 2);
        // The local path is the sealed library copy, never the card.
        assert_eq!(
            artifacts[0].local_path(),
            Path::new("/library/device/session/spool/source_00000.mp4")
        );
    }

    #[test]
    fn paired_eyes_plan_as_a_paired_publication() {
        let (source, receipt) = committed(
            "h264",
            &[
                ("video/left_00000.mp4", "video_left"),
                ("video/right_00000.mp4", "video_right"),
            ],
        );
        let input = normalization_input_for(&source, &receipt, Path::new("/library"))
            .expect("paired source plans");

        assert_eq!(
            input.kind(),
            SourceMediaKind::UnsignedPairedH264PublicationV1
        );
        assert_eq!(input.artifacts().len(), 2);
    }

    /// Metadata and IMU ride along with the source; sending them through the
    /// encoder would be a planning error, not merely wasted work.
    #[test]
    fn non_video_artifacts_stay_out_of_the_plan() {
        let (source, receipt) = committed("mjpeg", &[("spool/source_00000.mp4", "video_stereo")]);
        assert!(source
            .inventory()
            .iter()
            .any(|claim| claim.role() == SourceArtifactRole::Metadata));

        let input = normalization_input_for(&source, &receipt, Path::new("/library"))
            .expect("source plans");
        assert_eq!(input.artifacts().len(), 1);
    }

    /// The shipped manifest approves nothing, so every source must be refused
    /// here. This is the release gate, and a green run of this test is what
    /// says the gate is still closed.
    #[test]
    fn no_source_resolves_a_profile_while_the_manifest_approves_nothing() {
        let (source, _) = committed("mjpeg", &[("spool/source_00000.mp4", "video_stereo")]);
        let error = approved_profile_for(&source, &ApprovedProfileRegistry::empty())
            .expect_err("an empty registry approves nothing");
        assert_eq!(error.into_rpc().code, "encoder_unavailable");
    }

    #[test]
    fn unsigned_origin_identity_uses_stable_volume_and_sealed_content_not_candidate_epoch() {
        let (source, _) = committed("mjpeg", &[("spool/source_00000.mp4", "video_stereo")]);
        let origin = stable_origin_identity(&source).expect("stable origin");

        assert!(origin.starts_with("unsigned-volume:test-volume:"));
        assert!(origin.contains(source.content_revision().expect("sealed revision").as_str()));
        assert!(!origin.contains(source.candidate_id().as_str()));
    }
}
