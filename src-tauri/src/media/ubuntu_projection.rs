//! Strict Ubuntu projections from durable media-store records.
//!
//! The media application uses DTOs that are intentionally smaller than the
//! core aggregates. This module is the lossless boundary for the portions the
//! current Ubuntu runtime can actually recover: imports and derivations. It
//! never substitutes a row version for a collection revision, emits only
//! JavaScript-safe numeric values, and refuses to manufacture pipeline
//! control or upload evidence that `MediaStore` does not own.

use serde_json::json;
use ylx_transfer_core::ingest::{
    ImportDesiredState as CoreImportDesiredState, ImportFailure as CoreImportFailure,
    ImportFailureCode as CoreImportFailureCode, ImportJobState as CoreImportJobState,
    InventoryHashesVerdict, ManifestSignatureVerdict, ProducerKeyTrustVerdict,
    SourceKind as CoreSourceKind, SourceProvenance as CoreSourceProvenance, SourceRecording,
    SourceSchema as CoreSourceSchema,
};
use ylx_transfer_core::media_library::{
    CardPresence, DerivedLocalVerified, MediaLibraryProjection, ProjectedSourceArchive,
    RemoteUploadState, SourceLocalState,
};
use ylx_transfer_core::media_store::{RevisionedCollection, StoredDerivationJob, StoredImportJob};
use ylx_transfer_core::normalization::{
    DerivationDesiredState as CoreDerivationDesiredState,
    DerivationFailureCode as CoreDerivationFailureCode,
    DerivationJobState as CoreDerivationJobState,
};

use super::ports::{MediaErrorCode, MediaPortError, Observed};
use super::types::{
    CandidateId, DerivationJob, DerivationJobId, DerivationJobState, DerivationProgress, DerivedId,
    DesiredRunState, ImportJob, ImportJobId, ImportJobState, ImportProgress, InventoryIntegrity,
    MediaId, MediaLibraryCardPresence, MediaLibraryDerivedProjection, MediaLibraryEntryProjection,
    MediaLibraryRemoteState, MediaLibrarySourceArchive, MediaLibrarySourceLocalProjection,
    MediaLibraryUploadProjection, PipelineSourceSummary, ProducerKeyTrust, ProfileId,
    SignatureVerdict, SourceId, SourceKind, SourceProvenance as WireSourceProvenance, SourceSchema,
    UnsignedAdmission, UnsignedSourceSchema, ValidationProgress,
};

/// The largest integer JavaScript can represent exactly as an IEEE-754
/// `number`. Every numeric field in a DTO that can originate from a core
/// `u64` must pass this boundary before it is published to the WebView.
pub const MAX_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Map one durable import row without inferring transient file-reader state.
pub fn map_import_job(stored: &StoredImportJob) -> Result<ImportJob, MediaPortError> {
    let snapshot = &stored.snapshot;
    let source = stored.spec.source();
    let current_locator = &stored.locator.locator;
    let copied_bytes = snapshot.durable_bytes();
    let total_bytes = stored.spec.total_bytes();
    ensure_javascript_safe(copied_bytes, "import.progress.copied_bytes")?;
    ensure_javascript_safe(total_bytes, "import.progress.total_bytes")?;

    Ok(ImportJob {
        id: ImportJobId::new(snapshot.job_id().as_str()),
        candidate_id: CandidateId::new(source.candidate_id().as_str()),
        media_id: current_locator
            .media_generation_id()
            .map(|generation| MediaId::new(generation.as_str()))
            .unwrap_or_else(|| MediaId::new(current_locator.source_id().as_str())),
        // The core only assigns a durable content revision once its inventory
        // evidence is verified. An acquisition locator is not a substitute.
        source_id: snapshot
            .content_revision()
            .map(|revision| SourceId::new(revision.as_str())),
        state: map_import_state(snapshot.state()),
        desired_run_state: map_import_desired_state(snapshot.desired_state()),
        progress: ImportProgress {
            // A checkpoint says what is durable, not what a worker is reading
            // right now. Publishing a guessed file would create false state.
            current_file: None,
            copied_bytes,
            total_bytes,
            throughput_bytes_per_second: None,
            eta_seconds: None,
        },
        failure: snapshot.failure().map(map_import_failure),
        // The core retry state has no durable wall-clock retry timestamp.
        retry_at: None,
        created_at: stored.created_at.clone(),
        updated_at: stored.updated_at.clone(),
    })
}

/// Map the complete derivation collection using its authoritative store
/// revision.
pub fn map_derivation_collection(
    collection: &RevisionedCollection<StoredDerivationJob>,
) -> Result<Observed<Vec<DerivationJob>>, MediaPortError> {
    ensure_javascript_safe(collection.revision, "derivations.source_version")?;
    let jobs = collection
        .items
        .iter()
        .map(map_derivation_job)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Observed::new(collection.revision, jobs))
}

/// Map one durable derivation row, deriving progress only from its frozen
/// media plan and validated pair checkpoints.
pub fn map_derivation_job(stored: &StoredDerivationJob) -> Result<DerivationJob, MediaPortError> {
    let snapshot = &stored.snapshot;
    let plan = snapshot.media_plan();
    let checkpoint_count = checked_u32(
        snapshot.checkpoints().len(),
        "derivation.validation.decoded_segment_pairs",
    )?;
    let total_segment_pairs = plan
        .map(|plan| {
            checked_u32(
                plan.segment_pairs().len(),
                "derivation.progress.total_segment_pairs",
            )
        })
        .transpose()?;

    let processed_frames =
        processed_checkpoint_frames(snapshot.media_plan(), snapshot.checkpoints())?;
    ensure_javascript_safe(processed_frames, "derivation.progress.processed_frames")?;

    let total_frames = plan.map(|plan| plan.total_frames());
    if let Some(total_frames) = total_frames {
        ensure_javascript_safe(total_frames, "derivation.progress.total_frames")?;
    }

    if let Some(total_segment_pairs) = total_segment_pairs {
        if checkpoint_count > total_segment_pairs {
            return Err(projection_integrity_error(
                "derivation.validation.decoded_segment_pairs",
                "durable derivation checkpoints exceed the frozen media plan",
            ));
        }
    }

    if let Some(current_pair) = snapshot.current_pair() {
        let Some(plan) = plan else {
            return Err(projection_integrity_error(
                "derivation.progress.current_segment_pair",
                "durable derivation has an active pair before a media plan exists",
            ));
        };
        if plan.segment_pair(current_pair).is_none() {
            return Err(projection_integrity_error(
                "derivation.progress.current_segment_pair",
                "durable derivation refers to a segment absent from its media plan",
            ));
        }
    }

    let (state, failure) =
        map_derivation_state_and_failure(snapshot.state(), snapshot.desired_state());
    Ok(DerivationJob {
        id: DerivationJobId::new(snapshot.spec().job_id().as_str()),
        source_id: SourceId::new(snapshot.spec().source_revision().as_str()),
        profile_id: ProfileId::new(snapshot.spec().profile_revision().as_str()),
        derived_id: snapshot
            .completion()
            .map(|completion| DerivedId::new(completion.derived_revision().as_str())),
        state,
        desired_run_state: map_derivation_desired_state(snapshot.state(), snapshot.desired_state()),
        progress: DerivationProgress {
            current_segment_pair: snapshot.current_pair(),
            total_segment_pairs,
            processed_frames,
            total_frames,
            encoding_fps: None,
            eta_seconds: None,
        },
        validation: ValidationProgress {
            decoded_segment_pairs: checkpoint_count,
            // The wire type cannot express an unknown validation total. Zero
            // here means no frozen media plan has been durably published.
            total_segment_pairs: total_segment_pairs.unwrap_or(0),
        },
        failure,
        // The core retry state contains no durable schedule timestamp.
        retry_at: None,
        created_at: stored.created_at.clone(),
        updated_at: stored.updated_at.clone(),
    })
}

/// Map immutable source facts retained by a durable pipeline. This helper is
/// intentionally separate from pipeline lifecycle projection, whose missing
/// control and upload evidence is handled by the durable pipeline adapter.
pub fn map_pipeline_source_summary(
    source: &SourceRecording,
) -> Result<PipelineSourceSummary, MediaPortError> {
    let bytes = source.total_bytes();
    ensure_javascript_safe(bytes, "pipeline.source_summary.bytes")?;
    Ok(PipelineSourceSummary {
        source_key: source.revision_claim().as_str().to_string(),
        media_id: media_id_for(source),
        // An acquisition locator identifies a live source root, not a stable
        // source revision. Publish an ID only after core has made that claim.
        source_id: source
            .revision_claim()
            .stable()
            .map(|revision| SourceId::new(revision.as_str())),
        display_name: source.session_id().to_string(),
        session_id: Some(source.session_id().to_string()),
        schema: map_source_schema(source.schema()),
        source_kind: map_source_kind(source.source_kind()),
        provenance: map_source_provenance(source)?,
        // `None` is the selected acquisition-root convention in core. The
        // wire contract has a required string, so empty string is its exact
        // root representation rather than a guessed relative path.
        relative_path: source
            .locator()
            .candidate_relative_path()
            .map(|path| path.as_str().to_string())
            .unwrap_or_default(),
        bytes,
        // SourceRecording intentionally exposes no durable duration getter.
        duration_seconds: None,
    })
}

/// Map the independent durable media-library projection to a bounded wire
/// DTO. The core projection is intentionally richer than this boundary and
/// may contain commit receipts or signed publication material.
pub fn map_media_library_collection(
    source_version: u64,
    projections: &[MediaLibraryProjection],
) -> Result<Observed<Vec<MediaLibraryEntryProjection>>, MediaPortError> {
    ensure_javascript_safe(source_version, "library.source_version")?;
    let entries = projections
        .iter()
        .map(map_media_library_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Observed::new(source_version, entries))
}

fn map_media_library_entry(
    projection: &MediaLibraryProjection,
) -> Result<MediaLibraryEntryProjection, MediaPortError> {
    let source_local = match &projection.source_local {
        SourceLocalState::Verified(verified) => MediaLibrarySourceLocalProjection::Verified {
            import_receipt_id: verified.import_receipt_id.clone(),
            import_job_id: verified.import_job_id.clone(),
            relative_path: verified.tree.relative_path().as_str().to_string(),
            sealed_inventory_digest: verified.sealed_inventory_digest.as_str().to_string(),
            provenance: map_library_source_provenance(&verified.provenance)?,
            committed_at: verified.committed_at.clone(),
        },
        SourceLocalState::Removed {
            former_tree,
            policy_revision,
            removed_at,
            ..
        } => MediaLibrarySourceLocalProjection::Removed {
            relative_path: former_tree.relative_path().as_str().to_string(),
            policy_revision: policy_revision.clone(),
            removed_at: removed_at.clone(),
        },
    };

    let derived_local = projection
        .derived_local
        .values()
        .map(map_media_library_derived)
        .collect::<Result<Vec<_>, _>>()?;
    let upload_bundles = projection
        .upload_bundles
        .values()
        .map(map_media_library_upload)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MediaLibraryEntryProjection {
        entry_key: projection.entry_key.as_str().to_string(),
        source_identity: projection.source_identity.clone(),
        source_revision: projection.source_revision.as_str().to_string(),
        source_local,
        derived_local,
        upload_bundles,
        card_presence: map_media_library_card_presence(&projection.card_presence)?,
    })
}

fn map_library_source_provenance(
    provenance: &CoreSourceProvenance,
) -> Result<WireSourceProvenance, MediaPortError> {
    match provenance {
        CoreSourceProvenance::DeviceSigned(signed) => {
            // A DeviceSigned value can only be constructed after the core
            // verified the publication against a trusted paired key. The
            // import receipt also proves the sealed inventory was accepted.
            Ok(WireSourceProvenance::DeviceSigned {
                publication_key_fingerprint: signed.publication_key_fingerprint().to_string(),
                manifest_signature: SignatureVerdict::Valid,
                producer_key_trust: ProducerKeyTrust::Trusted,
                inventory_integrity: InventoryIntegrity::Valid,
            })
        }
        CoreSourceProvenance::LocallyValidatedUnsigned(unsigned) => {
            Ok(WireSourceProvenance::LocallyValidatedUnsigned {
                source_schema: map_unsigned_source_schema(unsigned.source_schema())?,
                validation_report_id: None,
                inventory_digest: unsigned
                    .computed_inventory_digest()
                    .map(|digest| digest.as_str().to_string()),
                admission: if unsigned.user_admission_receipt().is_some() {
                    UnsignedAdmission::Approved
                } else {
                    UnsignedAdmission::Required
                },
            })
        }
    }
}

fn map_media_library_derived(
    derived: &DerivedLocalVerified,
) -> Result<MediaLibraryDerivedProjection, MediaPortError> {
    Ok(MediaLibraryDerivedProjection {
        derivation_job_id: derived.derivation_job_id.clone(),
        profile_revision: derived.tree.profile_revision().as_str().to_string(),
        derived_revision: derived.tree.derived_revision().as_str().to_string(),
        relative_path: derived.tree.relative_path().as_str().to_string(),
        source_manifest_digest: derived.source_manifest_digest.as_str().to_string(),
        committed_at: derived.committed_at.clone(),
    })
}

fn map_media_library_upload(
    upload: &ylx_transfer_core::media_library::UploadBundleProjection,
) -> Result<MediaLibraryUploadProjection, MediaPortError> {
    Ok(MediaLibraryUploadProjection {
        bundle_revision: upload.bundle_revision().as_str().to_string(),
        storage_profile_identity: upload.storage_profile_identity().as_str().to_string(),
        source_revision: upload.source_revision().as_str().to_string(),
        derived_revision: upload.derived_revision().as_str().to_string(),
        remote: match upload.remote() {
            RemoteUploadState::NotVerified => MediaLibraryRemoteState::NotVerified,
            RemoteUploadState::Failed { code, retryable } => MediaLibraryRemoteState::Failed {
                code: code.clone(),
                retryable: *retryable,
            },
            RemoteUploadState::Verified {
                remote_receipt_sha256,
                verified_at_ms,
                source_archive,
            } => {
                ensure_javascript_safe(*verified_at_ms, "library.upload.remote.verified_at_ms")?;
                MediaLibraryRemoteState::Verified {
                    remote_receipt_digest: format!("sha256:{}", remote_receipt_sha256.to_hex()),
                    verified_at_ms: *verified_at_ms,
                    source_archive: map_media_library_source_archive(source_archive),
                }
            }
        },
    })
}

fn map_media_library_source_archive(archive: &ProjectedSourceArchive) -> MediaLibrarySourceArchive {
    match archive {
        ProjectedSourceArchive::NotIncluded => MediaLibrarySourceArchive::NotIncluded,
        ProjectedSourceArchive::Verified { policy_revision } => {
            MediaLibrarySourceArchive::Verified {
                policy_revision: policy_revision.clone(),
            }
        }
    }
}

fn map_media_library_card_presence(
    presence: &CardPresence,
) -> Result<MediaLibraryCardPresence, MediaPortError> {
    match presence {
        CardPresence::Unknown => Ok(MediaLibraryCardPresence::Unknown),
        CardPresence::Present {
            media_generation_id,
            observation_sequence,
            observed_at_ms,
        } => {
            ensure_javascript_safe(
                *observation_sequence,
                "library.card_presence.observation_sequence",
            )?;
            ensure_javascript_safe(*observed_at_ms, "library.card_presence.observed_at_ms")?;
            Ok(MediaLibraryCardPresence::Present {
                media_generation_id: media_generation_id.clone(),
                observation_sequence: *observation_sequence,
                observed_at_ms: *observed_at_ms,
            })
        }
        CardPresence::Absent {
            last_media_generation_id,
            observation_sequence,
            observed_at_ms,
        } => {
            ensure_javascript_safe(
                *observation_sequence,
                "library.card_presence.observation_sequence",
            )?;
            ensure_javascript_safe(*observed_at_ms, "library.card_presence.observed_at_ms")?;
            Ok(MediaLibraryCardPresence::Absent {
                last_media_generation_id: last_media_generation_id.clone(),
                observation_sequence: *observation_sequence,
                observed_at_ms: *observed_at_ms,
            })
        }
    }
}

/// Structurally map core source provenance into the frontend's discriminated
/// union. Incomplete signed trust evidence is rejected instead of being
/// coerced to a signed or unsigned status the core did not establish.
pub fn map_source_provenance(
    source: &SourceRecording,
) -> Result<WireSourceProvenance, MediaPortError> {
    match source.provenance() {
        CoreSourceProvenance::DeviceSigned(signed) => Ok(WireSourceProvenance::DeviceSigned {
            publication_key_fingerprint: signed.publication_key_fingerprint().to_string(),
            manifest_signature: map_device_signature(
                source.trust_verdicts().manifest_signature(),
                signed.publication_key_fingerprint(),
            )?,
            producer_key_trust: map_device_producer_key(
                source.trust_verdicts().producer_key(),
                signed.publication_key_fingerprint(),
            )?,
            inventory_integrity: map_inventory_integrity(
                source.trust_verdicts().inventory_hashes(),
            ),
        }),
        CoreSourceProvenance::LocallyValidatedUnsigned(unsigned) => {
            if source.schema() != unsigned.source_schema() {
                return Err(projection_integrity_error(
                    "source.provenance.source_schema",
                    "durable unsigned provenance disagrees with the recording schema",
                ));
            }
            Ok(WireSourceProvenance::LocallyValidatedUnsigned {
                source_schema: map_unsigned_source_schema(unsigned.source_schema())?,
                // Core stores a report, but not a stable report identifier.
                validation_report_id: None,
                inventory_digest: unsigned
                    .computed_inventory_digest()
                    .map(|digest| digest.as_str().to_string()),
                admission: if unsigned.user_admission_receipt().is_some() {
                    UnsignedAdmission::Approved
                } else {
                    UnsignedAdmission::Required
                },
            })
        }
    }
}

fn media_id_for(source: &SourceRecording) -> MediaId {
    source
        .locator()
        .media_generation_id()
        .map(|generation| MediaId::new(generation.as_str()))
        .unwrap_or_else(|| MediaId::new(source.locator().source_id().as_str()))
}

fn map_import_state(state: &CoreImportJobState) -> ImportJobState {
    match state {
        CoreImportJobState::Queued => ImportJobState::Queued,
        CoreImportJobState::WaitingForMedia { .. } => ImportJobState::WaitingForMedia,
        CoreImportJobState::Preflighting => ImportJobState::Preflighting,
        CoreImportJobState::Copying => ImportJobState::Copying,
        CoreImportJobState::Verifying => ImportJobState::Verifying,
        CoreImportJobState::Committing => ImportJobState::Committing,
        CoreImportJobState::LocalVerified => ImportJobState::LocalVerified,
        CoreImportJobState::RetryWait { .. } => ImportJobState::RetryWait,
        CoreImportJobState::Pausing { .. } => ImportJobState::Pausing,
        CoreImportJobState::Paused { .. } => ImportJobState::Paused,
        CoreImportJobState::Cancelling => ImportJobState::Cancelling,
        CoreImportJobState::Cancelled => ImportJobState::Cancelled,
        CoreImportJobState::Failed => ImportJobState::Failed,
    }
}

fn map_import_desired_state(state: CoreImportDesiredState) -> DesiredRunState {
    match state {
        CoreImportDesiredState::Running => DesiredRunState::Run,
        CoreImportDesiredState::Paused => DesiredRunState::Paused,
        CoreImportDesiredState::Cancelled => DesiredRunState::Cancelled,
    }
}

fn map_import_failure(failure: &CoreImportFailure) -> crate::application::RpcError {
    let (code, class) = match failure.code() {
        CoreImportFailureCode::SourceUnavailable => {
            (MediaErrorCode::MediaUnavailable, "source_unavailable")
        }
        CoreImportFailureCode::MediaChanged => (MediaErrorCode::MediaChanged, "media_changed"),
        CoreImportFailureCode::UnsafePath => (MediaErrorCode::UnsafePath, "unsafe_path"),
        CoreImportFailureCode::PermissionDenied => {
            (MediaErrorCode::MediaUnavailable, "permission_denied")
        }
        CoreImportFailureCode::InsufficientLocalSpace => (
            MediaErrorCode::InsufficientLocalSpace,
            "insufficient_local_space",
        ),
        CoreImportFailureCode::IntegrityMismatch => {
            (MediaErrorCode::IntegrityFailed, "integrity_mismatch")
        }
        CoreImportFailureCode::SourceRevisionMismatch => (
            MediaErrorCode::SourceRevisionMismatch,
            "source_revision_mismatch",
        ),
        CoreImportFailureCode::CommitFailed => {
            (MediaErrorCode::ImportCommandFailed, "commit_failed")
        }
        CoreImportFailureCode::ResourceStuck => (MediaErrorCode::ResourceStuck, "resource_stuck"),
        CoreImportFailureCode::Internal => (MediaErrorCode::ImportCommandFailed, "internal"),
    };
    MediaPortError::new(code, failure.message())
        .with_retryable(failure.retryable())
        .with_detail("import_failure", json!(class))
        .into_rpc()
}

fn processed_checkpoint_frames(
    plan: Option<&ylx_transfer_core::normalization::MediaPlan>,
    checkpoints: &[ylx_transfer_core::normalization::SegmentPairCheckpoint],
) -> Result<u64, MediaPortError> {
    if checkpoints.is_empty() {
        return Ok(0);
    }
    let Some(plan) = plan else {
        return Err(projection_integrity_error(
            "derivation.progress.processed_frames",
            "durable derivation has checkpoints before a media plan exists",
        ));
    };

    checkpoints
        .iter()
        .enumerate()
        .try_fold(0_u64, |total, (expected_index, checkpoint)| {
            let expected_index = u32::try_from(expected_index).map_err(|_| {
                projection_integrity_error(
                    "derivation.progress.processed_frames",
                    "durable derivation checkpoint index exceeds the frontend counter range",
                )
            })?;
            if checkpoint.segment_index() != expected_index {
                return Err(projection_integrity_error(
                    "derivation.progress.processed_frames",
                    "durable derivation checkpoints are not contiguous from segment zero",
                ));
            }
            let pair = plan
                .segment_pair(checkpoint.segment_index())
                .ok_or_else(|| {
                    projection_integrity_error(
                        "derivation.progress.processed_frames",
                        "durable derivation checkpoint is absent from its media plan",
                    )
                })?;
            total.checked_add(pair.frame_count()).ok_or_else(|| {
                projection_integrity_error(
                    "derivation.progress.processed_frames",
                    "durable derivation checkpoint frame counts overflowed",
                )
            })
        })
}

fn map_derivation_state_and_failure(
    state: &CoreDerivationJobState,
    desired: CoreDerivationDesiredState,
) -> (DerivationJobState, Option<crate::application::RpcError>) {
    match state {
        CoreDerivationJobState::Cancelling => (DerivationJobState::Cancelling, None),
        CoreDerivationJobState::Cancelled => (DerivationJobState::Cancelled, None),
        CoreDerivationJobState::DerivedVerified => (DerivationJobState::DerivedVerified, None),
        CoreDerivationJobState::Failed { code, retryable } => (
            DerivationJobState::Failed,
            Some(map_derivation_failure(*code, *retryable)),
        ),
        _ if desired == CoreDerivationDesiredState::Paused && state.is_active() => {
            (DerivationJobState::Pausing, None)
        }
        _ if desired == CoreDerivationDesiredState::Paused => (DerivationJobState::Paused, None),
        CoreDerivationJobState::Queued => (DerivationJobState::Queued, None),
        CoreDerivationJobState::WaitingForSource => (DerivationJobState::WaitingForSource, None),
        CoreDerivationJobState::Probing => (DerivationJobState::Probing, None),
        CoreDerivationJobState::Planning => (DerivationJobState::Planning, None),
        CoreDerivationJobState::Encoding => (DerivationJobState::Encoding, None),
        CoreDerivationJobState::Validating => (DerivationJobState::Validating, None),
        CoreDerivationJobState::Committing => (DerivationJobState::Committing, None),
        CoreDerivationJobState::RetryWait => (DerivationJobState::RetryWait, None),
    }
}

fn map_derivation_desired_state(
    state: &CoreDerivationJobState,
    desired: CoreDerivationDesiredState,
) -> DesiredRunState {
    if matches!(
        state,
        CoreDerivationJobState::Cancelling | CoreDerivationJobState::Cancelled
    ) {
        DesiredRunState::Cancelled
    } else if desired == CoreDerivationDesiredState::Paused {
        DesiredRunState::Paused
    } else {
        DesiredRunState::Run
    }
}

fn map_derivation_failure(
    code: CoreDerivationFailureCode,
    retryable: bool,
) -> crate::application::RpcError {
    let (wire_code, message, class) = match code {
        CoreDerivationFailureCode::SourceUnavailable => (
            MediaErrorCode::MediaUnavailable,
            "the local source required for normalization is unavailable",
            "source_unavailable",
        ),
        CoreDerivationFailureCode::ProbeFailed => (
            MediaErrorCode::DerivationCommandFailed,
            "source media probe failed",
            "probe_failed",
        ),
        CoreDerivationFailureCode::PlanRejected => (
            MediaErrorCode::DerivationCommandFailed,
            "source media cannot satisfy the selected normalization profile",
            "plan_rejected",
        ),
        CoreDerivationFailureCode::EncoderFailed => (
            MediaErrorCode::EncoderUnavailable,
            "the configured video encoder failed",
            "encoder_failed",
        ),
        CoreDerivationFailureCode::ValidationFailed => (
            MediaErrorCode::IntegrityFailed,
            "the derived media failed structural or quality validation",
            "validation_failed",
        ),
        CoreDerivationFailureCode::ProfileUnapproved => (
            MediaErrorCode::PolicyApprovalRequired,
            "the selected normalization profile is not approved",
            "profile_unapproved",
        ),
        CoreDerivationFailureCode::IntegrityMismatch => (
            MediaErrorCode::IntegrityFailed,
            "source or derived integrity evidence did not match",
            "integrity_mismatch",
        ),
        CoreDerivationFailureCode::Disk => (
            MediaErrorCode::InsufficientLocalSpace,
            "the local library does not have enough space for normalization",
            "disk",
        ),
        CoreDerivationFailureCode::DeadlineExceeded => (
            MediaErrorCode::ResourceStuck,
            "normalization exceeded its process deadline",
            "deadline_exceeded",
        ),
        CoreDerivationFailureCode::ResourceStuck => (
            MediaErrorCode::ResourceStuck,
            "normalization process did not exit cleanly",
            "resource_stuck",
        ),
        CoreDerivationFailureCode::Internal => (
            MediaErrorCode::DerivationCommandFailed,
            "normalization encountered an internal worker failure",
            "internal",
        ),
    };
    MediaPortError::new(wire_code, message)
        .with_retryable(retryable)
        .with_detail("derivation_failure", json!(class))
        .into_rpc()
}

fn map_source_kind(kind: CoreSourceKind) -> SourceKind {
    match kind {
        CoreSourceKind::Lan => SourceKind::Lan,
        CoreSourceKind::RemovableMedia => SourceKind::RemovableMedia,
        CoreSourceKind::LocalFolder => SourceKind::LocalFolder,
        CoreSourceKind::LegacyRemovableMedia => SourceKind::LegacyRemovableMedia,
    }
}

fn map_source_schema(schema: CoreSourceSchema) -> SourceSchema {
    match schema {
        CoreSourceSchema::DeviceSessionV1 => SourceSchema::DeviceSessionV1,
        CoreSourceSchema::DeviceSessionV2 => SourceSchema::DeviceSessionV2,
        CoreSourceSchema::SignedPublicationV1 => SourceSchema::SignedPublicationV1,
        CoreSourceSchema::RawCaptureV2 => SourceSchema::RawCaptureV2,
        CoreSourceSchema::LegacyMjpegSessionV5 => SourceSchema::LegacyMjpegSessionV5,
        CoreSourceSchema::CompleteUnpublishedV6 => SourceSchema::CompleteUnpublishedV6,
        CoreSourceSchema::ApplianceSpoolV6 => SourceSchema::ApplianceSpoolV6,
        CoreSourceSchema::UnsignedPublicationV1 => SourceSchema::UnsignedPublicationV1,
    }
}

fn map_unsigned_source_schema(
    schema: CoreSourceSchema,
) -> Result<UnsignedSourceSchema, MediaPortError> {
    match schema {
        CoreSourceSchema::DeviceSessionV1 => Ok(UnsignedSourceSchema::DeviceSessionV1),
        CoreSourceSchema::DeviceSessionV2 => Ok(UnsignedSourceSchema::DeviceSessionV2),
        CoreSourceSchema::RawCaptureV2 => Ok(UnsignedSourceSchema::RawCaptureV2),
        CoreSourceSchema::LegacyMjpegSessionV5 => Ok(UnsignedSourceSchema::LegacyMjpegSessionV5),
        CoreSourceSchema::CompleteUnpublishedV6 => Ok(UnsignedSourceSchema::CompleteUnpublishedV6),
        CoreSourceSchema::ApplianceSpoolV6 => Ok(UnsignedSourceSchema::ApplianceSpoolV6),
        CoreSourceSchema::UnsignedPublicationV1 => Ok(UnsignedSourceSchema::UnsignedPublicationV1),
        CoreSourceSchema::SignedPublicationV1 => Err(projection_integrity_error(
            "source.provenance.source_schema",
            "device-signed schema cannot be projected as locally validated unsigned media",
        )),
    }
}

fn map_device_signature(
    verdict: &ManifestSignatureVerdict,
    expected_fingerprint: &str,
) -> Result<SignatureVerdict, MediaPortError> {
    match verdict {
        ManifestSignatureVerdict::Valid { key_fingerprint } => {
            ensure_matching_fingerprint(
                key_fingerprint,
                expected_fingerprint,
                "source.provenance.manifest_signature",
            )?;
            Ok(SignatureVerdict::Valid)
        }
        ManifestSignatureVerdict::Invalid { .. } => Ok(SignatureVerdict::Invalid),
        ManifestSignatureVerdict::Pending | ManifestSignatureVerdict::NotApplicable => {
            Err(projection_integrity_error(
                "source.provenance.manifest_signature",
                "device-signed source has no representable manifest-signature verdict",
            ))
        }
    }
}

fn map_device_producer_key(
    verdict: &ProducerKeyTrustVerdict,
    expected_fingerprint: &str,
) -> Result<ProducerKeyTrust, MediaPortError> {
    match verdict {
        ProducerKeyTrustVerdict::Trusted { key_fingerprint } => {
            ensure_matching_fingerprint(
                key_fingerprint,
                expected_fingerprint,
                "source.provenance.producer_key_trust",
            )?;
            Ok(ProducerKeyTrust::Trusted)
        }
        ProducerKeyTrustVerdict::Unknown { key_fingerprint } => {
            ensure_matching_fingerprint(
                key_fingerprint,
                expected_fingerprint,
                "source.provenance.producer_key_trust",
            )?;
            Ok(ProducerKeyTrust::Unknown)
        }
        ProducerKeyTrustVerdict::Rejected { key_fingerprint } => {
            ensure_matching_fingerprint(
                key_fingerprint,
                expected_fingerprint,
                "source.provenance.producer_key_trust",
            )?;
            Ok(ProducerKeyTrust::Untrusted)
        }
        ProducerKeyTrustVerdict::NotApplicable => Err(projection_integrity_error(
            "source.provenance.producer_key_trust",
            "device-signed source has no representable producer-key verdict",
        )),
    }
}

fn map_inventory_integrity(verdict: &InventoryHashesVerdict) -> InventoryIntegrity {
    match verdict {
        InventoryHashesVerdict::Pending => InventoryIntegrity::Pending,
        InventoryHashesVerdict::Valid { .. } => InventoryIntegrity::Valid,
        InventoryHashesVerdict::Invalid { .. } => InventoryIntegrity::Invalid,
    }
}

fn ensure_matching_fingerprint(
    observed: &str,
    expected: &str,
    field: &'static str,
) -> Result<(), MediaPortError> {
    if observed == expected {
        return Ok(());
    }
    Err(projection_integrity_error(
        field,
        "durable device trust evidence disagrees with the signed publication fingerprint",
    ))
}

fn checked_u32(value: usize, field: &'static str) -> Result<u32, MediaPortError> {
    u32::try_from(value).map_err(|_| {
        projection_integrity_error(
            field,
            "durable media collection exceeds the frontend counter range",
        )
    })
}

fn ensure_javascript_safe(value: u64, field: &'static str) -> Result<(), MediaPortError> {
    if value <= MAX_JAVASCRIPT_SAFE_INTEGER {
        return Ok(());
    }
    Err(MediaPortError::new(
        MediaErrorCode::IntegrityFailed,
        "durable media value exceeds the JavaScript safe integer range",
    )
    .with_retryable(false)
    .with_detail("field", json!(field))
    // JSON numbers above the boundary would themselves be rounded, so retain
    // the diagnostic as a string.
    .with_detail("value", json!(value.to_string())))
}

fn projection_integrity_error(field: &'static str, message: &'static str) -> MediaPortError {
    MediaPortError::new(MediaErrorCode::IntegrityFailed, message)
        .with_retryable(false)
        .with_detail("field", json!(field))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ylx_transfer_core::media_library::{DerivedLocalVerified, MediaLibraryProjection};
    use ylx_transfer_core::media_store::{DerivedReceipt, LibraryImportReceipt};

    use super::*;

    fn import_receipt(
        source_identity: &str,
        provenance: serde_json::Value,
    ) -> LibraryImportReceipt {
        LibraryImportReceipt {
            receipt_id: format!("receipt-{source_identity}"),
            import_job_id: format!("import-{source_identity}"),
            source_revision: format!("sha256:{}", "a".repeat(64)),
            source_identity: source_identity.to_string(),
            sealed_inventory_digest: "b".repeat(64),
            provenance,
            local_path: format!("sources/{}", "a".repeat(64)),
            commit_receipt: json!({
                "commit_receipt": "internal-only",
                "publication_payload": [1, 2, 3],
                "publication_signature": [4, 5, 6],
                "publication_public_key": [7, 8, 9]
            }),
            committed_at: "2026-08-06T00:00:00Z".to_string(),
        }
    }

    fn unsigned_provenance() -> serde_json::Value {
        json!({
            "kind": "locally_validated_unsigned",
            "evidence": {
                "source_schema": "raw_capture_v2",
                "validation_report": {"accepted": true, "checks": []},
                "computed_inventory_digest": format!("sha256:{}", "b".repeat(64)),
                "user_admission_receipt": null,
            },
        })
    }

    fn signed_provenance() -> serde_json::Value {
        json!({
            "kind": "device_signed",
            "evidence": {
                "publication_key_fingerprint": format!("sha256:{}", "c".repeat(64)),
                "publication_revision": format!("sha256:{}", "a".repeat(64)),
                "publication_payload": [1, 2, 3],
                "publication_signature": [4, 5, 6],
                "publication_public_key": [7, 8, 9],
            },
        })
    }

    fn projection_with_derived(provenance: serde_json::Value) -> MediaLibraryProjection {
        let receipt = import_receipt("source-1", provenance);
        let mut projection = MediaLibraryProjection::from_import_receipt(&receipt)
            .expect("synthetic import receipt should produce a projection");
        let derived = DerivedLocalVerified::from_receipt(&DerivedReceipt {
            derivation_job_id: "derivation-1".to_string(),
            derived_revision: format!("sha256:{}", "e".repeat(64)),
            source_revision: receipt.source_revision.clone(),
            source_manifest_digest: format!("sha256:{}", "f".repeat(64)),
            profile_revision: format!("sha256:{}", "1".repeat(64)),
            local_path: format!(
                "derivatives/{}/{}/{}",
                "a".repeat(64),
                "1".repeat(64),
                "e".repeat(64)
            ),
            commit_receipt: json!({"commit_receipt": "derived-internal-only"}),
            committed_at: receipt.committed_at.clone(),
        })
        .expect("synthetic derived receipt should be safe");
        projection
            .derived_local
            .insert(derived.tree.derived_revision().clone(), derived);
        projection
    }

    #[test]
    fn library_dto_excludes_internal_commit_and_publication_evidence() {
        let projection = projection_with_derived(unsigned_provenance());
        let mapped = map_media_library_collection(7, &[projection]).expect("map library");
        let encoded = serde_json::to_string(&mapped.value).expect("serialize DTO");

        for forbidden in [
            "commit_receipt",
            "publication_payload",
            "publication_signature",
            "publication_public_key",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "application DTO leaked forbidden field {forbidden}"
            );
        }
        assert!(encoded.contains("sources/"));
        assert!(encoded.contains("derivatives/"));
        assert!(!encoded.contains("../"));
        assert!(!encoded.contains("/tmp/"));

        let source = &mapped.value[0].source_local;
        assert!(matches!(
            source,
            MediaLibrarySourceLocalProjection::Verified {
                provenance: WireSourceProvenance::LocallyValidatedUnsigned {
                    admission: UnsignedAdmission::Required,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn signed_library_provenance_maps_to_trusted_valid_evidence() {
        let receipt = import_receipt("signed-source-1", signed_provenance());
        let projection = MediaLibraryProjection::from_import_receipt(&receipt)
            .expect("signed synthetic receipt should produce a projection");
        let mapped = map_media_library_collection(8, &[projection]).expect("map library");
        let MediaLibrarySourceLocalProjection::Verified { provenance, .. } =
            &mapped.value[0].source_local
        else {
            panic!("expected a verified source projection");
        };
        assert!(matches!(
            provenance,
            WireSourceProvenance::DeviceSigned {
                manifest_signature: SignatureVerdict::Valid,
                producer_key_trust: ProducerKeyTrust::Trusted,
                inventory_integrity: InventoryIntegrity::Valid,
                ..
            }
        ));
    }

    #[test]
    fn library_mapping_preserves_collection_revision_and_has_no_extra_payload() {
        let projection = projection_with_derived(unsigned_provenance());
        let mapped = map_media_library_collection(11, &[projection]).expect("map library");
        assert_eq!(mapped.source_version, 11);
        let value = serde_json::to_value(mapped.value).expect("serialize DTO");
        let object = value[0].as_object().expect("entry object");
        assert_eq!(object.len(), 7);
        assert!(!object.contains_key("sourceArchive"));
        assert!(!object.contains_key("retention"));
    }
}
