use serde::{Deserialize, Serialize};

use crate::library::object_store_port::SourceSha256;
use crate::media_pipeline::{
    evaluate_source_retention, RemoteBundleReceipt, RetentionBlockReason as PipelineBlockReason,
    SourceRetentionDecision, SourceRetentionPolicy, UploadBundleRevision,
};
use crate::media_store::{LibraryLeaseMode, LibraryRevisionKind};

use super::model::{
    remote_receipt_sha256, validate_text, SourceArchiveProjection, SourceLocalState,
    SourceTreeLocator,
};

/// Why a local source tree cannot be proposed for retention cleanup yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionBlockReason {
    DisabledByDefault,
    SourceNotLocallyVerified,
    SourceArchiveNotRemotelyVerified,
    ArchivePolicyMismatch,
    RemoteEvidenceMismatch,
    GracePeriodNotElapsed,
    GracePeriodOverflow,
    InvalidProposalId,
}

/// The only destructive effect this module can propose.
///
/// Deliberately absent: a removable-media/card path, generation, or delete
/// variant. Card cleanup remains outside the PC application's V1 authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum RetentionEffectProposal {
    RemoveLocalSourceTree {
        proposal_id: String,
        source_tree: SourceTreeLocator,
        archive_policy_revision: String,
        remote_bundle_revision: UploadBundleRevision,
        remote_receipt_sha256: SourceSha256,
        archive_verified_at_ms: u64,
        not_before_ms: u64,
        proposed_at_ms: u64,
    },
}

impl RetentionEffectProposal {
    /// The executor must consume this exact exclusive source lease before
    /// deleting local bytes. No card lease/effect can be requested here.
    #[must_use]
    pub fn required_lease(&self) -> (LibraryRevisionKind, &SourceTreeLocator, LibraryLeaseMode) {
        match self {
            Self::RemoveLocalSourceTree { source_tree, .. } => (
                LibraryRevisionKind::Source,
                source_tree,
                LibraryLeaseMode::Exclusive,
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RetentionProjection {
    #[default]
    Disabled,
    Blocked {
        reason: RetentionBlockReason,
        evaluated_at_ms: Option<u64>,
    },
    GracePeriod {
        archive_policy_revision: String,
        archive_verified_at_ms: u64,
        not_before_ms: u64,
        evaluated_at_ms: u64,
    },
    EffectProposed {
        proposal: RetentionEffectProposal,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionEvaluation {
    pub projection: RetentionProjection,
    pub effect: Option<RetentionEffectProposal>,
}

impl RetentionEvaluation {
    fn blocked(reason: RetentionBlockReason, evaluated_at_ms: Option<u64>) -> Self {
        Self {
            projection: if reason == RetentionBlockReason::DisabledByDefault {
                RetentionProjection::Disabled
            } else {
                RetentionProjection::Blocked {
                    reason,
                    evaluated_at_ms,
                }
            },
            effect: None,
        }
    }
}

/// Evaluates a versioned source-retention policy without touching any bytes.
///
/// Eligibility requires all of the following at the same time:
///
/// - retention was explicitly enabled (the default is disabled);
/// - the source tree is still locally verified;
/// - completion-bound remote evidence proves the *source archive*, not just
///   a derivative, under the exact approved archive policy revision;
/// - the configured grace period has elapsed.
///
/// Even an eligible result is only a proposal. The caller must acquire and
/// reassert an exclusive source-revision lease immediately before removing
/// the local tree, then durably record the removal result.
#[must_use]
pub fn evaluate_retention(
    policy: &SourceRetentionPolicy,
    source_local: &SourceLocalState,
    source_archive: &SourceArchiveProjection,
    verified_remote: Option<&RemoteBundleReceipt>,
    now_ms: u64,
    proposal_id: &str,
) -> RetentionEvaluation {
    let SourceRetentionPolicy::AfterVerifiedSourceArchive {
        archive_policy_revision,
        grace_period_seconds,
    } = policy
    else {
        return RetentionEvaluation::blocked(RetentionBlockReason::DisabledByDefault, None);
    };

    let Some(local) = source_local.verified() else {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::SourceNotLocallyVerified,
            Some(now_ms),
        );
    };
    if validate_text("archive_policy_revision", archive_policy_revision, 256).is_err() {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::ArchivePolicyMismatch,
            Some(now_ms),
        );
    }
    let Some(remote) = verified_remote else {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::SourceArchiveNotRemotelyVerified,
            Some(now_ms),
        );
    };
    if remote.source_revision() != local.tree.source_revision() {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::RemoteEvidenceMismatch,
            Some(now_ms),
        );
    }
    match evaluate_source_retention(policy, remote) {
        SourceRetentionDecision::EligibleAfterGracePeriod {
            archive_policy_revision: eligible_policy,
            grace_period_seconds: eligible_grace,
        } if eligible_policy == archive_policy_revision.as_str()
            && eligible_grace == *grace_period_seconds => {}
        SourceRetentionDecision::KeepSource {
            reason: PipelineBlockReason::SourceArchiveNotRemotelyVerified,
        } => {
            return RetentionEvaluation::blocked(
                RetentionBlockReason::SourceArchiveNotRemotelyVerified,
                Some(now_ms),
            )
        }
        _ => {
            return RetentionEvaluation::blocked(
                RetentionBlockReason::ArchivePolicyMismatch,
                Some(now_ms),
            )
        }
    }
    let Some(archive) = source_archive.verified_for_policy(archive_policy_revision) else {
        let reason = if source_archive.proofs().next().is_some() {
            RetentionBlockReason::ArchivePolicyMismatch
        } else {
            RetentionBlockReason::SourceArchiveNotRemotelyVerified
        };
        return RetentionEvaluation::blocked(reason, Some(now_ms));
    };
    let receipt_digest = match remote_receipt_sha256(remote) {
        Ok(digest) => digest,
        Err(_) => {
            return RetentionEvaluation::blocked(
                RetentionBlockReason::RemoteEvidenceMismatch,
                Some(now_ms),
            )
        }
    };
    if archive.bundle_revision != remote.natural_key().upload_bundle_revision
        || archive.storage_profile_identity != remote.natural_key().storage_profile_identity
        || archive.remote_receipt_sha256 != receipt_digest
    {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::RemoteEvidenceMismatch,
            Some(now_ms),
        );
    }

    let Some(grace_ms) = grace_period_seconds.checked_mul(1_000) else {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::GracePeriodOverflow,
            Some(now_ms),
        );
    };
    let Some(not_before_ms) = archive.verified_at_ms.checked_add(grace_ms) else {
        return RetentionEvaluation::blocked(
            RetentionBlockReason::GracePeriodOverflow,
            Some(now_ms),
        );
    };
    if now_ms < not_before_ms {
        return RetentionEvaluation {
            projection: RetentionProjection::GracePeriod {
                archive_policy_revision: archive_policy_revision.clone(),
                archive_verified_at_ms: archive.verified_at_ms,
                not_before_ms,
                evaluated_at_ms: now_ms,
            },
            effect: None,
        };
    }
    if validate_text("retention_proposal_id", proposal_id, 256).is_err() {
        return RetentionEvaluation::blocked(RetentionBlockReason::InvalidProposalId, Some(now_ms));
    }

    let effect = RetentionEffectProposal::RemoveLocalSourceTree {
        proposal_id: proposal_id.to_string(),
        source_tree: local.tree.clone(),
        archive_policy_revision: archive_policy_revision.clone(),
        remote_bundle_revision: archive.bundle_revision.clone(),
        remote_receipt_sha256: archive.remote_receipt_sha256,
        archive_verified_at_ms: archive.verified_at_ms,
        not_before_ms,
        proposed_at_ms: now_ms,
    };
    RetentionEvaluation {
        projection: RetentionProjection::EffectProposed {
            proposal: effect.clone(),
        },
        effect: Some(effect),
    }
}
