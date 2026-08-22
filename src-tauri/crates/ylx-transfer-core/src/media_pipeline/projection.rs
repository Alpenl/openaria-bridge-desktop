use serde::{Deserialize, Serialize};

use crate::ingest::{SourceContentRevision, SourceProvenance, SourceSchema};
use crate::normalization::{DerivedRevision, ProfileRevision};

use super::{
    evaluate_source_retention, AwaitingDependency, PipelineActionRequired, PipelineError,
    PipelineEvidence, PipelinePolicy, RemoteSourceArchive, RestartReplayDecision,
    RetentionBlockReason, SessionPipeline, SessionPipelineId, SourceRetentionDecision,
    SourceRetentionPolicy, UploadBundleRevision,
};

/// Read model with three independent durability layers. It deliberately has
/// no aggregate percent and no ambiguous `uploaded` or `backed_up` boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPipelineProjection {
    pub pipeline_id: SessionPipelineId,
    pub source: SourceLayerProjection,
    pub derived: DerivedLayerProjection,
    pub remote: RemoteLayerProjection,
    pub next: PipelineNextProjection,
    pub source_retention: SourceRetentionDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SourceLayerProjection {
    ImportPending,
    LocalVerified {
        source_revision: SourceContentRevision,
        provenance: ProvenanceProjection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceProjection {
    DeviceSigned { publication_key_fingerprint: String },
    LocallyValidatedUnsigned { source_schema: SourceSchema },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DerivedLayerProjection {
    NotRequested,
    WaitingForLocalSource {
        profile_revision: ProfileRevision,
    },
    WaitingForDerivation {
        profile_revision: ProfileRevision,
    },
    LocalVerified {
        source_revision: SourceContentRevision,
        profile_revision: ProfileRevision,
        derived_revision: DerivedRevision,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RemoteLayerProjection {
    NotRequested,
    WaitingForLocalDerivative,
    ActionRequired {
        action: PipelineActionRequired,
    },
    WaitingForFrozenBundle,
    WaitingForUploadEnqueue {
        upload_bundle_revision: UploadBundleRevision,
    },
    UploadingOrVerifying {
        upload_bundle_revision: UploadBundleRevision,
    },
    DerivedBundleVerified {
        upload_bundle_revision: UploadBundleRevision,
        derived_revision: DerivedRevision,
        /// `NotArchived` here is intentional: a verified derivative alone is
        /// not an original/source backup.
        source_archive: RemoteSourceArchive,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "next", rename_all = "snake_case")]
pub enum PipelineNextProjection {
    Awaiting { dependency: AwaitingDependency },
    EnqueueDerivation,
    ActionRequired { action: PipelineActionRequired },
    FreezeUploadBundle,
    EnqueueUpload,
    Complete,
}

impl SessionPipeline {
    pub fn snapshot(
        &self,
        evidence: PipelineEvidence<'_>,
    ) -> Result<MediaPipelineProjection, PipelineError> {
        let decision = self.recover(evidence)?;
        let source = match evidence.source {
            None => SourceLayerProjection::ImportPending,
            Some(receipt) => SourceLayerProjection::LocalVerified {
                source_revision: receipt.content_revision().clone(),
                provenance: project_provenance(receipt.provenance()),
            },
        };

        let derived = match self.policy() {
            PipelinePolicy::ImportOnly => DerivedLayerProjection::NotRequested,
            PipelinePolicy::AutoNormalize { profile_revision }
            | PipelinePolicy::AutoUpload {
                profile_revision, ..
            } => match (evidence.source, evidence.derived) {
                (None, _) => DerivedLayerProjection::WaitingForLocalSource {
                    profile_revision: profile_revision.clone(),
                },
                (Some(_), None) => DerivedLayerProjection::WaitingForDerivation {
                    profile_revision: profile_revision.clone(),
                },
                (Some(_), Some(receipt)) => DerivedLayerProjection::LocalVerified {
                    source_revision: receipt.source_revision().clone(),
                    profile_revision: receipt.profile_revision().clone(),
                    derived_revision: receipt.derived_revision().clone(),
                },
            },
        };

        let remote = project_remote(self.policy(), evidence, &decision);
        let source_retention = match evidence.remote {
            Some(receipt) if matches!(&decision, RestartReplayDecision::Complete) => {
                evaluate_source_retention(self.policy().source_retention(), receipt)
            }
            _ => SourceRetentionDecision::KeepSource {
                reason: match self.policy().source_retention() {
                    SourceRetentionPolicy::Disabled => RetentionBlockReason::DisabledByDefault,
                    SourceRetentionPolicy::AfterVerifiedSourceArchive { .. } => {
                        RetentionBlockReason::SourceArchiveNotRemotelyVerified
                    }
                },
            },
        };

        Ok(MediaPipelineProjection {
            pipeline_id: self.id().clone(),
            source,
            derived,
            remote,
            next: project_next(decision),
            source_retention,
        })
    }
}

fn project_provenance(provenance: &SourceProvenance) -> ProvenanceProjection {
    match provenance {
        SourceProvenance::DeviceSigned(signed) => ProvenanceProjection::DeviceSigned {
            publication_key_fingerprint: signed.publication_key_fingerprint().to_string(),
        },
        SourceProvenance::LocallyValidatedUnsigned(unsigned) => {
            ProvenanceProjection::LocallyValidatedUnsigned {
                source_schema: unsigned.source_schema(),
            }
        }
    }
}

fn project_remote(
    policy: &PipelinePolicy,
    evidence: PipelineEvidence<'_>,
    decision: &RestartReplayDecision,
) -> RemoteLayerProjection {
    if !matches!(policy, PipelinePolicy::AutoUpload { .. }) {
        return RemoteLayerProjection::NotRequested;
    }
    if evidence.derived.is_none() {
        return RemoteLayerProjection::WaitingForLocalDerivative;
    }
    if let RestartReplayDecision::ActionRequired { action } = decision {
        return RemoteLayerProjection::ActionRequired {
            action: action.clone(),
        };
    }
    let Some(bundle) = evidence.bundle else {
        return RemoteLayerProjection::WaitingForFrozenBundle;
    };
    if let (RestartReplayDecision::Complete, Some(remote)) = (decision, evidence.remote) {
        return RemoteLayerProjection::DerivedBundleVerified {
            upload_bundle_revision: remote.natural_key().upload_bundle_revision.clone(),
            derived_revision: remote.derived_revision().clone(),
            source_archive: remote.source_archive().clone(),
        };
    }
    if matches!(decision, RestartReplayDecision::EnqueueUpload { .. }) {
        return RemoteLayerProjection::WaitingForUploadEnqueue {
            upload_bundle_revision: bundle.revision().clone(),
        };
    }
    RemoteLayerProjection::UploadingOrVerifying {
        upload_bundle_revision: bundle.revision().clone(),
    }
}

fn project_next(decision: RestartReplayDecision) -> PipelineNextProjection {
    match decision {
        RestartReplayDecision::Awaiting { dependency } => {
            PipelineNextProjection::Awaiting { dependency }
        }
        RestartReplayDecision::EnqueueDerivation { .. } => {
            PipelineNextProjection::EnqueueDerivation
        }
        RestartReplayDecision::ActionRequired { action } => {
            PipelineNextProjection::ActionRequired { action }
        }
        RestartReplayDecision::FreezeUploadBundle { .. } => {
            PipelineNextProjection::FreezeUploadBundle
        }
        RestartReplayDecision::EnqueueUpload { .. } => PipelineNextProjection::EnqueueUpload,
        RestartReplayDecision::Complete => PipelineNextProjection::Complete,
    }
}
