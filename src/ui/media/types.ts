import type {
  CandidateVerdict,
  DerivationProgress,
  ImportProgress,
  MediaError,
  MediaLibraryEntryProjection,
  MediaJobCommand as RuntimeMediaJobCommand,
  RequiredAction,
  SourceKind,
  SourceLayer,
  SourceProvenance,
  SourceSchema,
  UploadProgress,
  ValidationProgress,
} from "../../runtime/media/types";
import type { MediaResourceName } from "../../runtime/media/backend";

export type { MediaLibraryEntryProjection } from "../../runtime/media/types";

/**
 * Stable view contract for the removable-media workspace.
 *
 * The runtime owns discovery and every durable job. This module only renders
 * immutable projections and turns DOM events into typed intents.
 */

export type MediaIssue = MediaError;

export type MediaPolicyKey =
  | "autoScan"
  | "autoImport"
  | "autoNormalize"
  | "autoUploadDerived"
  | "uploadSourceVideo"
  | "autoDeletePcSource"
  | "preventSleepWhileActive";

export interface MediaPolicySetting {
  readonly enabled: boolean;
  readonly editable: boolean;
  readonly inherited: boolean;
}

export type MediaWorkflowPolicy = Readonly<Record<MediaPolicyKey, MediaPolicySetting>>;

export function defaultMediaWorkflowPolicy(): MediaWorkflowPolicy {
  return {
    autoScan: { enabled: false, editable: false, inherited: false },
    autoImport: { enabled: false, editable: false, inherited: false },
    autoNormalize: { enabled: false, editable: false, inherited: false },
    autoUploadDerived: { enabled: false, editable: false, inherited: false },
    uploadSourceVideo: { enabled: false, editable: false, inherited: false },
    autoDeletePcSource: { enabled: false, editable: false, inherited: false },
    preventSleepWhileActive: { enabled: false, editable: false, inherited: false },
  };
}

export type MediaScanState = "idle" | "scanning" | "ready" | "failed";

export interface MediaScanSnapshot {
  readonly state: MediaScanState;
  readonly sourceCount: number;
  readonly candidateCount: number;
  readonly lastCompletedAtLabel: string | null;
  readonly issue: MediaIssue | null;
}

export interface MediaResourceDegradation {
  readonly resource: MediaResourceName;
  readonly message: string;
  readonly retryable: boolean;
  readonly retrying: boolean;
}

export type MediaAcquisitionSourceKind = Exclude<SourceKind, "lan">;
export type MediaCandidateAcquisitionKind = SourceKind;
export type MediaSourceAvailability = "present" | "missing";
export type MediaSourceScanState = "idle" | "queued" | "scanning" | "complete" | "failed";

export type MediaReleaseSnapshot =
  | { readonly kind: "not_applicable" }
  | { readonly kind: "in_use"; readonly activeReaders: number }
  | { readonly kind: "ready" }
  | { readonly kind: "releasing" }
  | { readonly kind: "released"; readonly platformEjectSupported: boolean }
  | { readonly kind: "ejecting" }
  | { readonly kind: "ejected" }
  | { readonly kind: "release_failed"; readonly issue: MediaIssue }
  | { readonly kind: "eject_vetoed"; readonly reason: string }
  | { readonly kind: "eject_failed"; readonly issue: MediaIssue }
  | { readonly kind: "removed" };

export interface MediaAcquisitionSourceSnapshot {
  readonly id: string;
  readonly kind: MediaAcquisitionSourceKind;
  readonly displayName: string;
  readonly locationLabel: string;
  readonly fileSystem: string | null;
  readonly capacityBytes: number | null;
  readonly availability: MediaSourceAvailability;
  readonly scanState: MediaSourceScanState;
  readonly candidateCount: number;
  readonly scanIssue: MediaIssue | null;
  readonly release: MediaReleaseSnapshot;
}

export type MediaCandidateVerdictKind = CandidateVerdict;

export interface MediaCandidateVerdict {
  readonly kind: MediaCandidateVerdictKind;
  readonly detail: string | null;
}

export type MediaSourceKind = SourceSchema;
export type MediaProvenance = SourceProvenance;

export type MediaRequirement = "required" | "waiting_for_media" | "not_required" | "not_applicable";

export interface MediaCandidateSnapshot {
  readonly id: string;
  readonly sourceKey: string;
  readonly acquisitionSourceId: string;
  readonly pipelineId: string | null;
  readonly displayName: string;
  readonly sessionIdLabel: string;
  readonly acquisitionKind: MediaCandidateAcquisitionKind;
  readonly sourceKind: MediaSourceKind;
  readonly sourceLocationLabel: string;
  readonly verdict: MediaCandidateVerdict;
  readonly provenance: MediaProvenance;
  readonly totalBytes: number | null;
  readonly durationSeconds: number | null;
  readonly mediaRequirement: MediaRequirement;
  readonly selectable: boolean;
  readonly selected: boolean;
  readonly expanded: boolean;
}

export type SourceLocalState =
  | "not_imported"
  | "importing"
  | "waiting_for_media"
  | "verifying"
  | "committing"
  | "local_verified"
  | "retry_wait"
  | "pausing"
  | "paused"
  | "action_required"
  | "failed"
  | "cancelled";

export type DerivedLocalState =
  | "not_started"
  | "waiting_for_source"
  | "deriving"
  | "validating"
  | "committing"
  | "derived_verified"
  | "retry_wait"
  | "pausing"
  | "paused"
  | "action_required"
  | "failed"
  | "cancelled";

export type RemoteState =
  | "disabled"
  | "not_started"
  | "waiting_for_derived"
  | "uploading"
  | "verifying"
  | "remote_verified"
  | "retry_wait"
  | "pausing"
  | "paused"
  | "action_required"
  | "failed"
  | "cancelled";

export interface SourceLayerSnapshot {
  readonly state: SourceLocalState;
  readonly revisionLabel: string | null;
  readonly provenance: MediaProvenance;
  readonly retentionState: SourceLayer["retentionState"];
}

export interface DerivedLayerSnapshot {
  readonly state: DerivedLocalState;
  readonly revisionLabel: string | null;
  readonly profileLabel: string | null;
}

export type MediaRemoteSourceVideoState = "not_included" | "included_verified" | "unknown";

export interface RemoteLayerSnapshot {
  readonly state: RemoteState;
  readonly bundleRevisionLabel: string | null;
  readonly sourceVideoUploadState: MediaRemoteSourceVideoState;
}

export type MediaJobKind = "import" | "derivation" | "validation" | "upload";
export type MediaJobCommand = RuntimeMediaJobCommand;

export type MediaJobState =
  | "disabled"
  | "not_started"
  | "blocked"
  | "queued"
  | "waiting_for_media"
  | "waiting_for_source"
  | "preflighting"
  | "copying"
  | "verifying"
  | "probing"
  | "planning"
  | "encoding"
  | "validating"
  | "committing"
  | "uploading"
  | "remote_verifying"
  | "action_required"
  | "retry_wait"
  | "pausing"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "failed"
  | "completed";

export type MediaRequiredActionKind = RequiredAction["kind"];

export interface MediaRequiredAction {
  readonly kind: MediaRequiredActionKind;
  readonly label: string;
  readonly detail: string;
}

interface MediaJobSnapshotBase {
  readonly id: string;
  readonly state: MediaJobState;
  readonly issue: MediaIssue | null;
  readonly requiredAction: MediaRequiredAction | null;
  readonly availableCommands: readonly MediaJobCommand[];
}

export type MediaImportProgress = ImportProgress;
export type MediaDerivationProgress = DerivationProgress;
export type MediaValidationProgress = ValidationProgress;
export type MediaUploadProgress = UploadProgress;

export interface MediaImportJobSnapshot extends MediaJobSnapshotBase {
  readonly kind: "import";
  readonly progress: MediaImportProgress | null;
}

export interface MediaDerivationJobSnapshot extends MediaJobSnapshotBase {
  readonly kind: "derivation";
  readonly progress: MediaDerivationProgress | null;
}

export interface MediaValidationJobSnapshot extends MediaJobSnapshotBase {
  readonly kind: "validation";
  readonly progress: MediaValidationProgress | null;
}

export interface MediaUploadJobSnapshot extends MediaJobSnapshotBase {
  readonly kind: "upload";
  readonly progress: MediaUploadProgress | null;
}

export type MediaJobSnapshot =
  MediaImportJobSnapshot | MediaDerivationJobSnapshot | MediaValidationJobSnapshot | MediaUploadJobSnapshot;

export interface MediaPipelineSnapshot {
  readonly id: string;
  readonly candidateId: string;
  readonly sourceKey: string;
  readonly source: SourceLayerSnapshot;
  readonly derived: DerivedLayerSnapshot;
  readonly remote: RemoteLayerSnapshot;
  readonly jobs: {
    readonly import: MediaImportJobSnapshot;
    readonly derivation: MediaDerivationJobSnapshot;
    readonly validation: MediaValidationJobSnapshot;
    readonly upload: MediaUploadJobSnapshot;
  };
}

export type MediaBatchItemOutcome =
  | { readonly kind: "succeeded"; readonly detail: string }
  | { readonly kind: "processing"; readonly detail: string }
  | { readonly kind: "action_required"; readonly detail: string }
  | { readonly kind: "failed"; readonly detail: string; readonly retryable: boolean };

export interface MediaBatchItemSnapshot {
  readonly candidateId: string;
  readonly sourceKey: string;
  readonly displayName: string;
  readonly outcome: MediaBatchItemOutcome;
}

export type MediaBatchState = "running" | "action_required" | "completed" | "cancelled" | "failed";

export interface MediaBatchSnapshot {
  readonly id: string;
  readonly state: MediaBatchState;
  readonly startedAtLabel: string;
  readonly items: readonly MediaBatchItemSnapshot[];
  readonly operationIssue: MediaIssue | null;
  readonly canCancel: boolean;
  readonly canDismiss: boolean;
}

export interface MediaWorkspaceSnapshot {
  readonly scan: MediaScanSnapshot;
  readonly resourceDegradations: readonly MediaResourceDegradation[];
  readonly policy: MediaWorkflowPolicy;
  readonly sources: readonly MediaAcquisitionSourceSnapshot[];
  readonly library: readonly MediaLibraryEntryProjection[];
  readonly candidates: readonly MediaCandidateSnapshot[];
  readonly pipelines: readonly MediaPipelineSnapshot[];
  readonly batch: MediaBatchSnapshot | null;
  readonly unsignedApprovalArmed: boolean;
}

export type MediaWorkspaceAction =
  | { readonly kind: "media/scanAll" }
  | { readonly kind: "media/retryResource"; readonly resource: MediaResourceName }
  | { readonly kind: "media/revokeTrustedProducer"; readonly keyFingerprint: string }
  | { readonly kind: "media/exportLibraryEntry"; readonly entryKey: string }
  | { readonly kind: "media/rescanSource"; readonly sourceId: string }
  | { readonly kind: "media/releaseSource"; readonly sourceId: string }
  | { readonly kind: "media/ejectSource"; readonly sourceId: string }
  | { readonly kind: "media/toggleCandidateDetails"; readonly candidateId: string }
  | {
      readonly kind: "media/candidateSelectionChange";
      readonly candidateId: string;
      readonly selected: boolean;
    }
  | { readonly kind: "media/allCandidateSelectionChange"; readonly selected: boolean }
  | { readonly kind: "media/importSelected"; readonly candidateIds: readonly string[] }
  | { readonly kind: "media/configureStorage" }
  | { readonly kind: "media/approveUnsignedUpload"; readonly pipelineId: string }
  | {
      readonly kind: "media/jobCommand";
      readonly pipelineId: string;
      readonly jobId: string;
      readonly jobKind: MediaJobKind;
      readonly command: MediaJobCommand;
    }
  | { readonly kind: "media/cancelBatch"; readonly batchId: string }
  | { readonly kind: "media/dismissBatch"; readonly batchId: string };

export type MediaWorkspaceDispatch = (action: MediaWorkspaceAction) => void;
