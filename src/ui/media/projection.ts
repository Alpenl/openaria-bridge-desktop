import type { MediaRuntimeState } from "../../runtime/media/reducer";
import type {
  DerivationJob,
  ImportBatchOutcome,
  ImportJob,
  MediaDescriptor,
  PipelineBatchOutcome,
  PipelineSession,
  RequiredAction,
  ScanCandidate,
} from "../../runtime/media/types";
import {
  defaultMediaWorkflowPolicy,
  type DerivedLocalState,
  type MediaAcquisitionSourceKind,
  type MediaAcquisitionSourceSnapshot,
  type MediaBatchItemOutcome,
  type MediaBatchSnapshot,
  type MediaBatchState,
  type MediaCandidateSnapshot,
  type MediaImportJobSnapshot,
  type MediaJobCommand,
  type MediaJobState,
  type MediaPipelineSnapshot,
  type MediaReleaseSnapshot,
  type MediaResourceDegradation,
  type MediaRemoteSourceVideoState,
  type MediaRequiredAction,
  type MediaRequirement,
  type MediaUploadJobSnapshot,
  type MediaValidationJobSnapshot,
  type MediaWorkflowPolicy,
  type MediaWorkspaceSnapshot,
  type RemoteState,
  type SourceLocalState,
} from "./types";

const EMPTY_IDS: ReadonlySet<string> = new Set<string>();
const EMPTY_KINDS: ReadonlyMap<string, MediaAcquisitionSourceKind> = new Map();
const EMPTY_RELEASES: ReadonlyMap<string, MediaReleaseSnapshot> = new Map();

export interface MediaWorkspaceUiProjectionState {
  readonly selectedCandidateIds?: ReadonlySet<string>;
  readonly unsignedApprovalCandidateIds?: ReadonlySet<string>;
  readonly expandedCandidateIds?: ReadonlySet<string>;
  readonly sourceKindById?: ReadonlyMap<string, MediaAcquisitionSourceKind>;
  readonly releaseOverrideBySourceId?: ReadonlyMap<string, MediaReleaseSnapshot>;
  readonly policy?: MediaWorkflowPolicy;
  readonly batch?: MediaBatchSnapshot | null;
}

function runtimeValues<T>(resource: { readonly value: T | null; readonly lastGood: T | null }): T | null {
  return resource.value ?? resource.lastGood;
}

function releaseFromDescriptor(media: MediaDescriptor): MediaReleaseSnapshot {
  if (media.presence === "removed") return { kind: "removed" };
  if (media.readerCount > 0) return { kind: "in_use", activeReaders: media.readerCount };
  if (media.handleState === "in_use") return { kind: "ready" };
  switch (media.ejectState) {
    case "unsupported":
      return { kind: "released", platformEjectSupported: false };
    case "blocked":
      return { kind: "eject_vetoed", reason: media.ejectVeto ?? "系统未提供弹出原因" };
    case "available":
      return { kind: "released", platformEjectSupported: true };
    case "ejecting":
      return { kind: "ejecting" };
    case "ejected":
      return { kind: "ejected" };
    case "failed":
      return {
        kind: "eject_failed",
        issue: { code: "media_unavailable", message: "系统未能安全弹出介质", retryable: true },
      };
  }
}

function sourceKind(
  media: MediaDescriptor,
  candidates: readonly ScanCandidate[],
  configuredKinds: ReadonlyMap<string, MediaAcquisitionSourceKind>,
): MediaAcquisitionSourceKind {
  const configured = configuredKinds.get(media.id);
  if (configured !== undefined) return configured;
  const kinds = candidates
    .filter((candidate) => candidate.mediaId === media.id)
    .map((candidate) => candidate.sourceKind);
  if (kinds.includes("local_folder")) return "local_folder";
  if (kinds.includes("legacy_removable_media")) return "legacy_removable_media";
  return "removable_media";
}

function projectSource(
  media: MediaDescriptor,
  candidates: readonly ScanCandidate[],
  scanState: MediaAcquisitionSourceSnapshot["scanState"],
  configuredKinds: ReadonlyMap<string, MediaAcquisitionSourceKind>,
  releases: ReadonlyMap<string, MediaReleaseSnapshot>,
): MediaAcquisitionSourceSnapshot {
  const kind = sourceKind(media, candidates, configuredKinds);
  const scanIssue =
    media.accessIssue === null
      ? null
      : {
          code: "media_unavailable" as const,
          message: media.accessIssue,
          retryable: false,
        };
  return {
    id: media.id,
    kind,
    displayName: media.displayName,
    locationLabel: media.mountPath ?? "挂载路径不可用",
    fileSystem: media.filesystem,
    capacityBytes: null,
    availability: media.presence === "present" ? "present" : "missing",
    scanState,
    candidateCount: candidates.filter((candidate) => candidate.mediaId === media.id).length,
    scanIssue,
    release:
      kind === "local_folder" ? { kind: "not_applicable" } : (releases.get(media.id) ?? releaseFromDescriptor(media)),
  };
}

function requiredAction(action: RequiredAction | null): MediaRequiredAction | null {
  if (action === null) return null;
  const label = (() => {
    switch (action.kind) {
      case "approve_unsigned_source":
        return "未签名源视频上传未批准";
      case "configure_storage":
        return "对象存储尚未配置";
      case "install_supported_encoder":
        return "规范化编码不可用";
      case "resolve_policy":
        return "规范化质量策略待处理";
      case "retry_remote_verification":
        return "远端验证需要重试";
    }
  })();
  return { kind: action.kind, label, detail: action.message };
}

function pausedState(state: MediaJobState, desiredRunState: "run" | "paused" | "cancelled"): MediaJobState {
  if (state === "pausing" || state === "paused") return state;
  if (desiredRunState !== "paused") return state;
  if (
    state === "disabled" ||
    state === "not_started" ||
    state === "completed" ||
    state === "cancelled" ||
    state === "failed" ||
    state === "cancelling"
  ) {
    return state;
  }
  return "paused";
}

function commandsFor(state: MediaJobState, retryable: boolean): readonly MediaJobCommand[] {
  switch (state) {
    case "paused":
      return ["resume", "cancel"];
    case "failed":
      return retryable ? ["retry"] : [];
    case "retry_wait":
      return ["retry", "cancel"];
    case "pausing":
      return ["cancel"];
    case "waiting_for_media":
    case "action_required":
      return ["cancel"];
    case "queued":
    case "waiting_for_source":
    case "preflighting":
    case "copying":
    case "verifying":
    case "probing":
    case "planning":
    case "encoding":
    case "validating":
    case "committing":
    case "uploading":
    case "remote_verifying":
      return ["pause", "cancel"];
    case "disabled":
    case "not_started":
    case "blocked":
    case "cancelling":
    case "cancelled":
    case "completed":
      return [];
  }
}

function importState(job: ImportJob | undefined, pipeline: PipelineSession): MediaJobState {
  const state = job?.state ?? pipeline.source.state;
  const projected = state === "local_verified" ? "completed" : state === "not_started" ? "not_started" : state;
  return pausedState(projected, job?.desiredRunState ?? pipeline.desiredRunState);
}

function sourceLayerState(pipeline: PipelineSession, jobState: MediaJobState): SourceLocalState {
  if (jobState === "retry_wait" || jobState === "pausing" || jobState === "paused") return jobState;
  switch (pipeline.source.state) {
    case "not_started":
      return "not_imported";
    case "queued":
    case "preflighting":
    case "copying":
      return "importing";
    case "waiting_for_media":
      return "waiting_for_media";
    case "verifying":
      return "verifying";
    case "committing":
      return "committing";
    case "local_verified":
      return "local_verified";
    case "retry_wait":
      return "retry_wait";
    case "pausing":
      return "pausing";
    case "paused":
      return "paused";
    case "cancelling":
      return "importing";
    case "cancelled":
      return "cancelled";
    case "failed":
      return "failed";
  }
}

function projectImportJob(pipeline: PipelineSession, runtimeJob: ImportJob | undefined): MediaImportJobSnapshot {
  const state = importState(runtimeJob, pipeline);
  const issue = runtimeJob?.failure ?? pipeline.source.failure;
  return {
    kind: "import",
    id: runtimeJob?.id ?? pipeline.source.jobId ?? pipeline.id,
    state,
    progress: runtimeJob?.progress ?? pipeline.source.progress,
    issue,
    requiredAction: null,
    availableCommands: commandsFor(state, issue?.retryable ?? false),
  };
}

function derivationState(job: DerivationJob | undefined, pipeline: PipelineSession): MediaJobState {
  const state = job?.state ?? pipeline.derived.state;
  const projected =
    state === "derived_verified"
      ? "completed"
      : state === "action_required"
        ? "action_required"
        : state === "not_started"
          ? pipeline.policy.autoNormalize
            ? "not_started"
            : "disabled"
          : state;
  return pausedState(projected, job?.desiredRunState ?? pipeline.desiredRunState);
}

function derivedLayerState(pipeline: PipelineSession, jobState: MediaJobState): DerivedLocalState {
  if (jobState === "retry_wait" || jobState === "pausing" || jobState === "paused") return jobState;
  switch (pipeline.derived.state) {
    case "not_started":
      return "not_started";
    case "waiting_for_source":
      return "waiting_for_source";
    case "queued":
    case "probing":
    case "planning":
    case "encoding":
      return "deriving";
    case "validating":
      return "validating";
    case "committing":
      return "committing";
    case "derived_verified":
      return "derived_verified";
    case "action_required":
      return "action_required";
    case "retry_wait":
      return "retry_wait";
    case "pausing":
      return "pausing";
    case "paused":
      return "paused";
    case "cancelling":
      return "deriving";
    case "cancelled":
      return "cancelled";
    case "failed":
      return "failed";
  }
}

function projectDerivationJob(pipeline: PipelineSession, runtimeJob: DerivationJob | undefined) {
  const state = derivationState(runtimeJob, pipeline);
  const issue = runtimeJob?.failure ?? pipeline.derived.failure;
  return {
    kind: "derivation" as const,
    id: runtimeJob?.id ?? pipeline.derived.jobId ?? pipeline.id,
    state,
    progress: runtimeJob?.progress ?? pipeline.derived.progress,
    issue,
    requiredAction: requiredAction(pipeline.derived.action),
    availableCommands:
      runtimeJob === undefined && pipeline.derived.jobId === null ? [] : commandsFor(state, issue?.retryable ?? false),
  };
}

function projectValidationJob(
  pipeline: PipelineSession,
  runtimeJob: DerivationJob | undefined,
): MediaValidationJobSnapshot {
  let state: MediaJobState;
  if (!pipeline.policy.autoNormalize && pipeline.derived.state === "not_started") {
    state = "disabled";
  } else {
    switch (pipeline.derived.state) {
      case "validating":
        state = pausedState("validating", runtimeJob?.desiredRunState ?? pipeline.desiredRunState);
        break;
      case "derived_verified":
      case "committing":
        state = "completed";
        break;
      case "failed": {
        const failure = runtimeJob?.failure ?? pipeline.derived.failure;
        state = failure?.code === "integrity_failed" ? "failed" : "blocked";
        break;
      }
      case "cancelled":
        state = "cancelled";
        break;
      case "action_required":
        state = "action_required";
        break;
      case "retry_wait":
        state = "retry_wait";
        break;
      case "pausing":
        state = "pausing";
        break;
      case "paused":
        state = "paused";
        break;
      default:
        state = "blocked";
    }
  }
  return {
    kind: "validation",
    id: runtimeJob?.id ?? pipeline.derived.jobId ?? pipeline.id,
    state,
    progress: runtimeJob?.validation ?? pipeline.derived.validation,
    issue: state === "failed" ? (runtimeJob?.failure ?? pipeline.derived.failure) : null,
    requiredAction: null,
    availableCommands: [],
  };
}

function uploadState(pipeline: PipelineSession): MediaJobState {
  const mapped: MediaJobState = (() => {
    switch (pipeline.remote.state) {
      case "disabled":
        return "disabled";
      case "waiting_for_derived":
        return "waiting_for_source";
      case "queued":
        return "queued";
      case "uploading":
        return "uploading";
      case "verifying":
        return "remote_verifying";
      case "object_store_verified":
        return "completed";
      case "action_required":
        return "action_required";
      case "retry_wait":
        return "retry_wait";
      case "pausing":
        return "pausing";
      case "paused":
        return "paused";
      case "cancelling":
        return "cancelling";
      case "cancelled":
        return "cancelled";
      case "failed":
        return "failed";
    }
  })();
  return pausedState(mapped, pipeline.desiredRunState);
}

function remoteLayerState(pipeline: PipelineSession, state: MediaJobState): RemoteState {
  if (state === "retry_wait" || state === "pausing" || state === "paused") return state;
  switch (pipeline.remote.state) {
    case "disabled":
      return "disabled";
    case "waiting_for_derived":
    case "queued":
      return "waiting_for_derived";
    case "uploading":
      return "uploading";
    case "verifying":
      return "verifying";
    case "object_store_verified":
      return "remote_verified";
    case "action_required":
      return "action_required";
    case "retry_wait":
      return "retry_wait";
    case "pausing":
      return "pausing";
    case "paused":
      return "paused";
    case "cancelling":
      return "uploading";
    case "cancelled":
      return "cancelled";
    case "failed":
      return "failed";
  }
}

function projectUploadJob(pipeline: PipelineSession): MediaUploadJobSnapshot {
  const state = uploadState(pipeline);
  return {
    kind: "upload",
    id: pipeline.remote.uploadJobId ?? pipeline.id,
    state,
    progress: pipeline.remote.progress,
    issue: pipeline.remote.failure,
    requiredAction: requiredAction(pipeline.remote.action),
    availableCommands: commandsFor(state, pipeline.remote.failure?.retryable ?? false),
  };
}

function sourceVideoState(pipeline: PipelineSession): MediaRemoteSourceVideoState {
  if (pipeline.remote.state !== "object_store_verified") return "unknown";
  return pipeline.policy.uploadSourceVideo ? "included_verified" : "not_included";
}

function projectPipeline(
  pipeline: PipelineSession,
  imports: readonly ImportJob[],
  derivations: readonly DerivationJob[],
): MediaPipelineSnapshot {
  const importJob = imports.find((job) => job.id === pipeline.source.jobId);
  const derivationJob = derivations.find((job) => job.id === pipeline.derived.jobId);
  const projectedImport = projectImportJob(pipeline, importJob);
  const projectedDerivation = projectDerivationJob(pipeline, derivationJob);
  const projectedUpload = projectUploadJob(pipeline);
  return {
    id: pipeline.id,
    candidateId: pipeline.candidateId,
    sourceKey: pipeline.sourceSummary.sourceKey,
    source: {
      state: sourceLayerState(pipeline, projectedImport.state),
      revisionLabel: pipeline.source.sourceId,
      provenance: pipeline.sourceSummary.provenance,
      retentionState: pipeline.source.retentionState,
    },
    derived: {
      state: derivedLayerState(pipeline, projectedDerivation.state),
      revisionLabel: pipeline.derived.derivedId,
      profileLabel: derivationJob?.profileId ?? null,
    },
    remote: {
      state: remoteLayerState(pipeline, projectedUpload.state),
      bundleRevisionLabel: pipeline.remote.bundleId,
      sourceVideoUploadState: sourceVideoState(pipeline),
    },
    jobs: {
      import: projectedImport,
      derivation: projectedDerivation,
      validation: projectValidationJob(pipeline, derivationJob),
      upload: projectedUpload,
    },
  };
}

function mediaRequirement(candidate: ScanCandidate, pipeline: PipelineSession | undefined): MediaRequirement {
  if (candidate.sourceKind === "lan") return "not_applicable";
  if (pipeline?.source.state === "waiting_for_media") return "waiting_for_media";
  if (pipeline?.source.state === "local_verified") return "not_required";
  return candidate.mediaRequired ? "required" : "not_required";
}

function projectCandidate(
  candidate: ScanCandidate,
  mediaById: ReadonlyMap<string, MediaDescriptor>,
  pipeline: PipelineSession | undefined,
  currentlyScanned: boolean,
  selected: ReadonlySet<string>,
  expanded: ReadonlySet<string>,
): MediaCandidateSnapshot {
  const media = mediaById.get(candidate.mediaId);
  const sourceLabel = media === undefined ? candidate.relativePath : `${media.displayName} · ${candidate.relativePath}`;
  return {
    id: candidate.id,
    sourceKey: candidate.sourceKey,
    acquisitionSourceId: candidate.mediaId,
    pipelineId: pipeline?.id ?? null,
    displayName: candidate.displayName,
    sessionIdLabel: candidate.sessionId ?? candidate.id,
    acquisitionKind: candidate.sourceKind,
    sourceKind: candidate.schema,
    sourceLocationLabel: sourceLabel,
    verdict: { kind: candidate.verdict, detail: candidate.reason?.message ?? null },
    provenance: candidate.provenance,
    totalBytes: candidate.bytes,
    durationSeconds: candidate.durationSeconds,
    mediaRequirement: mediaRequirement(candidate, pipeline),
    selectable:
      (pipeline === undefined || (currentlyScanned && pipeline.source.state === "waiting_for_media")) &&
      (candidate.verdict === "ready_signed" ||
        candidate.verdict === "ready_unsigned_requires_policy" ||
        candidate.verdict === "pending_artifact_validation"),
    selected: selected.has(candidate.id),
    expanded: expanded.has(candidate.id),
  };
}

function durableCandidate(pipeline: PipelineSession): ScanCandidate {
  const summary = pipeline.sourceSummary;
  return {
    id: pipeline.candidateId,
    sourceKey: summary.sourceKey,
    mediaId: summary.mediaId,
    sourceId: summary.sourceId,
    sessionId: summary.sessionId,
    displayName: summary.displayName,
    relativePath: summary.relativePath,
    sourceKind: summary.sourceKind,
    schema: summary.schema,
    verdict: summary.provenance.kind === "device_signed" ? "ready_signed" : "ready_unsigned_requires_policy",
    reason: null,
    provenance: summary.provenance,
    bytes: summary.bytes,
    durationSeconds: summary.durationSeconds,
    mediaRequired: pipeline.source.state !== "local_verified",
  };
}

export function projectMediaWorkspace(
  runtime: MediaRuntimeState,
  ui: MediaWorkspaceUiProjectionState = {},
): MediaWorkspaceSnapshot {
  const scan = runtimeValues(runtime.scan);
  const scannedCandidates = scan?.candidates ?? [];
  const media = scan?.media ?? [];
  const imports = runtimeValues(runtime.imports) ?? [];
  const derivations = runtimeValues(runtime.derivations) ?? [];
  const pipelines = runtimeValues(runtime.pipelines) ?? [];
  const library = runtimeValues(runtime.library) ?? [];
  const scannedSourceKeys = new Set(scannedCandidates.map((candidate) => candidate.sourceKey));
  const candidates = [
    ...scannedCandidates,
    ...pipelines
      .filter((pipeline) => !scannedSourceKeys.has(pipeline.sourceSummary.sourceKey))
      .map((pipeline) => durableCandidate(pipeline)),
  ];
  const pipelineBySourceKey = new Map(
    pipelines.map((pipeline) => [pipeline.sourceSummary.sourceKey, pipeline] as const),
  );
  const mediaById = new Map(media.map((descriptor) => [String(descriptor.id), descriptor] as const));
  const selected = ui.selectedCandidateIds ?? EMPTY_IDS;
  const unsignedApproval = ui.unsignedApprovalCandidateIds ?? EMPTY_IDS;
  const expanded = ui.expandedCandidateIds ?? EMPTY_IDS;
  const configuredKinds = ui.sourceKindById ?? EMPTY_KINDS;
  const releases = ui.releaseOverrideBySourceId ?? EMPTY_RELEASES;
  const scanFailure =
    runtime.scan.error?.rpcError ??
    (runtime.scan.error === null
      ? null
      : { code: "scan_failed" as const, message: runtime.scan.error.message, retryable: runtime.scan.error.retryable });
  const scanIssue = scanFailure ?? scan?.attachIssue ?? null;
  const scanState =
    scanFailure !== null
      ? "failed"
      : runtime.scan.loading || scan?.status === "scanning"
        ? "scanning"
        : scan?.status === "complete"
          ? "ready"
          : "idle";
  const sourceScanState: MediaAcquisitionSourceSnapshot["scanState"] =
    scanState === "scanning" ? "scanning" : scan === null ? "idle" : "complete";
  const resourceDegradations: MediaResourceDegradation[] = [];
  for (const [resource, state] of [
    ["imports", runtime.imports],
    ["derivations", runtime.derivations],
    ["pipelines", runtime.pipelines],
    ["library", runtime.library],
  ] as const) {
    if (state.error === null) continue;
    resourceDegradations.push({
      resource,
      message: state.error.message,
      retryable: state.error.retryable,
      retrying: state.loading,
    });
  }

  const projectedPipelines = pipelines.map((pipeline) => projectPipeline(pipeline, imports, derivations));

  const projectedCandidates = candidates.map((candidate) =>
    projectCandidate(
      candidate,
      mediaById,
      pipelineBySourceKey.get(candidate.sourceKey),
      scannedSourceKeys.has(candidate.sourceKey),
      selected,
      expanded,
    ),
  );
  const selectedCandidateIds = projectedCandidates
    .filter((candidate) => candidate.selected)
    .map((candidate) => candidate.id);

  return {
    scan: {
      state: scanState,
      sourceCount: media.length,
      candidateCount: scannedCandidates.length,
      lastCompletedAtLabel: scan?.completedAt ?? null,
      issue: scanIssue,
    },
    resourceDegradations,
    policy: ui.policy ?? defaultMediaWorkflowPolicy(),
    sources: media.map((descriptor) =>
      projectSource(descriptor, scannedCandidates, sourceScanState, configuredKinds, releases),
    ),
    library,
    candidates: projectedCandidates,
    pipelines: projectedPipelines,
    batch: ui.batch === undefined || ui.batch === null ? null : reconcileBatch(ui.batch, projectedPipelines),
    unsignedApprovalArmed:
      selectedCandidateIds.length > 0 &&
      selectedCandidateIds.length === unsignedApproval.size &&
      selectedCandidateIds.every((candidateId) => unsignedApproval.has(candidateId)),
  };
}

function pipelineCompletion(pipeline: MediaPipelineSnapshot): MediaBatchItemOutcome {
  const jobs = [pipeline.jobs.import, pipeline.jobs.derivation, pipeline.jobs.validation, pipeline.jobs.upload];
  const required = jobs.find((job) => job.requiredAction !== null || job.state === "action_required");
  if (required !== undefined) {
    return { kind: "action_required", detail: required.requiredAction?.detail ?? "任务等待用户操作" };
  }
  const failed = jobs.find((job) => job.state === "failed");
  if (failed !== undefined) {
    return {
      kind: "failed",
      detail: failed.issue?.message ?? "任务失败",
      retryable: failed.issue?.retryable ?? false,
    };
  }
  const cancelled = jobs.find((job) => job.state === "cancelled");
  if (cancelled !== undefined) return { kind: "failed", detail: "任务已取消", retryable: false };
  const active = jobs.find(
    (job) =>
      job.state !== "disabled" && job.state !== "not_started" && job.state !== "completed" && job.state !== "blocked",
  );
  if (active !== undefined || pipeline.source.state === "not_imported") {
    return { kind: "processing", detail: "本地导入处理中" };
  }
  const downstreamEnabled = jobs
    .slice(1)
    .some((job) => job.state !== "disabled" && job.state !== "not_started" && job.state !== "blocked");
  return {
    kind: "succeeded",
    detail: downstreamEnabled ? "所有已启用任务均已完成" : "本地导入已完成",
  };
}

function reconcileBatch(
  batch: MediaBatchSnapshot,
  projectedPipelines: readonly MediaPipelineSnapshot[],
): MediaBatchSnapshot {
  if (batch.state === "cancelled" || batch.state === "failed" || batch.state === "completed") return batch;
  const bySourceKey = new Map(projectedPipelines.map((pipeline) => [pipeline.sourceKey, pipeline] as const));
  const items = batch.items.map((item) => {
    const pipeline = bySourceKey.get(item.sourceKey);
    return pipeline === undefined ? item : { ...item, outcome: pipelineCompletion(pipeline) };
  });
  const hasProcessing = items.some((item) => item.outcome.kind === "processing");
  const hasAction = items.some((item) => item.outcome.kind === "action_required");
  const hasFailure = items.some((item) => item.outcome.kind === "failed");
  const state: MediaBatchState = hasAction
    ? "action_required"
    : hasProcessing
      ? "running"
      : hasFailure
        ? "failed"
        : "completed";
  const canCancel = hasProcessing;
  const canDismiss = !canCancel;
  return {
    ...batch,
    items,
    state,
    canCancel,
    canDismiss,
  };
}

export function projectImportBatch(
  id: string,
  startedAtLabel: string,
  outcome: ImportBatchOutcome,
  candidates: readonly ScanCandidate[],
): MediaBatchSnapshot {
  const candidateById = new Map(candidates.map((candidate) => [String(candidate.id), candidate] as const));
  const items = outcome.results.map((result) => {
    const candidateId = String(result.item);
    const candidate = candidateById.get(candidateId);
    if (result.status === "success") {
      return {
        candidateId,
        sourceKey: candidate?.sourceKey ?? candidateId,
        displayName: candidate?.displayName ?? candidateId,
        outcome: { kind: "processing" as const, detail: `Import job ${result.jobId}` },
      };
    }
    return {
      candidateId,
      sourceKey: candidate?.sourceKey ?? candidateId,
      displayName: candidate?.displayName ?? candidateId,
      outcome:
        result.error.code === "policy_approval_required"
          ? { kind: "action_required" as const, detail: result.error.message }
          : {
              kind: "failed" as const,
              detail: result.error.message,
              retryable: result.error.retryable,
            },
    };
  });
  return {
    id,
    state: "running",
    startedAtLabel,
    items,
    operationIssue: outcome.operationError,
    canCancel: true,
    canDismiss: false,
  };
}

export function projectPipelineBatch(
  id: string,
  startedAtLabel: string,
  outcome: PipelineBatchOutcome,
  candidates: readonly ScanCandidate[],
): MediaBatchSnapshot {
  const candidateById = new Map(candidates.map((candidate) => [String(candidate.id), candidate] as const));
  const items = outcome.results.map((result) => {
    const candidateId = String(result.item);
    const candidate = candidateById.get(candidateId);
    if (result.status === "success") {
      return {
        candidateId,
        sourceKey: candidate?.sourceKey ?? candidateId,
        displayName: candidate?.displayName ?? candidateId,
        outcome: { kind: "processing" as const, detail: `本地导入任务 ${result.jobId} 已提交` },
      };
    }
    return {
      candidateId,
      sourceKey: candidate?.sourceKey ?? candidateId,
      displayName: candidate?.displayName ?? candidateId,
      outcome:
        result.error.code === "policy_approval_required"
          ? { kind: "action_required" as const, detail: result.error.message }
          : { kind: "failed" as const, detail: result.error.message, retryable: result.error.retryable },
    };
  });
  const hasProcessing = items.some((item) => item.outcome.kind === "processing");
  const hasAction = items.some((item) => item.outcome.kind === "action_required");
  return {
    id,
    state: hasAction ? "action_required" : hasProcessing ? "running" : "failed",
    startedAtLabel,
    items,
    operationIssue: outcome.operationError,
    canCancel: hasProcessing,
    canDismiss: !hasProcessing,
  };
}
