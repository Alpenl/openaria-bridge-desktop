import type { MediaBackend, MediaResourceName, Revisioned } from "./backend";
import type { DerivationJobId, ImportJobId, MediaId, PipelineId } from "./ids";
import { createMediaOperationRegistry, type MediaOperationRegistry, type MediaOperationResult } from "./operations";
import {
  createMediaRuntimeStore,
  type MediaCommitResult,
  type MediaRuntimeState,
  type MediaRuntimeStore,
} from "./reducer";
import { retryMediaResource, startMediaRuntime, type MediaRuntimeSession } from "./start";
import { validateImportBatchCoverage, validateMediaBatchRequests, validatePipelineBatchCoverage } from "./types";
import type {
  DerivationJob,
  ImportBatchOutcome,
  ImportJob,
  MediaJobCommand,
  MediaLibraryEntryExportResult,
  MediaTrustedProducerRevocation,
  MediaScanSnapshot,
  PipelineCommand,
  PipelineBatchOutcome,
  PipelineSession,
  ScanRequest,
  StartDerivationRequest,
  StartImportRequest,
  StartPipelineRequest,
} from "./types";

export interface MediaBatchRun {
  readonly outcome: Revisioned<ImportBatchOutcome>;
  readonly imports: Revisioned<readonly ImportJob[]>;
}

export interface MediaPipelineBatchRun {
  readonly outcome: Revisioned<PipelineBatchOutcome>;
  readonly pipelines: Revisioned<readonly PipelineSession[]>;
}

export interface MediaRuntimeOptions {
  readonly backend: MediaBackend;
  readonly store?: MediaRuntimeStore;
  readonly now?: () => number;
  readonly onChange?: (state: MediaRuntimeState, result: MediaCommitResult) => void;
  readonly onOperationError?: (error: unknown) => void;
}

export interface MediaRuntime {
  readonly store: MediaRuntimeStore;
  readonly operations: MediaOperationRegistry;
  start(): Promise<MediaRuntimeSession>;
  dispose(): void;
  retry(resource: MediaResourceName): Promise<MediaCommitResult>;
  scan(request: ScanRequest): Promise<MediaOperationResult<Revisioned<MediaScanSnapshot>>>;
  startImport(request: StartImportRequest): Promise<MediaOperationResult<Revisioned<ImportJob>>>;
  startImportBatch(requests: readonly StartImportRequest[]): Promise<MediaOperationResult<MediaBatchRun>>;
  startDerivation(request: StartDerivationRequest): Promise<MediaOperationResult<Revisioned<DerivationJob>>>;
  startPipeline(request: StartPipelineRequest): Promise<MediaOperationResult<Revisioned<PipelineSession>>>;
  startPipelineBatch(requests: readonly StartPipelineRequest[]): Promise<MediaOperationResult<MediaPipelineBatchRun>>;
  commandImport(jobId: ImportJobId, command: MediaJobCommand): Promise<MediaOperationResult<Revisioned<ImportJob>>>;
  commandDerivation(
    jobId: DerivationJobId,
    command: MediaJobCommand,
  ): Promise<MediaOperationResult<Revisioned<DerivationJob>>>;
  commandPipeline(
    pipelineId: PipelineId,
    command: PipelineCommand,
  ): Promise<MediaOperationResult<Revisioned<PipelineSession>>>;
  releaseMediaHandles(mediaId: MediaId): Promise<MediaOperationResult<Revisioned<MediaScanSnapshot>>>;
  ejectMedia(mediaId: MediaId): Promise<MediaOperationResult<Revisioned<MediaScanSnapshot>>>;
  revokeTrustedProducer(keyFingerprint: string): Promise<MediaOperationResult<MediaTrustedProducerRevocation>>;
  exportLibraryEntry(entryKey: string): Promise<MediaOperationResult<MediaLibraryEntryExportResult>>;
}

export function createMediaRuntime(options: MediaRuntimeOptions): MediaRuntime {
  const store = options.store ?? createMediaRuntimeStore();
  function notify(result: MediaCommitResult): void {
    try {
      options.onChange?.(store.getState(), result);
    } catch (error) {
      try {
        options.onOperationError?.(error);
      } catch {
        // Observers never own backend or reducer state.
      }
    }
  }
  const operations = createMediaOperationRegistry({
    onBusyChange: () => notify({ changed: true, stale: false }),
  });
  let activeSession: MediaRuntimeSession | null = null;
  let starting: Promise<MediaRuntimeSession> | null = null;

  function changed(result: MediaCommitResult): void {
    if (result.changed) notify(result);
  }

  function operationFailure(error: unknown): void {
    try {
      options.onOperationError?.(error);
    } catch {
      // Reporting is not part of the durable operation.
    }
  }

  function start(): Promise<MediaRuntimeSession> {
    if (activeSession !== null) return Promise.resolve(activeSession);
    if (starting !== null) return starting;
    starting = startMediaRuntime({
      backend: options.backend,
      store,
      now: options.now,
      onEvent: (_event, result) => changed(result),
      onSnapshot: changed,
    })
      .then((session) => {
        activeSession = session;
        return session;
      })
      .finally(() => {
        starting = null;
      });
    return starting;
  }

  return {
    store,
    operations,
    start,
    dispose() {
      activeSession?.dispose();
      activeSession = null;
    },
    async retry(resource) {
      const result = await retryMediaResource(options.backend, store, resource, options.now);
      changed(result);
      return result;
    },
    scan(request) {
      const sourceKey = request.source.kind === "selected_folder" ? request.source.path : request.source.kind;
      return operations.run({
        key: `media:scan:${sourceKey}`,
        scope: "media:scan",
        run: () => options.backend.scan(request),
        commit: (loaded) => changed(store.commit({ type: "scan/loaded", ...loaded })),
        failed: operationFailure,
      });
    },
    startImport(request) {
      return operations.run({
        key: `media:import:start:${request.candidateId}:${request.approveUnsigned}`,
        scope: `media:import:${request.candidateId}`,
        run: () => options.backend.startImport(request),
        commit: (loaded) => changed(store.commit({ type: "imports/upsert", ...loaded })),
        failed: operationFailure,
      });
    },
    startImportBatch(requests) {
      const key = [...new Set(requests.map((request) => `${request.candidateId}:${request.approveUnsigned}`))]
        .sort()
        .join(",");
      return operations.run({
        key: `media:import:batch:${key}`,
        scope: "media:import:batch",
        run: async (): Promise<MediaBatchRun> => {
          validateMediaBatchRequests(requests);
          const response = await options.backend.startImportBatch(requests);
          const outcome = { ...response, value: validateImportBatchCoverage(requests, response.value) };
          // Event delivery is best effort after durable publication. A direct
          // read makes command success converge even if every listener failed.
          const imports = await options.backend.readImportJobs();
          return { outcome, imports };
        },
        commit: ({ imports }) => changed(store.commit({ type: "imports/loaded", ...imports })),
        failed: operationFailure,
      });
    },
    startDerivation(request) {
      return operations.run({
        key: `media:derivation:start:${request.sourceId}:${request.profileId}`,
        scope: `media:derivation:${request.sourceId}`,
        run: () => options.backend.startDerivation(request),
        commit: (loaded) => changed(store.commit({ type: "derivations/upsert", ...loaded })),
        failed: operationFailure,
      });
    },
    startPipeline(request) {
      return operations.run({
        key: `media:pipeline:start:${request.candidateId}:${request.approveUnsigned}:${JSON.stringify(request.policy)}`,
        scope: `media:pipeline:candidate:${request.candidateId}`,
        run: () => options.backend.startPipeline(request),
        commit: (loaded) => changed(store.commit({ type: "pipelines/upsert", ...loaded })),
        failed: operationFailure,
      });
    },
    startPipelineBatch(requests) {
      const key = requests
        .map((request) => `${request.candidateId}:${request.approveUnsigned}:${JSON.stringify(request.policy)}`)
        .sort()
        .join(",");
      return operations.run({
        key: `media:pipeline:batch:${key}`,
        scope: "media:pipeline:batch",
        run: async (): Promise<MediaPipelineBatchRun> => {
          validateMediaBatchRequests(requests);
          const response = await options.backend.startPipelineBatch(requests);
          const outcome = { ...response, value: validatePipelineBatchCoverage(requests, response.value) };
          // A successful durable batch must converge without relying on event
          // delivery, including when the batch-level operationError is set.
          const pipelines = await options.backend.readPipelineSessions();
          return { outcome, pipelines };
        },
        commit: ({ pipelines }) => changed(store.commit({ type: "pipelines/loaded", ...pipelines })),
        failed: operationFailure,
      });
    },
    commandImport(jobId, command) {
      return operations.run({
        key: `media:import:${command}:${jobId}`,
        scope: `media:import:job:${jobId}`,
        run: () => options.backend.commandImport(jobId, command),
        commit: (loaded) => changed(store.commit({ type: "imports/upsert", ...loaded })),
        failed: operationFailure,
      });
    },
    commandDerivation(jobId, command) {
      return operations.run({
        key: `media:derivation:${command}:${jobId}`,
        scope: `media:derivation:job:${jobId}`,
        run: () => options.backend.commandDerivation(jobId, command),
        commit: (loaded) => changed(store.commit({ type: "derivations/upsert", ...loaded })),
        failed: operationFailure,
      });
    },
    commandPipeline(pipelineId, command) {
      return operations.run({
        key: `media:pipeline:${command}:${pipelineId}`,
        scope: `media:pipeline:${pipelineId}`,
        run: () => options.backend.commandPipeline(pipelineId, command),
        commit: (loaded) => changed(store.commit({ type: "pipelines/upsert", ...loaded })),
        failed: operationFailure,
      });
    },
    releaseMediaHandles(mediaId) {
      return operations.run({
        key: `media:release:${mediaId}`,
        scope: `media:physical:${mediaId}`,
        run: () => options.backend.releaseMediaHandles(mediaId),
        commit: (loaded) => changed(store.commit({ type: "scan/loaded", ...loaded })),
        failed: operationFailure,
      });
    },
    ejectMedia(mediaId) {
      return operations.run({
        key: `media:eject:${mediaId}`,
        scope: `media:physical:${mediaId}`,
        run: () => options.backend.ejectMedia(mediaId),
        commit: (loaded) => changed(store.commit({ type: "scan/loaded", ...loaded })),
        failed: operationFailure,
      });
    },
    revokeTrustedProducer(keyFingerprint) {
      return operations.run({
        key: `media:trust:revoke:${keyFingerprint}`,
        scope: `media:trust:${keyFingerprint}`,
        run: () => options.backend.revokeTrustedProducer(keyFingerprint),
        failed: operationFailure,
      });
    },
    exportLibraryEntry(entryKey) {
      return operations.run({
        key: `media:library:export:${entryKey}`,
        scope: `media:library:export:${entryKey}`,
        run: () => options.backend.exportLibraryEntry(entryKey),
        failed: operationFailure,
      });
    },
  };
}
