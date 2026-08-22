import {
  MediaBackendError,
  revisioned,
  type MediaBackend,
  type MediaBackendEvent,
  type MediaBackendSnapshot,
  type MediaEventSink,
  type Revisioned,
} from "./backend";
import {
  asDerivationJobId,
  asImportJobId,
  asPipelineId,
  type CandidateId,
  type DerivationJobId,
  type ImportJobId,
  type MediaId,
  type PipelineId,
} from "./ids";
import { validateMediaBatchRequests } from "./types";
import type {
  DerivationJob,
  ImportBatchOutcome,
  ImportJob,
  MediaError,
  MediaJobCommand,
  MediaLibraryEntryExportResult,
  MediaLibraryEntryProjection,
  MediaTrustedProducerRevocation,
  MediaScanSnapshot,
  PipelineCommand,
  PipelineBatchOutcome,
  PipelineSession,
  ScanCandidate,
  ScanRequest,
  StartDerivationRequest,
  StartImportRequest,
  StartPipelineRequest,
  TaggedDispatchResult,
} from "./types";

const EMPTY_SCAN: MediaScanSnapshot = {
  scanId: "",
  status: "idle",
  media: [],
  candidates: [],
  attachIssue: null,
  completedAt: null,
};

export interface MemoryMediaBackendOptions {
  readonly scan?: MediaScanSnapshot;
  readonly imports?: readonly ImportJob[];
  readonly derivations?: readonly DerivationJob[];
  readonly pipelines?: readonly PipelineSession[];
  readonly library?: readonly MediaLibraryEntryProjection[];
  readonly now?: () => string;
  readonly failSubscribe?: boolean;
  readonly importBatchOperationError?: MediaError | null;
  readonly pipelineBatchOperationError?: MediaError | null;
  readonly exportLibraryEntryResult?: MediaLibraryEntryExportResult;
}

export interface MediaRecordedCall {
  readonly name: string;
  readonly args: readonly unknown[];
}

export interface MediaDeliveryFailure {
  readonly event: MediaBackendEvent;
  readonly message: string;
}

export type MemoryMediaEvent =
  | { readonly kind: "scan"; readonly value: MediaScanSnapshot }
  | { readonly kind: "imports"; readonly value: readonly ImportJob[] }
  | { readonly kind: "derivations"; readonly value: readonly DerivationJob[] }
  | { readonly kind: "pipelines"; readonly value: readonly PipelineSession[] }
  | { readonly kind: "library"; readonly value: readonly MediaLibraryEntryProjection[] };

export interface MemoryMediaBackend extends MediaBackend {
  readonly calls: MediaRecordedCall[];
  readonly deliveryFailures: MediaDeliveryFailure[];
  emit(event: MemoryMediaEvent): number;
  setScan(value: MediaScanSnapshot): void;
  setImports(value: readonly ImportJob[]): void;
  setDerivations(value: readonly DerivationJob[]): void;
  setPipelines(value: readonly PipelineSession[]): void;
  setLibrary(value: readonly MediaLibraryEntryProjection[]): void;
}

function mediaError(code: MediaError["code"], message: string, retryable: boolean): MediaError {
  return { code, message, retryable };
}

export function createMemoryMediaBackend(options: MemoryMediaBackendOptions = {}): MemoryMediaBackend {
  const now = options.now ?? (() => new Date().toISOString());
  const calls: MediaRecordedCall[] = [];
  const deliveryFailures: MediaDeliveryFailure[] = [];
  const sinks = new Set<MediaEventSink>();
  let scan = options.scan ?? EMPTY_SCAN;
  let imports = options.imports ?? [];
  let derivations = options.derivations ?? [];
  let pipelines = options.pipelines ?? [];
  let library = options.library ?? [];
  let revision = 0;
  let scanRevision = 0;
  let importsRevision = 0;
  let derivationsRevision = 0;
  let pipelinesRevision = 0;
  let libraryRevision = 0;
  let scanSequence = 0;
  let importSequence = imports.length;
  let derivationSequence = derivations.length;
  let pipelineSequence = pipelines.length;

  function record(name: string, ...args: readonly unknown[]): void {
    calls.push({ name, args });
  }

  function deliver(event: MediaBackendEvent): void {
    for (const sink of [...sinks]) {
      try {
        sink(event);
      } catch (error) {
        let message = "media event sink failed";
        try {
          message = error instanceof Error ? error.message : String(error);
        } catch {
          // Keep a bounded diagnostic even for hostile thrown values.
        }
        deliveryFailures.push({ event, message: message.slice(0, 1024) });
      }
    }
  }

  function nextRevision(): number {
    revision += 1;
    return revision;
  }

  function publish(event: MemoryMediaEvent): number {
    const next = nextRevision();
    switch (event.kind) {
      case "scan":
        scan = event.value;
        scanRevision = next;
        break;
      case "imports":
        imports = event.value;
        importsRevision = next;
        break;
      case "derivations":
        derivations = event.value;
        derivationsRevision = next;
        break;
      case "pipelines":
        pipelines = event.value;
        pipelinesRevision = next;
        break;
      case "library":
        library = event.value;
        libraryRevision = next;
        break;
    }
    deliver({ ...event, revision: next } as MediaBackendEvent);
    return next;
  }

  function candidate(candidateId: CandidateId): ScanCandidate | undefined {
    return scan.candidates.find((item) => item.id === candidateId);
  }

  function throwMedia(channel: string, error: MediaError): never {
    throw new MediaBackendError(channel, error.message, error, error);
  }

  function importResult(request: StartImportRequest): TaggedDispatchResult<CandidateId, ImportJobId> {
    const item = candidate(request.candidateId);
    if (item === undefined) {
      return {
        status: "failure",
        item: request.candidateId,
        error: mediaError("candidate_not_found", "scan candidate no longer exists", true),
      };
    }
    if (
      (item.verdict === "ready_unsigned_requires_policy" || item.verdict === "pending_artifact_validation") &&
      !request.approveUnsigned
    ) {
      return {
        status: "failure",
        item: request.candidateId,
        error: mediaError("policy_approval_required", "unsigned source requires explicit approval", false),
      };
    }
    if (
      !["ready_signed", "ready_unsigned_requires_policy", "pending_artifact_validation", "already_imported"].includes(
        item.verdict,
      )
    ) {
      return {
        status: "failure",
        item: request.candidateId,
        error: mediaError("candidate_stale", `candidate is not importable: ${item.verdict}`, true),
      };
    }
    const existing = imports.find((job) => job.candidateId === request.candidateId && job.state !== "cancelled");
    if (existing !== undefined) return { status: "success", item: request.candidateId, jobId: existing.id };
    importSequence += 1;
    const timestamp = now();
    const job: ImportJob = {
      id: asImportJobId(`media-import-${importSequence}`),
      candidateId: request.candidateId,
      mediaId: item.mediaId,
      sourceId: item.sourceId,
      state: item.verdict === "already_imported" ? "local_verified" : "queued",
      desiredRunState: "run",
      progress: {
        currentFile: null,
        copiedBytes: item.verdict === "already_imported" ? item.bytes : 0,
        totalBytes: item.bytes,
        throughputBytesPerSecond: null,
        etaSeconds: null,
      },
      failure: null,
      retryAt: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    imports = [...imports, job];
    return { status: "success", item: request.candidateId, jobId: job.id };
  }

  function pipelineResult(request: StartPipelineRequest): TaggedDispatchResult<CandidateId, PipelineId> {
    const item = candidate(request.candidateId);
    if (item === undefined) {
      return {
        status: "failure",
        item: request.candidateId,
        error: mediaError("candidate_not_found", "scan candidate no longer exists", true),
      };
    }
    if (
      (item.verdict === "ready_unsigned_requires_policy" || item.verdict === "pending_artifact_validation") &&
      !request.approveUnsigned
    ) {
      return {
        status: "failure",
        item: request.candidateId,
        error: mediaError("policy_approval_required", "unsigned source requires explicit approval", false),
      };
    }
    if (
      !["ready_signed", "ready_unsigned_requires_policy", "pending_artifact_validation", "already_imported"].includes(
        item.verdict,
      )
    ) {
      return {
        status: "failure",
        item: request.candidateId,
        error: mediaError("candidate_stale", `candidate is not importable: ${item.verdict}`, true),
      };
    }
    const existingIndex = pipelines.findIndex((pipeline) => pipeline.sourceSummary.sourceKey === item.sourceKey);
    if (existingIndex >= 0) {
      const existing = pipelines[existingIndex];
      if (existing === undefined) throw new Error("memory media backend lost an existing pipeline");
      const samePolicy =
        existing.policy.autoNormalize === request.policy.autoNormalize &&
        existing.policy.autoUploadDerived === request.policy.autoUploadDerived &&
        existing.policy.uploadSourceVideo === request.policy.uploadSourceVideo &&
        existing.policy.unsignedUploadApproved === request.policy.unsignedUploadApproved;
      if (!samePolicy) {
        return {
          status: "failure",
          item: request.candidateId,
          error: mediaError("operation_conflict", "existing source pipeline uses a different policy", false),
        };
      }
      if (existing.source.state === "waiting_for_media") {
        const importIndex = imports.findIndex((job) => job.id === existing.source.jobId);
        const currentImport = importIndex < 0 ? undefined : imports[importIndex];
        if (currentImport !== undefined) {
          const updatedImport: ImportJob = {
            ...currentImport,
            state: "queued",
            failure: null,
            retryAt: null,
            updatedAt: now(),
          };
          imports = imports.map((job, index) => (index === importIndex ? updatedImport : job));
        }
        const updated: PipelineSession = {
          ...existing,
          source: {
            ...existing.source,
            state: "queued",
            progress: currentImport?.progress ?? existing.source.progress,
            failure: null,
          },
          updatedAt: now(),
        };
        pipelines = pipelines.map((pipeline, index) => (index === existingIndex ? updated : pipeline));
      }
      return { status: "success", item: request.candidateId, jobId: existing.id };
    }
    const importOutcome = importResult({
      candidateId: request.candidateId,
      approveUnsigned: request.approveUnsigned,
    });
    if (importOutcome.status === "failure") {
      return { status: "failure", item: request.candidateId, error: importOutcome.error };
    }
    const importJob = imports.find((job) => job.id === importOutcome.jobId);
    if (importJob === undefined) throw new Error("memory media backend lost a pipeline import job");
    pipelineSequence += 1;
    const timestamp = now();
    const pipeline: PipelineSession = {
      id: asPipelineId(`media-pipeline-${pipelineSequence}`),
      candidateId: item.id,
      sourceSummary: {
        sourceKey: item.sourceKey,
        mediaId: item.mediaId,
        sourceId: item.sourceId,
        displayName: item.displayName,
        sessionId: item.sessionId,
        schema: item.schema,
        sourceKind: item.sourceKind,
        provenance: item.provenance,
        relativePath: item.relativePath,
        bytes: item.bytes,
        durationSeconds: item.durationSeconds,
      },
      policy: request.policy,
      desiredRunState: "run",
      source: {
        state: importJob.state,
        sourceId: importJob.sourceId,
        jobId: importJob.id,
        retentionState: item.verdict === "already_imported" ? "retained" : "unknown",
        progress: importJob.progress,
        failure: importJob.failure,
      },
      derived: {
        state: request.policy.autoNormalize ? "waiting_for_source" : "not_started",
        derivedId: null,
        jobId: null,
        progress: null,
        validation: null,
        action: null,
        failure: null,
      },
      remote: {
        state: request.policy.autoUploadDerived ? "waiting_for_derived" : "disabled",
        bundleId: null,
        uploadJobId: null,
        progress: null,
        action: null,
        failure: null,
      },
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    pipelines = [...pipelines, pipeline];
    return { status: "success", item: request.candidateId, jobId: pipeline.id };
  }

  function validateBatch<T extends { readonly candidateId: CandidateId }>(
    channel: string,
    requests: readonly T[],
  ): void {
    try {
      validateMediaBatchRequests(requests);
    } catch (error) {
      throwMedia(
        channel,
        mediaError("invalid_input", error instanceof Error ? error.message : "invalid media batch", false),
      );
    }
  }

  function updateImport(jobId: ImportJobId, command: MediaJobCommand): ImportJob {
    const current = imports.find((job) => job.id === jobId);
    if (current === undefined) {
      return throwMedia("media_command_import", mediaError("invalid_input", "import job does not exist", false));
    }
    const updated: ImportJob = {
      ...current,
      state:
        command === "cancel"
          ? "cancelled"
          : command === "pause"
            ? "paused"
            : command === "resume" && (current.state === "paused" || current.state === "pausing")
              ? "queued"
              : command === "retry" && (current.state === "failed" || current.state === "retry_wait")
                ? "queued"
                : current.state,
      desiredRunState:
        command === "pause"
          ? "paused"
          : command === "cancel"
            ? "cancelled"
            : command === "resume" || command === "retry"
              ? "run"
              : current.desiredRunState,
      failure: command === "retry" ? null : current.failure,
      retryAt: command === "retry" ? null : current.retryAt,
      updatedAt: now(),
    };
    imports = imports.map((job) => (job.id === jobId ? updated : job));
    return updated;
  }

  function updateDerivation(jobId: DerivationJobId, command: MediaJobCommand): DerivationJob {
    const current = derivations.find((job) => job.id === jobId);
    if (current === undefined) {
      return throwMedia(
        "media_command_derivation",
        mediaError("invalid_input", "derivation job does not exist", false),
      );
    }
    const updated: DerivationJob = {
      ...current,
      state:
        command === "cancel"
          ? "cancelled"
          : command === "pause"
            ? "paused"
            : command === "resume" && (current.state === "paused" || current.state === "pausing")
              ? "queued"
              : command === "retry" && (current.state === "failed" || current.state === "retry_wait")
                ? "queued"
                : current.state,
      desiredRunState:
        command === "pause"
          ? "paused"
          : command === "cancel"
            ? "cancelled"
            : command === "resume" || command === "retry"
              ? "run"
              : current.desiredRunState,
      failure: command === "retry" ? null : current.failure,
      retryAt: command === "retry" ? null : current.retryAt,
      updatedAt: now(),
    };
    derivations = derivations.map((job) => (job.id === jobId ? updated : job));
    return updated;
  }

  function updatePipeline(pipelineId: PipelineId, command: PipelineCommand): PipelineSession {
    const current = pipelines.find((item) => item.id === pipelineId);
    if (current === undefined) {
      return throwMedia("media_command_pipeline", mediaError("invalid_input", "pipeline does not exist", false));
    }
    const updated: PipelineSession = {
      ...current,
      desiredRunState:
        command === "pause"
          ? "paused"
          : command === "cancel"
            ? "cancelled"
            : command === "resume" || command === "retry"
              ? "run"
              : current.desiredRunState,
      policy:
        command === "approve_unsigned_upload" ? { ...current.policy, unsignedUploadApproved: true } : current.policy,
      source:
        command === "cancel" && !["local_verified", "cancelled", "failed"].includes(current.source.state)
          ? { ...current.source, state: "cancelled" }
          : command === "pause" &&
              !["not_started", "local_verified", "cancelled", "failed"].includes(current.source.state)
            ? { ...current.source, state: "paused" }
            : command === "resume" && current.source.state === "paused"
              ? { ...current.source, state: "queued" }
              : current.source,
      derived:
        command === "cancel" && !["derived_verified", "cancelled", "failed"].includes(current.derived.state)
          ? { ...current.derived, state: "cancelled", action: null }
          : command === "pause" &&
              ![
                "not_started",
                "waiting_for_source",
                "derived_verified",
                "action_required",
                "cancelled",
                "failed",
              ].includes(current.derived.state)
            ? { ...current.derived, state: "paused" }
            : command === "resume" && current.derived.state === "paused"
              ? { ...current.derived, state: "queued" }
              : current.derived,
      remote:
        command === "cancel" &&
        !["object_store_verified", "cancelled", "failed", "disabled"].includes(current.remote.state)
          ? { ...current.remote, state: "cancelled", action: null }
          : command === "pause" &&
              ![
                "disabled",
                "waiting_for_derived",
                "object_store_verified",
                "action_required",
                "cancelled",
                "failed",
              ].includes(current.remote.state)
            ? { ...current.remote, state: "paused" }
            : command === "resume" && current.remote.state === "paused"
              ? { ...current.remote, state: "queued" }
              : command === "approve_unsigned_upload" && current.remote.state === "action_required"
                ? {
                    ...current.remote,
                    state: current.derived.state === "derived_verified" ? "queued" : "waiting_for_derived",
                    action: null,
                  }
                : current.remote,
      updatedAt: now(),
    };
    pipelines = pipelines.map((item) => (item.id === pipelineId ? updated : item));
    return updated;
  }

  const backend: MemoryMediaBackend = {
    calls,
    deliveryFailures,
    async subscribe(sink) {
      record("subscribe");
      if (options.failSubscribe === true) throw new MediaBackendError("media_events", "subscription failed");
      sinks.add(sink);
      let disposed = false;
      return () => {
        if (disposed) return;
        disposed = true;
        sinks.delete(sink);
      };
    },
    readSnapshot(): Promise<Revisioned<MediaBackendSnapshot>> {
      record("readSnapshot");
      return Promise.resolve(
        revisioned(revision, {
          scan: revisioned(scanRevision, scan),
          imports: revisioned(importsRevision, imports),
          derivations: revisioned(derivationsRevision, derivations),
          pipelines: revisioned(pipelinesRevision, pipelines),
          library: revisioned(libraryRevision, library),
        }),
      );
    },
    readScanCandidates() {
      record("readScanCandidates");
      return Promise.resolve(revisioned(scanRevision, scan));
    },
    readImportJobs() {
      record("readImportJobs");
      return Promise.resolve(revisioned(importsRevision, imports));
    },
    readDerivationJobs() {
      record("readDerivationJobs");
      return Promise.resolve(revisioned(derivationsRevision, derivations));
    },
    readPipelineSessions() {
      record("readPipelineSessions");
      return Promise.resolve(revisioned(pipelinesRevision, pipelines));
    },
    readLibraryProjections() {
      record("readLibraryProjections");
      return Promise.resolve(revisioned(libraryRevision, library));
    },
    revokeTrustedProducer(keyFingerprint: string): Promise<MediaTrustedProducerRevocation> {
      record("revokeTrustedProducer", keyFingerprint);
      return Promise.resolve({ keyFingerprint, revoked: false });
    },
    exportLibraryEntry(entryKey: string): Promise<MediaLibraryEntryExportResult> {
      record("exportLibraryEntry", entryKey);
      const entry = library.find((item) => item.entryKey === entryKey);
      if (entry === undefined) {
        return throwMedia(
          "media_export_library_entry",
          mediaError("media_not_found", "library entry does not exist", false),
        );
      }
      if (entry.sourceLocal.status !== "verified") {
        return throwMedia(
          "media_export_library_entry",
          mediaError("media_unavailable", "library source is not locally verified", false),
        );
      }
      return Promise.resolve(
        options.exportLibraryEntryResult ?? {
          status: "completed",
          outputPath: `/tmp/${entryKey}.mp4`,
          videoSegmentCount: 0,
          audioSegmentCount: 0,
          outputSizeBytes: 0,
        },
      );
    },
    scan(request: ScanRequest) {
      record("scan", request);
      scanSequence += 1;
      scan = { ...scan, scanId: `media-scan-${scanSequence}`, status: "complete", completedAt: now() };
      return Promise.resolve(revisioned(publish({ kind: "scan", value: scan }), scan));
    },
    startImport(request: StartImportRequest) {
      record("startImport", request);
      const result = importResult(request);
      if (result.status === "failure") throwMedia("media_start_import", result.error);
      const job = imports.find((item) => item.id === result.jobId);
      if (job === undefined) throw new Error("memory media backend lost a created import job");
      return Promise.resolve(revisioned(publish({ kind: "imports", value: imports }), job));
    },
    startImportBatch(requests: readonly StartImportRequest[]) {
      record("startImportBatch", requests);
      validateBatch("media_start_import_batch", requests);
      const before = imports;
      const results = requests.map(importResult);
      const changed = imports !== before;
      const at = changed ? publish({ kind: "imports", value: imports }) : importsRevision;
      return Promise.resolve(
        revisioned(at, {
          results,
          operationError: options.importBatchOperationError ?? null,
        } satisfies ImportBatchOutcome),
      );
    },
    startDerivation(request: StartDerivationRequest) {
      record("startDerivation", request);
      let job = derivations.find((item) => item.sourceId === request.sourceId && item.profileId === request.profileId);
      if (job === undefined) {
        derivationSequence += 1;
        const timestamp = now();
        job = {
          id: asDerivationJobId(`media-derivation-${derivationSequence}`),
          sourceId: request.sourceId,
          profileId: request.profileId,
          derivedId: null,
          state: "queued",
          desiredRunState: "run",
          progress: {
            currentSegmentPair: null,
            totalSegmentPairs: null,
            processedFrames: 0,
            totalFrames: null,
            encodingFps: null,
            etaSeconds: null,
          },
          validation: { decodedSegmentPairs: 0, totalSegmentPairs: 0 },
          failure: null,
          retryAt: null,
          createdAt: timestamp,
          updatedAt: timestamp,
        };
        derivations = [...derivations, job];
      }
      return Promise.resolve(revisioned(publish({ kind: "derivations", value: derivations }), job));
    },
    startPipeline(request: StartPipelineRequest) {
      record("startPipeline", request);
      const importsBefore = imports;
      const result = pipelineResult(request);
      if (result.status === "failure") throwMedia("media_start_pipeline", result.error);
      const pipeline = pipelines.find((item) => item.id === result.jobId);
      if (pipeline === undefined) throw new Error("memory media backend lost a created pipeline");
      if (imports !== importsBefore) publish({ kind: "imports", value: imports });
      return Promise.resolve(revisioned(publish({ kind: "pipelines", value: pipelines }), pipeline));
    },
    startPipelineBatch(requests: readonly StartPipelineRequest[]) {
      record("startPipelineBatch", requests);
      validateBatch("media_start_pipeline_batch", requests);
      const importsBefore = imports;
      const before = pipelines;
      const results = requests.map(pipelineResult);
      if (imports !== importsBefore) publish({ kind: "imports", value: imports });
      const changed = pipelines !== before;
      const at = changed ? publish({ kind: "pipelines", value: pipelines }) : pipelinesRevision;
      return Promise.resolve(
        revisioned(at, {
          results,
          operationError: options.pipelineBatchOperationError ?? null,
        } satisfies PipelineBatchOutcome),
      );
    },
    commandImport(jobId, command) {
      record("commandImport", jobId, command);
      const job = updateImport(jobId, command);
      return Promise.resolve(revisioned(publish({ kind: "imports", value: imports }), job));
    },
    commandDerivation(jobId, command) {
      record("commandDerivation", jobId, command);
      const job = updateDerivation(jobId, command);
      return Promise.resolve(revisioned(publish({ kind: "derivations", value: derivations }), job));
    },
    commandPipeline(pipelineId, command) {
      record("commandPipeline", pipelineId, command);
      const pipeline = updatePipeline(pipelineId, command);
      return Promise.resolve(revisioned(publish({ kind: "pipelines", value: pipelines }), pipeline));
    },
    releaseMediaHandles(mediaId: MediaId) {
      record("releaseMediaHandles", mediaId);
      scan = {
        ...scan,
        media: scan.media.map((item) =>
          item.id === mediaId ? { ...item, readerCount: 0, handleState: "released" as const } : item,
        ),
      };
      return Promise.resolve(revisioned(publish({ kind: "scan", value: scan }), scan));
    },
    ejectMedia(mediaId: MediaId) {
      record("ejectMedia", mediaId);
      scan = {
        ...scan,
        media: scan.media.map((item) =>
          item.id === mediaId && item.readerCount === 0
            ? { ...item, presence: "removed" as const, ejectState: "ejected" as const, mountPath: null }
            : item.id === mediaId
              ? { ...item, ejectState: "blocked" as const, ejectVeto: "active import reader" }
              : item,
        ),
      };
      return Promise.resolve(revisioned(publish({ kind: "scan", value: scan }), scan));
    },
    emit(event: MemoryMediaEvent): number {
      return publish(event);
    },
    setScan(value) {
      scan = value;
    },
    setImports(value) {
      imports = value;
    },
    setDerivations(value) {
      derivations = value;
    },
    setPipelines(value) {
      pipelines = value;
    },
    setLibrary(value) {
      library = value;
    },
  };

  return backend;
}
