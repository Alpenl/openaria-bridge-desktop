import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { subscribeAll, type EventRegistration } from "../subscribeAll";
import {
  MediaBackendError,
  type MediaBackend,
  type MediaBackendSnapshot,
  type MediaEventSink,
  type Revisioned,
} from "./backend";
import {
  decodeDerivationJob,
  decodeDerivationJobs,
  decodeImportBatchOutcome,
  decodeImportJob,
  decodeImportJobs,
  decodeMediaBackendSnapshot,
  decodeMediaError,
  decodeMediaLibraryEntries,
  decodeMediaTrustedProducerRevocation,
  decodeMediaScanSnapshot,
  decodePipelineSession,
  decodePipelineBatchOutcome,
  decodePipelineSessions,
  decodeRevisioned,
  decodeStartPipelineRequest,
  MediaDecodeError,
  type MediaDecoder,
} from "./decoder";
import {
  validateImportBatchCoverage,
  validateMediaBatchRequests,
  validatePipelineBatchCoverage,
  type MediaError,
  type MediaLibraryEntryExportResult,
} from "./types";

export const MEDIA_TAURI_COMMANDS = {
  readSnapshot: "media_read_snapshot",
  readScanCandidates: "media_read_scan_candidates",
  readImportJobs: "media_read_import_jobs",
  readDerivationJobs: "media_read_derivation_jobs",
  readPipelineSessions: "media_read_pipeline_sessions",
  readLibraryProjections: "media_read_library_projections",
  revokeTrustedProducer: "media_revoke_trusted_producer",
  exportLibraryEntry: "media_export_library_entry",
  scan: "media_scan",
  startImport: "media_start_import",
  startImportBatch: "media_start_import_batch",
  startDerivation: "media_start_derivation",
  startPipeline: "media_start_pipeline",
  startPipelineBatch: "media_start_pipeline_batch",
  commandImport: "media_command_import",
  commandDerivation: "media_command_derivation",
  commandPipeline: "media_command_pipeline",
  releaseMediaHandles: "media_release_handles",
  ejectMedia: "media_eject",
} as const;

export const MEDIA_TAURI_EVENTS = {
  scan: "media:scan:update",
  imports: "media:imports:update",
  derivations: "media:derivations:update",
  pipelines: "media:pipelines:update",
  library: "media:library:update",
} as const;

export class MediaInvocationError extends Error {
  readonly command: string;
  readonly mediaError: MediaError;

  constructor(command: string, mediaError: MediaError) {
    super(mediaError.message);
    this.name = "MediaInvocationError";
    this.command = command;
    this.mediaError = mediaError;
  }
}

function plainRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null ? (value as Record<string, unknown>) : null;
}

function rejectInvocation(command: string, reason: unknown): never {
  const record = plainRecord(reason);
  if (record === null) throw reason;
  const candidate = Object.prototype.hasOwnProperty.call(record, "error") ? record.error : reason;
  throw new MediaInvocationError(command, decodeMediaError(candidate, `${command}.error`));
}

function invokeRevisioned<T>(
  command: string,
  decoder: MediaDecoder<T>,
  payload?: Record<string, unknown>,
): Promise<Revisioned<T>> {
  return invoke<unknown>(command, payload).then(
    (raw) => decodeRevisioned(raw, decoder, `${command}.response`),
    (reason: unknown) => rejectInvocation(command, reason),
  );
}

function nonEmptyText(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new MediaDecodeError(path, "non-empty string", value);
  }
  return value;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new MediaDecodeError(path, "non-negative safe integer", value);
  }
  return value;
}

function exactKeys(item: Record<string, unknown>, keys: readonly string[], path: string): void {
  const allowed = new Set(keys);
  const unexpected = Object.keys(item).find((key) => !allowed.has(key));
  if (unexpected !== undefined) {
    throw new MediaDecodeError(`${path}.${unexpected}`, "field to be absent", item[unexpected]);
  }
}

function required<T>(
  item: Record<string, unknown>,
  key: string,
  decoder: (value: unknown, path: string) => T,
  path: string,
): T {
  if (!Object.prototype.hasOwnProperty.call(item, key)) {
    throw new MediaDecodeError(`${path}.${key}`, "present value", undefined);
  }
  return decoder(item[key], `${path}.${key}`);
}

function decodeMediaLibraryEntryExportResult(value: unknown, path = "payload"): MediaLibraryEntryExportResult {
  const item = plainRecord(value);
  if (item === null) throw new MediaDecodeError(path, "plain object", value);
  const status = required(item, "status", nonEmptyText, path);
  if (status === "cancelled") {
    exactKeys(item, ["status"], path);
    return { status };
  }
  if (status === "completed") {
    exactKeys(item, ["status", "outputPath", "videoSegmentCount", "audioSegmentCount", "outputSizeBytes"], path);
    return {
      status,
      outputPath: required(item, "outputPath", nonEmptyText, path),
      videoSegmentCount: required(item, "videoSegmentCount", nonNegativeInteger, path),
      audioSegmentCount: required(item, "audioSegmentCount", nonNegativeInteger, path),
      outputSizeBytes: required(item, "outputSizeBytes", nonNegativeInteger, path),
    };
  }
  throw new MediaDecodeError(`${path}.status`, "cancelled | completed", status);
}

function reportMalformedEvent(channel: string, error: unknown): void {
  let message = "malformed media event";
  try {
    message = error instanceof Error ? error.message : String(error);
  } catch {
    // Keep the diagnostic bounded and do not let logging break the listener.
  }
  console.error(`[${channel}] ${message.slice(0, 1024)}`);
}

function listenRevisioned<T>(
  channel: string,
  decoder: MediaDecoder<T>,
  receive: (value: T, revision: number) => void,
): Promise<UnlistenFn> {
  return listen<unknown>(channel, (event) => {
    try {
      const decoded = decodeRevisioned(event.payload, decoder, `${channel}.payload`);
      receive(decoded.value, decoded.revision);
    } catch (error) {
      reportMalformedEvent(channel, error);
    }
  });
}

function translate(channel: string, error: unknown): MediaBackendError {
  if (error instanceof MediaBackendError) return error;
  if (error instanceof MediaInvocationError) {
    return new MediaBackendError(channel, error.message, error, error.mediaError);
  }
  const message = error instanceof Error ? error.message : String(error);
  return new MediaBackendError(channel, message, error);
}

export function createTauriMediaBackend(): MediaBackend {
  function call<T>(channel: string, run: () => Promise<T>): Promise<T> {
    return Promise.resolve()
      .then(run)
      .catch((error: unknown) => {
        throw translate(channel, error);
      });
  }

  return {
    async subscribe(sink: MediaEventSink): Promise<() => void> {
      const registrations: EventRegistration[] = [
        () =>
          listenRevisioned(MEDIA_TAURI_EVENTS.scan, decodeMediaScanSnapshot, (value, revision) =>
            sink({ kind: "scan", revision, value }),
          ),
        () =>
          listenRevisioned(MEDIA_TAURI_EVENTS.imports, decodeImportJobs, (value, revision) =>
            sink({ kind: "imports", revision, value }),
          ),
        () =>
          listenRevisioned(MEDIA_TAURI_EVENTS.derivations, decodeDerivationJobs, (value, revision) =>
            sink({ kind: "derivations", revision, value }),
          ),
        () =>
          listenRevisioned(MEDIA_TAURI_EVENTS.pipelines, decodePipelineSessions, (value, revision) =>
            sink({ kind: "pipelines", revision, value }),
          ),
        () =>
          listenRevisioned(MEDIA_TAURI_EVENTS.library, decodeMediaLibraryEntries, (value, revision) =>
            sink({ kind: "library", revision, value }),
          ),
      ];
      try {
        return await subscribeAll(registrations);
      } catch (error) {
        throw translate("media_events", error);
      }
    },
    readSnapshot: () =>
      call(MEDIA_TAURI_COMMANDS.readSnapshot, async () => {
        const outer = await invokeRevisioned(MEDIA_TAURI_COMMANDS.readSnapshot, decodeMediaBackendSnapshot);
        for (const resource of ["scan", "imports", "derivations", "pipelines", "library"] as const) {
          if (outer.value[resource].revision > outer.revision) {
            throw new MediaDecodeError(
              `${MEDIA_TAURI_COMMANDS.readSnapshot}.response.value.${resource}.revision`,
              `revision <= ${outer.revision}`,
              outer.value[resource].revision,
            );
          }
        }
        return outer as Revisioned<MediaBackendSnapshot>;
      }),
    readScanCandidates: () =>
      call(MEDIA_TAURI_COMMANDS.readScanCandidates, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.readScanCandidates, decodeMediaScanSnapshot),
      ),
    readImportJobs: () =>
      call(MEDIA_TAURI_COMMANDS.readImportJobs, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.readImportJobs, decodeImportJobs),
      ),
    readDerivationJobs: () =>
      call(MEDIA_TAURI_COMMANDS.readDerivationJobs, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.readDerivationJobs, decodeDerivationJobs),
      ),
    readPipelineSessions: () =>
      call(MEDIA_TAURI_COMMANDS.readPipelineSessions, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.readPipelineSessions, decodePipelineSessions),
      ),
    readLibraryProjections: () =>
      call(MEDIA_TAURI_COMMANDS.readLibraryProjections, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.readLibraryProjections, decodeMediaLibraryEntries),
      ),
    revokeTrustedProducer: (keyFingerprint) =>
      call(MEDIA_TAURI_COMMANDS.revokeTrustedProducer, () =>
        invoke<unknown>(MEDIA_TAURI_COMMANDS.revokeTrustedProducer, { keyFingerprint }).then(
          (raw) => decodeMediaTrustedProducerRevocation(raw, `${MEDIA_TAURI_COMMANDS.revokeTrustedProducer}.response`),
          (reason: unknown) => rejectInvocation(MEDIA_TAURI_COMMANDS.revokeTrustedProducer, reason),
        ),
      ),
    exportLibraryEntry: (entryKey) =>
      call(MEDIA_TAURI_COMMANDS.exportLibraryEntry, () =>
        invoke<unknown>(MEDIA_TAURI_COMMANDS.exportLibraryEntry, { entryKey }).then(
          (raw) => decodeMediaLibraryEntryExportResult(raw, `${MEDIA_TAURI_COMMANDS.exportLibraryEntry}.response`),
          (reason: unknown) => rejectInvocation(MEDIA_TAURI_COMMANDS.exportLibraryEntry, reason),
        ),
      ),
    scan: (request) =>
      call(MEDIA_TAURI_COMMANDS.scan, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.scan, decodeMediaScanSnapshot, { request }),
      ),
    startImport: (request) =>
      call(MEDIA_TAURI_COMMANDS.startImport, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.startImport, decodeImportJob, { request }),
      ),
    startImportBatch: (requests) =>
      call(MEDIA_TAURI_COMMANDS.startImportBatch, () => {
        validateMediaBatchRequests(requests);
        return invokeRevisioned(MEDIA_TAURI_COMMANDS.startImportBatch, decodeImportBatchOutcome, { requests }).then(
          (result) => ({ ...result, value: validateImportBatchCoverage(requests, result.value) }),
        );
      }),
    startDerivation: (request) =>
      call(MEDIA_TAURI_COMMANDS.startDerivation, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.startDerivation, decodeDerivationJob, { request }),
      ),
    startPipeline: (request) =>
      call(MEDIA_TAURI_COMMANDS.startPipeline, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.startPipeline, decodePipelineSession, {
          request: decodeStartPipelineRequest(request, "request"),
        }),
      ),
    startPipelineBatch: (requests) =>
      call(MEDIA_TAURI_COMMANDS.startPipelineBatch, () => {
        validateMediaBatchRequests(requests);
        const decodedRequests = requests.map((request, index) =>
          decodeStartPipelineRequest(request, `requests[${index}]`),
        );
        return invokeRevisioned(MEDIA_TAURI_COMMANDS.startPipelineBatch, decodePipelineBatchOutcome, {
          requests: decodedRequests,
        }).then((result) => ({
          ...result,
          value: validatePipelineBatchCoverage(decodedRequests, result.value),
        }));
      }),
    commandImport: (jobId, command) =>
      call(MEDIA_TAURI_COMMANDS.commandImport, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.commandImport, decodeImportJob, { jobId, command }),
      ),
    commandDerivation: (jobId, command) =>
      call(MEDIA_TAURI_COMMANDS.commandDerivation, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.commandDerivation, decodeDerivationJob, { jobId, command }),
      ),
    commandPipeline: (pipelineId, command) =>
      call(MEDIA_TAURI_COMMANDS.commandPipeline, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.commandPipeline, decodePipelineSession, { pipelineId, command }),
      ),
    releaseMediaHandles: (mediaId) =>
      call(MEDIA_TAURI_COMMANDS.releaseMediaHandles, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.releaseMediaHandles, decodeMediaScanSnapshot, { mediaId }),
      ),
    ejectMedia: (mediaId) =>
      call(MEDIA_TAURI_COMMANDS.ejectMedia, () =>
        invokeRevisioned(MEDIA_TAURI_COMMANDS.ejectMedia, decodeMediaScanSnapshot, { mediaId }),
      ),
  };
}
