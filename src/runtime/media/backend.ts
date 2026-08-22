import type {
  DerivationJob,
  ImportBatchOutcome,
  ImportJob,
  MediaJobCommand,
  MediaScanSnapshot,
  PipelineCommand,
  PipelineBatchOutcome,
  PipelineSession,
  ScanRequest,
  StartDerivationRequest,
  StartImportRequest,
  StartPipelineRequest,
  MediaError,
  MediaLibraryEntryExportResult,
  MediaLibraryEntryProjection,
  MediaTrustedProducerRevocation,
} from "./types";
import type { DerivationJobId, ImportJobId, MediaId, PipelineId } from "./ids";

export interface Revisioned<T> {
  readonly revision: number;
  readonly value: T;
}

export function revisioned<T>(revision: number, value: T): Revisioned<T> {
  return { revision, value };
}

export type MediaResourceName = "scan" | "imports" | "derivations" | "pipelines" | "library";

export type MediaBackendEvent =
  | { readonly kind: "scan"; readonly revision: number; readonly value: MediaScanSnapshot }
  | { readonly kind: "imports"; readonly revision: number; readonly value: readonly ImportJob[] }
  | { readonly kind: "derivations"; readonly revision: number; readonly value: readonly DerivationJob[] }
  | { readonly kind: "pipelines"; readonly revision: number; readonly value: readonly PipelineSession[] }
  | { readonly kind: "library"; readonly revision: number; readonly value: readonly MediaLibraryEntryProjection[] };

export type MediaEventSink = (event: MediaBackendEvent) => void;

/** Nested resource watermarks are authoritative for startup replay. The outer
 * revision is only the publication watermark of this aggregate envelope. */
export interface MediaBackendSnapshot {
  readonly scan: Revisioned<MediaScanSnapshot>;
  readonly imports: Revisioned<readonly ImportJob[]>;
  readonly derivations: Revisioned<readonly DerivationJob[]>;
  readonly pipelines: Revisioned<readonly PipelineSession[]>;
  readonly library: Revisioned<readonly MediaLibraryEntryProjection[]>;
}

export class MediaBackendError extends Error {
  readonly channel: string;
  readonly causeValue: unknown;
  readonly mediaError: MediaError | null;

  constructor(channel: string, message: string, causeValue?: unknown, mediaError: MediaError | null = null) {
    super(`${channel}: ${message}`);
    this.name = "MediaBackendError";
    this.channel = channel;
    this.causeValue = causeValue;
    this.mediaError = mediaError;
  }
}

export interface MediaBackend {
  subscribe(sink: MediaEventSink): Promise<() => void>;
  readSnapshot(): Promise<Revisioned<MediaBackendSnapshot>>;

  readScanCandidates(): Promise<Revisioned<MediaScanSnapshot>>;
  readImportJobs(): Promise<Revisioned<readonly ImportJob[]>>;
  readDerivationJobs(): Promise<Revisioned<readonly DerivationJob[]>>;
  readPipelineSessions(): Promise<Revisioned<readonly PipelineSession[]>>;
  readLibraryProjections(): Promise<Revisioned<readonly MediaLibraryEntryProjection[]>>;
  revokeTrustedProducer(keyFingerprint: string): Promise<MediaTrustedProducerRevocation>;
  exportLibraryEntry(entryKey: string): Promise<MediaLibraryEntryExportResult>;

  scan(request: ScanRequest): Promise<Revisioned<MediaScanSnapshot>>;
  startImport(request: StartImportRequest): Promise<Revisioned<ImportJob>>;
  startImportBatch(requests: readonly StartImportRequest[]): Promise<Revisioned<ImportBatchOutcome>>;
  startDerivation(request: StartDerivationRequest): Promise<Revisioned<DerivationJob>>;
  startPipeline(request: StartPipelineRequest): Promise<Revisioned<PipelineSession>>;
  startPipelineBatch(requests: readonly StartPipelineRequest[]): Promise<Revisioned<PipelineBatchOutcome>>;

  commandImport(jobId: ImportJobId, command: MediaJobCommand): Promise<Revisioned<ImportJob>>;
  commandDerivation(jobId: DerivationJobId, command: MediaJobCommand): Promise<Revisioned<DerivationJob>>;
  commandPipeline(pipelineId: PipelineId, command: PipelineCommand): Promise<Revisioned<PipelineSession>>;

  releaseMediaHandles(mediaId: MediaId): Promise<Revisioned<MediaScanSnapshot>>;
  ejectMedia(mediaId: MediaId): Promise<Revisioned<MediaScanSnapshot>>;
}

export function describeMediaBackendError(error: unknown): string {
  if (error instanceof Error) return error.message;
  try {
    return String(error);
  } catch {
    return "media backend request failed";
  }
}
