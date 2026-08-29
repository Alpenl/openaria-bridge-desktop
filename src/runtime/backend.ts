// The one interface that owns every backend interaction.
//
// Nothing outside an adapter (`tauriBackend.ts`, `memoryBackend.ts`) may name a
// transport: no `invoke` command string, no `listen` channel, no `UnlistenFn`.
// The runtime (start, reducer, operation runner) and the views only ever see
// this interface, which is why the whole app can be driven by an in-memory
// backend in tests.
//
// Reads are revisioned. A snapshot or command reply carries the revision of the
// newest event that is guaranteed to be included in it, so the reducer can drop
// a reply that lost a race against a newer event instead of painting older data
// over newer state. Events carry strictly increasing revisions.

import type {
  Device,
  DownloadedCleanupPreview,
  DownloadedCleanupResult,
  LibraryEntry,
  PairingResolutionPayload,
  PairingTickPayload,
  RpcError,
  SaveStorageConfigInput,
  SessionCatalogAuthority,
  SessionCatalogDiagnostic,
  SessionCapabilities,
  SessionPaginationUnavailableReason,
  SessionPageView,
  SessionView,
  StorageConfig,
  Transfer,
  TransferJobEvent,
} from "../types";
import type {
  DeviceId,
  DownloadJobId,
  FileId,
  LibraryKey,
  PairingAttemptId,
  SessionId,
  TransferRetryId,
  UploadJobId,
} from "../ids";
import type { BatchItem, DispatchItem } from "./batch";

/** A value together with the event revision it is known to include. */
export interface Revisioned<T> {
  readonly revision: number;
  readonly value: T;
}

export function revisioned<T>(revision: number, value: T): Revisioned<T> {
  return { revision, value };
}

/** Every push the backend can make. One flat union so buffering, replay and
 * commit can treat events as data rather than as separate callbacks. */
export type BackendEvent =
  | { readonly kind: "devices"; readonly revision: number; readonly devices: Device[] }
  | {
      readonly kind: "sessions";
      readonly revision: number;
      readonly deviceId: string;
      readonly sessions: SessionView[];
      /** Optional only for in-process compatibility events. Production IPC
       * decoding requires all four fields; absence fails closed in state. */
      readonly catalogRevision?: string | null;
      readonly nextCursor?: string | null;
      readonly hasMore?: boolean;
      readonly catalogAuthority?: SessionCatalogAuthority;
      readonly paginationSupported?: boolean;
      readonly paginationUnavailableReason?: SessionPaginationUnavailableReason | null;
      readonly capabilities?: SessionCapabilities;
      readonly diagnostics?: SessionCatalogDiagnostic[];
    }
  | { readonly kind: "library"; readonly revision: number; readonly library: LibraryEntry[] }
  | { readonly kind: "transfers"; readonly revision: number; readonly transfers: Transfer[] }
  | { readonly kind: "storage"; readonly revision: number; readonly storage: StorageConfig }
  | { readonly kind: "transferJobs"; readonly revision: number; readonly jobs: TransferJobEvent[] }
  | { readonly kind: "pairingTick"; readonly revision: number; readonly payload: PairingTickPayload }
  | { readonly kind: "pairingResolved"; readonly revision: number; readonly payload: PairingResolutionPayload };

export type BackendEventKind = BackendEvent["kind"];

/** The whole backend-owned world as of one outer revision. The per-resource
 * watermarks come from the nested snapshot envelope and are what startup
 * replay uses; the outer revision is only the envelope's own watermark. */
export interface BackendSnapshot {
  readonly devices: Device[];
  readonly library: LibraryEntry[];
  readonly transfers: Transfer[];
  readonly storage: StorageConfig;
  readonly revisions: {
    readonly devices: number;
    readonly library: number;
    readonly transfers: number;
    readonly storage: number;
  };
}

export type BackendEventSink = (event: BackendEvent) => void;

/** A session mutation, per item, plus the refreshed session list the backend
 * chose to return (`null` when it could not re-read the device). */
export interface SessionMutation {
  readonly items: readonly BatchItem<SessionId>[];
  readonly sessions: SessionView[] | null;
  readonly operationError: RpcError | null;
}

/** A library mutation, per item, plus the refreshed library. */
export interface LibraryMutation {
  readonly items: readonly BatchItem<LibraryKey>[];
  readonly library: LibraryEntry[];
}

/** A batch that creates background jobs, per item. */
export interface JobDispatch<TId, TJob> {
  readonly items: readonly DispatchItem<TId, TJob>[];
}

export interface TransferBackend {
  /** Registers every channel or none of them; the returned disposer is
   * idempotent. Holding the transport's unsubscribe functions is the adapter's
   * job, never the caller's. */
  subscribe(sink: BackendEventSink): Promise<() => void>;
  /** The revisioned start snapshot. */
  readSnapshot(): Promise<Revisioned<BackendSnapshot>>;

  listDevices(): Promise<Revisioned<Device[]>>;
  listSessions(
    deviceId: DeviceId,
    cursor?: string | null,
    catalogRevision?: string | null,
  ): Promise<Revisioned<SessionPageView>>;
  getSessionDetail(
    deviceId: DeviceId,
    sessionId: SessionId,
    sessionRevision: string,
    catalogRevision: string | null,
  ): Promise<Revisioned<SessionView>>;
  listLibrary(): Promise<Revisioned<LibraryEntry[]>>;
  listTransfers(): Promise<Revisioned<Transfer[]>>;
  getStorageConfig(): Promise<Revisioned<StorageConfig>>;

  connectDevice(deviceId: DeviceId): Promise<PairingAttemptId>;
  cancelPairing(deviceId: DeviceId, attemptId: PairingAttemptId): Promise<void>;
  addManualDevice(ip: string): Promise<Revisioned<Device>>;
  disconnectDevice(deviceId: DeviceId): Promise<void>;

  deleteSessions(deviceId: DeviceId, sessionIds: readonly SessionId[]): Promise<Revisioned<SessionMutation>>;
  cleanupBackedUp(deviceId: DeviceId): Promise<Revisioned<SessionMutation>>;
  previewDownloadedCleanup(deviceId: DeviceId): Promise<DownloadedCleanupPreview>;
  cleanupDownloaded(deviceId: DeviceId): Promise<Revisioned<DownloadedCleanupResult>>;

  removeLibraryEntries(keys: readonly LibraryKey[]): Promise<Revisioned<LibraryMutation>>;
  revealLibraryFile(key: LibraryKey, fileId: FileId): Promise<void>;

  downloadSession(deviceId: DeviceId, sessionId: SessionId): Promise<DownloadJobId>;
  downloadSessions(
    deviceId: DeviceId,
    sessionIds: readonly SessionId[],
  ): Promise<JobDispatch<SessionId, DownloadJobId>>;
  uploadEntry(key: LibraryKey): Promise<UploadJobId>;
  uploadEntries(keys: readonly LibraryKey[]): Promise<JobDispatch<LibraryKey, UploadJobId>>;

  /** The one control both directions share. */
  retryTransfer(id: TransferRetryId): Promise<void>;
  pauseTransferJob(jobId: DownloadJobId): Promise<void>;
  resumeTransferJob(jobId: DownloadJobId): Promise<void>;
  cancelTransferJob(jobId: DownloadJobId): Promise<void>;
  dismissTransferJob(jobId: DownloadJobId): Promise<void>;
  /** Uploads are the only direction with an abort command, so this takes an
   * upload identity and nothing else — a `DownloadJobId` will not compile. */
  cancelUpload(jobId: UploadJobId): Promise<void>;
  dismissUpload(jobId: UploadJobId): Promise<void>;

  selectDownloadRoot(): Promise<string | null>;
  saveDownloadRoot(downloadRoot: string): Promise<Revisioned<StorageConfig>>;
  saveStorageConfig(config: SaveStorageConfigInput): Promise<Revisioned<StorageConfig>>;
  testStorageConnection(config: SaveStorageConfigInput): Promise<void>;

  setNotificationsEnabled(enabled: boolean): Promise<boolean>;
}

/** A transport failure translated by an adapter. `message` is the text the
 * transport produced, so user-facing strings keep reading exactly as before. */
export class BackendError extends Error {
  readonly channel: string;
  readonly rpcError: RpcError | null;
  /** The raw rejection value, kept for diagnostics. Assigned explicitly rather
   * than via `Error`'s `cause` option, which this build target predates. */
  readonly reason: unknown;

  constructor(channel: string, message: string, options?: { cause?: unknown; rpcError?: RpcError }) {
    super(message);
    this.name = "BackendError";
    this.channel = channel;
    this.reason = options?.cause;
    this.rpcError = options?.rpcError ?? null;
  }
}

/** The single place that turns any thrown value into toast text. */
export function describeBackendError(error: unknown): string {
  return error instanceof BackendError ? error.message : String(error);
}

export function backendRpcError(error: unknown): RpcError | null {
  return error instanceof BackendError ? error.rpcError : null;
}
