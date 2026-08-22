// An in-memory `TransferBackend` for workflow tests.
//
// It implements the same contract as the Tauri adapter — the same all-or-none
// subscription, the same idempotent disposer, the same revision stamping — and
// adds the controls a deterministic test needs: emit an event at any moment,
// hold a call pending, fail a channel registration, and inspect what was
// called and what was unsubscribed. No timers, no transport, no globals.

import { subscribeAll, type EventRegistration } from "./subscribeAll";
import {
  BackendError,
  revisioned,
  type BackendEvent,
  type BackendEventKind,
  type BackendEventSink,
  type BackendSnapshot,
  type JobDispatch,
  type LibraryMutation,
  type Revisioned,
  type SessionMutation,
  type TransferBackend,
} from "./backend";
import type { DispatchItem } from "./batch";
import {
  asDownloadJobId,
  asPairingAttemptId,
  asUploadJobId,
  type DeviceId,
  type DownloadJobId,
  type LibraryKey,
  type SessionId,
  type UploadJobId,
} from "../ids";
import type {
  Device,
  DownloadedCleanupPreview,
  DownloadedCleanupResult,
  LibraryEntry,
  RpcError,
  SaveStorageConfigInput,
  SessionView,
  StorageConfig,
  Transfer,
  TransferJobEvent,
} from "../types";

export const EMPTY_STORAGE: StorageConfig = {
  endpoint: "",
  bucket: "",
  prefix: "",
  urlStyle: "virtualHost",
  secretConfigured: false,
  downloadRoot: "",
  activeDownloadRoot: "/downloads",
};

export interface MemoryBackendOptions {
  /** Starting backend-owned world; missing parts default to empty. */
  snapshot?: Partial<BackendSnapshot>;
  /** Channels whose registration must reject, e.g. `["library"]`. */
  failingChannels?: readonly BackendEventKind[];
}

/** An event as a test writes it: everything but the revision, which the
 * backend stamps so ordering is always the backend's to decide. */
export type EmittedEvent = {
  [K in BackendEventKind]: Omit<Extract<BackendEvent, { kind: K }>, "revision">;
}[BackendEventKind];

/** One recorded call: the operation name and its arguments. */
export interface RecordedCall {
  readonly name: string;
  readonly args: readonly unknown[];
}

export interface EventDeliveryFailure {
  readonly event: BackendEvent;
  readonly error: Error;
}

export interface MemoryBackend extends TransferBackend {
  /** Every command/read this backend was asked for, in order. */
  readonly calls: RecordedCall[];
  /** Names only — the common assertion. */
  callNames(): string[];
  /** Channels whose unlisten actually ran. */
  readonly unsubscribed: BackendEventKind[];
  /** Channels currently registered. */
  readonly listening: BackendEventKind[];
  /** Sanitized diagnostics for event sinks that threw during delivery. */
  readonly deliveryFailures: EventDeliveryFailure[];

  /** Pushes an event and returns the revision it was stamped with. */
  emit(event: EmittedEvent): number;

  /** Later calls to `name` stay pending until `release`/`rejectHeld`. */
  hold(name: string): void;
  /** Resolves the oldest held call of `name`, optionally with a value. */
  release(name: string, value?: unknown): void;
  /** Resolves the newest held call — the "second request replies first" race. */
  releaseLast(name: string, value?: unknown): void;
  /** Rejects the oldest held call of `name`. */
  rejectHeld(name: string, error?: unknown): void;
  /** How many calls of `name` are waiting. */
  pending(name: string): number;

  setDevices(devices: Device[]): void;
  setSessions(deviceId: string, sessions: SessionView[]): void;
  /** Makes the next dispatch of `name` reject the listed items instead of
   * queueing them — the partial-failure case. */
  rejectBatchItems(name: "downloadSessions" | "uploadEntries", items: Record<string, string>): void;
  setLibrary(library: LibraryEntry[]): void;
  setTransfers(transfers: Transfer[]): void;
  setStorage(storage: StorageConfig): void;
  /** Fails every later call of `name` with `error`. */
  failCalls(name: string, error: unknown): void;
}

interface HeldCall {
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
  produce: () => unknown;
  mapExplicit: (value: unknown) => unknown;
}

const EVENT_CHANNELS: readonly BackendEventKind[] = [
  "devices",
  "sessions",
  "library",
  "transfers",
  "storage",
  "transferJobs",
  "pairingTick",
  "pairingResolved",
];

export function createMemoryBackend(options: MemoryBackendOptions = {}): MemoryBackend {
  const failing = new Set<BackendEventKind>(options.failingChannels ?? []);
  const sinks = new Set<BackendEventSink>();
  const listening: BackendEventKind[] = [];
  const unsubscribed: BackendEventKind[] = [];
  const deliveryFailures: EventDeliveryFailure[] = [];
  const calls: RecordedCall[] = [];
  const held = new Map<string, HeldCall[]>();
  const holding = new Set<string>();
  const failures = new Map<string, unknown>();
  const batchRejections = new Map<string, Record<string, string>>();

  let revision = 0;
  let devices: Device[] = options.snapshot?.devices ?? [];
  let library: LibraryEntry[] = options.snapshot?.library ?? [];
  let transfers: Transfer[] = options.snapshot?.transfers ?? [];
  let storage: StorageConfig = options.snapshot?.storage ?? EMPTY_STORAGE;
  const sessionsByDevice = new Map<string, SessionView[]>();
  let devicesRevision = options.snapshot?.revisions?.devices ?? 0;
  let libraryRevision = options.snapshot?.revisions?.library ?? 0;
  let transfersRevision = options.snapshot?.revisions?.transfers ?? 0;
  let storageRevision = options.snapshot?.revisions?.storage ?? 0;
  const sessionsRevisionByDevice = new Map<string, number>();
  revision = Math.max(devicesRevision, libraryRevision, transfersRevision, storageRevision);

  function deliver(event: BackendEvent): void {
    for (const sink of [...sinks]) {
      try {
        sink(event);
      } catch (error) {
        let message = "event sink failed";
        try {
          message = error instanceof Error ? error.message : String(error);
        } catch {
          // Keep diagnostics safe even when a hostile thrown value cannot be stringified.
        }
        deliveryFailures.push({ event, error: new Error(message) });
      }
    }
  }

  /** Records the call and either resolves it or parks it for `release`. */
  function respond<T>(
    name: string,
    args: readonly unknown[],
    produce: () => T,
    mapExplicit: (value: unknown) => unknown = (value) => value,
  ): Promise<T> {
    calls.push({ name, args });
    const failure = failures.get(name);
    if (failure !== undefined) return Promise.reject(failure);
    if (!holding.has(name)) return Promise.resolve(produce());
    return new Promise<T>((resolve, reject) => {
      const queue = held.get(name) ?? [];
      queue.push({
        resolve: (value) => resolve(value as T),
        reject,
        produce: produce as () => unknown,
        mapExplicit,
      });
      held.set(name, queue);
    });
  }

  function resourceRevision(kind: "devices" | "library" | "transfers" | "storage"): number {
    if (kind === "devices") return devicesRevision;
    if (kind === "library") return libraryRevision;
    if (kind === "transfers") return transfersRevision;
    return storageRevision;
  }

  function nextResourceRevision(
    kind: "devices" | "library" | "transfers" | "storage" | "sessions",
    deviceId?: string,
  ): number {
    revision += 1;
    if (kind === "devices") devicesRevision = revision;
    else if (kind === "library") libraryRevision = revision;
    else if (kind === "transfers") transfersRevision = revision;
    else if (kind === "storage") storageRevision = revision;
    else if (deviceId !== undefined) sessionsRevisionByDevice.set(deviceId, revision);
    return revision;
  }

  /** Read the value and its resource watermark in one synchronous operation. */
  function readAt<T>(
    name: string,
    args: readonly unknown[],
    kind: "devices" | "library" | "transfers" | "storage",
    produce: () => T,
  ): Promise<Revisioned<T>> {
    const at = resourceRevision(kind);
    return respond(
      name,
      args,
      () => revisioned(resourceRevision(kind), produce()),
      (value) => revisioned(at, value as T),
    );
  }

  function readSessionsAt<T>(name: string, deviceId: string, produce: () => T): Promise<Revisioned<T>> {
    const at = sessionsRevisionByDevice.get(deviceId) ?? 0;
    return respond(
      name,
      [deviceId],
      () => revisioned(sessionsRevisionByDevice.get(deviceId) ?? 0, produce()),
      (value) => revisioned(at, value as T),
    );
  }

  function mutate<T>(
    name: string,
    args: readonly unknown[],
    kind: "devices" | "library" | "storage" | "sessions",
    deviceId: string | undefined,
    produce: () => T,
    emit: (revision: number, value: T) => BackendEvent,
  ): Promise<Revisioned<T>> {
    return respond(name, args, () => {
      const next = nextResourceRevision(kind, deviceId);
      const value = produce();
      deliver(emit(next, value));
      return revisioned(next, value);
    });
  }

  /** Builds a per-item dispatch, honouring any configured partial failure. */
  function dispatch<TId extends string, TJob>(
    name: string,
    items: readonly TId[],
    brandJob: (raw: string) => TJob,
    jobIdFor: (item: TId) => string,
  ): JobDispatch<TId, TJob> {
    const rejected = batchRejections.get(name) ?? {};
    return {
      items: items.map((item): DispatchItem<TId, TJob> => {
        const error = Object.prototype.hasOwnProperty.call(rejected, item) ? rejected[item] : undefined;
        return error === undefined
          ? { status: "queued", item, jobId: brandJob(jobIdFor(item)) }
          : {
              status: "failed",
              item,
              error: {
                code: name === "downloadSessions" ? "download_enqueue_failed" : "upload_enqueue_failed",
                message: error,
                retryable: true,
                details: { item },
              } satisfies RpcError,
            };
      }),
    };
  }

  const backend: MemoryBackend = {
    calls,
    unsubscribed,
    listening,
    deliveryFailures,
    callNames: () => calls.map((call) => call.name),

    async subscribe(sink: BackendEventSink): Promise<() => void> {
      const registrations: EventRegistration[] = EVENT_CHANNELS.map((channel) => () => {
        if (failing.has(channel)) {
          return Promise.reject(new BackendError(channel, `channel ${channel} unavailable`));
        }
        listening.push(channel);
        return Promise.resolve(() => {
          unsubscribed.push(channel);
          const index = listening.indexOf(channel);
          if (index >= 0) listening.splice(index, 1);
        });
      });

      const dispose = await subscribeAll(registrations).catch((error: unknown) => {
        sinks.delete(sink);
        throw error;
      });
      sinks.add(sink);
      return () => {
        sinks.delete(sink);
        dispose();
      };
    },

    emit(event: EmittedEvent): number {
      const eventRevision = nextResourceRevision(
        event.kind === "devices"
          ? "devices"
          : event.kind === "library"
            ? "library"
            : event.kind === "transfers"
              ? "transfers"
              : event.kind === "storage"
                ? "storage"
                : "sessions",
        event.kind === "sessions" ? event.deviceId : undefined,
      );
      const stamped = { ...event, revision: eventRevision } as BackendEvent;
      switch (stamped.kind) {
        case "devices":
          devices = stamped.devices;
          break;
        case "sessions":
          sessionsByDevice.set(stamped.deviceId, stamped.sessions);
          break;
        case "library":
          library = stamped.library;
          break;
        case "transfers":
          transfers = stamped.transfers;
          break;
        case "storage":
          storage = stamped.storage;
          break;
        default:
          break;
      }
      deliver(stamped);
      return eventRevision;
    },

    readSnapshot(): Promise<Revisioned<BackendSnapshot>> {
      const at = revision;
      const snapshot: BackendSnapshot = {
        devices,
        library,
        transfers,
        storage,
        revisions: {
          devices: devicesRevision,
          library: libraryRevision,
          transfers: transfersRevision,
          storage: storageRevision,
        },
      };
      return respond("readSnapshot", [], () => snapshot).then((value) => revisioned(at, value));
    },

    listDevices: () => readAt("listDevices", [], "devices", () => devices),
    listSessions: (deviceId: DeviceId) =>
      readSessionsAt("listSessions", deviceId, () => sessionsByDevice.get(deviceId) ?? []),
    listLibrary: () => readAt("listLibrary", [], "library", () => library),
    listTransfers: () => readAt("listTransfers", [], "transfers", () => transfers),
    getStorageConfig: () => readAt("getStorageConfig", [], "storage", () => storage),

    connectDevice: (deviceId) => respond("connectDevice", [deviceId], () => asPairingAttemptId(`attempt-${deviceId}`)),
    cancelPairing: (deviceId, attemptId) => respond("cancelPairing", [deviceId, attemptId], () => undefined),
    addManualDevice: (ip) =>
      mutate(
        "addManualDevice",
        [ip],
        "devices",
        undefined,
        (): Device => {
          const device = {
            id: `ylx-${"0".repeat(64)}`,
            displayId: "YLX-00000000",
            ip,
            state: "idle" as const,
            lastSeen: null,
          };
          devices = [...devices.filter((candidate) => candidate.id !== device.id), device];
          return device;
        },
        (eventRevision) => ({ kind: "devices", revision: eventRevision, devices }),
      ),
    disconnectDevice: (deviceId) => respond("disconnectDevice", [deviceId], () => undefined),

    deleteSessions: (deviceId, sessionIds) =>
      mutate(
        "deleteSessions",
        [deviceId, sessionIds],
        "sessions",
        deviceId,
        (): SessionMutation => {
          const current = sessionsByDevice.get(deviceId) ?? [];
          const removed = new Set(sessionIds.map((id) => String(id)));
          const nextSessions = current.filter((session) => !removed.has(session.id));
          sessionsByDevice.set(deviceId, nextSessions);
          return {
            items: sessionIds.map((item) => ({ status: "ok", item })),
            sessions: nextSessions,
            operationError: null,
          };
        },
        (eventRevision, value) => ({
          kind: "sessions",
          revision: eventRevision,
          deviceId,
          sessions: value.sessions ?? [],
        }),
      ),
    cleanupBackedUp: (deviceId) =>
      mutate(
        "cleanupBackedUp",
        [deviceId],
        "sessions",
        deviceId,
        (): SessionMutation => ({
          items: [],
          sessions: sessionsByDevice.get(deviceId) ?? [],
          operationError: null,
        }),
        (eventRevision, value) => ({
          kind: "sessions",
          revision: eventRevision,
          deviceId,
          sessions: value.sessions ?? [],
        }),
      ),
    previewDownloadedCleanup: (deviceId) =>
      respond("previewDownloadedCleanup", [deviceId], (): DownloadedCleanupPreview => ({
        eligible: [],
        skipped: [],
        eligibleBytes: 0,
      })),
    cleanupDownloaded: (deviceId) =>
      mutate(
        "cleanupDownloaded",
        [deviceId],
        "sessions",
        deviceId,
        (): DownloadedCleanupResult => ({
          eligible: [],
          deleted: [],
          failed: [],
          skipped: [],
          sessions: sessionsByDevice.get(deviceId) ?? [],
        }),
        (eventRevision, value) => ({ kind: "sessions", revision: eventRevision, deviceId, sessions: value.sessions }),
      ),

    removeLibraryEntries: (keys) =>
      mutate(
        "removeLibraryEntries",
        [keys],
        "library",
        undefined,
        (): LibraryMutation => {
          const requested = new Set(keys.map((key) => String(key)));
          library = library.filter((entry) => !requested.has(`${entry.deviceId}|${entry.sessionId}`));
          return { items: keys.map((item) => ({ status: "ok", item })), library };
        },
        (eventRevision, value) => ({ kind: "library", revision: eventRevision, library: value.library }),
      ),
    revealLibraryFile: (key, fileId) => respond("revealLibraryFile", [key, fileId], () => undefined),

    downloadSession: (deviceId, sessionId) =>
      respond("downloadSession", [deviceId, sessionId], () => asDownloadJobId(`job-${sessionId}`)),
    downloadSessions: (deviceId, sessionIds) =>
      respond("downloadSessions", [deviceId, sessionIds], () =>
        dispatch<SessionId, DownloadJobId>("downloadSessions", sessionIds, asDownloadJobId, (id) => `job-${id}`),
      ),
    downloadFile: (deviceId, sessionId, fileId) =>
      respond("downloadFile", [deviceId, sessionId, fileId], () => asDownloadJobId(`job-${fileId}`)),
    uploadEntry: (key) => respond("uploadEntry", [key], () => asUploadJobId(`upload-${key}`)),
    uploadEntries: (keys) =>
      respond("uploadEntries", [keys], () =>
        dispatch<LibraryKey, UploadJobId>("uploadEntries", keys, asUploadJobId, (key) => `upload-${key}`),
      ),

    retryTransfer: (id) => respond("retryTransfer", [id], () => undefined),
    pauseTransferJob: (jobId) => respond("pauseTransferJob", [jobId], () => undefined),
    resumeTransferJob: (jobId) => respond("resumeTransferJob", [jobId], () => undefined),
    cancelTransferJob: (jobId) => respond("cancelTransferJob", [jobId], () => undefined),
    dismissTransferJob: (jobId) => respond("dismissTransferJob", [jobId], () => undefined),
    cancelUpload: (jobId) => respond("cancelUpload", [jobId], () => undefined),
    dismissUpload: (jobId) => respond("dismissUpload", [jobId], () => undefined),

    selectDownloadRoot: () => respond("selectDownloadRoot", [], () => null),
    saveDownloadRoot: (downloadRoot) =>
      mutate(
        "saveDownloadRoot",
        [downloadRoot],
        "storage",
        undefined,
        () => {
          storage = { ...storage, downloadRoot, activeDownloadRoot: downloadRoot || storage.activeDownloadRoot };
          return storage;
        },
        (eventRevision, value) => ({ kind: "storage", revision: eventRevision, storage: value }),
      ),
    saveStorageConfig: (config: SaveStorageConfigInput) =>
      mutate(
        "saveStorageConfig",
        [config],
        "storage",
        undefined,
        () => {
          storage = {
            ...storage,
            endpoint: config.endpoint,
            bucket: config.bucket,
            prefix: config.prefix,
            urlStyle: config.urlStyle,
            secretConfigured: config.secretKey.length > 0 ? true : storage.secretConfigured,
            downloadRoot: config.downloadRoot,
            activeDownloadRoot: config.downloadRoot || storage.activeDownloadRoot,
          };
          return storage;
        },
        (eventRevision, value) => ({ kind: "storage", revision: eventRevision, storage: value }),
      ),
    testStorageConnection: (config) => respond("testStorageConnection", [config], () => undefined),

    setNotificationsEnabled: (enabled) => respond("setNotificationsEnabled", [enabled], () => enabled),

    hold(name: string): void {
      holding.add(name);
    },
    release(name: string, value?: unknown): void {
      const queue = held.get(name);
      const next = queue?.shift();
      if (!next) throw new Error(`no held call named ${name}`);
      next.resolve(value === undefined ? next.produce() : next.mapExplicit(value));
    },
    releaseLast(name: string, value?: unknown): void {
      const queue = held.get(name);
      const next = queue?.pop();
      if (!next) throw new Error(`no held call named ${name}`);
      next.resolve(value === undefined ? next.produce() : next.mapExplicit(value));
    },
    rejectHeld(name: string, error: unknown = new BackendError(name, `${name} failed`)): void {
      const queue = held.get(name);
      const next = queue?.shift();
      if (!next) throw new Error(`no held call named ${name}`);
      next.reject(error);
    },
    pending: (name: string) => held.get(name)?.length ?? 0,

    setDevices(next: Device[]): void {
      devices = next;
    },
    setSessions(deviceId: string, next: SessionView[]): void {
      sessionsByDevice.set(deviceId, next);
    },
    setLibrary(next: LibraryEntry[]): void {
      library = next;
    },
    setTransfers(next: Transfer[]): void {
      transfers = next;
    },
    setStorage(next: StorageConfig): void {
      storage = next;
    },
    failCalls(name: string, error: unknown): void {
      failures.set(name, error);
    },
    rejectBatchItems(name: "downloadSessions" | "uploadEntries", items: Record<string, string>): void {
      batchRejections.set(name, items);
    },
  };

  return backend;
}

/** Convenience for tests that only need a plausible job event. */
export function memoryTransferJob(jobId: string, overrides: Partial<TransferJobEvent> = {}): TransferJobEvent {
  return {
    jobId,
    state: { state: "queued" },
    sessionId: null,
    deviceId: null,
    deviceDisplayId: null,
    totalBytes: 0,
    transferredBytes: 0,
    filesTotal: 0,
    filesDone: 0,
    desiredRunState: "run",
    ...overrides,
  };
}
