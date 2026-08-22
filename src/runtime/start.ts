// Race-free backend start.
//
// The old boot read a snapshot and subscribed at the same time, so an event
// that arrived in between could be lost — or, worse, be overwritten by the
// older snapshot that landed after it. The order here is the only one that
// cannot lose or invert an update:
//
//   1. subscribe first, buffering everything that arrives;
//   2. read the revisioned snapshot;
//   3. commit the snapshot;
//   4. discard buffered events already represented by the snapshot and replay
//      the newer ones through one FIFO drain;
//   5. go live.
//
// Subscribe failures and unclassified snapshot failures dispose every listener
// before the failure propagates. A recognized resource failure is different:
// its independent fallback reads keep the session alive in a degraded state so
// the UI can retry that resource without restarting the app.

import type { BackendEvent, BackendSnapshot, Revisioned, TransferBackend } from "./backend";
import { BackendError, backendRpcError, describeBackendError } from "./backend";
import type { AppStore, CommitResult } from "./reducer";
import type { Device, LibraryEntry, StorageConfig, Transfer } from "../types";

export interface BackendStartOptions {
  backend: TransferBackend;
  store: AppStore;
  /** Called for every event that reaches the store — replayed or live —
   * with what the commit changed, so the caller can repaint. */
  onEvent?: (event: BackendEvent, result: CommitResult) => void;
  /** Called once the snapshot has been committed. */
  onSnapshot?: (result: CommitResult) => void;
}

export interface BackendSession {
  /** Idempotent: shutdown, hot reload and tests may all call it. */
  dispose(): void;
}

const LOADING_RESOURCES = ["devices", "library", "transfers", "storage"] as const;
type BootResource = (typeof LOADING_RESOURCES)[number];

type EventResourceIdentity = BootResource | "transferJobs" | `sessions:${string}` | `pairing:${string}:${string}`;

type ReplayBoundary = { kind: "resources"; revisions: ReadonlyMap<EventResourceIdentity, number> };

function eventResourceIdentity(event: BackendEvent): EventResourceIdentity {
  switch (event.kind) {
    case "devices":
    case "library":
    case "transfers":
    case "storage":
    case "transferJobs":
      return event.kind;
    case "sessions":
      return `sessions:${event.deviceId}`;
    case "pairingTick":
    case "pairingResolved":
      return `pairing:${event.payload.deviceId}:${event.payload.attemptId}`;
  }
}

function snapshotIncludesEvent(boundary: ReplayBoundary, event: BackendEvent): boolean {
  const revision = boundary.revisions.get(eventResourceIdentity(event));
  return revision !== undefined && event.revision <= revision;
}

function failedSnapshotResource(error: unknown): BootResource | null {
  if (!(error instanceof BackendError)) return null;
  switch (error.channel) {
    case "list_devices":
    case "devices":
      return "devices";
    case "list_library":
    case "library":
      return "library";
    case "list_transfers":
    case "transfers":
      return "transfers";
    case "get_storage_config":
    case "storage":
      return "storage";
    default:
      return null;
  }
}

interface FallbackBootResult {
  resource: BootResource;
  result: CommitResult;
  revision: number | null;
}

export async function startBackend(options: BackendStartOptions): Promise<BackendSession> {
  const { backend, store, onEvent, onSnapshot } = options;

  /** Non-null while events are buffered; null once the session is live. */
  let buffer: BackendEvent[] | null = [];
  let disposed = false;

  function deliver(event: BackendEvent): void {
    if (disposed) return;
    const result = store.commit({ type: "backend/event", event });
    onEvent?.(event, result);
  }

  const unsubscribe = await backend.subscribe((event) => {
    if (buffer !== null) {
      buffer.push(event);
      return;
    }
    deliver(event);
  });

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    buffer = null;
    unsubscribe();
  };

  try {
    for (const resource of LOADING_RESOURCES) store.commit({ type: "resource/loading", resource });

    let snapshot: Revisioned<BackendSnapshot> | null = null;
    let snapshotAlreadyCommitted = false;
    let replayBoundary: ReplayBoundary | null = null;
    try {
      snapshot = await backend.readSnapshot();
    } catch (error) {
      const failedResource = failedSnapshotResource(error);
      // A transport/subscribe failure has no safe partial interpretation. Keep
      // the old fatal behavior for that case; only a named resource failure can
      // be recovered independently.
      if (failedResource === null) {
        const message = describeBackendError(error);
        const rpcError = backendRpcError(error);
        for (const resource of LOADING_RESOURCES) {
          store.commit({
            type: "resource/failed",
            resource,
            error: message,
            ...(rpcError === null ? {} : { rpcError }),
          });
        }
        throw error;
      }

      // The aggregate snapshot is a convenience, not an atomic requirement for
      // boot. Read each resource independently so a storage outage does not hide
      // devices, transfers or the last-good local library. Events remain buffered
      // throughout this recovery just as they are during the normal snapshot.
      const fallbackReads: readonly [
        BootResource,
        () => Promise<{ revision: number; value: unknown }>,
        (value: unknown, revision: number) => CommitResult,
      ][] = [
        [
          "devices",
          () => backend.listDevices(),
          (value, revision) => store.commit({ type: "devices/loaded", revision, devices: value as Device[] }),
        ],
        [
          "library",
          () => backend.listLibrary(),
          (value, revision) => store.commit({ type: "library/loaded", revision, library: value as LibraryEntry[] }),
        ],
        [
          "transfers",
          () => backend.listTransfers(),
          (value, revision) => store.commit({ type: "transfers/loaded", revision, transfers: value as Transfer[] }),
        ],
        [
          "storage",
          () => backend.getStorageConfig(),
          (value, revision) => store.commit({ type: "storage/loaded", revision, storage: value as StorageConfig }),
        ],
      ];
      const recovered = await Promise.all(
        fallbackReads.map(async ([resource, read, apply]): Promise<FallbackBootResult> => {
          try {
            const loaded = await read();
            return { resource, result: apply(loaded.value, loaded.revision), revision: loaded.revision };
          } catch (readError) {
            const message = describeBackendError(readError);
            const rpcError = backendRpcError(readError);
            const result = store.commit({
              type: "resource/failed",
              resource,
              error: message,
              ...(rpcError === null ? {} : { rpcError }),
            });
            return { resource, result, revision: null };
          }
        }),
      );
      const revisions = new Map<EventResourceIdentity, number>();
      for (const item of recovered) {
        if (item.revision !== null) revisions.set(item.resource, item.revision);
      }
      replayBoundary = { kind: "resources", revisions };
      const results = recovered.map((item) => item.result);
      onSnapshot?.({
        changed: results.some((result) => result.changed),
        stale: results.every((result) => result.stale),
      });
      snapshotAlreadyCommitted = true;
    }

    if (!snapshotAlreadyCommitted) {
      if (snapshot === null) throw new Error("backend start completed without a snapshot");
      replayBoundary = {
        kind: "resources",
        revisions: new Map<EventResourceIdentity, number>([
          ["devices", snapshot.value.revisions.devices],
          ["library", snapshot.value.revisions.library],
          ["transfers", snapshot.value.revisions.transfers],
          ["storage", snapshot.value.revisions.storage],
        ]),
      };
      const snapshotResult = store.commit({
        type: "backend/snapshot",
        revision: snapshot.revision,
        snapshot: snapshot.value,
      });
      onSnapshot?.(snapshotResult);
    }

    if (replayBoundary === null) throw new Error("backend start completed without a replay boundary");
    const queue = buffer ?? [];
    let cursor = 0;
    // Keep the subscriber in buffering mode while draining. Any event emitted
    // synchronously from `onEvent` appends to this same queue and is processed
    // after events that had already arrived.
    while (!disposed && cursor < queue.length) {
      const event = queue[cursor];
      cursor += 1;
      if (!snapshotIncludesEvent(replayBoundary, event)) deliver(event);
    }
    if (buffer === queue) buffer = null;

    return { dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}
