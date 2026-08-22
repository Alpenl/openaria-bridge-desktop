import {
  describeMediaBackendError,
  type MediaBackend,
  type MediaBackendEvent,
  type MediaResourceName,
  type Revisioned,
} from "./backend";
import type { MediaCommitResult, MediaResourceFailure, MediaRuntimeStore } from "./reducer";

export interface StartMediaRuntimeOptions {
  readonly backend: MediaBackend;
  readonly store: MediaRuntimeStore;
  readonly now?: () => number;
  readonly onEvent?: (event: MediaBackendEvent, result: MediaCommitResult) => void;
  readonly onSnapshot?: (result: MediaCommitResult) => void;
}

export interface MediaRuntimeSession {
  dispose(): void;
}

const RESOURCE_NAMES: readonly MediaResourceName[] = ["scan", "imports", "derivations", "pipelines", "library"];

export function mediaResourceFailureOf(error: unknown): MediaResourceFailure {
  if (error !== null && typeof error === "object") {
    const candidate = error as { readonly mediaError?: unknown; readonly rpcError?: unknown };
    const rpcError = candidate.mediaError ?? candidate.rpcError;
    if (
      rpcError !== null &&
      typeof rpcError === "object" &&
      typeof (rpcError as { readonly message?: unknown }).message === "string" &&
      typeof (rpcError as { readonly retryable?: unknown }).retryable === "boolean"
    ) {
      return {
        message: (rpcError as { readonly message: string }).message,
        retryable: (rpcError as { readonly retryable: boolean }).retryable,
        rpcError: rpcError as MediaResourceFailure["rpcError"],
      };
    }
  }
  return { message: describeMediaBackendError(error), retryable: true, rpcError: null };
}

function eventIncluded(revisions: ReadonlyMap<MediaResourceName, number>, event: MediaBackendEvent): boolean {
  const boundary = revisions.get(event.kind);
  return boundary !== undefined && event.revision <= boundary;
}

export async function startMediaRuntime(options: StartMediaRuntimeOptions): Promise<MediaRuntimeSession> {
  const { backend, store, onEvent, onSnapshot } = options;
  const now = options.now ?? Date.now;
  let buffer: MediaBackendEvent[] | null = [];
  let disposed = false;

  function deliver(event: MediaBackendEvent): void {
    if (disposed) return;
    onEvent?.(event, store.commit({ type: "event", event }));
  }

  const unsubscribe = await backend.subscribe((event) => {
    if (buffer !== null) buffer.push(event);
    else deliver(event);
  });

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    buffer = null;
    unsubscribe();
  };

  try {
    for (const resource of RESOURCE_NAMES) {
      store.commit({ type: "resource/loading", resource, retry: false, requestedAt: now() });
    }

    const boundaries = new Map<MediaResourceName, number>();
    try {
      const snapshot = await backend.readSnapshot();
      const nested = snapshot.value;
      for (const resource of RESOURCE_NAMES) {
        if (nested[resource].revision > snapshot.revision) {
          throw new Error(`${resource} revision exceeds aggregate media snapshot revision`);
        }
        boundaries.set(resource, nested[resource].revision);
      }
      onSnapshot?.(store.commit({ type: "snapshot", snapshot: nested }));
    } catch {
      const reads: {
        readonly resource: MediaResourceName;
        readonly read: () => Promise<Revisioned<unknown>>;
      }[] = [
        { resource: "scan", read: () => backend.readScanCandidates() },
        { resource: "imports", read: () => backend.readImportJobs() },
        { resource: "derivations", read: () => backend.readDerivationJobs() },
        { resource: "pipelines", read: () => backend.readPipelineSessions() },
        { resource: "library", read: () => backend.readLibraryProjections() },
      ];
      const results = await Promise.all(
        reads.map(async ({ resource, read }): Promise<MediaCommitResult> => {
          try {
            const loaded = await read();
            boundaries.set(resource, loaded.revision);
            return store.commit({
              type: `${resource}/loaded`,
              revision: loaded.revision,
              value: loaded.value,
            } as Parameters<MediaRuntimeStore["commit"]>[0]);
          } catch (error) {
            return store.commit({ type: "resource/failed", resource, failure: mediaResourceFailureOf(error) });
          }
        }),
      );
      onSnapshot?.({
        changed: results.some((result) => result.changed),
        stale: results.every((result) => result.stale),
      });
    }

    const queue = buffer ?? [];
    let cursor = 0;
    while (!disposed && cursor < queue.length) {
      const event = queue[cursor];
      cursor += 1;
      if (!eventIncluded(boundaries, event)) deliver(event);
    }
    if (buffer === queue) buffer = null;
    return { dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}

export async function retryMediaResource(
  backend: MediaBackend,
  store: MediaRuntimeStore,
  resource: MediaResourceName,
  now: () => number = Date.now,
): Promise<MediaCommitResult> {
  const requestRevision = store.getState()[resource].revision;
  store.commit({ type: "resource/loading", resource, retry: true, requestedAt: now() });
  try {
    const loaded =
      resource === "scan"
        ? await backend.readScanCandidates()
        : resource === "imports"
          ? await backend.readImportJobs()
          : resource === "derivations"
            ? await backend.readDerivationJobs()
            : resource === "pipelines"
              ? await backend.readPipelineSessions()
              : await backend.readLibraryProjections();
    return store.commit({
      type: `${resource}/loaded`,
      revision: loaded.revision,
      value: loaded.value,
    } as Parameters<MediaRuntimeStore["commit"]>[0]);
  } catch (error) {
    return store.commit({
      type: "resource/failed",
      resource,
      failure: mediaResourceFailureOf(error),
      requestRevision,
    });
  }
}
