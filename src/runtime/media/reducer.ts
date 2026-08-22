import type { MediaBackendEvent, MediaBackendSnapshot, MediaResourceName } from "./backend";
import type {
  DerivationJob,
  ImportJob,
  MediaError,
  MediaLibraryEntryProjection,
  MediaScanSnapshot,
  PipelineSession,
} from "./types";

export interface MediaResourceFailure {
  readonly message: string;
  readonly retryable: boolean;
  readonly rpcError: MediaError | null;
}

export interface MediaRetryState {
  readonly available: boolean;
  readonly attempts: number;
  readonly requestedAt: number | null;
}

/** A failed refresh never blanks data that was already proven good. */
export interface MediaResourceState<T> {
  readonly loading: boolean;
  readonly value: T | null;
  readonly lastGood: T | null;
  readonly error: MediaResourceFailure | null;
  readonly revision: number;
  readonly retry: MediaRetryState;
}

export function idleMediaResource<T>(): MediaResourceState<T> {
  return {
    loading: false,
    value: null,
    lastGood: null,
    error: null,
    revision: -1,
    retry: { available: false, attempts: 0, requestedAt: null },
  };
}

export interface MediaRuntimeState {
  scan: MediaResourceState<MediaScanSnapshot>;
  imports: MediaResourceState<readonly ImportJob[]>;
  derivations: MediaResourceState<readonly DerivationJob[]>;
  pipelines: MediaResourceState<readonly PipelineSession[]>;
  library: MediaResourceState<readonly MediaLibraryEntryProjection[]>;
}

export function createMediaRuntimeState(): MediaRuntimeState {
  return {
    scan: idleMediaResource(),
    imports: idleMediaResource(),
    derivations: idleMediaResource(),
    pipelines: idleMediaResource(),
    library: idleMediaResource(),
  };
}

export type MediaRuntimeAction =
  | { readonly type: "snapshot"; readonly snapshot: MediaBackendSnapshot }
  | { readonly type: "event"; readonly event: MediaBackendEvent }
  | {
      readonly type: "resource/loading";
      readonly resource: MediaResourceName;
      readonly retry: boolean;
      readonly requestedAt: number;
    }
  | {
      readonly type: "resource/failed";
      readonly resource: MediaResourceName;
      readonly failure: MediaResourceFailure;
      readonly requestRevision?: number;
    }
  | { readonly type: "scan/loaded"; readonly revision: number; readonly value: MediaScanSnapshot }
  | { readonly type: "imports/loaded"; readonly revision: number; readonly value: readonly ImportJob[] }
  | { readonly type: "derivations/loaded"; readonly revision: number; readonly value: readonly DerivationJob[] }
  | { readonly type: "pipelines/loaded"; readonly revision: number; readonly value: readonly PipelineSession[] }
  | {
      readonly type: "library/loaded";
      readonly revision: number;
      readonly value: readonly MediaLibraryEntryProjection[];
    }
  | { readonly type: "imports/upsert"; readonly revision: number; readonly value: ImportJob }
  | { readonly type: "derivations/upsert"; readonly revision: number; readonly value: DerivationJob }
  | { readonly type: "pipelines/upsert"; readonly revision: number; readonly value: PipelineSession };

export interface MediaCommitResult {
  readonly changed: boolean;
  readonly stale: boolean;
}

const CHANGED: MediaCommitResult = { changed: true, stale: false };
const UNCHANGED: MediaCommitResult = { changed: false, stale: false };
const STALE: MediaCommitResult = { changed: false, stale: true };

export interface MediaRuntimeStore {
  getState(): MediaRuntimeState;
  commit(action: MediaRuntimeAction): MediaCommitResult;
}

function valuesEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((value, index) => valuesEqual(value, right[index]));
  }
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord);
  const rightKeys = Object.keys(rightRecord);
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every(
    (key) => Object.prototype.hasOwnProperty.call(rightRecord, key) && valuesEqual(leftRecord[key], rightRecord[key]),
  );
}

function load<T>(
  current: MediaResourceState<T>,
  revision: number,
  value: T,
): { readonly next: MediaResourceState<T>; readonly result: MediaCommitResult } {
  if (revision < current.revision) return { next: current, result: STALE };
  const changed =
    current.loading || current.error !== null || current.retry.available || !valuesEqual(current.value, value);
  return {
    next: {
      loading: false,
      value,
      lastGood: value,
      error: null,
      revision,
      retry: { available: false, attempts: 0, requestedAt: null },
    },
    result: changed ? CHANGED : UNCHANGED,
  };
}

function markLoading<T>(current: MediaResourceState<T>, retry: boolean, requestedAt: number): MediaResourceState<T> {
  return {
    ...current,
    loading: true,
    error: null,
    value: current.lastGood,
    retry: {
      available: false,
      attempts: retry ? current.retry.attempts + 1 : current.retry.attempts,
      requestedAt: retry ? requestedAt : current.retry.requestedAt,
    },
  };
}

function fail<T>(
  current: MediaResourceState<T>,
  failure: MediaResourceFailure,
  requestRevision?: number,
): { readonly next: MediaResourceState<T>; readonly result: MediaCommitResult } {
  if (requestRevision !== undefined && requestRevision < current.revision) return { next: current, result: STALE };
  const next: MediaResourceState<T> = {
    ...current,
    loading: false,
    value: current.lastGood,
    error: failure,
    retry: { ...current.retry, available: failure.retryable },
  };
  return { next, result: valuesEqual(current, next) ? UNCHANGED : CHANGED };
}

function upsertById<T extends { readonly id: string }>(values: readonly T[] | null, item: T): readonly T[] {
  if (values === null) return [item];
  const index = values.findIndex((candidate) => candidate.id === item.id);
  if (index < 0) return [...values, item];
  if (valuesEqual(values[index], item)) return values;
  return values.map((candidate, candidateIndex) => (candidateIndex === index ? item : candidate));
}

function resourceAction(event: MediaBackendEvent): MediaRuntimeAction {
  switch (event.kind) {
    case "scan":
      return { type: "scan/loaded", revision: event.revision, value: event.value };
    case "imports":
      return { type: "imports/loaded", revision: event.revision, value: event.value };
    case "derivations":
      return { type: "derivations/loaded", revision: event.revision, value: event.value };
    case "pipelines":
      return { type: "pipelines/loaded", revision: event.revision, value: event.value };
    case "library":
      return { type: "library/loaded", revision: event.revision, value: event.value };
  }
}

export function createMediaRuntimeStore(initial: MediaRuntimeState = createMediaRuntimeState()): MediaRuntimeStore {
  const state = initial;

  function commitLoaded<T>(resource: MediaResourceName, revision: number, value: T): MediaCommitResult {
    const current = state[resource] as MediaResourceState<T>;
    const result = load(current, revision, value);
    Object.assign(state, { [resource]: result.next });
    return result.result;
  }

  function commit(action: MediaRuntimeAction): MediaCommitResult {
    switch (action.type) {
      case "snapshot": {
        const parts = [
          commitLoaded("scan", action.snapshot.scan.revision, action.snapshot.scan.value),
          commitLoaded("imports", action.snapshot.imports.revision, action.snapshot.imports.value),
          commitLoaded("derivations", action.snapshot.derivations.revision, action.snapshot.derivations.value),
          commitLoaded("pipelines", action.snapshot.pipelines.revision, action.snapshot.pipelines.value),
          commitLoaded("library", action.snapshot.library.revision, action.snapshot.library.value),
        ];
        return {
          changed: parts.some((part) => part.changed),
          stale: parts.every((part) => part.stale),
        };
      }
      case "event":
        return commit(resourceAction(action.event));
      case "resource/loading": {
        const current = state[action.resource] as MediaResourceState<unknown>;
        const next = markLoading(current, action.retry, action.requestedAt);
        Object.assign(state, { [action.resource]: next });
        return valuesEqual(current, next) ? UNCHANGED : CHANGED;
      }
      case "resource/failed": {
        const current = state[action.resource] as MediaResourceState<unknown>;
        const result = fail(current, action.failure, action.requestRevision);
        Object.assign(state, { [action.resource]: result.next });
        return result.result;
      }
      case "scan/loaded":
        return commitLoaded("scan", action.revision, action.value);
      case "imports/loaded":
        return commitLoaded("imports", action.revision, action.value);
      case "derivations/loaded":
        return commitLoaded("derivations", action.revision, action.value);
      case "pipelines/loaded":
        return commitLoaded("pipelines", action.revision, action.value);
      case "library/loaded":
        return commitLoaded("library", action.revision, action.value);
      case "imports/upsert":
        return commitLoaded(
          "imports",
          action.revision,
          upsertById(state.imports.value ?? state.imports.lastGood, action.value),
        );
      case "derivations/upsert":
        return commitLoaded(
          "derivations",
          action.revision,
          upsertById(state.derivations.value ?? state.derivations.lastGood, action.value),
        );
      case "pipelines/upsert":
        return commitLoaded(
          "pipelines",
          action.revision,
          upsertById(state.pipelines.value ?? state.pipelines.lastGood, action.value),
        );
    }
  }

  return { getState: () => state, commit };
}
