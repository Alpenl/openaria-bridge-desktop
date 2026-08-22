// The single commit entry point.
//
// Snapshots, events, command outcomes and timer actions all arrive here as
// actions; nothing else writes application state. That is what makes the two
// ordering rules enforceable in one place:
//
//   * every backend-owned resource carries the revision of the data it holds,
//     and a value stamped with an older revision is dropped instead of painting
//     stale data over newer state;
//   * a failed refresh keeps the last good value, so a view degrades to "stale
//     but readable" rather than blanking.
//
// `commit` reports whether anything a view can see actually changed, so the
// callers keep the app's existing explicit-render style without repainting on
// every duplicate event.

import {
  clearConfirmations,
  confirmPhaseOf,
  createUiState,
  resetDeviceViewState,
  selectionFor,
  filterFor,
  retainExistingSelection,
  type FilterState,
  type SelectionScope,
  type ThemePreference,
  type UiState,
  type ViewName,
} from "../store";
import type { OperationId } from "./confirm";
import type {
  MediaAcquisitionSourceKind,
  MediaBatchSnapshot,
  MediaPolicyKey,
  MediaReleaseSnapshot,
} from "../ui/media/types";
import { visibleSnapshotsEqual } from "../ui/visibleSnapshot";
import type { BackendEvent, BackendSnapshot } from "./backend";
import type {
  Device,
  LibraryEntry,
  PairingResolutionPayload,
  RpcError,
  SessionView,
  StorageConfig,
  Transfer,
  TransferJobEvent,
} from "../types";

/** Per-resource state: what is in flight, what is shown, what failed, how old
 * it is, and the last value that was actually good. */
export interface Resource<T> {
  readonly loading: boolean;
  readonly value: T | null;
  readonly error: string | null;
  /** Structured backend error when the failure came from an RPC contract. */
  readonly rpcError: RpcError | null;
  readonly revision: number;
  readonly lastGood: T | null;
}

export function idleResource<T>(): Resource<T> {
  return { loading: false, value: null, error: null, rpcError: null, revision: -1, lastGood: null };
}

export type ResourceKey =
  | "devices"
  | "sessions"
  | "library"
  | "transfers"
  | "transferJobs"
  | "storage"
  /** Public retry naming for the storage configuration resource. */
  | "storageConfig";

/** Resources whose backend read can be retried independently after a
 * degraded startup or refresh. `storageConfig` is deliberately distinct from
 * transfer-job retry: it addresses the configuration resource itself. */
export type ResourceRetryTarget = "devices" | "library" | "transfers" | "storageConfig";

/** Alias kept short for controller/action call sites. */
export type RetryableResource = ResourceRetryTarget;

/** Only ever a placeholder: the first `get_storage_config` overwrites it. The
 * shipped defaults live in Rust's `StorageConfig::default()`. */
export const PLACEHOLDER_STORAGE: StorageConfig = {
  endpoint: "",
  bucket: "",
  prefix: "",
  urlStyle: "virtualHost",
  secretConfigured: false,
  downloadRoot: "",
  activeDownloadRoot: "",
};

export interface AppState {
  devices: Resource<Device[]>;
  /** Keyed by device ids that arrive from the LAN, so a `Map` rather than a
   * plain object (see `UiState.openRows` for the same reason). */
  sessions: Map<string, Resource<SessionView[]>>;
  library: Resource<LibraryEntry[]>;
  transfers: Resource<Transfer[]>;
  transferJobs: Resource<TransferJobEvent[]>;
  storage: Resource<StorageConfig>;
  ui: UiState;
}

export function createAppState(): AppState {
  return {
    devices: idleResource(),
    sessions: new Map(),
    library: idleResource(),
    transfers: idleResource(),
    transferJobs: idleResource(),
    storage: idleResource(),
    ui: createUiState(),
  };
}

export type Action =
  | { type: "backend/snapshot"; revision: number; snapshot: BackendSnapshot }
  | { type: "backend/event"; event: BackendEvent }
  | { type: "resource/loading"; resource: ResourceKey; deviceId?: string }
  | {
      type: "resource/failed";
      resource: ResourceKey;
      deviceId?: string;
      error: string;
      rpcError?: RpcError;
      /** Revision observed when an independent retry started. A failure with
       * an older request revision cannot degrade newer resource state. */
      revision?: number;
    }
  | { type: "devices/loaded"; revision: number; devices: Device[] }
  | { type: "sessions/loaded"; revision: number; deviceId: string; sessions: SessionView[] }
  | { type: "library/loaded"; revision: number; library: LibraryEntry[] }
  | { type: "transfers/loaded"; revision: number; transfers: Transfer[] }
  | { type: "transferJobs/loaded"; revision: number; jobs: TransferJobEvent[] }
  | { type: "storage/loaded"; revision: number; storage: StorageConfig }
  | { type: "ui/theme"; theme: ThemePreference }
  | { type: "ui/view"; view: ViewName }
  | { type: "ui/activateDevice"; deviceId: string | null }
  | { type: "ui/resetDeviceView" }
  | { type: "ui/pairingStarted"; deviceId: string }
  | { type: "ui/pairingAttempt"; deviceId: string; attemptId: string }
  | { type: "ui/pairingDeferred"; payload: PairingResolutionPayload }
  | { type: "ui/pairingClosed" }
  | { type: "ui/toggleRow"; key: string }
  | { type: "ui/select"; scope: SelectionScope; key: string; selected: boolean }
  | { type: "ui/selectMany"; scope: SelectionScope; keys: string[]; selected: boolean }
  | { type: "ui/clearSelection"; scope: SelectionScope }
  | { type: "ui/retainSelection"; scope: SelectionScope; existingKeys: string[] }
  | { type: "ui/filter"; scope: SelectionScope; patch: Partial<FilterState> }
  // Confirmation transitions. Each names the operation it means; the reducer
  // drops any whose id is not the one currently in that phase, so a stale
  // timer or a duplicated click can never disturb a newer operation.
  | { type: "ui/confirmArm"; target: string; operationId: OperationId; expiresAt: number }
  | { type: "ui/confirmRun"; target: string; operationId: OperationId }
  | { type: "ui/confirmExpire"; target: string; operationId: OperationId }
  | { type: "ui/confirmSettle"; target: string; operationId: OperationId }
  | { type: "ui/confirmClear"; prefix: string }
  | { type: "ui/notify"; enabled: boolean }
  | { type: "ui/trayCollapsed"; collapsed: boolean }
  | { type: "ui/mediaCandidateSelection"; candidateId: string; selected: boolean }
  | { type: "ui/mediaCandidateSelectionMany"; candidateIds: string[]; selected: boolean }
  | { type: "ui/mediaUnsignedApprovalArm"; candidateIds: readonly string[] }
  | { type: "ui/mediaUnsignedApprovalClear" }
  | { type: "ui/mediaCandidateExpanded"; candidateId: string }
  | { type: "ui/mediaPolicy"; policy: MediaPolicyKey; enabled: boolean }
  | {
      type: "ui/mediaSourcesRemembered";
      sources: readonly { id: string; kind: MediaAcquisitionSourceKind; path: string | null }[];
    }
  | { type: "ui/mediaReleaseOverride"; sourceId: string; release: MediaReleaseSnapshot | null }
  | { type: "ui/mediaBatchSet"; batch: MediaBatchSnapshot | null; pipelineIds: readonly string[] }
  | { type: "ui/mediaBatchClear"; batchId: string };

export interface CommitResult {
  /** Something a view can see is different now. */
  readonly changed: boolean;
  /** The action carried data older than what the resource already holds. */
  readonly stale: boolean;
}

const UNCHANGED: CommitResult = { changed: false, stale: false };
const CHANGED: CommitResult = { changed: true, stale: false };
const STALE: CommitResult = { changed: false, stale: true };

export interface AppStore {
  getState(): AppState;
  /** The only way to write state. */
  commit(action: Action): CommitResult;
}

function loadResource<T>(
  current: Resource<T>,
  revision: number,
  value: T,
): { next: Resource<T>; result: CommitResult } {
  if (revision < current.revision) return { next: current, result: STALE };
  const changed =
    !visibleSnapshotsEqual(current.value, value) ||
    current.loading ||
    current.error !== null ||
    current.rpcError !== null ||
    current.value === null;
  return {
    next: { loading: false, value, error: null, rpcError: null, revision, lastGood: value },
    result: { changed, stale: false },
  };
}

function failResource<T>(
  current: Resource<T>,
  error: string,
  revision?: number,
  rpcError: RpcError | null = null,
): { next: Resource<T>; result: CommitResult } {
  if (revision !== undefined && revision < current.revision) {
    return { next: current, result: STALE };
  }
  // Degrade to the last good value rather than blanking the view.
  const value = current.lastGood;
  const changed =
    current.error !== error ||
    !visibleSnapshotsEqual(current.rpcError, rpcError) ||
    current.loading ||
    !visibleSnapshotsEqual(current.value, value);
  return { next: { ...current, loading: false, error, rpcError, value }, result: { changed, stale: false } };
}

function markLoading<T>(current: Resource<T>): { next: Resource<T>; result: CommitResult } {
  if (current.loading) return { next: current, result: UNCHANGED };
  return { next: { ...current, loading: true, error: null, rpcError: null }, result: CHANGED };
}

function resourceField(resource: ResourceKey): Exclude<ResourceKey, "storageConfig"> {
  return resource === "storageConfig" ? "storage" : resource;
}

export function createAppStore(initial: AppState = createAppState()): AppStore {
  const state = initial;

  function sessionsResource(deviceId: string): Resource<SessionView[]> {
    return state.sessions.get(deviceId) ?? idleResource<SessionView[]>();
  }

  function commitSessions(deviceId: string, next: Resource<SessionView[]>): void {
    state.sessions.set(deviceId, next);
  }

  function commitLoaded(action: Action): CommitResult {
    switch (action.type) {
      case "devices/loaded": {
        const { next, result } = loadResource(state.devices, action.revision, action.devices);
        state.devices = next;
        return result;
      }
      case "sessions/loaded": {
        const { next, result } = loadResource(sessionsResource(action.deviceId), action.revision, action.sessions);
        commitSessions(action.deviceId, next);
        return result;
      }
      case "library/loaded": {
        const { next, result } = loadResource(state.library, action.revision, action.library);
        state.library = next;
        return result;
      }
      case "transfers/loaded": {
        const { next, result } = loadResource(state.transfers, action.revision, action.transfers);
        state.transfers = next;
        return result;
      }
      case "transferJobs/loaded": {
        const { next, result } = loadResource(state.transferJobs, action.revision, action.jobs);
        state.transferJobs = next;
        return result;
      }
      case "storage/loaded": {
        const { next, result } = loadResource(state.storage, action.revision, action.storage);
        state.storage = next;
        return result;
      }
      default:
        return UNCHANGED;
    }
  }

  /** Events are just revisioned resource values; normalising them here keeps
   * one ordering rule instead of one per channel. */
  function eventAction(event: BackendEvent): Action | null {
    switch (event.kind) {
      case "devices":
        return { type: "devices/loaded", revision: event.revision, devices: event.devices };
      case "sessions":
        return {
          type: "sessions/loaded",
          revision: event.revision,
          deviceId: event.deviceId,
          sessions: event.sessions,
        };
      case "library":
        return { type: "library/loaded", revision: event.revision, library: event.library };
      case "transfers":
        return { type: "transfers/loaded", revision: event.revision, transfers: event.transfers };
      case "storage":
        return { type: "storage/loaded", revision: event.revision, storage: event.storage };
      case "transferJobs":
        return { type: "transferJobs/loaded", revision: event.revision, jobs: event.jobs };
      // Pairing events drive an overlay, not a resource; the pairing guard
      // classifies them and the view commits the outcome as a `ui/*` action.
      case "pairingTick":
      case "pairingResolved":
        return null;
    }
  }

  function commitUi(action: Action): CommitResult {
    const ui = state.ui;
    switch (action.type) {
      case "ui/theme":
        if (ui.theme === action.theme) return UNCHANGED;
        ui.theme = action.theme;
        return CHANGED;
      case "ui/view":
        if (ui.view === action.view) return UNCHANGED;
        ui.view = action.view;
        return CHANGED;
      case "ui/activateDevice":
        if (ui.activeDeviceId === action.deviceId) return UNCHANGED;
        ui.activeDeviceId = action.deviceId;
        return CHANGED;
      case "ui/resetDeviceView":
        resetDeviceViewState(ui);
        return CHANGED;
      case "ui/pairingStarted":
        ui.pairingTargetId = action.deviceId;
        ui.pairingAttemptId = null;
        ui.pairingDeferred.clear();
        return CHANGED;
      case "ui/pairingAttempt":
        // A reply for a flow the user already left must not adopt the overlay.
        if (ui.pairingTargetId !== action.deviceId) return STALE;
        ui.pairingAttemptId = action.attemptId;
        return CHANGED;
      case "ui/pairingDeferred":
        ui.pairingDeferred.set(action.payload.attemptId, action.payload);
        return UNCHANGED;
      case "ui/pairingClosed":
        ui.pairingTargetId = null;
        ui.pairingAttemptId = null;
        ui.pairingDeferred.clear();
        return CHANGED;
      case "ui/toggleRow":
        if (ui.openRows.has(action.key)) ui.openRows.delete(action.key);
        else ui.openRows.add(action.key);
        return CHANGED;
      case "ui/select": {
        const selection = selectionFor(ui, action.scope);
        if (selection.has(action.key) === action.selected) return UNCHANGED;
        if (action.selected) selection.add(action.key);
        else selection.delete(action.key);
        return CHANGED;
      }
      case "ui/selectMany": {
        const selection = selectionFor(ui, action.scope);
        for (const key of action.keys) {
          if (action.selected) selection.add(key);
          else selection.delete(key);
        }
        return CHANGED;
      }
      case "ui/clearSelection": {
        const selection = selectionFor(ui, action.scope);
        if (selection.size === 0) return UNCHANGED;
        selection.clear();
        return CHANGED;
      }
      case "ui/retainSelection": {
        const selection = selectionFor(ui, action.scope);
        const before = selection.size;
        retainExistingSelection(selection, action.existingKeys);
        return before === selection.size ? UNCHANGED : CHANGED;
      }
      case "ui/filter":
        Object.assign(filterFor(ui, action.scope), action.patch);
        return CHANGED;
      case "ui/confirmArm": {
        // An operation that is already executing can never re-enter confirming.
        if (confirmPhaseOf(ui, action.target).phase === "running") return UNCHANGED;
        ui.confirmations.set(action.target, {
          phase: "confirming",
          operationId: action.operationId,
          expiresAt: action.expiresAt,
        });
        return CHANGED;
      }
      case "ui/confirmRun": {
        const phase = confirmPhaseOf(ui, action.target);
        if (phase.phase !== "confirming" || phase.operationId !== action.operationId) return UNCHANGED;
        ui.confirmations.set(action.target, { phase: "running", operationId: action.operationId });
        return CHANGED;
      }
      case "ui/confirmExpire": {
        const phase = confirmPhaseOf(ui, action.target);
        // Only the confirmation this timer was armed for may be disarmed.
        if (phase.phase !== "confirming" || phase.operationId !== action.operationId) return UNCHANGED;
        ui.confirmations.delete(action.target);
        return CHANGED;
      }
      case "ui/confirmSettle": {
        const phase = confirmPhaseOf(ui, action.target);
        if (phase.phase !== "running" || phase.operationId !== action.operationId) return UNCHANGED;
        ui.confirmations.delete(action.target);
        return CHANGED;
      }
      case "ui/confirmClear":
        return clearConfirmations(ui, action.prefix) ? CHANGED : UNCHANGED;
      case "ui/notify":
        if (ui.notifyEnabled === action.enabled) return UNCHANGED;
        ui.notifyEnabled = action.enabled;
        return CHANGED;
      case "ui/trayCollapsed":
        if (ui.transferTrayCollapsed === action.collapsed) return UNCHANGED;
        ui.transferTrayCollapsed = action.collapsed;
        return CHANGED;
      case "ui/mediaCandidateSelection": {
        if (ui.mediaSelectedCandidateIds.has(action.candidateId) === action.selected) return UNCHANGED;
        if (action.selected) ui.mediaSelectedCandidateIds.add(action.candidateId);
        else ui.mediaSelectedCandidateIds.delete(action.candidateId);
        ui.mediaUnsignedApprovalCandidateIds.clear();
        return CHANGED;
      }
      case "ui/mediaCandidateSelectionMany": {
        let changed = false;
        for (const candidateId of action.candidateIds) {
          const has = ui.mediaSelectedCandidateIds.has(candidateId);
          if (has === action.selected) continue;
          changed = true;
          if (action.selected) ui.mediaSelectedCandidateIds.add(candidateId);
          else ui.mediaSelectedCandidateIds.delete(candidateId);
        }
        if (changed) ui.mediaUnsignedApprovalCandidateIds.clear();
        return changed ? CHANGED : UNCHANGED;
      }
      case "ui/mediaUnsignedApprovalArm": {
        const next = new Set(action.candidateIds);
        if (
          next.size === ui.mediaUnsignedApprovalCandidateIds.size &&
          [...next].every((candidateId) => ui.mediaUnsignedApprovalCandidateIds.has(candidateId))
        ) {
          return UNCHANGED;
        }
        ui.mediaUnsignedApprovalCandidateIds = next;
        return CHANGED;
      }
      case "ui/mediaUnsignedApprovalClear":
        if (ui.mediaUnsignedApprovalCandidateIds.size === 0) return UNCHANGED;
        ui.mediaUnsignedApprovalCandidateIds.clear();
        return CHANGED;
      case "ui/mediaCandidateExpanded":
        if (ui.mediaExpandedCandidateIds.has(action.candidateId))
          ui.mediaExpandedCandidateIds.delete(action.candidateId);
        else ui.mediaExpandedCandidateIds.add(action.candidateId);
        return CHANGED;
      case "ui/mediaPolicy": {
        const current = ui.mediaPolicy[action.policy];
        if (current.enabled === action.enabled) return UNCHANGED;
        ui.mediaPolicy = {
          ...ui.mediaPolicy,
          [action.policy]: { ...current, enabled: action.enabled },
        };
        return CHANGED;
      }
      case "ui/mediaSourcesRemembered": {
        let changed = false;
        for (const source of action.sources) {
          if (ui.mediaSourceKindById.get(source.id) !== source.kind) {
            ui.mediaSourceKindById.set(source.id, source.kind);
            changed = true;
          }
          if (source.path !== null && ui.mediaSourcePathById.get(source.id) !== source.path) {
            ui.mediaSourcePathById.set(source.id, source.path);
            changed = true;
          }
        }
        return changed ? CHANGED : UNCHANGED;
      }
      case "ui/mediaReleaseOverride":
        if (action.release === null) {
          if (!ui.mediaReleaseOverrideBySourceId.has(action.sourceId)) return UNCHANGED;
          ui.mediaReleaseOverrideBySourceId.delete(action.sourceId);
          return CHANGED;
        }
        if (ui.mediaReleaseOverrideBySourceId.get(action.sourceId) === action.release) return UNCHANGED;
        ui.mediaReleaseOverrideBySourceId.set(action.sourceId, action.release);
        return CHANGED;
      case "ui/mediaBatchSet":
        ui.mediaBatch = action.batch;
        ui.mediaBatchPipelineIds = new Set(action.pipelineIds);
        return CHANGED;
      case "ui/mediaBatchClear":
        if (ui.mediaBatch?.id !== action.batchId) return UNCHANGED;
        ui.mediaBatch = null;
        ui.mediaBatchPipelineIds.clear();
        return CHANGED;
      default:
        return UNCHANGED;
    }
  }

  function commit(action: Action): CommitResult {
    switch (action.type) {
      case "backend/snapshot": {
        const revisions = action.snapshot.revisions;
        const parts: CommitResult[] = [
          commitLoaded({ type: "devices/loaded", revision: revisions.devices, devices: action.snapshot.devices }),
          commitLoaded({ type: "library/loaded", revision: revisions.library, library: action.snapshot.library }),
          commitLoaded({
            type: "transfers/loaded",
            revision: revisions.transfers,
            transfers: action.snapshot.transfers,
          }),
          commitLoaded({ type: "storage/loaded", revision: revisions.storage, storage: action.snapshot.storage }),
        ];
        return {
          changed: parts.some((part) => part.changed),
          stale: parts.every((part) => part.stale),
        };
      }
      case "backend/event": {
        const normalized = eventAction(action.event);
        return normalized === null ? UNCHANGED : commit(normalized);
      }
      case "resource/loading": {
        if (action.resource === "sessions") {
          const deviceId = action.deviceId ?? "";
          const { next, result } = markLoading(sessionsResource(deviceId));
          commitSessions(deviceId, next);
          return result;
        }
        // Every non-session resource is a plain field on the state object;
        // only the flags change here, so the value type is irrelevant.
        const field = resourceField(action.resource);
        const { next, result } = markLoading(state[field] as Resource<unknown>);
        Object.assign(state, { [field]: next });
        return result;
      }
      case "resource/failed": {
        if (action.resource === "sessions") {
          const deviceId = action.deviceId ?? "";
          const { next, result } = failResource(
            sessionsResource(deviceId),
            action.error,
            action.revision,
            action.rpcError ?? null,
          );
          commitSessions(deviceId, next);
          return result;
        }
        const field = resourceField(action.resource);
        const { next, result } = failResource(
          state[field] as Resource<unknown>,
          action.error,
          action.revision,
          action.rpcError ?? null,
        );
        Object.assign(state, { [field]: next });
        return result;
      }
      case "devices/loaded":
      case "sessions/loaded":
      case "library/loaded":
      case "transfers/loaded":
      case "transferJobs/loaded":
      case "storage/loaded":
        return commitLoaded(action);
      default:
        return commitUi(action);
    }
  }

  return {
    getState: () => state,
    commit,
  };
}

/* ---------------------------------------------------------------------- */
/* selectors                                                              */
/* ---------------------------------------------------------------------- */

export function devicesOf(state: AppState): Device[] {
  return state.devices.value ?? [];
}

export function deviceById(state: AppState, deviceId: string | null): Device | undefined {
  if (deviceId === null) return undefined;
  return devicesOf(state).find((device) => device.id === deviceId);
}

/** Human-facing device projection for a canonical identity. Callers must keep
 * the canonical id for lookups and operation keys; this selector is only for
 * user-visible labels. */
export function deviceDisplayIdOf(state: AppState, deviceId: string | null): string | undefined {
  return deviceById(state, deviceId)?.displayId;
}

export function sessionsResourceOf(state: AppState, deviceId: string): Resource<SessionView[]> {
  return state.sessions.get(deviceId) ?? idleResource<SessionView[]>();
}

/** `undefined` means the device never reported sessions — a real distinction
 * from "reported an empty list", which the device pane renders differently. */
export function sessionsOf(state: AppState, deviceId: string | null): SessionView[] | undefined {
  if (deviceId === null) return undefined;
  return state.sessions.get(deviceId)?.value ?? undefined;
}

export function libraryOf(state: AppState): LibraryEntry[] {
  return state.library.value ?? [];
}

export function transfersOf(state: AppState): Transfer[] {
  return state.transfers.value ?? [];
}

export function transferJobsOf(state: AppState): TransferJobEvent[] {
  return state.transferJobs.value ?? [];
}

export function storageOf(state: AppState): StorageConfig {
  return state.storage.value ?? PLACEHOLDER_STORAGE;
}
