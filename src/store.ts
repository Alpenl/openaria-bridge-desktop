// The frontend's UI-only state shape and the key helpers that keep it honest.
//
// There is deliberately no exported mutable singleton any more: every write
// goes through `runtime/reducer.ts`'s single commit entry point, which owns an
// `AppState` containing exactly one `UiState` created here. What stays in this
// module is the shape, its fresh-value factories and the pure helpers
// (row keys, selection intersection) that both the reducer and the views use.

import { IDLE_PHASE, type ConfirmPhase } from "./runtime/confirm";
import { defaultMediaWorkflowPolicy } from "./ui/media/types";
import type {
  MediaAcquisitionSourceKind,
  MediaBatchSnapshot,
  MediaReleaseSnapshot,
  MediaWorkflowPolicy,
} from "./ui/media/types";
import type { PairingResolutionPayload } from "./types";

export interface FilterState {
  query: string;
  status: "all" | "pending" | "done";
  sortDesc: boolean;
}

export function freshFilter(): FilterState {
  return { query: "", status: "all", sortDesc: true };
}

export type ThemePreference = "dark" | "light" | "system";
export type ViewName = "device" | "library" | "media";
export type SelectionScope = "device" | "library";

export interface UiState {
  theme: ThemePreference;
  view: ViewName;
  activeDeviceId: string | null;
  pairingTargetId: string | null;
  /** Attempt id returned by `connect_device` for `pairingTargetId`'s live
   * pairing flow; `null` until that call replies. Pairing events are matched
   * against it so a superseded attempt cannot drive the overlay. */
  pairingAttemptId: string | null;
  /** Resolutions that arrived before `connect_device` told us which attempt
   * they belong to, keyed by attempt id. A very fast Pi can resolve an attempt
   * before the command's own reply reaches the WebView. */
  pairingDeferred: Map<string, PairingResolutionPayload>;
  notifyEnabled: boolean;
  transferTrayCollapsed: boolean;

  /** Row keys built by `deviceRowKey`/`libraryRowKey` — never raw ids, and
   * never plain-object keys: `{}` would resolve `__proto__`/`constructor`/
   * `toString` against `Object.prototype` and report rows nobody opened. */
  openRows: Set<string>;

  /** Every destructive control's confirmation/execution phase, keyed by the
   * targets in `runtime/confirm.ts`. One machine replaced the per-control
   * booleans and the row-level `deletingRows` set. */
  confirmations: Map<string, ConfirmPhase>;

  deviceFilter: FilterState;
  libraryFilter: FilterState;
  deviceSelection: Set<string>;
  librarySelection: Set<string>;

  /** Media workspace state is UI-only; durable scans and jobs remain in the
   * media runtime store and are projected at paint time. */
  mediaSelectedCandidateIds: Set<string>;
  /** Exact candidate selection awaiting a second, explicit unsigned-source
   * approval click. Any selection or mounted-card scan change clears it. */
  mediaUnsignedApprovalCandidateIds: Set<string>;
  mediaExpandedCandidateIds: Set<string>;
  mediaPolicy: MediaWorkflowPolicy;
  mediaSourceKindById: Map<string, MediaAcquisitionSourceKind>;
  mediaSourcePathById: Map<string, string>;
  mediaReleaseOverrideBySourceId: Map<string, MediaReleaseSnapshot>;
  mediaBatch: MediaBatchSnapshot | null;
  mediaBatchPipelineIds: Set<string>;
}

export function createUiState(): UiState {
  return {
    theme: "system",
    view: "device",
    activeDeviceId: null,
    pairingTargetId: null,
    pairingAttemptId: null,
    pairingDeferred: new Map(),
    notifyEnabled: false,
    transferTrayCollapsed: false,
    openRows: new Set(),
    confirmations: new Map(),
    deviceFilter: freshFilter(),
    libraryFilter: freshFilter(),
    deviceSelection: new Set(),
    librarySelection: new Set(),
    mediaSelectedCandidateIds: new Set(),
    mediaUnsignedApprovalCandidateIds: new Set(),
    mediaExpandedCandidateIds: new Set(),
    mediaPolicy: defaultMediaWorkflowPolicy(),
    mediaSourceKindById: new Map(),
    mediaSourcePathById: new Map(),
    mediaReleaseOverrideBySourceId: new Map(),
    mediaBatch: null,
    mediaBatchPipelineIds: new Set(),
  };
}

/** Clears in place: callers may hold the selection set. */
export function resetDeviceViewState(ui: UiState): void {
  ui.deviceSelection.clear();
  clearConfirmations(ui, "device:");
}

/** The phase of one destructive control. Absent means nothing is pending. */
export function confirmPhaseOf(ui: UiState, target: string): ConfirmPhase {
  return ui.confirmations.get(target) ?? IDLE_PHASE;
}

/** Drops armed confirmations under `prefix`. An operation that is already
 * running is left alone — it is in flight and settles itself. */
export function clearConfirmations(ui: UiState, prefix: string): boolean {
  let changed = false;
  for (const [target, phase] of [...ui.confirmations]) {
    if (!target.startsWith(prefix) || phase.phase === "running") continue;
    ui.confirmations.delete(target);
    changed = true;
  }
  return changed;
}

export function selectionFor(ui: UiState, scope: SelectionScope): Set<string> {
  return scope === "device" ? ui.deviceSelection : ui.librarySelection;
}

export function filterFor(ui: UiState, scope: SelectionScope): FilterState {
  return scope === "device" ? ui.deviceFilter : ui.libraryFilter;
}

/** Ids come from devices we do not control, so segments are escaped: without
 * it a device called `a|b` and a session called `c` would produce the same row
 * key as device `a` with session `b|c`. */
function encodeKeySegment(value: string): string {
  return encodeURIComponent(value);
}

/** Device rows are scoped by device: the same session id on two devices is two
 * different rows and must not share expanded/confirming state. */
export function deviceRowKey(deviceId: string, sessionId: string): string {
  return `device:${encodeKeySegment(deviceId)}:${encodeKeySegment(sessionId)}`;
}

export function libraryRowKey(entryKey: string): string {
  return `library:${encodeKeySegment(entryKey)}`;
}

/** Drops every selected key whose entity no longer exists, then returns the
 * survivors in the order the entities are listed. A selection made before a
 * refresh must never send a gone session/entry to a mutating command. */
export function retainExistingSelection(selection: Set<string>, existingKeys: Iterable<string>): string[] {
  const existing = new Set(existingKeys);
  for (const key of [...selection]) {
    if (!existing.has(key)) selection.delete(key);
  }
  return [...existing].filter((key) => selection.has(key));
}
