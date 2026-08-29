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
import { sessionHasUsableVerification } from "../types";
import type {
  Device,
  LibraryEntry,
  PairingResolutionPayload,
  RpcError,
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

const UNAVAILABLE_CAPABILITY = { supported: false, source: "unavailable" } as const;

/** Missing/legacy capability metadata is deliberately non-authoritative. */
export const UNAVAILABLE_SESSION_CAPABILITIES: SessionCapabilities = {
  profile: "unknown",
  sessionDeletion: UNAVAILABLE_CAPABILITY,
  sessionDetail: UNAVAILABLE_CAPABILITY,
  artifactDownload: UNAVAILABLE_CAPABILITY,
  captureStatus: UNAVAILABLE_CAPABILITY,
};

export interface SessionDetailState {
  readonly loading: boolean;
  readonly error: string | null;
  readonly sessionRevision: string;
  readonly catalogRevision: string | null;
  readonly manifestSha256: string;
}

export interface SessionCatalogState {
  readonly catalogRevision: string | null;
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly catalogAuthority: SessionCatalogAuthority;
  readonly paginationSupported: boolean;
  readonly paginationUnavailableReason: SessionPaginationUnavailableReason | null;
  readonly capabilities: SessionCapabilities;
  readonly diagnostics: readonly SessionCatalogDiagnostic[];
  readonly loadingMore: boolean;
  readonly loadMoreError: string | null;
  readonly details: ReadonlyMap<string, SessionDetailState>;
}

function idleSessionCatalog(): SessionCatalogState {
  return {
    catalogRevision: null,
    nextCursor: null,
    hasMore: false,
    catalogAuthority: "unavailable",
    paginationSupported: false,
    paginationUnavailableReason: "catalogRevisionUnavailable",
    capabilities: UNAVAILABLE_SESSION_CAPABILITIES,
    diagnostics: [],
    loadingMore: false,
    loadMoreError: null,
    details: new Map(),
  };
}

export interface AppState {
  devices: Resource<Device[]>;
  /** Keyed by device ids that arrive from the LAN, so a `Map` rather than a
   * plain object (see `UiState.openRows` for the same reason). */
  sessions: Map<string, Resource<SessionView[]>>;
  /** Pagination/capability/detail state is separate so existing list
   * selectors keep returning plain session rows. */
  sessionCatalogs: Map<string, SessionCatalogState>;
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
    sessionCatalogs: new Map(),
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
  | {
      type: "sessions/catalogLoaded";
      revision: number;
      deviceId: string;
      sessions: SessionView[];
      catalogRevision: string | null;
      nextCursor: string | null;
      hasMore: boolean;
      catalogAuthority: SessionCatalogAuthority;
      paginationSupported: boolean;
      paginationUnavailableReason: SessionPaginationUnavailableReason | null;
      capabilities: SessionCapabilities;
      diagnostics: SessionCatalogDiagnostic[];
    }
  | {
      type: "sessions/pageLoaded";
      revision: number;
      deviceId: string;
      page: SessionPageView;
      mode: "replace" | "append";
      expectedCatalogRevision?: string;
    }
  | { type: "sessions/loadMoreStarted"; deviceId: string; catalogRevision: string; cursor: string }
  | { type: "sessions/loadMoreFailed"; deviceId: string; catalogRevision: string; cursor: string; error: string }
  | { type: "sessions/catalogInvalidated"; deviceId: string; catalogRevision: string; cursor: string }
  | {
      type: "sessions/detailStarted";
      deviceId: string;
      sessionId: string;
      sessionRevision: string;
      catalogRevision: string | null;
      manifestSha256: string;
    }
  | {
      type: "sessions/detailFailed";
      deviceId: string;
      sessionId: string;
      sessionRevision: string;
      catalogRevision: string | null;
      manifestSha256: string;
      error: string;
    }
  | {
      type: "sessions/detailLoaded";
      revision: number;
      deviceId: string;
      detail: SessionView;
      sessionRevision: string;
      catalogRevision: string | null;
      manifestSha256: string;
    }
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

function usableManifestSha256(session: SessionView): string | null {
  return sessionHasUsableVerification(session) ? session.verification!.manifestSha256 : null;
}

function canRetainFetchedDetail(current: SessionView, candidate: SessionView): boolean {
  const currentManifest = usableManifestSha256(current);
  const candidateManifest = usableManifestSha256(candidate);
  return (
    current.revision === candidate.revision &&
    candidate.files.length === 0 &&
    current.files.length > 0 &&
    currentManifest !== null &&
    currentManifest === candidateManifest
  );
}

function mergeCatalogDiagnostics(
  existing: readonly SessionCatalogDiagnostic[],
  incoming: readonly SessionCatalogDiagnostic[],
): SessionCatalogDiagnostic[] | null {
  const merged = [...existing];
  const positions = new Map(merged.map((diagnostic, index) => [diagnostic.quarantineId, index]));
  for (const diagnostic of incoming) {
    const position = positions.get(diagnostic.quarantineId);
    if (position === undefined) {
      positions.set(diagnostic.quarantineId, merged.length);
      merged.push(diagnostic);
    } else {
      return null;
    }
  }
  return merged;
}

function hasDuplicateSessionIdentity(sessions: readonly SessionView[]): boolean {
  const seen = new Set<string>();
  for (const session of sessions) {
    if (seen.has(session.id)) return true;
    seen.add(session.id);
  }
  return false;
}

function hasDuplicateDiagnosticIdentity(diagnostics: readonly SessionCatalogDiagnostic[]): boolean {
  const seen = new Set<string>();
  for (const diagnostic of diagnostics) {
    if (seen.has(diagnostic.quarantineId)) return true;
    seen.add(diagnostic.quarantineId);
  }
  return false;
}

function sameCatalogMetadata(current: SessionCatalogState, page: SessionPageView): boolean {
  return (
    current.catalogRevision === page.catalogRevision &&
    current.nextCursor === page.nextCursor &&
    current.hasMore === page.hasMore &&
    current.catalogAuthority === page.catalogAuthority &&
    current.paginationSupported === page.paginationSupported &&
    current.paginationUnavailableReason === page.paginationUnavailableReason &&
    visibleSnapshotsEqual(current.capabilities, page.capabilities)
  );
}

function sameCatalogEventSnapshot(
  current: Resource<SessionView[]>,
  catalog: SessionCatalogState,
  action: Extract<Action, { type: "sessions/catalogLoaded" }>,
): boolean {
  return (
    visibleSnapshotsEqual(current.value ?? [], action.sessions) &&
    catalog.catalogRevision === action.catalogRevision &&
    catalog.nextCursor === action.nextCursor &&
    catalog.hasMore === action.hasMore &&
    catalog.catalogAuthority === action.catalogAuthority &&
    catalog.paginationSupported === action.paginationSupported &&
    catalog.paginationUnavailableReason === action.paginationUnavailableReason &&
    visibleSnapshotsEqual(catalog.capabilities, action.capabilities) &&
    visibleSnapshotsEqual(catalog.diagnostics, action.diagnostics)
  );
}

function pageIsCurrentSnapshotSuffix<T>(current: readonly T[], incoming: readonly T[]): boolean {
  if (incoming.length > current.length) return false;
  const offset = current.length - incoming.length;
  return visibleSnapshotsEqual(current.slice(offset), incoming);
}

function mergeSessionViews(existing: readonly SessionView[], incoming: readonly SessionView[]): SessionView[] {
  const merged = [...existing];
  const positions = new Map(merged.map((session, index) => [session.id, index]));
  for (const candidate of incoming) {
    const position = positions.get(candidate.id);
    if (position === undefined) {
      positions.set(candidate.id, merged.length);
      merged.push(candidate);
      continue;
    }
    const current = merged[position];
    merged[position] = canRetainFetchedDetail(current, candidate) ? { ...candidate, files: current.files } : candidate;
  }
  return merged;
}

function repeatsSessionIdentity(existing: readonly SessionView[], incoming: readonly SessionView[]): boolean {
  const seen = new Set(existing.map((session) => session.id));
  for (const session of incoming) {
    if (seen.has(session.id)) return true;
    seen.add(session.id);
  }
  return false;
}

function preservesAppendNewestFirstBoundary(
  existing: readonly SessionView[],
  incoming: readonly SessionView[],
): boolean {
  const previous = existing[existing.length - 1];
  const next = incoming[0];
  if (previous === undefined || next === undefined) return true;
  const previousStartedAt = Date.parse(previous.dateLabel);
  const nextStartedAt = Date.parse(next.dateLabel);
  if (!Number.isFinite(previousStartedAt) || !Number.isFinite(nextStartedAt)) return false;
  return previousStartedAt > nextStartedAt || (previousStartedAt === nextStartedAt && previous.id > next.id);
}

/** Replace with the authoritative complete snapshot while retaining an
 * already-fetched detail only for the exact same session revision. */
function replaceSessionViews(existing: readonly SessionView[], incoming: readonly SessionView[]): SessionView[] {
  const previous = new Map(existing.map((session) => [session.id, session]));
  return incoming.map((candidate) => {
    const current = previous.get(candidate.id);
    return current !== undefined && canRetainFetchedDetail(current, candidate)
      ? { ...candidate, files: current.files }
      : candidate;
  });
}

function retainMatchingDetailStates(
  details: ReadonlyMap<string, SessionDetailState>,
  sessions: readonly SessionView[],
  catalogRevision: string | null,
): ReadonlyMap<string, SessionDetailState> {
  if (catalogRevision === null) return new Map();
  const retained = new Map<string, SessionDetailState>();
  for (const session of sessions) {
    const detail = details.get(session.id);
    const manifestSha256 = usableManifestSha256(session);
    if (
      detail !== undefined &&
      manifestSha256 !== null &&
      detail.catalogRevision === catalogRevision &&
      detail.sessionRevision === session.revision &&
      detail.manifestSha256 === manifestSha256
    ) {
      retained.set(session.id, detail);
    }
  }
  return retained;
}

export function createAppStore(initial: AppState = createAppState()): AppStore {
  const state = initial;

  function sessionsResource(deviceId: string): Resource<SessionView[]> {
    return state.sessions.get(deviceId) ?? idleResource<SessionView[]>();
  }

  function commitSessions(deviceId: string, next: Resource<SessionView[]>): void {
    state.sessions.set(deviceId, next);
  }

  function sessionCatalog(deviceId: string): SessionCatalogState {
    return state.sessionCatalogs.get(deviceId) ?? idleSessionCatalog();
  }

  function commitSessionCatalog(deviceId: string, next: SessionCatalogState): void {
    state.sessionCatalogs.set(deviceId, next);
  }

  function commitCatalogSnapshot(action: Extract<Action, { type: "sessions/catalogLoaded" }>): CommitResult {
    const current = sessionsResource(action.deviceId);
    if (action.revision < current.revision) return STALE;
    const currentCatalog = sessionCatalog(action.deviceId);
    if (hasDuplicateSessionIdentity(action.sessions) || hasDuplicateDiagnosticIdentity(action.diagnostics)) {
      return STALE;
    }
    if (action.revision === current.revision) {
      return sameCatalogEventSnapshot(current, currentCatalog, action) ? UNCHANGED : STALE;
    }
    const sessions =
      action.catalogRevision === null
        ? [...action.sessions]
        : replaceSessionViews(current.value ?? [], action.sessions);
    const details = retainMatchingDetailStates(currentCatalog.details, sessions, action.catalogRevision);
    commitSessions(action.deviceId, {
      loading: false,
      value: sessions,
      error: null,
      rpcError: null,
      revision: action.revision,
      lastGood: sessions,
    });
    commitSessionCatalog(action.deviceId, {
      catalogRevision: action.catalogRevision,
      nextCursor: action.nextCursor,
      hasMore: action.hasMore,
      catalogAuthority: action.catalogAuthority,
      paginationSupported: action.paginationSupported,
      paginationUnavailableReason: action.paginationUnavailableReason,
      capabilities: action.capabilities,
      diagnostics: action.diagnostics,
      loadingMore: false,
      loadMoreError: null,
      details,
    });
    return CHANGED;
  }

  function commitSessionPage(action: Extract<Action, { type: "sessions/pageLoaded" }>): CommitResult {
    const current = sessionsResource(action.deviceId);
    if (action.revision < current.revision) return STALE;
    const catalog = sessionCatalog(action.deviceId);
    if (
      action.mode === "append" &&
      (action.expectedCatalogRevision === undefined || catalog.catalogRevision !== action.expectedCatalogRevision)
    ) {
      return STALE;
    }
    if (action.mode === "append" && action.page.catalogRevision !== action.expectedCatalogRevision) return STALE;
    if (hasDuplicateSessionIdentity(action.page.items) || hasDuplicateDiagnosticIdentity(action.page.diagnostics)) {
      return STALE;
    }

    // The backend publishes the accumulated event before resolving the RPC.
    // A same-revision reply must merge with that event rather than shrinking
    // it back to the page carried by the command response.
    const sameResourcePublication = action.revision === current.revision;
    if (sameResourcePublication) {
      if (!sameCatalogMetadata(catalog, action.page)) return STALE;
      const currentSessions = current.value ?? [];
      const exactSnapshot = visibleSnapshotsEqual(currentSessions, action.page.items);
      const suffixSnapshot = pageIsCurrentSnapshotSuffix(currentSessions, action.page.items);
      const diagnosticsSuffix = pageIsCurrentSnapshotSuffix(catalog.diagnostics, action.page.diagnostics);
      if ((exactSnapshot || suffixSnapshot) && diagnosticsSuffix) return UNCHANGED;
      return STALE;
    }
    if (action.mode === "append" && repeatsSessionIdentity(current.value ?? [], action.page.items)) return STALE;
    if (action.mode === "append" && !preservesAppendNewestFirstBoundary(current.value ?? [], action.page.items)) {
      return STALE;
    }
    const sessions =
      action.mode === "append" ? mergeSessionViews(current.value ?? [], action.page.items) : action.page.items;
    const diagnostics =
      action.mode === "append"
        ? mergeCatalogDiagnostics(catalog.diagnostics, action.page.diagnostics)
        : action.page.diagnostics;
    if (diagnostics === null) return STALE;
    const details = retainMatchingDetailStates(catalog.details, sessions, action.page.catalogRevision);
    commitSessions(action.deviceId, {
      loading: false,
      value: sessions,
      error: null,
      rpcError: null,
      revision: action.revision,
      lastGood: sessions,
    });
    commitSessionCatalog(action.deviceId, {
      catalogRevision: action.page.catalogRevision,
      nextCursor: action.page.nextCursor,
      hasMore: action.page.hasMore,
      catalogAuthority: action.page.catalogAuthority,
      paginationSupported: action.page.paginationSupported,
      paginationUnavailableReason: action.page.paginationUnavailableReason,
      capabilities: action.page.capabilities,
      diagnostics,
      loadingMore: false,
      loadMoreError: null,
      details,
    });
    return CHANGED;
  }

  function sessionMatches(
    deviceId: string,
    sessionId: string,
    sessionRevision: string,
    catalogRevision: string | null,
    manifestSha256: string,
  ): boolean {
    return (
      sessionCatalog(deviceId).catalogRevision === catalogRevision &&
      (sessionsResource(deviceId).value ?? []).some(
        (session) =>
          session.id === sessionId &&
          session.revision === sessionRevision &&
          usableManifestSha256(session) === manifestSha256,
      )
    );
  }

  function commitDetailLoaded(action: Extract<Action, { type: "sessions/detailLoaded" }>): CommitResult {
    const current = sessionsResource(action.deviceId);
    if (
      action.revision < current.revision ||
      action.detail.id === "" ||
      action.detail.revision !== action.sessionRevision ||
      usableManifestSha256(action.detail) !== action.manifestSha256 ||
      !sessionMatches(
        action.deviceId,
        action.detail.id,
        action.sessionRevision,
        action.catalogRevision,
        action.manifestSha256,
      )
    ) {
      return STALE;
    }
    const sessions = (current.value ?? []).map((session) =>
      session.id === action.detail.id ? action.detail : session,
    );
    const catalog = sessionCatalog(action.deviceId);
    const details = new Map(catalog.details);
    details.set(action.detail.id, {
      loading: false,
      error: null,
      sessionRevision: action.sessionRevision,
      catalogRevision: action.catalogRevision,
      manifestSha256: action.manifestSha256,
    });
    commitSessions(action.deviceId, {
      loading: false,
      value: sessions,
      error: current.error,
      rpcError: current.rpcError,
      revision: Math.max(current.revision, action.revision),
      lastGood: sessions,
    });
    commitSessionCatalog(action.deviceId, { ...catalog, details });
    return CHANGED;
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
      case "sessions/catalogLoaded":
        return commitCatalogSnapshot(action);
      case "sessions/pageLoaded":
        return commitSessionPage(action);
      case "sessions/detailLoaded":
        return commitDetailLoaded(action);
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
      case "sessions": {
        const hasExplicitPagination =
          event.catalogAuthority !== undefined &&
          event.paginationSupported !== undefined &&
          event.paginationUnavailableReason !== undefined;
        return {
          type: "sessions/catalogLoaded",
          revision: event.revision,
          deviceId: event.deviceId,
          sessions: event.sessions,
          catalogRevision: event.catalogRevision ?? null,
          nextCursor: hasExplicitPagination ? (event.nextCursor ?? null) : null,
          hasMore: hasExplicitPagination ? (event.hasMore ?? false) : false,
          catalogAuthority: hasExplicitPagination ? event.catalogAuthority! : "unavailable",
          paginationSupported: hasExplicitPagination ? event.paginationSupported! : false,
          paginationUnavailableReason: hasExplicitPagination
            ? event.paginationUnavailableReason!
            : "catalogRevisionUnavailable",
          capabilities: event.capabilities ?? UNAVAILABLE_SESSION_CAPABILITIES,
          diagnostics: event.diagnostics ?? [],
        };
      }
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
          const catalog = sessionCatalog(deviceId);
          commitSessionCatalog(deviceId, {
            ...catalog,
            loadingMore: false,
            loadMoreError: null,
            details: new Map(),
          });
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
      case "sessions/loadMoreStarted": {
        const catalog = sessionCatalog(action.deviceId);
        if (
          catalog.catalogRevision !== action.catalogRevision ||
          catalog.nextCursor !== action.cursor ||
          !catalog.hasMore ||
          !catalog.paginationSupported
        ) {
          return STALE;
        }
        if (catalog.loadingMore && catalog.loadMoreError === null) return UNCHANGED;
        commitSessionCatalog(action.deviceId, { ...catalog, loadingMore: true, loadMoreError: null });
        return CHANGED;
      }
      case "sessions/loadMoreFailed": {
        const catalog = sessionCatalog(action.deviceId);
        if (catalog.catalogRevision !== action.catalogRevision || catalog.nextCursor !== action.cursor) return STALE;
        commitSessionCatalog(action.deviceId, { ...catalog, loadingMore: false, loadMoreError: action.error });
        return CHANGED;
      }
      case "sessions/catalogInvalidated": {
        const catalog = sessionCatalog(action.deviceId);
        if (catalog.catalogRevision !== action.catalogRevision || catalog.nextCursor !== action.cursor) return STALE;
        commitSessionCatalog(action.deviceId, idleSessionCatalog());
        return CHANGED;
      }
      case "sessions/detailStarted": {
        if (
          !sessionMatches(
            action.deviceId,
            action.sessionId,
            action.sessionRevision,
            action.catalogRevision,
            action.manifestSha256,
          )
        ) {
          return STALE;
        }
        const catalog = sessionCatalog(action.deviceId);
        const details = new Map(catalog.details);
        details.set(action.sessionId, {
          loading: true,
          error: null,
          sessionRevision: action.sessionRevision,
          catalogRevision: action.catalogRevision,
          manifestSha256: action.manifestSha256,
        });
        commitSessionCatalog(action.deviceId, { ...catalog, details });
        return CHANGED;
      }
      case "sessions/detailFailed": {
        if (
          !sessionMatches(
            action.deviceId,
            action.sessionId,
            action.sessionRevision,
            action.catalogRevision,
            action.manifestSha256,
          )
        ) {
          return STALE;
        }
        const catalog = sessionCatalog(action.deviceId);
        const details = new Map(catalog.details);
        details.set(action.sessionId, {
          loading: false,
          error: action.error,
          sessionRevision: action.sessionRevision,
          catalogRevision: action.catalogRevision,
          manifestSha256: action.manifestSha256,
        });
        commitSessionCatalog(action.deviceId, { ...catalog, details });
        return CHANGED;
      }
      case "devices/loaded":
      case "sessions/loaded":
      case "sessions/catalogLoaded":
      case "sessions/pageLoaded":
      case "sessions/detailLoaded":
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

export function sessionCatalogOf(state: AppState, deviceId: string | null): SessionCatalogState {
  if (deviceId === null) return idleSessionCatalog();
  return state.sessionCatalogs.get(deviceId) ?? idleSessionCatalog();
}

export function sessionDetailStateOf(
  state: AppState,
  deviceId: string | null,
  sessionId: string,
): SessionDetailState | undefined {
  return sessionCatalogOf(state, deviceId).details.get(sessionId);
}

export function deviceSupportsSessionDeletion(state: AppState, deviceId: string | null): boolean {
  const capabilities = sessionCatalogOf(state, deviceId).capabilities;
  return capabilities.profile === "legacyPinnedTlsV1" && capabilities.sessionDeletion.supported;
}

export function deviceSupportsSessionDetail(state: AppState, deviceId: string | null): boolean {
  const capabilities = sessionCatalogOf(state, deviceId).capabilities;
  return capabilities.profile !== "unknown" && capabilities.sessionDetail.supported;
}

export function deviceSupportsSessionDownload(state: AppState, deviceId: string | null): boolean {
  const capabilities = sessionCatalogOf(state, deviceId).capabilities;
  return capabilities.profile !== "unknown" && capabilities.artifactDownload.supported;
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
