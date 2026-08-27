// The application, minus the DOM.
//
// `TransferApp` owns everything that used to be module-level state in
// `main.ts`: the reducer store, the backend adapter, the clock, the operation
// runner, the confirmation machine, the view guard and the device navigation
// controller. Its whole public surface is `start`, `dispatch` and `dispose`.
//
// That boundary is what makes the frontend testable: a headless test builds the
// controller over the in-memory backend, a fake clock and a recording `AppView`,
// then dispatches the same actions a click would have produced. `main.ts` is
// left with adapter construction and mounting.

import type { Dispatch, UiAction } from "./actions";
import type { AppView } from "./appView";
import type { AppUpdater, AppUpdateProgress, PendingAppUpdate } from "../runtime/appUpdater";
import { batchFeedback } from "../batchResult";
import {
  asDeviceId,
  asLibraryKey,
  asPairingAttemptId,
  asSessionId,
  type DeviceId,
  type LibraryKey,
  type SessionId,
} from "../ids";
import { asCandidateId, asDerivationJobId, asImportJobId, asMediaId, asPipelineId } from "../runtime/media/ids";
import { acceptedItems, type AnyBatchItem } from "../runtime/batch";
import {
  backendRpcError,
  describeBackendError,
  type BackendEvent,
  type Revisioned,
  type SessionMutation,
  type TransferBackend,
} from "../runtime/backend";
import type { Clock } from "../runtime/clock";
import { describeMediaBackendError, type MediaBackend } from "../runtime/media/backend";
import { createMediaRuntime, type MediaRuntime } from "../runtime/media/runtime";
import {
  IMPORT_ONLY_PIPELINE_POLICY,
  type MediaJobCommand as RuntimeMediaJobCommand,
  type PipelineCommand,
  type ScanCandidate,
  type MediaScanSnapshot,
  type ScanRequest,
  type StartPipelineRequest,
} from "../runtime/media/types";
import { confirmTargets, createConfirmController, DEVICE_CONFIRM_PREFIX, type OperationId } from "../runtime/confirm";
import { createOperationRunner, type Toaster } from "../runtime/operations";
import {
  createAppStore,
  deviceById,
  deviceDisplayIdOf,
  devicesOf,
  libraryOf,
  sessionsOf,
  storageOf,
  transferJobsOf,
  transfersOf,
  type Action,
  type AppState,
  type AppStore,
  type CommitResult,
  type ResourceRetryTarget,
} from "../runtime/reducer";
import { startBackend, type BackendSession } from "../runtime/start";
import { filterFor, type SelectionScope, type UiState } from "../store";
import { rowKeyFor, selectDeviceList, selectLibraryList, type ListSelection } from "../ui/listSelector";
import { createDeviceNavigationController } from "../ui/navigationController";
import { classifyPairingEvent } from "../ui/pairingGuard";
import { afterNextPaint, scheduleAnimationFrame, type FrameScheduler } from "../ui/renderScheduler";
import { selectTray, type TrayCommand } from "../ui/traySelector";
import { createViewGuard, type ViewCapture } from "../ui/viewGuard";
import { devicePaneSnapshotsEqual } from "../ui/visibleSnapshot";
import { projectMediaWorkspace, projectPipelineBatch } from "../ui/media/projection";
import {
  type MediaAcquisitionSourceKind,
  type MediaBatchItemOutcome,
  type MediaBatchSnapshot,
  type MediaCandidateSnapshot,
  type MediaIssue,
  type MediaReleaseSnapshot,
  type MediaWorkspaceAction,
  type MediaWorkspaceSnapshot,
} from "../ui/media/types";
import { formatBytes } from "../format";
import {
  libraryEntryCanUpload,
  libraryEntryKey,
  storageConfigured,
  type Device,
  type LibraryEntry,
  type PairingResolutionPayload,
  type PairingTickPayload,
  type SaveStorageConfigInput,
  type SessionView,
  type StorageConfig,
  type Transfer,
} from "../types";

export interface TransferAppOptions {
  backend: TransferBackend;
  /** Frozen compatibility seam for headless legacy harnesses. D-049 production
   * assembly does not supply this adapter or mount a removable-media view. */
  mediaBackend?: MediaBackend;
  clock: Clock;
  toast: Toaster;
  /** Built with the dispatcher so the view can send actions back. */
  view: (dispatch: Dispatch) => AppView;
  updater?: AppUpdater;
  store?: AppStore;
  /** How long a bulk/device-level confirmation stays armed. */
  confirmTtlMs?: number;
  /** How long a single row's delete confirmation stays armed. */
  rowConfirmTtlMs?: number;
  /** Injectable frame boundary for deterministic progress-render tests. */
  frameScheduler?: FrameScheduler;
}

export interface TransferApp {
  /** Subscribes, reads the snapshot, replays and paints the first frame.
   * Never rejects: a boot failure is reported through the view. */
  start(): Promise<void>;
  dispatch(action: UiAction): void;
  /** Re-reads one degraded backend resource without restarting the app or
   * touching any other resource. Identical in-flight retries are shared. */
  retryResource(resource: ResourceRetryTarget): Promise<void>;
  /** Idempotent: shutdown, hot reload and tests may all call it. */
  dispose(): void;
  /** Escape hatch for tests and assertions; not used by any view. */
  readonly store: AppStore;
}

const LIBRARY_RECONCILE_DEBOUNCE_MS = 2_000;

type AppUpdateStatus =
  "idle" | "checking" | "available" | "current" | "downloading" | "installing" | "restarting" | "failed";

/** Settings payloads are part of an operation's identity. Keeping the fields
 * explicit makes the key stable even if callers construct config objects with
 * a different property insertion order. */
function storageConfigIntentKey(config: SaveStorageConfigInput): string {
  return JSON.stringify([
    config.endpoint,
    config.bucket,
    config.prefix,
    config.urlStyle,
    config.accessKey,
    config.secretKey,
    config.downloadRoot,
  ]);
}

function settingsValueIntentKey(value: string | boolean): string {
  return JSON.stringify(value);
}

export function createTransferApp(options: TransferAppOptions): TransferApp {
  const { backend, clock, toast, updater } = options;
  const store = options.store ?? createAppStore();
  const confirmTtlMs = options.confirmTtlMs ?? 4000;
  const rowConfirmTtlMs = options.rowConfirmTtlMs ?? 3000;

  const runner = createOperationRunner({ toast });
  let session: BackendSession | null = null;
  let disposed = false;
  let startPromise: Promise<void> | null = null;
  let paintedDevice: Device | undefined;
  let lastLibraryReconcileStartedAt = 0;
  let trayFrameCancel: (() => void) | null = null;
  const scheduleFrame = options.frameScheduler ?? ((run: () => void) => scheduleAnimationFrame(run, clock));

  const state = (): AppState => store.getState();
  const ui = (): UiState => store.getState().ui;
  const commit = (action: Action): CommitResult => store.commit(action);

  /* ------------------------------------------------------------------ */
  /* view                                                                */
  /* ------------------------------------------------------------------ */

  const view = options.view((action) => dispatch(action));

  let mediaFolderGeneration = 0;
  let mediaBatchGeneration = 0;
  let mediaBatchSequence = 0;
  let mediaScanRevision = -1;
  const mediaPhysicalGeneration = new Map<string, number>();
  const mediaRuntime: MediaRuntime | null =
    options.mediaBackend === undefined
      ? null
      : createMediaRuntime({
          backend: options.mediaBackend,
          now: () => clock.now(),
          onChange: (mediaState, result) => {
            if (mediaState.scan.revision !== mediaScanRevision) {
              mediaScanRevision = mediaState.scan.revision;
              commit({ type: "ui/mediaUnsignedApprovalClear" });
            }
            if (disposed || !result.changed || ui().view !== "media") return;
            paintMedia();
          },
          onOperationError: (error) => {
            if (!disposed) toast(`介质操作失败：${describeMediaBackendError(error)}`, "danger");
          },
        });

  /** Every async commit is scoped to the view/device it started in, so a late
   * response or confirm timer cannot paint over a screen the user has since
   * navigated away from. */
  const viewGuard = createViewGuard(() => ({ view: ui().view, deviceId: ui().activeDeviceId }));

  const confirm = createConfirmController({
    store,
    clock,
    ttlMs: confirmTtlMs,
    onExpire: (target) => {
      if (disposed) return;
      if (target.startsWith(DEVICE_CONFIRM_PREFIX)) paintTopbar();
      paintList();
    },
  });

  function activeScope(): SelectionScope {
    return ui().view === "library" ? "library" : "device";
  }

  function deviceListOf(deviceId: DeviceId | null): ListSelection<SessionView> {
    return selectDeviceList(ui(), sessionsOf(state(), deviceId) ?? []);
  }
  function libraryListOf(): ListSelection<LibraryEntry> {
    return selectLibraryList(ui(), libraryOf(state()));
  }
  function activeList(): ListSelection<SessionView> | ListSelection<LibraryEntry> {
    return activeScope() === "library" ? libraryListOf() : deviceListOf(activeDeviceId());
  }

  function activeDeviceId(): DeviceId | null {
    const id = ui().activeDeviceId;
    return id === null ? null : asDeviceId(id);
  }

  /** A selection is only ever as valid as the current item list: entities that
   * disappeared between selecting and acting are dropped, so no bulk command
   * can address a session/entry that is gone. */
  function retainSelection(): void {
    const list = activeList();
    commit({ type: "ui/retainSelection", scope: list.scope, existingKeys: [...list.existingKeys] });
  }

  function paintRail(): void {
    view.renderRail(state());
  }
  function paintNav(): void {
    view.renderNav(state());
  }
  function mediaSnapshot(): MediaWorkspaceSnapshot | null {
    if (mediaRuntime === null) return null;
    const currentUi = ui();
    return projectMediaWorkspace(mediaRuntime.store.getState(), {
      selectedCandidateIds: currentUi.mediaSelectedCandidateIds,
      unsignedApprovalCandidateIds: currentUi.mediaUnsignedApprovalCandidateIds,
      expandedCandidateIds: currentUi.mediaExpandedCandidateIds,
      sourceKindById: currentUi.mediaSourceKindById,
      releaseOverrideBySourceId: currentUi.mediaReleaseOverrideBySourceId,
      policy: currentUi.mediaPolicy,
      batch: currentUi.mediaBatch,
    });
  }
  function paintMedia(): void {
    const snapshot = mediaSnapshot();
    if (snapshot === null) {
      view.renderTopbar(state());
      view.renderContent(state());
      return;
    }
    view.renderMedia?.(snapshot);
  }
  function paintTopbar(): void {
    if (ui().view === "media") {
      paintMedia();
      return;
    }
    paintedDevice = deviceById(state(), ui().activeDeviceId);
    view.renderTopbar(state());
  }
  function paintContent(): void {
    if (ui().view === "media") {
      paintMedia();
      return;
    }
    retainSelection();
    view.renderContent(state());
  }
  function paintList(): void {
    if (ui().view === "media") {
      paintMedia();
      return;
    }
    retainSelection();
    view.renderList(state());
  }
  function paintTray(): void {
    trayFrameCancel?.();
    trayFrameCancel = null;
    view.renderTray(
      selectTray(transfersOf(state()), transferJobsOf(state()), ui().transferTrayCollapsed, {
        error: state().transfers.error,
        loading: state().transfers.loading,
      }),
    );
  }

  /** Transfer progress can arrive several times in one task. Render the latest
   * reducer state once per frame; controls still resolve against the selection
   * that was actually painted. */
  function paintTraySoon(capture?: ViewCapture): void {
    if (disposed || trayFrameCancel !== null) return;
    trayFrameCancel = scheduleFrame(() => {
      trayFrameCancel = null;
      if (!disposed && (capture === undefined || capture.isCurrent())) {
        view.renderTray(
          selectTray(transfersOf(state()), transferJobsOf(state()), ui().transferTrayCollapsed, {
            error: state().transfers.error,
            loading: state().transfers.loading,
          }),
        );
      }
    });
  }
  function paintAll(): void {
    paintRail();
    paintNav();
    if (ui().view === "media") paintMedia();
    else {
      paintTopbar();
      paintContent();
    }
  }

  type RetryResourceValue = Device[] | LibraryEntry[] | Transfer[] | StorageConfig;

  function resourceState(
    resource: ResourceRetryTarget,
  ): AppState["devices"] | AppState["library"] | AppState["transfers"] | AppState["storage"] {
    switch (resource) {
      case "devices":
        return state().devices;
      case "library":
        return state().library;
      case "transfers":
        return state().transfers;
      case "storageConfig":
        return state().storage;
    }
  }

  function readResource(resource: ResourceRetryTarget): Promise<Revisioned<RetryResourceValue>> {
    switch (resource) {
      case "devices":
        return backend.listDevices();
      case "library":
        return backend.listLibrary();
      case "transfers":
        return backend.listTransfers();
      case "storageConfig":
        return backend.getStorageConfig();
    }
  }

  function commitResourceRead(resource: ResourceRetryTarget, loaded: Revisioned<RetryResourceValue>): CommitResult {
    switch (resource) {
      case "devices":
        return commit({ type: "devices/loaded", revision: loaded.revision, devices: loaded.value as Device[] });
      case "library":
        return commit({ type: "library/loaded", revision: loaded.revision, library: loaded.value as LibraryEntry[] });
      case "transfers":
        return commit({ type: "transfers/loaded", revision: loaded.revision, transfers: loaded.value as Transfer[] });
      case "storageConfig":
        return commit({
          type: "storage/loaded",
          revision: loaded.revision,
          storage: loaded.value as StorageConfig,
        });
    }
  }

  /** Paints only the resource's owning surface. The optional capture is
   * checked again by `paintTraySoon` because a frame can outlive navigation. */
  function paintResource(resource: ResourceRetryTarget, capture?: ViewCapture): void {
    switch (resource) {
      case "devices": {
        const selectedAfter = deviceById(state(), ui().activeDeviceId);
        paintRail();
        if (ui().view === "device" && !devicePaneSnapshotsEqual(paintedDevice, selectedAfter)) {
          if (selectedAfter?.state !== "connected") deviceNavigation.invalidate();
          paintTopbar();
          paintContent();
        }
        return;
      }
      case "library":
        paintNav();
        if (ui().view === "library") {
          paintTopbar();
          paintContent();
        }
        return;
      case "transfers":
        paintTraySoon(capture);
        return;
      case "storageConfig":
        view.renderDownloadRootLabel(state());
        if (ui().view === "library") {
          paintTopbar();
          paintContent();
        }
        return;
    }
  }

  const RESOURCE_LABELS: Record<ResourceRetryTarget, string> = {
    devices: "设备列表",
    library: "本地数据",
    transfers: "传输队列",
    storageConfig: "对象存储配置",
  };

  function retryResource(resource: ResourceRetryTarget): Promise<void> {
    if (disposed) return Promise.resolve();
    const capture = viewGuard.capture();
    const revision = resourceState(resource).revision;
    const loading = commit({ type: "resource/loading", resource });
    if (loading.changed) capture.commit(() => paintResource(resource, capture));

    return runner
      .run({
        key: `resource:retry:${resource}`,
        // All intents that mutate this resource belong to one stable scope;
        // the key still makes identical retry clicks share one request.
        scope: `resource:${resource}`,
        run: () => readResource(resource),
        commit: (loaded) => {
          const result = commitResourceRead(resource, loaded);
          if (result.changed) capture.commit(() => paintResource(resource, capture));
        },
        failure: (error, token) => {
          if (!token.isCurrent()) return null;
          const message = describeBackendError(error);
          const rpcError = backendRpcError(error);
          const result = commit({
            type: "resource/failed",
            resource,
            revision,
            error: message,
            ...(rpcError === null ? {} : { rpcError }),
          });
          if (result.changed) capture.commit(() => paintResource(resource, capture));
          return `无法刷新${RESOURCE_LABELS[resource]}：${message}`;
        },
      })
      .then(() => undefined);
  }

  function showBatchFeedback(action: string, items: readonly AnyBatchItem<string>[]): void {
    const feedback = batchFeedback(action, items);
    toast(feedback.message, feedback.tone);
  }

  /* ------------------------------------------------------------------ */
  /* application updates                                                 */
  /* ------------------------------------------------------------------ */

  let updateStatus: AppUpdateStatus = "idle";
  let currentAppVersion: string | null = null;
  let pendingUpdate: PendingAppUpdate | null = null;
  let updateProgress: AppUpdateProgress | null = null;
  let updateMessage: string | null = updater === undefined ? "此构建未启用应用内更新" : null;
  let updateError: string | null = null;

  function updateViewModel() {
    return {
      currentVersion: currentAppVersion ?? pendingUpdate?.currentVersion ?? null,
      availableVersion: pendingUpdate?.version ?? null,
      checked: updateStatus === "available" || updateStatus === "current",
      checking: updateStatus === "checking",
      installing: updateStatus === "downloading" || updateStatus === "installing" || updateStatus === "restarting",
      progressLabel: updateProgressLabel(),
      message: updateMessage,
      error: updateError,
      notes: pendingUpdate?.body ?? null,
      canCheck:
        updater !== undefined &&
        updateStatus !== "checking" &&
        updateStatus !== "downloading" &&
        updateStatus !== "installing" &&
        updateStatus !== "restarting",
      canInstall: updater !== undefined && pendingUpdate !== null && updateStatus === "available",
    };
  }

  function updateProgressLabel(): string | null {
    if (updateProgress === null) return null;
    const downloaded = formatBytes(updateProgress.downloadedBytes);
    if (updateProgress.totalBytes === null || updateProgress.totalBytes <= 0) return `${downloaded} 已下载`;
    const total = formatBytes(updateProgress.totalBytes);
    const percent = Math.min(100, Math.round((updateProgress.downloadedBytes / updateProgress.totalBytes) * 100));
    return `${percent}% · ${downloaded} / ${total}`;
  }

  function renderUpdateSettings(): void {
    view.renderUpdateSettings(updateViewModel());
  }

  async function openUpdateSettings(): Promise<void> {
    view.openUpdateSettings(updateViewModel());
    if (updater !== undefined && currentAppVersion === null) {
      try {
        currentAppVersion = await updater.currentVersion();
        if (!disposed) renderUpdateSettings();
      } catch {
        currentAppVersion = null;
      }
    }
  }

  function failUpdate(error: unknown): void {
    updateStatus = "failed";
    updateError = describeBackendError(error);
    updateMessage = null;
    updateProgress = null;
    renderUpdateSettings();
    toast(`应用更新失败：${updateError}`, "danger");
  }

  async function checkForUpdate(): Promise<void> {
    if (updater === undefined) return;
    await pendingUpdate?.close().catch(() => undefined);
    pendingUpdate = null;
    updateProgress = null;
    updateStatus = "checking";
    updateError = null;
    updateMessage = "正在检查更新";
    renderUpdateSettings();
    try {
      const update = await updater.check();
      if (update === null) {
        currentAppVersion = currentAppVersion ?? (await updater.currentVersion().catch(() => null));
        updateStatus = "current";
        updateMessage = "已是最新版本";
      } else {
        pendingUpdate = update;
        currentAppVersion = update.currentVersion;
        updateStatus = "available";
        updateMessage = `发现新版本 ${update.version}`;
      }
      renderUpdateSettings();
    } catch (error) {
      failUpdate(error);
    }
  }

  async function installUpdate(): Promise<void> {
    if (updater === undefined || pendingUpdate === null || updateStatus !== "available") return;
    updateStatus = "downloading";
    updateError = null;
    updateMessage = "正在下载更新";
    updateProgress = { downloadedBytes: 0, totalBytes: null };
    renderUpdateSettings();
    try {
      await pendingUpdate.downloadAndInstall((progress) => {
        if (disposed) return;
        updateStatus = "downloading";
        updateProgress = progress;
        renderUpdateSettings();
      });
      updateStatus = "restarting";
      updateMessage = "更新已安装，正在重启";
      updateProgress = null;
      renderUpdateSettings();
      await updater.relaunch();
    } catch (error) {
      failUpdate(error);
    }
  }

  function commitSessionMutation(
    deviceId: DeviceId,
    revision: number,
    value: SessionMutation,
    operationLabel: string,
  ): void {
    if (value.sessions !== null) {
      commit({ type: "sessions/loaded", revision, deviceId, sessions: value.sessions });
    }
    if (value.operationError !== null) {
      commit({
        type: "resource/failed",
        resource: "sessions",
        deviceId,
        revision,
        error: value.operationError.message,
        rpcError: value.operationError,
      });
      toast(`${operationLabel}：${value.operationError.message}`, "danger");
    }
  }

  function isActiveDeviceView(deviceId: string): boolean {
    return ui().view === "device" && ui().activeDeviceId === deviceId;
  }

  /* ------------------------------------------------------------------ */
  /* device navigation                                                   */
  /* ------------------------------------------------------------------ */

  const deviceNavigation = createDeviceNavigationController<{ revision: number; value: SessionView[] }>({
    onBegin: (deviceId, activate) => {
      if (activate) {
        invalidatePendingMediaUi();
        viewGuard.invalidate();
        commit({ type: "ui/activateDevice", deviceId });
        commit({ type: "ui/view", view: "device" });
        commit({ type: "ui/resetDeviceView" });
      }
      if (!isActiveDeviceView(deviceId)) return;
      commit({ type: "resource/loading", resource: "sessions", deviceId });
      if (activate) {
        paintRail();
        paintNav();
      }
      paintTopbar();
      paintContent();
    },
    loadSessions: (deviceId) => backend.listSessions(asDeviceId(deviceId)),
    isCurrent: (deviceId) => isActiveDeviceView(deviceId) && deviceById(state(), deviceId)?.state === "connected",
    onLoaded: (deviceId, loaded) => {
      commit({ type: "sessions/loaded", revision: loaded.revision, deviceId, sessions: loaded.value });
      paintTopbar();
      paintContent();
    },
    onFailed: (deviceId, error) => {
      const message = describeBackendError(error);
      const rpcError = backendRpcError(error);
      commit({
        type: "resource/failed",
        resource: "sessions",
        deviceId,
        error: message,
        ...(rpcError === null ? {} : { rpcError }),
      });
      toast(`无法刷新 ${deviceDisplayIdOf(state(), deviceId) ?? "设备"} 的会话列表：${message}`, "danger");
      paintTopbar();
      paintContent();
    },
    onInvalidated: () => {
      viewGuard.invalidate();
    },
  });

  function focusDevice(deviceId: DeviceId): Promise<unknown> {
    return deviceNavigation.focus(deviceId);
  }

  /* ------------------------------------------------------------------ */
  /* pairing                                                             */
  /* ------------------------------------------------------------------ */

  function closePairingFlow(): void {
    view.hidePairing();
    commit({ type: "ui/pairingClosed" });
    paintRail();
  }

  function beginPairing(deviceId: DeviceId): Promise<unknown> {
    commit({ type: "ui/pairingStarted", deviceId });
    paintRail();
    view.showPairing(deviceDisplayIdOf(state(), deviceId) ?? "设备");
    return runner.run({
      key: `device:pair:${deviceId}`,
      // One pairing overlay at a time: a newer attempt supersedes this reply.
      scope: "device:pair",
      run: () => backend.connectDevice(deviceId),
      commit: (attemptId) => {
        // The user may have moved on (cancelled, or started pairing another
        // device) while the request was in flight; that flow owns the overlay
        // now, so the reducer drops this reply as stale.
        if (commit({ type: "ui/pairingAttempt", deviceId, attemptId }).stale) return;
        const deferred = ui().pairingDeferred.get(attemptId);
        ui().pairingDeferred.clear();
        if (deferred) applyPairingResolution(deferred);
      },
      failure: (error) => {
        if (ui().pairingTargetId !== deviceId) return null;
        closePairingFlow();
        return describeBackendError(error);
      },
    });
  }

  function pairingFocus(): { deviceId: string | null; attemptId: string | null } {
    return { deviceId: ui().pairingTargetId, attemptId: ui().pairingAttemptId };
  }

  function handlePairingTick({ deviceId, attemptId, remaining, total }: PairingTickPayload): void {
    if (classifyPairingEvent(pairingFocus(), { deviceId, attemptId }) !== "apply") return;
    view.updatePairingRing(remaining, total);
  }

  function handlePairingResolved(payload: PairingResolutionPayload): void {
    const verdict = classifyPairingEvent(pairingFocus(), {
      deviceId: payload.deviceId,
      attemptId: payload.attemptId,
    });
    if (verdict === "drop") return;
    if (verdict === "defer") {
      commit({ type: "ui/pairingDeferred", payload });
      return;
    }
    applyPairingResolution(payload);
  }

  function applyPairingResolution({ deviceId, outcome, error }: PairingResolutionPayload): void {
    closePairingFlow();
    if (outcome === "connected") {
      toast(`已连接 ${deviceDisplayIdOf(state(), deviceId) ?? "设备"}`, "success");
      void focusDevice(asDeviceId(deviceId));
      return;
    }
    const message =
      error ??
      (outcome === "rejected"
        ? "设备拒绝了连接请求"
        : outcome === "expired"
          ? "连接请求超时，请重试"
          : "设备连接失败，请重试");
    toast(message, "danger");
  }

  /* ------------------------------------------------------------------ */
  /* library reconciliation                                              */
  /* ------------------------------------------------------------------ */

  /** Background reconciliation against the real filesystem. A reconcile
   * already in flight is de-duplicated by the operation runner; only the
   * debounce window is local. */
  function reconcileLibraryFromDisk(force = false): Promise<unknown> {
    const now = clock.now();
    const reconciling = runner.isBusy("library:reconcile");
    if (!force && !reconciling && now - lastLibraryReconcileStartedAt < LIBRARY_RECONCILE_DEBOUNCE_MS) {
      return Promise.resolve();
    }
    if (!reconciling) lastLibraryReconcileStartedAt = now;
    return runner.run({
      key: "library:reconcile",
      run: () => backend.listLibrary(),
      commit: ({ revision, value }) => {
        if (!commit({ type: "library/loaded", revision, library: value }).changed) return;
        paintNav();
        if (ui().view === "library") {
          paintTopbar();
          paintContent();
        }
      },
      failure: (error) => `无法核对本地文件状态：${describeBackendError(error)}`,
    });
  }

  /* ------------------------------------------------------------------ */
  /* commands                                                            */
  /* ------------------------------------------------------------------ */

  function selectDevice(deviceId: DeviceId): void {
    const device = deviceById(state(), deviceId);
    if (!device) return;
    if (device.state === "offline") {
      toast("设备离线，无法连接", "danger");
      return;
    }
    if (device.state === "connected") {
      void focusDevice(deviceId);
      return;
    }
    void beginPairing(deviceId);
  }

  function disconnectDevice(deviceId: DeviceId): void {
    deviceNavigation.invalidate();
    const displayId = deviceDisplayIdOf(state(), deviceId) ?? "设备";
    void runner.run({
      key: `device:disconnect:${deviceId}`,
      run: async () => {
        await backend.disconnectDevice(deviceId);
        return backend.listDevices();
      },
      commit: ({ revision, value }) => {
        commit({ type: "devices/loaded", revision, devices: value });
        if (ui().activeDeviceId === deviceId) commit({ type: "ui/activateDevice", deviceId: null });
        commit({ type: "ui/resetDeviceView" });
        toast(`已断开 ${displayId}`, "danger");
        paintRail();
        paintTopbar();
        paintContent();
      },
    });
  }

  function downloadAllNew(deviceId: DeviceId): void {
    const pending = (sessionsOf(state(), deviceId) ?? []).filter(
      (s) => s.downloadStatus === "none" || s.downloadStatus === "failed",
    );
    if (pending.length === 0) {
      toast("没有新数据需要下载", "success");
      return;
    }
    void runner.run({
      key: `device:downloadAll:${deviceId}`,
      run: () =>
        backend.downloadSessions(
          deviceId,
          pending.map((session) => asSessionId(session.id)),
        ),
      commit: (result) => showBatchFeedback("已加入下载队列", result.items),
    });
  }

  function cleanupBackedUp(deviceId: DeviceId): void {
    const target = confirmTargets.cleanupBackedUp(deviceId);
    const decision = confirm.request(target, confirmTtlMs);
    if (decision.decision === "busy") return;
    if (decision.decision === "armed") {
      paintTopbar();
      return;
    }
    const capture = viewGuard.capture();
    const operationId: OperationId = decision.operationId;
    void runner
      .run({
        key: `device:cleanupBackedUp:${deviceId}`,
        run: () => backend.cleanupBackedUp(deviceId),
        commit: ({ revision, value }) => {
          // The session snapshot is device-owned, so it is stored even when the
          // user navigated away; only the DOM commit is scoped to the view.
          commitSessionMutation(deviceId, revision, value, "清理完成，但会话列表不可用");
          if (value.items.length > 0 || value.operationError === null) {
            showBatchFeedback("已清理设备上的已备份数据", value.items);
          }
        },
      })
      .finally(() => {
        confirm.settle(target, operationId);
        capture.commit(() => {
          paintTopbar();
          paintContent();
        });
      });
  }

  async function cleanupDownloaded(deviceId: DeviceId): Promise<void> {
    const capture = viewGuard.capture();
    view.setBusy("正在核验本地副本…");

    try {
      const preview = await runner.run({
        key: `device:previewDownloadedCleanup:${deviceId}`,
        run: () => backend.previewDownloadedCleanup(deviceId),
      });
      if (preview.status !== "completed") return;
      // Asking to delete Pi data for a device the user already left would be a
      // destructive surprise, so a stale preview never reaches the confirm.
      if (!capture.isCurrent()) return;
      const { eligible, skipped, eligibleBytes } = preview.value;
      if (eligible.length === 0) {
        const suffix = skipped.length > 0 ? `，已安全跳过 ${skipped.length} 项` : "";
        toast(`没有可从 Pi 删除的完整已下载数据${suffix}`, "success");
        return;
      }

      const confirmed = view.confirmDestructive(
        `确认从 Pi 删除 ${eligible.length} 个已完整下载的会话（${formatBytes(eligibleBytes)}）？\n\n` +
          `PC 本地文件不会删除；未下载、下载失败或本地文件不完整的数据会保留。` +
          (skipped.length > 0 ? `\n本次将安全跳过 ${skipped.length} 个会话。` : ""),
      );
      if (!confirmed) return;

      await runner.run({
        key: `device:cleanupDownloaded:${deviceId}`,
        run: () => backend.cleanupDownloaded(deviceId),
        commit: ({ revision, value }) => {
          commit({ type: "sessions/loaded", revision, deviceId, sessions: value.sessions });
          const summary = `Pi 清理完成：删除 ${value.deleted.length} 项，失败 ${value.failed.length} 项，跳过 ${value.skipped.length} 项`;
          toast(summary, value.failed.length > 0 ? "danger" : "success");
          capture.commit(paintContent);
        },
      });
    } finally {
      view.setBusy(null);
      capture.commit(paintTopbar);
    }
  }

  async function uploadAllPending(): Promise<void> {
    if (!storageConfigured(storageOf(state()))) {
      toast("请先配置对象存储", "danger");
      await openStorageSettings();
      return;
    }
    const pending = libraryOf(state()).filter(
      (e) => e.complete && e.uploadStatus !== "done" && e.uploadStatus !== "uploading" && libraryEntryCanUpload(e),
    );
    if (pending.length === 0) {
      toast("没有待上传的数据", "success");
      return;
    }
    await runner.run({
      key: "library:uploadAll",
      run: () => backend.uploadEntries(pending.map(libraryEntryKey)),
      commit: (result) => showBatchFeedback("已加入上传队列", result.items),
    });
  }

  /* ---- bulk ---- */

  async function runBulkAction(scope: SelectionScope): Promise<void> {
    const capture = viewGuard.capture();
    const repaint = () => capture.commit(paintList);
    const selected = activeList().selectedKeys;
    if (selected.length === 0) return;

    if (scope === "device") {
      const deviceId = activeDeviceId();
      if (deviceId === null) return;
      await runner.run({
        key: `device:bulkDownload:${deviceId}`,
        run: () => backend.downloadSessions(deviceId, selected.map(asSessionId)),
        commit: (result) => {
          for (const id of acceptedItems(result.items)) {
            commit({ type: "ui/select", scope: "device", key: id, selected: false });
          }
          showBatchFeedback("已加入下载队列", result.items);
          repaint();
        },
      });
      return;
    }
    if (!storageConfigured(storageOf(state()))) {
      toast("请先配置对象存储", "danger");
      await openStorageSettings();
      return;
    }
    await runner.run({
      key: "library:bulkUpload",
      run: () => backend.uploadEntries(selected.map(asLibraryKey)),
      commit: (result) => {
        for (const key of acceptedItems(result.items)) {
          commit({ type: "ui/select", scope: "library", key, selected: false });
        }
        showBatchFeedback("已加入上传队列", result.items);
        repaint();
      },
    });
  }

  async function runBulkRemove(scope: SelectionScope): Promise<void> {
    const deviceId = activeDeviceId();
    const target =
      scope === "device" ? confirmTargets.deviceBulkRemove(deviceId ?? "") : confirmTargets.libraryBulkRemove();
    const decision = confirm.request(target, confirmTtlMs);
    if (decision.decision === "busy") return;
    if (decision.decision === "armed") {
      paintList();
      return;
    }

    const capture = viewGuard.capture();
    const operationId = decision.operationId;
    const selected = activeList().selectedKeys;
    try {
      if (scope === "device") {
        if (deviceId === null) return;
        await runner.run({
          key: `device:bulkDelete:${deviceId}`,
          run: () => backend.deleteSessions(deviceId, selected.map(asSessionId)),
          commit: ({ revision, value }) => {
            commitSessionMutation(deviceId, revision, value, "删除完成，但会话列表刷新失败");
            for (const id of acceptedItems(value.items)) {
              commit({ type: "ui/select", scope: "device", key: id, selected: false });
            }
            showBatchFeedback("设备数据删除完成", value.items);
            paintNav();
          },
        });
        return;
      }
      await runner.run({
        key: "library:bulkRemove",
        run: () => backend.removeLibraryEntries(selected.map(asLibraryKey)),
        commit: ({ revision, value }) => {
          commit({ type: "library/loaded", revision, library: value.library });
          for (const key of acceptedItems(value.items)) {
            commit({ type: "ui/select", scope: "library", key, selected: false });
          }
          showBatchFeedback("本地副本移除完成", value.items);
          paintNav();
        },
      });
    } finally {
      confirm.settle(target, operationId);
      capture.commit(paintContent);
    }
  }

  /* ---- per-row destructive ---- */

  function removeSession(deviceId: DeviceId, sessionId: SessionId): void {
    const rowKey = rowKeyFor("device", deviceId, sessionId);
    const target = confirmTargets.deviceRowRemove(rowKey);
    const decision = confirm.request(target, rowConfirmTtlMs);
    if (decision.decision === "busy") return;
    if (decision.decision === "armed") {
      paintList();
      return;
    }
    const capture = viewGuard.capture();
    const operationId = decision.operationId;
    void runner
      .run({
        key: `device:deleteSession:${deviceId}:${sessionId}`,
        run: () => backend.deleteSessions(deviceId, [sessionId]),
        commit: ({ revision, value }) => {
          commitSessionMutation(deviceId, revision, value, "删除完成，但会话列表刷新失败");
          showBatchFeedback("设备数据删除完成", value.items);
        },
      })
      .finally(() => {
        confirm.settle(target, operationId);
        capture.commit(() => {
          paintTopbar();
          paintContent();
        });
      });
  }

  function removeEntry(key: LibraryKey): void {
    const rowKey = rowKeyFor("library", "", key);
    const target = confirmTargets.libraryRowRemove(rowKey);
    const decision = confirm.request(target, rowConfirmTtlMs);
    if (decision.decision === "busy") return;
    if (decision.decision === "armed") {
      paintList();
      return;
    }
    const capture = viewGuard.capture();
    const operationId = decision.operationId;
    void runner
      .run({
        key: `library:remove:${key}`,
        run: () => backend.removeLibraryEntries([key]),
        commit: ({ revision, value }) => {
          commit({ type: "library/loaded", revision, library: value.library });
          showBatchFeedback("本地副本移除完成", value.items);
          paintNav();
        },
      })
      .finally(() => {
        confirm.settle(target, operationId);
        capture.commit(paintContent);
      });
  }

  /* ---- tray ---- */

  function runTrayCommand(command: TrayCommand): void {
    const { key, run, failure } = trayInvocation(command);
    void runner.run({ key, run, failure: (error) => `${failure}：${describeBackendError(error)}` });
  }

  function trayInvocation(command: TrayCommand): { key: string; run: () => Promise<unknown>; failure: string } {
    switch (command.kind) {
      case "retry":
        return { key: `tray:retry:${command.id}`, run: () => backend.retryTransfer(command.id), failure: "重试失败" };
      case "pauseJob":
        return {
          key: `tray:pause:${command.jobId}`,
          run: () => backend.pauseTransferJob(command.jobId),
          failure: "暂停失败",
        };
      case "resumeJob":
        return {
          key: `tray:resume:${command.jobId}`,
          run: () => backend.resumeTransferJob(command.jobId),
          failure: "继续传输失败",
        };
      case "cancelJob":
        return {
          key: `tray:cancelJob:${command.jobId}`,
          run: () => backend.cancelTransferJob(command.jobId),
          failure: "取消任务失败",
        };
      case "dismissJob":
        return {
          key: `tray:dismissJob:${command.jobId}`,
          run: () => backend.dismissTransferJob(command.jobId),
          failure: "清除任务失败",
        };
      case "cancelUpload":
        return {
          key: `tray:cancelUpload:${command.jobId}`,
          run: () => backend.cancelUpload(command.jobId),
          failure: "取消上传失败",
        };
      case "dismissUpload":
        return {
          key: `tray:dismissUpload:${command.jobId}`,
          run: () => backend.dismissUpload(command.jobId),
          failure: "清除上传任务失败",
        };
    }
  }

  /* ---- settings ---- */

  function openStorageSettings(): Promise<unknown> {
    return runner.run({
      key: "storage:readForSettings",
      run: () => backend.getStorageConfig(),
      commit: ({ revision, value: config }) => {
        commit({ type: "storage/loaded", revision, storage: config });
        view.renderDownloadRootLabel(state());
        view.openStorageSettings(config);
      },
    });
  }

  function openDownloadRootSettings(): Promise<unknown> {
    return runner.run({
      key: "storage:readForDownloadRoot",
      run: () => backend.getStorageConfig(),
      commit: ({ revision, value: config }) => {
        commit({ type: "storage/loaded", revision, storage: config });
        view.renderDownloadRootLabel(state());
        view.openDownloadRootSettings(config);
      },
    });
  }

  /* ------------------------------------------------------------------ */
  /* removable media workspace                                           */
  /* ------------------------------------------------------------------ */

  function mediaScanValue(): MediaScanSnapshot | null {
    if (mediaRuntime === null) return null;
    const resource = mediaRuntime.store.getState().scan;
    return resource.value ?? resource.lastGood;
  }

  function mediaRuntimeCandidates(): readonly ScanCandidate[] {
    return mediaScanValue()?.candidates ?? [];
  }

  function inferredMediaSourceKind(mediaId: string, candidates: readonly ScanCandidate[]): MediaAcquisitionSourceKind {
    const sourceKinds = candidates
      .filter((candidate) => String(candidate.mediaId) === mediaId)
      .map((candidate) => candidate.sourceKind);
    if (sourceKinds.includes("local_folder")) return "local_folder";
    if (sourceKinds.includes("legacy_removable_media")) return "legacy_removable_media";
    return "removable_media";
  }

  function rememberMediaSources(scan: MediaScanSnapshot, selectedPath: string | null): void {
    const candidates = scan.candidates;
    commit({
      type: "ui/mediaSourcesRemembered",
      sources: scan.media.map((media) => ({
        id: String(media.id),
        kind: selectedPath === null ? inferredMediaSourceKind(String(media.id), candidates) : "local_folder",
        path: selectedPath ?? media.mountPath,
      })),
    });
  }

  function runMediaScan(
    request: ScanRequest,
    capture: ViewCapture,
    generation: number,
    selectedPath: string | null,
  ): void {
    const runtime = mediaRuntime;
    if (runtime === null) return;
    void runtime.scan(request).then((result) => {
      if (disposed || generation !== mediaFolderGeneration || !capture.isCurrent()) return;
      if (result.status !== "completed") return;
      rememberMediaSources(result.value.value, selectedPath);
      paintMedia();
    });
  }

  function mediaIssueFromError(error: unknown): MediaIssue {
    if (error !== null && typeof error === "object") {
      const candidate = error as { readonly mediaError?: unknown };
      const value = candidate.mediaError;
      if (
        value !== null &&
        typeof value === "object" &&
        typeof (value as { readonly code?: unknown }).code === "string" &&
        typeof (value as { readonly message?: unknown }).message === "string" &&
        typeof (value as { readonly retryable?: unknown }).retryable === "boolean"
      ) {
        return value as MediaIssue;
      }
    }
    return { code: "media_unavailable", message: describeMediaBackendError(error), retryable: true };
  }

  function mediaPhysicalOverride(kind: "release" | "eject", error: unknown): MediaReleaseSnapshot {
    const issue = mediaIssueFromError(error);
    return kind === "release" ? { kind: "release_failed", issue } : { kind: "eject_failed", issue };
  }

  function mediaSourceSnapshot(sourceId: string): MediaWorkspaceSnapshot["sources"][number] | null {
    return mediaSnapshot()?.sources.find((source) => source.id === sourceId) ?? null;
  }

  function invalidatePendingMediaUi(): void {
    mediaFolderGeneration += 1;
    mediaBatchGeneration += 1;
    const batch = ui().mediaBatch;
    if (batch !== null && !batch.canDismiss) commit({ type: "ui/mediaBatchClear", batchId: batch.id });
  }

  function mediaBatchStartedAtLabel(): string {
    return new Date(clock.now()).toISOString();
  }

  function mediaBatchFailure(
    id: string,
    startedAtLabel: string,
    candidates: readonly MediaCandidateSnapshot[],
    error: unknown,
  ): MediaBatchSnapshot {
    const issue = mediaIssueFromError(error);
    const itemOutcome: MediaBatchItemOutcome = {
      kind: "failed",
      detail: issue.message,
      retryable: issue.retryable,
    };
    return {
      id,
      state: "failed",
      startedAtLabel,
      items: candidates.map((candidate) => ({
        candidateId: candidate.id,
        sourceKey: candidate.sourceKey,
        displayName: candidate.displayName,
        outcome: itemOutcome,
      })),
      operationIssue: issue,
      canCancel: false,
      canDismiss: true,
    };
  }

  function pipelineIdPairsForBatch(batch: MediaBatchSnapshot): readonly { candidateId: string; pipelineId: string }[] {
    if (mediaRuntime === null) return [];
    const values =
      mediaRuntime.store.getState().pipelines.value ?? mediaRuntime.store.getState().pipelines.lastGood ?? [];
    const bySourceKey = new Map(
      values.map((pipeline) => [pipeline.sourceSummary.sourceKey, String(pipeline.id)] as const),
    );
    return batch.items.flatMap((item) => {
      const pipelineId = bySourceKey.get(item.sourceKey);
      return pipelineId !== undefined && ui().mediaBatchPipelineIds.has(pipelineId)
        ? [{ candidateId: item.candidateId, pipelineId }]
        : [];
    });
  }

  function startMediaPipelineBatch(candidateIds: readonly string[]): void {
    const runtime = mediaRuntime;
    if (runtime === null) {
      toast("介质运行时不可用", "danger");
      return;
    }
    const snapshot = mediaSnapshot();
    if (snapshot === null) return;
    const runtimeCandidates = mediaRuntimeCandidates();
    const uniqueIds = [...new Set(candidateIds)];
    const selected = snapshot.candidates.filter(
      (candidate) => uniqueIds.includes(candidate.id) && candidate.selectable,
    );
    if (selected.length !== uniqueIds.length) {
      toast("部分会话已不可导入，请重新扫描后再试", "danger");
      return;
    }
    if (selected.length === 0) return;
    if (selected.length > 256) {
      toast("单批最多导入 256 个会话", "danger");
      return;
    }

    const selectedIds = selected.map((candidate) => candidate.id);
    const requiresUnsignedApproval = selected.some(
      (candidate) => candidate.verdict.kind === "ready_unsigned_requires_policy",
    );
    const armedSelection = ui().mediaUnsignedApprovalCandidateIds;
    const exactSelectionArmed =
      armedSelection.size === selectedIds.length && selectedIds.every((candidateId) => armedSelection.has(candidateId));
    if (requiresUnsignedApproval && !exactSelectionArmed) {
      commit({ type: "ui/mediaUnsignedApprovalArm", candidateIds: selectedIds });
      paintMedia();
      return;
    }
    commit({ type: "ui/mediaUnsignedApprovalClear" });

    const generation = ++mediaBatchGeneration;
    const capture = viewGuard.capture();
    const batchId = `media-batch-${++mediaBatchSequence}`;
    const startedAtLabel = mediaBatchStartedAtLabel();
    const pending: MediaBatchSnapshot = {
      id: batchId,
      state: "running",
      startedAtLabel,
      items: selected.map((candidate) => ({
        candidateId: candidate.id,
        sourceKey: candidate.sourceKey,
        displayName: candidate.displayName,
        outcome: { kind: "processing" as const, detail: "正在提交本地导入任务" },
      })),
      operationIssue: null,
      canCancel: false,
      canDismiss: false,
    };
    commit({ type: "ui/mediaBatchSet", batch: pending, pipelineIds: [] });
    paintMedia();

    const requests: readonly StartPipelineRequest[] = selected.map((candidate) => ({
      candidateId: asCandidateId(candidate.id),
      approveUnsigned: candidate.verdict.kind === "ready_unsigned_requires_policy",
      policy: IMPORT_ONLY_PIPELINE_POLICY,
    }));
    void runtime.startPipelineBatch(requests).then((result) => {
      if (disposed || generation !== mediaBatchGeneration || !capture.isCurrent()) return;
      if (result.status === "superseded") return;
      if (result.status === "failed") {
        commit({
          type: "ui/mediaBatchSet",
          batch: mediaBatchFailure(batchId, startedAtLabel, selected, result.error),
          pipelineIds: [],
        });
        paintMedia();
        return;
      }
      const outcome = result.value.outcome.value;
      // Keep the identity facts from the scan that produced this request. The
      // card may disappear before the command resolves, but the batch must
      // still reconcile through the stable source key rather than an obsolete
      // candidate generation ID.
      const projected = projectPipelineBatch(batchId, startedAtLabel, outcome, runtimeCandidates);
      const pipelineIds = outcome.results.filter((item) => item.status === "success").map((item) => String(item.jobId));
      commit({ type: "ui/mediaBatchSet", batch: projected, pipelineIds });
      commit({
        type: "ui/mediaCandidateSelectionMany",
        candidateIds: selected.map((candidate) => candidate.id),
        selected: false,
      });
      paintMedia();
    });
  }

  function cancelMediaBatch(batchId: string): void {
    const runtime = mediaRuntime;
    if (runtime === null) return;
    const batch = ui().mediaBatch;
    if (batch === null || batch.id !== batchId || !batch.canCancel) return;
    const generation = ++mediaBatchGeneration;
    const capture = viewGuard.capture();
    const pairs = pipelineIdPairsForBatch(batch);
    if (pairs.length === 0) {
      commit({
        type: "ui/mediaBatchSet",
        batch: { ...batch, state: "cancelled", canCancel: false, canDismiss: true },
        pipelineIds: [],
      });
      paintMedia();
      return;
    }
    void Promise.all(
      pairs.map(async (pair) => ({
        pair,
        result: await runtime.commandPipeline(asPipelineId(pair.pipelineId), "cancel"),
      })),
    ).then((settled) => {
      if (disposed || generation !== mediaBatchGeneration || !capture.isCurrent() || ui().mediaBatch?.id !== batchId)
        return;
      const outcomes = new Map<string, MediaBatchItemOutcome>();
      for (const { pair, result } of settled) {
        if (result.status === "completed")
          outcomes.set(pair.candidateId, { kind: "succeeded", detail: "已提交取消请求" });
        else if (result.status === "failed") {
          const issue = mediaIssueFromError(result.error);
          outcomes.set(pair.candidateId, { kind: "failed", detail: issue.message, retryable: issue.retryable });
        }
      }
      commit({
        type: "ui/mediaBatchSet",
        batch: {
          ...batch,
          state: "cancelled",
          items: batch.items.map((item) => ({ ...item, outcome: outcomes.get(item.candidateId) ?? item.outcome })),
          canCancel: false,
          canDismiss: true,
        },
        pipelineIds: [],
      });
      paintMedia();
    });
  }

  function dismissMediaBatch(batchId: string): void {
    if (ui().mediaBatch?.id !== batchId) return;
    ++mediaBatchGeneration;
    commit({ type: "ui/mediaBatchClear", batchId });
    paintMedia();
  }

  function mediaJobCommand(action: Extract<MediaWorkspaceAction, { readonly kind: "media/jobCommand" }>): void {
    if (mediaRuntime === null) return;
    if (action.jobKind === "import") {
      void mediaRuntime.commandImport(asImportJobId(action.jobId), action.command as RuntimeMediaJobCommand);
      return;
    }
    if (action.jobKind === "derivation" || action.jobKind === "validation") {
      void mediaRuntime.commandDerivation(asDerivationJobId(action.jobId), action.command as RuntimeMediaJobCommand);
      return;
    }
    void mediaRuntime.commandPipeline(asPipelineId(action.pipelineId), action.command as PipelineCommand);
  }

  function approveUnsignedMediaUpload(pipelineId: string): void {
    if (mediaRuntime === null) return;
    void mediaRuntime.commandPipeline(asPipelineId(pipelineId), "approve_unsigned_upload");
  }

  function revokeTrustedProducer(keyFingerprint: string): void {
    if (mediaRuntime === null) return;
    void mediaRuntime.revokeTrustedProducer(keyFingerprint).then((result) => {
      if (disposed || result.status !== "completed") return;
      if (result.value.revoked) {
        toast("已撤销该来源的本机信任；重新扫描后会重新评估准入", "success");
        scanAllMedia();
      } else {
        toast("该来源当前没有活动信任记录", "success");
      }
    });
  }

  function exportMediaLibraryEntry(entryKey: string): void {
    if (mediaRuntime === null) return;
    void mediaRuntime.exportLibraryEntry(entryKey).then((result) => {
      if (disposed || result.status !== "completed") return;
      if (result.value.status === "completed") {
        toast(`已导出 MP4：${result.value.outputPath}`, "success");
      }
    });
  }

  function scanAllMedia(): void {
    if (mediaRuntime === null) return;
    const generation = ++mediaFolderGeneration;
    const capture = viewGuard.capture();
    runMediaScan({ source: { kind: "mounted_volumes" } }, capture, generation, null);
  }

  function rescanMediaSource(sourceId: string): void {
    if (mediaRuntime === null) return;
    const source = mediaSourceSnapshot(sourceId);
    if (source === null) return;
    const generation = ++mediaFolderGeneration;
    const capture = viewGuard.capture();
    if (source.kind === "local_folder") {
      const scan = mediaScanValue();
      const descriptor = scan?.media.find((media) => String(media.id) === sourceId);
      const path = ui().mediaSourcePathById.get(sourceId) ?? descriptor?.mountPath ?? null;
      if (path === null || path === "") {
        toast("找不到已选择的目录，请重新选择目录", "danger");
        return;
      }
      runMediaScan({ source: { kind: "selected_folder", path } }, capture, generation, path);
      return;
    }
    runMediaScan({ source: { kind: "mounted_volumes" } }, capture, generation, null);
  }

  function releaseMediaSource(sourceId: string): void {
    if (mediaRuntime === null) return;
    const source = mediaSourceSnapshot(sourceId);
    if (source === null || source.kind === "local_folder") return;
    const generation = (mediaPhysicalGeneration.get(sourceId) ?? 0) + 1;
    mediaPhysicalGeneration.set(sourceId, generation);
    commit({ type: "ui/mediaReleaseOverride", sourceId, release: { kind: "releasing" } });
    paintMedia();
    void mediaRuntime.releaseMediaHandles(asMediaId(sourceId)).then((result) => {
      if (disposed || mediaPhysicalGeneration.get(sourceId) !== generation) return;
      if (result.status === "completed") {
        commit({ type: "ui/mediaReleaseOverride", sourceId, release: null });
      } else if (result.status === "failed") {
        commit({ type: "ui/mediaReleaseOverride", sourceId, release: mediaPhysicalOverride("release", result.error) });
      }
      if (ui().view === "media") paintMedia();
    });
  }

  function ejectMediaSource(sourceId: string): void {
    if (mediaRuntime === null) return;
    const source = mediaSourceSnapshot(sourceId);
    if (source === null || source.kind === "local_folder") return;
    const generation = (mediaPhysicalGeneration.get(sourceId) ?? 0) + 1;
    mediaPhysicalGeneration.set(sourceId, generation);
    commit({ type: "ui/mediaReleaseOverride", sourceId, release: { kind: "ejecting" } });
    paintMedia();
    void mediaRuntime.ejectMedia(asMediaId(sourceId)).then((result) => {
      if (disposed || mediaPhysicalGeneration.get(sourceId) !== generation) return;
      if (result.status === "completed") {
        commit({ type: "ui/mediaReleaseOverride", sourceId, release: null });
      } else if (result.status === "failed") {
        commit({ type: "ui/mediaReleaseOverride", sourceId, release: mediaPhysicalOverride("eject", result.error) });
      }
      if (ui().view === "media") paintMedia();
    });
  }

  /* ------------------------------------------------------------------ */
  /* dispatch                                                            */
  /* ------------------------------------------------------------------ */

  function dispatch(action: UiAction): void {
    if (disposed) return;
    switch (action.kind) {
      case "resource/retry":
        void retryResource(action.resource);
        return;

      case "device/select":
        selectDevice(action.deviceId);
        return;
      case "device/reconnect":
        void beginPairing(action.deviceId);
        return;
      case "device/disconnect":
        disconnectDevice(action.deviceId);
        return;
      case "device/refreshSessions":
        void deviceNavigation.refresh(action.deviceId).then((outcome) => {
          if (outcome === "applied") toast("已刷新会话列表", "success");
        });
        return;
      case "media/open":
        if (mediaRuntime === null) return;
        if (ui().view !== "media") {
          invalidatePendingMediaUi();
          deviceNavigation.invalidate();
          viewGuard.invalidate();
          commit({ type: "ui/view", view: "media" });
        }
        paintRail();
        paintNav();
        paintMedia();
        return;
      case "library/open": {
        invalidatePendingMediaUi();
        deviceNavigation.invalidate();
        viewGuard.invalidate();
        commit({ type: "ui/view", view: "library" });
        paintRail();
        paintNav();
        paintTopbar();
        paintContent();
        // Paint the cached library immediately; filesystem reconciliation is a
        // background refresh and must never delay the navigation frame.
        void afterNextPaint().then(() => reconcileLibraryFromDisk(true));
        return;
      }
      case "library/reconcile":
        void reconcileLibraryFromDisk(action.force);
        return;

      case "media/scanAll":
        scanAllMedia();
        return;
      case "media/rescanSource":
        rescanMediaSource(action.sourceId);
        return;
      case "media/releaseSource":
        releaseMediaSource(action.sourceId);
        return;
      case "media/ejectSource":
        ejectMediaSource(action.sourceId);
        return;
      case "media/retryResource":
        if (mediaRuntime !== null) {
          void mediaRuntime.retry(action.resource).then(() => {
            if (!disposed && ui().view === "media") paintMedia();
          });
        }
        return;
      case "media/revokeTrustedProducer":
        revokeTrustedProducer(action.keyFingerprint);
        return;
      case "media/exportLibraryEntry":
        exportMediaLibraryEntry(action.entryKey);
        return;
      case "media/toggleCandidateDetails":
        commit({ type: "ui/mediaCandidateExpanded", candidateId: action.candidateId });
        paintMedia();
        return;
      case "media/candidateSelectionChange":
        commit({ type: "ui/mediaCandidateSelection", candidateId: action.candidateId, selected: action.selected });
        paintMedia();
        return;
      case "media/allCandidateSelectionChange": {
        const candidates = mediaSnapshot()?.candidates.filter((candidate) => candidate.selectable) ?? [];
        commit({
          type: "ui/mediaCandidateSelectionMany",
          candidateIds: candidates.map((candidate) => candidate.id),
          selected: action.selected,
        });
        paintMedia();
        return;
      }
      case "media/importSelected":
        startMediaPipelineBatch(action.candidateIds);
        return;
      case "media/configureStorage":
        void openStorageSettings();
        return;
      case "media/approveUnsignedUpload":
        approveUnsignedMediaUpload(action.pipelineId);
        return;
      case "media/jobCommand":
        mediaJobCommand(action);
        return;
      case "media/cancelBatch":
        cancelMediaBatch(action.batchId);
        return;
      case "media/dismissBatch":
        dismissMediaBatch(action.batchId);
        return;

      case "pairing/cancel": {
        const target = ui().pairingTargetId;
        const attemptId = ui().pairingAttemptId;
        if (target === null || attemptId === null) return;
        void runner.run({
          key: `device:cancelPairing:${target}:${attemptId}`,
          run: () => backend.cancelPairing(asDeviceId(target), asPairingAttemptId(attemptId)),
          commit: () => {
            // Only close the flow this cancel actually belongs to.
            if (ui().pairingTargetId !== target || ui().pairingAttemptId !== attemptId) return;
            closePairingFlow();
          },
        });
        return;
      }
      case "device/openAdd":
        view.openAddDevice();
        return;
      case "device/closeAdd":
        view.closeAddDevice();
        return;
      case "device/submitAdd": {
        const ip = action.ip.trim();
        if (!ip) {
          toast("请输入 IP 地址", "danger");
          return;
        }
        toast(`正在探测 ${ip} 的 TLS 身份`, "success");
        void runner.run({
          key: `device:add:${ip}`,
          run: () => backend.addManualDevice(ip),
          commit: ({ revision, value: device }) => {
            const devices = devicesOf(state()).filter((candidate) => candidate.id !== device.id);
            devices.push(device);
            commit({ type: "devices/loaded", revision, devices });
            view.closeAddDevice();
            paintRail();
            void beginPairing(asDeviceId(device.id));
          },
        });
        return;
      }

      case "device/downloadAllNew":
        downloadAllNew(action.deviceId);
        return;
      case "device/cleanupBackedUp":
        cleanupBackedUp(action.deviceId);
        return;
      case "device/cleanupDownloaded":
        void cleanupDownloaded(action.deviceId);
        return;
      case "library/uploadAllPending":
        void uploadAllPending();
        return;

      case "list/filter":
        commit({ type: "ui/filter", scope: action.scope, patch: action.patch });
        paintList();
        return;
      case "list/toggleSort":
        commit({
          type: "ui/filter",
          scope: action.scope,
          patch: { sortDesc: !filterFor(ui(), action.scope).sortDesc },
        });
        paintList();
        return;
      case "list/toggleRow":
        commit({ type: "ui/toggleRow", key: action.rowKey });
        paintList();
        return;
      case "list/select":
        commit({ type: "ui/select", scope: action.scope, key: action.key, selected: action.selected });
        paintList();
        return;
      case "list/selectAll":
        commit({
          type: "ui/selectMany",
          scope: action.scope,
          keys: [...activeList().visibleKeys],
          selected: action.selected,
        });
        paintList();
        return;
      case "list/clearSelection":
        commit({ type: "ui/clearSelection", scope: action.scope });
        // Only the bulk confirmation for this scope is disarmed; a row's own
        // pending confirmation belongs to that row.
        confirm.clear(
          action.scope === "device"
            ? confirmTargets.deviceBulkRemove(ui().activeDeviceId ?? "")
            : confirmTargets.libraryBulkRemove(),
        );
        paintList();
        return;
      case "list/bulkAction":
        void runBulkAction(action.scope);
        return;
      case "list/bulkRemove":
        void runBulkRemove(action.scope);
        return;

      case "session/download":
        void runner.run({
          key: `device:download:${action.deviceId}:${action.sessionId}`,
          run: () => backend.downloadSession(action.deviceId, action.sessionId),
        });
        return;
      case "session/downloadFile":
        void runner.run({
          key: `device:downloadFile:${action.deviceId}:${action.sessionId}:${action.fileId}`,
          run: () => backend.downloadFile(action.deviceId, action.sessionId, action.fileId),
        });
        return;
      case "session/remove":
        removeSession(action.deviceId, action.sessionId);
        return;
      case "entry/upload":
        void runner.run({ key: `library:upload:${action.key}`, run: () => backend.uploadEntry(action.key) });
        return;
      case "entry/revealFile":
        void runner.run({
          key: `library:reveal:${action.key}:${action.fileId}`,
          run: () => backend.revealLibraryFile(action.key, action.fileId),
          success: () => "已在文件管理器中定位",
        });
        return;
      case "entry/remove":
        removeEntry(action.key);
        return;

      case "tray/toggle":
        commit({ type: "ui/trayCollapsed", collapsed: !ui().transferTrayCollapsed });
        paintTray();
        return;
      case "tray/command":
        runTrayCommand(action.command);
        return;

      case "settings/openStorage":
        void openStorageSettings();
        return;
      case "settings/closeStorage":
        view.closeStorageSettings();
        return;
      case "settings/testStorage": {
        if (!action.config.endpoint || !action.config.bucket) {
          toast("Endpoint 和 Bucket 不能为空", "danger");
          return;
        }
        toast("正在测试连接…", "success");
        const config = action.config;
        void runner.run({
          key: `storage:test:${storageConfigIntentKey(config)}`,
          scope: "storage:test",
          run: () => backend.testStorageConnection(config),
          success: () => "连接成功",
        });
        return;
      }
      case "settings/saveStorage": {
        const config = action.config;
        if (!config.endpoint || !config.bucket) {
          toast("Endpoint 和 Bucket 不能为空", "danger");
          return;
        }
        const downloadRootChanged = config.downloadRoot !== storageOf(state()).downloadRoot;
        void runner.run({
          key: `storage:save:${storageConfigIntentKey(config)}`,
          scope: "storage:save",
          run: () => backend.saveStorageConfig(config),
          commit: ({ revision, value }) => {
            commit({ type: "storage/loaded", revision, storage: value });
            view.closeStorageSettings();
            toast(downloadRootChanged ? "已保存设置 · 本机保存位置已更新" : "已保存对象存储设置", "success");
            view.renderDownloadRootLabel(state());
            paintTopbar();
            paintContent();
          },
        });
        return;
      }
      case "settings/pickStorageDownloadRoot":
        void runner.run({
          key: "storage:selectDownloadRoot:storageConfig",
          scope: "storage:selectDownloadRoot:storageConfig",
          run: () => backend.selectDownloadRoot(),
          commit: (selected) => {
            if (selected !== null) view.setStorageDownloadRootField(selected);
          },
        });
        return;
      case "settings/openDownloadRoot":
        void openDownloadRootSettings();
        return;
      case "settings/closeDownloadRoot":
        view.closeDownloadRootSettings();
        return;
      case "settings/pickDownloadRoot":
        void runner.run({
          key: "storage:selectDownloadRoot:downloadRoot",
          scope: "storage:selectDownloadRoot:downloadRoot",
          run: () => backend.selectDownloadRoot(),
          commit: (selected) => {
            if (selected !== null) view.setDownloadRootField(selected);
          },
        });
        return;
      case "settings/saveDownloadRoot": {
        const downloadRoot = action.downloadRoot;
        void runner.run({
          key: `storage:saveDownloadRoot:${settingsValueIntentKey(downloadRoot)}`,
          scope: "storage:saveDownloadRoot",
          run: () => backend.saveDownloadRoot(downloadRoot),
          commit: ({ revision, value }) => {
            commit({ type: "storage/loaded", revision, storage: value });
            view.closeDownloadRootSettings();
            view.renderDownloadRootLabel(state());
            paintTopbar();
            paintContent();
          },
          success: () => "已更新本机保存位置",
        });
        return;
      }
      case "settings/setNotifications": {
        const turningOn = action.enabled;
        void runner.run({
          key: `settings:notifications:${settingsValueIntentKey(turningOn)}`,
          scope: "settings:notifications",
          run: () => backend.setNotificationsEnabled(turningOn),
          commit: (granted) => {
            commit({ type: "ui/notify", enabled: granted });
            view.setNotificationsSwitch(granted);
            if (turningOn) toast(granted ? "已开启传输完成通知" : "未获得通知权限", granted ? "success" : "danger");
          },
        });
        return;
      }
      case "settings/setTheme":
        commit({ type: "ui/theme", theme: action.theme });
        view.renderTheme(state());
        return;

      case "updates/open":
        void openUpdateSettings();
        return;
      case "updates/close":
        view.closeUpdateSettings();
        return;
      case "updates/check":
        void checkForUpdate();
        return;
      case "updates/install":
        void installUpdate();
        return;
    }
  }

  /* ------------------------------------------------------------------ */
  /* events + lifecycle                                                  */
  /* ------------------------------------------------------------------ */

  /** Painting for one committed event. The reducer has already decided whether
   * the event was stale and whether anything visible changed. */
  function paintEvent(event: BackendEvent, result: CommitResult): void {
    if (disposed) return;
    switch (event.kind) {
      case "pairingTick":
        handlePairingTick(event.payload);
        return;
      case "pairingResolved":
        handlePairingResolved(event.payload);
        return;
      case "devices": {
        if (!result.changed) return;
        const selectedAfter = deviceById(state(), ui().activeDeviceId);
        paintRail();
        if (ui().view === "device" && !devicePaneSnapshotsEqual(paintedDevice, selectedAfter)) {
          if (selectedAfter?.state !== "connected") deviceNavigation.invalidate();
          paintTopbar();
          paintContent();
        }
        return;
      }
      case "sessions": {
        if (!result.changed) return;
        if (ui().view === "device" && ui().activeDeviceId === event.deviceId) {
          paintTopbar();
          paintContent();
        }
        return;
      }
      case "library": {
        if (!result.changed) return;
        paintNav();
        if (ui().view === "library") {
          paintTopbar();
          paintContent();
        }
        return;
      }
      case "transfers":
      case "transferJobs":
        if (result.changed) paintTraySoon();
        return;
      case "storage":
        if (!result.changed) return;
        view.renderDownloadRootLabel(state());
        if (ui().view === "library") {
          paintTopbar();
          paintContent();
        }
        return;
    }
  }

  async function boot(): Promise<void> {
    if (disposed) return;
    // A user may navigate while the native snapshot is still loading. The
    // automatic focus below is only valid if that initial view scope survived
    // the asynchronous boot; otherwise painting the current view wins.
    const bootCapture = viewGuard.capture();
    view.renderTheme(state());
    if (ui().view === "media") paintAll();

    const runtimeForBoot = mediaRuntime;
    const mediaStarting =
      runtimeForBoot === null
        ? null
        : runtimeForBoot.start().catch((error) => {
            if (!disposed) {
              toast(`介质数据加载失败：${describeMediaBackendError(error)}`, "danger");
              if (ui().view === "media") paintMedia();
            }
          });

    try {
      // Subscribe first and buffer, then read the revisioned snapshot, then
      // replay: no event can be lost, and no older snapshot can overwrite a
      // newer event.
      session = await startBackend({ backend, store, onEvent: paintEvent });
    } catch (error) {
      toast(`应用数据加载失败：${describeBackendError(error)}`, "danger");
      view.showFatal("数据加载失败", "无法读取真实设备或本地资料库状态，请检查错误后重试。");
      return;
    }
    if (disposed) {
      session.dispose();
      session = null;
      return;
    }

    await mediaStarting;
    if (disposed) return;

    view.renderDownloadRootLabel(state());
    renderUpdateSettings();
    view.setNotificationsSwitch(ui().notifyEnabled);

    const alreadyConnected = devicesOf(state()).find((d) => d.state === "connected");
    if (alreadyConnected && ui().view === "device" && bootCapture.isCurrent()) {
      void focusDevice(asDeviceId(alreadyConnected.id));
    } else {
      paintAll();
    }
    paintTray();
  }

  async function start(): Promise<void> {
    if (disposed) return;
    if (startPromise !== null) return startPromise;
    startPromise = boot().finally(() => {
      // A fatal subscribe/mount failure leaves no session to own. Allow an
      // explicit retry after the caller has fixed the environment; successful
      // starts stay idempotent and retain their promise.
      if (session === null && !disposed) startPromise = null;
    });
    return startPromise;
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    ++mediaFolderGeneration;
    ++mediaBatchGeneration;
    session?.dispose();
    session = null;
    mediaRuntime?.dispose();
    trayFrameCancel?.();
    trayFrameCancel = null;
    confirm.dispose();
    view.dispose();
  }

  return { start, dispatch, retryResource, dispose, store };
}
