// Deterministic controller workflows. These tests intentionally use the real
// controller over the in-memory backend and a headless view: no DOM timing or
// native transport can hide a stale navigation result.
import { test } from "node:test";
import assert from "node:assert/strict";

import type { AppUpdateViewModel, AppView } from "./appView";
import { createTransferApp } from "./transferApp";
import type { AppUpdater, AppUpdateProgress, PendingAppUpdate } from "../runtime/appUpdater";
import { createFakeClock } from "../runtime/clock";
import { createMemoryBackend, memoryTransferJob } from "../runtime/memoryBackend";
import { sessionCatalogOf, sessionDetailStateOf, sessionsOf, type AppState } from "../runtime/reducer";
import type { TraySelection } from "../ui/traySelector";
import type { FrameScheduler } from "../ui/renderScheduler";
import { asDeviceId, asLibraryKey, asSessionId } from "../ids";
import { deviceRowKey } from "../store";
import type { LibraryEntry, RpcError, SessionView, StorageConfig } from "../types";
import { BackendError, type TransferBackend } from "../runtime/backend";
import { asCandidateId, asDerivedId, asMediaId, asPipelineId, asSourceId } from "../runtime/media/ids";
import { createMemoryMediaBackend } from "../runtime/media/memoryBackend";
import type { MediaLibraryEntryProjection, MediaScanSnapshot, PipelineSession } from "../runtime/media/types";
import type { MediaWorkspaceSnapshot } from "../ui/media/types";

const DEVICE_A = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DEVICE_B = "ylx-abcdef0198765432abcdef0198765432abcdef0198765432abcdef0198765432";
const DISPLAY_ID = "YLX-ABCDEF01";

function device(id: string, state: "connected" | "idle" = "connected", displayId?: string) {
  return {
    id,
    displayId: displayId ?? (id.startsWith("ylx-") ? `YLX-${id.slice(4, 12).toUpperCase()}` : id),
    ip: "192.0.2.7",
    state,
    lastSeen: null,
  } as const;
}

interface RecordedView {
  appView: AppView;
  views: string[];
  fatal: string[];
  trayRenders: number;
  traySelections: TraySelection[];
  storageDownloadRootFields: string[];
  downloadRootFields: string[];
  mediaSnapshots: MediaWorkspaceSnapshot[];
  updateModels: AppUpdateViewModel[];
  readonly storageSettingsOpens: number;
}

function createRecordedView(): RecordedView {
  const views: string[] = [];
  const fatal: string[] = [];
  const traySelections: TraySelection[] = [];
  const storageDownloadRootFields: string[] = [];
  const downloadRootFields: string[] = [];
  const mediaSnapshots: MediaWorkspaceSnapshot[] = [];
  const updateModels: AppUpdateViewModel[] = [];
  let trayRenders = 0;
  let storageSettingsOpens = 0;
  const record = (state: AppState): void => {
    views.push(state.ui.view);
  };
  const noStorage = (_config: StorageConfig): void => {};
  const appView: AppView = {
    renderRail: record,
    renderNav: record,
    renderTopbar: record,
    renderContent: record,
    renderList: record,
    renderTray: (selection: TraySelection): void => {
      trayRenders += 1;
      traySelections.push(selection);
    },
    renderTheme: record,
    renderDownloadRootLabel: record,
    renderMedia: (snapshot): void => {
      mediaSnapshots.push(snapshot);
    },
    setNotificationsSwitch: (_enabled: boolean): void => {},
    showPairing: (_deviceId: string): void => {},
    updatePairingRing: (_remaining: number, _total: number): void => {},
    hidePairing: (): void => {},
    openAddDevice: (): void => {},
    closeAddDevice: (): void => {},
    openStorageSettings: (_config): void => {
      storageSettingsOpens += 1;
    },
    closeStorageSettings: (): void => {},
    setStorageDownloadRootField: (value: string): void => {
      storageDownloadRootFields.push(value);
    },
    openDownloadRootSettings: noStorage,
    closeDownloadRootSettings: (): void => {},
    setDownloadRootField: (value: string): void => {
      downloadRootFields.push(value);
    },
    openUpdateSettings: (model): void => {
      updateModels.push(model);
    },
    closeUpdateSettings: (): void => {},
    renderUpdateSettings: (model): void => {
      updateModels.push(model);
    },
    confirmDestructive: (_message: string): boolean => false,
    setBusy: (_label: string | null): void => {},
    showFatal: (title: string): void => {
      fatal.push(title);
    },
    dispose: (): void => {},
  };
  return {
    appView,
    views,
    fatal,
    traySelections,
    storageDownloadRootFields,
    downloadRootFields,
    mediaSnapshots,
    updateModels,
    get trayRenders() {
      return trayRenders;
    },
    get storageSettingsOpens() {
      return storageSettingsOpens;
    },
  };
}

function latestUpdateModel(recorded: RecordedView): AppUpdateViewModel | undefined {
  return recorded.updateModels[recorded.updateModels.length - 1];
}

async function until(predicate: () => boolean): Promise<void> {
  for (let count = 0; count < 100; count += 1) {
    if (predicate()) return;
    await Promise.resolve();
  }
  throw new Error("timed out waiting for controller workflow");
}

async function untilTask(predicate: () => boolean): Promise<void> {
  for (let count = 0; count < 100; count += 1) {
    if (predicate()) return;
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for controller task");
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (error: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

function session(id: string): SessionView {
  return {
    id,
    revision: "r1",
    dateLabel: "2026-08-03T00:00:00Z",
    durationSeconds: 12,
    totalBytes: 100,
    videoBytes: 100,
    imuSamples: null,
    files: [],
    downloadStatus: "none",
    backedUp: false,
    verification: {
      verdict: "usable",
      actor: "gateway",
      validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
      manifestSha256: "a".repeat(64),
      verifiedAt: "2026-08-03T00:00:01Z",
      diagnostics: [],
    },
  };
}

function libraryEntry(deviceId: string, sessionId: string, deviceDisplayId = DISPLAY_ID): LibraryEntry {
  return {
    deviceId,
    deviceDisplayId,
    sessionId,
    dateLabel: "2026-08-03T00:00:00Z",
    downloadedAt: "2026-08-03T00:05:00Z",
    bytes: 100,
    files: [],
    complete: true,
    uploadStatus: "none",
    uploadedAt: null,
    uploadError: null,
    uploadRetryable: false,
  };
}

class FakePendingUpdate implements PendingAppUpdate {
  readonly currentVersion: string;
  readonly version: string;
  readonly date = "2026-08-27T00:00:00Z";
  readonly body = "Bridge update";
  closed = false;
  downloads = 0;

  constructor(version = "0.2.0", currentVersion = "0.1.0") {
    this.version = version;
    this.currentVersion = currentVersion;
  }

  async downloadAndInstall(onProgress: (progress: AppUpdateProgress) => void): Promise<void> {
    this.downloads += 1;
    onProgress({ downloadedBytes: 128, totalBytes: 256 });
    onProgress({ downloadedBytes: 256, totalBytes: 256 });
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

function fakeUpdater(update: PendingAppUpdate | null): AppUpdater & { relaunches: number } {
  return {
    relaunches: 0,
    currentVersion: async () => "0.1.0",
    check: async () => update,
    async relaunch(): Promise<void> {
      this.relaunches += 1;
    },
  };
}

function mediaLibraryEntry(entryKey = "media-entry-1"): MediaLibraryEntryProjection {
  return {
    entryKey,
    sourceIdentity: "source-identity-1",
    sourceRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sourceLocal: {
      status: "verified",
      evidence: {
        importReceiptId: "receipt-1",
        importJobId: "import-1",
        relativePath: `sources/${entryKey}`,
        sealedInventoryDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        provenance: {
          kind: "locally_validated_unsigned",
          sourceSchema: "raw_capture_v2",
          validationReportId: null,
          inventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          admission: "approved",
        },
        committedAt: "2026-08-06T00:00:00Z",
      },
    },
    derivedLocal: [],
    uploadBundles: [],
    cardPresence: { status: "unknown" },
  };
}

function unsignedMediaScan(scanId: string): MediaScanSnapshot {
  return {
    scanId,
    status: "complete",
    media: [
      {
        id: asMediaId("media-card-1"),
        displayName: "TF card",
        mountPath: "/media/tf-card",
        filesystem: "ext4",
        presence: "present",
        readerCount: 0,
        handleState: "in_use",
        ejectState: "available",
        ejectVeto: null,
        accessIssue: null,
        observedAt: "2026-08-11T00:00:00Z",
      },
    ],
    candidates: [
      {
        id: asCandidateId("unsigned-candidate-1"),
        sourceKey: "unsigned-source-key-1",
        mediaId: asMediaId("media-card-1"),
        sourceId: null,
        sessionId: "session-1",
        displayName: "Unsigned session",
        relativePath: "YLX/session-1",
        sourceKind: "removable_media",
        schema: "unsigned_publication_v1",
        verdict: "ready_unsigned_requires_policy",
        reason: null,
        provenance: {
          kind: "locally_validated_unsigned",
          sourceSchema: "unsigned_publication_v1",
          validationReportId: "validation-report-1",
          inventoryDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          admission: "required",
        },
        bytes: 1024,
        durationSeconds: 5,
        mediaRequired: true,
      },
    ],
    attachIssue: null,
    completedAt: "2026-08-11T00:00:00Z",
  };
}

function unsignedUploadApprovalPipeline(): PipelineSession {
  return {
    id: asPipelineId("pipeline-unsigned-upload-action"),
    candidateId: asCandidateId("candidate-unsigned-upload-action"),
    sourceSummary: {
      sourceKey: "source-unsigned-upload-action",
      mediaId: asMediaId("media-unsigned-upload-action"),
      sourceId: asSourceId("source-id-unsigned-upload-action"),
      displayName: "Unsigned session awaiting approval",
      sessionId: "session-unsigned-upload-action",
      schema: "unsigned_publication_v1",
      sourceKind: "removable_media",
      provenance: {
        kind: "locally_validated_unsigned",
        sourceSchema: "unsigned_publication_v1",
        validationReportId: "validation-report-1",
        inventoryDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        admission: "approved",
      },
      relativePath: "YLX/session-unsigned-upload-action",
      bytes: 2048,
      durationSeconds: 10,
    },
    policy: {
      autoNormalize: true,
      autoUploadDerived: true,
      uploadSourceVideo: false,
      unsignedUploadApproved: false,
    },
    desiredRunState: "run",
    source: {
      state: "local_verified",
      sourceId: asSourceId("source-id-unsigned-upload-action"),
      jobId: null,
      retentionState: "retained",
      progress: null,
      failure: null,
    },
    derived: {
      state: "derived_verified",
      derivedId: asDerivedId("derived-unsigned-upload-action"),
      jobId: null,
      progress: null,
      validation: null,
      action: null,
      failure: null,
    },
    remote: {
      state: "action_required",
      bundleId: null,
      uploadJobId: null,
      progress: null,
      action: { kind: "approve_unsigned_source", message: "Explicit upload approval is required" },
      failure: null,
    },
    createdAt: "2026-08-11T00:00:00Z",
    updatedAt: "2026-08-11T00:00:00Z",
  };
}

test("D-049 ignores legacy media navigation when production omits its backend", async () => {
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    assert.equal(app.store.getState().ui.view, "device");
    app.dispatch({ kind: "media/open" });
    assert.equal(app.store.getState().ui.view, "device");
  } finally {
    app.dispose();
  }
});

test("unsigned media import requires a second click and resets on selection or card changes", async () => {
  const backend = createMemoryBackend();
  const mediaBackend = createMemoryMediaBackend({ scan: unsignedMediaScan("scan-1") });
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    mediaBackend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  try {
    await app.start();
    const candidateId = "unsigned-candidate-1";
    app.dispatch({ kind: "media/candidateSelectionChange", candidateId, selected: true });

    app.dispatch({ kind: "media/importSelected", candidateIds: [candidateId] });
    assert.equal(mediaBackend.calls.filter((call) => call.name === "startPipelineBatch").length, 0);
    assert.deepEqual([...app.store.getState().ui.mediaUnsignedApprovalCandidateIds], [candidateId]);
    assert.equal(recorded.mediaSnapshots[recorded.mediaSnapshots.length - 1]?.unsignedApprovalArmed, true);

    app.dispatch({ kind: "media/candidateSelectionChange", candidateId, selected: false });
    assert.equal(app.store.getState().ui.mediaUnsignedApprovalCandidateIds.size, 0);
    app.dispatch({ kind: "media/candidateSelectionChange", candidateId, selected: true });
    app.dispatch({ kind: "media/importSelected", candidateIds: [candidateId] });
    assert.equal(mediaBackend.calls.filter((call) => call.name === "startPipelineBatch").length, 0);

    mediaBackend.emit({ kind: "scan", value: unsignedMediaScan("scan-2") });
    assert.equal(app.store.getState().ui.mediaUnsignedApprovalCandidateIds.size, 0);
    app.dispatch({ kind: "media/importSelected", candidateIds: [candidateId] });
    assert.equal(mediaBackend.calls.filter((call) => call.name === "startPipelineBatch").length, 0);

    app.dispatch({ kind: "media/importSelected", candidateIds: [candidateId] });
    await until(() => mediaBackend.calls.some((call) => call.name === "startPipelineBatch"));
    const request = mediaBackend.calls.find((call) => call.name === "startPipelineBatch")?.args[0];
    assert.deepEqual(request, [
      {
        candidateId,
        approveUnsigned: true,
        policy: {
          autoNormalize: false,
          autoUploadDerived: false,
          uploadSourceVideo: false,
          unsignedUploadApproved: false,
        },
      },
    ]);
  } finally {
    app.dispose();
  }
});

test("media configure-storage action opens the existing storage settings", async () => {
  const backend = createMemoryBackend();
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "media/configureStorage" });
    await until(() => recorded.storageSettingsOpens === 1);
    assert.equal(backend.callNames().filter((name) => name === "getStorageConfig").length, 1);
  } finally {
    app.dispose();
  }
});

test("application updater checks, downloads, installs and relaunches from the settings modal", async () => {
  const recorded = createRecordedView();
  const updaterUpdate = new FakePendingUpdate();
  const updater = fakeUpdater(updaterUpdate);
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    updater,
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "updates/open" });
    await until(() => recorded.updateModels.some((model) => model.currentVersion === "0.1.0"));

    app.dispatch({ kind: "updates/check" });
    await until(() => recorded.updateModels.some((model) => model.availableVersion === "0.2.0" && model.canInstall));

    app.dispatch({ kind: "updates/install" });
    await until(() => updater.relaunches === 1);

    assert.ok(recorded.updateModels.some((model) => model.progressLabel === "50% · 128 B / 256 B"));
    assert.ok(recorded.updateModels.some((model) => model.message === "更新已安装，正在重启"));
    assert.equal(updaterUpdate.closed, true);
  } finally {
    app.dispose();
  }
});

test("application updater atomically coalesces rapid checks and installs", async () => {
  const recorded = createRecordedView();
  const checkResult = deferred<PendingAppUpdate | null>();
  const update = new FakePendingUpdate();
  let checks = 0;
  const updater: AppUpdater = {
    currentVersion: async () => "0.1.0",
    check: () => {
      checks += 1;
      return checkResult.promise;
    },
    relaunch: async () => {},
  };
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    updater,
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "updates/check" });
    app.dispatch({ kind: "updates/check" });
    assert.equal(latestUpdateModel(recorded)?.checking, true);
    await until(() => checks === 1);

    checkResult.resolve(update);
    await until(() => latestUpdateModel(recorded)?.canInstall === true);
    app.dispatch({ kind: "updates/install" });
    app.dispatch({ kind: "updates/install" });
    await until(() => update.closed);
    assert.equal(update.downloads, 1);
  } finally {
    app.dispose();
  }
});

test("application updater keeps an active install owned when its modal closes", async () => {
  class BlockingPendingUpdate extends FakePendingUpdate {
    private readonly completion: Promise<void>;

    constructor(completion: Promise<void>) {
      super();
      this.completion = completion;
    }

    override async downloadAndInstall(onProgress: (progress: AppUpdateProgress) => void): Promise<void> {
      this.downloads += 1;
      onProgress({ downloadedBytes: 128, totalBytes: 256 });
      await this.completion;
    }
  }

  const recorded = createRecordedView();
  const completion = deferred<void>();
  const update = new BlockingPendingUpdate(completion.promise);
  let checks = 0;
  let relaunches = 0;
  const updater: AppUpdater = {
    currentVersion: async () => "0.1.0",
    check: async () => {
      checks += 1;
      return update;
    },
    relaunch: async () => {
      relaunches += 1;
    },
  };
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    updater,
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "updates/check" });
    await until(() => latestUpdateModel(recorded)?.canInstall === true);
    app.dispatch({ kind: "updates/install" });
    await until(() => update.downloads === 1);

    app.dispatch({ kind: "updates/close" });
    await Promise.resolve();
    assert.equal(update.closed, false, "closing the modal must not release an active updater handle");

    app.dispatch({ kind: "updates/check" });
    await Promise.resolve();
    assert.equal(checks, 1, "an active install must exclude a second update check");

    completion.resolve();
    await until(() => relaunches === 1);
    assert.equal(update.closed, true, "the updater handle closes after downloadAndInstall completes");
    assert.equal(latestUpdateModel(recorded)?.message, "更新已安装，正在重启");
  } finally {
    app.dispose();
  }
});

test("application updater closes stale check results and keeps the newest generation", async () => {
  const recorded = createRecordedView();
  const first = deferred<PendingAppUpdate | null>();
  const second = deferred<PendingAppUpdate | null>();
  const staleUpdate = new FakePendingUpdate("0.2.0");
  const currentUpdate = new FakePendingUpdate("0.3.0");
  let checks = 0;
  const updater: AppUpdater = {
    currentVersion: async () => "0.1.0",
    check: () => {
      const result = checks === 0 ? first.promise : second.promise;
      checks += 1;
      return result;
    },
    relaunch: async () => {},
  };
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    updater,
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "updates/check" });
    await until(() => checks === 1);
    app.dispatch({ kind: "updates/close" });
    app.dispatch({ kind: "updates/check" });
    await until(() => checks === 2);

    second.resolve(currentUpdate);
    await until(() => latestUpdateModel(recorded)?.availableVersion === "0.3.0");
    first.resolve(staleUpdate);
    await until(() => staleUpdate.closed);
    assert.equal(latestUpdateModel(recorded)?.availableVersion, "0.3.0");
    assert.equal(currentUpdate.closed, false);
  } finally {
    app.dispose();
  }
  await until(() => currentUpdate.closed);
});

test("application updater closes a handle returned after app disposal without repainting", async () => {
  const recorded = createRecordedView();
  const checkResult = deferred<PendingAppUpdate | null>();
  const lateUpdate = new FakePendingUpdate();
  let checks = 0;
  const updater: AppUpdater = {
    currentVersion: async () => "0.1.0",
    check: () => {
      checks += 1;
      return checkResult.promise;
    },
    relaunch: async () => {},
  };
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    updater,
    view: () => recorded.appView,
  });

  await app.start();
  app.dispatch({ kind: "updates/check" });
  await until(() => checks === 1);
  const paintsBeforeDispose = recorded.updateModels.length;
  app.dispose();
  checkResult.resolve(lateUpdate);
  await until(() => lateUpdate.closed);
  assert.equal(recorded.updateModels.length, paintsBeforeDispose);
});

test("application updater treats missing metadata as a source failure, not current", async () => {
  const recorded = createRecordedView();
  const toasts: string[] = [];
  const updater: AppUpdater = {
    currentVersion: async () => "0.1.0",
    check: async () => {
      throw new Error("Download request failed with status: 404 NotFound");
    },
    relaunch: async () => {},
  };
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: (message) => toasts.push(message),
    updater,
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "updates/check" });
    await until(() => latestUpdateModel(recorded)?.error?.includes("HTTP 404") === true);
    assert.equal(latestUpdateModel(recorded)?.checked, false);
    assert.ok(latestUpdateModel(recorded)?.message !== "已是最新版本");
    assert.ok(toasts.some((message) => message.includes("更新源文件不存在")));
  } finally {
    app.dispose();
  }
});

test("application updater surfaces signature verification failure and permits a normal retry", async () => {
  class SignatureFailureUpdate extends FakePendingUpdate {
    override async downloadAndInstall(): Promise<void> {
      this.downloads += 1;
      throw new Error("updater signature verification failed");
    }
  }

  const recorded = createRecordedView();
  const update = new SignatureFailureUpdate();
  const updater = fakeUpdater(update);
  const app = createTransferApp({
    backend: createMemoryBackend(),
    clock: createFakeClock(),
    toast: () => {},
    updater,
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "updates/check" });
    await until(() => latestUpdateModel(recorded)?.canInstall === true);
    app.dispatch({ kind: "updates/install" });
    await until(() => latestUpdateModel(recorded)?.error?.includes("更新签名验证失败") === true);
    assert.equal(latestUpdateModel(recorded)?.canCheck, true);

    app.dispatch({ kind: "updates/check" });
    await until(() => update.closed);
  } finally {
    app.dispose();
  }
});

test("media unsigned-upload approval sends the dedicated pipeline command", async () => {
  const backend = createMemoryBackend();
  const pipeline = unsignedUploadApprovalPipeline();
  const mediaBackend = createMemoryMediaBackend({ pipelines: [pipeline] });
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    mediaBackend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "media/approveUnsignedUpload", pipelineId: String(pipeline.id) });
    await until(() => mediaBackend.calls.some((call) => call.name === "commandPipeline"));
    assert.deepEqual(mediaBackend.calls.find((call) => call.name === "commandPipeline")?.args, [
      pipeline.id,
      "approve_unsigned_upload",
    ]);
  } finally {
    app.dispose();
  }
});

test("media library export action calls the media runtime and reports the completed output path", async () => {
  const backend = createMemoryBackend();
  const mediaBackend = createMemoryMediaBackend({
    library: [mediaLibraryEntry()],
    exportLibraryEntryResult: {
      status: "completed",
      outputPath: "/exports/session-1.mp4",
      videoSegmentCount: 2,
      audioSegmentCount: 1,
      outputSizeBytes: 4096,
    },
  });
  const recorded = createRecordedView();
  const toasts: { readonly message: string; readonly tone: "success" | "danger" }[] = [];
  const app = createTransferApp({
    backend,
    mediaBackend,
    clock: createFakeClock(),
    toast: (message, tone) => {
      toasts.push({ message, tone });
    },
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "media/exportLibraryEntry", entryKey: "media-entry-1" });
    await until(() => mediaBackend.calls.some((call) => call.name === "exportLibraryEntry"));
    await until(() => toasts.some((toast) => toast.message === "已导出 MP4：/exports/session-1.mp4"));

    assert.deepEqual(mediaBackend.calls.find((call) => call.name === "exportLibraryEntry")?.args, ["media-entry-1"]);
    assert.deepEqual(toasts[toasts.length - 1], {
      message: "已导出 MP4：/exports/session-1.mp4",
      tone: "success",
    });
  } finally {
    app.dispose();
  }
});

test("boot completion cannot auto-focus over a navigation that happened while loading", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A, "connected", DISPLAY_ID)] } });
  backend.hold("readSnapshot");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  const starting = app.start();
  await until(() => backend.pending("readSnapshot") > 0);
  app.dispatch({ kind: "library/open" });
  backend.release("readSnapshot");
  await starting;

  assert.equal(app.store.getState().ui.view, "library");
  assert.equal(backend.callNames().includes("listSessions"), false, "the cancelled auto-focus never reads a device");
  assert.equal(recorded.fatal.length, 0);
  app.dispose();
});

test("concurrent start calls share one backend subscription and snapshot", async () => {
  const backend = createMemoryBackend();
  backend.hold("readSnapshot");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  const first = app.start();
  const second = app.start();
  await until(() => backend.pending("readSnapshot") > 0);
  assert.equal(backend.callNames().filter((name) => name === "readSnapshot").length, 1);
  backend.release("readSnapshot");
  await Promise.all([first, second]);
  assert.equal(backend.listening.length, 8);
  app.dispose();
});

test("a storage boot error stays degraded while the controller still mounts the device view", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A, "connected", DISPLAY_ID)] } });
  const storageFailure = new BackendError("get_storage_config", "对象存储不可用");
  backend.failCalls("readSnapshot", storageFailure);
  backend.failCalls("getStorageConfig", storageFailure);
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();

  assert.equal(recorded.fatal.length, 0);
  assert.deepEqual(
    app.store.getState().devices.value?.map((item) => item.id),
    [DEVICE_A],
  );
  assert.equal(app.store.getState().storage.error, "对象存储不可用");
  app.dispose();
});

test("manual device discovery commits the server revision", async () => {
  const backend = createMemoryBackend();
  backend.hold("addManualDevice");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();
  app.dispatch({ kind: "device/submitAdd", ip: "192.0.2.10" });
  await until(() => backend.pending("addManualDevice") === 1);
  backend.release("addManualDevice");
  await until(() => app.store.getState().devices.value?.some((item) => item.ip === "192.0.2.10") === true);

  const devices = app.store.getState().devices;
  assert.equal(devices.revision, 1);
  assert.equal(devices.value?.[0]?.ip, "192.0.2.10");
  app.dispose();
});

test("a fully degraded boot stays mounted and a single resource retry can recover", async () => {
  const backend = createMemoryBackend();
  const snapshotFailure = new BackendError("list_devices", "设备读取暂不可用");
  const devicesFailure = new BackendError("list_devices", "设备读取暂不可用");
  backend.failCalls("readSnapshot", snapshotFailure);
  backend.hold("listDevices");
  backend.failCalls("listLibrary", new BackendError("list_library", "资料库读取暂不可用"));
  backend.failCalls("listTransfers", new BackendError("list_transfers", "队列读取暂不可用"));
  backend.failCalls("getStorageConfig", new BackendError("get_storage_config", "对象存储暂不可用"));
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  const starting = app.start();
  await until(() => backend.pending("listDevices") === 1);
  backend.rejectHeld("listDevices", devicesFailure);
  await starting;

  assert.equal(recorded.fatal.length, 0);
  assert.equal(app.store.getState().devices.error, devicesFailure.message);
  const callsBeforeRetry = backend.callNames();

  const retry = app.retryResource("devices");
  await until(() => backend.pending("listDevices") === 1);
  backend.release("listDevices", [device(DEVICE_A, "connected", DISPLAY_ID)]);
  await retry;

  assert.deepEqual(
    app.store.getState().devices.value?.map((item) => item.id),
    [DEVICE_A],
  );
  assert.equal(app.store.getState().devices.error, null);
  assert.deepEqual(backend.callNames().slice(callsBeforeRetry.length), ["listDevices"]);
  app.dispose();
});

test("degraded boot does not auto-focus a connected event after navigation", async () => {
  const backend = createMemoryBackend();
  backend.failCalls("readSnapshot", new BackendError("list_devices", "设备读取暂不可用"));
  backend.hold("listDevices");
  backend.failCalls("listLibrary", new BackendError("list_library", "资料库读取暂不可用"));
  backend.failCalls("listTransfers", new BackendError("list_transfers", "队列读取暂不可用"));
  backend.failCalls("getStorageConfig", new BackendError("get_storage_config", "对象存储暂不可用"));
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  const starting = app.start();
  await until(() => backend.pending("listDevices") === 1);
  app.dispatch({ kind: "library/open" });
  backend.emit({ kind: "devices", devices: [device(DEVICE_A, "connected", DISPLAY_ID)] });
  backend.rejectHeld("listDevices", new BackendError("list_devices", "设备读取暂不可用"));
  await starting;

  assert.equal(app.store.getState().ui.view, "library");
  assert.equal(backend.callNames().includes("listSessions"), false);
  assert.equal(recorded.fatal.length, 0);
  app.dispose();
});

test("changed storage-save intents supersede instead of being silently deduplicated", async () => {
  const backend = createMemoryBackend();
  backend.hold("saveStorageConfig");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();

  const firstConfig = {
    endpoint: "https://storage.example.test",
    bucket: "first-bucket",
    prefix: "ylx/",
    urlStyle: "virtualHost" as const,
    accessKey: "access-1",
    secretKey: "secret-1",
    downloadRoot: "/downloads/one",
  };
  const changedConfig = { ...firstConfig, bucket: "second-bucket" };

  app.dispatch({ kind: "settings/saveStorage", config: firstConfig });
  await until(() => backend.pending("saveStorageConfig") === 1);
  // The exact same payload still shares its in-flight request.
  app.dispatch({ kind: "settings/saveStorage", config: firstConfig });
  await Promise.resolve();
  assert.equal(backend.pending("saveStorageConfig"), 1);

  // A changed payload is a new intent in the same scope, so it gets its own
  // call and makes the first response ineligible to commit.
  app.dispatch({ kind: "settings/saveStorage", config: changedConfig });
  await until(() => backend.pending("saveStorageConfig") === 2);
  assert.equal(backend.callNames().filter((name) => name === "saveStorageConfig").length, 2);

  backend.releaseLast("saveStorageConfig");
  backend.release("saveStorageConfig");
  assert.equal(backend.callNames().filter((name) => name === "getStorageConfig").length, 0);
  app.dispose();
});

test("concurrent directory pickers keep their requests and field targets distinct", async () => {
  const backend = createMemoryBackend();
  backend.hold("selectDownloadRoot");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();
  app.dispatch({ kind: "settings/pickStorageDownloadRoot" });
  app.dispatch({ kind: "settings/pickDownloadRoot" });
  await until(() => backend.pending("selectDownloadRoot") === 2);
  assert.equal(backend.callNames().filter((name) => name === "selectDownloadRoot").length, 2);

  backend.releaseLast("selectDownloadRoot", "/download-root-modal");
  backend.release("selectDownloadRoot", "/storage-config-form");
  await until(() => recorded.storageDownloadRootFields.length === 1 && recorded.downloadRootFields.length === 1);

  assert.deepEqual(recorded.storageDownloadRootFields, ["/storage-config-form"]);
  assert.deepEqual(recorded.downloadRootFields, ["/download-root-modal"]);
  app.dispose();
});

test("transfer progress events coalesce to one tray render per frame", async () => {
  const backend = createMemoryBackend();
  const recorded = createRecordedView();
  const frameHolder: { current: (() => void) | null } = { current: null };
  const frameScheduler: FrameScheduler = (run) => {
    frameHolder.current = run;
    return () => {
      if (frameHolder.current === run) frameHolder.current = null;
    };
  };
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    frameScheduler,
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();
  const before = recorded.trayRenders;
  const transfer = {
    key: `${DEVICE_A}|s1`,
    label: "s1",
    totalBytes: 100,
    sentBytes: 1,
    state: "running" as const,
    retryable: false,
    error: null,
    direction: "down" as const,
    targetLabel: "本机",
  };
  backend.emit({ kind: "transfers", transfers: [transfer] });
  backend.emit({ kind: "transfers", transfers: [{ ...transfer, sentBytes: 20 }] });
  assert.equal(recorded.trayRenders, before, "two events in one task wait for one frame");
  const flushFrame = frameHolder.current;
  if (flushFrame === null) throw new Error("the progress frame was not scheduled");
  flushFrame();
  assert.equal(recorded.trayRenders, before + 1);
  app.dispose();
});

const RESOURCE_RETRY_CASES = [
  { resource: "devices", call: "listDevices" },
  { resource: "library", call: "listLibrary" },
  { resource: "transfers", call: "listTransfers" },
  { resource: "storageConfig", call: "getStorageConfig" },
] as const;

for (const { resource, call } of RESOURCE_RETRY_CASES) {
  test(`${resource} retry succeeds through its own revisioned read`, async () => {
    const backend = createMemoryBackend();
    const recorded = createRecordedView();
    const app = createTransferApp({
      backend,
      clock: createFakeClock(),
      toast: () => {},
      view: () => recorded.appView,
    });

    await app.start();
    backend.hold(call);
    const retry = app.retryResource(resource);
    await until(() => backend.pending(call) === 1);
    backend.release(call);
    await retry;

    const state = app.store.getState();
    const resourceState =
      resource === "devices"
        ? state.devices
        : resource === "library"
          ? state.library
          : resource === "transfers"
            ? state.transfers
            : state.storage;
    assert.equal(resourceState.loading, false);
    assert.equal(resourceState.error, null);
    assert.equal(backend.callNames().filter((name) => name === call).length, 1);
    app.dispose();
  });

  test(`${resource} retry failure keeps its last good value and does not read other resources`, async () => {
    const backend = createMemoryBackend();
    const failure = new BackendError(call, `${resource} unavailable`);
    backend.failCalls(call, failure);
    const recorded = createRecordedView();
    const app = createTransferApp({
      backend,
      clock: createFakeClock(),
      toast: () => {},
      view: () => recorded.appView,
    });

    await app.start();
    await app.retryResource(resource);

    const state = app.store.getState();
    const resourceState =
      resource === "devices"
        ? state.devices
        : resource === "library"
          ? state.library
          : resource === "transfers"
            ? state.transfers
            : state.storage;
    assert.equal(resourceState.loading, false);
    assert.equal(resourceState.error, failure.message);
    assert.deepEqual(resourceState.value, resourceState.lastGood);
    assert.equal(
      backend.callNames().filter((name) => name === call).length,
      1,
      "a resource retry must not restart the aggregate snapshot or read another resource",
    );
    app.dispose();
  });

  test(`${resource} retry deduplicates an identical in-flight intent`, async () => {
    const backend = createMemoryBackend();
    backend.hold(call);
    const recorded = createRecordedView();
    const app = createTransferApp({
      backend,
      clock: createFakeClock(),
      toast: () => {},
      view: () => recorded.appView,
    });

    await app.start();
    const first = app.retryResource(resource);
    const second = app.retryResource(resource);
    await until(() => backend.pending(call) === 1);
    assert.equal(backend.callNames().filter((name) => name === call).length, 1);
    backend.release(call);
    await Promise.all([first, second]);
    app.dispose();
  });
}

test("a late library retry result updates state but cannot repaint after navigation", async () => {
  const backend = createMemoryBackend();
  backend.hold("listLibrary");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();
  const retry = app.retryResource("library");
  await until(() => backend.pending("listLibrary") === 1);
  app.dispatch({ kind: "library/open" });
  const rendersAfterNavigation = recorded.views.length;
  backend.release("listLibrary");
  await retry;

  assert.equal(app.store.getState().library.error, null);
  assert.equal(recorded.views.length, rendersAfterNavigation, "the stale capture may not repaint the focused view");
  app.dispose();
});

test("a late transfer retry failure is fenced by the newer transfer revision", async () => {
  const backend = createMemoryBackend();
  backend.hold("listTransfers");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();
  const retry = app.retryResource("transfers");
  await until(() => backend.pending("listTransfers") === 1);
  const transfer = {
    key: "newer",
    label: "newer",
    totalBytes: 1,
    sentBytes: 1,
    state: "succeeded" as const,
    retryable: false,
    error: null,
    direction: "down" as const,
    targetLabel: "本机",
  };
  backend.emit({ kind: "transfers", transfers: [transfer] });
  backend.rejectHeld("listTransfers", new BackendError("listTransfers", "late retry failure"));
  await retry;

  assert.equal(app.store.getState().transfers.error, null);
  assert.deepEqual(app.store.getState().transfers.value, [transfer]);
  app.dispose();
});

test("a late devices retry success is dropped when a newer event revision already landed", async () => {
  const backend = createMemoryBackend();
  backend.hold("listDevices");
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  await app.start();
  const retry = app.retryResource("devices");
  await until(() => backend.pending("listDevices") === 1);
  const newer = device("newer");
  backend.emit({ kind: "devices", devices: [newer] });
  backend.release("listDevices", [device("stale-retry")]);
  await retry;

  assert.deepEqual(app.store.getState().devices.value, [newer]);
  assert.equal(app.store.getState().devices.revision, 1);
  app.dispose();
});

test("the application controller carries a paired session through download, tray recovery and library projection", async () => {
  const deviceId = asDeviceId(DEVICE_A);
  const sessionId = asSessionId("s1");
  const connected = device(DEVICE_A, "connected", DISPLAY_ID);
  const catalogSession = session("s1");
  const completedLibraryEntry = libraryEntry(DEVICE_A, "s1", DISPLAY_ID);
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A, "idle", DISPLAY_ID)] } });
  backend.setSessions(DEVICE_A, [catalogSession]);

  const recorded = createRecordedView();
  const pendingFrames: Array<() => void> = [];
  const frameScheduler: FrameScheduler = (run) => {
    pendingFrames.push(run);
    return () => {
      const index = pendingFrames.indexOf(run);
      if (index >= 0) pendingFrames.splice(index, 1);
    };
  };
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    frameScheduler,
    toast: () => {},
    view: () => recorded.appView,
  });

  const flushTrayFrame = (): void => {
    const frame = pendingFrames.shift();
    if (frame === undefined) throw new Error("the tray frame was not scheduled");
    frame();
  };

  try {
    await app.start();
    const bootState = app.store.getState();
    assert.equal(recorded.fatal.length, 0);
    assert.equal(bootState.devices.loading, false);
    assert.equal(bootState.library.loading, false);
    assert.equal(bootState.transfers.loading, false);
    assert.equal(bootState.storage.loading, false);
    assert.deepEqual(
      bootState.devices.value?.map((item) => item.id),
      [DEVICE_A],
    );

    // The idle device follows the same pairing path as a click in the rail.
    app.dispatch({ kind: "device/select", deviceId });
    await until(() => backend.callNames().includes("connectDevice"));
    await until(() => app.store.getState().ui.pairingAttemptId === `attempt-${DEVICE_A}`);

    // A successful resolution is only useful once the device event has made
    // the navigation controller's connected guard true.
    backend.emit({ kind: "devices", devices: [connected] });
    backend.emit({
      kind: "pairingResolved",
      payload: {
        deviceId: DEVICE_A,
        attemptId: `attempt-${DEVICE_A}`,
        outcome: "connected",
        error: null,
      },
    });
    await untilTask(() => backend.callNames().includes("listSessions"));
    await until(() => app.store.getState().sessions.get(DEVICE_A)?.value?.length === 1);
    assert.equal(app.store.getState().ui.view, "device");
    assert.equal(app.store.getState().ui.activeDeviceId, DEVICE_A);
    assert.deepEqual(
      app.store
        .getState()
        .sessions.get(DEVICE_A)
        ?.value?.map((item) => item.id),
      ["s1"],
    );

    // The row action is sent through TransferApp, so the backend sees the
    // same command a real device-screen click would produce.
    app.dispatch({ kind: "session/download", deviceId, sessionId });
    await until(() => backend.callNames().includes("downloadSession"));
    const detailCallIndex = backend.callNames().indexOf("getSessionDetail");
    const downloadCallIndex = backend.callNames().indexOf("downloadSession");
    assert.ok(detailCallIndex >= 0 && detailCallIndex < downloadCallIndex, "detail must be fenced before download");
    const detailCall = backend.calls[detailCallIndex];
    assert.deepEqual(detailCall?.args, [deviceId, sessionId, "r1", `memory-catalog:${DEVICE_A}:1`]);
    const downloadCall = backend.calls.find((call) => call.name === "downloadSession");
    assert.deepEqual(downloadCall?.args, [deviceId, sessionId]);

    const runningJob = memoryTransferJob("job-s1", {
      state: { state: "transferring" },
      desiredRunState: "run",
      sessionId: "s1",
      deviceId: DEVICE_A,
      deviceDisplayId: DISPLAY_ID,
      totalBytes: 100,
      transferredBytes: 20,
      filesTotal: 1,
      filesDone: 0,
    });
    backend.emit({ kind: "transferJobs", jobs: [runningJob] });
    flushTrayFrame();
    const runningSelection = recorded.traySelections[recorded.traySelections.length - 1];
    assert.ok(runningSelection);
    const cancelControl = runningSelection.jobs[0]?.controls.find(
      (control) => control.action === "cancel-transfer-job",
    );
    assert.ok(cancelControl);
    app.dispatch({ kind: "tray/command", command: cancelControl.command });
    await until(() => backend.callNames().includes("cancelTransferJob"));
    const cancelCall = backend.calls.find((call) => call.name === "cancelTransferJob");
    assert.deepEqual(cancelCall?.args, ["job-s1"]);

    const retryableFailure = memoryTransferJob("job-s1", {
      state: { state: "failed", code: "network", retryable: true },
      desiredRunState: "run",
      sessionId: "s1",
      deviceId: DEVICE_A,
      deviceDisplayId: DISPLAY_ID,
      totalBytes: 100,
      transferredBytes: 20,
      filesTotal: 1,
      filesDone: 0,
    });
    backend.emit({ kind: "transferJobs", jobs: [retryableFailure] });
    flushTrayFrame();
    const failedSelection = recorded.traySelections[recorded.traySelections.length - 1];
    assert.ok(failedSelection);
    assert.equal(failedSelection.jobs[0]?.tone, "failed");
    const retryControl = failedSelection.jobs[0]?.controls.find((control) => control.action === "retry-transfer");
    assert.ok(retryControl);
    app.dispatch({ kind: "tray/command", command: retryControl.command });
    await until(() => backend.callNames().includes("retryTransfer"));
    const retryCall = backend.calls.find((call) => call.name === "retryTransfer");
    assert.deepEqual(retryCall?.args, ["job-s1"]);

    // Completion and the local projection arrive as independent backend
    // events; the application keeps both resources authoritative.
    backend.emit({
      kind: "transferJobs",
      jobs: [
        memoryTransferJob("job-s1", {
          state: { state: "succeeded" },
          desiredRunState: "run",
          sessionId: "s1",
          deviceId: DEVICE_A,
          deviceDisplayId: DISPLAY_ID,
          totalBytes: 100,
          transferredBytes: 100,
          filesTotal: 1,
          filesDone: 1,
        }),
      ],
    });
    backend.emit({ kind: "library", library: [completedLibraryEntry] });
    flushTrayFrame();
    assert.equal(recorded.traySelections[recorded.traySelections.length - 1]?.items.length, 0);

    const libraryReadsBeforeOpen = backend.callNames().filter((name) => name === "listLibrary").length;
    app.dispatch({ kind: "library/open" });
    await untilTask(() => backend.callNames().filter((name) => name === "listLibrary").length > libraryReadsBeforeOpen);
    assert.equal(app.store.getState().ui.view, "library");
    assert.deepEqual(app.store.getState().library.value, [completedLibraryEntry]);
    assert.equal(app.store.getState().transferJobs.value?.[0]?.state.state, "succeeded");
  } finally {
    app.dispose();
  }
});

test("same display label keeps navigation and upload operations on canonical device identities", async () => {
  const backend = createMemoryBackend({
    snapshot: {
      devices: [device(DEVICE_A, "connected", DISPLAY_ID), device(DEVICE_B, "connected", DISPLAY_ID)],
      library: [libraryEntry(DEVICE_A, "same-session"), libraryEntry(DEVICE_B, "same-session")],
    },
  });
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => recorded.appView,
  });

  try {
    await app.start();
    // Select each device as a user would so both canonical identities exercise
    // navigation even when
    // they intentionally share one display label.
    app.dispatch({ kind: "device/select", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.calls.some((call) => call.name === "listSessions" && call.args[0] === DEVICE_A));
    app.dispatch({ kind: "device/select", deviceId: asDeviceId(DEVICE_B) });
    await untilTask(() => backend.calls.some((call) => call.name === "listSessions" && call.args[0] === DEVICE_B));
    const sessionCalls = backend.calls.filter((call) => call.name === "listSessions");
    assert.ok(sessionCalls.some((call) => call.args[0] === DEVICE_A));
    assert.ok(sessionCalls.some((call) => call.args[0] === DEVICE_B));

    app.dispatch({ kind: "entry/upload", key: asLibraryKey(`${DEVICE_A}|same-session`) });
    app.dispatch({ kind: "entry/upload", key: asLibraryKey(`${DEVICE_B}|same-session`) });
    await until(() => backend.callNames().filter((name) => name === "uploadEntry").length === 2);
    const uploadKeys = backend.calls.filter((call) => call.name === "uploadEntry").map((call) => call.args[0]);
    assert.deepEqual(uploadKeys, [`${DEVICE_A}|same-session`, `${DEVICE_B}|same-session`]);
  } finally {
    app.dispose();
  }
});

test("session mutation operation errors remain visible and structured without becoming item failures", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(DEVICE_A, [
    {
      ...session("s1"),
      files: [{ fileId: "file-1", displayPath: "video/left_00000.mp4", bytes: 100, sha256: "0".repeat(64) }],
      downloadStatus: "done",
      backedUp: true,
    },
  ]);
  const operationError = {
    code: "cleanup_catalog_unavailable",
    message: "无法读取设备会话清单",
    retryable: true,
    details: { deviceId: DEVICE_A },
  } as const;
  let cleanupCalls = 0;
  backend.cleanupBackedUp = async () => {
    cleanupCalls += 1;
    return {
      revision: 7,
      value: { items: [], sessions: null, operationError },
    };
  };
  const toasts: Array<{ message: string; tone: string }> = [];
  const recorded = createRecordedView();
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: (message, tone) => toasts.push({ message, tone }),
    view: () => recorded.appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "device/select", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.calls.some((call) => call.name === "listSessions"));
    const action = { kind: "device/cleanupBackedUp", deviceId: asDeviceId(DEVICE_A) } as const;
    app.dispatch(action);
    app.dispatch(action);
    await until(() => cleanupCalls === 1);
    await until(() => app.store.getState().sessions.get(DEVICE_A)?.rpcError?.code === "cleanup_catalog_unavailable");

    const resource = app.store.getState().sessions.get(DEVICE_A);
    assert.deepEqual(resource?.rpcError, operationError);
    assert.equal(resource?.error, operationError.message);
    assert.ok(toasts.some((toast) => toast.tone === "danger" && toast.message.includes(operationError.message)));
    assert.ok(!toasts.some((toast) => toast.message.includes("成功 0 项")));
  } finally {
    app.dispose();
  }
});

test("Lab v4 never calls destructive commands even when contradictory flags claim support", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(DEVICE_A, [session("s1")]);
  backend.setSessionCapabilities(DEVICE_A, {
    profile: "labHttpV4",
    sessionDeletion: { supported: true, source: "deviceDescriptor" },
    sessionDetail: { supported: true, source: "profileContract" },
    artifactDownload: { supported: true, source: "profileContract" },
    captureStatus: { supported: true, source: "profileContract" },
  });
  const toasts: Array<{ message: string; tone: string }> = [];
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: (message, tone) => toasts.push({ message, tone }),
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    app.dispatch({ kind: "device/select", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.calls.some((call) => call.name === "listSessions" && call.args[0] === DEVICE_A));
    await until(() => app.store.getState().sessions.get(DEVICE_A)?.value?.length === 1);

    app.dispatch({ kind: "session/download", deviceId: asDeviceId(DEVICE_A), sessionId: asSessionId("s1") });
    await untilTask(() => backend.callNames().includes("downloadSession"));

    app.dispatch({ kind: "session/remove", deviceId: asDeviceId(DEVICE_A), sessionId: asSessionId("s1") });
    app.dispatch({ kind: "session/remove", deviceId: asDeviceId(DEVICE_A), sessionId: asSessionId("s1") });

    app.dispatch({ kind: "device/cleanupBackedUp", deviceId: asDeviceId(DEVICE_A) });
    app.dispatch({ kind: "device/cleanupBackedUp", deviceId: asDeviceId(DEVICE_A) });

    app.dispatch({ kind: "device/cleanupDownloaded", deviceId: asDeviceId(DEVICE_A) });

    app.dispatch({ kind: "list/select", scope: "device", key: "s1", selected: true });
    app.dispatch({ kind: "list/bulkRemove", scope: "device" });
    app.dispatch({ kind: "list/bulkRemove", scope: "device" });

    await Promise.resolve();

    assert.ok(!backend.callNames().includes("deleteSessions"));
    assert.ok(!backend.callNames().includes("cleanupBackedUp"));
    assert.ok(!backend.callNames().includes("previewDownloadedCleanup"));
    assert.ok(backend.callNames().includes("downloadSession"));
    assert.ok(
      toasts.some(
        (toast) => toast.tone === "danger" && toast.message.includes("Device API v4 契约不支持删除设备端会话"),
      ),
    );
  } finally {
    app.dispose();
  }
});

test("the application backend contract has no selected-file lane for any device profile", () => {
  const backend = createMemoryBackend();
  assert.equal(Object.prototype.hasOwnProperty.call(backend, "downloadFile"), false);
});

test("rows without eligible gateway verification never reach detail or download commands", async () => {
  const usable = session("usable-template").verification!;
  const rows: SessionView[] = [
    { ...session("missing"), verification: null },
    {
      ...session("unusable"),
      verification: {
        ...usable,
        verdict: "unusable",
        diagnostics: [{ code: "verification_failed", summary: "gateway rejected publication" }],
      },
    },
    {
      ...session("malformed"),
      verification: { ...usable, verdict: "usable", manifestSha256: "NOT-A-DIGEST" },
    },
  ];
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(DEVICE_A, rows);
  const toasts: Array<{ message: string; tone: string }> = [];
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: (message, tone) => toasts.push({ message, tone }),
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => sessionsOf(app.store.getState(), DEVICE_A)?.length === rows.length);
    for (const row of rows) {
      app.dispatch({
        kind: "session/download",
        deviceId: asDeviceId(DEVICE_A),
        sessionId: asSessionId(row.id),
      });
      app.dispatch({ kind: "list/select", scope: "device", key: row.id, selected: true });
    }
    const missingRowKey = deviceRowKey(DEVICE_A, "missing");
    app.dispatch({ kind: "list/toggleRow", scope: "device", rowKey: missingRowKey });
    app.dispatch({
      kind: "session/loadDetail",
      deviceId: asDeviceId(DEVICE_A),
      sessionId: asSessionId("missing"),
    });
    app.dispatch({ kind: "list/bulkAction", scope: "device" });
    app.dispatch({ kind: "device/downloadAllNew", deviceId: asDeviceId(DEVICE_A) });

    await untilTask(() => toasts.length >= 5);
    assert.ok(!backend.callNames().includes("getSessionDetail"));
    assert.ok(!backend.callNames().includes("downloadSession"));
    assert.ok(!backend.callNames().includes("downloadSessions"));
    assert.ok(toasts.some((toast) => toast.message.includes("未通过网关验证")));
    assert.ok(toasts.some((toast) => toast.message.includes("没有已验证的新数据")));
  } finally {
    app.dispose();
  }
});

test("a fresh detail whose manifest evidence changed cannot proceed to download", async () => {
  const summary = session("s1");
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(DEVICE_A, [summary]);
  backend.hold("getSessionDetail");
  const toasts: Array<{ message: string; tone: string }> = [];
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: (message, tone) => toasts.push({ message, tone }),
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => sessionsOf(app.store.getState(), DEVICE_A)?.length === 1);
    app.dispatch({
      kind: "session/download",
      deviceId: asDeviceId(DEVICE_A),
      sessionId: asSessionId("s1"),
    });
    await untilTask(() => backend.pending("getSessionDetail") === 1);
    backend.release("getSessionDetail", {
      ...summary,
      verification: { ...summary.verification!, manifestSha256: "d".repeat(64) },
      files: [{ fileId: "f1", displayPath: "video/left.mp4", bytes: 1, sha256: "d".repeat(64) }],
    });
    await untilTask(() => backend.pending("getSessionDetail") === 0);
    await untilTask(() => toasts.some((toast) => toast.message.includes("验证证据已变化")));

    assert.ok(!backend.callNames().includes("downloadSession"));
    assert.equal(sessionDetailStateOf(app.store.getState(), DEVICE_A, "s1")?.loading, false);
    assert.ok(sessionDetailStateOf(app.store.getState(), DEVICE_A, "s1")?.error?.includes("验证证据已变化"));
  } finally {
    app.dispose();
  }
});

test("device navigation reaches 200 sessions through explicit load-more actions", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(
    DEVICE_A,
    Array.from({ length: 200 }, (_unused, index) => ({
      ...session(`session-${index}`),
      dateLabel: new Date(Date.parse("2026-08-03T00:00:00Z") - index * 1_000).toISOString(),
    })),
  );
  let sessionReadRevision = 0;
  const appBackend = {
    ...backend,
    async listSessions(...args: Parameters<TransferBackend["listSessions"]>) {
      const loaded = await backend.listSessions(...args);
      return { ...loaded, revision: (sessionReadRevision += 1) };
    },
  } satisfies TransferBackend;
  const app = createTransferApp({
    backend: appBackend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);
    for (const expected of [100, 150, 200]) {
      app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
      await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === expected);
    }

    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).hasMore, false);
    assert.equal(new Set(sessionsOf(app.store.getState(), DEVICE_A)?.map((item) => item.id)).size, 200);
    assert.equal(backend.calls.filter((call) => call.name === "listSessions").length, 4);
  } finally {
    app.dispose();
  }
});

test("revisionless v2 sessions open verified detail but never request load more", async () => {
  const memory = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  const summary = session("session-v2");
  let listCalls = 0;
  let detailCatalogRevision: string | null | undefined;
  const backend: TransferBackend = {
    ...memory,
    async listSessions() {
      listCalls += 1;
      return {
        revision: listCalls,
        value: {
          items: [summary],
          nextCursor: null,
          hasMore: false,
          catalogRevision: null,
          catalogAuthority: "unavailable",
          paginationSupported: false,
          paginationUnavailableReason: "catalogRevisionUnavailable",
          capabilities: {
            profile: "labHttpV4",
            sessionDeletion: { supported: false, source: "profileContract" },
            sessionDetail: { supported: true, source: "profileContract" },
            artifactDownload: { supported: true, source: "deviceDescriptor" },
            captureStatus: { supported: true, source: "profileContract" },
          },
          diagnostics: [],
        },
      };
    },
    async getSessionDetail(_deviceId, _sessionId, _sessionRevision, catalogRevision) {
      detailCatalogRevision = catalogRevision;
      return {
        revision: 2,
        value: {
          ...summary,
          files: [{ fileId: "f1", displayPath: "video/left.mp4", bytes: 10, sha256: "c".repeat(64) }],
        },
      };
    },
  };
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => sessionsOf(app.store.getState(), DEVICE_A)?.length === 1);
    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).catalogRevision, null);

    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await Promise.resolve();
    assert.equal(listCalls, 1);

    app.dispatch({
      kind: "list/toggleRow",
      scope: "device",
      rowKey: deviceRowKey(DEVICE_A, summary.id),
    });
    app.dispatch({
      kind: "session/loadDetail",
      deviceId: asDeviceId(DEVICE_A),
      sessionId: asSessionId(summary.id),
    });
    await untilTask(() => sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files.length === 1);
    assert.equal(detailCatalogRevision, null);
  } finally {
    app.dispose();
  }
});

test("device switch invalidates late load-more and detail responses", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  const allSessions = Array.from({ length: 80 }, (_unused, index) => session(`session-${index}`));
  backend.setSessions(DEVICE_A, allSessions);
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);
    const catalog = sessionCatalogOf(app.store.getState(), DEVICE_A);
    assert.ok(catalog.nextCursor);

    backend.hold("listSessions");
    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 1);
    app.dispatch({ kind: "library/open" });
    backend.release("listSessions", {
      items: allSessions.slice(50),
      nextCursor: null,
      hasMore: false,
      catalogRevision: catalog.catalogRevision,
      catalogAuthority: catalog.catalogAuthority,
      paginationSupported: catalog.paginationSupported,
      paginationUnavailableReason: catalog.paginationUnavailableReason,
      capabilities: catalog.capabilities,
      diagnostics: catalog.diagnostics,
    });
    await untilTask(() => backend.pending("listSessions") === 0);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.length, 50);

    app.dispatch({ kind: "device/select", deviceId: asDeviceId(DEVICE_A) });
    // The held mode remains active, so release the first-page focus request.
    await untilTask(() => backend.pending("listSessions") === 1);
    backend.release("listSessions", {
      items: allSessions.slice(0, 50),
      nextCursor: catalog.nextCursor,
      hasMore: true,
      catalogRevision: catalog.catalogRevision,
      catalogAuthority: catalog.catalogAuthority,
      paginationSupported: catalog.paginationSupported,
      paginationUnavailableReason: catalog.paginationUnavailableReason,
      capabilities: catalog.capabilities,
      diagnostics: catalog.diagnostics,
    });
    await untilTask(() => backend.pending("listSessions") === 0);

    backend.hold("getSessionDetail");
    const sessionId = asSessionId("session-0");
    const rowKey = deviceRowKey(DEVICE_A, "session-0");
    // Use the actual action sequence emitted by DeviceScreen: open, then load.
    app.dispatch({ kind: "list/toggleRow", scope: "device", rowKey });
    app.dispatch({ kind: "session/loadDetail", deviceId: asDeviceId(DEVICE_A), sessionId });
    await untilTask(() => backend.pending("getSessionDetail") === 1);
    app.dispatch({ kind: "library/open" });
    backend.release("getSessionDetail", {
      ...allSessions[0],
      files: [{ fileId: "late", displayPath: "late.mp4", bytes: 1, sha256: "a".repeat(64) }],
    });
    await untilTask(() => backend.pending("getSessionDetail") === 0);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files.length, 0);
  } finally {
    app.dispose();
  }
});

test("catalog_changed load-more invalidates the old chain and reloads one fresh first page", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  const allSessions = Array.from({ length: 80 }, (_unused, index) => ({
    ...session(`session-${index}`),
    dateLabel: new Date(Date.parse("2026-08-03T00:00:00Z") - index * 1_000).toISOString(),
  }));
  backend.setSessions(DEVICE_A, allSessions);
  let sessionReadRevision = 0;
  const appBackend = {
    ...backend,
    async listSessions(...args: Parameters<TransferBackend["listSessions"]>) {
      const loaded = await backend.listSessions(...args);
      return { ...loaded, revision: (sessionReadRevision += 1) };
    },
  } satisfies TransferBackend;
  const app = createTransferApp({
    backend: appBackend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);
    const oldCatalog = sessionCatalogOf(app.store.getState(), DEVICE_A);
    assert.ok(oldCatalog.nextCursor);
    assert.ok(oldCatalog.catalogRevision);

    backend.hold("getSessionDetail");
    const first = allSessions[0]!;
    app.dispatch({ kind: "list/toggleRow", scope: "device", rowKey: deviceRowKey(DEVICE_A, first.id) });
    app.dispatch({ kind: "session/loadDetail", deviceId: asDeviceId(DEVICE_A), sessionId: asSessionId(first.id) });
    await untilTask(() => backend.pending("getSessionDetail") === 1);

    backend.hold("listSessions");
    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 1);
    const newCatalogRevision = `sha256:${"d".repeat(64)}`;
    backend.rejectHeld(
      "listSessions",
      new BackendError("listSessions", "The cursor belongs to an older catalog revision.", {
        rpcError: {
          code: "session_catalog_changed",
          message: "The cursor belongs to an older catalog revision.",
          retryable: true,
          details: { catalogRevision: newCatalogRevision },
        } as unknown as RpcError,
      }),
    );

    await untilTask(() => backend.pending("listSessions") === 1);
    const listCalls = backend.calls.filter((call) => call.name === "listSessions");
    assert.equal(listCalls.length, 3, "initial page, stale load-more, then one fresh first page");
    assert.deepEqual(listCalls[listCalls.length - 1]?.args, [DEVICE_A, null, null]);
    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).catalogRevision, null);
    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).nextCursor, null);

    backend.release("getSessionDetail", {
      ...first,
      files: [{ fileId: "late", displayPath: "late.mp4", bytes: 1, sha256: "a".repeat(64) }],
    });
    await untilTask(() => backend.pending("getSessionDetail") === 0);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files.length, 0);

    backend.release("listSessions", {
      items: allSessions.slice(0, 50),
      nextCursor: "fresh-cursor",
      hasMore: true,
      catalogRevision: newCatalogRevision,
      catalogAuthority: oldCatalog.catalogAuthority,
      paginationSupported: oldCatalog.paginationSupported,
      paginationUnavailableReason: oldCatalog.paginationUnavailableReason,
      capabilities: oldCatalog.capabilities,
      diagnostics: oldCatalog.diagnostics,
    });
    await untilTask(() => backend.pending("listSessions") === 0);
    await untilTask(() => sessionCatalogOf(app.store.getState(), DEVICE_A).catalogRevision === newCatalogRevision);
    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).catalogRevision, newCatalogRevision);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.length, 50);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files.length, 0);
    assert.equal(backend.calls.filter((call) => call.name === "listSessions").length, 3);
  } finally {
    app.dispose();
  }
});

test("catalog_changed on the automatic first-page reload does not create a retry loop", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(
    DEVICE_A,
    Array.from({ length: 80 }, (_unused, index) => session(`session-${index}`)),
  );
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });
  const catalogChanged = new BackendError("listSessions", "catalog changed", {
    rpcError: {
      code: "session_catalog_changed",
      message: "catalog changed",
      retryable: true,
      details: { catalogRevision: `sha256:${"e".repeat(64)}` },
    } as unknown as RpcError,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);
    backend.hold("listSessions");
    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 1);
    backend.rejectHeld("listSessions", catalogChanged);
    await untilTask(() => backend.pending("listSessions") === 1);
    backend.rejectHeld("listSessions", catalogChanged);
    await untilTask(() => backend.pending("listSessions") === 0);
    await Promise.resolve();

    assert.equal(backend.calls.filter((call) => call.name === "listSessions").length, 3);
    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).catalogRevision, null);
    assert.equal(app.store.getState().sessions.get(DEVICE_A)?.rpcError?.code, "session_catalog_changed");
  } finally {
    app.dispose();
  }
});

test("ordinary load-more failures keep the current catalog and do not auto-refresh", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  backend.setSessions(
    DEVICE_A,
    Array.from({ length: 80 }, (_unused, index) => session(`session-${index}`)),
  );
  const app = createTransferApp({
    backend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);
    const before = sessionCatalogOf(app.store.getState(), DEVICE_A);
    backend.hold("listSessions");
    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 1);
    backend.rejectHeld("listSessions", new BackendError("listSessions", "temporary network failure"));
    await untilTask(() => sessionCatalogOf(app.store.getState(), DEVICE_A).loadingMore === false);
    await Promise.resolve();

    const after = sessionCatalogOf(app.store.getState(), DEVICE_A);
    assert.equal(after.catalogRevision, before.catalogRevision);
    assert.equal(after.nextCursor, before.nextCursor);
    assert.equal(after.loadMoreError, "temporary network failure");
    assert.equal(backend.calls.filter((call) => call.name === "listSessions").length, 2);
  } finally {
    app.dispose();
  }
});

test("a rejected load-more page clears its spinner without replacing the catalog", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  const allSessions = Array.from({ length: 80 }, (_unused, index) => ({
    ...session(`session-${index}`),
    dateLabel: new Date(Date.parse("2026-08-03T00:00:00Z") - index * 1_000).toISOString(),
  }));
  backend.setSessions(DEVICE_A, allSessions);
  let listCalls = 0;
  let sessionReadRevision = 0;
  const appBackend = {
    ...backend,
    async listSessions(...args: Parameters<TransferBackend["listSessions"]>) {
      const loaded = await backend.listSessions(...args);
      listCalls += 1;
      const revision = ++sessionReadRevision;
      if (listCalls === 2) {
        const first = loaded.value.items[0];
        return {
          ...loaded,
          revision,
          value: {
            ...loaded.value,
            items: first === undefined ? [] : [first, first],
          },
        };
      }
      return { ...loaded, revision };
    },
  } satisfies TransferBackend;
  const toasts: string[] = [];
  const app = createTransferApp({
    backend: appBackend,
    clock: createFakeClock(),
    toast: (message) => toasts.push(message),
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);
    const beforeSessions = sessionsOf(app.store.getState(), DEVICE_A) ?? [];
    const beforeCatalog = sessionCatalogOf(app.store.getState(), DEVICE_A);
    assert.ok(beforeCatalog.nextCursor);

    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => sessionCatalogOf(app.store.getState(), DEVICE_A).loadingMore === false);

    const afterSessions = sessionsOf(app.store.getState(), DEVICE_A) ?? [];
    const afterCatalog = sessionCatalogOf(app.store.getState(), DEVICE_A);
    assert.deepEqual(afterSessions, beforeSessions);
    assert.equal(afterCatalog.catalogRevision, beforeCatalog.catalogRevision);
    assert.equal(afterCatalog.nextCursor, beforeCatalog.nextCursor);
    assert.equal(afterCatalog.loadMoreError, "设备返回了无效的会话分页，已保留当前目录，请重试");
    assert.ok(toasts.some((message) => message.includes("无效的会话分页")));
    assert.equal(listCalls, 2);
  } finally {
    app.dispose();
  }
});

test("manual refresh invalidates late pagination and detail without leaving a stuck loading row", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device(DEVICE_A)] } });
  const allSessions = Array.from({ length: 80 }, (_unused, index) => ({
    ...session(`session-${index}`),
    dateLabel: new Date(Date.parse("2026-08-03T00:00:00Z") - index * 1_000).toISOString(),
  }));
  backend.setSessions(DEVICE_A, allSessions);
  let sessionReadRevision = 0;
  const appBackend = {
    ...backend,
    async listSessions(...args: Parameters<TransferBackend["listSessions"]>) {
      const loaded = await backend.listSessions(...args);
      return { ...loaded, revision: (sessionReadRevision += 1) };
    },
    async getSessionDetail(...args: Parameters<TransferBackend["getSessionDetail"]>) {
      const loaded = await backend.getSessionDetail(...args);
      return { ...loaded, revision: (sessionReadRevision += 1) };
    },
  } satisfies TransferBackend;
  const app = createTransferApp({
    backend: appBackend,
    clock: createFakeClock(),
    toast: () => {},
    view: () => createRecordedView().appView,
  });

  try {
    await app.start();
    await untilTask(() => (sessionsOf(app.store.getState(), DEVICE_A)?.length ?? 0) === 50);

    backend.hold("listSessions");
    app.dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 1);
    app.dispatch({ kind: "device/refreshSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 2);

    // The refresh completes first and starts a new catalog generation.
    backend.releaseLast("listSessions");
    await untilTask(() => app.store.getState().sessions.get(DEVICE_A)?.loading === false);
    backend.release("listSessions");
    await untilTask(() => backend.pending("listSessions") === 0);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.length, 50);
    assert.equal(sessionCatalogOf(app.store.getState(), DEVICE_A).loadingMore, false);

    backend.hold("getSessionDetail");
    const sessionId = asSessionId("session-0");
    app.dispatch({ kind: "list/toggleRow", scope: "device", rowKey: deviceRowKey(DEVICE_A, sessionId) });
    app.dispatch({ kind: "session/loadDetail", deviceId: asDeviceId(DEVICE_A), sessionId });
    await untilTask(() => backend.pending("getSessionDetail") === 1);

    app.dispatch({ kind: "device/refreshSessions", deviceId: asDeviceId(DEVICE_A) });
    await untilTask(() => backend.pending("listSessions") === 1);
    backend.release("listSessions");
    await untilTask(() => app.store.getState().sessions.get(DEVICE_A)?.loading === false);
    backend.release("getSessionDetail", {
      ...allSessions[0],
      files: [{ fileId: "late", displayPath: "late.mp4", bytes: 1, sha256: "a".repeat(64) }],
    });
    await untilTask(() => backend.pending("getSessionDetail") === 0);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files.length, 0);
    assert.equal(sessionDetailStateOf(app.store.getState(), DEVICE_A, sessionId), undefined);

    // The same still-open row can immediately issue a fresh detail request.
    app.dispatch({ kind: "session/loadDetail", deviceId: asDeviceId(DEVICE_A), sessionId });
    await untilTask(() => backend.pending("getSessionDetail") === 1);
    backend.release("getSessionDetail", {
      ...allSessions[0],
      files: [{ fileId: "fresh", displayPath: "fresh.mp4", bytes: 1, sha256: "b".repeat(64) }],
    });
    await untilTask(() => sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files.length === 1);
    assert.equal(sessionsOf(app.store.getState(), DEVICE_A)?.[0]?.files[0]?.fileId, "fresh");
  } finally {
    app.dispose();
  }
});
