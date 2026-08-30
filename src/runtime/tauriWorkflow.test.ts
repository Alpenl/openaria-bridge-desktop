import { test } from "node:test";
import assert from "node:assert/strict";

import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";

import type { AppView } from "../app/appView";
import { createTransferApp } from "../app/transferApp";
import { asDeviceId, asLibraryKey, asSessionId } from "../ids";
import type { FrameScheduler } from "../ui/renderScheduler";
import type { TraySelection } from "../ui/traySelector";
import { createFakeClock } from "./clock";
import { createTauriBackend } from "./tauriBackend";

// Tauri's official IPC mock expects a browser-style global.
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: globalThis,
});

const fingerprint = `abcdef01${"1".repeat(56)}`;
const deviceId = `ylx-${fingerprint}`;
const deviceDisplayId = "YLX-ABCDEF01";
const sessionId = "session-001";
const libraryKey = `${deviceId}|${sessionId}`;

const idleDevice = {
  id: deviceId,
  displayId: deviceDisplayId,
  ip: "192.0.2.17",
  state: "idle",
  lastSeen: null,
} as const;

const connectedDevice = { ...idleDevice, state: "connected" } as const;

const catalogSession = {
  id: sessionId,
  revision: "catalog-r1",
  dateLabel: "2026-08-04T01:00:00Z",
  durationSeconds: 42,
  totalBytes: 1_024,
  videoBytes: 1_024,
  imuSamples: null,
  files: [],
  downloadStatus: "none",
  backedUp: false,
  verification: {
    verdict: "usable",
    actor: "gateway",
    validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
    manifestSha256: "a".repeat(64),
    verifiedAt: "2026-08-04T01:00:01Z",
    diagnostics: [],
  },
} as const;

const sessionCapabilities = {
  profile: "legacyPinnedTlsV1",
  sessionDeletion: { supported: true, source: "profileContract" },
  sessionDetail: { supported: true, source: "profileContract" },
  artifactDownload: { supported: true, source: "profileContract" },
  captureStatus: { supported: false, source: "unavailable" },
} as const;

const downloadedEntry = {
  deviceId,
  deviceDisplayId,
  sessionId,
  dateLabel: catalogSession.dateLabel,
  downloadedAt: "2026-08-04T01:01:00Z",
  bytes: catalogSession.totalBytes,
  files: [],
  complete: true,
  uploadStatus: "none",
  uploadedAt: null,
  uploadError: null,
  uploadRetryable: false,
} as const;

const storage = {
  endpoint: "http://127.0.0.1:9000",
  bucket: "recordings",
  prefix: "ylx",
  urlStyle: "path",
  secretConfigured: true,
  downloadRoot: "/recordings",
  activeDownloadRoot: "/recordings",
} as const;

type Invocation = { command: string; payload: unknown };

interface ViewRecorder {
  readonly appView: AppView;
  readonly pairingShown: string[];
  readonly pairingTicks: Array<{ remaining: number; total: number }>;
  readonly traySelections: TraySelection[];
  readonly fatal: string[];
}

function createViewRecorder(): ViewRecorder {
  const pairingShown: string[] = [];
  const pairingTicks: Array<{ remaining: number; total: number }> = [];
  const traySelections: TraySelection[] = [];
  const fatal: string[] = [];

  const appView: AppView = {
    renderRail: () => {},
    renderNav: () => {},
    renderTopbar: () => {},
    renderContent: () => {},
    renderList: () => {},
    renderTray: (selection) => traySelections.push(selection),
    renderTheme: () => {},
    renderDownloadRootLabel: () => {},
    setNotificationsSwitch: () => {},
    showPairing: (id) => pairingShown.push(id),
    updatePairingRing: (remaining, total) => pairingTicks.push({ remaining, total }),
    hidePairing: () => {},
    openAddDevice: () => {},
    closeAddDevice: () => {},
    setAddDeviceStatus: () => {},
    openStorageSettings: () => {},
    closeStorageSettings: () => {},
    setStorageDownloadRootField: () => {},
    openDownloadRootSettings: () => {},
    closeDownloadRootSettings: () => {},
    setDownloadRootField: () => {},
    openUpdateSettings: () => {},
    closeUpdateSettings: () => {},
    renderUpdateSettings: () => {},
    confirmDestructive: () => false,
    setBusy: () => {},
    showFatal: (title) => fatal.push(title),
    dispose: () => {},
  };

  return { appView, pairingShown, pairingTicks, traySelections, fatal };
}

function createFrameHarness(): {
  readonly scheduler: FrameScheduler;
  flush(): void;
} {
  const pending: Array<() => void> = [];
  const scheduler: FrameScheduler = (run) => {
    pending.push(run);
    return () => {
      const index = pending.indexOf(run);
      if (index >= 0) pending.splice(index, 1);
    };
  };

  return {
    scheduler,
    flush(): void {
      const frame = pending.shift();
      assert.ok(frame, "a transfer event must schedule a tray frame");
      frame();
    },
  };
}

async function until(predicate: () => boolean, message: string): Promise<void> {
  for (let count = 0; count < 100; count += 1) {
    if (predicate()) return;
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${message}`);
}

function invocationCount(invocations: readonly Invocation[], command: string): number {
  return invocations.filter((invocation) => invocation.command === command).length;
}

function lastTray(recorder: ViewRecorder): TraySelection {
  const selection = recorder.traySelections[recorder.traySelections.length - 1];
  assert.ok(selection, "the application must have rendered the transfer tray");
  return selection;
}

function transferJob(state: Record<string, unknown>, desiredRunState: "run" | "paused") {
  return {
    jobId: "download-job-1",
    state,
    desiredRunState,
    sessionId,
    deviceId,
    deviceDisplayId,
    totalBytes: catalogSession.totalBytes,
    transferredBytes: 256,
    filesTotal: 1,
    filesDone: 0,
  };
}

function uploadTransfer(jobId: string, state: "running" | "cancelled" | "failed" | "finalizing" | "succeeded") {
  return {
    key: jobId,
    label: sessionId,
    totalBytes: catalogSession.totalBytes,
    sentBytes: state === "succeeded" ? catalogSession.totalBytes : 512,
    state,
    retryable: state === "failed",
    error: state === "failed" ? "temporary object-store failure" : state === "cancelled" ? "cancelled by user" : null,
    direction: "up",
    targetLabel: "recordings/ylx",
  };
}

test("real app workflow converges through mocked Tauri commands and events", async () => {
  clearMocks();
  const invocations: Invocation[] = [];
  let libraryRevision = 0;
  let library: unknown[] = [];
  let uploadStarts = 0;

  mockIPC(
    (command, payload) => {
      invocations.push({ command, payload });
      switch (command) {
        case "read_snapshot":
          return {
            revision: 0,
            value: {
              devices: { revision: 0, value: [idleDevice] },
              library: { revision: libraryRevision, value: library },
              transfers: { revision: 0, value: [] },
              storage: { revision: 0, value: storage },
            },
          };
        case "list_devices":
          return { revision: 0, value: [idleDevice] };
        case "list_library":
          return { revision: libraryRevision, value: library };
        case "list_transfers":
          return { revision: 0, value: [] };
        case "get_storage_config":
          return { revision: 0, value: storage };
        case "connect_device":
          return "pairing-attempt-1";
        case "list_sessions":
          return {
            revision: 4,
            value: {
              items: [catalogSession],
              nextCursor: null,
              hasMore: false,
              catalogRevision: "catalog-r1",
              catalogAuthority: "deviceSnapshot",
              paginationSupported: true,
              paginationUnavailableReason: null,
              capabilities: sessionCapabilities,
              diagnostics: [],
            },
          };
        case "get_session_detail":
          return { revision: 4, value: catalogSession };
        case "download_session":
          return "download-job-1";
        case "resume_transfer_job":
        case "cancel_upload":
          return undefined;
        case "upload_entry":
          uploadStarts += 1;
          return `upload-job-${uploadStarts}`;
        case "retry_transfer":
          return payload && (payload as { jobId?: unknown }).jobId === "upload-job-2"
            ? "upload-job-3"
            : "download-job-2";
        default:
          return undefined;
      }
    },
    { shouldMockEvents: true },
  );

  const recorder = createViewRecorder();
  const frames = createFrameHarness();
  const toasts: Array<{ message: string; tone?: string }> = [];
  const app = createTransferApp({
    backend: createTauriBackend(),
    clock: createFakeClock(),
    frameScheduler: frames.scheduler,
    toast: (message, tone) => toasts.push({ message, tone }),
    view: () => recorder.appView,
  });

  try {
    await app.start();
    assert.equal(recorder.fatal.length, 0);
    assert.equal(
      invocationCount(invocations, "read_snapshot"),
      1,
      "boot discovers devices through one atomic snapshot",
    );
    assert.deepEqual(
      app.store.getState().devices.value?.map((device) => ({ id: device.id, displayId: device.displayId })),
      [{ id: deviceId, displayId: deviceDisplayId }],
    );

    app.dispatch({ kind: "device/select", deviceId: asDeviceId(deviceId) });
    await until(() => invocationCount(invocations, "connect_device") === 1, "the connect command");
    await until(() => app.store.getState().ui.pairingAttemptId === "pairing-attempt-1", "the pairing attempt");
    assert.deepEqual(recorder.pairingShown, [deviceDisplayId], "the overlay uses the display-only label");

    await emit("devices:update", { revision: 1, value: [connectedDevice] });
    await emit("pairing:tick", {
      revision: 2,
      value: { deviceId, attemptId: "pairing-attempt-1", remaining: 7, total: 10 },
    });
    await emit("pairing:resolved", {
      revision: 3,
      value: { deviceId, attemptId: "pairing-attempt-1", outcome: "connected", error: null },
    });
    await until(() => invocationCount(invocations, "list_sessions") === 1, "the revisioned session catalog read");
    await until(
      () => app.store.getState().sessions.get(deviceId)?.value?.[0]?.id === sessionId,
      "the session catalog projection",
    );
    assert.deepEqual(recorder.pairingTicks, [{ remaining: 7, total: 10 }]);
    assert.equal(app.store.getState().ui.activeDeviceId, deviceId);

    app.dispatch({
      kind: "session/download",
      deviceId: asDeviceId(deviceId),
      sessionId: asSessionId(sessionId),
    });
    await until(() => invocationCount(invocations, "download_session") === 1, "the download command");

    await emit("transfer_jobs:update", {
      revision: 5,
      value: [transferJob({ state: "transferring" }, "paused")],
    });
    frames.flush();
    const resume = lastTray(recorder).jobs[0]?.controls.find((control) => control.action === "resume-transfer-job");
    assert.ok(resume, "durably paused download work must expose its real resume command");
    app.dispatch({ kind: "tray/command", command: resume.command });
    await until(() => invocationCount(invocations, "resume_transfer_job") === 1, "the resume command");

    await emit("transfer_jobs:update", {
      revision: 6,
      value: [transferJob({ state: "failed", code: "network", retryable: true }, "run")],
    });
    frames.flush();
    const retryDownload = lastTray(recorder).jobs[0]?.controls.find((control) => control.action === "retry-transfer");
    assert.ok(retryDownload, "a retryable durable download must expose its backend-owned retry identity");
    app.dispatch({ kind: "tray/command", command: retryDownload.command });
    await until(
      () =>
        invocations.some(
          ({ command, payload }) =>
            command === "retry_transfer" && (payload as { jobId?: unknown } | undefined)?.jobId === "download-job-1",
        ),
      "the download retry command",
    );

    await emit("transfer_jobs:update", {
      revision: 7,
      value: [
        {
          ...transferJob({ state: "succeeded" }, "run"),
          jobId: "download-job-2",
          transferredBytes: catalogSession.totalBytes,
          filesDone: 1,
        },
      ],
    });
    frames.flush();
    assert.equal(lastTray(recorder).items.length, 0, "completed downloads retire from the visible tray");

    libraryRevision = 8;
    library = [downloadedEntry];
    await emit("library:update", { revision: libraryRevision, value: library });
    await until(() => app.store.getState().library.value?.[0]?.sessionId === sessionId, "the downloaded library row");

    const libraryReadsBeforeOpen = invocationCount(invocations, "list_library");
    app.dispatch({ kind: "library/open" });
    await until(
      () => invocationCount(invocations, "list_library") > libraryReadsBeforeOpen,
      "the filesystem-backed library reconciliation",
    );
    assert.equal(app.store.getState().ui.view, "library");

    app.dispatch({ kind: "entry/upload", key: asLibraryKey(libraryKey) });
    await until(() => invocationCount(invocations, "upload_entry") === 1, "the first upload command");
    await emit("transfers:update", { revision: 9, value: [uploadTransfer("upload-job-1", "running")] });
    frames.flush();
    const cancelUpload = lastTray(recorder).transfers[0]?.controls.find(
      (control) => control.action === "cancel-upload",
    );
    assert.ok(cancelUpload, "an active upload must expose its durable job cancellation command");
    assert.deepEqual(cancelUpload.command, { kind: "cancelUpload", jobId: "upload-job-1" });
    app.dispatch({ kind: "tray/command", command: cancelUpload.command });
    await until(() => invocationCount(invocations, "cancel_upload") === 1, "the upload cancellation command");

    libraryRevision = 10;
    library = [
      {
        ...downloadedEntry,
        uploadStatus: "failed",
        uploadError: "cancelled by user",
        uploadRetryable: true,
      },
    ];
    await emit("library:update", { revision: libraryRevision, value: library });
    await emit("transfers:update", { revision: 11, value: [uploadTransfer("upload-job-1", "cancelled")] });
    frames.flush();
    assert.equal(app.store.getState().library.value?.[0]?.uploadRetryable, true);

    // Retrying an acknowledged cancellation is the same library action the
    // rendered row exposes; the backend chooses the durable retry child.
    app.dispatch({ kind: "entry/upload", key: asLibraryKey(libraryKey) });
    await until(() => invocationCount(invocations, "upload_entry") === 2, "the cancelled upload retry");
    await emit("transfers:update", { revision: 12, value: [uploadTransfer("upload-job-2", "running")] });
    frames.flush();

    await emit("transfers:update", { revision: 13, value: [uploadTransfer("upload-job-2", "failed")] });
    frames.flush();
    const retryUpload = lastTray(recorder).transfers[0]?.controls.find(
      (control) => control.action === "retry-transfer",
    );
    assert.ok(retryUpload, "a retryable upload failure must expose the shared retry command");
    assert.deepEqual(retryUpload.command, { kind: "retry", id: "upload-job-2" });
    app.dispatch({ kind: "tray/command", command: retryUpload.command });
    await until(
      () =>
        invocations.some(
          ({ command, payload }) =>
            command === "retry_transfer" && (payload as { jobId?: unknown } | undefined)?.jobId === "upload-job-2",
        ),
      "the upload retry command",
    );

    await emit("transfers:update", { revision: 14, value: [uploadTransfer("upload-job-3", "finalizing")] });
    frames.flush();
    assert.equal(lastTray(recorder).activeCount, 1);
    assert.equal(lastTray(recorder).transfers[0]?.controls.length, 0, "final projection work has no unsafe controls");

    libraryRevision = 15;
    library = [
      {
        ...downloadedEntry,
        uploadStatus: "done",
        uploadedAt: "2026-08-04T01:05:00Z",
        uploadError: null,
        uploadRetryable: false,
      },
    ];
    await emit("library:update", { revision: libraryRevision, value: library });
    await emit("transfers:update", { revision: 16, value: [uploadTransfer("upload-job-3", "succeeded")] });
    frames.flush();

    const finalEntry = app.store.getState().library.value?.[0];
    assert.equal(finalEntry?.deviceId, deviceId);
    assert.equal(finalEntry?.deviceDisplayId, deviceDisplayId);
    assert.equal(finalEntry?.uploadStatus, "done");
    assert.equal(finalEntry?.uploadedAt, "2026-08-04T01:05:00Z");
    assert.equal(finalEntry?.uploadRetryable, false);
    assert.equal(app.store.getState().transfers.value?.[0]?.state, "succeeded");
    assert.equal(lastTray(recorder).items.length, 0, "the final durable success converges out of the visible tray");
    assert.equal(recorder.fatal.length, 0);
    assert.equal(
      toasts.some(({ tone }) => tone === "danger"),
      false,
      "the complete transport workflow has no application-level failure",
    );

    const workflowCalls = invocations
      .filter(({ command }) =>
        [
          "connect_device",
          "list_sessions",
          "get_session_detail",
          "download_session",
          "resume_transfer_job",
          "retry_transfer",
          "upload_entry",
          "cancel_upload",
        ].includes(command),
      )
      .map(({ command, payload }) => ({ command, payload }));
    assert.deepEqual(workflowCalls, [
      { command: "connect_device", payload: { deviceId } },
      { command: "list_sessions", payload: { deviceId, cursor: null, catalogRevision: null } },
      {
        command: "get_session_detail",
        payload: {
          deviceId,
          sessionId,
          sessionRevision: "catalog-r1",
          catalogRevision: "catalog-r1",
        },
      },
      { command: "download_session", payload: { deviceId, sessionId } },
      { command: "resume_transfer_job", payload: { jobId: "download-job-1" } },
      { command: "retry_transfer", payload: { jobId: "download-job-1" } },
      { command: "upload_entry", payload: { key: libraryKey } },
      { command: "cancel_upload", payload: { jobId: "upload-job-1" } },
      { command: "upload_entry", payload: { key: libraryKey } },
      { command: "retry_transfer", payload: { jobId: "upload-job-2" } },
    ]);
  } finally {
    app.dispose();
    clearMocks();
  }
});
