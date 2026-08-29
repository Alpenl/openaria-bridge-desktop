import { test } from "node:test";
import assert from "node:assert/strict";

import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";

import { RuntimeDecodeError } from "./decoder";
import {
  api,
  onDevicesUpdate,
  onSessionsUpdate,
  onStorageUpdate,
  revisionedApi,
  RpcInvocationError,
  subscribeAll,
} from "./tauriTransport";

// Tauri's official IPC mock expects a browser-style global.
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: globalThis,
});

const DEVICE_ID = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DEVICE_DISPLAY_ID = "YLX-ABCDEF01";

test("addManualDevice sends only the untrusted manual address into the SAS bootstrap", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
    return {
      revision: 7,
      value: { id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null },
    };
  });

  const device = await api.addManualDevice("192.0.2.10");
  assert.equal(device.id, DEVICE_ID);

  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({
      command: "add_manual_device",
      payload: { ip: "192.0.2.10" },
    }),
  );
});

test("addManualDevice rejects a legacy bare device response", async () => {
  clearMocks();
  mockIPC(() => ({ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null }));

  const failure = await api.addManualDevice("192.0.2.10").then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(failure instanceof RuntimeDecodeError);
});

test("revisionedApi.addManualDevice preserves the server revision", async () => {
  clearMocks();
  mockIPC(() => ({
    revision: 9,
    value: { id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null },
  }));

  assert.equal((await revisionedApi.addManualDevice("192.0.2.10")).revision, 9);
});

test("session pagination returns opaque cursors unchanged and detail sends both revision fences", async () => {
  const invocations: Array<{ command: string; payload: unknown }> = [];
  const session = {
    id: "session-1",
    revision: "session-revision-1",
    dateLabel: "2026-08-28T00:00:00Z",
    durationSeconds: 1,
    totalBytes: 10,
    videoBytes: 10,
    imuSamples: null,
    files: [],
    downloadStatus: "none",
    backedUp: false,
    verification: {
      verdict: "usable",
      actor: "gateway",
      validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
      manifestSha256: "a".repeat(64),
      verifiedAt: "2026-08-28T00:00:01Z",
      diagnostics: [],
    },
  };
  const capabilities = {
    profile: "labHttpV4",
    sessionDeletion: { supported: false, source: "profileContract" },
    sessionDetail: { supported: true, source: "profileContract" },
    artifactDownload: { supported: false, source: "unavailable" },
    captureStatus: { supported: true, source: "profileContract" },
  };
  clearMocks();
  mockIPC((command, payload) => {
    invocations.push({ command, payload });
    return command === "list_sessions"
      ? {
          revision: 5,
          value: {
            items: [session],
            nextCursor: "opaque://cursor?keep=%2F",
            hasMore: true,
            catalogRevision: "catalog-revision-1",
            catalogAuthority: "deviceSnapshot",
            paginationSupported: true,
            paginationUnavailableReason: null,
            capabilities,
            diagnostics: [],
          },
        }
      : { revision: 6, value: session };
  });

  const page = await revisionedApi.listSessions(DEVICE_ID, "opaque://incoming", "catalog-revision-1");
  const detail = await revisionedApi.getSessionDetail(
    DEVICE_ID,
    "session-1",
    "session-revision-1",
    "catalog-revision-1",
  );

  assert.equal(page.value.nextCursor, "opaque://cursor?keep=%2F");
  assert.equal(detail.value.id, "session-1");
  assert.deepEqual(invocations, [
    {
      command: "list_sessions",
      payload: { deviceId: DEVICE_ID, cursor: "opaque://incoming", catalogRevision: "catalog-revision-1" },
    },
    {
      command: "get_session_detail",
      payload: {
        deviceId: DEVICE_ID,
        sessionId: "session-1",
        sessionRevision: "session-revision-1",
        catalogRevision: "catalog-revision-1",
      },
    },
  ]);
});

test("revisionless session pages and detail preserve catalogRevision null across IPC", async () => {
  const invocations: Array<{ command: string; payload: unknown }> = [];
  const session = {
    id: "session-v2",
    revision: "sha256:" + "a".repeat(64),
    dateLabel: "2026-08-28T00:00:00Z",
    durationSeconds: 1,
    totalBytes: 10,
    videoBytes: 10,
    imuSamples: null,
    files: [],
    downloadStatus: "none",
    backedUp: false,
    verification: {
      verdict: "usable",
      actor: "gateway",
      validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
      manifestSha256: "a".repeat(64),
      verifiedAt: "2026-08-28T00:00:01Z",
      diagnostics: [],
    },
  };
  const capabilities = {
    profile: "labHttpV4",
    sessionDeletion: { supported: false, source: "profileContract" },
    sessionDetail: { supported: true, source: "profileContract" },
    artifactDownload: { supported: true, source: "deviceDescriptor" },
    captureStatus: { supported: true, source: "profileContract" },
  };
  clearMocks();
  mockIPC((command, payload) => {
    invocations.push({ command, payload });
    return command === "list_sessions"
      ? {
          revision: 7,
          value: {
            items: [session],
            nextCursor: null,
            hasMore: false,
            catalogRevision: null,
            catalogAuthority: "unavailable",
            paginationSupported: false,
            paginationUnavailableReason: "catalogRevisionUnavailable",
            capabilities,
            diagnostics: [],
          },
        }
      : { revision: 8, value: session };
  });

  const page = await revisionedApi.listSessions(DEVICE_ID, null, null);
  await revisionedApi.getSessionDetail(DEVICE_ID, session.id, session.revision, null);

  assert.equal(page.value.catalogRevision, null);
  assert.deepEqual(invocations, [
    { command: "list_sessions", payload: { deviceId: DEVICE_ID, cursor: null, catalogRevision: null } },
    {
      command: "get_session_detail",
      payload: {
        deviceId: DEVICE_ID,
        sessionId: session.id,
        sessionRevision: session.revision,
        catalogRevision: null,
      },
    },
  ]);
});

test("the real transport exposes no selected-file download command", () => {
  assert.equal(Object.prototype.hasOwnProperty.call(api, "downloadFile"), false);
});

test("downloaded Pi cleanup previews and executes against one connected device", async () => {
  const seen: { command: string; payload: unknown }[] = [];
  clearMocks();
  mockIPC((command, payload) => {
    seen.push({ command, payload });
    if (command === "preview_downloaded_cleanup") {
      return { eligible: [], skipped: [], eligibleBytes: 0 };
    }
    return { revision: 1, value: { eligible: [], deleted: [], failed: [], skipped: [], sessions: [] } };
  });

  await api.previewDownloadedCleanup("device-1");
  await api.cleanupDownloaded("device-1");

  assert.equal(
    JSON.stringify(seen),
    JSON.stringify([
      { command: "preview_downloaded_cleanup", payload: { deviceId: "device-1" } },
      { command: "cleanup_downloaded", payload: { deviceId: "device-1" } },
    ]),
  );
});

test("retryTransfer addresses a backend-owned real transfer id", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
    return "job-real-2";
  });

  const newJobId = await api.retryTransfer("job-real-1");

  assert.equal(newJobId, "job-real-2");
  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({
      command: "retry_transfer",
      payload: { jobId: "job-real-1" },
    }),
  );
});

test("revealLibraryFile sends a library key and opaque file id", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
  });

  await api.revealLibraryFile("device-1|session-1", "opaque-file-1");

  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({
      command: "reveal_library_file",
      payload: { key: "device-1|session-1", fileId: "opaque-file-1" },
    }),
  );
});

test("testStorageConnection tests every current form value without first persisting it", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
  });
  const config = {
    endpoint: "https://s3.example.test",
    bucket: "recordings",
    prefix: "rig-a",
    urlStyle: "virtualHost" as const,
    accessKey: "access-current",
    secretKey: "secret-current",
    downloadRoot: "/data/ylx",
  };

  await api.testStorageConnection(config);

  assert.equal(JSON.stringify(invocation), JSON.stringify({ command: "test_storage_connection", payload: { config } }));
});

test("selectDownloadRoot delegates directory selection to the native backend command", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
    return "C:\\YLX Recordings";
  });

  const selected = await api.selectDownloadRoot();

  assert.equal(selected, "C:\\YLX Recordings");
  assert.equal(JSON.stringify(invocation), JSON.stringify({ command: "select_download_root", payload: {} }));
});

test("selectDownloadRoot preserves native dialog cancellation as null", async () => {
  clearMocks();
  mockIPC(() => null);

  assert.equal(await api.selectDownloadRoot(), null);
});

test("saveDownloadRoot persists only the local download directory", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
    return {
      revision: 2,
      value: {
        endpoint: "https://s3.example.test",
        bucket: "recordings",
        prefix: "",
        urlStyle: "virtualHost",
        secretConfigured: false,
        downloadRoot: "C:\\YLX Recordings",
        activeDownloadRoot: "C:\\YLX Recordings",
      },
    };
  });

  const config = await api.saveDownloadRoot("C:\\YLX Recordings");

  assert.equal(config.activeDownloadRoot, "C:\\YLX Recordings");
  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({ command: "save_download_root", payload: { downloadRoot: "C:\\YLX Recordings" } }),
  );
});

test("pause/resume/cancel address a single backend-owned job id", async () => {
  const seen: { command: string; payload: unknown }[] = [];
  clearMocks();
  mockIPC((command, payload) => {
    seen.push({ command, payload });
  });

  await api.pauseTransferJob("job-real-1");
  await api.resumeTransferJob("job-real-1");
  await api.cancelTransferJob("job-real-1");

  assert.equal(
    JSON.stringify(seen),
    JSON.stringify([
      { command: "pause_transfer_job", payload: { jobId: "job-real-1" } },
      { command: "resume_transfer_job", payload: { jobId: "job-real-1" } },
      { command: "cancel_transfer_job", payload: { jobId: "job-real-1" } },
    ]),
  );
});

test("dismissTransferJob addresses one terminal backend-owned job id", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
  });

  await api.dismissTransferJob("job-failed-1");

  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({ command: "dismiss_transfer_job", payload: { jobId: "job-failed-1" } }),
  );
});

test("cancelUpload addresses one durable upload job id", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
  });

  await api.cancelUpload("upload-job-1");

  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({ command: "cancel_upload", payload: { jobId: "upload-job-1" } }),
  );
});

test("a failed registration unsubscribes the listeners that already registered", async () => {
  const unlistened: string[] = [];
  const registrations = [
    () => Promise.resolve(() => unlistened.push("devices")),
    () => Promise.reject(new Error("event channel unavailable")),
    () => Promise.resolve(() => unlistened.push("transfers")),
  ];

  const failure = await subscribeAll(registrations).then(
    () => null,
    (reason: unknown) => reason,
  );

  assert.match(String(failure), /event channel unavailable/);
  assert.deepEqual(unlistened.sort(), ["devices", "transfers"], "no listener may outlive a failed registration");
});

test("one failing unlisten during rollback still unsubscribes the rest", async () => {
  const unlistened: string[] = [];
  const registrations = [
    () =>
      Promise.resolve(() => {
        throw new Error("unlisten exploded");
      }),
    () => Promise.resolve(() => unlistened.push("sessions")),
    () => Promise.reject(new Error("registration failed")),
  ];

  const failure = await subscribeAll(registrations).then(
    () => null,
    (reason: unknown) => reason,
  );

  assert.match(String(failure), /registration failed/);
  assert.deepEqual(unlistened, ["sessions"]);
});

test("the returned disposer unlistens every listener exactly once", async () => {
  const unlistened: string[] = [];
  const dispose = await subscribeAll([
    () => Promise.resolve(() => unlistened.push("devices")),
    () => Promise.resolve(() => unlistened.push("sessions")),
  ]);

  dispose();
  dispose();
  dispose();

  assert.deepEqual(unlistened.sort(), ["devices", "sessions"], "a second dispose must be a no-op");
});

test("registrations run concurrently rather than one after another", async () => {
  const started: number[] = [];
  let releaseFirst = () => {};
  const first = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });

  const pending = subscribeAll([
    async () => {
      started.push(0);
      await first;
      return () => {};
    },
    async () => {
      started.push(1);
      return () => {};
    },
  ]);

  await Promise.resolve();
  assert.deepEqual(started, [0, 1], "a slow registration must not block the others");
  releaseFirst();
  (await pending)();
});

test("dismissUpload addresses one terminal durable upload job id", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
  });

  await api.dismissUpload("upload-transfer-1");

  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({ command: "dismiss_upload_transfer", payload: { jobId: "upload-transfer-1" } }),
  );
});

test("connectDevice hands back the pairing attempt id the backend created", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
    return "attempt-0001";
  });

  const attemptId = await api.connectDevice("YLX-REAL");

  assert.equal(attemptId, "attempt-0001");
  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({ command: "connect_device", payload: { deviceId: "YLX-REAL" } }),
  );
});

test("cancelPairing names the exact attempt it means, not just the device", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
  });

  await api.cancelPairing("YLX-REAL", "attempt-0001");

  assert.equal(
    JSON.stringify(invocation),
    JSON.stringify({
      command: "cancel_pairing",
      payload: { deviceId: "YLX-REAL", attemptId: "attempt-0001" },
    }),
  );
});

test("revisioned read responses preserve the backend envelope while value-only api stays compatible", async () => {
  clearMocks();
  mockIPC((command) => {
    if (command === "list_devices") {
      return {
        revision: 17,
        value: [{ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null }],
      };
    }
    return [];
  });

  const revisioned = await revisionedApi.listDevices();
  assert.equal(revisioned.revision, 17);
  assert.deepEqual(
    revisioned.value.map((device) => device.id),
    [DEVICE_ID],
  );
  assert.deepEqual(
    (await api.listDevices()).map((device) => device.id),
    [DEVICE_ID],
  );
});

test("revisioned command envelopes reject malformed or unsafe revisions", async () => {
  const devices = [{ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null }];
  const invalidEnvelopes: unknown[] = [
    { revision: -1, value: devices },
    { revision: 1.5, value: devices },
    { revision: Number.POSITIVE_INFINITY, value: devices },
    { revision: Number.MAX_SAFE_INTEGER + 1, value: devices },
    { revision: 1 },
    { value: devices },
  ];

  for (const envelope of invalidEnvelopes) {
    clearMocks();
    mockIPC(() => envelope);
    const failure = await revisionedApi.listDevices().then(
      () => null,
      (error: unknown) => error,
    );
    assert.ok(failure instanceof RuntimeDecodeError, `envelope ${JSON.stringify(envelope)} must fail closed`);
  }
});

test("revisioned command envelopes accept zero and the maximum safe revision", async () => {
  for (const revision of [0, Number.MAX_SAFE_INTEGER]) {
    clearMocks();
    mockIPC(() => ({
      revision,
      value: [{ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: null, state: "idle", lastSeen: null }],
    }));
    assert.equal((await revisionedApi.listDevices()).revision, revision);
  }
});

test("all revisioned read surfaces reject a bare response", async () => {
  clearMocks();
  mockIPC(() => []);
  const failure = await api.listDevices().then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(failure instanceof RuntimeDecodeError);
});

test("saveStorageConfig validates its envelope before unwrapping", async () => {
  clearMocks();
  const config = {
    endpoint: "https://s3.example.test",
    bucket: "recordings",
    prefix: "ylx",
    urlStyle: "virtualHost" as const,
    accessKey: "access",
    secretKey: "secret",
    downloadRoot: "/recordings",
  };
  const storage = {
    endpoint: config.endpoint,
    bucket: config.bucket,
    prefix: config.prefix,
    urlStyle: config.urlStyle,
    secretConfigured: true,
    downloadRoot: config.downloadRoot,
    activeDownloadRoot: config.downloadRoot,
  };
  mockIPC(() => ({ revision: 12, value: storage }));
  assert.deepEqual(await api.saveStorageConfig(config), storage);
  assert.deepEqual(await revisionedApi.saveStorageConfig(config), { revision: 12, value: storage });
});

test("structured command rejections preserve stable RPC error fields", async () => {
  const rpcError = {
    code: "session_list_failed",
    message: "设备暂时不可用",
    retryable: true,
    details: { deviceId: DEVICE_ID },
  } as const;
  clearMocks();
  mockIPC(() => {
    throw rpcError;
  });

  const failure = await api.listSessions(DEVICE_ID).then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(failure instanceof RpcInvocationError);
  if (failure instanceof RpcInvocationError) assert.deepEqual(failure.rpcError, rpcError);
});

test("catalog_changed command rejections preserve the replacement catalog revision", async () => {
  const catalogRevision = `sha256:${"d".repeat(64)}`;
  const rpcError = {
    code: "session_catalog_changed",
    message: "The cursor belongs to an older catalog revision.",
    retryable: true,
    details: { catalogRevision },
  } as const;
  clearMocks();
  mockIPC(() => {
    throw { error: rpcError };
  });

  const failure = await revisionedApi.listSessions(DEVICE_ID, "opaque-cursor", "old-revision").then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(failure instanceof RpcInvocationError);
  if (failure instanceof RpcInvocationError) assert.deepEqual(failure.rpcError, rpcError);
});

test("malformed structured command rejections fail closed", async () => {
  clearMocks();
  mockIPC(() => {
    throw {
      error: {
        code: "session_list_failed",
        message: "设备暂时不可用",
        retryable: true,
        details: "not-an-object",
      },
    };
  });
  const failure = await api.listSessions(DEVICE_ID).then(
    () => null,
    (error: unknown) => error,
  );
  assert.ok(failure instanceof RuntimeDecodeError);
});

test("sessions:update reuses canonical device identity validation", async () => {
  clearMocks();
  mockIPC(() => undefined, { shouldMockEvents: true });
  const seen: string[] = [];
  const diagnostics: string[] = [];
  const originalConsoleError = console.error;
  const catalog = {
    sessions: [],
    catalogRevision: "catalog-1",
    nextCursor: null,
    hasMore: false,
    catalogAuthority: "deviceSnapshot",
    paginationSupported: true,
    paginationUnavailableReason: null,
    capabilities: {
      profile: "labHttpV4",
      sessionDeletion: { supported: false, source: "profileContract" },
      sessionDetail: { supported: true, source: "profileContract" },
      artifactDownload: { supported: false, source: "unavailable" },
      captureStatus: { supported: true, source: "profileContract" },
    },
    diagnostics: [],
  };
  console.error = (...values: unknown[]) => diagnostics.push(values.map(String).join(" "));
  const unlisten = await onSessionsUpdate((payload) => seen.push(payload.deviceId));
  try {
    await emit("sessions:update", { revision: 1, value: { deviceId: DEVICE_DISPLAY_ID, ...catalog } });
    await emit("sessions:update", { revision: 2, value: { deviceId: DEVICE_ID, ...catalog } });
  } finally {
    await unlisten();
    console.error = originalConsoleError;
  }
  assert.deepEqual(seen, [DEVICE_ID]);
  assert.equal(diagnostics.length, 1);
});

test("storage:update delivers the server revision and rejects a bare payload", async () => {
  clearMocks();
  mockIPC(() => undefined, { shouldMockEvents: true });
  const seen: number[] = [];
  const diagnostics: string[] = [];
  const originalConsoleError = console.error;
  console.error = (...values: unknown[]) => diagnostics.push(values.map(String).join(" "));
  const unlisten = await onStorageUpdate((_storage, revision) => seen.push(revision));
  const storage = {
    endpoint: "https://s3.example.test",
    bucket: "recordings",
    prefix: "ylx",
    urlStyle: "virtualHost",
    secretConfigured: true,
    downloadRoot: "/recordings",
    activeDownloadRoot: "/recordings",
  };
  try {
    await emit("storage:update", storage);
    await emit("storage:update", { revision: 17, value: storage });
  } finally {
    await unlisten();
    console.error = originalConsoleError;
  }
  assert.deepEqual(seen, [17]);
  assert.equal(diagnostics.length, 1);
});

test("malformed event revisions are logged and dropped before subscriber callbacks", async () => {
  clearMocks();
  mockIPC(() => undefined, { shouldMockEvents: true });
  const seen: Array<number | undefined> = [];
  const diagnostics: string[] = [];
  const originalConsoleError = console.error;
  console.error = (...values: unknown[]) => diagnostics.push(values.map(String).join(" "));
  const unlisten = await onDevicesUpdate((_devices, revision) => seen.push(revision));
  const devices = [{ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: null, state: "idle", lastSeen: null }];

  try {
    const malformedPayloads: unknown[] = [
      ...[-1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1].map((revision) => ({
        revision,
        value: devices,
      })),
      { revision: 1 },
      { value: devices },
    ];
    for (const payload of malformedPayloads) {
      await emit("devices:update", payload);
    }
    await emit("devices:update", { revision: 0, value: devices });
    await emit("devices:update", { revision: Number.MAX_SAFE_INTEGER, value: devices });
  } finally {
    await unlisten();
    console.error = originalConsoleError;
  }

  assert.deepEqual(seen, [0, Number.MAX_SAFE_INTEGER]);
  assert.equal(diagnostics.length, 6, "every malformed event is diagnosed once and never delivered");
});
