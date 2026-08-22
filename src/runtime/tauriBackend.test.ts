import { test } from "node:test";
import assert from "node:assert/strict";

import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";

import { BackendError, type BackendEvent } from "./backend";
import { createTauriBackend } from "./tauriBackend";
import { asDeviceId, asSessionId } from "../ids";
import { jobIdFor } from "./batch";

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: globalThis,
});

const DEVICE_ID = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DEVICE_DISPLAY_ID = "YLX-ABCDEF01";

test("backend snapshot keeps the newest Rust resource revision", async () => {
  clearMocks();
  mockIPC((command) => {
    if (command !== "read_snapshot") return null;
    return {
      revision: 8,
      value: {
        devices: { revision: 4, value: [] },
        library: { revision: 8, value: [] },
        transfers: { revision: 6, value: [] },
        storage: {
          revision: 3,
          value: {
            endpoint: "",
            bucket: "",
            prefix: "",
            urlStyle: "virtualHost",
            secretConfigured: false,
            downloadRoot: "",
            activeDownloadRoot: "/downloads",
          },
        },
      },
    };
  });

  const snapshot = await createTauriBackend().readSnapshot();
  assert.equal(snapshot.revision, 8);
  assert.deepEqual(snapshot.value.devices, []);
  assert.deepEqual(snapshot.value.library, []);
  assert.deepEqual(snapshot.value.revisions, { devices: 4, library: 8, transfers: 6, storage: 3 });
});

test("backend snapshot rejects every unsafe resource watermark", async () => {
  for (const invalidRevision of [-1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
    clearMocks();
    mockIPC((command) => {
      if (command !== "read_snapshot") return null;
      return {
        revision: 10,
        value: {
          devices: { revision: 0, value: [] },
          library: { revision: invalidRevision, value: [] },
          transfers: { revision: 0, value: [] },
          storage: {
            revision: 0,
            value: {
              endpoint: "",
              bucket: "",
              prefix: "",
              urlStyle: "virtualHost",
              secretConfigured: false,
              downloadRoot: "",
              activeDownloadRoot: "/downloads",
            },
          },
        },
      };
    });

    const failure = await createTauriBackend()
      .readSnapshot()
      .then(
        () => null,
        (error: unknown) => error,
      );
    assert.ok(failure instanceof BackendError, `${String(invalidRevision)} must not become a snapshot watermark`);
    if (failure instanceof BackendError) assert.equal(failure.channel, "read_snapshot");
  }
});

test("backend snapshot rejects missing nested envelopes and inner revisions newer than the outer", async () => {
  const validStorage = {
    endpoint: "",
    bucket: "",
    prefix: "",
    urlStyle: "virtualHost",
    secretConfigured: false,
    downloadRoot: "",
    activeDownloadRoot: "/downloads",
  };
  const base = {
    devices: { revision: 0, value: [] },
    library: { revision: 0, value: [] },
    transfers: { revision: 0, value: [] },
    storage: { revision: 0, value: validStorage },
  };
  for (const value of [
    { ...base, library: { value: [] } },
    { ...base, storage: { revision: 0 } },
    { ...base, devices: { revision: 11, value: [] } },
  ]) {
    clearMocks();
    mockIPC(() => ({ revision: 10, value }));
    const failure = await createTauriBackend()
      .readSnapshot()
      .then(
        () => null,
        (error: unknown) => error,
      );
    assert.ok(failure instanceof BackendError);
  }
});

test("backend errors retain structured RPC diagnostics", async () => {
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

  const failure = await createTauriBackend()
    .listSessions(asDeviceId(DEVICE_ID))
    .then(
      () => null,
      (error: unknown) => error,
    );
  assert.ok(failure instanceof BackendError);
  if (failure instanceof BackendError) {
    assert.equal(failure.message, rpcError.message);
    assert.deepEqual(failure.rpcError, rpcError);
  }
});

test("addManualDevice preserves the server revision", async () => {
  clearMocks();
  mockIPC((command) => {
    if (command !== "add_manual_device") return null;
    return {
      revision: 12,
      value: { id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null },
    };
  });

  const result = await createTauriBackend().addManualDevice("192.0.2.10");
  assert.equal(result.revision, 12);
  assert.equal(result.value.id, DEVICE_ID);
});

test("addManualDevice rejects a legacy bare response", async () => {
  clearMocks();
  mockIPC(() => ({ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: "192.0.2.10", state: "idle", lastSeen: null }));

  const failure = await createTauriBackend()
    .addManualDevice("192.0.2.10")
    .then(
      () => null,
      (error: unknown) => error,
    );
  assert.ok(failure instanceof BackendError);
});

test("backend accepts shuffled tagged dispatch results and enforces request coverage", async () => {
  clearMocks();
  mockIPC(() => ({
    results: [
      { status: "success", item: "session-b", jobId: "job-b" },
      { status: "success", item: "session-a", jobId: "job-a" },
    ],
  }));
  const backend = createTauriBackend();
  const dispatch = await backend.downloadSessions(asDeviceId(DEVICE_ID), [
    asSessionId("session-a"),
    asSessionId("session-b"),
  ]);
  assert.equal(jobIdFor(dispatch.items, asSessionId("session-a")), "job-a");
  assert.equal(jobIdFor(dispatch.items, asSessionId("session-b")), "job-b");

  clearMocks();
  mockIPC(() => ({ results: [{ status: "success", item: "session-a", jobId: "job-a" }] }));
  const failure = await backend
    .downloadSessions(asDeviceId(DEVICE_ID), [asSessionId("session-a"), asSessionId("session-b")])
    .then(
      () => null,
      (error: unknown) => error,
    );
  assert.ok(failure instanceof BackendError);
  if (failure instanceof BackendError) assert.ok(failure.message.includes("omitted batch results"));
});

test("events require server revisions and reject bare payloads", async () => {
  clearMocks();
  mockIPC(() => undefined, { shouldMockEvents: true });
  const events: Array<{ revision: number }> = [];
  const diagnostics: string[] = [];
  const originalConsoleError = console.error;
  console.error = (...values: unknown[]) => diagnostics.push(values.map(String).join(" "));
  const dispose = await createTauriBackend().subscribe((event) => events.push(event));
  const devices = [{ id: DEVICE_ID, displayId: DEVICE_DISPLAY_ID, ip: null, state: "idle", lastSeen: null }];

  try {
    await emit("devices:update", { revision: Number.MAX_SAFE_INTEGER, value: devices });
    await emit("devices:update", devices);
  } finally {
    dispose();
    console.error = originalConsoleError;
  }

  assert.deepEqual(
    events.map((event) => event.revision),
    [Number.MAX_SAFE_INTEGER],
  );
  assert.equal(diagnostics.length, 1, "the bare event is diagnosed and dropped");
});

test("Tauri backend forwards storage events without inventing a revision", async () => {
  clearMocks();
  mockIPC(() => undefined, { shouldMockEvents: true });
  const seen: BackendEvent[] = [];
  const backend = createTauriBackend();
  const dispose = await backend.subscribe((event) => seen.push(event));
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
    await emit("storage:update", { revision: 42, value: storage });
  } finally {
    dispose();
  }
  assert.deepEqual(seen, [{ kind: "storage", revision: 42, storage }]);
});
