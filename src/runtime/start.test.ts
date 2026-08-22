// Boot ordering, against the in-memory backend. No real timers, no transport:
// every interleaving here is produced by holding a call and releasing it.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createMemoryBackend, EMPTY_STORAGE } from "./memoryBackend";
import { createAppStore, devicesOf } from "./reducer";
import { startBackend } from "./start";
import { BackendError } from "./backend";
import type { BackendEvent, TransferBackend } from "./backend";
import type { Device } from "../types";

function device(id: string, state: Device["state"] = "idle"): Device {
  return { id, displayId: "YLX-00000000", ip: "192.0.2.1", state, lastSeen: null };
}

/** Drains microtasks until `predicate` holds. Nothing in these tests uses a
 * timer, so a settled microtask queue means the runtime has made all the
 * progress it can. */
async function until(predicate: () => boolean, what: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}`);
}

test("an event that arrives before the snapshot is buffered, then applied in order", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device("YLX-A")] } });
  const store = createAppStore();
  const applied: BackendEvent[] = [];
  backend.hold("readSnapshot");

  const starting = startBackend({ backend, store, onEvent: (event) => applied.push(event) });
  await until(() => backend.pending("readSnapshot") > 0, "the snapshot read to be issued");

  // Two events race the snapshot read; neither may be lost.
  backend.emit({ kind: "devices", devices: [device("YLX-A", "connected")] });
  backend.emit({ kind: "devices", devices: [device("YLX-A", "connected"), device("YLX-B")] });
  assert.deepEqual(applied, [], "events must be buffered until the snapshot has been committed");

  backend.release("readSnapshot");
  const session = await starting;

  assert.deepEqual(
    applied.map((event) => (event.kind === "devices" ? event.devices.map((d) => d.id) : [])),
    [["YLX-A"], ["YLX-A", "YLX-B"]],
    "buffered events replay in arrival order",
  );
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["YLX-A", "YLX-B"],
    "the newest event wins over the older snapshot",
  );
  session.dispose();
});

test("a snapshot never overwrites an event that is newer than it", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device("stale-snapshot")] } });
  const store = createAppStore();
  backend.hold("readSnapshot");

  const starting = startBackend({ backend, store });
  await until(() => backend.pending("readSnapshot") > 0, "the snapshot read to be issued");
  backend.emit({ kind: "devices", devices: [device("from-event")] });
  backend.release("readSnapshot");
  const session = await starting;

  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["from-event"],
  );
  session.dispose();
});

test("buffered events the snapshot already includes are discarded, newer ones replayed", async () => {
  const memory = createMemoryBackend();
  const store = createAppStore();
  const applied: BackendEvent[] = [];

  let release = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  // A snapshot that resolves late and whose revision already covers the first
  // two events — exactly the race the buffer exists for.
  let readIssued = false;
  const backend: TransferBackend = {
    ...memory,
    readSnapshot: () => {
      readIssued = true;
      return gate.then(() => ({
        revision: 2,
        value: {
          devices: [device("from-snapshot")],
          library: [],
          transfers: [],
          storage: EMPTY_STORAGE,
          revisions: { devices: 2, library: 2, transfers: 2, storage: 2 },
        },
      }));
    },
  };

  const starting = startBackend({ backend, store, onEvent: (event) => applied.push(event) });
  await until(() => readIssued, "the snapshot read to be issued");
  memory.emit({ kind: "devices", devices: [device("revision-1")] }); // revision 1 — covered
  memory.emit({ kind: "devices", devices: [device("revision-2")] }); // revision 2 — covered
  memory.emit({ kind: "devices", devices: [device("revision-3")] }); // revision 3 — newer
  release();
  const session = await starting;

  assert.deepEqual(
    applied.map((event) => (event.kind === "devices" ? event.devices[0].id : "")),
    ["revision-3"],
    "only events strictly newer than the snapshot are replayed",
  );
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["revision-3"],
  );
  session.dispose();
});

test("normal snapshot replay uses each resource watermark and replays unsnapshotted streams", async () => {
  const store = createAppStore();
  let release = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let sink: ((event: BackendEvent) => void) | null = null;
  const memory = createMemoryBackend();
  const backend: TransferBackend = {
    ...memory,
    subscribe: async (next) => {
      sink = next;
      return () => {
        sink = null;
      };
    },
    readSnapshot: () =>
      gate.then(() => ({
        revision: 20,
        value: {
          devices: [device("snapshot-device")],
          library: [],
          transfers: [],
          storage: EMPTY_STORAGE,
          revisions: { devices: 10, library: 3, transfers: 8, storage: 5 },
        },
      })),
  };
  const applied: string[] = [];
  const starting = startBackend({
    backend,
    store,
    onEvent: (event) => applied.push(`${event.kind}:${event.revision}`),
  });
  await until(() => sink !== null, "subscription");
  const push = sink as unknown as (event: BackendEvent) => void;
  push({ kind: "devices", revision: 10, devices: [device("old-device")] });
  push({ kind: "devices", revision: 11, devices: [device("new-device")] });
  push({ kind: "library", revision: 3, library: [] });
  push({ kind: "library", revision: 4, library: [] });
  push({ kind: "storage", revision: 5, storage: EMPTY_STORAGE });
  push({ kind: "storage", revision: 6, storage: { ...EMPTY_STORAGE, bucket: "new" } });
  push({ kind: "sessions", revision: 1, deviceId: "YLX-A", sessions: [] });
  push({ kind: "transferJobs", revision: 1, jobs: [] });
  push({
    kind: "pairingTick",
    revision: 1,
    payload: { deviceId: "YLX-A", attemptId: "attempt-1", remaining: 1, total: 2 },
  });
  release();
  const session = await starting;

  assert.deepEqual(applied, ["devices:11", "library:4", "storage:6", "sessions:1", "transferJobs:1", "pairingTick:1"]);
  assert.equal(devicesOf(store.getState())[0]?.id, "new-device");
  assert.equal(store.getState().storage.value?.bucket, "new");
  session.dispose();
});

test("fallback replay compares each event with its own resource watermark", async () => {
  const memory = createMemoryBackend();
  const store = createAppStore();
  const applied: string[] = [];
  let releaseLibrary = () => {};
  const libraryGate = new Promise<void>((resolve) => {
    releaseLibrary = resolve;
  });
  let libraryReadIssued = false;
  const backend: TransferBackend = {
    ...memory,
    readSnapshot: () => Promise.reject(new BackendError("list_devices", "aggregate unavailable")),
    listDevices: () => Promise.resolve({ revision: 0, value: [device("devices-snapshot")] }),
    listLibrary: () => {
      libraryReadIssued = true;
      return libraryGate.then(() => ({ revision: 5, value: [] }));
    },
    listTransfers: () => Promise.resolve({ revision: 0, value: [] }),
    getStorageConfig: () => Promise.resolve({ revision: 0, value: EMPTY_STORAGE }),
  };

  const starting = startBackend({
    backend,
    store,
    onEvent: (event) => applied.push(`${event.kind}:${event.revision}`),
  });
  await until(
    () => libraryReadIssued && devicesOf(store.getState())[0]?.id === "devices-snapshot",
    "the devices fallback snapshot to commit while library remains pending",
  );

  memory.emit({ kind: "devices", devices: [device("devices-event")] });
  memory.emit({ kind: "sessions", deviceId: "YLX-A", sessions: [] });
  releaseLibrary();
  const session = await starting;

  assert.deepEqual(
    applied,
    ["devices:1", "sessions:2"],
    "a high library revision must not hide a newer device event or an unseeded per-device session event",
  );
  assert.deepEqual(devicesOf(store.getState()), [device("devices-event")]);
  session.dispose();
});

test("replay drains reentrant events through the same FIFO before going live", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const applied: string[] = [];
  backend.hold("readSnapshot");

  const starting = startBackend({
    backend,
    store,
    onEvent: (event) => {
      if (event.kind !== "devices") return;
      const id = event.devices[0]?.id ?? "";
      applied.push(id);
      if (id === "first") backend.emit({ kind: "devices", devices: [device("third")] });
    },
  });
  await until(() => backend.pending("readSnapshot") > 0, "the snapshot read to be issued");
  backend.emit({ kind: "devices", devices: [device("first")] });
  backend.emit({ kind: "devices", devices: [device("second")] });
  backend.release("readSnapshot");
  const session = await starting;

  assert.deepEqual(applied, ["first", "second", "third"]);
  assert.deepEqual(devicesOf(store.getState()), [device("third")]);
  session.dispose();
});

test("a partial listener registration cleans up the listeners that did register", async () => {
  const backend = createMemoryBackend({ failingChannels: ["library"] });
  const store = createAppStore();

  const failure = await startBackend({ backend, store }).then(
    () => null,
    (error: unknown) => error,
  );

  assert.match(String(failure), /library/);
  assert.equal(backend.listening.length, 0, "no listener may outlive a failed start");
  assert.ok(backend.unsubscribed.length > 0, "the registered channels must have been unsubscribed");
  assert.ok(backend.unsubscribed.includes("storage"), "storage listener participates in rollback");
  assert.equal(
    backend.callNames().includes("readSnapshot"),
    false,
    "the snapshot is never read after a failed subscribe",
  );
});

test("a failed snapshot read disposes every listener before the failure escapes", async () => {
  const backend = createMemoryBackend();
  backend.failCalls("readSnapshot", new Error("storage unavailable"));
  const store = createAppStore();

  const failure = await startBackend({ backend, store }).then(
    () => null,
    (error: unknown) => error,
  );

  assert.match(String(failure), /storage unavailable/);
  assert.equal(backend.listening.length, 0);
  assert.equal(store.getState().devices.loading, false, "a failed boot leaves no resource stuck loading");
});

test("an onSnapshot exception disposes every listener and remains the rejection", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const callbackError = new Error("snapshot callback failed");

  const failure = await startBackend({
    backend,
    store,
    onSnapshot: () => {
      throw callbackError;
    },
  }).then(
    () => null,
    (error: unknown) => error,
  );

  assert.equal(failure, callbackError);
  assert.equal(backend.listening.length, 0);
  assert.equal(backend.unsubscribed.length, 8);
});

test("a replay onEvent exception disposes every listener and remains the rejection", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const callbackError = new Error("event callback failed");
  backend.hold("readSnapshot");

  const starting = startBackend({
    backend,
    store,
    onEvent: () => {
      throw callbackError;
    },
  });
  await until(() => backend.pending("readSnapshot") > 0, "the snapshot read to be issued");
  backend.emit({ kind: "devices", devices: [device("buffered")] });
  backend.release("readSnapshot");
  const failure = await starting.then(
    () => null,
    (error: unknown) => error,
  );

  assert.equal(failure, callbackError);
  assert.equal(backend.listening.length, 0);
  assert.equal(backend.unsubscribed.length, 8);
});

test("dispose is idempotent", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const session = await startBackend({ backend, store });
  const registered = backend.unsubscribed.length;

  session.dispose();
  const afterFirst = backend.unsubscribed.length;
  session.dispose();
  session.dispose();

  assert.ok(afterFirst > registered, "the first dispose unlistens");
  assert.equal(backend.unsubscribed.length, afterFirst, "later disposes are no-ops");
});

test("events delivered after dispose are ignored", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const session = await startBackend({ backend, store });

  session.dispose();
  backend.emit({ kind: "devices", devices: [device("after-dispose")] });

  assert.deepEqual(devicesOf(store.getState()), [], "a disposed session commits nothing");
});

test("a storage snapshot failure degrades boot without hiding devices", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device("YLX-A")] } });
  const storageFailure = new BackendError("get_storage_config", "对象存储暂不可用");
  // The aggregate read reports the failing resource, and the fallback read
  // keeps reporting it while the independent device/library/transfer reads
  // remain healthy.
  backend.failCalls("readSnapshot", storageFailure);
  backend.failCalls("getStorageConfig", storageFailure);
  const store = createAppStore();

  const session = await startBackend({ backend, store });

  assert.deepEqual(
    devicesOf(store.getState()).map((item) => item.id),
    ["YLX-A"],
  );
  assert.equal(store.getState().storage.value, null, "no fake empty storage config is painted");
  assert.equal(store.getState().storage.error, "对象存储暂不可用");
  assert.equal(store.getState().devices.error, null);
  session.dispose();
});

test("a recognized snapshot failure keeps the session alive when every resource is degraded", async () => {
  const backend = createMemoryBackend();
  const snapshotFailure = new BackendError("list_devices", "设备读取暂不可用");
  backend.failCalls("readSnapshot", snapshotFailure);
  backend.failCalls("listDevices", new BackendError("list_devices", "设备读取暂不可用"));
  backend.failCalls("listLibrary", new BackendError("list_library", "资料库读取暂不可用"));
  backend.failCalls("listTransfers", new BackendError("list_transfers", "队列读取暂不可用"));
  backend.failCalls("getStorageConfig", new BackendError("get_storage_config", "对象存储暂不可用"));
  const store = createAppStore();

  const session = await startBackend({ backend, store });

  assert.equal(backend.listening.length, 8, "independent resource failures must not tear down subscriptions");
  assert.equal(store.getState().devices.error, "设备读取暂不可用");
  assert.equal(store.getState().library.error, "资料库读取暂不可用");
  assert.equal(store.getState().transfers.error, "队列读取暂不可用");
  assert.equal(store.getState().storage.error, "对象存储暂不可用");
  session.dispose();
  assert.equal(backend.listening.length, 0);
});
