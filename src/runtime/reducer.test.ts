import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createAppStore,
  deviceById,
  deviceDisplayIdOf,
  devicesOf,
  sessionsOf,
  sessionsResourceOf,
  storageOf,
} from "./reducer";
import { createFakeClock } from "./clock";
import { createConfirmController } from "./confirm";
import { EMPTY_STORAGE } from "./memoryBackend";
import type { Device, SessionView } from "../types";

function device(id: string, state: Device["state"] = "idle"): Device {
  return { id, displayId: id, ip: null, state, lastSeen: null };
}

const COLLIDING_DEVICE_A = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const COLLIDING_DEVICE_B = "ylx-abcdef0198765432abcdef0198765432abcdef0198765432abcdef0198765432";

function session(id: string): SessionView {
  return {
    id,
    revision: "r1",
    dateLabel: "2026-08-03T00:00:00Z",
    durationSeconds: 1,
    totalBytes: 1,
    videoBytes: 1,
    imuSamples: null,
    files: [],
    downloadStatus: "none",
    backedUp: false,
  };
}

test("a stale-revision value never overwrites newer state", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 7, devices: [device("newest")] });
  const result = store.commit({ type: "devices/loaded", revision: 3, devices: [device("late-reply")] });

  assert.equal(result.stale, true);
  assert.equal(result.changed, false);
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["newest"],
  );
});

test("a same-revision reply is accepted, since it cannot be older", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 4, devices: [device("a")] });
  const result = store.commit({ type: "devices/loaded", revision: 4, devices: [device("a"), device("b")] });

  assert.equal(result.stale, false);
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["a", "b"],
  );
});

test("canonical device identities stay distinct when display labels collide", () => {
  const store = createAppStore();
  store.commit({
    type: "devices/loaded",
    revision: 1,
    devices: [
      { ...device(COLLIDING_DEVICE_A), displayId: "YLX-ABCDEF01" },
      { ...device(COLLIDING_DEVICE_B), displayId: "YLX-ABCDEF01" },
    ],
  });

  assert.equal(deviceById(store.getState(), COLLIDING_DEVICE_A)?.id, COLLIDING_DEVICE_A);
  assert.equal(deviceById(store.getState(), COLLIDING_DEVICE_B)?.id, COLLIDING_DEVICE_B);
  assert.equal(deviceDisplayIdOf(store.getState(), COLLIDING_DEVICE_A), "YLX-ABCDEF01");
  assert.equal(deviceDisplayIdOf(store.getState(), COLLIDING_DEVICE_B), "YLX-ABCDEF01");
});

test("an unchanged value reports no visible change, so views do not repaint", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 1, devices: [device("a")] });
  const result = store.commit({ type: "devices/loaded", revision: 2, devices: [device("a")] });

  assert.equal(result.changed, false);
  assert.equal(store.getState().devices.revision, 2, "the revision still advances");
});

test("a failed refresh degrades to the last good value instead of blanking", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";

  store.commit({ type: "sessions/loaded", revision: 1, deviceId, sessions: [session("s1")] });
  store.commit({ type: "resource/loading", resource: "sessions", deviceId });
  store.commit({ type: "resource/failed", resource: "sessions", deviceId, error: "device unreachable" });

  const resource = sessionsResourceOf(store.getState(), deviceId);
  assert.equal(resource.loading, false);
  assert.equal(resource.error, "device unreachable");
  assert.deepEqual(
    resource.value?.map((s) => s.id),
    ["s1"],
    "the last good snapshot stays on screen",
  );
  assert.deepEqual(
    sessionsOf(store.getState(), deviceId)?.map((s) => s.id),
    ["s1"],
  );
});

test("a resource failure retains structured retryability and code", () => {
  const store = createAppStore();
  const rpcError = {
    code: "session_delete_failed",
    message: "删除会话失败",
    retryable: false,
    details: { deviceId: "YLX-A", sessionId: "s1" },
  } as const;

  store.commit({
    type: "resource/failed",
    resource: "sessions",
    deviceId: "YLX-A",
    error: rpcError.message,
    rpcError,
  });

  assert.deepEqual(sessionsResourceOf(store.getState(), "YLX-A").rpcError, rpcError);
  assert.equal(sessionsResourceOf(store.getState(), "YLX-A").rpcError?.retryable, false);
});

test("a retry failure from an older resource revision cannot degrade newer data", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 2, devices: [device("newer")] });
  const result = store.commit({
    type: "resource/failed",
    resource: "devices",
    revision: 1,
    error: "late retry failed",
  });

  assert.equal(result.stale, true);
  assert.equal(store.getState().devices.error, null);
  assert.deepEqual(
    devicesOf(store.getState()).map((item) => item.id),
    ["newer"],
  );
});

test("storageConfig is the public resource name but shares storage state", () => {
  const store = createAppStore();

  store.commit({ type: "storage/loaded", revision: 3, storage: EMPTY_STORAGE });
  store.commit({ type: "resource/loading", resource: "storageConfig" });
  assert.equal(store.getState().storage.loading, true);
  store.commit({ type: "resource/failed", resource: "storageConfig", error: "config unavailable" });
  assert.equal(store.getState().storage.error, "config unavailable");
  assert.equal(store.getState().storage.value, EMPTY_STORAGE);
});

test("a resource that never loaded stays absent, not empty", () => {
  const store = createAppStore();

  store.commit({ type: "resource/failed", resource: "sessions", deviceId: "YLX-A", error: "boom" });

  assert.equal(sessionsOf(store.getState(), "YLX-A"), undefined, "absent and empty are different screens");
});

test("a backend event commits through the same entry point as a snapshot", () => {
  const store = createAppStore();

  store.commit({
    type: "backend/snapshot",
    revision: 1,
    snapshot: {
      devices: [device("a")],
      library: [],
      transfers: [],
      storage: EMPTY_STORAGE,
      revisions: { devices: 1, library: 1, transfers: 1, storage: 1 },
    },
  });
  store.commit({
    type: "backend/event",
    event: { kind: "devices", revision: 2, devices: [device("a", "connected")] },
  });

  assert.equal(devicesOf(store.getState())[0].state, "connected");
  assert.equal(storageOf(store.getState()).activeDownloadRoot, EMPTY_STORAGE.activeDownloadRoot);
});

test("a stale snapshot cannot undo an event that already landed", () => {
  const store = createAppStore();

  store.commit({ type: "backend/event", event: { kind: "devices", revision: 9, devices: [device("live")] } });
  const result = store.commit({
    type: "backend/snapshot",
    revision: 4,
    snapshot: {
      devices: [device("old")],
      library: [],
      transfers: [],
      storage: EMPTY_STORAGE,
      revisions: { devices: 4, library: 4, transfers: 4, storage: 4 },
    },
  });

  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["live"],
  );
  assert.equal(result.changed, true, "the snapshot still fills in the resources it is newest for");
});

test("each resource and each device session stream rejects an out-of-order event independently", () => {
  const store = createAppStore();
  const newerStorage = { ...EMPTY_STORAGE, bucket: "new" };
  store.commit({ type: "backend/event", event: { kind: "devices", revision: 2, devices: [device("devices-new")] } });
  store.commit({ type: "backend/event", event: { kind: "devices", revision: 1, devices: [device("devices-old")] } });
  store.commit({ type: "backend/event", event: { kind: "library", revision: 2, library: [] } });
  store.commit({ type: "backend/event", event: { kind: "library", revision: 1, library: [] } });
  store.commit({ type: "backend/event", event: { kind: "transfers", revision: 2, transfers: [] } });
  store.commit({ type: "backend/event", event: { kind: "transfers", revision: 1, transfers: [] } });
  store.commit({ type: "backend/event", event: { kind: "storage", revision: 2, storage: newerStorage } });
  store.commit({ type: "backend/event", event: { kind: "storage", revision: 1, storage: EMPTY_STORAGE } });
  store.commit({ type: "backend/event", event: { kind: "sessions", revision: 2, deviceId: "A", sessions: [] } });
  store.commit({ type: "backend/event", event: { kind: "sessions", revision: 1, deviceId: "A", sessions: [] } });
  store.commit({ type: "backend/event", event: { kind: "sessions", revision: 1, deviceId: "B", sessions: [] } });

  assert.equal(devicesOf(store.getState())[0]?.id, "devices-new");
  assert.equal(store.getState().devices.revision, 2);
  assert.equal(store.getState().library.revision, 2);
  assert.equal(store.getState().transfers.revision, 2);
  assert.equal(store.getState().storage.revision, 2);
  assert.equal(store.getState().storage.value?.bucket, "new");
  assert.equal(store.getState().sessions.get("A")?.revision, 2);
  assert.equal(store.getState().sessions.get("B")?.revision, 1);
});

test("a confirm timer expires through the reducer, not by writing state directly", () => {
  const store = createAppStore();
  const clock = createFakeClock();
  const confirm = createConfirmController({ store, clock, ttlMs: 4000 });
  const target = "device:cleanupBackedUp:YLX-A";

  confirm.request(target);

  clock.advance(3999);
  assert.equal(confirm.phase(target).phase, "confirming", "the confirmation is still armed");
  clock.advance(1);
  assert.equal(confirm.phase(target).phase, "idle");
  assert.equal(clock.pending(), 0);
});

test("a second commit of the same ui value reports no change", () => {
  const store = createAppStore();

  assert.equal(store.commit({ type: "ui/view", view: "library" }).changed, true);
  assert.equal(store.commit({ type: "ui/view", view: "library" }).changed, false);
});

test("a pairing reply for a superseded flow is rejected as stale", () => {
  const store = createAppStore();

  store.commit({ type: "ui/pairingStarted", deviceId: "YLX-A" });
  store.commit({ type: "ui/pairingStarted", deviceId: "YLX-B" });
  const late = store.commit({ type: "ui/pairingAttempt", deviceId: "YLX-A", attemptId: "attempt-1" });

  assert.equal(late.stale, true);
  assert.equal(store.getState().ui.pairingAttemptId, null, "the newer flow keeps the overlay");
});
