import { test } from "node:test";
import assert from "node:assert/strict";

import { asDeviceId, asSessionId } from "../ids";
import type { BackendEvent } from "./backend";
import { createMemoryBackend, EMPTY_STORAGE } from "./memoryBackend";
import type { SessionView } from "../types";

function session(id: string): SessionView {
  return {
    id,
    revision: "r1",
    dateLabel: "2026-08-04",
    durationSeconds: 1,
    totalBytes: 1,
    videoBytes: 1,
    imuSamples: null,
    files: [],
    downloadStatus: "none",
    backedUp: false,
  };
}

test("memory mutations return the same resource revision they emit", async () => {
  const backend = createMemoryBackend();
  const events: BackendEvent[] = [];
  const dispose = await backend.subscribe((event) => events.push(event));
  backend.setSessions("device-a", [session("session-a")]);

  const sessionResult = await backend.deleteSessions(asDeviceId("device-a"), [asSessionId("session-a")]);
  const sessionEvent = events.find((event) => event.kind === "sessions");
  assert.ok(sessionEvent);
  assert.equal(sessionResult.revision, sessionEvent.revision);
  assert.equal(sessionResult.value.sessions?.length, 0);

  const config = {
    endpoint: "https://s3.example.test",
    bucket: "recordings",
    prefix: "ylx",
    urlStyle: "virtualHost" as const,
    accessKey: "access",
    secretKey: "secret",
    downloadRoot: "/recordings",
  };
  const storageResult = await backend.saveStorageConfig(config);
  const storageEvent = events.find((event) => event.kind === "storage");
  assert.ok(storageEvent);
  assert.equal(storageResult.revision, storageEvent.revision);
  assert.equal(storageResult.value.bucket, "recordings");

  const snapshot = await backend.readSnapshot();
  assert.equal(snapshot.value.revisions.storage, storageResult.revision);
  assert.equal(snapshot.value.revisions.devices, 0);
  assert.deepEqual(snapshot.value.storage, storageResult.value);
  dispose();
});

test("session revisions are independent per device", async () => {
  const backend = createMemoryBackend({ snapshot: { storage: EMPTY_STORAGE } });
  backend.setSessions("device-a", [session("a")]);
  backend.setSessions("device-b", [session("b")]);
  const first = await backend.listSessions(asDeviceId("device-a"));
  const second = await backend.listSessions(asDeviceId("device-b"));
  assert.equal(first.revision, 0);
  assert.equal(second.revision, 0);

  await backend.cleanupBackedUp(asDeviceId("device-a"));
  const afterA = await backend.listSessions(asDeviceId("device-a"));
  const untouchedB = await backend.listSessions(asDeviceId("device-b"));
  assert.ok(afterA.revision > first.revision);
  assert.equal(untouchedB.revision, second.revision);
});

test("held reads stamp the value and resource revision from the same state", async () => {
  const backend = createMemoryBackend();
  backend.hold("listDevices");

  const pending = backend.listDevices();
  const revision = backend.emit({
    kind: "devices",
    devices: [{ id: "ylx-device", displayId: "YLX-00000000", ip: "192.0.2.1", state: "idle", lastSeen: null }],
  });
  backend.release("listDevices");

  const result = await pending;
  assert.equal(result.revision, revision);
  assert.deepEqual(result.value, [
    { id: "ylx-device", displayId: "YLX-00000000", ip: "192.0.2.1", state: "idle", lastSeen: null },
  ]);
});

test("saving settings with an empty secret preserves the configured-secret marker", async () => {
  const backend = createMemoryBackend({ snapshot: { storage: { ...EMPTY_STORAGE, secretConfigured: true } } });

  const result = await backend.saveStorageConfig({
    endpoint: "https://s3.example.test",
    bucket: "recordings",
    prefix: "ylx",
    urlStyle: "virtualHost",
    accessKey: "access",
    secretKey: "",
    downloadRoot: "/recordings",
  });

  assert.equal(result.value.secretConfigured, true);
});

test("event sink failures are isolated while mutations and later reads converge", async () => {
  const backend = createMemoryBackend();
  const delivered: BackendEvent[] = [];
  const sinkError = new Error("sink exploded");
  await backend.subscribe(() => {
    throw sinkError;
  });
  await backend.subscribe((event) => delivered.push(event));

  const mutation = await backend.saveDownloadRoot("/captures");
  const event = delivered.find((item) => item.kind === "storage");
  assert.ok(event);
  assert.equal(event.revision, mutation.revision);
  assert.equal(backend.deliveryFailures.length, 1);
  assert.ok(backend.deliveryFailures[0]?.error !== sinkError);
  assert.equal(backend.deliveryFailures[0]?.error.message, sinkError.message);

  const read = await backend.getStorageConfig();
  assert.equal(read.revision, mutation.revision);
  assert.deepEqual(read.value, mutation.value);
});

test("addManualDevice returns and emits the same devices revision", async () => {
  const backend = createMemoryBackend();
  const events: BackendEvent[] = [];
  await backend.subscribe((event) => events.push(event));

  const result = await backend.addManualDevice("192.0.2.10");
  const event = events.find((item) => item.kind === "devices");
  assert.ok(event);
  assert.equal(result.revision, event.revision);
  assert.deepEqual(event.devices, [result.value]);

  const read = await backend.listDevices();
  assert.equal(read.revision, result.revision);
  assert.deepEqual(read.value, [result.value]);
});
