// One end-to-end pass through the runtime with no DOM and no transport:
// start → pair → browse sessions → download → live library update → dispose.
// Everything the views would do goes through the store and the runner, so this
// is the same code path the app runs.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createMemoryBackend } from "./memoryBackend";
import { createOperationRunner } from "./operations";
import { createAppStore, deviceById, devicesOf, libraryOf, sessionsOf } from "./reducer";
import { startBackend } from "./start";
import { classifyPairingEvent } from "../ui/pairingGuard";
import { acceptedItems } from "./batch";
import { asDeviceId, asSessionId } from "../ids";
import type { BackendEvent } from "./backend";
import type { Device, LibraryEntry, SessionView } from "../types";

function device(id: string, state: Device["state"] = "idle"): Device {
  return { id, displayId: "YLX-00000000", ip: "192.0.2.7", state, lastSeen: null };
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
  };
}

function libraryEntry(sessionId: string): LibraryEntry {
  return {
    deviceId: "YLX-A",
    deviceDisplayId: "YLX-00000000",
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

test("discover, pair, browse, download and converge — driven only by the runtime", async () => {
  const backend = createMemoryBackend({ snapshot: { devices: [device("YLX-A")] } });
  const store = createAppStore();
  const toasts: string[] = [];
  const runner = createOperationRunner({ toast: (message) => toasts.push(message) });
  const events: BackendEvent[] = [];

  const session_ = await startBackend({ backend, store, onEvent: (event) => events.push(event) });
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["YLX-A"],
    "the snapshot seeds the device list",
  );

  // Pairing: the attempt id from the command is what later events are matched
  // against, and the reducer owns that focus.
  store.commit({ type: "ui/pairingStarted", deviceId: "YLX-A" });
  const pairing = await runner.run({
    key: "device:pair:YLX-A",
    scope: "device:pair",
    run: () => backend.connectDevice(asDeviceId("YLX-A")),
    commit: (attemptId) => store.commit({ type: "ui/pairingAttempt", deviceId: "YLX-A", attemptId }),
  });
  assert.equal(pairing.status, "completed");
  assert.equal(store.getState().ui.pairingAttemptId, "attempt-YLX-A");

  assert.equal(
    classifyPairingEvent(
      { deviceId: store.getState().ui.pairingTargetId, attemptId: store.getState().ui.pairingAttemptId },
      { deviceId: "YLX-A", attemptId: "attempt-superseded" },
    ),
    "drop",
    "an event from another attempt can never drive this overlay",
  );

  backend.emit({ kind: "devices", devices: [device("YLX-A", "connected")] });
  store.commit({ type: "ui/pairingClosed" });
  assert.equal(deviceById(store.getState(), "YLX-A")?.state, "connected");

  // Browsing: the revisioned read is committed through the same entry point.
  backend.setSessions("YLX-A", [session("s1"), session("s2")]);
  await runner.run({
    key: "device:sessions:YLX-A",
    run: () => backend.listSessions(asDeviceId("YLX-A")),
    commit: ({ revision, value }) =>
      store.commit({ type: "sessions/loaded", revision, deviceId: "YLX-A", sessions: value }),
  });
  assert.deepEqual(
    sessionsOf(store.getState(), "YLX-A")?.map((s) => s.id),
    ["s1", "s2"],
  );

  // Downloading: one batch command, one toast decision, no ad-hoc try/catch.
  const download = await runner.run({
    key: "device:bulkDownload:YLX-A",
    run: () => backend.downloadSessions(asDeviceId("YLX-A"), [asSessionId("s1"), asSessionId("s2")]),
    success: (result) => `已加入下载队列 ${acceptedItems(result.items).length} 项`,
  });
  assert.equal(download.status, "completed");
  assert.deepEqual(toasts, ["已加入下载队列 2 项"]);

  // The backend then pushes the resulting library and progress.
  backend.emit({ kind: "library", library: [libraryEntry("s1")] });
  backend.emit({
    kind: "transfers",
    transfers: [
      {
        key: "YLX-A|s1",
        label: "s1",
        totalBytes: 100,
        sentBytes: 100,
        state: "succeeded",
        retryable: false,
        error: null,
        direction: "down",
        targetLabel: "本地",
      },
    ],
  });
  assert.deepEqual(
    libraryOf(store.getState()).map((entry) => entry.sessionId),
    ["s1"],
  );
  assert.equal(store.getState().transfers.value?.[0].state, "succeeded");
  assert.equal(events.length, 3, "every push reached the store exactly once");

  session_.dispose();
  backend.emit({ kind: "library", library: [] });
  assert.deepEqual(
    libraryOf(store.getState()).map((entry) => entry.sessionId),
    ["s1"],
    "dispose stops the session",
  );
});
