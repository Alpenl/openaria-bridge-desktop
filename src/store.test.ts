import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  confirmPhaseOf,
  createUiState,
  deviceRowKey,
  libraryRowKey,
  resetDeviceViewState,
  retainExistingSelection,
} from "./store";
import { createAppStore } from "./runtime/reducer";
import type { OperationId } from "./runtime/confirm";
import type { SessionView } from "./types";

const OP_1 = "op-1" as OperationId;

/** Ids arrive from LAN devices and from library keys, so they can be anything. */
const ADVERSARIAL_IDS = ["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", ""];

test("D-049 production assembly starts on LAN devices without a media workspace", () => {
  const mainSource = readFileSync(new URL("./main.ts", import.meta.url).pathname, "utf8");
  const html = readFileSync(new URL("../index.html", import.meta.url).pathname, "utf8");
  const domViewSource = readFileSync(new URL("./ui/views/appDom.ts", import.meta.url).pathname, "utf8");

  assert.equal(createUiState().view, "device");
  assert.equal(mainSource.includes("createTauriMediaBackend"), false);
  assert.equal(mainSource.includes("mediaBackend:"), false);
  assert.equal(html.includes("mediaNavItem"), false);
  assert.equal(html.includes("介质导入"), false);
  assert.equal(domViewSource.includes("createMediaScreen"), false);
});

function session(id: string): SessionView {
  return {
    id,
    revision: "revision-1",
    dateLabel: "2026-08-03T00:00:00Z",
    durationSeconds: 1,
    totalBytes: 1,
    videoBytes: 1,
    imuSamples: 1,
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

test("session snapshots are absent until the device really reported them", () => {
  const state = createAppStore().getState();
  for (const deviceId of ADVERSARIAL_IDS) {
    assert.equal(state.sessions.has(deviceId), false, `${deviceId} must not be inherited`);
    assert.equal(state.sessions.get(deviceId), undefined, `${deviceId} must not resolve to a prototype value`);
  }
});

test("a device named after a prototype member keeps its own session snapshot", () => {
  const store = createAppStore();
  for (const deviceId of ADVERSARIAL_IDS) {
    store.commit({ type: "sessions/loaded", revision: 1, deviceId, sessions: [session(`${deviceId}-session`)] });
  }
  const state = store.getState();
  for (const deviceId of ADVERSARIAL_IDS) {
    assert.deepEqual(
      state.sessions.get(deviceId)?.value?.map((s) => s.id),
      [`${deviceId}-session`],
    );
  }
  assert.equal(state.sessions.size, ADVERSARIAL_IDS.length);
});

test("selection membership is exact for adversarial ids", () => {
  const ui = createUiState();
  for (const id of ADVERSARIAL_IDS) {
    assert.equal(ui.deviceSelection.has(id), false, `${id} must not look selected`);
  }
  ui.deviceSelection.add("__proto__");
  assert.equal(ui.deviceSelection.has("__proto__"), true);
  assert.equal(ui.deviceSelection.has("toString"), false);
});

test("expanded-row state is not shared by adversarial ids", () => {
  const ui = createUiState();
  for (const id of ADVERSARIAL_IDS) {
    assert.equal(ui.openRows.has(deviceRowKey("YLX-A", id)), false);
    assert.equal(ui.openRows.has(libraryRowKey(id)), false);
  }
  ui.openRows.add(deviceRowKey("YLX-A", "constructor"));
  assert.equal(ui.openRows.has(deviceRowKey("YLX-A", "constructor")), true);
  assert.equal(ui.openRows.has(deviceRowKey("YLX-A", "toString")), false);
});

test("the same session id under two devices is two independent rows", () => {
  assert.equal(deviceRowKey("YLX-A", "session-1") === deviceRowKey("YLX-B", "session-1"), false);

  const ui = createUiState();
  ui.openRows.add(deviceRowKey("YLX-A", "session-1"));
  assert.equal(ui.openRows.has(deviceRowKey("YLX-B", "session-1")), false);
});

test("row keys cannot be forged by ids containing the key separators", () => {
  // Device `a|b` + session `c` and device `a` + session `b|c` must stay apart.
  assert.equal(deviceRowKey("a|b", "c") === deviceRowKey("a", "b|c"), false);
  assert.equal(deviceRowKey("a:b", "c") === deviceRowKey("a", "b:c"), false);
  // A library key can never be mistaken for a device row and vice versa.
  assert.equal(libraryRowKey("YLX-A|session-1") === deviceRowKey("YLX-A", "session-1"), false);
});

test("a selection is intersected with the entities that still exist", () => {
  const selection = new Set(["session-1", "session-2", "gone"]);

  const selected = retainExistingSelection(selection, ["session-2", "session-1"]);

  assert.deepEqual(selected, ["session-2", "session-1"], "survivors follow the current listing order");
  assert.equal(selection.has("gone"), false, "a removed entity must be dropped from the selection");
  assert.equal(selection.size, 2);
});

test("a selection of adversarial ids never survives on a prototype lookup", () => {
  const selection = new Set(ADVERSARIAL_IDS);

  const selected = retainExistingSelection(selection, ["session-1"]);

  assert.deepEqual(selected, []);
  assert.equal(selection.size, 0);
});

test("an existing entity keeps its selection across the intersection", () => {
  const selection = new Set(["__proto__"]);

  assert.deepEqual(retainExistingSelection(selection, ["__proto__", "session-1"]), ["__proto__"]);
  assert.equal(selection.has("__proto__"), true);
});

test("resetting the device view clears the device selection in place", () => {
  const ui = createUiState();
  ui.deviceSelection.add("session-1");
  const selectionBefore = ui.deviceSelection;
  ui.confirmations.set("device:bulkRemove:YLX-A", { phase: "confirming", operationId: OP_1, expiresAt: 1 });
  ui.confirmations.set("library:bulkRemove", { phase: "confirming", operationId: OP_1, expiresAt: 1 });

  resetDeviceViewState(ui);

  assert.equal(ui.deviceSelection, selectionBefore, "callers may hold the set; it must be cleared, not replaced");
  assert.equal(ui.deviceSelection.size, 0);
  assert.equal(confirmPhaseOf(ui, "device:bulkRemove:YLX-A").phase, "idle");
  assert.equal(
    confirmPhaseOf(ui, "library:bulkRemove").phase,
    "confirming",
    "leaving the device view must not disarm a library confirmation",
  );
});

test("the reducer's selection actions keep prototype-safe membership", () => {
  const store = createAppStore();
  for (const key of ADVERSARIAL_IDS) {
    store.commit({ type: "ui/select", scope: "device", key, selected: true });
  }
  const selection = store.getState().ui.deviceSelection;
  assert.equal(selection.size, ADVERSARIAL_IDS.length);
  assert.equal(selection.has("session-1"), false);

  store.commit({ type: "ui/retainSelection", scope: "device", existingKeys: ["__proto__"] });
  assert.deepEqual([...store.getState().ui.deviceSelection], ["__proto__"]);
});
