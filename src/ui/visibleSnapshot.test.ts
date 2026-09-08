import { test } from "node:test";
import assert from "node:assert/strict";

import { devicePaneSnapshotsEqual, visibleSnapshotsEqual } from "./visibleSnapshot";

test("equal cloned event snapshots are ignored", () => {
  const current = [{ id: "YLX-1", state: "connected", nested: { progress: 10 } }];
  const incoming = [{ id: "YLX-1", state: "connected", nested: { progress: 10 } }];
  assert.equal(visibleSnapshotsEqual(current, incoming), true);
});

test("a visible event change is accepted", () => {
  const current = [{ id: "YLX-1", state: "connected" }];
  const incoming = [{ id: "YLX-1", state: "error" }];
  assert.equal(visibleSnapshotsEqual(current, incoming), false);
});

test("object property order and absent optional fields do not trigger a repaint", () => {
  assert.equal(
    visibleSnapshotsEqual({ id: "job-1", progress: 10, error: undefined }, { progress: 10, id: "job-1" }),
    true,
  );
});

test("array ordering, nested changes and explicit null remain visible", () => {
  for (const [current, incoming] of [
    [
      [{ id: "a" }, { id: "b" }],
      [{ id: "b" }, { id: "a" }],
    ],
    [{ files: [{ bytes: 1 }] }, { files: [{ bytes: 2 }] }],
    [{ error: null }, {}],
    [[1], { "0": 1 }],
    [null, {}],
    [1, "1"],
    [{ a: 1 }, { b: 1 }],
  ]) {
    assert.equal(visibleSnapshotsEqual(current, incoming), false);
    assert.equal(visibleSnapshotsEqual(incoming, current), false);
  }
});

test("prototype-like keys are compared as snapshot data", () => {
  const current = JSON.parse('{"__proto__":{"state":"queued"},"constructor":"a"}');
  const incoming = JSON.parse('{"constructor":"a","__proto__":{"state":"queued"}}');
  assert.equal(visibleSnapshotsEqual(current, incoming), true);
  assert.equal(visibleSnapshotsEqual(current, { constructor: "a" }), false);
});

test("a changed prefix short-circuits the remaining snapshot", () => {
  let inspected = false;
  const tail = {
    get state() {
      inspected = true;
      return "queued";
    },
  };
  assert.equal(visibleSnapshotsEqual([{ state: "queued" }, tail], [{ state: "running" }, { state: "queued" }]), false);
  assert.equal(inspected, false);
});

test("heartbeat timestamps do not invalidate the device main pane", () => {
  const current = {
    id: "ylx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    displayId: "YLX-01234567",
    ip: "192.168.1.10",
    state: "connected" as const,
    lastSeen: "10:00:00",
  };
  const incoming = { ...current, lastSeen: "10:00:05" };
  assert.equal(devicePaneSnapshotsEqual(current, incoming), true);
  assert.equal(devicePaneSnapshotsEqual(current, { ...incoming, state: "offline" }), false);
  assert.equal(devicePaneSnapshotsEqual(current, { ...incoming, displayId: "YLX-76543210" }), false);
});
