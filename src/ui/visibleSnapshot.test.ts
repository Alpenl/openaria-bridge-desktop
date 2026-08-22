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
