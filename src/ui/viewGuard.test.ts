import { test } from "node:test";
import assert from "node:assert/strict";

import { createViewGuard, type ViewScope } from "./viewGuard";

/** Stand-in for the parts of `ui` the guard reads, plus a painted-DOM log. */
function createHarness() {
  const scope: ViewScope = { view: "device", deviceId: "YLX-A" };
  const painted: string[] = [];
  const guard = createViewGuard(() => ({ view: scope.view, deviceId: scope.deviceId }));
  return {
    guard,
    painted,
    openDevice(deviceId: string) {
      guard.invalidate();
      scope.view = "device";
      scope.deviceId = deviceId;
    },
    openLibrary() {
      guard.invalidate();
      scope.view = "library";
      scope.deviceId = null;
    },
  };
}

test("a device detail response that lands after switching devices never paints", async () => {
  const harness = createHarness();
  const capture = harness.guard.capture();

  const inFlight = new Promise<string[]>((resolve) => setTimeout(() => resolve(["session-1"]), 0));
  harness.openDevice("YLX-B");
  const sessions = await inFlight;

  assert.equal(
    capture.commit(() => harness.painted.push(`sessions:${sessions.join(",")}`)),
    false,
  );
  assert.deepEqual(harness.painted, []);
});

test("a device detail response that lands while the device is still open paints once", async () => {
  const harness = createHarness();
  const capture = harness.guard.capture();

  const sessions = await new Promise<string[]>((resolve) => setTimeout(() => resolve(["session-1"]), 0));

  assert.equal(
    capture.commit(() => harness.painted.push(`sessions:${sessions.join(",")}`)),
    true,
  );
  assert.deepEqual(harness.painted, ["sessions:session-1"]);
});

test("a bulk operation result that lands after leaving for the library never paints", async () => {
  const harness = createHarness();
  const capture = harness.guard.capture();

  const bulk = new Promise<{ succeeded: string[] }>((resolve) => setTimeout(() => resolve({ succeeded: ["a"] }), 0));
  harness.openLibrary();
  const result = await bulk;

  assert.equal(result.succeeded.length, 1); // the backend work still happened
  assert.equal(
    capture.commit(() => harness.painted.push("bulk-bar")),
    false,
  );
  assert.deepEqual(harness.painted, []);
});

test("a confirmation timer that fires after navigation expires state without painting", async () => {
  const harness = createHarness();
  const capture = harness.guard.capture();
  let confirming = true;

  const timer = new Promise<void>((resolve) =>
    setTimeout(() => {
      confirming = false;
      capture.commit(() => harness.painted.push("topbar"));
      resolve();
    }, 5),
  );
  harness.openLibrary();
  await timer;

  assert.equal(confirming, false, "the pending confirmation must always expire");
  assert.deepEqual(harness.painted, []);
});

test("returning to the same device does not revive a capture from the previous visit", () => {
  const harness = createHarness();
  const capture = harness.guard.capture();

  harness.openLibrary();
  harness.openDevice("YLX-A");

  assert.equal(capture.isCurrent(), false);
  assert.equal(
    capture.commit(() => harness.painted.push("stale")),
    false,
  );
});

test("captures taken after navigation are current again", () => {
  const harness = createHarness();
  harness.openDevice("YLX-B");
  const capture = harness.guard.capture();

  assert.equal(capture.isCurrent(), true);
  assert.equal(
    capture.commit(() => harness.painted.push("fresh")),
    true,
  );
  assert.deepEqual(harness.painted, ["fresh"]);
});
