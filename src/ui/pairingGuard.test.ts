import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyPairingEvent } from "./pairingGuard";

test("a result for the attempt on screen is applied", () => {
  assert.equal(
    classifyPairingEvent({ deviceId: "YLX-1", attemptId: "attempt-2" }, { deviceId: "YLX-1", attemptId: "attempt-2" }),
    "apply",
  );
});

test("a late result from a superseded attempt is dropped, not applied", () => {
  // The user reconnected: attempt-1's poll resolved after attempt-2 became
  // the live one. Matching on device id alone would have closed the
  // overlay for the wrong attempt.
  assert.equal(
    classifyPairingEvent({ deviceId: "YLX-1", attemptId: "attempt-2" }, { deviceId: "YLX-1", attemptId: "attempt-1" }),
    "drop",
  );
});

test("an event for another device, or with no overlay open, is dropped", () => {
  assert.equal(
    classifyPairingEvent({ deviceId: "YLX-1", attemptId: "attempt-1" }, { deviceId: "YLX-2", attemptId: "attempt-1" }),
    "drop",
  );
  assert.equal(
    classifyPairingEvent({ deviceId: null, attemptId: null }, { deviceId: "YLX-1", attemptId: "attempt-1" }),
    "drop",
  );
});

test("a result that beats connect_device's own reply is deferred, never guessed at", () => {
  assert.equal(
    classifyPairingEvent({ deviceId: "YLX-1", attemptId: null }, { deviceId: "YLX-1", attemptId: "attempt-1" }),
    "defer",
  );
});
