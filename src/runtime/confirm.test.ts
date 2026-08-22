// The confirm/execute state machine: the two races the old boolean could not
// express.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createFakeClock } from "./clock";
import { createConfirmController, decideConfirm, IDLE_PHASE, type OperationId } from "./confirm";
import { createAppStore } from "./reducer";

const TARGET = "device:bulkRemove:YLX-A";

function controller(ttlMs = 4000) {
  const store = createAppStore();
  const clock = createFakeClock();
  const repainted: string[] = [];
  const confirm = createConfirmController({ store, clock, ttlMs, onExpire: (target) => repainted.push(target) });
  return { store, clock, confirm, repainted };
}

test("the first click arms and the second one inside the window confirms", () => {
  const { confirm, clock } = controller();

  const first = confirm.request(TARGET);
  assert.equal(first.decision, "armed");
  assert.equal(confirm.phase(TARGET).phase, "confirming");

  clock.advance(3999);
  const second = confirm.request(TARGET);
  assert.equal(second.decision, "confirmed");
  assert.equal(confirm.phase(TARGET).phase, "running");
  assert.equal(
    second.decision === "confirmed" && first.decision === "armed" && second.operationId === first.operationId,
    true,
    "the confirmed operation is the one that was armed",
  );
});

// The bug this whole module exists for: click #1's timer must not disarm the
// confirmation that click #2 (after an expiry) armed.
test("an expired operation's timer cannot clear the newer operation that replaced it", () => {
  const { confirm, clock, repainted } = controller(4000);

  const first = confirm.request(TARGET);
  clock.advance(4000); // the first confirmation expires on its own
  assert.equal(confirm.phase(TARGET).phase, "idle");
  assert.deepEqual(repainted, [TARGET]);

  const second = confirm.request(TARGET);
  assert.equal(second.decision, "armed");
  assert.ok(
    second.decision === "armed" && first.decision === "armed" && second.operationId,
    "the expired operation is re-armed under a new id",
  );
  assert.ok(first.decision === "armed" && second.decision === "armed" && first.operationId !== second.operationId);

  // The first timer has already fired; advancing past the *old* deadline while
  // the new one is still live must change nothing.
  clock.advance(1);
  assert.equal(confirm.phase(TARGET).phase, "confirming", "the newer confirmation survives");
  const livePhase = confirm.phase(TARGET);
  if (livePhase.phase !== "confirming") throw new Error("the newer confirmation unexpectedly expired");
  assert.equal(second.decision, "armed");
  assert.equal(livePhase.operationId, second.operationId);
});

test("a stale expiry action naming an old operation is dropped by the reducer", () => {
  const store = createAppStore();
  const stale = "op-stale" as OperationId;
  const live = "op-live" as OperationId;

  store.commit({ type: "ui/confirmArm", target: TARGET, operationId: live, expiresAt: 100 });
  const result = store.commit({ type: "ui/confirmExpire", target: TARGET, operationId: stale });

  assert.equal(result.changed, false, "an expiry for another operation is not a state change");
  assert.equal(store.getState().ui.confirmations.get(TARGET)?.phase, "confirming");
});

// While the destructive command is executing, a further click must not re-arm
// a confirmation — that is how the same command got dispatched twice.
test("an executing operation cannot be pushed back into confirming", () => {
  const { confirm, clock, store } = controller();

  confirm.request(TARGET);
  const confirmed = confirm.request(TARGET);
  assert.equal(confirmed.decision, "confirmed");
  assert.equal(confirm.phase(TARGET).phase, "running");

  const third = confirm.request(TARGET);
  assert.equal(third.decision, "busy", "the click is refused, not turned into a new confirmation");
  assert.equal(confirm.phase(TARGET).phase, "running");

  // Even a direct arm action is refused while running.
  store.commit({ type: "ui/confirmArm", target: TARGET, operationId: "op-forced" as OperationId, expiresAt: 1 });
  assert.equal(confirm.phase(TARGET).phase, "running");

  // And no timer left over from the confirming phase may disarm it either.
  clock.advance(60_000);
  assert.equal(confirm.phase(TARGET).phase, "running");
});

test("only the operation that is running may settle it", () => {
  const { confirm } = controller();

  confirm.request(TARGET);
  const confirmed = confirm.request(TARGET);
  assert.equal(confirmed.decision, "confirmed");

  confirm.settle(TARGET, "op-someone-else" as OperationId);
  assert.equal(confirm.phase(TARGET).phase, "running", "a foreign settle is ignored");

  if (confirmed.decision === "confirmed") confirm.settle(TARGET, confirmed.operationId);
  assert.equal(confirm.phase(TARGET).phase, "idle");
});

test("clearing a scope disarms its confirmations but leaves running work alone", () => {
  const { confirm } = controller();

  confirm.request("device:row:a");
  confirm.request("device:cleanupBackedUp:YLX-A");
  confirm.request("device:cleanupBackedUp:YLX-A"); // now running
  confirm.request("library:bulkRemove");

  confirm.clear("device:");

  assert.equal(confirm.phase("device:row:a").phase, "idle");
  assert.equal(confirm.phase("device:cleanupBackedUp:YLX-A").phase, "running", "in-flight work settles itself");
  assert.equal(confirm.phase("library:bulkRemove").phase, "confirming", "another scope is untouched");
});

test("dispose cancels every pending expiry", () => {
  const { confirm, clock } = controller();

  confirm.request(TARGET);
  confirm.dispose();
  clock.advance(60_000);

  assert.equal(clock.pending(), 0);
});

test("the rule itself: expiry re-arms under a new id rather than confirming late", () => {
  let minted = 0;
  const mint = (): OperationId => `op-${++minted}` as OperationId;

  const armed = decideConfirm(IDLE_PHASE, 0, 1000, mint);
  assert.deepEqual(armed, { decision: "armed", operationId: "op-1", expiresAt: 1000 });

  const confirming = { phase: "confirming", operationId: "op-1" as OperationId, expiresAt: 1000 } as const;
  assert.deepEqual(decideConfirm(confirming, 999, 1000, mint), { decision: "confirmed", operationId: "op-1" });
  assert.deepEqual(decideConfirm(confirming, 1000, 1000, mint), {
    decision: "armed",
    operationId: "op-2",
    expiresAt: 2000,
  });
});
