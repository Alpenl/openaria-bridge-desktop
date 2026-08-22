// "Click again to confirm", modelled as a state machine instead of a boolean.
//
// The old shape was one `boolean` per destructive control plus a bare
// `setTimeout` that flipped it back. Two bugs are unrepresentable-by-accident
// there and impossible to fix locally:
//
//   * the timer armed by click #1 also fires after click #2 has already armed a
//     *new* confirmation, disarming an operation it knows nothing about;
//   * nothing distinguishes "waiting for the second click" from "the command is
//     already running", so a second click during execution re-armed the
//     confirmation and could dispatch the destructive command twice.
//
// So a confirmation is a discriminated union carrying an operation id and an
// expiry. Every transition names the operation it means, and a transition whose
// id does not match the operation actually in that state is dropped. An old
// timer cannot clear a newer operation, and `running` has no edge back to
// `confirming`.

import type { Clock } from "./clock";
import type { AppStore } from "./reducer";
import { confirmPhaseOf } from "../store";

declare const operationBrand: unique symbol;

/** Names one attempt at a destructive operation, from arming to settlement. */
export type OperationId = string & { readonly [operationBrand]: "OperationId" };

export type ConfirmPhase =
  | { readonly phase: "idle" }
  | { readonly phase: "confirming"; readonly operationId: OperationId; readonly expiresAt: number }
  | { readonly phase: "running"; readonly operationId: OperationId };

export const IDLE_PHASE: ConfirmPhase = { phase: "idle" };

/** What a click on a destructive control means, given what is already going on. */
export type ConfirmDecision =
  /** First click: the control now shows its confirm label until `expiresAt`. */
  | { readonly decision: "armed"; readonly operationId: OperationId; readonly expiresAt: number }
  /** Second click inside the window: run it, under the id that was armed. */
  | { readonly decision: "confirmed"; readonly operationId: OperationId }
  /** The operation is already executing; the click is ignored. */
  | { readonly decision: "busy"; readonly operationId: OperationId };

/** The pure rule. `mint` supplies the id for a fresh arming; an expired
 * confirmation re-arms under a *new* id, so the timer belonging to the old one
 * can no longer match anything. */
export function decideConfirm(
  phase: ConfirmPhase,
  now: number,
  ttlMs: number,
  mint: () => OperationId,
): ConfirmDecision {
  if (phase.phase === "running") return { decision: "busy", operationId: phase.operationId };
  if (phase.phase === "confirming" && now < phase.expiresAt) {
    return { decision: "confirmed", operationId: phase.operationId };
  }
  return { decision: "armed", operationId: mint(), expiresAt: now + ttlMs };
}

export interface ConfirmController {
  /** Applies one click to `target` and commits the resulting transition. */
  request(target: string, ttlMs?: number): ConfirmDecision;
  /** Ends a running operation — only if `operationId` is the one running. */
  settle(target: string, operationId: OperationId): void;
  phase(target: string): ConfirmPhase;
  isConfirming(target: string): boolean;
  isRunning(target: string): boolean;
  /** Drops every confirmation whose target starts with `prefix` (navigation,
   * disconnect, view reset). Running operations are left alone: they are
   * already in flight and will settle themselves. */
  clear(prefix: string): void;
  /** Cancels every pending expiry timer. Idempotent. */
  dispose(): void;
}

export interface ConfirmControllerOptions {
  store: AppStore;
  clock: Clock;
  /** How long an armed confirmation stays armed. */
  ttlMs: number;
  /** Called when an expiry actually disarmed something, so the view repaints. */
  onExpire?: (target: string) => void;
}

export function createConfirmController(options: ConfirmControllerOptions): ConfirmController {
  const { store, clock, ttlMs, onExpire } = options;
  let sequence = 0;
  let disposed = false;
  const cancels = new Set<() => void>();

  function mint(): OperationId {
    sequence += 1;
    return `op-${sequence}` as OperationId;
  }

  function phase(target: string): ConfirmPhase {
    return confirmPhaseOf(store.getState().ui, target);
  }

  function request(target: string, requestedTtlMs: number = ttlMs): ConfirmDecision {
    const decision = decideConfirm(phase(target), clock.now(), requestedTtlMs, mint);
    if (decision.decision === "busy") return decision;
    if (decision.decision === "confirmed") {
      store.commit({ type: "ui/confirmRun", target, operationId: decision.operationId });
      return decision;
    }

    store.commit({
      type: "ui/confirmArm",
      target,
      operationId: decision.operationId,
      expiresAt: decision.expiresAt,
    });
    if (disposed) return decision;
    const cancel = clock.setTimeout(() => {
      cancels.delete(cancel);
      // The reducer drops this if `target` has since moved on — a newer
      // operation, or one that is already running, is never disarmed here.
      if (store.commit({ type: "ui/confirmExpire", target, operationId: decision.operationId }).changed) {
        onExpire?.(target);
      }
    }, requestedTtlMs);
    cancels.add(cancel);
    return decision;
  }

  return {
    request,
    settle(target, operationId) {
      store.commit({ type: "ui/confirmSettle", target, operationId });
    },
    phase,
    isConfirming: (target) => phase(target).phase === "confirming",
    isRunning: (target) => phase(target).phase === "running",
    clear(prefix) {
      store.commit({ type: "ui/confirmClear", prefix });
    },
    dispose() {
      disposed = true;
      for (const cancel of [...cancels]) cancel();
      cancels.clear();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* target names                                                            */
/* ---------------------------------------------------------------------- */

/** Confirmation targets are namespaced so `clear("device:")` can drop every
 * device-scoped confirmation when the user leaves the device view. */
export const confirmTargets = {
  cleanupBackedUp: (deviceId: string) => `device:cleanupBackedUp:${deviceId}`,
  deviceBulkRemove: (deviceId: string) => `device:bulkRemove:${deviceId}`,
  deviceRowRemove: (rowKey: string) => `device:row:${rowKey}`,
  libraryBulkRemove: () => `library:bulkRemove`,
  libraryRowRemove: (rowKey: string) => `library:row:${rowKey}`,
} as const;

export const DEVICE_CONFIRM_PREFIX = "device:";
export const LIBRARY_CONFIRM_PREFIX = "library:";
