import { asMediaOperationId, type MediaOperationId } from "./ids";

export type MediaConfirmState =
  | { readonly phase: "idle" }
  | { readonly phase: "confirming"; readonly operationId: MediaOperationId; readonly expiresAt: number }
  | { readonly phase: "running"; readonly operationId: MediaOperationId; readonly expiresAt: number };

export type MediaConfirmDecision =
  | { readonly decision: "armed"; readonly operationId: MediaOperationId; readonly expiresAt: number }
  | { readonly decision: "confirmed"; readonly operationId: MediaOperationId; readonly expiresAt: number }
  | { readonly decision: "busy"; readonly operationId: MediaOperationId; readonly expiresAt: number };

export interface MediaConfirmClock {
  now(): number;
  setTimeout(callback: () => void, delayMs: number): () => void;
}

export interface MediaConfirmRegistry {
  request(target: string, ttlMs: number): MediaConfirmDecision;
  state(target: string): MediaConfirmState;
  settle(target: string, operationId: MediaOperationId): void;
  clear(prefix: string): void;
  dispose(): void;
}

export interface MediaConfirmRegistryOptions {
  readonly clock: MediaConfirmClock;
  readonly onChange?: (target: string, state: MediaConfirmState) => void;
}

export function decideMediaConfirmation(
  state: MediaConfirmState,
  now: number,
  ttlMs: number,
  mint: () => MediaOperationId,
): MediaConfirmDecision {
  if (state.phase === "running") {
    return { decision: "busy", operationId: state.operationId, expiresAt: state.expiresAt };
  }
  if (state.phase === "confirming" && now < state.expiresAt) {
    return { decision: "confirmed", operationId: state.operationId, expiresAt: state.expiresAt };
  }
  const operationId = mint();
  return { decision: "armed", operationId, expiresAt: now + ttlMs };
}

export function createMediaConfirmRegistry(options: MediaConfirmRegistryOptions): MediaConfirmRegistry {
  const states = new Map<string, Exclude<MediaConfirmState, { readonly phase: "idle" }>>();
  const cancels = new Set<() => void>();
  let sequence = 0;
  let disposed = false;

  function state(target: string): MediaConfirmState {
    return states.get(target) ?? { phase: "idle" };
  }

  function publish(target: string, next: MediaConfirmState): void {
    if (next.phase === "idle") states.delete(target);
    else states.set(target, next);
    options.onChange?.(target, next);
  }

  function mint(): MediaOperationId {
    sequence += 1;
    return asMediaOperationId(`media-confirm-${sequence}`);
  }

  function request(target: string, ttlMs: number): MediaConfirmDecision {
    const decision = decideMediaConfirmation(state(target), options.clock.now(), ttlMs, mint);
    if (decision.decision === "busy") return decision;
    if (decision.decision === "confirmed") {
      publish(target, {
        phase: "running",
        operationId: decision.operationId,
        expiresAt: decision.expiresAt,
      });
      return decision;
    }
    publish(target, {
      phase: "confirming",
      operationId: decision.operationId,
      expiresAt: decision.expiresAt,
    });
    if (!disposed) {
      let cancel = (): void => {};
      cancel = options.clock.setTimeout(() => {
        cancels.delete(cancel);
        const current = state(target);
        if (current.phase === "confirming" && current.operationId === decision.operationId) {
          publish(target, { phase: "idle" });
        }
      }, ttlMs);
      cancels.add(cancel);
    }
    return decision;
  }

  return {
    request,
    state,
    settle(target, operationId) {
      const current = state(target);
      if (current.phase === "running" && current.operationId === operationId) publish(target, { phase: "idle" });
    },
    clear(prefix) {
      for (const [target, current] of [...states]) {
        if (target.startsWith(prefix) && current.phase === "confirming") publish(target, { phase: "idle" });
      }
    },
    dispose() {
      disposed = true;
      for (const cancel of [...cancels]) cancel();
      cancels.clear();
    },
  };
}
