// One place owns everything a user-triggered backend call needs: busy state,
// de-duplication of identical in-flight intents, the operation token, error
// catching, the toast, and the `finally` cleanup.
//
// The token is what makes a late response safe. Every intent belongs to a
// scope; starting a new intent in a scope supersedes the older ones, and an
// operation may only commit while its token is still the newest for its scope.
// A reply that lost that race is reported as `superseded` and writes nothing.

import { describeBackendError } from "./backend";

export type ToastTone = "success" | "danger";
export type Toaster = (message: string, tone: ToastTone) => void;

export interface OperationToken {
  readonly key: string;
  readonly scope: string;
  /** True only while this is still the newest intent for its scope. */
  isCurrent(): boolean;
}

export interface OperationSpec<T> {
  /** Identical in-flight intents in the same effective scope share one call. */
  key: string;
  /** Newer intents here supersede older ones. Defaults to `key`. */
  scope?: string;
  run: () => Promise<T>;
  /** Runs only while the token is still current — the guard against a late
   * response overwriting a newer intent. */
  commit?: (value: T, token: OperationToken) => void;
  /** Toast on success; return null for silence. */
  success?: (value: T) => string | null;
  /** Toast on failure; return null for silence. Defaults to the error text. */
  failure?: (error: unknown, token: OperationToken) => string | null;
}

export type OperationResult<T> =
  | { readonly status: "completed"; readonly value: T }
  | { readonly status: "superseded"; readonly value: T }
  | { readonly status: "failed"; readonly error: unknown };

export interface OperationRunner {
  run<T>(spec: OperationSpec<T>): Promise<OperationResult<T>>;
  isBusy(key: string): boolean;
  busyKeys(): string[];
}

export interface OperationRunnerOptions {
  toast: Toaster;
  /** Notified whenever the busy set changes, so views can repaint controls. */
  onBusyChange?: (keys: string[]) => void;
}

export function createOperationRunner(options: OperationRunnerOptions): OperationRunner {
  const { toast, onBusyChange } = options;
  interface InFlightSlot {
    readonly token: OperationToken;
    readonly promise: Promise<OperationResult<unknown>>;
  }

  /** scope -> key -> the newest physical request for that exact intent. */
  const inFlight = new Map<string, Map<string, InFlightSlot>>();
  /** Public busy state remains key-based even when multiple scopes use it. */
  const busyCountByKey = new Map<string, number>();
  /** scope -> sequence of the newest intent started in it. */
  const newestByScope = new Map<string, number>();

  function announceBusy(): void {
    onBusyChange?.([...busyCountByKey.keys()]);
  }

  function startBusy(key: string): void {
    const count = busyCountByKey.get(key) ?? 0;
    busyCountByKey.set(key, count + 1);
    if (count === 0) announceBusy();
  }

  function finishBusy(key: string): void {
    const count = busyCountByKey.get(key);
    if (count === undefined) return;
    if (count > 1) {
      busyCountByKey.set(key, count - 1);
      return;
    }
    busyCountByKey.delete(key);
    announceBusy();
  }

  function run<T>(spec: OperationSpec<T>): Promise<OperationResult<T>> {
    const scope = spec.scope ?? spec.key;
    const scoped = inFlight.get(scope);
    const existing = scoped?.get(spec.key);
    // A request superseded by another key in this scope is no longer the same
    // intent, even if its key is reissued while the old promise is still alive.
    if (existing !== undefined && existing.token.isCurrent()) {
      return existing.promise as Promise<OperationResult<T>>;
    }

    const sequence = (newestByScope.get(scope) ?? 0) + 1;
    newestByScope.set(scope, sequence);
    const token: OperationToken = {
      key: spec.key,
      scope,
      isCurrent: () => newestByScope.get(scope) === sequence,
    };

    let resolveStarted = (_result: OperationResult<T>): void => {};
    let rejectStarted = (_error: unknown): void => {};
    const started = new Promise<OperationResult<T>>((resolve, reject) => {
      resolveStarted = resolve;
      rejectStarted = reject;
    });
    const slot: InFlightSlot = {
      token,
      promise: started as Promise<OperationResult<unknown>>,
    };

    const slots = scoped ?? new Map<string, InFlightSlot>();
    slots.set(spec.key, slot);
    if (scoped === undefined) inFlight.set(scope, slots);
    startBusy(spec.key);

    const execute = async (): Promise<OperationResult<T>> => {
      try {
        const value = await spec.run();
        if (!token.isCurrent()) return { status: "superseded", value } as const;
        spec.commit?.(value, token);
        const message = spec.success?.(value);
        if (message !== null && message !== undefined) toast(message, "success");
        return { status: "completed", value } as const;
      } catch (error) {
        // A superseded request may reject too. Its failure must not degrade
        // the resource or toast over the newer intent; callers that need to
        // commit failure state receive the same token used for success.
        const message = token.isCurrent()
          ? spec.failure
            ? spec.failure(error, token)
            : describeBackendError(error)
          : null;
        if (message !== null) toast(message, "danger");
        return { status: "failed", error } as const;
      } finally {
        const currentScope = inFlight.get(scope);
        if (currentScope?.get(spec.key) === slot) {
          currentScope.delete(spec.key);
          if (currentScope.size === 0) inFlight.delete(scope);
        }
        finishBusy(spec.key);
      }
    };

    // Register before invoking `run`: even a synchronous throw must clean up
    // this exact slot without racing a newer same-key reissue.
    void execute().then(resolveStarted, rejectStarted);
    return started;
  }

  return {
    run,
    isBusy: (key) => busyCountByKey.has(key),
    busyKeys: () => [...busyCountByKey.keys()],
  };
}
