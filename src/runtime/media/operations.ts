import { asMediaOperationId, type MediaOperationId } from "./ids";

export interface MediaOperationToken {
  readonly id: MediaOperationId;
  readonly key: string;
  readonly scope: string;
  isCurrent(): boolean;
}

export interface MediaOperationSpec<T> {
  readonly key: string;
  readonly scope?: string;
  readonly run: () => Promise<T>;
  readonly commit?: (value: T, token: MediaOperationToken) => void;
  readonly failed?: (error: unknown, token: MediaOperationToken) => void;
}

export type MediaOperationResult<T> =
  | { readonly status: "completed"; readonly operationId: MediaOperationId; readonly value: T }
  | {
      readonly status: "superseded";
      readonly operationId: MediaOperationId;
      readonly value?: T;
      readonly error?: unknown;
    }
  | { readonly status: "failed"; readonly operationId: MediaOperationId; readonly error: unknown };

export interface MediaOperationRegistry {
  run<T>(spec: MediaOperationSpec<T>): Promise<MediaOperationResult<T>>;
  isBusy(key: string): boolean;
  busyKeys(): readonly string[];
  /** Makes every current token in the scope stale without cancelling I/O. */
  invalidate(scope: string): void;
}

export interface MediaOperationRegistryOptions {
  readonly onBusyChange?: (busyKeys: readonly string[]) => void;
}

export function createMediaOperationRegistry(options: MediaOperationRegistryOptions = {}): MediaOperationRegistry {
  interface Slot {
    readonly token: MediaOperationToken;
    readonly promise: Promise<MediaOperationResult<unknown>>;
  }

  let operationSequence = 0;
  const scopeSequence = new Map<string, number>();
  const slotsByScope = new Map<string, Map<string, Slot>>();
  const busyCount = new Map<string, number>();

  function announce(): void {
    try {
      options.onBusyChange?.([...busyCount.keys()]);
    } catch {
      // Observer failures cannot change operation ownership or busy cleanup.
    }
  }

  function beginBusy(key: string): void {
    const previous = busyCount.get(key) ?? 0;
    busyCount.set(key, previous + 1);
    if (previous === 0) announce();
  }

  function endBusy(key: string): void {
    const previous = busyCount.get(key);
    if (previous === undefined) return;
    if (previous > 1) busyCount.set(key, previous - 1);
    else {
      busyCount.delete(key);
      announce();
    }
  }

  function invalidate(scope: string): void {
    scopeSequence.set(scope, (scopeSequence.get(scope) ?? 0) + 1);
  }

  function run<T>(spec: MediaOperationSpec<T>): Promise<MediaOperationResult<T>> {
    const scope = spec.scope ?? spec.key;
    const existing = slotsByScope.get(scope)?.get(spec.key);
    if (existing !== undefined && existing.token.isCurrent()) {
      return existing.promise as Promise<MediaOperationResult<T>>;
    }

    const sequence = (scopeSequence.get(scope) ?? 0) + 1;
    scopeSequence.set(scope, sequence);
    operationSequence += 1;
    const token: MediaOperationToken = {
      id: asMediaOperationId(`media-operation-${operationSequence}`),
      key: spec.key,
      scope,
      isCurrent: () => scopeSequence.get(scope) === sequence,
    };

    let settle = (_result: MediaOperationResult<T>): void => {};
    const promise = new Promise<MediaOperationResult<T>>((resolve) => {
      settle = resolve;
    });
    const slot: Slot = { token, promise: promise as Promise<MediaOperationResult<unknown>> };
    const scoped = slotsByScope.get(scope) ?? new Map<string, Slot>();
    scoped.set(spec.key, slot);
    slotsByScope.set(scope, scoped);
    beginBusy(spec.key);

    const execute = async (): Promise<MediaOperationResult<T>> => {
      try {
        const value = await spec.run();
        if (!token.isCurrent()) return { status: "superseded", operationId: token.id, value };
        spec.commit?.(value, token);
        return { status: "completed", operationId: token.id, value };
      } catch (error) {
        if (!token.isCurrent()) return { status: "superseded", operationId: token.id, error };
        try {
          spec.failed?.(error, token);
        } catch {
          // A reporting callback cannot strand or reclassify the operation.
        }
        return { status: "failed", operationId: token.id, error };
      } finally {
        const current = slotsByScope.get(scope);
        if (current?.get(spec.key) === slot) {
          current.delete(spec.key);
          if (current.size === 0) slotsByScope.delete(scope);
        }
        endBusy(spec.key);
      }
    };

    void execute().then(settle);
    return promise;
  }

  return {
    run,
    isBusy: (key) => busyCount.has(key),
    busyKeys: () => [...busyCount.keys()],
    invalidate,
  };
}
