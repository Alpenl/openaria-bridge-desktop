// All-or-nothing event registration, shared by every backend adapter.
//
// Transport-free on purpose: the Tauri adapter and the in-memory backend must
// have exactly the same partial-failure and dispose semantics, or a workflow
// test proves nothing about the real thing.

/** What a registered listener hands back so it can be torn down. */
export type Unsubscribe = () => void;

/** A pending event registration: called once, resolves to its unlisten fn. */
export type EventRegistration = () => Promise<Unsubscribe>;

function unsubscribeAll(unlisteners: Unsubscribe[]): void {
  while (unlisteners.length > 0) {
    const unlisten = unlisteners.pop();
    try {
      unlisten?.();
    } catch {
      // One failing unlisten must not strand the remaining listeners.
    }
  }
}

/**
 * Registers every listener or none of them. Registrations run concurrently, as
 * startup latency demands; if any of them rejects, the ones that did register
 * are unsubscribed before the failure propagates, so a half-registered app can
 * never keep listeners alive behind a failed boot.
 *
 * The returned disposer is idempotent — normal shutdown, a hot-reload dispose
 * hook and a test teardown may all call it, and only the first call unlistens.
 */
export async function subscribeAll(registrations: EventRegistration[]): Promise<() => void> {
  const settled = await Promise.allSettled(registrations.map((register) => register()));
  const registered = settled.flatMap((result) => (result.status === "fulfilled" ? [result.value] : []));
  const failure = settled.find((result): result is PromiseRejectedResult => result.status === "rejected");
  if (failure !== undefined) {
    unsubscribeAll(registered);
    throw failure.reason;
  }

  let disposed = false;
  return () => {
    if (disposed) return;
    disposed = true;
    unsubscribeAll(registered);
  };
}
