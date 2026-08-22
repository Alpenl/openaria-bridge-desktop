// Time as a dependency.
//
// Confirm timers ("click again to confirm") and the library reconciliation
// debounce are state transitions like any other, so they must be testable
// without waiting for real time. Everything that needs a delay takes a `Clock`;
// production passes `systemClock`, tests pass `createFakeClock()` and advance
// it themselves.

export interface Clock {
  now(): number;
  /** Schedules `run` and returns a cancel function. */
  setTimeout(run: () => void, delayMs: number): () => void;
}

export const systemClock: Clock = {
  now: () => Date.now(),
  setTimeout: (run, delayMs) => {
    const handle = globalThis.setTimeout(run, delayMs);
    return () => globalThis.clearTimeout(handle);
  },
};

export interface FakeClock extends Clock {
  /** Runs everything due within `ms`, in due order. */
  advance(ms: number): void;
  /** Timers still scheduled. */
  pending(): number;
}

export function createFakeClock(startMs = 0): FakeClock {
  interface Scheduled {
    at: number;
    sequence: number;
    run: () => void;
  }

  let current = startMs;
  let sequence = 0;
  let scheduled: Scheduled[] = [];

  return {
    now: () => current,
    setTimeout(run, delayMs) {
      const entry: Scheduled = { at: current + Math.max(0, delayMs), sequence: ++sequence, run };
      scheduled.push(entry);
      return () => {
        scheduled = scheduled.filter((candidate) => candidate !== entry);
      };
    },
    advance(ms: number): void {
      const target = current + ms;
      for (;;) {
        const due = scheduled
          .filter((entry) => entry.at <= target)
          .sort((left, right) => left.at - right.at || left.sequence - right.sequence);
        const next = due[0];
        if (next === undefined) break;
        scheduled = scheduled.filter((entry) => entry !== next);
        current = Math.max(current, next.at);
        next.run();
      }
      current = target;
    },
    pending: () => scheduled.length,
  };
}
