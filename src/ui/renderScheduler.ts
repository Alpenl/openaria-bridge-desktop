import type { Clock } from "../runtime/clock";

export type FrameScheduler = (run: () => void) => () => void;

/** Coalesces high-frequency progress updates into one browser frame. In a
 * headless test (where RAF does not exist) the injected clock makes the same
 * boundary deterministic instead of introducing a real-time sleep. */
export function scheduleAnimationFrame(run: () => void, clock: Clock): () => void {
  let cancelled = false;
  let cancelFallback = (): void => {};
  if (typeof globalThis.requestAnimationFrame === "function") {
    const frame = globalThis.requestAnimationFrame(() => {
      if (cancelled) return;
      cancelled = true;
      cancelFallback();
      run();
    });
    cancelFallback = clock.setTimeout(() => {
      if (cancelled) return;
      cancelled = true;
      globalThis.cancelAnimationFrame?.(frame);
      run();
    }, 100);
    return () => {
      cancelled = true;
      globalThis.cancelAnimationFrame?.(frame);
      cancelFallback();
    };
  }

  const cancel = clock.setTimeout(() => {
    if (cancelled) return;
    cancelled = true;
    run();
  }, 0);
  return () => {
    cancelled = true;
    cancel();
  };
}

/**
 * Resolves only after the browser has had an opportunity to commit the DOM
 * changes made in the current task. Native IPC may execute blocking platform
 * work, so starting it in the same task can hide an otherwise immediate view
 * transition until that work finishes.
 */
export function afterNextPaint(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof globalThis.requestAnimationFrame !== "function") {
      globalThis.setTimeout(resolve, 0);
      return;
    }

    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(fallback);
      resolve();
    };
    // requestAnimationFrame may be suspended while a window is hidden. Do
    // not let a background/restore transition wait forever for a frame.
    const fallback = globalThis.setTimeout(finish, 50);
    globalThis.requestAnimationFrame(() => globalThis.setTimeout(finish, 0));
  });
}
