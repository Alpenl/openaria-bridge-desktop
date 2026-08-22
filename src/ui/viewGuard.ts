// Async work started from a view — a per-device detail request, a bulk
// operation, a "click again to confirm" timer — can land long after the user
// navigated to another view, switched device, or disconnected. Committing it
// then paints stale data over the screen the user is actually looking at, or
// acts on a device that is no longer the active one.
//
// A capture records the scope the work started in (view + device) together
// with a generation counter that navigation bumps. The result may only be
// committed while all three still match.

export interface ViewScope {
  view: string;
  deviceId: string | null;
}

export interface ViewCapture {
  /** True only while the captured view, device and generation are all current. */
  isCurrent(): boolean;
  /** Runs `effect` only if the capture is still current; reports whether it ran. */
  commit(effect: () => void): boolean;
}

export interface ViewGuard {
  /** Snapshots the current scope; call when the async work starts. */
  capture(): ViewCapture;
  /** Invalidates every outstanding capture (navigation, disconnect, reset). */
  invalidate(): void;
}

export function createViewGuard(readScope: () => ViewScope): ViewGuard {
  let generation = 0;

  return {
    capture(): ViewCapture {
      const captured = readScope();
      const capturedGeneration = generation;
      const isCurrent = (): boolean => {
        if (capturedGeneration !== generation) return false;
        const now = readScope();
        return now.view === captured.view && now.deviceId === captured.deviceId;
      };
      const commit = (effect: () => void): boolean => {
        if (!isCurrent()) return false;
        effect();
        return true;
      };
      return { isCurrent, commit };
    },
    invalidate(): void {
      generation += 1;
    },
  };
}
