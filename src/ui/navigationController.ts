import type { SessionView } from "../types";
import { afterNextPaint } from "./renderScheduler";

export type DeviceSessionLoadOutcome = "applied" | "stale" | "failed";

/** `TLoaded` is whatever the backend hands back for a device's sessions — the
 * bare list in tests, a revisioned payload in the app. The controller only
 * cares that it may not be committed once superseded. */
interface DeviceNavigationDependencies<TLoaded> {
  onBegin: (deviceId: string, activate: boolean) => void;
  loadSessions: (deviceId: string) => Promise<TLoaded>;
  isCurrent: (deviceId: string) => boolean;
  onLoaded: (deviceId: string, loaded: TLoaded) => void;
  onFailed: (deviceId: string, error: unknown) => void;
  onInvalidated: () => void;
}

export interface DeviceNavigationController {
  focus: (deviceId: string) => Promise<DeviceSessionLoadOutcome>;
  refresh: (deviceId: string) => Promise<DeviceSessionLoadOutcome>;
  invalidate: () => void;
}

/** Keeps device navigation responsive while only the newest request may commit. */
export function createDeviceNavigationController<TLoaded = SessionView[]>(
  dependencies: DeviceNavigationDependencies<TLoaded>,
): DeviceNavigationController {
  let requestGeneration = 0;
  let invalidationGeneration = 0;
  const inFlightByDevice = new Map<string, { generation: number; request: Promise<TLoaded> }>();

  function loadSessionsOnce(deviceId: string, generation: number): Promise<TLoaded> {
    const existing = inFlightByDevice.get(deviceId);
    if (existing?.generation === generation) return existing.request;

    const request = Promise.resolve().then(() => dependencies.loadSessions(deviceId));
    const entry = { generation, request };
    inFlightByDevice.set(deviceId, entry);
    const clear = () => {
      if (inFlightByDevice.get(deviceId) === entry) inFlightByDevice.delete(deviceId);
    };
    void request.then(clear, clear);
    return request;
  }

  async function load(deviceId: string, activate: boolean): Promise<DeviceSessionLoadOutcome> {
    const currentRequestGeneration = ++requestGeneration;
    const currentInvalidationGeneration = invalidationGeneration;
    dependencies.onBegin(deviceId, activate);

    // Let the cached/skeleton device pane reach the screen before invoking
    // native code. This remains necessary even when the Rust command is async:
    // it protects the first frame if platform IPC scheduling regresses.
    await afterNextPaint();
    if (
      currentRequestGeneration !== requestGeneration ||
      currentInvalidationGeneration !== invalidationGeneration ||
      !dependencies.isCurrent(deviceId)
    ) {
      return "stale";
    }

    let loaded: TLoaded;
    try {
      loaded = await loadSessionsOnce(deviceId, currentInvalidationGeneration);
    } catch (error) {
      if (
        currentRequestGeneration !== requestGeneration ||
        currentInvalidationGeneration !== invalidationGeneration ||
        !dependencies.isCurrent(deviceId)
      ) {
        return "stale";
      }
      dependencies.onFailed(deviceId, error);
      return "failed";
    }

    if (
      currentRequestGeneration !== requestGeneration ||
      currentInvalidationGeneration !== invalidationGeneration ||
      !dependencies.isCurrent(deviceId)
    ) {
      return "stale";
    }
    dependencies.onLoaded(deviceId, loaded);
    return "applied";
  }

  return {
    focus: (deviceId) => load(deviceId, true),
    refresh: (deviceId) => load(deviceId, false),
    invalidate: () => {
      requestGeneration += 1;
      invalidationGeneration += 1;
      dependencies.onInvalidated();
    },
  };
}
