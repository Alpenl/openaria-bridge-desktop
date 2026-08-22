import type { Device } from "../types";

/** Tauri view models are JSON values, so equality can be checked before rebuilding DOM. */
export function visibleSnapshotsEqual(current: unknown, incoming: unknown): boolean {
  if (current === incoming) return true;
  return JSON.stringify(current) === JSON.stringify(incoming);
}

/** The device main pane does not render heartbeat timestamps. */
export function devicePaneSnapshotsEqual(current: Device | undefined, incoming: Device | undefined): boolean {
  if (current === undefined || incoming === undefined) return current === incoming;
  return (
    current.id === incoming.id &&
    current.displayId === incoming.displayId &&
    current.ip === incoming.ip &&
    current.state === incoming.state
  );
}
