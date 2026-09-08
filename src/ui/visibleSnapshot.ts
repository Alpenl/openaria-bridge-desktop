import type { Device } from "../types";

/** Compare decoded JSON snapshots without allocating two serialized copies.
 * Object property order is immaterial; array order remains visible. */
export function visibleSnapshotsEqual(current: unknown, incoming: unknown): boolean {
  if (current === incoming) return true;
  if (current === null || incoming === null || typeof current !== "object" || typeof incoming !== "object") {
    return false;
  }
  if (Array.isArray(current)) {
    if (!Array.isArray(incoming) || current.length !== incoming.length) return false;
    return current.every((value, index) => visibleSnapshotsEqual(value, incoming[index]));
  }
  if (Array.isArray(incoming)) return false;
  const left = current as Record<string, unknown>;
  const right = incoming as Record<string, unknown>;
  const leftKeys = Object.keys(left).filter((key) => left[key] !== undefined);
  const rightKeys = Object.keys(right).filter((key) => right[key] !== undefined);
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every(
    (key) => Object.prototype.hasOwnProperty.call(right, key) && visibleSnapshotsEqual(left[key], right[key]),
  );
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
