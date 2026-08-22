// Which pairing events the UI is allowed to act on.
//
// `connect_device` returns the id of the attempt it created, and every
// later backend event for that flow carries the same id. Because a device
// can be re-connected (a new attempt supersedes the old one) while an
// earlier attempt's poll is still in flight, matching on the device id
// alone is not enough: a late result from a dead attempt would close, or
// mislabel, the overlay the user is currently watching.

export interface PairingFocus {
  /** The device whose pairing overlay is on screen, if any. */
  deviceId: string | null;
  /** The attempt id `connect_device` returned — `null` while that call is
   * still in flight, i.e. the id is not known yet. */
  attemptId: string | null;
}

export interface PairingEventIdentity {
  deviceId: string;
  attemptId: string;
}

/** `apply`: this event belongs to the attempt on screen.
 *  `defer`: it belongs to the device on screen but arrived before its
 *  attempt id was known — hold it rather than guessing.
 *  `drop`: it belongs to some other device or a superseded attempt. */
export type PairingEventVerdict = "apply" | "defer" | "drop";

export function classifyPairingEvent(focus: PairingFocus, event: PairingEventIdentity): PairingEventVerdict {
  if (focus.deviceId === null || event.deviceId !== focus.deviceId) return "drop";
  if (focus.attemptId === null) return "defer";
  return event.attemptId === focus.attemptId ? "apply" : "drop";
}
