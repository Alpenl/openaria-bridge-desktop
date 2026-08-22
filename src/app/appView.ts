// The surface the controller paints through.
//
// `TransferApp` never touches the DOM; it calls these methods and passes the
// state they should render from. That is what lets the whole application be
// exercised headlessly: a test implements `AppView` with a recorder and drives
// the real controller.
//
// Every method is a *render*, not a *mutation*: they are idempotent for a given
// state, so the controller may call them whenever it thinks something changed.

import type { AppState } from "../runtime/reducer";
import type { TraySelection } from "../ui/traySelector";
import type { StorageConfig } from "../types";
import type { MediaWorkspaceSnapshot } from "../ui/media/types";

export interface AppView {
  /** Device list and connected count in the left rail. */
  renderRail(state: AppState): void;
  /** The library nav item and its pending badge. */
  renderNav(state: AppState): void;
  /** The top bar of whichever view is active. */
  renderTopbar(state: AppState): void;
  /** The whole content pane: summary, toolbar, section heading, list. */
  renderContent(state: AppState): void;
  /** Only the rows, the section heading and the counter — leaves the toolbar
   * (and the focused search field) alone. */
  renderList(state: AppState): void;
  /** The removable-media workspace owns its own runtime store and is painted
   * from an immutable projection. Optional keeps headless legacy views useful. */
  renderMedia?(snapshot: MediaWorkspaceSnapshot): void;
  renderTray(selection: TraySelection): void;
  renderTheme(state: AppState): void;
  renderDownloadRootLabel(state: AppState): void;
  setNotificationsSwitch(enabled: boolean): void;

  /* overlays */
  showPairing(deviceId: string): void;
  updatePairingRing(remaining: number, total: number): void;
  hidePairing(): void;
  openAddDevice(): void;
  closeAddDevice(): void;
  openStorageSettings(config: StorageConfig): void;
  closeStorageSettings(): void;
  setStorageDownloadRootField(value: string): void;
  openDownloadRootSettings(config: StorageConfig): void;
  closeDownloadRootSettings(): void;
  setDownloadRootField(value: string): void;

  /** A blocking, user-facing confirmation for an irreversible remote deletion.
   * Returns whether the user agreed. */
  confirmDestructive(message: string): boolean;
  /** Marks a control as busy while a long check runs before a prompt. */
  setBusy(label: string | null): void;
  /** The app could not be started at all. */
  showFatal(title: string, body: string): void;
  /** Removes listeners the view owns. Idempotent. */
  dispose(): void;
}
