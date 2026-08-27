// The `AppView` the browser gets: the LAN device, library and settings screens,
// plus the routing that
// decides which of them owns the top bar and the content pane right now.

import type { Dispatch } from "../../app/actions";
import type { AppView } from "../../app/appView";
import type { AppState } from "../../runtime/reducer";
import type { SelectionScope } from "../../store";
import type { StorageConfig } from "../../types";
import { el } from "../dom";
import { emptyStateHtml } from "../deviceView";
import type { TraySelection } from "../traySelector";
import { createDeviceScreen } from "./deviceScreen";
import { createLibraryScreen } from "./libraryScreen";
import { installListEvents } from "./listEvents";
import { createSettingsScreen } from "./settingsScreen";
import { createTrayScreen } from "./trayScreen";

export function createDomAppView(dispatch: Dispatch): AppView {
  /** The scope every shared toolbar/bulk event belongs to, resolved when the
   * event fires rather than when the listener was installed. */
  let scope: SelectionScope = "device";

  const device = createDeviceScreen(dispatch);
  const library = createLibraryScreen(dispatch);
  const tray = createTrayScreen(dispatch);
  const settings = createSettingsScreen(dispatch);
  const listEvents = installListEvents(el("content"), dispatch, () => scope);

  const isLibrary = (state: AppState): boolean => {
    scope = state.ui.view === "library" ? "library" : "device";
    return scope === "library";
  };

  return {
    renderRail: (state) => device.renderRail(state),
    renderNav: (state) => library.renderNav(state),
    renderTopbar: (state) => {
      if (isLibrary(state)) library.renderTopbar(state);
      else device.renderTopbar(state);
    },
    renderContent: (state) => {
      if (isLibrary(state)) library.renderContent(state);
      else device.renderContent(state);
    },
    renderList: (state) => {
      if (isLibrary(state)) library.renderList(state);
      else device.renderList(state);
    },
    renderTray: (selection: TraySelection) => tray.render(selection),
    renderTheme: (state) => settings.renderTheme(state),
    renderDownloadRootLabel: (state) => settings.renderDownloadRootLabel(state),
    setNotificationsSwitch: (enabled) => settings.setNotificationsSwitch(enabled),

    showPairing: (deviceId) => device.showPairing(deviceId),
    updatePairingRing: (remaining, total) => device.updatePairingRing(remaining, total),
    hidePairing: () => device.hidePairing(),
    openAddDevice: () => device.openAddDevice(),
    closeAddDevice: () => device.closeAddDevice(),
    openStorageSettings: (config: StorageConfig) => settings.openStorageSettings(config),
    closeStorageSettings: () => settings.closeStorageSettings(),
    setStorageDownloadRootField: (value) => settings.setStorageDownloadRootField(value),
    openDownloadRootSettings: (config: StorageConfig) => settings.openDownloadRootSettings(config),
    closeDownloadRootSettings: () => settings.closeDownloadRootSettings(),
    setDownloadRootField: (value) => settings.setDownloadRootField(value),
    openUpdateSettings: (model) => settings.openUpdateSettings(model),
    closeUpdateSettings: () => settings.closeUpdateSettings(),
    renderUpdateSettings: (model) => settings.renderUpdateSettings(model),

    confirmDestructive: (message) => globalThis.confirm(message),
    setBusy: (label) => device.setBusy(label),
    showFatal: (title, body) => {
      el("content").innerHTML = emptyStateHtml(title, body);
    },
    dispose: () => {
      listEvents.dispose();
      settings.dispose();
      tray.dispose();
      library.dispose();
      device.dispose();
    },
  };
}
