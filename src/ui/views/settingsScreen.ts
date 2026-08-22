// Settings: the object-storage modal, the download-root modal, the rail's
// saved-location control, notifications and the theme switch.

import type { Dispatch } from "../../app/actions";
import type { ThemePreference } from "../../store";
import { storageOf, type AppState } from "../../runtime/reducer";
import type { SaveStorageConfigInput, StorageConfig, StorageUrlStyle } from "../../types";
import { bindings, delegate, el, inputEl, selectEl } from "../dom";
import { downloadRootLabelText } from "../rail";

export interface SettingsScreen {
  renderTheme(state: AppState): void;
  renderDownloadRootLabel(state: AppState): void;
  setNotificationsSwitch(enabled: boolean): void;
  openStorageSettings(config: StorageConfig): void;
  closeStorageSettings(): void;
  setStorageDownloadRootField(value: string): void;
  openDownloadRootSettings(config: StorageConfig): void;
  closeDownloadRootSettings(): void;
  setDownloadRootField(value: string): void;
  dispose(): void;
}

function readStorageForm(): SaveStorageConfigInput {
  return {
    endpoint: inputEl("storageEndpoint").value.trim(),
    bucket: inputEl("storageBucket").value.trim(),
    accessKey: inputEl("storageAccessKey").value.trim(),
    secretKey: inputEl("storageSecretKey").value,
    prefix: inputEl("storagePrefix").value.trim(),
    urlStyle: selectEl("storageUrlStyle").value as StorageUrlStyle,
    downloadRoot: inputEl("storageDownloadRoot").value.trim(),
  };
}

export function createSettingsScreen(dispatch: Dispatch): SettingsScreen {
  const bound = bindings();
  const storageOverlay = el("storageOverlay");
  const downloadRootOverlay = el("downloadRootOverlay");

  /* ---- rail footer ---- */

  bound.add(
    delegate(el("openDownloadRootBtn"), "click", "#openDownloadRootBtn", () =>
      dispatch({ kind: "settings/openDownloadRoot" }),
    ),
  );
  bound.add(
    delegate(el("notifySwitch"), "click", "#notifySwitch", (matched) =>
      dispatch({ kind: "settings/setNotifications", enabled: matched.dataset.on !== "true" }),
    ),
  );
  bound.add(
    delegate(document.body, "click", "[data-theme-btn]", (matched) => {
      const theme = matched.dataset.themeBtn as ThemePreference | undefined;
      if (theme !== undefined) dispatch({ kind: "settings/setTheme", theme });
    }),
  );

  /* ---- object storage modal ---- */

  bound.add(
    delegate(storageOverlay, "click", "button", (matched) => {
      switch (matched.id) {
        case "cancelStorage":
          dispatch({ kind: "settings/closeStorage" });
          return;
        case "testStorageBtn":
          dispatch({ kind: "settings/testStorage", config: readStorageForm() });
          return;
        case "saveStorage":
          dispatch({ kind: "settings/saveStorage", config: readStorageForm() });
          return;
        case "selectDownloadRootBtn":
          dispatch({ kind: "settings/pickStorageDownloadRoot" });
          return;
        case "resetDownloadRootBtn":
          inputEl("storageDownloadRoot").value = "";
          return;
      }
    }),
  );

  /* ---- download root modal ---- */

  bound.add(
    delegate(downloadRootOverlay, "click", "button", (matched) => {
      switch (matched.id) {
        case "cancelDownloadRoot":
          dispatch({ kind: "settings/closeDownloadRoot" });
          return;
        case "chooseDownloadRootBtn":
          dispatch({ kind: "settings/pickDownloadRoot" });
          return;
        case "defaultDownloadRootBtn":
          inputEl("downloadRootInput").value = "";
          return;
        case "saveDownloadRoot":
          dispatch({ kind: "settings/saveDownloadRoot", downloadRoot: inputEl("downloadRootInput").value.trim() });
          return;
      }
    }),
  );

  return {
    renderTheme(state: AppState): void {
      const root = document.documentElement;
      const theme = state.ui.theme;
      if (theme === "system") root.removeAttribute("data-theme");
      else root.setAttribute("data-theme", theme);
      document.querySelectorAll<HTMLButtonElement>("[data-theme-btn]").forEach((btn) => {
        btn.dataset.on = String(btn.dataset.themeBtn === theme);
      });
    },
    renderDownloadRootLabel(state: AppState): void {
      const label = downloadRootLabelText(storageOf(state));
      el("downloadRootLabel").textContent = label;
      // The rail is 226px wide, so the path ellipsizes; the tooltip keeps the
      // whole thing readable without widening the sidebar.
      el("openDownloadRootBtn").title = `本机保存位置：${label}`;
    },
    setNotificationsSwitch(enabled: boolean): void {
      el("notifySwitch").dataset.on = String(enabled);
    },
    openStorageSettings(config: StorageConfig): void {
      inputEl("storageEndpoint").value = config.endpoint;
      inputEl("storageBucket").value = config.bucket;
      // The raw secret never round-trips from the backend (it lives only in the
      // OS keyring) — these fields always start empty. Saving with them left
      // empty means "keep the existing secret" (see SaveStorageConfigInput).
      const accessKeyInput = inputEl("storageAccessKey");
      const secretKeyInput = inputEl("storageSecretKey");
      accessKeyInput.value = "";
      secretKeyInput.value = "";
      const placeholder = config.secretConfigured ? "已设置 · 留空则不修改" : "";
      accessKeyInput.placeholder = placeholder;
      secretKeyInput.placeholder = placeholder;
      inputEl("storagePrefix").value = config.prefix;
      selectEl("storageUrlStyle").value = config.urlStyle;
      // Empty means "use the platform default download directory" — the
      // placeholder says so rather than us inventing a path we do not know.
      const downloadRootInput = inputEl("storageDownloadRoot");
      downloadRootInput.value = config.downloadRoot;
      downloadRootInput.placeholder = config.activeDownloadRoot;
      el("activeDownloadRoot").textContent =
        `当前生效目录：${config.activeDownloadRoot}。已有本地数据时请先上传并清除。`;
      storageOverlay.dataset.open = "true";
    },
    closeStorageSettings(): void {
      storageOverlay.dataset.open = "false";
    },
    setStorageDownloadRootField(value: string): void {
      inputEl("storageDownloadRoot").value = value;
    },
    openDownloadRootSettings(config: StorageConfig): void {
      const input = inputEl("downloadRootInput");
      input.value = config.downloadRoot;
      input.placeholder = config.activeDownloadRoot;
      el("downloadRootActive").textContent = `当前生效目录：${config.activeDownloadRoot}`;
      downloadRootOverlay.dataset.open = "true";
    },
    closeDownloadRootSettings(): void {
      downloadRootOverlay.dataset.open = "false";
    },
    setDownloadRootField(value: string): void {
      inputEl("downloadRootInput").value = value;
    },
    dispose: bound.dispose,
  };
}
