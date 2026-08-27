// Application-update adapter. The controller depends on this narrow interface
// so headless tests never import Tauri's native updater plugin.

import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type DownloadEvent, type Update } from "@tauri-apps/plugin-updater";

export interface AppUpdateProgress {
  readonly downloadedBytes: number;
  readonly totalBytes: number | null;
}

export interface PendingAppUpdate {
  readonly currentVersion: string;
  readonly version: string;
  readonly date: string | null;
  readonly body: string | null;
  downloadAndInstall(onProgress: (progress: AppUpdateProgress) => void): Promise<void>;
  close(): Promise<void>;
}

export interface AppUpdater {
  currentVersion(): Promise<string>;
  check(): Promise<PendingAppUpdate | null>;
  relaunch(): Promise<void>;
}

function mapUpdate(update: Update): PendingAppUpdate {
  return {
    currentVersion: update.currentVersion,
    version: update.version,
    date: update.date ?? null,
    body: update.body ?? null,
    async downloadAndInstall(onProgress): Promise<void> {
      let downloadedBytes = 0;
      let totalBytes: number | null = null;
      await update.downloadAndInstall((event: DownloadEvent) => {
        if (event.event === "Started") {
          downloadedBytes = 0;
          totalBytes = event.data.contentLength ?? null;
        } else if (event.event === "Progress") {
          downloadedBytes += event.data.chunkLength;
        }
        if (event.event !== "Finished") onProgress({ downloadedBytes, totalBytes });
      });
    },
    close: () => update.close(),
  };
}

export function createTauriAppUpdater(): AppUpdater {
  return {
    currentVersion: () => getVersion(),
    check: () => check().then((update) => (update === null ? null : mapUpdate(update))),
    relaunch,
  };
}
