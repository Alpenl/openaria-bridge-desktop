// Every user intent the app can act on, as data.
//
// A DOM view's whole job is to turn a click into one of these and hand it to
// `TransferApp.dispatch`. Views hold no backend, no store and no timers, and a
// headless test can drive the entire application by dispatching the same values
// a click would have produced.
//
// Identities are branded (`ids.ts`), so an action cannot carry the wrong kind
// of id — a `SessionId` will not fit where a `LibraryKey` is required, and the
// tray's `cancelUpload` command only accepts an `UploadJobId`.

import type { DeviceId, FileId, LibraryKey, SessionId } from "../ids";
import type { FilterState, SelectionScope, ThemePreference } from "../store";
import type { ResourceRetryTarget } from "../runtime/reducer";
import type { SaveStorageConfigInput } from "../types";
import type { TrayCommand } from "../ui/traySelector";
import type { MediaWorkspaceAction } from "../ui/media/types";

export type UiAction =
  /* independently recoverable backend resources */
  | { readonly kind: "resource/retry"; readonly resource: ResourceRetryTarget }

  /* navigation */
  | { readonly kind: "device/select"; readonly deviceId: DeviceId }
  | { readonly kind: "device/reconnect"; readonly deviceId: DeviceId }
  | { readonly kind: "device/disconnect"; readonly deviceId: DeviceId }
  | { readonly kind: "device/refreshSessions"; readonly deviceId: DeviceId }
  | { readonly kind: "library/open" }
  | { readonly kind: "library/reconcile"; readonly force: boolean }
  | { readonly kind: "media/open" }
  | MediaWorkspaceAction

  /* pairing + manual add */
  | { readonly kind: "pairing/cancel" }
  | { readonly kind: "device/openAdd" }
  | { readonly kind: "device/closeAdd" }
  | { readonly kind: "device/submitAdd"; readonly ip: string }

  /* device-wide commands */
  | { readonly kind: "device/downloadAllNew"; readonly deviceId: DeviceId }
  | { readonly kind: "device/cleanupBackedUp"; readonly deviceId: DeviceId }
  | { readonly kind: "device/cleanupDownloaded"; readonly deviceId: DeviceId }
  | { readonly kind: "library/uploadAllPending" }

  /* list controls */
  | { readonly kind: "list/filter"; readonly scope: SelectionScope; readonly patch: Partial<FilterState> }
  | { readonly kind: "list/toggleSort"; readonly scope: SelectionScope }
  | { readonly kind: "list/toggleRow"; readonly scope: SelectionScope; readonly rowKey: string }
  | {
      readonly kind: "list/select";
      readonly scope: SelectionScope;
      readonly key: string;
      readonly selected: boolean;
    }
  | { readonly kind: "list/selectAll"; readonly scope: SelectionScope; readonly selected: boolean }
  | { readonly kind: "list/clearSelection"; readonly scope: SelectionScope }
  | { readonly kind: "list/bulkAction"; readonly scope: SelectionScope }
  | { readonly kind: "list/bulkRemove"; readonly scope: SelectionScope }

  /* per-row commands */
  | { readonly kind: "session/download"; readonly deviceId: DeviceId; readonly sessionId: SessionId }
  | {
      readonly kind: "session/downloadFile";
      readonly deviceId: DeviceId;
      readonly sessionId: SessionId;
      readonly fileId: FileId;
    }
  | { readonly kind: "session/remove"; readonly deviceId: DeviceId; readonly sessionId: SessionId }
  | { readonly kind: "entry/upload"; readonly key: LibraryKey }
  | { readonly kind: "entry/revealFile"; readonly key: LibraryKey; readonly fileId: FileId }
  | { readonly kind: "entry/remove"; readonly key: LibraryKey }

  /* tray */
  | { readonly kind: "tray/toggle" }
  | { readonly kind: "tray/command"; readonly command: TrayCommand }

  /* settings */
  | { readonly kind: "settings/openStorage" }
  | { readonly kind: "settings/closeStorage" }
  | { readonly kind: "settings/testStorage"; readonly config: SaveStorageConfigInput }
  | { readonly kind: "settings/saveStorage"; readonly config: SaveStorageConfigInput }
  | { readonly kind: "settings/pickStorageDownloadRoot" }
  | { readonly kind: "settings/openDownloadRoot" }
  | { readonly kind: "settings/closeDownloadRoot" }
  | { readonly kind: "settings/pickDownloadRoot" }
  | { readonly kind: "settings/saveDownloadRoot"; readonly downloadRoot: string }
  | { readonly kind: "settings/setNotifications"; readonly enabled: boolean }
  | { readonly kind: "settings/setTheme"; readonly theme: ThemePreference };

export type Dispatch = (action: UiAction) => void;
