// The Tauri adapter: the only implementation of `TransferBackend` that talks to
// a real process. It owns the channel names (through `tauriTransport.ts`), the
// unsubscribe functions returned by `listen`, the translation of transport
// failures into `BackendError`, and the server-issued resource revisions that
// let the runtime order snapshots against events.

import {
  api,
  onDevicesUpdate,
  onLibraryUpdate,
  onPairingResolved,
  onPairingTick,
  onSessionsUpdate,
  onStorageUpdate,
  onTransferJobsUpdate,
  onTransfersUpdate,
  revisionedApi,
  RpcInvocationError,
  subscribeAll,
  type EventRegistration,
  type RevisionedWireValue,
} from "./tauriTransport";
import {
  BackendError,
  revisioned,
  type BackendEventSink,
  type BackendSnapshot,
  type JobDispatch,
  type LibraryMutation,
  type Revisioned,
  type SessionMutation,
  type TransferBackend,
} from "./backend";
import { toBatchItems, toDispatchItems } from "./batch";
import {
  asDownloadJobId,
  asLibraryKey,
  asPairingAttemptId,
  asSessionId,
  asUploadJobId,
  type DownloadJobId,
  type LibraryKey,
  type SessionId,
  type UploadJobId,
} from "../ids";
import type { BatchJobResult, LibraryMutationResult, SaveStorageConfigInput, SessionMutationResult } from "../types";

/** Every rejection that crosses the transport boundary becomes a
 * `BackendError` naming the channel it came from, so no caller has to know
 * what shape Tauri rejects with. */
function translate(channel: string, error: unknown): BackendError {
  if (error instanceof BackendError) return error;
  if (error instanceof RpcInvocationError) {
    return new BackendError(channel, error.rpcError.message, { cause: error, rpcError: error.rpcError });
  }
  return new BackendError(channel, String(error), { cause: error });
}

function sessionMutation(raw: SessionMutationResult, requested?: readonly string[]): SessionMutation {
  return {
    items: toBatchItems(raw, asSessionId, requested),
    sessions: raw.sessions,
    operationError: raw.operationError,
  };
}
function libraryMutation(raw: LibraryMutationResult, requested: readonly string[]): LibraryMutation {
  return { items: toBatchItems(raw, asLibraryKey, requested), library: raw.library };
}
function downloadDispatch(raw: BatchJobResult, requested: readonly string[]): JobDispatch<SessionId, DownloadJobId> {
  return { items: toDispatchItems(raw, asSessionId, asDownloadJobId, requested) };
}
function uploadDispatch(raw: BatchJobResult, requested: readonly string[]): JobDispatch<LibraryKey, UploadJobId> {
  return { items: toDispatchItems(raw, asLibraryKey, asUploadJobId, requested) };
}

function mapWireValue<T, U>(raw: RevisionedWireValue<T>, map: (value: T) => U): Revisioned<U> {
  return { revision: raw.revision, value: map(raw.value) };
}

export function createTauriBackend(): TransferBackend {
  /** Runs a command, translating its failure and naming its channel. */
  function call<T>(channel: string, run: () => Promise<T>): Promise<T> {
    return Promise.resolve()
      .then(run)
      .catch((error: unknown) => {
        throw translate(channel, error);
      });
  }

  return {
    async subscribe(sink: BackendEventSink): Promise<() => void> {
      const registrations: EventRegistration[] = [
        () =>
          onDevicesUpdate((devices, eventRevisionNumber) =>
            sink({ kind: "devices", revision: eventRevisionNumber, devices }),
          ),
        () =>
          onSessionsUpdate(({ deviceId, sessions }, eventRevisionNumber) =>
            sink({
              kind: "sessions",
              revision: eventRevisionNumber,
              deviceId,
              sessions,
            }),
          ),
        () =>
          onLibraryUpdate((library, eventRevisionNumber) =>
            sink({ kind: "library", revision: eventRevisionNumber, library }),
          ),
        () =>
          onTransfersUpdate((transfers, eventRevisionNumber) =>
            sink({ kind: "transfers", revision: eventRevisionNumber, transfers }),
          ),
        () =>
          onStorageUpdate((storage, eventRevisionNumber) =>
            sink({ kind: "storage", revision: eventRevisionNumber, storage }),
          ),
        () =>
          onTransferJobsUpdate((jobs, eventRevisionNumber) =>
            sink({
              kind: "transferJobs",
              revision: eventRevisionNumber,
              jobs,
            }),
          ),
        () =>
          onPairingTick((payload, eventRevisionNumber) =>
            sink({ kind: "pairingTick", revision: eventRevisionNumber, payload }),
          ),
        () =>
          onPairingResolved((payload, eventRevisionNumber) =>
            sink({
              kind: "pairingResolved",
              revision: eventRevisionNumber,
              payload,
            }),
          ),
      ];
      // `subscribeAll` registers all channels or none and hands back one
      // idempotent disposer — the transport's unlisten functions never escape.
      try {
        return await subscribeAll(registrations);
      } catch (error) {
        throw translate("events", error);
      }
    },

    async readSnapshot(): Promise<Revisioned<BackendSnapshot>> {
      const outer = await call("read_snapshot", () => revisionedApi.readSnapshot());
      return revisioned(outer.revision, {
        devices: outer.value.devices.value,
        library: outer.value.library.value,
        transfers: outer.value.transfers.value,
        storage: outer.value.storage.value,
        revisions: {
          devices: outer.value.devices.revision,
          library: outer.value.library.revision,
          transfers: outer.value.transfers.revision,
          storage: outer.value.storage.revision,
        },
      });
    },

    listDevices: () => call("list_devices", () => revisionedApi.listDevices()),
    listSessions: (deviceId) => call("list_sessions", () => revisionedApi.listSessions(deviceId)),
    listLibrary: () => call("list_library", () => revisionedApi.listLibrary()),
    listTransfers: () => call("list_transfers", () => revisionedApi.listTransfers()),
    getStorageConfig: () => call("get_storage_config", () => revisionedApi.getStorageConfig()),

    connectDevice: (deviceId) => call("connect_device", () => api.connectDevice(deviceId)).then(asPairingAttemptId),
    cancelPairing: (deviceId, attemptId) => call("cancel_pairing", () => api.cancelPairing(deviceId, attemptId)),
    addManualDevice: (ip) => call("add_manual_device", () => revisionedApi.addManualDevice(ip)),
    disconnectDevice: (deviceId) => call("disconnect_device", () => api.disconnectDevice(deviceId)),

    deleteSessions: (deviceId, sessionIds) =>
      call("delete_sessions", () =>
        revisionedApi
          .deleteSessions(deviceId, [...sessionIds])
          .then((raw) => mapWireValue(raw, (value) => sessionMutation(value, sessionIds))),
      ),
    cleanupBackedUp: (deviceId) =>
      call("cleanup_backed_up", () =>
        revisionedApi.cleanupBackedUp(deviceId).then((raw) => mapWireValue(raw, sessionMutation)),
      ),
    previewDownloadedCleanup: (deviceId) =>
      call("preview_downloaded_cleanup", () => api.previewDownloadedCleanup(deviceId)),
    cleanupDownloaded: (deviceId) => call("cleanup_downloaded", () => revisionedApi.cleanupDownloaded(deviceId)),

    removeLibraryEntries: (keys) =>
      call("remove_library_entries", () =>
        revisionedApi
          .removeLibraryEntries([...keys])
          .then((raw) => mapWireValue(raw, (value) => libraryMutation(value, keys))),
      ),
    revealLibraryFile: (key, fileId) => call("reveal_library_file", () => api.revealLibraryFile(key, fileId)),

    downloadSession: (deviceId, sessionId) =>
      call("download_session", () => api.downloadSession(deviceId, sessionId)).then(asDownloadJobId),
    downloadSessions: (deviceId, sessionIds) =>
      call("download_sessions", () =>
        api.downloadSessions(deviceId, [...sessionIds]).then((raw) => downloadDispatch(raw, sessionIds)),
      ),
    downloadFile: (deviceId, sessionId, fileId) =>
      call("download_file", () => api.downloadFile(deviceId, sessionId, fileId)).then(asDownloadJobId),
    uploadEntry: (key) => call("upload_entry", () => api.uploadEntry(key)).then(asUploadJobId),
    uploadEntries: (keys) =>
      call("upload_entries", () => api.uploadEntries([...keys]).then((raw) => uploadDispatch(raw, keys))),

    retryTransfer: (id) => call("retry_transfer", () => api.retryTransfer(id)).then(() => undefined),
    pauseTransferJob: (jobId) => call("pause_transfer_job", () => api.pauseTransferJob(jobId)),
    resumeTransferJob: (jobId) => call("resume_transfer_job", () => api.resumeTransferJob(jobId)),
    cancelTransferJob: (jobId) => call("cancel_transfer_job", () => api.cancelTransferJob(jobId)),
    dismissTransferJob: (jobId) => call("dismiss_transfer_job", () => api.dismissTransferJob(jobId)),
    cancelUpload: (jobId) => call("cancel_upload", () => api.cancelUpload(jobId)),
    dismissUpload: (jobId) => call("dismiss_upload_transfer", () => api.dismissUpload(jobId)),

    selectDownloadRoot: () => call("select_download_root", () => api.selectDownloadRoot()),
    saveDownloadRoot: (downloadRoot) => call("save_download_root", () => revisionedApi.saveDownloadRoot(downloadRoot)),
    saveStorageConfig: (config: SaveStorageConfigInput) =>
      call("save_storage_config", () => revisionedApi.saveStorageConfig(config)),
    testStorageConnection: (config: SaveStorageConfigInput) =>
      call("test_storage_connection", () => api.testStorageConnection(config)),

    setNotificationsEnabled: (enabled) => call("set_notifications_enabled", () => api.setNotificationsEnabled(enabled)),
  };
}
