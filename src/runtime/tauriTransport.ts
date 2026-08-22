// Typed wrapper around the Tauri command/event surface (part of the Tauri
// backend adapter: `tauriBackend.ts` is its only consumer). Production events
// come from the real composition; an explicit demo feature may emit the same
// shapes from its isolated simulator. Keep this the only frontend module that
// imports from `@tauri-apps/api`.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  Device,
  LibraryEntry,
  PairingResolutionPayload,
  PairingTickPayload,
  RpcError,
  SaveStorageConfigInput,
  SessionView,
  StorageConfig,
  Transfer,
  TransferJobEvent,
} from "../types";
import {
  decodeBatchJobs,
  decodeBoolean,
  decodeCleanupPreview,
  decodeCleanupResult,
  decodeDeviceValue,
  decodeDevices,
  decodeLibrary,
  decodeLibraryMutationResult,
  decodeNullableString,
  decodePairingResolutionPayload,
  decodePairingTickPayload,
  decodeRevision,
  decodeRpcErrorValue,
  decodeSessionMutationResult,
  decodeSaveStorageConfigInput,
  decodeSessions,
  decodeSessionsUpdate,
  decodeStorage,
  decodeString,
  decodeTransferJobs,
  decodeTransfers,
  decodeVoid,
  RuntimeDecodeError,
} from "./decoder";

export interface RevisionedWireValue<T> {
  readonly revision: number;
  readonly value: T;
}

export interface ApplicationSnapshotWire {
  readonly devices: RevisionedWireValue<Device[]>;
  readonly library: RevisionedWireValue<LibraryEntry[]>;
  readonly transfers: RevisionedWireValue<Transfer[]>;
  readonly storage: RevisionedWireValue<StorageConfig>;
}

export class RpcInvocationError extends Error {
  readonly command: string;
  readonly rpcError: RpcError;

  constructor(command: string, rpcError: RpcError) {
    super(rpcError.message);
    this.name = "RpcInvocationError";
    this.command = command;
    this.rpcError = rpcError;
  }
}

function plainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function rejectInvocation(command: string, reason: unknown): never {
  if (!plainObject(reason)) throw reason;
  const candidate = Object.prototype.hasOwnProperty.call(reason, "error") ? reason.error : reason;
  const rpcError = decodeRpcErrorValue(candidate, `${command}.error`);
  throw new RpcInvocationError(command, rpcError);
}

function unwrapRevisioned(value: unknown, path: string): RevisionedWireValue<unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RuntimeDecodeError(path, "revisioned object", value);
  }
  const item = value as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(item, "revision")) {
    throw new RuntimeDecodeError(`${path}.revision`, "present value", undefined);
  }
  if (!Object.prototype.hasOwnProperty.call(item, "value")) {
    throw new RuntimeDecodeError(`${path}.value`, "present value", undefined);
  }
  return {
    revision: decodeRevision(item.revision, `${path}.revision`),
    value: item.value,
  };
}

function decodeResponse<T>(channel: string, value: unknown, decoder: (raw: unknown, path?: string) => T): T {
  try {
    return decoder(value, `${channel}.response`);
  } catch (error) {
    if (error instanceof RuntimeDecodeError) throw error;
    throw new RuntimeDecodeError(`${channel}.response`, "valid payload", value);
  }
}

function invokeValueDecoded<T>(
  command: string,
  decoder: (raw: unknown, path?: string) => T,
  payload?: Record<string, unknown>,
): Promise<T> {
  return invoke<unknown>(command, payload).then(
    (value) => decodeResponse(command, value, decoder),
    (reason: unknown) => rejectInvocation(command, reason),
  );
}

function invokeRevisionedDecoded<T>(
  command: string,
  decoder: (raw: unknown, path?: string) => T,
  payload?: Record<string, unknown>,
): Promise<RevisionedWireValue<T>> {
  return invoke<unknown>(command, payload).then(
    (raw) => {
      const unwrapped = unwrapRevisioned(raw, `${command}.response`);
      return { revision: unwrapped.revision, value: decodeResponse(command, unwrapped.value, decoder) };
    },
    (reason: unknown) => rejectInvocation(command, reason),
  );
}

function decodeEvent<T>(
  channel: string,
  raw: unknown,
  decoder: (raw: unknown, path?: string) => T,
): {
  revision: number;
  value: T;
} {
  const unwrapped = unwrapRevisioned(raw, `${channel}.payload`);
  return { revision: unwrapped.revision, value: decodeResponse(channel, unwrapped.value, decoder) };
}

function decodeNestedRevisioned<T>(
  value: unknown,
  path: string,
  decoder: (raw: unknown, path?: string) => T,
): RevisionedWireValue<T> {
  const unwrapped = unwrapRevisioned(value, path);
  return { revision: unwrapped.revision, value: decodeResponse(path, unwrapped.value, decoder) };
}

export function decodeApplicationSnapshot(value: unknown, path = "payload"): ApplicationSnapshotWire {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RuntimeDecodeError(path, "object", value);
  }
  const item = value as Record<string, unknown>;
  return {
    devices: decodeNestedRevisioned(item.devices, `${path}.devices`, decodeDevices),
    library: decodeNestedRevisioned(item.library, `${path}.library`, decodeLibrary),
    transfers: decodeNestedRevisioned(item.transfers, `${path}.transfers`, decodeTransfers),
    storage: decodeNestedRevisioned(item.storage, `${path}.storage`, decodeStorage),
  };
}

function invokeSnapshotDecoded(command: string): Promise<RevisionedWireValue<ApplicationSnapshotWire>> {
  return invoke<unknown>(command).then(
    (raw) => {
      const outer = unwrapRevisioned(raw, `${command}.response`);
      const value = decodeApplicationSnapshot(outer.value, `${command}.response.value`);
      for (const [resource, nested] of Object.entries(value)) {
        if (nested.revision > outer.revision) {
          throw new RuntimeDecodeError(
            `${command}.response.value.${resource}.revision`,
            `revision <= ${outer.revision}`,
            nested.revision,
          );
        }
      }
      return { revision: outer.revision, value };
    },
    (reason: unknown) => rejectInvocation(command, reason),
  );
}

function reportEventDecodeError(channel: string, error: unknown): void {
  // Events have no caller awaiting a Promise. Dropping malformed input is the
  // fail-closed behavior; retain a bounded diagnostic for the developer log.
  console.error(`[${channel}] ${error instanceof Error ? error.message : String(error)}`);
}

function listenDecoded<T>(
  channel: string,
  decoder: (raw: unknown, path?: string) => T,
  cb: (value: T, revision: number) => void,
): Promise<UnlistenFn> {
  return listen<unknown>(channel, (event) => {
    try {
      const decoded = decodeEvent(channel, event.payload, decoder);
      cb(decoded.value, decoded.revision);
    } catch (error) {
      reportEventDecodeError(channel, error);
    }
  });
}

export const api = {
  // Historical callers expect the bare value shape; the transport still
  // validates the mandatory revisioned envelope before unwrapping it.
  listDevices: () => invokeRevisionedDecoded("list_devices", decodeDevices).then((raw) => raw.value),
  /** Resolves to the id of the pairing attempt the backend created. Every
   * later step of this flow — ticks, resolution, cancellation — is matched
   * against it, so a superseded attempt can never drive this UI. */
  connectDevice: (deviceId: string) => invokeValueDecoded("connect_device", decodeString, { deviceId }),
  cancelPairing: (deviceId: string, attemptId: string) =>
    invokeValueDecoded("cancel_pairing", decodeVoid, { deviceId, attemptId }),
  addManualDevice: (ip: string) =>
    invokeRevisionedDecoded("add_manual_device", decodeDeviceValue, { ip }).then((raw) => raw.value),
  disconnectDevice: (deviceId: string) => invokeValueDecoded("disconnect_device", decodeVoid, { deviceId }),

  listSessions: (deviceId: string) =>
    invokeRevisionedDecoded("list_sessions", decodeSessions, { deviceId }).then((raw) => raw.value),
  deleteSessions: (deviceId: string, sessionIds: string[]) =>
    invokeRevisionedDecoded("delete_sessions", decodeSessionMutationResult, { deviceId, sessionIds }).then(
      (raw) => raw.value,
    ),
  cleanupBackedUp: (deviceId: string) =>
    invokeRevisionedDecoded("cleanup_backed_up", decodeSessionMutationResult, { deviceId }).then((raw) => raw.value),
  previewDownloadedCleanup: (deviceId: string) =>
    invokeValueDecoded("preview_downloaded_cleanup", decodeCleanupPreview, { deviceId }),
  cleanupDownloaded: (deviceId: string) =>
    invokeRevisionedDecoded("cleanup_downloaded", decodeCleanupResult, { deviceId }).then((raw) => raw.value),

  listLibrary: () => invokeRevisionedDecoded("list_library", decodeLibrary).then((raw) => raw.value),
  removeLibraryEntries: (keys: string[]) =>
    invokeRevisionedDecoded("remove_library_entries", decodeLibraryMutationResult, { keys }).then((raw) => raw.value),

  listTransfers: () => invokeRevisionedDecoded("list_transfers", decodeTransfers).then((raw) => raw.value),
  downloadSession: (deviceId: string, sessionId: string) =>
    invokeValueDecoded("download_session", decodeString, { deviceId, sessionId }),
  downloadSessions: (deviceId: string, sessionIds: string[]) =>
    invokeValueDecoded("download_sessions", decodeBatchJobs, { deviceId, sessionIds }),
  downloadFile: (deviceId: string, sessionId: string, fileId: string) =>
    invokeValueDecoded("download_file", decodeString, { deviceId, sessionId, fileId }),
  uploadEntry: (key: string) => invokeValueDecoded("upload_entry", decodeString, { key }),
  uploadEntries: (keys: string[]) => invokeValueDecoded("upload_entries", decodeBatchJobs, { keys }),
  retryTransfer: (jobId: string) => invokeValueDecoded("retry_transfer", decodeString, { jobId }),
  pauseTransferJob: (jobId: string) => invokeValueDecoded("pause_transfer_job", decodeVoid, { jobId }),
  resumeTransferJob: (jobId: string) => invokeValueDecoded("resume_transfer_job", decodeVoid, { jobId }),
  cancelTransferJob: (jobId: string) => invokeValueDecoded("cancel_transfer_job", decodeVoid, { jobId }),
  dismissTransferJob: (jobId: string) => invokeValueDecoded("dismiss_transfer_job", decodeVoid, { jobId }),
  cancelUpload: (jobId: string) => invokeValueDecoded("cancel_upload", decodeVoid, { jobId }),
  dismissUpload: (jobId: string) => invokeValueDecoded("dismiss_upload_transfer", decodeVoid, { jobId }),
  revealLibraryFile: (key: string, fileId: string) =>
    invokeValueDecoded("reveal_library_file", decodeVoid, { key, fileId }),

  getStorageConfig: () => invokeRevisionedDecoded("get_storage_config", decodeStorage).then((raw) => raw.value),
  selectDownloadRoot: () => invokeValueDecoded("select_download_root", decodeNullableString),
  saveDownloadRoot: (downloadRoot: string) =>
    invokeRevisionedDecoded("save_download_root", decodeStorage, { downloadRoot }).then((raw) => raw.value),
  saveStorageConfig: (config: SaveStorageConfigInput) =>
    invokeRevisionedDecoded("save_storage_config", decodeStorage, {
      config: decodeSaveStorageConfigInput(config, "save_storage_config.input"),
    }).then((raw) => raw.value),
  testStorageConnection: (config: SaveStorageConfigInput) =>
    invokeValueDecoded("test_storage_connection", decodeVoid, {
      config: decodeSaveStorageConfigInput(config, "test_storage_connection.input"),
    }),

  setNotificationsEnabled: (enabled: boolean) =>
    invokeValueDecoded("set_notifications_enabled", decodeBoolean, { enabled }),
};

/** Read methods that preserve the backend's resource revision. The public
 * `api` above intentionally keeps its historical value-only shape for simple
 * command tests; the Tauri adapter uses this companion surface for ordering. */
export const revisionedApi = {
  readSnapshot: () => invokeSnapshotDecoded("read_snapshot"),
  listDevices: () => invokeRevisionedDecoded("list_devices", decodeDevices),
  listSessions: (deviceId: string) => invokeRevisionedDecoded("list_sessions", decodeSessions, { deviceId }),
  listLibrary: () => invokeRevisionedDecoded("list_library", decodeLibrary),
  listTransfers: () => invokeRevisionedDecoded("list_transfers", decodeTransfers),
  getStorageConfig: () => invokeRevisionedDecoded("get_storage_config", decodeStorage),
  addManualDevice: (ip: string) => invokeRevisionedDecoded("add_manual_device", decodeDeviceValue, { ip }),
  deleteSessions: (deviceId: string, sessionIds: string[]) =>
    invokeRevisionedDecoded("delete_sessions", decodeSessionMutationResult, { deviceId, sessionIds }),
  cleanupBackedUp: (deviceId: string) =>
    invokeRevisionedDecoded("cleanup_backed_up", decodeSessionMutationResult, { deviceId }),
  cleanupDownloaded: (deviceId: string) =>
    invokeRevisionedDecoded("cleanup_downloaded", decodeCleanupResult, { deviceId }),
  removeLibraryEntries: (keys: string[]) =>
    invokeRevisionedDecoded("remove_library_entries", decodeLibraryMutationResult, { keys }),
  saveDownloadRoot: (downloadRoot: string) =>
    invokeRevisionedDecoded("save_download_root", decodeStorage, { downloadRoot }),
  saveStorageConfig: (config: SaveStorageConfigInput) =>
    invokeRevisionedDecoded("save_storage_config", decodeStorage, {
      config: decodeSaveStorageConfigInput(config, "save_storage_config.input"),
    }),
};

export type { PairingResolutionPayload, PairingTickPayload };

export interface SessionsUpdatePayload {
  deviceId: string;
  sessions: SessionView[];
}

export function onDevicesUpdate(cb: (devices: Device[], revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("devices:update", decodeDevices, cb);
}

export function onSessionsUpdate(cb: (payload: SessionsUpdatePayload, revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("sessions:update", decodeSessionsUpdate, cb);
}

export function onLibraryUpdate(cb: (library: LibraryEntry[], revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("library:update", decodeLibrary, cb);
}

export function onTransfersUpdate(cb: (transfers: Transfer[], revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("transfers:update", decodeTransfers, cb);
}

export function onPairingTick(cb: (payload: PairingTickPayload, revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("pairing:tick", decodePairingTickPayload, cb);
}

export function onPairingResolved(
  cb: (payload: PairingResolutionPayload, revision: number) => void,
): Promise<UnlistenFn> {
  return listenDecoded("pairing:resolved", decodePairingResolutionPayload, cb);
}

// All-or-nothing registration is transport-independent, so it lives in its own
// module and is shared with the in-memory backend; re-exported here because
// this module is the Tauri adapter's event surface.
export { subscribeAll, type EventRegistration, type Unsubscribe } from "./subscribeAll";

/** Real transfer-job progress, pushed by `composition.rs`'s background
 * `spawn_transfer_poll_loop` (`transfer_jobs:update`) — one entry per job
 * currently known to the real `TransferCoordinator`. */
export function onTransferJobsUpdate(cb: (jobs: TransferJobEvent[], revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("transfer_jobs:update", decodeTransferJobs, cb);
}

export function onStorageUpdate(cb: (storage: StorageConfig, revision: number) => void): Promise<UnlistenFn> {
  return listenDecoded("storage:update", decodeStorage, cb);
}
