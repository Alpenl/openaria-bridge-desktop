// Runtime validation for the Tauri wire contract.
//
// TypeScript's `invoke<T>` generic only affects the compiler. The value at
// runtime is still JSON supplied by another process, so every response and
// event must be decoded before it can enter the reducer. These decoders are
// deliberately boring and explicit: an unknown enum or a missing field is a
// diagnostic failure, never a best-effort default.

import type {
  BatchItemResult,
  BatchJobItemResult,
  BatchJobResult,
  BatchOutcome,
  Device,
  DesiredRunState,
  DownloadedCleanupPreview,
  DownloadedCleanupResult,
  FailureCode,
  LibraryEntry,
  LibraryMutationResult,
  PairingResolutionPayload,
  PairingTickPayload,
  RpcError,
  SaveStorageConfigInput,
  SessionFile,
  SessionMutationResult,
  SessionView,
  StorageConfig,
  Transfer,
  TransferJobEvent,
  TransferJobState,
} from "../types";
import { RPC_ERROR_CODES, TRANSFER_STATES } from "../types";

export type Decoder<T> = (value: unknown, path?: string) => T;

export class RuntimeDecodeError extends Error {
  readonly path: string;
  readonly expected: string;
  readonly actual: string;

  constructor(path: string, expected: string, value: unknown) {
    const actual = describeValue(value);
    super(`Malformed backend payload at ${path}: expected ${expected}, got ${actual}`);
    this.name = "RuntimeDecodeError";
    this.path = path;
    this.expected = expected;
    this.actual = actual;
  }
}

function describeValue(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  switch (typeof value) {
    case "string":
      return "string";
    case "number":
      return Number.isFinite(value) ? "number" : "non-finite number";
    case "boolean":
      return "boolean";
    case "undefined":
      return "undefined";
    case "object":
      return "object";
    default:
      return typeof value;
  }
}

function fail(path: string, expected: string, value: unknown): never {
  throw new RuntimeDecodeError(path, expected, value);
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return fail(path, "object", value);
  return value as Record<string, unknown>;
}

function required<T>(value: Record<string, unknown>, key: string, decoder: Decoder<T>, path: string): T {
  if (!Object.prototype.hasOwnProperty.call(value, key)) return fail(`${path}.${key}`, "present value", undefined);
  return decoder(value[key], `${path}.${key}`);
}

function string(value: unknown, path = "payload"): string {
  if (typeof value !== "string") return fail(path, "string", value);
  return value;
}

function nonEmptyString(value: unknown, path = "payload"): string {
  const candidate = string(value, path);
  if (candidate.trim().length === 0) return fail(path, "non-empty string", value);
  return candidate;
}

const CANONICAL_DEVICE_ID = /^ylx-[0-9a-f]{64}$/;
const DEVICE_DISPLAY_ID = /^YLX-[0-9A-F]{8}$/;

function canonicalDeviceId(value: unknown, path = "payload"): string {
  const candidate = string(value, path);
  if (!CANONICAL_DEVICE_ID.test(candidate)) {
    return fail(path, "canonical ylx-<64 lowercase hex> device id", value);
  }
  return candidate;
}

function deviceDisplayId(value: unknown, path = "payload"): string {
  const candidate = string(value, path);
  if (!DEVICE_DISPLAY_ID.test(candidate)) return fail(path, "YLX-<8 uppercase hex> display id", value);
  return candidate;
}

function opaqueDeviceId(value: unknown, path = "payload"): string {
  const candidate = string(value, path);
  if (!CANONICAL_DEVICE_ID.test(candidate) && !DEVICE_DISPLAY_ID.test(candidate)) {
    return fail(path, "canonical ylx-<64 lowercase hex> or legacy YLX-<8 uppercase hex> device id", value);
  }
  return candidate;
}

function nullableString(value: unknown, path = "payload"): string | null {
  return value === null ? null : string(value, path);
}

function boolean(value: unknown, path = "payload"): boolean {
  if (typeof value !== "boolean") return fail(path, "boolean", value);
  return value;
}

function decodeDesiredRunState(value: unknown, path = "payload"): DesiredRunState {
  return oneOf(["run", "paused"] as const, value, path);
}

function finiteNumber(value: unknown, path = "payload"): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fail(path, "finite number", value);
  return value;
}

function nonNegativeNumber(value: unknown, path = "payload"): number {
  const result = finiteNumber(value, path);
  if (result < 0) return fail(path, "non-negative number", value);
  return result;
}

function nonNegativeSafeInteger(value: unknown, path = "payload"): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return fail(path, "non-negative safe integer", value);
  }
  return value;
}

/** Decode one Rust `u64` revision without allowing JavaScript number
 * rounding to manufacture or poison a reducer watermark. */
export function decodeRevision(value: unknown, path = "payload"): number {
  return nonNegativeSafeInteger(value, path);
}

function array<T>(value: unknown, decoder: Decoder<T>, path = "payload"): T[] {
  if (!Array.isArray(value)) return fail(path, "array", value);
  return value.map((item, index) => decoder(item, `${path}[${index}]`));
}

function oneOf<T extends string>(values: readonly T[], value: unknown, path: string): T {
  const candidate = string(value, path);
  if (!values.includes(candidate as T)) return fail(path, values.join(" | "), value);
  return candidate as T;
}

function decodeDevice(value: unknown, path = "payload"): Device {
  const item = object(value, path);
  return {
    id: required(item, "id", canonicalDeviceId, path),
    displayId: required(item, "displayId", deviceDisplayId, path),
    ip: required(item, "ip", nullableString, path),
    state: required(
      item,
      "state",
      (raw, field) => oneOf(["connected", "idle", "offline", "pending", "error"] as const, raw, field ?? path),
      path,
    ),
    lastSeen: required(item, "lastSeen", nullableString, path),
  };
}

function decodeSessionFile(value: unknown, path = "payload"): SessionFile {
  const item = object(value, path);
  return {
    fileId: required(item, "fileId", string, path),
    displayPath: required(item, "displayPath", string, path),
    bytes: required(item, "bytes", nonNegativeSafeInteger, path),
    sha256: required(item, "sha256", string, path),
  };
}

function decodeSessionView(value: unknown, path = "payload"): SessionView {
  const item = object(value, path);
  return {
    id: required(item, "id", string, path),
    revision: required(item, "revision", string, path),
    dateLabel: required(item, "dateLabel", string, path),
    durationSeconds: required(item, "durationSeconds", nonNegativeNumber, path),
    totalBytes: required(item, "totalBytes", nonNegativeSafeInteger, path),
    videoBytes: required(item, "videoBytes", nonNegativeSafeInteger, path),
    imuSamples: required(
      item,
      "imuSamples",
      (raw, field) => (raw === null ? null : nonNegativeSafeInteger(raw, field ?? path)),
      path,
    ),
    files: required(item, "files", (raw, field) => array(raw, decodeSessionFile, field ?? path), path),
    downloadStatus: required(
      item,
      "downloadStatus",
      (raw, field) => oneOf(["none", "downloading", "done", "failed"] as const, raw, field ?? path),
      path,
    ),
    backedUp: required(item, "backedUp", boolean, path),
  };
}

function decodeLibraryEntry(value: unknown, path = "payload"): LibraryEntry {
  const item = object(value, path);
  return {
    deviceId: required(item, "deviceId", opaqueDeviceId, path),
    deviceDisplayId: required(item, "deviceDisplayId", deviceDisplayId, path),
    sessionId: required(item, "sessionId", string, path),
    dateLabel: required(item, "dateLabel", string, path),
    downloadedAt: required(item, "downloadedAt", string, path),
    bytes: required(item, "bytes", nonNegativeSafeInteger, path),
    files: required(item, "files", (raw, field) => array(raw, decodeSessionFile, field ?? path), path),
    complete: required(item, "complete", boolean, path),
    uploadStatus: required(
      item,
      "uploadStatus",
      (raw, field) => oneOf(["none", "uploading", "done", "failed"] as const, raw, field ?? path),
      path,
    ),
    uploadedAt: required(item, "uploadedAt", nullableString, path),
    uploadError: required(item, "uploadError", nullableString, path),
    uploadRetryable: required(item, "uploadRetryable", boolean, path),
  };
}

function decodeStorageConfig(value: unknown, path = "payload"): StorageConfig {
  const item = object(value, path);
  return {
    endpoint: required(item, "endpoint", string, path),
    bucket: required(item, "bucket", string, path),
    prefix: required(item, "prefix", string, path),
    urlStyle: required(
      item,
      "urlStyle",
      (raw, field) => oneOf(["virtualHost", "path"] as const, raw, field ?? path),
      path,
    ),
    secretConfigured: required(item, "secretConfigured", boolean, path),
    downloadRoot: required(item, "downloadRoot", string, path),
    activeDownloadRoot: required(item, "activeDownloadRoot", string, path),
  };
}

function decodeTransfer(value: unknown, path = "payload"): Transfer {
  const item = object(value, path);
  // Do not silently accept the retired four-boolean DTO. A mixed payload is
  // almost certainly an older backend talking to a newer UI and must fail
  // closed instead of allowing two competing state authorities in memory.
  for (const legacyField of ["done", "failed", "queued", "resumed"] as const) {
    if (Object.prototype.hasOwnProperty.call(item, legacyField)) {
      return fail(`${path}.${legacyField}`, "retired field to be absent", item[legacyField]);
    }
  }
  return {
    key: required(item, "key", string, path),
    label: required(item, "label", string, path),
    totalBytes: required(item, "totalBytes", nonNegativeSafeInteger, path),
    sentBytes: required(item, "sentBytes", nonNegativeSafeInteger, path),
    state: required(item, "state", (raw, field) => oneOf(TRANSFER_STATES, raw, field ?? path), path),
    retryable: required(item, "retryable", boolean, path),
    error: required(item, "error", nullableString, path),
    direction: required(item, "direction", (raw, field) => oneOf(["down", "up"] as const, raw, field ?? path), path),
    targetLabel: required(item, "targetLabel", string, path),
  };
}

function decodeFailureCode(value: unknown, path = "payload"): FailureCode {
  if (typeof value === "string") {
    return oneOf(
      ["network", "disk_full", "hash_mismatch", "object_store_rejected", "device_heartbeat_failed"] as const,
      value,
      path,
    );
  }
  const item = object(value, path);
  return { other: required(item, "other", string, path) };
}

function decodeTransferJobState(value: unknown, path = "payload"): TransferJobState {
  const item = object(value, path);
  const state = required(item, "state", string, path);
  switch (state) {
    case "queued":
    case "waiting_for_device":
    case "waiting_for_pairing":
    case "paused_capture_active":
    case "preparing":
    case "transferring":
    case "verifying":
    case "committing":
    case "retry_wait":
    case "cancelling":
    case "succeeded":
    case "cancelled":
      return { state };
    case "failed":
      return {
        state,
        code: required(item, "code", decodeFailureCode, path),
        retryable: required(item, "retryable", boolean, path),
      };
    default:
      return fail(`${path}.state`, "known transfer job state", state);
  }
}

function decodeTransferJob(value: unknown, path = "payload"): TransferJobEvent {
  const item = object(value, path);
  if (Object.prototype.hasOwnProperty.call(item, "userPaused")) {
    return fail(`${path}.userPaused`, "retired field to be absent", item.userPaused);
  }
  const deviceId = required(
    item,
    "deviceId",
    (raw, field) => (raw === null ? null : opaqueDeviceId(raw, field ?? path)),
    path,
  );
  const displayId = required(
    item,
    "deviceDisplayId",
    (raw, field) => (raw === null ? null : deviceDisplayId(raw, field ?? path)),
    path,
  );
  if ((deviceId === null) !== (displayId === null)) {
    return fail(`${path}.deviceDisplayId`, "null exactly when deviceId is null", item.deviceDisplayId);
  }
  return {
    jobId: required(item, "jobId", string, path),
    state: required(item, "state", decodeTransferJobState, path),
    sessionId: required(item, "sessionId", nullableString, path),
    deviceId,
    deviceDisplayId: displayId,
    totalBytes: required(item, "totalBytes", nonNegativeSafeInteger, path),
    transferredBytes: required(item, "transferredBytes", nonNegativeSafeInteger, path),
    filesTotal: required(item, "filesTotal", nonNegativeSafeInteger, path),
    filesDone: required(item, "filesDone", nonNegativeSafeInteger, path),
    desiredRunState: required(item, "desiredRunState", decodeDesiredRunState, path),
  };
}

function rejectLegacyBatchArrays(value: Record<string, unknown>, path: string): void {
  for (const key of ["succeeded", "failures", "jobIds"] as const) {
    if (Object.prototype.hasOwnProperty.call(value, key))
      fail(`${path}.${key}`, "absent legacy batch field", value[key]);
  }
}

function decodeRpcError(value: unknown, path = "payload"): RpcError {
  const item = object(value, path);
  const error: RpcError = {
    code: required(item, "code", (raw, field) => oneOf(RPC_ERROR_CODES, raw, field ?? path), path),
    message: required(item, "message", nonEmptyString, path),
    retryable: required(item, "retryable", boolean, path),
  };
  if (Object.prototype.hasOwnProperty.call(item, "details")) {
    error.details = object(item.details, `${path}.details`);
  }
  return error;
}

function decodeBatchItemResult(value: unknown, path = "payload"): BatchItemResult {
  const item = object(value, path);
  const status = required(
    item,
    "status",
    (raw, field) => oneOf(["success", "failure"] as const, raw, field ?? path),
    path,
  );
  const itemId = required(item, "item", nonEmptyString, path);
  if (Object.prototype.hasOwnProperty.call(item, "jobId")) {
    return fail(`${path}.jobId`, "absent for a mutation result", item.jobId);
  }
  if (status === "success") {
    if (Object.prototype.hasOwnProperty.call(item, "error")) {
      return fail(`${path}.error`, "absent for a successful result", item.error);
    }
    return { status, item: itemId };
  }
  return { status, item: itemId, error: required(item, "error", decodeRpcError, path) };
}

function decodeBatchJobItemResult(value: unknown, path = "payload"): BatchJobItemResult {
  const item = object(value, path);
  const status = required(
    item,
    "status",
    (raw, field) => oneOf(["success", "failure"] as const, raw, field ?? path),
    path,
  );
  const itemId = required(item, "item", nonEmptyString, path);
  if (status === "success") {
    if (Object.prototype.hasOwnProperty.call(item, "error")) {
      return fail(`${path}.error`, "absent for a successful result", item.error);
    }
    return { status, item: itemId, jobId: required(item, "jobId", nonEmptyString, path) };
  }
  if (Object.prototype.hasOwnProperty.call(item, "jobId")) {
    return fail(`${path}.jobId`, "absent for a failed result", item.jobId);
  }
  return { status, item: itemId, error: required(item, "error", decodeRpcError, path) };
}

function decodeBatchOutcome(value: unknown, path = "payload"): BatchOutcome {
  const item = object(value, path);
  rejectLegacyBatchArrays(item, path);
  return {
    results: required(item, "results", (raw, field) => array(raw, decodeBatchItemResult, field ?? path), path),
  };
}

function decodeBatchJobResult(value: unknown, path = "payload"): BatchJobResult {
  const item = object(value, path);
  rejectLegacyBatchArrays(item, path);
  return {
    results: required(item, "results", (raw, field) => array(raw, decodeBatchJobItemResult, field ?? path), path),
  };
}

function decodeSessionMutation(value: unknown, path = "payload"): SessionMutationResult {
  const item = object(value, path);
  return {
    ...decodeBatchOutcome(value, path),
    sessions: required(
      item,
      "sessions",
      (raw, field) => (raw === null ? null : array(raw, decodeSessionView, field ?? path)),
      path,
    ),
    operationError: required(
      item,
      "operationError",
      (raw, field) => (raw === null ? null : decodeRpcError(raw, field ?? path)),
      path,
    ),
  };
}

function decodeLibraryMutation(value: unknown, path = "payload"): LibraryMutationResult {
  const item = object(value, path);
  return {
    ...decodeBatchOutcome(value, path),
    library: required(item, "library", (raw, field) => array(raw, decodeLibraryEntry, field ?? path), path),
  };
}

function decodeDownloadedCleanupItem(value: unknown, path = "payload"): DownloadedCleanupPreview["eligible"][number] {
  const item = object(value, path);
  return {
    sessionId: required(item, "sessionId", string, path),
    dateLabel: required(item, "dateLabel", string, path),
    bytes: required(item, "bytes", nonNegativeSafeInteger, path),
  };
}

function decodeDownloadedCleanupSkip(value: unknown, path = "payload"): DownloadedCleanupPreview["skipped"][number] {
  const item = object(value, path);
  return {
    ...decodeDownloadedCleanupItem(value, path),
    reason: required(item, "reason", string, path),
  };
}

function decodeDownloadedCleanupFailure(value: unknown, path = "payload"): DownloadedCleanupResult["failed"][number] {
  const item = object(value, path);
  return {
    sessionId: required(item, "sessionId", string, path),
    error: required(item, "error", decodeRpcError, path),
  };
}

function decodeDownloadedCleanupPreview(value: unknown, path = "payload"): DownloadedCleanupPreview {
  const item = object(value, path);
  return {
    eligible: required(item, "eligible", (raw, field) => array(raw, decodeDownloadedCleanupItem, field ?? path), path),
    skipped: required(item, "skipped", (raw, field) => array(raw, decodeDownloadedCleanupSkip, field ?? path), path),
    eligibleBytes: required(item, "eligibleBytes", nonNegativeSafeInteger, path),
  };
}

function decodeDownloadedCleanup(value: unknown, path = "payload"): DownloadedCleanupResult {
  const item = object(value, path);
  return {
    eligible: required(item, "eligible", (raw, field) => array(raw, decodeDownloadedCleanupItem, field ?? path), path),
    deleted: required(item, "deleted", (raw, field) => array(raw, decodeDownloadedCleanupItem, field ?? path), path),
    failed: required(item, "failed", (raw, field) => array(raw, decodeDownloadedCleanupFailure, field ?? path), path),
    skipped: required(item, "skipped", (raw, field) => array(raw, decodeDownloadedCleanupSkip, field ?? path), path),
    sessions: required(item, "sessions", (raw, field) => array(raw, decodeSessionView, field ?? path), path),
  };
}

function decodePairingTick(value: unknown, path = "payload"): PairingTickPayload {
  const item = object(value, path);
  return {
    deviceId: required(item, "deviceId", canonicalDeviceId, path),
    attemptId: required(item, "attemptId", string, path),
    remaining: required(item, "remaining", nonNegativeSafeInteger, path),
    total: required(item, "total", nonNegativeSafeInteger, path),
  };
}

function decodePairingResolution(value: unknown, path = "payload"): PairingResolutionPayload {
  const item = object(value, path);
  return {
    deviceId: required(item, "deviceId", canonicalDeviceId, path),
    attemptId: required(item, "attemptId", string, path),
    outcome: required(
      item,
      "outcome",
      (raw, field) => oneOf(["connected", "rejected", "expired", "failed"] as const, raw, field ?? path),
      path,
    ),
    error: required(item, "error", nullableString, path),
  };
}

export function decodeVoid(value: unknown, path = "payload"): void {
  // serde's unit is `null`; Tauri's mock and some versions of the API use
  // `undefined`. Both are valid, but any actual value is a contract error.
  if (value !== null && value !== undefined) fail(path, "null or undefined", value);
}

export function decodeBoolean(value: unknown, path = "payload"): boolean {
  return boolean(value, path);
}

export function decodeString(value: unknown, path = "payload"): string {
  return string(value, path);
}

export function decodeNullableString(value: unknown, path = "payload"): string | null {
  return nullableString(value, path);
}

export const decodeDevices: Decoder<Device[]> = (value, path = "payload") => array(value, decodeDevice, path);
export const decodeDeviceValue: Decoder<Device> = decodeDevice;
export const decodeDeviceList: Decoder<Device[]> = decodeDevices;
export const decodeSessions: Decoder<SessionView[]> = (value, path = "payload") =>
  array(value, decodeSessionView, path);
export const decodeLibrary: Decoder<LibraryEntry[]> = (value, path = "payload") =>
  array(value, decodeLibraryEntry, path);
export const decodeTransfers: Decoder<Transfer[]> = (value, path = "payload") => array(value, decodeTransfer, path);
export const decodeTransferJobs: Decoder<TransferJobEvent[]> = (value, path = "payload") =>
  array(value, decodeTransferJob, path);
export const decodeStorage: Decoder<StorageConfig> = decodeStorageConfig;
export const decodeRpcErrorValue: Decoder<RpcError> = decodeRpcError;
export const decodeBatch: Decoder<BatchOutcome> = decodeBatchOutcome;
export const decodeBatchJobs: Decoder<BatchJobResult> = decodeBatchJobResult;
export const decodeSessionMutationResult: Decoder<SessionMutationResult> = decodeSessionMutation;
export const decodeLibraryMutationResult: Decoder<LibraryMutationResult> = decodeLibraryMutation;
export const decodeCleanupPreview: Decoder<DownloadedCleanupPreview> = decodeDownloadedCleanupPreview;
export const decodeCleanupResult: Decoder<DownloadedCleanupResult> = decodeDownloadedCleanup;
export const decodePairingTickPayload: Decoder<PairingTickPayload> = decodePairingTick;
export const decodePairingResolutionPayload: Decoder<PairingResolutionPayload> = decodePairingResolution;
export const decodeSessionsUpdate = (value: unknown, path = "payload") => {
  const item = object(value, path);
  return {
    deviceId: required(item, "deviceId", canonicalDeviceId, path),
    sessions: required(item, "sessions", decodeSessions, path),
  };
};

/** Validates write-only settings before they are sent over IPC. */
export function decodeSaveStorageConfigInput(value: unknown, path = "payload"): SaveStorageConfigInput {
  const item = object(value, path);
  return {
    endpoint: required(item, "endpoint", string, path),
    bucket: required(item, "bucket", string, path),
    prefix: required(item, "prefix", string, path),
    urlStyle: required(
      item,
      "urlStyle",
      (raw, field) => oneOf(["virtualHost", "path"] as const, raw, field ?? path),
      path,
    ),
    accessKey: required(item, "accessKey", string, path),
    secretKey: required(item, "secretKey", string, path),
    downloadRoot: required(item, "downloadRoot", string, path),
  };
}

/** Event decoder used by tests and by the transport adapter. */
export const eventDecoders = {
  devices: decodeDevices,
  sessions: decodeSessionsUpdate,
  library: decodeLibrary,
  transfers: decodeTransfers,
  storage: decodeStorage,
  transferJobs: decodeTransferJobs,
  pairingTick: decodePairingTickPayload,
  pairingResolved: decodePairingResolutionPayload,
} as const;

export type DecodedEventPayload<K extends keyof typeof eventDecoders> = ReturnType<(typeof eventDecoders)[K]>;

/** Decode an event payload by its public event kind. Unknown kinds fail closed. */
export function decodeEventPayload(kind: string, value: unknown, path = "payload"): unknown {
  if (!Object.prototype.hasOwnProperty.call(eventDecoders, kind)) {
    return fail(`${path}.kind`, "known event kind", kind);
  }
  const decoder = eventDecoders[kind as keyof typeof eventDecoders];
  return decoder(value, path);
}
