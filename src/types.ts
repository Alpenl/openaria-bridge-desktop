// Mirrors src-tauri/src/models.rs — keep these two in sync by hand for now.
// (A codegen step, e.g. ts-rs, would be a reasonable v2 addition once the
// shapes stop moving every review round.)
//
// These are wire DTOs, so their id fields stay plain `string`: they are exactly
// what serde produced. Identities are branded (see `ids.ts`) the moment a value
// crosses out of the transport adapter into the app.

import { libraryKeyOf, type LibraryKey } from "./ids";

export type DeviceState = "connected" | "idle" | "offline" | "pending" | "error";

export interface Device {
  /** Canonical full-fingerprint identity: `ylx-` plus 64 lowercase hex. */
  id: string;
  /** Human-facing projection: `YLX-` plus the first 8 uppercase hex. */
  displayId: string;
  ip: string | null;
  state: DeviceState;
  lastSeen: string | null;
}

export interface SessionFile {
  /** Opaque Pi API identifier; never used as the filename for new downloads. */
  fileId: string;
  /** Signed Pi-relative path retained as the local directory and filename. */
  displayPath: string;
  bytes: number;
  sha256: string;
}

export interface Session {
  id: string;
  revision: string;
  dateLabel: string;
  durationSeconds: number;
  totalBytes: number;
  videoBytes: number;
  imuSamples: number | null;
  files: SessionFile[];
}

export type DownloadStatus = "none" | "downloading" | "done" | "failed";
export type UploadStatus = "none" | "uploading" | "done" | "failed";

/** `Session` plus derived per-row state — what `list_sessions` actually returns. */
export interface SessionView extends Session {
  downloadStatus: DownloadStatus;
  backedUp: boolean;
  /** Exact gateway verification evidence carried by the device catalog. A
   * missing verification is represented by explicit `null`, never omission. */
  verification: SessionVerification | null;
}

export type SessionVerificationDiagnostic = string | { code: string; summary: string };

export interface SessionValidatorIdentity {
  name: string;
  version: string;
  buildSha256: string;
}

export interface SessionVerification {
  verdict: "usable" | "unusable";
  actor: string;
  validator: SessionValidatorIdentity;
  manifestSha256: string;
  verifiedAt: string;
  diagnostics: SessionVerificationDiagnostic[];
}

const BARE_LOWERCASE_SHA256 = /^[0-9a-f]{64}$/;

/** UI eligibility only. The backend independently re-verifies every detail
 * and download request; this helper merely prevents an ineligible row from
 * offering an action in the first place. A nominally usable verdict with a
 * malformed manifest digest remains visible but fails closed here. */
export function sessionHasUsableVerification(session: Pick<SessionView, "verification"> | null | undefined): boolean {
  const verification = session?.verification;
  return (
    verification !== null &&
    verification !== undefined &&
    verification.verdict === "usable" &&
    BARE_LOWERCASE_SHA256.test(verification.manifestSha256)
  );
}

export type CapabilitySource = "deviceDescriptor" | "profileContract" | "unavailable";

/** One negotiated Device API capability. The source is retained so the UI
 * never has to infer support from incidental response data. */
export interface DeviceCapability {
  supported: boolean;
  source: CapabilitySource;
}

export interface SessionCapabilities {
  profile: "legacyPinnedTlsV1" | "labHttpV4" | "unknown";
  sessionDeletion: DeviceCapability;
  sessionDetail: DeviceCapability;
  artifactDownload: DeviceCapability;
  captureStatus: DeviceCapability;
}

export type SessionCatalogAuthority = "deviceSnapshot" | "unavailable";
export type SessionPaginationUnavailableReason = "catalogRevisionUnavailable";

/** One quarantined catalog record reported by the device adapter. Only
 * `message` is intended for display; the remaining fields are correlation
 * evidence and never grant an operation capability. */
export interface SessionCatalogDiagnostic {
  quarantineId: string;
  code: string;
  observedAt: string;
  message: string;
}

/** One bounded page of session summaries. `nextCursor` is opaque and must be
 * returned to the backend unchanged together with a non-null
 * `catalogRevision`. A revisionless compatibility page is first-page only. */
export interface SessionPageView {
  items: SessionView[];
  nextCursor: string | null;
  hasMore: boolean;
  catalogRevision: string | null;
  catalogAuthority: SessionCatalogAuthority;
  paginationSupported: boolean;
  paginationUnavailableReason: SessionPaginationUnavailableReason | null;
  capabilities: SessionCapabilities;
  diagnostics: SessionCatalogDiagnostic[];
}

export interface LibraryEntry {
  /** New writes use the canonical identity; reads may retain a legacy
   * `YLX-<8 uppercase hex>` identity for offline rows. */
  deviceId: string;
  /** Persisted human-facing source-device label for offline library rows. */
  deviceDisplayId: string;
  sessionId: string;
  dateLabel: string;
  downloadedAt: string;
  bytes: number;
  files: SessionFile[];
  complete: boolean;
  uploadStatus: UploadStatus;
  uploadedAt: string | null;
  uploadError: string | null;
  /** Whether a failed upload has an explicit durable retry authorization. */
  uploadRetryable: boolean;
}

/** A library row is eligible for a user-triggered upload when it is new or
 * when its terminal failure explicitly authorizes another attempt. */
export function libraryEntryCanUpload(entry: Pick<LibraryEntry, "uploadStatus" | "uploadRetryable">): boolean {
  return entry.uploadStatus !== "failed" || entry.uploadRetryable;
}

/** Stable machine-readable codes emitted by the Rust RPC boundary. Unknown
 * codes are protocol drift and fail runtime decoding. */
export const RPC_ERROR_CODES = [
  "invalid_input",
  "application_unavailable",
  "sink_poisoned",
  "event_delivery_failed",
  "serialization_failed",
  "device_list_failed",
  "device_connect_failed",
  "pairing_cancel_failed",
  "manual_device_add_failed",
  "device_disconnect_failed",
  "session_list_failed",
  "session_catalog_changed",
  "session_detail_failed",
  "session_batch_failed",
  "session_not_found",
  "session_delete_failed",
  "session_refresh_failed",
  "cleanup_catalog_unavailable",
  "downloaded_cleanup_preview_failed",
  "downloaded_cleanup_failed",
  "downloaded_cleanup_delete_failed",
  "library_list_failed",
  "library_batch_failed",
  "library_delete_busy",
  "library_delete_failed",
  "library_reveal_failed",
  "transfer_list_failed",
  "download_enqueue_failed",
  "upload_enqueue_failed",
  "transfer_retry_failed",
  "transfer_pause_failed",
  "transfer_resume_failed",
  "transfer_cancel_failed",
  "transfer_dismiss_failed",
  "upload_cancel_failed",
  "upload_dismiss_failed",
  "storage_config_read_failed",
  "download_root_selection_failed",
  "download_root_validation_failed",
  "download_root_save_failed",
  "storage_config_save_failed",
  "storage_connection_test_failed",
  "notification_update_failed",
] as const;

export type RpcErrorCode = (typeof RPC_ERROR_CODES)[number];

/** Stable machine-readable failure returned across the RPC boundary. */
export interface RpcError {
  code: RpcErrorCode;
  message: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}

export type BatchItemResult =
  { status: "success"; item: string } | { status: "failure"; item: string; error: RpcError };

export type BatchJobItemResult =
  { status: "success"; item: string; jobId: string } | { status: "failure"; item: string; error: RpcError };

export interface BatchOutcome {
  results: BatchItemResult[];
}

export interface BatchJobResult {
  results: BatchJobItemResult[];
}

export interface SessionMutationResult extends BatchOutcome {
  sessions: SessionView[] | null;
  operationError: RpcError | null;
}

export interface DownloadedCleanupItem {
  sessionId: string;
  dateLabel: string;
  bytes: number;
}

export interface DownloadedCleanupSkipDetail extends DownloadedCleanupItem {
  reason: string;
}

export interface DownloadedCleanupFailure {
  sessionId: string;
  error: RpcError;
}

export interface DownloadedCleanupPreview {
  eligible: DownloadedCleanupItem[];
  skipped: DownloadedCleanupSkipDetail[];
  eligibleBytes: number;
}

export interface DownloadedCleanupResult {
  eligible: DownloadedCleanupItem[];
  deleted: DownloadedCleanupItem[];
  failed: DownloadedCleanupFailure[];
  skipped: DownloadedCleanupSkipDetail[];
  sessions: SessionView[];
}

export interface LibraryMutationResult extends BatchOutcome {
  library: LibraryEntry[];
}

export type TransferDirection = "down" | "up";

/** Lifecycle values emitted by Rust's `TransferState` enum.
 *
 * This is a plain serde enum, so the wire value is one snake_case string (not
 * an object with a nested `state` field). Keeping the values in one tuple lets
 * the runtime decoder and any test fixtures share the exact contract. */
export const TRANSFER_STATES = [
  "queued",
  "preparing",
  "finalizing",
  "running",
  "paused",
  "cancelling",
  "succeeded",
  "failed",
  "cancelled",
] as const;

export type TransferState = (typeof TRANSFER_STATES)[number];

export interface Transfer {
  key: string;
  label: string;
  totalBytes: number;
  sentBytes: number;
  state: TransferState;
  /** Whether a terminal failure is eligible for a new attempt. The backend
   * keeps this false for successful, cancelled, and non-retryable rows. */
  retryable: boolean;
  error: string | null;
  direction: TransferDirection;
  targetLabel: string;
}

/** Finalizing is visible projection work, so only settled outcomes are
 * terminal from the UI's point of view. */
export function transferStateIsTerminal(state: TransferState): boolean {
  return state === "succeeded" || state === "failed" || state === "cancelled";
}

/** Every non-terminal state remains active in the durable lifecycle. A paused
 * transfer is still recoverable work and must remain in the active queue. */
export function transferStateIsActive(state: TransferState): boolean {
  return !transferStateIsTerminal(state);
}

export function transferStateIsFailed(state: TransferState): boolean {
  return state === "failed";
}

/** Returns a clamped display percentage, or `null` when the backend has not
 * reported a total yet. The renderer must not fabricate progress in that case. */
export function transferProgress(transfer: Pick<Transfer, "totalBytes" | "sentBytes">): number | null {
  if (transfer.totalBytes <= 0) return null;
  return Math.min(100, Math.max(0, Math.round((transfer.sentBytes / transfer.totalBytes) * 100)));
}

/** The optional backend error is orthogonal to lifecycle state. Rust uses it
 * for failed and cancelled outcomes, so callers should use this helper rather
 * than reading the wire field directly. */
export function transferError(transfer: Pick<Transfer, "state" | "error">): string | null {
  return transfer.error;
}

/** Convenience aliases for callers that prefer a value-oriented name. */
export function transferIsTerminal(transfer: Pick<Transfer, "state">): boolean {
  return transferStateIsTerminal(transfer.state);
}

export function transferIsActive(transfer: Pick<Transfer, "state">): boolean {
  return transferStateIsActive(transfer.state);
}

// Mirrors src-tauri/crates/ylx-transfer-core/src/transfer/mod.rs's
// `TransferJobState`/`FailureCode` — the real per-job state the
// `TransferCoordinator` background poll loop pushes out as
// `transfer_jobs:update` (see composition.rs's `JobStateEvent`). Rust's
// `#[serde(tag = "state", rename_all = "snake_case")]` puts the variant
// name in a `state` field alongside `Failed`'s `code`/`retryable`
// payload; `FailureCode` itself is plainly-tagged, so its `Other(String)`
// variant serializes as `{ other: string }` while every other variant is
// just its snake_case name.
export type FailureCode =
  "network" | "disk_full" | "hash_mismatch" | "object_store_rejected" | "device_heartbeat_failed" | { other: string };

/** Durable user intent for a transfer job. This is independent of the
 * execution state: a parked job can remain `queued` while its desired run
 * state is `paused`, and that intent survives coordinator restart. Mirrors
 * `ylx_transfer_core::transfer::DesiredRunState`. */
export type DesiredRunState = "run" | "paused";

export type TransferJobState =
  | { state: "queued" }
  | { state: "waiting_for_device" }
  | { state: "waiting_for_pairing" }
  | { state: "paused_capture_active" }
  | { state: "preparing" }
  | { state: "transferring" }
  | { state: "verifying" }
  | { state: "committing" }
  | { state: "retry_wait" }
  | { state: "cancelling" }
  | { state: "succeeded" }
  | { state: "failed"; code: FailureCode; retryable: boolean }
  | { state: "cancelled" };

/** One entry of a `transfer_jobs:update` event payload — mirrors
 * composition.rs's `JobStateEvent` (`#[serde(rename_all = "camelCase")]`).
 *
 * `sessionId`/`deviceId` are Pi-supplied strings (session_id / device
 * fingerprint per pi_http.rs) and are null for jobs the coordinator has not
 * yet resolved to a session — treat both as untrusted when rendering.
 * `totalBytes` is 0 while the job's manifest is still unknown, which is the
 * only honest signal that no percentage can be computed yet. */
export interface TransferJobEvent {
  jobId: string;
  state: TransferJobState;
  desiredRunState: DesiredRunState;
  sessionId: string | null;
  /** New jobs use the canonical identity; durable legacy jobs may retain a
   * `YLX-<8 uppercase hex>` identity while they are resolved. */
  deviceId: string | null;
  /** Human-facing source-device projection; null only while the job is unresolved. */
  deviceDisplayId: string | null;
  totalBytes: number;
  transferredBytes: number;
  filesTotal: number;
  filesDone: number;
}

export function transferJobIsTerminal(state: TransferJobState): boolean {
  return state.state === "succeeded" || state.state === "failed" || state.state === "cancelled";
}

/** `get_storage_config`'s response shape. The raw secret never round-trips
 * to the frontend — only whether one is already set. `downloadRoot` is the
 * local directory downloads land in; an empty string means "use the platform
 * default". A saved change applies to new downloads in the running app. */
/** How the S3-compatible endpoint is addressed. Not cosmetic: Aliyun OSS
 * rejects `path` outright before any signature check, while MinIO and most
 * self-hosted servers only work with `path`. Mirrors `StorageUrlStyle` in
 * src-tauri/src/models.rs. */
export type StorageUrlStyle = "virtualHost" | "path";

export interface StorageConfig {
  endpoint: string;
  bucket: string;
  prefix: string;
  urlStyle: StorageUrlStyle;
  secretConfigured: boolean;
  downloadRoot: string;
  /** Directory currently used by new downloads in this process. */
  activeDownloadRoot: string;
}

/** `save_storage_config`'s input shape. `accessKey`/`secretKey` are
 * write-only: an empty string means "leave the vault's existing secret
 * untouched" (see src-tauri/src/models.rs's `SaveStorageConfigInput` doc).
 * `downloadRoot` is not write-only — an empty string really does mean
 * "fall back to the default download directory". */
export interface SaveStorageConfigInput {
  endpoint: string;
  bucket: string;
  prefix: string;
  urlStyle: StorageUrlStyle;
  accessKey: string;
  secretKey: string;
  downloadRoot: string;
}

/** Mirrors composition.rs's `pairing:tick` payload. `attemptId` names the
 * pairing attempt `connect_device` returned — a tick for any other attempt
 * belongs to a superseded flow and must be ignored. */
export interface PairingTickPayload {
  deviceId: string;
  attemptId: string;
  remaining: number;
  total: number;
}

/** Mirrors composition.rs's `PairingResolutionEvent`. As with ticks, only a
 * resolution carrying the attempt id this UI is currently showing may close
 * (or label) the pairing overlay. */
export interface PairingResolutionPayload {
  deviceId: string;
  attemptId: string;
  outcome: "connected" | "rejected" | "expired" | "failed";
  error: string | null;
}

export function libraryEntryKey(entry: LibraryEntry): LibraryKey {
  return libraryKeyOf(entry.deviceId, entry.sessionId);
}

export function storageConfigured(config: StorageConfig): boolean {
  return config.endpoint.trim() !== "" && config.bucket.trim() !== "" && config.secretConfigured;
}
