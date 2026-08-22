// One selector for the whole transfer tray.
//
// The paused / failed / terminal rules used to be spelled out in four places:
// which rows are visible, how many are "进行中", what tone a row paints in, and
// which controls it offers. Each copy could — and did — disagree with the
// others: the combined counter called a desired-paused job active while the
// per-row renderer called it 已暂停.
//
// `selectTray` decides all four at once, from the same inputs, and hands back
// everything the tray needs. The renderers below it format what it decided;
// they no longer re-derive any of it.
//
// Controls carry branded identities (`ids.ts`), so a control cannot address the
// wrong kind of thing: `cancelUpload` only ever holds an `UploadJobId`. The DOM
// layer never re-brands a `data-key` by hand — it looks the control back up in
// the selection that rendered it (`findTrayCommand`).

import { asDownloadJobId, asUploadJobId, type DownloadJobId, type TransferRetryId, type UploadJobId } from "../ids";
import {
  transferJobIsTerminal,
  transferStateIsActive,
  transferStateIsFailed,
  transferStateIsTerminal,
  type Transfer,
  type TransferJobEvent,
  type TransferJobState,
} from "../types";

export type TrayTone = "active" | "paused" | "failed" | "done";

/** A backend command one tray control stands for, with the identity it
 * addresses already branded. */
export type TrayCommand =
  | { readonly kind: "retry"; readonly id: TransferRetryId }
  | { readonly kind: "pauseJob"; readonly jobId: DownloadJobId }
  | { readonly kind: "resumeJob"; readonly jobId: DownloadJobId }
  | { readonly kind: "cancelJob"; readonly jobId: DownloadJobId }
  | { readonly kind: "dismissJob"; readonly jobId: DownloadJobId }
  | { readonly kind: "cancelUpload"; readonly jobId: UploadJobId }
  | { readonly kind: "dismissUpload"; readonly jobId: UploadJobId };

/** The `data-action` names the rows render — unchanged, so the HTML is too. */
export type TrayActionName =
  | "retry-transfer"
  | "pause-transfer-job"
  | "resume-transfer-job"
  | "cancel-transfer-job"
  | "dismiss-transfer-job"
  | "cancel-upload"
  | "dismiss-upload";

export interface TrayControl {
  readonly action: TrayActionName;
  readonly label: string;
  /** The `data-key` attribute value; the raw id, escaped at render time. */
  readonly key: string;
  readonly command: TrayCommand;
}

export interface TrayJobItem {
  readonly kind: "job";
  readonly job: TransferJobEvent;
  readonly jobId: DownloadJobId;
  readonly tone: TrayTone;
  /** The desired run state is paused and the job has not settled. */
  readonly paused: boolean;
  readonly terminal: boolean;
  readonly countsActive: boolean;
  readonly controls: readonly TrayControl[];
}

export interface TrayTransferItem {
  readonly kind: "transfer";
  readonly transfer: Transfer;
  readonly tone: TrayTone;
  readonly countsActive: boolean;
  readonly controls: readonly TrayControl[];
}

export type TrayItem = TrayJobItem | TrayTransferItem;

export interface TraySelection {
  /** Visible rows in render order: coordinator jobs first, then transfers. */
  readonly items: readonly TrayItem[];
  readonly jobs: readonly TrayJobItem[];
  readonly transfers: readonly TrayTransferItem[];
  readonly activeCount: number;
  readonly failedCount: number;
  readonly countText: string;
  readonly open: boolean;
  readonly collapsed: boolean;
  /** A transfer-list read can fail independently of device/library data. */
  readonly resourceError: string | null;
  readonly resourceLoading: boolean;
}

export interface TrayResourceStatus {
  readonly error: string | null;
  readonly loading: boolean;
}

/* ---------------------------------------------------------------------- */
/* tone                                                                    */
/* ---------------------------------------------------------------------- */

/** A job's tone. `paused` is a separate input because the backend performs
 * no state transition when pausing a parked job: a paused job reports the same
 * `queued`/`waiting_*` state a never-started one does. Terminal jobs are
 * filtered before this value is derived, so stale desired state never reads
 * as paused. */
export function transferJobTone(state: TransferJobState, paused = false): TrayTone {
  if (state.state === "succeeded") return "done";
  if (state.state === "failed" || state.state === "cancelled") return "failed";
  return paused ? "paused" : "active";
}

/** Failed and cancelled terminal states remain failure-toned; a terminal
 * outcome must never be rendered as a successful completion. */
export function transferTone(transfer: Transfer): TrayTone {
  if (transferStateIsFailed(transfer.state)) return "failed";
  if (transfer.state === "succeeded") return "done";
  if (transfer.state === "cancelled") return "failed";
  if (transfer.state === "paused") return "paused";
  if (transfer.state === "finalizing") return "active";
  return "active";
}

/* ---------------------------------------------------------------------- */
/* controls                                                                */
/* ---------------------------------------------------------------------- */

/** A control the tray offers for one job. Each maps 1:1 onto a backend
 * command. */
export type TransferJobControl = "pause" | "resume" | "cancel" | "retry" | "dismiss";

/**
 * Which controls a job justifies, given its reported state and whether the
 * the desired run state is paused.
 *
 * Parked jobs (`queued`, `waiting_*`, `preparing`, `retry_wait`) cannot be
 * paused before work starts, so they offer cancellation only. A desired-paused
 * parked job is the exception: it offers resume/cancel when paused.
 * `paused_capture_active` is likewise device-paused and only offers cancel
 * unless the desired run state is also paused.
 */
export function transferJobControls(state: TransferJobState, paused: boolean): TransferJobControl[] {
  switch (state.state) {
    case "succeeded":
      return [];
    case "cancelled":
      return ["dismiss"];
    // Already tearing down; a second cancel or a pause would be a no-op.
    case "cancelling":
      return [];
    case "failed":
      return state.retryable ? ["retry", "dismiss"] : ["dismiss"];
    case "paused_capture_active":
      return paused ? ["resume", "cancel"] : ["cancel"];
    // A parked job has not begun work yet. There is nothing to pause, but a
    // desired-paused parked job still needs an explicit resume affordance.
    case "queued":
    case "waiting_for_device":
    case "waiting_for_pairing":
    case "preparing":
    case "retry_wait":
      return paused ? ["resume", "cancel"] : ["cancel"];
    default:
      return paused ? ["resume", "cancel"] : ["pause", "cancel"];
  }
}

function jobControl(control: TransferJobControl, jobId: DownloadJobId): TrayControl {
  switch (control) {
    case "pause":
      return { action: "pause-transfer-job", label: "暂停", key: jobId, command: { kind: "pauseJob", jobId } };
    case "resume":
      return { action: "resume-transfer-job", label: "继续", key: jobId, command: { kind: "resumeJob", jobId } };
    case "cancel":
      return { action: "cancel-transfer-job", label: "取消", key: jobId, command: { kind: "cancelJob", jobId } };
    case "retry":
      return { action: "retry-transfer", label: "重试", key: jobId, command: { kind: "retry", id: jobId } };
    case "dismiss":
      return { action: "dismiss-transfer-job", label: "清除", key: jobId, command: { kind: "dismissJob", jobId } };
  }
}

/* ---------------------------------------------------------------------- */
/* per-item selection                                                      */
/* ---------------------------------------------------------------------- */

export function selectJobItem(job: TransferJobEvent): TrayJobItem {
  const terminal = transferJobIsTerminal(job.state);
  const paused = job.desiredRunState === "paused" && !terminal;
  const tone = transferJobTone(job.state, paused);
  const jobId = asDownloadJobId(job.jobId);
  return {
    kind: "job",
    job,
    jobId,
    tone,
    paused,
    terminal,
    countsActive: tone === "active",
    controls: transferJobControls(job.state, paused).map((control) => jobControl(control, jobId)),
  };
}

export function selectTransferItem(transfer: Transfer): TrayTransferItem {
  const tone = transferTone(transfer);
  const key = transfer.key;
  const controls: TrayControl[] = [];
  if (transfer.state === "cancelled") {
    // A cancelled upload is terminal and can be removed from the activity
    // queue. Downloads have their own coordinator-job dismissal command.
    if (transfer.direction === "up") {
      const jobId = asUploadJobId(key);
      controls.push({ action: "dismiss-upload", label: "清除", key, command: { kind: "dismissUpload", jobId } });
    }
  } else if (transfer.state === "failed") {
    if (transfer.retryable) {
      const id: TransferRetryId = transfer.direction === "up" ? asUploadJobId(key) : asDownloadJobId(key);
      controls.push({ action: "retry-transfer", label: "重试", key, command: { kind: "retry", id } });
    }
    // Only uploads have a dismissible activity row of their own.
    if (transfer.direction === "up") {
      const jobId = asUploadJobId(key);
      controls.push({ action: "dismiss-upload", label: "清除", key, command: { kind: "dismissUpload", jobId } });
    }
  } else if (transfer.state === "finalizing") {
    // The upload outcome is durable, but its completion projection still has
    // to be acknowledged. Keep the row visible without offering cancellation
    // or retry while that bookkeeping converges.
  } else if (transfer.state === "cancelling") {
    // Cancellation is already in flight; do not offer a second request.
  } else if (transferStateIsActive(transfer.state) && transfer.direction === "up") {
    // Uploads are the one direction the backend can abort mid-flight.
    const jobId = asUploadJobId(key);
    controls.push({ action: "cancel-upload", label: "取消", key, command: { kind: "cancelUpload", jobId } });
  }
  return { kind: "transfer", transfer, tone, countsActive: transferStateIsActive(transfer.state), controls };
}

/* ---------------------------------------------------------------------- */
/* the selector                                                            */
/* ---------------------------------------------------------------------- */

export function selectTray(
  transfers: readonly Transfer[],
  jobs: readonly TransferJobEvent[],
  collapsed: boolean,
  resource: TrayResourceStatus = { error: null, loading: false },
): TraySelection {
  // A settled success retires itself; everything else stays until dismissed.
  const jobItems = jobs.filter((job) => job.state.state !== "succeeded").map(selectJobItem);
  // A successful transfer retires itself. Failed rows and cancelled uploads
  // remain visible until their explicit retry/dismiss action is handled;
  // cancelled downloads are represented by their coordinator job instead.
  const transferItems = transfers
    .filter(
      (transfer) =>
        !transferStateIsTerminal(transfer.state) ||
        transferStateIsFailed(transfer.state) ||
        (transfer.state === "cancelled" && transfer.direction === "up"),
    )
    .map(selectTransferItem);
  const items: TrayItem[] = [...jobItems, ...transferItems];

  const activeCount = items.filter((item) => item.countsActive).length;
  const failedCount = items.filter((item) => item.tone === "failed").length;

  return {
    items,
    jobs: jobItems,
    transfers: transferItems,
    activeCount,
    failedCount,
    countText:
      resource.error !== null
        ? "队列读取失败"
        : activeCount > 0
          ? `${activeCount} 项进行中`
          : failedCount > 0
            ? `${failedCount} 项失败或取消`
            : "全部完成",
    open: items.length > 0 || resource.error !== null,
    collapsed,
    resourceError: resource.error,
    resourceLoading: resource.loading,
  };
}

/** Resolves a clicked `data-action`/`data-key` pair back to the typed command
 * that rendered it. The DOM never invents an identity of its own. */
export function findTrayCommand(selection: TraySelection, action: string, key: string): TrayCommand | null {
  for (const item of selection.items) {
    for (const control of item.controls) {
      if (control.action === action && control.key === key) return control.command;
    }
  }
  return null;
}
