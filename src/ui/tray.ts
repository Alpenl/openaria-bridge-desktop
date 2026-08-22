// Tray row rendering. Every paused/failed/terminal decision is made by
// `traySelector.ts`; this module only formats what the selector decided, so
// there is exactly one place those rules live.

import { escapeAttr, escapeHtml, formatBytes } from "../format";
import {
  selectJobItem,
  selectTransferItem,
  selectTray,
  type TrayControl,
  type TrayJobItem,
  type TrayTransferItem,
} from "./traySelector";
import { transferError, transferProgress, type Transfer, type TransferJobEvent, type TransferJobState } from "../types";

export function transferJobCountText(jobs: readonly TransferJobEvent[]): string {
  return selectTray([], jobs, false).countText;
}

function controlsRowHtml(controls: readonly TrayControl[]): string {
  if (controls.length === 0) return "";
  return (
    `<div style="display:flex;justify-content:flex-end;gap:6px;">` +
    controls
      .map(
        (control) =>
          `<button class="btn btn-sm btn-ghost" data-action="${control.action}" data-key="${escapeAttr(control.key)}">${control.label}</button>`,
      )
      .join("") +
    `</div>`
  );
}

export function transferItemHtml(transfer: Transfer, item: TrayTransferItem = selectTransferItem(transfer)): string {
  // `t.label` (a session id) and `t.error` ultimately trace back to
  // Pi-controlled data (session_id from pi_http.rs's `SessionSummary`, and
  // download/upload error text that can embed Pi-derived strings via
  // `classify_download_error`/object-store errors -- see composition.rs).
  // `t.key`/`t.targetLabel` are locally generated today, but are escaped too
  // as cheap defense-in-depth.
  const t = transfer;
  const pct = transferProgress(t);
  const arrow = t.direction === "up" ? "↑" : "↓";
  const labelText = escapeHtml(t.label);
  const errorText = escapeHtml(transferError(t) ?? "");
  const targetLabelText = escapeHtml(t.targetLabel);

  let statsText: string;
  if (t.state === "queued") {
    statsText = "排队中…";
  } else if (t.state === "finalizing") {
    statsText =
      pct === null
        ? `收尾中… · ${targetLabelText}`
        : `收尾中… · ${pct}% · ${formatBytes(t.sentBytes)} / ${formatBytes(t.totalBytes)} · ${targetLabelText}`;
  } else if (item.tone === "failed") {
    const label = t.state === "cancelled" ? "已取消" : "失败";
    const detail = errorText === "" ? "" : ` · ${errorText}`;
    statsText = `<span style="color:var(--danger-500);">${pct === null ? label : `${label}于 ${pct}%`}${detail}</span>`;
  } else if (item.tone === "done") {
    statsText = `已完成 · ${formatBytes(t.totalBytes)} · ${targetLabelText}`;
  } else if (item.tone === "paused") {
    statsText =
      pct === null
        ? `已暂停 · ${targetLabelText}`
        : `已暂停 · ${pct}% · ${formatBytes(t.sentBytes)} / ${formatBytes(t.totalBytes)} · ${targetLabelText}`;
  } else {
    const phase = t.state === "preparing" ? "准备中" : t.state === "cancelling" ? "取消中" : null;
    statsText =
      pct === null
        ? `${phase ?? "传输中"} · ${formatBytes(t.sentBytes)} · ${targetLabelText}`
        : `${phase === null ? "" : `${phase} · `}${pct}% · ${formatBytes(t.sentBytes)} / ${formatBytes(t.totalBytes)} · ${targetLabelText}`;
  }

  // A failed row replaces its meter with the retry/dismiss controls; a live
  // upload keeps the meter and puts its cancel control underneath.
  const body =
    item.tone === "failed"
      ? controlsRowHtml(item.controls)
      : item.tone === "paused"
        ? pct === null
          ? ""
          : `<div class="meter"><div class="meter-fill" style="width:${pct}%"></div></div>`
        : pct === null && t.state !== "queued"
          ? `<div class="meter"><div class="meter-fill job-meter-indeterminate"></div></div>`
          : `<div class="meter"><div class="meter-fill" style="width:${t.state === "queued" ? 0 : (pct ?? 0)}%"></div></div>`;
  const cancelRow = item.tone === "failed" ? "" : controlsRowHtml(item.controls);
  const trayKey = escapeAttr(`transfer:${t.key}`);

  return (
    `<div class="transfer-item" data-tray-key="${trayKey}" data-state="${t.state}">` +
    `<div class="transfer-row1"><span class="transfer-name"><span class="transfer-arrow">${arrow}</span> ${labelText}</span>` +
    `<span class="transfer-stats">${statsText}</span></div>` +
    body +
    cancelRow +
    `</div>`
  );
}

/* ---------------------------------------------------------------------- *
 * Real download jobs (`TransferCoordinator`). These now carry the same
 * byte-level progress the `Transfer` upload rows above do (`totalBytes`/
 * `transferredBytes`/`filesDone` on `JobStateEvent`), so both directions
 * render the same way. A job whose manifest is not resolved yet reports
 * `totalBytes === 0`; that is the only case that falls back to the
 * indeterminate bar, so no percentage is ever fabricated.
 * ---------------------------------------------------------------------- */

const JOB_PHASE_LABELS: Record<string, string> = {
  queued: "排队中…",
  waiting_for_device: "等待设备连接…",
  waiting_for_pairing: "等待配对完成…",
  paused_capture_active: "设备正在采集，已暂停…",
  preparing: "准备中…",
  transferring: "传输中…",
  verifying: "校验中…",
  committing: "写入中…",
  retry_wait: "等待重试…",
  cancelling: "取消中…",
  succeeded: "已完成",
  cancelled: "已取消",
};

const FAILURE_CODE_LABELS: Record<string, string> = {
  network: "网络错误",
  disk_full: "磁盘空间不足",
  hash_mismatch: "校验和不匹配",
  object_store_rejected: "对象存储拒绝",
  device_heartbeat_failed: "设备心跳失败",
};

function failureText(state: Extract<TransferJobState, { state: "failed" }>): string {
  const label = typeof state.code === "string" ? (FAILURE_CODE_LABELS[state.code] ?? state.code) : state.code.other;
  return `失败 · ${label}${state.retryable ? "（可重试）" : ""}`;
}

export function transferJobStateText(state: TransferJobState): string {
  return state.state === "failed" ? failureText(state) : (JOB_PHASE_LABELS[state.state] ?? state.state);
}

export function transferJobItemHtml(job: TransferJobEvent, item: TrayJobItem = selectJobItem(job)): string {
  // `job.sessionId`/`job.deviceId` come straight off a Pi HTTP response
  // (session_id / device fingerprint per pi_http.rs) and `job.jobId` is
  // locally generated (coordinator.rs's `next_job_id`); `transferJobStateText`
  // can additionally surface a `FailureCode::Other(String)` payload carrying
  // Pi-derived error text (see `failureText`/`classify_download_error`).
  // Everything interpolated below is escaped: `escapeHtml` as text content,
  // `escapeAttr` inside quoted attributes.
  const paused = item.paused;
  const rawShortId = job.jobId.length > 10 ? `${job.jobId.slice(0, 10)}…` : job.jobId;
  const titleText = escapeHtml(job.sessionId ?? rawShortId);
  const deviceText = job.deviceDisplayId === null ? "" : escapeHtml(job.deviceDisplayId);
  const stateText = escapeHtml(paused ? "已暂停" : transferJobStateText(job.state));

  const pct = job.totalBytes > 0 ? Math.min(100, Math.round((job.transferredBytes / job.totalBytes) * 100)) : null;

  const statParts = [stateText];
  if (pct !== null) {
    statParts.push(`${pct}%`, `${formatBytes(job.transferredBytes)} / ${formatBytes(job.totalBytes)}`);
  }
  if (job.filesTotal > 1) statParts.push(`${job.filesDone}/${job.filesTotal} 个文件`);
  const stats = statParts.join(" · ");
  const statsText = item.tone === "failed" ? `<span style="color:var(--danger-500);">${stats}</span>` : stats;

  // A paused job with no known total gets no bar at all: an indeterminate
  // (animated) bar would read as "still working", which is the opposite of
  // what is happening. A known percentage still renders, frozen where it is.
  const live = item.tone === "active" || item.tone === "paused";
  const meter = !live
    ? ""
    : pct !== null
      ? `<div class="meter"><div class="meter-fill" style="width:${pct}%"></div></div>`
      : paused
        ? ""
        : `<div class="meter"><div class="meter-fill job-meter-indeterminate"></div></div>`;

  const trayKey = escapeAttr(`job:${job.jobId}`);
  return (
    `<div class="transfer-item" data-tray-key="${trayKey}" data-done="${item.tone === "done"}" data-failed="${item.tone === "failed"}" data-queued="${job.state.state === "queued"}">` +
    `<div class="transfer-row1"><span class="transfer-name"><span class="transfer-arrow">↓</span> ${titleText}` +
    (deviceText === "" ? "" : ` <span class="mono" style="opacity:.55;">${deviceText}</span>`) +
    `</span>` +
    `<span class="transfer-stats">${statsText}</span></div>` +
    meter +
    controlsRowHtml(item.controls) +
    `</div>`
  );
}

/** One row, whichever kind it is. */
export function trayItemHtml(item: TrayJobItem | TrayTransferItem): string {
  return item.kind === "job" ? transferJobItemHtml(item.job, item) : transferItemHtml(item.transfer, item);
}
