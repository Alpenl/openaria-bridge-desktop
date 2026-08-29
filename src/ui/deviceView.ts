import { escapeAttr, escapeHtml, formatBytes, formatBytesParts, formatCount, formatDuration } from "../format";
import { sessionHasUsableVerification } from "../types";
import type { SessionCatalogDiagnostic, SessionPaginationUnavailableReason, SessionView } from "../types";

function twoDigits(value: number): string {
  return value.toString().padStart(2, "0");
}

/** Formats the Pi's captured_at value in the PC's local time zone. */
export function recordingTitleText(capturedAt: string): string {
  const captured = new Date(capturedAt);
  if (Number.isNaN(captured.getTime())) return "录制时间未知";

  const date = `${captured.getFullYear()}-${twoDigits(captured.getMonth() + 1)}-${twoDigits(captured.getDate())}`;
  const time = `${twoDigits(captured.getHours())}:${twoDigits(captured.getMinutes())}:${twoDigits(captured.getSeconds())}`;
  return `录制 ${date} ${time}`;
}

export function statTileHtml(label: string, value: string | number, unit = ""): string {
  return (
    `<div class="stat"><span class="eyebrow">${label}</span>` +
    `<span class="value mono">${value}${unit ? `<span class="unit">${unit}</span>` : ""}</span></div>`
  );
}

export function deviceSummaryHtml(sessions: SessionView[]): string {
  const totalBytes = sessions.reduce((sum, s) => sum + s.totalBytes, 0);
  const knownSampleCounts = sessions.flatMap((s) => (s.imuSamples === null ? [] : [s.imuSamples]));
  const totalSamples = knownSampleCounts.reduce((sum, samples) => sum + samples, 0);
  const sampleText = knownSampleCounts.length === 0 ? "--" : formatCount(totalSamples);
  const pending = sessions.filter(
    (s) => sessionHasUsableVerification(s) && (s.downloadStatus === "none" || s.downloadStatus === "failed"),
  ).length;
  const [bytesValue, bytesUnit] = formatBytesParts(totalBytes);
  return (
    `<div class="summary-strip">` +
    statTileHtml("会话", sessions.length) +
    statTileHtml("待下载", pending) +
    statTileHtml("设备存储", bytesValue, bytesUnit) +
    statTileHtml("IMU 采样", sampleText, knownSampleCounts.length === 0 ? "" : "样本") +
    `</div>`
  );
}

export function emptyStateHtml(title: string, body: string): string {
  return (
    `<div class="empty-state">` +
    `<div class="rig"><span class="lensdot"></span><span class="lensdot"></span></div>` +
    `<h2>${title}</h2><p>${body}</p>` +
    `</div>`
  );
}

export function sessionPaginationHtml(
  sessionCount: number,
  catalog: {
    catalogRevision: string | null;
    hasMore: boolean;
    paginationSupported: boolean;
    paginationUnavailableReason: SessionPaginationUnavailableReason | null;
    diagnostics: readonly SessionCatalogDiagnostic[];
    loadingMore: boolean;
    loadMoreError: string | null;
  },
): string {
  const shell = (content: string) =>
    `<div class="section-heading" style="justify-content:center;margin-top:12px;">${content}</div>`;
  const diagnostics = catalog.diagnostics
    .map(
      (diagnostic) =>
        `<div class="section-heading" style="justify-content:center;margin-top:12px;">` +
        `<span class="count" style="color:var(--danger-500);">${escapeHtml(diagnostic.message)}</span></div>`,
    )
    .join("");

  if (!catalog.paginationSupported) {
    return (
      diagnostics +
      (catalog.paginationUnavailableReason === "catalogRevisionUnavailable"
        ? shell(`<span class="count">当前设备目录不提供稳定分页，仅显示首批会话</span>`)
        : "")
    );
  }
  if (catalog.hasMore) {
    const error =
      catalog.loadMoreError === null
        ? ""
        : `<span class="count" style="color:var(--danger-500);">${escapeHtml(catalog.loadMoreError)}</span>`;
    const buttonClass = catalog.loadMoreError === null ? "btn-ghost" : "btn-danger-outline";
    const buttonText = catalog.loadingMore ? "正在加载…" : catalog.loadMoreError === null ? "加载更多" : "重试加载更多";
    return (
      diagnostics +
      shell(
        `${error}<button class="btn ${buttonClass}" data-action="load-more-sessions" ${catalog.loadingMore ? "disabled" : ""}>${buttonText}</button>`,
      )
    );
  }
  return (
    diagnostics +
    (catalog.catalogRevision === null ? "" : shell(`<span class="count">已加载全部 ${sessionCount} 项</span>`))
  );
}

export function sessionRowHtml(
  session: SessionView,
  opts: {
    open: boolean;
    deleting: boolean;
    checked: boolean;
    canDelete?: boolean;
    canDownloadSession?: boolean;
    canLoadDetail?: boolean;
    detailLoading?: boolean;
    detailError?: string | null;
  },
): string {
  // `session.id`/`session.dateLabel` (and each file's ids/labels) are deserialized
  // straight from a Pi HTTP response body (see pi_http.rs's `SessionSummary`/
  // `SessionDetail`/`SessionFileEntry`) -- a malicious or spoofed Pi fully
  // controls their contents, so every interpolation below must be escaped:
  // `escapeAttr` inside quoted HTML attributes, `escapeHtml` as text content.
  const idAttr = escapeAttr(session.id);
  const idText = escapeHtml(session.id);
  const titleText = escapeHtml(recordingTitleText(session.dateLabel));
  const idTitleAttr = escapeAttr(`会话 ID: ${session.id}`);
  const verificationEligible = sessionHasUsableVerification(session);

  const chipMap: Record<SessionView["downloadStatus"], string> = {
    done: `<span class="chip chip-local">已下载</span>`,
    downloading: `<span class="chip chip-progress">下载中…</span>`,
    failed: `<span class="chip chip-fail">下载失败</span>`,
    none: `<span class="chip chip-idle">未下载</span>`,
  };
  let chip = chipMap[session.downloadStatus];
  if (session.backedUp) chip += `<span class="chip chip-ok">☁ 已备份</span>`;
  chip += verificationEligible
    ? `<span class="chip chip-ok">已验证</span>`
    : session.verification === null
      ? `<span class="chip chip-idle">未验证</span>`
      : session.verification.verdict === "unusable"
        ? `<span class="chip chip-fail">验证未通过</span>`
        : `<span class="chip chip-fail">验证异常</span>`;

  const downloadBtn = !verificationEligible
    ? `<button class="btn btn-sm" disabled>验证不可用</button>`
    : opts.canDownloadSession === false
      ? `<button class="btn btn-sm" disabled>下载不可用</button>`
      : session.downloadStatus === "downloading"
        ? `<button class="btn btn-sm" disabled>下载中</button>`
        : session.downloadStatus === "failed"
          ? `<button class="btn btn-primary btn-sm" data-action="download" data-session="${idAttr}">重试下载</button>`
          : session.downloadStatus === "done"
            ? `<button class="btn btn-ghost btn-sm" data-action="download" data-session="${idAttr}">重新下载</button>`
            : `<button class="btn btn-primary btn-sm" data-action="download" data-session="${idAttr}">下载</button>`;

  const deleteBtn =
    opts.canDelete === false
      ? ""
      : opts.deleting
        ? `<button class="btn btn-danger-confirm btn-sm" data-action="delete" data-session="${idAttr}">确认删除</button>`
        : `<button class="btn btn-danger-outline btn-sm" data-action="delete" data-session="${idAttr}">删除</button>`;

  const filesHtml = opts.open
    ? !verificationEligible
      ? `<li class="file-row"><span class="file-path">会话未通过网关验证，详情不可用</span><span class="file-size mono">--</span></li>`
      : session.files.length === 0
        ? opts.detailLoading
          ? `<li class="file-row"><span class="file-path">正在读取文件清单…</span><span class="file-size mono">--</span></li>`
          : opts.detailError
            ? `<li class="file-row"><span class="file-path">${escapeHtml(opts.detailError)}</span><span class="file-size mono">--</span>` +
              `<button class="btn btn-ghost btn-sm" data-action="retry-session-detail" data-session="${idAttr}">重试</button></li>`
            : opts.canLoadDetail === false
              ? `<li class="file-row"><span class="file-path">设备未提供会话文件清单</span><span class="file-size mono">--</span></li>`
              : `<li class="file-row"><span class="file-path">文件清单将在下载时按需读取</span><span class="file-size mono">--</span></li>`
        : session.files
            .map((f) => {
              const pathText = escapeHtml(f.displayPath);
              return (
                `<li class="file-row"><span class="file-path">${pathText}</span>` +
                `<span class="file-size mono">${formatBytes(f.bytes)}</span></li>`
              );
            })
            .join("")
    : "";

  return (
    `<div class="session-row" data-session="${idAttr}" data-open="${opts.open}">` +
    `<div class="session-main session-main-device" data-action="toggle" data-session="${idAttr}">` +
    `<input type="checkbox" class="row-check" data-select="${idAttr}" ${opts.checked ? "checked" : ""} />` +
    `<span class="chevron"></span>` +
    `<span class="session-id"><span class="session-title">${titleText}</span>` +
    `<span class="session-id-secondary" title="${idTitleAttr}">${idText}</span></span>` +
    `<span><span class="cell-label">时长</span><span class="cell-value">${formatDuration(session.durationSeconds)}</span></span>` +
    `<span><span class="cell-label">大小</span><span class="cell-value">${formatBytes(session.totalBytes)}</span></span>` +
    `<span><span class="cell-label">IMU 采样</span><span class="cell-value">${session.imuSamples === null ? "--" : formatCount(session.imuSamples)}</span></span>` +
    `<span style="display:flex;flex-wrap:wrap;gap:4px;">${chip}</span>` +
    `<span class="row-actions">${downloadBtn}${deleteBtn}</span>` +
    `</div>` +
    `<div class="session-files"><ul class="file-list">${filesHtml}</ul></div>` +
    `</div>`
  );
}
