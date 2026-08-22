import { escapeAttr, escapeHtml, formatBytes, formatBytesParts } from "../format";
import {
  libraryEntryCanUpload,
  libraryEntryKey,
  storageConfigured,
  type LibraryEntry,
  type StorageConfig,
} from "../types";
import type { Resource } from "../runtime/reducer";
import { recordingTitleText, statTileHtml } from "./deviceView";

export function librarySummaryHtml(library: LibraryEntry[]): string {
  const totalBytes = library.reduce((sum, e) => sum + e.bytes, 0);
  const pending = library.filter(
    (e) => e.complete && e.uploadStatus !== "done" && e.uploadStatus !== "uploading" && libraryEntryCanUpload(e),
  ).length;
  const done = library.filter((e) => e.uploadStatus === "done").length;
  const [bytesValue, bytesUnit] = formatBytesParts(totalBytes);
  return (
    `<div class="summary-strip">` +
    statTileHtml("本地会话", library.length) +
    statTileHtml("占用空间", bytesValue, bytesUnit) +
    statTileHtml("待上传", pending) +
    statTileHtml("已上传", done) +
    `</div>`
  );
}

export function libraryTopbarPillHtml(
  storage: StorageConfig,
  storageResource: Pick<Resource<StorageConfig>, "error" | "loading"> = { error: null, loading: false },
): string {
  const configured = storageConfigured(storage);
  const retry =
    storageResource.error === null
      ? ""
      : `<button type="button" class="btn btn-ghost btn-sm" data-action="retry-resource" data-resource="storageConfig" ${storageResource.loading ? "disabled" : ""}>${storageResource.loading ? "重试中…" : "重试读取配置"}</button>`;
  return (
    `<button type="button" class="pill-static clickable${configured ? "" : " warn"}" id="openStorageBtn">` +
    (configured ? `对象存储 · <span class="mono">${escapeHtml(storage.bucket)}</span>` : "未配置对象存储 · 点击设置") +
    `</button>${retry}`
  );
}

export function libraryRowHtml(
  entry: LibraryEntry,
  opts: { open: boolean; deleting: boolean; checked: boolean; configured: boolean },
): string {
  // `entry.sessionId`/`entry.deviceId` (and each file's `path`) ultimately
  // trace back to a Pi HTTP response body (session_id/device fingerprint/
  // display_path per pi_http.rs) -- a malicious or spoofed Pi controls their
  // contents, so every interpolation below must be escaped: `escapeAttr`
  // inside quoted HTML attributes, `escapeHtml` as text content. `key` is
  // derived from those same two fields, so it needs the same treatment.
  const key = libraryEntryKey(entry);
  const keyAttr = escapeAttr(key);
  const sessionIdText = escapeHtml(entry.sessionId);
  const deviceDisplayIdText = escapeHtml(entry.deviceDisplayId);
  const titleText = escapeHtml(recordingTitleText(entry.dateLabel));
  const sessionIdTitleAttr = escapeAttr(`会话 ID: ${entry.sessionId}`);
  const downloadedAtText = escapeHtml(entry.downloadedAt);

  const chipMap: Record<LibraryEntry["uploadStatus"], string> = {
    done: `<span class="chip chip-ok">已上传</span>`,
    uploading: `<span class="chip chip-upload">上传中…</span>`,
    failed: `<span class="chip chip-fail">上传失败</span>`,
    none: `<span class="chip chip-idle">未上传</span>`,
  };
  const chip = entry.complete
    ? chipMap[entry.uploadStatus]
    : `<span class="chip chip-idle">本地文件缺失或不完整</span>`;

  let uploadBtn: string;
  if (!entry.complete) {
    uploadBtn = `<button class="btn btn-sm" disabled>需要重新下载</button>`;
  } else if (!opts.configured) {
    uploadBtn = `<button class="btn btn-ghost btn-sm" data-action="open-storage">配置存储</button>`;
  } else if (entry.uploadStatus === "uploading") {
    uploadBtn = `<button class="btn btn-sm" disabled>上传中</button>`;
  } else if (entry.uploadStatus === "failed") {
    uploadBtn = entry.uploadRetryable
      ? `<button class="btn btn-primary btn-sm" data-action="upload" data-key="${keyAttr}">重试上传</button>`
      : `<button class="btn btn-sm" disabled>不可重试</button>`;
  } else if (entry.uploadStatus === "done") {
    uploadBtn = `<button class="btn btn-ghost btn-sm" data-action="upload" data-key="${keyAttr}">重新上传</button>`;
  } else {
    uploadBtn = `<button class="btn btn-primary btn-sm" data-action="upload" data-key="${keyAttr}">上传</button>`;
  }

  const removeBtn = opts.deleting
    ? `<button class="btn btn-danger-confirm btn-sm" data-action="remove-local" data-key="${keyAttr}">确认移除</button>`
    : `<button class="btn btn-danger-outline btn-sm" data-action="remove-local" data-key="${keyAttr}">移除本地副本</button>`;

  const filesHtml = opts.open
    ? entry.files
        .map((f) => {
          const pathText = escapeHtml(f.displayPath);
          const fileIdAttr = escapeAttr(f.fileId);
          return (
            `<li class="file-row"><span class="file-path">${pathText}</span>` +
            `<span class="file-size mono">${formatBytes(f.bytes)}</span>` +
            `<button class="btn btn-ghost btn-sm" data-action="reveal" data-key="${keyAttr}" data-file-id="${fileIdAttr}">在文件夹中显示</button></li>`
          );
        })
        .join("")
    : "";

  return (
    `<div class="session-row" data-key="${keyAttr}" data-open="${opts.open}">` +
    `<div class="session-main session-main-library" data-action="toggle-lib" data-key="${keyAttr}">` +
    `<input type="checkbox" class="row-check" data-select="${keyAttr}" ${opts.checked ? "checked" : ""} ${entry.complete ? "" : "disabled"} />` +
    `<span class="chevron"></span>` +
    `<span class="session-id"><span class="session-title">${titleText}</span>` +
    `<span class="session-id-secondary" title="${sessionIdTitleAttr}">${sessionIdText}</span></span>` +
    `<span><span class="cell-label">来源设备</span><span class="tag-device">${deviceDisplayIdText}</span></span>` +
    `<span><span class="cell-label">大小</span><span class="cell-value">${formatBytes(entry.bytes)}</span></span>` +
    `<span><span class="cell-label">下载时间</span><span class="cell-value">${downloadedAtText}</span></span>` +
    `<span>${chip}</span>` +
    `<span class="row-actions">${uploadBtn}${removeBtn}</span>` +
    `</div>` +
    `<div class="session-files"><ul class="file-list">${filesHtml}</ul></div>` +
    `</div>`
  );
}
