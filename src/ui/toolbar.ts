import { escapeAttr } from "../format";
import type { FilterState } from "../store";

export type ToolbarKind = "device" | "library";

const STATUS_LABELS: Record<ToolbarKind, [string, string][]> = {
  device: [
    ["all", "全部"],
    ["pending", "未下载"],
    ["done", "已下载"],
  ],
  library: [
    ["all", "全部"],
    ["pending", "未上传"],
    ["done", "已上传"],
  ],
};

export function renderToolbarHtml(kind: ToolbarKind, filter: FilterState): string {
  const pills = STATUS_LABELS[kind]
    .map(
      ([value, label]) =>
        `<button type="button" data-filter-status="${value}" data-on="${filter.status === value}">${label}</button>`,
    )
    .join("");
  return (
    `<div class="toolbar">` +
    `<div class="search-field"><svg viewBox="0 0 20 20" fill="none"><circle cx="9" cy="9" r="6" stroke="currentColor" stroke-width="1.6"/><path d="M14 14L18 18" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>` +
    `<input type="text" id="searchInput" placeholder="搜索会话 ID 或日期" value="${escapeAttr(filter.query)}" /></div>` +
    `<div class="filter-pills" id="filterPills">${pills}</div>` +
    `<button type="button" class="btn btn-ghost btn-sm" id="sortBtn">${filter.sortDesc ? "最新优先" : "最早优先"}</button>` +
    `</div>`
  );
}

export function renderSectionHeadingShellHtml(eyebrowLabel: string): string {
  return (
    `<div class="section-heading">` +
    `<label class="select-all-label"><input type="checkbox" class="row-check" id="selectAllBox" /><span class="eyebrow">${eyebrowLabel}</span></label>` +
    `<span id="sectionHeadingRight"></span>` +
    `</div>`
  );
}

export function renderBulkBarHtml(
  kind: ToolbarKind,
  selectedCount: number,
  bulkDeleting: boolean,
  options: { canRemove?: boolean } = {},
): string {
  if (selectedCount === 0) {
    return `<span class="count mono" id="sessionsCount"></span>`;
  }
  const actionLabel = kind === "device" ? "下载所选" : "上传所选";
  const removeLabel = kind === "device" ? "删除所选" : "移除所选";
  const removeButton =
    options.canRemove === false
      ? ""
      : `<button class="btn ${bulkDeleting ? "btn-danger-confirm" : "btn-danger-outline"}" style="padding:5px 11px;font-size:11px;border-radius:7px;margin-right:6px;" id="bulkRemoveBtn">${
          bulkDeleting ? "确认" + removeLabel : removeLabel
        }</button>`;
  return (
    `<span class="mono" style="font-size:10.5px;color:var(--text-secondary);margin-right:8px;">已选 ${selectedCount} 项</span>` +
    `<button class="btn btn-primary btn-sm" id="bulkActionBtn" style="margin-right:6px;">${actionLabel}</button>` +
    removeButton +
    `<button class="btn btn-ghost btn-sm" id="bulkClearBtn">取消</button>`
  );
}
