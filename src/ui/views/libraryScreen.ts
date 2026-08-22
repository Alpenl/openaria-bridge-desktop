// The library half of the DOM: the nav item and its badge, the library top
// bar, and the local-recording list.

import type { Dispatch } from "../../app/actions";
import { asFileId, asLibraryKey } from "../../ids";
import { confirmPhaseOf, filterFor, libraryRowKey } from "../../store";
import { confirmTargets } from "../../runtime/confirm";
import { libraryOf, storageOf, type AppState } from "../../runtime/reducer";
import { libraryEntryCanUpload, libraryEntryKey, storageConfigured } from "../../types";
import { escapeHtml } from "../../format";
import { bindings, delegate, el, elOpt } from "../dom";
import { emptyStateHtml } from "../deviceView";
import { libraryRowHtml, librarySummaryHtml, libraryTopbarPillHtml } from "../libraryView";
import { selectLibraryList } from "../listSelector";
import { renderBulkBarHtml, renderSectionHeadingShellHtml, renderToolbarHtml } from "../toolbar";
import { syncToolbar } from "./listEvents";

export interface LibraryScreen {
  renderNav(state: AppState): void;
  renderTopbar(state: AppState): void;
  renderContent(state: AppState): void;
  renderList(state: AppState): void;
  dispose(): void;
}

export function createLibraryScreen(dispatch: Dispatch): LibraryScreen {
  const bound = bindings();
  const content = el("content");
  const topbar = el("topbar");

  bound.add(delegate(el("libraryNavItem"), "click", "#libraryNavItem", () => dispatch({ kind: "library/open" })));

  bound.add(
    delegate(topbar, "click", "button", (matched) => {
      if (matched.dataset.action === "retry-resource") {
        if (matched.dataset.resource === "storageConfig")
          dispatch({ kind: "resource/retry", resource: "storageConfig" });
        return;
      }
      if (matched.id === "openStorageBtn") dispatch({ kind: "settings/openStorage" });
      if (matched.id === "uploadAllBtn") dispatch({ kind: "library/uploadAllPending" });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="retry-resource"]', (matched, event) => {
      event.stopPropagation();
      if (matched.dataset.resource === "library") dispatch({ kind: "resource/retry", resource: "library" });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="toggle-lib"]', (matched, event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.closest("button") || target.matches('input[type="checkbox"]')) return;
      const key = matched.dataset.key;
      if (key === undefined) return;
      dispatch({ kind: "list/toggleRow", scope: "library", rowKey: libraryRowKey(key) });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="upload"]', (matched, event) => {
      event.stopPropagation();
      const key = matched.dataset.key;
      if (key === undefined) return;
      dispatch({ kind: "entry/upload", key: asLibraryKey(key) });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="open-storage"]', (_matched, event) => {
      event.stopPropagation();
      dispatch({ kind: "settings/openStorage" });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="reveal"]', (matched, event) => {
      event.stopPropagation();
      const key = matched.dataset.key;
      const fileId = matched.dataset.fileId;
      if (key === undefined || fileId === undefined) return;
      dispatch({ kind: "entry/revealFile", key: asLibraryKey(key), fileId: asFileId(fileId) });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="remove-local"]', (matched, event) => {
      event.stopPropagation();
      const key = matched.dataset.key;
      if (key === undefined) return;
      dispatch({ kind: "entry/remove", key: asLibraryKey(key) });
    }),
  );

  function renderNav(state: AppState): void {
    const navItem = el("libraryNavItem");
    navItem.dataset.active = String(state.ui.view === "library");
    const badge = el("libraryBadge");
    const pending = libraryOf(state).filter(
      (e) => e.complete && e.uploadStatus !== "done" && e.uploadStatus !== "uploading" && libraryEntryCanUpload(e),
    ).length;
    badge.style.display = pending > 0 ? "inline-flex" : "none";
    badge.textContent = pending > 0 ? String(pending) : "";
  }

  function renderTopbar(state: AppState): void {
    topbar.innerHTML =
      `<div class="topbar-identity"><div><h1>本地数据</h1><div class="sub">跨设备下载到本机的录制数据，可上传到对象存储</div></div></div>` +
      `<div class="topbar-actions">${libraryTopbarPillHtml(storageOf(state), state.storage)}<button class="btn btn-primary" id="uploadAllBtn">全部上传</button></div>`;
  }

  function renderContent(state: AppState): void {
    const library = libraryOf(state);
    const retry =
      state.library.error === null
        ? ""
        : `<div class="resource-degraded"><span>本地数据刷新失败：${escapeHtml(state.library.error)}。当前显示最近一次成功读取的数据。</span><button class="btn btn-sm btn-primary" data-action="retry-resource" data-resource="library" ${state.library.loading ? "disabled" : ""}>${state.library.loading ? "重试中…" : "重试读取"}</button></div>`;
    if (library.length === 0) {
      content.innerHTML =
        retry +
        emptyStateHtml(
          state.library.error === null ? "本地暂无数据" : "本地数据暂不可用",
          state.library.error === null
            ? "从已连接设备下载录制会话后，会出现在这里，并可以上传到对象存储备份。"
            : "本地数据读取失败，请检查磁盘状态后重试。",
        );
      return;
    }
    content.innerHTML =
      retry +
      librarySummaryHtml(library) +
      renderToolbarHtml("library", filterFor(state.ui, "library")) +
      renderSectionHeadingShellHtml("本地录制") +
      `<div class="sessions" id="sessionsList"></div>`;

    renderList(state);
  }

  function renderList(state: AppState): void {
    const container = elOpt("sessionsList");
    if (container === null) return; // view switched away before this update landed

    const ui = state.ui;
    const list = selectLibraryList(ui, libraryOf(state));
    const configured = storageConfigured(storageOf(state));
    syncToolbar(content, filterFor(ui, "library"));

    const bulkConfirming = confirmPhaseOf(ui, confirmTargets.libraryBulkRemove()).phase === "confirming";
    const right = elOpt("sectionHeadingRight");
    if (right) right.innerHTML = renderBulkBarHtml("library", list.selectedKeys.length, bulkConfirming);

    const countEl = elOpt("sessionsCount");
    if (countEl) countEl.textContent = list.countText;

    if (list.visible.length === 0) {
      container.innerHTML = `<div class="empty-inline">没有匹配的记录</div>`;
    } else {
      container.innerHTML = list.visible
        .map((entry) => {
          const key = libraryEntryKey(entry);
          const rowKey = libraryRowKey(key);
          return libraryRowHtml(entry, {
            open: ui.openRows.has(rowKey),
            deleting: confirmPhaseOf(ui, confirmTargets.libraryRowRemove(rowKey)).phase === "confirming",
            checked: ui.librarySelection.has(key),
            configured,
          });
        })
        .join("");
    }

    const selectAllBox = document.getElementById("selectAllBox") as HTMLInputElement | null;
    if (selectAllBox) selectAllBox.checked = list.allVisibleSelected;
  }

  return { renderNav, renderTopbar, renderContent, renderList, dispose: bound.dispose };
}
