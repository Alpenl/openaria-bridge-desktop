// The device half of the DOM: left rail, pairing overlay, manual-add overlay,
// device top bar and the recording-session list.
//
// It renders HTML strings (identical to what the previous monolith produced,
// escaping included) and turns delegated DOM events into typed actions. It
// owns no state, calls no backend and starts no timers.

import type { Dispatch } from "../../app/actions";
import { asDeviceId, asSessionId } from "../../ids";
import { confirmPhaseOf, deviceRowKey, filterFor } from "../../store";
import { confirmTargets } from "../../runtime/confirm";
import {
  deviceById,
  deviceSupportsSessionDetail,
  deviceSupportsSessionDeletion,
  deviceSupportsSessionDownload,
  devicesOf,
  sessionCatalogOf,
  sessionDetailStateOf,
  sessionsOf,
  sessionsResourceOf,
  type AppState,
  type SessionCatalogState,
} from "../../runtime/reducer";
import { escapeHtml } from "../../format";
import { sessionHasUsableVerification } from "../../types";
import { bindings, delegate, el, elOpt, inputEl } from "../dom";
import { connectedCountText, renderDeviceListHtml } from "../rail";
import { deviceSummaryHtml, emptyStateHtml, sessionPaginationHtml, sessionRowHtml } from "../deviceView";
import { selectDeviceList } from "../listSelector";
import { renderBulkBarHtml, renderSectionHeadingShellHtml, renderToolbarHtml } from "../toolbar";
import { syncToolbar } from "./listEvents";

const PAIRING_RING_CIRCUMFERENCE = 226.1;

/**
 * A v2 catalog is intentionally first-page-only: it has no stable revision
 * and cannot safely claim that the visible rows are the complete device
 * history. Keep that scope visible in the bulk action's copy.
 */
export function sessionDownloadButtonText(
  catalog: Pick<SessionCatalogState, "catalogAuthority" | "paginationSupported">,
  phase: "pending" | "complete",
): string {
  const firstPageOnly = !catalog.paginationSupported && catalog.catalogAuthority === "unavailable";
  if (phase === "complete") return firstPageOnly ? "当前首批已下载" : "已全部下载";
  return firstPageOnly ? "下载当前首批新数据" : "下载全部新数据";
}

export interface DeviceScreen {
  renderRail(state: AppState): void;
  renderTopbar(state: AppState): void;
  renderContent(state: AppState): void;
  renderList(state: AppState): void;
  showPairing(deviceId: string): void;
  updatePairingRing(remaining: number, total: number): void;
  hidePairing(): void;
  openAddDevice(): void;
  closeAddDevice(): void;
  setAddDeviceStatus(message: string | null, tone: "progress" | "danger", busy: boolean): void;
  setBusy(label: string | null): void;
  dispose(): void;
}

export function createDeviceScreen(dispatch: Dispatch): DeviceScreen {
  const bound = bindings();
  const content = el("content");
  const topbar = el("topbar");

  /* ---- rail ---- */

  bound.add(
    delegate(el("deviceList"), "click", ".device-item", (matched) => {
      const id = matched.dataset.id;
      if (id !== undefined) dispatch({ kind: "device/select", deviceId: asDeviceId(id) });
    }),
  );
  bound.add(
    delegate(el("deviceList"), "click", '[data-action="retry-resource"]', (matched, event) => {
      event.stopPropagation();
      if (matched.dataset.resource === "devices") dispatch({ kind: "resource/retry", resource: "devices" });
    }),
  );
  bound.add(delegate(el("addDeviceBtn"), "click", "#addDeviceBtn", () => dispatch({ kind: "device/openAdd" })));
  bound.add(delegate(el("cancelAddDevice"), "click", "#cancelAddDevice", () => dispatch({ kind: "device/closeAdd" })));
  bound.add(
    delegate(el("submitAddDevice"), "click", "#submitAddDevice", () =>
      dispatch({ kind: "device/submitAdd", ip: inputEl("manualIp").value }),
    ),
  );
  bound.add(delegate(el("cancelPairing"), "click", "#cancelPairing", () => dispatch({ kind: "pairing/cancel" })));

  /* ---- top bar ---- */

  /** The topbar is rebuilt on every paint, so its controls are matched by the
   * ids the markup already used rather than re-bound each time. */
  let activeDeviceId: string | null = null;
  bound.add(
    delegate(topbar, "click", "button", (matched) => {
      if (activeDeviceId === null) return;
      const deviceId = asDeviceId(activeDeviceId);
      switch (matched.id) {
        case "reconnectBtn":
          dispatch({ kind: "device/reconnect", deviceId });
          return;
        case "disconnectBtn":
          dispatch({ kind: "device/disconnect", deviceId });
          return;
        case "refreshBtn":
          dispatch({ kind: "device/refreshSessions", deviceId });
          return;
        case "downloadAllBtn":
          dispatch({ kind: "device/downloadAllNew", deviceId });
          return;
        case "cleanupBtn":
          dispatch({ kind: "device/cleanupBackedUp", deviceId });
          return;
        case "cleanupDownloadedBtn":
          dispatch({ kind: "device/cleanupDownloaded", deviceId });
          return;
      }
    }),
  );

  /* ---- session rows ---- */

  bound.add(
    delegate(content, "click", '[data-action="toggle"]', (matched, event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.closest("button") || target.matches('input[type="checkbox"]')) return;
      const sessionId = matched.dataset.session;
      if (sessionId === undefined || activeDeviceId === null) return;
      dispatch({ kind: "list/toggleRow", scope: "device", rowKey: deviceRowKey(activeDeviceId, sessionId) });
      dispatch({
        kind: "session/loadDetail",
        deviceId: asDeviceId(activeDeviceId),
        sessionId: asSessionId(sessionId),
      });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="retry-session-detail"]', (matched, event) => {
      event.stopPropagation();
      const sessionId = matched.dataset.session;
      if (sessionId === undefined || activeDeviceId === null) return;
      dispatch({
        kind: "session/loadDetail",
        deviceId: asDeviceId(activeDeviceId),
        sessionId: asSessionId(sessionId),
      });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="load-more-sessions"]', (_matched, event) => {
      event.stopPropagation();
      if (activeDeviceId === null) return;
      dispatch({ kind: "device/loadMoreSessions", deviceId: asDeviceId(activeDeviceId) });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="download"]', (matched, event) => {
      event.stopPropagation();
      const sessionId = matched.dataset.session;
      if (sessionId === undefined || activeDeviceId === null) return;
      dispatch({
        kind: "session/download",
        deviceId: asDeviceId(activeDeviceId),
        sessionId: asSessionId(sessionId),
      });
    }),
  );

  bound.add(
    delegate(content, "click", '[data-action="delete"]', (matched, event) => {
      event.stopPropagation();
      const sessionId = matched.dataset.session;
      if (sessionId === undefined || activeDeviceId === null) return;
      dispatch({
        kind: "session/remove",
        deviceId: asDeviceId(activeDeviceId),
        sessionId: asSessionId(sessionId),
      });
    }),
  );

  /* ---- rendering ---- */

  function renderRail(state: AppState): void {
    el("deviceList").innerHTML = renderDeviceListHtml(devicesOf(state), state.ui, state.devices);
    el("connectedCount").textContent = connectedCountText(devicesOf(state));
  }

  function renderTopbar(state: AppState): void {
    const device = deviceById(state, state.ui.activeDeviceId);
    activeDeviceId = device?.id ?? null;

    if (!device) {
      topbar.innerHTML = `<div class="topbar-identity"><div><h1>未连接设备</h1><div class="sub">在左侧选择一台在线设备发起连接</div></div></div>`;
      return;
    }

    if (device.state !== "connected") {
      const status =
        device.state === "offline"
          ? "设备当前离线"
          : device.state === "pending"
            ? "正在建立局域网连接"
            : device.state === "error"
              ? "连接已中断，需要重新连接才能继续操作"
              : "设备尚未连接";
      topbar.innerHTML =
        `<div class="topbar-identity"><span class="heartbeat" data-tone="danger"></span>` +
        `<div><h1>${escapeHtml(device.displayId)}</h1><div class="sub" style="color:var(--danger-500);">${status}</div></div></div>` +
        `<div class="topbar-actions">${
          device.state === "offline" || device.state === "pending"
            ? ""
            : `<button class="btn btn-primary" id="reconnectBtn">重新连接</button>`
        }</div>`;
      return;
    }

    const sessionsState = sessionsResourceOf(state, device.id);
    const sessions = sessionsState.value ?? [];
    const catalog = sessionCatalogOf(state, device.id);
    const hasSessionSnapshot = sessionsState.value !== null;
    const refreshing = sessionsState.loading;
    const refreshFailed = sessionsState.error !== null;
    const pending = sessions.filter(
      (s) => sessionHasUsableVerification(s) && (s.downloadStatus === "none" || s.downloadStatus === "failed"),
    );
    const hasIneligiblePending = sessions.some(
      (s) => !sessionHasUsableVerification(s) && (s.downloadStatus === "none" || s.downloadStatus === "failed"),
    );
    const anyDownloading = sessions.some((s) => s.downloadStatus === "downloading");
    const canDeleteFromDevice = deviceSupportsSessionDeletion(state, device.id);
    const canDownloadArtifacts = deviceSupportsSessionDownload(state, device.id);
    const downloadAllBtn = !hasSessionSnapshot
      ? `<button class="btn btn-ghost" disabled>${refreshing ? "正在读取设备数据…" : "会话列表不可用"}</button>`
      : !canDownloadArtifacts
        ? `<button class="btn btn-ghost" disabled>下载不可用</button>`
        : pending.length > 0
          ? `<button class="btn btn-primary" id="downloadAllBtn">${sessionDownloadButtonText(catalog, "pending")}<span class="mono" style="opacity:.8;margin-left:2px;">(${pending.length})</span></button>`
          : anyDownloading
            ? `<button class="btn btn-ghost" disabled>新数据下载中…</button>`
            : hasIneligiblePending
              ? `<button class="btn btn-ghost" disabled>没有已验证的新数据</button>`
              : `<button class="btn btn-ghost" disabled>${sessionDownloadButtonText(catalog, "complete")}</button>`;

    const backedUp = sessions.filter((s) => s.downloadStatus === "done" && s.backedUp);
    const cleanupConfirming =
      confirmPhaseOf(state.ui, confirmTargets.cleanupBackedUp(device.id)).phase === "confirming";
    const cleanupBtn =
      canDeleteFromDevice && backedUp.length > 0
        ? cleanupConfirming
          ? `<button class="btn btn-danger-confirm" id="cleanupBtn">确认清理 ${backedUp.length} 项</button>`
          : `<button class="btn btn-ghost" id="cleanupBtn">清理已备份数据<span class="mono" style="opacity:.8;margin-left:2px;">(${backedUp.length})</span></button>`
        : "";
    const cleanupDownloadedBtn =
      canDeleteFromDevice && sessions.some((session) => session.downloadStatus === "done")
        ? `<button class="btn btn-danger-outline" id="cleanupDownloadedBtn">删除 Pi 已下载数据</button>`
        : "";

    topbar.innerHTML =
      `<div class="topbar-identity"><span class="heartbeat"></span>` +
      `<div><h1>${escapeHtml(device.displayId)} <span class="id mono">${escapeHtml(device.ip ?? "")}</span></h1>` +
      `<div class="sub">${refreshing ? (hasSessionSnapshot ? "正在刷新会话 · 当前显示缓存数据" : "正在读取设备会话") : refreshFailed && hasSessionSnapshot ? "会话刷新失败 · 当前显示缓存数据" : "心跳正常 · 会话仅在连接期间有效"}</div></div></div>` +
      `<div class="topbar-actions">${downloadAllBtn}${cleanupBtn}${cleanupDownloadedBtn}<button class="btn" id="refreshBtn" ${refreshing ? "disabled" : ""}>${refreshing ? "刷新中…" : "刷新"}</button><button class="btn btn-ghost" id="disconnectBtn">断开连接</button></div>`;
  }

  function renderContent(state: AppState): void {
    const device = deviceById(state, state.ui.activeDeviceId);
    activeDeviceId = device?.id ?? null;

    if (!device) {
      content.innerHTML = emptyStateHtml("尚未连接设备", "在左侧列表选择一台在线的 YLX 采集设备即可连接。");
      return;
    }
    if (device.state !== "connected") {
      const title =
        device.state === "offline" ? "设备离线" : device.state === "pending" ? "正在连接设备" : "设备未连接";
      content.innerHTML = emptyStateHtml(title, `${escapeHtml(device.displayId)} 当前没有可用连接。`);
      return;
    }

    const sessions = sessionsOf(state, device.id);
    if (sessions === undefined) {
      content.innerHTML =
        sessionsResourceOf(state, device.id).error !== null
          ? emptyStateHtml("无法读取设备数据", "会话列表刷新失败，请检查连接后重试。")
          : emptyStateHtml("正在读取设备数据", "正在刷新录制会话，请稍候。");
      return;
    }

    content.innerHTML =
      deviceSummaryHtml(sessions) +
      renderToolbarHtml("device", filterFor(state.ui, "device")) +
      renderSectionHeadingShellHtml("录制会话") +
      `<div class="sessions" id="sessionsList"></div>` +
      `<div id="sessionPagination"></div>`;

    renderList(state);
  }

  function renderList(state: AppState): void {
    const container = elOpt("sessionsList");
    if (container === null) return; // view switched away before this update landed

    const ui = state.ui;
    const ownerId = ui.activeDeviceId ?? "";
    const sessions = sessionsOf(state, ui.activeDeviceId) ?? [];
    const catalog = sessionCatalogOf(state, ui.activeDeviceId);
    const canDeleteFromDevice = deviceSupportsSessionDeletion(state, ui.activeDeviceId);
    const canDownloadSessions = deviceSupportsSessionDownload(state, ui.activeDeviceId);
    const list = selectDeviceList(ui, sessions);
    const selectedEligible = sessions.some(
      (session) => ui.deviceSelection.has(session.id) && sessionHasUsableVerification(session),
    );
    syncToolbar(content, filterFor(ui, "device"));

    const bulkConfirming = confirmPhaseOf(ui, confirmTargets.deviceBulkRemove(ownerId)).phase === "confirming";
    const right = elOpt("sectionHeadingRight");
    if (right)
      right.innerHTML = renderBulkBarHtml("device", list.selectedKeys.length, bulkConfirming, {
        canRemove: canDeleteFromDevice,
        canAct: canDownloadSessions && selectedEligible,
      });

    const countEl = elOpt("sessionsCount");
    if (countEl) countEl.textContent = list.countText;

    if (list.visible.length === 0) {
      container.innerHTML = `<div class="empty-inline">没有匹配的记录</div>`;
    } else {
      container.innerHTML = list.visible
        .map((session) => {
          const rowKey = deviceRowKey(ownerId, session.id);
          const detail = sessionDetailStateOf(state, ownerId, session.id);
          const verificationEligible = sessionHasUsableVerification(session);
          return sessionRowHtml(session, {
            open: ui.openRows.has(rowKey),
            deleting: confirmPhaseOf(ui, confirmTargets.deviceRowRemove(rowKey)).phase === "confirming",
            checked: ui.deviceSelection.has(session.id),
            canDelete: canDeleteFromDevice,
            canDownloadSession: canDownloadSessions && verificationEligible,
            canLoadDetail: deviceSupportsSessionDetail(state, ui.activeDeviceId) && verificationEligible,
            detailLoading: detail?.loading ?? false,
            detailError: detail?.error ?? null,
          });
        })
        .join("");
    }

    const pagination = elOpt("sessionPagination");
    if (pagination !== null) {
      pagination.innerHTML = sessionPaginationHtml(sessions.length, catalog);
    }

    const selectAllBox = document.getElementById("selectAllBox") as HTMLInputElement | null;
    if (selectAllBox) selectAllBox.checked = list.allVisibleSelected;
  }

  function setAddDeviceStatus(message: string | null, tone: "progress" | "danger", busy: boolean): void {
    const status = elOpt("manualAddStatus");
    if (status !== null) {
      status.textContent = message ?? "";
      status.dataset.tone = message === null ? "hidden" : tone;
    }

    const submit = elOpt("submitAddDevice") as HTMLButtonElement | null;
    if (submit !== null) {
      submit.disabled = busy;
      submit.textContent = busy ? "探测中..." : "连接";
    }

    const input = elOpt("manualIp") as HTMLInputElement | null;
    if (input !== null) input.disabled = busy;
  }

  return {
    renderRail,
    renderTopbar,
    renderContent,
    renderList,
    showPairing(deviceId: string): void {
      el("pairingDeviceId").textContent = deviceId;
      el("pairingOverlay").dataset.open = "true";
      el("ringProgress").style.strokeDashoffset = String(PAIRING_RING_CIRCUMFERENCE);
      el("ringSeconds").textContent = "...";
    },
    updatePairingRing(remaining: number, total: number): void {
      if (!Number.isFinite(remaining) || !Number.isFinite(total) || total <= 0) return;
      const fraction = 1 - Math.max(0, Math.min(remaining, total)) / total;
      el("ringProgress").style.strokeDashoffset = String(PAIRING_RING_CIRCUMFERENCE * fraction);
      el("ringSeconds").textContent = String(Math.max(remaining, 0));
    },
    hidePairing(): void {
      el("pairingOverlay").dataset.open = "false";
    },
    openAddDevice(): void {
      inputEl("manualIp").value = "";
      setAddDeviceStatus(null, "progress", false);
      el("addDeviceOverlay").dataset.open = "true";
    },
    closeAddDevice(): void {
      setAddDeviceStatus(null, "progress", false);
      el("addDeviceOverlay").dataset.open = "false";
    },
    setAddDeviceStatus,
    setBusy(label: string | null): void {
      const button = elOpt("cleanupDownloadedBtn") as HTMLButtonElement | null;
      if (!button) return;
      if (label === null) {
        button.disabled = false;
        return;
      }
      button.disabled = true;
      button.textContent = label;
    },
    dispose: bound.dispose,
  };
}
