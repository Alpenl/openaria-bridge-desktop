// Pure presentation: given data, return HTML strings. No DOM access, no
// event binding, no api calls — see main.ts for the interactive glue.

import type { Device, DeviceState, StorageConfig } from "../types";
import type { UiState } from "../store";
import type { Resource } from "../runtime/reducer";
import { escapeAttr, escapeHtml } from "../format";

function statusText(device: Device, visualState: DeviceState): string {
  switch (visualState) {
    case "connected":
      return `已连接 · ${escapeHtml(device.ip ?? "")}`;
    case "pending":
      return "正在连接…";
    case "error":
      return "连接中断，需要重新连接";
    case "offline":
      return `离线 · 最后在线 ${escapeHtml(device.lastSeen ?? "未知")}`;
    default:
      return `可连接 · ${escapeHtml(device.ip ?? "")}`;
  }
}

export function renderDeviceListHtml(
  devices: Device[],
  state: UiState,
  resource: Pick<Resource<Device[]>, "error" | "loading"> = { error: null, loading: false },
): string {
  const degraded =
    resource.error === null
      ? ""
      : `<div class="rail-empty resource-degraded"><span>设备列表读取失败：${escapeHtml(resource.error)}</span><button type="button" class="btn btn-sm btn-primary" data-action="retry-resource" data-resource="devices" ${resource.loading ? "disabled" : ""}>${resource.loading ? "重试中…" : "重试读取"}</button></div>`;
  if (devices.length === 0) {
    return resource.error === null
      ? `<div class="rail-empty">未发现设备<br />确认树莓派与本机在同一局域网</div>`
      : degraded;
  }
  return (
    degraded +
    devices
      .map((device) => {
        const visualState: DeviceState = state.pairingTargetId === device.id ? "pending" : device.state;
        const active = state.view === "device" && state.activeDeviceId === device.id;
        return (
          `<li><button type="button" class="device-item" data-id="${escapeAttr(device.id)}" data-active="${active}">` +
          `<span class="led" data-state="${visualState}"></span>` +
          `<span class="meta"><span class="id">${escapeHtml(device.displayId)}</span>` +
          `<span class="status-text">${statusText(device, visualState)}</span></span>` +
          `</button></li>`
        );
      })
      .join("")
  );
}

export function connectedCountText(devices: Device[]): string {
  const n = devices.filter((d) => d.state === "connected").length;
  return n > 0 ? `${n} 台已连接` : "";
}

/** Value shown under the rail footer's 本机保存位置 button. The backend
 * resolves the platform default into `activeDownloadRoot`, so an empty one
 * only happens before the first `get_storage_config` lands. Callers must
 * render this with `textContent`: the path is not HTML-escaped here. */
export function downloadRootLabelText(storage: StorageConfig): string {
  return storage.activeDownloadRoot || storage.downloadRoot || "默认目录";
}
