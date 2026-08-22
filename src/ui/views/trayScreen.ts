// The transfer tray.
//
// It renders whatever `selectTray` decided and keeps the selection it painted,
// so a clicked control is resolved back to its typed command instead of the DOM
// re-deriving an identity from a `data-key` string.

import type { Dispatch } from "../../app/actions";
import { escapeHtml } from "../../format";
import { bindings, delegate, el } from "../dom";
import { trayItemHtml } from "../tray";
import { findTrayCommand, selectTray, type TraySelection } from "../traySelector";

export interface TrayScreen {
  render(selection: TraySelection): void;
  dispose(): void;
}

export function createTrayScreen(dispatch: Dispatch): TrayScreen {
  const bound = bindings();
  const tray = el("tray");
  const body = el("trayBody");
  const count = el("trayCount");
  const toggle = el("trayToggleBtn");

  /** The selection currently on screen — the authority on what a click means. */
  let painted: TraySelection = selectTray([], [], false);

  bound.add(delegate(toggle, "click", "#trayToggleBtn", () => dispatch({ kind: "tray/toggle" })));

  bound.add(
    delegate(body, "click", "[data-action]", (matched) => {
      const action = matched.dataset.action;
      const key = matched.dataset.key;
      if (action === "retry-resource" && matched.dataset.resource === "transfers") {
        dispatch({ kind: "resource/retry", resource: "transfers" });
        return;
      }
      if (action === undefined || key === undefined) return;
      const command = findTrayCommand(painted, action, key);
      if (command === null) return;
      dispatch({ kind: "tray/command", command });
    }),
  );

  function render(selection: TraySelection): void {
    painted = selection;

    tray.setAttribute("aria-hidden", String(!selection.open));
    tray.dataset.collapsed = String(selection.collapsed);
    toggle.toggleAttribute("disabled", !selection.open);
    toggle.setAttribute("aria-expanded", String(!selection.collapsed));
    toggle.setAttribute("aria-label", selection.collapsed ? "展开传输队列" : "收起传输队列");
    toggle.setAttribute("title", selection.collapsed ? "展开传输队列" : "收起传输队列");
    body.setAttribute("aria-hidden", String(selection.collapsed));

    if (!selection.open) {
      tray.dataset.open = "false";
      count.textContent = "";
      body.replaceChildren();
      return;
    }
    tray.dataset.open = "true";
    count.textContent = selection.countText;

    // Keep the delegated listener stable and reconcile rows by their opaque
    // backend identity. Progress updates replace only changed rows; a fast
    // stream never tears down every button/listener on each tick.
    const existing = new Map<string, Element>();
    body.querySelectorAll<HTMLElement>("[data-tray-key]").forEach((node) => {
      const key = node.dataset.trayKey;
      if (key !== undefined) existing.set(key, node);
    });
    const fragment = document.createDocumentFragment();
    if (selection.resourceError !== null) {
      const degraded = document.createElement("div");
      degraded.className = "resource-degraded";
      degraded.innerHTML =
        `<span>传输队列读取失败：${escapeHtml(selection.resourceError)}</span>` +
        `<button class="btn btn-sm btn-primary" data-action="retry-resource" data-resource="transfers" ${selection.resourceLoading ? "disabled" : ""}>` +
        `${selection.resourceLoading ? "重试中…" : "重试读取"}</button>`;
      fragment.append(degraded);
    }
    for (const item of selection.items) {
      const html = trayItemHtml(item);
      const key = item.kind === "job" ? `job:${item.jobId}` : `transfer:${item.transfer.key}`;
      const previous = existing.get(key);
      if (previous !== undefined && previous.outerHTML === html) {
        fragment.append(previous);
        existing.delete(key);
        continue;
      }
      const template = document.createElement("template");
      template.innerHTML = html;
      const next = template.content.firstElementChild;
      if (next !== null) fragment.append(next);
      existing.delete(key);
    }
    body.replaceChildren(fragment);
  }

  return { render, dispose: bound.dispose };
}
