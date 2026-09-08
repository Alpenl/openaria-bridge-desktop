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

function updateRow(current: Element, incoming: Element): void {
  for (const attribute of Array.from(current.attributes)) {
    if (!incoming.hasAttribute(attribute.name)) current.removeAttribute(attribute.name);
  }
  for (const attribute of Array.from(incoming.attributes)) {
    if (current.getAttribute(attribute.name) !== attribute.value) {
      current.setAttribute(attribute.name, attribute.value);
    }
  }
  // Stats and meters change on every tick; unchanged control groups stay
  // attached, including the currently focused pause/cancel button.
  let cursor = current.firstElementChild;
  for (const child of Array.from(incoming.children)) {
    if (cursor === null) {
      current.append(child);
    } else {
      const next = cursor.nextElementSibling;
      if (cursor.outerHTML !== child.outerHTML) cursor.replaceWith(child);
      cursor = next;
    }
  }
  while (cursor !== null) {
    const next = cursor.nextElementSibling;
    cursor.remove();
    cursor = next;
  }
}

export function createTrayScreen(dispatch: Dispatch): TrayScreen {
  const bound = bindings();
  const tray = el("tray");
  const body = el("trayBody");
  const count = el("trayCount");
  const toggle = el("trayToggleBtn");

  /** The selection currently on screen — the authority on what a click means. */
  let painted: TraySelection = selectTray([], [], false);
  const rows = new Map<string, { node: Element; html: string }>();

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
      rows.clear();
      return;
    }
    tray.dataset.open = "true";
    count.textContent = selection.countText;

    // Cache row HTML so unchanged rows need no DOM inspection. Remove retired
    // jobs first so their remaining siblings do not have to move.
    const expectedKeys = new Set(
      selection.items.map((item) => (item.kind === "job" ? `job:${item.jobId}` : `transfer:${item.transfer.key}`)),
    );
    if (selection.resourceError !== null) expectedKeys.add("resource-error");
    for (const [key, row] of rows) {
      if (!expectedKeys.has(key)) {
        row.node.remove();
        rows.delete(key);
      }
    }
    let cursor = body.firstElementChild;
    function placeRow(key: string, html: string): void {
      let row = rows.get(key);
      if (row === undefined || row.html !== html) {
        const template = document.createElement("template");
        template.innerHTML = html;
        const node = template.content.firstElementChild;
        if (node === null) return;
        if (row !== undefined) {
          updateRow(row.node, node);
          row.html = html;
        } else {
          row = { node, html };
          rows.set(key, row);
        }
      }
      if (row.node !== cursor) body.insertBefore(row.node, cursor);
      cursor = row.node.nextElementSibling;
    }

    if (selection.resourceError !== null) {
      placeRow(
        "resource-error",
        '<div class="resource-degraded">' +
          `<span>传输队列读取失败：${escapeHtml(selection.resourceError)}</span>` +
          `<button class="btn btn-sm btn-primary" data-action="retry-resource" data-resource="transfers" ${selection.resourceLoading ? "disabled" : ""}>` +
          `${selection.resourceLoading ? "重试中…" : "重试读取"}</button></div>`,
      );
    }
    for (const item of selection.items) {
      const key = item.kind === "job" ? `job:${item.jobId}` : `transfer:${item.transfer.key}`;
      placeRow(key, trayItemHtml(item));
    }
  }

  return { render, dispose: bound.dispose };
}
