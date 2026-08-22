// The toolbar, selection and bulk controls, which the device pane and the
// library pane render identically. One set of delegated listeners on `#content`
// serves both; the scope is resolved when the event fires, not when the
// listener is installed, so switching views needs no rebinding.

import type { Dispatch } from "../../app/actions";
import { bindings, delegate, type Unbind } from "../dom";
import type { FilterState, SelectionScope } from "../../store";

export function installListEvents(
  content: HTMLElement,
  dispatch: Dispatch,
  scope: () => SelectionScope,
): { dispose: Unbind } {
  const bound = bindings();

  bound.add(
    delegate(content, "input", "#searchInput", (matched) => {
      dispatch({ kind: "list/filter", scope: scope(), patch: { query: (matched as HTMLInputElement).value } });
    }),
  );

  bound.add(
    delegate(content, "click", "#filterPills [data-filter-status]", (matched) => {
      const status = matched.dataset.filterStatus as FilterState["status"] | undefined;
      if (status === undefined) return;
      dispatch({ kind: "list/filter", scope: scope(), patch: { status } });
    }),
  );

  bound.add(
    delegate(content, "click", "#sortBtn", () => {
      dispatch({ kind: "list/toggleSort", scope: scope() });
    }),
  );

  bound.add(
    delegate(content, "change", "#selectAllBox", (matched) => {
      dispatch({ kind: "list/selectAll", scope: scope(), selected: (matched as HTMLInputElement).checked });
    }),
  );

  bound.add(
    delegate(content, "change", "input[data-select]", (matched) => {
      const key = matched.dataset.select;
      if (key === undefined) return;
      dispatch({ kind: "list/select", scope: scope(), key, selected: (matched as HTMLInputElement).checked });
    }),
  );

  bound.add(delegate(content, "click", "#bulkActionBtn", () => dispatch({ kind: "list/bulkAction", scope: scope() })));
  bound.add(delegate(content, "click", "#bulkRemoveBtn", () => dispatch({ kind: "list/bulkRemove", scope: scope() })));
  bound.add(
    delegate(content, "click", "#bulkClearBtn", () => dispatch({ kind: "list/clearSelection", scope: scope() })),
  );

  return { dispose: bound.dispose };
}

/** Repaints the toolbar's stateful bits without rebuilding the search field —
 * re-rendering the input would drop the caret while the user is typing. */
export function syncToolbar(content: HTMLElement, filter: FilterState): void {
  content.querySelectorAll<HTMLButtonElement>("#filterPills [data-filter-status]").forEach((pill) => {
    pill.dataset.on = String(pill.dataset.filterStatus === filter.status);
  });
  const sortBtn = content.querySelector<HTMLButtonElement>("#sortBtn");
  if (sortBtn) sortBtn.textContent = filter.sortDesc ? "最新优先" : "最早优先";
}
