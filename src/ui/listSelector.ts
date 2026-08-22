// Search / filter / sort for the two list views, in one place.
//
// Both the device pane and the library pane filter by query, filter by
// done-ness, sort by date and then intersect the selection with what actually
// exists. The rules are identical; only the accessors differ, so they are
// parameters rather than two copies.

import { deviceRowKey, filterFor, libraryRowKey, selectionFor, type SelectionScope, type UiState } from "../store";
import { libraryEntryKey, type LibraryEntry, type SessionView } from "../types";

export type ListEntity = SessionView | LibraryEntry;

export interface ListSelection<T extends ListEntity> {
  readonly scope: SelectionScope;
  /** Everything the view holds, before filtering. */
  readonly items: readonly T[];
  /** What the list actually renders, filtered and sorted. */
  readonly visible: readonly T[];
  /** Selection keys of `visible`, in render order. */
  readonly visibleKeys: readonly string[];
  /** Every key that exists at all — what the selection is intersected with. */
  readonly existingKeys: readonly string[];
  /** Currently selected keys that still exist. */
  readonly selectedKeys: readonly string[];
  readonly allVisibleSelected: boolean;
  readonly countText: string;
}

interface Accessors<T extends ListEntity> {
  key(item: T): string;
  searchId(item: T): string;
  done(item: T): boolean;
}

const DEVICE_ACCESSORS: Accessors<SessionView> = {
  key: (session) => session.id,
  searchId: (session) => session.id,
  done: (session) => session.downloadStatus === "done",
};

const LIBRARY_ACCESSORS: Accessors<LibraryEntry> = {
  key: (entry) => libraryEntryKey(entry),
  searchId: (entry) => entry.sessionId,
  done: (entry) => entry.uploadStatus === "done",
};

function select<T extends ListEntity>(
  ui: UiState,
  scope: SelectionScope,
  items: readonly T[],
  accessors: Accessors<T>,
): ListSelection<T> {
  const filter = filterFor(ui, scope);
  const query = filter.query.trim().toLowerCase();

  const visible = items.filter((item) => {
    const idStr = accessors.searchId(item);
    const dateStr = item.dateLabel ?? "";
    const matchesQuery = !query || idStr.toLowerCase().includes(query) || dateStr.toLowerCase().includes(query);
    if (!matchesQuery) return false;
    if (filter.status === "all") return true;
    const done = accessors.done(item);
    return filter.status === "done" ? done : !done;
  });

  visible.sort((a, b) => {
    const parsedA = Date.parse(a.dateLabel);
    const parsedB = Date.parse(b.dateLabel);
    const ka = Number.isNaN(parsedA) ? accessors.key(a) : String(parsedA).padStart(16, "0");
    const kb = Number.isNaN(parsedB) ? accessors.key(b) : String(parsedB).padStart(16, "0");
    return filter.sortDesc ? kb.localeCompare(ka) : ka.localeCompare(kb);
  });

  const selection = selectionFor(ui, scope);
  const visibleKeys = visible.map((item) => accessors.key(item));
  const existingKeys = items.map((item) => accessors.key(item));

  return {
    scope,
    items,
    visible,
    visibleKeys,
    existingKeys,
    selectedKeys: existingKeys.filter((key) => selection.has(key)),
    allVisibleSelected: visibleKeys.length > 0 && visibleKeys.every((key) => selection.has(key)),
    countText: `${visible.length} / ${items.length} 项`,
  };
}

export function selectDeviceList(ui: UiState, sessions: readonly SessionView[]): ListSelection<SessionView> {
  return select(ui, "device", sessions, DEVICE_ACCESSORS);
}

export function selectLibraryList(ui: UiState, library: readonly LibraryEntry[]): ListSelection<LibraryEntry> {
  return select(ui, "library", library, LIBRARY_ACCESSORS);
}

/** The confirmation/expansion key for one row. Device rows are scoped by
 * device: the same session id on two devices is two different rows. */
export function rowKeyFor(scope: SelectionScope, ownerId: string, itemKey: string): string {
  return scope === "device" ? deviceRowKey(ownerId, itemKey) : libraryRowKey(itemKey);
}
