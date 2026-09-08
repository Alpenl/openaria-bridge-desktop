import { test } from "node:test";
import assert from "node:assert/strict";
import { createUiState, filterFor, selectionFor } from "../store";
import { libraryEntryKey, type LibraryEntry } from "../types";
import { selectLibraryList } from "./listSelector";

function entry(
  sessionId: string,
  dateLabel: string,
  uploadStatus: LibraryEntry["uploadStatus"] = "none",
): LibraryEntry {
  return {
    deviceId: "device-1",
    deviceDisplayId: "Device 1",
    sessionId,
    dateLabel,
    downloadedAt: dateLabel,
    bytes: 100,
    files: [],
    complete: true,
    uploadStatus,
    uploadedAt: null,
    uploadError: null,
    uploadRetryable: false,
  };
}

test("precomputed date keys preserve both sort directions and stable ties", () => {
  const ui = createUiState();
  const rows = [
    entry("later", "2026-09-08T12:00:00Z"),
    entry("same-time-first", "2026-09-07T12:00:00Z"),
    entry("same-time-second", "2026-09-07T20:00:00+08:00"),
    entry("invalid", "unknown"),
  ];
  const original = [...rows];
  for (const descending of [true, false]) {
    filterFor(ui, "library").sortDesc = descending;
    const expected = [...rows].sort((a, b) => {
      const key = (row: LibraryEntry): string => {
        const parsed = Date.parse(row.dateLabel);
        return Number.isNaN(parsed) ? libraryEntryKey(row) : String(parsed).padStart(16, "0");
      };
      return descending ? key(b).localeCompare(key(a)) : key(a).localeCompare(key(b));
    });
    assert.deepEqual(selectLibraryList(ui, rows).visible, expected);
  }
  assert.deepEqual(rows, original);
});

test("filtering and hidden selections retain their existing behavior", () => {
  const ui = createUiState();
  const done = entry("take-done", "2026-09-08", "done");
  const pending = entry("take-pending", "2026-09-07");
  const other = entry("other", "2026-09-06");
  const filter = filterFor(ui, "library");
  filter.query = " TAKE ";
  filter.status = "pending";
  selectionFor(ui, "library").add(libraryEntryKey(done));
  selectionFor(ui, "library").add(libraryEntryKey(pending));
  selectionFor(ui, "library").add("deleted");
  const result = selectLibraryList(ui, [done, pending, other]);
  assert.deepEqual(result.visible, [pending]);
  assert.deepEqual(result.selectedKeys, [libraryEntryKey(done), libraryEntryKey(pending)]);
  assert.equal(result.allVisibleSelected, true);
  assert.equal(result.countText, "1 / 3 项");
});
