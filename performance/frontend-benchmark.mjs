/* global structuredClone, console, process */
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { visibleSnapshotsEqual } from "../src/ui/visibleSnapshot.ts";
import { selectLibraryList } from "../src/ui/listSelector.ts";
import { createUiState } from "../src/store.ts";
import { libraryEntryKey } from "../src/types.ts";

const rows = Array.from({ length: 500 }, (_, index) => ({
  deviceId: "device-1",
  deviceDisplayId: "Device 1",
  sessionId: `session-${index}`,
  dateLabel: new Date(Date.UTC(2026, 0, 1) + ((index * 7919) % 10000) * 60_000).toISOString(),
  downloadedAt: "2026-09-08T00:00:00Z",
  bytes: 100_000_000,
  files: Array.from({ length: 10 }, (_, file) => ({
    name: `video-${file}.mp4`,
    bytes: 10_000_000,
    sha256: "a".repeat(64),
  })),
  complete: true,
  uploadStatus: "none",
  uploadedAt: null,
  uploadError: null,
  uploadRetryable: false,
}));
const clone = structuredClone(rows);
const changed = structuredClone(rows);
changed[0].uploadStatus = "done";
const ui = createUiState();

function legacySelection() {
  const visible = rows.filter(() => true);
  visible.sort((a, b) => {
    const parsedA = Date.parse(a.dateLabel);
    const parsedB = Date.parse(b.dateLabel);
    const ka = Number.isNaN(parsedA) ? libraryEntryKey(a) : String(parsedA).padStart(16, "0");
    const kb = Number.isNaN(parsedB) ? libraryEntryKey(b) : String(parsedB).padStart(16, "0");
    return kb.localeCompare(ka);
  });
  const visibleKeys = visible.map(libraryEntryKey);
  const existingKeys = rows.map(libraryEntryKey);
  return { visible, visibleKeys, existingKeys, selectedKeys: existingKeys.filter(() => false) };
}

assert.equal(visibleSnapshotsEqual(rows, clone), true);
assert.equal(visibleSnapshotsEqual(rows, changed), false);
assert.deepEqual(selectLibraryList(ui, rows).visible, legacySelection().visible);

function median(values) {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}

function compare(name, before, after) {
  for (let i = 0; i < 30; i++) {
    before();
    after();
  }
  const samples = { before: [], after: [] };
  for (let round = 0; round < 11; round++) {
    for (const [key, run] of round % 2
      ? [
          ["after", after],
          ["before", before],
        ]
      : [
          ["before", before],
          ["after", after],
        ]) {
      const start = performance.now();
      for (let iteration = 0; iteration < 50; iteration++) run();
      samples[key].push((performance.now() - start) / 50);
    }
  }
  const beforeMs = median(samples.before);
  const afterMs = median(samples.after);
  return { name, beforeMs, afterMs, speedup: beforeMs / afterMs };
}

console.log(
  JSON.stringify(
    {
      node: process.version,
      rows: rows.length,
      filesPerRow: rows[0].files.length,
      samples: 11,
      iterationsPerSample: 50,
      results: [
        compare(
          "equal snapshot",
          () => JSON.stringify(rows) === JSON.stringify(clone),
          () => visibleSnapshotsEqual(rows, clone),
        ),
        compare(
          "changed first row",
          () => JSON.stringify(rows) === JSON.stringify(changed),
          () => visibleSnapshotsEqual(rows, changed),
        ),
        compare("library selection", legacySelection, () => selectLibraryList(ui, rows)),
      ],
    },
    null,
    2,
  ),
);
