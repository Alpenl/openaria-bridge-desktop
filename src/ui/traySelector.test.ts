// The one transfer selector: visible items, active count, tone and controls
// must all agree, because they are now decided together.
import { test } from "node:test";
import assert from "node:assert/strict";

import { findTrayCommand, selectTray } from "./traySelector";
import {
  transferError,
  transferProgress,
  transferStateIsActive,
  transferStateIsTerminal,
  type Transfer,
  type TransferJobEvent,
} from "../types";

function transfer(overrides: Partial<Transfer> = {}): Transfer {
  return {
    key: "YLX-A|s1",
    label: "s1",
    totalBytes: 100,
    sentBytes: 50,
    state: "running",
    retryable: false,
    error: null,
    direction: "up",
    targetLabel: "my-bucket",
    ...overrides,
  };
}

function job(overrides: Partial<TransferJobEvent> = {}): TransferJobEvent {
  return {
    jobId: "job-1",
    state: { state: "transferring" },
    sessionId: "s1",
    deviceId: "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    deviceDisplayId: "YLX-ABCDEF01",
    totalBytes: 100,
    transferredBytes: 10,
    filesTotal: 1,
    filesDone: 0,
    desiredRunState: "run",
    ...overrides,
  };
}

test("a desired-paused job is visible, not active, and offers resume", () => {
  const selection = selectTray([], [job({ desiredRunState: "paused" })], false);

  const [item] = selection.items;
  assert.equal(item.kind, "job");
  assert.equal(item.tone, "paused");
  assert.equal(item.countsActive, false);
  assert.equal(selection.activeCount, 0, "a paused job is never counted as 进行中");
  assert.equal(selection.countText, "全部完成");
  assert.deepEqual(
    item.controls.map((control) => control.action),
    ["resume-transfer-job", "cancel-transfer-job"],
  );
});

// This is exactly where the duplicated rules used to disagree: the combined
// counter called a paused job active while the row rendered it 已暂停.
test("the count and the row tone agree about pausing", () => {
  const selection = selectTray([], [job(), job({ jobId: "job-2", desiredRunState: "paused" })], false);

  assert.equal(selection.activeCount, 1);
  assert.equal(selection.countText, "1 项进行中");
  assert.deepEqual(
    selection.jobs.map((item) => item.tone),
    ["active", "paused"],
  );
});

test("a terminal job's stale desired run state never reads as paused", () => {
  for (const state of ["cancelled"] as const) {
    const [item] = selectTray([], [job({ state: { state }, desiredRunState: "paused" })], false).jobs;
    assert.equal(item.paused, false, state);
    assert.equal(item.terminal, true, state);
    assert.equal(item.tone, "failed", state);
  }

  const succeeded = selectTray([], [job({ state: { state: "succeeded" }, desiredRunState: "paused" })], false);
  assert.deepEqual(succeeded.items, [], "a succeeded job retires itself");
});

test("failed and cancelled work is counted as failed, never as complete", () => {
  const selection = selectTray(
    [transfer({ state: "failed", error: "S3 rejected" })],
    [job({ state: { state: "cancelled" } })],
    false,
  );

  assert.equal(selection.activeCount, 0);
  assert.equal(selection.failedCount, 2);
  assert.equal(selection.countText, "2 项失败或取消");
});

test("a settled success leaves the tray while everything else stays", () => {
  const selection = selectTray(
    [transfer({ key: "done", state: "succeeded" }), transfer({ key: "live" })],
    [job({ jobId: "gone", state: { state: "succeeded" } }), job({ jobId: "stays" })],
    false,
  );

  assert.deepEqual(
    selection.items.map((item) => (item.kind === "job" ? item.job.jobId : item.transfer.key)),
    ["stays", "live"],
    "jobs render before transfers, and settled successes render at all",
  );
  assert.equal(selection.open, true);
  assert.equal(selectTray([], [], false).open, false);
});

test("a non-retryable failure offers dismiss only", () => {
  const retryable = selectTray([], [job({ state: { state: "failed", code: "network", retryable: true } })], false);
  assert.deepEqual(
    retryable.jobs[0].controls.map((control) => control.action),
    ["retry-transfer", "dismiss-transfer-job"],
  );

  const terminal = selectTray(
    [],
    [job({ state: { state: "failed", code: "hash_mismatch", retryable: false } })],
    false,
  );
  assert.deepEqual(
    terminal.jobs[0].controls.map((control) => control.action),
    ["dismiss-transfer-job"],
  );
});

test("a job that is tearing down offers no controls at all", () => {
  assert.deepEqual(selectTray([], [job({ state: { state: "cancelling" } })], false).jobs[0].controls, []);
});

test("a finalizing upload stays visible without cancel or retry controls", () => {
  const selection = selectTray([transfer({ state: "finalizing" })], [], false);
  const item = selection.transfers[0];
  assert.ok(item);
  assert.equal(item.tone, "active");
  assert.equal(item.countsActive, true);
  assert.deepEqual(item.controls, []);
  assert.equal(selection.activeCount, 1);
  assert.equal(selection.failedCount, 0);
  assert.equal(findTrayCommand(selection, "retry-transfer", "YLX-A|s1"), null);
  assert.equal(findTrayCommand(selection, "cancel-upload", "YLX-A|s1"), null);
});

// Only an upload can be aborted mid-flight, and the control that does it
// carries an upload identity — the type system, not a string convention, is
// what stops a download job id reaching `cancel_upload`.
test("only a live upload offers cancel, and it addresses an upload identity", () => {
  const upload = selectTray([transfer({ direction: "up" })], [], false);
  const command = findTrayCommand(upload, "cancel-upload", "YLX-A|s1");
  assert.deepEqual(command, { kind: "cancelUpload", jobId: "YLX-A|s1" });

  const download = selectTray([transfer({ direction: "down" })], [], false);
  assert.deepEqual(download.transfers[0].controls, [], "downloads are cancelled through their coordinator job");
});

test("a cancelled upload remains visible with only its dismiss control", () => {
  const cancelled = selectTray([transfer({ state: "cancelled", direction: "up" })], [], false);

  assert.equal(cancelled.transfers.length, 1, "the durable upload row remains reachable until dismissal");
  assert.equal(cancelled.transfers[0].tone, "failed");
  assert.deepEqual(
    cancelled.transfers[0].controls.map((control) => control.action),
    ["dismiss-upload"],
  );
  assert.deepEqual(findTrayCommand(cancelled, "dismiss-upload", "YLX-A|s1"), {
    kind: "dismissUpload",
    jobId: "YLX-A|s1",
  });
  assert.equal(findTrayCommand(cancelled, "retry-transfer", "YLX-A|s1"), null);
  assert.equal(cancelled.failedCount, 1);
  assert.equal(cancelled.open, true);

  const dismissed = selectTray([], [], false);
  assert.deepEqual(dismissed.transfers, [], "a backend-dismissed row does not reappear");
  assert.equal(dismissed.open, false);

  const cancelledDownload = selectTray([transfer({ state: "cancelled", direction: "down" })], [], false);
  assert.deepEqual(cancelledDownload.transfers, [], "download dismissal stays owned by the coordinator job");
});

test("a clicked control resolves back to the typed command that rendered it", () => {
  const selection = selectTray([transfer({ state: "failed", retryable: true, error: "S3 rejected" })], [job()], false);

  assert.deepEqual(findTrayCommand(selection, "pause-transfer-job", "job-1"), { kind: "pauseJob", jobId: "job-1" });
  assert.deepEqual(findTrayCommand(selection, "retry-transfer", "YLX-A|s1"), { kind: "retry", id: "YLX-A|s1" });
  assert.equal(
    findTrayCommand(selection, "cancel-transfer-job", "job-never-rendered"),
    null,
    "a key the tray did not render is not a command",
  );
  assert.equal(findTrayCommand(selection, "pause-transfer-job", "YLX-A|s1"), null, "action and key must both match");
});

test("a non-retryable transfer failure offers dismissal but no retry", () => {
  const selection = selectTray([transfer({ state: "failed", error: "permanent rejection" })], [], false);

  assert.deepEqual(
    selection.transfers[0]?.controls.map((control) => control.action),
    ["dismiss-upload"],
  );
  assert.equal(findTrayCommand(selection, "retry-transfer", "YLX-A|s1"), null);
});

test("the collapsed flag is carried through untouched", () => {
  assert.equal(selectTray([transfer()], [], true).collapsed, true);
  assert.equal(selectTray([transfer()], [], false).collapsed, false);
});

test("a degraded transfer resource keeps cached rows and opens a scoped retry surface", () => {
  const selection = selectTray([transfer()], [], false, { error: "queue unavailable", loading: false });

  assert.equal(selection.open, true);
  assert.equal(selection.resourceError, "queue unavailable");
  assert.equal(selection.resourceLoading, false);
  assert.equal(selection.items.length, 1, "the cached transfer row remains visible");
  assert.equal(selection.countText, "队列读取失败");
});

test("tagged Transfer states drive active/terminal/progress/error helpers", () => {
  assert.equal(transferStateIsActive("queued"), true);
  assert.equal(transferStateIsActive("running"), true);
  assert.equal(transferStateIsActive("finalizing"), true);
  assert.equal(transferStateIsActive("paused"), true);
  assert.equal(transferStateIsActive("cancelling"), true);
  assert.equal(transferStateIsTerminal("succeeded"), true);
  assert.equal(transferStateIsTerminal("failed"), true);
  assert.equal(transferStateIsTerminal("cancelled"), true);
  assert.equal(transferStateIsTerminal("finalizing"), false);
  assert.equal(transferStateIsTerminal("running"), false);

  const running = transfer({ totalBytes: 3, sentBytes: 1 });
  assert.equal(transferProgress(running), 33);
  assert.equal(transferProgress(transfer({ totalBytes: 0, sentBytes: 0 })), null);
  assert.equal(transferError(transfer({ state: "running", error: "stale" })), "stale");
  assert.equal(transferError(transfer({ state: "failed", error: "network" })), "network");
});
