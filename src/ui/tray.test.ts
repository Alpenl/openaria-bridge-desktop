// Regression test for the XSS-via-Pi-controlled-fields vulnerability (SEC-01),
// covering the secondary sink flagged by the security review: main.ts line
// ~777-778 assigns `transferJobItemHtml`/`transferItemHtml` output to
// `.innerHTML`. `Transfer.label` is set to a Pi-controlled session_id (see
// composition.rs: `label: entry.session_id.clone()`), and `Transfer.error`/
// `FailureCode::Other`'s payload can embed Pi-derived error text (see
// `classify_download_error` in coordinator.rs). Neither must be able to
// inject raw markup.
//
// Run with:
//   node --import ./src/test-support/register-loader.mjs --test src/ui/tray.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";

import { transferItemHtml, transferJobCountText, transferJobItemHtml } from "./tray";
import { selectTray, transferJobControls } from "./traySelector";
import type { Transfer, TransferJobEvent } from "../types";

const PAYLOAD = `<img src=x onerror="alert(1)">`;
const DEVICE_ID = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DEVICE_DISPLAY_ID = "YLX-ABCDEF01";

function baseTransfer(overrides: Partial<Transfer> = {}): Transfer {
  return {
    key: "key-1",
    label: "sess-1",
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

test("transferItemHtml escapes a malicious label (Pi-derived session_id)", () => {
  const html = transferItemHtml(baseTransfer({ label: PAYLOAD }));
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("transferItemHtml escapes a malicious error message", () => {
  const html = transferItemHtml(baseTransfer({ state: "failed", error: PAYLOAD }));
  assert.ok(!html.includes("<img"), `expected no literal <img tag in error text, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("transferItemHtml escapes a malicious key inside the retry button's data-key attribute", () => {
  const html = transferItemHtml(baseTransfer({ state: "failed", key: PAYLOAD }));
  assert.ok(!html.includes(`data-key="${PAYLOAD}"`), `payload leaked unescaped into data-key: ${html}`);
});

test("an in-flight upload can be cancelled by its library key", () => {
  const html = transferItemHtml(baseTransfer());
  assert.ok(html.includes('data-action="cancel-upload"'));
  assert.ok(html.includes('data-key="key-1"'));
});

test("paused and cancelling states do not regress to the old boolean model", () => {
  const paused = transferItemHtml(baseTransfer({ state: "paused" }));
  assert.ok(paused.includes("已暂停"));
  assert.ok(!paused.includes("job-meter-indeterminate"), "paused work must not look active");
  assert.ok(paused.includes('data-action="cancel-upload"'));

  const cancelling = transferItemHtml(baseTransfer({ state: "cancelling" }));
  assert.ok(cancelling.includes("取消中"));
  assert.ok(!cancelling.includes('data-action="cancel-upload"'));
});

test("finalizing upload renders visible projection work without actions", () => {
  const html = transferItemHtml(baseTransfer({ state: "finalizing" }));
  assert.ok(html.includes("收尾中"));
  assert.ok(html.includes('data-state="finalizing"'));
  assert.ok(!html.includes("data-action="));
});

test("cancel-upload escapes a malicious key and never appears on a settled upload", () => {
  const malicious = transferItemHtml(baseTransfer({ key: PAYLOAD }));
  assert.ok(!malicious.includes(`data-key="${PAYLOAD}"`), `payload leaked unescaped: ${malicious}`);

  for (const overrides of [{ state: "succeeded" as const }, { state: "failed" as const, error: "S3 rejected" }]) {
    assert.ok(!transferItemHtml(baseTransfer(overrides)).includes('data-action="cancel-upload"'));
  }
});

test("a failed upload can be retried or cleared", () => {
  const html = transferItemHtml(baseTransfer({ state: "failed", retryable: true, error: "S3 rejected" }));
  assert.ok(html.includes('data-action="retry-transfer"'));
  assert.ok(html.includes('data-action="dismiss-upload"'));
  assert.ok(html.includes('data-key="key-1"'));
});

// Downloads run through the coordinator, which owns cancellation via
// `cancel_transfer_job` -- there is no `cancel_upload` for them.
test("download rows do not offer the upload-only cancel control", () => {
  const html = transferItemHtml(baseTransfer({ direction: "down" }));
  assert.ok(!html.includes('data-action="cancel-upload"'));
});

function baseJob(overrides: Partial<TransferJobEvent> = {}): TransferJobEvent {
  return {
    jobId: "job-1",
    state: { state: "transferring" },
    sessionId: "sess-1",
    deviceId: DEVICE_ID,
    deviceDisplayId: DEVICE_DISPLAY_ID,
    totalBytes: 0,
    transferredBytes: 0,
    filesTotal: 1,
    filesDone: 0,
    desiredRunState: "run",
    ...overrides,
  };
}

test("transferJobItemHtml escapes a malicious FailureCode::Other payload", () => {
  const html = transferJobItemHtml(baseJob({ state: { state: "failed", code: { other: PAYLOAD }, retryable: true } }));
  assert.ok(!html.includes("<img"), `expected no literal <img tag in failure text, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("transferJobItemHtml still renders normal jobs without visible entities", () => {
  const html = transferJobItemHtml(baseJob());
  assert.ok(html.includes("sess-1"));
  assert.ok(html.includes("传输中"));
});

test("transferJobItemHtml titles a job by its session id, not its opaque job id", () => {
  const html = transferJobItemHtml(baseJob({ sessionId: "2026-04-01T09-30-00Z" }));
  assert.ok(html.includes("2026-04-01T09-30-00Z"));
});

test("transferJobItemHtml falls back to a truncated job id when the session is not resolved yet", () => {
  const html = transferJobItemHtml(
    baseJob({ jobId: "job-0123456789abcdef", sessionId: null, deviceId: null, deviceDisplayId: null }),
  );
  assert.ok(html.includes("job-012345…"), `expected a truncated job id, got: ${html}`);
  assert.ok(!html.includes("job-0123456789abcdef</span>"));
});

test("transferJobItemHtml escapes a malicious Pi-supplied session id", () => {
  const html = transferJobItemHtml(baseJob({ sessionId: PAYLOAD }));
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("transferJobItemHtml escapes a malicious Pi-supplied device display id", () => {
  const html = transferJobItemHtml(baseJob({ deviceDisplayId: PAYLOAD }));
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("transferJobItemHtml escapes a malicious job id inside every control's data-key", () => {
  const html = transferJobItemHtml(baseJob({ jobId: PAYLOAD }));
  assert.ok(!html.includes(`data-key="${PAYLOAD}"`), `payload leaked unescaped into data-key: ${html}`);
  assert.ok(html.includes('data-action="pause-transfer-job"'));
});

test("transferJobItemHtml reports real byte progress with a determinate meter", () => {
  const html = transferJobItemHtml(baseJob({ totalBytes: 2048, transferredBytes: 512 }));
  assert.ok(html.includes("25%"));
  assert.ok(html.includes("512 B / 2.0 KB"));
  assert.ok(html.includes(`style="width:25%"`));
  assert.ok(!html.includes("job-meter-indeterminate"));
});

test("transferJobItemHtml never fabricates a percentage while the manifest is unknown", () => {
  const html = transferJobItemHtml(baseJob({ totalBytes: 0, transferredBytes: 0 }));
  assert.ok(html.includes("job-meter-indeterminate"));
  assert.ok(!html.includes("%"));
});

test("transferJobItemHtml clamps a backend over-report to 100 percent", () => {
  const html = transferJobItemHtml(baseJob({ totalBytes: 100, transferredBytes: 250 }));
  assert.ok(html.includes("100%"));
  assert.ok(html.includes(`style="width:100%"`));
});

test("transferJobItemHtml shows a file counter only for multi-file sessions", () => {
  const multi = transferJobItemHtml(baseJob({ filesTotal: 4, filesDone: 2 }));
  assert.ok(multi.includes("2/4 个文件"));

  const single = transferJobItemHtml(baseJob({ filesTotal: 1, filesDone: 0 }));
  assert.ok(!single.includes("个文件"));
});

test("an actively transferring job can be paused or cancelled", () => {
  assert.deepEqual(transferJobControls({ state: "transferring" }, false), ["pause", "cancel"]);
  const html = transferJobItemHtml(baseJob());
  assert.ok(html.includes('data-action="pause-transfer-job"'));
  assert.ok(html.includes('data-action="cancel-transfer-job"'));
  assert.ok(!html.includes('data-action="resume-transfer-job"'));
});

// The backend parks a paused job back in `queued`/`waiting_*`, which is
// state-for-state identical to a job that was never started. The desired run
// state -- not the lifecycle state -- is the only thing allowed to decide which it is.
test("queued and waiting states only offer cancellation unless the backend says so", () => {
  for (const state of ["queued", "waiting_for_device", "waiting_for_pairing", "preparing", "retry_wait"] as const) {
    assert.deepEqual(transferJobControls({ state }, false), ["cancel"], state);
    const html = transferJobItemHtml(baseJob({ state: { state } }));
    assert.ok(!html.includes("已暂停"), `${state} invented a paused label: ${html}`);
    assert.ok(!html.includes('data-action="resume-transfer-job"'), state);
    assert.ok(!html.includes('data-action="pause-transfer-job"'), state);
  }
});

test("the same states report 已暂停 and offer resume once desired run state is paused", () => {
  for (const state of ["queued", "waiting_for_device", "waiting_for_pairing", "preparing", "retry_wait"] as const) {
    assert.deepEqual(transferJobControls({ state }, true), ["resume", "cancel"], state);
    const html = transferJobItemHtml(baseJob({ state: { state }, desiredRunState: "paused" }));
    assert.ok(html.includes("已暂停"), `${state} lost the paused label: ${html}`);
    assert.ok(html.includes('data-action="resume-transfer-job"'), state);
    assert.ok(!html.includes('data-action="pause-transfer-job"'), state);
  }
});

// A paused job with no known total must not keep an animated bar running:
// that reads as "still working". A known percentage stays, frozen.
test("a paused job shows frozen progress, never an animated bar", () => {
  const unknownTotal = transferJobItemHtml(baseJob({ desiredRunState: "paused" }));
  assert.ok(!unknownTotal.includes("job-meter-indeterminate"), unknownTotal);

  const knownTotal = transferJobItemHtml(
    baseJob({ desiredRunState: "paused", totalBytes: 400, transferredBytes: 100 }),
  );
  assert.ok(knownTotal.includes("width:25%"), knownTotal);
  assert.ok(!knownTotal.includes("job-meter-indeterminate"));
});

test("a paused job is not counted as 进行中", () => {
  assert.equal(transferJobCountText([baseJob({ desiredRunState: "paused" })]), "全部完成");
  assert.equal(transferJobCountText([baseJob(), baseJob({ desiredRunState: "paused" })]), "1 项进行中");
});

// `paused_capture_active` is the device's decision, not the user's: the
// coordinator re-dispatches by itself once capture goes idle, so offering
// 继续 would imply a control the user does not have.
test("capture-paused offers only cancel unless the user also paused it", () => {
  assert.deepEqual(transferJobControls({ state: "paused_capture_active" }, false), ["cancel"]);
  const html = transferJobItemHtml(baseJob({ state: { state: "paused_capture_active" } }));
  assert.ok(html.includes("设备正在采集"));
  assert.ok(html.includes('data-action="cancel-transfer-job"'));
  assert.ok(!html.includes('data-action="resume-transfer-job"'));
  assert.ok(!html.includes('data-action="pause-transfer-job"'));

  assert.deepEqual(transferJobControls({ state: "paused_capture_active" }, true), ["resume", "cancel"]);
});

// A terminal job's desired run state is stale bookkeeping from before it settled.
test("a settled job never renders as paused", () => {
  for (const state of ["succeeded", "cancelled"] as const) {
    const html = transferJobItemHtml(baseJob({ state: { state }, desiredRunState: "paused" }));
    assert.ok(!html.includes("已暂停"), `${state} rendered a stale paused label: ${html}`);
    assert.ok(!html.includes('data-action="resume-transfer-job"'), state);
  }
});

test("successful jobs retire automatically while cancelled jobs can be cleared", () => {
  assert.deepEqual(transferJobControls({ state: "succeeded" }, false), []);
  assert.ok(!transferJobItemHtml(baseJob({ state: { state: "succeeded" } })).includes("data-action="));

  assert.deepEqual(transferJobControls({ state: "cancelled" }, false), ["dismiss"]);
  const cancelled = transferJobItemHtml(baseJob({ state: { state: "cancelled" } }));
  assert.ok(!cancelled.includes('data-action="pause-transfer-job"'));
  assert.ok(!cancelled.includes('data-action="cancel-transfer-job"'));
  assert.ok(cancelled.includes('data-action="dismiss-transfer-job"'));

  assert.deepEqual(transferJobControls({ state: "cancelling" }, false), []);
  assert.ok(!transferJobItemHtml(baseJob({ state: { state: "cancelling" } })).includes("data-action="));
});

test("a failed job offers retry and dismiss, never pause or cancel", () => {
  const html = transferJobItemHtml(baseJob({ state: { state: "failed", code: "network", retryable: true } }));
  assert.ok(html.includes('data-action="retry-transfer"'));
  assert.ok(html.includes('data-action="dismiss-transfer-job"'));
  assert.ok(!html.includes('data-action="pause-transfer-job"'));
  assert.ok(!html.includes('data-action="cancel-transfer-job"'));
});

test("transferJobItemHtml offers retry only when a failed real job is retryable", () => {
  const retryable = transferJobItemHtml(baseJob({ state: { state: "failed", code: "network", retryable: true } }));
  assert.ok(retryable.includes('data-action="retry-transfer"'));
  assert.ok(retryable.includes('data-key="job-1"'));

  const terminal = transferJobItemHtml(
    baseJob({ state: { state: "failed", code: "hash_mismatch", retryable: false } }),
  );
  assert.ok(!terminal.includes('data-action="retry-transfer"'));
  assert.ok(terminal.includes('data-action="dismiss-transfer-job"'));
});

test("transferJobItemHtml escapes a real job id in the retry button", () => {
  const html = transferJobItemHtml(
    baseJob({ jobId: PAYLOAD, state: { state: "failed", code: "network", retryable: true } }),
  );
  assert.ok(!html.includes(`data-key="${PAYLOAD}"`));
  assert.ok(html.includes('data-action="retry-transfer"'));
});

test("the tray selector counts real uploads and downloads together", () => {
  assert.equal(selectTray([baseTransfer()], [baseJob()], false).countText, "2 项进行中");
});

test("the tray selector does not call failed or cancelled work complete", () => {
  assert.equal(
    selectTray(
      [baseTransfer({ state: "failed", error: "S3 rejected" })],
      [baseJob({ state: { state: "cancelled" } })],
      false,
    ).countText,
    "2 项失败或取消",
  );
});

test("successful work is omitted from the active tray but failures and cancellations remain", () => {
  const visible = selectTray(
    [baseTransfer({ key: "upload-done", state: "succeeded" }), baseTransfer({ key: "upload-failed", state: "failed" })],
    [
      baseJob({ jobId: "download-done", state: { state: "succeeded" } }),
      baseJob({ jobId: "download-cancelled", state: { state: "cancelled" } }),
    ],
    true,
  );

  assert.deepEqual(
    visible.transfers.map((item) => item.transfer.key),
    ["upload-failed"],
  );
  assert.deepEqual(
    visible.jobs.map((item) => item.job.jobId),
    ["download-cancelled"],
  );
  assert.equal(visible.open, true);
  assert.equal(visible.collapsed, true);

  const progressed = selectTray(
    [baseTransfer({ key: "upload-failed", state: "failed", sentBytes: 80 })],
    [baseJob({ jobId: "download-cancelled", state: { state: "cancelled" }, transferredBytes: 80 })],
    visible.collapsed,
  );
  assert.equal(progressed.collapsed, true);
});

test("a failed tagged state remains visible with retry controls", () => {
  const selection = selectTray(
    [{ ...baseTransfer(), state: "failed", retryable: true, error: "checksum mismatch" }],
    [],
    false,
  );
  assert.equal(selection.failedCount, 1);
  assert.equal(selection.transfers[0]?.tone, "failed");
  assert.equal(selection.transfers[0]?.controls[0]?.action, "retry-transfer");
});

test("a non-retryable transfer failure remains dismissible without retry", () => {
  const selection = selectTray([baseTransfer({ state: "failed", error: "permanent rejection" })], [], false);
  assert.deepEqual(
    selection.transfers[0]?.controls.map((control) => control.action),
    ["dismiss-upload"],
  );
});

test("unknown total bytes renders indeterminate progress instead of fabricated 100 percent", () => {
  const html = transferItemHtml(baseTransfer({ totalBytes: 0, sentBytes: 0 }));
  assert.ok(html.includes("job-meter-indeterminate"));
  assert.ok(!html.includes("100%"));
});
