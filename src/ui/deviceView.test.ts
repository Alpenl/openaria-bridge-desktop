// Regression test for the XSS-via-Pi-controlled-fields vulnerability (SEC-01):
// `session.id`/`session.dateLabel`/each file's `path` are deserialized
// straight out of a Pi HTTP response body (pi_http.rs's `SessionSummary`/
// `SessionDetail`/`SessionFileEntry`), and `sessionRowHtml`'s output is
// assigned to `.innerHTML` in main.ts. A malicious or spoofed Pi must not be
// able to get raw markup/script into that string.
//
// Run with:
//   node --import ./src/test-support/register-loader.mjs --test src/ui/deviceView.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";

import { recordingTitleText, sessionRowHtml } from "./deviceView";
import type { SessionView } from "../types";

const PAYLOAD = `<img src=x onerror="alert(1)">`;

function baseSession(overrides: Partial<SessionView> = {}): SessionView {
  return {
    id: "sess-1",
    revision: `sha256:${"a".repeat(64)}`,
    dateLabel: "2026-08-01",
    durationSeconds: 12,
    totalBytes: 1024,
    videoBytes: 1024,
    imuSamples: 100,
    files: [{ fileId: "file-left-1", displayPath: "video/left_00000.mp4", bytes: 512, sha256: "b".repeat(64) }],
    downloadStatus: "none",
    backedUp: false,
    ...overrides,
  };
}

test("sessionRowHtml escapes a malicious session.id (text content)", () => {
  const html = sessionRowHtml(baseSession({ id: PAYLOAD }), { open: false, deleting: false, checked: false });
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"), `expected HTML-entity-encoded payload, got: ${html}`);
});

test("sessionRowHtml escapes a malicious session.id inside data-session attributes", () => {
  const html = sessionRowHtml(baseSession({ id: PAYLOAD }), { open: false, deleting: false, checked: false });
  // The raw payload must never appear verbatim inside a data-session="..." attribute.
  assert.ok(!html.includes(`data-session="${PAYLOAD}"`), `payload leaked unescaped into an attribute: ${html}`);
  assert.ok(html.includes("data-session=") && html.includes("&lt;img"));
});

test("sessionRowHtml escapes malicious file labels and opaque ids", () => {
  const html = sessionRowHtml(
    baseSession({ files: [{ fileId: PAYLOAD, displayPath: PAYLOAD, bytes: 1, sha256: "b".repeat(64) }] }),
    {
      open: true,
      deleting: false,
      checked: false,
    },
  );
  assert.ok(!html.includes("<img"), `expected no literal <img tag in file path, got: ${html}`);
  assert.ok(!html.includes(`data-file-id="${PAYLOAD}"`), `payload leaked unescaped into data-file-id: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("sessionRowHtml escapes a malicious dateLabel (Pi-derived captured_at)", () => {
  const html = sessionRowHtml(baseSession({ dateLabel: PAYLOAD }), { open: false, deleting: false, checked: false });
  assert.ok(!html.includes("<img"), `expected no literal <img tag in dateLabel, got: ${html}`);
  assert.ok(html.includes("录制时间未知"));
});

test("recordingTitleText formats captured_at as a readable local recording time", () => {
  assert.equal(recordingTitleText("2026-08-02T15:56:33"), "录制 2026-08-02 15:56:33");
});

test("sessionRowHtml makes captured_at the title and keeps the opaque id secondary", () => {
  const html = sessionRowHtml(
    baseSession({ id: "20260802T155633_687874_0000-eac869d91c91", dateLabel: "2026-08-02T15:56:42" }),
    { open: false, deleting: false, checked: false },
  );

  assert.ok(html.includes('<span class="session-title">录制 2026-08-02 15:56:42</span>'));
  assert.ok(
    html.includes(
      '<span class="session-id-secondary" title="会话 ID: 20260802T155633_687874_0000-eac869d91c91">20260802T155633_687874_0000-eac869d91c91</span>',
    ),
  );
  assert.ok(html.includes("session-main-device"));
});

test("sessionRowHtml still renders normal sessions without visible entities", () => {
  const html = sessionRowHtml(baseSession(), { open: true, deleting: false, checked: false });
  assert.ok(html.includes("sess-1"));
  assert.ok(html.includes("video/left_00000.mp4"));
});

test("collapsed sessions do not create hidden file rows or actions", () => {
  const html = sessionRowHtml(baseSession(), { open: false, deleting: false, checked: false });
  assert.ok(!html.includes("video/left_00000.mp4"));
  assert.ok(!html.includes('data-action="download-file"'));
  assert.ok(!html.includes('class="file-row"'));
});

test("single-file download identifies the real session and opaque file id without trusting UI byte counts", () => {
  const html = sessionRowHtml(baseSession(), { open: true, deleting: false, checked: false });
  assert.ok(html.includes('data-session="sess-1"'));
  assert.ok(html.includes('data-file-id="file-left-1"'));
  assert.ok(!html.includes("data-bytes="));
});

test("unknown IMU sample counts render as unavailable instead of a fabricated zero", () => {
  const html = sessionRowHtml(baseSession({ imuSamples: null }), { open: false, deleting: false, checked: false });
  assert.ok(html.includes('<span class="cell-label">IMU 采样</span><span class="cell-value">--</span>'));
});
