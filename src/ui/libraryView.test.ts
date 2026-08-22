// Regression test for the XSS-via-Pi-controlled-fields vulnerability (SEC-01):
// `entry.sessionId`/`entry.deviceId`/each file's `path` ultimately trace back
// to a Pi HTTP response body (session_id/device fingerprint/display_path per
// pi_http.rs), and `libraryRowHtml`'s output is assigned to `.innerHTML` in
// main.ts. A malicious or spoofed Pi must not be able to get raw
// markup/script into that string.
//
// Run with:
//   node --import ./src/test-support/register-loader.mjs --test src/ui/libraryView.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";

import { libraryRowHtml, libraryTopbarPillHtml } from "./libraryView";
import type { LibraryEntry } from "../types";

const PAYLOAD = `<img src=x onerror="alert(1)">`;
const DEVICE_ID = `ylx-abcdef01${"a".repeat(56)}`;
const DEVICE_ID_COLLISION = `ylx-abcdef01${"b".repeat(56)}`;
const DEVICE_DISPLAY_ID = "YLX-ABCDEF01";

function baseEntry(overrides: Partial<LibraryEntry> = {}): LibraryEntry {
  return {
    deviceId: DEVICE_ID,
    sessionId: "sess-1",
    dateLabel: "2026-08-01",
    downloadedAt: "刚刚",
    bytes: 1024,
    files: [{ fileId: "file-left-1", displayPath: "video/left_00000.mp4", bytes: 512, sha256: "b".repeat(64) }],
    complete: true,
    uploadStatus: "none",
    uploadedAt: null,
    uploadError: null,
    uploadRetryable: false,
    ...overrides,
    deviceDisplayId: overrides.deviceDisplayId ?? DEVICE_DISPLAY_ID,
  };
}

test("libraryRowHtml escapes a malicious sessionId (text content)", () => {
  const html = libraryRowHtml(baseEntry({ sessionId: PAYLOAD }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("libraryRowHtml escapes a malicious device display label (text content)", () => {
  const html = libraryRowHtml(baseEntry({ deviceDisplayId: PAYLOAD }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("libraryRowHtml escapes a malicious sessionId/deviceId inside data-key attributes", () => {
  const html = libraryRowHtml(baseEntry({ sessionId: PAYLOAD, deviceId: DEVICE_ID }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(!html.includes(`data-key="${DEVICE_ID}|${PAYLOAD}"`), `payload leaked unescaped into data-key: ${html}`);
});

test("libraryRowHtml escapes malicious file labels and opaque ids", () => {
  const html = libraryRowHtml(
    baseEntry({ files: [{ fileId: PAYLOAD, displayPath: PAYLOAD, bytes: 1, sha256: "b".repeat(64) }] }),
    {
      open: true,
      deleting: false,
      checked: false,
      configured: true,
    },
  );
  assert.ok(!html.includes("<img"), `expected no literal <img tag in file path, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("libraryRowHtml still renders normal entries without visible entities", () => {
  const html = libraryRowHtml(baseEntry(), { open: false, deleting: false, checked: false, configured: true });
  assert.ok(html.includes("sess-1"));
  assert.ok(html.includes(DEVICE_DISPLAY_ID));
});

test("libraryRowHtml uses a readable recording title and keeps the session id secondary", () => {
  const html = libraryRowHtml(
    baseEntry({ sessionId: "20260802T155633_687874_0000-eac869d91c91", dateLabel: "2026-08-02T15:56:42" }),
    { open: false, deleting: false, checked: false, configured: true },
  );

  assert.ok(html.includes('<span class="session-title">录制 2026-08-02 15:56:42</span>'));
  assert.ok(
    html.includes(
      '<span class="session-id-secondary" title="会话 ID: 20260802T155633_687874_0000-eac869d91c91">20260802T155633_687874_0000-eac869d91c91</span>',
    ),
  );
  assert.ok(html.includes("session-main-library"));
});

test("libraryRowHtml replaces an invalid Pi captured_at value with a safe fallback", () => {
  const html = libraryRowHtml(baseEntry({ dateLabel: PAYLOAD }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("录制时间未知"));
});

test("reveal action carries the library key and opaque file id for backend validation", () => {
  const html = libraryRowHtml(baseEntry(), { open: true, deleting: false, checked: false, configured: true });
  assert.ok(html.includes('data-action="reveal"'));
  assert.ok(html.includes(`data-key="${DEVICE_ID}|sess-1"`));
  assert.ok(html.includes('data-file-id="file-left-1"'));
});

test("collapsed library entries do not create hidden file rows or actions", () => {
  const html = libraryRowHtml(baseEntry(), { open: false, deleting: false, checked: false, configured: true });
  assert.ok(!html.includes("video/left_00000.mp4"));
  assert.ok(!html.includes('data-action="reveal"'));
  assert.ok(!html.includes('class="file-row"'));
});

test("libraryTopbarPillHtml escapes a malicious configured bucket", () => {
  const html = libraryTopbarPillHtml({
    endpoint: "https://storage.example",
    bucket: PAYLOAD,
    prefix: "",
    urlStyle: "virtualHost",
    secretConfigured: true,
    downloadRoot: "",
    activeDownloadRoot: "/tmp/ylx-library",
  });
  assert.ok(!html.includes("<img"), `expected no literal <img tag, got: ${html}`);
  assert.ok(html.includes("&lt;img"));
});

test("missing or incomplete local entries cannot be selected or uploaded", () => {
  const html = libraryRowHtml(baseEntry({ complete: false }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(html.includes("本地文件缺失或不完整"));
  assert.ok(html.includes("需要重新下载"));
  assert.ok(html.includes("disabled"));
  assert.ok(!html.includes('data-action="upload"'));
});

test("a retryable failed library entry exposes retry upload", () => {
  const html = libraryRowHtml(baseEntry({ uploadStatus: "failed", uploadRetryable: true }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(html.includes('data-action="upload"'));
  assert.ok(html.includes("重试上传"));
  assert.ok(!html.includes("不可重试"));
});

test("a non-retryable failed library entry has no retry action", () => {
  const html = libraryRowHtml(baseEntry({ uploadStatus: "failed", uploadRetryable: false }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  assert.ok(!html.includes('data-action="upload"'));
  assert.ok(html.includes("不可重试"));
  assert.ok(html.includes("disabled"));
});

test("same short device label does not collapse library row keys", () => {
  const first = libraryRowHtml(baseEntry({ deviceId: DEVICE_ID, sessionId: "same-session" }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });
  const second = libraryRowHtml(baseEntry({ deviceId: DEVICE_ID_COLLISION, sessionId: "same-session" }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });

  assert.ok(first.includes(`data-key="${DEVICE_ID}|same-session"`));
  assert.ok(second.includes(`data-key="${DEVICE_ID_COLLISION}|same-session"`));
  assert.ok(first.includes(DEVICE_DISPLAY_ID));
  assert.ok(second.includes(DEVICE_DISPLAY_ID));
});

test("legacy offline library identity remains an opaque key while showing its display label", () => {
  const legacyDeviceId = "YLX-1234ABCD";
  const html = libraryRowHtml(baseEntry({ deviceId: legacyDeviceId, deviceDisplayId: legacyDeviceId }), {
    open: false,
    deleting: false,
    checked: false,
    configured: true,
  });

  assert.ok(html.includes(`data-key="${legacyDeviceId}|sess-1"`));
  assert.ok(html.includes(legacyDeviceId));
});

test("a degraded storage resource exposes a storage-only retry control", () => {
  const html = libraryTopbarPillHtml(
    {
      endpoint: "",
      bucket: "",
      prefix: "",
      urlStyle: "virtualHost",
      secretConfigured: false,
      downloadRoot: "",
      activeDownloadRoot: "",
    },
    { error: `<img src=x>`, loading: false },
  );

  assert.ok(html.includes('data-action="retry-resource"'));
  assert.ok(html.includes('data-resource="storageConfig"'));
  assert.ok(!html.includes("<img src=x>"));
});
