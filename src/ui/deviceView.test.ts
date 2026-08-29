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

import { recordingTitleText, sessionPaginationHtml, sessionRowHtml } from "./deviceView";
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
    verification: {
      verdict: "usable",
      actor: "gateway",
      validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
      manifestSha256: "a".repeat(64),
      verifiedAt: "2026-08-01T00:00:01Z",
      diagnostics: [],
    },
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

test("summary-only sessions do not render destructive device deletion controls", () => {
  const html = sessionRowHtml(baseSession({ files: [] }), {
    open: true,
    deleting: false,
    checked: false,
    canDelete: false,
  });

  assert.ok(!html.includes('data-action="delete"'));
  assert.ok(html.includes("文件清单将在下载时按需读取"));
  assert.ok(!html.includes('data-action="download-file"'));
});

test("collapsed sessions do not create hidden file rows or actions", () => {
  const html = sessionRowHtml(baseSession(), { open: false, deleting: false, checked: false });
  assert.ok(!html.includes("video/left_00000.mp4"));
  assert.ok(!html.includes('data-action="download-file"'));
  assert.ok(!html.includes('class="file-row"'));
});

test("expanded file inventory is informational and exposes no per-file command payload", () => {
  const html = sessionRowHtml(baseSession(), { open: true, deleting: false, checked: false });
  assert.ok(html.includes('data-session="sess-1"'));
  assert.ok(html.includes("video/left_00000.mp4"));
  assert.ok(!html.includes("data-file-id="));
  assert.ok(!html.includes('data-action="download-file"'));
  assert.ok(!html.includes("data-bytes="));
});

test("all profiles keep complete-session download but ignore a contradictory legacy file flag", () => {
  const contradictoryLegacyOptions = {
    open: true,
    deleting: false,
    checked: false,
    canDownloadSession: true,
    canDownloadFiles: true,
  };
  const html = sessionRowHtml(baseSession(), contradictoryLegacyOptions);

  assert.ok(html.includes('data-action="download"'));
  assert.ok(html.includes("video/left_00000.mp4"));
  assert.ok(!html.includes('data-action="download-file"'));
});

test("unverified, unusable, and malformed-verification rows remain visible but expose no detail or download action", () => {
  const baseVerification = baseSession().verification!;
  const cases: Array<[string, SessionView["verification"]]> = [
    ["missing", null],
    [
      "unusable",
      {
        ...baseVerification,
        verdict: "unusable",
        diagnostics: [{ code: "verification_failed", summary: "private backend diagnostic" }],
      },
    ],
    ["malformed digest", { ...baseVerification, verdict: "usable", manifestSha256: "NOT-A-DIGEST" }],
  ];

  for (const [label, verification] of cases) {
    const html = sessionRowHtml(baseSession({ verification }), {
      open: true,
      deleting: false,
      checked: false,
      canDownloadSession: true,
      canLoadDetail: true,
    });
    assert.ok(html.includes("sess-1"), `${label} row disappeared`);
    assert.ok(html.includes("验证不可用") || html.includes("验证未通过"), `${label} lacks a safe status`);
    assert.ok(html.includes("会话未通过网关验证，详情不可用"), `${label} exposed detail state`);
    assert.ok(!html.includes('data-action="download"'), `${label} exposed session download`);
    assert.ok(!html.includes('data-action="download-file"'), `${label} exposed file download`);
    assert.ok(!html.includes("video/left_00000.mp4"), `${label} exposed cached file details`);
    assert.ok(!html.includes("private backend diagnostic"), `${label} exposed a row diagnostic`);
  }
});

test("unknown IMU sample counts render as unavailable instead of a fabricated zero", () => {
  const html = sessionRowHtml(baseSession({ imuSamples: null }), { open: false, deleting: false, checked: false });
  assert.ok(html.includes('<span class="cell-label">IMU 采样</span><span class="cell-value">--</span>'));
});

test("revisionless catalogs show a first-page limitation without offering load more", () => {
  const html = sessionPaginationHtml(50, {
    catalogRevision: null,
    hasMore: false,
    paginationSupported: false,
    paginationUnavailableReason: "catalogRevisionUnavailable",
    diagnostics: [],
    loadingMore: false,
    loadMoreError: null,
  });

  assert.ok(html.includes("当前设备目录不提供稳定分页"));
  assert.ok(!html.includes('data-action="load-more-sessions"'));
  assert.ok(!html.includes("已加载全部"));
});

test("authoritative catalogs expose retryable load-more state", () => {
  const html = sessionPaginationHtml(50, {
    catalogRevision: "catalog-1",
    hasMore: true,
    paginationSupported: true,
    paginationUnavailableReason: null,
    diagnostics: [],
    loadingMore: false,
    loadMoreError: "temporary <failure>",
  });

  assert.ok(html.includes('data-action="load-more-sessions"'));
  assert.ok(html.includes("重试加载更多"));
  assert.ok(html.includes("temporary &lt;failure&gt;"));
  assert.ok(!html.includes("temporary <failure>"));
});

test("catalog quarantine UI displays only escaped safe messages", () => {
  const html = sessionPaginationHtml(1, {
    catalogRevision: "catalog-1",
    hasMore: false,
    paginationSupported: true,
    paginationUnavailableReason: null,
    diagnostics: [
      {
        quarantineId: "private-quarantine-id",
        code: "private.adapter.code",
        observedAt: "2026-08-03T00:00:01Z",
        message: "已隔离 <script>alert(1)</script>",
      },
    ],
    loadingMore: false,
    loadMoreError: null,
  });

  assert.ok(html.includes("已隔离 &lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("private-quarantine-id"));
  assert.ok(!html.includes("private.adapter.code"));
  assert.ok(!html.includes("2026-08-03T00:00:01Z"));
});
