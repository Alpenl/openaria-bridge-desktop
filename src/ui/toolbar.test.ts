import { test } from "node:test";
import assert from "node:assert/strict";

import { renderBulkBarHtml } from "./toolbar";

test("device bulk bar can hide destructive remove when the API contract does not expose deletion", () => {
  const html = renderBulkBarHtml("device", 2, false, { canRemove: false });

  assert.ok(html.includes("下载所选"));
  assert.ok(!html.includes("删除所选"));
  assert.ok(!html.includes('id="bulkRemoveBtn"'));
});

test("device bulk bar omits download when artifact transfer is unavailable", () => {
  const html = renderBulkBarHtml("device", 2, false, { canAct: false });

  assert.ok(!html.includes("下载所选"));
  assert.ok(!html.includes('id="bulkActionBtn"'));
  assert.ok(html.includes("删除所选"));
});

test("library bulk bar keeps local remove enabled by default", () => {
  const html = renderBulkBarHtml("library", 1, false);

  assert.ok(html.includes("上传所选"));
  assert.ok(html.includes("移除所选"));
  assert.ok(html.includes('id="bulkRemoveBtn"'));
});
