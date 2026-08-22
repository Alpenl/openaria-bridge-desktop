import { test } from "node:test";
import assert from "node:assert/strict";

import { batchFeedback } from "./batchResult";
import { toBatchItems, toDispatchItems } from "./runtime/batch";
import type { RpcError } from "./types";

function error(message: string, code: RpcError["code"] = "upload_enqueue_failed"): RpcError {
  return { code, message, retryable: false, details: { source: "test" } };
}

test("batchFeedback reports the backend-confirmed success count", () => {
  const feedback = batchFeedback(
    "已加入下载队列",
    toBatchItems(
      {
        results: [
          { status: "success", item: "session-1" },
          { status: "success", item: "session-2" },
        ],
      },
      (raw) => raw,
    ),
  );

  assert.equal(feedback.tone, "success");
  assert.equal(feedback.message, "已加入下载队列 · 2 项");
});

test("batchFeedback surfaces partial failures and their real backend errors", () => {
  const feedback = batchFeedback(
    "上传处理完成",
    toBatchItems(
      {
        results: [
          { status: "success", item: "entry-1" },
          { status: "failure", item: "entry-2", error: error("S3 拒绝访问") },
          { status: "failure", item: "entry-3", error: error("本地文件不存在") },
        ],
      },
      (raw) => raw,
    ),
  );

  assert.equal(feedback.tone, "danger");
  assert.ok(feedback.message.includes("成功 1 项，失败 2 项"));
  assert.ok(feedback.message.includes("entry-2: S3 拒绝访问"));
  assert.ok(feedback.message.includes("entry-3: 本地文件不存在"));
});

test("a batch feedback reads its failures per item, not by array position", () => {
  const items = toDispatchItems(
    {
      results: [
        { status: "success", item: "ok-1", jobId: "job-1" },
        { status: "failure", item: "bad-1", error: error("磁盘已满", "download_enqueue_failed") },
      ],
    },
    (raw) => raw,
    (raw) => raw,
  );

  const feedback = batchFeedback("已加入下载队列", items);
  assert.equal(feedback.tone, "danger");
  assert.ok(feedback.message.includes("bad-1: 磁盘已满"));
  assert.ok(!feedback.message.includes("ok-1:"), "a queued item is never reported as a failure");
});
