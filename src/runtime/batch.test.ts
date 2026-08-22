// Branded identities and per-item batch outcomes.
import { test } from "node:test";
import assert from "node:assert/strict";

import { acceptedItems, BatchContractError, jobIdFor, rejectedItems, toBatchItems, toDispatchItems } from "./batch";
import { createMemoryBackend } from "./memoryBackend";
import { asDeviceId, asDownloadJobId, asLibraryKey, asSessionId, asUploadJobId } from "../ids";
import type { RpcError } from "../types";

const DEVICE_ID = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function rpcError(message: string, code: RpcError["code"] = "download_enqueue_failed"): RpcError {
  return { code, message, retryable: false, details: { source: "test" } };
}

function thrown(run: () => unknown): unknown {
  try {
    run();
    return null;
  } catch (error) {
    return error;
  }
}

// The type-level half of this guarantee cannot be asserted at runtime, so it is
// recorded here. Every line below is a compile error; uncommenting any one of
// them fails `npm run typecheck`, which is the test:
//
//   backend.listSessions(asSessionId("s1"));          // SessionId is not DeviceId
//   backend.listSessions("YLX-A");                    // a bare string is not an identity
//   backend.cancelUpload(asDownloadJobId("job-1"));   // a download id is not an upload id
//   backend.uploadEntry(asDeviceId("YLX-A"));         // DeviceId is not LibraryKey
//   backend.pauseTransferJob(asUploadJobId("up-1"));  // an upload has no coordinator job
//
// What *is* checkable at runtime is that branding is erasure-only: the wire
// value is unchanged, so nothing about JSON or command payloads shifts.
test("branding an id changes its type, never its value", () => {
  assert.equal(asDeviceId(DEVICE_ID), DEVICE_ID);
  assert.equal(asSessionId("s1"), "s1");
  assert.equal(asLibraryKey("YLX-A|s1"), "YLX-A|s1");
  assert.equal(asDownloadJobId("job-1"), "job-1");
  assert.equal(asUploadJobId("upload-job-1"), "upload-job-1");
});

test("a shuffled dispatch result maps each item to its own job id", () => {
  const dispatch = toDispatchItems(
    {
      results: [
        { status: "success", item: "s3", jobId: "job-c" },
        { status: "success", item: "s1", jobId: "job-a" },
        { status: "success", item: "s2", jobId: "job-b" },
      ],
    },
    asSessionId,
    asDownloadJobId,
    ["s1", "s2", "s3"],
  );

  assert.equal(jobIdFor(dispatch, asSessionId("s1")), "job-a");
  assert.equal(jobIdFor(dispatch, asSessionId("s2")), "job-b");
  assert.equal(jobIdFor(dispatch, asSessionId("s3")), "job-c");
  assert.equal(jobIdFor(dispatch, asSessionId("never-sent")), null);
});

test("a partial failure keeps every item's own verdict and job id", () => {
  const offline = rpcError("设备离线");
  const full = rpcError("磁盘空间不足");
  const dispatch = toDispatchItems(
    {
      results: [
        { status: "failure", item: "s1", error: offline },
        { status: "success", item: "s4", jobId: "job-for-s4" },
        { status: "failure", item: "s3", error: full },
        { status: "success", item: "s2", jobId: "job-for-s2" },
      ],
    },
    asSessionId,
    asDownloadJobId,
    ["s1", "s2", "s3", "s4"],
  );

  assert.deepEqual(acceptedItems(dispatch), ["s4", "s2"]);
  assert.deepEqual(rejectedItems(dispatch), [
    { item: "s1", error: offline },
    { item: "s3", error: full },
  ]);
  assert.equal(jobIdFor(dispatch, asSessionId("s2")), "job-for-s2");
  assert.equal(jobIdFor(dispatch, asSessionId("s4")), "job-for-s4");
  assert.equal(jobIdFor(dispatch, asSessionId("s1")), null, "a rejected item never carries a job id");
  assert.equal(jobIdFor(dispatch, asSessionId("s3")), null);
});

test("coverage rejects missing, duplicate, and unexpected response items", () => {
  assert.ok(
    thrown(() =>
      toDispatchItems({ results: [{ status: "success", item: "s1", jobId: "job-a" }] }, asSessionId, asDownloadJobId, [
        "s1",
        "s2",
      ]),
    ) instanceof BatchContractError,
  );
  assert.ok(
    thrown(() =>
      toDispatchItems(
        {
          results: [
            { status: "success", item: "s1", jobId: "job-a" },
            { status: "success", item: "s1", jobId: "job-b" },
          ],
        },
        asSessionId,
        asDownloadJobId,
        ["s1"],
      ),
    ) instanceof BatchContractError,
  );
  assert.ok(
    thrown(() =>
      toDispatchItems(
        { results: [{ status: "success", item: "other", jobId: "job-a" }] },
        asSessionId,
        asDownloadJobId,
        ["s1"],
      ),
    ) instanceof BatchContractError,
  );
});

test("a mutation result reports each unique requested item exactly once", () => {
  const busy = rpcError("文件被占用", "library_delete_busy");
  const items = toBatchItems(
    {
      results: [
        { status: "success", item: `${DEVICE_ID}|s1` },
        { status: "failure", item: `${DEVICE_ID}|s2`, error: busy },
      ],
    },
    asLibraryKey,
    [`${DEVICE_ID}|s1`, `${DEVICE_ID}|s1`, `${DEVICE_ID}|s2`],
  );

  assert.deepEqual(
    items.map((item) => `${item.item}:${item.status}`),
    [`${DEVICE_ID}|s1:ok`, `${DEVICE_ID}|s2:failed`],
  );
});

test("the backend adapter hands the app per-item outcomes, not parallel arrays", async () => {
  const backend = createMemoryBackend();
  backend.rejectBatchItems("downloadSessions", { s2: "设备离线" });

  const result = await backend.downloadSessions(asDeviceId(DEVICE_ID), [asSessionId("s1"), asSessionId("s2")]);

  assert.deepEqual(acceptedItems(result.items), ["s1"]);
  assert.deepEqual(rejectedItems(result.items), [
    {
      item: "s2",
      error: {
        code: "download_enqueue_failed",
        message: "设备离线",
        retryable: true,
        details: { item: "s2" },
      },
    },
  ]);
  assert.equal(jobIdFor(result.items, asSessionId("s1")), "job-s1");
});
