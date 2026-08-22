import { test } from "node:test";
import assert from "node:assert/strict";

import { createOperationRunner, type ToastTone } from "./operations";
import { createMemoryBackend } from "./memoryBackend";
import { createAppStore, devicesOf } from "./reducer";
import { BackendError } from "./backend";
import { asFileId, asLibraryKey, asUploadJobId } from "../ids";
import type { Device } from "../types";

interface RecordedToast {
  message: string;
  tone: ToastTone;
}

function runnerWithToasts() {
  const toasts: RecordedToast[] = [];
  const runner = createOperationRunner({ toast: (message, tone) => toasts.push({ message, tone }) });
  return { runner, toasts };
}

function device(id: string, state: Device["state"] = "idle"): Device {
  return { id, displayId: id, ip: null, state, lastSeen: null };
}

function deferred<T>() {
  let resolve = (_value: T): void => {};
  let reject = (_error: unknown): void => {};
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

test("two identical in-flight intents share one backend call", async () => {
  const backend = createMemoryBackend();
  const { runner } = runnerWithToasts();
  backend.hold("uploadEntry");

  const first = runner.run({ key: "library:upload:k1", run: () => backend.uploadEntry(asLibraryKey("k1")) });
  const second = runner.run({ key: "library:upload:k1", run: () => backend.uploadEntry(asLibraryKey("k1")) });
  assert.equal(runner.isBusy("library:upload:k1"), true);

  backend.release("uploadEntry");
  const [a, b] = await Promise.all([first, second]);

  assert.equal(backend.callNames().filter((name) => name === "uploadEntry").length, 1, "the command is sent once");
  assert.deepEqual(a, b, "both callers observe the same outcome");
  assert.equal(runner.isBusy("library:upload:k1"), false, "the finally cleanup always runs");
});

test("the same key in different scopes runs and supersedes independently", async () => {
  const { runner } = runnerWithToasts();
  const firstGate = deferred<string>();
  const secondGate = deferred<string>();
  const replacementGate = deferred<string>();
  const commits: string[] = [];
  let sharedRuns = 0;

  const first = runner.run({
    key: "shared-key",
    scope: "scope-one",
    run: () => {
      sharedRuns += 1;
      return firstGate.promise;
    },
    commit: (value) => commits.push(value),
  });
  const second = runner.run({
    key: "shared-key",
    scope: "scope-two",
    run: () => {
      sharedRuns += 1;
      return secondGate.promise;
    },
    commit: (value) => commits.push(value),
  });
  const replacement = runner.run({
    key: "replacement",
    scope: "scope-one",
    run: () => replacementGate.promise,
  });

  assert.equal(sharedRuns, 2, "scope is part of an intent's deduplication identity");
  assert.deepEqual(runner.busyKeys(), ["shared-key", "replacement"]);

  firstGate.resolve("superseded-scope-one");
  assert.equal((await first).status, "superseded");
  assert.equal(runner.isBusy("shared-key"), true, "scope-two still owns an in-flight request with this key");

  secondGate.resolve("scope-two");
  assert.equal((await second).status, "completed");
  assert.deepEqual(commits, ["scope-two"]);
  assert.equal(runner.isBusy("shared-key"), false);
  assert.deepEqual(runner.busyKeys(), ["replacement"]);

  replacementGate.resolve("replacement");
  assert.equal((await replacement).status, "completed");
  assert.deepEqual(runner.busyKeys(), []);
});

test("a stale same-key request is not reused after another key supersedes it", async () => {
  const { runner, toasts } = runnerWithToasts();
  const oldGate = deferred<string>();
  const middleGate = deferred<string>();
  const newestGate = deferred<string>();
  const commits: string[] = [];
  let runs = 0;

  const old = runner.run({
    key: "K",
    scope: "S",
    run: () => {
      runs += 1;
      return oldGate.promise;
    },
    commit: (value) => commits.push(value),
    success: () => "old K completed",
  });
  const middle = runner.run({
    key: "K2",
    scope: "S",
    run: () => {
      runs += 1;
      return middleGate.promise;
    },
    commit: (value) => commits.push(value),
    success: () => "K2 completed",
  });
  const newest = runner.run({
    key: "K",
    scope: "S",
    run: () => {
      runs += 1;
      return newestGate.promise;
    },
    commit: (value) => commits.push(value),
    success: () => "new K completed",
  });

  assert.equal(runs, 3, "the reissued K must not share the superseded K promise");

  oldGate.resolve("old K");
  assert.equal((await old).status, "superseded");
  assert.deepEqual(commits, []);
  assert.deepEqual(toasts, []);

  const duplicateOfNewest = runner.run({
    key: "K",
    scope: "S",
    run: () => {
      runs += 1;
      return Promise.resolve("unexpected fourth run");
    },
  });
  assert.equal(duplicateOfNewest, newest, "old K cleanup must not delete the newest K slot");
  assert.equal(runs, 3);

  newestGate.resolve("new K");
  assert.equal((await newest).status, "completed");
  assert.deepEqual(commits, ["new K"]);
  assert.deepEqual(toasts, [{ message: "new K completed", tone: "success" }]);

  middleGate.resolve("K2");
  assert.equal((await middle).status, "superseded");
  assert.deepEqual(runner.busyKeys(), []);
});

test("the same intent may run again once the first one settled", async () => {
  const backend = createMemoryBackend();
  const { runner } = runnerWithToasts();

  await runner.run({ key: "library:upload:k1", run: () => backend.uploadEntry(asLibraryKey("k1")) });
  await runner.run({ key: "library:upload:k1", run: () => backend.uploadEntry(asLibraryKey("k1")) });

  assert.equal(backend.callNames().filter((name) => name === "uploadEntry").length, 2);
});

test("a late response never overwrites a newer intent", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const { runner } = runnerWithToasts();
  backend.hold("listDevices");

  // Two refreshes of the same resource; the first one replies last.
  const first = runner.run({
    key: "devices:refresh:1",
    scope: "devices:refresh",
    run: () => backend.listDevices(),
    commit: ({ revision, value }) => store.commit({ type: "devices/loaded", revision, devices: value }),
  });
  const second = runner.run({
    key: "devices:refresh:2",
    scope: "devices:refresh",
    run: () => backend.listDevices(),
    commit: ({ revision, value }) => store.commit({ type: "devices/loaded", revision, devices: value }),
  });

  backend.setDevices([device("newer")]);
  backend.releaseLast("listDevices"); // the second intent replies first
  await second;
  backend.setDevices([device("older")]);
  backend.release("listDevices"); // the first, superseded intent replies late
  const late = await first;

  assert.equal(late.status, "superseded");
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["newer"],
    "the superseded reply must not commit",
  );
});

test("a superseded rejection cannot invoke the newer operation's failure effect", async () => {
  const backend = createMemoryBackend();
  const { runner } = runnerWithToasts();
  backend.hold("listDevices");
  let failures = 0;

  const first = runner.run({
    key: "devices:refresh:1",
    scope: "devices:refresh",
    run: () => backend.listDevices(),
    failure: () => {
      failures += 1;
      return "stale failure";
    },
  });
  const second = runner.run({
    key: "devices:refresh:2",
    scope: "devices:refresh",
    run: () => backend.listDevices(),
  });

  backend.rejectHeld("listDevices", new BackendError("list_devices", "old request failed"));
  await first;
  assert.equal(failures, 0);
  backend.release("listDevices");
  await second;
});

test("a still-current operation does commit", async () => {
  const backend = createMemoryBackend();
  const store = createAppStore();
  const { runner } = runnerWithToasts();

  const outcome = await runner.run({
    key: "devices:refresh",
    run: () => backend.listDevices(),
    commit: ({ revision, value }) => store.commit({ type: "devices/loaded", revision, devices: value }),
  });

  assert.equal(outcome.status, "completed");
});

test("a failure is caught once, toasted with the transport's own text, and cleans up", async () => {
  const backend = createMemoryBackend();
  const { runner, toasts } = runnerWithToasts();
  backend.failCalls("uploadEntry", new BackendError("upload_entry", "对象存储不可用"));

  const outcome = await runner.run({ key: "library:upload:k1", run: () => backend.uploadEntry(asLibraryKey("k1")) });

  assert.equal(outcome.status, "failed");
  assert.deepEqual(toasts, [{ message: "对象存储不可用", tone: "danger" }]);
  assert.equal(runner.isBusy("library:upload:k1"), false);
  assert.deepEqual(runner.busyKeys(), []);
});

test("a failed operation never runs its commit", async () => {
  const backend = createMemoryBackend();
  const { runner } = runnerWithToasts();
  backend.failCalls("listDevices", new BackendError("list_devices", "boom"));
  let committed = false;

  await runner.run({
    key: "devices:refresh",
    run: () => backend.listDevices(),
    commit: () => {
      committed = true;
    },
  });

  assert.equal(committed, false);
});

test("success and failure messages are the runner's job, not the caller's", async () => {
  const backend = createMemoryBackend();
  const { runner, toasts } = runnerWithToasts();

  await runner.run({
    key: "library:reveal:k1",
    run: () => backend.revealLibraryFile(asLibraryKey("k1"), asFileId("f1")),
    success: () => "已在文件管理器中定位",
  });
  backend.failCalls("cancelUpload", new BackendError("cancel_upload", "no such job"));
  await runner.run({
    key: "tray:cancel-upload:k1",
    run: () => backend.cancelUpload(asUploadJobId("k1")),
    failure: (error) => `取消上传失败：${String((error as Error).message)}`,
  });

  assert.deepEqual(toasts, [
    { message: "已在文件管理器中定位", tone: "success" },
    { message: "取消上传失败：no such job", tone: "danger" },
  ]);
});

test("busy keys are announced so views can disable their controls", async () => {
  const backend = createMemoryBackend();
  const seen: string[][] = [];
  const runner = createOperationRunner({ toast: () => {}, onBusyChange: (keys) => seen.push(keys) });
  backend.hold("uploadEntry");

  const pending = runner.run({ key: "library:upload:k1", run: () => backend.uploadEntry(asLibraryKey("k1")) });
  assert.deepEqual(seen[seen.length - 1], ["library:upload:k1"]);

  backend.release("uploadEntry");
  await pending;
  assert.deepEqual(seen[seen.length - 1], []);
});
