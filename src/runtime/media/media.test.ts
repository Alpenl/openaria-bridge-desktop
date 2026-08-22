import { test } from "node:test";
import assert from "node:assert/strict";

import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";

import type { MediaBackend } from "./backend";
import { MediaBackendError } from "./backend";
import { createMediaConfirmRegistry } from "./confirm";
import {
  decodeImportJob,
  decodeMediaLibraryEntry,
  decodeMediaLibraryEntries,
  decodeMediaScanSnapshot,
  decodeRevisioned,
  decodeStartPipelineRequest,
  MediaDecodeError,
} from "./decoder";
import { asCandidateId, asImportJobId, asPipelineId } from "./ids";
import { createMemoryMediaBackend } from "./memoryBackend";
import { createMediaOperationRegistry } from "./operations";
import { createMediaRuntimeStore } from "./reducer";
import { startMediaRuntime } from "./start";
import { createTauriMediaBackend } from "./tauriTransport";
import {
  MEDIA_BATCH_LIMIT,
  MediaBatchContractError,
  validateImportBatchCoverage,
  validateMediaBatchRequests,
  validatePipelineBatchCoverage,
  type MediaScanSnapshot,
  type StartImportRequest,
  type StartPipelineRequest,
} from "./types";

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: globalThis,
});

const EMPTY_SCAN: MediaScanSnapshot = {
  scanId: "",
  status: "idle",
  media: [],
  candidates: [],
  attachIssue: null,
  completedAt: null,
};

function importJob(state: unknown = "queued"): unknown {
  return {
    id: "import-1",
    candidateId: "candidate-1",
    mediaId: "media-1",
    sourceId: null,
    state,
    desiredRunState: "run",
    progress: {
      currentFile: null,
      copiedBytes: 0,
      totalBytes: 100,
      throughputBytesPerSecond: null,
      etaSeconds: null,
    },
    failure: null,
    retryAt: null,
    createdAt: "2026-08-04T00:00:00Z",
    updatedAt: "2026-08-04T00:00:00Z",
  };
}

function libraryEntry(sourcePath = "sources/source-1", derivedPath = "derivatives/derived-1"): unknown {
  return {
    entryKey: "entry-1",
    sourceIdentity: "source-identity-1",
    sourceRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sourceLocal: {
      status: "verified",
      evidence: {
        importReceiptId: "receipt-1",
        importJobId: "import-1",
        relativePath: sourcePath,
        sealedInventoryDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        provenance: {
          kind: "locally_validated_unsigned",
          sourceSchema: "raw_capture_v2",
          validationReportId: null,
          inventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          admission: "required",
        },
        committedAt: "2026-08-06T00:00:00Z",
      },
    },
    derivedLocal: [
      {
        derivationJobId: "derivation-1",
        profileRevision: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        derivedRevision: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        relativePath: derivedPath,
        sourceManifestDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        committedAt: "2026-08-06T00:00:00Z",
      },
    ],
    uploadBundles: [],
    cardPresence: { status: "unknown" },
  };
}

function deferred<T>() {
  let resolve = (_value: T): void => {};
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function until(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await Promise.resolve();
  }
  throw new Error("condition did not become true");
}

test("media decoders reject bare envelopes and unknown job states", () => {
  assert.throws(() => decodeRevisioned([], decodeImportJob), MediaDecodeError);
  assert.throws(() => decodeImportJob(importJob("invented_state")), MediaDecodeError);
});

test("library decoder accepts bounded source and derived projections", () => {
  const entry = decodeMediaLibraryEntry(libraryEntry());
  assert.equal(entry.sourceLocal.status, "verified");
  assert.equal(entry.sourceLocal.evidence.relativePath, "sources/source-1");
  assert.equal(entry.derivedLocal[0]?.relativePath, "derivatives/derived-1");
  assert.equal(decodeMediaLibraryEntries([libraryEntry()]).length, 1);
});

test("library decoder rejects absolute, Windows-drive, and traversal paths", () => {
  for (const invalid of ["/var/lib/media/source", "C:\\media\\source", "folder/../source"]) {
    assert.throws(() => decodeMediaLibraryEntry(libraryEntry(invalid)), MediaDecodeError);
    assert.throws(() => decodeMediaLibraryEntry(libraryEntry("sources/source-1", invalid)), MediaDecodeError);
  }
});

test("tauri media export transport sends the library entry key and decodes completed output", async () => {
  clearMocks();
  let invocation: { command: string; payload: unknown } | undefined;
  mockIPC((command, payload) => {
    invocation = { command, payload };
    return {
      status: "completed",
      outputPath: "/exports/session-sbs.mp4",
      videoSegmentCount: 2,
      audioSegmentCount: 1,
      outputSizeBytes: 4096,
    };
  });

  const result = await createTauriMediaBackend().exportLibraryEntry("entry-1");

  assert.deepEqual(result, {
    status: "completed",
    outputPath: "/exports/session-sbs.mp4",
    videoSegmentCount: 2,
    audioSegmentCount: 1,
    outputSizeBytes: 4096,
  });
  assert.deepEqual(invocation, {
    command: "media_export_library_entry",
    payload: { entryKey: "entry-1" },
  });
});

test("tauri media export transport preserves native cancellation", async () => {
  clearMocks();
  mockIPC(() => ({ status: "cancelled" }));

  assert.deepEqual(await createTauriMediaBackend().exportLibraryEntry("entry-1"), {
    status: "cancelled",
  });
});

test("tauri media export transport rejects malformed completed receipts", async () => {
  clearMocks();
  mockIPC(() => ({
    status: "completed",
    outputPath: "",
    videoSegmentCount: 1,
    audioSegmentCount: 0,
    outputSizeBytes: 128,
  }));

  const failure = await createTauriMediaBackend()
    .exportLibraryEntry("entry-1")
    .then(
      () => null,
      (error: unknown) => error,
    );

  assert.ok(failure instanceof MediaBackendError);
  assert.match(failure.message, /media_export_library_entry/);
});

test("library events retain the newest snapshot and reject stale revisions", () => {
  const store = createMediaRuntimeStore();
  const newest = decodeMediaLibraryEntries([libraryEntry("sources/newest")]);
  store.commit({ type: "library/loaded", revision: 4, value: newest });
  const stale = store.commit({
    type: "event",
    event: { kind: "library", revision: 3, value: decodeMediaLibraryEntries([libraryEntry("sources/stale")]) },
  });

  assert.equal(stale.stale, true);
  const current = store.getState().library.value?.[0];
  assert.equal(current?.sourceLocal.status, "verified");
  assert.equal(
    current?.sourceLocal.status === "verified" ? current.sourceLocal.evidence.relativePath : null,
    "sources/newest",
  );
});

test("pipeline requests keep source admission separate from unsigned upload approval", () => {
  const policy = {
    autoNormalize: true,
    autoUploadDerived: false,
    uploadSourceVideo: false,
    unsignedUploadApproved: false,
  };
  assert.deepEqual(decodeStartPipelineRequest({ candidateId: "candidate-1", approveUnsigned: true, policy }), {
    candidateId: "candidate-1",
    approveUnsigned: true,
    policy,
  });
  assert.throws(() => decodeStartPipelineRequest({ candidateId: "candidate-1", policy }), MediaDecodeError);
  assert.throws(
    () =>
      decodeStartPipelineRequest({
        candidateId: "candidate-1",
        approveUnsigned: true,
        policy: { ...policy, unsignedUploadApproved: true },
      }),
    MediaDecodeError,
  );
});

test("pipeline request decoder rejects unavailable and contradictory policies", () => {
  const base = {
    autoNormalize: false,
    autoUploadDerived: false,
    uploadSourceVideo: false,
    unsignedUploadApproved: false,
  };
  assert.throws(
    () =>
      decodeStartPipelineRequest({
        candidateId: "candidate-1",
        approveUnsigned: false,
        policy: { ...base, uploadSourceVideo: true },
      }),
    MediaDecodeError,
  );
  assert.throws(
    () =>
      decodeStartPipelineRequest({
        candidateId: "candidate-1",
        approveUnsigned: false,
        policy: { ...base, autoUploadDerived: true },
      }),
    MediaDecodeError,
  );
});

test("scan candidates require a stable source key independent of candidate generation", () => {
  const decoded = decodeMediaScanSnapshot({
    scanId: "scan-1",
    status: "complete",
    media: [],
    candidates: [
      {
        id: "candidate-generation-1",
        sourceKey: "revision-claim-1",
        mediaId: "media-1",
        sourceId: null,
        sessionId: "session-1",
        displayName: "session-1",
        relativePath: "recordings/session-1",
        sourceKind: "removable_media",
        schema: "raw_capture_v2",
        verdict: "ready_unsigned_requires_policy",
        reason: null,
        provenance: {
          kind: "locally_validated_unsigned",
          sourceSchema: "raw_capture_v2",
          validationReportId: null,
          inventoryDigest: null,
          admission: "required",
        },
        bytes: 1,
        durationSeconds: null,
        mediaRequired: true,
      },
    ],
    attachIssue: null,
    completedAt: "2026-08-04T00:00:00Z",
  });
  assert.equal(decoded.candidates[0]?.sourceKey, "revision-claim-1");
});

test("scan decoder preserves attach and mounted-card access issues", () => {
  const decoded = decodeMediaScanSnapshot({
    scanId: "scan-access-1",
    status: "complete",
    media: [
      {
        id: "media-1",
        displayName: "TF card",
        mountPath: "/media/tf-card",
        filesystem: "ext4",
        presence: "present",
        readerCount: 0,
        handleState: "in_use",
        ejectState: "unsupported",
        ejectVeto: null,
        accessIssue: "recording folder is not readable for this account",
        observedAt: "2026-08-06T00:00:00Z",
      },
    ],
    candidates: [],
    attachIssue: {
      code: "media_unavailable",
      message: "UDisks2 authorization is required",
      retryable: true,
      details: { capability: "udisks2_mount", reason: "authorization_required" },
    },
    completedAt: "2026-08-06T00:00:00Z",
  });

  assert.equal(decoded.media[0]?.accessIssue, "recording folder is not readable for this account");
  assert.equal(decoded.attachIssue?.code, "media_unavailable");
  assert.equal(decoded.attachIssue?.details?.reason, "authorization_required");
});

test("tagged import batches require exactly one result per requested candidate", () => {
  const first = asCandidateId("candidate-1");
  const second = asCandidateId("candidate-2");
  assert.throws(() =>
    validateImportBatchCoverage(
      [
        { candidateId: first, approveUnsigned: false },
        { candidateId: second, approveUnsigned: false },
      ],
      {
        results: [{ status: "success", item: first, jobId: asImportJobId("import-1") }],
        operationError: null,
      },
    ),
  );
});

test("media batch requests reject empty, oversized, and duplicate candidate sets", () => {
  assert.throws(() => validateMediaBatchRequests([]), MediaBatchContractError);
  assert.throws(
    () =>
      validateMediaBatchRequests(
        Array.from({ length: MEDIA_BATCH_LIMIT + 1 }, (_, index) => ({
          candidateId: asCandidateId(`candidate-${index}`),
          approveUnsigned: false,
        })),
      ),
    MediaBatchContractError,
  );
  const duplicate = asCandidateId("candidate-duplicate");
  assert.throws(
    () =>
      validateMediaBatchRequests([
        { candidateId: duplicate, approveUnsigned: false },
        { candidateId: duplicate, approveUnsigned: true },
      ]),
    MediaBatchContractError,
  );
});

test("tagged batch coverage rejects duplicate, unexpected, and omitted results", () => {
  const first = asCandidateId("candidate-1");
  const second = asCandidateId("candidate-2");
  const unexpected = asCandidateId("candidate-unexpected");
  const importRequests: readonly StartImportRequest[] = [
    { candidateId: first, approveUnsigned: false },
    { candidateId: second, approveUnsigned: false },
  ];
  const importSuccess = (item: typeof first, suffix: string) => ({
    status: "success" as const,
    item,
    jobId: asImportJobId(`import-${suffix}`),
  });
  for (const results of [
    [importSuccess(first, "1"), importSuccess(first, "duplicate")],
    [importSuccess(first, "1"), importSuccess(unexpected, "unexpected")],
    [importSuccess(first, "1")],
  ]) {
    assert.throws(
      () => validateImportBatchCoverage(importRequests, { results, operationError: null }),
      MediaBatchContractError,
    );
  }

  const policy = {
    autoNormalize: false,
    autoUploadDerived: false,
    uploadSourceVideo: false,
    unsignedUploadApproved: false,
  };
  const pipelineRequests: readonly StartPipelineRequest[] = [
    { candidateId: first, approveUnsigned: false, policy },
    { candidateId: second, approveUnsigned: false, policy },
  ];
  const pipelineSuccess = (item: typeof first, suffix: string) => ({
    status: "success" as const,
    item,
    jobId: asPipelineId(`pipeline-${suffix}`),
  });
  for (const results of [
    [pipelineSuccess(first, "1"), pipelineSuccess(first, "duplicate")],
    [pipelineSuccess(first, "1"), pipelineSuccess(unexpected, "unexpected")],
    [pipelineSuccess(first, "1")],
  ]) {
    assert.throws(
      () => validatePipelineBatchCoverage(pipelineRequests, { results, operationError: null }),
      MediaBatchContractError,
    );
  }
});

test("resource failures retain the last-good scan and stale events cannot overwrite it", () => {
  const store = createMediaRuntimeStore();
  const good = { ...EMPTY_SCAN, scanId: "scan-2", status: "complete" as const };
  store.commit({ type: "scan/loaded", revision: 2, value: good });
  store.commit({
    type: "resource/failed",
    resource: "scan",
    failure: { message: "reader unavailable", retryable: true, rpcError: null },
  });
  const stale = store.commit({ type: "scan/loaded", revision: 1, value: EMPTY_SCAN });

  assert.equal(stale.stale, true);
  assert.equal(store.getState().scan.value?.scanId, "scan-2");
  assert.equal(store.getState().scan.lastGood?.scanId, "scan-2");
  assert.equal(store.getState().scan.retry.available, true);
});

test("operation registry deduplicates identical intent and fences superseded commits", async () => {
  const registry = createMediaOperationRegistry();
  const firstGate = deferred<string>();
  const replacementGate = deferred<string>();
  const commits: string[] = [];
  let calls = 0;
  const first = registry.run({
    key: "scan-a",
    scope: "scan",
    run: () => {
      calls += 1;
      return firstGate.promise;
    },
    commit: (value) => commits.push(value),
  });
  const duplicate = registry.run({ key: "scan-a", scope: "scan", run: () => firstGate.promise });
  const replacement = registry.run({
    key: "scan-b",
    scope: "scan",
    run: () => replacementGate.promise,
    commit: (value) => commits.push(value),
  });

  firstGate.resolve("old");
  replacementGate.resolve("new");
  assert.equal((await first).status, "superseded");
  assert.equal((await duplicate).status, "superseded");
  assert.equal((await replacement).status, "completed");
  assert.equal(calls, 1);
  assert.deepEqual(commits, ["new"]);
});

test("confirmation expiry is scoped to the operation that armed it", () => {
  let now = 10;
  const callbacks: (() => void)[] = [];
  const registry = createMediaConfirmRegistry({
    clock: {
      now: () => now,
      setTimeout: (callback) => {
        callbacks.push(callback);
        return () => {};
      },
    },
  });
  const armed = registry.request("eject:media-1", 50);
  if (armed.decision !== "armed") throw new Error("expected confirmation to arm");
  now = 20;
  const confirmed = registry.request("eject:media-1", 50);
  assert.equal(confirmed.decision, "confirmed");
  callbacks[0]?.();
  assert.deepEqual(registry.state("eject:media-1"), {
    phase: "running",
    operationId: armed.operationId,
    expiresAt: 60,
  });
  registry.settle("eject:media-1", armed.operationId);
  assert.deepEqual(registry.state("eject:media-1"), { phase: "idle" });
});

test("startup buffers a new scan event until the older snapshot is committed", async () => {
  const memory = createMemoryMediaBackend();
  const initial = await memory.readSnapshot();
  const gate = deferred<void>();
  let readIssued = false;
  const backend: MediaBackend = {
    ...memory,
    readSnapshot: () => {
      readIssued = true;
      return gate.promise.then(() => initial);
    },
  };
  const store = createMediaRuntimeStore();
  const applied: string[] = [];
  const starting = startMediaRuntime({
    backend,
    store,
    onEvent: (event) => applied.push(event.kind),
  });
  await until(() => readIssued);
  memory.emit({ kind: "scan", value: { ...EMPTY_SCAN, scanId: "new", status: "complete" } });
  assert.deepEqual(applied, []);
  gate.resolve();
  const session = await starting;

  assert.deepEqual(applied, ["scan"]);
  assert.equal(store.getState().scan.value?.scanId, "new");
  session.dispose();
});
