// Runtime wire-contract tests. The compiler's `invoke<T>` annotation cannot
// protect us from an older/newer Rust process, so malformed and unknown values
// must be rejected before they reach the reducer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

import {
  decodeBatch,
  decodeBatchJobs,
  decodeDeviceValue,
  decodeDevices,
  decodeCleanupResult,
  decodeCleanupPreview,
  decodeEventPayload,
  decodeLibrary,
  decodeLibraryMutationResult,
  decodeRevision,
  decodeSessions,
  decodeSessionMutationResult,
  decodeRpcErrorValue,
  decodeStorage,
  decodeTransfers,
  decodeTransferJobs,
  RuntimeDecodeError,
} from "./decoder";

const DEVICE_A_ID = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DEVICE_B_ID = "ylx-abcdef0198765432abcdef0198765432abcdef0198765432abcdef0198765432";
const COLLIDING_DISPLAY_ID = "YLX-ABCDEF01";

const device = {
  id: DEVICE_A_ID,
  displayId: COLLIDING_DISPLAY_ID,
  ip: "192.0.2.10",
  state: "connected",
  lastSeen: null,
};

function transferJob(state: unknown = { state: "queued" }) {
  return {
    jobId: "job-1",
    state,
    sessionId: "s1",
    deviceId: DEVICE_A_ID,
    deviceDisplayId: COLLIDING_DISPLAY_ID,
    totalBytes: 100,
    transferredBytes: 20,
    filesTotal: 1,
    filesDone: 0,
    desiredRunState: "run",
  };
}

function transfer(state: unknown = "running") {
  return {
    key: "upload-1",
    label: "sess-1",
    totalBytes: 100,
    sentBytes: 20,
    state,
    retryable: false,
    error: null,
    direction: "up",
    targetLabel: "records",
  };
}

function session() {
  return {
    id: "session-1",
    revision: "publication-1",
    dateLabel: "2026-08-03",
    durationSeconds: 1.5,
    totalBytes: 100,
    videoBytes: 80,
    imuSamples: 10,
    files: [{ fileId: "file-1", displayPath: "video/left.mp4", bytes: 80, sha256: "a".repeat(64) }],
    downloadStatus: "none",
    backedUp: false,
  };
}

function libraryEntry() {
  return {
    deviceId: DEVICE_A_ID,
    deviceDisplayId: COLLIDING_DISPLAY_ID,
    sessionId: "session-1",
    dateLabel: "2026-08-03",
    downloadedAt: "2026-08-03T10:11:12Z",
    bytes: 100,
    files: [{ fileId: "file-1", displayPath: "video/left.mp4", bytes: 100, sha256: "a".repeat(64) }],
    complete: true,
    uploadStatus: "none",
    uploadedAt: null,
    uploadError: null,
    uploadRetryable: false,
  };
}

function thrown(run: () => unknown): unknown {
  try {
    run();
    return undefined;
  } catch (error) {
    return error;
  }
}

type RevisionedFixture = {
  revision: number;
  value: unknown;
};

type RpcFixtureBundle = {
  transfer: unknown;
  revisionedEvent: {
    name: string;
    payload: RevisionedFixture;
  };
  snapshot: {
    revision: number;
    value: {
      devices: RevisionedFixture;
      library: RevisionedFixture;
      transfers: RevisionedFixture;
      storage: RevisionedFixture;
    };
  };
  manualDevice: RevisionedFixture;
  batchJobs: unknown;
  sessionMutation: unknown;
  libraryMutation: unknown;
  downloadedCleanupResult: unknown;
  rpcError: unknown;
};

function readRpcFixture(): { raw: string; value: RpcFixtureBundle } {
  const raw = readFileSync(join(process.cwd(), "fixtures", "rpc", "application_contract.json"), "utf8");
  return { raw, value: JSON.parse(raw) as RpcFixtureBundle };
}

test("shared Rust/TypeScript RPC fixture keeps canonical JSON bytes", () => {
  const { raw, value } = readRpcFixture();
  assert.equal(`${JSON.stringify(value, null, 2)}\n`, raw);
});

test("shared RPC fixture decodes the transfer, event, snapshot resources, and error shape", () => {
  const { value } = readRpcFixture();
  assert.deepEqual(decodeTransfers([value.transfer]), [value.transfer]);
  assert.equal(value.revisionedEvent.name, "transfers:update");
  assert.equal(
    decodeRevision(value.revisionedEvent.payload.revision, "fixture.revisionedEvent.payload.revision"),
    value.revisionedEvent.payload.revision,
  );
  assert.deepEqual(
    decodeEventPayload("transfers", value.revisionedEvent.payload.value, "fixture.revisionedEvent.payload"),
    value.revisionedEvent.payload.value,
  );

  const snapshot = value.snapshot;
  assert.equal(decodeRevision(snapshot.revision, "fixture.snapshot.revision"), 18);
  for (const resource of [
    snapshot.value.devices,
    snapshot.value.library,
    snapshot.value.transfers,
    snapshot.value.storage,
  ]) {
    assert.equal(decodeRevision(resource.revision, "fixture.snapshot.resource.revision"), resource.revision);
    assert.ok(
      resource.revision <= snapshot.revision,
      "inner resource revisions cannot exceed the outer snapshot revision",
    );
  }
  assert.deepEqual(
    decodeDevices(snapshot.value.devices.value, "fixture.snapshot.value.devices.value"),
    snapshot.value.devices.value,
  );
  assert.deepEqual(
    decodeLibrary(snapshot.value.library.value, "fixture.snapshot.value.library.value"),
    snapshot.value.library.value,
  );
  const fixtureDevices = snapshot.value.devices.value as Array<{ id: string; displayId: string }>;
  assert.equal(fixtureDevices.length, 2);
  assert.ok(fixtureDevices[0]?.id !== fixtureDevices[1]?.id, "colliding labels must retain distinct identities");
  assert.equal(fixtureDevices[0]?.displayId, fixtureDevices[1]?.displayId, "fixture intentionally collides labels");
  const fixtureLibrary = snapshot.value.library.value as Array<{ deviceId: string; deviceDisplayId: string }>;
  assert.ok(fixtureLibrary[0]?.deviceId !== fixtureLibrary[1]?.deviceId);
  assert.equal(fixtureLibrary[0]?.deviceDisplayId, fixtureLibrary[1]?.deviceDisplayId);
  assert.deepEqual(
    decodeTransfers(snapshot.value.transfers.value, "fixture.snapshot.value.transfers.value"),
    snapshot.value.transfers.value,
  );
  assert.deepEqual(
    decodeStorage(snapshot.value.storage.value, "fixture.snapshot.value.storage.value"),
    snapshot.value.storage.value,
  );

  assert.equal(decodeRevision(value.manualDevice.revision, "fixture.manualDevice.revision"), 22);
  assert.deepEqual(decodeDeviceValue(value.manualDevice.value, "fixture.manualDevice.value"), value.manualDevice.value);

  assert.deepEqual(decodeBatchJobs(value.batchJobs, "fixture.batchJobs"), value.batchJobs);
  for (const [name, envelope] of [
    ["sessionMutation", value.sessionMutation],
    ["libraryMutation", value.libraryMutation],
    ["downloadedCleanupResult", value.downloadedCleanupResult],
  ] as const) {
    const revisioned = envelope as RevisionedFixture;
    assert.equal(decodeRevision(revisioned.revision, `fixture.${name}.revision`), revisioned.revision);
    assert.ok(Object.prototype.hasOwnProperty.call(revisioned, "value"));
  }
  assert.deepEqual(
    decodeSessionMutationResult((value.sessionMutation as RevisionedFixture).value, "fixture.sessionMutation.value"),
    (value.sessionMutation as RevisionedFixture).value,
  );
  assert.deepEqual(
    decodeLibraryMutationResult((value.libraryMutation as RevisionedFixture).value, "fixture.libraryMutation.value"),
    (value.libraryMutation as RevisionedFixture).value,
  );
  assert.deepEqual(
    decodeCleanupResult(
      (value.downloadedCleanupResult as RevisionedFixture).value,
      "fixture.downloadedCleanupResult.value",
    ),
    (value.downloadedCleanupResult as RevisionedFixture).value,
  );

  const error = value.rpcError;
  assert.ok(error !== null && typeof error === "object" && !Array.isArray(error));
  if (error !== null && typeof error === "object" && !Array.isArray(error)) {
    const structured = error as { code?: unknown; retryable?: unknown; details?: unknown };
    assert.equal(structured.code, "invalid_input");
    assert.equal(structured.retryable, false);
    assert.ok(structured.details !== null && typeof structured.details === "object");
  }
});

test("decoders accept a valid Rust-shaped device and preserve its value", () => {
  assert.deepEqual(decodeDeviceValue(device, "list_devices.response"), device);
});

test("tagged batch decoders preserve item-owned job ids and structured failures", () => {
  const failure = {
    code: "download_enqueue_failed",
    message: "设备离线",
    retryable: true,
    details: { deviceId: DEVICE_A_ID, sessionId: "session-a" },
  } as const;
  const payload = {
    results: [
      { status: "success", item: "session-b", jobId: "job-b" },
      { status: "failure", item: "session-a", error: failure },
    ],
  };

  assert.deepEqual(decodeBatchJobs(payload, "download_sessions.response"), payload);
  assert.deepEqual(decodeBatch({ results: [{ status: "failure", item: "session-a", error: failure }] }), {
    results: [{ status: "failure", item: "session-a", error: failure }],
  });
});

test("batch decoders reject legacy arrays and malformed tagged variants", () => {
  const failure = {
    code: "download_enqueue_failed",
    message: "设备离线",
    retryable: true,
  } as const;
  for (const invalid of [
    { succeeded: ["session-a"], failures: [], jobIds: ["job-a"] },
    { results: [{ status: "success", item: "session-a" }] },
    { results: [{ status: "success", item: "", jobId: "job-a" }] },
    { results: [{ status: "success", item: "session-a", jobId: "" }] },
    { results: [{ status: "failure", item: "session-a", jobId: "job-a", error: failure }] },
    { results: [{ status: "queued", item: "session-a", jobId: "job-a" }] },
  ]) {
    assert.ok(thrown(() => decodeBatchJobs(invalid)) instanceof RuntimeDecodeError);
  }
  assert.ok(
    thrown(() => decodeBatch({ results: [{ status: "success", item: "session-a", jobId: "job-a" }] })) instanceof
      RuntimeDecodeError,
  );
});

test("RPC error decoder rejects unknown codes and non-object details", () => {
  const valid = {
    code: "library_batch_failed",
    message: "操作失败",
    retryable: false,
    details: { command: "test" },
  } as const;
  assert.deepEqual(decodeRpcErrorValue(valid), valid);
  assert.deepEqual(decodeRpcErrorValue({ code: "library_batch_failed", message: "操作失败", retryable: false }), {
    code: "library_batch_failed",
    message: "操作失败",
    retryable: false,
  });
  for (const invalid of [
    { ...valid, code: "new_unknown_code" },
    { ...valid, message: "" },
    { ...valid, retryable: "yes" },
    { ...valid, details: null },
    { ...valid, details: [] },
    { ...valid, details: "opaque" },
  ]) {
    assert.ok(thrown(() => decodeRpcErrorValue(invalid)) instanceof RuntimeDecodeError);
  }
});

test("session and library mutations use tagged results and operation-scoped errors", () => {
  const operationError = {
    code: "session_refresh_failed",
    message: "会话刷新失败",
    retryable: true,
    details: { deviceId: DEVICE_A_ID },
  } as const;
  const sessionPayload = { results: [], sessions: null, operationError };
  assert.deepEqual(decodeSessionMutationResult(sessionPayload), sessionPayload);
  assert.deepEqual(decodeLibraryMutationResult({ results: [{ status: "success", item: "entry-a" }], library: [] }), {
    results: [{ status: "success", item: "entry-a" }],
    library: [],
  });
  assert.ok(thrown(() => decodeSessionMutationResult({ results: [], sessions: null })) instanceof RuntimeDecodeError);
});

test("device decoder requires canonical identity and its display projection", () => {
  const missingDisplay = { ...device } as Record<string, unknown>;
  delete missingDisplay.displayId;
  const missing = thrown(() => decodeDeviceValue(missingDisplay, "list_devices.response"));
  assert.ok(missing instanceof RuntimeDecodeError);
  if (missing instanceof RuntimeDecodeError) assert.equal(missing.path, "list_devices.response.displayId");

  for (const invalid of ["YLX-ABCDEF01", "ylx-ABCDEF01" + "0".repeat(56), "ylx-" + "0".repeat(63)]) {
    assert.ok(
      thrown(() => decodeDeviceValue({ ...device, id: invalid }, "list_devices.response")) instanceof
        RuntimeDecodeError,
      `non-canonical id ${invalid} must fail closed`,
    );
  }
  assert.ok(
    thrown(() => decodeDeviceValue({ ...device, displayId: "YLX-abcdef01" }, "list_devices.response")) instanceof
      RuntimeDecodeError,
  );
});

test("revision decoding accepts protocol boundaries and rejects unsafe watermarks", () => {
  assert.equal(decodeRevision(0, "revision"), 0);
  assert.equal(decodeRevision(Number.MAX_SAFE_INTEGER, "revision"), Number.MAX_SAFE_INTEGER);

  for (const invalid of [-1, 1.5, Number.POSITIVE_INFINITY, Number.NaN, Number.MAX_SAFE_INTEGER + 1, "1"]) {
    const error = thrown(() => decodeRevision(invalid, "revision"));
    assert.ok(error instanceof RuntimeDecodeError, `expected ${String(invalid)} to be rejected`);
    if (error instanceof RuntimeDecodeError) assert.equal(error.path, "revision");
  }
});

test("Rust integer counters require non-negative safe integers while duration may be fractional", () => {
  assert.equal(decodeSessions([session()])[0]?.durationSeconds, 1.5);
  assert.equal(
    decodeTransfers([{ ...transfer(), totalBytes: Number.MAX_SAFE_INTEGER, sentBytes: Number.MAX_SAFE_INTEGER }])[0]
      ?.totalBytes,
    Number.MAX_SAFE_INTEGER,
  );

  const cases: Array<[string, (invalid: number) => unknown]> = [
    [
      "session file bytes",
      (invalid) => decodeSessions([{ ...session(), files: [{ ...session().files[0], bytes: invalid }] }]),
    ],
    ["session total bytes", (invalid) => decodeSessions([{ ...session(), totalBytes: invalid }])],
    ["session video bytes", (invalid) => decodeSessions([{ ...session(), videoBytes: invalid }])],
    ["session IMU samples", (invalid) => decodeSessions([{ ...session(), imuSamples: invalid }])],
    ["library bytes", (invalid) => decodeLibrary([{ ...libraryEntry(), bytes: invalid }])],
    ["transfer total bytes", (invalid) => decodeTransfers([{ ...transfer(), totalBytes: invalid }])],
    ["transfer sent bytes", (invalid) => decodeTransfers([{ ...transfer(), sentBytes: invalid }])],
    ["transfer-job total bytes", (invalid) => decodeTransferJobs([{ ...transferJob(), totalBytes: invalid }])],
    [
      "transfer-job transferred bytes",
      (invalid) => decodeTransferJobs([{ ...transferJob(), transferredBytes: invalid }]),
    ],
    [
      "cleanup item bytes",
      (invalid) =>
        decodeCleanupPreview({
          eligible: [{ sessionId: "session-1", dateLabel: "2026-08-03", bytes: invalid }],
          skipped: [],
          eligibleBytes: 0,
        }),
    ],
    [
      "cleanup eligible bytes",
      (invalid) => decodeCleanupPreview({ eligible: [], skipped: [], eligibleBytes: invalid }),
    ],
  ];

  for (const invalid of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    for (const [label, run] of cases) {
      assert.ok(thrown(() => run(invalid)) instanceof RuntimeDecodeError, `${label} accepted ${String(invalid)}`);
    }
  }
});

test("unknown enum state fails closed with a path-rich diagnostic", () => {
  const error = thrown(() => decodeDeviceValue({ ...device, state: "future_state" }, "list_devices.response"));
  assert.ok(error instanceof RuntimeDecodeError);
  if (!(error instanceof RuntimeDecodeError)) return;
  assert.equal(error.path, "list_devices.response.state");
  assert.ok(error.message.includes("connected"));
});

test("malformed transfer job payload never defaults an absent required field", () => {
  const error = thrown(() =>
    decodeTransferJobs([transferJob({ state: "failed", code: "network" })], "transfer_jobs:update.payload"),
  );
  assert.ok(error instanceof RuntimeDecodeError);
  if (error instanceof RuntimeDecodeError) assert.ok(error.path.endsWith("retryable"));
});

test("transfer job decoding requires a valid desired run state", () => {
  const withoutDesiredRunState = { ...transferJob() } as Record<string, unknown>;
  delete withoutDesiredRunState.desiredRunState;
  const missing = thrown(() => decodeTransferJobs([withoutDesiredRunState], "transfer_jobs:update.payload"));
  assert.ok(missing instanceof RuntimeDecodeError);
  if (missing instanceof RuntimeDecodeError) assert.ok(missing.path.endsWith("desiredRunState"));

  const invalid = thrown(() =>
    decodeTransferJobs([{ ...transferJob(), desiredRunState: "suspended" }], "transfer_jobs:update.payload"),
  );
  assert.ok(invalid instanceof RuntimeDecodeError);
  if (invalid instanceof RuntimeDecodeError) assert.ok(invalid.path.endsWith("desiredRunState"));
});

test("transfer job decoding requires a display projection that matches device identity nullability", () => {
  const missingDisplay = { ...transferJob() } as Record<string, unknown>;
  delete missingDisplay.deviceDisplayId;
  const missing = thrown(() => decodeTransferJobs([missingDisplay], "transfer_jobs:update.payload"));
  assert.ok(missing instanceof RuntimeDecodeError);
  if (missing instanceof RuntimeDecodeError) assert.ok(missing.path.endsWith("deviceDisplayId"));

  assert.ok(
    thrown(() =>
      decodeTransferJobs([{ ...transferJob(), deviceDisplayId: "YLX-abcdef01" }], "transfer_jobs:update.payload"),
    ) instanceof RuntimeDecodeError,
  );

  assert.equal(
    decodeTransferJobs(
      [{ ...transferJob(), deviceId: "YLX-ABCDEF01", deviceDisplayId: "YLX-ABCDEF01" }],
      "transfer_jobs:update.payload",
    )[0]?.deviceId,
    "YLX-ABCDEF01",
  );
  for (const invalid of ["YLX-abcdef01", "YLX-ABCDEF0", "device-1"]) {
    assert.ok(
      thrown(() =>
        decodeTransferJobs(
          [{ ...transferJob(), deviceId: invalid, deviceDisplayId: "YLX-ABCDEF01" }],
          "transfer_jobs:update.payload",
        ),
      ) instanceof RuntimeDecodeError,
      `invalid transfer job identity ${invalid} must fail closed`,
    );
  }

  const idWithoutDisplay = thrown(() =>
    decodeTransferJobs([{ ...transferJob(), deviceDisplayId: null }], "transfer_jobs:update.payload"),
  );
  assert.ok(idWithoutDisplay instanceof RuntimeDecodeError);
  if (idWithoutDisplay instanceof RuntimeDecodeError) assert.ok(idWithoutDisplay.path.endsWith("deviceDisplayId"));

  const displayWithoutId = thrown(() =>
    decodeTransferJobs([{ ...transferJob(), deviceId: null }], "transfer_jobs:update.payload"),
  );
  assert.ok(displayWithoutId instanceof RuntimeDecodeError);
  if (displayWithoutId instanceof RuntimeDecodeError) assert.ok(displayWithoutId.path.endsWith("deviceDisplayId"));

  assert.deepEqual(
    decodeTransferJobs(
      [{ ...transferJob(), deviceId: null, deviceDisplayId: null }],
      "transfer_jobs:update.payload",
    )[0],
    { ...transferJob(), deviceId: null, deviceDisplayId: null },
  );
});

test("transfer job decoding rejects the retired userPaused side channel", () => {
  const error = thrown(() =>
    decodeTransferJobs([{ ...transferJob(), userPaused: false }], "transfer_jobs:update.payload"),
  );
  assert.ok(error instanceof RuntimeDecodeError);
  if (error instanceof RuntimeDecodeError) assert.ok(error.path.endsWith("userPaused"));
});

test("failed transfer state accepts only the tagged failure code shape", () => {
  const decoded = decodeTransferJobs(
    [transferJob({ state: "failed", code: { other: "remote text" }, retryable: false })],
    "transfer_jobs:update.payload",
  );
  assert.deepEqual(decoded[0]?.state, { state: "failed", code: { other: "remote text" }, retryable: false });

  assert.ok(
    thrown(() =>
      decodeTransferJobs([transferJob({ state: "failed", code: { unexpected: "x" }, retryable: false })]),
    ) instanceof RuntimeDecodeError,
  );
});

test("Transfer accepts every Rust lifecycle string and preserves it", () => {
  for (const state of [
    "queued",
    "preparing",
    "finalizing",
    "running",
    "paused",
    "cancelling",
    "succeeded",
    "failed",
    "cancelled",
  ] as const) {
    assert.equal(decodeTransfers([transfer(state)])[0]?.state, state);
  }
});

test("library decoding requires explicit upload retryability", () => {
  const missing = { ...libraryEntry() } as Record<string, unknown>;
  delete missing.uploadRetryable;
  const error = thrown(() => decodeLibrary([missing]));
  assert.ok(error instanceof RuntimeDecodeError);
  if (error instanceof RuntimeDecodeError) assert.ok(error.path.endsWith("uploadRetryable"));

  assert.ok(thrown(() => decodeLibrary([{ ...libraryEntry(), uploadRetryable: "yes" }])) instanceof RuntimeDecodeError);
});

test("library decoding accepts canonical or legacy opaque identity with persisted display label", () => {
  const missing = { ...libraryEntry() } as Record<string, unknown>;
  delete missing.deviceDisplayId;
  const error = thrown(() => decodeLibrary([missing]));
  assert.ok(error instanceof RuntimeDecodeError);
  if (error instanceof RuntimeDecodeError) assert.ok(error.path.endsWith("deviceDisplayId"));

  assert.equal(decodeLibrary([{ ...libraryEntry(), deviceId: "YLX-ABCDEF01" }])[0]?.deviceId, "YLX-ABCDEF01");
  for (const invalid of ["YLX-abcdef01", "YLX-ABCDEF0", "ylx-ABCDEF01", "device-1"]) {
    assert.ok(
      thrown(() => decodeLibrary([{ ...libraryEntry(), deviceId: invalid }])) instanceof RuntimeDecodeError,
      `invalid library identity ${invalid} must fail closed`,
    );
  }
  assert.ok(
    thrown(() => decodeLibrary([{ ...libraryEntry(), deviceDisplayId: "YLX-abcdef01" }])) instanceof RuntimeDecodeError,
  );
  assert.deepEqual(
    decodeLibrary([{ ...libraryEntry(), deviceId: DEVICE_B_ID, deviceDisplayId: COLLIDING_DISPLAY_ID }])[0],
    { ...libraryEntry(), deviceId: DEVICE_B_ID, deviceDisplayId: COLLIDING_DISPLAY_ID },
  );
});

test("Transfer rejects unknown states and retired boolean fields", () => {
  assert.ok(thrown(() => decodeTransfers([transfer("transferring")])) instanceof RuntimeDecodeError);
  assert.ok(
    thrown(() => {
      const missingRetryability = { ...transfer() } as Record<string, unknown>;
      delete missingRetryability.retryable;
      decodeTransfers([missingRetryability]);
    }) instanceof RuntimeDecodeError,
    "retryability is part of the explicit transfer wire contract",
  );
  assert.ok(
    thrown(() => decodeTransfers([{ ...transfer(), done: false }])) instanceof RuntimeDecodeError,
    "a mixed old/new payload must not reintroduce the boolean state model",
  );
  assert.ok(
    thrown(() => decodeTransfers([{ ...transfer(), failed: false, queued: false, resumed: false }])) instanceof
      RuntimeDecodeError,
  );
});

test("event decoder rejects an unknown event kind instead of dropping it silently", () => {
  for (const kind of ["future:event", "constructor", "toString", "__proto__", "hasOwnProperty"]) {
    assert.ok(
      thrown(() => decodeEventPayload(kind, {}, "event")) instanceof RuntimeDecodeError,
      `${kind} must not resolve through Object.prototype`,
    );
  }
});

test("storage decoder rejects an unknown URL style", () => {
  assert.ok(
    thrown(() =>
      decodeStorage(
        {
          endpoint: "https://s3.example.test",
          bucket: "records",
          prefix: "",
          urlStyle: "hosted",
          secretConfigured: true,
          downloadRoot: "",
          activeDownloadRoot: "/downloads",
        },
        "get_storage_config.response",
      ),
    ) instanceof RuntimeDecodeError,
  );
});
