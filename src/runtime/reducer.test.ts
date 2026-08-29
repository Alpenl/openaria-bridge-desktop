import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createAppStore,
  deviceById,
  deviceDisplayIdOf,
  deviceSupportsSessionDownload,
  deviceSupportsSessionDeletion,
  devicesOf,
  sessionCatalogOf,
  sessionDetailStateOf,
  sessionsOf,
  sessionsResourceOf,
  storageOf,
} from "./reducer";
import { createFakeClock } from "./clock";
import { createConfirmController } from "./confirm";
import { EMPTY_STORAGE } from "./memoryBackend";
import type { Device, SessionCapabilities, SessionPageView, SessionView } from "../types";

function device(id: string, state: Device["state"] = "idle"): Device {
  return { id, displayId: id, ip: null, state, lastSeen: null };
}

const COLLIDING_DEVICE_A = "ylx-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const COLLIDING_DEVICE_B = "ylx-abcdef0198765432abcdef0198765432abcdef0198765432abcdef0198765432";
const MANIFEST_SHA256 = "a".repeat(64);

function session(id: string): SessionView {
  return {
    id,
    revision: "r1",
    dateLabel: "2026-08-03T00:00:00Z",
    durationSeconds: 1,
    totalBytes: 1,
    videoBytes: 1,
    imuSamples: null,
    files: [],
    downloadStatus: "none",
    backedUp: false,
    verification: {
      verdict: "usable",
      actor: "gateway",
      validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
      manifestSha256: MANIFEST_SHA256,
      verifiedAt: "2026-08-03T00:00:01Z",
      diagnostics: [],
    },
  };
}

function sessionAt(id: string, dateLabel: string): SessionView {
  return { ...session(id), dateLabel };
}

const LEGACY_CAPABILITIES: SessionCapabilities = {
  profile: "legacyPinnedTlsV1",
  sessionDeletion: { supported: true, source: "profileContract" },
  sessionDetail: { supported: true, source: "profileContract" },
  artifactDownload: { supported: true, source: "profileContract" },
  captureStatus: { supported: false, source: "unavailable" },
};

function page(items: SessionView[], nextCursor: string | null, catalogRevision = "catalog-1"): SessionPageView {
  return {
    items,
    nextCursor,
    hasMore: nextCursor !== null,
    catalogRevision,
    catalogAuthority: "deviceSnapshot",
    paginationSupported: true,
    paginationUnavailableReason: null,
    capabilities: LEGACY_CAPABILITIES,
    diagnostics: [],
  };
}

test("four opaque pages make 200 sessions reachable and a repeated identity cannot overwrite one", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  for (let pageIndex = 0; pageIndex < 4; pageIndex += 1) {
    const items = Array.from({ length: 50 }, (_unused, index) => {
      const itemIndex = pageIndex * 50 + index;
      return sessionAt(`s-${itemIndex}`, new Date(Date.UTC(2026, 7, 4, 1, 0, 0) - itemIndex * 1000).toISOString());
    });
    const nextCursor = pageIndex === 3 ? null : `opaque://${pageIndex + 1}?do-not-parse=%2F`;
    store.commit({
      type: "sessions/pageLoaded",
      revision: pageIndex + 1,
      deviceId,
      page: page(items, nextCursor),
      mode: pageIndex === 0 ? "replace" : "append",
      ...(pageIndex === 0 ? {} : { expectedCatalogRevision: "catalog-1" }),
    });
  }

  assert.equal(sessionsOf(store.getState(), deviceId)?.length, 200);
  assert.equal(sessionCatalogOf(store.getState(), deviceId).hasMore, false);

  const beforeResource = sessionsResourceOf(store.getState(), deviceId);
  const beforeCatalog = sessionCatalogOf(store.getState(), deviceId);
  const changed = { ...session("s-75"), revision: "r2", totalBytes: 999 };
  const rejected = store.commit({
    type: "sessions/pageLoaded",
    revision: 5,
    deviceId,
    page: page([changed], null),
    mode: "append",
    expectedCatalogRevision: "catalog-1",
  });
  assert.deepEqual(rejected, { changed: false, stale: true });
  assert.equal(sessionsOf(store.getState(), deviceId)?.length, 200);
  assert.equal(sessionsOf(store.getState(), deviceId)?.find((item) => item.id === "s-75")?.totalBytes, 1);
  assert.equal(sessionsResourceOf(store.getState(), deviceId), beforeResource);
  assert.equal(sessionCatalogOf(store.getState(), deviceId), beforeCatalog);
});

test("an event-first accumulated catalog makes its exact RPC page an idempotent no-op", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  const newer = sessionAt("s-newer", "2026-08-03T00:00:02Z");
  const older = sessionAt("s-older", "2026-08-03T00:00:01Z");
  const firstDiagnostic = {
    quarantineId: "q-first",
    code: "adapter.invalid-entry" as const,
    observedAt: "2026-08-03T00:00:01Z",
    message: "first page",
  };
  const secondDiagnostic = {
    quarantineId: "q-second",
    code: "device.unknown-entry" as const,
    observedAt: "2026-08-03T00:00:00Z",
    message: "second page",
  };
  const firstPage = page([newer], "opaque-next");
  firstPage.diagnostics.push(firstDiagnostic);
  store.commit({
    type: "sessions/pageLoaded",
    revision: 1,
    deviceId,
    page: firstPage,
    mode: "replace",
  });
  store.commit({
    type: "backend/event",
    event: {
      kind: "sessions",
      revision: 2,
      deviceId,
      sessions: [newer, older],
      catalogRevision: "catalog-1",
      nextCursor: null,
      hasMore: false,
      catalogAuthority: "deviceSnapshot",
      paginationSupported: true,
      paginationUnavailableReason: null,
      capabilities: LEGACY_CAPABILITIES,
      diagnostics: [firstDiagnostic, secondDiagnostic],
    },
  });
  const beforeResource = sessionsResourceOf(store.getState(), deviceId);
  const beforeCatalog = sessionCatalogOf(store.getState(), deviceId);

  const rpcPage = page([older], null);
  rpcPage.diagnostics.push(secondDiagnostic);
  const result = store.commit({
    type: "sessions/pageLoaded",
    revision: 2,
    deviceId,
    page: rpcPage,
    mode: "append",
    expectedCatalogRevision: "catalog-1",
  });

  assert.deepEqual(result, { changed: false, stale: false });
  assert.equal(sessionsResourceOf(store.getState(), deviceId), beforeResource);
  assert.equal(sessionCatalogOf(store.getState(), deviceId), beforeCatalog);
});

test("a same-publication catalog conflict is rejected whether the event or RPC arrives second", () => {
  const deviceId = "YLX-A";
  const original = session("s1");
  const changed = { ...original, totalBytes: 999 };

  const eventFirst = createAppStore();
  eventFirst.commit({
    type: "backend/event",
    event: {
      kind: "sessions",
      revision: 7,
      deviceId,
      sessions: [original],
      catalogRevision: "catalog-1",
      nextCursor: null,
      hasMore: false,
      catalogAuthority: "deviceSnapshot",
      paginationSupported: true,
      paginationUnavailableReason: null,
      capabilities: LEGACY_CAPABILITIES,
      diagnostics: [],
    },
  });
  const beforeEventFirstResource = sessionsResourceOf(eventFirst.getState(), deviceId);
  const beforeEventFirstCatalog = sessionCatalogOf(eventFirst.getState(), deviceId);
  const lateRpc = eventFirst.commit({
    type: "sessions/pageLoaded",
    revision: 7,
    deviceId,
    page: page([changed], null),
    mode: "replace",
  });
  assert.deepEqual(lateRpc, { changed: false, stale: true });
  assert.equal(sessionsResourceOf(eventFirst.getState(), deviceId), beforeEventFirstResource);
  assert.equal(sessionCatalogOf(eventFirst.getState(), deviceId), beforeEventFirstCatalog);

  const rpcFirst = createAppStore();
  rpcFirst.commit({
    type: "sessions/pageLoaded",
    revision: 7,
    deviceId,
    page: page([original], null),
    mode: "replace",
  });
  const beforeRpcFirstResource = sessionsResourceOf(rpcFirst.getState(), deviceId);
  const beforeRpcFirstCatalog = sessionCatalogOf(rpcFirst.getState(), deviceId);
  const lateEvent = rpcFirst.commit({
    type: "backend/event",
    event: {
      kind: "sessions",
      revision: 7,
      deviceId,
      sessions: [changed],
      catalogRevision: "catalog-1",
      nextCursor: null,
      hasMore: false,
      catalogAuthority: "deviceSnapshot",
      paginationSupported: true,
      paginationUnavailableReason: null,
      capabilities: LEGACY_CAPABILITIES,
      diagnostics: [],
    },
  });
  assert.deepEqual(lateEvent, { changed: false, stale: true });
  assert.equal(sessionsResourceOf(rpcFirst.getState(), deviceId), beforeRpcFirstResource);
  assert.equal(sessionCatalogOf(rpcFirst.getState(), deviceId), beforeRpcFirstCatalog);
});

test("an identical quarantine diagnostic from one publication is idempotent, but a cross-page repeat is stale", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  const diagnostic = {
    quarantineId: "q-1",
    code: "adapter.invalid-entry" as const,
    observedAt: "2026-08-03T00:00:01Z",
    message: "同一隔离项",
  };
  const first = page([session("s1")], "opaque-next");
  first.diagnostics.push(diagnostic);
  store.commit({ type: "sessions/pageLoaded", revision: 1, deviceId, page: first, mode: "replace" });
  const beforeResource = sessionsResourceOf(store.getState(), deviceId);
  const beforeCatalog = sessionCatalogOf(store.getState(), deviceId);

  const samePublication = page([session("s1")], "opaque-next");
  samePublication.diagnostics.push(diagnostic);
  const idempotent = store.commit({
    type: "backend/event",
    event: {
      kind: "sessions",
      revision: 1,
      deviceId,
      sessions: samePublication.items,
      catalogRevision: samePublication.catalogRevision,
      nextCursor: samePublication.nextCursor,
      hasMore: samePublication.hasMore,
      catalogAuthority: samePublication.catalogAuthority,
      paginationSupported: samePublication.paginationSupported,
      paginationUnavailableReason: samePublication.paginationUnavailableReason,
      capabilities: samePublication.capabilities,
      diagnostics: samePublication.diagnostics,
    },
  });
  assert.deepEqual(idempotent, { changed: false, stale: false });
  assert.equal(sessionsResourceOf(store.getState(), deviceId), beforeResource);
  assert.equal(sessionCatalogOf(store.getState(), deviceId), beforeCatalog);

  const duplicatePage = page([session("s2")], null);
  duplicatePage.diagnostics.push(diagnostic);
  const rejected = store.commit({
    type: "sessions/pageLoaded",
    revision: 2,
    deviceId,
    page: duplicatePage,
    mode: "append",
    expectedCatalogRevision: "catalog-1",
  });
  assert.deepEqual(rejected, { changed: false, stale: true });
  assert.equal(sessionsResourceOf(store.getState(), deviceId), beforeResource);
  assert.equal(sessionCatalogOf(store.getState(), deviceId), beforeCatalog);
});

test("session append enforces newest-first at the 50/51 boundary without mutating state", () => {
  const firstFifty = (): SessionView[] =>
    Array.from({ length: 50 }, (_unused, index) =>
      sessionAt(`s-${index}`, new Date(Date.UTC(2026, 7, 4, 0, 0, 59 - index)).toISOString()),
    );
  const lastStartedAt = firstFifty()[49]!.dateLabel;

  for (const [caseName, invalid] of [
    ["newer timestamp", sessionAt("s-newer-boundary", "2026-08-04T00:00:11.000Z")],
    ["same timestamp higher id", sessionAt("s-z", lastStartedAt)],
  ] as const) {
    const store = createAppStore();
    const deviceId = `YLX-${caseName}`;
    store.commit({
      type: "sessions/pageLoaded",
      revision: 1,
      deviceId,
      page: page(firstFifty(), "opaque-item-51"),
      mode: "replace",
    });
    const beforeResource = sessionsResourceOf(store.getState(), deviceId);
    const beforeCatalog = sessionCatalogOf(store.getState(), deviceId);

    const rejected = store.commit({
      type: "sessions/pageLoaded",
      revision: 2,
      deviceId,
      page: page([invalid], null),
      mode: "append",
      expectedCatalogRevision: "catalog-1",
    });

    assert.deepEqual(rejected, { changed: false, stale: true }, caseName);
    assert.equal(sessionsResourceOf(store.getState(), deviceId), beforeResource, caseName);
    assert.equal(sessionCatalogOf(store.getState(), deviceId), beforeCatalog, caseName);
  }

  const validStore = createAppStore();
  validStore.commit({
    type: "sessions/pageLoaded",
    revision: 1,
    deviceId: "YLX-valid",
    page: page(firstFifty(), "opaque-item-51"),
    mode: "replace",
  });
  const accepted = validStore.commit({
    type: "sessions/pageLoaded",
    revision: 2,
    deviceId: "YLX-valid",
    page: page([sessionAt("s-50", "2026-08-04T00:00:09.000Z")], null),
    mode: "append",
    expectedCatalogRevision: "catalog-1",
  });
  assert.deepEqual(accepted, { changed: true, stale: false });
  assert.equal(sessionsOf(validStore.getState(), "YLX-valid")?.length, 51);
});

test("catalog invalidation atomically retires one exact cursor chain and rejects its late replies", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  const summary = session("s1");
  const cursor = "opaque://old-chain";
  store.commit({
    type: "sessions/pageLoaded",
    revision: 1,
    deviceId,
    page: page([summary], cursor),
    mode: "replace",
  });
  store.commit({
    type: "sessions/detailStarted",
    deviceId,
    sessionId: summary.id,
    sessionRevision: summary.revision,
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });

  const staleInvalidation = store.commit({
    type: "sessions/catalogInvalidated",
    deviceId,
    catalogRevision: "catalog-0",
    cursor,
  });
  assert.equal(staleInvalidation.stale, true);
  assert.equal(sessionCatalogOf(store.getState(), deviceId).catalogRevision, "catalog-1");

  const invalidated = store.commit({
    type: "sessions/catalogInvalidated",
    deviceId,
    catalogRevision: "catalog-1",
    cursor,
  });
  assert.equal(invalidated.changed, true);
  const catalog = sessionCatalogOf(store.getState(), deviceId);
  assert.equal(catalog.catalogRevision, null);
  assert.equal(catalog.nextCursor, null);
  assert.equal(catalog.loadingMore, false);
  assert.equal(sessionDetailStateOf(store.getState(), deviceId, summary.id), undefined);

  const latePage = store.commit({
    type: "sessions/pageLoaded",
    revision: 2,
    deviceId,
    page: page([session("late")], null),
    mode: "append",
    expectedCatalogRevision: "catalog-1",
  });
  const lateDetail = store.commit({
    type: "sessions/detailLoaded",
    revision: 3,
    deviceId,
    detail: {
      ...summary,
      files: [{ fileId: "late", displayPath: "late.mp4", bytes: 1, sha256: "c".repeat(64) }],
    },
    sessionRevision: summary.revision,
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });
  assert.equal(latePage.stale, true);
  assert.equal(lateDetail.stale, true);
  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 0);
});

test("detail is retained for the same revision and invalidated by a new catalog/session revision", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  const summary = session("s1");
  store.commit({ type: "sessions/pageLoaded", revision: 1, deviceId, page: page([summary], null), mode: "replace" });
  store.commit({
    type: "sessions/detailStarted",
    deviceId,
    sessionId: "s1",
    sessionRevision: "r1",
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });
  store.commit({
    type: "sessions/detailLoaded",
    revision: 2,
    deviceId,
    detail: {
      ...summary,
      files: [{ fileId: "f1", displayPath: "video/left.mp4", bytes: 1, sha256: "a".repeat(64) }],
    },
    sessionRevision: "r1",
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });

  store.commit({
    type: "sessions/catalogLoaded",
    revision: 3,
    deviceId,
    sessions: [summary],
    catalogRevision: "catalog-1",
    nextCursor: null,
    hasMore: false,
    catalogAuthority: "deviceSnapshot",
    paginationSupported: true,
    paginationUnavailableReason: null,
    capabilities: LEGACY_CAPABILITIES,
    diagnostics: [],
  });
  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 1);
  assert.equal(sessionDetailStateOf(store.getState(), deviceId, "s1")?.error, null);

  const newer = { ...summary, revision: "r2" };
  store.commit({
    type: "sessions/catalogLoaded",
    revision: 4,
    deviceId,
    sessions: [newer],
    catalogRevision: "catalog-2",
    nextCursor: null,
    hasMore: false,
    catalogAuthority: "deviceSnapshot",
    paginationSupported: true,
    paginationUnavailableReason: null,
    capabilities: LEGACY_CAPABILITIES,
    diagnostics: [],
  });
  const late = store.commit({
    type: "sessions/detailLoaded",
    revision: 5,
    deviceId,
    detail: { ...summary, files: [{ fileId: "late", displayPath: "late", bytes: 1, sha256: "b".repeat(64) }] },
    sessionRevision: "r1",
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });
  assert.equal(late.stale, true);
  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 0);
  assert.equal(sessionDetailStateOf(store.getState(), deviceId, "s1"), undefined);
});

test("a fresh catalog verification change invalidates cached detail and rejects a mismatched detail reply", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  const summary = session("s1");
  store.commit({ type: "sessions/pageLoaded", revision: 1, deviceId, page: page([summary], null), mode: "replace" });
  store.commit({
    type: "sessions/detailStarted",
    deviceId,
    sessionId: "s1",
    sessionRevision: summary.revision,
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });
  store.commit({
    type: "sessions/detailLoaded",
    revision: 2,
    deviceId,
    detail: {
      ...summary,
      files: [{ fileId: "f1", displayPath: "video/left.mp4", bytes: 1, sha256: "c".repeat(64) }],
    },
    sessionRevision: summary.revision,
    catalogRevision: "catalog-1",
    manifestSha256: MANIFEST_SHA256,
  });

  const changedManifest = {
    ...summary,
    verification: { ...summary.verification!, manifestSha256: "d".repeat(64) },
  };
  store.commit({
    type: "sessions/pageLoaded",
    revision: 3,
    deviceId,
    page: page([changedManifest], null, "catalog-2"),
    mode: "replace",
  });

  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 0);
  assert.equal(sessionDetailStateOf(store.getState(), deviceId, "s1"), undefined);
  const mismatched = store.commit({
    type: "sessions/detailLoaded",
    revision: 4,
    deviceId,
    detail: {
      ...changedManifest,
      verification: { ...changedManifest.verification, manifestSha256: "e".repeat(64) },
      files: [{ fileId: "late", displayPath: "late.mp4", bytes: 1, sha256: "e".repeat(64) }],
    },
    sessionRevision: summary.revision,
    catalogRevision: "catalog-1",
    manifestSha256: changedManifest.verification.manifestSha256,
  });
  assert.equal(mismatched.stale, true);
  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 0);
});

test("catalog quarantine diagnostics reject a cross-page duplicate identity without mutation", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  const firstPage = page([session("s1")], "opaque-next");
  firstPage.diagnostics.push({
    quarantineId: "q-1",
    code: "adapter.invalid-entry",
    observedAt: "2026-08-03T00:00:01Z",
    message: "首个隔离项",
  });
  store.commit({ type: "sessions/pageLoaded", revision: 1, deviceId, page: firstPage, mode: "replace" });

  const secondPage = page([sessionAt("s2", "2026-08-02T23:59:59Z")], null);
  secondPage.diagnostics.push(
    {
      quarantineId: "q-1",
      code: "adapter.invalid-entry",
      observedAt: "2026-08-03T00:00:02Z",
      message: "更新后的安全说明",
    },
    {
      quarantineId: "q-2",
      code: "device.unknown-entry",
      observedAt: "2026-08-03T00:00:03Z",
      message: "第二个隔离项",
    },
  );
  const beforeResource = sessionsResourceOf(store.getState(), deviceId);
  const beforeCatalog = sessionCatalogOf(store.getState(), deviceId);
  const rejected = store.commit({
    type: "sessions/pageLoaded",
    revision: 2,
    deviceId,
    page: secondPage,
    mode: "append",
    expectedCatalogRevision: "catalog-1",
  });

  assert.deepEqual(rejected, { changed: false, stale: true });
  assert.equal(sessionsResourceOf(store.getState(), deviceId), beforeResource);
  assert.equal(sessionCatalogOf(store.getState(), deviceId), beforeCatalog);
});

test("session deletion is fail-closed until an explicit capability is loaded", () => {
  const store = createAppStore();
  store.commit({ type: "sessions/loaded", revision: 1, deviceId: "YLX-A", sessions: [session("s1")] });
  assert.equal(deviceSupportsSessionDeletion(store.getState(), "YLX-A"), false);
  store.commit({
    type: "sessions/pageLoaded",
    revision: 2,
    deviceId: "YLX-A",
    page: page([session("s1")], null),
    mode: "replace",
  });
  assert.equal(deviceSupportsSessionDeletion(store.getState(), "YLX-A"), true);
});

test("Lab v4 preserves complete-session download when artifact transfer is negotiated", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  store.commit({
    type: "sessions/pageLoaded",
    revision: 1,
    deviceId,
    page: {
      ...page([session("s1")], null),
      capabilities: {
        ...LEGACY_CAPABILITIES,
        profile: "labHttpV4",
        artifactDownload: { supported: true, source: "deviceDescriptor" },
      },
    },
    mode: "replace",
  });

  assert.equal(sessionCatalogOf(store.getState(), deviceId).capabilities.artifactDownload.supported, true);
  assert.equal(deviceSupportsSessionDeletion(store.getState(), deviceId), false);
  assert.equal(deviceSupportsSessionDownload(store.getState(), deviceId), true);
});

test("a revisionless v2 catalog remains visible but pagination stays fail-closed", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";
  store.commit({
    type: "sessions/pageLoaded",
    revision: 1,
    deviceId,
    page: {
      ...page([session("s1")], null),
      catalogRevision: null,
      catalogAuthority: "unavailable",
      paginationSupported: false,
      paginationUnavailableReason: "catalogRevisionUnavailable",
    },
    mode: "replace",
  });

  const catalog = sessionCatalogOf(store.getState(), deviceId);
  assert.deepEqual(
    sessionsOf(store.getState(), deviceId)?.map((item) => item.id),
    ["s1"],
  );
  assert.equal(catalog.paginationSupported, false);
  assert.equal(catalog.catalogRevision, null);
  assert.equal(catalog.catalogAuthority, "unavailable");
  assert.equal(catalog.paginationUnavailableReason, "catalogRevisionUnavailable");
  assert.equal(catalog.hasMore, false);

  const summary = sessionsOf(store.getState(), deviceId)?.[0];
  assert.ok(summary);
  store.commit({
    type: "sessions/detailStarted",
    deviceId,
    sessionId: "s1",
    sessionRevision: summary.revision,
    catalogRevision: null,
    manifestSha256: MANIFEST_SHA256,
  });
  store.commit({
    type: "sessions/detailLoaded",
    revision: 2,
    deviceId,
    detail: {
      ...summary,
      files: [{ fileId: "f1", displayPath: "video/left.mp4", bytes: 1, sha256: "c".repeat(64) }],
    },
    sessionRevision: summary.revision,
    catalogRevision: null,
    manifestSha256: MANIFEST_SHA256,
  });
  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 1);
  assert.ok(sessionDetailStateOf(store.getState(), deviceId, "s1"));

  store.commit({
    type: "sessions/pageLoaded",
    revision: 3,
    deviceId,
    page: {
      ...page([session("s1")], null),
      catalogRevision: null,
      catalogAuthority: "unavailable",
      paginationSupported: false,
      paginationUnavailableReason: "catalogRevisionUnavailable",
    },
    mode: "replace",
  });
  assert.equal(sessionsOf(store.getState(), deviceId)?.[0]?.files.length, 0);
  assert.equal(sessionDetailStateOf(store.getState(), deviceId, "s1"), undefined);
});

test("a stale-revision value never overwrites newer state", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 7, devices: [device("newest")] });
  const result = store.commit({ type: "devices/loaded", revision: 3, devices: [device("late-reply")] });

  assert.equal(result.stale, true);
  assert.equal(result.changed, false);
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["newest"],
  );
});

test("a same-revision reply is accepted, since it cannot be older", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 4, devices: [device("a")] });
  const result = store.commit({ type: "devices/loaded", revision: 4, devices: [device("a"), device("b")] });

  assert.equal(result.stale, false);
  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["a", "b"],
  );
});

test("canonical device identities stay distinct when display labels collide", () => {
  const store = createAppStore();
  store.commit({
    type: "devices/loaded",
    revision: 1,
    devices: [
      { ...device(COLLIDING_DEVICE_A), displayId: "YLX-ABCDEF01" },
      { ...device(COLLIDING_DEVICE_B), displayId: "YLX-ABCDEF01" },
    ],
  });

  assert.equal(deviceById(store.getState(), COLLIDING_DEVICE_A)?.id, COLLIDING_DEVICE_A);
  assert.equal(deviceById(store.getState(), COLLIDING_DEVICE_B)?.id, COLLIDING_DEVICE_B);
  assert.equal(deviceDisplayIdOf(store.getState(), COLLIDING_DEVICE_A), "YLX-ABCDEF01");
  assert.equal(deviceDisplayIdOf(store.getState(), COLLIDING_DEVICE_B), "YLX-ABCDEF01");
});

test("an unchanged value reports no visible change, so views do not repaint", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 1, devices: [device("a")] });
  const result = store.commit({ type: "devices/loaded", revision: 2, devices: [device("a")] });

  assert.equal(result.changed, false);
  assert.equal(store.getState().devices.revision, 2, "the revision still advances");
});

test("a failed refresh degrades to the last good value instead of blanking", () => {
  const store = createAppStore();
  const deviceId = "YLX-A";

  store.commit({ type: "sessions/loaded", revision: 1, deviceId, sessions: [session("s1")] });
  store.commit({ type: "resource/loading", resource: "sessions", deviceId });
  store.commit({ type: "resource/failed", resource: "sessions", deviceId, error: "device unreachable" });

  const resource = sessionsResourceOf(store.getState(), deviceId);
  assert.equal(resource.loading, false);
  assert.equal(resource.error, "device unreachable");
  assert.deepEqual(
    resource.value?.map((s) => s.id),
    ["s1"],
    "the last good snapshot stays on screen",
  );
  assert.deepEqual(
    sessionsOf(store.getState(), deviceId)?.map((s) => s.id),
    ["s1"],
  );
});

test("a resource failure retains structured retryability and code", () => {
  const store = createAppStore();
  const rpcError = {
    code: "session_delete_failed",
    message: "删除会话失败",
    retryable: false,
    details: { deviceId: "YLX-A", sessionId: "s1" },
  } as const;

  store.commit({
    type: "resource/failed",
    resource: "sessions",
    deviceId: "YLX-A",
    error: rpcError.message,
    rpcError,
  });

  assert.deepEqual(sessionsResourceOf(store.getState(), "YLX-A").rpcError, rpcError);
  assert.equal(sessionsResourceOf(store.getState(), "YLX-A").rpcError?.retryable, false);
});

test("a retry failure from an older resource revision cannot degrade newer data", () => {
  const store = createAppStore();

  store.commit({ type: "devices/loaded", revision: 2, devices: [device("newer")] });
  const result = store.commit({
    type: "resource/failed",
    resource: "devices",
    revision: 1,
    error: "late retry failed",
  });

  assert.equal(result.stale, true);
  assert.equal(store.getState().devices.error, null);
  assert.deepEqual(
    devicesOf(store.getState()).map((item) => item.id),
    ["newer"],
  );
});

test("storageConfig is the public resource name but shares storage state", () => {
  const store = createAppStore();

  store.commit({ type: "storage/loaded", revision: 3, storage: EMPTY_STORAGE });
  store.commit({ type: "resource/loading", resource: "storageConfig" });
  assert.equal(store.getState().storage.loading, true);
  store.commit({ type: "resource/failed", resource: "storageConfig", error: "config unavailable" });
  assert.equal(store.getState().storage.error, "config unavailable");
  assert.equal(store.getState().storage.value, EMPTY_STORAGE);
});

test("a resource that never loaded stays absent, not empty", () => {
  const store = createAppStore();

  store.commit({ type: "resource/failed", resource: "sessions", deviceId: "YLX-A", error: "boom" });

  assert.equal(sessionsOf(store.getState(), "YLX-A"), undefined, "absent and empty are different screens");
});

test("a backend event commits through the same entry point as a snapshot", () => {
  const store = createAppStore();

  store.commit({
    type: "backend/snapshot",
    revision: 1,
    snapshot: {
      devices: [device("a")],
      library: [],
      transfers: [],
      storage: EMPTY_STORAGE,
      revisions: { devices: 1, library: 1, transfers: 1, storage: 1 },
    },
  });
  store.commit({
    type: "backend/event",
    event: { kind: "devices", revision: 2, devices: [device("a", "connected")] },
  });

  assert.equal(devicesOf(store.getState())[0].state, "connected");
  assert.equal(storageOf(store.getState()).activeDownloadRoot, EMPTY_STORAGE.activeDownloadRoot);
});

test("a stale snapshot cannot undo an event that already landed", () => {
  const store = createAppStore();

  store.commit({ type: "backend/event", event: { kind: "devices", revision: 9, devices: [device("live")] } });
  const result = store.commit({
    type: "backend/snapshot",
    revision: 4,
    snapshot: {
      devices: [device("old")],
      library: [],
      transfers: [],
      storage: EMPTY_STORAGE,
      revisions: { devices: 4, library: 4, transfers: 4, storage: 4 },
    },
  });

  assert.deepEqual(
    devicesOf(store.getState()).map((d) => d.id),
    ["live"],
  );
  assert.equal(result.changed, true, "the snapshot still fills in the resources it is newest for");
});

test("each resource and each device session stream rejects an out-of-order event independently", () => {
  const store = createAppStore();
  const newerStorage = { ...EMPTY_STORAGE, bucket: "new" };
  store.commit({ type: "backend/event", event: { kind: "devices", revision: 2, devices: [device("devices-new")] } });
  store.commit({ type: "backend/event", event: { kind: "devices", revision: 1, devices: [device("devices-old")] } });
  store.commit({ type: "backend/event", event: { kind: "library", revision: 2, library: [] } });
  store.commit({ type: "backend/event", event: { kind: "library", revision: 1, library: [] } });
  store.commit({ type: "backend/event", event: { kind: "transfers", revision: 2, transfers: [] } });
  store.commit({ type: "backend/event", event: { kind: "transfers", revision: 1, transfers: [] } });
  store.commit({ type: "backend/event", event: { kind: "storage", revision: 2, storage: newerStorage } });
  store.commit({ type: "backend/event", event: { kind: "storage", revision: 1, storage: EMPTY_STORAGE } });
  store.commit({ type: "backend/event", event: { kind: "sessions", revision: 2, deviceId: "A", sessions: [] } });
  store.commit({ type: "backend/event", event: { kind: "sessions", revision: 1, deviceId: "A", sessions: [] } });
  store.commit({ type: "backend/event", event: { kind: "sessions", revision: 1, deviceId: "B", sessions: [] } });

  assert.equal(devicesOf(store.getState())[0]?.id, "devices-new");
  assert.equal(store.getState().devices.revision, 2);
  assert.equal(store.getState().library.revision, 2);
  assert.equal(store.getState().transfers.revision, 2);
  assert.equal(store.getState().storage.revision, 2);
  assert.equal(store.getState().storage.value?.bucket, "new");
  assert.equal(store.getState().sessions.get("A")?.revision, 2);
  assert.equal(store.getState().sessions.get("B")?.revision, 1);
});

test("a confirm timer expires through the reducer, not by writing state directly", () => {
  const store = createAppStore();
  const clock = createFakeClock();
  const confirm = createConfirmController({ store, clock, ttlMs: 4000 });
  const target = "device:cleanupBackedUp:YLX-A";

  confirm.request(target);

  clock.advance(3999);
  assert.equal(confirm.phase(target).phase, "confirming", "the confirmation is still armed");
  clock.advance(1);
  assert.equal(confirm.phase(target).phase, "idle");
  assert.equal(clock.pending(), 0);
});

test("a second commit of the same ui value reports no change", () => {
  const store = createAppStore();

  assert.equal(store.commit({ type: "ui/view", view: "library" }).changed, true);
  assert.equal(store.commit({ type: "ui/view", view: "library" }).changed, false);
});

test("a pairing reply for a superseded flow is rejected as stale", () => {
  const store = createAppStore();

  store.commit({ type: "ui/pairingStarted", deviceId: "YLX-A" });
  store.commit({ type: "ui/pairingStarted", deviceId: "YLX-B" });
  const late = store.commit({ type: "ui/pairingAttempt", deviceId: "YLX-A", attemptId: "attempt-1" });

  assert.equal(late.stale, true);
  assert.equal(store.getState().ui.pairingAttemptId, null, "the newer flow keeps the overlay");
});
