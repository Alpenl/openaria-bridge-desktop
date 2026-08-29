import { test } from "node:test";
import assert from "node:assert/strict";

import { createDeviceNavigationController } from "./navigationController";
import type { SessionView } from "../types";

const SESSION: SessionView = {
  id: "session-1",
  revision: "revision-1",
  dateLabel: "2026-08-03T00:00:00Z",
  durationSeconds: 1,
  totalBytes: 1,
  videoBytes: 1,
  imuSamples: 1,
  files: [],
  downloadStatus: "none",
  backedUp: false,
  verification: {
    verdict: "usable",
    actor: "gateway",
    validator: { name: "catalog-validator", version: "1", buildSha256: "b".repeat(64) },
    manifestSha256: "a".repeat(64),
    verifiedAt: "2026-08-03T00:00:01Z",
    diagnostics: [],
  },
};

test("focus paints before an 800ms session refresh completes", async () => {
  const events: Array<{ name: string; at: number }> = [];
  const startedAt = performance.now();
  const controller = createDeviceNavigationController({
    onBegin: () => events.push({ name: "paint", at: performance.now() - startedAt }),
    loadSessions: async () => {
      await new Promise((resolve) => setTimeout(resolve, 800));
      return [SESSION];
    },
    isCurrent: () => true,
    onLoaded: () => events.push({ name: "loaded", at: performance.now() - startedAt }),
    onFailed: () => events.push({ name: "failed", at: performance.now() - startedAt }),
    onInvalidated: () => {},
  });

  const request = controller.focus("YLX-TEST");
  const paint = events.find((event) => event.name === "paint");
  assert.ok(paint !== undefined && paint.at < 30, `expected first paint under 30ms, got ${paint?.at}`);
  assert.equal(
    events.some((event) => event.name === "loaded"),
    false,
  );

  assert.equal(await request, "applied");
  const loaded = events.find((event) => event.name === "loaded");
  assert.ok(loaded !== undefined && loaded.at >= 750, `expected delayed data after about 800ms, got ${loaded?.at}`);
});

test("focus gives the renderer a frame before starting the native session refresh", async () => {
  const events: string[] = [];
  const rendererTurn = new Promise<void>((resolve) => {
    setTimeout(() => {
      events.push("renderer");
      resolve();
    }, 0);
  });
  const controller = createDeviceNavigationController({
    onBegin: () => events.push("begin"),
    loadSessions: async () => {
      events.push("native-refresh");
      return [SESSION];
    },
    isCurrent: () => true,
    onLoaded: () => events.push("loaded"),
    onFailed: () => events.push("failed"),
    onInvalidated: () => {},
  });

  const request = controller.focus("YLX-TEST");
  await rendererTurn;

  assert.deepEqual(events.slice(0, 2), ["begin", "renderer"]);
  assert.equal(await request, "applied");
  assert.deepEqual(events, ["begin", "renderer", "native-refresh", "loaded"]);
});

test("a newer device focus prevents an older response from committing", async () => {
  const resolvers = new Map<string, (sessions: SessionView[]) => void>();
  const applied: string[] = [];
  let currentDeviceId = "";
  const controller = createDeviceNavigationController({
    onBegin: (deviceId) => {
      currentDeviceId = deviceId;
    },
    loadSessions: (deviceId) =>
      new Promise((resolve) => {
        resolvers.set(deviceId, resolve);
      }),
    isCurrent: (deviceId) => currentDeviceId === deviceId,
    onLoaded: (deviceId) => applied.push(deviceId),
    onFailed: () => {},
    onInvalidated: () => {
      currentDeviceId = "";
    },
  });

  const first = controller.focus("YLX-A");
  const second = controller.focus("YLX-B");
  assert.equal(await first, "stale");
  assert.equal(resolvers.has("YLX-A"), false);
  assert.deepEqual(applied, []);

  await new Promise((resolve) => setTimeout(resolve, 0));
  resolvers.get("YLX-B")?.([SESSION]);
  assert.equal(await second, "applied");
  assert.deepEqual(applied, ["YLX-B"]);
});

test("repeated focus shares one in-flight refresh for the same device", async () => {
  let resolveSessions: ((sessions: SessionView[]) => void) | undefined;
  let loadCount = 0;
  const applied: string[] = [];
  const controller = createDeviceNavigationController({
    onBegin: () => {},
    loadSessions: () => {
      loadCount += 1;
      return new Promise((resolve) => {
        resolveSessions = resolve;
      });
    },
    isCurrent: () => true,
    onLoaded: (deviceId) => applied.push(deviceId),
    onFailed: () => {},
    onInvalidated: () => {},
  });

  const first = controller.focus("YLX-A");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(loadCount, 1);

  const second = controller.focus("YLX-A");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(loadCount, 1);

  resolveSessions?.([SESSION]);
  assert.equal(await first, "stale");
  assert.equal(await second, "applied");
  assert.deepEqual(applied, ["YLX-A"]);
});

test("invalidate starts a new same-device transport and only its response may commit", async () => {
  const resolvers: Array<(sessions: SessionView[]) => void> = [];
  const applied: string[] = [];
  let loadCount = 0;
  const controller = createDeviceNavigationController({
    onBegin: () => {},
    loadSessions: () => {
      loadCount += 1;
      return new Promise<SessionView[]>((resolve) => resolvers.push(resolve));
    },
    isCurrent: () => true,
    onLoaded: (_deviceId, sessions) => applied.push(sessions[0]?.revision ?? "missing"),
    onFailed: () => {},
    onInvalidated: () => {},
  });

  const stale = controller.refresh("YLX-A");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(loadCount, 1);

  controller.invalidate();
  const fresh = controller.refresh("YLX-A");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(loadCount, 2);

  resolvers[0]?.([{ ...SESSION, revision: "stale-revision" }]);
  assert.equal(await stale, "stale");
  assert.deepEqual(applied, []);

  resolvers[1]?.([{ ...SESSION, revision: "fresh-revision" }]);
  assert.equal(await fresh, "applied");
  assert.deepEqual(applied, ["fresh-revision"]);
});

test("refresh failures are reported without rejecting the navigation task", async () => {
  const failures: unknown[] = [];
  const controller = createDeviceNavigationController({
    onBegin: () => {},
    loadSessions: async () => {
      throw new Error("Pi unavailable");
    },
    isCurrent: () => true,
    onLoaded: () => {},
    onFailed: (_deviceId, error) => failures.push(error),
    onInvalidated: () => {},
  });

  assert.equal(await controller.refresh("YLX-TEST"), "failed");
  assert.equal(failures.length, 1);
});
