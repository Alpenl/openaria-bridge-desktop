// Run with:
//   node --import ./src/test-support/register-loader.mjs --test src/ui/rail.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";

import { downloadRootLabelText, renderDeviceListHtml } from "./rail";
import { createUiState } from "../store";
import type { Device, StorageConfig } from "../types";

const DEVICE_A = `ylx-01234567${"a".repeat(56)}`;
const DEVICE_B = `ylx-01234567${"b".repeat(56)}`;
const SHARED_DISPLAY_ID = "YLX-01234567";

function storage(overrides: Partial<StorageConfig> = {}): StorageConfig {
  return {
    endpoint: "https://storage.example",
    bucket: "recordings",
    prefix: "",
    urlStyle: "virtualHost",
    secretConfigured: true,
    downloadRoot: "",
    activeDownloadRoot: "",
    ...overrides,
  };
}

test("the rail footer shows the directory downloads actually land in", () => {
  const label = downloadRootLabelText(
    storage({ downloadRoot: "D:\\采集数据", activeDownloadRoot: "C:\\Users\\ylx\\Downloads\\YLX Transfer" }),
  );
  assert.equal(label, "C:\\Users\\ylx\\Downloads\\YLX Transfer");
});

test("a saved-but-not-yet-active root is shown rather than nothing", () => {
  assert.equal(downloadRootLabelText(storage({ downloadRoot: "D:\\采集数据" })), "D:\\采集数据");
});

test("before the first config lands the label names the fallback, not an empty string", () => {
  assert.equal(downloadRootLabelText(storage()), "默认目录");
});

test("the label is returned verbatim — main.ts renders it as text, never as HTML", () => {
  const payload = `<img src=x onerror="alert(1)">`;
  assert.equal(downloadRootLabelText(storage({ activeDownloadRoot: payload })), payload);
});

test("a degraded device resource keeps cached rows and exposes a scoped retry", () => {
  const html = renderDeviceListHtml(
    [{ id: DEVICE_A, displayId: SHARED_DISPLAY_ID, ip: "192.0.2.1", state: "connected", lastSeen: null }],
    createUiState(),
    { error: `<script>alert(1)</script>`, loading: false },
  );

  assert.ok(html.includes("设备列表读取失败"));
  assert.ok(html.includes('data-action="retry-resource"'));
  assert.ok(html.includes('data-resource="devices"'));
  assert.ok(!html.includes("<script>alert"));
  assert.ok(html.includes(SHARED_DISPLAY_ID), "degraded state must keep the last-good device rows visible");
  assert.ok(html.includes(`data-id="${DEVICE_A}"`), "device actions retain the canonical identity");
});

test("two canonical devices with one short display label remain separate rail rows", () => {
  const devices: Device[] = [
    { id: DEVICE_A, displayId: SHARED_DISPLAY_ID, ip: "192.0.2.1", state: "connected", lastSeen: null },
    { id: DEVICE_B, displayId: SHARED_DISPLAY_ID, ip: "192.0.2.2", state: "idle", lastSeen: null },
  ];

  const html = renderDeviceListHtml(devices, createUiState());

  assert.equal((html.match(/class="device-item"/g) ?? []).length, 2);
  assert.equal((html.match(new RegExp(SHARED_DISPLAY_ID, "g")) ?? []).length, 2);
  assert.ok(html.includes(`data-id="${DEVICE_A}"`));
  assert.ok(html.includes(`data-id="${DEVICE_B}"`));
  assert.ok(!html.includes(`data-id="${SHARED_DISPLAY_ID}"`));
});
