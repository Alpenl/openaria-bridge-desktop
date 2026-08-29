import { test } from "node:test";
import assert from "node:assert/strict";

import { sessionDownloadButtonText } from "./deviceScreen";

test("revisionless unavailable catalogs describe the bulk action as first-page-only", () => {
  const catalog = { catalogAuthority: "unavailable" as const, paginationSupported: false };

  assert.equal(sessionDownloadButtonText(catalog, "pending"), "下载当前首批新数据");
  assert.equal(sessionDownloadButtonText(catalog, "complete"), "当前首批已下载");
});

test("authoritative catalogs retain all-data bulk action copy", () => {
  const catalog = { catalogAuthority: "deviceSnapshot" as const, paginationSupported: true };

  assert.equal(sessionDownloadButtonText(catalog, "pending"), "下载全部新数据");
  assert.equal(sessionDownloadButtonText(catalog, "complete"), "已全部下载");
});

test("only the explicit unavailable/non-paginated combination is first-page-only", () => {
  assert.equal(
    sessionDownloadButtonText({ catalogAuthority: "deviceSnapshot", paginationSupported: false }, "pending"),
    "下载全部新数据",
  );
  assert.equal(
    sessionDownloadButtonText({ catalogAuthority: "unavailable", paginationSupported: true }, "complete"),
    "已全部下载",
  );
});
