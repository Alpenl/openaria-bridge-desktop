import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AppUpdateContractError,
  compareNumericAppVersions,
  describeAppUpdateFailure,
  numericAppVersion,
  validateAvailableAppVersion,
} from "./appUpdateError";

test("application update versions use the release X.Y.Z contract", () => {
  assert.equal(numericAppVersion("1.20.3", "版本"), "1.20.3");
  assert.equal(compareNumericAppVersions("1.10.0", "1.9.9"), 1);
  validateAvailableAppVersion("0.1.5", "0.1.6");
  assert.throws(() => numericAppVersion("v1.2.3", "版本"), AppUpdateContractError);
  assert.throws(() => numericAppVersion("1.2", "版本"), AppUpdateContractError);
  assert.throws(() => validateAvailableAppVersion("1.2.3", "1.2.3"), AppUpdateContractError);
  assert.throws(() => validateAvailableAppVersion("1.2.3", "1.2.2"), AppUpdateContractError);
});

test("application update failures distinguish broken sources from current versions", () => {
  assert.match(describeAppUpdateFailure(new Error("HTTP 404 Not Found"), "check"), /更新源文件不存在.*404/);
  assert.match(describeAppUpdateFailure(new Error("signature verification failed"), "download"), /更新签名验证失败/);
  assert.match(describeAppUpdateFailure(new Error("invalid release JSON"), "check"), /更新元数据无效/);
  assert.match(describeAppUpdateFailure(new Error("network connection timed out"), "check"), /无法连接应用更新源/);
  assert.match(describeAppUpdateFailure(new Error("disk rejected installer"), "install"), /安装更新失败/);
});
