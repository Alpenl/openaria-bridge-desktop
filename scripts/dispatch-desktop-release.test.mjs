import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "dispatch-desktop-release.sh");
const SOURCE = "1".repeat(40);
const OTHER_SOURCE = "2".repeat(40);
const RAW = '{"enabled":true,"enforced_by_owner":false}';

function lines(file) {
  return existsSync(file) ? readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean) : [];
}

function runDispatcher({
  version = "0.1.7",
  extra = [],
  actor = "Alpenl",
  admin = true,
  defaultHead = SOURCE,
  immutableResponse = RAW,
} = {}) {
  const temporary = mkdtempSync(path.join(os.tmpdir(), "openaria-desktop-dispatch-test-"));
  const gh = path.join(temporary, "gh");
  const capture = path.join(temporary, "capture.txt");
  const calls = path.join(temporary, "calls.txt");
  writeFileSync(
    gh,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "\${GH_CALLS}"
if [[ "$1" == "api" && "$2" == "user" ]]; then
  printf '%s\\n' "\${GH_ACTOR}"
elif [[ "$1" == "api" && "$2" == "repos/Alpenl/openaria-bridge-desktop" ]]; then
  printf '{"default_branch":"main","permissions":{"admin":%s}}\\n' "\${GH_ADMIN}"
elif [[ "$1" == "api" && "$2" == "repos/Alpenl/openaria-bridge-desktop/commits/${SOURCE}" ]]; then
  printf '%s\\n' '${SOURCE}'
elif [[ "$1" == "api" && "$2" == "repos/Alpenl/openaria-bridge-desktop/commits/main" ]]; then
  printf '%s\\n' "\${GH_DEFAULT_HEAD}"
elif [[ "$1" == "api" && "\${@: -1}" == "repos/Alpenl/openaria-bridge-desktop/immutable-releases" ]]; then
  printf '%s' "\${GH_IMMUTABLE_RESPONSE}"
elif [[ "$1" == "workflow" && "$2" == "run" ]]; then
  printf '%s\\n' "$@" > "\${GH_CAPTURE}"
else
  printf 'unexpected gh call: %s\\n' "$*" >&2
  exit 99
fi
`,
  );
  chmodSync(gh, 0o755);
  const result = spawnSync(SCRIPT, [SOURCE, version, ...extra], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 15_000,
    env: {
      ...process.env,
      PATH: `${temporary}:${process.env.PATH}`,
      GH_ACTOR: actor,
      GH_ADMIN: String(admin),
      GH_DEFAULT_HEAD: defaultHead,
      GH_IMMUTABLE_RESPONSE: immutableResponse,
      GH_CAPTURE: capture,
      GH_CALLS: calls,
    },
  });
  return { result, captured: lines(capture), calls: lines(calls) };
}

test("dispatcher binds owner, default HEAD, fresh immutable response, and exact workflow ref", () => {
  const { result, captured, calls } = runDispatcher();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(captured.slice(0, 7), [
    "workflow",
    "run",
    "ci.yml",
    "--repo",
    "Alpenl/openaria-bridge-desktop",
    "--ref",
    "main",
  ]);
  assert.ok(captured.includes("release_tag=0.1.7"));
  assert.ok(captured.includes(`source_commit=${SOURCE}`));
  assert.ok(captured.includes("immutable_preflight_actor=Alpenl"));
  assert.ok(captured.includes(`immutable_preflight_raw_response=${RAW}`));
  assert.ok(captured.includes(`immutable_preflight_sha256=${createHash("sha256").update(RAW).digest("hex")}`));
  assert.ok(captured.includes("allow_legacy_baseline_bootstrap=false"));
  assert.match(calls.at(-2), /immutable-releases$/);
  assert.match(calls.at(-1), /^workflow run ci\.yml/);
});

test("0.1.6 requires the one-time bootstrap flag and later versions reject it", () => {
  const missing = runDispatcher({ version: "0.1.6" });
  assert.equal(missing.result.status, 1);
  assert.match(missing.result.stderr, /requires --allow-legacy/);
  assert.equal(missing.calls.length, 0);

  const allowed = runDispatcher({ version: "0.1.6", extra: ["--allow-legacy-baseline-bootstrap"] });
  assert.equal(allowed.result.status, 0, allowed.result.stderr);
  assert.ok(allowed.captured.includes("allow_legacy_baseline_bootstrap=true"));

  const forbidden = runDispatcher({ extra: ["--allow-legacy-baseline-bootstrap"] });
  assert.equal(forbidden.result.status, 1);
  assert.match(forbidden.result.stderr, /only for 0\.1\.6/);
  assert.equal(forbidden.calls.length, 0);
});

test("non-owner and non-admin identities fail before immutable-setting read", () => {
  for (const scenario of [{ actor: "release-bot" }, { admin: false }]) {
    const { result, calls } = runDispatcher(scenario);
    assert.equal(result.status, 1);
    assert.equal(
      calls.some((call) => call.endsWith("immutable-releases")),
      false,
    );
    assert.equal(
      calls.some((call) => call.startsWith("workflow run")),
      false,
    );
  }
});

test("non-current default branch source fails before immutable-setting read", () => {
  const { result, calls } = runDispatcher({ defaultHead: OTHER_SOURCE });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /current main head/);
  assert.equal(
    calls.some((call) => call.endsWith("immutable-releases")),
    false,
  );
  assert.equal(
    calls.some((call) => call.startsWith("workflow run")),
    false,
  );
});

test("disabled or malformed immutable setting fails closed without dispatch", () => {
  for (const immutableResponse of [
    '{"enabled":false,"enforced_by_owner":false}',
    '{"enabled":true,"enforced_by_owner":false,"unexpected":true}',
    "not-json",
  ]) {
    const { result, calls } = runDispatcher({ immutableResponse });
    assert.equal(result.status, 1);
    assert.equal(
      calls.some((call) => call.startsWith("workflow run")),
      false,
    );
  }
});
