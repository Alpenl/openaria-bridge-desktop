// Contract test for the test runner itself (src/test-support/run-tests.mjs).
//
// The runner used to ignore every CLI argument, so `npm test -- some/path`
// silently ran the whole suite and a typo'd filter still exited 0. This test
// pins the contract by spawning the runner as a subprocess against throwaway
// fixture directories and asserting on exit codes + output.
//
// Run with:
//   node --import ./src/test-support/register-loader.mjs --test src/test-support/run-tests.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const supportDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = dirname(dirname(supportDirectory));
const runnerPath = join(supportDirectory, "run-tests.mjs");

function runRunner(args: readonly string[]): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [runnerPath, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.error) {
    throw result.error;
  }
  return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

/**
 * Builds a throwaway tree of passing test files:
 *   <root>/alpha.test.ts, <root>/beta.test.ts, <root>/nested/gamma.test.ts
 * plus a non-test file that discovery must ignore.
 */
function withFixtureRoot(body: (root: string) => void): void {
  const root = mkdtempSync(join(supportDirectory, ".ylx-runner-contract-"));
  try {
    mkdirSync(join(root, "nested"), { recursive: true });
    for (const [path, name] of [
      [join(root, "alpha.test.ts"), "alpha"],
      [join(root, "beta.test.ts"), "beta"],
      [join(root, "nested", "gamma.test.ts"), "gamma"],
    ]) {
      writeFileSync(path, `import { test } from "node:test";\ntest("${name} fixture", () => {});\n`, "utf8");
    }
    writeFileSync(join(root, "helper.ts"), "export const unused = 1;\n", "utf8");
    body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("no test paths runs every discovered test file under the root", () => {
  withFixtureRoot((root) => {
    const result = runRunner([`--root=${root}`]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /alpha fixture/);
    assert.match(result.stdout, /beta fixture/);
    assert.match(result.stdout, /gamma fixture/);
  });
});

test("the default root discovers this repository's whole suite", () => {
  // `--list` instead of a real run: the default root includes this very file,
  // so actually executing it would recurse.
  const result = runRunner(["--list"]);
  assert.equal(result.status, 0, result.stderr);
  const listed = result.stdout.trim().split("\n");
  assert.ok(listed.includes("src/test-support/run-tests.test.ts"), result.stdout);
  assert.ok(
    listed.some((path) => path.startsWith("src/ui/") && path.endsWith(".test.ts")),
    result.stdout,
  );
});

test("an explicit test path runs only that file", () => {
  withFixtureRoot((root) => {
    const result = runRunner([relative(repositoryRoot, join(root, "alpha.test.ts"))]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /alpha fixture/);
    assert.ok(!result.stdout.includes("beta fixture"), result.stdout);
  });
});

test("an explicit non-test helper is rejected instead of silently passing", () => {
  withFixtureRoot((root) => {
    const result = runRunner([join(root, "helper.ts")]);
    assert.ok(result.status !== 0, `expected a non-zero exit, got ${result.status}`);
    assert.match(result.stderr, /Test path must name a \.test\.ts file/);
    assert.ok(!result.stdout.includes("helper.ts"), result.stdout);
  });
});

test("an explicit directory path is searched recursively", () => {
  withFixtureRoot((root) => {
    const result = runRunner([join(root, "nested")]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /gamma fixture/);
    assert.ok(!result.stdout.includes("alpha fixture"), result.stdout);
  });
});

test("--filter keeps only the matching test files", () => {
  withFixtureRoot((root) => {
    const result = runRunner([`--root=${root}`, "--filter=beta"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /beta fixture/);
    assert.ok(!result.stdout.includes("alpha fixture"), result.stdout);
    assert.ok(!result.stdout.includes("gamma fixture"), result.stdout);
  });
});

test("--filter matching nothing fails instead of silently passing", () => {
  withFixtureRoot((root) => {
    const result = runRunner([`--root=${root}`, "--filter=no-such-test"]);
    assert.ok(result.status !== 0, `expected a non-zero exit, got ${result.status}`);
    assert.match(result.stderr, /No test files found/);
    assert.match(result.stderr, /no-such-test/);
  });
});

test("a nonexistent test path fails with a clear message", () => {
  const result = runRunner(["src/does/not/exist.test.ts"]);
  assert.ok(result.status !== 0, `expected a non-zero exit, got ${result.status}`);
  assert.match(result.stderr, /Test path not found: src\/does\/not\/exist\.test\.ts/);
});

test("a path outside the repository is rejected before discovery", () => {
  const result = runRunner(["../outside.test.ts"]);
  assert.ok(result.status !== 0, `expected a non-zero exit, got ${result.status}`);
  assert.match(result.stderr, /Test path must stay inside the repository/);
});

test("an empty directory fails instead of spawning an empty Node test run", () => {
  const root = mkdtempSync(join(supportDirectory, ".ylx-runner-empty-"));
  try {
    const result = runRunner([root]);
    assert.ok(result.status !== 0, `expected a non-zero exit, got ${result.status}`);
    assert.match(result.stderr, /No test files found/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a nonexistent --root fails with a clear message", () => {
  const result = runRunner(["--root=src/does/not/exist"]);
  assert.ok(result.status !== 0, `expected a non-zero exit, got ${result.status}`);
  assert.match(result.stderr, /Test root directory not found/);
});

test("an unknown option is rejected with usage output", () => {
  const result = runRunner(["--nope"]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown option: --nope/);
  assert.match(result.stderr, /Usage: node src\/test-support\/run-tests\.mjs/);
});

test("--filter without a value is rejected", () => {
  const result = runRunner(["--filter"]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--filter requires a value/);
});

test("a failing test file propagates a non-zero exit code", () => {
  const root = mkdtempSync(join(supportDirectory, ".ylx-runner-failure-"));
  try {
    writeFileSync(
      join(root, "failing.test.ts"),
      `import { test } from "node:test";\ntest("failing fixture", () => {\n  throw new Error("boom");\n});\n`,
      "utf8",
    );
    const result = runRunner([`--root=${root}`]);
    assert.equal(result.status, 1, result.stderr);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
