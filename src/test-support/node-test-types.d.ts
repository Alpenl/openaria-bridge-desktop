// Minimal ambient type declarations for the subset of Node's built-in test
// runner / assert module used by this project's *.test.ts files. The
// project intentionally has no test-runner devDependency (and no @types/node
// -- see ts-extension-loader.mjs's header comment for why), so `tsc` can't
// resolve "node:test"/"node:assert/strict" out of the box. These
// declarations exist purely to keep `npm run typecheck` accurate for test
// files without adding a dependency-manifest entry.
declare module "node:test" {
  export function test(name: string, fn: () => void | Promise<void>): void;
}

declare module "node:assert/strict" {
  interface StrictAssert {
    equal(actual: unknown, expected: unknown, message?: string): void;
    /** `node:assert/strict` aliases this to `deepStrictEqual`. */
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    ok(value: unknown, message?: string): asserts value;
    match(actual: string, expected: RegExp, message?: string): void;
    throws(block: () => unknown, expected?: unknown, message?: string): void;
  }
  const assert: StrictAssert;
  export default assert;
}

/*
 * The declarations below cover the (sync-only) Node built-ins used by
 * run-tests.test.ts, which shells out to the runner to pin its CLI contract.
 * Same rationale as above: no @types/node dependency, so only the exact
 * surface this repo's tests touch is declared.
 */
declare module "node:child_process" {
  export interface SpawnSyncResult {
    status: number | null;
    signal: string | null;
    stdout: string;
    stderr: string;
    error?: Error;
  }
  export function spawnSync(
    command: string,
    args: readonly string[],
    options: { cwd?: string; encoding: "utf8" },
  ): SpawnSyncResult;
}

declare module "node:fs" {
  export function mkdirSync(path: string, options?: { recursive?: boolean }): string | undefined;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string, encoding: "utf8"): void;
}

declare module "node:os" {
  export function tmpdir(): string;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...parts: string[]): string;
  export function relative(from: string, to: string): string;
}

declare module "node:process" {
  interface NodeProcess {
    readonly execPath: string;
    cwd(): string;
  }
  const nodeProcess: NodeProcess;
  export default nodeProcess;
}

declare module "node:url" {
  export function fileURLToPath(url: string | URL): string;
}
