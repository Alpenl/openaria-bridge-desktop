// Test runner entry point. Discovers `*.test.ts` files and hands them to
// Node's built-in test runner with the project's TypeScript loader
// registered (see register-loader.mjs / ts-extension-loader.mjs).
//
// CLI contract (exercised by run-tests.test.ts):
//
//   node src/test-support/run-tests.mjs [options] [test-path...]
//
//   test-path            An existing `*.test.ts` file, or a source directory
//                        to search recursively. Repeatable. Defaults to `src`.
//   --filter=<substring> Keep only targets whose repo-relative path contains
//                        <substring>.
//   --root=<dir>         Directory searched when no test-path is given
//                        (default: `src`).
//   --list               Print the resolved targets instead of running them.
//   --help, -h           Print this contract and exit 0.
//
// Exit codes:
//   0  the underlying `node --test` run succeeded
//   1  no test file matched the requested paths/filter, a requested path does
//      not exist, or the underlying `node --test` run failed
//   2  the arguments themselves were malformed (unknown/incomplete option)
import { spawn } from "node:child_process";
import { readdir, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const supportDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRoot = dirname(supportDirectory);
const repositoryRoot = dirname(defaultRoot);
const testFileSuffix = ".test.ts";

const USAGE = [
  "Usage: node src/test-support/run-tests.mjs [options] [test-path...]",
  "",
  "  test-path             An existing *.test.ts file, or a source directory searched recursively.",
  "  --filter=<substring>  Only run targets whose path contains <substring>.",
  "  --root=<dir>          Directory to search when no test-path is given.",
  "  --list                Print the resolved targets instead of running them.",
  "  --help, -h            Show this message.",
].join("\n");

/** Malformed arguments: the user asked for something that isn't expressible. */
class UsageError extends Error {}

/** Well-formed arguments that resolved to nothing runnable. */
class NoTargetsError extends Error {}

function parseArgs(argv) {
  const paths = [];
  let filter = null;
  let root = null;
  let help = false;
  let list = false;

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      help = true;
    } else if (arg === "--list") {
      list = true;
    } else if (arg.startsWith("--filter=")) {
      filter = arg.slice("--filter=".length);
      if (filter === "") {
        throw new UsageError("--filter requires a non-empty value, e.g. --filter=tray");
      }
    } else if (arg === "--filter") {
      throw new UsageError("--filter requires a value, e.g. --filter=tray");
    } else if (arg.startsWith("--root=")) {
      root = arg.slice("--root=".length);
      if (root === "") {
        throw new UsageError("--root requires a non-empty value, e.g. --root=src/ui");
      }
    } else if (arg === "--root") {
      throw new UsageError("--root requires a value, e.g. --root=src/ui");
    } else if (arg.startsWith("-")) {
      throw new UsageError(`Unknown option: ${arg}`);
    } else {
      paths.push(arg);
    }
  }

  return { paths, filter, root, help, list };
}

async function findTests(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const tests = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      tests.push(...(await findTests(path)));
    } else if (entry.isFile() && entry.name.endsWith(testFileSuffix)) {
      tests.push(path);
    }
  }
  return tests;
}

async function statOrNull(path) {
  try {
    return await stat(path);
  } catch {
    return null;
  }
}

/** Repo-relative, forward-slashed path -- what `--filter` matches against. */
function displayPath(path) {
  return relative(process.cwd(), path).replaceAll("\\", "/");
}

function isWithinRoot(path, root) {
  const pathFromRoot = relative(root, path);
  return pathFromRoot === "" || (!pathFromRoot.startsWith("..") && !isAbsolute(pathFromRoot));
}

function assertWithinRepository(path, label) {
  if (!isWithinRoot(path, repositoryRoot)) {
    throw new NoTargetsError(`${label} must stay inside the repository: ${displayPath(path)}`);
  }
}

function assertTestFile(path, input) {
  if (!path.endsWith(testFileSuffix)) {
    throw new NoTargetsError(`Test path must name a ${testFileSuffix} file: ${input}`);
  }
}

async function collectTargets({ paths, filter, root }) {
  const collected = [];

  if (paths.length === 0) {
    const rootDirectory = root === null ? defaultRoot : resolve(root);
    assertWithinRepository(rootDirectory, "Test root");
    const stats = await statOrNull(rootDirectory);
    if (stats === null || !stats.isDirectory()) {
      throw new NoTargetsError(`Test root directory not found: ${displayPath(rootDirectory)}`);
    }
    collected.push(...(await findTests(rootDirectory)));
  } else {
    for (const path of paths) {
      const absolute = resolve(path);
      assertWithinRepository(absolute, "Test path");
      const stats = await statOrNull(absolute);
      if (stats === null) {
        throw new NoTargetsError(`Test path not found: ${path}`);
      }
      if (stats.isDirectory()) {
        collected.push(...(await findTests(absolute)));
      } else {
        if (!stats.isFile()) {
          throw new NoTargetsError(`Test path is not a regular file: ${path}`);
        }
        assertTestFile(absolute, path);
        collected.push(absolute);
      }
    }
  }

  const unique = [...new Set(collected)].sort((left, right) => left.localeCompare(right));
  const matched = filter === null ? unique : unique.filter((path) => displayPath(path).includes(filter));

  if (matched.length === 0) {
    const scope =
      paths.length > 0
        ? `paths [${paths.join(", ")}]`
        : `root ${displayPath(root === null ? defaultRoot : resolve(root))}`;
    const withFilter = filter === null ? "" : ` matching filter ${JSON.stringify(filter)}`;
    throw new NoTargetsError(`No test files found under ${scope}${withFilter}.`);
  }

  return matched;
}

function nodeImportPath(path) {
  const relativePath = displayPath(path);
  return relativePath.startsWith(".") ? relativePath : `./${relativePath}`;
}

async function runNodeTest(targets) {
  const loader = nodeImportPath(join(supportDirectory, "register-loader.mjs"));
  const testArgs = targets.map((path) => nodeImportPath(path));
  // `node --test` refuses to run any file (and exits 0!) when it detects it is
  // already inside a test run via NODE_TEST_CONTEXT. Dropping the variable
  // keeps this runner honest when it is itself spawned from a test -- which is
  // exactly what run-tests.test.ts does.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", loader, "--test", ...testArgs], {
      stdio: "inherit",
      env,
    });
    child.once("error", rejectPromise);
    child.once("exit", (code, signal) => {
      if (signal) {
        rejectPromise(new Error(`Node test runner terminated by ${signal}`));
      } else {
        resolvePromise(code ?? 1);
      }
    });
  });
}

async function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n\n${USAGE}\n`);
      return 2;
    }
    throw error;
  }

  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }

  let targets;
  try {
    targets = await collectTargets(options);
  } catch (error) {
    if (error instanceof NoTargetsError) {
      process.stderr.write(`${error.message}\n`);
      return 1;
    }
    throw error;
  }

  if (options.list) {
    process.stdout.write(`${targets.map((path) => displayPath(path)).join("\n")}\n`);
    return 0;
  }

  return await runNodeTest(targets);
}

process.exitCode = await main(process.argv.slice(2));
