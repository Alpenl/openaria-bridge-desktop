// Minimal Node.js ESM loader hook so `node --test` can run this project's
// .ts sources directly (via Node's built-in TypeScript type-stripping,
// stable in this Node version) without pulling in a bundler/test-runner
// dependency. The project's source files use Vite/tsc "bundler" module
// resolution (see tsconfig.json's `moduleResolution: "bundler"`), which
// allows extensionless relative imports like `from "../format"` -- Node's
// native ESM resolver requires an explicit extension, so this hook retries
// a failed resolution by appending ".ts" before giving up.
//
// No test framework or transpiler dependency is added by this file; it only
// uses Node's built-in `node:module` customization hooks API.
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (err?.code === "ERR_MODULE_NOT_FOUND" && (specifier.startsWith("./") || specifier.startsWith("../"))) {
      return nextResolve(`${specifier}.ts`, context);
    }
    throw err;
  }
}
