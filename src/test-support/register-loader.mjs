// Bootstrap for ts-extension-loader.mjs via Node's recommended `--import`
// module-customization-hooks API (replaces the deprecated
// `--experimental-loader` flag). Usage:
//   node --import ./src/test-support/register-loader.mjs --test src/ui/*.test.ts
import { register } from "node:module";

register("./ts-extension-loader.mjs", import.meta.url);
