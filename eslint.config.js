// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";

/** Globals available to the Node-side tooling (test runner, loaders, configs). */
const nodeGlobals = {
  console: "readonly",
  process: "readonly",
  URL: "readonly",
  TextDecoder: "readonly",
  TextEncoder: "readonly",
};

export default tseslint.config(
  {
    ignores: [
      "dist",
      "src-tauri/target",
      "src-tauri/crates/target",
      "src-tauri/gen",
      // Rust build output can contain generated .js (rustdoc), never ours.
      "**/target/doc",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
  {
    // Tooling that runs on Node rather than in the webview: the test runner
    // and its loaders, plus the root config files.
    files: ["src/test-support/**/*.mjs", "scripts/**/*.mjs", "*.config.js", "*.config.ts", "*.config.mjs"],
    languageOptions: {
      globals: nodeGlobals,
    },
  },
  eslintConfigPrettier,
);
