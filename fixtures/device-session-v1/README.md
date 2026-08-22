# Vendored Device Session contracts

This directory contains the exact Device Session v1/v2 schemas and the valid
and invalid examples consumed by the desktop import gate. The files are a
curated consumer snapshot, not a copy of a planning or governance repository.

`contract-identity.json` pins every included file by SHA-256. Regenerate it
after an intentional contract update:

```bash
node scripts/generate-device-session-contract-identity.mjs
npm run contracts:check
```

Only the two JSON schemas are embedded in production code. The examples are
reference-only test inputs, and no vendored script is executed at runtime.
