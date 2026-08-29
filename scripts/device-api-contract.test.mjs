import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const validator = join(repository, "scripts", "validate-device-api-contract.mjs");
const fixtureFiles = [
  "contracts/ylx-device-api-support.json",
  "contracts/openapi/ylx-device-v4.openapi.yaml",
  "contracts/openapi/ylx-device-v4.provenance.json",
  "contracts/fixtures/device-api/session-list-v2.response.json",
  "contracts/fixtures/device-api/session-list-v3.response.json",
  "contracts/fixtures/device-api/catalog-changed.error.json",
];

function makeContractRoot() {
  const root = mkdtempSync(join(tmpdir(), "openaria-device-contract-"));
  for (const relativePath of fixtureFiles) {
    const destination = join(root, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(repository, relativePath), destination);
  }
  return root;
}

function readJson(root, relativePath) {
  return JSON.parse(readFileSync(join(root, relativePath), "utf8"));
}

function writeJson(root, relativePath, value) {
  writeFileSync(join(root, relativePath), `${JSON.stringify(value, null, 2)}\n`);
}

function runValidator(root) {
  return spawnSync(process.execPath, [validator, "--root", root], {
    cwd: repository,
    encoding: "utf8",
  });
}

function assertPassed(result) {
  assert.equal(result.status, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
}

function assertFailed(result, pattern) {
  assert.notEqual(result.status, 0, `validator unexpectedly passed:\n${result.stdout}`);
  assert.match(`${result.stdout}\n${result.stderr}`, pattern);
}

test("the complete vendored Device API contract set validates offline", () => {
  const root = makeContractRoot();
  try {
    assertPassed(runValidator(root));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a support-manifest identity drift fails closed", () => {
  const root = makeContractRoot();
  try {
    const support = readJson(root, "contracts/ylx-device-api-support.json");
    support.required_contracts[0].sha256 = "0".repeat(64);
    writeJson(root, "contracts/ylx-device-api-support.json", support);
    assertFailed(runValidator(root), /support manifest.*pinned|sha-?256.*support manifest/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a provenance commit drift fails closed", () => {
  const root = makeContractRoot();
  try {
    const provenance = readJson(root, "contracts/openapi/ylx-device-v4.provenance.json");
    provenance.source_commit = "0".repeat(40);
    writeJson(root, "contracts/openapi/ylx-device-v4.provenance.json", provenance);
    assertFailed(runValidator(root), /provenance.*source_commit/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a missing or byte-drifted OpenAPI file fails closed", async (t) => {
  await t.test("missing", () => {
    const root = makeContractRoot();
    try {
      rmSync(join(root, "contracts/openapi/ylx-device-v4.openapi.yaml"));
      assertFailed(runValidator(root), /OpenAPI.*missing|ENOENT/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test("byte drift", () => {
    const root = makeContractRoot();
    try {
      appendFileSync(join(root, "contracts/openapi/ylx-device-v4.openapi.yaml"), "\n# drift\n");
      assertFailed(runValidator(root), /OpenAPI.*(?:bytes|SHA-?256)/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

test("missing response fixtures fail closed", () => {
  const root = makeContractRoot();
  try {
    rmSync(join(root, "contracts/fixtures/device-api/session-list-v3.response.json"));
    assertFailed(runValidator(root), /session-list-v3\.response\.json.*missing|ENOENT/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("session-list v2 and v3 fixture identities cannot be interchanged", async (t) => {
  await t.test("v3 discriminator drift", () => {
    const root = makeContractRoot();
    try {
      const fixture = readJson(root, "contracts/fixtures/device-api/session-list-v3.response.json");
      fixture.schema = "ylx.session-list.v2";
      writeJson(root, "contracts/fixtures/device-api/session-list-v3.response.json", fixture);
      assertFailed(runValidator(root), /session-list v3.*discriminator/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  await t.test("legacy v2 gains v3 revision", () => {
    const root = makeContractRoot();
    try {
      const fixture = readJson(root, "contracts/fixtures/device-api/session-list-v2.response.json");
      fixture.catalog_revision = `sha256:${"2".repeat(64)}`;
      writeJson(root, "contracts/fixtures/device-api/session-list-v2.response.json", fixture);
      assertFailed(runValidator(root), /session-list v2.*closed|v2\/v3.*identity/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

test("catalog_changed must keep the closed retryable ylx.api-error.v2 envelope", () => {
  const root = makeContractRoot();
  try {
    const fixture = readJson(root, "contracts/fixtures/device-api/catalog-changed.error.json");
    fixture.error.retryable = false;
    writeJson(root, "contracts/fixtures/device-api/catalog-changed.error.json", fixture);
    assertFailed(runValidator(root), /catalog_changed.*retryable|retryable.*true/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("semantic OpenAPI checks reject drift independently of byte pinning", async () => {
  const moduleUrl = `${pathToFileURL(validator).href}?test=${createHash("sha256")
    .update(String(Date.now()))
    .digest("hex")}`;
  const { parseOpenApi, validateOpenApiSemantics } = await import(moduleUrl);
  const document = parseOpenApi(readFileSync(join(repository, "contracts/openapi/ylx-device-v4.openapi.yaml"), "utf8"));
  document.components.schemas.CatalogChangedError.properties.error.properties.retryable = {
    const: false,
  };
  assert.throws(() => validateOpenApiSemantics(document), /CatalogChangedError.*retryable|catalog_changed.*retryable/i);
});
