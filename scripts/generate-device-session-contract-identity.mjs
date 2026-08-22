import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixtureRoot = join(repository, "fixtures", "device-session-v1");
const contractRoot = join(fixtureRoot, "central");
const identityPath = join(fixtureRoot, "contract-identity.json");

const sourceSnapshot = "1f026c9d0273186acc35f465014aa25029bd6863";
const expectedCounts = { schemas: 2, valid_fixtures: 7, invalid_fixtures: 23 };

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sourcePath(path) {
  return `contracts/${relative(contractRoot, path).split(sep).join("/")}`;
}

function records(directory) {
  const root = join(contractRoot, directory);
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => join(root, entry.name))
    .sort()
    .map((path) => ({ path: sourcePath(path), sha256: sha256(path) }));
}

const schemas = records("schemas").map((record) => ({
  ...record,
  discriminator: record.path.includes("device-session-v1") ? "ylx.device-session.v1" : "ylx.device-session.v2",
}));
const validFixtures = records("fixtures/valid");
const invalidFixtures = records("fixtures/invalid");

for (const [name, value] of Object.entries({
  schemas,
  valid_fixtures: validFixtures,
  invalid_fixtures: invalidFixtures,
})) {
  if (value.length !== expectedCounts[name]) {
    throw new Error(`${name} contains ${value.length} files; expected ${expectedCounts[name]}`);
  }
}

const contractFiles = [...schemas, ...validFixtures, ...invalidFixtures]
  .map(({ path, sha256: digest }) => ({ path, sha256: digest }))
  .sort((left, right) => left.path.localeCompare(right.path));

const identity = {
  schema: "openaria.bridge.desktop.vendored-device-session-contracts.v1",
  source_snapshot: sourceSnapshot,
  source_note:
    "Curated Open Aria Device Session consumer snapshot; provenance is the snapshot id plus per-file SHA-256.",
  local_authority: "per_file_sha256",
  contract_file_count: contractFiles.length,
  contract_files: contractFiles,
  schemas,
  valid_fixtures: validFixtures,
  invalid_fixtures: invalidFixtures,
  runtime_gate: {
    schemas: "Embedded in the transfer detector and validated by Rust tests.",
    reference_files: "Reference-only conformance material; no script from the snapshot is executed at runtime.",
  },
};

const rendered = `${JSON.stringify(identity, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (!existsSync(identityPath) || readFileSync(identityPath, "utf8") !== rendered) {
    throw new Error("fixtures/device-session-v1/contract-identity.json is stale; run the generator without --check");
  }
} else {
  writeFileSync(identityPath, rendered);
}
