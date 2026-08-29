import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { JSON_SCHEMA, load as loadYaml } from "js-yaml";

const modulePath = fileURLToPath(import.meta.url);
const repository = resolve(dirname(modulePath), "..");

export const PINNED_DEVICE_API_CONTRACT = Object.freeze({
  major: 4,
  path: "openapi/ylx-device-v4.openapi.yaml",
  sha256: "b6f3c677c038e55c03581c587973811b0aa2dc91cfb8b602a95128fbac225827",
  bytes: 124739,
  info_version: "4.0.0",
  server_base_path: "/api/v4",
  lifecycle: "current",
});

const PINNED_PROVENANCE = Object.freeze({
  schema: "openaria.bridge.desktop.vendored-device-api-contract.v1",
  source_repository: "https://github.com/mirrorbloom/openaria-score",
  source_commit: "91a92d676bfeb96aa60b48d46f194c083d7aa32d",
  source_path: "contracts/openapi/ylx-device-v4.openapi.yaml",
  sha256: PINNED_DEVICE_API_CONTRACT.sha256,
  bytes: PINNED_DEVICE_API_CONTRACT.bytes,
});

const SUPPORT_PATH = "contracts/ylx-device-api-support.json";
const PROVENANCE_PATH = "contracts/openapi/ylx-device-v4.provenance.json";
const SESSION_LIST_V2_FIXTURE = "contracts/fixtures/device-api/session-list-v2.response.json";
const SESSION_LIST_V3_FIXTURE = "contracts/fixtures/device-api/session-list-v3.response.json";
const CATALOG_CHANGED_FIXTURE = "contracts/fixtures/device-api/catalog-changed.error.json";
const CATALOG_REVISION = /^sha256:[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class ContractError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "ContractError";
  }
}

function requireCondition(condition, message) {
  if (!condition) {
    throw new ContractError(message);
  }
}

function requireObject(value, label) {
  requireCondition(typeof value === "object" && value !== null && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function requireExactKeys(value, expectedKeys, label) {
  const object = requireObject(value, label);
  const actual = Object.keys(object).sort();
  const expected = [...expectedKeys].sort();
  requireCondition(
    isDeepStrictEqual(actual, expected),
    `${label} must be closed with exactly [${expected.join(", ")}]; got [${actual.join(", ")}]`,
  );
  return object;
}

function readRequiredBytes(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (error) {
    throw new ContractError(`${label} missing at ${path}`, { cause: error });
  }
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular file`);
  return readFileSync(path);
}

function readJson(root, relativePath, label) {
  const bytes = readRequiredBytes(join(root, relativePath), `${label} (${relativePath})`);
  try {
    return requireObject(JSON.parse(bytes.toString("utf8")), label);
  } catch (error) {
    if (error instanceof ContractError) {
      throw error;
    }
    throw new ContractError(`${label} is not valid JSON: ${error.message}`, { cause: error });
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireDeepEqual(actual, expected, label) {
  requireCondition(isDeepStrictEqual(actual, expected), `${label} drifted from its pinned value`);
}

function requireRef(value, expected, label) {
  requireExactKeys(value, ["$ref"], label);
  requireCondition(value.$ref === expected, `${label} must reference ${expected}`);
}

export function parseOpenApi(source) {
  let document;
  try {
    document = loadYaml(source, { schema: JSON_SCHEMA });
  } catch (error) {
    throw new ContractError(`OpenAPI YAML is invalid: ${error.message}`, { cause: error });
  }
  return requireObject(document, "OpenAPI document");
}

function expectedCatalogChangedErrorSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "error"],
    properties: {
      schema: { const: "ylx.api-error.v2" },
      error: {
        type: "object",
        additionalProperties: false,
        required: ["code", "message", "request_id", "retryable", "details"],
        properties: {
          code: { const: "catalog_changed" },
          message: { type: "string", minLength: 1, maxLength: 1024 },
          request_id: { type: "string", format: "uuid" },
          retryable: { const: true },
          details: {
            type: "object",
            additionalProperties: false,
            required: ["catalog_revision"],
            properties: {
              catalog_revision: {
                type: "string",
                pattern: "^sha256:[0-9a-f]{64}$",
              },
            },
          },
        },
      },
    },
  };
}

function validateSessionListSchema(sessionList) {
  requireExactKeys(
    sessionList,
    ["type", "additionalProperties", "required", "properties"],
    "OpenAPI SessionList schema",
  );
  requireCondition(sessionList.type === "object", "OpenAPI SessionList type must be object");
  requireCondition(sessionList.additionalProperties === false, "OpenAPI SessionList must reject additional properties");
  requireDeepEqual(
    sessionList.required,
    ["schema", "catalog_revision", "items", "diagnostics", "next_cursor"],
    "OpenAPI SessionList required fields",
  );
  const properties = requireExactKeys(
    sessionList.properties,
    ["schema", "catalog_revision", "items", "diagnostics", "next_cursor"],
    "OpenAPI SessionList properties",
  );
  requireCondition(
    properties.schema?.const === "ylx.session-list.v3",
    "OpenAPI SessionList discriminator must be ylx.session-list.v3",
  );
  requireCondition(
    properties.catalog_revision?.type === "string" && properties.catalog_revision?.pattern === "^sha256:[0-9a-f]{64}$",
    "OpenAPI SessionList catalog_revision identity drifted",
  );
  requireRef(properties.items?.items, "#/components/schemas/SessionSummary", "OpenAPI SessionList items");
  requireCondition(properties.items?.type === "array", "OpenAPI SessionList items must be an array");
  requireRef(
    properties.diagnostics?.items,
    "#/components/schemas/SessionDiscoveryDiagnostic",
    "OpenAPI SessionList diagnostics",
  );
  requireCondition(properties.diagnostics?.type === "array", "OpenAPI SessionList diagnostics must be an array");
  requireDeepEqual(
    properties.next_cursor,
    { oneOf: [{ type: "string", minLength: 1 }, { type: "null" }] },
    "OpenAPI SessionList next_cursor",
  );
}

export function validateOpenApiSemantics(document) {
  requireCondition(document.openapi === "3.1.0", "OpenAPI version must be 3.1.0");
  requireCondition(
    document.info?.version === PINNED_DEVICE_API_CONTRACT.info_version,
    `OpenAPI info.version must be ${PINNED_DEVICE_API_CONTRACT.info_version}`,
  );
  requireCondition(
    Array.isArray(document.servers) &&
      document.servers.some(
        (server) => typeof server?.url === "string" && server.url.endsWith(PINNED_DEVICE_API_CONTRACT.server_base_path),
      ),
    `OpenAPI servers must expose ${PINNED_DEVICE_API_CONTRACT.server_base_path}`,
  );

  const schemas = requireObject(document.components?.schemas, "OpenAPI components.schemas");
  validateSessionListSchema(requireObject(schemas.SessionList, "OpenAPI SessionList"));
  requireCondition(
    schemas.ErrorResponse?.properties?.schema?.const === "ylx.api-error.v2",
    "OpenAPI ErrorResponse discriminator must be ylx.api-error.v2",
  );
  requireDeepEqual(
    schemas.CatalogChangedError,
    expectedCatalogChangedErrorSchema(),
    "OpenAPI CatalogChangedError closed retryable envelope",
  );

  const sessionResponses = requireObject(
    document.paths?.["/sessions"]?.get?.responses,
    "OpenAPI GET /sessions responses",
  );
  requireRef(
    sessionResponses["200"]?.content?.["application/json"]?.schema,
    "#/components/schemas/SessionList",
    "OpenAPI GET /sessions 200",
  );
  requireRef(sessionResponses["409"], "#/components/responses/CatalogChanged", "OpenAPI GET /sessions 409");
  requireRef(
    document.components?.responses?.CatalogChanged?.content?.["application/problem+json"]?.schema,
    "#/components/schemas/CatalogChangedError",
    "OpenAPI CatalogChanged response",
  );
}

function validateSessionListFixture(fixture, major) {
  const isV3 = major === 3;
  const label = `session-list v${major} response`;
  const keys = isV3
    ? ["schema", "catalog_revision", "items", "diagnostics", "next_cursor"]
    : ["schema", "items", "diagnostics", "next_cursor"];
  requireExactKeys(fixture, keys, label);
  requireCondition(
    fixture.schema === `ylx.session-list.v${major}`,
    `${label} discriminator must be ylx.session-list.v${major}`,
  );
  if (isV3) {
    requireCondition(
      typeof fixture.catalog_revision === "string" && CATALOG_REVISION.test(fixture.catalog_revision),
      "session-list v3 catalog_revision must be a sha256 identity",
    );
  }
  requireCondition(Array.isArray(fixture.items), `${label} items must be an array`);
  requireCondition(Array.isArray(fixture.diagnostics), `${label} diagnostics must be an array`);
  requireCondition(
    fixture.next_cursor === null || (typeof fixture.next_cursor === "string" && fixture.next_cursor.length > 0),
    `${label} next_cursor must be null or a nonempty string`,
  );
}

function validateSessionListIdentity(v2, v3) {
  const v3AsV2 = JSON.parse(JSON.stringify(v3));
  v3AsV2.schema = "ylx.session-list.v2";
  delete v3AsV2.catalog_revision;
  requireDeepEqual(v3AsV2, v2, "session-list v2/v3 fixture identity");
}

function validateCatalogChangedFixture(fixture, document) {
  requireExactKeys(fixture, ["schema", "error"], "catalog_changed error envelope");
  requireCondition(
    fixture.schema === document.components.schemas.CatalogChangedError.properties.schema.const,
    "catalog_changed envelope must use ylx.api-error.v2",
  );
  const error = requireExactKeys(
    fixture.error,
    ["code", "message", "request_id", "retryable", "details"],
    "catalog_changed error",
  );
  requireCondition(error.code === "catalog_changed", "catalog_changed error code drifted");
  requireCondition(
    typeof error.message === "string" && error.message.length >= 1 && error.message.length <= 1024,
    "catalog_changed message must contain 1..1024 characters",
  );
  requireCondition(
    typeof error.request_id === "string" && UUID.test(error.request_id),
    "catalog_changed request_id must be a UUID",
  );
  requireCondition(error.retryable === true, "catalog_changed retryable must be true");
  const details = requireExactKeys(error.details, ["catalog_revision"], "catalog_changed details");
  requireCondition(
    typeof details.catalog_revision === "string" && CATALOG_REVISION.test(details.catalog_revision),
    "catalog_changed details.catalog_revision must be a sha256 identity",
  );
}

function resolveContractPath(root, descriptor) {
  requireCondition(!isAbsolute(descriptor.path), "support manifest OpenAPI path must be relative");
  const contractsRoot = resolve(root, "contracts");
  const path = resolve(contractsRoot, descriptor.path);
  const fromContracts = relative(contractsRoot, path);
  requireCondition(
    fromContracts !== "" && fromContracts !== ".." && !fromContracts.startsWith(`..${sep}`),
    "support manifest OpenAPI path escapes contracts/",
  );
  return path;
}

export function validateDeviceApiContract(root = repository) {
  const absoluteRoot = resolve(root);
  const support = readJson(absoluteRoot, SUPPORT_PATH, "Device API support manifest");
  requireExactKeys(
    support,
    ["schema", "consumer", "supported_device_api_majors", "unknown_major_policy", "required_contracts"],
    "Device API support manifest",
  );
  requireCondition(support.schema === "ylx.device-api-consumer-support.v1", "support manifest schema drifted");
  requireCondition(support.consumer === "openaria-bridge-desktop", "support manifest consumer drifted");
  requireDeepEqual(support.supported_device_api_majors, [4], "support manifest API majors");
  requireCondition(
    support.unknown_major_policy === "fail_closed",
    "support manifest unknown-major policy must fail closed",
  );
  requireCondition(
    isDeepStrictEqual(support.required_contracts, [PINNED_DEVICE_API_CONTRACT]),
    "support manifest is not the pinned Device API v4 SHA-256/bytes identity",
  );

  const provenance = readJson(absoluteRoot, PROVENANCE_PATH, "OpenAPI provenance");
  requireExactKeys(provenance, Object.keys(PINNED_PROVENANCE), "OpenAPI provenance");
  for (const [field, expected] of Object.entries(PINNED_PROVENANCE)) {
    requireCondition(provenance[field] === expected, `OpenAPI provenance ${field} must be ${expected}`);
  }

  const descriptor = support.required_contracts[0];
  const openApiPath = resolveContractPath(absoluteRoot, descriptor);
  const openApiBytes = readRequiredBytes(openApiPath, "Device API v4 OpenAPI");
  requireCondition(
    openApiBytes.length === descriptor.bytes,
    `Device API v4 OpenAPI bytes must be ${descriptor.bytes}; got ${openApiBytes.length}`,
  );
  const actualSha256 = sha256(openApiBytes);
  requireCondition(
    actualSha256 === descriptor.sha256,
    `Device API v4 OpenAPI SHA-256 must be ${descriptor.sha256}; got ${actualSha256}`,
  );
  const document = parseOpenApi(openApiBytes.toString("utf8"));
  validateOpenApiSemantics(document);

  const sessionListV2 = readJson(absoluteRoot, SESSION_LIST_V2_FIXTURE, "session-list v2 response fixture");
  const sessionListV3 = readJson(absoluteRoot, SESSION_LIST_V3_FIXTURE, "session-list v3 response fixture");
  const catalogChanged = readJson(absoluteRoot, CATALOG_CHANGED_FIXTURE, "catalog_changed error fixture");
  validateSessionListFixture(sessionListV2, 2);
  validateSessionListFixture(sessionListV3, 3);
  validateSessionListIdentity(sessionListV2, sessionListV3);
  validateCatalogChangedFixture(catalogChanged, document);
}

function parseRootArgument(args) {
  if (args.length === 0) {
    return repository;
  }
  requireCondition(
    args.length === 2 && args[0] === "--root" && args[1].length > 0,
    "usage: validate-device-api-contract.mjs [--root REPOSITORY]",
  );
  return args[1];
}

if (process.argv[1] && resolve(process.argv[1]) === modulePath) {
  try {
    const root = parseRootArgument(process.argv.slice(2));
    validateDeviceApiContract(root);
    console.log(
      `Device API v4 contract verified: ${PINNED_DEVICE_API_CONTRACT.sha256} ` +
        `(${PINNED_DEVICE_API_CONTRACT.bytes} bytes); response/error fixtures verified`,
    );
  } catch (error) {
    console.error(`Device API contract validation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
