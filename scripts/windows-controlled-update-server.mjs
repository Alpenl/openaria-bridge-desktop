import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import https from "node:https";
import path from "node:path";
import { setTimeout } from "node:timers";
import { fileURLToPath } from "node:url";

const SHA256 = /^[a-f0-9]{64}$/;
const NUMERIC_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function atomicJson(file, value) {
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(temporary, file);
}

export function validateControlledServerPlan(plan) {
  invariant(
    plan?.schema === "openaria.desktop.controlled-update-server.v1",
    "controlled server plan schema is invalid",
  );
  invariant(plan.host === "github.com", "controlled updater host must be github.com");
  invariant(
    plan.repository === "Alpenl/openaria-bridge-desktop",
    "controlled updater repository is not the production repository",
  );
  invariant(NUMERIC_SEMVER.test(plan.version), "controlled updater version is invalid");
  invariant(path.isAbsolute(plan.manifest.file), "controlled latest.json path must be absolute");
  invariant(path.isAbsolute(plan.installer.file), "controlled installer path must be absolute");
  invariant(
    Number.isSafeInteger(plan.manifest.bytes) && plan.manifest.bytes > 0,
    "controlled manifest size is invalid",
  );
  invariant(
    Number.isSafeInteger(plan.installer.bytes) && plan.installer.bytes > 0,
    "controlled installer size is invalid",
  );
  invariant(SHA256.test(plan.manifest.sha256), "controlled manifest SHA-256 is invalid");
  invariant(SHA256.test(plan.installer.sha256), "controlled installer SHA-256 is invalid");

  const manifestPath = `/${plan.repository}/releases/latest/download/latest.json`;
  const installerPath = `/${plan.repository}/releases/download/${plan.version}/${plan.installer.name}`;
  invariant(plan.manifest.request_path === manifestPath, "controlled latest.json request path is not production-exact");
  invariant(plan.installer.request_path === installerPath, "controlled installer request path is not production-exact");

  for (const [label, item] of [
    ["manifest", plan.manifest],
    ["installer", plan.installer],
  ]) {
    const bytes = readFileSync(item.file);
    invariant(bytes.length === item.bytes, `controlled ${label} bytes changed`);
    invariant(sha256(bytes) === item.sha256, `controlled ${label} digest changed`);
  }
  return plan;
}

function parseSingleRange(header, totalBytes) {
  if (header === undefined) return null;
  const match = header.match(/^bytes=(\d*)-(\d*)$/);
  invariant(match !== null, "controlled server received an invalid or multi-part Range header");
  let start;
  let end;
  if (match[1] === "") {
    const suffix = Number(match[2]);
    invariant(Number.isSafeInteger(suffix) && suffix > 0, "controlled server suffix range is invalid");
    start = Math.max(0, totalBytes - suffix);
    end = totalBytes - 1;
  } else {
    start = Number(match[1]);
    end = match[2] === "" ? totalBytes - 1 : Number(match[2]);
  }
  invariant(
    Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 0 && start <= end && end < totalBytes,
    "controlled server Range is outside the exact asset",
  );
  return { start, end };
}

export function resolveControlledRequest(plan, request) {
  validateControlledServerPlan(plan);
  const host = String(request.headers?.host ?? "")
    .toLowerCase()
    .replace(/:443$/, "");
  const method = String(request.method ?? "").toUpperCase();
  const url = new URL(request.url, "https://github.com");
  if (host !== plan.host || !["GET", "HEAD"].includes(method) || url.search !== "") {
    return { status: 404, kind: "rejected", body: Buffer.from("not found\n"), headers: {} };
  }

  const entry = [plan.manifest, plan.installer].find((candidate) => candidate.request_path === url.pathname);
  if (entry === undefined) {
    return { status: 404, kind: "rejected", body: Buffer.from("not found\n"), headers: {} };
  }
  const source = readFileSync(entry.file);
  const range = parseSingleRange(request.headers?.range, source.length);
  const body = range === null ? source : source.subarray(range.start, range.end + 1);
  const headers = {
    "accept-ranges": "bytes",
    "cache-control": "no-store",
    "content-length": String(body.length),
    "content-type": entry === plan.manifest ? "application/json" : "application/octet-stream",
  };
  if (range !== null) headers["content-range"] = `bytes ${range.start}-${range.end}/${source.length}`;
  return {
    status: range === null ? 200 : 206,
    kind: entry === plan.manifest ? "manifest" : "installer",
    body,
    headers,
    range,
    source_bytes: source.length,
    source_sha256: sha256(source),
  };
}

function options(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    invariant(argv[index]?.startsWith("--"), `expected option, got ${argv[index]}`);
    invariant(argv[index + 1] !== undefined, `missing value for ${argv[index]}`);
    values.set(argv[index].slice(2), argv[index + 1]);
  }
  return values;
}

function required(values, name) {
  const value = values.get(name);
  invariant(value !== undefined && value !== "", `missing --${name}`);
  return value;
}

async function serve(values) {
  const plan = validateControlledServerPlan(JSON.parse(readFileSync(required(values, "plan"), "utf8")));
  const pfx = readFileSync(required(values, "pfx"));
  const passphrase = readFileSync(required(values, "passphrase-file"), "utf8");
  const readyFile = required(values, "ready");
  const logFile = required(values, "log");
  const log = {
    schema: "openaria.desktop.controlled-update-server-log.v1",
    host: plan.host,
    repository: plan.repository,
    version: plan.version,
    started_at: new Date().toISOString(),
    requests: [],
  };
  atomicJson(logFile, log);

  const server = https.createServer({ pfx, passphrase }, (request, response) => {
    let resolved;
    try {
      resolved = resolveControlledRequest(plan, request);
    } catch (error) {
      resolved = {
        status: 416,
        kind: "rejected",
        body: Buffer.from("range not satisfiable\n"),
        headers: {},
        failure: error instanceof Error ? error.message : String(error),
      };
    }
    const entry = {
      at: new Date().toISOString(),
      method: request.method ?? null,
      host: request.headers.host ?? null,
      url: request.url ?? null,
      user_agent: request.headers["user-agent"] ?? null,
      range: request.headers.range ?? null,
      status: resolved.status,
      kind: resolved.kind,
      response_bytes: request.method === "HEAD" ? 0 : resolved.body.length,
      source_bytes: resolved.source_bytes ?? null,
      source_sha256: resolved.source_sha256 ?? null,
      failure: resolved.failure ?? null,
    };
    log.requests.push(entry);
    atomicJson(logFile, log);
    response.writeHead(resolved.status, resolved.headers);
    response.end(request.method === "HEAD" ? undefined : resolved.body);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(443, "127.0.0.1", resolve);
  });
  writeFileSync(
    readyFile,
    `${JSON.stringify({ pid: process.pid, host: "127.0.0.1", port: 443, ready_at: new Date().toISOString() })}\n`,
  );

  const stop = () => {
    log.finished_at = new Date().toISOString();
    atomicJson(logFile, log);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

async function main(argv) {
  const [command, ...rest] = argv;
  invariant(command === "serve", `unknown command ${JSON.stringify(command)}`);
  await serve(options(rest));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  });
}
