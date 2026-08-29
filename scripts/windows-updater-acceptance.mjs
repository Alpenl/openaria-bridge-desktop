import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { clearTimeout, setTimeout } from "node:timers";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { normalizedAssetPins, releaseAssetUrl, validateReleaseAssetUrl } from "./desktop-release-commit-point.mjs";
import { validateControlledServerPlan } from "./windows-controlled-update-server.mjs";

const NUMERIC_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const WINDOWS_PLATFORM = "windows-x86_64";
const FETCH_ATTEMPTS = 6;
const APP_START_TIMEOUT_MS = 90_000;
const UPDATE_HANDOFF_TIMEOUT_MS = 5 * 60_000;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function numericVersion(value, label) {
  invariant(typeof value === "string" && NUMERIC_SEMVER.test(value), `${label} must use numeric SemVer X.Y.Z`);
  return value;
}

function compareVersions(left, right) {
  const leftParts = numericVersion(left, "left version").split(".").map(Number);
  const rightParts = numericVersion(right, "right version").split(".").map(Number);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function releaseNames(version) {
  return {
    setup: `OpenAriaBridge_${version}_windows_x86_64-setup.exe`,
    setupSignature: `OpenAriaBridge_${version}_windows_x86_64-setup.exe.sig`,
    msi: `OpenAriaBridge_${version}_windows_x86_64.msi`,
    msiSignature: `OpenAriaBridge_${version}_windows_x86_64.msi.sig`,
  };
}

function parseSha256Sums(source) {
  const sums = new Map();
  for (const line of source.trim().split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64}) {2}([^/\\]+)$/);
    invariant(match !== null, `invalid SHA256SUMS line: ${line}`);
    invariant(!sums.has(match[2]), `duplicate SHA256SUMS entry: ${match[2]}`);
    sums.set(match[2], match[1]);
  }
  return sums;
}

function releaseAssetMap(release, label) {
  invariant(release !== null && typeof release === "object", `${label} metadata must be an object`);
  invariant(Array.isArray(release.assets), `${label} assets must be an array`);
  const assets = new Map();
  for (const asset of release.assets) {
    invariant(asset !== null && typeof asset === "object", `${label} asset metadata must be an object`);
    invariant(typeof asset.name === "string" && asset.name.length > 0, `${label} asset name is invalid`);
    invariant(!assets.has(asset.name), `${label} has duplicate asset ${asset.name}`);
    assets.set(asset.name, asset);
  }
  return assets;
}

function canonicalReleaseClosure(release) {
  return {
    assets: [...releaseAssetMap(release, "Release closure").values()]
      .map(({ name, size, digest, browser_download_url }) => ({ browser_download_url, digest, name, size }))
      .sort((left, right) => left.name.localeCompare(right.name)),
    draft: release.draft,
    id: release.id,
    immutable: release.immutable,
    prerelease: release.prerelease,
    published_at: release.published_at,
    tag_name: release.tag_name,
  };
}

function canonicalReleaseClosureSha256(release) {
  return sha256(Buffer.from(JSON.stringify(canonicalReleaseClosure(release))));
}

function validateMinisignDocument(value, label) {
  invariant(typeof value === "string" && value.trim().length > 0, `${label} is empty`);
  const compact = value.trim();
  invariant(/^[A-Za-z0-9+/]+={0,2}$/.test(compact), `${label} is not base64`);
  const decoded = Buffer.from(compact, "base64");
  invariant(decoded.length > 64, `${label} is too short`);
  invariant(decoded.toString("utf8").includes("untrusted comment:"), `${label} is not a minisign document`);
  return compact;
}

export function validateAcceptanceConfig(config) {
  invariant(config !== null && typeof config === "object", "Windows updater acceptance config must be an object");
  invariant(config.schema_version === 4, "unsupported Windows updater acceptance schema");
  invariant(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(config.repository), "acceptance repository is invalid");
  numericVersion(config.hardened_baseline_version, "acceptance hardened_baseline_version");
  numericVersion(config.formal_acceptance_target, "acceptance formal_acceptance_target");
  invariant(
    compareVersions(config.formal_acceptance_target, config.hardened_baseline_version) > 0,
    "formal acceptance target must be newer than the hardened baseline",
  );
  invariant(
    config.updater_endpoint === `https://github.com/${config.repository}/releases/latest/download/latest.json`,
    "acceptance updater endpoint is inconsistent with the repository",
  );
  invariant(
    Array.isArray(config.version_only_files) &&
      [...config.version_only_files].sort().join("\n") ===
        [
          "package-lock.json",
          "package.json",
          "src-tauri/Cargo.lock",
          "src-tauri/Cargo.toml",
          "src-tauri/tauri.conf.json",
        ].join("\n"),
    "formal two-hop acceptance must close over the five version authority files",
  );
  invariant(config.updater_runtime?.crate === "tauri-plugin-updater", "bootstrap updater runtime crate is invalid");
  invariant(/^2\.\d+\.\d+$/.test(config.updater_runtime.version), "bootstrap updater runtime version is invalid");
  invariant(SHA256.test(config.updater_runtime.cargo_checksum), "bootstrap updater runtime checksum is invalid");
  const legacy = config.legacy_bootstrap;
  invariant(legacy !== null && typeof legacy === "object", "legacy bootstrap pin is missing");
  numericVersion(legacy.target_version, "legacy bootstrap target_version");
  numericVersion(legacy.baseline_version, "legacy bootstrap baseline_version");
  invariant(
    legacy.target_version === config.hardened_baseline_version,
    "legacy bootstrap must create the hardened baseline",
  );
  invariant(
    compareVersions(legacy.target_version, legacy.baseline_version) > 0 &&
      compareVersions(config.formal_acceptance_target, legacy.target_version) > 0,
    "legacy bootstrap versions must be a closed baseline -> hardened -> formal sequence",
  );
  invariant(Number.isSafeInteger(legacy.release_id) && legacy.release_id > 0, "legacy bootstrap Release ID is invalid");
  invariant(GIT_COMMIT.test(legacy.commit), "legacy bootstrap commit is invalid");
  invariant(SHA256.test(legacy.canonical_closure_sha256), "legacy bootstrap closure digest is invalid");
  const canonicalLegacyClosure = canonicalReleaseClosure(legacy.canonical_closure);
  invariant(
    JSON.stringify(canonicalLegacyClosure) === JSON.stringify(legacy.canonical_closure),
    "legacy bootstrap closure tuple is not canonical",
  );
  invariant(
    canonicalLegacyClosure.id === legacy.release_id &&
      canonicalLegacyClosure.tag_name === legacy.baseline_version &&
      canonicalLegacyClosure.draft === false &&
      canonicalLegacyClosure.prerelease === false &&
      canonicalLegacyClosure.immutable === false &&
      typeof canonicalLegacyClosure.published_at === "string",
    "legacy bootstrap closure tuple identity is invalid",
  );
  invariant(
    sha256(Buffer.from(JSON.stringify(canonicalLegacyClosure))) === legacy.canonical_closure_sha256,
    "legacy bootstrap closure tuple digest is inconsistent",
  );
  invariant(SHA256.test(legacy.latest_json_sha256), "legacy bootstrap latest.json digest is invalid");
  invariant(
    Array.isArray(legacy.assets) && legacy.assets.length === 5,
    "legacy bootstrap must pin exactly five assets",
  );
  for (const asset of legacy.assets) {
    invariant(typeof asset.name === "string" && asset.name.length > 0, "legacy bootstrap asset name is invalid");
    invariant(Number.isSafeInteger(asset.size) && asset.size > 0, "legacy bootstrap asset size is invalid");
    invariant(/^sha256:[a-f0-9]{64}$/.test(asset.digest), "legacy bootstrap asset digest is invalid");
  }
  invariant(
    JSON.stringify(normalizedAssetPins(canonicalLegacyClosure.assets)) ===
      JSON.stringify(normalizedAssetPins(legacy.assets)),
    "legacy bootstrap closure tuple and asset pins differ",
  );
  return config;
}

export function assertAnonymousFetchAllowed(url, { config, targetVersion, bootstrapUrl = null }, purpose) {
  const targetNames = releaseNames(targetVersion);
  const forbiddenTargetInstaller = `https://github.com/${config.repository}/releases/download/${targetVersion}/${targetNames.setup}`;
  if (url === forbiddenTargetInstaller) {
    throw new Error("acceptance harness must not download the target installer; the old application must do it");
  }
  if (/\.(?:exe|msi)(?:$|\?)/i.test(url)) {
    invariant(
      purpose === "bootstrap-installer" && bootstrapUrl !== null && url === bootstrapUrl,
      `acceptance harness attempted an unauthorized executable download for ${purpose}`,
    );
  }
}

export function validateBootstrapRelease({
  config,
  targetVersion,
  release,
  tagRef,
  manifestBytes,
  signatureBytes,
  allowLegacyBootstrap = false,
}) {
  const manifest = parseJson(manifestBytes, "pre-publish latest.json");
  const baselineVersion = numericVersion(manifest.version, "pre-publish latest.json version");
  invariant(
    compareVersions(targetVersion, baselineVersion) > 0,
    "target must be newer than pre-publish latest baseline",
  );
  invariant(release.tag_name === baselineVersion, "bootstrap Release tag is inconsistent");
  invariant(release.draft === false && release.prerelease === false, "bootstrap Release is not public and stable");
  invariant(typeof release.published_at === "string", "bootstrap Release has no publication timestamp");
  invariant(tagRef?.ref === `refs/tags/${baselineVersion}`, "bootstrap Git ref is inconsistent");
  invariant(tagRef.object?.type === "commit", "bootstrap tag must resolve directly to a commit");
  invariant(GIT_COMMIT.test(tagRef.object.sha), "bootstrap tag commit is invalid");
  invariant(
    Object.keys(manifest.platforms ?? {}).length === 1 && manifest.platforms[WINDOWS_PLATFORM] !== undefined,
    "pre-publish latest.json must contain only windows-x86_64",
  );

  const names = releaseNames(baselineVersion);
  const expectedUrl = `https://github.com/${config.repository}/releases/download/${baselineVersion}/${names.setup}`;
  const platform = manifest.platforms[WINDOWS_PLATFORM];
  invariant(platform.url === expectedUrl, "pre-publish latest.json does not point at its baseline Release");
  const manifestSignature = validateMinisignDocument(platform.signature, "pre-publish latest.json signature");
  invariant(
    manifestSignature === signatureBytes.toString("utf8").trim(),
    "pre-publish latest.json signature differs from baseline .sig asset",
  );

  const assets = releaseAssetMap(release, "bootstrap Release");
  const installerAsset = assets.get(names.setup);
  const signatureAsset = assets.get(names.setupSignature);
  invariant(
    installerAsset !== undefined && signatureAsset !== undefined,
    "bootstrap Release lacks NSIS updater assets",
  );
  for (const [name, asset] of [
    [names.setup, installerAsset],
    [names.setupSignature, signatureAsset],
  ]) {
    invariant(asset.state === undefined || asset.state === "uploaded", `${name} is not uploaded`);
    invariant(Number.isSafeInteger(asset.size) && asset.size > 0, `${name} published size is invalid`);
    invariant(/^sha256:[a-f0-9]{64}$/.test(asset.digest), `${name} GitHub digest is invalid`);
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: config.repository,
      version: baselineVersion,
      name,
      expectedDraft: false,
    });
  }
  invariant(signatureBytes.length === signatureAsset.size, "downloaded bootstrap signature size differs from GitHub");
  invariant(
    signatureAsset.digest === `sha256:${sha256(signatureBytes)}`,
    "downloaded bootstrap signature digest differs from GitHub",
  );
  validateMinisignDocument(signatureBytes.toString("utf8"), "bootstrap signature");

  const legacy = config.legacy_bootstrap;
  const isLegacyBootstrap =
    allowLegacyBootstrap === true &&
    targetVersion === legacy.target_version &&
    baselineVersion === legacy.baseline_version;
  if (allowLegacyBootstrap) {
    invariant(isLegacyBootstrap, "legacy baseline bootstrap is valid only for its one pinned target");
    invariant(release.id === legacy.release_id, "legacy baseline Release ID differs from the pinned bootstrap");
    invariant(tagRef.object.sha === legacy.commit, "legacy baseline commit differs from the pinned bootstrap");
    invariant(release.immutable === false, "legacy bootstrap exception is only for the pinned mutable Release");
    invariant(
      JSON.stringify(canonicalReleaseClosure(release)) === JSON.stringify(legacy.canonical_closure) &&
        canonicalReleaseClosureSha256(release) === legacy.canonical_closure_sha256,
      "legacy baseline canonical Release closure changed",
    );
    invariant(
      JSON.stringify(normalizedAssetPins([...assets.values()])) === JSON.stringify(normalizedAssetPins(legacy.assets)),
      "legacy baseline asset pins changed",
    );
    invariant(sha256(manifestBytes) === legacy.latest_json_sha256, "legacy baseline latest.json bytes changed");
  } else {
    invariant(release.immutable === true, "normal updater baseline must be an immutable public Release");
    const expectedNames = [
      names.setup,
      names.setupSignature,
      names.msi,
      names.msiSignature,
      "SHA256SUMS",
      "latest.json",
    ].sort();
    invariant(
      [...assets.keys()].sort().join("\n") === expectedNames.join("\n"),
      "normal updater baseline must have the exact six-asset Windows closure",
    );
  }
  const latestAsset = assets.get("latest.json");
  invariant(latestAsset !== undefined, "bootstrap Release lacks latest.json");
  invariant(latestAsset.size === manifestBytes.length, "bootstrap latest.json size differs from Release metadata");
  invariant(
    latestAsset.digest === `sha256:${sha256(manifestBytes)}`,
    "bootstrap latest.json digest differs from Release metadata",
  );
  return {
    manifest,
    baselineVersion,
    names,
    installerAsset,
    signatureAsset,
    commit: tagRef.object.sha,
    isLegacyBootstrap,
    releaseClosure: canonicalReleaseClosure(release),
    releaseClosureSha256: canonicalReleaseClosureSha256(release),
  };
}

export function validateTargetRelease({
  config,
  version,
  manifestBytes,
  release,
  signatureBytes,
  sumsBytes,
  expectedDraft = false,
}) {
  numericVersion(version, "acceptance target version");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  invariant(manifest.version === version, `latest.json version ${manifest.version} != ${version}`);
  invariant(
    Object.keys(manifest.platforms ?? {}).length === 1 && manifest.platforms[WINDOWS_PLATFORM] !== undefined,
    "latest.json must contain only windows-x86_64",
  );
  invariant(release.tag_name === version, `published Release tag ${release.tag_name} != ${version}`);
  invariant(release.draft === expectedDraft, `target Release draft=${release.draft} != ${expectedDraft}`);
  invariant(release.prerelease === false, "target Release must not be a prerelease");
  invariant(Number.isSafeInteger(release.id) && release.id > 0, "target Release numeric ID is invalid");
  if (expectedDraft) {
    invariant(release.published_at === null, "never-public target draft has a publication timestamp");
  } else {
    invariant(typeof release.published_at === "string", "published target has no publication timestamp");
    invariant(release.immutable === true, "published target Release is not immutable");
  }

  const names = releaseNames(version);
  const expectedNames = [
    names.setup,
    names.setupSignature,
    names.msi,
    names.msiSignature,
    "SHA256SUMS",
    "latest.json",
  ].sort();
  const assets = releaseAssetMap(release, "target Release");
  invariant(
    [...assets.keys()].sort().join("\n") === expectedNames.join("\n"),
    "target GitHub Release must contain exactly the six Windows updater assets",
  );

  const setup = assets.get(names.setup);
  const setupSignature = assets.get(names.setupSignature);
  const latestAsset = assets.get("latest.json");
  const sumsAsset = assets.get("SHA256SUMS");
  for (const [name, asset] of assets) {
    invariant(asset.state === undefined || asset.state === "uploaded", `${name} is not in uploaded state`);
    invariant(Number.isSafeInteger(asset.size) && asset.size > 0, `${name} published size is invalid`);
    invariant(
      typeof asset.digest === "string" && /^sha256:[a-f0-9]{64}$/.test(asset.digest),
      `${name} GitHub digest is invalid`,
    );
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: config.repository,
      version,
      name,
      expectedDraft,
    });
  }
  invariant(latestAsset.size === manifestBytes.length, "latest.json GitHub size differs from anonymous bytes");
  invariant(
    latestAsset.digest === `sha256:${sha256(manifestBytes)}`,
    "latest.json GitHub digest differs from anonymous bytes",
  );
  invariant(sumsAsset.size === sumsBytes.length, "SHA256SUMS GitHub size differs from anonymous bytes");
  invariant(
    sumsAsset.digest === `sha256:${sha256(sumsBytes)}`,
    "SHA256SUMS GitHub digest differs from anonymous bytes",
  );
  invariant(setupSignature.size === signatureBytes.length, "setup signature GitHub size differs from anonymous bytes");
  invariant(
    setupSignature.digest === `sha256:${sha256(signatureBytes)}`,
    "setup signature GitHub digest differs from anonymous bytes",
  );

  const expectedUrl = releaseAssetUrl(config.repository, version, names.setup);
  const platform = manifest.platforms[WINDOWS_PLATFORM];
  invariant(platform.url === expectedUrl, `latest.json installer URL ${platform.url} != ${expectedUrl}`);
  const manifestSignature = validateMinisignDocument(platform.signature, "latest.json signature");
  invariant(
    manifestSignature === signatureBytes.toString("utf8").trim(),
    "latest.json signature differs from .sig asset",
  );

  const sums = parseSha256Sums(sumsBytes.toString("utf8"));
  const expectedChecksumNames = [names.setup, names.setupSignature, names.msi, names.msiSignature].sort();
  invariant([...sums.keys()].sort().join("\n") === expectedChecksumNames.join("\n"), "SHA256SUMS closure is invalid");
  const setupDigest = setup.digest.slice("sha256:".length);
  invariant(sums.get(names.setup) === setupDigest, "setup SHA256SUMS digest differs from GitHub digest");

  return {
    release_id: release.id,
    manifest,
    names,
    setup: {
      name: names.setup,
      url: expectedUrl,
      bytes: setup.size,
      sha256: setupDigest,
      github_digest: setup.digest,
    },
    signature: {
      name: names.setupSignature,
      bytes: setupSignature.size,
      sha256: setupSignature.digest.slice("sha256:".length),
      matches_latest_json: true,
    },
    release_assets: [...assets.values()].map((asset) => ({
      name: asset.name,
      bytes: asset.size,
      digest: asset.digest,
      url: asset.browser_download_url,
    })),
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

async function fetchBytes(url, label, fetchPolicy, purpose) {
  assertAnonymousFetchAllowed(url, fetchPolicy, purpose);
  let lastError;
  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt += 1) {
    try {
      const response = await globalThis.fetch(url, {
        redirect: "follow",
        signal: globalThis.AbortSignal.timeout(60_000),
        headers: {
          accept: purpose.includes("metadata") ? "application/vnd.github+json" : "application/octet-stream",
          "cache-control": "no-cache",
          "user-agent": "openaria-windows-updater-acceptance",
          "x-github-api-version": "2022-11-28",
        },
      });
      if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
      const bytes = Buffer.from(await response.arrayBuffer());
      invariant(bytes.length > 0, `${label} is empty`);
      return bytes;
    } catch (error) {
      lastError = error;
      if (attempt < FETCH_ATTEMPTS) await delay(attempt * 2_000);
    }
  }
  throw lastError;
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function fetchPublicReleaseHistory(config, targetVersion, fetchPolicy) {
  const publicReleases = [];
  for (let page = 1; page <= 20; page += 1) {
    const url = `https://api.github.com/repos/${config.repository}/releases?per_page=100&page=${page}`;
    const releases = await authenticatedGithubJson(url, `public Release history page ${page}`);
    invariant(Array.isArray(releases), "public Release history page is not an array");
    for (const release of releases) {
      if (release.draft === false && typeof release.published_at === "string") {
        publicReleases.push(release);
      }
    }
    if (releases.length < 100) break;
    invariant(page < 20, "public Release history exceeded the closed pagination bound");
  }
  const ids = new Set();
  const tags = new Set();
  const manifests = [];
  for (const release of publicReleases) {
    invariant(Number.isSafeInteger(release.id) && !ids.has(release.id), "public Release history has duplicate IDs");
    invariant(
      typeof release.tag_name === "string" && !tags.has(release.tag_name),
      "public Release history has duplicate tags",
    );
    ids.add(release.id);
    tags.add(release.tag_name);
    const assets = releaseAssetMap(release, `public Release ${release.tag_name}`);
    const latestAsset = assets.get("latest.json");
    if (latestAsset === undefined) continue;
    const releaseVersion = numericVersion(release.tag_name, "public updater Release tag");
    invariant(
      /^sha256:[a-f0-9]{64}$/.test(latestAsset.digest),
      `public Release ${releaseVersion} latest.json digest is invalid`,
    );
    const manifestBytes = await fetchBytes(
      latestAsset.browser_download_url,
      `public Release ${releaseVersion} latest.json`,
      fetchPolicy,
      "history-metadata",
    );
    invariant(manifestBytes.length === latestAsset.size, `public Release ${releaseVersion} latest.json size changed`);
    invariant(
      latestAsset.digest === `sha256:${sha256(manifestBytes)}`,
      `public Release ${releaseVersion} latest.json digest changed`,
    );
    const manifest = parseJson(manifestBytes, `public Release ${releaseVersion} latest.json`);
    invariant(manifest.version === releaseVersion, `public Release ${releaseVersion} manifest version changed`);
    manifests.push({
      release_id: release.id,
      version: releaseVersion,
      immutable: release.immutable === true,
      prerelease: release.prerelease === true,
      published_at: release.published_at,
      latest_json: { bytes: manifestBytes.length, sha256: sha256(manifestBytes) },
    });
  }
  manifests.sort((left, right) => compareVersions(left.version, right.version));
  invariant(manifests.length > 0, "repository has no public updater Release history");
  const highest = manifests.at(-1).version;
  invariant(
    compareVersions(targetVersion, highest) > 0,
    `candidate ${targetVersion} is not strictly newer than every public updater manifest (highest ${highest})`,
  );
  return { manifests, highest_public_version: highest };
}

function gitOutput(root, args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function sourceAt(root, commit, file) {
  return execFileSync("git", ["show", `${commit}:${file}`], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function normalizeJsonVersionSource(source, file, expectedVersion) {
  const value = JSON.parse(source);
  if (file === "package.json") {
    invariant(value.version === expectedVersion, `${file} version ${value.version} != ${expectedVersion}`);
    value.version = "__OPENARIA_VERSION__";
  } else if (file === "package-lock.json") {
    invariant(value.version === expectedVersion, `${file} root version ${value.version} != ${expectedVersion}`);
    invariant(
      value.packages?.[""]?.version === expectedVersion,
      `${file} application package version ${value.packages?.[""]?.version} != ${expectedVersion}`,
    );
    value.version = "__OPENARIA_VERSION__";
    value.packages[""].version = "__OPENARIA_VERSION__";
  } else if (file === "src-tauri/tauri.conf.json") {
    invariant(value.version === expectedVersion, `${file} version ${value.version} != ${expectedVersion}`);
    value.version = "__OPENARIA_VERSION__";
  } else {
    throw new Error(`no JSON version-only normalizer for ${file}`);
  }
  return `${JSON.stringify(value, null, 2)}\n`;
}

function normalizeCargoVersionSource(source, file, expectedVersion) {
  const pattern =
    file === "src-tauri/Cargo.toml"
      ? /(\[package\][\s\S]*?^version\s*=\s*")([^"]+)("\s*$)/m
      : /(\[\[package\]\]\s*\nname\s*=\s*"ylx-transfer"\s*\nversion\s*=\s*")([^"]+)(")/m;
  const match = source.match(pattern);
  invariant(match !== null, `${file} application version field is missing`);
  invariant(match[2] === expectedVersion, `${file} version ${match[2]} != ${expectedVersion}`);
  return source.replace(pattern, `$1__OPENARIA_VERSION__$3`).replaceAll("\r\n", "\n");
}

function normalizeVersionSource(source, file, expectedVersion) {
  return file.endsWith(".json")
    ? normalizeJsonVersionSource(source, file, expectedVersion)
    : normalizeCargoVersionSource(source, file, expectedVersion);
}

function fetchAndValidateBaselineTag(root, baselineVersion, baselineCommit) {
  execFileSync("git", ["fetch", "--force", "origin", `refs/tags/${baselineVersion}:refs/tags/${baselineVersion}`], {
    cwd: root,
    stdio: "inherit",
  });
  const localBaselineCommit = gitOutput(root, ["rev-parse", `${baselineVersion}^{commit}`]);
  invariant(
    localBaselineCommit === baselineCommit,
    "local baseline tag commit differs from anonymous GitHub tag metadata",
  );
}

function validateUpdaterRuntimeSource(cargoLock, config) {
  const updaterBlocks = cargoLock
    .split(/(?=^\[\[package\]\]$)/m)
    .filter((block) => /^name = "tauri-plugin-updater"$/m.test(block));
  invariant(updaterBlocks.length === 1, "Cargo.lock must contain exactly one tauri-plugin-updater package");
  const updaterBlock = updaterBlocks[0];
  const lockedVersion = updaterBlock.match(/^version = "([^"]+)"$/m)?.[1];
  const lockedChecksum = updaterBlock.match(/^checksum = "([a-f0-9]{64})"$/m)?.[1];
  invariant(
    lockedVersion === config.updater_runtime.version,
    `baseline updater crate ${lockedVersion} != pinned ${config.updater_runtime.version}`,
  );
  invariant(
    lockedChecksum === config.updater_runtime.cargo_checksum,
    "baseline updater crate checksum differs from the pinned checksum",
  );
  return {
    verified: true,
    ...config.updater_runtime,
    cargo_lock_sha256: sha256(Buffer.from(cargoLock)),
  };
}

function validateHardenedBaselineSource(root, baselineCommit, config) {
  const files = {
    "src/runtime/appUpdater.ts": sourceAt(root, baselineCommit, "src/runtime/appUpdater.ts"),
    "src/app/transferApp.ts": sourceAt(root, baselineCommit, "src/app/transferApp.ts"),
    "src-tauri/Cargo.lock": sourceAt(root, baselineCommit, "src-tauri/Cargo.lock"),
  };
  const contracts = [
    {
      file: "src/runtime/appUpdater.ts",
      name: "reject invalid or non-newer update metadata",
      pattern: /validateAvailableAppVersion\(update\.currentVersion, update\.version\);/,
    },
    {
      file: "src/runtime/appUpdater.ts",
      name: "make native update handle closure idempotent",
      pattern: /if \(closed\) return;\s+closed = true;\s+await update\.close\(\);/,
    },
    {
      file: "src/runtime/appUpdater.ts",
      name: "make update download single-flight",
      pattern: /if \(downloading\) throw new Error\([^\n]+\);\s+downloading = true;/,
    },
    {
      file: "src/runtime/appUpdater.ts",
      name: "ignore late progress after handle closure",
      pattern: /update\.downloadAndInstall\([^]*?if \(closed\) return;/,
    },
    {
      file: "src/app/transferApp.ts",
      name: "guard updater responses by generation",
      pattern: /let updateGeneration = 0;[^]*?return !disposed && generation === updateGeneration;/,
    },
    {
      file: "src/app/transferApp.ts",
      name: "close a late check response",
      pattern:
        /const update = await updater\.check\(\);\s+if \(!currentUpdate\(generation\)\) {\s+await update\?\.close\(\)\.catch/,
    },
    {
      file: "src/app/transferApp.ts",
      name: "enter checking state before the first awaited operation",
      pattern:
        /const generation = \+\+updateGeneration;[^]*?updateStatus = "checking";[^]*?renderUpdateSettings\(\);\s+try {\s+await previousUpdate\?\.close\(\);/,
    },
    {
      file: "src/app/transferApp.ts",
      name: "close pending handle when the dialog closes",
      pattern: /function closeUpdateSettings\(\): void {[^]*?\+\+updateGeneration;[^]*?void update\?\.close\(\)\.catch/,
    },
    {
      file: "src/app/transferApp.ts",
      name: "close pending handle when the controller is disposed",
      pattern: /function dispose\(\): void {[^]*?\+\+updateGeneration;[^]*?void update\?\.close\(\)\.catch/,
    },
  ];
  for (const contract of contracts) {
    invariant(contract.pattern.test(files[contract.file]), `hardened updater source is missing: ${contract.name}`);
  }

  const updaterRuntime = validateUpdaterRuntimeSource(files["src-tauri/Cargo.lock"], config);

  return {
    verified: true,
    updater_runtime: updaterRuntime,
    files: Object.entries(files).map(([file, source]) => ({ file, sha256: sha256(Buffer.from(source)) })),
    contracts: contracts.map(({ file, name }) => ({ file, name })),
  };
}

export function validateVersionOnlyUpgrade({ root, config, baselineVersion, baselineCommit, targetVersion }) {
  invariant(
    targetVersion === config.formal_acceptance_target,
    "version-only closure is reserved for the formal target",
  );
  invariant(
    baselineVersion === config.hardened_baseline_version,
    `formal baseline ${baselineVersion} != hardened ${config.hardened_baseline_version}`,
  );
  fetchAndValidateBaselineTag(root, baselineVersion, baselineCommit);
  const targetCommit = gitOutput(root, ["rev-parse", "HEAD"]);
  invariant(GIT_COMMIT.test(targetCommit), "target HEAD is not a full Git commit");
  const changedFiles = gitOutput(root, ["diff", "--name-only", baselineCommit, targetCommit])
    .split(/\r?\n/)
    .filter(Boolean)
    .sort();
  const expectedFiles = [...config.version_only_files].sort();
  invariant(
    changedFiles.join("\n") === expectedFiles.join("\n"),
    `formal second hop must change exactly the version authority files; changed ${JSON.stringify(changedFiles)}`,
  );

  for (const file of expectedFiles) {
    const baselineSource = sourceAt(root, baselineCommit, file);
    const targetSource = readFileSync(path.join(root, file), "utf8");
    const normalizedBaseline = normalizeVersionSource(baselineSource, file, baselineVersion);
    const normalizedTarget = normalizeVersionSource(targetSource, file, targetVersion);
    invariant(
      normalizedBaseline === normalizedTarget,
      `${file} contains changes beyond ${baselineVersion} -> ${targetVersion}`,
    );
  }
  const hardenedSource = validateHardenedBaselineSource(root, baselineCommit, config);
  return {
    baseline_commit: baselineCommit,
    target_commit: targetCommit,
    changed_files: changedFiles,
    version_only: true,
    hardened_source: hardenedSource,
  };
}

function verifyCapturedInstallerSignature(root, installer, signatureBytes) {
  const scratch = mkdtempSync(path.join(os.tmpdir(), "openaria-updater-baseline-signature-"));
  const tauri = JSON.parse(readFileSync(path.join(root, "src-tauri", "tauri.conf.json"), "utf8"));
  const publicKey = path.join(scratch, "updater.pub");
  const signature = path.join(scratch, "baseline.minisig");
  writeFileSync(publicKey, Buffer.from(tauri.plugins.updater.pubkey, "base64"));
  writeFileSync(signature, Buffer.from(signatureBytes.toString("utf8").trim(), "base64"));
  execFileSync("minisign", ["-Vm", installer, "-x", signature, "-p", publicKey], { stdio: "inherit" });
}

export function validateDispatchPreflight({ receipt, config, targetVersion, root }) {
  const repositoryOwner = config.repository.split("/", 1)[0];
  invariant(
    receipt?.schema === "openaria.desktop.release-dispatch-preflight.v1",
    "dispatch preflight schema is invalid",
  );
  invariant(receipt.repository === config.repository, "dispatch preflight repository is inconsistent");
  invariant(receipt.actor === repositoryOwner, "dispatch preflight actor is not the repository owner");
  invariant(receipt.event === "workflow_dispatch", "Release dispatch preflight did not come from workflow_dispatch");
  invariant(receipt.target_version === targetVersion, "dispatch preflight target version is inconsistent");
  invariant(GIT_COMMIT.test(receipt.source_commit), "dispatch preflight source commit is invalid");
  invariant(
    receipt.source_commit === gitOutput(root, ["rev-parse", "HEAD"]),
    "dispatch preflight source is not checkout HEAD",
  );
  invariant(
    typeof receipt.default_branch === "string" &&
      receipt.default_branch.length > 0 &&
      !/\s/.test(receipt.default_branch) &&
      receipt.default_branch_head === receipt.source_commit,
    "dispatch preflight is not bound to the default branch HEAD",
  );
  invariant(/^\d+$/.test(receipt.run_id) && /^\d+$/.test(receipt.run_attempt), "dispatch run identity is invalid");
  invariant(receipt.run_attempt === "1", "Release dispatch must use the first workflow run attempt");
  invariant(receipt.immutable_setting?.enabled === true, "immutable Release setting preflight was not enabled");
  invariant(
    SHA256.test(receipt.immutable_setting.raw_response_sha256),
    "immutable preflight response digest is invalid",
  );
  invariant(
    !Number.isNaN(Date.parse(receipt.immutable_setting.checked_at)),
    "immutable preflight checked_at is invalid",
  );
  invariant(!Number.isNaN(Date.parse(receipt.run_created_at)), "Release dispatch created_at is invalid");
  invariant(
    receipt.immutable_setting.checked_before_dispatch === true,
    "immutable preflight was not bound before dispatch",
  );
  invariant(receipt.immutable_setting.dispatch_gap_seconds >= -60, "immutable preflight dispatch gap is invalid");
  invariant(
    receipt.immutable_setting.dispatch_gap_seconds <= 300,
    "immutable preflight is outside the five-minute dispatch window",
  );
  invariant(typeof receipt.allow_legacy_baseline_bootstrap === "boolean", "legacy bootstrap input is not boolean");
  if (receipt.allow_legacy_baseline_bootstrap) {
    invariant(
      targetVersion === config.legacy_bootstrap.target_version,
      "legacy bootstrap input is valid only for the one pinned bootstrap target",
    );
  } else {
    invariant(
      targetVersion !== config.legacy_bootstrap.target_version,
      "the one legacy bootstrap target requires explicit allow_legacy_baseline_bootstrap=true",
    );
  }
  invariant(
    compareVersions(targetVersion, config.formal_acceptance_target) <= 0 ||
      receipt.allow_legacy_baseline_bootstrap === false,
    "legacy bootstrap cannot remain enabled after the formal target",
  );
  return receipt;
}

async function capturePrePublishBaseline({ root, config, targetVersion, outputRoot, dispatchPreflightFile }) {
  mkdirSync(outputRoot, { recursive: true });
  const dispatchPreflight = validateDispatchPreflight({
    receipt: parseJson(readFileSync(dispatchPreflightFile), "dispatch preflight receipt"),
    config,
    targetVersion,
    root,
  });
  const allowLegacyBootstrap = dispatchPreflight.allow_legacy_baseline_bootstrap;
  const metadataPolicy = { config, targetVersion };
  const release = await authenticatedGithubJson(
    `https://api.github.com/repos/${config.repository}/releases/latest`,
    "latest Release metadata",
  );
  invariant(release.draft === false && release.prerelease === false, "latest Release is not public and stable");
  const history = await fetchPublicReleaseHistory(config, targetVersion, metadataPolicy);
  const latestHistoryMatches = history.manifests.filter((entry) => entry.release_id === release.id);
  invariant(latestHistoryMatches.length === 1, "latest Release is not unique in the public updater history");
  const latestAsset = releaseAssetMap(release, "latest Release").get("latest.json");
  invariant(latestAsset !== undefined, "latest Release lacks latest.json");
  const [manifestBytes, endpointManifestBytes] = await Promise.all([
    fetchBytes(latestAsset.browser_download_url, "baseline Release latest.json", metadataPolicy, "bootstrap-metadata"),
    fetchBytes(config.updater_endpoint, "production latest updater endpoint", metadataPolicy, "bootstrap-metadata"),
  ]);
  invariant(
    manifestBytes.equals(endpointManifestBytes),
    "production latest updater endpoint does not resolve to the unique latest Release bytes",
  );
  const manifest = parseJson(manifestBytes, "pre-publish anonymous latest.json");
  const baselineVersion = numericVersion(manifest.version, "pre-publish latest version");
  invariant(release.tag_name === baselineVersion, "latest Release tag differs from production updater manifest");
  invariant(compareVersions(targetVersion, baselineVersion) > 0, "pre-publish latest version is not older than target");
  const names = releaseNames(baselineVersion);
  const bootstrapUrl = `https://github.com/${config.repository}/releases/download/${baselineVersion}/${names.setup}`;
  const fetchPolicy = { config, targetVersion, bootstrapUrl };
  const tagApi = `https://api.github.com/repos/${config.repository}/git/ref/tags/${baselineVersion}`;
  const signatureUrl = `${bootstrapUrl}.sig`;
  const [tagRef, signatureBytes] = await Promise.all([
    authenticatedGithubJson(tagApi, "bootstrap tag metadata"),
    fetchBytes(signatureUrl, "anonymous bootstrap signature", fetchPolicy, "bootstrap-signature"),
  ]);
  const validated = validateBootstrapRelease({
    config,
    targetVersion,
    release,
    tagRef,
    manifestBytes,
    signatureBytes,
    allowLegacyBootstrap,
  });
  const installerBytes = await fetchBytes(
    bootstrapUrl,
    "anonymous bootstrap installer",
    fetchPolicy,
    "bootstrap-installer",
  );
  invariant(installerBytes.length === validated.installerAsset.size, "bootstrap installer size differs from GitHub");
  invariant(
    validated.installerAsset.digest === `sha256:${sha256(installerBytes)}`,
    "bootstrap installer digest differs from GitHub",
  );

  const installer = path.join(outputRoot, names.setup);
  writeFileSync(installer, installerBytes);
  writeFileSync(path.join(outputRoot, names.setupSignature), signatureBytes);
  writeFileSync(path.join(outputRoot, "pre-publish-latest.json"), manifestBytes);
  writeFileSync(path.join(outputRoot, "baseline-release-metadata.json"), `${JSON.stringify(release, null, 2)}\n`);
  writeFileSync(path.join(outputRoot, "baseline-tag-metadata.json"), `${JSON.stringify(tagRef, null, 2)}\n`);
  verifyCapturedInstallerSignature(root, installer, signatureBytes);

  const formal = targetVersion === config.formal_acceptance_target;
  if (formal) {
    invariant(
      baselineVersion === config.hardened_baseline_version,
      `formal target ${targetVersion} requires pre-publish latest ${config.hardened_baseline_version}, observed ${baselineVersion}`,
    );
  }
  const sourceDiff = formal
    ? validateVersionOnlyUpgrade({
        root,
        config,
        baselineVersion,
        baselineCommit: validated.commit,
        targetVersion,
      })
    : {
        baseline_commit: validated.commit,
        target_commit: gitOutput(root, ["rev-parse", "HEAD"]),
        changed_files: null,
        version_only: false,
      };
  if (!formal) fetchAndValidateBaselineTag(root, baselineVersion, validated.commit);
  const baselineUpdaterRuntime = formal
    ? sourceDiff.hardened_source.updater_runtime
    : validateUpdaterRuntimeSource(sourceAt(root, validated.commit, "src-tauri/Cargo.lock"), config);
  const baseline = {
    schema: "openaria.windows-updater-baseline.v1",
    captured_at: new Date().toISOString(),
    captured_before_target_release: true,
    repository: config.repository,
    updater_endpoint: config.updater_endpoint,
    target_version: targetVersion,
    baseline_version: baselineVersion,
    baseline_commit: validated.commit,
    baseline_release_id: release.id,
    baseline_release_immutable: release.immutable === true,
    baseline_release_closure: validated.releaseClosure,
    baseline_release_closure_sha256: validated.releaseClosureSha256,
    legacy_bootstrap_exception: validated.isLegacyBootstrap,
    legacy_bootstrap_exception_auto_expires_after: config.legacy_bootstrap.target_version,
    public_updater_history: history,
    dispatch_preflight: dispatchPreflight,
    installer: {
      name: names.setup,
      url: bootstrapUrl,
      bytes: installerBytes.length,
      sha256: sha256(installerBytes),
      github_digest: validated.installerAsset.digest,
    },
    signature: {
      name: names.setupSignature,
      url: signatureUrl,
      bytes: signatureBytes.length,
      sha256: sha256(signatureBytes),
      github_digest: validated.signatureAsset.digest,
      matches_pre_publish_latest_json: true,
      minisign_verified: true,
    },
    updater_runtime: config.updater_runtime,
    baseline_updater_runtime: baselineUpdaterRuntime,
    source_diff: sourceDiff,
    formal_lifecycle_acceptance: formal,
    hardened_updater_source_verified: formal && sourceDiff.hardened_source?.verified === true,
    proves_hardened_updater_lifecycle: false,
    target_installer_downloaded_by_capture_harness: false,
  };
  writeFileSync(
    path.join(outputRoot, "release-dispatch-preflight.json"),
    `${JSON.stringify(dispatchPreflight, null, 2)}\n`,
  );
  writeFileSync(path.join(outputRoot, "baseline.json"), `${JSON.stringify(baseline, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(baseline, null, 2)}\n`);
  return baseline;
}

export function validateCapturedBaseline({ config, targetVersion, baselineRoot, root }) {
  const baseline = parseJson(readFileSync(path.join(baselineRoot, "baseline.json")), "captured baseline.json");
  invariant(baseline.schema === "openaria.windows-updater-baseline.v1", "captured baseline schema is invalid");
  invariant(baseline.repository === config.repository, "captured baseline repository is inconsistent");
  invariant(
    baseline.updater_endpoint === config.updater_endpoint,
    "captured baseline updater endpoint is inconsistent",
  );
  invariant(baseline.target_version === targetVersion, "captured baseline target version is inconsistent");
  const capturedPreflight = parseJson(
    readFileSync(path.join(baselineRoot, "release-dispatch-preflight.json")),
    "captured dispatch preflight receipt",
  );
  const dispatchPreflight = validateDispatchPreflight({ receipt: capturedPreflight, config, targetVersion, root });
  invariant(
    JSON.stringify(baseline.dispatch_preflight) === JSON.stringify(dispatchPreflight),
    "baseline embedded dispatch preflight differs from the captured receipt",
  );
  numericVersion(baseline.baseline_version, "captured baseline version");
  invariant(
    compareVersions(targetVersion, baseline.baseline_version) > 0,
    "captured baseline is not older than target",
  );
  invariant(GIT_COMMIT.test(baseline.baseline_commit), "captured baseline commit is invalid");
  invariant(Number.isSafeInteger(baseline.baseline_release_id), "captured baseline Release ID is invalid");
  invariant(SHA256.test(baseline.baseline_release_closure_sha256), "captured baseline closure digest is invalid");
  invariant(
    baseline.public_updater_history?.highest_public_version === baseline.baseline_version,
    "captured baseline is not the highest public updater manifest",
  );
  invariant(
    compareVersions(targetVersion, baseline.public_updater_history.highest_public_version) > 0,
    "captured target is not strictly newer than public updater history",
  );
  if (dispatchPreflight.allow_legacy_baseline_bootstrap) {
    invariant(baseline.legacy_bootstrap_exception === true, "legacy bootstrap baseline marker is missing");
    invariant(baseline.baseline_release_immutable === false, "legacy bootstrap baseline unexpectedly claims immutable");
    invariant(
      baseline.baseline_release_id === config.legacy_bootstrap.release_id &&
        baseline.baseline_release_closure_sha256 === config.legacy_bootstrap.canonical_closure_sha256,
      "legacy bootstrap baseline is not the one pinned Release closure",
    );
  } else {
    invariant(baseline.legacy_bootstrap_exception === false, "normal baseline claims the legacy exception");
    invariant(baseline.baseline_release_immutable === true, "normal captured baseline is not immutable");
  }
  invariant(!Number.isNaN(Date.parse(baseline.captured_at)), "captured baseline timestamp is invalid");
  invariant(baseline.captured_before_target_release === true, "baseline was not marked captured before publication");
  invariant(
    baseline.target_installer_downloaded_by_capture_harness === false,
    "capture harness downloaded target installer",
  );
  invariant(baseline.baseline_updater_runtime?.verified === true, "baseline updater runtime proof is missing");
  invariant(
    baseline.baseline_updater_runtime.crate === config.updater_runtime.crate &&
      baseline.baseline_updater_runtime.version === config.updater_runtime.version &&
      baseline.baseline_updater_runtime.cargo_checksum === config.updater_runtime.cargo_checksum &&
      SHA256.test(baseline.baseline_updater_runtime.cargo_lock_sha256),
    "baseline updater runtime proof is inconsistent",
  );

  const names = releaseNames(baseline.baseline_version);
  invariant(baseline.installer?.name === names.setup, "captured baseline installer name is invalid");
  invariant(baseline.signature?.name === names.setupSignature, "captured baseline signature name is invalid");
  const installer = path.join(baselineRoot, names.setup);
  const signatureBytes = readFileSync(path.join(baselineRoot, names.setupSignature));
  const installerBytes = readFileSync(installer);
  invariant(installerBytes.length === baseline.installer.bytes, "captured baseline installer size changed");
  invariant(sha256(installerBytes) === baseline.installer.sha256, "captured baseline installer digest changed");
  invariant(
    baseline.installer.github_digest === `sha256:${baseline.installer.sha256}`,
    "captured baseline installer GitHub digest is inconsistent",
  );
  invariant(signatureBytes.length === baseline.signature.bytes, "captured baseline signature size changed");
  invariant(sha256(signatureBytes) === baseline.signature.sha256, "captured baseline signature digest changed");
  invariant(
    baseline.signature.github_digest === `sha256:${baseline.signature.sha256}`,
    "captured baseline signature GitHub digest is inconsistent",
  );
  validateMinisignDocument(signatureBytes.toString("utf8"), "captured baseline signature");
  const manifestBytes = readFileSync(path.join(baselineRoot, "pre-publish-latest.json"));
  const manifest = parseJson(manifestBytes, "captured pre-publish latest.json");
  invariant(manifest.version === baseline.baseline_version, "captured latest.json version changed");
  invariant(
    manifest.platforms?.[WINDOWS_PLATFORM]?.url === baseline.installer.url,
    "captured latest.json installer URL changed",
  );
  invariant(
    manifest.platforms[WINDOWS_PLATFORM].signature === signatureBytes.toString("utf8").trim(),
    "captured latest.json signature changed",
  );
  const release = parseJson(
    readFileSync(path.join(baselineRoot, "baseline-release-metadata.json")),
    "captured baseline Release metadata",
  );
  const tagRef = parseJson(
    readFileSync(path.join(baselineRoot, "baseline-tag-metadata.json")),
    "captured baseline tag metadata",
  );
  const validatedRelease = validateBootstrapRelease({
    config,
    targetVersion,
    release,
    tagRef,
    manifestBytes,
    signatureBytes,
    allowLegacyBootstrap: dispatchPreflight.allow_legacy_baseline_bootstrap,
  });
  invariant(validatedRelease.commit === baseline.baseline_commit, "captured baseline commit metadata changed");
  invariant(
    validatedRelease.releaseClosureSha256 === baseline.baseline_release_closure_sha256,
    "captured baseline closure changed",
  );
  invariant(release.id === baseline.baseline_release_id, "captured baseline Release ID changed");
  invariant(
    validatedRelease.installerAsset.digest === baseline.installer.github_digest,
    "captured baseline installer metadata changed",
  );
  invariant(
    validatedRelease.signatureAsset.digest === baseline.signature.github_digest,
    "captured baseline signature metadata changed",
  );

  const targetInstallerName = releaseNames(targetVersion).setup;
  invariant(
    !readdirSync(baselineRoot).includes(targetInstallerName),
    "captured baseline artifact contains target installer",
  );
  if (targetVersion === config.formal_acceptance_target) {
    invariant(
      baseline.baseline_version === config.hardened_baseline_version,
      "formal acceptance did not start from the hardened updater baseline",
    );
    invariant(baseline.formal_lifecycle_acceptance === true, "formal lifecycle acceptance marker is missing");
    invariant(baseline.hardened_updater_source_verified === true, "hardened updater source marker is missing");
    invariant(
      baseline.proves_hardened_updater_lifecycle === false,
      "pre-publish baseline must not claim runtime lifecycle proof",
    );
    invariant(baseline.source_diff?.version_only === true, "formal second hop was not a version-only change");
    invariant(GIT_COMMIT.test(baseline.source_diff.target_commit), "formal target commit is invalid");
    invariant(
      [...baseline.source_diff.changed_files].sort().join("\n") === [...config.version_only_files].sort().join("\n"),
      "formal second-hop source closure is invalid",
    );
    invariant(baseline.source_diff.hardened_source?.verified === true, "hardened updater source proof is missing");
    invariant(
      JSON.stringify(baseline.source_diff.hardened_source.updater_runtime) ===
        JSON.stringify(baseline.baseline_updater_runtime),
      "hardened updater runtime proof is inconsistent",
    );
    invariant(
      Array.isArray(baseline.source_diff.hardened_source.files) &&
        baseline.source_diff.hardened_source.files.length === 3 &&
        baseline.source_diff.hardened_source.files.every(
          (file) => typeof file.file === "string" && SHA256.test(file.sha256),
        ),
      "hardened updater source hashes are invalid",
    );
    invariant(
      Array.isArray(baseline.source_diff.hardened_source.contracts) &&
        baseline.source_diff.hardened_source.contracts.length === 9 &&
        baseline.source_diff.hardened_source.contracts.every(
          (contract) => typeof contract.file === "string" && typeof contract.name === "string",
        ),
      "hardened updater lifecycle contracts are incomplete",
    );
  } else {
    invariant(baseline.formal_lifecycle_acceptance === false, "non-formal hop must not claim lifecycle closure");
    invariant(
      baseline.hardened_updater_source_verified === false,
      "non-formal hop must not claim hardened source proof",
    );
    invariant(baseline.proves_hardened_updater_lifecycle === false, "non-formal hop must not claim hardened proof");
  }
  return { baseline, installer };
}

class EvidenceRecorder {
  constructor(root, config, version, baseline, ownership) {
    this.root = root;
    mkdirSync(root, { recursive: true });
    this.file = path.join(root, "windows-updater-acceptance.json");
    this.value = {
      schema: "openaria.windows-updater-acceptance.v1",
      repository: config.repository,
      from_version: baseline.baseline_version,
      to_version: version,
      baseline_commit: baseline.baseline_commit,
      baseline_release_id: baseline.baseline_release_id,
      candidate_release_id: ownership.release_id,
      candidate_commit: ownership.target_commit,
      run_id: ownership.run_id,
      run_attempt: ownership.run_attempt,
      dispatch_preflight: baseline.dispatch_preflight,
      formal_lifecycle_acceptance: baseline.formal_lifecycle_acceptance,
      hardened_updater_source_verified: baseline.hardened_updater_source_verified,
      proves_hardened_updater_lifecycle: false,
      source_diff: baseline.source_diff,
      started_at: new Date().toISOString(),
      status: "running",
      target_installer_downloaded_by_harness: false,
      target_installer_served_only_to_production_updater: false,
      browser_or_manual_download_used: false,
      events: [],
    };
    this.flush();
  }

  event(kind, detail = {}) {
    const entry = { at: new Date().toISOString(), kind, ...detail };
    this.value.events.push(entry);
    this.flush();
    process.stdout.write(`[acceptance] ${kind} ${JSON.stringify(detail)}\n`);
  }

  set(key, value) {
    this.value[key] = value;
    this.flush();
  }

  pass() {
    this.value.status = "passed";
    this.value.proves_hardened_updater_lifecycle = this.value.formal_lifecycle_acceptance;
    this.value.finished_at = new Date().toISOString();
    this.flush();
  }

  fail(error) {
    this.value.status = "failed";
    this.value.finished_at = new Date().toISOString();
    this.value.failure = {
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? (error.stack ?? null) : null,
    };
    this.flush();
  }

  flush() {
    writeFileSync(this.file, `${JSON.stringify(this.value, null, 2)}\n`);
  }
}

export function validateNeverPublicCandidate({ config, version, candidateRoot, ownershipFile, root }) {
  const ownership = parseJson(readFileSync(ownershipFile), "candidate ownership receipt");
  invariant(ownership.schema === "openaria.desktop.release-ownership.v2", "candidate ownership schema is invalid");
  invariant(ownership.repository === config.repository, "candidate ownership repository is inconsistent");
  invariant(ownership.target_version === version, "candidate ownership target version is inconsistent");
  invariant(
    ownership.target_commit === gitOutput(root, ["rev-parse", "HEAD"]),
    "candidate commit is not checkout HEAD",
  );
  invariant(/^\d+$/.test(ownership.run_id) && /^\d+$/.test(ownership.run_attempt), "candidate run identity is invalid");
  invariant(ownership.run_attempt === "1", "candidate does not belong to the first workflow run attempt");
  invariant(
    Number.isSafeInteger(ownership.release_id) && ownership.release_id > 0,
    "candidate numeric Release ID is invalid",
  );
  invariant(ownership.draft_never_public === true, "candidate was not captured as never-public");
  invariant(ownership.draft_created_by_run === true, "candidate draft was not freshly created by this run");
  invariant(
    ownership.candidate_start?.exact_tag_absent === true && ownership.candidate_start?.exact_release_absent === true,
    "candidate ownership does not prove the tag and Release were initially absent",
  );
  invariant(
    ownership.target_tag_after_draft === null ||
      (ownership.target_tag_after_draft?.type === "commit" &&
        ownership.target_tag_after_draft?.commit === ownership.target_commit),
    "candidate ownership has an unexpected post-draft tag",
  );
  invariant(ownership.published_at === null, "candidate ownership has a publication timestamp");
  const expectedOwnershipMarker = `<!-- openaria.desktop.never-public-draft.v2 repository=${config.repository} version=${version} commit=${ownership.target_commit} run_id=${ownership.run_id} run_attempt=${ownership.run_attempt} -->`;
  invariant(
    ownership.draft_ownership_marker === expectedOwnershipMarker,
    "candidate draft ownership marker is inconsistent",
  );

  const release = parseJson(
    readFileSync(path.join(candidateRoot, "candidate-release-metadata.json")),
    "candidate draft Release metadata",
  );
  invariant(release.id === ownership.release_id, "candidate Release ID differs from ownership receipt");
  invariant(
    typeof release.body === "string" && release.body.includes(expectedOwnershipMarker),
    "candidate draft Release ownership marker changed",
  );
  const names = releaseNames(version);
  const files = {
    manifestBytes: readFileSync(path.join(candidateRoot, "latest.json")),
    signatureBytes: readFileSync(path.join(candidateRoot, names.setupSignature)),
    sumsBytes: readFileSync(path.join(candidateRoot, "SHA256SUMS")),
  };
  const validated = validateTargetRelease({
    config,
    version,
    release,
    ...files,
    expectedDraft: true,
  });
  invariant(validated.release_id === ownership.release_id, "validated candidate Release ID changed");
  for (const asset of ownership.assets ?? []) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: config.repository,
      version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  const expectedAssets = normalizedAssetPins(ownership.assets, "ownership asset pins");
  const validatedAssets = normalizedAssetPins(
    validated.release_assets.map(({ name, bytes: size, digest }) => ({ name, size, digest })),
    "validated candidate asset pins",
  );
  invariant(
    JSON.stringify(validatedAssets) === JSON.stringify(expectedAssets),
    "candidate asset pins differ from ownership",
  );

  const installer = path.join(candidateRoot, names.setup);
  const installerBytes = readFileSync(installer);
  invariant(installerBytes.length === validated.setup.bytes, "candidate installer size differs from draft metadata");
  invariant(
    sha256(installerBytes) === validated.setup.sha256,
    "candidate installer digest differs from draft metadata",
  );
  return { ownership, release, validated, installer, ...files };
}

async function authenticatedGithubJson(url, label, { allowNotFound = false } = {}) {
  const token = process.env.GITHUB_TOKEN;
  invariant(typeof token === "string" && token.length > 0, `${label} requires the workflow token`);
  const response = await globalThis.fetch(url, {
    redirect: "error",
    signal: globalThis.AbortSignal.timeout(30_000),
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "user-agent": "openaria-prepublish-windows-acceptance",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (allowNotFound && response.status === 404) return null;
  invariant(response.ok, `${label} returned HTTP ${response.status}`);
  return response.json();
}

async function recheckRemotePrepublishState({ config, baseline, candidate }) {
  const api = `https://api.github.com/repos/${config.repository}`;
  const [latest, baselineRelease, baselineTag, draft, targetTag] = await Promise.all([
    authenticatedGithubJson(`${api}/releases/latest`, "latest baseline recheck"),
    authenticatedGithubJson(`${api}/releases/${baseline.baseline_release_id}`, "numeric baseline recheck"),
    authenticatedGithubJson(`${api}/git/ref/tags/${baseline.baseline_version}`, "baseline tag recheck"),
    authenticatedGithubJson(`${api}/releases/${candidate.ownership.release_id}`, "numeric candidate draft recheck"),
    authenticatedGithubJson(`${api}/git/ref/tags/${candidate.ownership.target_version}`, "candidate tag recheck", {
      allowNotFound: true,
    }),
  ]);
  invariant(
    latest.id === baseline.baseline_release_id && latest.tag_name === baseline.baseline_version,
    "public latest changed before Windows updater acceptance",
  );
  invariant(
    JSON.stringify(canonicalReleaseClosure(baselineRelease)) === JSON.stringify(baseline.baseline_release_closure),
    "numeric baseline Release closure changed before Windows updater acceptance",
  );
  invariant(
    baselineTag.object?.type === "commit" && baselineTag.object.sha === baseline.baseline_commit,
    "baseline tag changed before Windows updater acceptance",
  );
  invariant(
    draft.id === candidate.ownership.release_id &&
      draft.tag_name === candidate.ownership.target_version &&
      draft.draft === true &&
      draft.prerelease === false &&
      draft.published_at === null &&
      typeof draft.body === "string" &&
      draft.body.includes(candidate.ownership.draft_ownership_marker),
    "candidate is no longer the owned never-public numeric draft",
  );
  for (const asset of draft.assets ?? []) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: config.repository,
      version: candidate.ownership.target_version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  for (const asset of candidate.release.assets ?? []) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: config.repository,
      version: candidate.ownership.target_version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  const releaseStateFields = ["draft", "id", "immutable", "prerelease", "published_at", "tag_name"];
  invariant(
    releaseStateFields.every((field) => draft[field] === candidate.release[field]) &&
      JSON.stringify(normalizedAssetPins(draft.assets, "remote candidate asset pins")) ===
        JSON.stringify(normalizedAssetPins(candidate.release.assets, "captured candidate asset pins")),
    "candidate draft identity or asset pins changed before Windows updater acceptance",
  );
  const observedTargetTag = targetTag === null ? null : { commit: targetTag.object?.sha, type: targetTag.object?.type };
  invariant(
    JSON.stringify(observedTargetTag) === JSON.stringify(candidate.ownership.target_tag_after_draft),
    "candidate tag state changed after numeric draft creation",
  );
  return {
    checked_at: new Date().toISOString(),
    latest_release_id: latest.id,
    baseline_release_id: baselineRelease.id,
    candidate_release_id: draft.id,
    candidate_draft: draft.draft,
    baseline_commit: baselineTag.object.sha,
    candidate_commit: candidate.ownership.target_commit,
    candidate_tag_absent: true,
  };
}

function runPowerShell(script, label) {
  const result = spawnSync(
    "pwsh.exe",
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8", windowsHide: true, timeout: 60_000 },
  );
  invariant(result.error === undefined, `${label} failed to start: ${result.error?.message}`);
  invariant(result.status === 0, `${label} failed (${result.status}): ${(result.stderr || result.stdout).trim()}`);
  return result.stdout.trim();
}

function powershellLiteral(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

function certificateProviderSetup() {
  return String.raw`
if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
  New-PSDrive -Name Cert -PSProvider Certificate -Root '\' -Scope Script | Out-Null
}
if (-not (Test-Path -LiteralPath "Cert:\CurrentUser")) {
  throw "The current-user Windows certificate store is unavailable."
}
`;
}

function configureControlledTls(evidence) {
  const tlsRoot = mkdtempSync(path.join(os.tmpdir(), "openaria-controlled-tls-"));
  const pfx = path.join(tlsRoot, "github.com.pfx");
  const ca = path.join(tlsRoot, "openaria-controlled-root.cer");
  const passphraseFile = path.join(tlsRoot, "pfx-passphrase.txt");
  const passphrase = randomBytes(24).toString("hex");
  writeFileSync(passphraseFile, passphrase);
  const resultFile = path.join(tlsRoot, "certificate-installation.json");
  const phaseFile = path.join(tlsRoot, "certificate-installation.phase");
  const source = String.raw`
$ErrorActionPreference = "Stop"
function Set-ControlledTlsPhase([string]$phase) {
  [IO.File]::WriteAllText(${powershellLiteral(phaseFile)}, $phase, [Text.UTF8Encoding]::new($false))
}
${certificateProviderSetup()}
Set-ControlledTlsPhase "certificate_provider_ready"
$caParams = @{
  Type = "Custom"
  Subject = "CN=OpenAria Desktop Release Acceptance Root"
  FriendlyName = "OpenAria Desktop Release Acceptance Root"
  CertStoreLocation = "Cert:\CurrentUser\My"
  KeyAlgorithm = "RSA"
  KeyLength = 3072
  HashAlgorithm = "SHA256"
  KeyExportPolicy = "Exportable"
  KeyUsage = @("CertSign", "CRLSign", "DigitalSignature")
  NotAfter = (Get-Date).AddHours(6)
  TextExtension = @("2.5.29.19={critical}{text}ca=1&pathlength=0")
}
$ca = New-SelfSignedCertificate @caParams
Set-ControlledTlsPhase "root_certificate_created"
$serverParams = @{
  Type = "Custom"
  Subject = "CN=github.com"
  DnsName = "github.com"
  FriendlyName = "OpenAria controlled github.com"
  Signer = $ca
  CertStoreLocation = "Cert:\CurrentUser\My"
  KeyAlgorithm = "RSA"
  KeyLength = 3072
  HashAlgorithm = "SHA256"
  KeyExportPolicy = "Exportable"
  KeyUsage = @("DigitalSignature", "KeyEncipherment")
  NotAfter = (Get-Date).AddHours(6)
  TextExtension = @("2.5.29.19={critical}{text}ca=0", "2.5.29.37={text}1.3.6.1.5.5.7.3.1")
}
$server = New-SelfSignedCertificate @serverParams
Set-ControlledTlsPhase "server_certificate_created"
$password = ConvertTo-SecureString -String ${powershellLiteral(passphrase)} -Force -AsPlainText
Export-Certificate -Cert $ca -FilePath ${powershellLiteral(ca)} -Type CERT | Out-Null
Set-ControlledTlsPhase "root_certificate_exported"
$certutilOutput = & certutil.exe -f -addstore Root ${powershellLiteral(ca)} 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "certutil failed to trust the controlled updater root: $($certutilOutput -join [Environment]::NewLine)"
}
Set-ControlledTlsPhase "root_certificate_trusted"
Export-PfxCertificate -Cert $server -FilePath ${powershellLiteral(pfx)} -Password $password -ChainOption EndEntityCertOnly | Out-Null
Set-ControlledTlsPhase "server_pfx_exported"
[pscustomobject]@{
  ca_thumbprint = $ca.Thumbprint
  trusted_thumbprint = $ca.Thumbprint
  server_thumbprint = $server.Thumbprint
  dns_name = "github.com"
  not_after = $server.NotAfter.ToUniversalTime().ToString("o")
} | ConvertTo-Json -Compress | Set-Content -LiteralPath ${powershellLiteral(resultFile)} -Encoding utf8NoBOM
Set-ControlledTlsPhase "metadata_written"
`;
  try {
    runPowerShell(source, "create and trust controlled updater TLS certificate");
  } catch (error) {
    const phase = existsSync(phaseFile) ? readFileSync(phaseFile, "utf8").trim() : "not_started";
    throw new Error(`${error.message}; controlled TLS phase: ${phase}`, { cause: error });
  }
  const certificate = JSON.parse(readFileSync(resultFile, "utf8"));
  evidence.event("controlled_tls_certificate_trusted", certificate);
  return { tlsRoot, pfx, ca, passphraseFile, certificate };
}

function configureGithubHosts(outputRoot, evidence) {
  const marker = `# openaria-desktop-release-${process.pid}`;
  const backupRoot = mkdtempSync(path.join(os.tmpdir(), "openaria-controlled-hosts-"));
  const backup = path.join(backupRoot, "hosts-before.txt");
  const metadata = path.join(outputRoot, "windows-hosts-override.json");
  const source = String.raw`
$ErrorActionPreference = "Stop"
$hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$before = [IO.File]::ReadAllText($hosts)
[IO.File]::WriteAllText(${powershellLiteral(backup)}, $before, [Text.UTF8Encoding]::new($false))
$entry = "127.0.0.1 github.com ${marker}"
$line = [Environment]::NewLine + $entry + [Environment]::NewLine
[IO.File]::AppendAllText($hosts, $line, [Text.ASCIIEncoding]::new())
ipconfig /flushdns | Out-Null
[pscustomobject]@{hosts_file=$hosts; entry=$entry; marker=${powershellLiteral(marker)}} |
  ConvertTo-Json -Compress | Set-Content -LiteralPath ${powershellLiteral(metadata)} -Encoding utf8NoBOM
`;
  runPowerShell(source, "route github.com to the controlled updater server");
  const value = JSON.parse(readFileSync(metadata, "utf8"));
  evidence.event("production_updater_host_routed_to_controlled_server", value);
  return { ...value, backup };
}

function restoreControlledEnvironment(tls, hosts, evidence) {
  if (hosts?.backup && existsSync(hosts.backup)) {
    const source = String.raw`
$ErrorActionPreference = "Stop"
$hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$before = [IO.File]::ReadAllText(${powershellLiteral(hosts.backup)})
[IO.File]::WriteAllText($hosts, $before, [Text.UTF8Encoding]::new($false))
ipconfig /flushdns | Out-Null
`;
    runPowerShell(source, "restore Windows hosts after updater acceptance");
    evidence?.event("production_updater_host_route_restored");
  }
  if (tls?.certificate) {
    const source = String.raw`
$ErrorActionPreference = "Stop"
${certificateProviderSetup()}
$certutilOutput = & certutil.exe -delstore Root ${powershellLiteral(tls.certificate.trusted_thumbprint)} 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "certutil failed to remove the controlled updater root: $($certutilOutput -join [Environment]::NewLine)"
}
foreach ($thumbprint in @(
  "${tls.certificate.server_thumbprint}",
  "${tls.certificate.ca_thumbprint}"
)) {
  $certutilOutput = & certutil.exe -user -delstore My $thumbprint 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "certutil failed to remove a controlled updater private certificate: $($certutilOutput -join [Environment]::NewLine)"
  }
}
`;
    runPowerShell(source, "remove controlled updater TLS certificates");
    evidence?.event("controlled_tls_certificate_removed");
  }
}

export function smokeControlledTls() {
  invariant(process.platform === "win32", "controlled TLS smoke requires Windows");
  const events = [];
  const evidence = {
    event(name, value) {
      events.push({ name, value: value ?? null });
    },
  };
  let tls;
  try {
    tls = configureControlledTls(evidence);
    invariant(existsSync(tls.pfx) && statSync(tls.pfx).size > 0, "controlled TLS smoke did not export a PFX");
    invariant(existsSync(tls.ca) && statSync(tls.ca).size > 0, "controlled TLS smoke did not export a CA certificate");
  } finally {
    restoreControlledEnvironment(tls, undefined, evidence);
  }
  const result = {
    schema: "openaria.desktop.controlled-tls-smoke.v1",
    certificate: tls.certificate,
    events,
  };
  rmSync(tls.tlsRoot, { recursive: true, force: true });
  return result;
}

async function startControlledUpdateServer({ root, config, version, candidate, outputRoot, evidence }) {
  const tls = configureControlledTls(evidence);
  const planFile = path.join(outputRoot, "controlled-update-server-plan.json");
  const logFile = path.join(outputRoot, "controlled-update-server-log.json");
  const readyFile = path.join(outputRoot, "controlled-update-server-ready.json");
  const plan = validateControlledServerPlan({
    schema: "openaria.desktop.controlled-update-server.v1",
    host: "github.com",
    repository: config.repository,
    version,
    manifest: {
      name: "latest.json",
      file: path.resolve(path.dirname(candidate.installer), "latest.json"),
      request_path: `/${config.repository}/releases/latest/download/latest.json`,
      bytes: candidate.manifestBytes.length,
      sha256: sha256(candidate.manifestBytes),
    },
    installer: {
      name: candidate.validated.setup.name,
      file: path.resolve(candidate.installer),
      request_path: `/${config.repository}/releases/download/${version}/${candidate.validated.setup.name}`,
      bytes: candidate.validated.setup.bytes,
      sha256: candidate.validated.setup.sha256,
    },
  });
  writeFileSync(planFile, `${JSON.stringify(plan, null, 2)}\n`);
  let server;
  let hosts;
  try {
    server = spawn(
      process.execPath,
      [
        path.join(root, "scripts", "windows-controlled-update-server.mjs"),
        "serve",
        "--plan",
        planFile,
        "--pfx",
        tls.pfx,
        "--passphrase-file",
        tls.passphraseFile,
        "--ready",
        readyFile,
        "--log",
        logFile,
      ],
      { stdio: ["ignore", "inherit", "inherit"], windowsHide: true },
    );
    invariant(server.pid !== undefined, "controlled updater server did not start");
    const deadline = Date.now() + 30_000;
    while (!existsSync(readyFile) && Date.now() < deadline) {
      invariant(server.exitCode === null, `controlled updater server exited with ${server.exitCode}`);
      await delay(100);
    }
    invariant(existsSync(readyFile), "controlled updater server did not become ready");
    hosts = configureGithubHosts(outputRoot, evidence);
    evidence.event("controlled_update_server_started", {
      pid: server.pid,
      release_id: candidate.ownership.release_id,
      target_commit: candidate.ownership.target_commit,
      manifest: plan.manifest,
      installer: plan.installer,
    });
    return { server, tls, hosts, plan, logFile };
  } catch (error) {
    if (server?.pid !== undefined) {
      spawnSync("taskkill.exe", ["/PID", String(server.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
        timeout: 15_000,
      });
    }
    restoreControlledEnvironment(tls, hosts, evidence);
    throw error;
  }
}

export function validateControlledRequestLog({ log, plan }) {
  invariant(
    log?.schema === "openaria.desktop.controlled-update-server-log.v1",
    "controlled server log schema is invalid",
  );
  invariant(log.host === "github.com" && log.version === plan.version, "controlled server log identity changed");
  invariant(
    Array.isArray(log.requests) && log.requests.length >= 3,
    "controlled server observed too few updater requests",
  );
  invariant(
    log.requests.every((request) => request.kind !== "rejected"),
    "production updater requested a non-closed path",
  );
  const manifests = log.requests.filter((request) => request.kind === "manifest" && request.status === 200);
  const installers = log.requests.filter(
    (request) => request.kind === "installer" && [200, 206].includes(request.status),
  );
  invariant(manifests.length >= 2, "old and relaunched applications did not both check the controlled manifest");
  invariant(installers.length >= 1, "old application did not request the controlled installer");
  invariant(
    manifests.every(
      (request) => request.source_bytes === plan.manifest.bytes && request.source_sha256 === plan.manifest.sha256,
    ),
    "controlled server served unexpected manifest bytes",
  );
  invariant(
    installers.every(
      (request) => request.source_bytes === plan.installer.bytes && request.source_sha256 === plan.installer.sha256,
    ),
    "controlled server served unexpected installer bytes",
  );
  const fullInstaller = installers.some(
    (request) => request.status === 200 && request.response_bytes === plan.installer.bytes,
  );
  invariant(fullInstaller, "controlled server did not observe a complete production updater installer response");
  return {
    total_requests: log.requests.length,
    manifest_requests: manifests.length,
    installer_requests: installers.length,
    complete_installer_response: fullInstaller,
  };
}

function inspectInstalledApplication() {
  const source = String.raw`
$ErrorActionPreference = "Stop"
$roots = @(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$entries = @($roots | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue })
$entry = $entries | Where-Object { $_.DisplayName -eq "Open Aria Bridge" } | Select-Object -First 1
if ($null -eq $entry) { exit 3 }
$candidates = [System.Collections.Generic.List[string]]::new()
if (-not [string]::IsNullOrWhiteSpace($entry.DisplayIcon)) {
  $candidates.Add(($entry.DisplayIcon -split ",")[0].Trim().Trim('"'))
}
if (-not [string]::IsNullOrWhiteSpace($entry.InstallLocation) -and (Test-Path -LiteralPath $entry.InstallLocation)) {
  Get-ChildItem -LiteralPath $entry.InstallLocation -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "(?i)uninstall" } |
    ForEach-Object { $candidates.Add($_.FullName) }
}
$candidate = $candidates |
  Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
  Sort-Object @{ Expression = { if ([IO.Path]::GetFileName($_) -eq "ylx-transfer.exe") { 0 } else { 1 } } }, @{ Expression = { $_ } } |
  Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($candidate)) { exit 4 }
$file = Get-Item -LiteralPath $candidate
[pscustomobject]@{
  uninstall_key = $entry.PSChildName
  display_name = $entry.DisplayName
  display_version = $entry.DisplayVersion
  publisher = $entry.Publisher
  install_location = $entry.InstallLocation
  executable = $file.FullName
  file_version = $file.VersionInfo.FileVersion
  product_version = $file.VersionInfo.ProductVersion
  product_name = $file.VersionInfo.ProductName
  original_filename = $file.VersionInfo.OriginalFilename
} | ConvertTo-Json -Compress
`;
  const output = runPowerShell(source, "inspect installed Open Aria Bridge");
  return JSON.parse(output);
}

function processInfoForExecutable(executable) {
  const literal = powershellLiteral(executable);
  const source = String.raw`
$items = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ExecutablePath -eq ${literal} } | ForEach-Object {
  [pscustomobject]@{
    pid = [int]$_.ProcessId
    parent_pid = [int]$_.ParentProcessId
    name = $_.Name
    executable = $_.ExecutablePath
    command_line = $_.CommandLine
  }
})
@($items) | ConvertTo-Json -Compress
`;
  const output = runPowerShell(source, "inspect Open Aria Bridge processes");
  const parsed = JSON.parse(output || "[]");
  return Array.isArray(parsed) ? parsed : [parsed];
}

function installBootstrap(installer, evidence) {
  evidence.event("bootstrap_install_started", { installer, arguments: ["/S"] });
  const result = spawnSync(installer, ["/S"], {
    stdio: "inherit",
    windowsHide: true,
    timeout: 3 * 60_000,
  });
  invariant(result.error === undefined, `bootstrap installer failed to start: ${result.error?.message}`);
  invariant(result.status === 0, `bootstrap installer exited with ${result.status}`);
  const installed = inspectInstalledApplication();
  evidence.event("bootstrap_install_completed", installed);
  return installed;
}

async function freeTcpPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  invariant(address !== null && typeof address === "object", "unable to reserve a WebView2 debug port");
  const port = address.port;
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return port;
}

class CdpClient {
  constructor(websocket) {
    this.websocket = websocket;
    this.nextId = 1;
    this.pending = new Map();
    websocket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id === undefined) return;
      const pending = this.pending.get(message.id);
      if (pending === undefined) return;
      this.pending.delete(message.id);
      if (message.error !== undefined) pending.reject(new Error(`CDP ${pending.method}: ${message.error.message}`));
      else pending.resolve(message.result ?? {});
    });
    const rejectPending = (reason) => {
      for (const pending of this.pending.values()) pending.reject(new Error(reason));
      this.pending.clear();
    };
    websocket.addEventListener("close", () => rejectPending("CDP connection closed"));
    websocket.addEventListener("error", () => rejectPending("CDP connection failed"));
  }

  static async connect(url, timeoutMs = 10_000) {
    const websocket = new globalThis.WebSocket(url);
    await Promise.race([
      new Promise((resolve, reject) => {
        websocket.addEventListener("open", resolve, { once: true });
        websocket.addEventListener("error", () => reject(new Error(`cannot connect to CDP target ${url}`)), {
          once: true,
        });
      }),
      delay(timeoutMs).then(() => {
        throw new Error(`timed out connecting to CDP target ${url}`);
      }),
    ]);
    return new CdpClient(websocket);
  }

  call(method, params = {}, timeoutMs = 15_000) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP ${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, {
        method,
        resolve: (value) => {
          clearTimeout(timeout);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timeout);
          reject(error);
        },
      });
      this.websocket.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const result = await this.call("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    invariant(result.exceptionDetails === undefined, `WebView evaluation failed: ${result.exceptionDetails?.text}`);
    return result.result?.value;
  }

  close() {
    this.websocket.close();
  }
}

async function webviewTargets(port) {
  const response = await globalThis.fetch(`http://127.0.0.1:${port}/json/list`, {
    signal: globalThis.AbortSignal.timeout(2_000),
  });
  if (!response.ok) throw new Error(`WebView2 CDP endpoint returned HTTP ${response.status}`);
  return response.json();
}

async function connectAppWebview(port, excludedTargetId = null, timeoutMs = APP_START_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const targets = await webviewTargets(port);
      for (const target of targets) {
        if (target.id === excludedTargetId || target.type !== "page" || !target.webSocketDebuggerUrl) continue;
        let client;
        try {
          client = await CdpClient.connect(target.webSocketDebuggerUrl, 3_000);
          const isApplication = await client.evaluate(
            `Boolean(document.querySelector("#openUpdateBtn") && document.querySelector("#updateCurrentVersion"))`,
          );
          if (isApplication) return { client, target };
        } catch (error) {
          lastError = error;
        }
        client?.close();
      }
    } catch (error) {
      lastError = error;
    }
    await delay(500);
  }
  throw new Error(
    `Open Aria Bridge WebView2 target was not observable: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

const UPDATE_UI_STATE = `(() => {
  const text = (id) => document.querySelector(id)?.textContent?.trim() ?? null;
  const button = (id) => document.querySelector(id);
  const progress = document.querySelector("#updateProgress");
  return {
    overlay_open: document.querySelector("#updateOverlay")?.dataset.open === "true",
    current_version: text("#updateCurrentVersion"),
    available_version: text("#updateAvailableVersion"),
    status: text("#updateStatusText"),
    progress: progress?.hasAttribute("hidden") ? null : progress?.textContent?.trim() ?? null,
    check_disabled: Boolean(button("#checkUpdateBtn")?.disabled),
    install_disabled: Boolean(button("#installUpdateBtn")?.disabled)
  };
})()`;

async function readUpdateUi(client) {
  return client.evaluate(UPDATE_UI_STATE);
}

async function waitForUi(client, predicate, label, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let lastState;
  let lastError;
  while (Date.now() < deadline) {
    try {
      lastState = await readUpdateUi(client);
      if (predicate(lastState)) return lastState;
    } catch (error) {
      lastError = error;
    }
    await delay(250);
  }
  throw new Error(
    `${label} timed out; last state=${JSON.stringify(lastState)} error=${lastError instanceof Error ? lastError.message : String(lastError ?? "none")}`,
  );
}

async function captureScreenshot(client, file, evidence, label) {
  try {
    await client.call("Page.enable");
    const result = await client.call("Page.captureScreenshot", { format: "png", fromSurface: true });
    writeFileSync(file, Buffer.from(result.data, "base64"));
    evidence.event("screenshot_captured", { label, file: path.basename(file), bytes: statSync(file).size });
  } catch (error) {
    evidence.event("screenshot_unavailable", {
      label,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

async function openUpdaterUi(client, expectedVersion) {
  const clicked = await client.evaluate(
    `(() => { const button = document.querySelector("#openUpdateBtn"); if (!button) return false; button.click(); return true; })()`,
  );
  invariant(clicked === true, "old application update settings button was not clickable");
  return waitForUi(
    client,
    (state) => state.overlay_open && state.current_version === expectedVersion,
    `application UI did not report version ${expectedVersion}`,
  );
}

async function checkForTargetThroughUi(client, version, evidence) {
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    const clicked = await client.evaluate(
      `(() => { const button = document.querySelector("#checkUpdateBtn"); if (!button || button.disabled) return false; button.click(); return true; })()`,
    );
    invariant(clicked === true, "old application check-update button was not clickable");
    await waitForUi(
      client,
      (state) => state.check_disabled || state.status === "正在检查更新",
      "old application did not begin its own update check",
      15_000,
    );
    const state = await waitForUi(
      client,
      (candidate) => !candidate.check_disabled,
      "old application update check did not finish",
      90_000,
    );
    evidence.event("old_application_update_check", { attempt, state });
    if (state.available_version === version && state.install_disabled === false) return state;
    await delay(attempt * 5_000);
  }
  throw new Error(`old application never offered target version ${version}`);
}

function updaterInstallerCandidates(version) {
  let directories;
  try {
    directories = readdirSync(os.tmpdir(), { withFileTypes: true });
  } catch {
    return [];
  }
  const candidates = [];
  for (const directory of directories) {
    if (!directory.isDirectory() || !directory.name.includes(`${version}-updater-`)) continue;
    const root = path.join(os.tmpdir(), directory.name);
    let files;
    try {
      files = readdirSync(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const file of files) {
      if (!file.isFile() || !file.name.endsWith(`${version}-installer.exe`)) continue;
      candidates.push(path.join(root, file.name));
    }
  }
  candidates.sort((left, right) => statSync(right).mtimeMs - statSync(left).mtimeMs);
  return candidates;
}

function findUpdaterInstaller(version, excludedPaths) {
  return updaterInstallerCandidates(version).find((candidate) => !excludedPaths.has(path.resolve(candidate))) ?? null;
}

function assertInstalledVersion(installed, version, label) {
  invariant(installed.display_name === "Open Aria Bridge", `${label} product display identity changed`);
  invariant(installed.product_name === "Open Aria Bridge", `${label} executable product identity changed`);
  invariant(
    typeof installed.uninstall_key === "string" && installed.uninstall_key.length > 0,
    `${label} package key is missing`,
  );
  invariant(
    installed.display_version === version,
    `${label} registry version ${installed.display_version} != ${version}`,
  );
  const observed = [installed.file_version, installed.product_version].filter((value) => typeof value === "string");
  invariant(
    observed.some((value) => value === version || value.startsWith(`${version}.`)),
    `${label} executable version is not ${version}`,
  );
}

async function waitForInstalledTarget(executable, oldPid, version, evidence) {
  const deadline = Date.now() + UPDATE_HANDOFF_TIMEOUT_MS;
  let lastInstalled;
  let lastProcesses = [];
  let lastError;
  while (Date.now() < deadline) {
    try {
      lastInstalled = inspectInstalledApplication();
      lastProcesses = processInfoForExecutable(executable);
      const targetProcess = lastProcesses.find((process) => process.pid !== oldPid);
      if (
        lastInstalled.display_version === version &&
        [lastInstalled.file_version, lastInstalled.product_version].some(
          (value) => typeof value === "string" && (value === version || value.startsWith(`${version}.`)),
        ) &&
        targetProcess !== undefined
      ) {
        evidence.event("target_application_autolaunched", {
          installed: lastInstalled,
          process: targetProcess,
          launched_directly_by_harness: false,
        });
        return { installed: lastInstalled, process: targetProcess };
      }
    } catch (error) {
      lastError = error;
    }
    await delay(1_000);
  }
  throw new Error(
    `updated application did not install and autolaunch; installed=${JSON.stringify(lastInstalled)} processes=${JSON.stringify(lastProcesses)} error=${lastError instanceof Error ? lastError.message : String(lastError ?? "none")}`,
  );
}

async function runAcceptance({ root, config, version, baselineRoot, candidateRoot, ownershipFile, outputRoot }) {
  invariant(process.platform === "win32", "real updater acceptance must run on a Windows runner");
  mkdirSync(outputRoot, { recursive: true });
  const { baseline, installer: bootstrapInstaller } = validateCapturedBaseline({
    config,
    targetVersion: version,
    baselineRoot,
    root,
  });
  const candidate = validateNeverPublicCandidate({
    config,
    version,
    candidateRoot,
    ownershipFile,
    root,
  });
  invariant(
    candidate.ownership.run_id === baseline.dispatch_preflight.run_id &&
      candidate.ownership.run_attempt === baseline.dispatch_preflight.run_attempt,
    "candidate ownership and dispatch preflight identify different workflow attempts",
  );
  if (baseline.formal_lifecycle_acceptance) {
    const observedClosure = validateVersionOnlyUpgrade({
      root,
      config,
      baselineVersion: baseline.baseline_version,
      baselineCommit: baseline.baseline_commit,
      targetVersion: version,
    });
    invariant(
      JSON.stringify(observedClosure) === JSON.stringify(baseline.source_diff),
      "formal second-hop source proof changed after the pre-publish capture",
    );
  }
  const evidence = new EvidenceRecorder(outputRoot, config, version, baseline, candidate.ownership);
  let oldProcess;
  let oldClient;
  let newProcess;
  let controlled;
  try {
    evidence.set("runner", {
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      os_release: os.release(),
      webview2_automation: "Chrome DevTools Protocol over WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    });
    evidence.event("pre_publish_baseline_artifact_verified", {
      captured_at: baseline.captured_at,
      captured_before_target_release: baseline.captured_before_target_release,
      version: baseline.baseline_version,
      commit: baseline.baseline_commit,
      installer: baseline.installer,
      signature: baseline.signature,
      baseline_updater_runtime: baseline.baseline_updater_runtime,
      formal_lifecycle_acceptance: baseline.formal_lifecycle_acceptance,
      hardened_updater_source_verified: baseline.hardened_updater_source_verified,
      target_installer_downloaded_by_capture_harness: baseline.target_installer_downloaded_by_capture_harness,
    });
    evidence.set("baseline", baseline);
    evidence.set("candidate", {
      release_id: candidate.ownership.release_id,
      target_commit: candidate.ownership.target_commit,
      assets: candidate.ownership.assets,
      draft_never_public: true,
      release_metadata: candidate.release,
    });
    evidence.set("remote_prepublish_recheck", await recheckRemotePrepublishState({ config, baseline, candidate }));
    const target = candidate.validated;
    const installedBootstrap = installBootstrap(bootstrapInstaller, evidence);
    assertInstalledVersion(installedBootstrap, baseline.baseline_version, "bootstrap application");

    controlled = await startControlledUpdateServer({
      root,
      config,
      version,
      candidate,
      outputRoot,
      evidence,
    });

    const debugPort = await freeTcpPort();
    const appEnvironment = {
      ...process.env,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${debugPort}`,
      NO_PROXY: "github.com,127.0.0.1,localhost",
      no_proxy: "github.com,127.0.0.1,localhost",
    };
    for (const name of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) {
      delete appEnvironment[name];
    }
    oldProcess = spawn(installedBootstrap.executable, [], {
      env: appEnvironment,
      stdio: "ignore",
      windowsHide: false,
    });
    invariant(oldProcess.pid !== undefined, "bootstrap application did not start");
    const oldPid = oldProcess.pid;
    let oldExit = null;
    oldProcess.once("exit", (code, signal) => {
      oldExit = { code, signal, at: new Date().toISOString() };
    });
    evidence.event("bootstrap_application_started", {
      pid: oldPid,
      executable: installedBootstrap.executable,
      debug_port: debugPort,
    });

    const oldWebview = await connectAppWebview(debugPort);
    oldClient = oldWebview.client;
    evidence.event("bootstrap_webview_attached", {
      target_id: oldWebview.target.id,
      title: oldWebview.target.title,
      url: oldWebview.target.url,
    });
    const initialState = await openUpdaterUi(oldClient, baseline.baseline_version);
    evidence.event("bootstrap_version_observed_in_application_ui", { state: initialState });
    await captureScreenshot(
      oldClient,
      path.join(outputRoot, "01-bootstrap-update-dialog.png"),
      evidence,
      "bootstrap update dialog",
    );

    const availableState = await checkForTargetThroughUi(oldClient, version, evidence);
    evidence.event("target_version_offered_by_old_application", { state: availableState });
    await captureScreenshot(
      oldClient,
      path.join(outputRoot, "02-target-update-available.png"),
      evidence,
      "target update available",
    );

    const preexistingUpdaterInstallers = new Set(
      updaterInstallerCandidates(version).map((candidate) => path.resolve(candidate)),
    );
    const downloadStartedAt = Date.now();
    const installClicked = await oldClient.evaluate(
      `(() => { const button = document.querySelector("#installUpdateBtn"); if (!button || button.disabled) return false; button.click(); return true; })()`,
    );
    invariant(installClicked === true, "old application download-and-install button was not clickable");
    evidence.event("old_application_download_and_install_clicked", {
      target_version: version,
      target_url_was_not_requested_by_harness: true,
      ignored_preexisting_updater_installers: preexistingUpdaterInstallers.size,
    });

    const progressSamples = [];
    let updaterInstaller = null;
    const handoffDeadline = Date.now() + UPDATE_HANDOFF_TIMEOUT_MS;
    while (Date.now() < handoffDeadline && oldExit === null) {
      try {
        const state = await readUpdateUi(oldClient);
        const previous = progressSamples.at(-1);
        if (state.progress !== null && state.progress !== previous?.progress) {
          const sample = { at: new Date().toISOString(), progress: state.progress, status: state.status };
          progressSamples.push(sample);
          evidence.event("old_application_download_progress", sample);
        }
      } catch {
        // The WebView closes immediately after the verified installer is handed off.
      }
      updaterInstaller ??= findUpdaterInstaller(version, preexistingUpdaterInstallers);
      await delay(100);
    }
    invariant(oldExit !== null, "old application did not exit after updater installer handoff");
    invariant(oldExit.code === 0, `old application exited unexpectedly: ${JSON.stringify(oldExit)}`);
    evidence.event("bootstrap_application_exited_for_update", oldExit);

    const installerDeadline = Date.now() + 60_000;
    while (Date.now() < installerDeadline) {
      updaterInstaller ??= findUpdaterInstaller(version, preexistingUpdaterInstallers);
      if (updaterInstaller !== null) {
        try {
          if (statSync(updaterInstaller).size === target.setup.bytes) break;
        } catch {
          updaterInstaller = null;
        }
      }
      await delay(250);
    }
    invariant(updaterInstaller !== null, "Tauri updater temporary target installer was not observed");
    const updaterInstallerBytes = readFileSync(updaterInstaller);
    const updaterInstallerDigest = sha256(updaterInstallerBytes);
    invariant(
      statSync(updaterInstaller).birthtimeMs >= downloadStartedAt - 5_000,
      "observed updater installer predates the in-app download",
    );
    invariant(
      updaterInstallerBytes.length === target.setup.bytes,
      `app-downloaded installer size ${updaterInstallerBytes.length} != Release ${target.setup.bytes}`,
    );
    invariant(
      updaterInstallerDigest === target.setup.sha256,
      `app-downloaded installer digest ${updaterInstallerDigest} != Release ${target.setup.sha256}`,
    );
    evidence.event("app_downloaded_installer_bytes_verified", {
      path: updaterInstaller,
      created_at: statSync(updaterInstaller).birthtime.toISOString(),
      bytes: updaterInstallerBytes.length,
      sha256: updaterInstallerDigest,
      release_asset: target.setup.name,
      release_github_digest: target.setup.github_digest,
      progress_samples: progressSamples.length,
      signature_verified_before_handoff_by: `${config.updater_runtime.crate} ${config.updater_runtime.version}`,
      signature_verification_runtime_proof: baseline.baseline_updater_runtime,
    });

    const installedTarget = await waitForInstalledTarget(installedBootstrap.executable, oldPid, version, evidence);
    assertInstalledVersion(installedTarget.installed, version, "updated application");
    invariant(
      installedTarget.installed.uninstall_key === installedBootstrap.uninstall_key,
      "updated application changed the installed package identity",
    );
    invariant(
      path.basename(installedTarget.installed.executable).toLowerCase() ===
        path.basename(installedBootstrap.executable).toLowerCase(),
      "updated application changed the product executable identity",
    );
    evidence.event("updated_package_identity_verified", {
      uninstall_key: installedTarget.installed.uninstall_key,
      display_name: installedTarget.installed.display_name,
      product_name: installedTarget.installed.product_name,
      executable_name: path.basename(installedTarget.installed.executable),
    });
    newProcess = installedTarget.process;

    oldClient.close();
    oldClient = null;
    const newWebview = await connectAppWebview(debugPort, oldWebview.target.id, APP_START_TIMEOUT_MS);
    const newClient = newWebview.client;
    try {
      evidence.event("target_webview_attached", {
        target_id: newWebview.target.id,
        title: newWebview.target.title,
        url: newWebview.target.url,
      });
      const targetState = await openUpdaterUi(newClient, version);
      evidence.event("target_version_observed_in_relaunched_application_ui", { state: targetState });
      await captureScreenshot(
        newClient,
        path.join(outputRoot, "03-updated-application.png"),
        evidence,
        "updated application",
      );

      const finalCheckClicked = await newClient.evaluate(
        `(() => { const button = document.querySelector("#checkUpdateBtn"); if (!button || button.disabled) return false; button.click(); return true; })()`,
      );
      invariant(finalCheckClicked === true, "updated application check-update button was not clickable");
      await waitForUi(
        newClient,
        (state) => state.check_disabled || state.status === "正在检查更新",
        "updated application did not begin its own update check",
        15_000,
      );
      const finalState = await waitForUi(
        newClient,
        (state) => !state.check_disabled && state.status === "已是最新版本",
        "updated application did not confirm the published target is current",
        90_000,
      );
      invariant(finalState.current_version === version, "updated application final UI version changed unexpectedly");
      invariant(finalState.available_version === "无", "updated application unexpectedly offered another version");
      evidence.event("updated_application_confirmed_candidate_current_through_in_app_check", { state: finalState });
      await captureScreenshot(
        newClient,
        path.join(outputRoot, "04-updated-application-current.png"),
        evidence,
        "updated application current",
      );
    } finally {
      newClient.close();
    }

    const requestLogBytes = readFileSync(controlled.logFile);
    const requestLog = parseJson(requestLogBytes, "controlled updater request log");
    const requestProof = validateControlledRequestLog({ log: requestLog, plan: controlled.plan });
    evidence.set("controlled_server_request_proof", {
      ...requestProof,
      request_log: {
        file: path.basename(controlled.logFile),
        bytes: requestLogBytes.length,
        sha256: sha256(requestLogBytes),
      },
    });
    evidence.set("target_installer_served_only_to_production_updater", true);
    spawnSync("taskkill.exe", ["/PID", String(controlled.server.pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
      timeout: 15_000,
    });
    restoreControlledEnvironment(controlled.tls, controlled.hosts, evidence);
    controlled.cleaned = true;
    evidence.pass();
    return evidence.value;
  } catch (error) {
    evidence.fail(error);
    throw error;
  } finally {
    oldClient?.close();
    const pids = [oldProcess?.pid, newProcess?.pid].filter((pid) => Number.isInteger(pid));
    for (const pid of pids) {
      spawnSync("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
        timeout: 15_000,
      });
    }
    if (controlled?.server?.pid && controlled.cleaned !== true) {
      spawnSync("taskkill.exe", ["/PID", String(controlled.server.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
        timeout: 15_000,
      });
    }
    if (controlled?.cleaned !== true) restoreControlledEnvironment(controlled?.tls, controlled?.hosts, evidence);
  }
}

async function main(argv) {
  const [command, ...rest] = argv;
  const values = options(rest);
  const root = path.resolve(values.get("root") ?? ".");
  const configFile = path.resolve(
    values.get("config") ?? path.join(root, "scripts", "windows-updater-acceptance.json"),
  );
  const config = validateAcceptanceConfig(JSON.parse(readFileSync(configFile, "utf8")));
  const version = numericVersion(required(values, "to"), "workflow target version");
  const outputRoot = path.resolve(required(values, "output"));
  mkdirSync(outputRoot, { recursive: true });
  try {
    if (command === "capture-baseline") {
      await capturePrePublishBaseline({
        root,
        config,
        targetVersion: version,
        outputRoot,
        dispatchPreflightFile: path.resolve(required(values, "dispatch-preflight")),
      });
      return;
    }
    if (command === "accept") {
      await runAcceptance({
        root,
        config,
        version,
        baselineRoot: path.resolve(required(values, "baseline")),
        candidateRoot: path.resolve(required(values, "candidate")),
        ownershipFile: path.resolve(required(values, "ownership")),
        outputRoot,
      });
      return;
    }
    if (command === "smoke-controlled-tls") {
      const result = smokeControlledTls();
      writeFileSync(path.join(outputRoot, "controlled-tls-smoke.json"), `${JSON.stringify(result, null, 2)}\n`);
      console.log(JSON.stringify(result));
      return;
    }
    throw new Error(`unknown Windows updater acceptance command ${JSON.stringify(command)}`);
  } catch (error) {
    writeFileSync(
      path.join(outputRoot, `${command || "unknown"}-failure.json`),
      `${JSON.stringify(
        {
          command: command ?? null,
          target_version: version,
          failed_at: new Date().toISOString(),
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? (error.stack ?? null) : null,
        },
        null,
        2,
      )}\n`,
    );
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  });
}
