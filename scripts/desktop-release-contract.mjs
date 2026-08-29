import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { releaseAssetUrl, validateReleaseAssetUrl } from "./desktop-release-commit-point.mjs";

const NUMERIC_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const WINDOWS_PLATFORM = "windows-x86_64";

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function numericVersion(value, label) {
  invariant(typeof value === "string" && NUMERIC_SEMVER.test(value), `${label} must use numeric SemVer X.Y.Z`);
  return value;
}

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function cargoPackageVersion(file) {
  const source = readFileSync(file, "utf8");
  const marker = source.indexOf("[package]");
  invariant(marker >= 0, `missing [package] section in ${file}`);
  const packageSource = source.slice(marker + "[package]".length);
  const nextSection = packageSource.search(/\n\[/);
  const packageSection = nextSection < 0 ? packageSource : packageSource.slice(0, nextSection);
  const version = packageSection.match(/^version\s*=\s*"([^"]+)"\s*$/m)?.[1];
  invariant(version !== undefined, `missing package version in ${file}`);
  return version;
}

function cargoLockPackageVersion(file, packageName) {
  const blocks = readFileSync(file, "utf8")
    .split(/(?=^\[\[package\]\]$)/m)
    .filter((block) => new RegExp(`^name = "${packageName}"$`, "m").test(block));
  invariant(blocks.length === 1, `expected exactly one ${packageName} package in ${file}`);
  const version = blocks[0].match(/^version = "([^"]+)"$/m)?.[1];
  invariant(version !== undefined, `missing ${packageName} version in ${file}`);
  return version;
}

export function validateVersionSources(root, requestedTag = null) {
  const tauri = readJson(path.join(root, "src-tauri", "tauri.conf.json"));
  const windowsTauri = readJson(path.join(root, "src-tauri", "tauri.windows.conf.json"));
  const packageJson = readJson(path.join(root, "package.json"));
  const packageLock = readJson(path.join(root, "package-lock.json"));
  const cargoVersion = cargoPackageVersion(path.join(root, "src-tauri", "Cargo.toml"));
  const cargoLockVersion = cargoLockPackageVersion(path.join(root, "src-tauri", "Cargo.lock"), "ylx-transfer");
  const mediaTools = readJson(path.join(root, "src-tauri", "resources", "windows-ffmpeg.json"));
  const composition = readFileSync(path.join(root, "src-tauri", "src", "composition.rs"), "utf8");
  const appVersion = numericVersion(tauri.version, "Tauri app version");

  invariant(
    packageJson.version === appVersion,
    `package.json version ${packageJson.version} != Tauri version ${appVersion}`,
  );
  invariant(
    packageLock.version === appVersion && packageLock.packages?.[""]?.version === appVersion,
    `package-lock.json application version != Tauri version ${appVersion}`,
  );
  invariant(cargoVersion === appVersion, `Cargo package version ${cargoVersion} != Tauri version ${appVersion}`);
  invariant(
    cargoLockVersion === appVersion,
    `Cargo.lock application version ${cargoLockVersion} != Tauri version ${appVersion}`,
  );
  if (requestedTag !== null && requestedTag !== "") {
    invariant(
      numericVersion(requestedTag, "Release tag") === appVersion,
      `Release tag ${requestedTag} != app version ${appVersion}`,
    );
  }
  invariant(tauri.bundle?.targets?.length === 2, "Tauri bundle targets must contain exactly NSIS and MSI");
  invariant(
    [...tauri.bundle.targets].sort().join(",") === "msi,nsis",
    "Tauri bundle targets must contain exactly NSIS and MSI",
  );
  invariant(
    tauri.bundle.externalBin === undefined,
    "base Tauri config must not impose Windows sidecars on Linux validation builds",
  );
  invariant(
    Array.isArray(windowsTauri.bundle?.externalBin) &&
      [...windowsTauri.bundle.externalBin].sort().join(",") === "binaries/ffmpeg,binaries/ffprobe",
    "Windows Tauri externalBin must contain exactly the bundled ffmpeg and ffprobe sidecars",
  );
  const expectedMediaExecutables = {
    ffmpeg: {
      archive_name: "ffmpeg.exe",
      tauri_source: "binaries/ffmpeg-x86_64-pc-windows-msvc.exe",
      installed_name: "ffmpeg.exe",
    },
    ffprobe: {
      archive_name: "ffprobe.exe",
      tauri_source: "binaries/ffprobe-x86_64-pc-windows-msvc.exe",
      installed_name: "ffprobe.exe",
    },
  };
  invariant(
    JSON.stringify(mediaTools.executables) === JSON.stringify(expectedMediaExecutables),
    "pinned Windows media tools must describe the exact ffmpeg and ffprobe Tauri sidecars",
  );
  const requiredRuntimeMediaContracts = [
    'resolve_bundled_media_tool_path("OPENARIA_FFMPEG", "ffmpeg")',
    'resolve_bundled_media_tool_path("OPENARIA_FFPROBE", "ffprobe")',
    "if ffmpeg.is_none() || ffprobe.is_none()",
    "config.with_ffmpeg_path(path)",
    "config.with_ffprobe_path(path)",
    "DerivedMediaCommitter::new(ffmpeg_export_config()?)",
  ];
  for (const contract of requiredRuntimeMediaContracts) {
    invariant(
      composition.includes(contract),
      `Windows media finalization must use both bundled sidecars without PATH fallback: missing ${contract}`,
    );
  }
  invariant(
    typeof tauri.plugins?.updater?.pubkey === "string" && tauri.plugins.updater.pubkey.length > 0,
    "updater pubkey is missing",
  );
  invariant(
    Array.isArray(tauri.plugins?.updater?.endpoints) &&
      tauri.plugins.updater.endpoints.length === 1 &&
      tauri.plugins.updater.endpoints[0] ===
        "https://github.com/Alpenl/openaria-bridge-desktop/releases/latest/download/latest.json",
    "updater endpoint must be the single in-app GitHub latest.json endpoint",
  );
  return { appVersion, updaterPubkey: tauri.plugins.updater.pubkey };
}

function walk(root) {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(root, entry.name);
    return entry.isDirectory() ? walk(file) : [file];
  });
}

function sha256File(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function decodedMinisign(value, label) {
  invariant(typeof value === "string" && value.trim().length > 0, `${label} is empty`);
  const compact = value.trim();
  invariant(/^[A-Za-z0-9+/]+={0,2}$/.test(compact), `${label} is not base64`);
  const decoded = Buffer.from(compact, "base64");
  invariant(decoded.length > 64, `${label} is too short`);
  invariant(decoded.toString("utf8").includes("untrusted comment:"), `${label} is not a minisign document`);
  return decoded;
}

function requireSingle(files, predicate, label) {
  const matches = files.filter(predicate);
  invariant(matches.length === 1, `expected exactly one ${label}; found ${matches.length}`);
  return matches[0];
}

function releaseNames(version) {
  return {
    setup: `OpenAriaBridge_${version}_windows_x86_64-setup.exe`,
    setupSignature: `OpenAriaBridge_${version}_windows_x86_64-setup.exe.sig`,
    msi: `OpenAriaBridge_${version}_windows_x86_64.msi`,
    msiSignature: `OpenAriaBridge_${version}_windows_x86_64.msi.sig`,
  };
}

export function validateLatestManifest(manifest, { version, repository }) {
  numericVersion(version, "Expected version");
  invariant(manifest !== null && typeof manifest === "object", "latest.json must be an object");
  invariant(manifest.version === version, `latest.json version ${manifest.version} != ${version}`);
  invariant(
    typeof manifest.pub_date === "string" && !Number.isNaN(Date.parse(manifest.pub_date)),
    "latest.json pub_date is invalid",
  );
  invariant(
    Object.keys(manifest.platforms ?? {}).length === 1 && manifest.platforms[WINDOWS_PLATFORM] !== undefined,
    "latest.json must contain only windows-x86_64",
  );
  const names = releaseNames(version);
  const expectedUrl = releaseAssetUrl(repository, version, names.setup);
  const platform = manifest.platforms[WINDOWS_PLATFORM];
  invariant(platform.url === expectedUrl, `latest.json URL ${platform.url} != ${expectedUrl}`);
  decodedMinisign(platform.signature, "latest.json signature");
  return platform;
}

export function stageReleaseAssets({ version, repository, inputRoot, outputRoot, pubDate = new Date().toISOString() }) {
  numericVersion(version, "Release version");
  const files = walk(inputRoot);
  const foreign = files.filter((file) => /\.(dmg|appimage|deb|rpm)$/i.test(file));
  invariant(foreign.length === 0, `non-Windows release assets are forbidden: ${foreign.map(path.basename).join(", ")}`);

  const setup = requireSingle(
    files,
    (file) => path.basename(file).endsWith("-setup.exe") && path.basename(file).includes(version),
    `Windows setup EXE for ${version}`,
  );
  const msi = requireSingle(
    files,
    (file) => path.basename(file).endsWith(".msi") && path.basename(file).includes(version),
    `Windows MSI for ${version}`,
  );
  const setupSignature = `${setup}.sig`;
  const msiSignature = `${msi}.sig`;
  invariant(files.includes(setupSignature), `missing updater signature ${path.basename(setupSignature)}`);
  invariant(files.includes(msiSignature), `missing updater signature ${path.basename(msiSignature)}`);
  decodedMinisign(readFileSync(setupSignature, "utf8"), "setup signature");
  decodedMinisign(readFileSync(msiSignature, "utf8"), "MSI signature");

  mkdirSync(outputRoot, { recursive: true });
  const names = releaseNames(version);
  const copies = [
    [setup, names.setup],
    [setupSignature, names.setupSignature],
    [msi, names.msi],
    [msiSignature, names.msiSignature],
  ];
  for (const [source, name] of copies) copyFileSync(source, path.join(outputRoot, name));

  const releaseUrl = `https://github.com/${repository}/releases/download/${version}`;
  const manifest = {
    version,
    notes: `Open Aria Bridge ${version}`,
    pub_date: pubDate,
    platforms: {
      [WINDOWS_PLATFORM]: {
        signature: readFileSync(setupSignature, "utf8").trim(),
        url: `${releaseUrl}/${names.setup}`,
      },
    },
  };
  validateLatestManifest(manifest, { version, repository });
  writeFileSync(path.join(outputRoot, "latest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

  const checksumNames = [names.setup, names.setupSignature, names.msi, names.msiSignature].sort();
  const checksums = checksumNames.map((name) => `${sha256File(path.join(outputRoot, name))}  ${name}`).join("\n");
  writeFileSync(path.join(outputRoot, "SHA256SUMS"), `${checksums}\n`);
  return manifest;
}

export function parseSha256Sums(source) {
  const result = new Map();
  for (const line of source.trim().split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64}) {2}([^/\\]+)$/);
    invariant(match !== null, `invalid SHA256SUMS line: ${line}`);
    invariant(!result.has(match[2]), `duplicate SHA256SUMS entry: ${match[2]}`);
    result.set(match[2], match[1]);
  }
  return result;
}

export function validatePublishedReleaseMetadata(metadata, { repository, version, assets }) {
  numericVersion(version, "Published Release tag");
  invariant(metadata !== null && typeof metadata === "object", "published Release metadata must be an object");
  invariant(metadata.tag_name === version, `published Release tag ${metadata.tag_name} != ${version}`);
  invariant(Number.isSafeInteger(metadata.id) && metadata.id > 0, "published Release numeric ID is invalid");
  invariant(metadata.draft === false, "published Release must not be a draft");
  invariant(metadata.prerelease === false, "published Release must not be a prerelease");
  invariant(metadata.immutable === true, "published Release must be immutable");
  invariant(typeof metadata.published_at === "string", "published Release timestamp is invalid");
  invariant(Array.isArray(metadata.assets), "published Release assets must be an array");
  invariant(assets instanceof Map && assets.size > 0, "expected published Release assets must be a non-empty Map");

  const publishedAssets = new Map();
  for (const asset of metadata.assets) {
    invariant(asset !== null && typeof asset === "object", "published Release asset metadata must be an object");
    invariant(typeof asset.name === "string" && asset.name.length > 0, "published Release asset name is invalid");
    invariant(!publishedAssets.has(asset.name), `duplicate published Release asset: ${asset.name}`);
    publishedAssets.set(asset.name, asset);
  }
  invariant(
    [...publishedAssets.keys()].sort().join("\n") === [...assets.keys()].sort().join("\n"),
    "published GitHub Release asset closure is invalid",
  );

  for (const [name, bytes] of assets) {
    const asset = publishedAssets.get(name);
    const digest = createHash("sha256").update(bytes).digest("hex");
    invariant(asset.size === bytes.length, `${name} GitHub size ${asset.size} != downloaded ${bytes.length}`);
    invariant(asset.digest === `sha256:${digest}`, `${name} GitHub digest ${asset.digest} != sha256:${digest}`);
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository,
      version,
      name,
      expectedDraft: false,
    });
  }
}

function decodeSigningFiles({ root, updaterPubkey, name, scratch }) {
  const publicKey = path.join(scratch, "updater.pub");
  const signature = path.join(scratch, `${name}.minisig`);
  writeFileSync(publicKey, Buffer.from(updaterPubkey, "base64"));
  writeFileSync(signature, decodedMinisign(readFileSync(path.join(root, `${name}.sig`), "utf8"), `${name} signature`));
  return { publicKey, signature };
}

export function verifyReleaseSignatures({ root, updaterPubkey, version }) {
  const names = releaseNames(version);
  const scratch = mkdtempSync(path.join(tmpdir(), "openaria-updater-signature-"));
  for (const name of [names.setup, names.msi]) {
    const { publicKey, signature } = decodeSigningFiles({ root, updaterPubkey, name, scratch });
    execFileSync("minisign", ["-Vm", path.join(root, name), "-x", signature, "-p", publicKey], { stdio: "inherit" });
  }
}

function assertWindowsX64Executable(bytes, label) {
  invariant(bytes.length > 64 && bytes.subarray(0, 2).toString("ascii") === "MZ", `${label} is not a PE executable`);
  const peOffset = bytes.readUInt32LE(0x3c);
  invariant(peOffset + 6 <= bytes.length, `${label} has a truncated PE header`);
  invariant(
    bytes.subarray(peOffset, peOffset + 4).toString("binary") === "PE\0\0",
    `${label} has an invalid PE header`,
  );
  invariant(bytes.readUInt16LE(peOffset + 4) === 0x8664, `${label} is not Windows x86_64`);
}

async function fetchBytes(url, label) {
  let lastError;
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    try {
      const response = await globalThis.fetch(url, {
        redirect: "follow",
        headers: { "user-agent": "openaria-release-verifier" },
      });
      if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
      const bytes = Buffer.from(await response.arrayBuffer());
      invariant(bytes.length > 0, `${label} is empty`);
      return bytes;
    } catch (error) {
      lastError = error;
      if (attempt < 6) await delay(attempt * 2_000);
    }
  }
  throw lastError;
}

export async function verifyPublishedRelease({ root, repository, version, outputRoot }) {
  const { updaterPubkey } = validateVersionSources(root, version);
  mkdirSync(outputRoot, { recursive: true });
  const cacheKey = encodeURIComponent(`${version}-${Date.now()}`);
  const latestBytes = await fetchBytes(
    `https://github.com/${repository}/releases/latest/download/latest.json?verify=${cacheKey}`,
    "anonymous latest.json",
  );
  const manifest = JSON.parse(latestBytes.toString("utf8"));
  validateLatestManifest(manifest, { version, repository });
  writeFileSync(path.join(outputRoot, "latest.json"), latestBytes);
  const downloadedAssets = new Map([["latest.json", latestBytes]]);

  const names = releaseNames(version);
  const releaseUrl = `https://github.com/${repository}/releases/download/${version}`;
  const sumsBytes = await fetchBytes(`${releaseUrl}/SHA256SUMS?verify=${cacheKey}`, "anonymous SHA256SUMS");
  const sums = parseSha256Sums(sumsBytes.toString("utf8"));
  const expectedNames = [names.setup, names.setupSignature, names.msi, names.msiSignature].sort();
  invariant(
    [...sums.keys()].sort().join("\n") === expectedNames.join("\n"),
    "published SHA256SUMS asset closure is invalid",
  );
  writeFileSync(path.join(outputRoot, "SHA256SUMS"), sumsBytes);
  downloadedAssets.set("SHA256SUMS", sumsBytes);

  for (const name of expectedNames) {
    const bytes = await fetchBytes(`${releaseUrl}/${name}?verify=${cacheKey}`, `anonymous ${name}`);
    const digest = createHash("sha256").update(bytes).digest("hex");
    invariant(digest === sums.get(name), `${name} digest ${digest} != published ${sums.get(name)}`);
    writeFileSync(path.join(outputRoot, name), bytes);
    downloadedAssets.set(name, bytes);
  }
  assertWindowsX64Executable(readFileSync(path.join(outputRoot, names.setup)), names.setup);
  invariant(
    readFileSync(path.join(outputRoot, names.setupSignature), "utf8").trim() ===
      manifest.platforms[WINDOWS_PLATFORM].signature,
    "latest.json signature differs from the published setup signature asset",
  );
  verifyReleaseSignatures({ root: outputRoot, updaterPubkey, version });

  const releaseMetadataBytes = await fetchBytes(
    `https://api.github.com/repos/${repository}/releases/tags/${version}?verify=${cacheKey}`,
    "anonymous GitHub Release metadata",
  );
  let releaseMetadata;
  try {
    releaseMetadata = JSON.parse(releaseMetadataBytes.toString("utf8"));
  } catch (error) {
    throw new Error(`anonymous GitHub Release metadata is invalid JSON: ${error.message}`);
  }
  validatePublishedReleaseMetadata(releaseMetadata, {
    repository,
    version,
    assets: downloadedAssets,
  });
}

function options(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    invariant(argv[index]?.startsWith("--"), `expected option, got ${argv[index]}`);
    invariant(argv[index + 1] !== undefined, `missing value for ${argv[index]}`);
    result.set(argv[index].slice(2), argv[index + 1]);
  }
  return result;
}

function required(values, name) {
  const value = values.get(name);
  invariant(value !== undefined && value !== "", `missing --${name}`);
  return value;
}

async function main(argv) {
  const [command, ...rest] = argv;
  const values = options(rest);
  const root = path.resolve(values.get("root") ?? ".");
  if (command === "validate-versions") {
    const result = validateVersionSources(root, values.get("tag") ?? null);
    process.stdout.write(`${result.appVersion}\n`);
    return;
  }
  if (command === "stage") {
    stageReleaseAssets({
      version: required(values, "version"),
      repository: required(values, "repository"),
      inputRoot: path.resolve(required(values, "input")),
      outputRoot: path.resolve(required(values, "output")),
    });
    return;
  }
  if (command === "verify-signatures") {
    const version = required(values, "version");
    const { updaterPubkey } = validateVersionSources(root, version);
    verifyReleaseSignatures({ root: path.resolve(required(values, "assets")), updaterPubkey, version });
    return;
  }
  if (command === "verify-published") {
    await verifyPublishedRelease({
      root,
      repository: required(values, "repository"),
      version: required(values, "version"),
      outputRoot: path.resolve(required(values, "output")),
    });
    return;
  }
  throw new Error(`unknown command ${JSON.stringify(command)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  });
}
