import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { releaseAssetUrl, validateReleaseAssetUrl } from "./desktop-release-commit-point.mjs";

const NUMERIC_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const WINDOWS_PLATFORM = "windows-x86_64";
const PE_MACHINE_I386 = 0x14c;
const PE_MACHINE_AMD64 = 0x8664;
const PE32_MAGIC = 0x10b;
const PE32_PLUS_MAGIC = 0x20b;
const MSI_SUMMARY_FMTID = Buffer.from("e0859ff2f94f6810ab9108002b27b3d9", "hex");
const NSIS_APPLICATION = "ylx-transfer.exe";
const MSI_SUMMARY_STREAM = "[5]SummaryInformation";
const MAX_APPLICATION_BYTES = 512 * 1024 * 1024;
const MAX_SUMMARY_BYTES = 1024 * 1024;
const MAX_METADATA_BYTES = 4 * 1024 * 1024;
const DOWNLOAD_ATTEMPTS = 4;
const DOWNLOAD_REQUEST_TIMEOUT_MS = 120_000;
const DOWNLOAD_TOTAL_TIMEOUT_MS = 360_000;

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

export function inspectPortableExecutable(bytes, label) {
  invariant(Buffer.isBuffer(bytes), `${label} bytes must be a Buffer`);
  invariant(bytes.length >= 64 && bytes.subarray(0, 2).toString("ascii") === "MZ", `${label} is not a PE executable`);
  const peOffset = bytes.readUInt32LE(0x3c);
  invariant(peOffset >= 64 && peOffset + 24 <= bytes.length, `${label} has a truncated PE header`);
  invariant(
    bytes.subarray(peOffset, peOffset + 4).toString("binary") === "PE\0\0",
    `${label} has an invalid PE header`,
  );
  const machine = bytes.readUInt16LE(peOffset + 4);
  const sectionCount = bytes.readUInt16LE(peOffset + 6);
  const optionalHeaderBytes = bytes.readUInt16LE(peOffset + 20);
  const optionalHeaderOffset = peOffset + 24;
  invariant(sectionCount > 0 && sectionCount <= 96, `${label} has an invalid PE section count`);
  invariant(
    optionalHeaderBytes >= 2 && optionalHeaderOffset + optionalHeaderBytes <= bytes.length,
    `${label} has a truncated PE optional header`,
  );
  const optionalMagic = bytes.readUInt16LE(optionalHeaderOffset);
  invariant(
    (machine === PE_MACHINE_I386 && optionalMagic === PE32_MAGIC) ||
      (machine === PE_MACHINE_AMD64 && optionalMagic === PE32_PLUS_MAGIC),
    `${label} has an unsupported or inconsistent PE machine/format`,
  );
  return {
    machine,
    machine_hex: `0x${machine.toString(16).padStart(4, "0")}`,
    optional_magic: optionalMagic,
    pe_format: optionalMagic === PE32_PLUS_MAGIC ? "PE32+" : "PE32",
  };
}

function propertyDirectory(summary, label) {
  invariant(Buffer.isBuffer(summary), `${label} SummaryInformation must be a Buffer`);
  invariant(summary.length >= 56 && summary.length <= MAX_SUMMARY_BYTES, `${label} SummaryInformation size is invalid`);
  invariant(summary.readUInt16LE(0) === 0xfffe, `${label} SummaryInformation byte order is invalid`);
  invariant(summary.readUInt16LE(2) === 0, `${label} SummaryInformation version is invalid`);
  invariant(summary.readUInt32LE(24) === 1, `${label} SummaryInformation must contain one property set`);
  invariant(summary.subarray(28, 44).equals(MSI_SUMMARY_FMTID), `${label} SummaryInformation FMTID is invalid`);
  const sectionOffset = summary.readUInt32LE(44);
  invariant(
    sectionOffset >= 48 && sectionOffset % 4 === 0 && sectionOffset + 8 <= summary.length,
    `${label} section offset is invalid`,
  );
  const sectionSize = summary.readUInt32LE(sectionOffset);
  const propertyCount = summary.readUInt32LE(sectionOffset + 4);
  const sectionEnd = sectionOffset + sectionSize;
  invariant(
    sectionSize >= 8 && sectionEnd <= summary.length,
    `${label} SummaryInformation property section is truncated`,
  );
  invariant(propertyCount > 0 && propertyCount <= 256, `${label} SummaryInformation property count is invalid`);
  invariant(
    sectionOffset + 8 + propertyCount * 8 <= sectionEnd,
    `${label} SummaryInformation property directory is truncated`,
  );
  const properties = new Map();
  for (let index = 0; index < propertyCount; index += 1) {
    const entryOffset = sectionOffset + 8 + index * 8;
    const id = summary.readUInt32LE(entryOffset);
    const relativeOffset = summary.readUInt32LE(entryOffset + 4);
    invariant(!properties.has(id), `${label} SummaryInformation has duplicate property ${id}`);
    invariant(
      relativeOffset >= 8 + propertyCount * 8 &&
        relativeOffset % 4 === 0 &&
        sectionOffset + relativeOffset + 4 <= sectionEnd,
      `${label} SummaryInformation property offset ${relativeOffset} is invalid`,
    );
    properties.set(id, sectionOffset + relativeOffset);
  }
  return { properties, sectionEnd };
}

export function parseMsiSummaryInformation(summary, label = "MSI") {
  const { properties, sectionEnd } = propertyDirectory(summary, label);
  const templateOffset = properties.get(7);
  const pageCountOffset = properties.get(14);
  invariant(templateOffset !== undefined, `${label} SummaryInformation is missing PID_TEMPLATE`);
  invariant(pageCountOffset !== undefined, `${label} SummaryInformation is missing PID_PAGECOUNT`);
  invariant(summary.readUInt32LE(templateOffset) === 30, `${label} PID_TEMPLATE must be VT_LPSTR`);
  invariant(templateOffset + 8 <= sectionEnd, `${label} PID_TEMPLATE is truncated`);
  const templateLength = summary.readUInt32LE(templateOffset + 4);
  invariant(templateLength >= 2 && templateLength <= 512, `${label} PID_TEMPLATE length is invalid`);
  invariant(templateOffset + 8 + templateLength <= sectionEnd, `${label} PID_TEMPLATE is truncated`);
  const templateBytes = summary.subarray(templateOffset + 8, templateOffset + 8 + templateLength);
  invariant(templateBytes.at(-1) === 0, `${label} PID_TEMPLATE is not NUL-terminated`);
  invariant(
    !templateBytes.subarray(0, -1).includes(0) && templateBytes.subarray(0, -1).every((byte) => byte < 0x80),
    `${label} PID_TEMPLATE is not canonical ASCII`,
  );
  const template = templateBytes.subarray(0, -1).toString("ascii");
  const match = template.match(/^([^;,]+);((?:0|[1-9]\d*)(?:,(?:0|[1-9]\d*))*)$/);
  invariant(match !== null, `${label} PID_TEMPLATE syntax is invalid`);
  invariant(summary.readUInt32LE(pageCountOffset) === 3, `${label} PID_PAGECOUNT must be VT_I4`);
  invariant(pageCountOffset + 8 <= sectionEnd, `${label} PID_PAGECOUNT is truncated`);
  const pageCount = summary.readInt32LE(pageCountOffset + 4);
  invariant(pageCount > 0, `${label} PID_PAGECOUNT is invalid`);
  return {
    languages: match[2].split(","),
    page_count: pageCount,
    platform: match[1],
    template,
  };
}

function sevenZipEntries(listing) {
  invariant(typeof listing === "string" && listing.length > 0, "7-Zip listing is empty");
  return listing
    .split(/\r?\n\s*\r?\n/)
    .map((block) =>
      Object.fromEntries(
        block
          .split(/\r?\n/)
          .map((line) => line.match(/^([^=]+?) = ?(.*)$/))
          .filter((match) => match !== null)
          .map((match) => [match[1].trim(), match[2]]),
      ),
    )
    .filter((entry) => typeof entry.Path === "string");
}

export function requireUniqueArchiveEntry(listing, expectedPath, label, maxBytes = Number.MAX_SAFE_INTEGER) {
  const expectedBasename = path.posix.basename(expectedPath);
  const matches = sevenZipEntries(listing).filter((entry) => {
    const normalized = entry.Path.replaceAll("\\", "/");
    return path.posix.basename(normalized) === expectedBasename;
  });
  invariant(matches.length === 1, `${label}: expected exactly one ${expectedBasename}; found ${matches.length}`);
  const normalized = matches[0].Path.replaceAll("\\", "/");
  invariant(
    normalized === expectedPath &&
      !normalized.startsWith("/") &&
      !/^[A-Za-z]:/.test(normalized) &&
      !normalized.split("/").some((part) => part === "" || part === "." || part === ".."),
    `${label} has an unsafe or ambiguous path: ${matches[0].Path}`,
  );
  invariant(/^\d+$/.test(matches[0].Size ?? ""), `${label} has an invalid declared size`);
  const size = Number(matches[0].Size);
  invariant(Number.isSafeInteger(size) && size > 0, `${label} has an invalid declared size`);
  invariant(size <= maxBytes, `${label} exceeds the byte limit: ${size} > ${maxBytes}`);
  return { path: normalized, size };
}

export function validateWindowsBundleArchitecture({
  setupBytes,
  applicationBytes,
  msiSummaryBytes,
  setupLabel = "setup stub",
  applicationLabel = "application payload",
  msiLabel = "MSI",
}) {
  const setup = inspectPortableExecutable(setupBytes, setupLabel);
  const application = inspectPortableExecutable(applicationBytes, applicationLabel);
  const msi = parseMsiSummaryInformation(msiSummaryBytes, msiLabel);
  invariant(application.machine === PE_MACHINE_AMD64, `${applicationLabel} is not Windows x86_64`);
  invariant(msi.platform === "x64", `${msiLabel} Template platform ${msi.platform} does not target x64`);
  invariant(
    msi.languages.length === 1 && msi.languages[0] === "0",
    `${msiLabel} Template languages ${msi.languages.join(",")} differ from the canonical language-neutral closure 0`,
  );
  invariant(msi.page_count >= 200, `${msiLabel} Page Count ${msi.page_count} is below the x64 minimum 200`);
  return { application, msi, setup_stub: setup };
}

function checkedSevenZip(sevenZip, root) {
  const tools = readJson(path.join(root, "scripts", "release-tools.json"));
  const expected = tools.seven_zip;
  invariant(expected !== undefined, "pinned 7-Zip metadata is missing");
  const stat = lstatSync(sevenZip);
  invariant(stat.isFile() && !stat.isSymbolicLink(), "pinned 7-Zip path is not a regular file");
  invariant(stat.size === expected.binary_bytes, `7-Zip binary bytes ${stat.size} != ${expected.binary_bytes}`);
  invariant(
    sha256File(sevenZip) === expected.binary_sha256,
    `7-Zip binary digest ${sha256File(sevenZip)} != ${expected.binary_sha256}`,
  );
  const identity = execFileSync(sevenZip, ["i"], { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  invariant(identity.includes(`7-Zip (z) ${expected.version} (x64)`), "pinned 7-Zip runtime identity is invalid");
  return {
    binary_bytes: stat.size,
    binary_sha256: expected.binary_sha256,
    version: expected.version,
  };
}

function listArchive(sevenZip, type, file) {
  return execFileSync(sevenZip, ["l", "-slt", "-ba", "-sccUTF-8", `-t${type}`, "--", file], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
}

function extractSingleArchiveEntry({ sevenZip, type, file, entry, declaredSize, maxBytes, label }) {
  const extractionRoot = mkdtempSync(path.join(tmpdir(), "openaria-release-architecture-"));
  let result;
  let primaryError;
  try {
    execFileSync(
      sevenZip,
      ["x", "-y", "-bd", "-bb0", "-sccUTF-8", `-t${type}`, `-o${extractionRoot}`, "--", file, entry],
      { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 },
    );
    invariant(
      readdirSync(extractionRoot).join("\n") === entry,
      `${label} extraction produced an unexpected file closure`,
    );
    const extracted = path.join(extractionRoot, entry);
    const stat = lstatSync(extracted);
    invariant(stat.isFile() && !stat.isSymbolicLink(), `${label} did not extract to a regular file`);
    invariant(stat.size === declaredSize, `${label} extracted bytes ${stat.size} != declared ${declaredSize}`);
    invariant(stat.size <= maxBytes, `${label} extracted bytes exceed the limit`);
    result = readFileSync(extracted);
  } catch (error) {
    primaryError = error;
  }
  let cleanupError;
  try {
    rmSync(extractionRoot, { recursive: true, force: false });
  } catch (error) {
    cleanupError = error;
  }
  if (primaryError && cleanupError) {
    throw new AggregateError([primaryError, cleanupError], `${label} verification and cleanup both failed`);
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return result;
}

export function inspectWindowsReleaseArchitecture({ root, assetsRoot, version, sevenZip }) {
  const tool = checkedSevenZip(sevenZip, root);
  const names = releaseNames(version);
  const setup = path.join(assetsRoot, names.setup);
  const msi = path.join(assetsRoot, names.msi);
  const applicationEntry = requireUniqueArchiveEntry(
    listArchive(sevenZip, "Nsis", setup),
    NSIS_APPLICATION,
    "NSIS application payload",
    MAX_APPLICATION_BYTES,
  );
  const summaryEntry = requireUniqueArchiveEntry(
    listArchive(sevenZip, "Compound", msi),
    MSI_SUMMARY_STREAM,
    "MSI SummaryInformation stream",
    MAX_SUMMARY_BYTES,
  );
  const applicationBytes = extractSingleArchiveEntry({
    sevenZip,
    type: "Nsis",
    file: setup,
    entry: applicationEntry.path,
    declaredSize: applicationEntry.size,
    maxBytes: MAX_APPLICATION_BYTES,
    label: "NSIS application payload",
  });
  const msiSummaryBytes = extractSingleArchiveEntry({
    sevenZip,
    type: "Compound",
    file: msi,
    entry: summaryEntry.path,
    declaredSize: summaryEntry.size,
    maxBytes: MAX_SUMMARY_BYTES,
    label: "MSI SummaryInformation stream",
  });
  return {
    ...validateWindowsBundleArchitecture({
      setupBytes: readFileSync(setup),
      applicationBytes,
      msiSummaryBytes,
      setupLabel: names.setup,
      applicationLabel: NSIS_APPLICATION,
      msiLabel: names.msi,
    }),
    application_sha256: createHash("sha256").update(applicationBytes).digest("hex"),
    extraction_tool: tool,
  };
}

async function fetchBytes(url, label, { expectedBytes, maxBytes, onEvent }) {
  invariant(
    expectedBytes === null || (Number.isSafeInteger(expectedBytes) && expectedBytes > 0),
    `${label} expected byte count is invalid`,
  );
  invariant(Number.isSafeInteger(maxBytes) && maxBytes > 0, `${label} maximum byte count is invalid`);
  invariant(expectedBytes === null || expectedBytes <= maxBytes, `${label} expected bytes exceed the download limit`);
  const scratch = mkdtempSync(path.join(tmpdir(), "openaria-anonymous-download-"));
  const output = path.join(scratch, "response.bin");
  const deadline = Date.now() + DOWNLOAD_TOTAL_TIMEOUT_MS;
  let lastError;
  let result;
  let primaryError;
  try {
    for (let attempt = 1; attempt <= DOWNLOAD_ATTEMPTS; attempt += 1) {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) break;
      const timeoutMs = Math.min(DOWNLOAD_REQUEST_TIMEOUT_MS, remainingMs);
      rmSync(output, { force: true });
      onEvent({ attempt, kind: "download_attempt_started", label, timeout_ms: timeoutMs, url });
      try {
        execFileSync(
          "curl",
          [
            "--fail",
            "--location",
            "--show-error",
            "--progress-bar",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "--max-time",
            String(Math.max(1, Math.floor(timeoutMs / 1000))),
            "--speed-limit",
            "1024",
            "--speed-time",
            "30",
            "--max-filesize",
            String(maxBytes),
            "--user-agent",
            "openaria-release-verifier",
            "--output",
            output,
            url,
          ],
          { stdio: ["ignore", "inherit", "inherit"], timeout: timeoutMs + 5_000 },
        );
        const stat = lstatSync(output);
        invariant(stat.isFile() && !stat.isSymbolicLink(), `${label} did not download to a regular file`);
        invariant(stat.size > 0 && stat.size <= maxBytes, `${label} downloaded byte count is invalid`);
        if (expectedBytes !== null)
          invariant(stat.size === expectedBytes, `${label} bytes ${stat.size} != ${expectedBytes}`);
        result = readFileSync(output);
        onEvent({ attempt, bytes: stat.size, kind: "download_attempt_completed", label });
        break;
      } catch (error) {
        lastError = error;
        let partialBytes = 0;
        try {
          partialBytes = lstatSync(output).size;
        } catch {
          // curl can fail before creating the output file.
        }
        const message = error instanceof Error ? error.message : String(error);
        onEvent({ attempt, bytes: partialBytes, error: message, kind: "download_attempt_failed", label });
        if (attempt === DOWNLOAD_ATTEMPTS) break;
      }
    }
    if (result === undefined) {
      throw lastError ?? new Error(`${label} exceeded its ${DOWNLOAD_TOTAL_TIMEOUT_MS}ms total download deadline`);
    }
  } catch (error) {
    primaryError = error;
  }
  let cleanupError;
  try {
    rmSync(scratch, { recursive: true, force: false });
  } catch (error) {
    cleanupError = error;
  }
  if (primaryError && cleanupError) {
    throw new AggregateError([primaryError, cleanupError], `${label} download and cleanup both failed`);
  }
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return result;
}

function expectedPublishedAssetMetadata(metadata, { repository, version, names }) {
  invariant(Array.isArray(metadata?.assets), "published Release assets must be an array");
  const expectedNames = ["latest.json", "SHA256SUMS", ...names].sort();
  const assets = new Map();
  for (const asset of metadata.assets) {
    invariant(typeof asset?.name === "string" && !assets.has(asset.name), "published Release asset names are invalid");
    assets.set(asset.name, asset);
  }
  invariant(
    [...assets.keys()].sort().join("\n") === expectedNames.join("\n"),
    "published GitHub Release asset closure is invalid",
  );
  for (const name of expectedNames) {
    const asset = assets.get(name);
    const maxBytes = name.endsWith(".exe") || name.endsWith(".msi") ? MAX_APPLICATION_BYTES : MAX_METADATA_BYTES;
    invariant(
      Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= maxBytes,
      `${name} GitHub size is invalid`,
    );
    invariant(/^sha256:[a-f0-9]{64}$/.test(asset.digest), `${name} GitHub digest is invalid`);
    validateReleaseAssetUrl(asset.browser_download_url, { repository, version, name, expectedDraft: false });
  }
  return assets;
}

export async function verifyPublishedRelease({ root, repository, version, outputRoot, sevenZip }) {
  const { updaterPubkey } = validateVersionSources(root, version);
  mkdirSync(outputRoot, { recursive: true });
  const cacheKey = encodeURIComponent(`${version}-${Date.now()}`);
  const downloadEvidence = {
    schema: "openaria.desktop.anonymous-downloads.v1",
    attempts: [],
  };
  const recordDownload = (event) => {
    downloadEvidence.attempts.push({ at: new Date().toISOString(), ...event });
    writeFileSync(path.join(outputRoot, "anonymous-downloads.json"), `${JSON.stringify(downloadEvidence, null, 2)}\n`);
  };
  const releaseMetadataBytes = await fetchBytes(
    `https://api.github.com/repos/${repository}/releases/tags/${version}?verify=${cacheKey}`,
    "anonymous GitHub Release metadata",
    { expectedBytes: null, maxBytes: MAX_METADATA_BYTES, onEvent: recordDownload },
  );
  let releaseMetadata;
  try {
    releaseMetadata = JSON.parse(releaseMetadataBytes.toString("utf8"));
  } catch (error) {
    throw new Error(`anonymous GitHub Release metadata is invalid JSON: ${error.message}`);
  }
  const names = releaseNames(version);
  const expectedNames = [names.setup, names.setupSignature, names.msi, names.msiSignature].sort();
  const publishedMetadata = expectedPublishedAssetMetadata(releaseMetadata, {
    repository,
    version,
    names: [names.setup, names.setupSignature, names.msi, names.msiSignature],
  });
  const latestBytes = await fetchBytes(
    `https://github.com/${repository}/releases/latest/download/latest.json?verify=${cacheKey}`,
    "anonymous latest.json",
    {
      expectedBytes: publishedMetadata.get("latest.json").size,
      maxBytes: MAX_METADATA_BYTES,
      onEvent: recordDownload,
    },
  );
  const manifest = JSON.parse(latestBytes.toString("utf8"));
  validateLatestManifest(manifest, { version, repository });
  writeFileSync(path.join(outputRoot, "latest.json"), latestBytes);
  const downloadedAssets = new Map([["latest.json", latestBytes]]);

  const releaseUrl = `https://github.com/${repository}/releases/download/${version}`;
  const sumsBytes = await fetchBytes(`${releaseUrl}/SHA256SUMS`, "anonymous SHA256SUMS", {
    expectedBytes: publishedMetadata.get("SHA256SUMS").size,
    maxBytes: MAX_METADATA_BYTES,
    onEvent: recordDownload,
  });
  const sums = parseSha256Sums(sumsBytes.toString("utf8"));
  invariant(
    [...sums.keys()].sort().join("\n") === expectedNames.join("\n"),
    "published SHA256SUMS asset closure is invalid",
  );
  writeFileSync(path.join(outputRoot, "SHA256SUMS"), sumsBytes);
  downloadedAssets.set("SHA256SUMS", sumsBytes);

  for (const name of expectedNames) {
    const asset = publishedMetadata.get(name);
    const bytes = await fetchBytes(`${releaseUrl}/${name}`, `anonymous ${name}`, {
      expectedBytes: asset.size,
      maxBytes: name.endsWith(".exe") || name.endsWith(".msi") ? MAX_APPLICATION_BYTES : MAX_METADATA_BYTES,
      onEvent: recordDownload,
    });
    const digest = createHash("sha256").update(bytes).digest("hex");
    invariant(digest === sums.get(name), `${name} digest ${digest} != published ${sums.get(name)}`);
    writeFileSync(path.join(outputRoot, name), bytes);
    downloadedAssets.set(name, bytes);
  }
  const architecture = inspectWindowsReleaseArchitecture({
    root,
    assetsRoot: outputRoot,
    version,
    sevenZip,
  });
  invariant(
    readFileSync(path.join(outputRoot, names.setupSignature), "utf8").trim() ===
      manifest.platforms[WINDOWS_PLATFORM].signature,
    "latest.json signature differs from the published setup signature asset",
  );
  verifyReleaseSignatures({ root: outputRoot, updaterPubkey, version });

  validatePublishedReleaseMetadata(releaseMetadata, {
    repository,
    version,
    assets: downloadedAssets,
  });
  const evidence = {
    schema: "openaria.desktop.published-release-verification.v1",
    repository,
    version,
    release_id: releaseMetadata.id,
    target_commit: releaseMetadata.target_commitish,
    immutable: releaseMetadata.immutable,
    assets: releaseMetadata.assets.map(({ name, size, digest, browser_download_url }) => ({
      browser_download_url,
      digest,
      name,
      size,
    })),
    architecture,
    verified_at: new Date().toISOString(),
  };
  writeFileSync(path.join(outputRoot, "postverify.json"), `${JSON.stringify(evidence, null, 2)}\n`);
  return evidence;
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
      sevenZip: path.resolve(required(values, "seven-zip")),
    });
    return;
  }
  if (command === "verify-architecture") {
    const version = required(values, "version");
    const outputRoot = path.resolve(required(values, "output"));
    mkdirSync(outputRoot, { recursive: true });
    const evidence = inspectWindowsReleaseArchitecture({
      root,
      assetsRoot: path.resolve(required(values, "assets")),
      version,
      sevenZip: path.resolve(required(values, "seven-zip")),
    });
    writeFileSync(path.join(outputRoot, "architecture.json"), `${JSON.stringify(evidence, null, 2)}\n`);
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
