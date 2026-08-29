import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  assertAnonymousFetchAllowed,
  validateAcceptanceConfig,
  validateBootstrapRelease,
  validateCapturedBaseline,
  validateControlledRequestLog,
  validateDispatchPreflight,
  validateTargetRelease,
  validateVersionOnlyUpgrade,
} from "./windows-updater-acceptance.mjs";
import { resolveControlledRequest, validateControlledServerPlan } from "./windows-controlled-update-server.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const CONFIG = validateAcceptanceConfig(
  JSON.parse(readFileSync(path.join(ROOT, "scripts/windows-updater-acceptance.json"), "utf8")),
);
const BASELINE_VERSION = CONFIG.hardened_baseline_version;
const TARGET_VERSION = CONFIG.formal_acceptance_target;
const BASELINE_COMMIT = "a".repeat(40);
const TARGET_COMMIT = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: ROOT,
  encoding: "utf8",
}).trim();
const FAKE_SIGNATURE = Buffer.from(
  "untrusted comment: signature from acceptance test\nRWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
).toString("base64");

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function names(version) {
  return {
    setup: `OpenAriaBridge_${version}_windows_x86_64-setup.exe`,
    setupSignature: `OpenAriaBridge_${version}_windows_x86_64-setup.exe.sig`,
    msi: `OpenAriaBridge_${version}_windows_x86_64.msi`,
    msiSignature: `OpenAriaBridge_${version}_windows_x86_64.msi.sig`,
  };
}

function releaseClosure(release) {
  return {
    assets: release.assets
      .map(({ name, size, digest: assetDigest, browser_download_url }) => ({
        browser_download_url,
        digest: assetDigest,
        name,
        size,
      }))
      .sort((left, right) => left.name.localeCompare(right.name)),
    draft: release.draft,
    id: release.id,
    immutable: release.immutable,
    prerelease: release.prerelease,
    published_at: release.published_at,
    tag_name: release.tag_name,
  };
}

function dispatchPreflight(overrides = {}) {
  return {
    schema: "openaria.desktop.release-dispatch-preflight.v1",
    repository: CONFIG.repository,
    actor: "Alpenl",
    event: "workflow_dispatch",
    target_version: TARGET_VERSION,
    source_commit: TARGET_COMMIT,
    default_branch: "main",
    default_branch_head: TARGET_COMMIT,
    run_id: "123456",
    run_attempt: "1",
    run_created_at: "2026-08-29T00:00:10Z",
    allow_legacy_baseline_bootstrap: false,
    immutable_setting: {
      enabled: true,
      checked_at: "2026-08-29T00:00:00Z",
      raw_response_sha256: "c".repeat(64),
      checked_before_dispatch: true,
      dispatch_gap_seconds: 10,
    },
    ...overrides,
  };
}

function bootstrapFixture() {
  const releaseNames = names(BASELINE_VERSION);
  const installerBytes = Buffer.from("captured baseline installer bytes");
  const signatureBytes = Buffer.from(FAKE_SIGNATURE);
  const releaseUrl = `https://github.com/${CONFIG.repository}/releases/download/${BASELINE_VERSION}`;
  const manifestBytes = Buffer.from(
    `${JSON.stringify({
      version: BASELINE_VERSION,
      platforms: {
        "windows-x86_64": {
          signature: FAKE_SIGNATURE,
          url: `${releaseUrl}/${releaseNames.setup}`,
        },
      },
    })}\n`,
  );
  const content = new Map([
    [releaseNames.setup, installerBytes],
    [releaseNames.setupSignature, signatureBytes],
    [releaseNames.msi, Buffer.from("captured baseline msi bytes")],
    [releaseNames.msiSignature, Buffer.from(FAKE_SIGNATURE)],
  ]);
  const sumsBytes = Buffer.from(
    `${[...content]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, bytes]) => `${digest(bytes)}  ${name}`)
      .join("\n")}\n`,
  );
  content.set("SHA256SUMS", sumsBytes);
  content.set("latest.json", manifestBytes);
  const release = {
    id: 456789,
    tag_name: BASELINE_VERSION,
    draft: false,
    prerelease: false,
    immutable: true,
    published_at: "2026-08-29T00:00:00Z",
    assets: [...content].map(([name, bytes]) => ({
      name,
      state: "uploaded",
      size: bytes.length,
      digest: `sha256:${digest(bytes)}`,
      browser_download_url: `${releaseUrl}/${name}`,
    })),
  };
  const tagRef = {
    ref: `refs/tags/${BASELINE_VERSION}`,
    object: { type: "commit", sha: BASELINE_COMMIT },
  };
  return { releaseNames, installerBytes, signatureBytes, manifestBytes, release, tagRef, releaseUrl, sumsBytes };
}

function targetFixture() {
  const version = TARGET_VERSION;
  const releaseNames = names(version);
  const signatureBytes = Buffer.from(FAKE_SIGNATURE);
  const releaseUrl = `https://github.com/${CONFIG.repository}/releases/download/${version}`;
  const manifestBytes = Buffer.from(
    `${JSON.stringify({
      version,
      notes: `Open Aria Bridge ${version}`,
      pub_date: "2026-08-29T00:00:00.000Z",
      platforms: {
        "windows-x86_64": {
          signature: FAKE_SIGNATURE,
          url: `${releaseUrl}/${releaseNames.setup}`,
        },
      },
    })}\n`,
  );
  const content = new Map([
    [releaseNames.setup, Buffer.from("target setup bytes")],
    [releaseNames.setupSignature, signatureBytes],
    [releaseNames.msi, Buffer.from("target msi bytes")],
    [releaseNames.msiSignature, Buffer.from("target msi signature bytes")],
  ]);
  const sumsBytes = Buffer.from(
    `${[...content]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, bytes]) => `${digest(bytes)}  ${name}`)
      .join("\n")}\n`,
  );
  content.set("SHA256SUMS", sumsBytes);
  content.set("latest.json", manifestBytes);
  const release = {
    id: 567890,
    tag_name: version,
    draft: false,
    prerelease: false,
    immutable: true,
    published_at: "2026-08-29T01:00:00Z",
    assets: [...content].map(([name, bytes]) => ({
      name,
      state: "uploaded",
      size: bytes.length,
      digest: `sha256:${digest(bytes)}`,
      browser_download_url: `${releaseUrl}/${name}`,
    })),
  };
  return { version, manifestBytes, release, signatureBytes, sumsBytes };
}

function writeCapturedBaseline(overrides = {}) {
  const fixture = bootstrapFixture();
  const baselineRoot = mkdtempSync(path.join(tmpdir(), "openaria-captured-baseline-test-"));
  const preflight = dispatchPreflight();
  const closure = releaseClosure(fixture.release);
  const baselineUpdaterRuntime = {
    verified: true,
    ...CONFIG.updater_runtime,
    cargo_lock_sha256: digest(Buffer.from("baseline Cargo.lock")),
  };
  const hardenedSource = {
    verified: true,
    updater_runtime: baselineUpdaterRuntime,
    files: ["src/runtime/appUpdater.ts", "src/app/transferApp.ts", "src-tauri/Cargo.lock"].map((file) => ({
      file,
      sha256: digest(Buffer.from(file)),
    })),
    contracts: Array.from({ length: 9 }, (_, index) => ({
      file: index < 4 ? "src/runtime/appUpdater.ts" : "src/app/transferApp.ts",
      name: `contract ${index + 1}`,
    })),
  };
  const baseline = {
    schema: "openaria.windows-updater-baseline.v1",
    captured_at: "2026-08-29T00:00:00.000Z",
    captured_before_target_release: true,
    repository: CONFIG.repository,
    updater_endpoint: CONFIG.updater_endpoint,
    target_version: TARGET_VERSION,
    baseline_version: BASELINE_VERSION,
    baseline_commit: BASELINE_COMMIT,
    baseline_release_id: fixture.release.id,
    baseline_release_immutable: true,
    baseline_release_closure: closure,
    baseline_release_closure_sha256: digest(Buffer.from(JSON.stringify(closure))),
    legacy_bootstrap_exception: false,
    legacy_bootstrap_exception_auto_expires_after: CONFIG.legacy_bootstrap.target_version,
    public_updater_history: {
      highest_public_version: BASELINE_VERSION,
      manifests: [{ release_id: fixture.release.id, version: BASELINE_VERSION, immutable: true }],
    },
    dispatch_preflight: preflight,
    installer: {
      name: fixture.releaseNames.setup,
      url: `${fixture.releaseUrl}/${fixture.releaseNames.setup}`,
      bytes: fixture.installerBytes.length,
      sha256: digest(fixture.installerBytes),
      github_digest: `sha256:${digest(fixture.installerBytes)}`,
    },
    signature: {
      name: fixture.releaseNames.setupSignature,
      url: `${fixture.releaseUrl}/${fixture.releaseNames.setupSignature}`,
      bytes: fixture.signatureBytes.length,
      sha256: digest(fixture.signatureBytes),
      github_digest: `sha256:${digest(fixture.signatureBytes)}`,
      matches_pre_publish_latest_json: true,
      minisign_verified: true,
    },
    updater_runtime: CONFIG.updater_runtime,
    baseline_updater_runtime: baselineUpdaterRuntime,
    source_diff: {
      baseline_commit: BASELINE_COMMIT,
      target_commit: TARGET_COMMIT,
      changed_files: [...CONFIG.version_only_files].sort(),
      version_only: true,
      hardened_source: hardenedSource,
    },
    formal_lifecycle_acceptance: true,
    hardened_updater_source_verified: true,
    proves_hardened_updater_lifecycle: false,
    target_installer_downloaded_by_capture_harness: false,
    ...overrides,
  };
  writeFileSync(path.join(baselineRoot, fixture.releaseNames.setup), fixture.installerBytes);
  writeFileSync(path.join(baselineRoot, fixture.releaseNames.setupSignature), fixture.signatureBytes);
  writeFileSync(path.join(baselineRoot, "pre-publish-latest.json"), fixture.manifestBytes);
  writeFileSync(path.join(baselineRoot, "baseline-release-metadata.json"), JSON.stringify(fixture.release));
  writeFileSync(path.join(baselineRoot, "baseline-tag-metadata.json"), JSON.stringify(fixture.tagRef));
  writeFileSync(path.join(baselineRoot, "release-dispatch-preflight.json"), JSON.stringify(preflight));
  writeFileSync(path.join(baselineRoot, "baseline.json"), JSON.stringify(baseline));
  return { baselineRoot, fixture };
}

function git(root, args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function writeVersionSources(root, version) {
  mkdirSync(path.join(root, "src-tauri"), { recursive: true });
  mkdirSync(path.join(root, "src", "runtime"), { recursive: true });
  mkdirSync(path.join(root, "src", "app"), { recursive: true });
  writeFileSync(path.join(root, "package.json"), `${JSON.stringify({ name: "ylx-transfer", version }, null, 2)}\n`);
  writeFileSync(
    path.join(root, "package-lock.json"),
    `${JSON.stringify({ name: "ylx-transfer", version, lockfileVersion: 3, packages: { "": { version } } }, null, 2)}\n`,
  );
  writeFileSync(
    path.join(root, "src-tauri", "Cargo.toml"),
    `[package]\nname = "ylx-transfer"\nversion = "${version}"\n`,
  );
  writeFileSync(
    path.join(root, "src-tauri", "Cargo.lock"),
    `[[package]]\nname = "tauri-plugin-updater"\nversion = "${CONFIG.updater_runtime.version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${CONFIG.updater_runtime.cargo_checksum}"\n\n[[package]]\nname = "ylx-transfer"\nversion = "${version}"\n`,
  );
  writeFileSync(path.join(root, "src-tauri", "tauri.conf.json"), `${JSON.stringify({ version }, null, 2)}\n`);
  writeFileSync(
    path.join(root, "src", "runtime", "appUpdater.ts"),
    `validateAvailableAppVersion(update.currentVersion, update.version);\nlet closed = false;\nlet downloading = false;\nasync function download() {\n  if (downloading) throw new Error("already downloading");\n  downloading = true;\n  await update.downloadAndInstall(() => { if (closed) return; });\n}\nasync function close() {\n  if (closed) return;\n  closed = true;\n  await update.close();\n}\n`,
  );
  writeFileSync(
    path.join(root, "src", "app", "transferApp.ts"),
    `let updateGeneration = 0;\nlet disposed = false;\nlet pendingUpdate;\nlet updateStatus;\nfunction currentUpdate(generation) { return !disposed && generation === updateGeneration; }\nasync function checkForUpdate() {\n  const generation = ++updateGeneration;\n  const previousUpdate = pendingUpdate;\n  updateStatus = "checking";\n  renderUpdateSettings();\n  try {\n    await previousUpdate?.close();\n    const update = await updater.check();\n    if (!currentUpdate(generation)) {\n      await update?.close().catch(() => undefined);\n    }\n  } catch {}\n}\nfunction closeUpdateSettings(): void {\n  ++updateGeneration;\n  const update = pendingUpdate;\n  pendingUpdate = null;\n  void update?.close().catch(() => undefined);\n}\nfunction dispose(): void {\n  ++updateGeneration;\n  const update = pendingUpdate;\n  pendingUpdate = null;\n  void update?.close().catch(() => undefined);\n}\n`,
  );
}

test("acceptance declares the 0.1.6 hardened baseline and 0.1.7 formal second hop", () => {
  assert.equal(CONFIG.schema_version, 4);
  assert.equal(BASELINE_VERSION, "0.1.6");
  assert.equal(TARGET_VERSION, "0.1.7");
  assert.deepEqual([...CONFIG.version_only_files].sort(), [
    "package-lock.json",
    "package.json",
    "src-tauri/Cargo.lock",
    "src-tauri/Cargo.toml",
    "src-tauri/tauri.conf.json",
  ]);
  const changedClosure = JSON.parse(readFileSync(path.join(ROOT, "scripts/windows-updater-acceptance.json"), "utf8"));
  changedClosure.legacy_bootstrap.canonical_closure.published_at = "2026-08-28T11:03:13Z";
  assert.throws(() => validateAcceptanceConfig(changedClosure), /closure tuple digest is inconsistent/);
});

test("acceptance harness can fetch only the captured baseline executable", () => {
  const fixture = bootstrapFixture();
  const bootstrapUrl = `${fixture.releaseUrl}/${fixture.releaseNames.setup}`;
  const policy = { config: CONFIG, targetVersion: TARGET_VERSION, bootstrapUrl };
  assert.doesNotThrow(() => assertAnonymousFetchAllowed(bootstrapUrl, policy, "bootstrap-installer"));
  assert.throws(
    () =>
      assertAnonymousFetchAllowed(
        `https://github.com/${CONFIG.repository}/releases/download/${TARGET_VERSION}/${names(TARGET_VERSION).setup}`,
        policy,
        "target-installer",
      ),
    /must not download the target installer/,
  );
  assert.throws(
    () =>
      assertAnonymousFetchAllowed(
        `${fixture.releaseUrl}/${names(BASELINE_VERSION).msi}`,
        policy,
        "bootstrap-installer",
      ),
    /unauthorized executable download/,
  );
});

test("pre-publish latest metadata binds the baseline tag, signature and GitHub digests", () => {
  const fixture = bootstrapFixture();
  const validated = validateBootstrapRelease({ config: CONFIG, targetVersion: TARGET_VERSION, ...fixture });
  assert.equal(validated.baselineVersion, BASELINE_VERSION);
  assert.equal(validated.commit, BASELINE_COMMIT);
  assert.throws(
    () =>
      validateBootstrapRelease({
        config: CONFIG,
        targetVersion: TARGET_VERSION,
        ...fixture,
        signatureBytes: Buffer.from(`${FAKE_SIGNATURE}changed`),
      }),
    /signature differs|digest differs/,
  );
});

test("captured formal baseline is self-contained and cannot contain the target installer", () => {
  const { baselineRoot } = writeCapturedBaseline();
  const validated = validateCapturedBaseline({
    config: CONFIG,
    targetVersion: TARGET_VERSION,
    baselineRoot,
    root: ROOT,
  });
  assert.equal(validated.baseline.hardened_updater_source_verified, true);
  assert.equal(validated.baseline.proves_hardened_updater_lifecycle, false);

  writeFileSync(path.join(baselineRoot, names(TARGET_VERSION).setup), "forbidden target bytes");
  assert.throws(
    () => validateCapturedBaseline({ config: CONFIG, targetVersion: TARGET_VERSION, baselineRoot, root: ROOT }),
    /contains target installer/,
  );
});

test("pre-publish artifact cannot claim that the runtime lifecycle already passed", () => {
  const { baselineRoot } = writeCapturedBaseline({ proves_hardened_updater_lifecycle: true });
  assert.throws(
    () => validateCapturedBaseline({ config: CONFIG, targetVersion: TARGET_VERSION, baselineRoot, root: ROOT }),
    /must not claim runtime lifecycle proof/,
  );
});

test("formal second hop is version-only and binds to the hardened baseline source", () => {
  const temporary = mkdtempSync(path.join(tmpdir(), "openaria-version-only-updater-test-"));
  const origin = path.join(temporary, "origin.git");
  const working = path.join(temporary, "working");
  mkdirSync(working);
  execFileSync("git", ["init", "--bare", origin], { stdio: "ignore" });
  git(working, ["init"]);
  git(working, ["config", "user.name", "Updater Acceptance Test"]);
  git(working, ["config", "user.email", "updater-acceptance@example.invalid"]);
  git(working, ["remote", "add", "origin", origin]);
  writeVersionSources(working, BASELINE_VERSION);
  git(working, ["add", "."]);
  git(working, ["commit", "-m", "hardened updater baseline"]);
  git(working, ["tag", BASELINE_VERSION]);
  git(working, ["push", "origin", `refs/tags/${BASELINE_VERSION}`]);
  const baselineCommit = git(working, ["rev-parse", "HEAD"]);

  writeVersionSources(working, TARGET_VERSION);
  git(working, ["add", ...CONFIG.version_only_files]);
  git(working, ["commit", "-m", "version only formal hop"]);
  const validated = validateVersionOnlyUpgrade({
    root: working,
    config: CONFIG,
    baselineVersion: BASELINE_VERSION,
    baselineCommit,
    targetVersion: TARGET_VERSION,
  });
  assert.equal(validated.version_only, true);
  assert.equal(validated.hardened_source.verified, true);
  assert.equal(validated.hardened_source.contracts.length, 9);

  writeFileSync(path.join(working, "unexpected.txt"), "not a version bump\n");
  git(working, ["add", "unexpected.txt"]);
  git(working, ["commit", "-m", "unexpected behavior change"]);
  assert.throws(
    () =>
      validateVersionOnlyUpgrade({
        root: working,
        config: CONFIG,
        baselineVersion: BASELINE_VERSION,
        baselineCommit,
        targetVersion: TARGET_VERSION,
      }),
    /must change exactly the version authority files/,
  );
});

test("target metadata binds latest.json, signature, checksums and exact GitHub assets", () => {
  const fixture = targetFixture();
  const validated = validateTargetRelease({ config: CONFIG, ...fixture });
  assert.equal(validated.setup.name, names(TARGET_VERSION).setup);
  assert.equal(validated.signature.matches_latest_json, true);

  assert.throws(
    () =>
      validateTargetRelease({
        config: CONFIG,
        ...fixture,
        release: {
          ...fixture.release,
          assets: [...fixture.release.assets, { name: "retired-macos.dmg" }],
        },
      }),
    /exactly the six Windows updater assets/,
  );
});

test("dispatch preflight rejects stale settings and any formal-hop legacy exception", () => {
  assert.doesNotThrow(() =>
    validateDispatchPreflight({
      receipt: dispatchPreflight(),
      config: CONFIG,
      targetVersion: TARGET_VERSION,
      root: ROOT,
    }),
  );
  assert.throws(
    () =>
      validateDispatchPreflight({
        receipt: dispatchPreflight({ run_attempt: "2" }),
        config: CONFIG,
        targetVersion: TARGET_VERSION,
        root: ROOT,
      }),
    /first workflow run attempt/,
  );
  assert.throws(
    () =>
      validateDispatchPreflight({
        receipt: dispatchPreflight({
          immutable_setting: {
            ...dispatchPreflight().immutable_setting,
            dispatch_gap_seconds: 301,
          },
        }),
        config: CONFIG,
        targetVersion: TARGET_VERSION,
        root: ROOT,
      }),
    /five-minute dispatch window/,
  );
  assert.throws(
    () =>
      validateDispatchPreflight({
        receipt: dispatchPreflight({ allow_legacy_baseline_bootstrap: true }),
        config: CONFIG,
        targetVersion: TARGET_VERSION,
        root: ROOT,
      }),
    /one pinned bootstrap target/,
  );
});

test("controlled TLS server exposes only production-exact updater paths and bytes", () => {
  const temporary = mkdtempSync(path.join(tmpdir(), "openaria-controlled-server-test-"));
  const manifest = Buffer.from('{"version":"0.1.7"}\n');
  const installer = Buffer.from("exact signed updater candidate bytes");
  const manifestFile = path.join(temporary, "latest.json");
  const installerFile = path.join(temporary, names(TARGET_VERSION).setup);
  writeFileSync(manifestFile, manifest);
  writeFileSync(installerFile, installer);
  const plan = validateControlledServerPlan({
    schema: "openaria.desktop.controlled-update-server.v1",
    host: "github.com",
    repository: CONFIG.repository,
    version: TARGET_VERSION,
    manifest: {
      name: "latest.json",
      file: manifestFile,
      request_path: `/${CONFIG.repository}/releases/latest/download/latest.json`,
      bytes: manifest.length,
      sha256: digest(manifest),
    },
    installer: {
      name: names(TARGET_VERSION).setup,
      file: installerFile,
      request_path: `/${CONFIG.repository}/releases/download/${TARGET_VERSION}/${names(TARGET_VERSION).setup}`,
      bytes: installer.length,
      sha256: digest(installer),
    },
  });
  const manifestResponse = resolveControlledRequest(plan, {
    method: "GET",
    url: plan.manifest.request_path,
    headers: { host: "github.com" },
  });
  assert.equal(manifestResponse.status, 200);
  assert.deepEqual(manifestResponse.body, manifest);
  const rangeResponse = resolveControlledRequest(plan, {
    method: "GET",
    url: plan.installer.request_path,
    headers: { host: "github.com", range: "bytes=0-4" },
  });
  assert.equal(rangeResponse.status, 206);
  assert.deepEqual(rangeResponse.body, installer.subarray(0, 5));
  assert.equal(
    resolveControlledRequest(plan, {
      method: "GET",
      url: `/${CONFIG.repository}/releases/download/${TARGET_VERSION}/unexpected.msi`,
      headers: { host: "github.com" },
    }).status,
    404,
  );

  const request = (kind, status, responseBytes, source) => ({
    kind,
    status,
    response_bytes: responseBytes,
    source_bytes: source.bytes,
    source_sha256: source.sha256,
  });
  const proof = validateControlledRequestLog({
    plan,
    log: {
      schema: "openaria.desktop.controlled-update-server-log.v1",
      host: "github.com",
      version: TARGET_VERSION,
      requests: [
        request("manifest", 200, manifest.length, plan.manifest),
        request("installer", 200, installer.length, plan.installer),
        request("manifest", 200, manifest.length, plan.manifest),
      ],
    },
  });
  assert.equal(proof.complete_installer_response, true);
});
