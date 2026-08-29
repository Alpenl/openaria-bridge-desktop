import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  parseSha256Sums,
  stageReleaseAssets,
  validateLatestManifest,
  validatePublishedReleaseMetadata,
  validateVersionSources,
} from "./desktop-release-contract.mjs";
import {
  draftOwnershipMarker,
  observedTargetTag,
  releaseAssetUrl,
  validateAcceptance,
  validateCandidateStartState,
  validateReleaseAssetUrl,
  validateReleaseRunIdentity,
} from "./desktop-release-commit-point.mjs";

const REPOSITORY = "Alpenl/openaria-bridge-desktop";
const ROOT = path.resolve(import.meta.dirname, "..");
const VERSION = JSON.parse(readFileSync(path.join(ROOT, "src-tauri/tauri.conf.json"), "utf8")).version;
const WRONG_VERSION = VERSION.replace(/\d+$/, (patch) => String(Number(patch) + 1));
const FAKE_SIGNATURE = Buffer.from(
  "untrusted comment: signature from test key\nRWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
).toString("base64");

test("source versions and Windows bundle targets have one release authority", () => {
  assert.equal(validateVersionSources(ROOT, VERSION).appVersion, VERSION);
  assert.throws(() => validateVersionSources(ROOT, WRONG_VERSION), /Release tag .* != app version/);
});

test("release staging produces the closed signed Windows asset set", () => {
  const temporary = mkdtempSync(path.join(tmpdir(), "desktop-release-contract-"));
  const input = path.join(temporary, "input");
  const output = path.join(temporary, "output");
  mkdirSync(input);
  const setup = path.join(input, `Open Aria Bridge_${VERSION}_x64-setup.exe`);
  const msi = path.join(input, `Open Aria Bridge_${VERSION}_x64_en-US.msi`);
  writeFileSync(setup, "setup");
  writeFileSync(msi, "msi");
  writeFileSync(`${setup}.sig`, FAKE_SIGNATURE);
  writeFileSync(`${msi}.sig`, FAKE_SIGNATURE);

  const manifest = stageReleaseAssets({
    version: VERSION,
    repository: REPOSITORY,
    inputRoot: input,
    outputRoot: output,
    pubDate: "2026-08-29T00:00:00.000Z",
  });
  validateLatestManifest(manifest, { version: VERSION, repository: REPOSITORY });
  assert.deepEqual(readdirSync(output).sort(), [
    `OpenAriaBridge_${VERSION}_windows_x86_64-setup.exe`,
    `OpenAriaBridge_${VERSION}_windows_x86_64-setup.exe.sig`,
    `OpenAriaBridge_${VERSION}_windows_x86_64.msi`,
    `OpenAriaBridge_${VERSION}_windows_x86_64.msi.sig`,
    "SHA256SUMS",
    "latest.json",
  ]);
  assert.equal(parseSha256Sums(readFileSync(path.join(output, "SHA256SUMS"), "utf8")).size, 4);
});

test("latest manifest rejects an old or nonexistent installer URL", () => {
  const manifest = {
    version: VERSION,
    pub_date: "2026-08-29T00:00:00.000Z",
    platforms: {
      "windows-x86_64": {
        signature: FAKE_SIGNATURE,
        url: `https://github.com/${REPOSITORY}/releases/download/0.0.9/OpenAriaBridge_0.0.9_windows_x86_64-setup.exe`,
      },
    },
  };
  assert.throws(
    () => validateLatestManifest(manifest, { version: VERSION, repository: REPOSITORY }),
    /latest\.json URL/,
  );
});

test("published Release metadata is an exact six-asset byte and digest closure", () => {
  const names = [
    `OpenAriaBridge_${VERSION}_windows_x86_64-setup.exe`,
    `OpenAriaBridge_${VERSION}_windows_x86_64-setup.exe.sig`,
    `OpenAriaBridge_${VERSION}_windows_x86_64.msi`,
    `OpenAriaBridge_${VERSION}_windows_x86_64.msi.sig`,
    "SHA256SUMS",
    "latest.json",
  ];
  const assets = new Map(names.map((name) => [name, Buffer.from(`published bytes for ${name}`)]));
  const metadata = {
    id: 123456789,
    tag_name: VERSION,
    draft: false,
    prerelease: false,
    immutable: true,
    published_at: "2026-08-29T00:00:00Z",
    assets: names.map((name) => {
      const bytes = assets.get(name);
      return {
        name,
        size: bytes.length,
        digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
        browser_download_url: `https://github.com/${REPOSITORY}/releases/download/${VERSION}/${name}`,
      };
    }),
  };

  validatePublishedReleaseMetadata(metadata, { repository: REPOSITORY, version: VERSION, assets });
  assert.throws(
    () =>
      validatePublishedReleaseMetadata(
        { ...metadata, assets: [...metadata.assets, { name: "old-macos.dmg" }] },
        { repository: REPOSITORY, version: VERSION, assets },
      ),
    /asset closure/,
  );
  assert.throws(
    () =>
      validatePublishedReleaseMetadata(
        {
          ...metadata,
          assets: metadata.assets.map((asset) =>
            asset.name === "latest.json" ? { ...asset, digest: "sha256:deadbeef" } : asset,
          ),
        },
        { repository: REPOSITORY, version: VERSION, assets },
      ),
    /GitHub digest/,
  );
});

test("workflow keeps CI triggers but restricts Release publication to evidence-bound dispatch", () => {
  const workflow = readFileSync(path.resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
  const trigger = workflow.slice(0, workflow.indexOf("\npermissions:"));
  const prepare = workflow.slice(workflow.indexOf("\n  prepare:\n"), workflow.indexOf("\n  frontend:\n"));
  assert.match(trigger, /push:\n {4}branches: \[main\]/);
  assert.match(trigger, /pull_request:/);
  assert.match(trigger, /workflow_dispatch:/);
  assert.doesNotMatch(trigger, /tags:/);
  for (const input of [
    "release_tag",
    "source_commit",
    "immutable_preflight_actor",
    "immutable_preflight_checked_at",
    "immutable_preflight_raw_response",
    "immutable_preflight_sha256",
    "allow_legacy_baseline_bootstrap",
  ]) {
    assert.match(trigger, new RegExp(`\\n      ${input}:\\n`));
  }
  assert.match(prepare, /GITHUB_EVENT_NAME}" == "workflow_dispatch"/);
  assert.doesNotMatch(prepare, /GITHUB_REF_TYPE|GITHUB_REF_NAME/);
  assert.match(prepare, /REQUESTED_SOURCE_COMMIT.*checkout_ref/);
  assert.match(prepare, /GITHUB_SHA.*REQUESTED_SOURCE_COMMIT/);
  assert.match(prepare, /GITHUB_ACTOR.*GITHUB_REPOSITORY_OWNER/);
  assert.match(prepare, /IMMUTABLE_PREFLIGHT_ACTOR.*GITHUB_ACTOR/);
  assert.match(prepare, /default_branch_head.*REQUESTED_SOURCE_COMMIT/);
  assert.match(prepare, /GITHUB_REF.*refs\/heads\/\$\{default_branch\}/);
  assert.match(prepare, /immutable-release-setting\.json/);
  assert.match(prepare, /raw_response_sha256/);
  assert.match(prepare, /dispatch_gap_seconds/);
  assert.match(prepare, /openaria\.desktop\.release-dispatch-preflight\.v1/);
  assert.match(prepare, /keys == \["enabled", "enforced_by_owner"\]/);
  assert.match(prepare, /-gt 300/);
  assert.match(prepare, /GITHUB_RUN_ATTEMPT[^\n]*!=[^\n]*"1"/);
});

test("every action reachable from Release is pinned to a reviewed commit", () => {
  const workflow = readFileSync(path.resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
  const reviewed = new Map([
    ["Swatinem/rust-cache", ["6323deb102c322ba6fcbdcafc7e3dddab59af2b6", "v2.9.2"]],
    ["actions/checkout", ["d23441a48e516b6c34aea4fa41551a30e30af803", "v6.1.0"]],
    ["actions/download-artifact", ["37930b1c2abaa49bbe596cd826c3c89aef350131", "v7.0.0"]],
    ["actions/setup-node", ["249970729cb0ef3589644e2896645e5dc5ba9c38", "v6.5.0"]],
    ["actions/upload-artifact", ["b7c566a772e6b6bfb58ed0dc250532a479d7789f", "v6.0.0"]],
    ["dtolnay/rust-toolchain", ["4360b52568e2003a75bf9bc1d59f33a8e3fc893c", "stable 2026-08-05"]],
    ["tauri-apps/tauri-action", ["84b9d35b5fc46c1e45415bdb6144030364f7ebc5", "v0.6.2"]],
  ]);
  const uses = workflow
    .split(/\r?\n/)
    .map((line) => line.trim())
    .map((line) => line.replace(/^-\s+/, ""))
    .filter((line) => line.startsWith("uses:"));
  assert.ok(uses.length > 0, "workflow must contain action dependencies");
  for (const line of uses) {
    const match = line.match(/^uses: ([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([a-f0-9]{40}) # (\S.*)$/);
    assert.notEqual(match, null, `action dependency is not pinned with a version comment: ${line}`);
    assert.deepEqual(match.slice(2), reviewed.get(match[1]), `action dependency is not an approved pin: ${line}`);
  }
});

test("a Release attempt cannot reuse a rerun, tag, Release, or draft", () => {
  assert.doesNotThrow(() => validateReleaseRunIdentity("123456", "1"));
  assert.throws(() => validateReleaseRunIdentity("123456", "2"), /first workflow run attempt/);
  assert.doesNotThrow(() => validateCandidateStartState({ releases: [], tag: null, version: VERSION }));
  assert.throws(
    () =>
      validateCandidateStartState({
        releases: [],
        tag: { ref: `refs/tags/${VERSION}`, object: { type: "commit", sha: "a".repeat(40) } },
        version: VERSION,
      }),
    /candidate Git tag already exists/,
  );
  for (const draft of [false, true]) {
    assert.throws(
      () =>
        validateCandidateStartState({
          releases: [{ id: 987654, tag_name: VERSION, draft }],
          tag: null,
          version: VERSION,
        }),
      /candidate GitHub Release already exists/,
    );
  }
  const marker = draftOwnershipMarker(REPOSITORY, VERSION, "b".repeat(40), "123456", "1");
  assert.match(marker, /run_id=123456 run_attempt=1/);
  assert.notEqual(marker, draftOwnershipMarker(REPOSITORY, VERSION, "b".repeat(40), "999999", "1"));
  assert.equal(observedTargetTag(null, "b".repeat(40)), null);
  assert.deepEqual(observedTargetTag({ object: { type: "commit", sha: "b".repeat(40) } }, "b".repeat(40)), {
    commit: "b".repeat(40),
    type: "commit",
  });
  assert.throws(
    () => observedTargetTag({ object: { type: "commit", sha: "c".repeat(40) } }, "b".repeat(40)),
    /unexpected target tag/,
  );
});

test("Release is staged, accepted through the old production updater, then published", () => {
  const workflow = readFileSync(path.resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
  const baselineStart = workflow.indexOf("\n  updater-baseline:\n");
  const tauriStart = workflow.indexOf("\n  tauri:\n");
  const draftStart = workflow.indexOf("\n  release-draft:\n");
  const acceptanceStart = workflow.indexOf("\n  windows-updater-acceptance:\n");
  const publicationStart = workflow.indexOf("\n  release-publication:\n");
  assert.ok(baselineStart >= 0 && tauriStart > baselineStart && draftStart > tauriStart);
  assert.ok(acceptanceStart > draftStart && publicationStart > acceptanceStart);

  const baseline = workflow.slice(baselineStart, tauriStart);
  const tauri = workflow.slice(tauriStart, draftStart);
  const draft = workflow.slice(draftStart, acceptanceStart);
  const acceptance = workflow.slice(acceptanceStart, publicationStart);
  const publication = workflow.slice(publicationStart);
  assert.doesNotMatch(workflow, /\n {2}legacy-compat:\n/);
  assert.doesNotMatch(workflow, /Run retained removable-media and interruption regressions/);
  assert.doesNotMatch(
    workflow,
    /cargo test --manifest-path src-tauri\/Cargo\.toml\s{1,}--workspace --all-targets --all-features/,
  );
  assert.match(workflow, /-p ylx-transfer-adapters --all-features session_export --\s+--nocapture --test-threads=1/);
  for (const gate of [
    "frontend",
    "device-contracts",
    "updater-contract",
    "rust-current",
    "media-contract",
    "object-store-minio",
    "tauri",
    "updater-baseline",
  ]) {
    assert.match(draft, new RegExp(`\\n      - ${gate}\\n`));
  }
  assert.match(draft, /desktop-release-commit-point\.mjs prepare-draft/);
  assert.match(draft, /numeric never-public draft/);
  assert.match(draft, /--output release-candidate/);
  assert.match(acceptance, /needs:[^]*release-draft/);
  assert.match(acceptance, /runs-on: windows-latest/);
  assert.match(
    acceptance,
    /permissions:\n {6}contents: write/,
    "GitHub only exposes draft Releases to tokens with push access; the acceptance job must be able to recheck the owned numeric draft",
  );
  assert.match(acceptance, /persist-credentials: false/);
  assert.match(acceptance, /windows-updater-acceptance\.mjs accept/);
  assert.match(acceptance, /--candidate release-candidate/);
  assert.match(acceptance, /--ownership release-candidate\/release-ownership\.json/);
  assert.match(acceptance, /Install unchanged public baseline and update through its production updater/);
  const acceptanceClient = readFileSync(path.resolve(import.meta.dirname, "windows-updater-acceptance.mjs"), "utf8");
  assert.match(tauri, /Smoke controlled updater TLS certificate setup/);
  assert.match(tauri, /windows-updater-acceptance\.mjs smoke-controlled-tls/);
  assert.match(acceptanceClient, /Get-PSDrive -Name Cert/);
  assert.match(acceptanceClient, /New-PSDrive -Name Cert -PSProvider Certificate/);
  assert.match(acceptanceClient, /spawnSync\(\s*"pwsh\.exe"/);
  assert.doesNotMatch(acceptanceClient, /spawnSync\(\s*"powershell\.exe"/);
  assert.match(acceptanceClient, /certutil\.exe -f -addstore Root/);
  assert.match(acceptanceClient, /certutil\.exe -delstore Root/);
  assert.match(acceptanceClient, /certutil\.exe -user -delstore My/);
  assert.doesNotMatch(acceptanceClient, /certutil\.exe -user .*Root/);
  assert.doesNotMatch(acceptanceClient, /Remove-Item -LiteralPath \$item/);
  assert.match(acceptanceClient, /-ChainOption EndEntityCertOnly/);
  assert.doesNotMatch(acceptanceClient, /-ChainOption BuildChain/);
  assert.match(acceptanceClient, /controlled TLS phase/);
  assert.doesNotMatch(acceptanceClient, /X509Store/);
  assert.doesNotMatch(acceptanceClient, /Import-Certificate/);
  assert.match(acceptanceClient, /command === "smoke-controlled-tls"/);
  assert.match(acceptanceClient, /createWebviewAutomationProfile\(\)/);
  assert.match(acceptanceClient, /webview2_user_data_folder: webviewUserDataFolder/);
  assert.match(acceptanceClient, /user_data_registry_path/);
  assert.match(acceptanceClient, /value: userDataFolder/);
  assert.match(acceptanceClient, /configureWebviewDebugPolicy\(/);
  assert.match(acceptanceClient, /AdditionalBrowserArguments/);
  assert.match(acceptanceClient, /UserDataFolder/);
  assert.match(acceptanceClient, /webview2_debug_policy_configured/);
  assert.match(acceptanceClient, /windows_process_integrity_observed/);
  assert.match(acceptanceClient, /webview2_hklm_policy_unavailable/);
  assert.match(acceptanceClient, /for \(const scope of \["HKLM", "HKCU"\]\)/);
  assert.match(acceptanceClient, /restoreWebviewDebugPolicy\(/);
  assert.match(acceptanceClient, /webview2_debug_policy_restored/);
  assert.match(acceptanceClient, /created_keys = @\(\$createdKeys\)/);
  assert.match(acceptanceClient, /Sort-Object \{ \$_\.Length \} -Descending/);
  assert.match(acceptanceClient, /GetSubKeyNames\(\)/);
  assert.match(acceptanceClient, /webview2_debug_environment_overrides_removed/);
  assert.match(acceptanceClient, /delete appEnvironment\[name\]/);
  assert.doesNotMatch(acceptanceClient, /WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS:\s*`/);
  assert.doesNotMatch(acceptanceClient, /WEBVIEW2_USER_DATA_FOLDER:\s*webviewUserDataFolder/);
  assert.match(acceptanceClient, /processInfoForWebview\(/);
  assert.match(acceptanceClient, /Get-NetTCPConnection/);
  assert.match(acceptanceClient, /webview2_process_diagnostics/);
  assert.match(acceptanceClient, /webview2_observation_failed/);
  assert.match(acceptanceClient, /removeWebviewAutomationProfile\(webviewUserDataFolder, evidence\)/);
  const acceptanceRunStart = acceptanceClient.indexOf("async function runAcceptance(");
  const acceptanceRunEnd = acceptanceClient.indexOf("async function main(");
  const acceptanceRun = acceptanceClient.slice(acceptanceRunStart, acceptanceRunEnd);
  assert.match(acceptanceRun, /const cleanupErrors = \[\]/);
  assert.match(acceptanceRun, /cleanupErrors\.length > 1[\s\S]*new AggregateError\(\s*cleanupErrors/);
  assert.match(acceptanceRun, /if \(acceptanceError && cleanupError\)/);
  assert.match(acceptanceRun, /new AggregateError\(\s*\[acceptanceError, cleanupError\]/);
  assert.match(acceptanceRun, /return acceptanceResult/);
  const captureStart = acceptanceClient.indexOf("async function capturePrePublishBaseline(");
  const recheckStart = acceptanceClient.indexOf("async function authenticatedGithubJson(");
  const capture = acceptanceClient.slice(captureStart, recheckStart);
  const historyStart = acceptanceClient.indexOf("async function fetchPublicReleaseHistory(");
  const historyEnd = acceptanceClient.indexOf("export function validateDispatchPreflight(");
  const history = acceptanceClient.slice(historyStart, historyEnd);
  assert.match(
    baseline,
    /Capture latest before publishing the target Release[^]*GITHUB_TOKEN: \$\{\{ github\.token \}\}/,
  );
  assert.match(capture, /authenticatedGithubJson\([^]*releases\/latest/);
  assert.match(capture, /authenticatedGithubJson\([^]*git\/ref\/tags/);
  assert.match(history, /authenticatedGithubJson\(/);
  assert.match(capture, /fetchBytes\(config\.updater_endpoint/);
  assert.match(capture, /fetchBytes\([^]*"anonymous bootstrap installer"/);
  assert.match(capture, /fetchBytes\([^]*"anonymous bootstrap signature"/);
  assert.doesNotMatch(acceptanceClient, /method:\s*["'](?:POST|PATCH|PUT|DELETE)["']/);
  assert.match(publication, /needs:[^]*windows-updater-acceptance/);
  assert.match(publication, /desktop-release-commit-point\.mjs publish/);
  assert.match(publication, /--request-log windows-updater-acceptance\/controlled-update-server-log\.json/);
  assert.match(publication, /Read-only anonymous exact-byte postverification/);
});

test("immutable publication has one numeric commit point and no rollback path", () => {
  const workflow = readFileSync(path.resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
  const commitPoint = readFileSync(path.resolve(import.meta.dirname, "desktop-release-commit-point.mjs"), "utf8");
  assert.doesNotMatch(workflow, /release-rollback:|restore previous latest|gh release edit|--latest/);
  assert.doesNotMatch(workflow, /releases\/tags\/[^\s]*.*(?:PATCH|publish)/);
  assert.doesNotMatch(commitPoint, /gh release|execFileSync\([^]*release edit/);
  assert.equal(
    [...commitPoint.matchAll(/method: "PATCH"/g)].length,
    2,
    "one PATCH call and one receipt description must remain",
  );
  assert.match(
    commitPoint,
    /request\(`\/repos\/\$\{ownership\.repository\}\/releases\/\$\{ownership\.release_id\}`[^]*method: "PATCH"/,
  );
  assert.match(commitPoint, /body: \{ draft: false, prerelease: false, make_latest: "true" \}/);
  assert.match(commitPoint, /mutation_retried: false/);
  assert.match(commitPoint, /if \(message\.includes\("returned HTTP"\)\) throw error/);
  assert.match(commitPoint, /candidate GitHub Release already exists/);
  assert.match(commitPoint, /never-public draft ownership marker changed/);
  assert.match(commitPoint, /openaria\.desktop\.never-public-draft\.v2/);
  assert.match(commitPoint, /acceptance request log exact-byte binding changed/);
  assert.match(commitPoint, /acceptance request log does not bind the exact candidate manifest/);
  assert.match(commitPoint, /release\.immutable === true/);
  assert.match(commitPoint, /POSTVERIFY_ATTEMPTS/);
  assert.doesNotMatch(commitPoint, /method: "PATCH"[^]*baseline\.release_id/);
  assert.match(commitPoint, /runAttempt === "1"/);
  assert.doesNotMatch(commitPoint, /async function ensureTag|\/git\/refs[^]*method: "POST"/);
  assert.doesNotMatch(commitPoint, /if \(matching\.length === 1\)|draft asset cleanup did not reach an empty closure/);
  assert.match(commitPoint, /candidate Git tag already exists/);
  assert.match(commitPoint, /candidate GitHub Release already exists/);
  assert.match(commitPoint, /openaria\.desktop\.never-public-draft\.v2[^\n]*run_id=[^\n]*run_attempt=/);
  assert.match(commitPoint, /candidate_start: \{ exact_release_absent: true, exact_tag_absent: true \}/);
  assert.match(commitPoint, /target_tag_after_draft: targetTagAfterDraft/);
});

test("Release history closure parses bounded JSON pages instead of a pagination stream", () => {
  const acceptance = readFileSync(path.resolve(import.meta.dirname, "windows-updater-acceptance.mjs"), "utf8");
  const commitPoint = readFileSync(path.resolve(import.meta.dirname, "desktop-release-commit-point.mjs"), "utf8");
  assert.match(acceptance, /for \(let page = 1; page <= 20; page \+= 1\)/);
  assert.match(acceptance, /authenticatedGithubJson\(url, `public Release history page \$\{page\}`\)/);
  assert.match(acceptance, /Array\.isArray\(releases\)/);
  assert.doesNotMatch(acceptance, /fetchBytes\(url, `public Release history page \$\{page\}`\)/);
  assert.match(commitPoint, /for \(let page = 1; page <= 20; page \+= 1\)/);
  assert.match(commitPoint, /Array\.isArray\(values\)/);
  assert.doesNotMatch(`${acceptance}\n${commitPoint}`, /--paginate|\bslurp\b/);
});

test("irreversible publication verifies the exact controlled-server request log", () => {
  const version = "0.1.6";
  const commit = "a".repeat(40);
  const releaseId = 2468;
  const manifest = Buffer.from("candidate latest manifest");
  const installer = Buffer.from("candidate signed installer");
  const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const manifestAsset = {
    name: "latest.json",
    size: manifest.length,
    digest: digest(manifest),
    browser_download_url: `https://github.com/${REPOSITORY}/releases/download/${version}/latest.json`,
  };
  const installerAsset = {
    name: `OpenAriaBridge_${version}_windows_x86_64-setup.exe`,
    size: installer.length,
    digest: digest(installer),
    browser_download_url: `https://github.com/${REPOSITORY}/releases/download/${version}/OpenAriaBridge_${version}_windows_x86_64-setup.exe`,
  };
  const ownership = {
    repository: REPOSITORY,
    run_id: "123",
    run_attempt: "1",
    target_version: version,
    target_commit: commit,
    release_id: releaseId,
    assets: [installerAsset, manifestAsset],
    dispatch_preflight: { schema: "test-preflight", enabled: true },
    baseline: { release_id: 1357, commit: "b".repeat(40), closure: { assets: [{ name: "baseline" }] } },
  };
  const requestLog = {
    schema: "openaria.desktop.controlled-update-server-log.v1",
    host: "github.com",
    repository: REPOSITORY,
    version,
    requests: [
      ...[1, 2].map(() => ({
        method: "GET",
        url: `/${REPOSITORY}/releases/latest/download/latest.json`,
        status: 200,
        kind: "manifest",
        response_bytes: manifest.length,
        source_bytes: manifest.length,
        source_sha256: manifestAsset.digest.slice("sha256:".length),
      })),
      {
        method: "GET",
        url: `/${REPOSITORY}/releases/download/${version}/${installerAsset.name}`,
        status: 200,
        kind: "installer",
        response_bytes: installer.length,
        source_bytes: installer.length,
        source_sha256: installerAsset.digest.slice("sha256:".length),
      },
    ],
  };
  const requestLogBytes = Buffer.from(`${JSON.stringify(requestLog)}\n`);
  const receipt = {
    schema: "openaria.windows-updater-acceptance.v1",
    status: "passed",
    repository: REPOSITORY,
    run_id: ownership.run_id,
    run_attempt: ownership.run_attempt,
    to_version: version,
    candidate_release_id: releaseId,
    candidate_commit: commit,
    dispatch_preflight: ownership.dispatch_preflight,
    baseline: {
      baseline_release_id: ownership.baseline.release_id,
      baseline_commit: ownership.baseline.commit,
      baseline_release_closure: ownership.baseline.closure,
    },
    candidate: { release_id: releaseId, target_commit: commit, assets: ownership.assets },
    browser_or_manual_download_used: false,
    target_installer_downloaded_by_harness: false,
    target_installer_served_only_to_production_updater: true,
    controlled_server_request_proof: {
      total_requests: 3,
      manifest_requests: 2,
      installer_requests: 1,
      complete_installer_response: true,
      request_log: {
        file: "controlled-update-server-log.json",
        bytes: requestLogBytes.length,
        sha256: createHash("sha256").update(requestLogBytes).digest("hex"),
      },
    },
    events: [{ kind: "target_version_observed_in_relaunched_application_ui" }],
  };

  assert.equal(validateAcceptance(receipt, ownership, requestLogBytes), receipt);

  const draftUrlReceipt = JSON.parse(JSON.stringify(receipt));
  draftUrlReceipt.candidate.assets = draftUrlReceipt.candidate.assets.map((asset) => ({
    ...asset,
    browser_download_url: `https://github.com/${REPOSITORY}/releases/download/untagged-820a80450dde06c5eeccf9/${asset.name}`,
  }));
  assert.equal(validateAcceptance(draftUrlReceipt, ownership, requestLogBytes), draftUrlReceipt);
  assert.throws(
    () => validateAcceptance(receipt, ownership, Buffer.concat([requestLogBytes, Buffer.from(" ")])),
    /request log exact-byte binding changed/,
  );

  const wrongPathLog = JSON.parse(JSON.stringify(requestLog));
  wrongPathLog.requests[0].url = "/wrong/latest.json";
  const wrongPathBytes = Buffer.from(`${JSON.stringify(wrongPathLog)}\n`);
  const wrongPathReceipt = JSON.parse(JSON.stringify(receipt));
  wrongPathReceipt.controlled_server_request_proof.request_log.bytes = wrongPathBytes.length;
  wrongPathReceipt.controlled_server_request_proof.request_log.sha256 = createHash("sha256")
    .update(wrongPathBytes)
    .digest("hex");
  assert.throws(
    () => validateAcceptance(wrongPathReceipt, ownership, wrongPathBytes),
    /does not bind the exact candidate manifest/,
  );
});

test("draft URL normalization accepts only GitHub untagged slugs and formalizes published paths", () => {
  const name = `OpenAriaBridge_${VERSION}_windows_x86_64-setup.exe`;
  const formal = releaseAssetUrl(REPOSITORY, VERSION, name);
  const draft = `https://github.com/${REPOSITORY}/releases/download/untagged-820a80450dde06c5eeccf9/${name}`;
  assert.deepEqual(validateReleaseAssetUrl(formal, { repository: REPOSITORY, version: VERSION, name }), {
    kind: "formal",
    url: formal,
  });
  assert.equal(
    validateReleaseAssetUrl(draft, { repository: REPOSITORY, version: VERSION, name, expectedDraft: true }).kind,
    "draft",
  );
  assert.throws(
    () => validateReleaseAssetUrl(draft, { repository: REPOSITORY, version: VERSION, name, expectedDraft: false }),
    /formal tag URL/,
  );
  assert.throws(
    () =>
      validateReleaseAssetUrl(`https://github.com/${REPOSITORY}/releases/download/untagged-not-hex/${name}`, {
        repository: REPOSITORY,
        version: VERSION,
        name,
        expectedDraft: true,
      }),
    /untagged GitHub draft URL/,
  );
});

test("one-time mutable legacy bootstrap is pinned and automatically expires", () => {
  const config = JSON.parse(readFileSync(path.resolve(import.meta.dirname, "windows-updater-acceptance.json"), "utf8"));
  const workflow = readFileSync(path.resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
  assert.equal(config.schema_version, 4);
  const expectedClosure = {
    assets: [
      {
        browser_download_url: "https://github.com/Alpenl/openaria-bridge-desktop/releases/download/0.1.5/latest.json",
        digest: "sha256:1e49f4c357df2f9832672955b26737c3695710707737c182cd14ef7722678753",
        name: "latest.json",
        size: 742,
      },
      {
        browser_download_url:
          "https://github.com/Alpenl/openaria-bridge-desktop/releases/download/0.1.5/OpenAriaBridge_0.1.5_windows_x86_64-setup.exe",
        digest: "sha256:ab77680b9d29bbbbd0682d3d2b8a9c807b3cbc34fc63f95ef2af2063469f66ca",
        name: "OpenAriaBridge_0.1.5_windows_x86_64-setup.exe",
        size: 35078814,
      },
      {
        browser_download_url:
          "https://github.com/Alpenl/openaria-bridge-desktop/releases/download/0.1.5/OpenAriaBridge_0.1.5_windows_x86_64-setup.exe.sig",
        digest: "sha256:89c0109f68b833899cfec183c963fd2df6132cfa7da46650659f33a8558f5f4c",
        name: "OpenAriaBridge_0.1.5_windows_x86_64-setup.exe.sig",
        size: 428,
      },
      {
        browser_download_url:
          "https://github.com/Alpenl/openaria-bridge-desktop/releases/download/0.1.5/OpenAriaBridge_0.1.5_windows_x86_64.msi",
        digest: "sha256:75e2842acf46af8943fcf417f968a3a4365b0ae5cb98955186105b2cc5643969",
        name: "OpenAriaBridge_0.1.5_windows_x86_64.msi",
        size: 48672768,
      },
      {
        browser_download_url:
          "https://github.com/Alpenl/openaria-bridge-desktop/releases/download/0.1.5/OpenAriaBridge_0.1.5_windows_x86_64.msi.sig",
        digest: "sha256:9904c3483bc4e78ed972dc436d0923c58087fdb8347891d1ce3b5c2479c52cff",
        name: "OpenAriaBridge_0.1.5_windows_x86_64.msi.sig",
        size: 428,
      },
    ],
    draft: false,
    id: 378428394,
    immutable: false,
    prerelease: false,
    published_at: "2026-08-28T11:03:12Z",
    tag_name: "0.1.5",
  };
  assert.deepEqual(config.legacy_bootstrap.canonical_closure, expectedClosure);
  assert.equal(
    createHash("sha256").update(JSON.stringify(expectedClosure)).digest("hex"),
    "f8e432c016f570421caee8e3f253df8c94f323e45a0cf7296c98b8a956a00007",
  );
  assert.deepEqual(
    {
      target: config.legacy_bootstrap.target_version,
      baseline: config.legacy_bootstrap.baseline_version,
      release: config.legacy_bootstrap.release_id,
      commit: config.legacy_bootstrap.commit,
      closure: config.legacy_bootstrap.canonical_closure_sha256,
    },
    {
      target: "0.1.6",
      baseline: "0.1.5",
      release: 378428394,
      commit: "c27d6b30824efdf2db0606e76e4faae71ba27695",
      closure: "f8e432c016f570421caee8e3f253df8c94f323e45a0cf7296c98b8a956a00007",
    },
  );
  assert.equal(config.legacy_bootstrap.assets.length, 5);
  assert.match(workflow, /allow_legacy_baseline_bootstrap/);
  assert.match(workflow, /permanently limited to target 0\.1\.6/);
  assert.match(workflow, /Target 0\.1\.6 requires explicit/);
  assert.doesNotMatch(workflow, /0\.1\.7[^\n]*allow_legacy_baseline_bootstrap=true/);
});

test("workflow remains Windows-only and signs Release builds only", () => {
  const workflow = readFileSync(path.resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
  const tauriStart = workflow.indexOf("\n  tauri:\n");
  const draftStart = workflow.indexOf("\n  release-draft:\n");
  const tauri = workflow.slice(tauriStart, draftStart);
  assert.match(tauri, /runs-on: windows-latest/);
  assert.doesNotMatch(tauri, /matrix:|macos-latest/);
  assert.match(tauri, /bundle\/nsis/);
  assert.match(tauri, /bundle\/msi/);
  assert.match(tauri, /TAURI_SIGNING_PRIVATE_KEY/);
  assert.match(tauri, /needs\.prepare\.outputs\.is_release == 'true'/);
});

test("retained media documentation is explicitly compatibility-only", () => {
  const readme = readFileSync(path.resolve(import.meta.dirname, "../README.md"), "utf8");
  const wiring = readFileSync(path.resolve(import.meta.dirname, "../src-tauri/src/media/WIRING.md"), "utf8");
  assert.match(
    readme,
    /No current CI or\s+release job executes those historical removable-media or interruption tests/,
  );
  assert.match(readme, /CI and release workflows do not execute the retained removable-media/);
  assert.match(readme, /delete cleanup that cannot finish is an incomplete, retryable outcome/);
  assert.match(wiring, /^# Frozen Linux compatibility wiring/m);
  assert.match(wiring, /production Windows composition uses fail-closed media ports/);
  assert.match(wiring, /no CI or release\s+job executes its removable-media\s+or interruption\/recovery tests/);
  assert.match(wiring, /never a Windows product startup\s+operation/);
});
