import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const NUMERIC_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const EXPECTED_REPOSITORY = "Alpenl/openaria-bridge-desktop";
const EXPECTED_ASSET_COUNT = 6;
const POSTVERIFY_ATTEMPTS = 20;
const LEGACY_BASELINE_CLOSURE_SHA256 = "f8e432c016f570421caee8e3f253df8c94f323e45a0cf7296c98b8a956a00007";
const DRAFT_DOWNLOAD_SLUG = /^untagged-[0-9a-f]{8,64}$/;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function json(file, label = file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function numericVersion(value, label) {
  invariant(typeof value === "string" && NUMERIC_SEMVER.test(value), `${label} must use numeric SemVer X.Y.Z`);
  return value;
}

function releaseNames(version) {
  return [
    "SHA256SUMS",
    "latest.json",
    `OpenAriaBridge_${version}_windows_x86_64-setup.exe`,
    `OpenAriaBridge_${version}_windows_x86_64-setup.exe.sig`,
    `OpenAriaBridge_${version}_windows_x86_64.msi`,
    `OpenAriaBridge_${version}_windows_x86_64.msi.sig`,
  ].sort();
}

export function draftOwnershipMarker(repository, version, commit, runId, runAttempt) {
  return `<!-- openaria.desktop.never-public-draft.v2 repository=${repository} version=${version} commit=${commit} run_id=${runId} run_attempt=${runAttempt} -->`;
}

export function validateReleaseRunIdentity(runId, runAttempt) {
  invariant(/^\d+$/.test(runId) && /^\d+$/.test(runAttempt), "workflow run identity is invalid");
  invariant(runAttempt === "1", "Release publication requires the first workflow run attempt");
}

export function validateCandidateStartState({ releases, tag, version }) {
  invariant(Array.isArray(releases), "GitHub Release history is invalid");
  invariant(
    releases.every((release) => release.tag_name !== version),
    "candidate GitHub Release already exists; existing Releases and drafts cannot be taken over",
  );
  invariant(tag === null, "candidate Git tag already exists; every release attempt requires a fresh version");
}

export function observedTargetTag(tag, commit) {
  if (tag === null) return null;
  invariant(
    tag.object?.type === "commit" && tag.object.sha === commit,
    "GitHub created an unexpected target tag while creating the numeric draft",
  );
  return { commit: tag.object.sha, type: tag.object.type };
}

export function releaseAssetUrl(repository, version, name) {
  invariant(
    typeof repository === "string" && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository),
    "Release repository is invalid",
  );
  numericVersion(version, "Release asset version");
  invariant(typeof name === "string" && name.length > 0 && !name.includes("/"), "Release asset name is invalid");
  return `https://github.com/${repository}/releases/download/${version}/${name}`;
}

export function validateReleaseAssetUrl(url, { repository, version, name, expectedDraft = false }) {
  const formalUrl = releaseAssetUrl(repository, version, name);
  invariant(typeof url === "string" && url.length > 0, `${name} download URL is missing`);
  if (url === formalUrl) return { kind: "formal", url: formalUrl };

  invariant(expectedDraft === true, `${name} download URL must use the formal tag URL after publication`);
  const prefix = `https://github.com/${repository}/releases/download/`;
  invariant(url.startsWith(prefix), `${name} draft download URL is not a GitHub repository URL`);
  const suffix = url.slice(prefix.length);
  const separator = suffix.indexOf("/");
  const slug = separator === -1 ? "" : suffix.slice(0, separator);
  const assetName = separator === -1 ? "" : suffix.slice(separator + 1);
  invariant(
    DRAFT_DOWNLOAD_SLUG.test(slug) && assetName === name,
    `${name} draft download URL must use an untagged GitHub draft URL`,
  );
  return { kind: "draft", slug, url };
}

export function normalizedAssetPins(assets, label = "asset pins") {
  invariant(Array.isArray(assets), `${label} must be an array`);
  const pins = assets.map((asset, index) => {
    invariant(asset !== null && typeof asset === "object", `${label} entry ${index} is invalid`);
    const { name, size, digest } = asset;
    invariant(typeof name === "string" && name.length > 0, `${label} entry ${index} name is invalid`);
    invariant(Number.isSafeInteger(size) && size > 0, `${label} ${name} size is invalid`);
    invariant(typeof digest === "string" && /^sha256:[a-f0-9]{64}$/.test(digest), `${label} ${name} digest is invalid`);
    return { name, size, digest };
  });
  invariant(new Set(pins.map((asset) => asset.name)).size === pins.length, `${label} contain duplicate names`);
  return pins.sort((left, right) => left.name.localeCompare(right.name));
}

export function canonicalAssets(release) {
  invariant(Array.isArray(release?.assets), "Release assets must be an array");
  const result = release.assets
    .map(({ name, size, digest, browser_download_url }) => ({ browser_download_url, digest, name, size }))
    .sort((left, right) => left.name.localeCompare(right.name));
  invariant(
    new Set(result.map((asset) => asset.name)).size === result.length,
    "Release assets contain duplicate names",
  );
  return result;
}

export function canonicalReleaseClosure(release) {
  return {
    assets: canonicalAssets(release),
    draft: release.draft,
    id: release.id,
    immutable: release.immutable,
    prerelease: release.prerelease,
    published_at: release.published_at,
    tag_name: release.tag_name,
  };
}

function localAssets(root, version) {
  const names = releaseNames(version);
  const observed = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
  invariant(observed.join("\n") === names.join("\n"), "local candidate must contain exactly six Windows assets");
  return names.map((name) => {
    const file = path.join(root, name);
    const bytes = readFileSync(file);
    invariant(bytes.length > 0, `${name} is empty`);
    return { file, name, size: bytes.length, digest: `sha256:${sha256(bytes)}` };
  });
}

function validateDispatchPreflight(receipt, { repository, version, commit, runId, runAttempt }) {
  validateReleaseRunIdentity(runId, runAttempt);
  const repositoryOwner = repository.split("/", 1)[0];
  invariant(
    receipt?.schema === "openaria.desktop.release-dispatch-preflight.v1",
    "dispatch preflight schema is invalid",
  );
  invariant(receipt.repository === repository, "dispatch preflight repository is inconsistent");
  invariant(receipt.actor === repositoryOwner, "dispatch preflight actor is not the repository owner");
  invariant(receipt.event === "workflow_dispatch", "Release publication is restricted to workflow_dispatch");
  invariant(
    receipt.target_version === version && receipt.source_commit === commit,
    "dispatch preflight target changed",
  );
  invariant(
    typeof receipt.default_branch === "string" &&
      receipt.default_branch.length > 0 &&
      !/\s/.test(receipt.default_branch) &&
      receipt.default_branch_head === commit,
    "dispatch preflight is not bound to the default branch HEAD",
  );
  invariant(receipt.run_id === runId && receipt.run_attempt === runAttempt, "dispatch preflight run identity changed");
  invariant(receipt.run_attempt === "1", "dispatch preflight was reused by a workflow rerun");
  invariant(receipt.immutable_setting?.enabled === true, "immutable Release setting was not enabled before dispatch");
  invariant(SHA256.test(receipt.immutable_setting.raw_response_sha256), "immutable setting response digest is invalid");
  invariant(
    receipt.immutable_setting.checked_before_dispatch === true,
    "immutable setting was not checked before dispatch",
  );
  invariant(
    Number.isInteger(receipt.immutable_setting.dispatch_gap_seconds) &&
      receipt.immutable_setting.dispatch_gap_seconds >= -60 &&
      receipt.immutable_setting.dispatch_gap_seconds <= 300,
    "immutable setting preflight is outside the dispatch time window",
  );
  return receipt;
}

export function validateBaselineState({ baseline, latest, liveRelease, liveTag }) {
  invariant(latest.id === baseline.baseline_release_id, "latest Release ID changed after baseline capture");
  invariant(latest.tag_name === baseline.baseline_version, "latest Release version changed after baseline capture");
  invariant(liveRelease.id === baseline.baseline_release_id, "numeric baseline Release ID changed");
  invariant(
    JSON.stringify(canonicalReleaseClosure(liveRelease)) === JSON.stringify(baseline.baseline_release_closure),
    "numeric baseline Release closure changed after capture",
  );
  invariant(
    liveTag.object?.type === "commit" && liveTag.object.sha === baseline.baseline_commit,
    "baseline tag commit changed after capture",
  );
  if (baseline.legacy_bootstrap_exception === true) {
    invariant(
      baseline.target_version === "0.1.6" &&
        baseline.baseline_version === "0.1.5" &&
        baseline.baseline_release_id === 378428394 &&
        baseline.baseline_commit === "c27d6b30824efdf2db0606e76e4faae71ba27695" &&
        baseline.baseline_release_closure_sha256 === LEGACY_BASELINE_CLOSURE_SHA256 &&
        liveRelease.immutable === false,
      "legacy bootstrap is not the one permanently pinned 0.1.5 -> 0.1.6 exception",
    );
  } else {
    invariant(liveRelease.immutable === true, "normal updater baseline is not immutable");
  }
}

class GitHubApi {
  constructor(repository, token) {
    invariant(repository === EXPECTED_REPOSITORY, "Release repository is not the production repository");
    invariant(typeof token === "string" && token.length > 0, "GITHUB_TOKEN is required");
    this.repository = repository;
    this.token = token;
  }

  async request(route, { method = "GET", body = null, upload = false, contentType = "application/json" } = {}) {
    const origin = upload ? "https://uploads.github.com" : "https://api.github.com";
    const response = await globalThis.fetch(`${origin}${route}`, {
      method,
      redirect: "error",
      signal: globalThis.AbortSignal.timeout(60_000),
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.token}`,
        "content-type": contentType,
        "user-agent": "openaria-desktop-release-commit-point",
        "x-github-api-version": "2022-11-28",
      },
      body:
        body === null || body === undefined
          ? undefined
          : contentType === "application/json"
            ? JSON.stringify(body)
            : body,
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (!response.ok) {
      throw new Error(`${method} ${route} returned HTTP ${response.status}: ${bytes.toString("utf8").slice(0, 1000)}`);
    }
    if (response.status === 204 || bytes.length === 0) return null;
    return JSON.parse(bytes.toString("utf8"));
  }

  async optional(route) {
    try {
      return await this.request(route);
    } catch (error) {
      if (error instanceof Error && error.message.includes("returned HTTP 404:")) return null;
      throw error;
    }
  }

  async allReleases() {
    const releases = [];
    for (let page = 1; page <= 20; page += 1) {
      const values = await this.request(`/repos/${this.repository}/releases?per_page=100&page=${page}`);
      invariant(Array.isArray(values), "GitHub Releases response is not an array");
      releases.push(...values);
      if (values.length < 100) return releases;
    }
    throw new Error("GitHub Release history exceeded the closed pagination bound");
  }
}

async function liveBaseline(api, baseline) {
  const repository = api.repository;
  const [latest, liveRelease, liveTag] = await Promise.all([
    api.request(`/repos/${repository}/releases/latest`),
    api.request(`/repos/${repository}/releases/${baseline.baseline_release_id}`),
    api.request(`/repos/${repository}/git/ref/tags/${baseline.baseline_version}`),
  ]);
  validateBaselineState({ baseline, latest, liveRelease, liveTag });
  return { latest, liveRelease, liveTag };
}

function validateDraft(release, { version, releaseId = null, ownershipMarker = null }) {
  invariant(Number.isSafeInteger(release.id) && release.id > 0, "draft numeric Release ID is invalid");
  if (releaseId !== null) invariant(release.id === releaseId, "draft numeric Release ID changed");
  invariant(release.tag_name === version, "draft Release tag changed");
  invariant(release.draft === true && release.prerelease === false, "candidate is not a stable never-public draft");
  invariant(release.published_at === null, "candidate draft was previously public");
  if (ownershipMarker !== null) {
    invariant(
      typeof release.body === "string" && release.body.includes(ownershipMarker),
      "never-public draft ownership marker changed",
    );
  }
  return release;
}

async function prepareDraft(values) {
  const repository = required(values, "repository");
  const version = numericVersion(required(values, "version"), "candidate version");
  const commit = required(values, "commit");
  invariant(GIT_COMMIT.test(commit), "candidate source commit is invalid");
  const runId = required(values, "run-id");
  const runAttempt = required(values, "run-attempt");
  validateReleaseRunIdentity(runId, runAttempt);
  const assetRoot = path.resolve(required(values, "assets"));
  const outputRoot = path.resolve(required(values, "output"));
  const baseline = json(path.resolve(required(values, "baseline")), "captured baseline");
  const preflight = validateDispatchPreflight(json(path.resolve(required(values, "preflight")), "dispatch preflight"), {
    repository,
    version,
    commit,
    runId,
    runAttempt,
  });
  invariant(baseline.target_version === version, "baseline target differs from candidate version");
  invariant(
    JSON.stringify(baseline.dispatch_preflight) === JSON.stringify(preflight),
    "baseline preflight binding changed",
  );
  const assets = localAssets(assetRoot, version);
  const api = new GitHubApi(repository, process.env.GITHUB_TOKEN);
  const ownershipMarker = draftOwnershipMarker(repository, version, commit, runId, runAttempt);
  await liveBaseline(api, baseline);

  const [releases, existingTag] = await Promise.all([
    api.allReleases(),
    api.optional(`/repos/${repository}/git/ref/tags/${version}`),
  ]);
  validateCandidateStartState({ releases, tag: existingTag, version });

  const draft = await api.request(`/repos/${repository}/releases`, {
    method: "POST",
    body: {
      tag_name: version,
      target_commitish: commit,
      name: `Release ${version}`,
      body: ownershipMarker,
      draft: true,
      prerelease: false,
      generate_release_notes: true,
    },
  });
  validateDraft(draft, { version, ownershipMarker });
  const releaseId = draft.id;

  for (const asset of assets) {
    validateDraft(await api.request(`/repos/${repository}/releases/${releaseId}`), {
      version,
      releaseId,
      ownershipMarker,
    });
    await api.request(`/repos/${repository}/releases/${releaseId}/assets?name=${encodeURIComponent(asset.name)}`, {
      method: "POST",
      body: readFileSync(asset.file),
      upload: true,
      contentType: "application/octet-stream",
    });
  }
  await liveBaseline(api, baseline);
  const owned = validateDraft(await api.request(`/repos/${repository}/releases/${releaseId}`), {
    version,
    releaseId,
    ownershipMarker,
  });
  const remoteAssets = canonicalAssets(owned);
  invariant(remoteAssets.length === EXPECTED_ASSET_COUNT, "draft does not expose the exact six-asset closure");
  for (const asset of assets) {
    const remote = remoteAssets.find((candidate) => candidate.name === asset.name);
    invariant(remote !== undefined, `draft lacks ${asset.name}`);
    invariant(remote.size === asset.size && remote.digest === asset.digest, `draft ${asset.name} bytes changed`);
    validateReleaseAssetUrl(remote.browser_download_url, {
      repository,
      version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  const targetTagAfterDraft = observedTargetTag(
    await api.optional(`/repos/${repository}/git/ref/tags/${version}`),
    commit,
  );

  mkdirSync(outputRoot, { recursive: true });
  for (const asset of assets) copyFileSync(asset.file, path.join(outputRoot, asset.name));
  writeFileSync(path.join(outputRoot, "candidate-release-metadata.json"), `${JSON.stringify(owned, null, 2)}\n`);
  const ownership = {
    schema: "openaria.desktop.release-ownership.v2",
    repository,
    run_id: runId,
    run_attempt: runAttempt,
    target_version: version,
    target_commit: commit,
    release_id: releaseId,
    draft_created_by_run: true,
    draft_never_public: true,
    candidate_start: { exact_release_absent: true, exact_tag_absent: true },
    draft_ownership_marker: ownershipMarker,
    published_at: null,
    assets: remoteAssets,
    target_tag_after_draft: targetTagAfterDraft,
    baseline: {
      version: baseline.baseline_version,
      commit: baseline.baseline_commit,
      release_id: baseline.baseline_release_id,
      immutable: baseline.baseline_release_immutable,
      closure: baseline.baseline_release_closure,
      legacy_bootstrap_exception: baseline.legacy_bootstrap_exception,
    },
    dispatch_preflight: preflight,
    prepared_at: new Date().toISOString(),
  };
  writeFileSync(path.join(outputRoot, "release-ownership.json"), `${JSON.stringify(ownership, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ release_id: releaseId, draft_created_by_run: true })}\n`);
}

export function validateAcceptance(receipt, ownership, requestLogBytes) {
  invariant(
    receipt?.schema === "openaria.windows-updater-acceptance.v1",
    "Windows updater acceptance schema is invalid",
  );
  invariant(receipt.status === "passed", "Windows updater acceptance did not pass");
  invariant(receipt.repository === ownership.repository, "acceptance repository changed");
  invariant(
    receipt.run_id === ownership.run_id && receipt.run_attempt === ownership.run_attempt,
    "acceptance run identity changed",
  );
  invariant(receipt.to_version === ownership.target_version, "acceptance target version changed");
  invariant(receipt.candidate_release_id === ownership.release_id, "acceptance candidate numeric ID changed");
  invariant(receipt.candidate_commit === ownership.target_commit, "acceptance candidate commit changed");
  invariant(
    JSON.stringify(receipt.dispatch_preflight) === JSON.stringify(ownership.dispatch_preflight),
    "acceptance dispatch preflight binding changed",
  );
  invariant(
    receipt.baseline?.baseline_release_id === ownership.baseline.release_id &&
      receipt.baseline?.baseline_commit === ownership.baseline.commit &&
      JSON.stringify(receipt.baseline?.baseline_release_closure) === JSON.stringify(ownership.baseline.closure),
    "acceptance baseline identity or asset closure changed",
  );
  invariant(
    receipt.candidate?.release_id === ownership.release_id &&
      receipt.candidate?.target_commit === ownership.target_commit,
    "acceptance candidate identity changed",
  );
  const acceptanceAssets = receipt.candidate?.assets;
  for (const asset of ownership.assets ?? []) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: ownership.repository,
      version: ownership.target_version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  for (const asset of acceptanceAssets ?? []) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: ownership.repository,
      version: ownership.target_version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  invariant(
    JSON.stringify(normalizedAssetPins(acceptanceAssets)) === JSON.stringify(normalizedAssetPins(ownership.assets)),
    "acceptance candidate asset pins changed",
  );
  invariant(receipt.browser_or_manual_download_used === false, "acceptance used a browser or manual download");
  invariant(receipt.target_installer_downloaded_by_harness === false, "acceptance harness downloaded the installer");
  invariant(
    receipt.target_installer_served_only_to_production_updater === true &&
      receipt.controlled_server_request_proof?.complete_installer_response === true &&
      receipt.controlled_server_request_proof?.manifest_requests >= 2 &&
      receipt.controlled_server_request_proof?.installer_requests >= 1,
    "acceptance lacks production updater controlled-server proof",
  );

  const logBinding = receipt.controlled_server_request_proof.request_log;
  invariant(
    logBinding?.file === "controlled-update-server-log.json" &&
      logBinding.bytes === requestLogBytes.length &&
      logBinding.sha256 === sha256(requestLogBytes),
    "acceptance request log exact-byte binding changed",
  );
  let requestLog;
  try {
    requestLog = JSON.parse(requestLogBytes.toString("utf8"));
  } catch (error) {
    throw new Error(
      `acceptance request log is invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  invariant(
    requestLog?.schema === "openaria.desktop.controlled-update-server-log.v1" &&
      requestLog.host === "github.com" &&
      requestLog.repository === ownership.repository &&
      requestLog.version === ownership.target_version &&
      Array.isArray(requestLog.requests),
    "acceptance request log identity changed",
  );
  invariant(
    requestLog.requests.every((request) => request.kind !== "rejected"),
    "acceptance request log contains a non-closed request",
  );
  const latestAsset = ownership.assets.find((asset) => asset.name === "latest.json");
  const setupAsset = ownership.assets.find((asset) => asset.name.endsWith("_windows_x86_64-setup.exe"));
  invariant(latestAsset !== undefined && setupAsset !== undefined, "acceptance ownership lacks updater assets");
  const manifestRequests = requestLog.requests.filter(
    (request) => request.kind === "manifest" && request.status === 200,
  );
  const installerRequests = requestLog.requests.filter(
    (request) => request.kind === "installer" && [200, 206].includes(request.status),
  );
  const manifestPath = `/${ownership.repository}/releases/latest/download/latest.json`;
  const installerPath = `/${ownership.repository}/releases/download/${ownership.target_version}/${setupAsset.name}`;
  invariant(
    requestLog.requests.length === receipt.controlled_server_request_proof.total_requests &&
      manifestRequests.length === receipt.controlled_server_request_proof.manifest_requests &&
      installerRequests.length === receipt.controlled_server_request_proof.installer_requests,
    "acceptance request log counts differ from the receipt",
  );
  invariant(
    manifestRequests.length >= 2 &&
      manifestRequests.every(
        (request) =>
          request.method === "GET" &&
          request.url === manifestPath &&
          request.source_bytes === latestAsset.size &&
          `sha256:${request.source_sha256}` === latestAsset.digest,
      ),
    "acceptance request log does not bind the exact candidate manifest",
  );
  invariant(
    installerRequests.length >= 1 &&
      installerRequests.every(
        (request) =>
          request.method === "GET" &&
          request.url === installerPath &&
          request.source_bytes === setupAsset.size &&
          `sha256:${request.source_sha256}` === setupAsset.digest,
      ) &&
      installerRequests.some((request) => request.status === 200 && request.response_bytes === setupAsset.size),
    "acceptance request log does not bind a complete exact candidate installer response",
  );
  invariant(
    receipt.events.some((event) => event.kind === "target_version_observed_in_relaunched_application_ui"),
    "acceptance lacks relaunched target UI identity",
  );
  return receipt;
}

async function verifyPublishState(api, ownership) {
  const repository = ownership.repository;
  const release = await api.request(`/repos/${repository}/releases/${ownership.release_id}`);
  const latest = await api.request(`/repos/${repository}/releases/latest`);
  const tag = await api.request(`/repos/${repository}/git/ref/tags/${ownership.target_version}`);
  invariant(
    release.id === ownership.release_id && release.tag_name === ownership.target_version,
    "published numeric Release identity changed",
  );
  invariant(release.draft === false && release.prerelease === false, "published Release state is invalid");
  invariant(release.immutable === true, "published Release is not immutable");
  invariant(typeof release.published_at === "string", "published Release has no timestamp");
  invariant(
    latest.id === ownership.release_id && latest.tag_name === ownership.target_version,
    "published Release is not latest",
  );
  invariant(
    tag.object?.type === "commit" && tag.object.sha === ownership.target_commit,
    "published tag commit changed",
  );
  const publishedAssets = canonicalAssets(release);
  for (const asset of publishedAssets) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository,
      version: ownership.target_version,
      name: asset.name,
      expectedDraft: false,
    });
  }
  invariant(
    JSON.stringify(normalizedAssetPins(publishedAssets)) === JSON.stringify(normalizedAssetPins(ownership.assets)),
    "published asset pins differ from ownership",
  );
  return { release, latest, tag };
}

async function publish(values) {
  const ownershipFile = path.resolve(required(values, "ownership"));
  const ownership = json(ownershipFile, "Release ownership receipt");
  invariant(ownership?.schema === "openaria.desktop.release-ownership.v2", "Release ownership schema is invalid");
  invariant(ownership.repository === EXPECTED_REPOSITORY, "Release ownership repository changed");
  invariant(
    ownership.draft_ownership_marker ===
      draftOwnershipMarker(
        ownership.repository,
        ownership.target_version,
        ownership.target_commit,
        ownership.run_id,
        ownership.run_attempt,
      ),
    "Release ownership draft marker is invalid",
  );
  const runId = required(values, "run-id");
  const runAttempt = required(values, "run-attempt");
  validateReleaseRunIdentity(runId, runAttempt);
  invariant(ownership.run_id === runId && ownership.run_attempt === runAttempt, "publication run identity changed");
  const requestLogBytes = readFileSync(path.resolve(required(values, "request-log")));
  const acceptance = validateAcceptance(
    json(path.resolve(required(values, "acceptance")), "Windows updater acceptance receipt"),
    ownership,
    requestLogBytes,
  );
  const outputRoot = path.resolve(required(values, "output"));
  mkdirSync(outputRoot, { recursive: true });
  const api = new GitHubApi(ownership.repository, process.env.GITHUB_TOKEN);

  const baseline = {
    target_version: ownership.target_version,
    baseline_version: ownership.baseline.version,
    baseline_commit: ownership.baseline.commit,
    baseline_release_id: ownership.baseline.release_id,
    baseline_release_immutable: ownership.baseline.immutable,
    baseline_release_closure: ownership.baseline.closure,
    baseline_release_closure_sha256: ownership.dispatch_preflight.allow_legacy_baseline_bootstrap
      ? LEGACY_BASELINE_CLOSURE_SHA256
      : sha256(Buffer.from(JSON.stringify(ownership.baseline.closure))),
    legacy_bootstrap_exception: ownership.baseline.legacy_bootstrap_exception,
  };
  await liveBaseline(api, baseline);
  const before = validateDraft(await api.request(`/repos/${ownership.repository}/releases/${ownership.release_id}`), {
    version: ownership.target_version,
    releaseId: ownership.release_id,
    ownershipMarker: ownership.draft_ownership_marker,
  });
  const draftAssets = canonicalAssets(before);
  for (const asset of draftAssets) {
    validateReleaseAssetUrl(asset.browser_download_url, {
      repository: ownership.repository,
      version: ownership.target_version,
      name: asset.name,
      expectedDraft: true,
    });
  }
  invariant(
    JSON.stringify(normalizedAssetPins(draftAssets)) === JSON.stringify(normalizedAssetPins(ownership.assets)),
    "candidate asset pins changed after acceptance",
  );
  const targetTagBeforePublish = observedTargetTag(
    await api.optional(`/repos/${ownership.repository}/git/ref/tags/${ownership.target_version}`),
    ownership.target_commit,
  );
  invariant(
    JSON.stringify(targetTagBeforePublish) === JSON.stringify(ownership.target_tag_after_draft),
    "candidate tag state changed after numeric draft creation",
  );

  // The only irreversible publication mutation: address the already-owned
  // never-public draft by numeric Release ID. No tag-based edit or rollback is
  // authorized after this request.
  let publicationResponseObserved = true;
  let ambiguousPublicationError = null;
  try {
    await api.request(`/repos/${ownership.repository}/releases/${ownership.release_id}`, {
      method: "PATCH",
      body: { draft: false, prerelease: false, make_latest: "true" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("returned HTTP")) throw error;
    publicationResponseObserved = false;
    ambiguousPublicationError = message;
  }

  let verified;
  let lastError;
  for (let attempt = 1; attempt <= POSTVERIFY_ATTEMPTS; attempt += 1) {
    try {
      verified = await verifyPublishState(api, ownership);
      break;
    } catch (error) {
      lastError = error;
      if (attempt < POSTVERIFY_ATTEMPTS) await delay(Math.min(attempt * 3_000, 30_000));
    }
  }
  if (verified === undefined) throw lastError;
  const receipt = {
    schema: "openaria.desktop.release-publication.v2",
    repository: ownership.repository,
    run_id: runId,
    run_attempt: runAttempt,
    release_id: ownership.release_id,
    target_version: ownership.target_version,
    target_commit: ownership.target_commit,
    published_at: verified.release.published_at,
    immutable: true,
    latest: true,
    assets: canonicalAssets(verified.release),
    irreversible_action: {
      method: "PATCH",
      numeric_release_id: ownership.release_id,
      body: { draft: false, prerelease: false, make_latest: "true" },
      response_observed: publicationResponseObserved,
      ambiguous_response_error: ambiguousPublicationError,
      mutation_retried: false,
    },
    acceptance: {
      status: acceptance.status,
      candidate_release_id: acceptance.candidate_release_id,
      finished_at: acceptance.finished_at,
      controlled_server_request_proof: acceptance.controlled_server_request_proof,
    },
    verified_at: new Date().toISOString(),
  };
  writeFileSync(path.join(outputRoot, "release-publication.json"), `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
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

async function main(argv) {
  const [command, ...rest] = argv;
  const values = options(rest);
  if (command === "prepare-draft") return prepareDraft(values);
  if (command === "publish") return publish(values);
  throw new Error(`unknown command ${JSON.stringify(command)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  });
}
