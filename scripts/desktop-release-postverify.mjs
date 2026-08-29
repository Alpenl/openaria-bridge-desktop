import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { verifyPublishedRelease } from "./desktop-release-contract.mjs";
import { validateAcceptance } from "./desktop-release-commit-point.mjs";

const EXPECTED_REPOSITORY = "Alpenl/openaria-bridge-desktop";
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const NUMERIC = /^[1-9]\d*$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function json(file, label) {
  let value;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error.message}`);
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function exactPositiveInteger(value, label) {
  invariant(typeof value === "string" && NUMERIC.test(value), `${label} must be a positive decimal integer`);
  const number = Number(value);
  invariant(Number.isSafeInteger(number), `${label} exceeds the safe integer range`);
  return number;
}

function canonicalAssets(release) {
  invariant(Array.isArray(release?.assets), "published Release assets must be an array");
  return release.assets
    .map(({ browser_download_url, digest, name, size }) => ({ browser_download_url, digest, name, size }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

function normalizedAssetPins(assets) {
  invariant(Array.isArray(assets), "asset pins must be an array");
  return assets
    .map(({ digest, name, size }) => ({ digest, name, size }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

function canonicalRelease(release) {
  return {
    assets: canonicalAssets(release),
    draft: release.draft,
    id: release.id,
    immutable: release.immutable,
    prerelease: release.prerelease,
    published_at: release.published_at,
    tag_name: release.tag_name,
    target_commitish: release.target_commitish,
  };
}

function canonicalArtifact(artifact) {
  return {
    created_at: artifact.created_at,
    digest: artifact.digest,
    expired: artifact.expired,
    id: artifact.id,
    name: artifact.name,
    size_in_bytes: artifact.size_in_bytes,
    workflow_run: {
      head_branch: artifact.workflow_run?.head_branch,
      head_repository_id: artifact.workflow_run?.head_repository_id,
      head_sha: artifact.workflow_run?.head_sha,
      id: artifact.workflow_run?.id,
      repository_id: artifact.workflow_run?.repository_id,
    },
  };
}

function canonicalJob(job) {
  return {
    completed_at: job.completed_at,
    conclusion: job.conclusion,
    head_sha: job.head_sha,
    id: job.id,
    name: job.name,
    run_attempt: job.run_attempt,
    run_id: job.run_id,
    status: job.status,
    started_at: job.started_at,
    steps: job.steps.map(({ completed_at, conclusion, name, number, started_at, status }) => ({
      completed_at,
      conclusion,
      name,
      number,
      started_at,
      status,
    })),
  };
}

export function canonicalPostverifySnapshot(snapshot) {
  return {
    artifacts: snapshot.artifacts.map(canonicalArtifact).sort((left, right) => left.id - right.id),
    artifacts_total_count: snapshot.artifacts_total_count,
    default_branch_head: snapshot.default_branch_head.sha,
    jobs: snapshot.jobs.map(canonicalJob).sort((left, right) => left.id - right.id),
    jobs_total_count: snapshot.jobs_total_count,
    latest: canonicalRelease(snapshot.latest),
    release_by_id: canonicalRelease(snapshot.release_by_id),
    release_by_tag: canonicalRelease(snapshot.release_by_tag),
    repository: {
      default_branch: snapshot.repository.default_branch,
      full_name: snapshot.repository.full_name,
      id: snapshot.repository.id,
      owner: snapshot.repository.owner?.login,
    },
    run: {
      actor: snapshot.run.actor?.login,
      conclusion: snapshot.run.conclusion,
      event: snapshot.run.event,
      head_branch: snapshot.run.head_branch,
      head_repository: snapshot.run.head_repository?.full_name,
      head_sha: snapshot.run.head_sha,
      id: snapshot.run.id,
      name: snapshot.run.name,
      path: snapshot.run.path,
      created_at: snapshot.run.created_at,
      run_attempt: snapshot.run.run_attempt,
      status: snapshot.run.status,
      triggering_actor: snapshot.run.triggering_actor?.login,
    },
    selected_artifacts: Object.fromEntries(
      Object.entries(snapshot.selected_artifacts)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, artifact]) => [name, canonicalArtifact(artifact)]),
    ),
    tag_ref: {
      object: snapshot.tag_ref.object,
      ref: snapshot.tag_ref.ref,
    },
  };
}

function uniqueNamed(values, name, label) {
  const matches = values.filter((value) => value.name === name);
  invariant(matches.length === 1, `expected exactly one ${label} ${name}; found ${matches.length}`);
  return matches[0];
}

function timestamp(value, label) {
  const parsed = Date.parse(value);
  invariant(Number.isFinite(parsed), `${label} timestamp is invalid`);
  return parsed;
}

function requireStep(job, name, number, conclusion) {
  const step = uniqueNamed(job.steps, name, `${job.name} step`);
  invariant(step.number === number, `${job.name} step ${name} number changed`);
  invariant(step.status === "completed" && step.conclusion === conclusion, `${job.name} step ${name} state changed`);
  invariant(
    timestamp(step.started_at, `${name} start`) <= timestamp(step.completed_at, `${name} completion`),
    `${job.name} step ${name} time window is invalid`,
  );
  return step;
}

function assertOrderedSteps(left, right, label) {
  invariant(
    timestamp(left.completed_at, `${left.name} completion`) <= timestamp(right.started_at, `${right.name} start`),
    `${label} step order changed`,
  );
}

function assertArtifactCreatedDuring(artifact, step, label) {
  const createdAt = timestamp(artifact.created_at, `${label} artifact creation`);
  invariant(
    createdAt >= timestamp(step.started_at, `${step.name} start`) &&
      createdAt <= timestamp(step.completed_at, `${step.name} completion`),
    `${label} artifact was not created during its upload step`,
  );
}

export function validatePostverifySnapshot(snapshot, expected) {
  const owner = expected.repository.split("/", 1)[0];
  invariant(snapshot.repository.full_name === expected.repository, "repository identity changed");
  invariant(snapshot.repository.owner?.login === owner, "repository owner identity changed");
  invariant(typeof snapshot.repository.default_branch === "string", "repository default branch is invalid");
  invariant(
    snapshot.default_branch_head.sha === expected.verifier_commit,
    "verifier is not the current default-branch HEAD",
  );

  const run = snapshot.run;
  invariant(run.id === expected.source_run_id, "source run ID changed");
  invariant(run.run_attempt === expected.source_run_attempt, "source run attempt changed");
  invariant(run.event === "workflow_dispatch", "source run was not workflow_dispatch");
  invariant(
    run.status === "completed" && run.conclusion === "failure",
    "source run must be completed with only postverify failure",
  );
  invariant(run.name === "CI / Release" && run.path === ".github/workflows/ci.yml", "source workflow identity changed");
  invariant(run.head_branch === snapshot.repository.default_branch, "source run was not on the default branch");
  invariant(run.head_sha === expected.source_commit, "source run commit changed");
  invariant(run.head_repository?.full_name === expected.repository, "source run head repository changed");
  invariant(
    run.actor?.login === owner && run.triggering_actor?.login === owner,
    "source run actor was not the repository owner",
  );

  invariant(snapshot.jobs_total_count === snapshot.jobs.length, "source attempt jobs require pagination");
  for (const job of snapshot.jobs) {
    invariant(job.run_id === expected.source_run_id, `${job.name} run ID changed`);
    invariant(job.run_attempt === expected.source_run_attempt, `${job.name} run attempt changed`);
    invariant(job.head_sha === expected.source_commit, `${job.name} source commit changed`);
    invariant(job.status === "completed", `${job.name} is not complete`);
  }
  const failedJobs = snapshot.jobs.filter((job) => job.conclusion !== "success");
  const publication = uniqueNamed(
    snapshot.jobs,
    "irreversible numeric publication and read-only verification",
    "source job",
  );
  invariant(
    failedJobs.length === 1 && failedJobs[0].id === publication.id,
    "a source job other than postverify failed",
  );
  invariant(
    publication.conclusion === "failure",
    "source publication job did not preserve the expected red postverify",
  );
  const publicationCandidate = requireStep(publication, "Download the exact never-public candidate", 4, "success");
  const publicationAcceptance = requireStep(
    publication,
    "Download the passed pre-publish updater receipt",
    5,
    "success",
  );
  const publishStep = requireStep(publication, "Publish the accepted draft by numeric Release ID", 6, "success");
  const postverifyTools = requireStep(
    publication,
    "Download and verify pinned minisign for read-only postverify",
    7,
    "success",
  );
  const failedStep = requireStep(publication, "Read-only anonymous exact-byte postverification", 8, "failure");
  const publicationUpload = requireStep(
    publication,
    "Upload immutable publication and anonymous byte evidence",
    9,
    "success",
  );
  const nonSuccessSteps = publication.steps.filter((step) => step.conclusion !== "success");
  const skippedPostSetup = uniqueNamed(
    nonSuccessSteps,
    "Post Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
    "automatically generated publication post-step",
  );
  invariant(
    nonSuccessSteps.length === 2 &&
      nonSuccessSteps.includes(failedStep) &&
      skippedPostSetup.number === 17 &&
      skippedPostSetup.status === "completed" &&
      skippedPostSetup.conclusion === "skipped",
    "source publication non-success step closure changed",
  );

  const prepare = uniqueNamed(snapshot.jobs, "resolve and validate build metadata", "source job");
  const metadataStep = requireStep(prepare, "Resolve build metadata from the application config", 4, "success");
  const preflightUpload = requireStep(prepare, "Upload exact Release dispatch preflight evidence", 5, "success");
  const draft = uniqueNamed(snapshot.jobs, "prepare exact never-public Windows draft", "source job");
  const draftPrepare = requireStep(draft, "Prepare a fresh numeric never-public draft", 10, "success");
  const draftUpload = requireStep(draft, "Upload exact candidate bytes and numeric ownership receipt", 11, "success");
  const acceptance = uniqueNamed(snapshot.jobs, "pre-publish real Windows in-app updater acceptance", "source job");
  const acceptanceRun = requireStep(
    acceptance,
    "Install unchanged public baseline and update through its production updater",
    6,
    "success",
  );
  const acceptanceUpload = requireStep(acceptance, "Upload pre-publish updater lifecycle evidence", 7, "success");
  for (const [left, right, label] of [
    [metadataStep, preflightUpload, "dispatch preflight"],
    [draftPrepare, draftUpload, "candidate ownership"],
    [draftUpload, acceptanceRun, "ownership to updater acceptance"],
    [acceptanceRun, acceptanceUpload, "updater acceptance evidence"],
    [acceptanceUpload, publicationCandidate, "acceptance to publication"],
    [publicationCandidate, publicationAcceptance, "publication evidence downloads"],
    [publicationAcceptance, publishStep, "evidence-bound publish"],
    [publishStep, postverifyTools, "publish to postverify tools"],
    [postverifyTools, failedStep, "postverify tool to byte verification"],
    [failedStep, publicationUpload, "failed postverify evidence upload"],
  ]) {
    assertOrderedSteps(left, right, label);
  }

  invariant(snapshot.artifacts_total_count === snapshot.artifacts.length, "source artifacts require pagination");
  for (const [kind, id] of [
    ["preflight", expected.preflight_artifact_id],
    ["candidate", expected.candidate_artifact_id],
    ["acceptance", expected.acceptance_artifact_id],
    ["publication", expected.publication_artifact_id],
  ]) {
    const artifact = snapshot.selected_artifacts[kind];
    invariant(artifact.id === id, `${kind} artifact ID changed`);
    invariant(artifact.expired === false, `${kind} artifact expired`);
    invariant(SHA256.test(artifact.digest?.replace(/^sha256:/, "") ?? ""), `${kind} artifact digest is invalid`);
    invariant(artifact.workflow_run?.id === expected.source_run_id, `${kind} artifact source run changed`);
    invariant(artifact.workflow_run?.head_sha === expected.source_commit, `${kind} artifact source commit changed`);
    const listed = snapshot.artifacts.filter((candidate) => candidate.id === id);
    invariant(listed.length === 1, `${kind} artifact is not unique in the source run`);
    invariant(
      JSON.stringify(canonicalArtifact(listed[0])) === JSON.stringify(canonicalArtifact(artifact)),
      `${kind} artifact latest and by-ID metadata differ`,
    );
  }
  invariant(
    snapshot.selected_artifacts.preflight.name ===
      `openaria-release-dispatch-preflight-${expected.version}-${expected.source_run_id}-${expected.source_run_attempt}`,
    "preflight artifact name changed",
  );
  invariant(
    snapshot.selected_artifacts.candidate.name ===
      `openaria-release-candidate-${expected.version}-${expected.source_run_id}-${expected.source_run_attempt}`,
    "candidate artifact name changed",
  );
  invariant(
    snapshot.selected_artifacts.acceptance.name ===
      `openaria-windows-updater-acceptance-${expected.version}-${expected.source_run_id}-${expected.source_run_attempt}`,
    "acceptance artifact name changed",
  );
  invariant(
    snapshot.selected_artifacts.publication.name ===
      `openaria-release-publication-${expected.version}-${expected.source_run_id}-${expected.source_run_attempt}`,
    "publication artifact name changed",
  );
  assertArtifactCreatedDuring(snapshot.selected_artifacts.preflight, preflightUpload, "preflight");
  assertArtifactCreatedDuring(snapshot.selected_artifacts.candidate, draftUpload, "candidate");
  assertArtifactCreatedDuring(snapshot.selected_artifacts.acceptance, acceptanceUpload, "acceptance");
  assertArtifactCreatedDuring(snapshot.selected_artifacts.publication, publicationUpload, "publication");

  for (const [label, release] of [
    ["numeric", snapshot.release_by_id],
    ["tag", snapshot.release_by_tag],
    ["latest", snapshot.latest],
  ]) {
    invariant(release.id === expected.release_id, `${label} Release ID changed`);
    invariant(release.tag_name === expected.version, `${label} Release tag changed`);
    invariant(release.target_commitish === expected.source_commit, `${label} Release commit changed`);
    invariant(release.draft === false && release.prerelease === false, `${label} Release state changed`);
    invariant(release.immutable === true, `${label} Release is not immutable`);
  }
  const releaseClosure = JSON.stringify(canonicalRelease(snapshot.release_by_id));
  invariant(
    releaseClosure === JSON.stringify(canonicalRelease(snapshot.release_by_tag)),
    "numeric and tag Release differ",
  );
  invariant(releaseClosure === JSON.stringify(canonicalRelease(snapshot.latest)), "numeric and latest Release differ");
  invariant(snapshot.tag_ref.ref === `refs/tags/${expected.version}`, "Release tag ref changed");
  invariant(
    snapshot.tag_ref.object?.type === "commit" && snapshot.tag_ref.object.sha === expected.source_commit,
    "Release tag no longer targets the source commit",
  );
  const publishedAt = timestamp(snapshot.release_by_id.published_at, "Release publication");
  invariant(
    publishedAt >= timestamp(publishStep.started_at, "publish step start") &&
      publishedAt <= timestamp(publishStep.completed_at, "publish step completion"),
    "Release published_at is outside the successful numeric publish step",
  );
  return { acceptance, draft, prepare, publication };
}

export function validateDownloadedSourceEvidence({
  preflightRoot,
  candidateRoot,
  acceptanceRoot,
  expected,
  release,
  run,
}) {
  const preflightReceiptFile = path.join(preflightRoot, "release-dispatch-preflight.json");
  const immutableSettingFile = path.join(preflightRoot, "immutable-release-setting.json");
  const ownershipFile = path.join(candidateRoot, "release-ownership.json");
  const acceptanceFile = path.join(acceptanceRoot, "windows-updater-acceptance.json");
  const requestLogFile = path.join(acceptanceRoot, "controlled-update-server-log.json");
  for (const [file, label] of [
    [preflightReceiptFile, "dispatch preflight receipt"],
    [immutableSettingFile, "immutable setting response"],
    [ownershipFile, "ownership receipt"],
    [acceptanceFile, "acceptance receipt"],
    [requestLogFile, "controlled updater request log"],
  ]) {
    const stat = lstatSync(file);
    invariant(stat.isFile() && !stat.isSymbolicLink(), `${label} is not a regular file`);
  }
  invariant(
    readdirSync(preflightRoot).sort().join("\n") ===
      ["immutable-release-setting.json", "release-dispatch-preflight.json"].join("\n"),
    "downloaded preflight artifact file closure changed",
  );
  const ownership = json(ownershipFile, "ownership receipt");
  invariant(ownership.schema === "openaria.desktop.release-ownership.v2", "ownership schema changed");
  invariant(ownership.repository === expected.repository, "ownership repository changed");
  invariant(ownership.run_id === String(expected.source_run_id), "ownership source run changed");
  invariant(ownership.run_attempt === String(expected.source_run_attempt), "ownership source attempt changed");
  invariant(ownership.target_version === expected.version, "ownership version changed");
  invariant(ownership.target_commit === expected.source_commit, "ownership source commit changed");
  invariant(ownership.release_id === expected.release_id, "ownership numeric Release ID changed");
  invariant(ownership.draft_never_public === true, "ownership was not for a never-public draft");
  const preflight = json(preflightReceiptFile, "dispatch preflight receipt");
  invariant(
    JSON.stringify(preflight) === JSON.stringify(ownership.dispatch_preflight),
    "ownership preflight receipt bytes changed",
  );
  invariant(preflight.schema === "openaria.desktop.release-dispatch-preflight.v1", "dispatch preflight schema changed");
  invariant(preflight.repository === expected.repository, "dispatch preflight repository changed");
  invariant(preflight.actor === expected.repository.split("/", 1)[0], "ownership actor changed");
  invariant(preflight.event === "workflow_dispatch", "dispatch preflight event changed");
  invariant(preflight.target_version === expected.version, "dispatch preflight target version changed");
  invariant(preflight.default_branch === "main", "ownership default branch changed");
  invariant(
    preflight.default_branch_head === expected.source_commit && preflight.source_commit === expected.source_commit,
    "ownership was not bound to the source default-branch HEAD",
  );
  invariant(
    preflight.run_id === String(expected.source_run_id) &&
      preflight.run_attempt === String(expected.source_run_attempt) &&
      preflight.run_created_at === run.created_at,
    "dispatch preflight source run identity changed",
  );
  invariant(
    preflight.allow_legacy_baseline_bootstrap === true && expected.version === "0.1.6",
    "0.1.6 bootstrap authority changed",
  );
  invariant(preflight.immutable_setting?.enabled === true, "immutable setting was not enabled before dispatch");
  invariant(
    preflight.immutable_setting?.checked_before_dispatch === true,
    "immutable setting was not checked before dispatch",
  );
  invariant(
    SHA256.test(preflight.immutable_setting?.raw_response_sha256 ?? ""),
    "immutable response digest is invalid",
  );
  const checkedAt = timestamp(preflight.immutable_setting.checked_at, "immutable setting check");
  const runCreatedAt = timestamp(run.created_at, "source run creation");
  const gapSeconds = Math.trunc((runCreatedAt - checkedAt) / 1000);
  invariant(
    gapSeconds >= -60 && gapSeconds <= 300 && gapSeconds === preflight.immutable_setting.dispatch_gap_seconds,
    "immutable setting preflight is outside the dispatch freshness window",
  );
  const immutableSettingBytes = readFileSync(immutableSettingFile);
  invariant(
    sha256(immutableSettingBytes) === preflight.immutable_setting.raw_response_sha256,
    "immutable setting raw response digest changed",
  );
  const immutableSetting = json(immutableSettingFile, "immutable setting response");
  invariant(
    JSON.stringify(Object.keys(immutableSetting).sort()) === JSON.stringify(["enabled", "enforced_by_owner"]) &&
      immutableSetting.enabled === true &&
      typeof immutableSetting.enforced_by_owner === "boolean",
    "immutable setting raw response schema or enabled state changed",
  );

  const expectedCandidateFiles = [
    ...ownership.assets.map((asset) => asset.name),
    "candidate-release-metadata.json",
    "release-ownership.json",
  ].sort();
  invariant(
    readdirSync(candidateRoot).sort().join("\n") === expectedCandidateFiles.join("\n"),
    "downloaded candidate artifact file closure changed",
  );
  for (const name of expectedCandidateFiles) {
    const stat = lstatSync(path.join(candidateRoot, name));
    invariant(stat.isFile() && !stat.isSymbolicLink(), `${name} is not a regular candidate evidence file`);
  }
  for (const asset of ownership.assets) {
    const file = path.join(candidateRoot, asset.name);
    const bytes = readFileSync(file);
    invariant(bytes.length === asset.size, `${asset.name} candidate size changed`);
    invariant(`sha256:${sha256(bytes)}` === asset.digest, `${asset.name} candidate digest changed`);
  }
  invariant(
    JSON.stringify(normalizedAssetPins(ownership.assets)) === JSON.stringify(normalizedAssetPins(release.assets)),
    "published Release bytes differ from the owned candidate",
  );

  const expectedAcceptanceFiles = [
    "01-bootstrap-update-dialog.png",
    "02-target-update-available.png",
    "03-updated-application.png",
    "04-updated-application-current.png",
    "controlled-update-server-log.json",
    "controlled-update-server-plan.json",
    "controlled-update-server-ready.json",
    "windows-hosts-override.json",
    "windows-updater-acceptance.json",
  ].sort();
  invariant(
    readdirSync(acceptanceRoot).sort().join("\n") === expectedAcceptanceFiles.join("\n"),
    "downloaded acceptance artifact file closure changed",
  );
  for (const name of expectedAcceptanceFiles) {
    const stat = lstatSync(path.join(acceptanceRoot, name));
    invariant(stat.isFile() && !stat.isSymbolicLink(), `${name} is not a regular acceptance evidence file`);
  }

  const acceptance = json(acceptanceFile, "acceptance receipt");
  const requestLogBytes = readFileSync(requestLogFile);
  validateAcceptance(acceptance, ownership, requestLogBytes);
  return {
    acceptance_receipt_sha256: sha256(readFileSync(acceptanceFile)),
    controlled_request_log_sha256: sha256(requestLogBytes),
    immutable_setting_raw_response_base64: immutableSettingBytes.toString("base64"),
    immutable_setting_raw_response_sha256: sha256(immutableSettingBytes),
    ownership,
    ownership_receipt_sha256: sha256(readFileSync(ownershipFile)),
  };
}

export function assertNoPostverifyToctou(before, after) {
  const beforeCanonical = canonicalPostverifySnapshot(before);
  const afterCanonical = canonicalPostverifySnapshot(after);
  const beforeBytes = Buffer.from(JSON.stringify(beforeCanonical));
  const afterBytes = Buffer.from(JSON.stringify(afterCanonical));
  invariant(beforeBytes.equals(afterBytes), "postverify remote state changed between initial and final reads");
  return sha256(beforeBytes);
}

class ReadOnlyGitHubApi {
  constructor(repository, token) {
    invariant(repository === EXPECTED_REPOSITORY, "postverify repository is not production");
    invariant(typeof token === "string" && token.length > 0, "GITHUB_TOKEN is required");
    this.repository = repository;
    this.token = token;
  }

  async get(route, label) {
    let lastError;
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      try {
        const response = await globalThis.fetch(`https://api.github.com${route}`, {
          method: "GET",
          redirect: "error",
          signal: globalThis.AbortSignal.timeout(60_000),
          headers: {
            accept: "application/vnd.github+json",
            authorization: `Bearer ${this.token}`,
            "user-agent": "openaria-desktop-read-only-postverify",
            "x-github-api-version": "2022-11-28",
          },
        });
        if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
        return await response.json();
      } catch (error) {
        lastError = error;
        if (attempt < 4) await delay(attempt * 2_000);
      }
    }
    throw lastError;
  }
}

async function readSnapshot(api, expected) {
  const prefix = `/repos/${expected.repository}`;
  const [repository, run, jobsPage, artifactsPage, releaseById, releaseByTag, latest, tagRef, ...selected] =
    await Promise.all([
      api.get(prefix, "repository metadata"),
      api.get(`${prefix}/actions/runs/${expected.source_run_id}`, "source run"),
      api.get(
        `${prefix}/actions/runs/${expected.source_run_id}/attempts/${expected.source_run_attempt}/jobs?per_page=100`,
        "source attempt jobs",
      ),
      api.get(`${prefix}/actions/runs/${expected.source_run_id}/artifacts?per_page=100`, "source artifacts"),
      api.get(`${prefix}/releases/${expected.release_id}`, "numeric Release"),
      api.get(`${prefix}/releases/tags/${encodeURIComponent(expected.version)}`, "tag Release"),
      api.get(`${prefix}/releases/latest`, "latest Release"),
      api.get(`${prefix}/git/ref/tags/${encodeURIComponent(expected.version)}`, "Release tag ref"),
      api.get(`${prefix}/actions/artifacts/${expected.preflight_artifact_id}`, "preflight artifact by ID"),
      api.get(`${prefix}/actions/artifacts/${expected.candidate_artifact_id}`, "candidate artifact by ID"),
      api.get(`${prefix}/actions/artifacts/${expected.acceptance_artifact_id}`, "acceptance artifact by ID"),
      api.get(`${prefix}/actions/artifacts/${expected.publication_artifact_id}`, "publication artifact by ID"),
    ]);
  const defaultBranchHead = await api.get(
    `${prefix}/commits/${encodeURIComponent(repository.default_branch)}`,
    "current default-branch HEAD",
  );
  return {
    artifacts: artifactsPage.artifacts,
    artifacts_total_count: artifactsPage.total_count,
    default_branch_head: defaultBranchHead,
    jobs: jobsPage.jobs,
    jobs_total_count: jobsPage.total_count,
    latest,
    release_by_id: releaseById,
    release_by_tag: releaseByTag,
    repository,
    run,
    selected_artifacts: {
      acceptance: selected[2],
      candidate: selected[1],
      preflight: selected[0],
      publication: selected[3],
    },
    tag_ref: tagRef,
  };
}

function validateVerifierContext(snapshot, expected) {
  invariant(process.env.GITHUB_EVENT_NAME === "workflow_dispatch", "postverify must run through workflow_dispatch");
  invariant(process.env.GITHUB_RUN_ATTEMPT === "1", "postverify workflow reruns are not accepted");
  invariant(
    process.env.GITHUB_ACTOR === expected.repository.split("/", 1)[0],
    "postverify actor is not repository owner",
  );
  invariant(
    process.env.GITHUB_REF === `refs/heads/${snapshot.repository.default_branch}`,
    "postverify workflow ref is not the default branch",
  );
  invariant(process.env.GITHUB_SHA === expected.verifier_commit, "postverify workflow commit changed");
}

async function verify(values) {
  const expected = {
    acceptance_artifact_id: exactPositiveInteger(required(values, "acceptance-artifact-id"), "acceptance artifact ID"),
    candidate_artifact_id: exactPositiveInteger(required(values, "candidate-artifact-id"), "candidate artifact ID"),
    publication_artifact_id: exactPositiveInteger(
      required(values, "publication-artifact-id"),
      "publication artifact ID",
    ),
    preflight_artifact_id: exactPositiveInteger(required(values, "preflight-artifact-id"), "preflight artifact ID"),
    release_id: exactPositiveInteger(required(values, "release-id"), "Release ID"),
    repository: required(values, "repository"),
    source_commit: required(values, "source-commit"),
    source_run_attempt: exactPositiveInteger(required(values, "source-run-attempt"), "source run attempt"),
    source_run_id: exactPositiveInteger(required(values, "source-run-id"), "source run ID"),
    verifier_commit: required(values, "verifier-commit"),
    version: required(values, "version"),
  };
  invariant(expected.repository === EXPECTED_REPOSITORY, "postverify repository is not production");
  invariant(COMMIT.test(expected.source_commit), "source commit is invalid");
  invariant(COMMIT.test(expected.verifier_commit), "verifier commit is invalid");
  invariant(SEMVER.test(expected.version), "Release version is invalid");
  const outputRoot = path.resolve(required(values, "output"));
  mkdirSync(outputRoot, { recursive: true });
  writeFileSync(
    path.join(outputRoot, "postverify-attempt.json"),
    `${JSON.stringify({ schema: "openaria.desktop.read-only-postverify-attempt.v1", expected }, null, 2)}\n`,
  );

  const api = new ReadOnlyGitHubApi(expected.repository, process.env.GITHUB_TOKEN);
  const before = await readSnapshot(api, expected);
  validatePostverifySnapshot(before, expected);
  validateVerifierContext(before, expected);
  const sourceEvidence = validateDownloadedSourceEvidence({
    preflightRoot: path.resolve(required(values, "preflight")),
    candidateRoot: path.resolve(required(values, "candidate")),
    acceptanceRoot: path.resolve(required(values, "acceptance")),
    expected,
    release: before.release_by_id,
    run: before.run,
  });
  const published = await verifyPublishedRelease({
    root: path.resolve(values.get("root") ?? "."),
    repository: expected.repository,
    version: expected.version,
    outputRoot,
    sevenZip: path.resolve(required(values, "seven-zip")),
  });
  invariant(published.release_id === expected.release_id, "anonymous verifier observed the wrong numeric Release");
  invariant(published.target_commit === expected.source_commit, "anonymous verifier observed the wrong source commit");
  const after = await readSnapshot(api, expected);
  validatePostverifySnapshot(after, expected);
  const remoteStateSha256 = assertNoPostverifyToctou(before, after);
  const receipt = {
    schema: "openaria.desktop.read-only-postverify.v1",
    repository: expected.repository,
    verifier: {
      actor: process.env.GITHUB_ACTOR,
      commit: expected.verifier_commit,
      event: process.env.GITHUB_EVENT_NAME,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT,
      run_id: process.env.GITHUB_RUN_ID,
    },
    source: expected,
    source_evidence: {
      acceptance_receipt_sha256: sourceEvidence.acceptance_receipt_sha256,
      controlled_request_log_sha256: sourceEvidence.controlled_request_log_sha256,
      immutable_setting_raw_response_base64: sourceEvidence.immutable_setting_raw_response_base64,
      immutable_setting_raw_response_sha256: sourceEvidence.immutable_setting_raw_response_sha256,
      ownership_receipt_sha256: sourceEvidence.ownership_receipt_sha256,
    },
    published_verification: published,
    initial_and_final_remote_state_sha256: remoteStateSha256,
    verified_at: new Date().toISOString(),
  };
  writeFileSync(path.join(outputRoot, "read-only-postverify.json"), `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...rest] = process.argv.slice(2);
  if (command !== "verify") {
    console.error(`unknown command ${JSON.stringify(command)}`);
    process.exitCode = 1;
  } else {
    verify(options(rest)).catch((error) => {
      console.error(error instanceof Error ? error.stack : error);
      process.exitCode = 1;
    });
  }
}
