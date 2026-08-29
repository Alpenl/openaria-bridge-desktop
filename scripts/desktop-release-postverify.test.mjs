import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

import {
  assertNoPostverifyToctou,
  canonicalPostverifySnapshot,
  validatePostverifySnapshot,
} from "./desktop-release-postverify.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const EXPECTED = {
  acceptance_artifact_id: 9716450265,
  candidate_artifact_id: 9716434253,
  publication_artifact_id: 9716456600,
  preflight_artifact_id: 9716255532,
  release_id: 379011766,
  repository: "Alpenl/openaria-bridge-desktop",
  source_commit: "ab579abb92a03c1b8d3da7b3752fdfdf63051e1b",
  source_run_attempt: 1,
  source_run_id: 33257516567,
  verifier_commit: "c".repeat(40),
  version: "0.1.6",
};

function artifact(id, kind) {
  const names = {
    acceptance: "openaria-windows-updater-acceptance",
    candidate: "openaria-release-candidate",
    preflight: "openaria-release-dispatch-preflight",
    publication: "openaria-release-publication",
  };
  const digestCharacters = { acceptance: "a", candidate: "c", preflight: "e", publication: "b" };
  const createdAt = {
    acceptance: "2026-08-29T14:21:10Z",
    candidate: "2026-08-29T14:11:10Z",
    preflight: "2026-08-29T14:01:10Z",
    publication: "2026-08-29T14:35:10Z",
  };
  return {
    id,
    name: `${names[kind]}-${EXPECTED.version}-${EXPECTED.source_run_id}-${EXPECTED.source_run_attempt}`,
    size_in_bytes: 1234,
    digest: `sha256:${digestCharacters[kind].repeat(64)}`,
    expired: false,
    created_at: createdAt[kind],
    workflow_run: {
      id: EXPECTED.source_run_id,
      repository_id: 10,
      head_repository_id: 10,
      head_branch: "main",
      head_sha: EXPECTED.source_commit,
    },
  };
}

function job(id, name, conclusion, steps) {
  const base = Date.parse("2026-08-29T13:50:00Z") + id * 10 * 60_000;
  return {
    id,
    run_id: EXPECTED.source_run_id,
    run_attempt: EXPECTED.source_run_attempt,
    head_sha: EXPECTED.source_commit,
    name,
    status: "completed",
    conclusion,
    started_at: new Date(base).toISOString(),
    completed_at: new Date(base + steps.length * 60_000).toISOString(),
    steps: steps.map(([stepName, stepConclusion, number], index) => ({
      name: stepName,
      number,
      status: "completed",
      conclusion: stepConclusion,
      started_at: new Date(base + index * 60_000).toISOString(),
      completed_at: new Date(base + index * 60_000 + 30_000).toISOString(),
    })),
  };
}

function release() {
  return {
    id: EXPECTED.release_id,
    tag_name: EXPECTED.version,
    target_commitish: EXPECTED.source_commit,
    draft: false,
    prerelease: false,
    immutable: true,
    published_at: "2026-08-29T14:32:10Z",
    assets: [
      {
        name: "latest.json",
        size: 742,
        digest: `sha256:${"d".repeat(64)}`,
        browser_download_url: `https://github.com/${EXPECTED.repository}/releases/download/${EXPECTED.version}/latest.json`,
      },
    ],
  };
}

function snapshot() {
  const selected = {
    acceptance: artifact(EXPECTED.acceptance_artifact_id, "acceptance"),
    candidate: artifact(EXPECTED.candidate_artifact_id, "candidate"),
    preflight: artifact(EXPECTED.preflight_artifact_id, "preflight"),
    publication: artifact(EXPECTED.publication_artifact_id, "publication"),
  };
  const jobs = [
    job(1, "resolve and validate build metadata", "success", [
      ["Resolve build metadata from the application config", "success", 4],
      ["Upload exact Release dispatch preflight evidence", "success", 5],
    ]),
    job(2, "prepare exact never-public Windows draft", "success", [
      ["Prepare a fresh numeric never-public draft", "success", 10],
      ["Upload exact candidate bytes and numeric ownership receipt", "success", 11],
    ]),
    job(3, "pre-publish real Windows in-app updater acceptance", "success", [
      ["Install unchanged public baseline and update through its production updater", "success", 6],
      ["Upload pre-publish updater lifecycle evidence", "success", 7],
    ]),
    job(4, "irreversible numeric publication and read-only verification", "failure", [
      ["Download the exact never-public candidate", "success", 4],
      ["Download the passed pre-publish updater receipt", "success", 5],
      ["Publish the accepted draft by numeric Release ID", "success", 6],
      ["Download and verify pinned minisign for read-only postverify", "success", 7],
      ["Read-only anonymous exact-byte postverification", "failure", 8],
      ["Upload immutable publication and anonymous byte evidence", "success", 9],
      ["Post Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38", "skipped", 17],
    ]),
  ];
  const published = release();
  return {
    repository: { id: 10, full_name: EXPECTED.repository, default_branch: "main", owner: { login: "Alpenl" } },
    default_branch_head: { sha: EXPECTED.verifier_commit },
    run: {
      id: EXPECTED.source_run_id,
      name: "CI / Release",
      path: ".github/workflows/ci.yml",
      event: "workflow_dispatch",
      status: "completed",
      conclusion: "failure",
      created_at: "2026-08-29T13:59:00Z",
      run_attempt: EXPECTED.source_run_attempt,
      head_branch: "main",
      head_sha: EXPECTED.source_commit,
      actor: { login: "Alpenl" },
      triggering_actor: { login: "Alpenl" },
      head_repository: { full_name: EXPECTED.repository },
    },
    jobs,
    jobs_total_count: jobs.length,
    artifacts: Object.values(selected),
    artifacts_total_count: Object.keys(selected).length,
    selected_artifacts: selected,
    release_by_id: published,
    release_by_tag: clone(published),
    latest: clone(published),
    tag_ref: { ref: `refs/tags/${EXPECTED.version}`, object: { type: "commit", sha: EXPECTED.source_commit } },
  };
}

test("read-only postverify accepts the exact source red and immutable published closure", () => {
  const value = snapshot();
  assert.doesNotThrow(() => validatePostverifySnapshot(value, EXPECTED));
  assert.match(assertNoPostverifyToctou(value, clone(value)), /^[a-f0-9]{64}$/);
  assert.equal(canonicalPostverifySnapshot(value).run.head_sha, EXPECTED.source_commit);
});

test("read-only postverify rejects provenance drift and a non-postverify source failure", () => {
  const wrongHead = snapshot();
  wrongHead.run.head_sha = "b".repeat(40);
  assert.throws(() => validatePostverifySnapshot(wrongHead, EXPECTED), /source run commit changed/);

  const failedPublish = snapshot();
  failedPublish.jobs[3].steps[2].conclusion = "failure";
  assert.throws(() => validatePostverifySnapshot(failedPublish, EXPECTED), /Publish the accepted draft.*state changed/);

  const falseGreen = snapshot();
  falseGreen.jobs[3].steps[4].conclusion = "success";
  assert.throws(
    () => validatePostverifySnapshot(falseGreen, EXPECTED),
    /Read-only anonymous exact-byte postverification.*state changed/,
  );

  const wrongArtifact = snapshot();
  wrongArtifact.selected_artifacts.candidate.id += 1;
  assert.throws(() => validatePostverifySnapshot(wrongArtifact, EXPECTED), /candidate artifact ID changed/);

  const extraFailure = snapshot();
  extraFailure.jobs[3].steps.push({
    name: "Unexpected product cleanup",
    number: 10,
    status: "completed",
    conclusion: "failure",
    started_at: "2026-08-29T14:37:00Z",
    completed_at: "2026-08-29T14:37:30Z",
  });
  assert.throws(() => validatePostverifySnapshot(extraFailure, EXPECTED), /non-success step closure changed/);

  const reorderedPublish = snapshot();
  reorderedPublish.jobs[3].steps[4].started_at = "2026-08-29T14:31:00Z";
  assert.throws(
    () => validatePostverifySnapshot(reorderedPublish, EXPECTED),
    /postverify tool to byte verification step order changed/,
  );

  const latePublication = snapshot();
  for (const published of [latePublication.release_by_id, latePublication.release_by_tag, latePublication.latest]) {
    published.published_at = "2026-08-29T14:33:00Z";
  }
  assert.throws(
    () => validatePostverifySnapshot(latePublication, EXPECTED),
    /outside the successful numeric publish step/,
  );

  const earlyAcceptanceArtifact = snapshot();
  earlyAcceptanceArtifact.selected_artifacts.acceptance.created_at = "2026-08-29T14:20:30Z";
  earlyAcceptanceArtifact.artifacts = Object.values(earlyAcceptanceArtifact.selected_artifacts);
  assert.throws(
    () => validatePostverifySnapshot(earlyAcceptanceArtifact, EXPECTED),
    /acceptance artifact was not created during its upload step/,
  );
});

test("final source/artifact/latest/by-id/by-tag/tag-ref reread rejects TOCTOU", () => {
  const before = snapshot();
  for (const mutate of [
    (after) => {
      after.release_by_id.assets[0].digest = `sha256:${"e".repeat(64)}`;
    },
    (after) => {
      after.selected_artifacts.acceptance.digest = `sha256:${"f".repeat(64)}`;
    },
    (after) => {
      after.selected_artifacts.preflight.created_at = "2026-08-29T14:01:11Z";
    },
    (after) => {
      after.tag_ref.object.sha = "a".repeat(40);
    },
  ]) {
    const after = clone(before);
    mutate(after);
    assert.throws(() => assertNoPostverifyToctou(before, after), /remote state changed/);
  }
});

test("0.1.6 workflow is hard-bound, read-only, non-mutating, and shares the publication lock", () => {
  const workflow = readFileSync(path.join(ROOT, ".github/workflows/desktop-0.1.6-postverify.yml"), "utf8");
  const ci = readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  const client = readFileSync(path.join(ROOT, "scripts/desktop-release-postverify.mjs"), "utf8");
  const releaseContract = readFileSync(path.join(ROOT, "scripts/desktop-release-contract.mjs"), "utf8");
  const tools = JSON.parse(readFileSync(path.join(ROOT, "scripts/release-tools.json"), "utf8"));
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /permissions:\n {2}actions: read\n {2}contents: read/);
  assert.match(workflow, /group: openaria-desktop-release-publication/);
  assert.match(workflow, /cancel-in-progress: false/);
  for (const binding of [
    "RELEASE_VERSION: 0.1.6",
    'RELEASE_ID: "379011766"',
    "SOURCE_COMMIT: ab579abb92a03c1b8d3da7b3752fdfdf63051e1b",
    'SOURCE_RUN_ID: "33257516567"',
    'SOURCE_RUN_ATTEMPT: "1"',
    'PREFLIGHT_ARTIFACT_ID: "9716255532"',
    'CANDIDATE_ARTIFACT_ID: "9716434253"',
    'ACCEPTANCE_ARTIFACT_ID: "9716450265"',
    'PUBLICATION_ARTIFACT_ID: "9716456600"',
  ]) {
    assert.ok(workflow.includes(binding), `missing exact postverify binding ${binding}`);
  }
  assert.equal((workflow.match(/artifact-ids:/g) ?? []).length, 3);
  assert.match(workflow, /merge-multiple: true/);
  assert.equal((workflow.match(/digest-mismatch: error/g) ?? []).length, 3);
  assert.equal(
    (workflow.match(/actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8\.0\.0/g) ?? []).length,
    3,
  );
  assert.match(workflow, /Upload read-only postpublish evidence/);
  assert.doesNotMatch(
    workflow,
    /contents: write|gh release|git push|workflow run|method:\s*(?:POST|PATCH|PUT|DELETE)/i,
  );
  assert.doesNotMatch(client, /method:\s*"(?:POST|PATCH|PUT|DELETE)"/);
  assert.match(client, /method: "GET"/);
  assert.match(client, /assertNoPostverifyToctou\(before, after\)/);
  assert.match(
    client,
    /actions\/runs\/\$\{expected\.source_run_id\}\/attempts\/\$\{expected\.source_run_attempt\}\/jobs/,
  );
  assert.match(releaseContract, /DOWNLOAD_REQUEST_TIMEOUT_MS = 120_000/);
  assert.match(releaseContract, /DOWNLOAD_TOTAL_TIMEOUT_MS = 360_000/);
  assert.match(releaseContract, /"--progress-bar"/);
  assert.match(releaseContract, /"--max-filesize"/);
  assert.match(releaseContract, /"--speed-time",\n\s+"30"/);
  assert.match(releaseContract, /anonymous-downloads\.json/);
  assert.match(ci, /--seven-zip "\$\{OPENARIA_SEVEN_ZIP\}"/);
  const publicationTools = ci.slice(ci.indexOf("      - name: Download and verify pinned postverify tools"));
  assert.equal((publicationTools.match(/--retry 3 --retry-all-errors/g) ?? []).length, 2);
  assert.equal((publicationTools.match(/--connect-timeout 20 --max-time 120 --max-filesize/g) ?? []).length, 2);
  assert.equal(tools.schema_version, 2);
  assert.deepEqual(
    {
      version: tools.seven_zip.version,
      bytes: tools.seven_zip.bytes,
      sha256: tools.seven_zip.sha256,
      binary_bytes: tools.seven_zip.binary_bytes,
      binary_sha256: tools.seven_zip.binary_sha256,
    },
    {
      version: "26.02",
      bytes: 1571416,
      sha256: "41aaba7b1235304ab5aa0624530c67ae829496cd29e875925271efdccc28c03e",
      binary_bytes: 2882112,
      binary_sha256: "1676a968815b92e865bc0ffeecee3fa284ba4402bf23dc2bec2412c4b502e922",
    },
  );
});
