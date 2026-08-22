import { test } from "node:test";
import assert from "node:assert/strict";

import { asCandidateId, asDerivedId, asMediaId, asPipelineId, asSourceId } from "../../runtime/media/ids";
import { createMediaRuntimeState, type MediaRuntimeState } from "../../runtime/media/reducer";
import type {
  MediaDescriptor,
  MediaLibraryEntryProjection,
  MediaScanSnapshot,
  PipelineSession,
} from "../../runtime/media/types";
import { projectMediaWorkspace } from "./projection";
import { mediaContentHtml } from "./render";

function media(accessIssue: string | null): MediaDescriptor {
  return {
    id: asMediaId("media-1"),
    displayName: "TF card",
    mountPath: "/media/tf-card",
    filesystem: "exfat",
    presence: "present",
    readerCount: 0,
    handleState: "in_use",
    ejectState: "unsupported",
    ejectVeto: null,
    accessIssue,
    observedAt: "2026-08-06T00:00:00Z",
  };
}

function workspaceFor(scan: MediaScanSnapshot): ReturnType<typeof projectMediaWorkspace> {
  const runtime: MediaRuntimeState = createMediaRuntimeState();
  runtime.scan = {
    loading: false,
    value: scan,
    lastGood: scan,
    error: null,
    revision: 1,
    retry: { available: false, attempts: 0, requestedAt: null },
  };
  return projectMediaWorkspace(runtime);
}

function completeScan(source: MediaDescriptor): MediaScanSnapshot {
  return {
    scanId: "scan-1",
    status: "complete",
    media: [source],
    candidates: [],
    attachIssue: null,
    completedAt: "2026-08-06T00:00:00Z",
  };
}

function verifiedLibraryEntry(entryKey = "entry-verified"): MediaLibraryEntryProjection {
  return {
    entryKey,
    sourceIdentity: "source-identity-1",
    sourceRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sourceLocal: {
      status: "verified",
      evidence: {
        importReceiptId: "receipt-1",
        importJobId: "import-1",
        relativePath: `sources/${entryKey}`,
        sealedInventoryDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        provenance: {
          kind: "locally_validated_unsigned",
          sourceSchema: "raw_capture_v2",
          validationReportId: null,
          inventoryDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          admission: "approved",
        },
        committedAt: "2026-08-06T00:00:00Z",
      },
    },
    derivedLocal: [],
    uploadBundles: [],
    cardPresence: { status: "unknown" },
  };
}

function removedLibraryEntry(entryKey = "entry-removed"): MediaLibraryEntryProjection {
  return {
    ...verifiedLibraryEntry(entryKey),
    sourceLocal: {
      status: "removed",
      evidence: {
        relativePath: `sources/${entryKey}`,
        policyRevision: "policy-1",
        removedAt: "2026-08-07T00:00:00Z",
      },
    },
  };
}

test("mounted-card access failures remain visible when no recording candidates were found", () => {
  const issue = "This card is mounted, but its recording folder will not open for user id 1000.";
  const snapshot = workspaceFor(completeScan(media(issue)));

  assert.equal(snapshot.sources.length, 1);
  assert.equal(snapshot.sources[0]?.candidateCount, 0);
  assert.deepEqual(snapshot.sources[0]?.scanIssue, {
    code: "media_unavailable",
    message: issue,
    retryable: false,
  });
});

test("an ordinary empty mounted card has no access issue", () => {
  const snapshot = workspaceFor(completeScan(media(null)));

  assert.equal(snapshot.sources[0]?.candidateCount, 0);
  assert.equal(snapshot.sources[0]?.scanIssue, null);
});

test("verified library source rows render the offline MP4 export action", () => {
  const runtime = createMediaRuntimeState();
  runtime.library = {
    loading: false,
    value: [verifiedLibraryEntry(), removedLibraryEntry()],
    lastGood: [verifiedLibraryEntry(), removedLibraryEntry()],
    error: null,
    revision: 1,
    retry: { available: false, attempts: 0, requestedAt: null },
  };

  const html = mediaContentHtml(projectMediaWorkspace(runtime));
  const exportButtons = html.match(/<button[^>]+data-media-action="export-library-entry"[^>]*>/g) ?? [];

  assert.equal(exportButtons.length, 1);
  assert.match(exportButtons[0] ?? "", /data-entry-key="entry-verified"/);
  assert.match(html, />导出 MP4<\/button>/);
});

test("configure-storage required actions render a settings command button", () => {
  const runtime = createMediaRuntimeState();
  const pipeline: PipelineSession = {
    id: asPipelineId("pipeline-storage-action"),
    candidateId: asCandidateId("candidate-storage-action"),
    sourceSummary: {
      sourceKey: "source-storage-action",
      mediaId: asMediaId("media-storage-action"),
      sourceId: asSourceId("source-id-storage-action"),
      displayName: "Session awaiting storage",
      sessionId: "session-storage-action",
      schema: "signed_publication_v1",
      sourceKind: "removable_media",
      provenance: {
        kind: "device_signed",
        publicationKeyFingerprint: "sha256:key",
        manifestSignature: "valid",
        producerKeyTrust: "trusted",
        inventoryIntegrity: "valid",
      },
      relativePath: "YLX/session-storage-action",
      bytes: 2048,
      durationSeconds: 10,
    },
    policy: {
      autoNormalize: true,
      autoUploadDerived: true,
      uploadSourceVideo: false,
      unsignedUploadApproved: false,
    },
    desiredRunState: "run",
    source: {
      state: "local_verified",
      sourceId: asSourceId("source-id-storage-action"),
      jobId: null,
      retentionState: "retained",
      progress: null,
      failure: null,
    },
    derived: {
      state: "not_started",
      derivedId: null,
      jobId: null,
      progress: null,
      validation: null,
      action: null,
      failure: null,
    },
    remote: {
      state: "action_required",
      bundleId: null,
      uploadJobId: null,
      progress: null,
      action: { kind: "configure_storage", message: "Storage profile is missing" },
      failure: null,
    },
    createdAt: "2026-08-11T00:00:00Z",
    updatedAt: "2026-08-11T00:00:00Z",
  };
  runtime.pipelines = {
    loading: false,
    value: [pipeline],
    lastGood: [pipeline],
    error: null,
    revision: 1,
    retry: { available: false, attempts: 0, requestedAt: null },
  };

  const snapshot = projectMediaWorkspace(runtime, {
    expandedCandidateIds: new Set([String(pipeline.candidateId)]),
  });
  const html = mediaContentHtml(snapshot);

  assert.match(html, /data-media-action="configure-storage"/);
  assert.match(html, />配置对象存储<\/button>/);
});

test("unsigned upload approval renders an actionable pipeline command", () => {
  const runtime = createMediaRuntimeState();
  const pipeline: PipelineSession = {
    id: asPipelineId("pipeline-unsigned-upload-action"),
    candidateId: asCandidateId("candidate-unsigned-upload-action"),
    sourceSummary: {
      sourceKey: "source-unsigned-upload-action",
      mediaId: asMediaId("media-unsigned-upload-action"),
      sourceId: asSourceId("source-id-unsigned-upload-action"),
      displayName: "Unsigned session awaiting approval",
      sessionId: "session-unsigned-upload-action",
      schema: "unsigned_publication_v1",
      sourceKind: "removable_media",
      provenance: {
        kind: "locally_validated_unsigned",
        sourceSchema: "unsigned_publication_v1",
        validationReportId: "validation-report-1",
        inventoryDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        admission: "approved",
      },
      relativePath: "YLX/session-unsigned-upload-action",
      bytes: 2048,
      durationSeconds: 10,
    },
    policy: {
      autoNormalize: true,
      autoUploadDerived: true,
      uploadSourceVideo: false,
      unsignedUploadApproved: false,
    },
    desiredRunState: "run",
    source: {
      state: "local_verified",
      sourceId: asSourceId("source-id-unsigned-upload-action"),
      jobId: null,
      retentionState: "retained",
      progress: null,
      failure: null,
    },
    derived: {
      state: "derived_verified",
      derivedId: asDerivedId("derived-unsigned-upload-action"),
      jobId: null,
      progress: null,
      validation: null,
      action: null,
      failure: null,
    },
    remote: {
      state: "action_required",
      bundleId: null,
      uploadJobId: null,
      progress: null,
      action: { kind: "approve_unsigned_source", message: "Explicit upload approval is required" },
      failure: null,
    },
    createdAt: "2026-08-11T00:00:00Z",
    updatedAt: "2026-08-11T00:00:00Z",
  };
  runtime.pipelines = {
    loading: false,
    value: [pipeline],
    lastGood: [pipeline],
    error: null,
    revision: 1,
    retry: { available: false, attempts: 0, requestedAt: null },
  };

  const snapshot = projectMediaWorkspace(runtime, {
    expandedCandidateIds: new Set([String(pipeline.candidateId)]),
  });
  const html = mediaContentHtml(snapshot);

  assert.match(html, /data-media-action="approve-unsigned-upload"/);
  assert.match(html, /data-pipeline-id="pipeline-unsigned-upload-action"/);
  assert.match(html, />批准上传未签名来源<\/button>/);
});
