import {
  asCandidateId,
  asDerivationJobId,
  asDerivedId,
  asImportJobId,
  asMediaId,
  asPipelineId,
  asProfileId,
  asSourceId,
  asUploadBundleId,
} from "./ids";
import type {
  CandidateVerdict,
  DerivationJob,
  DerivationProgress,
  DerivedLayer,
  DeviceSignedProvenance,
  ImportBatchOutcome,
  ImportJob,
  ImportProgress,
  LocallyValidatedUnsignedProvenance,
  MediaDescriptor,
  MediaLibraryCardPresence,
  MediaLibraryDerivedProjection,
  MediaLibraryEntryProjection,
  MediaLibraryRemoteState,
  MediaLibrarySourceArchive,
  MediaLibrarySourceLocalProjection,
  MediaLibraryUploadProjection,
  MediaTrustedProducerRevocation,
  MediaError,
  MediaScanSnapshot,
  PipelinePolicy,
  PipelineBatchOutcome,
  PipelineSourceSummary,
  PipelineSession,
  RemoteLayer,
  RequiredAction,
  ScanCandidate,
  SourceLayer,
  SourceProvenance,
  StartPipelineRequest,
  TaggedDispatchResult,
  UploadProgress,
  ValidationProgress,
} from "./types";
import { MEDIA_ERROR_CODES, SOURCE_SCHEMAS } from "./types";
import type { MediaBackendSnapshot, Revisioned } from "./backend";

export type MediaDecoder<T> = (value: unknown, path?: string) => T;

export class MediaDecodeError extends Error {
  readonly path: string;
  readonly expected: string;

  constructor(path: string, expected: string, value: unknown) {
    super(`Malformed media payload at ${path}: expected ${expected}, got ${describe(value)}`);
    this.name = "MediaDecodeError";
    this.path = path;
    this.expected = expected;
  }
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number" && !Number.isFinite(value)) return "non-finite number";
  return typeof value;
}

function fail(path: string, expected: string, value: unknown): never {
  throw new MediaDecodeError(path, expected, value);
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return fail(path, "object", value);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return fail(path, "plain object", value);
  return value as Record<string, unknown>;
}

function exact(item: Record<string, unknown>, keys: readonly string[], path: string): void {
  const allowed = new Set(keys);
  const unexpected = Object.keys(item).find((key) => !allowed.has(key));
  if (unexpected !== undefined) fail(`${path}.${unexpected}`, "field to be absent", item[unexpected]);
}

function required<T>(item: Record<string, unknown>, key: string, decoder: MediaDecoder<T>, path: string): T {
  if (!Object.prototype.hasOwnProperty.call(item, key)) fail(`${path}.${key}`, "present value", undefined);
  return decoder(item[key], `${path}.${key}`);
}

function text(value: unknown, path = "payload"): string {
  if (typeof value !== "string") return fail(path, "string", value);
  return value;
}

function nonEmptyText(value: unknown, path = "payload"): string {
  const result = text(value, path);
  return result.trim().length === 0 ? fail(path, "non-empty string", value) : result;
}

function nullable<T>(decoder: MediaDecoder<T>): MediaDecoder<T | null> {
  return (value, path = "payload") => (value === null ? null : decoder(value, path));
}

function bool(value: unknown, path = "payload"): boolean {
  if (typeof value !== "boolean") return fail(path, "boolean", value);
  return value;
}

function nonNegativeInteger(value: unknown, path = "payload"): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return fail(path, "non-negative safe integer", value);
  }
  return value;
}

function nonNegativeNumber(value: unknown, path = "payload"): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return fail(path, "non-negative finite number", value);
  }
  return value;
}

function list<T>(value: unknown, decoder: MediaDecoder<T>, path = "payload"): T[] {
  if (!Array.isArray(value)) return fail(path, "array", value);
  return value.map((item, index) => decoder(item, `${path}[${index}]`));
}

function oneOf<T extends string>(values: readonly T[], value: unknown, path: string): T {
  const result = text(value, path);
  return values.includes(result as T) ? (result as T) : fail(path, values.join(" | "), value);
}

function optionalDetails(value: unknown, path: string): Readonly<Record<string, unknown>> {
  return record(value, path);
}

export function decodeRevision(value: unknown, path = "payload"): number {
  return nonNegativeInteger(value, path);
}

export function decodeMediaError(value: unknown, path = "payload"): MediaError {
  const item = record(value, path);
  exact(item, ["code", "message", "retryable", "details"], path);
  const result: MediaError = {
    code: required(item, "code", (raw, field) => oneOf(MEDIA_ERROR_CODES, raw, field ?? path), path),
    message: required(item, "message", nonEmptyText, path),
    retryable: required(item, "retryable", bool, path),
  };
  if (Object.prototype.hasOwnProperty.call(item, "details")) {
    return { ...result, details: optionalDetails(item.details, `${path}.details`) };
  }
  return result;
}

function decodeMediaDescriptor(value: unknown, path = "payload"): MediaDescriptor {
  const item = record(value, path);
  exact(
    item,
    [
      "id",
      "displayName",
      "mountPath",
      "filesystem",
      "presence",
      "readerCount",
      "handleState",
      "ejectState",
      "ejectVeto",
      "accessIssue",
      "observedAt",
    ],
    path,
  );
  return {
    id: asMediaId(required(item, "id", nonEmptyText, path)),
    displayName: required(item, "displayName", nonEmptyText, path),
    mountPath: required(item, "mountPath", nullable(text), path),
    filesystem: required(item, "filesystem", nullable(text), path),
    presence: required(
      item,
      "presence",
      (raw, field) => oneOf(["present", "removed"] as const, raw, field ?? path),
      path,
    ),
    readerCount: required(item, "readerCount", nonNegativeInteger, path),
    handleState: required(
      item,
      "handleState",
      (raw, field) => oneOf(["in_use", "released"] as const, raw, field ?? path),
      path,
    ),
    ejectState: required(
      item,
      "ejectState",
      (raw, field) =>
        oneOf(["unsupported", "blocked", "available", "ejecting", "ejected", "failed"] as const, raw, field ?? path),
      path,
    ),
    ejectVeto: required(item, "ejectVeto", nullable(text), path),
    accessIssue: required(item, "accessIssue", nullable(text), path),
    observedAt: required(item, "observedAt", nonEmptyText, path),
  };
}

function decodeSignedProvenance(value: unknown, path: string): DeviceSignedProvenance {
  const item = record(value, path);
  exact(
    item,
    ["kind", "publicationKeyFingerprint", "manifestSignature", "producerKeyTrust", "inventoryIntegrity"],
    path,
  );
  const kind = required(item, "kind", text, path);
  if (kind !== "device_signed") fail(`${path}.kind`, "device_signed", kind);
  return {
    kind,
    publicationKeyFingerprint: required(item, "publicationKeyFingerprint", nonEmptyText, path),
    manifestSignature: required(
      item,
      "manifestSignature",
      (raw, field) => oneOf(["valid", "invalid"] as const, raw, field ?? path),
      path,
    ),
    producerKeyTrust: required(
      item,
      "producerKeyTrust",
      (raw, field) => oneOf(["trusted", "untrusted", "unknown"] as const, raw, field ?? path),
      path,
    ),
    inventoryIntegrity: required(
      item,
      "inventoryIntegrity",
      (raw, field) => oneOf(["pending", "valid", "invalid"] as const, raw, field ?? path),
      path,
    ),
  };
}

function decodeUnsignedProvenance(value: unknown, path: string): LocallyValidatedUnsignedProvenance {
  const item = record(value, path);
  exact(item, ["kind", "sourceSchema", "validationReportId", "inventoryDigest", "admission"], path);
  const kind = required(item, "kind", text, path);
  if (kind !== "locally_validated_unsigned") fail(`${path}.kind`, "locally_validated_unsigned", kind);
  const sourceSchema = required(item, "sourceSchema", (raw, field) => oneOf(SOURCE_SCHEMAS, raw, field ?? path), path);
  if (sourceSchema === "signed_publication_v1") {
    fail(`${path}.sourceSchema`, "unsigned source schema", sourceSchema);
  }
  return {
    kind,
    sourceSchema,
    validationReportId: required(item, "validationReportId", nullable(text), path),
    inventoryDigest: required(item, "inventoryDigest", nullable(text), path),
    admission: required(
      item,
      "admission",
      (raw, field) => oneOf(["required", "approved"] as const, raw, field ?? path),
      path,
    ),
  };
}

function decodeProvenance(value: unknown, path = "payload"): SourceProvenance {
  const item = record(value, path);
  const kind = required(item, "kind", text, path);
  if (kind === "device_signed") return decodeSignedProvenance(value, path);
  if (kind === "locally_validated_unsigned") return decodeUnsignedProvenance(value, path);
  return fail(`${path}.kind`, "device_signed | locally_validated_unsigned", kind);
}

function safeRelativePath(value: unknown, path: string): string {
  const result = nonEmptyText(value, path);
  if (
    result.startsWith("/") ||
    result.startsWith("\\") ||
    /^[A-Za-z]:[\\/]/.test(result) ||
    result.includes("\0") ||
    result.split("/").some((segment) => segment === "..")
  ) {
    fail(path, "safe relative path", value);
  }
  return result;
}

function decodeMediaLibrarySourceLocal(value: unknown, path = "payload"): MediaLibrarySourceLocalProjection {
  const item = record(value, path);
  const status = required(item, "status", text, path);
  if (status === "verified") {
    exact(item, ["status", "evidence"], path);
    const evidence = record(
      required(item, "evidence", (raw, field) => record(raw, field ?? path), path),
      `${path}.evidence`,
    );
    exact(
      evidence,
      ["importReceiptId", "importJobId", "relativePath", "sealedInventoryDigest", "provenance", "committedAt"],
      `${path}.evidence`,
    );
    return {
      status,
      evidence: {
        importReceiptId: required(evidence, "importReceiptId", nonEmptyText, `${path}.evidence`),
        importJobId: required(evidence, "importJobId", nonEmptyText, `${path}.evidence`),
        relativePath: required(
          evidence,
          "relativePath",
          (raw, field) => safeRelativePath(raw, field ?? path),
          `${path}.evidence`,
        ),
        sealedInventoryDigest: required(evidence, "sealedInventoryDigest", nonEmptyText, `${path}.evidence`),
        provenance: required(evidence, "provenance", decodeProvenance, `${path}.evidence`),
        committedAt: required(evidence, "committedAt", nonEmptyText, `${path}.evidence`),
      },
    };
  }
  if (status === "removed") {
    exact(item, ["status", "evidence"], path);
    const evidence = record(
      required(item, "evidence", (raw, field) => record(raw, field ?? path), path),
      `${path}.evidence`,
    );
    exact(evidence, ["relativePath", "policyRevision", "removedAt"], `${path}.evidence`);
    return {
      status,
      evidence: {
        relativePath: required(
          evidence,
          "relativePath",
          (raw, field) => safeRelativePath(raw, field ?? path),
          `${path}.evidence`,
        ),
        policyRevision: required(evidence, "policyRevision", nonEmptyText, `${path}.evidence`),
        removedAt: required(evidence, "removedAt", nonEmptyText, `${path}.evidence`),
      },
    };
  }
  return fail(`${path}.status`, "verified | removed", status);
}

function decodeMediaLibrarySourceArchive(value: unknown, path = "payload"): MediaLibrarySourceArchive {
  const item = record(value, path);
  const status = required(item, "status", text, path);
  if (status === "not_included") {
    exact(item, ["status"], path);
    return { status };
  }
  if (status === "verified") {
    exact(item, ["status", "policyRevision"], path);
    return { status, policyRevision: required(item, "policyRevision", nonEmptyText, path) };
  }
  return fail(`${path}.status`, "not_included | verified", status);
}

function decodeMediaLibraryRemote(value: unknown, path = "payload"): MediaLibraryRemoteState {
  const item = record(value, path);
  const status = required(item, "status", text, path);
  if (status === "not_verified") {
    exact(item, ["status"], path);
    return { status };
  }
  if (status === "failed") {
    exact(item, ["status", "evidence"], path);
    const evidence = record(
      required(item, "evidence", (raw, field) => record(raw, field ?? path), path),
      `${path}.evidence`,
    );
    exact(evidence, ["code", "retryable"], `${path}.evidence`);
    return {
      status,
      evidence: {
        code: required(evidence, "code", nonEmptyText, `${path}.evidence`),
        retryable: required(evidence, "retryable", bool, `${path}.evidence`),
      },
    };
  }
  if (status === "verified") {
    exact(item, ["status", "evidence"], path);
    const evidence = record(
      required(item, "evidence", (raw, field) => record(raw, field ?? path), path),
      `${path}.evidence`,
    );
    exact(evidence, ["remoteReceiptDigest", "verifiedAtMs", "sourceArchive"], `${path}.evidence`);
    return {
      status,
      evidence: {
        remoteReceiptDigest: required(evidence, "remoteReceiptDigest", nonEmptyText, `${path}.evidence`),
        verifiedAtMs: required(evidence, "verifiedAtMs", nonNegativeInteger, `${path}.evidence`),
        sourceArchive: required(evidence, "sourceArchive", decodeMediaLibrarySourceArchive, `${path}.evidence`),
      },
    };
  }
  return fail(`${path}.status`, "not_verified | failed | verified", status);
}

function decodeMediaLibraryCardPresence(value: unknown, path = "payload"): MediaLibraryCardPresence {
  const item = record(value, path);
  const status = required(item, "status", text, path);
  if (status === "unknown") {
    exact(item, ["status"], path);
    return { status };
  }
  if (status === "present") {
    exact(item, ["status", "mediaGenerationId", "observationSequence", "observedAtMs"], path);
    return {
      status,
      mediaGenerationId: required(item, "mediaGenerationId", nonEmptyText, path),
      observationSequence: required(item, "observationSequence", nonNegativeInteger, path),
      observedAtMs: required(item, "observedAtMs", nonNegativeInteger, path),
    };
  }
  if (status === "absent") {
    exact(item, ["status", "lastMediaGenerationId", "observationSequence", "observedAtMs"], path);
    return {
      status,
      lastMediaGenerationId: required(item, "lastMediaGenerationId", nullable(text), path),
      observationSequence: required(item, "observationSequence", nonNegativeInteger, path),
      observedAtMs: required(item, "observedAtMs", nonNegativeInteger, path),
    };
  }
  return fail(`${path}.status`, "unknown | present | absent", status);
}

function decodeMediaLibraryDerived(value: unknown, path = "payload"): MediaLibraryDerivedProjection {
  const item = record(value, path);
  exact(
    item,
    ["derivationJobId", "profileRevision", "derivedRevision", "relativePath", "sourceManifestDigest", "committedAt"],
    path,
  );
  return {
    derivationJobId: required(item, "derivationJobId", nonEmptyText, path),
    profileRevision: required(item, "profileRevision", nonEmptyText, path),
    derivedRevision: required(item, "derivedRevision", nonEmptyText, path),
    relativePath: required(item, "relativePath", (raw, field) => safeRelativePath(raw, field ?? path), path),
    sourceManifestDigest: required(item, "sourceManifestDigest", nonEmptyText, path),
    committedAt: required(item, "committedAt", nonEmptyText, path),
  };
}

function decodeMediaLibraryUpload(value: unknown, path = "payload"): MediaLibraryUploadProjection {
  const item = record(value, path);
  exact(item, ["bundleRevision", "storageProfileIdentity", "sourceRevision", "derivedRevision", "remote"], path);
  return {
    bundleRevision: required(item, "bundleRevision", nonEmptyText, path),
    storageProfileIdentity: required(item, "storageProfileIdentity", nonEmptyText, path),
    sourceRevision: required(item, "sourceRevision", nonEmptyText, path),
    derivedRevision: required(item, "derivedRevision", nonEmptyText, path),
    remote: required(item, "remote", decodeMediaLibraryRemote, path),
  };
}

export function decodeMediaLibraryEntry(value: unknown, path = "payload"): MediaLibraryEntryProjection {
  const item = record(value, path);
  exact(
    item,
    ["entryKey", "sourceIdentity", "sourceRevision", "sourceLocal", "derivedLocal", "uploadBundles", "cardPresence"],
    path,
  );
  return {
    entryKey: required(item, "entryKey", nonEmptyText, path),
    sourceIdentity: required(item, "sourceIdentity", nonEmptyText, path),
    sourceRevision: required(item, "sourceRevision", nonEmptyText, path),
    sourceLocal: required(item, "sourceLocal", decodeMediaLibrarySourceLocal, path),
    derivedLocal: required(item, "derivedLocal", (raw, field) => list(raw, decodeMediaLibraryDerived, field), path),
    uploadBundles: required(item, "uploadBundles", (raw, field) => list(raw, decodeMediaLibraryUpload, field), path),
    cardPresence: required(item, "cardPresence", decodeMediaLibraryCardPresence, path),
  };
}

export function decodeMediaLibraryEntries(value: unknown, path = "payload"): readonly MediaLibraryEntryProjection[] {
  const entries = list(value, decodeMediaLibraryEntry, path);
  const keys = new Set<string>();
  for (const entry of entries) {
    if (keys.has(entry.entryKey)) fail(path, `unique library entry key ${entry.entryKey}`, entry.entryKey);
    keys.add(entry.entryKey);
  }
  return entries;
}

export function decodeMediaTrustedProducerRevocation(value: unknown, path = "payload"): MediaTrustedProducerRevocation {
  const item = record(value, path);
  exact(item, ["keyFingerprint", "revoked"], path);
  return {
    keyFingerprint: required(item, "keyFingerprint", nonEmptyText, path),
    revoked: required(item, "revoked", bool, path),
  };
}

function decodeCandidate(value: unknown, path = "payload"): ScanCandidate {
  const item = record(value, path);
  exact(
    item,
    [
      "id",
      "sourceKey",
      "mediaId",
      "sourceId",
      "sessionId",
      "displayName",
      "relativePath",
      "sourceKind",
      "schema",
      "verdict",
      "reason",
      "provenance",
      "bytes",
      "durationSeconds",
      "mediaRequired",
    ],
    path,
  );
  return {
    id: asCandidateId(required(item, "id", nonEmptyText, path)),
    sourceKey: required(item, "sourceKey", nonEmptyText, path),
    mediaId: asMediaId(required(item, "mediaId", nonEmptyText, path)),
    sourceId: required(
      item,
      "sourceId",
      nullable((raw, field) => asSourceId(nonEmptyText(raw, field))),
      path,
    ),
    sessionId: required(item, "sessionId", nullable(text), path),
    displayName: required(item, "displayName", nonEmptyText, path),
    relativePath: required(item, "relativePath", nonEmptyText, path),
    sourceKind: required(
      item,
      "sourceKind",
      (raw, field) =>
        oneOf(["removable_media", "legacy_removable_media", "local_folder", "lan"] as const, raw, field ?? path),
      path,
    ),
    schema: required(item, "schema", (raw, field) => oneOf(SOURCE_SCHEMAS, raw, field ?? path), path),
    verdict: required(
      item,
      "verdict",
      (raw, field) =>
        oneOf(
          [
            "ready_signed",
            "ready_unsigned_requires_policy",
            "pending_artifact_validation",
            "already_imported",
            "waiting_for_pairing_key",
            "recording_or_encoding_incomplete",
            "unsupported_schema",
            "unsafe_path",
            "insufficient_local_space",
            "corrupt",
          ] as const,
          raw,
          field ?? path,
        ),
      path,
    ) as CandidateVerdict,
    reason: required(item, "reason", nullable(decodeMediaError), path),
    provenance: required(item, "provenance", decodeProvenance, path),
    bytes: required(item, "bytes", nonNegativeInteger, path),
    durationSeconds: required(item, "durationSeconds", nullable(nonNegativeNumber), path),
    mediaRequired: required(item, "mediaRequired", bool, path),
  };
}

export function decodeMediaScanSnapshot(value: unknown, path = "payload"): MediaScanSnapshot {
  const item = record(value, path);
  exact(item, ["scanId", "status", "media", "candidates", "attachIssue", "completedAt"], path);
  const media = required(item, "media", (raw, field) => list(raw, decodeMediaDescriptor, field), path);
  const candidates = required(item, "candidates", (raw, field) => list(raw, decodeCandidate, field), path);
  const mediaIds = new Set<string>();
  for (const descriptor of media) {
    if (mediaIds.has(descriptor.id)) fail(`${path}.media`, `unique media id ${descriptor.id}`, descriptor.id);
    mediaIds.add(descriptor.id);
  }
  const candidateIds = new Set<string>();
  for (const candidate of candidates) {
    if (candidateIds.has(candidate.id)) fail(`${path}.candidates`, `unique candidate id ${candidate.id}`, candidate.id);
    candidateIds.add(candidate.id);
  }
  return {
    scanId: required(item, "scanId", text, path),
    status: required(
      item,
      "status",
      (raw, field) => oneOf(["idle", "scanning", "complete"] as const, raw, field ?? path),
      path,
    ),
    media,
    candidates,
    attachIssue: required(item, "attachIssue", nullable(decodeMediaError), path),
    completedAt: required(item, "completedAt", nullable(text), path),
  };
}

function decodeImportProgress(value: unknown, path = "payload"): ImportProgress {
  const item = record(value, path);
  exact(item, ["currentFile", "copiedBytes", "totalBytes", "throughputBytesPerSecond", "etaSeconds"], path);
  const copiedBytes = required(item, "copiedBytes", nonNegativeInteger, path);
  const totalBytes = required(item, "totalBytes", nonNegativeInteger, path);
  if (copiedBytes > totalBytes) fail(`${path}.copiedBytes`, `number <= ${totalBytes}`, copiedBytes);
  return {
    currentFile: required(item, "currentFile", nullable(text), path),
    copiedBytes,
    totalBytes,
    throughputBytesPerSecond: required(item, "throughputBytesPerSecond", nullable(nonNegativeNumber), path),
    etaSeconds: required(item, "etaSeconds", nullable(nonNegativeNumber), path),
  };
}

function validateJobFailure(state: string, failure: MediaError | null, path: string): void {
  const mayHaveFailure = state === "failed" || state === "retry_wait";
  if (state === "failed" && failure === null) fail(`${path}.failure`, "error for failed state", failure);
  if (!mayHaveFailure && failure !== null) fail(`${path}.failure`, "null outside failed/retry_wait", failure);
}

export function decodeImportJob(value: unknown, path = "payload"): ImportJob {
  const item = record(value, path);
  exact(
    item,
    [
      "id",
      "candidateId",
      "mediaId",
      "sourceId",
      "state",
      "desiredRunState",
      "progress",
      "failure",
      "retryAt",
      "createdAt",
      "updatedAt",
    ],
    path,
  );
  const state = required(
    item,
    "state",
    (raw, field) =>
      oneOf(
        [
          "queued",
          "waiting_for_media",
          "preflighting",
          "copying",
          "verifying",
          "committing",
          "local_verified",
          "retry_wait",
          "pausing",
          "paused",
          "cancelling",
          "cancelled",
          "failed",
        ] as const,
        raw,
        field ?? path,
      ),
    path,
  );
  const failure = required(item, "failure", nullable(decodeMediaError), path);
  validateJobFailure(state, failure, path);
  return {
    id: asImportJobId(required(item, "id", nonEmptyText, path)),
    candidateId: asCandidateId(required(item, "candidateId", nonEmptyText, path)),
    mediaId: asMediaId(required(item, "mediaId", nonEmptyText, path)),
    sourceId: required(
      item,
      "sourceId",
      nullable((raw, field) => asSourceId(nonEmptyText(raw, field))),
      path,
    ),
    state,
    desiredRunState: required(
      item,
      "desiredRunState",
      (raw, field) => oneOf(["run", "paused", "cancelled"] as const, raw, field ?? path),
      path,
    ),
    progress: required(item, "progress", decodeImportProgress, path),
    failure,
    retryAt: required(item, "retryAt", nullable(text), path),
    createdAt: required(item, "createdAt", nonEmptyText, path),
    updatedAt: required(item, "updatedAt", nonEmptyText, path),
  };
}

function decodeDerivationProgress(value: unknown, path = "payload"): DerivationProgress {
  const item = record(value, path);
  exact(
    item,
    ["currentSegmentPair", "totalSegmentPairs", "processedFrames", "totalFrames", "encodingFps", "etaSeconds"],
    path,
  );
  const current = required(item, "currentSegmentPair", nullable(nonNegativeInteger), path);
  const total = required(item, "totalSegmentPairs", nullable(nonNegativeInteger), path);
  if (current !== null && total !== null && current > total)
    fail(`${path}.currentSegmentPair`, `number <= ${total}`, current);
  const frames = required(item, "processedFrames", nonNegativeInteger, path);
  const totalFrames = required(item, "totalFrames", nullable(nonNegativeInteger), path);
  if (totalFrames !== null && frames > totalFrames) fail(`${path}.processedFrames`, `number <= ${totalFrames}`, frames);
  return {
    currentSegmentPair: current,
    totalSegmentPairs: total,
    processedFrames: frames,
    totalFrames,
    encodingFps: required(item, "encodingFps", nullable(nonNegativeNumber), path),
    etaSeconds: required(item, "etaSeconds", nullable(nonNegativeNumber), path),
  };
}

function decodeValidationProgress(value: unknown, path = "payload"): ValidationProgress {
  const item = record(value, path);
  exact(item, ["decodedSegmentPairs", "totalSegmentPairs"], path);
  const decoded = required(item, "decodedSegmentPairs", nonNegativeInteger, path);
  const total = required(item, "totalSegmentPairs", nonNegativeInteger, path);
  if (decoded > total) fail(`${path}.decodedSegmentPairs`, `number <= ${total}`, decoded);
  return { decodedSegmentPairs: decoded, totalSegmentPairs: total };
}

export function decodeDerivationJob(value: unknown, path = "payload"): DerivationJob {
  const item = record(value, path);
  exact(
    item,
    [
      "id",
      "sourceId",
      "profileId",
      "derivedId",
      "state",
      "desiredRunState",
      "progress",
      "validation",
      "failure",
      "retryAt",
      "createdAt",
      "updatedAt",
    ],
    path,
  );
  const state = required(
    item,
    "state",
    (raw, field) =>
      oneOf(
        [
          "queued",
          "waiting_for_source",
          "probing",
          "planning",
          "encoding",
          "validating",
          "committing",
          "derived_verified",
          "retry_wait",
          "pausing",
          "paused",
          "cancelling",
          "cancelled",
          "failed",
        ] as const,
        raw,
        field ?? path,
      ),
    path,
  );
  const failure = required(item, "failure", nullable(decodeMediaError), path);
  validateJobFailure(state, failure, path);
  return {
    id: asDerivationJobId(required(item, "id", nonEmptyText, path)),
    sourceId: asSourceId(required(item, "sourceId", nonEmptyText, path)),
    profileId: asProfileId(required(item, "profileId", nonEmptyText, path)),
    derivedId: required(
      item,
      "derivedId",
      nullable((raw, field) => asDerivedId(nonEmptyText(raw, field))),
      path,
    ),
    state,
    desiredRunState: required(
      item,
      "desiredRunState",
      (raw, field) => oneOf(["run", "paused", "cancelled"] as const, raw, field ?? path),
      path,
    ),
    progress: required(item, "progress", decodeDerivationProgress, path),
    validation: required(item, "validation", decodeValidationProgress, path),
    failure,
    retryAt: required(item, "retryAt", nullable(text), path),
    createdAt: required(item, "createdAt", nonEmptyText, path),
    updatedAt: required(item, "updatedAt", nonEmptyText, path),
  };
}

function decodeRequiredAction(value: unknown, path = "payload"): RequiredAction {
  const item = record(value, path);
  exact(item, ["kind", "message"], path);
  return {
    kind: required(
      item,
      "kind",
      (raw, field) =>
        oneOf(
          [
            "approve_unsigned_source",
            "configure_storage",
            "install_supported_encoder",
            "resolve_policy",
            "retry_remote_verification",
          ] as const,
          raw,
          field ?? path,
        ),
      path,
    ),
    message: required(item, "message", nonEmptyText, path),
  };
}

function decodeUploadProgress(value: unknown, path = "payload"): UploadProgress {
  const item = record(value, path);
  exact(
    item,
    ["uploadedBytes", "totalBytes", "currentPart", "totalParts", "throughputBytesPerSecond", "etaSeconds"],
    path,
  );
  const uploaded = required(item, "uploadedBytes", nonNegativeInteger, path);
  const total = required(item, "totalBytes", nonNegativeInteger, path);
  if (uploaded > total) fail(`${path}.uploadedBytes`, `number <= ${total}`, uploaded);
  const currentPart = required(item, "currentPart", nullable(nonNegativeInteger), path);
  const totalParts = required(item, "totalParts", nullable(nonNegativeInteger), path);
  if (currentPart !== null && totalParts !== null && currentPart > totalParts)
    fail(`${path}.currentPart`, `number <= ${totalParts}`, currentPart);
  return {
    uploadedBytes: uploaded,
    totalBytes: total,
    currentPart,
    totalParts,
    throughputBytesPerSecond: required(item, "throughputBytesPerSecond", nullable(nonNegativeNumber), path),
    etaSeconds: required(item, "etaSeconds", nullable(nonNegativeNumber), path),
  };
}

function validateLayerFailure(state: string, failure: MediaError | null, path: string): void {
  if (state === "failed" && failure === null) fail(`${path}.failure`, "error for failed state", failure);
  if (state !== "failed" && state !== "retry_wait" && failure !== null) {
    fail(`${path}.failure`, "null outside failed/retry_wait", failure);
  }
}

function decodeSourceLayer(value: unknown, path = "payload"): SourceLayer {
  const item = record(value, path);
  exact(item, ["state", "sourceId", "jobId", "retentionState", "progress", "failure"], path);
  const state = required(
    item,
    "state",
    (raw, field) =>
      oneOf(
        [
          "not_started",
          "queued",
          "waiting_for_media",
          "preflighting",
          "copying",
          "verifying",
          "committing",
          "local_verified",
          "retry_wait",
          "pausing",
          "paused",
          "cancelling",
          "cancelled",
          "failed",
        ] as const,
        raw,
        field ?? path,
      ),
    path,
  );
  const failure = required(item, "failure", nullable(decodeMediaError), path);
  validateLayerFailure(state, failure, path);
  return {
    state,
    sourceId: required(
      item,
      "sourceId",
      nullable((raw, field) => asSourceId(nonEmptyText(raw, field))),
      path,
    ),
    jobId: required(
      item,
      "jobId",
      nullable((raw, field) => asImportJobId(nonEmptyText(raw, field))),
      path,
    ),
    retentionState: required(
      item,
      "retentionState",
      (raw, field) => oneOf(["retained", "not_retained", "unknown"] as const, raw, field ?? path),
      path,
    ),
    progress: required(item, "progress", nullable(decodeImportProgress), path),
    failure,
  };
}

function decodeDerivedLayer(value: unknown, path = "payload"): DerivedLayer {
  const item = record(value, path);
  exact(item, ["state", "derivedId", "jobId", "progress", "validation", "action", "failure"], path);
  const state = required(
    item,
    "state",
    (raw, field) =>
      oneOf(
        [
          "not_started",
          "waiting_for_source",
          "queued",
          "probing",
          "planning",
          "encoding",
          "validating",
          "committing",
          "derived_verified",
          "action_required",
          "retry_wait",
          "pausing",
          "paused",
          "cancelling",
          "cancelled",
          "failed",
        ] as const,
        raw,
        field ?? path,
      ),
    path,
  );
  const action = required(item, "action", nullable(decodeRequiredAction), path);
  if ((state === "action_required") !== (action !== null))
    fail(`${path}.action`, state === "action_required" ? "action" : "null", action);
  const failure = required(item, "failure", nullable(decodeMediaError), path);
  validateLayerFailure(state, failure, path);
  return {
    state,
    derivedId: required(
      item,
      "derivedId",
      nullable((raw, field) => asDerivedId(nonEmptyText(raw, field))),
      path,
    ),
    jobId: required(
      item,
      "jobId",
      nullable((raw, field) => asDerivationJobId(nonEmptyText(raw, field))),
      path,
    ),
    progress: required(item, "progress", nullable(decodeDerivationProgress), path),
    validation: required(item, "validation", nullable(decodeValidationProgress), path),
    action,
    failure,
  };
}

function decodeRemoteLayer(value: unknown, path = "payload"): RemoteLayer {
  const item = record(value, path);
  exact(item, ["state", "bundleId", "uploadJobId", "progress", "action", "failure"], path);
  const state = required(
    item,
    "state",
    (raw, field) =>
      oneOf(
        [
          "disabled",
          "waiting_for_derived",
          "queued",
          "uploading",
          "verifying",
          "object_store_verified",
          "action_required",
          "retry_wait",
          "pausing",
          "paused",
          "cancelling",
          "cancelled",
          "failed",
        ] as const,
        raw,
        field ?? path,
      ),
    path,
  );
  const action = required(item, "action", nullable(decodeRequiredAction), path);
  if ((state === "action_required") !== (action !== null))
    fail(`${path}.action`, state === "action_required" ? "action" : "null", action);
  const failure = required(item, "failure", nullable(decodeMediaError), path);
  validateLayerFailure(state, failure, path);
  return {
    state,
    bundleId: required(
      item,
      "bundleId",
      nullable((raw, field) => asUploadBundleId(nonEmptyText(raw, field))),
      path,
    ),
    uploadJobId: required(item, "uploadJobId", nullable(nonEmptyText), path),
    progress: required(item, "progress", nullable(decodeUploadProgress), path),
    action,
    failure,
  };
}

function decodePipelinePolicy(value: unknown, path = "payload"): PipelinePolicy {
  const item = record(value, path);
  exact(item, ["autoNormalize", "autoUploadDerived", "uploadSourceVideo", "unsignedUploadApproved"], path);
  const policy = {
    autoNormalize: required(item, "autoNormalize", bool, path),
    autoUploadDerived: required(item, "autoUploadDerived", bool, path),
    uploadSourceVideo: required(item, "uploadSourceVideo", bool, path),
    unsignedUploadApproved: required(item, "unsignedUploadApproved", bool, path),
  };
  if (policy.uploadSourceVideo) {
    fail(`${path}.uploadSourceVideo`, "false while source archival is unavailable in V1", policy.uploadSourceVideo);
  }
  if (policy.autoUploadDerived && !policy.autoNormalize) {
    fail(`${path}.autoUploadDerived`, "false unless autoNormalize is true", policy.autoUploadDerived);
  }
  return policy;
}

export function decodeStartPipelineRequest(value: unknown, path = "payload"): StartPipelineRequest {
  const item = record(value, path);
  exact(item, ["candidateId", "approveUnsigned", "policy"], path);
  const request = {
    candidateId: asCandidateId(required(item, "candidateId", nonEmptyText, path)),
    approveUnsigned: required(item, "approveUnsigned", bool, path),
    policy: required(item, "policy", decodePipelinePolicy, path),
  };
  if (request.policy.unsignedUploadApproved) {
    fail(
      `${path}.policy.unsignedUploadApproved`,
      "false; upload approval is issued only by approve_unsigned_upload",
      request.policy.unsignedUploadApproved,
    );
  }
  return request;
}

function decodePipelineSourceSummary(value: unknown, path = "payload"): PipelineSourceSummary {
  const item = record(value, path);
  exact(
    item,
    [
      "sourceKey",
      "mediaId",
      "sourceId",
      "displayName",
      "sessionId",
      "schema",
      "sourceKind",
      "provenance",
      "relativePath",
      "bytes",
      "durationSeconds",
    ],
    path,
  );
  return {
    sourceKey: required(item, "sourceKey", nonEmptyText, path),
    mediaId: asMediaId(required(item, "mediaId", nonEmptyText, path)),
    sourceId: required(
      item,
      "sourceId",
      nullable((raw, field) => asSourceId(nonEmptyText(raw, field))),
      path,
    ),
    displayName: required(item, "displayName", nonEmptyText, path),
    sessionId: required(item, "sessionId", nullable(text), path),
    schema: required(item, "schema", (raw, field) => oneOf(SOURCE_SCHEMAS, raw, field ?? path), path),
    sourceKind: required(
      item,
      "sourceKind",
      (raw, field) =>
        oneOf(["removable_media", "legacy_removable_media", "local_folder", "lan"] as const, raw, field ?? path),
      path,
    ),
    provenance: required(item, "provenance", decodeProvenance, path),
    relativePath: required(item, "relativePath", nonEmptyText, path),
    bytes: required(item, "bytes", nonNegativeInteger, path),
    durationSeconds: required(item, "durationSeconds", nullable(nonNegativeNumber), path),
  };
}

export function decodePipelineSession(value: unknown, path = "payload"): PipelineSession {
  const item = record(value, path);
  exact(
    item,
    [
      "id",
      "candidateId",
      "sourceSummary",
      "policy",
      "desiredRunState",
      "source",
      "derived",
      "remote",
      "createdAt",
      "updatedAt",
    ],
    path,
  );
  return {
    id: asPipelineId(required(item, "id", nonEmptyText, path)),
    candidateId: asCandidateId(required(item, "candidateId", nonEmptyText, path)),
    sourceSummary: required(item, "sourceSummary", decodePipelineSourceSummary, path),
    policy: required(item, "policy", decodePipelinePolicy, path),
    desiredRunState: required(
      item,
      "desiredRunState",
      (raw, field) => oneOf(["run", "paused", "cancelled"] as const, raw, field ?? path),
      path,
    ),
    source: required(item, "source", decodeSourceLayer, path),
    derived: required(item, "derived", decodeDerivedLayer, path),
    remote: required(item, "remote", decodeRemoteLayer, path),
    createdAt: required(item, "createdAt", nonEmptyText, path),
    updatedAt: required(item, "updatedAt", nonEmptyText, path),
  };
}

export function decodeImportJobs(value: unknown, path = "payload"): readonly ImportJob[] {
  return list(value, decodeImportJob, path);
}

export function decodeDerivationJobs(value: unknown, path = "payload"): readonly DerivationJob[] {
  return list(value, decodeDerivationJob, path);
}

export function decodePipelineSessions(value: unknown, path = "payload"): readonly PipelineSession[] {
  const sessions = list(value, decodePipelineSession, path);
  const ids = new Set<string>();
  const sourceKeys = new Set<string>();
  for (const session of sessions) {
    if (ids.has(session.id)) fail(path, `unique pipeline id ${session.id}`, session.id);
    ids.add(session.id);
    if (sourceKeys.has(session.sourceSummary.sourceKey)) {
      fail(path, `unique pipeline source key ${session.sourceSummary.sourceKey}`, session.sourceSummary.sourceKey);
    }
    sourceKeys.add(session.sourceSummary.sourceKey);
  }
  return sessions;
}

function decodeImportDispatch(
  value: unknown,
  path = "payload",
): TaggedDispatchResult<ReturnType<typeof asCandidateId>, ReturnType<typeof asImportJobId>> {
  const item = record(value, path);
  const status = required(
    item,
    "status",
    (raw, field) => oneOf(["success", "failure"] as const, raw, field ?? path),
    path,
  );
  if (status === "success") {
    exact(item, ["status", "item", "jobId"], path);
    return {
      status,
      item: asCandidateId(required(item, "item", nonEmptyText, path)),
      jobId: asImportJobId(required(item, "jobId", nonEmptyText, path)),
    };
  }
  exact(item, ["status", "item", "error"], path);
  return {
    status,
    item: asCandidateId(required(item, "item", nonEmptyText, path)),
    error: required(item, "error", decodeMediaError, path),
  };
}

function decodePipelineDispatch(
  value: unknown,
  path = "payload",
): TaggedDispatchResult<ReturnType<typeof asCandidateId>, ReturnType<typeof asPipelineId>> {
  const item = record(value, path);
  const status = required(
    item,
    "status",
    (raw, field) => oneOf(["success", "failure"] as const, raw, field ?? path),
    path,
  );
  if (status === "success") {
    exact(item, ["status", "item", "jobId"], path);
    return {
      status,
      item: asCandidateId(required(item, "item", nonEmptyText, path)),
      jobId: asPipelineId(required(item, "jobId", nonEmptyText, path)),
    };
  }
  exact(item, ["status", "item", "error"], path);
  return {
    status,
    item: asCandidateId(required(item, "item", nonEmptyText, path)),
    error: required(item, "error", decodeMediaError, path),
  };
}

export function decodeImportBatchOutcome(value: unknown, path = "payload"): ImportBatchOutcome {
  const item = record(value, path);
  exact(item, ["results", "operationError"], path);
  const results = required(item, "results", (raw, field) => list(raw, decodeImportDispatch, field), path);
  const seen = new Set<string>();
  for (const result of results) {
    if (seen.has(result.item)) fail(`${path}.results`, `unique item ${result.item}`, result.item);
    seen.add(result.item);
  }
  return {
    results,
    operationError: required(item, "operationError", nullable(decodeMediaError), path),
  };
}

export function decodePipelineBatchOutcome(value: unknown, path = "payload"): PipelineBatchOutcome {
  const item = record(value, path);
  exact(item, ["results", "operationError"], path);
  const results = required(item, "results", (raw, field) => list(raw, decodePipelineDispatch, field), path);
  const seen = new Set<string>();
  for (const result of results) {
    if (seen.has(result.item)) fail(`${path}.results`, `unique item ${result.item}`, result.item);
    seen.add(result.item);
  }
  return {
    results,
    operationError: required(item, "operationError", nullable(decodeMediaError), path),
  };
}

export function decodeRevisioned<T>(value: unknown, decoder: MediaDecoder<T>, path = "payload"): Revisioned<T> {
  const item = record(value, path);
  exact(item, ["revision", "value"], path);
  return {
    revision: required(item, "revision", decodeRevision, path),
    value: required(item, "value", decoder, path),
  };
}

export function decodeMediaBackendSnapshot(value: unknown, path = "payload"): MediaBackendSnapshot {
  const item = record(value, path);
  exact(item, ["scan", "imports", "derivations", "pipelines", "library"], path);
  return {
    scan: required(item, "scan", (raw, field) => decodeRevisioned(raw, decodeMediaScanSnapshot, field), path),
    imports: required(item, "imports", (raw, field) => decodeRevisioned(raw, decodeImportJobs, field), path),
    derivations: required(
      item,
      "derivations",
      (raw, field) => decodeRevisioned(raw, decodeDerivationJobs, field),
      path,
    ),
    pipelines: required(item, "pipelines", (raw, field) => decodeRevisioned(raw, decodePipelineSessions, field), path),
    library: required(item, "library", (raw, field) => decodeRevisioned(raw, decodeMediaLibraryEntries, field), path),
  };
}
