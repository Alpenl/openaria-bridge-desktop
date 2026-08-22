import type {
  CandidateId,
  DerivationJobId,
  DerivedId,
  ImportJobId,
  MediaId,
  PipelineId,
  ProfileId,
  SourceId,
  UploadBundleId,
} from "./ids";

export const MEDIA_ERROR_CODES = [
  "invalid_input",
  "application_unavailable",
  "event_delivery_failed",
  "scan_failed",
  "media_not_found",
  "media_changed",
  "media_unavailable",
  "candidate_not_found",
  "candidate_stale",
  "source_revision_mismatch",
  "unsafe_path",
  "unsupported_schema",
  "insufficient_local_space",
  "integrity_failed",
  "import_start_failed",
  "import_command_failed",
  "derivation_start_failed",
  "derivation_command_failed",
  "encoder_unavailable",
  "resource_stuck",
  "pipeline_start_failed",
  "pipeline_command_failed",
  "policy_approval_required",
  "storage_not_configured",
  "remote_verification_failed",
  "media_export_selection_failed",
  "media_export_source_unavailable",
  "media_export_failed",
  "operation_conflict",
] as const;

export type MediaErrorCode = (typeof MEDIA_ERROR_CODES)[number];

export interface MediaError {
  readonly code: MediaErrorCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: Readonly<Record<string, unknown>>;
}

export const SOURCE_SCHEMAS = [
  "device_session_v1",
  "device_session_v2",
  "raw_capture_v2",
  "legacy_mjpeg_session_v5",
  "appliance_spool_v6",
  "complete_unpublished_v6",
  "unsigned_publication_v1",
  "signed_publication_v1",
] as const;

export type SourceSchema = (typeof SOURCE_SCHEMAS)[number];
export type SourceKind = "removable_media" | "legacy_removable_media" | "local_folder" | "lan";

export interface MediaDescriptor {
  readonly id: MediaId;
  readonly displayName: string;
  readonly mountPath: string | null;
  readonly filesystem: string | null;
  readonly presence: "present" | "removed";
  readonly readerCount: number;
  readonly handleState: "in_use" | "released";
  readonly ejectState: "unsupported" | "blocked" | "available" | "ejecting" | "ejected" | "failed";
  readonly ejectVeto: string | null;
  /**
   * Why this card is mounted and recognized yet still shows nothing, when the
   * reason is about access rather than content. `null` means no such obstacle
   * was observed, which is not a promise that the card holds recordings.
   */
  readonly accessIssue: string | null;
  readonly observedAt: string;
}

export type CandidateVerdict =
  | "ready_signed"
  | "ready_unsigned_requires_policy"
  | "pending_artifact_validation"
  | "already_imported"
  | "waiting_for_pairing_key"
  | "recording_or_encoding_incomplete"
  | "unsupported_schema"
  | "unsafe_path"
  | "insufficient_local_space"
  | "corrupt";

export interface DeviceSignedProvenance {
  readonly kind: "device_signed";
  readonly publicationKeyFingerprint: string;
  readonly manifestSignature: "valid" | "invalid";
  readonly producerKeyTrust: "trusted" | "untrusted" | "unknown";
  readonly inventoryIntegrity: "pending" | "valid" | "invalid";
}

export interface LocallyValidatedUnsignedProvenance {
  readonly kind: "locally_validated_unsigned";
  readonly sourceSchema: Exclude<SourceSchema, "signed_publication_v1">;
  readonly validationReportId: string | null;
  readonly inventoryDigest: string | null;
  readonly admission: "required" | "approved";
}

export type SourceProvenance = DeviceSignedProvenance | LocallyValidatedUnsignedProvenance;

/** Independent durable evidence for one imported source. This is separate
 * from scan candidates and pipeline control state: a card may be absent and
 * a job may be retired while this evidence remains authoritative. */
export type MediaLibrarySourceLocalProjection =
  | {
      readonly status: "verified";
      readonly evidence: {
        readonly importReceiptId: string;
        readonly importJobId: string;
        readonly relativePath: string;
        readonly sealedInventoryDigest: string;
        readonly provenance: SourceProvenance;
        readonly committedAt: string;
      };
    }
  | {
      readonly status: "removed";
      readonly evidence: {
        readonly relativePath: string;
        readonly policyRevision: string;
        readonly removedAt: string;
      };
    };

export type MediaLibraryRemoteState =
  | { readonly status: "not_verified" }
  | { readonly status: "failed"; readonly evidence: { readonly code: string; readonly retryable: boolean } }
  | {
      readonly status: "verified";
      readonly evidence: {
        readonly remoteReceiptDigest: string;
        readonly verifiedAtMs: number;
        readonly sourceArchive: MediaLibrarySourceArchive;
      };
    };

export type MediaLibrarySourceArchive =
  { readonly status: "not_included" } | { readonly status: "verified"; readonly policyRevision: string };

export type MediaLibraryCardPresence =
  | { readonly status: "unknown" }
  | {
      readonly status: "present";
      readonly mediaGenerationId: string;
      readonly observationSequence: number;
      readonly observedAtMs: number;
    }
  | {
      readonly status: "absent";
      readonly lastMediaGenerationId: string | null;
      readonly observationSequence: number;
      readonly observedAtMs: number;
    };

export interface MediaLibraryDerivedProjection {
  readonly derivationJobId: string;
  readonly profileRevision: string;
  readonly derivedRevision: string;
  readonly relativePath: string;
  readonly sourceManifestDigest: string;
  readonly committedAt: string;
}

export interface MediaLibraryUploadProjection {
  readonly bundleRevision: string;
  readonly storageProfileIdentity: string;
  readonly sourceRevision: string;
  readonly derivedRevision: string;
  readonly remote: MediaLibraryRemoteState;
}

export interface MediaLibraryEntryProjection {
  readonly entryKey: string;
  readonly sourceIdentity: string;
  readonly sourceRevision: string;
  readonly sourceLocal: MediaLibrarySourceLocalProjection;
  readonly derivedLocal: readonly MediaLibraryDerivedProjection[];
  readonly uploadBundles: readonly MediaLibraryUploadProjection[];
  readonly cardPresence: MediaLibraryCardPresence;
}

export type MediaLibraryEntryExportResult =
  | { readonly status: "cancelled" }
  | {
      readonly status: "completed";
      readonly outputPath: string;
      readonly videoSegmentCount: number;
      readonly audioSegmentCount: number;
      readonly outputSizeBytes: number;
    };

export interface MediaTrustedProducerRevocation {
  readonly keyFingerprint: string;
  readonly revoked: boolean;
}

export interface ScanCandidate {
  readonly id: CandidateId;
  readonly sourceKey: string;
  readonly mediaId: MediaId;
  readonly sourceId: SourceId | null;
  readonly sessionId: string | null;
  readonly displayName: string;
  readonly relativePath: string;
  readonly sourceKind: SourceKind;
  readonly schema: SourceSchema;
  readonly verdict: CandidateVerdict;
  readonly reason: MediaError | null;
  readonly provenance: SourceProvenance;
  readonly bytes: number;
  readonly durationSeconds: number | null;
  readonly mediaRequired: boolean;
}

export interface MediaScanSnapshot {
  readonly scanId: string;
  readonly status: "idle" | "scanning" | "complete";
  readonly media: readonly MediaDescriptor[];
  readonly candidates: readonly ScanCandidate[];
  readonly attachIssue: MediaError | null;
  readonly completedAt: string | null;
}

export type ImportJobState =
  | "queued"
  | "waiting_for_media"
  | "preflighting"
  | "copying"
  | "verifying"
  | "committing"
  | "local_verified"
  | "retry_wait"
  | "pausing"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "failed";

export interface ImportProgress {
  readonly currentFile: string | null;
  readonly copiedBytes: number;
  readonly totalBytes: number;
  readonly throughputBytesPerSecond: number | null;
  readonly etaSeconds: number | null;
}

export interface ImportJob {
  readonly id: ImportJobId;
  readonly candidateId: CandidateId;
  readonly mediaId: MediaId;
  readonly sourceId: SourceId | null;
  readonly state: ImportJobState;
  readonly desiredRunState: "run" | "paused" | "cancelled";
  readonly progress: ImportProgress;
  readonly failure: MediaError | null;
  readonly retryAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type DerivationJobState =
  | "queued"
  | "waiting_for_source"
  | "probing"
  | "planning"
  | "encoding"
  | "validating"
  | "committing"
  | "derived_verified"
  | "retry_wait"
  | "pausing"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "failed";

export interface DerivationProgress {
  readonly currentSegmentPair: number | null;
  readonly totalSegmentPairs: number | null;
  readonly processedFrames: number;
  readonly totalFrames: number | null;
  readonly encodingFps: number | null;
  readonly etaSeconds: number | null;
}

export interface ValidationProgress {
  readonly decodedSegmentPairs: number;
  readonly totalSegmentPairs: number;
}

export interface DerivationJob {
  readonly id: DerivationJobId;
  readonly sourceId: SourceId;
  readonly profileId: ProfileId;
  readonly derivedId: DerivedId | null;
  readonly state: DerivationJobState;
  readonly desiredRunState: "run" | "paused" | "cancelled";
  readonly progress: DerivationProgress;
  readonly validation: ValidationProgress;
  readonly failure: MediaError | null;
  readonly retryAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface UploadProgress {
  readonly uploadedBytes: number;
  readonly totalBytes: number;
  readonly currentPart: number | null;
  readonly totalParts: number | null;
  readonly throughputBytesPerSecond: number | null;
  readonly etaSeconds: number | null;
}

export interface RequiredAction {
  readonly kind:
    | "approve_unsigned_source"
    | "configure_storage"
    | "install_supported_encoder"
    | "resolve_policy"
    | "retry_remote_verification";
  readonly message: string;
}

export interface SourceLayer {
  readonly state:
    | "not_started"
    | "queued"
    | "waiting_for_media"
    | "preflighting"
    | "copying"
    | "verifying"
    | "committing"
    | "local_verified"
    | "retry_wait"
    | "pausing"
    | "paused"
    | "cancelling"
    | "cancelled"
    | "failed";
  readonly sourceId: SourceId | null;
  readonly jobId: ImportJobId | null;
  /** Current local-tree evidence, independent of content identity/history. */
  readonly retentionState: "retained" | "not_retained" | "unknown";
  readonly progress: ImportProgress | null;
  readonly failure: MediaError | null;
}

export interface DerivedLayer {
  readonly state:
    | "not_started"
    | "waiting_for_source"
    | "queued"
    | "probing"
    | "planning"
    | "encoding"
    | "validating"
    | "committing"
    | "derived_verified"
    | "action_required"
    | "retry_wait"
    | "pausing"
    | "paused"
    | "cancelling"
    | "cancelled"
    | "failed";
  readonly derivedId: DerivedId | null;
  readonly jobId: DerivationJobId | null;
  readonly progress: DerivationProgress | null;
  readonly validation: ValidationProgress | null;
  readonly action: RequiredAction | null;
  readonly failure: MediaError | null;
}

export interface RemoteLayer {
  readonly state:
    | "disabled"
    | "waiting_for_derived"
    | "queued"
    | "uploading"
    | "verifying"
    | "object_store_verified"
    | "action_required"
    | "retry_wait"
    | "pausing"
    | "paused"
    | "cancelling"
    | "cancelled"
    | "failed";
  readonly bundleId: UploadBundleId | null;
  readonly uploadJobId: string | null;
  readonly progress: UploadProgress | null;
  readonly action: RequiredAction | null;
  readonly failure: MediaError | null;
}

export interface PipelinePolicy {
  readonly autoNormalize: boolean;
  readonly autoUploadDerived: boolean;
  readonly uploadSourceVideo: boolean;
  readonly unsignedUploadApproved: boolean;
}

/** Ubuntu removable-media MVP policy: durable local import only. */
export const IMPORT_ONLY_PIPELINE_POLICY: PipelinePolicy = {
  autoNormalize: false,
  autoUploadDerived: false,
  uploadSourceVideo: false,
  unsignedUploadApproved: false,
};

/** Immutable presentation/provenance facts copied into the durable pipeline.
 * A current scan may legitimately forget a removed card; recovery rows must
 * still explain which source and media generation they are waiting for. */
export interface PipelineSourceSummary {
  readonly sourceKey: string;
  readonly mediaId: MediaId;
  readonly sourceId: SourceId | null;
  readonly displayName: string;
  readonly sessionId: string | null;
  readonly schema: SourceSchema;
  readonly sourceKind: SourceKind;
  readonly provenance: SourceProvenance;
  readonly relativePath: string;
  readonly bytes: number;
  readonly durationSeconds: number | null;
}

/** No aggregate percentage exists by design. Each durable layer reports only
 * the evidence and progress it actually owns. */
export interface PipelineSession {
  readonly id: PipelineId;
  readonly candidateId: CandidateId;
  readonly sourceSummary: PipelineSourceSummary;
  readonly policy: PipelinePolicy;
  readonly desiredRunState: "run" | "paused" | "cancelled";
  readonly source: SourceLayer;
  readonly derived: DerivedLayer;
  readonly remote: RemoteLayer;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type MediaJobCommand = "pause" | "resume" | "cancel" | "retry";
export type PipelineCommand = MediaJobCommand | "approve_unsigned_upload";

export interface ScanRequest {
  readonly source: { readonly kind: "mounted_volumes" } | { readonly kind: "selected_folder"; readonly path: string };
}

export interface StartImportRequest {
  readonly candidateId: CandidateId;
  readonly approveUnsigned: boolean;
}

export interface StartDerivationRequest {
  readonly sourceId: SourceId;
  readonly profileId: ProfileId;
}

export interface StartPipelineRequest {
  readonly candidateId: CandidateId;
  readonly approveUnsigned: boolean;
  readonly policy: PipelinePolicy;
}

export type TaggedDispatchResult<TItem, TJob> =
  | { readonly status: "success"; readonly item: TItem; readonly jobId: TJob }
  | { readonly status: "failure"; readonly item: TItem; readonly error: MediaError };

export interface ImportBatchOutcome {
  readonly results: readonly TaggedDispatchResult<CandidateId, ImportJobId>[];
  readonly operationError: MediaError | null;
}

export interface PipelineBatchOutcome {
  readonly results: readonly TaggedDispatchResult<CandidateId, PipelineId>[];
  readonly operationError: MediaError | null;
}

export const MEDIA_BATCH_LIMIT = 256;

export class MediaBatchContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MediaBatchContractError";
  }
}

export function validateMediaBatchRequests<T extends { readonly candidateId: CandidateId }>(
  requests: readonly T[],
): readonly T[] {
  if (requests.length === 0) throw new MediaBatchContractError("media batch must not be empty");
  if (requests.length > MEDIA_BATCH_LIMIT) {
    throw new MediaBatchContractError(`media batch exceeds ${MEDIA_BATCH_LIMIT} items`);
  }
  const seen = new Set<CandidateId>();
  for (const request of requests) {
    if (seen.has(request.candidateId)) {
      throw new MediaBatchContractError(`media batch repeats candidate ${request.candidateId}`);
    }
    seen.add(request.candidateId);
  }
  return requests;
}

/** A tagged result still fails closed if the server omitted, duplicated or
 * invented an item. Duplicate request values intentionally expect one result. */
export function validateImportBatchCoverage(
  requested: readonly StartImportRequest[],
  outcome: ImportBatchOutcome,
): ImportBatchOutcome {
  const expected = new Set(requested.map((request) => request.candidateId));
  const seen = new Set<CandidateId>();
  for (const result of outcome.results) {
    if (!expected.has(result.item)) {
      throw new MediaBatchContractError(`backend returned unexpected candidate ${result.item}`);
    }
    if (seen.has(result.item)) {
      throw new MediaBatchContractError(`backend returned candidate ${result.item} more than once`);
    }
    seen.add(result.item);
  }
  const missing = [...expected].filter((candidateId) => !seen.has(candidateId));
  if (missing.length > 0) {
    throw new MediaBatchContractError(`backend omitted candidates: ${missing.join(", ")}`);
  }
  return outcome;
}

export function validatePipelineBatchCoverage(
  requested: readonly StartPipelineRequest[],
  outcome: PipelineBatchOutcome,
): PipelineBatchOutcome {
  const expected = new Set(requested.map((request) => request.candidateId));
  const seen = new Set<CandidateId>();
  for (const result of outcome.results) {
    if (!expected.has(result.item)) {
      throw new MediaBatchContractError(`backend returned unexpected candidate ${result.item}`);
    }
    if (seen.has(result.item)) {
      throw new MediaBatchContractError(`backend returned candidate ${result.item} more than once`);
    }
    seen.add(result.item);
  }
  const missing = [...expected].filter((candidateId) => !seen.has(candidateId));
  if (missing.length > 0) {
    throw new MediaBatchContractError(`backend omitted candidates: ${missing.join(", ")}`);
  }
  return outcome;
}

export interface BatchSummary {
  readonly succeeded: number;
  readonly processing: number;
  readonly actionRequired: number;
  readonly failed: number;
}

export function summarizePipelines(pipelines: readonly PipelineSession[]): BatchSummary {
  let succeeded = 0;
  let processing = 0;
  let actionRequired = 0;
  let failed = 0;
  for (const pipeline of pipelines) {
    if (pipeline.remote.state === "object_store_verified") succeeded += 1;
    else if (
      pipeline.source.state === "failed" ||
      pipeline.derived.state === "failed" ||
      pipeline.remote.state === "failed"
    )
      failed += 1;
    else if (pipeline.derived.state === "action_required" || pipeline.remote.state === "action_required")
      actionRequired += 1;
    else processing += 1;
  }
  return { succeeded, processing, actionRequired, failed };
}
