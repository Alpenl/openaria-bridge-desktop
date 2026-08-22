declare const mediaIdBrand: unique symbol;

type MediaBranded<Kind extends string> = string & { readonly [mediaIdBrand]: Kind };

/** One observed removable-media generation, not a mount path or drive letter. */
export type MediaId = MediaBranded<"MediaId">;
/** One bounded scanner result. It is only provisional until admitted. */
export type CandidateId = MediaBranded<"CandidateId">;
/** Stable source-content identity after trust/admission and full hashing. */
export type SourceId = MediaBranded<"SourceId">;
/** A durable source-copy job. */
export type ImportJobId = MediaBranded<"ImportJobId">;
/** A durable normalization job. */
export type DerivationJobId = MediaBranded<"DerivationJobId">;
/** The policy/dependency aggregate for one recording workflow. */
export type PipelineId = MediaBranded<"PipelineId">;
/** Versioned normalization parameters and encoder compatibility class. */
export type ProfileId = MediaBranded<"ProfileId">;
/** Immutable derived-manifest identity. */
export type DerivedId = MediaBranded<"DerivedId">;
/** Immutable object set sent to one storage profile. */
export type UploadBundleId = MediaBranded<"UploadBundleId">;
/** One destructive confirmation attempt. */
export type MediaOperationId = MediaBranded<"MediaOperationId">;

export function asMediaId(raw: string): MediaId {
  return raw as MediaId;
}

export function asCandidateId(raw: string): CandidateId {
  return raw as CandidateId;
}

export function asSourceId(raw: string): SourceId {
  return raw as SourceId;
}

export function asImportJobId(raw: string): ImportJobId {
  return raw as ImportJobId;
}

export function asDerivationJobId(raw: string): DerivationJobId {
  return raw as DerivationJobId;
}

export function asPipelineId(raw: string): PipelineId {
  return raw as PipelineId;
}

export function asProfileId(raw: string): ProfileId {
  return raw as ProfileId;
}

export function asDerivedId(raw: string): DerivedId {
  return raw as DerivedId;
}

export function asUploadBundleId(raw: string): UploadBundleId {
  return raw as UploadBundleId;
}

export function asMediaOperationId(raw: string): MediaOperationId {
  return raw as MediaOperationId;
}
