// Per-item batch outcomes. The Rust wire contract already tags each result;
// this module only brands its identities and verifies that every unique
// requested item received exactly one verdict.

import type { BatchJobResult, BatchOutcome, RpcError } from "../types";

/** What a batch command did to one item it was given. */
export type BatchItem<TId> =
  | { readonly status: "ok"; readonly item: TId }
  | { readonly status: "failed"; readonly item: TId; readonly error: RpcError };

/** What a job-dispatching batch command did to one item. A successful wire
 * result cannot exist without the durable job ID owned by that same item. */
export type DispatchItem<TId, TJob> =
  | { readonly status: "queued"; readonly item: TId; readonly jobId: TJob }
  | { readonly status: "failed"; readonly item: TId; readonly error: RpcError };

export type AnyBatchItem<TId> = BatchItem<TId> | DispatchItem<TId, unknown>;

/** The items a batch accepted. */
export function acceptedItems<TId>(items: readonly AnyBatchItem<TId>[]): TId[] {
  return items.filter((item) => item.status !== "failed").map((item) => item.item);
}

/** The items a batch rejected, with the backend's structured error. */
export function rejectedItems<TId>(items: readonly AnyBatchItem<TId>[]): { item: TId; error: RpcError }[] {
  return items.flatMap((item) => (item.status === "failed" ? [{ item: item.item, error: item.error }] : []));
}

/** The job the backend created for one specific item, or `null` when that item
 * failed or was not part of the result. */
export function jobIdFor<TId, TJob>(items: readonly DispatchItem<TId, TJob>[], item: TId): TJob | null {
  const found = items.find((candidate) => candidate.item === item);
  return found !== undefined && found.status === "queued" ? found.jobId : null;
}

export function batchFailed<TId>(items: readonly AnyBatchItem<TId>[]): boolean {
  return items.some((item) => item.status === "failed");
}

export class BatchContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BatchContractError";
  }
}

function validateCoverage(requested: readonly string[] | undefined, results: readonly { item: string }[]): void {
  if (requested === undefined) return;
  const expected = [...new Set(requested)];
  const expectedSet = new Set(expected);
  const seen = new Set<string>();
  for (const result of results) {
    if (!expectedSet.has(result.item)) {
      throw new BatchContractError(`backend returned an unexpected batch item: ${result.item}`);
    }
    if (seen.has(result.item)) {
      throw new BatchContractError(`backend returned duplicate results for batch item: ${result.item}`);
    }
    seen.add(result.item);
  }
  const missing = expected.filter((item) => !seen.has(item));
  if (missing.length > 0) {
    throw new BatchContractError(`backend omitted batch results for: ${missing.join(", ")}`);
  }
}

/** Brands an already-tagged mutation result. Duplicate request values use the
 * backend's existing unique-item semantics and therefore expect one result. */
export function toBatchItems<TId>(
  raw: BatchOutcome,
  brandItem: (raw: string) => TId,
  requested?: readonly string[],
): BatchItem<TId>[] {
  validateCoverage(requested, raw.results);
  return raw.results.map((result): BatchItem<TId> =>
    result.status === "success"
      ? { status: "ok", item: brandItem(result.item) }
      : { status: "failed", item: brandItem(result.item), error: result.error },
  );
}

/** Brands an already-tagged job result; `jobId` is read from the same object
 * as its `item`, never from another array or request position. */
export function toDispatchItems<TId, TJob>(
  raw: BatchJobResult,
  brandItem: (raw: string) => TId,
  brandJob: (raw: string) => TJob,
  requested?: readonly string[],
): DispatchItem<TId, TJob>[] {
  validateCoverage(requested, raw.results);
  return raw.results.map((result): DispatchItem<TId, TJob> =>
    result.status === "success"
      ? { status: "queued", item: brandItem(result.item), jobId: brandJob(result.jobId) }
      : { status: "failed", item: brandItem(result.item), error: result.error },
  );
}
