import { acceptedItems, rejectedItems, type AnyBatchItem } from "./runtime/batch";

export interface BatchFeedback {
  message: string;
  tone: "success" | "danger";
}

/** One toast for a batch, read off the per-item outcomes rather than off
 * parallel arrays: an item's failure text is the one recorded against that
 * item, so no message can attribute an error to the wrong session or entry. */
export function batchFeedback(action: string, items: readonly AnyBatchItem<string>[]): BatchFeedback {
  const accepted = acceptedItems(items);
  const rejected = rejectedItems(items);
  if (rejected.length === 0) {
    return {
      message: `${action} · ${accepted.length} 项`,
      tone: "success",
    };
  }

  const shown = rejected
    .slice(0, 2)
    .map((failure) => `${failure.item}: ${failure.error.message}`)
    .join("；");
  const omitted = rejected.length - 2;
  const suffix = omitted > 0 ? `；另有 ${omitted} 项失败` : "";
  return {
    message: `${action}：成功 ${accepted.length} 项，失败 ${rejected.length} 项；${shown}${suffix}`,
    tone: "danger",
  };
}
