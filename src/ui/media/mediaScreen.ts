import { bindings, delegate, el, type Unbind } from "../dom";
import { mediaContentHtml, mediaTopbarHtml } from "./render";
import type { MediaJobCommand, MediaJobKind, MediaWorkspaceDispatch, MediaWorkspaceSnapshot } from "./types";
import type { MediaResourceName } from "../../runtime/media/backend";

export interface MediaScreenRoots {
  readonly topbar: HTMLElement;
  readonly content: HTMLElement;
}

export interface MediaScreen {
  render(snapshot: MediaWorkspaceSnapshot): void;
  renderTopbar(snapshot: MediaWorkspaceSnapshot): void;
  renderContent(snapshot: MediaWorkspaceSnapshot): void;
  dispose(): void;
}

const JOB_KINDS: readonly MediaJobKind[] = ["import", "derivation", "validation", "upload"];
const JOB_COMMANDS: readonly MediaJobCommand[] = ["pause", "resume", "retry", "cancel"];
const RESOURCE_NAMES: readonly MediaResourceName[] = ["scan", "imports", "derivations", "pipelines", "library"];

function memberOf<T extends string>(value: string | undefined, values: readonly T[]): value is T {
  return value !== undefined && values.some((candidate) => candidate === value);
}

function nonEmpty(value: string | undefined): value is string {
  return value !== undefined && value.length > 0;
}

function defaultRoots(): MediaScreenRoots {
  return { topbar: el("topbar"), content: el("content") };
}

export function createMediaScreen(dispatch: MediaWorkspaceDispatch, suppliedRoots?: MediaScreenRoots): MediaScreen {
  const roots = suppliedRoots ?? defaultRoots();
  const bound = bindings();
  let currentSnapshot: MediaWorkspaceSnapshot | null = null;

  const dispatchSimpleTopbarAction = (action: string | undefined): void => {
    if (action === "scan-all") dispatch({ kind: "media/scanAll" });
  };

  bound.add(
    delegate(roots.topbar, "click", "button[data-media-action]", (matched) => {
      dispatchSimpleTopbarAction(matched.dataset.mediaAction);
    }),
  );

  bound.add(
    delegate(roots.content, "click", "[data-media-action]", (matched, event) => {
      const action = matched.dataset.mediaAction;
      if (action === "scan-all") {
        dispatch({ kind: "media/scanAll" });
        return;
      }
      if (action === "retry-resource") {
        const resource = matched.dataset.resource;
        if (memberOf(resource, RESOURCE_NAMES)) dispatch({ kind: "media/retryResource", resource });
        return;
      }
      if (action === "revoke-trusted-producer") {
        const keyFingerprint = matched.dataset.keyFingerprint;
        if (nonEmpty(keyFingerprint)) dispatch({ kind: "media/revokeTrustedProducer", keyFingerprint });
        return;
      }
      if (action === "export-library-entry") {
        const entryKey = matched.dataset.entryKey;
        if (nonEmpty(entryKey)) dispatch({ kind: "media/exportLibraryEntry", entryKey });
        return;
      }
      if (action === "toggle-candidate") {
        const target = event.target;
        if (!(target instanceof Element) || target.closest("button, input, a")) return;
        const candidateId = matched.dataset.candidateId;
        if (nonEmpty(candidateId)) dispatch({ kind: "media/toggleCandidateDetails", candidateId });
        return;
      }
      if (action === "rescan-source" || action === "release-source" || action === "eject-source") {
        const sourceId = matched.dataset.sourceId;
        if (!nonEmpty(sourceId)) return;
        if (action === "rescan-source") dispatch({ kind: "media/rescanSource", sourceId });
        if (action === "release-source") dispatch({ kind: "media/releaseSource", sourceId });
        if (action === "eject-source") dispatch({ kind: "media/ejectSource", sourceId });
        return;
      }
      if (action === "import-selected") {
        const candidateIds =
          currentSnapshot?.candidates
            .filter((candidate) => candidate.selectable && candidate.selected)
            .map((candidate) => candidate.id) ?? [];
        if (candidateIds.length > 0) dispatch({ kind: "media/importSelected", candidateIds });
        return;
      }
      if (action === "configure-storage") {
        dispatch({ kind: "media/configureStorage" });
        return;
      }
      if (action === "approve-unsigned-upload") {
        const pipelineId = matched.dataset.pipelineId;
        if (nonEmpty(pipelineId)) dispatch({ kind: "media/approveUnsignedUpload", pipelineId });
        return;
      }
      if (action === "job-command") {
        const pipelineId = matched.dataset.pipelineId;
        const jobId = matched.dataset.jobId;
        const jobKind = matched.dataset.jobKind;
        const command = matched.dataset.jobCommand;
        if (
          nonEmpty(pipelineId) &&
          nonEmpty(jobId) &&
          memberOf(jobKind, JOB_KINDS) &&
          memberOf(command, JOB_COMMANDS)
        ) {
          dispatch({ kind: "media/jobCommand", pipelineId, jobId, jobKind, command });
        }
        return;
      }
      if (action === "cancel-batch" || action === "dismiss-batch") {
        const batchId = matched.dataset.batchId;
        if (!nonEmpty(batchId)) return;
        dispatch(
          action === "cancel-batch" ? { kind: "media/cancelBatch", batchId } : { kind: "media/dismissBatch", batchId },
        );
      }
    }),
  );

  bound.add(
    delegate(roots.content, "keydown", '[data-media-action="toggle-candidate"]', (matched, event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const target = event.target;
      if (!(target instanceof Element) || target.closest("button, input, a")) return;
      const candidateId = matched.dataset.candidateId;
      if (!nonEmpty(candidateId)) return;
      event.preventDefault();
      dispatch({ kind: "media/toggleCandidateDetails", candidateId });
    }),
  );

  bound.add(
    delegate(roots.content, "change", "input[data-media-select-candidate]", (matched) => {
      const candidateId = matched.dataset.mediaSelectCandidate;
      if (!nonEmpty(candidateId)) return;
      dispatch({
        kind: "media/candidateSelectionChange",
        candidateId,
        selected: (matched as HTMLInputElement).checked,
      });
    }),
  );

  bound.add(
    delegate(roots.content, "change", "input[data-media-select-all]", (matched) => {
      dispatch({ kind: "media/allCandidateSelectionChange", selected: (matched as HTMLInputElement).checked });
    }),
  );

  function syncSelectAll(snapshot: MediaWorkspaceSnapshot): void {
    const checkbox = roots.content.querySelector<HTMLInputElement>("input[data-media-select-all]");
    if (checkbox === null) return;
    const selectable = snapshot.candidates.filter((candidate) => candidate.selectable);
    const selected = selectable.filter((candidate) => candidate.selected).length;
    checkbox.checked = selectable.length > 0 && selected === selectable.length;
    checkbox.indeterminate = selected > 0 && selected < selectable.length;
  }

  function renderTopbar(snapshot: MediaWorkspaceSnapshot): void {
    currentSnapshot = snapshot;
    roots.topbar.innerHTML = mediaTopbarHtml(snapshot);
  }

  function renderContent(snapshot: MediaWorkspaceSnapshot): void {
    currentSnapshot = snapshot;
    roots.content.innerHTML = mediaContentHtml(snapshot);
    syncSelectAll(snapshot);
  }

  function render(snapshot: MediaWorkspaceSnapshot): void {
    renderTopbar(snapshot);
    renderContent(snapshot);
  }

  return { render, renderTopbar, renderContent, dispose: bound.dispose };
}

export type { Unbind };
