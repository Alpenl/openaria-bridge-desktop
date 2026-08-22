import { escapeAttr, escapeHtml, formatBytes } from "../../format";
import type { MediaResourceName } from "../../runtime/media/backend";
import type {
  DerivedLocalState,
  MediaAcquisitionSourceSnapshot,
  MediaBatchItemOutcome,
  MediaBatchSnapshot,
  MediaCandidateSnapshot,
  MediaCandidateAcquisitionKind,
  MediaCandidateVerdictKind,
  MediaDerivationProgress,
  MediaImportProgress,
  MediaJobCommand,
  MediaJobKind,
  MediaJobSnapshot,
  MediaLibraryEntryProjection,
  MediaJobState,
  MediaPipelineSnapshot,
  MediaProvenance,
  MediaReleaseSnapshot,
  MediaRequirement,
  MediaSourceKind,
  MediaUploadProgress,
  MediaValidationProgress,
  MediaWorkspaceSnapshot,
  RemoteState,
  SourceLocalState,
} from "./types";

type Tone = "idle" | "progress" | "ok" | "warn" | "danger";

function finiteNonNegative(value: number): number {
  return Number.isFinite(value) ? Math.max(0, value) : 0;
}

function safeCount(value: number): number {
  return Math.floor(finiteNonNegative(value));
}

function bytesText(value: number): string {
  return formatBytes(finiteNonNegative(value));
}

function formatEta(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) return "ETA --";
  const rounded = Math.ceil(seconds);
  if (rounded < 60) return `ETA ${rounded} 秒`;
  const minutes = Math.ceil(rounded / 60);
  if (minutes < 60) return `ETA ${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `ETA ${hours} 小时 ${remainingMinutes} 分钟`;
}

function formatDuration(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) return "时长未知";
  const total = Math.floor(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const remainingSeconds = total % 60;
  const two = (part: number): string => String(part).padStart(2, "0");
  return hours > 0 ? `${hours}:${two(minutes)}:${two(remainingSeconds)}` : `${two(minutes)}:${two(remainingSeconds)}`;
}

function rateText(bytesPerSecond: number | null): string {
  if (bytesPerSecond === null || !Number.isFinite(bytesPerSecond) || bytesPerSecond < 0) return "--/s";
  return `${bytesText(bytesPerSecond)}/s`;
}

function percent(completed: number, total: number): number | null {
  if (!Number.isFinite(completed) || !Number.isFinite(total) || total <= 0) return null;
  return Math.min(100, Math.max(0, (completed / total) * 100));
}

function chip(label: string, tone: Tone): string {
  return `<span class="media-chip" data-tone="${tone}">${escapeHtml(label)}</span>`;
}

function scanLabel(snapshot: MediaWorkspaceSnapshot): string {
  switch (snapshot.scan.state) {
    case "idle":
      return "尚未扫描";
    case "scanning":
      return `正在扫描 ${safeCount(snapshot.scan.sourceCount)} 个来源`;
    case "ready":
      return `已发现 ${safeCount(snapshot.scan.candidateCount)} 个录制会话`;
    case "failed":
      return "扫描未完成";
  }
}

function scanTone(state: MediaWorkspaceSnapshot["scan"]["state"]): Tone {
  switch (state) {
    case "idle":
      return "idle";
    case "scanning":
      return "progress";
    case "ready":
      return "ok";
    case "failed":
      return "danger";
  }
}

export function mediaTopbarHtml(snapshot: MediaWorkspaceSnapshot): string {
  const scanning = snapshot.scan.state === "scanning";
  const completed = snapshot.scan.lastCompletedAtLabel;
  const scope = "Ubuntu/Linux TF 卡 MVP；Windows/macOS 与 exFAT 录制目标后续支持";
  const sub =
    completed === null ? `${scanLabel(snapshot)} · ${scope}` : `${scanLabel(snapshot)} · ${completed} · ${scope}`;
  return (
    `<div class="topbar-identity media-topbar-identity">` +
    `<span class="media-status-dot" data-tone="${scanTone(snapshot.scan.state)}" aria-hidden="true"></span>` +
    `<div><h1>介质导入</h1><div class="sub">${escapeHtml(sub)}</div></div></div>` +
    `<div class="topbar-actions">` +
    `<button type="button" class="btn btn-primary" data-media-action="scan-all" ${scanning ? "disabled" : ""}>${
      scanning ? "扫描中…" : "扫描介质"
    }</button></div>`
  );
}

function sourceScanLabel(source: MediaAcquisitionSourceSnapshot): string {
  if (source.availability === "missing") return "来源已断开";
  switch (source.scanState) {
    case "idle":
      return "等待扫描";
    case "queued":
      return "等待扫描";
    case "scanning":
      return "扫描中";
    case "complete":
      return `${safeCount(source.candidateCount)} 个会话`;
    case "failed":
      return "扫描失败";
  }
}

function sourceScanTone(source: MediaAcquisitionSourceSnapshot): Tone {
  if (source.availability === "missing") return "warn";
  switch (source.scanState) {
    case "idle":
    case "queued":
      return "idle";
    case "scanning":
      return "progress";
    case "complete":
      return "ok";
    case "failed":
      return "danger";
  }
}

function releasePresentation(release: MediaReleaseSnapshot): {
  label: string;
  tone: Tone;
  detail: string | null;
  action: "release" | "eject" | null;
  actionLabel: string | null;
  disabled: boolean;
} {
  switch (release.kind) {
    case "not_applicable":
      return { label: "本地目录", tone: "idle", detail: null, action: null, actionLabel: null, disabled: false };
    case "in_use":
      return {
        label: "卡仍需连接",
        tone: "progress",
        detail: `${safeCount(release.activeReaders)} 个导入读取器仍在使用`,
        action: null,
        actionLabel: null,
        disabled: false,
      };
    case "ready":
      return {
        label: "可释放应用句柄",
        tone: "warn",
        detail: null,
        action: "release",
        actionLabel: "释放介质",
        disabled: false,
      };
    case "releasing":
      return {
        label: "正在释放应用句柄",
        tone: "progress",
        detail: null,
        action: "release",
        actionLabel: "释放中…",
        disabled: true,
      };
    case "released":
      return release.platformEjectSupported
        ? {
            label: "应用句柄已释放",
            tone: "ok",
            detail: null,
            action: "eject",
            actionLabel: "系统安全弹出",
            disabled: false,
          }
        : {
            label: "应用已释放，可在系统中安全移除",
            tone: "ok",
            detail: null,
            action: null,
            actionLabel: null,
            disabled: false,
          };
    case "ejecting":
      return {
        label: "正在请求系统弹出",
        tone: "progress",
        detail: null,
        action: "eject",
        actionLabel: "弹出中…",
        disabled: true,
      };
    case "ejected":
      return { label: "系统已弹出", tone: "ok", detail: null, action: null, actionLabel: null, disabled: false };
    case "release_failed":
      return {
        label: "应用句柄释放失败",
        tone: "danger",
        detail: release.issue.message,
        action: release.issue.retryable ? "release" : null,
        actionLabel: release.issue.retryable ? "重试释放" : null,
        disabled: false,
      };
    case "eject_vetoed":
      return {
        label: "系统阻止弹出",
        tone: "warn",
        detail: release.reason,
        action: "eject",
        actionLabel: "重试弹出",
        disabled: false,
      };
    case "eject_failed":
      return {
        label: "系统弹出失败",
        tone: "danger",
        detail: release.issue.message,
        action: release.issue.retryable ? "eject" : null,
        actionLabel: release.issue.retryable ? "重试弹出" : null,
        disabled: false,
      };
    case "removed":
      return { label: "介质已移除", tone: "idle", detail: null, action: null, actionLabel: null, disabled: false };
  }
}

function sourceRowHtml(source: MediaAcquisitionSourceSnapshot): string {
  const sourceIdAttr = escapeAttr(source.id);
  const release = releasePresentation(source.release);
  const details = [source.fileSystem, source.capacityBytes === null ? null : bytesText(source.capacityBytes)]
    .filter((part): part is string => part !== null && part.length > 0)
    .join(" · ");
  const scanIssue =
    source.scanIssue === null
      ? ""
      : `<div class="media-inline-issue" data-tone="danger"><span>${escapeHtml(source.scanIssue.message)}</span></div>`;
  const releaseDetail =
    release.detail === null ? "" : `<span class="media-source-note">${escapeHtml(release.detail)}</span>`;
  const releaseButton =
    release.action === null || release.actionLabel === null
      ? ""
      : `<button type="button" class="btn btn-sm ${release.action === "eject" ? "btn-primary" : "btn-ghost"}" data-media-action="${
          release.action === "eject" ? "eject-source" : "release-source"
        }" data-source-id="${sourceIdAttr}" ${release.disabled ? "disabled" : ""}>${escapeHtml(release.actionLabel)}</button>`;

  return (
    `<article class="media-source-row" data-availability="${source.availability}">` +
    `<div class="media-source-main"><span class="media-source-kind" aria-hidden="true">${
      source.kind === "removable_media" || source.kind === "legacy_removable_media" ? "卡" : "目录"
    }</span>` +
    `<span class="media-source-name"><strong>${escapeHtml(source.displayName)}</strong>` +
    `<span class="mono" title="${escapeAttr(source.locationLabel)}">${escapeHtml(source.locationLabel)}</span></span></div>` +
    `<span class="media-source-meta">${escapeHtml(details || "文件系统未知")}</span>` +
    `<span>${chip(sourceScanLabel(source), sourceScanTone(source))}</span>` +
    `<span class="media-release-state">${chip(release.label, release.tone)}${releaseDetail}</span>` +
    `<span class="media-row-actions"><button type="button" class="btn btn-ghost btn-sm" data-media-action="rescan-source" data-source-id="${sourceIdAttr}" ${
      source.availability === "missing" || source.scanState === "scanning" ? "disabled" : ""
    }>重新扫描</button>${releaseButton}</span>${scanIssue}</article>`
  );
}

function sourcesHtml(snapshot: MediaWorkspaceSnapshot): string {
  const sourceRows =
    snapshot.sources.length === 0
      ? `<div class="media-empty-inline">未检测到已挂载介质或已选择目录</div>`
      : `<div class="media-source-list">${snapshot.sources.map(sourceRowHtml).join("")}</div>`;
  return (
    `<section class="media-band" aria-labelledby="mediaSourcesHeading">` +
    `<div class="media-section-head"><div><h2 id="mediaSourcesHeading">介质与目录</h2>` +
    `<span>${safeCount(snapshot.sources.length)} 个来源</span></div></div>${sourceRows}</section>`
  );
}

function libraryCardPresenceLabel(entry: MediaLibraryEntryProjection): { label: string; tone: Tone } {
  switch (entry.cardPresence.status) {
    case "present":
      return { label: "原卡在场", tone: "ok" };
    case "absent":
      return { label: "原卡已移除", tone: "warn" };
    case "unknown":
      return { label: "原卡状态未知", tone: "idle" };
  }
  return { label: "原卡状态未知", tone: "idle" };
}

function librarySourceLabel(entry: MediaLibraryEntryProjection): { label: string; tone: Tone } {
  return entry.sourceLocal.status === "verified"
    ? { label: "本地源已验证", tone: "ok" }
    : { label: "本地源已移除", tone: "warn" };
}

function libraryEntryHtml(entry: MediaLibraryEntryProjection): string {
  const source = librarySourceLabel(entry);
  const card = libraryCardPresenceLabel(entry);
  const verifiedUploads = entry.uploadBundles.filter((bundle) => bundle.remote.status === "verified").length;
  const sourceEvidence = entry.sourceLocal.status === "verified" ? entry.sourceLocal.evidence : null;
  const sourcePath = entry.sourceLocal.evidence.relativePath;
  const provenance = sourceEvidence === null ? "来源证明已移除" : provenanceHtml(sourceEvidence.provenance);
  const exportButton =
    sourceEvidence === null
      ? ""
      : `<button type="button" class="btn btn-primary btn-sm" data-media-action="export-library-entry" data-entry-key="${escapeAttr(
          entry.entryKey,
        )}">导出 MP4</button>`;
  const revokeButton =
    sourceEvidence?.provenance.kind === "device_signed"
      ? `<button type="button" class="btn btn-ghost btn-sm" data-media-action="revoke-trusted-producer" data-key-fingerprint="${escapeAttr(
          sourceEvidence.provenance.publicationKeyFingerprint,
        )}">撤销此来源信任</button>`
      : "";
  return (
    `<article class="media-source-row" data-library-entry="${escapeAttr(entry.entryKey)}">` +
    `<div class="media-source-main"><span class="media-source-kind" aria-hidden="true">库</span>` +
    `<span class="media-source-name"><strong>${escapeHtml(entry.sourceIdentity)}</strong>` +
    `<span class="mono" title="${escapeAttr(entry.sourceRevision)}">${escapeHtml(entry.sourceRevision)}</span></span></div>` +
    `<span class="media-source-meta mono" title="${escapeAttr(sourcePath)}">${escapeHtml(sourcePath)}</span>` +
    `<span>${chip(source.label, source.tone)}</span>` +
    `<span>${chip(card.label, card.tone)}</span>` +
    `<span class="media-source-note">${safeCount(entry.derivedLocal.length)} 个已验证派生 · ${safeCount(
      verifiedUploads,
    )} 个远端已验证</span>` +
    `<div class="media-detail-meta"><span><small>来源证明</small>${provenance}</span>` +
    `<span><small>Entry key</small><span class="mono media-breakable">${escapeHtml(entry.entryKey)}</span></span></div>` +
    `<div class="media-row-actions">${exportButton}${revokeButton}</div>` +
    `</article>`
  );
}

function libraryHtml(snapshot: MediaWorkspaceSnapshot): string {
  const rows =
    snapshot.library.length === 0
      ? `<div class="media-empty-inline">尚无已提交的本地媒体库证据</div>`
      : `<div class="media-source-list">${snapshot.library.map(libraryEntryHtml).join("")}</div>`;
  return (
    `<section class="media-band" aria-labelledby="mediaLibraryHeading">` +
    `<div class="media-section-head"><div><h2 id="mediaLibraryHeading">媒体库证据</h2>` +
    `<span>${safeCount(snapshot.library.length)} 个已记录来源</span></div></div>${rows}</section>`
  );
}

function verdictPresentation(kind: MediaCandidateVerdictKind): { label: string; tone: Tone } {
  switch (kind) {
    case "ready_signed":
      return { label: "签名来源，可导入", tone: "ok" };
    case "ready_unsigned_requires_policy":
      return { label: "未签名，需策略确认", tone: "warn" };
    case "pending_artifact_validation":
      return { label: "待导入校验", tone: "warn" };
    case "already_imported":
      return { label: "已导入", tone: "ok" };
    case "waiting_for_pairing_key":
      return { label: "等待配对密钥", tone: "warn" };
    case "recording_or_encoding_incomplete":
      return { label: "录制或编码未完成", tone: "warn" };
    case "unsupported_schema":
      return { label: "版本不受支持", tone: "danger" };
    case "unsafe_path":
      return { label: "路径不安全", tone: "danger" };
    case "insufficient_local_space":
      return { label: "本地空间不足", tone: "danger" };
    case "corrupt":
      return { label: "内容损坏", tone: "danger" };
  }
}

function sourceKindLabel(kind: MediaSourceKind): string {
  switch (kind) {
    case "device_session_v1":
      return "Device session v1";
    case "device_session_v2":
      return "Device session v2";
    case "signed_publication_v1":
      return "Signed publication v1";
    case "raw_capture_v2":
      return "Raw capture v2";
    case "legacy_mjpeg_session_v5":
      return "Legacy MJPEG v5";
    case "appliance_spool_v6":
      return "Appliance spool v6";
    case "complete_unpublished_v6":
      return "完整未发布会话 v6";
    case "unsigned_publication_v1":
      return "未签名发布 v1";
  }
}

function mediaRequirementPresentation(
  requirement: MediaRequirement,
  acquisitionKind: MediaCandidateAcquisitionKind,
): { label: string; tone: Tone } {
  const removable = acquisitionKind === "removable_media" || acquisitionKind === "legacy_removable_media";
  switch (requirement) {
    case "required":
      return { label: removable ? "卡仍需连接" : "目录仍需可用", tone: "progress" };
    case "waiting_for_media":
      return { label: removable ? "等待原介质" : "等待来源目录", tone: "warn" };
    case "not_required":
      return { label: removable ? "卡可移除" : "来源可断开", tone: "ok" };
    case "not_applicable":
      return { label: "无需介质", tone: "idle" };
  }
}

function provenanceHtml(provenance: MediaProvenance): string {
  switch (provenance.kind) {
    case "device_signed": {
      const signature = provenance.manifestSignature === "valid" ? "Manifest 签名有效" : "Manifest 签名无效";
      const trust =
        provenance.producerKeyTrust === "trusted"
          ? "Producer 密钥已信任"
          : provenance.producerKeyTrust === "untrusted"
            ? "Producer 密钥未受信"
            : "Producer 密钥信任未知";
      const inventory =
        provenance.inventoryIntegrity === "valid"
          ? "Inventory 已验证"
          : provenance.inventoryIntegrity === "invalid"
            ? "Inventory 校验失败"
            : "Inventory 等待本地复核";
      return (
        `<span class="media-provenance-title">设备签名来源</span>` +
        `<span>${signature} · ${trust} · ${inventory}</span>` +
        `<span class="mono media-breakable">${escapeHtml(provenance.publicationKeyFingerprint)}</span>`
      );
    }
    case "locally_validated_unsigned": {
      const report =
        provenance.validationReportId === null ? "验证报告待提交" : `验证报告 ${provenance.validationReportId}`;
      const digest =
        provenance.inventoryDigest === null ? "Inventory digest 待生成" : `Inventory ${provenance.inventoryDigest}`;
      return (
        `<span class="media-provenance-title">本地校验，设备身份未认证</span>` +
        `<span>${escapeHtml(provenance.sourceSchema)} · ${escapeHtml(report)}</span>` +
        `<span class="mono media-breakable">${escapeHtml(digest)}</span>` +
        `<span>${provenance.admission === "approved" ? "未签名来源准入已批准" : "准入前需要策略批准"}</span>`
      );
    }
  }
}

function sourceLayerPresentation(state: SourceLocalState): { label: string; tone: Tone } {
  switch (state) {
    case "not_imported":
      return { label: "未导入", tone: "idle" };
    case "importing":
      return { label: "正在导入", tone: "progress" };
    case "waiting_for_media":
      return { label: "等待原介质", tone: "warn" };
    case "verifying":
      return { label: "正在校验本地源", tone: "progress" };
    case "committing":
      return { label: "正在提交本地源", tone: "progress" };
    case "local_verified":
      return { label: "本地源已验证", tone: "ok" };
    case "retry_wait":
      return { label: "导入等待重试", tone: "warn" };
    case "pausing":
      return { label: "正在暂停导入", tone: "progress" };
    case "paused":
      return { label: "导入已暂停", tone: "warn" };
    case "action_required":
      return { label: "需要用户操作", tone: "warn" };
    case "failed":
      return { label: "本地源失败", tone: "danger" };
    case "cancelled":
      return { label: "导入已取消", tone: "idle" };
  }
}

function derivedLayerPresentation(state: DerivedLocalState): { label: string; tone: Tone } {
  switch (state) {
    case "not_started":
      return { label: "未生成", tone: "idle" };
    case "waiting_for_source":
      return { label: "等待本地源", tone: "idle" };
    case "deriving":
      return { label: "正在规范化", tone: "progress" };
    case "validating":
      return { label: "正在验证派生件", tone: "progress" };
    case "committing":
      return { label: "正在提交派生件", tone: "progress" };
    case "derived_verified":
      return { label: "派生件已验证", tone: "ok" };
    case "retry_wait":
      return { label: "规范化等待重试", tone: "warn" };
    case "pausing":
      return { label: "正在暂停规范化", tone: "progress" };
    case "paused":
      return { label: "规范化已暂停", tone: "warn" };
    case "action_required":
      return { label: "需要用户操作", tone: "warn" };
    case "failed":
      return { label: "派生件失败", tone: "danger" };
    case "cancelled":
      return { label: "规范化已取消", tone: "idle" };
  }
}

function remoteLayerPresentation(state: RemoteState): { label: string; tone: Tone } {
  switch (state) {
    case "disabled":
      return { label: "自动上传已关闭", tone: "idle" };
    case "not_started":
      return { label: "未上传", tone: "idle" };
    case "waiting_for_derived":
      return { label: "等待派生件", tone: "idle" };
    case "uploading":
      return { label: "正在上传", tone: "progress" };
    case "verifying":
      return { label: "正在验证远端内容", tone: "progress" };
    case "remote_verified":
      return { label: "派生 bundle 已远端验证", tone: "ok" };
    case "retry_wait":
      return { label: "上传等待重试", tone: "warn" };
    case "pausing":
      return { label: "正在暂停上传", tone: "progress" };
    case "paused":
      return { label: "上传已暂停", tone: "warn" };
    case "action_required":
      return { label: "需要用户操作", tone: "warn" };
    case "failed":
      return { label: "远端验证失败", tone: "danger" };
    case "cancelled":
      return { label: "上传已取消", tone: "idle" };
  }
}

function layerSummaryHtml(pipeline: MediaPipelineSnapshot | null): string {
  if (pipeline === null) {
    return (
      `<span class="media-layer-mini"><small>本地源</small>${chip("未导入", "idle")}</span>` +
      `<span class="media-layer-mini"><small>派生件</small>${chip("未生成", "idle")}</span>` +
      `<span class="media-layer-mini"><small>远端</small>${chip("未上传", "idle")}</span>`
    );
  }
  const source = sourceLayerPresentation(pipeline.source.state);
  const derived = derivedLayerPresentation(pipeline.derived.state);
  const remote = remoteLayerPresentation(pipeline.remote.state);
  return (
    `<span class="media-layer-mini"><small>本地源</small>${chip(source.label, source.tone)}</span>` +
    `<span class="media-layer-mini"><small>派生件</small>${chip(derived.label, derived.tone)}</span>` +
    `<span class="media-layer-mini"><small>远端</small>${chip(remote.label, remote.tone)}</span>`
  );
}

function revisionHtml(label: string, value: string | null): string {
  if (value === null || value.length === 0) return "";
  return `<span class="media-revision"><span>${escapeHtml(label)}</span><span class="mono media-breakable">${escapeHtml(value)}</span></span>`;
}

function layersHtml(pipeline: MediaPipelineSnapshot): string {
  const source = sourceLayerPresentation(pipeline.source.state);
  const derived = derivedLayerPresentation(pipeline.derived.state);
  const remote = remoteLayerPresentation(pipeline.remote.state);
  return (
    `<div class="media-layer-grid" aria-label="资料状态">` +
    `<section class="media-layer"><span class="media-layer-label">本地 source</span>${chip(source.label, source.tone)}` +
    `${revisionHtml("Source revision", pipeline.source.revisionLabel)}` +
    `<span class="media-layer-detail">${
      pipeline.source.retentionState === "retained"
        ? "源副本保留在本机"
        : pipeline.source.retentionState === "not_retained"
          ? "本机未保留源副本"
          : "本地源保留状态尚未确认"
    }</span></section>` +
    `<section class="media-layer"><span class="media-layer-label">本地 derived</span>${chip(derived.label, derived.tone)}` +
    `${revisionHtml("Derived revision", pipeline.derived.revisionLabel)}` +
    `${revisionHtml("Profile", pipeline.derived.profileLabel)}</section>` +
    `<section class="media-layer"><span class="media-layer-label">对象存储 remote</span>${chip(remote.label, remote.tone)}` +
    `${revisionHtml("Bundle revision", pipeline.remote.bundleRevisionLabel)}` +
    `<span class="media-layer-detail">${
      pipeline.remote.sourceVideoUploadState === "included_verified"
        ? "派生 bundle 与源视频均已远端验证"
        : pipeline.remote.sourceVideoUploadState === "not_included"
          ? "源视频未包含在派生 bundle"
          : "源视频远端状态尚未确认"
    }</span></section></div>`
  );
}

function jobTitle(kind: MediaJobKind): string {
  switch (kind) {
    case "import":
      return "Import";
    case "derivation":
      return "Derivation";
    case "validation":
      return "Validation";
    case "upload":
      return "Upload";
  }
}

function jobStateLabel(state: MediaJobState, kind: MediaJobKind): string {
  switch (state) {
    case "disabled":
      return "策略已关闭";
    case "not_started":
      return "未开始";
    case "blocked":
      return "等待前置条件";
    case "queued":
      return "已排队";
    case "waiting_for_media":
      return "等待原介质";
    case "waiting_for_source":
      return "等待本地源";
    case "preflighting":
      return "预检中";
    case "copying":
      return "复制中";
    case "verifying":
      return kind === "upload" ? "远端校验中" : "校验中";
    case "probing":
      return "探测媒体中";
    case "planning":
      return "生成编码计划";
    case "encoding":
      return "编码中";
    case "validating":
      return "完整解码验证中";
    case "committing":
      return "提交中";
    case "uploading":
      return "上传中";
    case "remote_verifying":
      return "远端内容验证中";
    case "action_required":
      return "需要用户操作";
    case "retry_wait":
      return "等待重试";
    case "pausing":
      return "正在暂停";
    case "paused":
      return "已暂停";
    case "cancelling":
      return "正在取消";
    case "cancelled":
      return "已取消";
    case "failed":
      return "失败";
    case "completed":
      switch (kind) {
        case "import":
          return "本地源已验证";
        case "derivation":
          return "派生件已提交";
        case "validation":
          return "完整解码已通过";
        case "upload":
          return "远端内容已验证";
      }
  }
}

function jobStateTone(state: MediaJobState): Tone {
  switch (state) {
    case "completed":
      return "ok";
    case "failed":
      return "danger";
    case "waiting_for_media":
    case "action_required":
    case "retry_wait":
    case "pausing":
    case "paused":
      return "warn";
    case "preflighting":
    case "copying":
    case "verifying":
    case "probing":
    case "planning":
    case "encoding":
    case "validating":
    case "committing":
    case "uploading":
    case "remote_verifying":
    case "cancelling":
      return "progress";
    case "disabled":
    case "not_started":
    case "blocked":
    case "queued":
    case "waiting_for_source":
    case "cancelled":
      return "idle";
  }
}

function isActivelyProgressing(state: MediaJobState): boolean {
  return (
    state === "preflighting" ||
    state === "copying" ||
    state === "verifying" ||
    state === "probing" ||
    state === "planning" ||
    state === "encoding" ||
    state === "validating" ||
    state === "committing" ||
    state === "uploading" ||
    state === "remote_verifying"
  );
}

function meterHtml(value: number | null, label: string, indeterminate: boolean): string {
  const safeLabel = escapeAttr(label);
  if (value === null) {
    return indeterminate
      ? `<div class="media-meter" role="progressbar" aria-label="${safeLabel}"><span class="media-meter-fill" data-indeterminate="true"></span></div>`
      : `<div class="media-meter" role="progressbar" aria-label="${safeLabel}" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"><span class="media-meter-fill" style="width:0%"></span></div>`;
  }
  const safeValue = Math.min(100, Math.max(0, value));
  return `<div class="media-meter" role="progressbar" aria-label="${safeLabel}" aria-valuenow="${safeValue.toFixed(
    1,
  )}" aria-valuemin="0" aria-valuemax="100"><span class="media-meter-fill" style="width:${safeValue.toFixed(2)}%"></span></div>`;
}

function importProgressHtml(progress: MediaImportProgress): string {
  const copied = finiteNonNegative(progress.copiedBytes);
  const total = finiteNonNegative(progress.totalBytes);
  const currentFile = progress.currentFile === null ? "准备文件" : progress.currentFile;
  return (
    `<div class="media-progress-copy"><span class="media-progress-primary media-breakable" title="${escapeAttr(
      currentFile,
    )}">${escapeHtml(currentFile)}</span>` +
    `<span class="media-progress-numbers mono">${bytesText(copied)} / ${bytesText(total)}</span>` +
    `${meterHtml(percent(copied, total), "导入字节进度", true)}` +
    `<span class="media-progress-meta mono">${rateText(progress.throughputBytesPerSecond)} · ${formatEta(
      progress.etaSeconds,
    )}</span></div>`
  );
}

function derivationProgressHtml(progress: MediaDerivationProgress): string {
  const processed = finiteNonNegative(progress.processedFrames);
  const total = progress.totalFrames === null ? null : finiteNonNegative(progress.totalFrames);
  const pair = progress.currentSegmentPair === null ? "--" : String(safeCount(progress.currentSegmentPair));
  const totalPairs = progress.totalSegmentPairs === null ? "--" : String(safeCount(progress.totalSegmentPairs));
  const fps =
    progress.encodingFps === null || !Number.isFinite(progress.encodingFps)
      ? "-- fps"
      : `${finiteNonNegative(progress.encodingFps).toFixed(1)} fps`;
  return (
    `<div class="media-progress-copy"><span class="media-progress-primary">分段对 ${pair} / ${totalPairs}</span>` +
    `<span class="media-progress-numbers mono">${safeCount(processed)} / ${
      total === null ? "--" : safeCount(total)
    } 帧</span>` +
    `${meterHtml(total === null ? null : percent(processed, total), "规范化帧进度", true)}` +
    `<span class="media-progress-meta mono">${fps} · ${formatEta(progress.etaSeconds)}</span></div>`
  );
}

function validationProgressHtml(progress: MediaValidationProgress): string {
  const completed = safeCount(progress.decodedSegmentPairs);
  const total = safeCount(progress.totalSegmentPairs);
  return (
    `<div class="media-progress-copy"><span class="media-progress-primary">完整解码 ${completed} / ${total} 个分段对</span>` +
    `<span class="media-progress-numbers mono">左右目同步验证</span>` +
    `${meterHtml(percent(completed, total), "完整解码分段进度", true)}` +
    `<span class="media-progress-meta">以已完整解码的分段数计</span></div>`
  );
}

function uploadProgressHtml(progress: MediaUploadProgress): string {
  const uploaded = finiteNonNegative(progress.uploadedBytes);
  const total = finiteNonNegative(progress.totalBytes);
  return (
    `<div class="media-progress-copy"><span class="media-progress-primary">派生 bundle</span>` +
    `<span class="media-progress-numbers mono">${bytesText(uploaded)} / ${bytesText(total)}</span>` +
    `${meterHtml(percent(uploaded, total), "上传字节进度", true)}` +
    `<span class="media-progress-meta mono">Part ${
      progress.currentPart === null ? "--" : safeCount(progress.currentPart)
    } / ${progress.totalParts === null ? "--" : safeCount(progress.totalParts)} · ${rateText(
      progress.throughputBytesPerSecond,
    )} · ${formatEta(progress.etaSeconds)}</span></div>`
  );
}

function progressHtml(job: MediaJobSnapshot): string {
  if (job.progress !== null) {
    switch (job.kind) {
      case "import":
        return importProgressHtml(job.progress);
      case "derivation":
        return derivationProgressHtml(job.progress);
      case "validation":
        return validationProgressHtml(job.progress);
      case "upload":
        return uploadProgressHtml(job.progress);
    }
  }
  return `<div class="media-progress-copy"><span class="media-progress-primary">${escapeHtml(
    jobStateLabel(job.state, job.kind),
  )}</span>${meterHtml(null, `${jobTitle(job.kind)} 状态`, isActivelyProgressing(job.state))}</div>`;
}

function commandLabel(command: MediaJobCommand): string {
  switch (command) {
    case "pause":
      return "暂停";
    case "resume":
      return "继续";
    case "retry":
      return "重试";
    case "cancel":
      return "取消";
  }
}

function jobControlsHtml(job: MediaJobSnapshot, pipelineId: string): string {
  const seen = new Set<MediaJobCommand>();
  const controls = job.availableCommands
    .filter((command) => {
      if (seen.has(command)) return false;
      seen.add(command);
      return true;
    })
    .map(
      (command) =>
        `<button type="button" class="btn btn-sm ${
          command === "cancel"
            ? "btn-danger-outline"
            : command === "retry" || command === "resume"
              ? "btn-primary"
              : "btn-ghost"
        }" data-media-action="job-command" data-pipeline-id="${escapeAttr(pipelineId)}" data-job-id="${escapeAttr(
          job.id,
        )}" data-job-kind="${job.kind}" data-job-command="${command}">${commandLabel(command)}</button>`,
    )
    .join("");
  const requiredControl = (() => {
    switch (job.requiredAction?.kind) {
      case "configure_storage":
        return '<button type="button" class="btn btn-primary btn-sm" data-media-action="configure-storage">配置对象存储</button>';
      case "approve_unsigned_source":
        return `<button type="button" class="btn btn-primary btn-sm" data-media-action="approve-unsigned-upload" data-pipeline-id="${escapeAttr(
          pipelineId,
        )}">批准上传未签名来源</button>`;
      default:
        return "";
    }
  })();
  const required =
    job.requiredAction === null
      ? ""
      : `<div class="media-required-action"><span><strong>${escapeHtml(job.requiredAction.label)}</strong><small>${escapeHtml(
          job.requiredAction.detail,
        )}</small></span>${requiredControl}</div>`;
  const issue =
    job.issue === null
      ? ""
      : `<div class="media-job-issue" data-retryable="${job.issue.retryable}"><span class="mono">${escapeHtml(
          job.issue.code,
        )}</span><span>${escapeHtml(job.issue.message)}</span></div>`;
  return `${required}${issue}<div class="media-job-actions">${controls}</div>`;
}

function jobHtml(job: MediaJobSnapshot, pipelineId: string): string {
  return (
    `<section class="media-job" data-job-kind="${job.kind}" data-job-state="${job.state}">` +
    `<div class="media-job-name"><strong>${jobTitle(job.kind)}</strong>${chip(
      jobStateLabel(job.state, job.kind),
      jobStateTone(job.state),
    )}</div>` +
    `${progressHtml(job)}<div class="media-job-controls">${jobControlsHtml(job, pipelineId)}</div></section>`
  );
}

function pipelineDetailsHtml(pipeline: MediaPipelineSnapshot | null): string {
  if (pipeline === null) return `<div class="media-pipeline-empty">尚未创建导入任务</div>`;
  return (
    `${layersHtml(pipeline)}` +
    `<div class="media-job-list" aria-label="任务进度">${jobHtml(pipeline.jobs.import, pipeline.id)}${jobHtml(
      pipeline.jobs.derivation,
      pipeline.id,
    )}${jobHtml(pipeline.jobs.validation, pipeline.id)}${jobHtml(pipeline.jobs.upload, pipeline.id)}</div>`
  );
}

function candidateHtml(candidate: MediaCandidateSnapshot, pipeline: MediaPipelineSnapshot | null): string {
  const candidateIdAttr = escapeAttr(candidate.id);
  const verdict = verdictPresentation(candidate.verdict.kind);
  const media = mediaRequirementPresentation(candidate.mediaRequirement, candidate.acquisitionKind);
  const metrics = [
    candidate.totalBytes === null ? "大小未知" : bytesText(candidate.totalBytes),
    formatDuration(candidate.durationSeconds),
  ].join(" · ");
  const verdictDetail =
    candidate.verdict.detail === null
      ? ""
      : `<div class="media-verdict-detail" data-tone="${verdict.tone}">${escapeHtml(candidate.verdict.detail)}</div>`;
  const checkbox = `<input type="checkbox" class="row-check" data-media-select-candidate="${candidateIdAttr}" aria-label="选择 ${escapeAttr(
    candidate.displayName,
  )}" ${candidate.selected ? "checked" : ""} ${candidate.selectable ? "" : "disabled"} />`;
  return (
    `<article class="media-candidate" data-open="${candidate.expanded}" data-selectable="${candidate.selectable}">` +
    `<div class="media-candidate-main" data-media-action="toggle-candidate" data-candidate-id="${candidateIdAttr}" role="button" tabindex="0" aria-expanded="${
      candidate.expanded
    }">${checkbox}<span class="chevron" aria-hidden="true"></span>` +
    `<span class="media-candidate-name"><strong>${escapeHtml(candidate.displayName)}</strong>` +
    `<span class="mono" title="${escapeAttr(`会话 ID: ${candidate.sessionIdLabel}`)}">${escapeHtml(
      candidate.sessionIdLabel,
    )}</span></span>` +
    `<span class="media-candidate-source"><small>${escapeHtml(sourceKindLabel(candidate.sourceKind))}</small>` +
    `<span title="${escapeAttr(candidate.sourceLocationLabel)}">${escapeHtml(candidate.sourceLocationLabel)}</span>` +
    `<span class="mono">${escapeHtml(metrics)}</span></span>` +
    `<span class="media-candidate-verdict">${chip(verdict.label, verdict.tone)}</span>` +
    `<span class="media-candidate-layers">${layerSummaryHtml(pipeline)}</span>` +
    `<span class="media-candidate-media">${chip(media.label, media.tone)}</span></div>` +
    `<div class="media-candidate-details"><div class="media-candidate-details-inner">${verdictDetail}` +
    `<div class="media-detail-meta"><span><small>来源判定</small>${provenanceHtml(candidate.provenance)}</span>` +
    `<span><small>介质依赖</small><strong>${escapeHtml(media.label)}</strong></span></div>` +
    `${pipelineDetailsHtml(pipeline)}</div></div></article>`
  );
}

function batchOutcomePresentation(outcome: MediaBatchItemOutcome): { label: string; tone: Tone } {
  switch (outcome.kind) {
    case "succeeded":
      return { label: "成功", tone: "ok" };
    case "processing":
      return { label: "处理中", tone: "progress" };
    case "action_required":
      return { label: "需要用户操作", tone: "warn" };
    case "failed":
      return { label: outcome.retryable ? "失败，可重试" : "失败", tone: "danger" };
  }
}

function batchStateLabel(batch: MediaBatchSnapshot): string {
  switch (batch.state) {
    case "running":
      return "批量导入处理中";
    case "action_required":
      return "批量导入需要用户操作";
    case "completed":
      return "批量导入已完成";
    case "cancelled":
      return "批量导入已取消";
    case "failed":
      return "批量导入失败";
  }
}

function batchHtml(batch: MediaBatchSnapshot | null): string {
  if (batch === null) return "";
  const counts = { succeeded: 0, processing: 0, action_required: 0, failed: 0 };
  for (const item of batch.items) counts[item.outcome.kind] += 1;
  const items = batch.items
    .map((item) => {
      const presentation = batchOutcomePresentation(item.outcome);
      return (
        `<li><span class="media-batch-name">${escapeHtml(item.displayName)}</span>` +
        `<span>${chip(presentation.label, presentation.tone)}</span>` +
        `<span class="media-batch-detail">${escapeHtml(item.outcome.detail)}</span></li>`
      );
    })
    .join("");
  const operationIssue =
    batch.operationIssue === null
      ? ""
      : `<div class="media-scan-issue" role="status"><span><strong>批量请求未完全提交</strong><span>${escapeHtml(
          batch.operationIssue.message,
        )}</span></span></div>`;
  return (
    `<section class="media-band media-batch" aria-labelledby="mediaBatchHeading">` +
    `<div class="media-section-head"><div><h2 id="mediaBatchHeading">${batchStateLabel(batch)}</h2>` +
    `<span>${escapeHtml(batch.startedAtLabel)}</span></div><div class="media-row-actions">${
      batch.canCancel
        ? `<button type="button" class="btn btn-danger-outline btn-sm" data-media-action="cancel-batch" data-batch-id="${escapeAttr(
            batch.id,
          )}">取消批次</button>`
        : ""
    }${
      batch.canDismiss
        ? `<button type="button" class="btn btn-ghost btn-sm" data-media-action="dismiss-batch" data-batch-id="${escapeAttr(
            batch.id,
          )}">关闭结果</button>`
        : ""
    }</div></div>` +
    `${operationIssue}<div class="media-batch-counts"><span><strong>${counts.succeeded}</strong><small>成功</small></span>` +
    `<span><strong>${counts.processing}</strong><small>处理中</small></span>` +
    `<span><strong>${counts.action_required}</strong><small>需要用户操作</small></span>` +
    `<span><strong>${counts.failed}</strong><small>失败</small></span></div>` +
    `<ul class="media-batch-items">${items}</ul></section>`
  );
}

function candidatesHtml(snapshot: MediaWorkspaceSnapshot): string {
  const selectable = snapshot.candidates.filter((candidate) => candidate.selectable);
  const selected = selectable.filter((candidate) => candidate.selected);
  const approvesUnsigned = selected.some(
    (candidate) =>
      candidate.verdict.kind === "ready_unsigned_requires_policy" ||
      candidate.verdict.kind === "pending_artifact_validation",
  );
  const startLabel = approvesUnsigned
    ? snapshot.unsignedApprovalArmed
      ? "确认批准并导入"
      : "批准未签名来源并导入"
    : "导入选中项";
  const pipelineBySourceKey = new Map(snapshot.pipelines.map((pipeline) => [pipeline.sourceKey, pipeline] as const));
  const rows =
    snapshot.candidates.length === 0
      ? `<div class="media-empty-inline">已扫描的来源中没有录制会话</div>`
      : `<div class="media-candidate-list">${snapshot.candidates
          .map((candidate) => candidateHtml(candidate, pipelineBySourceKey.get(candidate.sourceKey) ?? null))
          .join("")}</div>`;
  return (
    `<section class="media-band media-candidates" aria-labelledby="mediaCandidatesHeading">` +
    `<div class="media-section-head"><div><h2 id="mediaCandidatesHeading">录制会话</h2>` +
    `<span>${safeCount(snapshot.candidates.length)} 项 · ${safeCount(selected.length)} 项已选</span></div>` +
    `<div class="media-selection-actions"><label class="media-select-all"><input type="checkbox" class="row-check" data-media-select-all aria-label="选择全部可导入会话" ${
      selected.length > 0 && selected.length === selectable.length ? "checked" : ""
    } ${selectable.length === 0 ? "disabled" : ""} /><span>全选可导入项</span></label>` +
    `<button type="button" class="btn btn-primary" data-media-action="import-selected" data-confirm-armed="${
      snapshot.unsignedApprovalArmed
    }" ${
      selected.length === 0 || (snapshot.batch !== null && !snapshot.batch.canDismiss) ? "disabled" : ""
    }>${startLabel} (${safeCount(selected.length)})</button></div></div>${rows}</section>`
  );
}

function scanIssueHtml(snapshot: MediaWorkspaceSnapshot): string {
  if (snapshot.scan.issue === null) return "";
  return (
    `<div class="media-scan-issue" role="status"><span><strong>${escapeHtml(snapshot.scan.issue.code)}</strong>` +
    `<span>${escapeHtml(snapshot.scan.issue.message)}</span></span>` +
    `<button type="button" class="btn btn-primary btn-sm" data-media-action="scan-all" ${
      snapshot.scan.issue.retryable ? "" : "disabled"
    }>重试扫描</button></div>`
  );
}

function resourceDegradationsHtml(snapshot: MediaWorkspaceSnapshot): string {
  if (snapshot.resourceDegradations.length === 0) return "";
  const labels: Readonly<Record<MediaResourceName, string>> = {
    scan: "扫描结果",
    imports: "导入任务",
    derivations: "规范化任务",
    pipelines: "导入会话",
    library: "媒体库证据",
  };
  return `<div class="media-resource-issues">${snapshot.resourceDegradations
    .map(
      (failure) =>
        `<div class="media-scan-issue" role="status"><span><strong>${labels[failure.resource]}状态刷新失败</strong>` +
        `<span>${escapeHtml(failure.message)} · 当前显示最近一次成功读取的数据</span></span>` +
        `<button type="button" class="btn btn-primary btn-sm" data-media-action="retry-resource" data-resource="${
          failure.resource
        }" ${!failure.retryable || failure.retrying ? "disabled" : ""}>${
          failure.retrying ? "重试中…" : "重试读取"
        }</button></div>`,
    )
    .join("")}</div>`;
}

export function mediaContentHtml(snapshot: MediaWorkspaceSnapshot): string {
  return (
    `<div class="media-workspace" aria-busy="${snapshot.scan.state === "scanning"}">` +
    `${scanIssueHtml(snapshot)}${resourceDegradationsHtml(snapshot)}${sourcesHtml(
      snapshot,
    )}${libraryHtml(snapshot)}${batchHtml(snapshot.batch)}${candidatesHtml(snapshot)}</div>`
  );
}
