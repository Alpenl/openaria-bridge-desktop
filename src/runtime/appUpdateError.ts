export type AppUpdateStage = "check" | "download" | "install";

const NUMERIC_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export class AppUpdateContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppUpdateContractError";
  }
}

export function numericAppVersion(value: string, field: string): string {
  if (!NUMERIC_SEMVER.test(value)) {
    throw new AppUpdateContractError(`${field} 必须是 X.Y.Z 格式，实际为 ${JSON.stringify(value)}`);
  }
  return value;
}

export function compareNumericAppVersions(left: string, right: string): number {
  const leftParts = numericAppVersion(left, "当前版本").split(".").map(Number);
  const rightParts = numericAppVersion(right, "可用版本").split(".").map(Number);
  for (let index = 0; index < leftParts.length; index += 1) {
    const difference = leftParts[index]! - rightParts[index]!;
    if (difference !== 0) return difference;
  }
  return 0;
}

export function validateAvailableAppVersion(currentVersion: string, availableVersion: string): void {
  numericAppVersion(currentVersion, "当前版本");
  numericAppVersion(availableVersion, "可用版本");
  if (compareNumericAppVersions(availableVersion, currentVersion) <= 0) {
    throw new AppUpdateContractError(`可用版本 ${availableVersion} 不高于当前版本 ${currentVersion}`);
  }
}

function errorText(error: unknown): string {
  if (error instanceof Error) return error.message.trim();
  if (typeof error === "string") return error.trim();
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

/**
 * Native updater failures are deliberately classified at the application
 * boundary. In particular, a missing manifest is a broken update source, not
 * evidence that the installed version is current.
 */
export function describeAppUpdateFailure(error: unknown, stage: AppUpdateStage): string {
  const detail = errorText(error) || "未知错误";
  const normalized = detail.toLowerCase();

  if (/\b404\b|not[ -]?found/.test(normalized)) {
    return `更新源文件不存在（HTTP 404）：${detail}`;
  }
  if (/signature|minisign|public key|verification failed|verify signature/.test(normalized)) {
    return `更新签名验证失败：${detail}`;
  }
  if (
    error instanceof AppUpdateContractError ||
    /invalid (release )?(json|metadata|version)|release json|manifest|semver|missing.*(url|version|signature)/.test(
      normalized,
    )
  ) {
    return `更新元数据无效：${detail}`;
  }
  if (/network|request|fetch|connect|connection|dns|tls|certificate|timed? ?out|http status/.test(normalized)) {
    return `无法连接应用更新源：${detail}`;
  }

  const operation = stage === "check" ? "检查更新" : stage === "download" ? "下载更新" : "安装更新";
  return `${operation}失败：${detail}`;
}
