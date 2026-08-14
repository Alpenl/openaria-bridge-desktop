from __future__ import annotations

import importlib
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, runtime_checkable

from .runtime import CancellationToken, OperationCancelled


class SdkUnavailableError(RuntimeError):
    pass


class SdkVersionError(RuntimeError):
    pass


class SdkOperationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SessionFile:
    relative_path: str
    size: int
    sha256: str
    inline_content: bytes | None = None


@dataclass(frozen=True, slots=True)
class SessionCopyPlan:
    session_id: str
    format_version: str
    files: tuple[SessionFile, ...]
    commit_last: str


@dataclass(frozen=True, slots=True)
class SessionSummary:
    session_id: str
    path: Path
    created_at: str | None = None
    label: str | None = None


@dataclass(frozen=True, slots=True)
class SessionInspection:
    session_id: str
    format_version: str
    sealed: bool
    files: tuple[SessionFile, ...]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ValidationReport:
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@runtime_checkable
class SdkClient(Protocol):
    """PC 应用所需的最小 SDK 能力，不暴露录制文件内部字段。"""

    @property
    def api_version(self) -> str: ...

    def discover_sessions(
        self, root: Path, cancellation: CancellationToken
    ) -> tuple[SessionSummary, ...]: ...

    def inspect_session(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionInspection: ...

    def validate_session(
        self, path: Path, cancellation: CancellationToken
    ) -> ValidationReport: ...

    def build_copy_plan(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionCopyPlan: ...


class SdkGateway:
    """隔离 SDK 版本与异常；业务层只依赖这一层的稳定值对象。"""

    SUPPORTED_API_MAJOR = 1

    def __init__(self, client: SdkClient) -> None:
        self._client = client
        self._check_version(client.api_version)

    @classmethod
    def _check_version(cls, version: str) -> None:
        try:
            major = int(version.split(".", maxsplit=1)[0])
        except (ValueError, IndexError) as exc:
            raise SdkVersionError(f"无法识别 SDK API 版本：{version}") from exc
        if major != cls.SUPPORTED_API_MAJOR:
            raise SdkVersionError(
                f"SDK API {version} 不兼容，需要 {cls.SUPPORTED_API_MAJOR}.x"
            )

    def discover_sessions(
        self, root: Path, cancellation: CancellationToken
    ) -> tuple[SessionSummary, ...]:
        return self._invoke(
            "发现会话", cancellation, self._client.discover_sessions, root, cancellation
        )

    def inspect_session(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionInspection:
        return self._invoke(
            "检查会话", cancellation, self._client.inspect_session, path, cancellation
        )

    def validate_session(
        self, path: Path, cancellation: CancellationToken
    ) -> ValidationReport:
        return self._invoke(
            "校验会话", cancellation, self._client.validate_session, path, cancellation
        )

    def build_copy_plan(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionCopyPlan:
        return self._invoke(
            "生成复制计划",
            cancellation,
            self._client.build_copy_plan,
            path,
            cancellation,
        )

    @staticmethod
    def _invoke(name: str, cancellation: CancellationToken, call, *args):
        cancellation.raise_if_cancelled()
        try:
            result = call(*args)
        except OperationCancelled:
            raise
        except Exception as exc:
            raise SdkOperationError(f"SDK {name}失败：{exc}") from exc
        cancellation.raise_if_cancelled()
        return result


class UnavailableSdkClient:
    """SDK 未安装时提供明确错误，不在应用内降级解析会话。"""

    api_version = "1.0"

    @staticmethod
    def _raise() -> None:
        raise SdkUnavailableError("未安装兼容的 ylx-card-pipeline；请安装后重试")

    def discover_sessions(
        self, root: Path, cancellation: CancellationToken
    ) -> tuple[SessionSummary, ...]:
        self._raise()

    def inspect_session(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionInspection:
        self._raise()

    def validate_session(
        self, path: Path, cancellation: CancellationToken
    ) -> ValidationReport:
        self._raise()

    def build_copy_plan(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionCopyPlan:
        self._raise()


class PipelineSdkClient:
    """把 ylx-card-pipeline 的公开 API 映射为应用内部的稳定边界。"""

    api_version = "1.0"
    SUPPORTED_PACKAGE_SERIES = (0, 1)

    def __init__(self, module: ModuleType | Any | None = None) -> None:
        try:
            self._module = module or importlib.import_module("ylx_card_pipeline")
        except ImportError as exc:
            raise SdkUnavailableError(
                "未安装 ylx-card-pipeline；请安装 0.1.x 版本后重试"
            ) from exc
        version = str(getattr(self._module, "__version__", ""))
        if version == "0+unknown":
            version = _source_checkout_version(self._module) or version
        try:
            series = tuple(int(item) for item in version.split(".")[:2])
        except ValueError as exc:
            raise SdkVersionError(
                f"无法识别 ylx-card-pipeline 版本：{version}"
            ) from exc
        if series != self.SUPPORTED_PACKAGE_SERIES:
            raise SdkVersionError(f"ylx-card-pipeline {version} 不兼容，需要 0.1.x")

    def discover_sessions(
        self, root: Path, cancellation: CancellationToken
    ) -> tuple[SessionSummary, ...]:
        cancellation.raise_if_cancelled()
        paths = self._module.discover_sessions(root)
        summaries = []
        for path in paths:
            cancellation.raise_if_cancelled()
            report = self._module.validate_session(path, verify_hashes=False)
            summaries.append(
                SessionSummary(
                    session_id=str(report.session_id or Path(path).name),
                    path=Path(path),
                )
            )
        return tuple(summaries)

    def inspect_session(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionInspection:
        cancellation.raise_if_cancelled()
        manifest = self._module.require_valid_session(path, verify_hashes=True)
        cancellation.raise_if_cancelled()
        artifacts = tuple(
            SessionFile(
                relative_path=str(artifact.path),
                size=int(artifact.size_bytes),
                sha256=str(artifact.sha256),
            )
            for artifact in manifest.artifacts
        )
        return SessionInspection(
            session_id=str(manifest.session_id),
            format_version=str(getattr(manifest, "format_version", "v0")),
            sealed=True,
            files=artifacts,
            metadata={},
        )

    def validate_session(
        self, path: Path, cancellation: CancellationToken
    ) -> ValidationReport:
        cancellation.raise_if_cancelled()
        report = self._module.validate_session(path, verify_hashes=True)
        cancellation.raise_if_cancelled()
        return ValidationReport(
            valid=bool(report.valid),
            errors=tuple(
                f"{issue.code}: {issue.message}"
                + (f"（{issue.location}）" if issue.location else "")
                for issue in report.issues
            ),
        )

    def build_copy_plan(
        self, path: Path, cancellation: CancellationToken
    ) -> SessionCopyPlan:
        cancellation.raise_if_cancelled()
        builder = getattr(self._module, "build_publication_plan", None)
        if builder is None:
            raise SdkUnavailableError(
                "ylx-card-pipeline 尚未提供完整复制计划；需要 SDK-05 版本"
            )
        plan = builder(path)
        cancellation.raise_if_cancelled()
        files = tuple(
            SessionFile(
                relative_path=str(item.relative_path),
                size=int(item.size_bytes),
                sha256=str(item.sha256),
            )
            for item in plan.objects
        )
        commit_markers = [
            str(item.relative_path) for item in plan.objects if item.commit_marker
        ]
        if len(commit_markers) != 1:
            raise SdkOperationError("SDK 发布计划必须有且只有一个提交对象")
        return SessionCopyPlan(
            session_id=str(plan.session_id),
            format_version="v0",
            files=files,
            commit_last=commit_markers[0],
        )


def _source_checkout_version(module: ModuleType | Any) -> str | None:
    raw_file = getattr(module, "__file__", None)
    if not isinstance(raw_file, str):
        return None
    module_path = Path(raw_file).resolve()
    for parent in module_path.parents[:3]:
        project_file = parent / "pyproject.toml"
        if not project_file.is_file():
            continue
        try:
            project = tomllib.loads(project_file.read_text(encoding="utf-8")).get(
                "project"
            )
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            return None
        if not isinstance(project, dict) or project.get("name") != "ylx-card-pipeline":
            return None
        declared = project.get("version")
        return declared if isinstance(declared, str) else None
    return None
