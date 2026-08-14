from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .database import SourceRepository, StaleSourceObservation
from .models import SourceKind, SourceRecord, SourceSessionRecord
from .runtime import CancellationToken, OperationCancelled
from .sdk import SdkGateway

_STABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    device_id: str
    display_name: str
    api_version: str


@dataclass(frozen=True, slots=True)
class DeviceSession:
    session_id: str
    locator: str
    label: str | None = None
    created_at: str | None = None
    manifest_sha256: str | None = None
    total_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class DeviceSnapshot:
    identity: DeviceIdentity
    sessions: tuple[DeviceSession, ...]
    metadata: dict[str, Any] | None = None


class DeviceProbe(Protocol):
    def probe(
        self, endpoint: str, cancellation: CancellationToken
    ) -> DeviceSnapshot: ...


class JsonHttpDeviceProbe:
    """最小 HTTP 探针；路径可按 RP-YLX 的版本化 API 注入。"""

    def __init__(
        self,
        *,
        identity_path: str = "api/v0/device",
        sessions_path: str = "api/v0/sessions",
        timeout: float = 2.0,
    ) -> None:
        self._identity_path = identity_path
        self._sessions_path = sessions_path
        self._timeout = timeout

    def probe(self, endpoint: str, cancellation: CancellationToken) -> DeviceSnapshot:
        cancellation.raise_if_cancelled()
        identity = self._get_json(endpoint, self._identity_path)
        cancellation.raise_if_cancelled()
        sessions_payload = self._get_json(endpoint, self._sessions_path)
        cancellation.raise_if_cancelled()
        try:
            identity_value = identity["device"]
            device = DeviceIdentity(
                device_id=str(identity_value["id"]),
                display_name=str(identity_value["label"]),
                api_version=str(identity["api_version"]),
            )
            entries = sessions_payload["sessions"]
            sessions = tuple(
                DeviceSession(
                    session_id=str(entry["session_id"]),
                    locator=_device_session_locator(
                        device.device_id, str(entry["session_id"])
                    ),
                    label=_optional_text(entry.get("label")),
                    created_at=_optional_text(entry.get("started_at")),
                )
                for entry in entries
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DiscoveryError(f"设备响应格式无效：{exc}") from exc
        return DeviceSnapshot(identity=device, sessions=sessions)

    def _get_json(self, endpoint: str, path: str) -> dict[str, Any]:
        url = urllib.parse.urljoin(f"{endpoint.rstrip('/')}/", path.lstrip("/"))
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "ylx-transfer/0.1"},
        )
        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise DiscoveryError(f"设备返回了不支持的内容类型：{content_type}")
            return json.load(response)


class DeviceDiscovery:
    def __init__(self, repository: SourceRepository, probe: DeviceProbe) -> None:
        self._repository = repository
        self._probe = probe

    def connect(
        self, endpoint: str, cancellation: CancellationToken
    ) -> tuple[SourceRecord, tuple[SourceSessionRecord, ...]]:
        normalized = _normalize_endpoint(endpoint)
        observation = self._repository.begin_observation(SourceKind.DEVICE, normalized)
        try:
            snapshot = self._probe.probe(normalized, cancellation)
            cancellation.raise_if_cancelled()
            _validate_stable_id(snapshot.identity.device_id, "设备 ID")
            return self._repository.apply_observation(
                kind=SourceKind.DEVICE,
                location=normalized,
                token=observation,
                stable_id=snapshot.identity.device_id,
                display_name=snapshot.identity.display_name,
                metadata={
                    **(snapshot.metadata or {}),
                    "api_version": snapshot.identity.api_version,
                },
                exclusive_location=True,
                sessions=(
                    (
                        session.session_id,
                        session.locator,
                        session.label,
                        session.created_at,
                    )
                    for session in snapshot.sessions
                ),
            )
        except OperationCancelled:
            raise
        except StaleSourceObservation as exc:
            raise DiscoveryError(str(exc)) from exc
        except Exception as exc:
            self._repository.mark_observation_offline(
                SourceKind.DEVICE, normalized, observation
            )
            if isinstance(exc, DiscoveryError):
                raise
            if isinstance(exc, (TimeoutError, urllib.error.URLError)):
                raise DiscoveryError(
                    f"无法连接设备 {normalized}：连接超时或已离线"
                ) from exc
            raise DiscoveryError(f"无法连接设备 {normalized}：{exc}") from exc


class MediaDiscovery:
    MARKER = ".ylx-volume.json"
    MAX_MARKER_BYTES = 64 * 1024

    def __init__(
        self,
        repository: SourceRepository,
        sdk: SdkGateway,
        allowed_roots: tuple[Path, ...],
    ) -> None:
        if not allowed_roots:
            raise ValueError("至少需要一个介质扫描根目录")
        self._repository = repository
        self._sdk = sdk
        self._allowed_roots = tuple(root.resolve() for root in allowed_roots)

    def scan(
        self, mount_path: Path, cancellation: CancellationToken
    ) -> tuple[SourceRecord, tuple[SourceSessionRecord, ...]]:
        mount = self._safe_mount(mount_path)
        location = str(mount)
        observation = self._repository.begin_observation(SourceKind.MEDIA, location)
        cancellation.raise_if_cancelled()
        marker = mount / self.MARKER
        if marker.is_symlink() or not marker.is_file():
            raise DiscoveryError(f"介质缺少只读身份标记 {self.MARKER}")
        if marker.stat().st_size > self.MAX_MARKER_BYTES:
            raise DiscoveryError("介质身份标记过大")
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
            volume_id = str(payload["volume_id"])
            label = str(payload.get("label") or volume_id)
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise DiscoveryError(f"介质身份标记无效：{exc}") from exc
        _validate_stable_id(volume_id, "介质 ID")

        summaries = self._sdk.discover_sessions(mount, cancellation)
        safe_sessions = []
        for summary in summaries:
            session_path = summary.path.resolve(strict=True)
            if not _is_within(session_path, mount) or summary.path.is_symlink():
                raise DiscoveryError(
                    f"SDK 返回了介质范围之外的会话路径：{summary.path}"
                )
            safe_sessions.append(
                (
                    summary.session_id,
                    str(session_path),
                    summary.label,
                    summary.created_at,
                )
            )

        try:
            return self._repository.apply_observation(
                kind=SourceKind.MEDIA,
                location=location,
                token=observation,
                stable_id=volume_id,
                display_name=label,
                sessions=safe_sessions,
                metadata={},
                exclusive_location=False,
            )
        except StaleSourceObservation as exc:
            raise DiscoveryError(str(exc)) from exc

    def removed(self, mount_path: Path) -> None:
        location = str(mount_path.resolve(strict=False))
        observation = self._repository.begin_observation(SourceKind.MEDIA, location)
        self._repository.mark_observation_offline(
            SourceKind.MEDIA, location, observation
        )

    def _safe_mount(self, path: Path) -> Path:
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise DiscoveryError(f"介质路径不可用：{path}") from exc
        if not resolved.is_dir():
            raise DiscoveryError(f"介质路径不是目录：{path}")
        if not any(_is_within(resolved, root) for root in self._allowed_roots):
            raise DiscoveryError(f"介质路径不在允许的扫描范围内：{path}")
        return resolved


def _normalize_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DiscoveryError("设备地址必须是完整的 http 或 https URL")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise DiscoveryError("设备地址不能包含凭据、查询参数或片段")
    path = parsed.path.rstrip("")
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), path.rstrip("/"), "", "")
    ).rstrip("/")


def _device_session_locator(device_id: str, session_id: str) -> str:
    _validate_stable_id(device_id, "设备 ID")
    _validate_stable_id(session_id, "会话 ID")
    return (
        "ylx-device://"
        f"{urllib.parse.quote(device_id, safe='')}/"
        f"{urllib.parse.quote(session_id, safe='')}"
    )


def _optional_text(value: object) -> str | None:
    return None if value is None else str(value)


def _validate_stable_id(value: str, name: str) -> None:
    if not _STABLE_ID.fullmatch(value):
        raise DiscoveryError(f"{name} 不安全或长度不合法")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
