from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
import socket
import ssl
import urllib.parse
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from typing import Protocol

from .discovery import DeviceIdentity, DeviceSession, DeviceSnapshot
from .runtime import CancellationToken
from .transfers import EnvironmentCredentialProvider

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UUID_V7 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DEVICE_LABEL = re.compile(r"^YLX-[0-9A-F]{8}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_SUPPORTED_API_VERSION = "3.0"


class CredentialProvider(Protocol):
    def resolve(self, reference: str | None) -> str | None: ...


class LanFailure(RuntimeError):
    def __init__(self, code: str, message: str, recovery_action: str) -> None:
        super().__init__(message)
        self.code = code
        self.recovery_action = recovery_action


@dataclass(frozen=True, slots=True)
class TlsPin:
    target: str
    algorithm: str
    encoding: str
    value: str


@dataclass(frozen=True, slots=True)
class LanConnectionSpec:
    endpoint: str
    credential_ref: str | None = None
    tls_pin: TlsPin | None = None


@dataclass(frozen=True, slots=True)
class ManifestResource:
    payload: bytes
    sha256: str
    identity: str


@dataclass(frozen=True, slots=True)
class ArtifactResource:
    size: int
    media_type: str
    sha256: str
    identity: str


class LanDeviceClient:
    USER_AGENT = "ylx-transfer/0.1"

    def __init__(
        self,
        spec: LanConnectionSpec,
        *,
        credentials: CredentialProvider | None = None,
        timeout: float = 10.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout 必须大于零")
        self.spec = _validate_connection_spec(spec)
        self._credentials = credentials or EnvironmentCredentialProvider()
        self._timeout = timeout
        self._parsed = urllib.parse.urlsplit(self.spec.endpoint)

    def probe(self, cancellation: CancellationToken) -> DeviceSnapshot:
        cancellation.raise_if_cancelled()
        descriptor = self._get_json("/api/v3/device")
        cancellation.raise_if_cancelled()
        identity = self._parse_device(descriptor)
        sessions: list[DeviceSession] = []
        cursor: str | None = None
        observed_cursors: set[str] = set()
        while True:
            query = {"limit": "200"}
            if cursor is not None:
                query["cursor"] = cursor
            page = self._get_json("/api/v3/sessions?" + urllib.parse.urlencode(query))
            cancellation.raise_if_cancelled()
            sessions.extend(self._parse_session_page(page, identity.device_id))
            next_cursor = page.get("next_cursor")
            if next_cursor is None:
                break
            if not isinstance(next_cursor, str) or not next_cursor:
                raise _protocol_failure("sessions.next_cursor 无效")
            if next_cursor in observed_cursors:
                raise _protocol_failure("sessions 分页 cursor 形成循环")
            observed_cursors.add(next_cursor)
            cursor = next_cursor
        return DeviceSnapshot(
            identity=identity,
            sessions=tuple(sessions),
            metadata={
                "lan": {
                    "connection": asdict(self.spec),
                    "sessions": {
                        item.session_id: {
                            "manifest_sha256": item.manifest_sha256,
                            "total_bytes": item.total_bytes,
                        }
                        for item in sessions
                    },
                }
            },
        )

    def read_manifest(self, session_id: str) -> ManifestResource:
        _require_uuid_v7(session_id, "session_id")
        response, connection = self._request(
            "GET", f"/api/v3/sessions/{session_id}", accept="application/json"
        )
        try:
            content_type = _content_type(response)
            if content_type != "application/json":
                raise _protocol_failure("manifest Content-Type 必须是 application/json")
            payload = _read_bounded(response, _MAX_MANIFEST_BYTES, "manifest")
            declared_size = _required_int_header(response, "Content-Length")
            digest = hashlib.sha256(payload).hexdigest()
            etag = _required_etag(response)
            header_digest = response.getheader("YLX-Manifest-SHA256")
            if (
                declared_size != len(payload)
                or etag != f'"{digest}"'
                or header_digest != digest
            ):
                raise LanFailure(
                    "REMOTE_CHANGED",
                    "manifest 字节与 Content-Length、ETag 或 SHA-256 不一致",
                    "重新扫描设备并为新 manifest 创建导入任务",
                )
            return ManifestResource(payload=payload, sha256=digest, identity=etag)
        finally:
            response.close()
            connection.close()

    def inspect_artifact(
        self,
        session_id: str,
        *,
        artifact_id: str,
        expected_size: int,
        expected_media_type: str,
    ) -> ArtifactResource:
        _validate_artifact_arguments(
            session_id, artifact_id, expected_size, expected_media_type
        )
        response, connection = self._request(
            "HEAD", _artifact_path(session_id, artifact_id), accept="*/*"
        )
        try:
            size = _required_int_header(response, "Content-Length")
            media_type = _content_type(response)
            identity = _required_etag(response)
            if response.getheader("Accept-Ranges") != "bytes":
                raise _protocol_failure("artifact HEAD 未声明 Accept-Ranges: bytes")
            if (
                size != expected_size
                or media_type != expected_media_type
                or identity != f'"{artifact_id}"'
            ):
                raise LanFailure(
                    "REMOTE_CHANGED",
                    "artifact HEAD 与 manifest descriptor 不一致",
                    "重新扫描设备并为新 manifest 创建导入任务",
                )
            return ArtifactResource(
                size=size,
                media_type=media_type,
                sha256=artifact_id,
                identity=identity,
            )
        finally:
            response.close()
            connection.close()

    def download_artifact(
        self,
        session_id: str,
        *,
        artifact_id: str,
        offset: int,
        expected_size: int,
        expected_media_type: str,
        expected_identity: str,
        chunk_size: int,
    ) -> Iterator[bytes]:
        _validate_artifact_arguments(
            session_id, artifact_id, expected_size, expected_media_type
        )
        if offset < 0 or offset > expected_size or chunk_size < 1:
            raise ValueError("artifact offset 或 chunk_size 无效")
        if expected_identity != f'"{artifact_id}"':
            raise ValueError("expected_identity 必须是 artifact 的强 ETag")
        if offset == expected_size:
            return
        headers = {
            "Range": f"bytes={offset}-",
            "If-Range": expected_identity,
        }
        response, connection = self._request(
            "GET",
            _artifact_path(session_id, artifact_id),
            accept="*/*",
            headers=headers,
            allowed_statuses={200, 206},
        )
        try:
            if offset > 0 and response.status != 206:
                raise LanFailure(
                    "REMOTE_CHANGED",
                    "If-Range 未返回请求的部分表示",
                    "保留旧检查点并为新远端身份创建任务",
                )
            if response.status == 200 and offset != 0:
                raise _protocol_failure("非零 Range 返回了完整表示")
            if response.getheader("Accept-Ranges") != "bytes":
                raise _protocol_failure("artifact GET 未声明 Accept-Ranges: bytes")
            if (
                _content_type(response) != expected_media_type
                or _required_etag(response) != expected_identity
            ):
                raise LanFailure(
                    "REMOTE_CHANGED",
                    "artifact GET 表示身份与 manifest 不一致",
                    "重新扫描设备并创建新任务",
                )
            body_size = _required_int_header(response, "Content-Length")
            expected_body_size = expected_size - offset
            if body_size != expected_body_size:
                raise _protocol_failure("artifact Content-Length 与请求范围不一致")
            if response.status == 206:
                expected_range = f"bytes {offset}-{expected_size - 1}/{expected_size}"
                if response.getheader("Content-Range") != expected_range:
                    raise _protocol_failure("artifact Content-Range 与请求范围不一致")
            received = 0
            reader = getattr(response, "read1", response.read)
            while chunk := reader(min(chunk_size, expected_body_size - received)):
                received += len(chunk)
                if received > expected_body_size:
                    raise _protocol_failure("artifact 返回字节超过声明范围")
                yield chunk
            if received != expected_body_size:
                raise LanFailure(
                    "NETWORK_ERROR",
                    f"artifact 连接提前结束，收到 {received}/{expected_body_size} 字节",
                    "检查网络后从已持久化检查点重试",
                )
        except (OSError, http.client.HTTPException) as exc:
            if isinstance(exc, LanFailure):
                raise
            raise LanFailure(
                "NETWORK_ERROR",
                f"artifact 下载连接中断：{exc}",
                "检查网络后从已持久化检查点重试",
            ) from exc
        finally:
            response.close()
            connection.close()

    def _get_json(self, path: str) -> dict[str, object]:
        response, connection = self._request("GET", path, accept="application/json")
        try:
            if _content_type(response) != "application/json":
                raise _protocol_failure("设备 JSON 响应 Content-Type 无效")
            payload = _read_bounded(response, _MAX_JSON_BYTES, "JSON response")
            try:
                value = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise _protocol_failure(f"设备 JSON 响应无法解析：{exc}") from exc
            if not isinstance(value, dict):
                raise _protocol_failure("设备 JSON 响应顶层必须是对象")
            return value
        finally:
            response.close()
            connection.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        accept: str,
        headers: dict[str, str] | None = None,
        allowed_statuses: set[int] | None = None,
    ) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
        connection = self._connect()
        request_headers = {
            "Accept": accept,
            "User-Agent": self.USER_AGENT,
            **(headers or {}),
        }
        credential = self._credentials.resolve(self.spec.credential_ref)
        if credential is not None:
            request_headers["Authorization"] = f"Bearer {credential}"
        try:
            connection.request(method, path, headers=request_headers)
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise LanFailure(
                "NETWORK_ERROR",
                f"无法连接设备：{exc}",
                "检查手动地址、网络和设备状态后重试",
            ) from exc
        accepted = allowed_statuses or {200}
        if response.status not in accepted:
            try:
                _read_bounded(response, 64 * 1024, "error response")
            finally:
                response.close()
                connection.close()
            raise _http_failure(response.status)
        return response, connection

    def _connect(self) -> http.client.HTTPConnection:
        host = self._parsed.hostname
        if host is None:
            raise ValueError("设备 endpoint 缺少 host")
        if self._parsed.scheme == "http":
            connection: http.client.HTTPConnection = http.client.HTTPConnection(
                host, self._parsed.port, timeout=self._timeout
            )
            try:
                connection.connect()
            except (OSError, http.client.HTTPException) as exc:
                connection.close()
                raise LanFailure(
                    "NETWORK_ERROR",
                    f"无法连接设备：{exc}",
                    "检查手动地址、网络和设备状态后重试",
                ) from exc
            return connection

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        secure = http.client.HTTPSConnection(
            host, self._parsed.port, timeout=self._timeout, context=context
        )
        try:
            secure.connect()
            peer = secure.sock.getpeercert(binary_form=True) if secure.sock else None
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            secure.close()
            raise LanFailure(
                "TLS_ERROR",
                f"设备 TLS 握手失败：{exc}",
                "检查手动地址、设备证书和 TLS 配置",
            ) from exc
        pin = self.spec.tls_pin
        if peer is None or pin is None:
            secure.close()
            raise LanFailure(
                "TLS_PIN_MISMATCH",
                "无法取得与配置匹配的设备 TLS 身份",
                "重新置备明确的设备 TLS pin 后重试",
            )
        observed = hashlib.sha256(peer).hexdigest()
        if not secrets.compare_digest(observed, pin.value):
            secure.close()
            raise LanFailure(
                "TLS_PIN_MISMATCH",
                "设备 TLS pin 与置备值不匹配",
                "停止连接并核对设备身份或受控轮换记录",
            )
        return secure

    @staticmethod
    def _parse_device(value: dict[str, object]) -> DeviceIdentity:
        try:
            device = value["device"]
            if not isinstance(device, dict):
                raise TypeError("device")
            device_id = device["device_id"]
            label = device["device_label"]
            api_version = value["api_version"]
            capabilities = value["capabilities"]
            if not isinstance(capabilities, dict):
                raise TypeError("capabilities")
        except (KeyError, TypeError) as exc:
            raise _protocol_failure(f"DeviceDescriptor 缺少字段：{exc}") from exc
        if value.get("schema") != "ylx.device.v3":
            raise _protocol_failure("设备 schema 不是 ylx.device.v3")
        if api_version != _SUPPORTED_API_VERSION:
            raise LanFailure(
                "INCOMPATIBLE_API_VERSION",
                f"设备 API 版本 {api_version!r} 不兼容；需要 3.0",
                "升级设备或使用明确支持的兼容 adapter",
            )
        if capabilities.get("range_download") is not True:
            raise LanFailure(
                "CAPABILITY_MISSING",
                "设备未声明 range_download 能力",
                "升级设备 gateway 后重试",
            )
        if not isinstance(device_id, str) or not _UUID_V4.fullmatch(device_id):
            raise _protocol_failure("device.device_id 不是 canonical UUIDv4")
        if not isinstance(label, str) or not _DEVICE_LABEL.fullmatch(label):
            raise _protocol_failure("device.device_label 无效")
        return DeviceIdentity(device_id, label, str(api_version))

    @staticmethod
    def _parse_session_page(
        value: dict[str, object], device_id: str
    ) -> tuple[DeviceSession, ...]:
        if value.get("schema") != "ylx.session-list.v2":
            raise _protocol_failure("session list schema 不兼容")
        items = value.get("items")
        diagnostics = value.get("diagnostics")
        if not isinstance(items, list) or not isinstance(diagnostics, list):
            raise _protocol_failure("session list inventory 无效")
        result: list[DeviceSession] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise _protocol_failure(f"sessions.items.{index} 不是对象")
            verification = item.get("verification")
            if verification is None:
                continue
            if not isinstance(verification, dict):
                raise _protocol_failure(f"sessions.items.{index}.verification 无效")
            verdict = verification.get("verdict")
            if verdict == "unusable":
                continue
            if verdict != "usable":
                raise _protocol_failure(
                    f"sessions.items.{index}.verification.verdict 无效"
                )
            session_id = item.get("session_id")
            manifest_sha256 = verification.get("manifest_sha256")
            total_bytes = item.get("total_bytes")
            historical_device = item.get("device")
            if not isinstance(session_id, str) or not _UUID_V7.fullmatch(session_id):
                raise _protocol_failure(f"sessions.items.{index}.session_id 无效")
            if not isinstance(manifest_sha256, str) or not _SHA256.fullmatch(
                manifest_sha256
            ):
                raise _protocol_failure(
                    f"sessions.items.{index}.verification.manifest_sha256 无效"
                )
            if not isinstance(total_bytes, int) or total_bytes < 0:
                raise _protocol_failure(f"sessions.items.{index}.total_bytes 无效")
            if (
                not isinstance(historical_device, dict)
                or historical_device.get("device_id") != device_id
            ):
                raise _protocol_failure(f"sessions.items.{index}.device 身份冲突")
            result.append(
                DeviceSession(
                    session_id=session_id,
                    locator=(
                        "ylx-device://"
                        f"{urllib.parse.quote(device_id, safe='')}/"
                        f"{urllib.parse.quote(session_id, safe='')}"
                    ),
                    label=(
                        str(item["display_name"])
                        if isinstance(item.get("display_name"), str)
                        else None
                    ),
                    created_at=(
                        str(item["started_at"])
                        if isinstance(item.get("started_at"), str)
                        else None
                    ),
                    manifest_sha256=manifest_sha256,
                    total_bytes=total_bytes,
                )
            )
        return tuple(result)


def _validate_connection_spec(spec: LanConnectionSpec) -> LanConnectionSpec:
    parsed = urllib.parse.urlsplit(spec.endpoint.strip())
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("设备 endpoint 必须是完整 http 或 https URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("设备 endpoint 不能包含凭据、查询参数或片段")
    if parsed.path not in {"", "/", "/api/v3", "/api/v3/"}:
        raise ValueError("设备 endpoint 只能是 origin 或 /api/v3 base URL")
    host = parsed.hostname
    port = f":{parsed.port}" if parsed.port is not None else ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    endpoint = f"{parsed.scheme.lower()}://{host.lower()}{port}"
    if parsed.scheme == "http":
        try:
            addresses = {
                item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)
            }
        except OSError as exc:
            raise ValueError(f"无法解析设备 endpoint：{exc}") from exc
        if not addresses or not all(_is_loopback(address) for address in addresses):
            raise ValueError("非 loopback LAN 设备必须使用 HTTPS 和显式 TLS pin")
        if spec.tls_pin is not None:
            raise ValueError("HTTP endpoint 不能配置 TLS pin")
    else:
        _validate_tls_pin(spec.tls_pin)
    return LanConnectionSpec(endpoint, spec.credential_ref, spec.tls_pin)


def _validate_tls_pin(pin: TlsPin | None) -> None:
    if pin is None:
        raise ValueError("HTTPS LAN 设备必须配置显式 TLS pin")
    supported = (
        pin.target == "leaf-certificate-der"
        and pin.algorithm == "sha256"
        and pin.encoding == "lowercase-hex"
    )
    if not supported:
        raise ValueError("不支持的 TLS pin target、algorithm 或 encoding")
    if not _SHA256.fullmatch(pin.value):
        raise ValueError("TLS pin value 必须是 lowercase hex SHA-256")


def _is_loopback(address: str) -> bool:
    try:
        import ipaddress

        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _artifact_path(session_id: str, artifact_id: str) -> str:
    return f"/api/v3/sessions/{session_id}/artifacts/{artifact_id}"


def _validate_artifact_arguments(
    session_id: str, artifact_id: str, size: int, media_type: str
) -> None:
    _require_uuid_v7(session_id, "session_id")
    if not _SHA256.fullmatch(artifact_id):
        raise ValueError("artifact_id 必须是 lowercase SHA-256")
    if size < 0:
        raise ValueError("artifact size 不能为负数")
    if not _MEDIA_TYPE.fullmatch(media_type):
        raise ValueError("artifact media_type 无效")


def _require_uuid_v7(value: str, field: str) -> None:
    if not _UUID_V7.fullmatch(value):
        raise ValueError(f"{field} 必须是 canonical UUIDv7")


def _content_type(response: http.client.HTTPResponse) -> str:
    return response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()


def _required_int_header(response: http.client.HTTPResponse, name: str) -> int:
    value = response.getheader(name)
    try:
        result = int(value) if value is not None else -1
    except ValueError as exc:
        raise _protocol_failure(f"{name} 不是整数") from exc
    if result < 0:
        raise _protocol_failure(f"缺少有效 {name}")
    return result


def _required_etag(response: http.client.HTTPResponse) -> str:
    value = response.getheader("ETag")
    if value is None or not re.fullmatch(r'"[0-9a-f]{64}"', value):
        raise _protocol_failure("缺少有效强 SHA-256 ETag")
    return value


def _read_bounded(response: http.client.HTTPResponse, limit: int, label: str) -> bytes:
    declared = response.getheader("Content-Length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError as exc:
            raise _protocol_failure(f"{label} Content-Length 无效") from exc
        if size < 0 or size > limit:
            raise _protocol_failure(f"{label} 超过大小限制")
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise _protocol_failure(f"{label} 超过大小限制")
    return payload


def _protocol_failure(message: str) -> LanFailure:
    return LanFailure(
        "PROTOCOL_ERROR",
        f"Device API v3 响应无效：{message}",
        "确认设备运行兼容的冻结 Device API v3 后重试",
    )


def _http_failure(status: int) -> LanFailure:
    values = {
        401: (
            "AUTHENTICATION_REQUIRED",
            "设备拒绝了 Bearer 凭据",
            "更新凭据引用后重试",
        ),
        403: ("FORBIDDEN", "当前主体无权读取设备会话", "联系管理员授予只读权限"),
        404: ("NOT_FOUND", "设备会话或 artifact 不存在", "重新扫描设备会话"),
        409: (
            "SESSION_NOT_VERIFIED",
            "设备没有当前 manifest 的 usable 验证结果",
            "等待设备验证完成并重新扫描",
        ),
        416: (
            "RANGE_NOT_SATISFIABLE",
            "设备拒绝了已持久化 Range 检查点",
            "核对 artifact 身份和大小后重新开始该对象",
        ),
        423: (
            "CAPTURE_BUSY",
            "设备采集资源正忙，暂不允许 artifact IO",
            "等待设备进入 idle 后重试",
        ),
    }
    code, message, action = values.get(
        status,
        (
            "DEVICE_HTTP_ERROR",
            f"设备返回 HTTP {status}",
            "检查设备状态和兼容版本后重试",
        ),
    )
    return LanFailure(code, message, action)


class ConfiguredLanDeviceProbe:
    def __init__(self, client: LanDeviceClient) -> None:
        self._client = client

    def probe(self, endpoint: str, cancellation: CancellationToken) -> DeviceSnapshot:
        if endpoint != self._client.spec.endpoint:
            raise LanFailure(
                "ENDPOINT_MISMATCH",
                "规范化设备 endpoint 与 LAN 连接配置不一致",
                "重新输入设备地址后重试",
            )
        return self._client.probe(cancellation)
