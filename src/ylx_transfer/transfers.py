from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .database import Database, utc_now
from .runtime import CancellationToken, OperationCancelled
from .tasks import (
    StaleTaskUpdate,
    TaskKind,
    TaskRecord,
    TaskRepository,
    TaskState,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TransferDirection(StrEnum):
    DOWNLOAD = "download"
    UPLOAD = "upload"


class OperationPaused(RuntimeError):
    pass


class TransferFailure(RuntimeError):
    def __init__(self, code: str, message: str, recovery_action: str) -> None:
        super().__init__(message)
        self.code = code
        self.recovery_action = recovery_action


@dataclass(frozen=True, slots=True)
class TransferSpec:
    direction: TransferDirection
    endpoint: str
    local_path: str
    expected_sha256: str
    total_size: int
    chunk_size: int = 4 * 1024 * 1024
    credential_ref: str | None = None
    publish_url: str | None = None


@dataclass(frozen=True, slots=True)
class RemoteObjectInfo:
    size: int
    sha256: str | None
    identity: str
    upload_offset: int = 0


@dataclass(frozen=True, slots=True)
class UploadProgress:
    offset: int
    identity: str


@dataclass(frozen=True, slots=True)
class TransferOperation:
    task_id: str
    spec: TransferSpec
    offset: int
    remote_identity: str | None
    checkpoint_generation: int
    completion: dict[str, Any] | None
    receipt: dict[str, Any] | None


class CredentialProvider(Protocol):
    def resolve(self, reference: str | None) -> str | None: ...


class EnvironmentCredentialProvider:
    PREFIX = "YLX_TRANSFER_CREDENTIAL_"

    def resolve(self, reference: str | None) -> str | None:
        if reference is None:
            return None
        key = self.PREFIX + re.sub(r"[^A-Za-z0-9]", "_", reference).upper()
        value = os.environ.get(key)
        if not value:
            raise TransferFailure(
                "CREDENTIAL_MISSING",
                f"找不到凭据引用：{reference}",
                f"配置环境凭据 {key} 后重试",
            )
        return value


class RemoteTransport(Protocol):
    def inspect_download(
        self, endpoint: str, credential: str | None
    ) -> RemoteObjectInfo: ...

    def download_chunks(
        self,
        endpoint: str,
        offset: int,
        chunk_size: int,
        expected_identity: str,
        credential: str | None,
    ) -> Iterator[bytes]: ...

    def inspect_upload(
        self,
        endpoint: str,
        idempotency_key: str,
        credential: str | None,
    ) -> RemoteObjectInfo: ...

    def upload_chunk(
        self,
        endpoint: str,
        *,
        offset: int,
        total_size: int,
        content: bytes,
        expected_sha256: str,
        idempotency_key: str,
        credential: str | None,
    ) -> UploadProgress: ...

    def verify_upload(
        self,
        endpoint: str,
        idempotency_key: str,
        credential: str | None,
    ) -> RemoteObjectInfo: ...

    def publish(
        self,
        publish_url: str,
        *,
        endpoint: str,
        total_size: int,
        sha256: str,
        idempotency_key: str,
        credential: str | None,
    ) -> dict[str, Any]: ...


class HttpTransport:
    """小型版本化 HTTP 对象协议实现；不与 RP-YLX 设备 v0 混用。"""

    USER_AGENT = "ylx-transfer/0.1"

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    def inspect_download(
        self, endpoint: str, credential: str | None
    ) -> RemoteObjectInfo:
        response = self._open(
            urllib.request.Request(
                endpoint,
                method="HEAD",
                headers=self._headers(credential),
            )
        )
        with response:
            return self._object_info(response.headers)

    def download_chunks(
        self,
        endpoint: str,
        offset: int,
        chunk_size: int,
        expected_identity: str,
        credential: str | None,
    ) -> Iterator[bytes]:
        headers = self._headers(credential)
        headers["Range"] = f"bytes={offset}-"
        response = self._open(urllib.request.Request(endpoint, headers=headers))
        try:
            status = getattr(response, "status", response.getcode())
            if offset > 0 and status != 206:
                raise TransferFailure(
                    "RANGE_UNSUPPORTED",
                    "远端没有按 Range 返回可恢复内容",
                    "确认存储端支持 Range 后重试",
                )
            identity = _header_identity(response.headers)
            if identity != expected_identity:
                raise TransferFailure(
                    "REMOTE_CHANGED",
                    "下载过程中远端内容身份发生变化",
                    "保留现有数据，确认远端版本后创建新任务",
                )
            while chunk := response.read(chunk_size):
                yield chunk
        except (
            TimeoutError,
            urllib.error.URLError,
            OSError,
            http.client.HTTPException,
        ) as exc:
            raise TransferFailure(
                "NETWORK_ERROR",
                f"下载连接中断：{exc}",
                "检查网络后重试，已确认的分段会保留",
            ) from exc
        finally:
            response.close()

    def inspect_upload(
        self,
        endpoint: str,
        idempotency_key: str,
        credential: str | None,
    ) -> RemoteObjectInfo:
        headers = self._headers(credential)
        headers["Idempotency-Key"] = idempotency_key
        try:
            response = self._open(
                urllib.request.Request(endpoint, method="HEAD", headers=headers)
            )
        except TransferFailure as exc:
            if exc.code == "NOT_FOUND":
                return RemoteObjectInfo(0, None, idempotency_key, 0)
            raise
        with response:
            return self._object_info(response.headers, upload=True)

    def upload_chunk(
        self,
        endpoint: str,
        *,
        offset: int,
        total_size: int,
        content: bytes,
        expected_sha256: str,
        idempotency_key: str,
        credential: str | None,
    ) -> UploadProgress:
        end = offset + len(content) - 1
        headers = self._headers(credential)
        headers.update(
            {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(content)),
                "Content-Range": f"bytes {offset}-{end}/{total_size}",
                "Idempotency-Key": idempotency_key,
                "X-Content-SHA256": expected_sha256,
            }
        )
        response = self._open(
            urllib.request.Request(
                endpoint, data=content, method="PUT", headers=headers
            )
        )
        with response:
            next_offset = int(response.headers.get("Upload-Offset", end + 1))
            identity = response.headers.get("Upload-Id", idempotency_key)
        if next_offset != end + 1:
            raise TransferFailure(
                "REMOTE_OFFSET_MISMATCH",
                "远端确认的上传位置与本次分段不一致",
                "保留任务，检查远端上传状态后重试",
            )
        return UploadProgress(next_offset, identity)

    def verify_upload(
        self,
        endpoint: str,
        idempotency_key: str,
        credential: str | None,
    ) -> RemoteObjectInfo:
        return self.inspect_upload(endpoint, idempotency_key, credential)

    def publish(
        self,
        publish_url: str,
        *,
        endpoint: str,
        total_size: int,
        sha256: str,
        idempotency_key: str,
        credential: str | None,
    ) -> dict[str, Any]:
        body = json.dumps(
            {"object_url": endpoint, "size": total_size, "sha256": sha256},
            separators=(",", ":"),
        ).encode()
        headers = self._headers(credential)
        headers.update(
            {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": idempotency_key,
            }
        )
        response = self._open(
            urllib.request.Request(
                publish_url, data=body, method="POST", headers=headers
            )
        )
        with response:
            try:
                receipt = json.load(response)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise TransferFailure(
                    "INVALID_RECEIPT",
                    "发布服务返回的回执不是有效 JSON",
                    "不要重复发布；查询远端后再重试",
                ) from exc
        if receipt.get("sha256") != sha256:
            raise TransferFailure(
                "INVALID_RECEIPT",
                "发布回执的内容摘要与上传对象不一致",
                "不要标记完成；查询远端发布状态",
            )
        return receipt

    def _open(self, request: urllib.request.Request):
        try:
            return urllib.request.urlopen(request, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            code = "NOT_FOUND" if exc.code == 404 else "HTTP_ERROR"
            raise TransferFailure(
                code,
                f"远端 HTTP 请求失败：{exc.code}",
                "检查远端地址和服务状态后重试",
            ) from exc
        except (TimeoutError, urllib.error.URLError) as exc:
            raise TransferFailure(
                "NETWORK_ERROR",
                f"无法连接远端：{exc}",
                "检查网络、地址和凭据后重试",
            ) from exc

    @classmethod
    def _headers(cls, credential: str | None) -> dict[str, str]:
        headers = {"User-Agent": cls.USER_AGENT, "Accept": "application/json"}
        if credential is not None:
            headers["Authorization"] = f"Bearer {credential}"
        return headers

    @staticmethod
    def _object_info(headers, upload: bool = False) -> RemoteObjectInfo:
        offset = int(headers.get("Upload-Offset", "0")) if upload else 0
        size = int(headers.get("X-Object-Size", headers.get("Content-Length", offset)))
        digest = headers.get("X-Content-SHA256")
        return RemoteObjectInfo(
            size=size,
            sha256=digest,
            identity=_header_identity(headers, fallback=digest),
            upload_offset=offset,
        )


class TransferRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, task: TaskRecord, spec: TransferSpec) -> TransferOperation:
        now = utc_now()
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO transfer_operations (
                    task_id, direction, spec_json, checkpoint_generation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO NOTHING
                """,
                (
                    task.task_id,
                    spec.direction.value,
                    json.dumps(asdict(spec), ensure_ascii=False, sort_keys=True),
                    task.generation,
                    now,
                    now,
                ),
            )
        return self.get(task.task_id)

    def get(self, task_id: str) -> TransferOperation:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM transfer_operations WHERE task_id = ?", (task_id,)
            ).fetchone()
        if row is None:
            raise KeyError(task_id)
        payload = json.loads(row["spec_json"])
        payload["direction"] = TransferDirection(payload["direction"])
        return TransferOperation(
            task_id=row["task_id"],
            spec=TransferSpec(**payload),
            offset=row["offset_bytes"],
            remote_identity=row["remote_identity"],
            checkpoint_generation=row["checkpoint_generation"],
            completion=(
                json.loads(row["completion_json"])
                if row["completion_json"] is not None
                else None
            ),
            receipt=(
                json.loads(row["receipt_json"])
                if row["receipt_json"] is not None
                else None
            ),
        )

    def lease(self, task_id: str, generation: int) -> TransferOperation:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE transfer_operations
                SET checkpoint_generation = ?, updated_at = ?
                WHERE task_id = ? AND checkpoint_generation <= ?
                    AND EXISTS (
                        SELECT 1 FROM tasks
                        WHERE tasks.task_id = transfer_operations.task_id
                            AND tasks.generation = ? AND tasks.state = 'running'
                    )
                """,
                (generation, now, task_id, generation, generation),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"传输任务 {task_id} 的检查点代次已过期")
        return self.get(task_id)

    def checkpoint(
        self,
        task_id: str,
        generation: int,
        offset: int,
        remote_identity: str | None = None,
    ) -> TransferOperation:
        if offset < 0:
            raise ValueError("offset 不能为负数")
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE transfer_operations
                SET offset_bytes = ?,
                    remote_identity = COALESCE(?, remote_identity),
                    updated_at = ?
                WHERE task_id = ? AND checkpoint_generation = ?
                    AND EXISTS (
                        SELECT 1 FROM tasks
                        WHERE tasks.task_id = transfer_operations.task_id
                            AND tasks.generation = ?
                            AND tasks.state IN (
                                'running', 'pause_requested', 'cancel_requested'
                            )
                    )
                """,
                (
                    offset,
                    remote_identity,
                    now,
                    task_id,
                    generation,
                    generation,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"传输任务 {task_id} 的检查点事件已过期")
        return self.get(task_id)

    def complete(
        self,
        task_id: str,
        generation: int,
        completion: Mapping[str, Any],
        receipt: Mapping[str, Any] | None = None,
    ) -> TransferOperation:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE transfer_operations
                SET completion_json = ?, receipt_json = ?, updated_at = ?
                WHERE task_id = ? AND checkpoint_generation = ?
                    AND EXISTS (
                        SELECT 1 FROM tasks
                        WHERE tasks.task_id = transfer_operations.task_id
                            AND tasks.generation = ? AND tasks.state = 'running'
                    )
                """,
                (
                    json.dumps(completion, ensure_ascii=False, sort_keys=True),
                    (
                        json.dumps(receipt, ensure_ascii=False, sort_keys=True)
                        if receipt is not None
                        else None
                    ),
                    now,
                    task_id,
                    generation,
                    generation,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"传输任务 {task_id} 的完成证据已过期")
        return self.get(task_id)


class TransferService:
    def __init__(
        self,
        *,
        root: Path,
        tasks: TaskRepository,
        transfers: TransferRepository,
        transport: RemoteTransport,
        credentials: CredentialProvider | None = None,
    ) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._temporary_root = self._root / ".transfers"
        self._temporary_root.mkdir(exist_ok=True)
        self._tasks = tasks
        self._transfers = transfers
        self._transport = transport
        self._credentials = credentials or EnvironmentCredentialProvider()

    def enqueue(self, spec: TransferSpec) -> tuple[TaskRecord, bool]:
        _validate_spec(spec, self._root)
        canonical = json.dumps(asdict(spec), sort_keys=True, separators=(",", ":"))
        key = "transfer:" + hashlib.sha256(canonical.encode()).hexdigest()
        task, created = self._tasks.create(
            kind=(
                TaskKind.DOWNLOAD
                if spec.direction is TransferDirection.DOWNLOAD
                else TaskKind.UPLOAD
            ),
            idempotency_key=key,
            parameters={"direction": spec.direction.value},
            progress_total=spec.total_size,
            progress_unit="bytes",
        )
        self._transfers.create(task, spec)
        return task, created

    def run(
        self, task_id: str, cancellation: CancellationToken | None = None
    ) -> TaskRecord:
        token = cancellation or CancellationToken()
        task = self._tasks.get(task_id)
        if task.state is TaskState.SUCCEEDED:
            return task
        running = self._tasks.claim(task_id, task.generation)
        operation = self._transfers.lease(task_id, running.generation)
        try:
            credential = self._credentials.resolve(operation.spec.credential_ref)
            if operation.spec.direction is TransferDirection.DOWNLOAD:
                completion, receipt = self._download(
                    operation, running, token, credential
                )
            else:
                completion, receipt = self._upload(
                    operation, running, token, credential
                )
            self._transfers.complete(task_id, running.generation, completion, receipt)
            return self._tasks.succeed(task_id, running.generation)
        except OperationPaused:
            return self._tasks.pause(task_id, running.generation)
        except OperationCancelled:
            return self._tasks.cancel(task_id, running.generation)
        except TransferFailure as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code=exc.code,
                message=str(exc),
                recovery_action=exc.recovery_action,
            )
        except OSError as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code="FILESYSTEM_ERROR",
                message=f"本地文件操作失败：{exc}",
                recovery_action="检查本地路径、权限和剩余空间后重试",
            )
        except Exception as exc:  # noqa: BLE001 - persistent task failure boundary
            return self._tasks.fail(
                task_id,
                running.generation,
                code="INTERNAL_ERROR",
                message=f"传输失败：{exc}",
                recovery_action="保留任务并重试；若重复失败请导出诊断信息",
            )

    def _download(
        self,
        operation: TransferOperation,
        task: TaskRecord,
        token: CancellationToken,
        credential: str | None,
    ) -> tuple[dict[str, Any], None]:
        spec = operation.spec
        destination = _safe_local(Path(spec.local_path), self._root)
        if destination.exists():
            if _file_matches(destination, spec.total_size, spec.expected_sha256):
                self._tasks.set_progress(
                    task.task_id,
                    task.generation,
                    spec.total_size,
                    spec.total_size,
                    "bytes",
                )
                return (
                    {
                        "size": spec.total_size,
                        "sha256": spec.expected_sha256,
                        "path": str(destination),
                    },
                    None,
                )
            raise TransferFailure(
                "TARGET_CONFLICT",
                "下载目标已存在，但内容不一致",
                "选择新的目标路径或人工处理现有文件",
            )

        info = self._transport.inspect_download(spec.endpoint, credential)
        if info.size != spec.total_size:
            raise TransferFailure(
                "REMOTE_CHANGED",
                "远端对象大小与任务参数不一致",
                "确认远端版本后创建新任务",
            )
        if info.sha256 is not None and info.sha256 != spec.expected_sha256:
            raise TransferFailure(
                "REMOTE_CHANGED",
                "远端对象摘要与任务参数不一致",
                "确认远端版本后创建新任务",
            )
        if operation.remote_identity and operation.remote_identity != info.identity:
            raise TransferFailure(
                "REMOTE_CHANGED",
                "远端对象身份在恢复前发生变化",
                "保留部分文件，确认远端版本后创建新任务",
            )

        part = self._temporary_root / f"{task.task_id}.part"
        offset = self._reconcile_download_checkpoint(operation, part, info.identity)
        self._tasks.set_progress(
            task.task_id, task.generation, offset, spec.total_size, "bytes"
        )
        part.parent.mkdir(parents=True, exist_ok=True)
        with part.open("ab") as output:
            for chunk in self._transport.download_chunks(
                spec.endpoint,
                offset,
                spec.chunk_size,
                info.identity,
                credential,
            ):
                self._control_point(task.task_id, task.generation, token)
                if offset + len(chunk) > spec.total_size:
                    raise TransferFailure(
                        "REMOTE_CHANGED",
                        "远端返回的数据超过预期大小",
                        "确认远端版本后创建新任务",
                    )
                output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
                offset += len(chunk)
                self._transfers.checkpoint(
                    task.task_id, task.generation, offset, info.identity
                )
                self._tasks.set_progress(
                    task.task_id, task.generation, offset, spec.total_size, "bytes"
                )

        if offset < spec.total_size:
            raise TransferFailure(
                "NETWORK_ERROR",
                f"下载连接提前结束，已保留 {offset} 字节检查点",
                "检查网络后重试，已确认的分段会保留",
            )
        if not _file_matches(part, spec.total_size, spec.expected_sha256):
            part.write_bytes(b"")
            self._transfers.checkpoint(task.task_id, task.generation, 0, info.identity)
            raise TransferFailure(
                "CONTENT_MISMATCH",
                "下载完成后的内容摘要不匹配",
                "检查远端内容和网络代理后重试",
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise TransferFailure(
                "TARGET_CONFLICT",
                "发布下载文件时目标路径已被占用",
                "人工检查目标文件后重试",
            )
        os.rename(part, destination)
        _fsync_directory(destination.parent)
        return (
            {
                "size": spec.total_size,
                "sha256": spec.expected_sha256,
                "path": str(destination),
                "remote_identity": info.identity,
            },
            None,
        )

    def _upload(
        self,
        operation: TransferOperation,
        task: TaskRecord,
        token: CancellationToken,
        credential: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        spec = operation.spec
        source = _safe_local(Path(spec.local_path), self._root)
        if not _file_matches(source, spec.total_size, spec.expected_sha256):
            raise TransferFailure(
                "LOCAL_CHANGED",
                "本地上传文件与任务参数不一致",
                "重新校验本地会话并创建新任务",
            )
        remote = self._transport.inspect_upload(
            spec.endpoint, task.idempotency_key, credential
        )
        if remote.upload_offset > spec.total_size:
            raise TransferFailure(
                "CHECKPOINT_CORRUPT",
                "远端上传位置超过对象大小",
                "查询或清理远端未完成上传后创建新任务",
            )
        if operation.remote_identity and remote.identity != operation.remote_identity:
            raise TransferFailure(
                "REMOTE_CHANGED",
                "远端上传身份在恢复前发生变化",
                "查询远端未完成上传后创建新任务",
            )
        offset = remote.upload_offset
        self._transfers.checkpoint(
            task.task_id, task.generation, offset, remote.identity
        )
        self._tasks.set_progress(
            task.task_id, task.generation, offset, spec.total_size, "bytes"
        )
        with source.open("rb") as handle:
            handle.seek(offset)
            while offset < spec.total_size:
                self._control_point(task.task_id, task.generation, token)
                content = handle.read(min(spec.chunk_size, spec.total_size - offset))
                if not content:
                    raise TransferFailure(
                        "LOCAL_CHANGED",
                        "上传过程中本地文件提前结束",
                        "重新校验本地会话并创建新任务",
                    )
                progress = self._transport.upload_chunk(
                    spec.endpoint,
                    offset=offset,
                    total_size=spec.total_size,
                    content=content,
                    expected_sha256=spec.expected_sha256,
                    idempotency_key=task.idempotency_key,
                    credential=credential,
                )
                offset = progress.offset
                self._transfers.checkpoint(
                    task.task_id, task.generation, offset, progress.identity
                )
                self._tasks.set_progress(
                    task.task_id, task.generation, offset, spec.total_size, "bytes"
                )

        if not _file_matches(source, spec.total_size, spec.expected_sha256):
            raise TransferFailure(
                "LOCAL_CHANGED",
                "上传期间本地文件内容发生变化",
                "不要发布远端对象；重新校验并创建新任务",
            )
        verified = self._transport.verify_upload(
            spec.endpoint, task.idempotency_key, credential
        )
        if verified.size != spec.total_size or verified.sha256 != spec.expected_sha256:
            raise TransferFailure(
                "REMOTE_DIGEST_MISMATCH",
                "远端回读的对象大小或摘要不匹配",
                "不要发布；检查远端上传状态后重试",
            )
        completion = {
            "size": spec.total_size,
            "sha256": spec.expected_sha256,
            "remote_identity": verified.identity,
            "endpoint": spec.endpoint,
        }
        receipt = None
        if spec.publish_url is not None:
            receipt = self._transport.publish(
                spec.publish_url,
                endpoint=spec.endpoint,
                total_size=spec.total_size,
                sha256=spec.expected_sha256,
                idempotency_key=task.idempotency_key,
                credential=credential,
            )
        return completion, receipt

    def _reconcile_download_checkpoint(
        self, operation: TransferOperation, part: Path, identity: str
    ) -> int:
        spec = operation.spec
        if part.is_symlink():
            raise TransferFailure(
                "UNSAFE_CHECKPOINT",
                "下载暂存文件被符号链接替换",
                "删除该任务的暂存文件后重试",
            )
        actual = part.stat().st_size if part.is_file() and not part.is_symlink() else 0
        offset = operation.offset
        if offset > spec.total_size or actual < offset:
            offset = 0 if actual > spec.total_size else actual
        if actual > offset:
            with part.open("r+b") as handle:
                handle.truncate(offset)
                handle.flush()
                os.fsync(handle.fileno())
        self._transfers.checkpoint(
            operation.task_id, operation.checkpoint_generation, offset, identity
        )
        return offset

    def _control_point(
        self, task_id: str, generation: int, token: CancellationToken
    ) -> None:
        token.raise_if_cancelled()
        current = self._tasks.get(task_id)
        if current.generation != generation:
            raise StaleTaskUpdate(f"任务 {task_id} 执行代次已过期")
        if current.state is TaskState.CANCEL_REQUESTED:
            raise OperationCancelled("操作已取消")
        if current.state is TaskState.PAUSE_REQUESTED:
            raise OperationPaused("操作已暂停")


class TransferScheduler:
    """进程内有界调度；传输进度和终态仍全部来自 SQLite。"""

    def __init__(self, service: TransferService, max_workers: int = 2) -> None:
        if max_workers < 1:
            raise ValueError("max_workers 必须大于零")
        self._service = service
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="ylx-transfer-network"
        )
        self._tokens: dict[str, CancellationToken] = {}
        self._lock = threading.Lock()

    def submit(self, task_id: str) -> Future[TaskRecord]:
        token = CancellationToken()
        with self._lock:
            self._tokens[task_id] = token
        future = self._executor.submit(self._service.run, task_id, token)
        future.add_done_callback(lambda _: self._forget(task_id))
        return future

    def cancel(self, task_id: str) -> None:
        self._service._tasks.request_cancel(task_id)
        with self._lock:
            token = self._tokens.get(task_id)
        if token is not None:
            token.cancel()

    def pause(self, task_id: str) -> None:
        self._service._tasks.request_pause(task_id)

    def close(self) -> None:
        self._executor.shutdown(wait=True)

    def _forget(self, task_id: str) -> None:
        with self._lock:
            self._tokens.pop(task_id, None)


def _validate_spec(spec: TransferSpec, root: Path) -> None:
    parsed = urllib.parse.urlsplit(spec.endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("远端地址必须是完整的 http 或 https URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("远端地址不能包含凭据或片段")
    if spec.publish_url is not None:
        publish = urllib.parse.urlsplit(spec.publish_url)
        if publish.scheme not in {"http", "https"} or not publish.hostname:
            raise ValueError("发布地址必须是完整的 http 或 https URL")
    if spec.total_size < 0 or spec.chunk_size < 1:
        raise ValueError("传输大小和分段大小不合法")
    if not _SHA256.fullmatch(spec.expected_sha256):
        raise ValueError("expected_sha256 必须是小写 SHA-256")
    _safe_local(Path(spec.local_path), root)


def _safe_local(path: Path, root: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("本地路径必须是绝对路径")
    resolved_parent = path.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError as exc:
        raise ValueError("本地路径必须位于应用仓库目录内") from exc
    if path.is_symlink():
        raise ValueError("本地路径不能是符号链接")
    return path


def _header_identity(headers, fallback: str | None = None) -> str:
    identity = headers.get("ETag") or headers.get("Upload-Id") or fallback
    if not identity:
        raise TransferFailure(
            "REMOTE_IDENTITY_MISSING",
            "远端没有提供可用于恢复的内容身份",
            "配置 ETag 或 Upload-Id 后重试",
        )
    return identity.strip('"')


def _file_matches(path: Path, size: int, sha256: str) -> bool:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest() == sha256


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
