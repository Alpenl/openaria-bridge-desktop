from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .contracts import (
    MAX_MANIFEST_BYTES,
    ContractValidationError,
    DeviceSessionManifest,
    parse_device_session_manifest,
    validate_device_session_directory,
)
from .database import Database, SourceRepository, utc_now
from .lan import LanConnectionSpec, LanDeviceClient, LanFailure, TlsPin
from .models import Availability, SourceKind
from .runtime import CancellationToken, OperationCancelled
from .sdk import (
    SdkGateway,
    SdkOperationError,
    SessionCopyPlan,
    SessionFile,
)
from .tasks import TaskKind, TaskRecord, TaskRepository, TaskState

_SAFE_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ImportFailure(RuntimeError):
    def __init__(self, code: str, message: str, recovery_action: str) -> None:
        super().__init__(message)
        self.code = code
        self.recovery_action = recovery_action


@dataclass(frozen=True, slots=True)
class ImportOperation:
    task_id: str
    source_session_record_id: str
    session_id: str
    revision: str
    staging_path: Path
    final_path: Path
    copy_plan: SessionCopyPlan


@dataclass(frozen=True, slots=True)
class LocalSessionRecord:
    local_session_id: str
    session_id: str
    revision: str
    path: Path
    source_session_record_id: str
    total_bytes: int
    imported_at: str


@dataclass(frozen=True, slots=True)
class LanImportOperation:
    task_id: str
    connection: LanConnectionSpec
    manifest_sha256: str
    checkpoint_generation: int
    checkpoints: dict[str, tuple[int, str]]


class LanImportRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        task: TaskRecord,
        connection_spec: LanConnectionSpec,
        manifest_sha256: str,
        files: tuple[SessionFile, ...],
    ) -> LanImportOperation:
        now = utc_now()
        spec = {
            "endpoint": connection_spec.endpoint,
            "credential_ref": connection_spec.credential_ref,
            "tls_pin": (
                {
                    "target": connection_spec.tls_pin.target,
                    "algorithm": connection_spec.tls_pin.algorithm,
                    "encoding": connection_spec.tls_pin.encoding,
                    "value": connection_spec.tls_pin.value,
                }
                if connection_spec.tls_pin is not None
                else None
            ),
        }
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO lan_import_operations (
                    task_id, spec_json, manifest_sha256, checkpoint_generation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO NOTHING
                """,
                (
                    task.task_id,
                    json.dumps(spec, ensure_ascii=False, sort_keys=True),
                    manifest_sha256,
                    task.generation,
                    now,
                    now,
                ),
            )
            for item in files:
                if item.relative_path == "manifest.json":
                    continue
                connection.execute(
                    """
                    INSERT INTO lan_import_checkpoints (
                        task_id, relative_path, offset_bytes, remote_identity,
                        updated_at
                    ) VALUES (?, ?, 0, ?, ?)
                    ON CONFLICT(task_id, relative_path) DO NOTHING
                    """,
                    (task.task_id, item.relative_path, f'"{item.sha256}"', now),
                )
        return self.get(task.task_id)

    def get(self, task_id: str) -> LanImportOperation | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM lan_import_operations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            checkpoints = connection.execute(
                """
                SELECT relative_path, offset_bytes, remote_identity
                FROM lan_import_checkpoints WHERE task_id = ?
                """,
                (task_id,),
            ).fetchall()
        if row is None:
            return None
        raw_spec = json.loads(row["spec_json"])
        raw_pin = raw_spec.get("tls_pin")
        spec = LanConnectionSpec(
            endpoint=str(raw_spec["endpoint"]),
            credential_ref=(
                str(raw_spec["credential_ref"])
                if raw_spec.get("credential_ref") is not None
                else None
            ),
            tls_pin=TlsPin(**raw_pin) if isinstance(raw_pin, dict) else None,
        )
        return LanImportOperation(
            task_id=row["task_id"],
            connection=spec,
            manifest_sha256=row["manifest_sha256"],
            checkpoint_generation=row["checkpoint_generation"],
            checkpoints={
                item["relative_path"]: (
                    item["offset_bytes"],
                    item["remote_identity"],
                )
                for item in checkpoints
            },
        )

    def lease(self, task_id: str, generation: int) -> LanImportOperation:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE lan_import_operations SET updated_at = ?
                WHERE task_id = ? AND checkpoint_generation = ?
                    AND EXISTS (
                        SELECT 1 FROM tasks
                        WHERE tasks.task_id = lan_import_operations.task_id
                            AND tasks.generation = ? AND tasks.state = 'running'
                    )
                """,
                (now, task_id, generation, generation),
            )
            if cursor.rowcount != 1:
                from .tasks import StaleTaskUpdate

                raise StaleTaskUpdate(f"LAN 导入任务 {task_id} 的 lease 已过期")
        operation = self.get(task_id)
        if operation is None:
            raise KeyError(task_id)
        return operation

    def checkpoint(
        self,
        task_id: str,
        generation: int,
        relative_path: str,
        offset: int,
        remote_identity: str,
    ) -> None:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE lan_import_checkpoints
                SET offset_bytes = ?, updated_at = ?
                WHERE task_id = ? AND relative_path = ?
                    AND remote_identity = ?
                    AND EXISTS (
                        SELECT 1 FROM lan_import_operations operation
                        JOIN tasks ON tasks.task_id = operation.task_id
                        WHERE operation.task_id = lan_import_checkpoints.task_id
                            AND operation.checkpoint_generation = ?
                            AND tasks.generation = ? AND tasks.state = 'running'
                    )
                """,
                (
                    offset,
                    now,
                    task_id,
                    relative_path,
                    remote_identity,
                    generation,
                    generation,
                ),
            )
            if cursor.rowcount != 1:
                from .tasks import StaleTaskUpdate

                raise StaleTaskUpdate(
                    f"LAN artifact {relative_path} 的检查点事件已过期"
                )


class ImportRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create_operation(
        self,
        *,
        task_id: str,
        source_session_record_id: str,
        session_id: str,
        revision: str,
        staging_path: Path,
        final_path: Path,
        copy_plan: SessionCopyPlan,
    ) -> ImportOperation:
        now = utc_now()
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO import_operations (
                    task_id, source_session_record_id, session_id, revision,
                    staging_path, final_path, copy_plan_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO NOTHING
                """,
                (
                    task_id,
                    source_session_record_id,
                    session_id,
                    revision,
                    str(staging_path),
                    str(final_path),
                    _encode_plan(copy_plan),
                    now,
                    now,
                ),
            )
        return self.get_operation(task_id)

    def get_operation(self, task_id: str) -> ImportOperation | None:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM import_operations WHERE task_id = ?", (task_id,)
            ).fetchone()
        if row is None:
            return None
        return ImportOperation(
            task_id=row["task_id"],
            source_session_record_id=row["source_session_record_id"],
            session_id=row["session_id"],
            revision=row["revision"],
            staging_path=Path(row["staging_path"]),
            final_path=Path(row["final_path"]),
            copy_plan=_decode_plan(row["copy_plan_json"]),
        )

    def register_local(self, operation: ImportOperation) -> LocalSessionRecord:
        now = utc_now()
        total_bytes = sum(item.size for item in operation.copy_plan.files)
        local_session_id = str(uuid.uuid4())
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO local_sessions (
                    local_session_id, session_id, revision, path,
                    source_session_record_id, total_bytes, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, revision) DO NOTHING
                """,
                (
                    local_session_id,
                    operation.session_id,
                    operation.revision,
                    str(operation.final_path),
                    operation.source_session_record_id,
                    total_bytes,
                    now,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM local_sessions
                WHERE session_id = ? AND revision = ?
                """,
                (operation.session_id, operation.revision),
            ).fetchone()
        return self._local_from_row(row)

    def list_local(self) -> tuple[LocalSessionRecord, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM local_sessions ORDER BY imported_at DESC"
            ).fetchall()
        return tuple(self._local_from_row(row) for row in rows)

    def get_local(self, local_session_id: str) -> LocalSessionRecord:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM local_sessions WHERE local_session_id = ?",
                (local_session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(local_session_id)
        return self._local_from_row(row)

    @staticmethod
    def _local_from_row(row) -> LocalSessionRecord:
        return LocalSessionRecord(
            local_session_id=row["local_session_id"],
            session_id=row["session_id"],
            revision=row["revision"],
            path=Path(row["path"]),
            source_session_record_id=row["source_session_record_id"],
            total_bytes=row["total_bytes"],
            imported_at=row["imported_at"],
        )


class ImportService:
    def __init__(
        self,
        *,
        repository_root: Path,
        sources: SourceRepository,
        tasks: TaskRepository,
        imports: ImportRepository,
        sdk: SdkGateway,
        lan_imports: LanImportRepository,
        free_space: Callable[[Path], int] | None = None,
        chunk_size: int = 1024 * 1024,
        lan_client_factory=None,
    ) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size 必须大于零")
        self._root = repository_root.resolve()
        self._sources = sources
        self._tasks = tasks
        self._imports = imports
        self._lan_imports = lan_imports
        self._lan_client_factory = lan_client_factory or (
            lambda spec: LanDeviceClient(spec)
        )
        self._sdk = sdk
        self._free_space = free_space or (lambda path: shutil.disk_usage(path).free)
        self._chunk_size = chunk_size
        (self._root / ".staging").mkdir(parents=True, exist_ok=True)
        (self._root / "sessions").mkdir(parents=True, exist_ok=True)

    def enqueue(self, source_session_record_id: str) -> tuple[TaskRecord, bool]:
        self._sources.get_session(source_session_record_id)
        return self._tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key=f"import:{source_session_record_id}",
            parameters={"source_session_record_id": source_session_record_id},
            progress_unit="bytes",
        )

    def run(
        self,
        task_id: str,
        cancellation: CancellationToken | None = None,
        stage_hook: Callable[[str], None] | None = None,
    ) -> TaskRecord:
        token = cancellation or CancellationToken()
        hook = stage_hook or (lambda stage: None)
        task = self._tasks.get(task_id)
        if task.kind is not TaskKind.IMPORT:
            raise ValueError("任务不是导入任务")
        if task.state is TaskState.SUCCEEDED:
            return task
        running = self._tasks.claim(task_id, task.generation)
        try:
            operation = self._imports.get_operation(task_id)
            if operation is None:
                operation = self._prepare_operation(running, token)
            lan_operation = self._lan_imports.get(task_id)
            if lan_operation is not None:
                lan_operation = self._lan_imports.lease(task_id, running.generation)
            hook("planned")
            if lan_operation is None:
                self._execute_copy(operation, running.generation, token)
            else:
                self._execute_lan_copy(
                    operation, lan_operation, running.generation, token
                )
            hook("copied")
            self._publish_or_adopt(operation, token)
            hook("published")
            self._imports.register_local(operation)
            total = sum(item.size for item in operation.copy_plan.files)
            self._tasks.set_progress(task_id, running.generation, total, total, "bytes")
            return self._tasks.succeed(task_id, running.generation)
        except OperationCancelled:
            return self._tasks.cancel(task_id, running.generation)
        except ImportFailure as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code=exc.code,
                message=str(exc),
                recovery_action=exc.recovery_action,
            )
        except LanFailure as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code=exc.code,
                message=str(exc),
                recovery_action=exc.recovery_action,
            )
        except ContractValidationError as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code="INVALID_SESSION",
                message=str(exc),
                recovery_action="重新扫描设备；若仍失败请保留来源并导出诊断信息",
            )
        except FileNotFoundError as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code="SOURCE_REMOVED",
                message=f"源文件不可用：{exc}",
                recovery_action="重新连接设备或插入原介质，然后重试",
            )
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                code = "INSUFFICIENT_SPACE"
                action = "释放本地仓库空间，然后重试"
            else:
                code = "FILESYSTEM_ERROR"
                action = "检查源介质和本地仓库权限，然后重试"
            return self._tasks.fail(
                task_id,
                running.generation,
                code=code,
                message=f"文件操作失败：{exc}",
                recovery_action=action,
            )
        except SdkOperationError as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code="INVALID_SESSION",
                message=str(exc),
                recovery_action="在来源列表查看校验问题，修复或重新录制后重试",
            )
        except Exception as exc:  # noqa: BLE001 - persistent task failure boundary
            return self._tasks.fail(
                task_id,
                running.generation,
                code="INTERNAL_ERROR",
                message=f"导入失败：{exc}",
                recovery_action="保留任务并重试；若重复失败请导出诊断信息",
            )

    def recover(self) -> tuple[TaskRecord, ...]:
        return tuple(
            task
            for task in self._tasks.recover_incomplete()
            if task.kind is TaskKind.IMPORT and task.state is TaskState.QUEUED
        )

    def _prepare_operation(
        self, task: TaskRecord, token: CancellationToken
    ) -> ImportOperation:
        record_id = str(task.parameters["source_session_record_id"])
        source_session = self._sources.get_session(record_id)
        if source_session.availability is Availability.OFFLINE:
            raise ImportFailure(
                "SOURCE_REMOVED",
                "源设备或介质当前不可用",
                "重新连接设备或插入原介质，然后重试",
            )
        source_path = Path(source_session.locator)
        if not source_path.is_absolute():
            source = self._sources.get_source(source_session.source_id)
            if source.kind is SourceKind.DEVICE:
                return self._prepare_lan_operation(
                    task, source_session, source.metadata
                )
            raise ImportFailure(
                "INVALID_SOURCE",
                "来源 locator 不是可导入的绝对介质路径",
                "重新扫描来源后重试",
            )
        device_manifest = _read_media_device_session(source_path)
        plan = (
            _device_session_copy_plan(device_manifest)
            if device_manifest is not None
            else self._sdk.build_copy_plan(source_path, token)
        )
        _validate_plan(plan)
        if plan.session_id != source_session.session_id:
            raise ImportFailure(
                "SESSION_ID_MISMATCH",
                "SDK 返回的会话身份与发现记录不一致",
                "重新扫描介质；若仍失败请导出诊断信息",
            )
        revision = _plan_revision(plan)
        final_path = self._root / "sessions" / revision[:16] / plan.session_id
        operation = self._imports.create_operation(
            task_id=task.task_id,
            source_session_record_id=record_id,
            session_id=plan.session_id,
            revision=revision,
            staging_path=self._root / ".staging" / task.task_id / plan.session_id,
            final_path=final_path,
            copy_plan=plan,
        )
        total = sum(item.size for item in plan.files)
        self._tasks.set_progress(task.task_id, task.generation, 0, total, "bytes")
        return operation

    def _prepare_lan_operation(
        self, task: TaskRecord, source_session, source_metadata: dict[str, object]
    ) -> ImportOperation:
        try:
            lan_metadata = source_metadata["lan"]
            if not isinstance(lan_metadata, dict):
                raise TypeError("lan")
            raw_connection = lan_metadata["connection"]
            sessions = lan_metadata["sessions"]
            if not isinstance(raw_connection, dict) or not isinstance(sessions, dict):
                raise TypeError("connection/sessions")
            session_fact = sessions[source_session.session_id]
            if not isinstance(session_fact, dict):
                raise TypeError("session fact")
            raw_pin = raw_connection.get("tls_pin")
            spec = LanConnectionSpec(
                endpoint=str(raw_connection["endpoint"]),
                credential_ref=(
                    str(raw_connection["credential_ref"])
                    if raw_connection.get("credential_ref") is not None
                    else None
                ),
                tls_pin=(TlsPin(**raw_pin) if isinstance(raw_pin, dict) else None),
            )
            discovered_sha256 = str(session_fact["manifest_sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ImportFailure(
                "LAN_SOURCE_CONFIG_INVALID",
                f"LAN 来源缺少可恢复连接事实：{exc}",
                "使用设备连接对话框重新扫描后重试",
            ) from exc
        client = self._lan_client_factory(spec)
        manifest_resource = client.read_manifest(source_session.session_id)
        if manifest_resource.sha256 != discovered_sha256:
            raise ImportFailure(
                "REMOTE_CHANGED",
                "设备 manifest 自发现后发生变化",
                "重新扫描设备并为新 manifest 创建导入任务",
            )
        manifest = parse_device_session_manifest(
            manifest_resource.payload,
            expected_session_id=source_session.session_id,
        )
        plan = _device_session_copy_plan(manifest)
        _validate_plan(plan)
        revision = _plan_revision(plan)
        operation = self._imports.create_operation(
            task_id=task.task_id,
            source_session_record_id=source_session.record_id,
            session_id=plan.session_id,
            revision=revision,
            staging_path=self._root / ".staging" / task.task_id / plan.session_id,
            final_path=self._root / "sessions" / revision[:16] / plan.session_id,
            copy_plan=plan,
        )
        self._lan_imports.create(
            task,
            spec,
            manifest.sha256,
            plan.files,
        )
        total = sum(item.size for item in plan.files)
        self._tasks.set_progress(task.task_id, task.generation, 0, total, "bytes")
        return operation

    def _execute_lan_copy(
        self,
        operation: ImportOperation,
        lan_operation: LanImportOperation,
        generation: int,
        token: CancellationToken,
    ) -> None:
        if operation.final_path.exists():
            return
        stage = operation.staging_path
        if stage.is_symlink():
            raise ImportFailure(
                "UNSAFE_STAGING_PATH",
                "暂存目录被符号链接替换",
                "删除受影响任务的暂存目录后重试",
            )
        stage.mkdir(parents=True, exist_ok=True)
        manifest = parse_device_session_manifest(
            operation.copy_plan.files[-1].inline_content or b"",
            expected_session_id=operation.session_id,
        )
        descriptors = {item.relative_path: item for item in manifest.artifacts}
        client = self._lan_client_factory(lan_operation.connection)
        total = sum(item.size for item in operation.copy_plan.files)
        completed = 0
        pending_size = sum(
            item.size
            for item in operation.copy_plan.files
            if not _matches(_safe_destination(stage, item.relative_path), item)
        )
        if self._free_space(self._root) < pending_size:
            raise ImportFailure(
                "INSUFFICIENT_SPACE",
                f"本地空间不足，还需要至少 {pending_size} 字节",
                "释放本地仓库空间，然后重试",
            )
        for item in operation.copy_plan.files[:-1]:
            destination = _safe_destination(stage, item.relative_path)
            if _matches(destination, item):
                completed += item.size
                continue
            descriptor = descriptors[item.relative_path]
            temporary = destination.with_name(f".{destination.name}.part")
            if temporary.is_symlink() or (
                temporary.exists() and not temporary.is_file()
            ):
                raise ImportFailure(
                    "UNSAFE_STAGING_PATH",
                    f"LAN 暂存对象不是普通文件：{item.relative_path}",
                    "删除受影响任务的暂存目录后重试",
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            _reject_symlink_parents(destination, stage)
            offset = temporary.stat().st_size if temporary.exists() else 0
            if offset > item.size:
                temporary.unlink()
                offset = 0
            remote = client.inspect_artifact(
                operation.session_id,
                artifact_id=descriptor.artifact_id,
                expected_size=item.size,
                expected_media_type=descriptor.media_type,
            )
            self._lan_imports.checkpoint(
                operation.task_id,
                generation,
                item.relative_path,
                offset,
                remote.identity,
            )
            self._tasks.set_progress(
                operation.task_id, generation, completed + offset, total, "bytes"
            )
            with temporary.open("ab") as output:
                for chunk in client.download_artifact(
                    operation.session_id,
                    artifact_id=descriptor.artifact_id,
                    offset=offset,
                    expected_size=item.size,
                    expected_media_type=descriptor.media_type,
                    expected_identity=remote.identity,
                    chunk_size=self._chunk_size,
                ):
                    token.raise_if_cancelled()
                    output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                    offset += len(chunk)
                    self._lan_imports.checkpoint(
                        operation.task_id,
                        generation,
                        item.relative_path,
                        offset,
                        remote.identity,
                    )
                    self._tasks.set_progress(
                        operation.task_id,
                        generation,
                        completed + offset,
                        total,
                        "bytes",
                    )
            if not _matches(temporary, item):
                if temporary.exists():
                    temporary.unlink()
                self._lan_imports.checkpoint(
                    operation.task_id,
                    generation,
                    item.relative_path,
                    0,
                    remote.identity,
                )
                raise ImportFailure(
                    "CONTENT_MISMATCH",
                    f"LAN artifact 大小或摘要不匹配：{item.relative_path}",
                    "重新扫描设备并从该 artifact 起点重试",
                )
            os.replace(temporary, destination)
            _fsync_directory(destination.parent)
            completed += item.size

        manifest_file = operation.copy_plan.files[-1]
        destination = _safe_destination(stage, manifest_file.relative_path)
        if not _matches(destination, manifest_file):
            if destination.is_symlink():
                raise ImportFailure(
                    "UNSAFE_STAGING_PATH",
                    "LAN manifest 暂存路径被符号链接替换",
                    "删除受影响任务的暂存目录后重试",
                )
            temporary = destination.with_name(f".{destination.name}.part")
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()
            with temporary.open("xb") as output:
                output.write(manifest.payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            _fsync_directory(destination.parent)
        validate_device_session_directory(stage, expected_manifest=manifest.payload)
        self._tasks.set_progress(operation.task_id, generation, total, total, "bytes")
        _fsync_directory(stage)

    def _execute_copy(
        self,
        operation: ImportOperation,
        generation: int,
        token: CancellationToken,
    ) -> None:
        # 崩溃可能发生在原子发布后、数据库登记前；此时直接走收养校验。
        if operation.final_path.exists():
            return
        source_session = self._sources.get_session(operation.source_session_record_id)
        if source_session.availability is Availability.OFFLINE:
            raise ImportFailure(
                "SOURCE_REMOVED",
                "源设备或介质当前不可用",
                "重新连接设备或插入原介质，然后重试",
            )
        source_root = Path(source_session.locator).resolve(strict=True)
        stage = operation.staging_path
        if stage.is_symlink():
            raise ImportFailure(
                "UNSAFE_STAGING_PATH",
                "暂存目录被符号链接替换",
                "删除受影响任务的暂存目录后重试",
            )
        stage.mkdir(parents=True, exist_ok=True)
        completed = 0
        pending_size = 0
        for item in operation.copy_plan.files:
            destination = _safe_destination(stage, item.relative_path)
            if _matches(destination, item):
                completed += item.size
            else:
                pending_size += item.size
        if self._free_space(self._root) < pending_size:
            raise ImportFailure(
                "INSUFFICIENT_SPACE",
                f"本地空间不足，还需要至少 {pending_size} 字节",
                "释放本地仓库空间，然后重试",
            )
        self._tasks.set_progress(
            operation.task_id,
            generation,
            completed,
            sum(item.size for item in operation.copy_plan.files),
            "bytes",
        )

        for item in operation.copy_plan.files:
            token.raise_if_cancelled()
            destination = _safe_destination(stage, item.relative_path)
            if _matches(destination, item):
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            _reject_symlink_parents(destination, stage)
            temporary = destination.with_name(f".{destination.name}.part")
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()
            digest = hashlib.sha256()
            written = 0
            try:
                with temporary.open("xb") as output:
                    if item.inline_content is not None:
                        chunks = (item.inline_content,)
                    else:
                        source = _safe_source(source_root, item.relative_path)
                        chunks = _read_chunks(source, self._chunk_size, token)
                    for chunk in chunks:
                        token.raise_if_cancelled()
                        output.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
                        self._tasks.set_progress(
                            operation.task_id,
                            generation,
                            completed + written,
                            sum(entry.size for entry in operation.copy_plan.files),
                            "bytes",
                        )
                    output.flush()
                    os.fsync(output.fileno())
                if written != item.size or digest.hexdigest() != item.sha256:
                    raise ImportFailure(
                        "CONTENT_MISMATCH",
                        f"文件内容与清单不符：{item.relative_path}",
                        "重新插入原始介质并重试；若仍失败请重新录制",
                    )
                os.replace(temporary, destination)
                completed += item.size
            except BaseException:
                if temporary.exists():
                    temporary.unlink()
                raise

        self._validate_copied_session(operation, stage, token)
        _fsync_directory(stage)

    def _validate_copied_session(
        self,
        operation: ImportOperation,
        directory: Path,
        token: CancellationToken,
    ) -> None:
        if operation.copy_plan.format_version == "ylx.device-session.v1":
            validate_device_session_directory(
                directory,
                expected_manifest=operation.copy_plan.files[-1].inline_content,
            )
            return
        report = self._sdk.validate_session(directory, token)
        if not report.valid:
            raise ImportFailure(
                "TARGET_VALIDATION_FAILED",
                "复制后的会话未通过 SDK 校验：" + "；".join(report.errors),
                "保留来源并重试；若仍失败请导出诊断信息",
            )

    def _publish_or_adopt(
        self,
        operation: ImportOperation,
        token: CancellationToken,
    ) -> None:
        token.raise_if_cancelled()
        final = operation.final_path
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            if not _plan_matches(final, operation.copy_plan):
                raise ImportFailure(
                    "TARGET_CONFLICT",
                    "目标会话修订目录已存在，但内容不一致",
                    "不要覆盖现有目录；导出诊断信息后人工检查",
                )
            try:
                self._validate_copied_session(operation, final, token)
            except (ContractValidationError, ImportFailure) as exc:
                raise ImportFailure(
                    "TARGET_CONFLICT",
                    f"目标会话修订目录已存在，但校验失败：{exc}",
                    "不要覆盖现有目录；导出诊断信息后人工检查",
                ) from exc
            _remove_empty_task_staging(operation.staging_path)
            return
        try:
            os.rename(operation.staging_path, final)
        except FileExistsError:
            if not _plan_matches(final, operation.copy_plan):
                raise ImportFailure(
                    "TARGET_CONFLICT",
                    "另一任务写入了不同的目标内容",
                    "保留两个来源并导出诊断信息",
                )
        _remove_empty_task_staging(operation.staging_path)
        _fsync_directory(final.parent)


def _read_media_device_session(path: Path) -> DeviceSessionManifest | None:
    manifest_path = path / "manifest.json"
    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        payload = manifest_path.read_bytes()
        value = json.loads(payload)
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != "ylx.device-session.v1":
        return None
    return validate_device_session_directory(path)


def _device_session_copy_plan(
    manifest: DeviceSessionManifest,
) -> SessionCopyPlan:
    files = tuple(
        SessionFile(
            relative_path=item.relative_path,
            size=item.size,
            sha256=item.sha256,
        )
        for item in manifest.artifacts
    ) + (
        SessionFile(
            relative_path="manifest.json",
            size=len(manifest.payload),
            sha256=manifest.sha256,
            inline_content=manifest.payload,
        ),
    )
    return SessionCopyPlan(
        session_id=manifest.session_id,
        format_version="ylx.device-session.v1",
        files=files,
        commit_last="manifest.json",
    )


def _validate_plan(plan: SessionCopyPlan) -> None:
    if not _SAFE_SESSION_ID.fullmatch(plan.session_id):
        raise ImportFailure(
            "UNSAFE_SESSION_ID",
            "会话 ID 不能安全用作本地身份",
            "使用新版录制端重新生成会话",
        )
    if not plan.files or plan.files[-1].relative_path != plan.commit_last:
        raise ImportFailure(
            "INVALID_COPY_PLAN",
            "SDK 复制计划没有把提交对象放在最后",
            "升级 ylx-card-pipeline 后重试",
        )
    seen = set()
    for item in plan.files:
        _safe_parts(item.relative_path)
        if (
            item.relative_path in seen
            or item.size < 0
            or not _SHA256.fullmatch(item.sha256)
        ):
            raise ImportFailure(
                "INVALID_COPY_PLAN",
                f"SDK 复制计划条目不合法：{item.relative_path}",
                "升级 ylx-card-pipeline 后重试",
            )
        if item.inline_content is not None and len(item.inline_content) != item.size:
            raise ImportFailure(
                "INVALID_COPY_PLAN",
                f"SDK 内联对象大小不符：{item.relative_path}",
                "升级 ylx-card-pipeline 后重试",
            )
        seen.add(item.relative_path)


def _plan_revision(plan: SessionCopyPlan) -> str:
    encoded = json.dumps(
        {
            "session_id": plan.session_id,
            "format_version": plan.format_version,
            "files": [
                [item.relative_path, item.size, item.sha256] for item in plan.files
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_parts(relative_path: str) -> tuple[str, ...]:
    if "\\" in relative_path or "\x00" in relative_path:
        raise ImportFailure(
            "UNSAFE_PATH", f"不安全的相对路径：{relative_path}", "升级 SDK 后重试"
        )
    path = PurePosixPath(relative_path)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        raise ImportFailure(
            "UNSAFE_PATH", f"不安全的相对路径：{relative_path}", "升级 SDK 后重试"
        )
    return path.parts


def _safe_destination(root: Path, relative_path: str) -> Path:
    destination = root.joinpath(*_safe_parts(relative_path))
    try:
        destination.parent.resolve(strict=False).relative_to(root.resolve())
    except ValueError as exc:
        raise ImportFailure(
            "UNSAFE_PATH", f"目标路径逃逸：{relative_path}", "删除暂存目录后重试"
        ) from exc
    return destination


def _safe_source(root: Path, relative_path: str) -> Path:
    candidate = root.joinpath(*_safe_parts(relative_path))
    if candidate.is_symlink():
        raise ImportFailure(
            "UNSAFE_SOURCE_PATH",
            f"源文件不能是符号链接：{relative_path}",
            "使用原始录制介质重新扫描",
        )
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ImportFailure(
            "UNSAFE_SOURCE_PATH",
            f"源文件路径逃逸：{relative_path}",
            "使用原始录制介质重新扫描",
        ) from exc
    if not resolved.is_file():
        raise ImportFailure(
            "UNSAFE_SOURCE_PATH",
            f"源对象不是普通文件：{relative_path}",
            "使用原始录制介质重新扫描",
        )
    return resolved


def _reject_symlink_parents(path: Path, root: Path) -> None:
    current = path.parent
    while current != root:
        if current.is_symlink():
            raise ImportFailure(
                "UNSAFE_STAGING_PATH",
                "暂存目录包含符号链接",
                "删除受影响任务的暂存目录后重试",
            )
        current = current.parent


def _read_chunks(path: Path, size: int, token: CancellationToken):
    with path.open("rb") as source:
        while chunk := source.read(size):
            token.raise_if_cancelled()
            yield chunk


def _matches(path: Path, expected: SessionFile) -> bool:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected.size:
        return False
    return _hash_file(path) == expected.sha256


def _plan_matches(root: Path, plan: SessionCopyPlan) -> bool:
    return all(
        _matches(_safe_destination(root, item.relative_path), item)
        for item in plan.files
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_empty_task_staging(staging_path: Path) -> None:
    try:
        staging_path.parent.rmdir()
    except FileNotFoundError:
        pass
    except OSError as exc:
        if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
            raise


def _encode_plan(plan: SessionCopyPlan) -> str:
    return json.dumps(
        {
            "session_id": plan.session_id,
            "format_version": plan.format_version,
            "commit_last": plan.commit_last,
            "files": [
                {
                    "relative_path": item.relative_path,
                    "size": item.size,
                    "sha256": item.sha256,
                    "inline_content": (
                        base64.b64encode(item.inline_content).decode("ascii")
                        if item.inline_content is not None
                        else None
                    ),
                }
                for item in plan.files
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _decode_plan(encoded: str) -> SessionCopyPlan:
    payload = json.loads(encoded)
    return SessionCopyPlan(
        session_id=payload["session_id"],
        format_version=payload["format_version"],
        commit_last=payload["commit_last"],
        files=tuple(
            SessionFile(
                relative_path=item["relative_path"],
                size=item["size"],
                sha256=item["sha256"],
                inline_content=(
                    base64.b64decode(item["inline_content"])
                    if item["inline_content"] is not None
                    else None
                ),
            )
            for item in payload["files"]
        ),
    )
