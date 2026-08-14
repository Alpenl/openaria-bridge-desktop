from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol

from .contracts import (
    BUCKET_PUBLICATION_SCHEMA,
    ContractValidationError,
    DeviceArtifact,
    parse_device_session_manifest,
    validate_device_session_directory,
    validate_json_schema,
)
from .database import Database, utc_now
from .imports import ImportRepository
from .runtime import CancellationToken, OperationCancelled
from .tasks import StaleTaskUpdate, TaskKind, TaskRecord, TaskRepository, TaskState

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UUID_V7 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DEVICE_LABEL = re.compile(r"^YLX-[0-9A-F]{8}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_READ_SIZE = 1024 * 1024
_RESERVED_SEGMENT = "__ylx_evidence__"
_NORMALIZER_NAME = "ylx-stereo-delivery"
_NORMALIZER_VERSION = "1.0.0"


class PublicationError(RuntimeError):
    pass


class InvalidSourceSession(PublicationError):
    pass


class ObjectConflict(PublicationError):
    pass


class ObjectVerificationError(PublicationError):
    pass


@dataclass(frozen=True, slots=True)
class StoredObject:
    key: str
    size: int
    sha256: str | None
    media_type: str | None


class ImmutableObjectStore(Protocol):
    def inspect(self, key: str) -> StoredObject | None: ...

    def read_chunks(
        self, key: str, chunk_size: int = _READ_SIZE
    ) -> Iterator[bytes]: ...

    def put_if_absent(
        self,
        key: str,
        source: BinaryIO,
        *,
        size: int,
        sha256: str,
        media_type: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class PublicationObject:
    key: str
    size: int
    sha256: str
    media_type: str
    source_path: Path | None = None
    content: bytes | None = None

    def open(self) -> BinaryIO:
        if self.content is not None:
            from io import BytesIO

            return BytesIO(self.content)
        if self.source_path is None:
            raise PublicationError(f"发布对象没有字节来源：{self.key}")
        return self.source_path.open("rb")


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    publication_id: str
    session_id: str
    publication_key: str
    publication_bytes: bytes
    data_objects: tuple[PublicationObject, ...]


@dataclass(frozen=True, slots=True)
class _PreparedArtifact:
    artifact_id: str
    role: str
    media_type: str
    size: int
    provenance: dict[str, Any]
    source_path: Path | None = None
    content: bytes | None = None


@dataclass(frozen=True, slots=True)
class PublicationResult:
    publication_id: str
    publication_key: str
    uploaded: tuple[str, ...]
    reused: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PublicationSpec:
    local_session_id: str
    bucket: str
    raw_prefix: str
    endpoint_url: str | None = None
    region_name: str | None = None
    credential_ref: str | None = None
    tls_verify: bool | str = True


@dataclass(frozen=True, slots=True)
class PublicationOperation:
    task_id: str
    spec: PublicationSpec
    publication_id: str
    published_at: str
    publication_key: str | None
    checkpoint_generation: int
    receipt: dict[str, Any] | None


class PublicationRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        task: TaskRecord,
        spec: PublicationSpec,
        *,
        publication_id: str | None = None,
        published_at: str | None = None,
    ) -> PublicationOperation:
        identity = publication_id or new_publication_id()
        timestamp = published_at or datetime.now(UTC).isoformat(timespec="milliseconds")
        now = utc_now()
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO publication_operations (
                    task_id, local_session_id, spec_json, publication_id,
                    published_at, checkpoint_generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO NOTHING
                """,
                (
                    task.task_id,
                    spec.local_session_id,
                    json.dumps(asdict(spec), ensure_ascii=False, sort_keys=True),
                    identity,
                    timestamp,
                    task.generation,
                    now,
                    now,
                ),
            )
        return self.get(task.task_id)

    def get(self, task_id: str) -> PublicationOperation:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM publication_operations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            raise KeyError(task_id)
        return PublicationOperation(
            task_id=row["task_id"],
            spec=PublicationSpec(**json.loads(row["spec_json"])),
            publication_id=row["publication_id"],
            published_at=row["published_at"],
            publication_key=row["publication_key"],
            checkpoint_generation=row["checkpoint_generation"],
            receipt=(
                json.loads(row["receipt_json"])
                if row["receipt_json"] is not None
                else None
            ),
        )

    def list(self) -> tuple[PublicationOperation, ...]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT task_id FROM publication_operations ORDER BY created_at DESC"
            ).fetchall()
        return tuple(self.get(row["task_id"]) for row in rows)

    def lease(self, task_id: str, generation: int) -> PublicationOperation:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE publication_operations
                SET checkpoint_generation = ?, updated_at = ?
                WHERE task_id = ? AND checkpoint_generation <= ?
                    AND EXISTS (
                        SELECT 1 FROM tasks
                        WHERE tasks.task_id = publication_operations.task_id
                            AND tasks.generation = ? AND tasks.state = 'running'
                    )
                """,
                (generation, now, task_id, generation, generation),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"发布任务 {task_id} 的 lease 已过期")
        return self.get(task_id)

    def complete(
        self,
        task_id: str,
        generation: int,
        publication_key: str,
        receipt: dict[str, Any],
    ) -> PublicationOperation:
        now = utc_now()
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE publication_operations
                SET publication_key = ?, receipt_json = ?, updated_at = ?
                WHERE task_id = ? AND checkpoint_generation = ?
                    AND EXISTS (
                        SELECT 1 FROM tasks
                        WHERE tasks.task_id = publication_operations.task_id
                            AND tasks.generation = ? AND tasks.state = 'running'
                    )
                """,
                (
                    publication_key,
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True),
                    now,
                    task_id,
                    generation,
                    generation,
                ),
            )
            if cursor.rowcount != 1:
                raise StaleTaskUpdate(f"发布任务 {task_id} 的完成证据已过期")
        return self.get(task_id)


class PublicationService:
    def __init__(
        self,
        *,
        tasks: TaskRepository,
        imports: ImportRepository,
        publications: PublicationRepository,
        store_factory,
        normalization_root: Path,
    ) -> None:
        self._tasks = tasks
        self._imports = imports
        self._publications = publications
        self._store_factory = store_factory
        self._normalization_root = normalization_root.resolve()
        self._normalization_root.mkdir(parents=True, exist_ok=True)

    def enqueue(self, spec: PublicationSpec) -> tuple[TaskRecord, bool]:
        validate_publication_spec(spec)
        local = self._imports.get_local(spec.local_session_id)
        identity = json.dumps(asdict(spec), sort_keys=True, separators=(",", ":"))
        idempotency_key = "publish:" + hashlib.sha256(identity.encode()).hexdigest()
        task, created = self._tasks.create(
            kind=TaskKind.PUBLISH,
            idempotency_key=idempotency_key,
            parameters={
                "local_session_id": local.local_session_id,
                "bucket": spec.bucket,
            },
            progress_total=1,
            progress_unit="publication",
        )
        self._publications.create(task, spec)
        return task, created

    def run(
        self, task_id: str, cancellation: CancellationToken | None = None
    ) -> TaskRecord:
        token = cancellation or CancellationToken()
        task = self._tasks.get(task_id)
        if task.state is TaskState.SUCCEEDED:
            return task
        running = self._tasks.claim(task_id, task.generation)
        operation = self._publications.lease(task_id, running.generation)
        try:
            token.raise_if_cancelled()
            local = self._imports.get_local(operation.spec.local_session_id)
            plan = build_publication_plan(
                local.path,
                publication_id=operation.publication_id,
                published_at=operation.published_at,
                raw_prefix=operation.spec.raw_prefix,
                workspace=self._normalization_root / task_id,
            )
            token.raise_if_cancelled()
            store = self._store_factory(operation.spec)
            result = publish(plan, store)
            marker = read_publication(store, result.publication_key)
            token.raise_if_cancelled()
            self._publications.complete(
                task_id,
                running.generation,
                result.publication_key,
                {
                    "publication_id": result.publication_id,
                    "publication_key": result.publication_key,
                    "publication_sha256": hashlib.sha256(
                        plan.publication_bytes
                    ).hexdigest(),
                    "objects": len(plan.data_objects) + 1,
                    "readback": marker["sealed"] is True,
                },
            )
            self._tasks.set_progress(task_id, running.generation, 1, 1, "publication")
            return self._tasks.succeed(task_id, running.generation)
        except OperationCancelled:
            return self._tasks.cancel(task_id, running.generation)
        except (PublicationError, OSError, ValueError, KeyError) as exc:
            return self._tasks.fail(
                task_id,
                running.generation,
                code=(
                    "PUBLICATION_CONFLICT"
                    if isinstance(exc, ObjectConflict)
                    else "PUBLICATION_FAILED"
                ),
                message=str(exc),
                recovery_action="检查本地会话和对象存储后重试；不要覆盖已有对象",
            )


class EnvironmentS3StoreFactory:
    PREFIX = "YLX_TRANSFER_S3_"

    def __call__(self, spec: PublicationSpec) -> Boto3ObjectStore:
        access_key = None
        secret_key = None
        session_token = None
        if spec.credential_ref is not None:
            suffix = re.sub(r"[^A-Za-z0-9]", "_", spec.credential_ref).upper()
            prefix = f"{self.PREFIX}{suffix}_"
            access_key = os.environ.get(prefix + "ACCESS_KEY_ID")
            secret_key = os.environ.get(prefix + "SECRET_ACCESS_KEY")
            session_token = os.environ.get(prefix + "SESSION_TOKEN")
            if not access_key or not secret_key:
                raise PublicationError(
                    f"找不到 S3 凭据引用：{spec.credential_ref}；需要 "
                    f"{prefix}ACCESS_KEY_ID 和 {prefix}SECRET_ACCESS_KEY"
                )
        return Boto3ObjectStore.connect(
            bucket=spec.bucket,
            endpoint_url=spec.endpoint_url,
            region_name=spec.region_name,
            access_key_id=access_key,
            secret_access_key=secret_key,
            session_token=session_token,
            verify=spec.tls_verify,
        )


def new_publication_id() -> str:
    timestamp_ms = int(time.time_ns() // 1_000_000) & ((1 << 48) - 1)
    random_a = secrets.randbits(12)
    random_b = secrets.randbits(62)
    value = (
        (timestamp_ms << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    )
    encoded = f"{value:032x}"
    return (
        f"{encoded[:8]}-{encoded[8:12]}-{encoded[12:16]}-"
        f"{encoded[16:20]}-{encoded[20:]}"
    )


def build_publication_plan(
    session_directory: Path,
    *,
    publication_id: str,
    published_at: str,
    raw_prefix: str,
    workspace: Path | None = None,
) -> PublicationPlan:
    session_root = session_directory.resolve(strict=True)
    if not session_root.is_dir() or session_directory.is_symlink():
        raise InvalidSourceSession("来源会话必须是普通目录")
    try:
        source_session = validate_device_session_directory(session_root)
    except ContractValidationError as exc:
        raise InvalidSourceSession(str(exc)) from exc
    manifest_bytes = source_session.payload
    manifest = source_session.value
    _validate_manifest_identity(manifest, session_root, publication_id, published_at)
    artifacts = _prepare_publication_artifacts(
        source_session.artifacts,
        manifest,
        session_root,
        workspace,
    )
    roles = [item.role for item in artifacts]
    if len(roles) != len(set(roles)):
        raise InvalidSourceSession("Bucket Publication artifact role 必须唯一")

    prefix = _normalize_prefix(raw_prefix)
    device = manifest["device"]
    session_id = str(manifest["session_id"])
    authority = f"{prefix}{device['device_id']}/{session_id}/"
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    manifest_key = f"{authority}f-{manifest_sha256}"
    publication_key = f"{authority}{_RESERVED_SEGMENT}/publication.json"

    published_artifacts: list[dict[str, Any]] = []
    data_objects: list[PublicationObject] = []
    for artifact in artifacts:
        artifact_id = artifact.artifact_id
        key = f"{authority}f-{artifact_id}"
        published_artifacts.append(
            {
                "artifact_id": artifact_id,
                "role": artifact.role,
                "object_key": key,
                "media_type": artifact.media_type,
                "bytes": artifact.size,
                "sha256": artifact.artifact_id,
                "provenance": artifact.provenance,
            }
        )
        data_objects.append(
            PublicationObject(
                key=key,
                size=artifact.size,
                sha256=artifact.artifact_id,
                media_type=artifact.media_type,
                source_path=artifact.source_path,
                content=artifact.content,
            )
        )

    data_objects.append(
        PublicationObject(
            key=manifest_key,
            size=len(manifest_bytes),
            sha256=manifest_sha256,
            media_type="application/json",
            content=manifest_bytes,
        )
    )
    publication = {
        "schema": "ylx.bucket-publication.v2",
        "publication_id": publication_id,
        "sealed": True,
        "published_at": published_at,
        "device": {
            "device_id": device["device_id"],
            "device_label": device["device_label"],
        },
        "source_manifest": {
            "manifest_id": manifest["manifest_id"],
            "schema": manifest["schema"],
            "session_id": session_id,
            "volume_id": manifest["volume_id"],
            "object_key": manifest_key,
            "bytes": len(manifest_bytes),
            "sha256": manifest_sha256,
        },
        "take": manifest["take"],
        "publication_object_key": publication_key,
        "artifacts": published_artifacts,
    }
    try:
        validate_json_schema(
            publication,
            BUCKET_PUBLICATION_SCHEMA,
            "publication.json",
        )
    except ContractValidationError as exc:
        raise PublicationError(str(exc)) from exc
    publication_bytes = _canonical_json(publication)
    return PublicationPlan(
        publication_id=publication_id,
        session_id=session_id,
        publication_key=publication_key,
        publication_bytes=publication_bytes,
        data_objects=tuple(data_objects),
    )


def _prepare_publication_artifacts(
    source_artifacts: tuple[DeviceArtifact, ...],
    manifest: dict[str, Any],
    session_root: Path,
    workspace: Path | None,
) -> tuple[_PreparedArtifact, ...]:
    video = manifest["video"]
    if video["layout"] == "split-eyes" and len(video["segments"]) == 1:
        return tuple(_direct_artifact(item, session_root) for item in source_artifacts)
    if workspace is None:
        raise InvalidSourceSession("视频归一化需要任务专用 workspace")
    normalized_video, execution, normalized_source_ids = _normalize_video(
        source_artifacts,
        manifest,
        session_root,
        workspace,
    )
    direct = tuple(
        _direct_artifact(item, session_root)
        for item in source_artifacts
        if item.role not in {"video.left", "video.right", "video.raw-side-by-side"}
    )
    evidence = _canonical_json(execution)
    evidence_id = hashlib.sha256(evidence).hexdigest()
    transform_log = _PreparedArtifact(
        artifact_id=evidence_id,
        role="publication.transform-log",
        media_type="application/json",
        size=len(evidence),
        content=evidence,
        provenance={
            "kind": "normalized-output",
            "source_artifact_ids": normalized_source_ids,
            "transform": {
                "name": "ylx-transform-log",
                "version": _NORMALIZER_VERSION,
                "parameters": execution,
            },
        },
    )
    return (*normalized_video, *direct, transform_log)


def _direct_artifact(item: DeviceArtifact, session_root: Path) -> _PreparedArtifact:
    return _PreparedArtifact(
        artifact_id=item.artifact_id,
        role=item.role,
        media_type=item.media_type,
        size=item.size,
        source_path=session_root.joinpath(*PurePosixPath(item.relative_path).parts),
        provenance={
            "kind": "device-artifact",
            "source_artifact_ids": [item.artifact_id],
        },
    )


def _normalize_video(
    source_artifacts: tuple[DeviceArtifact, ...],
    manifest: dict[str, Any],
    session_root: Path,
    workspace: Path,
) -> tuple[tuple[_PreparedArtifact, _PreparedArtifact], dict[str, Any], list[str]]:
    root = _normalization_workspace(workspace, session_root)
    by_path = {item.relative_path: item for item in source_artifacts}
    video = manifest["video"]
    if video["layout"] == "raw-side-by-side":
        raw = _source_artifact(by_path, video["artifact"])
        left_sources = (raw,)
        right_sources = (raw,)
        ordered_sources = (raw,)
        operation = "split-side-by-side"
    else:
        segments = video["segments"]
        left_sources = tuple(
            _source_artifact(by_path, segment["artifacts"]["left"])
            for segment in segments
        )
        right_sources = tuple(
            _source_artifact(by_path, segment["artifacts"]["right"])
            for segment in segments
        )
        ordered_sources = tuple(
            item
            for segment in segments
            for item in (
                _source_artifact(by_path, segment["artifacts"]["left"]),
                _source_artifact(by_path, segment["artifacts"]["right"]),
            )
        )
        operation = "ordered-concat"
    normalized_source_ids = _unique_source_ids(ordered_sources)
    command, tool, environment = _run_ffmpeg_normalization(
        root,
        session_root,
        video["layout"],
        left_sources,
        right_sources,
    )
    left_path = root / "left.mp4"
    right_path = root / "right.mp4"
    left_size, left_id = _digest_regular_file(left_path, root)
    right_size, right_id = _digest_regular_file(right_path, root)
    left_provenance = _video_provenance(left_sources, "left", operation)
    right_provenance = _video_provenance(right_sources, "right", operation)
    return (
        (
            _PreparedArtifact(
                artifact_id=left_id,
                role="video.left",
                media_type="video/mp4",
                size=left_size,
                source_path=left_path,
                provenance=left_provenance,
            ),
            _PreparedArtifact(
                artifact_id=right_id,
                role="video.right",
                media_type="video/mp4",
                size=right_size,
                source_path=right_path,
                provenance=right_provenance,
            ),
        ),
        {
            "command": command,
            "tool": tool,
            "environment": environment,
            "exit_status": {"code": 0, "signal": None},
        },
        normalized_source_ids,
    )


def _source_artifact(
    by_path: dict[str, DeviceArtifact], descriptor: dict[str, Any]
) -> DeviceArtifact:
    item = by_path.get(str(descriptor["path"]))
    if item is None or item.artifact_id != descriptor["artifact_id"]:
        raise InvalidSourceSession("video descriptor 未绑定已验证的 source artifact")
    return item


def _unique_source_ids(items: tuple[DeviceArtifact, ...]) -> list[str]:
    values = [item.artifact_id for item in items]
    if len(values) != len(set(values)):
        raise InvalidSourceSession("归一化 source artifact IDs 必须唯一且有序")
    return values


def _video_provenance(
    sources: tuple[DeviceArtifact, ...], eye: str, operation: str
) -> dict[str, Any]:
    return {
        "kind": "normalized-output",
        "source_artifact_ids": _unique_source_ids(sources),
        "transform": {
            "name": _NORMALIZER_NAME,
            "version": _NORMALIZER_VERSION,
            "parameters": {
                "eye": eye,
                "operation": operation,
                "codec": "h264",
                "container": "mp4",
            },
        },
    }


def _normalization_workspace(workspace: Path, session_root: Path) -> Path:
    if workspace.is_symlink():
        raise InvalidSourceSession("归一化 workspace 不能是符号链接")
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve(strict=True)
    if not root.is_dir():
        raise InvalidSourceSession("归一化 workspace 必须是普通目录")
    try:
        root.relative_to(session_root)
    except ValueError:
        pass
    else:
        raise InvalidSourceSession("归一化 workspace 不能位于源会话内")
    return root


def _run_ffmpeg_normalization(
    workspace: Path,
    session_root: Path,
    layout: str,
    left_sources: tuple[DeviceArtifact, ...],
    right_sources: tuple[DeviceArtifact, ...],
) -> tuple[list[str], dict[str, Any], dict[str, str]]:
    executable = shutil.which("ffmpeg")
    if executable is None:
        raise InvalidSourceSession("视频归一化需要安装 ffmpeg")
    environment = {"LC_ALL": "C.UTF-8", "TZ": "UTC"}
    left_temporary = workspace / ".left.part.mp4"
    right_temporary = workspace / ".right.part.mp4"
    for path in (left_temporary, right_temporary):
        if path.exists() or path.is_symlink():
            if path.is_dir() and not path.is_symlink():
                raise InvalidSourceSession(f"归一化临时路径不是文件：{path.name}")
            path.unlink()

    if layout == "raw-side-by-side":
        input_paths = (_artifact_path(session_root, left_sources[0]),)
        filters = (
            "[0:v]split=2[rawleft][rawright];"
            "[rawleft]crop=iw/2:ih:0:0,setsar=1[left];"
            "[rawright]crop=iw/2:ih:iw/2:0,setsar=1[right]"
        )
    else:
        input_paths = tuple(
            _artifact_path(session_root, item)
            for item in (*left_sources, *right_sources)
        )
        left_labels = []
        right_labels = []
        filters_parts = []
        for index in range(len(left_sources)):
            label = f"left{index}"
            filters_parts.append(f"[{index}:v]setpts=PTS-STARTPTS[{label}]")
            left_labels.append(f"[{label}]")
        right_offset = len(left_sources)
        for index in range(len(right_sources)):
            label = f"right{index}"
            filters_parts.append(
                f"[{right_offset + index}:v]setpts=PTS-STARTPTS[{label}]"
            )
            right_labels.append(f"[{label}]")
        filters_parts.extend(
            (
                "".join(left_labels) + f"concat=n={len(left_sources)}:v=1:a=0[left]",
                "".join(right_labels) + f"concat=n={len(right_sources)}:v=1:a=0[right]",
            )
        )
        filters = ";".join(filters_parts)

    command = [executable, "-hide_banner", "-loglevel", "error", "-nostdin"]
    for path in input_paths:
        command.extend(("-i", str(path)))
    command.extend(("-filter_complex", filters))
    command.extend(_ffmpeg_output_arguments("[left]", "left", left_temporary))
    command.extend(_ffmpeg_output_arguments("[right]", "right", right_temporary))
    command.append("-y")
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()[-4096:] or "ffmpeg 未提供错误详情"
        raise InvalidSourceSession(f"视频归一化失败：{detail}")
    _commit_normalized_output(left_temporary, workspace / "left.mp4", workspace)
    _commit_normalized_output(right_temporary, workspace / "right.mp4", workspace)

    version_result = subprocess.run(
        [executable, "-version"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    first_line = version_result.stdout.splitlines()[0] if version_result.stdout else ""
    version_parts = first_line.split()
    version = version_parts[2] if len(version_parts) >= 3 else "unknown"
    executable_path = Path(executable).resolve(strict=True)
    _, executable_sha256 = _digest_regular_file(executable_path, executable_path.parent)
    tool = {
        "name": "ffmpeg",
        "version": version,
        "build": {
            "build_id": f"ffmpeg-{version}",
            "artifact_sha256": executable_sha256,
        },
    }
    return command, tool, environment


def _artifact_path(session_root: Path, item: DeviceArtifact) -> Path:
    return session_root.joinpath(*PurePosixPath(item.relative_path).parts)


def _ffmpeg_output_arguments(stream: str, eye: str, destination: Path) -> list[str]:
    return [
        "-map",
        stream,
        "-an",
        "-c:v",
        "libx264",
        "-preset",
        "medium",
        "-crf",
        "18",
        "-pix_fmt",
        "yuv420p",
        "-threads",
        "1",
        "-map_metadata",
        "-1",
        "-map_chapters",
        "-1",
        "-metadata",
        f"comment=ylx-eye:{eye}",
        "-fflags",
        "+bitexact",
        "-flags:v",
        "+bitexact",
        "-movflags",
        "+faststart",
        str(destination),
    ]


def _commit_normalized_output(temporary: Path, final: Path, root: Path) -> None:
    if temporary.is_symlink() or not temporary.is_file():
        raise InvalidSourceSession(f"ffmpeg 未生成普通输出文件：{temporary.name}")
    with temporary.open("rb") as source:
        os.fsync(source.fileno())
    if final.exists() or final.is_symlink():
        if final.is_symlink() or not final.is_file():
            raise InvalidSourceSession(f"归一化输出路径不安全：{final.name}")
        existing = _digest_regular_file(final, root)
        candidate = _digest_regular_file(temporary, root)
        if existing != candidate:
            temporary.unlink()
            raise InvalidSourceSession("相同输入与配置生成了不同归一化字节")
        temporary.unlink()
    else:
        os.replace(temporary, final)
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(plan: PublicationPlan, store: ImmutableObjectStore) -> PublicationResult:
    uploaded: list[str] = []
    reused: list[str] = []
    for item in plan.data_objects:
        _publish_object(store, item, uploaded, reused)

    marker = PublicationObject(
        key=plan.publication_key,
        size=len(plan.publication_bytes),
        sha256=hashlib.sha256(plan.publication_bytes).hexdigest(),
        media_type="application/json",
        content=plan.publication_bytes,
    )
    _publish_object(store, marker, uploaded, reused)
    return PublicationResult(
        publication_id=plan.publication_id,
        publication_key=plan.publication_key,
        uploaded=tuple(uploaded),
        reused=tuple(reused),
    )


def read_publication(
    store: ImmutableObjectStore, publication_key: str
) -> dict[str, Any]:
    _safe_key(publication_key, allow_evidence=True)
    marker = store.inspect(publication_key)
    if marker is None:
        raise KeyError(publication_key)
    payload = b"".join(store.read_chunks(publication_key))
    if len(payload) != marker.size:
        raise ObjectVerificationError("publication.json 回读大小不一致")
    if (
        marker.sha256 is not None
        and hashlib.sha256(payload).hexdigest() != marker.sha256
    ):
        raise ObjectVerificationError("publication.json 回读摘要不一致")
    try:
        publication = json.loads(payload, object_pairs_hook=_closed_readback_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObjectVerificationError(f"publication.json 无效：{exc}") from exc
    if not isinstance(publication, dict):
        raise ObjectVerificationError("publication.json 顶层必须是对象")
    _validate_schema(
        publication,
        BUCKET_PUBLICATION_SCHEMA,
        ObjectVerificationError,
        "publication.json",
    )
    if (
        publication.get("schema") != "ylx.bucket-publication.v2"
        or publication.get("sealed") is not True
        or publication.get("publication_object_key") != publication_key
    ):
        raise ObjectVerificationError("publication.json 身份或 sealed 状态无效")
    source = publication.get("source_manifest")
    artifacts = publication.get("artifacts")
    if not isinstance(source, dict) or not isinstance(artifacts, list):
        raise ObjectVerificationError("publication.json 对象清单无效")
    authority = publication_key.removesuffix(f"{_RESERVED_SEGMENT}/publication.json")
    if not authority or publication_key == authority:
        raise ObjectVerificationError("publication.json 对象 key 无效")
    _verify_content_key(
        source,
        identity_field="sha256",
        authority=authority,
        label="source_manifest",
    )
    _verify_declared_object(store, source, "application/json")
    source_payload = b"".join(store.read_chunks(str(source["object_key"])))
    try:
        source_manifest = parse_device_session_manifest(
            source_payload,
            expected_session_id=str(source["session_id"]),
        )
    except ContractValidationError as exc:
        raise ObjectVerificationError(f"source_manifest 内容无效：{exc}") from exc
    if publication["take"] != source_manifest.value["take"]:
        raise ObjectVerificationError("publication take 未绑定 source_manifest")
    _verify_source_manifest_binding(publication, source, source_manifest)
    source_by_id: dict[str, list[DeviceArtifact]] = {}
    for source_artifact in source_manifest.artifacts:
        source_by_id.setdefault(source_artifact.artifact_id, []).append(source_artifact)
    referenced_source_ids: set[str] = set()
    object_descriptors: dict[str, tuple[int, str, str]] = {}
    roles: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ObjectVerificationError("publication artifact descriptor 无效")
        role = str(artifact["role"])
        if role in roles:
            raise ObjectVerificationError(f"publication artifact role 重复：{role}")
        roles.add(role)
        if artifact.get("artifact_id") != artifact.get("sha256"):
            raise ObjectVerificationError("artifact_id 必须等于 artifact sha256")
        _verify_content_key(
            artifact,
            identity_field="artifact_id",
            authority=authority,
            label="artifact",
        )
        key = str(artifact["object_key"])
        facts = (
            int(artifact["bytes"]),
            str(artifact["sha256"]),
            str(artifact["media_type"]),
        )
        prior = object_descriptors.setdefault(key, facts)
        if prior != facts:
            raise ObjectVerificationError(
                f"同一 object_key 的内容 descriptor 不一致：{key}"
            )
        provenance = artifact["provenance"]
        source_ids = {str(item) for item in provenance["source_artifact_ids"]}
        if not source_ids.issubset(source_by_id):
            raise ObjectVerificationError(
                f"artifact provenance 引用了 source_manifest 之外的 ID：{role}"
            )
        referenced_source_ids.update(source_ids)
        if provenance["kind"] == "device-artifact":
            source_id = next(iter(source_ids))
            direct_facts = (
                str(artifact["artifact_id"]),
                role,
                str(artifact["media_type"]),
                int(artifact["bytes"]),
            )
            candidates = {
                (item.artifact_id, item.role, item.media_type, item.size)
                for item in source_by_id[source_id]
            }
            if direct_facts not in candidates:
                raise ObjectVerificationError(
                    f"direct artifact provenance 未保留 source descriptor：{role}"
                )
        _verify_declared_object(store, artifact, str(artifact.get("media_type", "")))
        if role == "publication.transform-log":
            evidence_bytes = b"".join(store.read_chunks(key))
            try:
                evidence = json.loads(
                    evidence_bytes,
                    object_pairs_hook=_closed_readback_object,
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                ObjectVerificationError,
            ) as exc:
                raise ObjectVerificationError(
                    f"publication.transform-log JSON 无效：{exc}"
                ) from exc
            if (
                not isinstance(evidence, dict)
                or evidence != provenance["transform"]["parameters"]
            ):
                raise ObjectVerificationError(
                    "publication.transform-log 字节与 marker parameters 不一致"
                )
    if referenced_source_ids != set(source_by_id):
        raise ObjectVerificationError(
            "artifact provenance 未完整覆盖 source_manifest inventory"
        )
    return publication


def _verify_content_key(
    descriptor: dict[str, Any],
    *,
    identity_field: str,
    authority: str,
    label: str,
) -> None:
    key = str(descriptor.get("object_key", ""))
    identity = str(descriptor.get(identity_field, ""))
    if key != f"{authority}f-{identity}":
        raise ObjectVerificationError(f"{label} object_key 未绑定 {identity_field}")


def _verify_source_manifest_binding(
    publication: dict[str, Any],
    descriptor: dict[str, Any],
    manifest,
) -> None:
    value = manifest.value
    expected = {
        "manifest_id": value["manifest_id"],
        "schema": value["schema"],
        "session_id": value["session_id"],
        "volume_id": value["volume_id"],
    }
    if any(descriptor[name] != expected[name] for name in expected):
        raise ObjectVerificationError(
            "source_manifest descriptor 未绑定精确 manifest 身份"
        )
    expected_device = {
        "device_id": value["device"]["device_id"],
        "device_label": value["device"]["device_label"],
    }
    if publication["device"] != expected_device:
        raise ObjectVerificationError("publication device 未绑定 source_manifest")
    suffix = f"{expected_device['device_id']}/{value['session_id']}/"
    authority = str(publication["publication_object_key"]).removesuffix(
        f"{_RESERVED_SEGMENT}/publication.json"
    )
    if not authority.endswith(suffix):
        raise ObjectVerificationError(
            "publication authority 未绑定 source_manifest device/session"
        )


def _closed_readback_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ObjectVerificationError(f"JSON 对象包含重复字段：{key}")
        value[key] = item
    return value


def _publish_object(
    store: ImmutableObjectStore,
    item: PublicationObject,
    uploaded: list[str],
    reused: list[str],
) -> None:
    _verify_source(item)
    existing = store.inspect(item.key)
    if existing is not None:
        _verify_stored(store, item, existing)
        reused.append(item.key)
        return
    try:
        with item.open() as source:
            store.put_if_absent(
                item.key,
                source,
                size=item.size,
                sha256=item.sha256,
                media_type=item.media_type,
            )
    except BaseException as exc:
        observed = store.inspect(item.key)
        if observed is None:
            if isinstance(exc, PublicationError):
                raise
            raise PublicationError(f"对象写入失败：{item.key}：{exc}") from exc
        _verify_stored(store, item, observed)
        reused.append(item.key)
        return
    observed = store.inspect(item.key)
    if observed is None:
        raise ObjectVerificationError(f"对象写入后不存在：{item.key}")
    _verify_stored(store, item, observed)
    uploaded.append(item.key)


def _verify_source(item: PublicationObject) -> None:
    with item.open() as source:
        size, digest = _digest_stream(source)
    if size != item.size or digest != item.sha256:
        raise ObjectConflict(f"发布计划生成后来源发生变化：{item.key}")


def _verify_stored(
    store: ImmutableObjectStore,
    expected: PublicationObject,
    actual: StoredObject,
) -> None:
    if actual.size != expected.size:
        raise ObjectConflict(f"目标对象大小冲突：{expected.key}")
    if actual.media_type is not None and actual.media_type != expected.media_type:
        raise ObjectConflict(f"目标对象媒体类型冲突：{expected.key}")
    size, digest = _digest_chunks(store.read_chunks(expected.key))
    if size != expected.size or digest != expected.sha256:
        raise ObjectConflict(f"目标对象精确字节冲突：{expected.key}")
    if actual.sha256 is not None and actual.sha256 != expected.sha256:
        raise ObjectConflict(f"目标对象摘要元数据冲突：{expected.key}")


def _verify_declared_object(
    store: ImmutableObjectStore, descriptor: dict[str, Any], media_type: str
) -> None:
    try:
        item = PublicationObject(
            key=str(descriptor["object_key"]),
            size=int(descriptor["bytes"]),
            sha256=str(descriptor["sha256"]),
            media_type=media_type,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ObjectVerificationError(f"对象 descriptor 无效：{exc}") from exc
    actual = store.inspect(item.key)
    if actual is None:
        raise ObjectVerificationError(f"publication 引用对象不存在：{item.key}")
    try:
        _verify_stored(store, item, actual)
    except ObjectConflict as exc:
        raise ObjectVerificationError(str(exc)) from exc


def _validate_manifest_identity(
    manifest: dict[str, Any],
    session_root: Path,
    publication_id: str,
    published_at: str,
) -> None:
    required = {
        "schema",
        "manifest_id",
        "sealed",
        "sealed_at",
        "session_id",
        "volume_id",
        "capture_mode",
        "display_name",
        "device",
        "time",
        "take",
        "camera",
        "video",
        "imu",
        "frames",
        "logs",
        "integrity",
    }
    if set(manifest) != required:
        raise InvalidSourceSession("Device Session manifest 顶层字段不闭合")
    if (
        manifest.get("schema") != "ylx.device-session.v1"
        or manifest.get("sealed") is not True
    ):
        raise InvalidSourceSession("仅可发布 sealed ylx.device-session.v1")
    if not _UUID_V7.fullmatch(str(manifest.get("manifest_id", ""))):
        raise InvalidSourceSession("manifest_id 不是 canonical UUIDv7")
    session_id = str(manifest.get("session_id", ""))
    if not _UUID_V7.fullmatch(session_id) or session_root.name != session_id:
        raise InvalidSourceSession("session_id 无效或与目录基名不一致")
    if not _UUID_V4.fullmatch(str(manifest.get("volume_id", ""))):
        raise InvalidSourceSession("volume_id 不是 canonical UUIDv4")
    if not _UUID_V7.fullmatch(publication_id):
        raise ValueError("publication_id 必须是 canonical UUIDv7")
    try:
        timestamp = datetime.fromisoformat(published_at)
    except ValueError as exc:
        raise ValueError("published_at 必须是 RFC 3339 date-time") from exc
    if timestamp.tzinfo is None:
        raise ValueError("published_at 必须包含时区")
    device = manifest.get("device")
    if not isinstance(device, dict):
        raise InvalidSourceSession("device identity 无效")
    if not _UUID_V4.fullmatch(str(device.get("device_id", ""))):
        raise InvalidSourceSession("device_id 不是 canonical UUIDv4")
    if not _DEVICE_LABEL.fullmatch(str(device.get("device_label", ""))):
        raise InvalidSourceSession("device_label 无效")
    take = manifest.get("take")
    if not isinstance(take, dict) or set(take) != {
        "take_id",
        "sequence",
        "continuation_of",
    }:
        raise InvalidSourceSession("take 关系无效")
    if not _UUID_V7.fullmatch(str(take.get("take_id", ""))):
        raise InvalidSourceSession("take_id 不是 canonical UUIDv7")
    sequence = take.get("sequence")
    continuation = take.get("continuation_of")
    if not isinstance(sequence, int) or sequence < 1:
        raise InvalidSourceSession("take.sequence 无效")
    if (sequence == 1) != (continuation is None):
        raise InvalidSourceSession("take continuation 关系无效")
    if continuation is not None and not _UUID_V7.fullmatch(str(continuation)):
        raise InvalidSourceSession("continuation_of 不是 canonical UUIDv7")


def _artifact_descriptors(manifest: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    try:
        video = manifest["video"]
        if video["layout"] != "split-eyes":
            raise InvalidSourceSession("raw-side-by-side 发布需要独立归一化输出")
        segments = video["segments"]
        if not isinstance(segments, list) or len(segments) != 1:
            raise InvalidSourceSession("多分段视频发布需要独立归一化输出")
        pair = segments[0]["artifacts"]
        artifacts = [
            pair["left"],
            pair["right"],
            manifest["imu"]["artifact"],
            manifest["frames"]["artifact"],
            *manifest["logs"],
        ]
    except InvalidSourceSession:
        raise
    except (KeyError, TypeError) as exc:
        raise InvalidSourceSession(
            f"Device Session artifact inventory 无效：{exc}"
        ) from exc
    if not all(isinstance(item, dict) for item in artifacts):
        raise InvalidSourceSession("Device Session artifact descriptor 必须是对象")
    roles = [item.get("role") for item in artifacts]
    if roles.count("video.left") != 1 or roles.count("video.right") != 1:
        raise InvalidSourceSession("发布需要恰好一个左右眼视频对象")
    return tuple(artifacts)


def _validate_artifact_descriptor(descriptor: dict[str, Any]) -> None:
    required = {"artifact_id", "role", "path", "media_type", "bytes", "sha256"}
    if set(descriptor) != required:
        raise InvalidSourceSession("artifact descriptor 字段不闭合")
    artifact_id = str(descriptor["artifact_id"])
    digest = str(descriptor["sha256"])
    if not _SHA256.fullmatch(artifact_id) or artifact_id != digest:
        raise InvalidSourceSession("artifact_id 必须等于 sha256")
    if not isinstance(descriptor["bytes"], int) or descriptor["bytes"] < 0:
        raise InvalidSourceSession("artifact bytes 无效")
    if not _MEDIA_TYPE.fullmatch(str(descriptor["media_type"])):
        raise InvalidSourceSession("artifact media_type 无效")
    _safe_relative_path(str(descriptor["path"]))


def _safe_relative_path(value: str) -> tuple[str, ...]:
    if (
        not value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InvalidSourceSession(f"不安全的 artifact path：{value}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise InvalidSourceSession(f"不安全的 artifact path：{value}")
    if path.parts[0] in {"manifest.json", "recording.json"}:
        raise InvalidSourceSession(f"artifact path 使用保留名称：{value}")
    if any(re.fullmatch(r"[^/]*\.tmp(?:[._-][^/]*)?", part) for part in path.parts):
        raise InvalidSourceSession(f"artifact path 使用临时名称：{value}")
    return path.parts


def _resolve_artifact(root: Path, relative_path: str) -> Path:
    path = root.joinpath(*_safe_relative_path(relative_path))
    current = root
    for part in _safe_relative_path(relative_path):
        current = current / part
        if current.is_symlink():
            raise InvalidSourceSession(
                f"artifact path 不能经过符号链接：{relative_path}"
            )
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise InvalidSourceSession(
            f"artifact path 越出会话目录：{relative_path}"
        ) from exc
    return path


def _validate_inventory(root: Path, expected_paths: set[str]) -> None:
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise InvalidSourceSession(
                f"会话中不允许符号链接：{path.relative_to(root)}"
            )
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative not in {"manifest.json", "recording.json"}:
                actual.add(relative)
        elif not path.is_dir():
            raise InvalidSourceSession(
                f"会话中存在非普通文件：{path.relative_to(root)}"
            )
    if actual != expected_paths:
        raise InvalidSourceSession(
            f"artifact inventory 不一致：missing={sorted(expected_paths - actual)}；"
            f"extra={sorted(actual - expected_paths)}"
        )


def _read_regular_file(path: Path, root: Path) -> bytes:
    if path.is_symlink():
        raise InvalidSourceSession(f"文件不能是符号链接：{path.name}")
    try:
        path.resolve(strict=True).relative_to(root)
        before = path.stat()
    except (OSError, ValueError) as exc:
        raise InvalidSourceSession(f"无法安全读取文件：{path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise InvalidSourceSession(f"对象不是普通文件：{path}")
    content = path.read_bytes()
    after = path.stat()
    if (
        _file_identity(before) != _file_identity(after)
        or len(content) != before.st_size
    ):
        raise InvalidSourceSession(f"读取期间文件发生变化：{path}")
    return content


def _digest_regular_file(path: Path, root: Path) -> tuple[int, str]:
    if path.is_symlink():
        raise InvalidSourceSession(f"文件不能是符号链接：{path}")
    try:
        path.resolve(strict=True).relative_to(root)
        before = path.stat()
    except (OSError, ValueError) as exc:
        raise InvalidSourceSession(f"无法安全读取 artifact：{path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise InvalidSourceSession(f"artifact 不是普通文件：{path}")
    with path.open("rb") as source:
        size, digest = _digest_stream(source)
    after = path.stat()
    if _file_identity(before) != _file_identity(after) or size != before.st_size:
        raise InvalidSourceSession(f"校验期间 artifact 发生变化：{path}")
    return size, digest


def _file_identity(value) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _normalize_prefix(value: str) -> str:
    if not value or not value.endswith("/"):
        raise ValueError("raw_prefix 必须是以 / 结尾的非空相对目录")
    trimmed = value[:-1]
    _safe_key(trimmed, allow_evidence=False)
    return value


def validate_publication_spec(spec: PublicationSpec) -> None:
    if not spec.bucket:
        raise ValueError("bucket 不能为空")
    _normalize_prefix(spec.raw_prefix)
    if spec.endpoint_url is None:
        return
    endpoint = spec.endpoint_url.strip()
    if endpoint != spec.endpoint_url:
        raise ValueError("S3 endpoint 不能包含首尾空白")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("S3 endpoint 必须是完整 http 或 https URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("S3 endpoint 不能包含凭据、查询参数或片段")
    if parsed.path not in {"", "/"}:
        raise ValueError("S3 endpoint 只能是 origin URL")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("S3 endpoint 端口无效") from exc
    if port == 0:
        raise ValueError("S3 endpoint 端口无效")
    if parsed.scheme == "http":
        try:
            addresses = {
                item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)
            }
        except OSError as exc:
            raise ValueError(f"无法解析 S3 endpoint：{exc}") from exc
        if not addresses or not all(_is_loopback_address(item) for item in addresses):
            raise ValueError("非 loopback S3 endpoint 必须使用 HTTPS")


def _is_loopback_address(value: str) -> bool:
    try:
        import ipaddress

        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _safe_key(value: str, *, allow_evidence: bool) -> str:
    if not value or len(value) > 1024 or "\\" in value:
        raise ValueError("对象 key 无效")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ValueError("对象 key 包含控制字符")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise ValueError("对象 key 必须是规范 POSIX 相对路径")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("对象 key 包含不安全 segment")
    evidence_positions = [
        index for index, part in enumerate(path.parts) if part == _RESERVED_SEGMENT
    ]
    if evidence_positions and (
        not allow_evidence
        or len(evidence_positions) != 1
        or evidence_positions[0] != len(path.parts) - 2
        or path.parts[-1] != "publication.json"
    ):
        raise ValueError("对象 key 非法使用 evidence 命名空间")
    return value


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _validate_schema(value: object, name: str, error_type, label: str) -> None:
    try:
        validate_json_schema(value, name, label)
    except ContractValidationError as exc:
        raise error_type(str(exc)) from exc


def _digest_stream(source: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(_READ_SIZE):
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _digest_chunks(chunks: Iterator[bytes]) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    for chunk in chunks:
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


class Boto3ObjectStore:
    def __init__(self, client: Any, bucket: str) -> None:
        if not bucket:
            raise ValueError("S3 bucket 不能为空")
        self._client = client
        self._bucket = bucket

    @classmethod
    def connect(
        cls,
        *,
        bucket: str,
        endpoint_url: str | None = None,
        region_name: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        session_token: str | None = None,
        verify: bool | str = True,
    ) -> Boto3ObjectStore:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise PublicationError("S3 发布需要安装 boto3") from exc
        client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region_name,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            verify=verify,
            config=Config(s3={"addressing_style": "path"}),
        )
        return cls(client, bucket)

    def inspect(self, key: str) -> StoredObject | None:
        _safe_key(key, allow_evidence=True)
        try:
            response = self._client.head_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            code = _s3_error_code(exc)
            if code in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise PublicationError(f"S3 HEAD 失败：{key}：{exc}") from exc
        metadata = response.get("Metadata") or {}
        return StoredObject(
            key=key,
            size=int(response["ContentLength"]),
            sha256=metadata.get("sha256"),
            media_type=response.get("ContentType"),
        )

    def read_chunks(self, key: str, chunk_size: int = _READ_SIZE) -> Iterator[bytes]:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            body = response["Body"]
        except Exception as exc:
            raise PublicationError(f"S3 GET 失败：{key}：{exc}") from exc
        try:
            while chunk := body.read(chunk_size):
                yield chunk
        finally:
            body.close()

    def put_if_absent(
        self,
        key: str,
        source: BinaryIO,
        *,
        size: int,
        sha256: str,
        media_type: str,
    ) -> None:
        _safe_key(key, allow_evidence=True)
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=source,
                ContentLength=size,
                ContentType=media_type,
                Metadata={"sha256": sha256},
                IfNoneMatch="*",
            )
        except Exception as exc:
            if _s3_error_code(exc) in {
                "409",
                "412",
                "ConditionalRequestConflict",
                "PreconditionFailed",
            }:
                raise ObjectConflict(f"S3 对象已存在：{key}") from exc
            raise PublicationError(f"S3 PUT 失败：{key}：{exc}") from exc


def _s3_error_code(exc: BaseException) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error = response.get("Error")
    if isinstance(error, dict) and error.get("Code") is not None:
        return str(error["Code"])
    metadata = response.get("ResponseMetadata")
    if isinstance(metadata, dict) and metadata.get("HTTPStatusCode") is not None:
        return str(metadata["HTTPStatusCode"])
    return None
