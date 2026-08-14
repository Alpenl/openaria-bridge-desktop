from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contracts import validate_device_session_directory
from .publications import (
    EnvironmentS3StoreFactory,
    ImmutableObjectStore,
    PublicationError,
    PublicationSpec,
    build_publication_plan,
    new_publication_id,
    publish,
    read_publication,
    validate_publication_spec,
)

CHECKPOINT_SCHEMA = "ylx.transfer-script-publication-checkpoint.v1"


@dataclass(frozen=True, slots=True)
class ScriptPublicationRequest:
    session: Path
    bucket: str
    raw_prefix: str
    endpoint_url: str
    region_name: str | None
    credential_ref: str
    tls_verify: bool | str
    checkpoint: Path


@dataclass(frozen=True, slots=True)
class ScriptPublicationResult:
    publication_id: str
    publication_key: str
    source_session_id: str
    source_manifest_sha256: str
    publication_sha256: str
    objects: int
    uploaded: tuple[str, ...]
    reused: tuple[str, ...]
    readback: bool
    checkpoint: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


StoreFactory = Callable[[PublicationSpec], ImmutableObjectStore]


def publish_s3_session(
    request: ScriptPublicationRequest,
    *,
    store_factory: StoreFactory | None = None,
) -> ScriptPublicationResult:
    spec = _publication_spec(request)
    session_input = request.session.expanduser().absolute()
    checkpoint = request.checkpoint.expanduser().absolute()
    _validate_paths(session_input, checkpoint)
    session = session_input.resolve(strict=True)
    checkpoint = checkpoint.resolve(strict=False)
    _validate_paths(session, checkpoint)
    source = validate_device_session_directory(session)
    request_digest = _request_digest(request, source.session_id, source.sha256)
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    lock_path = checkpoint.with_name(checkpoint.name + ".lock")
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    locked = False
    try:
        _secure_mode(descriptor)
        _lock(descriptor)
        locked = True
        state = _load_or_prepare_checkpoint(
            checkpoint,
            request_digest=request_digest,
            source_session_id=source.session_id,
            source_manifest_sha256=source.sha256,
        )
        workspace = checkpoint.with_name(checkpoint.name + ".work")
        plan = build_publication_plan(
            session,
            publication_id=str(state["publication_id"]),
            published_at=str(state["published_at"]),
            raw_prefix=request.raw_prefix,
            workspace=workspace,
        )
        if validate_device_session_directory(session).sha256 != source.sha256:
            raise PublicationError("发布计划生成期间源 manifest 发生变化")
        store = (store_factory or EnvironmentS3StoreFactory())(spec)
        result = publish(plan, store)
        marker = read_publication(store, result.publication_key)
        if (
            marker.get("publication_id") != result.publication_id
            or marker.get("source_manifest", {}).get("sha256") != source.sha256
            or marker.get("source_manifest", {}).get("session_id") != source.session_id
        ):
            raise PublicationError("对象存储回读未绑定精确源会话")
        completed = {
            **state,
            "status": "completed",
            "publication_key": result.publication_key,
            "publication_sha256": hashlib.sha256(plan.publication_bytes).hexdigest(),
            "objects": len(plan.data_objects) + 1,
            "uploaded": list(result.uploaded),
            "reused": list(result.reused),
            "readback": True,
            "completed_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        }
        _write_checkpoint(checkpoint, completed)
        return _completed_result(completed, checkpoint)
    finally:
        if locked:
            _unlock(descriptor)
        os.close(descriptor)


def _publication_spec(request: ScriptPublicationRequest) -> PublicationSpec:
    endpoint = urlsplit(request.endpoint_url)
    if endpoint.scheme != "https" or endpoint.hostname is None:
        raise ValueError("publish-s3 只接受完整 HTTPS 对象存储 endpoint")
    if not request.credential_ref.strip():
        raise ValueError("publish-s3 必须使用非空对象存储凭据引用")
    spec = PublicationSpec(
        local_session_id=request.session.name,
        bucket=request.bucket,
        raw_prefix=request.raw_prefix,
        endpoint_url=request.endpoint_url,
        region_name=request.region_name,
        credential_ref=request.credential_ref,
        tls_verify=request.tls_verify,
    )
    validate_publication_spec(spec)
    return spec


def _lock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_EX)


def _unlock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _secure_mode(descriptor: int) -> None:
    if os.name != "nt":
        os.fchmod(descriptor, 0o600)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    directory = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _validate_paths(session: Path, checkpoint: Path) -> None:
    if session.is_symlink() or not session.is_dir():
        raise ValueError("源会话必须是普通目录")
    try:
        checkpoint.relative_to(session)
    except ValueError:
        pass
    else:
        raise ValueError("checkpoint 必须位于只读源会话之外")
    if checkpoint.exists() and (checkpoint.is_symlink() or not checkpoint.is_file()):
        raise ValueError("checkpoint 必须是普通文件")
    if checkpoint.parent.exists() and checkpoint.parent.is_symlink():
        raise ValueError("checkpoint 父目录不能是符号链接")


def _request_digest(
    request: ScriptPublicationRequest,
    source_session_id: str,
    source_manifest_sha256: str,
) -> str:
    value = {
        "bucket": request.bucket,
        "credential_ref": request.credential_ref,
        "endpoint_url": request.endpoint_url,
        "raw_prefix": request.raw_prefix,
        "region_name": request.region_name,
        "source_manifest_sha256": source_manifest_sha256,
        "source_session_id": source_session_id,
        "tls_verify": request.tls_verify,
    }
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _load_or_prepare_checkpoint(
    path: Path,
    *,
    request_digest: str,
    source_session_id: str,
    source_manifest_sha256: str,
) -> dict[str, Any]:
    if path.exists():
        state = _load_checkpoint(path)
        if state.get("request_sha256") != request_digest:
            raise ValueError("checkpoint 与当前源会话或对象存储配置不一致")
        return state
    state = {
        "schema": CHECKPOINT_SCHEMA,
        "status": "prepared",
        "request_sha256": request_digest,
        "source_session_id": source_session_id,
        "source_manifest_sha256": source_manifest_sha256,
        "publication_id": new_publication_id(),
        "published_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "prepared_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
    }
    _write_checkpoint(path, state)
    return state


def _load_checkpoint(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"checkpoint 无法读取：{error}") from error
    if not isinstance(value, dict):
        raise TypeError("checkpoint 顶层必须是对象")
    required = {
        "schema",
        "status",
        "request_sha256",
        "source_session_id",
        "source_manifest_sha256",
        "publication_id",
        "published_at",
        "prepared_at",
    }
    completed = {
        "publication_key",
        "publication_sha256",
        "objects",
        "uploaded",
        "reused",
        "readback",
        "completed_at",
    }
    expected = required | (completed if value.get("status") == "completed" else set())
    if set(value) != expected:
        raise ValueError("checkpoint 字段集合或状态无效")
    if value.get("schema") != CHECKPOINT_SCHEMA or value.get("status") not in {
        "prepared",
        "completed",
    }:
        raise ValueError("checkpoint schema 或状态无效")
    for key in ("request_sha256", "source_manifest_sha256"):
        if not _is_sha256(value.get(key)):
            raise ValueError(f"checkpoint {key} 无效")
    for key in ("source_session_id", "publication_id"):
        if not _is_uuid(value.get(key)):
            raise ValueError(f"checkpoint {key} 无效")
    for key in ("published_at", "prepared_at"):
        if not _is_timestamp(value.get(key)):
            raise ValueError(f"checkpoint {key} 无效")
    if value.get("status") == "completed":
        if value.get("readback") is not True:
            raise ValueError("completed checkpoint 缺少精确读回证据")
        if not _is_sha256(value.get("publication_sha256")):
            raise ValueError("checkpoint publication_sha256 无效")
        if not isinstance(value.get("publication_key"), str) or not value[
            "publication_key"
        ].endswith("/__ylx_evidence__/publication.json"):
            raise ValueError("checkpoint publication_key 无效")
        if not isinstance(value.get("objects"), int) or value["objects"] < 2:
            raise ValueError("checkpoint objects 无效")
        for key in ("uploaded", "reused"):
            items = value.get(key)
            if not isinstance(items, list) or not all(
                isinstance(item, str) and item for item in items
            ):
                raise ValueError(f"checkpoint {key} 无效")
        if not _is_timestamp(value.get("completed_at")):
            raise ValueError("checkpoint completed_at 无效")
    return value


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"checkpoint 包含重复字段：{key}")
        value[key] = item
    return value


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


def _is_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _write_checkpoint(path: Path, value: dict[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        _secure_mode(descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _completed_result(
    state: dict[str, Any], checkpoint: Path
) -> ScriptPublicationResult:
    return ScriptPublicationResult(
        publication_id=str(state["publication_id"]),
        publication_key=str(state["publication_key"]),
        source_session_id=str(state["source_session_id"]),
        source_manifest_sha256=str(state["source_manifest_sha256"]),
        publication_sha256=str(state["publication_sha256"]),
        objects=int(state["objects"]),
        uploaded=tuple(str(item) for item in state["uploaded"]),
        reused=tuple(str(item) for item in state["reused"]),
        readback=state["readback"] is True,
        checkpoint=str(checkpoint),
    )
