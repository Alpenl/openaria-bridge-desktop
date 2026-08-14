from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

DEVICE_SESSION_SCHEMA = "ylx-device-session-v1.schema.json"
BUCKET_PUBLICATION_SCHEMA = "ylx-bucket-publication-v2.schema.json"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ContractValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DeviceArtifact:
    artifact_id: str
    role: str
    relative_path: str
    media_type: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DeviceSessionManifest:
    payload: bytes
    value: dict[str, Any]
    session_id: str
    sha256: str
    artifacts: tuple[DeviceArtifact, ...]


def validate_json_schema(value: object, name: str, label: str) -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise ContractValidationError("契约校验需要安装 jsonschema") from exc
    resource = files("ylx_transfer").joinpath("schemas", name)
    schema = json.loads(resource.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if not errors:
        return
    error = errors[0]
    path = ".".join(str(part) for part in error.absolute_path) or "$"
    raise ContractValidationError(f"{label} schema 校验失败：{path}：{error.message}")


def parse_device_session_manifest(
    payload: bytes, *, expected_session_id: str | None = None
) -> DeviceSessionManifest:
    if not payload or len(payload) > MAX_MANIFEST_BYTES:
        raise ContractValidationError("Device Session manifest 大小无效")
    try:
        value = json.loads(payload, object_pairs_hook=_closed_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractValidationError(
            f"Device Session manifest 不是有效 JSON：{exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ContractValidationError("Device Session manifest 顶层必须是对象")
    validate_json_schema(value, DEVICE_SESSION_SCHEMA, "Device Session manifest")
    _validate_device_session_semantics(value)
    session_id = str(value["session_id"])
    if expected_session_id is not None and session_id != expected_session_id:
        raise ContractValidationError(
            "Device Session manifest session_id 与请求身份不一致"
        )
    artifacts = _manifest_artifacts(value)
    return DeviceSessionManifest(
        payload=payload,
        value=value,
        session_id=session_id,
        sha256=hashlib.sha256(payload).hexdigest(),
        artifacts=artifacts,
    )


def _validate_device_session_semantics(value: dict[str, Any]) -> None:
    camera = value["camera"]
    timing = value["time"]
    integrity = value["integrity"]
    take = value["take"]
    frames = value["frames"]

    if camera["width"] != camera["eye_width"] * 2:
        raise ContractValidationError("camera width 与 eye_width 不一致")
    if take["continuation_of"] == value["session_id"]:
        raise ContractValidationError("Device Session 不能 continuation_of 自身")

    started = _manifest_datetime(timing["started_at"])
    ended = _manifest_datetime(timing["ended_at"])
    verified = _manifest_datetime(integrity["verified_at"])
    sealed = _manifest_datetime(value["sealed_at"])
    if not started <= ended <= verified <= sealed:
        raise ContractValidationError("Device Session 时间顺序无效")
    if (
        "duration_clock" not in timing
        and abs(timing["duration_seconds"] - (ended - started).total_seconds()) > 1e-3
    ):
        raise ContractValidationError("duration_seconds 与壁钟时间戳不一致")

    drops = integrity["drop_events"]
    dropped_sum = 0
    previous_end: int | None = None
    for drop in drops:
        if (
            drop["end_frame"] <= drop["start_frame"]
            or drop["dropped"] != drop["end_frame"] - drop["start_frame"]
            or (previous_end is not None and drop["start_frame"] <= previous_end)
        ):
            raise ContractValidationError("Device Session drop event 无效")
        dropped_sum += drop["dropped"]
        previous_end = drop["end_frame"]
    if dropped_sum != integrity["dropped_frames"]:
        raise ContractValidationError("dropped_frames 与 drop_events 不一致")

    nominal_fps = camera["sensor_fps"] / camera["frame_decimation"]
    policy = integrity.get("quality_policy")
    measured = "nominal_fps" in camera and policy is not None
    if ("nominal_fps" in camera) != (policy is not None):
        raise ContractValidationError("nominal_fps 与 quality_policy 必须成对出现")
    if not measured:
        if dropped_sum:
            raise ContractValidationError(
                "legacy Device Session 非零丢帧缺少可验证质量策略"
            )
        if abs(camera["effective_fps"] - nominal_fps) > 1e-9:
            raise ContractValidationError("legacy effective_fps 与名义帧率不一致")
        return

    if abs(camera["nominal_fps"] - nominal_fps) > 1e-9:
        raise ContractValidationError(
            "nominal_fps 必须等于 sensor_fps/frame_decimation"
        )
    measured_fps = (
        0.0
        if timing["duration_seconds"] == 0
        else frames["count"] / timing["duration_seconds"]
    )
    if abs(camera["effective_fps"] - measured_fps) > 1e-9:
        raise ContractValidationError(
            "effective_fps 必须等于 frames.count/duration_seconds"
        )

    total = frames["count"] + dropped_sum
    drop_fraction = 0.0 if total == 0 else dropped_sum / total
    max_contiguous = max((drop["dropped"] for drop in drops), default=0)
    max_window = max(
        (
            sum(
                other["dropped"]
                for other in drops
                if drop["at_time_seconds"]
                <= other["at_time_seconds"]
                < drop["at_time_seconds"] + policy["window_seconds"]
            )
            for drop in drops
        ),
        default=0,
    )
    if (
        max_contiguous > policy["max_contiguous_dropped_frames"]
        or dropped_sum > policy["max_total_dropped_frames"]
        or drop_fraction > policy["max_drop_fraction"]
        or max_window > policy["max_dropped_frames_per_window"]
    ):
        raise ContractValidationError("Device Session 丢帧超过 quality_policy")

    video = value["video"]
    if video["layout"] == "split-eyes":
        _validate_split_eye_segments(video, frames["count"], drops, dropped_sum)


def _validate_split_eye_segments(
    video: dict[str, Any],
    frame_count: int,
    drops: list[dict[str, Any]],
    dropped_sum: int,
) -> None:
    segments = video["segments"]
    previous_frame_end: int | None = None
    previous_time_end: float | None = None
    for expected_index, segment in enumerate(segments):
        if (
            segment["index"] != expected_index
            or segment["start_frame"] >= segment["end_frame"]
            or segment["start_time_seconds"] >= segment["end_time_seconds"]
            or (
                previous_frame_end is not None
                and segment["start_frame"] != previous_frame_end
            )
            or (
                previous_time_end is not None
                and abs(segment["start_time_seconds"] - previous_time_end) > 1e-9
            )
        ):
            raise ContractValidationError("Device Session video segment 无效")
        previous_frame_end = segment["end_frame"]
        previous_time_end = float(segment["end_time_seconds"])

    sequence_start = segments[0]["start_frame"]
    sequence_end = segments[-1]["end_frame"]
    if any(
        drop["start_frame"] < sequence_start or drop["end_frame"] > sequence_end
        for drop in drops
    ):
        raise ContractValidationError("Device Session drop event 超出视频帧域")
    if frame_count != sequence_end - sequence_start - dropped_sum:
        raise ContractValidationError("frames.count 与视频帧域不一致")


def _manifest_datetime(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ContractValidationError("Device Session 时间戳无效") from exc


def validate_device_session_directory(
    root: Path, *, expected_manifest: bytes | None = None
) -> DeviceSessionManifest:
    if root.is_symlink() or not root.is_dir():
        raise ContractValidationError("Device Session 必须是普通目录")
    resolved = root.resolve(strict=True)
    manifest_path = resolved / "manifest.json"
    manifest_bytes = _read_regular(manifest_path, resolved)
    if expected_manifest is not None and manifest_bytes != expected_manifest:
        raise ContractValidationError("本地 manifest 与已绑定的远端原始字节不一致")
    manifest = parse_device_session_manifest(
        manifest_bytes, expected_session_id=resolved.name
    )
    expected_paths = {item.relative_path for item in manifest.artifacts}
    actual_paths: set[str] = set()
    for path in resolved.rglob("*"):
        relative = path.relative_to(resolved).as_posix()
        if path.is_symlink():
            raise ContractValidationError(f"会话中不允许符号链接：{relative}")
        mode = path.stat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ContractValidationError(f"会话中存在非普通文件：{relative}")
        if relative not in {"manifest.json", "recording.json"}:
            actual_paths.add(relative)
    if actual_paths != expected_paths:
        raise ContractValidationError(
            "artifact inventory 不一致："
            f"missing={sorted(expected_paths - actual_paths)}；"
            f"extra={sorted(actual_paths - expected_paths)}"
        )
    for item in manifest.artifacts:
        path = resolved.joinpath(*safe_relative_parts(item.relative_path))
        size, digest = _digest_regular(path, resolved)
        if size != item.size or digest != item.sha256:
            raise ContractValidationError(
                f"artifact 大小或摘要不匹配：{item.relative_path}"
            )
    return manifest


def safe_relative_parts(value: str) -> tuple[str, ...]:
    if (
        not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ContractValidationError(f"不安全的 artifact path：{value}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ContractValidationError(f"不安全的 artifact path：{value}")
    if path.parts[0] in {"manifest.json", "recording.json"}:
        raise ContractValidationError(f"artifact path 使用保留名称：{value}")
    if any(re.fullmatch(r"[^/]*\.tmp(?:[._-][^/]*)?", part) for part in path.parts):
        raise ContractValidationError(f"artifact path 使用临时名称：{value}")
    return path.parts


def _manifest_artifacts(value: dict[str, Any]) -> tuple[DeviceArtifact, ...]:
    video = value["video"]
    descriptors: list[dict[str, Any]] = []
    if video["layout"] == "split-eyes":
        previous_frame = 0
        previous_time = 0.0
        for expected_index, segment in enumerate(video["segments"]):
            if segment["index"] != expected_index:
                raise ContractValidationError("video segment index 必须连续且有序")
            if (
                segment["start_frame"] != previous_frame
                or segment["end_frame"] <= segment["start_frame"]
                or segment["start_time_seconds"] < previous_time
                or segment["end_time_seconds"] <= segment["start_time_seconds"]
            ):
                raise ContractValidationError("video segment frame/time 边界无效")
            previous_frame = segment["end_frame"]
            previous_time = float(segment["end_time_seconds"])
            descriptors.extend(
                (segment["artifacts"]["left"], segment["artifacts"]["right"])
            )
    elif video["layout"] == "raw-side-by-side":
        descriptors.append(video["artifact"])
    else:
        raise ContractValidationError("不支持的 Device Session video.layout")
    descriptors.extend((value["imu"]["artifact"], value["frames"]["artifact"]))
    descriptors.extend(value["logs"])

    by_path: dict[str, DeviceArtifact] = {}
    ordered: list[DeviceArtifact] = []
    for descriptor in descriptors:
        artifact = DeviceArtifact(
            artifact_id=str(descriptor["artifact_id"]),
            role=str(descriptor["role"]),
            relative_path=str(descriptor["path"]),
            media_type=str(descriptor["media_type"]),
            size=int(descriptor["bytes"]),
            sha256=str(descriptor["sha256"]),
        )
        safe_relative_parts(artifact.relative_path)
        if (
            not _SHA256.fullmatch(artifact.artifact_id)
            or artifact.artifact_id != artifact.sha256
        ):
            raise ContractValidationError("artifact_id 必须等于 sha256")
        existing = by_path.get(artifact.relative_path)
        if existing is not None:
            if (
                existing.artifact_id,
                existing.media_type,
                existing.size,
                existing.sha256,
            ) != (
                artifact.artifact_id,
                artifact.media_type,
                artifact.size,
                artifact.sha256,
            ):
                raise ContractValidationError(
                    f"重复 artifact path descriptor 冲突：{artifact.relative_path}"
                )
            continue
        by_path[artifact.relative_path] = artifact
        ordered.append(artifact)
    return tuple(ordered)


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractValidationError(f"JSON 对象包含重复字段：{key}")
        value[key] = item
    return value


def _read_regular(path: Path, root: Path) -> bytes:
    if path.is_symlink():
        raise ContractValidationError(f"文件不能是符号链接：{path.name}")
    try:
        path.resolve(strict=True).relative_to(root)
        before = path.stat()
    except (OSError, ValueError) as exc:
        raise ContractValidationError(f"无法安全读取文件：{path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ContractValidationError(f"对象不是普通文件：{path}")
    content = path.read_bytes()
    after = path.stat()
    if (
        _file_identity(before) != _file_identity(after)
        or len(content) != before.st_size
    ):
        raise ContractValidationError(f"读取期间文件发生变化：{path}")
    return content


def _digest_regular(path: Path, root: Path) -> tuple[int, str]:
    if path.is_symlink():
        raise ContractValidationError(f"artifact 不能是符号链接：{path}")
    try:
        path.resolve(strict=True).relative_to(root)
        before = path.stat()
    except (OSError, ValueError) as exc:
        raise ContractValidationError(f"无法安全读取 artifact：{path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ContractValidationError(f"artifact 不是普通文件：{path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    after = path.stat()
    if _file_identity(before) != _file_identity(after) or size != before.st_size:
        raise ContractValidationError(f"校验期间 artifact 发生变化：{path}")
    return size, digest.hexdigest()


def _file_identity(value) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
