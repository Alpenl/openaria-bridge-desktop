from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
import uuid
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ylx_transfer.application import Application
from ylx_transfer.contracts import (
    ContractValidationError,
    parse_device_session_manifest,
)
from ylx_transfer.database import Database, SourceRepository
from ylx_transfer.imports import ImportOperation, ImportRepository
from ylx_transfer.models import SourceKind
from ylx_transfer.publications import (
    Boto3ObjectStore,
    InvalidSourceSession,
    ObjectConflict,
    ObjectVerificationError,
    PublicationRepository,
    PublicationService,
    PublicationSpec,
    StoredObject,
    build_publication_plan,
    publish,
    read_publication,
)
from ylx_transfer.script_publication import (
    ScriptPublicationRequest,
    _fsync_directory,
    _lock,
    _secure_mode,
    _unlock,
    publish_s3_session,
)
from ylx_transfer.sdk import SessionCopyPlan, SessionFile
from ylx_transfer.server import create_server
from ylx_transfer.tasks import TaskRepository, TaskState

PUBLICATION_ID = "01989f70-0000-7d4e-bf50-61728394a5b6"
PUBLISHED_AT = "2026-08-08T11:00:00+08:00"


class MemoryObjectStore:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.puts: list[str] = []

    def inspect(self, key: str):
        stored = self.objects.get(key)
        if stored is None:
            return None
        content, media_type = stored
        return StoredObject(
            key=key,
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            media_type=media_type,
        )

    def read_chunks(self, key: str, chunk_size: int = 1024 * 1024):
        content = self.objects[key][0]
        for offset in range(0, len(content), chunk_size):
            yield content[offset : offset + chunk_size]

    def put_if_absent(
        self,
        key: str,
        source,
        *,
        size: int,
        sha256: str,
        media_type: str,
    ) -> None:
        content = source.read()
        if len(content) != size or hashlib.sha256(content).hexdigest() != sha256:
            raise AssertionError("publisher sent bytes outside its declared descriptor")
        if key in self.objects:
            raise ObjectConflict(f"object already exists: {key}")
        self.objects[key] = (content, media_type)
        self.puts.append(key)


class LostResponseStore(MemoryObjectStore):
    def __init__(self) -> None:
        super().__init__()
        self.lose_next_response = True

    def put_if_absent(self, key, source, **kwargs):
        super().put_if_absent(key, source, **kwargs)
        if self.lose_next_response:
            self.lose_next_response = False
            raise OSError("simulated response loss after commit")


class CommitThenLoseStore:
    def __init__(self, delegate, lost_key: str) -> None:
        self.delegate = delegate
        self.lost_key = lost_key
        self.lost = False

    def inspect(self, key):
        return self.delegate.inspect(key)

    def read_chunks(self, key, chunk_size=1024 * 1024):  # gitleaks:allow - parameter names
        return self.delegate.read_chunks(key, chunk_size)

    def put_if_absent(self, key, source, **kwargs):
        self.delegate.put_if_absent(key, source, **kwargs)
        if key == self.lost_key and not self.lost:
            self.lost = True
            raise ConnectionResetError("simulated response loss after MinIO commit")


class PublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.session = create_device_session(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def script_request(self, checkpoint: Path) -> ScriptPublicationRequest:
        return ScriptPublicationRequest(
            session=self.session,
            bucket="production-bucket",
            raw_prefix="qa/script/",
            endpoint_url="https://objects.example.test",
            region_name="cn-test-1",
            credential_ref="qa-script",
            tls_verify=True,
            checkpoint=checkpoint,
        )

    def manifest_value(self) -> dict[str, object]:
        return json.loads((self.session / "manifest.json").read_bytes())

    def write_manifest(self, value: dict[str, object]) -> bytes:
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        (self.session / "manifest.json").write_bytes(payload)
        return payload

    def test_measured_and_legacy_fps_semantics_are_explicit(self) -> None:
        measured = self.manifest_value()
        parsed = parse_device_session_manifest(self.write_manifest(measured))
        self.assertEqual(parsed.value["camera"]["nominal_fps"], 30)
        self.assertAlmostEqual(parsed.value["camera"]["effective_fps"], 1 / 30)

        legacy = self.manifest_value()
        legacy["time"].pop("duration_clock")
        legacy["camera"].pop("nominal_fps")
        legacy["camera"]["effective_fps"] = 30
        legacy["integrity"].pop("quality_policy")
        parsed_legacy = parse_device_session_manifest(self.write_manifest(legacy))
        self.assertEqual(parsed_legacy.value["camera"]["effective_fps"], 30)

    def test_fps_and_quality_mutations_fail_closed(self) -> None:
        baseline = self.manifest_value()
        mutations = (
            (lambda value: value["camera"].pop("nominal_fps"), "成对出现"),
            (lambda value: value["integrity"].pop("quality_policy"), "成对出现"),
            (lambda value: value["camera"].update(nominal_fps=29), "nominal_fps"),
            (lambda value: value["camera"].update(effective_fps=30), "effective_fps"),
        )
        for mutate, expected in mutations:
            with self.subTest(expected=expected):
                value = deepcopy(baseline)
                mutate(value)
                with self.assertRaisesRegex(ContractValidationError, expected):
                    parse_device_session_manifest(self.write_manifest(value))

        legacy_drop = deepcopy(baseline)
        legacy_drop["time"].pop("duration_clock")
        legacy_drop["camera"].pop("nominal_fps")
        legacy_drop["camera"]["effective_fps"] = 30
        legacy_drop["integrity"].pop("quality_policy")
        legacy_drop["integrity"]["dropped_frames"] = 1
        legacy_drop["integrity"]["drop_events"] = [
            {
                "start_frame": 0,
                "end_frame": 1,
                "at_time_seconds": 0,
                "reason": "write_backpressure",
                "dropped": 1,
            }
        ]
        with self.assertRaisesRegex(ContractValidationError, "legacy.*非零丢帧"):
            parse_device_session_manifest(self.write_manifest(legacy_drop))

        policy_drop = deepcopy(baseline)
        policy_drop["integrity"]["dropped_frames"] = 1
        policy_drop["integrity"]["drop_events"] = [
            {
                "start_frame": 0,
                "end_frame": 1,
                "at_time_seconds": 0,
                "reason": "write_backpressure",
                "dropped": 1,
            }
        ]
        with self.assertRaisesRegex(ContractValidationError, "超过 quality_policy"):
            parse_device_session_manifest(self.write_manifest(policy_drop))

    def test_publication_rejects_unusable_source_before_planning_objects(self) -> None:
        value = self.manifest_value()
        value["camera"]["effective_fps"] = 30
        self.write_manifest(value)

        with self.assertRaisesRegex(InvalidSourceSession, "effective_fps"):
            build_publication_plan(
                self.session,
                publication_id=PUBLICATION_ID,
                published_at=PUBLISHED_AT,
                raw_prefix="raw/",
            )

    def test_script_publish_is_checkpointed_idempotent_and_read_back(self) -> None:
        store = MemoryObjectStore()
        checkpoint = self.root / "state" / "publish.json"
        request = self.script_request(checkpoint)

        first = publish_s3_session(request, store_factory=lambda spec: store)
        second = publish_s3_session(request, store_factory=lambda spec: store)

        self.assertEqual(first.publication_id, second.publication_id)
        self.assertEqual(first.publication_key, second.publication_key)
        self.assertTrue(second.readback)
        self.assertEqual(first.publication_key, store.puts[-1])
        marker = read_publication(store, first.publication_key)
        self.assertEqual(marker["publication_id"], first.publication_id)

    @unittest.skipIf(os.name == "nt", "Windows does not expose POSIX mode bits")
    def test_script_publish_posix_checkpoint_is_owner_only(self) -> None:
        checkpoint = self.root / "state" / "publish.json"

        publish_s3_session(
            self.script_request(checkpoint),
            store_factory=lambda spec: MemoryObjectStore(),
        )

        self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o600)

    def test_script_publish_reuses_prepared_identity_after_interruption(self) -> None:
        checkpoint = self.root / "state" / "publish.json"
        request = self.script_request(checkpoint)

        with self.assertRaises(OSError):
            publish_s3_session(
                request,
                store_factory=lambda spec: (_ for _ in ()).throw(OSError("offline")),
            )
        prepared = json.loads(checkpoint.read_bytes())
        store = MemoryObjectStore()
        result = publish_s3_session(request, store_factory=lambda spec: store)

        self.assertEqual(result.publication_id, prepared["publication_id"])
        self.assertEqual(json.loads(checkpoint.read_bytes())["status"], "completed")

    def test_script_publish_rejects_target_drift(self) -> None:
        checkpoint = self.root / "state" / "publish.json"
        request = self.script_request(checkpoint)
        publish_s3_session(request, store_factory=lambda spec: MemoryObjectStore())

        changed = ScriptPublicationRequest(
            **{**asdict(request), "raw_prefix": "different/"}
        )
        with self.assertRaisesRegex(ValueError, "checkpoint 与当前"):
            publish_s3_session(changed, store_factory=lambda spec: MemoryObjectStore())

    def test_script_publish_rejects_ambiguous_or_corrupt_checkpoint(self) -> None:
        checkpoint = self.root / "state" / "publish.json"
        request = self.script_request(checkpoint)
        with self.assertRaises(OSError):
            publish_s3_session(
                request,
                store_factory=lambda spec: (_ for _ in ()).throw(OSError("offline")),
            )
        original = checkpoint.read_text(encoding="utf-8").rstrip()
        checkpoint.write_text(
            original[:-1] + ',"schema":"duplicate"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "重复字段"):
            publish_s3_session(request, store_factory=lambda spec: MemoryObjectStore())

        checkpoint.write_text(original + "\n", encoding="utf-8")
        state = json.loads(checkpoint.read_bytes())
        state["publication_id"] = "not-a-uuid"
        checkpoint.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "publication_id 无效"):
            publish_s3_session(request, store_factory=lambda spec: MemoryObjectStore())

    def test_script_publish_rejects_non_https_and_checkpoint_on_source(self) -> None:
        request = self.script_request(self.session / "publish.json")
        with self.assertRaisesRegex(ValueError, "checkpoint 必须"):
            publish_s3_session(request, store_factory=lambda spec: MemoryObjectStore())
        insecure = ScriptPublicationRequest(
            **{
                **asdict(request),
                "endpoint_url": "http://127.0.0.1:9000",
                "checkpoint": self.root / "state.json",
            }
        )
        with self.assertRaisesRegex(ValueError, "只接受完整 HTTPS"):
            publish_s3_session(insecure, store_factory=lambda spec: MemoryObjectStore())

    def test_script_publish_rejects_checkpoint_ancestor_symlink_to_source(self) -> None:
        alias = self.root / "source-alias"
        alias.symlink_to(self.session, target_is_directory=True)
        request = self.script_request(alias / "state" / "publish.json")

        with self.assertRaisesRegex(ValueError, "checkpoint 必须"):
            publish_s3_session(request, store_factory=lambda spec: MemoryObjectStore())
        self.assertFalse((self.session / "state").exists())

    def test_script_publish_windows_lock_uses_one_stable_byte(self) -> None:
        lock_path = self.root / "windows.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        calls: list[tuple[int, int, int]] = []
        fake = SimpleNamespace(
            LK_LOCK=1,
            LK_UNLCK=2,
            locking=lambda fd, mode, length: calls.append((fd, mode, length)),
        )
        try:
            with (
                patch("ylx_transfer.script_publication.os.name", "nt"),
                patch.dict("sys.modules", {"msvcrt": fake}),
            ):
                _lock(descriptor)
                _unlock(descriptor)
        finally:
            os.close(descriptor)

        self.assertEqual([item[1:] for item in calls], [(1, 1), (2, 1)])
        self.assertEqual(lock_path.stat().st_size, 1)

    def test_script_publish_windows_skips_unavailable_posix_durability_calls(
        self,
    ) -> None:
        descriptor = os.open(self.root / "windows-state", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with (
                patch("ylx_transfer.script_publication.os.name", "nt"),
                patch(
                    "ylx_transfer.script_publication.os.fchmod", create=True
                ) as fchmod,
                patch("ylx_transfer.script_publication.os.open") as open_directory,
            ):
                _secure_mode(descriptor)
                _fsync_directory(self.root)
        finally:
            os.close(descriptor)

        fchmod.assert_not_called()
        open_directory.assert_not_called()

    def test_data_objects_are_verified_before_publication_marker(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )

        first = publish(plan, store)
        second = publish(plan, store)
        publication = read_publication(store, plan.publication_key)

        self.assertEqual(store.puts[-1], plan.publication_key)
        self.assertEqual(first.uploaded[-1], plan.publication_key)
        self.assertEqual(second.uploaded, ())
        self.assertEqual(set(second.reused), set(store.objects))
        self.assertEqual(publication["schema"], "ylx.bucket-publication.v2")
        self.assertEqual(publication["publication_id"], PUBLICATION_ID)
        self.assertEqual(publication["published_at"], PUBLISHED_AT)
        self.assertEqual(
            publication["source_manifest"]["sha256"],
            hashlib.sha256((self.session / "manifest.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(
            {item["role"] for item in publication["artifacts"]},
            {"video.left", "video.right", "imu.samples", "frames.index"},
        )

    @unittest.skipUnless(
        shutil.which("ffmpeg") and shutil.which("ffprobe"),
        "归一化测试需要 ffmpeg 与 ffprobe",
    )
    def test_raw_side_by_side_is_split_with_hash_bound_transform_evidence(self) -> None:
        session = create_raw_side_by_side_session(self.root / "raw")
        source = json.loads((session / "manifest.json").read_bytes())["video"][
            "artifact"
        ]

        plan = build_publication_plan(
            session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
            workspace=self.root / "normalization",
        )
        publication = json.loads(plan.publication_bytes)
        by_role = {item["role"]: item for item in publication["artifacts"]}

        self.assertEqual(
            set(by_role),
            {
                "video.left",
                "video.right",
                "imu.samples",
                "frames.index",
                "publication.transform-log",
            },
        )
        for role in ("video.left", "video.right"):
            descriptor = by_role[role]
            self.assertEqual(descriptor["media_type"], "video/mp4")
            self.assertEqual(descriptor["artifact_id"], descriptor["sha256"])
            self.assertEqual(
                descriptor["provenance"]["source_artifact_ids"],
                [source["artifact_id"]],
            )
            self.assertEqual(descriptor["provenance"]["kind"], "normalized-output")
            output = next(
                item
                for item in plan.data_objects
                if item.key == descriptor["object_key"]
            )
            probe = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=codec_name,width,height",
                    "-of",
                    "json",
                    str(output.source_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            stream = json.loads(probe.stdout)["streams"][0]
            self.assertEqual(stream["codec_name"], "h264")
            self.assertEqual((stream["width"], stream["height"]), (32, 16))

        transform = by_role["publication.transform-log"]
        self.assertEqual(
            transform["provenance"]["source_artifact_ids"],
            [source["artifact_id"]],
        )
        evidence = next(
            item for item in plan.data_objects if item.key == transform["object_key"]
        )
        self.assertEqual(
            json.loads(evidence.content),
            transform["provenance"]["transform"]["parameters"],
        )

    @unittest.skipUnless(
        shutil.which("ffmpeg") and shutil.which("ffprobe"),
        "归一化测试需要 ffmpeg 与 ffprobe",
    )
    def test_multi_segment_eyes_are_concatenated_in_manifest_order(self) -> None:
        session, expected = create_multi_segment_session(self.root / "segments")

        plan = build_publication_plan(
            session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
            workspace=self.root / "normalization",
        )
        publication = json.loads(plan.publication_bytes)
        by_role = {item["role"]: item for item in publication["artifacts"]}

        for eye in ("left", "right"):
            role = f"video.{eye}"
            descriptor = by_role[role]
            self.assertEqual(
                descriptor["provenance"]["source_artifact_ids"], expected[eye]
            )
            self.assertEqual(
                descriptor["provenance"]["transform"]["parameters"]["operation"],
                "ordered-concat",
            )
            output = next(
                item
                for item in plan.data_objects
                if item.key == descriptor["object_key"]
            )
            probe = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-count_frames",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=codec_name,nb_read_frames",
                    "-of",
                    "json",
                    str(output.source_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            stream = json.loads(probe.stdout)["streams"][0]
            self.assertEqual(stream["codec_name"], "h264")
            self.assertEqual(int(stream["nb_read_frames"]), 4)

        transform = by_role["publication.transform-log"]
        self.assertEqual(
            transform["provenance"]["source_artifact_ids"],
            [
                expected["left"][0],
                expected["right"][0],
                expected["left"][1],
                expected["right"][1],
            ],
        )

    @unittest.skipUnless(shutil.which("ffmpeg"), "归一化重试测试需要 ffmpeg")
    def test_normalized_retry_adopts_exact_outputs_in_the_same_workspace(self) -> None:
        session = create_raw_side_by_side_session(self.root / "raw-retry")
        workspace = self.root / "durable-task-workspace"
        first = build_publication_plan(
            session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
            workspace=workspace,
        )
        first_output_bytes = {
            item.key: item.source_path.read_bytes()
            for item in first.data_objects
            if item.source_path is not None
        }

        retried = build_publication_plan(
            session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
            workspace=workspace,
        )
        store = MemoryObjectStore()
        publish(first, store)
        replay = publish(retried, store)

        self.assertEqual(retried.publication_bytes, first.publication_bytes)
        self.assertEqual(
            {
                item.key: item.source_path.read_bytes()
                for item in retried.data_objects
                if item.source_path is not None
            },
            first_output_bytes,
        )
        self.assertEqual(replay.uploaded, ())
        self.assertEqual(set(replay.reused), set(store.objects))

    def test_lost_put_response_is_reconciled_by_exact_readback(self) -> None:
        store = LostResponseStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )

        result = publish(plan, store)

        self.assertIn(plan.data_objects[0].key, result.reused)
        self.assertEqual(store.puts[-1], plan.publication_key)
        self.assertEqual(
            read_publication(store, plan.publication_key)["publication_id"],
            PUBLICATION_ID,
        )

    def test_existing_different_object_is_never_overwritten_or_published(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        conflicting = plan.data_objects[0]
        store.objects[conflicting.key] = (b"different", conflicting.media_type)

        with self.assertRaises(ObjectConflict):
            publish(plan, store)

        self.assertEqual(store.objects[conflicting.key][0], b"different")
        self.assertNotIn(plan.publication_key, store.objects)

    def test_existing_different_marker_is_never_overwritten(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        store.objects[plan.publication_key] = (
            b'{"different":true}\n',
            "application/json",
        )

        with self.assertRaises(ObjectConflict):
            publish(plan, store)

        self.assertEqual(
            store.objects[plan.publication_key][0], b'{"different":true}\n'
        )

    def test_device_session_nested_schema_violation_is_rejected(self) -> None:
        manifest_path = self.session / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["camera"]["width"] = 0
        manifest_path.write_bytes(
            (
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
        )

        with self.assertRaisesRegex(InvalidSourceSession, "camera"):
            build_publication_plan(
                self.session,
                publication_id=PUBLICATION_ID,
                published_at=PUBLISHED_AT,
                raw_prefix="raw/",
            )

    def test_schema_invalid_publication_marker_is_rejected_on_readback(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        publish(plan, store)
        marker = json.loads(plan.publication_bytes)
        marker["artifacts"][0]["role"] = "invalid"
        invalid = (
            json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        store.objects[plan.publication_key] = (invalid, "application/json")

        with self.assertRaisesRegex(ObjectVerificationError, "artifacts"):
            read_publication(store, plan.publication_key)

    def test_publication_marker_with_duplicate_json_key_is_rejected(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        publish(plan, store)
        schema = b'"schema":"ylx.bucket-publication.v2"'
        ambiguous = plan.publication_bytes.replace(schema, schema + b"," + schema, 1)
        store.objects[plan.publication_key] = (ambiguous, "application/json")

        with self.assertRaisesRegex(ObjectVerificationError, "重复字段.*schema"):
            read_publication(store, plan.publication_key)

    def test_readback_rejects_take_not_bound_to_source_manifest(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        publish(plan, store)
        marker = json.loads(plan.publication_bytes)
        marker["take"]["take_id"] = "01989f69-f001-7c3d-ae4f-5061728394a5"
        replace_marker(store, plan.publication_key, marker)

        with self.assertRaisesRegex(ObjectVerificationError, "take"):
            read_publication(store, plan.publication_key)

    def test_readback_rejects_artifact_id_not_bound_to_content_key(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        publish(plan, store)
        marker = json.loads(plan.publication_bytes)
        marker["artifacts"][0]["artifact_id"] = "f" * 64
        replace_marker(store, plan.publication_key, marker)

        with self.assertRaisesRegex(ObjectVerificationError, "artifact_id"):
            read_publication(store, plan.publication_key)

    def test_readback_rejects_incomplete_source_provenance(self) -> None:
        store = MemoryObjectStore()
        plan = build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
        )
        publish(plan, store)
        marker = json.loads(plan.publication_bytes)
        marker["artifacts"][0]["provenance"]["source_artifact_ids"] = [
            marker["artifacts"][1]["artifact_id"]
        ]
        replace_marker(store, plan.publication_key, marker)

        with self.assertRaisesRegex(ObjectVerificationError, "provenance"):
            read_publication(store, plan.publication_key)

    @unittest.skipUnless(shutil.which("ffmpeg"), "transform log 读回测试需要 ffmpeg")
    def test_readback_rejects_transform_log_not_equal_to_marker_parameters(
        self,
    ) -> None:
        session = create_raw_side_by_side_session(self.root / "raw-readback")
        store = MemoryObjectStore()
        plan = build_publication_plan(
            session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix="raw/",
            workspace=self.root / "normalization-readback",
        )
        publish(plan, store)
        marker = json.loads(plan.publication_bytes)
        transform = next(
            item
            for item in marker["artifacts"]
            if item["role"] == "publication.transform-log"
        )
        changed = b'{"different":true}\n'
        changed_id = hashlib.sha256(changed).hexdigest()
        authority = transform["object_key"].rsplit("f-", 1)[0]
        transform.update(
            artifact_id=changed_id,
            object_key=f"{authority}f-{changed_id}",
            bytes=len(changed),
            sha256=changed_id,
        )
        store.objects[transform["object_key"]] = (changed, "application/json")
        replace_marker(store, plan.publication_key, marker)

        with self.assertRaisesRegex(ObjectVerificationError, "transform-log"):
            read_publication(store, plan.publication_key)

    def test_persistent_task_reuses_identity_after_application_restart(self) -> None:
        database = Database(self.root / "state.db")
        database.initialize()
        sources = SourceRepository(database)
        source = sources.observe_source(
            kind=SourceKind.MEDIA,
            stable_id="6ba7b810-9dad-41d1-80b4-00c04fd430c8",
            display_name="test volume",
            location=str(self.session.parent),
        )
        source_session = sources.observe_sessions(
            source.source_id,
            ((self.session.name, str(self.session), "fixture", None),),
        )[0]
        copy_files = tuple(
            SessionFile(
                path.relative_to(self.session).as_posix(),
                path.stat().st_size,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in sorted(self.session.rglob("*"))
            if path.is_file()
        )
        plan = SessionCopyPlan(
            self.session.name,
            "ylx.device-session.v1",
            tuple(item for item in copy_files if item.relative_path != "manifest.json")
            + tuple(
                item for item in copy_files if item.relative_path == "manifest.json"
            ),
            "manifest.json",
        )
        imports = ImportRepository(database)
        local = imports.register_local(
            ImportOperation(
                task_id="fixture",
                source_session_record_id=source_session.record_id,
                session_id=self.session.name,
                revision="a" * 64,
                staging_path=self.root / "unused",
                final_path=self.session,
                copy_plan=plan,
            )
        )
        store = MemoryObjectStore()
        tasks = TaskRepository(database)
        publications = PublicationRepository(database)
        service = PublicationService(
            tasks=tasks,
            imports=imports,
            publications=publications,
            store_factory=lambda spec: store,
            normalization_root=self.root / "publication-work",
        )
        task, created = service.enqueue(
            PublicationSpec(
                local_session_id=local.local_session_id,
                bucket="test-bucket",
                raw_prefix="raw/",
            )
        )
        persisted = publications.get(task.task_id)

        restarted = PublicationService(
            tasks=TaskRepository(database),
            imports=ImportRepository(database),
            publications=PublicationRepository(database),
            store_factory=lambda spec: store,
            normalization_root=self.root / "publication-work",
        )
        result = restarted.run(task.task_id)
        completed = PublicationRepository(database).get(task.task_id)
        marker = read_publication(store, completed.publication_key)

        self.assertTrue(created)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(completed.publication_id, persisted.publication_id)
        self.assertEqual(completed.published_at, persisted.published_at)
        self.assertEqual(marker["publication_id"], persisted.publication_id)
        self.assertEqual(marker["published_at"], persisted.published_at)

    def test_http_publication_flow_projects_persistent_receipt(self) -> None:
        store = MemoryObjectStore()
        application = Application(
            self.root / "app",
            media_roots=(self.root,),
            sdk_client=UnavailablePublicationSdk(),
            publication_store_factory=lambda spec: store,
            auto_start=False,
        )
        local = register_local_session(application, self.session)
        server = create_server("127.0.0.1", 0, application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            status, queued = post_json(
                url,
                "/api/publications",
                {
                    "local_session_id": local.local_session_id,
                    "bucket": "test-bucket",
                    "raw_prefix": "raw/",
                },
            )
            task_id = queued["task"]["task_id"]
            deadline = time.monotonic() + 5
            while True:
                with urllib.request.urlopen(f"{url}/api/state") as response:
                    state = json.load(response)
                task = next(
                    item for item in state["tasks"] if item["task_id"] == task_id
                )
                if task["state"] in {"succeeded", "failed", "cancelled"}:
                    break
                if time.monotonic() >= deadline:
                    self.fail(f"publication task did not finish: {task}")
                time.sleep(0.01)

            self.assertEqual(status, 202)
            self.assertEqual(task["state"], "succeeded", task)
            self.assertEqual(len(state["publications"]), 1)
            operation = state["publications"][0]
            self.assertEqual(operation["task_id"], task_id)
            self.assertTrue(operation["receipt"]["readback"])
            marker = read_publication(store, operation["publication_key"])
            self.assertEqual(marker["publication_id"], operation["publication_id"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            application.close()

    def test_s3_endpoint_credentials_are_rejected_before_persistence(self) -> None:
        application = Application(
            self.root / "endpoint-app",
            media_roots=(self.root,),
            sdk_client=UnavailablePublicationSdk(),
            publication_store_factory=lambda spec: MemoryObjectStore(),
            auto_start=False,
        )
        local = register_local_session(application, self.session)
        fake_credential_url = "https://access:" + "raw-secret@example.com"
        try:
            with self.assertRaisesRegex(ValueError, "不能包含凭据"):
                application.enqueue_publication(
                    {
                        "local_session_id": local.local_session_id,
                        "bucket": "test-bucket",
                        "raw_prefix": "raw/",
                        "endpoint_url": fake_credential_url,
                    }
                )

            persisted = application.database.path.read_bytes()
            self.assertNotIn(b"access", persisted)
            self.assertNotIn(b"raw-secret", persisted)
            self.assertEqual(application.tasks.list(), ())
        finally:
            application.close()


@unittest.skipUnless(
    os.environ.get("YLX_TEST_MINIO_ENDPOINT")
    and os.environ.get("YLX_TEST_MINIO_ACCESS_KEY_ID")
    and os.environ.get("YLX_TEST_MINIO_SECRET_ACCESS_KEY"),
    "需要 YLX_TEST_MINIO_ENDPOINT 和测试凭据才能运行真实 MinIO 测试",
)
class MinioPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.session = create_device_session(self.root)
        self.bucket = f"ylx-transfer-{uuid.uuid4().hex}"
        self.store = Boto3ObjectStore.connect(
            bucket=self.bucket,
            endpoint_url=os.environ["YLX_TEST_MINIO_ENDPOINT"],
            region_name="us-east-1",
            access_key_id=os.environ["YLX_TEST_MINIO_ACCESS_KEY_ID"],
            secret_access_key=os.environ["YLX_TEST_MINIO_SECRET_ACCESS_KEY"],
            verify=False,
        )
        self.client = self.store._client
        self.client.create_bucket(Bucket=self.bucket)

    def tearDown(self) -> None:
        response = self.client.list_objects_v2(Bucket=self.bucket)
        objects = [{"Key": item["Key"]} for item in response.get("Contents", [])]
        if objects:
            self.client.delete_objects(
                Bucket=self.bucket,
                Delete={"Objects": objects, "Quiet": True},
            )
        self.client.delete_bucket(Bucket=self.bucket)
        self.temporary.cleanup()

    def plan(self, raw_prefix: str):
        return build_publication_plan(
            self.session,
            publication_id=PUBLICATION_ID,
            published_at=PUBLISHED_AT,
            raw_prefix=raw_prefix,
        )

    def test_real_minio_first_publish_replay_and_exact_readback(self) -> None:
        plan = self.plan("real/")

        first = publish(plan, self.store)
        second = publish(plan, self.store)
        marker = read_publication(self.store, plan.publication_key)

        self.assertEqual(first.uploaded[-1], plan.publication_key)
        self.assertEqual(second.uploaded, ())
        self.assertEqual(set(second.reused), set(first.uploaded))
        self.assertEqual(marker["publication_id"], PUBLICATION_ID)
        expected = {
            item.key: (
                item.content
                if item.content is not None
                else item.source_path.read_bytes()
            )
            for item in plan.data_objects
        }
        expected[plan.publication_key] = plan.publication_bytes
        for key, payload in expected.items():
            actual = self.client.get_object(Bucket=self.bucket, Key=key)["Body"]
            try:
                self.assertEqual(actual.read(), payload)
            finally:
                actual.close()

    def test_script_publish_checkpoint_replay_on_real_minio(self) -> None:
        checkpoint = self.root / "state" / "publish.json"
        request = ScriptPublicationRequest(
            session=self.session,
            bucket=self.bucket,
            raw_prefix="script/",
            endpoint_url="https://objects.production.example",
            region_name="us-east-1",
            credential_ref="qa-script",
            tls_verify=True,
            checkpoint=checkpoint,
        )

        first = publish_s3_session(request, store_factory=lambda spec: self.store)
        second = publish_s3_session(request, store_factory=lambda spec: self.store)

        self.assertEqual(first.publication_id, second.publication_id)
        self.assertEqual(first.publication_key, second.publication_key)
        self.assertTrue(second.readback)
        marker = read_publication(self.store, first.publication_key)
        self.assertEqual(marker["publication_id"], first.publication_id)

    def test_real_minio_reconciles_response_loss_after_commit(self) -> None:
        plan = self.plan("lost-response/")
        store = CommitThenLoseStore(self.store, plan.data_objects[0].key)

        result = publish(plan, store)

        self.assertTrue(store.lost)
        self.assertIn(plan.data_objects[0].key, result.reused)
        self.assertEqual(
            read_publication(self.store, plan.publication_key)["publication_id"],
            PUBLICATION_ID,
        )

    def test_real_minio_never_overwrites_conflicting_object(self) -> None:
        plan = self.plan("conflict/")
        conflicting = plan.data_objects[0]
        self.client.put_object(
            Bucket=self.bucket,
            Key=conflicting.key,
            Body=b"different",
            ContentType=conflicting.media_type,
            Metadata={"sha256": hashlib.sha256(b"different").hexdigest()},
        )

        with self.assertRaises(ObjectConflict):
            publish(plan, self.store)

        body = self.client.get_object(Bucket=self.bucket, Key=conflicting.key)["Body"]
        try:
            self.assertEqual(body.read(), b"different")
        finally:
            body.close()
        self.assertIsNone(self.store.inspect(plan.publication_key))


class UnavailablePublicationSdk:
    api_version = "1.0"

    def discover_sessions(self, root, cancellation):
        return ()

    def build_copy_plan(self, path, cancellation):
        raise RuntimeError("not used")

    def validate_session(self, path, cancellation):
        raise RuntimeError("not used")

    def inspect_session(self, path, cancellation):
        raise RuntimeError("not used")


def register_local_session(application: Application, session: Path):
    source = application.sources.observe_source(
        kind=SourceKind.MEDIA,
        stable_id="6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        display_name="test volume",
        location=str(session.parent),
    )
    source_session = application.sources.observe_sessions(
        source.source_id,
        ((session.name, str(session), "fixture", None),),
    )[0]
    files = tuple(
        SessionFile(
            path.relative_to(session).as_posix(),
            path.stat().st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(session.rglob("*"))
        if path.is_file()
    )
    plan = SessionCopyPlan(
        session.name,
        "ylx.device-session.v1",
        tuple(item for item in files if item.relative_path != "manifest.json")
        + tuple(item for item in files if item.relative_path == "manifest.json"),
        "manifest.json",
    )
    return application.imports.register_local(
        ImportOperation(
            task_id="fixture",
            source_session_record_id=source_session.record_id,
            session_id=session.name,
            revision="a" * 64,
            staging_path=session.parent / "unused",
            final_path=session,
            copy_plan=plan,
        )
    )


def post_json(url: str, path: str, payload: dict[str, object]):
    request = urllib.request.Request(
        f"{url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return response.status, json.load(response)


def replace_marker(
    store: MemoryObjectStore, key: str, value: dict[str, object]
) -> None:
    store.objects[key] = (
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        "application/json",
    )


def create_device_session(root: Path) -> Path:
    session_id = "01989f6a-2c00-7a1b-8c2d-3e4f50617283"
    session = root / session_id
    contents = {
        "video/left.mp4": b"left-video-bytes",
        "video/right.mp4": b"right-video-bytes",
        "imu/imu.jsonl": b'{"sample":1}\n',
        "imu/frames.jsonl": b'{"frame":0}\n',
    }
    descriptors = {}
    roles = {
        "video/left.mp4": ("video.left", "video/mp4"),
        "video/right.mp4": ("video.right", "video/mp4"),
        "imu/imu.jsonl": ("imu.samples", "application/x-ndjson"),
        "imu/frames.jsonl": ("frames.index", "application/x-ndjson"),
    }
    for relative_path, content in contents.items():
        path = session.joinpath(*relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        role, media_type = roles[relative_path]
        descriptors[relative_path] = {
            "artifact_id": digest,
            "role": role,
            "path": relative_path,
            "media_type": media_type,
            "bytes": len(content),
            "sha256": digest,
        }
    manifest = {
        "schema": "ylx.device-session.v1",
        "manifest_id": "01989f6a-2c01-7b2c-9d3e-4f5061728394",
        "sealed": True,
        "sealed_at": "2026-08-08T10:24:33+08:00",
        "session_id": session_id,
        "volume_id": "6ba7b810-9dad-41d1-80b4-00c04fd430c8",
        "capture_mode": "production",
        "display_name": "fixture",
        "device": {
            "device_id": "550e8400-e29b-41d4-a716-446655440000",
            "device_label": "YLX-30D5872D",
            "hardware_fingerprint": "sha256:" + "a" * 64,
            "platform": "test",
            "software_version": "1.0.0",
            "commit": "b" * 40,
        },
        "time": {
            "started_at": "2026-08-08T10:24:00+08:00",
            "ended_at": "2026-08-08T10:24:30+08:00",
            "timezone": "Asia/Shanghai",
            "duration_seconds": 30,
            "duration_clock": "host_monotonic",
        },
        "take": {
            "take_id": "01989f69-f000-7c3d-ae4f-5061728394a5",
            "sequence": 1,
            "continuation_of": None,
        },
        "camera": {
            "width": 2,
            "height": 1,
            "eye_width": 1,
            "sensor_fps": 30,
            "frame_decimation": 1,
            "nominal_fps": 30,
            "effective_fps": 1 / 30,
            "coordinate_frame": "opencv_optical",
        },
        "video": {
            "layout": "split-eyes",
            "codec": "h264",
            "container": "mp4",
            "segments": [
                {
                    "index": 0,
                    "start_frame": 0,
                    "end_frame": 1,
                    "start_time_seconds": 0,
                    "end_time_seconds": 30,
                    "artifacts": {
                        "left": descriptors["video/left.mp4"],
                        "right": descriptors["video/right.mp4"],
                    },
                }
            ],
        },
        "imu": {
            "artifact": descriptors["imu/imu.jsonl"],
            "sample_count": 1,
            "units": "raw_int16",
            "coordinate_frame": "opencv_optical",
        },
        "frames": {"artifact": descriptors["imu/frames.jsonl"], "count": 1},
        "logs": [],
        "integrity": {
            "verified_at": "2026-08-08T10:24:32+08:00",
            "dropped_frames": 0,
            "quality_policy": {
                "policy_id": "rdk-x5-lossless-v1",
                "max_contiguous_dropped_frames": 0,
                "max_total_dropped_frames": 0,
                "max_drop_fraction": 0,
                "window_seconds": 1,
                "max_dropped_frames_per_window": 0,
            },
            "drop_events": [],
            "fatal_errors": [],
        },
    }
    (session / "manifest.json").write_bytes(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    return session


def create_raw_side_by_side_session(root: Path) -> Path:
    session = create_device_session(root)
    left = session / "video" / "left.mp4"
    right = session / "video" / "right.mp4"
    left.unlink()
    right.unlink()
    raw = session / "video" / "stereo.mjpeg"
    subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=red:s=32x16:r=5:d=1",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=32x16:r=5:d=1",
            "-filter_complex",
            "[0:v][1:v]hstack=inputs=2",
            "-c:v",
            "mjpeg",
            "-f",
            "mjpeg",
            "-y",
            str(raw),
        ],
        check=True,
    )
    content = raw.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    manifest_path = session / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["capture_mode"] = "calibration"
    manifest["camera"].update(width=64, eye_width=32)
    manifest["video"] = {
        "layout": "raw-side-by-side",
        "codec": "mjpeg",
        "continuous": True,
        "artifact": {
            "artifact_id": digest,
            "role": "video.raw-side-by-side",
            "path": "video/stereo.mjpeg",
            "media_type": "video/x-motion-jpeg",
            "bytes": len(content),
            "sha256": digest,
        },
    }
    manifest_path.write_bytes(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    return session


def create_multi_segment_session(
    root: Path,
) -> tuple[Path, dict[str, list[str]]]:
    session = create_device_session(root)
    manifest_path = session / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for path in (session / "video").glob("*.mp4"):
        path.unlink()
    colors = {
        "left": ("red", "green"),
        "right": ("blue", "yellow"),
    }
    descriptors: dict[str, list[dict[str, object]]] = {"left": [], "right": []}
    for eye, eye_colors in colors.items():
        for index, color in enumerate(eye_colors):
            relative = f"video/{eye}-{index}.mp4"
            path = session / relative
            subprocess.run(
                [
                    "ffmpeg",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "lavfi",
                    "-i",
                    f"color=c={color}:s=32x16:r=2:d=1",
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    "-threads",
                    "1",
                    "-y",
                    str(path),
                ],
                check=True,
            )
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            descriptors[eye].append(
                {
                    "artifact_id": digest,
                    "role": f"video.{eye}",
                    "path": relative,
                    "media_type": "video/mp4",
                    "bytes": len(content),
                    "sha256": digest,
                }
            )
    manifest["camera"].update(
        width=64,
        eye_width=32,
        sensor_fps=2,
        nominal_fps=2,
        effective_fps=2,
    )
    manifest["time"].update(duration_seconds=2)
    manifest["frames"]["count"] = 4
    manifest["video"]["segments"] = [
        {
            "index": index,
            "start_frame": index * 2,
            "end_frame": (index + 1) * 2,
            "start_time_seconds": index,
            "end_time_seconds": index + 1,
            "artifacts": {
                "left": descriptors["left"][index],
                "right": descriptors["right"][index],
            },
        }
        for index in range(2)
    ]
    manifest_path.write_bytes(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    expected = {
        eye: [str(item["artifact_id"]) for item in items]
        for eye, items in descriptors.items()
    }
    return session, expected


if __name__ == "__main__":
    unittest.main()
