from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ylx_transfer.database import Database, SourceRepository
from ylx_transfer.imports import ImportRepository, ImportService, LanImportRepository
from ylx_transfer.models import SourceKind
from ylx_transfer.runtime import CancellationToken
from ylx_transfer.sdk import (
    SdkGateway,
    SessionCopyPlan,
    SessionFile,
    ValidationReport,
)
from ylx_transfer.tasks import TaskRepository, TaskState


def entry(path: str, content: bytes, *, inline: bool = False) -> SessionFile:
    return SessionFile(
        relative_path=path,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        inline_content=content if inline else None,
    )


class FakeImportSdk:
    api_version = "1.0"

    def __init__(self, plan: SessionCopyPlan) -> None:
        self.plan = plan

    def build_copy_plan(self, path, cancellation):
        cancellation.raise_if_cancelled()
        return self.plan

    def validate_session(self, path, cancellation):
        cancellation.raise_if_cancelled()
        errors = []
        for item in self.plan.files:
            candidate = path.joinpath(*item.relative_path.split("/"))
            if not candidate.is_file():
                errors.append(f"缺少 {item.relative_path}")
                continue
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if digest != item.sha256:
                errors.append(f"摘要错误 {item.relative_path}")
        return ValidationReport(valid=not errors, errors=tuple(errors))

    def discover_sessions(self, root, cancellation):
        raise NotImplementedError

    def inspect_session(self, path, cancellation):
        raise NotImplementedError


class SimulatedCrash(BaseException):
    pass


class ImportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source = self.base / "card" / "session-1"
        self.source.mkdir(parents=True)
        self.contents = {
            "session.json": b'{"session_id":"session-1"}',
            "streams/data.bin": b"0123456789abcdef",
            "manifest.json": b'{"sealed":true}',
        }
        for relative_path, content in self.contents.items():
            if relative_path == "manifest.json":
                continue
            path = self.source.joinpath(*relative_path.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.plan = SessionCopyPlan(
            session_id="session-1",
            format_version="v0",
            files=(
                entry("session.json", self.contents["session.json"]),
                entry("streams/data.bin", self.contents["streams/data.bin"]),
                entry("manifest.json", self.contents["manifest.json"], inline=True),
            ),
            commit_last="manifest.json",
        )
        self._build_service()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_service(self, free_space=None) -> None:
        database = Database(self.base / "state.db")
        database.initialize()
        self.sources = SourceRepository(database)
        sources = self.sources.list_sources()
        if sources:
            source = sources[0]
        else:
            source = self.sources.observe_source(
                kind=SourceKind.MEDIA,
                stable_id="volume-1",
                display_name="录制卡",
                location=str(self.source.parent),
            )
        sessions = self.sources.observe_sessions(
            source.source_id,
            (("session-1", str(self.source), "测试会话", None),),
        )
        self.source_record_id = sessions[0].record_id
        self.tasks = TaskRepository(database)
        self.imports = ImportRepository(database)
        self.service = ImportService(
            repository_root=self.base / "repository",
            sources=self.sources,
            tasks=self.tasks,
            imports=self.imports,
            lan_imports=LanImportRepository(database),
            sdk=SdkGateway(FakeImportSdk(self.plan)),
            free_space=free_space,
            chunk_size=4,
        )

    def test_import_copies_validates_and_atomically_publishes(self) -> None:
        task, created = self.service.enqueue(self.source_record_id)
        result = self.service.run(task.task_id)
        self.assertTrue(created)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        local = self.imports.list_local()[0]
        self.assertEqual(local.session_id, "session-1")
        self.assertEqual(
            (local.path / "streams" / "data.bin").read_bytes(),
            self.contents["streams/data.bin"],
        )
        self.assertEqual(
            (local.path / "manifest.json").read_bytes(),
            self.contents["manifest.json"],
        )
        self.assertFalse(
            (self.base / "repository" / ".staging" / task.task_id).exists()
        )

    def test_duplicate_import_returns_existing_terminal_task(self) -> None:
        task, _ = self.service.enqueue(self.source_record_id)
        self.service.run(task.task_id)
        duplicate, created = self.service.enqueue(self.source_record_id)
        result = self.service.run(duplicate.task_id)
        self.assertFalse(created)
        self.assertEqual(duplicate.task_id, task.task_id)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(len(self.imports.list_local()), 1)

    def test_source_removed_after_plan_is_explained(self) -> None:
        task, _ = self.service.enqueue(self.source_record_id)

        def remove_source(stage):
            if stage == "planned":
                (self.source / "streams" / "data.bin").unlink()

        result = self.service.run(task.task_id, stage_hook=remove_source)
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "SOURCE_REMOVED")
        self.assertIn("重新连接", result.recovery_action)

    def test_insufficient_space_fails_before_copy(self) -> None:
        self._build_service(free_space=lambda path: 0)
        task, _ = self.service.enqueue(self.source_record_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "INSUFFICIENT_SPACE")

    def test_changed_source_never_reaches_final_directory(self) -> None:
        (self.source / "streams" / "data.bin").write_bytes(b"changed")
        task, _ = self.service.enqueue(self.source_record_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "CONTENT_MISMATCH")
        self.assertFalse(
            any((self.base / "repository" / "sessions").rglob("manifest.json"))
        )

    def test_existing_different_target_is_not_overwritten(self) -> None:
        task, _ = self.service.enqueue(self.source_record_id)

        def create_conflict(stage):
            if stage != "planned":
                return
            operation = self.imports.get_operation(task.task_id)
            operation.final_path.mkdir(parents=True)
            (operation.final_path / "session.json").write_bytes(b"different")

        result = self.service.run(task.task_id, stage_hook=create_conflict)
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "TARGET_CONFLICT")
        self.assertEqual(
            self.imports.get_operation(task.task_id)
            .final_path.joinpath("session.json")
            .read_bytes(),
            b"different",
        )

    def test_cancel_before_copy_is_terminal_without_final_data(self) -> None:
        task, _ = self.service.enqueue(self.source_record_id)
        token = CancellationToken()

        def cancel(stage):
            if stage == "planned":
                token.cancel()

        result = self.service.run(task.task_id, token, cancel)
        self.assertEqual(result.state, TaskState.CANCELLED)
        self.assertFalse(any((self.base / "repository" / "sessions").iterdir()))

    def test_each_crash_stage_recovers_idempotently(self) -> None:
        for crash_stage in ("planned", "copied", "published"):
            with (
                self.subTest(stage=crash_stage),
                tempfile.TemporaryDirectory() as isolated,
            ):
                original_base = self.base
                original_source = self.source
                self.base = Path(isolated)
                self.source = self.base / "card" / "session-1"
                self.source.mkdir(parents=True)
                for relative_path, content in self.contents.items():
                    if relative_path == "manifest.json":
                        continue
                    path = self.source.joinpath(*relative_path.split("/"))
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                self._build_service()
                task, _ = self.service.enqueue(self.source_record_id)

                def crash(stage, expected_stage=crash_stage):
                    if stage == expected_stage:
                        raise SimulatedCrash(stage)

                with self.assertRaises(SimulatedCrash):
                    self.service.run(task.task_id, stage_hook=crash)
                self.assertEqual(self.tasks.get(task.task_id).state, TaskState.RUNNING)
                self._build_service()
                recovered = self.service.recover()
                self.assertEqual(recovered[0].task_id, task.task_id)
                result = self.service.run(task.task_id)
                self.assertEqual(result.state, TaskState.SUCCEEDED)
                self.assertEqual(len(self.imports.list_local()), 1)
                self.assertFalse(
                    (self.base / "repository" / ".staging" / task.task_id).exists()
                )
                self.base = original_base
                self.source = original_source

    def test_process_kill_after_copy_recovers_without_changing_source(self) -> None:
        large_content = b"0123456789abcdef" * (256 * 1024)
        data_path = self.source / "streams" / "data.bin"
        data_path.write_bytes(large_content)
        self.contents["streams/data.bin"] = large_content
        self.plan = SessionCopyPlan(
            session_id="session-1",
            format_version="test",
            files=tuple(
                entry(relative_path, content)
                for relative_path, content in self.contents.items()
            ),
            commit_last="manifest.json",
        )
        (self.source / "manifest.json").write_bytes(self.contents["manifest.json"])
        self._build_service()
        before = _tree_facts(self.source)
        task, _ = self.service.enqueue(self.source_record_id)
        ready = self.base / "copied.ready"
        worker = Path(__file__).with_name("restart_import_worker.py")
        environment = os.environ.copy()
        source_root = str(Path(__file__).parents[1] / "src")
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, (source_root, environment.get("PYTHONPATH")))
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(worker),
                str(self.base),
                str(self.source.parent.parent),
                str(self.source),
                task.task_id,
                str(ready),
            ],
            env=environment,
        )
        try:
            deadline = time.monotonic() + 10
            while not ready.exists():
                if process.poll() is not None:
                    self.fail(f"import worker exited early with {process.returncode}")
                if time.monotonic() >= deadline:
                    self.fail("import worker did not reach copied checkpoint")
                time.sleep(0.01)
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        database = Database(self.base / "state.db")
        database.initialize()
        resumed_tasks = TaskRepository(database)
        resumed_imports = ImportRepository(database)
        resumed_service = ImportService(
            repository_root=self.base / "repository",
            sources=SourceRepository(database),
            tasks=resumed_tasks,
            imports=resumed_imports,
            lan_imports=LanImportRepository(database),
            sdk=SdkGateway(FakeImportSdk(self.plan)),
        )
        recovered = resumed_service.recover()
        self.assertEqual([item.task_id for item in recovered], [task.task_id])
        result = resumed_service.run(task.task_id)

        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(result.generation, 2)
        self.assertEqual(_tree_facts(self.source), before)
        self.assertEqual(len(resumed_imports.list_local()), 1)
        self.assertFalse(
            (self.base / "repository" / ".staging" / task.task_id).exists()
        )

    def test_unsafe_plan_path_is_rejected(self) -> None:
        evil = entry("../outside.bin", b"bad", inline=True)
        self.plan = SessionCopyPlan("session-1", "v0", (evil,), "../outside.bin")
        self._build_service()
        task, _ = self.service.enqueue(self.source_record_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "UNSAFE_PATH")
        self.assertFalse((self.base / "outside.bin").exists())


def _tree_facts(root: Path):
    return {
        path.relative_to(root).as_posix(): (
            path.stat().st_mode,
            path.stat().st_size,
            path.stat().st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


if __name__ == "__main__":
    unittest.main()
