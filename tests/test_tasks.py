from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ylx_transfer.database import Database
from ylx_transfer.tasks import (
    StaleTaskUpdate,
    TaskKind,
    TaskRepository,
    TaskState,
)


class TaskRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        database = Database(Path(self.temporary.name) / "state.db")
        database.initialize()
        self.tasks = TaskRepository(database)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_duplicate_command_returns_same_task(self) -> None:
        first, created = self.tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key="import:record-1",
            parameters={"record_id": "record-1"},
        )
        second, duplicate_created = self.tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key="import:record-1",
            parameters={"record_id": "record-1"},
        )
        self.assertTrue(created)
        self.assertFalse(duplicate_created)
        self.assertEqual(first.task_id, second.task_id)

    def test_progress_and_failure_are_persistent(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key="import:record-1",
            parameters={},
        )
        running = self.tasks.claim(task.task_id, task.generation)
        self.tasks.set_progress(running.task_id, running.generation, 4, 10, "bytes")
        failed = self.tasks.fail(
            running.task_id,
            running.generation,
            code="SOURCE_REMOVED",
            message="源介质已移除",
            recovery_action="重新插入介质后重试",
        )
        loaded = self.tasks.get(task.task_id)
        self.assertEqual(loaded.state, TaskState.FAILED)
        self.assertEqual(loaded.progress_current, 4)
        self.assertEqual(loaded.error_code, "SOURCE_REMOVED")
        self.assertEqual(loaded.recovery_action, "重新插入介质后重试")
        self.assertEqual(failed, loaded)

    def test_recovery_invalidates_old_executor(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key="import:record-1",
            parameters={},
        )
        running = self.tasks.claim(task.task_id, task.generation)
        recovered = self.tasks.recover_incomplete()[0]
        self.assertEqual(recovered.state, TaskState.QUEUED)
        self.assertEqual(recovered.generation, running.generation + 1)
        with self.assertRaises(StaleTaskUpdate):
            self.tasks.set_progress(running.task_id, running.generation, 1, 1, "files")

    def test_retry_advances_generation(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.DOWNLOAD,
            idempotency_key="download:1",
            parameters={},
        )
        running = self.tasks.claim(task.task_id, task.generation)
        failed = self.tasks.fail(
            task.task_id,
            running.generation,
            code="NETWORK",
            message="网络中断",
            recovery_action="检查网络后重试",
        )
        retried = self.tasks.retry(failed.task_id)
        self.assertEqual(retried.state, TaskState.QUEUED)
        self.assertEqual(retried.generation, failed.generation + 1)
        self.assertIsNone(retried.error_code)

    def test_cancel_queued_task_is_terminal(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.UPLOAD,
            idempotency_key="upload:1",
            parameters={},
        )
        cancelled = self.tasks.request_cancel(task.task_id)
        self.assertEqual(cancelled.state, TaskState.CANCELLED)
        self.assertIsNotNone(cancelled.finished_at)

    def test_cancel_request_is_honored_during_restart(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.UPLOAD,
            idempotency_key="upload:running",
            parameters={},
        )
        running = self.tasks.claim(task.task_id, task.generation)
        requested = self.tasks.request_cancel(running.task_id)
        self.assertEqual(requested.state, TaskState.CANCEL_REQUESTED)
        recovered = self.tasks.recover_incomplete()[0]
        self.assertEqual(recovered.state, TaskState.CANCELLED)
        self.assertEqual(recovered.generation, requested.generation + 1)

    def test_pause_resume_advances_generation(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.DOWNLOAD,
            idempotency_key="download:paused",
            parameters={},
        )
        running = self.tasks.claim(task.task_id, task.generation)
        requested = self.tasks.request_pause(running.task_id)
        self.assertEqual(requested.state, TaskState.PAUSE_REQUESTED)
        paused = self.tasks.pause(running.task_id, running.generation)
        self.assertEqual(paused.state, TaskState.PAUSED)
        resumed = self.tasks.resume(paused.task_id)
        self.assertEqual(resumed.state, TaskState.QUEUED)
        self.assertEqual(resumed.generation, paused.generation + 1)

    def test_pause_request_is_honored_during_restart(self) -> None:
        task, _ = self.tasks.create(
            kind=TaskKind.DOWNLOAD,
            idempotency_key="download:restart-paused",
            parameters={},
        )
        running = self.tasks.claim(task.task_id, task.generation)
        requested = self.tasks.request_pause(running.task_id)
        recovered = self.tasks.recover_incomplete()[0]
        self.assertEqual(requested.state, TaskState.PAUSE_REQUESTED)
        self.assertEqual(recovered.state, TaskState.PAUSED)


if __name__ == "__main__":
    unittest.main()
