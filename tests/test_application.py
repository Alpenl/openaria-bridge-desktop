from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ylx_transfer.application import Application
from ylx_transfer.models import SourceKind
from ylx_transfer.sdk import (
    SessionCopyPlan,
    SessionFile,
    ValidationReport,
)
from ylx_transfer.server import create_server
from ylx_transfer.tasks import StaleTaskUpdate, TaskKind, TaskState


class ApplicationSdk:
    api_version = "1.0"

    def __init__(self, plan: SessionCopyPlan) -> None:
        self.plan = plan

    def build_copy_plan(self, path, cancellation):
        return self.plan

    def validate_session(self, path, cancellation):
        errors = []
        for item in self.plan.files:
            candidate = path.joinpath(*item.relative_path.split("/"))
            if not candidate.is_file():
                errors.append(f"缺少 {item.relative_path}")
                continue
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != item.sha256:
                errors.append(f"摘要错误 {item.relative_path}")
        return ValidationReport(valid=not errors, errors=tuple(errors))

    def discover_sessions(self, root, cancellation):
        return ()

    def inspect_session(self, path, cancellation):
        raise NotImplementedError


class ApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source = self.base / "media" / "session-1"
        self.source.mkdir(parents=True)
        contents = {
            "session.json": b"session",
            "data.bin": b"data",
            "manifest.json": b"manifest",
        }
        files = []
        for relative_path, content in contents.items():
            (self.source / relative_path).write_bytes(content)
            files.append(
                SessionFile(
                    relative_path,
                    len(content),
                    hashlib.sha256(content).hexdigest(),
                )
            )
        self.plan = SessionCopyPlan("session-1", "v0", tuple(files), "manifest.json")
        self.app = Application(
            self.base / "app",
            media_roots=(self.base / "media",),
            sdk_client=ApplicationSdk(self.plan),
            auto_start=False,
        )
        source = self.app.sources.observe_source(
            kind=SourceKind.MEDIA,
            stable_id="volume-1",
            display_name="测试介质",
            location=str(self.source.parent),
        )
        self.source_session = self.app.sources.observe_sessions(
            source.source_id,
            (("session-1", str(self.source), "测试会话", None),),
        )[0]
        self.server = create_server("127.0.0.1", 0, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.app.close()
        self.temporary.cleanup()

    def get(self, path):
        with urllib.request.urlopen(f"{self.url}{path}") as response:
            return response.status, json.load(response)

    def post(self, path, payload):
        request = urllib.request.Request(
            f"{self.url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)

    def test_api_import_flow_projects_persistent_facts(self) -> None:
        status, response = self.post(
            "/api/imports",
            {"source_session_record_id": self.source_session.record_id},
        )
        self.assertEqual(status, 202)
        task_id = response["task"]["task_id"]
        deadline = time.monotonic() + 3
        while True:
            _, snapshot = self.get("/api/state")
            task = next(
                item for item in snapshot["tasks"] if item["task_id"] == task_id
            )
            if task["state"] == "succeeded":
                break
            if time.monotonic() > deadline:
                self.fail(f"导入任务未完成：{task}")
            time.sleep(0.01)
        self.assertEqual(len(snapshot["sources"]), 1)
        self.assertEqual(len(snapshot["sessions"]), 1)
        self.assertEqual(len(snapshot["local_sessions"]), 1)
        self.assertTrue(Path(snapshot["local_sessions"][0]["path"]).is_dir())

    def test_task_cancel_command_reads_back_database_state(self) -> None:
        task, _ = self.app.tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key="manual:cancel",
            parameters={},
        )
        status, response = self.post(f"/api/tasks/{task.task_id}/cancel", {})
        self.assertEqual(status, 202)
        self.assertEqual(response["task"]["state"], "cancelled")
        self.assertEqual(self.app.tasks.get(task.task_id).state, TaskState.CANCELLED)

    def test_invalid_transfer_returns_structured_error(self) -> None:
        payload = {
            "direction": "download",
            "endpoint": "http://example.invalid/object",
            "local_path": "/tmp/outside.bin",
            "expected_sha256": "a" * 64,
            "total_size": 1,
        }
        request = urllib.request.Request(
            f"{self.url}/api/transfers",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        body = json.load(caught.exception)
        self.assertEqual(caught.exception.code, 400)
        self.assertIn("error", body)
        self.assertIn("应用仓库目录", body["error"]["message"])

    def test_restart_requeues_running_task_and_rejects_old_generation(self) -> None:
        task, _ = self.app.tasks.create(
            kind=TaskKind.IMPORT,
            idempotency_key="manual:crash",
            parameters={},
        )
        running = self.app.tasks.claim(task.task_id, task.generation)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.app.close()
        self.app = Application(
            self.base / "app",
            media_roots=(self.base / "media",),
            sdk_client=ApplicationSdk(self.plan),
            auto_start=False,
        )
        self.server = create_server("127.0.0.1", 0, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        recovered = self.app.tasks.get(task.task_id)
        self.assertEqual(recovered.state, TaskState.QUEUED)
        self.assertEqual(recovered.generation, running.generation + 1)
        with self.assertRaises(StaleTaskUpdate):
            self.app.tasks.set_progress(task.task_id, running.generation, 1, 1, "items")

    def test_page_contains_operational_views(self) -> None:
        with urllib.request.urlopen(f"{self.url}/") as response:
            page = response.read().decode()
        self.assertIn("来源会话", page)
        self.assertIn("本地会话", page)
        self.assertIn("新建传输", page)


if __name__ == "__main__":
    unittest.main()
