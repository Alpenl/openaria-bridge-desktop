from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ylx_transfer.database import Database
from ylx_transfer.tasks import StaleTaskUpdate, TaskRepository, TaskState
from ylx_transfer.transfers import (
    HttpTransport,
    TransferDirection,
    TransferRepository,
    TransferScheduler,
    TransferService,
    TransferSpec,
)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class ObjectState:
    def __init__(self) -> None:
        self.download = b"download-content-" * 64
        self.download_etag = "download-v1"
        self.reported_download_sha: str | None = None
        self.disconnect_downloads = 0
        self.ranges: list[str] = []
        self.upload = bytearray()
        self.upload_id = "upload-v1"
        self.expected_upload_sha: str | None = None
        self.expected_upload_size: int | None = None
        self.reported_upload_sha: str | None = None
        self.put_calls = 0
        self.fail_put_calls: set[int] = set()
        self.publish_calls = 0
        self.required_token: str | None = None
        self.slow = False
        self.active_downloads = 0
        self.max_active_downloads = 0
        self.lock = threading.Lock()


def handler_for(state: ObjectState):
    class Handler(BaseHTTPRequestHandler):
        def _authorized(self) -> bool:
            if state.required_token is None:
                return True
            return self.headers.get("Authorization") == f"Bearer {state.required_token}"

        def _deny(self) -> None:
            self.send_response(401)
            self.end_headers()

        def do_HEAD(self):
            if not self._authorized():
                self._deny()
                return
            path = urllib.parse.urlsplit(self.path).path
            if path == "/download":
                self.send_response(200)
                self.send_header("Content-Length", str(len(state.download)))
                self.send_header(
                    "X-Content-SHA256",
                    state.reported_download_sha or digest(state.download),
                )
                self.send_header("ETag", f'"{state.download_etag}"')
                self.end_headers()
                return
            if path == "/upload":
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_header("X-Object-Size", str(len(state.upload)))
                self.send_header("Upload-Offset", str(len(state.upload)))
                self.send_header("Upload-Id", state.upload_id)
                if (
                    state.expected_upload_size is not None
                    and len(state.upload) == state.expected_upload_size
                ):
                    self.send_header(
                        "X-Content-SHA256",
                        state.reported_upload_sha or digest(bytes(state.upload)),
                    )
                self.end_headers()
                return
            self.send_error(404)

        def do_GET(self):
            if not self._authorized():
                self._deny()
                return
            if urllib.parse.urlsplit(self.path).path != "/download":
                self.send_error(404)
                return
            range_header = self.headers.get("Range", "bytes=0-")
            start = int(range_header.removeprefix("bytes=").split("-", 1)[0])
            with state.lock:
                state.ranges.append(range_header)
                state.active_downloads += 1
                state.max_active_downloads = max(
                    state.max_active_downloads, state.active_downloads
                )
            content = state.download[start:]
            self.send_response(206)
            self.send_header("Content-Length", str(len(content)))
            self.send_header(
                "Content-Range",
                f"bytes {start}-{len(state.download) - 1}/{len(state.download)}",
            )
            self.send_header("ETag", f'"{state.download_etag}"')
            self.end_headers()
            try:
                if state.disconnect_downloads > 0:
                    state.disconnect_downloads -= 1
                    self.wfile.write(content[:128])
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                step = 64 if state.slow else len(content) or 1
                for index in range(0, len(content), step):
                    self.wfile.write(content[index : index + step])
                    self.wfile.flush()
                    if state.slow:
                        time.sleep(0.005)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with state.lock:
                    state.active_downloads -= 1

        def do_PUT(self):
            if not self._authorized():
                self._deny()
                return
            if urllib.parse.urlsplit(self.path).path != "/upload":
                self.send_error(404)
                return
            value = self.headers["Content-Range"]
            range_value, total = value.removeprefix("bytes ").split("/")
            start, end = (int(item) for item in range_value.split("-"))
            content = self.rfile.read(int(self.headers["Content-Length"]))
            if start != len(state.upload) or end + 1 != start + len(content):
                self.send_error(409)
                return
            state.expected_upload_size = int(total)
            state.expected_upload_sha = self.headers["X-Content-SHA256"]
            state.upload.extend(content)
            state.put_calls += 1
            if state.put_calls in state.fail_put_calls:
                self.send_error(503)
                return
            self.send_response(204)
            self.send_header("Upload-Offset", str(len(state.upload)))
            self.send_header("Upload-Id", state.upload_id)
            self.end_headers()

        def do_POST(self):
            if not self._authorized():
                self._deny()
                return
            if urllib.parse.urlsplit(self.path).path != "/publish":
                self.send_error(404)
                return
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.publish_calls += 1
            receipt = {
                "publication_id": "publication-1",
                "status": "published",
                "sha256": payload["sha256"],
            }
            body = json.dumps(receipt).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return Handler


class StaticCredentials:
    def __init__(self, token: str) -> None:
        self.token = token

    def resolve(self, reference):
        return self.token if reference is not None else None


class TransferServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.database = Database(Path(self.temporary.name) / "state.db")
        self.database.initialize()
        self.tasks = TaskRepository(self.database)
        self.transfers = TransferRepository(self.database)
        self.state = ObjectState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.service = TransferService(
            root=self.root,
            tasks=self.tasks,
            transfers=self.transfers,
            transport=HttpTransport(timeout=2),
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def download_spec(self, name: str = "download.bin") -> TransferSpec:
        return TransferSpec(
            direction=TransferDirection.DOWNLOAD,
            endpoint=f"{self.url}/download",
            local_path=str(self.root / "downloads" / name),
            expected_sha256=digest(self.state.download),
            total_size=len(self.state.download),
            chunk_size=64,
        )

    def upload_spec(
        self, name: str = "upload.bin", publish: bool = True
    ) -> TransferSpec:
        source = self.root / "sessions" / name
        source.parent.mkdir(parents=True, exist_ok=True)
        content = b"upload-content-" * 32
        source.write_bytes(content)
        return TransferSpec(
            direction=TransferDirection.UPLOAD,
            endpoint=f"{self.url}/upload",
            local_path=str(source),
            expected_sha256=digest(content),
            total_size=len(content),
            chunk_size=64,
            publish_url=f"{self.url}/publish" if publish else None,
        )

    def test_download_and_duplicate_command_are_idempotent(self) -> None:
        spec = self.download_spec()
        task, created = self.service.enqueue(spec)
        result = self.service.run(task.task_id)
        duplicate, duplicate_created = self.service.enqueue(spec)
        duplicate_result = self.service.run(duplicate.task_id)
        self.assertTrue(created)
        self.assertFalse(duplicate_created)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(duplicate_result.state, TaskState.SUCCEEDED)
        self.assertEqual(Path(spec.local_path).read_bytes(), self.state.download)

    def test_interrupted_download_resumes_from_persisted_offset(self) -> None:
        self.state.disconnect_downloads = 1
        spec = self.download_spec()
        task, _ = self.service.enqueue(spec)
        failed = self.service.run(task.task_id)
        checkpoint = self.transfers.get(task.task_id)
        self.assertEqual(failed.state, TaskState.FAILED)
        self.assertEqual(failed.error_code, "NETWORK_ERROR")
        self.assertGreater(checkpoint.offset, 0)
        self.assertLess(checkpoint.offset, spec.total_size)
        self.tasks.retry(task.task_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertIn(f"bytes={checkpoint.offset}-", self.state.ranges)

    def test_remote_identity_change_rejects_resume(self) -> None:
        self.state.disconnect_downloads = 1
        task, _ = self.service.enqueue(self.download_spec())
        self.service.run(task.task_id)
        part = self.root / ".transfers" / f"{task.task_id}.part"
        partial_size = part.stat().st_size
        self.state.download_etag = "download-v2"
        self.tasks.retry(task.task_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.error_code, "REMOTE_CHANGED")
        self.assertEqual(part.stat().st_size, partial_size)

    def test_corrupt_download_checkpoint_is_reconciled_with_file(self) -> None:
        self.state.disconnect_downloads = 1
        spec = self.download_spec()
        task, _ = self.service.enqueue(spec)
        self.service.run(task.task_id)
        actual = (self.root / ".transfers" / f"{task.task_id}.part").stat().st_size
        self.tasks.retry(task.task_id)
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE transfer_operations SET offset_bytes = ? WHERE task_id = ?",
                (spec.total_size + 100, task.task_id),
            )
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertIn(f"bytes={actual}-", self.state.ranges)

    def test_download_digest_mismatch_resets_checkpoint(self) -> None:
        spec = self.download_spec()
        wrong = b"x" * len(self.state.download)
        self.state.reported_download_sha = digest(wrong)
        spec = replace(spec, expected_sha256=self.state.reported_download_sha)
        task, _ = self.service.enqueue(spec)
        result = self.service.run(task.task_id)
        self.assertEqual(result.error_code, "CONTENT_MISMATCH")
        self.assertEqual(self.transfers.get(task.task_id).offset, 0)

    def test_upload_digest_readback_and_publication_receipt(self) -> None:
        spec = self.upload_spec()
        task, _ = self.service.enqueue(spec)
        result = self.service.run(task.task_id)
        operation = self.transfers.get(task.task_id)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(bytes(self.state.upload), Path(spec.local_path).read_bytes())
        self.assertEqual(operation.completion["sha256"], spec.expected_sha256)
        self.assertEqual(operation.receipt["status"], "published")
        self.assertEqual(self.state.publish_calls, 1)
        duplicate, created = self.service.enqueue(spec)
        self.service.run(duplicate.task_id)
        self.assertFalse(created)
        self.assertEqual(self.state.publish_calls, 1)

    def test_recovery_rejects_old_generation_completion_evidence(self) -> None:
        task, _ = self.service.enqueue(self.upload_spec())
        running = self.tasks.claim(task.task_id, task.generation)
        leased = self.transfers.lease(task.task_id, running.generation)
        self.assertEqual(leased.checkpoint_generation, running.generation)

        recovered = self.tasks.recover_incomplete()[0]
        self.assertEqual(recovered.generation, running.generation + 1)
        self.assertEqual(
            self.transfers.get(task.task_id).checkpoint_generation,
            recovered.generation,
        )
        with self.assertRaises(StaleTaskUpdate):
            self.transfers.complete(
                task.task_id,
                running.generation,
                {"size": 1, "sha256": "a" * 64},
                {"publication_id": "late-old-worker", "sha256": "a" * 64},
            )
        operation = self.transfers.get(task.task_id)
        self.assertIsNone(operation.completion)
        self.assertIsNone(operation.receipt)

    def test_upload_recovers_remote_progress_after_lost_response(self) -> None:
        self.state.fail_put_calls.add(1)
        spec = self.upload_spec(publish=False)
        task, _ = self.service.enqueue(spec)
        failed = self.service.run(task.task_id)
        remote_offset = len(self.state.upload)
        self.assertEqual(failed.state, TaskState.FAILED)
        self.assertGreater(remote_offset, 0)
        self.tasks.retry(task.task_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(bytes(self.state.upload), Path(spec.local_path).read_bytes())

    def test_upload_identity_change_rejects_stale_resume(self) -> None:
        self.state.fail_put_calls.add(2)
        spec = self.upload_spec(publish=False)
        task, _ = self.service.enqueue(spec)
        failed = self.service.run(task.task_id)
        self.assertEqual(failed.state, TaskState.FAILED)
        self.assertEqual(self.transfers.get(task.task_id).remote_identity, "upload-v1")
        self.state.upload_id = "upload-v2"
        self.tasks.retry(task.task_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.error_code, "REMOTE_CHANGED")

    def test_upload_digest_mismatch_never_publishes(self) -> None:
        self.state.reported_upload_sha = "0" * 64
        spec = self.upload_spec(publish=True)
        task, _ = self.service.enqueue(spec)
        result = self.service.run(task.task_id)
        self.assertEqual(result.error_code, "REMOTE_DIGEST_MISMATCH")
        self.assertEqual(self.state.publish_calls, 0)
        self.assertIsNone(self.transfers.get(task.task_id).receipt)

    def test_pause_and_resume_use_persisted_checkpoint(self) -> None:
        self.state.slow = True
        spec = self.download_spec()
        task, _ = self.service.enqueue(spec)
        result_holder = {}

        def run():
            result_holder["task"] = self.service.run(task.task_id)

        worker = threading.Thread(target=run)
        worker.start()
        deadline = time.monotonic() + 2
        while self.tasks.get(task.task_id).progress_current == 0:
            if time.monotonic() > deadline:
                self.fail("传输没有开始")
            time.sleep(0.005)
        self.tasks.request_pause(task.task_id)
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result_holder["task"].state, TaskState.PAUSED)
        paused_offset = self.transfers.get(task.task_id).offset
        self.assertGreater(paused_offset, 0)
        self.tasks.resume(task.task_id)
        result = self.service.run(task.task_id)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertIn(f"bytes={paused_offset}-", self.state.ranges)

    def test_scheduler_enforces_concurrency_limit(self) -> None:
        class BlockingService:
            def __init__(self):
                self.lock = threading.Lock()
                self.release = threading.Event()
                self.active = 0
                self.maximum = 0

            def run(self, task_id, token):
                with self.lock:
                    self.active += 1
                    self.maximum = max(self.maximum, self.active)
                    if self.active == 2:
                        self.release.set()
                if not self.release.wait(2):
                    raise RuntimeError("两个 worker 未并行启动")
                time.sleep(0.02)
                with self.lock:
                    self.active -= 1
                return task_id

        blocking = BlockingService()
        scheduler = TransferScheduler(blocking, max_workers=2)
        try:
            futures = [scheduler.submit(str(index)) for index in range(3)]
            results = [future.result(timeout=5) for future in futures]
        finally:
            scheduler.close()
        self.assertEqual(results, ["0", "1", "2"])
        self.assertEqual(blocking.maximum, 2)

    def test_credential_secret_is_not_persisted(self) -> None:
        self.state.required_token = "very-secret-token"
        self.service = TransferService(
            root=self.root,
            tasks=self.tasks,
            transfers=self.transfers,
            transport=HttpTransport(timeout=2),
            credentials=StaticCredentials(self.state.required_token),
        )
        original = self.download_spec()
        spec = TransferSpec(
            direction=original.direction,
            endpoint=original.endpoint,
            local_path=original.local_path,
            expected_sha256=original.expected_sha256,
            total_size=original.total_size,
            chunk_size=original.chunk_size,
            credential_ref="production-store",
        )
        task, _ = self.service.enqueue(spec)
        result = self.service.run(task.task_id)
        with self.database.connect() as connection:
            dump = "\n".join(connection.iterdump())
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertNotIn(self.state.required_token, dump)
        self.assertIn("production-store", dump)


if __name__ == "__main__":
    unittest.main()
