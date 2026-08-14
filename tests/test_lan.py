from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from tests.test_publications import (
    UnavailablePublicationSdk,
    create_device_session,
)
from ylx_transfer.application import Application
from ylx_transfer.lan import (
    LanConnectionSpec,
    LanDeviceClient,
    LanFailure,
    TlsPin,
)
from ylx_transfer.publications import build_publication_plan
from ylx_transfer.runtime import CancellationToken
from ylx_transfer.sdk import SessionSummary
from ylx_transfer.server import create_server
from ylx_transfer.tasks import StaleTaskUpdate, TaskState

DEVICE_ID = "550e8400-e29b-41d4-a716-446655440000"
SESSION_ONE = "01989f6a-2c00-7a1b-8c2d-3e4f50617283"
SESSION_TWO = "01989f6a-2c10-7a1b-8c2d-3e4f50617283"
ARTIFACT = b"0123456789"
ARTIFACT_ID = hashlib.sha256(ARTIFACT).hexdigest()


class StaticCredentialProvider:
    def resolve(self, reference):
        if reference != "device-a":
            raise AssertionError(reference)
        return "reader-token"


class DeviceSessionMediaSdk(UnavailablePublicationSdk):
    def __init__(self, session: Path) -> None:
        self.session = session

    def discover_sessions(self, root, cancellation):
        cancellation.raise_if_cancelled()
        return (SessionSummary(self.session.name, self.session),)

    def build_copy_plan(self, path, cancellation):
        raise AssertionError("Device Session v1 media must use the frozen contract")

    def validate_session(self, path, cancellation):
        raise AssertionError("Device Session v1 media must use the frozen contract")


class DeviceV3Handler(BaseHTTPRequestHandler):
    manifest_bytes = b'{"schema":"ylx.device-session.v1"}\n'
    requests: ClassVar[list[tuple[str, str, str | None, str | None]]] = []
    error_status: int | None = None
    artifact_payloads: ClassVar[dict[str, tuple[bytes, str]]] = {
        ARTIFACT_ID: (ARTIFACT, "video/mp4")
    }
    interrupt_artifact: str | None = None
    interrupted = False
    ranges: ClassVar[list[str | None]] = []
    stream_chunk_size: int | None = None
    stream_delay = 0.0

    def do_HEAD(self):
        self._handle(head=True)

    def do_GET(self):
        self._handle(head=False)

    def _handle(self, *, head: bool) -> None:
        type(self).requests.append(
            (
                self.command,
                self.path,
                self.headers.get("Authorization"),
                self.headers.get("If-Range"),
            )
        )
        type(self).ranges.append(self.headers.get("Range"))
        if self.headers.get("Authorization") != "Bearer reader-token":
            self._problem(401, "unauthorized", head=head)
            return
        if type(self).error_status is not None:
            status = type(self).error_status
            codes = {
                401: "unauthorized",
                403: "forbidden",
                409: "session_not_verified",
                423: "capture_busy",
                416: "range_not_satisfiable",
            }
            self._problem(status, codes[status], head=head)
            return

        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/api/v3/device":
            self._json(
                {
                    "schema": "ylx.device.v3",
                    "device": {
                        "device_id": DEVICE_ID,
                        "device_label": "YLX-30D5872D",
                    },
                    "api_version": "3.0",
                    "capabilities": {"range_download": True},
                }
            )
            return
        if parsed.path == "/api/v3/sessions":
            cursor = urllib.parse.parse_qs(parsed.query).get("cursor", [None])[0]
            if cursor is None:
                items = [
                    self._summary(
                        SESSION_ONE,
                        "usable",
                        hashlib.sha256(type(self).manifest_bytes).hexdigest(),
                        sum(
                            len(payload)
                            for payload, _ in type(self).artifact_payloads.values()
                        ),
                    ),
                    self._summary(
                        "01989f6a-2c20-7a1b-8c2d-3e4f50617283",
                        "unusable",
                        "b" * 64,
                        len(ARTIFACT),
                    ),
                ]
                next_cursor = "page two"
            elif cursor == "page two":
                items = [self._summary(SESSION_TWO, "usable", "c" * 64, len(ARTIFACT))]
                next_cursor = None
            else:
                self._problem(400, "bad_cursor", head=head)
                return
            self._json(
                {
                    "schema": "ylx.session-list.v2",
                    "items": items,
                    "diagnostics": [],
                    "next_cursor": next_cursor,
                }
            )
            return
        if parsed.path == f"/api/v3/sessions/{SESSION_ONE}":
            digest = hashlib.sha256(type(self).manifest_bytes).hexdigest()
            self._bytes(
                type(self).manifest_bytes,
                "application/json",
                headers={"ETag": f'"{digest}"', "YLX-Manifest-SHA256": digest},
                head=head,
            )
            return
        prefix = f"/api/v3/sessions/{SESSION_ONE}/artifacts/"
        if parsed.path.startswith(prefix):
            artifact_id = parsed.path.removeprefix(prefix)
            stored = type(self).artifact_payloads.get(artifact_id)
            if stored is None:
                self._problem(404, "not_found", head=head)
                return
            artifact_payload, media_type = stored
            range_header = self.headers.get("Range")
            headers = {
                "Accept-Ranges": "bytes",
                "ETag": f'"{artifact_id}"',
            }
            if head:
                self._bytes(artifact_payload, media_type, headers=headers, head=True)
            else:
                offset = 0
                status = 200
                if range_header is not None:
                    offset = int(range_header.removeprefix("bytes=").removesuffix("-"))
                    status = 206
                    headers["Content-Range"] = (
                        f"bytes {offset}-{len(artifact_payload) - 1}/{len(artifact_payload)}"
                    )
                selected = artifact_payload[offset:]
                if (
                    artifact_id == type(self).interrupt_artifact
                    and not type(self).interrupted
                ):
                    type(self).interrupted = True
                    self.send_response(status)
                    self.send_header("Content-Type", media_type)
                    self.send_header("Content-Length", str(len(selected)))
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(selected[:4])
                    self.wfile.flush()
                    self.close_connection = True
                    return
                if type(self).stream_chunk_size is None:
                    self._bytes(
                        selected,
                        media_type,
                        status=status,
                        headers=headers,
                    )
                else:
                    self.send_response(status)
                    self.send_header("Content-Type", media_type)
                    self.send_header("Content-Length", str(len(selected)))
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.end_headers()
                    size = type(self).stream_chunk_size
                    for start in range(0, len(selected), size):
                        self.wfile.write(selected[start : start + size])
                        self.wfile.flush()
                        time.sleep(type(self).stream_delay)
            return
        self._problem(404, "not_found", head=head)

    @staticmethod
    def _summary(session_id: str, verdict: str, manifest_sha256: str, total_bytes: int):
        diagnostics = [] if verdict == "usable" else ["fixture rejected"]
        return {
            "session_id": session_id,
            "producer_outcome": "sealed",
            "take_id": "01989f69-f000-7c3d-ae4f-5061728394a5",
            "take_sequence": 1,
            "continuation_of": None,
            "display_name": session_id,
            "device": {
                "device_id": DEVICE_ID,
                "device_label": "YLX-30D5872D",
            },
            "started_at": "2026-08-08T10:24:00+08:00",
            "ended_at": "2026-08-08T10:24:30+08:00",
            "duration_seconds": 30,
            "total_bytes": total_bytes,
            "verification": {
                "actor": "gateway",
                "validator": {
                    "name": "fixture",
                    "version": "1",
                    "build_sha256": "d" * 64,
                },
                "manifest_sha256": manifest_sha256,
                "verified_at": "2026-08-08T10:25:00+08:00",
                "verdict": verdict,
                "diagnostics": diagnostics,
            },
        }

    def _json(self, value) -> None:
        self._bytes(
            json.dumps(value, separators=(",", ":")).encode(),
            "application/json",
        )

    def _problem(self, status: int, code: str, *, head: bool) -> None:
        headers = {}
        if status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        if status == 409:
            headers["YLX-Error-Code"] = "session_not_verified"
        if status == 423:
            headers.update(
                {
                    "YLX-Error-Code": "capture_busy",
                    "YLX-Wait-State": "idle",
                    "Retry-After": "1",
                }
            )
        if status == 416:
            headers["Content-Range"] = f"bytes */{len(ARTIFACT)}"
        payload = json.dumps({"error": {"code": code}}).encode()
        self._bytes(
            payload,
            "application/problem+json",
            status=status,
            headers=headers,
            head=head,
        )

    def _bytes(
        self,
        payload: bytes,
        content_type: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        head: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if not head:
            self.wfile.write(payload)

    def log_message(self, format, *args):
        return


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        return


class LanDeviceClientTests(unittest.TestCase):
    def setUp(self) -> None:
        DeviceV3Handler.requests = []
        DeviceV3Handler.error_status = None
        DeviceV3Handler.manifest_bytes = b'{"schema":"ylx.device-session.v1"}\n'
        DeviceV3Handler.artifact_payloads = {ARTIFACT_ID: (ARTIFACT, "video/mp4")}
        DeviceV3Handler.interrupt_artifact = None
        DeviceV3Handler.interrupted = False
        DeviceV3Handler.ranges = []
        DeviceV3Handler.stream_chunk_size = None
        DeviceV3Handler.stream_delay = 0.0
        self.server = QuietThreadingHTTPServer(("127.0.0.1", 0), DeviceV3Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.client = LanDeviceClient(
            LanConnectionSpec(endpoint=endpoint, credential_ref="device-a"),
            credentials=StaticCredentialProvider(),
            timeout=2,
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_v3_bearer_pagination_and_usable_filter(self) -> None:
        snapshot = self.client.probe(CancellationToken())

        self.assertEqual(snapshot.identity.device_id, DEVICE_ID)
        self.assertEqual(snapshot.identity.api_version, "3.0")
        self.assertEqual(
            [item.session_id for item in snapshot.sessions],
            [SESSION_ONE, SESSION_TWO],
        )
        self.assertEqual(
            snapshot.sessions[0].manifest_sha256,
            hashlib.sha256(DeviceV3Handler.manifest_bytes).hexdigest(),
        )
        self.assertTrue(
            any("cursor=page+two" in path for _, path, _, _ in DeviceV3Handler.requests)
        )
        self.assertTrue(
            all(
                auth == "Bearer reader-token"
                for _, _, auth, _ in DeviceV3Handler.requests
            )
        )

    def test_manifest_and_range_preserve_exact_remote_identity(self) -> None:
        manifest = self.client.read_manifest(SESSION_ONE)
        artifact = self.client.inspect_artifact(
            SESSION_ONE,
            artifact_id=ARTIFACT_ID,
            expected_size=len(ARTIFACT),
            expected_media_type="video/mp4",
        )
        chunks = tuple(
            self.client.download_artifact(
                SESSION_ONE,
                artifact_id=ARTIFACT_ID,
                offset=4,
                expected_size=len(ARTIFACT),
                expected_media_type="video/mp4",
                expected_identity=artifact.identity,
                chunk_size=2,
            )
        )

        self.assertEqual(manifest.payload, DeviceV3Handler.manifest_bytes)
        self.assertEqual(
            manifest.sha256,
            hashlib.sha256(DeviceV3Handler.manifest_bytes).hexdigest(),
        )
        self.assertEqual(artifact.identity, f'"{ARTIFACT_ID}"')
        self.assertEqual(b"".join(chunks), ARTIFACT[4:])
        self.assertIn(
            (
                "GET",
                f"/api/v3/sessions/{SESSION_ONE}/artifacts/{ARTIFACT_ID}",
                "Bearer reader-token",
                f'"{ARTIFACT_ID}"',
            ),
            DeviceV3Handler.requests,
        )

    def test_frozen_error_statuses_have_stable_failure_codes(self) -> None:
        expected = {
            401: "AUTHENTICATION_REQUIRED",
            403: "FORBIDDEN",
            409: "SESSION_NOT_VERIFIED",
            423: "CAPTURE_BUSY",
            416: "RANGE_NOT_SATISFIABLE",
        }
        for status, code in expected.items():
            with self.subTest(status=status):
                DeviceV3Handler.error_status = status
                with self.assertRaises(LanFailure) as caught:
                    self.client.inspect_artifact(
                        SESSION_ONE,
                        artifact_id=ARTIFACT_ID,
                        expected_size=len(ARTIFACT),
                        expected_media_type="video/mp4",
                    )
                self.assertEqual(caught.exception.code, code)

    def test_incompatible_api_version_is_rejected(self) -> None:
        original = DeviceV3Handler._handle

        def incompatible(handler, *, head):
            if handler.path == "/api/v3/device":
                handler._json(
                    {
                        "schema": "ylx.device.v3",
                        "device": {
                            "device_id": DEVICE_ID,
                            "device_label": "YLX-30D5872D",
                        },
                        "api_version": "4.0",
                        "capabilities": {"range_download": True},
                    }
                )
                return
            original(handler, head=head)

        DeviceV3Handler._handle = incompatible
        try:
            with self.assertRaisesRegex(LanFailure, "3.0"):
                self.client.probe(CancellationToken())
        finally:
            DeviceV3Handler._handle = original


class LanApplicationImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.session = create_device_session(self.root / "remote")
        manifest = json.loads((self.session / "manifest.json").read_bytes())
        DeviceV3Handler.manifest_bytes = (self.session / "manifest.json").read_bytes()
        DeviceV3Handler.artifact_payloads = {
            descriptor["artifact_id"]: (
                self.session.joinpath(*descriptor["path"].split("/")).read_bytes(),
                descriptor["media_type"],
            )
            for descriptor in _artifact_descriptors(manifest)
        }
        DeviceV3Handler.requests = []
        DeviceV3Handler.error_status = None
        DeviceV3Handler.interrupt_artifact = next(
            iter(DeviceV3Handler.artifact_payloads)
        )
        DeviceV3Handler.interrupted = False
        DeviceV3Handler.ranges = []
        self.server = QuietThreadingHTTPServer(("127.0.0.1", 0), DeviceV3Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.old_credential = os.environ.get("YLX_TRANSFER_CREDENTIAL_DEVICE_A")
        os.environ["YLX_TRANSFER_CREDENTIAL_DEVICE_A"] = "reader-token"
        self.app = self._application()

    def tearDown(self) -> None:
        self.app.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        if self.old_credential is None:
            os.environ.pop("YLX_TRANSFER_CREDENTIAL_DEVICE_A", None)
        else:
            os.environ["YLX_TRANSFER_CREDENTIAL_DEVICE_A"] = self.old_credential
        self.temporary.cleanup()

    def _application(self, *, free_space=None):
        return Application(
            self.root / "app",
            media_roots=(self.root,),
            sdk_client=UnavailablePublicationSdk(),
            import_free_space=free_space,
            auto_start=False,
        )

    def test_lan_import_checks_remaining_space_before_artifact_transfer(self) -> None:
        DeviceV3Handler.interrupt_artifact = None
        self.app.close()
        self.app = self._application(free_space=lambda path: 0)
        self.app.connect_device(
            {"endpoint": self.endpoint, "credential_ref": "device-a"}
        )
        session = next(
            item
            for item in self.app.sources.list_sessions()
            if item.session_id == self.session.name
        )
        DeviceV3Handler.requests = []
        task, _ = self.app.import_service.enqueue(session.record_id)

        result = self.app.import_service.run(task.task_id)

        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "INSUFFICIENT_SPACE")
        self.assertFalse(
            any("/artifacts/" in path for _, path, _, _ in DeviceV3Handler.requests)
        )
        self.assertEqual(self.app.imports.list_local(), ())

    def test_http_device_connection_and_import_complete_the_lan_workflow(self) -> None:
        DeviceV3Handler.interrupt_artifact = None
        api = create_server("127.0.0.1", 0, self.app)
        thread = threading.Thread(target=api.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{api.server_port}"
        try:
            status, connected = _post_json(
                url,
                "/api/sources/device",
                {"endpoint": self.endpoint, "credential_ref": "device-a"},
            )
            with urllib.request.urlopen(f"{url}/api/state") as response:
                state = json.load(response)
            source = next(item for item in state["sources"] if item["kind"] == "device")
            session = next(
                item
                for item in state["sessions"]
                if item["source_id"] == source["source_id"]
                and item["session_id"] == self.session.name
            )

            queued_status, queued = _post_json(
                url,
                "/api/imports",
                {"source_session_record_id": session["record_id"]},
            )
            task = _wait_for_task(url, queued["task"]["task_id"])

            self.assertEqual(status, 202)
            self.assertEqual(queued_status, 202)
            self.assertEqual(connected["sessions"], 2)
            self.assertEqual(task["state"], "succeeded", task)
            with urllib.request.urlopen(f"{url}/api/state") as response:
                completed = json.load(response)
            local = Path(completed["local_sessions"][0]["path"])
            self.assertEqual(_tree_bytes(local), _tree_bytes(self.session))
            with urllib.request.urlopen(f"{url}/") as response:
                page = response.read().decode("utf-8")
            for field in (
                'name="credential_ref"',
                'name="tls_pin_target"',
                'name="tls_pin_algorithm"',
                'name="tls_pin_encoding"',
                'name="tls_pin_value"',
            ):
                self.assertIn(field, page)
        finally:
            api.shutdown()
            api.server_close()
            thread.join()

    def test_lan_and_read_only_media_gui_import_the_same_device_session(self) -> None:
        DeviceV3Handler.interrupt_artifact = None
        lan_local = _http_import_device(self.app, self.endpoint, self.session.name)

        mount = self.root / "media" / "card"
        media_session = mount / "recordings" / self.session.name
        media_session.parent.mkdir(parents=True)
        shutil.copytree(self.session, media_session)
        (mount / ".ylx-volume.json").write_text(
            json.dumps(
                {
                    "format": "ylx.volume.v1",
                    "volume_id": "0198c9a8-7a3c-4000-8000-000000000001",
                    "label": "Device Session v1 fixture",
                }
            ),
            encoding="utf-8",
        )
        media_app = Application(
            self.root / "media-app",
            media_roots=(self.root / "media",),
            sdk_client=DeviceSessionMediaSdk(media_session),
            auto_start=False,
        )
        try:
            media_local = _http_import_media(media_app, mount, self.session.name)
        finally:
            media_app.close()

        self.assertEqual(_tree_bytes(lan_local), _tree_bytes(media_local))
        self.assertEqual(_tree_bytes(media_local), _tree_bytes(self.session))
        lan_plan = build_publication_plan(
            lan_local,
            publication_id="01989f70-0000-7d4e-bf50-61728394a5b6",
            published_at="2026-08-08T11:00:00+08:00",
            raw_prefix="pairwise/",
        )
        media_plan = build_publication_plan(
            media_local,
            publication_id="01989f70-0000-7d4e-bf50-61728394a5b6",
            published_at="2026-08-08T11:00:00+08:00",
            raw_prefix="pairwise/",
        )
        self.assertEqual(lan_plan.publication_bytes, media_plan.publication_bytes)
        self.assertEqual(
            tuple((item.key, item.size, item.sha256) for item in lan_plan.data_objects),
            tuple(
                (item.key, item.size, item.sha256) for item in media_plan.data_objects
            ),
        )

    def test_interrupted_lan_import_resumes_after_application_restart(self) -> None:
        connected = self.app.connect_device(
            {"endpoint": self.endpoint, "credential_ref": "device-a"}
        )
        session = next(
            item
            for item in self.app.sources.list_sessions()
            if item.session_id == self.session.name
        )
        task, created = self.app.import_service.enqueue(session.record_id)

        first = self.app.import_service.run(task.task_id)

        self.assertTrue(created)
        self.assertEqual(connected["sessions"], 2)
        self.assertEqual(first.state, TaskState.FAILED)
        self.assertEqual(first.error_code, "NETWORK_ERROR")
        self.app.close()
        self.app = self._application()
        retry = self.app.tasks.retry(task.task_id)
        completed = self.app.import_service.run(retry.task_id)

        self.assertEqual(completed.state, TaskState.SUCCEEDED)
        self.assertEqual(completed.generation, 2)
        local = self.app.imports.list_local()[0]
        self.assertEqual(_tree_bytes(local.path), _tree_bytes(self.session))
        interrupted_id = DeviceV3Handler.interrupt_artifact
        self.assertTrue(
            any(
                if_range == f'"{interrupted_id}"'
                for _, _, _, if_range in DeviceV3Handler.requests
            )
        )
        self.assertIn("bytes=4-", DeviceV3Handler.ranges)
        with self.app.database.connect() as connection:
            persisted = connection.execute(
                "SELECT spec_json FROM lan_import_operations WHERE task_id = ?",
                (task.task_id,),
            ).fetchone()["spec_json"]
        self.assertNotIn("reader-token", persisted)

    def test_retry_rejects_late_checkpoint_from_previous_generation(self) -> None:
        self.app.connect_device(
            {"endpoint": self.endpoint, "credential_ref": "device-a"}
        )
        session = next(
            item
            for item in self.app.sources.list_sessions()
            if item.session_id == self.session.name
        )
        task, _ = self.app.import_service.enqueue(session.record_id)
        failed = self.app.import_service.run(task.task_id)
        retained = self.app.lan_imports.get(task.task_id)
        self.assertIsNotNone(retained)
        assert retained is not None
        relative_path, (offset, identity) = next(iter(retained.checkpoints.items()))

        retried = self.app.tasks.retry(task.task_id)

        self.assertEqual(failed.state, TaskState.FAILED)
        self.assertEqual(retried.generation, failed.generation + 1)
        with self.assertRaises(StaleTaskUpdate):
            self.app.lan_imports.checkpoint(
                task.task_id,
                failed.generation,
                relative_path,
                offset + 1,
                identity,
            )
        current = self.app.lan_imports.get(task.task_id)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.checkpoints[relative_path], (offset, identity))

    def test_process_kill_resumes_lan_import_from_durable_range_checkpoint(
        self,
    ) -> None:
        DeviceV3Handler.interrupt_artifact = None
        descriptor = _artifact_descriptors(
            json.loads((self.session / "manifest.json").read_bytes())
        )[0]
        original_id = descriptor["artifact_id"]
        payload = b"0123456789abcdef" * (256 * 1024)
        source_path = self.session.joinpath(*descriptor["path"].split("/"))
        source_path.write_bytes(payload)
        manifest = json.loads((self.session / "manifest.json").read_bytes())
        changed = next(
            item
            for item in _artifact_descriptors(manifest)
            if item["artifact_id"] == original_id
        )
        changed_id = hashlib.sha256(payload).hexdigest()
        changed.update(
            artifact_id=changed_id,
            bytes=len(payload),
            sha256=changed_id,
        )
        manifest_bytes = (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        (self.session / "manifest.json").write_bytes(manifest_bytes)
        DeviceV3Handler.manifest_bytes = manifest_bytes
        DeviceV3Handler.artifact_payloads.pop(original_id)
        DeviceV3Handler.artifact_payloads[changed_id] = (payload, "video/mp4")
        DeviceV3Handler.stream_chunk_size = 64 * 1024
        DeviceV3Handler.stream_delay = 0.01
        self.app.connect_device(
            {"endpoint": self.endpoint, "credential_ref": "device-a"}
        )
        session = next(
            item
            for item in self.app.sources.list_sessions()
            if item.session_id == self.session.name
        )
        task, _ = self.app.import_service.enqueue(session.record_id)
        self.app.close()
        worker = Path(__file__).with_name("restart_lan_worker.py")
        environment = os.environ.copy()
        source_root = str(Path(__file__).parents[1] / "src")
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, (source_root, environment.get("PYTHONPATH")))
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(worker),
                str(self.root / "app"),
                str(self.root),
                task.task_id,
            ],
            env=environment,
        )
        try:
            deadline = time.monotonic() + 10
            checkpoint = 0
            while checkpoint == 0:
                if process.poll() is not None:
                    self.fail(
                        f"LAN import worker exited early with {process.returncode}"
                    )
                with self.app.database.connect() as connection:
                    row = connection.execute(
                        """
                        SELECT MAX(offset_bytes) AS offset_bytes
                        FROM lan_import_checkpoints WHERE task_id = ?
                        """,
                        (task.task_id,),
                    ).fetchone()
                checkpoint = int(row["offset_bytes"] or 0)
                if time.monotonic() >= deadline:
                    self.fail("LAN import worker did not persist a checkpoint")
                time.sleep(0.01)
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        DeviceV3Handler.stream_chunk_size = None
        DeviceV3Handler.stream_delay = 0.0
        DeviceV3Handler.ranges = []
        self.app = self._application()
        recovered = self.app.tasks.get(task.task_id)
        result = self.app.import_service.run(task.task_id)

        self.assertEqual(recovered.state, TaskState.QUEUED)
        self.assertEqual(recovered.generation, 2)
        self.assertEqual(result.state, TaskState.SUCCEEDED)
        self.assertEqual(result.generation, 2)
        self.assertTrue(
            any(
                value is not None and int(value[6:-1]) >= checkpoint
                for value in DeviceV3Handler.ranges
            )
        )
        self.assertEqual(
            _tree_bytes(self.app.imports.list_local()[0].path),
            _tree_bytes(self.session),
        )

    def test_manifest_change_after_discovery_never_creates_local_session(self) -> None:
        self.app.connect_device(
            {"endpoint": self.endpoint, "credential_ref": "device-a"}
        )
        session = next(
            item
            for item in self.app.sources.list_sessions()
            if item.session_id == self.session.name
        )
        DeviceV3Handler.manifest_bytes += b"\n"
        task, _ = self.app.import_service.enqueue(session.record_id)

        result = self.app.import_service.run(task.task_id)

        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "REMOTE_CHANGED")
        self.assertEqual(self.app.imports.list_local(), ())

    def test_artifact_digest_mismatch_never_publishes_local_session(self) -> None:
        DeviceV3Handler.interrupt_artifact = None
        self.app.connect_device(
            {"endpoint": self.endpoint, "credential_ref": "device-a"}
        )
        session = next(
            item
            for item in self.app.sources.list_sessions()
            if item.session_id == self.session.name
        )
        artifact_id = next(iter(DeviceV3Handler.artifact_payloads))
        payload, media_type = DeviceV3Handler.artifact_payloads[artifact_id]
        DeviceV3Handler.artifact_payloads[artifact_id] = (
            b"x" * len(payload),
            media_type,
        )
        task, _ = self.app.import_service.enqueue(session.record_id)

        result = self.app.import_service.run(task.task_id)

        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.error_code, "CONTENT_MISMATCH")
        self.assertEqual(self.app.imports.list_local(), ())
        self.assertFalse(
            any((self.root / "app" / "repository" / "sessions").rglob("manifest.json"))
        )


@unittest.skipUnless(shutil.which("openssl"), "真实 TLS pin 测试需要 openssl")
class LanTlsPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.cert = root / "cert.pem"
        self.key = root / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(self.key),
                "-out",
                str(self.cert),
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        DeviceV3Handler.requests = []
        DeviceV3Handler.error_status = None
        DeviceV3Handler.ranges = []
        self.server = QuietThreadingHTTPServer(("127.0.0.1", 0), DeviceV3Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        der = ssl.PEM_cert_to_DER_cert(self.cert.read_text(encoding="ascii"))
        self.digest = hashlib.sha256(der).hexdigest()
        self.endpoint = f"https://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def spec(self, digest: str, *, target: str = "leaf-certificate-der"):
        return LanConnectionSpec(
            endpoint=self.endpoint,
            credential_ref="device-a",
            tls_pin=TlsPin(
                target=target,
                algorithm="sha256",
                encoding="lowercase-hex",
                value=digest,
            ),
        )

    def test_manual_ip_tls_pin_match_allows_bearer_v3_request(self) -> None:
        client = LanDeviceClient(
            self.spec(self.digest),
            credentials=StaticCredentialProvider(),
            timeout=2,
        )

        snapshot = client.probe(CancellationToken())

        self.assertEqual(snapshot.identity.device_id, DEVICE_ID)
        self.assertTrue(DeviceV3Handler.requests)
        self.assertTrue(
            all(
                auth == "Bearer reader-token"
                for _, _, auth, _ in DeviceV3Handler.requests
            )
        )

    def test_tls_pin_mismatch_sends_no_http_or_bearer_request(self) -> None:
        client = LanDeviceClient(
            self.spec("0" * 64),
            credentials=StaticCredentialProvider(),
            timeout=2,
        )

        with self.assertRaises(LanFailure) as caught:
            client.probe(CancellationToken())

        self.assertEqual(caught.exception.code, "TLS_PIN_MISMATCH")
        self.assertEqual(DeviceV3Handler.requests, [])

    def test_unknown_tls_pin_target_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "target"):
            LanDeviceClient(
                self.spec(self.digest, target="guessed-spki"),
                credentials=StaticCredentialProvider(),
            )


def _post_json(url: str, path: str, payload: dict[str, object]):
    request = urllib.request.Request(
        f"{url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return response.status, json.load(response)


def _wait_for_task(url: str, task_id: str):
    deadline = time.monotonic() + 5
    while True:
        with urllib.request.urlopen(f"{url}/api/state") as response:
            state = json.load(response)
        task = next(item for item in state["tasks"] if item["task_id"] == task_id)
        if task["state"] in {"succeeded", "failed", "cancelled"}:
            return task
        if time.monotonic() >= deadline:
            raise AssertionError(f"LAN import did not finish: {task}")
        time.sleep(0.01)


def _http_import_device(
    application: Application, endpoint: str, session_id: str
) -> Path:
    return _http_import(
        application,
        "/api/sources/device",
        {"endpoint": endpoint, "credential_ref": "device-a"},
        session_id,
    )


def _http_import_media(application: Application, mount: Path, session_id: str) -> Path:
    return _http_import(
        application,
        "/api/sources/media",
        {"path": str(mount)},
        session_id,
    )


def _http_import(
    application: Application,
    source_path: str,
    source_payload: dict[str, object],
    session_id: str,
) -> Path:
    server = create_server("127.0.0.1", 0, application)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        status, _ = _post_json(url, source_path, source_payload)
        with urllib.request.urlopen(f"{url}/api/state") as response:
            state = json.load(response)
        source_session = next(
            item for item in state["sessions"] if item["session_id"] == session_id
        )
        queued_status, queued = _post_json(
            url,
            "/api/imports",
            {"source_session_record_id": source_session["record_id"]},
        )
        task = _wait_for_task(url, queued["task"]["task_id"])
        if status != 202 or queued_status != 202 or task["state"] != "succeeded":
            raise AssertionError(f"HTTP import did not succeed: {task}")
        with urllib.request.urlopen(f"{url}/api/state") as response:
            completed = json.load(response)
        local = next(
            item
            for item in completed["local_sessions"]
            if item["session_id"] == session_id
        )
        return Path(local["path"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _artifact_descriptors(manifest):
    video = manifest["video"]
    values = []
    if video["layout"] == "split-eyes":
        for segment in video["segments"]:
            values.extend(segment["artifacts"].values())
    else:
        values.append(video["artifact"])
    values.extend((manifest["imu"]["artifact"], manifest["frames"]["artifact"]))
    values.extend(manifest["logs"])
    return values


def _tree_bytes(root: Path):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


if __name__ == "__main__":
    unittest.main()
