from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ylx_transfer.database import Database, SourceRepository
from ylx_transfer.discovery import (
    DeviceDiscovery,
    DeviceIdentity,
    DeviceSession,
    DeviceSnapshot,
    DiscoveryError,
    JsonHttpDeviceProbe,
    MediaDiscovery,
)
from ylx_transfer.models import Availability
from ylx_transfer.runtime import CancellationToken
from ylx_transfer.sdk import SdkGateway, SessionSummary


class FakeProbe:
    def __init__(self) -> None:
        self.responses = {}

    def probe(self, endpoint, cancellation):
        response = self.responses[endpoint]
        if isinstance(response, Exception):
            raise response
        return response


class SequencedProbe:
    def __init__(self, snapshots):
        self.snapshots = iter(snapshots)

    def probe(self, endpoint, cancellation):
        response = next(self.snapshots)
        if callable(response):
            return response()
        return response


class RpApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/v0/device":
            payload = {
                "api_version": "v0",
                "device": {
                    "id": "rp-001",
                    "label": "胸前相机",
                    "model": "Pi",
                    "software_version": "0.1.0",
                },
            }
        elif self.path == "/api/v0/sessions":
            payload = {
                "revision": 7,
                "sessions": [
                    {
                        "session_id": "session-1",
                        "state": "sealed",
                        "started_at": "2026-08-10T08:00:00Z",
                        "ended_at": "2026-08-10T08:10:00Z",
                        "bytes": 42,
                    }
                ],
            }
        else:
            self.send_error(404)
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class FakeMediaSdk:
    api_version = "1.0"

    def __init__(self, session_path: Path) -> None:
        self.session_path = session_path

    def discover_sessions(self, root, cancellation):
        cancellation.raise_if_cancelled()
        return (SessionSummary("session-1", self.session_path, label="测试会话"),)

    def inspect_session(self, path, cancellation):
        raise NotImplementedError

    def validate_session(self, path, cancellation):
        raise NotImplementedError


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        database = Database(root / "state.db")
        database.initialize()
        self.repository = SourceRepository(database)
        self.root = root

    def tearDown(self) -> None:
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
        self.temporary.cleanup()

    def test_same_name_does_not_merge_different_devices(self) -> None:
        probe = FakeProbe()
        probe.responses = {
            "http://10.0.0.1": DeviceSnapshot(
                DeviceIdentity("device-a", "相机", "1"), ()
            ),
            "http://10.0.0.2": DeviceSnapshot(
                DeviceIdentity("device-b", "相机", "1"), ()
            ),
        }
        discovery = DeviceDiscovery(self.repository, probe)
        first, _ = discovery.connect("http://10.0.0.1/", CancellationToken())
        second, _ = discovery.connect("http://10.0.0.2", CancellationToken())
        self.assertNotEqual(first.source_id, second.source_id)
        self.assertEqual(len(self.repository.list_sources()), 2)

    def test_address_change_keeps_identity_and_retires_old_address(self) -> None:
        probe = FakeProbe()
        snapshot = DeviceSnapshot(
            DeviceIdentity("device-a", "相机 A", "1"),
            (DeviceSession("s1", "/sessions/s1"),),
        )
        probe.responses = {
            "http://10.0.0.1": snapshot,
            "http://10.0.0.9": snapshot,
        }
        discovery = DeviceDiscovery(self.repository, probe)
        first, _ = discovery.connect("http://10.0.0.1", CancellationToken())
        second, _ = discovery.connect("http://10.0.0.9", CancellationToken())
        self.assertEqual(first.source_id, second.source_id)
        refreshed = self.repository.get_source(first.source_id)
        availability = {
            item.location: item.availability for item in refreshed.locations
        }
        self.assertEqual(availability["http://10.0.0.1"], Availability.OFFLINE)
        self.assertEqual(availability["http://10.0.0.9"], Availability.ONLINE)

    def test_timeout_marks_known_device_offline(self) -> None:
        probe = FakeProbe()
        endpoint = "http://10.0.0.1"
        probe.responses[endpoint] = DeviceSnapshot(
            DeviceIdentity("device-a", "相机 A", "1"), ()
        )
        discovery = DeviceDiscovery(self.repository, probe)
        source, _ = discovery.connect(endpoint, CancellationToken())
        probe.responses[endpoint] = TimeoutError()
        with self.assertRaisesRegex(DiscoveryError, "已离线"):
            discovery.connect(endpoint, CancellationToken())
        self.assertEqual(
            self.repository.get_source(source.source_id).availability,
            Availability.OFFLINE,
        )

    def test_late_device_scan_cannot_retire_newer_session_facts(self) -> None:
        endpoint = "http://10.0.0.1"
        old = DeviceSnapshot(
            DeviceIdentity("device-a", "相机 A", "3.0"),
            (DeviceSession("session-old", "/sessions/session-old"),),
        )
        new = DeviceSnapshot(
            DeviceIdentity("device-a", "相机 A", "3.0"),
            (DeviceSession("session-new", "/sessions/session-new"),),
        )
        old_started = threading.Event()
        release_old = threading.Event()

        def delayed_old():
            old_started.set()
            self.assertTrue(release_old.wait(2))
            return old

        discovery = DeviceDiscovery(
            self.repository, SequencedProbe((old, delayed_old, new))
        )
        source, _ = discovery.connect(endpoint, CancellationToken())
        late_error = []

        def run_late_scan():
            try:
                discovery.connect(endpoint, CancellationToken())
            except DiscoveryError as exc:
                late_error.append(exc)

        late = threading.Thread(target=run_late_scan)
        late.start()
        self.assertTrue(old_started.wait(2))
        discovery.connect(endpoint, CancellationToken())
        release_old.set()
        late.join(2)

        self.assertFalse(late.is_alive())
        self.assertEqual(len(late_error), 1)
        self.assertIsInstance(late_error[0], DiscoveryError)
        self.assertIn("过期", str(late_error[0]))
        sessions = {
            item.session_id: item.availability
            for item in self.repository.list_sessions(source.source_id)
        }
        self.assertEqual(
            sessions,
            {
                "session-new": Availability.ONLINE,
                "session-old": Availability.OFFLINE,
            },
        )

    def test_scan_superseded_by_newer_in_flight_scan_is_rejected(self) -> None:
        endpoint = "http://10.0.0.1"
        old = DeviceSnapshot(
            DeviceIdentity("device-a", "相机 A", "3.0"),
            (DeviceSession("session-old", "/sessions/session-old"),),
        )
        new = DeviceSnapshot(
            DeviceIdentity("device-a", "相机 A", "3.0"),
            (DeviceSession("session-new", "/sessions/session-new"),),
        )
        old_started = threading.Event()
        new_started = threading.Event()
        release_old = threading.Event()
        release_new = threading.Event()

        def delayed_old():
            old_started.set()
            self.assertTrue(release_old.wait(2))
            return old

        def delayed_new():
            new_started.set()
            self.assertTrue(release_new.wait(2))
            return new

        discovery = DeviceDiscovery(
            self.repository, SequencedProbe((delayed_old, delayed_new))
        )
        old_errors = []
        new_results = []

        def run_old_scan():
            try:
                discovery.connect(endpoint, CancellationToken())
            except DiscoveryError as exc:
                old_errors.append(exc)

        def run_new_scan():
            new_results.append(discovery.connect(endpoint, CancellationToken()))

        old_thread = threading.Thread(target=run_old_scan)
        new_thread = threading.Thread(target=run_new_scan)
        old_thread.start()
        self.assertTrue(old_started.wait(2))
        new_thread.start()
        self.assertTrue(new_started.wait(2))
        release_old.set()
        old_thread.join(2)

        self.assertFalse(old_thread.is_alive())
        self.assertEqual(len(old_errors), 1)
        self.assertIn("过期", str(old_errors[0]))
        self.assertEqual(self.repository.list_sources(), ())

        release_new.set()
        new_thread.join(2)
        self.assertFalse(new_thread.is_alive())
        self.assertEqual(len(new_results), 1)
        self.assertEqual(
            [item.session_id for item in new_results[0][1]], ["session-new"]
        )

    def test_real_http_probe_matches_rp_v0_contract(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), RpApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            discovery = DeviceDiscovery(self.repository, JsonHttpDeviceProbe(timeout=1))
            source, sessions = discovery.connect(endpoint, CancellationToken())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(source.stable_id, "rp-001")
        self.assertEqual(source.display_name, "胸前相机")
        self.assertEqual(sessions[0].session_id, "session-1")
        self.assertEqual(sessions[0].locator, "ylx-device://rp-001/session-1")

    def _make_media(self, name: str, volume_id: str = "volume-1") -> tuple[Path, Path]:
        mount = self.root / name
        session = mount / "sessions" / "session-1"
        session.mkdir(parents=True)
        (mount / ".ylx-volume.json").write_text(
            json.dumps({"volume_id": volume_id, "label": "录制卡"}),
            encoding="utf-8",
        )
        return mount, session

    def test_read_only_media_is_discovered_without_changes(self) -> None:
        mount, session = self._make_media("card")
        before = {
            str(path.relative_to(mount)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in mount.rglob("*")
            if path.is_file()
        }
        for directory in [session, session.parent, mount]:
            directory.chmod(0o555)
        discovery = MediaDiscovery(
            self.repository,
            SdkGateway(FakeMediaSdk(session)),
            (self.root,),
        )
        source, sessions = discovery.scan(mount, CancellationToken())
        after = {
            str(path.relative_to(mount)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in mount.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(source.stable_id, "volume-1")
        self.assertEqual(sessions[0].session_id, "session-1")

    def test_duplicate_mount_uses_one_stable_source(self) -> None:
        first_mount, first_session = self._make_media("card-a")
        second_mount, second_session = self._make_media("card-b")
        first_discovery = MediaDiscovery(
            self.repository, SdkGateway(FakeMediaSdk(first_session)), (self.root,)
        )
        second_discovery = MediaDiscovery(
            self.repository, SdkGateway(FakeMediaSdk(second_session)), (self.root,)
        )
        first, _ = first_discovery.scan(first_mount, CancellationToken())
        second, _ = second_discovery.scan(second_mount, CancellationToken())
        self.assertEqual(first.source_id, second.source_id)
        self.assertEqual(len(self.repository.list_sources()), 1)
        self.assertEqual(len(self.repository.get_source(first.source_id).locations), 2)

    def test_removal_makes_sessions_unavailable(self) -> None:
        mount, session = self._make_media("card")
        discovery = MediaDiscovery(
            self.repository, SdkGateway(FakeMediaSdk(session)), (self.root,)
        )
        source, _ = discovery.scan(mount, CancellationToken())
        discovery.removed(mount)
        self.assertEqual(
            self.repository.get_source(source.source_id).availability,
            Availability.OFFLINE,
        )
        self.assertEqual(
            self.repository.list_sessions(source.source_id)[0].availability,
            Availability.OFFLINE,
        )

    def test_sdk_path_cannot_escape_media(self) -> None:
        mount, _ = self._make_media("card")
        outside = self.root / "outside-session"
        outside.mkdir()
        discovery = MediaDiscovery(
            self.repository, SdkGateway(FakeMediaSdk(outside)), (mount,)
        )
        with self.assertRaisesRegex(DiscoveryError, "范围之外"):
            discovery.scan(mount, CancellationToken())

    def test_mount_symlink_cannot_escape_allowed_root(self) -> None:
        allowed = self.root / "allowed"
        allowed.mkdir()
        outside, session = self._make_media("outside")
        link = allowed / "card"
        os.symlink(outside, link)
        discovery = MediaDiscovery(
            self.repository, SdkGateway(FakeMediaSdk(session)), (allowed,)
        )
        with self.assertRaisesRegex(DiscoveryError, "允许的扫描范围"):
            discovery.scan(link, CancellationToken())


if __name__ == "__main__":
    unittest.main()
