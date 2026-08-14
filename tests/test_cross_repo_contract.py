from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from ylx_transfer.application import Application
from ylx_transfer.runtime import CancellationToken
from ylx_transfer.sdk import PipelineSdkClient, SdkGateway
from ylx_transfer.server import create_server

PIPELINE_SRC = os.environ.get("YLX_PIPELINE_SRC")
RP_FIXTURE = os.environ.get("YLX_RP_FIXTURE")


@unittest.skipUnless(
    PIPELINE_SRC and RP_FIXTURE,
    "需要 YLX_PIPELINE_SRC 与 YLX_RP_FIXTURE 才能运行跨仓契约测试",
)
class CrossRepositoryContractTests(unittest.TestCase):
    def test_rp_fixture_builds_complete_sdk_copy_plan(self) -> None:
        sys.path.insert(0, str(PIPELINE_SRC))
        try:
            plan = SdkGateway(PipelineSdkClient()).build_copy_plan(
                Path(str(RP_FIXTURE)), CancellationToken()
            )
        finally:
            sys.path.remove(str(PIPELINE_SRC))
        self.assertEqual(len(plan.files), 7)
        self.assertEqual(plan.files[-1].relative_path, plan.commit_last)
        self.assertEqual(plan.commit_last, "manifest.json")

    def test_real_media_http_import_publishes_a_valid_session(self) -> None:
        sys.path.insert(0, str(PIPELINE_SRC))
        try:
            sdk_client = PipelineSdkClient()
        finally:
            sys.path.remove(str(PIPELINE_SRC))

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            mount = base / "media" / "volume"
            session_id = Path(str(RP_FIXTURE)).name
            session = mount / "recordings" / session_id
            session.parent.mkdir(parents=True)
            shutil.copytree(Path(str(RP_FIXTURE)), session)
            (mount / ".ylx-volume.json").write_text(
                json.dumps(
                    {
                        "format": "ylx.volume.v1",
                        "volume_id": "0198c9a8-7a3c-4000-8000-000000000001",
                        "label": "DT-02 contract fixture",
                    }
                ),
                encoding="utf-8",
            )
            source_facts = _tree_facts(mount)
            application = Application(
                base / "app",
                media_roots=(base / "media",),
                sdk_client=sdk_client,
                auto_start=False,
            )
            server = create_server("127.0.0.1", 0, application)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                _, scan = _post_json(url, "/api/sources/media", {"path": str(mount)})
                self.assertEqual(scan["sessions"], 1)
                with urllib.request.urlopen(f"{url}/api/state") as response:
                    state = json.load(response)
                record_id = state["sessions"][0]["record_id"]
                _, queued = _post_json(
                    url,
                    "/api/imports",
                    {"source_session_record_id": record_id},
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
                        self.fail(f"real media import did not finish: {task}")
                    time.sleep(0.01)

                self.assertEqual(task["state"], "succeeded", task)
                self.assertEqual(len(state["local_sessions"]), 1)
                published = Path(state["local_sessions"][0]["path"])
                self.assertEqual(published.name, session_id)
                report = SdkGateway(sdk_client).validate_session(
                    published, CancellationToken()
                )
                self.assertTrue(report.valid, report.errors)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
                application.close()
            self.assertEqual(_tree_facts(mount), source_facts)
            self.assertEqual(_open_descriptors_under(mount), ())

    def test_failed_real_media_import_releases_source_handles(self) -> None:
        sys.path.insert(0, str(PIPELINE_SRC))
        try:
            sdk_client = PipelineSdkClient()
        finally:
            sys.path.remove(str(PIPELINE_SRC))

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            mount = base / "media" / "volume"
            session_id = Path(str(RP_FIXTURE)).name
            session = mount / "recordings" / session_id
            session.parent.mkdir(parents=True)
            shutil.copytree(Path(str(RP_FIXTURE)), session)
            (session / "video" / "left.bin").write_bytes(b"corrupt-source")
            (mount / ".ylx-volume.json").write_text(
                json.dumps(
                    {
                        "format": "ylx.volume.v1",
                        "volume_id": "0198c9a8-7a3c-4000-8000-000000000002",
                        "label": "DT-02 invalid contract fixture",
                    }
                ),
                encoding="utf-8",
            )
            source_facts = _tree_facts(mount)
            application = Application(
                base / "app",
                media_roots=(base / "media",),
                sdk_client=sdk_client,
                auto_start=False,
            )
            server = create_server("127.0.0.1", 0, application)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                _, scan = _post_json(url, "/api/sources/media", {"path": str(mount)})
                self.assertEqual(scan["sessions"], 1)
                with urllib.request.urlopen(f"{url}/api/state") as response:
                    state = json.load(response)
                _, queued = _post_json(
                    url,
                    "/api/imports",
                    {"source_session_record_id": state["sessions"][0]["record_id"]},
                )
                task = _wait_for_task(url, queued["task"]["task_id"])
                self.assertEqual(task["state"], "failed")
                self.assertEqual(task["error"]["code"], "INVALID_SESSION")
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
                application.close()
            self.assertEqual(_tree_facts(mount), source_facts)
            self.assertEqual(_open_descriptors_under(mount), ())

    def test_media_gui_and_dt01_cli_preserve_the_same_legacy_session(self) -> None:
        fixture = Path(str(RP_FIXTURE))
        source_manifest_bytes = (fixture / "manifest.json").read_bytes()
        source_manifest = json.loads(source_manifest_bytes)
        sys.path.insert(0, str(PIPELINE_SRC))
        try:
            sdk_client = PipelineSdkClient()
        finally:
            sys.path.remove(str(PIPELINE_SRC))

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            mount = base / "media" / "volume"
            media_session = mount / "recordings" / fixture.name
            media_session.parent.mkdir(parents=True)
            shutil.copytree(fixture, media_session)
            (mount / ".ylx-volume.json").write_text(
                json.dumps(
                    {
                        "format": "ylx.volume.v1",
                        "volume_id": "0198c9a8-7a3c-4000-8000-000000000003",
                        "label": "DT-02 pairwise fixture",
                    }
                ),
                encoding="utf-8",
            )
            imported = _http_media_import(base / "app", mount, sdk_client)
            target = base / "dt01-objects"
            checkpoint = base / "dt01-checkpoint.json"
            first = _pipeline_cli(
                "publish-local",
                str(fixture),
                str(target),
                "--prefix",
                "pairwise",
                "--checkpoint",
                str(checkpoint),
                "--json",
            )
            second = _pipeline_cli(
                "publish-local",
                str(fixture),
                str(target),
                "--prefix",
                "pairwise",
                "--checkpoint",
                str(checkpoint),
                "--json",
            )
            inspected = _pipeline_cli("inspect", str(fixture), "--json")
            marker_path = target.joinpath(*first["publication_key"].split("/"))
            marker_bytes = marker_path.read_bytes()
            marker = json.loads(marker_bytes)

            self.assertEqual(_tree_bytes(imported), _tree_bytes(fixture))
            self.assertEqual(
                (imported / "manifest.json").read_bytes(), source_manifest_bytes
            )
            self.assertEqual(inspected["session_id"], source_manifest["session_id"])
            self.assertEqual(marker["session_id"], source_manifest["session_id"])
            self.assertIsNone(source_manifest.get("take"))
            self.assertNotIn("take", marker)

            expected = {
                item["path"]: (item["role"], item["bytes"], item["sha256"])
                for item in source_manifest["artifacts"]
            }
            published = {
                item["relative_path"]: (
                    item["role"],
                    item["bytes"],
                    item["sha256"],
                )
                for item in marker["objects"]
                if item["role"] != "session.manifest"
            }
            self.assertEqual(published, expected)
            for item in marker["objects"]:
                stored = target.joinpath(*item["object_key"].split("/"))
                source = fixture.joinpath(*item["relative_path"].split("/"))
                self.assertEqual(stored.read_bytes(), source.read_bytes())
                self.assertEqual(stored.stat().st_size, item["bytes"])
                self.assertEqual(
                    hashlib.sha256(stored.read_bytes()).hexdigest(), item["sha256"]
                )

            self.assertEqual(first["uploaded"][-1], first["publication_key"])
            self.assertEqual(
                first["uploaded"][-2], marker["source_manifest"]["object_key"]
            )
            self.assertEqual(marker["source_manifest"], marker["objects"][-1])
            self.assertEqual(
                marker["source_manifest"]["sha256"],
                hashlib.sha256(source_manifest_bytes).hexdigest(),
            )
            self.assertEqual(second["uploaded"], [])
            self.assertEqual(set(second["reused"]), set(first["uploaded"]))
            self.assertTrue(second["resumed"])


def _post_json(url: str, path: str, payload: dict[str, object]):
    request = urllib.request.Request(
        f"{url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return response.status, json.load(response)


def _http_media_import(data_dir: Path, mount: Path, sdk_client) -> Path:
    application = Application(
        data_dir,
        media_roots=(mount.parent,),
        sdk_client=sdk_client,
        auto_start=False,
    )
    server = create_server("127.0.0.1", 0, application)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _, scan = _post_json(url, "/api/sources/media", {"path": str(mount)})
        if scan["sessions"] != 1:
            raise AssertionError(f"unexpected media session count: {scan}")
        with urllib.request.urlopen(f"{url}/api/state") as response:
            state = json.load(response)
        _, queued = _post_json(
            url,
            "/api/imports",
            {"source_session_record_id": state["sessions"][0]["record_id"]},
        )
        task = _wait_for_task(url, queued["task"]["task_id"])
        if task["state"] != "succeeded":
            raise AssertionError(f"media import failed: {task}")
        with urllib.request.urlopen(f"{url}/api/state") as response:
            completed = json.load(response)
        return Path(completed["local_sessions"][0]["path"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        application.close()


def _pipeline_cli(*arguments: str) -> dict[str, object]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PIPELINE_SRC)
    result = subprocess.run(
        [sys.executable, "-m", "ylx_card_pipeline", *arguments],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise AssertionError(f"DT-01 CLI returned an invalid result: {value}")
    return value


def _wait_for_task(url: str, task_id: str):
    deadline = time.monotonic() + 5
    while True:
        with urllib.request.urlopen(f"{url}/api/state") as response:
            state = json.load(response)
        task = next(item for item in state["tasks"] if item["task_id"] == task_id)
        if task["state"] in {"succeeded", "failed", "cancelled"}:
            return task
        if time.monotonic() >= deadline:
            raise AssertionError(f"media import did not finish: {task}")
        time.sleep(0.01)


def _tree_facts(root: Path):
    return {
        path.relative_to(root).as_posix(): (
            path.stat().st_ino,
            path.stat().st_uid,
            path.stat().st_gid,
            path.stat().st_mode,
            path.stat().st_size,
            path.stat().st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def _tree_bytes(root: Path):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _open_descriptors_under(root: Path):
    proc = Path("/proc/self/fd")
    if not proc.is_dir():
        return ()
    resolved_root = root.resolve()
    held = []
    for descriptor in proc.iterdir():
        try:
            target = Path(os.readlink(descriptor))
            if target.is_absolute() and target.resolve(strict=False).is_relative_to(
                resolved_root
            ):
                held.append((descriptor.name, str(target)))
        except (FileNotFoundError, OSError):
            continue
    return tuple(sorted(held))


if __name__ == "__main__":
    unittest.main()
