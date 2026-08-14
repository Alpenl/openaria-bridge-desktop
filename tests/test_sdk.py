from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ylx_transfer.runtime import CancellationToken, OperationCancelled
from ylx_transfer.sdk import (
    PipelineSdkClient,
    SdkGateway,
    SdkOperationError,
    SdkVersionError,
    SessionCopyPlan,
    SessionInspection,
    SessionSummary,
    ValidationReport,
)


class FakeSdk:
    def __init__(self, version: str = "1.0", fail: bool = False) -> None:
        self.api_version = version
        self.fail = fail

    def discover_sessions(self, root: Path, cancellation: CancellationToken):
        cancellation.raise_if_cancelled()
        if self.fail:
            raise ValueError("模拟失败")
        return (SessionSummary("session-1", root / "session-1"),)

    def inspect_session(self, path: Path, cancellation: CancellationToken):
        return SessionInspection("session-1", "0", True, ())

    def validate_session(self, path: Path, cancellation: CancellationToken):
        return ValidationReport(valid=True)

    def build_copy_plan(self, path: Path, cancellation: CancellationToken):
        return SessionCopyPlan("session-1", "v0", (), "manifest.json")


class SdkGatewayTests(unittest.TestCase):
    def test_success_preserves_sdk_values(self) -> None:
        gateway = SdkGateway(FakeSdk())
        with tempfile.TemporaryDirectory() as directory:
            sessions = gateway.discover_sessions(Path(directory), CancellationToken())
        self.assertEqual(sessions[0].session_id, "session-1")

    def test_sdk_failure_has_operation_context(self) -> None:
        gateway = SdkGateway(FakeSdk(fail=True))
        with self.assertRaisesRegex(SdkOperationError, "发现会话失败"):
            gateway.discover_sessions(Path("/media"), CancellationToken())

    def test_cancelled_call_is_not_reported_as_sdk_failure(self) -> None:
        gateway = SdkGateway(FakeSdk())
        token = CancellationToken()
        token.cancel()
        with self.assertRaises(OperationCancelled):
            gateway.discover_sessions(Path("/media"), token)

    def test_incompatible_api_version_is_rejected_before_use(self) -> None:
        with self.assertRaisesRegex(SdkVersionError, "需要 1.x"):
            SdkGateway(FakeSdk(version="2.0"))

    def test_malformed_api_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(SdkVersionError, "无法识别"):
            SdkGateway(FakeSdk(version="unknown"))


class PipelineSdkClientTests(unittest.TestCase):
    def make_module(self):
        artifact = SimpleNamespace(path="left.bin", size_bytes=4, sha256="a" * 64)
        manifest = SimpleNamespace(
            session_id="session-1", format_version="v0", artifacts=(artifact,)
        )
        report = SimpleNamespace(valid=True, session_id="session-1", issues=())
        return SimpleNamespace(
            __version__="0.1.0",
            discover_sessions=lambda root: (root / "session-1",),
            validate_session=lambda path, verify_hashes: report,
            require_valid_session=lambda path, verify_hashes: manifest,
        )

    def test_public_pipeline_api_is_mapped_without_parsing_files(self) -> None:
        root = Path("/media/card")
        client = PipelineSdkClient(self.make_module())
        sessions = client.discover_sessions(root, CancellationToken())
        inspection = client.inspect_session(sessions[0].path, CancellationToken())
        report = client.validate_session(sessions[0].path, CancellationToken())
        self.assertEqual(sessions[0].session_id, "session-1")
        self.assertEqual(inspection.files[0].relative_path, "left.bin")
        self.assertTrue(report.valid)

    def test_incompatible_pipeline_package_is_rejected(self) -> None:
        module = self.make_module()
        module.__version__ = "0.2.0"
        with self.assertRaisesRegex(SdkVersionError, "需要 0.1.x"):
            PipelineSdkClient(module)

    def test_source_checkout_uses_its_declared_project_version(self) -> None:
        module = self.make_module()
        module.__version__ = "0+unknown"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "src" / "ylx_card_pipeline"
            package.mkdir(parents=True)
            module.__file__ = str(package / "__init__.py")
            (root / "pyproject.toml").write_text(
                """
[project]
name = "ylx-card-pipeline"
version = "0.1.0"
""".strip(),
                encoding="utf-8",
            )

            client = PipelineSdkClient(module)

        self.assertIsNotNone(client)

    def test_unknown_version_without_matching_project_metadata_is_rejected(
        self,
    ) -> None:
        module = self.make_module()
        module.__version__ = "0+unknown"
        with self.assertRaisesRegex(SdkVersionError, "无法识别"):
            PipelineSdkClient(module)

    def test_publication_plan_maps_exact_sdk_05_fields(self) -> None:
        module = self.make_module()
        objects = (
            SimpleNamespace(
                relative_path="session.json",
                source_path=Path("/media/session/session.json"),
                size_bytes=2,
                sha256="a" * 64,
                commit_marker=False,
            ),
            SimpleNamespace(
                relative_path="manifest.json",
                source_path=Path("/media/session/manifest.json"),
                size_bytes=2,
                sha256="b" * 64,
                commit_marker=True,
            ),
        )
        module.build_publication_plan = lambda path: SimpleNamespace(
            session_id="session-1", objects=objects
        )
        plan = PipelineSdkClient(module).build_copy_plan(
            Path("/media/session"), CancellationToken()
        )
        self.assertEqual(plan.commit_last, "manifest.json")
        self.assertEqual(plan.files[-1].relative_path, "manifest.json")
        self.assertIsNone(plan.files[-1].inline_content)


if __name__ == "__main__":
    unittest.main()
