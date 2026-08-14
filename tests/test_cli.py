from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ylx_transfer import cli
from ylx_transfer.script_publication import ScriptPublicationResult


class PublishS3CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self) -> list[str]:
        return [
            "publish-s3",
            str(self.root / "session"),
            "--bucket",
            "production-bucket",
            "--raw-prefix",
            "recordings/",
            "--endpoint",
            "https://objects.example.test",
            "--region",
            "cn-test-1",
            "--credential-ref",
            "qa-script",
            "--checkpoint",
            str(self.root / "state.json"),
            "--json",
        ]

    def test_publish_s3_emits_stable_json_success(self) -> None:
        result = ScriptPublicationResult(
            publication_id="publication-id",
            publication_key="recordings/device/session/__ylx_evidence__/publication.json",
            source_session_id="session-id",
            source_manifest_sha256="a" * 64,
            publication_sha256="b" * 64,
            objects=7,
            uploaded=("object",),
            reused=(),
            readback=True,
            checkpoint=str(self.root / "state.json"),
        )
        output = io.StringIO()
        with (
            patch.object(cli, "publish_s3_session", return_value=result),
            redirect_stdout(output),
        ):
            exit_code = cli.main(self.arguments())

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["operation"], "publish-s3")
        self.assertTrue(payload["readback"])

    def test_publish_s3_emits_stable_json_failure(self) -> None:
        output = io.StringIO()
        error = io.StringIO()
        with (
            patch.object(
                cli, "publish_s3_session", side_effect=ValueError("invalid target")
            ),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            exit_code = cli.main(self.arguments())

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["operation"], "publish-s3")
        self.assertEqual(payload["error"]["code"], "invalid_request")
        self.assertEqual(error.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
