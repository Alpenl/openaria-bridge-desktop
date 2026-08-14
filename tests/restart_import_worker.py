from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

from ylx_transfer.application import Application
from ylx_transfer.sdk import SessionCopyPlan, SessionFile, ValidationReport


class RestartImportSdk:
    api_version = "1.0"

    def __init__(self, source: Path) -> None:
        files = []
        for relative_path in ("session.json", "streams/data.bin", "manifest.json"):
            content = source.joinpath(*relative_path.split("/")).read_bytes()
            files.append(
                SessionFile(
                    relative_path,
                    len(content),
                    hashlib.sha256(content).hexdigest(),
                )
            )
        self.plan = SessionCopyPlan("session-1", "test", tuple(files), "manifest.json")

    def build_copy_plan(self, path, cancellation):
        cancellation.raise_if_cancelled()
        return self.plan

    def validate_session(self, path, cancellation):
        cancellation.raise_if_cancelled()
        errors = []
        for item in self.plan.files:
            candidate = path.joinpath(*item.relative_path.split("/"))
            if not candidate.is_file():
                errors.append(f"missing {item.relative_path}")
            elif hashlib.sha256(candidate.read_bytes()).hexdigest() != item.sha256:
                errors.append(f"digest mismatch {item.relative_path}")
        if path.name != self.plan.session_id:
            errors.append("session directory mismatch")
        return ValidationReport(valid=not errors, errors=tuple(errors))

    def discover_sessions(self, root, cancellation):
        return ()

    def inspect_session(self, path, cancellation):
        raise NotImplementedError


def main() -> int:
    data_dir, media_root, source, task_id, ready_path = map(Path, sys.argv[1:])
    application = Application(
        data_dir,
        media_roots=(media_root,),
        sdk_client=RestartImportSdk(source),
        auto_start=False,
    )

    def stop_after_copy(stage: str) -> None:
        if stage == "copied":
            ready_path.write_text("copied", encoding="utf-8")
            while True:
                time.sleep(60)

    application.import_service.run(str(task_id), stage_hook=stop_after_copy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
