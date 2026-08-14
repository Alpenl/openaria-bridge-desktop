from __future__ import annotations

import sys
from pathlib import Path

from ylx_transfer.application import Application


class UnavailableSdk:
    api_version = "1.0"

    def discover_sessions(self, root, cancellation):
        return ()

    def build_copy_plan(self, path, cancellation):
        raise RuntimeError("LAN import does not use the media SDK")

    def validate_session(self, path, cancellation):
        raise RuntimeError("LAN import validates the Device Session contract")

    def inspect_session(self, path, cancellation):
        raise RuntimeError("LAN import does not inspect media sessions")


def main() -> int:
    data_dir, media_root, task_id = sys.argv[1:]
    application = Application(
        Path(data_dir),
        media_roots=(Path(media_root),),
        sdk_client=UnavailableSdk(),
        auto_start=False,
    )
    application.import_service.run(task_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
