from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .application import Application
from .publications import PublicationError
from .script_publication import ScriptPublicationRequest, publish_s3_session
from .server import create_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ylx-transfer",
        description="YLX 录制数据导入与传输应用",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="启动本地应用")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8765, type=int)
    serve.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    serve.add_argument(
        "--data-dir",
        type=Path,
        default=Path(
            os.environ.get(
                "YLX_TRANSFER_DATA_DIR",
                Path.home() / ".local" / "share" / "ylx-transfer",
            )
        ),
        help="应用状态与本地仓库目录",
    )
    serve.add_argument(
        "--media-root",
        action="append",
        type=Path,
        dest="media_roots",
        help="允许扫描的介质根目录，可重复指定",
    )

    doctor = subparsers.add_parser("doctor", help="检查应用运行环境")
    doctor.add_argument("--json", action="store_true", dest="as_json")

    publish_s3 = subparsers.add_parser(
        "publish-s3", help="从只读介质脚本幂等发布会话到 S3 对象存储"
    )
    publish_s3.add_argument("session", type=Path, help="Device Session v1 会话目录")
    publish_s3.add_argument("--bucket", required=True)
    publish_s3.add_argument("--raw-prefix", required=True)
    publish_s3.add_argument("--endpoint", required=True, dest="endpoint_url")
    publish_s3.add_argument("--region", dest="region_name")
    publish_s3.add_argument("--credential-ref", required=True)
    publish_s3.add_argument("--ca-bundle", type=Path)
    publish_s3.add_argument("--checkpoint", required=True, type=Path)
    publish_s3.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        result = {
            "ok": sys.version_info >= (3, 11),
            "python": ".".join(map(str, sys.version_info[:3])),
            "version": __version__,
        }
        if args.as_json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            print("环境正常" if result["ok"] else "需要 Python 3.11 或更高版本")
        return 0 if result["ok"] else 1

    if args.command == "publish-s3":
        try:
            result = publish_s3_session(
                ScriptPublicationRequest(
                    session=args.session,
                    bucket=args.bucket,
                    raw_prefix=args.raw_prefix,
                    endpoint_url=args.endpoint_url,
                    region_name=args.region_name,
                    credential_ref=args.credential_ref,
                    tls_verify=(str(args.ca_bundle) if args.ca_bundle else True),
                    checkpoint=args.checkpoint,
                )
            )
        except (OSError, TypeError, ValueError, KeyError, PublicationError) as error:
            if isinstance(error, PublicationError):
                code = "publication_failed"
            elif isinstance(error, OSError):
                code = "io_error"
            else:
                code = "invalid_request"
            payload = {
                "ok": False,
                "operation": "publish-s3",
                "error": {"code": code, "message": str(error)},
            }
            if args.as_json:
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            else:
                print(f"发布失败：{error}", file=sys.stderr)
            return 1
        payload = {"ok": True, "operation": "publish-s3", **result.as_dict()}
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"发布完成：{result.publication_key}")
        return 0

    media_roots = tuple(args.media_roots or _default_media_roots())
    application = Application(args.data_dir, media_roots=media_roots)
    server = create_server(args.host, args.port, application)
    address, port = server.server_address[:2]
    url = f"http://{address}:{port}"
    print(f"ylx-transfer 已启动：{url}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        application.close()
    return 0


def _default_media_roots() -> tuple[Path, ...]:
    candidates = (Path("/media"), Path("/run/media"), Path("/Volumes"))
    existing = tuple(path for path in candidates if path.is_dir())
    return existing or (Path.cwd(),)
