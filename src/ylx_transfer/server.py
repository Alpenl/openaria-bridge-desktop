from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from . import __version__

_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}


class ApiBackend(Protocol):
    def health(self) -> dict[str, Any]: ...

    def snapshot(self) -> dict[str, Any]: ...

    def connect_device(self, value: str | dict[str, Any]) -> dict[str, Any]: ...

    def scan_media(self, path: str) -> dict[str, Any]: ...

    def enqueue_import(self, record_id: str) -> dict[str, Any]: ...

    def enqueue_transfer(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def enqueue_publication(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def task_action(self, task_id: str, action: str) -> dict[str, Any]: ...


class BasicBackend:
    def health(self) -> dict[str, Any]:
        return {"status": "ok", "sdk": "unavailable", "sdk_error": None}

    def snapshot(self) -> dict[str, Any]:
        return {"sources": [], "sessions": [], "local_sessions": [], "tasks": []}


def _handler_for(backend: ApiBackend):
    class AppRequestHandler(BaseHTTPRequestHandler):
        server_version = "ylx-transfer"

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/api/health":
                self._send_json(
                    {
                        **backend.health(),
                        "version": __version__,
                        "service": "ylx-transfer",
                    }
                )
                return
            if path == "/api/state":
                self._send_json(backend.snapshot())
                return
            self._send_asset(path)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            try:
                payload = self._read_json()
                if path == "/api/sources/device":
                    result = backend.connect_device(payload)
                elif path == "/api/sources/media":
                    result = backend.scan_media(str(payload["path"]))
                elif path == "/api/imports":
                    result = backend.enqueue_import(
                        str(payload["source_session_record_id"])
                    )
                elif path == "/api/transfers":
                    result = backend.enqueue_transfer(payload)
                elif path == "/api/publications":
                    result = backend.enqueue_publication(payload)
                elif path.startswith("/api/tasks/"):
                    parts = path.strip("/").split("/")
                    if len(parts) != 4:
                        raise KeyError(path)
                    result = backend.task_action(parts[2], parts[3])
                else:
                    raise KeyError(path)
                self._send_json(result, HTTPStatus.ACCEPTED)
            except KeyError as exc:
                self._send_error_json(
                    HTTPStatus.NOT_FOUND,
                    "NOT_FOUND",
                    f"资源或请求字段不存在：{exc}",
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                self._send_error_json(
                    HTTPStatus.BAD_REQUEST,
                    type(exc).__name__.upper(),
                    str(exc),
                )
            except Exception:  # noqa: BLE001 - HTTP error isolation boundary
                self._send_error_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "请求处理失败，请查看本地诊断信息",
                )

        def _read_json(self) -> dict[str, Any]:
            if self.headers.get_content_type() != "application/json":
                raise ValueError("请求内容类型必须是 application/json")
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 1024 * 1024:
                raise ValueError("请求正文大小不合法")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise TypeError("请求正文必须是 JSON 对象")
            return value

        def _send_asset(self, path: str) -> None:
            asset = "index.html" if path in {"/", "/index.html"} else path[1:]
            if asset not in {"index.html", "styles.css", "app.js"}:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            resource = files("ylx_transfer").joinpath("static", asset)
            payload = resource.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", _CONTENT_TYPES[Path(asset).suffix])
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _send_json(
            self, value: dict[str, Any], status: HTTPStatus = HTTPStatus.OK
        ) -> None:
            payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _send_error_json(self, status: HTTPStatus, code: str, message: str) -> None:
            self._send_json(
                {"error": {"code": code, "message": message, "retryable": False}},
                status,
            )

        def log_message(self, format: str, *args: object) -> None:
            return

    return AppRequestHandler


def create_server(
    host: str, port: int, backend: ApiBackend | None = None
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _handler_for(backend or BasicBackend()))
