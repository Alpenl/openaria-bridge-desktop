"""测量 SDK 三种进程边界；仅用于 TR-01 决策，不参与生产运行。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from statistics import median

Payload = dict[str, object]


def operation(payload: Payload) -> Payload:
    return {"ok": True, "session_id": payload["session_id"]}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        body = json.dumps(operation(payload)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def in_process(payload: Payload) -> Payload:
    return operation(payload)


def subprocess_call(payload: Payload) -> Payload:
    code = (
        "import json,sys; p=json.load(sys.stdin); "
        "json.dump({'ok': True, 'session_id': p['session_id']}, sys.stdout)"
    )
    process = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(process.stdout)


def service_call(url: str, payload: Payload) -> Payload:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.load(response)


def measure(call: Callable[[Payload], Payload], iterations: int) -> float:
    samples = []
    for index in range(iterations):
        started = time.perf_counter_ns()
        result = call({"session_id": f"session-{index}"})
        if not result["ok"]:
            raise RuntimeError("原型调用失败")
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return round(median(samples), 3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = {
            "iterations": args.iterations,
            "median_ms": {
                "in_process": measure(in_process, args.iterations),
                "subprocess": measure(subprocess_call, args.iterations),
                "local_service": measure(
                    lambda payload: service_call(url, payload), args.iterations
                ),
            },
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
