from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.request

from ylx_transfer.cli import main
from ylx_transfer.runtime import BackgroundExecutor, OperationCancelled
from ylx_transfer.server import create_server


class BaselineTests(unittest.TestCase):
    def test_doctor_reports_supported_runtime(self) -> None:
        self.assertEqual(main(["doctor", "--json"]), 0)

    def test_health_endpoint_and_index_start(self) -> None:
        server = create_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/health"
            ) as response:
                body = json.load(response)
            self.assertEqual(body["status"], "ok")
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as response:
                page = response.read().decode("utf-8")
            self.assertIn("YLX 传输", page)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_background_operation_can_be_cancelled(self) -> None:
        started = threading.Event()

        def operation(token):
            started.set()
            while True:
                token.raise_if_cancelled()
                time.sleep(0.005)

        with BackgroundExecutor(max_workers=1) as executor:
            handle = executor.submit(operation)
            self.assertTrue(started.wait(1))
            handle.cancel()
            with self.assertRaises(OperationCancelled):
                handle.future.result(timeout=1)


if __name__ == "__main__":
    unittest.main()
