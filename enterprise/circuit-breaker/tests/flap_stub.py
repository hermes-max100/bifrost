#!/usr/bin/env python3
"""Test stub for bifrost-breaker live tests. NOT part of the service.

Listens on 127.0.0.1:18099. Behavior is driven by the mode file
/tmp/breaker-test-mode, which the test script flips between:

    fail  -> POST /v1/chat/completions returns HTTP 500
    ok    -> POST /v1/chat/completions returns a canned 200 completion
    slow  -> sleeps 5s, then returns 200 (breaker timeout is 2s for test-slow)

GET /health always returns 200. Only used during testing; never in production.
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE_FILE = "/tmp/breaker-test-mode"


def mode():
    try:
        with open(MODE_FILE) as f:
            return f.read().strip()
    except OSError:
        return "fail"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "mode": mode()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        m = mode()
        if m == "slow":
            time.sleep(5)
            self._json(200, {"choices": [{"message": {"content": "SLOW-OK"}}]})
        elif m == "ok":
            self._json(200, {"choices": [{"message": {"content": "STUB-OK"}}],
                        "model": "test/flap", "usage": {"total_tokens": 3}})
        else:
            self._json(500, {"error": {"message": "stub failure (mode=fail)"}})


if __name__ == "__main__":
    print("test stub on 127.0.0.1:18099, mode file", MODE_FILE, flush=True)
    ThreadingHTTPServer(("127.0.0.1", 18099), H).serve_forever()
