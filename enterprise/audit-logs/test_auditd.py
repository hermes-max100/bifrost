#!/usr/bin/env python3
"""Unit tests for auditd.py -- chain integrity, checkpoints, tamper
detection, metrics parsing, and proxy forwarding against a fake upstream.
Stdlib only: python3 -m unittest test_auditd -v
"""
import copy
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auditd
from auditd import AuditLog, verify_chain, parse_metrics, entry_hash, canonical


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmp, "audit.jsonl")
        self.cp_dir = os.path.join(self.tmp, "checkpoints")
        self.log = AuditLog(self.log_path, self.cp_dir, checkpoint_every=3)

    def test_append_and_verify(self):
        for i in range(5):
            e = self.log.append({"type": "t", "i": i})
            self.assertEqual(e["seq"], i + 1)
        ok, checked, failures = verify_chain(self.log_path, self.cp_dir)
        self.assertTrue(ok, failures)
        self.assertEqual(checked, 5)

    def test_checkpoint_files_match_chain(self):
        for i in range(6):  # checkpoints at seq 3 and 6
            self.log.append({"type": "t", "i": i})
        names = sorted(os.listdir(self.cp_dir))
        self.assertIn("checkpoint-3.json", names)
        self.assertIn("checkpoint-6.json", names)
        with open(os.path.join(self.cp_dir, "checkpoint-6.json")) as f:
            cp = json.load(f)
        self.assertEqual(cp["head_hash"], self.log.head()["head_hash"])
        ok, _, failures = verify_chain(self.log_path, self.cp_dir)
        self.assertTrue(ok, failures)

    def test_tamper_body_detected(self):
        for i in range(3):
            self.log.append({"type": "t", "i": i})
        lines = open(self.log_path).read().splitlines()
        entry = json.loads(lines[1])
        entry["i"] = 999  # modify a sealed field, keep old hash
        lines[1] = canonical(entry)
        open(self.log_path, "w").write("\n".join(lines) + "\n")
        ok, _, failures = verify_chain(self.log_path, self.cp_dir)
        self.assertFalse(ok)
        self.assertTrue(any("entry_hash mismatch" in f for f in failures))

    def test_tamper_delete_detected(self):
        for i in range(4):
            self.log.append({"type": "t", "i": i})
        lines = open(self.log_path).read().splitlines()
        del lines[1]  # delete entry seq 2
        open(self.log_path, "w").write("\n".join(lines) + "\n")
        ok, _, failures = verify_chain(self.log_path, self.cp_dir)
        self.assertFalse(ok)
        self.assertTrue(any("seq" in f or "prev_hash" in f for f in failures))

    def test_tamper_reorder_detected(self):
        for i in range(3):
            self.log.append({"type": "t", "i": i})
        lines = open(self.log_path).read().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        open(self.log_path, "w").write("\n".join(lines) + "\n")
        ok, _, failures = verify_chain(self.log_path, self.cp_dir)
        self.assertFalse(ok)

    def test_hash_deterministic(self):
        body = {"a": 1, "b": "x"}
        self.assertEqual(entry_hash("0" * 64, body), entry_hash("0" * 64, body))
        self.assertNotEqual(
            entry_hash("0" * 64, body), entry_hash("1" * 64, body)
        )

    def test_recover_resumes_chain(self):
        for i in range(3):
            self.log.append({"type": "t", "i": i})
        head = self.log.head()
        log2 = AuditLog(self.log_path, self.cp_dir, checkpoint_every=3)
        self.assertEqual(log2.head(), head)
        e = log2.append({"type": "t", "i": 3})
        self.assertEqual(e["seq"], 4)
        self.assertEqual(e["prev_hash"], head["head_hash"])
        ok, _, failures = verify_chain(self.log_path, self.cp_dir)
        self.assertTrue(ok, failures)


class MetricsTests(unittest.TestCase):
    def test_parse(self):
        text = (
            '# HELP bifrost_input_tokens_total x\n'
            '# TYPE bifrost_input_tokens_total counter\n'
            'bifrost_input_tokens_total{method="chat_completion",model="qwen/qwen3.8-27b",'
            'provider="groq",selected_key_name="groq-1"} 123\n'
            'bifrost_input_tokens_total{method="list_models",model="",provider=""} 5\n'
            'bifrost_cost_total{method="chat_completion",model="qwen/qwen3.8-27b",'
            'provider="groq"} 0.007\n'
        )
        out = parse_metrics(text)
        self.assertEqual(out[("input_tokens_total", "groq", "qwen/qwen3.8-27b")], 123)
        self.assertEqual(out[("cost_total", "groq", "qwen/qwen3.8-27b")], 0.007)
        self.assertEqual(len(out), 2)  # list_models excluded


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fake upstream Bifrost: echoes model + usage.
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n) if n else b""
                try:
                    model = json.loads(body).get("model")
                except Exception:
                    model = None
                resp = json.dumps({
                    "id": "chatcmpl-test", "object": "chat.completion",
                    "model": model,
                    "choices": [{"message": {"role": "assistant", "content": "hi"}}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 2,
                              "total_tokens": 7},
                    "extra_fields": {"routing_info": {
                        "provider": "groq", "model": model, "key": "groq-1",
                        "requested_provider": "groq",
                        "requested_model": model,
                        "resolved_model_used": model, "latency": 42}},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.up_port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

        cls.tmp = tempfile.mkdtemp()
        cfg = dict(auditd.DEFAULT_CONFIG)
        cfg.update({
            "listen_host": "127.0.0.1", "listen_port": 0,
            "upstream_host": "127.0.0.1", "upstream_port": cls.up_port,
            "data_dir": cls.tmp, "metrics_interval_s": 3600,
        })
        cls.service = auditd.AuditService(cfg)
        handler = auditd.make_handler(cls.service)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    def test_proxied_completion_is_audited(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/chat/completions",
            data=json.dumps({
                "model": "groq/qwen/qwen3.8-27b",
                "messages": [{"role": "user", "content": "hi"}],
            }).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer SECRET-DO-NOT-LOG"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
        self.assertEqual(data["choices"][0]["message"]["content"], "hi")
        entries = auditd.tail_entries(
            os.path.join(self.tmp, "audit.jsonl"), 5
        )
        prox = [e for e in entries if e.get("type") == "proxy_request"]
        self.assertEqual(len(prox), 1)
        e = prox[0]
        self.assertEqual(e["model"], "groq/qwen/qwen3.8-27b")
        self.assertEqual(e["provider"], "groq")
        self.assertEqual(e["status"], 200)
        self.assertEqual(e["usage"]["total_tokens"], 7)
        self.assertEqual(e["routing_decision"]["selected_key"], "groq-1")
        self.assertEqual(e["routing_decision"]["upstream_latency_ms"], 42)
        self.assertEqual(e["client_fp"], hashlib.sha256(
            b"Bearer SECRET-DO-NOT-LOG").hexdigest()[:16])
        self.assertNotIn("SECRET-DO-NOT-LOG", json.dumps(entries))
        ok, _, failures = verify_chain(
            os.path.join(self.tmp, "audit.jsonl"),
            os.path.join(self.tmp, "checkpoints"),
        )
        self.assertTrue(ok, failures)

    def test_tailer_dedupes_replayed_request_ids(self):
        line = json.dumps({
            "level": "info", "message": "request completed",
            "http.method": "POST", "http.target": "/v1/chat/completions",
            "http.status_code": 200, "http.request_duration_ms": 123,
            "http.remote_addr": "100.83.164.96:55555",
            "http.user_agent": "test", "trace_id": "t1",
            "request_id": "dedup-test-id-1", "time": "2026-11-20T09:00:00Z",
        })
        before = self.service.log.head()["seq"]
        self.service._handle_log_line(line)
        self.service._handle_log_line(line)  # replayed by docker logs restart
        after = self.service.log.head()["seq"]
        self.assertEqual(after - before, 1)

    def test_status_endpoint(self):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}/audit/status", timeout=10
        ) as resp:
            data = json.load(resp)
        self.assertEqual(data["service"], "bifrost-audit")
        self.assertGreaterEqual(data["head_seq"], 1)

    def test_verify_endpoint(self):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}/audit/verify", timeout=10
        ) as resp:
            data = json.load(resp)
        self.assertTrue(data["ok"])


if __name__ == "__main__":
    unittest.main()
