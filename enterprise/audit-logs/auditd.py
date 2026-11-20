#!/usr/bin/env python3
"""
bifrost-audit -- immutable audit logs for the Bifrost gateway (own code).

Clean-room rebuild of the "immutable audit log" enterprise capability for
the hermes-max100/bifrost deployment. Written from observed Bifrost
behaviour (its /health, /v1/models, /metrics, and JSON container logs) and
from first principles. No Bifrost Enterprise code was available or used,
and none is copied here: this is a standalone service that sits beside the
stock OSS gateway.

What it does
------------
1. PROXY (audited request path): an HTTP reverse proxy on its own port
   that forwards OpenAI-compatible traffic to Bifrost unchanged and
   records one hash-chained audit entry per request: who (fingerprint of
   the credential, never the credential itself), what model/provider,
   when, outcome (status), latency, token usage when the upstream
   reports it, and the routing/guardrail decision context.
2. TAILER (complete coverage): follows `docker logs -f bifrost` and
   records every request Bifrost itself logs as completed -- including
   traffic that bypasses the proxy -- so no gateway request goes
   unrecorded. Bifrost's container logs carry no model, so tailer
   entries record model as null and say so explicitly.
3. METRICS SNAPSHOTTER: polls /metrics and records per-(provider, model)
   token/cost/error counter deltas as aggregate entries, so per-model
   totals exist in the chain even for direct traffic.
4. HASH CHAIN: every entry is chained to the previous entry's SHA-256
   hash. Checkpoints are written every N entries and on demand.
   `auditd.py verify` re-walks the whole chain and fails loudly on any
   modification, deletion, or reordering.

Immutability model: append-only file, O_APPEND writes + fsync per entry,
single-writer lock inside the process. Tampering is DETECTED (the chain
fails verification), not physically prevented against root -- that is the
honest guarantee, and the verify command is the proof.

Privacy: provider API keys and client credentials are NEVER stored.
Only a truncated SHA-256 fingerprint of an Authorization header is kept.
Prompt/completion TEXT is never logged -- only token counts when the
upstream reports them.

Usage
-----
  auditd.py serve [--config auditd.json]   run proxy + tailer + snapshots
  auditd.py verify --log <audit.jsonl>     verify a chain (exit 0/1)
  auditd.py tail --log <audit.jsonl>        print last entries
  auditd.py checkpoint --log <audit.jsonl>  force a checkpoint

Config (JSON, all optional): listen_host, listen_port, upstream_host,
upstream_port, data_dir, log_file, checkpoint_every, metrics_interval_s,
model_map_refresh_s.
"""

import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.0.0"
GENESIS_PREV = "0" * 64
DEFAULT_CONFIG = {
    "listen_host": "100.83.164.96",
    "listen_port": 8090,
    "upstream_host": "100.83.164.96",
    "upstream_port": 8081,
    "data_dir": "/var/lib/bifrost-audit",
    "log_file": "audit.jsonl",
    "checkpoint_every": 100,
    "metrics_interval_s": 60,
    "model_map_refresh_s": 300,
    "upstream_timeout_s": 300,
}

# ---------------------------------------------------------------------------
# Hash chain
# ---------------------------------------------------------------------------

def canonical(obj):
    """Deterministic JSON encoding used for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(prev_hash, entry_without_hash):
    """SHA-256 over prev_hash + canonical entry body."""
    payload = prev_hash + "\n" + canonical(entry_without_hash)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Append-only, hash-chained JSONL log. Single writer; thread-safe."""

    def __init__(self, path, checkpoint_dir, checkpoint_every=100):
        self.path = path
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_every = checkpoint_every
        self.lock = threading.Lock()
        self.seq = 0
        self.head_hash = GENESIS_PREV
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.makedirs(checkpoint_dir, exist_ok=True)
        self._recover()

    def _recover(self):
        """Rebuild seq/head from an existing log file (read-only scan)."""
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.seq = max(self.seq, int(entry.get("seq", 0)))
                self.head_hash = entry.get("entry_hash", self.head_hash)

    def append(self, entry):
        """Chain and durably append one entry. Returns the sealed entry."""
        with self.lock:
            body = dict(entry)
            body["seq"] = self.seq + 1
            body["ts"] = utcnow()
            body["prev_hash"] = self.head_hash
            sealed_hash = entry_hash(self.head_hash, body)
            body["entry_hash"] = sealed_hash
            line = canonical(body) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            self.seq = body["seq"]
            self.head_hash = sealed_hash
            if self.seq % self.checkpoint_every == 0:
                self._write_checkpoint_locked()
            return body

    def _write_checkpoint_locked(self):
        cp = {
            "seq": self.seq,
            "head_hash": self.head_hash,
            "ts": utcnow(),
            "log_file": os.path.basename(self.path),
            "entries": self.seq,
        }
        tmp = os.path.join(self.checkpoint_dir, f".checkpoint-{self.seq}.tmp")
        final = os.path.join(self.checkpoint_dir, f"checkpoint-{self.seq}.json")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(canonical(cp) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
        latest = os.path.join(self.checkpoint_dir, "latest.json")
        with open(latest, "w", encoding="utf-8") as f:
            f.write(canonical(cp) + "\n")
        return cp

    def checkpoint(self):
        with self.lock:
            return self._write_checkpoint_locked()

    def head(self):
        with self.lock:
            return {"seq": self.seq, "head_hash": self.head_hash}


def verify_chain(path, checkpoint_dir=None):
    """Re-walk a log file and recompute every hash.

    Returns (ok, checked, failures) where failures is a list of strings.
    Checks: seq continuity from 1, prev_hash linkage, entry_hash
    recomputation, and (when checkpoint_dir is given) that every
    checkpoint file's head_hash matches the entry at that seq.
    """
    failures = []
    checked = 0
    prev = GENESIS_PREV
    expected_seq = 1
    heads = {}
    if not os.path.exists(path):
        return False, 0, [f"log file not found: {path}"]
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                failures.append(f"line {lineno}: not valid JSON ({e})")
                continue
            checked += 1
            seq = entry.get("seq")
            if seq != expected_seq:
                failures.append(
                    f"line {lineno}: seq {seq} != expected {expected_seq} "
                    f"(gap / deletion / reorder)"
                )
            if entry.get("prev_hash") != prev:
                failures.append(
                    f"line {lineno} (seq {seq}): prev_hash mismatch -- "
                    f"chain broken here (entry modified, inserted, or removed)"
                )
            sealed = entry.get("entry_hash")
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            if sealed != entry_hash(entry.get("prev_hash", ""), body):
                failures.append(
                    f"line {lineno} (seq {seq}): entry_hash mismatch -- "
                    f"entry contents were modified after sealing"
                )
            heads[seq] = sealed
            prev = sealed if isinstance(sealed, str) else prev
            expected_seq = (seq + 1) if isinstance(seq, int) else expected_seq + 1
    if checkpoint_dir and os.path.isdir(checkpoint_dir):
        for name in sorted(os.listdir(checkpoint_dir)):
            if not (name.startswith("checkpoint-") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(checkpoint_dir, name), encoding="utf-8") as f:
                    cp = json.load(f)
                cp_seq, cp_hash = cp.get("seq"), cp.get("head_hash")
                if heads.get(cp_seq) != cp_hash:
                    failures.append(
                        f"checkpoint {name}: head_hash {cp_hash} does not match "
                        f"log entry {cp_seq} ({heads.get(cp_seq)})"
                    )
            except (json.JSONDecodeError, OSError) as e:
                failures.append(f"checkpoint {name}: unreadable ({e})")
    return (not failures), checked, failures


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fingerprint(value):
    """Truncated SHA-256 fingerprint of a credential. Never store the value."""
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def provider_of_model(model, model_map):
    """Provider from a model id. Bifrost ids are '<provider>/<model>' for
    groq/nim; other providers use bare names resolved via the live map."""
    if not model:
        return None
    if "/" in model:
        return model.split("/", 1)[0]
    return model_map.get(model)


METRIC_RE = re.compile(
    r"^bifrost_(input_tokens_total|output_tokens_total|cost_total|"
    r"error_requests_total|requests_total)\{([^}]*)\}\s+([0-9.eE+-]+)$"
)
LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_metrics(text):
    """Parse Bifrost Prometheus text into {(metric, provider, model): value}."""
    out = {}
    for line in text.splitlines():
        m = METRIC_RE.match(line.strip())
        if not m:
            continue
        metric, labels_raw, value = m.groups()
        labels = dict(LABEL_RE.findall(labels_raw))
        provider = labels.get("provider", "")
        model = labels.get("model", "")
        if labels.get("method") != "chat_completion":
            continue
        try:
            out[(metric, provider, model)] = float(value)
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class AuditService:
    def __init__(self, config):
        self.cfg = config
        data_dir = config["data_dir"]
        log_path = os.path.join(data_dir, config["log_file"])
        self.log = AuditLog(
            log_path,
            os.path.join(data_dir, "checkpoints"),
            checkpoint_every=config["checkpoint_every"],
        )
        self.started_at = time.time()
        self.model_map = {}          # model id -> provider
        self.model_map_lock = threading.Lock()
        self.recent_proxy_ports = {}  # upstream src port -> (seq, ts, method, path, status)
        self.ports_lock = threading.Lock()
        self.metrics_prev = None
        self._stop = threading.Event()
        # Request ids already in the chain (loaded at startup) so a tailer
        # restart -- docker logs replays the last minute -- cannot record
        # the same Bifrost request twice.
        self.seen_request_ids = self._load_seen_request_ids()

    def _load_seen_request_ids(self):
        seen = set()
        path = os.path.join(self.cfg["data_dir"], self.cfg["log_file"])
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rid = e.get("bifrost_request_id")
                    if rid:
                        seen.add(rid)
        return seen

    # -- model map ---------------------------------------------------------
    def refresh_model_map(self):
        """Build model->provider from live /v1/models, falling back to the
        read-only Bifrost config's model lists (names only, never keys)."""
        new_map = {}
        try:
            req = urllib.request.Request(
                f"http://{self.cfg['upstream_host']}:{self.cfg['upstream_port']}/v1/models",
                headers={"User-Agent": "bifrost-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
            for item in data.get("data", []):
                mid = item.get("id", "")
                if mid:
                    new_map[mid] = mid.split("/", 1)[0] if "/" in mid else "unknown"
        except Exception as e:
            self._note("model_map_live_failed", {"error": str(e)[:200]})
        if not new_map:
            try:
                with open("/etc/bifrost/config.json", encoding="utf-8") as f:
                    cfg = json.load(f)
                for provider, pdata in cfg.get("providers", {}).items():
                    for key in pdata.get("keys", []):
                        for model in key.get("models", []):
                            new_map.setdefault(model, provider)
            except Exception as e:
                self._note("model_map_config_failed", {"error": str(e)[:200]})
        if new_map:
            with self.model_map_lock:
                self.model_map = new_map

    def _model_map_loop(self):
        while not self._stop.wait(0):
            self.refresh_model_map()
            self._stop.wait(self.cfg["model_map_refresh_s"])

    # -- internal notes ----------------------------------------------------
    def _note(self, kind, fields):
        try:
            self.log.append({"type": "service_event", "event": kind, **fields})
        except Exception:
            pass

    # -- proxy -------------------------------------------------------------
    def record_proxy(self, fields):
        return self.log.append({"type": "proxy_request", "source": "proxy", **fields})

    def record_tailer(self, fields):
        return self.log.append({"type": "gateway_request", "source": "tailer", **fields})

    def remember_proxy_port(self, port, seq, method, path, status):
        with self.ports_lock:
            now = time.time()
            self.recent_proxy_ports = {
                p: v for p, v in self.recent_proxy_ports.items() if now - v[1] < 120
            }
            self.recent_proxy_ports[port] = (seq, now, method, path, status)

    def match_proxy_port(self, port):
        with self.ports_lock:
            now = time.time()
            hit = self.recent_proxy_ports.get(port)
            if hit and now - hit[1] < 120:
                return hit
            return None

    # -- metrics snapshots -------------------------------------------------
    def metrics_snapshot_once(self):
        try:
            req = urllib.request.Request(
                f"http://{self.cfg['upstream_host']}:{self.cfg['upstream_port']}/metrics",
                headers={"User-Agent": "bifrost-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                current = parse_metrics(resp.read().decode("utf-8", "replace"))
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}
        deltas = {}
        if self.metrics_prev is not None:
            keys = set(current) | set(self.metrics_prev)
            for (metric, provider, model) in sorted(keys):
                d = current.get((metric, provider, model), 0.0) - self.metrics_prev.get(
                    (metric, provider, model), 0.0
                )
                if d:
                    deltas[f"{metric}|{provider}|{model}"] = d
        self.metrics_prev = current
        entry = self.log.append(
            {
                "type": "metrics_snapshot",
                "source": "metrics",
                "totals": {f"{m}|{p}|{mo}": v for (m, p, mo), v in sorted(current.items())},
                "deltas_since_last_snapshot": deltas,
            }
        )
        return {"ok": True, "seq": entry["seq"], "delta_keys": len(deltas)}

    def _metrics_loop(self):
        while not self._stop.wait(self.cfg["metrics_interval_s"]):
            self.metrics_snapshot_once()

    # -- docker log tailer -------------------------------------------------
    def tailer_loop(self):
        """Follow Bifrost container logs; record every completed request."""
        backoff = 5
        while not self._stop.is_set():
            proc = None
            try:
                proc = subprocess.Popen(
                    ["docker", "logs", "-f", "--since", "1m", "bifrost"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                for line in proc.stdout:
                    if self._stop.is_set():
                        break
                    self._handle_log_line(line.strip())
                backoff = 5
            except Exception as e:
                self._note("tailer_error", {"error": str(e)[:200]})
            finally:
                if proc is not None:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
            if not self._stop.wait(backoff):
                backoff = min(backoff * 2, 60)

    def _handle_log_line(self, line):
        if not line:
            return
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return
        if rec.get("message") != "request completed":
            return
        rid = rec.get("request_id")
        if rid:
            # Skip Bifrost requests already in the chain (tailer restart
            # replays `docker logs --since 1m`; same request twice would
            # double-count the audit).
            with self.ports_lock:
                if rid in self.seen_request_ids:
                    return
                self.seen_request_ids.add(rid)
        remote = rec.get("http.remote_addr", "") or ""
        src_port = None
        if ":" in remote:
            try:
                src_port = int(remote.rsplit(":", 1)[1])
            except ValueError:
                src_port = None
        correlated_seq = None
        if src_port is not None:
            # The proxy records its upstream port just AFTER Bifrost logs
            # completion, so a first lookup can race it. Poll briefly.
            hit = self.match_proxy_port(src_port)
            for _ in range(10):
                if hit:
                    break
                time.sleep(0.1)
                hit = self.match_proxy_port(src_port)
            if hit:
                seq, _, method, path, status = hit
                if (
                    method == rec.get("http.method")
                    and path == rec.get("http.target")
                    and status == rec.get("http.status_code")
                ):
                    correlated_seq = seq
        self.record_tailer(
            {
                "method": rec.get("http.method"),
                "path": rec.get("http.target"),
                "status": rec.get("http.status_code"),
                "latency_ms": rec.get("http.request_duration_ms"),
                "client_ip": remote.rsplit(":", 1)[0] if ":" in remote else remote,
                "user_agent": rec.get("http.user_agent"),
                "bifrost_request_id": rec.get("request_id"),
                "trace_id": rec.get("trace_id"),
                "bifrost_time": rec.get("time"),
                # Bifrost container logs carry no model/provider; say so.
                "model": None,
                "provider": None,
                "model_unknown_reason": "not present in Bifrost container logs",
                "correlated_proxy_seq": correlated_seq,
                "duplicate_of_proxy": correlated_seq is not None,
            }
        )


# ---------------------------------------------------------------------------
# Proxy HTTP handler
# ---------------------------------------------------------------------------

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
}


def make_handler(service):
    cfg = service.cfg

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bifrost-audit/1.0"

        def log_message(self, *args):  # keep stdout clean; audit log is the record
            pass

        # -- audit API (served locally, never forwarded) -------------------
        def _audit_api(self):
            parsed = urlparse(self.path)
            if parsed.path == "/audit/status":
                head = service.log.head()
                body = {
                    "service": "bifrost-audit",
                    "version": VERSION,
                    "uptime_s": round(time.time() - service.started_at, 1),
                    "head_seq": head["seq"],
                    "head_hash": head["head_hash"],
                    "upstream": f"http://{cfg['upstream_host']}:{cfg['upstream_port']}",
                    "listen": f"{cfg['listen_host']}:{cfg['listen_port']}",
                }
                self._send_json(200, body)
                return True
            if parsed.path == "/audit/verify":
                ok, checked, failures = verify_chain(
                    service.log.path, service.log.checkpoint_dir
                )
                self._send_json(
                    200 if ok else 500,
                    {"ok": ok, "entries_checked": checked, "failures": failures},
                )
                return True
            if parsed.path == "/audit/entries":
                qs = parse_qs(parsed.query)
                try:
                    limit = max(1, min(500, int(qs.get("limit", ["50"])[0])))
                except ValueError:
                    limit = 50
                entries = tail_entries(service.log.path, limit)
                self._send_json(200, {"entries": entries, "count": len(entries)})
                return True
            if parsed.path == "/audit/checkpoints":
                names = sorted(
                    n for n in os.listdir(service.log.checkpoint_dir)
                    if n.startswith("checkpoint-") and n.endswith(".json")
                )
                self._send_json(200, {"checkpoints": names})
                return True
            if parsed.path == "/audit/checkpoint" and self.command == "POST":
                cp = service.log.checkpoint()
                self._send_json(200, {"checkpoint": cp})
                return True
            return False

        def _send_json(self, status, obj):
            data = (canonical(obj) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        # -- proxy ---------------------------------------------------------
        def _proxy(self):
            started = time.monotonic()
            length = self.headers.get("Content-Length")
            body = b""
            if length is not None:
                try:
                    body = self.rfile.read(int(length))
                except (ValueError, OSError):
                    body = b""
            model = None
            stream = False
            if body:
                try:
                    payload = json.loads(body.decode("utf-8", "replace"))
                    model = payload.get("model") if isinstance(payload, dict) else None
                    stream = bool(payload.get("stream")) if isinstance(payload, dict) else False
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            with service.model_map_lock:
                mmap = dict(service.model_map)
            provider = provider_of_model(model, mmap)
            client_fp = fingerprint(self.headers.get("Authorization"))
            status, resp_headers, resp_body, upstream_port, error = self._forward(body)
            latency_ms = round((time.monotonic() - started) * 1000, 1)
            usage = {}
            routing_decision = None
            if resp_body and not stream:
                try:
                    data = json.loads(resp_body.decode("utf-8", "replace"))
                    if isinstance(data, dict) and isinstance(data.get("usage"), dict):
                        usage = {
                            "prompt_tokens": data["usage"].get("prompt_tokens"),
                            "completion_tokens": data["usage"].get("completion_tokens"),
                            "total_tokens": data["usage"].get("total_tokens"),
                        }
                    # Bifrost reports its real routing decision in the
                    # response body (observed live): which provider key
                    # served the request and the upstream latency. The
                    # resolved model / latency live in extra_fields, not
                    # inside routing_info, so read both levels.
                    ef = data.get("extra_fields") or {}
                    ri = ef.get("routing_info")
                    if isinstance(ri, dict):
                        routing_decision = {
                            "provider": ri.get("provider"),
                            "selected_key": ri.get("key"),
                            "requested_provider": ri.get("requested_provider"),
                            "requested_model": ri.get("requested_model"),
                            "resolved_model_used": ef.get("resolved_model_used")
                            or ri.get("resolved_model_used"),
                            "upstream_latency_ms": ef.get("latency")
                            if ef.get("latency") is not None
                            else ri.get("latency"),
                        }
                    elif ef.get("original_model_requested") or ef.get(
                        "resolved_model_used"
                    ):
                        routing_decision = {
                            "provider": ef.get("provider"),
                            "selected_key": None,
                            "requested_provider": None,
                            "requested_model": ef.get("original_model_requested"),
                            "resolved_model_used": ef.get("resolved_model_used"),
                            "upstream_latency_ms": ef.get("latency"),
                        }
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            entry = service.record_proxy(
                {
                    "method": self.command,
                    "path": self.path,
                    "model": model,
                    "provider": provider,
                    "client_fp": client_fp,
                    "client_ip": self.client_address[0],
                    "user_agent": self.headers.get("User-Agent"),
                    "status": status,
                    "latency_ms": latency_ms,
                    "req_bytes": len(body),
                    "resp_bytes": len(resp_body),
                    "stream": stream,
                    "usage": usage or None,
                    "bifrost_request_id": resp_headers.get("x-request-id")
                    or resp_headers.get("x-requestid"),
                    "upstream_src_port": upstream_port,
                    "routing": {
                        "requested_model": model,
                        "provider": provider,
                        "fallback_index": 0,
                        "routing_rule": "none configured (OSS core routing)",
                    },
                    # Real routing decision as reported by Bifrost itself
                    # in the response body (selected provider key, resolved
                    # model, upstream latency); null when Bifrost does not
                    # report one (errors, non-chat paths).
                    "routing_decision": routing_decision,
                    "guardrails": {
                        "decision": "none configured",
                        "note": "governance plugin absent in OSS build "
                        "(Bifrost logs: 'governance plugin not found')",
                    },
                    "error": error,
                }
            )
            if upstream_port:
                service.remember_proxy_port(
                    upstream_port, entry["seq"], self.command, self.path, status
                )
            self._send_proxied(status, resp_headers, resp_body)

        def _forward(self, body):
            """Forward one request to Bifrost; stream SSE through in chunks.
            Returns (status, headers dict, full body bytes, src port, error)."""
            conn = http.client.HTTPConnection(
                cfg["upstream_host"], cfg["upstream_port"],
                timeout=cfg["upstream_timeout_s"],
            )
            headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in HOP_HEADERS
            }
            try:
                conn.request(self.command, self.path, body=body or None, headers=headers)
                resp = conn.getresponse()
                src_port = None
                try:
                    src_port = conn.sock.getsockname()[1]
                except Exception:
                    pass
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                chunks = []
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return resp.status, resp_headers, b"".join(chunks), src_port, None
            except (OSError, http.client.HTTPException, socket.timeout) as e:
                return 502, {}, b"", None, f"upstream unreachable: {e}"
            finally:
                conn.close()

        def _send_proxied(self, status, resp_headers, resp_body):
            self.send_response(status)
            for k, v in resp_headers.items():
                if k.lower() in HOP_HEADERS or k.lower() == "content-length":
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            if resp_body:
                try:
                    self.wfile.write(resp_body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):
            if self.path.startswith("/audit/"):
                if not self._audit_api():
                    self._send_json(404, {"error": "unknown audit endpoint"})
                return
            self._proxy()

        def do_POST(self):
            if self.path.startswith("/audit/"):
                if not self._audit_api():
                    self._send_json(404, {"error": "unknown audit endpoint"})
                return
            self._proxy()

        def do_PUT(self):
            self._proxy()

        def do_DELETE(self):
            self._proxy()

        def do_PATCH(self):
            self._proxy()

    return Handler


def tail_entries(path, limit):
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = 65536
        data = b""
        pos = size
        lines = []
        while pos > 0 and len(lines) <= limit:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
            lines = data.split(b"\n")
        out = []
        for raw in reversed([ln for ln in lines if ln.strip()]):
            if len(out) >= limit:
                break
            try:
                out.append(json.loads(raw.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
        return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(description="bifrost-audit immutable audit logs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--config", default=None)
    v = sub.add_parser("verify")
    v.add_argument("--log", required=True)
    v.add_argument("--checkpoints", default=None)
    t = sub.add_parser("tail")
    t.add_argument("--log", required=True)
    t.add_argument("--limit", type=int, default=10)
    c = sub.add_parser("checkpoint")
    c.add_argument("--log", required=True)
    c.add_argument("--checkpoints", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "verify":
        cp_dir = args.checkpoints
        if cp_dir is None:
            cp_dir = os.path.join(os.path.dirname(args.log), "checkpoints")
        ok, checked, failures = verify_chain(args.log, cp_dir)
        print(f"entries_checked={checked} ok={ok}")
        for f in failures:
            print(f"FAIL: {f}")
        return 0 if ok else 1

    if args.cmd == "tail":
        for e in tail_entries(args.log, args.limit):
            print(canonical(e))
        return 0

    if args.cmd == "checkpoint":
        log = AuditLog(args.log, args.checkpoints)
        cp = log.checkpoint()
        print(canonical(cp))
        return 0

    if args.cmd == "serve":
        cfg = load_config(args.config)
        service = AuditService(cfg)
        service.log.append(
            {"type": "service_event", "event": "startup", "version": VERSION}
        )
        handler = make_handler(service)
        server = ThreadingHTTPServer(
            (cfg["listen_host"], cfg["listen_port"]), handler
        )
        server.daemon_threads = True
        threads = [
            threading.Thread(target=service.tailer_loop, daemon=True),
            threading.Thread(target=service._metrics_loop, daemon=True),
            threading.Thread(target=service._model_map_loop, daemon=True),
        ]
        for th in threads:
            th.start()
        print(
            f"bifrost-audit {VERSION} listening on "
            f"{cfg['listen_host']}:{cfg['listen_port']} "
            f"-> upstream {cfg['upstream_host']}:{cfg['upstream_port']}",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            service._stop.set()
            service.log.append({"type": "service_event", "event": "shutdown"})
        return 0


if __name__ == "__main__":
    sys.exit(main())
