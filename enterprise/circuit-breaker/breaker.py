#!/usr/bin/env python3
"""bifrost-breaker — enterprise circuit breaker for Bifrost (clean-room rebuild).

Standalone reverse proxy that sits in front of a Bifrost gateway and wraps
every upstream call in a per-route circuit breaker with the classic three
states:

    CLOSED     -- traffic flows; consecutive failures are counted.
    OPEN       -- failure threshold reached; requests fast-fail with 503
                  (Retry-After) and NO upstream call is attempted.
    HALF_OPEN  -- after the cooldown, a bounded number of probe requests
                  are allowed through; probe success closes the breaker,
                  probe failure re-opens it.

Design notes (behavior spec, derived from observed Bifrost behavior and the
standard breaker pattern — no Enterprise source was available or used):

* Bifrost OSS (v2.6.0, verified live) retries per provider only
  (max_retries 1-2 in config) and has no breaker: a dead provider burns
  retries and latency on every request. This service is the missing layer.
* Failure = transport error, timeout, or HTTP 5xx from upstream.
  HTTP 4xx is a client error and does NOT count toward the threshold.
* Breaker identity = route name (provider for real Bifrost traffic, e.g.
  ``groq`` / ``nim``; a test-route name for synthetic targets) plus, when
  a Bearer token is present, a truncated sha256 of the token — so one bad
  virtual key cannot trip the breaker for every other key.
* Streaming (SSE) responses are proxied chunk-by-chunk; the breaker
  decision is made on the response status line, before the body streams.
* State survives restarts via a JSON snapshot written on every transition.
* Prometheus metrics at /metrics; breaker state at /breaker/state.

Stdlib only. No third-party dependencies, no paid tier, no license key.
"""

import hashlib
import http.client
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
DEFAULT_CONFIG_PATH = "/etc/bifrost-breaker/config.json"

# ---------------------------------------------------------------- config ---

DEFAULTS = {
    "failure_threshold": 3,        # consecutive failures to trip OPEN
    "cooldown_seconds": 30,        # OPEN dwell before HALF_OPEN probing
    "half_open_max_probes": 1,     # concurrent trial requests in HALF_OPEN
    "success_threshold": 1,        # consecutive probe successes to CLOSE
    "upstream_timeout_seconds": 30,
}

BUILTIN_CONFIG = {
    "listen_host": "100.83.164.96",
    "listen_port": 8082,
    "bifrost_url": "http://100.83.164.96:8081",
    "state_file": "/var/lib/bifrost-breaker/state.json",
    "defaults": dict(DEFAULTS),
    "routes": [],  # {"name","model_prefix","upstream", ...overrides}
}


def load_config(path):
    cfg = json.loads(json.dumps(BUILTIN_CONFIG))  # deep copy of builtins
    if os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
        cfg.update(user)
        cfg["defaults"] = {**DEFAULTS, **user.get("defaults", {})}
    return cfg


# -------------------------------------------------------------- breaker ----

class Breaker:
    """One circuit breaker instance. All state changes under one lock."""

    def __init__(self, name, cfg, state=None):
        self.name = name
        self.lock = threading.Lock()
        self.cfg = cfg
        self.state = "closed"
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.opened_at = None
        self.probes_in_flight = 0
        self.total_requests = 0
        self.total_failures = 0
        self.total_fast_fails = 0
        self.transitions = 0
        self.last_transition_at = None
        self.last_error = None
        if state:
            self.state = state.get("state", "closed")
            self.consecutive_failures = state.get("consecutive_failures", 0)
            self.consecutive_successes = state.get("consecutive_successes", 0)
            self.opened_at = state.get("opened_at")
            self.total_requests = state.get("total_requests", 0)
            self.total_failures = state.get("total_failures", 0)
            self.total_fast_fails = state.get("total_fast_fails", 0)
            self.transitions = state.get("transitions", 0)
            self.last_transition_at = state.get("last_transition_at")
            self.last_error = state.get("last_error")

    # -- transitions ------------------------------------------------------
    def _transition(self, new_state, now):
        if self.state != new_state:
            old = self.state
            self.state = new_state
            self.transitions += 1
            self.last_transition_at = now
            log(f"breaker={self.name} {old} -> {new_state}")
            if new_state == "open":
                self.opened_at = now
                self.probes_in_flight = 0
            if new_state == "closed":
                self.consecutive_failures = 0
                self.consecutive_successes = 0
                self.opened_at = None
            if new_state == "half_open":
                self.consecutive_successes = 0
                self.probes_in_flight = 0
            return True
        return False

    def allow_request(self):
        """Return (allowed, is_probe). Fast-fail path returns allowed=False."""
        now = time.time()
        with self.lock:
            self.total_requests += 1
            if self.state == "closed":
                return True, False
            if self.state == "open":
                if now - (self.opened_at or 0) >= self.cfg["cooldown_seconds"]:
                    self._transition("half_open", now)
                else:
                    self.total_fast_fails += 1
                    return False, False
            # half_open
            if self.probes_in_flight >= self.cfg["half_open_max_probes"]:
                self.total_fast_fails += 1
                return False, False
            self.probes_in_flight += 1
            return True, True

    def record_success(self, is_probe):
        now = time.time()
        with self.lock:
            if is_probe:
                self.probes_in_flight = max(0, self.probes_in_flight - 1)
            if self.state == "half_open":
                self.consecutive_successes += 1
                self.consecutive_failures = 0
                if self.consecutive_successes >= self.cfg["success_threshold"]:
                    self._transition("closed", now)
            elif self.state == "closed":
                self.consecutive_failures = 0

    def record_failure(self, is_probe, error):
        now = time.time()
        with self.lock:
            self.total_failures += 1
            self.last_error = str(error)[:200]
            if is_probe:
                self.probes_in_flight = max(0, self.probes_in_flight - 1)
            if self.state == "half_open":
                self._transition("open", now)
                return
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            if self.consecutive_failures >= self.cfg["failure_threshold"]:
                self._transition("open", now)

    def retry_after(self):
        if self.state != "open" or not self.opened_at:
            return 0
        remaining = self.cfg["cooldown_seconds"] - (time.time() - self.opened_at)
        return max(0, int(remaining) + 1)

    def snapshot(self):
        with self.lock:
            return {
                "name": self.name,
                "state": self.state,
                "consecutive_failures": self.consecutive_failures,
                "consecutive_successes": self.consecutive_successes,
                "opened_at": self.opened_at,
                "probes_in_flight": self.probes_in_flight,
                "total_requests": self.total_requests,
                "total_failures": self.total_failures,
                "total_fast_fails": self.total_fast_fails,
                "transitions": self.transitions,
                "last_transition_at": self.last_transition_at,
                "last_error": self.last_error,
                "config": self.cfg,
            }


# -------------------------------------------------------------- registry ----

class Registry:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.breakers = {}
        self._load_state()

    def _load_state(self):
        path = self.config.get("state_file")
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    saved = json.load(f)
                for name, st in saved.get("breakers", {}).items():
                    cfg = self._cfg_for(name)
                    self.breakers[name] = Breaker(name, cfg, st)
                log(f"restored {len(self.breakers)} breaker(s) from {path}")
            except Exception as e:  # corrupt snapshot must not block startup
                log(f"state restore failed ({e}); starting fresh")

    def save_state(self):
        path = self.config.get("state_file")
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"breakers": {n: b.snapshot()
                                        for n, b in self.breakers.items()}},
                          f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            log(f"state save failed: {e}")

    def _cfg_for(self, route_name):
        cfg = dict(self.config["defaults"])
        for r in self.config.get("routes", []):
            if r["name"] == route_name:
                for k in DEFAULTS:
                    if k in r:
                        cfg[k] = r[k]
        return cfg

    def get(self, route_name, virtual_key=None):
        """Breaker identity: route (+ truncated token hash when present)."""
        key = route_name
        if virtual_key:
            digest = hashlib.sha256(virtual_key.encode()).hexdigest()[:12]
            key = f"{route_name}:{digest}"
        with self.lock:
            b = self.breakers.get(key)
            if b is None:
                b = Breaker(key, self._cfg_for(route_name))
                self.breakers[key] = b
            return b

    def all_snapshots(self):
        with self.lock:
            return {n: b.snapshot() for n, b in self.breakers.items()}

    def reset(self, name=None):
        with self.lock:
            if name:
                self.breakers.pop(name, None)
            else:
                self.breakers.clear()
        self.save_state()


REGISTRY = None
CONFIG = None


def log(msg):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} breaker {msg}", flush=True)


# -------------------------------------------------------------- routing -----

def route_for(model):
    """Longest-prefix route match; default route is Bifrost itself."""
    best = None
    for r in CONFIG.get("routes", []):
        prefix = r.get("model_prefix", "")
        if model.startswith(prefix) and (best is None or
                                         len(prefix) > len(best.get("model_prefix", ""))):
            best = r
    if best:
        return best["name"], best["upstream"]
    provider = (model.split("/")[0] if model else "unknown") or "unknown"
    return provider, CONFIG["bifrost_url"]


# -------------------------------------------------------------- proxy ------

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "transfer-encoding", "upgrade"}


def proxy_upstream(handler, method, path, body, headers, upstream_url, timeout):
    """Stream the upstream response back to the client. Returns HTTP status.

    Raises on transport errors / timeout so the caller can count a failure.
    """
    u = urllib.parse.urlparse(upstream_url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" \
        else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=timeout)
    fwd = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk == "host":
            continue
        fwd[k] = v
    fwd["Host"] = host if port in (80, 443) else f"{host}:{port}"
    upstream_path = u.path.rstrip("/") + path
    conn.request(method, upstream_path, body=body, headers=fwd)
    resp = conn.getresponse()
    status = resp.status
    out_headers = [(k, v) for k, v in resp.getheaders()
                   if k.lower() not in HOP_BY_HOP]
    handler.send_response(status)
    for k, v in out_headers:
        handler.send_header(k, v)
    handler.end_headers()
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        handler.wfile.write(chunk)
    conn.close()
    return status


# -------------------------------------------------------------- handler -----

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"bifrost-breaker/{VERSION}"

    def log_message(self, fmt, *args):  # keep stdout clean; we log our own lines
        pass

    # -- helpers ----------------------------------------------------------
    def _send_json(self, status, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _virtual_key(self):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

    # -- admin / observability --------------------------------------------
    def do_GET(self):
        if self.path == "/health":
            snaps = REGISTRY.all_snapshots()
            open_breakers = [n for n, s in snaps.items() if s["state"] == "open"]
            self._send_json(200, {"status": "ok", "version": VERSION,
                                  "breakers": len(snaps),
                                  "open_breakers": open_breakers})
            return
        if self.path == "/breaker/state":
            self._send_json(200, {"breakers": REGISTRY.all_snapshots()})
            return
        if self.path.startswith("/breaker/state/"):
            name = urllib.parse.unquote(self.path[len("/breaker/state/"):])
            snaps = REGISTRY.all_snapshots()
            if name in snaps:
                self._send_json(200, snaps[name])
            else:
                self._send_json(404, {"error": f"no breaker named {name}"})
            return
        if self.path == "/metrics":
            self._send_metrics()
            return
        if self.path == "/v1/models":
            self._proxy_passthrough("GET", self.path, b"")
            return
        self._send_json(404, {"error": f"unknown path {self.path}"})

    def _send_metrics(self):
        lines = []
        snaps = REGISTRY.all_snapshots()
        state_val = {"closed": 0, "half_open": 1, "open": 2}
        for name, s in sorted(snaps.items()):
            safe = name.replace(":", "_")
            lines.append(f'# HELP bifrost_breaker_state 0=closed 1=half_open 2=open')
            lines.append(f'bifrost_breaker_state{{breaker="{safe}"}} '
                         f'{state_val[s["state"]]}')
            lines.append(f'bifrost_breaker_requests_total{{breaker="{safe}"}} '
                         f'{s["total_requests"]}')
            lines.append(f'bifrost_breaker_failures_total{{breaker="{safe}"}} '
                         f'{s["total_failures"]}')
            lines.append(f'bifrost_breaker_fast_fails_total{{breaker="{safe}"}} '
                         f'{s["total_fast_fails"]}')
            lines.append(f'bifrost_breaker_transitions_total{{breaker="{safe}"}} '
                         f'{s["transitions"]}')
        body = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type",
                         "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/breaker/reset":
            body = self._read_body()
            name = None
            if body:
                try:
                    name = json.loads(body).get("provider")
                except Exception:
                    pass
            REGISTRY.reset(name)
            self._send_json(200, {"status": "reset", "provider": name or "all"})
            return
        if self.path in ("/v1/chat/completions", "/v1/embeddings",
                         "/v1/responses"):
            body = self._read_body()
            try:
                model = json.loads(body).get("model", "") if body else ""
            except Exception:
                model = ""
            route_name, upstream = route_for(model)
            breaker = REGISTRY.get(route_name, self._virtual_key())
            allowed, is_probe = breaker.allow_request()
            if not allowed:
                retry = breaker.retry_after()
                log(f"breaker={breaker.name} FAST-FAIL state=open "
                    f"retry_after={retry}s path={self.path} model={model}")
                self._send_json(
                    503,
                    {"error": {"code": "circuit_open",
                               "message": f"circuit breaker open for "
                                          f"{route_name}; failing fast",
                               "provider": route_name,
                               "retry_after_seconds": retry}},
                    extra={"Retry-After": str(retry)})
                REGISTRY.save_state()
                return
            timeout = breaker.cfg["upstream_timeout_seconds"]
            t0 = time.time()
            try:
                status = proxy_upstream(self, "POST", self.path, body,
                                        self.headers, upstream, timeout)
            except (socket.timeout, TimeoutError, ConnectionError,
                    http.client.HTTPException, OSError) as e:
                dt = time.time() - t0
                breaker.record_failure(is_probe, f"{type(e).__name__}: {e}")
                log(f"breaker={breaker.name} FAILURE probe={is_probe} "
                    f"{type(e).__name__} {dt:.2f}s model={model}")
                REGISTRY.save_state()
                try:
                    self._send_json(502, {"error": {"code": "upstream_unavailable",
                                                    "message": f"upstream error for "
                                                               f"{route_name}: {e}",
                                                    "provider": route_name}})
                except (BrokenPipeError, ConnectionResetError):
                    pass  # client already gone; failure is recorded regardless
                return
            dt = time.time() - t0
            if status >= 500:
                breaker.record_failure(
                    is_probe, f"upstream HTTP {status}")
                log(f"breaker={breaker.name} FAILURE probe={is_probe} "
                    f"HTTP {status} {dt:.2f}s model={model}")
            elif status >= 400:
                # Client error: do not count toward the breaker threshold.
                log(f"breaker={breaker.name} client HTTP {status} "
                    f"{dt:.2f}s model={model} (not counted)")
            else:
                breaker.record_success(is_probe)
                log(f"breaker={breaker.name} success probe={is_probe} "
                    f"HTTP {status} {dt:.2f}s model={model}")
            REGISTRY.save_state()
            return
        self._send_json(404, {"error": f"unknown path {self.path}"})

    def _proxy_passthrough(self, method, path, body):
        """No breaker: catalog passthrough straight to Bifrost."""
        try:
            proxy_upstream(self, method, path, body, self.headers,
                           CONFIG["bifrost_url"],
                           CONFIG["defaults"]["upstream_timeout_seconds"])
        except Exception as e:
            self._send_json(502, {"error": {"code": "upstream_unavailable",
                                            "message": str(e)}})


def main():
    global CONFIG, REGISTRY
    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_PATH
    CONFIG = load_config(config_path)
    REGISTRY = Registry(CONFIG)

    def reload_config(signum, frame):
        global CONFIG
        CONFIG = load_config(config_path)
        log(f"config reloaded from {config_path}")

    signal.signal(signal.SIGHUP, reload_config)
    server = ThreadingHTTPServer((CONFIG["listen_host"], CONFIG["listen_port"]),
                                 Handler)
    log(f"bifrost-breaker {VERSION} listening on "
        f"{CONFIG['listen_host']}:{CONFIG['listen_port']} "
        f"upstream={CONFIG['bifrost_url']} config={config_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
