# Enterprise Circuit Breaker for Bifrost — clean-room rebuild

Standalone service that wraps Bifrost upstream calls in a per-provider /
per-key circuit breaker (closed / open / half-open), so a failing provider
is cut off fast instead of burning retries and latency on every request,
and is probed back into service on recovery.

## Why this exists

Bifrost OSS v2.6.0 (verified live on the IONOS VPS, 2026-11-20) has only
per-provider `max_retries` (1–2) and **no circuit breaker anywhere in the
build**. The enterprise breaker is license-gated inside the OSS binary —
there is no config flag to enable it. This is a fresh, own-code rebuild of
the behavior: study the observable behavior + docs, write new code, never
copy Enterprise code (none was available). Stdlib-only Python, no paid
tier, no license key.

## What it does

* Reverse-proxies `POST /v1/chat/completions`, `/v1/embeddings`,
  `/v1/responses` to Bifrost (default) or to a per-route upstream override.
  `GET /v1/models` passes through unbroken. Streaming (SSE) responses are
  proxied chunk-by-chunk.
* Breaker identity = route name (provider for real traffic: `groq`, `nim`,
  `pplx`, …) plus, when a Bearer token is present, a truncated sha256 of
  the token — one bad virtual key cannot trip the breaker for all keys.
* **Failure** = transport error, timeout, or HTTP 5xx. **HTTP 4xx does not
  count** (client error, not provider failure).
* **Closed → open** after `failure_threshold` consecutive failures.
  **Open** fast-fails with `503 {"error":{"code":"circuit_open",…}}` and a
  `Retry-After` header — zero upstream calls while open.
  **Half-open** after `cooldown_seconds`: up to `half_open_max_probes`
  concurrent trial requests; probe success closes (after
  `success_threshold` consecutive successes), probe failure re-opens.
* Observability: `GET /health`, `GET /breaker/state[/<name>]`,
  `POST /breaker/reset`, `GET /metrics` (Prometheus).
* State survives restarts via a JSON snapshot written on every transition.
  Config reloads on `SIGHUP`.

## Files

| File | Purpose |
|---|---|
| `breaker.py` | The service (stdlib only) |
| `config.json` | Listen address, Bifrost URL, defaults, test routes |
| `bifrost-breaker.service` | systemd unit (own port, never touches `bifrost.service`) |
| `tests/flap_stub.py` | Test upstream stub (mode file: `fail` / `ok` / `slow`) |
| `tests/test_breaker.sh` | Live test script (run on the VPS) |

## Deployment (VPS)

Live at `http://100.83.164.96:8082` (tailnet-only, same posture as
Bifrost on `:8081`). Code in `/opt/bifrost-breaker/`, config in
`/etc/bifrost-breaker/config.json`, state in
`/var/lib/bifrost-breaker/state.json`. `systemctl status bifrost-breaker`.
It never touches `/etc/bifrost/config.json` or the live Bifrost container.

## Live test evidence — 2026-11-20 ~01:30 PST, VPS

Full run: `tests/test_breaker.sh` on the VPS. All assertions passed except
one timing check that failed only because `bc` is not installed on the VPS;
re-verified with a Python timing probe (below).

| Test | Result |
|---|---|
| A. `test/dead` → `127.0.0.1:9` (connection refused), 3× `502` | breaker **open** after 3 failures; 4th request **503 fast-fail** with `retry_after_seconds: 5`, `total_fast_fails` counted |
| B. Cooldown (5 s) → half-open probe fails | **re-opens** (state `open`) |
| C. `test/flap` 3× `500` → open; stub mode `ok`, probe after cooldown | **200 `STUB-OK`, breaker closed**; next request 200 |
| D. `test/slow` (5 s upstream sleep, 2 s timeout), 2× `502` after 2.03 s each | breaker **open** after 2 timeouts; fast-fail **503 in 14.9 ms** (vs 2 s timeout + 5 s sleep) |
| Timing probe | `test-dead` fast-fail **503 in 38.1 ms** |
| E. Real traffic: `groq/qwen/qwen3.8-27b` via breaker | **200 in 0.19 s**, breaker `closed`, `total_failures: 0`; direct Bifrost also 200 |
| F. `/metrics` | per-breaker `state` / `requests_total` / `failures_total` / `fast_fails_total` / `transitions_total` live (e.g. `test-dead state 2`, `groq state 0`) |
| G. Bifrost untouched | `/health` 200 on both services, `bifrost.service` + `bifrost-breaker.service` both `active` |

## What remains

* **Cutover is NOT done and NOT attempted here.** Consumers still talk to
  Bifrost `:8081` directly; pointing them at `:8082` is a separate
  decision (route the traffic, then watch `/breaker/state` + `/metrics`).
* Per-provider tuning is at defaults (`failure_threshold 3`,
  `cooldown_seconds 30`, `upstream_timeout_seconds 30`) — the `pplx`
  lanes (currently degraded upstream, returning 502s via the penguin shim)
  would trip their breaker quickly once routed through here; that is the
  intended behavior, but confirm it is wanted before cutover.
* The `test/*` routes in `config.json` are test-only; remove them (and the
  stub) before any production cutover, or keep them as a permanent
  self-test harness — either way they only trigger on `test/*` model names.
* No auth on the breaker admin endpoints (`/breaker/reset`,
  `/breaker/state`) — same tailnet-only posture as Bifrost itself; add
  gateway auth before any exposure beyond the tailnet.
