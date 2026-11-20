# bifrost-audit — immutable audit logs for Bifrost (own code)

Clean-room rebuild of the "immutable audit log" enterprise capability,
for the hermes-max100/bifrost deployment on the IONOS VPS. Written from
observed Bifrost behaviour (its `/health`, `/v1/models`, `/metrics`, and
JSON container logs) and first principles. No Bifrost Enterprise code was
available or used, and none is copied here: this is a standalone service
that sits **beside** the stock OSS gateway and never modifies it.

## What it does

Three ingest paths write into one hash-chained, append-only log:

1. **Proxy (audited request path)** — an HTTP reverse proxy on
   `100.83.164.96:8090` that forwards OpenAI-compatible traffic to
   Bifrost (`:8081`) unchanged and records one entry per request: who
   (truncated SHA-256 fingerprint of the credential, never the
   credential), model/provider, timestamp, outcome (HTTP status),
   latency, token usage when the upstream reports it, and the
   routing/guardrail decision context.
2. **Tailer (complete coverage)** — follows `docker logs -f bifrost`
   (read-only) and records every request Bifrost itself logs as
   completed, including traffic that bypasses the proxy. Bifrost's
   container logs carry no model, so tailer entries record `model: null`
   and say why. Entries for requests that also went through the proxy
   are marked `duplicate_of_proxy` with the proxy entry's seq, matched
   on Bifrost's logged `remote_addr` port.
3. **Metrics snapshotter** — polls `/metrics` every 60 s and records
   per-(provider, model) token/cost/error counter totals and deltas as
   aggregate entries, so per-model totals exist in the chain even for
   direct traffic.

## Tamper evidence

Every entry carries `seq`, `prev_hash`, and `entry_hash`, where

```
entry_hash = SHA256(prev_hash + "\n" + canonical_json(entry without entry_hash))
```

Checkpoints (`checkpoints/checkpoint-<seq>.json`, plus `latest.json`)
are written every 100 entries and on demand. Verification re-walks the
whole chain, recomputes every hash, checks seq continuity and every
checkpoint:

```
python3 auditd.py verify --log /var/lib/bifrost-audit/audit.jsonl
```

Any modification, deletion, insertion, or reordering fails
verification. The guarantee is **detection**, not physical prevention
against root — the log file is append-only (`O_APPEND` + `fsync` per
entry, single-writer lock) and verification is the proof.

## Privacy

Provider API keys and client credentials are never stored — only a
16-hex-char SHA-256 fingerprint of an `Authorization` header.
Prompt/completion **text** is never logged, only token counts when the
upstream reports them.

## Honest limits

- Routing/guardrail "decisions" in proxy entries record what is true
  of this deployment: no routing rules and no guardrails are
  configured (the OSS build logs `governance plugin not found`). The
  entry says so explicitly rather than inventing a decision.
- Tailer entries have no model/provider: Bifrost's container logs do
  not include them. The full-fidelity record for a request is its
  proxy entry.
- Streaming responses: token usage is captured only if the upstream
  reports it (OpenAI `stream_options.include_usage`); otherwise
  `usage` is null and byte counts + latency are still recorded.

## Layout on the VPS

| Path | What |
|---|---|
| `/opt/bifrost-audit/auditd.py` | the service (stdlib only) |
| `/opt/bifrost-audit/auditd.json` | config |
| `/opt/bifrost-audit/test_auditd.py` | unit tests |
| `/opt/bifrost-audit/summarize.py` | one-line-per-entry log summarizer |
| `/opt/bifrost-audit/tamper_demo.py` | tamper demo (copies the log, never touches it) |
| `/var/lib/bifrost-audit/audit.jsonl` | the chained log |
| `/var/lib/bifrost-audit/checkpoints/` | checkpoints |
| `/etc/systemd/system/bifrost-audit.service` | systemd unit (own service; `bifrost.service` untouched) |

## API (same port, tailnet-only)

- `GET /audit/status` — head seq/hash, uptime, upstream
- `GET /audit/verify` — full chain verification as JSON
- `GET /audit/entries?limit=N` — newest N entries
- `GET /audit/checkpoints` — checkpoint list
- `POST /audit/checkpoint` — force a checkpoint

Everything else is proxied to Bifrost unchanged.

## Operations

```bash
systemctl status bifrost-audit
journalctl -u bifrost-audit -f
curl -s http://100.83.164.96:8090/audit/status
curl -s http://100.83.164.96:8090/audit/verify
python3 /opt/bifrost-audit/auditd.py verify \
  --log /var/lib/bifrost-audit/audit.jsonl
python3 -m unittest discover -s /opt/bifrost-audit -p 'test_*.py' -v
```

Point a client at the audited path by changing only the base URL:

```
http://100.83.164.96:8090/v1   # instead of http://100.83.164.96:8081/v1
```

## Tests

`test_auditd.py` (stdlib unittest, 11 tests): chain append/verify,
checkpoint files matching the chain, tamper detection for body
modification, deletion, and reordering, hash determinism, chain
recovery/resume, metrics parsing, and proxy forwarding against a fake
upstream with credential-fingerprint and no-secret-leak checks.
