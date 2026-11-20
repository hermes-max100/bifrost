#!/usr/bin/env python3
"""Summarize audit.jsonl entries for the live-test report."""
import json
import sys

path = sys.argv[1]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 40
with open(path) as f:
    lines = [ln for ln in f if ln.strip()]
for line in lines[-limit:]:
    e = json.loads(line)
    t = e.get("type")
    if t == "proxy_request":
        print(
            "PROXY seq=%s %s %s model=%s provider=%s status=%s latency=%sms "
            "usage=%s routing_decision=%s"
            % (
                e["seq"], e["method"], e["path"], e["model"], e["provider"],
                e["status"], e["latency_ms"], e.get("usage"),
                e.get("routing_decision"),
            )
        )
    elif t == "gateway_request":
        print(
            "TAILER seq=%s %s %s status=%s latency=%sms dup_of_proxy=%s "
            "corr_seq=%s req=%s"
            % (
                e["seq"], e["method"], e["path"], e["status"],
                e["latency_ms"], e.get("duplicate_of_proxy"),
                e.get("correlated_proxy_seq"), e.get("bifrost_request_id"),
            )
        )
    elif t == "metrics_snapshot":
        print(
            "METRICS seq=%s delta_keys=%d totals_keys=%d"
            % (
                e["seq"],
                len(e.get("deltas_since_last_snapshot", {})),
                len(e.get("totals", {})),
            )
        )
    else:
        print("%s seq=%s" % (t, e["seq"]))
print("TOTAL_ENTRIES=%d" % len(lines))
