#!/usr/bin/env python3
"""Tamper demo: copy the live log, modify one entry, show verify failing.
Usage: tamper_demo.py <src> <dst> <seq-to-modify> <field> <new-value>
Never modifies the live log."""
import json
import sys

src, dst, seq, field, value = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
lines = open(src).read().splitlines()
for i, line in enumerate(lines):
    e = json.loads(line)
    if e["seq"] == seq:
        print(f"tampering seq={seq}: {field} {e.get(field)!r} -> {value!r}")
        e[field] = value
        lines[i] = json.dumps(e, sort_keys=True)
        break
else:
    print(f"seq {seq} not found")
    sys.exit(1)
open(dst, "w").write("\n".join(lines) + "\n")
print(f"wrote tampered copy: {dst}")
