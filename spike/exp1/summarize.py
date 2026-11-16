#!/usr/bin/env python3
"""Print a one-line-per-event digest of a swapproxy.py log (already redacted)."""
import json
import sys

for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    e = d.pop("event")
    d.pop("t", None)
    if e == "request":
        h = d.get("headers", {})
        auth = {k: v for k, v in h.items() if v.startswith("<redacted")}
        print("request", d["method"], d["path"], "ua=" + h.get("user-agent", "")[:60], auth)
    elif e == "response":
        keys = ("status", "ctype", "bytes", "chunks", "ttfb_s", "first_chunk_s", "last_chunk_s",
                "swapped", "err_sample")
        print("response", {k: d.get(k) for k in keys if d.get(k) is not None})
    else:
        print(e, d)
