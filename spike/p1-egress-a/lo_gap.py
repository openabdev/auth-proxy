#!/usr/bin/env python3
"""Run as the agent UID. Can the agent reach the sidecar's other loopback
listener (the spike's mock broker) and resolve its own surrogate into the real
credential? Prints status codes, JSON key names and the credential's length only.
"""
import json
import urllib.error
import urllib.request

BROKER = "http://127.0.0.1:18190"
surr = open("/handoff/surrogate").read().strip()
out = {}
try:
    with urllib.request.urlopen(BROKER + "/admin/stats", timeout=3) as r:
        out["admin_stats"] = r.status
except Exception as e:  # noqa: BLE001
    out["admin_stats"] = type(e).__name__ + ":" + str(getattr(e, "reason", e))
try:
    req = urllib.request.Request(BROKER + "/v1/resolve", method="POST",
                                 data=json.dumps({"caller": "agent-1", "route": "krs", "surrogate": surr}).encode())
    with urllib.request.urlopen(req, timeout=3) as r:
        body = json.load(r)
        out["resolve"] = {"status": r.status, "keys": sorted(body),
                          "credential_len": len(body.get("credential", ""))}
except Exception as e:  # noqa: BLE001
    out["resolve"] = type(e).__name__ + ":" + str(getattr(e, "reason", e))
print(json.dumps(out))
