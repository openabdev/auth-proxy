#!/usr/bin/env python3
"""Mock credential broker for Experiment 2 (stands in for the Phase 1 broker).

  broker.py --listen PORT --cred ID=ENVVAR [--cred ...]

Credential values are read from environment variables by NAME and are never
logged or returned except to /v1/resolve. Surrogates live in memory only, so
a restart forgets them (that is what "broker unreachable, no stale cache"
tests against).

  POST /v1/resolve {caller, route, surrogate} -> 200 {credential, credential_id, expires_at}
                                                 401/403 {"error": code}
  POST /admin/mint   {caller, route, credential_id, ttl} -> {surrogate}
                     route may be a comma list: one CLI credential can span several
                     upstream hosts (kiro-cli uses one key for 3 hosts)
  POST /admin/revoke {surrogate}
  GET  /admin/stats  -> {resolves}

The admin endpoints share the port only because this is a mock; in Phase 1
minting belongs to the admin plane, not to anything the agent can reach.
"""
import argparse
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CREDS = {}
SURR = {}
STATS = {"resolves": 0}
LOCK = threading.Lock()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True  # else Nagle + delayed ACK adds 40 ms per response

    def log_message(self, *a):
        pass

    def _reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/admin/stats":
            return self._reply(200, STATS)
        self._reply(404, {"error": "not_found"})

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._reply(400, {"error": "bad_json"})
        with LOCK:
            if self.path == "/v1/resolve":
                STATS["resolves"] += 1
                s = SURR.get(req.get("surrogate"))
                if not s:
                    return self._reply(401, {"error": "surrogate_unknown"})
                if s["revoked"]:
                    return self._reply(401, {"error": "surrogate_revoked"})
                if s["exp"] <= time.time():
                    return self._reply(401, {"error": "surrogate_expired"})
                if s["caller"] != req.get("caller"):
                    return self._reply(403, {"error": "surrogate_wrong_caller"})
                if s["route"] != req.get("route") and req.get("route") not in s["route"].split(","):
                    return self._reply(403, {"error": "surrogate_wrong_route"})
                return self._reply(200, {"credential": CREDS[s["cred"]], "credential_id": s["cred"],
                                         "expires_at": int(s["exp"])})
            if self.path == "/admin/mint":
                if req.get("credential_id") not in CREDS:
                    return self._reply(400, {"error": "unknown_credential"})
                tok = "aps_" + secrets.token_hex(16)
                SURR[tok] = {"caller": req["caller"], "route": req["route"], "cred": req["credential_id"],
                             "exp": time.time() + float(req.get("ttl", 900)), "revoked": False}
                return self._reply(200, {"surrogate": tok})
            if self.path == "/admin/revoke":
                if req.get("surrogate") in SURR:
                    SURR[req["surrogate"]]["revoked"] = True
                return self._reply(200, {})
        self._reply(404, {"error": "not_found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--cred", action="append", default=[])
    a = ap.parse_args()
    for spec in a.cred:
        cid, env = spec.split("=", 1)
        v = os.environ.get(env)
        if not v:
            print(f"broker: env {env} is empty", file=sys.stderr)
            return 2
        CREDS[cid] = v
    srv = ThreadingHTTPServer(("127.0.0.1", a.listen), H)
    srv.daemon_threads = True
    print("broker ready", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
