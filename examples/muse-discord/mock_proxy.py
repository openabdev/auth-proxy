#!/usr/bin/env python3
"""Mock auth-proxy for trying the reference caller without a deployment.

Implements just enough of the real proxy's caller-facing contract to exercise
caller.py end to end:

  * /ap/<caller-key>/<route><path> addressing and caller-key checking
    (sha256 compared, like crates/ap-proxy/src/pipeline.rs),
  * the surrogate in "Authorization: Bearer aps_..." form,
  * an allow-listed read answered with canned upstream data,
  * the approval flow proposed in issues #5/#6: a write is parked with
    "202 + request_id", and GET /ap/<caller-key>/requests/<request-id>
    reports parked / executed / denied / expired.

Simplifications, deliberately: one identity, one route, one registered
surrogate, no canonicalization, no audit, and parked requests live in memory.
The "upstream" is fabricated; no Discord call ever happens, and the mock
"executes" a parked write by inventing the upstream response.

Test-only admin endpoints (NOT part of the proposed contract; they stand in
for the owner's approval plane):

  POST /_mock/approve/<request-id>     approve and "execute" the parked write
  POST /_mock/deny/<request-id>        deny it

Environment:
  MOCK_TTL   seconds a parked request awaits a decision (default 60)
  MOCK_PORT  port to bind, 0 = ephemeral (default 0); the bound port is
             printed as "MOCK_PORT=<port>" on stdout.
"""

import hashlib
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The example key material from README.md. Only digests are kept for the
# caller key, like the real config; the surrogate is registered by digest too.
EXAMPLE_CALLER_KEY = "apk_c6267244721d31df7f7ab84ca4f5d16ad4d3ef9d6d53b06662cd7dac6704c26c"
EXAMPLE_SURROGATE = "aps_ac5e3eca49b3e957da4c8709180f7f62a4336de3e14e68faf46df0735a016b03"
CALLER_SHA256 = hashlib.sha256(EXAMPLE_CALLER_KEY.encode()).hexdigest()
SURROGATE_SHA256 = hashlib.sha256(EXAMPLE_SURROGATE.encode()).hexdigest()
SURROGATE_FORM = re.compile(r"^Bearer (aps_[0-9a-f]{64})$")
CHANNEL_MESSAGES = re.compile(r"^/api/v10/channels/(\d+)/messages$")

TTL = float(os.environ.get("MOCK_TTL", "60"))
_lock = threading.Lock()
_parked: dict[str, dict] = {}
_counter = [0]


def _json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    # -- helpers ---------------------------------------------------------
    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def _check_caller(self, caller_key: str) -> bool:
        digest = hashlib.sha256(caller_key.encode()).hexdigest()
        if digest != CALLER_SHA256:
            _json(self, 403, {"code": "caller_rejected"})
            return False
        match = SURROGATE_FORM.match(self.headers.get("Authorization") or "")
        if not match:
            _json(self, 403, {"code": "surrogate_malformed"})
            return False
        if hashlib.sha256(match.group(1).encode()).hexdigest() != SURROGATE_SHA256:
            _json(self, 403, {"code": "surrogate_unknown"})
            return False
        return True

    # -- routing ---------------------------------------------------------
    def do_POST(self):  # noqa: N802 (http.server naming)
        if self.path.startswith("/_mock/"):
            return self._admin(self.path)
        parts = self.path.split("/", 4)
        if len(parts) < 5 or parts[1] != "ap":
            return _json(self, 404, {"code": "route_unknown"})
        _empty, _ap, caller_key, route, rest = parts
        if not self._check_caller(caller_key):
            return
        upstream_path = "/" + rest.split("?")[0]
        match = CHANNEL_MESSAGES.match(upstream_path) if route == "discord" else None
        if not match:
            return _json(self, 404, {"code": "route_unknown"})
        body = self._read_json()
        with _lock:
            _counter[0] += 1
            request_id = f"req_{_counter[0]:04d}"
            _parked[request_id] = {
                "status": "parked",
                "channel_id": match.group(1),
                "body": body,
                "expires_at": time.monotonic() + TTL,
                "result": None,
            }
        return _json(self, 202, {"request_id": request_id, "status": "parked"})

    def do_GET(self):  # noqa: N802
        parts = self.path.split("/", 4)
        if len(parts) < 4 or parts[1] != "ap":
            return _json(self, 404, {"code": "route_unknown"})
        caller_key, route = parts[2], parts[3]
        if not self._check_caller(caller_key):
            return
        if route == "requests":
            request_id = parts[4] if len(parts) > 4 else ""
            return self._outcome(request_id)
        if route != "discord" or len(parts) < 5:
            return _json(self, 404, {"code": "route_unknown"})
        upstream_path = "/" + parts[4].split("?")[0]
        if CHANNEL_MESSAGES.match(upstream_path):
            return _json(self, 200, [{
                "id": "1570000000000000000",
                "channel_id": upstream_path.split("/")[4],
                "content": "canned message from the mock upstream",
                "author": {"id": "1499476122885423204", "username": "mock-bot"},
            }])
        return _json(self, 404, {"code": "route_unknown"})

    # -- approval outcome + test-only admin ------------------------------
    def _outcome(self, request_id: str) -> None:
        with _lock:
            entry = _parked.get(request_id)
            if entry is None:
                return _json(self, 404, {"code": "request_unknown"})
            if entry["status"] == "parked" and time.monotonic() > entry["expires_at"]:
                entry["status"] = "expired"
            payload = {"request_id": request_id, "status": entry["status"]}
            if entry["status"] == "executed":
                payload["result"] = entry["result"]
            return _json(self, 200, payload)

    def _admin(self, path: str) -> None:
        bits = path.strip("/").split("/")
        if len(bits) != 3 or bits[1] not in ("approve", "deny"):
            return _json(self, 404, {"code": "admin_unknown"})
        action, request_id = bits[1], bits[2]
        with _lock:
            entry = _parked.get(request_id)
            if entry is None or entry["status"] != "parked":
                return _json(self, 409, {"code": "not_parked"})
            if action == "deny":
                entry["status"] = "denied"
            else:
                entry["status"] = "executed"
                entry["result"] = {
                    "status": 201,
                    "body": {
                        "id": "1570000000000000001",
                        "channel_id": entry["channel_id"],
                        "content": entry["body"].get("content", ""),
                        "message_reference": entry["body"].get("message_reference"),
                        "via": "mock-upstream",
                    },
                }
        return _json(self, 200, {"request_id": request_id, "status": entry["status"]})


def main() -> None:
    port = int(os.environ.get("MOCK_PORT", "0"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"MOCK_PORT={server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
