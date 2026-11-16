#!/usr/bin/env python3
"""Mock auth-proxy -- CONTRACT SKETCH for issue #5, NOT the real proxy.
Requires Python 3.11+ (stdlib only).

This mock is a contract sketch for the approval flow proposed in #5/#6.
It is NOT a stand-in that verifies the real proxy: it deliberately omits
canonicalization, policy evaluation, the session registry, audit and
upstream forwarding (see "Simplifications" below). Tests that pass against
this mock therefore say little about the real proxy in crates/ -- they only
exercise caller.py against this sketched contract. Once #5 settles the
approval contract, this mock should be re-derived from that spec, and a
separate test should run the caller against the real proxy.

Implements just enough of the caller-facing shape to exercise caller.py:

  * /ap/<caller-key>/<route><path> addressing and caller-key checking
    (sha256 compared, like crates/ap-proxy/src/pipeline.rs),
  * the surrogate in "Authorization: Bearer aps_..." form,
  * an allow-listed read answered with canned upstream data,
  * the proposed approval flow: a write is parked with
    "202 + X-Auth-Proxy-Approval: parked + request_id", and
    GET /ap/<caller-key>/_approval/<request-id> reports
    parked / executed / denied / expired. The poll segment is "_approval":
    "_" is rejected by valid_slug for route names, so it cannot collide
    with a configured route. A bare 202 without the marker
    header is NOT a parked request (caller.py returns it as upstream data);
    the fabricated upstream answers POST /api/v10/async-accepted with a
    bare 202 so tests can exercise that path. The fabricated upstream also
    answers /api/v10/redirect-me (GET or POST) with a 302 whose Location
    is MOCK_REDIRECT_LOCATION, so tests can exercise the caller's
    no-redirect transport: the caller must treat the 302 as an error and
    must not make a second request to that Location.

Simplifications, deliberately: one identity, one route, one registered
surrogate, no canonicalization, no policy evaluation, no registry, no
audit, and parked requests live in memory. The "upstream" is fabricated;
no Discord call ever happens, and the mock "executes" a parked write by
inventing the upstream response.

No reusable credential material is committed in this file. The caller key
and surrogate are ephemeral: test_caller.py generates them with
secrets.token_hex(32) and passes them in via the environment; a manual run
generates fresh ones at startup and prints them.

Test-only admin endpoints (NOT part of the proposed contract; they stand in
for the owner's approval plane):

  POST /_mock/approve/<request-id>     approve and "execute" the parked write
  POST /_mock/deny/<request-id>        deny it
  POST /_mock/revoke/<surrogate-sha256>  unregister a surrogate and drop
                                       every request it parked
  GET  /_mock/parked                   ids of currently parked requests, so
                                       tests can discover ids instead of
                                       sleeping and guessing them

Every /_mock/ route requires the per-run admin token in the
"X-Mock-Admin" header (compared in constant time). Without it, anything
that can reach the caller listener could approve a parked write.

Approval semantics sketched here (all still open in #5):

  * Expiry is enforced under the lock before EVERY list, approve, deny
    and outcome operation, so a request past its TTL can never be
    approved, whether or not the caller is still polling.
  * A parked request is bound to the surrogate (session) that created
    it. Polling it with any other surrogate answers 404, the same as an
    unknown id.
  * Revoking a surrogate drops its parked requests.
  * Request ids are unguessable (128 random bits), not a counter.

Environment:
  MOCK_TTL         seconds a parked request awaits a decision (default 60)
  MOCK_PORT        port to bind, 0 = ephemeral (default 0); the bound port is
                   printed as "MOCK_PORT=<port>" on stdout, followed by the
                   ephemeral MOCK_CALLER_KEY / MOCK_SURROGATE in use.
  MOCK_CALLER_KEY  apk_... caller key to accept (default: generated)
  MOCK_SURROGATE   aps_... surrogate to accept  (default: generated)
  MOCK_SURROGATE_2 optional second aps_... surrogate (a second session),
                   used by the two-session isolation tests
  MOCK_ADMIN_TOKEN token required by /_mock/ routes (default: generated)
  MOCK_REDIRECT_LOCATION  Location returned by the fabricated
                   /api/v10/redirect-me endpoint (default:
                   https://example.invalid/steal); tests point it at a
                   local counting server to assert no second request.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Ephemeral key material only -- nothing reusable is committed here.
EXAMPLE_CALLER_KEY = os.environ.get("MOCK_CALLER_KEY") or ("apk_" + secrets.token_hex(32))
EXAMPLE_SURROGATE = os.environ.get("MOCK_SURROGATE") or ("aps_" + secrets.token_hex(32))
CALLER_SHA256 = hashlib.sha256(EXAMPLE_CALLER_KEY.encode()).hexdigest()
EXAMPLE_SURROGATE_2 = os.environ.get("MOCK_SURROGATE_2") or ""
ADMIN_TOKEN = os.environ.get("MOCK_ADMIN_TOKEN") or secrets.token_hex(32)
SURROGATE_FORM = re.compile(r"^Bearer (aps_[0-9a-f]{64})$")
CHANNEL_MESSAGES = re.compile(r"^/api/v10/channels/(\d+)/messages$")

TTL = float(os.environ.get("MOCK_TTL", "60"))
REDIRECT_LOCATION = os.environ.get("MOCK_REDIRECT_LOCATION", "https://example.invalid/steal")
_lock = threading.Lock()
_parked: dict[str, dict] = {}
# Registered surrogates (sha256 hex), the mock's stand-in for the registry.
_surrogates: set[str] = {hashlib.sha256(EXAMPLE_SURROGATE.encode()).hexdigest()}
if EXAMPLE_SURROGATE_2:
    _surrogates.add(hashlib.sha256(EXAMPLE_SURROGATE_2.encode()).hexdigest())


def _expire_locked(now: float) -> None:
    """The one deadline transition. Callers hold _lock and call this before
    any list, approve, deny or outcome operation."""
    for entry in _parked.values():
        if entry["status"] == "parked" and now > entry["expires_at"]:
            entry["status"] = "expired"


def _json(handler: BaseHTTPRequestHandler, status: int, payload, extra_headers: dict | None = None) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    for key, value in (extra_headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def _redirect(handler: BaseHTTPRequestHandler, location: str) -> None:
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


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

    def _check_caller(self, caller_key: str) -> str | None:
        """Return the session id (surrogate sha256) or None after answering."""
        digest = hashlib.sha256(caller_key.encode()).hexdigest()
        if digest != CALLER_SHA256:
            _json(self, 403, {"code": "caller_rejected"})
            return None
        match = SURROGATE_FORM.match(self.headers.get("Authorization") or "")
        if not match:
            _json(self, 403, {"code": "surrogate_malformed"})
            return None
        session = hashlib.sha256(match.group(1).encode()).hexdigest()
        with _lock:
            registered = session in _surrogates
        if not registered:
            _json(self, 403, {"code": "surrogate_unknown"})
            return None
        return session

    def _check_admin(self) -> bool:
        supplied = self.headers.get("X-Mock-Admin") or ""
        if not hmac.compare_digest(supplied.encode(), ADMIN_TOKEN.encode()):
            _json(self, 403, {"code": "admin_rejected"})
            return False
        return True

    # -- routing ---------------------------------------------------------
    def do_POST(self):  # noqa: N802 (http.server naming)
        if self.path.startswith("/_mock/"):
            if not self._check_admin():
                return
            return self._admin(self.path)
        parts = self.path.split("/", 4)
        if len(parts) < 5 or parts[1] != "ap":
            return _json(self, 404, {"code": "route_unknown"})
        _empty, _ap, caller_key, route, rest = parts
        session = self._check_caller(caller_key)
        if session is None:
            return
        upstream_path = "/" + rest.split("?")[0]
        if route == "discord" and upstream_path == "/api/v10/redirect-me":
            # Fabricated upstream endpoint that answers 302 with an
            # external Location: the caller must not follow it (its
            # surrogate Authorization header would leave the proxy).
            return _redirect(self, REDIRECT_LOCATION)
        if route == "discord" and upstream_path == "/api/v10/async-accepted":
            # Fabricated upstream endpoint that legitimately answers a bare
            # 202 (no approval marker): the caller must return it as data.
            return _json(self, 202, {"status": "accepted", "via": "mock-upstream"})
        if route == "discord" and upstream_path == "/api/v10/marker-collision":
            # Fabricated HOSTILE upstream: it answers 202 with the same
            # marker header and a request id of its choosing. Nothing in
            # this mock strips it. The real proxy must (see README, #5).
            return _json(self, 202, {"request_id": "req_" + "ab" * 16, "status": "parked"},
                         extra_headers={"X-Auth-Proxy-Approval": "parked"})
        match = CHANNEL_MESSAGES.match(upstream_path) if route == "discord" else None
        if not match:
            return _json(self, 404, {"code": "route_unknown"})
        body = self._read_json()
        with _lock:
            _expire_locked(time.monotonic())
            request_id = "req_" + secrets.token_hex(16)
            _parked[request_id] = {
                "session": session,
                "status": "parked",
                "channel_id": match.group(1),
                "body": body,
                "expires_at": time.monotonic() + TTL,
                "result": None,
            }
        # Proposed #5 marker: parked responses carry the proxy-owned header
        # in addition to the 202 status, so a bare upstream 202 is not
        # mistaken for a parked request.
        return _json(self, 202, {"request_id": request_id, "status": "parked"},
                     extra_headers={"X-Auth-Proxy-Approval": "parked"})

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/_mock/"):
            return self._admin_get(self.path)
        parts = self.path.split("/", 4)
        if len(parts) < 4 or parts[1] != "ap":
            return _json(self, 404, {"code": "route_unknown"})
        caller_key, route = parts[2], parts[3]
        session = self._check_caller(caller_key)
        if session is None:
            return
        if route == "_approval":
            request_id = parts[4] if len(parts) > 4 else ""
            return self._outcome(request_id, session)
        if route != "discord" or len(parts) < 5:
            return _json(self, 404, {"code": "route_unknown"})
        upstream_path = "/" + parts[4].split("?")[0]
        if upstream_path == "/api/v10/redirect-me":
            return _redirect(self, REDIRECT_LOCATION)
        if CHANNEL_MESSAGES.match(upstream_path):
            return _json(self, 200, [{
                "id": "1570000000000000000",
                "channel_id": upstream_path.split("/")[4],
                "content": "canned message from the mock upstream",
                "author": {"id": "9999999999999999001", "username": "mock-bot"},
            }])
        return _json(self, 404, {"code": "route_unknown"})

    # -- approval outcome + test-only admin ------------------------------
    def _admin_get(self, path: str) -> None:
        if not self._check_admin():
            return
        if path.strip("/") == "_mock/parked":
            with _lock:
                _expire_locked(time.monotonic())
                ids = [rid for rid, e in _parked.items() if e["status"] == "parked"]
            return _json(self, 200, {"parked": ids})
        return _json(self, 404, {"code": "admin_unknown"})

    def _outcome(self, request_id: str, session: str) -> None:
        with _lock:
            _expire_locked(time.monotonic())
            entry = _parked.get(request_id)
            # Another session's id answers exactly like an unknown id.
            if entry is None or entry["session"] != session:
                return _json(self, 404, {"code": "request_unknown"})
            payload = {"request_id": request_id, "status": entry["status"]}
            if entry["status"] == "executed":
                payload["result"] = entry["result"]
            return _json(self, 200, payload)

    def _admin(self, path: str) -> None:
        bits = path.strip("/").split("/")
        if len(bits) != 3 or bits[1] not in ("approve", "deny", "revoke"):
            return _json(self, 404, {"code": "admin_unknown"})
        action, request_id = bits[1], bits[2]
        if action == "revoke":
            with _lock:
                _surrogates.discard(request_id)
                for rid in [r for r, e in _parked.items() if e["session"] == request_id]:
                    del _parked[rid]
            return _json(self, 200, {"revoked": request_id})
        with _lock:
            _expire_locked(time.monotonic())
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
    print(f"MOCK_CALLER_KEY={EXAMPLE_CALLER_KEY}", flush=True)
    print(f"MOCK_SURROGATE={EXAMPLE_SURROGATE}", flush=True)
    print(f"MOCK_ADMIN_TOKEN={ADMIN_TOKEN}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
