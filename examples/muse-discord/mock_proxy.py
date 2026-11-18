#!/usr/bin/env python3
"""Mock of the Muse gate, stage 1 -- NOT the real proxy.
Requires Python 3.11+ (stdlib only).

This mock models the caller-facing contract of the passthrough gate that is
merged on main (stage 1; crates/ap-proxy/src/passthrough.rs, design in
docs/design/muse-gated-passthrough.md, measurements in
docs/evidence/muse-stage1.md). It exists so caller.py can be exercised without
a Rust build. It is not a stand-in that verifies the real gate: it omits
canonicalization, the `Host` check, framing checks, body limits, audit and
evidence lines, TLS and real upstream forwarding. A green run here says the
caller follows the contract the mock sketches, nothing more.

What it models, in the order the real gate applies it:

  1. Caller key from exactly one place: the X-AP-Caller-Key header, or the
     /ap/<caller-key>/ path prefix (stripped before routing). Both present is
     400 caller_key_ambiguous. A missing, malformed or unknown key is 401
     caller_rejected. The key is compared by sha256. The path form mirrors
     canon::parse_ap_path: /ap/<key> with no slash after the key is 401
     caller_rejected, /ap/<key>/ is authenticated and then 423 route_unknown.
  2. Route name from the first path segment ([a-z0-9-]{1,32}). An unknown
     route, with the names read from the policy's [[route]] tables, is 423
     route_unknown.
  3. More than one Authorization header is 400 authorization_duplicate.
  4. Grant: the policy is read from deploy/muse/pilot-policy.example.toml
     (override with MOCK_POLICY): a method match plus a raw starts_with on the
     route-relative path. Anything not granted, writes included, is 423
     no_grant. There is NO hold and NO approval flow: that is stage 2 and is
     still in review, so it is deliberately absent here.
  5. A granted request is answered by a fabricated upstream. The caller's
     Authorization passes through unchanged; the caller-key header and every
     x-ap-* header are not forwarded. /api/v10/users/@me echoes what the
     upstream saw so tests can prove both.

Every refusal the mock generates carries X-AP-Decision and the two-field JSON
body {"ap_decision": ..., "code": ...}, the same shape as the real gate
(ap_core::outcome::render_passthrough). Discord's own answers carry no
X-AP-Decision.

No reusable credential material is committed: the caller key is generated
at startup (or passed in MOCK_CALLER_KEY by the tests) and printed.

Environment:
  MOCK_PORT        port to bind, 0 = ephemeral (default 0); the bound port is
                   printed as "MOCK_PORT=<port>" on stdout, followed by the
                   MOCK_CALLER_KEY in use.
  MOCK_CALLER_KEY  apk_... caller key to accept (default: generated)
  MOCK_POLICY      policy file to read grants from
  MOCK_REDIRECT_LOCATION  Location returned by the fabricated
                   /api/v10/channels/redirect-me endpoint (default:
                   https://example.invalid/steal); tests point it at a local
                   counting server to assert the caller makes no second
                   request.
"""

import hashlib
import json
import os
import re
import secrets
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY = os.path.join(HERE, "..", "..", "deploy", "muse", "pilot-policy.example.toml")

CALLER_KEY = os.environ.get("MOCK_CALLER_KEY") or ("apk_" + secrets.token_hex(32))
CALLER_SHA256 = hashlib.sha256(CALLER_KEY.encode()).hexdigest()
KEY_RE = re.compile(r"^apk_[0-9a-f]{64}$")
KEY_HEADER = "x-ap-caller-key"
REDIRECT_LOCATION = os.environ.get("MOCK_REDIRECT_LOCATION", "https://example.invalid/steal")

# (status, X-AP-Decision), as in ap_core::outcome::passthrough_outcome.
OUTCOMES = {
    "no_grant": (423, "denied"),
    "route_unknown": (423, "denied"),
    "caller_rejected": (401, "rejected"),
    "caller_key_ambiguous": (400, "denied"),
    "authorization_duplicate": (400, "denied"),
}


def load_grants(path: str) -> list[dict]:
    with open(path, "rb") as fh:
        return tomllib.load(fh).get("grant", [])


def load_routes(path: str) -> set[str]:
    with open(path, "rb") as fh:
        return {r["name"] for r in tomllib.load(fh).get("route", []) if "name" in r}


_POLICY_PATH = os.environ.get("MOCK_POLICY") or DEFAULT_POLICY
GRANTS = load_grants(_POLICY_PATH)
ROUTES = load_routes(_POLICY_PATH)
ROUTE_NAME_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def parse_ap_path(path: str) -> tuple[str, str]:
    """Mirror of ap_core::canon::parse_ap_path plus the gate's handling of its
    errors. Returns (key, path after the key). Raises KeyError(code).

    `/ap/<key>` with no `/` after the key is caller_rejected (split_once fails);
    `/ap/<key>/` is a well formed key with no route, authenticated first and
    then route_unknown."""
    rest = path[len("/ap/"):]
    if "/" not in rest:
        raise KeyError("caller_rejected")
    key, _after = rest.split("/", 1)
    if not KEY_RE.match(key):
        raise KeyError("caller_rejected")
    return key, path[len("/ap/") + len(key):]


def granted(route: str, method: str, path: str) -> bool:
    """Policy::evaluate for a passthrough grant: route and method match, and the
    route-relative path starts with one of the grant's paths (raw starts_with).
    The mock has one identity, so the identity column is not modelled."""
    return any(
        g["route"] == route
        and method in g["methods"]
        and any(path.startswith(p) for p in g["paths"])
        for g in GRANTS
    )


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes, headers: dict) -> None:
    handler.send_response(status)
    for key, value in headers.items():
        handler.send_header(key, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def refuse(handler: BaseHTTPRequestHandler, code: str) -> None:
    status, decision = OUTCOMES[code]
    body = json.dumps({"ap_decision": decision, "code": code}, separators=(",", ":")).encode()
    _send(handler, status, body, {"Content-Type": "application/json", "X-AP-Decision": decision})


def upstream_json(handler: BaseHTTPRequestHandler, status: int, payload) -> None:
    # A fabricated Discord answer: no X-AP-Decision.
    _send(handler, status, json.dumps(payload).encode(), {"Content-Type": "application/json"})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # drained; the gate never looks at the body
        split = self.path.split("?", 1)
        path = split[0]

        # 1. Caller key from exactly one place.
        header_keys = self.headers.get_all(KEY_HEADER) or []
        path_form = path.startswith("/ap/")
        if header_keys and path_form:
            return refuse(self, "caller_key_ambiguous")
        if path_form:
            try:
                key, path = parse_ap_path(path)
            except KeyError as code:
                return refuse(self, code.args[0])
        elif len(header_keys) == 1:
            key = header_keys[0]
        else:
            return refuse(self, "caller_rejected")
        if not KEY_RE.match(key) or hashlib.sha256(key.encode()).hexdigest() != CALLER_SHA256:
            return refuse(self, "caller_rejected")

        # 2. Route name in the path (canon::parse_route_path: [a-z0-9-]{1,32}).
        rest = path[1:] if path.startswith("/") else None
        if rest is None:
            return refuse(self, "route_unknown")
        route, _, tail = rest.partition("/")
        rel = "/" + tail if "/" in rest else "/"
        if not ROUTE_NAME_RE.match(route) or route not in ROUTES:
            return refuse(self, "route_unknown")

        # 3. One Authorization header at most.
        authorization = self.headers.get_all("Authorization") or []
        if len(authorization) > 1:
            return refuse(self, "authorization_duplicate")

        # 4. Grant. Everything not granted is 423 no_grant (no hold on main).
        if not granted(route, self.command, rel):
            return refuse(self, "no_grant")

        # 5. Fabricated upstream. The caller's Authorization is forwarded as is.
        if rel == "/api/v10/channels/redirect-me":
            self.send_response(302)
            self.send_header("Location", REDIRECT_LOCATION)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # What the caller SENT (raw request), apart from what the gate forwards.
        raw_target = self.path
        sent_key_headers = [k for k, v in self.headers.items() if CALLER_KEY in v]
        forwarded = [(k, v) for k, v in self.headers.items() if not k.lower().startswith("x-ap-")]
        if rel == "/api/v10/users/@me":
            return upstream_json(self, 200, {
                # A boolean, not the value: the caller scrubs its stdout, so the
                # header is compared here against the value the test passed in.
                "upstream_authorization_matches": bool(authorization)
                and authorization[0] == os.environ.get("MOCK_EXPECT_AUTHORIZATION", ""),
                # The gate removes the caller-key header and every x-ap-* header.
                # Computed from the forwarded values, so a key smuggled into any
                # other header is visible here.
                "upstream_saw_caller_key_header": any(
                    k.lower() == KEY_HEADER or CALLER_KEY in v for k, v in forwarded),
                "upstream_saw_key_in_path": "apk_" in self.path.replace(
                    "/ap/" + CALLER_KEY, "", 1) if path_form else "apk_" in self.path,
                # Raw request, before the mock's own stripping.
                "caller_sent_key_header_names": [k.lower() for k in sent_key_headers],
                "caller_sent_key_in_query": CALLER_KEY in (split[1] if len(split) > 1 else ""),
                "caller_sent_key_in_target_after_prefix": CALLER_KEY in (
                    raw_target.replace("/ap/" + CALLER_KEY, "", 1) if path_form else raw_target),
            })
        match = re.match(r"^/api/v10/channels/(\d+)/messages$", rel)
        if match and not authorization:
            # Discord's own 401; it carries no X-AP-Decision.
            return upstream_json(self, 401, {"message": "401: Unauthorized", "code": 0})
        if match:
            return upstream_json(self, 200, [{
                "id": "1570000000000000000",
                "channel_id": match.group(1),
                "content": "canned message from the mock upstream",
                "author": {"id": "9999999999999999001", "username": "mock-bot"},
            }])
        return upstream_json(self, 404, {"message": "404: Not Found", "code": 0})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle  # noqa: N815


def main() -> None:
    port = int(os.environ.get("MOCK_PORT", "0"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"MOCK_PORT={server.server_address[1]}", flush=True)
    print(f"MOCK_CALLER_KEY={CALLER_KEY}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
