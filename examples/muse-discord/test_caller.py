#!/usr/bin/env python3
"""Tests: caller.py against mock_proxy.py ONLY (a mock of the stage 1 gate).

These tests do NOT run the caller against the real gate, so they do not verify
canonicalization, the Host check, framing, audit or forwarding in crates/. Green
here means the caller follows the contract the mock models (see mock_proxy.py).

Covered:

  1. a granted read passes in the path form (/ap/<key>/discord/...) and in the
     header form (X-AP-Caller-Key), and the caller's Authorization reaches the
     fabricated upstream unchanged,
  2. neither the caller key (header or path) nor any x-ap-* header reaches the
     fabricated upstream,
  3. a write is refused 423 no_grant (stage 1 has no write grant and no hold):
     exit 3, and the caller reads the decision from the body alone,
  4. a bad key is 401 rejected (exit 3); an unknown route is 423 route_unknown,
  5. both key placements at once is 400 caller_key_ambiguous (exit 3),
  6. Discord's own 401 (no Authorization sent) is NOT mistaken for a gate
     refusal: it is an upstream error (exit 2),
  7. a 503 unavailable decision maps to exit 5 and an expired decision to
     exit 4 (stage 2 only; main never sends it), via the pure helper,
  8. an upstream 302 with an external Location is not followed: exit 2 and no
     second request reaches the external server.

No reusable credential material is committed: the caller key below is
generated per run and passed to the mock through its environment.

Run: python3 test_caller.py   (stdlib only, binds loopback ports only)
"""

import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import caller as caller_mod  # noqa: E402

CALLER_KEY = "apk_" + secrets.token_hex(32)
OTHER_KEY = "apk_" + secrets.token_hex(32)
AUTHORIZATION = "Bot test-" + secrets.token_hex(8)  # placeholder, never a real token
CHANNEL = "2222222222222222222"

failures = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


class _ExternalHandler(BaseHTTPRequestHandler):
    """Counting 'external' server: any hit means the caller followed a redirect."""

    hits: list[str] = []

    def log_message(self, *args):
        pass

    def _hit(self):
        type(self).hits.append(self.path)
        body = json.dumps({"status": "external-reached"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _hit
    do_POST = _hit


def start_external() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ExternalHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/steal"


def start_mock(redirect_location: str = "") -> tuple[subprocess.Popen, str]:
    env = dict(os.environ, MOCK_PORT="0", MOCK_CALLER_KEY=CALLER_KEY)
    if redirect_location:
        env["MOCK_REDIRECT_LOCATION"] = redirect_location
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "mock_proxy.py")],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True,
    )
    try:
        port = proc.stdout.readline().strip().split("=", 1)[1]
    except BaseException:
        proc.kill()
        proc.wait(timeout=10)
        raise
    return proc, f"http://127.0.0.1:{port}"


def run_caller(base: str, args: list[str], key: str = CALLER_KEY, placement: str = "path",
               authorization: str | None = AUTHORIZATION, route: str = "discord"):
    env = dict(os.environ, AP_BASE=base, AP_CALLER_KEY=key, AP_KEY_PLACEMENT=placement, AP_ROUTE=route)
    env.pop("AP_AUTHORIZATION", None)
    if authorization is not None:
        env["AP_AUTHORIZATION"] = authorization
    return subprocess.run(
        [sys.executable, os.path.join(HERE, "caller.py"), *args],
        capture_output=True, text=True, env=env, timeout=30,
    )


def http(base: str, method: str, path: str, headers: list[tuple[str, str]] | None = None,
         body: bytes | None = None) -> tuple[int, dict, str]:
    """Raw request with repeatable headers, no redirects."""
    import http.client
    host, port = base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    conn.putrequest(method, path)
    for k, v in headers or []:
        conn.putheader(k, v)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    resp = conn.getresponse()
    out = resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read().decode()
    conn.close()
    return out


def main() -> int:
    external, external_url = start_external()
    mock, base = start_mock(redirect_location=external_url)
    try:
        # 1. Granted read, both placements, Authorization unchanged.
        for placement in ("path", "header"):
            r = run_caller(base, ["request", "GET", "/api/v10/users/@me"], placement=placement)
            seen = json.loads(r.stdout) if r.returncode == 0 else {}
            check(f"{placement} form: granted read succeeds", r.returncode == 0, r.stderr)
            check(f"{placement} form: Authorization reaches upstream unchanged",
                  seen.get("upstream_saw_authorization") == AUTHORIZATION)
            check(f"{placement} form: caller key stays off the upstream request",
                  seen.get("upstream_saw_caller_key_header") is False
                  and seen.get("upstream_saw_key_in_path") is False)
        r = run_caller(base, ["get-messages", CHANNEL, "5"])
        check("get-messages returns the canned upstream message",
              r.returncode == 0 and "canned message" in r.stdout, r.stderr)

        # 3. Write: 423 no_grant, decision readable from the body alone.
        r = run_caller(base, ["send", CHANNEL, "hello"])
        check("send is refused: exit 3", r.returncode == 3, f"rc={r.returncode} {r.stderr}")
        check("refusal names the decision and code", "denied/no_grant" in r.stderr and "423" in r.stderr, r.stderr)
        check("refusal says nothing was sent", "nothing was sent" in r.stderr)
        r = run_caller(base, ["request", "DELETE", f"/api/v10/channels/{CHANNEL}/messages/1"])
        check("DELETE is refused no_grant too", r.returncode == 3 and "no_grant" in r.stderr)

        # Wire shape of a refusal, as the real gate renders it.
        status, headers, text = http(base, "POST", f"/ap/{CALLER_KEY}/discord/api/v10/channels/{CHANNEL}/messages",
                                     [("Authorization", AUTHORIZATION), ("Content-Type", "application/json")], b"{}")
        check("refusal wire shape: 423, X-AP-Decision, two-field JSON body",
              status == 423 and headers.get("x-ap-decision") == "denied"
              and json.loads(text) == {"ap_decision": "denied", "code": "no_grant"}, f"{status} {text}")

        # 4. Bad key, unknown route.
        r = run_caller(base, ["get-messages", CHANNEL], key=OTHER_KEY)
        check("unknown key: 401 rejected, exit 3", r.returncode == 3 and "rejected/caller_rejected" in r.stderr, r.stderr)
        r = run_caller(base, ["get-messages", CHANNEL], route="nowhere")
        check("unknown route: 423 route_unknown, exit 3", r.returncode == 3 and "route_unknown" in r.stderr, r.stderr)

        # 5. Both placements at once.
        status, _h, text = http(base, "GET", f"/ap/{CALLER_KEY}/discord/api/v10/users/@me",
                                [("X-AP-Caller-Key", CALLER_KEY), ("Authorization", AUTHORIZATION)])
        check("both key placements: 400 caller_key_ambiguous",
              status == 400 and json.loads(text)["code"] == "caller_key_ambiguous", f"{status} {text}")
        # A second Authorization header is refused before the grant.
        status, _h, text = http(base, "GET", "/discord/api/v10/users/@me",
                                [("X-AP-Caller-Key", CALLER_KEY), ("Authorization", "a"), ("Authorization", "b")])
        check("duplicate Authorization: 400 authorization_duplicate",
              status == 400 and json.loads(text)["code"] == "authorization_duplicate", f"{status} {text}")

        # 6. Discord's own 401 is not a gate refusal.
        r = run_caller(base, ["get-messages", CHANNEL], authorization=None)
        check("upstream 401 is an upstream error (exit 2), not a gate refusal",
              r.returncode == 2 and "upstream or transport answered 401" in r.stderr, f"rc={r.returncode} {r.stderr}")

        # 8. Redirect not followed.
        r = run_caller(base, ["request", "GET", "/api/v10/channels/redirect-me"])
        check("302 is an error (exit 2)", r.returncode == 2, f"rc={r.returncode} {r.stderr}")
        check("302 is not followed: no request reached the external server", _ExternalHandler.hits == [],
              str(_ExternalHandler.hits))
    finally:
        mock.kill()
        mock.wait(timeout=10)
        external.shutdown()

    # 7. Decision mapping, pure helper (the real gate sends 503 unavailable; expired is stage 2).
    body = lambda d, c: json.dumps({"ap_decision": d, "code": c})  # noqa: E731
    check("gate_decision parses a two-field body", caller_mod.gate_decision(body("denied", "no_grant")) == ("denied", "no_grant"))
    check("gate_decision rejects a Discord error object",
          caller_mod.gate_decision('{"message": "401: Unauthorized", "code": 0}') is None)
    check("gate_decision rejects extra fields",
          caller_mod.gate_decision('{"ap_decision": "denied", "code": "x", "more": 1}') is None)
    check("gate_decision rejects an unknown decision", caller_mod.gate_decision(body("maybe", "x")) is None)
    check("denied and rejected map to exit 3",
          caller_mod.report_refusal(423, "denied", "no_grant") == 3 and caller_mod.report_refusal(401, "rejected", "caller_rejected") == 3)
    check("unavailable maps to exit 5", caller_mod.report_refusal(503, "unavailable", "connect_failed") == 5)
    check("expired maps to exit 4 (stage 2, in review)", caller_mod.report_refusal(410, "expired", "expired") == 4)

    print(f"\n{'ALL PASSED' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
