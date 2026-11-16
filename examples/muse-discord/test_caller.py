#!/usr/bin/env python3
"""Tests: caller.py against mock_proxy.py ONLY (contract sketch for #5).

These tests exercise the mock, which is a contract sketch for the proposed
#5 approval flow -- they do NOT run the caller against the real proxy and
therefore do not verify canonicalization, policy evaluation, the session
registry, audit or upstream forwarding in crates/. Green here means the
caller follows the sketched contract, not that the real proxy behaves
the same way.

Covers the outcome paths of the sketched caller contract:

  1. allow-listed read executes immediately (200),
  2. a write parks (marked 202), the owner approves, the caller sees the
     executed upstream response,
  3. a write parks, the owner denies, the caller exits 3,
  4. a write parks, nobody decides, the request expires, the caller exits 4,
  5. a bad surrogate is refused by the mock (exit 2),
  6. a bare upstream 202 without the approval marker is returned as
     ordinary data, not mistaken for a parked request.
  7. an upstream 302 with an external Location is treated as an error
     (exit 2) and is NOT followed: no second request reaches the
     external server, so the surrogate never leaves the proxy.

  8. expiry is enforced without polling: after MOCK_TTL a parked request
     can no longer be approved (409) and is reported expired (H-1),
  9. a colliding approval marker coming from the UPSTREAM does not make
     the caller execute anything: the fabricated request id is unknown to
     the proxy, the poll answers 404 and the caller exits 2 (the real
     proxy must also strip the header, see README / #5),
 10. polling is bound to the creating session: a second surrogate cannot
     read another session's parked request, ids are unguessable, and
     revoking a surrogate drops what it parked.

Parked request ids are discovered by polling the mock's test-only
/_mock/parked endpoint -- never by sleeping a fixed time and guessing
an id.

No reusable credential material is committed: the caller key and surrogate
below are generated ephemerally per run with secrets.token_hex(32) and
passed to the mock at startup via its environment.

Run: python3 test_caller.py   (stdlib only, binds loopback ports only)
"""

import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CALLER_KEY = "apk_" + secrets.token_hex(32)
SURROGATE = "aps_" + secrets.token_hex(32)
SURROGATE_2 = "aps_" + secrets.token_hex(32)
ADMIN_TOKEN = secrets.token_hex(32)
CHANNEL = "2222222222222222222"

failures = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


class _ExternalHandler(BaseHTTPRequestHandler):
    """Counting 'external' server: any hit means the caller followed a
    redirect and sent a second request (with the surrogate) outside."""

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


def start_mock(ttl: str, redirect_location: str = "") -> tuple[subprocess.Popen, str]:
    env = dict(os.environ, MOCK_TTL=ttl, MOCK_PORT="0",
               MOCK_CALLER_KEY=CALLER_KEY, MOCK_SURROGATE=SURROGATE,
               MOCK_SURROGATE_2=SURROGATE_2, MOCK_ADMIN_TOKEN=ADMIN_TOKEN)
    if redirect_location:
        env["MOCK_REDIRECT_LOCATION"] = redirect_location
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "mock_proxy.py")],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True,
    )
    line = proc.stdout.readline()
    port = line.strip().split("=", 1)[1]
    return proc, f"http://127.0.0.1:{port}"


def run_caller(base: str, args: list[str], surrogate: str = SURROGATE,
               wait: bool = True) -> subprocess.Popen | subprocess.CompletedProcess:
    env = dict(os.environ, AP_BASE=base, AP_CALLER_KEY=CALLER_KEY,
               AP_SURROGATE=surrogate, AP_POLL_INTERVAL="0.3", AP_POLL_TIMEOUT="15")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "caller.py"), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True,
    )
    if wait:
        out, err = proc.communicate(timeout=30)
        return subprocess.CompletedProcess(args, proc.returncode, out, err)
    return proc


def http(base: str, method: str, path: str, headers: dict | None = None,
         body: dict | None = None) -> tuple[int, dict, dict]:
    """Raw call to the mock; returns (status, lower-cased headers, json body)."""
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, json.loads(err.read() or b"{}")


def admin_call(base: str, method: str, path: str, token: str = ADMIN_TOKEN) -> tuple[int, dict, dict]:
    return http(base, method, path, {"X-Mock-Admin": token})


def admin(base: str, action: str, request_id: str) -> dict:
    return admin_call(base, "POST", f"/_mock/{action}/{request_id}")[2]


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def write_as(base: str, surrogate: str) -> str:
    """Park one write as the given session and return its request id."""
    status, headers, body = http(
        base, "POST", f"/ap/{CALLER_KEY}/discord/api/v10/channels/{CHANNEL}/messages",
        {"Authorization": f"Bearer {surrogate}", "Content-Type": "application/json"}, {"content": "x"})
    assert status == 202 and headers.get("x-auth-proxy-approval") == "parked", (status, body)
    return body["request_id"]


def poll_as(base: str, surrogate: str, request_id: str) -> tuple[int, dict]:
    status, _h, body = http(base, "GET", f"/ap/{CALLER_KEY}/_approval/{request_id}",
                            {"Authorization": f"Bearer {surrogate}"})
    return status, body


def wait_parked(base: str, known: set[str], timeout: float = 10.0) -> str | None:
    """Poll the mock until a new request is parked; return its id."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ids = admin_call(base, "GET", "/_mock/parked")[2].get("parked", [])
        except Exception:
            ids = []
        fresh = [rid for rid in ids if rid not in known]
        if fresh:
            return fresh[0]
        time.sleep(0.1)
    return None


def main() -> int:
    external = mock_a = mock_b = None
    try:
        external, external_location = start_external()
        mock_a, base_a = start_mock("60", redirect_location=external_location)
        mock_b, base_b = start_mock("1.5")
        # 1. allow-listed read
        res = run_caller(base_a, ["get-messages", CHANNEL, "5"])
        check("read executes immediately", res.returncode == 0 and "canned message" in res.stdout,
              f"rc={res.returncode} out={res.stdout!r} err={res.stderr!r}")

        # 2. park -> approve -> executed
        seen: set[str] = set()
        proc = run_caller(base_a, ["send", CHANNEL, "hello via approval", "--reply-to", "1570000000000000000"], wait=False)
        rid = wait_parked(base_a, seen)
        check("write parks for approval", rid is not None)
        if rid is not None:
            seen.add(rid)
            admin(base_a, "approve", rid)
        out, err = proc.communicate(timeout=30)
        body = json.loads(out) if out.strip() else {}
        check("approved write executes", proc.returncode == 0
              and body.get("content") == "hello via approval"
              and body.get("message_reference", {}).get("message_id") == "1570000000000000000",
              f"rc={proc.returncode} out={out!r} err={err!r}")

        # 3. park -> deny
        proc = run_caller(base_a, ["send", CHANNEL, "never send this"], wait=False)
        rid = wait_parked(base_a, seen)
        check("second write parks for approval", rid is not None)
        if rid is not None:
            seen.add(rid)
            admin(base_a, "deny", rid)
        proc.communicate(timeout=30)
        check("denied write exits 3", proc.returncode == 3, f"rc={proc.returncode}")

        # 4. park -> expire (short-TTL mock)
        res = run_caller(base_b, ["send", CHANNEL, "too slow"])
        check("expired write exits 4", res.returncode == 4, f"rc={res.returncode} err={res.stderr!r}")

        # 5. bad surrogate refused
        res = run_caller(base_a, ["get-messages", CHANNEL], surrogate="aps_" + "0" * 64)
        check("bad surrogate refused (exit 2)", res.returncode == 2 and "surrogate_unknown" in res.stderr,
              f"rc={res.returncode} err={res.stderr!r}")

        # 6. bare upstream 202 (no approval marker) is ordinary data
        res = run_caller(base_a, ["request", "POST", "/api/v10/async-accepted"])
        check("bare upstream 202 returned as data", res.returncode == 0 and "accepted" in res.stdout,
              f"rc={res.returncode} out={res.stdout!r} err={res.stderr!r}")

        # 7. upstream 302 with an external Location is not followed
        _ExternalHandler.hits.clear()
        res = run_caller(base_a, ["request", "GET", "/api/v10/redirect-me"])
        check("redirect treated as error (exit 2)", res.returncode == 2,
              f"rc={res.returncode} out={res.stdout!r} err={res.stderr!r}")
        check("no second request to external Location", _ExternalHandler.hits == [],
              f"hits={_ExternalHandler.hits!r}")

        # 8. H-1: expiry holds with no caller polling at all
        rid = write_as(base_b, SURROGATE)
        time.sleep(2.2)  # past MOCK_TTL=1.5, and nobody polls
        status, _h, body = admin_call(base_b, "POST", f"/_mock/approve/{rid}")
        check("approve after TTL is rejected (no polling happened)", status == 409, f"{status} {body}")
        check("expired request is not listed as parked",
              rid not in admin_call(base_b, "GET", "/_mock/parked")[2].get("parked", []))
        status, body = poll_as(base_b, SURROGATE, rid)
        check("expired request reports expired and never executed",
              status == 200 and body.get("status") == "expired" and "result" not in body, f"{status} {body}")
        rid = write_as(base_b, SURROGATE)
        time.sleep(2.2)
        status, _h, body = admin_call(base_b, "POST", f"/_mock/deny/{rid}")
        check("deny after TTL is rejected too", status == 409, f"{status} {body}")

        # 9. colliding marker from the upstream is not trusted
        res = run_caller(base_a, ["request", "POST", "/api/v10/marker-collision"])
        check("colliding upstream marker: caller exits 2, executes nothing",
              res.returncode == 2 and "404" in res.stderr and not res.stdout.strip(),
              f"rc={res.returncode} out={res.stdout!r} err={res.stderr!r}")

        # 10. polling bound to the creating session; ids unguessable
        rid1 = write_as(base_a, SURROGATE)
        rid2 = write_as(base_a, SURROGATE)
        check("request ids are unguessable (not a counter)",
              rid1 != rid2 and len(rid1) >= 32 and rid1[4:] != "0001", rid1)
        status, body = poll_as(base_a, SURROGATE_2, rid1)
        check("second surrogate cannot poll another session's request",
              status == 404 and "status" not in body, f"{status} {body}")
        status, body = poll_as(base_a, SURROGATE, rid1)
        check("creating surrogate can poll its own request",
              status == 200 and body.get("status") == "parked", f"{status} {body}")
        # revoke the SECOND session after it parks something of its own
        rid_s2 = write_as(base_a, SURROGATE_2)
        admin_call(base_a, "POST", f"/_mock/revoke/{sha(SURROGATE_2)}")
        check("revoked surrogate's parked request is dropped",
              rid_s2 not in admin_call(base_a, "GET", "/_mock/parked")[2].get("parked", []))
        status, _h, body = admin_call(base_a, "POST", f"/_mock/approve/{rid_s2}")
        check("revoked session's request can no longer be approved", status == 409, f"{status} {body}")
        status, _h, body = http(base_a, "GET", f"/ap/{CALLER_KEY}/_approval/{rid_s2}",
                                {"Authorization": f"Bearer {SURROGATE_2}"})
        check("revoked surrogate is refused", status == 403, f"{status} {body}")
        status, body = poll_as(base_a, SURROGATE, rid2)
        check("other session's requests survive the revoke",
              status == 200 and body.get("status") == "parked", f"{status} {body}")

        # L-5: the admin routes are not open to the caller listener
        status, _h, _b = admin_call(base_a, "POST", f"/_mock/approve/{rid2}", token="wrong")
        check("admin route without the run token is refused", status == 403, str(status))
        status, _h, _b = http(base_a, "GET", "/_mock/parked")
        check("admin list without a token is refused", status == 403, str(status))
    finally:
        for proc in (mock_a, mock_b):
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=10)
        if external is not None:
            external.shutdown()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
