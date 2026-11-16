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

Parked request ids are discovered by polling the mock's test-only
/_mock/parked endpoint -- never by sleeping a fixed time and guessing
an id.

No reusable credential material is committed: the caller key and surrogate
below are generated ephemerally per run with secrets.token_hex(32) and
passed to the mock at startup via its environment.

Run: python3 test_caller.py   (stdlib only, binds loopback ports only)
"""

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CALLER_KEY = "apk_" + secrets.token_hex(32)
SURROGATE = "aps_" + secrets.token_hex(32)
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
               MOCK_CALLER_KEY=CALLER_KEY, MOCK_SURROGATE=SURROGATE)
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


def admin(base: str, action: str, request_id: str) -> dict:
    req = urllib.request.Request(f"{base}/_mock/{action}/{request_id}", data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def wait_parked(base: str, known: set[str], timeout: float = 10.0) -> str | None:
    """Poll the mock until a new request is parked; return its id."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/_mock/parked", timeout=5) as resp:
                ids = json.loads(resp.read()).get("parked", [])
        except Exception:
            ids = []
        fresh = [rid for rid in ids if rid not in known]
        if fresh:
            return fresh[0]
        time.sleep(0.1)
    return None


def main() -> int:
    external, external_location = start_external()
    mock_a, base_a = start_mock("60", redirect_location=external_location)
    mock_b, base_b = start_mock("1.5")
    try:
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
    finally:
        mock_a.terminate()
        mock_b.terminate()
        external.shutdown()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
