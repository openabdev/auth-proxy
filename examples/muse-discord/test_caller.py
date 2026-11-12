#!/usr/bin/env python3
"""End-to-end tests: caller.py against mock_proxy.py.

Covers the four outcome paths of the caller contract:

  1. allow-listed read executes immediately (200),
  2. a write parks (202), the owner approves, the caller sees the executed
     upstream response,
  3. a write parks, the owner denies, the caller exits 3,
  4. a write parks, nobody decides, the request expires, the caller exits 4,
  5. a bad surrogate is refused by the proxy (exit 2).

Run: python3 test_caller.py   (stdlib only, binds loopback ports only)
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CALLER_KEY = "apk_c6267244721d31df7f7ab84ca4f5d16ad4d3ef9d6d53b06662cd7dac6704c26c"
SURROGATE = "aps_ac5e3eca49b3e957da4c8709180f7f62a4336de3e14e68faf46df0735a016b03"
CHANNEL = "2222222222222222222"

failures = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def start_mock(ttl: str) -> tuple[subprocess.Popen, str]:
    env = dict(os.environ, MOCK_TTL=ttl, MOCK_PORT="0")
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


def main() -> int:
    mock_a, base_a = start_mock("60")
    mock_b, base_b = start_mock("1.5")
    try:
        # 1. allow-listed read
        res = run_caller(base_a, ["get-messages", CHANNEL, "5"])
        check("read executes immediately", res.returncode == 0 and "canned message" in res.stdout,
              f"rc={res.returncode} out={res.stdout!r} err={res.stderr!r}")

        # 2. park -> approve -> executed
        proc = run_caller(base_a, ["send", CHANNEL, "hello via approval", "--reply-to", "1570000000000000000"], wait=False)
        time.sleep(1.0)
        admin(base_a, "approve", "req_0001")
        out, err = proc.communicate(timeout=30)
        body = json.loads(out) if out.strip() else {}
        check("approved write executes", proc.returncode == 0
              and body.get("content") == "hello via approval"
              and body.get("message_reference", {}).get("message_id") == "1570000000000000000",
              f"rc={proc.returncode} out={out!r} err={err!r}")

        # 3. park -> deny
        proc = run_caller(base_a, ["send", CHANNEL, "never send this"], wait=False)
        time.sleep(1.0)
        admin(base_a, "deny", "req_0002")
        proc.communicate(timeout=30)
        check("denied write exits 3", proc.returncode == 3, f"rc={proc.returncode}")

        # 4. park -> expire (short-TTL mock)
        res = run_caller(base_b, ["send", CHANNEL, "too slow"])
        check("expired write exits 4", res.returncode == 4, f"rc={res.returncode} err={res.stderr!r}")

        # 5. bad surrogate refused
        res = run_caller(base_a, ["get-messages", CHANNEL], surrogate="aps_" + "0" * 64)
        check("bad surrogate refused (exit 2)", res.returncode == 2 and "surrogate_unknown" in res.stderr,
              f"rc={res.returncode} err={res.stderr!r}")
    finally:
        mock_a.terminate()
        mock_b.terminate()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
