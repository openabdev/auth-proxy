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
     exit 4 (stage 2; main sends it only from its measurement probe), via the pure helper,
  8. an upstream 302 with an external Location is not followed: exit 2 and no
     second request reaches the external server,
  9. the mock mirrors parse_ap_path: /ap/<key> is 401 caller_rejected and
     /ap/<key>/ is 423 route_unknown,
 10. a malformed AP_BASE (whitespace, control characters, fragment, query,
     userinfo, bad scheme, a base path, bad port) is exit 64 before any URL
     with the key exists,
 11. a table of failure modes (refusals, aborted or truncated connections,
     a bad status line, a connection closed mid-request, oversized or
     non-JSON bodies, forced exceptions of every transport class, an
     unexpected exception) checks the exit code and that neither the caller
     key nor "/ap/" ever reaches stdout or stderr, and no traceback is shown,
 12. response bodies are capped on the success and the HTTP error path.

No reusable credential material is committed: the caller key below is
generated per run and passed to the mock through its environment.

Run: python3 test_caller.py   (stdlib only, binds loopback ports only)
"""

import contextlib
import io
import json
import os
import secrets
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http import client as http_client
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


def start_raw_server(behave, partial: bool = False) -> socketserver.ThreadingTCPServer:
    """A server that speaks (or abuses) HTTP by hand. `partial` closes the
    socket after reading only the first bytes of the request."""

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            conn = self.request
            conn.settimeout(5)
            try:
                if partial:
                    conn.recv(8)
                    conn.shutdown(socket.SHUT_RDWR)
                    return
                req = b""
                while b"\r\n\r\n" not in req:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    req += chunk
                behave(conn, req)
            except OSError:
                pass

    class S(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = S(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


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
    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "caller.py"), *args],
        capture_output=True, text=True, env=env, timeout=60,
    )
    # Every invocation, every exit path: the key never reaches an output stream.
    check_no_leak(f"caller {' '.join(args[:2])} rc={r.returncode}", r.stdout + r.stderr, key)
    return r


def run_inproc(argv: list[str]) -> tuple[int, str, str]:
    """caller.run() in this process; SystemExit is an exit code like any other."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = caller_mod.run(argv)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        except BaseException:  # a leaked exception is a test failure, not a crash
            rc = -1
    return rc, out.getvalue(), err.getvalue()


def check_no_leak(name: str, output: str, key: str = CALLER_KEY) -> None:
    check(f"no key or /ap/ prefix in output: {name}",
          key not in output and "/ap/" not in output and "apk_" not in output
          and "Traceback" not in output, output[:300].replace(key, "<KEY>"))


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
            # What the caller itself sent, read from the raw request (not the mock's view).
            check(f"{placement} form: the caller puts the key in exactly one place",
                  seen.get("caller_sent_key_in_query") is False
                  and seen.get("caller_sent_key_in_target_after_prefix") is False
                  and seen.get("caller_sent_key_header_names")
                  == (["x-ap-caller-key"] if placement == "header" else []),
                  str(seen))
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

        # 9. Key-only paths, as the real gate (canon::parse_ap_path, passthrough/tests.rs).
        for label, path, want in [
            ("/ap/<key> (no slash)", f"/ap/{CALLER_KEY}", (401, "rejected", "caller_rejected")),
            ("/ap/<key>/", f"/ap/{CALLER_KEY}/", (423, "denied", "route_unknown")),
            ("/ap/<other key>/", f"/ap/{OTHER_KEY}/", (401, "rejected", "caller_rejected")),
            ("/ap/<other key> (no slash)", f"/ap/{OTHER_KEY}", (401, "rejected", "caller_rejected")),
            ("/ap/<short key>/discord/x", "/ap/apk_short/discord/x", (401, "rejected", "caller_rejected")),
            ("/ap/<UPPER key>/discord/x", f"/ap/{CALLER_KEY.upper()}/discord/x", (401, "rejected", "caller_rejected")),
        ]:
            status, headers, text = http(base, "GET", path)
            check(f"mock mirrors the gate for {label}",
                  (status, headers.get("x-ap-decision"), json.loads(text).get("code")) == want, f"{status} {text}")

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

    # 10. Malformed AP_BASE: exit 64, before any URL with the key is built.
    FIXED_BASE_MESSAGE = ("caller: AP_BASE must be http:// or https:// followed by a host and an optional "
                          "port only (no path, query, fragment, userinfo, whitespace or control characters)\n")
    bad_bases = [
        "http://127.0.0.1/base space", "http://127.0.0.1:9/\n", "http://127.0.0.1:9/\r",
        "http://127.0.0.1:9\t", "http://127.0.0.1:9/a#frag", "http://127.0.0.1:9/?q=1",
        "http://127.0.0.1:9?q=1", "http://127.0.0.1:9#f", "ftp://127.0.0.1:9", "file:///etc/passwd",
        "127.0.0.1:9", "http://", "http://[::1", "http://127.0.0.1:99999", "http://127.0.0.1:x",
        "http://user:pw@127.0.0.1:9", "http://127.0.0.1:9/base", "http://127.0.0.1:9//",
        "http://127.0.0.1:9\\x", "http://127.0.0.1\x7f", "http://h\u00e9llo:9",
        "http://127.0.0.1 :9", " http://127.0.0.1:9", "",
    ]
    for base in bad_bases:
        for placement in ("path", "header"):
            r = run_caller(base, ["get-messages", CHANNEL], placement=placement)
            check(f"bad AP_BASE {base!r} ({placement}): exit 64, fixed message",
                  r.returncode == 64 and r.stdout == "" and r.stderr == FIXED_BASE_MESSAGE,
                  f"rc={r.returncode} {r.stderr[:200]}")
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            caller_mod._validate_base("http://127.0.0.1\x00")
        check("NUL in AP_BASE is rejected", False)
    except SystemExit as exc:
        check("NUL in AP_BASE is rejected", exc.code == 64)
    for good in ("http://127.0.0.1:9", "http://127.0.0.1:9/", "https://example.invalid", "http://[::1]:9"):
        env_ok = caller_mod._validate_base(good)
        check(f"good AP_BASE {good!r} is accepted and normalised", env_ok == good.rstrip("/"), env_ok)

    # 11/12. Failure table against raw socket servers.
    cap = caller_mod.MAX_RESPONSE_BYTES
    nested = "[" * 200000

    def reply(status_line: str, body: bytes, extra: str = "", declared: int | None = None) -> bytes:
        n = len(body) if declared is None else declared
        return (f"{status_line}\r\nContent-Length: {n}\r\n{extra}Connection: close\r\n\r\n").encode() + body

    big = b"x" * (cap + 1)
    refusal = json.dumps({"ap_decision": "denied", "code": "no_grant"}).encode()
    behaviours = {
        "close without a response": (lambda conn, req: None, 2),
        "closed mid-request": (lambda conn, req: None, 2),  # server reads only part of the request
        "truncated body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 200 OK", b"abc", declared=100)), 2),
        "truncated error body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 500 X", b"abc", declared=100)), 2),
        "non-HTTP status line": (lambda conn, req: conn.sendall(b"garbage\r\n\r\n"), 2),
        "oversized success body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 200 OK", big)), 2),
        "oversized success body, no Content-Length": (
            lambda conn, req: conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + big), 2),
        "oversized declared Content-Length (body never sent)": (
            lambda conn, req: conn.sendall(reply("HTTP/1.1 200 OK", b"", declared=10**9)), 2),
        "oversized gate refusal": (
            lambda conn, req: conn.sendall(reply("HTTP/1.1 423 Locked", refusal + b" " * (cap + 1))), 2),
        "oversized declared error Content-Length": (
            lambda conn, req: conn.sendall(reply("HTTP/1.1 500 X", b"", declared=cap + 1)), 2),
        "non-JSON 400 body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 400 Bad", b"<html>no</html>")), 2),
        "non-JSON 200 body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 200 OK", b"<html>ok</html>")), 0),
        "deeply nested JSON 400 body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 400 Bad", nested.encode())), 2),
        "empty 502 body": (lambda conn, req: conn.sendall(reply("HTTP/1.1 502 Bad Gateway", b"")), 2),
        "valid refusal": (lambda conn, req: conn.sendall(reply("HTTP/1.1 423 Locked", refusal)), 3),
        "valid unavailable": (lambda conn, req: conn.sendall(reply(
            "HTTP/1.1 503 Unavailable", b'{"ap_decision":"unavailable","code":"connect_failed"}')), 5),
    }
    for name, (behave, want_rc) in behaviours.items():
        server = start_raw_server(behave, partial=(name == "closed mid-request"))
        try:
            for placement in ("path", "header"):
                r = run_caller(f"http://127.0.0.1:{server.server_address[1]}",
                               ["get-messages", CHANNEL], placement=placement)
                check(f"{name} ({placement}): exit {want_rc}", r.returncode == want_rc,
                      f"rc={r.returncode} {r.stderr[:200]}")
                if name == "non-JSON 200 body":
                    continue
                check(f"{name} ({placement}): bounded output", len(r.stdout) + len(r.stderr) < 4096,
                      str(len(r.stdout) + len(r.stderr)))
                if name.startswith(("close", "truncated", "non-HTTP")):
                    check(f"{name} ({placement}): not reported as a refusal",
                          "nothing was sent to Discord" not in r.stderr, r.stderr)
                if name in ("close without a response", "closed mid-request"):
                    check(f"{name} ({placement}): fixed abort message",
                          "closed the connection" in r.stderr and "may already have reached Discord" in r.stderr,
                          r.stderr)
                if name.startswith("oversized"):
                    check(f"{name} ({placement}): fixed cap message",
                          "larger than" in r.stderr and "cap; discarded" in r.stderr, r.stderr[:200])
        finally:
            server.shutdown()
            server.server_close()
    # Connection refused: nothing listens.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    r = run_caller(f"http://127.0.0.1:{dead_port}", ["get-messages", CHANNEL])
    check("connection refused: exit 2", r.returncode == 2, r.stderr)

    # Forced exceptions of every class, in-process, with the key inside the exception text.
    def forced(exc):
        def boom(*_a, **_k):
            raise exc
        return boom
    target = f"/ap/{CALLER_KEY}/discord/api/v10/channels/{CHANNEL}/messages?limit=20"
    cases = [
        ("InvalidURL", http_client.InvalidURL(f"URL can't contain control characters. {target!r}"), 2),
        ("ValueError", ValueError(f"bad {target}"), 2),
        ("OSError", OSError(f"boom {target}"), 2),
        ("TimeoutError", TimeoutError(target), 2),
        ("ConnectionResetError", ConnectionResetError(target), 2),
        ("ConnectionRefusedError", ConnectionRefusedError(target), 2),
        ("BrokenPipeError", BrokenPipeError(target), 2),
        ("RemoteDisconnected", http_client.RemoteDisconnected(target), 2),
        ("IncompleteRead", http_client.IncompleteRead(target.encode(), 5), 2),
        ("BadStatusLine", http_client.BadStatusLine(target), 2),
        ("LineTooLong", http_client.LineTooLong(target), 2),
        ("ssl.SSLError", ssl.SSLError(1, target), 2),
        ("ssl.SSLCertVerificationError", ssl.SSLCertVerificationError(1, target), 2),
        ("URLError(ssl)", urllib.error.URLError(ssl.SSLError(1, target)), 2),
        ("URLError(timeout)", urllib.error.URLError(TimeoutError(target)), 2),
        ("URLError(str)", urllib.error.URLError(target), 2),
        ("UnicodeError", UnicodeError(target), 2),
        ("RecursionError", RecursionError(target), 2),
        ("RuntimeError (unexpected)", RuntimeError(target), 2),
        ("MemoryError", MemoryError(target), 2),
    ]
    saved_open = caller_mod._OPENER.open
    real_main = caller_mod.main
    saved_env = dict(os.environ)
    try:
        os.environ.update(AP_BASE="http://127.0.0.1:9", AP_CALLER_KEY=CALLER_KEY, AP_KEY_PLACEMENT="path")
        for name, exc, want in cases:
            caller_mod._OPENER.open = forced(exc)
            rc, out, err = run_inproc(["caller.py", "get-messages", CHANNEL])
            check(f"forced {name}: exit {want}", rc == want, f"rc={rc} {err[:200]}")
            if name in ("ConnectionResetError", "RemoteDisconnected", "BrokenPipeError"):
                check(f"forced {name}: fixed abort message", "closed the connection" in err, err)
            check_no_leak(f"forced {name}", out + err)
        # Unexpected exception outside the request path (guard): exit 70, fixed text.
        caller_mod.main = forced(RuntimeError(target))
        rc, out, err = run_inproc(["caller.py"])
        caller_mod.main = real_main
        check("unexpected exception: guard exits 70", rc == 70, f"rc={rc}")
        check_no_leak("guard", out + err)
        caller_mod.main = forced(KeyboardInterrupt())
        rc, out, err = run_inproc(["caller.py"])
        caller_mod.main = real_main
        check("KeyboardInterrupt: exit 130, fixed text", rc == 130 and err == "caller: interrupted\n", f"rc={rc} {err}")
        # The documented usage errors on this path stay at 64.
        caller_mod._OPENER.open = saved_open
        rc, out, err = run_inproc(["caller.py", "--help"])
        check("--help is a usage error with no key", rc == 64, f"rc={rc}")
        check_no_leak("--help", out + err)
    finally:
        caller_mod._OPENER.open = saved_open
        caller_mod.main = real_main
        os.environ.clear()
        os.environ.update(saved_env)

    # 7. Decision mapping, pure helper (the real gate sends 503 unavailable; expired is stage 2).
    body = lambda d, c: json.dumps({"ap_decision": d, "code": c})  # noqa: E731
    check("gate_decision parses a two-field body", caller_mod.gate_decision(body("denied", "no_grant")) == ("denied", "no_grant"))
    check("gate_decision rejects a Discord error object",
          caller_mod.gate_decision('{"message": "401: Unauthorized", "code": 0}') is None)
    check("gate_decision rejects extra fields",
          caller_mod.gate_decision('{"ap_decision": "denied", "code": "x", "more": 1}') is None)
    check("gate_decision survives a deeply nested body", caller_mod.gate_decision("[" * 200000) is None)
    check("gate_decision rejects an unknown decision", caller_mod.gate_decision(body("maybe", "x")) is None)
    check("denied and rejected map to exit 3",
          caller_mod.report_refusal(423, "denied", "no_grant") == 3 and caller_mod.report_refusal(401, "rejected", "caller_rejected") == 3)
    check("unavailable maps to exit 5", caller_mod.report_refusal(503, "unavailable", "connect_failed") == 5)
    check("expired maps to exit 4 (stage 2, in review)", caller_mod.report_refusal(410, "expired", "expired") == 4)

    print(f"\n{'ALL PASSED' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
