#!/usr/bin/env python3
"""Black-box matrix for the Muse gated passthrough, stage 1 (docs/design/muse-gated-passthrough.md,
section 7). Separate from matrix.py, whose 41 rows are unchanged.

  passthrough.py --bin DIR [--work DIR] [--json OUT]

DIR holds an `auth-proxy` built with `--features matrix-upstream,stage1-probe`. Each row asserts the
client-visible outcome AND what the mock upstream received. The upstream is the harness mock, so
nothing real is involved; every sentinel is random per run.

Not automatable here (see docs/runbooks/muse-stage1.md): acceptance 11 (ACL isolation), and the
real-connector and real-front parts of 10 and 12.
"""
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Env, sha256_hex, wait_port  # noqa: E402

PORT_A = 18200  # main instance
PORT_B = 18201  # small-limits instance
PORT_C = 18202  # refused-at-startup checks
AUTHORITY = "gate.example.test"
KEY_HEADER = "x-ap-caller-key"

CASES = []  # (id, row, name, instance, fn)
EXPECTED = ["PT-01", "PT-02", "PT-03", "PT-04", "PT-05", "PT-06", "PT-07", "PT-08", "PT-09",
            "PT-10a", "PT-12", "PT-13", "PT-14", "PT-15", "PT-16"]


def case(cid, row, name, instance="main"):
    def deco(f):
        CASES.append((cid, row, name, instance, f))
        return f
    return deco


# ------------------------------------------------------------------ config and client helpers
def pt_text(key, port, limits="", probe=True, listen_host="127.0.0.1"):
    return f"""version = 1

[listen]
proxy = "{listen_host}:{port}"

[limits]
max_body_bytes = 4096

[passthrough]
public_authority = "{AUTHORITY}"
{limits}

[probe]
enabled = {"true" if probe else "false"}

[[identity]]
name = "muse-pilot"
caller_key_sha256 = "{sha256_hex(key)}"

[[route]]
name = "discord"
host = "api.up.test"
port = 18443
mode = "passthrough"

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["GET"]
paths = ["/v1/"]

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["POST"]
paths = ["/v1/upload/"]
"""


def exchange(port, raw, timeout=4.0, stall=None):
    """Send raw bytes, read one response. Returns dict(status, headers, body, closed, head).

    `stall` is a (bytes, seconds) pair: the bytes are sent after `raw`, then the client waits.
    """
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(timeout)
    try:
        s.sendall(raw)
        if stall:
            time.sleep(stall[0])
    except OSError:
        pass
    buf = b""
    closed = False
    try:
        while b"\r\n\r\n" not in buf:
            b = s.recv(65536)
            if not b:
                closed = True
                break
            buf += b
    except (socket.timeout, OSError):
        pass
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    first = lines[0].split(" ") if lines and lines[0] else []
    status = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = rest
    try:
        if "chunked" in headers.get("transfer-encoding", ""):
            while not body.endswith(b"0\r\n\r\n"):
                b = s.recv(65536)
                if not b:
                    break
                body += b
        elif "content-length" in headers:
            while len(body) < int(headers["content-length"]):
                b = s.recv(65536)
                if not b:
                    break
                body += b
    except (socket.timeout, OSError):
        pass
    s.close()
    return dict(status=status, headers=headers, body=body, closed=closed, head=head.decode(errors="replace"))


def build(method, path, headers, body=b"", host=AUTHORITY, add_host=True):
    lines = [f"{method} {path} HTTP/1.1"]
    if add_host:
        lines.append(f"Host: {host}")
    lines += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class Ctx:
    """Per-run state shared by the rows."""

    def __init__(self, env):
        self.e = env
        self.key = "apk_" + secrets.token_hex(32)
        self.auth = "Bot SENTINEL-" + secrets.token_hex(12)
        self.path_token = "PATHTOKEN" + secrets.token_hex(10)
        self.port = PORT_A

    def good(self, extra=(), key=True, auth=True):
        h = []
        if key:
            h.append((KEY_HEADER, self.key))
        if auth:
            h.append(("Authorization", self.auth))
        return h + list(extra)

    def get(self, path, extra=(), port=None, **kw):
        return exchange(port or self.port, build("GET", path, self.good(extra, **kw)))

    def ulog(self):
        return self.e.ulog()


def code_of(r):
    try:
        return json.loads(r["body"]).get("code")
    except ValueError:
        return None


def refused(c, r, status, decision, code, n_up=0):
    n = len(c.ulog())
    ok = (r["status"] == status and r["headers"].get("x-ap-decision") == decision
          and code_of(r) == code and n == n_up)
    return ok, f"status={r['status']} decision={r['headers'].get('x-ap-decision')} code={code_of(r)} upstream={n}"


# ------------------------------------------------------------------ rows (instance "main")
@case("PT-01", "acc 1", "GET on an allowed prefix passes; upstream x-ap-* response headers are kept")
def pt01(c):
    r = c.get("/discord/v1/xap")
    up = c.ulog()
    ok = (r["status"] == 200 and r["headers"].get("x-ap-decision") == "denied"
          and r["headers"].get("x-ap-other") == "kept" and r["body"].startswith(b"upstream-body")
          and len(up) == 1 and up[0]["method"] == "GET" and up[0]["path"] == "/v1/xap")
    return ok, f"status={r['status']} headers={sorted(k for k in r['headers'] if k.startswith('x-ap'))} upstream={len(up)}"


@case("PT-15", "design 6", "upstream Connection nominations are dropped from the response (X-Hop and Connection do not reach the caller)")
def pt15(c):
    r = c.get("/discord/v1/hop")
    h = r["headers"]
    ok = (r["status"] == 200 and r["body"] == b"hop-body" and "x-hop" not in h
          and "connection" not in h and h.get("x-kept") == "ok")
    return ok, f"status={r['status']} x-hop={'x-hop' in h} connection={h.get('connection')} x-kept={h.get('x-kept')}"


@case("PT-16", "design 6", "upstream Proxy-Authenticate does not reach the caller")
def pt16(c):
    r = c.get("/discord/v1/hop")
    ok = r["status"] == 200 and "proxy-authenticate" not in r["headers"]
    return ok, f"status={r['status']} proxy-authenticate={'proxy-authenticate' in r['headers']}"


@case("PT-02", "acc 2", "POST message create is 423 no_grant with X-AP-Decision: denied, nothing upstream")
def pt02(c):
    body = b'{"content":"hi"}'
    r = exchange(c.port, build("POST", "/discord/v1/channels/1/messages",
                               c.good([("Content-Type", "application/json"), ("Content-Length", str(len(body)))]), body))
    return refused(c, r, 423, "denied", "no_grant")


@case("PT-03", "acc 3", "caller-key shapes, unknown route, duplicate Authorization, CONNECT, Upgrade")
def pt03(c):
    out, ok = [], True
    shapes = {
        "missing": c.good(key=False),
        "malformed": [(KEY_HEADER, "apk_zz"), ("Authorization", c.auth)],
        "unknown": [(KEY_HEADER, "apk_" + secrets.token_hex(32)), ("Authorization", c.auth)],
        "duplicate": [(KEY_HEADER, c.key), (KEY_HEADER, c.key), ("Authorization", c.auth)],
    }
    for name, hs in shapes.items():
        r = exchange(c.port, build("GET", "/discord/v1/x", hs))
        good, d = refused(c, r, 401, "rejected", "caller_rejected")
        ok &= good
        out.append(f"{name}:{d}")
    r = exchange(c.port, build("GET", "/nope/v1/x", c.good()))
    good, d = refused(c, r, 423, "denied", "route_unknown")
    ok &= good
    out.append(f"route:{d}")
    r = exchange(c.port, build("GET", "/discord/v1/x", c.good([("Authorization", "second")])))
    good, d = refused(c, r, 400, "denied", "authorization_duplicate")
    ok &= good
    out.append(f"dupauth:{d}")
    r = exchange(c.port, build("CONNECT", "/discord/v1/x", c.good()))
    good, d = refused(c, r, 405, "denied", "connect_refused")
    ok &= good
    out.append(f"connect:{d}")
    r = exchange(c.port, build("GET", "/discord/v1/x", c.good([("Upgrade", "websocket"), ("Connection", "Upgrade")])))
    good, d = refused(c, r, 501, "denied", "websocket_unsupported")
    ok &= good
    out.append(f"upgrade:{d}")
    return ok, " | ".join(out)


FRONT = [("Forwarded", "for=1"), ("X-Forwarded-For", "1"), ("X-Real-IP", "1"), ("Via", "1"),
         ("CF-Ray", "1"), ("Tailscale-User-Login", "someone"), ("Cookie", "a=b"),
         ("Proxy-Authorization", "x"), ("X-Api-Key", "k"), ("X-AP-Other", "1"), ("Expect", "100-continue")]


@case("PT-04", "acc 4", "caller key, x-ap-*, front and credential headers are stripped upstream")
def pt04(c):
    r = c.get("/discord/v1/echo", FRONT + [("X-Keep", "yes")])
    up = c.ulog()
    names = [k for k, _ in up[0]["headers"]] if up else []
    gone = [KEY_HEADER, "x-ap-other", "forwarded", "x-forwarded-for", "x-real-ip", "via", "cf-ray",
            "tailscale-user-login", "cookie", "proxy-authorization", "x-api-key", "expect"]
    leaked = [g for g in gone if g in names]
    ok = r["status"] == 200 and len(up) == 1 and not leaked and "x-keep" in names
    return ok, f"status={r['status']} leaked={leaked} names={names}"


@case("PT-05", "acc 5", "Authorization reaches upstream identical")
def pt05(c):
    r = c.get("/discord/v1/echo")
    up = c.ulog()
    vals = [v for k, v in up[0]["headers"] if k == "authorization"] if up else []
    return r["status"] == 200 and vals == [c.auth], f"status={r['status']} identical={vals == [c.auth]}"


@case("PT-07", "acc 7", "path and Host rows of the sidecar matrix on a passthrough route")
def pt07(c):
    out, ok = [], True
    for p in ["/discord/v1/../x", "/discord/v1/%2e%2e/x", "/discord/v1/%2e/x", "/discord/v1%2fx",
              "/discord//v1/x", "/discord/v1/%252e%252e/x"]:
        r = exchange(c.port, build("GET", p, c.good()))
        good, d = refused(c, r, 400, "denied", "path_ambiguous")
        ok &= good
        out.append(f"{p}:{r['status']}")
    r = exchange(c.port, build("GET", "/discord/v1/x", c.good(), host="evil.example"))
    good, d = refused(c, r, 400, "denied", "host_rejected")
    ok &= good
    r = exchange(c.port, build("GET", "/discord/v1/x", c.good([("Host", AUTHORITY)])))
    good, d = refused(c, r, 400, "denied", "host_rejected")
    ok &= good
    r = exchange(c.port, build("GET", "/discord/v1/x", c.good(), add_host=False))
    good, d = refused(c, r, 400, "denied", "host_rejected")
    ok &= good
    r = exchange(c.port, build("GET", f"http://{AUTHORITY}/discord/v1/x", c.good()))
    good, d = refused(c, r, 400, "denied", "absolute_form")
    ok &= good
    return ok, " ".join(out) + f" upstream={len(c.ulog())}"


@case("PT-12", "acc 12", "framing conflicts produce no upstream request (layer and header recorded)")
def pt12(c):
    cases = {
        "cl+te": [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
        "dup-cl-differing": [("Content-Length", "2"), ("Content-Length", "3")],
        "comma-cl": [("Content-Length", "2, 2")],
        "te-gzip": [("Transfer-Encoding", "gzip")],
        "te-gzip-chunked": [("Transfer-Encoding", "gzip, chunked")],
        "connection-nominates-cl": [("Connection", "close, Content-Length"), ("Content-Length", "2")],
        "connection-nominates-key": [("Connection", KEY_HEADER)],
    }
    out = []
    for name, hs in cases.items():
        r = exchange(c.port, build("POST", "/discord/v1/upload/x", c.good(hs), b"{}"))
        layer = "gate" if r["headers"].get("x-ap-decision") else ("hyper" if r["status"] else "closed")
        out.append(f"{name}:{r['status']}/{layer}/decision={r['headers'].get('x-ap-decision')}")
    # obs-fold: a folded header line. hyper's parser answers it; the layer is recorded.
    fold = build("POST", "/discord/v1/upload/x", c.good([("X-Folded", "a\r\n b"), ("Content-Length", "2")]), b"{}")
    r = exchange(c.port, fold)
    layer = "gate" if r["headers"].get("x-ap-decision") else ("hyper" if r["status"] else "closed")
    out.append(f"obs-fold:{r['status']}/{layer}")
    n = len(c.ulog())
    # Known gap, measured not asserted (design 3.1): hyper deletes Content-Length when chunked is
    # present, accepts bare LF, and collapses identical duplicate Content-Length. The proxy is
    # loopback-only and the front normalises these, so stage 1 documents them.
    r = exchange(c.port, build("GET", "/discord/api/x", c.good([("Content-Length", "2"), ("Transfer-Encoding", "chunked")]), b"0\r\n\r\n"))
    out.append(f"get-cl+te(known gap, not asserted):{r['status']}")
    lf = build("GET", "/discord/api/x", c.good(), b"").replace(b"\r\n", b"\n")
    r = exchange(c.port, lf)
    out.append(f"bare-lf(known gap, not asserted):{r['status']}")
    # Measurement, not an assertion: hyper collapses a duplicate Content-Length with identical
    # values into one before the handler runs, so the gate cannot see it and forwards one value.
    r = exchange(c.port, build("POST", "/discord/v1/upload/x", c.good([("Content-Length", "2"), ("Content-Length", "2")]), b"{}"))
    out.append(f"dup-cl-identical(hyper collapses, not asserted):{r['status']}")
    return n == 0, f"upstream={n} " + " ".join(out)


@case("PT-10a", "acc 10", "probe: statuses with matching decision, keyless 401, bad params 400, client-gone line")
def pt10(c):
    out, ok = [], True
    body = b"{}"
    hs = lambda: c.good([("Content-Length", "2")])  # noqa: E731
    res = {}

    def one(st):
        res[st] = exchange(c.port, build("POST", f"/__ap_probe/{st}/10", hs(), body), timeout=20)

    threads = [threading.Thread(target=one, args=(st,)) for st in (200, 410, 423, 503)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    took = time.time() - t0
    want = {200: None, 410: "expired", 423: "denied", 503: "unavailable"}
    for st, dec in want.items():
        r = res[st]
        good = r["status"] == st and r["headers"].get("x-ap-decision") == dec and "retry-after" not in r["headers"]
        ok &= good
        out.append(f"{st}:{'ok' if good else 'BAD'}")
    r = exchange(c.port, build("POST", "/__ap_probe/200/10", [("Content-Length", "2")], body))
    ok &= r["status"] == 401 and r["headers"].get("x-ap-decision") == "rejected"
    out.append(f"keyless:{r['status']}")
    for bad in ("/__ap_probe/201/10", "/__ap_probe/200/7"):
        r = exchange(c.port, build("POST", bad, hs(), body))
        ok &= r["status"] == 400 and code_of(r) == "probe_params"
    # Client disconnect during the wait: record whether the proxy notices and how fast.
    s = socket.create_connection(("127.0.0.1", c.port), 5)
    s.sendall(build("POST", "/__ap_probe/200/10", hs(), body))
    time.sleep(0.5)
    s.close()
    time.sleep(2.0)
    with open(c.e.audit_file, "rb") as f:
        text = f.read().decode(errors="replace")
    gone = '"event":"client_gone"' in text
    out.append(f"client_gone_line={'yes' if gone else 'no (measurement: disconnect did not reach the handler within 2s)'}")
    ok &= len(c.ulog()) == 0 and took < 25
    return ok, " ".join(out) + f" upstream={len(c.ulog())}"


# ------------------------------------------------------------------ PT-06 (runs on its own instance)
@case("PT-06", "acc 6", "no Authorization, caller key or path token in stdout, stderr, audit or any file", "secrets")
def pt06(c):
    e = c.e
    hook = f"/discord/v1/webhooks/1/{c.path_token}/github"
    inter = f"/discord/v1/interactions/1/{c.path_token}/callback"
    steps = [
        ("allow", build("GET", "/discord/v1/echo", c.good())),
        ("deny-write", build("POST", hook, c.good([("Content-Length", "2")]), b"{}")),
        ("deny-inter", build("POST", inter, c.good([("Content-Length", "2")]), b"{}")),
        ("413", build("POST", "/discord/v1/upload/x", c.good([("Content-Length", "99999")]))),
        ("malformed", build("GET", "/discord/v1/x", [(KEY_HEADER, "apk_bad"), ("Authorization", c.auth)])),
        ("panic", build("GET", "/__ap_test_panic", c.good())),
        ("webhook-read", build("GET", hook, c.good())),
    ]
    out = []
    for name, raw in steps:
        r = exchange(c.port, raw)
        out.append(f"{name}:{r['status']}")
    # Upstream failure: point the route at a dead port, then restore.
    cfg = e.cur_cfg
    with open(cfg) as f:
        text = f.read()
    e.write_file(cfg, text.replace("port = 18443", "port = 9"))
    r = exchange(c.port, build("GET", "/discord/v1/x", c.good()))
    out.append(f"upstream-down:{r['status']}")
    e.write_file(cfg, text)
    r = exchange(c.port, build("GET", "/discord/v1/echo", c.good()))
    alive = r["status"] == 200
    out.append(f"alive-after-panic:{alive}")
    e.stop_proxy()  # flush every file
    needles = [c.auth.split(" ", 1)[1].encode(), c.key.encode(), c.path_token.encode()]
    hits, scanned = [], []
    for root, _d, files in os.walk(e.work):
        rel = os.path.relpath(root, e.work)
        if rel == "secrets" or rel.startswith("secrets" + os.sep):
            continue
        for fn in files:
            p = os.path.join(root, fn)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            scanned.append(os.path.relpath(p, e.work))
            if any(n in data for n in needles):
                hits.append(os.path.relpath(p, e.work))
    log = open(os.path.join(e.work, f"proxy-{c.port}.log"), "rb").read()
    panicked = b"panic at" in log
    audit_has = os.path.exists(e.audit_file) and b"<redacted>" in open(e.audit_file, "rb").read()
    ok = not hits and alive and panicked and audit_has
    return ok, f"hits={hits} scanned={len(scanned)} panic_line={panicked} redacted_in_audit={audit_has} " + " ".join(out)


# ------------------------------------------------------------------ PT-08 (startup refusals)
@case("PT-08", "acc 8", "a non-loopback listener is refused at startup: exit 2, nothing listening", "startup")
def pt08(c):
    e = c.e
    cfg = os.path.join(e.work, "config-nonloop.toml")
    e.write_file(cfg, pt_text(c.key, PORT_C, listen_host="0.0.0.0"))
    p = subprocess.run([os.path.join(e.bindir, "auth-proxy"), "--config", cfg], capture_output=True,
                       env=e._proxy_env(), timeout=10)
    listening = wait_port(PORT_C, None, 0.5)
    # Probe enabled is allowed by this build; a loopback config must start without an expiry store.
    return p.returncode == 2 and not listening, f"exit={p.returncode} listening={listening}"


# ------------------------------------------------------------------ PT-09, PT-13 (small limits)
@case("PT-09", "acc 9", "connection cap, header-read and body-read timeouts close the connection, proxy keeps serving",
      "limits")
def pt09(c):
    port = PORT_B
    out, ok = [], True
    held = [socket.create_connection(("127.0.0.1", port), 5) for _ in range(3)]
    for s in held:  # three idle connections hold the three permits
        s.sendall(b"GET /discord/v1/x HTTP/1.1\r\nHost: " + AUTHORITY.encode() + b"\r\n")
    time.sleep(0.2)
    extra = socket.create_connection(("127.0.0.1", port), 5)
    extra.settimeout(3)
    try:
        extra.sendall(build("GET", "/discord/v1/echo", c.good()))
        data = extra.recv(4096)
    except OSError:
        data = b""
    capped = data == b""
    extra.close()
    out.append(f"cap_closed={capped}")
    ok &= capped
    for s in held:
        s.close()
    time.sleep(1.5)
    r = exchange(port, build("GET", "/discord/v1/echo", c.good()))
    ok &= r["status"] == 200
    out.append(f"after_cap={r['status']}")
    # Header read timeout: half a header line.
    r = exchange(port, b"GET /discord/v1/x HTT", timeout=4, stall=(0, 0))
    ok &= r["status"] == 0 and r["closed"]
    out.append(f"header_timeout_closed={r['closed']}")
    r = exchange(port, build("GET", "/discord/v1/echo", c.good()))
    ok &= r["status"] == 200
    # Body read timeout: a chunk, then silence.
    r = exchange(port, build("POST", "/discord/v1/upload/x", c.good([("Transfer-Encoding", "chunked")]), b"3\r\nabc\r\n"),
                 timeout=5)
    ok &= r["status"] == 0 and r["closed"]
    out.append(f"body_timeout_closed={r['closed']}")
    r = exchange(port, build("GET", "/discord/v1/echo", c.good()))
    ok &= r["status"] == 200
    out.append(f"still_serving={r['status']}")
    return ok, " ".join(out)


@case("PT-13", "acc 13", "allowed-body boundary: stall and over-cap before and after the first byte; chunked stays chunked",
      "limits")
def pt13(c):
    port = PORT_B
    out, ok = [], True
    # Stall after a prefix: closed, one audit line body_failed_after_send.
    before = open(c.e.audit_file, "rb").read().count(b"body_failed_after_send")
    r = exchange(port, build("POST", "/discord/v1/upload/x", c.good([("Transfer-Encoding", "chunked")]), b"3\r\nabc\r\n"),
                 timeout=5)
    time.sleep(0.3)
    after = open(c.e.audit_file, "rb").read().count(b"body_failed_after_send")
    good = r["status"] == 0 and r["closed"] and after - before == 1
    ok &= good
    out.append(f"stall_after_prefix closed={r['closed']} audit_lines={after - before}")
    # Stall before the first byte: 503.
    r = exchange(port, build("POST", "/discord/v1/upload/x", c.good([("Transfer-Encoding", "chunked")])), timeout=5)
    good = r["status"] == 503 and r["headers"].get("x-ap-decision") == "unavailable"
    ok &= good
    out.append(f"stall_before={r['status']}")
    # Undeclared over-cap before any byte: 413.
    big = b"%x\r\n%s\r\n" % (6000, b"a" * 6000)
    r = exchange(port, build("POST", "/discord/v1/upload/x", c.good([("Transfer-Encoding", "chunked")]), big + b"0\r\n\r\n"),
                 timeout=5)
    ok &= r["status"] == 413
    out.append(f"overcap_before={r['status']}")
    # Undeclared over-cap after a prefix: closed.
    part = b"%x\r\n%s\r\n" % (3000, b"a" * 3000)
    r = exchange(port, build("POST", "/discord/v1/upload/x", c.good([("Transfer-Encoding", "chunked")]),
                             part + part + b"0\r\n\r\n"), timeout=5)
    ok &= r["status"] == 0 and r["closed"]
    out.append(f"overcap_after_closed={r['closed']}")
    # Chunked allowed body arrives chunked with no Content-Length.
    c.e.ureset()
    ch = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    r = exchange(port, build("POST", "/discord/v1/upload/x", c.good([("Transfer-Encoding", "chunked")]), ch), timeout=5)
    up = c.ulog()
    names = [k for k, _ in up[0]["headers"]] if up else []
    good = (r["status"] == 200 and len(up) == 1 and "chunked" in up[0]["transfer_encoding"]
            and "content-length" not in names and up[0]["body_len"] == 11)
    ok &= good
    out.append(f"chunked_ok={good}")
    return ok, " ".join(out)


@case("PT-14", "acc 5/start", "passthrough-only config starts with no expiry store, session or admin socket", "startup")
def pt14(c):
    e = c.e
    cfg = os.path.join(e.work, "config-nostore.toml")
    e.write_file(cfg, pt_text(c.key, PORT_C))
    e.start_passthrough(cfg, PORT_C)
    try:
        r = exchange(PORT_C, build("GET", "/discord/v1/xap", c.good()))
        socks = [n for n in os.listdir(e.run_dir)] if os.path.isdir(e.run_dir) else []
    finally:
        e.stop_proxy()
    return r["status"] == 200 and not socks, f"status={r['status']} sockets={socks}"


# ------------------------------------------------------------------ driver
def run_instance(c, instance, results):
    cases = [x for x in CASES if x[3] == instance]
    if not cases:
        return
    e = c.e
    cfg = os.path.join(e.work, f"config-{instance}.toml")
    if instance == "main":
        e.write_file(cfg, pt_text(c.key, PORT_A))
        e.start_passthrough(cfg, PORT_A)
        c.port = PORT_A
    elif instance == "secrets":
        e.write_file(cfg, pt_text(c.key, PORT_A, probe=False))
        e.start_passthrough(cfg, PORT_A)
        c.port = PORT_A
    elif instance == "limits":
        lim = "max_connections = 3\nheader_read_secs = 1\nbody_read_secs = 1"
        e.write_file(cfg, pt_text(c.key, PORT_B, limits=lim, probe=False))
        e.start_passthrough(cfg, PORT_B)
        c.port = PORT_B
    try:
        for cid, row, name, _, fn in cases:
            e.ureset()
            try:
                ok, detail = fn(c)
            except Exception as ex:
                ok, detail = False, f"EXCEPTION {ex!r} {traceback.format_exc(limit=2)}"
            results.append({"id": cid, "row": row, "case": name, "verdict": "PASS" if ok else "FAIL", "detail": detail})
            print(f"{'PASS' if ok else 'FAIL'} | {cid} | {row} | {name} | {detail}", flush=True)
    finally:
        e.stop_proxy()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="directory with auth-proxy (matrix-upstream + stage1-probe build)")
    ap.add_argument("--work", help="work directory (default: a fresh temp dir)")
    ap.add_argument("--json", help="write the per-case results here")
    a = ap.parse_args()
    bindir = os.path.abspath(a.bin)
    if not os.path.exists(os.path.join(bindir, "auth-proxy")):
        print(f"missing binary auth-proxy in {bindir}", file=sys.stderr)
        return 2
    work = os.path.abspath(a.work) if a.work else tempfile.mkdtemp(prefix="apm-pt-")
    os.makedirs(work, exist_ok=True)
    c = Ctx(Env(bindir, work))
    results = []
    try:
        for instance in ("main", "secrets", "limits", "startup"):
            run_instance(c, instance, results)
    finally:
        c.e.close()
    ids = [r["id"] for r in results]
    missing = [i for i in EXPECTED if i not in ids]
    extra = [i for i in ids if i not in EXPECTED]
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"bin": bindir, "results": results, "missing": missing}, f, indent=1)
    print(f"\nrows: {len(results)} run, {len(EXPECTED)} expected, missing={missing or 'none'} extra={extra or 'none'}")
    print(f"summary: {passed} PASS of {len(EXPECTED)} rows; work dir {work}")
    return 0 if (passed == len(EXPECTED) and not missing and not extra) else 1


if __name__ == "__main__":
    sys.exit(main())
