#!/usr/bin/env python3
"""Fail-closed test matrix for auth-proxy and ap-egress (FEAT-005).

  matrix.py --bin DIR [--work DIR] [--json OUT]

DIR holds the built `auth-proxy` and `ap-egress` binaries. Build them with the `matrix-upstream`
feature (see tests/matrix/harness.py). Each case asserts the client-visible outcome AND what the mock
upstreams received, so "refused" means "nothing reached upstream", not only "the client saw a 4xx".

Output: one line per case (PASS or FAIL, with the detail), then a summary. The exit code is 1 when a
case fails or when a registered case is missing from the run.
"""
import argparse
import http.client
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
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import (  # noqa: E402
    AUTH, DEFAULT_GRANTS, EGRESS_NAME, MAX_BODY, PORT_AUTHORITY, PORT_EGRESS, PORT_LEASE, PORT_MAIN, PORT_PROBE,
    PORT_RESTART, UPSTREAM_PORTS, Env, check_hello_vector, read_response, sha256_hex, tls_get,
)

CASES = []  # (id, row, name, instance, fn)

GATE_IDS = [
    "R1-1", "R1-2", "R1-3", "R1-4", "R1-5", "R2-1", "R3-1", "R3-2", "R3-3", "R3-4",
    "X1-1", "X1-2", "X1-3", "R4-1", "R4-2", "R5-1", "R5-2", "X2-1", "X3-1", "R6-1", "R6-2",
    "R7-1", "R8-1", "R8-2", "R8-3", "X4-1", "X5-1", "X6-1",
]
P1_IDS = ["P1-01", "P1-02", "P1-03", "P1-04", "P1-05", "P1-06", "P1-07", "P1-08", "P1-09", "P1-10",
          "P1-11", "P1-12", "P1-13"]
EXPECTED = GATE_IDS + P1_IDS


def case(cid, row, name, instance="main"):
    def deco(f):
        CASES.append((cid, row, name, instance, f))
        return f
    return deco


def code_of(body):
    """The refusal code in a body: generic `error`, or the AWS `message` prefix."""
    try:
        j = json.loads(body)
    except ValueError:
        return None
    if not isinstance(j, dict):
        return None
    if "error" in j:
        return j["error"]
    msg = j.get("message", "")
    if msg.startswith("auth-proxy: "):
        return msg[len("auth-proxy: "):].split(":")[0]
    return None


def refusal(e, st, body, want_status, want_code):
    """Expected status and code, and zero requests at any upstream."""
    n = len(e.ulog())
    code = code_of(body)
    ok = st == want_status and code == want_code and n == 0
    return ok, f"status={st} code={code} upstream_requests={n}"


def auth_values(entry):
    return [(k, v) for k, v in entry["headers"] if k in AUTH]


# ================================================================ R1 policy
@case("R1-1", "R1", "identity grants empty")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.write_main(e.main_text(grants=[g for g in DEFAULT_GRANTS if g["identity"] != "agent-1"]))
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    return refusal(e, st, b, 403, "policy_empty")


@case("R1-2", "R1", "policy file 0 bytes")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.write_main("")
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    return refusal(e, st, b, 503, "policy_unavailable")


@case("R1-3", "R1", "policy file deleted after a good load")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st0, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    e.ureset()
    os.remove(e.main_cfg)
    time.sleep(0.1)
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    ok, d = refusal(e, st, b, 503, "policy_unavailable")
    return ok and st0 == 200, f"before={st0} after: {d}"


@case("R1-4", "R1", "policy file is corrupt TOML")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.write_main('version = 1\n[listen\nproxy = "127.0.0.1:18100"\n')
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    return refusal(e, st, b, 503, "policy_unavailable")


@case("R1-5", "R1", "grant only for POST /v2/; request GET /v1/echo")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.write_main(e.main_text(grants=[dict(identity="agent-1", credential="c-up", route="up",
                                          methods=["POST"], paths=["/v2/"])]))
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    return refusal(e, st, b, 403, "policy_denied")


# ================================================================ R2 session revoke
@case("R2-1", "R2", "session revoked on the session plane, then same surrogate")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st0, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    e.ureset()
    rv = e.revoke(s)
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    ok, d = refusal(e, st, b, 403, "surrogate_revoked")
    return ok and st0 == 200 and rv == 204, f"before={st0} revoke={rv} after: {d}"


# ================================================================ R3 surrogate state (403 for every state)
@case("R3-1", "R3", "session lease expired (lease_secs = 1)", instance="lease")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    time.sleep(1.6)
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    return refusal(e, st, b, 403, "surrogate_expired")


@case("R3-2", "R3", "revoked after one good use")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st0, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    e.ureset()
    e.revoke(s)
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    ok, d = refusal(e, st, b, 403, "surrogate_revoked")
    return ok and st0 == 200, f"before={st0} after: {d}"


@case("R3-3", "R3", "unknown, malformed and missing surrogate")
def _(e):
    out = []
    e.ureset()
    for label, hs, code in (
        ("unknown", e.bearer("aps_" + "0" * 64), "surrogate_unknown"),
        ("malformed", e.bearer("sk-not-a-surrogate"), "surrogate_malformed"),
        ("missing", [], "surrogate_missing"),
    ):
        st, _, b = e.req("GET", e.ap("up", "/v1/echo"), hs)
        ok, d = refusal(e, st, b, 403, code)
        out.append(f"{label}: {d}")
        if not ok:
            return False, " ".join(out)
    return True, " ".join(out)


@case("R3-4", "R3", "revoked surrogate on the AWS-dialect route")
def _(e):
    s = e.mint("agent-1", ("c-aws",))
    e.revoke(s)
    e.ureset()
    st, _, b = e.req("POST", e.ap("upaws", "/v1/echo"), e.bearer(s) + [("Content-Type", "application/x-amz-json-1.1")],
                     body=b"{}")
    ok, d = refusal(e, st, b, 403, "surrogate_revoked")
    try:
        j = json.loads(b)
    except ValueError:
        j = {}
    ok = ok and j.get("__type") == "AccessDeniedException" and "auth-proxy" in j.get("message", "")
    return ok, f"{d} __type={j.get('__type')}"


# ================================================================ X1 caller key and surrogate binding
@case("X1-1", "X1", "wrong caller key in path")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo", key="apk_" + "f" * 64), e.bearer(s))
    return refusal(e, st, b, 403, "caller_rejected")


@case("X1-2", "X1", "identity B's surrogate on identity A's path")
def _(e):
    s = e.mint("agent-2", ("c-up",))
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo", identity="agent-1"), e.bearer(s))
    return refusal(e, st, b, 403, "surrogate_wrong_caller")


@case("X1-3", "X1", "surrogate granted for route upaws, sent to route up")
def _(e):
    s = e.mint("agent-1", ("c-aws",))
    e.ureset()
    st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    return refusal(e, st, b, 403, "surrogate_wrong_route")


# ================================================================ R4 redirects
@case("R4-1", "R4", "302 to another host, another port, and http://")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    good, evil = UPSTREAM_PORTS["good"], UPSTREAM_PORTS["evil"]
    out = []
    ok_all = True
    for label, to in (
        ("host", f"https://evil.up.test:{evil}/v1/echo"),
        ("port", f"https://api.up.test:{evil}/v1/echo"),
        ("scheme", f"http://api.up.test:{good}/v1/echo"),
    ):
        e.ureset()
        path = e.ap("up", "/v1/redirect?to=" + urllib.parse.quote(to, safe=""))
        st, hdr, _ = e.req("GET", path, e.bearer(s))
        lg = e.ulog()
        at_good = [r for r in lg if r["listener"] == "good"]
        elsewhere = [r for r in lg if r["listener"] != "good"]
        ok = st == 302 and hdr.get("location") == to and len(at_good) == 1 and not elsewhere
        ok_all = ok_all and ok
        out.append(f"{label}: status={st} location_unchanged={hdr.get('location') == to} "
                   f"good={len(at_good)} other={len(elsewhere)}")
    return ok_all, "; ".join(out)


@case("R4-2", "R4", "a client that follows the redirect itself, holding only the surrogate")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st = tls_get(UPSTREAM_PORTS["evil"], "evil.up.test", "/v1/echo", e.bearer(s), os.path.join(e.pki, "ca.pem"))
    lg = e.ulog()
    seen = [r for r in lg if r["listener"] == "evil"]
    own = [("authorization", f"Bearer {s}")]
    got = auth_values(seen[0]) if len(seen) == 1 else None
    vals = [v for r in lg for _, v in auth_values(r)]
    leaked = any(c in v for v in vals for c in e.creds.values())
    ok = st == 200 and len(seen) == 1 and got == own and not leaked
    return ok, (f"evil status={st} seen={len(seen)} auth_is_own_surrogate={got == own} "
                f"real_credential_seen={leaked}")


# ================================================================ R5 host canonicalization
@case("R5-1", "R5", "nine raw Host and request-target variants")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    a = e.authority()
    path = e.ap("up", "/v1/echo")
    au = [("Authorization", f"Bearer {s}")]
    variants = [
        ("Host userinfo", f"GET {path} HTTP/1.1", [("Host", f"user@{a}")] + au),
        ("Host foreign name", f"GET {path} HTTP/1.1", [("Host", "evil.up.test")] + au),
        ("Host IPv4 short form", f"GET {path} HTTP/1.1", [("Host", f"127.1:{e.port}")] + au),
        ("Host trailing dot", f"GET {path} HTTP/1.1", [("Host", f"127.0.0.1.:{e.port}")] + au),
        ("Host IPv6-mapped", f"GET {path} HTTP/1.1", [("Host", f"[::ffff:127.0.0.1]:{e.port}")] + au),
        ("two Host headers", f"GET {path} HTTP/1.1", [("Host", a), ("Host", "evil.up.test")] + au),
        ("no Host (HTTP/1.0)", f"GET {path} HTTP/1.0", au),
        ("absolute-form foreign", f"GET http://evil.up.test{path} HTTP/1.1", [("Host", a)] + au),
        ("absolute-form userinfo", f"GET http://u:p@{a}{path} HTTP/1.1", [("Host", a)] + au),
    ]
    out, bad = [], []
    for label, line, hs in variants:
        e.ureset()
        st, _, _ = e.raw_req(line, hs)
        n = len(e.ulog())
        out.append(f"[{label}: {st}/{n}]")
        if st != 400 or n != 0:
            bad.append(label)
    return not bad, " ".join(out) + (f" FAILED: {bad}" if bad else "")


@case("R5-2", "R5", "route host is an IP literal, userinfo, trailing dot, short IPv4 or uppercase")
def _(e):
    out, ok = [], True
    bad_hosts = [("IPv4", "127.0.0.1"), ("IPv6", "::1"), ("userinfo", "u@api.up.test"),
                 ("trailing dot", "api.up.test."), ("IPv4 short", "127.1"), ("uppercase", "API.up.test")]
    path = os.path.join(e.work, "config-bad-host.toml")
    base = e.main_text()
    for label, host in bad_hosts:
        with open(path, "w") as f:
            f.write(base.replace('host = "api.up.test"', f'host = "{host}"'))
        r = subprocess.run([os.path.join(e.bindir, "auth-proxy"), "--config", path],
                           capture_output=True, timeout=10)
        out.append(f"[{label}: exit={r.returncode}]")
        ok = ok and r.returncode == 2
    return ok, " ".join(out)


@case("X2-1", "X2", "six path variants: dot segments, encodings, empty segment, route hop")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    k = e.keys["agent-1"]
    au = [("Authorization", f"Bearer {s}")]
    variants = [
        ("..", f"/ap/{k}/up/v1/../v1/echo"),
        ("%2e%2e", f"/ap/{k}/up/v1/%2e%2e/v1/echo"),
        ("%2f", f"/ap/{k}/up/v1%2fecho"),
        ("//", f"/ap/{k}/up//v1/echo"),
        ("route hop", f"/ap/{k}/badca/../up/v1/echo"),
        ("%252e", f"/ap/{k}/up/v1/%252e%252e/echo"),
    ]
    out, ok_all = [], True
    for label, path in variants:
        e.ureset()
        before = sum(1 for _ in open(e.audit_file, "rb")) if os.path.exists(e.audit_file) else 0
        st, _, _ = e.raw_req(f"GET {path} HTTP/1.1", [("Host", e.authority())] + au)
        lg = e.ulog()
        if not lg:
            ok = 400 <= st < 500
            d = f"refused {st}"
        else:
            with open(e.audit_file, "rb") as f:
                new = f.read().splitlines()[before:]
            seen = [json.loads(line).get("path") for line in new if line.strip()]
            got = lg[0]["path"].split("?")[0]
            ok = bool(seen) and seen[-1] == got and ".." not in got and "%" not in got
            d = f"forwarded {st}, policy saw {seen[-1:]} upstream got {got!r}"
        out.append(f"[{label}: {d}]")
        ok_all = ok_all and ok
    return ok_all, " ".join(out)


@case("X3-1", "X3", "CONNECT on the credential listener")
def _(e):
    e.ureset()
    st, _, b = e.raw_req(f"CONNECT api.up.test:{UPSTREAM_PORTS['good']} HTTP/1.1",
                         [("Host", f"api.up.test:{UPSTREAM_PORTS['good']}")])
    return refusal(e, st, b, 405, "connect_refused")


# ================================================================ R6 SNI and Host
@case("R6-1", "R6", "client X-Forwarded-Host is ignored; SNI and Host are the route host")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s) + [("X-Forwarded-Host", "evil.up.test")])
    lg = e.ulog()
    if len(lg) != 1:
        return False, f"status={st} upstream_requests={len(lg)}"
    r = lg[0]
    hosts = [v for k, v in r["headers"] if k == "host"]
    ok = st == 200 and r["sni"] == "api.up.test" and hosts == [f"api.up.test:{UPSTREAM_PORTS['good']}"] \
        and r["listener"] == "good"
    return ok, f"status={st} sni={r['sni']} host={hosts}"


@case("R6-2", "R6", "certificate names another host")
def _(e):
    s = e.mint("agent-1", ("c-wrong",))
    e.ureset()
    st, _, b = e.req("GET", e.ap("wrongname", "/v1/echo"), e.bearer(s))
    n = len(e.ulog())
    code = code_of(b)
    hf = dict(e.up.rec.handshake_fail)
    ok = st == 502 and code == "upstream_unavailable" and n == 0
    return ok, f"status={st} code={code} upstream_requests={n} handshake_fail={hf}"


# ================================================================ R7 upstream TLS
@case("R7-1", "R7", "certificate chains to an untrusted CA")
def _(e):
    s = e.mint("agent-1", ("c-badca",))
    e.ureset()
    st, _, b = e.req("GET", e.ap("badca", "/v1/echo"), e.bearer(s))
    n = len(e.ulog())
    code = code_of(b)
    hf = dict(e.up.rec.handshake_fail)
    ok = st == 502 and code == "upstream_unavailable" and n == 0
    return ok, f"status={st} code={code} upstream_requests={n} handshake_fail={hf}"


# ================================================================ R8 header hygiene
@case("R8-1", "R8", "bearer surrogate plus six junk auth headers plus TokenType")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    hs = e.bearer(s) + [("X-Api-Key", "junk-1"), ("Proxy-Authorization", "Basic junk-2"), ("Cookie", "a=junk-3"),
                        ("X-Goog-Api-Key", "junk-4"), ("X-Amz-Security-Token", "junk-5"), ("Api-Key", "junk-6"),
                        ("TokenType", "API_KEY")]
    e.ureset()
    st, _, _ = e.req("POST", e.ap("up", "/v1/echo"), hs, body=b"{}")
    lg = e.ulog()
    if len(lg) != 1:
        return False, f"status={st} upstream_requests={len(lg)}"
    hd = lg[0]["headers"]
    auth = auth_values(lg[0])
    allv = " ".join(v for _, v in hd) + " " + lg[0]["path"]
    want = [("authorization", f"Bearer {e.creds['c-up']}")]
    ok = (st == 200 and auth == want and s not in allv and "junk-" not in allv
          and ["tokentype", "API_KEY"] in hd and e.keys["agent-1"] not in allv)
    return ok, (f"status={st} auth_headers_upstream={[k for k, _ in auth]} "
                f"real_credential={auth == want} surrogate_seen={s in allv} junk_seen={'junk-' in allv} "
                f"tokentype_kept={['tokentype', 'API_KEY'] in hd} caller_key_seen={e.keys['agent-1'] in allv}")


@case("R8-2", "R8", "x-api-key route with a junk Authorization header")
def _(e):
    s = e.mint("agent-1", ("c-key",))
    e.ureset()
    st, _, _ = e.req("POST", e.ap("upkey", "/v1/echo"),
                     [("x-api-key", f"Bearer {s}"), ("Authorization", "Bearer junk-7")], body=b"{}")
    lg = e.ulog()
    if len(lg) != 1:
        return False, f"status={st} upstream_requests={len(lg)}"
    auth = auth_values(lg[0])
    want = [("x-api-key", f"Bearer {e.creds['c-key']}")]
    return st == 200 and auth == want, f"status={st} auth_headers_upstream={[k for k, _ in auth]} real={auth == want}"


@case("R8-3", "R8", "two Authorization surrogate headers")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st, _, b = e.raw_req(f"GET {e.ap('up', '/v1/echo')} HTTP/1.1",
                         [("Host", e.authority()), ("Authorization", f"Bearer {s}"),
                          ("Authorization", f"Bearer {s}")])
    return refusal(e, st, b, 400, "surrogate_ambiguous")


# ================================================================ X4 credential store
@case("X4-1", "X4", "credential file removed from the store root")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st0, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    e.ureset()
    path = e.secret_path("c-up")
    os.remove(path)
    try:
        st, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
        ok, d = refusal(e, st, b, 503, "broker_unavailable")
    finally:
        with open(path, "w") as f:
            f.write(e.creds["c-up"])
    return ok and st0 == 200, f"before={st0} after: {d}"


# ================================================================ X5 no secret in any file (runs last)
@case("X5-1", "X5", "no test credential, surrogate or caller key in any work-dir file", instance="final")
def _(e):
    hits, scanned = e.secrets_in_files()
    return not hits, f"files_with_secret={hits} files_scanned={len(scanned)}"


# ================================================================ X6 streaming
@case("X6-1", "X6", "SSE upstream streamed, not buffered")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    c = http.client.HTTPConnection("127.0.0.1", e.port, timeout=10)
    c.putrequest("GET", e.ap("up", "/v1/sse"), skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", e.authority())
    c.putheader("Authorization", f"Bearer {s}")
    c.endheaders()
    t0 = time.time()
    r = c.getresponse()
    ts = []
    while True:
        line = r.fp.readline()
        if not line:
            break
        if line.startswith(b"data:"):
            ts.append(time.time() - t0)
        if len(ts) == 20:
            break
    c.close()
    ok = r.status == 200 and len(ts) == 20 and ts[0] < 0.3 and ts[-1] - ts[0] > 0.8
    return ok, (f"status={r.status} events={len(ts)} first={ts[0] if ts else -1:.3f}s "
                f"spread={(ts[-1] - ts[0]) if ts else 0:.3f}s")



# ================================================================ Phase 1 cases (session plane, bodies, egress)
class Probe:
    """A loopback TCP listener that counts connections. A connection here means egress reached out."""

    def __init__(self, port):
        self.n = 0
        self.lock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(16)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with self.lock:
                self.n += 1
            c.close()

    def count(self):
        with self.lock:
            return self.n

    def close(self):
        self.srv.close()


def ref(sess, gen=1):
    return {"session": sess, "generation": gen}


def new_surrogate():
    return "aps_" + secrets.token_hex(32)


def send_tolerant(e, head, body):
    """Send a request whose body the proxy may refuse early. A reset after the send still counts."""
    s = socket.create_connection(("127.0.0.1", e.port), 5)
    s.settimeout(5)
    try:
        s.sendall(head + body)
    except OSError:
        pass
    try:
        return read_response(s)
    except OSError:
        return 0, "", b""


def uds_raw(e, method, path, token, body):
    """A session-plane request whose body may be refused early. Returns the status."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(e.session_sock)
    head = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode()
    try:
        s.sendall(head + body)
    except OSError:
        pass
    try:
        st, _, _ = read_response(s)
    except OSError:
        st = 0
    return st


def egress_send(data):
    s = socket.create_connection(("127.0.0.1", PORT_EGRESS), 5)
    s.settimeout(3)
    try:
        s.sendall(data)
    except OSError:
        pass
    try:
        st, _, _ = read_response(s)
    except OSError:
        st = 0
    return st


@case("P1-01", "P1", "session plane call with no bearer")
def _(e):
    st, _ = e.sp("POST", "/v1/renew", {"sessions": []})
    return st == 401, f"status={st}"


@case("P1-02", "P1", "session plane call with a wrong bearer")
def _(e):
    st, _ = e.sp("POST", "/v1/renew", {"sessions": []}, token="not-the-token")
    return st == 401, f"status={st}"


@case("P1-03", "P1", "second hello while the authority lease is live; hello after it lapses",
      instance="authority")
def _(e):
    st1, _ = e.hello("agent-1")
    st2, j2 = e.hello("agent-1")
    s = e.mint("agent-1", ("c-up",))
    time.sleep(2.5)
    st3, _ = e.hello("agent-1")
    e.ureset()
    st4, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    code4 = code_of(b)
    err2 = (j2 or {}).get("error")
    ok = st1 == 201 and st2 == 409 and err2 == "authority_active" and st3 == 201 \
        and st4 == 403 and code4 == "surrogate_revoked"
    return ok, (f"hello={st1} second_hello={st2}/{err2} hello_after_lapse={st3} "
                f"old_surrogate={st4}/{code4}")


@case("P1-12", "P1", "hello with only an identity (no proof) refused as proof_missing")
def _(e):
    st, j = e.sp("POST", "/v1/hello", {"identity": "agent-1"})
    err = (j or {}).get("error")
    return st == 401 and err == "proof_missing", f"status={st} error={err}"


@case("P1-13", "P1", "hello with a proof signed by another key refused as proof_invalid")
def _(e):
    st0, ch = e.sp("GET", "/v1/hello/challenge")
    if st0 != 200:
        return False, f"challenge status={st0}"
    nonce = ch["nonce"]
    wrong = e.sign_hello("agent-1", nonce, seed=secrets.token_bytes(32))
    st, j = e.sp("POST", "/v1/hello", {"identity": "agent-1", "nonce": nonce, "proof": wrong})
    err = (j or {}).get("error")
    return st == 401 and err == "proof_invalid", f"status={st} error={err}"


@case("P1-04", "P1", "session PUT with one bad entry: 400 and nothing applied")
def _(e):
    tok = e.token("agent-1")
    s = new_surrogate()
    good = {"session": "p104-" + secrets.token_hex(6), "generation": 1,
            "surrogate_sha256": sha256_hex(s), "credentials": ["c-up"]}
    bad = {"session": "a b", "generation": 1, "surrogate_sha256": sha256_hex(s), "credentials": ["c-up"]}
    st, _ = e.sp("PUT", "/v1/sessions", {"sessions": [good, bad]}, token=tok)
    e.ureset()
    st2, _, b = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(s))
    ok, d = refusal(e, st2, b, 403, "surrogate_unknown")
    return st == 400 and ok, f"put={st} then: {d}"


@case("P1-05", "P1", "proxy restarted: renew reports unknown, resync restores only the listed session",
      instance="restart")
def _(e):
    tok = e.token("agent-1")
    sa = e.mint("agent-1", ("c-up",))
    sb = e.mint("agent-1", ("c-up",))
    st0, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(sa))
    e.stop_proxy()
    e.restart_proxy()
    st1, _, b1 = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(sa))
    code1 = code_of(b1)
    ren_st, ren = e.sp("POST", "/v1/renew", {"sessions": [ref(e.sessions[sa][1]), ref(e.sessions[sb][1])]},
                       token=tok)
    unknown = len((ren or {}).get("unknown", []))
    res_st, res = e.sp("PUT", "/v1/sessions", {"sessions": [e.entry_for(sa)]}, token=tok)
    st2, _, _ = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(sa))
    st3, _, b3 = e.req("GET", e.ap("up", "/v1/echo"), e.bearer(sb))
    code3 = code_of(b3)
    ok = (st0 == 200 and st1 == 403 and code1 == "surrogate_unknown" and ren_st == 200 and unknown == 2
          and res_st == 200 and (res or {}).get("registered") == 1 and st2 == 200
          and st3 == 403 and code3 == "surrogate_unknown")
    return ok, (f"before={st0} after_restart={st1}/{code1} renew={ren_st} unknown={unknown} "
                f"resync={res_st} listed={st2} left_out={st3}/{code3}")


@case("P1-06", "P1", "aws_targets grant allows X; request sends Y")
def _(e):
    s = e.mint("agent-1", ("c-aws",))
    e.ureset()
    st, _, b = e.req("POST", e.ap("upaws", "/v1/echo"),
                     e.bearer(s) + [("X-Amz-Target", "AwsSvc.Other"),
                                    ("Content-Type", "application/x-amz-json-1.1")], body=b"{}")
    return refusal(e, st, b, 403, "policy_denied")


@case("P1-07", "P1", "body over the 1 MiB cap refused; slow body under the cap accepted")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    over = MAX_BODY + 1
    head = (f"POST {e.ap('up', '/v1/echo')} HTTP/1.1\r\nHost: {e.authority()}\r\n"
            f"Authorization: Bearer {s}\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Length: {over}\r\n\r\n").encode()
    e.ureset()
    st1, _, b1 = send_tolerant(e, head, b"x" * over)
    n1 = len(e.ulog())
    size = 512 * 1024
    head2 = (f"POST {e.ap('up', '/v1/echo')} HTTP/1.1\r\nHost: {e.authority()}\r\n"
             f"Authorization: Bearer {s}\r\nContent-Type: application/octet-stream\r\n"
             f"Content-Length: {size}\r\n\r\n").encode()
    e.ureset()
    sock = socket.create_connection(("127.0.0.1", e.port), 5)
    sock.settimeout(5)
    sock.sendall(head2)
    for _ in range(4):
        sock.sendall(b"y" * (size // 4))
        time.sleep(0.2)
    st2, _, _ = read_response(sock)
    n2 = len(e.ulog())
    ok = st1 == 413 and code_of(b1) == "body_too_large" and n1 == 0 and st2 == 200 and n2 == 1
    return ok, f"over_cap={st1}/{code_of(b1)} upstream={n1}; slow_under_cap={st2} upstream={n2}"


@case("P1-08", "P1", "Upgrade: websocket request refused")
def _(e):
    s = e.mint("agent-1", ("c-up",))
    e.ureset()
    st, _, b = e.raw_req(f"GET {e.ap('up', '/v1/echo')} HTTP/1.1",
                         [("Host", e.authority()), ("Authorization", f"Bearer {s}"),
                          ("Connection", "Upgrade"), ("Upgrade", "websocket")])
    return refusal(e, st, b, 501, "websocket_unsupported")


@case("P1-09", "P1", "egress refuses a loopback name, IP literals and an unlisted host, with no connect",
      instance="egress")
def _(e):
    # loop.test is on this instance's allowlist and the test resolver maps it to 127.0.0.1, so its 403
    # can only come from the resolver's address check: an unlisted host would be NotAllowed, and a failed
    # lookup would be 502. With that check removed, the connect reaches the probe and the client gets 200.
    out, ok = [], True
    for target, why in (
        (f"{EGRESS_NAME}:{PORT_PROBE}", "allowlisted, mapped to loopback"),
        ("10.0.0.1:443", "IP literal, private range"),
        (f"127.0.0.1:{PORT_PROBE}", "IP literal, loopback"),
        ("example.org:443", "not allowlisted"),
    ):
        before = e.probe.count()
        st = egress_send(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        hit = e.probe.count() - before
        good = st == 403 and hit == 0
        ok = ok and good
        out.append(f"[{target} ({why}): {st} connects={hit}]")
    return ok, " ".join(out)


@case("P1-10", "P1", "egress refuses a plain HTTP proxy request and an allowlisted host on a wrong port",
      instance="egress")
def _(e):
    before = e.probe.count()
    st1 = egress_send(b"GET http://allowed.test:443/ HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
    st2 = egress_send(b"CONNECT allowed.test:8443 HTTP/1.1\r\nHost: allowed.test:8443\r\n\r\n")
    hit = e.probe.count() - before
    ok = st1 == 405 and st2 == 403 and hit == 0
    return ok, f"plain_get={st1} wrong_port={st2} connects={hit}"


@case("P1-11", "P1", "session PUT over 1 MiB refused 413; invalid session id refused 400")
def _(e):
    tok = e.token("agent-1")
    big = b'{"sessions":[' + b" " * (MAX_BODY + 1) + b"]}"
    st1 = uds_raw(e, "PUT", "/v1/sessions", tok, big)
    st2, _ = e.sp("POST", "/v1/sessions",
                  {"session": "a b", "generation": 1, "surrogate_sha256": sha256_hex(new_surrogate()),
                   "credentials": ["c-up"]}, token=tok)
    return st1 == 413 and st2 == 400, f"oversize_put={st1} invalid_session={st2}"


# ================================================================ driver
def run_instance(e, instance, results):
    """Start the processes this instance needs, run its cases in table order, stop them."""
    cases = [c for c in CASES if c[3] == instance]
    if not cases:
        return
    if instance == "main":
        e.write_main_default()
        e.start_proxy(e.main_cfg, PORT_MAIN)
    elif instance == "lease":
        cfg = os.path.join(e.work, "config-lease.toml")
        e.write_file(cfg, e.main_text(port=PORT_LEASE, lease=1))
        e.start_proxy(cfg, PORT_LEASE)
    elif instance == "authority":
        cfg = os.path.join(e.work, "config-authority.toml")
        e.write_file(cfg, e.main_text(port=PORT_AUTHORITY, authority=2))
        e.start_proxy(cfg, PORT_AUTHORITY)
    elif instance == "restart":
        cfg = os.path.join(e.work, "config-restart.toml")
        e.write_file(cfg, e.main_text(port=PORT_RESTART))
        e.start_proxy(cfg, PORT_RESTART)
    elif instance == "egress":
        cfg = os.path.join(e.work, "config-egress.toml")
        e.write_file(cfg, e.main_text(egress_allow=("allowed.test:443", f"{EGRESS_NAME}:{PORT_PROBE}")))
        e.probe = Probe(PORT_PROBE)
        e.start_egress(cfg)
    try:
        for cid, row, name, _, fn in cases:
            if instance == "main":
                e.write_main_default()
            e.ureset()
            try:
                ok, detail = fn(e)
            except Exception as ex:  # a crash is a failure, with the traceback
                ok, detail = False, f"EXCEPTION {ex!r} {traceback.format_exc(limit=2)}"
            results.append({"id": cid, "row": row, "case": name, "verdict": "PASS" if ok else "FAIL",
                            "detail": detail})
            print(f"{'PASS' if ok else 'FAIL'} | {cid} | {row} | {name} | {detail}", flush=True)
    finally:
        if instance == "egress":
            e.stop_egress()
            e.probe.close()
        else:
            e.stop_proxy()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="directory with auth-proxy and ap-egress")
    ap.add_argument("--work", help="work directory (default: a fresh temp dir)")
    ap.add_argument("--json", help="write the per-case results here")
    a = ap.parse_args()
    bindir = os.path.abspath(a.bin)
    for b in ("auth-proxy", "ap-egress"):
        if not os.path.exists(os.path.join(bindir, b)):
            print(f"missing binary {b} in {bindir}", file=sys.stderr)
            return 2
    work = os.path.abspath(a.work) if a.work else tempfile.mkdtemp(prefix="apm-")
    os.makedirs(work, exist_ok=True)
    # Refuse to run the matrix if the proof signing path disagrees with the Rust vector.
    check_hello_vector(work)
    e = Env(bindir, work)
    results = []
    try:
        for instance in ("main", "lease", "authority", "restart", "egress", "final"):
            if instance == "final":
                run_instance(e, "final", results)
            else:
                run_instance(e, instance, results)
    finally:
        e.close()
    ids = [r["id"] for r in results]
    missing = [i for i in EXPECTED if i not in ids]
    extra = [i for i in ids if i not in EXPECTED]
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    gate = sum(1 for r in results if r["id"] in GATE_IDS and r["verdict"] == "PASS")
    probe_target = sum(1 for r in results if r["id"] in P1_IDS and r["verdict"] == "PASS")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"bin": bindir, "results": results, "missing": missing}, f, indent=1)
    print(f"\nrows: {len(results)} run, {len(EXPECTED)} expected, missing={missing or 'none'} extra={extra or 'none'}")
    print(f"gate: {gate} PASS of {len(GATE_IDS)}; phase 1: {probe_target} PASS of {len(P1_IDS)}")
    print(f"summary: {passed} PASS of {len(EXPECTED)} rows; work dir {work}")
    return 0 if (passed == len(EXPECTED) and not missing and not extra) else 1


if __name__ == "__main__":
    sys.exit(main())
