#!/usr/bin/env python3
"""The fail-closed matrix (design doc section 7), run against the real `auth-proxy`.

  matrix.py --bin DIR [--work DIR] [--json OUT]

Ported from spike/exp2/test/matrix.py. The 25 Phase 0 rows are kept (Phase 1
expectations: 403 for every surrogate state, the mock broker replaced by the
real session plane, X4 now "credential store unreadable"), and rows are added
for the session plane, resync after a proxy restart, aws_targets, request
bodies and WebSocket upgrades. A row is never removed or loosened without the
reason in the PR's review contract.

Each case asserts the client-visible outcome AND what the mock upstreams
actually received, so "refused" means "nothing reached upstream", not just
"the client saw a 4xx".

Exit code 0 only if no row FAILs. The lease-lapse, authority-restart and
`hello`-race rows need a shortened authority lease and live in the Rust
integration tests (crates/ap-proxy/tests/hello_race.rs).
"""
import argparse
import json
import os
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import AUTHORITY, MAX_BODY, SESSION_LEASE_SECS, P, Env, short_workdir  # noqa: E402

CASES = []


def case(row, name, phase0=True):
    def deco(f):
        CASES.append((row, name, f, phase0))
        return f
    return deco


AUTH = ("authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie",
        "x-amz-security-token")


def n_req(e, listener=None):
    lg = e.ulog()["log"]
    return len([r for r in lg if listener is None or r["listener"] == listener])


def bearer(s):
    return [("Authorization", f"Bearer {s}")]


def refused(e, st, hdr, want_status=None, want_code=None):
    """Refused = expected status/code and zero requests at any upstream."""
    n = n_req(e)
    ok = n == 0 and 400 <= st < 600
    code = hdr.get("x-auth-proxy-error")
    match = (want_status is None or st == want_status) and (want_code is None or code == want_code)
    return ok and match, f"status={st} code={code} upstream_requests={n}"


def raw_req(e, line, headers):
    data = (line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n").encode()
    return e.raw(data)


# ---------------------------------------------------------------- R1 policy
@case("R1 policy empty or unavailable → refuse", "policy has no grants")
def _(e):
    s = e.mint()
    e.set_policy(grants=[])
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    return refused(e, st, h, 403, "policy_empty")


@case("R1 policy empty or unavailable → refuse", "policy file is 0 bytes")
def _(e):
    s = e.mint()
    e.set_policy(raw="")
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    return refused(e, st, h, 503, "policy_unavailable")


@case("R1 policy empty or unavailable → refuse", "policy file deleted after a good load")
def _(e):
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.set_policy(delete=True)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    ok, d = refused(e, st, h, 503, "policy_unavailable")
    return ok and st0 == 200, f"before={st0} after: {d}"


@case("R1 policy empty or unavailable → refuse", "policy file corrupt TOML")
def _(e):
    s = e.mint()
    e.set_policy(raw='version = 1\n[[route\nname = "x"')
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    return refused(e, st, h, 503, "policy_unavailable")


@case("R1 policy empty or unavailable → refuse", "policy allows other path/method only")
def _(e):
    s = e.mint()
    e.set_policy(grants=[{"credential": "c-up", "route": "up", "methods": ["POST"], "paths": ["/v2/"]}])
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    return refused(e, st, h, 403, "policy_denied")


# ---------------------------------------------------------------- R2 broker
@case("R2 broker unreachable → refuse, no stale cache",
      "success, then session revoked through the session plane, same surrogate")
def _(e):
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.revoke(s)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    ok, d = refused(e, st, h, 403, "surrogate_revoked")
    return ok and st0 == 200, f"before={st0} after: {d}"


# ---------------------------------------------------------------- R3 surrogate state
@case("R3 surrogate expired or revoked → explicit 4xx", f"expired (session lease {SESSION_LEASE_SECS} s, not renewed)")
def _(e):
    s = e.mint()
    time.sleep(SESSION_LEASE_SECS + 0.7)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    return refused(e, st, h, 403, "surrogate_expired")


@case("R3 surrogate expired or revoked → explicit 4xx", "revoked after one good use")
def _(e):
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.revoke(s)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    ok, d = refused(e, st, h, 403, "surrogate_revoked")
    return ok and st0 == 200, f"before={st0} after: {d}"


@case("R3 surrogate expired or revoked → explicit 4xx", "unknown / malformed / missing surrogate")
def _(e):
    out = []
    for label, hs, code in (("unknown", bearer("aps_" + "0" * 64), "surrogate_unknown"),
                            ("malformed", bearer("sk-not-a-surrogate"), "surrogate_malformed"),
                            ("missing", [], "surrogate_missing")):
        st, h, _ = e.req("GET", e.url("up", "/v1/echo"), hs)
        out.append((label, refused(e, st, h, 403, code)))
    return all(o[1][0] for o in out), "; ".join(f"{l}: {d}" for l, (_, d) in out)


@case("R3 surrogate expired or revoked → explicit 4xx", "aws-dialect route: refusal body has __type")
def _(e):
    s = e.mint()
    e.revoke(s)
    st, h, b = e.req("POST", e.url("upaws", "/v1/echo"), bearer(s), body=b"{}")
    ok, d = refused(e, st, h, 403, "surrogate_revoked")
    try:
        j = json.loads(b)
    except ValueError:
        j = {}
    ok = ok and j.get("__type") == "AccessDeniedException" and "auth-proxy" in j.get("message", "")
    return ok, f"{d} __type={j.get('__type')}"


# ---------------------------------------------------------------- caller binding (pipeline steps 3 to 5)
@case("X1 caller key and surrogate binding", "wrong caller key / surrogate of another identity / other route's surrogate")
def _(e):
    out = []
    st, h, _ = e.req("GET", f"/ap/apk_{'f' * 64}/up/v1/echo", bearer(e.mint()))
    out.append(("bad key", refused(e, st, h, 403, "caller_rejected")))
    # A surrogate registered under identity agent-1; the policy now names agent-2.
    s = e.mint()
    e.set_policy(identity="agent-2")
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    out.append(("other identity", refused(e, st, h, 403, "surrogate_wrong_caller")))
    e.set_policy()
    # c-key is granted on route upkey only.
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(e.mint(cred="c-key")))
    out.append(("other route", refused(e, st, h, 403, "surrogate_wrong_route")))
    return all(o[1][0] for o in out), "; ".join(f"{l}: {d}" for l, (_, d) in out)


# ---------------------------------------------------------------- R4 redirects
@case("R4 cross-host/port/scheme redirect → credential never forwarded", "302 to other host, other port, http://")
def _(e):
    s = e.mint()
    out = []
    for label, to in (("host", f"https://evil.up.test:{P['evil']}/v1/echo"),
                      ("port", f"https://api.up.test:{P['evil']}/v1/echo"),
                      ("scheme", f"http://api.up.test:{P['good']}/v1/echo")):
        e.ureset()
        st, h, _ = e.req("GET", e.url("up", f"/v1/redirect?to={to}"), bearer(s))
        lg = e.ulog()["log"]
        good = [r for r in lg if r["listener"] == "good"]
        evil = [r for r in lg if r["listener"] != "good"]
        ok = st == 302 and h.get("location") == to and len(good) == 1 and not evil
        out.append((label, ok, f"status={st} location_unchanged={h.get('location') == to} "
                               f"good={len(good)} other={len(evil)}"))
    # A naive client that follows the redirect itself only holds the surrogate.
    e.ureset()
    e.direct_tls(P["evil"], "evil.up.test", "/v1/echo", bearer(s))
    lg = e.ulog()["log"]
    vals = [v for r in lg for k, v in r["headers"] if k in AUTH]
    leaked = any(c in v for v in vals for c in e.creds.values())
    out.append(("client follows", not leaked, f"evil got real credential={leaked}"))
    return all(o[1] for o in out), "; ".join(f"{l}: {d}" for l, _, d in out)


# ---------------------------------------------------------------- R5 host canonicalization
@case("R5 userinfo, IP literal or ambiguous host → reject", "client Host / request-target variants (raw)")
def _(e):
    s = e.mint()
    path = e.url("up", "/v1/echo")
    au = [("Authorization", f"Bearer {s}")]
    variants = [
        ("Host userinfo", f"GET {path} HTTP/1.1", [("Host", f"user@{AUTHORITY}")] + au),
        ("Host foreign name", f"GET {path} HTTP/1.1", [("Host", "evil.up.test")] + au),
        ("Host IPv4 short form", f"GET {path} HTTP/1.1", [("Host", f"127.1:{P['listen']}")] + au),
        ("Host trailing dot", f"GET {path} HTTP/1.1", [("Host", f"127.0.0.1.:{P['listen']}")] + au),
        ("Host IPv6-mapped", f"GET {path} HTTP/1.1", [("Host", f"[::ffff:127.0.0.1]:{P['listen']}")] + au),
        ("two Host headers", f"GET {path} HTTP/1.1", [("Host", AUTHORITY), ("Host", "evil.up.test")] + au),
        ("no Host (HTTP/1.0)", f"GET {path} HTTP/1.0", au),
        ("absolute-form foreign", f"GET http://evil.up.test{path} HTTP/1.1", [("Host", AUTHORITY)] + au),
        ("absolute-form userinfo", f"GET http://u:p@{AUTHORITY}{path} HTTP/1.1", [("Host", AUTHORITY)] + au),
    ]
    out = []
    for label, line, hs in variants:
        e.ureset()
        st, _ = raw_req(e, line, hs)
        n = n_req(e)
        out.append((label, 400 <= st < 500 and n == 0, f"{st}/{n}"))
    bad = [l for l, ok, _ in out if not ok]
    return not bad, " ".join(f"[{l}: {d}]" for l, _, d in out) + (f" FAILED: {bad}" if bad else "")


@case("R5 userinfo, IP literal or ambiguous host → reject", "upstream route host is IP literal / userinfo / trailing dot")
def _(e):
    out = []
    for label, host in (("IPv4", "127.0.0.1"), ("IPv6", "::1"), ("userinfo", "u@api.up.test"),
                        ("trailing dot", "api.up.test."), ("IPv4 short", "127.1"), ("uppercase", "API.up.test")):
        p = os.path.join(e.work, "policy-bad.toml")
        with open(p, "w") as f:
            f.write(e.policy_toml(routes=[{"name": "x", "host": host}], credentials=False))
        rc, _ = e.run_startup_check(p)
        out.append((label, rc == 2, f"exit={rc}"))
    return all(o[1] for o in out), " ".join(f"[{l}: {d}]" for l, _, d in out)


@case("X2 path canonicalization", "dot-segments, encoded dots/slashes, empty segments (raw)")
def _(e):
    s = e.mint()
    k = e.caller_key
    au = [("Host", AUTHORITY), ("Authorization", f"Bearer {s}")]
    out = []
    for label, path in (("..", f"/ap/{k}/up/v1/../v1/echo"), ("%2e%2e", f"/ap/{k}/up/v1/%2e%2e/v1/echo"),
                        ("%2f", f"/ap/{k}/up/v1%2fecho"), ("//", f"/ap/{k}/up//v1/echo"),
                        ("route hop", f"/ap/{k}/badca/../up/v1/echo"), ("%252e", f"/ap/{k}/up/v1/%252e%252e/echo")):
        e.ureset()
        open(e.audit_file, "a").close()
        before = sum(1 for _ in open(e.audit_file))
        st, _ = raw_req(e, f"GET {path} HTTP/1.1", au)
        lg = e.ulog()["log"]
        new = [json.loads(l) for l in list(open(e.audit_file))[before:]]
        if not lg:
            ok, d = 400 <= st < 500, f"refused {st}"
        else:
            # Forwarded: only acceptable if what policy saw is exactly what upstream got.
            seen = [a.get("path") for a in new if a.get("decision") == "allow"]
            got = lg[0]["path"].split("?")[0]
            ok = seen == [got] and ".." not in got and "%" not in got
            d = f"forwarded {st}, policy saw {seen} upstream got {got!r} ({lg[0]['listener']})"
        out.append((label, ok, d))
    return all(o[1] for o in out), " ".join(f"[{l}: {d}]" for l, _, d in out)


@case("X3 CONNECT refused", "CONNECT api.up.test:443")
def _(e):
    st, _ = raw_req(e, f"CONNECT api.up.test:{P['good']} HTTP/1.1", [("Host", f"api.up.test:{P['good']}")])
    n = n_req(e)
    return st == 405 and n == 0, f"status={st} upstream_requests={n}"


# ---------------------------------------------------------------- R6 SNI / Host
@case("R6 SNI/Host mismatch → reject", "upstream sees SNI == Host == route host; client X-Forwarded-Host ignored")
def _(e):
    s = e.mint()
    st, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s) + [("X-Forwarded-Host", "evil.up.test")])
    lg = e.ulog()["log"]
    if len(lg) != 1:
        return False, f"status={st} upstream_requests={len(lg)}"
    r = lg[0]
    hosts = [v for k, v in r["headers"] if k == "host"]
    ok = st == 200 and r["sni"] == "api.up.test" and hosts == [f"api.up.test:{P['good']}"] and r["listener"] == "good"
    return ok, f"status={st} sni={r['sni']} host={hosts}"


@case("R6 SNI/Host mismatch → reject", "cert name ≠ route host (SNI wrongname.up.test, cert other.up.test)")
def _(e):
    st, h, _ = e.req("GET", e.url("wrongname", "/v1/echo"), bearer(e.mint()))
    ok, d = refused(e, st, h, 502, "upstream_unavailable")
    hf = e.ulog()["handshake_fail"]
    return ok, f"{d} handshake_fail={hf}"


# ---------------------------------------------------------------- R7 upstream TLS
@case("R7 upstream TLS verification failure → refuse", "cert from an untrusted CA")
def _(e):
    st, h, _ = e.req("GET", e.url("badca", "/v1/echo"), bearer(e.mint()))
    ok, d = refused(e, st, h, 502, "upstream_unavailable")
    hf = e.ulog()["handshake_fail"]
    return ok, f"{d} handshake_fail={hf}"


# ---------------------------------------------------------------- R8 header hygiene
@case("R8 client auth stripped, exactly one upstream credential", "bearer route + 6 junk auth headers + TokenType")
def _(e):
    s = e.mint()
    hs = bearer(s) + [("X-Api-Key", "junk-1"), ("Proxy-Authorization", "Basic junk-2"), ("Cookie", "a=junk-3"),
                      ("X-Goog-Api-Key", "junk-4"), ("X-Amz-Security-Token", "junk-5"), ("Api-Key", "junk-6"),
                      ("TokenType", "API_KEY")]
    st, _, _ = e.req("POST", e.url("up", "/v1/echo"), hs, body=b"{}")
    lg = e.ulog()["log"]
    if len(lg) != 1:
        return False, f"status={st} upstream_requests={len(lg)}"
    hd = lg[0]["headers"]
    auth = [(k, v) for k, v in hd if k in AUTH]
    allv = " ".join(v for _, v in hd)
    ok = (st == 200 and auth == [("authorization", f"Bearer {e.creds['c-up']}")] and s not in allv
          and "junk-" not in allv and ("tokentype", "API_KEY") in [(k, v) for k, v in hd]
          and e.caller_key not in allv and e.caller_key not in lg[0]["path"])
    return ok, (f"status={st} auth_headers_upstream={[k for k, _ in auth]} real={auth[:1] and auth[0][1].endswith(e.creds['c-up'])} "
                f"surrogate_seen={s in allv} junk_seen={'junk-' in allv} tokentype_kept={'API_KEY' in allv} "
                f"caller_key_seen={e.caller_key in allv + lg[0]['path']}")


@case("R8 client auth stripped, exactly one upstream credential", "x-api-key route + junk Authorization")
def _(e):
    s = e.mint(cred="c-key")
    st, _, _ = e.req("POST", e.url("upkey", "/v1/echo"), [("x-api-key", s), ("Authorization", "Bearer junk-7")],
                     body=b"{}")
    lg = e.ulog()["log"]
    if len(lg) != 1:
        return False, f"status={st} upstream_requests={len(lg)}"
    auth = [(k, v) for k, v in lg[0]["headers"] if k in AUTH]
    return st == 200 and auth == [("x-api-key", e.creds["c-key"])], f"status={st} auth_headers_upstream={[k for k, _ in auth]}"


@case("R8 client auth stripped, exactly one upstream credential", "two surrogate headers → reject")
def _(e):
    s = e.mint()
    st, _ = raw_req(e, f"GET {e.url('up', '/v1/echo')} HTTP/1.1",
                    [("Host", AUTHORITY), ("Authorization", f"Bearer {s}"), ("Authorization", f"Bearer {s}")])
    n = n_req(e)
    return st == 400 and n == 0, f"status={st} upstream_requests={n}"


# ---------------------------------------------------------------- X4 enforcement point down
@case("X4 enforcement point down → refuse", "credential store unreadable after a good request (S1 file removed)")
def _(e):
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.remove_secret("c-up")
    try:
        st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
        ok, d = refused(e, st, h, 503, "broker_unavailable")
    finally:
        e.write_secret("c-up")
    return ok and st0 == 200, f"before={st0} after: {d}"


# ---------------------------------------------------------------- streaming
@case("X6 SSE streaming through the proxy (mock)", "20 events × 50 ms: not buffered")
def _(e):
    import http.client
    s = e.mint()
    c = http.client.HTTPConnection("127.0.0.1", P["listen"], timeout=10)
    t0 = time.time()
    c.putrequest("GET", e.url("up", "/v1/sse"), skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", AUTHORITY)
    c.putheader("Authorization", f"Bearer {s}")
    c.endheaders()
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
    return ok, f"status={r.status} events={len(ts)} first={ts[0] if ts else -1:.3f}s spread={(ts[-1] - ts[0]) if ts else 0:.3f}s"


# ================================================================ rows added in Phase 1
@case("P1 session plane authentication", "no token / wrong token / hello while an authority is live", phase0=False)
def _(e):
    out = []
    st, j = e.plane("POST", "/v1/sessions", {"session": "x", "generation": 1, "surrogate_sha256": "0" * 64,
                                              "credentials": ["c-up"]}, token=None)
    out.append(("no token", st == 401, f"{st} {j and j.get('error')}"))
    for label, call in (("renew", ("POST", "/v1/renew", {"sessions": []})),
                        ("revoke", ("DELETE", "/v1/sessions/x/1", None)),
                        ("resync", ("PUT", "/v1/sessions", {"sessions": []}))):
        st, j = e.plane(*call, token="apt_" + "0" * 64)
        out.append((f"wrong token {label}", st == 401, f"{st} {j and j.get('error')}"))
    st, j = e.plane("POST", "/v1/hello", {}, token=None)
    out.append(("hello while live", st == 409 and j.get("error") == "authority_active", f"{st} {j and j.get('error')}"))
    st, j = e.plane("POST", "/v1/sessions", {"session": "x", "generation": 1, "surrogate_sha256": "XYZ",
                                              "credentials": ["c-up"]})
    out.append(("bad field", st == 400, f"{st}"))
    st, j = e.plane("POST", "/v1/sessions", {"session": "x", "generation": 1, "surrogate_sha256": "0" * 64,
                                              "credentials": ["nope"]})
    out.append(("credential not granted", st == 403, f"{st}"))
    st, j = e.plane("POST", "/v1/sessions", raw=b"x" * (1024 * 1024 + 1))
    out.append(("body over 1 MiB", st == 413, f"{st}"))
    return all(o[1] for o in out), " ".join(f"[{l}: {d}]" for l, _, d in out)


@case("P2 resync after a proxy restart", "same surrogate works again, dropped sessions stay dropped", phase0=False)
def _(e):
    keep, drop = e.mint(session="keep"), e.mint(session="drop")
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(keep))
    e.stop("auth-proxy", kill=True)  # SIGKILL: the socket files stay behind and must be replaced
    e.start_impl()
    e.ureset()
    st1, h1, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(keep))
    gap_ok, gap = refused(e, st1, h1, 403, "surrogate_unknown")
    sk, sd = e.sessions[keep], e.sessions[drop]
    st, j = e.plane("POST", "/v1/renew", {"sessions": [{"session": s["session"], "generation": s["generation"]}
                                                       for s in (sk, sd)]})
    unknown = sorted(u["session"] for u in (j or {}).get("unknown", []))
    st2, j2 = e.plane("PUT", "/v1/sessions", {"sessions": [sk]})
    e.ureset()
    st3, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(keep))
    st4, h4, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(drop))
    n_drop_gap = n_req(e)
    ok = (st0 == 200 and gap_ok and st == 200 and unknown == ["drop", "keep"] and st2 == 200
          and j2 == {"registered": 1, "dropped": 0} and st3 == 200 and st4 == 403 and n_drop_gap == 1)
    return ok, (f"before={st0} gap: {gap}; renew unknown={unknown}; resync={st2} {j2}; "
                f"after keep={st3} drop={st4}/{h4.get('x-auth-proxy-error')} upstream_requests={n_drop_gap}")


@case("P3 aws_targets", "one X-Amz-Target allowed; none, two and a wrong one denied", phase0=False)
def _(e):
    s = e.mint()
    e.set_policy(grants=[{"credential": "c-up", "route": "upaws", "methods": ["POST"], "paths": ["/v1/"],
                          "aws_targets": ["Svc.Allowed"]}])
    url = e.url("upaws", "/v1/echo")
    out = []
    st, _, _ = e.req("POST", url, bearer(s) + [("X-Amz-Target", "Svc.Allowed")], body=b"{}")
    out.append(("allowed", st == 200 and n_req(e) == 1, f"{st}"))
    e.ureset()
    for label, extra in (("none", []), ("wrong", [("X-Amz-Target", "Svc.Other")]),
                         ("two", [("X-Amz-Target", "Svc.Allowed"), ("X-Amz-Target", "Svc.Allowed")])):
        st, h, b = e.req("POST", url, bearer(s) + extra, body=b"{}")
        ok, d = refused(e, st, h, 403, "policy_denied")
        out.append((label, ok and b"AccessDeniedException" in b, d))
    return all(o[1] for o in out), " ".join(f"[{l}: {d}]" for l, _, d in out)


@case("P4 request body cap", f"1.5 MiB streams through; over the {MAX_BODY >> 20} MiB cap is 413 with nothing sent upstream",
      phase0=False)
def _(e):
    s = e.mint()
    big = b"a" * (3 * 1024 * 1024 // 2)
    st, _, _ = e.req("POST", e.url("up", "/v1/echo"), bearer(s), body=big)
    lg = e.ulog()["log"]
    ok1 = st == 200 and len(lg) == 1 and lg[0]["body_len"] == len(big)
    e.ureset()
    st2, h2, _ = e.req("POST", e.url("up", "/v1/echo"), bearer(s), body=b"b" * (MAX_BODY + 1))
    ok2, d2 = refused(e, st2, h2, 413, "body_too_large")
    return ok1 and ok2, f"1.5MiB: status={st} upstream_body={lg[0]['body_len'] if lg else None}; over cap: {d2}"


@case("P5 slow request body", "1000 bytes over 1.2 s is forwarded whole", phase0=False)
def _(e):
    import socket
    s = e.mint()
    sock = socket.create_connection(("127.0.0.1", P["listen"]), 5)
    head = (f"POST {e.url('up', '/v1/echo')} HTTP/1.1\r\nHost: {AUTHORITY}\r\nAuthorization: Bearer {s}\r\n"
            f"Content-Length: 1000\r\n\r\n").encode()
    sock.sendall(head)
    for _ in range(10):
        sock.sendall(b"x" * 100)
        time.sleep(0.12)
    sock.settimeout(5)
    out = b""
    while b"\r\n\r\n" not in out:
        b = sock.recv(65536)
        if not b:
            break
        out += b
    sock.close()
    lg = e.ulog()["log"]
    status = out.split(b" ", 2)[1] if out else b"?"
    ok = status == b"200" and len(lg) == 1 and lg[0]["body_len"] == 1000
    return ok, f"status={status.decode()} upstream_requests={len(lg)} upstream_body={lg[0]['body_len'] if lg else None}"


@case("P6 WebSocket upgrade refused", "GET with Upgrade: websocket → 501, nothing upstream", phase0=False)
def _(e):
    s = e.mint()
    st, h, _ = e.req("GET", e.url("up", "/v1/ws"), bearer(s) + [("Connection", "Upgrade"), ("Upgrade", "websocket")])
    return refused(e, st, h, 501, "websocket_unsupported")


# ---------------------------------------------------------------- log hygiene (last)
@case("X5 no secret in any log", "real test credentials, surrogates, caller key, authority token vs every work-dir file")
def _(e):
    hits = e.secrets_in_files()
    prefix = []
    for fn in (e.audit_file, e.err_file):
        data = open(fn, "rb").read()
        if b"/ap/" in data:
            prefix.append(os.path.basename(fn))
    files = sorted(os.listdir(e.work))
    return not hits and not prefix, (f"files_with_secret={hits} files_with_/ap/_prefix={prefix} "
                                     f"scanned={[f for f in files if f not in ('pki', 'secrets')]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--work")
    ap.add_argument("--json")
    a = ap.parse_args()
    work = a.work or short_workdir()
    e = Env(work, os.path.abspath(a.bin))
    results = []
    try:
        e.start_upstream()
        e.set_policy()
        e.start_impl()
        e.hello()
        for row, name, f, phase0 in CASES:
            e.set_policy()
            e.ureset()
            try:
                ok, detail = f(e)
            except Exception as ex:  # a crash is a failure, with the traceback
                ok, detail = False, f"EXCEPTION {ex!r} {traceback.format_exc(limit=2)}"
            verdict = "n/a" if ok is None else ("PASS" if ok else "FAIL")
            results.append({"row": row, "case": name, "verdict": verdict, "detail": detail, "phase0": phase0})
            print(f"{verdict:4} | {row} | {name} | {detail}", flush=True)
    finally:
        e.close()
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"results": results}, f, indent=1)
    base = [r for r in results if r["phase0"]]
    added = [r for r in results if not r["phase0"]]
    fails = [r for r in results if r["verdict"] != "PASS"]
    bp = sum(r["verdict"] == "PASS" for r in base)
    ap_ = sum(r["verdict"] == "PASS" for r in added)
    print(f"\nPhase 0 rows: {bp}/{len(base)} PASS; added session-plane/body rows: {ap_}/{len(added)} PASS; "
          f"total {len(results) - len(fails)}/{len(results)} PASS; work dir {work}")
    return 1 if fails or len(base) != 25 else 0


if __name__ == "__main__":
    sys.exit(main())
