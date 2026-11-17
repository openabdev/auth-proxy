#!/usr/bin/env python3
"""Experiment 2 fail-closed test matrix (RFC #1), run against option A or B.

  matrix.py a|b --bin DIR [--work DIR] [--json OUT]

Option A = ap-proxy. Option B = Envoy + ap-authz (ext_authz, failure_mode_allow=false).
Each case asserts the client-visible outcome AND what the mock upstreams
actually received, so "refused" means "nothing reached upstream", not just
"the client saw a 4xx".
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import AUTHORITY, P, Env  # noqa: E402

CASES = []


def case(row, name):
    def deco(f):
        CASES.append((row, name, f))
        return f
    return deco


AUTH = ("authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie",
        "x-amz-security-token")


def n_req(e, listener=None):
    lg = e.ulog()["log"]
    return len([r for r in lg if listener is None or r["listener"] == listener])


def bearer(s):
    return [("Authorization", f"Bearer {s}")]


def refused(e, st, hdr, want_status=None, want_code=None, soft=False):
    """Refused = expected status/code and zero requests at any upstream.

    soft=True: the RFC row only requires a refusal; whether the reason code
    reaches the client is recorded (diagnosable=...) but does not decide PASS.
    """
    n = n_req(e)
    ok = n == 0 and 400 <= st < 600
    code = hdr.get("x-auth-proxy-error")
    match = (want_status is None or st == want_status) and (want_code is None or code == want_code)
    if soft:
        return ok, f"status={st} code={code} upstream_requests={n} diagnosable={match}"
    return ok and match, f"status={st} code={code} upstream_requests={n}"


def raw_req(e, line, headers):
    data = (line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n").encode()
    return e.raw(data)


# ---------------------------------------------------------------- R1 policy
@case("R1 policy empty or unavailable → refuse", "policy {\"rules\":[]}")
def _(e):
    e.set_policy({"rules": []})
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(e.mint()))
    return refused(e, st, h, 403, "policy_empty")


@case("R1 policy empty or unavailable → refuse", "policy file is 0 bytes")
def _(e):
    e.set_policy(raw="")
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(e.mint()))
    return refused(e, st, h, 503, "policy_unavailable", soft=True)


@case("R1 policy empty or unavailable → refuse", "policy file deleted after a good load")
def _(e):
    e.set_policy()
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.set_policy(delete=True)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    ok, d = refused(e, st, h, 503, "policy_unavailable", soft=True)
    return ok and st0 == 200, f"before={st0} after: {d}"


@case("R1 policy empty or unavailable → refuse", "policy file corrupt JSON")
def _(e):
    e.set_policy(raw='{"rules": [')
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(e.mint()))
    return refused(e, st, h, 503, "policy_unavailable", soft=True)


@case("R1 policy empty or unavailable → refuse", "policy allows other path/method only")
def _(e):
    e.set_policy({"rules": [{"caller": "agent-1", "route": "up", "methods": ["POST"], "path_prefixes": ["/v2/"]}]})
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(e.mint()))
    return refused(e, st, h, 403, "policy_denied")


# ---------------------------------------------------------------- R2 broker
@case("R2 broker unreachable → refuse, no stale cache", "success, then broker stopped, same surrogate")
def _(e):
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.stop("broker")
    try:
        st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
        ok, d = refused(e, st, h, 503, "broker_unavailable", soft=True)
    finally:
        e.start_broker()
    return ok and st0 == 200, f"before={st0} after: {d}"


# ---------------------------------------------------------------- R3 surrogate state
@case("R3 surrogate expired or revoked → explicit 4xx", "expired (ttl 1 s)")
def _(e):
    s = e.mint(ttl=1)
    time.sleep(1.6)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    return refused(e, st, h, 401, "surrogate_expired")


@case("R3 surrogate expired or revoked → explicit 4xx", "revoked after one good use")
def _(e):
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.revoke(s)
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    ok, d = refused(e, st, h, 401, "surrogate_revoked")
    return ok and st0 == 200, f"before={st0} after: {d}"


@case("R3 surrogate expired or revoked → explicit 4xx", "unknown / malformed / missing surrogate")
def _(e):
    out = []
    for label, hs, code in (("unknown", bearer("aps_" + "0" * 32), "surrogate_unknown"),
                            ("malformed", bearer("sk-not-a-surrogate"), "surrogate_malformed"),
                            ("missing", [], "surrogate_missing")):
        st, h, _ = e.req("GET", e.url("up", "/v1/echo"), hs)
        out.append((label, refused(e, st, h, 401, code)))
    return all(o[1][0] for o in out), "; ".join(f"{l}: {d}" for l, (_, d) in out)


@case("R3 surrogate expired or revoked → explicit 4xx", "aws-dialect route: refusal body has __type")
def _(e):
    s = e.mint(route="upaws")
    e.revoke(s)
    st, h, b = e.req("POST", e.url("upaws", "/v1/echo"), bearer(s), body=b"{}")
    ok, d = refused(e, st, h, 401, "surrogate_revoked")
    try:
        j = json.loads(b)
    except ValueError:
        j = {}
    ok = ok and j.get("__type") == "AccessDeniedException" and "auth-proxy" in j.get("message", "")
    return ok, f"{d} __type={j.get('__type')}"


# ---------------------------------------------------------------- caller binding (pipeline step 1)
@case("X1 caller key and surrogate binding", "wrong caller key / other caller's surrogate / other route's surrogate")
def _(e):
    out = []
    st, h, _ = e.req("GET", f"/ap/{'f' * 32}/up/v1/echo", bearer(e.mint()))
    out.append(("bad key", refused(e, st, h, 403, "caller_rejected")))
    st, h, _ = e.req("GET", e.url("up", "/v1/echo", caller="agent-1"), bearer(e.mint(caller="agent-2")))
    out.append(("other caller", refused(e, st, h, 403, "surrogate_wrong_caller")))
    st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(e.mint(route="upaws")))
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
        cfg = e.config(routes=[{"name": "x", "host": host, "port": 443}])
        p = e.write_config(cfg, "config-bad.json")
        if e.impl == "a":
            r = subprocess.run([f"{e.bindir}/ap-proxy", p], capture_output=True, timeout=10)
            rc = [r.returncode]
        else:
            r1 = subprocess.run([f"{e.bindir}/ap-authz", "render-envoy", p], capture_output=True, timeout=10)
            r2 = subprocess.run([f"{e.bindir}/ap-authz", "serve", p], capture_output=True, timeout=10)
            rc = [r1.returncode, r2.returncode]
        out.append((label, all(c == 2 for c in rc), f"exit={rc}"))
    return all(o[1] for o in out), " ".join(f"[{l}: {d}]" for l, _, d in out)


@case("X2 path canonicalization", "dot-segments, encoded dots/slashes, empty segments (raw)")
def _(e):
    s = e.mint()
    k = e.keys["agent-1"]
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
    return 400 <= st < 500 and n == 0, f"status={st} upstream_requests={n}"


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
    st, h, _ = e.req("GET", e.url("wrongname", "/v1/echo"), bearer(e.mint(route="wrongname")))
    ok, d = refused(e, st, h)
    hf = e.ulog()["handshake_fail"]
    return ok and st in (502, 503), f"{d} handshake_fail={hf}"


# ---------------------------------------------------------------- R7 upstream TLS
@case("R7 upstream TLS verification failure → refuse", "cert from an untrusted CA")
def _(e):
    st, h, _ = e.req("GET", e.url("badca", "/v1/echo"), bearer(e.mint(route="badca")))
    ok, d = refused(e, st, h)
    hf = e.ulog()["handshake_fail"]
    return ok and st in (502, 503), f"{d} handshake_fail={hf}"


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
          and e.keys["agent-1"] not in allv and e.keys["agent-1"] not in lg[0]["path"])
    return ok, (f"status={st} auth_headers_upstream={[k for k, _ in auth]} real={auth[:1] and auth[0][1].endswith(e.creds['c-up'])} "
                f"surrogate_seen={s in allv} junk_seen={'junk-' in allv} tokentype_kept={'API_KEY' in allv} "
                f"caller_key_seen={e.keys['agent-1'] in allv + lg[0]['path']}")


@case("R8 client auth stripped, exactly one upstream credential", "x-api-key route + junk Authorization")
def _(e):
    s = e.mint(route="upkey", cred="c-key")
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
    return 400 <= st < 500 and n == 0, f"status={st} upstream_requests={n}"


# ---------------------------------------------------------------- B only: authz down
@case("X4 enforcement point down → refuse", "B: ext_authz service stopped (failure_mode_allow=false)")
def _(e):
    if e.impl != "b":
        return None, "n/a for A (single process: if it is down, nothing listens)"
    s = e.mint()
    st0, _, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
    e.ureset()
    e.stop("ap-authz")
    try:
        st, h, _ = e.req("GET", e.url("up", "/v1/echo"), bearer(s))
        n = n_req(e)
    finally:
        e.start_authz()
    return st0 == 200 and 400 <= st < 600 and n == 0, f"before={st0} after: status={st} upstream_requests={n}"


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


# ---------------------------------------------------------------- log hygiene (last)
@case("X5 no secret in any log", "real test credentials, surrogates, caller keys vs every work-dir file")
def _(e):
    hits = e.secrets_in_files()
    files = sorted(os.listdir(e.work))
    return not hits, f"files_with_secret={hits} scanned={[f for f in files if f != 'pki']}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("impl", choices=["a", "b"])
    ap.add_argument("--bin", required=True)
    ap.add_argument("--work")
    ap.add_argument("--json")
    a = ap.parse_args()
    work = a.work or tempfile.mkdtemp(prefix=f"ap-exp2-{a.impl}-")
    e = Env(a.impl, work, os.path.abspath(a.bin))
    results = []
    try:
        e.start_upstream()
        e.start_broker()
        e.set_policy()
        e.start_impl()
        for row, name, f in CASES:
            e.set_policy()
            e.ureset()
            try:
                ok, detail = f(e)
            except Exception as ex:  # a crash is a failure, with the traceback
                ok, detail = False, f"EXCEPTION {ex!r} {traceback.format_exc(limit=2)}"
            verdict = "n/a" if ok is None else ("PASS" if ok else "FAIL")
            results.append({"row": row, "case": name, "verdict": verdict, "detail": detail})
            print(f"{verdict:4} | {row} | {name} | {detail}", flush=True)
    finally:
        e.close()
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"impl": a.impl, "results": results}, f, indent=1)
    fails = [r for r in results if r["verdict"] == "FAIL"]
    print(f"\n{a.impl}: {len(results) - len(fails)} of {len(results)} cases not failing; work dir {work}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
