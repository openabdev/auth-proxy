#!/usr/bin/env python3
"""Experiment 2 measurements: added latency, RSS idle and under load.

  bench.py a|b --bin DIR [--n 2000] [--conc 32] [--dur 15] [--json OUT]

Latency: sequential GETs of a tiny body over one keep-alive connection,
direct to the mock TLS upstream vs through the proxy. Each proxied request
also makes one broker round-trip (by design: no credential cache), which is
measured separately. Load: --conc keep-alive connections for --dur seconds.
The client, mock upstream and mock broker are Python, so absolute throughput
is bounded by them; the A-vs-B difference is the comparison that matters.
"""
import argparse
import http.client
import json
import os
import socket
import ssl
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import AUTHORITY, P, Env  # noqa: E402


def rss_kb(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def summary(xs):
    return {"p50_ms": round(pct(xs, 0.50) * 1e3, 3), "p90_ms": round(pct(xs, 0.90) * 1e3, 3),
            "p99_ms": round(pct(xs, 0.99) * 1e3, 3), "mean_ms": round(statistics.mean(xs) * 1e3, 3), "n": len(xs)}


def timed(fn, n, warm=200):
    for _ in range(warm):
        fn()
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("impl", choices=["a", "b"])
    ap.add_argument("--bin", required=True)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--conc", type=int, default=32)
    ap.add_argument("--dur", type=float, default=15)
    ap.add_argument("--json")
    a = ap.parse_args()
    e = Env(a.impl, tempfile.mkdtemp(prefix=f"ap-bench-{a.impl}-"), os.path.abspath(a.bin))
    res = {"impl": a.impl}
    try:
        e.start_upstream()
        e.start_broker()
        e.set_policy()
        e.start_impl()
        pids = e.impl_pids()
        time.sleep(2)
        res["rss_idle_kb"] = {n: rss_kb(p) for n, p in pids.items()}
        s = e.mint()
        path = e.url("up", "/v1/small")

        # direct baseline: one keep-alive TLS connection with the right SNI
        ctx = ssl.create_default_context(cafile=f"{e.pki}/ca.pem")
        dc = http.client.HTTPSConnection("127.0.0.1", P["good"], context=ctx, timeout=10)
        dc.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", P["good"])), server_hostname="api.up.test")

        def direct():
            dc.request("GET", "/v1/small", headers={"Host": f"api.up.test:{P['good']}", "Authorization": "Bearer x"})
            dc.getresponse().read()

        pc = http.client.HTTPConnection("127.0.0.1", P["listen"], timeout=10)

        def proxied():
            pc.request("GET", path, headers={"Host": AUTHORITY, "Authorization": f"Bearer {s}"})
            r = pc.getresponse()
            r.read()
            assert r.status == 200, r.status

        bc = http.client.HTTPConnection("127.0.0.1", P["broker"], timeout=10)
        body = json.dumps({"caller": "agent-1", "route": "up", "surrogate": s})

        def broker():
            bc.request("POST", "/v1/resolve", body=body, headers={"content-type": "application/json"})
            bc.getresponse().read()

        for k, fn in (("latency_direct", direct), ("latency_proxied", proxied), ("latency_broker_only", broker)):
            res[k] = summary(timed(fn, a.n))
            print(k, res[k], file=sys.stderr, flush=True)
        res["added_p50_ms"] = round(res["latency_proxied"]["p50_ms"] - res["latency_direct"]["p50_ms"], 3)
        res["added_p99_ms"] = round(res["latency_proxied"]["p99_ms"] - res["latency_direct"]["p99_ms"], 3)
        res["rss_warm_kb"] = {n: rss_kb(p) for n, p in pids.items()}

        # load
        stop = time.time() + a.dur
        counts, errors, peak = [0] * a.conc, [0] * a.conc, {n: 0 for n in pids}

        def worker(i):
            c = http.client.HTTPConnection("127.0.0.1", P["listen"], timeout=10)
            while time.time() < stop:
                try:
                    c.request("GET", path, headers={"Host": AUTHORITY, "Authorization": f"Bearer {s}"})
                    r = c.getresponse()
                    r.read()
                    if r.status == 200:
                        counts[i] += 1
                    else:
                        errors[i] += 1
                except Exception:
                    errors[i] += 1
                    c.close()
                    c = http.client.HTTPConnection("127.0.0.1", P["listen"], timeout=10)

        def sampler():
            while time.time() < stop:
                for n, p in pids.items():
                    peak[n] = max(peak[n], rss_kb(p))
                time.sleep(0.1)

        print("load start", file=sys.stderr, flush=True)
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(a.conc)] + [threading.Thread(target=sampler)]
        t0 = time.time()
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        el = time.time() - t0
        res["load"] = {"conc": a.conc, "seconds": round(el, 1), "ok": sum(counts), "errors": sum(errors),
                       "rps": round(sum(counts) / el, 1), "rss_peak_kb": peak}
        time.sleep(2)
        res["rss_after_load_kb"] = {n: rss_kb(p) for n, p in pids.items()}
    finally:
        e.close()
        e.cleanup()
    out = json.dumps(res, indent=1)
    print(out)
    if a.json:
        open(a.json, "w").write(out)


if __name__ == "__main__":
    main()
