#!/usr/bin/env python3
"""Live streaming check: kiro-cli (ACP mode, as openab drives it) through option A or B
to the real Kiro service, with a surrogate in place of KIRO_API_KEY.

  live_kiro.py a|b --bin DIR [--prompt TEXT]

The real KIRO_API_KEY is read from ~/.env BY NAME (a bash subshell sources the
file and writes the one value to a pipe). It goes into the mock broker's
environment only. kiro-cli gets a random surrogate, a throwaway HOME whose
global settings point api.{cps,krs,codewhisperer,q}.service at the proxy, and
HTTPS_PROXY set to a closed loopback port so any side traffic fails instead
of leaving the host. Afterwards every file in the work dir and the throwaway
HOME is checked for the real key; the value is never printed. Paid requests:
one model turn plus kiro-cli's own start-up calls.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import P, Env  # noqa: E402

REGION = "us-east-1"
ROUTES = {  # kiro-cli setting key -> (route, default upstream host); hosts measured in Experiment 1
    "api.cps.service": ("cps", f"management.{REGION}.kiro.dev"),
    "api.krs.service": ("krs", f"runtime.{REGION}.kiro.dev"),
    "api.codewhisperer.service": ("cw", f"q.{REGION}.amazonaws.com"),
    "api.q.service": ("q", f"q.{REGION}.amazonaws.com"),
}


def load_key():
    r = subprocess.run(["bash", "-c", 'set -a; . "$HOME/.env" >/dev/null 2>&1; printf %s "${KIRO_API_KEY:-}"'],
                       capture_output=True, text=True)
    if not r.stdout:
        sys.exit("KIRO_API_KEY not found in ~/.env")
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("impl", choices=["a", "b"])
    ap.add_argument("--bin", required=True)
    ap.add_argument("--prompt", default="Count from 1 to 60, one number per line, nothing else.")
    a = ap.parse_args()
    work = tempfile.mkdtemp(prefix=f"ap-live-{a.impl}-")
    e = Env(a.impl, work, os.path.abspath(a.bin))
    real = load_key()
    e.creds = {"c-kiro": real}
    routes = [{"name": rn, "host": host, "error_shape": "aws"} for rn, host in ROUTES.values()]
    cfg = e.config(routes=routes)
    cfg.pop("ca_file")  # public web PKI
    rules = [{"caller": "agent-1", "route": rn, "methods": ["GET", "POST"], "path_prefixes": ["/"]}
             for rn, _ in ROUTES.values()]
    out = {"impl": a.impl}
    try:
        e.start_broker(creds=e.creds)
        del real
        e.set_policy({"rules": rules})
        e.start_impl(e.write_config(cfg))
        s = e.mint(route=",".join(rn for rn, _ in ROUTES.values()), cred="c-kiro")
        home = os.path.join(work, "home")
        ws = os.path.join(work, "ws")
        os.makedirs(home)
        os.makedirs(ws)
        env = {"HOME": home, "PATH": os.path.expanduser("~/.local/bin") + ":/usr/bin:/bin",
               "KIRO_API_KEY": s, "KIRO_DISABLE_TELEMETRY": "1",
               "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}
        for key, (rn, _) in ROUTES.items():
            ep = json.dumps({"endpoint": f"http://127.0.0.1:{P['listen']}{e.url(rn, '')}", "region": REGION})
            subprocess.run(["kiro-cli", "settings", key, ep], env=env, cwd=ws, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ver = subprocess.run(["kiro-cli", "--version"], env=env, capture_output=True, text=True).stdout.strip()
        here = os.path.dirname(os.path.abspath(__file__))
        t0 = time.time()
        r = subprocess.run(["python3", f"{here}/acp_timed.py", a.prompt, "--", "kiro-cli", "acp"], env=env, cwd=ws,
                           capture_output=True, text=True, timeout=180)
        out["kiro_cli"] = ver
        out["wall_s"] = round(time.time() - t0, 2)
        out["acp"] = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {"stderr_tail": r.stderr[-300:]}
        audit = [json.loads(l) for l in open(e.audit_file)] if os.path.exists(e.audit_file) else []
        summ = {}
        for x in audit:
            k = f"{x['route']}:{x['decision']}:{x['code']}:{x['status']}"
            summ[k] = summ.get(k, 0) + 1
        out["audit"] = summ
    finally:
        e.close()
    needle = e.creds["c-kiro"].encode()
    hits = []
    for root, _, files in os.walk(work):
        for fn in files:
            try:
                if needle in open(os.path.join(root, fn), "rb").read():
                    hits.append(os.path.relpath(os.path.join(root, fn), work))
            except OSError:
                pass
    out["files_with_real_key"] = len(hits)
    print(json.dumps(out, indent=1))
    e.cleanup()


if __name__ == "__main__":
    main()
