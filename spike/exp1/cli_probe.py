#!/usr/bin/env python3
"""Experiment 1 probe for CLIs we hold no usable live credential for.

    cli_probe.py <recipe> <proxy-mode> [--noproxy]

Chain: CLI --surrogate--> swapproxy.py --mock real cred--> mock_upstream.py.
Neither credential is real: both are random strings minted per run, so this
probe needs no secret and spends no paid request. It measures what the CLI
does locally: whether the base-URL knob is honoured, whether an opaque
surrogate is rejected before any request, whether streaming survives the hop,
and what the CLI does on 401/403/expired from the proxy.

Bypass detection, two independent ways:
  * HTTPS_PROXY points at swapproxy, which logs and refuses every CONNECT.
  * The CLI runs in its own process group; lsof is polled for any TCP socket
    of that group with a non-loopback peer. --noproxy is the self-test: it
    unsets HTTPS_PROXY so side traffic must show up as direct peers.
The CLI runs with a throwaway HOME, so the user's own logins are never used.
"""
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PP, MP = 18191, 18190
PROMPT = "Reply with the single word pong."
CLIS = os.environ.get("AP_CLI_BIN", "/tmp/ap-clis/node_modules/.bin")


def recipes(work, surr):
    base = "http://127.0.0.1:%d" % PP
    codex_cfg = os.path.join(work, "codex")
    os.makedirs(codex_cfg)
    with open(os.path.join(codex_cfg, "config.toml"), "w") as f:
        f.write('model = "gpt-5"\nmodel_provider = "ap"\n[model_providers.ap]\n'
                'name = "auth-proxy"\nbase_url = "%s/v1"\nenv_key = "AP_CODEX_KEY"\n'
                'wire_api = "responses"\n' % base)
    codex_base = os.path.join(work, "codex-base")
    os.makedirs(codex_base)
    with open(os.path.join(codex_base, "config.toml"), "w") as f:
        f.write('model = "gpt-5"\nopenai_base_url = "%s/v1"\n' % base)
    # Codex ChatGPT-subscription mode with surrogates in auth.json: once fully
    # opaque, once with a JWT-shaped (unsigned, fake-claims) id_token.
    import base64

    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    fake_jwt = "%s.%s.%s" % (b64({"alg": "none", "typ": "JWT"}), b64({
        "exp": int(time.time()) + 3600, "email": "surrogate@example.invalid",
        "https://api.openai.com/auth": {"chatgpt_plan_type": "plus",
                                        "chatgpt_account_id": "acct-surrogate"}}), "sig")
    for name, idt in (("codex-chatgpt-opaque", surr), ("codex-chatgpt-jwtshape", fake_jwt)):
        d = os.path.join(work, name)
        os.makedirs(d)
        with open(os.path.join(d, "config.toml"), "w") as f:
            f.write('model = "gpt-5"\nchatgpt_base_url = "%s/backend-api/"\n' % base)
            if os.environ.get("AP_CODEX_OPENAI_BASE"):  # also redirect the model endpoint
                f.write('openai_base_url = "%s/backend-api/codex"\n' % base)
        with open(os.path.join(d, "auth.json"), "w") as f:
            json.dump({"auth_mode": "chatgpt", "OPENAI_API_KEY": None, "last_refresh":
                       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "tokens": {"id_token": idt, "access_token": surr,
                                  "refresh_token": "aps_refresh_surrogate",
                                  "account_id": "acct-surrogate"}}, f)
    ks = os.path.join(work, "home", ".kiro", "settings")
    os.makedirs(ks)
    with open(os.path.join(ks, "cli.json"), "w") as f:   # same keys as kiro-probe.sh
        json.dump({k: {"endpoint": "%s/tag-%s" % (base, k), "region": "us-east-1"} for k in (
            "api.codewhisperer.service", "api.krs.service", "api.cps.service",
            "api.q.service")}, f)
    gem = os.path.join(work, "home", ".gemini")
    os.makedirs(gem)
    with open(os.path.join(gem, "settings.json"), "w") as f:
        json.dump({"security": {"auth": {"selectedType": "gemini-api-key"}}}, f)
    oc = os.path.join(work, "opencode.json")
    with open(oc, "w") as f:
        json.dump({"$schema": "https://opencode.ai/config.json",
                   "model": "anthropic/claude-sonnet-4-5",
                   "provider": {"anthropic": {"options": {
                       "baseURL": base + "/v1", "apiKey": "{env:AP_OC_KEY}"}}}}, f)
    return {
        "claude-apikey": ({"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": surr},
                          ["claude", "-p", PROMPT]),
        "claude-authtoken": ({"ANTHROPIC_BASE_URL": base, "ANTHROPIC_AUTH_TOKEN": surr},
                             ["claude", "-p", PROMPT]),
        "claude-oauth": ({"ANTHROPIC_BASE_URL": base, "CLAUDE_CODE_OAUTH_TOKEN": surr},
                         ["claude", "-p", PROMPT]),
        "codex": ({"CODEX_HOME": codex_cfg, "AP_CODEX_KEY": surr},
                  ["codex", "exec", "--skip-git-repo-check", PROMPT]),
        "codex-env": ({"CODEX_HOME": os.path.join(work, "codex-empty"),
                       "OPENAI_BASE_URL": base + "/v1", "OPENAI_API_KEY": surr},
                      ["codex", "exec", "--skip-git-repo-check", PROMPT]),
        "codex-cfgbase": ({"CODEX_HOME": codex_base, "CODEX_API_KEY": surr},
                          ["codex", "exec", "--skip-git-repo-check", PROMPT]),
        "codex-chatgpt-opaque": ({"CODEX_HOME": os.path.join(work, "codex-chatgpt-opaque")},
                                 ["codex", "exec", "--skip-git-repo-check", PROMPT]),
        "codex-chatgpt-jwtshape": ({"CODEX_HOME": os.path.join(work, "codex-chatgpt-jwtshape")},
                                   ["codex", "exec", "--skip-git-repo-check", PROMPT]),
        # refuse modes only: the mock does not speak the AWS JSON protocol
        "kiro": ({"KIRO_API_KEY": surr, "KIRO_DISABLE_TELEMETRY": "1", "KIRO_NO_AUTO_UPDATE": "1"},
                 ["kiro-cli", "chat", "--no-interactive", "--trust-tools=", PROMPT]),
        "gemini-envonly": ({"GOOGLE_GEMINI_BASE_URL": base, "GEMINI_API_KEY": surr,
                            "AP_GEMINI_NOSETTINGS": "1", "GEMINI_CLI_TRUST_WORKSPACE": "true"},
                           [os.path.join(CLIS, "gemini"), "-p", PROMPT]),
        "gemini": ({"GOOGLE_GEMINI_BASE_URL": base, "GEMINI_API_KEY": surr,
                    "GEMINI_CLI_TRUST_WORKSPACE": "true"},
                   [os.path.join(CLIS, "gemini"), "-m", "gemini-2.5-flash", "-p", PROMPT]),
        "opencode": ({"OPENCODE_CONFIG": oc, "AP_OC_KEY": surr},
                     [os.path.join(CLIS, "opencode"), "run", PROMPT]),
    }


def lsof_peers(pgid):
    try:
        out = subprocess.run(["lsof", "-nP", "-a", "-g", str(pgid), "-iTCP"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:  # noqa: BLE001
        return set()
    peers = set()
    for line in out.splitlines()[1:]:
        m = re.search(r"->(\[?[0-9a-fA-F.:]+\]?):(\d+)", line)
        if m and not m.group(1).startswith(("127.", "[::1]", "::1")):
            peers.add(m.group(1) + ":" + m.group(2))
    return peers


def main():
    recipe, mode = sys.argv[1], sys.argv[2]
    noproxy = "--noproxy" in sys.argv
    work = tempfile.mkdtemp(prefix="ap-cli.")
    home = os.path.join(work, "home")
    os.makedirs(home)
    os.makedirs(os.path.join(work, "codex-empty"))
    surr = "aps_" + secrets.token_hex(16)
    real = "mock-real-" + secrets.token_hex(16)
    env_common = dict(os.environ, AP_SURROGATE=surr, AP_MOCK_REAL=real)
    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_upstream.py"), str(MP)],
                            stdout=open(os.path.join(work, "mock.log"), "w"),
                            stderr=subprocess.STDOUT, env=env_common)
    proxy = subprocess.Popen([sys.executable, os.path.join(HERE, "swapproxy.py"),
                              "--listen", "127.0.0.1:%d" % PP,
                              "--upstream", "http://127.0.0.1:%d" % MP,
                              "--real-env", "AP_MOCK_REAL", "--mode", mode],
                             stdout=open(os.path.join(work, "proxy.log"), "w"),
                             stderr=subprocess.STDOUT, env=env_common)
    time.sleep(1)
    assert mock.poll() is None and proxy.poll() is None, "mock/proxy failed to start"
    extra, cmd = recipes(work, surr)[recipe]
    if extra.pop("AP_GEMINI_NOSETTINGS", None):
        os.remove(os.path.join(home, ".gemini", "settings.json"))
    if not os.path.isabs(cmd[0]):
        cmd[0] = shutil.which(cmd[0]) or cmd[0]
    env = {k: v for k, v in os.environ.items()
           if not re.match(r"(ANTHROPIC|OPENAI|GEMINI|GOOGLE|CLAUDE|CODEX|KIRO|HTTPS?_PROXY)", k,
                           re.I)}
    env.update(HOME=home, **extra)
    for kv in os.environ.get("AP_EXTRA_ENV", "").split(","):   # e.g. FOO=1,BAR=2
        if "=" in kv:
            env[kv.split("=", 1)[0]] = kv.split("=", 1)[1]
    if not noproxy:
        env.update(HTTPS_PROXY="http://127.0.0.1:%d" % PP, https_proxy="http://127.0.0.1:%d" % PP,
                   NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
    t0 = time.time()
    cli = subprocess.Popen(cmd, cwd=work, env=env, stdin=subprocess.DEVNULL,
                           stdout=open(os.path.join(work, "cli.out"), "w"),
                           stderr=subprocess.STDOUT, start_new_session=True)
    peers = set()
    timeout = float(os.environ.get("TMO", "90"))
    while cli.poll() is None and time.time() - t0 < timeout:
        peers |= lsof_peers(cli.pid)
        time.sleep(0.2)
    if cli.poll() is None:
        try:
            os.killpg(cli.pid, signal.SIGTERM)
        except OSError:
            pass
        time.sleep(1)
        rc = "timeout"
    else:
        rc = cli.returncode
    try:
        os.killpg(cli.pid, signal.SIGKILL)
    except OSError:
        pass
    for p in (proxy, mock):
        p.terminate()
    out = open(os.path.join(work, "cli.out"), errors="replace").read()
    out = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", out).replace(surr, "<SURROGATE>").replace(
        real, "<MOCKREAL>")
    print(json.dumps({"recipe": recipe, "mode": mode, "noproxy": noproxy, "exit": rc,
                      "elapsed_s": round(time.time() - t0, 1),
                      "direct_non_loopback_peers": len(peers), "work": work}))
    subprocess.run([sys.executable, os.path.join(HERE, "summarize.py"),
                    os.path.join(work, "proxy.log")])
    print("--- mock ---")
    for line in open(os.path.join(work, "mock.log")):
        print(line.rstrip()[:300])
    print("--- cli output (tail) ---")
    print(out[-1500:])


if __name__ == "__main__":
    try:
        main()
    finally:
        subprocess.run(["pkill", "-f", "mock_upstream.py %d" % MP])
        subprocess.run(["pkill", "-f", "swapproxy.py --listen 127.0.0.1:%d" % PP])
