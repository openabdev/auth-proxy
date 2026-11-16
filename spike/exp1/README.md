# Experiment 1: CLI surrogate compatibility probes

Probe code only. This is not the auth-proxy implementation.

| File | Purpose |
|---|---|
| `swapproxy.py` | Loopback reverse proxy. It swaps the surrogate for the real credential, which it reads from an env var by name, and forwards over verified TLS. It redacts every auth header in its log, refuses (401) requests that carry no surrogate, and logs then refuses `CONNECT`. `--mode refuse401\|refuse403\|expired` answers without calling upstream. `--route PREFIX=URL` gives multi-upstream routing. |
| `kiro-probe.sh` | Live kiro-cli run on a Linux host. It loads `KIRO_API_KEY` from `~/.env` by name, gives kiro-cli a random surrogate, sets the `api.*.service` endpoints in a throwaway HOME, and watches for direct (non-loopback) sockets. `ACP=1` drives `kiro-cli acp`. |
| `acp_driver.py` | Minimal ACP client used by `kiro-probe.sh` (initialize → session/new → session/prompt). |
| `cli_probe.py` | Claude Code, Codex, Gemini CLI, OpenCode (and kiro-cli in refuse modes) against `mock_upstream.py` behind `swapproxy.py`. It needs no real credential. |
| `mock_upstream.py` | Loopback mock of the Anthropic Messages, OpenAI Responses/Chat and Gemini APIs. It checks which credential arrived and streams paced SSE. |
| `summarize.py` | One line per proxy log event. |

Examples:

```sh
# Linux host with kiro-cli and ~/.env holding KIRO_API_KEY
KIRO_DISABLE_TELEMETRY=1 bash kiro-probe.sh swap api.codewhisperer.service,api.krs.service,api.cps.service,api.q.service
ERROR_SHAPE=aws bash kiro-probe.sh expired api.codewhisperer.service,api.krs.service,api.cps.service,api.q.service

# any host, no credential needed
python3 cli_probe.py claude-apikey swap
python3 cli_probe.py codex refuse403
python3 cli_probe.py claude-apikey swap --noproxy   # bypass-watcher self-test: must report peers > 0
```

Findings: `.agents/tasks/phase0-spike/exp1.md` (and the Phase 0 report).
