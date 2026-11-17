#!/usr/bin/env bash
# Experiment 1 probe for kiro-cli on a Linux test host.
#
#   kiro-probe.sh <proxy-mode> <setting-keys> [prompt]
#
# proxy-mode   swap | refuse401 | refuse403 | expired   (see swapproxy.py)
# setting-keys comma list of kiro-cli settings to point at the loopback proxy,
#              e.g. api.codewhisperer.service,api.cps.service ("none" = no override)
#
# The real KIRO_API_KEY is loaded by NAME from ~/.env into AP_REAL_KIRO, which
# only the proxy reads. kiro-cli itself receives an opaque random surrogate in
# KIRO_API_KEY. HTTPS_PROXY points at the same proxy, which logs and refuses
# every CONNECT, so any request that bypasses the base URL is visible and never
# leaves the host. The api.*.service settings are global-only (kiro-cli refuses
# them at workspace level), so the CLI runs with a throwaway HOME.
set -euo pipefail
MODE=${1:?mode}
KEYS=${2:?setting keys}
PROMPT=${3:-"Reply with exactly the word: pong"}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-18082}
REGION=${REGION:-us-east-1}
UPSTREAM=${UPSTREAM:-}
WORK=$(mktemp -d /tmp/ap-kiro.XXXXXX)
export PATH=$HOME/.local/bin:$PATH

set -a; . "$HOME/.env"; set +a          # defines KIRO_API_KEY (never echoed)
export AP_REAL_KIRO="$KIRO_API_KEY"
AP_SURROGATE="${SURROGATE_OVERRIDE:-aps_$(python3 -c "import secrets;print(secrets.token_hex(16))")}"   # opaque, random
export AP_SURROGATE
export KIRO_API_KEY="$AP_SURROGATE"

# Default kiro-cli upstreams per setting key (from strings in the binary; confirmed by live run).
python3 "$HERE/swapproxy.py" --listen 127.0.0.1:$PORT --upstream "$UPSTREAM" \
  --route /tag-api.codewhisperer.service=https://q.$REGION.amazonaws.com \
  --route /tag-api.krs.service=https://runtime.$REGION.kiro.dev \
  --route /tag-api.cps.service=https://management.$REGION.kiro.dev \
  --route /tag-api.q.service=https://q.$REGION.amazonaws.com \
  --real-env AP_REAL_KIRO --mode "$MODE" --error-shape "${ERROR_SHAPE:-plain}" > "$WORK/proxy.log" 2>&1 &
PP=$!
sleep 1; kill -0 $PP 2>/dev/null || { cat "$WORK/proxy.log"; exit 3; }   # port busy etc.
trap 'kill $PP 2>/dev/null || true' EXIT
unset AP_REAL_KIRO                       # the CLI process must not inherit it
sleep 1

# Global-only settings: isolate them in a throwaway HOME, not the user's.
mkdir -p "$WORK/ws" "$WORK/home"; cd "$WORK/ws"
export HOME="$WORK/home"
if [ "$KEYS" != none ]; then
  IFS=, read -ra KS <<< "$KEYS"
  for k in "${KS[@]}"; do
    sfx="/tag-$k"   # path prefix shows which key routed; the proxy strips it
    kiro-cli settings "$k" \
      "{\"endpoint\":\"http://127.0.0.1:$PORT$sfx\",\"region\":\"$REGION\"}" >/dev/null
  done
fi
set +e
PX="HTTPS_PROXY=http://127.0.0.1:$PORT https_proxy=http://127.0.0.1:$PORT"
[ -n "${NOPROXY:-}" ] && PX="AP_NOPROXY=1"   # watcher self-test: let side traffic go direct
# The CLI runs in its own session so the watcher can attribute sockets to it.
if [ -n "${ACP:-}" ]; then        # ACP mode, the way openab drives kiro-cli
  CLI=(python3 "$HERE/acp_driver.py" "$PROMPT" -- kiro-cli acp)
else
  CLI=(kiro-cli chat --no-interactive --trust-tools= "$PROMPT")
fi
setsid env $PX timeout ${TMO:-90} "${CLI[@]}" \
  > "$WORK/cli.out" 2>&1 &
CP=$!
# Independent bypass detector: poll the socket table for any TCP connection from
# a process in the CLI's session to a non-loopback peer (catches traffic that
# ignores HTTPS_PROXY). Self-tested with NOPROXY=1, where it must see peers.
( set +e +o pipefail
  while kill -0 $CP 2>/dev/null; do
    ss -Htnp 2>/dev/null | grep -v '127.0.0.1' | while read -r _ _ _ _ peer procs; do
      for pid in $(grep -oE 'pid=[0-9]+' <<< "$procs" | cut -d= -f2); do
        [ "$(ps -o sid= -p "$pid" 2>/dev/null | tr -d ' ')" = "$CP" ] && echo "$peer"
      done
    done
    sleep 0.1
  done ) > "$WORK/direct.txt" 2>/dev/null &
SW=$!
trap 'kill $PP $SW 2>/dev/null || true' EXIT
wait $CP; RC=$?
wait $SW 2>/dev/null
set -e
echo "cli_exit=$RC work=$WORK"
echo "direct_non_loopback_peers: $(sort -u "$WORK/direct.txt" | wc -l | tr -d ' ')"   # count only; no IPs in output
python3 "$HERE/summarize.py" "$WORK/proxy.log"
echo "--- cli output (tail) ---"
tail -c 1200 "$WORK/cli.out" | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g'
