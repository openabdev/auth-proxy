#!/bin/sh
# Proxy sidecar entrypoint (UID 1001, no capabilities). Plays the platform's
# proxy-side role for the spike:
#   1. caller key: generated once per pod (kept in the proxy-private emptyDir, so a
#      container restart keeps it), copied to the handoff dir for the agent.
#   2. ap-proxy config + policy (proxy-private).
#   3. mock broker on loopback; the real key goes from the mounted Secret file into
#      the broker's environment only. Stands in for the remote Phase 1 broker.
#   4. mint a surrogate for the agent, write it to the handoff dir.
#   5. exec ap-proxy.
set -eu
R=/run/ap            # proxy-private emptyDir
H=/handoff           # shared with the agent (read-only there)
S=/var/run/ap-secret # Secret, mounted in this container only
LISTEN=127.0.0.1:18100
BROKER=18190

umask 077
[ -s "$R/caller-key" ] || python3 -c 'import secrets; print(secrets.token_hex(16), end="")' > "$R/caller-key"

python3 - "$R" "$LISTEN" "$BROKER" <<'EOF'
import hashlib, json, sys
r, listen, broker = sys.argv[1:4]
key = open(f"{r}/caller-key").read().strip()
reg = "us-east-1"
routes = [("cps", f"management.{reg}.kiro.dev"), ("krs", f"runtime.{reg}.kiro.dev"),
          ("cw", f"q.{reg}.amazonaws.com"), ("q", f"q.{reg}.amazonaws.com")]
cfg = {"listen": listen, "listener_authorities": [listen],
       "broker_url": f"http://127.0.0.1:{broker}", "policy_file": f"{r}/policy.json",
       "audit_file": f"{r}/audit.jsonl",
       "callers": [{"id": "agent-1", "key_sha256": hashlib.sha256(key.encode()).hexdigest()}],
       "routes": [{"name": n, "host": h, "error_shape": "aws"} for n, h in routes]}
json.dump(cfg, open(f"{r}/config.json", "w"), indent=1)
json.dump({"rules": [{"caller": "agent-1", "route": n, "methods": ["GET", "POST"], "path_prefixes": ["/"]}
                     for n, _ in routes]}, open(f"{r}/policy.json", "w"), indent=1)
EOF

# The value is read inside the child's own environment assignment; it is never
# echoed, and this shell is replaced by ap-proxy below.
KIRO_API_KEY="$(cat "$S/KIRO_API_KEY")" python3 /opt/ap/broker.py --listen "$BROKER" --cred c-kiro=KIRO_API_KEY &
i=0
until curl -s -o /dev/null "http://127.0.0.1:$BROKER/admin/stats"; do
  i=$((i+1)); [ $i -lt 100 ] || { echo "broker did not start" >&2; exit 1; }; sleep 0.1
done
SURR=$(curl -s -X POST "http://127.0.0.1:$BROKER/admin/mint" \
  -d '{"caller":"agent-1","route":"cps,krs,cw,q","credential_id":"c-kiro","ttl":86400}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["surrogate"], end="")')

umask 022
printf %s "$SURR" > "$H/surrogate.tmp" && mv "$H/surrogate.tmp" "$H/surrogate"
cp "$R/caller-key" "$H/caller-key.tmp" && chmod 644 "$H/caller-key.tmp" && mv "$H/caller-key.tmp" "$H/caller-key"
echo "${LISTEN##*:}" > "$H/port"
echo "proxy-entry: broker up, surrogate minted, handoff written"
exec /usr/local/bin/ap-proxy "$R/config.json"
