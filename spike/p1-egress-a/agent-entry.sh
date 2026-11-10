#!/bin/sh
# Agent container entrypoint: the "platform" step that runs before any kiro-cli
# process. It writes ~/.kiro/settings/cli.json so that kiro-cli's four API
# endpoints point at the loopback proxy, then idles. kiro-cli itself is started
# later (kubectl exec, through /opt/ap/kiro-run) and never configures anything.
set -eu
i=0
until [ -s /handoff/caller-key ] && [ -s /handoff/port ]; do
  i=$((i+1)); [ $i -lt 600 ] || { echo "no handoff from proxy" >&2; exit 1; }; sleep 0.1
done
mkdir -p "$HOME/.kiro/settings" /work
python3 - <<'EOF'
import json, os
key = open("/handoff/caller-key").read().strip()
port = open("/handoff/port").read().strip()
base = f"http://127.0.0.1:{port}/ap/{key}"
s = {k: {"endpoint": f"{base}/{r}", "region": "us-east-1"} for k, r in
     (("api.cps.service", "cps"), ("api.krs.service", "krs"),
      ("api.codewhisperer.service", "cw"), ("api.q.service", "q"))}
p = os.path.expanduser("~/.kiro/settings/cli.json")
json.dump(s, open(p, "w"), indent=2)
print("agent-entry: wrote", p, "with", len(s), "loopback endpoints")
EOF
trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
