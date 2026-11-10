#!/bin/bash
# Run on the node (sudo). Counts files and process environments visible to the
# agent container that contain the real KIRO_API_KEY. Prints counts and paths
# only; the value is read from ~/.env by name and passed to grep on a pipe.
#   POD=ap-a bash scan-agent.sh
set -euo pipefail
POD=${POD:-ap-a}
NS=auth-proxy-spike
CID=$(sudo k3s crictl ps --namespace "$NS" --pod "$(sudo k3s crictl pods --namespace "$NS" --name "$POD" -q)" --name agent -q)
APID=$(sudo k3s crictl inspect "$CID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["pid"])')
key() { ( set -a; . "$HOME/.env" >/dev/null 2>&1; printf %s "$KIRO_API_KEY" ); }
# 1. every process in the agent container's PID namespace: environ + cmdline
n=0; hit=0
for p in $(sudo ls /proc | grep -E '^[0-9]+$'); do
  [ "$(sudo readlink /proc/$p/ns/pid 2>/dev/null)" = "$(sudo readlink /proc/$APID/ns/pid)" ] || continue
  [ "$(sudo readlink /proc/$p/ns/mnt 2>/dev/null)" = "$(sudo readlink /proc/$APID/ns/mnt)" ] || continue
  n=$((n+1))
  if sudo cat /proc/$p/environ /proc/$p/cmdline 2>/dev/null | grep -qaF -f <(key); then hit=$((hit+1)); fi
done
echo "agent-container processes scanned: $n, with real key in environ/cmdline: $hit"
# 2. the agent container's whole filesystem view (image + every mount it has)
files=$(key | sudo grep -rlaF -f - --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev "/proc/$APID/root/" 2>/dev/null || true)
echo "files in the agent's filesystem view with the real key: $(printf %s "$files" | grep -c . || true)"
printf '%s\n' "$files" | sed "s#/proc/$APID/root##" | grep . || true
# 3. sanity check of the probe on the other side: the proxy's Secret mount must match
PCID=$(sudo k3s crictl ps --namespace "$NS" --pod "$(sudo k3s crictl pods --namespace "$NS" --name "$POD" -q)" --name proxy -q)
PPID_=$(sudo k3s crictl inspect "$PCID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["pid"])')
c=$(key | sudo grep -rlaF -f - "/proc/$PPID_/root/run/ap-secret/" 2>/dev/null | wc -l)
echo "control: files under the proxy's Secret mount with the real key: $c (expect >= 1)"
