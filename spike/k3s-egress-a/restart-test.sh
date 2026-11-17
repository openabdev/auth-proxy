#!/bin/bash
# Run on the node. Test 8: do the per-UID rules survive an app-container restart,
# and what happens on pod recreation. Containers are stopped with crictl so that
# kubelet restarts them in the same pod sandbox (same network namespace).
set -uo pipefail
NS=auth-proxy-spike
K="sudo k3s kubectl -n $NS"
HERE=$(cd "$(dirname "$0")" && pwd)
sandbox() { sudo k3s crictl pods --namespace $NS --name "$1" --state ready -q; }
netpid() { sudo k3s crictl inspectp "$(sandbox "$1")" | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["pid"])'; }
rules() { echo "rules in pod netns (node view): $(sudo nsenter -t "$(netpid "$1")" -n nft list ruleset 2>/dev/null | grep -c 'skuid 1000') skuid-1000 rules; sandbox=$(sandbox "$1" | cut -c1-12)"; }
egress() { echo "agent egress: $($K exec -i "$1" -c agent -- python3 - tcp:1.1.1.1:443 udp53:resolv tcp:127.0.0.1:18100 < "$HERE/probe.py" | python3 -c 'import json,sys; print(" ".join(f"{d["target"]}={d["result"]}" for d in map(json.loads, sys.stdin)))')"; }
proxy_ok() { echo "proxy path (ListAvailableModels, control-plane call): $($K exec "$1" -c agent -- sh -c 'curl -s -o /dev/null -w "%{http_code}" -m 20 -X POST http://127.0.0.1:18100/ap/$(cat /handoff/caller-key)/cps/ -H "Authorization: Bearer $(cat /handoff/surrogate)" -H "TokenType: API_KEY" -H "Content-Type: application/x-amz-json-1.0" -H "X-Amz-Target: KiroControlPlaneBearerService.ListAvailableModels" -d "{\"origin\":\"KIRO_CLI\"}"')"; }
restarts() { echo "restartCount: $($K get pod "$1" -o jsonpath='{range .status.initContainerStatuses[*]}{.name}={.restartCount} {end}{range .status.containerStatuses[*]}{.name}={.restartCount} {end}')"; }
stop() { sudo k3s crictl stop --timeout 1 "$(sudo k3s crictl ps --namespace $NS --pod "$(sandbox "$1")" --name "$2" -q)" >/dev/null; }
waitready() { for _ in $(seq 60); do [ "$($K get pod "$1" -o jsonpath='{.status.containerStatuses[*].ready}')" = "true true" ] && return; sleep 1; done; }

P=ap-a
echo "=== baseline"; rules $P; restarts $P; egress $P
echo "=== 8a: stop the agent container"; stop $P agent; sleep 2; waitready $P
rules $P; restarts $P; egress $P
echo "cli.json rewritten by the platform entrypoint on restart: $($K exec $P -c agent -- python3 -c 'import json,os; print(sorted(json.load(open(os.path.expanduser("~/.kiro/settings/cli.json")))))')"
echo "=== 8b: stop the proxy container"; stop $P proxy; sleep 2; waitready $P
rules $P; restarts $P; egress $P; proxy_ok $P
echo "=== 8c: delete and recreate the pod"
$K delete pod $P --wait=true >/dev/null
$K apply -f "$HERE/pod-a.yaml" >/dev/null; $K wait --for=condition=Ready pod/$P --timeout=120s >/dev/null
rules $P; restarts $P; egress $P; proxy_ok $P
echo "netinit log of the new pod:"; $K logs $P -c netinit | sed 's/^/  /'
echo "=== 8d: same pod without NET_ADMIN on the init container"
sed -e 's/name: ap-a/name: ap-c/' -e 's/variant: a/variant: c/' -e 's/add: \[NET_ADMIN\]/add: []/' "$HERE/pod-a.yaml" |
  python3 -c 'import sys; print(sys.stdin.read().split("---\n",1)[1])' | $K apply -f - >/dev/null
sleep 15
$K get pod ap-c -o wide --no-headers | awk '{print "ap-c status:", $3, "ready:", $2}'
echo "netinit log:"; $K logs ap-c -c netinit 2>&1 | sed 's/^/  /' | head -5
echo "agent container state: $($K get pod ap-c -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].state}')"
$K delete pod ap-c --wait=true >/dev/null
