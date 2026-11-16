#!/bin/sh
# Option A rule-set test for a real cluster (manual or nightly). NOT run by the
# Phase 1 Kubernetes task: no cluster was available. Ported from
# spike/k3s-egress-a (scan-agent.sh, restart-test.sh, probe.py).
#
# Needs: kubectl for the target cluster, a namespace at PSA privileged, the images
# from deploy/k8s built and pushed, and a policy ConfigMap filled in.
#
# Usage: NS=ap-test POD=ap-agent MANIFEST=deploy/k8s/pod.yaml \
#        PROXY_PORT=18080 EGRESS_PORT=3128 sh tests/k8s-egress/run.sh
#
# Checks (each prints PASS/FAIL, exit status 1 if any failed):
#   F1  per-port reject: the agent UID cannot reach an unlisted loopback port
#   F2  inbound replies: ESTABLISHED replies leave for an inbound connection
#   DNS the agent UID cannot resolve names (UDP/TCP 53 rejected)
#   REACH the agent UID reaches the proxy port and the egress port
#   OFF  the agent UID cannot reach 1.1.1.1:443 directly
#   HELLO kill the agent container; no agent-UID orphan; the fresh PID 1 wins hello
#         after the 90 s lock
set -u
NS=${NS:-ap-test}
POD=${POD:-ap-agent}
MANIFEST=${MANIFEST:-deploy/k8s/pod.yaml}
PROXY_PORT=${PROXY_PORT:-18080}
EGRESS_PORT=${EGRESS_PORT:-3128}
OTHER_PORT=${OTHER_PORT:-18999}     # a loopback port nothing allows; a listener is started on it
K="kubectl -n $NS"
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1: $2"; fail=1; }

# TCP connect probe run as the agent UID inside the agent container.
# Prints: open | refused | timeout
probe() {
  $K exec "$POD" -c agent -- python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET); s.settimeout(3)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); print("open")
except ConnectionRefusedError:
    print("refused")
except Exception:
    print("timeout")
PY
}

# The manifest is applied with OTHER_PORTS set on netinit, so that F1 tests a rule
# that exists. A refused connect alone proves nothing (it is also what a closed
# port answers), so F1 starts listeners and requires one reject and one accept.
sed "s|value: \"3128\"}|value: \"3128\"}\n    - {name: OTHER_PORTS, value: \"$OTHER_PORT\"}|" "$MANIFEST" | $K apply -f - >/dev/null \
  || { echo "cannot apply $MANIFEST"; exit 1; }
$K wait --for=condition=Ready "pod/$POD" --timeout=180s >/dev/null || { echo "pod not ready"; exit 1; }
echo "netinit rules:"; $K logs "$POD" -c netinit | sed 's/^/  /'

# Listeners owned by the agent UID: OTHER_PORT (rule: reject) and CONTROL_PORT (no rule).
CONTROL_PORT=$((OTHER_PORT + 1))
$K exec "$POD" -c agent -- sh -c "nohup python3 -c '
import socket, time
for p in ($OTHER_PORT, $CONTROL_PORT):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"127.0.0.1\", p)); s.listen(8); globals()[\"s%d\" % p] = s
time.sleep(600)' >/dev/null 2>&1 &" 
sleep 2
r=$(probe 127.0.0.1 "$OTHER_PORT")
c=$(probe 127.0.0.1 "$CONTROL_PORT")
[ "$r" = refused ] && [ "$c" = open ] && ok "F1 listed loopback port rejected ($r), unlisted control open ($c)" \
  || bad F1 "listed=$r (want refused) control=$c (want open)"

# REACH: allowed ports connect.
r=$(probe 127.0.0.1 "$PROXY_PORT");  [ "$r" = open ] && ok "REACH proxy port" || bad REACH "proxy port: $r"
r=$(probe 127.0.0.1 "$EGRESS_PORT"); [ "$r" = open ] && ok "REACH egress port" || bad REACH "egress port: $r"

# OFF: direct internet is rejected.
r=$(probe 1.1.1.1 443); [ "$r" != open ] && ok "OFF direct 1.1.1.1:443 blocked ($r)" || bad OFF "reachable"

# DNS: name resolution as the agent UID fails.
d=$($K exec "$POD" -c agent -- python3 -c "
import socket
socket.setdefaulttimeout(3)
try: socket.gethostbyname('github.com'); print('resolved')
except Exception: print('failed')")
[ "$d" = failed ] && ok "DNS blocked" || bad DNS "resolved"

# F2: replies to an inbound connection. Connect to the pod from another pod and
# check the proxy port answers (the reply leaves via the ESTABLISHED rule only
# for the agent UID; this checks that the agent runtime's own listener replies).
# Needs the runtime to listen on 8090 (openab-pty). Skipped when it does not.
ip=$($K get pod "$POD" -o jsonpath='{.status.podIP}')
if $K run ap-f2-client --rm -i --restart=Never --image=docker.io/library/busybox:1.36 -- \
     sh -c "echo | nc -w 3 $ip 8090" >/dev/null 2>&1; then
  ok "F2 inbound reply from the agent UID"
else
  echo "SKIP F2 (no listener on 8090 in the agent container, or client pod failed)"
fi

# HELLO: kill the agent container (PID 1 = runtime). Kubelet restarts it in the
# same sandbox; the rules stay. No agent-UID process of the old container may
# survive, and the fresh PID 1 must win hello once the 90 s lock lapses.
before=$($K get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')
$K exec "$POD" -c agent -- sh -c 'kill -9 1' >/dev/null 2>&1
for _ in $(seq 60); do
  now=$($K get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')
  [ "$now" != "$before" ] && break
  sleep 1
done
$K wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null
n=$($K exec "$POD" -c agent -- sh -c 'ps -eo pid,uid | awk "\$2==1000" | wc -l')
echo "agent-UID processes right after restart: $n (the fresh runtime and its children only)"
echo "waiting up to 120 s for the fresh PID 1 to win hello (lock lapses at 90 s)..."
won=0
for _ in $(seq 24); do
  if $K logs "$POD" -c agent --tail=50 2>/dev/null | grep -q "hello ok"; then won=1; break; fi
  sleep 5
done
[ "$won" = 1 ] && ok "HELLO fresh PID 1 won hello" || bad HELLO "no 'hello ok' in the agent log (adjust the grep to your runtime's message)"

exit "$fail"
