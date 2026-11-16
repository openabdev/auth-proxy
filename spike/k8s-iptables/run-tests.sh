#!/bin/bash
# Node-side driver: runs agent-battery.sh sections in the pod's containers and writes raw output to
# $OUT/*.txt. Needs the pod from setup.sh. Env: KUBECTL (default "k3s kubectl"), NS, OUT, BATT.
set -u
KUBECTL=${KUBECTL:-k3s kubectl}; NS=${NS:-ap-verify-ipt}; OUT=${OUT:-/tmp/ap-verify-results}
BATT=${BATT:-$(dirname "$0")/agent-battery.sh}
K="$KUBECTL -n $NS"; mkdir -p "$OUT"
x() { c=$1; sec=$2; $K exec -i ap-agent -c "$c" -- env GH_IP="$GH_IP" SECTION="$sec" bash -s < "$BATT"; }

GH_IP=$($K exec ap-agent -c proxy -- getent ahostsv4 github.com | awk 'NR==1{print $1}')
echo "github IPv4 resolved by the proxy UID: ${GH_IP:+yes}"

# decoy sidecar loopback listeners owned by the proxy UID: 18190 is in OTHER_PORTS, 19999 is not
$K exec ap-agent -c proxy -- sh -c 'nohup python3 -c "
import socket,time
for p in (18190,19999):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",p)); s.listen(8); globals()[\"s%d\"%p]=s
time.sleep(3600)" >/dev/null 2>&1 &' 
sleep 2

{ date -u +%FT%TZ; x agent rules; }              > "$OUT/10-agent-rules.txt" 2>&1
{ x agent noproxy; }                              > "$OUT/20-noproxy.txt" 2>&1
{ x agent refused; }                              > "$OUT/30-refused.txt" 2>&1
{ x agent via-egress; }                           > "$OUT/40-via-egress.txt" 2>&1
{ x agent ignore; }                               > "$OUT/50-ignore-proxy.txt" 2>&1
{ echo "== proxy UID (1001)"; x proxy uid; echo "== ap-egress UID (1002)"; x ap-egress uid; } > "$OUT/60-other-uids.txt" 2>&1

# ESTABLISHED: inbound connection to an agent-UID listener on the pod IP, answered from the agent UID
POD_IP=$($K get pod ap-agent -o jsonpath='{.status.podIP}')
$K exec ap-agent -c agent -- sh -c 'nohup python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"0.0.0.0\",8099)); s.listen(4)
c,_=s.accept(); c.sendall(b\"reply-from-agent-uid\n\"); c.close()" >/dev/null 2>&1 &'
sleep 1
{ echo "inbound to agent-UID listener (node -> pod), answered under the OUTPUT rules:"; \
  python3 -c "
import socket,sys
s=socket.create_connection(('$POD_IP',8099),5); print(s.recv(100))" 2>&1; } > "$OUT/70-established.txt"

# rule counters from inside the pod netns (node side, read-only)
PID=$(pgrep -f 'ap-egress --policy' | head -1)   # any process of the pod shares its netns
{ echo "== iptables -L OUTPUT -v -n -x (pod netns)"; sudo -n nsenter -t "$PID" -n iptables -L OUTPUT -v -n -x; echo "== ip6tables"; sudo -n nsenter -t "$PID" -n ip6tables -L OUTPUT -v -n -x; } > "$OUT/80-counters.txt" 2>&1
$K logs ap-agent -c netinit > "$OUT/00-netinit.txt" 2>&1
$K get pod ap-agent -o jsonpath='{range .status.containerStatuses[*]}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{"\n"}{end}' > "$OUT/01-pod-status.txt"
echo done
