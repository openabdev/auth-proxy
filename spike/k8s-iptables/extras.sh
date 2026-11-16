#!/bin/bash
# Node-side extras (after run-tests.sh): (1) negative control for the ESTABLISHED rule, applied to the
# test pod's netns only and restored; (2) where the multi-second lookups through ap-egress come from.
set -u
KUBECTL=${KUBECTL:-k3s kubectl}; NS=${NS:-ap-verify-ipt}; K="$KUBECTL -n $NS"
PID=$(pgrep -f 'ap-egress --policy' | head -1)
NSX() { sudo -n nsenter -t "$PID" -n "$@"; }
POD_IP=$($K get pod ap-agent -o jsonpath='{.status.podIP}')
listener() { $K exec ap-agent -c agent -- sh -c 'nohup python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"0.0.0.0\",8099)); s.listen(4)
c,_=s.accept(); c.sendall(b\"reply-from-agent-uid\n\"); c.close()" >/dev/null 2>&1 &'; sleep 1; }
dial() { python3 -c "
import socket
try:
    s=socket.create_connection(('$POD_IP',8099),5); s.settimeout(5); print('received', s.recv(100))
except Exception as e: print('failed:', type(e).__name__, e)"; }
echo "== ESTABLISHED negative control (pod netns, rule 1 removed, then restored)"
RULE='OUTPUT -m owner --uid-owner 1000 -m conntrack --ctstate ESTABLISHED -j ACCEPT'
echo "-- with rule 1:";    listener; dial
NSX iptables -D $RULE; echo "-- rule 1 removed:"; listener; dial
NSX iptables -I OUTPUT 1 -m owner --uid-owner 1000 -m conntrack --ctstate ESTABLISHED -j ACCEPT
echo "-- rule 1 restored:"; listener; dial
NSX iptables -S OUTPUT | head -3
echo
echo "== cluster DNS latency as the ap-egress UID (no iptables rule applies to UID 1002)"
for h in pypi.org files.pythonhosted.org index.crates.io registry.npmjs.org github.com; do
  for i in 1 2; do
    s=$EPOCHREALTIME; $K exec ap-agent -c ap-egress -- getent ahostsv4 $h >/dev/null; e=$EPOCHREALTIME
    printf '%s try%s getent+exec %.2fs\n' $h $i "$(python3 -c "print(${e/,/.}-${s/,/.})")"
  done
done
s=$EPOCHREALTIME; $K exec ap-agent -c ap-egress -- python3 -c "
import socket,time
for h in ('pypi.org','files.pythonhosted.org','registry.npmjs.org'):
    t=time.time(); socket.getaddrinfo(h,443,proto=6); print(h, 'getaddrinfo %.2fs'%(time.time()-t))"
