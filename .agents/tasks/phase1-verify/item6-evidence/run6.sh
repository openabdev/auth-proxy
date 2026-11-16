#!/bin/bash
# Timed hello-race run on the live pod. Foreground, raw output to stdout.
K="sudo -n k3s kubectl -n ap-item6"
now() { date -u +%H:%M:%S.%N | cut -c1-12; }
ev() { echo "[$(now)Z driver] $*"; }
ev "pod before:"; $K get pod ap-agent -o wide --no-headers
ev "no socket-mode override anywhere in the applied pod:"; $K get pod ap-agent -o yaml | grep -ci "SESSION_SOCKET_MODE\|session-socket-mode" ; echo "(count above must be 0)"
ev "proxy container env + args"; $K get pod ap-agent -o jsonpath='{.spec.containers[?(@.name=="proxy")].args}{" env="}{.spec.containers[?(@.name=="proxy")].env}{"\n"}'
ev "session socket as seen by the agent (numeric ids)"; $K exec ap-agent -c agent -- sh -c 'id; ls -ln /run/auth-proxy; ls -ld /run/auth-proxy-admin 2>&1'
ev "ap-egress container: socket paths mounted?"; $K exec ap-agent -c ap-egress -- sh -c 'id -u; ls /run/auth-proxy /run/auth-proxy-admin 2>&1'
ev "container ps (before kill)"; $K exec ap-agent -c agent -- /usr/local/bin/hr-authority ps
# wait for 3 renews, then 7 s more
while [ "$($K logs ap-agent -c agent | grep -c ' RENEW ')" -lt 3 ]; do sleep 2; done
sleep 7
ev "orphan.log tail before kill"; $K exec ap-agent -c agent -- tail -n 3 /tmp/orphan.log
ev "agent log before kill"; $K logs ap-agent -c agent | grep -v ORPHAN
CID=$($K get pod ap-agent -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].containerID}' | sed 's#containerd://##')
OLDSUR=$($K exec ap-agent -c agent -- sh -c 'ls /tmp/surrogate.sess-*' 2>/dev/null | head -1)
ev "old surrogate file: $OLDSUR  container id: ${CID:0:12}"
ev "KILL agent container now (crictl stop --timeout 0 = SIGKILL to PID 1)"
sudo -n k3s crictl stop --timeout 0 "$CID" >/dev/null
ev "KILLED (crictl returned)"
# wait for restart
for i in $(seq 1 60); do
  RC=$($K get pod ap-agent -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')
  ST=$($K get pod ap-agent -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].state}')
  case "$ST" in *running*) [ "$RC" = 1 ] && break;; esac
  sleep 1
done
ev "agent restartCount=$RC state=$ST"
$K get pod ap-agent -o wide --no-headers
ev "container ps (after restart)"; $K exec ap-agent -c agent -- /usr/local/bin/hr-authority ps
ev "orphan.log: lines after the kill? (tail)"; $K exec ap-agent -c agent -- tail -n 2 /tmp/orphan.log
ev "start rival probe (uid 1000, exec'd, 50 s, hello every 5 s)"
$K exec ap-agent -c agent -- /usr/local/bin/hr-authority probe 50 > /tmp/ap-item6-build/probe.out 2>&1 &
PP=$!
# poll for the new PID1 to win
for i in $(seq 1 120); do
  if $K logs ap-agent -c agent 2>/dev/null | grep -q HELLO_WON; then break; fi
  sleep 2
done
ev "new PID 1 HELLO_WON observed by driver"
wait $PP
ev "probe output"; cat /tmp/ap-item6-build/probe.out
ev "GET old surrogate through proxy listener (after lapse)"
$K exec ap-agent -c agent -- /usr/local/bin/hr-authority get "$OLDSUR"
ev "agent log (new container)"; $K logs ap-agent -c agent
ev "agent log (previous container)"; $K logs ap-agent -c agent --previous
ev "proxy log (full)"; $K logs ap-agent -c proxy
ev "restart counts"; $K get pod ap-agent -o jsonpath='{range .status.containerStatuses[*]}{.name}={.restartCount} {end}{"\n"}'
