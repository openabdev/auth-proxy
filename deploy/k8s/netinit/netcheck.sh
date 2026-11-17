#!/bin/sh
# Rule-presence checker (root, CAP_NET_ADMIN only). Runs for the life of the pod, next to the app
# containers. Every INTERVAL seconds it compares the live OUTPUT chain (iptables and ip6tables) with
# the snapshot netinit.sh took when it installed the rules, and writes one status line:
#
#   tick=<token> state=ok|fail reason=<code>
#
# The proxy reads that file (read-only) and refuses to serve unless it says ok and the tick keeps
# changing. This script opens no socket, reads no secret and does not change any rule; it holds
# NET_ADMIN only because reading netfilter rules needs it. If it dies, or hangs in a call, the tick
# stops and the proxy closes (fail closed).
#
# Reason codes: ok, expected_missing (no snapshot), rules_unreadable (the iptables call failed or
# timed out), rules_changed (the live chain differs from the snapshot).
#
# Env:
#   EXPECT_DIR  directory with the netinit snapshot (default /run/netinit)
#   STATUS      status file to write (default /run/netcheck/status)
#   INTERVAL    seconds between checks (default 30)
set -u

EXPECT_DIR=${EXPECT_DIR:-/run/netinit}
STATUS=${STATUS:-/run/netcheck/status}
INTERVAL=${INTERVAL:-30}

case "$INTERVAL" in
  '' | *[!0-9]* | 0)
    echo "netcheck: INTERVAL must be a positive number, got '$INTERVAL'" >&2
    exit 2
    ;;
esac

# One check of one table. Prints the reason code.
check_one() {
  tool=$1
  exp="$EXPECT_DIR/expected-$tool"
  if [ ! -s "$exp" ]; then
    echo expected_missing
    return
  fi
  if ! cur=$(timeout 10 "$tool" -S OUTPUT 2>/dev/null); then
    echo rules_unreadable
    return
  fi
  if [ "$cur" != "$(cat "$exp")" ]; then
    echo rules_changed
    return
  fi
  echo ok
}

start=$(date +%s)
n=0
while :; do
  reason=ok
  for tool in iptables ip6tables; do
    r=$(check_one "$tool")
    if [ "$r" != ok ]; then
      reason=$r
      break
    fi
  done
  n=$((n + 1))
  if [ "$reason" = ok ]; then state=ok; else state=fail; fi
  # Write beside the status file, then rename, so the reader never sees a partial line.
  printf 'tick=%s-%s state=%s reason=%s\n' "$start" "$n" "$state" "$reason" > "$STATUS.tmp" &&
    mv "$STATUS.tmp" "$STATUS"
  if [ "$reason" != ok ]; then
    echo "netcheck: fail: $reason" >&2
  fi
  sleep "$INTERVAL"
done
