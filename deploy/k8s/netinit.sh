#!/bin/sh
# Init container (root, CAP_NET_ADMIN only). Installs the combined Option A rule
# set from docs/design/phase1.md (Q3) in the pod network namespace, for iptables
# and ip6tables, prints it, and exits. The rules live in the pod netns, so they
# outlive restarts of the app containers.
#
# Env:
#   AGENT_UID     UID the rules confine (default 1000)
#   PROXY_PORT    P, the auth-proxy loopback listener (required)
#   EGRESS_PORT   E, the ap-egress loopback listener (required)
#   OTHER_PORTS   space list of further sidecar loopback ports the agent UID must
#                 not reach (default empty: the proxy binds no other TCP port)
#   TEST_V6_ADDR  test aid only: add this IPv6 address to eth0 so that IPv6
#                 traffic has a non-lo route and reaches OUTPUT
#
# Rule order matters: iptables takes the first match.
#   1 ESTABLISHED accept (replies to inbound connections)
#   2 accept lo -> P
#   3 accept lo -> E
#   4 REJECT every other sidecar port (tcp-reset)
#   5 REJECT everything else that is not lo
set -eu
AGENT_UID=${AGENT_UID:-1000}
: "${PROXY_PORT:?PROXY_PORT is required}"
: "${EGRESS_PORT:?EGRESS_PORT is required}"

if [ -n "${TEST_V6_ADDR:-}" ]; then
  ip -6 addr add "$TEST_V6_ADDR" dev eth0 nodad
fi

for T in iptables ip6tables; do
  $T -A OUTPUT -m owner --uid-owner "$AGENT_UID" -m conntrack --ctstate ESTABLISHED -j ACCEPT
  $T -A OUTPUT -o lo -p tcp --dport "$PROXY_PORT" -m owner --uid-owner "$AGENT_UID" -j ACCEPT
  $T -A OUTPUT -o lo -p tcp --dport "$EGRESS_PORT" -m owner --uid-owner "$AGENT_UID" -j ACCEPT
  for p in ${OTHER_PORTS:-}; do
    $T -A OUTPUT -o lo -p tcp --dport "$p" -m owner --uid-owner "$AGENT_UID" -j REJECT --reject-with tcp-reset
  done
  $T -A OUTPUT ! -o lo -m owner --uid-owner "$AGENT_UID" -j REJECT
done

echo "== iptables $(iptables -V)"
iptables -S OUTPUT
echo "== ip6tables"
ip6tables -S OUTPUT
