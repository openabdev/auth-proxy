#!/bin/sh
# Init container (root, CAP_NET_ADMIN only). Installs the per-UID egress rules in
# the pod network namespace, prints them, and exits. Rules live in the pod netns,
# which belongs to the pod sandbox, so they outlive restarts of the app containers.
#
# Env:
#   AGENT_UID              UID the rules confine (default 1000)
#   DENY_LO_PORTS          space list of loopback TCP ports the agent UID may NOT
#                          reach (the sidecar's private listeners, e.g. the broker)
#   ALLOW_INBOUND_REPLIES  1 = accept agent-UID packets of connections that are
#                          already ESTABLISHED (replies to inbound connections)
#   TEST_V6_ADDR           test aid only: add this IPv6 address to eth0 so that
#                          IPv6 traffic has a non-lo route and reaches OUTPUT
set -eu
AGENT_UID=${AGENT_UID:-1000}

if [ -n "${TEST_V6_ADDR:-}" ]; then
  ip -6 addr add "$TEST_V6_ADDR" dev eth0 nodad
fi

for T in iptables ip6tables; do
  for p in ${DENY_LO_PORTS:-}; do
    $T -A OUTPUT -o lo -p tcp --dport "$p" -m owner --uid-owner "$AGENT_UID" -j REJECT --reject-with tcp-reset
  done
  if [ "${ALLOW_INBOUND_REPLIES:-0}" = 1 ]; then
    $T -A OUTPUT -m owner --uid-owner "$AGENT_UID" -m conntrack --ctstate ESTABLISHED -j ACCEPT
  fi
  # The rule from the RFC draft: the agent UID may use only lo.
  $T -A OUTPUT -m owner --uid-owner "$AGENT_UID" ! -o lo -j REJECT
done

echo "== iptables $(iptables -V)"
iptables -S OUTPUT
echo "== ip6tables"
ip6tables -S OUTPUT
