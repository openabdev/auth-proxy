#!/bin/sh
# Init container (root, CAP_NET_ADMIN only). Installs the per-UID egress rules in the pod
# network namespace, prints them, and exits. The rules live in the pod netns, so they stay
# in place across restarts of the app containers.
#
# Rule set (design Q3-E2, with findings F1 and F2 applied). P is the auth-proxy listener and
# E is the ap-egress listener. Each rule is repeated for ip6tables.
#   1. ESTABLISHED replies for the agent UID are accepted (F2).
#   2. The agent UID may reach P and E on loopback.
#   3. The agent UID may reach no other loopback TCP port listed in OTHER_LO_PORTS.
#   4. Any other loopback packet from the agent UID is rejected (F1: lo is not open to the agent).
#   5. Anything from the agent UID that leaves lo is rejected. This also closes DNS.
#
# Env:
#   AGENT_UID        UID the rules confine (default 1000)
#   PROXY_PORT       loopback port of the auth-proxy listener (default 18080)
#   EGRESS_PORT      loopback port of the ap-egress listener (default 18081)
#   OTHER_LO_PORTS   space list of extra loopback TCP ports the agent UID may not reach
set -eu

AGENT_UID=${AGENT_UID:-1000}
PROXY_PORT=${PROXY_PORT:-18080}
EGRESS_PORT=${EGRESS_PORT:-18081}
OTHER_LO_PORTS=${OTHER_LO_PORTS:-}

# The values go into rule arguments, so accept digits only.
for v in "$AGENT_UID" "$PROXY_PORT" "$EGRESS_PORT" $OTHER_LO_PORTS; do
  case "$v" in
    '' | *[!0-9]*)
      echo "netinit: numeric value required, got '$v'" >&2
      exit 2
      ;;
  esac
done

for T in iptables ip6tables; do
  $T -F OUTPUT
  $T -A OUTPUT -m owner --uid-owner "$AGENT_UID" -m conntrack --ctstate ESTABLISHED -j ACCEPT
  $T -A OUTPUT -o lo -p tcp --dport "$PROXY_PORT" -m owner --uid-owner "$AGENT_UID" -j ACCEPT
  $T -A OUTPUT -o lo -p tcp --dport "$EGRESS_PORT" -m owner --uid-owner "$AGENT_UID" -j ACCEPT
  for p in $OTHER_LO_PORTS; do
    $T -A OUTPUT -o lo -p tcp --dport "$p" -m owner --uid-owner "$AGENT_UID" -j REJECT --reject-with tcp-reset
  done
  $T -A OUTPUT -o lo -m owner --uid-owner "$AGENT_UID" -j REJECT --reject-with tcp-reset
  $T -A OUTPUT ! -o lo -m owner --uid-owner "$AGENT_UID" -j REJECT
done

echo "== iptables $(iptables -V)"
iptables -S OUTPUT
echo "== ip6tables"
ip6tables -S OUTPUT
