#!/bin/sh
# Node-side setup for the Phase 1 K8s combined iptables verification. Run on the k3s node, from the
# repo root (needs deploy/k8s/). Applies deploy/k8s/pod.yaml with only test substitutions:
#   - the four image placeholders -> locally imported ap-verify/* images
#   - netinit gets OTHER_PORTS=18190 (a decoy sidecar loopback port) and TEST_V6_ADDR (test aid)
#   - the placeholder ConfigMap is replaced by a real policy; the Secret holds a dummy value
# Env: KUBECTL (default "k3s kubectl"), NS (default ap-verify-ipt).
set -eu
KUBECTL=${KUBECTL:-k3s kubectl}
NS=${NS:-ap-verify-ipt}
CALLER_KEY=dummy-caller-key-not-real
HASH=$(printf %s "$CALLER_KEY" | sha256sum | cut -d' ' -f1)

$KUBECTL create ns "$NS"
$KUBECTL label ns "$NS" pod-security.kubernetes.io/enforce=privileged

sed "s/^caller_key_sha256 = \"[0-9a-f]*\".*/caller_key_sha256 = \"$HASH\"/" deploy/k8s/policy.example.toml > /tmp/ap-verify-policy.toml
$KUBECTL -n "$NS" create configmap auth-proxy-policy --from-file=policy.toml=/tmp/ap-verify-policy.toml
printf %s dummy-credential-not-real | $KUBECTL -n "$NS" create secret generic auth-proxy-kiro --from-file=api_key=/dev/stdin

# Pod document only (second YAML document), images substituted, test env added to netinit.
awk 'BEGIN{d=1} /^---$/{d++; next} d>=2' deploy/k8s/pod.yaml \
 | sed -e 's#REPLACE/auth-proxy-netinit:TAG#docker.io/ap-verify/netinit:dev#' \
       -e 's#REPLACE/auth-proxy:TAG#docker.io/ap-verify/proxy:dev#' \
       -e 's#REPLACE/ap-egress:TAG#docker.io/ap-verify/egress:dev#' \
       -e 's#REPLACE/agent-runtime:TAG#docker.io/ap-verify/agent:dev#' \
       -e 's#^\( *\)- {name: EGRESS_PORT, value: "3128"}#&\n\1- {name: OTHER_PORTS, value: "18190"}\n\1- {name: TEST_V6_ADDR, value: "fd00:a9::2/64"}#' \
 | $KUBECTL -n "$NS" apply -f -
rm -f /tmp/ap-verify-policy.toml
echo "setup done: ns=$NS"
