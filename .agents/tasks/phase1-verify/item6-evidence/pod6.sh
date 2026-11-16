#!/bin/bash
# Run on mini: render and apply the interim pod (INTERIM=1) or pod.yaml (INTERIM=0). Test-only edits listed in the report.
set -eu
K="sudo -n k3s kubectl"; NS=ap-item6; B=/tmp/ap-item6-build
SIP=$(cat $B/keys/stub.ip); SH=$(cat $B/keys/surrogate.hash)
if [ "${INTERIM:-1}" = 1 ]; then SRC=$B/src/deploy/k8s/pod-interim-static.yaml; AG=agent; else SRC=$B/src/deploy/k8s/pod.yaml; AG=hr; fi
awk 'BEGIN{d=1} /^---$/{d++; next} d>=2' $SRC \
 | sed -e 's#REPLACE/auth-proxy-netinit:TAG#docker.io/ap-item6/netinit:dev#' \
       -e 's#REPLACE/auth-proxy:TAG#docker.io/ap-item6/proxy:dev#' \
       -e 's#REPLACE/ap-egress:TAG#docker.io/ap-item6/egress:dev#' \
       -e "s#REPLACE/agent-runtime:TAG#docker.io/ap-item6/$AG:dev#" \
       -e "s#REPLACE_WITH_SHA256_OF_THE_SURROGATE\"\]#$SH\", \"--ca-file\", \"/etc/ap-ca/ca.pem\"]#" \
       -e 's#^\(    - {name: proxy-state, mountPath: /var/lib/auth-proxy}.*\)$#\1\n    - {name: ap-ca, mountPath: /etc/ap-ca, readOnly: true}#' \
       -e 's#^  - {name: work, emptyDir: {}}$#  - {name: work, emptyDir: {}}\n  - {name: ap-ca, configMap: {name: ap-ca, defaultMode: 0444}}#' \
       -e "s#^  enableServiceLinks: false\$#  enableServiceLinks: false\n  hostAliases:\n  - {ip: \"$SIP\", hostnames: [\"runtime.us-east-1.kiro.dev\", \"control-plane.placeholder.example\"]}#" \
       -e 's#image: \(docker.io/ap-item6/[a-z]*:dev\)#image: \1\n    imagePullPolicy: Never#' > $B/pod-rendered.yaml
diff <(awk 'BEGIN{d=1} /^---$/{d++; next} d>=2' $SRC) $B/pod-rendered.yaml > $B/pod-rendered.diff || true
$K -n $NS apply -f $B/pod-rendered.yaml
