#!/bin/sh
# Run on the k3s test node (Linux x86_64, cargo + podman present).
#   WORK=<dir holding exp2/ (rsync of spike/exp2) and k3s-egress-a/>  sh build.sh
# Builds ap-proxy, assembles the image context, builds the image with podman and
# imports it into k3s containerd as localhost/ap-spike:dev.
set -eu
WORK=${WORK:?}
KIRO_BIN=${KIRO_BIN:-$HOME/.local/bin}
IMG=localhost/ap-spike:dev
(cd "$WORK/exp2" && "$HOME/.cargo/bin/cargo" build --release --bin ap-proxy)
C="$WORK/ctx"
rm -rf "$C" && mkdir -p "$C/bin"
cp "$WORK/exp2/target/release/ap-proxy" "$KIRO_BIN/kiro-cli" "$KIRO_BIN/kiro-cli-chat" "$KIRO_BIN/kiro-cli-term" "$C/bin/"
cp "$WORK/exp2/test/broker.py" "$WORK/exp2/test/acp_timed.py" "$C/"
cp "$WORK"/k3s-egress-a/Containerfile "$WORK"/k3s-egress-a/*.sh "$WORK"/k3s-egress-a/*.py "$WORK/k3s-egress-a/kiro-run" "$C/"
podman build -t "$IMG" -f "$C/Containerfile" "$C"
podman save --format docker-archive "$IMG" | sudo k3s ctr -n k8s.io images import -
sudo k3s ctr -n k8s.io images ls -q | grep ap-spike
