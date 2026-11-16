#!/bin/sh
# INTERIM Q1-A path (docs/interim-static-session.md): generate the one caller key and
# the one pod-lifetime surrogate, and print the three things that go elsewhere.
#
# Usage: deploy/k8s/interim-keygen.sh OUTDIR
#
# Writes OUTDIR/caller-key and OUTDIR/surrogate (mode 0600, directory 0700). They are
# secrets: create the Kubernetes Secret from them, then delete the directory. The
# printed hashes are not secret.
set -eu
out=${1:?usage: interim-keygen.sh OUTDIR}
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
umask 077
mkdir -p "$out"
[ ! -e "$out/caller-key" ] && [ ! -e "$out/surrogate" ] \
  || { echo "refusing to overwrite $out/caller-key or $out/surrogate" >&2; exit 1; }
printf 'apk_%s' "$(openssl rand -hex 32)" > "$out/caller-key"
printf 'aps_%s' "$(openssl rand -hex 32)" > "$out/surrogate"
hash() { openssl dgst -sha256 -r < "$1" | cut -d' ' -f1; }
cat <<MSG
Generated $out/caller-key and $out/surrogate (secret, mode 0600).

1. policy.toml, top level:
   caller_key_sha256 = "$(hash "$out/caller-key")"

2. proxy container argument (deploy/k8s/pod-interim-static.yaml):
   --interim-static-surrogate-sha256=$(hash "$out/surrogate")

3. the Secret the agent pod reads (then delete $out):
   kubectl create secret generic auth-proxy-interim-agent \\
     --from-file=caller-key=$out/caller-key --from-file=surrogate=$out/surrogate
MSG
