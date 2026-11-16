#!/bin/bash
# Run on the k3s test node. Creates Secret ap-kiro (key KIRO_API_KEY) from
# ~/.env by key name. The value goes through a pipe into kubectl's stdin only:
# never on a command line, in a file, or in any output.
set -euo pipefail
K=${K:-sudo k3s kubectl}
( set -a; . "$HOME/.env" >/dev/null 2>&1; set +a
  [ -n "${KIRO_API_KEY:-}" ] || { echo "KIRO_API_KEY not in ~/.env" >&2; exit 1; }
  printf %s "$KIRO_API_KEY" ) |
  $K -n auth-proxy-spike create secret generic ap-kiro --from-file=KIRO_API_KEY=/dev/stdin -o name
# key names only
$K -n auth-proxy-spike get secret ap-kiro -o go-template='{{range $k, $v := .data}}{{$k}}{{"\n"}}{{end}}'
