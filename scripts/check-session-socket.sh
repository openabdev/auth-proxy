#!/bin/sh
# Session-socket access check. Two modes.
#
#   static (default): reads the pod manifests, needs no cluster. Run from the repo root:
#       sh scripts/check-session-socket.sh [manifest ...]   (default: both deploy/k8s pods)
#   live: against a running pod, as the non-root agent UID 1000 in the agent container:
#       LIVE=1 NS=ap-test POD=ap-agent sh scripts/check-session-socket.sh
#
# Design (docs/design/phase1.md, "Session socket access"): the proxy and the agent
# container share ONE primary group (GID 2000); the socket is 0660 proxy:2000. ap-egress
# (GID 1002) is not in it. The admin socket sits in a volume only the proxy mounts.
# No fsGroup or supplementalGroups (pod-wide), no world-writable socket.
set -u
SGID=2000
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1: $2"; fail=1; }

if [ "${LIVE:-}" = 1 ]; then
  NS=${NS:-ap-test}; POD=${POD:-ap-agent}
  K="kubectl -n $NS exec $POD -c agent --"
  uid=$($K id -u 2>/dev/null)
  [ "$uid" = 1000 ] && ok "agent container runs as UID 1000" || bad "uid" "got '$uid'"
  out=$($K python3 - <<'PY' 2>&1
import os, socket
def try_(p):
    s = socket.socket(socket.AF_UNIX); s.settimeout(3)
    try:
        s.connect(p); return "open"
    except FileNotFoundError: return "absent"
    except PermissionError: return "denied"
    except Exception as e: return "error:" + type(e).__name__
    finally: s.close()
st = os.stat("/run/auth-proxy/session.sock")
print("stat", oct(st.st_mode & 0o7777), st.st_uid, st.st_gid)
print("session", try_("/run/auth-proxy/session.sock"))
print("admin", try_("/run/auth-proxy-admin/admin.sock"))
print("dirs", os.path.exists("/run/auth-proxy-admin"))
PY
)
  echo "$out" | sed 's/^/  /'
  echo "$out" | grep -q '^session open$' && ok "UID 1000 connects to the session socket" \
    || bad "session" "UID 1000 cannot connect"
  echo "$out" | grep -qE '^admin (absent|denied)$' && ok "UID 1000 cannot reach the admin socket" \
    || bad "admin" "admin socket reachable or probe failed"
  echo "$out" | grep -q "^stat 0o660 .* $SGID\$" && ok "session socket is 0660, group $SGID (not world-accessible)" \
    || bad "mode" "expected 0660 with group $SGID"
  exit $fail
fi

[ $# -gt 0 ] || set -- deploy/k8s/pod.yaml deploy/k8s/pod-interim-static.yaml
for f in "$@"; do
  [ -f "$f" ] || { bad "$f" "not found"; continue; }
  # Extract the lines of one container (a "- name: X" entry in the containers list).
  blk() { awk -v n="$1" '
    /^  (initContainers|containers|volumes):/ {sec=$1}
    sec=="containers:" && /^  - name: / {cur=($3==n)}
    sec=="containers:" && cur {print}' "$f"; }
  gid() { blk "$1" | sed -n 's/.*runAsGroup: *\([0-9]*\).*/\1/p' | head -1; }
  pg=$(gid proxy); ag=$(gid agent); eg=$(gid ap-egress)
  if blk agent | grep -q 'session-sock'; then
    [ "$pg" = "$SGID" ] && [ "$ag" = "$SGID" ] \
      && ok "$f: proxy and agent share runAsGroup $SGID" \
      || bad "$f" "proxy runAsGroup='$pg' agent runAsGroup='$ag', both must be $SGID"
  else
    [ "$pg" != "$ag" ] && ok "$f: agent does not mount the session socket (no shared group needed)" \
      || bad "$f" "agent has no session socket but shares a group with the proxy"
  fi
  [ -n "$eg" ] && [ "$eg" != "$SGID" ] && [ "$eg" != "$ag" ] \
    && ok "$f: ap-egress is outside the shared group (GID $eg)" \
    || bad "$f" "ap-egress runAsGroup='$eg' must differ from $SGID"
  [ "$(blk agent | sed -n 's/.*runAsUser: *\([0-9]*\).*/\1/p' | head -1)" = 1000 ] \
    && ok "$f: agent runs as UID 1000" || bad "$f" "agent is not UID 1000"
  # Pod-wide group knobs would add the group to every container, ap-egress included.
  if grep -v '^ *#' "$f" | grep -qE 'fsGroup|supplementalGroups'; then
    bad "$f" "fsGroup/supplementalGroups set (applies to every container)"
  else ok "$f: no fsGroup or supplementalGroups"; fi
  if grep -v '^ *#' "$f" | grep -qE 'AP_SESSION_SOCKET_MODE|--session-socket-mode'; then
    bad "$f" "session socket mode overridden; the default 0660 must be kept"
  else ok "$f: session socket mode is the 0660 default"; fi
  blk agent | grep -q 'admin-sock' && bad "$f" "agent mounts the admin socket volume" \
    || ok "$f: agent does not mount the admin socket volume"
  blk ap-egress | grep -qE 'admin-sock|session-sock' && bad "$f" "ap-egress mounts a socket volume" \
    || ok "$f: ap-egress mounts neither socket volume"
  blk proxy | grep -q 'admin-sock' && ok "$f: proxy mounts the admin socket volume" \
    || bad "$f" "proxy does not mount admin-sock"
  blk agent | grep -qE 'kiro-secret' && bad "$f" "agent mounts the credential Secret" \
    || ok "$f: agent does not mount the credential Secret"
done
exit $fail
