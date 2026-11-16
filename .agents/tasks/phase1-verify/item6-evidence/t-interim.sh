#!/bin/bash
# Run on mini. All output is masked for apk_/aps_ values. Stub logs never contain header values.
K="sudo -n k3s kubectl -n ap-item6"; A="$K exec ap-agent -c agent --"
mask() { sed -E 's/(apk|aps)_[0-9a-f]{64}/\1_<masked>/g; s/real-dummy-[0-9a-f]+/<REAL-masked>/g'; }
h() { echo; echo "### $*"; }
slog() { $K logs stub | python3 -c '
import sys,json,collections
c=collections.Counter()
for l in sys.stdin:
    if l.startswith("{"):
        r=json.loads(l); c[(r["host"],r["method"],r["path"].split("?")[0],r["xamz_target"],r["authorization_class"])]+=1
for k,v in sorted(c.items()): print(v,"x host=%s %s %s target=%s authorization_class=%s"%k)
print("total requests at stub:",sum(c.values()))'; }
$K delete pod stub --wait=true >/dev/null; $K apply -f /tmp/ap-item6-build/stub.yaml >/dev/null; $K wait --for=condition=Ready pod/stub --timeout=90s >/dev/null
{
h "pod"; $K get pod ap-agent -o wide --no-headers; $K get pod ap-agent -o jsonpath='{range .status.initContainerStatuses[*]}{.name} exit={.state.terminated.exitCode} {end}{"\n"}'
h "proxy start log"; $K logs ap-agent -c proxy | head -8
h "netinit log"; $K logs ap-agent -c netinit | head -14
h "kiro-settings init log"; $K logs ap-agent -c kiro-settings
h "settings file in agent HOME (caller key masked)"; $A sh -c 'cd /home/agent; find . -type f | head; for f in $(find . -name "*.json" -o -name settings* | head -3); do echo "-- $f"; cat $f; echo; done'
h "agent identity and env (surrogate masked)"; $A sh -c 'id; env | grep -E "^(HTTPS_PROXY|NO_PROXY|KIRO_)" '
h "agent mounts: session socket path present?"; $A sh -c 'ls -la /run/auth-proxy /run/auth-proxy-admin 2>&1 | head -4'
echo; echo "######## T1 surrogate-only agent reaches the stub through the proxy"
CK=$($A sh -c "grep -o 'ap/apk_[0-9a-f]*' -r /home/agent | head -1 | sed 's#.*ap/##'")
h "POST krs with surrogate, caller key in path"
$A sh -c "curl -s -o /dev/null -w 'status=%{http_code}\n' -X POST http://127.0.0.1:18080/ap/$CK/kiro-krs/ -H \"authorization: Bearer \$KIRO_API_KEY\" -H 'tokentype: API_KEY' -H 'content-type: application/x-amz-json-1.0' -H 'x-amz-target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse' -d '{}'" | mask
h "POST cps with surrogate"
$A sh -c "curl -s -w ' status=%{http_code}\n' -X POST http://127.0.0.1:18080/ap/$CK/kiro-cps/ -H \"authorization: Bearer \$KIRO_API_KEY\" -H 'x-amz-target: AmazonCodeWhispererService.GetProfile' -d '{}'" | mask
h "negative: wrong surrogate"
$A sh -c "curl -s -w ' status=%{http_code}\n' -X POST http://127.0.0.1:18080/ap/$CK/kiro-krs/ -H 'authorization: aps_0000000000000000000000000000000000000000000000000000000000000000' -d '{}'" | mask
h "negative: no surrogate"
$A sh -c "curl -s -w ' status=%{http_code}\n' -X POST http://127.0.0.1:18080/ap/$CK/kiro-krs/ -d '{}'" | mask
h "negative: wrong caller key"
$A sh -c "curl -s -w ' status=%{http_code}\n' -X POST http://127.0.0.1:18080/ap/apk_0000000000000000000000000000000000000000000000000000000000000000/kiro-krs/ -H \"authorization: Bearer \$KIRO_API_KEY\" -d '{}'" | mask
h "stub log (what the upstream saw, summarised)"; slog; echo "last raw line header names:"; $K logs stub | tail -1 | cut -c1-400
echo; echo "######## T2 real credential never in the agent container"
REAL=$(cat /tmp/ap-item6-build/keys/real)
printf '%s\n' "$REAL" | $K exec -i ap-agent -c agent -- sh -c '
read R
echo "uid=$(id -u) pid1-cmd=$(tr "\0" " " </proc/1/cmdline)"
n=0; for p in /proc/[0-9]*; do for f in environ cmdline; do if grep -aqF -- "$R" $p/$f 2>/dev/null; then n=$((n+1)); echo "HIT $p/$f"; fi; done; done
echo "proc environ+cmdline hits: $n"
echo "procs scanned: $(ls -d /proc/[0-9]* | wc -l)"
m=$(grep -rlF -- "$R" /home /tmp /work /etc /run /var /opt /usr/local /root 2>/dev/null | wc -l); echo "filesystem files containing it (home tmp work etc run var opt usr/local root): $m"
echo "secret volume mounted? $(ls /run/secrets 2>&1 | head -1)"
' | mask
h "mounts in agent container that mention secrets"; $A sh -c 'grep -E "secrets|auth-proxy-kiro" /proc/self/mountinfo | wc -l'
h "negative control: the same scan against the PROXY container's own secret file finds it? (proxy has no shell: skip) ; scan finds the value when planted in /tmp"
printf '%s\n' "$REAL" | $K exec -i ap-agent -c agent -- sh -c 'read R; printf %s "$R" > /tmp/plant; echo "control hits: $(grep -rlF -- "$R" /tmp 2>/dev/null | wc -l)"; rm /tmp/plant'
echo; echo "######## T3 direct egress and DNS refused for the agent UID"
STUB=$(cat /tmp/ap-item6-build/keys/stub.ip)
for cmd in \
 "curl -sS --noproxy '*' -m 8 -o /dev/null -w '%{http_code}' https://example.com" \
 "curl -sS --noproxy '*' -m 8 --resolve example.com:443:93.184.216.34 -o /dev/null -w '%{http_code}' https://example.com" \
 "curl -sS --noproxy '*' -m 8 -k -o /dev/null -w '%{http_code}' https://$STUB:8443/" \
 "getent hosts github.com" \
 "dig +time=2 +tries=1 @10.43.0.10 github.com" \
 "nc -zv -w 3 1.1.1.1 443" \
 "nc -zvu -w 3 10.43.0.10 53" \
 "python3 -c \"import socket;socket.create_connection(('8.8.8.8',53),3)\"" ; do
  echo; echo "\$ $cmd"; t0=$(date +%s.%N); out=$($K exec ap-agent -c agent -- sh -c "$cmd" 2>&1); rc=$?; echo "$out" | tail -3; echo "exit=$rc elapsed=$(awk -v a=$t0 -v b=$(date +%s.%N) 'BEGIN{printf "%.2f",b-a}')s"
done
h "via ap-egress (allowlisted) vs not"
$A sh -c "curl -sS -m 15 -o /dev/null -w 'github.com via egress: %{http_code}\n' https://github.com/; curl -sS -m 10 -o /dev/null -w 'example.com via egress: %{http_code}\n' https://example.com/ 2>&1 | tail -1"
h "agent UID cannot reach the proxy's other things: admin socket"; $A sh -c 'ls /run/auth-proxy-admin 2>&1'
echo; echo "######## T4 Q1-A interim session via kiro-cli (settings written by the init container)"
h "kiro-cli version"; $A kiro-cli --version
h "kiro-cli settings read back (keys masked)"; $A sh -c 'kiro-cli settings api.krs.service; kiro-cli settings api.cps.service' | mask
h "kiro-cli chat --no-interactive (stub upstream, timeout 90s)"
$A sh -c 'cd /work && timeout 90 kiro-cli chat --no-interactive --trust-tools= "say hi" 2>&1 | tail -15; echo "exit=$?"' | mask
h "stub log after kiro-cli (summarised)"; slog
h "proxy audit lines (summarised) and a leak scan"; $K logs ap-agent -c proxy | python3 -c '
import sys,json,collections
c=collections.Counter()
for l in sys.stdin:
    if l.startswith("{"):
        r=json.loads(l); c[(r["route"],r["aws_target"],r["decision"],r["code"],r["session"],r["status"])]+=1
for k,v in sorted(c.items(),key=str): print(v,"x route=%s target=%s decision=%s code=%s session=%s status=%s"%k)'
echo "audit lines containing apk_/aps_/real-dummy: $($K logs ap-agent -c proxy | grep -cE 'apk_|aps_|real-dummy')"
} 2>&1 | mask
