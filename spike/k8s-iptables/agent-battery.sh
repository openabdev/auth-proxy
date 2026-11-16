#!/bin/bash
# Run inside a pod container as that container's UID (bash -s on stdin via kubectl exec).
# Usage env: GH_IP (a literal github.com IPv4), SECTION (rules|ignore|via-egress|refused|noproxy|uid).
# Prints "<label> <TAB> rc=<n> <TAB> <seconds> <TAB> <last output line>" per check.
cd /tmp
t() {  # t LABEL CMD...   (runs with the environment as given; wrap with env -u to drop proxy vars)
  local label=$1; shift
  local s=$EPOCHREALTIME out rc
  out=$(timeout 120 "$@" 2>&1); rc=$?
  local e=$EPOCHREALTIME
  printf '%s\trc=%s\t%.2fs\t%s\n' "$label" "$rc" "$(echo "$e - $s" | python3 -c 'import sys;print(eval(sys.stdin.read().replace(",",".")))')" \
    "$(printf %s "$out" | tr -d '\r' | grep -v '^\s*$' | tail -1 | cut -c1-150)"
}
NOPX=(env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u NO_PROXY)
echo "uid=$(id -u) HTTPS_PROXY=${HTTPS_PROXY:-unset} NO_PROXY=${NO_PROXY:-unset}"
P=/opt/ap/probe.py
case "$SECTION" in
rules)
  python3 $P tcp:127.0.0.1:18080 tcp:127.0.0.1:3128 tcp:127.0.0.1:18190 tcp:127.0.0.1:19999 \
    udp53:resolv tcp53:resolv name:github.com tcp:1.1.1.1:443 "tcp:$GH_IP:443" tcp:10.42.0.1:22 \
    tcp6:fd00:a9::1:80 tcp6:2606:4700:4700::1111:443 tcp:127.0.0.1:1
  ;;
ignore)
  mkdir -p tb && cd tb
  t curl-noproxy-name      "${NOPX[@]}" curl -sS -m 60 -o /dev/null https://github.com/
  t curl-noproxy-name-2    "${NOPX[@]}" curl -sS -m 60 -o /dev/null https://github.com/
  t curl-noproxy-ip        "${NOPX[@]}" curl -sS -m 60 -o /dev/null --resolve github.com:443:$GH_IP https://github.com/
  t wget-noproxy           "${NOPX[@]}" wget -q -T 60 -O /dev/null https://github.com/
  t git-clone-noproxy      "${NOPX[@]}" git clone --depth 1 https://github.com/octocat/Hello-World.git
  t python-urllib-noproxy  "${NOPX[@]}" python3 -c 'import urllib.request as u;print(u.urlopen("https://github.com/",timeout=60).status)'
  t pip-noproxy-retries0   "${NOPX[@]}" python3 -m pip download --no-cache-dir --no-deps -d ./pipd six --retries 0
  t pip-noproxy-default-retries "${NOPX[@]}" python3 -m pip download --no-cache-dir --no-deps -d ./pipd six
  # fresh cache dirs: a warm npm/cargo cache would answer without any network use
  t npm-noproxy            "${NOPX[@]}" npm install --no-audit --no-fund --cache "$(mktemp -d)" --prefix ./npmp is-number
  mkdir -p cg && cargo init -q --name tb ./cg >/dev/null 2>&1; printf 'itoa = "1"\n' >> ./cg/Cargo.toml
  t cargo-noproxy          "${NOPX[@]}" env CARGO_HOME="$(mktemp -d)" cargo fetch --manifest-path ./cg/Cargo.toml
  t getent-name            getent hosts github.com
  t nc-direct-ip           "${NOPX[@]}" nc -zv -w 30 $GH_IP 443
  t nc-direct-1.1.1.1      "${NOPX[@]}" nc -zv -w 30 1.1.1.1 443
  t dig-udp                dig +time=5 +tries=1 github.com
  cd /tmp && rm -rf tb
  ;;
via-egress)  # proxy variables as the pod sets them: only allowlisted hosts should work
  mkdir -p tb && cd tb
  t curl-github            curl -sS -m 60 -o /dev/null -w '%{http_code}' https://github.com/
  t curl-npm-registry      curl -sS -m 60 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/is-number
  t curl-pypi              curl -sS -m 60 -o /dev/null -w '%{http_code}' https://pypi.org/simple/six/
  t curl-pythonhosted      curl -sS -m 60 -o /dev/null -w '%{http_code}' https://files.pythonhosted.org/
  t curl-crates-index      curl -sS -m 60 -o /dev/null -w '%{http_code}' https://index.crates.io/config.json
  t curl-crates-static     curl -sS -m 60 -o /dev/null -w '%{http_code}' https://static.crates.io/
  t git-clone              git clone --depth 1 https://github.com/octocat/Hello-World.git
  t npm-install            npm install --no-audit --no-fund --cache "$(mktemp -d)" --prefix ./npmp is-number
  t pip-download           python3 -m pip download --no-cache-dir --no-deps -d ./pipd six
  mkdir -p cg && cargo init -q --name tb ./cg >/dev/null 2>&1; printf 'itoa = "1"\n' >> ./cg/Cargo.toml
  t cargo-fetch            env CARGO_HOME="$(mktemp -d)" cargo fetch --manifest-path ./cg/Cargo.toml
  cd /tmp && rm -rf tb
  ;;
refused)  # through ap-egress, hosts or forms that are not in [egress].allow
  t curl-example.com       curl -sS -m 30 -o /dev/null https://example.com/
  t curl-api.github.com    curl -sS -m 30 -o /dev/null https://api.github.com/
  t curl-kiro-route-host   curl -sS -m 30 -o /dev/null https://runtime.us-east-1.kiro.dev/
  t curl-github-port-80    curl -sS -m 30 -o /dev/null https://github.com:80/
  t curl-github-ssh-22     curl -sS -m 30 -o /dev/null https://github.com:22/
  t curl-ip-literal        curl -sS -m 30 -o /dev/null "https://$GH_IP/"
  t curl-ip-literal-1.1.1.1 curl -sS -m 30 -o /dev/null https://1.1.1.1/
  t curl-loopback-target   curl -sS -m 30 -o /dev/null --noproxy '' --proxy http://127.0.0.1:3128 https://127.0.0.1:18080/
  t curl-localhost-target  curl -sS -m 30 -o /dev/null --noproxy '' --proxy http://127.0.0.1:3128 https://localhost:18080/
  t curl-plain-http-via-proxy curl -sS -m 30 -o /dev/null -w '%{http_code}' --proxy http://127.0.0.1:3128 http://github.com/
  t git-clone-gitlab       git clone --depth 1 https://gitlab.com/gitlab-org/gitlab-foss.git
  echo "-- raw CONNECT status lines"
  for tgt in github.com:443 example.com:443 github.com:22 "$GH_IP:443" 127.0.0.1:18080; do
    printf '%s\t' "CONNECT $tgt"
    python3 - "$tgt" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", 3128), 5); s.settimeout(10)
t = sys.argv[1]
s.sendall(f"CONNECT {t} HTTP/1.1\r\nHost: {t}\r\n\r\n".encode())
print(s.recv(200).split(b"\r\n")[0].decode(errors="replace"))
PY
  done
  ;;
noproxy)  # NO_PROXY=127.0.0.1,localhost keeps loopback traffic to the auth-proxy off ap-egress
  t http-proxy-env-with-NO_PROXY    env HTTP_PROXY=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128 curl -sS -m 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/
  t http-proxy-env-without-NO_PROXY env -u NO_PROXY HTTP_PROXY=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128 curl -sS -m 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/
  echo "-- auth-proxy body with NO_PROXY (agent -> loopback P):"
  curl -sS -m 10 -i -X POST http://127.0.0.1:18080/ap/dummy-caller-key-not-real/kiro-krs/ -d '{}' 2>&1 | head -12
  ;;
uid)  # proxy UID (1001) and ap-egress UID (1002) are not covered by the rules
  python3 $P name:github.com udp53:resolv tcp:1.1.1.1:443 "tcp:$GH_IP:443" tcp6:2606:4700:4700::1111:443
  ;;
esac
