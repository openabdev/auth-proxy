RESULT: OPEN (not filled; item 4 does not support a concrete host)

# Item 6c: `kiro-cps` route host

`item4-xamz-target.md` pointed every endpoint at a local listener (`api.cps.service` included), so it records the
`X-Amz-Target` values but never the real control-plane host. It cannot fill `deploy/k8s/policy.example.toml`.
The placeholder `control-plane.placeholder.example` stays, and the pod stays "cannot be deployed until replaced".

Also tried here: `kiro-cli settings api.cps.service` on kiro-cli 2.37.0 -> "No value associated" (there is no readable
default), and a string search of the binary found no unambiguous cps host (the search for host-looking strings ended in
a timeout and noise). Nothing guessed.

## Exactly what is needed
The host (and port, and the `Host` header, if not 443) that kiro-cli 3.3.0 (the verified version) uses for
`GetProfile` and `ListAvailableModels` by default, observed with NO real credential and with the request not completing.
Literal command for the owner, on a machine with kiro-cli 3.3.0 and no network egress to the service:

```
# dummy key, DNS observed only; the connection is expected to fail
sudo tcpdump -ni any -l 'udp port 53' > /tmp/dns.txt & TP=$!
KIRO_API_KEY=aps_$(openssl rand -hex 32) HOME=$(mktemp -d) kiro-cli chat --no-interactive --trust-tools= hi
sudo kill $TP; grep -Eo '[a-z0-9.-]*(kiro\.dev|amazonaws\.com)' /tmp/dns.txt | sort -u
```
Run it without outbound access to the service (for example with the network cable/Wi-Fi to the internet down but
resolver reachable, or `unshare -n` plus a local DNS logger) if the owner does not want even a dummy-key request to
leave. Then set `host` in the `kiro-cps` route, and check `pass_headers` (`tokentype`) and `error_shape = "aws"`
against that host's first response.
