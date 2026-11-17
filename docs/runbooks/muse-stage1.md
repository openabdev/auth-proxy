# Muse gated passthrough, stage 1 runbook

Design: `docs/design/muse-gated-passthrough.md` (sections 3, 6, 7). Stage 1 is measurement plus
allow/deny passthrough for one consumer (Muse) and one upstream (Discord), on a single instance. No
approval machinery exists yet: a write that would later be held is denied with 423 `no_grant`.

**The gate constrains the agent, not the Muse platform.** Muse's egress holds the real Discord token,
so Muse or anyone who compromises it can call Discord directly and skip the gate.

All host names below are placeholders. Do not commit real tailnet names, addresses or logins.

## 1. Build

Build on a build host, not a laptop. The measurement build includes the probe:

```
cargo build --release -p ap-proxy --features stage1-probe
```

A default build (no feature) has no probe code and no `__ap_probe` string. A config with
`[probe] enabled = true` makes that binary exit 2. Stage 2 builds without the feature.

## 2. Issue the caller key

```
key="apk_$(openssl rand -hex 32)"
printf '%s' "$key" | shasum -a 256        # put the hex digest in caller_key_sha256
```

Give `$key` to the Muse connector as the value of the `X-AP-Caller-Key` header (the header name is
configurable with `passthrough.caller_key_header`). The key never goes into the config, a log or a
commit. Revoke it by deleting the identity and its grants from the policy file (hot reload). Deleting only the identity leaves grants naming an unknown identity, the file stops validating, and every request gets 503 until it is fixed.

## 3. Policy

Start from `deploy/muse/pilot-policy.example.toml`. Set `public_authority` to the `Host` the front
passes to the loopback listener (a request whose `Host` differs is refused 400 `host_rejected` and audited without an identity). The proxy refuses a
non-loopback `listen.proxy`; the TLS front (for example `tailscale serve --bg --https=443 http://127.0.0.1:8443`)
exposes it to the tailnet only. Do not use Funnel.

Run:

```
auth-proxy --config /etc/auth-proxy/policy.toml
```

No expiry store, session socket, admin socket or secret root is needed or read for a passthrough-only config.

Muse base URL: `https://<public-host>/discord` (the Discord path after `/discord` goes upstream unchanged).
Whether the connector accepts a path prefix is open question 4.

## 4. Gate behaviour to expect

| Request | Answer |
|---|---|
| `GET` on a granted prefix | Discord's own response, unchanged |
| any other method or path (including `POST /api/v10/channels/{id}/messages`) | 423, `X-AP-Decision: denied`, `no_grant` |
| unknown route name | 423 `route_unknown` |
| missing, duplicate or malformed caller key | 401, `X-AP-Decision: rejected` |
| ambiguous path, bad `Host`, framing conflict, duplicate `Authorization` | 400 |

## 5. Evidence collection

With a valid caller key, each request writes one `{"evidence":{...}}` line next to the audit line. Fields
(fixed; no header value, no length, no key, no body): `identity`, `route`, `method`, redacted `path`,
`status`, `http_version`, `auth_present`,
`chunked`, `compressed`, `content_type_class`, `expect_continue`, `front_headers_present`
(`forwarded`, `x_forwarded`, `x_real_ip`, `via`, `tailscale`, `cf`), and `fwd_names_digest` (sha256 over
sorted header names only; equal digests for two identical connector calls mean the same header names).

Manual checklist, names only, redacted, written into the design doc afterwards:

- [ ] which header carries the key (confirm the configured name arrives)
- [ ] `auth_present` for message-read calls
- [ ] path prefix as seen at the loopback listener (a wrong `Host` shows only as a `host_rejected` audit line)
- [ ] HTTP version at the front
- [ ] chunked and compressed bodies
- [ ] other non-secret header names the connector sends (names only)
- [ ] two identical connector calls: same `fwd_names_digest`
- [ ] `Content-Type` class of message create (denied in stage 1, but still logged)
- [ ] whether the front sends `100 Continue` itself

## 6. Hold-tolerance probe (acceptance 10)

Enable `[probe] enabled = true` on the `stage1-probe` build. From the Muse connector, through the real
front, send probe calls directly to the proxy (they are not Discord calls and do not use a route prefix):
`POST https://<public-host>/__ap_probe/<status>/<secs>` with a small body and the caller key. `status`
is one of 200, 410, 423, 503 and `secs` one of 10, 30, 60, 120, 300. 410, 423 and 503 return the matching
`X-AP-Decision`; 200 returns none.

Record for each run:

- the largest `secs` that completes through the front
- whether the front interrupts a long idle connection
- whether a client disconnect during the wait reaches the proxy, and how fast: the audit stream gets a
  `{"probe":{"event":"client_gone",...}}` line when it does, `completed` when the answer was sent
  (measure both direct to the loopback listener and through the front)
- Muse's reaction to each status, to its own timeout, to a dropped connection, and its retry behaviour

**Stop rule:** if the connection is cut well below a usable `hold_secs`, or disconnects never reach the
proxy and Muse retries without bound, stop and rethink the design instead of building stage 2.

## 7. Framing and ACL checks (acceptance 11, 12)

- ACL isolation: from Muse's node only the public port is reachable; every other port (SSH included)
  fails. This needs the real ACL, so it is checked by hand.
- Framing: send raw HTTP/1 requests with both `Content-Length` and `Transfer-Encoding`, differing or
  comma-joined `Content-Length`, a `Transfer-Encoding` other than `chunked`, and a `Connection` header
  naming `Content-Length`, directly and through the front. The upstream must see nothing. Record which
  layer refused (hyper or the gate) and whether the answer carries `X-AP-Decision`. The automated matrix
  (`tests/matrix/passthrough.py`, row PT-12) records the direct path. It also shows that hyper collapses a
  duplicate `Content-Length` with identical values before the gate sees it. The same row measures a GET
  with `Content-Length` and chunked, and bare-LF line endings. All three are the design 3.1 known gap:
  forwarded on a direct request, not asserted as refused, deferred to stage 2 (raw-head scanner). The
  listener is loopback-only, so direct requests come only from the proxy host.

## 8. Automated checks

```
cargo build -p ap-proxy -p ap-egress --features ap-proxy/matrix-upstream,ap-proxy/stage1-probe,ap-egress/matrix-upstream
cargo test -p ap-proxy --features matrix-upstream,stage1-probe --test matrix_passthrough
python3 tests/matrix/passthrough.py --bin target/debug      # needs an OpenSSL 3 `openssl` on PATH
python3 tests/matrix/matrix.py --bin target/debug           # sidecar matrix, still 41 rows
```
