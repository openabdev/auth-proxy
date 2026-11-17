# Muse stage 1: front and framing measurements (redacted)

Redacted excerpt of the stage 1 owner measurements. It holds no hostnames, addresses, logins, URLs or keys.
`<front>` is the TLS front (a `tailscale serve` entry, tailnet only) and `<loopback>` is the proxy's
loopback listener on the same host. All requests used a dummy `Authorization` value; the real Discord
token was never used. Tags follow the design doc: [M] measured.

## Through the front

- [M] No caller key: 401, `X-AP-Decision: rejected`. Wrong caller key: 401.
- [M] Valid key, `POST /discord/api/v10/channels/1/messages`: 423 `no_grant`, `X-AP-Decision: denied`.
- [M] Valid key, `GET /discord/api/v10/users/@me` with the dummy Authorization: 401 carrying Discord's own
  headers and a 43-byte body. A direct request to Discord with the same dummy value also returned 401. The
  bodies were not byte-diffed.
- [M] Hold probe `POST /__ap_probe/200/30` and `/200/120`: 200 after 30.05 s and 120.05 s. The front did not
  cut the held connection. The evidence log recorded `elapsed_ms` 30000 and 120001.
- [M] The front passes a `Host` that includes its port. A request whose `Host` lacks the port is refused
  400 `host_rejected`, so a client that omits the port would be refused.
- [M] The front adds `tailscale-*` and `x-forwarded-*` headers. `cf-*`, `via`, `forwarded` and `x-real-ip`
  were absent.
- [M] Framing through the front: duplicate `Content-Length: 0`, an obsolete folded header and bare-LF line
  endings were accepted and forwarded (Discord answered 401). A POST with both `Content-Length` and
  `Transfer-Encoding: chunked` reached the proxy as chunked and got 423 `no_grant`. The front normalises or
  terminates these, so they cannot be tested end to end through it.

## Directly to `<loopback>` (raw HTTP/1)

| Request | Result |
|---|---|
| different `Content-Length` values (0 and 5) | 400, empty body (hyper) |
| obsolete folded header | 400 (hyper) |
| `Host` not the public authority, or duplicate `Host` | 400 `host_rejected` |
| duplicate identical `Content-Length: 0` | accepted and forwarded |
| bare-LF line endings | accepted and forwarded |
| GET with `Content-Length: 1` and `Transfer-Encoding: chunked` | accepted and forwarded |

The last three fall to the HTTP parser's defaults, not to a stage 1 rule. This is the documented framing gap.

## No-leak check

Counts only, patterns fed through stdin: 0 audit lines (44 inspected) contain the caller key, the dummy
Authorization value, `apk_`, `authorization` or `x-ap-caller-key`. The service journal had 0 matches.
Evidence entries carry presence flags and a digest of header names, never values.
