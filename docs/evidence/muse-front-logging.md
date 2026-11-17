# Muse stage 1: does the front or the host log the request URL?

Issue #22. The Muse connector can only carry the caller key in the URL path (`/ap/<key>/...`), so any layer that
logs request URLs would record the key. This file measures the layers we operate. Redacted: no hostnames,
addresses, logins, keys or the sentinel value.

Tags: **[M]** measured by us. **[D]** documented by the vendor, not measured. **[M-reported]** not applicable here.

## Setup

- Date: 2026-11-17.
- Host role: the gate host (a Linux box that runs the gate behind the owner's private-network TLS front).
- Front: Tailscale 1.104.6, `tailscale serve` reverse proxy (HTTPS, tailnet only, no Funnel, no path mounts)
  forwarding to the gate on loopback.
- Gate: stage 1 probe build from commit `d108cebb` (branch `feat/muse-stage1`), run as a systemd unit whose stdout
  (audit and evidence lines) is appended to a file and whose stderr goes to the journal.
- Real caller key: never used. A random sentinel with a key-like shape (`SENTINEL-` plus 32 random hex) was put in
  the path.

## Method

1. From one place (the laptop, on the tailnet), 5 requests in two rounds through the real front, each with a fresh
   sentinel per round: 3 of `GET /ap/<sentinel>/discord/api/v10/users/@me` and 2 of
   `POST /ap/<sentinel>/__ap_probe/200/10` with a dummy `Authorization`. All 5 answers were HTTP 401, the status
   the gate gives an unknown caller key (`caller_rejected`), as intended. Response bodies were not captured.
2. On the gate host, read-only (sudo only to read), search for the sentinel with `grep -F`.
   The sentinel was passed to `grep` with `-f <file in tmpfs>`, shredded afterwards, never on a command line.
3. Laptop side: shell history files and the repository tree.

Method note: the first search passed the sentinel as a command-line argument. The system `sudo` auth log then
recorded that command line, giving 1 hit in `/var/log` and 1 in process command lines (the search's own `grep`).
Both are artifacts of the probe, not of the front. The repeat with `-f` removed them. Do not search for a
secret with it on the command line.

## Results [M]

| Place | Matches of the sentinel |
|---|---|
| Whole system journal (about 398,000 lines) | 0 |
| Journal of the Tailscale daemon unit | 0 |
| Journal of the gate unit | 0 |
| Kernel journal | 0 |
| `/var/log` (all files) | 0 (after removing the probe's own `sudo` log line) |
| Tailscale state directory | 0 |
| Gate state directory (audit and evidence file) | 0 |
| `/etc`, `/tmp`, `/run`, `/var/tmp` | 0 |
| Process command lines (all processes, `/proc/*/cmdline`) | 0 |
| Process environments (all processes, `/proc/*/environ`) | 0 |
| Laptop shell history (zsh, bash) | 0 |
| Repository working tree on the laptop | 0 |

The gate audit file did record the refusals themselves (`caller_rejected` lines), without the path prefix, as the
design states.

## Does the front have request logging? 

- [M] `tailscale serve status --json` shows only the TCP/HTTPS ports and one `Handlers` entry per mount with a
  `Proxy` target. There is no logging field or option in the serve configuration.
- [D] The `tailscale serve` command reference lists its flags (`--https`, `--http`, `--set-path`, `--proxy-protocol`,
  `--tcp`, `--tls-terminated-tcp`, `--bg`, `--yes`, and others). None controls request or access logging:
  https://tailscale.com/kb/1242/tailscale-serve
- [D] Tailscale's logging page describes what the daemon logs: client logs sent for support (opt out with
  `--no-logs-no-support` or `TS_NO_LOGS_NO_SUPPORT=true`), network flow logs (connection metadata, "strictly do
  not contain any information about client operations or contents of network traffic"; Premium and Enterprise
  plans), and configuration audit logs (tailnet configuration changes). No source in that list records HTTP
  request lines: https://tailscale.com/kb/1011/log-mesh-traffic
- [M] The measurement agrees: 0 matches in the daemon journal while the front terminated TLS and proxied the 5 requests.

## Conclusions

- On the gate host, with this front and this gate build, no place we operate recorded the URL path. The "front and
  host logs record the key" risk is **not observed** [M].
- This holds for the Tailscale version and the default logging configuration above. It can change with a Tailscale
  upgrade or if someone adds a different front (for example a reverse proxy with an access log). Re-run this
  measurement after either change.
- Not measured, outside our control: logs on the calling platform (before and after its credential swap) and on
  any intermediate network. A key in a URL path is unsafe wherever such a log is kept. Treat the key as
  exposable and keep it rotatable: `docs/runbooks/muse-key-rotation.md`.
- Network flow logs, if the owner enables them, record connection metadata and not URLs [D]. Not measured.
- Prefer a header-borne key if the calling platform ever supports it (design section 3.2).
- No logging needed disabling and no key needed rotation as a result of this measurement.
