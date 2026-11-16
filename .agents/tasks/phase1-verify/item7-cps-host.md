RESULT: host MEASURED = `management.us-east-1.kiro.dev:443`; `pass_headers` / `error_shape` UNCHECKED (need a real first response).

# Item 7: `kiro-cps` route host

- Real requests to the service: **0**. Dummy `KIRO_API_KEY=aps_<random hex>`, throwaway HOME and working dir under `/tmp`. No real key read.
- Host: the laptop (macOS), kiro-cli 3.3.0 (the item 4 host). Homelab Linux hosts do not have 3.3.0 (`mini` 2.37.0, `bl` 2.1.1, rpi1/rpi2 none), so no `unshare -n` run; macOS has no netns.
- Containment instead: `HTTPS_PROXY`/`HTTP_PROXY` -> a local listener that logs the `CONNECT host:port` line and answers 403. kiro-cli honors the proxy, so there was no DNS lookup and no connection beyond localhost.
- Run 1 (60 s, one attempt): CONNECT counts: `management.us-east-1.kiro.dev:443` x30, `runtime.us-east-1.kiro.dev:443` x3 (model path, = `kiro-krs`), `q.us-east-1.amazonaws.com` x3, `telemetry.us-east-1.kiro.dev` x1, `cognito-identity.us-east-1.amazonaws.com` x7, `desktop-release.q.us-east-1.amazonaws.com` x3, and `management.*` in eu-central-1, us-gov-east-1, us-gov-west-1 and four us-iso* regions, x9 each.
- Run 2 (one attempt): same, plus `api.cps.service` overridden to the local listener (the item 4 knob). Every `management.*` CONNECT vanished; 29 POSTs to `/cps/` arrived. So `management.us-east-1.kiro.dev` is the default cps host; `runtime.us-east-1.kiro.dev` stays the model host.
- Not seen: the `Host` header inside TLS (assumed `management.us-east-1.kiro.dev`, port 443), which call goes to the other regions, `tokentype` and the error shape.
- Total diagnostic runs: 2 (plus one that failed to start because `timeout` is missing on macOS).

## Cleanup check
- Listener killed (`pgrep -fl cap.py` empty); `/tmp/cpsprobe` (HOME, workdir, logs) deleted and `ls` reports it absent.
- Only a `/tmp/keep` copy of two CONNECT logs remains outside the repo and is removed at the end of this step.
- No tailscale or system state touched; kiro-cli not installed anywhere; no hosts, IPs or logins in this report.

## Checks (macmini, this commit's tree)
fmt --check, clippy --workspace --all-targets -D warnings, cargo test --workspace: all pass; check-egress-deps.sh and check-no-test-resolve.sh (after `cargo build --release`): ok.
