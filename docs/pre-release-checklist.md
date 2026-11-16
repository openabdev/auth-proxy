# Pre-release checklist

Items 1 and 2 are done. The real-pod `hello` race (item 3) is still a **release gate**, and the
`kiro-cps` host (item 5) is measured for us-east-1 but its response-side settings are unchecked.

1. **Combined iptables/ip6tables rule set in one pod.** Done [M]: PASS on a real k3s node with the
   real `auth-proxy` and `ap-egress` binaries (`docs/verification/phase1-k8s-iptables.md`; test
   assets in `spike/k8s-iptables/`). `tests/k8s-egress/run.sh` (the shipped script, covering
   per-port reject, ESTABLISHED accept, DNS blocked and the `hello` kill) has still not been run
   itself. Re-run the rule-set checks on any new cluster or CNI.
2. **kiro-cli `X-Amz-Target`.** Done: kiro-cli 3.3.0 sends one `X-Amz-Target` per call
   [M, `docs/verification/phase1-xamz-target.md`]. `aws_targets` stays dormant: no shipped policy
   uses it. Re-check after a kiro-cli upgrade.
3. **Real-pod hello race. RELEASE GATE (owner decision).** Kill the runtime container with the
   proxy up, confirm no agent-UID orphan survives and the fresh PID 1 wins `hello` after the 90 s
   lock. (The automated version is `crates/ap-proxy/tests/hello_race.rs`.) The interim static
   session does not call `hello`, but this gate is still required before release.
   Measured [M] on a real k3s pod with a stand-in runtime, on `deploy/k8s/pod.yaml` with the shared group 2000 and
   no socket-mode override: the 90 s lock held, only the fresh PID 1 won, no orphan survived
   (`docs/verification/phase1-interim-k3s.md`). Re-run it with the real runtime before release.
4. **PSA.** The `NET_ADMIN` init container needs Pod Security Admission `privileged` in the
   target namespace.
5. **`kiro-cps` route host. Measured [M], response side still open.** kiro-cli 3.3.0 (macOS, one run,
   dummy `KIRO_API_KEY`, throwaway HOME) was run with `HTTPS_PROXY` pointing at a local listener
   that logged each `CONNECT host:port` and answered 403, so nothing left the machine and no DNS
   lookup happened. It asked for `management.us-east-1.kiro.dev:443` 30 times (retries), and for
   `runtime.us-east-1.kiro.dev:443` for the model path (the `kiro-krs` host, unchanged). In a
   second run with only the `api.cps.service` endpoint overridden to the local listener, every
   `management.*` CONNECT disappeared and 29 POSTs arrived at the override instead, so
   `management.us-east-1.kiro.dev` is the default `api.cps.service` host. `policy.example.toml`
   now uses it with port 443 and no special `Host` header.
   Still unchecked: (a) `pass_headers = ["tokentype"]` and `error_shape = "aws"` can only be
   verified against a real first response from that host; (b) the same run also tried
   `management.*` hosts in other regions (eu-central-1, us-gov-east-1, us-gov-west-1 and four
   `us-iso*` hosts, 9 CONNECTs each), probably a profile-region fan-out. TLS was not decrypted,
   so which call went to which region is unknown. The policy allows only us-east-1, so those
   would be denied; check with a real session whether kiro-cli copes; (c) the `Host` header
   value inside TLS was not seen (a CONNECT proxy only sees `host:443`); (d) only the laptop
   had kiro-cli 3.3.0: `mini` has 2.37.0 and `bl` 2.1.1, so no homelab Linux run was done.
6. **Interim acceptance.** The first deployment uses the interim static session: no per-session
   revocation, accepted by the owner (`docs/interim-static-session.md`). Confirm the proxy start
   line says `INTERIM static session enabled` and that the pod mounts no session socket into the
   agent container.
