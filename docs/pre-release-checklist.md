# Pre-release checklist

Items 1 and 2 are done. The real-pod `hello` race (item 3) is still a **release gate**, and the
`kiro-cps` host (item 5) is open.

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
5. **`kiro-cps` route host (open).** `deploy/k8s/policy.example.toml` carries a placeholder.
   The verified kiro-cli capture (`docs/verification/phase1-xamz-target.md`) pointed every
   endpoint at a local listener, so it does not contain the real `api.cps.service` host and
   cannot fill it in. What is needed: the real control-plane host kiro-cli 3.3.0 uses by default,
   with no credential involved. Either read it from kiro-cli's default `api.cps.service` endpoint
   setting, or observe the TLS server name kiro-cli connects to for `GetProfile` /
   `ListAvailableModels` (a DNS or SNI log, with the request not completing). Then set `host`,
   and check that the route's `pass_headers` and error shape match what that host expects.
6. **Interim acceptance.** The first deployment uses the interim static session: no per-session
   revocation, accepted by the owner (`docs/interim-static-session.md`). Confirm the proxy start
   line says `INTERIM static session enabled` and that the pod mounts no session socket into the
   agent container.
