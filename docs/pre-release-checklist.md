# Pre-release checklist

These need a cluster or the real CLI. Phase 1 wrote the scripts and docs; none of this has
been run.

1. **Combined iptables/ip6tables rule set in one pod.** Run `tests/k8s-egress/run.sh`
   against a cluster with `NET_ADMIN` (ESTABLISHED accept, per-port allow and reject,
   `! -o lo` reject, DNS blocked). Until then the combined set is [I]; the parts were
   measured separately [M k3s F1, F2].
2. **kiro-cli `X-Amz-Target`.** Done: kiro-cli 3.3.0 sends one `X-Amz-Target` per call
   [M, `docs/verification/phase1-xamz-target.md`]. Re-check after a kiro-cli upgrade.
3. **Real-pod hello race.** Kill the runtime container with the proxy up, confirm no
   agent-UID orphan survives and the fresh PID 1 wins `hello` after the 90 s lock. (The
   automated version is `crates/ap-proxy/tests/hello_race.rs`.)
4. **PSA.** The `NET_ADMIN` init container needs Pod Security Admission `privileged` in the
   target namespace.
