# Recipe: kiro-cli

Claim tags: [M exp1] measured in Phase 0 (`spike/exp1/`), [I] inferred.

- **Base URLs.** The platform writes `cli.json` once with each route's base URL under the
  caller key: `http://127.0.0.1:<P>/ap/<caller-key>/<route>` [M exp1]. kiro-cli's settings are
  global, so this is written once per HOME, not per session [M exp1].
- **Credential.** `KIRO_API_KEY` is the per-session surrogate, set by the runtime in each
  child's environment. The real key exists only in the proxy container.
- **Headers.** Routes must pass `tokentype` through, else the service answers 400
  "profileArn is required" [M exp1]. kiro-cli shows AWS-shaped error bodies verbatim, so
  routes use `error_shape = "aws"` [M exp1].
- **Proxy variables.** `HTTPS_PROXY=http://127.0.0.1:<E>` sends git, npm, pip and cargo
  through `ap-egress`. `NO_PROXY=127.0.0.1,localhost` keeps the loopback base URLs direct.
  Both are set in `deploy/k8s/pod.yaml`.
- **Telemetry.** `KIRO_DISABLE_TELEMETRY=1`.
- **`aws_targets`.** kiro-cli 3.3.0 sends one `X-Amz-Target` per call; the model call on the
  krs route is `AmazonCodeWhispererStreamingService.GenerateAssistantResponse`
  [M, `docs/verification/phase1-xamz-target.md`]. Other routes use other targets. The matcher
  is dormant: no shipped policy uses it, and a test fails if one does.
- **Control-plane host.** The `kiro-cps` route host in `deploy/k8s/policy.example.toml` is
  still a placeholder (open item in `docs/pre-release-checklist.md`).
- **Interim deployment.** The first deployment writes the settings once from an init
  container and uses one static surrogate (`docs/interim-static-session.md`, no per-session
  revocation).

Other CLIs: Phase 0 probe results are in `spike/exp1/` [M exp1]. This repository ships no
recipe for them in Phase 1 and makes no new claims about them.
