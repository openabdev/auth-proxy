# Recipe: kiro-cli behind auth-proxy (Kubernetes, Phase 1)

This recipe runs kiro-cli in the agent container of `deploy/k8s/pod.yaml` so that it reaches the
model API only through the proxy. The agent never sees the real API key.

## 1. Base URLs in `~/.kiro/settings/cli.json`

kiro-cli reads its endpoints from one global settings file, not from the process environment. The
platform entrypoint writes that file before kiro-cli starts. It reads the caller key from the file
mounted at `/var/run/auth-proxy/caller/caller_key`, and it never writes the key anywhere else.

Each of the four kiro-cli services points at one route. The base URL is
`http://127.0.0.1:18080/ap/<caller-key>/<route>`:

| cli.json key | Route (path segment) |
|---|---|
| `api.cps.service` | `kiro-cps` |
| `api.krs.service` | `kiro-krs` |
| `api.codewhisperer.service` | `kiro-cw` |
| `api.q.service` | `kiro-q` |

Each entry also sets `"region": "us-east-1"`. The file is an object of the form
`{"api.cps.service": {"endpoint": "...", "region": "us-east-1"}, ...}`.

The proxy listens on plain `http://` on loopback, which kiro-cli accepts. The hop from the agent to
the proxy never leaves the pod.

Because cli.json is global, one file serves every session in the pod. Any per-session value must
travel in the process environment instead.

## 2. Surrogate as `KIRO_API_KEY`

The authority starts each kiro-cli process with `KIRO_API_KEY` set to a surrogate. The authority
registers `sha256(surrogate)` with the proxy over the session plane (see `docs/session-plane.md`).
Set the variable in the session environment, not in `pod.yaml`. The pod spec never contains
`KIRO_API_KEY`, and the validator checks that.

The real key stays in the proxy's Secret. kiro-cli sends the surrogate, the proxy checks it,
replaces it with the real key, and forwards the request.

## 3. Environment

| Variable | Value | Why |
|---|---|---|
| `KIRO_DISABLE_TELEMETRY` | `1` | Telemetry on makes kiro-cli linger about 3.9 s after its reply [M k3s 4]. Off, it exits in 0.02 to 0.11 s (n=2). |
| `HTTPS_PROXY` | `http://127.0.0.1:18081` | Sends non-credential traffic through `ap-egress`. |
| `NO_PROXY` | `127.0.0.1,localhost` | The base URLs use loopback, so they must not go through `ap-egress`. `ap-egress` accepts only CONNECT, so a plain `http://127.0.0.1` request sent to it would fail. |

The pod spec sets these three variables on the agent container. Keep `NO_PROXY` as given.

## 4. Embedding model (semantic search)

kiro-cli downloads its semantic-search model from
`desktop-release.q.<region>.amazonaws.com/models/all-MiniLM-L6-v2.zip`. Under the Phase 1 deny,
that download fails in both telemetry modes [M k3s 4]. Search then runs in degraded mode. Pick one
of these two options:

1. Allow the host through `ap-egress`. Add `desktop-release.q.us-east-1.amazonaws.com:443` to
   `[egress].allow` in `identity-configmap.yaml`. This sends the download through `ap-egress`
   without a credential.
2. Pre-seed the model in the agent image. Whether kiro-cli uses a pre-seeded model is not verified.

## 5. Failure modes to expect

- **Slow failure on tampering.** If the agent rewrites cli.json to the real hosts or removes it,
  kiro-cli retries for about 44 s before it fails with `dispatch failure` [M k3s 5a, 5b]. The
  proxy cannot shorten that wait. The platform rewrites cli.json at each agent container start,
  which undoes the tampering.
- **Tools that ignore proxy variables fail slowly.** Under the full deny, npm takes about 71 s to
  fail [M k3s 7]. pip takes about 8 s and cargo about 11 s. Users see hangs, not errors. The
  recipe does not change this.
- **Audit attribution between sessions is best effort.** Sessions in the same pod run as the same
  UID. A session can read a neighbour's surrogate from `/proc/<pid>/environ` and spend it, and
  that spoofs the audit line for the neighbour. The surrogate check still refuses any session that
  is not registered or has been revoked.
- **403 on every refused surrogate.** Refusals return 403, not 401, so kiro-cli does not retry for
  minutes. kiro-cli shows the AWS-shaped reason text as given [M exp1].

## 6. Checks before you rely on this recipe

- Confirm that kiro-cli sends `X-Amz-Target` before any grant uses `aws_targets`.
- Run the Phase 1 Kubernetes test, which applies the combined rule set in one pod.
