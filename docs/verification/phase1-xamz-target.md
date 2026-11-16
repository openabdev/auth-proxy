PASS: kiro-cli 3.3.0 sends exactly one `X-Amz-Target` on every call; the model call carries `AmazonCodeWhispererStreamingService.GenerateAssistantResponse`.

# Item 4: kiro-cli X-Amz-Target

- Real requests to the live service: **0**. No real credential was used or read.
- Host: this laptop (macOS), `kiro-cli 3.3.0`. One host only.

## Method

1. A throwaway HOME and a throwaway working directory under `/tmp`.
2. A local capture listener on `127.0.0.1:18099` (plain HTTP). It logged the method, path, header names, the `X-Amz-Target` value and body length. It never logged header values other than `X-Amz-Target`. It answered every request with a 400 AWS-shaped error.
3. The four service endpoints were pointed at the listener with `kiro-cli settings api.{codewhisperer,krs,cps,q}.service '{"endpoint":"http://127.0.0.1:18099/tag-<key>","region":"us-east-1"}'`, the same knob as `spike/exp1/kiro-probe.sh`.
4. `KIRO_API_KEY` was set to a random surrogate (`aps_` plus 32 hex), `HTTPS_PROXY` unset, telemetry and auto-update off.
5. One run: `kiro-cli chat --no-interactive --trust-tools= "say hi"`.

## Evidence (7 captured requests, all POST to path `/`)

| Endpoint key | `X-Amz-Target` (header count) | Calls |
|---|---|---|
| `api.krs.service` | `AmazonCodeWhispererStreamingService.GenerateAssistantResponse` (1) | 1 |
| `api.cps.service` | `AmazonCodeWhispererService.GetProfile` (1) | 1 |
| `api.cps.service` | `KiroControlPlaneBearerService.ListAvailableModels` (1) | 4 (retries after the 400) |
| `api.codewhisperer.service` | `AmazonCodeWhispererService.SendTelemetryEvent` (1) | 1 |

Header names present on every request: accept, accept-encoding, amz-sdk-invocation-id, amz-sdk-request, authorization, content-length, content-type, host, tokentype, user-agent, x-amz-target, x-amz-user-agent, x-amzn-codewhisperer-optout. The model call also sent `x-amzn-kiro-attempt`. The model call body was 28843 bytes.

## Consequence for `aws_targets`

- The header is present and single-valued on all captured calls, so the "zero or two headers means deny" rule does not trip on kiro-cli traffic.
- The design example grant (`route = "kiro-krs"`, `paths = ["/"]`, `aws_targets = ["AmazonCodeWhispererStreamingService.GenerateAssistantResponse"]`) matches the observed model call exactly.
- A grant on the `krs` route that lists only `GenerateAssistantResponse` allows the model call.
- kiro-cli also calls other targets on other routes (`GetProfile`, `ListAvailableModels` on cps; `SendTelemetryEvent` on codewhisperer). A grant for those routes needs its own `aws_targets` list or no matcher.
- Limit: one `chat` run, one version (3.3.0), and the model call was answered with an error, so only the first attempt on the krs route was seen. Tool-use or resumed turns were not exercised. Re-check after a kiro-cli upgrade.

## Cleanup check

- Listener process killed (`pgrep -f "cap.py 18099"` returns nothing).
- `/tmp` working directory and marker file deleted (no `xamz` entries left).
- No tailscale or other host state touched. No hostnames, IPs or logins appear in this report.
