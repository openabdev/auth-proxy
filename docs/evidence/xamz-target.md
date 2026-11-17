# kiro-cli `X-Amz-Target` measurement

Result: kiro-cli 3.3.0 sends exactly one `X-Amz-Target` header on every call captured. The model call carries `AmazonCodeWhispererStreamingService.GenerateAssistantResponse`.

- Real requests to the live service: **0**. No real credential was used or read.
- Host: one macOS laptop, `kiro-cli 3.3.0`.

## How it was captured

1. A throwaway HOME and working directory under `/tmp`.
2. A local capture listener on `127.0.0.1` (plain HTTP). It logged the method, path, header names, the `X-Amz-Target` value and the body length, and no other header value. It answered every request with a 400 AWS-shaped error.
3. The four service endpoints were pointed at the listener with `kiro-cli settings api.{codewhisperer,krs,cps,q}.service '{"endpoint":"http://127.0.0.1:<port>/tag-<key>","region":"us-east-1"}'`.
4. `KIRO_API_KEY` was a random surrogate (`aps_` plus 32 hex). `HTTPS_PROXY` unset, telemetry and auto-update off.
5. One run: `kiro-cli chat --no-interactive --trust-tools= "say hi"`.

## Evidence (7 captured requests, all `POST /`)

| Endpoint key | `X-Amz-Target` (header count) | Calls |
|---|---|---|
| `api.krs.service` | `AmazonCodeWhispererStreamingService.GenerateAssistantResponse` (1) | 1 |
| `api.cps.service` | `AmazonCodeWhispererService.GetProfile` (1) | 1 |
| `api.cps.service` | `KiroControlPlaneBearerService.ListAvailableModels` (1) | 4 (retries after the 400) |
| `api.codewhisperer.service` | `AmazonCodeWhispererService.SendTelemetryEvent` (1) | 1 |

Header names on every request: accept, accept-encoding, amz-sdk-invocation-id, amz-sdk-request, authorization, content-length, content-type, host, tokentype, user-agent, x-amz-target, x-amz-user-agent, x-amzn-codewhisperer-optout. The model call also sent `x-amzn-kiro-attempt`. Its body was 28843 bytes.

## Consequence for `aws_targets`

- The header is present and single-valued on all captured calls, so a "zero or two headers means deny" rule does not trip on kiro-cli traffic.
- A grant on the krs route that lists only `GenerateAssistantResponse` matches the observed model call.
- kiro-cli also calls other targets on other routes (`GetProfile`, `ListAvailableModels` on cps; `SendTelemetryEvent` on codewhisperer). Those routes need their own `aws_targets` list or none.
- No shipped policy uses `aws_targets` for the cps or codewhisperer routes.

## Not verified

- Only one `chat` run on one version (3.3.0) and one host.
- The model call was answered with an error, so only the first attempt on the krs route was seen. Tool-use and resumed turns were not exercised.
- The cps and codewhisperer targets were seen against a local listener, not the real hosts.
- Re-check after a kiro-cli upgrade.
