#!/usr/bin/env python3
"""Reference caller: a Muse custom-connector helper talking to the gate.

Scope: a reference for the caller side of the Muse gated passthrough as merged
to main (stage 1). Design: docs/design/muse-gated-passthrough.md. Measurements:
docs/evidence/muse-stage1.md. Not a runnable end-to-end Muse -> Discord client:
the Muse platform, not this script, injects the real Discord credential.

Wire contract (stage 1), as implemented by crates/ap-proxy/src/passthrough.rs:

  * The request goes to the gate in origin form. The caller key (apk_ + 64
    lowercase hex) travels in exactly ONE place, never both (both is 400
    caller_key_ambiguous):
      - path form (default here, the form the Muse connector used in the
        stage 1 measurements):  {AP_BASE}/ap/<caller-key>/<route><discord-path>
      - header form:           {AP_BASE}/<route><discord-path> with
        X-AP-Caller-Key: <caller-key>  (name configurable on the gate).
  * There is no surrogate and no session. The caller's own Authorization
    header passes to Discord unchanged: Muse's egress puts the real Discord
    credential there, so this script only forwards what AP_AUTHORIZATION
    holds (optional; leave it unset when the platform injects it).
  * The gate only allows or denies. A GET on a granted prefix returns
    Discord's own response. Everything else, writes included, is refused
    423 no_grant in stage 1: no hold or approval flow exists on main.
  * Every refusal the gate itself generates has the body
    {"ap_decision": "<denied|rejected|unavailable|expired>", "code": "<code>"}
    and an X-AP-Decision header. Muse's real helper drops response headers
    and shows the agent only "HTTP <status>: <body>", so this caller reads
    the decision from the BODY alone. Discord's own errors carry "message"
    and "code" and no "ap_decision", so they are not mistaken for refusals.

Credential scheme: the gate swaps nothing in passthrough mode, so it never
sets "Bot " or "Bearer ". Whatever Muse injects is what Discord sees; a
Discord bot token must be sent as "Bot <token>" by the platform. The
hard-coded "Bearer" prefix only affects the swap path (issue #12).

Environment:
  AP_BASE           gate base URL         (default http://127.0.0.1:8443)
  AP_CALLER_KEY     apk_... caller key    (required)
  AP_KEY_PLACEMENT  "path" (default) or "header"
  AP_KEY_HEADER     header name for the header form (default X-AP-Caller-Key)
  AP_ROUTE          route name            (default "discord")
  AP_AUTHORIZATION  optional Authorization value to send (normally injected
                    by the Muse platform, not by this script)

Exit codes: 0 success, 2 transport error, upstream error or malformed gate
answer, 3 refused by the gate (denied or rejected), 4 gate decision
"expired", 5 gate unavailable (503, retry later), 64 usage/config error.
Code 4 is part of the design but stage 2 (in review); main never sends it.

Transport hardening: all requests go through an explicit opener with no
redirect following and no ambient proxy. The gate forwards without following
redirects, so an upstream 3xx reaches this caller unchanged; following it
would resend the Authorization header to whatever host Location names, and
honouring http_proxy/https_proxy would route it through a third party. A 3xx
is returned as a status and treated by main as an error (exit 2).
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

KEY_RE = re.compile(r"^apk_[0-9a-f]{64}$")
SNOWFLAKE_RE = re.compile(r"^\d+$")
ROUTE_RE = re.compile(r"^[a-z0-9-]+$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
DECISIONS = {"denied", "rejected", "unavailable", "expired"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: returning None makes urllib raise HTTPError
    for the 3xx, which _send returns as a status (exit 2 in main)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Explicit opener: ProxyHandler({}) disables ambient http_proxy/https_proxy,
# and _NoRedirect disables redirect following (see module docstring).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def die(message: str, code: int = 64) -> "SystemExit":
    print(f"caller: {message}", file=sys.stderr)
    raise SystemExit(code)


def _require_snowflake(value: str, what: str) -> str:
    if not SNOWFLAKE_RE.match(value or ""):
        die(f"{what} must be a numeric (snowflake) id, got {value!r}")
    return value


def _has_control(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def _validate_internal_path(path: str) -> str:
    # Internal call sites may use a query string (e.g. ?limit=), but a
    # fragment or control characters are never legitimate.
    if not path.startswith("/") or "#" in path or _has_control(path):
        die(f"path must be an origin-form path starting with '/' with no fragment or control characters, got {path!r}")
    return path


def _validate_user_path(path: str) -> str:
    # User-supplied `request` paths: no query or fragment injection either.
    if not path.startswith("/") or "#" in path or "?" in path or _has_control(path) or " " in path:
        die(f"path must be an origin-form path starting with '/' with no query, fragment, space or control characters, got {path!r}")
    return path


def gate_decision(text: str) -> tuple[str, str] | None:
    """Return (ap_decision, code) when `text` is exactly a gate refusal body.

    The gate's body has exactly two fields. Anything else, including a
    Discord error object, is not a gate decision."""
    try:
        body = json.loads(text)
    except ValueError:
        return None
    if not isinstance(body, dict) or set(body) != {"ap_decision", "code"}:
        return None
    decision, code = body["ap_decision"], body["code"]
    if decision in DECISIONS and isinstance(code, str) and code:
        return decision, code
    return None


class Caller:
    def __init__(self) -> None:
        self.base = os.environ.get("AP_BASE", "http://127.0.0.1:8443").rstrip("/")
        self.caller_key = os.environ.get("AP_CALLER_KEY", "")
        self.placement = os.environ.get("AP_KEY_PLACEMENT", "path")
        self.key_header = os.environ.get("AP_KEY_HEADER", "X-AP-Caller-Key")
        self.route = os.environ.get("AP_ROUTE", "discord")
        self.authorization = os.environ.get("AP_AUTHORIZATION", "")
        if not KEY_RE.match(self.caller_key):
            die("AP_CALLER_KEY must be apk_ followed by 64 lowercase hex characters")
        if self.placement not in ("path", "header"):
            die(f"AP_KEY_PLACEMENT must be 'path' or 'header', got {self.placement!r}")
        if not HEADER_NAME_RE.match(self.key_header):
            die(f"AP_KEY_HEADER is not a valid header name: {self.key_header!r}")
        if not ROUTE_RE.match(self.route):
            die(f"AP_ROUTE must be lowercase letters, digits and '-', got {self.route!r}")
        if _has_control(self.authorization):
            die("AP_AUTHORIZATION must not contain control characters")

    def _url(self, path: str) -> str:
        if self.placement == "path":
            return f"{self.base}/ap/{self.caller_key}/{self.route}{path}"
        return f"{self.base}/{self.route}{path}"

    def _send(self, method: str, url: str, body: dict | None) -> tuple[int, str]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if self.placement == "header":
            req.add_header(self.key_header, self.caller_key)
        if self.authorization:
            req.add_header("Authorization", self.authorization)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with _OPENER.open(req, timeout=30) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", "replace")
        except urllib.error.URLError as err:
            die(f"cannot reach the gate at {self.base}: {err.reason}", 2)
        except TimeoutError:
            # A read timeout is not a URLError; exit 2 instead of a traceback.
            die(f"timed out talking to the gate at {self.base}", 2)

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, str]:
        """One call through the gate. Returns (status, body text)."""
        _validate_internal_path(path)
        return self._send(method, self._url(path), body)


def report_refusal(status: int, decision: str, code: str) -> int:
    print(f"caller: the gate answered {status} {decision}/{code}; nothing was sent to Discord", file=sys.stderr)
    if decision == "expired":
        return 4
    if decision == "unavailable":
        return 5
    return 3


def main(argv: list[str]) -> int:
    caller = Caller()
    if len(argv) < 2:
        die(__doc__.splitlines()[0] + "\nusage: caller.py <get-messages|send|request> ...")
    command, args = argv[1], argv[2:]

    if command == "get-messages":
        if not args:
            die("usage: caller.py get-messages <channel-id> [limit]")
        channel = _require_snowflake(args[0], "channel-id")
        limit = _require_snowflake(args[1], "limit") if len(args) > 1 else "20"
        status, text = caller.request(
            "GET", f"/api/v10/channels/{channel}/messages?limit={limit}"
        )
    elif command == "send":
        if len(args) < 2:
            die("usage: caller.py send <channel-id> <text> [--reply-to <message-id>]")
        channel = _require_snowflake(args[0], "channel-id")
        payload: dict = {"content": args[1]}
        if "--reply-to" in args:
            idx = args.index("--reply-to")
            if idx + 1 >= len(args):
                die("usage: caller.py send <channel-id> <text> --reply-to <message-id> (missing message-id)")
            ref = _require_snowflake(args[idx + 1], "message-id")
            payload["message_reference"] = {"message_id": ref}
        # Stage 1 has no write grant: expect 423 no_grant from the gate.
        status, text = caller.request(
            "POST", f"/api/v10/channels/{channel}/messages", payload
        )
    elif command == "request":
        if len(args) < 2:
            die("usage: caller.py request <METHOD> <path> [json-body]")
        path = _validate_user_path(args[1])
        if not re.fullmatch(r"[A-Za-z]+", args[0] or ""):
            die(f"method must be alphabetic, got {args[0]!r}")
        try:
            body = json.loads(args[2]) if len(args) > 2 else None
        except ValueError as exc:
            die(f"invalid JSON body: {exc}")
        status, text = caller.request(args[0].upper(), path, body)
    else:
        die(f"unknown command: {command}")

    decision = gate_decision(text) if status >= 400 else None
    if decision is not None:
        return report_refusal(status, *decision)
    if 200 <= status < 300:
        print(text)
        return 0
    print(f"caller: upstream or transport answered {status}: {text}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
