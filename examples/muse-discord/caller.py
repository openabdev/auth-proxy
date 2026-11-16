#!/usr/bin/env python3
"""Proposal caller: a Muse custom-connector helper talking to auth-proxy.

Scope: this is a proposal plus mock (see README.md), not a runnable
end-to-end Muse -> Discord client today. The read wire format below
matches the proxy as shipped; the approval flow is a proposed contract
for issue #5 that has NOT been agreed or implemented in the proxy yet.

This mirrors the wire protocol implemented by crates/ap-client and enforced by
crates/ap-proxy/src/pipeline.rs:

  * The request goes to  {AP_BASE}/ap/<caller-key>/<route><upstream-path>
    in origin form. The caller key (apk_ + 64 lowercase hex) travels in the path;
    the proxy config stores only its sha256.
  * The session surrogate (aps_ + 64 lowercase hex) travels in the route's
    surrogate header (default "authorization") as "Bearer <surrogate>".
  * The caller never holds the real upstream credential. The proxy checks the
    caller key, the surrogate registration and the grant, then swaps the
    surrogate for the real credential and forwards upstream.

Approval flow (PROPOSED in issues #5 and #6, NOT yet implemented by the proxy
and NOT yet agreed): a request whose grant says require_approval would be
answered "202 Accepted" ONLY when it also carries the proxy-owned marker
header "X-Auth-Proxy-Approval: parked", together with a request id. The
caller then polls {AP_BASE}/ap/<caller-key>/_approval/<request-id> until
the parked request is executed, denied, or expired. The poll segment is
"_approval", not a route-style name: route names must satisfy valid_slug
(crates/ap-core/src/config.rs -- lowercase, digits and "-" only), so a
segment containing "_" can never collide with a configured route. A bare 202 without that
header is treated as an ordinary upstream 202 response, not as a parked
request -- upstream APIs may legitimately return 202 themselves. Once #5
settles the marker, response schema, poll authorization and expiry /
revocation semantics, this sketch should be re-derived from that spec.

Environment:
  AP_BASE           proxy base URL      (default http://127.0.0.1:18080)
  AP_CALLER_KEY     apk_... caller key  (required)
  AP_SURROGATE      aps_... surrogate   (required)
  AP_ROUTE          route name          (default "discord")
  AP_POLL_TIMEOUT   seconds to wait for an approval outcome (default 300)
  AP_POLL_INTERVAL  seconds between polls                   (default 2)

Exit codes: 0 executed, 2 proxy refusal or upstream error, 3 approval denied,
4 approval expired, 5 approval wait timed out, 64 usage/config error.

Transport hardening: all requests go through an explicit opener with no
redirect following and no ambient proxy. The proxy itself is built with
``reqwest::redirect::Policy::none()``, so an upstream 3xx reaches this
caller unchanged; following it here would resend the surrogate
``Authorization`` header to whatever host the ``Location`` names, and
honouring ``http_proxy``/``https_proxy`` from the environment would route
the surrogate through a third party. A 3xx is therefore returned as a
status and treated by ``main`` as a proxy/upstream error (exit 2).
"""

import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request

KEY_RE = re.compile(r"^apk_[0-9a-f]{64}$")
SURROGATE_RE = re.compile(r"^aps_[0-9a-f]{64}$")
# A request id is interpolated into the poll URL, so it is restricted to a
# fixed pattern: no slashes, dots or other path syntax.
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SNOWFLAKE_RE = re.compile(r"^\d+$")
APPROVAL_HEADER = "x-auth-proxy-approval"
APPROVAL_MARKER = "parked"


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


def _parse_poll_value(name: str, default: str, positive: bool = False) -> float:
    raw = os.environ.get(name, default)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        die(f"{name} must be a finite number, got {raw!r}")
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        kind = "positive" if positive else "non-negative"
        die(f"{name} must be a finite {kind} number, got {raw!r}")
    return value


def _require_snowflake(value: str, what: str) -> str:
    if not SNOWFLAKE_RE.match(value or ""):
        die(f"{what} must be a numeric (snowflake) id, got {value!r}")
    return value


def _require_limit(value: str) -> str:
    if not SNOWFLAKE_RE.match(value or ""):
        die(f"limit must be digits only, got {value!r}")
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


class Caller:
    def __init__(self) -> None:
        self.base = os.environ.get("AP_BASE", "http://127.0.0.1:18080").rstrip("/")
        self.caller_key = os.environ.get("AP_CALLER_KEY", "")
        self.surrogate = os.environ.get("AP_SURROGATE", "")
        self.route = os.environ.get("AP_ROUTE", "discord")
        self.poll_timeout = _parse_poll_value("AP_POLL_TIMEOUT", "300")
        # The interval must be positive: 0 would turn polling into a busy loop.
        self.poll_interval = _parse_poll_value("AP_POLL_INTERVAL", "2", positive=True)
        if not KEY_RE.match(self.caller_key):
            die("AP_CALLER_KEY must be apk_ followed by 64 lowercase hex characters")
        if not SURROGATE_RE.match(self.surrogate):
            die("AP_SURROGATE must be aps_ followed by 64 lowercase hex characters")

    def _url(self, path: str) -> str:
        return f"{self.base}/ap/{self.caller_key}/{self.route}{path}"

    def _send(self, method: str, url: str, body: dict | None) -> tuple[int, dict, str]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.surrogate}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with _OPENER.open(req, timeout=30) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, headers, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
            return err.code, headers, err.read().decode("utf-8", "replace")
        except urllib.error.URLError as err:
            die(f"cannot reach the proxy at {self.base}: {err.reason}", 2)

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, str]:
        """One upstream call through the proxy, following the proposed approval flow."""
        _validate_internal_path(path)
        status, headers, text = self._send(method, self._url(path), body)
        if status != 202:
            return status, text
        # F1: a bare 202 is NOT a parked request. Only a 202 carrying the
        # proxy-owned approval marker header is treated as parked; any
        # other 202 is an ordinary upstream response and is returned as-is.
        if (headers.get(APPROVAL_HEADER) or "").strip().lower() != APPROVAL_MARKER:
            return status, text
        try:
            request_id = json.loads(text)["request_id"]
        except (ValueError, KeyError, TypeError):
            die(f"proxy answered a marked 202 without a request_id: {text}", 2)
        if not isinstance(request_id, str) or not REQUEST_ID_RE.match(request_id):
            die(f"proxy answered a marked 202 with a malformed request_id: {request_id!r}", 2)
        print(f"caller: parked for approval as {request_id}", file=sys.stderr)
        return self._await_outcome(request_id)

    def _await_outcome(self, request_id: str) -> tuple[int, str]:
        poll_url = f"{self.base}/ap/{self.caller_key}/_approval/{request_id}"
        deadline = time.monotonic() + self.poll_timeout
        while True:
            status, _headers, text = self._send("GET", poll_url, None)
            if status != 200:
                return status, text
            try:
                outcome = json.loads(text)
            except ValueError:
                die(f"unparsable outcome for {request_id}: {text}", 2)
            if not isinstance(outcome, dict):
                die(f"malformed outcome for {request_id}: not an object: {text}", 2)
            state = outcome.get("status")
            if state == "executed":
                # Fail closed: an executed outcome is only trusted when its
                # result is an object with an integer status. Anything else
                # is a proxy/contract error (exit 2), never a silent success.
                result = outcome.get("result")
                if not isinstance(result, dict):
                    die(f"malformed executed outcome for {request_id}: result is not an object", 2)
                result_status = result.get("status")
                if not isinstance(result_status, int) or isinstance(result_status, bool):
                    die(f"malformed executed outcome for {request_id}: result.status is not an integer", 2)
                result_body = result.get("body", "")
                if not isinstance(result_body, str):
                    result_body = json.dumps(result_body)
                return result_status, result_body
            if state == "denied":
                print(f"caller: {request_id} was denied by the owner", file=sys.stderr)
                raise SystemExit(3)
            if state == "expired":
                print(f"caller: {request_id} expired without a decision", file=sys.stderr)
                raise SystemExit(4)
            if time.monotonic() > deadline:
                print(f"caller: still parked after {self.poll_timeout:g}s", file=sys.stderr)
                raise SystemExit(5)
            time.sleep(self.poll_interval)


def main(argv: list[str]) -> int:
    caller = Caller()
    if len(argv) < 2:
        die(__doc__.splitlines()[0] + "\nusage: caller.py <get-messages|send|request> ...")
    command, args = argv[1], argv[2:]

    if command == "get-messages":
        if not args:
            die("usage: caller.py get-messages <channel-id> [limit]")
        channel = _require_snowflake(args[0], "channel-id")
        limit = _require_limit(args[1]) if len(args) > 1 else "20"
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

    if 200 <= status < 300:
        print(text)
        return 0
    print(f"caller: proxy/upstream answered {status}: {text}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
