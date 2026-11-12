#!/usr/bin/env python3
"""Reference caller: a Muse custom-connector helper talking to auth-proxy.

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

Approval flow (proposed in issues #5 and #6, NOT yet implemented by the proxy):
a request whose grant says require_approval is answered "202 Accepted" with a
request id instead of being forwarded. The caller polls
{AP_BASE}/ap/<caller-key>/requests/<request-id> until the parked request is
executed (the upstream response is returned), denied, or expired. Against a
Phase 1 proxy nothing returns 202 and this code path simply never triggers.

Any connector helper can adopt this shape: keep the operation surface you
already have, change the base URL to the proxy, and attach the two values
above. The example operations below are the Discord ones from issue #6.

Environment:
  AP_BASE           proxy base URL      (default http://127.0.0.1:18080)
  AP_CALLER_KEY     apk_... caller key  (required)
  AP_SURROGATE      aps_... surrogate   (required)
  AP_ROUTE          route name          (default "discord")
  AP_POLL_TIMEOUT   seconds to wait for an approval outcome (default 300)
  AP_POLL_INTERVAL  seconds between polls                   (default 2)

Exit codes: 0 executed, 2 proxy refusal or upstream error, 3 approval denied,
4 approval expired, 5 approval wait timed out, 64 usage/config error.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

KEY_RE = re.compile(r"^apk_[0-9a-f]{64}$")
SURROGATE_RE = re.compile(r"^aps_[0-9a-f]{64}$")


def die(message: str, code: int = 64) -> "SystemExit":
    print(f"caller: {message}", file=sys.stderr)
    raise SystemExit(code)


class Caller:
    def __init__(self) -> None:
        self.base = os.environ.get("AP_BASE", "http://127.0.0.1:18080").rstrip("/")
        self.caller_key = os.environ.get("AP_CALLER_KEY", "")
        self.surrogate = os.environ.get("AP_SURROGATE", "")
        self.route = os.environ.get("AP_ROUTE", "discord")
        self.poll_timeout = float(os.environ.get("AP_POLL_TIMEOUT", "300"))
        self.poll_interval = float(os.environ.get("AP_POLL_INTERVAL", "2"))
        if not KEY_RE.match(self.caller_key):
            die("AP_CALLER_KEY must be apk_ followed by 64 lowercase hex characters")
        if not SURROGATE_RE.match(self.surrogate):
            die("AP_SURROGATE must be aps_ followed by 64 lowercase hex characters")

    def _url(self, path: str) -> str:
        return f"{self.base}/ap/{self.caller_key}/{self.route}{path}"

    def _send(self, method: str, url: str, body: dict | None) -> tuple[int, str]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.surrogate}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", "replace")
        except urllib.error.URLError as err:
            die(f"cannot reach the proxy at {self.base}: {err.reason}", 2)

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, str]:
        """One upstream call through the proxy, following the approval flow."""
        status, text = self._send(method, self._url(path), body)
        if status != 202:
            return status, text
        # Parked for approval (issue #5 contract). Poll for the outcome.
        try:
            request_id = json.loads(text)["request_id"]
        except (ValueError, KeyError):
            die(f"proxy answered 202 without a request_id: {text}", 2)
        print(f"caller: parked for approval as {request_id}", file=sys.stderr)
        return self._await_outcome(request_id)

    def _await_outcome(self, request_id: str) -> tuple[int, str]:
        poll_url = f"{self.base}/ap/{self.caller_key}/requests/{request_id}"
        deadline = time.monotonic() + self.poll_timeout
        while True:
            status, text = self._send("GET", poll_url, None)
            if status != 200:
                return status, text
            try:
                outcome = json.loads(text)
            except ValueError:
                die(f"unparsable outcome for {request_id}: {text}", 2)
            state = outcome.get("status")
            if state == "executed":
                result = outcome.get("result") or {}
                return int(result.get("status", 200)), json.dumps(result.get("body", ""))
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
        limit = args[1] if len(args) > 1 else "20"
        status, text = caller.request(
            "GET", f"/api/v10/channels/{args[0]}/messages?limit={limit}"
        )
    elif command == "send":
        if len(args) < 2:
            die("usage: caller.py send <channel-id> <text> [--reply-to <message-id>]")
        payload: dict = {"content": args[1]}
        if "--reply-to" in args:
            ref = args[args.index("--reply-to") + 1]
            payload["message_reference"] = {"message_id": ref}
        status, text = caller.request(
            "POST", f"/api/v10/channels/{args[0]}/messages", payload
        )
    elif command == "request":
        if len(args) < 2:
            die("usage: caller.py request <METHOD> <path> [json-body]")
        body = json.loads(args[2]) if len(args) > 2 else None
        status, text = caller.request(args[0].upper(), args[1], body)
    else:
        die(f"unknown command: {command}")

    if 200 <= status < 300:
        print(text)
        return 0
    print(f"caller: proxy/upstream answered {status}: {text}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
