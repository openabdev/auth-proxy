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

Exit codes: 0 success, 2 transport error (cannot connect, TLS failure,
timeout, the gate closed the connection without answering, a malformed or
truncated HTTP answer), upstream error, malformed gate answer (including an
unknown refusal code) or a response over the size cap, 3 refused by the gate
(denied or rejected), 4 gate decision "expired", 5 gate unavailable (503,
retry later), 64 usage/config error (including a malformed AP_BASE), 70
unexpected internal error, 130 interrupted (SIGINT).
Code 4 is part of the design but stage 2 (in review). Main sends "expired"
only from its stage 1 measurement probe, which this caller cannot reach; no
production path sends it.

A closed connection with no answer (exit 2) is NOT a gate refusal. In main it
is the abort signal for an upstream failure after the request was sent, so the
write may have reached Discord. Do not treat it as "nothing was sent".

Key safety: the caller key travels in the request path in the default form, so
every diagnostic here is fixed text. No message, exception string or traceback
ever contains a URL, the /ap/<key> prefix or the key, and an invalid command,
channel id, method, placement, route or header name is never echoed back.
AP_BASE is validated before any URL holding the key is built, and every
exception raised while building or sending the request is mapped to a fixed
message.

Single output path: everything written to stdout or stderr goes through
_emit(). It removes the configured key in every form it can take (raw,
percent-encoded in either hex case, JSON \\u00XX and HTML entity escapes,
case-mixed), any "/ap/..." prefix, any "apk_..." token, any 64-hex run and any
run of 40 or more token characters (which also covers the key's hex and
base64 forms); it replaces
control and other non-printable characters with "?" (newline and tab are kept);
and it truncates to MAX_STDOUT_CHARS (stdout) or MAX_STDERR_CHARS (stderr).
run() also replaces sys.stdout and sys.stderr with guards that call _emit(), so
even a stray print() is scrubbed; test_caller.py fails the build if the source
holds a bare print or a direct stream write. This covers channels the caller
does not control: a server or reverse proxy that echoes the request target in
an error body, in a gate-shaped body's "code", or in a 2xx body. The
redaction is a last line of defence, not a reason to send the key to the wrong
host: a misdirected AP_BASE has already received it, so rotate the key.

Bounds: a response body is capped at MAX_RESPONSE_BYTES (8 MiB). A declared
Content-Length over the cap is rejected before reading, and reads stop at
cap + 1 bytes on both the success and the HTTP error path (exit 2). A body
shorter than its declared Content-Length is a transport error (exit 2). An
upstream error body is echoed to stderr scrubbed and truncated to
MAX_SHOWN_CHARS. The whole exchange (connect, headers and body) has a hard
wall-clock budget of TOTAL_TIMEOUT_SECS (60 s) enforced with a SIGALRM interval
timer that interrupts a blocked read, so a peer that drips one byte at a time
cannot extend it; the 30 s per-socket-operation timeout still applies inside
it. Where setitimer is unavailable (non-POSIX, or off the main thread) the
budget is only checked between reads.

Transport hardening: all requests go through an explicit opener with no
redirect following and no ambient proxy. The gate forwards without following
redirects, so an upstream 3xx reaches this caller unchanged; following it
would resend the Authorization header to whatever host Location names, and
honouring http_proxy/https_proxy would route it through a third party. A 3xx
is returned as a status and treated by main as an error (exit 2).
"""

import http.client
import json
import os
import re
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# fullmatch with ASCII classes: "$" would accept a trailing newline, \d a non-ASCII digit.
KEY_RE = re.compile(r"apk_[0-9a-f]{64}")
SNOWFLAKE_RE = re.compile(r"[0-9]+")
ROUTE_RE = re.compile(r"[a-z0-9-]+")
HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]+")
DECISIONS = {"denied", "rejected", "unavailable", "expired"}
# Every code ap_core::outcome::render_passthrough can send, plus the stage 2
# "expired". Any other code is a malformed gate answer, never echoed.
KNOWN_CODES = {
    "no_grant", "route_unknown", "caller_rejected", "path_ambiguous", "host_rejected",
    "absolute_form", "framing_refused", "authorization_duplicate", "connect_refused",
    "websocket_unsupported", "body_too_large", "policy_unavailable", "body_read_timeout",
    "connect_failed", "probe_params", "caller_key_ambiguous", "expired",
}
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
SOCKET_TIMEOUT_SECS = 30
MAX_SHOWN_CHARS = 2048  # of an upstream error body echoed to stderr
MAX_STDOUT_CHARS = MAX_RESPONSE_BYTES  # one success body is never cut below the response cap
MAX_STDERR_CHARS = 4096  # any single diagnostic, after the body was cut to MAX_SHOWN_CHARS
TOTAL_TIMEOUT_SECS = 60
# scheme://host[:port] only: a bracketed IPv6 literal, or a DNS name / IPv4.
BASE_RE = re.compile(r"(https?)://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/?")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: returning None makes urllib raise HTTPError
    for the 3xx, which _send returns as a status (exit 2 in main)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Explicit opener: ProxyHandler({}) disables ambient http_proxy/https_proxy,
# and _NoRedirect disables redirect following (see module docstring).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class _TooLarge(Exception):
    """A response body went over MAX_RESPONSE_BYTES."""


class _Deadline(BaseException):
    """The wall-clock budget for one exchange ran out. A BaseException so that
    no `except Exception` inside http.client or urllib can swallow it."""


# ---- the one output path -------------------------------------------------

_secret_values: list[str] = []
_scrub_re: "re.Pattern[str] | None" = None
# Control characters (newline and tab kept), line/paragraph separators, bidi
# overrides, surrogates and private-use characters.
_NONPRINTABLE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff\ue000-\uf8ff]")
_GENERIC_SCRUB = re.compile(
    r"/ap/[^\s\"'<>,}\]]*"            # an /ap/<key> prefix, and what follows it up to a delimiter
    r"|apk_[A-Za-z0-9_%\\-]*"          # any caller-key-shaped token
    r"|[0-9A-Fa-f]{64}"                 # any 64-hex value (a key body, a sha256)
    r"|[A-Za-z0-9_-]{40,}"              # any other token-shaped run
)
REDACTED = "[redacted]"


def _char_pattern(ch: str) -> str:
    """One character of a secret, as itself, %XX, \\u00XX, &#N; or &#xHH;."""
    n = ord(ch)
    alts = [re.escape(ch), f"%{n:02x}", f"\\\\u{n:04x}", f"&#{n};", f"&#x{n:x};"]
    return "(?:" + "|".join(alts) + ")"


def register_secrets(*values: str) -> None:
    """Set the values _emit() must never print, and compile the scrubber."""
    global _scrub_re
    _secret_values[:] = [v for v in values if v and len(v) >= 8]
    parts = ["".join(_char_pattern(c) for c in v) for v in _secret_values]
    _scrub_re = re.compile("|".join(parts), re.IGNORECASE) if parts else None


def scrub(text: str, limit: int) -> str:
    """Remove secrets and token-shaped values, replace non-printable
    characters, then truncate to `limit` characters (marker included)."""
    text = str(text)
    if _scrub_re is not None:
        text = _scrub_re.sub(REDACTED, text)
    text = _GENERIC_SCRUB.sub(REDACTED, text)
    text = _NONPRINTABLE.sub("?", text)
    if len(text) > limit:
        text = text[:max(0, limit - 14)] + "...(truncated)"
    return text


_raw_streams: dict[bool, object] = {}


def _emit(text: str, err: bool = True, newline: bool = True) -> None:
    """The only function that writes to stdout or stderr."""
    raw = _raw_streams.get(err) or (sys.stderr if err else sys.stdout)
    out = scrub(text, MAX_STDERR_CHARS if err else MAX_STDOUT_CHARS) + ("\n" if newline else "")
    enc = getattr(raw, "encoding", None) or "utf-8"
    raw.write(out.encode(enc, "replace").decode(enc, "replace"))


class _Guard:
    """Stands in for sys.stdout / sys.stderr so that any write, even a stray
    print(), passes through _emit()."""

    def __init__(self, err: bool) -> None:
        self.err = err

    def write(self, text: str) -> int:
        _emit(text, self.err, newline=False)
        return len(text)

    def flush(self) -> None:
        raw = _raw_streams.get(self.err)
        if raw is not None:
            raw.flush()

    def isatty(self) -> bool:
        return False


def die(message: str, code: int = 64) -> "SystemExit":
    _emit(f"caller: {message}")
    raise SystemExit(code)


def _require_snowflake(value: str, what: str) -> str:
    if not SNOWFLAKE_RE.fullmatch(value or ""):
        die(f"{what} must be a numeric (snowflake) id")
    return value


def _has_control(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def _validate_internal_path(path: str) -> str:
    # Internal call sites may use a query string (e.g. ?limit=), but a
    # fragment or control characters are never legitimate.
    if not path.startswith("/") or "#" in path or _has_control(path):
        die("path must be an origin-form path starting with '/' with no fragment or control characters")
    return path


def _validate_user_path(path: str) -> str:
    # User-supplied `request` paths: no query or fragment injection either.
    if not path.startswith("/") or "#" in path or "?" in path or _has_control(path) or " " in path:
        die("path must be an origin-form path starting with '/' with no query, fragment, space or control characters")
    return path


def _validate_base(raw: str) -> str:
    """Return a normalised scheme://host[:port] or exit 64 with a fixed message.

    Runs before any URL holding the caller key exists. The raw value is never
    echoed: a bad AP_BASE is exactly the input most likely to be mistyped."""
    bad = "AP_BASE must be http:// or https:// followed by a host and an optional port only (no path, query, fragment, userinfo, whitespace or control characters)"
    if not raw.isascii() or _has_control(raw) or " " in raw or "\\" in raw:
        die(bad)
    m = BASE_RE.fullmatch(raw)
    if not m:
        die(bad)
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port
        host = parts.hostname
    except ValueError:
        die(bad)
    if not host or parts.query or parts.fragment or "?" in raw or "#" in raw:
        die(bad)
    if port is not None and not 0 < port < 65536:
        die(bad)
    return f"{m.group(1)}://{m.group(2)}{m.group(3) or ''}"


def gate_decision(text: str) -> tuple[str, str] | None:
    """Return (ap_decision, code) when `text` is exactly a gate refusal body.

    The gate's body has exactly two fields. Anything else, including a
    Discord error object, is not a gate decision."""
    try:
        body = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(body, dict) or set(body) != {"ap_decision", "code"}:
        return None
    decision, code = body["ap_decision"], body["code"]
    if decision in DECISIONS and isinstance(code, str) and code:
        return decision, code
    return None


class Caller:
    def __init__(self) -> None:
        self.base = _validate_base(os.environ.get("AP_BASE", "http://127.0.0.1:8443"))
        self.caller_key = os.environ.get("AP_CALLER_KEY", "")
        self.placement = os.environ.get("AP_KEY_PLACEMENT", "path")
        self.key_header = os.environ.get("AP_KEY_HEADER", "X-AP-Caller-Key")
        self.route = os.environ.get("AP_ROUTE", "discord")
        self.authorization = os.environ.get("AP_AUTHORIZATION", "")
        if not KEY_RE.fullmatch(self.caller_key):
            die("AP_CALLER_KEY must be apk_ followed by 64 lowercase hex characters")
        if self.placement not in ("path", "header"):
            die("AP_KEY_PLACEMENT must be 'path' or 'header'")
        if not HEADER_NAME_RE.fullmatch(self.key_header):
            die("AP_KEY_HEADER is not a valid header name")
        if not ROUTE_RE.fullmatch(self.route):
            die("AP_ROUTE must be lowercase letters, digits and '-'")
        if _has_control(self.authorization):
            die("AP_AUTHORIZATION must not contain control characters")

    def _url(self, path: str) -> str:
        if self.placement == "path":
            return f"{self.base}/ap/{self.caller_key}/{self.route}{path}"
        return f"{self.base}/{self.route}{path}"

    def _send(self, method: str, url: str, body: dict | None) -> tuple[int, str]:
        failure = self._exchange(method, url, body)
        if isinstance(failure, str):
            die(failure, 2)
        return failure

    def _exchange(self, method: str, url: str, body: dict | None) -> "tuple[int, str] | str":
        """Return (status, text) or a fixed failure message. Never raises and
        never formats the URL, the exception text or the exception chain."""
        deadline = time.monotonic() + TOTAL_TIMEOUT_SECS
        old_handler = old_timer = None
        try:
            # Hard total budget: an interval timer interrupts a blocked read,
            # which a between-reads check cannot (a peer dripping one byte at a
            # time stays inside the per-operation timeout forever).
            if hasattr(signal, "setitimer"):
                def _on_alarm(_signum, _frame):
                    raise _Deadline
                try:
                    old_handler = signal.signal(signal.SIGALRM, _on_alarm)
                    old_timer = signal.setitimer(signal.ITIMER_REAL, TOTAL_TIMEOUT_SECS)
                except ValueError:  # not the main thread: fall back to the between-reads check
                    old_handler = old_timer = None
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(url, data=data, method=method)
            if self.placement == "header":
                req.add_header(self.key_header, self.caller_key)
            if self.authorization:
                req.add_header("Authorization", self.authorization)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with _OPENER.open(req, timeout=SOCKET_TIMEOUT_SECS) as resp:
                    return resp.status, _read_bounded(resp, deadline)
            except urllib.error.HTTPError as err:
                try:
                    return err.code, _read_bounded(err, deadline)
                finally:
                    err.close()
        except BaseException as exc:  # noqa: BLE001 - mapped to fixed text below
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return _failure_message(exc)
        finally:
            if old_handler is not None:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)
                if old_timer and old_timer[0] > 0:
                    signal.setitimer(signal.ITIMER_REAL, old_timer[0], old_timer[1])

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, str]:
        """One call through the gate. Returns (status, body text)."""
        _validate_internal_path(path)
        return self._send(method, self._url(path), body)


def _read_bounded(resp, deadline: float) -> str:
    declared = resp.headers.get("Content-Length")
    if declared is not None and declared.strip().isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise _TooLarge
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise _Deadline
        chunk = resp.read(min(65536, MAX_RESPONSE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise _TooLarge
    if declared is not None and declared.strip().isdigit() and total != int(declared):
        # urllib returns a short body silently; a truncated answer is not an answer.
        raise http.client.IncompleteRead(b"", int(declared) - total)
    return b"".join(chunks).decode("utf-8", "replace")


def _failure_message(exc: BaseException) -> str:
    """Map any request-construction or transport exception to fixed text.

    The exception text is never used: http.client.InvalidURL and friends embed
    the full request target, which in path form holds the caller key."""
    if isinstance(exc, _TooLarge):
        return f"the gate's answer is larger than the {MAX_RESPONSE_BYTES}-byte cap; discarded"
    if isinstance(exc, (_Deadline, TimeoutError, socket.timeout)):
        return "timed out talking to the gate"
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else None
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timed out talking to the gate"
    if isinstance(exc, ssl.SSLError) or isinstance(reason, ssl.SSLError):
        return "TLS failure talking to the gate"
    if isinstance(exc, (http.client.RemoteDisconnected, ConnectionError)) or isinstance(reason, ConnectionError):
        if isinstance(exc, ConnectionRefusedError) or isinstance(reason, ConnectionRefusedError):
            return "cannot reach the gate (connection refused)"
        return ("the gate closed the connection without a complete answer; this is not a refusal, "
                "and the request may already have reached Discord")
    if isinstance(exc, http.client.InvalidURL):
        return "the request could not be built (invalid URL or header value)"
    if isinstance(exc, http.client.HTTPException):
        return "malformed or truncated HTTP answer from the gate"
    if isinstance(exc, urllib.error.URLError) or isinstance(exc, OSError):
        return "cannot reach the gate"
    if isinstance(exc, ValueError):
        return "the request could not be built (invalid URL or header value)"
    return "unexpected error while talking to the gate"


def report_refusal(status: int, decision: str, code: str) -> int:
    """Print one fixed-shape line and return the exit code. A decision or code
    outside the gate's vocabulary is a malformed answer: fixed text, exit 2."""
    if decision not in DECISIONS or code not in KNOWN_CODES or not isinstance(status, int):
        _emit("caller: malformed answer from the gate (unknown refusal code)")
        return 2
    _emit(f"caller: the gate answered {status} {decision}/{code}; nothing was sent to Discord")
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
            die("method must be alphabetic")
        try:
            body = json.loads(args[2]) if len(args) > 2 else None
        except ValueError:
            die("invalid JSON body")
        status, text = caller.request(args[0].upper(), path, body)
    else:
        die("unknown command (expected get-messages, send or request)")

    decision = gate_decision(text) if status >= 400 else None
    if decision is not None:
        return report_refusal(status, *decision)
    if 200 <= status < 300:
        _emit(text, err=False)
        return 0
    # Scrub before cutting, so a key straddling the cut cannot survive as a prefix.
    shown = scrub(text, MAX_SHOWN_CHARS)
    _emit(f"caller: upstream or transport answered {status}: {shown}")
    return 2


def run(argv: list[str]) -> int:
    """main() behind a top-level guard: the configured secrets are registered,
    sys.stdout and sys.stderr are replaced by guards that scrub every write, and
    an unexpected exception prints fixed text and exits 70, never a traceback
    (a traceback can carry the key)."""
    register_secrets(os.environ.get("AP_CALLER_KEY", ""))
    saved = sys.stdout, sys.stderr
    _raw_streams[False], _raw_streams[True] = saved
    sys.stdout, sys.stderr = _Guard(False), _Guard(True)
    try:
        return main(argv)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        _emit("caller: interrupted")
        return 130
    except BaseException:  # noqa: BLE001
        try:
            _emit("caller: unexpected internal error (details withheld)")
        except BaseException:  # noqa: BLE001
            pass
        return 70
    finally:
        sys.stdout, sys.stderr = saved
        _raw_streams.clear()


if __name__ == "__main__":
    sys.exit(run(sys.argv))
