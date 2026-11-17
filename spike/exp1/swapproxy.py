#!/usr/bin/env python3
"""Phase 0 / Experiment 1: tiny logging reverse proxy that swaps a surrogate
for the real credential and forwards upstream over verified TLS.

This is a probe, not the product. It exists to answer four questions per CLI:
is the base-URL knob honoured, is an opaque surrogate accepted, does streaming
survive the hop, and what does the CLI do when the proxy refuses.

Security properties the probe keeps (so it can run next to real keys):
  * The real credential is read from an environment variable *by name*
    (--real-env) and is never logged; neither is the surrogate.
  * Every auth-bearing header is logged as <redacted len=N match=...>.
  * Fail-closed: a request that does not carry the surrogate is refused with
    401 and never reaches upstream. Client-supplied auth headers that do not
    carry the surrogate are stripped; exactly one upstream credential is set.
  * Upstream TLS uses the default verifying context. Plain-http upstreams are
    only allowed on loopback (for the mock upstream used in offline tests).
  * CONNECT is never tunnelled: it is logged (as evidence that the CLI tried
    to bypass the base URL, when HTTPS_PROXY points here) and refused.

Modes (--mode):
  swap        normal operation
  refuse401   answer 401 to every request, no upstream call
  refuse403   answer 403 to every request, no upstream call
  expired     answer 401 {"error":"surrogate_expired"}, no upstream call
"""
import argparse
import http.client
import http.server
import json
import os
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse

AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "proxy-authorization",
    "cookie",
    "x-amz-security-token",
}
# Not secret, must pass through: kiro-cli sends "TokenType: API_KEY" next to the
# bearer; stripping it makes the service treat the key as an SSO token.
HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
QUERY_KEYS = {"key", "api_key", "access_token"}

ARGS = None
REAL = None
SURR = None
ROUTES = []
LOCK = threading.Lock()


def log(event, **kw):
    kw["event"] = event
    kw["t"] = round(time.time(), 3)
    line = json.dumps(kw, sort_keys=True)
    # Belt and braces: never let a secret reach the log even by accident.
    for secret in (REAL, SURR):
        if secret and secret in line:
            line = line.replace(secret, "<SECRET-LEAK-BLOCKED>")
    with LOCK:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def redact(name, value):
    match = "surrogate" if SURR and SURR in value else "other"
    return "<redacted len=%d match=%s>" % (len(value), match)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):  # silence default stderr logging
        pass

    def _refuse(self, status, err, note):
        if ARGS and ARGS.error_shape == "aws":
            # AWS JSON-protocol error dialect, so SDK-based clients can surface the message.
            atype = "AccessDeniedException" if status == 403 else "UnauthorizedException"
            if err == "surrogate_expired":
                atype = "ExpiredTokenException"
            body = json.dumps({"__type": atype, "message": "auth-proxy: " + note}).encode()
            self.send_response(status)
            self.send_header("x-amzn-errortype", atype)
            self.send_header("content-type", "application/x-amz-json-1.0")
        else:
            body = json.dumps({"error": err, "message": note}).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        log("refuse", status=status, error=err, method=self.command, path=self._safe_path())

    def _safe_path(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        q = [(k, "<redacted>" if k.lower() in QUERY_KEYS else v) for k, v in q]
        return u.path + ("?" + urllib.parse.urlencode(q) if q else "")

    def do_CONNECT(self):
        log("connect_attempt", target=self.path)
        self._refuse(403, "connect_refused", "probe never tunnels CONNECT")

    def _handle(self):
        hdr_log = {}
        for k, v in self.headers.items():
            hdr_log[k.lower()] = redact(k, v) if k.lower() in AUTH_HEADERS else v[:120]
        log("request", method=self.command, path=self._safe_path(), headers=hdr_log)

        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            body = self._read_chunked()

        mode = ARGS.mode
        if mode == "refuse401":
            return self._refuse(401, "unauthorized", "auth-proxy refused (probe refuse401)")
        if mode == "refuse403":
            return self._refuse(403, "forbidden", "auth-proxy policy denied (probe refuse403)")
        if mode == "expired":
            return self._refuse(401, "surrogate_expired", "surrogate expired; re-mint")

        # Find the surrogate. Fail closed if absent.
        found = []
        out_headers = []
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP:
                continue
            if lk in AUTH_HEADERS:
                if SURR in v:
                    found.append(lk)
                    out_headers.append((k, v.replace(SURR, REAL)))
                else:
                    log("strip_client_auth", header=lk)
                continue
            out_headers.append((k, v))
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        newq = []
        for k, v in q:
            if k.lower() in QUERY_KEYS:
                if v == SURR:
                    found.append("query:" + k)
                    newq.append((k, REAL))
                else:
                    log("strip_client_auth", header="query:" + k)
                continue
            newq.append((k, v))
        if len(found) != 1:
            return self._refuse(401, "no_surrogate" if not found else "multiple_credentials",
                                "request must carry exactly one surrogate; found %d" % len(found))

        upstream, req_path = ARGS.upstream, u.path
        for prefix, target in ROUTES:
            if req_path == prefix or req_path.startswith(prefix + "/"):
                upstream, req_path = target, req_path[len(prefix):] or "/"
                break
        else:
            if ROUTES and not ARGS.upstream:
                return self._refuse(404, "no_route", "no upstream bound to this path")
        up = urllib.parse.urlsplit(upstream)
        base_path = up.path.rstrip("/")
        path = base_path + req_path + ("?" + urllib.parse.urlencode(newq) if newq else "")
        host = up.hostname
        port = up.port or (443 if up.scheme == "https" else 80)
        if up.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, context=ssl.create_default_context(),
                                               timeout=ARGS.timeout)
        else:
            assert host in ("127.0.0.1", "localhost", "::1"), "plain http upstream only on loopback"
            conn = http.client.HTTPConnection(host, port, timeout=ARGS.timeout)
        out_headers.append(("Host", host if port in (80, 443) else "%s:%d" % (host, port)))
        out_headers.append(("Content-Length", str(len(body))))
        t0 = time.time()
        try:
            conn.putrequest(self.command, path, skip_host=True, skip_accept_encoding=True)
            for k, v in out_headers:
                conn.putheader(k, v)
            conn.endheaders(body)
            resp = conn.getresponse()
        except ssl.SSLError as e:
            log("upstream_tls_error", error=type(e).__name__)
            return self._refuse(502, "upstream_tls_verify_failed", "refusing: upstream TLS failed")
        except Exception as e:  # noqa: BLE001
            log("upstream_error", error=type(e).__name__, detail=str(e)[:200])
            return self._refuse(502, "upstream_unreachable", "refusing: upstream unreachable")
        ttfb = time.time() - t0
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in HOP:
                continue
            self.send_header(k, v)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        chunks = 0
        total = 0
        err_sample = b""
        stamps = []
        while True:
            data = resp.read1(65536) if hasattr(resp, "read1") else resp.read(4096)
            if not data:
                break
            chunks += 1
            total += len(data)
            if len(stamps) < 400:
                stamps.append(round(time.time() - t0, 3))
            if resp.status >= 400 and len(err_sample) < 400:
                err_sample += data[: 400 - len(err_sample)]
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        conn.close()
        log("response", status=resp.status, ctype=resp.getheader("content-type"),
            upstream_te=resp.getheader("transfer-encoding"), bytes=total, chunks=chunks,
            ttfb_s=round(ttfb, 3), total_s=round(time.time() - t0, 3),
            first_chunk_s=stamps[0] if stamps else None,
            last_chunk_s=stamps[-1] if stamps else None,
            swapped=found,
            err_sample=err_sample.decode("utf-8", "replace") if err_sample else None)

    def _read_chunked(self):
        out = b""
        while True:
            size = int(self.rfile.readline().strip().split(b";")[0], 16)
            if size == 0:
                self.rfile.readline()
                return out
            out += self.rfile.read(size)
            self.rfile.readline()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        log("conn_error", error=type(sys.exc_info()[1]).__name__)


def main():
    global ARGS, REAL, SURR, ROUTES
    p = argparse.ArgumentParser()
    p.add_argument("--listen", default="127.0.0.1:18080")
    p.add_argument("--upstream", default="", help="default upstream https://host[:port][/base]")
    p.add_argument("--route", action="append", default=[],
                   help="PREFIX=https://host[/base]; requests under PREFIX go there (prefix stripped)")
    p.add_argument("--real-env", required=True, help="env var NAME holding the real credential")
    p.add_argument("--surrogate-env", default="AP_SURROGATE",
                   help="env var NAME holding the surrogate")
    p.add_argument("--mode", default="swap", choices=["swap", "refuse401", "refuse403", "expired"])
    p.add_argument("--timeout", type=float, default=300)
    p.add_argument("--error-shape", default="plain", choices=["plain", "aws"],
                   help="body format of refusals (aws = AWS JSON protocol error)")
    ARGS = p.parse_args()
    REAL = os.environ.get(ARGS.real_env)
    SURR = os.environ.get(ARGS.surrogate_env)
    if not REAL or not SURR:
        sys.exit("missing --real-env or --surrogate-env value (names: %s, %s)"
                 % (ARGS.real_env, ARGS.surrogate_env))
    if REAL == SURR:
        sys.exit("surrogate must differ from the real credential")
    ROUTES = [tuple(r.split("=", 1)) for r in ARGS.route]
    if not ARGS.upstream and not ROUTES:
        sys.exit("need --upstream or --route")
    host, port = ARGS.listen.rsplit(":", 1)
    assert host in ("127.0.0.1", "localhost"), "probe binds loopback only"
    log("start", listen=ARGS.listen, upstream=ARGS.upstream, routes=ROUTES, mode=ARGS.mode,
        real_len=len(REAL), surrogate_len=len(SURR))
    Server((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
