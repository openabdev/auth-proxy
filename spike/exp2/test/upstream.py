#!/usr/bin/env python3
"""Mock TLS upstreams for the Experiment 2 test matrix (test credentials only).

  upstream.py --control PORT --listen NAME=PORT:CERT:KEY [--listen ...]

Every listener records each request it receives: SNI, method, path, and all
headers. The harness reads the record from the plain-HTTP control port
(GET /log, POST /reset). The values recorded are random per-run test
credentials, never real ones.

Paths: /v1/echo (200 JSON), /v1/small (tiny body, for latency runs),
/v1/sse (20 SSE events, 50 ms apart, chunked), /v1/redirect?to=URL (302).
"""
import argparse
import json
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
HANDSHAKE_FAIL = {}
LOCK = threading.Lock()


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256

    def __init__(self, addr, handler, ctx, name):
        super().__init__(addr, handler)
        self.ctx, self.name = ctx, name

    def finish_request(self, request, client_address):
        # Handshake in the worker thread, so a failing client cannot stall accept().
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            with LOCK:
                HANDSHAKE_FAIL[self.name] = HANDSHAKE_FAIL.get(self.name, 0) + 1
            return
        self.RequestHandlerClass(tls, client_address, self)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True  # else Nagle + delayed ACK adds 40 ms per response

    def log_message(self, *a):
        pass

    def _record(self):
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        with LOCK:
            LOG.append({
                "listener": self.server.name,
                "sni": getattr(self.connection, "ap_sni", None),
                "method": self.command,
                "path": self.path,
                "headers": [[k.lower(), v] for k, v in self.headers.items()],
            })

    def _send(self, code, body=b"", ctype="application/json", extra=()):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self):
        self._record()
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/v1/sse":
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for i in range(20):
                chunk = f"event: delta\ndata: {{\"i\": {i}}}\n\n".encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
            return
        if u.path == "/v1/redirect":
            to = urllib.parse.parse_qs(u.query).get("to", ["https://evil.up.test/"])[0]
            return self._send(302, b"", extra=[("location", to)])
        if u.path == "/v1/small":
            return self._send(200, b'{"ok":true}')
        return self._send(200, json.dumps({"ok": True, "listener": self.server.name}).encode())

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_any


class Ctl(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def log_message(self, *a):
        pass

    def do_GET(self):
        with LOCK:
            b = json.dumps({"log": LOG, "handshake_fail": HANDSHAKE_FAIL}).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        with LOCK:
            LOG.clear()
            HANDSHAKE_FAIL.clear()
        self.send_response(204)
        self.send_header("content-length", "0")
        self.end_headers()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", type=int, required=True)
    ap.add_argument("--listen", action="append", default=[])
    a = ap.parse_args()
    for spec in a.listen:
        name, rest = spec.split("=", 1)
        port, cert, key = rest.split(":")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.sni_callback = lambda s, n, c: setattr(s, "ap_sni", n)
        srv = TLSServer(("127.0.0.1", int(port)), H, ctx, name)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    ctl = ThreadingHTTPServer(("127.0.0.1", a.control), Ctl)
    print("upstream ready", flush=True)
    ctl.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
