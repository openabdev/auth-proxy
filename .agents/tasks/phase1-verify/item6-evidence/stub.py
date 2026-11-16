# Test stub upstream (HTTPS). Logs one JSON line per request. Never prints header VALUES:
# the Authorization header is classified against the (dummy) real credential and the
# surrogate prefix only.
import http.server, ssl, json, sys, time
REAL = open("/run/secrets/real/api_key").read().strip()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _do(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        a = self.headers.get("authorization")
        cls = "none" if a is None else ("REAL" if a.strip() == REAL or a.strip() == "Bearer " + REAL else ("SURROGATE-prefix" if "aps_" in a else "other"))
        rec = {"t": round(time.time(), 3), "host": self.headers.get("host"), "method": self.command,
               "path": self.path, "xamz_target": self.headers.get("x-amz-target"),
               "authorization_class": cls, "header_names": sorted(k.lower() for k in self.headers.keys()),
               "body_len": len(body)}
        print(json.dumps(rec), flush=True)
        out = json.dumps({"__type": "ValidationException", "message": "stub upstream"}).encode()
        self.send_response(400)
        self.send_header("content-type", "application/x-amz-json-1.0")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_GET = do_POST = do_PUT = _do
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/etc/stub-pki/cert.pem", "/etc/stub-pki/key.pem")
s = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
print("stub up", flush=True)
s.serve_forever()
