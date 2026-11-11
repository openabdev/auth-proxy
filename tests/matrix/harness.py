"""Shared setup for the fail-closed matrix (FEAT-005, Phase 1).

Brings up, on loopback only: a throwaway CA, mock TLS upstreams (in process), and the real
`auth-proxy` and `ap-egress` binaries. The TOML config is written here. Every secret is random per
run: test credentials, caller keys and surrogates. Nothing real is involved.

The proxy trusts the throwaway CA and resolves the mock upstream names only when it is built with
the `matrix-upstream` feature (crates/ap-proxy/src/matrix_hooks.rs). The positive rows therefore run
against a feature-enabled test binary, not the exact release artifact.
"""
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT_MAIN = 18100
PORT_LEASE = 18101
PORT_AUTHORITY = 18102
PORT_RESTART = 18103
PORT_EGRESS = 18110
PORT_PROBE = 18120
UPSTREAM_PORTS = dict(good=18443, evil=18444, badca=18445, wrongname=18446)
# Test name map for ap-egress (matrix-upstream build only). The name is two labels, so the
# allowlist validator accepts it; it resolves to loopback, so the address check must refuse it.
EGRESS_NAME = "loop.test"
EGRESS_RESOLVE = f"{EGRESS_NAME}=127.0.0.1"
MAX_BODY = 1024 * 1024  # test body cap (limits.max_body_bytes), also the session-plane cap

# Header names that carry a credential. The proxy must strip every one of them from agent requests.
AUTH = ("authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie",
        "x-amz-security-token")

IDENTITIES = ("agent-1", "agent-2")
CREDENTIALS = {  # credential id -> (source, routes). Secret files live under <work>/secrets.
    "c-up": ("k8s:auth-proxy-up:api_key", ["up"]),
    "c-aws": ("k8s:auth-proxy-aws:api_key", ["upaws"]),
    "c-key": ("k8s:auth-proxy-key:api_key", ["upkey"]),
    "c-badca": ("k8s:auth-proxy-badca:api_key", ["badca"]),
    "c-wrong": ("k8s:auth-proxy-wrong:api_key", ["wrongname"]),
}
DEFAULT_GRANTS = [
    dict(identity="agent-1", credential="c-up", route="up", methods=["GET", "POST"], paths=["/v1/"]),
    dict(identity="agent-1", credential="c-aws", route="upaws", methods=["POST"], paths=["/v1/"],
         aws_targets=["AwsSvc.Op"]),
    dict(identity="agent-1", credential="c-key", route="upkey", methods=["GET", "POST"], paths=["/v1/"]),
    dict(identity="agent-1", credential="c-badca", route="badca", methods=["GET"], paths=["/v1/"]),
    dict(identity="agent-1", credential="c-wrong", route="wrongname", methods=["GET"], paths=["/v1/"]),
    dict(identity="agent-2", credential="c-up", route="up", methods=["GET", "POST"], paths=["/v1/"]),
]
ROUTE_HOSTS = {  # route -> (host, upstream port key, extra TOML lines)
    "up": ("api.up.test", "good", 'pass_headers = ["tokentype"]'),
    "upaws": ("api.up.test", "good", 'error_shape = "aws"'),
    "upkey": ("api.up.test", "good", 'surrogate_header = "x-api-key"\ncredential_header = "x-api-key"'),
    "badca": ("badca.up.test", "badca", ""),
    "wrongname": ("wrongname.up.test", "wrongname", ""),
}


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def sh(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# Ed25519 through openssl 3 (pkeyutl -rawin). A seed becomes a PKCS8 DER key by prefixing the
# fixed 16-byte header. The public key is the last 32 bytes of the SubjectPublicKeyInfo.
PKCS8_ED25519_HEAD = bytes.fromhex("302e020100300506032b657004220420")
HELLO_VECTOR_SEED = b"\x07" * 32
HELLO_VECTOR_IDENTITY = "pty-team-a"
HELLO_VECTOR_NONCE = "0" * 64


def hello_message(identity, nonce):
    """The bytes the runtime signs: the constant line, a u32 big-endian length, the identity, a
    newline and the nonce. Mirrors ap_core::session_wire::hello_message."""
    raw = identity.encode()
    return b"auth-proxy hello v1\n" + len(raw).to_bytes(4, "big") + raw + b"\n" + nonce.encode()


def _key_der(work, seed):
    path = os.path.join(work, "rt-%s.der" % secrets.token_hex(6))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(PKCS8_ED25519_HEAD + seed)
    return path


def ed25519_pubkey_b64(work, seed):
    """Standard base64 of the 32-byte public key for `seed`, as the proxy config holds it."""
    import base64
    key = _key_der(work, seed)
    spki = subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", key, "-pubout", "-outform", "DER"],
                          check=True, capture_output=True).stdout
    os.remove(key)
    return base64.b64encode(spki[-32:]).decode()


def ed25519_sign_hello(work, seed, identity, nonce):
    """Standard base64 of the Ed25519 signature over hello_message, made with openssl."""
    import base64
    key = _key_der(work, seed)
    msg = os.path.join(work, "hello-%s.bin" % secrets.token_hex(6))
    sig = msg + ".sig"
    with open(msg, "wb") as f:
        f.write(hello_message(identity, nonce))
    try:
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-keyform", "DER", "-rawin",
                        "-in", msg, "-out", sig], check=True, capture_output=True)
        with open(sig, "rb") as f:
            raw = f.read()
    finally:
        for p in (key, msg, sig):
            if os.path.exists(p):
                os.remove(p)
    if len(raw) != 64:
        raise RuntimeError("openssl returned %d signature bytes" % len(raw))
    return base64.b64encode(raw).decode()


def check_hello_vector(work):
    """Pin the signing path against the value the Rust test ap-client proof::tests pins. Both
    sides sign the same seed, identity and nonce, and Ed25519 is deterministic, so the two must
    agree byte for byte. A mismatch means the wire message or the key format differs."""
    got = ed25519_sign_hello(work, HELLO_VECTOR_SEED, HELLO_VECTOR_IDENTITY, HELLO_VECTOR_NONCE)
    if got != HELLO_VECTOR_PROOF:
        raise RuntimeError("hello signing vector mismatch: got %s, want %s" % (got, HELLO_VECTOR_PROOF))
    return got


HELLO_VECTOR_PROOF = "0gzaf9i0GWkxQUg/sALsKLMChV90x4st2hZgF2HEl3NQCs6riM7m+AtUZRrQKddz6+gj5eF4sdkGwXD+287QBQ=="


def wait_port(port, proc=None, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class Recorder:
    """What each mock upstream received. Shared by all listeners."""

    def __init__(self):
        self.lock = threading.Lock()
        self.log = []
        self.handshake_fail = {}

    def add(self, rec):
        with self.lock:
            self.log.append(rec)

    def fail(self, name):
        with self.lock:
            self.handshake_fail[name] = self.handshake_fail.get(name, 0) + 1

    def reset(self):
        with self.lock:
            self.log.clear()
            self.handshake_fail.clear()

    def snapshot(self):
        with self.lock:
            return list(self.log)


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True  # else Nagle plus delayed ACK adds 40 ms per response

    def log_message(self, *a):
        pass

    def _record(self):
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        self.server.rec.add({
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

    def _any(self):
        self._record()
        path = self.path.split("?", 1)[0]
        if path == "/v1/sse":
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for i in range(20):
                chunk = f'event: delta\ndata: {{"i": {i}}}\n\n'.encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
            return
        if path == "/v1/redirect":
            import urllib.parse
            to = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("to", [""])[0]
            return self._send(302, b"", extra=[("location", to)])
        return self._send(200, json.dumps({"ok": True, "listener": self.server.name}).encode())

    do_GET = do_POST = do_PUT = do_DELETE = _any


_HANDSHAKE = threading.local()  # SNI from the callback, read by the same thread after the handshake


class TLSUpstream(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, port, ctx, name, rec):
        super().__init__(("127.0.0.1", port), UpstreamHandler)
        self.ctx, self.name, self.rec = ctx, name, rec

    def finish_request(self, request, client_address):
        _HANDSHAKE.sni = None
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            self.rec.fail(self.name)
            return
        tls.ap_sni = _HANDSHAKE.sni
        self.RequestHandlerClass(tls, client_address, self)


class Upstreams:
    """Four TLS listeners on loopback. Each serves the cert named after its host."""

    SPEC = [("good", "api.up.test"), ("evil", "evil.up.test"), ("badca", "badca.up.test"),
            ("wrongname", "other.up.test")]

    def __init__(self, pki):
        self.rec = Recorder()
        for name, cert_host in self.SPEC:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(f"{pki}/{cert_host}.pem", f"{pki}/{cert_host}.key")
            ctx.sni_callback = lambda _sock, server_name, _ctx: setattr(_HANDSHAKE, "sni", server_name)
            srv = TLSUpstream(UPSTREAM_PORTS[name], ctx, name, self.rec)
            threading.Thread(target=srv.serve_forever, daemon=True).start()


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._sock_path)
        self.sock = s


class Env:
    def __init__(self, bindir, work):
        self.bindir, self.work = bindir, work
        self.run_dir = os.path.join(work, "run")
        self.tokens_dir = os.path.join(work, "tokens")  # replaced per proxy instance in start_proxy
        self.secrets_dir = os.path.join(work, "secrets")
        self.pki = os.path.join(work, "pki")
        for d in (self.run_dir, self.tokens_dir, self.pki):
            os.makedirs(d, exist_ok=True)
        self.session_sock = os.path.join(self.run_dir, "session.sock")
        self.admin_sock = os.path.join(self.run_dir, "admin.sock")
        self.audit_file = os.path.join(work, "audit.jsonl")
        self.keys = {i: "apk_" + secrets.token_hex(32) for i in IDENTITIES}
        # One runtime seed per identity. The config holds only the public key.
        self.runtime_seeds = {i: secrets.token_bytes(32) for i in IDENTITIES}
        self.runtime_pub = {i: ed25519_pubkey_b64(work, self.runtime_seeds[i]) for i in IDENTITIES}
        self.creds = {c: "real-" + secrets.token_hex(24) for c in CREDENTIALS}
        self.minted = []  # every surrogate issued this run, for the secret scan
        self.sessions = {}  # surrogate -> (identity, session, generation, credentials)
        self.tokens = {}  # identity -> authority token (memory only)
        self.proc = None
        self.egress = None
        self.probe = None
        self.cur_cfg = None
        self.port = PORT_MAIN
        self.main_cfg = os.path.join(work, "config-main.toml")
        self._certs()
        self._write_secrets()
        self.up = Upstreams(self.pki)

    # ------------------------------------------------------------ PKI and secret store
    def _certs(self):
        d = self.pki
        for ca in ("ca", "evilca"):
            sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
               "-keyout", f"{d}/{ca}.key", "-out", f"{d}/{ca}.pem", "-days", "2", "-subj", f"/CN=ap-test-{ca}")
        for name, ca in (("api.up.test", "ca"), ("evil.up.test", "ca"), ("badca.up.test", "evilca"),
                         ("other.up.test", "ca")):
            sh("openssl", "req", "-newkey", "rsa:2048", "-nodes",
               "-keyout", f"{d}/{name}.key", "-out", f"{d}/{name}.csr", "-subj", f"/CN={name}")
            ext = f"{d}/{name}.ext"
            with open(ext, "w") as f:
                f.write(f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth\n")
            sh("openssl", "x509", "-req", "-in", f"{d}/{name}.csr", "-CA", f"{d}/{ca}.pem", "-CAkey",
               f"{d}/{ca}.key", "-CAcreateserial", "-out", f"{d}/{name}.pem", "-days", "2", "-extfile", ext)

    def secret_path(self, cred):
        source = CREDENTIALS[cred][0]
        _, secret, key = source.split(":")
        return os.path.join(self.secrets_dir, secret, key)

    def _write_secrets(self):
        for cred, value in self.creds.items():
            p = self.secret_path(cred)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(value)

    # ------------------------------------------------------------ TOML config
    def main_text(self, port=PORT_MAIN, lease=900, authority=600, grants=None,
                  egress_allow=("allowed.test:443",)):
        grants = DEFAULT_GRANTS if grants is None else grants
        out = [
            "version = 1",
            "",
            "[listen]",
            f'proxy = "127.0.0.1:{port}"',
            "",
            "[sessions]",
            f"lease_secs = {lease}",
            f"authority_lease_secs = {authority}",
            "max_sessions = 1024",
            "",
            "[limits]",
            f"max_body_bytes = {MAX_BODY}",
            "",
        ]
        for name in IDENTITIES:
            out += ["[[identity]]", f'name = "{name}"', f'runtime_pubkey = "{self.runtime_pub[name]}"',
                    f'caller_key_sha256 = "{sha256_hex(self.keys[name])}"', ""]
        for route, (host, port_key, extra) in ROUTE_HOSTS.items():
            out += ["[[route]]", f'name = "{route}"', f'host = "{host}"', f"port = {UPSTREAM_PORTS[port_key]}"]
            if extra:
                out.append(extra)
            out.append("")
        for cred, (source, routes) in CREDENTIALS.items():
            rs = ", ".join(f'"{r}"' for r in routes)
            out += ["[[credential]]", f'id = "{cred}"', f'source = "{source}"', f"routes = [{rs}]", ""]
        for g in grants:
            ms = ", ".join(f'"{m}"' for m in g["methods"])
            ps = ", ".join(f'"{p}"' for p in g["paths"])
            out += ["[[grant]]", f'identity = "{g["identity"]}"', f'credential = "{g["credential"]}"',
                    f'route = "{g["route"]}"', f"methods = [{ms}]", f"paths = [{ps}]"]
            if g.get("aws_targets"):
                ts = ", ".join(f'"{t}"' for t in g["aws_targets"])
                out.append(f"aws_targets = [{ts}]")
            out.append("")
        allow = ", ".join(f'"{x}"' for x in egress_allow)
        out += ["[egress]", f"allow = [{allow}]", ""]
        return "\n".join(out)

    def write_file(self, path, text):
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, path)
        time.sleep(0.1)  # let the stat-based reload see the change

    def write_main(self, text):
        self.write_file(self.main_cfg, text)

    def write_main_default(self):
        self.write_main(self.main_text())

    # ------------------------------------------------------------ processes
    def _proxy_env(self):
        resolve = ",".join(f"{h}=127.0.0.1" for h in ("api.up.test", "evil.up.test", "badca.up.test",
                                                       "wrongname.up.test"))
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.work,
                "AP_TEST_UPSTREAM_CA": os.path.join(self.pki, "ca.pem"), "AP_TEST_RESOLVE": resolve}

    def start_proxy(self, cfg_path, port, keep_tokens=False):
        """Start the proxy. A fresh instance gets a fresh token directory, because a restored
        authority hash holds a full lease and refuses hello (by design). A restart keeps it."""
        self.stop_proxy()
        if not keep_tokens:
            self.tokens = {}
            self.tokens_dir = os.path.join(self.work, f"tokens-{port}-{secrets.token_hex(4)}")
            os.makedirs(self.tokens_dir)
            # The proxy refuses to start without its expiry store. The pod creates it once in
            # expiry-store-bootstrap (pod.yaml); the harness does the same, with the same header.
            with open(os.path.join(self.tokens_dir, "session-expiry.v1"), "x") as f:
                f.write("auth-proxy session expiry v1\n")
        self.port = port
        self.cur_cfg = cfg_path
        out = open(self.audit_file, "ab")
        err = open(os.path.join(self.work, f"proxy-{port}.log"), "ab")
        self.proc = subprocess.Popen(
            [os.path.join(self.bindir, "auth-proxy"), "--config", cfg_path,
             "--session-socket", self.session_sock, "--admin-socket", self.admin_sock,
             "--secret-root", self.secrets_dir, "--token-dir", self.tokens_dir],
            stdout=out, stderr=err, env=self._proxy_env())
        out.close()
        err.close()
        if not wait_port(port, self.proc) or not os.path.exists(self.session_sock):
            raise RuntimeError(f"auth-proxy did not start on {port}; see proxy-{port}.log")

    def stop_proxy(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def restart_proxy(self):
        """Stop and start the same proxy with the same config and sockets (a crash-and-restart)."""
        self.start_proxy(self.cur_cfg, self.port, keep_tokens=True)

    def start_egress(self, cfg_path):
        err = open(os.path.join(self.work, "egress.log"), "ab")
        self.egress = subprocess.Popen(
            [os.path.join(self.bindir, "ap-egress"), "--config", cfg_path, "--listen", f"127.0.0.1:{PORT_EGRESS}"],
            stdout=err, stderr=err,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AP_TEST_EGRESS_RESOLVE": EGRESS_RESOLVE})
        err.close()
        if not wait_port(PORT_EGRESS, self.egress):
            raise RuntimeError("ap-egress did not start; see egress.log")

    def stop_egress(self):
        if self.egress is not None:
            self.egress.terminate()
            try:
                self.egress.wait(5)
            except subprocess.TimeoutExpired:
                self.egress.kill()
            self.egress = None

    def close(self):
        self.stop_proxy()
        self.stop_egress()

    # ------------------------------------------------------------ session plane (UDS)
    def sp(self, method, path, body=None, token=None, raw_body=None):
        c = UnixHTTP(self.session_sock)
        headers = {"content-type": "application/json"}
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            j = json.loads(raw) if raw else None
        except ValueError:
            j = None
        return r.status, j

    def sign_hello(self, identity, nonce, seed=None):
        """A proof over the hello message. Uses the identity's runtime seed unless `seed` is given."""
        return ed25519_sign_hello(self.work, seed or self.runtime_seeds[identity], identity, nonce)

    def hello(self, identity, seed=None):
        """Fetch a challenge, sign it, and post the hello. Stores the token on 201."""
        st, ch = self.sp("GET", "/v1/hello/challenge")
        if st != 200:
            return st, ch
        nonce = ch["nonce"]
        proof = self.sign_hello(identity, nonce, seed)
        st, j = self.sp("POST", "/v1/hello", {"identity": identity, "nonce": nonce, "proof": proof})
        if st == 201:
            self.tokens[identity] = j["authority_token"]
        return st, j

    def token(self, identity):
        if identity not in self.tokens:
            st, j = self.hello(identity)
            if st != 201:
                raise RuntimeError(f"hello for {identity} returned {st} {j}")
        return self.tokens[identity]

    def mint(self, identity="agent-1", creds=("c-up",), session=None, gen=1):
        """Register one session with a fresh surrogate, through the real session plane."""
        tok = self.token(identity)
        surrogate = "aps_" + secrets.token_hex(32)
        sess = session or ("s-" + secrets.token_hex(6))
        entry = {"session": sess, "generation": gen, "surrogate_sha256": sha256_hex(surrogate),
                 "credentials": list(creds)}
        st, j = self.sp("POST", "/v1/sessions", entry, token=tok)
        if st != 201:
            raise RuntimeError(f"register returned {st} {j}")
        self.minted.append(surrogate)
        self.sessions[surrogate] = (identity, sess, gen, list(creds))
        return surrogate

    def entry_for(self, surrogate):
        identity, sess, gen, creds = self.sessions[surrogate]
        return {"session": sess, "generation": gen, "surrogate_sha256": sha256_hex(surrogate),
                "credentials": creds}

    def revoke(self, surrogate, identity="agent-1"):
        _, sess, gen, _ = self.sessions[surrogate]
        st, _ = self.sp("DELETE", f"/v1/sessions/{sess}/{gen}", token=self.token(identity))
        return st

    # ------------------------------------------------------------ agent side (TCP, proxy listener)
    def authority(self):
        return f"127.0.0.1:{self.port}"

    def ap(self, route, rest, identity="agent-1", key=None):
        return f"/ap/{key or self.keys[identity]}/{route}{rest}"

    def bearer(self, s):
        return [("Authorization", f"Bearer {s}")]

    def req(self, method, path, headers=(), body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        hs = list(headers)
        if not any(k.lower() == "host" for k, _ in hs):
            hs.insert(0, ("Host", self.authority()))
        for k, v in hs:
            c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        data = r.read()
        hdr = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, hdr, data

    def raw(self, data, timeout=3):
        """Send raw bytes, return (status, head_text, body). Reads Content-Length bodies only."""
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        s.settimeout(timeout)
        try:
            s.sendall(data)
        except OSError:
            pass
        return read_response(s)

    def raw_req(self, line, headers):
        lines = [line] + [f"{k}: {v}" for k, v in headers] + ["", ""]
        return self.raw("\r\n".join(lines).encode())

    def ulog(self):
        return self.up.rec.snapshot()

    def ureset(self):
        self.up.rec.reset()

    # ------------------------------------------------------------ secret scan
    def secrets_in_files(self):
        """Work-dir files that contain a test credential, surrogate, or raw caller key (or /ap/<key>).

        The secret store (`secrets/`) is skipped: it holds the test credentials by design, and it is
        the only place they are allowed to live.
        """
        needles = [v.encode() for v in self.creds.values()] + [s.encode() for s in self.minted]
        for k in self.keys.values():
            needles += [k.encode(), ("/ap/" + k).encode()]
        hits, scanned = [], []
        for root, _dirs, files in os.walk(self.work):
            rel = os.path.relpath(root, self.work)
            if rel == "secrets" or rel.startswith("secrets" + os.sep):
                continue
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                scanned.append(os.path.relpath(p, self.work))
                if any(n in data for n in needles):
                    hits.append(os.path.relpath(p, self.work))
        return hits, scanned


def read_response(s):
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            b = s.recv(65536)
            if not b:
                break
            buf += b
        head, _, rest = buf.partition(b"\r\n\r\n")
        cl = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                cl = int(line.split(b":", 1)[1])
        while len(rest) < cl:
            b = s.recv(65536)
            if not b:
                break
            rest += b
    except socket.timeout:
        head, rest = buf, b""
    finally:
        s.close()
    first = head.split(b"\r\n", 1)[0].decode(errors="replace").split(" ")
    status = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
    return status, head.decode(errors="replace"), rest


def tls_get(port, sni, path, headers, cafile):
    """A client that follows a redirect itself, holding only what it was given."""
    ctx = ssl.create_default_context(cafile=cafile)
    raw = socket.create_connection(("127.0.0.1", port), 5)
    s = ctx.wrap_socket(raw, server_hostname=sni)
    s.settimeout(5)
    lines = [f"GET {path} HTTP/1.1", f"Host: {sni}:{port}"] + [f"{k}: {v}" for k, v in headers] + ["", ""]
    s.sendall("\r\n".join(lines).encode())
    status, _, _ = read_response(s)
    return status
