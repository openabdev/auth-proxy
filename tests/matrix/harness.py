"""Shared setup for the fail-closed matrix (ported from spike/exp2/test/harness.py).

Brings up, on loopback only: a throwaway CA pair, mock TLS upstreams
(upstream.py) and the real `auth-proxy` binary. The mock broker of the spike is
gone: sessions are registered through the real session plane, over the Unix
socket, by an authority this harness plays (hello, register, renew, revoke,
resync). All credentials are random per run; nothing real is involved.

Work files live under a short /tmp path because a Unix socket path is limited
to 104 bytes on macOS.
"""
import hashlib
import http.client
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request

P = dict(listen=18100, ctl=18199, good=18443, evil=18444, badca=18445, wrongname=18446)
AUTHORITY = f"127.0.0.1:{P['listen']}"
MAX_BODY = 2 * 1024 * 1024
SESSION_LEASE_SECS = 2


def sh(*cmd, **kw):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def wait_port(port, timeout=15.0, proc=None):
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


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


class Env:
    def __init__(self, work, bindir):
        self.work, self.bindir = work, bindir
        os.makedirs(work, exist_ok=True)
        self.procs = {}
        self.caller_key = "apk_" + secrets.token_hex(32)
        self.creds = {"c-up": "real-" + secrets.token_hex(24), "c-key": "real-" + secrets.token_hex(24)}
        self.minted = []          # surrogates, for the secret scan
        self.sessions = {}        # surrogate -> registration dict (what the authority would resync)
        self.token = None         # authority token, never written to disk
        self.policy_file = os.path.join(work, "policy.toml")
        self.audit_file = os.path.join(work, "audit.jsonl")
        self.err_file = os.path.join(work, "proxy.err")
        self.secrets_dir = os.path.join(work, "secrets")
        self.state_dir = os.path.join(work, "state")
        self.session_sock = os.path.join(work, "sess", "s.sock")
        self.admin_sock = os.path.join(work, "adm", "a.sock")
        self._stop_renew = threading.Event()
        self._renewer = None
        self._certs()
        for cid, v in self.creds.items():
            self.write_secret(cid, v)

    # ------------------------------------------------------------ certs
    def _certs(self):
        d = os.path.join(self.work, "pki")
        os.makedirs(d, exist_ok=True)
        self.pki = d
        # ecparam writes a named-curve key. `req -newkey ec` on LibreSSL (the macOS system openssl)
        # writes explicit curve parameters, which no TLS stack accepts.
        for ca in ("ca", "evilca"):
            sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{d}/{ca}.key")
            sh("openssl", "req", "-x509", "-new", "-key", f"{d}/{ca}.key", "-out", f"{d}/{ca}.pem",
               "-days", "2", "-sha256", "-subj", f"/CN=ap-test-{ca}")
        for name, ca in (("api.up.test", "ca"), ("evil.up.test", "ca"), ("badca.up.test", "evilca"),
                         ("other.up.test", "ca")):
            sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{d}/{name}.key")
            sh("openssl", "req", "-new", "-key", f"{d}/{name}.key", "-out", f"{d}/{name}.csr", "-subj",
               f"/CN={name}")
            ext = f"{d}/{name}.ext"
            with open(ext, "w") as f:
                f.write(f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth\n")
            sh("openssl", "x509", "-req", "-in", f"{d}/{name}.csr", "-CA", f"{d}/{ca}.pem", "-CAkey", f"{d}/{ca}.key",
               "-CAcreateserial", "-out", f"{d}/{name}.pem", "-days", "2", "-sha256", "-extfile", ext)

    # ------------------------------------------------------------ policy (Q3-A TOML)
    def routes(self):
        lo = "127.0.0.1"
        return [
            {"name": "up", "host": "api.up.test", "port": P["good"], "connect_to": f"{lo}:{P['good']}"},
            {"name": "upaws", "host": "api.up.test", "port": P["good"], "connect_to": f"{lo}:{P['good']}",
             "error_shape": "aws"},
            {"name": "upkey", "host": "api.up.test", "port": P["good"], "connect_to": f"{lo}:{P['good']}",
             "surrogate_header": "x-api-key", "surrogate_scheme": "",
             "credential_header": "x-api-key", "credential_scheme": ""},
            {"name": "badca", "host": "badca.up.test", "port": P["badca"], "connect_to": f"{lo}:{P['badca']}"},
            {"name": "wrongname", "host": "wrongname.up.test", "port": P["wrongname"],
             "connect_to": f"{lo}:{P['wrongname']}"},
        ]

    # credential id -> routes it may be applied to
    CREDENTIALS = {"c-up": ["up", "upaws", "badca", "wrongname"], "c-key": ["upkey"]}

    def default_grants(self):
        return [{"credential": c, "route": r, "methods": ["GET", "POST"], "paths": ["/v1/"]}
                for c, rs in self.CREDENTIALS.items() for r in rs]

    @staticmethod
    def _q(v):
        return json.dumps(v)  # a TOML basic string / array of strings has JSON syntax

    def policy_toml(self, identity="agent-1", grants=None, routes=None, credentials=True):
        lines = ["version = 1", f"identity = {self._q(identity)}",
                 f"caller_key_sha256 = {self._q(sha256_hex(self.caller_key))}", ""]
        for r in (routes if routes is not None else self.routes()):
            lines.append("[[route]]")
            for k, v in r.items():
                lines.append(f"{k} = {self._q(v)}")
            lines.append("")
        if credentials:
            for cid, rs in self.CREDENTIALS.items():
                lines += ["[[credential]]", f"id = {self._q(cid)}", f"source = {self._q(f'k8s:{cid}:api_key')}",
                          f"routes = {self._q(rs)}", ""]
            for g in (grants if grants is not None else self.default_grants()):
                lines.append("[[grant]]")
                for k, v in g.items():
                    lines.append(f"{k} = {self._q(v)}")
                lines.append("")
        return "\n".join(lines)

    def set_policy(self, raw=None, delete=False, **kw):
        if delete:
            if os.path.exists(self.policy_file):
                os.remove(self.policy_file)
            return
        data = raw if raw is not None else self.policy_toml(**kw)
        tmp = self.policy_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(data)
        os.replace(tmp, self.policy_file)  # new inode, like kubelet's symlink swap
        time.sleep(0.02)

    def write_secret(self, cid, value=None):
        d = os.path.join(self.secrets_dir, cid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "api_key"), "w") as f:
            f.write(value if value is not None else self.creds[cid])

    def remove_secret(self, cid):
        os.remove(os.path.join(self.secrets_dir, cid, "api_key"))

    # ------------------------------------------------------------ processes
    def _spawn(self, name, cmd, env=None, port=None, stdout=None, stderr=None):
        out = stdout or open(os.path.join(self.work, f"{name}.log"), "ab")
        p = subprocess.Popen(cmd, stdout=out, stderr=stderr or out, env=env)
        self.procs[name] = p
        if port and not wait_port(port, proc=p):
            raise RuntimeError(f"{name} did not start; see {name}.log")
        return p

    def stop(self, name, kill=False):
        p = self.procs.pop(name, None)
        if p:
            p.kill() if kill else p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()

    def start_upstream(self):
        here = os.path.dirname(os.path.abspath(__file__))
        L = []
        for nm, host in (("good", "api.up.test"), ("evil", "evil.up.test"), ("badca", "badca.up.test"),
                         ("wrongname", "other.up.test")):
            L += ["--listen", f"{nm}={P[nm]}:{self.pki}/{host}.pem:{self.pki}/{host}.key"]
        self._spawn("upstream", ["python3", f"{here}/upstream.py", "--control", str(P["ctl"])] + L, port=P["ctl"])

    def proxy_cmd(self, policy=None):
        return [f"{self.bindir}/auth-proxy", "--policy", policy or self.policy_file,
                "--secrets-dir", self.secrets_dir, "--listen", AUTHORITY,
                "--session-socket", self.session_sock, "--admin-socket", self.admin_sock,
                "--state-dir", self.state_dir, "--ca-file", f"{self.pki}/ca.pem",
                "--max-body-bytes", str(MAX_BODY), "--session-lease-secs", str(SESSION_LEASE_SECS)]

    def clean_env(self):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.work}

    def start_impl(self):
        """Audit lines (stdout) and operator messages (stderr) go to files the X5 scan reads."""
        out = open(self.audit_file, "ab")
        err = open(self.err_file, "ab")
        self._spawn("auth-proxy", self.proxy_cmd(), env=self.clean_env(), port=P["listen"], stdout=out, stderr=err)
        end = time.time() + 5
        while time.time() < end and not (os.path.exists(self.session_sock) and os.path.exists(self.admin_sock)):
            time.sleep(0.02)

    def run_startup_check(self, policy_path):
        """Run the proxy against another policy file and return its exit code (it must not start)."""
        r = subprocess.run(self.proxy_cmd(policy_path), capture_output=True, timeout=15, env=self.clean_env())
        return r.returncode, r.stdout + r.stderr

    def close(self):
        self._stop_renew.set()
        for n in list(self.procs):
            self.stop(n)

    # ------------------------------------------------------------ session plane (the authority's side)
    def plane(self, method, path, obj=None, token="auto", raw=None):
        c = UnixHTTPConnection(self.session_sock)
        hs = {}
        tok = self.token if token == "auto" else token
        if tok:
            hs["Authorization"] = f"Bearer {tok}"
        body = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else None)
        if body is not None:
            hs["Content-Type"] = "application/json"
        try:
            c.request(method, path, body=body, headers=hs)
        except (BrokenPipeError, ConnectionResetError):
            pass  # an early refusal (413) may close before the body is sent; the answer is still readable
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            j = json.loads(data) if data else None
        except ValueError:
            j = None
        return r.status, j

    def hello(self):
        st, j = self.plane("POST", "/v1/hello", {}, token=None)
        assert st == 201, f"hello failed: {st} {j}"
        self.token = j["authority_token"]
        self._renewer = threading.Thread(target=self._renew_loop, daemon=True)
        self._renewer.start()

    def _renew_loop(self):
        """Keeps the authority's own lease alive (an empty session list), like a live runtime.
        Sessions are deliberately not renewed here, so their 2 s lease can lapse in R3."""
        while not self._stop_renew.wait(1.0):
            try:
                self.plane("POST", "/v1/renew", {"sessions": []})
            except OSError:
                pass

    def mint(self, cred="c-up", session=None, generation=1):
        """Generate a surrogate and register its hash, as the runtime does at session spawn."""
        s = "aps_" + secrets.token_hex(32)
        sid = session or f"m{len(self.minted)}"
        reg = {"session": sid, "generation": generation, "surrogate_sha256": sha256_hex(s), "credentials": [cred]}
        st, j = self.plane("POST", "/v1/sessions", reg)
        assert st == 201, f"register failed: {st} {j}"
        self.minted.append(s)
        self.sessions[s] = reg
        return s

    def revoke(self, s):
        reg = self.sessions[s]
        st, _ = self.plane("DELETE", f"/v1/sessions/{reg['session']}/{reg['generation']}")
        assert st == 204, f"revoke failed: {st}"

    # ------------------------------------------------------------ upstream control
    def ulog(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{P['ctl']}/", timeout=5) as r:
            return json.loads(r.read())

    def ureset(self):
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{P['ctl']}/", data=b"", method="POST"),
                               timeout=5).read()

    # ------------------------------------------------------------ client side
    def url(self, route, rest, key=None):
        return f"/ap/{key or self.caller_key}/{route}{rest}"

    def req(self, method, path, headers=(), body=None, conn=None):
        c = conn or http.client.HTTPConnection("127.0.0.1", P["listen"], timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        hs = list(headers)
        if not any(k.lower() == "host" for k, _ in hs):
            hs.insert(0, ("Host", AUTHORITY))
        for k, v in hs:
            c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        data = r.read()
        if conn is None:
            c.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def raw(self, data, port=None):
        s = socket.create_connection(("127.0.0.1", port or P["listen"]), 5)
        s.sendall(data)
        out = b""
        s.settimeout(5)
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                out += b
                if b"\r\n\r\n" in out:
                    head, _, rest = out.partition(b"\r\n\r\n")
                    cl = [l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")]
                    if cl and len(rest) >= int(cl[0].split(b":")[1]):
                        break
        except socket.timeout:
            pass
        s.close()
        line = out.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = line.split(" ")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0, out

    def direct_tls(self, port, sni, path, headers):
        """A naive client following a redirect itself (carries whatever it holds: the surrogate)."""
        ctx = ssl.create_default_context(cafile=f"{self.pki}/ca.pem")
        # Python >= 3.13 sets VERIFY_X509_STRICT, which rejects the test CA (no keyUsage extension).
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
        c._tunnel_host = None
        sock = socket.create_connection(("127.0.0.1", port), 5)
        c.sock = ctx.wrap_socket(sock, server_hostname=sni)
        c.putrequest("GET", path, skip_host=True)
        c.putheader("Host", f"{sni}:{port}")
        for k, v in headers:
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def secrets_in_files(self):
        """Work-dir files that contain a real test credential, surrogate, caller key or the
        authority token. The throwaway CA and the credential Secret files are exempt: they are
        meant to hold key material."""
        needles = [v.encode() for v in self.creds.values()] + [s.encode() for s in self.minted] + \
                  [self.caller_key.encode()] + ([self.token.encode()] if self.token else [])
        hits = []
        for root, _, files in os.walk(self.work):
            if root.startswith(self.pki) or root.startswith(self.secrets_dir):
                continue
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                for n in needles:
                    if n in data:
                        hits.append(fn)
                        break
        return hits

    def cleanup(self):
        shutil.rmtree(self.work, ignore_errors=True)


def short_workdir():
    return tempfile.mkdtemp(prefix="apm-", dir="/tmp")
