"""Shared setup for the Experiment 2 matrix and benchmarks.

Brings up, on loopback only: a throwaway CA pair, mock TLS upstreams, the mock
broker, and either option A (ap-proxy) or option B (Envoy + ap-authz). All
credentials here are random per run; nothing real is involved.
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
import time
import urllib.request

P = dict(listen=18100, authz=18101, broker=18190, ctl=18199,
         good=18443, evil=18444, badca=18445, wrongname=18446)
AUTHORITY = f"127.0.0.1:{P['listen']}"


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


class Env:
    def __init__(self, impl, work, bindir):
        assert impl in ("a", "b")
        self.impl, self.work, self.bindir = impl, work, bindir
        os.makedirs(work, exist_ok=True)
        self.procs = {}
        self.keys = {"agent-1": secrets.token_hex(16), "agent-2": secrets.token_hex(16)}
        self.creds = {"c-up": "real-" + secrets.token_hex(24), "c-key": "real-" + secrets.token_hex(24)}
        self.minted = []
        self.policy_file = os.path.join(work, "policy.json")
        self.audit_file = os.path.join(work, "audit.jsonl")
        self._certs()

    # ------------------------------------------------------------ certs
    def _certs(self):
        d = os.path.join(self.work, "pki")
        os.makedirs(d, exist_ok=True)
        self.pki = d
        for ca in ("ca", "evilca"):
            sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
               "-keyout", f"{d}/{ca}.key", "-out", f"{d}/{ca}.pem", "-days", "2", "-subj", f"/CN=ap-test-{ca}")
        for name, ca in (("api.up.test", "ca"), ("evil.up.test", "ca"), ("badca.up.test", "evilca"),
                         ("other.up.test", "ca")):
            sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
               "-keyout", f"{d}/{name}.key", "-out", f"{d}/{name}.csr", "-subj", f"/CN={name}")
            ext = f"{d}/{name}.ext"
            with open(ext, "w") as f:
                f.write(f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth\n")
            sh("openssl", "x509", "-req", "-in", f"{d}/{name}.csr", "-CA", f"{d}/{ca}.pem", "-CAkey", f"{d}/{ca}.key",
               "-CAcreateserial", "-out", f"{d}/{name}.pem", "-days", "2", "-extfile", ext)

    # ------------------------------------------------------------ config
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

    def config(self, routes=None):
        return {
            "listen": f"127.0.0.1:{P['listen']}",
            "authz_listen": f"127.0.0.1:{P['authz']}",
            "listener_authorities": [AUTHORITY, f"localhost:{P['listen']}"],
            "broker_url": f"http://127.0.0.1:{P['broker']}",
            "policy_file": self.policy_file,
            "ca_file": f"{self.pki}/ca.pem",
            "audit_file": self.audit_file,
            "callers": [{"id": c, "key_sha256": hashlib.sha256(k.encode()).hexdigest()} for c, k in self.keys.items()],
            "routes": routes if routes is not None else self.routes(),
        }

    def write_config(self, cfg, name="config.json"):
        p = os.path.join(self.work, name)
        with open(p, "w") as f:
            json.dump(cfg, f, indent=1)
        return p

    def default_policy(self):
        rules = [{"caller": "agent-1", "route": r["name"], "methods": ["GET", "POST"], "path_prefixes": ["/v1/"]}
                 for r in self.routes()]
        rules.append({"caller": "agent-2", "route": "up", "methods": ["GET", "POST"], "path_prefixes": ["/v1/"]})
        return {"rules": rules}

    def set_policy(self, obj=None, raw=None, delete=False):
        if delete:
            if os.path.exists(self.policy_file):
                os.remove(self.policy_file)
            return
        data = raw if raw is not None else json.dumps(obj if obj is not None else self.default_policy())
        tmp = self.policy_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(data)
        os.replace(tmp, self.policy_file)
        time.sleep(0.02)

    # ------------------------------------------------------------ processes
    def _spawn(self, name, cmd, env=None, port=None):
        log = open(os.path.join(self.work, f"{name}.log"), "ab")
        p = subprocess.Popen(cmd, stdout=log, stderr=log, env=env)
        self.procs[name] = p
        if port and not wait_port(port, proc=p):
            raise RuntimeError(f"{name} did not start; see {name}.log")
        return p

    def stop(self, name):
        p = self.procs.pop(name, None)
        if p:
            p.terminate()
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

    def start_broker(self, extra_env=None, creds=None):
        here = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ)
        args = []
        for cid, v in (creds or self.creds).items():
            ev = "AP_TEST_CRED_" + cid.replace("-", "_").upper()
            env[ev] = v
            args += ["--cred", f"{cid}={ev}"]
        env.update(extra_env or {})
        self._spawn("broker", ["python3", f"{here}/broker.py", "--listen", str(P["broker"])] + args, env=env,
                    port=P["broker"])

    def start_impl(self, cfg_path=None):
        cfg_path = cfg_path or self.write_config(self.config())
        clean = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.work}
        if self.impl == "a":
            self._spawn("ap-proxy", [f"{self.bindir}/ap-proxy", cfg_path], env=clean, port=P["listen"])
        else:
            self.start_authz(cfg_path)
            ej = os.path.join(self.work, "envoy.json")
            with open(ej, "w") as f:
                subprocess.run([f"{self.bindir}/ap-authz", "render-envoy", cfg_path], stdout=f, check=True)
            self._spawn("envoy", [f"{self.bindir}/envoy", "-c", ej, "--log-level", "warn",
                                  "--disable-hot-restart", "--base-id", "7"], env=clean, port=P["listen"])

    def start_authz(self, cfg_path=None):
        cfg_path = cfg_path or os.path.join(self.work, "config.json")
        clean = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.work}
        self._spawn("ap-authz", [f"{self.bindir}/ap-authz", "serve", cfg_path], env=clean, port=P["authz"])

    def impl_pids(self):
        names = ["ap-proxy"] if self.impl == "a" else ["envoy", "ap-authz"]
        return {n: self.procs[n].pid for n in names if n in self.procs}

    def close(self):
        for n in list(self.procs):
            self.stop(n)

    # ------------------------------------------------------------ broker / upstream control
    def _post(self, port, path, obj):
        r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(obj).encode(),
                                   headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(r, timeout=5) as resp:
            b = resp.read()
            return json.loads(b) if b else {}

    def mint(self, caller="agent-1", route="up", cred="c-up", ttl=900):
        s = self._post(P["broker"], "/admin/mint", {"caller": caller, "route": route, "credential_id": cred,
                                                    "ttl": ttl})["surrogate"]
        self.minted.append(s)
        return s

    def revoke(self, s):
        self._post(P["broker"], "/admin/revoke", {"surrogate": s})

    def ulog(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{P['ctl']}/", timeout=5) as r:
            return json.loads(r.read())

    def ureset(self):
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{P['ctl']}/", data=b"", method="POST"),
                               timeout=5).read()

    # ------------------------------------------------------------ client side
    def url(self, route, rest, caller="agent-1"):
        return f"/ap/{self.keys[caller]}/{route}{rest}"

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
        """Count work-dir files containing any real test credential, surrogate or caller key."""
        needles = [v.encode() for v in self.creds.values()] + [s.encode() for s in self.minted] + \
                  [k.encode() for k in self.keys.values()]
        hits = []
        for root, _, files in os.walk(self.work):
            if "pki" in root:
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
