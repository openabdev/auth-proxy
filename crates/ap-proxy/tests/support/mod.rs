//! Fixtures for the integration tests: the real `auth-proxy` binary, a mock TLS
//! upstream (tests/matrix/upstream.py, the same one the matrix uses), a policy
//! file, Secret files, and blocking HTTP helpers.
//!
//! Unix socket paths stay short (macOS limit: 104 bytes).
#![allow(dead_code)]

use ap_client::Client;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- ports, certs

pub fn free_port() -> u16 {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let used = USED.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        let p = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if used.lock().unwrap().insert(p) {
            return p;
        }
    }
}

fn sh(cmd: &str, args: &[&str]) {
    let st = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("cannot run {cmd}: {e}"));
    assert!(st.success(), "{cmd} {args:?} failed");
}

/// A throwaway CA and one server certificate for `api.up.test`, made once per
/// test binary. `ecparam` writes a named-curve key; `req -newkey ec` on
/// LibreSSL (macOS) writes explicit parameters that no TLS stack accepts.
pub fn pki() -> &'static Path {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        let d = PathBuf::from(format!("/tmp/apx-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = |f: &str| d.join(f).to_string_lossy().into_owned();
        sh(
            "openssl",
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                &p("ca.key"),
            ],
        );
        sh(
            "openssl",
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &p("ca.key"),
                "-out",
                &p("ca.pem"),
                "-days",
                "2",
                "-sha256",
                "-subj",
                "/CN=ap-test-ca",
            ],
        );
        sh(
            "openssl",
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                &p("api.key"),
            ],
        );
        sh(
            "openssl",
            &[
                "req",
                "-new",
                "-key",
                &p("api.key"),
                "-out",
                &p("api.csr"),
                "-subj",
                "/CN=api.up.test",
            ],
        );
        std::fs::write(
            d.join("api.ext"),
            "subjectAltName=DNS:api.up.test\nextendedKeyUsage=serverAuth\n",
        )
        .unwrap();
        sh(
            "openssl",
            &[
                "x509",
                "-req",
                "-in",
                &p("api.csr"),
                "-CA",
                &p("ca.pem"),
                "-CAkey",
                &p("ca.key"),
                "-CAcreateserial",
                "-out",
                &p("api.pem"),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                &p("api.ext"),
            ],
        );
        d
    })
}

// ---------------------------------------------------------------- HTTP (blocking)

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The proxy's refusal code.
    pub fn code(&self) -> Option<&str> {
        self.header("x-auth-proxy-error")
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

fn parse_resp(raw: &[u8]) -> Resp {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response head in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("bad status line in {head:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    if chunked {
        let mut out = Vec::new();
        let mut rest = &body[..];
        while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(
                std::str::from_utf8(&rest[..eol])
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .trim(),
                16,
            )
            .unwrap_or(0);
            if n == 0 || rest.len() < eol + 2 + n {
                break;
            }
            out.extend_from_slice(&rest[eol + 2..eol + 2 + n]);
            rest = &rest[(eol + 2 + n + 2).min(rest.len())..];
        }
        body = out;
    }
    Resp {
        status,
        headers,
        body,
    }
}

/// Send `req` and read to EOF (requests carry `Connection: close`). A write
/// error (the proxy refused early and closed) does not stop the read.
pub fn raw_http(port: u16, req: &[u8]) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let _ = s.write_all(req);
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if !out.is_empty() && e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => panic!("read response: {e}"),
        }
    }
    parse_resp(&out)
}

// ---------------------------------------------------------------- the fixture

#[derive(Clone, Default)]
pub struct Opts {
    pub authority_lease_secs: Option<u64>,
    pub session_lease_secs: Option<u64>,
    pub absolute_ttl_secs: Option<u64>,
    pub max_sessions: Option<u64>,
    pub max_body_bytes: Option<u64>,
    /// INTERIM Q1-A: sha256 (hex) of the pod-lifetime surrogate.
    pub interim_static_sha256: Option<String>,
}

pub fn grant(cred: &str, route: &str, methods: &[&str], paths: &[&str], aws: &[&str]) -> String {
    let q = |v: &[&str]| serde_json::to_string(v).unwrap();
    let mut s = format!(
        "[[grant]]\ncredential = \"{cred}\"\nroute = \"{route}\"\nmethods = {}\npaths = {}\n",
        q(methods),
        q(paths)
    );
    if !aws.is_empty() {
        s.push_str(&format!("aws_targets = {}\n", q(aws)));
    }
    s
}

/// Grants on every route of the default policy.
pub fn default_grants() -> String {
    [
        grant("c-up", "up", &["GET", "POST"], &["/v1/"], &[]),
        grant("c-up", "upaws", &["GET", "POST"], &["/v1/"], &[]),
        grant("c-up", "dead", &["GET", "POST"], &["/v1/"], &[]),
        grant("c-other", "other", &["GET", "POST"], &["/v1/"], &[]),
    ]
    .join("\n")
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct Fixture {
    pub dir: PathBuf,
    /// The agent listener.
    pub port: u16,
    pub up_port: u16,
    pub up_ctl: u16,
    pub dead_port: u16,
    pub caller_key: String,
    pub creds: Vec<(String, String)>,
    pub opts: Opts,
    upstream: Option<Child>,
    proxy: Option<Child>,
}

impl Fixture {
    /// A fixture with the mock upstream running and the policy and Secrets
    /// written. The proxy is not started.
    pub fn new(opts: Opts) -> Fixture {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("/tmp/apx-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = ap_client::Surrogate::generate().unwrap().into_string();
        let caller_key = format!("apk_{}", &key[4..]);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let creds = vec![
            ("c-up".to_string(), format!("real-up-{nanos:x}-{n}")),
            ("c-other".to_string(), format!("real-other-{nanos:x}-{n}")),
        ];
        let mut f = Fixture {
            dir,
            port: free_port(),
            up_port: free_port(),
            up_ctl: free_port(),
            dead_port: free_port(),
            caller_key,
            creds,
            opts,
            upstream: None,
            proxy: None,
        };
        for (id, v) in f.creds.clone() {
            f.write_secret(&id, &v);
        }
        f.set_policy("agent-1", &default_grants());
        f.start_upstream();
        f
    }

    // ---- paths
    pub fn policy_path(&self) -> PathBuf {
        self.dir.join("policy.toml")
    }
    pub fn secrets_dir(&self) -> PathBuf {
        self.dir.join("secrets")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }
    pub fn session_sock(&self) -> PathBuf {
        self.dir.join("s").join("s.sock")
    }
    pub fn admin_sock(&self) -> PathBuf {
        self.dir.join("a").join("a.sock")
    }
    pub fn stdout_log(&self) -> PathBuf {
        self.dir.join("stdout.log")
    }
    pub fn stderr_log(&self) -> PathBuf {
        self.dir.join("stderr.log")
    }

    // ---- policy and secrets
    pub fn policy_toml(&self, identity: &str, grants: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(self.caller_key.as_bytes()));
        let up = self.up_port;
        let dead = self.dead_port;
        format!(
            r#"version = 1
identity = "{identity}"
caller_key_sha256 = "{hash}"

[[route]]
name = "up"
host = "api.up.test"
port = {up}
connect_to = "127.0.0.1:{up}"
pass_headers = ["tokentype"]

[[route]]
name = "upaws"
host = "api.up.test"
port = {up}
connect_to = "127.0.0.1:{up}"
error_shape = "aws"

[[route]]
name = "other"
host = "api.up.test"
port = {up}
connect_to = "127.0.0.1:{up}"

[[route]]
name = "dead"
host = "dead.up.test"
port = {dead}
connect_to = "127.0.0.1:{dead}"

[[credential]]
id = "c-up"
source = "k8s:c-up:api_key"
routes = ["up", "upaws", "dead"]

[[credential]]
id = "c-other"
source = "k8s:c-other:api_key"
routes = ["other"]

{grants}
"#
        )
    }

    /// Replace the policy file in one rename, as kubelet does.
    pub fn set_policy(&self, identity: &str, grants: &str) {
        self.set_policy_raw(&self.policy_toml(identity, grants));
    }

    pub fn set_policy_raw(&self, content: &str) {
        let tmp = self.dir.join("policy.toml.tmp");
        std::fs::write(&tmp, content).unwrap();
        std::fs::rename(&tmp, self.policy_path()).unwrap();
    }

    pub fn write_secret(&self, id: &str, value: &str) {
        let d = self.secrets_dir().join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("api_key"), value).unwrap();
    }

    pub fn remove_secret(&self, id: &str) {
        std::fs::remove_file(self.secrets_dir().join(id).join("api_key")).unwrap();
    }

    pub fn secret_value(&self, id: &str) -> String {
        self.creds.iter().find(|(i, _)| i == id).unwrap().1.clone()
    }

    // ---- processes
    fn start_upstream(&mut self) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/matrix/upstream.py");
        let pki = pki();
        let listen = format!(
            "good={}:{}:{}",
            self.up_port,
            pki.join("api.pem").display(),
            pki.join("api.key").display()
        );
        let child = Command::new("python3")
            .arg(&script)
            .args(["--control", &self.up_ctl.to_string(), "--listen", &listen])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3 is needed for the mock upstream");
        self.upstream = Some(child);
        wait_port(self.up_ctl, "mock upstream");
        wait_port(self.up_port, "mock upstream listener");
    }

    pub fn proxy_command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_auth-proxy"));
        c.args(["--policy", &self.policy_path().to_string_lossy()])
            .args(["--secrets-dir", &self.secrets_dir().to_string_lossy()])
            .args(["--listen", &format!("127.0.0.1:{}", self.port)])
            .args(["--session-socket", &self.session_sock().to_string_lossy()])
            .args(["--admin-socket", &self.admin_sock().to_string_lossy()])
            .args(["--state-dir", &self.state_dir().to_string_lossy()])
            .args(["--ca-file", &pki().join("ca.pem").to_string_lossy()]);
        let o = &self.opts;
        for (flag, v) in [
            ("--authority-lease-secs", o.authority_lease_secs),
            ("--session-lease-secs", o.session_lease_secs),
            ("--absolute-ttl-secs", o.absolute_ttl_secs),
            ("--max-sessions", o.max_sessions),
            ("--max-body-bytes", o.max_body_bytes),
        ] {
            if let Some(v) = v {
                c.args([flag, &v.to_string()]);
            }
        }
        if let Some(h) = &o.interim_static_sha256 {
            c.args(["--interim-static-surrogate-sha256", h]);
        }
        c.env_clear().env("PATH", "/usr/bin:/bin");
        c
    }

    fn log_file(&self, p: PathBuf) -> Stdio {
        Stdio::from(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .unwrap(),
        )
    }

    /// Start the proxy with stdout and stderr captured to files (appended, so a
    /// restart keeps the history), and wait until it answers.
    pub fn start_proxy(&mut self) {
        assert!(self.proxy.is_none(), "proxy already running");
        let mut cmd = self.proxy_command();
        cmd.stdout(self.log_file(self.stdout_log()))
            .stderr(self.log_file(self.stderr_log()));
        let mut child = cmd.spawn().expect("spawn auth-proxy");
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(st) = child.try_wait().unwrap() {
                panic!(
                    "auth-proxy exited early ({st}); stderr:\n{}",
                    std::fs::read_to_string(self.stderr_log()).unwrap_or_default()
                );
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok()
                && self.session_sock().exists()
                && self.admin_sock().exists()
            {
                break;
            }
            assert!(Instant::now() < end, "auth-proxy did not start in 15 s");
            std::thread::sleep(Duration::from_millis(20));
        }
        self.proxy = Some(child);
    }

    pub fn proxy_pid(&self) -> u32 {
        self.proxy.as_ref().expect("proxy running").id()
    }

    /// SIGKILL: the socket files stay behind, like after a crash.
    pub fn kill_proxy(&mut self) {
        if let Some(mut c) = self.proxy.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// SIGTERM, then wait: returns the exit code.
    pub fn stop_proxy(&mut self) -> Option<i32> {
        let mut c = self.proxy.take()?;
        let _ = Command::new("kill")
            .args(["-TERM", &c.id().to_string()])
            .status();
        c.wait().ok().and_then(|s| s.code())
    }

    pub fn proxy_alive(&mut self) -> bool {
        self.proxy
            .as_mut()
            .is_some_and(|c| c.try_wait().unwrap().is_none())
    }

    // ---- session plane and admin
    pub fn client(&self) -> Client {
        Client::new(self.session_sock())
    }

    pub fn admin(&self) -> Client {
        Client::new(self.admin_sock())
    }

    // ---- agent requests
    pub fn request(
        &self,
        method: &str,
        route: &str,
        rest: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        self.request_with_key(&self.caller_key, method, route, rest, headers, body)
    }

    pub fn request_with_key(
        &self,
        key: &str,
        method: &str,
        route: &str,
        rest: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        let mut req = format!(
            "{method} /ap/{key}/{route}{rest} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n",
            self.port
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !body.is_empty() || method == "POST" {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(body);
        raw_http(self.port, &bytes)
    }

    /// `GET /ap/<key>/<route><rest>` with the surrogate as a Bearer token.
    pub fn get(&self, route: &str, rest: &str, surrogate: &str) -> Resp {
        self.request(
            "GET",
            route,
            rest,
            &[("Authorization", &format!("Bearer {surrogate}"))],
            b"",
        )
    }

    // ---- mock upstream
    fn control(&self, method: &str) -> Vec<u8> {
        let mut s = TcpStream::connect(("127.0.0.1", self.up_ctl)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "{method} / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        )
        .unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    /// Requests the mock upstream has received.
    pub fn upstream_log(&self) -> Vec<serde_json::Value> {
        let r = parse_resp(&self.control("GET"));
        r.json()["log"].as_array().cloned().unwrap_or_default()
    }

    pub fn upstream_count(&self) -> usize {
        self.upstream_log().len()
    }

    pub fn reset_upstream(&self) {
        self.control("POST");
    }

    // ---- logs
    pub fn read_logs(&self) -> (String, String) {
        (
            std::fs::read_to_string(self.stdout_log()).unwrap_or_default(),
            std::fs::read_to_string(self.stderr_log()).unwrap_or_default(),
        )
    }

    /// Request audit lines (those with a `decision`).
    pub fn audit_lines(&self) -> Vec<serde_json::Value> {
        self.read_logs()
            .0
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v.get("decision").is_some())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kill_proxy();
        if let Some(mut u) = self.upstream.take() {
            let _ = u.kill();
            let _ = u.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_port(port: u16, what: &str) {
    let end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < end {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("{what} did not come up on {port}");
}

/// Register a session through a fresh surrogate, returning it.
pub async fn register(
    client: &Client,
    session: &str,
    generation: u64,
    creds: &[&str],
) -> ap_client::Surrogate {
    let s = ap_client::Surrogate::generate().unwrap();
    let reg = ap_client::Registration::new(session, generation, &s, creds);
    client.register(&reg).await.expect("register");
    s
}
