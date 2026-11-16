//! Command line and environment. Every option has an `AP_*` environment
//! twin; the command line wins. Any problem is a startup failure (exit 2).

use std::net::SocketAddr;
use std::path::PathBuf;

pub const USAGE: &str = "\
auth-proxy: credential-swapping reverse proxy (Phase 1, Kubernetes)

  --policy PATH              policy file (TOML, one identity)            AP_POLICY (required)
  --secrets-dir DIR          credential Secret volumes (proxy-only)      AP_SECRETS_DIR
                             [/run/secrets/auth-proxy]
  --listen ADDR              agent listener, loopback only, e.g.         AP_LISTEN
                             127.0.0.1:18080 (else policy [listener])
  --session-socket PATH      session plane (shared with the agent)       AP_SESSION_SOCKET
                             [/run/auth-proxy/session.sock]
  --session-socket-mode OCT  mode of the session socket                  AP_SESSION_SOCKET_MODE [660]
  --admin-socket PATH        admin plane (proxy-only mount)              AP_ADMIN_SOCKET
                             [/run/auth-proxy-admin/admin.sock]
  --state-dir DIR            proxy-private state (authority token hash)  AP_STATE_DIR
                             [/var/lib/auth-proxy]
  --max-body-bytes N         request body cap, 413 above it              AP_MAX_BODY_BYTES [33554432]
  --ca-file PATH             PEM roots for upstream TLS (replaces the    AP_CA_FILE
                             built-in roots; used by tests)
  --authority-lease-secs N   authority lease, >= 3                       AP_AUTHORITY_LEASE_SECS [90]
  --session-lease-secs N     session lease, >= 1                         AP_SESSION_LEASE_SECS [900]
  --absolute-ttl-secs N      session absolute TTL                        AP_ABSOLUTE_TTL_SECS [43200]
  --max-sessions N           registered sessions cap                     AP_MAX_SESSIONS [256]
  --help

Exit codes: 0 clean stop, 2 invalid arguments, policy or sockets.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub policy: PathBuf,
    pub secrets_dir: PathBuf,
    pub listen: Option<SocketAddr>,
    pub session_socket: PathBuf,
    pub session_socket_mode: u32,
    pub admin_socket: PathBuf,
    pub state_dir: PathBuf,
    pub max_body_bytes: u64,
    pub ca_file: Option<PathBuf>,
    pub authority_lease_secs: u64,
    pub session_lease_secs: u64,
    pub absolute_ttl_secs: u64,
    pub max_sessions: usize,
}

pub enum Parsed {
    Run(Box<Args>),
    Help,
}

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

struct Opt {
    flag: &'static str,
    env: &'static str,
}

const OPTS: &[Opt] = &[
    Opt {
        flag: "--policy",
        env: "AP_POLICY",
    },
    Opt {
        flag: "--secrets-dir",
        env: "AP_SECRETS_DIR",
    },
    Opt {
        flag: "--listen",
        env: "AP_LISTEN",
    },
    Opt {
        flag: "--session-socket",
        env: "AP_SESSION_SOCKET",
    },
    Opt {
        flag: "--session-socket-mode",
        env: "AP_SESSION_SOCKET_MODE",
    },
    Opt {
        flag: "--admin-socket",
        env: "AP_ADMIN_SOCKET",
    },
    Opt {
        flag: "--state-dir",
        env: "AP_STATE_DIR",
    },
    Opt {
        flag: "--max-body-bytes",
        env: "AP_MAX_BODY_BYTES",
    },
    Opt {
        flag: "--ca-file",
        env: "AP_CA_FILE",
    },
    Opt {
        flag: "--authority-lease-secs",
        env: "AP_AUTHORITY_LEASE_SECS",
    },
    Opt {
        flag: "--session-lease-secs",
        env: "AP_SESSION_LEASE_SECS",
    },
    Opt {
        flag: "--absolute-ttl-secs",
        env: "AP_ABSOLUTE_TTL_SECS",
    },
    Opt {
        flag: "--max-sessions",
        env: "AP_MAX_SESSIONS",
    },
];

pub fn parse(argv: impl IntoIterator<Item = String>, env: Env<'_>) -> Result<Parsed, String> {
    let mut given: Vec<Option<String>> = vec![None; OPTS.len()];
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            return Ok(Parsed::Help);
        }
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (a.clone(), None),
        };
        let i = OPTS
            .iter()
            .position(|o| o.flag == flag)
            .ok_or_else(|| format!("unknown argument {flag:?} (see --help)"))?;
        let v = match inline {
            Some(v) => v,
            None => it.next().ok_or_else(|| format!("{flag} needs a value"))?,
        };
        if given[i].replace(v).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    let get = |flag: &str| -> Option<String> {
        let i = OPTS.iter().position(|o| o.flag == flag).unwrap();
        given[i]
            .clone()
            .or_else(|| env(OPTS[i].env).filter(|v| !v.is_empty()))
    };
    let num = |flag: &str, default: u64, min: u64| -> Result<u64, String> {
        match get(flag) {
            None => Ok(default),
            Some(v) => {
                let n: u64 = v
                    .parse()
                    .map_err(|_| format!("{flag} must be a number, got {v:?}"))?;
                if n < min {
                    return Err(format!("{flag} must be at least {min}"));
                }
                Ok(n)
            }
        }
    };
    let path = |flag: &str, default: Option<&str>| -> Result<Option<PathBuf>, String> {
        match get(flag).or_else(|| default.map(String::from)) {
            None => Ok(None),
            Some(p) if p.is_empty() || p.contains('\0') => Err(format!("{flag}: bad path")),
            Some(p) => Ok(Some(PathBuf::from(p))),
        }
    };

    let policy = path("--policy", None)?.ok_or("--policy (or AP_POLICY) is required")?;
    let listen = match get("--listen") {
        None => None,
        Some(v) => Some(
            v.parse::<SocketAddr>()
                .map_err(|_| format!("--listen must be ip:port, got {v:?}"))?,
        ),
    };
    let mode = match get("--session-socket-mode") {
        None => 0o660,
        Some(v) => u32::from_str_radix(&v, 8)
            .ok()
            .filter(|m| *m <= 0o777 && m & 0o600 == 0o600)
            .ok_or("--session-socket-mode must be octal with owner read/write, e.g. 660")?,
    };
    Ok(Parsed::Run(Box::new(Args {
        policy,
        secrets_dir: path("--secrets-dir", Some("/run/secrets/auth-proxy"))?.unwrap(),
        listen,
        session_socket: path("--session-socket", Some("/run/auth-proxy/session.sock"))?.unwrap(),
        session_socket_mode: mode,
        admin_socket: path("--admin-socket", Some("/run/auth-proxy-admin/admin.sock"))?.unwrap(),
        state_dir: path("--state-dir", Some("/var/lib/auth-proxy"))?.unwrap(),
        max_body_bytes: num("--max-body-bytes", 32 * 1024 * 1024, 1)?,
        ca_file: path("--ca-file", None)?,
        authority_lease_secs: num(
            "--authority-lease-secs",
            ap_broker::DEFAULT_AUTHORITY_LEASE_SECS,
            ap_broker::MIN_AUTHORITY_LEASE_SECS,
        )?,
        session_lease_secs: num(
            "--session-lease-secs",
            ap_broker::DEFAULT_SESSION_LEASE_SECS,
            1,
        )?,
        absolute_ttl_secs: num(
            "--absolute-ttl-secs",
            ap_broker::DEFAULT_ABSOLUTE_TTL_SECS,
            1,
        )?,
        max_sessions: num("--max-sessions", ap_broker::DEFAULT_MAX_SESSIONS as u64, 1)? as usize,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str], env: &[(&str, &str)]) -> Result<Args, String> {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let lookup = move |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        match parse(args.iter().map(|s| s.to_string()), &lookup)? {
            Parsed::Run(a) => Ok(*a),
            Parsed::Help => Err("help".into()),
        }
    }

    #[test]
    fn defaults_match_the_design() {
        let a = run(&["--policy", "/p.toml"], &[]).unwrap();
        assert_eq!(a.authority_lease_secs, 90);
        assert_eq!(a.session_lease_secs, 900);
        assert_eq!(a.absolute_ttl_secs, 43_200);
        assert_eq!(a.max_body_bytes, 32 * 1024 * 1024);
        assert_eq!(a.session_socket_mode, 0o660);
        assert_eq!(a.max_sessions, 256);
        assert!(a.listen.is_none());
    }

    #[test]
    fn command_line_beats_environment() {
        let a = run(
            &["--policy", "/a", "--listen=127.0.0.1:1"],
            &[("AP_POLICY", "/b"), ("AP_LISTEN", "127.0.0.1:2")],
        )
        .unwrap();
        assert_eq!(a.policy, PathBuf::from("/a"));
        assert_eq!(a.listen.unwrap().port(), 1);
        let a = run(&[], &[("AP_POLICY", "/b")]).unwrap();
        assert_eq!(a.policy, PathBuf::from("/b"));
    }

    #[test]
    fn bad_input_is_an_error() {
        for (args, env) in [
            (vec![], vec![]),
            (vec!["--policy"], vec![]),
            (vec!["--policy", "/p", "--nope", "1"], vec![]),
            (vec!["--policy", "/p", "--policy", "/q"], vec![]),
            (vec!["--policy", "/p", "--listen", "localhost"], vec![]),
            (
                vec!["--policy", "/p", "--authority-lease-secs", "2"],
                vec![],
            ),
            (vec!["--policy", "/p", "--max-sessions", "0"], vec![]),
            (vec!["--policy", "/p", "--max-body-bytes", "x"], vec![]),
            (
                vec!["--policy", "/p", "--session-socket-mode", "999"],
                vec![],
            ),
            (
                vec!["--policy", "/p", "--session-socket-mode", "060"],
                vec![],
            ),
        ] {
            assert!(run(&args, &env).is_err(), "{args:?}");
        }
    }
}
