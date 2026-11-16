//! Compiled policy snapshot, grant evaluation and the reloading store.

use crate::code::Code;
use crate::config::{Config, ConfigError, CredentialCfg, RouteCfg, MAX_CONFIG_BYTES};
use crate::stamp::FileStamp;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

/// An immutable, fully validated snapshot of one identity's policy file.
#[derive(Debug)]
pub struct Policy {
    cfg: Config,
    caller_sha256: [u8; 32],
}

impl Policy {
    pub fn parse(raw: &[u8]) -> Result<Policy, ConfigError> {
        Policy::from_config(Config::parse(raw)?)
    }

    /// Re-validates, so a `Policy` always comes from a valid `Config`.
    pub fn from_config(cfg: Config) -> Result<Policy, ConfigError> {
        cfg.validate()?;
        let mut caller_sha256 = [0u8; 32];
        // validate() guarantees 64 lowercase hex characters.
        hex::decode_to_slice(&cfg.caller_key_sha256, &mut caller_sha256)
            .map_err(|e| ConfigError(vec![format!("caller_key_sha256: {e}")]))?;
        Ok(Policy { cfg, caller_sha256 })
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn identity(&self) -> &str {
        &self.cfg.identity
    }

    pub fn route(&self, name: &str) -> Option<&RouteCfg> {
        self.cfg.route(name)
    }

    pub fn credential(&self, id: &str) -> Option<&CredentialCfg> {
        self.cfg.credential(id)
    }

    /// Constant-time check of a presented caller key against the stored hash.
    pub fn caller_matches(&self, key: &str) -> bool {
        let h: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        bool::from(h.ct_eq(&self.caller_sha256))
    }

    /// No grant at all: nothing is allowed.
    pub fn has_no_grants(&self) -> bool {
        self.cfg.grants.is_empty()
    }

    /// Evaluate grants for a request whose surrogate is bound to
    /// `session_credentials`. `path` is the route-relative path (no query,
    /// already checked for ambiguity). `aws_targets` holds the value of every
    /// `X-Amz-Target` header the request carried.
    ///
    /// Returns the id of the credential whose grant allows the request.
    pub fn authorize(
        &self,
        session_credentials: &[String],
        route: &str,
        method: &str,
        path: &str,
        aws_targets: &[&[u8]],
    ) -> Result<&str, Code> {
        if self.cfg.grants.is_empty() {
            return Err(Code::PolicyEmpty);
        }
        self.cfg
            .grants
            .iter()
            .find(|g| {
                g.route == route
                    && session_credentials.contains(&g.credential)
                    && g.methods.iter().any(|m| m == method)
                    && g.paths.iter().any(|p| path.starts_with(p.as_str()))
                    && aws_target_ok(&g.aws_targets, aws_targets)
            })
            .map(|g| g.credential.as_str())
            .ok_or(Code::PolicyDenied)
    }
}

/// The `aws_targets` matcher. An empty list is no constraint. Otherwise the
/// request must carry exactly one `X-Amz-Target` value, equal to an entry:
/// zero headers and two headers (even two equal ones) both deny.
pub fn aws_target_ok(allowed: &[String], presented: &[&[u8]]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    match presented {
        [one] => allowed.iter().any(|a| a.as_bytes() == *one),
        _ => false,
    }
}

struct State {
    good: Option<(FileStamp, Arc<Policy>)>,
    /// A file that failed to parse or validate, keyed by its stamp, so an
    /// unchanged bad file is not re-parsed per request. I/O errors are never
    /// cached: the next request tries again.
    bad: Option<FileStamp>,
    last_error: Option<String>,
}

/// Re-reads the policy file when its mtime, size or inode changes. Any stat,
/// read, parse or validation failure makes the policy unavailable, which
/// refuses every request: a good snapshot is never kept after the file has gone
/// bad. Readers get an `Arc` to one immutable snapshot, so a swap is atomic.
pub struct PolicyStore {
    path: PathBuf,
    state: Mutex<State>,
}

impl PolicyStore {
    pub fn new(path: impl Into<PathBuf>) -> PolicyStore {
        PolicyStore {
            path: path.into(),
            state: Mutex::new(State {
                good: None,
                bad: None,
                last_error: None,
            }),
        }
    }

    /// Startup form: load now, and fail with the validation error (exit code 2).
    pub fn open(path: impl Into<PathBuf>) -> Result<PolicyStore, String> {
        let s = PolicyStore::new(path);
        s.refresh()?;
        Ok(s)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The snapshot for this request, or `policy_unavailable`.
    pub fn current(&self) -> Result<Arc<Policy>, Code> {
        self.refresh().map_err(|_| Code::PolicyUnavailable)
    }

    /// Why the policy is unavailable, for the operator's log (never contains a
    /// secret: the file holds hashes and references only).
    pub fn last_error(&self) -> Option<String> {
        self.state.lock().unwrap().last_error.clone()
    }

    fn refresh(&self) -> Result<Arc<Policy>, String> {
        let mut st = self.state.lock().unwrap();
        let outcome = self.refresh_locked(&mut st);
        st.last_error = outcome.as_ref().err().cloned();
        outcome
    }

    fn refresh_locked(&self, st: &mut State) -> Result<Arc<Policy>, String> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                st.good = None;
                st.bad = None;
                return Err(format!("open policy: {e}"));
            }
        };
        // Stat the open handle so the stamp describes the bytes we read.
        let stamp = match file.metadata() {
            Ok(md) => FileStamp::of(&md),
            Err(e) => {
                st.good = None;
                st.bad = None;
                return Err(format!("stat policy: {e}"));
            }
        };
        if let Some((s, p)) = &st.good {
            if *s == stamp {
                return Ok(p.clone());
            }
        }
        if st.bad == Some(stamp) {
            st.good = None;
            return Err(st
                .last_error
                .clone()
                .unwrap_or_else(|| "policy invalid".into()));
        }
        let mut raw = Vec::new();
        if let Err(e) = (&mut file)
            .take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut raw)
        {
            st.good = None;
            st.bad = None;
            return Err(format!("read policy: {e}"));
        }
        match Policy::parse(&raw) {
            Ok(p) => {
                let p = Arc::new(p);
                st.good = Some((stamp, p.clone()));
                st.bad = None;
                Ok(p)
            }
            Err(e) => {
                st.good = None;
                st.bad = Some(stamp);
                Err(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{sample_toml, SAMPLE_CALLER_KEY};
    use std::fs;
    use std::time::{Duration, SystemTime};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ap-core-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write and force a distinct mtime so the test does not depend on clock
    /// granularity.
    fn write(path: &Path, content: &str, n: u64) {
        fs::write(path, content).unwrap();
        let f = fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + n))
            .unwrap();
    }

    /// Replace the file in one rename, as kubelet does, so a reader never sees
    /// a half-written file.
    fn write_atomic(path: &Path, content: &str, n: u64) {
        let tmp = path.with_extension("tmp");
        write(&tmp, content, n);
        fs::rename(&tmp, path).unwrap();
    }

    fn sample() -> Policy {
        Policy::parse(sample_toml().as_bytes()).unwrap()
    }

    #[test]
    fn caller_key_constant_time_compare_semantics() {
        let p = sample();
        assert!(p.caller_matches(SAMPLE_CALLER_KEY));
        assert!(!p.caller_matches("apk_x"));
        assert!(!p.caller_matches(""));
        assert!(!p.caller_matches(&SAMPLE_CALLER_KEY.to_uppercase()));
    }

    #[test]
    fn aws_targets_matcher() {
        let allowed = vec!["Svc.A".to_string(), "Svc.B".to_string()];
        assert!(aws_target_ok(&allowed, &[b"Svc.A"]));
        assert!(aws_target_ok(&allowed, &[b"Svc.B"]));
        assert!(!aws_target_ok(&allowed, &[b"Svc.C"]));
        assert!(!aws_target_ok(&allowed, &[]), "zero headers deny");
        assert!(
            !aws_target_ok(&allowed, &[b"Svc.A", b"Svc.A"]),
            "two headers deny"
        );
        assert!(!aws_target_ok(&allowed, &[b"Svc.A", b"Svc.C"]));
        assert!(!aws_target_ok(&allowed, &[b"Svc.A, Svc.B"]));
        assert!(
            !aws_target_ok(&allowed, &[b"svc.a"]),
            "exact, case-sensitive"
        );
        assert!(aws_target_ok(&[], &[]), "no constraint without aws_targets");
        assert!(aws_target_ok(&[], &[b"x", b"y"]));
    }

    #[test]
    fn authorize_decisions() {
        let p = sample();
        let kiro = vec!["kiro".to_string()];
        let target: &[&[u8]] = &[b"AmazonCodeWhispererStreamingService.GenerateAssistantResponse"];
        assert_eq!(
            p.authorize(&kiro, "kiro-krs", "POST", "/", target),
            Ok("kiro")
        );
        // wrong target, none, two
        assert_eq!(
            p.authorize(&kiro, "kiro-krs", "POST", "/", &[b"Other.Op"]),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            p.authorize(&kiro, "kiro-krs", "POST", "/", &[]),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            p.authorize(&kiro, "kiro-krs", "POST", "/", &[target[0], target[0]]),
            Err(Code::PolicyDenied)
        );
        // wrong method, other route without grant, session without the credential
        assert_eq!(
            p.authorize(&kiro, "kiro-krs", "GET", "/", target),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            p.authorize(&kiro, "kiro-q", "POST", "/", target),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            p.authorize(&[], "kiro-krs", "POST", "/", target),
            Err(Code::PolicyDenied)
        );
        // prefix grant on the anthropic route
        let ant = vec!["anthropic".to_string()];
        assert_eq!(
            p.authorize(&ant, "anthropic", "POST", "/v1/messages", &[]),
            Ok("anthropic")
        );
        assert_eq!(
            p.authorize(&ant, "anthropic", "POST", "/v1/", &[]),
            Ok("anthropic")
        );
        assert_eq!(
            p.authorize(&ant, "anthropic", "POST", "/v1", &[]),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            p.authorize(&ant, "anthropic", "POST", "/v2/x", &[]),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            p.authorize(&ant, "anthropic", "DELETE", "/v1/messages", &[]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn empty_policy_denies_with_policy_empty() {
        let p = Policy::parse(
            format!(
                "version = 1\nidentity = \"x\"\ncaller_key_sha256 = \"{}\"\n",
                crate::testing::SAMPLE_CALLER_SHA256
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(p.has_no_grants());
        assert_eq!(
            p.authorize(&["kiro".into()], "kiro-krs", "POST", "/", &[]),
            Err(Code::PolicyEmpty)
        );
    }

    // ---- R1 cases (ported from the spike matrix) ----

    #[test]
    fn store_r1_zero_bytes_corrupt_deleted_other_path_and_recovery() {
        let d = tmpdir("r1");
        let f = d.join("policy.toml");
        let good = sample_toml();

        write(&f, &good, 1);
        let store = PolicyStore::open(&f).unwrap();
        assert_eq!(store.current().unwrap().identity(), "pty-team-a");

        // 0 bytes
        write(&f, "", 2);
        assert_eq!(store.current().unwrap_err(), Code::PolicyUnavailable);
        assert!(store.last_error().is_some());
        // unchanged bad file stays unavailable (and is not re-parsed into good)
        assert_eq!(store.current().unwrap_err(), Code::PolicyUnavailable);

        // recovery on restore
        write(&f, &good, 3);
        assert!(store.current().is_ok());
        assert!(store.last_error().is_none());

        // corrupt
        write(&f, "this is = = not toml [[", 4);
        assert_eq!(store.current().unwrap_err(), Code::PolicyUnavailable);
        // valid TOML, failed validation (route name upper-case)
        write(
            &f,
            &good.replace("name = \"anthropic\"", "name = \"Anthropic\""),
            5,
        );
        assert_eq!(store.current().unwrap_err(), Code::PolicyUnavailable);
        write(&f, &good, 6);
        assert!(store.current().is_ok());

        // deleted after a good load: never serve the stale snapshot
        fs::remove_file(&f).unwrap();
        assert_eq!(store.current().unwrap_err(), Code::PolicyUnavailable);
        write(&f, &good, 7);
        assert!(store.current().is_ok());

        // grants for another path or method only: valid, but denies
        let other = good.replace(
            "methods = [\"POST\"]\npaths = [\"/v1/\"]",
            "methods = [\"GET\"]\npaths = [\"/models/\"]",
        );
        assert_ne!(other, good);
        write(&f, &other, 8);
        let p = store.current().unwrap();
        assert_eq!(
            p.authorize(
                &["anthropic".into()],
                "anthropic",
                "POST",
                "/v1/messages",
                &[]
            ),
            Err(Code::PolicyDenied)
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn store_open_fails_on_bad_file_and_missing_file() {
        let d = tmpdir("open");
        let f = d.join("policy.toml");
        assert!(PolicyStore::open(&f).is_err(), "missing");
        write(&f, "", 1);
        assert!(PolicyStore::open(&f).is_err(), "0 bytes");
        write(&f, "version = 2\n", 2);
        assert!(PolicyStore::open(&f).is_err(), "bad");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn store_detects_atomic_symlink_swap_with_same_size_and_mtime() {
        // ConfigMap layout: policy.toml -> ..data/policy.toml, ..data -> ..vN
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let d = tmpdir("swap");
            let a = sample_toml();
            let b = sample_toml().replace("pty-team-a", "pty-team-b");
            assert_eq!(a.len(), b.len());
            fs::create_dir(d.join("..v1")).unwrap();
            fs::create_dir(d.join("..v2")).unwrap();
            write(&d.join("..v1/policy.toml"), &a, 1);
            write(&d.join("..v2/policy.toml"), &b, 1);
            symlink("..v1", d.join("..data")).unwrap();
            symlink("..data/policy.toml", d.join("policy.toml")).unwrap();
            let store = PolicyStore::open(d.join("policy.toml")).unwrap();
            assert_eq!(store.current().unwrap().identity(), "pty-team-a");
            symlink("..v2", d.join("..data_tmp")).unwrap();
            fs::rename(d.join("..data_tmp"), d.join("..data")).unwrap();
            assert_eq!(store.current().unwrap().identity(), "pty-team-b");
            let _ = fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn no_half_applied_swap_under_concurrent_requests() {
        let d = tmpdir("conc");
        let f = d.join("policy.toml");
        let a = sample_toml();
        let b = sample_toml().replace("pty-team-a", "pty-team-b");
        write_atomic(&f, &a, 1);
        let store = Arc::new(PolicyStore::open(&f).unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let (s, stop) = (store.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut seen = 0u32;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        match s.current() {
                            Ok(p) => {
                                // a snapshot is internally consistent: identity and grants
                                // always come from the same file
                                assert!(["pty-team-a", "pty-team-b"].contains(&p.identity()));
                                assert_eq!(p.config().grants.len(), 3);
                                assert!(p.caller_matches(SAMPLE_CALLER_KEY));
                            }
                            Err(c) => assert_eq!(c, Code::PolicyUnavailable),
                        }
                        seen += 1;
                    }
                    seen
                })
            })
            .collect();
        for i in 0..60u64 {
            if i % 7 == 6 {
                write_atomic(&f, "", 10 + i);
            } else {
                write_atomic(&f, if i % 2 == 0 { &a } else { &b }, 10 + i);
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for r in readers {
            assert!(r.join().unwrap() > 0);
        }
        let _ = fs::remove_dir_all(&d);
    }
}
