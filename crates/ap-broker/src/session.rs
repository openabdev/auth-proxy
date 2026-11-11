//! Session plane operations that sit on the registry: batch resync (all or nothing) and the
//! authority token hash on disk. The hash is written to a temporary file and renamed over the
//! target, so a reader sees either the old hash or the new one.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ap_core::session_wire::{validate_entry, Entry, ResyncResp, SessionRef};

use crate::clock::Clock;
use crate::expiry::record_key;
use crate::registry::{sha256_hex, Key, Registry, SessErr};

/// Path of one identity's hash file under `dir`. The file name is the sha256 of the identity
/// name, so any identity name is safe as a file name.
pub fn token_file(dir: &Path, identity: &str) -> PathBuf {
    dir.join(format!("{}.sha256", sha256_hex(identity)))
}

/// Replace `path` with `sha256_hex` atomically: write a sibling temp file, fsync it, rename.
pub fn write_token_hash(path: &Path, sha256_hex: &str) -> io::Result<()> {
    let mut tmp: OsString = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // A leftover temp file keeps its old mode when reopened, so remove it before creating.
    let _ = fs::remove_file(&tmp);
    {
        let mut f = create_private(&tmp)?;
        f.write_all(sha256_hex.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Create a new file for writing that only the owner can read. On Unix the mode is 0600.
pub(crate) fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Read the stored hash text. The caller checks that it is 64 lowercase hex digits.
pub fn read_token_hash(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
}

impl<C: Clock> Registry<C> {
    /// Replace the identity's whole session set with `list`.
    ///
    /// Every check runs before any change: wire validation of each entry, grants, duplicate
    /// keys or surrogates in the list, surrogates bound to another session or revoked, and the
    /// size limit. Any failure returns an error and leaves the registry as it was.
    ///
    /// On success, sessions not listed with the same surrogate are revoked and their surrogates
    /// tombstoned. `dropped` counts those. Listed sessions get a fresh lease. An existing
    /// session keeps its absolute expiry; a new one gets `absolute_ttl_secs` from now.
    ///
    /// A listed surrogate that was revoked (for example by a DELETE racing this resync) makes
    /// the whole batch fail with `Conflict`. The authority must rebuild its list without that
    /// surrogate and resend.
    ///
    /// A listed session whose stored absolute expiry has passed is skipped, not an error: it is
    /// not registered, and the rest of the batch still applies.
    pub fn resync(
        &mut self,
        identity: &str,
        token: &str,
        list: Vec<Entry>,
        now: u64,
    ) -> Result<ResyncResp, SessErr> {
        self.check_token(identity, token, now)?;
        for e in &list {
            validate_entry(e).map_err(SessErr::Invalid)?;
            self.check_grants(identity, &e.credentials)?;
        }
        let mut keys: HashSet<Key> = HashSet::new();
        let mut surrogates: HashSet<String> = HashSet::new();
        let mut plan: Vec<(Entry, u64)> = Vec::with_capacity(list.len());
        let mut pending: Vec<(String, u64)> = Vec::new();
        let mut expired: Vec<SessionRef> = Vec::new();
        for e in list {
            let key = (e.session.clone(), e.generation);
            if !keys.insert(key.clone()) || !surrogates.insert(e.surrogate_sha256.clone()) {
                return Err(SessErr::Conflict);
            }
            match self.index.get(&e.surrogate_sha256) {
                Some((owner, k)) if owner == identity && *k == key => {}
                Some(_) => return Err(SessErr::Conflict),
                None => {}
            }
            if self.revoked.contains(&e.surrogate_sha256) {
                return Err(SessErr::Conflict);
            }
            // Same rule as register: a live session cannot change its credential set.
            if let Some(s) = self.sessions.get(identity).and_then(|m| m.get(&key)) {
                if s.credentials != e.credentials {
                    return Err(SessErr::Conflict);
                }
            }
            // A session key keeps the absolute expiry stored when it was first recorded. A key
            // the store has never seen gets a new one, persisted before anything changes.
            let absolute = match self.stored_expiry(identity, &key, now) {
                Ok(Some(absolute)) => absolute,
                Ok(None) => {
                    let absolute = now + self.cfg.absolute_ttl_secs;
                    pending.push((record_key(identity, &key.0, key.1), absolute));
                    absolute
                }
                // Past its stored absolute expiry: leave it out of the batch. The key stays
                // unbound, so its surrogate is refused as unknown, and the rest still applies.
                Err(SessErr::AbsoluteExpired) => {
                    expired.push(SessionRef {
                        session: e.session.clone(),
                        generation: e.generation,
                    });
                    continue;
                }
                Err(e) => return Err(e),
            };
            plan.push((e, absolute));
        }
        if plan.len() > self.cfg.max_sessions {
            return Err(SessErr::TooMany);
        }
        self.persist(&pending)?;

        // Nothing below can fail.
        let listed: HashMap<Key, String> = plan
            .iter()
            .map(|(e, _)| {
                (
                    (e.session.clone(), e.generation),
                    e.surrogate_sha256.clone(),
                )
            })
            .collect();
        let existing: Vec<(Key, String)> = self
            .sessions
            .get(identity)
            .map(|m| {
                m.iter()
                    .map(|(k, s)| (k.clone(), s.surrogate.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut dropped = 0;
        for (key, surrogate) in existing {
            if listed.get(&key) != Some(&surrogate) {
                self.revoke_key(identity, &key);
                dropped += 1;
            }
        }
        self.touch(identity, now);
        let registered = plan.len();
        for (e, absolute) in plan {
            let key = (e.session.clone(), e.generation);
            self.put(
                identity,
                key,
                e.surrogate_sha256,
                e.credentials,
                absolute,
                now,
            );
        }
        Ok(ResyncResp {
            registered,
            dropped,
            expired,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::expiry::MemoryExpiry;
    use crate::registry::test_support::{
        access, cfg, entry, new_reg, sha, snapshot, tmp_dir, IDENT, T0,
    };
    use crate::registry::{Deny, Registry, SessErr};
    use ap_core::session_wire::{Entry, WireErr};

    fn hello(r: &mut Registry<ManualClock>, id: &str, now: u64) -> String {
        r.hello(id, now).expect("hello")
    }

    #[test]
    fn resync_with_invalid_entry_applies_nothing() {
        let clock = ManualClock::new(T0);
        let mut r = new_reg(&clock);
        let tok = hello(&mut r, IDENT, T0);
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0).unwrap();
        let before = snapshot(&r);
        let mut bad = entry("s9", 1, "z");
        bad.surrogate_sha256 = "not-hex".into();
        let list = vec![entry("s2", 1, "b"), bad];
        assert_eq!(
            r.resync(IDENT, &tok, list, T0),
            Err(SessErr::Invalid(WireErr {
                field: "surrogate_sha256"
            }))
        );
        assert_eq!(snapshot(&r), before);
        assert!(r.authorize(&sha("a"), IDENT, "kiro-api", T0).is_ok());
    }

    #[test]
    fn resync_invalid_entry_after_conflicting_entry_still_returns_invalid() {
        let clock = ManualClock::new(T0);
        let mut r = new_reg(&clock);
        let tok = hello(&mut r, IDENT, T0);
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0).unwrap();
        let before = snapshot(&r);
        let mut bad = entry("s9", 1, "z");
        bad.surrogate_sha256 = "not-hex".into();
        // The duplicate key is a conflict, but the malformed entry after it must win.
        let list = vec![entry("s2", 1, "b"), entry("s2", 1, "c"), bad];
        assert_eq!(
            r.resync(IDENT, &tok, list, T0),
            Err(SessErr::Invalid(WireErr {
                field: "surrogate_sha256"
            }))
        );
        assert_eq!(snapshot(&r), before);
    }

    #[test]
    fn resync_with_changed_credentials_on_live_session_is_conflict() {
        let clock = ManualClock::new(T0);
        let mut a = access();
        a.grants
            .get_mut(IDENT)
            .unwrap()
            .insert("kiro-2".to_string());
        let mut r = Registry::new(
            clock.clone(),
            cfg(),
            a,
            None,
            Box::new(MemoryExpiry::default()),
        )
        .expect("registry");
        let tok = hello(&mut r, IDENT, T0);
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0).unwrap();
        let before = snapshot(&r);
        let mut changed = entry("s1", 1, "a");
        changed.credentials = vec!["kiro".into(), "kiro-2".into()];
        assert_eq!(
            r.resync(IDENT, &tok, vec![changed], T0),
            Err(SessErr::Conflict)
        );
        assert_eq!(snapshot(&r), before);
    }

    #[test]
    fn resync_with_duplicate_key_or_ungranted_credential_applies_nothing() {
        let clock = ManualClock::new(T0);
        let mut r = new_reg(&clock);
        let tok = hello(&mut r, IDENT, T0);
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0).unwrap();
        let before = snapshot(&r);
        let dup = vec![entry("s2", 1, "b"), entry("s2", 1, "c")];
        assert_eq!(r.resync(IDENT, &tok, dup, T0), Err(SessErr::Conflict));
        let mut ungranted = entry("s3", 1, "d");
        ungranted.credentials = vec!["other-cred".into()];
        assert_eq!(
            r.resync(IDENT, &tok, vec![ungranted], T0),
            Err(SessErr::CredentialNotGranted)
        );
        assert_eq!(snapshot(&r), before);
    }

    #[test]
    fn resync_drops_unlisted_sessions_and_revokes_their_surrogates() {
        let clock = ManualClock::new(T0);
        let mut r = new_reg(&clock);
        let tok = hello(&mut r, IDENT, T0);
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0).unwrap();
        r.register(IDENT, &tok, entry("s2", 1, "b"), T0).unwrap();
        let resp = r
            .resync(IDENT, &tok, vec![entry("s1", 1, "a")], T0)
            .unwrap();
        assert_eq!(
            resp,
            ap_core::session_wire::ResyncResp {
                registered: 1,
                dropped: 1,
                expired: vec![],
            }
        );
        assert_eq!(
            r.authorize(&sha("b"), IDENT, "kiro-api", T0),
            Err(Deny::Revoked)
        );
        assert!(r.authorize(&sha("a"), IDENT, "kiro-api", T0).is_ok());
    }

    #[test]
    fn resync_keeps_listed_session_with_same_surrogate() {
        let clock = ManualClock::new(T0);
        let mut r = new_reg(&clock);
        let tok = hello(&mut r, IDENT, T0);
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0).unwrap();
        let list: Vec<Entry> = vec![entry("s1", 1, "a"), entry("s2", 1, "b")];
        let resp = r.resync(IDENT, &tok, list, T0 + 10).unwrap();
        assert_eq!(resp.dropped, 0);
        assert_eq!(resp.registered, 2);
    }

    #[test]
    fn resync_requires_a_valid_token() {
        let clock = ManualClock::new(T0);
        let mut r = new_reg(&clock);
        hello(&mut r, IDENT, T0);
        assert_eq!(
            r.resync(IDENT, "apt_wrong", vec![entry("s1", 1, "a")], T0),
            Err(SessErr::Unauthorized)
        );
    }

    #[test]
    fn token_file_holds_only_the_hash() {
        let clock = ManualClock::new(T0);
        let dir = tmp_dir("hash-only");
        let mut r = Registry::new(
            clock.clone(),
            cfg(),
            access(),
            Some(dir.clone()),
            Box::new(MemoryExpiry::default()),
        )
        .expect("registry");
        let tok = hello(&mut r, IDENT, T0);
        let text = std::fs::read_to_string(token_file(&dir, IDENT)).unwrap();
        assert_eq!(text, sha256_hex(&tok));
        assert!(!text.contains(&tok));
        assert!(!text.contains("apt_"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let clock = ManualClock::new(T0);
        let dir = tmp_dir("mode");
        let mut r = Registry::new(
            clock.clone(),
            cfg(),
            access(),
            Some(dir.clone()),
            Box::new(MemoryExpiry::default()),
        )
        .expect("registry");
        hello(&mut r, IDENT, T0);
        let mode = std::fs::metadata(token_file(&dir, IDENT))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_hash_reload_keeps_authority_valid() {
        let clock = ManualClock::new(T0);
        let dir = tmp_dir("reload");
        let mut first = Registry::new(
            clock.clone(),
            cfg(),
            access(),
            Some(dir.clone()),
            Box::new(crate::expiry::FileExpiryStore::new(crate::expiry::file_in(
                &dir,
            ))),
        )
        .expect("registry");
        let tok = hello(&mut first, IDENT, T0);
        drop(first);
        clock.set(T0 + 10);
        let mut second = Registry::new(
            clock.clone(),
            cfg(),
            access(),
            Some(dir.clone()),
            Box::new(crate::expiry::FileExpiryStore::new(crate::expiry::file_in(
                &dir,
            ))),
        )
        .expect("registry");
        assert!(second.renew(IDENT, &tok, &[], clock.now()).is_ok());
        assert!(matches!(
            second.hello(IDENT, clock.now()),
            Err(crate::registry::HelloErr::AuthorityActive { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
