//! Session plane operations that sit on the registry: batch resync (all or nothing) and the
//! authority token hash on disk. The hash is written to a temporary file and renamed over the
//! target, so a reader sees either the old hash or the new one.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ap_core::session_wire::{validate_entry, Entry, ResyncResp};

use crate::clock::Clock;
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
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(sha256_hex.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
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
        let mut surrogates: HashSet<&str> = HashSet::new();
        for e in &list {
            let key = (e.session.clone(), e.generation);
            if !keys.insert(key.clone()) || !surrogates.insert(e.surrogate_sha256.as_str()) {
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
        }
        if list.len() > self.cfg.max_sessions {
            return Err(SessErr::TooMany);
        }

        // Nothing below can fail.
        let listed: HashMap<Key, String> = list
            .iter()
            .map(|e| {
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
        let registered = list.len();
        for e in list {
            let key = (e.session.clone(), e.generation);
            let absolute = match self.sessions.get(identity).and_then(|m| m.get(&key)) {
                Some(s) => s.absolute_expiry,
                None => now + self.cfg.absolute_ttl_secs,
            };
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
        })
    }
}
