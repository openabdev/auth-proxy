//! Credential values and the S1 file store.
//!
//! `Secret` is the only type in the workspace that holds a credential value.
//! It has no `Debug`, no `Display`, no `Clone` and no `Serialize`; it zeroizes
//! its bytes on drop.

use ap_core::{CredentialSource, FileStamp};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: u64 = 64 * 1024;

pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Secret {
        Secret(Zeroizing::new(bytes))
    }

    /// The raw value. Callers put it in one header and nowhere else.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Why a credential could not be read. Carries no value and no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Missing, unreadable, too large or empty.
    Unavailable(&'static str),
    /// The source kind is not resolved by this store (`env:` in Phase 1).
    Unsupported,
}

pub trait Store: Send + Sync {
    fn resolve(&self, source: &CredentialSource) -> Result<Arc<Secret>, StoreError>;
}

/// S1: reads Secret files. `k8s:<secret>:<key>` maps to
/// `<secrets_dir>/<secret>/<key>` (each Secret mounted at
/// `<secrets_dir>/<secret>`, only into the proxy container); `file:<path>` is
/// read as is. Every request stats the file and re-reads it when its mtime,
/// size or inode changed, so kubelet's atomic symlink swap is picked up with no
/// restart. A failed stat or read drops the cached value: nothing is served
/// from memory once the file is gone.
pub struct FileStore {
    secrets_dir: PathBuf,
    cache: Mutex<HashMap<PathBuf, (FileStamp, Arc<Secret>)>>,
}

impl FileStore {
    pub fn new(secrets_dir: impl Into<PathBuf>) -> FileStore {
        FileStore {
            secrets_dir: secrets_dir.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Startup check: every source in the policy is one this store resolves.
    pub fn supports(source: &CredentialSource) -> bool {
        !matches!(source, CredentialSource::Env(_))
    }

    fn path_of(&self, source: &CredentialSource) -> Result<PathBuf, StoreError> {
        match source {
            CredentialSource::K8s { secret, key } => Ok(self.secrets_dir.join(secret).join(key)),
            CredentialSource::File(p) => Ok(p.clone()),
            CredentialSource::Env(_) => Err(StoreError::Unsupported),
        }
    }
}

impl Store for FileStore {
    fn resolve(&self, source: &CredentialSource) -> Result<Arc<Secret>, StoreError> {
        let path = self.path_of(source)?;
        let mut cache = self.cache.lock().unwrap();
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => {
                cache.remove(&path);
                return Err(StoreError::Unavailable(
                    "credential file missing or unreadable",
                ));
            }
        };
        // Stat the open handle so the stamp describes the bytes we read.
        let stamp = match file.metadata() {
            Ok(md) => FileStamp::of(&md),
            Err(_) => {
                cache.remove(&path);
                return Err(StoreError::Unavailable(
                    "credential file cannot be inspected",
                ));
            }
        };
        if let Some((s, v)) = cache.get(&path) {
            if *s == stamp {
                return Ok(v.clone());
            }
        }
        let mut buf = Zeroizing::new(Vec::new());
        if (&mut file)
            .take(MAX_SECRET_BYTES + 1)
            .read_to_end(&mut buf)
            .is_err()
        {
            cache.remove(&path);
            return Err(StoreError::Unavailable("credential file unreadable"));
        }
        if buf.len() as u64 > MAX_SECRET_BYTES {
            cache.remove(&path);
            return Err(StoreError::Unavailable("credential file too large"));
        }
        // `echo value > file` leaves a newline; no credential ends in one.
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        if buf.is_empty() {
            cache.remove(&path);
            return Err(StoreError::Unavailable("credential file empty"));
        }
        let secret = Arc::new(Secret::new(std::mem::take(&mut *buf)));
        cache.insert(path, (stamp, secret.clone()));
        Ok(secret)
    }
}
