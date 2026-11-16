//! File credential store (S1). A source `k8s:<secret>:<key>` resolves to `<root>/<secret>/<key>`.
//!
//! Each read stats the file and re-reads it when its mtime or size changed, so a rotated
//! Secret takes effect without a restart. A missing or unreadable file is `Unavailable`, and
//! the caller fails closed.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// A credential value. `Debug` prints `<redacted>`, and there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    /// The raw value. Only the forwarder should call this.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The store could not provide the value. It has no detail on purpose, so no path or
/// secret name reaches an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErr {
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: SystemTime,
    len: u64,
}

/// Reads credentials from files under `root`, one directory per secret.
pub struct FileStore {
    root: PathBuf,
    cache: Mutex<HashMap<PathBuf, (FileStamp, SecretBytes)>>,
}

impl FileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FileStore {
            root: root.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `source` and return the current value of its file.
    pub fn read(&self, source: &str) -> Result<SecretBytes, StoreErr> {
        let path = self.path_for(source)?;
        let meta = fs::metadata(&path).map_err(|_| StoreErr::Unavailable)?;
        if !meta.is_file() {
            return Err(StoreErr::Unavailable);
        }
        let stamp = FileStamp {
            modified: meta.modified().map_err(|_| StoreErr::Unavailable)?,
            len: meta.len(),
        };
        let mut cache = self.cache.lock().map_err(|_| StoreErr::Unavailable)?;
        if let Some((cached, value)) = cache.get(&path) {
            if *cached == stamp {
                return Ok(value.clone());
            }
        }
        let value = SecretBytes::new(fs::read(&path).map_err(|_| StoreErr::Unavailable)?);
        cache.insert(path, (stamp, value.clone()));
        Ok(value)
    }

    fn path_for(&self, source: &str) -> Result<PathBuf, StoreErr> {
        let (secret, key) = parse_source(source).ok_or(StoreErr::Unavailable)?;
        Ok(self.root.join(secret).join(key))
    }
}

/// Split `k8s:<secret>:<key>` into its two parts. Each part is `[a-z0-9-_.]`, 1 to 253 bytes,
/// and is not `.` or `..`, so no source can leave its secret directory.
pub fn parse_source(source: &str) -> Option<(&str, &str)> {
    let rest = source.strip_prefix("k8s:")?;
    let (secret, key) = rest.split_once(':')?;
    if valid_part(secret) && valid_part(key) {
        Some((secret, key))
    } else {
        None
    }
}

fn valid_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s != "."
        && s != ".."
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root =
            std::env::temp_dir().join(format!("ap-store-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(root.join("kiro")).expect("create temp root");
        root
    }

    #[test]
    fn parse_source_accepts_only_the_k8s_form() {
        assert_eq!(
            parse_source("k8s:kiro-creds:api-key"),
            Some(("kiro-creds", "api-key"))
        );
        assert_eq!(parse_source("k8s:a.b_c:d"), Some(("a.b_c", "d")));
        assert_eq!(parse_source("aws-sm:secret:key"), None);
        assert_eq!(parse_source("k8s:onlyone"), None);
        assert_eq!(parse_source("k8s:a:b:c"), None);
        assert_eq!(parse_source("k8s::key"), None);
    }

    #[test]
    fn parse_source_rejects_traversal_and_bad_characters() {
        for bad in [
            "k8s:..:key",
            "k8s:.:key",
            "k8s:kiro:..",
            "k8s:kiro:a/b",
            "k8s:Kiro:key",
            "k8s:kiro:key with space",
            "k8s:kiro:ke%2fy",
        ] {
            assert_eq!(parse_source(bad), None, "{bad}");
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = SecretBytes::new(b"test-value".to_vec());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), b"test-value");
    }

    #[test]
    fn file_store_reads_the_new_value_after_a_replace() {
        let root = tmp_root("reload");
        let file = root.join("kiro").join("api-key");
        fs::write(&file, b"old-value").unwrap();
        let store = FileStore::new(&root);
        assert_eq!(
            store.read("k8s:kiro:api-key").unwrap().expose(),
            b"old-value"
        );
        fs::write(&file, b"new-value-longer").unwrap();
        assert_eq!(
            store.read("k8s:kiro:api-key").unwrap().expose(),
            b"new-value-longer"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn file_store_is_unavailable_when_the_file_is_missing() {
        let root = tmp_root("missing");
        let file = root.join("kiro").join("api-key");
        let store = FileStore::new(&root);
        assert_eq!(store.read("k8s:kiro:api-key"), Err(StoreErr::Unavailable));
        fs::write(&file, b"v").unwrap();
        assert!(store.read("k8s:kiro:api-key").is_ok());
        fs::remove_file(&file).unwrap();
        assert_eq!(store.read("k8s:kiro:api-key"), Err(StoreErr::Unavailable));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn file_store_refuses_a_malformed_source_without_touching_disk() {
        let store = FileStore::new(std::env::temp_dir());
        assert_eq!(store.read("k8s:..:passwd"), Err(StoreErr::Unavailable));
    }
}
