//! The policy file as the pipeline sees it: loaded, validated and reloaded on change.
//!
//! The file's stamp (mtime and size) is checked on every read. A change triggers a reload. A file
//! that cannot be read or validated drops the snapshot, and every request that needs it gets 503
//! until a valid file appears.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use ap_core::config::{self, Config};
use ap_core::policy::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: SystemTime,
    len: u64,
}

fn stamp_of(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    Some(Stamp {
        modified: meta.modified().ok()?,
        len: meta.len(),
    })
}

/// A policy file that loaded and validated, with the stamp it was read under.
#[derive(Clone)]
pub(crate) struct Loaded {
    stamp: Stamp,
    pub(crate) cfg: Arc<Config>,
    pub(crate) snap: Arc<Snapshot>,
}

pub(crate) struct PolicyStore {
    path: PathBuf,
    slot: RwLock<Option<Loaded>>,
}

impl PolicyStore {
    /// A store over `path`, seeded with `cfg`, which was read from that file at startup.
    pub(crate) fn new(path: PathBuf, cfg: Config) -> PolicyStore {
        let snap = Arc::new(Snapshot::from_config(&cfg));
        let loaded = stamp_of(&path).map(|stamp| Loaded {
            stamp,
            snap,
            cfg: Arc::new(cfg),
        });
        PolicyStore {
            path,
            slot: RwLock::new(loaded),
        }
    }

    /// The policy in force now. `None` means the caller answers 503.
    pub(crate) fn current(&self) -> Option<Loaded> {
        let Some(stamp) = stamp_of(&self.path) else {
            self.drop_policy();
            return None;
        };
        if let Ok(guard) = self.slot.read() {
            if let Some(l) = guard.as_ref() {
                if l.stamp == stamp {
                    return Some(l.clone());
                }
            }
        }
        let loaded = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| config::load(&text).ok())
            .map(|cfg| Loaded {
                stamp,
                snap: Arc::new(Snapshot::from_config(&cfg)),
                cfg: Arc::new(cfg),
            });
        match self.slot.write() {
            Ok(mut slot) => *slot = loaded.clone(),
            Err(_) => return None,
        }
        loaded
    }

    fn drop_policy(&self) {
        if let Ok(mut slot) = self.slot.write() {
            *slot = None;
        }
    }
}
