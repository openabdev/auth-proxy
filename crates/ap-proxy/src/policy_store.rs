//! The policy file as the pipeline sees it: loaded, validated and reloaded on change.
//!
//! The file's bytes are read on every check and compared with the bytes the snapshot was parsed
//! from. Metadata is not trusted: a rewrite that keeps the length and the mtime still changes the
//! policy. A change triggers a reload. A file that cannot be read or validated drops the snapshot,
//! and every request that needs it gets 503 until a valid file appears.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use ap_core::config::{self, Config};
use ap_core::policy::Snapshot;

/// The bytes of the policy file, or `None` when it cannot be read.
fn read_source(path: &Path) -> Option<Arc<[u8]>> {
    std::fs::read(path).ok().map(Arc::from)
}

/// A policy file that loaded and validated, with the exact bytes it was parsed from.
#[derive(Clone)]
pub(crate) struct Loaded {
    source: Arc<[u8]>,
    /// Counts loads of this store: every successful (re)load gets the next number. A held
    /// request records the generation it was admitted under.
    pub(crate) generation: u64,
    pub(crate) cfg: Arc<Config>,
    pub(crate) snap: Arc<Snapshot>,
}

pub(crate) struct PolicyStore {
    path: PathBuf,
    slot: RwLock<Option<Loaded>>,
    generation: AtomicU64,
}

impl PolicyStore {
    /// A store over `path`, seeded with `cfg`, which was read from that file at startup.
    pub(crate) fn new(path: PathBuf, cfg: Config) -> PolicyStore {
        let snap = Arc::new(Snapshot::from_config(&cfg));
        let loaded = read_source(&path).map(|source| Loaded {
            source,
            generation: 1,
            snap,
            cfg: Arc::new(cfg),
        });
        PolicyStore {
            path,
            slot: RwLock::new(loaded),
            generation: AtomicU64::new(1),
        }
    }

    /// The policy in force now. `None` means the caller answers 503.
    pub(crate) fn current(&self) -> Option<Loaded> {
        let Some(source) = read_source(&self.path) else {
            self.drop_policy();
            return None;
        };
        if let Ok(guard) = self.slot.read() {
            if let Some(l) = guard.as_ref() {
                if l.source == source {
                    return Some(l.clone());
                }
            }
        }
        let loaded = std::str::from_utf8(&source)
            .ok()
            .and_then(|text| config::load(text).ok())
            .map(|cfg| Loaded {
                source,
                generation: self.generation.fetch_add(1, Ordering::SeqCst) + 1,
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
