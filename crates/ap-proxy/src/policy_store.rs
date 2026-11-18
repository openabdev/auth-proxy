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
    /// A store over `path`, seeded with `cfg`, which was parsed from `text`, the bytes read from
    /// that file at startup. The snapshot's source is `text`, not a fresh read of the file, so
    /// the policy in force always matches the bytes it came from.
    pub(crate) fn new(path: PathBuf, cfg: Config, text: &str) -> PolicyStore {
        let snap = Arc::new(Snapshot::from_config(&cfg));
        let loaded = Loaded {
            source: Arc::from(text.as_bytes()),
            generation: 1,
            snap,
            cfg: Arc::new(cfg),
        };
        PolicyStore {
            path,
            slot: RwLock::new(Some(loaded)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::config::load;
    use ap_core::error::Code;

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// A valid policy whose only grant lets `muse` GET under `paths`.
    fn policy(paths: &str) -> String {
        format!(
            "version = 1\n[listen]\nproxy = \"127.0.0.1:8443\"\n[passthrough]\npublic_authority = \"gate.example.test\"\n[[identity]]\nname = \"muse\"\ncaller_key_sha256 = \"{KEY}\"\n[[route]]\nname = \"discord\"\nhost = \"discord.com\"\nmode = \"passthrough\"\n[[grant]]\nidentity = \"muse\"\nroute = \"discord\"\nmethods = [\"GET\"]\npaths = [\"{paths}\"]\n"
        )
    }

    #[test]
    fn startup_policy_is_not_replaced_by_a_file_changed_before_the_store_is_built() {
        let text_a = policy("/api/v10/channels/");
        let cfg_a = load(&text_a).expect("policy A is valid");
        let path = std::env::temp_dir().join(format!(
            "ap-policy-store-startup-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, &text_a).expect("write policy A");
        // The grant is revoked between the startup parse and the store's construction.
        std::fs::write(&path, policy("/api/v10/other/")).expect("write policy B");
        let store = PolicyStore::new(path.clone(), cfg_a, &text_a);
        let loaded = store.current();
        let _ = std::fs::remove_file(&path);
        let got = loaded.map(|l| {
            l.snap
                .evaluate_verdict("muse", "discord", "GET", "/api/v10/channels/1/messages")
        });
        assert_eq!(got, Some(Err(Code::PolicyDenied)));
    }
}
