//! Persisted absolute expiry per session key (FEAT-002 F3, owner option C).
//!
//! A session's absolute TTL starts when the proxy first records the session key. The record
//! maps `record_key(identity, session, generation)` to the absolute expiry in Unix seconds, and
//! it is written before the session is accepted. After a proxy restart, `register` and `resync`
//! read the stored value, so a restart cannot extend a session's absolute TTL.
//!
//! The store holds key hashes and expiry times only. It never holds a surrogate or a caller
//! key.
//!
//! Records are never removed. Removing one would let a later resync of the same session key
//! start a new absolute TTL, which is the extension this store prevents. The file grows by one
//! line per session key ever registered.
//!
//! File format: a header line, then one `<record key hex> <expiry seconds>` line per record,
//! sorted by key. Any other content is corrupt, and the store refuses to load it.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ap_core::canon::is_lower_hex_64;
use sha2::{Digest, Sha256};

use crate::registry::hex;
use crate::session::create_private;

/// File name under the proxy-private token directory.
pub const FILE_NAME: &str = "session-expiry.v1";

const HEADER: &str = "auth-proxy session expiry v1";

/// Where the absolute expiry records are kept. The registry holds one of these behind a trait,
/// so the location can change without touching the session logic.
pub trait ExpiryStore: Send {
    /// Every stored record. A store with no file yet has no records. Any other read failure,
    /// or content that is not a valid store, is an error.
    fn load(&self) -> io::Result<HashMap<String, u64>>;

    /// Replace every stored record with `records`. On error the stored records are unchanged.
    fn save(&mut self, records: &HashMap<String, u64>) -> io::Result<()>;
}

/// Key of one session in the store: sha256 over the identity, session and generation.
pub fn record_key(identity: &str, session: &str, generation: u64) -> String {
    let mut h = Sha256::new();
    h.update(identity.as_bytes());
    h.update([0u8]);
    h.update(session.as_bytes());
    h.update([0u8]);
    h.update(generation.to_be_bytes());
    hex(&h.finalize())
}

/// The store file inside the proxy-private token directory.
pub fn file_in(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// Expiry records kept in one file, written atomically.
pub struct FileExpiryStore {
    path: PathBuf,
}

impl FileExpiryStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileExpiryStore { path: path.into() }
    }
}

impl ExpiryStore for FileExpiryStore {
    fn load(&self) -> io::Result<HashMap<String, u64>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e),
        };
        parse(&text)
    }

    fn save(&mut self, records: &HashMap<String, u64>) -> io::Result<()> {
        write_atomic(&self.path, render(records).as_bytes())
    }
}

fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "session expiry store is corrupt",
    )
}

fn render(records: &HashMap<String, u64>) -> String {
    let mut lines: Vec<(&String, &u64)> = records.iter().collect();
    lines.sort();
    let mut out = String::from(HEADER);
    out.push('\n');
    for (key, expiry) in lines {
        let _ = writeln!(out, "{key} {expiry}");
    }
    out
}

fn parse(text: &str) -> io::Result<HashMap<String, u64>> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(corrupt());
    }
    let mut out = HashMap::new();
    for line in lines {
        let (key, value) = line.split_once(' ').ok_or_else(corrupt)?;
        if !is_lower_hex_64(key) || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(corrupt());
        }
        let expiry: u64 = value.parse().map_err(|_| corrupt())?;
        if out.insert(key.to_string(), expiry).is_some() {
            return Err(corrupt());
        }
    }
    Ok(out)
}

/// Replace `path` with `bytes`: write a sibling temp file, fsync it, rename it over `path`,
/// then fsync the directory so the rename is durable.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_with(path, bytes, |from, to| fs::rename(from, to))
}

/// `write_atomic` with the rename step injected, so a test can make it fail.
fn write_atomic_with(
    path: &Path,
    bytes: &[u8],
    rename: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let tmp = tmp_path(path);
    // A leftover temp file from a crash would keep its old contents and mode.
    let _ = fs::remove_file(&tmp);
    if let Err(e) = write_and_sync(&tmp, bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = rename(tmp.as_path(), path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::File::open(dir)?.sync_all()
}

fn write_and_sync(tmp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = create_private(tmp)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp: OsString = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// In-memory store for tests that do not need a file.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryExpiry {
    records: HashMap<String, u64>,
}

#[cfg(test)]
impl ExpiryStore for MemoryExpiry {
    fn load(&self) -> io::Result<HashMap<String, u64>> {
        Ok(self.records.clone())
    }

    fn save(&mut self, records: &HashMap<String, u64>) -> io::Result<()> {
        self.records = records.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, ManualClock};
    use crate::registry::test_support::{access, cfg, entry, sha, tmp_dir, IDENT, T0};
    use crate::registry::{Deny, Registry, SessErr};
    use ap_core::session_wire::SessionRef;

    fn open(
        clock: &ManualClock,
        token_dir: &Path,
        path: &Path,
    ) -> io::Result<Registry<ManualClock>> {
        Registry::new(
            clock.clone(),
            cfg(),
            access(),
            Some(token_dir.to_path_buf()),
            Box::new(FileExpiryStore::new(path)),
        )
    }

    /// Renew the authority and one session every 60 s until `until`, so the test can move time
    /// past the session's lease without letting the authority or the session lapse.
    fn keep_alive(
        r: &mut Registry<ManualClock>,
        clock: &ManualClock,
        tok: &str,
        session: &str,
        until: u64,
    ) {
        let refs = [SessionRef {
            session: session.into(),
            generation: 1,
        }];
        while clock.now() + 60 < until {
            clock.set(clock.now() + 60);
            r.renew(IDENT, tok, &refs, clock.now()).expect("keep alive");
        }
        clock.set(until);
    }

    #[test]
    fn store_round_trips_records() {
        let dir = tmp_dir("round-trip");
        let path = file_in(&dir);
        let mut store = FileExpiryStore::new(&path);
        assert!(store.load().expect("missing file").is_empty());
        let mut records = HashMap::new();
        records.insert(record_key(IDENT, "s1", 1), 42_000);
        records.insert(record_key(IDENT, "s2", 3), 43_000);
        store.save(&records).expect("save");
        assert_eq!(store.load().expect("load"), records);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn absolute_expiry_survives_restart_and_is_not_extended() {
        let dir = tmp_dir("abs-restart");
        let path = file_in(&dir);
        let clock = ManualClock::new(T0);
        let abs = T0 + cfg().absolute_ttl_secs;

        let mut first = open(&clock, &dir, &path).expect("start");
        let tok = first.hello(IDENT, T0).expect("hello");
        first
            .register(IDENT, &tok, entry("s1", 1, "a"), T0)
            .expect("register");
        drop(first);

        // Restart ten hours in. The restored authority gets a fresh lease, and resync re-sends
        // the session with a new lease, but the absolute expiry must stay at T0 + 12 h.
        clock.set(T0 + 10 * 3600);
        let mut second = open(&clock, &dir, &path).expect("restart");
        second
            .resync(IDENT, &tok, vec![entry("s1", 1, "a")], clock.now())
            .expect("resync after restart");
        keep_alive(&mut second, &clock, &tok, "s1", abs - 1);
        assert!(second
            .authorize(&sha("a"), IDENT, "kiro-api", abs - 1)
            .is_ok());
        clock.set(abs);
        assert_eq!(
            second.authorize(&sha("a"), IDENT, "kiro-api", abs),
            Err(Deny::Expired)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resync_refuses_session_past_stored_absolute_expiry() {
        let dir = tmp_dir("past-abs");
        let path = file_in(&dir);
        let clock = ManualClock::new(T0);
        let mut first = open(&clock, &dir, &path).expect("start");
        let tok = first.hello(IDENT, T0).expect("hello");
        first
            .register(IDENT, &tok, entry("s1", 1, "a"), T0)
            .expect("register");
        drop(first);

        let past = T0 + cfg().absolute_ttl_secs;
        clock.set(past);
        let mut second = open(&clock, &dir, &path).expect("restart");
        assert_eq!(
            second.resync(IDENT, &tok, vec![entry("s1", 1, "a")], past),
            Err(SessErr::AbsoluteExpired)
        );
        assert_eq!(
            second.register(IDENT, &tok, entry("s1", 1, "a"), past),
            Err(SessErr::AbsoluteExpired)
        );
        assert_eq!(
            second.authorize(&sha("a"), IDENT, "kiro-api", past),
            Err(Deny::Unknown)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_unreadable_at_startup_refuses_to_start() {
        let dir = tmp_dir("unreadable");
        let path = file_in(&dir);
        // A directory where the file should be cannot be read as a file.
        std::fs::create_dir(&path).expect("blocking directory");
        let clock = ManualClock::new(T0);
        assert!(open(&clock, &dir, &path).is_err());
        assert!(path.is_dir(), "startup must not replace the store");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_store_file_refuses_to_start() {
        let key = record_key(IDENT, "s1", 1);
        let cases = [
            String::new(),
            "not the header\n".to_string(),
            format!("{HEADER}\n{key} notanumber\n"),
            format!("{HEADER}\nXYZ 42\n"),
            format!("{HEADER}\n{key} 42\n{key} 43\n"),
            format!("{HEADER}\n{key}\n"),
        ];
        let clock = ManualClock::new(T0);
        for (i, text) in cases.iter().enumerate() {
            let dir = tmp_dir(&format!("corrupt-{i}"));
            let path = file_in(&dir);
            std::fs::write(&path, text).expect("write corrupt store");
            assert!(open(&clock, &dir, &path).is_err(), "case {i} must refuse");
            assert_eq!(std::fs::read_to_string(&path).expect("read"), *text);
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn failed_rename_leaves_old_store_file_intact() {
        let dir = tmp_dir("rename-fail");
        let path = file_in(&dir);
        let mut store = FileExpiryStore::new(&path);
        let mut records = HashMap::new();
        records.insert(record_key(IDENT, "s1", 1), 42_000);
        store.save(&records).expect("first save");
        let old = std::fs::read_to_string(&path).expect("read old");

        let err = write_atomic_with(&path, b"replacement", |_: &Path, _: &Path| {
            Err(io::Error::other("injected rename failure"))
        });
        assert!(err.is_err());
        assert_eq!(std::fs::read_to_string(&path).expect("read"), old);
        assert!(!tmp_path(&path).exists(), "temp file must be removed");
        assert_eq!(store.load().expect("load").len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_file_holds_no_surrogate_or_caller_key() {
        let dir = tmp_dir("no-secrets");
        let path = file_in(&dir);
        let clock = ManualClock::new(T0);
        let mut r = open(&clock, &dir, &path).expect("start");
        let tok = r.hello(IDENT, T0).expect("hello");
        r.register(IDENT, &tok, entry("s1", 1, "a"), T0)
            .expect("register");
        r.resync(
            IDENT,
            &tok,
            vec![entry("s1", 1, "a"), entry("s2", 1, "b")],
            T0,
        )
        .expect("resync");
        let text = std::fs::read_to_string(&path).expect("read store");
        assert!(!text.contains(&tok), "caller key in store");
        assert!(!text.contains("apt_"), "token prefix in store");
        assert!(!text.contains(&sha("a")), "surrogate hash in store");
        assert!(!text.contains(&sha("b")), "surrogate hash in store");
        assert!(text.contains(&record_key(IDENT, "s1", 1)));
        for line in text.lines().skip(1) {
            let (key, value) = line.split_once(' ').expect("key and value");
            assert!(is_lower_hex_64(key));
            assert!(value.bytes().all(|b| b.is_ascii_digit()));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn register_fails_closed_when_store_write_fails() {
        let dir = tmp_dir("write-fail");
        let store_dir = dir.join("store");
        std::fs::create_dir(&store_dir).expect("store dir");
        let path = file_in(&store_dir);
        let clock = ManualClock::new(T0);
        let mut r = open(&clock, &dir, &path).expect("start");
        let tok = r.hello(IDENT, T0).expect("hello");
        // Remove the directory after startup, so the next save cannot create its temp file.
        std::fs::remove_dir_all(&store_dir).expect("remove store dir");
        assert_eq!(
            r.register(IDENT, &tok, entry("s1", 1, "a"), T0),
            Err(SessErr::Unavailable)
        );
        assert_eq!(
            r.authorize(&sha("a"), IDENT, "kiro-api", T0),
            Err(Deny::Unknown)
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
