//! Authority token hash on disk. The hash is written to a temporary file and renamed over the
//! target, so a reader sees either the old hash or the new one.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::registry::sha256_hex;

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
