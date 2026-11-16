//! A cheap change detector for files that are re-read when they change.

use std::fs::Metadata;
use std::time::{SystemTime, UNIX_EPOCH};

/// mtime, size and (on Unix) device and inode. Kubelet replaces Secret and
/// ConfigMap contents by flipping a symlink to a new directory, which gives
/// the file a new inode even when mtime and size happen to match.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileStamp {
    mtime: SystemTime,
    len: u64,
    dev: u64,
    ino: u64,
}

impl FileStamp {
    pub fn of(md: &Metadata) -> FileStamp {
        #[cfg(unix)]
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            (md.dev(), md.ino())
        };
        #[cfg(not(unix))]
        let (dev, ino) = (0, 0);
        FileStamp {
            mtime: md.modified().unwrap_or(UNIX_EPOCH),
            len: md.len(),
            dev,
            ino,
        }
    }
}
