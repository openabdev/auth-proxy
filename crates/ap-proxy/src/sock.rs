//! Unix socket binding with the stale-socket rule from the design doc: a
//! socket file left by a dead proxy is replaced only after a connect probe gets
//! no answer. File identity (device and inode) is not used, because ext4 can
//! hand a successor the predecessor's inode number. A live socket, or a path
//! that is not a socket, is a startup failure.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Bind `path` with `mode`. The socket is bound under a temporary name,
/// chmod-ed, then renamed into place, so it is never reachable with the wrong
/// mode.
pub async fn bind_unix(path: &Path, mode: u32) -> Result<UnixListener, String> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create socket dir: {}", e.kind()))?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => {
            match tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(path)).await {
                Ok(Ok(_)) => {
                    return Err("socket is live: another auth-proxy is already running".into())
                }
                Ok(Err(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    std::fs::remove_file(path)
                        .map_err(|e| format!("remove stale socket: {}", e.kind()))?;
                }
                Ok(Err(e)) => return Err(format!("probe existing socket: {}", e.kind())),
                Err(_) => return Err("probe existing socket: timed out".into()),
            }
        }
        Ok(_) => return Err("path exists and is not a socket".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("inspect socket path: {}", e.kind())),
    }
    let tmp = sibling(path, ".new");
    let _ = std::fs::remove_file(&tmp);
    let l = UnixListener::bind(&tmp).map_err(|e| format!("bind socket: {}", e.kind()))?;
    let finish = || -> std::io::Result<()> {
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, path)
    };
    if let Err(e) = finish() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("install socket: {}", e.kind()));
    }
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = PathBuf::from(format!("/tmp/apx-sock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn binds_with_the_requested_mode_and_replaces_a_dead_socket() {
        let d = dir("a");
        let p = d.join("s.sock");
        let l = bind_unix(&p, 0o660).await.unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        // Live: refused.
        let e = bind_unix(&p, 0o660).await.unwrap_err();
        assert!(e.contains("live"), "{e}");
        // Dead: the file stays behind, the probe gets no answer, it is replaced.
        drop(l);
        assert!(p.exists());
        let l2 = bind_unix(&p, 0o600).await.unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(l2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn refuses_a_regular_file() {
        let d = dir("b");
        let p = d.join("s.sock");
        std::fs::write(&p, b"keep me").unwrap();
        let e = bind_unix(&p, 0o660).await.unwrap_err();
        assert!(e.contains("not a socket"), "{e}");
        assert_eq!(std::fs::read(&p).unwrap(), b"keep me");
        let _ = std::fs::remove_dir_all(&d);
    }
}
