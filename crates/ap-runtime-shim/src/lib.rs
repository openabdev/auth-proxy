//! The runtime side of the pod split. It holds the hello proof, takes the authority from the proxy,
//! and serves the narrow agent-runtime API on its own Unix socket. The agent never reaches the
//! session socket.

pub mod agent_api;
pub mod args;

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;

use tokio::net::UnixListener;

/// Bind the agent socket at `path`, mode 0660. The directory is setgid, so the socket takes the
/// agent's group. A stale socket that nothing answers is replaced. A live listener, or any file
/// that is not a socket, is never removed.
///
/// This mirrors `ap_proxy::listener::bind_unix_socket`. The shim does not depend on the proxy
/// crate at run time.
pub fn bind_agent_socket(path: &Path) -> io::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "path exists and is not a socket",
                ));
            }
            if StdUnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a live listener answers on the agent socket path",
                ));
            }
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aps-bind-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[tokio::test]
    async fn agent_socket_is_0660() {
        let dir = scratch("mode");
        let path = dir.join("runtime.sock");
        let _l = bind_agent_socket(&path).expect("bind");
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_regular_file_at_the_socket_path_is_never_removed() {
        let dir = scratch("regular");
        let path = dir.join("runtime.sock");
        fs::write(&path, "keep me").expect("write");
        let err = bind_agent_socket(&path).expect_err("regular file must block the bind");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).expect("read"), "keep me");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_live_listener_is_not_replaced() {
        let dir = scratch("live");
        let path = dir.join("runtime.sock");
        let _first = bind_agent_socket(&path).expect("first bind");
        let err = bind_agent_socket(&path).expect_err("second bind must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        let _ = fs::remove_dir_all(&dir);
    }
}
