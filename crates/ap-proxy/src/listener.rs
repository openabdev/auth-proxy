//! Socket binding for the agent listener and the Unix session and admin sockets.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;

use tokio::net::{TcpListener, UnixListener};

#[cfg(test)]
mod tests;

/// Bind the agent listener. Any address that is not loopback is refused before the bind.
pub async fn bind_loopback(addr: SocketAddr) -> io::Result<TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listener address must be loopback",
        ));
    }
    TcpListener::bind(addr).await
}

/// Bind a Unix socket at `path` with file mode `mode`.
///
/// An existing path is replaced only when it is a socket that nothing answers. A connect
/// probe decides: if a live listener answers, the bind is refused. File identity alone is not
/// enough, because on ext4 a successor socket can reuse the predecessor's inode number.
/// Any other existing file is left alone and the bind fails.
pub fn bind_unix_socket(path: &Path, mode: u32) -> io::Result<UnixListener> {
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
                    "a live listener answers on the socket path",
                ));
            }
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Bind the session-plane socket. The agent container reaches it, so the mode is 0666.
pub fn bind_session_socket(path: &Path) -> io::Result<UnixListener> {
    bind_unix_socket(path, 0o666)
}
