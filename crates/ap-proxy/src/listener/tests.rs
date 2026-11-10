//! Listener tests: loopback-only binding and the connect-probe rules for Unix socket paths.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::test_support::Scratch;

#[tokio::test]
async fn agent_listener_refuses_every_non_loopback_address() {
    assert!(bind_loopback("127.0.0.1:0".parse().expect("addr"))
        .await
        .is_ok());
    for addr in ["0.0.0.0:0", "192.0.2.1:0"] {
        let err = bind_loopback(addr.parse().expect("addr"))
            .await
            .expect_err(addr);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{addr}");
    }
}

#[tokio::test]
async fn session_socket_refuses_a_bind_while_a_live_listener_answers() {
    let scratch = Scratch::new("live");
    let path = scratch.path().join("s.sock");
    let _live = bind_session_socket(&path).expect("first bind");
    let err = bind_session_socket(&path).expect_err("second bind must fail");
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert!(path.exists(), "the live socket must be left in place");
}

#[tokio::test]
async fn stale_socket_file_is_replaced_once_the_probe_gets_no_answer() {
    let scratch = Scratch::new("stale");
    let path = scratch.path().join("s.sock");
    // A listener that is dropped leaves its socket file behind with nothing answering.
    drop(std::os::unix::net::UnixListener::bind(&path).expect("stale socket"));
    assert!(path.exists());
    let fresh = bind_session_socket(&path).expect("stale socket is replaced");
    drop(fresh);
}

#[tokio::test]
async fn a_regular_file_at_the_socket_path_is_never_removed() {
    let scratch = Scratch::new("regular");
    let path = scratch.path().join("s.sock");
    std::fs::write(&path, "not a socket").expect("write");
    let err = bind_session_socket(&path).expect_err("regular file must block the bind");
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "not a socket"
    );
}

#[tokio::test]
async fn session_socket_is_0666_and_admin_socket_is_0600() {
    let scratch = Scratch::new("modes");
    let session = scratch.path().join("session.sock");
    let admin = scratch.path().join("admin.sock");
    let _s = bind_session_socket(&session).expect("session bind");
    let _a = bind_unix_socket(&admin, 0o600).expect("admin bind");
    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode(&session), 0o666);
    assert_eq!(mode(&admin), 0o600);
}
