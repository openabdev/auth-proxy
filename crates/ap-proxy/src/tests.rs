//! Startup tests: argument parsing and the exit status of `run`.

use super::*;
use crate::test_support::Scratch;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parse_args_requires_config_and_rejects_unknown_flags() {
    assert!(parse_args(args(&[])).is_err());
    assert!(parse_args(args(&["--config", "p.toml", "--bogus", "x"])).is_err());
    assert!(parse_args(args(&["--config"])).is_err());
}

#[test]
fn parse_args_reads_every_flag() {
    let opts = parse_args(args(&[
        "--config",
        "p.toml",
        "--session-socket",
        "s.sock",
        "--admin-socket",
        "a.sock",
        "--secret-root",
        "/secrets",
        "--token-dir",
        "/tokens",
    ]))
    .expect("valid args");
    assert_eq!(opts.config, PathBuf::from("p.toml"));
    assert_eq!(opts.session_socket, PathBuf::from("s.sock"));
    assert_eq!(opts.admin_socket, PathBuf::from("a.sock"));
    assert_eq!(opts.secret_root, PathBuf::from("/secrets"));
    assert_eq!(opts.token_dir, PathBuf::from("/tokens"));
}

#[tokio::test]
async fn invalid_config_exits_with_status_2_and_binds_nothing() {
    let scratch = Scratch::new("badcfg");
    let config = scratch.path().join("policy.toml");
    std::fs::write(&config, "version = 2\n").expect("write");
    let session = scratch.path().join("session.sock");
    let code = run(Options {
        config,
        session_socket: session.clone(),
        admin_socket: scratch.path().join("admin.sock"),
        secret_root: scratch.path().join("secrets"),
        token_dir: scratch.path().join("tokens"),
        expiry_store: None,
    })
    .await;
    assert_eq!(code, 2);
    assert!(!session.exists(), "no socket may be bound on a bad config");
}

#[tokio::test]
async fn missing_config_exits_with_status_2() {
    let scratch = Scratch::new("nocfg");
    let code = run(Options {
        config: scratch.path().join("absent.toml"),
        session_socket: scratch.path().join("s.sock"),
        admin_socket: scratch.path().join("a.sock"),
        secret_root: scratch.path().join("secrets"),
        token_dir: scratch.path().join("tokens"),
        expiry_store: None,
    })
    .await;
    assert_eq!(code, 2);
}

#[tokio::test]
async fn missing_expiry_store_exits_with_status_2_and_binds_nothing() {
    let scratch = Scratch::new("nostore");
    let config = scratch.path().join("policy.toml");
    let text = crate::test_support::policy_text(&"a".repeat(64), 8443);
    std::fs::write(&config, text).expect("write");
    let tokens = scratch.path().join("tokens");
    std::fs::create_dir_all(&tokens).expect("token dir");
    let session = scratch.path().join("session.sock");
    let code = run(Options {
        config,
        session_socket: session.clone(),
        admin_socket: scratch.path().join("admin.sock"),
        secret_root: scratch.path().join("secrets"),
        token_dir: tokens.clone(),
        expiry_store: None,
    })
    .await;
    assert_eq!(code, 2, "a missing store must stop the start");
    assert!(
        !session.exists(),
        "no socket may be bound without the store"
    );
    assert!(
        !tokens.join(ap_broker::expiry::FILE_NAME).exists(),
        "a refused start must not create the store"
    );
}
