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
        netfilter: None,
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
        netfilter: None,
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
        netfilter: None,
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

#[test]
fn netfilter_flags_are_all_or_nothing() {
    let base = ["--config", "p.toml"];
    let with = |extra: &[&str]| {
        let mut v: Vec<&str> = base.to_vec();
        v.extend_from_slice(extra);
        parse_args(args(&v))
    };
    assert_eq!(with(&[]).expect("none").netfilter, None);
    let nf = with(&[
        "--netfilter-rules-status",
        "/r/status",
        "--netfilter-probe-status",
        "/p/status",
    ])
    .expect("both")
    .netfilter
    .expect("enabled");
    assert_eq!(nf.rules_status, PathBuf::from("/r/status"));
    assert_eq!(nf.probe_status, PathBuf::from("/p/status"));
    assert_eq!(
        nf.interval,
        std::time::Duration::from_secs(netguard::DEFAULT_INTERVAL_SECS)
    );
    let nf = with(&[
        "--netfilter-rules-status",
        "/r",
        "--netfilter-probe-status",
        "/p",
        "--netfilter-interval-secs",
        "7",
    ])
    .expect("interval")
    .netfilter
    .expect("enabled");
    assert_eq!(nf.interval, std::time::Duration::from_secs(7));
    assert_eq!(nf.max_age(), std::time::Duration::from_secs(19));
    // One file alone, or an interval alone, would leave the check half set up.
    assert!(with(&["--netfilter-rules-status", "/r"]).is_err());
    assert!(with(&["--netfilter-probe-status", "/p"]).is_err());
    assert!(with(&["--netfilter-interval-secs", "5"]).is_err());
    for bad in ["0", "3601", "x", "-1"] {
        assert!(
            with(&[
                "--netfilter-rules-status",
                "/r",
                "--netfilter-probe-status",
                "/p",
                "--netfilter-interval-secs",
                bad,
            ])
            .is_err(),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn passthrough_config_with_the_netfilter_check_exits_with_status_2() {
    let scratch = Scratch::new("ptnf");
    let config = scratch.path().join("policy.toml");
    let key = "a".repeat(64);
    std::fs::write(
        &config,
        format!(
            r#"version = 1

[listen]
proxy = "127.0.0.1:18299"

[passthrough]
public_authority = "gate.example.test"

[[identity]]
name = "muse-pilot"
caller_key_sha256 = "{key}"

[[route]]
name = "discord"
host = "api.up.test"
mode = "passthrough"

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["GET"]
paths = ["/v1/"]
"#
        ),
    )
    .expect("write");
    let code = run(Options {
        config,
        session_socket: scratch.path().join("s.sock"),
        admin_socket: scratch.path().join("a.sock"),
        secret_root: scratch.path().join("secrets"),
        token_dir: scratch.path().join("tokens"),
        expiry_store: None,
        netfilter: Some(NetfilterOpts {
            rules_status: scratch.path().join("r"),
            probe_status: scratch.path().join("p"),
            interval: std::time::Duration::from_secs(30),
            rules_uid: 0,
            probe_uid: 1000,
        }),
    })
    .await;
    assert_eq!(
        code, 2,
        "a passthrough config has no per-UID rules to check"
    );
}
