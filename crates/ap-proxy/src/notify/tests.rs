//! The ntfy notifier against a local TCP server, and the secret-file loader.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::test_support::Scratch;

const TOKEN: &str = "tk_SECRET_TOKEN_0007";
const TOPIC: &str = "secret-topic-0008";
const URL: &str = "https://approve.example.test/pending/abc123";

/// What the server saw: the head (request line and headers) and the body.
#[derive(Clone, Debug, Default)]
struct Seen {
    head: String,
    body: String,
}

/// A one-reply HTTP server. `reply` is the full response text; `None` accepts and stays silent.
async fn server(reply: Option<String>) -> (String, Arc<Mutex<Vec<Seen>>>, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let hits = Arc::new(AtomicUsize::new(0));
    let (s, h) = (Arc::clone(&seen), Arc::clone(&hits));
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            let (s, reply) = (Arc::clone(&s), reply.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let (head, body) = loop {
                    let n = c.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let want = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= want {
                            break (head.to_string(), body.to_string());
                        }
                    }
                };
                s.lock().unwrap().push(Seen { head, body });
                match reply {
                    Some(r) => {
                        let _ = c.write_all(r.as_bytes()).await;
                        let _ = c.shutdown().await;
                    }
                    None => tokio::time::sleep(Duration::from_secs(30)).await,
                }
            });
        }
    });
    (base, seen, hits)
}

fn ok() -> String {
    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_string()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[tokio::test]
async fn posts_the_fixed_text_with_click_and_bearer() {
    let (base, seen, _) = server(Some(ok())).await;
    let n = NtfyNotifier::new(&format!("{base}/"), TOPIC, Some(TOKEN)).unwrap();
    n.notify("abc123", TEXT, URL).await.unwrap();
    let s = seen.lock().unwrap()[0].clone();
    assert!(
        s.head.starts_with(&format!("POST /{TOPIC} HTTP/1.1")),
        "{}",
        s.head
    );
    assert_eq!(s.body, TEXT);
    assert_eq!(header(&s.head, "click"), Some(URL));
    assert_eq!(
        header(&s.head, "authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert!(!s.head.contains("abc123 ") && !s.body.contains("abc123"));
}

#[tokio::test]
async fn no_bearer_header_without_a_token() {
    let (base, seen, _) = server(Some(ok())).await;
    let n = NtfyNotifier::new(&base, TOPIC, None).unwrap();
    n.notify("abc123", TEXT, URL).await.unwrap();
    let s = seen.lock().unwrap()[0].clone();
    assert!(header(&s.head, "authorization").is_none());
}

#[tokio::test]
async fn a_non_success_status_is_a_failure() {
    let (base, _, hits) = server(Some(
        "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_string(),
    ))
    .await;
    let n = NtfyNotifier::new(&base, TOPIC, None).unwrap();
    assert_eq!(n.notify("a", TEXT, URL).await, Err(NotifyError));
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one attempt, no retry");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (target, _, target_hits) = server(Some(ok())).await;
    let (base, _, hits) = server(Some(format!(
        "HTTP/1.1 307 Temporary Redirect\r\nlocation: {target}/elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )))
    .await;
    let n = NtfyNotifier::new(&base, TOPIC, Some(TOKEN)).unwrap();
    assert_eq!(n.notify("a", TEXT, URL).await, Err(NotifyError));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_silent_server_times_out() {
    let (base, _, _) = server(None).await;
    let n = NtfyNotifier::with_timeout(&base, TOPIC, None, Duration::from_millis(300)).unwrap();
    let start = Instant::now();
    assert_eq!(n.notify("a", TEXT, URL).await, Err(NotifyError));
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_dead_server_is_a_failure() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    let n = NtfyNotifier::new(&base, TOPIC, None).unwrap();
    assert_eq!(n.notify("a", TEXT, URL).await, Err(NotifyError));
}

#[test]
fn bad_topics_and_tokens_are_refused_and_debug_hides_them() {
    for topic in ["", "a/b", "a b", "t?x=1", "t#f"] {
        assert!(NtfyNotifier::new("http://127.0.0.1:1", topic, None).is_err());
    }
    assert!(NtfyNotifier::new("http://127.0.0.1:1", TOPIC, Some("bad\ntoken")).is_err());
    let n = NtfyNotifier::new("http://127.0.0.1:1", TOPIC, Some(TOKEN)).unwrap();
    let shown = format!("{n:?} {}", NotifyError);
    assert!(!shown.contains(TOPIC) && !shown.contains(TOKEN));
}

fn secret(tag: &str, mode: u32, text: &str) -> (Scratch, std::path::PathBuf) {
    let s = Scratch::new(tag);
    let p = s.path().join("secret");
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    (s, p)
}

#[test]
fn secret_file_with_mode_0600_is_read_and_trimmed() {
    let (_s, p) = secret("sec-ok", 0o600, "  my-topic\n\n");
    assert_eq!(read_secret_file(&p).unwrap(), "my-topic");
}

#[test]
fn secret_file_readable_by_group_or_other_is_refused() {
    for mode in [0o644, 0o640, 0o604, 0o660, 0o666, 0o601] {
        let (_s, p) = secret("sec-perm", mode, "my-topic\n");
        let e = read_secret_file(&p).unwrap_err();
        assert_eq!(e, SecretError::TooPermissive, "mode {mode:o}");
        assert!(!e.to_string().contains("my-topic"));
    }
}

#[test]
fn secret_file_must_be_a_regular_nonempty_short_file() {
    let s = Scratch::new("sec-kinds");
    assert_eq!(
        read_secret_file(s.path()).unwrap_err(),
        SecretError::NotRegularFile
    );
    assert_eq!(
        read_secret_file(&s.path().join("absent")).unwrap_err(),
        SecretError::Unreadable
    );
    let (_a, empty) = secret("sec-empty", 0o600, "\n");
    assert_eq!(read_secret_file(&empty).unwrap_err(), SecretError::Empty);
    let (_b, long) = secret("sec-long", 0o600, &"a".repeat(5000));
    assert_eq!(read_secret_file(&long).unwrap_err(), SecretError::TooLong);
    let (_c, odd) = secret("sec-odd", 0o600, "two words");
    assert_eq!(read_secret_file(&odd).unwrap_err(), SecretError::Invalid);
}

// ---------------------------------------------------------------- ambient proxy variables

const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Sets every proxy variable to `url` for the life of the value, then restores the old values.
///
/// Only the isolated child processes below use this: they run one test each, so the change to
/// the process environment cannot reach another test. The parent test binary never mutates
/// its environment.
struct ProxyEnv {
    old: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl ProxyEnv {
    fn set(url: &str) -> ProxyEnv {
        let old = PROXY_VARS
            .iter()
            .map(|k| (*k, std::env::var_os(k)))
            .collect();
        for k in PROXY_VARS {
            std::env::set_var(k, url);
        }
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
        ProxyEnv { old }
    }
}

impl Drop for ProxyEnv {
    fn drop(&mut self) {
        for (k, v) in &self.old {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// Runs the `#[ignore]`d test `name` of this module alone, in a child copy of the test binary,
/// and requires that it ran and passed. A test that needs process-wide environment changes goes
/// through here, so no other test thread can observe them.
fn run_isolated(name: &str) {
    let module = module_path!().split_once("::").map_or("", |(_, rest)| rest);
    let full = format!("{module}::{name}");
    let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([full.as_str(), "--exact", "--ignored", "--test-threads=1"])
        .output()
        .expect("spawn the isolated test");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && text.contains("1 passed"),
        "isolated test {full} did not pass:\n{text}"
    );
}

#[test]
fn the_notifier_ignores_every_proxy_environment_variable() {
    run_isolated("isolated_notifier_ignores_proxy_variables");
}

#[test]
fn the_upstream_clients_ignore_every_proxy_environment_variable() {
    run_isolated("isolated_upstream_clients_ignore_proxy_variables");
}

#[ignore = "runs in a child process, see run_isolated"]
#[tokio::test(flavor = "multi_thread")]
async fn isolated_notifier_ignores_proxy_variables() {
    let (capture, seen, hits) = server(Some(ok())).await;
    let _env = ProxyEnv::set(&capture);
    // Control: a default client does honour the variables, so the capture listener can see a
    // request and the assertions below mean something.
    let control = reqwest::Client::builder().build().unwrap();
    let _ = control
        .post("http://notify.example.test/control")
        .send()
        .await;
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "the control client did not reach the capture proxy; the test proves nothing"
    );
    let before = hits.load(Ordering::SeqCst);
    let before_seen = seen.lock().unwrap().len();

    let n = NtfyNotifier::new("http://notify.example.test", TOPIC, Some(TOKEN)).unwrap();
    let r = n.notify("id", TEXT, URL).await;
    assert!(r.is_err(), "the name does not resolve, so the send fails");
    assert_eq!(hits.load(Ordering::SeqCst), before, "the proxy was dialled");
    let all = format!("{:?}", seen.lock().unwrap());
    assert_eq!(seen.lock().unwrap().len(), before_seen);
    for s in [TOKEN, TOPIC, URL] {
        assert!(!all.contains(s), "{s} reached the proxy");
    }
}

#[ignore = "runs in a child process, see run_isolated"]
#[tokio::test(flavor = "multi_thread")]
async fn isolated_upstream_clients_ignore_proxy_variables() {
    let (capture, _seen, hits) = server(Some(ok())).await;
    let _env = ProxyEnv::set(&capture);
    for c in [
        crate::forward::client_builder().build().unwrap(),
        crate::forward::held_client_builder().build().unwrap(),
    ] {
        let r = c.get("https://notify.example.test/x").send().await;
        assert!(r.is_err());
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the proxy was dialled");
}
