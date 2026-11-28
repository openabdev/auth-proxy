//! The Telegram notifier against a local TCP server, and the secret-file loader. Every value here is
//! synthetic and no test reaches the real Bot API.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::test_support::Scratch;

const TOKEN: &str = "123456:SYNTHETIC_TOKEN_0007";
const CHAT: &str = "-100777000111";
const URL: &str = "https://approve.example.test/pending/abc123";
const REQ_ID: &str = "abc123";

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

fn notifier(api: &str) -> TelegramNotifier {
    TelegramNotifier::with_api(api, TOKEN, CHAT, Duration::from_secs(5)).unwrap()
}

#[tokio::test]
async fn sends_one_send_message_with_only_the_fixed_text_id_and_link() {
    let (base, seen, hits) = server(Some(ok())).await;
    notifier(&base)
        .notify(REQ_ID, TEXT, URL, None)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "one send, no retry on success"
    );
    let s = seen.lock().unwrap()[0].clone();

    // The token is in the path, and only there.
    assert!(
        s.head
            .starts_with(&format!("POST /bot{TOKEN}/sendMessage HTTP/1.1")),
        "{}",
        s.head
    );
    assert_eq!(s.head.matches(TOKEN).count(), 1);
    assert!(!s.body.contains(TOKEN));
    assert!(header(&s.head, "authorization").is_none());
    assert_eq!(header(&s.head, "content-type"), Some("application/json"));

    // The body is the chat id, the fixed text with the id and the link, and link preview off.
    let json: serde_json::Value = serde_json::from_str(&s.body).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
    assert_eq!(json["chat_id"], CHAT);
    assert_eq!(json["text"], format!("{TEXT}\nRequest: {REQ_ID}\n{URL}"));
    assert_eq!(json["link_preview_options"]["is_disabled"], true);
}

#[tokio::test]
async fn buttons_message_has_only_fixed_text_id_link_and_buttons() {
    const VIEW_URL: &str = "https://view.example.test/view/fedcba9876543210fedcba9876543210";
    const HOLD_ID: &str = "0123456789abcdef0123456789abcdef";
    const NONCE: &str = "aabbccddeeff001122334455";
    // Synthetic stand-ins for what must never reach Telegram: a body, a credential, a digest.
    const SECRET_BODY: &str = "SYNTHETIC-BODY-0009";
    const SECRET_AUTH: &str = "Bot SYNTHETIC-AUTH-0010";
    const SECRET_DIGEST: &str = "0f0e0d0c0b0a09080706050403020100";
    let (base, seen, _hits) = server(Some(ok())).await;
    let buttons = Buttons {
        approve: format!("a{HOLD_ID}{NONCE}"),
        deny: format!("d{HOLD_ID}{NONCE}"),
    };
    notifier(&base)
        .notify(HOLD_ID, TEXT, VIEW_URL, Some(&buttons))
        .await
        .unwrap();
    let s = seen.lock().unwrap()[0].clone();
    let json: serde_json::Value = serde_json::from_str(&s.body).unwrap();
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["chat_id", "link_preview_options", "reply_markup", "text"]
    );
    assert_eq!(
        json["text"],
        format!("{TEXT}\nRequest: {HOLD_ID}\n{VIEW_URL}")
    );
    let row = &json["reply_markup"]["inline_keyboard"][0];
    assert_eq!(row[0]["text"], "Deny");
    assert_eq!(row[1]["text"], "Approve");
    assert_eq!(row[0]["callback_data"], buttons.deny);
    assert_eq!(row[1]["callback_data"], buttons.approve);
    assert_eq!(buttons.approve.len(), poll::CALLBACK_DATA_LEN);
    assert_eq!(buttons.deny.len(), poll::CALLBACK_DATA_LEN);
    let text = json["text"].as_str().unwrap();
    for leak in [SECRET_BODY, SECRET_AUTH, SECRET_DIGEST, NONCE] {
        assert!(!text.contains(leak), "text carries {leak}");
        assert!(!s
            .body
            .replace(&buttons.approve, "")
            .replace(&buttons.deny, "")
            .contains(leak));
    }
}

#[tokio::test]
async fn a_non_success_status_is_a_failure_with_one_attempt() {
    let (base, _, hits) = server(Some(
        "HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
    ))
    .await;
    assert_eq!(
        notifier(&base).notify("a", TEXT, URL, None).await,
        Err(NotifyError)
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a rejected send is not retried"
    );
}

#[tokio::test]
async fn a_transport_failure_is_retried_once() {
    // The server reads the request and closes without a reply. The message may have been
    // delivered, so the retry can duplicate it. That is accepted: a missed hold is worse.
    let (base, _, hits) = server(Some(String::new())).await;
    assert_eq!(
        notifier(&base).notify("a", TEXT, URL, None).await,
        Err(NotifyError)
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (target, _, target_hits) = server(Some(ok())).await;
    let (base, _, hits) = server(Some(format!(
        "HTTP/1.1 307 Temporary Redirect\r\nlocation: {target}/elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )))
    .await;
    assert_eq!(
        notifier(&base).notify("a", TEXT, URL, None).await,
        Err(NotifyError)
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_silent_server_times_out_within_the_bound() {
    let (base, _, hits) = server(None).await;
    let n = TelegramNotifier::with_api(&base, TOKEN, CHAT, Duration::from_millis(300)).unwrap();
    let start = Instant::now();
    assert_eq!(n.notify("a", TEXT, URL, None).await, Err(NotifyError));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "a timeout gets one retry, then fails"
    );
}

#[tokio::test]
async fn a_dead_server_is_a_bounded_failure() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    let n = TelegramNotifier::with_api(&base, TOKEN, CHAT, Duration::from_millis(300)).unwrap();
    let start = Instant::now();
    assert_eq!(n.notify("a", TEXT, URL, None).await, Err(NotifyError));
    // One retry on a refused connect, each attempt bounded by the timeout.
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn bad_tokens_and_chat_ids_are_refused_and_debug_hides_them() {
    for token in [
        "",
        "123:abc/def",
        "123:abc?x=1",
        "123:abc#f",
        "123 456",
        "a\nb",
    ] {
        assert!(TelegramNotifier::with_api(
            "http://127.0.0.1:1",
            token,
            CHAT,
            Duration::from_secs(1)
        )
        .is_err());
    }
    assert!(
        TelegramNotifier::with_api("http://127.0.0.1:1", TOKEN, "", Duration::from_secs(1))
            .is_err()
    );
    let n = notifier("http://127.0.0.1:1");
    let shown = format!("{n:?} {}", NotifyError);
    assert!(!shown.contains(TOKEN) && !shown.contains(CHAT));
}

#[test]
fn production_notifier_targets_the_bot_api_root() {
    assert_eq!(TELEGRAM_API, "https://api.telegram.org");
    assert!(TelegramNotifier::new(TOKEN, CHAT).is_ok());
}

fn secret(tag: &str, mode: u32, text: &str) -> (Scratch, std::path::PathBuf) {
    let s = Scratch::new(tag);
    let p = s.path().join("secret");
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    (s, p)
}

#[test]
fn token_file_with_mode_0600_is_read_and_trimmed() {
    let (_s, p) = secret("tok-ok", 0o600, &format!("{TOKEN}\n\n"));
    assert_eq!(read_secret_file(&p).unwrap(), TOKEN);
}

#[test]
fn token_file_readable_by_group_or_other_is_refused() {
    for mode in [0o644, 0o640, 0o604, 0o660, 0o666, 0o601] {
        let (_s, p) = secret("tok-perm", mode, &format!("{TOKEN}\n"));
        let e = read_secret_file(&p).unwrap_err();
        assert_eq!(e, SecretError::TooPermissive, "mode {mode:o}");
        assert!(!e.to_string().contains(TOKEN));
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
        .post("http://telegram.example.test/control")
        .send()
        .await;
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "the control client did not reach the capture proxy; the test proves nothing"
    );
    let before = hits.load(Ordering::SeqCst);
    let before_seen = seen.lock().unwrap().len();

    let n = TelegramNotifier::with_api(
        "http://telegram.example.test",
        TOKEN,
        CHAT,
        Duration::from_secs(2),
    )
    .unwrap();
    let r = n.notify("id", TEXT, URL, None).await;
    assert!(r.is_err(), "the name does not resolve, so the send fails");
    assert_eq!(hits.load(Ordering::SeqCst), before, "the proxy was dialled");
    let all = format!("{:?}", seen.lock().unwrap());
    assert_eq!(seen.lock().unwrap().len(), before_seen);
    for s in [TOKEN, CHAT, URL] {
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
