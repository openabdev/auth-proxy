//! Q3-A behavior: the policy file is validated as a whole at startup (exit 2)
//! and at every reload (503 `policy_unavailable`), swaps are atomic, a bad file
//! never leaves a half-applied or stale policy, and `aws_targets` is enforced.

mod support;

use ap_client::ClientError;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::*;

type Breakage = Box<dyn Fn(&Fixture)>;
type State<'a> = (&'a str, Vec<(&'a str, String)>, &'a str);

fn run_proxy(fx: &Fixture) -> std::process::Output {
    fx.proxy_command().output().unwrap()
}

#[test]
fn a_policy_that_fails_validation_stops_the_proxy_with_exit_code_2() {
    let fx = Fixture::new(Opts::default());
    let good = fx.policy_toml("agent-1", &default_grants());
    let other_port = free_port();
    let bad: Vec<(&str, String)> = vec![
        ("version 2", good.replace("version = 1", "version = 2")),
        (
            "unknown key",
            good.replace("version = 1", "version = 1\nbogus = true"),
        ),
        (
            "IP literal route host",
            good.replacen("api.up.test", "127.0.0.1", 1),
        ),
        (
            "uppercase route host",
            good.replacen("api.up.test", "API.up.test", 1),
        ),
        (
            "userinfo route host",
            good.replacen("api.up.test", "u@api.up.test", 1),
        ),
        (
            "grant names an unknown credential",
            fx.policy_toml("agent-1", &grant("nope", "up", &["GET"], &["/"], &[])),
        ),
        (
            "grant path without a trailing slash",
            fx.policy_toml("agent-1", &grant("c-up", "up", &["GET"], &["/v1"], &[])),
        ),
        (
            "aws: source (deferred)",
            good.replace("k8s:c-up:api_key", "aws:secretsmanager:x"),
        ),
        (
            "env: source (not resolved in Phase 1)",
            good.replace("k8s:c-up:api_key", "env:FOO"),
        ),
        (
            "bad caller hash",
            good.replace("caller_key_sha256 = \"", "caller_key_sha256 = \"zz"),
        ),
        ("empty file", String::new()),
        ("not TOML", "[[route".into()),
        (
            "listener differs from --listen",
            format!("{good}\n[listener]\nlisten = \"127.0.0.1:{other_port}\"\n"),
        ),
        (
            "non-loopback policy listener",
            format!("{good}\n[listener]\nlisten = \"0.0.0.0:{other_port}\"\n"),
        ),
    ];
    for (label, content) in bad {
        fx.set_policy_raw(&content);
        let out = run_proxy(&fx);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{label}: stderr: {err}");
        assert!(err.starts_with("auth-proxy: "), "{label}: {err}");
        assert!(
            !err.contains("panicked") && !err.contains("RUST_BACKTRACE"),
            "{label}: {err}"
        );
        assert!(
            !fx.session_sock().exists(),
            "{label}: a socket was bound before the policy passed"
        );
    }
    // A missing file too.
    std::fs::remove_file(fx.policy_path()).unwrap();
    assert_eq!(run_proxy(&fx).status.code(), Some(2));
    // And the good file starts.
    fx.set_policy_raw(&good);
    let mut fx = fx;
    fx.start_proxy();
}

#[test]
fn the_listener_can_be_configured_in_the_policy() {
    let fx = Fixture::new(Opts::default());
    let toml = format!(
        "{}\n[listener]\nlisten = \"127.0.0.1:{}\"\n",
        fx.policy_toml("agent-1", &default_grants()),
        fx.port
    );
    fx.set_policy_raw(&toml);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_auth-proxy"));
    cmd.args(["--policy", &fx.policy_path().to_string_lossy()])
        .args(["--secrets-dir", &fx.secrets_dir().to_string_lossy()])
        .args(["--session-socket", &fx.session_sock().to_string_lossy()])
        .args(["--admin-socket", &fx.admin_sock().to_string_lossy()])
        .args(["--state-dir", &fx.state_dir().to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", fx.port)).is_err() {
        assert!(Instant::now() < end, "proxy did not start");
        std::thread::sleep(Duration::from_millis(30));
    }
    // Both default authorities are accepted, others are not.
    let ask = |host: String| {
        raw_http(
            fx.port,
            format!(
                "GET /ap/apk_{}/up/v1/echo HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
                "0".repeat(64)
            )
            .as_bytes(),
        )
    };
    assert_eq!(
        ask(format!("127.0.0.1:{}", fx.port)).code(),
        Some("caller_rejected")
    );
    assert_eq!(
        ask(format!("localhost:{}", fx.port)).code(),
        Some("caller_rejected")
    );
    assert_eq!(ask("evil.example".into()).code(), Some("host_rejected"));
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test(flavor = "multi_thread")]
async fn unreadable_policy_refuses_everything_and_recovers_when_restored() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let s = register(&a, "s1", 1, &["c-up"]).await;
    let good = fx.policy_toml("agent-1", &default_grants());
    let ask = |fx: &Fixture| fx.get("up", "/v1/echo", s.expose());

    let r = ask(&fx);
    assert_eq!(r.status, 200, "{}", r.text());
    let mut forwarded = 1;
    assert_eq!(fx.upstream_count(), forwarded);

    let breakages: Vec<(&str, Breakage)> = vec![
        ("0 bytes", Box::new(|fx: &Fixture| fx.set_policy_raw(""))),
        (
            "corrupt",
            Box::new(|fx: &Fixture| fx.set_policy_raw("version = 1\n[[route\nname")),
        ),
        (
            "valid TOML, whole-file validation fails",
            Box::new(|fx: &Fixture| {
                fx.set_policy("agent-1", &grant("c-up", "nowhere", &["GET"], &["/"], &[]))
            }),
        ),
        (
            "deleted",
            Box::new(|fx: &Fixture| std::fs::remove_file(fx.policy_path()).unwrap()),
        ),
    ];
    for (label, breakage) in breakages {
        breakage(&fx);
        let r = ask(&fx);
        assert_eq!(
            (r.status, r.code()),
            (503, Some("policy_unavailable")),
            "{label}: {}",
            r.text()
        );
        // The last good snapshot is not kept: every route, including ones that
        // did not change, is refused.
        assert_eq!(
            fx.get("upaws", "/v1/echo", s.expose()).code(),
            Some("policy_unavailable"),
            "{label}"
        );
        // Session registration needs the policy too.
        let e = a
            .register(&ap_client::Registration::new(
                "x",
                1,
                &ap_client::Surrogate::generate().unwrap(),
                &["c-up"],
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(e, ClientError::Api { status: 503, .. }),
            "{label}: {e}"
        );
        assert_eq!(
            fx.upstream_count(),
            forwarded,
            "{label}: a refused request reached the upstream"
        );
        // Restore: back to normal at once, no restart.
        fx.set_policy_raw(&good);
        let r = ask(&fx);
        assert_eq!(r.status, 200, "{label}: {}", r.text());
        forwarded += 1;
        assert_eq!(fx.upstream_count(), forwarded);
    }
    let (_, err) = fx.read_logs();
    assert!(
        err.contains("policy unavailable"),
        "the operator is told on stderr: {err}"
    );
}

#[test]
fn a_policy_swap_is_atomic_under_concurrent_requests() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    // Policy A names identity ident-a (the session is registered under it),
    // policy B names ident-b and has no /v1/ grant. A request judged against a
    // half-applied swap would show ident-a with a deny, or ident-b with an allow.
    let pa = fx.policy_toml("ident-a", &default_grants());
    let pb = fx.policy_toml("ident-b", &grant("c-up", "up", &["POST"], &["/v9/"], &[]));
    fx.set_policy_raw(&pa);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let s = rt.block_on(async {
        let a = fx.client();
        a.hello().await.unwrap();
        register(&a, "s1", 1, &["c-up"]).await
    });
    let reg_ok = fx.get("up", "/v1/echo", s.expose());
    assert_eq!(reg_ok.status, 200, "{}", reg_ok.text());
    fx.reset_upstream();

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let swapper = {
        let (dir, path, stop) = (fx.dir.clone(), fx.policy_path(), stop.clone());
        std::thread::spawn(move || {
            let tmp = dir.join("swap.tmp");
            let mut flip = false;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::fs::write(&tmp, if flip { &pb } else { &pa }).unwrap();
                std::fs::rename(&tmp, &path).unwrap();
                flip = !flip;
                std::thread::sleep(Duration::from_millis(4));
            }
        })
    };
    let req = format!(
        "GET /ap/{}/up/v1/echo HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        fx.caller_key,
        fx.port,
        s.expose()
    );
    let port = fx.port;
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let req = req.clone();
            std::thread::spawn(move || {
                let mut seen: Vec<(u16, Option<String>)> = Vec::new();
                let end = Instant::now() + Duration::from_millis(2500);
                while Instant::now() < end {
                    let r = raw_http(port, req.as_bytes());
                    seen.push((r.status, r.code().map(String::from)));
                }
                seen
            })
        })
        .collect();
    let mut tally: HashMap<(u16, Option<String>), usize> = HashMap::new();
    for w in workers {
        for k in w.join().unwrap() {
            *tally.entry(k).or_default() += 1;
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    swapper.join().unwrap();

    let allowed = tally.get(&(200, None)).copied().unwrap_or(0);
    let denied = tally
        .get(&(403, Some("surrogate_wrong_caller".into())))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        allowed + denied,
        tally.values().sum::<usize>(),
        "unexpected outcomes during swaps: {tally:?}"
    );
    assert!(
        allowed > 10 && denied > 10,
        "both policies must have been seen: {tally:?}"
    );
    assert_eq!(
        fx.upstream_count(),
        allowed,
        "only allowed requests reach the upstream"
    );
    for l in fx.audit_lines() {
        let pair = (l["identity"].as_str().unwrap(), l["code"].as_str().unwrap());
        if l["session"] == "s1" || l["identity"] != "-" {
            assert!(
                pair == ("ident-a", "ok") || pair == ("ident-b", "surrogate_wrong_caller"),
                "half-applied policy: {l}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn aws_targets_deny_zero_and_two_headers_and_every_refusal_is_aws_shaped() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let s = register(&a, "s1", 1, &["c-up"]).await;
    fx.set_policy(
        "agent-1",
        &[
            grant("c-up", "upaws", &["POST"], &["/v1/"], &["Svc.Allowed"]),
            grant("c-up", "up", &["POST"], &["/v1/"], &[]),
        ]
        .join("\n"),
    );
    let auth = format!("Bearer {}", s.expose());
    let post = |route: &str, targets: &[&str]| {
        let mut h: Vec<(&str, &str)> = vec![("Authorization", auth.as_str())];
        for t in targets {
            h.push(("X-Amz-Target", *t));
        }
        fx.request("POST", route, "/v1/echo", &h, b"{}")
    };

    let r = post("upaws", &["Svc.Allowed"]);
    assert_eq!(r.status, 200, "{}", r.text());
    let log = fx.upstream_log();
    assert_eq!(log.len(), 1);
    let targets: Vec<_> = log[0]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h[0] == "x-amz-target")
        .collect();
    assert_eq!(
        targets.len(),
        1,
        "the one allowed target is forwarded as is"
    );

    for (label, t) in [
        ("none", vec![]),
        ("two equal", vec!["Svc.Allowed", "Svc.Allowed"]),
        ("two different", vec!["Svc.Allowed", "Svc.Other"]),
        ("wrong", vec!["Svc.Other"]),
        ("wrong case", vec!["svc.allowed"]),
        ("comma list", vec!["Svc.Allowed, Svc.Other"]),
    ] {
        let r = post("upaws", &t);
        assert_eq!(
            (r.status, r.code()),
            (403, Some("policy_denied")),
            "{label}"
        );
        let j = r.json();
        assert_eq!(j["__type"], "AccessDeniedException", "{label}: {j}");
        assert_eq!(
            r.header("x-amzn-errortype"),
            Some("AccessDeniedException"),
            "{label}"
        );
    }
    // The route without aws_targets takes any number of them.
    assert_eq!(post("up", &["X.A", "X.B"]).status, 200);
    assert_eq!(
        fx.upstream_count(),
        2,
        "denied requests reached the upstream"
    );

    // Every surrogate state is a 403 with the AWS-shaped body on an aws route,
    // and the JSON dialect elsewhere.
    a.revoke("s1", 1).await.unwrap();
    let unknown = ap_client::Surrogate::generate().unwrap();
    let states: Vec<State> = vec![
        (
            "revoked",
            vec![("Authorization", auth.clone())],
            "surrogate_revoked",
        ),
        (
            "unknown",
            vec![("Authorization", format!("Bearer {}", unknown.expose()))],
            "surrogate_unknown",
        ),
        (
            "malformed",
            vec![("Authorization", "Bearer nope".into())],
            "surrogate_malformed",
        ),
        ("missing", vec![], "surrogate_missing"),
    ];
    for (label, headers, code) in states {
        let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = fx.request("POST", "upaws", "/v1/echo", &h, b"{}");
        assert_eq!((r.status, r.code()), (403, Some(code)), "{label}");
        assert_eq!(r.json()["__type"], "AccessDeniedException", "{label}");
        let r = fx.request("POST", "up", "/v1/echo", &h, b"{}");
        assert_eq!((r.status, r.code()), (403, Some(code)), "{label} (json)");
        assert_eq!(r.json()["error"]["type"], code, "{label} (json)");
    }
    assert_eq!(fx.upstream_count(), 2);
}
