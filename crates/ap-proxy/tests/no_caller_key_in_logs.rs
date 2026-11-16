//! Owner condition (b): no audit or access log contains the
//! `/ap/<caller-key>` prefix.
//!
//! The real binary runs with stdout and stderr captured to files. The test
//! drives a success, every one of the 21 refusal codes, a wrong caller key, odd
//! paths, an upstream failure and session-plane errors (including ids that look
//! like keys), then stops the proxy cleanly and searches everything it wrote.
//!
//! Design guards this test backs up: no tracing or access-log layer exists in
//! the process; `ApPath::verify` is the one place the prefix is taken apart and
//! hands on only the route-relative path; pre-verification refusals log path
//! `-`; upstream error text (which embeds the URL) is never printed; the panic
//! hook prints a fixed line.

mod support;

use ap_client::Surrogate;
use ap_core::Code;
use std::collections::BTreeSet;
use std::time::Duration;
use support::*;

fn sref(session: &str) -> ap_client::SessionRef {
    ap_client::SessionRef {
        session: session.into(),
        generation: 1,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_caller_key_prefix_in_any_log() {
    let mut fx = Fixture::new(Opts {
        session_lease_secs: Some(2),
        max_body_bytes: Some(1000),
        ..Default::default()
    });
    fx.start_proxy();
    let key = fx.caller_key.clone();
    let a = fx.client();
    a.hello().await.unwrap();
    let token = a.token().unwrap();

    let mut used: Vec<String> = vec![token.clone()];
    let mut codes: BTreeSet<String> = BTreeSet::new();
    let mut note = |r: &Resp, want_status: u16, want_code: &str| {
        assert_eq!(r.status, want_status, "{want_code}: {}", r.text());
        assert_eq!(r.code(), Some(want_code), "{}", r.text());
        codes.insert(want_code.to_string());
    };
    let mut reg = |s: Surrogate| {
        used.push(s.expose().to_string());
        s
    };

    // The long-lived sessions are renewed in the background (the session lease
    // is 2 s); `s-exp`, registered later, is deliberately not.
    let renewer = {
        let a = a.clone();
        tokio::spawn(async move {
            let live = [sref("s-ok"), sref("s-wr"), sref("s-wc"), sref("s-dead")];
            loop {
                let _ = a.renew(&live).await;
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        })
    };

    // ---- a success, with a query string that must not be logged either
    let ok = reg(register(&a, "s-ok", 1, &["c-up"]).await);
    let ok_val = format!("Bearer {}", ok.expose());
    let ok_h = [("Authorization", ok_val.as_str())];
    let q = format!("/v1/echo?q=SECRETQUERY&k={key}");
    let r = fx.request("GET", "up", &q, &ok_h, b"");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(fx.upstream_count(), 1);

    // ---- refusals before the caller key is verified (audit path is `-`)
    let port = fx.port;
    let raw = |req: String| raw_http(port, req.as_bytes());
    let r = raw(format!(
        "GET http://evil.example/ap/{key}/up/v1/echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    ));
    note(&r, 400, "absolute_form");
    let r = raw(format!(
        "GET /ap/{key}/up/v1/echo HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"
    ));
    note(&r, 400, "host_rejected");
    let r = fx.request("GET", "up", "/v1/../etc/passwd", &ok_h, b"");
    note(&r, 400, "path_ambiguous");
    let r = fx.request_with_key(
        &format!("apk_{}", "0".repeat(64)),
        "GET",
        "up",
        "/v1/echo",
        &ok_h,
        b"",
    );
    note(&r, 403, "caller_rejected");
    let r = raw(
        "CONNECT api.up.test:443 HTTP/1.1\r\nHost: api.up.test:443\r\nConnection: close\r\n\r\n"
            .to_string(),
    );
    note(&r, 405, "connect_refused");
    let r = fx.request(
        "GET",
        "up",
        "/v1/ws",
        &[("Connection", "Upgrade"), ("Upgrade", "websocket")],
        b"",
    );
    note(&r, 501, "websocket_unsupported");
    // A path that is not /ap/<key>/<route>/...: the shape itself is wrong.
    let r = raw(format!(
        "GET /not-ap/{key} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    ));
    assert_eq!(r.status, 404);
    assert_eq!(r.code(), Some("route_unknown"));

    // ---- refusals after verification
    let r = fx.request("GET", "nope", "/v1/echo", &ok_h, b"");
    note(&r, 404, "route_unknown");
    let r = fx.request("GET", "up", "/v1/echo", &[], b"");
    note(&r, 403, "surrogate_missing");
    let r = fx.request(
        "GET",
        "up",
        "/v1/echo",
        &[("Authorization", "Bearer not-a-surrogate")],
        b"",
    );
    note(&r, 403, "surrogate_malformed");
    let two = format!("Bearer {}", ok.expose());
    let r = fx.request(
        "GET",
        "up",
        "/v1/echo",
        &[("Authorization", &two), ("Authorization", &two)],
        b"",
    );
    note(&r, 400, "surrogate_ambiguous");
    let unknown = reg(Surrogate::generate().unwrap());
    let r = fx.get("up", "/v1/echo", unknown.expose());
    note(&r, 403, "surrogate_unknown");
    let rev = reg(register(&a, "s-rev", 1, &["c-up"]).await);
    a.revoke("s-rev", 1).await.unwrap();
    let r = fx.get("up", "/v1/echo", rev.expose());
    note(&r, 403, "surrogate_revoked");
    let wr = reg(register(&a, "s-wr", 1, &["c-other"]).await);
    let r = fx.get("up", "/v1/echo", wr.expose());
    note(&r, 403, "surrogate_wrong_route");
    let wc = reg(register(&a, "s-wc", 1, &["c-up"]).await);
    fx.set_policy("someone-else", &default_grants());
    let r = fx.get("up", "/v1/echo", wc.expose());
    note(&r, 403, "surrogate_wrong_caller");
    fx.set_policy("agent-1", &default_grants());
    fx.set_policy("agent-1", "");
    let r = fx.get("up", "/v1/echo", ok.expose());
    note(&r, 403, "policy_empty");
    fx.set_policy("agent-1", &grant("c-up", "up", &["POST"], &["/v2/"], &[]));
    let r = fx.get("up", "/v1/echo", ok.expose());
    note(&r, 403, "policy_denied");
    fx.set_policy_raw("version = 1\n[[route\n");
    let r = fx.get("up", "/v1/echo", ok.expose());
    note(&r, 503, "policy_unavailable");
    fx.set_policy("agent-1", &default_grants());
    fx.remove_secret("c-up");
    let r = fx.get("up", "/v1/echo", ok.expose());
    note(&r, 503, "broker_unavailable");
    fx.write_secret("c-up", &fx.secret_value("c-up"));
    let r = fx.request("POST", "up", "/v1/echo", &ok_h, &[b'x'; 2000]);
    note(&r, 413, "body_too_large");
    let dead = reg(register(&a, "s-dead", 1, &["c-up"]).await);
    let r = fx.get("dead", "/v1/echo", dead.expose());
    note(&r, 502, "upstream_unavailable");
    let exp = reg(register(&a, "s-exp", 1, &["c-up"]).await);
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let r = fx.get("up", "/v1/echo", exp.expose());
    note(&r, 403, "surrogate_expired");

    // ---- session-plane errors, with ids that look like keys
    let c = fx.client();
    let r = c
        .raw("POST", "/v1/sessions", None, Some(b"{}"))
        .await
        .unwrap();
    assert_eq!(r.status, 401);
    c.set_token(Some(format!("apt_{}", "0".repeat(64))));
    assert_eq!(
        c.raw(
            "POST",
            "/v1/renew",
            c.token().as_deref(),
            Some(br#"{"sessions":[]}"#)
        )
        .await
        .unwrap()
        .status,
        401
    );
    let e = c.hello().await.unwrap_err();
    assert!(e.is_authority_active());
    let good_hash = "ab".repeat(32);
    let body_key_session = format!(
        r#"{{"session":"{key}","generation":1,"surrogate_sha256":"{good_hash}","credentials":["c-up"]}}"#
    );
    let r = a
        .raw(
            "POST",
            "/v1/sessions",
            Some(&token),
            Some(body_key_session.as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status, 201,
        "a session named like the key is allowed, and masked in the log"
    );
    let bad_hash = format!(
        r#"{{"session":"{key}","generation":2,"surrogate_sha256":"{key}","credentials":["c-up"]}}"#
    );
    let r = a
        .raw(
            "POST",
            "/v1/sessions",
            Some(&token),
            Some(bad_hash.as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 400);
    let not_granted = format!(
        r#"{{"session":"s-ng","generation":1,"surrogate_sha256":"{good_hash}","credentials":["{key}"]}}"#
    );
    let r = a
        .raw(
            "POST",
            "/v1/sessions",
            Some(&token),
            Some(not_granted.as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    let renew = format!(r#"{{"sessions":[{{"session":"{key}","generation":1}}]}}"#);
    let r = a
        .raw("POST", "/v1/renew", Some(&token), Some(renew.as_bytes()))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    let r = a
        .raw(
            "DELETE",
            &format!("/v1/sessions/{key}/1"),
            Some(&token),
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.status, 204);
    let r = a
        .raw(
            "POST",
            "/v1/sessions",
            Some(&token),
            Some(&vec![b'x'; 1024 * 1024 + 1]),
        )
        .await
        .unwrap();
    assert_eq!(r.status, 413);
    let r = a
        .raw("GET", "/v1/resolve", Some(&token), None)
        .await
        .unwrap();
    assert_eq!(r.status, 404);
    let r = a
        .raw("POST", "/v1/sessions", Some(&token), Some(b"not json"))
        .await
        .unwrap();
    assert_eq!(r.status, 400);

    renewer.abort();

    // ---- every refusal code has been exercised
    let want: BTreeSet<String> = Code::ALL.iter().map(|c| c.as_str().to_string()).collect();
    let missing: Vec<_> = want.difference(&codes).collect();
    assert!(missing.is_empty(), "codes not exercised: {missing:?}");

    // ---- stop cleanly, then search everything the proxy wrote
    assert_eq!(fx.stop_proxy(), Some(0), "SIGTERM is a clean stop");
    let (out, err) = fx.read_logs();
    assert!(
        out.lines().count() > 40,
        "audit log looks empty: {} lines",
        out.lines().count()
    );
    assert!(err.contains("ready"), "stderr: {err}");
    let mut forbidden: Vec<String> = vec![
        key.clone(),
        "apk_".into(),
        "aps_".into(),
        "apt_".into(),
        "/ap/".into(),
        "SECRETQUERY".into(),
        fx.secret_value("c-up"),
        fx.secret_value("c-other"),
    ];
    forbidden.extend(used.iter().cloned());
    for (name, text) in [("stdout", &out), ("stderr", &err)] {
        for f in &forbidden {
            assert!(!text.contains(f.as_str()), "{name} contains {f:?}");
        }
    }

    // Audit lines: pre-verification refusals have no path; the rest have only
    // the route-relative one.
    let lines = fx.audit_lines();
    assert!(lines.iter().filter(|l| l["decision"] == "deny").count() >= 21);
    let pre = [
        "absolute_form",
        "host_rejected",
        "path_ambiguous",
        "caller_rejected",
        "connect_refused",
        "websocket_unsupported",
        "policy_unavailable",
    ];
    for l in &lines {
        let path = l["path"].as_str().unwrap();
        assert!(
            path == "-" || (path.starts_with('/') && !path.contains("/ap/") && !path.contains('?')),
            "{l}"
        );
        if pre.contains(&l["code"].as_str().unwrap()) {
            assert_eq!(path, "-", "{l}");
        }
    }
    let ok_line = lines
        .iter()
        .find(|l| l["decision"] == "allow")
        .expect("an allow line");
    assert_eq!(ok_line["path"], "/v1/echo");
    assert_eq!(ok_line["identity"], "agent-1");
    assert_eq!(ok_line["session"], "s-ok");
}
