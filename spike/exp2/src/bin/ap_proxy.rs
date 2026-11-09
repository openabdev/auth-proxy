//! Option A: minimal Rust reverse proxy.
//! caller key → canonicalize → policy → surrogate resolve → swap → forward → audit.
//!
//! Usage: ap-proxy <config.json>

use ap_spike::{deny_parts, strip_request_headers, AuditRec, Config, Core, Deny, HOP_HEADERS};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::response::Response;
use axum::serve::ListenerExt;
use http::{HeaderName, StatusCode};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct App {
    core: Core,
    client: reqwest::Client,
}

fn refusal(core: &Core, uri: &http::Uri, d: &Deny) -> Response {
    let (st, hs, body) = deny_parts(core.shape_for(uri), d);
    let mut r = Response::builder().status(st);
    for (k, v) in hs {
        r = r.header(k, v);
    }
    r.body(Body::from(body)).unwrap()
}

async fn handle(State(app): State<Arc<App>>, req: Request) -> Response {
    let t0 = Instant::now();
    let (parts, body) = req.into_parts();
    let mut rec = AuditRec {
        method: parts.method.to_string(),
        ..Default::default()
    };
    let adm = match app
        .core
        .admit(&parts.method, &parts.uri, &parts.headers)
        .await
    {
        Ok(a) => a,
        Err(d) => {
            rec.decision = "deny";
            rec.code = d.code;
            rec.status = d.status.as_u16();
            rec.route = parts.uri.path().split('/').nth(3).map(str::to_string);
            app.core.audit(&rec);
            return refusal(&app.core, &parts.uri, &d);
        }
    };
    rec.caller = Some(adm.caller.clone());
    rec.route = Some(adm.route.name.clone());
    rec.path = Some(adm.rest.split('?').next().unwrap_or("").to_string());
    rec.credential_id = Some(adm.credential_id.clone());

    // Request bodies are prompts: buffer (bounded) so upstream gets a Content-Length.
    let body = match to_bytes(body, 32 << 20).await {
        Ok(b) => b,
        Err(_) => {
            let d = Deny {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: "body_too_large",
                msg: "request body too large",
            };
            rec.decision = "deny";
            rec.code = d.code;
            rec.status = 413;
            app.core.audit(&rec);
            return refusal(&app.core, &parts.uri, &d);
        }
    };
    // 5. strip every client auth header, then apply exactly one credential.
    let mut h = parts.headers;
    strip_request_headers(&mut h);
    let cred_name = HeaderName::from_bytes(adm.route.credential_header.as_bytes()).unwrap();
    h.insert(cred_name, adm.credential_value);
    let url = format!("https://{}{}", adm.route.authority(), adm.rest);
    let up = app
        .client
        .request(parts.method, url)
        .headers(h)
        .body(body)
        .send()
        .await;
    let up = match up {
        Ok(r) => r,
        Err(_) => {
            // Connect, TLS verification and protocol errors all end here. The
            // error text is not echoed to the client.
            let d = Deny {
                status: StatusCode::BAD_GATEWAY,
                code: "upstream_unavailable",
                msg: "upstream connection or TLS verification failed",
            };
            rec.decision = "deny";
            rec.code = d.code;
            rec.status = 502;
            rec.ms = t0.elapsed().as_millis() as u64;
            app.core.audit(&rec);
            return refusal(&app.core, &parts.uri, &d);
        }
    };
    rec.decision = "allow";
    rec.code = "forwarded";
    rec.status = up.status().as_u16();
    rec.ms = t0.elapsed().as_millis() as u64;
    app.core.audit(&rec);

    let mut r = Response::builder().status(up.status());
    for (k, v) in up.headers() {
        if !HOP_HEADERS.contains(&k.as_str()) || k == "content-length" {
            r = r.header(k, v);
        }
    }
    // Streamed chunk by chunk (SSE, AWS eventstream): no buffering.
    r.body(Body::from_stream(up.bytes_stream())).unwrap()
}

#[tokio::main]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: ap-proxy <config.json>");
    let cfg = match Config::load(path.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ap-proxy: config rejected: {e}");
            std::process::exit(2);
        }
    };
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none()) // never follow: the client gets the 3xx
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(60));
    if let Some(ca) = &cfg.ca_file {
        let pem = std::fs::read(ca).expect("read ca_file");
        b = b
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).expect("parse ca_file"));
    }
    for r in &cfg.routes {
        if let Some(a) = r.connect_to {
            b = b.resolve(&r.host, a);
        }
    }
    let client = b.build().expect("upstream client");
    let listen = cfg.listen;
    let core = Core::new(cfg, "a").unwrap_or_else(|e| {
        eprintln!("ap-proxy: {e}");
        std::process::exit(2)
    });
    let app = Arc::new(App { core, client });
    let router = axum::Router::new().fallback(handle).with_state(app);
    // axum does not set TCP_NODELAY on accepted sockets; without it a streamed
    // response (head, then body) meets the client's delayed ACK: +40 ms p99 (measured).
    let l = tokio::net::TcpListener::bind(listen)
        .await
        .expect("bind")
        .tap_io(|t| {
            let _ = t.set_nodelay(true);
        });
    eprintln!("ap-proxy listening");
    axum::serve(l, router).await.unwrap();
}
