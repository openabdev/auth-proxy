//! Option B: Envoy `ext_authz` HTTP service. Envoy forwards; this service
//! holds the policy and the surrogate → credential lookup.
//!
//!   ap-authz serve <config.json>           check-request server on authz_listen
//!   ap-authz render-envoy <config.json>    print the Envoy bootstrap (JSON) for the same config
//!
//! Rendering Envoy's config from the same validated file keeps one source of
//! truth for the upstream host: Envoy's clusters and this service's routes
//! cannot drift apart, and an IP-literal or userinfo upstream is rejected
//! before Envoy ever sees it.

use ap_spike::{deny_parts, AuditRec, Config, Core, AUTH_HEADERS};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::serve::ListenerExt;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

async fn check(State(core): State<Arc<Core>>, req: Request) -> Response {
    let t0 = Instant::now();
    let (parts, _) = req.into_parts();
    let mut rec = AuditRec {
        method: parts.method.to_string(),
        ..Default::default()
    };
    match core.admit(&parts.method, &parts.uri, &parts.headers).await {
        Err(d) => {
            rec.decision = "deny";
            rec.code = d.code;
            rec.status = d.status.as_u16();
            rec.route = parts.uri.path().split('/').nth(3).map(str::to_string);
            core.audit(&rec);
            let (st, hs, body) = deny_parts(core.shape_for(&parts.uri), &d);
            let mut r = Response::builder().status(st);
            for (k, v) in hs {
                r = r.header(k, v);
            }
            r.body(Body::from(body)).unwrap()
        }
        Ok(a) => {
            rec.decision = "allow";
            rec.code = "authorized";
            rec.status = 200;
            rec.caller = Some(a.caller.clone());
            rec.route = Some(a.route.name.clone());
            rec.path = Some(a.rest.split('?').next().unwrap_or("").to_string());
            rec.credential_id = Some(a.credential_id.clone());
            rec.ms = t0.elapsed().as_millis() as u64;
            core.audit(&rec);
            // Envoy sets the credential header (allowed_upstream_headers,
            // overwrite) and removes every other auth header the client sent.
            let remove: Vec<&str> = AUTH_HEADERS
                .iter()
                .copied()
                .filter(|h| *h != a.route.credential_header)
                .collect();
            Response::builder()
                .status(200)
                .header(a.route.credential_header.as_str(), a.credential_value)
                .header("x-envoy-auth-headers-to-remove", remove.join(","))
                .body(Body::empty())
                .unwrap()
        }
    }
}

fn exact(names: &[&str]) -> Value {
    json!({"patterns": names.iter().map(|n| json!({"exact": n})).collect::<Vec<_>>()})
}

fn render(cfg: &Config) -> Value {
    let authz = cfg
        .authz_listen
        .expect("authz_listen is required for option B");
    let ca = cfg
        .ca_file
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".into());
    let mut routes = vec![];
    let mut clusters = vec![json!({
        "name": "authz", "type": "STATIC", "connect_timeout": "1s",
        "load_assignment": {"cluster_name": "authz", "endpoints": [{"lb_endpoints": [{"endpoint": {"address":
            {"socket_address": {"address": authz.ip().to_string(), "port_value": authz.port()}}}}]}]}
    })];
    for r in &cfg.routes {
        let cname = format!("r_{}", r.name);
        routes.push(json!({
            "match": {"safe_regex": {"regex": format!("^/ap/[^/]+/{}(/.*)?$", r.name)}},
            "route": {
                "cluster": cname,
                "regex_rewrite": {"pattern": {"regex": format!("^/ap/[^/]+/{}/?", r.name)}, "substitution": "/"},
                "host_rewrite_literal": r.authority(),
                "timeout": "0s"   // default 15 s would cut long model streams
            }
        }));
        let (ty, addr, port) = match r.connect_to {
            Some(a) => ("STATIC", a.ip().to_string(), a.port()),
            None => ("STRICT_DNS", r.host.clone(), r.port),
        };
        clusters.push(json!({
            "name": cname, "type": ty, "connect_timeout": "10s", "dns_lookup_family": "V4_PREFERRED",
            "load_assignment": {"cluster_name": cname, "endpoints": [{"lb_endpoints": [{"endpoint": {"address":
                {"socket_address": {"address": addr, "port_value": port}}}}]}]},
            "transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "sni": r.host,
                "common_tls_context": {"validation_context": {
                    "trusted_ca": {"filename": ca},
                    "match_typed_subject_alt_names": [{"san_type": "DNS", "matcher": {"exact": r.host}}]
                }}
            }}
        }));
    }
    let hcm = json!({
        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": "ap",
        // Base-URL mode only: absolute-form targets are proxy-style requests.
        // With the default (true) Envoy drops userinfo and forwards (measured).
        "http_protocol_options": {"allow_absolute_url": false},
        "normalize_path": true,
        "merge_slashes": true,
        "path_with_escaped_slashes_action": "REJECT_REQUEST",
        "route_config": {"name": "ap", "virtual_hosts": [{"name": "ap", "domains": ["*"], "routes": routes}]},
        "http_filters": [
            {"name": "envoy.filters.http.ext_authz", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
                "failure_mode_allow": false,
                // Any 5xx from ap-authz (policy or broker unavailable) and any
                // transport error become this fixed reply; the body and
                // x-auth-proxy-error are dropped (measured).
                "status_on_error": {"code": "ServiceUnavailable"},
                "allowed_headers": {"patterns": [{"safe_regex": {"regex": ".*"}}]},
                "http_service": {
                    "server_uri": {"uri": format!("http://{authz}"), "cluster": "authz", "timeout": "2s"},
                    "authorization_response": {
                        "allowed_upstream_headers": exact(&["authorization", "x-api-key", "x-goog-api-key"]),
                        "allowed_client_headers": exact(&["x-auth-proxy-error", "content-type", "x-amzn-errortype"])
                    }
                }
            }},
            {"name": "envoy.filters.http.router", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
                "suppress_envoy_headers": true
            }}
        ]
    });
    json!({
        "static_resources": {
            "listeners": [{
                "name": "ap",
                "address": {"socket_address": {"address": cfg.listen.ip().to_string(), "port_value": cfg.listen.port()}},
                "filter_chains": [{"filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}]}]
            }],
            "clusters": clusters
        }
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ap-authz serve|render-envoy <config.json>");
        std::process::exit(64);
    }
    let cfg = match Config::load(args[2].as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ap-authz: config rejected: {e}");
            std::process::exit(2);
        }
    };
    if args[1] == "render-envoy" {
        println!("{}", serde_json::to_string_pretty(&render(&cfg)).unwrap());
        return;
    }
    let listen = cfg.authz_listen.expect("authz_listen is required");
    let core = Arc::new(Core::new(cfg, "b").unwrap_or_else(|e| {
        eprintln!("ap-authz: {e}");
        std::process::exit(2)
    }));
    let router = axum::Router::new().fallback(check).with_state(core);
    let l = tokio::net::TcpListener::bind(listen)
        .await
        .expect("bind")
        .tap_io(|t| {
            let _ = t.set_nodelay(true);
        });
    eprintln!("ap-authz listening");
    axum::serve(l, router).await.unwrap();
}
