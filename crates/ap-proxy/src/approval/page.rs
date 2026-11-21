//! The approval pages (design 3.6) and the JSON views the same API serves.
//!
//! Every value that came from a request is escaped here. Each page carries one fixed stylesheet,
//! and the Content-Security-Policy allows exactly that block by its SHA-256 hash. No page has a
//! script, an image, a font or any other external resource, and no element has a `style`
//! attribute. A credential header value is never in a [`View`], so it cannot reach a page; the
//! page shows that the header is present.
//!
//! Layout, top to bottom: a compact header (request id, held time, remaining seconds), the payload
//! block (method, route, redacted path and the message content), the approve and deny buttons on
//! the decision page, and a closed `<details>` with the secondary facts.

use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::hold::{State, View, ViewContent};

/// The stylesheet inlined in every page. The Content-Security-Policy allows this block by hash.
const STYLE: &str = r#"
*{box-sizing:border-box}
body{margin:0;font:16px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:#f4f4f1;color:#1a1a1a}
main{max-width:680px;margin:0 auto;padding:12px 14px 32px}
h1{font-size:17px;margin:0;font-weight:600}
h2{font-size:15px;margin:16px 0 6px}
a{color:#0b5cad}
.top{padding:4px 0 10px;border-bottom:1px solid #d9d9d4}
.id{margin:2px 0 0;font:13px/1.3 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#555;word-break:break-all}
.meta{margin:6px 0 0;font-size:14px;color:#444}
.banner{margin:12px 0 0;padding:10px 12px;border-radius:10px;background:#fff3cd;color:#5c4300;font-size:15px}
.note{margin:12px 0 0;font-size:15px;color:#444}
.payload{margin-top:12px;background:#fff;border:1px solid #cfcfc9;border-radius:14px;padding:14px}
.label{margin:10px 0 6px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#666}
.label:first-child{margin-top:0}
.req{margin:0;font-size:22px;font-weight:700;line-height:1.25;overflow-wrap:anywhere}
.method{color:#0b5cad}
.path{margin:4px 0 0;font:15px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.body{margin:0;padding:12px;max-height:60vh;overflow:auto;background:#f3f3ef;border-radius:10px;font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.actions{display:grid;gap:10px;margin-top:14px}
.actions form{margin:0}
.btn{width:100%;min-height:60px;border-radius:14px;font:inherit;font-size:20px;font-weight:700;cursor:pointer}
.btn:disabled{opacity:.45;cursor:not-allowed}
.approve{background:#1d7a3c;color:#fff;border:0}
.deny{background:#fff;color:#b3261e;border:2px solid #b3261e}
details{margin-top:16px;background:#fff;border:1px solid #cfcfc9;border-radius:14px;padding:0 14px}
summary{min-height:48px;display:flex;align-items:center;font-weight:600;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:14px;margin:0 0 12px}
th,td{padding:8px 4px;border-top:1px solid #ebebe7;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{width:36%;color:#555;font-weight:600}
.foot{margin-top:18px;font-size:15px}
@media (min-width:560px){.actions{grid-template-columns:1fr 1fr}}
@media (prefers-color-scheme:dark){
body{background:#151515;color:#e8e8e6}
.top{border-color:#333}
.payload,details{background:#1e1e1e;border-color:#3a3a3a}
.body{background:#262626}
.label,.meta,.note,.id,th{color:#aaa}
th,td{border-color:#333}
.banner{background:#3d3200;color:#ffe08a}
.method,a{color:#7ab8ff}
.approve{background:#2a8f4a}
.deny{background:#1e1e1e;color:#ff8a80;border-color:#ff8a80}
}
"#;

/// The Content-Security-Policy of every response. Scripts, images, fonts and frames are refused,
/// and the one inline stylesheet is allowed by its SHA-256 hash.
pub fn csp() -> &'static str {
    static CSP: OnceLock<String> = OnceLock::new();
    CSP.get_or_init(|| {
        let hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
        format!(
            "default-src 'none'; style-src 'sha256-{hash}'; frame-ancestors 'none'; form-action 'self'"
        )
    })
}

/// Escape text for an HTML text node or a double-quoted attribute value.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The stable name of a state, as the JSON API and the page show it.
pub fn state_str(s: State) -> &'static str {
    match s {
        State::Pending => "pending",
        State::Approved => "approved",
        State::Denied => "denied",
        State::Expired => "expired",
        State::Abandoned => "abandoned",
        State::Superseded => "superseded",
        State::Dropped => "dropped",
    }
}

fn shell(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{}</title><style>{STYLE}</style></head><body><main>\n{body}</main></body></html>\n",
        escape(title)
    )
}

/// A one-line message page (errors and results).
pub fn message(title: &str, text: &str, newest: Option<&str>) -> String {
    let mut b = format!(
        "<h1>{}</h1>\n<p class=\"note\">{}</p>\n",
        escape(title),
        escape(text)
    );
    if let Some(n) = newest {
        b.push_str(&format!(
            "<p class=\"note\">Newer request: <a href=\"/pending/{0}\">{0}</a></p>\n",
            escape(n)
        ));
    }
    b.push_str("<p class=\"foot\"><a href=\"/pending\">Pending requests</a></p>\n");
    shell(title, &b)
}

/// The list of pending entries.
pub fn list(items: &[View]) -> String {
    let mut b = String::from("<h1>Pending requests</h1>\n");
    if items.is_empty() {
        b.push_str("<p class=\"note\">No request is waiting.</p>\n");
    } else {
        b.push_str("<ul>\n");
        for v in items {
            let Some(c) = &v.content else { continue };
            b.push_str(&format!(
                "<li><a href=\"/pending/{id}\">{method} {route}{path}</a> ({identity})</li>\n",
                id = escape(&v.id),
                method = escape(&c.method),
                route = escape(&c.route),
                path = escape(&c.path),
                identity = escape(&v.identity),
            ));
        }
        b.push_str("</ul>\n");
    }
    shell("Pending requests", &b)
}

fn row(name: &str, value: &str) -> String {
    format!("<tr><th>{}</th><td>{}</td></tr>\n", escape(name), value)
}

fn header(v: &View) -> String {
    let mut h = format!(
        "<header class=\"top\"><h1>Request</h1><p class=\"id\">{}</p>",
        escape(&v.id)
    );
    if let Some(c) = &v.content {
        h.push_str(&format!(
            "<p class=\"meta\">Held {} s ago · {} s left when this page loaded</p>",
            c.held_secs, c.remaining_secs
        ));
    }
    h.push_str("</header>\n");
    h
}

/// The text of the `content` field when the body is a JSON object whose `content` is a string.
/// The JSON string is decoded, so escapes such as `\uff5c` become the characters they stand for.
/// `None` for anything else, including malformed JSON; this never panics.
fn message_content(body: &str) -> Option<String> {
    match serde_json::from_str::<Value>(body).ok()? {
        Value::Object(mut fields) => match fields.remove("content")? {
            Value::String(text) => Some(text),
            _ => None,
        },
        _ => None,
    }
}

/// The top-level fields of a JSON object body other than `content`, as names only. serde_json
/// without `preserve_order` keeps object keys sorted, so these are sorted, not in body order.
/// Empty for anything that is not a JSON object.
fn extra_field_names(body: &str) -> Vec<String> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(fields)) => fields
            .keys()
            .filter(|k| k.as_str() != "content")
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// The visible line that names fields sent besides `content`. Empty when there are none.
fn extra_fields_line(body: &str) -> String {
    let names = extra_field_names(body);
    if names.is_empty() {
        return String::new();
    }
    let escaped: Vec<String> = names.iter().map(|n| escape(n)).collect();
    let (count, noun) = if names.len() == 1 {
        (1, "field")
    } else {
        (names.len(), "fields")
    };
    format!(
        "<p class=\"banner extra-fields\">+ {count} more {noun} will be sent: {} (see Details)</p>\n",
        escaped.join(", ")
    )
}

/// The payload block: what will be sent, in large type. The message content is shown decoded when
/// the body has one; otherwise the body is shown as it was received. Fields other than `content`
/// are named in a line above the content, so they are visible without opening Details.
fn payload(c: &ViewContent) -> String {
    let mut b = String::from("<section class=\"payload\" aria-label=\"Payload to send\">\n");
    b.push_str("<p class=\"label\">This request will be sent</p>\n");
    b.push_str(&format!(
        "<p class=\"req\"><span class=\"method\">{}</span> <span class=\"route\">{}</span></p>\n",
        escape(&c.method),
        escape(&c.route)
    ));
    b.push_str(&format!("<p class=\"path\">{}</p>\n", escape(&c.path)));
    b.push_str("<p class=\"label\">Message content</p>\n");
    if c.body_lossy {
        b.push_str("<p class=\"banner\"><strong>The body is not valid UTF-8.</strong> Invalid bytes are shown as U+FFFD; Discord receives the original bytes.</p>\n");
    }
    b.push_str(&extra_fields_line(&c.body_text));
    let shown = message_content(&c.body_text).unwrap_or_else(|| c.body_text.clone());
    b.push_str(&format!("<pre class=\"body\">{}</pre>\n", escape(&shown)));
    b.push_str("</section>\n");
    b
}

/// The approve and deny buttons. `csrf` is the token for their forms; without it both buttons are
/// disabled (every state but `Pending`).
fn actions(id: &str, csrf: Option<&str>) -> String {
    let mut b = String::from("<div class=\"actions\">\n");
    for (action, label, class) in [
        ("approve", "Approve", "btn approve"),
        ("deny", "Deny", "btn deny"),
    ] {
        match csrf {
            Some(token) => b.push_str(&format!(
                "<form method=\"post\" action=\"/pending/{id}/{action}\">\
<input type=\"hidden\" name=\"csrf\" value=\"{token}\">\
<button class=\"{class}\" type=\"submit\">{label}</button></form>\n",
                id = escape(id),
                token = escape(token),
            )),
            None => b.push_str(&format!(
                "<form><button class=\"{class}\" type=\"button\" disabled>{label}</button></form>\n"
            )),
        }
    }
    b.push_str("</div>\n");
    b
}

/// The secondary facts, closed by default: identity, upstream, query, content type, size, digest,
/// the caller connection, the forwarded headers and, when the message content was decoded, the raw
/// JSON body.
fn details(v: &View, c: &ViewContent) -> String {
    let mut t = String::from("<details>\n<summary>Details</summary>\n<table>\n");
    t.push_str(&row("Identity", &escape(&v.identity)));
    t.push_str(&row("Sent to", &escape(&c.upstream)));
    t.push_str(&row(
        "Query",
        &c.query
            .as_deref()
            .map_or_else(|| "(none)".to_string(), escape),
    ));
    t.push_str(&row(
        "Content type",
        &c.content_type
            .as_deref()
            .map_or_else(|| "(none)".to_string(), escape),
    ));
    t.push_str(&row("Body size", &format!("{} bytes", c.body_len)));
    t.push_str(&row("Digest", &escape(&c.digest)));
    t.push_str(&row("Caller connection", "unknown"));
    t.push_str("</table>\n");
    t.push_str("<h2>Headers that will be forwarded</h2>\n<table>\n");
    for h in &c.headers {
        let value = match &h.value {
            Some(v) => escape(v),
            None => "present (value not shown)".to_string(),
        };
        t.push_str(&row(&h.name, &value));
    }
    t.push_str("</table>\n");
    if message_content(&c.body_text).is_some() {
        t.push_str("<h2>Raw body</h2>\n");
        t.push_str(&format!(
            "<pre class=\"body\">{}</pre>\n",
            escape(&c.body_text)
        ));
    }
    t.push_str("</details>\n");
    t
}

/// The page for one entry. `csrf` is the token for the approve and deny forms; without it the
/// buttons are disabled.
pub fn entry(v: &View, csrf: Option<&str>) -> String {
    let mut b = header(v);
    match v.state {
        State::Superseded => {
            b.push_str("<p class=\"banner\"><strong>Superseded.</strong> A newer identical request replaced this one; nothing was sent for it.");
            if let Some(n) = &v.superseded_by {
                b.push_str(&format!(
                    " Decide on <a href=\"/pending/{0}\">the newest request {0}</a>.",
                    escape(n)
                ));
            }
            b.push_str("</p>\n");
        }
        State::Pending => {}
        other => b.push_str(&format!(
            "<p class=\"banner\">This request is {} and can no longer be decided.</p>\n",
            state_str(other)
        )),
    }
    if let Some(c) = &v.content {
        b.push_str(&payload(c));
    }
    b.push_str(&actions(&v.id, csrf));
    if let Some(c) = &v.content {
        b.push_str(&details(v, c));
    }
    b.push_str("<p class=\"foot\"><a href=\"/pending\">Pending requests</a></p>\n");
    shell(&format!("Request {}", v.id), &b)
}

/// The read-only page for a `Pending` hold, reached by its one-time view link. It has no form,
/// no buttons and no token: the owner decides in Telegram.
pub fn view_only(v: &View) -> String {
    let mut b = header(v);
    b.push_str("<p class=\"note\">Read only. Decide in Telegram.</p>\n");
    if let Some(c) = &v.content {
        b.push_str(&payload(c));
        b.push_str(&details(v, c));
    }
    shell(&format!("Request {}", v.id), &b)
}

/// The summary of one pending entry, for the JSON list.
pub fn summary_json(v: &View) -> Value {
    match &v.content {
        Some(c) => json!({
            "id": v.id,
            "identity": v.identity,
            "method": c.method,
            "route": c.route,
            "path": c.path,
            "body_len": c.body_len,
        }),
        None => json!({"id": v.id, "state": state_str(v.state)}),
    }
}

/// The JSON for one entry. `csrf` is present only while the entry is `Pending`.
pub fn entry_json(v: &View, csrf: Option<&str>) -> Value {
    let mut out = json!({
        "id": v.id,
        "state": state_str(v.state),
        "identity": v.identity,
    });
    let map = out.as_object_mut().expect("object");
    if let Some(n) = &v.superseded_by {
        map.insert("newest".into(), json!(n));
    }
    if let Some(c) = &v.content {
        let headers: Vec<Value> = c
            .headers
            .iter()
            .map(|h| match &h.value {
                Some(value) => json!({"name": h.name, "value": value}),
                None => json!({"name": h.name, "credential": "present"}),
            })
            .collect();
        map.insert("method".into(), json!(c.method));
        map.insert("route".into(), json!(c.route));
        map.insert("upstream".into(), json!(c.upstream));
        map.insert("path".into(), json!(c.path));
        map.insert("query".into(), json!(c.query));
        map.insert("content_type".into(), json!(c.content_type));
        map.insert("body_len".into(), json!(c.body_len));
        map.insert("body".into(), json!(c.body_text));
        map.insert("body_lossy".into(), json!(c.body_lossy));
        map.insert("digest".into(), json!(c.digest));
        map.insert("headers".into(), json!(headers));
        map.insert("connection".into(), json!("unknown"));
    }
    if let Some(t) = csrf {
        map.insert("csrf".into(), json!(t));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hold::ViewHeader;

    fn pending(body: &str) -> View {
        View {
            id: "a".repeat(32),
            state: State::Pending,
            identity: "muse-pilot".into(),
            superseded_by: None,
            content: Some(ViewContent {
                method: "POST".into(),
                route: "discord".into(),
                upstream: "https://discord.example.test:443".into(),
                path: "/webhooks/123/<redacted>".into(),
                query: Some("wait=true".into()),
                content_type: Some("application/json".into()),
                body_len: body.len(),
                body_text: body.into(),
                body_lossy: false,
                digest: "d".repeat(64),
                headers: vec![
                    ViewHeader {
                        name: "authorization".into(),
                        value: None,
                    },
                    ViewHeader {
                        name: "x-note".into(),
                        value: Some("<b>v</b>".into()),
                    },
                ],
                held_secs: 12,
                remaining_secs: 288,
            }),
        }
    }

    #[test]
    fn escape_covers_the_five_characters() {
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn script_body_and_header_values_are_escaped() {
        let html = entry(&pending("<script>alert(1)</script>"), Some("tok"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<b>v</b>") && html.contains("&lt;b&gt;v&lt;/b&gt;"));
        assert!(html.contains("present (value not shown)"));
        assert!(html.contains("name=\"csrf\" value=\"tok\""));
        assert!(!html.contains(" style="), "no inline style attribute");
        assert!(html.contains(&format!("<style>{STYLE}</style>")));
    }

    #[test]
    fn every_dynamic_value_in_the_payload_and_details_is_escaped() {
        let mut v = pending("x");
        v.identity = "<i>id</i>".into();
        let c = v.content.as_mut().unwrap();
        c.route = "<r>".into();
        c.path = "/p/\"'<q>".into();
        c.query = Some("a=<x>&b=\"y\"".into());
        c.content_type = Some("<ct>".into());
        c.upstream = "https://<up>:443".into();
        let html = entry(&v, None);
        for raw in ["<i>", "<r>", "<q>", "<x>", "<ct>", "<up>", "\"y\""] {
            assert!(!html.contains(raw), "{raw} reached the page");
        }
        assert!(html.contains("&lt;r&gt;") && html.contains("&lt;i&gt;id&lt;/i&gt;"));
    }

    #[test]
    fn the_details_section_is_present_and_closed_by_default() {
        let html = entry(&pending("{}"), Some("t"));
        assert_eq!(html.matches("<details").count(), 1);
        assert!(html.contains("<details>\n<summary>Details</summary>"));
        assert!(!html.contains("<details open"), "details must start closed");
        let d = html.find("<details>").unwrap();
        for key in [
            "Sent to",
            "Digest",
            "Caller connection",
            "Headers that will be forwarded",
        ] {
            assert!(html.find(key).unwrap() > d, "{key} is outside details");
        }
    }

    #[test]
    fn the_payload_block_comes_first_with_the_buttons_and_before_details() {
        let html = entry(&pending("hello"), Some("t"));
        let payload = html.find("<section class=\"payload\"").unwrap();
        let actions = html.find("<div class=\"actions\">").unwrap();
        let details = html.find("<details>").unwrap();
        assert!(payload < actions && actions < details);
        assert!(html.contains("<pre class=\"body\">hello</pre>"));
        assert!(html.contains("<p class=\"req\"><span class=\"method\">POST</span>"));
        assert!(html.contains("Held 12 s ago · 288 s left"));
    }

    #[test]
    fn the_view_page_has_the_payload_and_no_form_or_button() {
        let html = view_only(&pending("hello"));
        assert!(html.contains("<section class=\"payload\""));
        assert!(html.contains("Read only. Decide in Telegram."));
        assert!(!html.contains("<form") && !html.contains("<button") && !html.contains("csrf"));
        assert!(html.find("<details>").unwrap() > html.find("<pre class=\"body\"").unwrap());
    }

    #[test]
    fn no_external_resource_or_script_is_loaded() {
        for html in [entry(&pending("{}"), Some("t")), view_only(&pending("{}"))] {
            for banned in [
                "<script",
                "<link",
                "<img",
                "<iframe",
                "<object",
                "src=",
                "@import",
                "url(",
                "href=\"http",
            ] {
                assert!(!html.contains(banned), "page contains {banned}");
            }
        }
    }

    #[test]
    fn the_csp_pins_the_one_stylesheet_by_hash() {
        let hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
        assert_eq!(
            csp(),
            format!("default-src 'none'; style-src 'sha256-{hash}'; frame-ancestors 'none'; form-action 'self'")
        );
        assert!(!csp().contains("unsafe-"), "no unsafe source in the CSP");
    }

    #[test]
    fn the_page_and_the_json_name_the_upstream_the_request_goes_to() {
        let v = pending("{}");
        let html = entry(&v, None);
        assert!(html.contains("Sent to") && html.contains("https://discord.example.test:443"));
        let j = entry_json(&v, None);
        assert_eq!(j["upstream"], "https://discord.example.test:443");
    }

    #[test]
    fn superseded_page_has_a_banner_a_link_and_disabled_buttons() {
        let v = View {
            id: "a".repeat(32),
            state: State::Superseded,
            identity: "muse-pilot".into(),
            superseded_by: Some("b".repeat(32)),
            content: None,
        };
        let html = entry(&v, None);
        assert!(html.contains("Superseded."));
        assert!(html.contains(&format!("href=\"/pending/{}\"", "b".repeat(32))));
        assert!(html.contains("disabled") && !html.contains("<form method"));
    }

    #[test]
    fn invalid_utf8_gets_a_banner() {
        let mut v = pending("x");
        v.content.as_mut().unwrap().body_lossy = true;
        assert!(entry(&v, Some("t")).contains("not valid UTF-8"));
        assert!(!entry(&pending("x"), Some("t")).contains("not valid UTF-8"));
    }

    #[test]
    fn json_view_lists_credentials_as_present_and_carries_the_token() {
        let j = entry_json(&pending("{}"), Some("tok"));
        assert_eq!(j["csrf"], "tok");
        assert_eq!(j["connection"], "unknown");
        assert_eq!(
            j["headers"][0],
            json!({"name":"authorization","credential":"present"})
        );
        assert!(entry_json(&pending("{}"), None).get("csrf").is_none());
    }

    fn with_body(body: &str) -> View {
        let mut v = pending(body);
        v.content.as_mut().unwrap().body_len = body.len();
        v
    }

    #[test]
    fn decoded_content_is_shown_in_the_message_block() {
        let html = entry(
            &with_body(r#"{"content":"Stage 2 gate test \uff5c \u5c0f"}"#),
            Some("t"),
        );
        let block = html.find("<pre class=\"body\">").unwrap();
        let shown = "<pre class=\"body\">Stage 2 gate test \u{ff5c} \u{5c0f}</pre>";
        assert!(html.contains(shown), "{html}");
        assert!(html.find(shown).unwrap() < html.find("<details>").unwrap());
        assert!(block < html.find("<details>").unwrap());
    }

    #[test]
    fn malformed_json_falls_back_to_the_raw_text() {
        for body in [r#"{"content":"x""#, "not json", "\"plain\"", "[1,2]", "{}"] {
            let html = entry(&with_body(body), Some("t"));
            let escaped = escape(body);
            assert!(
                html.contains(&format!("<pre class=\"body\">{escaped}</pre>")),
                "{body} did not fall back: {html}"
            );
            assert_eq!(html.matches("<h2>Raw body</h2>").count(), 0, "{body}");
        }
    }

    #[test]
    fn a_non_string_content_field_falls_back_to_the_raw_text() {
        let body = r#"{"content":5}"#;
        let html = entry(&with_body(body), Some("t"));
        assert!(html.contains(&format!("<pre class=\"body\">{}</pre>", escape(body))));
    }

    #[test]
    fn the_raw_json_appears_only_inside_details() {
        let body = r#"{"content":"Stage 2 gate test \uff5c \u5c0f"}"#;
        let html = entry(&with_body(body), Some("t"));
        let details = html.find("<details>").unwrap();
        assert_eq!(html.matches(&escape(body)).count(), 1, "{html}");
        assert!(html.find(&escape(body)).unwrap() > details);
        assert!(!html.contains("<details open"));
        let view = view_only(&with_body(body));
        assert_eq!(view.matches(&escape(body)).count(), 1);
        assert!(view.find(&escape(body)).unwrap() > view.find("<details>").unwrap());
    }

    #[test]
    fn escaping_applies_to_the_decoded_content() {
        let body = r#"{"content":"<script>alert(1)<\/script> \u003cb\u003e"}"#;
        let html = entry(&with_body(body), Some("t"));
        assert!(!html.contains("<script>alert(1)"), "{html}");
        assert!(!html.contains("<b>"), "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &lt;b&gt;"));
    }

    #[test]
    fn a_content_only_body_shows_no_extra_fields_line() {
        let html = entry(&with_body(r#"{"content":"hi"}"#), Some("t"));
        assert!(!html.contains("extra-fields"), "{html}");
        assert!(!view_only(&with_body(r#"{"content":"hi"}"#)).contains("extra-fields"));
    }

    #[test]
    fn a_field_besides_content_is_named_above_details_and_its_value_is_not() {
        let body = r#"{"content":"hi","username":"SYNTH-VALUE-7"}"#;
        let html = entry(&with_body(body), Some("t"));
        let line_start = html
            .find("<p class=\"banner extra-fields\">")
            .expect("indicator");
        let line_end = line_start + html[line_start..].find("</p>").unwrap();
        let line = &html[line_start..line_end];
        assert!(
            line.contains("+ 1 more field will be sent: username (see Details)"),
            "{line}"
        );
        assert!(!line.contains("SYNTH-VALUE-7"), "{line}");
        assert!(line_end < html.find("<details>").unwrap());
        assert!(line_start < html.find("<pre class=\"body\">").unwrap());
        let view = view_only(&with_body(body));
        assert!(view.contains("+ 1 more field will be sent: username"));
    }

    #[test]
    fn the_extra_field_name_is_escaped() {
        let body = r#"{"content":"hi","<b>x</b>":1,"embeds":[]}"#;
        let html = entry(&with_body(body), Some("t"));
        assert!(
            html.contains(
                "+ 2 more fields will be sent: &lt;b&gt;x&lt;/b&gt;, embeds (see Details)"
            ),
            "{html}"
        );
        assert!(!html.contains("<b>x</b>"), "{html}");
    }
}
