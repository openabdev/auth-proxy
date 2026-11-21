//! The approval pages (design 3.6) and the JSON views the same API serves.
//!
//! Every value that came from a request is escaped here, and the pages carry no script and no
//! inline style. A credential header value is never in a [`View`], so it cannot reach a page; the
//! page shows that the header is present.

use serde_json::{json, Value};

use crate::hold::{State, View, ViewContent};

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
<title>{}</title></head><body>\n{body}</body></html>\n",
        escape(title)
    )
}

/// A one-line message page (errors and results).
pub fn message(title: &str, text: &str, newest: Option<&str>) -> String {
    let mut b = format!("<h1>{}</h1>\n<p>{}</p>\n", escape(title), escape(text));
    if let Some(n) = newest {
        b.push_str(&format!(
            "<p>Newer request: <a href=\"/pending/{0}\">{0}</a></p>\n",
            escape(n)
        ));
    }
    b.push_str("<p><a href=\"/pending\">Pending requests</a></p>\n");
    shell(title, &b)
}

/// The list of pending entries.
pub fn list(items: &[View]) -> String {
    let mut b = String::from("<h1>Pending requests</h1>\n");
    if items.is_empty() {
        b.push_str("<p>No request is waiting.</p>\n");
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

fn content_table(v: &View, c: &ViewContent) -> String {
    let mut t = String::from("<table border=\"1\">\n");
    t.push_str(&row("Identity", &escape(&v.identity)));
    t.push_str(&row("Method", &escape(&c.method)));
    t.push_str(&row("Route", &escape(&c.route)));
    t.push_str(&row("Sent to", &escape(&c.upstream)));
    t.push_str(&row("Path", &escape(&c.path)));
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
    t
}

fn headers_table(c: &ViewContent) -> String {
    let mut t = String::from("<h2>Headers that will be forwarded</h2>\n<table border=\"1\">\n");
    for h in &c.headers {
        let value = match &h.value {
            Some(v) => escape(v),
            None => "present (value not shown)".to_string(),
        };
        t.push_str(&row(&h.name, &value));
    }
    t.push_str("</table>\n");
    t
}

fn buttons(id: &str, csrf: Option<&str>) -> String {
    let mut b = String::new();
    for (action, label) in [("approve", "Approve"), ("deny", "Deny")] {
        match csrf {
            Some(token) => b.push_str(&format!(
                "<form method=\"post\" action=\"/pending/{id}/{action}\">\
<input type=\"hidden\" name=\"csrf\" value=\"{token}\">\
<button type=\"submit\">{label}</button></form>\n",
                id = escape(id),
                token = escape(token),
            )),
            None => b.push_str(&format!(
                "<form><button type=\"button\" disabled>{label}</button></form>\n"
            )),
        }
    }
    b
}

/// The page for one entry. `csrf` is the token for the approve and deny forms; without it the
/// buttons are disabled (every state but `Pending`).
pub fn entry(v: &View, csrf: Option<&str>) -> String {
    let mut b = format!(
        "<h1>Request {}</h1>\n<p>State: {}</p>\n",
        escape(&v.id),
        state_str(v.state)
    );
    match v.state {
        State::Superseded => {
            b.push_str("<p><strong>Superseded.</strong> A newer identical request replaced this one; nothing was sent for it.");
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
            "<p>This request is {} and can no longer be decided.</p>\n",
            state_str(other)
        )),
    }
    if let Some(c) = &v.content {
        b.push_str(&details(v, c));
    }
    b.push_str(&buttons(&v.id, csrf));
    b.push_str("<p><a href=\"/pending\">Pending requests</a></p>\n");
    shell(&format!("Request {}", v.id), &b)
}

/// The read-only page for a `Pending` hold, reached by its one-time view link. It has no form,
/// no buttons and no token: the owner decides in Telegram.
pub fn view_only(v: &View) -> String {
    let mut b = format!(
        "<h1>Request {}</h1>\n<p>State: {}. This page is read only. Decide in Telegram.</p>\n",
        escape(&v.id),
        state_str(v.state)
    );
    if let Some(c) = &v.content {
        b.push_str(&details(v, c));
    }
    shell(&format!("Request {}", v.id), &b)
}

/// The request details shared by the decision page and the read-only view.
fn details(v: &View, c: &ViewContent) -> String {
    let mut b = content_table(v, c);
    if c.body_lossy {
        b.push_str("<p><strong>The body is not valid UTF-8.</strong> Invalid bytes are shown as U+FFFD; Discord receives the original bytes.</p>\n");
    }
    b.push_str(&format!(
        "<h2>Body</h2>\n<pre>{}</pre>\n",
        escape(&c.body_text)
    ));
    b.push_str(&headers_table(c));
    b
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
                path: "/webhooks/1/<redacted>".into(),
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
        assert!(!html.contains("<style") && !html.contains(" style="));
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
}
