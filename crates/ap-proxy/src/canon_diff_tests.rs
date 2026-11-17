//! Differential test for the sidecar pipeline: for every accepted request, the path that the
//! policy matched is byte-identical to the path the upstream received; every other request is
//! refused before anything is sent. Inputs come from a fixed-seed generator over the classes in
//! issue #19. The mock upstream is the one the other pipeline tests use.

use std::sync::atomic::Ordering;

use axum::body::{to_bytes, Body};
use axum::extract::Request;

use crate::pipeline::handle;
use crate::test_support::{
    register_session, start_upstream, Fixture, CAP, IDENTITY, LISTEN, ROUTE,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

const ATOMS: &[&str] = &[
    "a", "v1", "msg", "..", ".", "...", "%2e", "%2E", "%2f", "%5c", "%00", "%25", "%252f", "%255c",
    "%2500", "%", "%zz", ";", "a;b", "..;", ".;x", "\\", "{", "}", "|", "^", "\"", "<", ">", "`",
    "[", "]", "@", ":", "*", "~", "é", "\u{ff0e}", "%C3%A9", "%41", "+", "=", "&", "!", "$", "'",
    "(", ")", ",", "-", "_", "ap", "up", "%20", " ",
];
const SEPS: &[&str] = &["/", "/", "/", "", "//"];

fn gen(r: &mut Rng) -> String {
    let mut p = String::new();
    for _ in 0..(1 + r.below(5)) {
        p.push_str(r.pick(SEPS));
        p.push_str(r.pick(ATOMS));
    }
    p
}

#[tokio::test]
async fn matched_path_is_the_forwarded_path() {
    let up = start_upstream().await;
    let f = Fixture::new("canon-diff", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);
    let mut r = Rng(0x19C0_FFEE_5EED);
    let (mut forwarded, mut refused, mut unparsed) = (0, 0, 0);
    let mut mismatches: Vec<String> = Vec::new();

    for i in 0..600 {
        // `/echo2` makes the mock upstream answer with the request target it received.
        let p = format!("{}/echo2", gen(&mut r));
        let again = match r.below(4) {
            0 => format!("/ap/{}/{ROUTE}", f.caller),
            _ => String::new(),
        };
        let target = format!("/ap/{}/{ROUTE}{again}{p}", f.caller);
        let Ok(req) = Request::builder()
            .method("GET")
            .uri(&target)
            .header("host", LISTEN)
            .header("authorization", format!("Bearer {surrogate}"))
            .body(Body::empty())
        else {
            unparsed += 1;
            continue;
        };
        let hits_before = up.hits.load(Ordering::SeqCst);
        let audit_before = f.audit_text().lines().count();
        let resp = handle(std::sync::Arc::clone(&f.app), req).await;
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        if status != 200 {
            refused += 1;
            if status != 502 {
                assert_eq!(
                    up.hits.load(Ordering::SeqCst),
                    hits_before,
                    "#{i} {target:?}: refused with {status} but upstream was contacted"
                );
            }
            continue;
        }
        forwarded += 1;
        let seen: serde_json::Value = serde_json::from_slice(&body).expect("echo2 json");
        let got = seen["path"].as_str().expect("path").to_string();
        let want = format!("{again}{p}");
        let text = f.audit_text();
        let line = text.lines().nth(audit_before).expect("audit line");
        let rec: serde_json::Value = serde_json::from_str(line).expect("audit json");
        let matched = rec["path"].as_str().expect("audit path").to_string();
        if got != want || matched != want {
            mismatches.push(format!(
                "request {target:?}: policy matched {matched:?}, upstream got {got:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "matched path differs from forwarded path:\n{}",
        mismatches.join("\n")
    );
    assert!(forwarded > 50, "too few accepted requests: {forwarded}");
    assert!(refused > 50, "too few refused requests: {refused}");
    eprintln!("canon diff: forwarded={forwarded} refused={refused} unparsed={unparsed} cap={CAP}");
}
