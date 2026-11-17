//! Differential test for request canonicalization.
//!
//! A fixed-seed generator produces paths, hosts and headers from the classes in issue #19. Each
//! input goes through the shared invariants (`common/invariants.rs`), which compare our verdict
//! with the `http` and `url` parsers and check that an accepted input is never rewritten. The seed
//! is fixed, so a failure reproduces; the same invariants run under cargo-fuzz for open-ended input.

mod common;
use common::invariants::*;

/// xorshift64*: deterministic, no dependency.
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

const SEED: u64 = 0x19C0_FFEE_5EED;
const KEY: &str = "apk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const PATH_ATOMS: &[&str] = &[
    "a", "v1", "echo", "x", "..", ".", "...", "%2e", "%2E", "%2f", "%2F", "%5c", "%5C", "%00",
    "%25", "%252f", "%252e", "%2525", "%", "%zz", "%e", ";", "a;b", "..;", ".;", "..;x", ";..",
    "\\", "{", "}", "|", "^", "\"", "<", ">", "`", "[", "]", "@", ":", "*", "~", "é", "ap", "apk_",
    "?", "#", "+", "=", "&", "!", "$", "'", "(", ")", ",", "-", "_",
];
const SEPS: &[&str] = &["/", "/", "/", "", "//", "/"];

fn gen_path(r: &mut Rng) -> String {
    let mut p = String::new();
    for _ in 0..(1 + r.below(6)) {
        p.push_str(r.pick(SEPS));
        p.push_str(r.pick(PATH_ATOMS));
    }
    p
}

fn gen_ap_path(r: &mut Rng) -> String {
    let key = match r.below(6) {
        0 => String::new(),
        1 => KEY.to_uppercase(),
        2 => KEY[..KEY.len() - 1].to_string(),
        3 => format!("{KEY}{}", r.pick(PATH_ATOMS)),
        _ => KEY.to_string(),
    };
    let route = r.pick(&["up", "", "UP", "up;x", "up%2f", "..", "ap", "a b", "r-1"]);
    format!("/ap/{key}/{route}{}", gen_path(r))
}

#[test]
fn generated_paths_hold_the_invariants() {
    let mut r = Rng(SEED);
    let mut accepted = 0;
    for _ in 0..40_000 {
        let p = if r.below(2) == 0 {
            gen_path(&mut r)
        } else {
            gen_ap_path(&mut r)
        };
        check_path(&p);
        if !ap_core::canon::path_ambiguous(&p) {
            accepted += 1;
        }
    }
    assert!(accepted > 1000, "generator never reached the accept side");
}

const HOST_ATOMS: &[&str] = &[
    "api",
    "example",
    "com",
    "EXAMPLE",
    "xn--e1afmkfd",
    "xn--a-",
    "xn--",
    "xn--zz",
    "127",
    "0",
    "1",
    "0x7f",
    "0177",
    "300",
    "2130706433",
    "-a",
    "a-",
    "a_b",
    "é",
    "ａ",
    "[::1]",
    "::1",
    "@",
    "u@h",
    ":443",
    "",
    " ",
    "a b",
    "ı",
    "ß",
    "İ",
    "k",
    "K",
];

fn gen_host(r: &mut Rng) -> String {
    let n = 1 + r.below(4);
    let labels: Vec<&str> = (0..n).map(|_| r.pick(HOST_ATOMS)).collect();
    let mut h = labels.join(".");
    match r.below(8) {
        0 => h.push('.'),
        1 => h.push_str(":443"),
        _ => {}
    }
    h
}

#[test]
fn generated_hosts_hold_the_invariants() {
    let mut r = Rng(SEED ^ 1);
    let mut accepted = 0;
    for _ in 0..40_000 {
        let h = gen_host(&mut r);
        check_host(&h);
        if ap_core::canon::canonical_host(&h).is_ok() {
            accepted += 1;
        }
    }
    assert!(accepted > 100, "generator never reached the accept side");
}

#[test]
fn generated_request_targets_hold_the_invariants() {
    let mut r = Rng(SEED ^ 2);
    let expected = "127.0.0.1:8443";
    for _ in 0..20_000 {
        let target = match r.below(5) {
            0 => format!(
                "http://{}{}",
                r.pick(&[expected, "evil.test", "u@127.0.0.1:8443"]),
                gen_path(&mut r)
            ),
            1 => format!("https://{}/x", r.pick(&[expected, "EVIL.test"])),
            2 => gen_path(&mut r),
            3 => format!("//{expected}/x"),
            _ => expected.to_string(),
        };
        let n = r.below(4);
        let hosts: Vec<Vec<u8>> = (0..n)
            .map(|_| {
                r.pick(&[
                    expected,
                    "evil.test",
                    "127.0.0.1:8443 ",
                    "127.0.0.1:8443,evil.test",
                    "u@127.0.0.1:8443",
                    "127.0.0.1.:8443",
                    "[::ffff:127.0.0.1]:8443",
                ])
                .as_bytes()
                .to_vec()
            })
            .collect();
        check_origin(&target, &hosts, r.below(2) == 0, expected);
    }
}

const HDR_NAMES: &[&str] = &[
    "x-ap-caller-key",
    "authorization",
    "content-length",
    "transfer-encoding",
    "connection",
    "host",
    "X-AP-Caller-Key",
    "Authorization",
    "Content-Length",
    "x-other",
];

fn gen_value(r: &mut Rng) -> Vec<u8> {
    let sur = format!("Bearer aps_{}", &KEY[4..]);
    let v: Vec<u8> = match r.below(14) {
        0 => KEY.as_bytes().to_vec(),
        1 => sur.into_bytes(),
        2 => b"5".to_vec(),
        3 => b"5, 5".to_vec(),
        4 => b"+5".to_vec(),
        5 => b"chunked".to_vec(),
        6 => b"CHUNKED".to_vec(),
        7 => b"chunked, chunked".to_vec(),
        8 => b"identity".to_vec(),
        9 => b"close, X-AP-Caller-Key".to_vec(),
        10 => b"keep-alive, Host".to_vec(),
        11 => b"a\r\nX-Injected: 1".to_vec(),
        12 => b"a\r\n folded".to_vec(),
        _ => vec![0xff, b'a'],
    };
    v
}

#[test]
fn generated_headers_hold_the_invariants() {
    let mut r = Rng(SEED ^ 3);
    for _ in 0..30_000 {
        let n = r.below(6);
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
            .map(|_| (r.pick(HDR_NAMES).as_bytes().to_vec(), gen_value(&mut r)))
            .collect();
        check_headers(&pairs, "x-ap-caller-key");
    }
}
