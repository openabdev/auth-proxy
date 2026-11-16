//! Q3-A validation: the doc sketch is accepted, every listed rule rejects.

use ap_core::config::{parse_host_port, Config, CredentialSource};
use ap_core::testing::{sample_toml, SAMPLE_CALLER_SHA256};

fn rejects(label: &str, from: &str, to: &str, needle: &str) {
    let base = sample_toml();
    assert!(base.contains(from), "{label}: fixture lacks {from:?}");
    let mutated = base.replacen(from, to, 1);
    let err = Config::parse(mutated.as_bytes()).expect_err(label);
    let msg = err.to_string();
    assert!(msg.contains(needle), "{label}: {msg:?} lacks {needle:?}");
}

fn rejects_append(label: &str, extra: &str, needle: &str) {
    let mutated = format!("{}\n{extra}", sample_toml());
    let err = Config::parse(mutated.as_bytes()).expect_err(label);
    let msg = err.to_string();
    assert!(msg.contains(needle), "{label}: {msg:?} lacks {needle:?}");
}

#[test]
fn accepts_the_doc_sketch() {
    let c = Config::parse(sample_toml().as_bytes()).unwrap();
    assert_eq!(c.version, 1);
    assert_eq!(c.identity, "pty-team-a");
    assert_eq!(c.caller_key_sha256, SAMPLE_CALLER_SHA256);
    assert_eq!(c.routes.len(), 5);
    assert_eq!(c.credentials.len(), 2);
    assert_eq!(c.grants.len(), 3);
    assert_eq!(c.egress.entries().len(), 6);
    assert_eq!(
        c.credential("kiro").unwrap().source,
        CredentialSource::K8s {
            secret: "auth-proxy-kiro".into(),
            key: "api_key".into()
        }
    );
    let krs = c.route("kiro-krs").unwrap();
    assert_eq!(krs.port, 443);
    assert_eq!(krs.credential_scheme, "Bearer");
    assert_eq!(krs.pass_headers, ["tokentype"]);
    assert_eq!(krs.authority(), "runtime.us-east-1.kiro.dev");
}

#[test]
fn rejects_top_level() {
    rejects("version", "version = 1", "version = 2", "version must be 1");
    rejects(
        "identity",
        "identity = \"pty-team-a\"",
        "identity = \"a b\"",
        "identity",
    );
    rejects(
        "identity empty",
        "identity = \"pty-team-a\"",
        "identity = \"\"",
        "identity",
    );
    rejects(
        "hash length",
        SAMPLE_CALLER_SHA256,
        &SAMPLE_CALLER_SHA256[..63],
        "64 lowercase hex",
    );
    rejects(
        "hash upper-case",
        SAMPLE_CALLER_SHA256,
        &SAMPLE_CALLER_SHA256.to_uppercase(),
        "64 lowercase hex",
    );
    rejects_append("unknown top-level key", "bogus = 1", "unknown field");
    rejects_append(
        "unknown route key",
        "[[route]]\nname = \"x\"\nhost = \"a.b\"\nbogus = 1",
        "unknown field",
    );
}

#[test]
fn rejects_routes() {
    rejects(
        "route name case",
        "name = \"anthropic\"",
        "name = \"Anthropic\"",
        "route name",
    );
    rejects(
        "route name empty",
        "name = \"anthropic\"",
        "name = \"\"",
        "route name",
    );
    rejects(
        "route name too long",
        "name = \"anthropic\"",
        &format!("name = \"{}\"", "a".repeat(33)),
        "route name",
    );
    rejects(
        "route name underscore",
        "name = \"kiro-q\"",
        "name = \"kiro_q\"",
        "route name",
    );
    rejects(
        "route name duplicate",
        "name = \"kiro-q\"",
        "name = \"kiro-cw\"",
        "not unique",
    );
    for (label, host) in [
        ("ip literal", "127.0.0.1"),
        ("ipv6", "[::1]"),
        ("numeric tld", "127.1"),
        ("userinfo", "user@api.x.com"),
        ("port", "api.x.com:443"),
        ("trailing dot", "api.x.com."),
        ("upper", "API.x.com"),
        ("single label", "localhost"),
        ("empty label", "a..b"),
    ] {
        rejects(
            label,
            "host = \"api.anthropic.com\"",
            &format!("host = \"{host}\""),
            "upstream host rejected",
        );
    }
    rejects(
        "port 0",
        "host = \"api.anthropic.com\"",
        "host = \"api.anthropic.com\"\nport = 0",
        "port 0",
    );
    rejects(
        "unknown surrogate header",
        "surrogate_header = \"x-api-key\"",
        "surrogate_header = \"x-custom\"",
        "not a known auth header",
    );
    rejects(
        "unknown credential header",
        "credential_header = \"x-api-key\"",
        "credential_header = \"x-custom\"",
        "not a known auth header",
    );
    rejects(
        "pass header stripped",
        "pass_headers = [\"tokentype\"]",
        "pass_headers = [\"authorization\"]",
        "stripped by design",
    );
    rejects(
        "pass header hop",
        "pass_headers = [\"tokentype\"]",
        "pass_headers = [\"host\"]",
        "stripped by design",
    );
    rejects(
        "pass header upper",
        "pass_headers = [\"tokentype\"]",
        "pass_headers = [\"TokenType\"]",
        "lowercase header name",
    );
    rejects(
        "bad scheme",
        "surrogate_scheme = \"\"",
        "surrogate_scheme = \"Bearer x\"",
        "surrogate_scheme",
    );
}

#[test]
fn rejects_credentials() {
    rejects(
        "credential route missing",
        "routes = [\"anthropic\"]",
        "routes = [\"nope\"]",
        "does not exist",
    );
    rejects(
        "credential routes empty",
        "routes = [\"anthropic\"]",
        "routes = []",
        "routes is empty",
    );
    rejects(
        "credential route twice",
        "routes = [\"anthropic\"]",
        "routes = [\"anthropic\", \"anthropic\"]",
        "listed twice",
    );
    rejects(
        "credential id dup",
        "id = \"anthropic\"",
        "id = \"kiro\"",
        "not unique",
    );
    rejects(
        "credential id bad",
        "id = \"anthropic\"",
        "id = \"a b\"",
        "credential id",
    );
    for (label, src, needle) in [
        ("aws deferred", "aws:secretsmanager:prod/key", "deferred"),
        ("unknown scheme", "vault:x", "unknown source scheme"),
        ("k8s no key", "k8s:only-secret", "k8s:<secret>:<key>"),
        ("k8s upper secret", "k8s:Bad:key", "bad secret name"),
        ("k8s dotdot key", "k8s:s:..", "bad key name"),
        ("k8s slash key", "k8s:s:a/b", "bad key name"),
        ("file relative", "file:rel/path", "absolute path"),
        ("file dotdot", "file:/a/../b", "absolute path"),
        ("env digit", "env:1X", "env:<NAME>"),
        ("env empty", "env:", "env:<NAME>"),
    ] {
        rejects(
            label,
            "source = \"k8s:auth-proxy-anthropic:api_key\"",
            &format!("source = \"{src}\""),
            needle,
        );
    }
}

#[test]
fn accepts_file_and_env_source_syntax() {
    for src in [
        "file:/run/secrets/key",
        "env:ANTHROPIC_API_KEY",
        "k8s:s.v1:k_2",
    ] {
        let t = sample_toml().replacen(
            "source = \"k8s:auth-proxy-anthropic:api_key\"",
            &format!("source = \"{src}\""),
            1,
        );
        Config::parse(t.as_bytes()).unwrap_or_else(|e| panic!("{src}: {e}"));
    }
}

#[test]
fn rejects_grants() {
    rejects(
        "grant credential missing",
        "credential = \"anthropic\"\nroute = \"anthropic\"",
        "credential = \"ghost\"\nroute = \"anthropic\"",
        "credential \"ghost\" does not exist",
    );
    rejects(
        "grant route not in credential",
        "credential = \"anthropic\"\nroute = \"anthropic\"",
        "credential = \"anthropic\"\nroute = \"kiro-q\"",
        "is not one of credential",
    );
    rejects(
        "methods lower-case",
        "methods = [\"POST\"]\npaths = [\"/v1/\"]",
        "methods = [\"post\"]\npaths = [\"/v1/\"]",
        "upper-case token",
    );
    rejects(
        "methods empty",
        "methods = [\"POST\"]\npaths = [\"/v1/\"]",
        "methods = []\npaths = [\"/v1/\"]",
        "methods is empty",
    );
    rejects(
        "paths empty",
        "paths = [\"/v1/\"]",
        "paths = []",
        "paths is empty",
    );
    for (label, p, needle) in [
        ("no leading slash", "v1/", "must start with '/'"),
        ("no trailing slash", "/v1", "must end with '/'"),
        ("dot segment", "/v1/./x/", "dot segment"),
        ("dotdot segment", "/v1/../x/", "dot segment"),
        ("percent", "/v1/%2e/", "'%'"),
        ("double slash", "/v1//x/", "'//'"),
        ("backslash", "/v1\\\\x/", "must not contain '%'"),
        ("query", "/v1/?x/", "'?'"),
        ("non-ascii", "/v1/é/", "printable ASCII"),
    ] {
        rejects(
            label,
            "paths = [\"/v1/\"]",
            &format!("paths = [\"{p}\"]"),
            needle,
        );
    }
    rejects(
        "aws target comma",
        "aws_targets = [\"AmazonCodeWhispererStreamingService.GenerateAssistantResponse\"]",
        "aws_targets = [\"A.b, C.d\"]",
        "aws_targets",
    );
    rejects(
        "aws target empty",
        "aws_targets = [\"AmazonCodeWhispererStreamingService.GenerateAssistantResponse\"]",
        "aws_targets = [\"\"]",
        "aws_targets",
    );
}

#[test]
fn grant_count_limit_is_256() {
    let grant = "\n[[grant]]\ncredential = \"anthropic\"\nroute = \"anthropic\"\nmethods = [\"POST\"]\npaths = [\"/v1/\"]\n";
    // the sample has 3 grants
    let ok = format!("{}{}", sample_toml(), grant.repeat(253));
    assert_eq!(Config::parse(ok.as_bytes()).unwrap().grants.len(), 256);
    let too_many = format!("{}{}", sample_toml(), grant.repeat(254));
    let e = Config::parse(too_many.as_bytes()).unwrap_err().to_string();
    assert!(e.contains("more than 256 grants"), "{e}");
}

#[test]
fn rejects_egress() {
    for (label, entry, needle) in [
        ("no port", "github.com", "host:port"),
        ("port 0", "github.com:0", "1..=65535"),
        ("port too big", "github.com:65536", "1..=65535"),
        ("port non-digit", "github.com:44x", "digits"),
        ("port plus", "github.com:+443", "digits"),
        ("ip literal", "10.0.0.1:443", "host rejected"),
        ("ipv6", "[::1]:443", "host rejected"),
        ("upper host", "GitHub.com:443", "host rejected"),
        ("userinfo", "u@github.com:443", "host rejected"),
        ("trailing dot", "github.com.:443", "host rejected"),
        (
            "credential route host",
            "api.anthropic.com:443",
            "credential route host",
        ),
        (
            "credential route host other port",
            "runtime.us-east-1.kiro.dev:8443",
            "credential route host",
        ),
    ] {
        rejects(
            label,
            "allow = [\"github.com:443\",",
            &format!("allow = [\"{entry}\","),
            needle,
        );
    }
    // explicit opt-out
    let t = sample_toml()
        .replacen(
            "allow = [\"github.com:443\",",
            "allow = [\"api.anthropic.com:443\",",
            1,
        )
        .replacen("[egress]", "[egress]\nallow_route_hosts = true", 1);
    Config::parse(t.as_bytes()).unwrap();
}

#[test]
fn route_host_check_only_covers_routes_used_by_a_credential() {
    // a route that no credential references does not block an egress entry
    let t = sample_toml().replacen(
        "allow = [\"github.com:443\",",
        "allow = [\"unused.example.com:443\",",
        1,
    ) + "\n[[route]]\nname = \"unused\"\nhost = \"unused.example.com\"\n";
    Config::parse(t.as_bytes()).unwrap();
}

#[test]
fn listener_is_one_loopback_address_only() {
    let with = |l: &str| format!("{}\n{l}", sample_toml());
    let ok = with("[listener]\nlisten = \"127.0.0.1:18080\"");
    let c = Config::parse(ok.as_bytes()).unwrap();
    assert_eq!(
        c.listener.unwrap().effective_authorities(),
        ["127.0.0.1:18080", "localhost:18080"]
    );
    Config::parse(with("[listener]\nlisten = \"[::1]:18080\"").as_bytes()).unwrap();
    for (label, l, needle) in [
        (
            "all interfaces",
            "[listener]\nlisten = \"0.0.0.0:8080\"",
            "not a loopback",
        ),
        (
            "lan",
            "[listener]\nlisten = \"192.168.0.5:8080\"",
            "not a loopback",
        ),
        (
            "port 0",
            "[listener]\nlisten = \"127.0.0.1:0\"",
            "port must not be 0",
        ),
        (
            "second listener key",
            "[listener]\nlisten = \"127.0.0.1:8080\"\nadmin_listen = \"127.0.0.1:9000\"",
            "unknown field",
        ),
        (
            "two listeners",
            "[listener]\nlisten = [\"127.0.0.1:8080\", \"127.0.0.1:8081\"]",
            "invalid",
        ),
        (
            "array of tables",
            "[[listener]]\nlisten = \"127.0.0.1:8080\"\n[[listener]]\nlisten = \"127.0.0.1:8081\"",
            "invalid",
        ),
        (
            "authority with space",
            "[listener]\nlisten = \"127.0.0.1:8080\"\nauthorities = [\"a b\"]",
            "plain Host",
        ),
    ] {
        let e = Config::parse(with(l).as_bytes())
            .expect_err(label)
            .to_string();
        assert!(e.contains(needle), "{label}: {e}");
    }
}

#[test]
fn errors_are_reported_together() {
    let t = sample_toml()
        .replacen("version = 1", "version = 9", 1)
        .replacen("name = \"anthropic\"", "name = \"A\"", 1);
    let e = Config::parse(t.as_bytes()).unwrap_err();
    assert!(e.0.len() >= 2, "{e}");
}

#[test]
fn empty_and_garbage_files_are_errors() {
    for raw in [&b""[..], b"\xff\xfe", b"not = [toml", b"version = 1\n"] {
        assert!(Config::parse(raw).is_err());
    }
    assert!(Config::parse(&vec![b'#'; 1024 * 1024 + 1]).is_err());
}

#[test]
fn host_port_parser() {
    assert_eq!(
        parse_host_port("github.com:443").unwrap(),
        ("github.com".into(), 443)
    );
    assert!(parse_host_port("github.com:").is_err());
    assert!(parse_host_port(":443").is_err());
}
