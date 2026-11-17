//! Immutable policy snapshot compiled from a validated config.
//!
//! The snapshot answers one question: may this identity make this request on this route?
//! Reloading is the caller's job (ap-proxy stats the file and swaps in a new snapshot).

use crate::config::{Config, Decision, Grant, Route};
use crate::error::Code;
use std::collections::HashMap;

/// What a matching grant does with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Hold,
}

/// Whole-path segment match. A `*` pattern segment matches exactly one non-empty path segment;
/// every other segment must be equal. The segment counts must match, so a trailing `/` or a
/// longer path never matches.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let (Some(pat), Some(path)) = (pattern.strip_prefix('/'), path.strip_prefix('/')) else {
        return false;
    };
    let mut p = pat.split('/');
    let mut s = path.split('/');
    loop {
        match (p.next(), s.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) => {
                if b.is_empty() || (a != "*" && a != b) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    routes: HashMap<String, Route>,
    grants: HashMap<String, Vec<Grant>>,
}

impl Snapshot {
    /// Compile a snapshot. The config must already have passed `config::load`.
    pub fn from_config(cfg: &Config) -> Snapshot {
        let routes = cfg
            .routes
            .iter()
            .map(|r| (r.name.clone(), r.clone()))
            .collect();
        let mut grants: HashMap<String, Vec<Grant>> = HashMap::new();
        for g in &cfg.grants {
            grants
                .entry(g.identity.clone())
                .or_default()
                .push(g.clone());
        }
        Snapshot { routes, grants }
    }

    /// The route with this name, if the snapshot has one.
    pub fn route(&self, name: &str) -> Option<&Route> {
        self.routes.get(name)
    }

    /// Passthrough decision: `Hold` when a hold grant matches (hold beats allow), `Allow` when
    /// only allow grants match. A grant matches on a `paths` prefix or a `path_patterns` entry
    /// matched against the whole path. Errors follow `evaluate`: `policy_empty` without grants,
    /// `policy_denied` when none matches. `evaluate` itself is unchanged.
    pub fn evaluate_verdict(
        &self,
        identity: &str,
        route: &str,
        method: &str,
        path: &str,
    ) -> Result<Verdict, Code> {
        let grants = match self.grants.get(identity) {
            Some(g) if !g.is_empty() => g,
            _ => return Err(Code::PolicyEmpty),
        };
        let mut verdict = None;
        for g in grants {
            let hit = g.route == route
                && g.methods.iter().any(|m| m == method)
                && (g.paths.iter().any(|p| path.starts_with(p.as_str()))
                    || g.path_patterns.iter().any(|p| pattern_matches(p, path)));
            if !hit {
                continue;
            }
            match g.decision {
                Decision::Hold => return Ok(Verdict::Hold),
                Decision::Allow => verdict = Some(Verdict::Allow),
            }
        }
        verdict.ok_or(Code::PolicyDenied)
    }

    /// Decide whether `identity` may send `method` `path` to `route`.
    ///
    /// `path` is route-relative and already passed `canon::path_ambiguous`.
    /// `aws_targets` holds every `X-Amz-Target` value on the request. A grant that lists
    /// `aws_targets` needs exactly one value, and that value must be listed.
    ///
    /// Returns `policy_empty` when the identity has no grants at all, and `policy_denied`
    /// when it has grants but none matches.
    pub fn evaluate(
        &self,
        identity: &str,
        route: &str,
        method: &str,
        path: &str,
        aws_targets: &[&str],
    ) -> Result<(), Code> {
        let grants = match self.grants.get(identity) {
            Some(g) if !g.is_empty() => g,
            _ => return Err(Code::PolicyEmpty),
        };
        let matched = grants.iter().any(|g| {
            g.route == route
                && g.methods.iter().any(|m| m == method)
                && g.paths.iter().any(|p| path.starts_with(p.as_str()))
                && (g.aws_targets.is_empty()
                    || matches!(aws_targets, [t] if g.aws_targets.iter().any(|a| a == t)))
        });
        if matched {
            Ok(())
        } else {
            Err(Code::PolicyDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load, tests::base};

    const IDLE_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TARGET: &str = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse";

    fn snapshot() -> Snapshot {
        // base() has one identity with a grant; add a second identity that has no grants.
        let text = base()
            + &format!("\n[[identity]]\nname = \"idle\"\ncaller_key_sha256 = \"{IDLE_KEY}\"\n");
        Snapshot::from_config(&load(&text).expect("valid"))
    }

    const ID: &str = "pty-team-a";
    const RT: &str = "kiro-krs";

    #[test]
    fn allows_matching_request() {
        assert_eq!(snapshot().evaluate(ID, RT, "POST", "/", &[TARGET]), Ok(()));
    }

    #[test]
    fn identity_without_grants_is_policy_empty() {
        assert_eq!(
            snapshot().evaluate("idle", RT, "POST", "/", &[TARGET]),
            Err(Code::PolicyEmpty)
        );
    }

    #[test]
    fn unknown_identity_is_policy_empty() {
        assert_eq!(
            snapshot().evaluate("nobody", RT, "POST", "/", &[TARGET]),
            Err(Code::PolicyEmpty)
        );
    }

    #[test]
    fn non_matching_method_is_denied() {
        assert_eq!(
            snapshot().evaluate(ID, RT, "GET", "/", &[TARGET]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn route_without_grant_is_denied() {
        assert_eq!(
            snapshot().evaluate(ID, "kiro-cw", "POST", "/", &[TARGET]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn non_matching_path_is_denied() {
        let text = base().replace("paths = [\"/\"]", "paths = [\"/v1/\"]");
        let s = Snapshot::from_config(&load(&text).unwrap());
        assert_eq!(
            s.evaluate(ID, RT, "POST", "/other", &[TARGET]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn wrong_aws_target_is_denied() {
        assert_eq!(
            snapshot().evaluate(ID, RT, "POST", "/", &["Other.Op"]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn missing_aws_target_is_denied_when_grant_lists_targets() {
        assert_eq!(
            snapshot().evaluate(ID, RT, "POST", "/", &[]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn two_aws_target_values_are_denied() {
        assert_eq!(
            snapshot().evaluate(ID, RT, "POST", "/", &[TARGET, TARGET]),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn grant_without_aws_targets_ignores_the_header() {
        let text = base().replace(
            "aws_targets = [\"AmazonCodeWhispererStreamingService.GenerateAssistantResponse\"]\n",
            "",
        );
        let s = Snapshot::from_config(&load(&text).unwrap());
        assert_eq!(s.evaluate(ID, RT, "POST", "/", &[]), Ok(()));
        assert_eq!(
            s.evaluate(ID, RT, "POST", "/", &["Any.Op", "Two.Ops"]),
            Ok(())
        );
    }

    #[test]
    fn prefix_path_matches_only_below_the_prefix() {
        let text = base().replace("paths = [\"/\"]", "paths = [\"/v1/\"]");
        let s = Snapshot::from_config(&load(&text).unwrap());
        assert_eq!(
            s.evaluate(ID, RT, "POST", "/v1/messages", &[TARGET]),
            Ok(())
        );
        assert_eq!(
            s.evaluate(ID, RT, "POST", "/v10", &[TARGET]),
            Err(Code::PolicyDenied)
        );
    }

    fn pt(grants: &str) -> Snapshot {
        let text = format!(
            "version = 1\n[listen]\nproxy = \"127.0.0.1:8443\"\n[passthrough]\npublic_authority = \"gate.example.test\"\n[[identity]]\nname = \"muse\"\ncaller_key_sha256 = \"{IDLE_KEY}\"\n[[route]]\nname = \"discord\"\nhost = \"discord.com\"\nmode = \"passthrough\"\n{grants}"
        );
        Snapshot::from_config(&load(&text).expect("valid"))
    }

    const HOLD: &str = "[[grant]]\nidentity = \"muse\"\nroute = \"discord\"\ndecision = \"hold\"\nmethods = [\"POST\"]\npath_patterns = [\"/api/v10/channels/*/messages\"]\n";
    const ALLOW: &str = "[[grant]]\nidentity = \"muse\"\nroute = \"discord\"\nmethods = [\"GET\", \"POST\"]\npaths = [\"/api/v10/channels/\"]\n";

    #[test]
    fn verdict_hold_matches_whole_path_only() {
        let s = pt(HOLD);
        let v = |m, p| s.evaluate_verdict("muse", "discord", m, p);
        assert_eq!(v("POST", "/api/v10/channels/1/messages"), Ok(Verdict::Hold));
        assert_eq!(
            v("POST", "/api/v10/channels/1/messages/2/reactions"),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            v("POST", "/api/v10/channels/1/messages/"),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            v("POST", "/api/v10/channels//messages"),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            v("POST", "/api/v10/channels/1/2/messages"),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            v("GET", "/api/v10/channels/1/messages"),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            s.evaluate_verdict("muse", "other", "POST", "/api/v10/channels/1/messages"),
            Err(Code::PolicyDenied)
        );
        assert_eq!(
            s.evaluate_verdict("nobody", "discord", "POST", "/api/v10/channels/1/messages"),
            Err(Code::PolicyEmpty)
        );
    }

    #[test]
    fn verdict_hold_beats_allow_in_either_grant_order() {
        let path = "/api/v10/channels/1/messages";
        for text in [format!("{ALLOW}{HOLD}"), format!("{HOLD}{ALLOW}")] {
            let s = pt(&text);
            assert_eq!(
                s.evaluate_verdict("muse", "discord", "POST", path),
                Ok(Verdict::Hold)
            );
            assert_eq!(
                s.evaluate_verdict("muse", "discord", "GET", path),
                Ok(Verdict::Allow)
            );
            assert_eq!(
                s.evaluate_verdict(
                    "muse",
                    "discord",
                    "POST",
                    "/api/v10/channels/1/messages/2/reactions"
                ),
                Ok(Verdict::Allow)
            );
        }
    }

    #[test]
    fn evaluate_ignores_path_patterns() {
        let s = pt(HOLD);
        assert_eq!(
            s.evaluate(
                "muse",
                "discord",
                "POST",
                "/api/v10/channels/1/messages",
                &[]
            ),
            Err(Code::PolicyDenied)
        );
    }

    #[test]
    fn route_lookup_returns_configured_route() {
        let s = snapshot();
        assert_eq!(s.route(RT).unwrap().host, "runtime.us-east-1.kiro.dev");
        assert!(s.route("missing").is_none());
    }
}
