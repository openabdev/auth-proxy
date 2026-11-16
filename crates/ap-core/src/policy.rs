//! Immutable policy snapshot compiled from a validated config.
//!
//! The snapshot answers one question: may this identity make this request on this route?
//! Reloading is the caller's job (ap-proxy stats the file and swaps in a new snapshot).

use crate::config::{Config, Grant, Route};
use crate::error::Code;
use std::collections::HashMap;

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

    #[test]
    fn route_lookup_returns_configured_route() {
        let s = snapshot();
        assert_eq!(s.route(RT).unwrap().host, "runtime.us-east-1.kiro.dev");
        assert!(s.route("missing").is_none());
    }
}
