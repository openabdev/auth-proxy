//! Fixtures shared by the workspace's tests. Sample values only: the hosts,
//! secret names and the caller key below are made up.

pub const SAMPLE_CALLER_KEY: &str =
    "apk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const SAMPLE_CALLER_SHA256: &str =
    "568d4a822d8e13b84959ce5e7ae2ca69ea3698da858dba712b49c022886de406";

/// The design doc's Q3-A sketch with sample values: two credentials, five
/// routes, three grants (one with `aws_targets`), an egress allowlist.
pub fn sample_toml() -> String {
    format!(
        r#"version = 1
identity = "pty-team-a"
caller_key_sha256 = "{SAMPLE_CALLER_SHA256}"

[[route]]
name = "anthropic"
host = "api.anthropic.com"
surrogate_header = "x-api-key"
surrogate_scheme = ""
credential_header = "x-api-key"
credential_scheme = ""

[[route]]
name = "kiro-cps"
host = "profile.us-east-1.kiro.dev"
error_shape = "aws"

[[route]]
name = "kiro-krs"
host = "runtime.us-east-1.kiro.dev"
error_shape = "aws"
surrogate_header = "authorization"
credential_header = "authorization"
pass_headers = ["tokentype"]

[[route]]
name = "kiro-cw"
host = "cw.us-east-1.kiro.dev"
error_shape = "aws"

[[route]]
name = "kiro-q"
host = "api.q.service"
error_shape = "aws"

[[credential]]
id = "anthropic"
source = "k8s:auth-proxy-anthropic:api_key"
routes = ["anthropic"]

[[credential]]
id = "kiro"
source = "k8s:auth-proxy-kiro:api_key"
routes = ["kiro-cps", "kiro-krs", "kiro-cw", "kiro-q"]

[[grant]]
credential = "anthropic"
route = "anthropic"
methods = ["POST"]
paths = ["/v1/"]

[[grant]]
credential = "kiro"
route = "kiro-krs"
methods = ["POST"]
paths = ["/"]
aws_targets = ["AmazonCodeWhispererStreamingService.GenerateAssistantResponse"]

[[grant]]
credential = "kiro"
route = "kiro-cps"
methods = ["POST"]
paths = ["/"]

[egress]
allow = ["github.com:443", "registry.npmjs.org:443", "pypi.org:443",
         "files.pythonhosted.org:443", "index.crates.io:443", "static.crates.io:443"]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn sample_hash_matches_sample_key() {
        assert_eq!(
            hex::encode(Sha256::digest(SAMPLE_CALLER_KEY.as_bytes())),
            SAMPLE_CALLER_SHA256
        );
    }
}
