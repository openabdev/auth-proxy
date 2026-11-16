//! Command-line arguments. Every flag takes one value, and every flag is required.

use std::path::PathBuf;

/// Usage line, printed with every argument error.
pub const USAGE: &str = "usage: ap-runtime-shim --identity <name> --session-socket <path> \
--agent-socket <path> --seed-file <path>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Identity the runtime authenticates as. The config must hold it with a `runtime_pubkey`.
    pub identity: String,
    /// The proxy's session socket.
    pub session_socket: PathBuf,
    /// The socket the agent connects to.
    pub agent_socket: PathBuf,
    /// File holding the Ed25519 seed as base64 text.
    pub seed_file: PathBuf,
}

/// Parse the arguments after the program name.
pub fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut identity = None;
    let mut session_socket = None;
    let mut agent_socket = None;
    let mut seed_file = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--identity" => identity = Some(value),
            "--session-socket" => session_socket = Some(PathBuf::from(value)),
            "--agent-socket" => agent_socket = Some(PathBuf::from(value)),
            "--seed-file" => seed_file = Some(PathBuf::from(value)),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let missing = |name: &str| format!("{name} is required\n{USAGE}");
    let identity = identity.ok_or_else(|| missing("--identity"))?;
    if identity.is_empty() {
        return Err(format!("--identity must not be empty\n{USAGE}"));
    }
    Ok(Args {
        identity,
        session_socket: session_socket.ok_or_else(|| missing("--session-socket"))?,
        agent_socket: agent_socket.ok_or_else(|| missing("--agent-socket"))?,
        seed_file: seed_file.ok_or_else(|| missing("--seed-file"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_all_four_flags() {
        let a = parse_args(argv(&[
            "--identity",
            "pty-team-a",
            "--session-socket",
            "/s.sock",
            "--agent-socket",
            "/a.sock",
            "--seed-file",
            "/seed",
        ]))
        .expect("valid");
        assert_eq!(a.identity, "pty-team-a");
        assert_eq!(a.session_socket, PathBuf::from("/s.sock"));
        assert_eq!(a.agent_socket, PathBuf::from("/a.sock"));
        assert_eq!(a.seed_file, PathBuf::from("/seed"));
    }

    #[test]
    fn every_flag_is_required() {
        let full = [
            ("--identity", "x"),
            ("--session-socket", "/s"),
            ("--agent-socket", "/a"),
            ("--seed-file", "/k"),
        ];
        for skip in 0..full.len() {
            let mut v = Vec::new();
            for (i, (f, val)) in full.iter().enumerate() {
                if i != skip {
                    v.push(f.to_string());
                    v.push(val.to_string());
                }
            }
            let err = parse_args(v).expect_err("a missing flag must fail");
            assert!(err.contains(full[skip].0), "{err}");
        }
    }

    #[test]
    fn unknown_flag_and_flag_without_value_fail() {
        assert!(parse_args(argv(&["--bogus", "x"])).is_err());
        assert!(parse_args(argv(&["--identity"])).is_err());
    }

    #[test]
    fn empty_identity_fails() {
        let err = parse_args(argv(&[
            "--identity",
            "",
            "--session-socket",
            "/s",
            "--agent-socket",
            "/a",
            "--seed-file",
            "/k",
        ]))
        .expect_err("empty identity");
        assert!(err.contains("--identity"));
    }
}
