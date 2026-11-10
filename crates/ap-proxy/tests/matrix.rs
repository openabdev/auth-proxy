//! Runs the fail-closed matrix driver (`tests/matrix/matrix.py`) against the built binaries.
//!
//! Build with the test feature, so that the proxy trusts the throwaway CA:
//!   cargo build -p ap-proxy -p ap-egress --features ap-proxy/matrix-upstream
//!   cargo test -p ap-proxy --features matrix-upstream --test matrix
//!
//! The test passes only when the driver exits 0, prints no FAIL row, and reports every registered
//! row as PASS. If python3 or openssl is missing, the test prints a skip message and returns. The CI
//! job asserts that both tools exist, so the skip cannot hide a failure there.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Directory holding the built binaries: the parent of the test's `deps` directory.
fn bin_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    exe.parent()
        .and_then(Path::parent)
        .expect("target profile directory")
        .to_path_buf()
}

fn tool_works(tool: &str, arg: &str) -> bool {
    Command::new(tool)
        .arg(arg)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn matrix() {
    if !tool_works("python3", "--version") || !tool_works("openssl", "version") {
        eprintln!("SKIP matrix: python3 or openssl is not on PATH");
        return;
    }
    let bins = bin_dir();
    for bin in ["auth-proxy", "ap-egress"] {
        assert!(
            bins.join(bin).exists(),
            "missing {bin} in {}; build it with --features ap-proxy/matrix-upstream",
            bins.display()
        );
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .current_dir(&root)
        .arg("tests/matrix/matrix.py")
        .arg("--bin")
        .arg(&bins)
        .output()
        .expect("run matrix driver");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(out.status.success(), "matrix driver exited {}", out.status);
    assert!(
        !stdout.lines().any(|l| l.starts_with("FAIL")),
        "matrix reported a FAIL row"
    );
    assert!(
        stdout.contains("summary: 39 PASS of 39 rows"),
        "not every registered row passed:\n{stdout}"
    );
}
