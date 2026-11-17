//! Runs the passthrough matrix driver (`tests/matrix/passthrough.py`) against the built binary.
//!
//! Build with both test features, then run:
//!   cargo build -p ap-proxy --features matrix-upstream,stage1-probe
//!   cargo test -p ap-proxy --features matrix-upstream,stage1-probe --test matrix_passthrough
//!
//! Passes only when the driver exits 0, prints no FAIL row and reports every registered row as
//! PASS. The sidecar matrix (`tests/matrix.rs`) is separate and unchanged.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Rows registered in `tests/matrix/passthrough.py`.
const ROWS: usize = 16;

/// Directory holding the built binary. `CARGO_BIN_EXE_auth-proxy` is set by cargo for this package's
/// binaries, so it holds up when cargo keeps test executables in a separate build directory.
fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_auth-proxy"))
        .parent()
        .expect("binary directory")
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
fn matrix_passthrough() {
    if !tool_works("python3", "--version") || !tool_works("openssl", "version") {
        eprintln!("SKIP matrix_passthrough: python3 or openssl is not on PATH");
        return;
    }
    let bins = bin_dir();
    assert!(
        bins.join("auth-proxy").exists(),
        "missing auth-proxy in {}; build it with --features matrix-upstream,stage1-probe",
        bins.display()
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .current_dir(&root)
        .arg("tests/matrix/passthrough.py")
        .arg("--bin")
        .arg(&bins)
        .output()
        .expect("run passthrough matrix driver");
    let stdout = String::from_utf8_lossy(&out.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "driver exited {}", out.status);
    assert!(
        !stdout.lines().any(|l| l.starts_with("FAIL")),
        "a row failed"
    );
    assert!(
        stdout.contains(&format!("summary: {ROWS} PASS of {ROWS} rows")),
        "not every row passed:\n{stdout}"
    );
}
