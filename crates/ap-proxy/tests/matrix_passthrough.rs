//! Runs the passthrough matrix driver (`tests/matrix/passthrough.py`) against the built binary.
//!
//! Build with both test features, then run:
//!   cargo build -p ap-proxy --features matrix-upstream,stage1-probe
//!   cargo test -p ap-proxy --features matrix-upstream,stage1-probe --test matrix_passthrough
//!
//! With `AP_MATRIX_NOPROBE_BIN=<dir>` the driver also runs the rows that need a build without the
//! probe route, and the expected count grows by `ROWS_NOPROBE`.
//!
//! Passes only when the driver exits 0, prints no FAIL row and reports every registered row as
//! PASS. The sidecar matrix (`tests/matrix.rs`) is separate and unchanged.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Rows registered in `tests/matrix/passthrough.py` that run on the build under test.
const ROWS: usize = 27;

/// Extra rows that run when `AP_MATRIX_NOPROBE_BIN` names a directory holding an `auth-proxy` built
/// without `stage1-probe` (CI builds one into `target/noprobe`).
const ROWS_NOPROBE: usize = 3;

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
    let noprobe = std::env::var_os("AP_MATRIX_NOPROBE_BIN");
    let mut cmd = Command::new("python3");
    cmd.current_dir(&root)
        .arg("tests/matrix/passthrough.py")
        .arg("--bin")
        .arg(&bins);
    if let Some(dir) = &noprobe {
        cmd.arg("--noprobe-bin").arg(dir);
    }
    let rows = ROWS + if noprobe.is_some() { ROWS_NOPROBE } else { 0 };
    let out = cmd.output().expect("run passthrough matrix driver");
    let stdout = String::from_utf8_lossy(&out.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "driver exited {}", out.status);
    assert!(
        !stdout.lines().any(|l| l.starts_with("FAIL")),
        "a row failed"
    );
    assert!(
        stdout.contains(&format!("summary: {rows} PASS of {rows} rows")),
        "not every row passed:\n{stdout}"
    );
}
