//! `ap-netprobe`: runs as the agent UID and checks that the per-UID netfilter rules are in force.
//!
//!   ap-netprobe --status <file> [--interval-secs <n>]   probe forever, write the status file
//!   ap-netprobe --once                                   probe once, print the line, exit 0 or 1

use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: ap-netprobe --status <file> [--interval-secs <n>] | --once";

fn main() {
    let mut status: Option<PathBuf> = None;
    let mut interval = 30u64;
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--once" => once = true,
            "--status" => status = args.next().map(PathBuf::from),
            "--interval-secs" => match args.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(n) if n > 0 => interval = n,
                _ => die("--interval-secs needs a positive number"),
            },
            _ => die(&format!("unknown argument {flag}")),
        }
    }
    if once {
        let (result, lines) = ap_netprobe::run_probes_detailed();
        for l in lines {
            eprintln!("ap-netprobe: {l}");
        }
        print!("{}", ap_netprobe::status_line("once", result));
        exit(i32::from(result.is_err()));
    }
    let Some(status) = status else {
        die("--status is required");
    };
    // The token changes on every write. It starts from the clock, so a restarted probe does not
    // repeat a token the proxy has already seen.
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut n: u64 = 0;
    loop {
        let (result, lines) = ap_netprobe::run_probes_detailed();
        n += 1;
        let line = ap_netprobe::status_line(&format!("{start}-{n}"), result);
        if let Err(e) = ap_netprobe::write_status(&status, &line) {
            eprintln!("ap-netprobe: cannot write the status file: {e}");
        }
        if let Err(reason) = result {
            eprintln!("ap-netprobe: fail: {reason}: {}", lines.join("; "));
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn die(msg: &str) -> ! {
    eprintln!("ap-netprobe: {msg}\n{USAGE}");
    exit(2);
}
