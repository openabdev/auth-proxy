#!/usr/bin/env python3
"""Run a command, time each stdout chunk as it arrives, print one JSON line.

  chat_timed.py -- kiro-run chat --no-interactive --trust-tools= "<prompt>"

Output: start epoch ms, exit code, wall time, time to first stdout byte, number
of stdout reads (chunks) and their span, reply size, and the last 300 chars of
stderr with ANSI codes stripped (for error messages). The reply text is not
printed beyond its first 40 characters.
"""
import json
import os
import re
import subprocess
import sys
import time

cmd = sys.argv[sys.argv.index("--") + 1:]
t0 = time.time()
p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ts, buf = [], b""
while True:
    b = os.read(p.stdout.fileno(), 65536)
    if not b:
        break
    ts.append(time.time() - t0)
    buf += b
err = p.stderr.read()
rc = p.wait()
ansi = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
text = ansi.sub(b"", buf).decode(errors="replace")
print(json.dumps({
    "start_ms": int(t0 * 1000), "rc": rc, "wall_s": round(time.time() - t0, 2),
    "first_stdout_s": round(ts[0], 3) if ts else None,
    "stdout_reads": len(ts), "span_s": round(ts[-1] - ts[0], 3) if ts else None,
    "reply_chars": len(text), "reply_head": text.strip()[:40],
    "stderr_tail": ansi.sub(b"", err).decode(errors="replace")[-300:],
}))
