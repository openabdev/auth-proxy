#!/usr/bin/env python3
"""ACP client that times streamed chunks: initialize → session/new → session/prompt.

  acp_timed.py "<prompt>" -- kiro-cli acp

Prints one JSON line: ok, chunks, first/last chunk time after the prompt was
sent, and the reply length. The reply text itself is not printed.
"""
import json
import os
import subprocess
import sys
import time

prompt = sys.argv[1]
cmd = sys.argv[sys.argv.index("--") + 1:]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                     bufsize=1)
nid = 0


def send(method, params):
    global nid
    nid += 1
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": nid, "method": method, "params": params}) + "\n")
    p.stdin.flush()
    return nid


def wait(rid, timeout=120, t0=None):
    end = time.time() + timeout
    ts, text = [], []
    while time.time() < end:
        line = p.stdout.readline()
        if not line:
            return None, ts, text
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("method") == "session/update":
            u = m["params"].get("update", {})
            if u.get("sessionUpdate") == "agent_message_chunk":
                ts.append(time.time() - (t0 or 0))
                text.append(u.get("content", {}).get("text", ""))
        elif "id" in m and "method" in m:
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": m["id"],
                                      "error": {"code": -32601, "message": "unsupported"}}) + "\n")
            p.stdin.flush()
        elif m.get("id") == rid:
            return m, ts, text
    return None, ts, text


out = {"ok": False}
r, _, _ = wait(send("initialize", {"protocolVersion": 1, "clientCapabilities": {}}))
r, _, _ = wait(send("session/new", {"cwd": os.getcwd(), "mcpServers": []}))
if r and "result" in r:
    t0 = time.time()
    r, ts, text = wait(send("session/prompt", {"sessionId": r["result"]["sessionId"],
                                               "prompt": [{"type": "text", "text": prompt}]}), t0=t0)
    body = "".join(text)
    out = {"ok": bool(r and "result" in r), "chunks": len(ts),
           "first_chunk_s": round(ts[0], 3) if ts else None, "last_chunk_s": round(ts[-1], 3) if ts else None,
           "reply_chars": len(body), "reply_lines": body.count("\n") + 1 if body else 0,
           "error": (r or {}).get("error", {}).get("message") if r and "error" in r else None}
else:
    out["error"] = "session/new failed: " + json.dumps((r or {}).get("error"))[:300]
p.terminate()
print(json.dumps(out))
sys.exit(0 if out["ok"] else 1)
