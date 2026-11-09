#!/usr/bin/env python3
"""Minimal ACP client: run `<cmd> acp`, send one prompt, print streamed text.

Used to check that kiro-cli honours the same endpoint settings in ACP mode,
which is how openab drives it. Usage: acp_driver.py "<prompt>" -- kiro-cli acp
"""
import json
import os
import subprocess
import sys
import time

prompt = sys.argv[1]
cmd = sys.argv[sys.argv.index("--") + 1:]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
nid = 0


def send(method, params):
    global nid
    nid += 1
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": nid, "method": method, "params": params}) + "\n")
    p.stdin.flush()
    return nid


def wait(rid, timeout=120):
    end = time.time() + timeout
    updates = 0
    while time.time() < end:
        line = p.stdout.readline()
        if not line:
            return None, updates
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("method") == "session/update":
            u = m["params"].get("update", {})
            if u.get("sessionUpdate") == "agent_message_chunk":
                updates += 1
                sys.stdout.write(u.get("content", {}).get("text", ""))
                sys.stdout.flush()
        elif "id" in m and "method" in m:  # agent -> client request (permissions etc.)
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": m["id"],
                                      "error": {"code": -32601, "message": "unsupported"}}) + "\n")
            p.stdin.flush()
        elif m.get("id") == rid:
            return m, updates
    return None, updates


r, _ = wait(send("initialize", {"protocolVersion": 1, "clientCapabilities": {}}))
print("initialize:", "ok" if r and "result" in r else r)
r, _ = wait(send("session/new", {"cwd": os.getcwd(), "mcpServers": []}))
if not r or "result" not in r:
    print("session/new failed:", r)
    sys.exit(1)
sid = r["result"]["sessionId"]
r, n = wait(send("session/prompt", {"sessionId": sid, "prompt": [{"type": "text", "text": prompt}]}))
print("\nprompt_result:", (r or {}).get("result") or (r or {}).get("error"), "chunks:", n)
p.terminate()
sys.exit(0 if r and "result" in r else 1)
