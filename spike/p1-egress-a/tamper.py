#!/usr/bin/env python3
"""Agent-side tampering with the platform-written kiro-cli settings (test 5).

  tamper.py real     point the four api.*.service keys back at the real hosts
  tamper.py unset    remove the four keys (kiro-cli falls back to its defaults)
  tamper.py restore  put the platform's file back (saved by the first call)
"""
import json
import os
import shutil
import sys

p = os.path.expanduser("~/.kiro/settings/cli.json")
saved = "/work/cli.json.platform"
if not os.path.exists(saved):
    shutil.copy(p, saved)
r = "us-east-1"
real = {"api.cps.service": f"management.{r}.kiro.dev", "api.krs.service": f"runtime.{r}.kiro.dev",
        "api.codewhisperer.service": f"q.{r}.amazonaws.com", "api.q.service": f"q.{r}.amazonaws.com"}
mode = sys.argv[1]
if mode == "real":
    json.dump({k: {"endpoint": "https://" + v, "region": r} for k, v in real.items()}, open(p, "w"), indent=1)
elif mode == "unset":
    s = json.load(open(saved))
    json.dump({k: v for k, v in s.items() if k not in real}, open(p, "w"), indent=1)
elif mode == "restore":
    shutil.copy(saved, p)
print(f"tamper {mode}: cli.json keys now:", {k: v.get("endpoint") if isinstance(v, dict) else v
                                             for k, v in json.load(open(p)).items()})
