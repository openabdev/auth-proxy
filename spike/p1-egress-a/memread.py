#!/usr/bin/env python3
"""Run as the agent UID: try to read the proxy's credential. Prints only the
outcome of each attempt (ok + byte count, or the errno), never any content.

  memread.py
Looks at every process visible in /proc that does not belong to the caller's UID,
plus the Secret mount path as seen from the caller's own mount namespace.
"""
import errno
import json
import os

SECRET = "/run/ap-secret/KIRO_API_KEY"  # /var/run is a symlink to /run in the image


def attempt(path, mode="read"):
    try:
        if mode == "mem":
            # read one byte from each of the first few readable mappings
            pid = path.split("/")[2]
            n = 0
            with open(f"/proc/{pid}/maps") as m, open(path, "rb", buffering=0) as f:
                for line in list(m)[:8]:
                    a = int(line.split("-")[0], 16)
                    f.seek(a)
                    n += len(f.read(1))
            return f"ok:{n}B"
        with open(path, "rb") as f:
            return f"ok:{len(f.read())}B"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e))


out = {"uid": os.getuid(), "own_mount_secret": attempt(SECRET), "procs": []}
for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
    try:
        st = os.stat(f"/proc/{pid}")
        comm = open(f"/proc/{pid}/comm").read().strip()
    except OSError:
        continue
    if st.st_uid == os.getuid():
        continue
    out["procs"].append({
        "pid": int(pid), "uid": st.st_uid, "comm": comm,
        "environ": attempt(f"/proc/{pid}/environ"),
        "mem": attempt(f"/proc/{pid}/mem", "mem"),
        "maps": attempt(f"/proc/{pid}/maps"),
        "root_secret": attempt(f"/proc/{pid}/root{SECRET}"),
        "cmdline": attempt(f"/proc/{pid}/cmdline"),
    })
out["visible_other_uid_procs"] = len(out["procs"])
print(json.dumps(out, indent=1))
