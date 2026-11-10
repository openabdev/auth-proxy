#!/usr/bin/env python3
"""Egress probe. Prints one JSON line per target with the caller's UID, the
result (ok / errno name / timeout) and the elapsed time.

  probe.py TARGET...
    tcp:<ipv4>:<port>        TCP connect over IPv4
    tcp6:<ipv6>:<port>       TCP connect over IPv6 (last ':' separates the port)
    udp53:<ns>               DNS A query for github.com over UDP to <ns>:53
    tcp53:<ns>               same over TCP
    name:<host>              getaddrinfo(<host>) through the system resolver
  <ns> may be the word "resolv": the first nameserver in /etc/resolv.conf (kube-dns).
"""
import errno
import json
import os
import socket
import struct
import sys
import time

TIMEOUT = 5.0


def q(name):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    body = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return hdr + body + struct.pack(">HH", 1, 1)


def err(e):
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, socket.gaierror):
        return f"gaierror:{e.args[0]}:{e.args[1]}"
    n = getattr(e, "errno", None)
    return errno.errorcode.get(n, str(e)) if n else type(e).__name__


def resolv_ns():
    for line in open("/etc/resolv.conf"):
        if line.startswith("nameserver"):
            return line.split()[1]


def run(t):
    kind, _, rest = t.partition(":")
    if kind in ("udp53", "tcp53") and rest == "resolv":
        rest = resolv_ns()
    t0 = time.time()
    res = "ok"
    try:
        if kind in ("tcp", "tcp6"):
            host, port = rest.rsplit(":", 1)
            fam = socket.AF_INET6 if kind == "tcp6" else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((host, int(port)))
            s.close()
        elif kind == "udp53":
            fam = socket.AF_INET6 if ":" in rest else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.settimeout(TIMEOUT)
            s.sendto(q("github.com"), (rest, 53))
            s.recvfrom(512)
            res = "ok:answer"
        elif kind == "tcp53":
            fam = socket.AF_INET6 if ":" in rest else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((rest, 53))
            m = q("github.com")
            s.sendall(struct.pack(">H", len(m)) + m)
            s.recv(2)
            res = "ok:answer"
        elif kind == "name":
            addrs = sorted({a[4][0] for a in socket.getaddrinfo(rest, 443, proto=socket.IPPROTO_TCP)})
            res = "ok:" + ",".join(addrs[:3])
        else:
            res = "bad-target"
    except Exception as e:  # noqa: BLE001
        res = err(e)
    return {"uid": os.getuid(), "target": t, "result": res, "ms": round((time.time() - t0) * 1000)}


for t in sys.argv[1:]:
    print(json.dumps(run(t)), flush=True)
