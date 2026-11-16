#!/bin/bash
K="sudo -n k3s kubectl -n ap-item6"
echo "### timeline from the proxy's own audit (ms, proxy clock)"
$K logs ap-agent -c proxy | python3 -c '
import sys,json
ev=[json.loads(l) for l in sys.stdin if l.startswith("{")]
req=[e for e in ev if "plane" not in e]
ev=[e for e in ev if "plane" in e]
for r in req: print("request audit:",{k:r[k] for k in ("route","decision","code","session","status")})
ren=[e["t"] for e in ev if e["plane"]=="renew"]
h201=[e["t"] for e in ev if e["plane"]=="hello" and e["status"]==201]
h409=[e["t"] for e in ev if e["plane"]=="hello" and e["status"]==409]
print("hello 201 times:",h201)
print("renew times:",ren)
last=max(t for t in ren if t<h201[-1])
print("last renew before the new winner:",last)
print("lease 90s lapses at:",last+90000)
b=[t for t in h409 if t>last]
print("409s after last renew: %d, last 409 at %d (= last+%.1fs)"%(len(b),b[-1],(b[-1]-last)/1000))
print("first 409 after last renew... early hellos won before lapse: ",[t for t in h201 if t<last+90000 and t>h201[0]])
print("winner 201 at %d = last renew + %.1fs"%(h201[-1],(h201[-1]-last)/1000))
for e in ev:
    if e["plane"] not in ("hello","renew") : print("other plane event:",e["plane"],e["result"],e["status"],e["t"])
'
echo "### old surrogate through the proxy after the lapse (as UID 1000 in agent)"
cat /tmp/ap-item6-build/keys/k/caller-key | $K exec -i ap-agent -c agent -- sh -c 'read CK; S=$(cat /tmp/surrogate.sess-1794856771); curl -s -i -X POST http://127.0.0.1:18080/ap/$CK/kiro-krs/ -H "authorization: Bearer $S" -d "{}" | head -8' | sed -E 's/(apk|aps)_[0-9a-f]{64}/\1_<masked>/g'
echo "### new session's surrogate works? (live, goes to the stub: a 400 from the stub means admitted)"
cat /tmp/ap-item6-build/keys/k/caller-key | $K exec -i ap-agent -c agent -- sh -c 'read CK; S=$(cat $(ls -t /tmp/surrogate.sess-* | head -1)); curl -s -o /dev/null -w "new surrogate status=%{http_code}\n" -X POST http://127.0.0.1:18080/ap/$CK/kiro-krs/ -H "authorization: Bearer $S" -d "{}"'
