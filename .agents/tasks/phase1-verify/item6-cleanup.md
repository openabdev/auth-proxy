RESULT: PASS (mini left as found)

# Item 6d: cleanup check on `mini`

Start state recorded BEFORE any change in `item6-evidence/before.txt` (`snap.sh`: namespaces, pods, `ctr -n k8s.io`
images, listening sockets, tailscale status, `~` and `/tmp` listings, `~/.cargo/bin`, `~/.local/bin`, crictl container
count, host `iptables -S OUTPUT` md5, `iptables-save | grep ap-item6`, disk). After: `item6-evidence/after.txt`.

Created and removed (one prefix, `ap-item6`):
- namespace `ap-item6` (pods, Services, Secrets, ConfigMaps): `kubectl delete ns ap-item6 --wait=true` -> deleted;
- images `docker.io/ap-item6/{proxy,egress,agent,hr,netinit}:dev` and the 5 index `sha256:` names the import added
  (`ctr -n k8s.io images rm --sync`);
- `/tmp/ap-item6-build` (sources, build target, throwaway cargo home, keys, PKI, tar), `/tmp/ap-item6-snap.sh`;
- macmini: docker images `ap-item6/*` (6), `/tmp/ap-item6-ctx`; laptop: `/tmp/ap-item6-ctx`, `/tmp/ap-item6-tool`.
No cargo or rustc ran on the laptop or macmini. kiro-cli binaries were only copied (read) from `mini`'s install.

Comparison after cleanup ([M]):
```
namespaces                : default kube-node-lease kube-public kube-system openab   (same as before)
ctr images (sorted) md5   : 1b52afe0a10081120714dbf0a88a6778  before and after (identical)
ctr images matching ap-item6: 0
ls /tmp | grep -c ap-item6: 0
ps auth-proxy|ap-egress|hr-authority: 0
host iptables OUTPUT md5  : 6aa9113fa8015deb4c7a93b5c2f03524  before and after
crictl containers         : 13 before, 13 after
ls -A ~ md5               : 573255538318e555fbedd46e38caa2ce  (same as the item 1 / item 5 baseline; ~ untouched)
df free on /              : 31G before, 31G after
tailscale                 : state never touched; status header identical
```
`diff before.txt after.txt` has only two lines, both artefacts of the snapshot itself: `ap-item6-after.txt` (the output
file existing in /tmp while the snapshot ran) and the `ps` counter 1 -> 2 (the snapshot's own shell command line
contains "ap-item6"). Both were re-checked without the artefact (counts above are 0). p1 was not touched.
