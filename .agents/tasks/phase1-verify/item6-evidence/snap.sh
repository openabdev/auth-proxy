#!/bin/sh
# state snapshot of mini; run on mini
echo "## namespaces"; sudo -n k3s kubectl get ns --no-headers | awk '{print $1,$2}'
echo "## pods all"; sudo -n k3s kubectl get pods -A --no-headers | awk '{print $1,$2,$4}'
echo "## images (ctr k8s.io)"; sudo -n k3s ctr -n k8s.io images ls -q | sort
echo "## listening"; ss -tulnH | awk '{print $1,$5}' | sort
echo "## tailscale"; tailscale status 2>&1 | awk '{print $1,$2,$5,$6,$7}'
echo "## ~ files"; ls -A ~ | sort
echo "## /tmp files (ssh-* excluded)"; ls -A /tmp | grep -v '^ssh-' | sort
echo "## cargo bin"; ls ~/.cargo/bin | sort
echo "## local bin"; ls -A ~/.local/bin | sort
echo "## crictl containers"; sudo -n k3s crictl ps -a -q | wc -l
echo "## host iptables OUTPUT md5"; sudo -n iptables -S OUTPUT | md5sum
echo "## iptables ap-item6 refs"; sudo -n iptables-save | grep -c ap-item6
echo "## ps ap procs"; ps -eo args | grep -E "auth-proxy|ap-egress|hr-authority|ap-item6" | grep -v grep | wc -l
echo "## df"; df -h / | tail -1 | awk '{print $2,$3,$4}'
