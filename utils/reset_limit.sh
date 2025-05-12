#!/bin/bash
set -e

DEVICE=$(ip route | awk '/default/ {print $5}')

echo "[INFO] Cleaning up traffic control rules..."
sudo tc qdisc del dev ifb0 root 2>/dev/null || true
sudo tc qdisc del dev "$DEVICE" ingress 2>/dev/null || true
sudo ip link set ifb0 down 2>/dev/null || true
sudo ip link delete ifb0 type ifb 2>/dev/null || true

echo "[DONE] Traffic shaping removed."
