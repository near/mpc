#!/bin/bash
set -e

# === Config ===
PORT=8443
LIMIT=1kbps             # You can use e.g. 2mbit, 500kbit, etc.
QUEUE_LIMIT_PACKETS=100 # Max packets to queue before dropping

# === Find default network interface ===
DEVICE=$(ip route | awk '/default/ {print $5}')
echo "[INFO] Using network device: $DEVICE"

# === Load ifb module if not already loaded ===
if ! lsmod | grep -q '^ifb'; then
    echo "[INFO] Loading ifb module..."
    sudo modprobe ifb
fi

# === Create and bring up ifb0 if needed ===
if ! ip link show ifb0 >/dev/null 2>&1; then
    echo "[INFO] Creating ifb0 device..."
    sudo ip link add ifb0 type ifb
fi
sudo ip link set ifb0 up

# === Clean previous rules to avoid duplicates ===
echo "[INFO] Cleaning up existing traffic control rules..."
sudo tc qdisc del dev ifb0 root 2>/dev/null || true
sudo tc qdisc del dev "$DEVICE" ingress 2>/dev/null || true

# === Redirect ingress traffic for PORT to ifb0 ===
echo "[INFO] Setting up ingress redirection for port $PORT..."
sudo tc qdisc add dev "$DEVICE" ingress
sudo tc filter add dev "$DEVICE" ingress protocol ip \
    u32 match ip dport $PORT 0xffff \
    action mirred egress redirect dev ifb0

# === Apply bandwidth limit on ifb0 ===
echo "[INFO] Applying HTB rate limit of $LIMIT to redirected traffic..."
sudo tc qdisc add dev ifb0 root handle 1: htb default 1
sudo tc class add dev ifb0 parent 1: classid 1:1 htb rate $LIMIT

# === Attach leaf qdisc to enforce queue/drop behavior ===
echo "[INFO] Attaching fq_codel to limit queue size to $QUEUE_LIMIT_PACKETS packets..."
sudo tc qdisc add dev ifb0 parent 1:1 handle 10: fq_codel limit $QUEUE_LIMIT_PACKETS

echo "[DONE] Port $PORT ingress traffic is now safely limited to $LIMIT with controlled queueing."
