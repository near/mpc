#!/bin/bash
set -e

# === Config ===
PORT=8443
LIMIT=1kbit             # You can use e.g. 2mbit, 500kbit, etc.
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

while true; do
    # Pick bandwidth: 0 = 1kbit, 1 = 300kbit, 2 = 15mbit
    bw=$((RANDOM % 3))
    if [ $bw -eq 0 ]; then
        rate="1kbit"
        sleep_time=$((RANDOM % 16 + 5))
    elif [ $bw -eq 1 ]; then
        rate="300kbit"
        sleep_time=$((RANDOM % 16 + 5))
    else
        rate="15mbit"
        sleep_time=$((RANDOM % 5 + 1))
    fi

    # Pick packet loss: 0%, 10%, 20%
    case $((RANDOM % 3)) in
    0) loss="0%" ;;
    1) loss="10%" ;;
    2) loss="20%" ;;
    esac

    sudo tc class change dev ifb0 parent 1: classid 1:1 htb rate $rate
    echo "[INFO] rate=$rate, loss=$loss, duration=${sleep_time}s"
    sudo tc qdisc del dev ifb0 parent 1:1 netem 2>/dev/null || true
    echo "[INFO] rate=$rate, loss=$loss, duration=${sleep_time}s"
    sudo tc qdisc add dev ifb0 parent 1:1 netem loss "$loss" limit 50
    echo "[INFO] rate=$rate, loss=$loss, duration=${sleep_time}s"

    sleep $sleep_time
done
# 3. Add netem as leaf qdisc to inject 10% packet loss
#sudo tc qdisc add dev ifb0 parent 1:1 netem loss 10% limit 50

# === Attach leaf qdisc to enforce queue/drop behavior ===
#echo "[INFO] Attaching fq_codel to limit queue size to $QUEUE_LIMIT_PACKETS packets..."
#sudo tc qdisc add dev ifb0 parent 1:1 handle 10: fq_codel limit $QUEUE_LIMIT_PACKETS

#echo "[DONE] Port $PORT ingress traffic is now safely limited to $LIMIT with controlled queueing."
