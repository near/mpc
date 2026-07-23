#!/usr/bin/env bash
#
# upgrade-status.sh — Read-only view of where an upgrade stands on a net.
#
# Runs the verify queries (version, proposed_updates, state, and on TEE nets
# code_hash_votes + allowed_docker_image_hashes) and, for any node IPs given,
# curls their :8080 build-info metric. Read-only: issues only as-read-only calls.
# See how-to/cluster-upgrade.md (Verify & monitor).
#
# Usage:  ./scripts/ops/upgrade-status.sh <net> [node-ip...]
# Example: ./scripts/ops/upgrade-status.sh testnet 34.82.122.173

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ops/lib.sh
source "$HERE/lib.sh"

[[ $# -ge 1 ]] || die "Usage: $SCRIPT_NAME <net> [node-ip...]"
net="$1"; shift
resolve_net "$net"
require_cmds near

read_only() {
    local method="$1"
    echo "--- ${method} (${NET_CONTRACT}) ---"
    run near contract call-function as-read-only "$NET_CONTRACT" "$method" \
        json-args '{}' network-config "$NET_NETWORK" now || echo "(query failed)"
    echo
}

echo "==> Read-only contract state for ${net} (${NET_CONTRACT})"
read_only version
read_only proposed_updates
read_only state
if [[ "$NET_IS_TEE" -eq 1 ]]; then
    read_only code_hash_votes
    read_only allowed_docker_image_hashes
fi

if [[ $# -gt 0 ]]; then
    require_cmds curl
    echo "==> Node build info"
    for ip in "$@"; do
        printf -- '--- %s ---\n' "$ip"
        run curl -sf --max-time 10 "http://${ip}:8080/metrics" | grep mpc_node_build_info \
            || echo "(unreachable or metric absent)"
    done
fi
