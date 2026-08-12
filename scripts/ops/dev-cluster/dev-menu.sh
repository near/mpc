#!/usr/bin/env bash
#
# dev-menu.sh — entry point for dev-cluster work. Picks the network and
# version, then upgrades the cluster nodes and verifies them.
#
# Usage: ./scripts/ops/dev-cluster/dev-menu.sh [testnet|mainnet] [VERSION]
# Prompts for the Nomad IP, credentials, and node metrics addresses; exporting
# NOMAD_ADDR_DEV_*, NOMAD_HTTP_AUTH_DEV_*, or MPC_NODE_ADDRS_DEV_* for the
# network skips the matching prompt.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../common.sh
source "${SCRIPT_DIR}/../../common.sh"
# shellcheck source=dev-common.sh
source "${SCRIPT_DIR}/dev-common.sh"

# Sets NETWORK: a valid CLI argument passes, an invalid one dies (so scripted
# use fails loudly), no argument prompts until valid.
resolve_network() {
    NETWORK="${1:-}"
    [[ -z "$NETWORK" ]] || case "$NETWORK" in
        testnet|mainnet) return 0 ;;
        *) die "Unknown network '${NETWORK}' (expected testnet|mainnet)." ;;
    esac
    while true; do
        read -rp "Network (testnet|mainnet) [testnet]: " NETWORK
        NETWORK="${NETWORK:-testnet}"
        case "$NETWORK" in
            testnet|mainnet) return 0 ;;
            *) echo "Unknown network '${NETWORK}'." ;;
        esac
    done
}

# Sets VERSION from the CLI argument or a prompt, then validates it.
resolve_version() {
    VERSION="${1:-}"
    [[ -n "$VERSION" ]] || read -rp "Version (e.g. 3.14.0): " VERSION
    check_version "$VERSION"
}

resolve_network "${1:-}"
resolve_version "${2:-}"
resolve_dev_cluster "$NETWORK"

prompt_nomad_ip "$NETWORK"
[[ -n "${NOMAD_HTTP_AUTH+set}" ]] || prompt_http_auth
prompt_node_addrs

cat <<EOF

Upgrading the ${NETWORK} dev cluster to ${VERSION}
  contract:      ${CONTRACT}
  Nomad:         ${NOMAD_ADDR}
  Nomad auth:    $(nomad_auth_state)
  node metrics:  ${MPC_NODE_ADDRS:-(none — verification will be skipped)}
EOF
confirm "Proceed?" || { echo "Aborted."; exit 0; }

step "### Step 1 — nodes"
run_cmd "${SCRIPT_DIR}/migrate-dev-nodes.sh" "$NETWORK" "$VERSION" \
    || die "Node upgrade did not complete."

step "### Verify"
if [[ -n "${MPC_NODE_ADDRS:-}" ]]; then
    run_step verify_nodes "$VERSION" || true
else
    echo "No node addresses given — skipping the build-info check."
fi
run_step test_sign "$NETWORK" || true

echo
ok "Done. Testnet first — upgrade the mainnet dev cluster only once this one is healthy."
