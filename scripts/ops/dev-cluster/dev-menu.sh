#!/usr/bin/env bash
#
# dev-menu.sh — entry point for dev-cluster work. Picks the network and
# version, then runs the upgrade in runbook order: nodes, verify, contract.
#
# Usage: ./scripts/ops/dev-cluster/dev-menu.sh [testnet|mainnet] [VERSION]
# Env:   NOMAD_ADDR_DEV_{TESTNET,MAINNET}, MPC_NODE_ADDRS_DEV_{TESTNET,MAINNET},
#        NOMAD_HTTP_AUTH_DEV_{TESTNET,MAINNET} — the chosen network selects one.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=dev-common.sh
source "${SCRIPT_DIR}/dev-common.sh"

# Validated here so a typo re-prompts instead of hitting resolve_dev_cluster's die().
ask_network() {
    local choice
    while true; do
        read -rp "Network (testnet|mainnet) [testnet]: " choice
        NETWORK="${choice:-testnet}"
        case "$NETWORK" in
            testnet|mainnet) return 0 ;;
            *) echo "Unknown network '${NETWORK}'." ;;
        esac
    done
}

NETWORK="${1:-}"
VERSION="${2:-}"
case "$NETWORK" in
    testnet|mainnet) ;;
    "") ask_network ;;
    *) die "Unknown network '${NETWORK}' (expected testnet|mainnet)." ;;
esac
if [[ -z "$VERSION" ]]; then
    read -rp "Version (e.g. 3.14.0): " VERSION
fi
check_version "$VERSION"

resolve_dev_cluster "$NETWORK"

cat <<EOF

Upgrading the ${NETWORK} dev cluster to ${VERSION}
  contract:       ${CONTRACT}
  NOMAD_ADDR:     ${NOMAD_ADDR:-(not set)}
  MPC_NODE_ADDRS: ${MPC_NODE_ADDRS:-(not set)}
EOF
confirm "Proceed?" || { echo "Aborted."; exit 0; }

echo
echo "### Step 1 — nodes"
run_cmd "${SCRIPT_DIR}/migrate-dev-cluster.sh" "$VERSION" \
    || die "Node upgrade did not complete — stopping before the contract step."

echo
echo "### Verify"
# Subshells: a die() here must not skip the contract step below.
( verify_nodes "$VERSION" ) || true
( test_sign "$NETWORK" ) || true

echo
echo "### Step 2 — contract"
echo "Only for releases that change crates/contract (diff it between the two tags)."
if confirm "Upgrade the contract too?"; then
    run_cmd "${SCRIPT_DIR}/upgrade-dev-contract.sh" "$VERSION" "$NETWORK" || true
else
    echo "Skipped — nodes only."
fi

echo
echo "Done. Testnet first — upgrade the mainnet dev cluster only once this one is healthy."
