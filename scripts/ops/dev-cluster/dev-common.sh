#!/usr/bin/env bash
#
# dev-common.sh — helpers specific to the NEAR One dev clusters (source, don't
# run). Generic helpers live in ../common.sh.
#

# Sets CONTRACT, NEAR_NET, MEMBER_ACCOUNTS, SIGN_DEPOSIT, PROPOSE_DEPOSIT for a
# dev cluster, and re-points the endpoint vars at it when per-cluster ones are
# exported (NOMAD_ADDR_DEV_TESTNET, MPC_NODE_ADDRS_DEV_MAINNET, ...) so that
# choosing the network drives every step. Addresses stay out of this repo.
resolve_dev_cluster() {
    local suffix var
    case "$1" in
        testnet)
            CONTRACT="mpc-dev-contract.testnet" NEAR_NET="testnet" SIGN_DEPOSIT="1"
            MEMBER_ACCOUNTS="mpc-node-0-mpc-dev.testnet mpc-node-1-mpc-dev.testnet"
            suffix="TESTNET" ;;
        mainnet)
            CONTRACT="dev-contract.near" NEAR_NET="mainnet" SIGN_DEPOSIT="0.1"
            MEMBER_ACCOUNTS="mpc-0-dev-mainnet.dev-signer.near mpc-1-dev-mainnet.dev-signer.near"
            suffix="MAINNET" ;;
        *) die "Unknown dev cluster '$1' (expected testnet|mainnet)." ;;
    esac
    # 15 NEAR is just under the ~15.13 storage requirement.
    PROPOSE_DEPOSIT="16 NEAR"

    var="NOMAD_ADDR_DEV_${suffix}";      [[ -z "${!var:-}" ]] || export NOMAD_ADDR="${!var}"
    var="MPC_NODE_ADDRS_DEV_${suffix}";  [[ -z "${!var:-}" ]] || export MPC_NODE_ADDRS="${!var}"
    # +set so an intentionally empty per-cluster value still disables the prompt.
    var="NOMAD_HTTP_AUTH_DEV_${suffix}"; [[ -z "${!var+set}" ]] || export NOMAD_HTTP_AUTH="${!var}"
}

# Check each node in MPC_NODE_ADDRS reports release="<version>" in build info.
verify_nodes() {
    local version=$1
    require_cmds curl
    [[ -n "${MPC_NODE_ADDRS:-}" ]] || die "MPC_NODE_ADDRS is not set (e.g. \"host:8080 host:8080\")."

    local addr info ok=0 fail=0
    for addr in ${MPC_NODE_ADDRS}; do
        show_cmd curl -sf "http://${addr}/metrics" '|' grep mpc_node_build_info
        info=$(curl -sf --max-time 5 "http://${addr}/metrics" \
            | grep -o 'mpc_node_build_info{[^}]*}') || { echo "  (unreachable)"; fail=1; continue; }
        echo "  $info"
        if [[ "$info" == *"release=\"${version}\""* ]]; then ok=1; else fail=1; fi
    done
    [[ "$fail" -eq 0 && "$ok" -eq 1 ]] \
        && echo "All nodes report release=\"${version}\"." \
        || echo "Not all nodes are on ${version} yet."
}

# Submit a test signature request to the dev cluster contract (on-chain txn).
test_sign() {
    resolve_dev_cluster "$1"
    require_cmds near

    local signer=${MEMBER_ACCOUNTS%% *}
    local payload='[12,1,2,0,4,5,6,8,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,44]'
    local cmd=(near call --network-id "$NEAR_NET" "$CONTRACT" sign
        "{\"request\": {\"payload\": ${payload}, \"path\": \"test\", \"key_version\": 0}}"
        --accountId "$signer" --gas 300000000000000 --deposit "$SIGN_DEPOSIT")

    echo "Test sign on ${CONTRACT} as ${signer} (deposit ${SIGN_DEPOSIT} NEAR)."
    show_cmd "${cmd[@]}"
    confirm "Send it?" || return 0
    "${cmd[@]}" \
        && echo "Signature returned — the cluster is signing." \
        || echo "Test sign failed — investigate before proceeding."
}
