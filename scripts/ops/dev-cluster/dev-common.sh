#!/usr/bin/env bash
#
# dev-common.sh — helpers specific to the NEAR One dev clusters (source, don't
# run). Generic helpers live in ../common.sh.
#
# MPC_SIGN_WITH overrides how near-cli signs — use sign-with-legacy-keychain
# when the keychain can't find a key written to ~/.near-credentials.
#

SIGN_WITH="${MPC_SIGN_WITH:-sign-with-keychain}"

# Sets CONTRACT, NEAR_NET, MEMBER_ACCOUNTS, SIGN_DEPOSIT, PROPOSE_DEPOSIT for a
# dev cluster, and re-points the endpoint vars at it when per-cluster ones are
# exported (NOMAD_ADDR_DEV_TESTNET, MPC_NODE_ADDRS_DEV_MAINNET, ...) so that
# choosing the network drives every step. Addresses stay out of this repo.
resolve_dev_cluster() {
    local suffix var
    case "$1" in
        testnet)
            CONTRACT="mpc-dev-contract.testnet" NEAR_NET="testnet" SIGN_DEPOSIT="1 NEAR"
            MEMBER_ACCOUNTS="mpc-node-0-mpc-dev.testnet mpc-node-1-mpc-dev.testnet"
            suffix="TESTNET" ;;
        mainnet)
            CONTRACT="dev-contract.near" NEAR_NET="mainnet" SIGN_DEPOSIT="0.1 NEAR"
            MEMBER_ACCOUNTS="mpc-0-dev-mainnet.dev-signer.near mpc-1-dev-mainnet.dev-signer.near"
            suffix="MAINNET" ;;
        *) die "Unknown dev cluster '$1' (expected testnet|mainnet)." ;;
    esac
    # Comfortably over ProposedUpdates::required_deposit (see
    # propose_update_required_deposit_yoctonear); the excess is refunded.
    # Read by upgrade-dev-contract.sh.
    PROPOSE_DEPOSIT="16 NEAR"

    var="NOMAD_ADDR_DEV_${suffix}";      [[ -z "${!var:-}" ]] || export NOMAD_ADDR="${!var}"
    var="MPC_NODE_ADDRS_DEV_${suffix}";  [[ -z "${!var:-}" ]] || export MPC_NODE_ADDRS="${!var}"
    # +set so an intentionally empty per-cluster value still disables the prompt.
    var="NOMAD_HTTP_AUTH_DEV_${suffix}"; [[ -z "${!var+set}" ]] || export NOMAD_HTTP_AUTH="${!var}"
}

# The endpoint and its credentials are typed in per run. Exporting the matching
# NOMAD_ADDR_DEV_<NET> / NOMAD_HTTP_AUTH_DEV_<NET> skips the corresponding prompt.
# Asks for the bare IP; the scheme and API path are the script's business.
prompt_nomad_ip() {
    local label=${1:-target} input
    while [[ -z "${NOMAD_ADDR:-}" ]]; do
        read -rp "Nomad IP address for the ${label} dev cluster: " input
        # Tolerate a pasted URL rather than rejecting it.
        input="${input#http://}"; input="${input#https://}"; input="${input%%/*}"
        if [[ ! "$input" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?$ ]]; then
            echo "  Expected an IPv4 address, optionally with a port (e.g. 10.0.0.1 or 10.0.0.1:4646)."
            continue
        fi
        NOMAD_ADDR="http://${input}"
    done
    export NOMAD_ADDR
}

prompt_http_auth() {
    local user pass
    read -rp "Nomad user for ${NOMAD_ADDR} (or user:password, blank for none): " user
    if [[ -z "$user" ]]; then
        NOMAD_HTTP_AUTH=""
    elif [[ "$user" == *:* ]]; then
        # Already joined — note this form echoes the password to the terminal.
        NOMAD_HTTP_AUTH="$user"
    else
        read -rsp "Nomad password: " pass
        echo
        NOMAD_HTTP_AUTH="${user}:${pass}"
    fi
    export NOMAD_HTTP_AUTH
}

prompt_node_addrs() {
    local input
    [[ -z "${MPC_NODE_ADDRS+set}" ]] || return 0
    read -rp "Node metrics addresses, space-separated (blank to skip verification): " input
    export MPC_NODE_ADDRS="$input"
}

# Report whether a credential is configured — never the credential itself.
nomad_auth_state() {
    if [[ -z "${NOMAD_HTTP_AUTH+set}" ]]; then echo "(will prompt)"
    elif [[ -n "$NOMAD_HTTP_AUTH" ]]; then echo "(set)"
    else echo "(none)"; fi
}

# Check each node in MPC_NODE_ADDRS reports release="<version>" in build info.
verify_nodes() {
    local version=$1
    require_cmds curl
    [[ -n "${MPC_NODE_ADDRS:-}" ]] || die "MPC_NODE_ADDRS is not set (e.g. \"host:8080 host:8080\")."

    local addr info ok=0 fail=0
    for addr in ${MPC_NODE_ADDRS}; do
        # The node's debug/metrics listener is plain HTTP, reachable only from
        # inside the cluster network; there is no TLS endpoint to point at.
        # nosemgrep: trailofbits.generic.curl-unencrypted-url.curl-unencrypted-url
        show_cmd curl -sf "http://${addr}/metrics" '|' grep mpc_node_build_info
        # nosemgrep: trailofbits.generic.curl-unencrypted-url.curl-unencrypted-url
        info=$(curl -sf --max-time 5 "http://${addr}/metrics" \
            | grep -o 'mpc_node_build_info{[^}]*}') || { echo "  (unreachable)"; fail=1; continue; }
        echo "  $info"
        if [[ "$info" == *"release=\"${version}\""* ]]; then ok=1; else fail=1; fi
    done
    if [[ "$fail" -eq 0 && "$ok" -eq 1 ]]; then
        ok "All nodes report release=\"${version}\"."
    else
        warn "Not all nodes are on ${version} yet."
    fi
}

# Submit a test signature request to the dev cluster contract (on-chain txn).
test_sign() {
    resolve_dev_cluster "$1"
    require_cmds near

    local signer=${MEMBER_ACCOUNTS%% *}
    local payload='[12,1,2,0,4,5,6,8,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,44]'
    local cmd=(near contract call-function as-transaction "$CONTRACT" sign
        json-args "{\"request\": {\"payload\": ${payload}, \"path\": \"test\", \"key_version\": 0}}"
        prepaid-gas '300.0 Tgas' attached-deposit "$SIGN_DEPOSIT"
        sign-as "$signer" network-config "$NEAR_NET" "$SIGN_WITH" send)

    echo "Test sign on ${CONTRACT} as ${signer} (deposit ${SIGN_DEPOSIT})."
    show_cmd "${cmd[@]}"
    confirm "Send it?" || return 0
    if "${cmd[@]}"; then
        ok "Signature returned — the cluster is signing."
    else
        warn "Test sign failed — investigate before proceeding."
    fi
}
