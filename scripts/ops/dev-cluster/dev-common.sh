#!/usr/bin/env bash
#
# dev-common.sh — helpers specific to the NEAR One dev clusters (source, don't
# run). Generic helpers live in ../common.sh.
#
# MPC_SIGN_WITH overrides the signer (default sign-with-legacy-keychain, which
# reads the ~/.near-credentials files first-time-setup.sh writes).
#

SIGN_WITH="${MPC_SIGN_WITH:-sign-with-legacy-keychain}"

# Sets CONTRACT, NEAR_NET, MEMBER_ACCOUNTS, SIGN_DEPOSIT and re-points endpoint
# vars from per-cluster exports; network choice drives every step.
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
    var="NOMAD_ADDR_DEV_${suffix}";      [[ -z "${!var:-}" ]] || export NOMAD_ADDR="${!var}"
    var="MPC_NODE_ADDRS_DEV_${suffix}";  [[ -z "${!var:-}" ]] || export MPC_NODE_ADDRS="${!var}"
    # +set: an intentionally empty value still disables the prompt.
    var="NOMAD_HTTP_AUTH_DEV_${suffix}"; [[ -z "${!var+set}" ]] || export NOMAD_HTTP_AUTH="${!var}"
}

# Prompts per run; NOMAD_ADDR_DEV_<NET> export skips it. Takes bare IP only.
prompt_nomad_ip() {
    local label=${1:-target} input scheme
    while [[ -z "${NOMAD_ADDR:-}" ]]; do
        read -rp "Nomad IP address for the ${label} dev cluster: " input
        # Tolerate pasted URL; preserve HTTPS, never downgrade to HTTP.
        scheme="http"; [[ "$input" != https://* ]] || scheme="https"
        input="${input#http://}"; input="${input#https://}"; input="${input%%/*}"
        if [[ ! "$input" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?$ ]]; then
            echo "  Expected an IPv4 address, optionally with a port (e.g. 10.0.0.1 or 10.0.0.1:4646)."
            continue
        fi
        NOMAD_ADDR="${scheme}://${input}"
    done
    export NOMAD_ADDR
}

prompt_http_auth() {
    local user pass
    read -rp "Nomad user for ${NOMAD_ADDR} (or user:password, blank for none): " user
    if [[ -z "$user" ]]; then
        NOMAD_HTTP_AUTH=""
    elif [[ "$user" == *:* ]]; then
        # Already in user:pass format (echoes password).
        NOMAD_HTTP_AUTH="$user"
    else
        read -rsp "Nomad password: " pass
        echo
        NOMAD_HTTP_AUTH="${user}:${pass}"
    fi
    export NOMAD_HTTP_AUTH
    # Base64 on the wire is still cleartext over plain HTTP.
    [[ -z "$NOMAD_HTTP_AUTH" || "${NOMAD_ADDR:-}" == https://* ]] \
        || warn "Note: these credentials will be sent over plain HTTP (${NOMAD_ADDR:-})."
}

prompt_node_addrs() {
    local input
    [[ -z "${MPC_NODE_ADDRS+set}" ]] || return 0
    read -rp "Node metrics addresses, space-separated (blank to skip verification): " input
    export MPC_NODE_ADDRS="$input"
}

# Whether a credential is configured — never the credential itself.
nomad_auth_state() {
    if [[ -z "${NOMAD_HTTP_AUTH+set}" ]]; then echo "(will prompt)"
    elif [[ -n "$NOMAD_HTTP_AUTH" ]]; then echo "(set)"
    else echo "(none)"; fi
}

# Probes the legacy ~/.near-credentials layout; first-time-setup.sh writes here.
have_signing_key() {
    [[ -f "${HOME}/.near-credentials/${NEAR_NET}/${1}.json" ]]
}

# Retries per node (warm-up delay after allocation starts).
verify_nodes() {
    local version=$1
    require_cmds curl
    [[ -n "${MPC_NODE_ADDRS:-}" ]] || die "MPC_NODE_ADDRS is not set (e.g. \"host:8080 host:8080\")."

    local addr info matched=0 fail=0 try fetch
    for addr in ${MPC_NODE_ADDRS}; do
        # Internal-only plain HTTP; no TLS endpoint exists.
        # nosemgrep: trailofbits.generic.curl-unencrypted-url.curl-unencrypted-url
        fetch=(curl -sf --max-time 5 "http://${addr}/metrics")
        show_cmd "${fetch[@]}"
        info=""
        for try in 1 2 3; do
            info=$("${fetch[@]}" | grep -o 'mpc_node_build_info{[^}]*}') || info=""
            [[ "$info" != *"release=\"${version}\""* ]] || break
            if (( try < 3 )); then sleep 5; fi
        done
        if [[ -z "$info" ]]; then echo "  (unreachable)"; fail=1; continue; fi
        echo "  $info"
        if [[ "$info" == *"release=\"${version}\""* ]]; then matched=1; else fail=1; fi
    done
    if [[ "$fail" -eq 0 && "$matched" -eq 1 ]]; then
        ok "All nodes report release=\"${version}\"."
    else
        warn "Not all nodes are on ${version} yet."
    fi
}

# Test signature request against the cluster contract (on-chain txn).
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
