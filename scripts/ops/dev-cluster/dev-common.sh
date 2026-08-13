#!/usr/bin/env bash
#
# dev-common.sh — helpers specific to the NEAR One dev clusters, including the
# Nomad HTTP client (source, don't run). Generic helpers live in ../common.sh.
#
# MPC_SIGN_WITH overrides the signer (default sign-with-legacy-keychain, which
# reads the ~/.near-credentials files first-time-setup.sh writes).
#

SIGN_WITH="${MPC_SIGN_WITH:-sign-with-legacy-keychain}"
# The node's web server (routes /metrics and /public_data) — static port in
# every mpc-node-* job spec, so it never needs discovering, only the host.
NODE_HTTP_PORT="${MPC_NODE_HTTP_PORT:-8080}"

# curl -K parses values as quoted strings with backslash escapes.
curl_cfg_escape() {
    local s=${1//\\/\\\\}
    printf '%s' "${s//\"/\\\"}"
}

# Echoes the request, and the response for mutations. Never the credentials.
nomad_curl() {
    local method=$1 path=$2 data=${3:-}
    local url="${NOMAD_ADDR%/}/v1${path}"
    # The API ignores the NOMAD_NAMESPACE env var (a nomad-CLI feature).
    if [[ -n "${NOMAD_NAMESPACE:-}" ]]; then
        local sep="?"; [[ "$url" != *\?* ]] || sep="&"
        url+="${sep}namespace=${NOMAD_NAMESPACE}"
    fi
    # --fail-with-body (curl >= 7.76): plain -f discards Nomad's error body.
    local args=(-sS --fail-with-body --max-time 30 -X "$method" "$url")
    [[ -z "$data" ]] || args+=(-H 'Content-Type: application/json' --data-binary @-)

    show_cmd curl -X "$method" "$url" ${data:+--data-binary @-}

    # Secrets not on argv: credentials via config stream, body via stdin.
    local config=""
    [[ -z "${NOMAD_HTTP_AUTH:-}" ]] || config+="user = \"$(curl_cfg_escape "$NOMAD_HTTP_AUTH")\""$'\n'
    [[ -z "${NOMAD_TOKEN:-}" ]] || config+="header = \"X-Nomad-Token: $(curl_cfg_escape "$NOMAD_TOKEN")\""$'\n'

    local response status=0
    response=$(printf '%s' "$data" | curl -K <(printf '%s' "$config") "${args[@]}") || status=$?
    if (( status != 0 )); then
        [[ -z "$response" ]] || show_output "$response"
        return "$status"
    fi

    # GET bodies are whole job definitions — too noisy to echo.
    [[ "$method" == GET ]] || show_output "$response"
    printf '%s' "$response"
}

# IDs of every mpc-node-* job on the cluster.
discover_job_ids() {
    local ids
    ids=$(nomad_curl GET "/jobs?prefix=mpc-node" | jq -r '.[].ID') \
        || die "Could not list jobs from ${NOMAD_ADDR}."
    [[ -n "$ids" ]] || die "No mpc-node-* jobs found at ${NOMAD_ADDR}."
    printf '%s' "$ids"
}

# Sets CONTRACT, NEAR_NET, MEMBER_ACCOUNTS, SIGN_DEPOSIT and re-points endpoint
# vars from per-cluster exports; network choice drives every step.
resolve_dev_cluster() {
    local suffix="${1^^}" var
    case "$1" in
        testnet)
            CONTRACT="mpc-dev-contract.testnet" NEAR_NET="testnet" SIGN_DEPOSIT="1 NEAR"
            MEMBER_ACCOUNTS="mpc-node-0-mpc-dev.testnet mpc-node-1-mpc-dev.testnet" ;;
        mainnet)
            CONTRACT="dev-contract.near" NEAR_NET="mainnet" SIGN_DEPOSIT="0.1 NEAR"
            MEMBER_ACCOUNTS="mpc-0-dev-mainnet.dev-signer.near mpc-1-dev-mainnet.dev-signer.near" ;;
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
        read -rp "Nomad URL for the ${label} dev cluster: " input
        # Tolerate pasted URL; preserve HTTPS, never downgrade to HTTP.
        scheme="http"; [[ "$input" != https://* ]] || scheme="https"
        input="${input#http://}"; input="${input#https://}"; input="${input%%/*}"
        if [[ ! "$input" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?$ ]]; then
            echo "  Expected an IPv4 address or URL (e.g. 10.0.0.1, 10.0.0.1:4646, http://10.0.0.1:4646)."
            continue
        fi
        NOMAD_ADDR="${scheme}://${input}"
    done
    export NOMAD_ADDR
}

prompt_http_auth() {
    local input
    while true; do
        read -rp "Nomad credentials for ${NOMAD_ADDR} (user:password): " input
        [[ "$input" != *:* ]] || break
        echo "  Expected user:password."
    done
    export NOMAD_HTTP_AUTH="$input"
    # Base64 on the wire is still cleartext over plain HTTP.
    [[ "${NOMAD_ADDR:-}" == https://* ]] \
        || warn "Note: these credentials will be sent over plain HTTP (${NOMAD_ADDR:-})."
}

# host:port of a job's running allocation, for MPC_NODE_ADDRS. Static port
# (NODE_HTTP_PORT) — only the host varies by where Nomad scheduled the job.
discover_node_addr() {
    local job_id=$1 alloc_id node_id ip
    alloc_id=$(nomad_curl GET "/job/${job_id}/allocations" \
        | jq -r '[.[] | select(.ClientStatus == "running")] | sort_by(.CreateIndex) | last | .ID // empty') \
        || return 1
    [[ -n "$alloc_id" ]] || return 1
    node_id=$(nomad_curl GET "/allocation/${alloc_id}" | jq -r '.NodeID // empty') || return 1
    [[ -n "$node_id" ]] || return 1
    ip=$(nomad_curl GET "/node/${node_id}" \
        | jq -r '.Attributes["unique.network.ip-address"] // (.HTTPAddr // "" | split(":")[0])') || return 1
    [[ -n "$ip" ]] || return 1
    printf '%s:%s' "$ip" "$NODE_HTTP_PORT"
}

# Tries Nomad auto-discovery first; only prompts if that finds nothing.
# MPC_NODE_ADDRS export (or MPC_NODE_ADDRS_DEV_<NET>) skips both.
prompt_node_addrs() {
    local input job_ids job_id addr addrs=()
    [[ -z "${MPC_NODE_ADDRS+set}" ]] || return 0

    if job_ids=$(discover_job_ids); then
        for job_id in $job_ids; do
            addr=$(discover_node_addr "$job_id") && addrs+=("$addr")
        done
    fi

    if [[ ${#addrs[@]} -gt 0 ]]; then
        export MPC_NODE_ADDRS="${addrs[*]}"
        ok "Discovered node metrics addresses: ${MPC_NODE_ADDRS}"
        return 0
    fi

    warn "Could not auto-discover node addresses from Nomad."
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

    local addr info try fetch
    local -a upgraded=() stale=() unreachable=()
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
        if [[ -z "$info" ]]; then echo "  (unreachable)"; unreachable+=("$addr"); continue; fi
        echo "  $info"
        if [[ "$info" == *"release=\"${version}\""* ]]; then
            upgraded+=("$addr")
        else
            stale+=("$addr")
        fi
    done

    # Unreachable is a visibility problem, not an upgrade failure — the dev
    # nodes sit on internal IPs, so report it separately from a version miss.
    (( ! ${#stale[@]} )) || warn "Not yet on ${version}: ${stale[*]}"
    (( ! ${#unreachable[@]} )) || \
        warn "Could not reach (upgrade state unknown): ${unreachable[*]}"
    if (( ${#upgraded[@]} && ! ${#stale[@]} && ! ${#unreachable[@]} )); then
        ok "All nodes report release=\"${version}\"."
    elif (( ${#upgraded[@]} )); then
        ok "${#upgraded[@]} node(s) report release=\"${version}\"."
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
