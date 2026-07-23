#!/usr/bin/env bash
#
# upgrade-commands.sh — Print the ready-to-run propose/vote commands for a net.
#
# Emits the propose_update, vote_update, and (TEE nets only) vote_code_hash calls
# with the contract account, network, and deposit already filled in. It prints
# commands for you to review and run; it does not submit anything. See
# how-to/contract-upgrade.md and node-hash-vote.md.
#
# Usage:  ./scripts/ops/upgrade-commands.sh <VERSION> <net> [--update-id ID] [--account ACCT]
# Example: ./scripts/ops/upgrade-commands.sh 3.13.0 testnet --update-id 5

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ops/lib.sh
source "$HERE/lib.sh"

[[ $# -ge 2 ]] || die "Usage: $SCRIPT_NAME <VERSION> <net> [--update-id ID] [--account ACCT]"
version="$1"; net="$2"; shift 2
validate_version "$version"
resolve_net "$net"

update_id="<UPDATE_ID>"
# Placeholder is emitted verbatim into the sample command, so it must stay literal.
# shellcheck disable=SC2016
account='$YOUR_MPC_ACCOUNT'
while [[ $# -gt 0 ]]; do
    case "$1" in
        --update-id) update_id="${2:?--update-id needs a value}"; shift 2 ;;
        --account)   account="${2:?--account needs a value}"; shift 2 ;;
        *) die "Unknown flag '$1'." ;;
    esac
done

cat <<EOF
# --- ${net} (${NET_CONTRACT}, network-config ${NET_NETWORK}) ---

# 1. Propose the new WASM (run once; note the returned UpdateId). Needs serialized.bin
#    from upgrade-prepare.sh. Deposit ${NET_DEPOSIT} covers storage; excess is refunded.
near contract call-function as-transaction ${NET_CONTRACT} propose_update \\
  file-args serialized.bin prepaid-gas '100.0 Tgas' attached-deposit '${NET_DEPOSIT}' \\
  sign-as ${account} network-config ${NET_NETWORK} sign-with-keychain send

# 2. Vote for the proposal (every participant). 300 Tgas: the deciding vote deploys
#    + migrates inline.
near contract call-function as-transaction ${NET_CONTRACT} vote_update \\
  json-args '{"id": ${update_id}}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \\
  sign-as ${account} network-config ${NET_NETWORK} sign-with-keychain send
EOF

if [[ "$NET_IS_TEE" -eq 1 ]]; then
    require_cmds skopeo
    bare="$(node_digest "$version")"; bare="${bare#sha256:}"
    cat <<EOF

# 3. Vote the node image hash into the allow-list (every participant; TEE nets only).
near contract call-function as-transaction ${NET_CONTRACT} vote_code_hash \\
  json-args '{"code_hash": "${bare}"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \\
  sign-as ${account} network-config ${NET_NETWORK} sign-with-keychain send
EOF
else
    echo
    echo "# (dev cluster: no vote_code_hash — nodes run plain Nomad jobs, not TEE.)"
fi
