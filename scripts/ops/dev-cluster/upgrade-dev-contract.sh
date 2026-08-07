#!/usr/bin/env bash
#
# upgrade-dev-contract.sh — Step 2 of a dev-cluster upgrade: get the contract
# WASM (published release or a local build), borsh-serialize it, propose the
# update and vote it in with the cluster's member accounts. Run only after the
# nodes are on the new version.
#
# Usage: ./scripts/ops/dev-cluster/upgrade-dev-contract.sh <VERSION> <testnet|mainnet>
# Env:   MPC_WASM_SOURCE=release|build skips the source prompt;
#        MPC_SIGN_WITH overrides the signing method (default sign-with-keychain);
#        MPC_OPS_CACHE (default ~/.cache/mpc-ops) holds the artifacts.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=dev-common.sh
source "${SCRIPT_DIR}/dev-common.sh"

write_u32_le() {
    local n=$1 i
    for i in 0 8 16 24; do
        # shellcheck disable=SC2059
        printf "\\x$(printf '%02x' $(( (n >> i) & 0xFF )))"
    done
}

# Echoes the wasm path; progress goes to stderr so it stays capturable.
fetch_wasm() {
    local version=$1 dir=$2 source=${MPC_WASM_SOURCE:-}
    local wasm="${dir}/mpc-contract-v${version}.wasm"

    if [[ -z "$source" ]]; then
        local choice
        read -rp "WASM source — (r)eleased ${version} or local (b)uild? [r] " choice >&2
        case "${choice:-r}" in
            r|R) source=release ;;
            b|B) source=build ;;
            *) die "Unknown source '${choice}'." ;;
        esac
    fi

    if [[ "$source" == release ]]; then
        if [[ -f "$wasm" ]]; then
            step "==> Reusing ${wasm}" >&2
        else
            step "==> Downloading contract WASM from release ${version}..." >&2
            require_cmds gh tar
            run_cmd gh release download "$version" --repo near/mpc \
                --pattern "mpc-contract-v${version}.tar.gz" --dir "$dir" --clobber >&2
            run_cmd tar xzf "${dir}/mpc-contract-v${version}.tar.gz" -C "$dir" >&2
            [[ -f "$wasm" ]] || die "Expected ${wasm} after extracting the tarball."
        fi
    else
        require_cmds cargo git
        local root built
        root=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
        step "==> Building the contract from ${root} (local build — not a released artifact)..." >&2
        ( cd "$root" && run_cmd cargo near build non-reproducible-wasm --features abi \
            --profile=release-contract --manifest-path crates/contract/Cargo.toml --locked >&2 )
        # Named, not globbed: target/near also holds tee_verifier and
        # test_parallel_contract.
        built="${root}/target/near/mpc_contract/mpc_contract.wasm"
        [[ -f "$built" ]] || die "Expected ${built} after the cargo-near build."
        cp "$built" "$wasm"
    fi
    echo "$wasm"
}

[[ $# -eq 2 ]] || die "Usage: $0 <VERSION> <testnet|mainnet>"
VERSION=$1
check_version "$VERSION"
resolve_dev_cluster "$2"
require_cmds near

CACHE="${MPC_OPS_CACHE:-$HOME/.cache/mpc-ops}/${VERSION}"
mkdir -p "$CACHE"

WASM=$(fetch_wasm "$VERSION" "$CACHE")
echo "    wasm sha256: $(sha256_of "$WASM")"

SERIALIZED="${CACHE}/serialized.bin"
WASM_SIZE=$(wc -c < "$WASM")
# borsh ProposeUpdateArgs { code: Some(wasm), config: None }
{
    printf '\x01'
    write_u32_le "$WASM_SIZE"
    cat "$WASM"
    printf '\x00'
} > "$SERIALIZED"
[[ "$(wc -c < "$SERIALIZED")" -eq $((WASM_SIZE + 6)) ]] \
    || die "serialized.bin has an unexpected length."
step "==> ${SERIALIZED} ready ($(wc -c < "$SERIALIZED") bytes)"

PROPOSER=${MEMBER_ACCOUNTS%% *}
PROPOSE_CMD=(near contract call-function as-transaction "$CONTRACT" propose_update
    file-args "$SERIALIZED" prepaid-gas '100.0 Tgas' attached-deposit "$PROPOSE_DEPOSIT"
    sign-as "$PROPOSER" network-config "$NEAR_NET" "$SIGN_WITH" send)

step "About to propose the ${VERSION} contract on ${CONTRACT} (${NEAR_NET})"
echo "  proposer: ${PROPOSER}, deposit ${PROPOSE_DEPOSIT}"
show_cmd "${PROPOSE_CMD[@]}"
confirm "Send propose_update?" || { echo "Aborted before proposing."; exit 0; }

"${PROPOSE_CMD[@]}" \
    || die "propose_update failed (an account low on NEAR is the usual cause — top it up)."

step "==> Pending proposals:"
near_view proposed_updates || true

# near-cli's result format is too unstable to parse an id out of.
read -rp "UpdateId to vote on: " UPDATE_ID
[[ "$UPDATE_ID" =~ ^[0-9]+$ ]] || die "'${UPDATE_ID}' is not a numeric UpdateId."

# The deciding vote deploys + migrates inline, hence 300 Tgas.
for account in $MEMBER_ACCOUNTS; do
    vote_cmd=(near contract call-function as-transaction "$CONTRACT" vote_update
        json-args "{\"id\": ${UPDATE_ID}}" prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR'
        sign-as "$account" network-config "$NEAR_NET" "$SIGN_WITH" send)
    show_cmd "${vote_cmd[@]}"
    confirm "Vote for update ${UPDATE_ID} as ${account}?" || { echo "    skipped."; continue; }
    "${vote_cmd[@]}" || echo "    vote failed for ${account}."
done

step "==> Contract version (expect ${VERSION} once threshold was reached):"
near_view version || true
