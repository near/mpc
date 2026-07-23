# shellcheck shell=bash
#
# lib.sh — shared helpers for the scripts/ops/ operator tooling.
#
# Sourced, not executed. Sets strict mode + an ERR trap so every script reports
# exactly which command failed, and provides run() so every external command is
# echoed before it runs. See how-to/cluster-upgrade.md for the flow these serve.

set -Eeuo pipefail

SCRIPT_NAME="${0##*/}"

_on_err() {
    local ec="$1" line="$2" cmd="$3"
    printf 'Error: command exited %d at %s:%s\n  %s\n' "$ec" "$SCRIPT_NAME" "$line" "$cmd" >&2
    exit "$ec"
}
# $? first so the exit code is captured before anything else in the trap expands.
trap '_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

# Echo the exact command (shell-quoted, reusable as-is) to stderr, then run it.
run() {
    { printf '+'; printf ' %q' "$@"; printf '\n'; } >&2
    "$@"
}

require_cmds() {
    local missing=0 cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'Missing dependency: %s\n' "$cmd" >&2
            missing=1
        }
    done
    [[ "$missing" -eq 0 ]] || die "Install the missing dependencies above (hint: run from within 'nix develop')."
}

validate_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "'$1' is not valid semver (expected MAJOR.MINOR.PATCH)."
}

# Maps a <net> to its contract account, near-cli network, propose deposit, and whether
# it is a TEE-gated production signer (dev clusters run plain Nomad jobs, no hash vote).
# Sets: NET_CONTRACT NET_NETWORK NET_DEPOSIT NET_IS_TEE
# (consumed by the scripts that source this lib, so not "used" within it.)
# shellcheck disable=SC2034
resolve_net() {
    case "$1" in
        mainnet)      NET_CONTRACT="v1.signer";                NET_NETWORK="mainnet"; NET_DEPOSIT="20 NEAR"; NET_IS_TEE=1 ;;
        testnet)      NET_CONTRACT="v1.signer-prod.testnet";   NET_NETWORK="testnet"; NET_DEPOSIT="20 NEAR"; NET_IS_TEE=1 ;;
        dev-testnet)  NET_CONTRACT="mpc-dev-contract.testnet"; NET_NETWORK="testnet"; NET_DEPOSIT="16 NEAR"; NET_IS_TEE=0 ;;
        dev-mainnet)  NET_CONTRACT="dev-contract.near";        NET_NETWORK="mainnet"; NET_DEPOSIT="16 NEAR"; NET_IS_TEE=0 ;;
        *) die "Unknown net '$1' (expected: mainnet | testnet | dev-testnet | dev-mainnet)." ;;
    esac
}

# Echoes the sha256:-prefixed manifest digest of nearone/mpc-node:<VERSION>.
# The bare-hex form (for vote_code_hash) is the same value minus the sha256: prefix.
node_digest() {
    local version="$1" digest
    digest="$(run skopeo inspect --no-creds --format '{{.Digest}}' "docker://nearone/mpc-node:${version}")" \
        || die "skopeo could not inspect nearone/mpc-node:${version} (is it published?)."
    printf '%s\n' "$digest"
}
