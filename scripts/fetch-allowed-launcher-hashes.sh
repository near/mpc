#!/usr/bin/env bash
#
# fetch-allowed-launcher-hashes.sh
#
# Prints the launcher and MPC node manifest digests currently allowed by the
# MPC contract. Read-only: never writes a file, never exports env. The
# operator decides what to do with the values.
#
# Pair with `scripts/render-launcher-compose.sh`, which requires the digests
# to be explicitly set in the environment before it will render anything.
#
# Usage:
#   ./scripts/fetch-allowed-launcher-hashes.sh --network testnet
#   ./scripts/fetch-allowed-launcher-hashes.sh --network mainnet --contract v1.signer
#   ./scripts/fetch-allowed-launcher-hashes.sh --network testnet --export
#
# Flags:
#   --network <name>       NEAR network-config name. Default: testnet.
#                          Examples: testnet, mainnet, mpc-localnet.
#   --contract <id>        Contract account id. If omitted, a default is
#                          chosen per network (see DEFAULT_CONTRACTS below).
#   --export               Emit shell `export` lines so the operator can:
#                            eval "$(./scripts/fetch-allowed-launcher-hashes.sh --network testnet --export)"
#                          The operator still chooses to eval — nothing is
#                          set behind their back.
#   --all                  List every allowed digest, not just the latest.
#   -h, --help             Show this help.
#
# Requires: `near` CLI, `jq`.
#
# The contract returns hashes as 64-char lowercase hex. This script prefixes
# them with `sha256:` to match Docker manifest digest format.

set -euo pipefail

# ----- defaults ----------------------------------------------------------

NETWORK="testnet"
CONTRACT=""
EXPORT_FORMAT=0
LIST_ALL=0

declare -A DEFAULT_CONTRACTS=(
  [testnet]="v1.signer-prod.testnet"
  [mainnet]="v1.signer"
  [mpc-localnet]="mpc-contract.test.near"
)

# ----- parse flags -------------------------------------------------------

print_help() {
  sed -n '2,/^set -euo pipefail/p' "$0" | sed -E 's/^# ?//;/set -euo pipefail/d'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)  NETWORK="$2"; shift 2 ;;
    --contract) CONTRACT="$2"; shift 2 ;;
    --export)   EXPORT_FORMAT=1; shift ;;
    --all)      LIST_ALL=1; shift ;;
    -h|--help)  print_help; exit 0 ;;
    *) echo "Unknown flag: $1" >&2; print_help >&2; exit 2 ;;
  esac
done

if [[ -z "$CONTRACT" ]]; then
  CONTRACT="${DEFAULT_CONTRACTS[$NETWORK]:-}"
fi
if [[ -z "$CONTRACT" ]]; then
  echo "Error: no default contract for network '$NETWORK'. Pass --contract <id>." >&2
  exit 2
fi

# ----- preflight ---------------------------------------------------------

command -v near >/dev/null 2>&1 || {
  echo "Error: 'near' CLI not found. Install: https://github.com/near/near-cli-rs" >&2
  exit 3
}
command -v jq >/dev/null 2>&1 || {
  echo "Error: 'jq' not found. Install via your package manager." >&2
  exit 3
}

# ----- contract call -----------------------------------------------------

# `near contract call-function as-read-only` prints the JSON return value
# between two banner lines. Pull just the JSON. The CLI sometimes exits
# non-zero even when the call succeeds (observed: empty array result on
# mainnet returns exit 1), so we don't trust the exit code — we trust the
# JSON. If parsing fails, then it's a real error.
near_call_ro() {
  local method="$1" out json
  out=$(near contract call-function as-read-only "$CONTRACT" "$method" \
          json-args '{}' network-config "$NETWORK" now 2>&1 || true)
  json=$(printf '%s\n' "$out" \
    | sed -n '/^Function execution return value/,/^Here is your console/{
        /^Function/d
        /^Here is your console/d
        p
      }')
  if ! echo "$json" | jq empty >/dev/null 2>&1; then
    echo "Error: failed to parse JSON from contract view '$method' on '$CONTRACT' (network '$NETWORK')." >&2
    echo "Raw CLI output follows:" >&2
    printf '%s\n' "$out" >&2
    exit 5
  fi
  printf '%s\n' "$json"
}

# Returns hex strings (no sha256: prefix); prefix to match Docker digest form.
# Empty arrays render as "(none — no digests voted in)" so the caller can tell
# the difference between "contract has no allowlist yet" and "fetch failed."
format_digest_list() {
  local raw="$1" mode="$2"  # mode: "all" or "latest"
  local count
  count=$(echo "$raw" | jq 'length')
  if [[ "$count" -eq 0 ]]; then
    echo "(none — no digests voted in on this contract)"
    return
  fi
  if [[ "$mode" == "latest" ]]; then
    echo "$raw" | jq -r '.[0]' | sed 's/^/sha256:/'
  else
    echo "$raw" | jq -r '.[]'  | sed 's/^/sha256:/'
  fi
}

# Prints the latest digest with `sha256:` prefix, or empty if the list is empty.
latest_digest() {
  local raw="$1"
  local count
  count=$(echo "$raw" | jq 'length')
  [[ "$count" -eq 0 ]] && return
  echo "$raw" | jq -r '.[0]' | sed 's/^/sha256:/'
}

launcher_raw="$(near_call_ro allowed_launcher_image_hashes)"
mpc_raw="$(near_call_ro allowed_docker_image_hashes)"

mode="latest"; [[ "$LIST_ALL" -eq 1 ]] && mode="all"

launcher_formatted="$(format_digest_list "$launcher_raw" "$mode")"
mpc_formatted="$(format_digest_list "$mpc_raw" "$mode")"
latest_launcher="$(latest_digest "$launcher_raw")"
latest_mpc="$(latest_digest "$mpc_raw")"

# ----- output ------------------------------------------------------------

if [[ "$EXPORT_FORMAT" -eq 1 ]]; then
  # Always export only the latest, even with --all (env vars are scalar).
  if [[ -z "$latest_launcher" || -z "$latest_mpc" ]]; then
    echo "Error: contract '${CONTRACT}' on '${NETWORK}' has no allowed digests voted in;" >&2
    echo "       nothing to export. Vote a digest in first or pick a contract that has one." >&2
    exit 4
  fi
  echo "export LAUNCHER_MANIFEST_DIGEST=${latest_launcher}"
  echo "export MPC_MANIFEST_DIGEST=${latest_mpc}"
  exit 0
fi

cat <<EOF
Contract:  ${CONTRACT}
Network:   ${NETWORK}

Allowed launcher image digest(s) (latest first):
$(echo "$launcher_formatted" | sed 's/^/  /')

Allowed MPC node image digest(s) (latest first):
$(echo "$mpc_formatted" | sed 's/^/  /')
EOF

if [[ -n "$latest_launcher" && -n "$latest_mpc" ]]; then
  cat <<EOF

To use the latest with the render script:

  export LAUNCHER_MANIFEST_DIGEST=${latest_launcher}
  export MPC_MANIFEST_DIGEST=${latest_mpc}
  ./scripts/render-launcher-compose.sh --tee --out launcher_docker_compose.yaml

Or have this script emit the exports for eval:

  eval "\$(./scripts/fetch-allowed-launcher-hashes.sh --network ${NETWORK} --export)"
EOF
fi
