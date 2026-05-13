#!/usr/bin/env bash
#
# render-launcher-compose.sh
#
# Renders the launcher Docker Compose template at
#   crates/contract/assets/launcher_docker_compose.yaml.template          (TEE)
#   deployment/cvm-deployment/launcher_docker_compose_nontee.yaml.template  (non-TEE)
# by substituting the launcher and MPC node manifest digests, which must be
# supplied via environment variables.
#
# The rendered file's SHA256 is part of the remote attestation flow; the
# template is the same one the contract uses to compute its allowed compose
# hashes, so a render with the right digests produces a file the contract
# will accept.
#
# Required env:
#   LAUNCHER_MANIFEST_DIGEST   e.g. sha256:5308ee3f...
#   MPC_MANIFEST_DIGEST        e.g. sha256:5d1e604d...
#
# To discover the currently-allowed digests:
#   ./scripts/fetch-allowed-launcher-hashes.sh --network testnet
#
# Usage:
#   ./scripts/render-launcher-compose.sh                              # TEE, to stdout
#   ./scripts/render-launcher-compose.sh --nontee                     # non-TEE, to stdout
#   ./scripts/render-launcher-compose.sh --out launcher_docker_compose.yaml
#   ./scripts/render-launcher-compose.sh --verify-allowed --network testnet
#
# Flags:
#   --tee                  Render the TEE template (default).
#   --nontee               Render the non-TEE template.
#   --out <path>           Write to <path>. Default: stdout.
#   --verify-allowed       Also fetch the contract's allowed digest list and
#                          warn (don't fail) if either env digest is not
#                          present. Requires --network if not the default.
#   --network <name>       Network for --verify-allowed. Default: testnet.
#   --contract <id>        Contract id for --verify-allowed.
#   -h, --help             Show this help.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# The TEE template lives under crates/contract/assets/ because the contract
# `include_str!`s it into its WASM to derive the allowed compose hashes
# (see crates/contract/src/tee/proposal.rs). The non-TEE template is purely
# a deployment artifact — the contract never reads it — so it lives under
# deployment/.
TEE_TEMPLATE="$REPO_ROOT/crates/contract/assets/launcher_docker_compose.yaml.template"
NONTEE_TEMPLATE="$REPO_ROOT/deployment/cvm-deployment/launcher_docker_compose_nontee.yaml.template"

MODE="tee"
OUT=""
VERIFY=0
NETWORK="testnet"
CONTRACT=""

print_help() {
  sed -n '2,/^set -euo pipefail/p' "$0" | sed -E 's/^# ?//;/set -euo pipefail/d'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tee)              MODE="tee"; shift ;;
    --nontee)           MODE="nontee"; shift ;;
    --out)              OUT="$2"; shift 2 ;;
    --verify-allowed)   VERIFY=1; shift ;;
    --network)          NETWORK="$2"; shift 2 ;;
    --contract)         CONTRACT="$2"; shift 2 ;;
    -h|--help)          print_help; exit 0 ;;
    *) echo "Unknown flag: $1" >&2; print_help >&2; exit 2 ;;
  esac
done

# ----- validate env ------------------------------------------------------

missing=()
[[ -z "${LAUNCHER_MANIFEST_DIGEST:-}" ]] && missing+=(LAUNCHER_MANIFEST_DIGEST)
[[ -z "${MPC_MANIFEST_DIGEST:-}"      ]] && missing+=(MPC_MANIFEST_DIGEST)

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Error: required environment variable(s) not set: ${missing[*]}" >&2
  echo >&2
  echo "To see currently allowed digests:" >&2
  echo "  ./scripts/fetch-allowed-launcher-hashes.sh --network testnet" >&2
  echo >&2
  echo "Then export both digests and re-run:" >&2
  echo "  export LAUNCHER_MANIFEST_DIGEST=sha256:<launcher digest>" >&2
  echo "  export MPC_MANIFEST_DIGEST=sha256:<mpc node digest>" >&2
  exit 2
fi

digest_re='^sha256:[0-9a-f]{64}$'
if ! [[ "$LAUNCHER_MANIFEST_DIGEST" =~ $digest_re ]]; then
  echo "Error: LAUNCHER_MANIFEST_DIGEST is not a valid sha256 digest:" >&2
  echo "  '$LAUNCHER_MANIFEST_DIGEST'" >&2
  echo "  Expected form: sha256:<64 lowercase hex chars>" >&2
  exit 2
fi
if ! [[ "$MPC_MANIFEST_DIGEST" =~ $digest_re ]]; then
  echo "Error: MPC_MANIFEST_DIGEST is not a valid sha256 digest:" >&2
  echo "  '$MPC_MANIFEST_DIGEST'" >&2
  echo "  Expected form: sha256:<64 lowercase hex chars>" >&2
  exit 2
fi

# ----- pick template -----------------------------------------------------

case "$MODE" in
  tee)    TEMPLATE="$TEE_TEMPLATE" ;;
  nontee) TEMPLATE="$NONTEE_TEMPLATE" ;;
esac

[[ -f "$TEMPLATE" ]] || { echo "Error: template not found: $TEMPLATE" >&2; exit 3; }

# ----- optional contract verification (warn only) ------------------------

if [[ "$VERIFY" -eq 1 ]]; then
  fetcher="$SCRIPT_DIR/fetch-allowed-launcher-hashes.sh"
  if [[ ! -x "$fetcher" ]]; then
    echo "Warning: --verify-allowed requested but $fetcher not executable; skipping." >&2
  else
    args=(--network "$NETWORK" --all)
    [[ -n "$CONTRACT" ]] && args+=(--contract "$CONTRACT")
    allowed="$("$fetcher" "${args[@]}" 2>/dev/null || true)"
    if ! grep -Fq "$LAUNCHER_MANIFEST_DIGEST" <<<"$allowed"; then
      echo "Warning: LAUNCHER_MANIFEST_DIGEST not in contract's allowed_launcher_image_hashes on '$NETWORK'." >&2
      echo "         Attestation will be rejected unless this digest is voted in." >&2
    fi
    if ! grep -Fq "$MPC_MANIFEST_DIGEST" <<<"$allowed"; then
      echo "Warning: MPC_MANIFEST_DIGEST not in contract's allowed_docker_image_hashes on '$NETWORK'." >&2
      echo "         Attestation will be rejected unless this digest is voted in." >&2
    fi
  fi
fi

# ----- render ------------------------------------------------------------

launcher_hex="${LAUNCHER_MANIFEST_DIGEST#sha256:}"
mpc_hex="${MPC_MANIFEST_DIGEST#sha256:}"

rendered="$(sed \
  -e "s|{{LAUNCHER_IMAGE_HASH}}|${launcher_hex}|g" \
  -e "s|{{DEFAULT_IMAGE_DIGEST_HASH}}|${mpc_hex}|g" \
  "$TEMPLATE")"

if grep -q '{{' <<<"$rendered"; then
  echo "Error: unfilled placeholders remain after rendering:" >&2
  grep '{{' <<<"$rendered" >&2
  exit 4
fi

if [[ -n "$OUT" ]]; then
  printf '%s\n' "$rendered" > "$OUT"
  echo "Wrote $OUT" >&2
else
  printf '%s\n' "$rendered"
fi
