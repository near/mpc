#!/usr/bin/env bash
#
# menu.sh — entry point for the MPC release/ops tooling.
# Usage: ./scripts/ops/menu.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

while true; do
    cat <<EOF

MPC ops menu
  1) release github code    — apply the local release file changes (prepare-github-release.sh)
  2) migrate devnet cluster — upgrade a dev cluster's nodes, verify, then its contract
  q) quit
EOF
    read -rp "> " choice || exit 0
    # Subshells so a die() in a step ends the step, not the menu.
    case "$choice" in
        1) (
               read -rp "Version to release (e.g. 3.14.0): " version
               check_version "$version"
               "${SCRIPT_DIR}/prepare-github-release.sh" "$version"
           ) || true ;;
        2) ( "${SCRIPT_DIR}/dev-cluster/dev-menu.sh" ) || true ;;
        q|Q) exit 0 ;;
        *) echo "Unknown choice '${choice}'." ;;
    esac
done
