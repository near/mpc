#!/usr/bin/env bash
#
# menu.sh — Interactive entry point for the scripts/ops/ operator tooling.
#
# Presents the available operations and dispatches to the individual scripts
# (each of which is also runnable on its own). Prompts for the inputs an action
# needs, then runs it — echoing the exact command it launches.
#
# Usage: ./scripts/ops/menu.sh

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ops/lib.sh
source "$HERE/lib.sh"

ask() {
    # ask <prompt> <var-name>; empty input is rejected.
    local prompt="$1" __var="$2" __val
    read -rp "$prompt" __val
    [[ -n "$__val" ]] || die "no value given."
    printf -v "$__var" '%s' "$__val"
}

# Set indirectly by ask() via printf -v; declared here so it reads as assigned.
version=""; net=""

echo "MPC ops menu — pick an action:"
PS3=$'\nAction (number): '
options=(
    "Cut a release (version bump, changelog, ABI, licenses)"
    "Prepare an upgrade (build serialized.bin + hashes)"
    "Print propose/vote commands for a net"
    "Show read-only upgrade status for a net"
    "Quit"
)
select opt in "${options[@]}"; do
    case "${opt:-}" in
        "${options[0]}")
            ask "Version (e.g. 3.13.0): " version
            run "$HERE/prepare-release.sh" "$version"
            break ;;
        "${options[1]}")
            ask "Version (e.g. 3.13.0): " version
            run "$HERE/upgrade-prepare.sh" "$version"
            break ;;
        "${options[2]}")
            ask "Version (e.g. 3.13.0): " version
            ask "Net (mainnet|testnet|dev-testnet|dev-mainnet): " net
            run "$HERE/upgrade-commands.sh" "$version" "$net"
            break ;;
        "${options[3]}")
            ask "Net (mainnet|testnet|dev-testnet|dev-mainnet): " net
            read -rp "Node IPs (space-separated, optional): " -a ips
            if [[ ${#ips[@]} -gt 0 ]]; then
                run "$HERE/upgrade-status.sh" "$net" "${ips[@]}"
            else
                run "$HERE/upgrade-status.sh" "$net"
            fi
            break ;;
        "${options[4]}")
            exit 0 ;;
        *)
            echo "Invalid choice — enter a number from the list." ;;
    esac
done
