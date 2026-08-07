#!/usr/bin/env bash
#
# common.sh — generic helpers shared by the ops scripts (source, don't run).
# Dev-cluster-specific helpers live in dev-cluster/dev-common.sh.
#

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

require_cmds() {
    local missing=0
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'Missing dependency: %s\n' "$cmd" >&2
            missing=1
        }
    done
    [[ "$missing" -eq 0 ]] || die "Please install the missing dependencies above."
}

check_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "'$1' is not valid semver (expected MAJOR.MINOR.PATCH)."
}

confirm() {
    local reply
    read -rp "$1 [y/N] " reply
    [[ "$reply" == y || "$reply" == Y ]]
}
