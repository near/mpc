#!/usr/bin/env bash
#
# common.sh — generic helpers shared by the ops scripts (source, don't run).
#

# Only when both streams are terminals, so redirected output stays clean.
# NO_COLOR is honoured (https://no-color.org).
if [[ -t 1 && -t 2 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m' C_ERR=$'\033[1;31m'
else
    C_RESET="" C_ERR=""
fi

die() {
    printf '%sError: %s%s\n' "$C_ERR" "$1" "$C_RESET" >&2
    exit 1
}

require_cmds() {
    local cmd missing=0
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'Missing dependency: %s\n' "$cmd" >&2
            missing=1
        }
    done
    [[ "$missing" -eq 0 ]] || die "Please install the missing dependencies above (hint: run from within 'nix develop')."
}

# Mirrors .github/workflows/release.yml, so release candidates work too.
check_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] \
        || die "'$1' is not valid semver (expected MAJOR.MINOR.PATCH[-SUFFIX])."
}
