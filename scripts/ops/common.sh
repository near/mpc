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

# Render a command so the printed line stays copy-pasteable: anything outside
# the shell-safe set gets single-quoted.
fmt_cmd() {
    local out="" arg
    for arg in "$@"; do
        case "$arg" in
            ''|*[!A-Za-z0-9_/.:=@%+,-]*) out+=" '${arg//\'/\'\\\'\'}'" ;;
            *) out+=" $arg" ;;
        esac
    done
    printf '%s' "${out# }"
}

# Echo a command as it runs. Goes to stderr so it stays visible even when the
# caller captures the command's stdout.
show_cmd() {
    printf '\n  $ %s\n' "$(fmt_cmd "$@")" >&2
}

# Echo a captured response the caller would otherwise swallow, truncating the
# long ones (Nomad job definitions run to several KB).
show_output() {
    local text=$1 limit=${2:-1500}
    if (( ${#text} > limit )); then
        printf '%s\n  … (%d more characters)\n' "${text:0:limit}" "$(( ${#text} - limit ))" >&2
    else
        printf '%s\n' "$text" >&2
    fi
}

# Print a command, run it, and let its output through.
run_cmd() {
    show_cmd "$@"
    "$@"
}
