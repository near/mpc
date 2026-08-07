#!/usr/bin/env bash
#
# common.sh — generic helpers shared by the ops scripts (source, don't run).
# Dev-cluster-specific helpers live in dev-cluster/dev-common.sh.
#

# Colour only when both streams are terminals, so redirected output stays
# clean. NO_COLOR is honoured (https://no-color.org).
if [[ -t 1 && -t 2 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m' C_CMD=$'\033[36m' C_OUT=$'\033[2m'
    C_STEP=$'\033[1;34m' C_OK=$'\033[32m' C_WARN=$'\033[33m' C_ERR=$'\033[1;31m'
else
    C_RESET="" C_CMD="" C_OUT="" C_STEP="" C_OK="" C_WARN="" C_ERR=""
fi

die() {
    printf '%sError: %s%s\n' "$C_ERR" "$1" "$C_RESET" >&2
    exit 1
}

step() { printf '\n%s%s%s\n' "$C_STEP" "$*" "$C_RESET"; }
ok()   { printf '%s%s%s\n' "$C_OK" "$*" "$C_RESET"; }
warn() { printf '%s%s%s\n' "$C_WARN" "$*" "$C_RESET" >&2; }

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

# Mirrors the pattern .github/workflows/release.yml accepts, so a release
# candidate can be rolled out with this tooling too.
check_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] \
        || die "'$1' is not valid semver (expected MAJOR.MINOR.PATCH[-SUFFIX])."
}

# sha256sum is GNU-only; macOS ships shasum instead.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "Need sha256sum or shasum to hash ${1}."
    fi
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
    printf '\n%s  $ %s%s\n' "$C_CMD" "$(fmt_cmd "$@")" "$C_RESET" >&2
}

# Echo a captured response the caller would otherwise swallow, truncating the
# long ones (Nomad job definitions run to several KB).
show_output() {
    local text=$1 limit=${2:-1500}
    if (( ${#text} > limit )); then
        printf '%s%s\n  … (%d more characters)%s\n' \
            "$C_OUT" "${text:0:limit}" "$(( ${#text} - limit ))" "$C_RESET" >&2
    else
        printf '%s%s%s\n' "$C_OUT" "$text" "$C_RESET" >&2
    fi
}

# Print a command, run it, and let its output through.
run_cmd() {
    show_cmd "$@"
    "$@"
}
