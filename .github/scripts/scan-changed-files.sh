#!/usr/bin/env bash
#
# Scans changed files for malicious code, for executable content disguised as a
# binary asset, and for edits to files that run on repo open or build.
#
#   RULES_DIR=<dir of .yar files> BASE_SHA=<sha> HEAD_SHA=<sha> scan-changed-files.sh
#
# Exit 1 on a blocking finding, 2 when it cannot scan properly, 0 otherwise.

set -euo pipefail

# Fetch the pack with fetch-yara-rules.sh; see .github/yara/README.md.
RULES_DIR="${RULES_DIR:-}"
BLOCKING_RULES_FILE="${BLOCKING_RULES_FILE:-.github/yara/blocking-rules.txt}"
ALLOW_MISSING_SCANNERS="${ALLOW_MISSING_SCANNERS:-0}"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Runs on repo open or build without being invoked. Annotated, never blocked:
# editing these is routine here.
readonly AUTO_EXEC_PATTERN='^\.(vscode|devcontainer|githooks|cursor|claude|idea|github)/|\.code-workspace$|(^|/)build\.rs$|^\.cargo/config\.toml$|^(Makefile\.toml|justfile|flake\.nix|shell\.nix)$|\.(bat|cmd|ps1)$'

log()  { printf '%s\n' "$*" >&2; }
fail() { printf '::error::%s\n' "$*"; }
warn() { printf '::warning::%s\n' "$*"; }
die()  { log "$*"; exit 2; }

# Returns 1 when the caller opted out of a missing scanner, so its section skips.
have_scanner() {
    command -v "$1" >/dev/null 2>&1 && return 0
    [[ "$ALLOW_MISSING_SCANNERS" == "1" ]] || die "$1 is not installed; set ALLOW_MISSING_SCANNERS=1 to skip it."
    log "$1 is not installed; skipping its checks."
    return 1
}

[[ -n "$RULES_DIR" ]]    || die "RULES_DIR must point at a directory of .yar files."
[[ -n "${BASE_SHA:-}" ]] || die "BASE_SHA must be set."
[[ -n "${HEAD_SHA:-}" ]] || die "HEAD_SHA must be set."

# Diffing against a base that is missing finds no files and would pass, so refuse.
git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null \
    || die "Base commit ${BASE_SHA} is not in this clone; needs actions/checkout with fetch-depth: 0."

# -z is required: without it core.quotePath quotes any path holding a byte above
# 0x80, the literal fails the -f test below, and a homoglyph-named payload is
# dropped from the scan silently.
mapfile -d '' -t changed < <(git diff --name-only --diff-filter=ACMR -z "$BASE_SHA" "$HEAD_SHA")

files=()
for path in "${changed[@]}"; do
    [[ -f "$path" ]] && files+=("$path")   # renames and deletions are gone
done

if (( ${#files[@]} == 0 )); then
    log "No files to scan."
    exit 0
fi

log "Scanning ${#files[@]} changed file(s)."
blocking_findings=0

# ------------------------------------------------------------------- yara ---
if have_scanner yarac && have_scanner yara; then
    # Rules off the allowlist still report, they just do not fail the build, so a
    # version bump cannot add an unmeasured gate.
    declare -A is_blocking=()
    while read -r rule; do
        is_blocking["$rule"]=1
    done < <(grep -vE '^[[:space:]]*(#|$)' "$BLOCKING_RULES_FILE")

    (( ${#is_blocking[@]} > 0 )) || die "No blocking rules listed in $BLOCKING_RULES_FILE."
    log "${#is_blocking[@]} rule(s) are blocking; the rest are advisory."

    compiled="$(mktemp)"
    trap 'rm -f "$compiled"' EXIT
    yarac -w "$RULES_DIR"/*.yar "$compiled" || die "Failed to compile YARA rules from $RULES_DIR."

    for path in "${files[@]}"; do
        # One file per invocation: yara takes a single target, and given several it
        # silently treats the extras as rule sources and still exits 0.
        if ! matches=$(yara -w -C "$compiled" "$path" 2>&1); then
            fail "$path: yara failed: $matches"
            blocking_findings=1
            continue
        fi
        while read -r rule _; do
            [[ -n "$rule" ]] || continue
            if [[ -n "${is_blocking[$rule]:-}" ]]; then
                fail "$path: yara rule $rule matched"
                blocking_findings=1
            else
                warn "$path: yara rule $rule matched (advisory only)"
            fi
        done <<< "$matches"
    done
fi

# ----------------------------------------------------------------- magika ---
if have_scanner magika; then
    # Status checked here, not on the pipeline below whose status is python's: a
    # magika crash would otherwise yield no findings and pass.
    detected=$(magika --jsonl -- "${files[@]}" 2>&1) || die "magika failed: $detected"

    mismatches=$(printf '%s\n' "$detected" | python3 "$SCRIPT_DIR/find-type-mismatches.py") \
        || die "Could not interpret magika output."

    while IFS=$'\t' read -r path label extension; do
        [[ -n "$path" ]] || continue
        fail "$path: content is $label but the .$extension extension declares a binary asset"
        blocking_findings=1
    done <<< "$mismatches"
fi

# --------------------------------------------------------- auto-exec paths ---
for path in "${files[@]}"; do
    [[ "$path" =~ $AUTO_EXEC_PATTERN ]] \
        && warn "$path: runs automatically when the repo is opened or built - review as code"
done

exit "$blocking_findings"
