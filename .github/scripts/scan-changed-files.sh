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
ALLOW_MISSING_SCANNERS="${ALLOW_MISSING_SCANNERS:-0}"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BLOCKING_RULES_FILE="${BLOCKING_RULES_FILE:-$SCRIPT_DIR/../yara/blocking-rules.txt}"

# yara-x spins up a thread pool per run, which costs more than it saves on a
# small list. Measured on a 3-file scan: 33ms default versus 27ms single-threaded,
# while at 930 files single-threaded is 330ms against 116ms. Switch at a point
# comfortably above this repo's p90 diff of 17 files.
readonly SINGLE_THREAD_BELOW=50

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

# A commit missing from the clone makes the diff empty, which would pass, so
# refuse. Both ends need this: a head sha goes missing when a fork PR's branch is
# force-pushed between event dispatch and checkout.
for sha in "$BASE_SHA" "$HEAD_SHA"; do
    git cat-file -e "${sha}^{commit}" 2>/dev/null \
        || die "Commit ${sha} is not in this clone; needs actions/checkout with fetch-depth: 0."
done

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# -z is required: without it core.quotePath quotes any path holding a byte above
# 0x80, the literal fails the -f test below, and a homoglyph-named payload is
# dropped from the scan silently. Staged through a file because a process
# substitution's exit status is invisible to mapfile.
git diff --name-only --diff-filter=ACMR -z "$BASE_SHA" "$HEAD_SHA" > "$workdir/changed" \
    || die "git diff ${BASE_SHA}..${HEAD_SHA} failed."
mapfile -d '' -t changed < "$workdir/changed"

files=()
for path in "${changed[@]}"; do
    if [[ -f "$path" ]]; then
        # Both scanners take their targets as a newline-delimited list, so a path
        # containing a newline cannot be expressed and would be read as two
        # entries. Git permits such paths, so refuse rather than mis-scan.
        [[ "$path" == *$'\n'* ]] && die "Path contains a newline, which cannot be scanned safely: ${path@Q}"
        files+=("$path")
    else
        # ACMR excludes deletions and a rename reports only its destination, so
        # anything else here is unexpected rather than routine.
        log "Skipping ${path}: not a regular file."
    fi
done

if (( ${#files[@]} == 0 )); then
    log "No files to scan."
    exit 0
fi

log "Scanning ${#files[@]} changed file(s)."
printf '%s\n' "${files[@]}" > "$workdir/list"
blocking_findings=0

# ----------------------------------------------------------------- yara-x ---
if have_scanner yr; then
    # Rules off the allowlist still report, they just do not fail the build, so a
    # version bump cannot add an unmeasured gate.
    declare -A is_blocking=()
    while read -r rule || [[ -n "$rule" ]]; do   # tolerate a missing final newline
        is_blocking["$rule"]=1
    done < <(grep -vE '^[[:space:]]*(#|$)' "$BLOCKING_RULES_FILE")

    (( ${#is_blocking[@]} > 0 )) || die "No blocking rules listed in $BLOCKING_RULES_FILE."

    # --include-dir because three rules `include` the .meta files by bare name and
    # yr resolves those against the working directory, not the including file.
    compiled="$workdir/rules.yarc"
    yr compile -w --include-dir "$RULES_DIR" "$RULES_DIR"/*.yar -o "$compiled" 2>"$workdir/compile.err" \
        || die "Failed to compile YARA rules: $(cat "$workdir/compile.err")"

    # An allowlisted name that no longer exists means a bump renamed the rule, and
    # the renamed one would silently drop to advisory.
    mapfile -t pack_rules < <(sed -n 's/^rule[[:space:]]\{1,\}\([A-Za-z0-9_]\{1,\}\).*/\1/p' "$RULES_DIR"/*.yar | sort -u)
    for rule in "${!is_blocking[@]}"; do
        printf '%s\n' "${pack_rules[@]}" | grep -qxF "$rule" \
            || die "Blocking rule '$rule' is not in the pack; re-measure and update $BLOCKING_RULES_FILE."
    done
    log "${#is_blocking[@]} rule(s) are blocking; the rest are advisory."

    threads=()
    (( ${#files[@]} < SINGLE_THREAD_BELOW )) && threads=(--threads 1)

    # yr exits 0 even when it could not read a listed file, reporting only on
    # stderr, so stderr is the failure signal here rather than the exit status.
    yr scan -w "${threads[@]}" --compiled-rules --scan-list "$compiled" "$workdir/list" \
        > "$workdir/matches" 2> "$workdir/scan.err" \
        || die "yr scan failed: $(cat "$workdir/scan.err")"
    [[ -s "$workdir/scan.err" ]] && die "yr could not scan every file: $(cat "$workdir/scan.err")"

    while read -r rule path; do
        [[ -n "$rule" ]] || continue
        if [[ -n "${is_blocking[$rule]:-}" ]]; then
            fail "$path: yara rule $rule matched"
            blocking_findings=1
        else
            warn "$path: yara rule $rule matched (advisory only)"
        fi
    done < "$workdir/matches"
fi

# ----------------------------------------------------------------- magika ---
if have_scanner magika; then
    # Status checked separately from the pipeline below, whose status would be
    # python's: a magika crash would otherwise yield no findings and pass.
    magika --jsonl -- "${files[@]}" > "$workdir/detected" 2> "$workdir/magika.err" \
        || die "magika failed: $(cat "$workdir/magika.err")"
    [[ -s "$workdir/magika.err" ]] && log "magika stderr: $(cat "$workdir/magika.err")"

    mismatches=$(python3 "$SCRIPT_DIR/find-type-mismatches.py" < "$workdir/detected") \
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
