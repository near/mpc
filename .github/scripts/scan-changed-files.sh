#!/usr/bin/env bash
#
# Scans changed files for executable content disguised as a binary asset, and
# annotates edits to files that run on repo open or build.
#
#   BASE_SHA=<sha> HEAD_SHA=<sha> [SARIF_OUT=<path>] scan-changed-files.sh
#
# Writes a SARIF run to SARIF_OUT and exits 0 even when it reported something:
# blocking a merge is code scanning merge protection's job, not this script's.
# Exits 2 when it cannot scan properly, which must never look like a clean run.

set -euo pipefail

SARIF_OUT="${SARIF_OUT:-results.sarif}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly MISMATCH_SCRIPT="$SCRIPT_DIR/find-type-mismatches.py"

# Runs on repo open or build without being invoked. Annotated, never blocked:
# editing these is routine here.
readonly AUTO_EXEC_PATTERN='^\.(vscode|devcontainer|githooks|cursor|claude|idea|github)/|\.code-workspace$|(^|/)build\.rs$|^\.cargo/config\.toml$|^(Makefile\.toml|justfile|flake\.nix|shell\.nix)$|\.(bat|cmd|ps1)$'

log()  { printf '%s\n' "$*" >&2; }
warn() { printf '::warning::%s\n' "$*"; }
die()  { log "$*"; exit 2; }

# Reads magika JSONL on stdin. Staged in the workdir so a failure part-way cannot
# leave a truncated SARIF behind, which would upload as "nothing found".
write_sarif() {
    python3 "$MISMATCH_SCRIPT" > "$workdir/sarif" || die "Could not write SARIF."
    mv "$workdir/sarif" "$SARIF_OUT"
}

command -v magika  >/dev/null 2>&1 || die "magika is not installed; see .github/security-scan/README.md."
command -v python3 >/dev/null 2>&1 || die "python3 is not installed."

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
        # magika reports each path back in its JSONL, so a path containing a
        # newline would be indistinguishable from two entries. Git permits such
        # paths, so refuse rather than mis-scan.
        [[ "$path" == *$'\n'* ]] && die "Path contains a newline, which cannot be scanned safely: ${path@Q}"
        files+=("$path")
    else
        # ACMR excludes deletions and a rename reports only its destination, so
        # anything else here is unexpected rather than routine.
        log "Skipping ${path}: not a regular file."
    fi
done

# An empty run still has to be written: uploading it is what clears alerts an
# earlier commit raised, so skipping the write would leave them showing forever.
if (( ${#files[@]} == 0 )); then
    log "No files to scan."
    write_sarif < /dev/null
    exit 0
fi

log "Scanning ${#files[@]} changed file(s)."

# Status checked separately from the conversion below, whose status would be
# python's: a magika crash would otherwise yield no findings and pass. magika
# also exits non-zero when a listed file could not be read, reporting the reason
# in its JSONL rather than on stderr, so both streams go into the message.
magika --jsonl -- "${files[@]}" > "$workdir/detected" 2> "$workdir/magika.err" \
    || die "magika failed: $(cat "$workdir/magika.err"; head -c 300 "$workdir/detected")"
[[ -s "$workdir/magika.err" ]] && log "magika stderr: $(cat "$workdir/magika.err")"

write_sarif < "$workdir/detected"

for path in "${files[@]}"; do
    [[ "$path" =~ $AUTO_EXEC_PATTERN ]] \
        && warn "$path: runs automatically when the repo is opened or built - review as code"
done

log "Wrote $SARIF_OUT"
exit 0
