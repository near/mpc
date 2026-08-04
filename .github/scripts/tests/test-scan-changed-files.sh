#!/usr/bin/env bash
#
# Tests for scan-changed-files.sh, run against throwaway git repos.
#
#   .github/scripts/tests/test-scan-changed-files.sh
#
# Needs magika, python3, jq and git on PATH. Exit 0 when every case passes.
#
# Locally: nix develop --command .github/scripts/tests/test-scan-changed-files.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SCAN="$SCRIPT_DIR/../scan-changed-files.sh"

# JavaScript behind a long run of spaces, saved as a font: content that is code, a
# name claiming an inert asset, and a payload pushed off-screen in a diff. magika
# still types this as javascript, which is what the check keys on.
make_payload() {
    { printf '%*s' 1700 ''
      printf "globalThis['r']=require;\n"
      printf "function go(x){return x*2};\nmodule.exports={go};\n"
    } > "$1"
}

passed=0
failed=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        printf 'ok   %s\n' "$name"
        passed=$((passed + 1))
    else
        printf 'FAIL %s (expected %s, got %s)\n' "$name" "$expected" "$actual"
        failed=$((failed + 1))
    fi
}

# A repo with one commit on main.
new_repo() {
    local dir; dir="$(mktemp -d)"
    git -C "$dir" init -q -b main
    git -C "$dir" config user.email t@example.com
    git -C "$dir" config user.name Test
    echo seed > "$dir/README.md"
    git -C "$dir" add -A
    git -C "$dir" commit -qm seed
    printf '%s' "$dir"
}

# Runs the scan with SARIF written outside the repo under test, so the report
# cannot show up in a later diff. Sets SARIF for findings() to read.
SARIF=""
scan_in() {
    local dir="$1" base="$2" head="$3"
    SARIF="$(mktemp)"
    ( cd "$dir" && BASE_SHA="$base" HEAD_SHA="$head" SARIF_OUT="$SARIF" "$SCAN" >/dev/null 2>&1 )
}

findings() {
    jq '[.runs[].results[]] | length' "$SARIF"
}

rev() { git -C "$1" rev-parse "$2"; }

# --- the payload is reported, under an ASCII name and a homoglyph one ----------
# The Cyrillic 'a' matters: git quotes such paths unless the diff is read -z, and
# a quoted path silently drops out of the file list.
for name in 'fa-solid-400.woff2' "$(printf 'f\xd0\xb0-solid-400.woff2')"; do
    repo="$(new_repo)"
    mkdir -p "$repo/public/fonts"
    make_payload "$repo/public/fonts/$name"
    git -C "$repo" add -A
    git -C "$repo" commit -qm payload
    rc=0; scan_in "$repo" "$(rev "$repo" HEAD~1)" "$(rev "$repo" HEAD)" || rc=$?
    check "scan succeeds: $name" 0 "$rc"
    check "payload reported: $name" 1 "$(findings)"
    rm -rf "$repo"
done

# --- a genuine font is left alone --------------------------------------------
repo="$(new_repo)"
mkdir -p "$repo/public/fonts"
printf 'wOF2\x00\x01\x00\x00' > "$repo/public/fonts/real.woff2"
head -c 4000 /dev/urandom >> "$repo/public/fonts/real.woff2"
git -C "$repo" add -A
git -C "$repo" commit -qm font
rc=0; scan_in "$repo" "$(rev "$repo" HEAD~1)" "$(rev "$repo" HEAD)" || rc=$?
check "genuine woff2 exits 0" 0 "$rc"
check "genuine woff2 reports nothing" 0 "$(findings)"
rm -rf "$repo"

# --- a payload in an earlier commit of a multi-commit range is still found ----
# Regression for the base-commit fallback: scanning only the tip missed this.
repo="$(new_repo)"
mkdir -p "$repo/public/fonts"
make_payload "$repo/public/fonts/fa-solid-400.woff2"
git -C "$repo" add -A
git -C "$repo" commit -qm payload
echo later > "$repo/later.txt"
git -C "$repo" add -A
git -C "$repo" commit -qm later
scan_in "$repo" "$(rev "$repo" HEAD~2)" "$(rev "$repo" HEAD)"
check "payload in a non-tip commit reported" 1 "$(findings)"
# ... and confirm the narrow range really would have missed it, so the case bites
scan_in "$repo" "$(rev "$repo" HEAD~1)" "$(rev "$repo" HEAD)"
check "tip-only range misses it (why the fallback matters)" 0 "$(findings)"
rm -rf "$repo"

# --- refusing to scan nothing ------------------------------------------------
repo="$(new_repo)"
head="$(rev "$repo" HEAD)"
missing=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef

rc=0; scan_in "$repo" "$head" "$missing" || rc=$?
check "absent head sha exits 2" 2 "$rc"

rc=0; scan_in "$repo" "$missing" "$head" || rc=$?
check "absent base sha exits 2" 2 "$rc"

sarif_out="$(mktemp)"
rc=0; ( cd "$repo" && BASE_SHA="$head" SARIF_OUT="$sarif_out" "$SCAN" >/dev/null 2>&1 ) || rc=$?
check "missing HEAD_SHA exits 2" 2 "$rc"

# An empty diff must still write a run: uploading it is what clears alerts an
# earlier commit raised.
rc=0; scan_in "$repo" "$head" "$head" || rc=$?
check "empty diff exits 0" 0 "$rc"
check "empty diff still writes an empty run" 0 "$(findings)"
rm -rf "$repo"

# --- a file the scanner cannot read must not pass -----------------------------
repo="$(new_repo)"
echo secret > "$repo/unreadable.txt"
git -C "$repo" add -A
git -C "$repo" commit -qm unreadable
chmod 000 "$repo/unreadable.txt"
rc=0; scan_in "$repo" "$(rev "$repo" HEAD~1)" "$(rev "$repo" HEAD)" || rc=$?
chmod 644 "$repo/unreadable.txt"
check "unreadable file exits 2" 2 "$rc"
rm -rf "$repo"

# --- a path containing a newline must be refused, not silently mis-listed -----
repo="$(new_repo)"
printf 'x\n' > "$repo/$(printf 'we\nird.txt')" 2>/dev/null || true
if git -C "$repo" add -A 2>/dev/null && git -C "$repo" commit -qm newline 2>/dev/null; then
    rc=0; scan_in "$repo" "$(rev "$repo" HEAD~1)" "$(rev "$repo" HEAD)" || rc=$?
    check "newline in path exits 2" 2 "$rc"
else
    printf 'skip newline case (filesystem rejected the name)\n'
fi
rm -rf "$repo"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 ))
