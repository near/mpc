#!/usr/bin/env bash
#
# Tests for scan-changed-files.sh, run against throwaway git repos.
#
#   .github/scripts/tests/test-scan-changed-files.sh [rules-dir]
#
# Needs yara, yarac and magika on PATH, plus a GuardDog rule pack. Without a
# rules-dir argument it fetches one. Exit 0 when every case passes.

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCAN="$SCRIPT_DIR/../scan-changed-files.sh"

# One line of JavaScript behind a long run of spaces, saved as a font. Mirrors the
# shape the scan exists to catch: content that is code, a name that claims an
# asset, and a payload pushed off-screen in a diff. `global['r']=require` and
# eval( are what the GuardDog obfuscation rules key on.
make_payload() {
    { printf '%*s' 1700 ''
      printf "%s" "global['r']=require;const h=require('http');"
      printf "%s\n" "function go(x){eval(x)};go('1');"
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
        printf 'FAIL %s (expected exit %s, got %s)\n' "$name" "$expected" "$actual"
        failed=$((failed + 1))
    fi
}

# A repo with one commit on main, then `$1` extra commits on a branch.
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

scan_in() {
    local dir="$1" base="$2" head="$3"
    ( cd "$dir" && RULES_DIR="$RULES_DIR" BASE_SHA="$base" HEAD_SHA="$head" "$SCAN" >/dev/null 2>&1 )
}

RULES_DIR="${1:-}"
if [[ -z "$RULES_DIR" ]]; then
    RULES_DIR="$(mktemp -d)"
    "$SCRIPT_DIR/../fetch-yara-rules.sh" "$RULES_DIR" >/dev/null 2>&1
fi
export RULES_DIR

# --- the payload is blocked, under an ASCII name and a homoglyph one ----------
# The Cyrillic 'a' matters: git quotes such paths unless the diff is read -z, and
# a quoted path silently drops out of the file list.
for name in 'fa-solid-400.woff2' "$(printf 'f\xd0\xb0-solid-400.woff2')"; do
    repo="$(new_repo)"
    mkdir -p "$repo/public/fonts"
    make_payload "$repo/public/fonts/$name"
    git -C "$repo" add -A
    git -C "$repo" commit -qm payload
    rc=0; scan_in "$repo" "$(git -C "$repo" rev-parse HEAD~1)" "$(git -C "$repo" rev-parse HEAD)" || rc=$?
    check "payload blocked: $name" 1 "$rc"
    rm -rf "$repo"
done

# --- a genuine font is left alone --------------------------------------------
repo="$(new_repo)"
mkdir -p "$repo/public/fonts"
printf 'wOF2\x00\x01\x00\x00' > "$repo/public/fonts/real.woff2"
head -c 4000 /dev/urandom >> "$repo/public/fonts/real.woff2"
git -C "$repo" add -A
git -C "$repo" commit -qm font
rc=0; scan_in "$repo" "$(git -C "$repo" rev-parse HEAD~1)" "$(git -C "$repo" rev-parse HEAD)" || rc=$?
check "genuine woff2 passes" 0 "$rc"
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
rc=0; scan_in "$repo" "$(git -C "$repo" rev-parse HEAD~2)" "$(git -C "$repo" rev-parse HEAD)" || rc=$?
check "payload in a non-tip commit blocked" 1 "$rc"
# ... and confirm the narrow range really would have missed it, so the case bites
rc=0; scan_in "$repo" "$(git -C "$repo" rev-parse HEAD~1)" "$(git -C "$repo" rev-parse HEAD)" || rc=$?
check "tip-only range misses it (why the fallback matters)" 0 "$rc"
rm -rf "$repo"

# --- refusing to scan nothing ------------------------------------------------
repo="$(new_repo)"
head="$(git -C "$repo" rev-parse HEAD)"
missing=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef

rc=0; scan_in "$repo" "$head" "$missing" || rc=$?
check "absent head sha exits 2" 2 "$rc"

rc=0; scan_in "$repo" "$missing" "$head" || rc=$?
check "absent base sha exits 2" 2 "$rc"

rc=0; ( cd "$repo" && RULES_DIR="$RULES_DIR" BASE_SHA="$head" "$SCAN" >/dev/null 2>&1 ) || rc=$?
check "missing HEAD_SHA exits 2" 2 "$rc"

rc=0; ( cd "$repo" && env -u RULES_DIR BASE_SHA="$head" HEAD_SHA="$head" "$SCAN" >/dev/null 2>&1 ) || rc=$?
check "missing RULES_DIR exits 2" 2 "$rc"

rc=0; scan_in "$repo" "$head" "$head" || rc=$?
check "empty diff exits 0" 0 "$rc"
rm -rf "$repo"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 ))
