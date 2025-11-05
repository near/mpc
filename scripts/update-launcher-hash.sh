#!/usr/bin/env bash
set -euo pipefail

# The old hash to replace
old_hash="40d78e393b51ec42a9a4964fb9cef72f499503430b626c1a8e874d4a5b3f55c9"

# Confirm inside a git repo
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "❌ Error: not inside a Git repository." >&2
    exit 1
fi

# Check for a clean working directory
if ! git diff --ignore-submodules=all --quiet || ! git diff --cached --quiet; then
    echo "❌ Error: you have unstaged or uncommitted changes."
    echo "   Please commit or stash them before running this script."
    exit 1
fi

# Ask for the new hash
read -rp "Enter new hash value: " new_hash

echo "This will replace all occurrences of:"
echo "  $old_hash"
echo "with:"
echo "  $new_hash"
read -rp "Proceed? (y/N): " confirm
[[ "${confirm,,}" == "y" ]] || exit 0

# Find all tracked text files (skip binaries)
git grep -rl ${old_hash} ../ | xargs sed -i "s|${old_hash}|${new_hash}|g"

# Show which files changed
echo "✅ Replacement done. Changed files:"
git diff --compact-summary

echo "Don't forget to commit"
