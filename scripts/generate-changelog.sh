#!/usr/bin/env bash
#
# generate-changelog.sh — Generate a filtered CHANGELOG.md using git-cliff.
#
# Skips commits listed in .changelog-skip-commits (e.g. history imported
# from merged external repos like threshold-signatures).
#
# Usage:  ./scripts/generate-changelog.sh <VERSION>
# Example: ./scripts/generate-changelog.sh 3.6.0
#

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

# --- Argument parsing ---

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <VERSION>  (e.g. 3.6.0)" >&2
    exit 1
fi

VERSION="$1"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: '$VERSION' is not valid semver (expected MAJOR.MINOR.PATCH)." >&2
    exit 1
fi

# --- Dependency check ---

if ! command -v git-cliff >/dev/null 2>&1; then
    echo "Error: git-cliff not found. Install it or run from within 'nix develop'." >&2
    exit 1
fi

# git-cliff needs a GitHub token to avoid API rate limits when resolving PR links.
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        echo "==> GITHUB_TOKEN not set, obtaining from 'gh auth token'."
        export GITHUB_TOKEN=$(gh auth token)
    else
        echo "WARNING: GITHUB_TOKEN is not set and 'gh' CLI is not authenticated." >&2
        echo "         PR links in the changelog may be missing. Fix: export GITHUB_TOKEN=<token> or 'gh auth login'." >&2
    fi
fi

# --- Build skip list from merged external repos ---

SKIP_COMMITS_FILE="${REPO_ROOT}/.changelog-skip-commits"
SKIP_ARGS=()
if [[ -f "$SKIP_COMMITS_FILE" ]]; then
    while IFS= read -r sha; do
        [[ -z "$sha" || "$sha" == \#* ]] && continue
        SKIP_ARGS+=(--skip-commit "$sha")
    done < "$SKIP_COMMITS_FILE"
    echo "==> Generating changelog (skipping $(( ${#SKIP_ARGS[@]} / 2 )) external commits)..."
else
    echo "==> Generating changelog..."
fi

# --- Generate ---

git-cliff -t "$VERSION" "${SKIP_ARGS[@]}" > "${REPO_ROOT}/CHANGELOG.md"
echo "==> Wrote CHANGELOG.md"
