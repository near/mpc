#!/usr/bin/env bash
#
# release-automation.sh — Automates local steps of the MPC release process.
#
# This script prepares a release branch for a given version. It:
#   1. Validates the version argument is valid semver (MAJOR.MINOR.PATCH).
#   2. Ensures the git working tree is clean (no uncommitted changes).
#   3. Creates a release branch "release/v<VERSION>" or switches to it if
#      it already exists.
#   4. Pushes the branch to origin with upstream tracking.
#
# Usage:
#   ./release-automation.sh <VERSION>
#
# Example:
#   ./release-automation.sh 3.6.0
#

# Exit immediately on error (-e), treat unset variables as errors (-u),
# and fail a pipeline if any command in it fails (-o pipefail).
set -euo pipefail

# Resolve the repo root directory (one level up from scripts/).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --- Argument parsing ---

usage() {
    echo "Usage: $0 <VERSION>"
    echo ""
    echo "  VERSION  Semver version string, e.g. 3.6.0"
    echo ""
    echo "Example:"
    echo "  $0 3.6.0"
    exit 1
}

# Require exactly one argument.
if [[ $# -ne 1 ]]; then
    echo "Error: Expected exactly one argument, got $#."
    usage
fi

VERSION="$1"

# --- Version validation ---

# Enforce strict semver format: one or more digits, dot, repeat, no prefix.
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: '$VERSION' is not a valid semver version."
    echo "       Expected format: MAJOR.MINOR.PATCH (e.g. 3.6.0)"
    exit 1
fi

echo "==> Preparing release for version ${VERSION}"

BRANCH="release/v${VERSION}"

# --- Change to repo root ---

echo "==> Repository root: ${REPO_ROOT}"
cd "$REPO_ROOT"

# --- Clean working tree check ---

# git diff --quiet exits non-zero if there are unstaged changes.
# git diff --cached --quiet exits non-zero if there are staged changes.
# We require both to be clean so the branch switch doesn't carry over
# unrelated modifications.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: Working tree has uncommitted changes."
    echo "       Please commit or stash them before running this script."
    exit 1
fi

echo "==> Working tree is clean."

# --- Branch creation or checkout ---

if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
    # Branch already exists locally — just switch to it.
    echo "==> Branch '${BRANCH}' already exists locally, switching to it."
    git checkout "$BRANCH"
else
    # Branch does not exist — create it from current HEAD.
    echo "==> Creating new branch '${BRANCH}' from current HEAD ($(git rev-parse --short HEAD))."
    git checkout -b "$BRANCH"
fi

echo "==> Now on branch '${BRANCH}'."

# --- Push to origin ---

# Push with -u to set upstream tracking, so future git pull/push on this
# branch work without specifying the remote.
echo "==> Pushing '${BRANCH}' to origin..."
git push -u origin "$BRANCH"

echo "==> Done. Branch '${BRANCH}' is pushed and tracking origin/${BRANCH}."
