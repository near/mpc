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
#   5. Generates the changelog using git-cliff.
#   6. Bumps the workspace version in the root Cargo.toml.
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

# --- Dependency checks ---

# Verify that git-cliff is available (provided by nix develop shell).
if ! command -v git-cliff &>/dev/null; then
    echo "Error: 'git-cliff' not found on PATH."
    echo "       Run this script from within 'nix develop' or install git-cliff manually."
    exit 1
fi

# git-cliff needs an authenticated GitHub token to resolve PR links without
# hitting the API rate limit (60 req/hour unauthenticated vs 5,000 authenticated).
# If GITHUB_TOKEN is not already set, try to get it from the gh CLI.
# If neither is available, warn and continue — git-cliff will still work but
# may produce warnings or incomplete PR links.
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        echo "==> GITHUB_TOKEN not set, obtaining from 'gh auth token'."
        export GITHUB_TOKEN=$(gh auth token)
    else
        echo "WARNING: GITHUB_TOKEN is not set and 'gh' CLI is not authenticated."
        echo "         git-cliff will run without GitHub authentication."
        echo "         You may see rate-limit errors or warnings, and PR links may be missing."
        echo "         To fix: export GITHUB_TOKEN=<token> or run 'gh auth login'."
    fi
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

# --- Generate changelog ---

# git-cliff generates a changelog from conventional commits up to the given tag.
# The tag doesn't need to exist yet — git-cliff uses it as a label for unreleased commits.
# Note: the branch must be pushed to origin first, otherwise git-cliff cannot
# resolve PR links in the generated notes.
echo "==> Generating changelog for version ${VERSION}..."
git-cliff -t "$VERSION" > CHANGELOG.md

echo "==> Changelog written to CHANGELOG.md."

# --- Bump workspace version in Cargo.toml ---

# All crates inherit their version from [workspace.package] in the root Cargo.toml,
# so this single substitution bumps every crate in the workspace.
CARGO_TOML="${REPO_ROOT}/Cargo.toml"
OLD_VERSION=$(grep -Po '(?<=^version = ")[0-9]+\.[0-9]+\.[0-9]+(?=")' "$CARGO_TOML")

echo "==> Bumping workspace version: ${OLD_VERSION} -> ${VERSION} in Cargo.toml"
sed -i "0,/^version = \"${OLD_VERSION}\"/s//version = \"${VERSION}\"/" "$CARGO_TOML"

echo "==> Cargo.toml version updated."

# --- Verify contract ABI has changed ---

# The version bump should cause the contract ABI to differ from the checked-in
# snapshot. We run the ABI comparison test and expect it to fail — if it passes,
# something is wrong (the ABI was not affected by the version change).
echo "==> Verifying contract ABI has changed after version bump..."
if cargo nextest run -p mpc-contract abi_has_not_changed 2>/dev/null; then
    echo "Error: abi_has_not_changed test passed, but it should have failed after a version bump."
    exit 1
fi
echo "==> ABI change confirmed (test failed as expected)."

# --- Update ABI snapshot ---

echo "==> Accepting updated ABI snapshot..."
cargo insta accept

# --- Update third-party licenses ---

echo "==> Regenerating third-party licenses..."
cd "${REPO_ROOT}/third-party-licenses"
cargo about generate --locked -m ../Cargo.toml about.hbs > licenses.html
cd "$REPO_ROOT"
echo "==> Third-party licenses updated."

# --- Commit and push release changes ---

echo "==> Committing release changes..."
git add -A
git commit -m "Release v${VERSION}"
git push

echo "==> Release v${VERSION} committed and pushed."
