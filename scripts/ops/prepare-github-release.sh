#!/usr/bin/env bash
#
# prepare-github-release.sh — Apply the local file changes for a release.
#
# Run this on a working branch off the release-source branch (e.g. off
# `main` for a minor release, off `release/vX.Y` for a patch). The script
# only touches files and commits — branch creation, push, and PR opening
# are the operator's responsibility.
#
# Steps:
#   1. Generate changelog section with git-cliff
#   2. Bump workspace version in Cargo.toml
#   3. Verify and update contract ABI snapshot
#   4. Regenerate third-party licenses
#   5. Commit the release changes
#
# Usage:  ./scripts/ops/prepare-github-release.sh <VERSION>
# Example: ./scripts/ops/prepare-github-release.sh 3.6.0
#

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=../common.sh
source "${REPO_ROOT}/scripts/common.sh"

# --- Argument parsing ---

[[ $# -eq 1 ]] || die "Usage: $0 <VERSION>  (e.g. 3.6.0)"
VERSION="$1"
check_version "$VERSION"

# --- Dependency checks ---

require_cmds git-cliff cargo-about cargo-insta

# git-cliff needs a GitHub token to avoid API rate limits when resolving PR links.
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        echo "==> GITHUB_TOKEN not set, obtaining from 'gh auth token'."
        GITHUB_TOKEN=$(gh auth token)
        export GITHUB_TOKEN
    else
        echo "WARNING: GITHUB_TOKEN is not set and 'gh' CLI is not authenticated."
        echo "         PR links in the changelog may be missing. Fix: export GITHUB_TOKEN=<token> or 'gh auth login'."
    fi
fi

echo "==> Preparing release v${VERSION}"

cd "$REPO_ROOT"

# --- Clean working tree check ---

if ! git diff --quiet || ! git diff --cached --quiet; then
    die "Working tree has uncommitted changes. Please commit or stash them first."
fi

# --- Generate changelog ---

# Use --prepend (preserves manual sections) and concrete SHA for metadata so
# branch-only PRs appear with correct links; append cherry-picks to .cliffignore.
echo "==> Generating changelog..."
BASE_TAG=$(git describe --tags --abbrev=0 --match '[0-9]*.[0-9]*.[0-9]*' HEAD) \
    || die "Could not find a previous semver tag reachable from HEAD."
git-cliff --prepend CHANGELOG.md -t "$VERSION" "${BASE_TAG}..$(git rev-parse HEAD)"

# --- Bump workspace version in Cargo.toml ---

# GNU sed/grep won't work on macOS — use POSIX forms.

CARGO_TOML="${REPO_ROOT}/Cargo.toml"
OLD_VERSION=$(awk -F'"' '/^version = "[0-9]+\.[0-9]+\.[0-9]+"/ {print $2; exit}' "$CARGO_TOML")
[[ -n "$OLD_VERSION" ]] || die "Could not find a workspace 'version = \"X.Y.Z\"' line in $CARGO_TOML."

echo "==> Bumping workspace version: ${OLD_VERSION} -> ${VERSION}"
sed -i.bak -E "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/version = \"${VERSION}\"/" "$CARGO_TOML" && rm "${CARGO_TOML}.bak"

# --- Verify contract ABI has changed ---

# Test fails if ABI was not affected by the version bump (the expected case).
echo "==> Verifying contract ABI changed after version bump..."
if cargo nextest run --cargo-profile=test-release -p mpc-contract abi_has_not_changed 2>/dev/null; then
    die "abi_has_not_changed test passed unexpectedly — ABI was not affected by version bump."
fi

# --- Update ABI snapshot ---

echo "==> Accepting updated ABI snapshot..."
cargo insta accept

# --- Update third-party licenses ---

echo "==> Regenerating third-party licenses..."
cd "${REPO_ROOT}/third-party-licenses"
cargo about generate --locked -m ../Cargo.toml about.hbs > licenses.html
cd "$REPO_ROOT"

# --- Commit release changes ---

git add -A
git commit -m "release: v${VERSION}"
echo "==> Done. Review the commit, push your branch, and open a PR against the release-source branch."
