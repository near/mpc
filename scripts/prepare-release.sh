#!/usr/bin/env bash
#
# prepare-release.sh — Apply the local file changes for a release.
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
# Usage:  ./scripts/prepare-release.sh <VERSION>
# Example: ./scripts/prepare-release.sh 3.6.0
#

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

# --- Argument parsing ---

usage() {
    echo "Usage: $0 <VERSION>  (e.g. 3.6.0)"
    exit 1
}

if [[ $# -ne 1 ]]; then
    echo "Error: Expected exactly one argument, got $#."
    usage
fi

VERSION="$1"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: '$VERSION' is not valid semver (expected MAJOR.MINOR.PATCH)."
    exit 1
fi

# --- Helper functions ---

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

require_cmds() {
    local missing=0
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'Missing dependency: %s\n' "$cmd" >&2
            missing=1
        }
    done
    [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above (hint: run from within 'nix develop')."
}

# --- Dependency checks ---

require_cmds git-cliff cargo-about cargo-insta

# git-cliff needs a GitHub token to avoid API rate limits when resolving PR links.
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        echo "==> GITHUB_TOKEN not set, obtaining from 'gh auth token'."
        export GITHUB_TOKEN=$(gh auth token)
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

# Use --prepend --unreleased so the new release section is added on top of
# CHANGELOG.md, preserving any manually authored sections (e.g. for releases
# whose tag does not live on main, like 3.9.1 on release/v3.9.1). When new
# sections need to be hand-written, append the relevant duplicate cherry-pick
# commits to .cliffignore so they don't reappear in the next auto-generated
# release block.
echo "==> Generating changelog..."
git-cliff --prepend CHANGELOG.md --unreleased -t "$VERSION"

# --- Bump workspace version in Cargo.toml ---

# `grep -P` (PCRE) and `sed -i` without a suffix are GNU-only; use POSIX
# forms so this works on both Linux and macOS (BSD userland).

CARGO_TOML="${REPO_ROOT}/Cargo.toml"
OLD_VERSION=$(awk -F'"' '/^version = "[0-9]+\.[0-9]+\.[0-9]+"/ {print $2; exit}' "$CARGO_TOML")
[[ -n "$OLD_VERSION" ]] || die "Could not find a workspace 'version = \"X.Y.Z\"' line in $CARGO_TOML."

echo "==> Bumping workspace version: ${OLD_VERSION} -> ${VERSION}"
sed -i.bak -E "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/version = \"${VERSION}\"/" "$CARGO_TOML" && rm "${CARGO_TOML}.bak"

# --- Verify contract ABI has changed ---

# The version bump should cause the ABI snapshot to differ. We expect
# the test to fail — if it passes, the ABI was not affected.
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
