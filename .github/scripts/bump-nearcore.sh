#!/usr/bin/env bash
set -euo pipefail

# Bumps nearcore to the latest (or specified) release tag and opens a PR.
#
# Required env vars: GH_TOKEN, GITHUB_REPOSITORY
# Optional env vars: NEARCORE_TAG (target nearcore tag; defaults to latest release)

# Extract the tag value from the first nearcore git dependency in Cargo.toml
# e.g. nearcore = { git = "...", tag = "2.11.0" } -> 2.11.0
CURRENT_TAG=$(grep -m1 'near/nearcore.*tag' Cargo.toml | sed 's/.*tag = "\([^"]*\)".*/\1/')
if [[ -z "$CURRENT_TAG" ]]; then
  echo "ERROR: could not parse current nearcore tag from Cargo.toml"
  exit 1
fi
NEW_TAG=${NEARCORE_TAG:-$(gh release view --repo near/nearcore --json tagName -q '.tagName')}

echo "Current: $CURRENT_TAG"
echo "Target:  $NEW_TAG"

if [[ "$CURRENT_TAG" == "$NEW_TAG" ]]; then
  echo "Already at $NEW_TAG, nothing to do."
  exit 0
fi

BRANCH="chore/bump-nearcore-$NEW_TAG"
if gh pr list --repo "$GITHUB_REPOSITORY" --head "$BRANCH" --limit 1 --json number -q '.[].number' | grep -q .; then
  echo "PR already exists for $NEW_TAG"
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"

git push origin --delete "$BRANCH" 2>/dev/null || true

sed -i "s|tag = \"$CURRENT_TAG\"|tag = \"$NEW_TAG\"|g" Cargo.toml
sed -i "/DEFAULT_SANDBOX_VERSION/s|\"$CURRENT_TAG\"|\"$NEW_TAG\"|g" crates/e2e-tests/src/cluster.rs
(cd libs/nearcore && git fetch origin --tags && git checkout "$NEW_TAG")
cargo update nearcore

git checkout -b "$BRANCH"
git add Cargo.toml Cargo.lock libs/nearcore crates/e2e-tests/src/cluster.rs
git commit -m "chore: bump to nearcore $NEW_TAG"
git push origin "$BRANCH"

gh pr create \
  --repo "$GITHUB_REPOSITORY" \
  --title "chore: bump to nearcore $NEW_TAG" \
  --body "Automated bump from $CURRENT_TAG to $NEW_TAG." \
  --base main
