#! /usr/bin/env bash
#
# Builds the Rust launcher Docker image reproducibly and asserts that its
# manifest digest is one of the digests declared as allowed in
#   crates/contract/assets/allowed-launcher-hashes.json
#
# When voting a new launcher digest into the contract's
# `allowed_launcher_image_hashes`, add the same digest to that JSON file in
# the same PR. That makes this check the human-reviewed gate for "the
# launcher binary I built matches the launcher digest we intend to allow."
#
# The structural diff between the deployment compose and the contract
# template used to live here; it no longer applies — the deployment compose
# is now rendered from the template at deploy time (see
# `deployment/cvm-deployment/deploy-launcher.sh` and
# `scripts/render-launcher-compose.sh`).
#
# Known caveat: the launcher binary is built against the full workspace
# Cargo.lock, so unrelated workspace dependency changes shift the launcher
# digest. Tracked in #2662. Until #2662 is resolved, every PR that touches
# Cargo.lock will require an `allowed-launcher-hashes.json` bump (or this
# check will fail). That cost is intentional — the alternative is no gate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ALLOWED_HASHES_JSON="$REPO_ROOT/crates/contract/assets/allowed-launcher-hashes.json"

./deployment/build-images.sh --rust-launcher

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
echo "using $temp_dir"
skopeo copy --all --dest-compress docker-daemon:mpc-rust-launcher:latest dir:"$temp_dir"
built_hex="$(sha256sum "$temp_dir/manifest.json" | cut -d' ' -f1)"
built_digest="sha256:${built_hex}"
echo "Built launcher image hash: $built_digest"

command -v jq >/dev/null 2>&1 || {
  echo "Error: 'jq' is required to read $ALLOWED_HASHES_JSON" >&2
  exit 3
}

if jq -e --arg d "$built_digest" \
     '.allowed_launcher_image_digests | index($d)' \
     "$ALLOWED_HASHES_JSON" >/dev/null; then
  echo "✅ Built launcher digest is in $ALLOWED_HASHES_JSON"
  exit 0
fi

echo "❌ Built launcher digest is NOT in $ALLOWED_HASHES_JSON"
echo
echo "Built digest:"
echo "  $built_digest"
echo
echo "Currently allowed digests:"
jq -r '.allowed_launcher_image_digests[] | "  " + .' "$ALLOWED_HASHES_JSON"
echo
echo "If the new digest is intentional, add it to:"
echo "  $ALLOWED_HASHES_JSON"
echo "and vote it into the contract's allowed_launcher_image_hashes in the same PR."
exit 1
