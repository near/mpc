#! /usr/bin/env bash
#
# Builds the Rust launcher reproducibly and prints its manifest digest.
# No assertion — the previous strict check was removed in #3199; see
# https://github.com/near/mpc/issues/2662 for context and the
# preconditions for restoring it.

set -euo pipefail

./deployment/build-images.sh --rust-launcher

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
echo "using $temp_dir"
skopeo copy --all --dest-compress docker-daemon:mpc-rust-launcher:latest dir:"$temp_dir"
built_hex="$(sha256sum "$temp_dir/manifest.json" | cut -d' ' -f1)"
echo "Built launcher image hash: sha256:${built_hex}"
