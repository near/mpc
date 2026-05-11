#! /usr/bin/env bash

# Builds the Rust launcher Docker image reproducibly and prints its manifest
# digest. CI uses this to surface the digest so reviewers can compare it
# against `allowed_launcher_image_hashes` on the contract.
#
# This script used to also diff the deployment compose file against the
# contract template; that diff is now vacuous (the deployment compose is
# rendered from the contract template at deploy time — see
# `deployment/cvm-deployment/deploy-launcher.sh`).

set -euo pipefail

./deployment/build-images.sh --rust-launcher

temp_dir=$(mktemp -d)
echo "using $temp_dir"
skopeo copy --all --dest-compress docker-daemon:mpc-rust-launcher:latest dir:$temp_dir
built_launcher_hash=$(sha256sum $temp_dir/manifest.json | cut -d' ' -f1)
echo "Built launcher image hash: sha256:$built_launcher_hash"
