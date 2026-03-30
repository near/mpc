#! /usr/bin/env bash

set -euo pipefail

./deployment/build-images.sh --rust-launcher

# Step 1: Get the built Rust launcher image's manifest hash
temp_dir=$(mktemp -d)
echo "using $temp_dir"
skopeo copy --all --dest-compress docker-daemon:mpc-rust-launcher:latest dir:$temp_dir
built_launcher_hash=$(sha256sum $temp_dir/manifest.json | cut -d' ' -f1)
echo "Built launcher image hash: $built_launcher_hash"

# Step 2: Extract the launcher hash from the Rust launcher deployment compose file
deployed_launcher_hash=$(grep -o 'nearone/mpc-launcher@sha256:.*' deployment/cvm-deployment/launcher_docker_compose.yaml | grep -o '@sha256:.*' | cut -c 9-)

# Note: Template structure comparison is skipped for the Rust launcher.
# The contract template (launcher_docker_compose.yaml.template) currently matches
# the Python launcher compose (shared-volume:ro). The Rust launcher compose uses
# shared-volume:rw. The template will be updated when the Python launcher is removed.

# Step 3: Verify the built launcher image hash matches the deployment compose
if [ "${deployed_launcher_hash}" == "${built_launcher_hash}" ]; then
    echo "Rust launcher docker image hash verified"
else
    echo "Rust launcher docker image hash verification failed"
    echo "Deployment compose has: ${deployed_launcher_hash}"
    echo "Built image hash:       ${built_launcher_hash}"
    exit 1
fi
