#! /usr/bin/env bash

set -euo pipefail

./deployment/build-images.sh --launcher

# Step 1: Get the built launcher image's manifest hash
temp_dir=$(mktemp -d)
echo "using $temp_dir"
# This compresses the built image to a local directory, which implicitly computes the manifest
# digest in $temp_dir/manifest.json
skopeo copy --all --dest-compress docker-daemon:mpc-launcher:latest dir:$temp_dir
built_launcher_hash=$(sha256sum $temp_dir/manifest.json | cut -d' ' -f1)
echo "Built launcher image hash: $built_launcher_hash"

# Step 2: Extract the launcher and MPC hashes from the deployment compose file
deployed_launcher_hash=$(sed -n '5p' tee_launcher/launcher_docker_compose.yaml | grep -o '@sha256:.*' | cut -c 9-)
deployed_mpc_hash=$(grep 'DEFAULT_IMAGE_DIGEST=sha256:' tee_launcher/launcher_docker_compose.yaml | grep -o 'sha256:.*' | cut -c 8-)

# Step 3: Fill the contract template with the deployment compose hashes and compare
# This verifies both:
# - The template structure matches the deployment compose exactly
# - The built launcher hash matches what's in the deployment compose
filled_template=$(sed \
    -e "s/{{LAUNCHER_IMAGE_HASH}}/${deployed_launcher_hash}/" \
    -e "s/{{DEFAULT_IMAGE_DIGEST_HASH}}/${deployed_mpc_hash}/" \
    crates/contract/assets/launcher_docker_compose.yaml.template)

if ! diff <(echo "$filled_template") tee_launcher/launcher_docker_compose.yaml > /dev/null; then
    echo "Template structure verification failed"
    echo "The contract template (filled with deployment hashes) does not match the deployment compose file."
    diff <(echo "$filled_template") tee_launcher/launcher_docker_compose.yaml || true
    exit 1
fi
echo "Template structure verified: contract template matches deployment compose"

# Step 4: Verify the built launcher image hash matches the deployment compose
if [ "${deployed_launcher_hash}" == "${built_launcher_hash}" ]; then
    echo "Launcher docker image hash verified"
else
    echo "Launcher docker image hash verification failed"
    echo "Deployment compose has: ${deployed_launcher_hash}"
    echo "Built image hash:       ${built_launcher_hash}"
    exit 1
fi
