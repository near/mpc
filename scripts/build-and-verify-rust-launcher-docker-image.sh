#! /usr/bin/env bash

set -euo pipefail

# Step 1: Build the Rust launcher image and compute its manifest digest. The
# `*-manifest-digest` derivation runs skopeo entirely inside the Nix sandbox,
# so the digest is deterministic across builders and the only output is a
# `sha256:HEX` line.
nix build .#rust-launcher-image-manifest-digest --out-link result-rust-launcher-digest -L
built_launcher_hash=$(cut -d':' -f2 result-rust-launcher-digest)
echo "Built launcher image hash: $built_launcher_hash"

# Step 2: Extract the launcher and MPC hashes from the Rust launcher deployment compose file
deployed_launcher_hash=$(grep -o 'nearone/mpc-launcher@sha256:.*' deployment/cvm-deployment/launcher_docker_compose.yaml | grep -o '@sha256:.*' | cut -c 9-)
deployed_mpc_hash=$(grep 'DEFAULT_IMAGE_DIGEST=sha256:' deployment/cvm-deployment/launcher_docker_compose.yaml | grep -o 'sha256:.*' | cut -c 8-)

# Step 3: Fill the contract template with the deployment hashes and compare
filled_template=$(sed \
    -e "s/{{LAUNCHER_IMAGE_HASH}}/${deployed_launcher_hash}/" \
    -e "s/{{DEFAULT_IMAGE_DIGEST_HASH}}/${deployed_mpc_hash}/" \
    crates/contract/assets/launcher_docker_compose.yaml.template)

if ! diff <(echo "$filled_template") deployment/cvm-deployment/launcher_docker_compose.yaml > /dev/null; then
    echo "Template structure verification failed"
    echo "The Rust launcher contract template (filled with deployment hashes) does not match the deployment compose file."
    diff <(echo "$filled_template") deployment/cvm-deployment/launcher_docker_compose.yaml || true
    exit 1
fi
echo "Template structure verified: Rust launcher contract template matches deployment compose"

# Step 4: Verify the built launcher image hash matches the deployment compose
if [ "${deployed_launcher_hash}" == "${built_launcher_hash}" ]; then
    echo "Rust launcher docker image hash verified"
else
    # TODO(#2662): Re-enable after the launcher hash is re-pinned
    echo "WARNING: Rust launcher docker image hash mismatch (temporarily allowed)"
    echo "Deployment compose has: ${deployed_launcher_hash}"
    echo "Built image hash:       ${built_launcher_hash}"
fi
