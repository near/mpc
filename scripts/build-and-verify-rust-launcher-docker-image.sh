#! /usr/bin/env bash
#
# Builds the Rust launcher Docker image reproducibly and prints its manifest
# digest. CI uses this to (a) confirm the launcher still builds reproducibly
# from the current workspace, and (b) surface the digest in the run log so
# reviewers and operators can compare it against the contract's
# allowed_launcher_image_hashes when needed.
#
# This script intentionally does NOT enforce that the built digest matches
# any pinned reference. The previous strict equality check (against the
# hard-coded digest in `launcher_docker_compose.yaml`) was demoted to a
# warning in #2619 and removed in #3199, because `repro-env` builds the
# launcher against the full workspace `Cargo.lock` — so any unrelated
# workspace lockfile change shifts the launcher digest. Enforcing on every
# PR would mean a digest-bump alongside every dependency change. Tracked in:
#   https://github.com/near/mpc/issues/2662
#
# Once #2662 is resolved (e.g. tee-launcher in its own workspace/lockfile),
# this script should be restored to an assertion — either against a
# checked-in allow list or against the contract's allowed_launcher_image_hashes.

set -euo pipefail

./deployment/build-images.sh --rust-launcher

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
echo "using $temp_dir"
skopeo copy --all --dest-compress docker-daemon:mpc-rust-launcher:latest dir:"$temp_dir"
built_hex="$(sha256sum "$temp_dir/manifest.json" | cut -d' ' -f1)"
echo "Built launcher image hash: sha256:${built_hex}"
