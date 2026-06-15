#! /usr/bin/env bash
# Script to reproducibly build the docker images for the node and launcher.
#
# The heavy lifting happens in Nix: each image is a `dockerTools` derivation
# (see nix/*-image.nix) and each has a companion `*-manifest-digest`
# derivation that computes the registry manifest digest deterministically
# inside the Nix sandbox. This script is a thin wrapper that builds the
# requested derivations, prints the binary hashes and manifest digests, and
# optionally pushes the images.
#
# Requirements: nix (with flakes enabled), git — nothing else; skopeo is
# run through `nix run .#skopeo`.
# Extra requirements if using --push: logged in to the registry, e.g.
#   nix run .#skopeo -- login docker.io
#
# Usage:
#   ./deployment/build-images.sh [--node] [--node-gcp] [--rust-launcher] [--push]
# If no image flags are used, all images are built
# Manifest digests are always computed and printed

set -euo pipefail

USE_RUST_LAUNCHER=false
USE_NODE=false
USE_NODE_GCP=false
USE_PUSH=false

for arg in "$@"
do
  case "$arg" in
    --node)
      USE_NODE=true
      ;;
    --node-gcp)
      USE_NODE_GCP=true
      ;;
    --rust-launcher)
      USE_RUST_LAUNCHER=true
      ;;
    --push)
      USE_PUSH=true
      ;;
    *)
      echo "Unknown parameter: $arg"
      echo "Usage: $0 [--node] [--node-gcp] [--rust-launcher] [--push]"
      exit 1
      ;;
  esac
done

if ! $USE_RUST_LAUNCHER && ! $USE_NODE && ! $USE_NODE_GCP; then
    USE_RUST_LAUNCHER=true
    USE_NODE=true
    USE_NODE_GCP=true
fi

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmds() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'Missing dependency: %s\n' "$cmd" >&2; missing=1; }
  done
  [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above."
}

require_cmds nix git

if [ ! "$(pwd)" = "$(git rev-parse --show-toplevel)" ]; then
    die "Must be called from project root!"
fi

: "${NODE_IMAGE_NAME:=mpc-node}"
: "${NODE_GCP_IMAGE_NAME:=mpc-node-gcp}"
: "${RUST_LAUNCHER_IMAGE_NAME:=mpc-rust-launcher}"

GIT_COMMIT_HASH=$(git rev-parse HEAD)

# Build a flake attribute and print its store output path. Build logs go to
# stderr; only the path lands on stdout.
nix_out() {
    nix build --no-link --print-out-paths ".#$1"
}

# The flake-pinned skopeo — the same one image-dir.nix used to produce the
# layouts being pushed, and no system install needed.
skopeo() {
    nix run .#skopeo -- "$@"
}

if $USE_NODE || $USE_NODE_GCP; then
    node_binary_hash=$(sha256sum "$(nix_out mpc-node)/bin/mpc-node" | cut -d' ' -f1)
fi

if $USE_NODE; then
    node_image_dir=$(nix_out node-image-dir)
    node_manifest_digest=$(cat "$(nix_out node-image-manifest-digest)")
fi

if $USE_NODE_GCP; then
    node_gcp_image_dir=$(nix_out node-gcp-image-dir)
    node_gcp_manifest_digest=$(cat "$(nix_out node-gcp-image-manifest-digest)")
fi

if $USE_RUST_LAUNCHER; then
    rust_launcher_binary_hash=$(sha256sum "$(nix_out tee-launcher)/bin/tee-launcher" | cut -d' ' -f1)
    rust_launcher_image_dir=$(nix_out rust-launcher-image-dir)
    rust_launcher_manifest_digest=$(cat "$(nix_out rust-launcher-image-manifest-digest)")
fi

if $USE_PUSH; then
    # This assumes that skopeo is logged-in to the dockerhub registry with the nearone user

    branch_name=$(git branch --show-current)
    if [ -z "$branch_name" ]; then
        branch_name="detached"
    fi
    sanitized_branch_name="${branch_name//\//-}"

    # Fixed 7-char truncation (not `git rev-parse --short`) so the tag is a
    # pure function of the SHA — the Release workflow computes the same
    # string via `${SHA::7}` when looking up the image to retag.
    short_hash="${GIT_COMMIT_HASH:0:7}"
    image_tag="$sanitized_branch_name-$short_hash"
    echo "Using branch-hash tag: $image_tag"

    # Push the Nix-built `dir:` layouts. Their blobs are already compressed
    # and their manifest is exactly what the `*-manifest-digest` derivations
    # hashed, so with `--preserve-digests` the digest that lands in the
    # registry is guaranteed to be the one printed below — independent of
    # the skopeo version doing the pushing.
    if $USE_NODE; then
        skopeo copy --preserve-digests "dir:$node_image_dir" "docker://docker.io/nearone/$NODE_IMAGE_NAME:$image_tag"
    fi

    if $USE_NODE_GCP; then
        skopeo copy --preserve-digests "dir:$node_gcp_image_dir" "docker://docker.io/nearone/$NODE_GCP_IMAGE_NAME:$image_tag"
    fi

    if $USE_RUST_LAUNCHER; then
        skopeo copy --preserve-digests "dir:$rust_launcher_image_dir" "docker://docker.io/nearone/$RUST_LAUNCHER_IMAGE_NAME:$image_tag"
    fi
fi

echo "commit hash: $GIT_COMMIT_HASH"
if $USE_NODE || $USE_NODE_GCP; then
    echo "node binary hash: $node_binary_hash"
fi
if $USE_NODE; then
    echo "node manifest digest: $node_manifest_digest"
fi
if $USE_NODE_GCP; then
    echo "node gcp manifest digest: $node_gcp_manifest_digest"
fi
if $USE_RUST_LAUNCHER; then
    echo "rust launcher binary hash: $rust_launcher_binary_hash"
    echo "rust launcher manifest digest: $rust_launcher_manifest_digest"
fi
