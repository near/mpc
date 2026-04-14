#! /usr/bin/env bash
# Script to reproducibly build the docker images for the node and launcher
#
# Requirements: docker, docker-buildx, jq, git, find, touch, skopeo
# Extra requirements if using --node or --rust-launcher: repro-env, podman
# Extra requirements if using --push: docker must be logged in to registry
#
# Usage:
#   ./deployment/build-images.sh [--node] [--node-gcp] [--launcher] [--rust-launcher] [--push]
# If no image flags are used, all images are built
# Manifest digests are always computed and printed (skopeo required)


set -euo pipefail

USE_LAUNCHER=false
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
    --launcher)
      USE_LAUNCHER=true
      ;;
    --rust-launcher)
      USE_RUST_LAUNCHER=true
      ;;
    --push)
      USE_PUSH=true
      ;;
    *)
      echo "Unknown parameter: $arg"
      echo "Usage: $0 [--node] [--launcher] [--rust-launcher] [--push]"
      exit 1
      ;;
  esac
done

if ! $USE_LAUNCHER && ! $USE_RUST_LAUNCHER && ! $USE_NODE && ! $USE_NODE_GCP; then
    USE_LAUNCHER=true
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

require_cmds docker jq git find touch

if $USE_NODE || $USE_RUST_LAUNCHER; then
    require_cmds repro-env podman
fi

require_cmds skopeo

if ! docker buildx &>/dev/null; then
  die "Please install docker-buildx"
fi

if [ ! "$(pwd)" = "$(git rev-parse --show-toplevel)" ]; then
    echo "Must be called from project root!"
    exit 1
fi

DOCKERFILE_NODE=deployment/Dockerfile-node
: "${NODE_IMAGE_NAME:=mpc-node}"

DOCKERFILE_NODE_GCP=deployment/Dockerfile-node-gcp
: "${NODE_GCP_IMAGE_NAME:=mpc-node-gcp}"

DOCKERFILE_LAUNCHER=deployment/Dockerfile-launcher
: "${LAUNCHER_IMAGE_NAME:=mpc-launcher}"

DOCKERFILE_RUST_LAUNCHER=deployment/Dockerfile-rust-launcher
: "${RUST_LAUNCHER_IMAGE_NAME:=mpc-rust-launcher}"


SOURCE_DATE_EPOCH=0
GIT_COMMIT_HASH=$(git rev-parse HEAD)

# This might be necessary to fix reproducibility with old docker versions where
# rewrite-timestamp is not working as expected
# https://github.com/moby/buildkit/issues/4986
find . \( -type f -o -type d \) -exec touch -d @"$SOURCE_DATE_EPOCH" {} +

# Create our own builder (build env) to enable reproducible images

buildkit_version="0.27.1"
buildkit_image_name="buildkit_${buildkit_version}"

if ! docker buildx inspect ${buildkit_image_name} &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v${buildkit_version} --name ${buildkit_image_name}
fi


build_reproducible_image() {
  local image_name=$1
  local dockerfile_path=$2
  docker buildx build --builder ${buildkit_image_name} --no-cache \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --output type=docker,name=$image_name,rewrite-timestamp=true \
    --progress plain -f "$dockerfile_path" .
}

get_image_hash() {
    local image_name=$1
    docker inspect $image_name | jq -r .[0].Id
}

# Compress a locally built image via skopeo and compute its manifest digest.
# Sets two global variables: <prefix>_manifest_digest and <prefix>_skopeo_dir
# Usage: skopeo_compress <image_name> <variable_prefix>
skopeo_compress() {
    local image_name="$1"
    local prefix="$2"
    local td
    td=$(mktemp -d)
    # Compress the built image to a local directory, which implicitly computes
    # the manifest digest in $td/manifest.json
    skopeo copy --all --dest-compress "docker-daemon:${image_name}:latest" "dir:$td"
    local digest="sha256:$(sha256sum "$td/manifest.json" | cut -d' ' -f1)"
    printf -v "${prefix}_manifest_digest" '%s' "$digest"
    printf -v "${prefix}_skopeo_dir" '%s' "$td"
}

if $USE_LAUNCHER; then
    build_reproducible_image $LAUNCHER_IMAGE_NAME $DOCKERFILE_LAUNCHER
    launcher_image_hash=$(get_image_hash $LAUNCHER_IMAGE_NAME)
    skopeo_compress "$LAUNCHER_IMAGE_NAME" launcher
fi

if $USE_RUST_LAUNCHER; then
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH repro-env build --env SOURCE_DATE_EPOCH -- cargo build -p tee-launcher --profile reproducible --locked
    rust_launcher_binary_hash=$(sha256sum target/reproducible/tee-launcher | cut -d' ' -f1)

    build_reproducible_image $RUST_LAUNCHER_IMAGE_NAME $DOCKERFILE_RUST_LAUNCHER
    rust_launcher_image_hash=$(get_image_hash $RUST_LAUNCHER_IMAGE_NAME)
    skopeo_compress "$RUST_LAUNCHER_IMAGE_NAME" rust_launcher
fi

if $USE_NODE || $USE_NODE_GCP; then
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH repro-env build --env SOURCE_DATE_EPOCH -- cargo build -p mpc-node --profile reproducible --locked
    node_binary_hash=$(sha256sum target/reproducible/mpc-node | cut -d' ' -f1)
fi

if $USE_NODE; then
    build_reproducible_image $NODE_IMAGE_NAME $DOCKERFILE_NODE
    node_image_hash=$(get_image_hash $NODE_IMAGE_NAME)
    skopeo_compress "$NODE_IMAGE_NAME" node
fi

if $USE_NODE_GCP; then
    build_reproducible_image $NODE_GCP_IMAGE_NAME $DOCKERFILE_NODE_GCP
    node_gcp_image_hash=$(get_image_hash $NODE_GCP_IMAGE_NAME)
    skopeo_compress "$NODE_GCP_IMAGE_NAME" node_gcp
fi

if $USE_PUSH; then
    # This assumes that docker is logged-in dockerhub registry with nearone user

    branch_name=$(git branch --show-current)
    if [ -z "$branch_name" ]; then
        branch_name="detached"
    fi
    sanitized_branch_name="${branch_name//\//-}"

    short_hash=$(git rev-parse --short HEAD)
    image_tag="$sanitized_branch_name-$short_hash"
    echo "Using branch-hash tag: $image_tag"

    # Push from the already-compressed local directory, preserving the manifest digest.
    if $USE_LAUNCHER; then
        skopeo copy --preserve-digests "dir:$launcher_skopeo_dir" "docker://docker.io/nearone/$LAUNCHER_IMAGE_NAME:$image_tag"
    fi

    if $USE_NODE; then
        skopeo copy --preserve-digests "dir:$node_skopeo_dir" "docker://docker.io/nearone/$NODE_IMAGE_NAME:$image_tag"
    fi

    if $USE_NODE_GCP; then
        skopeo copy --preserve-digests "dir:$node_gcp_skopeo_dir" "docker://docker.io/nearone/$NODE_GCP_IMAGE_NAME:$image_tag"
    fi

    if $USE_RUST_LAUNCHER; then
        skopeo copy --preserve-digests "dir:$rust_launcher_skopeo_dir" "docker://docker.io/nearone/$RUST_LAUNCHER_IMAGE_NAME:$image_tag"
    fi
fi

echo "commit hash: $GIT_COMMIT_HASH"
echo "SOURCE_DATE_EPOCH used: $SOURCE_DATE_EPOCH"
if $USE_NODE || $USE_NODE_GCP; then
    echo "node binary hash: $node_binary_hash"
fi
if $USE_NODE; then
    echo "node docker image hash: $node_image_hash"
    echo "node manifest digest: $node_manifest_digest"
fi
if $USE_NODE_GCP; then
    echo "node gcp docker image hash: $node_gcp_image_hash"
    echo "node gcp manifest digest: $node_gcp_manifest_digest"
fi
if $USE_LAUNCHER; then
    echo "launcher docker image hash: $launcher_image_hash"
    echo "launcher manifest digest: $launcher_manifest_digest"
fi
if $USE_RUST_LAUNCHER; then
    echo "rust launcher binary hash: $rust_launcher_binary_hash"
    echo "rust launcher docker image hash: $rust_launcher_image_hash"
    echo "rust launcher manifest digest: $rust_launcher_manifest_digest"
fi
