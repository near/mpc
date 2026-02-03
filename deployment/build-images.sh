#! /usr/bin/env bash
# Script to reproducibly the docker images for the node and launcher
#
# Requirements: docker, docker-buildx, jq, git, find, touch
# Extra requirements if using --node: repro-env, podman
#
# Usage:
#   ./deployment/build-images.sh [--node] [--launcher] [--push]
# If neither --node nor --launcher are used, both images are built
# If using --pushed, docker must be logged in to registry


set -euo pipefail

USE_LAUNCHER=false
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
    --push)
      USE_PUSH=true
      ;;
    *)
      echo "Unknown parameter: $arg"
      echo "Usage: $0 [--node] [--launcher] [--push]"
      exit 1
      ;;
  esac
done

if ! $USE_LAUNCHER && ! $USE_NODE && ! $USE_NODE_GCP; then
    USE_LAUNCHER=true
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

if $USE_NODE; then
    require_cmds repro-env podman
fi

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


SOURCE_DATE_EPOCH=0
export RUSTFLAGS=" \
  -C target-cpu=x86-64 \
  -C metadata=reproducible \
  -C codegen-units=1 \
  -Clink-arg=-Wl,--sort-section=alignment \
  -Clink-arg=-Wl,--build-id=non"
GIT_COMMIT_HASH=$(git rev-parse HEAD)

# This might be necessary to fix reproducibility with old docker versions where
# rewrite-timestamp is not working as expected
# https://github.com/moby/buildkit/issues/4986
find . \( -type f -o -type d \) -exec touch -d @"$SOURCE_DATE_EPOCH" {} +

# Create our own builder (build env) to enable reproducible images

buildkit_version="0.24.0"
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

if $USE_LAUNCHER; then
    build_reproducible_image $LAUNCHER_IMAGE_NAME $DOCKERFILE_LAUNCHER
    launcher_image_hash=$(get_image_hash $LAUNCHER_IMAGE_NAME)
fi

if $USE_NODE || $USE_NODE_GCP; then
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH repro-env build --env SOURCE_DATE_EPOCH --env RUSTFLAGS -- cargo build -p mpc-node --profile reproducible --locked
    node_binary_hash=$(sha256sum target/reproducible/mpc-node | cut -d' ' -f1)
fi

if $USE_NODE; then
    build_reproducible_image $NODE_IMAGE_NAME $DOCKERFILE_NODE
    node_image_hash=$(get_image_hash $NODE_IMAGE_NAME)
fi

if $USE_NODE_GCP; then
    build_reproducible_image $NODE_GCP_IMAGE_NAME $DOCKERFILE_NODE_GCP
    node_gcp_image_hash=$(get_image_hash $NODE_GCP_IMAGE_NAME)
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

    if $USE_LAUNCHER; then
        temp_dir=$(mktemp -d)
        echo "using $temp_dir"
        # This compresses the built image to a local directory, which implicitly computes the manifest
        # digest in $temp_dir/manifest.json
        skopeo copy --all --dest-compress docker-daemon:$LAUNCHER_IMAGE_NAME:latest dir:$temp_dir
        # Then we publish the image from the directory, making sure the manifest digest does not change
        skopeo copy --preserve-digests dir:$temp_dir docker://docker.io/nearone/$LAUNCHER_IMAGE_NAME:$image_tag
    fi

    if $USE_NODE; then
        docker tag $NODE_IMAGE_NAME nearone/$NODE_IMAGE_NAME:$image_tag
        docker push nearone/$NODE_IMAGE_NAME:$image_tag
    fi

    if $USE_NODE_GCP; then
        docker tag $NODE_GCP_IMAGE_NAME nearone/$NODE_GCP_IMAGE_NAME:$image_tag
        docker push nearone/$NODE_GCP_IMAGE_NAME:$image_tag
    fi
fi

echo "commit hash: $GIT_COMMIT_HASH"
echo "SOURCE_DATE_EPOCH used: $SOURCE_DATE_EPOCH"
if $USE_NODE || $USE_NODE_GCP; then
    echo "node binary hash: $node_binary_hash"
fi
if $USE_NODE; then
    echo "node docker image hash: $node_image_hash"
fi
if $USE_NODE_GCP; then
    echo "node gcp docker image hash: $node_gcp_image_hash"
fi
if $USE_LAUNCHER; then
    echo "launcher docker image hash: $launcher_image_hash"
fi
