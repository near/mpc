#!/bin/bash

# Script to reproducibly build MPC binary and the docker image.

push_flag=false

for arg in "$@"; do
  if [[ "$arg" == "--push" ]]; then
    push_flag=true
  fi
done

DOCKERFILE_NODE_TEE=deployment/Dockerfile-mpc-tee
: "${NODE_IMAGE_NAME_TEE:=mpc-node-tee}"

DOCKERFILE_LAUNCHER=deployment/Dockerfile-launcher
: "${LAUNCHER_IMAGE_NAME:=mpc-launcher}"


SOURCE_DATE=$(git log -1 --pretty=%ct)
GIT_COMMIT_HASH=$(git rev-parse HEAD)


if [ ! "$(pwd)" = "$(git rev-parse --show-toplevel)" ]; then
    echo "Must be called from project root!"
    exit 1
fi

# This might be necessary to fix reproducibility with old docker versions where
# rewrite-timestamp is not working as expected
# https://github.com/moby/buildkit/issues/4986
find . \( -type f -o -type d \) -exec touch -d @"$SOURCE_DATE" {} +

# Create our own builder (build env) to enable reproducible images
if ! docker buildx &>/dev/null; then
    echo "Must install docker-buildx"
   exit 1
fi

buildkit_version="0.24.0"
buildkit_image_name="buildkit_${buildkit_version}"

# Create our own builder (build env) to enable reproducible images
if ! docker buildx inspect ${buildkit_image_name} &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v${buildkit_version} --name ${buildkit_image_name}
fi

SOURCE_DATE_EPOCH=${SOURCE_DATE} CXXFLAGS=" -include cstdint" repro-env build --env SOURCE_DATE_EPOCH --env CXXFLAGS -- cargo build -p mpc-node --release --locked

mpc_node_binary_hash=$(sha256sum target/release/mpc-node | cut -d' ' -f1)

docker buildx build --builder ${buildkit_image_name} --no-cache \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE" \
    --output type=docker,name=$NODE_IMAGE_NAME_TEE,rewrite-timestamp=true \
    --progress plain -f "$DOCKERFILE_NODE_TEE" .

node_tee_image_hash=$(docker inspect $NODE_IMAGE_NAME_TEE | jq .[0].Id)

docker buildx build --builder ${buildkit_image_name} --no-cache \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE" \
    --output type=docker,name=$LAUNCHER_IMAGE_NAME,rewrite-timestamp=true \
    --progress plain -f "$DOCKERFILE_LAUNCHER" .

launcher_image_hash=$(docker inspect $LAUNCHER_IMAGE_NAME | jq .[0].Id)

echo "commit hash: $GIT_COMMIT_HASH"
echo "SOURCE_DATE_EPOCH used: $SOURCE_DATE"
echo "node binary hash: $mpc_node_binary_hash"
echo "node tee docker image hash: $node_tee_image_hash"
echo "launcher docker image hash: $launcher_image_hash"

if $push_flag; then
    # This assumes that docker is logged-in dockerhub registry with nearone user
    branch_name=$(git branch --show-current)
    short_hash=$(git rev-parse --short HEAD)

    docker tag $NODE_IMAGE_NAME_TEE nearone/$NODE_IMAGE_NAME_TEE:$branch_name-$short_hash
    docker push nearone/$NODE_IMAGE_NAME_TEE:$branch_name-$short_hash

    docker tag $LAUNCHER_IMAGE_NAME nearone/$LAUNCHER_IMAGE_NAME:$branch_name-$short_hash
    docker push nearone/$LAUNCHER_IMAGE_NAME:$branch_name-$short_hash
fi
