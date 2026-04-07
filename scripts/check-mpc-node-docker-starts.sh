#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

USE_LAUNCHER=false
USE_RUST_LAUNCHER=false
for arg in "$@"; do
  case "$arg" in
  --launcher)
    USE_LAUNCHER=true
    ;;
  --rust-launcher)
    USE_RUST_LAUNCHER=true
    ;;
  *)
    echo "Unknown parameter: $arg"
    echo "Usage: $0 [--launcher] [--rust-launcher]"
    exit 1
    ;;
  esac
done

: "${NODE_IMAGE_NAME:=mpc-node}"
: "${LAUNCHER_IMAGE_NAME:=mpc-launcher-nontee}"
: "${RUST_LAUNCHER_IMAGE_NAME:=mpc-rust-launcher-nontee}"

if $USE_LAUNCHER; then
  cd "$REPO_ROOT/tee_launcher"
  export LAUNCHER_IMAGE_NAME
  docker compose -f launcher_docker_compose_nontee.yaml up -d
  sleep 10
  launcher_logs=$(docker logs --tail 10 "$LAUNCHER_IMAGE_NAME" 2>&1)
  if ! echo "$launcher_logs" | grep "MPC launched successfully."; then
    echo "MPC launcher image did not start properly"
    echo "$launcher_logs"
    exit 1
  fi
  CONTAINER_ID=$(docker ps -aqf "name=^mpc-node$")
elif $USE_RUST_LAUNCHER; then
  cd "$REPO_ROOT/deployment/cvm-deployment"
  # Use the locally built image instead of pulling from Docker Hub.
  # This ensures the runtime test uses the same image that was just built. See #2704.
  docker tag mpc-rust-launcher:latest nearone/mpc-launcher:ci-local
  # Create a temporary compose in the same directory (so relative volume mounts work)
  sed 's|nearone/mpc-launcher@sha256:[a-f0-9]*|nearone/mpc-launcher:ci-local|' \
    launcher_docker_compose_nontee.yaml > launcher_docker_compose_nontee_local.yaml
  export RUST_LAUNCHER_IMAGE_NAME
  docker compose -f launcher_docker_compose_nontee_local.yaml up -d
  sleep 10
  launcher_logs=$(docker logs --tail 10 "$RUST_LAUNCHER_IMAGE_NAME" 2>&1)
  if ! echo "$launcher_logs" | grep "MPC launched successfully."; then
    echo "Rust MPC launcher image did not start properly"
    echo "$launcher_logs"
    exit 1
  fi
  CONTAINER_ID=$(docker ps -aqf "name=^mpc-node$")
else
  touch /tmp/image-digest.bin
  # Test container startup - fail if container can't start
  # Start container in background and check status after 60 seconds
  CONTAINER_ID=$(docker run -d \
    -v /tmp/:/data \
    -e MPC_HOME_DIR="/data" \
    -e MPC_ACCOUNT_ID=test_image.near \
    -e RUST_BACKTRACE="full" \
    -e RUST_LOG="mpc=debug,info" \
    -e MPC_SECRET_STORE_KEY=BD399143F5B3126098B0EAA023A0E730 \
    -e MPC_P2P_PRIVATE_KEY=ed25519:2WBi5gRyJntYA7dCyddiwNV2yNTdr5uZhrP4WX5GNBL5DSVCSR7ESvcXF2DBfY5oPYhzBmHnguPVSXjr6UCi8h1g \
    -e MPC_ACCOUNT_SK=ed25519:6X3Bnghdf89WjHQfHDFYjW2UeNaNqCQ1AUGxX7zgvbJT4KSoeXzuHEdux6A2jsphTZTmS4SUGQRyYqC2ik3UrMP \
    -e NEAR_BOOT_NODES=ed25519:ERguu7jQuYk8pxNsRC6FdezvNsegBPva1GRGqjmtD7i2@10.10.10.10:24567 \
    -e MPC_CONTRACT_ID=v1.signer_test \
    -e MPC_IMAGE_HASH=5ba283860c0efa3d4c3e08a76a2b77fab4725baad4f48504eac858e04af7fd64 \
    -e MPC_LATEST_ALLOWED_HASH_FILE=/tmp/image-digest.bin \
    -e MPC_BACKUP_ENCRYPTION_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    -e MPC_ENV=mainnet "${NODE_IMAGE_NAME}")

fi

if [ -z "$CONTAINER_ID" ]; then
  echo "❌ Failed to start container"
  exit 1
fi

echo "Container started: $CONTAINER_ID"

# Check if container is actually running
WAIT_SECS=60
sleep $WAIT_SECS
if [ -z "$(docker ps --filter "id=$CONTAINER_ID" --format "{{.ID}}")" ]; then
  docker logs --tail 100 "$CONTAINER_ID" 2>&1
  echo "❌ Container cannot initialize/start properly"
  exit 1
fi

echo "✅ Container started successfully"

docker rm -f "$CONTAINER_ID"

if $USE_LAUNCHER; then
  docker compose -f launcher_docker_compose_nontee.yaml down -v --rmi local
elif $USE_RUST_LAUNCHER; then
  docker compose -f launcher_docker_compose_nontee_local.yaml down -v --rmi local
  rm -f launcher_docker_compose_nontee_local.yaml
else
  rm /tmp/image-digest.bin
fi
