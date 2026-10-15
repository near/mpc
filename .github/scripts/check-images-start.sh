#!/usr/bin/env bash

set -euo pipefail

# Runs the start checks of the mpc-node and mpc-rust-launcher images in Docker. Each
# check waits a fixed time for its container to stay up, so they run concurrently, with each line of
# output prefixed by the image it checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_STARTS="$SCRIPT_DIR/../../scripts/check-mpc-node-docker-starts.sh"

check() {
  local image="$1"
  shift
  "$@" 2>&1 | sed -u "s/^/[$image] /"
}

check mpc-launcher "$CHECK_STARTS" --rust-launcher &
launcher_check=$!
check mpc-node env NODE_IMAGE_NAME=mpc-node "$CHECK_STARTS" &
node_check=$!

status=0
for pid in "$launcher_check" "$node_check"; do
  wait "$pid" || status=1
done
exit "$status"
