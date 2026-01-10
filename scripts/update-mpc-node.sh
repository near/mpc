#!/bin/bash

CONTAINER_NAME="mpc-node"
IMAGE_NAME="nearone/mpc-node-gcp:testnet-release"
ENV_FILE=".env"
VOLUME_PATH="/home/mpc/data:/data"

# Get currently running container image ID (if exists)
RUNNING_IMAGE_ID=$(docker inspect --format "{{.Image}}" "$CONTAINER_NAME" 2>/dev/null || echo "")

# Pull latest image
echo "📥 Pulling latest image: $IMAGE_NAME..."
docker pull "$IMAGE_NAME"

# Get the latest image ID
LATEST_IMAGE_ID=$(docker inspect --format "{{.Id}}" "$IMAGE_NAME")

# Compare the running container’s image with the latest pulled image
if [ "$RUNNING_IMAGE_ID" == "$LATEST_IMAGE_ID" ]; then
    echo "✅ No update needed. The running container is already using the latest image."
    exit 0
fi

echo "🔄 New image detected. Proceeding with update..."

# Stop and remove existing container if such exist
echo "🛑 Stopping existing container..."
docker stop "$CONTAINER_NAME"

echo "🗑 Removing existing container..."
docker rm "$CONTAINER_NAME"

PORT_OVERRIDE_PORT="80:80"
NEARD_RPC_PORT="3000:3030"
MPC_DEBUG_PORT="8080:8080"
# Restricted to localhost for security
PPROF_PORT="127.0.0.1:34001:34001"

# Run the new container
echo "🚀 Starting new container..."
docker run -d --name "$CONTAINER_NAME" \
    -p "$PORT_OVERRIDE_PORT" \
    -p "$NEARD_RPC_PORT" \
    -p "$MPC_DEBUG_PORT" \
    -p "$PPROF_PORT" \
    --restart always \
    -v "$VOLUME_PATH" \
    --env-file "$ENV_FILE" \
    "$IMAGE_NAME"

# Check if the container is running
if docker ps -q -f name="$CONTAINER_NAME"; then
    echo "✅ $CONTAINER_NAME is running successfully!"
    docker logs --tail 20 "$CONTAINER_NAME"
else
    echo "❌ Failed to start $CONTAINER_NAME. Check logs for details."
    exit 1
fi
