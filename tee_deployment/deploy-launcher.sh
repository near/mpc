#!/bin/bash

# Deploys a new launcher_test_app VM to dstack-vmm using a templated Docker Compose file.
# Loads environment variables from a .env file, generates app-compose.json, and runs deployment.
# Based on: https://github.com/Dstack-TEE/dstack/blob/be9d0476a63e937eda4c13659547a25088393394/kms/dstack-app/deploy-to-vmm.sh



# Default .env path
ENV_FILE="default.env"

# Parse optional arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -e|--env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    -b|--base-path)
      basePath="$2"
      shift 2
      ;;
    -p|--python-exec)
      pythonExec="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--env-file <path>] [--base-path <path>] [--python-exec <path>]"
      exit 1
      ;;
  esac
done

# Check if .env file exists
if [ -f "$ENV_FILE" ]; then
  echo "Loading environment variables from $ENV_FILE..."
  set -a
  source "$ENV_FILE"
  set +a
else
  echo "Creating template $ENV_FILE..."
  cat >"$ENV_FILE" <<EOF

EOF
  echo "Please edit $ENV_FILE and set the required variables, then run this script again."
  exit 1
fi


# do not change these variables
# SSH ports (only for dev images)
INTERNAL_SSH_PORT=22
# Address of the dstack guest agent service inside the CVM
INTERNAL_AGENT_ADDR=8090

# do not change these variables - those are messured and reflected int the attestation
VCPU=8 # Number of vCPUs for the VM
MEMORY=64G # Memory for the VM



required_env_vars=(
  "VMM_RPC"
  "INTERNAL_AGENT_ADDR"
  "SEALING_KEY_TYPE"
  "DISK"
)

echo $VMM_RPC

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: Required environment variable $var is not set."
    echo "Please edit the .env file and set a value for $var, then run this script again."
    exit 1
  fi
done

# Default basePath if not provided via CLI
if [ -z "$basePath" ]; then
  basePath="/mnt/data/barak" # parent folder of meta-dstack
fi

# Default pythonExec if not provided via CLI
if [ -z "$pythonExec" ]; then
  pythonExec="python"
fi

CLI="$pythonExec $basePath/meta-dstack/dstack/vmm/src/vmm-cli.py --url \$VMM_RPC"


COMPOSE_TMP=$(mktemp)

cp $DOCKER_COMPOSE_FILE_PATH "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}


echo "Docker compose file:"
cat "$COMPOSE_TMP"

KEY_FLAG=""
case $SEALING_KEY_TYPE in
  KMS)
    KEY_FLAG="--kms"
    ;;
  SGX)
    KEY_FLAG="--local-key-provider"
    ;;
  *)
    echo "Error: unknown KEY_PROVIDER value '$SEALING_KEY_TYPE'. Use 'KMS' or 'SGX'."
    exit 1
    ;;
esac


echo "\n starting to create app-compose.json..."
$CLI compose \
  --docker-compose "$COMPOSE_TMP" \
  --name $APP_NAME \
  $KEY_FLAG \
  --public-logs \
  --public-sysinfo \
  --no-instance-id \
  --output .app-compose.json

echo "app-compose.json"
cat .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"


echo "Deploying $APP_NAME to dstack-vmm..."
echo "Press enter to continue..."
read


cmd="$CLI deploy \
  --name $APP_NAME \
  --compose .app-compose.json \
  --image $OS_IMAGE \
  --port tcp:$EXTERNAL_DSTACK_AGENT_PORT:$INTERNAL_AGENT_ADDR \
  --port tcp:$EXTERNAL_SSH_PORT:$INTERNAL_SSH_PORT \
  --port tcp:$EXTERNAL_MPC_PUBLIC_DEBUG_PORT:$INTERNAL_MPC_PUBLIC_DEBUG_PORT \
  --port tcp:$EXTERNAL_MPC_LOCAL_DEBUG_PORT:$INTERNAL_MPC_LOCAL_DEBUG_PORT \
  --port tcp:$EXTERNAL_MPC_MAIN_PORT:$INTERNAL_MPC_MAIN_PORT \
  --user-config $USER_CONFIG_FILE_PATH \
  --vcpu $VCPU \
  --memory $MEMORY \
  --disk $DISK"

echo "$cmd"
eval "$cmd"

#can't use port 24567
#--port tcp:$EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC:$INTERNAL_MPC_DECENTRALIZED_STATE_SYNC \
  