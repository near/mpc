#!/bin/bash

# Deploys a new launcher_test_app VM to dstack-vmm using a templated Docker Compose file.
# Loads environment variables from a .env file, generates app-compose.json, and runs deployment.
# Based on: https://github.com/Dstack-TEE/dstack/blob/be9d0476a63e937eda4c13659547a25088393394/kms/dstack-app/deploy-to-vmm.sh

check_ports_in_use() {
    PORT_VARS="
    EXTERNAL_DSTACK_AGENT_PORT
    EXTERNAL_SSH_PORT
    EXTERNAL_MPC_PUBLIC_DEBUG_PORT
    EXTERNAL_MPC_LOCAL_DEBUG_PORT
    EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC
    EXTERNAL_MPC_MAIN_PORT
    EXTERNAL_MPC_FUTURE_PORT
    "

    if ! command -v ss >/dev/null 2>&1; then
        echo "⚠️  WARNING: could not check port conflict. please install ss"
        exit 1
    fi

    any_in_use=0

    # Only IPv4 listeners (-4). Local address is column 4 (e.g. 0.0.0.0:13002 or 51.68.219.11:13002)
    addrs="$(ss -H -4 -ltn 2>/dev/null | awk '{print $4}')"

    for var in $PORT_VARS; do
        val=$(eval echo \$$var)
        [ -z "$val" ] && continue

        ip="${val%%:*}"
        port="${val##*:}"

        echo "Checking $var ($ip:$port)..."

        conflict=0

        if [[ "$ip" == "0.0.0.0" ]]; then
            # Binding to all IPv4 addresses conflicts with ANY existing listener on that port.
            if echo "$addrs" | grep -Eq ":$port$"; then
                conflict=1
            fi
        else
            # Binding to a specific IPv4 address conflicts if:
            # 1) someone already bound 0.0.0.0:port, OR
            # 2) someone already bound that exact ip:port.
            if echo "$addrs" | grep -Eq "0\.0\.0\.0:$port$|${ip//./\\.}:$port$"; then
                conflict=1
            fi
        fi

        if [ $conflict -eq 1 ]; then
            echo "  -> ❌ CONFLICT"
            any_in_use=1
        else
            echo "  -> ✅ free"
        fi
    done

    if [ $any_in_use -eq 1 ]; then
        echo "❌ One or more required IPv4 IP:ports conflict. Aborting."
        exit 1
    else
        echo "✅ All required IPv4 IP:ports are free."
    fi
}


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
      -y|--yes)
      AUTO_YES=1
      shift 1
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


# Do not change these variables
# SSH ports (only for dev images)
INTERNAL_SSH_PORT=22
# Address of the dstack guest agent service inside the CVM
INTERNAL_AGENT_ADDR=8090

# Do not change these variables - those are measured and reflected in the attestation
VCPU=4 # Number of vCPUs for the VM
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
  basePath="./" # parent folder of meta-dstack
fi

# Default pythonExec if not provided via CLI
if [ -z "$pythonExec" ]; then
  pythonExec="python"
fi

CLI="$pythonExec $basePath/vmm/src/vmm-cli.py --url $VMM_RPC"


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


echo -e "\nCreating app-compose.json..."
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


echo -e "Deploying $APP_NAME to dstack-vmm..."
if [ -z "${AUTO_YES:-}" ]; then
  echo "Press enter to continue..."
  read
else
  echo "--yes set: continuing without prompt"
fi

# check if port are free
check_ports_in_use

cmd="$CLI deploy \
  --name $APP_NAME \
  --compose .app-compose.json \
  --image $OS_IMAGE \
  --port tcp:$EXTERNAL_DSTACK_AGENT_PORT:$INTERNAL_AGENT_ADDR \
  --port tcp:$EXTERNAL_SSH_PORT:$INTERNAL_SSH_PORT \
  --port tcp:$EXTERNAL_MPC_PUBLIC_DEBUG_PORT:$INTERNAL_MPC_PUBLIC_DEBUG_PORT \
  --port tcp:$EXTERNAL_MPC_LOCAL_DEBUG_PORT:$INTERNAL_MPC_LOCAL_DEBUG_PORT \
  --port tcp:$EXTERNAL_MPC_MAIN_PORT:$INTERNAL_MPC_MAIN_PORT \
  --port tcp:$EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC:$INTERNAL_MPC_DECENTRALIZED_STATE_SYNC \
  --port tcp:$EXTERNAL_MPC_FUTURE_PORT:$INTERNAL_MPC_FUTURE_PORT \
  --user-config $USER_CONFIG_FILE_PATH \
  --vcpu $VCPU \
  --memory $MEMORY \
  --disk $DISK"

echo "$cmd"
eval "$cmd"