# this is reference script for updating ports for SAM VM.
# update the hard-coded values as needed.
#!/bin/bash
set -euo pipefail

# Hard-coded VM ID
VM_ID="301e47cc-f9e7-40b8-bb95-c734fdd257ab"

# Hard-coded VMM RPC
VMM_RPC="http://127.0.0.1:10000"

# Path to vmm-cli, wrapped with python3
CLI="python3 /mnt/data/barak/dstack/vmm/src/vmm-cli.py --url $VMM_RPC"

# Hard-coded port mappings
PORTS=(
  "tcp:127.0.0.1:18092:8090"
  "tcp:127.0.0.1:1221:22"
  "tcp:51.68.219.2:18082:8080"
  "tcp:127.0.0.1:3032:3030"
  "tcp:51.68.219.2:13002:13002"
  "tcp:51.68.219.2:80:80"
  "tcp:51.68.219.2:24567:24567"
  "tcp:51.68.219.2:2080:2080"
)

echo "Updating ports for VM: $VM_ID"

echo "Stopping VM..."
$CLI stop "$VM_ID" || true

echo "Updating port mappings..."
PORT_ARGS=()
for p in "${PORTS[@]}"; do
  PORT_ARGS+=( "--port" "$p" )
done

$CLI update-ports "$VM_ID" "${PORT_ARGS[@]}"

echo "Starting VM..."
$CLI start "$VM_ID"

echo "Done!"
