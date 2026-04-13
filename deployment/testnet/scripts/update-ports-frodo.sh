#!/bin/bash

# this is reference script for updating ports for FRODO VM.
# update the hard-coded values as needed.

set -euo pipefail

# Hard-coded VM ID
VM_ID="04ffdac4-09f8-4a4e-9813-d1e3f0c27e02"

# Hard-coded VMM RPC
VMM_RPC="http://127.0.0.1:10000"

# Path to vmm-cli, wrapped with python3
CLI="python3 /mnt/data/barak/dstack/vmm/src/vmm-cli.py --url $VMM_RPC"

# Hard-coded port mappings
PORTS=(
  "tcp:127.0.0.1:18091:8090"
  "tcp:127.0.0.1:1220:22"
  "tcp:51.68.219.1:18081:8080"
  "tcp:127.0.0.1:3031:3030"
  "tcp:51.68.219.1:80:80"
  "tcp:51.68.219.1:13001:13001"
  "tcp:51.68.219.1:24567:24567"
  "tcp:51.68.219.1:2080:2080"
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
