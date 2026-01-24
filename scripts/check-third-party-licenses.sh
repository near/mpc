#!/bin/bash

set -euo pipefail


# debug
echo "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}"
d=$(ls -d ${CARGO_HOME:-$HOME/.cargo}/registry/src/*/rkyv_derive-0.8.13 2>/dev/null | head -n1)
echo "dir=$d"
ls -la "$d"/LICENSE* 2>/dev/null || true

## end debug

# Configuration
LICENSE_FILE="licenses.html"
TEMP_LICENSE_FILE="/tmp/mpc_third_party_licenses.html"
WORKSPACE_FILE="../Cargo.toml"
TEMPLATE="about.hbs"

cd third-party-licenses

echo "Checking if $LICENSE_FILE is up to date..."

# 1. Generate the license data to the temp file
if ! cargo about generate --locked --offline -m $WORKSPACE_FILE "$TEMPLATE" > "$TEMP_LICENSE_FILE"; then
    echo "❌ Error: cargo-about failed to generate licenses."
    rm -f "$TEMP_LICENSE_FILE"
    exit 1
fi

# 2. Compare the temp file with the committed file
if diff -u "$LICENSE_FILE" "$TEMP_LICENSE_FILE"; then
    echo "✅ Success: $LICENSE_FILE is up to date."
    rm "$TEMP_LICENSE_FILE"
    exit 0
else
    echo "❌ Failure: $LICENSE_FILE is out of sync."
    echo "Check https://github.com/near/mpc/blob/main/third-party-licenses/README.md for instructions on how to update the license file."
    rm "$TEMP_LICENSE_FILE"
    exit 1
fi