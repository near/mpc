#!/bin/bash

# Check if both arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <input_json_file> <output_directory>"
    echo "Example: $0 temp.json ./output"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_DIR="$2"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Check if output directory was created successfully
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Could not create output directory '$OUTPUT_DIR'"
    exit 1
fi

echo "Extracting data from '$INPUT_FILE' to '$OUTPUT_DIR'..."

# Extract P2P TLS public key
jq -j '.near_p2p_public_key' "$INPUT_FILE" > "$OUTPUT_DIR/near_p2p_public_key.pub"

# Extract app_compose.json. We set 4 width indentation, and remove trailing newline, so it matches the original string in tests.
printf '%s' "$(jq -r --indent 4 '.tee_participant_info.raw_tcb_info | fromjson | .app_compose | fromjson' "$INPUT_FILE")" > "$OUTPUT_DIR/app_compose.json"

# Extract collateral
jq -r '.tee_participant_info.quote_collateral | fromjson' "$INPUT_FILE" > "$OUTPUT_DIR/collateral.json"

# Extract quote
jq -c '.tee_participant_info.tee_quote' "$INPUT_FILE" > "$OUTPUT_DIR/quote.json"

# Extract tcb_info
jq -r '.tee_participant_info.raw_tcb_info | fromjson' "$INPUT_FILE" > "$OUTPUT_DIR/tcb_info.json"

# Extract launcher_image_compose.yaml. It is whitespace sensitive, and we need its exact hash
# to match.
jq -j '.tee_participant_info.raw_tcb_info | fromjson | .app_compose | fromjson | .docker_compose_file' "$INPUT_FILE" > "$OUTPUT_DIR/launcher_image_compose.yaml"

# Extract expected digest
printf "%s" "$(grep 'DEFAULT_IMAGE_DIGEST' "$OUTPUT_DIR/launcher_image_compose.yaml" | grep -o '[a-f0-9]\{64\}')" > "$OUTPUT_DIR/mpc_image_digest.txt"

echo "Extraction complete. Files written to '$OUTPUT_DIR':"
ls -la "$OUTPUT_DIR"