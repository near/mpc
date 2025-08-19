# Extract P2P TLS public key
jq -j '.near_p2p_public_key' temp.json > near_p2p_public_key.pub

# Extract app_compose.json
jq -r '.tee_participant_info.raw_tcb_info | fromjson | .app_compose | fromjson' temp.json > app_compose.json

# Extract collateral
jq -r '.tee_participant_info.quote_collateral | fromjson' temp.json > collateral.json

# Extract quote
jq -c '.tee_participant_info.tee_quote' temp.json > quote.json

# Extract tcb_info
jq -r '.tee_participant_info.raw_tcb_info | fromjson' temp.json > tcb_info.json

# Extract launcher_image_compose.yaml. It is whitespace sensitive, and we need it's exact hash
# to match.
jq -j '.tee_participant_info.raw_tcb_info | fromjson | .app_compose | fromjson | .docker_compose_file' temp.json > launcher_image_compose.yaml

# Extract expected digest
printf "%s" "$(grep 'DEFAULT_IMAGE_DIGEST' launcher_image_compose.yaml | grep -o '[a-f0-9]\{64\}')" > mpc_image_digest.txt