# Updating Test Assets

To update the test asset files, fetch `/public_data` from the MPC node’s public
HTTP endpoint and save the response to a JSON file.

Example:

    curl http://<MPC_NODE_IP>:<MPC_NODE_PORT>/public_data -o public_data.json

Then run the asset extraction script:

    bash crates/test_utils/assets/create_assets.sh public_data.json crates/test_utils/assets

This will regenerate the following files:

- `near_p2p_public_key.pub`
- `near_account_public_key.pub`
- `app_compose.json`
- `collateral.json`
- `quote.json`
- `tcb_info.json`
- `launcher_image_compose.yaml`
- `mpc_image_digest.txt`

All files will be written into the specified output directory.

## Note
Also add the original `public_data.json` file to this directory.  
This allows future developers to trace test vectors back to their source.