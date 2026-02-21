# Updating Test Assets

To update the test asset files, fetch `/public_data` from the MPC node’s public
HTTP endpoint and save the response to a JSON file.

See [single_node_readme.md](../../../localnet/tee/scripts/single_node_readme.md)
for automation script instruction.

This is needed when updating launcher code.  See [UPDATING_LAUNCHER.md](../../../tee_launcher/UPDATING_LAUNCHER.md)


Example:

```shell
curl http://<MPC_NODE_IP>:<MPC_NODE_PORT>/public_data -o public_data.json
```

## Steps

1. Change into the `crates/test_utils/assets` directory:

   ```shell
   cd crates/test_utils/assets
   ```

2. Copy the `public_data.json` file into this directory.  
   Keeping the original file allows future developers to trace the test vectors back to their source.

3. Run the asset extraction script:

   ```shell
   bash ./create_assets.sh public_data.json .
   ```

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
