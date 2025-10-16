1. To update the assets file, go to the MPC nodes public HTTP endpoint, and fetch /public_data. Save the response to a file.
2. Run the `create_assets.sh` script with

```bash
bash attestation/tests/assets/create_assets.sh <<PATH_TO_PUBLIC_DATA_RESPONSE>> <<PATH_TO_ASSETS_DIRECTORY>>
```

Example:

```shell
bash attestation/tests/assets/create_assets.sh temp.json attestation/tests/assets
```
