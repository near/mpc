# Updating Test Assets

Updating test assets is needed when updating launcher code (or when updating other measured components).  See [updating-launcher-internal-guide.md](../../../docs/updating-launcher-internal-guide.md)


To update the test asset files, fetch `/public_data` from the MPC node’s public
HTTP endpoint and save the response to a JSON file.

Example:

```shell
curl http://<MPC_NODE_IP>:<MPC_NODE_PORT>/public_data -o public_data.json
```


See [single-node-readme.md](../../../localnet/tee/scripts/rust-launcher/single-node-readme.md)
for an automation script that will launch a TEE MPC node, collect the attestation, and save the public data to a temp directory (path printed by the script).


## Steps

1. Change into the `crates/test-utils/assets` directory:

   ```shell
   cd crates/test-utils/assets
   ```

2. Copy the `public_data.json` file into this directory.
   Keeping the original file allows future developers to trace the test vectors back to their source.

3. Run the asset extraction script:

   ```shell
   bash ./create-assets.sh public_data.json .
   ```

This will regenerate the following files:

- `near_p2p_public_key.pub`
- `near_account_public_key.pub`
- `app_compose.json`
- `quote.json`
- `tcb_info.json`
- `launcher_image_compose.yaml`
- `mpc_image_digest.txt`

All files will be written into the specified output directory.

`public_data.json` is the endpoint response verbatim, so its collateral byte fields are arrays, while
`collateral.json` holds the same bytes hex-encoded for the contract DTO.

4. Update `VALID_ATTESTATION_TIMESTAMP` in `crates/test-utils/src/attestation.rs` to a Unix timestamp after the date when the measurements were taken. This ensures that the tests will consider the measurements valid.

5. Copy the node's NEAR signer secret key into `near_account_secret_key` (one line,
   `ed25519:<base58>`). Tests sign as the fixture node with it, since the quote's
   `report_data` binds it. It is not in `public_data.json`: it lives in `secrets.json`
   inside the CVM, exported by
   [the collection compose](../../../localnet/tee/scripts/rust-launcher/README.md#exporting-the-nodes-signer-key).
   Only a throwaway localnet key may be committed — check that before you do. Scanners might flag
   it; it is worthless outside localnet.

   ```shell
   cargo nextest run -p test-utils account_secret_key
   ```

6. Update `crates/attestation-types/assets/tcb_info.json` — copy the newly generated `tcb_info.json`
   there as well, since unit tests in the `attestation` crate use it for deserialization tests.
   This is optional — the tests only verify parsing, not measurement values — but keeping it
   in sync avoids confusion.

7. Update the compiled-in measurements in `crates/mpc-attestation/assets/`. Skippable unless the OS
   image changed: these cover `mrtd` and `rtmr0`-`rtmr2`, none of which the compose files affect.
   - `tcb_info_dev.json` — replace with the `tcb_info.json` from a **dev** image attestation
   - `tcb_info.json` — replace with the `tcb_info.json` from a **release** (non-dev) image attestation

   These are compiled into the contract and node binary via the `include_measurements!` macro.
   You need attestation data from **both** release and dev images — run the single-node script
   twice with `OS_IMAGE=dstack-<version>` and `OS_IMAGE=dstack-dev-<version>`.

   **Why this matters:** These measurements are seeded as the default allowed OS measurements
   when the contract is deployed or migrated (see `default_measurements()` in
   `mpc-attestation/src/attestation.rs`). If they are stale, nodes running a newer OS image
   will fail attestation until operators vote in the correct measurements.

   > **Note:** This hardcoded seeding is a bootstrap mechanism. After release 3.8, measurements
   > will be managed entirely through on-chain voting (`vote_add_os_measurement`), and these
   > files will no longer need to be kept in sync with the deployed OS image.

8. Regenerate the derived fixtures — `collateral.json` (the captured collateral, hex-encoded for the
   contract DTO) and the verifier's borsh arguments — then refresh the report values the verifier test
   hardcodes (`mr_config_id`, `rt_mr3`, `report_data` change with every new node):

   ```shell
   UPDATE_FIXTURES=1 cargo test -p test-utils collateral_fixture
   UPDATE_FIXTURES=1 cargo test -p tee-verifier --test verify_quote verify_quote_args_fixture
   cargo test -p tee-verifier --test verify_quote
   ```

   The last run fails on `verify_quote__should_return_verified_td10_report_for_valid_fixture`
   and prints the values actually produced; copy them into
   `crates/tee-verifier/tests/verify_quote.rs`.

## Tests that depend on these assets

After updating assets, run the tests in the crates that consume them:

```shell
cargo nextest run --cargo-profile=test-release \
  -p attestation -p mpc-attestation -p test-utils -p attestation-cli -p tee-verifier \
  -p tee-authority -p mpc-contract
```
