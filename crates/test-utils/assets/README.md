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
- `collateral.json`
- `quote.json`
- `tcb_info.json`
- `launcher_image_compose.yaml`
- `mpc_image_digest.txt`

All files will be written into the specified output directory.

4. Update `VALID_ATTESTATION_TIMESTAMP` in `crates/test-utils/src/attestation.rs` to a Unix timestamp after the date when the measurements were taken. This ensures that the tests will consider the measurements valid.

5. Update `crates/attestation/assets/tcb_info.json` — copy the newly generated `tcb_info.json`
   there as well, since unit tests in the `attestation` crate use it for deserialization tests.
   This is optional — the tests only verify parsing, not measurement values — but keeping it
   in sync avoids confusion.

6. Update the compiled-in measurements in `crates/mpc-attestation/assets/`:
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

## Tests that depend on these assets

After updating assets, these tests should pass:

```shell
cargo test -p mpc-contract test_submit_participant_info_succeeds_with_valid_dstack_attestation
cargo test -p mpc-contract test_tee_attestation_fails_with_invalid_tls_key
cargo test -p mpc-contract test_submit_participant_info_fails_without_approved_mpc_hash
cargo test -p mpc-contract test_verify_tee_triggers_resharing_and_kickout_on_expired_attestation
cargo test -p test-utils
```
