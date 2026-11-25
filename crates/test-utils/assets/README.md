# Updating Test Assets

Updating test assets is needed when updating launcher code (or when updating other measured components).  See [updating-launcher-internal-guide.md](../../../docs/development/updating-launcher-internal-guide.md)

Each attestation fixture lives in its own `dstack-<version>/` folder, named after the dstack
version it was captured on, and is exposed as an `AttestationFixture` constant in
`crates/test-utils/src/attestation.rs`. `LATEST` is the fixture most tests use; tests that must
pass on every fixture take it as an `rstest` `#[values(...)]` parameter. Keep a fixture for an
older OS while nodes still run it. `dstack-0.5.8/` is the one exception to the release-image rule
below: it was captured on `dstack-dev-0.5.8`.

To capture a new fixture, fetch `/public_data` from the MPC node’s public
HTTP endpoint and save the response to a JSON file.

Example:

```shell
curl http://<MPC_NODE_IP>:<MPC_NODE_PORT>/public_data -o public_data.json
```


See [single-node-readme.md](../../../localnet/tee/scripts/rust-launcher/single-node-readme.md)
for an automation script that will launch a TEE MPC node, collect the attestation, and save the public data to a temp directory (path printed by the script).
Capture on the release image (`OS_IMAGE=dstack-<version>`).


## Steps

1. Create the fixture folder and change into `crates/test-utils/assets`:

   ```shell
   mkdir -p crates/test-utils/assets/dstack-<version>
   cd crates/test-utils/assets
   ```

2. Copy the `public_data.json` file into `dstack-<version>/`.
   Keeping the original file allows future developers to trace the test vectors back to their source.

3. Run the asset extraction script:

   ```shell
   bash ./create-assets.sh dstack-<version>/public_data.json dstack-<version>
   ```

This will regenerate the following files:

- `near_p2p_public_key.pub`
- `near_account_public_key.pub`
- `app_compose.json`
- `quote.json`
- `tcb_info.json`
- `launcher_image_compose.yaml`
- `mpc_image_digest.txt`
- `collateral.json`, empty when new; step 8 fills it in

All files will be written into the specified output directory.

`public_data.json` is the endpoint response verbatim, so its collateral byte fields are arrays, while
`collateral.json` holds the same bytes hex-encoded for the contract DTO.

4. Add an `AttestationFixture` constant for the folder in `crates/test-utils/src/attestation.rs`,
   with a `valid_timestamp` after the date the attestation was taken, add it to the `#[values(...)]`
   lists of the tests that run on every fixture, and point `LATEST` at it if it is the newest.

5. Copy the node's NEAR signer secret key into `dstack-<version>/near_account_secret_key` (one line,
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
   there as well, since unit tests in the `attestation-types` crate use it for deserialization tests.
   This is optional — the tests only verify parsing, not measurement values — but keeping it
   in sync avoids confusion.

7. When the OS image changed, replace `crates/mpc-attestation/assets/tcb_info.json` with the new
   fixture's `tcb_info.json`. It is the attestation CLI's default and the measurement set operators
   vote in with `vote_add_os_measurement`. It covers `mrtd`, `rtmr0`-`rtmr2` and the key-provider
   event, none of which the compose files affect; `rtmr0` depends on the CVM's vCPU and memory
   configuration. While nodes still run the previous OS image, keep its set as
   `tcb_info_dstack_<version>.json` in `production_measurements()`, so the CLI accepts both.

8. Regenerate the derived fixtures — `collateral.json` (the captured collateral, hex-encoded for the
   contract DTO) and the verifier's borsh arguments — then refresh the report values the verifier test
   hardcodes (`mr_config_id`, `rt_mr3`, `report_data` change with every new node):

   ```shell
   UPDATE_FIXTURES=1 cargo test -p test-utils collateral_fixture
   UPDATE_FIXTURES=1 cargo test -p tee-verifier --test verify_quote verify_quote_args_fixture
   cargo test -p tee-verifier --test verify_quote
   ```

   The first `collateral_fixture` run fails, since it checks against the empty file compiled in
   before it wrote the new one; run it again to confirm it passes.

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
