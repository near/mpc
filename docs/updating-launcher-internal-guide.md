# Updating the MPC Launcher: what else must change

When you change the launcher image or anything that affects the **launcher
docker-compose contents**, you are changing the **measured compose hash** used
by the contract's TEE attestation verification. That means you must update
**both production assets and test fixtures** so they stay consistent.

## Why this matters

The contract verifies a "compose hash" derived from the launcher compose file
included in the attestation (`app_compose.docker_compose_file`). If the hash
isn't in the contract's approved list, tests (and real nodes) will fail with
errors like:

> "MPC launcher compose hash … is not in the allowed hashes list"

---

## 1) Create a docker image with the new launcher

Use the existing CI workflow for building the launcher image.
<https://github.com/near/mpc/actions/workflows/docker_build_rust_launcher.yml>

This will produce a new docker image in
<https://hub.docker.com/r/nearone/mpc-launcher>

Collect the new Manifest digest from Docker hub:

```yaml
sha256:<NEW>
```

## 2) Update the launcher compose assets used for deployment/docs

For the TEE flow, operators render the contract template at deploy time
using the `LAUNCHER_MANIFEST_DIGEST` and `MPC_MANIFEST_DIGEST` env vars —
there is no checked-in TEE compose file to bump. Make sure the new
launcher digest matches the contract template's expected structure:

- `crates/contract/assets/launcher_docker_compose.yaml.template`

The non-TEE flow still pins digests in a checked-in compose file:

- `deployment/cvm-deployment/launcher_docker_compose_nontee.yaml` (non-TEE)

Update the digests there to match the intended release.

---

## 3) Regenerate/refresh test assets (follow the README)

1. Manually or use the script in `localnet/tee/scripts/rust-launcher/single-node.sh` (follow
   the instructions in `localnet/tee/scripts/rust-launcher/single-node-readme.md`) to generate
   a new attestation with the updated launcher, then extract the measurements
   and update the test fixtures accordingly.

2. Follow the instructions in [`crates/test-utils/assets/README.md`](../crates/test-utils/assets/README.md) on how to
   update the test assets

This should regenerate/update the required assets so the fixture attestation
measurements match the updated launcher/contract expectations.

---

## 4) Update the test "measurements validity" timestamp

Tests often treat the stored measurements as valid only after a given timestamp
(to avoid accepting stale measurements).

- `crates/test-utils/src/attestation.rs`

Update:

- `VALID_ATTESTATION_TIMESTAMP`

**Rule:** Set it to a Unix timestamp **after** the date/time when the
measurements were taken.

Example:

```rust
pub const VALID_ATTESTATION_TIMESTAMP: u64 = 1774018367;
```

---

## 5) Verify

Run the tests that depend on attestation assets:

```shell
cargo test -p mpc-contract test_submit_participant_info_succeeds_with_valid_dstack_attestation
cargo test -p mpc-contract test_tee_attestation_fails_with_invalid_tls_key
cargo test -p mpc-contract test_submit_participant_info_fails_without_approved_mpc_hash
cargo test -p mpc-contract test_verify_tee_triggers_resharing_and_kickout_on_expired_attestation
cargo test -p test-utils
```
