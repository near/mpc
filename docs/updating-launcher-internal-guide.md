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
<https://github.com/near/mpc/actions/workflows/docker_build_launcher.yml>

This will produce a new docker image in
<https://hub.docker.com/r/nearone/mpc-launcher>

Collect the new Manifest digest from Docker hub:

```yaml
sha256:<NEW>
```

## 2) Update the launcher compose files used for deployment/docs

These are what operators actually run.

- `deployment/cvm-deployment/launcher_docker_compose.yaml` (TEE)
- `deployment/cvm-deployment/launcher_docker_compose_nontee.yaml` (non-TEE)
- (optional) any other compose templates used by deployment scripts

Keep the launcher image digest (and related env like `DEFAULT_IMAGE_DIGEST`)
consistent with the intended release.

---

## 3) Regenerate/refresh test assets (follow the README)

1. Manually or use the script in `localnet/tee/scripts/single-node.sh` (follow
   the instructions in `localnet/tee/scripts/single-node-readme.md`) to generate
   a new attestation with the updated launcher, then extract the measurements
   and update the test fixtures accordingly.

2. Follow the instructions in `crates/test-utils/assets/README.md` on how to
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

```shell
date +%s  # generate a current timestamp
```

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

Note: The launcher image hash is extracted automatically from
`test-utils/assets/launcher_image_compose.yaml` by
`test_utils::attestation::launcher_image_hash()`. No manual hash update is
needed in contract test code when assets are refreshed.
