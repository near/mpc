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

## 2) Update the launcher hash allowlist

For both TEE and non-TEE, operators render the contract template at deploy
time using the `LAUNCHER_MANIFEST_DIGEST` and `MPC_MANIFEST_DIGEST` env vars
— there are no checked-in deployment compose files to bump.

What you need to update:

- `crates/contract/assets/allowed-launcher-hashes.json` — add the new
  `sha256:<NEW>` launcher digest to `allowed_launcher_image_digests`. CI's
  `build-and-verify-rust-launcher-docker-image.sh` fails if a
  reproducibly-built launcher image's manifest digest is not in this list.
  Vote the same digest into the contract's `allowed_launcher_image_hashes`
  in the same PR.
- `crates/contract/assets/launcher_docker_compose.yaml.template` (TEE) and
  `crates/contract/assets/launcher_docker_compose_nontee.yaml.template`
  (non-TEE) — only touch these if the **shape** of the compose changes
  (volumes, env vars, etc.). For digest-only updates, no template change is
  needed; the digests are substituted in at deploy time.
- If you do change either template's shape, regenerate the snapshot:

  ```bash
  UPDATE_SNAPSHOT=1 ./scripts/check-launcher-template-snapshot.sh
  ```

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
