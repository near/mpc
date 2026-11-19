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

## 2) Update the launcher compose files used for deployment/docs

These are what operators actually run.

- `deployment/cvm-deployment/launcher_docker_compose_nontee.yaml` (non-TEE)

Keep the launcher image digest (and related env like `DEFAULT_IMAGE_DIGEST`)
consistent with the intended release.

---

## 3) Regenerate/refresh test assets (follow the README)

1. Manually or use the script in `localnet/tee/scripts/rust-launcher/single-node.sh` (follow
   the instructions in `localnet/tee/scripts/rust-launcher/single-node-readme.md`) to generate
   a new attestation with the updated launcher, then extract the measurements
   and update the test fixtures accordingly.

2. Follow the instructions in [`crates/test-utils/assets/README.md`](../../crates/test-utils/assets/README.md) on how to
   update the test assets

This should regenerate/update the required assets so the fixture attestation
measurements match the updated launcher/contract expectations.

---

## 4) Update the test "measurements validity" timestamp

Each fixture is an `AttestationFixture` in `crates/test-utils/src/attestation.rs`, and is
valid only at its `valid_timestamp`.

**Rule:** Set `valid_timestamp` to a Unix timestamp **after** the date/time when the
measurements were taken (step 4 of the [assets README](../../crates/test-utils/assets/README.md#steps)).

---

## 5) Verify

Run the tests listed in [Tests that depend on these assets](../../crates/test-utils/assets/README.md#tests-that-depend-on-these-assets).
