# Updating the MPC Launcher: what else must change

When you change the launcher image or anything that affects the **launcher
docker-compose contents**, you are changing the **measured compose hash** used
by the contract’s TEE attestation verification. That means you must update
**both production assets and test fixtures** so they stay consistent.

## Why this matters

The contract verifies a “compose hash” derived from the launcher compose file
included in the attestation (`app_compose.docker_compose_file`). If the hash
isn’t in the contract’s approved list, tests (and real nodes) will fail with
errors like:

> “MPC launcher compose hash … is not in the allowed hashes list”

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

- `tee_launcher/launcher_docker_compose.yaml` (TEE)
- `tee_launcher/launcher_docker_compose_nontee.yaml` (non-TEE)
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

- `crates/test-utils/assets/README.md`

This should regenerate/update the required assets so the fixture attestation
measurements match the updated launcher/contract expectations.

Then re-run the relevant contract tests (at minimum the TEE attestation ones) to
confirm everything is consistent.

---

## 4) Vote for new OS measurements (if RTMRs or key-provider changed)

If the launcher or dstack update changes the CVM's OS measurements (MRTD,
RTMR0-2, or key-provider event digest), participants must vote to approve the
new measurement set **before** nodes running the updated image can pass
attestation:

```bash
near contract call-function as-transaction \
  <signer-contract> \
  vote_add_os_measurement \
  json-args '{"measurement": {"mrtd": "<hex>", "rtmr0": "<hex>", "rtmr1": "<hex>", "rtmr2": "<hex>", "key_provider_event_digest": "<hex>"}}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as <your-account-id> \
  network-config testnet \
  sign-with-keychain \
  send
```

A threshold of participants must vote for the same measurement set. Use
`allowed_os_measurements` to verify the new set was accepted. The old
measurement set can be removed via `vote_remove_os_measurement` (requires
unanimity) once all nodes have upgraded.

See the [operator guide](../docs/running-an-mpc-node-in-tdx-external-guide.md#os-measurement-voting)
for full details.

---

## 5) Update the test "measurements validity" timestamp

Tests often treat the stored measurements as valid only after a given timestamp
(to avoid accepting stale measurements).

- `crates/test-utils/src/attestation.rs`

Update:

- `VALID_ATTESTATION_TIMESTAMP`

**Rule:** Set it to a Unix timestamp **after** the date/time when the
measurements were taken.

Example:

```rust
pub const VALID_ATTESTATION_TIMESTAMP: u64 = 1771419095;
```
