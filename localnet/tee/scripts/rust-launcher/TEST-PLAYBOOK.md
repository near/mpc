# Rust Launcher Test Playbook

## Environment

| Component | Value |
|-----------|-------|
| Machine | 51.68.219.1 (alice profile) |
| dstack version | dstack-dev-0.5.8 |
| OS image | dstack-dev-0.5.8 |
| Rust launcher image | `nearone/mpc-launcher@sha256:f0d8146ae705dad182f7e9601e6e97215be4cf94ce80b38fddb2df654020be49` |
| MPC node (initial) | `nearone/mpc-node:main-9515e18` (hash: `6a5700fccbb3facddd1f3934f4976c4dcefc176c4aac28cd2fd035984b368980`) |
| MPC node (upgrade) | `nearone/mpc-node:main-f80f491` (hash: `9799081990b33d138483e534487c63cda322e2b19233971484b7d0e8ddcab628`) |
| NEAR network | mpc-localnet |
| Cluster size | N=2, threshold=2 |
| Branch | `barak/port-node-launcher-to-rust-v3` |
| Date | 2026-03-29 |

## Test Matrix

| # | Test | Script | Status |
|---|------|--------|--------|
| 1 | 2-node cluster deploy + verify | `deploy-tee-localnet.sh` + `test-verify-and-upgrade.sh verify` | PASS |
| 2 | Rolling upgrade (main-9515e18 → main-f80f491) | `test-verify-and-upgrade.sh upgrade main-f80f491` | PASS |
| 3 | Hash override (force older approved hash) | `test-hash-override.sh override <hash> <tag>` | PASS |
| 4 | Hash override rejection (unapproved hash) | `test-hash-override.sh override-reject` | PASS |
| 5 | Image-digest.bin persistence across CVM restart | Manual test | PASS (with compatible MPC node) |

---

## Tests

### Test 1: 2-Node Cluster Deploy + Verify

**Setup**: Fresh localnet, deploy 2-node cluster with Rust launcher + `main-9515e18`.

**Steps**:
1. Reset localnet (`neard init`)
2. Run `deploy-tee-localnet.sh` (preflight → render → accounts → contract → deploy → collect → init → vote → domains)
3. Run `test-verify-and-upgrade.sh verify`

**Expected**: Contract in Running state, 2 TEE accounts, real Dstack attestation, ECDSA signature works.

**Result**: All 6 checks pass.

**Status**: PASS

---

### Test 2: Rolling Upgrade

**Setup**: Running 2-node cluster on `main-9515e18`.

**Steps**:
1. Vote for new MPC image hash (`main-f80f491`)
2. Wait for nodes to detect and persist hash to `image-digest.bin`
3. Update TOML config with new tag, stop → update-user-config → start each CVM
4. Verify cluster operational with new image

**Expected**: Nodes pick up new hash from disk, launcher selects newest approved hash, pulls new image, cluster operational.

**Result**: All steps pass. Signature needs ~60s after restart for triple generation.

**Status**: PASS

---

### Test 3: Hash Override (Positive)

**Setup**: Running 2-node cluster with both `6a5700fc...` and `979908...` approved.

**Steps**:
1. Add `mpc_hash_override = "sha256:6a5700fc..."` to TOML config
2. Set `image_tags = ["main-9515e18"]`
3. Stop → update-user-config → start
4. Verify launcher used override hash (not newest)

**Expected**: Launcher selects overridden hash instead of newest, attestation confirms override hash.

**Result**: Launcher used override hash. Attestation confirms `6a5700fc...` (the older image).

**Status**: PASS

---

### Test 4: Hash Override Rejection (Negative)

**Setup**: Running node with approved hashes on disk.

**Steps**:
1. Set `mpc_hash_override` to a hash NOT in the approved list (`000...000`)
2. Stop → update-user-config → start
3. Check launcher logs for rejection error
4. Confirm MPC node container did not start

**Expected**: Launcher exits with `InvalidHashOverride` error, MPC node never starts.

**Result**: Launcher logged `MPC_HASH_OVERRIDE=sha256:000...000 does not match any approved hash` and exited.

**Status**: PASS

---

### Test 5: Image-Digest.bin Persistence

**Setup**: Running node with a new hash voted and approved on-chain.

**Steps**:
1. Vote for new hash, wait for node to write `image-digest.bin`
2. Stop CVM → update-user-config with new tag → start CVM
3. Check launcher logs for hash file read

**Expected**: Launcher reads approved hashes from disk on restart, selects newest.

**Result**:
- **Python launcher**: Works — `image-digest.bin` persists, launcher reads both hashes.
- **Rust launcher with `main-9515e18`**: Works — node writes file, launcher reads it on restart.
- **Rust launcher with `3.7.0` (Docker Hub release)**: Fails — node doesn't write file because 3.7.0 doesn't support TOML `[tee]` config (pre-dates Rust launcher).

**Status**: PASS (with compatible MPC node image)

---

## Full Run Details

### Test 1: 2-Node Cluster Deploy + Verify

**Deploy command**:
```bash
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh
export NO_PAUSE=1 FORCE_RECOLLECT=1 FORCE_REINIT_ARGS=1 \
  MPC_CONTRACT_ACCOUNT=mpc.mpc-local.test.near \
  START_FROM_PHASE=preflight RESUME=0
bash localnet/tee/scripts/rust-launcher/deploy-tee-localnet.sh
```

**Deploy output** (summary):
```
MPC_IMAGE_TAGS      : main-9515e18
CODE_HASH           : 6a5700fccbb3facddd1f3934f4976c4dcefc176c4aac28cd2fd035984b368980
LAUNCHER_HASH       : f0d8146ae705dad182f7e9601e6e97215be4cf94ce80b38fddb2df654020be49
✅ Done
```

**Verify command**:
```bash
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh verify
```

**Verify output**:
```
[PASS] Contract is in Running state
[PASS] TEE accounts: 2 registered (expected 2)
[PASS] node0 attestation: Dstack (mpc_hash=6a5700fccbb3facd...)
[PASS] node1 attestation: Dstack (mpc_hash=6a5700fccbb3facd...)
[PASS] ECDSA signature generated (big_r=03ffb1a5947a284c356d...)
[PASS] Allowed MPC image hashes: 1
[PASS] All verification checks passed
```

**Verification commands**:
```bash
# State
near contract call-function as-read-only mpc.mpc-local.test.near state json-args {} network-config mpc-localnet now
# → { "Running": { ... } }

# TEE accounts
near contract call-function as-transaction mpc.mpc-local.test.near get_tee_accounts json-args {} \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as mpc-local.test.near network-config mpc-localnet sign-with-keychain send
# → 2 accounts with tls_public_key

# Attestation (per node)
near contract call-function as-read-only mpc.mpc-local.test.near get_attestation \
  json-args '{"tls_public_key": "ed25519:<key>"}' network-config mpc-localnet now
# → { "Dstack": { "mpc_image_hash": "6a5700fc...", ... } }

# Sign
near contract call-function as-transaction mpc.mpc-local.test.near sign \
  file-args docs/localnet/args/sign_ecdsa.json \
  prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
  sign-as node0.mpc-local.test.near network-config mpc-localnet sign-with-keychain send
# → { "big_r": { "affine_point": "03ffb1a5..." }, "s": { ... } }
```

---

### Test 2: Rolling Upgrade

**Command**:
```bash
bash localnet/tee/scripts/rust-launcher/test-verify-and-upgrade.sh upgrade main-f80f491
```

**Key output**:
```
[PASS] All verification checks passed          (pre-upgrade)
New MPC image config digest: 9799081990b33d138483e534487c63cda322e2b19233971484b7d0e8ddcab628
[PASS] New hash approved on-chain: 9799081990b33d...
[PASS] Nodes detected new approved hash
  node0: stopping VM ... updating user-config ... starting VM
  node1: stopping VM ... updating user-config ... starting VM
[PASS] node0 is back online
[PASS] node1 is back online
```

**Launcher logs after restart** (node0):
```
INFO tee_launcher: selected newest approved hash selected=DockerSha256Digest(... [151, 153, 8, 25, ...])
INFO tee_launcher: config digest matched, resolved manifest digest tag="main-f80f491" content_digest=sha256:d44fba73...
INFO tee_launcher: MPC launched successfully.
```

**Post-upgrade verification** (manual, after 60s wait):
```
=== STATE ===
{ "Running": { ... } }

=== ATTESTATION ===
  node0: "Dstack" (mpc_hash=9799081990b33d13...)
  node1: "Dstack" (mpc_hash=9799081990b33d13...)

=== SIGN ===
  ECDSA signature: OK

=== ALLOWED HASHES ===
  "9799081990b33d138483e534487c63cda322e2b19233971484b7d0e8ddcab628"
  "6a5700fccbb3facddd1f3934f4976c4dcefc176c4aac28cd2fd035984b368980"
```

**Note**: The automated post-upgrade verify ran too quickly after restart — signature failed with "Transaction has expired" because nodes needed ~60s to generate triples. Manual retry after 60s succeeded. Script was updated with retry logic (4 attempts, 30s intervals).

---

### Test 3: Hash Override (Positive)

**Command**:
```bash
bash localnet/tee/scripts/rust-launcher/test-hash-override.sh override \
  6a5700fccbb3facddd1f3934f4976c4dcefc176c4aac28cd2fd035984b368980 main-9515e18
```

**Output**:
```
[PASS] node0 is back online
[PASS] node1 is back online
[PASS] Attestation confirms override hash: 6a5700fccbb3facd...
[PASS] ECDSA signature generated
[PASS] Hash override test passed
```

**TOML config change applied**:
```toml
[launcher_config]
mpc_hash_override = "sha256:6a5700fccbb3facddd1f3934f4976c4dcefc176c4aac28cd2fd035984b368980"
image_tags = ["main-9515e18"]
```

The launcher log confirmed it used the override instead of the newest hash (`979908...`).

---

### Test 4: Hash Override Rejection (Negative)

**Command**:
```bash
bash localnet/tee/scripts/rust-launcher/test-hash-override.sh override-reject
```

**Launcher logs** (confirming rejection):
```
INFO tee_launcher: override mpc image hash provided override_image=DockerSha256Digest(... [0, 0, 0, ...])
ERROR tee_launcher: Error: MPC_HASH_OVERRIDE invalid: MPC_HASH_OVERRIDE=sha256:0000000000000000000000000000000000000000000000000000000000000000 does not match any approved hash
```

The launcher exited with error code 1. MPC node container never started.

---

### Test 5: Image-Digest.bin Persistence

**Context**: The MPC node writes approved hashes to `/mnt/shared/image-digest.bin` when it detects new approved hashes on-chain. On CVM restart, the launcher reads this file to know which hashes are approved.

**Python launcher test**:
```bash
# After voting for new hash and waiting 20s:
# Launcher logs on restart:
INFO Approved MPC image hashes (newest → oldest):
INFO   - sha256:00006c1059cc0219005b21956a4df8238b0cc33ad559a578a63169de4e28c81e
INFO   - sha256:e2ef71c220158f9ee19a265d583647eedb4e0cd7ca37021fbf0ab34e3d214ed0
INFO Selected MPC hash (newest allowed): sha256:00006c10...
INFO MPC launched successfully.
```
Result: **PASS** — file persists, launcher reads both hashes.

**Rust launcher test** (with `main-9515e18`):
```bash
# Node log confirming write:
INFO mpc_node::tee::allowed_image_hashes_watcher: Writing approved MPC image hashes to disk (JSON format). self.file_path="/mnt/shared/image-digest.bin" len=2

# Launcher logs on restart:
INFO tee_launcher: selected newest approved hash selected=DockerSha256Digest(... [0, 0, 108, 16, ...])
INFO tee_launcher: config digest matched, resolved manifest digest tag="main-ff99aa5"
INFO tee_launcher: MPC launched successfully.
```
Result: **PASS** — file persists, launcher reads it.

**Rust launcher with `3.7.0`** (Docker Hub release):
```bash
# Launcher logs on restart:
WARN tee_launcher: approved hashes file does not exist on disk, falling back to default digest
```
Result: **FAIL** — the `3.7.0` image predates the Rust launcher and doesn't support TOML `[tee]` config, so it never writes `image-digest.bin`. The node needs to be built from a commit that includes PR #2499 (`chore: move TEE config into launcher-interface`).

---

## Known Issues / Notes

1. **Signature generation after restart**: Nodes need ~60s after CVM restart to generate triples/presignatures. The test script retries up to 4 times with 30s intervals.

2. **MPC node compatibility**: The Rust launcher requires an MPC node image built from commit `9515e18b` or later (includes TOML `[tee]` config support from PR #2499). Earlier images (e.g., `3.7.0` from Docker Hub) don't write `image-digest.bin` and can't be upgraded via the stop/update/start flow.

3. **Vote timing**: After voting for a new hash, the script needs to wait ~5s for chain finalization before checking the approved list.

4. **reqwest TLS**: The launcher Docker image must include `ca-certificates` for reqwest 0.13's `rustls-platform-verifier` to work. Without it, the launcher panics with "No CA certificates were loaded from the system".

5. **Docker Compose v2**: The launcher uses `docker compose up -d` (v2 CLI plugin), not the old `docker-compose` (v1). The Dockerfile must install the Compose v2 binary at `/usr/local/lib/docker/cli-plugins/docker-compose`.
