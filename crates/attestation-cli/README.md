# attestation-cli

Standalone verification tool for MPC node TEE attestations. It performs the same Intel TDX (DCAP) attestation verification that the NEAR contract and MPC nodes use, allowing external auditors, operators, and developers to independently validate that an MPC node is running trusted code inside genuine hardware.

## Building

From the repository root:

```bash
cargo build -p attestation-cli --release
```

The binary is at `target/release/attestation-cli`.

## Prerequisites

Before running verification you need:

1. **Allowed MPC Docker image hash(es)** — SHA256 hex strings identifying trusted MPC node Docker images. These are the same hashes registered in the MPC signer contract. You can query them from the contract:

   ```bash
   near view v1.signer state ''
   ```

   Look for the `allowed_image_hashes` field in the contract state.

2. **Launcher docker-compose YAML file** — The launcher compose file used by the TEE environment. The CLI computes the SHA256 hash internally and compares it against the hash attested by the node.

3. **(Optional) Expected measurements JSON file** — A `tcb_info.json` file containing the expected TDX measurements (MRTD, RTMR0-2, key-provider event digest). If not provided, the CLI uses the compiled-in default measurements (same as the MPC contract and node use).

## Usage

```
attestation-cli verify [OPTIONS]
```

### Required flags

| Flag | Description |
|------|-------------|
| `--allowed-image-hash <HEX>` | Allowed MPC Docker image hash (repeatable for multiple hashes) |
| `--launcher-compose-file <PATH>` | Path to the launcher docker-compose YAML file |

### Data source (one required)

| Flag | Description |
|------|-------------|
| `--url <URL>` | Fetch attestation data live from a node's `/public_data` HTTP endpoint |
| `--file <PATH>` | Read attestation data from a saved JSON file |

### Optional flags

| Flag | Description |
|------|-------------|
| `--expected-measurements <PATH>` | Path to expected TCB measurements JSON file (defaults to compiled-in measurements) |

## Examples

### Verify a live node

```bash
attestation-cli verify \
  --url http://<node-host>:3000/public_data \
  --allowed-image-hash abc123...def \
  --launcher-compose-file launcher-compose.yaml
```

### Verify from a saved file

First save the node's response:

```bash
curl -o public_data.json http://<node-host>:3000/public_data
```

Then verify offline:

```bash
attestation-cli verify \
  --file public_data.json \
  --allowed-image-hash abc123...def \
  --launcher-compose-file launcher-compose.yaml
```

### Multiple allowed image hashes

```bash
attestation-cli verify \
  --url http://<node-host>:3000/public_data \
  --allowed-image-hash abc123...def \
  --allowed-image-hash 789012...345 \
  --launcher-compose-file launcher-compose.yaml
```

### Custom expected measurements

```bash
attestation-cli verify \
  --file public_data.json \
  --allowed-image-hash abc123...def \
  --launcher-compose-file launcher-compose.yaml \
  --expected-measurements tcb_info.json
```

The measurements file uses the same format as `crates/mpc-attestation/assets/tcb_info.json`:

```json
{
  "mrtd": "<96-char hex>",
  "rtmr0": "<96-char hex>",
  "rtmr1": "<96-char hex>",
  "rtmr2": "<96-char hex>",
  "rtmr3": "...",
  "event_log": [
    {
      "imr": 2,
      "event_type": 13,
      "digest": "<96-char hex>",
      "event": "key-provider",
      "event_payload": "..."
    }
  ],
  ...
}
```

The CLI extracts MRTD, RTMR0-2, and the `key-provider` event digest from this file.

## Reading the output

On success:

```
=== MPC Node Attestation Verification ===

TLS Public Key (P2P):   ed25519:<base58-encoded key>
Account Public Key:     ed25519:<base58-encoded key>
Attestation Type:       Dstack (TDX)

--- Extracted Values ---
MPC Image Hash:         <64-char hex>
Launcher Compose Hash:  <64-char hex>
Expiry Timestamp:       2025-07-15 12:00:00 UTC (unix: 1752577200)

Verdict: PASS
```

On failure the output includes the error details and ends with `Verdict: FAIL`.

| Field | Meaning |
|-------|---------|
| TLS Public Key (P2P) | The node's ed25519 key used for P2P TLS connections |
| Account Public Key | The node's ed25519 key used for NEAR account signing |
| Attestation Type | TEE attestation type (Dstack = Intel TDX via Dstack) |
| MPC Image Hash | SHA256 of the MPC Docker image running inside the TEE |
| Launcher Compose Hash | SHA256 of the docker-compose file used by the launcher |
| Expiry Timestamp | Attestation validity window (7 days from verification time) |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Verification passed |
| 1 | Verification failed or input error |

## Troubleshooting

**"tee_participant_info is null in the response"**
The node's `/public_data` response does not contain attestation data. The node may not be running in a TEE environment.

**"attestation is a Mock — cannot verify mock attestations"**
The node is using a mock attestation (development/test mode). Only genuine Dstack (TDX) attestations can be verified.

**"MPC image hash ... is not in the allowed list"**
The MPC Docker image running on the node does not match any of the `--allowed-image-hash` values you provided. Verify you are using the correct hashes.

**"launcher compose hash ... is not in the allowed list"**
The SHA256 of the `--launcher-compose-file` you provided does not match the compose file attested by the node. Make sure you are using the exact same launcher compose file.

**"failed to load expected measurements"**
The `--expected-measurements` file could not be read or parsed. Ensure it is valid JSON in the `tcb_info.json` format.

**DCAP verification errors (quote validation, certificate chain, etc.)**
These indicate the TDX attestation quote failed cryptographic verification. This could mean the attestation is invalid, expired, or the measurements do not match.
