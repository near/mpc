# attestation-cli

Standalone verification tool for MPC node TEE attestations. It performs the same Intel TDX (DCAP) attestation verification that the NEAR contract and MPC nodes use, allowing external auditors, operators, and developers to independently validate that an MPC node is running trusted code inside genuine hardware.

Two subcommands: `verify` answers "is this node's attestation acceptable?", and `tcb-status` answers "does this node's platform still clear Intel's TCB bar, and will it clear the next one?".

## Building

From the repository root:

```bash
cargo build -p attestation-cli --release
```

The binary is at `target/release/attestation-cli`.

To install it on your PATH:

```bash
cargo install --path crates/attestation-cli
```

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
  --url http://<node-host>:8080/public_data \
  --allowed-image-hash abc123...def \
  --launcher-compose-file launcher-compose.yaml
```

### Verify from a saved file

First save the node's response:

```bash
curl -o public_data.json http://<node-host>:8080/public_data
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
  --url http://<node-host>:8080/public_data \
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

`tcb-status` has an exit-code rule of its own, described [below](#tcb-status).

## Collateral handling

Attestation verification requires DCAP collateral (certificates, CRLs, TCB info) to validate the Intel TDX quote. The CLI uses the collateral **embedded in the node's attestation payload** (the same collateral that was fetched when the node generated its attestation). This is the same approach used by the MPC contract and node.

`verify` does not currently support fetching fresh collateral from Intel's Provisioning Certification Service (PCS) or overriding CRLs. If the embedded collateral is stale, the verification may fail with a DCAP-related error. See [#2320](https://github.com/near/mpc/issues/2320) and [#2286](https://github.com/near/mpc/issues/2286) for planned improvements. `tcb-status` does fetch fresh collateral, so it is the way to tell a stale snapshot apart from a genuinely rejected platform.

## `tcb-status`

```
attestation-cli tcb-status [OPTIONS]
```

Reports where a node's platform stands against Intel's TCB requirements. The contract accepts an attestation only when DCAP returns `UpToDate`, and that verdict depends on Intel's TCB info, which Intel revises on its own schedule: a node accepted yesterday can be rejected today with nothing changed on the operator's side.

The node's quote is evaluated against three sets, and all three are reported:

| Collateral source | What it tells you |
|-------------------|-------------------|
| served by the node | What the node's own boot-time collateral says. `/public_data` serves the attestation built at CVM boot, so this can lag reality by days. |
| Intel `standard` | What the contract will decide the next time the node re-attests. Omitting the `update` parameter is what selects the `standard` tier, and it is what the node does too. The fetch goes straight to Intel rather than through the node's PCCS, so the two can differ in cache freshness. |
| Intel `early` | What the contract will decide once Intel promotes the set it already publishes under `update=early`. A platform demoted here is still accepted today, which is the point: it is the only advance warning of a TCB recovery. The early set can be more than one ahead of `standard`, so the demotion lands at some upcoming promotion, not necessarily the next. |

All three verdicts come from `dcap-qvl`, the same verification the contract runs. Contacting Intel is anonymous: no PCS subscription key and no node credentials.

The command exits 0 when the deciding Intel row reads `UpToDate`, and 1 otherwise, including when that row's collateral could not be fetched or did not verify.

It takes the same `--url` / `--file` data source as `verify`. Unlike `verify`, network access is always required: `--file` chooses where the quote comes from, not whether Intel is contacted.

`--evaluation-data-set <standard|early>` evaluates only that set, which then decides the exit code. Left out, both are evaluated and `standard` decides, so a demoted `early` row still exits 0: the platform is accepted until Intel promotes.

`--as-of <unix-timestamp>` evaluates collateral validity at a past instant instead of now. Intel serves only current collateral, so this is for reading a saved quote whose boot-time snapshot has since expired. The Intel rows and the exit code stay present-day verdicts, so neither is meaningful with it set.

```bash
attestation-cli tcb-status --url http://<node-host>:8080/public_data
```

```
=== MPC Node Platform TCB Status ===

--- Platform, as the quote reports it ---
FMSPC:                  00A06D080000
tee_tcb_svn:            07030600000000000000000000000000
TDX module:             TDX_03 at ISV SVN 7
TDX TCB components:     [7, 3, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
SGX TCB components:     [4, 4, 2, 2, 4, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
PCESVN:                 13

--- served by the node: TCB recovery set 20, issued 2026-08-27T00:44:44Z ---
Status:                 UpToDate

--- Intel `standard`: TCB recovery set 20, issued 2026-08-28T10:19:36Z ---
Status:                 UpToDate

--- Intel `early`: TCB recovery set 22, issued 2026-08-28T10:15:47Z ---
Status:                 OutOfDate
Advisory IDs:           INTEL-SA-01379, INTEL-SA-01404, INTEL-SA-01428, INTEL-SA-01439, INTEL-SA-01442, INTEL-SA-01419, INTEL-SA-01436
  TDX module TDX_03 ISV SVN is 7, needs 9 -> update the TDX module (SEAM loader)
  TDX TCB component 2 is 6, needs 8 -> update BIOS/microcode
  SGX TCB component 0 is 4, needs 8 -> update BIOS/microcode
  SGX TCB component 1 is 4, needs 8 -> update BIOS/microcode
  SGX TCB component 4 is 4, needs 7 -> update BIOS/microcode

This platform clears TCB recovery set 20 but not set 22, which Intel publishes and has yet to promote.
```

The node above is accepted today and stops being accepted when Intel promotes set 22, with nothing changed on the operator's side. That is the point of the third row: the firmware update its shortfall lines call for takes planning, and the two rows above it only ever report a demotion that has already happened. [What to do about it](../../docs/tdx-tcb-status.md#when-you-are-about-to-be-out-of-date).

For a scheduled check, evaluate the early set alone, so the demotion that has yet to land is what fails the check:

```bash
attestation-cli tcb-status --url http://<node-host>:8080/public_data \
  --evaluation-data-set early
```

A non-zero exit there means the platform will be demoted at some upcoming promotion, not that it is rejected today.

The served row can also lag the `standard` row by days, or by a whole set. The node itself is not stuck when it does: it re-attests every hour with freshly fetched collateral. What is frozen is `/public_data`, which keeps returning the snapshot built at CVM boot. So a stale served row does not mean the node is submitting stale attestations, and the `standard` row is the one that predicts what the next submission will be judged against.

A quote is judged in two independent halves, and either one can demote the platform.

- **TDX module half.** `tee_tcb_svn[0]`, the module's ISV SVN, matched against the identity that `tee_tcb_svn[1]` selects. A newer Intel TDX module (SEAM) raises it, usually shipped inside a vendor BIOS.
- **Platform half.** The rest of `tee_tcb_svn`, plus the PCK certificate's SGX components and PCESVN. BIOS and CPU microcode raise those.

The shortfall lines say which half is short, so you know which update you need.

## Troubleshooting

**"tee_participant_info is null in the response"**
The node's `/public_data` response does not contain attestation data. The node may not be running in a TEE environment.

**"attestation is a Mock — cannot produce verification result"**
The node is using a mock attestation (development/test mode). Only genuine Dstack (TDX) attestations can be verified.

**"MPC image hash ... is not in the allowed list"**
The MPC Docker image running on the node does not match any of the `--allowed-image-hash` values you provided. Verify you are using the correct hashes.

**"launcher compose hash ... is not in the allowed list"**
The SHA256 of the `--launcher-compose-file` you provided does not match the compose file attested by the node. Make sure you are using the exact same launcher compose file.

**"failed to load expected measurements"**
The `--expected-measurements` file could not be read or parsed. Ensure it is valid JSON in the `tcb_info.json` format.

**`tcb-status` reports `Rejected` for "served by the node"**
The collateral in the node's boot-time snapshot has expired. The Intel rows are evaluated against freshly fetched collateral, so their verdicts still stand; restart the CVM to make the served row meaningful again.

**DCAP verification errors (quote validation, certificate chain, etc.)**
These indicate the TDX attestation quote failed cryptographic verification. This could mean the attestation is invalid, expired, or the measurements do not match.
