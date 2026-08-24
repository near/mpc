# TDX platform TCB status

Whether a TDX host is up-to-date enough for the MPC contract to keep accepting its
attestation, and what to do when it is not.

```bash
cargo install --path crates/attestation-cli   # from the repository root
attestation-cli tcb-status --url http://<node-host>:8080/public_data
```

Flags and exit codes:
[`tcb-status`](../crates/attestation-cli/README.md#tcb-status) in the
attestation-cli README.

`/public_data` is served by the mpc-node inside the CVM, so the check needs a
running CVM. It does not need a synced one: the payload is a snapshot built at
startup and served before the node waits for the indexer to catch up, so it
answers as soon as the CVM is up, whether or not the node is in sync with the
chain or currently accepted by the contract.

## Why an attestation that worked yesterday can fail today

`UpToDate` is not a property of your quote. It is your platform's security
version numbers (SVNs) judged against Intel's TCB info, and Intel revises that
TCB info on its own schedule. When it publishes a *TCB recovery*, the bar moves:
platforms that cleared it yesterday stop clearing it today, with nothing changed
on your side.

What follows is silent:

1. Your node keeps submitting hourly, and the contract rejects every submission.
2. The stored attestation expires 7 days after the last accepted one
   (`DEFAULT_EXPIRATION_DURATION_SECONDS`).
3. `verify_tee` then drops your node from the participant set and reshares
   without it. If this happens for several nodes then it becomes a network problem.

## Symptoms

The node logs the reason once per attempt:

```text
WARN periodic_attestation_submission: mpc_node::tee::remote_attestation:
  Attestation is not valid: TCB status `OutOfDate` is not up to date
```

On chain, `expiry_timestamp_seconds` on your stored attestation stops advancing.
A healthy node's is always about 7 days out and moves forward every hour, which
makes it the cheapest health signal available:

```bash
near contract call-function as-read-only \
  v1.signer-prod.testnet get_attestation \
  json-args '{"tls_public_key":"ed25519:<your-tls-key>"}' \
  network-config testnet now
```

A demotion can also stop the CVM from booting at all, because
`gramine-sealing-key-provider` verifies a quote before releasing the disk
sealing key. See
[`gramine-sealing-key-provider` failures](./running-an-mpc-node-in-tdx-external-guide.md#quote-verification-fails--dcap-error--failed-to-get-sealing-key).

## Reading `tcb-status`

`attestation-cli tcb-status` reads a node's `/public_data` and runs the
contract's own DCAP verification twice: against the collateral the node served,
and against collateral fetched from Intel just now. Its output for a demoted
platform, which is what Intel's promotion of set 19 to set 20 on 2026-08-13
looked like:

```text
=== MPC Node Platform TCB Status ===

--- Platform, as the quote reports it ---
FMSPC:                  90C06F000000
tee_tcb_svn:            06010300000000000000000000000000
TDX module:             TDX_01 at ISV SVN 6
TDX TCB components:     [6, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
SGX TCB components:     [3, 3, 2, 2, 4, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0]
PCESVN:                 13

--- served by the node: TCB recovery set 19, issued 2026-08-10T23:45:04Z ---
Status:                 UpToDate

--- Intel `standard`: TCB recovery set 20, issued 2026-08-24T11:12:32Z ---
Status:                 OutOfDate
Advisory IDs:           INTEL-SA-01192, INTEL-SA-01245, INTEL-SA-01312, INTEL-SA-01313
  TDX module TDX_01 ISV SVN is 6, needs 11 -> update the TDX module (SEAM loader)
  TDX TCB component 2 is 3, needs 4 -> update BIOS/microcode
  SGX TCB component 0 is 3, needs 4 -> update BIOS/microcode
  SGX TCB component 1 is 3, needs 4 -> update BIOS/microcode
```

What to act on:

- The **served by the node** row lags, because `/public_data` hands out the
  attestation built at CVM boot while the node re-fetches collateral and
  resubmits hourly. A stale `UpToDate` here says the published snapshot is old,
  not that the node is submitting stale attestations.
- The **Intel `standard`** row is what the contract effectively decides at the
  next submission, and what the exit code follows.
- The **shortfall lines** name every SVN that is short and the update that
  raises it. Current microcode does not imply a current TDX module, and a module
  update does not fix an old BIOS, so expect to need whichever the lines name.

A healthy platform prints the same shape with `UpToDate` on both rows and no
shortfall lines. For the anatomy of each row, and what a `Rejected` row means,
see [`tcb-status`](../crates/attestation-cli/README.md#tcb-status) in the
attestation-cli README.

## When you are out of date

### 1. Protect your key share first

**A microcode update can make the CVM's encrypted disk unreadable.** The disk key
derives from the SGX sealing key, which `EGETKEY` derives from CPUSVN among other
inputs. A TCB recovery fix moves CPUSVN, so the existing disk no longer unseals,
and key shares, triples, presignatures and the P2P identity key all live on it.

So before touching firmware: take a fresh backup with the `backup-cli`
following
[Backup Keyshares from Old Node](./node-migration-guide.md#step-4-backup-keyshares-from-old-node),
and be ready to redeploy the CVM and restore from backup per the
[node migration guide](./node-migration-guide.md).

### 2. Record what the host has now

None of these numbers is what Intel compares against, and there is no published
mapping from a BIOS or module version to an SVN, so they are only useful as
before/after evidence. Take them before you touch any firmware:

```bash
sudo dmesg | grep -i "tdx module"
grep -m1 microcode /proc/cpuinfo
sudo dmidecode -s bios-version
```

### 3. Apply the update the shortfall lines call for

| Shortfall | What you need |
|---|---|
| TDX module ISV SVN | a newer Intel TDX module. Vendors ship it inside a BIOS/firmware package, so a vendor BIOS update is the reliable path; an `intel-microcode` package update does *not* move it |
| TDX components, SGX components, PCESVN | newer BIOS and CPU microcode from your server vendor |
| both | usually a single vendor BIOS update, since it bundles microcode and the TDX module. Verify afterwards rather than assuming |

Use the `INTEL-SA-*` advisories from the output to confirm a candidate BIOS
release actually carries the fixes.

### 4. Reboot, then confirm

**Reboot the host.** TCB SVNs are latched at platform reset, so nothing takes
effect without one. Start the CVM again too, since `/public_data` serves the
quote generated at CVM boot. `tcb-status` answers as soon as the node is up,
with no need to wait for it to sync. Then:

- `tcb-status` must read `UpToDate` on the Intel row, and `tee_tcb_svn` must
  differ from before, which is what confirms the platform moved and not just the
  collateral. Re-running the step 2 commands says whether the firmware itself
  changed.
- Within the hour, `get_attestation` should show `expiry_timestamp_seconds` about
  7 days out, meaning the contract accepted a submission.

If collateral fetches start failing instead, your PCCS may not have a PCK
certificate for the platform's new TCB level yet. See
[Self-hosting a local PCCS](./running-an-mpc-node-in-tdx-external-guide.md#appendix-self-hosting-a-local-pccs).

## What this check does not cover

`tcb-status` answers the TCB question only. `UpToDate` means the TCB bar is
cleared, not that the attestation as a whole is acceptable: the contract also
requires the RTMR3 event log to replay, the app compose to match, and the boot
measurements, MPC image hash and launcher compose hash to be in its allow-lists,
which expire on a clock of their own. Use
[`attestation-cli verify`](../crates/attestation-cli/README.md) for those, and
[`submit_participant_info` failures](./running-an-mpc-node-in-tdx-external-guide.md#submit_participant_info-failures)
for how those rejections present.
