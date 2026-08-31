# TDX platform TCB status

Intel raises the TCB bar on its own schedule, and a platform below it has its
attestation rejected until the host's firmware is updated. This is what to do
when your host is the one that fell behind; in the appendix you can find more
details about why it happens and how it shows up.

```bash
cargo install --path crates/attestation-cli   # from the repository root
attestation-cli tcb-status --url http://<node-host>:8080/public_data
```

Flags: [`tcb-status`](../crates/attestation-cli/README.md#tcb-status) in the
attestation-cli README.

## When you are about to be out of date

A demoted `Intel early` row under an `UpToDate` `Intel standard` row is this same
problem before it lands: Intel has published the evaluation data set your
platform fails and has not yet promoted it. Nothing is rejected and the command
still exits 0, but everything below applies, and Intel announces no promotion
dates, so treat the row as the notice.

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

The shortfall lines are the `is N, needs M` lines `tcb-status` prints under a
demoted status:

| Shortfall | What you need |
|---|---|
| TDX module ISV SVN | a newer Intel TDX module. Vendors ship it inside a BIOS/firmware package, so a vendor BIOS update is the reliable path; an `intel-microcode` package update does *not* move it |
| TDX components, SGX components, PCESVN | newer BIOS and CPU microcode from your server vendor |
| both | usually a single vendor BIOS update, since it bundles microcode and the TDX module. Verify afterwards rather than assuming |

Use the `INTEL-SA-*` advisories from the `tcb-status` output to confirm a
candidate BIOS release actually carries the fixes.

### 4. Reboot, then confirm

**Reboot the host.** TCB SVNs are latched at platform reset, so nothing takes
effect without one. Whether the CVM then starts on its existing disk depends on
the update: if it moved CPUSVN, the sealing key moved with it and that disk will
never unseal again, so deploy a fresh CVM and restore the step 1 backup into it
per the [node migration guide](./node-migration-guide.md). Either way a CVM has
to be running before you can check anything, since `/public_data` serves the
quote generated at CVM boot, and `tcb-status` answers as soon as the node is up,
with no need to wait for it to sync. Then:

- `tcb-status` must read `UpToDate` on the `Intel standard` row, the verdict
  against collateral it fetches from Intel as it runs, and `tee_tcb_svn` must
  differ from before, which is what confirms the platform moved and not just the
  collateral. Re-running the step 2 commands says whether the firmware itself
  changed. Check the `Intel early` row while you are there, or re-run with
  `--evaluation-data-set early` for a plain pass or fail: an update that clears
  only the current set leaves you doing this again at the next promotion.
- Within the hour, `get_attestation` should show `expiry_timestamp_seconds` about
  7 days out, meaning the contract accepted a submission.

If collateral fetches start failing instead, your PCCS may not have a PCK
certificate for the platform's new TCB level yet. The node then starts with no
attestation at all and keeps retrying, so `tcb-status` reports that the node is
not running in a TEE rather than naming a TCB problem. See
[Self-hosting a local PCCS](./running-an-mpc-node-in-tdx-external-guide.md#appendix-self-hosting-a-local-pccs),
and restart the CVM once the PCCS can serve the new level.

## Appendix

### Why an attestation that worked yesterday can fail today

`UpToDate` is not a property of your quote. It is your platform's security
version numbers (SVNs) judged against Intel's TCB info, and Intel revises that
TCB info on its own schedule: when it publishes a *TCB recovery*, platforms that
cleared the bar yesterday stop clearing it today, with nothing changed on your
side.

Nothing reaches out to warn you: the `Intel early` row is the advance notice,
and only when someone runs the check. Once the promotion lands, the node logs
the rejection every attempt (see [Symptoms](#symptoms)) and keeps submitting
hourly, the contract rejects every submission, the stored attestation expires 7
days after the last accepted one (`DEFAULT_EXPIRATION_DURATION_SECONDS`), and
`verify_tee` then drops the node from the participant set and reshares without
it. For several nodes at once, it becomes a network problem rather than only
yours.

### Symptoms

The node logs the reason once per attempt:

```text
WARN periodic_attestation_submission: mpc_node::tee::remote_attestation:
  Attestation is not valid: TCB status `OutOfDate` is not up to date
```

On chain, `expiry_timestamp_seconds` on the stored attestation stops advancing.
A healthy node's is always about 7 days out and moves forward every hour, which
makes it the cheapest health signal available:

```bash
near contract call-function as-read-only \
  v1.signer-prod.testnet get_attestation \
  json-args '{"tls_public_key":"ed25519:<your-tls-key>"}' \
  network-config testnet now
```

A platform that has fallen behind can also stop the CVM from booting at all,
because `gramine-sealing-key-provider` verifies a quote before releasing the
disk sealing key. See
[Quote verification fails](./running-an-mpc-node-in-tdx-external-guide.md#quote-verification-fails--dcap-error--failed-to-get-sealing-key).

### What this check does not cover

`tcb-status` answers the TCB question only. `UpToDate` means the TCB bar is
cleared, not that the attestation as a whole is acceptable: the contract also
requires the RTMR3 event log to replay, the app compose to match, and the boot
measurements, MPC image hash and launcher compose hash to be in its allow-lists,
which expire on a clock of their own. Use
[`attestation-cli verify`](../crates/attestation-cli/README.md) for those, and
[`submit_participant_info` failures](./running-an-mpc-node-in-tdx-external-guide.md#submit_participant_info-failures)
for how those rejections present.
