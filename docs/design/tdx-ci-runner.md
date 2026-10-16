# TDX-enabled CI runner

**Status:** Design — agreed shape, not yet implemented
**Issue:** [#944](https://github.com/near/mpc/issues/944)
**Related:** [Securing MPC with TEE](./securing-mpc-with-tee/securing-mpc-with-tee.md), [TEE lifecycle](./tee-lifecycle.md), [TDX platform TCB status](../guide/tdx-tcb-status.md), [TEE localnet](../development/localnet/tee-localnet.md), [E2E test infra](../../crates/e2e-tests/README.md)

## TL;DR

No CI job runs on TDX hardware today, and none verifies an attestation against live
collateral. Real-TDX runs happen only when someone hand-drives the deploy scripts.

The agreed design: a **nightly GitHub-hosted job SSHes into a dedicated TDX host (Eva)**,
triggers the existing bash scripts against a freshly published node/launcher image,
and collects a results file. No self-hosted runner, no new test framework — the first
version reuses what already exists.

Deliberately staged:

| Stage | Scope | Status |
|---|---|---|
| **1. Host provisioning** | Bring a box to a clean OS + TDX + dstack state | Out of scope — manual for now |
| **2. Scripts emit results** | Existing bash writes a machine-readable results file | Small change to `tools/tee-cluster` |
| **3. CI job** | Nightly: resolve image → SSH → run → collect | The work this doc covers |
| **4. Image publishing** | Node + launcher images pushed on merge to `main` | Already exists |
| **5. Rust test infrastructure** | Replace bash with the e2e harness | Future work |

## Architecture

```
GitHub Actions (hosted runner, nightly)
  │  1. resolve main HEAD → image tag → manifest digests
  │  2. ssh ubuntu@<eva>  (key from repo secret)
  ▼
Eva (dedicated TDX host)
  │  deploy-tee-cluster.sh  → localnet + 3 CVMs
  │  test-*.sh              → assertions, write results file
  ▼
GitHub Actions
     3. fetch results + logs → publish (checks / artifact / Slack)
```

The cluster scripts — `deploy-tee-cluster.sh` and the `test-*.sh` scenarios — live in
`tools/tee-cluster` in `mpc-private`, already checked out on the host.

Each run starts a localnet blockchain and CVMs from scratch, and destroys them at the end.
No state is carried between runs, so a run can never pass because of something a previous
one left behind.

Nothing but reviewed scripts runs on Eva, and the runner stays ephemeral and GitHub-hosted.
The workflow can live in the public `near/mpc` repo: neither `schedule` nor
`workflow_dispatch` can be triggered from a fork. A collaborator can still dispatch any
branch, including an unmerged edit of the workflow itself, so the SSH key belongs in an
`environment` secret with the deployment branch restricted to `main` — the pattern
`docker_build_node.yml` already uses. Infra-ops is equally viable, and an SRE call.

### Host: Eva

A server dedicated to CI, running the same setup we use for our testnet and mainnet hosts,
so CVMs on it produce measurements matching production.

### Image selection

Two workflows publish on every push to `main`, both calling `deployment/build-images.sh`:

| Workflow | Image |
|---|---|
| `.github/workflows/docker_build_node.yml` | `nearone/mpc-node` |
| `.github/workflows/docker_build_rust_launcher.yml` | `nearone/mpc-launcher` |

The tag is `<sanitized-branch>-<7-char-sha>` (`build-images.sh:231-241`), so `main-abc1234`
for a merge to `main`. There is no `latest`. The 7 characters are a fixed truncation of the
SHA rather than `git rev-parse --short`, so the job can form the tag from a commit without
asking the registry.

The nightly job therefore takes `main` HEAD, forms `main-${SHA::7}`, resolves that tag to a
manifest digest for each image, and passes both to `deploy-tee-cluster.sh` as
`MPC_MANIFEST_DIGEST` and `LAUNCHER_MANIFEST_DIGEST`. A failure then names the exact commit
under test rather than a 24-hour window.

**The CVM pulls by digest, not by tag.** `deploy-tee-cluster.sh` requires
`MPC_MANIFEST_DIGEST` and `LAUNCHER_MANIFEST_DIGEST` up front; the tag is only how CI
looks them up. The design forces
this — the contract allow-lists a digest via `vote_mpc_node_manifest_digest`, and the
launcher reads the approved one from `/mnt/shared/image-digest.bin`. A tag is a mutable
pointer, and nothing measured can bind to it.

**The contract must be built from the same commit as the image.** `deploy-tee-cluster.sh`
builds it from `$MPC_REPO_ROOT`, so the job must check that out at the resolved SHA rather
than inherit whatever was last left on the host by hand.

**Needs a fallback.** Node and launcher are published by two independent workflows, so HEAD's
tag can be missing or half-present when the job fires. Fall back to the most recent commit
for which *both* tags exist, and report which commit was actually exercised.

### Results

Scripts today print `[PASS]`/`[FAIL]` and keep a `FAILURES` counter, but emit nothing a
machine can read — that is the one script-side change stage 2 needs.

**JUnit XML** is the suggested format: GitHub renders it natively, and `cargo nextest`
supports it, so when stage 5 replaces bash with Rust the CI plumbing is unchanged.
Raw logs ship alongside as an artifact.

### Cadence

Nightly to start, plus `workflow_dispatch`.

Running after every merge to `main` may be possible later. It depends on how long a run
takes, which nobody has measured yet. Runs happen one at a time, so when merges arrive
faster than runs finish, the `concurrency` group skips the commits in between.

**Restriction: we have one dedicated server, and it can run at most six nodes at once.** A
cluster takes three, so a single run occupies the host. The workflow needs a `concurrency`
group with `cancel-in-progress: false` — cancelling mid-run skips the teardown and leaves
CVMs running. More parallelism means another server, not another job.

## What the run covers

To start, exactly what the scripts do today:

| Script | What it does |
|---|---|
| `deploy-tee-cluster.sh` | Brings up a localnet and a 3-node TEE cluster from scratch. |
| `test-verify-and-upgrade.sh verify` | Contract is `Running`, TEE accounts registered, attestations are real Dstack and not Mock, allowed image hashes match, an ECDSA signature succeeds. |
| `test-verify-and-upgrade.sh upgrade` | Rolling upgrade to a new manifest digest, verifying the cluster before and after. |
| `test-hash-override.sh override` | A node launched with an approved override hash attests and signs. |
| `test-hash-override.sh override-reject` | A node launched with an unapproved hash is rejected. |
| `test-migration.sh` | A full `backup-cli` migration: keyshares out of one node, into a replacement, and back. |

Even this much is the first CI signal for parts no current job touches: real quote
generation, DCAP verification against live collateral, the launcher's RTMR3 extension,
compose-hash derivation from a real `app_compose`, and the contract's TEE gate against a
real quote.

Later the run can be extended, but only with TEE-specific flows the Rust e2e tests cannot
reach. They already cover resharing (`test_key_resharing`) and `backup-cli` migration
(`migration_service__should_migrate_nodes_via_backup_cli`) with a mock attestation, and
anything they can do is cheaper to test there.

## Constraints

**One server supports about six nodes.** A 6-node TEE network on a single host is stable;
at 10 nodes, triple generation timed out frequently and signing became unreliable, and
dropping to 8 active nodes fixed it (mpc-private, `resources/experiment-log/2026-01-21-testnet-tee-10-notes-with-automation-one-server/`).
Two nodes is the smallest cluster that runs at all, but at 2-of-2 both nodes have to
survive every resharing, so no node can be replaced or rejected. Three is the minimum that
covers those tests, which makes two clusters the ceiling on one server. We run one at a
time.

**The launcher must come from Docker Hub.** The contract derives the allowed compose hash
by filling `crates/contract/assets/launcher_docker_compose.yaml.template`
(`crates/contract/src/tee/proposal.rs:401`), which hardcodes `nearone/mpc-launcher@sha256:…`.
So a PR-built launcher cannot run in a CVM — harmless for a nightly job on published images.

## The gap this design does *not* close

The nightly run does verify a real quote against live collateral: the localnet deploys the
real `tee-verifier` contract, which calls `dcap_qvl::verify::verify` at the current block
time. But it covers only Eva's platform, once a night, and only when the whole cluster
comes up. The rest of the fleet runs different firmware — which is what went wrong when
Intel promoted TCB-R 20 on 2026-08-13.

A cheap check in the normal CI job would catch collateral problems in minutes without
hardware. Tracked in [#4717](https://github.com/near/mpc/issues/4717).

## Future work

- **Automate host setup.** Bringing a box to a clean OS with TDX and dstack is manual
  today (stage 1). A provisioning workflow would make a replacement or a second host
  reproducible instead of a day's work.
- **Replace the bash with real test infrastructure.** The scripts were written to be
  driven by hand, and they assert by printing. Moving the scenarios to the Rust e2e
  harness (stage 5) gets proper assertions, failure messages and reporting. Keeping JUnit
  as the results format from stage 2 means that swap touches no CI wiring.

## Open questions

1. **How long does a full run take?** Nobody has measured it.
2. **Where does the workflow live** — `near/mpc` or infra-ops — and where is the SSH key
   kept? SRE call.
3. **How do failures get reported?** GitHub check annotations, an artifact, Slack, or all
   three.
