# TDX-enabled CI runner

**Status:** Design — agreed shape, not yet implemented
**Issue:** [#944](https://github.com/near/mpc/issues/944)
**Related:** [Securing MPC with TEE](./securing-mpc-with-tee/securing-mpc-with-tee.md), [TEE lifecycle](./tee-lifecycle.md), [TDX platform TCB status](../guide/tdx-tcb-status.md), [TEE localnet](../development/localnet/tee-localnet.md), [E2E test infra](../../crates/e2e-tests/README.md)

## TL;DR

**The problem.** No CI job runs on TDX hardware today, and none verifies an attestation
against live collateral. Real-TDX runs happen only when someone hand-drives the deploy
scripts.

**The solution.** A nightly job on our existing CI runners SSHes into a dedicated TDX
host, triggers the existing bash scripts against a freshly published node/launcher
image, and collects a results file. No new test framework — the first version reuses what
already exists, and is meant to be replaced once the scenarios move to the Rust harness.
The runner stays off the TDX host on purpose; [Why the runner is not on the TDX
host](#why-the-runner-is-not-on-the-tdx-host) covers the alternatives.

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
GitHub Actions (our existing CI runners, nightly)
  │  1. resolve main HEAD → image tag → manifest digests
  │  2. ssh <ci user>@<tdx host>  (key from an environment secret)
  ▼
TDX host (dedicated to CI)
  │  deploy-tee-cluster.sh  → localnet + 3 CVMs
  │  test-*.sh              → assertions, write results file
  ▼
GitHub Actions
     3. fetch results + logs → publish (checks / artifact / Slack)
```

The cluster scripts — `deploy-tee-cluster.sh` and the `test-*.sh` scenarios — live in
`tools/tee-cluster` in `mpc-private` and are checked out on the host once; they change
rarely and are not tied to the commit under test. The `near/mpc` checkout is tied to it:
the scripts build the contract from that tree, so the job moves it to the commit being
tested (see [Image selection](#image-selection)).

Each run starts a localnet blockchain and CVMs from scratch and destroys them at the end,
so no cluster state carries over. The host itself does — OS, dstack and the checkouts
persist — which is what the golden-state reinstall under [Future work](#future-work)
would fix.

The job runs on the same runners as the rest of CI (`warp-ubuntu-2604-x64-*`), so this
adds no runner infrastructure.

The workflow can live in the public `near/mpc` repo: neither `schedule` nor
`workflow_dispatch` can be triggered from a fork. A collaborator can still dispatch any
branch, including an unmerged edit of the workflow itself, so two things bound what a
dispatch can do:

- The SSH key lives in an `environment` secret whose deployment branches are restricted
  to `main`. The repo already leans on this to stop a release being published off a dev
  branch: `release.yml` and `docker_node_release.yml` are `workflow_dispatch`-only and
  draw their secrets from the `production` environment, so a dispatch from elsewhere
  starts but gets nothing. `production` also allows `release/*`, so the TDX job wants its
  own environment.
- The key is restricted to a **forced command** on the host, so it invokes the test script
  and nothing else:

  ```
  command="/home/<ci user>/run-tdx-ci.sh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...
  ```

  CI therefore holds one remote call on one unprivileged account, not a shell. The account
  still needs the dstack socket, Docker and the signing keychain, so this bounds the blast
  radius rather than removing it.

Infra-ops is equally viable as a home for the workflow, and an SRE call.

### Why the runner is not on the TDX host

A self-hosted Actions runner on the host would be better on its own terms: outbound
polling, no inbound SSH, no long-lived key to steal. The blocker is that **whatever
drives a run has to outlive the machine under test** — we want a job that reinstalls the
host's OS first, and a runner cannot wipe the machine it is running on.

| Option | Shape | Trade-off |
|---|---|---|
| Runner on the TDX host | The host registers an Actions runner and runs the job locally. | Cannot drive an OS reinstall. Also a persistent runner on a public repo, which GitHub advises against — though no fork can trigger `schedule` or `workflow_dispatch`. |
| Golden image ships the runner | An external job triggers the reinstall; the image carries the runner, which registers on boot and then runs the tests. | Probably the right end state. Needs automated provisioning first, a registration token injected at install time, and two workflow runs to correlate. |
| External job + SSH (**chosen**) | The job runs on our existing CI runners and invokes one script over SSH. | Simplest thing that works today, and the control path survives a reinstall. |

The last two are not exclusive: a reinstall has to be driven from off the host either
way, so the only question is whether the tests then run locally.

The reinstall job does not exist yet — host provisioning is stage 1 and manual — so this
choice is partly justified by work we have not done. **If we decide not to automate
reinstalls, the first option wins and we should switch.**

### Host requirements

A server dedicated to CI, running the same setup we use for our testnet and mainnet hosts,
so CVMs on it produce measurements matching production. Which machine that is belongs in
the host inventory in `mpc-private`, not here.

### Image selection

Two workflows publish on every push to `main`, both calling `deployment/build-images.sh`:

| Workflow | Image |
|---|---|
| `.github/workflows/docker_build_node.yml` | `nearone/mpc-node` |
| `.github/workflows/docker_build_rust_launcher.yml` | `nearone/mpc-launcher` |

The tag is `<sanitized-branch>-<7-char-sha>` (`build-images.sh:231-241`), so `main-abc1234`
for a merge to `main`. There is no `latest`.

**Everything in a run pins to one commit.** The job takes `main` HEAD, forms
`main-${SHA::7}`, resolves both tags to manifest digests, and passes them to
`deploy-tee-cluster.sh` as `MPC_MANIFEST_DIGEST` and `LAUNCHER_MANIFEST_DIGEST`, together
with the CI contract's account id as `MPC_CONTRACT_ID`. The CVM
pulls by digest and never by tag: the contract allow-lists a digest via
`vote_mpc_node_manifest_digest` and the launcher reads the approved one from
`/mnt/shared/image-digest.bin`, and nothing measured can bind to a mutable pointer. The
`near/mpc` checkout moves to the same SHA, since the scripts build the contract from it.
A failure then names one commit rather than a 24-hour window.

Both images are public, so the job needs no registry credentials — the SSH key is the
only secret it holds.

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

**Goal: the flows that need real TDX hardware, and nothing else.** Anything a mock
attestation can reach belongs in the Rust e2e tests, where it is faster and cheaper to
run. What only a real machine exercises:

| Component | Flow |
|---|---|
| **Node** | Asking dstack for a real TDX quote over `/var/run/dstack.sock`, with the NEAR account and P2P TLS keys bound into `report_data`, and submitting it via `submit_participant_info`. |
| **Launcher** | Extending RTMR3 with the manifest digest, deriving the compose hash from a real `app_compose`, and launching the node image by the digest the node wrote to `/mnt/shared/image-digest.bin`. |
| **Contract** | The TEE gate on participants, and the `tee-verifier` contract running `verify_quote` — a real DCAP verification against collateral fetched live, inside the gas budget. |

To start, the run does exactly what the scripts do today:

| Script | What it does |
|---|---|
| `deploy-tee-cluster.sh` | Brings up a localnet and a 3-node TEE cluster from scratch. |
| `test-verify-and-upgrade.sh verify` | Contract is `Running`, TEE accounts registered, attestations are real Dstack and not Mock, allowed image hashes match, an ECDSA signature succeeds. |
| `test-verify-and-upgrade.sh upgrade` | Rolling upgrade to a new manifest digest, verifying the cluster before and after. |
| `test-hash-override.sh override` | A node launched with an approved override hash attests and signs. |
| `test-hash-override.sh override-reject` | A node launched with an unapproved hash is rejected. |
| `test-migration.sh` | A full `backup-cli` migration: keyshares out of one node, into a replacement, and back. |

That already covers every row above, and none of it has CI signal today.

Later the run can be extended, but only against that goal. The Rust e2e tests already
cover resharing (`test_key_resharing`) and `backup-cli` migration
(`migration_service__should_migrate_nodes_via_backup_cli`) with a mock attestation, so
repeating them here buys nothing but runtime on a machine we only have one of.

## Constraints

**One server supports about six nodes, and we run one cluster at a time.** A 6-node TEE
network on a single host is stable; at 10, triple generation timed out frequently and
signing became unreliable (mpc-private, `resources/experiment-log/2026-01-21-testnet-tee-10-notes-with-automation-one-server/`).
A cluster needs three nodes: two would run, but at 2-of-2 no node can be replaced or
rejected, which is exactly what the upgrade and migration tests do.

**The launcher must come from Docker Hub.** The contract derives the allowed compose hash
by filling `crates/contract/assets/launcher_docker_compose.yaml.template` with the image
digests and its own account id, and the template hardcodes `nearone/mpc-launcher@sha256:…`.
So a PR-built launcher cannot run in a CVM — harmless for a nightly job on published images.

## The gap this design does *not* close

The nightly run does verify a real quote against live collateral: the localnet deploys the
real `tee-verifier` contract, which calls `dcap_qvl::verify::verify` at the current block
time. But it covers one host's platform, once a night, and only when the whole cluster
comes up. The rest of the fleet runs different firmware — which is what went wrong when
Intel promoted TCB-R 20 on 2026-08-13.

A cheap check in the normal CI job would catch collateral problems in minutes without
hardware. Tracked in [#4717](https://github.com/near/mpc/issues/4717).

## Future work

- **Automate host setup.** Bringing a box to a clean OS with TDX and dstack is manual
  today (stage 1). A provisioning workflow would make a replacement or a second host
  reproducible instead of a day's work.
- **Reinstall the host to a golden state before a run.** The cluster is rebuilt each run
  but the host is not, so a run inherits whatever the last one left on the box. Reimaging
  first would fix that — and it is the reason the runner stays off the host.
- **Replace the bash with real test infrastructure.** The scripts were written to be
  driven by hand, and they assert by printing. Moving the scenarios to the Rust e2e
  harness (stage 5) gets proper assertions, failure messages and reporting. Keeping JUnit
  as the results format from stage 2 means that swap touches no CI wiring.

## Open questions

1. **How long does a full run take?** Nobody has measured it.
2. **Where does the workflow live** — `near/mpc` or infra-ops — and who holds the SSH
   key? SRE call.
3. **Who can trigger a run, and does a manual one need approval?** `workflow_dispatch` is
   open to anyone with write access, on any branch. A deployment-branch restriction on
   the environment is the proven answer here — it is what keeps a release from being
   published off a dev branch — but it needs a dedicated environment, since `production`
   also allows `release/*`.
   Whether a manual run additionally needs a second pair of eyes is open. Required
   reviewers would gate it, but they would also stall the nightly, which sits in
   `Waiting` until someone approves and fails after 30 days if nobody does — so gating
   both would need two environments chosen by `github.event_name`.
4. **How do failures get reported?** GitHub check annotations, an artifact, Slack, or all
   three.
