# TDX-enabled CI runner

**Status:** Research — options and open questions, no decision yet
**Issue:** [#944](https://github.com/near/mpc/issues/944)
**Related:** [Securing MPC with TEE](../securing-mpc-with-tee-design-doc.md), [TEE lifecycle](../tee-lifecycle.md), [TDX platform TCB status](../tdx-tcb-status.md), [TEE localnet](../localnet/tee-localnet.md), [E2E test infra](../../crates/e2e-tests/README.md)

## TL;DR

No CI job runs on TDX hardware, and none ever computes an attestation verdict against
live collateral. Real-TDX runs happen only when someone hand-drives the deploy scripts
on `alice`.

Three separable pieces of work, cheapest first:

| | What | Hardware | Rough cost |
|---|---|---|---|
| **B0** | Assert a TCB *verdict* against live collateral, not just that collateral parses | None | Hours |
| **B1** | One CVM: generate a fresh quote, verify it with the existing Rust path | 1 CVM | Days |
| **B2** | N CVMs: real signing, resharing, upgrade, migration | 2+ CVMs | Weeks |

Only B2 is what #944 literally asks for. B0 and B1 cover most of the risk that has
actually bitten us, and B1 is what proves the runner infrastructure.

Suggested runner: a **dedicated bare-metal TDX box**, with `alice` as the bootstrap
host while workflows are built. Hard capacity constraint either way: **every CVM costs
8 vCPU and 64 GB RAM**, because those values are measured into RTMR0.

## What CI covers today

| Job | TEE relevance |
|---|---|
| `mpc-e2e-tests` | Real `neard` + real `mpc-node` processes, **mock attestation** |
| `docker-tee-build` | Builds the `-tee` node image; only checks it *starts* |
| `docker-rust-launcher-build-and-verify` | Builds the launcher; runtime check is explicitly **non-TEE** |
| `mpc-unittests` | Verifies the **committed fixture** quote at a frozen timestamp |
| `external-services-tests` | Live PCCS + live Intel PCS calls — see below |

All runners are ephemeral and WarpBuild-hosted. None has TDX.

### The collateral checks that already exist

Two external-services tests already reach live infrastructure:

- `test_fetch_collateral_from_pccs` (`crates/tee-authority/src/tee_authority.rs:1344`)
  fetches collateral for the fixture quote from the real PCCS and asserts each field is
  non-empty.
- `fetch_from_intel__should_serve_an_early_set_ahead_of_the_standard_one`
  (`crates/attestation-cli/src/tcb_status.rs:639`) asserts Intel's early TCB evaluation
  data set is ahead of the standard one — i.e. that the `update` parameter still works.

Neither asserts a **verdict**. `fetch_collateral_from` does run
`check_collateral_freshness(…, now_utc())`, but `MAX_COLLATERAL_AGE` is 31 days,
deliberately outside Intel's own 30-day `nextUpdate`: `dcap-qvl` already rejects
anything past `nextUpdate`, so the check can no longer fire. The fix to the 2026-07-23
stale-PCK-CRL incident disabled it rather than retuning it, pending a permanent policy
([#3946](https://github.com/near/mpc/issues/3946)).

So the gap is precise: **no CI job verifies a quote against live collateral at `now`.**
Every verification test passes a frozen timestamp — `VALID_ATTESTATION_TIMESTAMP` or `0`
(`crates/mpc-attestation/tests/test_attestation_verification.rs`). That call is the one
that validates `nextUpdate` on TCB Info, QE Identity and both CRLs *and* produces the TCB
status, so it is what would surface a TCB-R promotion or a revoked PCK cert.

The machinery to close this already landed: `attestation-cli`'s `tcb-status` verifies at
`SystemTime::now()` and reports served / standard / early verdicts plus shortfalls
against the next TCB set. CI just doesn't assert on it.

### The fixture treadmill

`VALID_ATTESTATION_TIMESTAMP` is `1_786_622_400` — 2026-08-13, the day Intel promoted
TCB-R 20 ([#4169](https://github.com/near/mpc/issues/4169)). Fixtures are currently
fresh, but only because someone regenerated them by hand after that event.

Regeneration is a manual CVM deploy plus a multi-step copy procedure
(`crates/test-utils/assets/README.md`), run **twice** — once for a dev image, once for a
release image — because `default_measurements()` compiles in both
(`crates/mpc-attestation/assets/tcb_info{,_dev}.json`). Those defaults seed the
contract's accepted measurements on deploy/migrate, so when they drift from the deployed
dstack OS image, nodes are rejected until operators vote. Nothing detects that drift.

## Constraints

1. **`near/mpc` is public.** A self-hosted runner must be structurally unreachable from
   fork PRs. `alice` also hosts live testnet CVMs, so a compromised job is an incident.

2. **CVM size is measured — CI CVMs cannot be made cheap.**
   `deployment/cvm-deployment/deploy-launcher.sh:134-136` marks `VCPU=8` / `MEMORY=64G`
   as *"Do not change — those are measured and reflected in the attestation."* RTMR0
   covers VM configuration, and `Measurements`
   (`crates/attestation-types/src/measurements.rs:19`) compares `mrtd`, `rtmr0`, `rtmr1`,
   `rtmr2`. The fixtures confirm it: dev and release are byte-identical through `rtmr1`
   and diverge only at `rtmr2`. The only escape is voting bespoke measurements into the
   CI contract, which forfeits the "our defaults match reality" assertion.

3. **A PR-built launcher cannot be tested in a CVM.**
   `crates/contract/assets/launcher_docker_compose.yaml.template` hardcodes
   `nearone/mpc-launcher@sha256:{{LAUNCHER_IMAGE_HASH}}`, and `proposal.rs:510` derives
   the allowed compose hash by filling that template — so the launcher must come from
   Docker Hub under that exact name.

4. **A PR-built node image *can* be.** `image_reference` lives in the launcher's
   `user_config`, which is not measured — attestation covers report data, RTMR3 events,
   and `sha256(app_compose.docker_compose_file)`
   (`crates/mpc-attestation/src/attestation.rs:482`). `validate_image_reference`
   (`crates/tee-launcher/src/config.rs:65`) accepts `registry.example.com:5000/…`, so a
   host-local registry at the QEMU slirp gateway `10.0.2.2:5000` serves PR builds.

5. **PCCS is a live dependency** on every attestation, and a known rate-limit and
   flakiness source. A caching proxy on the CI host is near-prerequisite.

6. **The dstack install is hand-rolled** — on `alice` it lives under an engineer's home
   directory, started by hand in `tmux`. CI needs it pinned and service-managed.

### Capacity

`alice`: 32 threads, 503 GB RAM, 21 TB disk, TDX enabled, 14 static public IPs. At the
time of writing 446 GB RAM was already committed and two CVMs were running.

At 8 vCPU / 64 GB each: a 2-node cluster costs 128 GB and 16 vCPU; 3 nodes cost 192 GB
and 24 vCPU against 32 threads shared with the host, `neard` and the runner. **~5 CVMs
is the ceiling**, and only on a dedicated box.

## Options

### Runner topology

| | Isolation (public repo) | Contention | Effort | Cost |
|---|---|---|---|---|
| **A1** Ephemeral self-hosted runner on `alice` | Weak — workflow code runs on the TDX host | High | Low | None |
| **A2** Runner in a non-TDX guest VM on `alice` | Good — needs a VM escape | High | Medium | None |
| **A3** Cloud runner + fixed remote executor on `alice` | Strongest — only reviewed scripts run there | High | Med/High | None |
| **A4** Dedicated bare-metal TDX box | Good — nothing valuable co-resident | None | Low | Recurring |

Nested TDX does not exist, so hosted confidential VMs (Azure DCesv5, GCP c3 TDX) cannot
run dstack CVMs. Any option needs bare metal with TDX in BIOS.

**Leaning A4, bootstrapped on A2.** A1 on a public repo, alongside live testnet CVMs, is
the one option worth ruling out. Regardless of choice: `--ephemeral` runners, dedicated
unprivileged user, runner group scoped to named workflows, no fork `pull_request`
trigger, and `concurrency: 1` (the VMM, IP pool and host ports are singletons).

### Vehicle for B2

| | Reuse | Assertions live in | Risk |
|---|---|---|---|
| **C1** CVM backend behind `MpcNodeSetup::start()` | High — existing tests run unchanged | Rust, shared with non-TEE suite | Touches the harness everything depends on |
| **C2** Wrap the `mpc-private` bash | Highest short-term | Bash, in a private repo | Permanent divergence |
| **C3** New thin Rust driver over `dstack-vmm` | Medium — reuses `NearBlockchain` | Rust, separate suite | Duplication |

C1 is the shape the harness invites. The TEE boundary is two lines —
`crates/e2e-tests/src/mpc_node.rs:436` writes `TeeAuthorityConfig::Local`, and
`crates/e2e-tests/src/cluster.rs:1383` submits `Attestation::Mock(MockAttestation::Valid)`
on each node's behalf. `MpcNodeSetup` already writes a `StartConfig` TOML, which is
exactly the `[mpc_node_config]` table the launcher's `user_config` expects, and
`wait_for_participant_attestations` (`cluster.rs:657`) already exists for the inverted
flow where nodes submit their own attestations.

## Suggested sequence

- **Phase 0 — B0.** Assert a verdict in the job that already fetches the collateral,
  reusing `attestation-cli`'s `evaluate()`. Coordinate with the freshness-policy work
  ([#3946](https://github.com/near/mpc/issues/3946)).
- **Phase 1 — host prep.** Service-managed dstack with a pinned guest image; local
  registry; caching PCCS proxy; a teardown reaper (an orphan CVM leaks 64 GB); IP/port
  allocation that cannot collide with anything else on the box.
- **Phase 2 — B1 on the self-hosted runner.** `workflow_dispatch` first, then nightly.
  Proves the runner topology and CVM lifecycle on the cheapest useful job, and can
  auto-open a PR when fixtures drift.
- **Phase 3 — B2.** Vehicle chosen by spike. 2 nodes. Nightly at most.

Triggers: nightly plus `workflow_dispatch` for anything CVM-bound, with the Slack
failure notification `nightly_build.yml` already uses. `push: main` — what #944 asks for
— becomes reasonable once Phase 2 shows stable runtime and reliable teardown; before
that it serialises merges behind a slow job. Per-PR TDX signal is out of scope for a
public repo.

## Discussion points

1. **Dedicated box — budget and timeline?** Decides whether Phase 2 lands on `alice`
   behind `workflow_dispatch` or waits. If it stays on `alice`, is the box dedicated?
   446 of 503 GB were committed at the time of writing; CI cannot share that.
2. **Is B0 + B1 enough?** They cover the failure modes that have caused incidents. B2
   costs weeks and a permanent CVM budget. Do we want it now, or a placeholder?
3. **Smaller CVMs for B2 by voting bespoke measurements into the CI contract?** Roughly
   doubles cluster size, forfeits the measurement-drift assertion. B1 keeps that
   assertion regardless, which may make the trade fine.
4. **Do we need PR-built *launcher* images tested in a CVM?** If yes, constraint 3 forces
   either a Docker Hub publish for CI builds or a change to compose-hash derivation.
5. **What is the actual wall clock?** Unmeasured. Needs a spike: image build + registry
   push, CVM boot, launcher pull, node start, localnet keygen. Phase 2's trigger policy
   depends on it.
6. **C1 vs C3** — resolve by spiking the CVM backend against one existing test.
7. **Dev image, release image, or both?** The contract ships both measurement sets, with
   [#1433](https://github.com/near/mpc/issues/1433) tracking removal of dev measurements
   from production builds.
8. **Where do the cluster scripts live?** `tools/tee-cluster` sits in `mpc-private`
   specifically to avoid full mpc-repo review. Anything CI depends on should move back
   here, or CI needs cross-repo checkout.
