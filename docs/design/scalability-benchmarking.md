# Scalability Benchmarking

**Status:** Draft — for team review
**Issue:** [#3671](https://github.com/near/mpc/issues/3671)
**Related:** [#1833](https://github.com/near/mpc/issues/1833) (test-framework vision), [#1825](https://github.com/near/mpc/issues/1825), [#399](https://github.com/near/mpc/issues/399)

## Context

Two of this year's objectives require benchmarking capabilities we don't yet have:

1. **Avoid performance regressions** — catch a throughput/latency/asset-generation
   regression introduced by a PR before it reaches production.
2. **Scale to 100 nodes** — gain confidence that the network sustains acceptable
   signing performance as the participant set grows toward 100, including during
   and after resharing and with degraded participants.

Today we can spin up clusters and send load (`mpc-devnet`), and nodes export rich
Prometheus metrics, but nothing ties these together: load-test results are printed
to stdout and lost, there is no regression baseline, and no large-N scaling numbers
are recorded anywhere. This document proposes a design to close that gap and seeks
team agreement before implementation.

## Goals

- A repeatable way to measure end-to-end signing **throughput**, **latency**, and
  **success rate** for a cluster of a given size under a given load shape.
- A **regression signal** on `main` that flags performance drops between commits.
- **Scaling curves** (performance vs. participant count). 100 nodes is the
  target, not the starting point: early sweeps stop around 20 and the upper end
  grows as bottlenecks are found and fixed.
- Coverage of the **system conditions** called out in #3671: steady state,
  during/after resharing, several network sizes, some nodes down, and (stretch)
  misbehaving nodes.
- Results stored somewhere they can be **analyzed over time** and **diffed across runs**.

## Non-goals

- A new general test framework. Scalability benchmarking slots into the unified
  test-framework vision of #1833; it does not replace it.
- Component micro-benchmarks. Cryptographic primitive timing already lives in
  `crates/threshold-signatures/benches/` (Criterion) and contract-gas regression in
  `crates/contract/tests/sandbox/participants_gas.rs`. Those stay as-is and are
  complementary to the system-level benchmarking proposed here.
- Production monitoring/alerting. Operator-facing metrics are covered by
  [`docs/design/node-operator-metrics.md`](./node-operator-metrics.md).

## What we already have

| Asset | Location | Relevance |
| --- | --- | --- |
| Cluster lifecycle CLI (`mpc-devnet`) | `crates/devnet/` | Provisions GCP clusters via Terraform (infra-ops), deploys contract + Nomad jobs, does resharing/participant changes. |
| In-cluster localnet chain | `mpc-devnet ... deploy-chain` | Runs a `neard` validator inside the cluster — no testnet sync wait, no shared-RPC rate limits. Purpose-built for this (capacity at large N still needs validation, see harness ceiling). |
| Load generator | `crates/devnet/src/loadtest.rs` | `--qps`, `--duration`, `--parallel-sign-calls-per-domain`, multi-domain. Reports submitted/signed/end-to-end success rates. **stdout only — not persisted, and individual requests are not timed (no latency percentiles).** |
| Load-shape scenarios | `crates/devnet/scripts/loadtest-scenarios.sh` | sustained / high / spike shapes already scripted. |
| Node metrics | `crates/node/src/metrics.rs`, `requests/metrics.rs` | Latency **histograms** (`near_mpc_signature_time_elapsed`, `mpc_signature_request_response_latency_seconds`/`_blocks`, presig/triple/CKD timing), asset gauges, queue sizes, `mpc_num_fail_on_timeout_indexed`. Exposed at `GET /metrics` (port 8080). |
| Metrics scraping helper | `crates/e2e-tests/src/mpc_node.rs::get_metric` | Parses Prometheus text from `/metrics`. Reusable by a harness. |
| E2E harness | `crates/e2e-tests/` | Real `neard` sandbox + real `mpc-node` processes, small N. Good for cheap regression checks, not 100-node scale. |
| CI patterns | `.github/workflows/` | `warp-ubuntu-*` runners; `nightly_build.yml` shows the cron + `act10ns/slack` + `secrets.SLACK_WEBHOOK` failure-notify pattern; `changes.yml` path-filter gating. |

## Key decision: extend `mpc-devnet`, do not build new

The issue asks whether to "brush up Devnet or build something new." Recommendation:
**extend `mpc-devnet`.** It already owns cluster provisioning, the in-cluster
localnet chain (which removes the testnet-sync bottleneck that would otherwise
dominate benchmark turnaround), participant changes/resharing, and a working load
generator. Building a parallel system would duplicate all of that. This also keeps
us aligned with #1833, which wants fewer overlapping frameworks, not more.

The work is therefore additive, not a rewrite:

1. **Persist results.** Add a results-emitter to the load test: write a structured
   JSON summary per run (see schema below) instead of only printing to stdout.
2. **Measure per-request latency in the load generator.** Record submission and
   response timestamps per request and compute exact p50/p95/p99 client-side —
   the node histograms are too coarse for this
   (`mpc_signature_request_response_latency_seconds` uses exponential buckets
   2 s, 3 s, 4.5 s, … — no resolution below 2 s). Note the client-side number is
   end-to-end user latency and includes chain inclusion time in both directions;
   the node histograms are the MPC-only view. Still scrape `/metrics` at run end
   for the internal breakdown (presignature wait, signing time, store levels).
3. **A scenario manifest.** Promote `loadtest-scenarios.sh` to a declarative
   manifest (cluster size, load shape, conditions, duration) so a run is fully
   described by data and is reproducible.

## Benchmark dimensions

A benchmark run is the cross product of **cluster shape × load shape × domain mix
× condition**.

- **Cluster size (participants):** e.g. 4, 8, 16, 20, 32, 64, 100; threshold
  scales with it. Early phases sweep only to ~20.
- **Load shape:** sustained baseline, high steady-state, spike (warm→burst→cool) —
  already in `loadtest-scenarios.sh`; parameterized by QPS, duration, parallel-sign batch.
- **Domain mix:** ECDSA (Secp256k1) is the asset-bound path (each signature
  consumes a presignature, each presignature two triples); EdDSA (Ed25519) is
  comparatively cheap. ECDSA-only is the minimum; mixed domains are closer to
  production. Sign load only at first — CKD and foreign-chain verification are a
  later extension.
- **System condition:**
  - **Steady state** — baseline.
  - **During resharing** — start load, trigger `vote-new-parameters`, measure the
    dip and time-to-recovery while keys are redistributed.
  - **After resharing** — steady state on the new participant set.
  - **Some nodes down** — kill `f` nodes (up to threshold tolerance), measure
    degraded throughput and whether the network keeps signing.
  - **Misbehaving nodes** *(stretch)* — nodes that respond slowly or with garbage.
  - **Injected WAN latency** *(stretch)* — `tc netem` delay between nodes;
    single-zone links are unrealistically fast. Until then, testnet runs are the
    cross-check.

We do not need the full cross product on every run. Define a small **smoke matrix**
for nightly regression (small N, steady + spike) and a larger **scaling matrix**
run on-demand or weekly (the size sweep, plus resharing/nodes-down).

**Pitfall — buffered assets flatter throughput.** A short ECDSA run can be served
entirely from stockpiled presignatures, measuring buffer depth rather than
sustainable rate. Distinguish **burst capacity** (buffer-absorbed spikes) from
**sustained capacity** (the generation-bound rate at store equilibrium): sustained
runs must last long enough for store levels to stabilize, and every run records
store levels at start/end so a draining buffer is visible.

## Metrics / KPIs

Recorded per run, sourced from node `/metrics` plus the load generator:

- **Throughput:** sustained signatures/sec achieved vs. offered QPS.
- **Latency:** request→response p50/p95/p99, measured client-side by the load
  generator; node histograms serve as cross-check and per-node breakdown.
- **Success rate:** end-to-end (already computed by `loadtest.rs`), plus
  `mpc_num_fail_on_timeout_indexed` deltas.
- **Asset generation:** triple/presignature generation time, available-asset
  gauges, and store levels at run start/end — the usual scaling bottleneck as N
  grows.
- **Resharing recovery:** wall-clock from resharing start to throughput recovery.
  Resharing is a strict superset of keygen, so this also covers keygen at scale.
- **Node resources:** per-node CPU, memory, network bandwidth. The P2P mesh is
  O(N²) connections, making bandwidth a likely scaling ceiling.

The scaling objective needs agreed **pass/fail targets** on these KPIs (e.g.
"p95 ≤ X s at Y QPS with 100 participants") — without them, "scales to 100" is
not falsifiable. See open questions.

## Environments (tiered)

- **Primary — in-cluster localnet.** Reproducible, no sync wait, no shared-RPC
  limits. Used for regression gating and scaling curves where we want clean,
  comparable numbers.
- **Secondary — testnet.** Periodic runs against a real cluster on testnet for
  realism (real network latency, real RPC limits). Higher cost and noisier, so used
  for validation rather than per-commit gating.

The same harness and result schema serve both; only the target (`--mpc-network`
localnet cluster vs. `--mpc-contract` on testnet) differs.

**Harness ceiling.** A single validator absorbs every sign and respond
transaction, and one load generator sustains the offered QPS. Measure the
harness's own ceiling (e.g. against a trivial contract) before trusting large-N
numbers, so harness saturation is not mistaken for MPC saturation.

## Results storage (two complementary sinks)

1. **Structured JSON/CSV summary per run — for regression gating.** One record per
   run: commit SHA, timestamp, cluster size, condition, load shape, and the KPIs
   above. Stored as CI artifacts and appended to a results branch/repo so runs are
   diffable over time. Regression gating compares each fresh summary against the
   checked-in baseline (see [Regression detection](#regression-detection)); the
   accumulated history serves trend analysis.

   Proposed schema (sketch):
   ```json
   {
     "commit": "b245cc29", "timestamp": "2026-06-26T00:00:00Z",
     "env": "localnet", "instance_type": "n2d-standard-8",
     "participants": 16, "threshold": 11,
     "condition": "steady_state", "domains": ["Secp256k1"],
     "load": { "qps": 10, "duration_s": 300, "batch": 10 },
     "repetition": 1,
     "throughput_sps": 9.6,
     "latency_s": { "p50": 1.8, "p95": 3.2, "p99": 4.1 },
     "success_rate": 0.998,
     "timeouts": 1,
     "presignatures": { "start": 8192, "end": 5120 },
     "triples": { "start": 32768, "end": 18000 },
     "resharing": { "triggered_at": "2026-06-26T00:02:00Z", "recovery_s": 45.0 }
   }
   ```

   The `resharing` block (present only for resharing conditions) is derived from
   the load generator's throughput-over-time series, which the emitter keeps
   in-memory to compute the dip and time-to-recovery.

2. **Prometheus + Grafana — for live/time-series analysis.** Scrape cluster node
   `/metrics` into a Prometheus instance (hosted in infra-ops) and visualize in
   Grafana for during-run inspection and historical trends. Reuses the existing
   metrics; no node changes required. Dashboards/scrape config live in infra-ops,
   not this repo (consistent with `node-operator-metrics.md`).

The JSON summary is the source of truth for pass/fail gating; Grafana is for humans
investigating *why* a run regressed.

## Automation

- **Manual, on any PR/commit.** An engineer runs the scenario manifest against a
  devnet cluster (localnet or testnet) and gets a JSON summary — for investigating a
  suspected regression or validating a perf-sensitive change. This is just the
  extended CLI; no new infra.
- **Nightly on `main`.** A scheduled workflow (mirroring `nightly_build.yml`'s cron +
  `act10ns/slack`/`SLACK_WEBHOOK` failure notification) runs the **smoke matrix** on a
  localnet cluster, emits the JSON summary, and compares against the stored baseline.
  Regression beyond a threshold → Slack alert + failed run.
  - **Cluster lifecycle:** stop VMs between runs (a warm 24/7 cluster costs ~10×,
    see costs); reset node state on start (`deploy-nomad --shutdown-and-reset`).
  - **Triage:** a red nightly needs an owner who decides regression vs. noise,
    then files the fix or updates the baseline.
  - **Evidence capture:** on failure, bundle node logs and `/debug/tasks` output
    as CI artifacts before teardown.
  - **CI access:** devnet assumes a local infra-ops checkout and personal
    `gcloud` auth; the workflow needs a service account and cluster RPC access —
    part of this phase's scope.
- **Per-PR canary** *(optional)*. A small-N check on the e2e-tests harness catches
  gross regressions pre-merge; the devnet benchmark stays authoritative.

## Regression detection

A run regresses if a KPI deviates from the baseline beyond a tolerance band
(to absorb cloud noise). Start simple — fixed percentage thresholds per KPI
(e.g. throughput −15%, p99 +25%, success rate < 99%) — and tighten once we observe
real run-to-run variance.

**Baseline mechanism:** mirror the contract gas-threshold pattern
(`crates/contract/tests/sandbox/gas_thresholds.json`): a checked-in
`benchmark-baselines.json` keyed by matrix cell, holding expected KPI values and
per-KPI tolerances. The nightly job fails on breach; baseline updates are
deliberate PRs, so intentional performance changes are visible in review.

**Variance control:**

- Gated KPIs use the median of 3 repetitions of each smoke-matrix cell.
- Instance type is fixed per matrix cell and recorded in the result schema.
- Reused clusters are reset to a known state (`deploy-nomad --shutdown-and-reset`)
  before a gated run, so RocksDB size and asset-store levels don't drift across
  nights.

**Attribution:** a nightly regression may span a day of merges; since a run is
fully described by manifest + commit, bisect by re-running the failing cell at
suspect commits.

## Cost considerations

GCP list prices (July 2026): `n2d-standard-8` — the type devnet already uses —
runs ≈ $0.34/h on-demand, ≈ $0.08/h spot; disks are negligible (~$0.014/h per
node for 100 GB pd-balanced).

- **A 100-node run is cheap:** ~$35/h for the whole cluster, so a ~3 h session
  (keygen + 3 repetitions) is ~$110–120, and a full size sweep (~1 h per size) is
  ~$100 — even weekly that is ~$450/month. Cost is not a blocker at the target size.
- **Nightly smoke:** ~8 nodes × 2 h/night ≈ $170–200/month with VMs stopped
  between runs; the same cluster warm 24/7 would be ~$1,400–2,000/month.
- **Spot** (~76% cheaper) suits exploratory runs only; preemption mid-run
  invalidates a gated benchmark.
- **Quota:** 100 × n2d-standard-8 is 800 N2D vCPUs in one region — well above
  default Compute Engine quotas. Request the increase ahead of the first large
  sweep.
- Localnet-in-cluster avoids per-node testnet sync (~1h+ each), the dominant
  turnaround cost for large N — strongly favored for the size sweep.

## Open questions

- Exact regression thresholds per KPI — needs a few baseline runs to set sensibly.
- Where the full run history accumulates for trend analysis (results branch vs.
  dedicated repo vs. artifact retention) — gating itself needs only the checked-in
  baseline file.
- Target SLOs: the pass/fail numbers for the 100-node objective (latency,
  throughput, success rate).
- TEE representativeness: production nodes run in TDX; do gated numbers need
  TDX-capable instances, or is a one-time TEE vs. non-TEE calibration run enough?
- Division of ownership for the Prometheus/Grafana piece between this repo and infra-ops.
- How much of this should converge with the #1833 framework vs. ship independently first.
