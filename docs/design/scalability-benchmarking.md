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
- **Scaling curves** (performance vs. participant count) up to ~100 nodes.
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
| In-cluster localnet chain | `mpc-devnet ... deploy-chain` | Runs a `neard` validator inside the cluster — no testnet sync wait, chain won't throttle the benchmark. Purpose-built for this. |
| Load generator | `crates/devnet/src/loadtest.rs` | `--qps`, `--duration`, `--parallel-sign-calls-per-domain`, multi-domain. Reports submitted/signed/end-to-end success rates. **stdout only — not persisted, no latency percentiles.** |
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
2. **Capture latency percentiles.** The node already records latency histograms;
   have the harness scrape `/metrics` (reusing the `get_metric` mechanism) at the
   end of a run and fold p50/p95/p99 into the JSON summary, rather than relying on
   the load generator's client-side polling.
3. **A scenario manifest.** Promote `loadtest-scenarios.sh` to a declarative
   manifest (cluster size, load shape, conditions, duration) so a run is fully
   described by data and is reproducible.

## Benchmark dimensions

A benchmark run is the cross product of **cluster shape × load shape × condition**.

- **Cluster size (participants):** e.g. 4, 8, 16, 32, 64, 100. Threshold scales with it.
- **Load shape:** sustained baseline, high steady-state, spike (warm→burst→cool) —
  already in `loadtest-scenarios.sh`; parameterized by QPS, duration, parallel-sign batch.
- **System condition:**
  - **Steady state** — baseline.
  - **During resharing** — start load, trigger `vote-new-parameters`, measure the
    dip and time-to-recovery while keys are redistributed.
  - **After resharing** — steady state on the new participant set.
  - **Some nodes down** — kill `f` nodes (up to threshold tolerance), measure
    degraded throughput and whether the network keeps signing.
  - **Misbehaving nodes** *(stretch)* — nodes that respond slowly or with garbage.

We do not need the full cross product on every run. Define a small **smoke matrix**
for nightly regression (small N, steady + spike) and a larger **scaling matrix**
run on-demand or weekly (the size sweep, plus resharing/nodes-down).

## Metrics / KPIs

Recorded per run, sourced from node `/metrics` plus the load generator:

- **Throughput:** sustained signatures/sec achieved vs. offered QPS.
- **Latency:** request→response p50/p95/p99 in seconds and blocks
  (`mpc_signature_request_response_latency_seconds`/`_blocks`).
- **Success rate:** end-to-end (already computed by `loadtest.rs`), plus
  `mpc_num_fail_on_timeout_indexed` deltas.
- **Asset generation:** triple/presignature generation time and available-asset
  gauges — the usual scaling bottleneck as N grows.
- **Resharing recovery:** wall-clock from resharing start to throughput recovery.

## Environments (tiered)

- **Primary — in-cluster localnet.** Reproducible, no sync wait, chain isn't a
  throttle. Used for regression gating and scaling curves where we want clean,
  comparable numbers.
- **Secondary — testnet.** Periodic runs against a real cluster on testnet for
  realism (real network latency, real RPC limits). Higher cost and noisier, so used
  for validation rather than per-commit gating.

The same harness and result schema serve both; only the target (`--mpc-network`
localnet cluster vs. `--mpc-contract` on testnet) differs.

## Results storage (two complementary sinks)

1. **Structured JSON/CSV summary per run — for regression gating.** One record per
   run: commit SHA, timestamp, cluster size, condition, load shape, and the KPIs
   above. Stored as CI artifacts and appended to a results branch/repo so runs are
   diffable and a baseline can be tracked. This is what an automated regression
   check reads.

   Proposed schema (sketch):
   ```json
   {
     "commit": "b245cc29", "timestamp": "2026-06-26T00:00:00Z",
     "env": "localnet", "participants": 16, "threshold": 11,
     "condition": "steady_state",
     "load": { "qps": 10, "duration_s": 300, "batch": 10 },
     "throughput_sps": 9.6,
     "latency_s": { "p50": 1.8, "p95": 3.2, "p99": 4.1 },
     "success_rate": 0.998,
     "timeouts": 1
   }
   ```

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
  - **Cluster reuse** matters for cost: prefer a long-lived (or reset-without-resync,
    via `deploy-nomad --shutdown-and-reset`) localnet cluster over provisioning fresh
    each night.

## Regression detection

A run regresses if a KPI deviates from the rolling baseline beyond a tolerance band
(to absorb cloud noise). Start simple — fixed percentage thresholds per KPI
(e.g. throughput −15%, p99 +25%, success rate < 99%) — and tighten once we observe
real run-to-run variance. This mirrors the `buffer_percent` approach already used by
the contract gas-threshold tests.

## Cost considerations

- Localnet-in-cluster avoids per-node testnet sync (~1h+ each), the dominant time/cost
  for large N — strongly favored for the size sweep.
- Nightly should use a small smoke matrix on a reused cluster; the full 100-node
  scaling sweep is on-demand/weekly, not nightly.
- **Open:** confirm GCP cost per cluster-hour at the larger sizes (n2d-standard-8 ×
  ~100, plus validator) and whether a 100-node run is affordable as a one-off vs.
  needing a smaller extrapolation point (e.g. 64). To be filled in with infra-ops.

## Phased rollout (proposed follow-up issues)

1. **Persist load-test results** — JSON summary emitter on `loadtest run` + scrape
   latency percentiles from `/metrics`. (Smallest, unblocks everything.)
2. **Scenario manifest** — declarative cluster×load×condition definition replacing
   the bash scenarios.
3. **Nightly smoke workflow** — scheduled run on localnet + baseline comparison +
   Slack alert.
4. **Condition coverage** — resharing-recovery and nodes-down scenarios in the harness.
5. **Scaling sweep + Grafana** — size sweep to 100, infra-ops Prometheus/Grafana wiring.
6. **(Stretch)** misbehaving-node scenarios.

## Open questions

- Exact regression thresholds per KPI — needs a few baseline runs to set sensibly.
- Where the JSON results baseline lives (results branch vs. dedicated repo vs.
  artifact retention) and how the nightly job reads the previous baseline.
- GCP cost/feasibility of a true 100-node run vs. extrapolating from a smaller max.
- Division of ownership for the Prometheus/Grafana piece between this repo and infra-ops.
- How much of this should converge with the #1833 framework vs. ship independently first.
