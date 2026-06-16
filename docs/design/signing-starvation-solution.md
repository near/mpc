# Issue #1175 — Signing starvation after resharing

## Problem

After every resharing, signing latency degrades for hours-to-days until the
asset buffers refill. The ticket suspects "asset generation should run on a
separate lower-priority thread but doesn't" — and that is exactly what the
code does today.

## Root cause

Three architectural facts, plus two that make them fire after a resharing:

1. **Shared runtime, equal priority.** Signing, leader gen, and follower gen
   all run as peer `tracking::spawn` tasks on the same `cores`-limited
   per-epoch tokio runtime (`coordinator.rs::create_runtime_and_run`). The
   `cores` limit exists to protect the indexer, not signing.
2. **CPU-bound, non-yielding poke loop.** `run_protocol` in `protocol.rs`
   runs `protocol.poke()` until `Action::Wait`. A 64-batch triple gen burst
   is tens-to-hundreds of ms between awaits.
3. **Unbounded follower fan-out.**
   `mpc_client.rs::monitor_passive_channels_inner` spawns one task per
   incoming peer channel with no cap, so a node has no way to bound how much
   follower work peers can push onto it.
4. **Resharing erases the asset buffers.** Triples reference the old
   participant set and get cleaned up (`assets::cleanup`); presignatures
   embed the old keyshare and are also wiped. Every node empties at once and
   refills toward `desired_*_to_buffer`, so the load spike is synchronized
   network-wide.
5. **Mainnet runs two CaitSith domains.** Presignature generation runs
   per-domain (one background loop per `(provider, domain)` in
   `spawn_background_tasks`), so the per-node presig pipeline doubles.

## Solution options

### A — Lower-OS-priority gen runtime

A second tokio runtime (`gen_runtime`) dedicated to triple/presignature
generation, with worker threads spawned at lower OS priority via
`thread-priority` (Linux `nice`, macOS QoS, Windows-equivalent). Signing,
network routing, and indexer stay on the original `mpc_runtime` at normal
priority; the OS scheduler preempts gen whenever normal-priority work is
ready.

Blast radius:

- `tracking.rs` grows `spawn_on` / `spawn_checked_on` so call sites can
  target a specific runtime; existing `spawn` becomes a `Handle::current()`
  wrapper (no call-site churn elsewhere).
- `runtime.rs` adds a helper that builds the runtime with
  `Builder::on_thread_start` setting `ThreadPriority::Min`.
- `coordinator.rs` builds `gen_runtime` next to `mpc_runtime` and passes its
  handle into `MpcClient`.
- `mpc_client.rs` routes the four `*_background_tasks` spawns to
  `gen_runtime`, and dispatches triple/presig follower channels in
  `monitor_passive_channels_inner` to `gen_runtime` (signing/CKD/foreign-tx
  follower channels stay on `mpc_runtime`).

Caveat: when no normal-priority thread is ready (signing happens to be
awaiting), gen threads still run. On a CPU-oversubscribed host that leaves
some residual tail.

### A.1 — `gen_cores` config knob

`Option<usize>` on `ConfigFile`, defaulting to `cores` when unset, mirrored
into `/debug/node_config`. Lets operators size `gen_runtime` independently
of `mpc_runtime` as a defensive bound on top of OS priority — useful if
priority preemption ever proves insufficient on a particular kernel/host.

### B — Bound follower concurrency

Cap concurrent follower gen tasks per peer, both as DoS protection and as a
defensive bound on fan-out.

**Must be per-peer admission, not a single global semaphore.** A small
global cap deadlocks in the threshold-N circular-wait case (A waits on B to
free a slot to accept A's gen; B waits on C; C waits on A). Concrete shape:
`try_admit(leader_id) -> Option<Permit>`, non-blocking; on unavailable, drop
the channel and let the leader time out and retry with different
participants.

Necessary only if memory pressure or scheduler queue depth turn out to be a
problem after A. If A leaves only CPU contention, B is overkill.

### C — `yield_now()` in the poke loop

A single `tokio::task::yield_now().await` in `run_protocol`'s outer loop
shortens the maximum CPU burst between cooperative yield points
(a comment in `protocol.rs` already documents the hazard).

With A in place this mainly helps fairness *within* `gen_runtime`; gen tasks
yielding to each other does not free a core for signing. Cheap, harmless,
defensible independently of #1175.

### Lower `presignature.concurrency`

Existing `ConfigFile` knob; mainnet sets it to 16, which exceeds
`cores = 12` — leader-side presig generation alone over-subscribes the
runtime once enough triples are available. Halving or quartering this
directly shrinks the number of concurrent presig poke loops on the runtime,
at the cost of a slower refill toward
`desired_presignatures_to_buffer`. Pure operational tuning — no code change,
no protocol rollout.

### Reduce `SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE`

Drop the `SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE` const in `triple.rs` from
64 → ~16. Each follower poke burst
becomes 4× shorter; gen threads idle more often, opening more chances for
higher-priority threads to grab a core. **Protocol-affecting**: followers
validate `count == BATCH_SIZE` in `triple.rs`, so leader and follower
must agree — coordinated network-wide rollout. Worth doing only if a
protocol bump is already on the table.

### E — `spawn_blocking` or dedicated rayon pool

Move CPU-bound compute off async worker threads entirely. Overlaps with what
A achieves through runtime separation, but at a deeper restructuring layer.

## Open questions

1. **Does A fully fix mainnet?** Mechanism is correct, but host shape
   matters (CPU oversubscription leaves residual tail). A testnet or
   latency-injected run resolves this.
2. **Is follower fan-out a memory/scheduler problem, or only CPU?** If only
   CPU, A suffices and B is unneeded.
3. **What does the indexer contribute to the latency floor?** The indexer
   runtime is unbounded today (`indexer/real.rs`, tracked in #1515). Worth
   profiling on a real node so it does not confound a "did we fix it?"
   measurement.
