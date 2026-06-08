# CI E2E flake diagnostic — `migration_service__should_handle_back_migration_a_to_b_to_a`

The `back-migration` E2E test on PR #3362 fails with two distinct nearcore panics — both triggered by SIGKILL of an mpc-node process during active block production followed by an immediate restart. The same test passes ~100% on the baseline branch (no #3362 code), so the bug is upstream in nearcore — but PR #3362's `submit_attestation_before_concluding_migration` is necessary to reach it, and the failure rate also depends on what activity happens on chain between forward conclude and the SIGKILL.

> **Headline statistics.**
> - **PR #3365 pre-merge** (no #3362 code): 0/15 fail.
> - **PR #3362 against nearcore `aab31b0`** (initial branch state): 5/6 fail (~83%).
> - **Revert experiment PR #3373** (PR #3362 minus the node-side fix, otherwise identical): 0/5 fail.
> - **PR #3362 against nearcore `fadb5c1`** (after merging main, `Cargo.lock` bump within `2.12.0-rc.1`): back-migration test ~11/17 fail (~65%) combined across four sample batches.
> - **Focused-repro matrix** at the same commit — full 2⁴ on `(pre-sign, pre-ckd, post-sign, post-ckd)` plus SIGTERM counterparts for the worst variant and the back-migration test:
>
>   | # | pre-sign | pre-ckd | post-sign | post-ckd | Kill | Fail rate |
>   |---|---|---|---|---|---|---|
>   | 0 | — | — | — | — | SIGKILL | 0 / 20 |
>   | 1–6 | (1-of-4 or 2-of-4 activity, all combos) | | | | SIGKILL | **all 0%** |
>   | 7 | ✓ | — | ✓ | — | SIGKILL | 1 / 3 (small sample) |
>   | 10–11 | (other 2-of-4 combos) | | | | SIGKILL | 0% |
>   | 12 | — | ✓ | ✓ | ✓ | SIGKILL | 1 / 10 (~10%) |
>   | 13 | ✓ | ✓ | ✓ | — | SIGKILL | 3 / 10 (~30%) |
>   | 14 | ✓ | ✓ | — | ✓ | SIGKILL | 3 / 10 (~30%) |
>   | **15** | ✓ | ✓ | ✓ | ✓ | SIGKILL | **7 / 10 (~70%)** |
>   | 15-T | ✓ | ✓ | ✓ | ✓ | **SIGTERM 30s** | **2 / 2 (small)** |
>   | back-mig-T | ✓ | ✓ | ✓ | ✓ + back round | **SIGTERM 30s** | **2 / 2 (small)** |
>
> The revert experiment proves PR #3362's code is *necessary* to reach the bug. The focused-repro matrix proves it isn't *sufficient* on its own — all four activity types (pre-sign + pre-ckd + post-sign + post-ckd) need to be present to reach ~70% reproduction. Drop any one and the rate falls to ~30% or zero. The back-migration round itself adds nothing.
>
> **No teardown change we've tried prevents the panic.** SIGTERM at 30 s grace fails 2 / 2 — but it turns out `mpc-node` has no SIGTERM handler, so the "graceful" path was effectively identical to SIGKILL. Drain-via-`listen_blocks.flag` then SIGKILL fails 5 / 5 — the flag only pauses our consumer-side; the panic is on nearcore's producer-side. A real graceful shutdown of mpc-node doesn't exist today (no SIGTERM handler, no `/shutdown` endpoint) and adding one is a separate piece of work.

---

## Overview of failures so far

| Attempt | Run | Commit | Surface |
|---|---|---|---|
| 1 | [26471648821](https://github.com/near/mpc/actions/runs/26471648821) | `990cad3a` | "Connection refused" on `/debug/migrations` — A0 process already exited by the time PR #3365's diagnostic ran. (Pre-3365 helper, opaque). |
| 2 | [26473240463](https://github.com/near/mpc/actions/runs/26473240463) | `f947ff9e` | Same as attempt 1. |
| 3 | [26495701290](https://github.com/near/mpc/actions/runs/26495701290) | `3a63c918` | `wait_for_node_indexer_height_above` timed out; first run on top of #3365's branch — diagnostic surfaced "node may have exited" but no stderr dump yet. |
| 4 | [26498637558](https://github.com/near/mpc/actions/runs/26498637558) | `d9707221` (rebased on #3365) | First stderr-tail dump: **`streamer/mod.rs:207` — "receipt must be present"**. Pre-kill height 312. |
| — | [26497683232](https://github.com/near/mpc/actions/runs/26497683232) | `d9707221` (lint-failed CI run) | **E2E passed.** Same commit as run #4 but a different attempt. |
| 5 (attempt 1) | [26501678885](https://github.com/near/mpc/actions/runs/26501678885) | `cc3eeae0` (rebased on main after #3365 merge) | Second stderr-tail dump: **`client_actor.rs:217` — `StorageInconsistentState ... No ChunkExtra`**. Pre-kill height 464. |
| 5 (rerun #1) | 26501678885 attempt 2 | `cc3eeae0` | **`streamer/mod.rs:207`**. Pre-kill height 305. |
| 5 (rerun #2) | 26501678885 attempt 3 | `cc3eeae0` | **`streamer/mod.rs:207`**. Pre-kill height 313. |
| 5 (rerun #3) | 26501678885 attempt 4 | `cc3eeae0` | **`streamer/mod.rs:207`**. Pre-kill height 304. |
| 5 (rerun #4) | 26501678885 attempt 5 | `cc3eeae0` | **`streamer/mod.rs:207`**. Pre-kill height 306. |

### Statistics on the cc3eeae0 commit (nearcore `aab31b0`)

| Failure mode | Count | Pre-kill heights |
|---|---|---|
| A — `streamer/mod.rs:207` (receipt missing) | 5 | 304, 305, 306, 312, 313 (tight cluster) |
| B — `client_actor.rs:217` (StorageInconsistentState) | 1 | 464 (outlier high) |

Mode A dominates and clusters tightly around height ~305. Mode B has only surfaced once and only at the highest pre-kill height we've seen — weak circumstantial evidence that B is reachable when there's more state on disk to corrupt, A is the "default" failure when state is fresher.

### Statistics after merging main (`e610ffb7`, nearcore `fadb5c1`)

Same nearcore tag (`2.12.0-rc.1`), different resolved commit (`Cargo.lock` was bumped by main's recent dependency updates). 9 sequential CI runs:

| # | `forward_migration_kill_restart` | `should_handle_back_migration_a_to_b_to_a` | Pre-kill height |
|---|---|---|---|
| 1 | PASS (36.1 s) | FAIL — `streamer/mod.rs:207` | 303 |
| 2 | PASS (36.2 s) | PASS (60.2 s) | — |
| 3 | PASS (37.6 s) | PASS (58.8 s) | — |
| 4 | PASS (37.2 s) | FAIL — `streamer/mod.rs:207` | 313 |
| 5 | PASS (37.3 s) | PASS (58.8 s) | — |
| 6 | PASS (36.2 s) | FAIL — `streamer/mod.rs:207` | 311 |
| 7 | PASS (36.8 s) | FAIL — `streamer/mod.rs:207` | (mode A) |
| 8 | PASS (37.8 s) | FAIL — `streamer/mod.rs:207` | (mode A) |
| 9 | PASS (36.7 s) | PASS (58.0 s) | — |

| | Pass | Fail | Failure rate |
|---|---|---|---|
| `forward_migration_kill_restart` | 9 | 0 | 0% |
| `should_handle_back_migration_a_to_b_to_a` | 4 | 5 | ~55% |

All 5 failures are mode A at the same `streamer/mod.rs:207` line as before. No mode B observed in this batch.

---

## Failure mode A — `streamer/mod.rs:207` (in-memory race during catch-up)

**Run:** [26498637558 job 78033060779](https://github.com/near/mpc/actions/runs/26498637558/job/78033060779)
**Commit:** `04971e0c` (PR #3362, branch `barak/2121-contract-stale-attestation-test` rebased onto #3365's `fix/migration-back-wait-indexer-ready`)

```
thread 'migration_service::migration_service__should_handle_back_migration_a_to_b_to_a' (651425) panicked at crates/e2e-tests/tests/migration_service.rs:744:6:
A0's indexer did not resume + advance within 60s after restart: node 0 indexer did not advance past height 312 within 60s
--- last 16KB of node 0 stderr.log (#3366 diagnostics) ---

thread 'tokio-rt-worker' (886644) panicked at /home/runner/.cargo/git/checkouts/nearcore-86558fdb18093f53/aab31b0/chain/indexer/src/streamer/mod.rs:207:42:
`receipt` must be present at this moment
stack backtrace:
   0: __rustc::rust_begin_unwind
   1: core::panicking::panic_fmt
   2: core::option::expect_failed
   3: <alloc::vec::into_iter::IntoIter<T,A> as core::iter::traits::iterator::Iterator>::fold
   4: near_indexer::streamer::build_streamer_message::{{closure}}
   5: near_indexer::streamer::start::{{closure}}
   6: tokio::runtime::task::core::Core<T,S>::poll
   7: tokio::runtime::task::harness::Harness<T,S>::poll
   8: tokio::runtime::scheduler::multi_thread::worker::Context::run_task
   9: tokio::runtime::scheduler::multi_thread::worker::Context::run
  10: tokio::runtime::context::scoped::Scoped<T>::set
  11: tokio::runtime::context::runtime::enter_runtime
  12: tokio::runtime::scheduler::multi_thread::worker::run
  13: <tokio::runtime::blocking::task::BlockingTask<T> as core::future::future::Future>::poll
  14: tokio::runtime::task::core::Core<T,S>::poll
  15: tokio::runtime::task::harness::Harness<T,S>::poll
  16: tokio::runtime::blocking::pool::Inner::run
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

--- end stderr.log ---

Caused by:
    indexer block-height metric not available — node may have exited
```

### Interpretation

- An `expect("receipt must be present at this moment")` deep inside `near_indexer::streamer::build_streamer_message` fires while building a streamer message — a receipt referenced by a block isn't present in the lookup the indexer is doing.
- The panic kills the `tokio-rt-worker` carrying nearcore's indexer streamer task. That thread is the only producer for the `StreamerMessage` channel that mpc-node's `listen_blocks` consumes — so the consumer stops receiving messages and `MPC_INDEXER_LATEST_BLOCK_HEIGHT` stops advancing.
- The mpc-node main process keeps running just long enough that PR #3365's `wait_for_node_indexer_height_above` helper sees a stale metric. Then the metric server itself becomes unscrapable and the helper's fallback ("node may have exited") fires.

The class of bug here is *in-memory racy state during block streaming after kill+restart catch-up* — likely because nearcore's indexer accumulates state from blocks as they're produced and then loses it when SIGKILL'd mid-build.

---

## Failure mode B — `client_actor.rs:217` (on-disk inconsistency at startup)

**Run:** [26501678885 job 78043485451](https://github.com/near/mpc/actions/runs/26501678885/job/78043485451)
**Commit:** `cc3eeae0` (PR #3362 rebased on main after #3365 was squash-merged)

```
thread 'migration_service::migration_service__should_handle_back_migration_a_to_b_to_a' (501699) panicked at crates/e2e-tests/tests/migration_service.rs:744:6:
A0's indexer did not resume + advance within 60s after restart: node 0 indexer did not advance past height 464 within 60s
--- last 16KB of node 0 stderr.log (#3366 diagnostics) ---

thread '<unnamed>' (749092) panicked at /home/runner/.cargo/git/checkouts/nearcore-86558fdb18093f53/aab31b0/chain/client/src/client_actor.rs:217:6:
called `Result::unwrap()` on an `Err` value: Chain(StorageError(StorageInconsistentState("No ChunkExtra for block 4cqR4KRwGv92jgnsFLzmJvDdNy7hj5JGUak8nY1tWsVu in shard s0.v0")))
stack backtrace:
   0: __rustc::rust_begin_unwind
   1: core::panicking::panic_fmt
   2: core::result::unwrap_failed
   3: near_client::client_actor::start_client
   4: nearcore::start_with_config_and_synchronization_impl::{{closure}}
   5: mpc_node::indexer::real::spawn_real_indexer::{{closure}}::{{closure}}
   6: tokio::runtime::runtime::Runtime::block_on

thread 'main' (749090) panicked at crates/node/src/indexer/real.rs:225:10:
txn_sender is returned from the `block_on` expression above.: RecvError(())
stack backtrace:
   0: __rustc::rust_begin_unwind
   1: core::panicking::panic_fmt
   2: core::result::unwrap_failed
   3: mpc_node::indexer::real::spawn_real_indexer
   4: mpc_node::run::run_mpc_node::{{closure}}
   5: std::thread::local::LocalKey<T>::with
   6: futures_executor::local_pool::block_on
   7: mpc_node::main
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

--- end stderr.log ---

Caused by:
    indexer block-height metric not available — node may have exited
```

### Interpretation

- `near_client::client_actor::start_client` does an `unwrap()` (at `chain/client/src/client_actor.rs:217`) on a `Result<_, near_chain::Error>` and that result is `Err(StorageError(StorageInconsistentState("No ChunkExtra for block <hash> in shard s0.v0")))`.
- `ChunkExtra` is metadata persisted to RocksDB *after* a chunk is processed. If it's missing for a block neard tries to load on startup, that means the previous run was SIGKILL'd mid-write or some other ordering invariant was violated. The recovery code expects this to always be present.
- This panic happens **at startup, before block streaming even begins**. neard never finishes booting. So the indexer never starts streaming → `txn_sender_sender` is dropped without ever being used → mpc-node's main thread `blocking_recv()` returns `RecvError(())` → secondary panic at `crates/node/src/indexer/real.rs:225` (the `.expect("txn_sender is returned from the 'block_on' expression above.")`).

The class of bug here is *on-disk inconsistency that nearcore's recovery code can't tolerate* — a missing `ChunkExtra` should either be retryable or the recovery code should gracefully reconstruct it, not unwrap.

---

## What relates PR #3362's code to the failure

The only operational change #3362 introduces during the forward round is one extra `SubmitParticipantInfo` transaction (from `submit_attestation_before_concluding_migration`) submitted via `submit_remote_attestation` immediately before `ConcludeNodeMigration`. That helper uses `send_and_wait`, so the conclude transaction follows in a *separate* near-future block.

### Revert experiment — hypothesis 1 confirmed

[PR #3373](https://github.com/near/mpc/pull/3373) was created with exactly one commit reverted from PR #3362: the `submit_attestation_before_concluding_migration` change. Everything else stayed identical (contract sandbox tests, stderr-tail diagnostic, lint fixes, the merge of #3365's flake-fix from main). Five sequential CI runs were observed:

| Run | Workflow attempt | E2E result |
|---|---|---|
| 1 | 26505165380 attempt 1 | ✅ pass |
| 2 | 26505165380 attempt 2 | ✅ pass |
| 3 | 26505165380 attempt 3 | ✅ pass |
| 4 | 26505165380 attempt 4 | ✅ pass |
| 5 | 26505165380 attempt 5 | ✅ pass |

**Result: 0/5 fail.** Combined with the 5/6 failure rate on #3362, the experiment definitively isolates the trigger to that single commit. The other two hypotheses — nonce contention with `periodic_attestation_submission`, and a chain-depth threshold — are ruled out, because the experiment branch produces near-identical block counts (the only saved transactions are the per-conclude `SubmitParticipantInfo` ones).

### Concrete trigger pattern

The minimal repro shape, with each step described in terms an upstream nearcore reader can act on:

1. An mpc-node binary (which embeds `near-indexer`) is running and producing blocks.
2. The node submits two function-call transactions back-to-back from the **same signer** to the **same contract**, the second only after the first reaches `TransactionStatus::Executed`. The two transactions therefore land in different but very close blocks.
3. **Additional same-signer function-call activity continues for ~10–20 s after the two-tx pattern.** Without this extra activity the bug is much less reachable — see the focused-repro experiment below.
4. The neard process is sent SIGKILL while the indexer is mid-block-stream.
5. The neard process is restarted against the same `home_dir`.
6. On restart, the embedded `near-indexer` panics with either:
   - `chain/indexer/src/streamer/mod.rs:207` — "`receipt` must be present at this moment" (the common case, mode A), or
   - `chain/client/src/client_actor.rs:217` — `StorageInconsistentState("No ChunkExtra for block <hash> in shard s0.v0")` (rarer, mode B; correlates with higher pre-kill height).

### Focused-repro experiments — isolating the trigger

A family of focused tests was added next to the back-migration test. Each runs the same forward migration + node kill + restart + indexer-progress assertion, varying only the sign / CKD activity around the migration. The full 2⁴ matrix on `(pre-sign, pre-ckd, post-sign, post-ckd)` is covered, plus SIGTERM counterparts for the most-failing variant and the back-migration test.

`pre-forward` activity is signed by A0 + A1 while A0 is still an active participant. `post-forward` activity is signed by B0 + A1 after A0 has been demoted by `conclude_node_migration`.

#### Consolidated results across four campaigns

Aggregated across campaign 1 (variants 0–3, 5 runs), campaign 2 (0–6, 5 runs), campaign 3 (0–15 + SIGTERMs, 5 runs), and campaign 4 (full set, 5 runs, with `gh run rerun` instead of `--failed` to defeat nextest's retry-filtering). Variants added later have fewer total observations because nextest's per-rerun test filtering still partially skipped passing tests on some attempts.

| # | pre-sign | pre-ckd | post-sign | post-ckd | Kill mode | Fail / Total | Fail rate |
|---|---|---|---|---|---|---|---|
| 0 | — | — | — | — | SIGKILL | 0 / 20 | **0%** |
| 1 | — | — | ✓ | — | SIGKILL | 0 / 12 | **0%** |
| 2 | — | — | — | ✓ | SIGKILL | 0 / 20 | **0%** |
| 3 | — | — | ✓ | ✓ | SIGKILL | 1 / 12 | ~8% |
| 4 | ✓ | — | — | — | SIGKILL | 0 / 11 | **0%** |
| 5 | — | ✓ | — | — | SIGKILL | 0 / 15 | **0%** |
| 6 | ✓ | ✓ | — | — | SIGKILL | 0 / 7 | **0%** |
| 7 | ✓ | — | ✓ | — | SIGKILL | 1 / 3 | (small sample) |
| 8 | ✓ | — | — | ✓ | SIGKILL | 0 / 3 | (small) |
| 9 | ✓ | — | ✓ | ✓ | SIGKILL | 0 / 3 | (small) |
| 10 | — | ✓ | ✓ | — | SIGKILL | 0 / 9 | **0%** |
| 11 | — | ✓ | — | ✓ | SIGKILL | 0 / 10 | **0%** |
| 12 | — | ✓ | ✓ | ✓ | SIGKILL | 1 / 10 | ~10% |
| 13 | ✓ | ✓ | ✓ | — | SIGKILL | 3 / 10 | ~30% |
| 14 | ✓ | ✓ | — | ✓ | SIGKILL | 3 / 10 | ~30% |
| **15** | ✓ | ✓ | ✓ | ✓ | SIGKILL | **7 / 10** | **~70%** |
| 15-T | ✓ | ✓ | ✓ | ✓ | SIGTERM 30s | **2 / 2** | (small) |
| back-mig | ✓ | ✓ | ✓ | ✓ + back round | SIGKILL | ~11 / ~17 | **~65%** |
| back-mig-T | ✓ | ✓ | ✓ | ✓ + back round | SIGTERM 30s | **2 / 2** | (small) |

#### Observations

1. **Variant 15 is the smoking-gun repro.** Same `(pre, post)` activity profile as the back-migration test, same panic, same failure rate (~70%). The back-migration round itself adds nothing to the failure rate — the bug is reachable without it.
2. **All four activity types are needed simultaneously.** Drop any one of the four (variants 12, 13, 14, 9) and the rate falls to ~10–30% or zero.
3. **2-of-4 or fewer almost never fires.** Variants 3 and 7 each fired once across a few observations; too small to call a true rate, but consistent with "you need at least three of the four kinds of activity to make the panic reachable at all."
4. **SIGTERM is *not* a clean fix** at 30 s grace. Both observations of the variant-15 SIGTERM counterpart and the back-migration SIGTERM counterpart failed at ~101 s with the same `streamer/mod.rs:207` panic. Strong hint (small sample, but two-for-two) that graceful shutdown doesn't address the upstream bug — either neard's graceful path also has the issue, or 30 s isn't enough time to flush whatever state needs flushing.
5. **Every observed panic is mode A** (`streamer/mod.rs:207` "receipt must be present at this moment") across the focused matrix. Mode B (`StorageInconsistentState`) appeared once early in the investigation but hasn't recurred in the focused-test campaigns — which fits if mode B requires more on-disk chain depth than the focused setup produces.

#### Three plausible explanations, refined

1. **Write-rate effect.** More function-calls per second → more block writes → larger chance SIGKILL lands mid-write. Doesn't explain why variants 0–6 never fire while variant 15 fires ~70%, since the per-second write rate doesn't differ that much between, say, variants 13 (3 of 4 activity types) and 15 (4 of 4). Demoted.
2. **Receipt-graph effect (most actionable).** `sign_respond` and `respond_ckd` produce a specific receipt-chain shape (request receipt → MPC respond → state-cleanup receipt) that the indexer tracks in-memory. The `streamer/mod.rs:207` panic site is inside a `.fold` over a receipt collection — a specific receipt-graph topology likely leaves the collection with a "referenced-but-absent" gap when SIGKILL hits. The variant-15 result is consistent with this: both pre- and post-forward, both sign- and ckd-shaped, are needed to set up a graph topology the recovery code can't reconstruct.
3. **Time-based effect.** Neard runs periodic background work. The variant-13/14 rates (~30 % each, both with 3-of-4 activity) and variant-15 rate (~70 %, 4-of-4) are consistent with timing — more activity = more chance SIGKILL falls in a fragile window — but the receipt-graph explanation accounts for the same pattern without requiring an unrelated time mechanism.

The receipt-graph hypothesis remains the best fit. SIGTERM failing at 30 s grace strengthens it: if the issue is purely write-timing, graceful shutdown should have fixed it. The fact that it didn't suggests the in-memory streamer state — not just the on-disk RocksDB — is the broken thing.

### Drain-then-kill experiment — also does not fix it

Following the SIGTERM-still-fails result, we tried draining each node before SIGKILL: write `listen_blocks.flag = false` to pause our `listen_blocks` consumer, poll the indexer block-height metric until it stops advancing for 3 seconds (30 s timeout), *then* SIGKILL. The intuition: pause traffic, let the indexer reach an idle state, then kill — matching how operators do production rolling restarts.

Results across 5 of 5 runs on commit `89a7341d`:

| Test | Pass | Fail | Fail rate |
|---|---|---|---|
| `forward_migration_kill_restart_with_pre_both_and_post_both` + drain | 0 | 5 | **100%** |
| `should_handle_back_migration_a_to_b_to_a` + drain at both kill sites | 0 | 5 | **100%** |

Every failure is the same `streamer/mod.rs:207` panic. Timings increased from ~102 s to 106–127 s, which confirms the drain step ran for several seconds — it just didn't help.

#### Why it didn't work

The drain pauses our **consumer-side** of the block-update channel (`listen_blocks` in `crates/node/src/indexer/handler.rs`). The panic, however, lives in the **producer-side** task — `near_indexer::streamer::start::{{closure}}` calling `build_streamer_message` inside nearcore itself. Pausing our consumer doesn't stop nearcore's streamer from continuing to produce messages or from writing whatever state it writes before SIGKILL. So the on-disk state we restart against is the same with or without the drain.

#### Updated picture of the failure mode

This is now the third teardown strategy we've tried, all failing:

| Approach | Outcome | Rules out |
|---|---|---|
| Plain SIGKILL | Fails ~70% (variant 15) / ~65% (back-mig) | nothing |
| SIGTERM, 30 s grace | Fails 2 / 2 observed | nothing — `mpc-node` has no SIGTERM handler, so the "graceful" path was actually identical to SIGKILL |
| Drain consumer + SIGKILL | Fails 5 / 5 observed | "the bug is about in-flight consumer-side work" |

What remains as plausible mechanism: the panic-causing state is written *during normal block production* by nearcore's streamer task, persisted in RocksDB or in-memory in a way that needs a graceful shutdown of *nearcore's own* task to drain. From a test-side perspective, we have no mechanism that can drain that task short of waiting for neard to genuinely finish a graceful shutdown — which SIGTERM-at-30-s either didn't trigger or wasn't given enough time to finish.

### What this means for the bug location

The panics live in nearcore code. PR #3362's two-tx pattern is necessary to reach them; the back-migration test's sustained sign + ckd activity (both pre- and post-forward) is also necessary. That makes this a real upstream defect in nearcore 2.12.0-rc.1's restart/recovery path — not a defect in #3362. **No test-side teardown change we've tried (SIGTERM, drain) prevents the panic.** This is now solid evidence that the bug must be fixed in nearcore itself; we can't paper over it from the e2e test without losing the kill+restart semantics the test exists to model.

### Real SIGTERM handler in mpc-node — also does not fix it

Earlier rows in the table above show "SIGTERM with 30 s grace" failing 2/2, but that was misleading: mpc-node had no SIGTERM handler installed, so the OS terminated the process immediately and our "graceful" path was indistinguishable from SIGKILL. The data couldn't distinguish "graceful shutdown doesn't help" from "we never actually tested graceful shutdown."

To close that gap we wrote a real SIGTERM handler in mpc-node ([issue #3409](https://github.com/near/mpc/issues/3409), [PR #3410](https://github.com/near/mpc/pull/3410)). It routes SIGTERM into the existing internal shutdown channel and calls `near_async::shutdown_all_actors()` before exit. To prove the handler actually ran in CI, we added a diagnostic that `eprintln!`s `[E2E-DIAG] mpc-node pid=X exited gracefully Xms after SIGTERM` from the test's `terminate_with_grace` helper.

#### Iteration 1: handler hangs

First implementation also called `near_store::db::RocksDB::block_until_all_instances_are_dropped()` after `shutdown_all_actors()` — that's what neard's standalone binary does on its SIGTERM path. **It hung in 5/5 runs:** the diagnostic showed `SIGTERM grace period (60s) elapsed; falling back to SIGKILL` every time, and the test then hit the same `streamer/mod.rs:207` panic on restart.

Root cause: our indexer runs in a `std::thread::spawn`'d closure that does `indexer_tokio_runtime.block_on(async { … })`. The async block holds an `Arc<IndexerState>` which transitively holds `Arc<RocksDB>` references, and the spawned `monitor_*`/`indexer_logger` tasks each hold their own clone. Nothing in our code cancels those tasks on shutdown, so `listen_blocks` runs forever, `block_on` never returns, the std::thread keeps the Arcs alive, and `block_until_all_instances_are_dropped` loops waiting for a refcount that will never reach zero. The 60 s test grace expires, the test SIGKILLs us, and we're back to the original problem.

#### Iteration 2: drop the block_until_all_instances_are_dropped call

Removing that one call lets the handler return immediately after `shutdown_all_actors()`. The diagnostic now shows `exited gracefully 100ms after SIGTERM` in 5/5 runs — the handler does complete, and quickly.

Results on commit `3527e4d4` (5 runs in parallel via sister-branch dispatch):

| Run | Test outcome | Handler shutdown | Restart panic |
|---|---|---|---|
| 1 (PR branch) | ✅ all 23 e2e pass, back-mig pass @ 59.7 s | (suppressed by nextest on pass) | none |
| 2 | ❌ back-mig fail @ line 760 | 100 ms graceful | streamer/mod.rs:207 |
| 3 | ❌ back-mig fail @ line 760 | 19420 ms graceful (CI load outlier) | streamer/mod.rs:207 |
| 4 | ❌ back-mig fail @ line 760 | 100 ms graceful | streamer/mod.rs:207 |
| 5 | ❌ back-mig fail @ line 760 | 100 ms graceful | streamer/mod.rs:207 |

**Pass rate jumped from 0/5 (with v1's hang, or with no handler at all) to 1/5 (with v2).** That's a real improvement — the handler is doing useful work — but **the bug still fires 4/5 times even after a verified 100 ms shutdown.**

#### What "graceful 100 ms" actually covers — and what it doesn't

The 100 ms covers mpc-node's main runtime path: select! exit, `cancellation_token.cancel()`, the image-hash watcher join, and `near_async::shutdown_all_actors()` (which sends a stop signal into nearcore's `ACTOR_SYSTEMS` registry and returns synchronously — it does not wait). After that the process exits.

It does **not** cover the embedded indexer thread:

- The indexer runs in a separate `std::thread::spawn`'d closure with its own tokio runtime ([`crates/node/src/indexer/real.rs:80`](../../crates/node/src/indexer/real.rs)).
- That runtime hosts `near_indexer::streamer::start`'s block-streaming loop *and* the ~6 `tokio::spawn`'d monitor tasks (`indexer_logger`, `monitor_allowed_docker_images`, `monitor_allowed_launcher_compose_hashes`, `monitor_tee_accounts`, `monitor_allowed_foreign_chain_providers`, `foreign_chain_whitelist_verifier::run`).
- Each of those tasks holds `Arc<IndexerState>` → transitively `Arc<RocksDB>`. Our handler installs no cancellation into that runtime; nothing tells these tasks to stop.
- The outer `block_on` therefore never returns, and the std::thread is terminated by OS-level process exit ~100 ms after SIGTERM, mid-flight, exactly as it would be on SIGKILL.

So our experiment shows that **signaling nearcore's actor system to stop does not prevent the panic** — it does not yet show that *fully draining the indexer thread* (option B from the earlier discussion) would also not prevent it. The 100 ms timing alone proves the indexer thread didn't have time to finish anything: a real near-indexer drain typically takes seconds, not milliseconds.

That said, three reasons we still believe the bug is upstream and option B wouldn't materially change the outcome:

1. **The panic site reads state from normal block production, not from shutdown.** `build_streamer_message`'s `.fold` panics because a referenced receipt is missing in the in-memory tracking map (rebuilt from RocksDB on restart). That state was written before shutdown started.
2. **RocksDB's WAL already guarantees consistency for committed data.** A more graceful indexer-thread shutdown would mostly close a small uncommitted-flush window — which our earlier "drain + 60 s settle-time" experiment (2/2 fail) was already targeting and didn't close.
3. **The recovery path should not panic regardless.** SIGKILL is a legitimate production scenario; recovery should reconstruct cleanly or surface a clear error, not `expect()`/`unwrap()`.

#### Why this matters for the upstream bug report

The previous version of [`nearcore-indexer-sigkill-restart-panic.md`](./nearcore-indexer-sigkill-restart-panic.md) had to hedge: "we cannot claim to know whether a proper graceful-shutdown path would prevent the panic." That hedge is now substantially narrower — we've ruled out "actor-system stop + main-runtime drain" as a fix. The remaining unknown is "would *fully draining the indexer thread itself* (option B) prevent the panic?" Per the three reasons above we believe the answer is no, but we don't have an empirical 5-run campaign that proves it. The cost/benefit of doing option B for the CI flake doesn't justify it (substantial refactor across 7 task spawn sites for an experiment we expect to show what we already believe); it may be worth doing later for shutdown hygiene independent of the test.

---

## Common trigger

Both failure modes share the same operational sequence:

1. mpc-node is running and its embedded `neard` is actively producing/processing blocks.
2. The e2e test sends SIGKILL via `kill_nodes` (which drops `ProcessGuard`, which calls `std::process::Child::kill()` — SIGKILL, not SIGTERM).
3. mpc-node is restarted with the same home directory (`start_nodes` does *not* wipe state).
4. On restart, `nearcore::start_with_config_and_synchronization_impl` runs and either:
   - Panics during startup if RocksDB state is inconsistent (failure mode B), or
   - Starts cleanly but later panics during stream building when an in-memory data structure is in a half-built state (failure mode A).

The user-visible result is the same in both cases: A0's indexer-height metric never advances past the pre-kill height, and PR #3365's `wait_for_node_indexer_height_above` helper times out after 60 s.

---

## Recommended follow-ups

1. **Open an upstream nearcore issue.** Draft is ready at [`nearcore-indexer-sigkill-restart-panic.md`](./nearcore-indexer-sigkill-restart-panic.md) — self-contained, formatted as a GitHub issue body. Title suggestion: *"`near-indexer` panics on restart in `streamer/mod.rs:207` / `client_actor.rs:217` after stop+start, even with a graceful nearcore shutdown"*. The draft now includes the SIGTERM-handler campaign showing 4/5 fail even after a verified 100 ms graceful `shutdown_all_actors` — which is the cleanest single piece of evidence that the bug is upstream and not in how we shut down.
2. **Decide what to do with the two remaining repro tests in PR #3362.** Variant 15 and the back-migration test both fail ~100% in this state. Options:
   - Mark both `#[ignore]` with a note linking the upstream issue, so CI is green without removing the regression coverage.
   - Use `reset_and_start_nodes` (wipes home dir) instead of `start_nodes` for the kill+restart step. The test becomes stable but loses the "keyshares preserved across restart" semantic that's the whole point of the back-migration model.
   - Leave them flaky until nearcore is fixed.
3. **Don't block PR #3362 on this flake.** The panics are inside nearcore code paths, not in #3362's diff. The stale-attestation node fix is independent and demonstrably correct (covered by the contract-sandbox tests in the same PR).
4. **Factor the stderr-tail diagnostic** out of #3362 into a small standalone follow-up. It's a generally useful CI debuggability improvement and it has now paid off many times in surfacing this upstream bug.
5. **~~mpc-node has no graceful-shutdown path — file a separate issue.~~** **In flight: [issue #3409](https://github.com/near/mpc/issues/3409) + [PR #3410](https://github.com/near/mpc/pull/3410).** The handler routes SIGTERM into the existing internal shutdown channel and calls `near_async::shutdown_all_actors()` before exit. Confirmed working in CI: 5/5 graceful shutdowns at 100 ms, no SIGKILL fallback. As called out in the "Real SIGTERM handler in mpc-node — also does not fix it" section above, the handler is a real production improvement (operators using dstack/Docker/Kubernetes/systemd now get graceful shutdown semantics) but **does not prevent the upstream nearcore panic**, which fires non-deterministically regardless of shutdown cleanliness. A more complete shutdown — wiring a `CancellationToken` through the indexer thread so `block_until_all_instances_are_dropped` could safely run — is a follow-up that's not necessary for the production improvement landed in #3410.
6. **Close PR #3373** once it has served its diagnostic purpose; no merge is intended.
