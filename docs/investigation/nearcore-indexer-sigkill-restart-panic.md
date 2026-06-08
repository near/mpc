# near-indexer: SIGKILL + restart panic in `streamer/mod.rs:207` and `client_actor.rs:217`

## TL;DR

A process embedding `near-indexer`, when stopped during normal block production
and then restarted against the same `home_dir`, **panics on restart ~65–80% of
the time** in a specific operational scenario we've isolated. The panic is
inside `near-indexer` / `near-client`. We've tried every approach reasonably
available to the embedder — SIGTERM with a real handler that signals
`shutdown_all_actors()`, the indexer thread fully drained (its tokio runtime
dropped, every `Arc<RocksDB>` released, `RocksDB::block_until_all_instances_are_dropped()`
returns), consumer-side drain, settle-time delays — **none of them prevent
the panic** at a meaningful rate. The panic site reads state that was written
during normal block production (not during shutdown), so the fix needs to be
in nearcore's recovery path, not in how embedders stop the process.

This was discovered during end-to-end testing of NEAR's MPC node
back-migration flow (A → B → A), which by design requires stopping the
old participant node and then restarting it before the back-migration
round.

## Operational impact

This is not a test-only flake. We hit it via an e2e test, but the underlying
operational scenario is real production:

- Operator-initiated node restarts (container/orchestrator stop: `docker stop`,
  `kubectl delete`, `systemctl stop`, dstack CVM stop) — every such restart
  carries this panic risk on the next start.
- OOM kills, container evictions, host hardware faults, kernel panics — same.
- For a TSS network like NEAR's chain-signatures MPC cluster, where every
  participating node embeds `near-indexer` to watch the on-chain signer
  contract, a restart that lands on this panic takes one signer out of the
  threshold for as long as it takes the operator to manually clear state
  (which loses keyshare-preservation guarantees the production flow relies on).

## Affected versions

- nearcore tag **`2.12.0`** (final) — resolved commit `1144e31`. Mode-A panic
  reproduced on the rebased near/mpc#3362 branch in a CI run on commit
  `3a2ceafe`; the panic backtrace is inlined in the test failure message
  via the diagnostic in [near/mpc#3362](https://github.com/near/mpc/pull/3362).
- nearcore tags **`2.12.0-rc.1`** and **`2.12.0-rc.2`** — earlier investigation.
  Specific resolved commits we observed the panic on: `aab31b0e` and `fadb5c1`
  (both within the `2.12.0-rc.1` tag at different points after a `Cargo.lock`
  bump in our workspace).
- The panic-site code in `chain/indexer/src/streamer/mod.rs:207` and
  `chain/client/src/client_actor.rs:217` is **unchanged between `2.12.0-rc.1`
  and `2.12.0` final**. Only `chain/chain/src/{chain,runtime,types}.rs` and
  VM/cache code differ across those tags.

## When this bug is reachable in practice

The panic is reachable from a specific operational pattern, not from arbitrary
SIGKILL+restart. In our setup it requires:

1. **A two-tx pattern**: two function-call transactions in adjacent blocks,
   signed by the same access key, both touching overlapping contract state
   (`tee_state` and the participant set in our case). This is what the
   embedder PR introduces — see "Reproduction via CI" below.
2. **Sustained background activity** during the kill window — both sign and
   CKD-style requests, pre- and post-forward-migration. Drop any one of the
   four and the rate falls from ~70% to ~10–30%; drop two and it's near zero.
3. **SIGKILL or equivalent of the process** (operator restart, OOM kill,
   container eviction, hardware fault, kernel panic).

This is not a contrived test setup. Production operators of TSS networks
that embed `near-indexer` will hit (1) whenever they ship a similar two-tx
pattern, (2) is normal operational background, and (3) happens every time
anyone runs out of memory, reboots a host, etc.

### Reproduction rate: latent on `main`, ~70–80% on near/mpc#3362

The same back-migration e2e test exists on both `main` and on
[near/mpc#3362](https://github.com/near/mpc/pull/3362):

| Branch | Trigger present? | Fail rate observed |
|---|---|---|
| `main` | No | **rarely** — single-digit %, very occasional failures the team has not been able to attribute, no consistent panic stack |
| near/mpc#3362 (`barak/2121-contract-stale-attestation-test`) | Yes | **~70–80%** — every failure carries the same mode-A panic stack at `streamer/mod.rs:207` (or, less commonly, mode B at `client_actor.rs:217`) |

The qualitative difference between "rare and shapeless" on `main` and
"frequent with a consistent stack" on near/mpc#3362 is the load-bearing evidence
that the trigger (the two-tx pattern added by near/mpc#3362's
`submit_attestation_before_concluding_migration` function) is what makes
this nearcore race reliably reachable. Once near/mpc#3362 merges, every CI run
of this test on `main` will be at the ~70–80% rate — i.e. the panic will
become the dominant cause of test failure in this file.

## Symptoms — two distinct panic modes

Both modes share the same trigger (SIGKILL + restart with the chain in a
certain state) and the same user-visible result (the embedding process exits
on restart). Internal stack frames differ.

### Mode A — `streamer/mod.rs:207` (most common, ~70% of failures we see)

```
thread 'tokio-rt-worker' (886644) panicked at
  /home/runner/.cargo/git/checkouts/nearcore-86558fdb18093f53/aab31b0/chain/indexer/src/streamer/mod.rs:207:42:
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
```

The `.expect("receipt must be present at this moment")` at
`chain/indexer/src/streamer/mod.rs:207` fires inside `build_streamer_message`'s
`.fold` over a receipt collection — the indexer expects every receipt ID it
references to be in its in-memory tracking map, and one is missing.

### Mode B — `client_actor.rs:217` (rarer, on-disk inconsistency)

```
thread '<unnamed>' (749092) panicked at
  /home/runner/.cargo/git/checkouts/nearcore-86558fdb18093f53/aab31b0/chain/client/src/client_actor.rs:217:6:
called `Result::unwrap()` on an `Err` value:
  Chain(StorageError(StorageInconsistentState(
    "No ChunkExtra for block 4cqR4KRwGv92jgnsFLzmJvDdNy7hj5JGUak8nY1tWsVu in shard s0.v0"
  )))
stack backtrace:
   0: __rustc::rust_begin_unwind
   1: core::panicking::panic_fmt
   2: core::result::unwrap_failed
   3: near_client::client_actor::start_client
   4: nearcore::start_with_config_and_synchronization_impl::{{closure}}
   5: mpc_node::indexer::real::spawn_real_indexer::{{closure}}::{{closure}}
   6: tokio::runtime::runtime::Runtime::block_on
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
```

The `unwrap()` at `chain/client/src/client_actor.rs:217` fires during
`start_client` because RocksDB is missing a `ChunkExtra` record the recovery
code expects to find.

## Reproduction

The bug is reachable from near/mpc PR [near/mpc#3362](https://github.com/near/mpc/pull/3362),
which adds a node-side fix for an unrelated issue (near/mpc#2121 — stale attestation in
back-migration). The fix happens to produce a transaction pattern that makes
the underlying nearcore receipt-graph race reach a ~70–80% per-run repro rate.
near/mpc#3362 is still open at time of filing; the repro therefore lives on its
branch.

### Failing test

A single test fires the bug:

- **Test:** `migration_service__should_handle_back_migration_a_to_b_to_a`
- **File:** `crates/e2e-tests/tests/migration_service.rs`
- **What it does:** Sets up a 2-of-2 MPC cluster (A0, A1) plus a back-migration
  target B0. Performs forward migration A0 → B0 (this submits the two-tx
  pattern from the trigger). Then SIGKILLs A0 and restarts it. Then performs
  back-migration B0 → A0.
- **Symptom of the bug:** When A0 is restarted (step "Stop A0 + start A0"),
  its `near-indexer` panics with mode A (or rarely mode B) and the process
  exits. The test's `wait_for_node_indexer_height_above` polls A0's
  `indexer_latest_block_height` Prometheus metric for 60s, never sees it
  advance past the pre-kill height (because the indexer is dead), and times
  out at `migration_service.rs:771` with:
  ```
  A0's indexer did not resume + advance within 60s after restart:
    node 0 indexer did not advance past height N within 60s
  ```
- **Test runtime:** ~100–110s on a failing run, ~50–60s on a passing run.

### Reproduction via CI

The easiest way to reproduce is to push to near/mpc#3362's branch and let GitHub
Actions run the test. CI builds everything from scratch and runs the test
once; you can get N data points by pushing N times.

```bash
# 1. Authorize a push to near/mpc#3362 or create a sister branch.
git clone git@github.com:near/mpc.git
cd mpc
git checkout barak/2121-contract-stale-attestation-test    # head of near/mpc#3362
git push origin HEAD:refs/heads/my-repro-branch            # forks to a branch you own
gh workflow run CI --ref my-repro-branch                   # triggers the CI workflow

# 2. Watch the run.
gh run watch <run-id>

# 3. On failure, the test panic message inline-dumps the failing node's
#    pre-restart stdout, pre-restart stderr, post-restart stdout, and
#    post-restart stderr (each 16 KB). The upstream panic stack appears in
#    the post-restart stderr.log block. Search the job log for:
#
#       last 16KB of node 0 stderr.log (post-restart stderr; upstream
#       nearcore panic stack typically here)
#
#    or just `streamer/mod.rs:207` to jump right to the panic site.
```

### Local reproduction

```bash
git clone git@github.com:near/mpc.git
cd mpc
git checkout barak/2121-contract-stale-attestation-test
# Branch shape: stacked on near/mpc#3410 (SIGTERM handler) + near/mpc#3486
# (full indexer drain). The trigger is on top as commit `0c02d27a`.
# nearcore is resolved to 2.12.0 (final) via main's Cargo.lock.

# Build the e2e test binaries (~5 min cold).
cargo make e2e-tests-skip-build  # builds then skips on subsequent runs

# Run just the failing test:
cargo nextest run --cargo-profile=test-release -p e2e-tests --all-features \
  --locked --profile ci-e2e \
  migration_service__should_handle_back_migration_a_to_b_to_a

# Expected: fails ~70–80% with the mode-A panic on restart. On the rare
# pass, the run finishes in ~50–60 s. On fail, ~100–110 s (the test
# waits 60 s for the indexer to recover before giving up).
```

### What this PR adds that makes the bug strongly reproducible

The relevant change is in
[`crates/node/src/tee/remote_attestation.rs`](../../crates/node/src/tee/remote_attestation.rs)
(see commit `1bcbb439` titled
`fix(node): refresh attestation before concluding back-migration (#2121)`).
It adds a function `submit_attestation_before_concluding_migration` that's
called from `execute_onboarding` just before `retry_conclude_onboarding`:

```rust
// Submit a fresh on-chain attestation before concluding migration.
pub async fn submit_attestation_before_concluding_migration(
    tee_authority: TeeAuthority,
    tx_sender: impl TransactionSender,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
) -> anyhow::Result<()> {
    let report_data: ReportData = ReportDataV1::new(...).into();
    let attestation = tee_authority.generate_attestation(report_data).await?;
    submit_remote_attestation(tx_sender, attestation, tls_public_key).await
}
```

This produces a `SubmitParticipantInfo` transaction from node B0's signer
key, which lands in chain just before B0 signs a `ConcludeNodeMigration`
transaction in the *next* block. Both are signed by the same access key and
write to overlapping contract state (`tee_state` and the participant set).

#### Revert experiment isolating this change

We opened PR
[`#3373`](https://github.com/near/mpc/pull/3373) (a `chore:` PR that
**reverts only `1bcbb439`**, leaves everything else identical) and ran the
same back-migration test 5 times: **0/5 failed.** Reverting that single
commit takes the bug from ~65–70% to 0%. The commit doesn't touch
nearcore code paths; it's just the trigger.

## What we ruled out (none of these prevent the panic)

| Approach | Sample | Outcome | What we learned |
|---|---|---|---|
| Plain SIGKILL | 17 obs | ~65% fail | baseline |
| Smaller activity profiles (1-of-4, 2-of-4 sign/CKD TXs) | 50+ obs | ~0% fail | a specific 4-of-4 activity profile is needed |
| 3-of-4 activity profiles | 30 obs | ~10–30% fail | partial — the full 4-of-4 is what reaches ~70% |
| SIGTERM with 30s grace period, no handler in mpc-node | 2 obs | 2/2 fail | mpc-node had no SIGTERM handler, so SIGTERM was effectively SIGKILL |
| Drain consumer (pause `listen_blocks.flag`) then SIGKILL | 5 obs | 5/5 fail | the panic is producer-side (`streamer::start`), not consumer-side |
| Drain + 60s sleep before SIGKILL | 2 obs | 2/2 fail | rules out "writes still settling" — the bug isn't recent-write timing |
| **SIGTERM with handler installed, mpc-node main-runtime + `shutdown_all_actors()` complete in 100 ms** | **5 obs** | **4/5 fail** | **graceful actor-system shutdown does NOT prevent the panic** (caveat: indexer thread itself still terminated mid-flight — see below) |

The cumulative evidence is that **no test-side teardown change prevents the
panic.** We've now tried five different kill strategies, including real
graceful shutdown. All fail at meaningful rates. The bug is in nearcore's
recovery path, not in how the embedding shuts down.

### Strongest evidence: actor-system shutdown doesn't help

The earlier version of this document noted that our SIGTERM experiments
couldn't distinguish "graceful shutdown doesn't fix it" from "mpc-node has no
SIGTERM handler so we never actually tested graceful shutdown." We've now
closed most of that gap, though one slice remains open — see "Caveat" below.

We installed a SIGTERM handler in mpc-node that routes into the existing
internal shutdown channel and calls `near_async::shutdown_all_actors()`
before exit (commit landed in [near/mpc#3410](https://github.com/near/mpc/pull/3410)
on near/mpc, addressing [issue #3409](https://github.com/near/mpc/issues/3409)).
With this handler, the diagnostic emits `mpc-node pid=X exited gracefully
100ms after SIGTERM` in 5/5 observed runs — nearcore's actor system was given
a stop signal and the process exited within 100 ms.

Re-running the back-migration test five times against this handler:

- **1/5 passed** the full e2e flow (including the kill+restart).
- **4/5 failed** with the same `streamer/mod.rs:207` `` `receipt` must be
  present at this moment `` panic on restart, identical stack to plain
  SIGKILL.

Pass rate is statistically indistinguishable from plain SIGKILL on the same
test (small samples on both sides, but the central tendency is identical).

#### Caveat — what "graceful 100 ms" actually covers

Important precision for anyone reviewing this: the 100 ms graceful shutdown
covers **mpc-node's main runtime path** and a **stop signal sent to nearcore's
actor system** (`near_async::shutdown_all_actors()` returns synchronously
after signaling stop, it does not wait for actors to finish). It does **not**
cover the embedded indexer thread.

mpc-node embeds `near-indexer` in a separate `std::thread::spawn`'d closure
with its own tokio runtime. That runtime hosts:

- `near_indexer::streamer::start`'s `build_streamer_message` loop (the one
  that panics on restart), and
- ~6 `tokio::spawn`'d monitor tasks each holding `Arc<IndexerState>` →
  `Arc<RocksDB>` references.

Nothing in our handler propagates a cancellation into that runtime; the
spawned tasks keep running, the outer `block_on` never returns, and the
thread is terminated by the OS when mpc-node's process exits ~100 ms after
SIGTERM. So this experiment shows that **stopping nearcore's actor system
cleanly does not prevent the panic** — it does not yet show that *fully
draining the indexer thread* would also not prevent it.

We did initially try to drain it: the first version of the handler also
called `near_store::db::RocksDB::block_until_all_instances_are_dropped()`
after `shutdown_all_actors()` (which is what neard's standalone binary
does), but it **hung indefinitely** waiting for the indexer thread's
Arc<RocksDB> refs to drop. The 60 s test grace expired, the orchestrator
SIGKILLed us, and we landed back at the SIGKILL baseline.

#### Why we still believe the bug is upstream

Even granting the caveat, the panic mechanism doesn't depend on shutdown
draining:

1. **The panic site reads state written during normal block production.**
   `build_streamer_message`'s `.fold` panics because a receipt it references
   is missing from the in-memory tracking map. That map is rebuilt from
   RocksDB on restart. The "missing receipt" was written (or was about to be
   written) during normal block production *before* shutdown — not during
   shutdown itself.
2. **RocksDB's WAL already guarantees consistency for committed data.** Any
   batch nearcore committed via the WAL survives a kill. The only data lost
   to a kill is data that hadn't been flushed yet. A more graceful indexer
   shutdown would mostly close that small flush window — which our drain
   + 60 s settle-time experiment (2/2 fail) already failed to close.
3. **Recovery shouldn't panic regardless of how the previous run ended.**
   SIGKILL is a legitimate production scenario (OOM kill, container
   eviction, hardware fault, kernel panic). The `.expect("receipt must be
   present at this moment")` and `client_actor.rs:217`'s `unwrap()` aren't
   correctness — they're load-bearing assumptions about prior-state
   consistency that don't hold across an interrupted process. Robust
   recovery would either reconstruct cleanly or surface a clear error; it
   shouldn't `panic!`.

In other words: graceful shutdown of the indexer thread is a thing worth
doing for hygiene (and may close a small remaining slice of the failure
rate), but the **structural issue is in the recovery path**. The fix needs
to land in nearcore.

#### Production framing

Independent of the bug, the SIGTERM handler is a legitimate production
improvement — operators using dstack CVM stop / `docker stop` / `kubectl
delete` / `systemctl stop` previously had SIGTERM functionally equivalent
to SIGKILL; the handler gives them real graceful main-runtime shutdown
semantics. It just doesn't fix this particular upstream bug. SIGKILL also
remains a legitimate production scenario regardless of how clean the
graceful path is.

## Concrete operational trigger

Reduced to the simplest description we could derive:

1. A process embedding `near-indexer` is running and consuming blocks normally.
2. Two function-call transactions land in **adjacent blocks**, **signed by the
   same access key**, with the additional context that **both touch overlapping
   contract state** (`tee_state` and the participant set in our case).
3. Optionally, surrounding activity (other sign / CKD transactions from other
   signers around the same window) increases the failure rate from
   background-level to ~70%.
4. SIGKILL the process.
5. Restart the process against the same `home_dir`.
6. The indexer panics on restart — mode A (typical) or mode B (occasional).

Without step 2, the bug is unreachable in our test (focused-repro matrix:
0/9 fail). With step 2 but without step 3, the bug reproduces only
occasionally. With both, it reproduces ~70%.

## Hypothesis

Mode A's panic site is inside `build_streamer_message`'s `.fold` over a
receipt collection, with the `.expect("receipt must be present at this
moment")` indicating a referenced receipt isn't in the in-memory map.

The most parsimonious explanation we've found:

1. Block N contains B0's `SubmitParticipantInfo` TX. Its execution emits a
   receipt that gets applied in block N+1.
2. Block N+1 contains B0's `ConcludeNodeMigration` TX and the receipt from N.
   Both touch the same contract state region (`tee_state` and participants).
3. nearcore's indexer tracks receipts in an in-memory map as they're produced
   and removes them as they're consumed.
4. RocksDB writes for these two TXs (and their receipts) may not be co-flushed
   atomically. SIGKILL between flushes could persist one but not the other.
5. On restart, the in-memory map is reconstructed from RocksDB — but with a
   gap where the un-flushed receipt would have been.
6. The next `build_streamer_message` call iterates a receipt set referencing
   the absent ID and panics.

Worth checking:

- Are the receipts produced by adjacent same-signer function-call TXs that
  modify the same contract state written into the same RocksDB column family
  with a single flush boundary, or across multiple flush boundaries?
- Does `client_actor::start_client` (mode B's panic site) assume that
  `ChunkExtra` for every block referenced by chain head has been durably
  written before the chunk's processing-output receipts? If so, a SIGKILL
  between those writes could produce the observed `StorageInconsistentState`.

## Workarounds

We don't have a working test-side workaround. Options we evaluated:

- **Install a SIGTERM handler in mpc-node so nearcore's actor system gets a
  clean stop** ([near/mpc#3410](https://github.com/near/mpc/pull/3410),
  [issue #3409](https://github.com/near/mpc/issues/3409)). Real production
  improvement on its own, but **does not** prevent the panic — see the
  "Strongest evidence" section above. 4/5 still fail with the handler.
- **Avoid the kill+restart in our test** — works for our specific test but
  doesn't fix the production scenario (operator decommissions then revives a
  node). We expect to take this option for CI green and file this issue
  separately.
- **Wipe `home_dir` on restart** (`reset_and_start_nodes` already exists for
  this reason — its comment even calls out SIGKILL leaving data corrupt) —
  the test that has a kill+restart pattern goes green at the cost of losing
  the "keyshares survive on disk" assertion. Not viable for our case.

## Logs and supporting evidence

Full failure logs are in CI runs linked from the investigation doc. Examples
that include both panic modes:

- Mode A — [run 26498637558 job 78033060779](https://github.com/near/mpc/actions/runs/26498637558/job/78033060779)
- Mode B — [run 26501678885 job 78043485451](https://github.com/near/mpc/actions/runs/26501678885/job/78043485451)
- 5-run drain-then-kill campaign (5/5 fail) — [run 26569167447](https://github.com/near/mpc/actions/runs/26569167447)
- 2-run option-A settle-then-kill campaign (2/2 fail at ~167s each) — [run 26575144185](https://github.com/near/mpc/actions/runs/26575144185)
- **5-run SIGTERM-handler campaign (4/5 fail, handler completes in 100 ms)** on commit `3527e4d4` — [PR run](https://github.com/near/mpc/actions/runs/26713165138/job/78727019813) (1/5 pass) plus 4 sister-branch runs ([26713169213](https://github.com/near/mpc/actions/runs/26713169213), [26713169682](https://github.com/near/mpc/actions/runs/26713169682), [26713170287](https://github.com/near/mpc/actions/runs/26713170287), [26713170844](https://github.com/near/mpc/actions/runs/26713170844)). Diagnostic line in each failing run: `[E2E-DIAG] mpc-node pid=X exited gracefully 100ms after SIGTERM`, followed by the same `streamer/mod.rs:207` panic on the restarted process.

The CI logs include the failing node's `stderr.log` tail inline in the test
panic message (search for `--- last 16KB of node 0 stderr.log` in any failing
run's log), so the upstream panic stack is right there.

## References

- near/mpc PR exposing the bug: [near/mpc#3362](https://github.com/near/mpc/pull/3362)
- near/mpc revert-experiment PR (isolates the trigger as our two-tx pattern,
  not a defect in our code): [`#3373`](https://github.com/near/mpc/pull/3373) — `chore:` PR
- near/mpc SIGTERM-handler PR (proves that adding a real graceful path on the
  embedder side does NOT prevent the panic): [`#3410`](https://github.com/near/mpc/pull/3410)
- near/mpc indexer-drain PR (proves that fully draining the indexer thread —
  including the `block_until_all_instances_are_dropped()` step neard's
  standalone binary uses — also does NOT prevent the panic): [`#3486`](https://github.com/near/mpc/pull/3486)
