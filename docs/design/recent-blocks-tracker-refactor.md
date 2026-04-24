# RecentBlocksTracker / PendingRequests refactor — issues, assessment, and PR plan

Working document for the branch `kd/share-recent-blocks-tracker-between-queues`.
Captures: the issues raised, what the code actually shows, whether the
branch is needed, a draft GitHub issue description, and a proposed
incremental PR split.

## Context

On `main`, the node runs three independent queues (`PendingRequests<_, _>`):
signatures, CKDs, verify-foreign-tx. Each queue **owns its own
`RecentBlocksTracker<BufferedBlockData>`**, and every block from the indexer
is fed into all three via
`notify_new_block(requests, completed_requests, block)`.

The tracker's stated job: given blocks from the indexer, classify any
given block hash as one of
`RecentAndFinal | NotIncluded | OptimisticAndCanonical | OptimisticButNotCanonical | Unknown | OlderThanRecentWindow`.
A pure view over the local chain topology.

## Issues raised

1. **Three queues × three trackers** (duplication).
2. **Leaky abstraction**: the tracker knows about MPC-peer-network state
   (`maximum_height_available` fed from peer indexer heights) and about
   queue state (generic `T` + `node_to_content` buffer for request lists).
3. **`queue.rs:486`** — leader attempts start on `CheckBlockResult::Unknown`.
4. **Failed-as-leader removal** — on `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`
   we delete the `QueuedRequest` from the queue; user's concern was this
   also blocks our ability to participate as a non-leader when asked.
5. **Submitting before finalization** — leader attempts also start on
   `CheckBlockResult::OptimisticAndCanonical`, which is not yet final.
6. **Test refactor** (commit `e4a2ece8`) — may or may not belong here.

## Verification — what the code actually shows

### 1. Three queues × three trackers — REAL
- `main`: `mpc_client::monitor_block_updates` constructs three
  `PendingRequests`; `queue.rs:274` calls
  `RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS)` in the constructor.
  Each tracker replays the full block stream.
- Branch: `crates/node/src/mpc_client.rs:201` constructs one tracker,
  feeds it via `add_block` once per block, and passes
  `&recent_blocks_tracker` into `get_requests_to_attempt` for each queue.

Verdict: real duplication, branch's fix is clean.

### 2. Leaky abstraction — REAL, cleanly fixed on branch
- **Block content leak.** `RecentBlocksTracker<T>` on main stores
  `node_to_content: HashMap<CryptoHash, T>`; `T = BufferedBlockData {
  requests, completed_requests, timestamp_received }`. The tracker's
  `AddBlockResult` exposes a stream of `(finalized_height, T)` so the
  queue can GC completed requests when finality arrives. This is queue
  state living inside the tracker.
- **MPC-mesh height leak.** On main,
  `PendingRequests::get_requests_to_attempt` calls
  `recent_blocks.notify_maximum_height_available(max_peer_indexer_height)`
  with the max height across **alive MPC peer participants**, not the
  local indexer. `maximum_height_available` is then used by
  `classify_block` to decide what's "recent enough" to be `Unknown` vs
  `OlderThanRecentWindow`. `classify_block` on main takes `(hash, height)`;
  the `height` argument is a direct consequence of this leak.
- **Branch.** `RecentBlocksTracker` becomes non-generic.
  `notify_maximum_height_available` is deleted.
  `maximum_height_available` grows only via `add_block` (local indexer
  only). `classify_block` drops its `height` arg; `Unknown` now means
  "hash not in `hash_to_node`" — a clean local property. Queue instead
  tracks `response_blocks: Vec<SubmittedResponse>` per `QueuedRequest`
  and reclassifies each one on every tick.

Verdict: real abstraction-boundary violations; branch's shape is correct.
These are the specific leaks that would block relocating the tracker into
`chain-gateway`.

### 3. Acting on `Unknown` — REAL, flagged but not fixed
- `main` and branch both have the match arm
  `RecentAndFinal | OptimisticAndCanonical | Unknown => { start leader attempt }`.
- Branch comments this with
  `// todo: we participate in "unknown", which is prolly not ideal.`
  (queue.rs:482-486) but keeps the behavior.
- The semantics of `Unknown` get strictly cleaner on branch (see §2), so
  the fix for this issue (drop `Unknown` from the leader arm) is easier
  to land after the refactor.

### 4. Failed-as-leader removal — REFUTED as stated; code smell remains
User's stated consequence: "we might reject when we get asked to
participate in a request later." Not true. Verified by tracing the
passive-participant path:

- ECDSA follower: `providers/ecdsa/sign.rs:134` → `sign_request_store.get(id)`.
- CKD follower: `providers/ckd/sign.rs:93` → `ckd_request_store.get(id)`.
- VerifyForeignTx follower: `providers/verify_foreign_tx/sign.rs:106` →
  `verify_foreign_tx_request_store.get(id)`.

All three stores are persistent, DB-backed (`crates/node/src/storage.rs`),
and expose only `new / add / get` — **no delete method**. Queue removal
(`self.requests.remove(&id)`) is strictly in-memory and does not cascade.
A leader that gave up after 10 attempts still serves as a follower if
another leader pings it.

**The in-branch TODO at `queue.rs:492-496` that claims otherwise is
itself wrong and should be deleted.** The comment is the main reason this
sounded scary — the underlying behavior is fine.

Residual code smell: using "gave up as leader" as the GC signal conflates
two concerns (retry logic vs. lifetime). Worth a follow-up, but not a
bug. Not in scope of this refactor.

### 5. Submitting before finalization — REAL, flagged but not fixed
- Same match arm as §3: `OptimisticAndCanonical` starts a leader attempt.
  If the block dies on a fork, we've wasted compute + a failed tx (the
  contract will reject a response to a receipt that never made the
  canonical chain).
- Not a "sign the wrong thing" bug — it's a wasted-work bug. Still
  worth fixing post-refactor: narrow the leader-start arm to
  `RecentAndFinal` only.

### 6. Test refactor (`e4a2ece8`) — MIXED
- **Mechanical:** adapts tests to the new
  `notify_new_block(Requests { block, requests, completed_requests })`
  signature introduced in the earlier commit. Required once the signature
  lands; not optional.
- **Cleanup:** extracts a `TestRequestFactory` trait to DRY up
  `test_sign_request` / `test_ckd_request`. Orthogonal — can land on its
  own.
- Does **not** migrate tests into the
  `<system_under_test>__should_<assertion>()` convention documented in
  `docs/engineering-standards.md`. That's a separate codebase-wide pass.

## Is the branch needed?

**Yes.** Issues 1, 2, 3, 5, 6 are real; the branch's structural direction
is correct. Issue 4 as stated is refuted, but the misleading TODO the
branch author left in `queue.rs:492-496` is itself worth removing.

The branch also *unlocks* the downstream correctness follow-ups: once
the tracker is a pure local-chain-view component with well-defined
`Unknown` semantics, narrowing the leader-start arm to `RecentAndFinal`
becomes a small PR.

Correctly scoped *not* to fix issues 3 and 5 here — those changes need
their own tests and their own review.

## Draft GitHub issue description

> **Title:** Refactor: decouple RecentBlocksTracker from PendingRequests and share one tracker across queues
>
> ### Problem
>
> The node runs three request queues — signatures, CKDs, verify-foreign-tx
> — and each currently owns its own `RecentBlocksTracker<BufferedBlockData>`
> (`crates/node/src/requests/queue.rs`, `PendingRequests::new`). The
> tracker's job is to take blocks from the indexer and classify any
> given block hash as Final / OptimisticAndCanonical /
> OptimisticButNotCanonical / Unknown / NotIncluded / OlderThanRecentWindow
> — a pure view over the local chain.
>
> Two problems follow from the current shape:
>
> 1. **Duplication.** All three trackers see the same indexer stream and
>    maintain the same tree; we pay 3× the memory and 3× the per-block
>    work.
>
> 2. **Leaky abstraction.** The tracker is coupled to queue-request
>    semantics in two places that do not belong in "classify a block":
>
>    a. The generic type parameter `T` and `node_to_content: HashMap<CryptoHash, T>`
>       buffer, used so that the tracker's finalized-block stream can hand
>       the queue back `BufferedBlockData` (request IDs, completion lists,
>       timestamps). Queue state, not chain state.
>
>    b. `notify_maximum_height_available(peer_max_height)`, called from
>       `PendingRequests::get_requests_to_attempt` with the max indexer
>       height across alive **MPC peer participants**. This lets MPC-mesh
>       state bleed into a component that should only reflect our local
>       indexer view. As a consequence, `classify_block` takes `height`
>       as an argument; that argument becomes redundant once the mesh-height
>       leak is removed.
>
> These leaks block any future relocation of the tracker (e.g. into the
> `chain-gateway` crate, which already owns a notion of local chain state).
>
> ### In scope
>
> - One `RecentBlocksTracker` owned by `mpc_client::monitor_block_updates`,
>   borrowed into each `PendingRequests::get_requests_to_attempt` call.
> - `RecentBlocksTracker` is non-generic, has no queue-request data in it,
>   and receives only local indexer blocks via `add_block`.
>   `classify_block` takes just `CryptoHash`.
> - Queue tracks its own response-block observations
>   (`response_blocks: Vec<SubmittedResponse>` per `QueuedRequest`) and
>   classifies them on each tick.
> - Existing leader-selection behavior preserved.
>
> ### Out of scope — follow-up issues to file
>
> While working here we observed three correctness follow-ups in the same
> file that should be tracked separately:
>
> - Leader attempts start on `CheckBlockResult::Unknown`
>   (`queue.rs:482-486`). A block we've never seen should not drive our
>   submission logic.
> - Leader attempts start on `CheckBlockResult::OptimisticAndCanonical` —
>   i.e. before the request-block is final. A fork kills the block and
>   we submit to a request that never made the canonical chain (wasted
>   compute + failed tx).
> - On `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER` we delete the `QueuedRequest`.
>   A TODO in the same file claims this also breaks passive-participant
>   response; that claim is **wrong** — follower paths
>   (`providers/ecdsa/sign.rs`, `providers/ckd/sign.rs`,
>   `providers/verify_foreign_tx/sign.rs`) look up persistent
>   `SignRequestStorage` / `CKDRequestStorage` /
>   `VerifyForeignTransactionRequestStorage`, not the queue. The comment
>   should be rewritten. The underlying code smell (using "gave up as
>   leader" as the GC signal) is polish, not a bug.
>
> ### Approach
>
> See attached PR split — six small PRs, each independently reviewable and
> build/test-green.

## Incremental PR split

Each PR compiles and has tests green on its own; each is reviewable in
one sitting.

### PR 1 — Extract `FromChain` trait + `Requests<T>` struct  (S)
- Move request construction (SignatureRequest / CKDRequest /
  VerifyForeignTxRequest) out of `mpc_client::monitor_block_updates` into
  a `FromChain<T>` trait in `types.rs`.
- Introduce `Requests<T>` + `Requests::from_chain` helper.
- Keep `notify_new_block`'s current parameter shape by adapting at the
  call site. No queue or tracker changes.
- Touches: `crates/node/src/mpc_client.rs`, `crates/node/src/types.rs`.
- Green because: pure code motion.

### PR 2 — Change `notify_new_block` to take `Requests<T>`  (M)
- Adopt the `Requests { block, requests, completed_requests }` parameter
  on all three queues.
- Port the mechanical test adjustments from `e4a2ece8`.
- Leave `test_sign_request` / `test_ckd_request` duplicated —
  `TestRequestFactory` extraction ships in PR 6.
- Depends on: PR 1.
- Touches: `crates/node/src/mpc_client.rs`, `crates/node/src/requests/queue.rs`.
- Green because: 1-to-1 translation of existing call sites; semantics unchanged.

### PR 3 — Share one `RecentBlocksTracker`  (M; S1 in the plan)
- Construct the tracker in `mpc_client::monitor_block_updates`, pass
  `&RecentBlocksTracker` into `get_requests_to_attempt`, drive
  `add_block` from `mpc_client`.
- Tracker internals untouched: `T` / `node_to_content` stay,
  `notify_maximum_height_available` stays, `classify_block(hash, height)`
  stays. Strictly physical sharing.
- Depends on: PR 2.
- Touches: `crates/node/src/mpc_client.rs`, `crates/node/src/requests/queue.rs`.
- Green because: three ex-owners were fed identical streams; one owner is
  behaviorally equivalent.

### PR 4 — Remove `T` generic; classify per tick  (L; S2a — the unavoidable big one)
- Delete `node_to_content`, `BufferedBlockData`,
  `AddBlockResult.removed_blocks`.
- Add `response_blocks: Vec<SubmittedResponse>` per `QueuedRequest`.
- Move the `*_LATENCY_BLOCKS` / `*_LATENCY_SECONDS` emission to
  finality-detection time inside the tick loop.
- Keep `*_FINALIZED_BLOCKS_INDEXED` metric with `#[expect(dead_code)]` —
  retire in a separate dashboards PR, not here.
- Depends on: PR 3.
- Touches: `crates/node/src/requests/queue.rs`,
  `crates/node/src/requests/recent_blocks_tracker.rs`.
- Green because: "any observed response block reaching finality completes
  the request" is a strict superset of "the one buffered response block
  reaching finality completes the request" for all non-fork paths, which
  is what tests cover.

### PR 5 — Remove peer-network height from the tracker  (S; S2b)
- Delete `notify_maximum_height_available`; `maximum_height_available`
  grows only via `add_block`; drop `height` arg from `classify_block`.
- Queue still computes `max_peer_indexer_height` from
  `NetworkAPIForRequests` for its own use (timeout window); the tracker
  just stops knowing about it.
- Depends on: PR 4.
- Touches: `crates/node/src/requests/queue.rs`,
  `crates/node/src/requests/recent_blocks_tracker.rs`.

### PR 6 — Test cleanup + comment hygiene  (S; optional)
- Extract `TestRequestFactory` trait from `e4a2ece8`.
- Delete the incorrect TODO at `queue.rs:492-496` (passive-participant
  claim is wrong).
- Reword the `Unknown` TODO at `queue.rs:482-486` so it records a real
  follow-up instead of a hedge.
- Touches: `crates/node/src/requests/queue.rs` only (tests + comments).

### Follow-up issues — file separately, NOT in this series
- Narrow the leader-start arm to `RecentAndFinal` only (fixes issues 3 and 5).
- Decouple "gave up as leader" from "GC the `QueuedRequest`" (code smell).
- Consider relocating `RecentBlocksTracker` into the `chain-gateway`
  crate now that its dependencies are purely local.

### Rejected alternative orderings

- *Semantic change first, then share* (PR 4 before PR 3): forces the new
  classification path through three copies of the tracker. Strictly harder
  to review; no upside.
- *One mega-PR for S1 + S2*: PR 4 alone is already the reviewer
  bottleneck; folding S1 into it pushes past one-sitting reviewable and
  eliminates a clean revert boundary for the shared-tracker change.

## Scope-creep traps to resist

1. Fixing `Unknown` / `OptimisticAndCanonical` in this series.
2. Rewriting the `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER` GC path.
3. Renaming/removing dashboards-facing metrics.
4. Committing this file or the `libs/nearcore` submodule bump with any of
   these PRs (both in the current working tree, both unrelated).
5. Adding `TestRequestFactory` to PR 2 "while the file is already open".

## Verification — per PR

- `cargo make check-all-fast`
- `cargo nextest run --cargo-profile=test-release -p mpc-node requests::`
- `cargo clippy --all-targets --locked -- -D warnings`
- After PR 3 and PR 4: compare `{:?}` debug output of
  `RecentBlocksTracker` on a representative indexer replay before/after
  (no-behavior-change gate).
- After PR 5: hand-verify that `maximum_height_available` no longer
  diverges from the local indexer tip under a peer-lag scenario in the
  fake-indexer harness at `crates/node/src/indexer/fake.rs`.
