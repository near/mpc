# RecentBlocksTracker / PendingRequests refactor — issues & plan

Working document for the branch `kd/share-recent-blocks-tracker-between-queues`.
Goal: figure out which problems are real, whether the branch is truly needed, and
how to split it into incremental PRs.

## Context

On `main`, the node runs three independent queues (`PendingRequests<_, _>`):
signatures, CKDs, verify-foreign-tx. Each queue **owns its own
`RecentBlocksTracker<BufferedBlockData>`**, and every block from the indexer is
fed into all three via `notify_new_block(requests, completed_requests, block)`.

The tracker's stated job is: "given blocks from the indexer, classify any given
block as (Final / OptimisticAndCanonical / OptimisticButNotCanonical /
NotIncluded / OlderThanRecentWindow / Unknown)." That is a pure view over the
local indexer's block topology.

## Issues reported by the user

1. **Three queues × three trackers.** The tracker is an expensive per-block
   data structure (block tree, content map, finality bookkeeping), and we
   duplicate it three times even though all three queues consume the same
   indexer stream.
2. **Leaky abstraction (tracker knows about the queue).** The tracker on
   `main` carries:
   - `maximum_height_available`, set by the queue from **MPC peer network**
     heights (`notify_maximum_height_available`). That is a property of the
     MPC mesh, not of the local chain view.
   - `node_to_content: HashMap<CryptoHash, BufferedBlockData>` — per-block
     lists of requests / completed requests — so that when the tracker later
     reports a block as final, it can walk the list and tell the queue which
     requests to mark complete. That is queue state.

   Neither belongs in a component whose only job is "assess how likely a
   block from the indexer is to be finalized." The tracker should plausibly
   live in `chain-gateway` one day; the two leaks above would block that move.
3. **`queue.rs:486` — treating `Unknown` blocks as eligible to start as
   leader.** The match arm `RecentAndFinal | OptimisticAndCanonical | Unknown`
   starts a leader attempt on `Unknown`. "Unknown" means "we've never seen
   this block hash" — we should not be acting on requests we cannot place in
   our own view of the chain.
4. **Removing failed-as-leader requests from the queue.** On hitting
   `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`, we call `requests_to_remove.push(id)`
   and drop the request entirely. That also breaks our ability to **respond
   as a passive participant** if another node's leader later asks us to join
   the protocol for the same request.
5. **Submitting before the request block is finalized.** Because the leader
   match arm fires on `OptimisticAndCanonical` (and `Unknown`), we can start
   generating + submitting a response for a request whose request-block is
   still optimistic — so the chain could resolve a different fork and our
   submission targets a request that never existed on the canonical chain.
6. **Test refactor in the branch.** Commit `e4a2ece8 "test refactor"`
   reshapes queue tests; needs a sanity check on whether it belongs here or
   should be split out / dropped.

## Verification status

For each issue, what the code actually shows. (Filled in as I investigate.)

### 1. Three queues × three trackers

**Status:** CONFIRMED on `main`.
- `mpc_client.rs` (main) spins up three `PendingRequests` instances in
  `monitor_block_updates` (signatures, CKDs, verify-foreign-tx).
- `PendingRequests::new` constructs `RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS)`
  (queue.rs:274 on main).
- `monitor_block_updates` calls `pending_signatures.notify_new_block(...)`,
  `pending_ckds.notify_new_block(...)`, `pending_verify_foreign_txs.notify_new_block(...)`
  with the same block, so each tracker independently replays the full block
  stream into its own tree/content map.
- The branch's `mpc_client.rs` already hoists a single tracker out of the
  queues (`let mut recent_blocks_tracker = RecentBlocksTracker::new(...)`;
  the tracker is fed via `recent_blocks_tracker.add_block(&block_update.block)`
  once per block and passed into `get_requests_to_attempt(&recent_blocks_tracker)`).

**Verdict:** real. The cost is three trees + three content maps kept in sync
on every indexer tick, and three sets of block-processing bugs if they ever
diverge.

### 2. Tracker leaks: MPC-network height and block content

**Status:** CONFIRMED on `main`.
- `RecentBlocksTracker` (main) carries `maximum_height_available: BlockHeight`,
  set by the queue in `get_requests_to_attempt` via
  `self.recent_blocks.notify_maximum_height_available(maximum_height)` where
  `maximum_height` comes from `network_api.indexer_heights()` of **peer MPC
  nodes**. It is used to decide what `Unknown` means (any hash above
  `maximum_height_available - window` is plausibly Unknown vs definitively
  NotIncluded/OlderThanRecentWindow).
- `RecentBlocksTracker` is generic in `T: Clone`, instantiated with
  `BufferedBlockData { requests, completed_requests, timestamp_received }`.
  The tracker stores this in `node_to_content: HashMap<CryptoHash, T>` so it
  can emit `AddBlockResult::new_final_blocks: Vec<(height, T)>`. The queue
  uses that to mark completed requests and compute latency metrics.
- The branch removes `T`: `RecentBlocksTracker` becomes non-generic. The
  queue no longer stashes per-block content in the tracker — it tracks
  `response_blocks: Vec<SubmittedResponse>` on each `QueuedRequest` and, on
  every tick, reclassifies those blocks against the tracker to decide
  completion. The `notify_maximum_height_available` call is commented out
  (queue.rs:395 on branch) and the `AddBlockResult.removed_blocks` plumbing
  (used to GC the content map when the tracker pruned blocks) is gone.

**Verdict:** real. Both of these tie the tracker to "queues of MPC signature
requests on an MPC peer network", which blocks any reuse or relocation of the
tracker (e.g. moving it into `chain-gateway`, which already has its own notion
of the local chain view). The branch removes both leaks.

Caveat to verify: whether the commented-out
`notify_maximum_height_available` changes the semantics of `Unknown`. With
the branch's single shared tracker fed straight from the indexer,
`max_height` becomes "max height we've seen locally", which is a strictly
local property and plausibly the right thing. But the distinction between
`Unknown` and `OlderThanRecentWindow` depends on it — flagged for issue (3).

### 3. `queue.rs:486` — acting on `Unknown`

**Status:** CONFIRMED on both `main` and branch.
- `main` queue.rs line ~457: the match arm is
  `RecentAndFinal | OptimisticAndCanonical | Unknown => { ... start leader attempt ... }`.
- Branch queue.rs:482–486: same arm, now annotated
  `// todo: we participate in "unknown", which is prolly not ideal.`
- `Unknown` from `classify_block` means: the block hash is not in
  `hash_to_node`, but the tracker cannot prove it is too old (height within
  window). With the `main`-side injection of peer network height into
  `maximum_height_available`, a block we've literally never heard of can
  be classified `Unknown` because *someone else* has seen height >= this
  block's implied height. On `main` we then happily start a leader attempt
  on such a block.
- Once the branch stops injecting peer height, `maximum_height_available`
  only grows from blocks our own indexer delivered. That reduces (but does
  not eliminate) the window in which `Unknown` fires — `classify_block`
  still returns `Unknown` for hashes we've never seen when the block-hash
  argument happens to fall inside `[max - window + 1, max]` in some other
  interpretation. Need to re-read `classify_block` on the branch to confirm
  the exact conditions.

**Verdict:** real. The branch notes it with a TODO but does not fix it.
Proper fix: drop `Unknown` from the "start as leader" arm; treat it the
same as `OptimisticButNotCanonical` (wait for the block to show up in our
view), or move on entirely if we can prove the block is NotIncluded.

### 4. Removing failed-as-leader requests

**Status:** CONFIRMED on both `main` and branch.
- `main` queue.rs line ~465 and branch queue.rs:497–507: when
  `progress.attempts >= MAX_ATTEMPTS_PER_REQUEST_AS_LEADER` we push the
  request onto `requests_to_remove` and later `self.requests.remove(&id)`.
- The `PendingRequests` map is consulted by passive-participant code paths
  when a peer (acting as leader for the same request) asks us to join the
  protocol: if the request is not in the queue, we reject.
  (TODO: confirm exact passive-join lookup site — check
  `passive channels` / `message_router` code paths and wire it up in the
  doc.)
- The branch's inline TODO at queue.rs:492–496 acknowledges this:
  `// removing the request from our queue only stops us retrying as leader.
  Another node's leader can still ask us to participate via a passive
  channel, and we'll reject because the request is gone.`

**Verdict:** real. The failure mode is: node A hits 10 leader attempts,
drops request R from its queue. Shortly after, leadership rotates
(eligibility set changes, alive-set changes) and node B becomes leader
for R and pings A to join. A has forgotten R exists → rejects → B's
attempt stalls. We should separate "gave up as leader" from "GC the
request entirely".

### 5. Submitting before the request block is finalized

**Status:** CONFIRMED on both `main` and branch.
- Same match arm as (3): `OptimisticAndCanonical` is on the "start as
  leader" path. A block that is optimistically on the canonical chain has
  not yet been finalized, so a fork could later invalidate it.
- The concrete failure mode: leader starts signing for a request observed
  in an optimistic block; the optimistic block dies on a fork; the request
  never reappears on the canonical chain; our response transaction either
  times out via yield-resume or, worse, attaches to some stale state.
- This is likely the *reason* we currently keep failed-as-leader removal
  (issue 4): without it the queue would grow forever for requests that
  never actually made it on chain. Once (5) is tightened — only act on
  `RecentAndFinal` — (4) becomes safer too, because the queue self-prunes
  via the final chain.

**Verdict:** real, and structurally coupled to (3) and (4).

### 6. Test refactor (`e4a2ece8`)

**Status:** not yet assessed. Need to diff the commit and decide: does it
stand on its own, does it block/enable the functional changes, can it be
landed first as its own PR?

## Preliminary conclusion

All four code-smell items (1–2) and all three correctness items (3–5) are
real. The branch is valuable. It does two things at once:

- **Separation of concerns** (1 + 2): hoist the tracker out of the queue,
  drop the `T` content map, stop injecting peer-network height.
- **Correctness TODOs flagged but not fixed** (3 + 4 + 5): the branch
  leaves these as comments.

The refactor is a prerequisite for fixing 3/4/5 cleanly — once the tracker
is purely "local indexer view", the semantics of `Unknown` become
well-defined, and we can confidently refuse to act on non-final blocks.

## Draft issue description

*(filled in after consolidating findings)*

## Incremental PR plan

*(filled in after consolidating findings)*
