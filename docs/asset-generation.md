# Triple and Presignature Asset Generation

This document describes how the MPC node generates and manages its cryptographic
assets — **triples**, **presignatures**, and their consumption during
**signature generation**. It applies only to **OT based ECDSA**/**Cait Sith** at
this point.

## Pipeline overview

```
Triples  ──►  Presignatures  ──►  Signatures
(slow)         (fast)              (1 round)
```

Each MPC signature requires one **presignature**, and each presignature
requires a pair of **triples** (called a `PairedTriple`). Triple generation
is the bottleneck: it involves heavy OT-based cryptographic computation.
Presignature generation is significantly faster, and signature generation
is a single round.

Our system supports several domains, where each domain has its own secret key
and purpose (to be used for signatures, ckd, foreign transactions, etc). Triples
are not domain-specific; a single shared triple store feeds presignature
generation for all ECDSA domains. Presignatures are per-domain because they
incorporate the domain's key share.

## Asset Storage

Every asset has exactly one **owner**, the participant who initiated its
generation, which we call the leader. After generation, the leader stored the
**owned** part of the asset, and all other participants (followers) store the
**unowned** parts. All the parts of an asset are different, but can be
identified by a unique ID which is known to all participants that participated
in that asset generation. Only the owner may pick which asset will be used for a
given computation. For example, when computing signatures, a presignature is
needed. Which presignature to use is the choice of the leader of that
computation.

| Role | Storage | Retrieval |
|------|---------|-----------|
| Owner (leader) | In-memory queue + RocksDB | `take_owned()` — pops next usable asset, blocks if none available |
| Follower | RocksDB only | `take_unowned(id)` — looks up by specific ID chosen by the leader |

When the leader starts a presignature or signature computation it
broadcasts the asset ID. Followers look the asset up by that ID.

**Follower-side generation:** Followers do not run their own generation loops
(explained in the next section) for assets they don't own. Instead, the generic
protocol runner (`crates/node/src/protocol.rs`) handles incoming generation
requests from leaders over the P2P network. When a leader spawns a triple or
presignature protocol, it uses a network channel with the chosen participant
set. Each follower receives the protocol message, runs its side of the MPC
computation, and stores the result as an unowned asset.

## Background generation loops

Background generation is launched by `spawn_background_tasks()`
(`crates/node/src/providers/ecdsa.rs:232`). It spawns:

1. **One** triple generation loop (shared across all domains).
2. **One** presignature generation loop **per domain**.

### Triple generation loop

Source: `crates/node/src/providers/ecdsa/triple.rs`

```
loop {
    update metrics
    if num_owned + in_flight < desired_triples_to_buffer
       AND in_flight < concurrency * 2 * 64:
        pick threshold random active participants
        reserve batch of 64 IDs
        spawn async task (semaphore-limited to `concurrency`):
            run MPC triple protocol → 64 triples
            store each as owned PairedTriple
        sleep(parallel_triple_generation_stagger_time_sec)
        continue

    if store is full (num_owned == desired):
        maybe_discard_owned(32)   // clean out unusable assets

    sleep 100ms
}
```

Key details:

- Triples are generated in **batches of 64** (`SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE`).
  Each batch produces 64 raw triples which are paired into 32 `PairedTriple` values.
- The leader selects `threshold` random participants from those currently
  alive over the P2P network.
- `InFlightGenerationTracker` counts how many triples are "in flight"
  (spawned but not yet completed) using an atomic counter with a drop guard.
- A tokio semaphore limits actual concurrent protocol executions to
  `config.concurrency`.
- A stagger delay (`parallel_triple_generation_stagger_time_sec`) between
  successive spawns avoids thundering-herd effects.
- The `sleep 100ms` at the bottom of the loop is a non-blocking
  `tokio::time::sleep` — it yields to the async runtime, not the OS thread.

### Presignature generation loop

Source: `crates/node/src/providers/ecdsa/presign.rs`

```
loop {
    update metrics + progress tracker
    if num_owned + in_flight < desired_presignatures_to_buffer
       AND in_flight < concurrency * 2:
        reserve 1 ID
        take_owned triple (BLOCKS until one is available)
        participant set = participants from that triple
        spawn async task (semaphore-limited to `concurrency`):
            run MPC presign protocol → 1 presignature
            store as owned PresignOutputWithParticipants
        continue

    if store is full (num_owned == desired):
        maybe_discard_owned(1)

    sleep 100ms
}
```

Key details:

- Presignatures are generated **one at a time** (not batched).
- The participant set is determined by the triple pair. Both triples in
  a pair are always generated in the same batch with the same participant
  set, so they share the same participants. (The code defensively computes
  an intersection via `participants_from_triples()`, but in practice the
  sets are identical.)
- `take_owned()` on the triple store will **block** if no triples with
  all-online participants are available. This is the most common reason
  presignature generation stalls.
- The progress tracker reports whether the loop is "waiting for triples".

### Signature consumption

Source: `crates/node/src/providers/ecdsa/sign.rs`

When a signature request arrives:

1. **Leader** calls `presignature_store.take_owned()` for the relevant
   domain, consuming one presignature.
2. Leader opens a network channel with the presignature's participant set
   and broadcasts the presignature ID along with the signature request.
3. **Followers** call `presignature_store.take_unowned(id)` to retrieve
   their share, then run the protocol.
4. The signature computation is a single round. The leader does **not**
   wait for all followers to confirm success (`leader_waits_for_success`
   returns `false`).

## Hot/cold queue architecture

Owned assets live in a `DoubleQueue` which has two layers:

```
  ┌──────────────┐       ┌────────────────────────────────────────────────┐
  │  Hot queue   │──────►│                Cold queue                      │
  │ (flume chan) │       │          [ready | unknown | offline]           │
  └──────────────┘       └────────────────────────────────────────────────┘
```

### Hot queue

An unbounded `flume` channel. Newly generated assets are pushed here by
`add_owned()`. The hot queue is drained into the cold queue the first
time an asset is needed.

### Cold queue

A `VecDeque` divided into three logical regions by two barriers:

```
0                          cold_ready        cold_available                len
 ──────────────────────────── ──────────────────── ─────────────────────────
│ Condition-satisfying       │   Unknown          │ Non-satisfying          │
 ───────────────────────────────────────────────────────────────────────────
```

- **`cold_ready`** (index 0..cold_ready): assets known to have all
  participants alive. Returned immediately by `take()`.
- **Unknown** (cold_ready..cold_available): not yet checked against
  current condition. Checked lazily during `take()`.
- **Non-satisfying** (cold_available..len): assets known to have at least
  one offline participant. Skipped by `take()`, targeted by `discard()`.

The **condition** is: "are all of the asset's participants in the current
alive-participants set?" The alive set is fetched from the P2P network
layer at most once per second (1s cache in `ColdQueue`).

When the alive set changes, the barriers reset — the entire queue becomes
"unknown" — and assets are re-classified lazily on next access.

### take_owned() flow

1. Force-refresh the condition value.
2. Try to pop from the cold queue's ready/unknown region.
3. If the cold queue is exhausted, wait for an item from the hot queue
   (with a 1-second timeout so condition changes are noticed).
4. A freshly received hot-queue item that doesn't satisfy the condition
   is pushed to the cold queue's non-satisfying region.

### maybe_discard_owned() flow

Called when the store is full (`num_owned == desired_to_buffer`). It
processes a fixed number of elements:

1. Pops from the back of the cold queue. If an asset doesn't satisfy
   the condition, it is permanently removed (deleted from DB too).
2. If the cold queue is exhausted, drains available hot-queue items and
   classifies them.

This prevents the store from filling up with unusable assets when
participants go offline.

## Online / offline status

An asset is considered **online** if all participants in its participant
set have an active P2P TLS connection. Otherwise it is **offline**.

- Online assets can be used immediately.
- Offline assets are kept (they may become usable again when participants
  reconnect) but are not selected by `take_owned()`. If *all* owned
  assets are offline, `take_owned()` blocks — it will not return an
  offline asset. It re-checks the alive set every second and unblocks as
  soon as any asset's full participant set comes back online.
- If the store is full of offline assets, `maybe_discard_owned()` slowly
  evicts them to make room for fresh generation.

The status check is done via `all_alive_participant_ids()` on the
`MeshNetworkClient`, which returns the set of participants with an
active P2P connection.

## Asset cleanup on startup

Source: `crates/node/src/assets/cleanup.rs`

On node startup, `delete_stale_triples_and_presignatures()` compares
the current epoch data with what was stored in RocksDB:

| Scenario | Action |
|----------|--------|
| First run (no epoch in DB) | Keep all assets |
| **Epoch ID changed** (resharing occurred) | **Delete all** triples and presignatures (see note below) |
| Same epoch, no participant TLS key changes | Keep all assets |
| Same epoch, some participant changed TLS key | Delete only assets involving changed participants |

**Note on epoch-change cleanup:** Deleting all assets on epoch change is
a conservative choice. Presignatures incorporate key shares and are
definitely invalidated by resharing, but triples are independent of key
shares (just correlated randomness) and could theoretically be preserved
if the participant set remains compatible.

A participant's P2P public key changes when they regenerate their
`secrets.json` (e.g. the node is redeployed from scratch). The P2P key
itself is unrelated to the cryptographic shares, but changing it signals
that the participant likely lost their local state (RocksDB), meaning they
no longer have their copies of asset shares. Any asset involving that
participant is therefore unrecoverable. These are removed from the DB
using `clean_db()`, which iterates the RocksDB key range for owned assets
and checks whether all of the asset's participants are in the
"unchanged" set. (This reuses the `is_subset_of_active_participants()`
trait method, passing the list of persistent participants rather than
live-online participants.)

## Prometheus metrics

### Asset counts (gauges, updated each loop iteration)

| Metric | Description |
|--------|-------------|
| `mpc_owned_num_triples_available` | Total owned triples (online + offline + unknown). Maps to `num_owned()` which is `hot.len() + cold_available`. |
| `mpc_owned_num_triples_online` | Owned triples confirmed to have all participants alive. Maps to `num_owned_ready()` which is `cold_ready`. |
| `mpc_owned_num_triples_with_offline_participant` | Owned triples with at least one offline participant. Maps to `num_owned_offline()` which is `cold_queue.len() - cold_available`. |
| `mpc_owned_num_presignatures_available` | Total owned presignatures. Same semantics as triples. |
| `mpc_owned_num_presignatures_online` | Owned presignatures with all participants alive. |
| `mpc_owned_num_presignatures_with_offline_participant` | Owned presignatures with some offline participant. |

**Important note on `_available` vs `_online`**: `_available` counts
the hot queue plus the first `cold_available` entries in the cold queue
(i.e. ready + unknown assets). `_offline` counts the remainder of the
cold queue (`len - cold_available`). Therefore,
`_available = _online + unknown`, and the identity
`_available + _offline = total` holds, but
`_available >= _online + _offline` because the unknown assets in
`_available` have not yet been checked against the current alive set.

## Configuration knobs

Defined in `crates/node/src/config.rs` and set in `config.yaml`.

### `TripleConfig`

| Field | Type | Description |
|-------|------|-------------|
| `concurrency` | `usize` | Max concurrent triple generation protocol executions (semaphore permits). |
| `desired_triples_to_buffer` | `usize` | Target number of owned triples to maintain. Generation pauses when `num_owned + in_flight >= desired`. |
| `timeout_sec` | `u64` | Timeout for a single triple generation protocol execution. |
| `parallel_triple_generation_stagger_time_sec` | `u64` | Delay between spawning successive triple generation tasks, to avoid thundering herd. |

### `PresignatureConfig`

| Field | Type | Description |
|-------|------|-------------|
| `concurrency` | `usize` | Max concurrent presignature generation protocol executions. |
| `desired_presignatures_to_buffer` | `usize` | Target number of owned presignatures per domain. |
| `timeout_sec` | `u64` | Timeout for a single presignature generation protocol execution. |

### `SignatureConfig`

| Field | Type | Description |
|-------|------|-------------|
| `timeout_sec` | `u64` | Timeout for a single signature computation. |

### Example config.yaml snippet (illustrative — see your deployment's config.yaml for actual values)

```yaml
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
```

## Troubleshooting: observed production anomaly

The following was observed simultaneously in production (#2123):

1. The presignature generation task is not reported as running.
2. The node is computing signatures as leader.
3. The number of available presignatures does not decrease.

**Explanation:** The asset count gauges (`mpc_owned_num_presignatures_available`,
`_online`, `_with_offline_participant`) are only updated inside the
presignature generation loop (`run_background_presignature_generation`).
The signature path consumes presignatures via `take_owned()` but never
updates these metrics. If the generation loop dies, the gauges freeze at
their last value. The node can continue signing (consuming presignatures
from the store) while the metrics show a stale, unchanging count.

Eventually the node will exhaust its owned presignatures. At that point
`take_owned()` blocks indefinitely (waiting for a presignature that will
never arrive), and the node stops being able to lead signature
computations. It can still participate as a **follower**, since
`take_unowned(id)` looks up presignatures stored by other leaders'
generation loops and does not depend on the local loop being alive.
