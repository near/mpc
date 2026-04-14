# Race condition in `take_unowned()` — problem & options

## Problem

`DistributedAssetStorage::take_unowned()` performs a non-atomic read-then-delete
on RocksDB:

```rust
pub fn take_unowned(&self, id: UniqueId) -> anyhow::Result<T> {
    let key = self.make_key(id);
    let value_ser = self.db.get(self.col, &key)?;    // 1. read
    let mut update = self.db.update();
    update.delete(self.col, &key);                    // 2. delete
    update.commit()?;
    Ok(serde_json::from_slice(&value_ser)?)
}
```

Two concurrent callers can both complete the read before either commits the
delete, causing both to receive the same presignature. This is reachable because
a malicious leader can send two `Start` messages on different `channel_id`s
referencing the same `presignature_id`, and each spawns an independent async
task that calls `take_unowned()`.

Reusing a presignature violates a hard security invariant of the signing
protocol. In theory, a single malicious leader could exploit this against one
honest follower to recover that follower's secret presignature material.

**Practical risk is low** — our production config (threshold 5-of-8, presignature
sets of 5) would require all 4 honest followers to independently lose the race
simultaneously, and operators are vetted. But the invariant violation is real and
worth fixing as hardening.

## Options

### Option A: In-memory lock in `take_unowned()` (recommended)

Add a process-local `Mutex<HashSet<UniqueId>>` (or similar) to
`DistributedAssetStorage`. Before the DB read, lock the set and insert the ID.
If the ID is already present, return an error. Remove it after the delete
commits (or on drop).

```
Pro:  Minimal change, self-contained in assets.rs, zero DB schema changes.
      Fully prevents the race regardless of caller.
Con:  Only works within a single process (fine — we run one node per process).
      Adds a synchronization point, but take_unowned is not hot-path.
```

### Option B: Dedup at the network/task layer

Before spawning a follower signing task, check whether a task with the same
`presignature_id` is already in flight. Reject duplicates. This could be done
in `process_channel_task()` or in the channel dispatch in `network.rs`.

```
Pro:  Prevents the race earlier in the pipeline, avoids even starting duplicate work.
Con:  Requires threading presignature_id awareness into the network layer, which
      currently only knows about channel_id/task_id. More invasive, and fragile
      if new call sites appear. Does not protect take_unowned itself.
```

### Option C: Atomic DB primitive (compare-and-delete)

Replace the get+delete with a single RocksDB `merge` operator or a
`get_for_update` inside a pessimistic transaction that locks the key.

```
Pro:  Solves it at the storage layer with no in-memory state.
Con:  RocksDB transactions require opening the DB with TransactionDB, which is a
      larger change to SecretDB. Merge operators add complexity. Overkill for
      this use case.
```

### Option D: Combine A + B (belt and suspenders)

Apply the lock in `take_unowned()` (Option A) AND reject duplicate
presignature_id tasks at the network layer (Option B).

```
Pro:  Defense in depth — protects the invariant even if one layer is bypassed.
Con:  Two changes instead of one. Probably unnecessary given the low practical risk.
```

## Recommendation

**Option A.** A `Mutex<HashSet<UniqueId>>` inside `take_unowned()` is the
smallest change that fully closes the race. It's self-contained, easy to test
(spawn two tasks racing on the same ID, assert exactly one succeeds), and
doesn't require changes outside `assets.rs`. The network-layer dedup (Option B)
is a nice-to-have but not necessary to fix the bug.
