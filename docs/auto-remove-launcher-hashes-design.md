# Auto-Removal of Unused Launcher Image Hashes

**Status:** Draft — for team review
**Issue:** [#3381](https://github.com/near/mpc/issues/3381)
**Related:** [Securing MPC with TEE][securing-mpc-with-tee], [TEE Lifecycle][tee-lifecycle], [Updating the Launcher][updating-launcher]

[securing-mpc-with-tee]: securing-mpc-with-tee-design-doc.md
[tee-lifecycle]: tee-lifecycle.md
[updating-launcher]: updating-launcher-internal-guide.md

## Problem

The contract's `allowed_launcher_image_hashes` list accumulates entries forever
unless they are explicitly voted out — and removal requires a **unanimous**
vote (`vote_remove_launcher_hash`). MPC Docker image hashes, by contrast,
auto-expire 7 days after a newer image is voted in.

This asymmetry was intentional: launcher upgrades are rare and operationally
heavy (CVM migration), so launcher hashes were given no expiry. The practical
consequence is that stale hashes pile up — testnet currently carries 3 entries,
of which only the newest is in use — and removing them requires coordinating a
unanimous vote across all node operators for what is effectively housekeeping.

The insight (from the Slack discussion): **not using a launcher is itself a
vote.** Every node already proves hourly which launcher it runs, via its
attestation. The contract can observe disuse directly and evict stale hashes
without any explicit vote.

## Goals

- Launcher hashes that no participant has used for a configurable period
  (default **14 days**) are automatically no longer accepted, and eventually
  removed from storage.
- No new node-side behavior; reuse the existing hourly attestation
  resubmission as the "in use" signal.
- No new voting flows. The existing unanimous `vote_remove_launcher_hash`
  remains as a manual early-removal override (e.g. compromised launcher).
- The mechanism must never strand a healthy network: a hash backing a valid
  participant attestation is never evicted, and the list never becomes empty.

### Non-Goals

- **OS measurements** keep their current explicit add/remove voting. Multiple
  measurement sets must legitimately coexist long-term, so usage-based expiry
  does not apply ([Slack thread][issue] consensus).
- No change to MPC Docker image hash expiry (existing 7-day mechanism stays).

[issue]: https://github.com/near/mpc/issues/3381

## Current State

| | MPC Docker image hashes | Launcher image hashes |
|---|---|---|
| Add | threshold vote (`vote_code_hash`) | threshold vote (`vote_add_launcher_hash`) |
| Remove | **auto-expiry**: lazy cleanup with 7-day grace after a newer hash lands ([`AllowedDockerImageHashes::valid_entries`][valid-entries]) | **unanimous vote only**; cannot remove the last entry |
| Storage | `Vec<AllowedMpcDockerImage { image_hash, added }>` | `Vec<AllowedLauncherImage { launcher_hash, compose_hashes }>` — no timestamps |

[valid-entries]: ../crates/contract/src/tee/proposal.rs

How a launcher hash is "used" today:

1. Every node resubmits a fresh attestation via `submit_participant_info`
   every hour (`ATTESTATION_RESUBMISSION_INTERVAL`, `crates/node/src/run.rs`).
2. Attestation verification extracts the node's launcher docker-compose hash
   from `app_compose` and checks it against the flattened set of compose
   hashes of all allowed launcher images
   (`crates/mpc-attestation/src/attestation.rs`).
3. Each compose hash belongs to exactly one `AllowedLauncherImage` entry, so
   every successful attestation identifies the launcher its node runs.

Stored attestations expire 7 days after submission
(`DEFAULT_EXPIRATION_DURATION_SECONDS`); a participant whose attestation
lapses fails the next `verify_tee` re-verification.

## Proposed Design

### Data model

```rust
pub struct AllowedLauncherImage {
    launcher_hash: LauncherImageHash,
    compose_hashes: Vec<LauncherDockerComposeHash>,
    added: Timestamp,          // NEW: when the hash was (last) voted in
    last_attested: Timestamp,  // NEW: last successful attestation using this launcher
}
```

New config field in `crates/contract/src/config.rs`:

```rust
/// A launcher hash unused for this long is no longer accepted and gets evicted.
/// Invariant: MUST be greater than the attestation validity period (7 days).
pub launcher_hash_unused_ttl_seconds: u64,  // default: 14 * 24 * 60 * 60 (14 days)
```

### Expiry definition

An entry is **expired** when:

```
max(added, last_attested) + TTL < now
```

Counting from `added` means a hash that was voted in but **never adopted**
also expires after one full TTL window. This addresses the corner case raised
on the issue (the freshly voted launcher is not yet used by anyone at vote
time): it gets a 14-day adoption window, after which the vote is presumed
abandoned. Recovery is a threshold re-vote, not unanimity.

### Mechanism — three parts

**1. Refresh on use.** `TeeState::add_participant` (the `submit_participant_info`
path), after successful verification, maps the validated
`launcher_compose_hash` back to its owning `AllowedLauncherImage` and sets
`last_attested = now`. Since every node does this hourly, an in-use launcher's
entry is always fresh. Mock attestations (no compose hash) skip the refresh.

**2. Read-time filtering — this is what enforces expiry.** All read paths skip
expired entries:

- `get_allowed_launcher_compose_hashes()` (attestation verify / re-verify)
- `get_allowed_launcher_hashes()` / the `allowed_launcher_image_hashes` view

A contract cannot wake itself at the TTL deadline, but it doesn't need to:
the moment the TTL lapses, the next read excludes the entry, so attestations
against it are rejected immediately — regardless of when storage is actually
cleaned.

**Fallback:** if *all* entries are expired, the read paths still return the
newest one. This mirrors `AllowedDockerImageHashes::valid_entries` (which
always retains the latest image) and guarantees a network recovering from a
long outage can still attest with at least one launcher.

**3. Lazy storage sweep.** `verify_tee` calls
`cleanup_expired_launcher_hashes(ttl)` inline, physically deleting expired
entries (always retaining at least the newest). Between TTL lapse and the next
`verify_tee` the entry sits in storage but is inert everywhere.

The issue's acceptance criteria suggest deferring cleanup to detached promises
so it cannot fail the host transaction. That concern applies to unbounded
collections; `allowed_launcher_images` is operator-curated and holds a handful
of entries, so the sweep is a few comparisons — inline is simpler and matches
the existing Docker-hash pattern. (Open question 2 below.)

### Re-vote refreshes

`vote_add_launcher_hash` reaching threshold for a hash **already present**
(possibly expired but not yet swept) resets its `added` timestamp instead of
being rejected as a duplicate. This is the recovery path for a hash that aged
out before adoption.

### Safety invariants

1. **A hash backing a valid attestation is never expired.** Follows
   arithmetically from `TTL (14d) > attestation validity (7d)`: any valid
   attestation refreshed its entry within the last 7 days. No explicit
   "in use" check is needed; the invariant `TTL > 7 days` is enforced in
   config validation.
2. **The list is never empty / never fully rejected.** The sweep retains at
   least the newest entry, and the read fallback returns the newest entry even
   if expired.
3. **Order safety in `verify_tee`.** Read-time filtering means re-verification
   already sees the post-expiry view; the sweep only reclaims storage and
   cannot change which participants pass.

### What does NOT change

- `vote_add_launcher_hash` (threshold) — unchanged semantics, plus re-vote
  refresh.
- `vote_remove_launcher_hash` (unanimous) — kept as the manual override for
  removing a hash *before* its TTL lapses (e.g. compromised launcher).
- Node, launcher, and attestation-generation code — no changes.

## Lifecycle / Flows

```mermaid
sequenceDiagram
    participant Ops as Operators
    participant C as Contract
    participant N as Nodes (hourly attestation)

    Ops->>C: vote_add_launcher_hash(B) × threshold
    Note over C: B.added = now (14-day adoption clock starts)
    N->>C: submit_participant_info (launcher A)
    Note over C: A.last_attested refreshed hourly
    Note over Ops,N: CVMs migrate from A to B over days/weeks
    N->>C: submit_participant_info (launcher B)
    Note over C: B.last_attested refreshed; A.last_attested freezes<br/>once the last node leaves A
    Note over C: A.last_attested + 14d passes →<br/>A rejected by all read paths (immediately)
    Ops->>C: verify_tee (routine)
    Note over C: sweep deletes A from storage
```

### Operator scenarios

| Scenario | Behavior |
|---|---|
| **Normal rotation** | Vote in `B`, migrate nodes, do nothing else. 14 days after the last node leaves `A`, it is auto-rejected and swept on the next `verify_tee`. No removal vote. |
| **Rollback** | `B` is broken; nodes revert to `A` within 14 days. `A` is still valid and refreshes resume. `B` ages out if abandoned. |
| **Slow rollout** (> 14 days between vote and first migration) | `B` expires unused → first migrated node fails attestation → operators re-vote `B` (threshold), `added` resets. Operational rule of thumb: **vote within 14 days of actually migrating**. |
| **Node offline > 14 days on an old launcher** | Its launcher hash may age out (its attestation already expired at day 7 anyway). On recovery: upgrade to a live launcher, or have the old hash re-voted in. |
| **Network-wide outage > 14 days** | All entries expire; the newest is still honored via the read fallback. Others recoverable by threshold re-vote. |
| **Compromised launcher** | Don't wait for the TTL: unanimous `vote_remove_launcher_hash` removes it immediately (unchanged). |

## Migration

`AllowedLauncherImage` gains two fields → borsh layout change → contract state
migration required. Existing entries are initialized with
`added = last_attested = migration time`, giving every current hash a fresh
14-day clock. In-use hashes immediately resume refreshing; stale testnet
hashes age out 14 days post-upgrade with no further action.

## Alternatives Considered

- **Instant eviction once no participant references a hash** (no TTL). Faster
  cleanup but removes the rollback window: the moment the last node migrates,
  the old launcher is gone, and a broken new launcher would require a re-vote
  under incident pressure. The TTL is the buffer.
- **TTL refreshed by `re_verify` as well** (stored attestations keep hashes
  alive without fresh submissions). Rejected: a stored attestation is at most
  7 days old, so fresh submissions dominate anyway; refreshing on re-verify
  would let an idle network keep hashes alive artificially.
- **Exempting never-used hashes from expiry.** Rejected: a forgotten or
  mistaken vote would linger forever, which is the very problem being solved.
- **Detached-promise cleanup** per the issue AC. Deferred — see open
  question 2.

## Implementation Surface

| Location | Change |
|---|---|
| `crates/contract/src/tee/proposal.rs` | `added`/`last_attested` fields, expiry filter + newest-fallback, `cleanup_expired_launcher_hashes`, re-vote refresh |
| `crates/contract/src/tee/tee_state.rs` | refresh-on-use in `add_participant`, TTL plumbed through launcher getters |
| `crates/contract/src/lib.rs` | sweep call in `verify_tee`, view filtering |
| `crates/contract/src/config.rs` | `launcher_hash_unused_ttl_seconds` (default 14d), `> 7d` validation |
| Contract migration | initialize new fields to migration time |
| Tests | refresh-on-use, expiry + read fallback, never-used expiry, re-vote refresh, sweep in `verify_tee`, rotation/rollback lifecycle, migration |

## Open Questions

1. **TTL default — 14 days.** Is the team comfortable with the implied
   operational rule (*vote a launcher in at most 14 days before migrating to
   it*)? 30 days would be more forgiving for slow rollouts at the cost of
   slower cleanup.
2. **Inline sweep vs. detached promise.** This doc proposes inline cleanup in
   `verify_tee` (bounded, operator-curated collection). Does anyone see a path
   to this collection growing beyond a handful of entries?
3. **Observability.** Should auto-eviction emit a contract event/log for
   operator monitoring, beyond the existing `log!` pattern?
