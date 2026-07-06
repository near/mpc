# Unified contract voting

The MPC contract exposes roughly fifteen `vote_*` entry points, and almost every one is
backed by its own bespoke vote-storage struct that re-implements the same primitives:
register a vote, replace a voter's previous vote, count votes for a proposal, prune voters
who left the participant set, and clear votes after a decision. This document proposes
consolidating the **governance / CRUD / configuration** flows onto a single
**commit-reveal** voting interface built on the existing generic `Votes<V>` primitive.

To try and keep the scope small and with little complexity, we took two decisions: we build on the primitive that already exists rather
than inventing a new framework, and we explicitly **exclude** the protocol-driven key-event
votes, whose semantics do not fit a generic proposal interface (see §6).

## Table of Contents

1. [Goals](#1-goals)
2. [Current state analysis](#2-current-state-analysis)
3. [Proposed design — commit-reveal unified interface](#3-proposed-design--commit-reveal-unified-interface)
4. [Conclusion mechanics and conflicting proposals](#4-conclusion-mechanics-and-conflicting-proposals)
5. [Cleanup and TTL semantics](#5-cleanup-and-ttl-semantics)
6. [Scope — what migrates and what stays bespoke](#6-scope--what-migrates-and-what-stays-bespoke)
7. [Migration strategy](#7-migration-strategy)
8. [Alternatives considered](#8-alternatives-considered)
9. [Open questions](#9-open-questions)

## 1. Goals

- **Consolidate** the ad-hoc governance/CRUD/config voting flows onto one interface, removing
  duplicated vote/count/replace/cleanup logic.
- **Reduce on-chain cost** by letting participants commit to a proposal with a 32-byte hash
  and revealing the full payload only once, when the proposal is concluded.
- **Unify cleanup and TTL semantics** so that abandoned proposals cannot accumulate in
  contract storage indefinitely.

Non-goals: folding the protocol-driven key-event votes into the governance interface (§6.1
explains why they stay separate — though §6.2 notes they can be consolidated *among
themselves*), or building the off-chain proposal-sharing service (§3, treated as optional UX).

## 2. Current state analysis

### 2.1 The `vote_*` entry points

All entry points live in `crates/contract/src/lib.rs`. The **threshold** column is the passing
rule — how many votes a proposal needs to take effect. There are only three distinct rules
plus one special case:

- **`t-of-n`** — the configured signing threshold in `ThresholdParameters` (a subset
  suffices).
- **`n-of-n (current)`** — every participant in the *current* set must vote (unanimity).
- **`n-of-n (proposed)`** — every participant in the *incoming* set must vote; distinct from
  the above only because the participant set itself is being changed.
- **`unilateral`** — a single participant suffices.

| Entry point | Line | Backing store | Threshold | Shape |
|---|---|---|---|---|
| `vote_new_parameters` | 886 | `ThresholdParametersVotes` | `n-of-n (proposed)` | singleton |
| `vote_add_domains` | 948 | `AddDomainsVotes` | `n-of-n (current)` | singleton |
| `vote_pk` | 1103 | `KeyEventInstance` | `n-of-n (current)` | key-event |
| `vote_reshared` | 1161 | `KeyEventInstance` | `n-of-n (current)` | key-event |
| `vote_cancel_resharing` | 1254 | `HashSet` in resharing state | `t-of-n` | key-event |
| `vote_cancel_keygen` | 1272 | `BTreeSet` in init state | `t-of-n` | key-event |
| `vote_abort_key_event_instance` | 1285 | `KeyEventInstance` | `unilateral` | key-event |
| `vote_update` | 1343 | `ProposedUpdates` | `t-of-n` | singleton (per id) |
| `vote_code_hash` | 1407 | `CodeHashesVotes` | `t-of-n` | singleton |
| `vote_add_launcher_hash` | 1437 | `LauncherHashVotes` | `t-of-n` | CRUD (add) |
| `vote_remove_launcher_hash` | 1470 | `LauncherHashVotes` | `n-of-n (current)` | CRUD (remove) |
| `vote_add_os_measurement` | 1499 | `MeasurementVotes` | `t-of-n` | CRUD (add) |
| `vote_remove_os_measurement` | 1527 | `MeasurementVotes` | `n-of-n (current)` | CRUD (remove) |
| `vote_update_foreign_chain_providers` | 1573 | `ProviderVotes` | `t-of-n` (per chain) | CRUD (per chain) |
| `vote_tee_verifier_change` | 1617 | `TeeVerifierVotes` | `t-of-n` | singleton |

Backing structs:

- `ThresholdParametersVotes` — `crates/contract/src/primitives/threshold_votes.rs:12`
- `AddDomainsVotes` — `crates/contract/src/primitives/domain.rs:239`
- `CodeHashesVotes` / `LauncherHashVotes` — `crates/contract/src/tee/proposal.rs:22` / `:87`
- `MeasurementVotes` — `crates/contract/src/tee/measurements.rs:33`
- `ProposedUpdates` — `crates/contract/src/update.rs:145`
- `KeyEventInstance` — `crates/contract/src/state/key_event.rs:242`
- `TeeVerifierVotes` — `crates/contract/src/tee/verifier_votes.rs:44`
- `ProviderVotes` — `crates/contract/src/foreign_chain_rpc.rs:147`

### 2.2 The primitive already exists

`crates/contract/src/primitives/votes.rs` defines a generic `Votes<V>` that is exactly the
"hashing mechanism" the original sketch reached for:

```rust
pub struct Votes<V>
where
    V: BorshSerialize + Ord,
{
    proposal_by_voter: IterableMap<V, ProposalHash>,
    votes_by_proposal: IterableMap<ProposalHash, VoterSet<V>>,
}
```

- A vote stores a `ProposalHash` — a 32-byte SHA-256 digest derived from any type that
  implements `ProposalHashEncoding` (`votes.rs:148`), via borsh serialization.
- `vote()` replaces a voter's prior vote automatically (idempotent re-votes).
- `votes_by_proposal` is a reverse index, so counting votes for a proposal is cheap.
- `VoterSet::count_for(predicate)` counts only the voters matching a predicate — used to
  count only *current* participants.
- Cleanup is first-class: `remove_votes_for_proposal()`, `retain_votes(predicate)`, and
  `clear()`.

**Two of the flows above already use it:** `TeeVerifierVotes`
(`tee/verifier_votes.rs:44`) wraps `Votes<AuthenticatedParticipantId>`, and `ProviderVotes`
(`foreign_chain_rpc.rs:147`) wraps `Votes<(AuthenticatedParticipantId, ForeignChain)>`. The
remaining flows each reinvent a subset of the same behavior over a plain `BTreeMap`.

### 2.3 What is *not* implemented today

Every `vote_*` method — including the two `Votes<V>` adopters — takes the **full proposal**
at vote time and lets the contract compute its hash. Nothing votes on a bare hash and defers
the payload. The "defer revealing content until late" idea in the original sketch is the one
genuinely new capability this document proposes.

## 3. Proposed design — commit-reveal unified interface

### 3.1 One proposal enum

Introduce a single enum whose variants carry their payloads, and derive the commitment hash
from it through the existing `ProposalHashEncoding` trait:

```rust
enum Proposal {
    AddLauncherHash(LauncherImageHash),
    RemoveLauncherHash(LauncherImageHash),
    AddOsMeasurement(ContractExpectedMeasurements),
    RemoveOsMeasurement(ContractExpectedMeasurements),
    CodeHash(NodeImageHash),
    TeeVerifierChange(VerifierChangeProposal),
    ForeignChainProviders(/* per-chain entries */),
    Update(UpdateId),
    AddDomains(Vec<DomainConfig>),
    NewParameters(ProposedThresholdParameters),
}
```

Because the borsh encoding of an enum is prefixed with its variant discriminant, the derived
`ProposalHash` is domain-separated across variants for free: a hash committed for
`AddLauncherHash` cannot be reinterpreted as `RemoveLauncherHash`. Each variant knows (a) how
to apply its effect and (b) its required threshold (`t-of-n` vs `n-of-n`, per the table in
§2.1).

The original sketch also proposed a separate `ProposalId` enum (`DomainAdd(Digest)`,
`ContractUpgrade(Digest)`, …). We recommend **dropping it**: the `ProposalHash` derived from
the `Proposal` enum already serves as the identifier, so a parallel id enum is redundant and
a second thing to keep in sync.

### 3.2 The API

```
vote(proposal_hash: ProposalHash)   // commit
conclude(proposal: Proposal)        // reveal + execute
```

- `vote(class, proposal_hash)` records a 32-byte commitment for the caller in the `Votes<V>`
  partition for the proposal's conflict class (§4.2), keyed by their
  `AuthenticatedParticipantId`. Cheap and constant-size regardless of how large the proposal
  is.
- `conclude(proposal)` recomputes `ProposalHash::from(&proposal)`, looks up its `VoterSet`,
  checks `count_for(is_current_participant)` against the variant's required threshold,
  re-validates the proposal against current state, executes the effect, and cleans up (§4).

This preserves every existing threshold rule; only the *shape* of the interface changes.
The conclusion step and its safety story are detailed in §4.

### 3.3 Off-chain proposal sharing

Voters need the preimage of a hash before they can meaningfully commit to it. As the original
sketch notes, gossiping proposals off-chain is acceptable: whoever authors a proposal has
every incentive to distribute it. A dedicated sharing service would improve UX but is
**optional** — it is not required for correctness, and is out of scope for this design.

## 4. Conclusion mechanics and conflicting proposals

### 4.1 How `conclude` fires

Conclusion is **necessarily a separate transaction**, not an automatic side effect of the
threshold-crossing vote. The vote that tips the threshold carries only the 32-byte hash, so
the contract does not hold the proposal payload and has nothing to execute at vote time. Once
a participant observes (off-chain) that a hash has reached threshold, they submit
`conclude(proposal)` with the preimage they already hold from gossip. Conclusion may be called
by any participant; a `vote_and_conclude(proposal)` convenience could let the participant who
tips the threshold commit and conclude in one call.

### 4.2 The out-of-order hazard (new to commit-reveal)

Separating the tally (`vote`) from the application (`conclude`) in time creates a hazard that
**does not exist in the contract today**: several proposals can each cross threshold and sit
"decided but not applied," and the order in which someone calls `conclude` is arbitrary. A
stale or superseded proposal could therefore be applied after a newer decision — e.g. two
competing `NewParameters`, or `AddLauncherHash(X)` racing `RemoveLauncherHash(X)`.

For contrast, every current `vote_*` method applies its effect **synchronously in the same
transaction that crosses the threshold**: `vote_update` calls `do_update` inline
(`lib.rs:1383`), which also clears all sibling entries and votes (`update.rs:199`), and
`vote_new_parameters` / `vote_add_domains` transition state inline and discard the old state's
tally. There is no "decided but not yet applied" window today, so this ordering problem is a
genuine *cost introduced by* commit-reveal, not a pre-existing bug (see also §8).

The design closes it with two complementary mechanisms.

### 4.3 Conflict-class clearing

Each `Proposal` variant declares a **conflict class** via a `conflict_key()`. Concluding a
proposal clears all pending votes that share its conflict key, so no conflicting sibling can
subsequently conclude. This generalizes the existing `do_update` clear (`update.rs:199`) to
every flow.

The granularity of a conflict class is *not* uniformly "same proposal type":

| Flow shape | Conflict key | Concluding one clears… |
|---|---|---|
| Singleton (`NewParameters`, `TeeVerifierChange`, `Update`, `CodeHash`) | the variant/type | all other pending proposals of that type — only one can win |
| State transition (`NewParameters`, `AddDomains`) | a shared "leaves `Running`" key | pending proposals *across* variants that are mutually exclusive |
| CRUD (`AddLauncherHash`, `AddOsMeasurement`) | `(family, entity)` | only the same-entity opposite op (`Add(X)` vs `Remove(X)`); independent entries such as `Add(X)` and `Add(Y)` do **not** conflict |

So "delete all same-type proposals" is correct for singletons, too coarse for CRUD (it would
wrongly drop independent entries), and too narrow for state transitions (it would miss a
mutually-exclusive proposal of a different type).

**Storage implication.** The vote store holds only opaque hashes, so at conclude time the
contract cannot decode sibling hashes to learn their class. Clearing "by class" is therefore
made cheap by **namespacing the vote store per conflict class** — a `Votes<V>` partition (a
storage-key prefix) per class. `vote(class, hash)` commits into the class partition;
`conclude` calls `clear()` on its own partition. This preserves payload hiding (only the hash
is revealed early) and degrades gracefully to the per-flow `Votes<V>` structure that already
exists today (`TeeVerifierVotes`, `ProviderVotes`).

### 4.4 Precondition re-validation (the safety guarantee)

Clearing removes siblings that already accumulated votes, but it does not stop a threshold of
participants from *re-voting* a stale proposal after the base state changed under it (e.g. a
`NewParameters` authored against a since-replaced participant set). Therefore `conclude` also
**re-validates the proposal's precondition against current state** and rejects it if no longer
valid.

Clearing is the fast path and keeps storage tidy; the precondition check is the actual safety
guarantee. Together they make conclusion order-independent. This mirrors existing prior art:
the key-event votes bind to a `KeyEventId` and `verify_vote` (`state/key_event.rs:173`)
rejects votes targeting a superseded attempt.

## 5. Cleanup and TTL semantics

### 5.1 CRUD vs singleton cleanup

The two shapes call for different cleanup, both already supported by `Votes<V>`:

- **Singleton** (e.g. `Update`, `NewParameters`, `CodeHash`, `TeeVerifierChange`): concluding
  one decides the singleton, so `clear()` all votes for that flow.
- **CRUD add** (e.g. `AddLauncherHash`, `AddOsMeasurement`): concluding one entry says nothing
  about the others, so only `remove_votes_for_proposal(&hash)` for the concluded proposal.

### 5.2 TTL

Proposals that never reach threshold must expire so they cannot accumulate in storage. Prior
art exists: `KeyEventInstance` carries an `expires_on` block height
(`state/key_event.rs:248`, checked at `:270`). We recommend attaching a per-proposal expiry
block height and pruning expired proposals either lazily (on the next `vote`/`conclude` that
touches the flow) or via a permissionless `prune` call. Exact TTL length is an open question
(§9).

### 5.3 Participant-set changes during a vote

This is the subtlety the original sketch flagged ("be careful to account for participant set
changes during votes"). `Votes<V>` handles it: it is keyed by `AuthenticatedParticipantId`,
counting always filters to the *current* set via `count_for`, and `retain_votes(predicate)`
prunes voters who have left after a resharing. This is a primary reason to build on the
existing primitive rather than a fresh `BTreeMap`.

## 6. Scope — what migrates and what stays bespoke

**In scope (commit-reveal candidates)** — the governance/CRUD/config flows: add/remove
launcher hash, add/remove OS measurement, code hash, TEE verifier change, foreign-chain
providers, contract `update`, add domains, new parameters.

**Out of scope for the governance interface** — the protocol-driven key-event votes:
`vote_pk`, `vote_reshared`, `vote_cancel_resharing`, `vote_cancel_keygen`,
`vote_abort_key_event_instance`.

### 6.1 Why the key-event votes stay separate

They should **not** be folded into the governance `vote(hash)` / `conclude(Proposal)`
interface:

- **Attempt-scoped, not free-floating.** Every key-event vote is bound to a `KeyEventId`
  (epoch + domain + `attempt_id`), and `KeyEvent::verify_vote`
  (`state/key_event.rs:173`) rejects votes that target a superseded attempt. A flat proposal
  store has no notion of "the current attempt."
- **Disagreement detection is the point.** `vote_pk` compares the submitted public keys and
  **aborts the attempt on mismatch** (`state/key_event.rs:135`). Under commit-reveal, two
  honest-but-diverging keys would simply produce two different hashes and reach no consensus
  *silently*, losing the explicit abort signal.
- **`conclude` would become a god-method.** Concluding these votes drives the core state
  machine — advancing domains, transitioning between Running / Initializing / Resharing, and
  firing the post-resharing cleanup promise fan-out (`lib.rs:1177`). That is not "apply a
  proposal effect."
- **No commit-reveal payoff.** The payloads are tiny and protocol-generated, and must hit the
  chain regardless — there is no storage to defer and no need for off-chain gossip.

### 6.2 Consolidation available *within* the key-event family

The five nonetheless carry only **three** distinct semantics, so they can be consolidated
among themselves (independently of the governance interface):

| Group | Methods today | Threshold | Effect |
|---|---|---|---|
| Success attestation | `vote_pk`, `vote_reshared` | `n-of-n (current)`, attempt-scoped | advance the state machine |
| Cancel the key event | `vote_cancel_resharing`, `vote_cancel_keygen` | `t-of-n` | → `Running` |
| Abort the attempt | `vote_abort_key_event_instance` | unilateral (first voter) | retry with next `attempt_id` |

- **Merge `vote_pk` + `vote_reshared` into one success-attestation method.** They already
  share `verify_vote` and the same unanimity tally; the only difference is the payload —
  keygen carries a newly generated public key (with disagreement detection), resharing carries
  nothing (the key is preserved). A single method taking an `Option<PublicKey>` (or a small
  `KeyEventOutcome` enum) covers both. This is a clean 2→1 win.
- **Merging `vote_cancel_resharing` + `vote_cancel_keygen`** into one state-dispatching method
  is possible but largely cosmetic: their side effects genuinely diverge (keygen permanently
  deletes the remaining domains and keeps the generated ones; resharing restores the previous
  parameters).
- **`vote_abort_key_event_instance` stays on its own** — it is unilateral
  (`KeyEvent::vote_abort`, `state/key_event.rs:145`, drops the instance on the first vote),
  not a tally, so it does not share the counting machinery at all.

Net: the key-event surface can shrink from five methods to roughly three, sharing the
`KeyEventInstance` lifecycle (and optionally the `Votes<V>` primitive for the unanimity
tally), while remaining a **sibling** interface to the governance commit-reveal one rather
than being merged into it. This is the deliberate application of the cost/benefit caveat:
consolidation pays off both for the governance flows and, separately, within the key-event
family — but merging the two families would only add friction.

## 7. Migration strategy

The contract is upgradeable through `vote_update`, so rollout is incremental:

- Migrate one flow at a time onto `Votes<V>` + its `Proposal` variant. `TeeVerifierVotes` and
  `ProviderVotes` are already there and serve as the reference shape.
- Each migration changes a stored struct's layout, which requires a state migration on
  upgrade. We recommend **clearing in-flight votes at the upgrade boundary** (a short
  governance quiet period) rather than migrating live tallies — vote state is cheap to
  re-cast and this avoids fragile per-struct migration code.

## 8. Alternatives considered

- **(a) Status quo** — keep every bespoke struct. Zero migration cost, but the duplicated
  vote/count/replace/cleanup logic keeps growing with each new flow, and TTL/cleanup remain
  inconsistent.
- **(b) Consolidate onto `Votes<V>`, keep reveal-at-vote** — migrate the in-scope flows onto
  the primitive but keep passing the full proposal at vote time (as `TeeVerifierVotes` /
  `ProviderVotes` do today). Simpler, needs no off-chain gossip, still removes the
  duplication, and — because it applies the effect atomically at threshold — **avoids the
  out-of-order conclusion hazard of §4.2 entirely**. Its cost is forgoing the storage/gas
  saving of committing to a 32-byte hash.
- **(c) Full commit-reveal (recommended)** — (b) plus deferring the payload to `conclude`.
  Adds the requirement that voters obtain the preimage off-chain *and* the conflict-class
  clearing + precondition machinery of §4 to make deferred conclusion order-independent, in
  exchange for the smallest possible on-chain vote footprint. Chosen because the per-vote
  storage win applies to every flow and every re-vote, and the concurrency machinery reuses
  patterns already in the contract (`do_update`-style clearing, `verify_vote`-style
  precondition checks).

## 9. Open questions

- **`conflict_key()` per variant.** The precise conflict class for each `Proposal` variant
  (§4.3) needs pinning down — especially the shared "leaves `Running`" class spanning
  `NewParameters` and `AddDomains`.
- **CRUD reveal-vs-hide.** For CRUD flows the entity *is* the (tiny) payload, so hiding it
  until `conclude` saves little and prevents entity-level conflict keys (§4.3). Whether CRUD
  flows should hide the payload at all, or reveal at vote time like today, is left per-flow.
- **TTL length and prune trigger.** What expiry is appropriate, how it interacts with the
  per-class store partitions (§4.3), and whether pruning is lazy (piggy-backed on
  `vote`/`conclude`) or a dedicated permissionless call.
- **`conclude` authorization and gas.** Who may call `conclude`, and who pays for the reveal
  transaction (which carries the full payload)?
- **Fusing the final vote and conclude.** Should `vote_and_conclude` (§4.1) be offered so the
  vote that reaches threshold concludes atomically, saving a round-trip?
- **Proposal-sharing service.** Is a dedicated off-chain service worth building, or is ad-hoc
  gossip sufficient in practice?
