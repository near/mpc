# Unified contract voting

The MPC contract exposes roughly fifteen `vote_*` entry points, and almost every one is
backed by its own bespoke vote-storage struct that re-implements the same primitives:
register a vote, replace a voter's previous vote, count votes for a proposal, prune voters
who left the participant set, and clear votes after a decision. This document proposes
consolidating the **governance / CRUD / configuration** flows onto a single
**on-chain commit-reveal** voting interface built on the existing generic `Votes<V>` primitive.
Here voting stays on-chain — each participant submits a `vote(hash)` transaction — and only the
proposal *payload* is shared off-chain. A more radical, *fully off-chain* voting alternative
(the tally itself moves off-chain, with a single aggregated submission on-chain) is a distinct
architecture, kept separate in §10.

To try and keep the scope small and with little complexity, we took two decisions: we build on the primitive that already exists rather
than inventing a new framework, and we explicitly **exclude** the protocol-driven key-event
votes, whose semantics do not fit a generic proposal interface (see §6).

## Table of Contents

1. [Goals](#1-goals)
2. [Current state analysis](#2-current-state-analysis)
3. [Proposed design — commit-reveal unified interface](#3-proposed-design--commit-reveal-unified-interface)
4. [Execution mechanics and conflicting proposals](#4-execution-mechanics-and-conflicting-proposals)
5. [Cleanup and TTL semantics](#5-cleanup-and-ttl-semantics)
6. [Scope — what migrates and what stays bespoke](#6-scope--what-migrates-and-what-stays-bespoke)
7. [Migration strategy](#7-migration-strategy)
8. [Cost model](#8-cost-model)
9. [Alternatives considered](#9-alternatives-considered)
10. [Alternative architecture: fully off-chain aggregated voting](#10-alternative-architecture-fully-off-chain-aggregated-voting)
11. [Open questions](#11-open-questions)

## 1. Goals

- **Consolidate** the ad-hoc governance/CRUD/config voting flows onto one interface, removing
  duplicated vote/count/replace/cleanup logic.
- **Reduce on-chain cost** by letting participants commit to a proposal with a 32-byte hash
  and revealing the full payload only once, when the proposal is executed.
- **Unify cleanup and TTL semantics** so that abandoned proposals cannot accumulate in
  contract storage indefinitely.

Non-goals: folding the protocol-driven key-event votes into the governance interface (§6.1
explains why they stay separate — though §6.2 notes they can be consolidated *among
themselves*), or building a dedicated off-chain proposal-sharing *service* — that service is
optional UX (§3.3); distributing proposals off-chain so voters can hash them is required, but
ad-hoc gossip suffices.

## 2. Current state analysis

### 2.1 The `vote_*` entry points

All entry points live in `crates/contract/src/lib.rs`. The **threshold** column is the passing
rule — how many votes a proposal needs to take effect. There are only three distinct rules
plus one special case:

- **`t-of-n`** — the **governance threshold** in `ThresholdParameters` (a subset suffices).
  The contract keeps this `>= max(reconstruction_threshold)` across domains, so a governance
  action can never pass with fewer voters than are needed to reconstruct a key.
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

`crates/contract/src/primitives/votes.rs` defines a generic `Votes<V>` that provides exactly
the hashing-based vote storage this design needs:

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
the payload. Deferring the payload until execution is the one genuinely new capability this
document proposes.

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

The `ProposalHash` derived from the `Proposal` enum doubles as the proposal's identifier, so
no separate id type is needed.

### 3.2 The API

```
vote(proposal_hash: ProposalHash)   // commit
execute(proposal: Proposal)        // reveal + execute
```

- `vote(class, proposal_hash)` records a 32-byte commitment for the caller in the `Votes<V>`
  partition for the proposal's conflict class (§4.2), keyed by their
  `AuthenticatedParticipantId`. Cheap and constant-size regardless of how large the proposal
  is.
- `execute(proposal)` recomputes `ProposalHash::from(&proposal)`, looks up its `VoterSet`, and
  **verifies the hash has enough votes to meet the variant's required threshold** —
  `count_for(is_current_participant)` against that threshold, which for the `t-of-n` governance
  variants is the governance threshold (kept `>= max(reconstruction_threshold)`, §2.1). It then
  re-validates the proposal against current state, executes the effect, and cleans up (§4).

Both `vote` and `execute` are **on-chain** transactions: the tally lives on-chain (as a set of
commitments), and each participant casts their own `vote`. Only the proposal *payload* travels
off-chain (§3.3). This is the defining difference from the fully off-chain alternative of §10,
where the tally itself is gathered off-chain.

This preserves every existing threshold rule; only the *shape* of the interface changes.
The execution step and its safety story are detailed in §4.

### 3.3 Off-chain payload sharing

The only off-chain step is distributing the proposal so voters can hash it: `vote` carries just
the hash. Gossip suffices — the author has every incentive to distribute it — so a dedicated
sharing *service* is **optional** and out of scope.

The preimage is no off-chain secret: `execute(proposal)` delivers it on-chain, and the contract
checks `hash(proposal)` matches a threshold-reaching vote before applying (§4.1). The only
liveness need is that one honest party still holds the proposal at execute time; §4.5 shows this
falls out of normal voting.

## 4. Execution mechanics and conflicting proposals

### 4.1 How `execute` fires

Execution is **necessarily a separate transaction**, not an automatic side effect of the
threshold-crossing vote. The vote that tips the threshold carries only the 32-byte hash, so
the contract does not hold the proposal payload and has nothing to execute at vote time. Once
a participant observes (off-chain) that a hash has reached threshold, they submit
`execute(proposal)` with the preimage they already hold from gossip. Execution may be called
by any participant.

For **unilateral** proposals (threshold 1) there is nothing to accumulate: the single
authorized caller crosses the threshold on their own, so the commit phase is redundant and the
flow collapses to a direct `execute(proposal)`. (The only unilateral vote today,
`vote_abort_key_event_instance`, is a
key-event vote and stays outside the governance interface (§6), but it already behaves this
way: it takes effect on its first and only vote.)

### 4.2 The out-of-order hazard (new to commit-reveal)

Separating the tally (`vote`) from the application (`execute`) in time creates a hazard that
**does not exist in the contract today**: several proposals can each cross threshold and sit
"decided but not applied," and the order in which someone calls `execute` is arbitrary. A
stale or superseded proposal could therefore be applied after a newer decision — e.g. two
competing `NewParameters`, or `AddLauncherHash(X)` racing `RemoveLauncherHash(X)`.

For contrast, every current `vote_*` method applies its effect **synchronously in the same
transaction that crosses the threshold**: `vote_update` calls `do_update` inline
(`lib.rs:1383`), which also clears all sibling entries and votes (`update.rs:199`), and
`vote_new_parameters` / `vote_add_domains` transition state inline and discard the old state's
tally. There is no "decided but not yet applied" window today, so this ordering problem is a
genuine *cost introduced by* commit-reveal, not a pre-existing bug (see also §9).

The design closes it with two complementary mechanisms: a per-class **execution lock** (§4.3)
and **precondition re-validation** (§4.4).

### 4.3 Conflict-class execution lock

Each `Proposal` variant declares a **conflict class** via a `conflict_key()`. Executing a
proposal acquires a per-class **execution lock**: while it is held, no other proposal in the
same class may execute, so a conflicting sibling cannot also be applied. The lock is on
*execution only* — it does **not** block vote gathering. Voting stays optimistic and
concurrent: several proposals in a class may keep accumulating votes at once (as `ProviderVotes`
already does per-chain, `foreign_chain_rpc.rs:192-196`), and the lock decides only which one gets
to apply. Sibling votes are **preserved**, not wiped.

The granularity of a conflict class is *not* uniformly "same proposal type":

| Flow shape | Conflict key | Executing one blocks… |
|---|---|---|
| Singleton (`NewParameters`, `TeeVerifierChange`, `Update`, `CodeHash`) | the variant/type | execution of all other proposals of that type — only one can win |
| State transition (`NewParameters`, `AddDomains`) | a shared "leaves `Running`" key | execution of proposals *across* variants that are mutually exclusive |
| CRUD (`AddLauncherHash`, `AddOsMeasurement`) | `(family, entity)` | only the same-entity opposite op (`Add(X)` vs `Remove(X)`); independent entries such as `Add(X)` and `Add(Y)` do **not** conflict |

So "one type, one lock" is correct for singletons, too coarse for CRUD (it would wrongly block
independent entries), and too narrow for state transitions (it would miss a mutually-exclusive
proposal of a different type). Note the state-transition classes are *already* serialized by the
protocol state machine — `vote_add_domains` runs only in `Running` (`state.rs:143`) and executing
a transition replaces the state variant (`running.rs:239`) — so the explicit lock mainly matters
for the non-phase-changing classes (code hash, launcher/OS hashes, tee verifier, foreign chain,
update).

**Lock lifecycle.** The lock is a small per-class record — the holder's hash plus an `expires_on`
block height; it does not touch the vote buckets. It is acquired on `execute` and released at the
end of that transaction for synchronous effects. For **asynchronous** effects it is held across
the callback: `do_update` deploys code and calls `migrate` via a `Promise` (`update.rs:195`–`226`),
and holding the lock until that resolves prevents a second `Update` executing mid-upgrade (see
§4.4 and the async-`execute` open question in §11). A block-height TTL (mirroring
`KeyEventInstance.expires_on`, set `key_event.rs:260`, checked `key_event.rs:269`, released lazily
by `cleanup_if_timed_out`, `key_event.rs:163`) is the automatic backstop against a hung lock. This
single-in-flight-slot pattern is exactly `KeyEvent`'s (`key_event.rs:65`–`79`), reused per conflict
class.

**Recovering a stuck lock.** When waiting for the TTL is unacceptable — an async effect that
hangs, or a holder that disappears — participants can **vote to install a fresh ephemeral lock**
that supersedes the stuck one, re-opening the class under a new holder and expiry. This override
is a governance action (a threshold of participants) and matters mainly on the governance side;
the state-transition classes already have their own cancel votes and the state machine to fall
back on. Crucially, the function that installs the ephemeral lock is **not itself gated by any
execution lock** — otherwise a stuck lock could block its own recovery — so it can always make
progress.

### 4.4 Precondition re-validation (the safety guarantee)

The execution lock stops a *decided* sibling from also applying, but it only serializes proposals
*within* a conflict class. It does nothing about the executing proposal's **own** staleness — a
threshold of participants could still execute (or re-vote and execute) a proposal whose base
state has drifted from cross-class changes or the mere passage of time (e.g. a `NewParameters`
authored against a since-replaced participant set). Therefore `execute` also **re-validates the
proposal's precondition against current state** and rejects it if no longer valid.

The lock keeps execution serialized and storage tidy; the precondition check is the actual safety
guarantee. Together they make execution order-independent. This mirrors existing prior art: the
key-event votes bind to a `KeyEventId` and `verify_vote` (`state/key_event.rs:173`) rejects votes
targeting a superseded attempt — the same slot-plus-staleness-check pairing the execution lock
uses.

### 4.5 Observability: how `execute` gets triggered

Commit-reveal changes what the chain reveals about a *pending* decision, and that interacts
with how off-chain actors watch the contract today:

- The contract emits **no structured events** for governance actions — outcomes are visible
  only through the mutated `ProtocolContractState`. Nodes learn of governance decisions by
  **polling the `state` view (~1s) and diffing the whole `ProtocolContractState`**
  (`node/src/indexer/participants.rs:266`, reacted to in `node/src/coordinator.rs:110`); the
  receipt indexer ignores every `vote_*` method (`node/src/indexer/handler.rs:221`). Nothing
  watches a vote *tally*.

Under commit-reveal the on-chain tally is a set of **opaque hashes**, so an observer that only
diffs state cannot tell *what* reached threshold, nor reconstruct a payload to execute, unless
it already holds the preimage. Three consequences:

1. **Someone must trigger `execute`.** An actor has to (a) hold the proposal, (b) notice its
   hash crossed threshold, and (c) submit `execute` — a **liveness** requirement, not optional
   UX. Any participant may execute (not just the proposer), so any voter still holding the
   proposal suffices. A **soft prevention** of losing the preimage: have the node's `vote`
   command take the full `Proposal` and hash it locally, so every voter retains what it voted on
   and can later `execute` it — no custody service needed. Only *soft*: the contract sees only
   the hash and cannot force clients to keep proposals.
2. **Outcomes stay observable.** `execute` mutates concrete `ProtocolContractState`, so existing
   state-diff detection still catches the *result* — only the intermediate tally is hidden, so
   no new event is required for correctness.
3. **An optional `execute` event** would spare indexers from diffing whole-state snapshots —
   worth considering, not required given (2).

### 4.6 Local hashing in the node's `vote` command

The soft prevention above is a client-side convention. The *contract* method is unchanged —
`vote(proposal_hash)` only ever sees a hash — but the node's vote helper takes the full
`Proposal` and hashes it locally, submitting only the 32-byte hash:

```rust
// today: the full payload goes on-chain; the contract hashes it
fn vote_code_hash(code_hash) { tx.call("vote_code_hash", code_hash); }

// commit-reveal: the node hashes the preimage locally and sends only the hash
fn vote(proposal: Proposal) {
    let hash = ProposalHash::from(&proposal);  // hash locally
    self.store.persist(&proposal);             // retain it for a later execute(proposal)
    tx.call("vote", hash);                     // only 32 bytes on-chain
}
```

Because the helper cannot run without the proposal, a node can never vote for a hash whose
preimage it does not hold (no blind voting), and any voter can later `execute(proposal)` from
its own retained copy without a separate custody actor.

**Caveat — canonical encoding.** Every voter must hash the *identical* borsh bytes, or two votes
for the "same" proposal produce different hashes and never converge on a threshold. The node's
local hashing must therefore use exactly the `ProposalHashEncoding` the contract applies at
`execute` time (§3.1), so the `Proposal` enum's serialization must be stable and shared.

## 5. Cleanup and TTL semantics

### 5.1 TTL

Because the execution lock (§4.3) is non-destructive, votes are never wiped when a proposal is
decided — reclaiming storage is left entirely to expiry. Both proposals that never reach threshold
and the losing siblings of one that does must expire so they cannot accumulate.

The TTL length is a **predefined contract parameter** (a config value), not an expiry date chosen
per proposal — this keeps it uniform and governable (adjustable via a config update) and stops a
proposer from setting its own deadline. Expiry is then *derived*, not stored: the contract stamps
each hashed proposal with an `updated_on` block height — set by the contract via
`env::block_height()`, **not modifiable by the nodes** — and the hash is expired once
`current_block > updated_on + TTL`. (`KeyEventInstance` stores an absolute `expires_on`,
`state/key_event.rs:248`, checked at `:270`, only because it has a single active slot; with many
concurrent hashes deriving expiry from the contract-wide TTL is simpler.) Expired hashes are
pruned lazily — on the next `vote`/`execute` that touches the flow — or via a permissionless
`prune` call.

The TTL is measured **relative to the last vote**, not creation: each `vote(hash)` makes the
contract refresh that hash's `updated_on` to the current block, so a hash still gathering votes
stays alive and only one idle for `TTL` blocks becomes prunable. Because `updated_on` is written
by the contract, a node cannot extend a proposal's life except by casting a real vote. This keeps
actively-contested proposals from being pruned out from under an in-progress tally while still
bounding storage for abandoned ones. The exact TTL value is an open question (§11).

### 5.2 Participant-set changes during a vote

Participant-set changes mid-vote are a subtlety the design must account for, and `Votes<V>`
handles it: it is keyed by `AuthenticatedParticipantId`,
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

They should **not** be folded into the governance `vote(hash)` / `execute(Proposal)`
interface:

- **Attempt-scoped, not free-floating.** Every key-event vote is bound to a `KeyEventId`
  (epoch + domain + `attempt_id`), and `KeyEvent::verify_vote`
  (`state/key_event.rs:173`) rejects votes that target a superseded attempt. A flat proposal
  store has no notion of "the current attempt."
- **Disagreement detection is the point.** `vote_pk` compares the submitted public keys and
  **aborts the attempt on mismatch** (`state/key_event.rs:135`). Under commit-reveal, two
  honest-but-diverging keys would simply produce two different hashes and reach no consensus
  *silently*, losing the explicit abort signal.
- **`execute` would become a god-method.** Executing these votes drives the core state
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

### 7.1 ABI and consumer migration

The state migration above is only half the story: collapsing ~15 public `vote_*` methods into
`vote`/`execute` is a **breaking ABI change**, which the rollout must stage.

- **The ABI is snapshot-locked.** `crates/contract/tests/abi.rs` asserts the full generated ABI
  against `abi__abi_has_not_changed.snap` (every method name, its params, and JSON schema;
  schema version pinned `0.4.0`), and the storage layout is locked by
  `mpc_contract__tests__mpc_contract_borsh_schema_has_not_changed.snap`. Both snapshots must be
  regenerated as each flow migrates.
- **In-repo consumers must move in lockstep:** the interface crate
  (`crates/near-mpc-contract-interface/`: `method_names.rs`, `call_args.rs`, `types/`), the
  devnet driver/CLI (`crates/devnet/src/mpc.rs`, `cli.rs`), and the sandbox suite
  (`crates/contract/tests/sandbox/`). (The node's *self-driven* key-event votes in
  `crates/node/src/key_events.rs` are out of scope — §6.)
- **External callers need a deprecation window.** Governance tooling and dashboards call the old
  method names directly. Recommend **dual-running** the old `vote_*` methods alongside
  `vote`/`execute` for a deprecation period — the old methods can delegate to the new path —
  rather than a hard cutover, and versioning the interface crate accordingly. This composes with
  the one-flow-at-a-time rollout above.

## 8. Cost model

Two facts drive the accounting:

- **Every vote is uniformly cheap.** `vote(hash)` stores a 32-byte `ProposalHash` for the caller
  and updates a reverse-index counter (`votes.rs:14`) — minimal computation, constant size,
  whatever the proposal. This matters because today the bespoke TEE vote maps store the **full
  payload once per voter** (they key `voter → payload` and count by *scanning* for equal values,
  `tee/proposal.rs:47`, `measurements.rs:58`). So committing a hash both shrinks per-voter storage
  to 32 bytes and replaces the O(voters) scan with an O(1) counter — a saving multiplied by the
  voter count and by every re-vote.
- **The payload is revealed once, by a single participant.** `execute` is one call: the executor
  carries the full payload and performs the apply that *one* actor pays anyway (today it is folded
  into whoever casts the threshold-crossing vote). The reveal is therefore **not** charged to
  every voter; the only added cost is the base overhead of that single extra transaction.

There is still no gas baseline for the `vote_*` methods today (the only gas suite,
`participants_gas.rs`, benchmarks the `Participants` struct, not voting), so establishing one
remains a prerequisite to putting exact numbers on this. The per-flow picture, with real borsh
payload sizes measured **per voter**:

| Flow | Payload | Stored per voter today | Under commit-reveal | Verdict |
|---|---|---|---|---|
| `AddOsMeasurement` / `RemoveOsMeasurement` | `ContractExpectedMeasurements` | **240 B** (5×48-B digests, `measurements.rs:166`) | 32 B | **big saving** |
| `NewParameters` | `ProposedThresholdParameters` | ~100 B × participants | 32 B | **big saving**, scales with set |
| `AddDomains` | `Vec<DomainConfig>` | ~25 B × domains | 32 B | saving when many |
| `CodeHash` | `NodeImageHash` | 32 B | 32 B | wash |
| `AddLauncherHash` / `RemoveLauncherHash` | `LauncherImageHash` | 32 B (+1) | 32 B | wash |
| `TeeVerifierChange` | account + code hash (~38–100 B) | 32 B — already hash-only | 32 B | already optimal |
| `ForeignChainProviders` | `ChainEntry` (URLs; variable, large) | 32 B — already hash-only | 32 B | already optimal |
| `Update` | `UpdateId` | 8 B | 32 B | mild loss |

- **Measurements is the standout** — 240 B per voter (`measurements.rs:166`) collapses to a
  32-byte hash, ~208 B saved per voter and again per re-vote.
- **`NewParameters` / `AddDomains` scale** with participant and domain count, so their per-voter
  saving grows with the network.
- **`CodeHash` / launcher hashes are already 32 bytes**, so hashing only normalizes the model.
- **`TeeVerifierChange` and `ForeignChainProviders` already store hash-only** via the generic
  `Votes<V>` (`verifier_votes.rs:44`, `foreign_chain_rpc.rs:148`) — the very scheme this design
  generalizes; migrating them changes nothing.
- **`Update` is the one mild loss**: `UpdateId` is 8 bytes (`update.rs:42`), smaller than a
  32-byte hash, and the large payload (the code) is already on-chain from `propose_update`.

**Net:** the vote is cheap for every flow, the payload is revealed once by a single participant,
and the storage/compute win is real wherever the payload exceeds 32 bytes — most governance flows,
dramatically so for OS measurements. Only the flows whose payload already *is* a 32-byte hash are
a wash, and only `Update` is a (mild) loss. This is a stronger case for commit-reveal than a
per-flow "+1 transaction" framing suggested; the remaining nuance for CRUD is the conflict-key
interaction of §4.3, not cost.

## 9. Alternatives considered

- **(a) Status quo** — keep every bespoke struct. Zero migration cost, but the duplicated
  vote/count/replace/cleanup logic keeps growing with each new flow, and TTL/cleanup remain
  inconsistent.
- **(b) Consolidate onto `Votes<V>`, keep reveal-at-vote** — migrate the in-scope flows onto
  the primitive but keep passing the full proposal at vote time (as `TeeVerifierVotes` /
  `ProviderVotes` do today). Simpler, needs no off-chain gossip, still removes the
  duplication, and — because it applies the effect atomically at threshold — **avoids the
  out-of-order execution hazard of §4.2 entirely**. Its cost is forgoing the storage/gas
  saving of committing to a 32-byte hash.
- **(c) Full commit-reveal (recommended)** — (b) plus deferring the payload to `execute`.
  Adds the requirement that voters obtain the preimage off-chain *and* the execution-lock +
  precondition machinery of §4 to make deferred execution order-independent, in exchange for the
  smallest possible on-chain vote footprint. Chosen because the per-vote storage win applies to
  every flow and every re-vote, and the concurrency machinery reuses patterns already in the
  contract (`KeyEventInstance`-style single-slot lock, `verify_vote`-style precondition checks).
- **(d) Fully off-chain aggregated voting** — a *different architecture*, not a tweak to (c):
  the tally itself moves off-chain and only a single aggregated (BLS) submission hits the chain.
  Because it is a distinct and more complex direction, it is written up separately in §10 rather
  than compared inline here.

## 10. Alternative architecture: fully off-chain aggregated voting

The proposal above (§3) keeps **voting on-chain**: every participant submits a `vote(hash)`
transaction, and only the payload is shared off-chain (§3.3). A more ambitious alternative moves
the **tally itself off-chain**, so an entire vote costs a *single* on-chain transaction. It is
more complex and depends on new cryptographic machinery, so it is recorded here as a separate
direction rather than folded into the main design.

### 10.1 Sketch

- Each participant signs the `ProposalHash` off-chain — there is no on-chain `vote` transaction.
- Once enough signatures are gathered, a **single** participant submits one transaction carrying
  the proposal opening plus the collected signatures.
- Ideally the signatures are combined into one constant-size **BLS aggregate signature** — all
  voters sign the *same* proposal hash, the ideal case for aggregation — accompanied by a signer
  bitmap.
- The contract reconstructs the aggregate public key from the participant set's registered BLS
  keys, runs a single pairing check, counts the bitmap (filtered to current participants, §5.2)
  against the variant's threshold, re-validates the precondition (§4.4), and applies the effect.

### 10.2 Why it is attractive

- **One transaction per decision, fleet-wide.** Where the on-chain design puts `n` `vote`
  transactions on-chain (plus an `execute`), this puts down a single submission regardless of
  participant count — the largest possible gas saving.
- **No out-of-order hazard.** Voting and application collapse into one atomic transaction, so it
  sidesteps the §4.2 hazard the same way option (b) does.

### 10.3 What it costs

- A **BLS key per participant** — new key material and lifecycle in the participant set, plus a
  **proof-of-possession at registration** to defend against rogue-key aggregation attacks.
- **On-chain pairing-based verification** — feasible on NEAR, which exposes pairing-check host
  functions (`alt_bn128` today, BLS12-381 via NEP-488), but the concrete curve, security margin,
  and gas cost need evaluation.
- **Replay protection** — the signed message must bind to current state (epoch / nonce /
  proposal hash) so a stale off-chain vote set cannot be replayed.
- **An off-chain aggregation role** — liveness needs only one honest aggregator (any participant
  may submit, so a chosen submitter cannot censor), but the per-vote on-chain audit trail is
  replaced by the submitted signature list.

### 10.4 Relationship to the main proposal

This is a *different architecture*, not a variant of §3: the main proposal hides the **payload**
until execution while keeping votes on-chain, whereas this moves the **votes** off-chain
entirely. The two are complementary — a design could layer commit-reveal payload hiding on top
of off-chain aggregated voting — but they are independent decisions. Open questions specific to
this direction are collected in §11.

## 11. Open questions

- **`conflict_key()` per variant.** The precise conflict class for each `Proposal` variant
  (§4.3) needs pinning down — especially the shared "leaves `Running`" class spanning
  `NewParameters` and `AddDomains`.
- **Execution-lock lifecycle (§4.3).** The release rule for synchronous vs asynchronous effects,
  the TTL length, and the exact semantics of the voted ephemeral-lock override (its threshold, and
  how the fresh lock supersedes the stuck one) all need pinning down.
- **CRUD reveal-vs-hide (conflict-key axis).** On cost, §8 favors hashing for CRUD (measurements
  save a lot; launcher/code hashes are a wash) — but hiding a CRUD payload until `execute` removes
  the contract's ability to derive the entity-level conflict keys of §4.3 from the vote. Whether
  any CRUD flow should reveal its (tiny) entity at vote time to keep those conflict keys, despite
  the storage cost, remains per-flow.
- **State-machine gating of `vote`/`execute`.** The current flows have divergent state
  requirements the unified API must still enforce: `vote_add_domains` and `vote_update` are
  Running-only (`state.rs:143`, `lib.rs:1350`), `vote_new_parameters` is Running/Resharing
  (`state.rs:126`), while the TEE/launcher/measurement/verifier/foreign-chain votes are legal in
  any initialized state (`state.rs:199`). The participant set authenticated against is also
  phase-dependent (Initializing→proposed, Running→current, Resharing→previous-running;
  `state.rs:222`). Open: which states permit `vote` and `execute` per variant, how the right
  participant set is selected, and what happens to accumulated votes when the contract *phase*
  changes mid-vote (§5.2 covers participant-set changes, not phase transitions). Note too that
  two *in-scope* variants (`NewParameters`, `AddDomains`) themselves drive
  Running→Resharing/Initializing transitions — the same "god-method" property used to exclude
  the key-event votes (§6.1); whether executing a state transition fits the `execute` mold
  cleanly needs resolving.
- **Async / fallible `execute` effects.** `execute` is modeled as apply-then-clean-up
  synchronously, but `do_update` applies **asynchronously**: it returns a `Promise` that deploys
  the new code and calls `migrate` (`update.rs:195`–`226`); success is unknown when `execute`
  returns. Holding the execution lock across the callback (§4.3) prevents a competing same-class
  execute mid-upgrade, but the design must still state how a **failed** `migrate` is handled — a
  confirmation callback that releases the lock and rolls back, or an explicit acceptance of the
  existing fire-and-forget semantics.
- **Anti-spam bound (a property to state).** `Votes<V>` keeps **one vote per voter per
  partition** — `vote()` drops the voter's prior vote first (`votes.rs:53`), so junk-hash
  commitments are bounded to `participants × conflict-classes` and each re-vote overwrites
  rather than accumulating. Worth stating explicitly, since commit-reveal invites the "what
  stops junk hashes?" question.
- **Variant → apply-helper mapping.** The §3.1 claim that each `Proposal` variant "knows how to
  apply its effect" should be pinned to the existing helpers, since there is no unified dispatch
  today and the threshold check lives inline in `lib.rs` for most flows: `do_update`
  (`update.rs:195`), `process_new_parameters_proposal` (`running.rs:143`),
  `DomainRegistry::add_domains` (`domain.rs:123`), `TeeState::whitelist_tee_proposal` / `add_*` /
  `remove_*` (`tee_state.rs:305`–`377`), `TeeVerifierVotes::vote` (`verifier_votes.rs:64`),
  `ForeignChainRpcWhitelist::vote` (`foreign_chain_rpc.rs:222`). A mapping table would validate
  feasibility and surface the transition/Promise mismatches above.
- **TTL length and prune trigger.** What expiry is appropriate, how it interacts with the
  per-class store partitions (§4.3), and whether pruning is lazy (piggy-backed on
  `vote`/`execute`) or a dedicated permissionless call.
- **`execute` authorization and gas.** Who may call `execute`, and who pays for the reveal
  transaction (which carries the full payload)?
- **Proposal-sharing service.** Is a dedicated off-chain service worth building, or is ad-hoc
  gossip sufficient in practice?
- **Aggregated off-chain submission (§10).** Is the gas saving of a single aggregated
  submission worth introducing per-participant BLS keys and pairing-based verification? Which
  curve and host functions (`alt_bn128` vs BLS12-381 / NEP-488), and what is the on-chain
  verification gas cost relative to the `n` `vote` transactions it replaces? How are the BLS
  keys registered, rotated, and bound to participants (proof-of-possession), and how does the
  off-chain signature-collection role interact with the participant-set changes of §5.2?
