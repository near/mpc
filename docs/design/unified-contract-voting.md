# Unified contract voting

The MPC contract exposes fifteen `vote_*` entry points. Four of them already tally through the
generic `Votes<V>` primitive; the other governance flows each carry a bespoke vote-storage struct
that re-implements the same primitives: register a vote, replace a voter's previous vote, count
votes for a proposal, prune voters who left the participant set, and clear votes after a
decision. This document proposes consolidating the **governance / CRUD / configuration** flows
onto a single `vote(Proposal)` entry point built on `Votes<V>`.

The shape is **reveal-at-vote with atomic application**: every vote carries the full proposal,
the contract hashes it and stores only the 32-byte hash per voter, and the vote that crosses the
threshold applies the effect **in the same receipt**. Deciding and applying are one atomic step,
so there is no "decided but not yet applied" window to protect, no execution lock, no deferred
reveal, and no off-chain custody of proposal payloads. The one flow whose payload is too large
to carry per vote — the contract update — already runs a separate reveal step on `main` and
stays that way (§4.5). A *fully off-chain* alternative (the tally itself moves off-chain, with a
single aggregated submission on-chain) is a distinct architecture, kept separate in §10.

Two scope decisions keep this small: build on the primitive that already exists rather than
inventing a new framework, and explicitly **exclude** the protocol-driven key-event votes, whose
semantics do not fit a generic proposal interface (§6).

> **Revision note.** An earlier draft of this document proposed hash-only votes with a separate
> `execute(proposal)` step (commit-reveal), serialized by per-class execution locks. That
> direction was dropped: §9(c) records why.

All file and line references below are against `main` at `v3.17.0`.

## Table of Contents

1. [Goals](#1-goals)
2. [Current state analysis](#2-current-state-analysis)
3. [Proposed design — one `vote(Proposal)` entry point](#3-proposed-design--one-voteproposal-entry-point)
4. [Atomic application and conflicting proposals](#4-atomic-application-and-conflicting-proposals)
5. [Cleanup semantics](#5-cleanup-semantics)
6. [Scope — what migrates and what stays bespoke](#6-scope--what-migrates-and-what-stays-bespoke)
7. [Migration strategy](#7-migration-strategy)
8. [Cost model](#8-cost-model)
9. [Alternatives considered](#9-alternatives-considered)
10. [Alternative architecture: fully off-chain aggregated voting](#10-alternative-architecture-fully-off-chain-aggregated-voting)
11. [Open questions](#11-open-questions)

## 1. Goals

- **Consolidate** the ad-hoc governance/CRUD/config voting flows onto one interface, removing
  duplicated vote/count/replace/cleanup logic.
- **Shrink per-voter storage to a 32-byte hash** for every flow, without deferring the payload:
  the contract hashes what the voter sends and keeps only the digest.
- **Unify cleanup semantics**: the winning proposal clears its partition, departed voters are
  pruned after resharing, and a voter can withdraw — the same three rules for every flow.

Non-goals: folding the protocol-driven key-event votes into the governance interface (§6.1
explains why they stay separate — though §6.2 notes they can be consolidated *among
themselves*); any off-chain proposal-sharing service (voters send the proposal with their vote,
so nothing has to be distributed out of band); the fully off-chain tally of §10.

## 2. Current state analysis

### 2.1 The `vote_*` entry points

The entry points live under `crates/contract/src/api/`. The **threshold** column is the passing
rule — how many votes a proposal needs to take effect. There are only three distinct rules plus
one special case:

- **`t-of-n`** — the **governance threshold** in `GovernanceThresholdParameters`. The contract
  keeps it `>=` every domain's reconstruction threshold
  (`validate_domains_against_governance`, `state/running.rs:182`), so a governance action can
  never pass with fewer voters than are needed to reconstruct a key.
- **`n-of-n (current)`** — every participant in the *current* set must vote (unanimity).
- **`n-of-n (proposed)`** — every participant in the *incoming* set must vote; distinct from
  the above only because the participant set itself is being changed.
- **`unilateral`** — a single participant suffices.

| Entry point | Location | Backing store | Threshold | Shape |
|---|---|---|---|---|
| `vote_new_parameters` | `api/governance.rs:31` | `GovernanceThresholdParametersVotes` | `n-of-n (proposed)` | singleton |
| `vote_add_domains` | `api/governance.rs:92` | `AddDomainsVotes` | `n-of-n (current)` | singleton |
| `vote_pk` | `api/key_events.rs:40` | `KeyEventInstance` | `n-of-n (current)` | key-event |
| `vote_reshared` | `api/key_events.rs:98` | `KeyEventInstance` | `n-of-n (current)` | key-event |
| `vote_cancel_resharing` | `api/key_events.rs:178` | `BTreeSet` in resharing state | `t-of-n` | key-event |
| `vote_cancel_keygen` | `api/key_events.rs:196` | `BTreeSet` in initializing state | `t-of-n` | key-event |
| `vote_abort_key_event_instance` | `api/key_events.rs:209` | `KeyEventInstance` | `unilateral` | key-event |
| `vote_contract_update` | `api/update.rs:82` | `ContractUpdateVotes` = `Votes<_>` | `t-of-n` | singleton, **hash-only** |
| `vote_mpc_node_manifest_digest` | `api/tee_measurements.rs:17` | `TeeState::votes` = `Votes<_>` | `t-of-n` | singleton |
| `vote_add_launcher_hash` | `api/tee_measurements.rs:54` | `LauncherHashVotes` | `t-of-n` | CRUD (add) |
| `vote_remove_launcher_hash` | `api/tee_measurements.rs:90` | `LauncherHashVotes` | `n-of-n (current)` | CRUD (remove) |
| `vote_add_os_measurement` | `api/tee_measurements.rs:119` | `MeasurementVotes` | `t-of-n` | CRUD (add) |
| `vote_remove_os_measurement` | `api/tee_measurements.rs:147` | `MeasurementVotes` | `n-of-n (current)` | CRUD (remove) |
| `vote_update_foreign_chain_providers` | `api/foreign_chain/support.rs:76` | `ProviderVotes` = `Votes<_>` | `t-of-n` (per chain) | CRUD (per chain) |
| `vote_tee_verifier_change` | `api/tee_verifier.rs:22` | `TeeVerifierVotes` = `Votes<_>` | `t-of-n` | singleton |

Backing structs:

- `GovernanceThresholdParametersVotes` — `crates/contract/src/primitives/threshold_votes.rs:12`
  (carries `TODO(#2825)` to move onto `Votes<V>`)
- `AddDomainsVotes` — `crates/contract/src/primitives/domain.rs:258`
- `LauncherHashVotes` — `crates/contract/src/tee/proposal.rs:33`
- `MeasurementVotes` — `crates/contract/src/tee/measurements.rs:15`
- `ContractUpdateVotes` — `crates/contract/src/update.rs:15`
- `TeeState::votes` (node manifest digest) — `crates/contract/src/tee/tee_state.rs:91`
- `TeeVerifierVotes` — `crates/contract/src/tee/verifier_votes.rs:43`
- `ProviderVotes` — `crates/contract/src/foreign_chain_rpc.rs:120`
- `KeyEventInstance` — `crates/contract/src/state/key_event.rs:242`

Around the vote methods sit three kinds of secondary endpoint that a unified interface must also
cover: **withdrawals** (`withdraw_tee_verifier_vote`, `api/tee_verifier.rs:60`;
`remove_contract_update_vote`, `api/update.rs:114`), **post-resharing sweeps** that drop votes
from departed participants (fanned out as detached self-calls from `vote_reshared`,
`api/key_events.rs:112`–`159`), and **tally views** (`contract_update_votes`,
`tee_verifier_votes`, `launcher_hash_votes`, `mpc_node_manifest_digest_votes`,
`os_measurement_votes`). Only some flows have a withdrawal today; the unified interface gives
every flow one.

### 2.2 The primitive already exists

`crates/contract/src/primitives/votes.rs:16` defines a generic `Votes<V>`:

```rust
pub struct Votes<V>
where
    V: BorshSerialize + Ord,
{
    proposal_by_voter: IterableMap<V, ProposalHash>,
    votes_by_proposal: IterableMap<ProposalHash, VoterSet<V>>,
}
```

- A vote stores a `ProposalHash` — a 32-byte digest (`crates/primitives/src/hash.rs:247`).
  Any type becomes a proposal by implementing `ToProposalHash`
  (`crates/contract/src/primitives/proposal_hash.rs:78`, #4371), choosing a serializer
  (`Borsh`, `Json`, or `Identity` for values that already are a digest) and a hasher (`Sha256`
  or `Identity`).
- `vote()` (`votes.rs:53`) replaces a voter's prior vote automatically (idempotent re-votes).
- `votes_by_proposal` is a reverse index, so counting votes for a proposal is one lookup.
- `VoterSet::count_participants(participants)` (`votes.rs:159`) counts only voters still in a
  given participant set.
- Cleanup is first-class: `remove_vote` (`:76`), `remove_votes_for_proposal` (`:98`),
  `retain_votes(predicate)` (`:108`), `clear` (`:120`).

**Four flows already use it**, in two different shapes:

- **Reveal-at-vote** (three flows): the call carries the full proposal, the contract hashes it,
  stores the hash, and applies the effect in the same call when the count crosses threshold.
  `TeeVerifierVotes::vote` (`tee/verifier_votes.rs:63`) hashes a `VerifierChangeProposal`
  with Borsh + SHA-256 and clears all pending votes on a win (`:79`).
  `ProviderVotes::vote` (`foreign_chain_rpc.rs:145`) keys voters by `(participant, chain)`
  (`:121`), counts per chain (`:157`), and on a win drops only that chain's rows (`:163`).
  The node manifest digest (`tee_state.rs:336`, #4403) treats the 32-byte `NodeImageHash` as
  its own proposal hash (`tee/proposal.rs:16`) and clears the tally when it whitelists
  (`tee_state.rs:367`).
- **Vote-then-submit** (one flow): `vote_contract_update(update_hash)` (`api/update.rs:82`,
  #4537) records a hash of the update; `submit_contract_update(update)` (`api/update.rs:23`)
  later carries the payload, re-counts the hash's votes against the current participant set
  (`:48`–`:56`), clears every update vote (`:57`), and dispatches the deploy-and-migrate or
  config-update promise (`:58`–`:75`). This is commit-reveal for one flow, and it runs
  **without any lock** — §4.5 explains why that is sound.

The remaining governance flows each reinvent a subset of the same behavior over a plain
`BTreeMap`, counting by scanning every voter's stored payload for equality
(`tee/proposal.rs:58`, `tee/measurements.rs:40`, `primitives/threshold_votes.rs:19`,
`primitives/domain.rs:278`).

### 2.3 What is *not* implemented today

There is no single entry point, no shared `Proposal` type, and no uniform rule for which votes
survive a decision or a resharing: each flow decides for itself what to clear and when. The
partition/threshold/apply triple of §3 is the genuinely new part; the storage primitive and both
tally shapes already exist.

## 3. Proposed design — one `vote(Proposal)` entry point

### 3.1 One proposal enum

Introduce a single enum whose variants carry their payloads, and derive the hash from it through
`ToProposalHash` with `Borsh` + `Sha256`:

```rust
enum Proposal {
    AddLauncherHash(LauncherImageHash),
    RemoveLauncherHash(LauncherImageHash),
    AddOsMeasurement(ExpectedMeasurements),
    RemoveOsMeasurement(ExpectedMeasurements),
    NodeManifestDigest(NodeImageHash),
    TeeVerifierChange(VerifierChangeProposal),
    ForeignChainProviders { chain: ForeignChain, entry: ChainEntry },
    AddDomains(Vec<DomainConfig>),
    NewParameters { prospective_epoch_id: EpochId, proposal: ProposedGovernanceThresholdParameters },
}
```

Because the borsh encoding of an enum is prefixed with its variant discriminant, the derived
`ProposalHash` is domain-separated across variants for free: a hash cast for
`AddLauncherHash(X)` can never pool with one for `RemoveLauncherHash(X)`. Each variant knows
(a) its **partition** (§3.3), (b) its **electorate and threshold** (§3.4), (c) how to
**validate** itself against current state (§4.3), and (d) how to **apply** its effect (§3.5).

Binding fields that today travel as separate arguments move *into* the payload. For example
`vote_new_parameters(prospective_epoch_id, proposal)` becomes one variant carrying both, so the
epoch is part of the hash and votes cast against different epochs never pool — strictly stronger
than the current argument check at `state/running.rs:111`–`119`.

### 3.2 The API

```
vote(proposal: Proposal) -> VoteOutcome        // tally, and apply if this vote crosses threshold
withdraw_vote(family: ProposalFamily)          // drop the caller's vote in one partition
votes(family: ProposalFamily) -> tally view    // hash → voters
```

The generic path, with per-variant hooks in bold:

```rust
pub fn vote(&mut self, proposal: dtos::Proposal) -> Result<VoteOutcome, Error> {
    let proposal: Proposal = proposal.try_into_contract_type()?;
    let (electorate, required) = proposal.electorate(&self.protocol_state)?;   // §3.4
    let voter = AuthenticatedParticipantId::new(electorate)?;

    proposal.validate(self)?;                                                   // §4.3, every vote

    let family = proposal.family();                                             // §3.3
    let hash = proposal.to_proposal_hash();
    let count = self
        .governance_votes
        .vote((voter, family), hash)
        .count_for(|(p, f)| *f == family && electorate.is_participant(p));

    if count < required {
        return Ok(VoteOutcome::Pending { votes: count, required });
    }
    self.governance_votes.retain_votes(|(_, f)| *f != family);                 // §4.2
    proposal.apply(self)?;                                                      // §3.5, same receipt
    Ok(VoteOutcome::Applied)
}
```

`vote` is an **on-chain** transaction carrying the full proposal; there is no second step. The
contract hashes the *deserialized* struct, so the encoding is canonical by construction — two
voters who submit the same proposal with different JSON key order still land in the same bucket.

The foreign-chain flow today accepts a batch keyed by chain
(`api/foreign_chain/support.rs:78`) and applies each chain independently within one call
(`foreign_chain_rpc.rs:198`–`208`). Under the unified entry point that is either one `vote`
per chain or a thin `vote_many` that loops; since each chain is its own partition, several may
cross threshold in one receipt without interfering.

### 3.3 Partitions

The store is one `Votes<(AuthenticatedParticipantId, ProposalFamily)>`, the `ProviderVotes`
shape generalized: a voter holds **at most one vote per family**, and families never see each
other's votes. A family is the unit that a winning proposal clears (§4.2). The default is one
family per flow, which is exactly what each bespoke struct enforces today:

| Family | Variants | Today's store | Cleared today by |
|---|---|---|---|
| `NewParameters` | `NewParameters` | `GovernanceThresholdParametersVotes` | transition to Resharing (`running.rs:122`) |
| `AddDomains` | `AddDomains` | `AddDomainsVotes` | transition to Initializing (`running.rs:235`) |
| `NodeManifestDigest` | `NodeManifestDigest` | `TeeState::votes` | `whitelist_tee_proposal` (`tee_state.rs:367`) |
| `Launcher` | `AddLauncherHash`, `RemoveLauncherHash` | `LauncherHashVotes` | `add_launcher_image` / `remove_launcher_image` (`tee_state.rs:416`, `:426`) |
| `OsMeasurement` | `AddOsMeasurement`, `RemoveOsMeasurement` | `MeasurementVotes` | `add_measurement` / `remove_measurement` (`tee_state.rs:447`, `:453`) |
| `TeeVerifier` | `TeeVerifierChange` | `TeeVerifierVotes` | `TeeVerifierVotes::vote` (`verifier_votes.rs:79`) |
| `ForeignChain(chain)` | `ForeignChainProviders` | `ProviderVotes` | per-chain `retain_votes` (`foreign_chain_rpc.rs:163`) |

Note that `Launcher` and `OsMeasurement` already share one map across their add and remove
variants (`LauncherVoteAction`, `MeasurementVoteAction`), so a participant cannot hold
`Add(X)` and `Remove(Y)` at once today; the family table preserves that. Whether CRUD families
should instead be keyed per entity (`Launcher(X)`), as the foreign-chain flow is keyed per
chain, is an open question (§11) — it changes only the clearing granularity, nothing else.

### 3.4 Electorate and threshold per variant

The threshold rules of §2.1 are unchanged; `Proposal::electorate` returns the participant set
that may vote and the number of votes required:

- `t-of-n` variants use the phase-appropriate `GovernanceThresholdParameters`
  (`ProtocolContractState::threshold_parameters`, `state.rs:181`: Initializing → proposed set,
  Running → current set, Resharing → previous running set).
- `n-of-n (current)` variants require `participants.len()` votes from the same set
  (`api/tee_measurements.rs:108`, `running.rs:233`).
- `NewParameters` is special: the electorate is the *proposed* set, and a voter who is not yet
  a current participant is admitted only after `t` current participants have voted for the
  same proposal (`running.rs:191`–`200`). That admission rule is part of this variant's
  `validate`, not of the generic path.

### 3.5 Apply helpers

`Proposal::apply` dispatches to the helpers that exist today; nothing is re-implemented:

| Variant | Apply helper |
|---|---|
| `NewParameters` | `process_new_parameters_proposal` + `transition_to_resharing_no_checks` (`state/running.rs:143`, `:66`), re-proposal path `state/resharing.rs:56` |
| `AddDomains` | `DomainRegistry::add_domains` (`primitives/domain.rs:142`) + Initializing transition (`state/running.rs:234`–`245`) |
| `NodeManifestDigest` | `TeeState::whitelist_tee_proposal` (`tee/tee_state.rs:362`) |
| `AddLauncherHash` / `RemoveLauncherHash` | `TeeState::add_launcher_image` / `remove_launcher_image` (`tee/tee_state.rs:410`, `:425`) |
| `AddOsMeasurement` / `RemoveOsMeasurement` | `TeeState::add_measurement` / `remove_measurement` (`tee/tee_state.rs:446`, `:452`) |
| `TeeVerifierChange` | assign `tee_verifier_account_id` (`api/tee_verifier.rs:52`) |
| `ForeignChainProviders` | `AllowedProviders::replace` (`foreign_chain_rpc.rs:205`) + `recompute_available_foreign_chains` (`api/foreign_chain/support.rs:103`) |

The two state-transition variants return a new `ProtocolContractState` rather than mutating in
place, so `apply` must be allowed to replace `self.protocol_state` (as `api/governance.rs:59`
and `:101` do today). That is a signature detail, not a design problem: the unified `vote` is a
thin dispatcher over helpers that already perform these transitions.

## 4. Atomic application and conflicting proposals

### 4.1 Apply in the threshold-crossing receipt

A NEAR function-call receipt executes atomically: either every state change it makes is
committed, or none is. Because `vote` tallies **and** applies in the same receipt, a proposal is
never observable as "decided but not yet applied". Two proposals in the same family therefore
cannot both be decided and then applied in an arbitrary order — the first receipt whose vote
crosses threshold applies and clears the family (§4.2), and any later vote for the sibling
starts from an empty tally against the *new* state.

Each `vote` call carries exactly one proposal, so at most one threshold crossing happens per
call. A caller may still batch several `vote` actions into one transaction; they execute in
order within the receipt, each against the state left by the previous one, and a failing later
action reverts the whole receipt including an earlier successful apply. That is the caller's
own footgun, identical to batching any two contract calls today, and needs no contract-side
guard.

This is the property every current flow already has — `vote_tee_verifier_change` assigns the
new verifier inline (`api/tee_verifier.rs:47`–`53`), `vote_new_parameters` transitions inline
(`api/governance.rs:55`–`60`) — generalized rather than invented.

### 4.2 The winner clears its family

When a proposal crosses threshold, `vote` drops every vote in that family before applying
(`retain_votes(|(_, f)| *f != family)`). This is the single rule that replaces the per-flow
clearing calls in §3.3, and it is what makes conflicting proposals safe:

- A **competing sibling** (`NewParameters` A vs B, `AddLauncherHash(X)` vs
  `RemoveLauncherHash(X)`) loses its accumulated votes the moment the winner applies. To revive
  it, participants must re-vote against the post-apply state, and the sibling's `validate`
  (§4.3) then runs against that state.
- **Independent entries** in a CRUD family (`AddLauncherHash(X)` vs `AddLauncherHash(Y)`) are
  also cleared, as they are today (`tee_state.rs:416`). If that is judged too coarse, the
  family key gains the entity (§11); the rule itself does not change.

No lock, TTL, or override vote is needed, because there is no in-flight state to serialize:
the family is either tallying or being applied, and both happen inside one receipt.

### 4.3 Precondition validation on every vote (the safety guarantee)

Clearing the family protects against *siblings*; it does nothing about the winning proposal's
**own** staleness — a proposal authored against state that an unrelated family has since
changed. `Proposal::validate` runs on **every** vote, including the one that crosses threshold,
so the apply is always checked against the state it will actually mutate. Earlier voters
committed to the exact payload by hash, so what gets applied is what they voted for.

The checks are the ones the flows already perform at vote time, moved behind one hook:

- `NewParameters`: `prospective_epoch_id` must be the next epoch (`state/running.rs:111`),
  the proposal must be valid against current parameters
  (`validate_incoming_proposal`, `primitives/thresholds.rs:123`), every proposed participant
  must hold a valid attestation (`api/governance.rs:47`–`82`), and the governance threshold
  must dominate every domain's reconstruction threshold (`running.rs:182`).
- `AddDomains`: non-empty, contiguous ids starting at `next_domain_id`, valid purposes
  (`running.rs:215`–`230`, `domain.rs:142`).
- `TeeVerifierChange`: candidate differs from the current verifier (`api/tee_verifier.rs:36`).
- `RemoveOsMeasurement`: removal must leave at least one measurement
  (`tee/measurements.rs:97`–`101`).

This mirrors existing prior art: the key-event votes bind to a `KeyEventId`, and `verify_vote`
(`state/key_event.rs:173`) rejects votes targeting a superseded attempt.

### 4.4 Observability

Reveal-at-vote changes nothing about what the chain reveals:

- The contract emits **no structured events** for governance actions — outcomes are visible
  only through the mutated state. Nodes learn of decisions by polling the `state` view every
  second and diffing it (`monitor_contract_state`, `crates/node/src/indexer/participants.rs:309`,
  refresh interval `:314`, diff `:365`), reacted to in `crates/node/src/coordinator.rs:115`
  and `:223`. The receipt indexer matches only `sign`, `request_app_private_key` and
  `verify_foreign_transaction` and ignores every `vote_*` method
  (`crates/node/src/indexer/handler.rs:178`–`224`). Nothing watches a vote *tally*.
- Under the unified interface the apply still mutates concrete state in the crossing receipt,
  so state-diff detection catches the result exactly as it does today.
- The tally stays legible: `votes(family)` returns hash → voters, and any participant can
  recompute a hash from a proposal they hold. The per-flow tally views of §2.1 become one.
- An **optional event** on apply would spare indexers from diffing whole-state snapshots —
  worth considering, not required.

### 4.5 The one deferred flow: contract updates

`Update::Code` carries the full wasm (`near-mpc-contract-interface/src/types/updates.rs:13`),
far too large to send with every vote. `main` therefore already runs this flow as
**vote-then-submit** (#4537): `vote_contract_update(UpdateHash)` records a 32-byte hash of the
update (`api/update.rs:82`–`96`, hashed by `near_mpc_sdk::update::hash_with`,
`crates/near-mpc-sdk/src/update.rs:14`), and `submit_contract_update(Update)` is the reveal
(`api/update.rs:23`–`78`). This *is* a decided-but-not-applied window, and it is sound
without a lock for three reasons that the implementation already encodes:

1. **`submit` re-checks the threshold at submit time** against the *current* participant set
   (`:48`–`:56`), not against a cached decision, and rejects with `UpdateNotApproved`
   otherwise.
2. **`submit` clears the whole family** before dispatching (`:57`). Two approved hashes race
   only to the first `submit`; the loser's votes are gone and must be re-cast against the
   upgraded contract.
3. **The effect is one detached promise to self** (`:58`–`:75`). A second update cannot be
   approved before it lands without a complete fresh vote.

That is the same "winner clears its family" rule as §4.2, triggered by the submit receipt
instead of the crossing vote. The design keeps this flow exactly as it is. Its tally already
lives on `Votes<V>` (`update.rs:15`), so it is consolidated at the primitive level; whether to
also route the tally through `vote(Proposal::ContractUpdate(UpdateHash))` — a variant whose
`apply` is a no-op and whose family is cleared by `submit` rather than at threshold — is an
open question (§11). The pre-existing question of what happens when the dispatched `migrate`
fails is unchanged by this document.

## 5. Cleanup semantics

### 5.1 Storage is bounded without a TTL

`Votes<V>` keeps **one vote per voter per family** — `vote()` drops the voter's prior vote
first (`votes.rs:55`) — so the store can never hold more than `participants × families`
entries, each a 32-byte hash plus its key. A re-vote overwrites rather than accumulates, and a
win clears the family (§4.2). Junk hashes are therefore bounded by construction, which answers
the "what stops spam?" question without an expiry mechanism.

### 5.2 Participant-set changes during a vote

Participant-set changes mid-vote are a subtlety the design must account for, and `Votes<V>`
handles it: it is keyed by `AuthenticatedParticipantId`, counting always filters to the
electorate via `count_for`, and `retain_votes(predicate)` prunes voters who have left. The
post-resharing sweep that today fans out one self-call per store
(`api/key_events.rs:112`–`159`) collapses to one call over the single partitioned store, and
the current flows' defensive filtering at count time (`api/update.rs:52`,
`foreign_chain_rpc.rs:157`) keeps the tally correct even if that sweep fails. This is a
primary reason to build on the existing primitive rather than a fresh `BTreeMap`.

Phase transitions are handled by the family rule: `NewParameters` and `AddDomains` clear their
own family when they apply, and their electorate is re-derived from the new phase on the next
vote (§3.4).

### 5.3 Optional vote expiry

None of the flows expires votes today, and §5.1 shows storage does not need it. A TTL would
only address *stale intent* — a vote cast long ago that still counts when the same proposal
resurfaces. If that is wanted, the shape is: the contract stamps each hash with an `updated_on`
block height on every vote (set via `env::block_height()`, not modifiable by callers), a
contract-wide TTL config value, and lazy pruning on the next `vote` that touches the family.
Deliberately left out of the core design; see §11.

## 6. Scope — what migrates and what stays bespoke

**In scope (move onto `vote(Proposal)`)** — the governance/CRUD/config flows: add/remove
launcher hash, add/remove OS measurement, node manifest digest, TEE verifier change,
foreign-chain providers, add domains, new parameters.

**Consolidated at the primitive, kept as its own entry points** — contract update
(`vote_contract_update` / `submit_contract_update`), for the payload-size reason of §4.5.

**Out of scope for the governance interface** — the protocol-driven key-event votes:
`vote_pk`, `vote_reshared`, `vote_cancel_resharing`, `vote_cancel_keygen`,
`vote_abort_key_event_instance`.

### 6.1 Why the key-event votes stay separate

They should **not** be folded into `vote(Proposal)`:

- **Attempt-scoped, not free-floating.** Every key-event vote is bound to a `KeyEventId`
  (epoch + domain + `attempt_id`), and `KeyEvent::verify_vote` (`state/key_event.rs:173`)
  rejects votes that target a superseded attempt. A flat proposal store has no notion of "the
  current attempt."
- **Disagreement detection is the point.** `vote_pk` compares the submitted public keys and
  **aborts the attempt on mismatch** (`state/key_event.rs:135`). Under a hash tally, two
  honest-but-diverging keys would simply produce two different hashes and reach no consensus
  *silently*, losing the explicit abort signal.
- **The node drives them.** These votes are sent by the node's own key-event loop
  (`crates/node/src/key_events.rs:117`, `:355`), not by operators, and their payloads are
  protocol-generated and tiny; there is no duplication to remove and no operator-facing API to
  simplify.
- **They drive the core state machine** — advancing domains, transitioning between Running /
  Initializing / Resharing, and firing the post-resharing cleanup fan-out
  (`api/key_events.rs:107`–`160`). That is a different job from "apply a governance proposal."

### 6.2 Consolidation available *within* the key-event family

The five nonetheless carry only **three** distinct semantics, so they can be consolidated among
themselves (independently of the governance interface):

| Group | Methods today | Threshold | Effect |
|---|---|---|---|
| Success attestation | `vote_pk`, `vote_reshared` | `n-of-n (current)`, attempt-scoped | advance the state machine |
| Cancel the key event | `vote_cancel_resharing`, `vote_cancel_keygen` | `t-of-n` | → `Running` |
| Abort the attempt | `vote_abort_key_event_instance` | unilateral (first voter) | retry with next `attempt_id` |

- **Merge `vote_pk` + `vote_reshared` into one success-attestation method.** They already
  share `verify_vote` and the same unanimity tally (`KeyEvent::vote_success`,
  `state/key_event.rs:116`); the only difference is the payload — keygen carries a newly
  generated public key (with disagreement detection), resharing carries nothing. A single
  method taking an `Option<PublicKey>` covers both. This is a clean 2→1 win.
- **Merging `vote_cancel_resharing` + `vote_cancel_keygen`** into one state-dispatching method
  is possible but largely cosmetic: their side effects genuinely diverge
  (`state/initializing.rs:117` permanently deletes the remaining domains and keeps the
  generated ones; `state/resharing.rs:173` restores the previous parameters).
- **`vote_abort_key_event_instance` stays on its own** — it is unilateral
  (`KeyEvent::vote_abort`, `state/key_event.rs:145`, drops the instance on the first vote),
  not a tally, so it does not share the counting machinery at all.

Net: the key-event surface can shrink from five methods to roughly three, sharing the
`KeyEventInstance` lifecycle, while remaining a **sibling** interface to the governance one
rather than being merged into it.

## 7. Migration strategy

The contract is upgradeable through `submit_contract_update`, so rollout is incremental, one
family at a time:

1. **Introduce the skeleton**: the `Proposal` enum, `vote` / `withdraw_vote` / `votes`, and
   the partitioned store under a new pair of storage keys (the `storage_keys.rs:41`–`44`
   pattern). Move the three reveal-at-vote `Votes<V>` adopters first — they already store
   hashes, so this changes keys and dispatch, not semantics.
2. **Migrate the bespoke stores**, starting with `#2825` (`GovernanceThresholdParametersVotes`
   must leave `RunningContractState`, which the TODO at `threshold_votes.rs:8` already calls
   for), then `AddDomainsVotes`, `LauncherHashVotes`, `MeasurementVotes`. Each is a stored
   layout change and needs a state migration on upgrade, in the `v3_16_0_state.rs` style. We
   recommend **clearing in-flight votes at the upgrade boundary** (a short governance quiet
   period) rather than migrating live tallies — vote state is cheap to re-cast and this avoids
   fragile per-struct migration code.
3. **Dual-run** the old `vote_*` names as thin delegates to `vote` for a deprecation window,
   then remove them. The interface crate already does this for the legacy update methods
   (`TODO(#4513)`, `method_names.rs:30`), which is the precedent to follow.

### 7.1 ABI and consumer migration

Collapsing the public `vote_*` methods into `vote` is a **breaking ABI change**, which the
rollout must stage:

- **The ABI is snapshot-locked.** `crates/contract/tests/abi.rs:45` asserts the full generated
  ABI against `crates/contract/tests/snapshots/abi__abi_has_not_changed.snap` (every method
  name, its params, and JSON schema; schema version pinned `0.4.0` at `:38`), and the storage
  layout is locked by `crates/contract/src/lib.rs:82` against
  `crates/contract/src/snapshots/mpc_contract__tests__mpc_contract_borsh_schema_has_not_changed.snap`.
  Both snapshots must be regenerated as each family migrates.
- **In-repo consumers must move in lockstep:** the interface crate
  (`crates/near-mpc-contract-interface/src/`: `method_names.rs`, `call_args.rs`, the typed
  `client.rs`, `types/`), the devnet driver/CLI (`crates/devnet/src/mpc.rs`, `cli.rs`), and
  the sandbox suite (`crates/contract/tests/sandbox/`). The node's self-driven key-event votes
  (`crates/node/src/key_events.rs`) are out of scope (§6).
- **External callers need a deprecation window.** Governance tooling and the operator guides
  (`docs/development/`, `docs/guide/`) call the old method names directly; the dual-running
  step above covers them.

## 8. Cost model

Two facts drive the accounting:

- **Per-voter storage becomes a 32-byte hash for every flow.** `Votes<V>` stores the digest
  and a reverse-index entry, whatever the proposal size. The bespoke stores keep the **full
  payload once per voter** and count by scanning them.
- **Transaction count and argument bytes are unchanged.** Every current flow already sends
  the payload with each vote; the unified `vote` does the same, and there is no extra reveal
  transaction.

There is still no gas baseline for the `vote_*` methods (the only gas suite,
`crates/contract/tests/sandbox/participants_gas.rs` with `crates/contract/src/bench.rs`,
benchmarks the `Participants` struct), so establishing one remains a prerequisite to exact
numbers. The per-flow picture, with borsh payload sizes measured **per voter**:

| Flow | Payload | Stored per voter today | Unified | Verdict |
|---|---|---|---|---|
| `AddOsMeasurement` / `RemoveOsMeasurement` | `ExpectedMeasurements` | 1 B tag + **240 B** (5 × 48-B SHA-384 digests, `types/tee.rs:80`, `hash.rs:214`–`243`) | 32 B | **big saving** |
| `NewParameters` | `ProposedGovernanceThresholdParameters` | ~100 B × participants, plus per-domain thresholds | 32 B | **big saving**, scales with set |
| `AddDomains` | `Vec<DomainConfig>` | ~25 B × domains | 32 B | saving when many |
| `AddLauncherHash` / `RemoveLauncherHash` | `LauncherImageHash` | 1 B tag + 32 B | 32 B | wash |
| `NodeManifestDigest` | `NodeImageHash` | 32 B — already `Votes<V>` | 32 B | already optimal |
| `TeeVerifierChange` | account + code hash (~38–100 B) | 32 B — already `Votes<V>` | 32 B | already optimal |
| `ForeignChainProviders` | `ChainEntry` (URLs; variable, large) | 32 B — already `Votes<V>` | 32 B | already optimal |
| contract update | `UpdateHash` | 32 B — already `Votes<V>` | unchanged | already optimal |

- **Measurements is the standout** — 240 B per voter collapses to 32 B, saved again on every
  re-vote.
- **`NewParameters` / `AddDomains` scale** with participant and domain count, so their saving
  grows with the network.
- **Counting goes from O(voters) to O(1)**: the bespoke stores scan every voter's payload for
  equality (`tee/proposal.rs:58`, `measurements.rs:40`, `threshold_votes.rs:19`,
  `domain.rs:278`); `Votes<V>` returns the voter set for a hash in one lookup.

**What hash-only voting would add on top.** Deferring the payload to a separate reveal (§9(c))
does not change any row above: `Votes<V>` already stores only the hash. It would save the
argument bytes of the `n − 1` non-final votes — gas, not storage — and cost one extra base
transaction for the reveal, plus the machinery §9(c) lists. For these payload sizes that trade
is negative or negligible, which is why the contract update is the only flow where it applies.

## 9. Alternatives considered

- **(a) Status quo** — keep every bespoke struct. Zero migration cost, but the duplicated
  vote/count/replace/cleanup logic keeps growing with each new flow, cleanup rules stay
  inconsistent, and counting stays O(voters).
- **(b) Consolidate onto `Votes<V>`, reveal at vote, apply at threshold (recommended)** — the
  design of §3–§5. It is the shape three flows already have (§2.2), it inherits their atomicity
  so there is nothing to serialize, it needs no off-chain distribution beyond what voting
  already requires (a voter must know what they vote on), and it captures the full per-voter
  storage saving of §8.
- **(c) Commit-reveal with execution locks (the earlier draft)** — hash-only `vote(hash)` plus
  a separate `execute(proposal)`, with per-class execution locks, a lock TTL, and a voted
  override for stuck locks. Rejected. Separating the tally from the application creates a
  "decided but not applied" window that does not exist today, and every piece of the lock
  machinery exists only to police that window. What it bought was the argument bytes of the
  non-final votes; the storage picture is identical to (b) (§8). It also required voters to
  retain preimages off-chain, a liveness assumption that *someone* triggers `execute`, opaque
  tallies for observers, and a client-side canonical-encoding convention. The one flow where
  deferring the payload is justified by its size already runs that way on `main` and shows it
  needs no lock (§4.5).
- **(d) Fully off-chain aggregated voting** — a *different architecture*, not a tweak to (b):
  the tally itself moves off-chain and only a single aggregated (BLS) submission hits the chain.
  Because it is a distinct and more complex direction, it is written up separately in §10.

## 10. Alternative architecture: fully off-chain aggregated voting

The proposal above (§3) keeps **voting on-chain**: every participant submits a `vote`
transaction carrying the proposal. A more ambitious alternative moves the **tally itself
off-chain**, so an entire vote costs a *single* on-chain transaction. It is more complex and
depends on new cryptographic machinery, so it is recorded here as a separate direction rather
than folded into the main design.

### 10.1 Sketch

- Each participant signs the `ProposalHash` off-chain — there is no on-chain `vote` transaction.
- Once enough signatures are gathered, a **single** participant submits one transaction carrying
  the proposal plus the collected signatures.
- Ideally the signatures are combined into one constant-size **BLS aggregate signature** — all
  voters sign the *same* proposal hash, the ideal case for aggregation — accompanied by a signer
  bitmap.
- The contract reconstructs the aggregate public key from the participant set's registered BLS
  keys, runs a single pairing check, counts the bitmap (filtered to the electorate, §5.2)
  against the variant's threshold, validates the proposal (§4.3), and applies the effect.

### 10.2 Why it is attractive

- **One transaction per decision, fleet-wide.** Where the on-chain design puts `n` `vote`
  transactions on-chain, this puts down a single submission regardless of participant count —
  the largest possible gas saving.
- **Same atomicity as the main design.** Tally verification and application happen in one
  receipt, so it has the §4.1 property for free.

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

This is a *different architecture*, not a variant of §3: the main proposal keeps every vote
on-chain, whereas this moves the **votes** off-chain entirely. The `Proposal` enum, the
per-variant electorate/threshold/validate/apply hooks, and the family-clearing rule carry over
unchanged; only the tally mechanism differs. Open questions specific to this direction are
collected in §11.

## 11. Open questions

- **Partition granularity for CRUD.** Whether `Launcher` and `OsMeasurement` stay one family
  each (status quo: a win clears independent entries too, `tee_state.rs:416`) or are keyed per
  entity, as `ForeignChain(chain)` already is (`foreign_chain_rpc.rs:121`).
- **Electorate and phase gating per variant.** The current flows diverge: `vote_add_domains` is
  Running-only (`state.rs:145`), `vote_new_parameters` is Running/Resharing (`state.rs:128`),
  the TEE / launcher / measurement / verifier / foreign-chain / update votes are legal in any
  initialized state (`threshold_parameters_or_panic`, `state.rs:201`). The participant set is
  also phase-dependent (`state.rs:181`–`198`), and two different voter identity types are in
  use (`AuthenticatedParticipantId` vs `AuthenticatedAccountId`, both `IdentifiesParticipant`).
  `Proposal::electorate` must encode all of this; the exact table needs pinning down.
- **Caller authentication.** Flows differ between `assert_caller_is_signer`
  (`api/governance.rs:36`) and `voter_or_panic` (`api/tee_measurements.rs:26`,
  `api/authorization.rs:29`). The unified `vote` must pick one rule, or make it per variant.
- **`#2825` mechanics.** `Votes<V>` is backed by `IterableMap` and is neither `Clone` nor
  `PartialEq`, which is why the parameters tally still lives in `RunningContractState`
  (`threshold_votes.rs:8`). Moving it to the contract-level store is the first bespoke
  migration and shapes the others.
- **Contract-update tally in the enum.** Whether `vote(Proposal::ContractUpdate(UpdateHash))`
  should replace `vote_contract_update` (apply is a no-op; the family is cleared by `submit`,
  §4.5), or the update flow keeps its own two entry points.
- **Failed `migrate` after `submit_contract_update`.** `submit` dispatches a detached promise
  (`api/update.rs:75`); success is unknown when it returns. Pre-existing, unchanged by this
  document, but still unanswered: a confirmation callback that rolls back, or explicit
  acceptance of fire-and-forget.
- **Vote expiry.** Whether the optional TTL of §5.3 is wanted, and if so its length and prune
  trigger.
- **Gas baseline.** No gas suite covers the vote methods; one is needed before and after each
  family migrates to confirm §8.
- **Apply event.** Whether to emit a structured event on apply (§4.4) so indexers stop diffing
  whole-state snapshots.
- **Aggregated off-chain submission (§10).** Is the gas saving of a single aggregated
  submission worth introducing per-participant BLS keys and pairing-based verification? Which
  curve and host functions (`alt_bn128` vs BLS12-381 / NEP-488), and what is the on-chain
  verification gas cost relative to the `n` `vote` transactions it replaces? How are the BLS
  keys registered, rotated, and bound to participants (proof-of-possession), and how does the
  off-chain signature-collection role interact with the participant-set changes of §5.2?
