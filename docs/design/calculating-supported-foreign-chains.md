# Calculating the whitelisted and available foreign-chain sets

Status: Proposed — supersedes the all-participant intersection rule in
[`docs/foreign-chain-transactions.md`](../foreign-chain-transactions.md). Tracked by
[#3434](https://github.com/near/mpc/issues/3434).

## Background

Today, `get_supported_foreign_chains()` returns the **strict intersection** of every
active participant's registered chains, and `verify_foreign_transaction` rejects any
request whose target chain is not in it. A single node that registers an empty list
(or hasn't registered yet) drops **every** chain — one operator can take the whole
feature down. That is what this proposal fixes.

It builds on the per-chain RPC whitelist (`ForeignChainRpcWhitelist`), which holds,
per chain, the network-trusted providers and the **RPC quorum** (`ChainEntry.quorum`
— how many of a node's providers must agree for it to accept a result).

## Proposal: two sets of chains

> **Terms** (whitelisted, available, RPC quorum, signing threshold, *covers*) are defined in
> [Foreign Chain Transaction Verification Design — Terminology](../foreign-chain-transactions.md#terminology).

The network distinguishes the **whitelisted** set (vote-driven policy, `get_whitelisted_foreign_chains()`)
from the **available** set (servable right now, `get_available_foreign_chains()`):

- **Whitelisted** is derived purely from the on-chain RPC whitelist — **no per-node input can add or
  remove a chain**, so no single operator can change it.
- **Available** is computed dynamically from the per-node config reports: `C` is available iff
  ≥ `signing_threshold` active participants cover `C`. `available ⊆ whitelisted` always.

`verify_foreign_transaction(C)` is **rejected unless `C` is available**: the contract fails fast
instead of accepting a request that can't reach the signing threshold and letting it time out. The
rejection is temporary — `C` becomes serviceable again as soon as enough nodes report coverage.

The legacy `get_supported_foreign_chains()` (the intersection rule) is **to be deprecated** in favour
of the two views above.

## Why two sets

**Whitelisted** is a stable, operator-visible commitment: it changes only by vote,
never flaps with node churn, and no single operator can change it. Every node is
expected to cover every whitelisted chain.

**Available** avoids spending resources on a request the network can't fulfill: one
for a chain without a signing threshold's worth of coverage is rejected up front, not
attempted and left to time out. Because it requires `signing_threshold` — not all —
participants, a chain leaves it only when more than `n − signing_threshold` nodes
stop covering it.

In a healthy network `available == whitelisted`. A gap means nodes are down or
misconfigured for a chain — an operational anomaly that alerting surfaces (see
[Per-node registration](#per-node-registration)), not a steady state.

## Verification behavior

Each node fans the query out to its whitelisted providers for `C` and accepts a
result only when ≥ `rpc_quorum(C)` return the same response. If fewer agree, the node
errors out and produces no signature share.

**This sub-quorum outcome must be terminal — the leader must not re-attempt the
request.** Implementation requirement, not current behavior: the generic queue
retries every request up to `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`
(`requests/queue.rs:38`), so the foreign-tx path must special-case a sub-quorum
result as non-retryable. (Open: whether a sub-quorum from purely *transient*
failures — timeouts, finality not reached — should still retry, vs. only genuine
disagreement being terminal.)

## Participant election

Foreign-tx signing must elect participants that **cover** the requested chain
(report ≥ `rpc_quorum(C)` providers for `C`), not merely online ones — a
non-covering participant produces no share and can stall the request.
Implementation requirement, not current behavior: today the signing set is inherited
from a presignature (`take_owned()` in `verify_foreign_tx/sign.rs`), whose
participants were chosen for liveness, not chain coverage.

## Per-node registration

Per-node registration (`register_available_foreign_chain_config` /
`get_available_foreign_chain_by_node`) reports which chains each node currently covers,
and serves two roles:

- it **feeds the available set** — the contract counts, per chain, how many active
  participants report coverage and compares against `signing_threshold`; and
- it **drives alerting** — when an active node does not cover a whitelisted chain,
  monitoring fires for *us* (maintainers), who nudge the operator. Ideally operators
  run their own coverage alert and fix the gap first.

Registration reflects each node's *current* config.

Because this data now feeds the *available* set, the methods are renamed to reflect that:
`register_foreign_chain_config` → `register_available_foreign_chain_config` and
`get_foreign_chain_support_by_node` → `get_available_foreign_chain_by_node`. The old names are kept as thin
wrappers delegating to the new ones, then deprecated and removed once node and contract have both
migrated — the same independent node/contract rollout used for the view methods, so the rename needs
no flag-day coordination.

## Guarantees preserved

**Safety** — the network signs an observation only if ≥ `signing_threshold`
participants each independently verified it (each via its own RPC quorum). Fewer than
`signing_threshold` cannot force a false attestation.

**Liveness** — a request is accepted only when `C` is available (≥ `signing_threshold`
participants cover it), so an accepted request can reach the signing threshold; and a
chain leaves the available set only when more than `n − signing_threshold` nodes drop
it. This strictly improves on the intersection rule, where one non-registering node
dropped a chain to zero availability.

## Known tradeoff

When a chain is available but not *every* node covers it, the non-covering nodes are
treated as down for `C`: they don't participate, and the pre-generated assets they
co-own (usable only while all their participants are alive) become offline assets. As
long as the leader knows a node is down there is no waste, only an asset that stays
offline for a long period is eventually discarded, wasting the work that produced it.
Two surfaces where that lands:

- **Presignatures are per-domain.** Foreign-tx signing uses a dedicated `ForeignTx`
  domain (`DomainPurpose::ForeignTx`), so stranded foreign-tx presignatures stay in
  that pool.
- **Triples are shared** across all CaitSith domains with the same signing threshold,
  so stranding them also dents ordinary `sign()` presignature generation — this cost
  is **not** confined to `C`.

The mitigation is operational: the alerting above keeps coverage high, and operators
are expected to configure every node for every chain.

## Migration

`get_supported_foreign_chains()` stays working throughout, so the new node version
can roll out before the contract upgrade (node and contract migrate independently):

1. Keep `get_supported_foreign_chains()` unchanged.
2. Add `get_whitelisted_foreign_chains()` and `get_available_foreign_chains()` (additive).
3. Vote the RPC providers / chains into the whitelist.
4. Upgrade the contract.
5. Switch node code to the new methods and deprecate `get_supported_foreign_chains()`.

## Documentation impact

Adopting this rule makes the following stale. Update in the same change (per the
doc-alignment rule):

- `docs/foreign-chain-transactions.md` — "Contract State (Foreign Chain
  Configurations)", the `get_supported_foreign_chains` description (now superseded by
  `get_whitelisted_foreign_chains` / `get_available_foreign_chains`), the operator-flow
  note about a chain appearing "only once **every** active participant has registered
  it", and the rollout-coordination risk all describe the intersection rule.
- `docs/design/allowing-per-node-foreign-chain-rpc-configuration.md` requirement #5
  — restate it as the whitelisted/available split above (registration feeds the
  available set; it is not monitoring-only).
