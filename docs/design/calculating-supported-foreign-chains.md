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
participants, the network tolerates up to `n − signing_threshold` nodes
stopping coverage.

In a healthy network `available == whitelisted`. If there exists a chain that's 
whitelisted but not available means nodes are down or
misconfigured for a chain — an operational anomaly that alerting surfaces (see
[Per-node registration](#per-node-registration)), not a steady state.

## Verification behavior

Each node fans the query out to its whitelisted providers for `C` and accepts a
result only when ≥ `rpc_quorum(C)` return the same response. If fewer agree, the node
errors out and produces no signature share.

**This sub-quorum outcome must be terminal — the leader must not re-attempt the
request.** Implementation requirement, not current behavior: the generic queue
retries every request, so the foreign-tx path must special-case a sub-quorum
result as non-retryable. (Open: whether a sub-quorum from purely *transient*
failures — timeouts, finality not reached — should still retry, vs. only genuine
disagreement being terminal. Tracked in [#3477](https://github.com/near/mpc/issues/3477).)

## Participant election

Foreign-tx signing must elect participants that **cover** the requested chain
(report ≥ `rpc_quorum(C)` providers for `C`), not merely online ones — a
non-covering participant produces no share and can stall the request.
Implementation requirement, not current behavior: today the signing set is inherited
from a presignature, whose
participants were chosen for liveness, not chain coverage.

## Per-node registration

Per-node registration (`register_available_foreign_chain_config` /
`get_available_foreign_chain_by_node`) reports which chains each node currently covers,
and serves two roles:

- it **feeds the available set** — the contract counts, per chain, how many active
  participants report coverage and compares against `signing_threshold`; and
- it **will drive alerting** (planned, not yet implemented — tracked in
  [#3476](https://github.com/near/mpc/issues/3476)) — when an active node does not cover a
  whitelisted chain, monitoring should fire for *us* (maintainers), who nudge the operator. Ideally
  operators run their own coverage alert and fix the gap first.

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

A node that's up but not covering a chain only sidelines the `ForeignTx` **presignatures** it co-owns
(discarded if they stay offline long enough). Its **triples are not lost** — they're shared across
domains and stay in use, so triples go offline only if the node is genuinely down. Mitigation is
operational: alerting keeps coverage high and operators are expected to configure every node for
every chain.

## Migration

`get_supported_foreign_chains()` stays working throughout, so the new node version
can roll out before the contract upgrade (node and contract migrate independently):

1. Keep `get_supported_foreign_chains()` unchanged.
2. Add `get_whitelisted_foreign_chains()` and `get_available_foreign_chains()` (additive).
3. Vote the RPC providers / chains into the whitelist.
4. Upgrade the contract.
5. Switch node code to the new methods and deprecate `get_supported_foreign_chains()`.
