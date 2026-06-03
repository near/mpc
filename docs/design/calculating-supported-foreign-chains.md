# Calculating the supported foreign-chain set

Status: Proposed — supersedes the all-participant intersection rule in
[`docs/foreign-chain-transactions.md`](../foreign-chain-transactions.md). Tracked by
[#3434](https://github.com/near/mpc/issues/3434).

## Background

`get_supported_foreign_chains()` is the set of chains the network advertises as
verifiable. `verify_foreign_transaction` rejects any request whose target chain is
not in it.

Today that set is the **strict intersection** across all active participants, so a
single node that registers an empty list (or hasn't registered yet) drops **every**
chain — one operator can take the whole feature down. That is what this proposal
fixes. It builds on the per-chain RPC whitelist (`ForeignChainRpcWhitelist`), which
holds, per chain, the network-trusted providers and the **RPC response quorum**
`ChainEntry.quorum` (how many of a node's providers must agree for it to accept a
result).

## Proposal: two sets of chains

The network distinguishes two sets:

- **Supported** — the explicit, whitelist-driven policy set every node is expected
  to serve. `C` is supported iff the on-chain RPC whitelist has a `ChainEntry` for
  `C`. `get_supported_foreign_chains()` returns exactly these keys. **No per-node
  input can add or remove a chain**, so no single operator can drop one.
- **Available** — the set the network can actually serve right now, computed
  dynamically from the per-node config reports. `C` is available iff ≥ `threshold`
  active participants report support for `C`, where `threshold` is the
  reconstruction threshold of the `ForeignTx` domain and a participant *supports*
  `C` iff it has ≥ `quorum(C)` whitelisted providers configured for `C`.

`available ⊆ supported` always — a node can only support a whitelisted chain.

`verify_foreign_transaction(C)` is **rejected unless `C` is available**: the
contract fails fast instead of accepting a request that can't reach a signing
quorum and letting it time out. The rejection is temporary — `C` becomes
serviceable again as soon as enough nodes report support.

| symbol | meaning | source |
|---|---|---|
| `whitelist(C)` | provider ids the network trusts for `C` | `AllowedProviders.entries[C].providers` |
| `quorum(C)` | per-chain RPC response quorum | `AllowedProviders.entries[C].quorum` |

## Why two sets

**Supported** is a stable, operator-visible commitment: it changes only by vote,
never flaps with node churn, and no single operator can shrink it. Every node is
expected to cover every supported chain.

**Available** avoids spending resources on a request the network can't fulfill: one
for a chain without a signing threshold's worth of support is rejected up front, not
attempted and left to time out. Because it requires `threshold` — not all —
participants, a chain leaves it only when more than `n − threshold` nodes stop
supporting it.

In a healthy network `available == supported`. A gap means nodes are down or
misconfigured for a chain — an operational anomaly that alerting surfaces (see
[Per-node registration](#per-node-registration)), not a steady state.

## Verification behavior

Each node fans the query out to its whitelisted providers for `C` and accepts a
result only when ≥ `quorum(C)` return the same response. If fewer agree, the node
errors out and produces no signature share.

**This sub-quorum outcome must be terminal — the leader must not re-attempt the
request.** Implementation requirement, not current behavior: the generic queue
retries every request up to `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`
(`requests/queue.rs:38`), so the foreign-tx path must special-case a sub-quorum
result as non-retryable. (Open: whether a sub-quorum from purely *transient*
failures — timeouts, finality not reached — should still retry, vs. only genuine
disagreement being terminal.)

## Per-node registration

Per-node registration (`register_foreign_chain_config` /
`get_foreign_chain_support_by_node`) reports which chains each node currently
supports, and serves two roles:

- it **feeds the available set** — the contract counts, per chain, how many active
  participants report support and compares against `threshold`; and
- it **drives alerting** — when an active node does not cover a supported chain,
  monitoring fires for *us* (maintainers), who nudge the operator. Ideally operators
  run their own coverage alert and fix the gap first.

Registration reflects each node's *current* config.

## Guarantees preserved

**Safety** — the network signs an observation only if ≥ `threshold` participants
each independently verified it (each via its own RPC quorum). Fewer than `threshold`
cannot force a false attestation.

**Liveness** — a request is accepted only when `C` is available (≥ `threshold`
participants support it), so an accepted request can reach a signing quorum; and a
chain leaves the available set only when more than `n − threshold` nodes drop it.
This strictly improves on the intersection rule, where one non-registering node
dropped a chain to zero availability.

## Known tradeoff

When a chain is available but not *every* node supports it, the non-supporting nodes
are treated as down for `C`: they don't participate, and the pre-generated assets
they co-own (usable only while all their participants are alive) become offline
assets. As long as the leader knows a node is down there is no waste, only an asset
that stays offline for a long period is eventually discarded, wasting the work that
produced it. Two surfaces where that lands:

- **Presignatures are per-domain.** Foreign-tx signing uses a dedicated `ForeignTx`
  domain (`DomainPurpose::ForeignTx`), so stranded foreign-tx presignatures stay in
  that pool.
- **Triples are shared** per reconstruction threshold across all CaitSith domains,
  so stranding them also dents ordinary `sign()` presignature generation — this cost
  is **not** confined to `C`.

The mitigation is operational: the alerting above keeps coverage high, and operators
are expected to configure every node for every chain.

## Documentation impact

Adopting this rule makes the following stale. Update in the same change (per the
doc-alignment rule):

- `docs/foreign-chain-transactions.md` — "Contract State (Foreign Chain
  Configurations)", the `get_supported_foreign_chains` description, the operator-flow
  note about a chain appearing "only once **every** active participant has registered
  it", and the rollout-coordination risk all describe the intersection rule.
- `docs/design/allowing-per-node-foreign-chain-rpc-configuration.md` requirement #5
  — restate it as the supported/available split above (registration feeds the
  available set; it is not monitoring-only).
