# Calculating the supported foreign-chain set

Status: Proposed — supersedes the all-participant intersection rule described in
[`docs/foreign-chain-transactions.md`](../foreign-chain-transactions.md). Tracked by
[#3434](https://github.com/near/mpc/issues/3434).

## Background

For foreign-chain transaction verification, the contract exposes
`get_supported_foreign_chains()` — the set of chains the network advertises as
verifiable. A `verify_foreign_transaction` request is rejected on-chain unless
its target chain is in this set.

Today that set is the **strict intersection** across every active participant: a
chain is kept only if the set of nodes that registered it is a superset of *all*
active participants. A single node that registers an empty list — or simply
hasn't registered yet — removes **every** chain from the supported set. One
operator can therefore take the whole feature down. That is the problem this
proposal fixes.

We now also have the per-chain RPC whitelist (`ForeignChainRpcWhitelist`), which
carries, for each chain, the network-trusted provider list and the **RPC
response quorum** `ChainEntry.quorum` (the number of a node's providers that must
agree for that node to accept a verification result). The new rule builds on it.

## Proposal

The supported set is derived from the **on-chain RPC whitelist**, not from
per-node registration:

```
supported(C)  ⇔  AllowedProviders.entries contains an entry for C
                 (non-empty provider list + its RPC response quorum)
```

`get_supported_foreign_chains()` therefore returns `AllowedProviders.entries`'
keys. The set is vote-gated whitelist state: a chain becomes supported when the
network votes in a `ChainEntry` for it (see the whitelist vote semantics in
[`docs/foreign-chain-transactions.md`](../foreign-chain-transactions.md#on-chain-rpc-provider-whitelist)),
and no per-node input can subtract a chain from it.

**Every active node is required to support every supported chain.** A node
*supports* `C` iff it has at least `quorum(C)` whitelisted RPC providers
configured for `C` (the minimum it needs to ever reach its RPC response quorum at
verification time). Requiring all nodes to support all chains is the option that
deviates least from today's liveness and security guarantees — under the old
intersection rule, every node already had to register a chain for it to count —
while removing the single-operator DoS.

A node that does **not** support a supported chain is treated **identically to a
node that is down** for that chain: it abstains from `C`'s verification requests,
and the request proceeds with the remaining signers (subject to the usual signing
threshold). The accepted cost is wasted assets — and the waste is **not confined
to chain `C`**. Pre-generated triples and presignatures are usable only while
every participant associated with them is alive, so the ones co-owned with a node
treated as offline get stranded and discarded as offline assets, exactly as a
genuinely down node strands the assets generated with it. These are **shared
signing assets**, not foreign-chain-specific: triples are domain-agnostic, and
foreign-tx signing reuses the same ECDSA presignature pool as ordinary `sign()`
(see `crates/node/src/providers/verify_foreign_tx.rs`). So the cost falls on the
network's overall signing capacity across all domains, not just on `C`'s
availability. We consider this acceptable in exchange for the simplicity and the
DoS resistance.

| symbol | meaning | source |
|---|---|---|
| `whitelist(C)` | provider ids the network trusts for `C` | `AllowedProviders.entries[C].providers` |
| `quorum(C)` | per-chain RPC response quorum | `AllowedProviders.entries[C].quorum` |

## Verification behavior

When a foreign-tx verification request is processed, each node fans out the query
to its locally-configured whitelisted providers for `C`. If fewer than `quorum(C)`
of them return the same response, the node **errors out the foreign-tx validation
and does not retry** that request — it abstains for that request rather than
re-querying or falling back. This keeps the trust property crisp: a result is only
accepted when an RPC response quorum genuinely agreed, and a node that can't reach
that bar contributes nothing rather than a weaker observation.

## Monitoring and alerting

Because a node that doesn't support a supported chain is silently treated as down,
we need to detect that state so it doesn't quietly become the norm (which would
erode the real availability margin for that chain). Per-node registration —
`register_foreign_chain_config` / `get_foreign_chain_support_by_node` — is
**retained solely as the signal for this**: it no longer feeds the supported-set
computation, but it lets monitoring compare each active node's registered chains
against the supported set and **alert when any active node does not support a
supported chain**. This alert fires for *us* (the network maintainers) off the
on-chain registrations; we then nudge the affected operator to fix that node's
configuration. Ideally each operator also runs their own alert that checks their
node covers every supported chain, so they catch and fix the gap before we have
to chase them.

## Why this is safe

- **Single-operator DoS is gone.** The supported set is vote-gated whitelist
  state, not per-node input. One node registering nothing — or being slow to
  register — cannot remove a chain; at worst it is treated as down for that chain,
  exactly like any offline node, and the alert fires.
- **A chain with no whitelist entry is never supported**, which is correct: a
  chain with no network-trusted providers must not be advertised.
- **Trust is unchanged.** It still comes entirely from the per-node RPC response
  quorum and the chain-identity probe at verification time; a node that lacks
  enough providers simply abstains. Requiring all nodes to support all chains does
  not weaken any per-request trust property — it only sets the availability
  expectation.

## Known tradeoff

A node that doesn't support a supported chain strands the pre-generated
triples/presignatures it co-owns — they become offline assets and are discarded
unused. Because these are shared assets (domain-agnostic triples; an ECDSA
presignature pool reused for ordinary `sign()`), the cost is borne by overall
signing throughput across domains, not just by chain `C`'s availability margin. The mitigation is operational rather than
protocol-level: the alerting above keeps coverage high, and operators are expected
to configure every node for every supported chain. We deliberately do **not** make
the supported set adapt to which nodes happen to support a chain — that is exactly
the per-node-input coupling whose removal kills the single-operator DoS.

## Documentation impact

Adopting this rule makes the following existing text stale; it must be updated in
the same change (per the repo's doc-alignment rule):

- `docs/foreign-chain-transactions.md` — the "Contract State (Foreign Chain
  Configurations)" section, the `get_supported_foreign_chains` description, the
  operator-flow note that a chain appears "only once **every** active participant
  has registered it", and the rollout-coordination risk all describe the
  intersection rule.
- `docs/design/allowing-per-node-foreign-chain-rpc-configuration.md` requirement
  #5 currently states "**every** node has at least a quorum number of whitelisted
  RPC providers configured" — change to the whitelist-driven rule above.
