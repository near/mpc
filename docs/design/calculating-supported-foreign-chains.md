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

A chain `C` is supported by the network **iff at least a protocol-signing-threshold
number of active participants each support `C`**, where a node *supports* `C` iff
it has at least `quorum(C)` whitelisted RPC providers configured for `C`:

```
supported(C)  ⇔
    |{ node ∈ active_participants :
         | configured_providers(node, C) ∩ whitelist(C) |  ≥  quorum(C) }|
    ≥  protocol_signing_threshold
```

All inputs are read from current on-chain state:

| symbol | meaning | source |
|---|---|---|
| `whitelist(C)` | provider ids the network trusts for `C` | `AllowedProviders.entries[C].providers` |
| `quorum(C)` | per-chain RPC response quorum | `AllowedProviders.entries[C].quorum` |
| `protocol_signing_threshold` | signers required per request | `self.threshold()?.value()` |
| `configured_providers(node, C)` | provider ids the node registered for `C` | per-node registration (see below) |

This involves **two distinct quorums**, by design:

1. **Per-node provider quorum — `quorum(C)`.** A node can only reach its RPC
   response quorum at verification time if it has at least that many whitelisted
   providers configured. A node with fewer can never produce a verification for
   `C`, so it does not count as supporting `C`.
2. **Per-network node quorum — the protocol signing threshold.** A foreign-tx
   verification needs `threshold` independent signers, each verifying locally. If
   fewer than `threshold` nodes can verify `C`, no request on `C` can ever gather
   enough partial signatures, so advertising `C` would be dishonest. Requiring
   `threshold` nodes — rather than *all* `n` — is exactly what stops one operator
   from removing a chain.

### Per-node registration

To evaluate the rule the contract must know, per node and per chain, which
*whitelisted* providers that node has configured. Nodes therefore register a
per-chain set of `provider_id`s (the providers they resolved from local config
against the on-chain whitelist), rather than just a flat set of chains as today.

Registering provider *ids* — not a pre-computed "I support `C`" flag — means the
supported set re-derives automatically when the whitelist or `quorum(C)` changes
(e.g. a provider is voted out): no node has to re-register for the network's view
to stay correct.

A node that registers a provider id not present in `whitelist(C)` simply doesn't
have it counted toward `quorum(C)`; registration is a liveness hint, never a
trust anchor.

## Why this is safe

- **It is a liveness floor, not a trust change.** `≥ threshold` supporting nodes
  guarantees at least one viable signing committee exists for `C`. Trust still
  comes entirely from the per-node RPC response quorum and the chain-identity
  probe at verification time; a node that over-claims support just fails to
  verify and abstains.
- **A chain with no whitelist entry is never supported** (`whitelist(C)` empty),
  which is correct: a chain with no network-trusted providers must not be
  advertised.
- **Single-operator DoS is gone.** One node registering nothing (or being slow
  to register) can at most reduce the supporting-node count by one; as long as
  `threshold` other nodes support `C`, `C` stays up.

## Known tradeoff

If exactly `threshold` nodes support `C`, runtime flakiness of any one of them
still causes individual requests to time out — `threshold` is the minimum for the
chain to be *advertisable*, not a comfortable availability margin. Operators who
want headroom run more nodes with `≥ quorum(C)` providers; the rule does not cap
how many nodes may support a chain. We deliberately do not introduce a separate,
larger "support quorum" knob — the signing threshold is the precise liveness
requirement, and a higher bar would reintroduce the easier-to-DoS behavior we are
removing.

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
  RPC providers configured" — change to the threshold-of-nodes rule above.
