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

## Proposal

The supported set is derived from the **on-chain RPC whitelist**, not per-node
registration:

```
supported(C)  ⇔  AllowedProviders.entries contains an entry for C
                 (non-empty provider list + its RPC response quorum)
```

So `get_supported_foreign_chains()` returns `AllowedProviders.entries`' keys — a
chain is supported once the network votes in a `ChainEntry` for it (see
[whitelist vote semantics](../foreign-chain-transactions.md#on-chain-rpc-provider-whitelist)),
and no per-node input can subtract a chain.

**Every active node is required to support every supported chain** — a node
*supports* `C` iff it has ≥ `quorum(C)` whitelisted providers configured for `C`.
A node lacking them behaves exactly like an offline node, a fault the threshold
protocol already tolerates, so universal support is an operational expectation,
not a new correctness/liveness requirement (see
[Guarantees preserved](#guarantees-preserved)). Such a node is treated
**identically to one that is down** for `C`: it does not participate, and the request proceeds
with the remaining signers. The cost is stranded pre-generated assets — see
[Known tradeoff](#known-tradeoff).

| symbol | meaning | source |
|---|---|---|
| `whitelist(C)` | provider ids the network trusts for `C` | `AllowedProviders.entries[C].providers` |
| `quorum(C)` | per-chain RPC response quorum | `AllowedProviders.entries[C].quorum` |

## Verification behavior

Each node fans the query out to its whitelisted providers for `C` and accepts a
result only when ≥ `quorum(C)` return the same response. If fewer agree, the node
errors out and produces no partial signature.

**This sub-quorum outcome must be terminal — the leader must not re-attempt the
request.** Implementation requirement, not current behavior: the generic queue
retries every request up to `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`
(`requests/queue.rs:38`), so the foreign-tx path must special-case a sub-quorum
result as non-retryable. (Open: whether a sub-quorum from purely *transient*
failures — timeouts, finality not reached — should still retry, vs. only genuine
disagreement being terminal.)

## Monitoring and alerting

A node silently treated as down erodes a chain's availability margin, so we must
detect it. Per-node registration (`register_foreign_chain_config` /
`get_foreign_chain_support_by_node`) is **retained solely for this** — it no longer
feeds the supported set, but lets monitoring **alert when an active node does not
support a supported chain**. That alert fires for *us* (maintainers), who then
nudge the operator. Ideally operators also run their own coverage alert and fix
the gap first.

## Guarantees preserved

Two guarantees hold today, and this rule keeps both.

**Security** — the network signs an observation only if ≥ `threshold` participants
each independently verified it (each via its own RPC quorum). Fewer than
`threshold` can never force a false attestation. This holds because the
supported-set source never touches the per-request verification path: a node
treated as down — genuinely offline or just under-provisioned — does not
participate, so it can never push a partial signature toward a false result.
Over-claiming support doesn't help an attacker either, as the node just fails its
RPC quorum and does not participate.

**Liveness** — a request completes as long as ≥ `threshold` supporting participants
are online, the same `n − threshold` fault tolerance as the rest of signing. A
non-supporting node is exactly an offline node to the protocol, a fault already
absorbed. This strictly improves on the intersection rule, where one
non-registering node dropped a chain to zero availability (a one-fault DoS, worse
than `n − threshold`).

Also: **a chain with no whitelist entry is never supported** — correct, since a
chain with no trusted providers must not be advertised.

## Known tradeoff

A node treated as down strands the pre-generated assets it co-owns (usable only
while all their participants are alive), which are then discarded. Two surfaces:

- **Presignatures are per-domain.** Foreign-tx signing uses a dedicated
  `ForeignTx` domain (`DomainPurpose::ForeignTx`), so stranded foreign-tx
  presignatures stay in that pool.
- **Triples are shared** per reconstruction threshold across all CaitSith
  domains, so stranding them also dents ordinary `sign()` presignature
  generation — this cost is **not** confined to `C`.

The mitigation is operational: the alerting above keeps coverage high, and
operators are expected to configure every node for every chain. We deliberately do
**not** make the supported set adapt to which nodes support a chain — that
per-node-input coupling is exactly what enables the single-operator DoS we remove.

## Documentation impact

Adopting this rule makes the following stale. Update in the same change (per the
doc-alignment rule):

- `docs/foreign-chain-transactions.md` — "Contract State (Foreign Chain
  Configurations)", the `get_supported_foreign_chains` description, the operator-flow
  note about a chain appearing "only once **every** active participant has registered
  it", and the rollout-coordination risk all describe the intersection rule.
- `docs/design/allowing-per-node-foreign-chain-rpc-configuration.md` requirement #5
  ("**every** node has at least a quorum number of whitelisted RPC providers
  configured") — change to the whitelist-driven rule above.
