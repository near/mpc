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
per chain, the network-trusted providers and the voted **RPC quorum** (`ChainEntry.quorum`,
stored for a deferred quorum policy and not yet consumed: verification compares every
configured provider, see [Verification behavior](#verification-behavior)).

## Proposal: two sets of chains

> **Terms** (whitelisted, available, RPC quorum, signing threshold, *covers*) are defined in
> [Foreign Chain Transaction Verification Design — Terminology](../foreign-chain-transactions.md#terminology).

The network distinguishes the **whitelisted** set (vote-driven policy, `allowed_foreign_chain_providers()`)
from the **available** set (servable right now, `get_available_foreign_chains()`):

- **Whitelisted** is derived purely from the on-chain RPC whitelist — **no per-node input can add or
  remove a chain**, so no single operator can change it.
- **Available** is computed dynamically from the per-node config reports: `C` is available iff
  ≥ `signing_threshold` active participants cover `C`. `available ⊆ whitelisted` always.

`verify_foreign_transaction(C)` is **rejected unless `C` is available**: the contract fails fast
instead of accepting a request that can't reach the signing threshold and letting it time out. The
rejection is temporary — `C` becomes serviceable again as soon as enough nodes report coverage.

The legacy `get_supported_foreign_chains()` (the intersection rule) is **deprecated** in favour
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
result only when every provider that reached a verdict reached the same one; providers
that fail to answer are tolerated. On any disagreement the node errors out and produces
no signature share.

**A disagreement outcome must be terminal — the leader must not re-attempt the
request.** Implementation requirement, not current behavior: the generic queue
retries every request, so the foreign-tx path must special-case a disagreement
as non-retryable. The fan out already distinguishes the two outcomes in its
return value: when no provider reaches a verdict it propagates the underlying
error, and only genuine disagreement between verdicts reports a mismatch.
Whether the no-verdict outcome should retry while disagreement stays terminal
is tracked in [#3477](https://github.com/near/mpc/issues/3477).

## Participant selection

Foreign-tx signing must select participants that **cover** the requested chain
(their registration lists `C`), not merely online ones — a
non-covering participant produces no share and can stall the request.

Implemented in two places:
1. Leader selection is chain- and threshold-aware: the
pending-request queue narrows a request's eligible leaders to the supporters
of `C`, and selects one only when at least a reconstruction threshold's worth
of them is online (the same threshold that gates availability). Otherwise the request
parks — no attempt is consumed, the `mpc_num_requests_without_refined_leader_total` metric counts the queue
passes — until supporters come back or the request expires.
2. On the
presignature-selection side, the leader only takes a presignature whose
participants are all alive **and** supporters of `C`, and as defense-in-depth
refuses to lead a request for a chain it does not itself support (every owned
presignature includes the leader).

Residual limitation, accepted as-is: presignature generation remains
liveness-driven, so participant sets are random `t`-subsets of the alive set.
When not all alive participants support `C`, many presignatures are
incompatible, and a request may wait until a compatible one is generated or
the request times out. We do not plan chain-aware generation, the
`mpc_num_verify_foreign_tx_presignature_waits` metric (plus a warning log)
makes such waits observable. A broader redesign of asset selection and the
underlying queue — which could subsume this limitation — is tracked in
[#377](https://github.com/near/mpc/issues/377).

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
participants each independently verified it, each against its own configured providers
(see [Verification behavior](#verification-behavior)). Fewer than
`signing_threshold` cannot force a false attestation.

**Liveness** — a request is accepted only when `C` is available (≥ `signing_threshold`
participants cover it), so an accepted request can reach the signing threshold; and a
chain leaves the available set only when more than `n − signing_threshold` nodes drop
it. This strictly improves on the intersection rule, where one non-registering node
dropped a chain to zero availability.

## Known limitations

A node that's up but not covering a chain `C` shrinks the eligible presignature
pool for `C`: presignatures it co-owns are excluded from selection for `C`'s
requests (they stay usable for chains the node does cover), and the smaller
the supporter set, the fewer generated presignatures qualify (see
[Participant selection](#participant-selection)). Its **triples are
not lost** — they're shared across domains and stay in use, so triples go
offline only if the node is genuinely down. Mitigation is operational:
alerting keeps coverage high and operators are expected to configure every
node for every chain.

## Migration

`get_supported_foreign_chains()` stays working throughout, so the new node version
can roll out before the contract upgrade (node and contract migrate independently):

1. Keep `get_supported_foreign_chains()` unchanged.
2. Add `allowed_foreign_chain_providers()` and `get_available_foreign_chains()` (additive).
3. Vote the RPC providers / chains into the whitelist. This must precede step 4 on every
   network: `available ⊆ whitelisted`, so with an empty whitelist the new gate rejects every
   request.
4. Upgrade the contract: `verify_foreign_transaction` gates on the available set instead of
   the supported set, and `get_supported_foreign_chains()` is deprecated.
5. Switch node code to the new methods and drop the legacy registration.
