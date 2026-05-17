# Configuration of foreign chain RPC providers without full consensus

> **Canonical design:** see [`docs/foreign-chain-transactions.md` — "On-chain RPC Provider Whitelist"](../foreign-chain-transactions.md#on-chain-rpc-provider-whitelist) for the full end-to-end shape, type definitions, vote semantics, and rationale. This doc captures the *motivation* and the high-level shape; the linked section is the source of truth for the implementation.

## Background
For the foreign chain transaction validation feature supported by the MPC network, individual MPC nodes each query a set
of configured RPC providers to verify the state of a foreign transaction. Each MPC node that partakes in a signing operation
for verification of a foreign chain transaction will get an RPC provider randomly assigned with consistent hashing. That means
each MPC node only queries 1 RPC provider per verification request.

Currently, an RPC provider is only accepted if and only if all MPC nodes have their local configuration set up to use that RPC
provider on a per-chain basis. For example, if an MPC node wants to use Quiknode as an RPC provider for Solana, then all other
MPC nodes must also add Quiknode to their Solana configuration.

## What
As part of [#2648](https://github.com/near/mpc/issues/2648), we want to be able to configure nodes with RPC providers without
requiring all other nodes to have the exact same configuration.

### Requirements
1. RPC providers are whitelisted by being voted into the contract by node operators submitting votes. The whitelist is **per-chain**, keyed by `(ForeignChain, ProviderId)`.
2. The contract owns the connection config (`base_url`, `auth_scheme`, `chain_routing`), not the operator. Operator yaml carries `provider_id` + a `token_env` reference only.
3. Nodes do not need to have local configurations covering all whitelisted RPC providers — a quorum number of locally-configured providers per chain is sufficient.
4. Every node partaking in a foreign signature verification request queries all its locally configured RPC providers for the relevant chain, independently of other nodes. A quorum of those RPC providers must agree on the verification.
5. A foreign chain is considered supported by the MPC network iff every node has at least a quorum number of whitelisted RPC providers configured for that chain. The quorum threshold is per-chain.

## Why
The current setup has many limitations and was implemented as an MVP.

### Availability
Currently, if a single RPC provider is unresponsive, then a foreign chain validation will fail because the nodes that are mapped to that RPC provider will fail.
### Security
By requiring every node to have a valid quorum of RPC providers for a verification, each node does not need to trust the other nodes' RPC configurations. Putting the connection config (`base_url`, `auth_scheme`, `chain_routing`) on chain also closes the gap where a TEE-attested binary trusts its operator's local config — the operator can no longer point the node at an arbitrary URL, only at one the network has voted to trust for that chain.
### Flexibility
We want to allow nodes to use newly whitelisted RPC providers without forcing all other node operators to also configure RPC accounts for that provider.

## How

The high-level shape is sketched below; see the canonical doc for the full type definitions, validation rules, vote semantics, and design rationale.

### Whitelisting policy for RPC providers on chain

The MPC contract has functionality to vote on a wide set of proposals where node operators cast votes manually — for example allowed node binary hashes, contract configuration, contract binary upgrade, node participant set, etc. We extend the contract to track a per-chain whitelist of RPC providers, voted in by the same mechanism.

```rust
struct MpcContractState {
    // ...
    foreign_chain_rpc_whitelist: ForeignChainRpcWhitelist,
}

struct ForeignChainRpcWhitelist {
    entries: AllowedProviders,
    votes: ProviderVotes,
}

struct AllowedProviders {
    // Each chain stores its full whitelist + the RPC response quorum nodes should
    // use when fanning out queries to those providers.
    entries: BTreeMap<ForeignChain, ChainEntry>,
}

struct ChainEntry {
    providers: Vec<ProviderEntry>,
    // RPC response quorum: when a node fans out a query to the N providers above,
    // at least this many must return the same value for the response to be accepted.
    threshold: u64,
}

struct ProviderVotes {
    // Pending per-chain proposals, keyed by `(participant, chain)`. The slot holds the
    // exact `ChainEntry` the participant is proposing for that chain. The chain's state
    // is replaced wholesale once the protocol's signing threshold of participants holds
    // the same canonical `(providers, threshold)` pair.
    pending: BTreeMap<(AuthenticatedParticipantId, ForeignChain), ChainEntry>,
}

struct ProviderEntry {
    provider_id: ProviderId, // newtype around String — typed boundary so a base_url
                             // can't be passed where a provider_id is expected.
    // Provider's stable base. When `chain_routing == Embedded`, the chain identifier is
    // already encoded in `base_url` (subdomain or path prefix). Otherwise `base_url` is
    // chain-agnostic and `chain_routing` carries the chain marker.
    base_url: String,
    auth_scheme: AuthScheme,   // Header / Path / Query / None — where the operator's token gets injected
    chain_routing: ChainRouting, // Embedded / PathSegment / QueryParam — exactly one
}

// The vote-input DTO submitted by participants.
struct ChainVote {
    chain: ForeignChain,
    providers: Vec<ProviderEntry>, // full proposed list for `chain` (snapshot, not a diff)
    threshold: u64,                // proposed RPC response quorum for `chain`
}
```

This shape differs from earlier sketches of this design in two important ways:

- **Per-chain keying**, not a global `BTreeSet<RpcProvider>` + URL prefix match. A provider voted in for `Ethereum` is structurally invisible when the node loads its `Polygon` section, so cross-chain confusion (e.g. an Ethereum-mainnet URL accidentally accepted under a testnet bucket) is impossible at lookup time.
- **Connection config on chain.** `base_url`, `auth_scheme`, and `chain_routing` live in the whitelist entry instead of being supplied by the operator. The operator only picks `provider_id` and supplies the API token via env. This removes the operator's syntactic surface to inject extra path/query components that could redirect the call.

### Nodes checking if local configuration is valid

On startup, the node validates that every `provider_id` it references in its local [foreign chain configuration](https://github.com/near/mpc/blob/main/crates/node-config/src/foreign_chains.rs) appears in the whitelist for that chain. If a referenced `provider_id` is not whitelisted (e.g. it was just voted out), the node logs a warning and drops that provider from its registration set; if a chain ends up with zero surviving providers, the whole chain is dropped from this run's registration.

Drop-and-log rather than hard-crash so that a single hostile vote-removal participant can't take a node offline by removing a provider that node depends on — operators see the dropped providers in logs/alerts and react.

Since the nodes are running in a Trusted Execution Environment (TEE), this functionality lets the node guard against operators that might otherwise point the binary at a malicious RPC URL. The full URL is assembled from on-chain `base_url` + `chain_routing` + operator-supplied token via `auth_scheme`, so the operator never writes a URL directly.

### Individual node quorum of RPC providers for verification requests

When a foreign TX verification request is processed by a set of nodes, every node individually queries its locally-configured RPC providers for that chain. A node considers the foreign TX verified iff at least a per-chain quorum number of providers agreed.

The quorum value comes from on-chain `ChainEntry.threshold`, voted in as part of the same `ChainVote` that voted the chain's provider list — so participants agree on both "which providers are trusted" and "how many of them must concur" in one round.

### Nodes submit the configured foreign chains on-chain

Nodes submit their per-chain provider set on-chain so the network knows which chains they support. Functionality for this was added on the contract side in [#2784](https://github.com/near/mpc/pull/2784) and is kept — the whitelist is a new layer on top, not a replacement.

## Rollout

Landing in stacked PRs under [#3208](https://github.com/near/mpc/issues/3208):

- **PR 1** ([#3216](https://github.com/near/mpc/pull/3216)): on-chain data shape and storage field (`ForeignChainRpcWhitelist`, `ProviderEntry`, `AuthScheme`, `ChainRouting`, `ProviderId`), `MpcContract` field + storage key, and the `AllowedProviders` data-structure helpers (add/remove/get). No vote endpoints, no view function, no node-side wiring.
- **PR 2** ([#3249](https://github.com/near/mpc/pull/3249)): contract-side voting on the whitelist. Adds `vote_update_foreign_chain_providers(votes: Vec<ChainVote>)`, the `ProviderVotes` pending-vote storage, canonicalization (`providers` sorted by `provider_id`; duplicate chain or `provider_id` in a batch rejected with `InvalidParameters::MalformedPayload`), and the `clean_tee_status` extension that drops votes from non-participants. Voting is **full-snapshot**: each `ChainVote` proposes the chain's complete state (provider list + RPC response quorum), and the chain's stored `ChainEntry` is replaced wholesale once the protocol's signing threshold of participants holds the same canonical `(providers, threshold)` pair (same gate as `vote_add_os_measurement`). Drops the original Add/Remove-ops design for two reasons: (1) snapshot semantics canonicalize trivially (sort the proposed list), avoiding the order-of-apply ambiguity Add/Remove batches introduced, and (2) bundling the RPC response quorum into `ChainVote.threshold` collapses what was originally going to be two separate vote endpoints (whitelist + quorum) into one.
- **PR 3**: node-side wiring — operator-yaml schema change (`provider_id` + `token` only), indexer task streaming the whitelist into a `watch::Receiver`, coordinator startup pipeline (resolve → chain-identity probe → sample-tx probe → register), per-inspector chain-identity probe.
