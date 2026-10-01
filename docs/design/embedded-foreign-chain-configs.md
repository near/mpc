# Embedding foreign chain configs in the node image

**Status:** Proposed — tracked by [#4611](https://github.com/near/mpc/issues/4611)\
**Date:** 2026-10-01

## Background

Rolling out a new foreign chain requires:

1. implementing support in the contract and the node,
2. upgrading the all nodes and the contract (on both network)
3. voting to whitelist the chain and its providers (on both network)
4. every operator updating their `foreign_chains` config.

Step 4 is the slowest, as it needs manual work from every operator. Yet across operators the only
values that differ are API keys and endpoint slugs (e.g. QuickNode's `https://<slug>.<network>.quiknode.pro`). 
Moreover, nodes usually use single multi-chain endpoint per provider, using the same API key.

## Goal

Goal of this design is solely to make step 4. as simple as possible.

Requirements:
- Existing configs keep working unchanged after upgrading.
- Operators supply credentials (API key, plus slug where the provider needs one) once per provider,
  reused for every chain.
- Testnet and mainnet keys stay separate.

Out of scope:

- Distribution of provider API keys
- Contract changes and the whitelist vote (step 3), including deriving the whitelist from the
  embedded config.
- Per (chain, provider) pair credentials.
- Provisioning credentials automatically.
- Removing support for legacy `foreign_chains` sections.


## Design

The proposal can be summarized in 2 steps below:
1. On startup node reads embedded foreign chain config on startup and populates provider credentials in it. (Chain, Provider) pair is active if there is credential configured for that provider.
2. It merges active (Chain, Provider) pairs from the step 1. into the foreign chain config from node configuration file (latter taking priority)

### Config type

`mpc_node_config::ForeignChainsConfig` stays the single type for both the embedded and the operator config, and gets one optional field:

```rust
pub struct ForeignChainsConfig {
    // ...existing per-chain fields unchanged...
    pub credentials: BTreeMap<RpcProviderName, ProviderCredentials>,
}

pub struct ProviderCredentials {
    pub api_key: TokenConfig,
    pub slug: Option<String>,
}
```


### Embedded config

`crates/node-config/foreign_chains/{mainnet,testnet}.toml`, loaded with `include_str!` and parsed
into `ForeignChainsConfig` using today's schema. The node selects the file by `mpc_node_config.near_init.chain_id` any other chain id, or `near_init = None`, means no embedded config.

Being part of the binary, the embedded config is covered by the image hash vote.

### Operator config

Once migrated, the operator's foreign chain config is only:

```toml
[mpc_node_config.node.foreign_chains.credentials]
alchemy   = { val = "..." }
geomi     = { env = "GEOMI_API_KEY" }
quicknode = { val = "...", slug = "my-endpoint" }
```

Testnet and mainnet credentials are separate by construction, since each node runs on one network.

### Config Resolution

The unit of resolution is a (chain, provider) pair, taken whole from one source — never merged field
by field. The config from the file takes precedence.

1. **Embedded Config pairs.** Each embedded (chain, provider) not defined in the file is added if its `auth`
   is `none` or `credentials` has an entry for the provider. Its `auth.token` is set to the entry's
   API key. If its `rpc_url` contains `{slug}`, the entry must also have a slug, which is substituted
   into `rpc_url`, without one the provider is dropped with a warning. 
1. **Node Config pairs.** Each (chain, provider) in the node config's `foreign_chains` overrides embedded config, and logs warning if it exists in both but constructed rpc_url differs.
1. **Chain-level fields** (`timeout_sec`, `max_retries`, `expected_network_fingerprint`) come from
   the file when it defines the chain, otherwise from the embedded config.
1. **Empty chains** — a chain with no providers left — are dropped.
1. `validate()` runs on the resolved config.

The resolved config lives only in memory and is never written back to disk. All consumers
(inspectors, probe, `register_foreign_chains`, whitelist verifier, web UI) receive the resolved
config instead of the file's `foreign_chains`. Since it is the same type, their code doesn't change.

At startup the node logs each pair with its source (`embedded` or `node_config`), and warns 
if same pair is defined in both places but differ, so that operators can remove them.

## Migration

| Operator config | Result |
|---|---|
| Legacy `foreign_chains`, no `credentials` | File pairs and chain-level fields kept as written. Embedded no-auth providers added for pairs the file doesn't define. |
| Legacy + `credentials` | File pairs kept as written. Embedded pairs for providers with credentials added for pairs the file doesn't define. |
| `credentials` only | Embedded config only — the target state. |

## Tradeoffs

The current proposal allows node operators to configure RPC provider credential once and it will be picked up for all existing and new chains that use that provider.
This is great for simplicity but restricts flexibility of setting different credentials per chain for the same provider. This is why we still allow fine-grained configuration per node that way they we keep the config simple while still allowing flexibility with more involved manual editing (as it is today).

## Related

- [Calculating the whitelisted and available foreign-chain sets](calculating-supported-foreign-chains.md)
- [Allowing per-node foreign chain RPC configuration](../archive/design/allowing-per-node-foreign-chain-rpc-configuration.md) (archived)
