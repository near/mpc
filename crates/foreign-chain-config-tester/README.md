# Foreign-chain RPC config tester

A standalone tool that checks the foreign-chain RPC providers in an MPC node
config, so a misconfiguration (unreachable URL, wrong/expired API key, or a
provider pointed at the wrong network) is caught before the node hits it in
production.

For each configured provider it runs a fixed request against a known reference
transaction — the same inspector and auth handling the node uses — and compares
the result against a known-good value. Sui, Starknet, Bitcoin, and the EVM chains
are the exceptions: they verify the provider's chain identity (a constant that is
never pruned) and then inspect a recently produced transaction — Sui from its
latest checkpoint, Starknet from its latest L1-accepted block (requires provider
JSON-RPC v0.9+), Bitcoin from a recent block (identity: the genesis block hash),
the EVM chains from the latest finalized block — so the check never depends on
months-old archived history. Every provider is checked independently: one bad
provider does not stop the others from being reported.

Expected identities can be seeded from config under
`foreign_chain_health_check.identities` (chain label -> identity), overriding
the built-in reference — useful for a local or custom network:

```yaml
foreign_chain_health_check:
  identities:
    starknet: "0x534e5f4d41494e" # SN_MAIN (felt)
    base: "8453"                 # EVM numeric chain id
```

## Usage

```bash
cargo run -p foreign-chain-config-tester -- --config /path/to/user-config.toml
```

`--config` accepts any of the config shapes the project uses, in YAML or TOML
(format is inferred from the extension):

- the dstack `user-config.toml` (`foreign_chains` under `mpc_node_config.node`);
- the launcher config (`foreign_chains` under `node`);
- the legacy `config.yaml` (`foreign_chains` at the top level).

### Network

Reference transactions are network-specific. The network is auto-detected from
the config (`chain_id`, falling back to `mpc_contract_id`). Override it — or set
it for configs that carry no such field — with `--network`:

```bash
cargo run -p foreign-chain-config-tester -- --config user-config.toml --network testnet
```

## Output

A row per provider, a summary line, and the reason for each failure listed
below the table. The process exits non-zero if any provider failed.

```
CHAIN     PROVIDER   RESULT
abstract  public     ✓ ok
bitcoin   public     ✓ ok
starknet  public     ✗ failed
aptos     public     ✓ ok
sui       public     ✓ ok

4 passed, 1 failed, 0 skipped

Failures:
  starknet / public: inner network client failed to fetch: Transaction hash not found
```

> **Note:** for providers that carry the API key in the URL (`path` / `query`
> auth), a failure message may include that URL, and therefore the key. Scrub any
> secrets from the output before sharing it.
