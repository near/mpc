# Foreign-chain RPC config tester

A standalone tool that checks the foreign-chain RPC providers in an MPC node
config, so a misconfiguration (unreachable URL, wrong/expired API key, or a
provider pointed at the wrong network) is caught before the node hits it in
production.

For each configured provider it runs a fixed request against a known reference
transaction — the same inspector and auth handling the node uses — and compares
the result against a known-good value. Sui and Starknet are the exceptions: they
verify the provider's chain identity (a genesis-derived constant that is never
pruned) and then inspect a recently produced transaction — Sui from its latest
checkpoint, Starknet from its latest L1-accepted block (requires provider JSON-RPC
v0.9+) — so the check never depends on
months-old archived history. Every provider is checked independently: one bad
provider does not stop the others from being reported.

The expected identity of each identity-probed chain comes from configuration —
there are no built-in values, so the check works for any network, including
local or custom ones. A configured chain without an identity fails its check:

```yaml
foreign_chain_health_check:
  identities:
    starknet: "0x534e5f4d41494e"                              # felt; decode hex as ASCII
    sui: "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S"       # base58 genesis checkpoint digest
```

Well-known values:

| Chain    | Identity                | Mainnet                                        | Testnet                                        |
|----------|-------------------------|------------------------------------------------|------------------------------------------------|
| starknet | `starknet_chainId` felt | `0x534e5f4d41494e` (`SN_MAIN`)                 | `0x534e5f5345504f4c4941` (`SN_SEPOLIA`)        |
| sui      | genesis digest (base58) | `4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S` | `69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD` |

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
