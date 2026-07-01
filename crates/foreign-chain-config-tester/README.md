# Foreign-chain RPC config tester

A standalone tool that checks the foreign-chain RPC providers in an MPC node
config, so a misconfiguration (unreachable URL, wrong/expired API key, or a
provider pointed at the wrong network) is caught before the node hits it in
production.

For each configured provider it runs a fixed request against a known reference
transaction — the same inspector and auth handling the node uses — and compares
the result against a known-good value. Every provider is checked independently:
one bad provider does not stop the others from being reported.

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

A row per provider, plus a summary line. The process exits non-zero if any
provider failed.

```
CHAIN     PROVIDER   RESULT
abstract  public     ✓ ok
bitcoin   public     ✓ ok
starknet  public     ✗ inner network client failed to fetch: Transaction hash not found
aptos     public     – skipped (no testnet reference transaction for this chain)

3 passed, 1 failed, 1 skipped
```
