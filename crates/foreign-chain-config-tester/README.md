# Foreign chain RPC config tester

A standalone tool that checks the foreign chain RPC providers in an MPC node
config, so a misconfiguration (unreachable URL, wrong or expired API key, or a
provider pointed at the wrong network) is caught before the node hits it in
production.

It runs the probe the node itself runs after startup and then hourly: every
configured provider is asked which network it serves, and the answer is compared
with the chain's `expected_network_fingerprint` from the same config. Every
provider is checked independently, so one bad provider does not stop the others
from being reported, and the verdicts are exactly the ones the node logs for
that config.

## Usage

```bash
cargo run -p foreign-chain-config-tester -- --config /path/to/user-config.toml
```

`--config` accepts any of the config shapes the project uses, in YAML or TOML
(format is inferred from the extension):

- the dstack `user-config.toml` (`foreign_chains` under `mpc_node_config.node`);
- the launcher config (`foreign_chains` under `node`);
- the legacy `config.yaml` (`foreign_chains` at the top level).

The section is validated the way the node validates it at startup, so a config
the node would refuse fails before any provider is contacted. Tokens configured
with `env` are read from the environment: export them in the shell that runs
the tester.

Each chain needs an `expected_network_fingerprint`; the values per chain and
network are listed in the operator guide under
[Expected network fingerprints](../../docs/guide/running-an-mpc-node-in-tdx-external-guide/running-an-mpc-node-in-tdx-external-guide.md#expected-network-fingerprints).
The expectation is set per chain, so a config can mix networks. A chain
configured without it fails, as it does in the node.

## Output

A row per provider, a placeholder row per chain absent from the config, a
summary line, and the reason for each failure listed below the table. The
process exits with a failure status if any provider failed, or if the config
holds no foreign chains at all.

```
CHAIN      PROVIDER          RESULT
abstract   abstract-testnet  ✓ ok
abstract   alchemy           ✗ failed
adi        -                 – skipped (not configured)
aptos      alchemy           ✗ failed
aptos      public            ✓ ok
bitcoin    public            ✓ ok
ethereum   -                 – skipped (not configured)
fogo       public            ✓ ok
solana     alchemy           ✗ failed
solana     public            ✓ ok
starknet   alchemy           ✗ failed
starknet   publicnode        ✓ ok
sui        public            ✓ ok
...

7 passed, 11 failed, 8 skipped

Failures:
  abstract / alchemy: request rejected: credentials invalid, or not enabled for this chain
  aptos / alchemy: request rejected: credentials invalid, or not enabled for this chain
  solana / alchemy: request rejected: credentials invalid, or not enabled for this chain
  ...
```

| Result | Meaning |
|---|---|
| `ok` | the provider serves the expected network |
| `failed` | the provider is unhealthy; the reason is listed under `Failures` |
| `skipped` | the chain is not configured |

The table and the failure reasons name chains and providers only. They carry no
URLs, tokens, or provider error text, so they can be shared as is. When the
tester refuses the config it reports a validation error instead, and that error
may quote a provider URL, along with a key embedded in it: scrub it before
sharing.
