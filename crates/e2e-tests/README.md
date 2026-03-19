# E2E Test Infrastructure

Rust E2E test framework will be replacing the Python pytest system tests. 
We'll spawn real `mpc-node` OS processes against a local NEAR sandbox, exercising 
the full binary including config parsing, P2P networking and built-in NEAR indexer.

## Architecture

```
MpcCluster
  |-- SandboxNode          near-sandbox process with controlled ports
  |-- NearBlockchain       RPC client (near-workspaces) for contract interaction
  |-- Vec<MpcNode>         N mpc-node OS processes, each with its own neard indexer
```

- **SandboxNode** starts a `near-sandbox` neard validator with deterministic ports.
- **NearBlockchain** is a pure RPC client wrapping `near-workspaces`. It deploys
  the MPC contract, creates accounts, submits transactions, and queries state.
  Environment-agnostic -- can target sandbox or testnet.
- **MpcNode** manages a single `mpc-node` binary. Generates a `start_config.toml`
  pointing the node's built-in NEAR indexer at the sandbox validator via
  `boot_nodes`. Each node runs its own neard process internally, peering with the
  sandbox validator over P2P.
- **MpcCluster** orchestrates everything: starts sandbox, deploys contract, creates
  accounts, starts N nodes, initializes the contract, adds signature domains, and
  waits for the Running state.

## Port Allocation

Each test gets a unique `test_id`. All ports are computed deterministically:

```
BASE_PORT (20000) + test_id * 82 + offset
```

Per test: 2 cluster-level ports (sandbox RPC, sandbox network) + 8 ports per
node (P2P, web UI, migration UI, pprof, near RPC, near network, 2 reserved)
times up to 10 nodes = 82 ports total.


## Design Reference

See `docs/pytest-deprecation.md` (PR #2446) for the full design document
describing the migration from Python to Rust E2E tests.
