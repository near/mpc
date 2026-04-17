# E2E Test Infrastructure

Rust E2E test framework will be replacing the Python pytest system tests. 
We'll spawn real `mpc-node` OS processes against a local NEAR sandbox, exercising 
the full binary including config parsing, P2P networking and built-in NEAR indexer.

## Architecture

```
MpcCluster
  |-- NearNode             NEAR node process with controlled ports
  |-- NearBlockchain       RPC client (near-workspaces) for contract interaction
  |-- Vec<MpcNode>         N mpc-node OS processes, each with its own neard indexer
```

- **NearNode** starts a NEAR validator with deterministic ports.
- **NearBlockchain** is a pure RPC client wrapping `near-workspaces`. It deploys
  the MPC contract, creates accounts, submits transactions, and queries state.
  Environment-agnostic -- can target sandbox or testnet.
- **MpcNode** manages a single `mpc-node` binary. Generates a `start_config.toml`
  pointing the node's built-in NEAR indexer at the NEAR validator via
  `boot_nodes`. Each node runs its own neard process internally, peering with the
  NEAR validator over P2P.
- **MpcCluster** orchestrates everything: starts NEAR node, deploys contract, creates
  accounts, starts N nodes, initializes the contract, adds signature domains, and
  waits for the Running state.

## Port Allocation

Each test gets a unique `test_id`. All ports are computed deterministically:

```
BASE_PORT (20000) + test_id * 82 + offset
```

Per test: 2 cluster-level ports (NEAR node RPC, NEAR node network) + 8 ports per
node (P2P, web UI, migration UI, pprof, near RPC, near network, 2 reserved)
times up to 10 nodes = 82 ports total.


## Running the tests

```bash
cargo make e2e-tests                           # Rebuild binaries then run all tests
cargo make e2e-tests-skip-build                # Reuse binaries from a previous run
cargo make e2e-tests-skip-build -- <test>      # Run a single test (name filter passed to nextest)
cargo make kill-orphan-mpc-nodes              # Kill mpc-node processes left over from interrupted runs
```

> **Tip:** Ports are deterministic per test, so orphan `mpc-node` processes from an
> interrupted run will hold the exact ports the next run needs. If tests fail with
> "address already in use", run `cargo make kill-orphan-mpc-nodes` first.

## Design Reference

See `docs/pytest-deprecation.md` (PR #2446) for the full design document
describing the migration from Python to Rust E2E tests.
