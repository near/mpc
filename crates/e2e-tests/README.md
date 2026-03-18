# E2E Test Infrastructure

Rust E2E test framework replacing the Python pytest system tests. Spawns real
`mpc-node` OS processes against a local NEAR sandbox, exercising the full
binary including config parsing, P2P networking, built-in NEAR indexer, and
Prometheus metrics.

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

This allows `cargo nextest` to run tests in parallel without port collisions.

## Running Tests

```bash
# Prerequisites: build mpc-node binary and contract WASM
cargo build -p mpc-node --release --features test-utils
cargo near build non-reproducible-wasm \
  --manifest-path crates/contract/Cargo.toml --locked

# Run E2E tests
cargo nextest run -p e2e-tests --cargo-profile=test-release
```

## Adding a New Test

1. Create `tests/my_test.rs`
2. Use a unique `E2ePortAllocator::new(<unique_id>)` to avoid port collisions
3. Build an `MpcCluster` with your desired configuration
4. Use cluster methods to interact with the contract and assert behavior

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_my_scenario() -> anyhow::Result<()> {
    let cluster = MpcCluster::start(ClusterConfig {
        num_nodes: 3,
        threshold: 2,
        port_allocator: E2ePortAllocator::new(42),
        ..ClusterConfig::default()
    }).await?;

    // ... test logic ...
    Ok(())
}
```

## Design Reference

See `docs/pytest-deprecation.md` (PR #2446) for the full design document
describing the migration from Python to Rust E2E tests.
