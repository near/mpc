# AGENTS.md

This file provides guidance to code agents when working in this repository.

## Build and Test Commands

### Quick Reference
```bash
# Build
cargo build -p mpc-node --release  # Build MPC node
cargo near build non-reproducible-wasm --features abi --profile=release-contract --manifest-path crates/contract/Cargo.toml --locked  # Build contract

# Test - warning, many tests are currently slow, prefer to run specific tests during development
cargo nextest run --cargo-profile=test-release --all-features  # With nextest

# Run single test
cargo nextest run --cargo-profile=test-release test_name

# Linting and checks
cargo make check-all-fast                      # Fast checks (no tests)
cargo make check-all                           # All checks including tests
cargo clippy --all-targets --locked -- -D warnings
cargo fmt -- --check
```

### System Tests (pytest)
```bash
cd pytest
pytest                                         # Run all tests
pytest -m "not slow"                           # Skip slow tests
pytest --non-reproducible tests/path/test.py::test_name  # Single test
```

Requires building node with: `cargo build -p mpc-node --release --features=network-hardship-simulation`

## Architecture Overview

This is a **Threshold Signature Scheme (TSS)** implementation on NEAR blockchain. Users submit signature requests to an on-chain contract, and MPC nodes collaboratively generate signatures without any single party possessing the complete key.

### Two Main Components

1. **NEAR Indexer**: Monitors the signer contract (`v1.signer` on mainnet) for incoming `sign` requests
2. **MPC Signing**: Threshold ECDSA based on cait-sith library with:
   - Background Beaver triple generation (up to 1M per node)
   - Presignature generation (requires 2 triples each)
   - Signature generation (1 round using a presignature)

### Key Crates

| Crate | Purpose |
|-------|---------|
| `mpc-node` | Main node binary: indexer, coordinator, P2P networking, signature protocols |
| `mpc-contract` | NEAR smart contract: manages requests, participant set, protocol state |
| `contract-interface` | DTOs for contract communication |
| `mpc-primitives` | Core domain types (domain IDs, signature schemes) |
| `mpc-tls` | TLS transport for secure P2P communication |
| `test-utils` | Testing utilities for integration tests |

### mpc-node Internal Structure

- **`providers/`**: Signature implementations (ECDSA, EdDSA, CKD)
- **`coordinator.rs`**: Main state machine watching contract state, spawning MPC jobs
- **`protocol.rs`**: Generic threshold protocol runner
- **`network.rs`**: Mesh network with task-based multiplexing
- **`p2p.rs`**: TLS-based persistent connections
- **`indexer/`**: Blockchain monitoring, transaction submission
- **`db.rs`**: RocksDB persistence for keyshares, triples, presignatures

### Contract State Machine

```
NotInitialized → Running ↔ Initializing/Resharing
```

- **Running**: Normal operation (signing, CKD requests)
- **Initializing**: Key generation across multiple domains
- **Resharing**: Key redistribution after participant changes

### Signature Request Flow

1. User calls `sign()` on contract
2. Indexer detects receipt, adds to SignRequestStorage
3. Coordinator spawns signature provider job
4. Provider acquires triple/presignature, runs FROST protocol
5. Nodes exchange partial signatures via P2P
6. Final signature submitted back to contract

## Test Terminology

- **Unit test**: Rust test in `/src` folder
- **Integration test**: Rust test in `/tests` folder
- **System test**: pytest in `/pytest` folder

