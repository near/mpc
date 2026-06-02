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

### Updating Snapshots
```bash
# We use cargo insta for snapshot testing (.snap files)
cargo nextest run --cargo-profile=test-release <test_name>  # Run failing test to generate .snap.new
cargo insta review                                          # Interactively review pending snapshots
cargo insta accept                                          # Accept all pending snapshots
# Commit updated .snap files alongside code changes
```

### E2E Tests
```bash
cargo make e2e-tests                            # Build required binaries and run all E2E tests
cargo make e2e-tests-skip-build                 # Reuse binaries from a previous run
cargo make e2e-tests-skip-build -- <name>       # Run a single test (filter passed to nextest)
```
See `crates/e2e-tests/README.md` for details.

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

## Code Style

**Before writing or modifying code, read [engineering-standards.md](./docs/engineering-standards.md).** It describes mandatory coding and testing conventions — including test structure, panic policy, and I/O separation — that apply to every change.

### Test Structure
New tests must use this form:

```rust
#[test]
fn <system_under_test>__should_<test_assertion>() {
    // Given
    <setup>

    // When
    <action>

    // Then
    <assertion>
}
```

See `docs/engineering-standards.md` for the full rationale and additional testing conventions.

### Arithmetic in Tests
Do not suggest using `checked_add`, `checked_mul`, `checked_sub`, `saturating_add`, or similar checked/saturating arithmetic in test code — this includes `#[cfg(test)]` modules, integration test crates, and e2e test crates. Raw arithmetic operators (`+`, `-`, `*`, `/`) are fine in tests — overflow will cause a panic, which is the desired behavior in tests.

## Test Terminology

- **Unit test**: Rust test in `/src` folder
- **Integration test**: Rust test in `/tests` folder
- **E2E test**: Rust test in `crates/e2e-tests`

## Documentation alignment

When authoring or reviewing a change that renames, removes, or reshapes code (types, methods, contract entry points, config fields, protocol state, architecture), verify that the surrounding documentation still describes the new behavior. This covers Markdown under `docs/` and any referenced templates, as well as Rust doc comments (`///`, `//!`) on and near the changed items — names, parameters, invariants, and examples in doc comments drift just as easily as prose docs. Design documents (`docs/design/`, `docs/*-design.md`) that describe a superseded design must be either updated, removed, or prominently marked as outdated (e.g. a "Status: superseded by #NNNN" banner at the top) — never left silently stale. If you find stale passages, flag them with `file:line` and, when authoring, fix them in the same PR. Doc drift is a review-blocking issue, not a follow-up.

