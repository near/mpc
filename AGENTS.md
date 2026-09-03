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
cargo make e2e-tests-skip-build <name>          # Run tests matching a substring filter
cargo make e2e-tests-skip-build -E 'test(request_lifecycle)' --no-capture  # Forward nextest flags
```
Everything after the task name is forwarded to `cargo nextest run` unchanged (filters, `-E` expressions, `--no-capture`, `--retries`, `-j`, etc.); no arguments runs the whole suite with the `ci-e2e` profile. Do not put flags after a `--` separator: it is forwarded verbatim, and nextest only accepts filters, not flags, after `--`.
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

### Trait Naming
Traits should model a single capability, and be named after the action, not as an agent noun derived from it: `ReadContractState`, not `ContractStateReader`. This follows std-idiomatic patterns (`From*`/`Into*`/`To*` conversions). This applies to new traits and opportunistic renames, existing traits may deviate from this principle.

See `docs/engineering-standards.md` §Name capability traits after the action for the full rationale and a `Don't` / `Do` example.

### Code Comments
Default to writing no comments. Add one only in case one of the following applies:
- the *why* is non-obvious: an invariant, a constraint, a surprising behavior;
- it is part of the public API. In this case, focus on information relevant to the _consumer_ of that code (provide brief example, explain complexity);
- the code requires a follow-up. In this case, there should be an issue for it, linked via a `TODO(#example_issue_number): <description>` comment. The issue should do the heavy-lifting when it comes to explaining the desired behavior, not the code comment.

Avoid comments that are:
- paraphrasing the code;
- explaining common knowledge or terminology;
- burdening the reader with non-relevant information;

AI-generated code tends to arrive with obvious comments: restating what the next line does, labeling steps (`// setup`, `// send the request`), or narrating the edit that produced the code. Strip these before submitting. Keep a comment only if it says something the code cannot; if a reader can reconstruct it from the names and types on the same screen, delete it. This applies doubly in tests, where the `// Given` / `// When` / `// Then` structure already tells the story.

Prefer concise comments, using correct terminology.

In doc comments, reference other items with rustdoc intra-doc links (`` [`Foo`] ``), not plain `` `Foo` `` backticks. CI rejects broken links in everything rustdoc documents (test code is outside its view), and only linked references are checked at all; a plain backtick reference rots silently when the item is renamed. A backticked word that merely looks like an item (an algorithm name, a type from a crate we do not depend on, a `cfg(test)` item invisible to rustdoc) stays a plain code span.

See `docs/engineering-standards.md` §Write helpful code comments for the full rationale and a `Don't` / `Do` example.

## Test Terminology

- **Unit test**: Rust test in `/src` folder
- **Integration test**: Rust test in `/tests` folder
- **E2E test**: Rust test in `crates/e2e-tests`

## Documentation alignment

Archived documents are recognizable by a `**Status:** ARCHIVED` banner directly below the title; such documents must never be modified. When a PR archives a file, flag contents at risk of becoming stale (such as file paths). This is non-blocking, as version history preserves the paths valid at archiving time. The archiving procedure is described in [README.md §Documentation](README.md#documentation).

All other documents are considered live and expected to be updated if invalidated by a change.

When authoring or reviewing a change that renames, removes, or reshapes code (types, methods, contract entry points, config fields, protocol state, architecture), verify that the surrounding documentation still describes the new behavior. This covers Markdown under `docs/` and any referenced templates, as well as Rust doc comments (`///`, `//!`) on and near the changed items — names, parameters, invariants, and examples in doc comments drift just as easily as prose docs. Design documents (`docs/design/`, `docs/*-design.md`) that describe a superseded design must never be left silently stale: update them in the same PR, or — when the rewrite is too big for the PR that invalidated them — mark the stale sections with a status banner linking an issue that tracks the rewrite (e.g. `**Status:** Partially superseded — TODO(#3825): …`).

If you find stale passages in a live doc, flag them with `file:line` and, when authoring, fix them in the same PR. Doc drift is a review-blocking issue, not a follow-up.
