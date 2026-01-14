# `as_conversions` Clippy Lint

## Overview

This document describes the implementation and usage of the `as_conversions` clippy lint in the MPC project. This lint helps prevent potentially dangerous implicit type conversions using the `as` keyword, encouraging more explicit and safer conversion methods.

## Background

The `as` keyword in Rust can perform various type conversions, some of which can be lossy or have unexpected behavior:
- Truncation (e.g., `u64 as u32` silently discards upper bits)
- Sign changes (e.g., `i32 as u32`)
- Precision loss (e.g., `f64 as f32`)
- Potential undefined behavior in some edge cases

By requiring explicit conversion methods, we make the intent clearer and reduce the risk of bugs.

## Implementation

### Workspace Configuration

The lint is enabled at the workspace level in `Cargo.toml`:

```toml
[workspace.lints.clippy]
as_conversions = "warn"
```

Each crate inherits this configuration:

```toml
[lints]
workspace = true
```

### Existing Conversions

To avoid blocking development while we gradually refactor existing code, 49 files containing existing `as` conversions have been marked with:

```rust
#![allow(clippy::as_conversions)]
```

This allows the existing code to compile while preventing new `as` conversions from being introduced.

## Usage

### What This Means for Developers

When adding new code, you **cannot** use `as` for type conversions. Instead, use explicit conversion methods:

#### ❌ Bad (Will trigger warning):
```rust
let x: u32 = 42;
let y = x as u64;  // Warning: using a potentially dangerous silent `as` conversion
```

#### ✅ Good (Use explicit conversions):
```rust
// For infallible conversions (no precision/data loss):
let x: u32 = 42;
let y = u64::from(x);  // Clear intent: u32 always fits in u64

// For potentially fallible conversions:
let x: u64 = 42;
let y = u32::try_from(x).expect("value too large");  // Explicit about potential failure

// For intentionally lossy conversions:
let x: u64 = 42;
#[allow(clippy::as_conversions)]
let y = x as u32;  // Documented that truncation is intentional
```

### Recommended Conversion Methods

| Scenario | Method | Example |
|----------|--------|---------|
| Infallible conversion (no data loss) | `From::from()` or `Into::into()` | `u64::from(x)` |
| Fallible conversion (may fail) | `TryFrom::try_from()` | `u32::try_from(x)?` |
| Intentionally lossy | `#[allow(clippy::as_conversions)]` with `as` | See below |
| Numeric truncation with wrapping | `.wrapping_as()` (if available) | Check num-traits |

### When You Must Use `as`

If you have a legitimate reason to use `as` (e.g., performance-critical code where the conversion is verified safe), you can allow it locally:

```rust
// Allow for a single statement
#[allow(clippy::as_conversions)]
let y = x as u32;

// Allow for a function
#[allow(clippy::as_conversions)]
fn my_function() {
    let y = x as u32;
}
```

**Important**: Always add a comment explaining why the `as` conversion is safe or intentional.

## Files with Existing `as` Conversions

The following files currently contain allowed `as` conversions and are candidates for refactoring:

### Contract Crate (20 files)
- `src/lib.rs`
- `src/primitives/domain.rs`
- `src/primitives/participants.rs`
- `src/primitives/test_utils.rs`
- `src/primitives/thresholds.rs`
- `src/primitives/votes.rs`
- `src/state/initializing.rs`
- `src/state/resharing.rs`
- `src/state/running.rs`
- `src/state/test_utils.rs`
- `src/tee/proposal.rs`
- `src/update.rs`
- `tests/inprocess/attestation_submission.rs`
- `tests/sandbox/common.rs`
- `tests/sandbox/tee_cleanup_after_resharing.rs`
- `tests/sandbox/tee.rs`
- `tests/sandbox/update_votes_cleanup_after_resharing.rs`
- `tests/sandbox/upgrade_from_current_contract.rs`
- `tests/sandbox/upgrade_to_current_contract.rs`
- `tests/sandbox/vote.rs`

### Node Crate (24 files)
- `src/config.rs`
- `src/coordinator.rs`
- `src/indexer/handler.rs`
- `src/indexer/stats.rs`
- `src/network/indexer_heights.rs`
- `src/network.rs`
- `src/p2p.rs`
- `src/primitives.rs`
- `src/providers/ckd/key_resharing.rs`
- `src/providers/ckd/sign.rs`
- `src/providers/ecdsa/key_resharing.rs`
- `src/providers/ecdsa/presign.rs`
- `src/providers/ecdsa.rs`
- `src/providers/ecdsa/triple.rs`
- `src/providers/eddsa/key_resharing.rs`
- `src/providers/eddsa/sign.rs`
- `src/providers/robust_ecdsa/presign.rs`
- `src/requests/debug.rs`
- `src/requests/queue.rs`
- `src/tests/basic_cluster.rs`
- `src/tests/multidomain.rs`
- `src/tests/research.rs`
- `src/tests/resharing.rs`

### Other Crates (5 files)
- `crates/devnet/src/loadtest.rs`
- `crates/devnet/src/mpc.rs`
- `crates/devnet/src/rpc.rs`
- `crates/mpc-attestation/src/report_data.rs`
- `crates/primitives/src/hash.rs`
- `crates/tee-authority/src/tee_authority.rs`

## Refactoring Guide

When refactoring a file to remove `as` conversions:

1. Review each `as` conversion in the file
2. Determine the intent:
   - Is it infallible? Use `From::from()`
   - Could it fail? Use `TryFrom::try_from()`
   - Is it intentionally lossy? Document why and use `#[allow]` locally
3. Make the changes
4. Test thoroughly
5. Remove the `#![allow(clippy::as_conversions)]` from the top of the file
6. Run `cargo clippy` to ensure no warnings

## Verification

To verify the lint is working:

```bash
# Should pass with no warnings
cargo clippy --workspace --all-targets

# Should pass even with warnings as errors
cargo clippy --workspace --all-targets -- -D warnings
```

## References

- [Clippy `as_conversions` documentation](https://rust-lang.github.io/rust-clippy/master/index.html#as_conversions)
- [PR Discussion](https://github.com/near/mpc/pull/1699#discussion_r2634534748)
- [Rust Book: Type Casting](https://doc.rust-lang.org/book/ch03-02-data-types.html)
- [Rust Reference: Type Coercions](https://doc.rust-lang.org/reference/type-coercions.html)