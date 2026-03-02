# Confidential Key Derivation (`src/confidential_key_derivation/`)

This module implements a threshold protocol for generating deterministic keys in a confidential manner, based on **BLS signatures** over BLS12-381 and **ElGamal encryption**.

The intended use case is providing deterministic secrets to applications running inside a TEE (Trusted Execution Environment), where the application can derive a key without any single MPC node learning the derived secret.

For a detailed description of the protocol, see the [full specification](../../docs/confidential_key_derivation/confidential-key-derivation.md).

## Modules

### `ciphersuite.rs`

Defines the `BLS12381SHA256` ciphersuite:
- DKG keys live in **G2**
- CKD output (BLS signatures) live in **G1**
- Hash-to-curve uses `ExpandMsgXmd` (RFC 9380) with context string `"NEAR-BLS12381-G2-SHA256-v1"`

### `protocol.rs`

The `ckd()` protocol function -- a **single-round** protocol:
- Participants compute their blinded contribution and send it privately to the coordinator
- The coordinator aggregates and returns `CKDOutput`
- Non-coordinator participants return `None`

### `app_id.rs`

The `AppId` type -- an application identifier.

### `scalar_wrapper.rs`

BLS scalar wrapper utilities for `hash_to_field` compatibility.

## Types

- **`CKDOutput`** -- contains `(Y, C)` (the blinding point and encrypted signature). Provides `unmask(secret_scalar)` to recover the BLS signature.
- **`CKDOutputOption`** -- `Option<CKDOutput>`, since only the coordinator receives output
- **`hash_app_id_with_pk(pk, app_id)`** -- hash-to-curve on BLS12-381 G1

## DKG

Uses the same curve-generic DKG as all other schemes: `keygen::<BLS12381SHA256>(...)`. Keys are generated over G2.

## Further Reading

- [`docs/confidential_key_derivation/confidential_key_derivation.md`](../../docs/confidential_key_derivation/confidential-key-derivation.md) -- full protocol specification with security analysis
- [Main README](../../README.md) -- overview of CKD functionalities
