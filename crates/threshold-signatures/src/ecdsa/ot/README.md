# Oblivious Transfer (`src/ecdsa/ot/`)

This module holds the Oblivious Transfer protocols over Secp256k1. They are shared building blocks for the ECDSA schemes; today the only consumer is [triple generation](../ot_based_ecdsa/triples/README.md).

## Module Structure

```
base/        base OTs, one file per scheme
extension/   OT extensions built on a base OT, one folder per scheme
bits.rs      bit vectors and matrices
```

### `base/co15.rs`

Implements the "Simplest" OT Protocol \[[CO15](https://eprint.iacr.org/2015/267)\]. The sender obtains two random keys; the receiver selects one based on a choice bit. This is the base OT layer that bootstraps all subsequent extensions.

### `extension/kos15_roy22/random.rs`

Extends a small number of base OTs into many via the \[[KOS15](https://eprint.iacr.org/2015/546)\] SoftspokenOT scheme, producing random OT correlations efficiently.

**The amendment.** The original KOS15 consistency check compresses each row of the OT matrix into one element of GF(2^λ), and the sender verifies a single equation `q = t + x·Δ` using a field multiplication by `Δ`. \[[Roy22](https://eprint.iacr.org/2022/192)\] (SoftSpokenOT) found a flaw in the security proof of that check. The amended check hashes each of the λ columns separately: the receiver sends `x` and `t_1, ..., t_λ`, and the sender verifies `q_j = t_j + Δ_j·x` for every column `j`, where `Δ_j` is a single bit. This costs λ + 1 field elements of communication instead of 2.

### `extension/kos15_roy22/correlated.rs`

The inner step of the extension, called by `random.rs`. It stretches the base OT keys with a PRG: the receiver inputs a matrix `X` and learns a random `T`, and the sender learns `Q = T + X·Δ`. It has no consistency check of its own.

### `bits.rs`

Bit manipulation utilities (`BitVector`, `BitMatrix`, `ChoiceVector`) used throughout the OT protocols.

## Further Reading

- [`docs/ecdsa/ot_based_ecdsa/triples.md`](../../../docs/ecdsa/ot_based_ecdsa/triples.md) -- specification of the OT sub-protocols
