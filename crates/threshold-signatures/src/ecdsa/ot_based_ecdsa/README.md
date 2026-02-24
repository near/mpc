# OT-based Threshold ECDSA (`src/ecdsa/ot_based_ecdsa/`)

This module implements the Cait-Sith OT-based threshold ECDSA scheme over Secp256k1. The signing workflow is split into three phases, each of which can involve different participant sets and thresholds.

## Pipeline

```
Triple Generation (offline)  -->  Presigning (offline)  -->  Signing (online)
   2 triples per presig              1 presignature              1 signature
```

Each output is consumed **exactly once** (one-time use).

## Modules

### `triples/`

Beaver triple generation via Oblivious Transfer. Produces `(TripleShare, TriplePub)` pairs where the shares satisfy `a * b = c` and the public values are commitments `(A, B, C) = (g^a, g^b, g^c)`.

See [`triples/README.md`](triples/README.md) for the full OT pipeline.

### `presign.rs`

Two-round presigning protocol. Consumes two Beaver triples to produce a `PresignOutput` containing `(R, k_i, sigma_i)`. The presignature can later be rerandomized for a specific signing context. See the [presigning specification](../../../docs/ecdsa/ot_based_ecdsa/signing.md).

### `sign.rs`

One-round online signing protocol. Takes a `RerandomizedPresignOutput` (produced by rerandomizing a presignature with HKDF-SHA3-256) and the message hash, then produces the final ECDSA `Signature`. The coordinator aggregates partial signatures and returns the result. See the [signing specification](../../../docs/ecdsa/ot_based_ecdsa/signing.md).

## Types

- **`PresignArguments`** -- input to presigning: two triples + keygen output + threshold
- **`PresignOutput`** -- presignature: `(big_r, k, sigma)`
- **`RerandomizedPresignOutput`** -- presignature after rerandomization for a specific message/context

## Further Reading

- [`docs/ecdsa/ot_based_ecdsa/intro.md`](../../../docs/ecdsa/ot_based_ecdsa/intro.md) -- overview of the three-phase pipeline
- [`docs/ecdsa/ot_based_ecdsa/signing.md`](../../../docs/ecdsa/ot_based_ecdsa/signing.md) -- presigning and signing protocol specification
- [`docs/ecdsa/ot_based_ecdsa/orchestration.md`](../../../docs/ecdsa/ot_based_ecdsa/orchestration.md) -- orchestration diagram and threshold constraints
