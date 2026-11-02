# OT-based Threshold ECDSA (`src/ecdsa/ot_based_ecdsa/`)

This module implements the Cait-Sith OT-based threshold ECDSA scheme over Secp256k1. Signing runs as triple generation followed by a single online protocol, `presign_and_sign`; the signers may be a subset of the triple generators, but must use the triples' threshold.

## Pipeline

```
Triple Generation (offline)  -->  Presigning and signing (online)
   2 triples per signature                1 signature
```

Each output is consumed **exactly once** (one-time use).

## Modules

### `triples/`

Beaver triple generation via Oblivious Transfer. Produces `(TripleShare, TriplePub)` pairs where the shares satisfy `a * b = c` and the public values are commitments `(A, B, C) = (g^a, g^b, g^c)`.

See [`triples/README.md`](triples/README.md) for the full OT pipeline.

### `presign_and_sign.rs`

The signing protocol. Runs the presigning rounds and the signing round over one channel, consuming two Beaver triples once the message hash is known, so no presignature is stored. The key-derivation tweak is applied locally between the two, so each triple, not just the pair, must be used at most once. See the [specification](../../../docs/ecdsa/ot_based_ecdsa/signing.md).

### `presign.rs`

The two presigning rounds of `presign_and_sign`. Consume two Beaver triples to produce a presignature `(R, k_i, sigma_i)` that stays local to the run. See the [presigning specification](../../../docs/ecdsa/ot_based_ecdsa/signing.md#presigning).

### `sign.rs`

The signing round of `presign_and_sign`, with a designated coordinator. Takes the tweaked presignature and the message hash; the coordinator aggregates partial signatures into the final ECDSA `Signature`. See the [signing specification](../../../docs/ecdsa/ot_based_ecdsa/signing.md#signing).

## Types

- **`PresignArguments`** -- input to `presign_and_sign`: two triples + keygen output + threshold

## Further Reading

- [`docs/ecdsa/ot_based_ecdsa/intro.md`](../../../docs/ecdsa/ot_based_ecdsa/intro.md) -- overview of the protocol documents
- [`docs/ecdsa/ot_based_ecdsa/signing.md`](../../../docs/ecdsa/ot_based_ecdsa/signing.md) -- signing protocol specification
- [`docs/ecdsa/ot_based_ecdsa/orchestration.md`](../../../docs/ecdsa/ot_based_ecdsa/orchestration.md) -- orchestration diagram and threshold constraints
