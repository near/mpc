# OT-based Threshold ECDSA (`src/ecdsa/ot_based_ecdsa/`)

This module implements the Cait-Sith OT-based threshold ECDSA scheme over Secp256k1. Signing runs as triple generation followed by a single online protocol, `sign`; the signers may be a subset of the triple generators, but must use the triples' threshold.

## Pipeline

```
Triple Generation (offline)  -->  Signing (online)
   2 triples per signature          1 signature
```

Each output is consumed **exactly once** (one-time use).

## Modules

### `triples/`

Beaver triple generation via Oblivious Transfer. Produces `(TripleShare, TriplePub)` pairs where the shares satisfy `a * b = c` and the public values are commitments `(A, B, C) = (g^a, g^b, g^c)`.

See [`triples/README.md`](triples/README.md) for the full OT pipeline.

### `sign.rs`

The signing protocol, as a single function. Runs three rounds over one channel, consuming two Beaver triples once the message hash is known. Rounds 1 and 2 produce `R` and the shares `k_i`, `sigma_i`, which stay local to the run. The key-derivation tweak is applied locally between rounds 2 and 3. In round 3 the designated coordinator aggregates partial signatures into the final ECDSA `Signature`. Nothing binds `R`, which `triple0` alone determines, to the message, so each triple, not just the pair, must be used at most once. See the [specification](../../../docs/ecdsa/ot_based_ecdsa/signing.md).

## Types

- **`SignArguments`** -- input to `sign`: two triples + keygen output + threshold

## Further Reading

- [`docs/ecdsa/ot_based_ecdsa/intro.md`](../../../docs/ecdsa/ot_based_ecdsa/intro.md) -- overview of the protocol documents
- [`docs/ecdsa/ot_based_ecdsa/signing.md`](../../../docs/ecdsa/ot_based_ecdsa/signing.md) -- signing protocol specification
- [`docs/ecdsa/ot_based_ecdsa/orchestration.md`](../../../docs/ecdsa/ot_based_ecdsa/orchestration.md) -- orchestration diagram and threshold constraints
