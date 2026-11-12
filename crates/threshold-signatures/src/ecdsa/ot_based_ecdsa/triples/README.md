# Beaver Triple Generation (`src/ecdsa/ot_based_ecdsa/triples/`)

This module implements the full Beaver triple generation pipeline via Oblivious Transfer. A triple consists of threshold-shared values `(a, b, c)` satisfying `a * b = c`, along with public commitments `(A, B, C) = (g^a, g^b, g^c)`.

Triples are the foundational building block for OT-based ECDSA signing -- each signature requires two triples.

## Public API

- **`generate_triple(participants, me, threshold, rng)`** -- generates a single triple
- **`generate_triple_many(participants, me, threshold, batch_size, rng)`** -- generates `batch_size` triples at once
- **`TripleShare`** -- secret share `(a, b, c)`
- **`TriplePub`** -- public commitments `(A, B, C)` plus participant/threshold metadata

## Internal Pipeline

The triple generation protocol builds on the OT primitives in [`src/ecdsa/ot/`](../../ot/README.md):

```
Batch Random OT          (ot/base/co15.rs)              -- [CO15]
       |
Correlated OT Extension  (ot/extension/kos15_roy22/correlated.rs)
       |
Random OT Extension      (ot/extension/kos15_roy22/random.rs) -- [KOS15] / SoftspokenOT variant
       |
MTA (Multiplicative-to-Additive)  (mta.rs)           -- [HMRT21]
       |
Multiplication            (multiplication.rs)        -- n-party shared multiplication
       |
Triple Generation          (generation.rs)           -- final stage
```

### `mta.rs`

Multiplicative-to-Additive conversion \[[HMRT21](https://eprint.iacr.org/2021/1373)\]. Converts multiplicative shares into additive shares using OT, enabling the two parties to jointly compute a product without revealing their inputs.

### `multiplication.rs`

N-party multiplication protocol. For each pair of parties, runs MTA (with one as sender and one as receiver) then aggregates the results. Each party's local product `a_i * b_i` plus the MTA corrections yields additive shares of the global product `a * b`.

### `generation.rs`

The full 5-round triple generation protocol that ties together all the layers above. See the [triple generation specification](../../../../docs/ecdsa/ot_based_ecdsa/triples.md) for the round-by-round description.

## Further Reading

- [`docs/ecdsa/ot_based_ecdsa/triples.md`](../../../../docs/ecdsa/ot_based_ecdsa/triples.md) -- full specification of the triple generation protocol and all OT sub-protocols
- [`docs/ecdsa/ot_based_ecdsa/intro.md`](../../../../docs/ecdsa/ot_based_ecdsa/intro.md) -- how triples fit into the overall ECDSA pipeline
