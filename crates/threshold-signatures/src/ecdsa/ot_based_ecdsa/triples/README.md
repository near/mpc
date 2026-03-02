# Beaver Triple Generation (`src/ecdsa/ot_based_ecdsa/triples/`)

This module implements the full Beaver triple generation pipeline via Oblivious Transfer. A triple consists of threshold-shared values `(a, b, c)` satisfying `a * b = c`, along with public commitments `(A, B, C) = (g^a, g^b, g^c)`.

Triples are the foundational building block for OT-based ECDSA presigning -- each presignature requires two triples.

## Public API

- **`generate_triple(participants, me, threshold, rng)`** -- generates a single triple
- **`generate_triple_many<N>(participants, me, threshold, rng)`** -- generates N triples at once
- **`TripleShare`** -- secret share `(a, b, c)`
- **`TriplePub`** -- public commitments `(A, B, C)` plus participant/threshold metadata

## Internal Pipeline

The triple generation protocol builds on several layers of OT primitives:

```
Batch Random OT          (batch_random_ot.rs)        -- [CO15]
       |
Random OT Extension      (random_ot_extension.rs)    -- [KOS15] / SoftspokenOT variant
       |
Correlated OT Extension  (correlated_ot_extension.rs)
       |
MTA (Multiplicative-to-Additive)  (mta.rs)           -- [HMRT21]
       |
Multiplication            (multiplication.rs)        -- n-party shared multiplication
       |
Triple Generation          (generation.rs)           -- final stage
```

### `batch_random_ot.rs`

Implements the "Simplest" OT Protocol \[[CO15](https://eprint.iacr.org/2015/267)\]. The sender obtains two random keys; the receiver selects one based on a choice bit. This is the base OT layer that bootstraps all subsequent extensions.

### `random_ot_extension.rs`

Extends a small number of base OTs into many via the \[[KOS15](https://eprint.iacr.org/2015/546)\] SoftspokenOT scheme, producing random OT correlations efficiently.

### `correlated_ot_extension.rs`

Builds correlated OT from random OT extension, producing correlated pairs for use in MTA.

### `mta.rs`

Multiplicative-to-Additive conversion \[[HMRT21](https://eprint.iacr.org/2021/1373)\]. Converts multiplicative shares into additive shares using OT, enabling the two parties to jointly compute a product without revealing their inputs.

### `multiplication.rs`

N-party multiplication protocol. For each pair of parties, runs MTA (with one as sender and one as receiver) then aggregates the results. Each party's local product `a_i * b_i` plus the MTA corrections yields additive shares of the global product `a * b`.

### `generation.rs`

The full 5-round triple generation protocol that ties together all the layers above. See the [triple generation specification](../../../../docs/ecdsa/ot_based_ecdsa/triples.md) for the round-by-round description.

### `bits.rs`

Bit manipulation utilities (`BitVector`, `BitMatrix`, `ChoiceVector`) used throughout the OT protocols.

## Further Reading

- [`docs/ecdsa/ot_based_ecdsa/triples.md`](../../../../docs/ecdsa/ot_based_ecdsa/triples.md) -- full specification of the triple generation protocol and all OT sub-protocols
- [`docs/ecdsa/ot_based_ecdsa/intro.md`](../../../../docs/ecdsa/ot_based_ecdsa/intro.md) -- how triples fit into the overall ECDSA pipeline
