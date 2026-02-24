# Threshold ECDSA (`src/ecdsa/`)

This module implements two threshold ECDSA signing schemes over the **Secp256k1** curve.

## Shared Types (`mod.rs`)

Both schemes share common types defined in this module:

- **`Signature`** -- ECDSA signature containing the full point `big_r` and scalar `s`, with a `verify(public_key, msg_hash)` method
- **`RerandomizationArguments`** -- binds a presignature to a specific signing context (public key, tweak, message hash, participants) before use. Derives a deterministic scalar `delta` via HKDF-SHA3-256 that rerandomizes the presignature nonce, mitigating Wagner attacks (see \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\])
- **`KeygenOutput`** / **`Tweak`** -- Secp256k1-specialized aliases for the curve-generic DKG output types. `Tweak` allows deriving different signing keys from a single DKG output
- **Type aliases** -- `Scalar`, `Element`, `Polynomial`, `PolynomialCommitment`, `CoefficientCommitment` specialized to `Secp256K1Sha256`

## Schemes

### OT-based ECDSA (`ot_based_ecdsa/`)

Originally imported from the [Cait-Sith](https://github.com/cronokirby/cait-sith) library. Uses an **offline phase with two protocols** (triple generation + presigning) to enable efficient one-round online signing. Requires `N >= t` participants where `t = ReconstructionLowerBound`.

See [`ot_based_ecdsa/README.md`](ot_based_ecdsa/README.md) for details.

### Robust ECDSA (`robust_ecdsa/`)

Implemented from scratch following \[[DJNPO20](https://eprint.iacr.org/2020/501)\] with minimal modifications. Avoids triple generation entirely -- the offline round consists of a single presigning protocol using degree-2t polynomials. Requires `N >= 2t+1` signers where `t = MaxMalicious`.

See [`robust_ecdsa/README.md`](robust_ecdsa/README.md) for details.

## Key Differences

| | OT-based ECDSA | Robust ECDSA |
|---|---|---|
| **Offline phases** | Triple generation + Presigning | Presigning only |
| **Offline rounds** | 11+ | 3 |
| **Sign rounds** | 1 | 1 |
| **Triple requirement** | 2 triples per presignature | None |
| **Threshold parameter** | `ReconstructionLowerBound` | `MaxMalicious` |
| **Scaling** | Less efficient with many participants | Better efficiency and bandwidth |

See the [benchmark analysis](../../docs/benches/model.md) for detailed performance comparisons.

## DKG

Both schemes share the same curve-generic DKG implementation (see [root API](../lib.rs) and [`docs/dkg.md`](../../docs/dkg.md)). Key generation, resharing, and refresh are identical -- only the signing workflow differs.

## Further Reading

- [`docs/ecdsa/preliminaries.md`](../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Main README](../../README.md) -- overview of ECDSA functionalities and important notes on hashing and thresholds
