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

Originally imported from the [Cait-Sith](https://github.com/cronokirby/cait-sith) library. Uses an **offline phase with two protocols** (triple generation + presigning) to enable efficient one-round online signing. Requires `N >= t` participants where `t = ReconstructionThreshold`.

See [`ot_based_ecdsa/README.md`](ot_based_ecdsa/README.md) for details.

### Robust ECDSA (`robust_ecdsa/`) -- stub, not a secure scheme

The \[[DJNPO20](https://eprint.iacr.org/2020/501)\] implementation was removed and replaced by a stub that produces valid signatures while leaking the signing key, so that the node plumbing built around this protocol stays exercised until a real robust scheme replaces it. Requires exactly `N = 2t+1` signers where `t = MaxMalicious`.

See [`robust_ecdsa/README.md`](robust_ecdsa/README.md) before using it for anything.

## Key Differences

OT-based ECDSA is the only secure scheme in this module; the comparison below records
the interface each one presents, not a choice between them.

| | OT-based ECDSA | Robust ECDSA (stub) |
|---|---|---|
| **Offline phases** | Triple generation + Presigning | Presigning only |
| **Offline rounds** | 11+ | 1 |
| **Sign rounds** | 1 | 1 |
| **Triple requirement** | 2 triples per presignature | None |
| **Threshold parameter** | `ReconstructionThreshold` | `MaxMalicious` |
| **Participants** | `N >= t` | exactly `N = 2t + 1` |

The [benchmark analysis](../../docs/benches/results.md) compares OT-based ECDSA against
the removed robust implementation; its robust figures no longer describe this module.

## DKG

Both schemes share the same curve-generic DKG implementation (see [root API](../lib.rs) and [`docs/dkg.md`](../../docs/dkg.md)). Key generation, resharing, and refresh are identical -- only the signing workflow differs.

## Further Reading

- [`docs/ecdsa/preliminaries.md`](../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Main README](../../README.md) -- overview of ECDSA functionalities and important notes on hashing and thresholds
