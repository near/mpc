# Robust Threshold ECDSA (`src/ecdsa/robust_ecdsa/`)

This module implements an amended version of the threshold ECDSA scheme from \[[DJNPO20](https://eprint.iacr.org/2020/501)\]. Unlike OT-based ECDSA, it avoids Beaver triple generation entirely -- the offline phase consists of a single presigning protocol using degree-2t polynomials, resulting in fewer rounds and simpler orchestration.

## Pipeline

```
Presigning (offline)  -->  Signing (online)
  3 rounds                   1 round
```

Each presignature is consumed **exactly once** (one-time use).

## Modules

### `presign.rs`

Three-round presigning protocol that produces a `PresignOutput` from polynomial secret sharing. See the [protocol specification](../../../docs/ecdsa/robust_ecdsa/signing.md) for the full round description.

### `sign.rs`

One-round online signing protocol with a designated coordinator. Takes a rerandomized presignature and the message hash, produces a standard ECDSA signature (low-S normalized). See the [protocol specification](../../../docs/ecdsa/robust_ecdsa/signing.md) for details.

## Types

- **`PresignArguments`** -- input to presigning: keygen output + maximum number of malicious parties
- **`PresignOutput`** -- presignature: `(big_r, c, e, alpha, beta)`
- **`RerandomizedPresignOutput`** -- presignature after rerandomization via HKDF-SHA3-256 for a specific signing context

## Threshold

The threshold parameter is `MaxMalicious`, denoted `t`. Both presigning and signing require **exactly** `N = 2t + 1` participants. This constraint is enforced at initialization and prevents split-view attacks where different subsets sign different messages using shares from the same presignature.

Additionally, `msg_hash == 0` is rejected to prevent a related-key split-view attack.

## Further Reading

- [`docs/ecdsa/robust_ecdsa/signing.md`](../../../docs/ecdsa/robust_ecdsa/signing.md) -- protocol specification with security analysis
- [`docs/ecdsa/preliminaries.md`](../../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Parent ECDSA README](../README.md) -- comparison with OT-based ECDSA
