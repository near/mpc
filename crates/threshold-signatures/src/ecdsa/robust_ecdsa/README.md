# Robust Threshold ECDSA — stub (`src/ecdsa/robust_ecdsa/`)

> **Status: this is not a secure scheme.**
> The [[DJNPO20](https://eprint.iacr.org/2020/501)] implementation that used to live
> here was removed. What remains is a stub that produces valid ECDSA signatures while
> leaking the signing key. It exists so that the node and contract plumbing built
> around this protocol — presignature storage, task routing, resharing, threshold
> validation — stays compiled and exercised until a real robust scheme replaces it.
> Never add a domain for this protocol on mainnet or testnet.

## Pipeline

```
Presigning (offline)  -->  Signing (online)
  1 round                    1 round
```

Each presignature is consumed **exactly once** (one-time use).

## Modules

### `presign.rs`

One-round presigning protocol. Participants broadcast additive contributions to the
nonce `k`, so all of them learn `k` and agree on `R = k * G`, then fill the
`PresignOutput` fields so the signing phase recombines them into a valid signature.
**This is where the key leaks:** any presigner can recover `x` from a resulting
signature via `x = (s * k - h) / R_x`. See the [protocol
specification](../../../docs/ecdsa/robust_ecdsa/signing.md).

### `sign.rs`

One-round online signing protocol with a designated coordinator. Takes a rerandomized
presignature and the message hash, produces a standard ECDSA signature (low-S
normalized). Unchanged from the removed scheme and scheme-agnostic: it sums
Lagrange-linearized shares of `s` and provides no secrecy of its own. See the
[protocol specification](../../../docs/ecdsa/robust_ecdsa/signing.md) for details.

## Types

Preserved verbatim from the removed scheme, so a replacement can reuse them:

- **`PresignArguments`** -- input to presigning: keygen output + maximum number of malicious parties
- **`PresignOutput`** -- presignature: `(big_r, c, e, alpha, beta)`
- **`RerandomizedPresignOutput`** -- presignature after rerandomization via HKDF-SHA3-256 for a specific signing context

## Threshold

The threshold parameter is `MaxMalicious`, denoted `t`. Both presigning and signing
require **exactly** `N = 2t + 1` participants, and `msg_hash == 0` is rejected. The
stub does not need either restriction; both are retained because the removed scheme
needed them to blunt split-view attacks, and a replacement scheme likely will too.

## Further Reading

- [`docs/ecdsa/robust_ecdsa/signing.md`](../../../docs/ecdsa/robust_ecdsa/signing.md) -- protocol specification
- [`docs/ecdsa/preliminaries.md`](../../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Parent ECDSA README](../README.md) -- comparison with OT-based ECDSA
