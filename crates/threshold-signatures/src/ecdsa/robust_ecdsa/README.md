# Robust Threshold ECDSA — stub (`src/ecdsa/robust_ecdsa/`)

> **Status: this is not a secure scheme.**
> The implementation that used to live here was removed. What remains is a stub that
> produces valid ECDSA signatures while leaking the signing key. It exists so that the node and contract plumbing built
> around this protocol (task routing, resharing, threshold
> validation) stays compiled and exercised until a real robust scheme replaces it.
> TODO(#4383): replace the stub with a real robust scheme.
> Never add a domain for this protocol on mainnet or testnet.

## Pipeline

```
Presigning  -->  Signing
  1 round        1 round
```

`presign_and_sign` runs both rounds as one protocol once the message is known, so no
presignature is ever stored or reused.

## Modules

### `presign.rs`

The one-round presigning step of `presign_and_sign`. Participants broadcast additive
contributions to the nonce `k`, so all of them learn `k` and agree on `R = k * G`, then
fill the `PresignOutput` fields so the signing phase recombines them into a valid
signature. **This is where the key leaks:** any presigner can recover `x` from a
resulting signature via `x = (s * k - h) / R_x`. See the [protocol
specification](../../../docs/ecdsa/robust_ecdsa/signing.md).

### `presign_and_sign.rs`

Presigning and signing as one two-round protocol over a single channel. The tweak is
applied locally between the two rounds, without rerandomization, and only the
coordinator obtains the signature. The node signs with this protocol. See the
[protocol specification](../../../docs/ecdsa/robust_ecdsa/signing.md#presigning-and-signing-in-one-protocol).

### `sign.rs`

The one-round signing step of `presign_and_sign`, with a designated coordinator. Takes
the tweaked presignature and the message hash, produces a standard ECDSA signature
(low-S normalized). Unchanged from the removed scheme and scheme-agnostic: it sums
Lagrange-linearized shares of `s` and provides no secrecy of its own. See the
[protocol specification](../../../docs/ecdsa/robust_ecdsa/signing.md) for details.

## Types

Preserved verbatim from the removed scheme, so a replacement can reuse them:

- **`PresignArguments`** -- input to presigning: keygen output + maximum number of malicious parties
- **`PresignOutput`** -- presignature: `(big_r, c, e, alpha, beta)`

## Threshold

The threshold parameter is `MaxMalicious`, denoted `t`. Both presigning and signing
require **exactly** `N = 2t + 1` participants, and `msg_hash == 0` is rejected. The
stub does not need either restriction; both are retained because the removed scheme
needed them to blunt split-view attacks, and a replacement scheme likely will too.

## Further Reading

- [`docs/ecdsa/robust_ecdsa/signing.md`](../../../docs/ecdsa/robust_ecdsa/signing.md) -- protocol specification
- [`docs/ecdsa/preliminaries.md`](../../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Parent ECDSA README](../README.md) -- comparison with OT-based ECDSA
