# Robust Threshold ECDSA (`src/ecdsa/robust_ecdsa/`)

This module carries two things: the real robust scheme in `ecdsa_v2_sign.rs`, and the
insecure stub (`presign.rs`, `sign.rs`) it supersedes, kept only until the node
switches over. TODO(#4383): remove the stub.

## `ecdsa_v2_sign.rs` — the robust scheme

Implements the signing protocol of
[`docs/ecdsa/robust_ecdsa/signing.md`](../../../docs/ecdsa/robust_ecdsa/signing.md)
as a single protocol with no stored presignatures:

```
Round 1              Round 2                Round 3              Round 4
deal k,a,b,d,e       verify shares against  interpolate R and w  verify the proofs,
under Pedersen       the commitments,       and prove the w_i    send signature shares
commitments          echo the hash η        opening in ZK        to the coordinator
```

- The message hash and tweak are inputs of round 1: key derivation is applied to the
  key shares before the protocol starts, and nonce shares never outlive one
  `(msg_hash, tweak)`, so no presignature rerandomization is needed.
- Shares of `a` and `b` are dealt under Pedersen commitments
  ([`crypto/pedersen.rs`](../../crypto/pedersen.rs)); a dealer sending an
  inconsistent share is identified by the receiving participant.
- Every participant proves in zero knowledge
  ([`crypto/proofs/w_opening.rs`](../../crypto/proofs/w_opening.rs)) that its `w_i`
  opens consistently with its committed `a_i` and `b_i`; the Fiat-Shamir challenge
  is bound to the echoed commitment hash η and the prover's index.
- The last round is asymmetric: participants send their Lagrange-linearized
  signature shares only to the coordinator, which sums them, low-S normalizes and
  verifies the signature.

**Types**: `SignArguments` (keygen output + `MaxMalicious`). The entry point `sign()`
returns a protocol whose output is `Some(signature)` for the coordinator and `None`
for every other participant.

### Threshold

The threshold parameter is `MaxMalicious`, denoted `t`. Signing requires **exactly**
`N = 2t + 1` participants, and `msg_hash == 0` is rejected; both restrictions prevent
split-view attacks (see the security considerations of the spec).

## The stub (`presign.rs`, `sign.rs`)

> **Status: not a secure scheme.** The stub produces valid ECDSA signatures while
> leaking the signing key (`presign.rs` broadcasts the nonce `k` in the clear). It
> only exists so the node and contract plumbing — presignature storage, task
> routing, resharing — stays compiled and exercised until the node switches to
> `ecdsa_v2_sign`. Never add a domain for this protocol on mainnet or testnet.

Its types (`PresignArguments`, `PresignOutput`, `RerandomizedPresignOutput`) are
preserved verbatim from the removed scheme.

## Further Reading

- [`docs/ecdsa/robust_ecdsa/signing.md`](../../../docs/ecdsa/robust_ecdsa/signing.md) -- protocol specification with security considerations
- [`docs/ecdsa/preliminaries.md`](../../../docs/ecdsa/preliminaries.md) -- standard ECDSA recap
- [Parent ECDSA README](../README.md) -- comparison with OT-based ECDSA
