# Zero-Knowledge Proofs (`src/crypto/proofs/`)

This module implements Maurer \[[Mau09](https://crypto.ethz.ch/publications/files/Maurer09.pdf)\] NIZK (Non-Interactive Zero-Knowledge) sigma proofs using the Fiat-Shamir transform.

## Modules

### `dlog.rs` -- Discrete Log Proof (Schnorr)

Proves knowledge of a scalar `x` such that `x * G = X` (where `G` is the group generator). This is the standard Schnorr identification protocol made non-interactive.

**Used in:**
- OT-based ECDSA triple generation

### `dlogeq.rs` -- Discrete Log Equality Proof

Proves knowledge of a scalar `x` such that `x * G = X0` **and** `x * H = X1` simultaneously (where `G` and `H` are different generators). This ensures the same secret was used in two different group operations.

**Used in:**
- OT-based ECDSA triple generation (round 3, proving consistency of triple commitments)

### `strobe_transcript.rs` -- Fiat-Shamir Transcript

A Merlin-style duplex-sponge transcript built on Strobe128. Provides `T.Add(label, data)` and `T.Challenge(label)` operations for the Fiat-Shamir transform. Supports cloning/forking for proof contexts that need to branch.

### `strobe.rs` (private)

Low-level Strobe128 symmetric primitive implementation.

## Protocol

Both proofs follow the same pattern:
1. Create a `Transcript` with a domain label
2. Absorb the `Statement` (public values) into the transcript
3. **Prover**: commit to a caller-provided nonce, derive challenge from the transcript, compute response
4. **Verifier**: recompute the commitment from challenge + response, check consistency

## Further Reading

- [`docs/crypto/proofs.md`](../../../docs/crypto/proofs.md) -- formal specification with the `Prove`/`Verify` algorithms and notation
