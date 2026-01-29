# Threshold Signatures

This repository offers cryptographic implementations of **threshold ECDSA**,
**threshold EdDSA** and **Confidential Key Derivation**. Prior to
[PR#15](https://github.com/near/threshold-signatures/pull/15), the
implementation had undergone professional *audit*.

The ECDSA code implements an OT-based threshold protocol and a Secret-Sharing
based one. The former is originally imported from the
[Cait-Sith](https://github.com/cronokirby/cait-sith) library and amended to meet
our industrial needs. This includes modifying parts of the code to improve the
performance, augment the security, and generalize functions' syntax. The latter
however is implemented from scratch and follows
\[[DJNPØ](https://eprint.iacr.org/2020/501)\]

The EdDSA implementation is mainly a wrapper of the
[Frost](https://github.com/ZcashFoundation/frost) signing functions instantiated
with Curve25519.

The Confidential Key Derivation (CKD) code implements a threshold protocol to
generate deterministic keys in a confidential manner. The scheme is based on
threshold BLS signatures and ElGamal encryption. Our intended use-case is to
provide deterministic secrets to apps running inside a TEE. For more details,
see the
[CKD docs](docs/confidential_key_derivation/confidential_key_derivation.md).

## Code organization

The repository provides implementations for ECDSA, EdDSA and CKD. Each signature
scheme has its own repository that implements it, namely, `src/ecdsa`,
`src/eddsa`, `src/confidential_key_derivation`. Additionally, `src/crypto`
implements generic mathematical and cryptographic tools used for both schemes
such as polynomial manipulations, randomness generation and commitment schemes.
The module at `src/crypto/proofs` implements
\[[Mau09](https://crypto.ethz.ch/publications/files/Maurer09.pdf)\] proofs for
discrete logarithms, and `src/protocol` allows defining participants,
communication channels, asynchronous functions that run and test the protocol
and reliable broadcast channel. Some additional files are found in `src`.
`src/participants.rs` provides complex structures related to participants mainly
based on hash maps and `src/dkg.rs` implements a distributed key
generation (DKG) that is agnostic of the curve.

## Important Technical Details

### Threshold ECDSA Functionalities

The repository provides two different Threshold ECDSA schemes implemented
over the Secp256k1 curve: an OT-based ECDSA scheme and a Robust ECDSA scheme.
While both rely on the same DKG and key resharing, they differ in their
signing workflows and preprocessing requirements.

#### OT-based Threshold ECDSA

The OT-based threshold ECDSA scheme relies on offline phase with two protocols (triple generation and presigning) to enable
efficient online signing. The following functionalities are provided:

1) **Distributed Key Generation (DKG)**: allows multiple parties to each
generate its own secret key shares and a corresponding master public key.

2) **Key Resharing / Key Refresh**: allows parties to reshare their keys,
add new members, or remove existing ones. Key Refresh refers to resharing
without changing the participant set.

3) **Beaver Triple Generation (offline)**: allows the distributed generation
of multiplicative Beaver triples $(a, b, c)$ and their commitments
$(A, B, C)= (g^a, g^b, g^c)$ where $c = a \cdot b$. These triples are required for presigning.
More details can be found in
[docs](docs/ecdsa/ot_based_ecdsa/triples.md).

4) **Presigning (offline)**: allows generating presignatures during an offline
phase, which are later consumed during online signing when the message becomes
known to the set of signers. More details can be found in
[docs](docs/ecdsa/ot_based_ecdsa/signing.md).

5) **Signing (online)**: corresponds to the online signing phase in which the
signing parties produce a valid ECDSA signature using precomputed material.
More details can be found in
[docs](docs/ecdsa/ot_based_ecdsa/signing.md).

#### Robust Threshold ECDSA

The Robust ECDSA scheme improves efficiency and communication overhead
by avoiding Beaver triple generation. In this variant,
the offline round consists of a single, round-efficient, presigning protocol. 

The following functionalities are provided:

1) **Distributed Key Generation (DKG)**: same as in OT-based ECDSA.

2) **Key Resharing / Key Refresh**: same as in OT-based ECDSA.

3) **Presigning (offline)**: allows generating presignatures during an offline
phase using a different approach than OT-based ECDSA. These presignatures are
later consumed during online signing when the message becomes known.
More details can be found in
[docs](docs/ecdsa/robust_ecdsa/signing.md).

4) **Signing (online)**: signing is performed in a single round protocol between the signers. More details can be found in [docs](docs/ecdsa/robust_ecdsa/signing.md).
### Threshold EdDSA Functionalities

The threshold EdDSA scheme is implemented over curve
Curve25519. We refer to such scheme as Ed25519.
The following functionalities are provided:

1) **Distributed Key Generation (DKG)**: Same as in ECDSA.

2) **Key Resharing** and **Key Refresh**: Same as in ECDSA.

3) **Signing (online)**: Threshold EdDSA is generally more efficient than
threshold ECDSA due to the mathematical formula behind the signature
computation. Our Ed25519 implementation does not necessitate an offline phase of
computation. More details in
[docs](docs/eddsa/signing.md).

### CKD Functionalities

The CKD scheme is implemented over curve
BLS12-381.
The following functionalities are provided:

1) **Distributed Key Generation (DKG)**: Same as in ECDSA, over group $G_2$.

2) **Key Resharing** and **Key Refresh**: Same as in ECDSA.

3) **CKD (online)**: Corresponds to the online signing phase in which the
signing parties produce a valid BLS signature encrypted with an ElGammal public
key. More details in
[docs](docs/confidential_key_derivation/confidential_key_derivation.md).

### Comments

* We do not implement any verification algorithm. In fact, a party possessing
  the message-signature pair can simply run the verification algorithm of the
  corresponding classic, non-distributed scheme using the master verification
  key.

* Our ECDSA signing scheme outsources the message hash to the function caller
  (i.e. expects a hashed message as input and does not internally hash the
  input). However, our EdDSA implementation does not outsource the message
  hashing. Instead, it internally performs the message hash. This distinction is
  an artifact of the multiple different verifiers implemented in the wild where
  some might perform a "double hashing" and others not. (See
  \[[PoeRas24](https://link.springer.com/chapter/10.1007/978-3-031-57718-5_10)\]
  for an in-depth security study of ECDSA with outsourced hashing).

* This implementation allows arbitrary number of parties and thresholds as long
  as the latter verifies some basic requirements (see the
  [documentation](docs/ecdsa/orchestration.md)). However, it is worth mentioning
  that the ECDSA scheme scales non-efficiently with the number of participants
  (Benchmarks to be added soon).

* **🚨 Important 🚨:** Our DKG/Resharing protocol is the same for ECDSA, EdDSA
  and CKD but differs depending on the underlying elliptic curve instantiation.
  Internally, this DKG makes use of a reliable broadcast channel implemented for
  asynchronous peer-to-peer communication. Due to a fundamental impossibility
  theorem for asynchronous broadcast channel, our DKG/Resharing protocol can
  only tolerate $\frac{n}{3}$ malicious parties where $n$ is the total number of
  parties.

* All our public functions that involve network interactions, such as `keygen`,
  `reshare`, `sign`, and `ckd`, are designed to wait indefinitely for the
  expected messages. For instance, if a message needed to proceed is never
  received, the function will enter an infinite wait loop. This behavior is
  intentional, allowing the caller to determine how long to wait in each
  situation. Consequently, **the caller is responsible** for managing potential
  issues, such as implementing timeouts or other mechanisms to prevent functions
  from running indefinitely.

## Build and Test

Building the crate is fairly simple using
``cargo build``.

Run ``cargo test`` to run all the built-in test cases. Some of the tests might
take some time to run as they require running complex protocols with multiple
participants at once.

### Developer Pre-commit Checks

Before committing code, developers should ensure all checks pass. This helps
prevent CI failures. Run:

```sh
cargo check
cargo clippy --all-features --all-targets --locked
cargo fmt -- --check
cargo nextest run --release --all-features --all-targets --locked
```

Or, if using `cargo-make` (`cargo install cargo-make`):

```sh
cargo make check-all
```

This ensures:

* Code compiles (`cargo check`)
* Linting passes (`cargo clippy`)
* Code formatting is consistent (`cargo fmt`)

## Benchmarks

To run all the benchmarks, simply type the following command in your terminal:

```sh
cargo bench
```

Some benchmarks accept additional features that one can fix such as the maximum number of malicious parties `MAX_MALICIOUS`, the number of iterations to be executed `SAMPLE_SIZE`, and the network latency `LATENCY`. All three variables have to be added as environment variables. Example:

```sh
MAX_MALICIOUS=15 LATENCY=100 SAMPLE_SIZE=20 cargo bench -- robust_ecdsa_presign_advanced
```

By default, the maximum number of malicious parties is 6, the latency is 0 milliseconds and the number of iterations is 15.
The detailed numbers and analysis can be found in the [docs/benches/model.md](docs/benches/model.md) documentation.

In a nutshell, our results show that the Robust ECDSA scheme is better to deploy than the OT based ECDSA in terms of efficiency and network bandwidth. In fact, with 15 maximum malicious parties and 100 ms of latency, the Robust ECDSA offline phase is roughly **4.7 times** faster than the OT based ECDSA offline phase and transmits **130 times** less bytes over the network before completing.

## Acknowledgments

This implementation relies on
[Cait-Sith](https://github.com/cronokirby/cait-sith),
[FROST](https://github.com/ZcashFoundation/frost) and
[blstr](https://github.com/filecoin-project/blstrs) and was possible thanks to
contributors that actively put this together:

* Mårten Blankfors
* Robin Cheng
* Kevin Deforth
* Reynaldo Gil Pons
* Chelsea Komlo
* George Kuksa
* Matej Pavlovic
* Simon Rastikian
* Daniel Sharifi
* Bowen Wang

### External Contributors
[0xsecaas](https://github.com/0xsecaas), [Aditya2274](https://github.com/Aditya2274)
