# NEAR MPC

This repository contains the MPC node and the on-chain signer contract behind [Chain Signatures](https://docs.near.org/chain-abstraction/chain-signatures): NEAR accounts and contracts request signatures over arbitrary payloads, and a network of MPC nodes produces them with threshold cryptography — no single party ever holds the complete signing key.

```text
        sign(request)         ┌─────────────────┐    observe request     ┌───────────┐
User ───────────────────────▶ │ signer contract │ ─────────────────────▶ │ MPC nodes │
     ◀─────────────────────── │     (NEAR)      │ ◀───────────────────── │  (t-of-n) │
        signature             └─────────────────┘   respond(signature)   └───────────┘
```

## How it works

Each MPC node embeds a NEAR indexer that tracks the signer contract (`v1.signer` on mainnet; see the [chain-gateway design doc](docs/archive/design/chain-gateway-design.md)). Every `sign` request is hashed and mapped to a *leader* node, which drives the threshold signing protocol over P2P with its peers and submits the signature back to the contract. If the leader is offline, or no response has landed on chain within a failover interval, backup leaders take over in turn.

Keys and requests are organized into *domains*, each pairing a signature scheme with a purpose. All schemes share the same curve-independent [distributed key generation](crates/threshold-signatures/docs/dkg.md) but differ in their signing workflows:

- **[OT-based ECDSA](crates/threshold-signatures/docs/ecdsa/ot_based_ecdsa/intro.md)** (Secp256k1) — derived from [Cait-Sith](https://github.com/cronokirby/cait-sith); Beaver triples and presignatures are generated continuously in the background to keep the signing phase itself short.
- **[EdDSA](crates/threshold-signatures/docs/eddsa/signing.md)** (Ed25519) — based on [FROST](https://eprint.iacr.org/2020/852); one signing round using a presignature.
- **[Robust ECDSA](crates/threshold-signatures/docs/ecdsa/robust_ecdsa/signing.md)** (Secp256k1) — currently an insecure stub, never enabled in production; see its documentation.
- **[Confidential Key Derivation](crates/threshold-signatures/docs/confidential_key_derivation/confidential-key-derivation.md)** (BLS12-381) — derives application-specific keys without revealing the master secret.
- **Foreign chain transaction verification** — nodes independently verify transactions on foreign chains (Ethereum, Solana, Aptos, …) and threshold-sign the observed values, letting NEAR contracts react to external chain events without a trusted relayer; see the [design doc](docs/archive/design/foreign-chain-transactions.md).

Nodes can run inside a trusted execution environment (TEE) for defense in depth; see the [TEE design doc](docs/design/securing-mpc-with-tee/securing-mpc-with-tee.md).

## Where to go next

- **Building on the network?** Start with the [Chain Signatures documentation](https://docs.near.org/chain-abstraction/chain-signatures); the [`near-mpc-sdk`](crates/near-mpc-sdk) crate provides request builders and response verification.
- **Operating a node?** Check the [node requirements](docs/guide/node-requirements.md) and the [operating guide](docs/guide/operating-an-mpc-node.md); the rest of [`docs/guide/`](docs/guide) covers TEE setups, metrics, and migrations.
- **Developing this code?** [Building and testing](docs/development/building-and-testing.md) gets you from checkout to green checks; [`docs/development/`](docs/development) has the rest, including the [engineering standards](docs/development/engineering-standards.md).
- **Contributing?** The [contribution guidelines](CONTRIBUTING.md) describe our issue and PR workflow.
- **Researching security?** We strive to have every feature and critical code path independently audited; the reports live in [`audits/`](audits/README.md). To report a vulnerability, follow the [security policy](.github/SECURITY.md).

## Repository layout

All crates live in a [Cargo workspace](Cargo.toml) under `crates/`. The ones you are most likely to look for:

| Crate | Purpose |
|-------|---------|
| [`mpc-node`](crates/node) | The binary run by MPC participants: NEAR indexer, P2P networking, and the threshold protocols themselves |
| [`mpc-contract`](crates/contract) | The smart contract on NEAR: accepts signature requests, manages the participant set and protocol state, governs upgrades through participant voting |
| [`near-mpc-contract-interface`](crates/near-mpc-contract-interface) | Wire formats accepted by the contract, plus a `client` feature for constructing typed contract calls |
| [`near-mpc-sdk`](crates/near-mpc-sdk) | Logic shared between the MPC contract and its callers |
| [`threshold-signatures`](crates/threshold-signatures) | The threshold cryptography itself |

## Releases

Releases are created from `main` with semantic versioning and bundle the node binary with the contract: minor versions stay backward compatible with previous node versions, major versions with the previous major version's contract. See [RELEASES.md](RELEASES.md) for the full process and compatibility guarantees. Node and launcher Docker images support [reproducible builds](docs/guide/reproducible-builds.md).

## Get in touch

- Questions, feedback, or building something on top? Join the [NEAR Dev Telegram](https://t.me/neardev).
- Interested in operating an MPC node? Write to [mpc@nearone.org](mailto:mpc@nearone.org).
