# near/mpc

near/mpc implements NEAR Chain Signatures: users call the signer contract
(`v1.signer` on mainnet), and a network of MPC nodes jointly produces threshold
ECDSA (secp256k1) and EdDSA (Ed25519) signatures, confidential key derivations
(CKD, BLS12-381), and attested foreign-chain transaction verifications. No node
holds a full private key. Architecture: AGENTS.md. Security policy:
.github/SECURITY.md. Design and threat-model docs: docs/design/, in particular
docs/design/threat-model-diagram.md and
docs/design/securing-mpc-with-tee/securing-mpc-with-tee.md. Past audits: audits/.

## Components, in priority order

1. `crates/threshold-signatures`: DKG, resharing, OT-based ECDSA (Beaver
   triples, signing), FROST EdDSA, CKD, and the reliable broadcast and OT
   primitives under them.
2. `crates/contract`: the signer contract. Request intake (`sign`,
   `request_app_private_key`, `verify_foreign_transaction`), responses
   (`respond*`), key derivation from predecessor account and path, participant
   and threshold governance votes, key events (keygen, resharing), TEE
   attestation and allowed measurements, node migration, contract updates.
3. `crates/node`: the MPC node. P2P mesh over mutually authenticated TLS
   (`p2p.rs`, `network/`, `crates/tls`), the coordinator and protocol runner,
   signature providers (`providers/`), the NEAR indexer that reads requests from
   chain, keyshare storage (`keyshare/`, `db.rs`), the migration/backup service
   (`migration_service/`), foreign-chain RPC verification, and the HTTP server
   (`web.rs`).
   `crates/chain-gateway` holds the NEAR indexer's event subscriber and the
   transaction sender. `crates/foreign-chain-inspector` and
   `crates/foreign-chain-rpc-*` query and parse each foreign chain's RPC
   responses; this is the code a malicious RPC provider reaches.
   `crates/backup-cli` is its counterpart for node migration: the operator's
   tool that fetches keyshares from a node's migration service, keeps them
   encrypted with the backup key, and restores them onto the new node.
4. TEE attestation: `crates/attestation`, `crates/mpc-attestation`,
   `crates/tee-*`, `crates/tee-launcher`.
5. Client-facing verification: `crates/near-mpc-sdk`,
   `crates/near-mpc-signature-verifier`, `crates/near-mpc-contract-interface`.

Out of scope: `crates/e2e-tests`, `crates/devnet`, `crates/test-*`,
`crates/*-test-contract`, developer CLIs (`attestation-cli`, `ckd-example-cli`,
`proposal-generator`, `foreign-chain-config-tester`), `deployment/`,
`localnet/`, `scripts/`, Nix files and docs. Report defects in third-party
dependencies, including nearcore, upstream.

## Trust boundaries and attacker positions

State which position an attack needs:

- **Any NEAR account.** Can call any public contract method with arbitrary
  arguments and deposit, and craft requests the indexer and nodes will process.
  This is the most important position.
- **Network attacker.** Can reach a node's P2P and HTTP ports and
  send, drop, delay and reorder traffic, but holds no participant TLS key.
- **Malicious participant(s).** Up to `threshold - 1` participants for ECDSA,
  EdDSA and CKD signing. DKG and resharing use an asynchronous reliable
  broadcast and tolerate fewer than n/3 malicious participants; attacks above
  these bounds are not implementation bugs. A malicious participant may run
  modified code, send arbitrary protocol messages, and vote arbitrarily.
- **Malicious foreign-chain RPC provider.** A node accepts a foreign-chain
  result only when a voted quorum of whitelisted providers agrees. Attacks
  that need fewer providers than the quorum are in scope.
- **Malicious host of a TEE node.** Controls the OS, disk, network and launcher
  inputs outside the Intel TDX CVM, but not CVM memory. Keyshare exposure or
  running unapproved code with a valid attestation is in scope.

Trusted: the NEAR blockchain's consensus, Intel TDX hardware and its attestation
roots, and, on non-TEE nodes, the operator's own local configuration and secrets
files. On TEE nodes, everything the host passes through the launcher, including
the `[mpc_node_config]` table it passes to the node, is attacker input. The
launcher injects `tee` and `node.indexer.mpc_contract_id` itself and rejects
host configs that set them; a bypass of that check is in scope.

## What to look for

- Leakage of key shares, triples or secret nonces (including nonce reuse,
  biased nonces, or triple reuse) through protocol messages, logs, metrics,
  the HTTP server, the migration service, or `backup-cli` (including keyshares
  going to or from a host other than the one registered in the contract, and
  weak handling of the backup encryption key).
- Signature forgery, or a valid signature for a payload, key or derivation
  path the requester is not entitled to; wrong predecessor/path binding; a
  response accepted for the wrong pending request.
- Protocol messages from a malicious participant that cause honest nodes to
  output wrong keys, wrong signatures, or accept an invalid reshare.
- Contract state corruption: governance or threshold bypass, votes counted
  from non-participants, stuck or skippable key events, unauthorized contract
  updates or migrations, attestation checks that can be bypassed.
- Remote crashes, panics, unbounded memory/queue growth, or stalls caused by
  untrusted P2P messages, contract state or chain data. Note that the protocol
  functions in `threshold-signatures` wait indefinitely by design; the node is
  responsible for timeouts.
- Foreign-chain verification accepting a transaction that the quorum of
  providers did not confirm, or for the wrong chain, block or finality.

## Rating severity

- **Critical**: recovery of a private key or of enough key shares to sign;
  signature forgery or signing on behalf of another account/path; theft of
  contract funds; bypass of participant/threshold governance; a TEE node
  exposing plaintext keyshares to its host. Reachable by any NEAR account or a
  network attacker, or by a single malicious participant.
- **High**: key or share recovery, forgery, fund theft or a governance bypass
  that needs several colluding participants (still below the threshold);
  halting the whole network's signing or key events by a non-participant; a
  permanent denial of service by malicious participants: one that outlasts
  their removal by vote, or that blocks the resharing that would remove them; a
  remote crash of honest nodes by a non-participant; a false foreign-chain
  verification.
- **Medium**: denial of service against one node or one request type by a
  non-participant; griefing that costs the attacker gas proportional to the
  damage; leaks of non-secret but private operational data.
- **Low**: temporary denial of service by malicious participants; hardening
  issues without a demonstrated impact; issues needing operator
  misconfiguration on a non-TEE node.

Account for gas costs, deposits and existing limits in resource attacks.

Production `mpc-node` and `tee-launcher` binaries use the `reproducible`
profile (`Cargo.toml`): overflow checks are on and `panic = "abort"`, so an
arithmetic overflow or any other panic, including one inside a spawned task,
kills the node. The contract uses `release-contract`: overflow checks are off,
so overflow wraps silently. `debug_assert!` is off in every production build,
so a failing debug assertion alone is not a crash. A contract panic reverts
that receipt only and is not a crash unless it blocks progress.

Tests ignore `panic = "abort"` and unwind, so a panic inside a spawned task
does not fail a test unless something awaits that task. A reproducer for such
a panic must assert on the task's `JoinError` or call the panicking code
directly.

## Known and intentional: do not report

- `crates/threshold-signatures/src/ecdsa/robust_ecdsa` is a deliberate stub
  that leaks the signing key (see its README). Do not report the leak itself.
- Protocol functions in `threshold-signatures` block forever on missing
  messages; see above.
- Methods behind the `sandbox-test-methods`, `bench-contract-methods`,
  `test-utils` or `network-hardship-simulation` features are not deployed.
- `/debug/*`, `/metrics`, `/public_data` and `/health` on the node's web port
  are intentionally unauthenticated. Report them only if they expose secrets or
  allow state changes.

## Environment and reproduction

The checkout is at /src. The image has the Rust toolchain pinned in
`rust-toolchain.toml` with the wasm32 target, cargo-near, cargo-nextest, and a
`near-sandbox` binary (`NEAR_SANDBOX_BIN_PATH`). Tests are precompiled in the
`test-release` profile (release with overflow checks and debug assertions).
The contract tests compile their contract wasm variants
on first run, which takes a few minutes and works offline.

Run the baseline offline with:

```sh
mpc-tests
```

It runs `cargo nextest run --profile oss-scanner --cargo-profile=test-release
--all-features` over the workspace. The `oss-scanner` profile in
`.config/nextest.toml` leaves out the E2E suite and the tests that need
Internet access. Extra arguments are passed to nextest and narrow the run, for
example `mpc-tests -E 'package(threshold-signatures)'` or
`mpc-tests -E 'test(sign)'`. Narrow with `-E`, not `-p`, which recompiles
dependencies.

Contract sandbox tests in `crates/contract/tests/sandbox` start a local NEAR
node and are the best place to reproduce contract issues end to end. In-process
multi-node tests in `crates/node/src/tests` exercise the node's protocols.
The E2E suite (`crates/e2e-tests`) is excluded: it needs the `mpc-node` binary
and artifacts that `cargo make e2e-tests` builds, which the image does not
provide.

Follow AGENTS.md and docs/development/engineering-standards.md for test
structure.
