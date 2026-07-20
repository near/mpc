# Proving the TEE verifier on localnet

This walks through verifying, on a local network, that:

1. `launch-localnet.sh` deploys the stateless `tee-verifier` contract and votes it
   in as the trusted verifier from every node, and
2. the deployed contract actually executes its DCAP verification logic when
   `verify_quote` is called.

## Scope

Localnet nodes submit `Mock` attestations, so the normal flow never calls the
verifier's DCAP path. This document therefore proves it two ways:

- **Deploy + vote-in** — the config path `launch-localnet.sh` adds (sections 3a–3c).
- **`verify_quote` executes** — by calling it directly on the deployed contract
  with a real fixture quote (section 4). On a live clock it returns
  `Rejected("TCBInfo expired")`, because the fixture collateral's `nextUpdate`
  (2026-04-29) is in the past — the contract runs correctly; only the fixture is
  time-expired.

The accepting (`Verified`) verdict cannot be produced on localnet, whose block
clock cannot be wound back into the fixture's validity window; it is covered by a
pinned-clock unit test, `crates/tee-verifier/tests/verify_quote.rs::verify_quote__should_return_verified_td10_report_for_valid_fixture`.

## Prerequisites

Run every command inside the nix devshell (`nix develop --command ...`). The
binaries must match the nearcore version this workspace pins (2.13.1); the nix
shell also provides near-cli 0.25.1 (the docs require >= 0.25.0) and the pinned
wasm toolchain, which the host toolchain does not.

```bash
# neard, matching the pinned nearcore tag
cargo install --git https://github.com/near/nearcore --tag 2.13.1 neard --locked
# mpc-node, from this workspace
cargo install --path crates/node --locked
```

```console
$ neard --version
neard (release 2.13.1) (commit 9d05464c13dca4794c1802e11f45f163ed9936c2) (rustc 1.97.0) (protocol 86) (db 49)
$ mpc-node --version
mpc-node 3.13.0
$ nix develop --command near --version
near-cli-rs 0.25.1
```

## How the timing works

`launch-localnet.sh` starts a validator and two MPC nodes, drives the whole setup,
then **pauses** at `Press Enter to finish the script and run clean-up steps...`.
While it is paused the chain is live; pressing Enter tears everything down.

> The on-chain checks in **Phase 2** only work while the script is paused with the
> chain still up. Run them from a **second terminal**. Use two terminals:
>
> 1. **Terminal 1** — run `launch-localnet.sh`; wait until it prints the
>    `tee-verifier` lines and pauses at a `Press Enter ...` prompt. Leave it there.
> 2. **Terminal 2** — run the Phase 2 checks against the live chain.
> 3. **Terminal 1** — press Enter to tear down.
>
> Everything runs inside `nix develop`. (A `connection refused (localhost:3030)`
> error means the chain isn't up — either the script already exited, or you used
> the host near-cli instead of the nix one.)

## Phase 1 — build and launch (Terminal 1)

Build both contracts. `--no-abi` is required for the verifier: its `verify_quote`
types don't derive `BorshSchema`, so the default ABI-embedding build fails; the
plain wasm is all localnet needs.

```console
$ nix develop --command cargo near build non-reproducible-wasm --features abi --profile=release-contract --manifest-path crates/contract/Cargo.toml --locked
    Finished cargo near build
    Binary: target/near/mpc_contract/mpc_contract.wasm

$ nix develop --command cargo near build non-reproducible-wasm --no-abi --profile=release-contract --manifest-path crates/tee-verifier/Cargo.toml --locked
    Finished cargo near build
    Binary: target/near/tee_verifier/tee_verifier.wasm
    SHA-256 checksum hex : 475b182cb348798fec20e71bb3f9f85a982c7e36e1e79cfaa95ad0700ef8ea07
```

Launch the network:

```console
$ nix develop --command ./scripts/launch-localnet.sh
Using mpc-contract binary from ./target/near/mpc_contract/mpc_contract.wasm
Creating network with 2 mpc nodes and threshold 2
Cleaning ~/.near folder
Started: neard PID: 24958
Waiting 60 seconds for neard to start properly
Creating mpc-contract account
Deploying mpc-contract
Creating mpc-node accounts
Creating mpc nodes configuration
Starting mpc nodes
Started: mpc-node-1.test.near PID: 25273
Started: mpc-node-2.test.near PID: 25275
Waiting 20 seconds for mpc nodes to start properly
Adding account keys for the nodes
Initializing contract
Adding domains to contract
Waiting 20 seconds for key generation to happen
Creating tee-verifier account
Deploying tee-verifier
Voting in tee-verifier
Executing signature requests
Press Enter to finish the script and run clean-up steps...
```

Reaching `Executing signature requests` means the whole verifier block succeeded:
the account was created, the wasm deployed, and every node's `vote_tee_verifier_change`
call returned (each is guarded, so any failure aborts the script). Leave the script
paused here and switch to Terminal 2.

> The script's final step (`verify_foreign_transaction`) can occasionally fail with
> `Transaction has expired`, an unrelated pre-existing near-cli timing flake that
> happens after all the verifier work. If it does, the script drops straight into
> its clean-up prompt — the chain is still up, so the Phase 2 checks still work.

## Phase 2 — on-chain proof (Terminal 2, while the script is paused)

### 3a. The verifier account exists with the wasm deployed

```console
$ nix develop --command near account view-account-summary tee-verifier.test.near network-config mpc-localnet now
 tee-verifier.test.near                 At block #1375
 Native account balance                 4.9973310937266962 NEAR
 Storage used by the account            365.8 KB
 Local Contract (SHA-256 checksum hex)  475b182cb348798fec20e71bb3f9f85a982c7e36e1e79cfaa95ad0700ef8ea07
 Access keys                            1 full access keys and 0 function-call-only access keys
```

The on-chain code hash equals the wasm built and voted on in Phase 1.

### 3b. The deployed contract exposes `verify_quote`

```console
$ nix develop --command near contract inspect tee-verifier.test.near network-config mpc-localnet now
 tee-verifier.test.near     At block #1376
 SHA-256 checksum [hex]     475b182cb348798fec20e71bb3f9f85a982c7e36e1e79cfaa95ad0700ef8ea07
 SHA-256 checksum [base58]  5oYWdjLumKFKhXb35YntThoKyXuZBh3in1VKpWi32Hcr
 Storage used               365.8 KB (365.7 KB Wasm + 182 B data)
 Contract version           3.13.0
 Supported standards        nep330 (1.3.0)

 Functions: (NEAR ABI is not available, so only function names are extracted)
 fn __getrandom_custom(...) -> ...
 fn contract_source_metadata(...) -> ...
 fn verify_quote(...) -> ...
 fn ring_core_0_17_14__bn_mul_mont(...) -> ...
```

### 3c. The votes were applied (pending votes consumed => verifier accepted)

```console
$ nix develop --command near contract call-function as-read-only mpc-contract.test.near tee_verifier_votes json-args {} network-config mpc-localnet now
Function execution return value (printed to stdout):
{}
```

An empty map means both nodes' votes crossed threshold and were applied, so
`tee-verifier.test.near` is now the trusted verifier.

## Phase 3 — `verify_quote` runs its real logic (Terminal 2, while paused)

`verify_quote(quote: QuoteBytes, collateral: Collateral)` has two
`#[serializer(borsh)]` parameters, which near-sdk decodes as a single struct, so
the raw input is `borsh(quote) ++ borsh(collateral)`. Those bytes are committed as
a fixture, so the call is directly runnable:

```console
$ nix develop --command near contract call-function as-read-only tee-verifier.test.near verify_quote file-args crates/tee-verifier/tests/fixtures/verify_quote_args.borsh network-config mpc-localnet now
Function execution return value (printed to stdout):
TCBInfo expired
```

`TCBInfo expired` is `VerificationResult::Rejected(DcapVerification("TCBInfo expired"))`.
The deployed contract ran its real DCAP path (`dcap_qvl::verify` parsed the quote
and collateral and reached the TCB-expiry check) and correctly rejected: the
fixture collateral's `nextUpdate` (2026-04-29) is past the live block time. The
contract works; only the fixture is time-expired on a live clock.

## Phase 4 — tear down (Terminal 1)

Press Enter at the launch script's prompt. It stops the nodes and validator and
removes `~/.near`.

## Regenerating the `verify_quote` args fixture

`crates/tee-verifier/tests/fixtures/verify_quote_args.borsh` is derived from the
`quote`/`collateral` test fixtures. A guard test keeps it in sync — it fails if the
fixtures change and the file isn't regenerated. Regenerate with:

```bash
UPDATE_FIXTURES=1 nix develop --command cargo test -p tee-verifier --test verify_quote verify_quote_args_fixture
```

## Summary

1. The verifier wasm builds (`--no-abi`), SHA-256 `475b182c...`.
2. `launch-localnet.sh` created and deployed `tee-verifier.test.near` and voted it
   in from both nodes; `tee_verifier_votes` is empty, confirming the votes applied.
3. The deployed account's on-chain code hash equals the voted hash (`475b182c...`).
4. A direct `verify_quote` call executed the real DCAP logic and returned a verdict
   (`TCBInfo expired`, the expected result on today's live clock).
