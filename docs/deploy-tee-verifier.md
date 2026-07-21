# Deploy the TEE verifier contract

This runbook deploys the stateless [`tee-verifier`](../crates/tee-verifier) contract and
makes it the trusted verifier for the MPC contract. The steps are the same on `mainnet` and `testnet`; only
account funding differs ([step 2](#2-create-the-verifier-account)).

## Overview

Deploying puts the audited verifier code on-chain at a locked account, but the MPC
contract does not trust an account just because code lives there. The active participants
must vote that account (and its code hash) in, which is what makes it the trusted
verifier. So this runbook has two halves: deploy and lock the account
([steps 1-5](#1-reproducibly-build-the-verifier-and-record-its-hash)), then have
participants vote it in ([step 6](#6-vote-the-verifier-in-participants)).

## Prerequisites

Run the commands inside the nix devshell (`nix develop`) for the pinned `cargo-near`,
`near-cli`, and toolchain versions. A running Docker daemon is required for the
reproducible build. Both `mainnet` and `testnet` are built-in `near-cli` network configs,
so no custom network setup is needed.

## Set your target

The rest of this guide uses these variables. Set them once for the network you are
deploying to.

```shell
# mainnet
export NETWORK=mainnet
export SIGNER_CONTRACT=v1.signer
export VERIFIER_ACCOUNT=tee-verifier.near

# testnet
export NETWORK=testnet
export SIGNER_CONTRACT=v1.signer-prod.testnet
export VERIFIER_ACCOUNT=tee-verifier.testnet
```

## 1. Reproducibly build the verifier and record its hash

The hash produced here is `H_source`, the value every operator independently
reproduces and the `expected_code_hash` they commit to when voting. Use the
reproducible (docker) build: only it yields a hash others can reproduce from the public
source.

```shell
cargo near build reproducible-wasm --manifest-path crates/tee-verifier/Cargo.toml
sha256sum target/near/tee_verifier/tee_verifier.wasm
```

The build runs inside the pinned `sourcescan/cargo-near` image declared in
`crates/tee-verifier/Cargo.toml` and prints the SHA-256 both as hex and bs58. Record
the hash; it is published alongside the vote.

## 2. Create the verifier account

Create a dedicated account for the verifier. It will be locked in
[step 5](#5-lock-the-account), and there
is no in-place upgrade afterwards: rotating the verifier means a new locked account,
so pick a name you are willing to freeze.

On `testnet` the faucet service funds the new account:

```shell
near account create-account sponsor-by-faucet-service "$VERIFIER_ACCOUNT" autogenerate-new-keypair save-to-keychain network-config "$NETWORK" create
```

On `mainnet` there is no faucet; create and fund the account from an existing one. The
balance only needs to cover storage staking for the deployed WASM (about 1 NEAR per
100 KB); 5 NEAR comfortably covers the ~360 KB verifier:

```shell
near account create-account fund-myself "$VERIFIER_ACCOUNT" '5 NEAR' autogenerate-new-keypair save-to-keychain sign-as <funding-account> network-config "$NETWORK" sign-with-keychain send
```

`near-cli` prints the account's new full-access public key. Note it;
[step 5](#5-lock-the-account) deletes it.

## 3. Deploy the verifier

The verifier is stateless and has no initializer, so deploy `without-init-call`.

```shell
near contract deploy "$VERIFIER_ACCOUNT" use-file target/near/tee_verifier/tee_verifier.wasm without-init-call network-config "$NETWORK" sign-with-keychain send
```

## 4. Audit the deployed account (before locking)

`mpc-contract` cannot check either of the verifier requirements itself, so each
operator audits them off-chain. Confirm the deployed bytes match `H_source`:

```shell
near contract download-wasm regular "$VERIFIER_ACCOUNT" save-to-file /tmp/onchain_verifier.wasm network-config "$NETWORK" now
sha256sum /tmp/onchain_verifier.wasm
```

The hash must equal the `H_source` from
[step 1](#1-reproducibly-build-the-verifier-and-record-its-hash). At this point the
account still has
its full-access key:

```shell
near account list-keys "$VERIFIER_ACCOUNT" network-config "$NETWORK" now
```

Optionally confirm the contract executes by calling `verify_quote` read-only with the
committed fixture. With the fixture's time-expired collateral on the live clock this
returns `TCBInfo expired`, which proves the DCAP path runs (the accepting verdict is
covered by the pinned-clock unit test in `crates/tee-verifier/tests/verify_quote.rs`):

```shell
near contract call-function as-read-only "$VERIFIER_ACCOUNT" verify_quote file-args crates/tee-verifier/tests/fixtures/verify_quote_args.borsh network-config "$NETWORK" now
```

## 5. Lock the account

Locking means removing every full-access key so the deployed bytes can never be
replaced. This is irreversible: once the last full-access key is gone, the account
cannot be controlled again. Delete the key from
[step 2](#2-create-the-verifier-account):

```shell
near account delete-keys "$VERIFIER_ACCOUNT" public-keys <full-access-public-key> network-config "$NETWORK" sign-with-keychain send
```

Confirm the account is now locked (no keys listed) and the code is unchanged:

```shell
near account list-keys "$VERIFIER_ACCOUNT" network-config "$NETWORK" now
near contract download-wasm regular "$VERIFIER_ACCOUNT" save-to-file /tmp/onchain_verifier_locked.wasm network-config "$NETWORK" now
sha256sum /tmp/onchain_verifier_locked.wasm
```

## 6. Vote the verifier in (participants)

Publish `$VERIFIER_ACCOUNT` and `H_source` so every operator can rerun the
[step 4 audit](#4-audit-the-deployed-account-before-locking) before voting. Each participant then votes for the same
`(candidate_account_id, expected_code_hash)` pair. Voters who submit different hashes
land in different buckets and never combine, so the published hash must match exactly.

Read the current signing threshold; the change applies once that many participants
have voted for the same pair:

```shell
near contract call-function as-read-only "$SIGNER_CONTRACT" state json-args {} network-config "$NETWORK" now
```

Each participant votes from their own MPC account:

```shell
near contract call-function as-transaction "$SIGNER_CONTRACT" vote_tee_verifier_change json-args '{"candidate_account_id":"'"$VERIFIER_ACCOUNT"'","expected_code_hash":"<H_source>"}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as <your-mpc-account> network-config "$NETWORK" sign-with-keychain send
```

`expected_code_hash` is the SHA-256 hex from
[step 1](#1-reproducibly-build-the-verifier-and-record-its-hash).

## 7. Confirm the change applied

There is no view that returns the resolved `tee_verifier_account_id`, so confirm two
other ways. Pending votes clear to `{}` once the threshold is reached:

```shell
near contract call-function as-read-only "$SIGNER_CONTRACT" tee_verifier_votes json-args {} network-config "$NETWORK" now
```

The threshold-crossing transaction also logs `vote_tee_verifier_change: new verifier =
$VERIFIER_ACCOUNT`. The contract stays `Running` throughout.
