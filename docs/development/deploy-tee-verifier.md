# Deploy the TEE verifier contract

This runbook deploys the stateless [`tee-verifier`](../../crates/tee-verifier) contract and
makes it the trusted verifier for the MPC contract.

## Overview

Putting the verifier code on-chain is not enough for the MPC contract to use it: the
contract only calls the verifier it trusts, the one named at init or voted in since. So this
runbook has two halves. First, deploy the verifier to its own account and lock it — remove the
account's keys so the code can never change
([steps 1-5](#1-reproducibly-build-the-verifier-and-record-its-hash)). Then the
participants vote that account, together with its code hash, in as the trusted verifier
([step 6](#6-vote-the-verifier-in-participants)).

Replacing a verifier that is already voted in follows the same steps. A locked account can
never be redeployed, so every new verifier gets a new account.

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
export VERIFIER_ACCOUNT=tee-verifier-<YYYY-MM-DD>.near

# testnet
export NETWORK=testnet
export SIGNER_CONTRACT=v1.signer-prod.testnet
export VERIFIER_ACCOUNT=tee-verifier-<YYYY-MM-DD>.testnet
```

Dating the account name keeps every deployment's name unique, since each one needs a new
account.

## 1. Reproducibly build the verifier and record its hash

The hash produced here is `H_source`, the value every operator independently
reproduces and the `expected_code_hash` they commit to when voting.

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
balance must cover storage staking for the deployed WASM, 1 NEAR per 100 KB of the size
printed in [step 1](#1-reproducibly-build-the-verifier-and-record-its-hash), plus a little
gas for the deploy and the lock. If the amount sent exceeds what is needed, the excess can be
refunded before the account is locked (see [step 5](#5-lock-the-account)):

```shell
# storage stake for the WASM size from step 1, plus 0.1 NEAR for gas; e.g. 420 KB -> 4.2 + 0.1
export FUNDING_NEAR=4.3
near account create-account fund-myself "$VERIFIER_ACCOUNT" "$FUNDING_NEAR NEAR" autogenerate-new-keypair save-to-keychain sign-as <funding-account> network-config "$NETWORK" sign-with-keychain send
```

`near-cli` prints the account's new full-access public key. Note it;
[step 5](#5-lock-the-account) deletes it.

## 3. Deploy the verifier

The verifier is stateless and has no initializer, so deploy `without-init-call`.

```shell
near contract deploy "$VERIFIER_ACCOUNT" use-file target/near/tee_verifier/tee_verifier.wasm without-init-call network-config "$NETWORK" sign-with-keychain send
```

## 4. Audit the deployed account (before locking)

`mpc-contract` cannot check the verifier requirements itself, so each
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

The verifier holds no state of its own, so its storage must be empty. Deploying does not
clear storage, so anything written before this point survives every later deploy and
outlives the lock:

```shell
near contract view-storage "$VERIFIER_ACCOUNT" all as-text network-config "$NETWORK" now
```

Any key listed here is a failed audit: the other checks look only at code and access
keys, so unexpected state means something unexpected reached the account.

Optionally confirm the contract executes by calling each method read-only with the
committed fixture. Either outcome proves the DCAP path runs: a verified report while
the fixture's collateral is inside its validity window, or `TCBInfo expired` once the
live clock passes it. A verified report after that point is a failed audit: the
contract is not reading block time. Tests control the verification clock instead of
relying on that window: the crate tests set the VM block timestamp
(`crates/tee-verifier/tests/verify_quote.rs`), and the sandbox tests build the verifier
with its clock pinned at compile time (`crates/contract/tests/sandbox/tee_verifier.rs`):

```shell
near contract call-function as-read-only "$VERIFIER_ACCOUNT" verify_quote file-args crates/tee-verifier/tests/fixtures/verify_quote_args.borsh network-config "$NETWORK" now
near contract call-function as-read-only "$VERIFIER_ACCOUNT" verify_quote_with_collateral_dates file-args crates/tee-verifier/tests/fixtures/verify_quote_args.borsh network-config "$NETWORK" now
```

Both methods take the same arguments and must give the same verdict. Verifiers deployed
before `verify_quote_with_collateral_dates` was added don't have it; the second call then
fails with `MethodNotFound`.

## 5. Lock the account

Locking means removing every full-access key so the deployed bytes can never be
replaced. This is irreversible: once the last full-access key is gone, the account
cannot be controlled again, and neither can its balance.

First return the balance the account does not need. Read its balance and storage use:

```shell
near account view-account-summary "$VERIFIER_ACCOUNT" network-config "$NETWORK" now
```

Keep the storage stake (1 NEAR per 100 KB of storage used) plus 0.01 NEAR for the lock
transaction's gas, and send the rest back:

```shell
# balance - storage stake - 0.01; e.g. 4.2997 NEAR balance, 420 KB used -> 4.2997 - 4.2 - 0.01
export EXCESS_NEAR=0.0897
near tokens "$VERIFIER_ACCOUNT" send-near <funding-account> "$EXCESS_NEAR NEAR" network-config "$NETWORK" sign-with-keychain send
```

Then delete the key from [step 2](#2-create-the-verifier-account):

```shell
near account delete-keys "$VERIFIER_ACCOUNT" public-keys <full-access-public-key> network-config "$NETWORK" sign-with-keychain send
```

Confirm the account is now locked (no keys listed), the code is unchanged, and storage
is still empty:

```shell
near account list-keys "$VERIFIER_ACCOUNT" network-config "$NETWORK" now
near contract download-wasm regular "$VERIFIER_ACCOUNT" save-to-file /tmp/onchain_verifier_locked.wasm network-config "$NETWORK" now
sha256sum /tmp/onchain_verifier_locked.wasm
near contract view-storage "$VERIFIER_ACCOUNT" all as-text network-config "$NETWORK" now
```

## 6. Vote the verifier in (participants)

Publish `$VERIFIER_ACCOUNT` and `H_source` so every operator can independently audit the
account before voting. Each operator confirms every verifier requirement:

- the deployed code hash matches `H_source` (`near contract download-wasm regular
  "$VERIFIER_ACCOUNT" ...` then `sha256sum`, as in [step 4](#4-audit-the-deployed-account-before-locking));
- the account is locked — `near account list-keys "$VERIFIER_ACCOUNT" network-config
  "$NETWORK" now` returns no keys, so the code can never be replaced; and
- the account's storage is empty — `near contract view-storage "$VERIFIER_ACCOUNT" all
  as-text network-config "$NETWORK" now` lists no keys.

Each participant then votes for the same `(candidate_account_id, expected_code_hash)`
pair. Voters who submit different hashes land in different buckets and never combine, so
the published hash must match exactly.

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

Pending votes, grouped by proposal, show who has voted so far; the list clears once a
proposal reaches the threshold:

```shell
near contract call-function as-read-only "$SIGNER_CONTRACT" tee_verifier_votes json-args {} network-config "$NETWORK" now
```

## 7. Confirm the change applied

The vote that reaches the threshold logs `vote_tee_verifier_change: new verifier =
$VERIFIER_ACCOUNT`. Read the resolved verifier; it now returns `$VERIFIER_ACCOUNT`:

```shell
near contract call-function as-read-only "$SIGNER_CONTRACT" tee_verifier_account_id json-args {} network-config "$NETWORK" now
```

The contract stays `Running` throughout.
