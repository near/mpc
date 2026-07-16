# Typed client for the MPC contract

Status: draft, discussed on `kd/contract-calls`. Claims verified against the
tree at `2dcccc7f3`; corrections folded in.

## Problem

Every consumer that calls the MPC contract assembles the call by hand: method
name (at best a `method_names` constant), a `serde_json::json!` body, gas, and
deposit — repeated per call site, per backend. The wire format of each method
is therefore defined implicitly, N times. Concretely, the `sign` argument
shape alone is privately re-declared three times (`devnet/src/contracts.rs
SignArgsV1`/`SignArgsV2`, `test-parallel-contract SignArgs`), and one-off
local structs keep appearing where `json!` gets unwieldy (`VoteUpdateArgs`
in `devnet/src/mpc.rs:601`, `SignResponseArgs` in
`contract/tests/sandbox/utils/sign_utils.rs:177`, two divergent private
`ProposeUpdateArgs` — `contract/src/update.rs:89` vs `devnet/src/mpc.rs:543`
— plus e2e's `ProposeUpdateArgsBorsh`, `cluster.rs:1346`). Gas
policy is duplicated the same way (`SIGN_GAS`/`SIGN_DEPOSIT` in
`e2e-tests/src/cluster.rs`, again in `tee-context`, again in devnet call
sites). We want the near-kit
`#[contract]`-style ergonomics (`contract.respond(request, response).await`)
with compile-time argument types, without binding the interface to a single
RPC client, since our consumers sit on five different transports (see table
below).

## Background: where we interact with the contract

| # | Site | Transport | Style today |
|---|------|-----------|-------------|
| 1 | `crates/e2e-tests` | near-kit (`DeployedContract::call_from*`) | `method_names` constant + `json!` body |
| 2 | `crates/contract/tests/sandbox` | near-workspaces (`Account::call`) | constant + `json!`/typed args, gas/deposit inline |
| 3 | `crates/devnet` | near-jsonrpc-client (`submit_tx_to_call_function`) | constant + `json!` body |
| 4 | `crates/tee-context` | chain-gateway (`SubmitFunctionCall`) | **already the target shape**: `call_args` struct → `FunctionCallArgs` |
| 5 | `crates/node` (production) | raw `SignedTransaction` via own tx processor | `ChainSendTransactionRequest` enum (typed, queued), `#[serde(untagged)]` serialization |
| 6 | `crates/node/src/indexer/fake.rs` (fake indexer) | none — interprets the enum against a mock contract | typed enum, no serialization |
| 7 | `crates/ckd-example-cli`, `crates/near-mpc-sdk` | none — emit args for external submission | constant + hand-built body; stays outside the handle (consumes arg structs + constants) |

Contract methods currently called per site (change methods and view methods
listed separately — both are covered by this design):


**e2e-tests**: `init`, `sign`, `request_app_private_key`,
`verify_foreign_transaction`, `propose_update`, `vote_update`,
`vote_new_parameters`, `vote_add_domains`, `vote_cancel_keygen`,
`vote_cancel_resharing`, `submit_participant_info`, `start_node_migration`,
`register_backup_service`, `register_foreign_chain_support`.
Views: `state`, `migration_info`, `get_tee_accounts`,
`get_supported_foreign_chains`, `get_foreign_chain_support_by_node`.

**contract sandbox tests**: everything e2e calls (minus
`start_node_migration`, `register_backup_service`) plus `init_running`,
`migrate`, `respond`, `respond_ckd`, `respond_verify_foreign_tx`, `vote_pk`,
`vote_reshared`, `start_keygen_instance`, `start_reshare_instance`,
`vote_code_hash`, `vote_add_launcher_hash`, `verify_tee`, `clean_tee_status`,
`clean_invalid_attestations`, `vote_update_foreign_chain_providers`, and the
deprecated `register_foreign_chain_config`.
Views: `state`, `config`, `public_key`, `derived_public_key`,
`latest_key_version`, `proposed_updates`, `get_pending_request`,
`get_pending_ckd_request`, `get_pending_verify_foreign_tx_request`,
`get_attestation`, `get_tee_accounts`, `get_supported_foreign_chains`,
`get_foreign_chain_support_by_node`, `allowed_foreign_chain_providers`,
`allowed_docker_image_hashes`, `allowed_launcher_compose_hashes`,
`pending_signature_queue_len`, `pending_ckd_queue_len`.

**devnet**: `init`, `sign`, `request_app_private_key`, `propose_update`,
`vote_update`, `vote_new_parameters`, `vote_add_domains`, `vote_code_hash`.
Views: `state`.

**tee-context**: `submit_participant_info`, `verify_tee`.
Views: `allowed_docker_image_hashes`, `allowed_launcher_compose_hashes`.

**node (production)** — via `ChainSendTransactionRequest`: `respond`,
`respond_ckd`, `respond_verify_foreign_tx`, `vote_pk`, `vote_reshared`,
`start_keygen_instance`, `start_reshare_instance`,
`vote_abort_key_event_instance`, `verify_tee`, `submit_participant_info`,
`conclude_node_migration`, deprecated `register_foreign_chain_config`.
Views: `state`, `migration_info`, `get_attestation`, `get_pending_request`,
`get_pending_ckd_request`, `get_pending_verify_foreign_tx_request`,
`get_supported_foreign_chains`, `get_tee_accounts`,
`allowed_docker_image_hashes`, `allowed_foreign_chain_providers`,
`allowed_launcher_compose_hashes`.

**fake indexer**: consumes the same enum variants as the node, pre-serialization.

## Design

Two layers: two SPI traits (`CallContract`, `ViewContract`) and one handle
struct over them. Interactive consumers (sites 1–4) call the handle
directly; the node's providers do too, with its pipeline (queue, signing,
observation) behind the `CallContract` seam. Site 7 has no transport to
wrap — `ckd-example-cli` prints a method name + JSON body for manual
submission, `near-mpc-sdk` is a transport-less library — so both stay
consumers of the arg structs and method-name constants only.

### Layer 1 — `CallContract`: the transport SPI

One implementation per backend. Location: `near-contract-transport` (today's
`mpc-call-args`, renamed in one of the first PRs), next to
`FunctionCallArgs` — chain-gateway already depends on that crate but not on
the interface crate (the node gains the dependency in PR 6), and the trait
is pure transport vocabulary. One wasm consumer exists:
`chain-gateway-test-contract` (a reproducible wasm build) uses the payload
structs, so the traits and `CallError` (with their `thiserror`/`serde_json`
deps) sit behind a default-on `traits` feature that the test contract
disables. The handle and the arg structs stay in
`near-mpc-contract-interface`, behind the `client` feature — the point is
keeping the transport dependency and client-only code out of the contract's
wasm build (`serde_json`/`thiserror` themselves the contract already depends
on directly).

```rust
pub trait CallContract {
    /// Backend-specific successful call outcome.
    type Output;

    fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> impl Future<Output = Result<Self::Output, CallError>> + Send;
}

/// A `&T` transport is a transport: lets handles borrow a caller
/// instead of consuming it.
impl<T: CallContract> CallContract for &T {
    type Output = T::Output;
    async fn call_contract(&self, id: &AccountId, call: FunctionCallArgs)
        -> Result<T::Output, CallError> {
        T::call_contract(self, id, call).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("failed to serialize call arguments: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to borsh-encode call arguments: {0}")]
    Encode(#[from] std::io::Error),
    #[error("contract call failed: {0}")]
    Call(Box<dyn std::error::Error + Send + Sync>),
}
```

Implementations and where they live:

| Impl | Wraps | Output | Location |
|------|-------|--------|----------|
| `NearKitCaller` | `near_kit::Near` | `FinalExecutionOutcome` | `e2e-tests/src/blockchain.rs` |
| `SandboxCaller<'a>` | `&near_workspaces::Account` | `ExecutionFinalResult` | `contract/tests/sandbox/common.rs` |
| `SandboxAsyncCaller<'a>` | `&near_workspaces::Account` (`transact_async`) | `TransactionStatus` | `contract/tests/sandbox/common.rs` |
| `DevnetCaller` | `Arc<Mutex<OperatingAccessKey>>` | `RpcTransactionResponse` | `devnet/src/caller.rs` |
| `AccountCaller<T>` | `T: SubmitFunctionCall` + key pool (`Vec<Arc<TransactionSigner>>`, one account) | `CryptoHash` | `chain-gateway/src/transaction_sender` |
| `TransactionProcessorHandle` (+ `.awaiting()`) | mpsc into the node's tx pipeline | `()` / `TransactionStatus` | `node/src/indexer/tx_sender.rs` |
| `MockTransactionSender` | mpsc into the fake indexer core | `()` | `node/src/tests/common.rs` |

This is the complete list — every crate that *transacts* with the contract
goes through one of these (site 7 emits args for external submission and
stays outside the handle). tee-context brings no impl of its own (it uses
`AccountCaller`); the node and fake indexer rows are detailed in "Node and
chain-gateway migration" below.

Every impl is spelled out — verified against its backend's actual API — in
the per-crate subsections under "Backend × capability matrix" at the end of
this document.

### Layer 2 — `MpcContractHandle<C>`: the typed interface

Views are covered by the same handle — see "Read side: `ViewContract`"
below. No `Write`/`Read` type split is needed: write methods exist when the
backend implements `CallContract`, view methods when it implements
`ViewContract`.

A struct, not a trait. One inherent `async fn` per contract change method;
each body is the single definition of that method's wire format: method-name
constant, argument struct, gas, deposit. Method signatures mirror the
contract's entry points verbatim — `sign(request)`, `respond(request,
response)`, `vote_update(id)` — so the handle is mechanically checkable
against the contract. The `call_args.rs` struct is the named-parameter wire
encoding of that signature, built inside the handle, never at call sites.
Transaction-level values that are not contract arguments (e.g.
`propose_update`'s deposit) are extra trailing parameters.

```rust
/// Typed interface of the MPC signer contract at a fixed account,
/// generic over the transport backend.
#[derive(Clone)]
pub struct MpcContractHandle<C> {
    caller: C,
    contract_id: AccountId,
}

impl<C: CallContract> MpcContractHandle<C> {
    pub fn new(caller: C, contract_id: AccountId) -> Self { ... }

    pub async fn respond(
        &self,
        request: SignatureRequest,
        response: SignatureResponse,
    ) -> Result<C::Output, CallError> {
        let args = serde_json::to_vec(&SignatureRespondArgs::new(request, response))?;
        self.caller.call_contract(&self.contract_id, FunctionCallArgs {
            method_name: RESPOND.to_string(),
            args,
            gas: MAX_GAS,
            deposit: NearToken::from_yoctonear(0),
        }).await
    }

    // ... one method per row of the table below
}
```

**Gas and deposit are part of the method definition, not the call site.**
Data-driven variation stays inside the body (`request_app_private_key`
matches the `CKDAppPublicKey` variant to pick `SIGN_GAS` vs `CKD_PV_GAS`);
caller-owned values are parameters (`propose_update(&self, code, deposit)` —
the deposit covers storage of the proposed code). No per-call override knob.
Tests that need non-standard gas/deposit on purpose (limit probing, error
paths) use the raw escape hatch: build `FunctionCallArgs` yourself and go
through `caller.call_contract(...)`.

Bind once at setup, call everywhere:

```rust
let mpc_contract = MpcContractHandle::new(&caller, contract_id);   // borrows caller
let mpc_contract = MpcContractHandle::new(caller.clone(), id);     // owns (for `async move` fan-outs)
```

### Handle method set

| Group | Methods |
|-------|---------|
| user requests | `sign`, `request_app_private_key`, `verify_foreign_transaction` |
| node responses | `respond`, `respond_ckd`, `respond_verify_foreign_tx` |
| key events | `vote_pk`, `vote_reshared`, `start_keygen_instance`, `start_reshare_instance`, `vote_abort_key_event_instance`¹, `vote_cancel_keygen`, `vote_cancel_resharing` |
| governance | `vote_new_parameters`, `vote_add_domains`, `vote_update`, `propose_update` (borsh), `vote_code_hash`, `vote_add_launcher_hash`, `vote_update_foreign_chain_providers` |
| TEE | `submit_participant_info`, `verify_tee`, `clean_tee_status`², `clean_invalid_attestations` |
| migration/backup | `start_node_migration`, `register_backup_service`, `conclude_node_migration` |
| foreign chains | `register_foreign_chain_support`, `register_foreign_chain_config` (carries `#[deprecated(note = "#3079")]`) |
| lifecycle | `init`, `init_running`, `migrate` |

¹ `vote_abort_key_event_instance` is currently only sent by the node (via
the enum), not by any client site; included for parity since its args struct
already exists.

² `clean_tee_status` is `#[private]` (`contract/src/lib.rs:1805`): the
contract only accepts it with predecessor == the contract account. The
handle carries it for the sandbox tests, which call as that account.

Everything gets ported, including deprecated methods (typed, marked
`#[deprecated]` so removal stays tracked). The only call sites that stay on
the raw backend are adversarial tests that deliberately send malformed
arguments — the escape hatch is a feature: error-path tests must be able to
send garbage.

"Everything" is scoped to methods some workspace crate calls today. The
contract exposes further public entry points that nothing in the workspace
exercises (`register_foreign_chains_config`, `remove_update_vote`,
`vote_remove_launcher_hash`, `vote_add_os_measurement`,
`vote_remove_os_measurement`, `vote_tee_verifier_change`,
`withdraw_tee_verifier_vote`; views `metrics`, `launcher_hash_votes`,
`code_hash_votes`, `tee_verifier_votes`, `os_measurement_votes`,
`allowed_os_measurements`, `allowed_launcher_image_hashes`,
`get_available_foreign_chains`, `get_foreign_chains_configs`) — those grow
handle methods on first use. Mind the near-collision when that happens: the
live `register_foreign_chains_config` (plural) and the deprecated
`register_foreign_chain_config` (singular) differ by one letter.

### Read side: `ViewContract`

The second SPI, next to `CallContract` in `near-contract-transport`. Views need no
signer, gas, or deposit — just bytes in, bytes out; the handle owns the
typed encoding/decoding. `ViewArgs` mirrors `FunctionCallArgs`; block
reference/finality is its natural future field (all call sites read `Final`
today):

```rust
/// A NEAR view-function request: method name and encoded args.
#[derive(Debug, Clone)]
pub struct ViewArgs {
    pub method_name: String,
    pub args: Vec<u8>,
}

pub trait ViewContract {
    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<Vec<u8>, CallError>> + Send;
}
```

View methods live on the same `MpcContractHandle<C>`, in a second,
capability-gated impl block — signatures mirror the contract's view entry
points *including return types*:

```rust
impl<C: ViewContract> MpcContractHandle<C> {
    pub async fn state(&self) -> Result<ProtocolContractState, CallError> { ... }
    pub async fn get_pending_request(&self, request: &SignatureRequest)
        -> Result<Option<YieldIndex>, CallError> { ... }
    // ...one per view method in the Background inventory (~20)
}
```

Implementations: `NearKitCaller` (near-kit `view`), `SandboxCaller`
(workspaces `view`), `DevnetCaller` (jsonrpc query), and — directly, since no
signer is involved — `ChainGateway` (its `pub(crate) QueryViewFunction` is
the same shape; the impl lives in-crate, so no visibility change). The node's
`IndexerViewClient` implements it too, replacing its 11 hand-rolled
contract-view helpers (`indexer.rs:101-407`; `latest_final_block`,
`indexer.rs:311`, is a block query, not a contract view — it stays, and the
tx submit path keeps using it). `TransactionProcessorHandle`
deliberately does *not* implement it: a queue cannot view, and the type
system now says so.

Decoding is JSON for every view except `allowed_foreign_chain_providers`,
the contract's single `#[result_serializer(borsh)]` view
(`contract/src/lib.rs:1671`); its handle method borsh-decodes, exactly as
the node's `get_allowed_foreign_chain_providers` does today.

Out of scope here: subscriptions (tee-context's hash *watcher* streams view
updates via `state_viewer` — a different shape than one-shot views), and
`ObservedState`'s block-height metadata (chain-gateway can report at which
height a value was observed; the trait flattens to bytes until a consumer
needs the height). Missing return-type DTOs get added to the interface crate
as they come up.

### Argument structs

This section is PR 1 of the rollout (see "Rollout: PR sequence"): purely
additive to `call_args.rs`, no behavior change, and every consumer PR builds
on it.

`call_args.rs` stays the single wire-format truth. Structs that exist on main
are kept: `SignatureRespondArgs`, `CKDRespondArgs`,
`VerifyForeignTransactionRespondArgs`, `VotePkArgs`, `VoteResharedArgs`,
`StartKeygenArgs`, `StartReshareArgs`, `VoteAbortKeyEventInstanceArgs`,
`SubmitParticipantInfoArgs`, `ConcludeNodeMigrationArgs`,
`RegisterForeignChainConfigArgs`. Seven of them (`VotePkArgs`,
`VoteResharedArgs`, `StartKeygenArgs`, `StartReshareArgs`,
`VoteAbortKeyEventInstanceArgs`, `ConcludeNodeMigrationArgs`,
`RegisterForeignChainConfigArgs`) are `Serialize`-only today and gain
`Deserialize` here: PR 6's `method_name`+deserialize dispatch (observation,
fake indexer) round-trips every variant.

`ProposeUpdateArgs` moves in from the contract crate
(`contract/src/update.rs:89`) — the contract depends on this crate, so the
handle cannot name the struct where it lives today without a dependency
cycle. The move also retires the divergent duplicates: devnet's
`ProposeUpdateArgs` (`mpc.rs:543`; field named `contract`, config typed
`Option<()>` — wire-compatible only because borsh is positional and `config`
is always `None`) and e2e's `ProposeUpdateArgsBorsh` (`cluster.rs:1346`).

Other private duplicates get deleted in favor of the shared structs:
`VoteUpdateArgs` (devnet), `SignResponseArgs` (sandbox tests), and — as
follow-up work — `SignArgsV1`/`SignArgsV2` (devnet). The node's `SignArgs`
(`indexer/handler.rs:48`) is *not* on this list: it is the validated
indexing-side form of an incoming request (the wire shape it parses is
`UnvalidatedSignArgs { request: SignRequestArgs }`), not a call encoding.

Gas and deposit policy lives next to the handle as constants
(`SIGN_GAS = 15 Tgas`, `CKD_PV_GAS = 100 Tgas` for the pairing-check variant,
`SIGN_DEPOSIT = 1 yocto`, `MAX_GAS = 300 Tgas` carrying TODO(#166) —
benchmark and reduce).

## Before / after, per site

**e2e-tests** (`cluster.rs:780-789`):

```rust
// before
let args = json!({
    "request": { "domain_id": domain_id, "path": "test", "payload_v2": payload }
});
self.contract
    .call_from_with_deposit(&client, method_names::SIGN, args, SIGN_GAS, SIGN_DEPOSIT)
    .await

// after (gas and deposit move into the handle)
let mpc = MpcContractHandle::new(&client, contract_id);
mpc.sign(request).await
```

`DeployedContract` keeps deployment and `code_hash` (an account query, not a
contract view) and loses `call_from*` to the write side and `view`/`state`
to the read side.

**contract sandbox tests** (`sign_utils.rs:323-345`, where `args` is the
locally-defined `SignResponseArgs`):

```rust
// before
let respond = attested_account
    .call(contract.id(), method)   // method = RESPOND
    .args_json(args)
    .max_gas()
    .transact()
    .await?;

// after (local SignResponseArgs deleted in favor of the shared SignatureRespondArgs)
let mpc = MpcContractHandle::new(SandboxCaller(attested_account), contract_id);
let respond = mpc.respond(request, response).await?;
```

**devnet** (`mpc.rs:571-578`, using the locally-defined `VoteUpdateArgs`):

```rust
// before
key.submit_tx_to_call_function(
    &contract,
    method_names::VOTE_UPDATE,
    &serde_json::to_vec(&VoteUpdateArgs { id: self.update_id }).unwrap(),
    300, 0, near_primitives::views::TxExecutionStatus::Final, true,
).await

// after (local VoteUpdateArgs moves to call_args.rs)
let mpc = MpcContractHandle::new(DevnetCaller::new(key), contract.clone());
mpc.vote_update(self.update_id).await
mpc.propose_update(args, deposit).await
```

**tee-context** (struct at `lib.rs:61-69`, write path at `lib.rs:119-152`) —
in scope, and goes further than a call-site swap: `TeeContext` has no
consumers yet, so it is redesigned to hold the handle directly. The write
path stops knowing about signers, gas, and the contract id:

```rust
// before
pub struct TeeContext<S> { governance_contract: AccountId, submitter: S, ... }
ctx.submit_attestation(&signer, attestation, tls_public_key).await   // hand-builds FunctionCallArgs

// after: handle bound at construction (signer + contract id absorbed);
// methods lose their `signer` parameter and delegate to the handle
pub struct TeeContext<S> { mpc_contract: MpcContractHandle<AccountCaller<S>>, ... }
ctx.submit_attestation(attestation, tls_public_key).await   // → mpc_contract.submit_participant_info(...)
```

The read side (background hash watcher / view subscriptions) keeps its
gateway view dependency: the watcher is a *subscription*, which stays
outside the one-shot `ViewContract` (see "Read side: `ViewContract`").


### Node and chain-gateway migration

The node's providers use the same handle as everyone else. The queue keeps
its role, but its currency changes from `ChainSendTransactionRequest` to
`FunctionCallArgs`, and the node's `TransactionSender` trait is deleted —
`CallContract` *is* that trait, generalized. `TransactionProcessorHandle`
(the mpsc handle behind today's trait) implements `CallContract` with
`Output = ()` by enqueueing; a thin `.awaiting()` newtype implements it with
`Output = TransactionStatus` for today's `send_and_wait` callers. Account
choice is expressed by which handle a provider holds: each
`TransactionProcessorHandle` is constructed for one signing account (respond
vs owner) and stamps it on every queue message — the routing that
`signer_for` (`tx_signer.rs:139`) derives from the enum variant today rides
on the message instead, since `FunctionCallArgs` alone cannot carry it:

```rust
// wiring: two handles over the same processor, bound to different accounts
let respond_mpc = MpcContractHandle::new(respond_sender, contract_id.clone());
let owner_mpc   = MpcContractHandle::new(owner_sender, contract_id);

// provider call site, before → after
sender.send(ChainSendTransactionRequest::Respond(
    SignatureRespondArgs::new(request, response))).await;
respond_mpc.respond(request, response).await;
```

Behind the queue the pipeline is unchanged — sign, submit, record metrics,
observe — with three adjustments:

- `observe_tx_result` re-keys from enum-variant match to `method_name` match
  plus `serde_json::from_slice` of the args it needs (the respond structs
  and `SubmitParticipantInfoArgs` derive `Deserialize` already; PR 1 adds it
  to the other seven — see "Argument structs").
- `SubmitParticipantInfo`'s `serde(skip)` expiry baseline (observation
  context that must never reach the wire; today view-read by the caller and
  threaded into the enum variant, `tee/remote_attestation.rs:66`) is
  captured at submit time instead: the processor, on dequeueing a
  `SUBMIT_PARTICIPANT_INFO` message, view-reads the pre-submit expiry itself
  (deserializing `tls_public_key` from the args). The queue handle stays
  view-less — the processor owns view access, so "a queue cannot view"
  still holds.
- until PR 7 the signing step remains the node's own `tx_signer`, whose
  `create_and_sign_function_call_tx` takes a raw `Gas` and hardcodes deposit
  0 (`tx_signer.rs:52`): PR 6 threads the message's `NearGas` (converted)
  and deposit through it. Every node-sent method is zero-deposit today, so
  behavior is unchanged.

Deleted outright: `ChainSendTransactionRequest` with its `method()` and
`gas_required()` (gas/deposit now come from the handle — single source), the
`TransactionSender` trait, and `signer_for` (account choice collapsed into
which handle a provider holds; key rotation stays inside the per-account
signer pool, later inside `AccountCaller`).

The fake indexer follows the same currency change: `MockTransactionSender`
implements `CallContract`, and the fake's apply loop dispatches on
`method_name` + deserializes. `TestNodeUid` attribution and
`txn_delay_blocks` live on the channel, not the payload — unchanged. Node
integration tests then exercise the real wire encoding by construction.

The chain-gateway swap becomes a bottom-of-processor change: the
sign-and-submit step is replaced by `AccountCaller` (one per account),
deleting `indexer/tx_signer.rs` — the nonce semantics match the gateway
signer's (both keep a per-key `nonce: Mutex<u64>` floored by block height).
One chain-gateway visibility change is needed: `SubmitFunctionCall` is
blanket-implemented for `T: FetchLatestFinalBlockInfo +
SubmitSignedTransaction`, but both bound traits are `pub(crate)`
(`primitives.rs:53,61`), which seals the blanket to in-crate types — PR 7
makes them `pub`, so the node can implement them on its existing
`IndexerViewClient` / `IndexerRpcHandler` (same nearcore actors underneath);
feature-gated exports (the existing `test-utils` `cfg` pattern) remain the
fallback. Both interim paths dissolve once the node adopts
`ChainGateway::start()` wholesale. The node's debug page
(`/debug/recent_transactions`) is fed from the processor's `submit_tx`
through the `LogTransaction` channel (`tx_sender.rs:163`, `web.rs:346`);
after the swap, nonce/signature/block height are produced inside
chain-gateway's signer and `submit_function_call_tx` returns only a
`CryptoHash`, so PR 7 either extends chain-gateway to surface per-submission
metadata or consciously drops those columns — decided in the PR.

This lands as PRs 6 and 7 of the rollout (see "Rollout: PR sequence").


## Backend × capability matrix

| Backend | Crate | `CallContract` (Output) | `ViewContract` |
|---|---|---|---|
| `NearKitCaller` (near-kit) | e2e-tests | ✓ (`FinalExecutionOutcome`) | ✓ |
| `SandboxCaller<'a>` (near-workspaces) | contract sandbox tests | ✓ (`ExecutionFinalResult`) | ✓ |
| `SandboxAsyncCaller<'a>` (`transact_async`) | contract sandbox tests | ✓ (`TransactionStatus`) | — |
| `DevnetCaller` (near-jsonrpc-client) | devnet | ✓ (`RpcTransactionResponse`) | ✓ |
| `AccountCaller<T>` (signer pool) | chain-gateway | ✓ (`CryptoHash`) | — (views need no signer; use `ChainGateway`) |
| `ChainGateway` | chain-gateway | — (holds no signer) | ✓ |
| `TransactionProcessorHandle` (+ `.awaiting()`) | node | ✓ (`()` / `TransactionStatus`) | — (a queue cannot view) |
| `IndexerViewClient` | node | — | ✓ |
| `MockTransactionSender` | node tests (fake indexer) | ✓ (`()`) | — |
| `MockChainState` | chain-gateway `mock` (`test-utils`) | via `AccountCaller<MockChainState>` | ✓ |

### e2e-tests — `NearKitCaller` (near-kit)

*CallContract*:
```rust
impl CallContract for NearKitCaller {
    type Output = FinalExecutionOutcome;
    async fn call_contract(&self, id: &AccountId, call: FunctionCallArgs)
        -> Result<Self::Output, CallError> {
        // near-kit depends on the same single-version near-gas/near-token
        // as FunctionCallArgs (Cargo.lock), presumably re-exported — confirm
        // at PR 3, along with `args_raw` existing on the *call* builder
        // (verified on the view builder only; `.args()` would double-encode).
        self.inner.call(id.as_str(), &call.method_name)
            .args_raw(call.args)
            .gas(call.gas)
            .deposit(call.deposit)
            .send().await
            .map_err(|e| CallError::Call(Box::new(e)))
    }
}
```

*ViewContract*:
```rust
impl ViewContract for NearKitCaller {
    async fn view_contract(&self, id: &AccountId, view_args: ViewArgs)
        -> Result<Vec<u8>, CallError> {
        // near-kit 0.11 exposes no raw-bytes view result publicly
        // (ViewFunctionResult.result is crate-private), so round-trip via
        // serde_json::Value. Wart; candidate upstream fix.
        let value: serde_json::Value = self.inner
            .view(id.as_str(), &view_args.method_name)
            .args_raw(view_args.args)
            .await
            .map_err(|e| CallError::Call(Box::new(e)))?;
        Ok(serde_json::to_vec(&value)?)
    }
}
```

### contract sandbox tests — `SandboxCaller` (near-workspaces)

*CallContract* (`SandboxAsyncCaller` identical with `.transact_async()`,
`Output = TransactionStatus`):
```rust
impl CallContract for SandboxCaller<'_> {
    type Output = ExecutionFinalResult;
    async fn call_contract(&self, id: &AccountId, call: FunctionCallArgs)
        -> Result<Self::Output, CallError> {
        self.0.call(id, &call.method_name)
            .args(call.args)
            .gas(call.gas)
            .deposit(call.deposit)
            .transact().await
            .map_err(|e| CallError::Call(Box::new(e)))
    }
}
```

*ViewContract*:
```rust
impl ViewContract for SandboxCaller<'_> {
    async fn view_contract(&self, id: &AccountId, view_args: ViewArgs)
        -> Result<Vec<u8>, CallError> {
        let details = self.0.view(id, &view_args.method_name)   // ViewResultDetails
            .args(view_args.args)
            .await
            .map_err(|e| CallError::Call(Box::new(e)))?;
        Ok(details.result)
    }
}
```

### devnet — `DevnetCaller` (near-jsonrpc-client)

*CallContract*:
```rust
impl CallContract for DevnetCaller {
    type Output = RpcTransactionResponse;
    async fn call_contract(&self, id: &AccountId, call: FunctionCallArgs)
        -> Result<Self::Output, CallError> {
        self.key.lock().await
            .submit_tx_to_call_function(
                id, &call.method_name, &call.args,
                call.gas.as_tgas(), call.deposit.as_yoctonear(),
                self.wait_until, self.verbose)
            .await
            .map_err(|e| CallError::Call(e.into()))
    }
}
```

*ViewContract* (no key needed — `OperatingAccessKey` already holds the
`Arc<NearRpcClients>`; same pattern as today's `read_contract_state`):
```rust
impl ViewContract for DevnetCaller {
    async fn view_contract(&self, id: &AccountId, view_args: ViewArgs)
        -> Result<Vec<u8>, CallError> {
        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: id.clone(),
                method_name: view_args.method_name,
                args: FunctionArgs::from(view_args.args),
            },
        };
        let response = self.rpc().submit(request).await
            .map_err(|e| CallError::Call(e.into()))?;
        match response.kind {
            QueryResponseKind::CallResult(r) => Ok(r.result),
            other => Err(CallError::Call(format!("unexpected response: {other:?}").into())),
        }
    }
}
```

### chain-gateway — `AccountCaller<T>` / `ChainGateway`

*CallContract* (on `AccountCaller<T>`; `ChainGateway` holds no signer — it is
account-agnostic shared infrastructure — so it *produces* callers. One caller
= one on-chain identity; >1 key = parallel nonce lanes — production guidance
recommends 50+ keys for the respond account, `node/src/config.rs:415`):
```rust
pub struct AccountCaller<T> {
    submitter: T,
    signers: Vec<Arc<TransactionSigner>>,
    next: AtomicUsize,
}

impl ChainGateway {
    pub fn caller(&self, signers: Vec<Arc<TransactionSigner>>) -> AccountCaller<ChainGateway> {
        AccountCaller { submitter: self.clone(), signers, next: AtomicUsize::new(0) }
    }
}

impl<T: SubmitFunctionCall + Sync> CallContract for AccountCaller<T> {
    type Output = CryptoHash;
    async fn call_contract(&self, id: &AccountId, call: FunctionCallArgs)
        -> Result<Self::Output, CallError> {
        let signer = &self.signers[self.next.fetch_add(1, Ordering::Relaxed) % self.signers.len()];
        // each TransactionSigner manages its own nonce internally (signer.rs:27)
        self.submitter.submit_function_call_tx(signer, id.clone(), call)
            .await
            .map_err(|e| CallError::Call(Box::new(e)))
    }
}
```
tee-context constructs a single-key caller: `gateway.caller(vec![signer])`.

*ViewContract* (directly on `ChainGateway` — views need no signer; its
`pub(crate) QueryViewFunction` has exactly this shape and the impl lives
in-crate, so no visibility change):
```rust
impl ViewContract for ChainGateway {
    async fn view_contract(&self, id: &AccountId, view_args: ViewArgs)
        -> Result<Vec<u8>, CallError> {
        let observed = self.query_view_function(id, &view_args.method_name, &view_args.args)
            .await
            .map_err(|e| CallError::Call(Box::new(e)))?;
        Ok(observed.value)   // ObservedState<Vec<u8>>; observed_at dropped for now
    }
}
```

### node — `TransactionProcessorHandle` / `IndexerViewClient`

*CallContract* (enqueue; message type lands with the queue-currency PR —
design-stage, unlike the impls above):
```rust
impl CallContract for TransactionProcessorHandle {
    type Output = ();
    async fn call_contract(&self, id: &AccountId, call: FunctionCallArgs)
        -> Result<(), CallError> {
        self.transaction_sender
            .send(TransactionSenderSubmission {
                contract_id: id.clone(),
                call,
                // one handle = one signing account, fixed at construction;
                // replaces today's enum-variant `signer_for` routing
                account: self.account,
                response_sender: None,
            })
            .await
            .map_err(|_| CallError::Call("transaction processor closed".into()))
    }
}
// `.awaiting()` newtype: same body with a oneshot response_sender,
// Output = TransactionStatus.
```

*ViewContract* (on `IndexerViewClient`; generalizes its 11 hand-rolled contract-view
helpers — mechanics verified against `get_pending_request`, `indexer.rs:102`):
```rust
impl ViewContract for IndexerViewClient {
    async fn view_contract(&self, id: &AccountId, view_args: ViewArgs)
        -> Result<Vec<u8>, CallError> {
        let query = near_client::Query {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: id.clone(),
                method_name: view_args.method_name,
                args: view_args.args.into(),
            },
        };
        let response = self.view_client.send_async(query).await
            .map_err(|e| CallError::Call(Box::new(e)))?    // actor mailbox error
            .map_err(|e| CallError::Call(Box::new(e)))?;   // query error
        match response.kind {
            QueryResponseKind::CallResult(r) => Ok(r.result),
            other => Err(CallError::Call(format!("unexpected response: {other:?}").into())),
        }
    }
}
```

### fake indexer & mocks — `MockTransactionSender` / `MockChainState`

*CallContract* (`MockTransactionSender`, `node/src/tests/common.rs`; queue
currency changes with the same PR):
```rust
impl CallContract for MockTransactionSender {
    type Output = ();
    async fn call_contract(&self, _id: &AccountId, call: FunctionCallArgs)
        -> Result<(), CallError> {
        self.transaction_sender.send(call).await
            .map_err(|_| CallError::Call("fake indexer closed".into()))
    }
}
```

*ViewContract* (`MockChainState`, chain-gateway `mock`, `test-utils`-gated):
its `QueryViewFunction` impl (`mock.rs:145`) already records calls and
returns scripted `ObservedState`s — the `ViewContract` impl wraps it exactly
like `ChainGateway`'s does.

Deliberate asymmetries are the design working: writes always need an
identity (signer or queue), views never do, and each backend implements
exactly what it can honor.
## Handle methods — exact signatures

Extracted from `contract/src/lib.rs`; per the mirror rule these *are* the
handle signatures. Write methods return `C::Output` (the backend's execution
outcome) — contract return values (e.g. `vote_update → bool`) ride inside
that outcome, and extracting them typed is backend-specific and out of scope.
Gas: `SIGN_GAS` = 15 Tgas, `CKD_PV_GAS` = 100 Tgas, `MAX_GAS` = 300 Tgas —
`MAX_GAS` carries TODO(#166) (today at `node/src/indexer/types.rs:117`): it
is too high in most settings and should be benchmarked and reduced; this
refactor moves that TODO to the single gas-constants module rather than
resolving it. Deposit is 0 unless noted.

### Write methods (`C: CallContract`)

| Method | Parameters | Gas | Deposit |
|---|---|---|---|
| `sign` | `request: SignRequestArgs` | `SIGN_GAS` | 1 yocto |
| `request_app_private_key` | `request: CKDRequestArgs` | `SIGN_GAS` / `CKD_PV_GAS` by `CKDAppPublicKey` variant | 1 yocto |
| `verify_foreign_transaction` | `request: VerifyForeignTransactionRequestArgs` | `SIGN_GAS` | 1 yocto |
| `respond` | `request: SignatureRequest, response: SignatureResponse` | `MAX_GAS` | |
| `respond_ckd` | `request: CKDRequest, response: CKDResponse` | `MAX_GAS` | |
| `respond_verify_foreign_tx` | `request: VerifyForeignTransactionRequest, response: VerifyForeignTransactionResponse` | `MAX_GAS` | |
| `vote_pk` | `key_event_id: KeyEventId, public_key: PublicKey` | `MAX_GAS` | |
| `vote_reshared` | `key_event_id: KeyEventId` | `MAX_GAS` | |
| `start_keygen_instance` | `key_event_id: KeyEventId` | `MAX_GAS` | |
| `start_reshare_instance` | `key_event_id: KeyEventId` | `MAX_GAS` | |
| `vote_abort_key_event_instance` | `key_event_id: KeyEventId` | `MAX_GAS` | |
| `vote_cancel_keygen` | `next_domain_id: u64` | `MAX_GAS` | |
| `vote_cancel_resharing` | — | `MAX_GAS` | |
| `vote_new_parameters` | `prospective_epoch_id: EpochId, proposal: ProposedThresholdParameters` | `MAX_GAS` | |
| `vote_add_domains` | `domains: Vec<DomainConfig>` | `MAX_GAS` | |
| `vote_update` | `id: UpdateId` | `MAX_GAS` | |
| `propose_update` | `args: ProposeUpdateArgs` (borsh; struct moves into `call_args.rs` — see "Argument structs") + trailing `deposit: NearToken` | `MAX_GAS` | caller-supplied |
| `vote_code_hash` | `code_hash: NodeImageHash` | `MAX_GAS` | |
| `vote_add_launcher_hash` | `launcher_hash: LauncherImageHash` | `MAX_GAS` | |
| `vote_update_foreign_chain_providers` | `votes: NonEmptyBTreeMap<ForeignChain, ChainEntry>` (borsh) | `MAX_GAS` | |
| `submit_participant_info` | `proposed_participant_attestation: Attestation, tls_public_key: Ed25519PublicKey` | `MAX_GAS` | |
| `verify_tee` | — | `MAX_GAS` | |
| `clean_tee_status` (`#[private]`: predecessor must be the contract account) | — | `MAX_GAS` | |
| `clean_invalid_attestations` | `max_scan: u32` | `MAX_GAS` | |
| `start_node_migration` | `destination_node_info: DestinationNodeInfo` | `MAX_GAS` | |
| `register_backup_service` | `backup_service_info: BackupServiceInfo` | `MAX_GAS` | |
| `conclude_node_migration` | `keyset: &Keyset` | `MAX_GAS` | |
| `register_foreign_chain_support` | `foreign_chain_support: SupportedForeignChains` | `MAX_GAS` | |
| `register_foreign_chain_config` (deprecated, #3079) | `foreign_chain_configuration: ForeignChainConfiguration` | `MAX_GAS` | |
| `init` | `parameters: ThresholdParameters, init_config: Option<InitConfig>` | `MAX_GAS` | |
| `init_running` | `domains: Vec<DomainConfig>, next_domain_id: u64, keyset: Keyset, parameters: ThresholdParameters, init_config: Option<InitConfig>` | `MAX_GAS` | |
| `migrate` | — | `MAX_GAS` | |

Note: `propose_update` and `vote_update_foreign_chain_providers` are the two
borsh-encoded methods; everything else is JSON.

Note: `submit_participant_info` is `#[payable]` — a new attestation from a
non-participant caller must attach a storage-covering deposit
(`contract/src/lib.rs:823`). Every current caller is a participant sending
0, which is what the handle sends; a prospective-participant flow uses the
escape hatch (or grows a deposit parameter when it becomes real).

### View methods (`C: ViewContract`)

| Method | Parameters | Returns |
|---|---|---|
| `state` | — | `ProtocolContractState` |
| `config` | — | `Config` |
| `version` | — | `String` |
| `public_key` | `domain_id: Option<DomainId>` | `PublicKey` |
| `derived_public_key` | `path: String, predecessor: Option<AccountId>, domain_id: Option<DomainId>` | `PublicKey` |
| `latest_key_version` | `signature_scheme: Option<Curve>` | `u32` |
| `proposed_updates` | — | `ProposedUpdates` |
| `get_pending_request` | `request: &SignatureRequest` | `Option<YieldIndex>` |
| `get_pending_ckd_request` | `request: &CKDRequest` | `Option<YieldIndex>` |
| `get_pending_verify_foreign_tx_request` | `request: &VerifyForeignTransactionRequest` | `Option<YieldIndex>` |
| `get_attestation` | `tls_public_key: Ed25519PublicKey` | `Option<VerifiedAttestation>` |
| `get_tee_accounts` | — | `Vec<NodeId>` |
| `get_supported_foreign_chains` | — | `SupportedForeignChains` |
| `get_foreign_chain_support_by_node` | — | `ForeignChainSupportByNode` |
| `allowed_foreign_chain_providers` | — | `BTreeMap<ForeignChain, ChainEntry>` — borsh-decoded (the one `#[result_serializer(borsh)]` view) |
| `allowed_docker_image_hashes` | — | `Vec<AllowedMpcDockerImageHash>` |
| `allowed_launcher_compose_hashes` | — | `Vec<LauncherDockerComposeHash>` |
| `migration_info` | — | `BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>` |
| `pending_signature_queue_len`¹ | `request: SignatureRequest` | `u32` |
| `pending_ckd_queue_len`¹ | `request: CKDRequest` | `u32` |

¹ Test-only contract surface (`contract/src/sandbox_test_methods.rs`) —
included for the sandbox tests that call them; gated the same way there.

Contract methods returning `Result<T, Error>` surface as `T` through the
handle (a contract-side `Err` fails the view/call and lands in `CallError`).
## Call-site deviation audit

Every deviation from "MAX_GAS, zero deposit, JSON args, wait for finality"
found across the current call sites, and where it lands in the design:

| Deviation | Where today | Resolution |
|---|---|---|
| `sign` gas: 15 Tgas vs `.max_gas()` (=300) vs 300 hardcoded | `e2e/cluster.rs:34` vs sandbox tests vs `devnet/mpc.rs` | one constant `SIGN_GAS = 15` (e2e proves it suffices; the others were convenience) |
| `MAX_GAS = 1000 Tgas` — above the 300 Tgas protocol cap on prepaid gas | `e2e/blockchain.rs:8` | the backing sandbox runs default protocol config and these calls pass, so near-kit must be capping prepaid gas — confirm in its source at PR 3; handle uses 300 either way |
| CKD gas split by key variant (`AppPublicKeyPV` runs a pairing check) | `e2e/cluster.rs:802` | `match` inside `request_app_private_key` — data-driven, stays in the method body |
| `propose_update` deposit: 17 NEAR const vs CLI flag vs 40 NEAR vs 17 NEAR again as `CURRENT_CONTRACT_DEPLOY_DEPOSIT` (misnamed: every use is a `propose_update` deposit, not a deployment) | `e2e/cluster.rs:47`, `devnet/mpc.rs:510`, `sandbox/upgrade_from_current_contract.rs:66`, `sandbox/common.rs:354` | caller-supplied trailing parameter |
| 1-yocto deposits on `sign`/CKD/verify-foreign requests | e2e `SIGN_DEPOSIT`, sandbox `.deposit(1)` sites | `SIGN_DEPOSIT` constant in the handle |
| tee-context's own gas constants (`SUBMIT_ATTESTATION_GAS`/`VERIFY_TEE_GAS`, both 300) | `tee-context/lib.rs:28` | collapse into the handle's `MAX_GAS` |
| wait semantics: `send()` vs `transact`/`transact_async` vs `TxExecutionStatus::Final`/`Included` | e2e / sandbox / devnet (`loadtest.rs` uses `Included`) | backend concern, never the handle's: `SandboxAsyncCaller` is its own impl; `DevnetCaller` takes the wait level at construction |
| devnet `verbose` printing flag | `devnet/mpc.rs` call sites | `DevnetCaller` constructor state |
| per-call signer parameter | `tee-context/lib.rs:121` | absorbed at `TeeContext` construction (see the tee-context section) |
| node: flat `MAX_GAS` for all transaction kinds | `node/indexer/types.rs:107` (TODO(#166)) | unchanged — handle uses the same constant; #166 stays open in the gas-constants module |
| deliberately malformed args / wrong deposits in error-path tests | scattered sandbox tests | stay on the raw escape hatch, by design |

No deviation requires a handle-level knob: every one is either a constant, a
data-driven `match`, a method parameter, backend construction state, or
explicitly out of scope.

## Rollout: PR sequence

The handle is *not* built in one isolated PR — it grows with its consumers.
Each migration PR adds the handle methods it needs, plus their
`RecordingCaller` encoding tests, so every method lands together with its
first real call site.

| # | PR | Contents |
|---|---|---|
| 1 | argument structs | new `*Args` in `call_args.rs`; promote devnet's `VoteUpdateArgs` and sandbox's `SignResponseArgs`; move `ProposeUpdateArgs` out of the contract crate (retiring the devnet/e2e duplicates); add the seven missing `Deserialize` derives. Additive only; independent of 2 |
| 2 | transport + chain-gateway + tee-context | the vertical slice proving the architecture: rename `mpc-call-args` → `near-contract-transport`, add `CallContract`/`ViewContract`/`ViewArgs`/`CallError` + `&T` blankets; `AccountCaller` + `ChainGateway: ViewContract`; implement the traits for chain-gateway's test contract and `MockChainState` — the second-contract pattern, and PR 2's `ViewContract` exercise (tee-context's reads are subscriptions, out of scope); redesign `TeeContext` to hold the handle; birth of the `client` module with the first MPC methods (`submit_participant_info`, `verify_tee`); traits + `CallError` behind a default-on `traits` feature — `chain-gateway-test-contract` builds this crate into wasm and keeps payload-only |
| 3 | e2e | `NearKitCaller` (rename from `ClientHandle`) + both impls; handle grows the e2e methods, including the first MPC *view* methods (`state`, `migration_info`, …); migrate `cluster.rs`/tests; shrink `DeployedContract` to deployment + `code_hash`; confirm near-kit caps prepaid gas and has `args_raw` on the call builder (open items in the deviation audit) |
| 4 | sandbox | `SandboxCaller`/`SandboxAsyncCaller` impls; handle grows the respond/key-event methods; migrate tests; delete local `SignResponseArgs` |
| 5 | devnet | `DevnetCaller` impls; handle grows `propose_update` (with its deposit parameter) etc.; migrate `mpc.rs`; `read_contract_state` → view methods |
| 6 | node: queue currency | `TransactionSender` trait deleted in favor of `CallContract`; queue carries `FunctionCallArgs` + the signing account (replaces `signer_for`); `observe_tx_result` re-keyed on `method_name`; expiry baseline view-read by the processor at submit time; interim `tx_signer` threads the message's gas/deposit; fake indexer deserializing round-trip; `IndexerViewClient: ViewContract` (the observe re-key rewrites those call sites anyway); handle grows the node-only methods (`vote_abort_key_event_instance`, `conclude_node_migration`); settle `.awaiting()` naming |
| 7 | node: transport | processor's sign-and-submit replaced by `AccountCaller`; make `FetchLatestFinalBlockInfo`/`SubmitSignedTransaction` `pub` (the `SubmitFunctionCall` blanket is sealed while they are `pub(crate)`); settle the debug-page metadata story; delete `indexer/tx_signer.rs` (nonce semantics match the gateway signer's) |

Ordering: 1 ∥ 2, then 3 → 4 → 5 (sequential by default — they append to the
same impl blocks; parallel work just means trivial merge conflicts), 6 after
4 (needs the respond/vote methods), 7 after 2 + 6. Docs (e2e README, this
document's status line) are updated in whichever PR makes them stale.

## Naming decisions

| Name | Decision | Rationale |
|---|---|---|
| `CallContract` / `ViewContract` | **keep** | the traits encode transport mechanism (transaction vs RPC query), which is exactly NEAR's call/view split — not read/write semantics (a view method *can* be invoked in a transaction); every impl body speaks `.view()`/`view_function` |
| `MpcContractHandle<C>` | **keep, single type** | writer/reader semantics already come from capability-gating (`MpcContractHandle<TransactionProcessorHandle>` *is* a writer — no view methods exist on it); a `Writer`/`Reader` type split would force tests that interleave calls and views to bind two objects per contract |
| `FunctionCallArgs` / `ViewArgs` | **keep** | `FunctionCallArgs` mirrors NEAR's `FunctionCallAction` field-for-field; the family stays NEAR-native alongside the trait names |
| `AccountCaller<T>` (was `GatewayCaller`) | **decided** | "one caller = one on-chain identity"; the `*Caller` suffix means "implements `CallContract`" (convention: `SandboxCaller`, `DevnetCaller`, `NearKitCaller`) |
| `near-contract-transport` (crate, was `mpc-call-args`) | **decided**, one of the first PRs | hosts both payload structs and both SPI traits — all generic NEAR vocabulary, nothing MPC-specific. Not "client": clients are built *on* the transport. Traits + `CallError` sit behind a default-on `traits` feature: `chain-gateway-test-contract` builds this crate into wasm and needs the payload structs only |
| `NearKitCaller` (was `ClientHandle`, e2e) | **decided**, e2e PR | the one `CallContract` implementor that wasn't named a caller; doubly confusing next to the `client` module |
| `client` (feature + module, interface crate) | **decided: `client`** | gates the handle and its transport dependency out of the contract's wasm build — the contract depends on this crate for DTOs, so the wasm build compiles it with the feature off (`serde_json`/`thiserror` the contract already depends on directly; the gate is about the transport crate and client-only code); the module's content is a client for this contract |
| `.awaiting()` | open | alternative: `.with_status()` — settle in the node PR |


