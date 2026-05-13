//! End-to-end test that a single `respond` drains a fully-saturated fan-out queue.
//!
//! Items are declared in order of occurrence: every function (or type) is defined
//! before any helper it transitively depends on.

#![allow(non_snake_case)] // Tests use the `<sut>__should_<assertion>` form mandated by CLAUDE.md.

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::parallel_contract,
        shared_key_utils::SharedSecretKey,
        sign_utils::{
            create_response_ckd, create_response_ed25519, create_response_secp256k1,
            submit_ckd_response, submit_signature_response, CKDResponseArgs, SignResponseArgs,
        },
    },
};
use elliptic_curve::Group;
use mpc_contract::MAX_PENDING_REQUEST_FAN_OUT;
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, CKDAppPublicKey, CKDRequestArgs, Protocol, SignRequestArgs,
};
use near_workspaces::operations::TransactionStatus;
use serde::Serialize;
use std::time::Duration;
use threshold_signatures::blstrs;

/// Sign-flavored schemes attach 15 TGas per cross-contract `sign()` call. Ten calls
/// (≈150 TGas) fit comfortably under the per-receipt 300 TGas ceiling.
const SIGN_CALLS_PER_BATCH: u64 = 10;

/// CKD attaches 30 TGas per cross-contract `request_app_private_key()` call. Five calls
/// (≈150 TGas) leave equivalent headroom.
const CKD_CALLS_PER_BATCH: u64 = 5;

/// Blocks to fast-forward between submitting successive batch transactions so each
/// batch's parent receipt has time to land before the next one is sent.
const NUM_BLOCKS_BETWEEN_REQUESTS: u64 = 2;

/// Saturates the fan-out queue to its declared cap and asserts a single `respond` drains
/// every queued yield. A passing run is the empirical proof that `respond` can drain a
/// fully-saturated queue inside its 300 TGas budget — i.e. that
/// [`MAX_PENDING_REQUEST_FAN_OUT`] is reachable on a real runtime. The panic-on-cap path
/// is separately covered by the unit test
/// `add_signature_request__should_panic_when_pending_queue_is_full`.
#[tokio::test]
async fn respond__should_drain_saturated_fan_out_queue() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_sandbox_test_methods()
        .build()
        .await;
    let attested = &mpc_signer_accounts[0];
    let parallel = worker.dev_deploy(parallel_contract()).await?;
    let parallel_id: AccountId = parallel.id().clone();

    for key in &keys {
        let domain_id = key.domain_config.id;
        // Per-scheme disambiguator threaded through every protocol: into the message hash
        // for sign paths and into the CKD derivation path. Keeps request keys from
        // colliding when multiple domains are exercised in the same fixture.
        let scheme_tag = format!("fanout-{:?}-{}", key.domain_config.protocol, domain_id.0);

        match (&key.domain_config.protocol, &key.domain_secret_key) {
            (Protocol::CaitSith | Protocol::DamgardEtAl, SharedSecretKey::Secp256k1(sk)) => {
                let (payload, request, response) =
                    create_response_secp256k1(domain_id, &parallel_id, &scheme_tag, "", sk);
                let response_args = SignResponseArgs { request, response };
                let sign_args = SignRequestArgs {
                    payload,
                    path: String::new(),
                    domain_id,
                };
                run_sign_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    attested,
                    &response_args,
                    &sign_args,
                )
                .await?;
            }
            (Protocol::Frost, SharedSecretKey::Ed25519(sk)) => {
                let (payload, request, response) =
                    create_response_ed25519(domain_id, &parallel_id, &scheme_tag, "", sk);
                let response_args = SignResponseArgs { request, response };
                let sign_args = SignRequestArgs {
                    payload,
                    path: String::new(),
                    domain_id,
                };
                run_sign_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    attested,
                    &response_args,
                    &sign_args,
                )
                .await?;
            }
            (Protocol::ConfidentialKeyDerivation, SharedSecretKey::Bls12381(sk)) => {
                let app_pk = make_app_public_key(domain_id.0 + 1);
                let (request, response) =
                    create_response_ckd(&parallel_id, &app_pk, &domain_id, sk, &scheme_tag);
                let response_args = CKDResponseArgs { request, response };
                let ckd_args = CKDRequestArgs {
                    derivation_path: scheme_tag,
                    domain_id,
                    app_public_key: CKDAppPublicKey::AppPublicKey(app_pk),
                };
                run_ckd_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    attested,
                    &response_args,
                    &ckd_args,
                )
                .await?;
            }
            (protocol, _) => panic!("unexpected protocol/key pairing: {protocol:?}"),
        }
    }

    Ok(())
}

/// Drives the sign-flavored fan-out exercise: stack `DUPLICATE_REQUEST_FAN_OUT`
/// identical `sign()` calls via the parallel contract, wait for the queue to reach that
/// length, submit the single matching `respond()`, and assert every batch transaction
/// observed all its sign promises resolve.
async fn run_sign_fan_out(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    attested: &near_workspaces::Account,
    response_args: &SignResponseArgs,
    sign_args: &SignRequestArgs,
) -> anyhow::Result<()> {
    let statuses = submit_duplicate_sign_batches(
        worker,
        contract,
        parallel,
        sign_args,
        u64::from(MAX_PENDING_REQUEST_FAN_OUT),
    )
    .await?;
    wait_for_pending_signature_queue(
        contract,
        &response_args.request,
        u32::from(MAX_PENDING_REQUEST_FAN_OUT),
    )
    .await?;
    submit_signature_response(response_args, contract, attested).await?;
    await_batch_statuses(statuses).await?;
    Ok(())
}

/// Splits a total fan-out of `total_calls` into batch transactions, each calling the
/// parallel contract's `make_duplicate_sign_calls` to enqueue up to `SIGN_CALLS_PER_BATCH`
/// duplicates of `sign_args`. Batching is required because each child `sign()` call
/// reserves ~15 TGas of the parent receipt's 300 TGas budget.
async fn submit_duplicate_sign_batches(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    sign_args: &SignRequestArgs,
    total_calls: u64,
) -> anyhow::Result<Vec<(TransactionStatus, u64)>> {
    let mut statuses = Vec::new();
    let mut remaining = total_calls;
    while remaining > 0 {
        let k = remaining.min(SIGN_CALLS_PER_BATCH);
        let status = parallel
            .call("make_duplicate_sign_calls")
            .args_json(MakeDuplicateSignCallsArgs {
                target_contract: contract.id(),
                request: sign_args,
                count: k,
            })
            .max_gas()
            .transact_async()
            .await?;
        statuses.push((status, k));
        remaining -= k;
        worker.fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS).await?;
    }
    Ok(statuses)
}

/// Wire shape for `test_parallel_contract::make_duplicate_sign_calls`. The contract
/// just fans the supplied `request` out `count` times; the test owns the payload.
#[derive(Serialize)]
struct MakeDuplicateSignCallsArgs<'a> {
    target_contract: &'a AccountId,
    request: &'a SignRequestArgs,
    count: u64,
}

/// Polls the contract's `pending_signature_queue_len` view until the queue holds
/// `expected_len` yields. Calling `respond` before all submitted batches have created
/// their yields would leave the late arrivals stranded, so this turns an otherwise
/// timing-dependent invariant into an explicit assertion. Requires the contract to be
/// built with `--features sandbox-test-methods` (see
/// [`crate::sandbox::common::SandboxTestSetupBuilder::with_sandbox_test_methods`]).
async fn wait_for_pending_signature_queue(
    contract: &near_workspaces::Contract,
    request: &mpc_contract::primitives::signature::SignatureRequest,
    expected_len: u32,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let len: u32 = contract
            .view("pending_signature_queue_len")
            .args_json(serde_json::json!({ "request": request }))
            .await?
            .json()?;
        if len >= expected_len {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for signature queue to reach {expected_len} (saw {len})"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Awaits every batch tx and asserts its `handle_results` callback observed all `k`
/// promises succeed. This is the per-scheme proof that the response fanned out to
/// every queued yield — if a single yield were dropped, the corresponding sign()
/// promise would never resolve and the batch tx would never complete.
async fn await_batch_statuses(statuses: Vec<(TransactionStatus, u64)>) -> anyhow::Result<()> {
    for (status, expected_completed) in statuses {
        let completed: u64 = status.await?.into_result()?.json()?;
        assert_eq!(
            completed, expected_completed,
            "expected handle_results to observe {expected_completed} completed calls"
        );
    }
    Ok(())
}

/// CKD counterpart to [`run_sign_fan_out`].
async fn run_ckd_fan_out(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    attested: &near_workspaces::Account,
    response_args: &CKDResponseArgs,
    ckd_args: &CKDRequestArgs,
) -> anyhow::Result<()> {
    let statuses = submit_duplicate_ckd_batches(
        worker,
        contract,
        parallel,
        ckd_args,
        u64::from(MAX_PENDING_REQUEST_FAN_OUT),
    )
    .await?;
    wait_for_pending_ckd_queue(
        contract,
        &response_args.request,
        u32::from(MAX_PENDING_REQUEST_FAN_OUT),
    )
    .await?;
    submit_ckd_response(response_args, contract, attested).await?;
    await_batch_statuses(statuses).await?;
    Ok(())
}

/// CKD counterpart to [`submit_duplicate_sign_batches`]; the lower per-batch ceiling
/// reflects CKD's ~30 TGas per child call.
async fn submit_duplicate_ckd_batches(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    ckd_args: &CKDRequestArgs,
    total_calls: u64,
) -> anyhow::Result<Vec<(TransactionStatus, u64)>> {
    let mut statuses = Vec::new();
    let mut remaining = total_calls;
    while remaining > 0 {
        let k = remaining.min(CKD_CALLS_PER_BATCH);
        let status = parallel
            .call("make_duplicate_ckd_calls")
            .args_json(MakeDuplicateCkdCallsArgs {
                target_contract: contract.id(),
                request: ckd_args,
                count: k,
            })
            .max_gas()
            .transact_async()
            .await?;
        statuses.push((status, k));
        remaining -= k;
        worker.fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS).await?;
    }
    Ok(statuses)
}

/// CKD counterpart to [`MakeDuplicateSignCallsArgs`].
#[derive(Serialize)]
struct MakeDuplicateCkdCallsArgs<'a> {
    target_contract: &'a AccountId,
    request: &'a CKDRequestArgs,
    count: u64,
}

/// CKD counterpart to [`wait_for_pending_signature_queue`]; same rationale.
async fn wait_for_pending_ckd_queue(
    contract: &near_workspaces::Contract,
    request: &mpc_contract::primitives::ckd::CKDRequest,
    expected_len: u32,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let len: u32 = contract
            .view("pending_ckd_queue_len")
            .args_json(serde_json::json!({ "request": request }))
            .await?
            .json()?;
        if len >= expected_len {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for CKD queue to reach {expected_len} (saw {len})");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Generates a Bls12-381 G1 app public key from an arbitrary scalar so the test can
/// produce a `CKDRequestArgs` to fan out. The value is opaque — what matters is that
/// the test holds it and can feed the matching `request` into `create_response_ckd`.
///
/// Callers should pass a non-zero `seed` (e.g. `domain_id.0 + 1`) so the scalar avoids
/// mapping to the curve's identity element.
fn make_app_public_key(seed: u64) -> Bls12381G1PublicKey {
    let scalar = blstrs::Scalar::from(seed);
    let point = blstrs::G1Projective::generator() * scalar;
    Bls12381G1PublicKey::from(&point)
}
