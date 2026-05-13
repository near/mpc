use crate::sandbox::{
    common::{candidates, create_account_given_id, init, SandboxTestSetup},
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::parallel_contract,
        shared_key_utils::SharedSecretKey,
        sign_utils::{
            create_response_ckd, create_response_ed25519, create_response_secp256k1,
            gen_secp_256k1_sign_test, submit_ckd_response, submit_ckd_response_measure_gas,
            submit_signature_response, verify_timeout, CKDRequestTest, CKDResponseArgs,
            DomainResponseTest, SignResponseArgs,
        },
    },
};
use anyhow::Context;
use elliptic_curve::Group;
use mpc_contract::{
    errors,
    primitives::{
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    Bls12381G1PublicKey, CKDAppPublicKey, CKDRequestArgs, Protocol, SignRequestArgs,
};
use near_workspaces::operations::TransactionStatus;
use near_workspaces::types::NearToken;
use rand::SeedableRng;
use serde::Serialize;
use std::time::Duration;
use threshold_signatures::blstrs;

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;
const NUM_BLOCKS_BETWEEN_REQUESTS: u64 = 2;

#[tokio::test]
async fn test_contract_request_all_schemes() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let attested_account = &mpc_signer_accounts[0];

    let account_ids: [AccountId; 5] = [
        "alice".parse().unwrap(),
        "this_is_an_app".parse().unwrap(),
        "another".parse().unwrap(),
        "a_better_one".parse().unwrap(),
        "a_fake_one".parse().unwrap(),
    ];

    for predecessor_id in account_ids {
        let alice = create_account_given_id(&worker, predecessor_id)
            .await
            .unwrap()
            .unwrap();
        let predecessor_id = alice.id();
        for key in &keys {
            {
                let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
                req.run(&alice, &contract, attested_account)
                    .await
                    .with_context(|| format!("{:?}", req))
                    .unwrap();
            }
        }
    }
    Ok(())
}

/// Total number of identical sign / CKD requests stacked per scheme before a single
/// response is submitted. Matches `MAX_PENDING_REQUEST_FAN_OUT` so a passing run is the
/// empirical proof that `respond()` can drain a fully-saturated queue inside its 300 TGas
/// budget — i.e. that the cap chosen in the contract is actually reachable on a real
/// runtime. The panic-on-cap path is separately covered by the unit test
/// `add_signature_request__should_panic_when_pending_queue_is_full`.
const DUPLICATE_REQUEST_FAN_OUT: u64 = 128;

/// Sign-flavored schemes attach 15 TGas per cross-contract `sign()` call. Ten calls
/// (≈150 TGas) fit comfortably under the per-receipt 300 TGas ceiling.
const SIGN_CALLS_PER_BATCH: u64 = 10;

/// CKD attaches 30 TGas per cross-contract `request_app_private_key()` call. Five calls
/// (≈150 TGas) leave equivalent headroom.
const CKD_CALLS_PER_BATCH: u64 = 5;

/// Wire shape for `test_parallel_contract::make_duplicate_sign_calls`. The contract just
/// fans the supplied `request` out `count` times; the test owns the payload.
#[derive(Serialize)]
struct MakeDuplicateSignCallsArgs<'a> {
    target_contract: &'a AccountId,
    request: &'a SignRequestArgs,
    count: u64,
}

/// CKD counterpart to [`MakeDuplicateSignCallsArgs`].
#[derive(Serialize)]
struct MakeDuplicateCkdCallsArgs<'a> {
    target_contract: &'a AccountId,
    request: &'a CKDRequestArgs,
    count: u64,
}

/// Generates a Bls12-381 G1 app public key from an arbitrary scalar so the test can
/// produce a `CKDRequestArgs` to fan out. The value is opaque — what matters is that
/// the test holds it and can feed the matching `request` into `create_response_ckd`.
fn make_app_public_key(seed: u64) -> Bls12381G1PublicKey {
    let scalar = blstrs::Scalar::from(seed);
    let point = blstrs::G1Projective::generator() * scalar;
    Bls12381G1PublicKey::from(&point)
}

#[tokio::test]
async fn test_contract_request_duplicate_requests_fan_out() -> anyhow::Result<()> {
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
        // The payload string is per-scheme so the test can run with multiple domains
        // in one fixture without colliding request keys; the actual bytes are arbitrary.
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
                    create_response_ckd(&parallel_id, &app_pk, &domain_id, sk, "");
                let response_args = CKDResponseArgs { request, response };
                let ckd_args = CKDRequestArgs {
                    derivation_path: String::new(),
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

/// Drives the sign-flavored fan-out exercise: stack `DUPLICATE_REQUEST_FAN_OUT` identical
/// `sign()` calls via the parallel contract, wait for the queue to reach that length,
/// submit the single matching `respond()`, and assert every batch transaction observed
/// all its sign promises resolve.
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
        DUPLICATE_REQUEST_FAN_OUT,
    )
    .await?;
    wait_for_pending_signature_queue(
        contract,
        &response_args.request,
        DUPLICATE_REQUEST_FAN_OUT as u32,
    )
    .await?;
    submit_signature_response(response_args, contract, attested).await?;
    await_batch_statuses(statuses).await?;
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
        DUPLICATE_REQUEST_FAN_OUT,
    )
    .await?;
    wait_for_pending_ckd_queue(
        contract,
        &response_args.request,
        DUPLICATE_REQUEST_FAN_OUT as u32,
    )
    .await?;
    submit_ckd_response(response_args, contract, attested).await?;
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

/// Polls the contract's `pending_signature_queue_len` view until the queue holds
/// `expected_len` yields. Calling `respond` before all submitted batches have created
/// their yields would leave the late arrivals stranded, so this turns an otherwise
/// timing-dependent invariant into an explicit assertion. Requires the contract to be
/// built with `--features sandbox-test-methods` (see
/// [`SandboxTestSetupBuilder::with_sandbox_test_methods`]).
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

/// Awaits every batch tx and asserts its `handle_results` callback observed all `k`
/// promises succeed. This is the per-scheme proof that the response fanned out to
/// every queued yield — if a single yield were dropped, the corresponding sign() promise
/// would never resolve and the batch tx would never complete.
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

#[tokio::test]
async fn test_contract_request_timeout_all_schemes() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    for key in &keys {
        let alice = worker.dev_create_account().await.unwrap();
        let predecessor_id = alice.id();
        // Check that a sign with no response from MPC network properly errors out:
        let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
        let status = req
            .submit_request_ensure_included(&alice, &contract)
            .await?;
        worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
        verify_timeout(status).await.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_success_refund_all_schemes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let attested_account = &mpc_signer_accounts[0];

    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let mut contract_balance = contract.view_account().await?.balance;

    for key in &keys {
        let req = DomainResponseTest::new(&mut rng, key, alice.id());
        req.run(&alice, &contract, attested_account).await?;

        let new_balance = alice.view_account().await?.balance;
        let new_contract_balance = contract.view_account().await?.balance;
        assert!(
            balance.as_millinear() - new_balance.as_millinear() < 10,
            "refund should happen"
        );
        assert!(
            contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
            "contract balance should not decrease after refunding deposit"
        );
        // probably not necessary, but better safe than race condition
        worker
            .fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS)
            .await
            .unwrap();

        contract_balance = new_contract_balance
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_fail_refund_all_schemes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let mut rng = rand::rngs::StdRng::from_seed([2u8; 32]);
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let mut contract_balance = contract.view_account().await?.balance;

    for key in &keys {
        let req = DomainResponseTest::new(&mut rng, key, alice.id());
        let status = req
            .submit_request_ensure_included(&alice, &contract)
            .await?;
        worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
        // we do not respond, sign will fail due to timeout
        verify_timeout(status).await?;

        let new_balance = alice.view_account().await?.balance;
        let new_contract_balance = contract.view_account().await?.balance;
        assert!(balance >= new_balance, "user balance should not increase");
        assert!(
            balance.as_millinear() - new_balance.as_millinear() < 10,
            "refund should happen"
        );
        assert!(
            contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
            "contract balance should not decrease after refunding deposit"
        );
        contract_balance = new_contract_balance;
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_request_deposits_all_schemes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        keys,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let attested_account = &mpc_signer_accounts[0];
    let predecessor_id = contract.id();

    for key in &keys {
        // Try to sign with no deposit, should fail.
        let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
        let status = match &req {
            DomainResponseTest::Sign(req) => {
                let status = contract
                    .call(method_names::SIGN)
                    .args_json(req.request_json_args())
                    .max_gas()
                    .transact_async()
                    .await?;
                dbg!(&status);
                status
            }
            DomainResponseTest::CKD(req) => {
                let status = contract
                    .call(method_names::REQUEST_APP_PRIVATE_KEY)
                    .args_json(req.request_json_args())
                    .max_gas()
                    .transact_async()
                    .await?;
                dbg!(&status);
                status
            }
        };

        // Responding to the request should fail with missing request because the deposit is too low,
        // so the request should have never made it into the request queue and subsequently the MPC network.
        let respond = req.submit_response(&contract, attested_account).await;
        dbg!(&respond);
        assert!(respond
            .unwrap_err()
            .to_string()
            .contains(&errors::InvalidParameters::RequestNotFound.to_string()));

        let execution = status.await?;
        dbg!(&execution);
        assert!(execution
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("Attached deposit is lower than required"));
    }
    Ok(())
}

#[tokio::test]
async fn test_sign_v1_compatibility() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        keys,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let key = &keys[0];
    const LEGACY_KEY_VERSION: u64 = 0; // this is the first cait-sith domain in the contract
    const NUM_MSGS: usize = 5;
    assert_eq!(key.domain_id().0, LEGACY_KEY_VERSION);
    let SharedSecretKey::Secp256k1(sk) = &key.domain_secret_key else {
        anyhow::bail!("expected secp256k1");
    };
    let attested_account = &mpc_signer_accounts[0];
    let predecessor_id = contract.id();

    for _ in 0..NUM_MSGS {
        let req = gen_secp_256k1_sign_test(&mut rng, key.domain_id(), predecessor_id, sk);

        let status = contract
            .call(method_names::SIGN)
            .args_json(serde_json::json!({
                "request": {
                    "payload": req.payload().as_ecdsa().unwrap(),
                    "path": req.path(),
                    "key_version": LEGACY_KEY_VERSION,
                },
            }))
            .deposit(NearToken::from_yoctonear(1))
            .max_gas()
            .transact_async()
            .await?;
        dbg!(&status);

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Call `respond` as if we are the MPC network itself.
        submit_signature_response(&req.response, &contract, attested_account).await?;
        req.verify_execution_outcome(status).await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_initialization() -> anyhow::Result<()> {
    let (_, contract) = init().await;

    // Empty candidates should fail.
    let participants = Participants::new();
    let threshold = Threshold::new(0);
    let proposed_parameters = ThresholdParameters::new_unvalidated(participants, threshold);
    let result = contract
        .call(method_names::INIT)
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with zero candidates or less than threshold candidates should fail"
    );

    let proposed_parameters =
        ThresholdParameters::new(candidates(None), Threshold::new(3)).unwrap();
    let result = contract
        .call(method_names::INIT)
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
        }))
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "initializing with valid candidates should succeed"
    );

    // Reinitializing after the first successful initialization should fail.
    let result = contract
        .call(method_names::INIT)
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
            "config": "null",
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with valid candidates again should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_ckd_pv_request() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([3u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::ConfidentialKeyDerivation])
        .build()
        .await;
    let attested_account = &mpc_signer_accounts[0];

    let bls_key = &keys[0];
    let SharedSecretKey::Bls12381(sk) = &bls_key.domain_secret_key else {
        anyhow::bail!("expected bls12381 key");
    };

    let alice = worker.dev_create_account().await?;
    let req = CKDRequestTest::new_pv(&mut rng, bls_key.domain_id(), alice.id(), sk);
    let test = DomainResponseTest::CKD(req);
    test.run(&alice, &contract, attested_account)
        .await
        .with_context(|| format!("{:?}", test))?;

    Ok(())
}

/// Gas regression test for CKD request and respond operations.
///
/// Measures gas consumed by `request_app_private_key` and `respond_ckd` for
/// both legacy and PV variants, and asserts they stay within expected bounds.
/// The PV path runs on-chain BLS12-381 pairing checks which are significantly
/// more expensive.
#[tokio::test]
async fn test_ckd_gas_regression() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([6u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::ConfidentialKeyDerivation])
        .build()
        .await;
    let attested_account = &mpc_signer_accounts[0];

    let bls_key = &keys[0];
    let SharedSecretKey::Bls12381(sk) = &bls_key.domain_secret_key else {
        anyhow::bail!("expected bls12381 key");
    };

    // --- Legacy CKD ---
    let alice = worker.dev_create_account().await?;
    let legacy = CKDRequestTest::new(&mut rng, bls_key.domain_id(), alice.id(), sk);
    let legacy_test = DomainResponseTest::CKD(legacy);
    let legacy_request_status = legacy_test
        .submit_request_ensure_included(&alice, &contract)
        .await?;
    let legacy_respond_gas = match &legacy_test {
        DomainResponseTest::CKD(inner) => {
            submit_ckd_response_measure_gas(&inner.response, &contract, attested_account).await?
        }
        _ => unreachable!(),
    };
    let legacy_request_execution = legacy_request_status.await?;
    let legacy_request_gas = legacy_request_execution.total_gas_burnt;
    legacy_request_execution.into_result()?;

    // --- PV CKD ---
    let bob = worker.dev_create_account().await?;
    let pv = CKDRequestTest::new_pv(&mut rng, bls_key.domain_id(), bob.id(), sk);
    let pv_test = DomainResponseTest::CKD(pv);
    let pv_request_status = pv_test
        .submit_request_ensure_included(&bob, &contract)
        .await?;
    let pv_respond_gas = match &pv_test {
        DomainResponseTest::CKD(inner) => {
            submit_ckd_response_measure_gas(&inner.response, &contract, attested_account).await?
        }
        _ => unreachable!(),
    };
    let pv_request_execution = pv_request_status.await?;
    let pv_request_gas = pv_request_execution.total_gas_burnt;
    pv_request_execution.into_result()?;

    println!(
        "  CKD request (legacy): {} TGas",
        legacy_request_gas.as_tgas()
    );
    println!(
        "  CKD respond (legacy): {} TGas",
        legacy_respond_gas.as_tgas()
    );
    println!("  CKD request (PV):     {} TGas", pv_request_gas.as_tgas());
    println!("  CKD respond (PV):     {} TGas", pv_respond_gas.as_tgas());

    // Gas thresholds (in TGas) with ~25% buffer over measured values.
    // PV adds BLS12-381 pairing checks on both request and respond.
    const MAX_LEGACY_REQUEST_TGAS: u64 = 10;
    const MAX_LEGACY_RESPOND_TGAS: u64 = 7;
    const MAX_PV_REQUEST_TGAS: u64 = 72;
    const MAX_PV_RESPOND_TGAS: u64 = 75;

    assert!(
        legacy_request_gas.as_tgas() <= MAX_LEGACY_REQUEST_TGAS,
        "GAS REGRESSION: legacy request_app_private_key used {} TGas (limit: {} TGas)",
        legacy_request_gas.as_tgas(),
        MAX_LEGACY_REQUEST_TGAS,
    );
    assert!(
        legacy_respond_gas.as_tgas() <= MAX_LEGACY_RESPOND_TGAS,
        "GAS REGRESSION: legacy respond_ckd used {} TGas (limit: {} TGas)",
        legacy_respond_gas.as_tgas(),
        MAX_LEGACY_RESPOND_TGAS,
    );
    assert!(
        pv_request_gas.as_tgas() <= MAX_PV_REQUEST_TGAS,
        "GAS REGRESSION: PV request_app_private_key used {} TGas (limit: {} TGas)",
        pv_request_gas.as_tgas(),
        MAX_PV_REQUEST_TGAS,
    );
    assert!(
        pv_respond_gas.as_tgas() <= MAX_PV_RESPOND_TGAS,
        "GAS REGRESSION: PV respond_ckd used {} TGas (limit: {} TGas)",
        pv_respond_gas.as_tgas(),
        MAX_PV_RESPOND_TGAS,
    );

    Ok(())
}
