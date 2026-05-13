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
use mpc_contract::{
    errors,
    primitives::{
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{Bls12381G1PublicKey, DomainId, Protocol};
use near_workspaces::operations::TransactionStatus;
use near_workspaces::types::NearToken;
use rand::SeedableRng;
use serde::Serialize;
use std::collections::BTreeMap;
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
/// response is submitted. The contract caps each fan-out queue at
/// `MAX_PENDING_REQUEST_FAN_OUT = 128`; the panic-on-cap path is already covered by the
/// unit test `add_signature_request__should_panic_when_pending_queue_is_full`. This test
/// exists to prove the fan-out path works end-to-end in a sandbox, not to stress the cap.
/// Dial down if a particular scheme runs into sandbox gas / promise limits.
const DUPLICATE_REQUEST_FAN_OUT: u64 = 10;

/// Sign-flavored schemes attach 15 TGas per cross-contract `sign()` call. Ten calls
/// (≈150 TGas) fit comfortably under the per-receipt 300 TGas ceiling.
const SIGN_CALLS_PER_BATCH: u64 = 10;

/// CKD attaches 30 TGas per cross-contract `request_app_private_key()` call. Five calls
/// (≈150 TGas) leave equivalent headroom.
const CKD_CALLS_PER_BATCH: u64 = 5;

/// Seed passed to `make_parallel_sign_calls`. The contract applies its own per-scheme
/// offset (e.g. `+1_000_000` for EdDSA) before hashing the payload; the test mirrors
/// the same offsets when computing the expected `SignatureRequest`.
const PARALLEL_CONTRACT_SEED: u64 = 42;

/// Mirrors the four `*_calls_by_domain` parameters of
/// `test_parallel_contract::make_parallel_sign_calls`. Exactly one of the four is
/// populated per call so each batch tx exercises one scheme.
#[derive(Serialize)]
struct ParallelSignArgs<'a> {
    target_contract: &'a AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecdsa_calls_by_domain: Option<BTreeMap<u64, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eddsa_calls_by_domain: Option<BTreeMap<u64, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ckd_calls_by_domain: Option<BTreeMap<u64, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    robust_ecdsa_calls_by_domain: Option<BTreeMap<u64, u64>>,
    seed: u64,
    unique_payloads: bool,
}

impl<'a> ParallelSignArgs<'a> {
    fn new(target_contract: &'a AccountId) -> Self {
        Self {
            target_contract,
            ecdsa_calls_by_domain: None,
            eddsa_calls_by_domain: None,
            ckd_calls_by_domain: None,
            robust_ecdsa_calls_by_domain: None,
            seed: PARALLEL_CONTRACT_SEED,
            unique_payloads: false,
        }
    }
}

#[derive(Clone, Copy)]
enum SignScheme {
    EcdsaCaitSith,
    EcdsaDamgardEtAl,
    Eddsa,
}

impl SignScheme {
    /// Per-scheme seed offset applied inside `make_parallel_sign_calls` before hashing
    /// the payload. The test reproduces these offsets to know which 32-byte payload
    /// the parallel contract is going to submit.
    fn seed_offset(self) -> u64 {
        match self {
            SignScheme::EcdsaCaitSith => 0,
            SignScheme::Eddsa => 1_000_000,
            SignScheme::EcdsaDamgardEtAl => 2_000_000,
        }
    }

    fn populate_args(self, args: &mut ParallelSignArgs<'_>, domain_id: DomainId, calls: u64) {
        let entry = BTreeMap::from([(domain_id.0, calls)]);
        match self {
            SignScheme::EcdsaCaitSith => args.ecdsa_calls_by_domain = Some(entry),
            SignScheme::Eddsa => args.eddsa_calls_by_domain = Some(entry),
            SignScheme::EcdsaDamgardEtAl => args.robust_ecdsa_calls_by_domain = Some(entry),
        }
    }
}

/// `test_parallel_contract::generate_app_public_key`, reproduced so the test can compute
/// the expected app public key without depending on the contract crate at the source
/// level.
fn parallel_app_public_key(seed: u64) -> Bls12381G1PublicKey {
    use elliptic_curve::Group;
    let x = blstrs::Scalar::from(seed);
    let big_x = blstrs::G1Projective::generator() * x;
    Bls12381G1PublicKey::from(&big_x)
}

/// Submits one batch transaction calling the parallel contract's
/// `make_parallel_sign_calls`. Returns the `TransactionStatus` so callers can await
/// final completion after the matching `respond` is submitted.
async fn submit_parallel_batch(
    parallel: &near_workspaces::Contract,
    args: &ParallelSignArgs<'_>,
) -> anyhow::Result<TransactionStatus> {
    let status = parallel
        .call("make_parallel_sign_calls")
        .args_json(args)
        .max_gas()
        .transact_async()
        .await?;
    Ok(status)
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
        .build()
        .await;
    let attested = &mpc_signer_accounts[0];
    let parallel = worker.dev_deploy(parallel_contract()).await?;
    let parallel_id: AccountId = parallel.id().clone();

    for key in &keys {
        let domain_id = key.domain_config.id;

        match (&key.domain_config.protocol, &key.domain_secret_key) {
            (Protocol::CaitSith, SharedSecretKey::Secp256k1(sk)) => {
                exercise_sign_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    &parallel_id,
                    attested,
                    domain_id,
                    SignScheme::EcdsaCaitSith,
                    sk,
                )
                .await?;
            }
            (Protocol::DamgardEtAl, SharedSecretKey::Secp256k1(sk)) => {
                exercise_sign_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    &parallel_id,
                    attested,
                    domain_id,
                    SignScheme::EcdsaDamgardEtAl,
                    sk,
                )
                .await?;
            }
            (Protocol::Frost, SharedSecretKey::Ed25519(sk)) => {
                exercise_eddsa_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    &parallel_id,
                    attested,
                    domain_id,
                    sk,
                )
                .await?;
            }
            (Protocol::ConfidentialKeyDerivation, SharedSecretKey::Bls12381(sk)) => {
                exercise_ckd_fan_out(
                    &worker,
                    &contract,
                    &parallel,
                    &parallel_id,
                    attested,
                    domain_id,
                    sk,
                )
                .await?;
            }
            (protocol, _) => panic!("unexpected protocol/key pairing: {protocol:?}"),
        }
    }

    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper; threading context through a struct would obscure call sites"
)]
async fn exercise_sign_fan_out(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    parallel_id: &AccountId,
    attested: &near_workspaces::Account,
    domain_id: DomainId,
    scheme: SignScheme,
    sk: &threshold_signatures::ecdsa::KeygenOutput,
) -> anyhow::Result<()> {
    let scheme_seed = PARALLEL_CONTRACT_SEED + scheme.seed_offset();
    let msg = format!("{scheme_seed}");
    let (_, request, response) = create_response_secp256k1(domain_id, parallel_id, &msg, "", sk);
    let response_args = SignResponseArgs {
        request: request.clone(),
        response,
    };

    let statuses = submit_sign_batches(
        worker,
        contract,
        parallel,
        scheme,
        domain_id,
        DUPLICATE_REQUEST_FAN_OUT,
    )
    .await?;
    wait_for_pending_signature_queue(contract, &request).await?;
    settle_yields(worker).await?;
    submit_signature_response(&response_args, contract, attested).await?;
    await_batch_statuses(statuses).await?;
    Ok(())
}

async fn exercise_eddsa_fan_out(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    parallel_id: &AccountId,
    attested: &near_workspaces::Account,
    domain_id: DomainId,
    sk: &threshold_signatures::frost::eddsa::KeygenOutput,
) -> anyhow::Result<()> {
    let scheme = SignScheme::Eddsa;
    let scheme_seed = PARALLEL_CONTRACT_SEED + scheme.seed_offset();
    let msg = format!("{scheme_seed}");
    let (_, request, response) = create_response_ed25519(domain_id, parallel_id, &msg, "", sk);
    let response_args = SignResponseArgs {
        request: request.clone(),
        response,
    };

    let statuses = submit_sign_batches(
        worker,
        contract,
        parallel,
        scheme,
        domain_id,
        DUPLICATE_REQUEST_FAN_OUT,
    )
    .await?;
    wait_for_pending_signature_queue(contract, &request).await?;
    settle_yields(worker).await?;
    submit_signature_response(&response_args, contract, attested).await?;
    await_batch_statuses(statuses).await?;
    Ok(())
}

async fn exercise_ckd_fan_out(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    parallel_id: &AccountId,
    attested: &near_workspaces::Account,
    domain_id: DomainId,
    sk: &threshold_signatures::confidential_key_derivation::KeygenOutput,
) -> anyhow::Result<()> {
    // Matches `build_ckd_calls` in test_parallel_contract: key_seed = seed + 2 when
    // unique_payloads = false.
    let app_pk = parallel_app_public_key(PARALLEL_CONTRACT_SEED + 2);
    let (request, response) = create_response_ckd(parallel_id, &app_pk, &domain_id, sk, "");
    let response_args = CKDResponseArgs {
        request: request.clone(),
        response,
    };

    let statuses = submit_ckd_batches(worker, contract, parallel, domain_id).await?;
    wait_for_pending_ckd_queue(contract, &request).await?;
    settle_yields(worker).await?;
    submit_ckd_response(&response_args, contract, attested).await?;
    await_batch_statuses(statuses).await?;
    Ok(())
}

/// Once the first yield in a fan-out queue is visible to the view layer, the
/// remaining children may still be sitting in pending receipts. Block-fast-forward
/// plus a real sleep is the same pattern the legacy duplicate test used
/// (`TODO(#1306): remove the need to sleep`) — it gives every batch's parent receipt
/// time to emit its K `sign()` children and for those children to push their yields
/// into `pending_signature_requests` before `respond()` drains the queue.
async fn settle_yields(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
) -> anyhow::Result<()> {
    worker.fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    worker.fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS).await?;
    Ok(())
}

async fn submit_sign_batches(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    scheme: SignScheme,
    domain_id: DomainId,
    total_calls: u64,
) -> anyhow::Result<Vec<(TransactionStatus, u64)>> {
    let mut statuses = Vec::new();
    let mut remaining = total_calls;
    while remaining > 0 {
        let k = remaining.min(SIGN_CALLS_PER_BATCH);
        let mut args = ParallelSignArgs::new(contract.id());
        scheme.populate_args(&mut args, domain_id, k);
        let status = submit_parallel_batch(parallel, &args).await?;
        statuses.push((status, k));
        remaining -= k;
        worker.fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS).await?;
    }
    Ok(statuses)
}

async fn submit_ckd_batches(
    worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    contract: &near_workspaces::Contract,
    parallel: &near_workspaces::Contract,
    domain_id: DomainId,
) -> anyhow::Result<Vec<(TransactionStatus, u64)>> {
    let mut statuses = Vec::new();
    let mut remaining = DUPLICATE_REQUEST_FAN_OUT;
    while remaining > 0 {
        let k = remaining.min(CKD_CALLS_PER_BATCH);
        let mut args = ParallelSignArgs::new(contract.id());
        args.ckd_calls_by_domain = Some(BTreeMap::from([(domain_id.0, k)]));
        let status = submit_parallel_batch(parallel, &args).await?;
        statuses.push((status, k));
        remaining -= k;
        worker.fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS).await?;
    }
    Ok(statuses)
}

async fn wait_for_pending_signature_queue(
    contract: &near_workspaces::Contract,
    request: &mpc_contract::primitives::signature::SignatureRequest,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let pending: Option<mpc_contract::primitives::signature::YieldIndex> = contract
            .view(method_names::GET_PENDING_REQUEST)
            .args_json(serde_json::json!({ "request": request }))
            .await?
            .json()?;
        if pending.is_some() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for signature request to appear in queue");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_pending_ckd_queue(
    contract: &near_workspaces::Contract,
    request: &mpc_contract::primitives::ckd::CKDRequest,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let pending: Option<mpc_contract::primitives::signature::YieldIndex> = contract
            .view(method_names::GET_PENDING_CKD_REQUEST)
            .args_json(serde_json::json!({ "request": request }))
            .await?
            .json()?;
        if pending.is_some() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for CKD request to appear in queue");
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
