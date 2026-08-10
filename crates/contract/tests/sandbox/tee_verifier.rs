//! Sandbox tests for the async [`submit_participant_info`] flow, driving the real
//! `tee-verifier` (or no verifier):
//! - Rejected: real verifier with a malformed quote.
//! - Unavailable: a verifier account that was never deployed.
//! - Verified: real verifier built with `sandbox-test-hooks`, its verification
//!   time pinned to the fixture's validity window. The pin is needed because
//!   real `verify_quote` checks the quote against block time: the fixture
//!   collateral is valid only inside a fixed window, while sandbox time is
//!   wall-clock and forward-only.
//!
//! Verified-path tests that store an attestation sign as the fixture account:
//! the quote's report_data binds the fixture account key, and the contract
//! reads that key from the transaction signer.
#![allow(non_snake_case)]

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::{tee_verifier_contract, tee_verifier_contract_with_sandbox_test_hooks},
        mpc_contract::{
            get_config, get_participant_attestation, get_tee_accounts, get_verified_attestation,
            prepay_and_submit_participant_info, prepay_attestation_grants, submit_participant_info,
            tee_verifier_account_id, total_gas_fee, vote_add_launcher_hash,
            vote_add_os_measurement, vote_for_hash, vote_tee_verifier_change,
        },
    },
};
use mpc_attestation::attestation::{DEFAULT_EXPIRATION_DURATION_SECONDS, default_measurements};
use mpc_contract::{
    errors::TeeError,
    tee::{measurements::ContractExpectedMeasurements, tee_state::AttestationSubmissionError},
};
use near_mpc_contract_interface::types as dtos;
use near_workspaces::{
    Account, AccountId, Contract, Worker,
    network::Sandbox,
    result::ExecutionFinalResult,
    types::{Gas, NearToken, SecretKey},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tee_verifier_interface::SANDBOX_TEST_PINNED_NOW_STORAGE_KEY;
use test_utils::attestation::{
    VALID_ATTESTATION_TIMESTAMP, account_key, account_secret_key, image_digest,
    launcher_compose_digest, launcher_image_hash, mock_dto_dstack_attestation, p2p_tls_key,
};

async fn setup() -> SandboxTestSetup {
    SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await
}

/// Setup for tests that expect the fixture to pass the post-DCAP checks, which needs the
/// wasm that accepts its app-compose.
async fn setup_accepting_fixture_attestation() -> SandboxTestSetup {
    SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_sandbox_test_attestation()
        .build()
        .await
}

/// Votes `verifier` in as `mpc-contract`'s trusted verifier (all participants vote
/// so the change crosses threshold).
async fn trust_verifier(contract: &Contract, participants: &[Account], verifier: &AccountId) {
    let expected_code_hash = [7u8; 32];
    for account in participants {
        vote_tee_verifier_change(account, contract, verifier, expected_code_hash)
            .await
            .unwrap();
    }
}

async fn deploy_and_trust_verifier(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    participants: &[Account],
) {
    let verifier = worker.dev_deploy(tee_verifier_contract()).await.unwrap();
    trust_verifier(contract, participants, verifier.id()).await;
}

/// Deploys the verifier build with the pinnable verification clock, pins it to
/// [`VALID_ATTESTATION_TIMESTAMP`] (the only time window in which the fixture
/// collateral verifies), and votes it in. Returns the verifier so tests can
/// match its receipt by executor.
async fn deploy_and_trust_pinned_verifier(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    participants: &[Account],
) -> Contract {
    let verifier = worker
        .dev_deploy(tee_verifier_contract_with_sandbox_test_hooks())
        .await
        .unwrap();
    worker
        .patch_state(
            verifier.id(),
            SANDBOX_TEST_PINNED_NOW_STORAGE_KEY,
            &VALID_ATTESTATION_TIMESTAMP.to_le_bytes(),
        )
        .await
        .unwrap();
    trust_verifier(contract, participants, verifier.id()).await;
    verifier
}

/// Votes the fixture's image hash, launcher hash, and OS measurements into the
/// on-chain allowlists, the sandbox analogue of the in-process
/// `whitelist_dstack_measurements` helper. The image hash must be voted in
/// before the launcher hash: allowed compose hashes are derived from the
/// currently allowed image hashes.
async fn whitelist_fixture_dstack_measurements(contract: &Contract, participants: &[Account]) {
    for account in participants {
        vote_for_hash(account, contract, &image_digest())
            .await
            .unwrap();
    }
    for account in participants {
        vote_add_launcher_hash(account, contract, &launcher_image_hash())
            .await
            .unwrap();
    }
    for &measurements in default_measurements() {
        let measurements = ContractExpectedMeasurements::from(measurements);
        for account in participants {
            vote_add_os_measurement(account, contract, &measurements)
                .await
                .unwrap();
        }
    }
}

/// Creates an account holding the fixture secret key, so its submissions pass
/// the report_data binding baked into the fixture quote.
async fn create_fixture_account(worker: &Worker<Sandbox>, account_id: &str) -> Account {
    let secret_key: SecretKey = account_secret_key()
        .parse()
        .expect("near_account_secret_key asset holds a valid ed25519 secret key");
    assert_eq!(
        secret_key.public_key().key_data(),
        account_key(),
        "near_account_secret_key does not match near_account_public_key.pub; \
         regenerate the fixture assets as a pair"
    );
    worker
        .create_root_account_subaccount(account_id.parse().unwrap(), secret_key)
        .await
        .unwrap()
        .into_result()
        .unwrap()
}

fn wall_clock_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Funds one attestation-storage grant for `beneficiary` from a throwaway account, the
/// way an operator does for a node. Storing a first attestation for a TLS key needs a
/// grant, and keeping the payer separate leaves the beneficiary's balance untouched so
/// tests can still assert it spent only gas.
async fn prepay_grant_from_separate_payer(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    beneficiary: &AccountId,
) {
    let payer = worker.dev_create_account().await.unwrap();
    let prepayment = prepay_attestation_grants(&payer, contract, beneficiary, 1)
        .await
        .unwrap();
    assert!(prepayment.is_success(), "prepayment failed: {prepayment:?}");
}

async fn submit_dstack(submitter: &Account, contract: &Contract) -> ExecutionFinalResult {
    submit_participant_info(
        submitter,
        contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
    )
    .await
    .unwrap()
}

/// Asserts a Dstack submission failed cleanly: a receipt failed mentioning every
/// string in `expected_error` (`fail_attestation_submission` panics in its own
/// receipt), no attestation was stored, and the caller spent only gas.
async fn assert_submission_failed_cleanly(
    result: &ExecutionFinalResult,
    contract: &Contract,
    submitter: &Account,
    balance_before: NearToken,
    expected_error: &[&str],
) {
    let failures = result.failures();
    assert!(
        !failures.is_empty(),
        "expected the promise chain to fail on a receipt, got: {result:#?}"
    );
    // Substring-match: near-workspaces keeps `ExecutionOutcome.status`
    // `pub(crate)`, so the error is only reachable via the Debug dump.
    let rendered = format!("{failures:?}");
    for expected in expected_error {
        assert!(
            rendered.contains(expected),
            "expected a receipt failure containing {expected:?}, got: {rendered}"
        );
    }

    // Typed as `VerifiedAttestation`: a wrongly stored Dstack entry must surface as
    // this assertion, not as a deserialization panic in the view helper.
    let stored = get_verified_attestation(contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_none(), "nothing should be stored on failure");
    assert_only_gas_spent(submitter, balance_before, result).await;
}

/// Asserts the caller spent only gas: no deposit is attached, so a failed submission costs nothing
/// beyond gas.
async fn assert_only_gas_spent(
    account: &Account,
    balance_before: NearToken,
    result: &ExecutionFinalResult,
) {
    let balance_after = account.view_account().await.unwrap().balance;
    let net_spent = balance_before.saturating_sub(balance_after);
    assert_eq!(net_spent, total_gas_fee(result));
}

#[tokio::test]
async fn submit_participant_info__should_reject_dstack_when_verifier_not_configured() {
    // Given
    let SandboxTestSetup {
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;

    // When
    let result = prepay_and_submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
    )
    .await
    .unwrap();

    // Then: it fails synchronously (before any cross-contract call), so the error
    // is on the top-level tx result, not a later receipt.
    let err = result
        .into_result()
        .expect_err("Dstack submit must fail when no verifier is configured")
        .to_string();
    let expected_panic = format!(
        "Smart contract panicked: {}",
        TeeError::VerifierNotConfigured
    );
    assert!(
        err.contains(&expected_panic),
        "expected {expected_panic:?}, got: {err}"
    );
    let stored = get_participant_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_none(), "no attestation should be stored");
}

#[tokio::test]
async fn tee_verifier_account_id__should_return_none_until_a_verifier_is_voted_in() {
    // Given
    let SandboxTestSetup {
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;
    assert_eq!(tee_verifier_account_id(&contract).await, None);

    // When
    let verifier: AccountId = "verifier.near".parse().unwrap();
    trust_verifier(&contract, &mpc_signer_accounts, &verifier).await;

    // Then
    assert_eq!(tee_verifier_account_id(&contract).await, Some(verifier));
}

#[tokio::test]
async fn submit_participant_info__should_store_nothing_on_verifier_rejection() {
    // Given
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;
    deploy_and_trust_verifier(&worker, &contract, &mpc_signer_accounts).await;
    let submitter = mpc_signer_accounts[0].clone();
    // A separate account funds the grant, exactly as an operator does for a node. Keeping the
    // payer distinct leaves the submitter's balance untouched by the prepayment, so the
    // assertion below is about the failed submission alone: it must cost nothing but gas.
    let payer = worker.dev_create_account().await.unwrap();
    let prepayment = prepay_attestation_grants(&payer, &contract, submitter.id(), 1)
        .await
        .unwrap();
    assert!(prepayment.is_success(), "prepayment failed: {prepayment:?}");
    let balance_before = submitter.view_account().await.unwrap().balance;
    let mut attestation = mock_dto_dstack_attestation();
    let dtos::Attestation::Dstack(dstack) = &mut attestation else {
        panic!("fixture must be a Dstack attestation");
    };
    dstack.quote = dtos::HexVec(vec![0u8; 16]);

    // When
    let result =
        submit_participant_info(&submitter, &contract, &attestation, &p2p_tls_key().into())
            .await
            .unwrap();

    // Then
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &[&TeeError::QuoteRejected {
            reason: String::new(),
        }
        .to_string()],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_fail_and_store_nothing_when_verifier_unreachable() {
    // Given: a verifier account that was never deployed, so the verify_quote promise fails.
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;
    let missing_verifier: AccountId = "nonexistent-verifier.near".parse().unwrap();
    trust_verifier(&contract, &mpc_signer_accounts, &missing_verifier).await;
    let submitter = mpc_signer_accounts[0].clone();
    // A separate account funds the grant, exactly as an operator does for a node. Keeping the
    // payer distinct leaves the submitter's balance untouched by the prepayment, so the
    // assertion below is about the failed submission alone: it must cost nothing but gas.
    let payer = worker.dev_create_account().await.unwrap();
    let prepayment = prepay_attestation_grants(&payer, &contract, submitter.id(), 1)
        .await
        .unwrap();
    assert!(prepayment.is_success(), "prepayment failed: {prepayment:?}");
    let balance_before = submitter.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&submitter, &contract).await;

    // Then
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &[&TeeError::VerifierUnavailable.to_string()],
    )
    .await;
}

/// Tolerance for comparing an on-chain expiry stamp against this process's
/// wall clock (sandbox block time tracks it loosely).
const EXPIRY_SLACK_SECONDS: u64 = 600;

#[tokio::test]
async fn submit_participant_info__should_run_dcap_within_verifier_gas_budget() {
    // Given
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;
    let verifier = deploy_and_trust_pinned_verifier(&worker, &contract, &mpc_signer_accounts).await;
    whitelist_fixture_dstack_measurements(&contract, &mpc_signer_accounts).await;
    let submitter = mpc_signer_accounts[0].clone();
    prepay_grant_from_separate_payer(&worker, &contract, submitter.id()).await;
    let balance_before = submitter.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the real DCAP run succeeds within the production gas budget and its
    // Verified verdict reaches the callback. This test deliberately submits from
    // a plain dev account rather than the fixture node, so it then fails at the
    // post-DCAP report_data binding; asserting that terminal error pins that the
    // verdict was Verified, not Rejected.
    let outcomes = result.outcomes();
    let verify_quote_outcome = outcomes
        .iter()
        .find(|outcome| outcome.executor_id == *verifier.id())
        .expect("the verify_quote receipt must have executed on the verifier");
    assert!(
        verify_quote_outcome.is_success(),
        "verify_quote must succeed, got: {verify_quote_outcome:#?}"
    );
    // The receipt is created with exactly `verifier_tera_gas` of static gas, so
    // succeeding already proves it fit the budget. Assert headroom instead, which
    // is the regression that matters: `dcap-qvl` growing until it OOGs in
    // production. Read the budget from the contract so it cannot drift from
    // `DEFAULT_VERIFIER_TERA_GAS`.
    let budget = Gas::from_tgas(get_config(&contract).await.unwrap().verifier_tera_gas);
    let headroom = Gas::from_gas(budget.as_gas() / 10);
    assert!(
        verify_quote_outcome.gas_burnt <= budget.saturating_sub(headroom),
        "verify_quote burnt {} of the configured {budget}, leaving less than the {headroom} \
         headroom this test exists to protect. Raise DEFAULT_VERIFIER_TERA_GAS (config.rs) \
         before the real cost reaches the budget",
        verify_quote_outcome.gas_burnt,
    );
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        // Substrings that survive the error's Debug formatting and
        // near-workspaces' quote escaping.
        &["failed verification", "report_data"],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_fail_cleanly_when_verifier_gas_budget_too_low() {
    // Given: a verifier gas budget far below the ~170 Tgas a real DCAP run
    // needs, so the verify_quote receipt runs out of gas.
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_init_config(dtos::InitConfig {
            verifier_tera_gas: Some(10),
            ..Default::default()
        })
        .build()
        .await;
    deploy_and_trust_verifier(&worker, &contract, &mpc_signer_accounts).await;
    let submitter = mpc_signer_accounts[0].clone();
    prepay_grant_from_separate_payer(&worker, &contract, submitter.id()).await;
    let balance_before = submitter.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the failed promise is indistinguishable from a crashed verifier.
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &[&TeeError::VerifierUnavailable.to_string()],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_store_attestation_on_verified_quote() {
    // Given
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = setup_accepting_fixture_attestation().await;
    deploy_and_trust_pinned_verifier(&worker, &contract, &mpc_signer_accounts).await;
    whitelist_fixture_dstack_measurements(&contract, &mpc_signer_accounts).await;
    let submitter = create_fixture_account(&worker, "fixture-node-a").await;
    prepay_grant_from_separate_payer(&worker, &contract, submitter.id()).await;
    let balance_before = submitter.view_account().await.unwrap().balance;
    let submitted_at = wall_clock_seconds();

    // When
    let result = submit_dstack(&submitter, &contract).await;

    // Then
    assert!(
        result.failures().is_empty(),
        "expected every receipt to succeed, got: {result:#?}"
    );
    let stored = get_verified_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap()
        .expect("a Verified submission must store an attestation");
    let dtos::VerifiedAttestation::Dstack(stored) = stored else {
        panic!("expected a stored Dstack attestation, got: {stored:?}");
    };
    assert_eq!(stored.mpc_image_hash, image_digest());
    assert_eq!(stored.launcher_compose_hash, launcher_compose_digest());
    let expected_expiry = submitted_at + DEFAULT_EXPIRATION_DURATION_SECONDS;
    assert!(
        stored.expiry_timestamp_seconds.abs_diff(expected_expiry) < EXPIRY_SLACK_SECONDS,
        "expiry {} should be about {expected_expiry} (submission time + default expiration)",
        stored.expiry_timestamp_seconds,
    );
    // Storage is funded by the contract, so the submitter pays only gas.
    assert_only_gas_spent(&submitter, balance_before, &result).await;
}

#[tokio::test]
async fn submit_participant_info__should_reject_verified_quote_when_tls_key_owned_by_other_account()
{
    // Given: an owner stored a Verified attestation for the fixture TLS key. The
    // quote's report_data binds only the key pair, not the account id, and NEAR
    // allows the same public key on two accounts, so nothing in the attestation
    // itself distinguishes the second submitter — only the ownership guard does.
    // That guard runs before verification, so the rejection is synchronous and
    // never reaches the verifier.
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = setup_accepting_fixture_attestation().await;
    deploy_and_trust_pinned_verifier(&worker, &contract, &mpc_signer_accounts).await;
    whitelist_fixture_dstack_measurements(&contract, &mpc_signer_accounts).await;
    let owner = create_fixture_account(&worker, "fixture-node-a").await;
    prepay_grant_from_separate_payer(&worker, &contract, owner.id()).await;
    submit_dstack(&owner, &contract)
        .await
        .into_result()
        .unwrap();
    let stored_before = get_verified_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap()
        .expect("the owner's submission must store an attestation");
    let attacker = create_fixture_account(&worker, "fixture-node-b").await;
    let balance_before = attacker.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&attacker, &contract).await;

    // Then: match the whole result rather than a receipt, so the assertion holds
    // whichever layer the guard rejects from.
    assert!(
        result.is_failure(),
        "expected the attacker's submission to fail, got: {result:#?}"
    );
    let rendered = format!("{result:?}");
    let expected = AttestationSubmissionError::TlsKeyOwnedByOtherAccount.to_string();
    assert!(
        rendered.contains(&expected),
        "expected a failure containing {expected:?}, got: {rendered}"
    );
    let stored_after = get_verified_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap()
        .expect("the owner's attestation must survive the attack");
    assert_eq!(
        stored_after, stored_before,
        "the owner's entry must be unchanged"
    );
    let tee_accounts = get_tee_accounts(&contract).await.unwrap();
    assert!(
        tee_accounts
            .iter()
            .any(|node| node.account_id.as_str() == owner.id().as_str()
                && node.tls_public_key == p2p_tls_key().into()),
        "the fixture TLS key must still belong to the owner, got: {tee_accounts:?}"
    );
    assert_only_gas_spent(&attacker, balance_before, &result).await;
}
